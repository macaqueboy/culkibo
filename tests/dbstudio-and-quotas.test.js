const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  DbStudioService,
  validateReadOnlySql,
  validateSafeRedisCommand,
  analyzePostgresBloat,
  summarizeExplainPlan,
  MAX_ROW_LIMIT,
  STATEMENT_TIMEOUT_MS
} = require('../server/services/dbStudioService');
const {
  QuotaMeteringService,
  DEFAULT_QUOTA,
  DEFAULT_UNIT_RATES,
  escapeCsvCell,
  exportLedgerCsv
} = require('../server/services/quotaMeteringService');

/**
 * Suite Cycle #9: Zero-Dep Read-Only Live DB Studio & Safe Redis Inspector
 * (`Dokploy CVE-2026-24841`) + Agency Multi-Tenant Quotas & CSV-Formula-Safe
 * Billing Usage Ledger (`Dokploy CVE-2026-116068`/`CVE-2026-127212`).
 *
 * Runs 100% isolated inside `os.tmpdir()` — ZERO mutations to live `data/`.
 */
async function runTests() {
  console.log('--- Iniciando Tests de Read-Only DB Studio, Safe Redis Inspector y Agency Quotas/Ledger ---');

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-dbstudio-quotas-'));
  const dataDir = path.join(tmpRoot, 'data');
  fs.mkdirSync(dataDir, { recursive: true });

  const studio = new DbStudioService();
  const metering = new QuotaMeteringService({ dataDir });

  let passed = 0;
  const runCase = async (name, fn) => {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  };

  try {
    // =========================================================================
    // 1. SQL LEXICAL READ-ONLY GATE (BLOCKS ALL ADVERSARIAL ATTACKS)
    // =========================================================================
    await runCase('1. validateReadOnlySql() blocks stacked, comment-hidden, CTE mutations, COPY, psql \\! & pg_read_file', async () => {
      assert.strictEqual(MAX_ROW_LIMIT, 200);
      assert.strictEqual(STATEMENT_TIMEOUT_MS, 5000);

      const attacks = [
        'SELECT 1; DROP TABLE users',
        '/* safe */ DELETE FROM accounts WHERE id = 1',
        'SELECT /* nested /* comment */ */ 1; TRUNCATE logs',
        'WITH x AS (DELETE FROM sessions RETURNING *) SELECT * FROM x',
        'WITH upd AS (UPDATE users SET role = \'admin\' RETURNING *) SELECT * FROM upd',
        "COPY users TO PROGRAM 'id'",
        '\\! cat /etc/passwd',
        '\\copy users from /etc/shadow',
        "SELECT pg_read_file('/etc/passwd')",
        'SELECT pg_terminate_backend(1234)',
        "SELECT lo_export(12345, '/tmp/pwn')",
        'DO $$ BEGIN EXECUTE \'DROP TABLE users\'; END $$',
        'EXPLAIN ANALYZE DELETE FROM users',
        'INSERT INTO users VALUES (1)',
        'VACUUM FULL users',
        'ANALYZE users',
        'SET statement_timeout = 0',
        'SELECT * INTO evil_copy FROM users',
        ''
      ];

      for (const bad of attacks) {
        assert.throws(
          () => validateReadOnlySql(bad),
          (err) => err && (err.status === 400 || err.status === 403),
          `Must reject mutating/malicious SQL: ${bad}`
        );
      }

      // Clean SELECT (auto-appends LIMIT 200 and wraps in READ ONLY transaction)
      const q1 = validateReadOnlySql('SELECT id, email FROM users WHERE note = \'do not drop\' -- trailing comment');
      assert.strictEqual(q1.ok, true);
      assert.strictEqual(q1.readOnlyEnforced, true);
      assert.ok(q1.sanitizedSql.endsWith('LIMIT 200'));
      assert.ok(q1.wrappedSql.startsWith("BEGIN TRANSACTION READ ONLY; SET LOCAL statement_timeout = '5000ms';"));
      assert.ok(q1.wrappedSql.endsWith('; ROLLBACK;'));

      // Oversized LIMIT clamped to 200
      const q2 = validateReadOnlySql('SELECT * FROM orders LIMIT 50000;');
      assert.strictEqual(q2.limitClamped, true);
      assert.ok(q2.sanitizedSql.endsWith('LIMIT 200'));

      // Clean WITH CTE SELECT + EXPLAIN (FORMAT JSON) allowed
      const q3 = validateReadOnlySql('WITH recent AS (SELECT id FROM orders) SELECT * FROM recent LIMIT 10');
      assert.strictEqual(q3.leadingKeyword, 'WITH');
      assert.ok(q3.sanitizedSql.endsWith('LIMIT 10'));

      const q4 = validateReadOnlySql('EXPLAIN (FORMAT JSON) SELECT * FROM orders WHERE id = 1');
      assert.strictEqual(q4.leadingKeyword, 'EXPLAIN');

      // runReadOnlyQuery dryRunPreview & custom executor
      const preview = await studio.runReadOnlyQuery({ databaseId: 'db_pg_1', query: 'SELECT 1 AS ok' });
      assert.strictEqual(preview.ok, true);
      assert.strictEqual(preview.dryRunPreview, true);
      assert.strictEqual(preview.rowCap, 200);
      assert.strictEqual(preview.statementTimeoutMs, 5000);
    });

    // =========================================================================
    // 2. POSTGRES BLOAT ANALYZER & EXPLAIN JSON SUMMARIZER
    // =========================================================================
    await runCase('2. analyzePostgresBloat() & summarizeExplainPlan() produce actionable diagnostics', async () => {
      const bloat = analyzePostgresBloat([
        {
          schema: 'public',
          table: 'events',
          liveTuples: 50000,
          deadTuples: 30000,
          sizeBytes: 120 * 1024 * 1024,
          indexes: [
            { name: 'idx_events_unused', idx_scan: 0, sizeBytes: 4 * 1024 * 1024 },
            { name: 'idx_events_pkey', idx_scan: 98000, sizeBytes: 2 * 1024 * 1024 }
          ]
        },
        {
          schema: 'public',
          table: 'users',
          liveTuples: 10000,
          deadTuples: 200,
          sizeBytes: 4 * 1024 * 1024,
          indexes: []
        }
      ]);

      assert.strictEqual(bloat.checkedTables, 2);
      assert.strictEqual(bloat.bloatedTables.length, 1);
      assert.strictEqual(bloat.bloatedTables[0].table, 'events');
      assert.strictEqual(bloat.bloatedTables[0].deadTupleRatio, 0.375);
      assert.strictEqual(bloat.unusedIndexes.length, 1);
      assert.strictEqual(bloat.unusedIndexes[0].indexName, 'idx_events_unused');
      assert.ok(bloat.recommendations.length >= 2);

      const explain = summarizeExplainPlan([
        {
          'Planning Time': 0.42,
          'Execution Time': 1250.5,
          Plan: {
            'Node Type': 'Hash Join',
            'Total Cost': 14200.5,
            Plans: [
              { 'Node Type': 'Seq Scan', 'Relation Name': 'events', 'Total Cost': 8200, 'Actual Rows': 45000, Filter: "(status = 'open')" },
              { 'Node Type': 'Index Scan', 'Relation Name': 'users', 'Index Name': 'users_pkey', 'Total Cost': 12.5, 'Actual Rows': 10 }
            ]
          }
        }
      ]);
      assert.strictEqual(explain.totalCost, 14200.5);
      assert.strictEqual(explain.executionTimeMs, 1250.5);
      assert.strictEqual(explain.seqScanNodes.length, 1);
      assert.strictEqual(explain.indexScanNodes.length, 1);
      assert.ok(explain.warnings.length >= 2);
    });

    // =========================================================================
    // 3. SAFE REDIS / VALKEY INSPECTOR (DENY KEYS/FLUSHALL/EVAL/CONFIG, CLAMP SCAN)
    // =========================================================================
    await runCase('3. validateSafeRedisCommand() blocks dangerous commands & clamps SCAN COUNT <= 100', async () => {
      const blocked = [
        'KEYS *',
        'FLUSHALL',
        'FLUSHDB',
        'CONFIG GET *',
        'EVAL "return 1" 0',
        'EVALSHA abc 0',
        'SET foo bar',
        'DEL session:1',
        'SHUTDOWN NOSAVE',
        'ACL LIST',
        'SCRIPT FLUSH'
      ];
      for (const bad of blocked) {
        assert.throws(
          () => validateSafeRedisCommand(bad),
          (err) => err && err.status === 403,
          `Must reject Redis command: ${bad}`
        );
      }

      // SCAN 0 COUNT 500 clamped to 100!
      const scanClamped = validateSafeRedisCommand('SCAN 0 MATCH user:* COUNT 500');
      assert.strictEqual(scanClamped.ok, true);
      assert.strictEqual(scanClamped.countClamped, true);
      assert.deepStrictEqual(scanClamped.normalizedArgv, ['SCAN', '0', 'MATCH', 'user:*', 'COUNT', '100']);

      // SCAN 0 without COUNT defaults to COUNT 50
      const scanDef = validateSafeRedisCommand(['SCAN', '0']);
      assert.deepStrictEqual(scanDef.normalizedArgv, ['SCAN', '0', 'COUNT', '50']);

      const infoCmd = await studio.runSafeRedisInspect({ databaseId: 'db_vk_1', argv: 'INFO memory' });
      assert.strictEqual(infoCmd.ok, true);
      assert.strictEqual(infoCmd.dryRunPreview, true);
      assert.deepStrictEqual(infoCmd.normalizedArgv, ['INFO', 'memory']);
    });

    // =========================================================================
    // 4. FAIL-CLOSED MULTI-TENANT QUOTAS, ACL ISOLATION & CSV FORMULA NEUTRALIZATION
    // =========================================================================
    await runCase('4. QuotaMeteringService enforces fail-closed quotas, strict tenant ACLs & CSV formula safety', async () => {
      assert.ok(DEFAULT_QUOTA.memoryMb === 4096);
      assert.ok(DEFAULT_UNIT_RATES.cpuCoreHourUsd > 0);

      metering.setQuota('proj_tenant_a', {
        containers: 4,
        memoryMb: 2048,
        cpuCores: 2,
        storageGb: 20,
        bandwidthGbMo: 100,
        tenantId: 'agency_alpha'
      });
      metering.setQuota('proj_tenant_b', {
        containers: 2,
        memoryMb: 1024,
        cpuCores: 1,
        storageGb: 10,
        bandwidthGbMo: 50,
        tenantId: 'agency_beta'
      });

      // Reload from disk verifies persistence
      const meteringReloaded = new QuotaMeteringService({ dataDir });
      assert.strictEqual(meteringReloaded.getQuota('proj_tenant_a').memoryMb, 2048);

      // Fail-closed quota check: pass vs violations
      const okCheck = meteringReloaded.checkQuotaAllowance('proj_tenant_a', { containers: 3, memoryMb: 1536, cpuCores: 2 });
      assert.strictEqual(okCheck.allowed, true);
      assert.strictEqual(okCheck.violations.length, 0);

      const failCheck = meteringReloaded.checkQuotaAllowance('proj_tenant_a', { containers: 6, memoryMb: 4096, bandwidthGbMo: 250 });
      assert.strictEqual(failCheck.allowed, false);
      assert.strictEqual(failCheck.violations.length, 3);
      assert.ok(failCheck.violations.some((v) => v.resource === 'memoryMb' && v.exceededBy === 2048));

      // Cross-tenant isolation in listQuotas & buildUsageLedger (Dokploy CVE-2026-116068/127212)
      const listA = meteringReloaded.listQuotas({ allowedProjectIds: ['proj_tenant_a'] });
      assert.strictEqual(listA.count, 1);
      assert.strictEqual(listA.quotas[0].projectId, 'proj_tenant_a');

      const ledgerA = meteringReloaded.buildUsageLedger({
        projects: [
          { id: 'proj_tenant_a', name: "=CMD|' /C calc'!A0", cpus: 2, memoryMb: 1024, status: 'active' },
          { id: 'proj_tenant_b', name: 'Secret Beta Client', cpus: 4, memoryMb: 4096, status: 'active' }
        ],
        databases: [
          { id: 'db_a', projectId: 'proj_tenant_a', storageGb: 10 },
          { id: 'db_b', projectId: 'proj_tenant_b', storageGb: 100 }
        ],
        allowedProjectIds: ['proj_tenant_a'],
        periodDays: 30
      });

      assert.strictEqual(ledgerA.entries.length, 1);
      assert.strictEqual(ledgerA.entries[0].projectId, 'proj_tenant_a');
      assert.strictEqual(ledgerA.totals.totalDatabases, 1);
      assert.ok(ledgerA.totals.estimatedCostUsd > 0);
      assert.ok(!JSON.stringify(ledgerA).includes('Secret Beta Client'), 'Cross-tenant project MUST NOT leak in ledger');

      // CSV formula neutralization (OWASP CSV Injection)
      assert.strictEqual(escapeCsvCell("=CMD|' /C calc'!A0"), "'=CMD|' /C calc'!A0");
      assert.strictEqual(escapeCsvCell('+1+1'), "'+1+1");
      assert.strictEqual(escapeCsvCell('-2+3'), "'-2+3");
      assert.strictEqual(escapeCsvCell('@SUM(A1)'), "'@SUM(A1)");
      assert.strictEqual(escapeCsvCell('\t=1+1'), "'\t=1+1");
      assert.strictEqual(escapeCsvCell('hello, "world"'), '"hello, ""world"""');

      const csv = exportLedgerCsv(ledgerA);
      assert.ok(csv.startsWith('projectId,projectName,tenantId,'));
      assert.ok(csv.includes("'=CMD|' /C calc'!A0"), 'Dangerous formula project name must be prefixed with single quote');
      assert.ok(csv.includes('\nTOTAL,1 project(s),ALL,'));
      assert.ok(!csv.includes('Secret Beta Client'));
    });

    console.log(`\n✅ Read-Only DB Studio & Agency Quotas/Ledger Suite: ${passed}/4 tests PASSED!`);
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ DB Studio & Quotas test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
