const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  auditPgVacuumHealth,
  planWraparoundRecovery,
  renderHardenedVacuumSql,
  listVacuumAudits
} = require('../server/services/pgVacuumGuardService');
const {
  resolveAffectedServices,
  computeTopologicalDeployWaves,
  detectWorkspaceCycles,
  planMonorepoRollout,
  listMonorepoPlans
} = require('../server/services/monorepoGraphService');
const {
  auditSpfRecord,
  auditEmailDeliverability,
  renderHardenedDnsAuthRecords,
  listEmailAuthAudits
} = require('../server/services/emailAuthGuardService');

/**
 * Suite Cycle #21: PostgreSQL Autovacuum/XID Wraparound Guard, Monorepo Affected-Graph
 * Selective Builder (Dokploy#5547), and Transactional Email Auth / SMTP Guard (Coolify#4311).
 *
 * Runs strictly inside an isolated `os.tmpdir()` `CULKIBO_DATA_DIR` — ZERO mutations to live `data/`.
 */
async function runTests() {
  console.log('--- Iniciando Tests de PG Vacuum Guard, Monorepo Graph y Email Auth Guard ---');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c21-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = tmpDir;

  let passed = 0;
  const runCase = async (name, fn) => {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  };

  try {
    // =========================================================================
    // 1. POSTGRESQL AUTOVACUUM, 32-BIT XID WRAPAROUND & BLOAT GUARD
    // =========================================================================
    await runCase('1. pgVacuumGuardService flags XID wraparound/xmin pin/disabled table & emits online SQL (never VACUUM FULL)', async () => {
      const badAudit = auditPgVacuumHealth({
        databaseName: 'orders_prod',
        xidAge: 1_650_000_000,
        idleInTxSec: 900,
        deadTuplePct: 42,
        autovacuumDisabledTables: ['events'],
        inactiveSlots: 1,
        idleInTxTimeoutMs: 0
      });

      assert.strictEqual(badAudit.safe, false);
      assert.strictEqual(badAudit.blocked, true);
      assert.strictEqual(badAudit.status, 'CRITICAL');
      assert.ok(badAudit.findingCodes.includes('XID_WRAPAROUND_IMMINENT'));
      assert.ok(badAudit.findingCodes.includes('IDLE_IN_TX_XMIN_PIN'));
      assert.ok(badAudit.findingCodes.includes('MISSING_IDLE_TX_TIMEOUT'));
      assert.ok(badAudit.findingCodes.includes('AUTOVACUUM_DISABLED_TABLE'));
      assert.ok(badAudit.findingCodes.includes('TABLE_BLOAT_HIGH'));
      assert.ok(badAudit.findingCodes.includes('INACTIVE_REPLICATION_SLOT_PIN'));

      const recovery = planWraparoundRecovery(badAudit);
      assert.strictEqual(recovery.dryRun, true);
      assert.strictEqual(recovery.usesVacuumFull, false);
      assert.ok(recovery.recoverySql.includes('VACUUM (VERBOSE, FREEZE, ANALYZE)'));
      assert.ok(!recovery.recoverySql.toUpperCase().includes('VACUUM FULL'), 'Must NEVER emit VACUUM FULL during wraparound!');

      const sqlOnly = renderHardenedVacuumSql({ databaseName: 'orders_prod', autovacuumDisabledTables: ['events'] });
      assert.strictEqual(sqlOnly.usesVacuumFull, false);
      assert.strictEqual(listVacuumAudits('orders_prod').length, 1);

      const healthy = auditPgVacuumHealth({
        databaseName: 'orders_prod',
        xidAge: 120_000_000,
        idleInTxSec: 2,
        deadTuplePct: 4,
        autovacuumDisabledTables: [],
        inactiveSlots: 0,
        idleInTxTimeoutMs: 60000
      });
      assert.strictEqual(healthy.safe, true);
      assert.strictEqual(healthy.status, 'HEALTHY');
    });

    // =========================================================================
    // 2. MONOREPO AFFECTED-GRAPH SELECTIVE BUILDER & TOPOLOGICAL WAVES (DOKPLOY#5547)
    // =========================================================================
    await runCase('2. monorepoGraphService filters affected services, computes Kahn deploy/rollback waves & catches cycles', async () => {
      const workspaces = [
        { name: 'packages/ui', dir: 'packages/ui', deps: [] },
        { name: 'apps/web', dir: 'apps/web', deps: ['packages/ui'] },
        { name: 'apps/billing', dir: 'apps/billing', deps: [] }
      ];

      const aff = resolveAffectedServices({
        workspaces,
        changedFiles: ['packages/ui/btn.tsx']
      });
      assert.deepStrictEqual(aff.directlyAffected, ['packages/ui']);
      assert.deepStrictEqual(aff.transitivelyAffected, ['apps/web']);
      assert.deepStrictEqual(aff.skippedServices, ['apps/billing']);

      const waves = computeTopologicalDeployWaves({ workspaces, affectedNames: aff.affectedNames });
      assert.strictEqual(waves.hasCycle, false);
      assert.deepStrictEqual(waves.deployWaves, [['packages/ui'], ['apps/web']]);
      assert.deepStrictEqual(waves.rollbackWaves, [['apps/web'], ['packages/ui']]);

      const plan = planMonorepoRollout({
        projectId: 'proj-mono',
        workspaces,
        changedFiles: ['packages/ui/btn.tsx'],
        dryRun: false
      });
      assert.strictEqual(plan.safe, true);
      assert.strictEqual(plan.persisted, true);
      assert.strictEqual(listMonorepoPlans('proj-mono').length, 1);

      // Cyclic workspace graph MUST return WORKSPACE_CYCLE_DETECTED
      const cyclicWs = [
        { name: 'pkg-a', dir: 'packages/a', deps: ['pkg-b'] },
        { name: 'pkg-b', dir: 'packages/b', deps: ['pkg-a'] }
      ];
      const cyc = detectWorkspaceCycles(cyclicWs);
      assert.strictEqual(cyc.hasCycle, true);
      assert.strictEqual(cyc.code, 'WORKSPACE_CYCLE_DETECTED');

      const blockedPlan = planMonorepoRollout({ projectId: 'proj-cyc', workspaces: cyclicWs, changedFiles: ['packages/a/index.ts'] });
      assert.strictEqual(blockedPlan.blocked, true);
      assert.strictEqual(blockedPlan.code, 'WORKSPACE_CYCLE_DETECTED');
    });

    // =========================================================================
    // 3. TRANSACTIONAL EMAIL AUTH (SPF/DKIM/DMARC/MTA-STS) & SMTP GUARD (COOLIFY#4311)
    // =========================================================================
    await runCase('3. emailAuthGuardService catches SPF >10 lookups, 1024-bit DKIM, unaligned DMARC & port 587 TLS mismatch', async () => {
      const spf12 = 'v=spf1 ' + Array.from({ length: 12 }, (_, i) => `include:s${i}.example.net`).join(' ') + ' +all';
      const spfRes = auditSpfRecord(spf12);
      assert.strictEqual(spfRes.valid, false);
      assert.strictEqual(spfRes.dnsLookups, 12);
      assert.ok(spfRes.findingCodes.includes('SPF_LOOKUP_LIMIT_EXCEEDED'));
      assert.ok(spfRes.findingCodes.includes('SPF_PERMISSIVE_ALL'));

      const badMail = auditEmailDeliverability({
        domain: 'acme.io',
        fromAddress: 'alerts@other-domain.net',
        spfTxt: spf12,
        dkimBits: 1024,
        dmarcTxt: 'v=DMARC1; p=quarantine;',
        mtaStsMode: 'none',
        smtpPort: 587,
        smtpTlsMode: 'none'
      });
      assert.strictEqual(badMail.blocked, true);
      assert.ok(badMail.findingCodes.includes('SPF_LOOKUP_LIMIT_EXCEEDED'));
      assert.ok(badMail.findingCodes.includes('DKIM_KEY_TOO_WEAK'));
      assert.ok(badMail.findingCodes.includes('DMARC_MISSING_OR_UNALIGNED'));
      assert.ok(badMail.findingCodes.includes('MTA_STS_NOT_ENFORCED'));
      assert.ok(badMail.findingCodes.includes('SMTP_TLS_MISMATCH'));
      assert.strictEqual(typeof badMail.dnsRecordsBlock, 'string');

      const goodMail = auditEmailDeliverability({
        domain: 'acme.io',
        fromAddress: 'noreply@acme.io',
        spfTxt: 'v=spf1 include:_spf.resend.com ~all',
        dkimBits: 2048,
        dmarcTxt: 'v=DMARC1; p=reject; adkim=s; aspf=s;',
        mtaStsMode: 'enforce',
        smtpPort: 587,
        smtpTlsMode: 'starttls'
      });
      assert.strictEqual(goodMail.safe, true);
      assert.strictEqual(goodMail.blocked, false);
      assert.strictEqual(goodMail.status, 'PASS');

      const rendered = renderHardenedDnsAuthRecords({ domain: 'acme.io' });
      assert.strictEqual(rendered.dryRun, true);
      assert.ok(rendered.dnsRecordsBlock.includes('_dmarc.acme.io'));
      assert.strictEqual(listEmailAuthAudits('acme.io').length, 2);
    });

    console.log(`\n✅ PG Vacuum Guard, Monorepo Graph & Email Auth Guard Suite: ${passed}/3 tests PASSED!`);
  } finally {
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ Vacuum/Monorepo/Email test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
