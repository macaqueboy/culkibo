const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  analyzeExplainPlan,
  auditPoolBudget,
  detectNPlusOne,
  evaluateDbCutoverGate,
  listQueryGuardHistory
} = require('../server/services/queryPlanGuardService');
const {
  auditLateralMovement,
  compileSegmentationPolicy,
  renderComposeNetworks,
  listSegmentationPolicies
} = require('../server/services/netSegCompilerService');
const {
  UPGRADE_LANES,
  classifyUpgradeRisk,
  planDependencyUpgrades,
  generatePackageManagerCooldown,
  listUpgradePlans
} = require('../server/services/depUpgradePlannerService');

/**
 * Suite Cycle #18: DB Query-Plan & Pool Exhaustion Guard, Container Network
 * Micro-Segmentation Compiler (Dokploy#2798/#2987), and Security Patch / Cooldown Upgrade Planner.
 *
 * Runs strictly inside an isolated `os.tmpdir()` `CULKIBO_DATA_DIR` — ZERO mutations to live `data/`.
 */
async function runTests() {
  console.log('--- Iniciando Tests de Query-Plan Guard, Network Micro-Seg y Dep Upgrade Planner ---');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c18-'));
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
    // 1. DB QUERY-PLAN & POOL EXHAUSTION REGRESSION GUARD
    // =========================================================================
    await runCase('1. queryPlanGuardService catches Seq Scan, row skew, disk sort, pool overcommit & N+1', async () => {
      const badExplain = [{
        Plan: {
          'Node Type': 'Sort',
          'Total Cost': 64200,
          'Plan Rows': 500,
          'Actual Rows': 85000,
          'Sort Space Type': 'Disk',
          'Sort Space Used': 24576,
          Plans: [{
            'Node Type': 'Seq Scan',
            'Relation Name': 'orders',
            'Total Cost': 48000,
            'Plan Rows': 500,
            'Actual Rows': 85000
          }]
        }
      }];

      const expRes = analyzeExplainPlan({ planJson: badExplain, sql: 'SELECT * FROM orders ORDER BY created_at DESC' });
      assert.strictEqual(expRes.safe, false);
      const expCodes = new Set(expRes.findings.map((f) => f.code));
      assert.ok(expCodes.has('SEQ_SCAN_REGRESSION'), 'Expected SEQ_SCAN_REGRESSION');
      assert.ok(expCodes.has('ROW_ESTIMATE_SKEW'), 'Expected ROW_ESTIMATE_SKEW');
      assert.ok(expCodes.has('DISK_SORT_SPILL'), 'Expected DISK_SORT_SPILL');

      // Pool overcommit + missing idleTimeoutSec (Prisma 7 leak)
      const badPool = auditPoolBudget({
        maxConnections: 100,
        reservedSuperuser: 5,
        replicas: 8,
        poolSizePerReplica: 20,
        idleTimeoutSec: 0
      });
      assert.strictEqual(badPool.safe, false);
      const poolCodes = new Set(badPool.blockers.map((b) => b.code));
      assert.ok(poolCodes.has('POOL_OVERCOMMIT'));
      assert.ok(poolCodes.has('MISSING_IDLE_TIMEOUT'));

      const goodPool = auditPoolBudget({
        maxConnections: 100,
        reservedSuperuser: 5,
        replicas: 4,
        poolSizePerReplica: 15,
        idleTimeoutSec: 30
      });
      assert.strictEqual(goodPool.safe, true);

      // N+1 query detector (>= 20 identical parameterized lookups)
      const trace = Array.from({ length: 25 }, (_, i) => `SELECT * FROM users WHERE id = ${i + 1}`);
      const n1 = detectNPlusOne(trace);
      assert.strictEqual(n1.detected, true);
      assert.strictEqual(n1.code, 'N_PLUS_ONE_DETECTED');
      assert.strictEqual(n1.offenders[0].count, 25);

      const gate = evaluateDbCutoverGate({
        projectId: 'proj-db',
        planJson: badExplain,
        poolConfig: { maxConnections: 100, replicas: 8, poolSizePerReplica: 20, idleTimeoutSec: 0 },
        queryTrace: trace
      });
      assert.strictEqual(gate.allowed, false);
      assert.ok(gate.blockerCodes.includes('SEQ_SCAN_REGRESSION'));
      assert.ok(gate.blockerCodes.includes('POOL_OVERCOMMIT'));
      assert.ok(gate.blockerCodes.includes('N_PLUS_ONE_DETECTED'));
      assert.strictEqual(listQueryGuardHistory('proj-db').length, 1);
    });

    // =========================================================================
    // 2. CONTAINER NETWORK MICRO-SEGMENTATION COMPILER (DOKPLOY#2798/#2987)
    // =========================================================================
    await runCase('2. netSegCompilerService flags flat-bridge LATERAL_DB_EXPOSURE & compiles internal: true data_postgres', async () => {
      const flatAudit = auditLateralMovement({
        sharedNetworkName: 'dokploy-network',
        services: [
          { name: 'web', tier: 'frontend', public: true, networks: ['dokploy-network'] },
          { name: 'api', tier: 'api', networks: ['dokploy-network'] },
          { name: 'postgres', tier: 'database', networks: ['dokploy-network'] }
        ],
        networks: { 'dokploy-network': { internal: false } }
      });
      assert.strictEqual(flatAudit.safe, false);
      const codes = new Set(flatAudit.violations.map((v) => v.code));
      assert.ok(codes.has('LATERAL_DB_EXPOSURE'));
      assert.ok(codes.has('UNISOLATED_DATA_TIER'));

      const compiled = compileSegmentationPolicy({
        projectId: 'proj-shop',
        services: [
          { name: 'web', tier: 'frontend', public: true },
          { name: 'api', tier: 'api' },
          { name: 'postgres', tier: 'database' }
        ],
        allowedEdges: [
          { from: 'web', to: 'api' },
          { from: 'api', to: 'postgres' }
        ],
        ingressServices: ['web'],
        persist: true
      });
      assert.strictEqual(compiled.ok, true);
      assert.strictEqual(compiled.frontendToDbIsolated, true);
      assert.strictEqual(compiled.networks.data_postgres.internal, true);
      assert.ok(compiled.networks.data_postgres.members.includes('api'));
      assert.ok(compiled.networks.data_postgres.members.includes('postgres'));
      assert.ok(!compiled.networks.data_postgres.members.includes('web'), 'Frontend web must NEVER reach data_postgres!');

      const yaml = renderComposeNetworks(compiled);
      assert.ok(yaml.includes('data_postgres:'));
      assert.ok(yaml.includes('internal: true'));
      assert.strictEqual(listSegmentationPolicies('proj-shop').length, 1);

      // Re-auditing the compiled topology proves 0 violations!
      const reAudit = auditLateralMovement({
        services: Object.entries(compiled.serviceNetworks).map(([name, nets]) => ({
          name,
          tier: name === 'postgres' ? 'database' : (name === 'web' ? 'frontend' : 'api'),
          public: name === 'web',
          networks: nets
        })),
        networks: compiled.networks
      });
      assert.strictEqual(reAudit.safe, true);
      assert.strictEqual(reAudit.violations.length, 0);
    });

    // =========================================================================
    // 3. SECURITY PATCH & TRANSITIVE DEP UPGRADE PLANNER (PNPM/RENOVATE)
    // =========================================================================
    await runCase('3. depUpgradePlannerService routes CVE fast-track, cooldown hold, safe patch & major review + syncs .npmrc', async () => {
      assert.deepStrictEqual(UPGRADE_LANES, ['FAST_TRACK_CVE', 'COOLDOWN_HOLD', 'SAFE_PATCH_MINOR', 'MAJOR_MANUAL_REVIEW']);

      const nowMs = Date.parse('2026-11-28T02:00:00Z');
      const hoursAgo = (h) => new Date(nowMs - h * 3600000).toISOString();

      const plan = planDependencyUpgrades({
        projectId: 'proj-web',
        nowIso: new Date(nowMs).toISOString(),
        minReleaseAgeHours: 168,
        advisories: [{ package: 'tar', cve: 'CVE-2026-99999', severity: 'critical' }],
        dependencies: [
          { name: 'tar', currentVersion: '7.4.0', targetVersion: '7.4.3', publishedAt: hoursAgo(2), transitive: true },
          { name: 'fresh-lib', currentVersion: '1.2.0', targetVersion: '1.3.0', publishedAt: hoursAgo(6) },
          { name: 'ws', currentVersion: '8.18.0', targetVersion: '8.18.3', publishedAt: hoursAgo(400) },
          { name: 'express', currentVersion: '4.21.2', targetVersion: '5.1.0', publishedAt: hoursAgo(600) }
        ]
      });

      assert.strictEqual(plan.ok, true);
      assert.strictEqual(plan.counts.FAST_TRACK_CVE, 1);
      assert.strictEqual(plan.lanes.FAST_TRACK_CVE[0].name, 'tar');
      assert.strictEqual(plan.counts.COOLDOWN_HOLD, 1);
      assert.strictEqual(plan.lanes.COOLDOWN_HOLD[0].name, 'fresh-lib');
      assert.strictEqual(plan.counts.SAFE_PATCH_MINOR, 1);
      assert.strictEqual(plan.lanes.SAFE_PATCH_MINOR[0].name, 'ws');
      assert.strictEqual(plan.counts.MAJOR_MANUAL_REVIEW, 1);
      assert.strictEqual(plan.lanes.MAJOR_MANUAL_REVIEW[0].name, 'express');

      // Direct risk helper check for missing publish timestamp -> COOLDOWN_HOLD
      const noTs = classifyUpgradeRisk({ name: 'mystery', currentVersion: '1.0.0', targetVersion: '1.0.1' });
      assert.strictEqual(noTs.lane, 'COOLDOWN_HOLD');

      // Cooldown config excludes CVE fast-track package cleanly
      const cfg = generatePackageManagerCooldown({ manager: 'pnpm', minReleaseAgeMinutes: 10080, exclude: ['tar'] });
      assert.ok(cfg.npmrc.includes('minimum-release-age=10080'));
      assert.ok(cfg.npmrc.includes('minimum-release-age-exclude[]=tar'));
      assert.ok(cfg.pnpmWorkspaceYaml.includes('minimumReleaseAge: 10080'));
      assert.strictEqual(listUpgradePlans('proj-web').length, 1);
    });

    console.log(`\n✅ Query-Plan Guard, Network Micro-Seg & Dep Upgrade Planner Suite: ${passed}/3 tests PASSED!`);
  } finally {
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ Query/NetSeg/Upgrades test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
