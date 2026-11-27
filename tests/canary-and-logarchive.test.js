'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const sloCanaryController = require('../server/services/sloCanaryController');
const logArchiveService = require('../server/services/logArchiveService');

const {
  SloCanaryController,
  DEFAULT_CANARY_STEPS,
  DEFAULT_SLO_TARGET,
  DEFAULT_MAX_BURN_RATE,
  buildCaddyWeightedRoute,
  computeErrorBudgetBurnRate
} = sloCanaryController;

const {
  LogArchiveService,
  assertSafeRegex,
  DEFAULT_MAX_ARCHIVE_MB,
  DEFAULT_RETENTION_DAYS
} = logArchiveService;

async function testSloCanaryController(tmpRoot) {
  assert.deepStrictEqual(DEFAULT_CANARY_STEPS, [10, 25, 50, 100]);
  assert.strictEqual(DEFAULT_SLO_TARGET, 0.999);
  assert.strictEqual(DEFAULT_MAX_BURN_RATE, 14.4);

  // 1. Pure helpers: Caddy weighted_round_robin & Google SRE error-budget burn rate
  const route = buildCaddyWeightedRoute({
    hostname: 'api.culkibo.dev',
    stableUpstream: '127.0.0.1:4001',
    canaryUpstream: '127.0.0.1:4002',
    canaryWeight: 25
  });
  assert.strictEqual(route.handle[0].handler, 'reverse_proxy');
  assert.deepStrictEqual(route.handle[0].load_balancing.selection_policy, {
    policy: 'weighted_round_robin',
    weights: [75, 25]
  });

  // With sloTarget 0.999 (budget=0.001): 2% 5xx error rate => burnRate = 0.02 / 0.001 = 20x (> 14.4x!)
  const burnHigh = computeErrorBudgetBurnRate({ totalRequests: 1000, error5xxCount: 20, sloTarget: 0.999 });
  assert.strictEqual(burnHigh.burnRate, 20);
  const burnHealthy = computeErrorBudgetBurnRate({ totalRequests: 1000, error5xxCount: 1, sloTarget: 0.999 });
  assert.strictEqual(burnHealthy.burnRate, 1);

  const ctrl = new SloCanaryController({ dataDir: path.join(tmpRoot, 'canary-data') });

  // 2. Healthy progressive canary: 10 -> 25 -> 50 -> 100 (PROMOTED)
  /** @type {Array<{ stableWeight: number, canaryWeight: number, status: string }>} */
  const appliedWeights = [];
  const applyWeightsImpl = async (/** @type {any} */ p) => {
    appliedWeights.push({ stableWeight: p.stableWeight, canaryWeight: p.canaryWeight, status: p.status });
  };

  const r1 = await ctrl.startRollout({
    projectId: 'proj_api',
    hostname: 'api.culkibo.dev',
    stableUpstream: '127.0.0.1:4001',
    canaryUpstream: '127.0.0.1:4002',
    applyWeightsImpl
  });
  assert.strictEqual(r1.status, 'IN_PROGRESS');
  assert.strictEqual(r1.canaryWeight, 10);
  assert.deepStrictEqual(r1.caddyRoute.handle[0].load_balancing.selection_policy.weights, [90, 10]);

  const s2 = await ctrl.evaluateRollout(r1.id, { totalRequests: 500, error5xxCount: 0, baselineP95Ms: 12, canaryP95Ms: 14, applyWeightsImpl });
  assert.strictEqual(s2.canaryWeight, 25);
  assert.strictEqual(s2.status, 'IN_PROGRESS');

  const s3 = await ctrl.evaluateRollout(r1.id, { totalRequests: 500, error5xxCount: 1, baselineP95Ms: 12, canaryP95Ms: 15, applyWeightsImpl });
  assert.strictEqual(s3.canaryWeight, 50);
  assert.strictEqual(s3.status, 'IN_PROGRESS');

  const s4 = await ctrl.evaluateRollout(r1.id, { totalRequests: 1000, error5xxCount: 1, baselineP95Ms: 12, canaryP95Ms: 13, applyWeightsImpl });
  assert.strictEqual(s4.canaryWeight, 100);
  assert.strictEqual(s4.stableWeight, 0);
  assert.strictEqual(s4.status, 'PROMOTED');
  assert.deepStrictEqual(appliedWeights.map((w) => w.canaryWeight), [10, 25, 50, 100]);

  // 3. Burn-rate breach (>14.4x) -> INSTANT 100/0 ROLLED_BACK + alert
  let burnAlert = null;
  const r2 = await ctrl.startRollout({
    projectId: 'proj_api',
    hostname: 'api.culkibo.dev',
    stableUpstream: '127.0.0.1:4001',
    canaryUpstream: '127.0.0.1:4003'
  });
  const rolledBurn = await ctrl.evaluateRollout(r2.id, {
    totalRequests: 1000,
    error5xxCount: 25, // 2.5% -> 25x burn rate (> 14.4x)
    baselineP95Ms: 15,
    canaryP95Ms: 18,
    onAlert: (ev) => { burnAlert = ev; }
  });
  assert.strictEqual(rolledBurn.status, 'ROLLED_BACK');
  assert.strictEqual(rolledBurn.canaryWeight, 0);
  assert.strictEqual(rolledBurn.stableWeight, 100);
  assert.deepStrictEqual(rolledBurn.caddyRoute.handle[0].load_balancing.selection_policy.weights, [100, 0]);
  assert.ok(rolledBurn.breachReasons.some((b) => b.code === 'SLO_BURN_RATE_BREACH'));
  assert.ok(burnAlert && burnAlert.type === 'slo_canary_rollback');

  // 4. Latency p95 spike (>2.0x AND >= +25ms) -> INSTANT 100/0 ROLLED_BACK
  const r3 = await ctrl.startRollout({
    projectId: 'proj_web',
    hostname: 'web.culkibo.dev',
    stableUpstream: '127.0.0.1:5001',
    canaryUpstream: '127.0.0.1:5002'
  });
  const rolledLat = await ctrl.evaluateRollout(r3.id, {
    totalRequests: 1000,
    error5xxCount: 0,
    baselineP95Ms: 20,
    canaryP95Ms: 85 // 4.25x & +65ms!
  });
  assert.strictEqual(rolledLat.status, 'ROLLED_BACK');
  assert.strictEqual(rolledLat.canaryWeight, 0);
  assert.ok(rolledLat.breachReasons.some((b) => b.code === 'LATENCY_P95_BREACH'));

  // 5. Manual abort -> ABORTED + 100/0 weights
  const r4 = await ctrl.startRollout({
    projectId: 'proj_web',
    hostname: 'web.culkibo.dev',
    stableUpstream: '127.0.0.1:5001',
    canaryUpstream: '127.0.0.1:5003'
  });
  const aborted = await ctrl.abortRollout(r4.id, { reason: 'operator_halt' });
  assert.strictEqual(aborted.status, 'ABORTED');
  assert.strictEqual(aborted.canaryWeight, 0);
  assert.strictEqual(aborted.stableWeight, 100);
  assert.strictEqual(ctrl.listRollouts('proj_api').length, 2);
  assert.strictEqual(ctrl.getRollout(r1.id)?.status, 'PROMOTED');

  console.log('  ✓ 1. SLO Canary Controller: 10→25→50→100 PROMOTED, burn-rate (>14.4x) & p95-spike instant 100/0 ROLLED_BACK + alert & manual abort verified');
}

async function testLogArchiveService(tmpRoot) {
  assert.strictEqual(DEFAULT_MAX_ARCHIVE_MB, 50);
  assert.strictEqual(DEFAULT_RETENTION_DAYS, 30);

  // 1. ReDoS regex guard must strictly reject catastrophic backtracking patterns
  const maliciousPatterns = [
    '(a+)+$',
    '([a-zA-Z]+)*$',
    '(a*)*',
    '(a|aa)+',
    '((x+))+$',
    '(foo)\\1+',
    '(?<=secret)foo',
    'a'.repeat(125)
  ];
  for (const pat of maliciousPatterns) {
    assert.throws(
      () => assertSafeRegex(pat),
      (/** @type {any} */ err) => err && err.code === 'UNSAFE_REGEX',
      `ReDoS/unsafe regex MUST be rejected: ${pat}`
    );
  }
  assert.ok(assertSafeRegex('error\\s+50[0-9]|timeout') instanceof RegExp);

  // 2. Multi-date compressed .ndjson.gz append (surviving redeploys) & filtered search
  const svc = new LogArchiveService({ dataDir: path.join(tmpRoot, 'logs-data') });
  const nowMs = Date.UTC(2026, 10, 27, 15, 0, 0);

  // Release #1 logs on day 1 (two separate appends to same date verifying RFC 1952 concatenated gzip!)
  svc.appendLogs('shop-api', [
    { ts: '2026-11-25T10:00:00Z', level: 'info', releaseId: 'rel_001', stream: 'stdout', message: 'Server listening on :3000' },
    { ts: '2026-11-25T10:05:00Z', level: 'error', releaseId: 'rel_001', stream: 'stderr', message: 'Stripe webhook timeout 504 on /charge' }
  ], { dateStr: '2026-11-25', nowMs });
  svc.appendLogs('shop-api', [
    { ts: '2026-11-25T11:00:00Z', level: 'warn', releaseId: 'rel_001', stream: 'stdout', message: 'Connection pool at 85% saturation' }
  ], { dateStr: '2026-11-25', nowMs });

  // Simulated redeploy -> Release #2 logs on day 2
  svc.appendLogs('shop-api', [
    { ts: '2026-11-26T09:00:00Z', level: 'info', releaseId: 'rel_002', stream: 'stdout', message: 'Blue-green cutover complete' },
    { ts: '2026-11-26T09:12:00Z', level: 'error', releaseId: 'rel_002', stream: 'stderr', message: 'DB error 503 during checkout retry' }
  ], { dateStr: '2026-11-26', nowMs });

  // Search across both releases & dates
  const allErrors = svc.searchArchives({ projectId: 'shop-api', level: 'error' });
  assert.strictEqual(allErrors.filesScanned, 2);
  assert.strictEqual(allErrors.totalMatches, 2);

  const rel1Only = svc.searchArchives({ projectId: 'shop-api', releaseId: 'rel_001' });
  assert.strictEqual(rel1Only.totalMatches, 3, 'All 3 concatenated-gzip lines from rel_001 must survive redeploy');

  const queryMatch = svc.searchArchives({ projectId: 'shop-api', query: 'stripe webhook' });
  assert.strictEqual(queryMatch.totalMatches, 1);
  assert.strictEqual(queryMatch.entries[0].releaseId, 'rel_001');

  const safeRegexMatch = svc.searchArchives({ projectId: 'shop-api', regex: '50[34]' });
  assert.strictEqual(safeRegexMatch.totalMatches, 2);

  // ReDoS pattern passed to searchArchives MUST throw UNSAFE_REGEX
  assert.throws(
    () => svc.searchArchives({ projectId: 'shop-api', regex: '(a+)+$' }),
    (/** @type {any} */ err) => err && err.code === 'UNSAFE_REGEX'
  );
  // Path traversal in projectId MUST throw INVALID_PROJECT_ID
  assert.throws(
    () => svc.searchArchives({ projectId: '../etc' }),
    (/** @type {any} */ err) => err && err.code === 'INVALID_PROJECT_ID'
  );

  // 3. Verify oldest-shard pruning when exceeding maxArchiveMb
  const bigLine = 'X'.repeat(500) + ' ' + Math.random().toString(36);
  const pruneSvc = new LogArchiveService({ dataDir: path.join(tmpRoot, 'prune-data') });
  for (const day of ['2026-11-24', '2026-11-25', '2026-11-26', '2026-11-27']) {
    pruneSvc.appendLogs('noisy-app', Array.from({ length: 12 }, (_, i) => ({
      ts: `${day}T00:00:${String(i).padStart(2, '0')}Z`,
      level: 'info',
      message: `${day}-${i}-${bigLine}-${i * 7919}`
    })), { dateStr: day, maxArchiveMb: 0.0005, retentionDays: 30, nowMs }); // ~524B cap forces oldest-shard eviction!
  }
  const stAfterPrune = pruneSvc.getArchiveStats('noisy-app');
  assert.ok(stAfterPrune.shardCount < 4, `Oldest shards must be pruned when exceeding maxArchiveMb (got ${stAfterPrune.shardCount})`);
  assert.strictEqual(stAfterPrune.newestDate, '2026-11-27', 'Newest shard must be preserved while oldest shards are pruned');

  console.log('  ✓ 2. Compressed .ndjson.gz Log Archive: concatenated gzip multi-date/redeploy search, level/release/query/regex filters, maxArchiveMb pruning & ReDoS block verified');
}

async function runCanaryAndLogArchiveTests() {
  console.log('\n🚦 Testing SLO Canary Auto-Rollback Controller & Compressed .ndjson.gz Log Archive...\n');
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-cycle10-canary-logs-'));
  try {
    await testSloCanaryController(tmpRoot);
    await testLogArchiveService(tmpRoot);
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
  console.log('\n✅ All SLO Canary & Compressed Log Archive tests PASSED!\n');
}

module.exports = runCanaryAndLogArchiveTests;

if (require.main === module) {
  runCanaryAndLogArchiveTests().catch((err) => {
    console.error('❌ Canary & LogArchive test FAILED:', err);
    process.exit(1);
  });
}
