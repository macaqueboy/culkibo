'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const egressFirewallService = require('../server/services/egressFirewallService');
const chaosGameDayService = require('../server/services/chaosGameDayService');

const {
  EgressFirewallService,
  DEFAULT_EGRESS_POLICY,
  saveEgressPolicy,
  getEgressPolicy,
  auditFirewallAndEgress
} = egressFirewallService;

const {
  ChaosGameDayService,
  FAULT_TYPES,
  evaluateResilienceScore,
  runGameDaySimulation,
  listGameDays
} = chaosGameDayService;

/**
 * Verifies egress policy persistence, metadata/private-LAN/unallowlisted socket auditing,
 * missing DOCKER-USER & forward-drop chain detection, and anti-lockout preservation of 22/80/443.
 * @param {string} tmpRoot
 */
function testEgressFirewallService(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'egress-data');
  const svc = new EgressFirewallService({ dataDir });

  // 1. Default policy sanity
  const defPol = svc.getEgressPolicy('proj_api');
  assert.strictEqual(defPol.mode, DEFAULT_EGRESS_POLICY.mode);
  assert.strictEqual(defPol.blockMetadata, true);
  assert.strictEqual(defPol.blockPrivateLan, true);
  assert.deepStrictEqual(defPol.preserveAdminPorts, [22, 80, 443]);

  // 2. Save custom allowlist policy (attempting to drop port 22 must still keep 22/80/443!)
  const saved = svc.saveEgressPolicy('proj_api', {
    mode: 'allowlist',
    allowedCidrs: ['1.1.1.1/32', '104.16.0.0/12'],
    allowedDomains: ['api.stripe.com', '*.github.com'],
    preserveAdminPorts: [8443]
  });
  assert.ok(fs.existsSync(path.join(dataDir, 'egress-policies.json')));
  assert.ok(saved.preserveAdminPorts.includes(22) && saved.preserveAdminPorts.includes(80) && saved.preserveAdminPorts.includes(443));
  assert.ok(saved.preserveAdminPorts.includes(8443));

  // 3. Audit catches cloud metadata (IPv4 + IPv6 + hostname), private LAN, unallowlisted egress,
  //    AND missing DOCKER-USER / forward-drop chains
  const dirtyAudit = svc.auditFirewallAndEgress({
    projectId: 'proj_api',
    backend: 'nftables',
    firewallRules: ['table inet filter { chain input { type filter hook input priority 0; policy accept; } }'],
    observedSockets: [
      { remoteIp: '169.254.169.254', port: 80, protocol: 'tcp' },
      { remoteIp: 'fd00:ec2::254', port: 80, protocol: 'tcp' },
      'metadata.google.internal:80',
      { remoteIp: '10.0.4.22', port: 5432, protocol: 'tcp' },
      { remoteIp: '8.8.8.8', port: 443, protocol: 'tcp' },
      // Permitted by allowlist (must NOT be flagged):
      { remoteIp: '1.1.1.1', port: 443, protocol: 'tcp' },
      { remoteHost: 'api.github.com', port: 443, protocol: 'tcp' }
    ]
  });

  assert.strictEqual(dirtyAudit.ok, true);
  assert.strictEqual(dirtyAudit.compliant, false);
  assert.ok(dirtyAudit.riskScore >= 80, `Expected high riskScore, got ${dirtyAudit.riskScore}`);
  assert.strictEqual(dirtyAudit.antiLockoutSafe, true);
  assert.ok(dirtyAudit.missingChains.includes('DOCKER-USER'));
  assert.ok(dirtyAudit.missingChains.includes('nftables-forward-drop'));

  const ruleIds = dirtyAudit.violations.map((v) => v.ruleId);
  assert.strictEqual(dirtyAudit.violations.filter((v) => v.ruleId === 'CLOUD_METADATA_EGRESS').length, 3);
  assert.ok(ruleIds.includes('UNAUTHORIZED_PRIVATE_LAN_EGRESS'));
  assert.ok(ruleIds.includes('UNALLOWLISTED_EGRESS'));
  assert.ok(ruleIds.includes('MISSING_DOCKER_USER_CHAIN'));
  assert.ok(ruleIds.includes('MISSING_EGRESS_DROP_RULE'));

  // Allowed targets must not appear in violations
  assert.ok(!dirtyAudit.violations.some((v) => v.target === '1.1.1.1' || v.target === 'api.github.com'));

  // Suggested nftables rules preserve 22, 80, 443 and cover both docker0 & br-*
  const nftText = dirtyAudit.suggestedRules.join('\n');
  assert.ok(/tcp dport \{[^}]*22[^}]*80[^}]*443[^}]*\} accept/.test(nftText));
  assert.ok(nftText.includes('"br-*"') && nftText.includes('169.254.169.254'));

  // 4. Clean compliant audit using the generated nftables rules and only allowlisted traffic
  const cleanAudit = svc.auditFirewallAndEgress({
    projectId: 'proj_api',
    backend: 'nftables',
    firewallRules: dirtyAudit.suggestedRules,
    observedSockets: [
      { remoteIp: '1.1.1.1', port: 443 },
      { remoteHost: 'api.stripe.com', port: 443 }
    ]
  });
  assert.strictEqual(cleanAudit.compliant, true);
  assert.strictEqual(cleanAudit.riskScore, 0);
  assert.strictEqual(cleanAudit.violations.length, 0);
  assert.strictEqual(cleanAudit.missingChains.length, 0);
  assert.strictEqual(cleanAudit.antiLockoutSafe, true);

  // 5. iptables backend also generates anti-lockout rules preserving 22,80,443
  const iptAudit = svc.auditFirewallAndEgress({
    projectId: 'proj_api',
    backend: 'iptables',
    firewallRules: [],
    observedSockets: []
  });
  assert.strictEqual(iptAudit.antiLockoutSafe, true);
  assert.ok(iptAudit.suggestedRules.some((r) => r.includes('--dports 22,80,443') && r.includes('-j ACCEPT')));
}

/**
 * Verifies production safety lock, automatic error-rate abort, deterministic resilience scoring,
 * and atomic persistence of chaos GameDay scorecards.
 * @param {string} tmpRoot
 */
function testChaosGameDayService(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'chaos-data');
  const svc = new ChaosGameDayService({ dataDir });

  assert.deepStrictEqual(Array.from(FAULT_TYPES), [
    'latency_jitter',
    'http_5xx',
    'timeout_drop',
    'dns_failure',
    'bandwidth_cap'
  ]);

  // 1. Production environment hard-blocked without explicitProdConfirm: true
  const prodBlocked = svc.runGameDaySimulation({
    projectId: 'proj_checkout',
    environment: 'production',
    explicitProdConfirm: false,
    faultType: 'latency_jitter',
    dryRun: true
  });
  assert.strictEqual(prodBlocked.ok, false);
  assert.strictEqual(prodBlocked.blocked, true);
  assert.strictEqual(prodBlocked.code, 'PROD_CHAOS_CONFIRM_REQUIRED');
  assert.strictEqual(svc.listGameDays('proj_checkout').length, 0, 'Blocked run must not persist a scorecard');

  // 2. Production allowed ONLY with explicitProdConfirm: true
  const prodConfirmed = svc.runGameDaySimulation({
    projectId: 'proj_checkout',
    environment: 'production',
    explicitProdConfirm: true,
    faultType: 'latency_jitter',
    latencyMs: 180,
    jitterMs: 30,
    faultRatePct: 10,
    recoverySec: 10,
    sloP95Ms: 400,
    dryRun: true
  });
  assert.strictEqual(prodConfirmed.ok, true);
  assert.strictEqual(prodConfirmed.blocked, false);
  assert.strictEqual(prodConfirmed.status, 'COMPLETED');
  assert.ok(prodConfirmed.resilienceScore >= 85, `Expected healthy score >= 85, got ${prodConfirmed.resilienceScore}`);
  assert.ok(prodConfirmed.grade === 'A' || prodConfirmed.grade === 'B');

  // 3. Auto-abort when simulated error rate exceeds maxErrorAbortPct
  const abortedSim = svc.runGameDaySimulation({
    projectId: 'proj_checkout',
    environment: 'staging',
    faultType: 'http_5xx',
    faultRatePct: 30,
    maxErrorAbortPct: 15,
    recoverySec: 20
  });
  assert.strictEqual(abortedSim.ok, true);
  assert.strictEqual(abortedSim.status, 'AUTO_ABORTED');
  assert.strictEqual(abortedSim.aborted, true);
  assert.ok(abortedSim.metrics.errorRatePct > 15);
  assert.ok(abortedSim.resilienceScore < 70);

  // 4. Auto-abort on caller-supplied failing requestSamples
  const sampleAbort = svc.runGameDaySimulation({
    projectId: 'proj_checkout',
    environment: 'staging',
    faultType: 'timeout_drop',
    maxErrorAbortPct: 15,
    requestSamples: [
      { latencyMs: 80, status: 200 },
      { latencyMs: 1800, status: 504 },
      { latencyMs: 1900, status: 504 },
      { latencyMs: 90, status: 200 }
    ]
  });
  assert.strictEqual(sampleAbort.status, 'AUTO_ABORTED');
  assert.strictEqual(sampleAbort.metrics.errorRatePct, 50);

  // 5. Healthy staging GameDay scorecard >= 85 (grade A)
  const healthy = svc.runGameDaySimulation({
    projectId: 'proj_checkout',
    environment: 'staging',
    faultType: 'latency_jitter',
    latencyMs: 200,
    jitterMs: 40,
    faultRatePct: 10,
    maxErrorAbortPct: 15,
    recoverySec: 12,
    sloP95Ms: 400
  });
  assert.strictEqual(healthy.status, 'COMPLETED');
  assert.strictEqual(healthy.aborted, false);
  assert.ok(healthy.resilienceScore >= 85, `Expected >= 85, got ${healthy.resilienceScore}`);
  assert.strictEqual(healthy.grade, 'A');

  // 6. Direct evaluateResilienceScore verification
  const perfect = svc.evaluateResilienceScore({
    errorRatePct: 0.2,
    allowedErrorRatePct: 1.0,
    p95LatencyMs: 220,
    sloP95Ms: 400,
    recoverySec: 10,
    targetRecoverySec: 30
  });
  assert.strictEqual(perfect.resilienceScore, 100);
  assert.strictEqual(perfect.grade, 'A');

  assert.ok(fs.existsSync(path.join(dataDir, 'chaos-gamedays.json')));
  assert.strictEqual(svc.listGameDays('proj_checkout').length, 4);
}

/**
 * Verifies BOTH singleton (`svc.fn`) AND destructured (`fn`) exports with dynamic `CULKIBO_DATA_DIR`.
 * @param {string} tmpRoot
 */
function testSingletonAndDestructuredExports(tmpRoot) {
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = path.join(tmpRoot, 'singleton-env');

  try {
    // EgressFirewallService singleton + destructured
    const pol = egressFirewallService.saveEgressPolicy('singleton-proj', {
      mode: 'allowlist',
      allowedCidrs: ['9.9.9.9/32']
    });
    assert.deepStrictEqual(getEgressPolicy('singleton-proj').allowedCidrs, ['9.9.9.9/32']);
    assert.strictEqual(pol.projectId, 'singleton-proj');

    const audit1 = auditFirewallAndEgress({
      projectId: 'singleton-proj',
      observedSockets: [{ remoteIp: '169.254.169.254', port: 80 }],
      firewallRules: []
    });
    assert.strictEqual(audit1.compliant, false);
    assert.strictEqual(audit1.antiLockoutSafe, true);

    const pol2 = saveEgressPolicy('singleton-proj', { allowedDomains: ['api.culkibo.dev'] });
    assert.ok(pol2.allowedDomains.includes('api.culkibo.dev'));
    assert.strictEqual(egressFirewallService.getEgressPolicy('singleton-proj').allowedDomains[0], 'api.culkibo.dev');

    // ChaosGameDayService singleton + destructured
    const sc = evaluateResilienceScore({ errorRatePct: 0.5, p95LatencyMs: 300, recoverySec: 15 });
    assert.strictEqual(sc.resilienceScore, 100);

    const blocked = chaosGameDayService.runGameDaySimulation({
      projectId: 'singleton-proj',
      environment: 'production'
    });
    assert.strictEqual(blocked.code, 'PROD_CHAOS_CONFIRM_REQUIRED');

    const sim = runGameDaySimulation({
      projectId: 'singleton-proj',
      environment: 'staging',
      faultType: 'latency_jitter',
      latencyMs: 150,
      jitterMs: 25,
      faultRatePct: 10
    });
    assert.strictEqual(sim.status, 'COMPLETED');
    assert.ok(sim.resilienceScore >= 85);
    assert.strictEqual(listGameDays('singleton-proj').length, 1);
    assert.strictEqual(chaosGameDayService.listGameDays('singleton-proj').length, 1);
  } finally {
    if (prevDataDir === undefined) {
      delete process.env.CULKIBO_DATA_DIR;
    } else {
      process.env.CULKIBO_DATA_DIR = prevDataDir;
    }
  }
}

async function runAllTests() {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c14-egress-chaos-'));
  try {
    testEgressFirewallService(tmpRoot);
    testChaosGameDayService(tmpRoot);
    testSingletonAndDestructuredExports(tmpRoot);
    console.log('✅ egress-and-chaos.test.js PASSED (egress/nftables drift, anti-lockout, chaos prod-lock, auto-abort, resilience score, singleton+destructured)');
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runAllTests().catch((err) => {
    console.error('❌ egress-and-chaos.test.js FAILED:', err);
    process.exit(1);
  });
}

module.exports = runAllTests;
