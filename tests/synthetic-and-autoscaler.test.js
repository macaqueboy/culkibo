'use strict';

const assert = require('assert');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const syntheticSentinelService = require('../server/services/syntheticSentinelService');
const workerAutoscalerService = require('../server/services/workerAutoscalerService');

const { SyntheticSentinelService, checkTlsSentinel } = syntheticSentinelService;
const { WorkerAutoscalerService, DEFAULT_POLICY } = workerAutoscalerService;

/** Starts a loopback mock API server implementing a 2-step auth -> protected data flow. */
async function startMockApiServer() {
  const secretJwt = 'eyJhbGciOiJIUzI1NiJ9.EPHEMERAL_TEST_TOKEN_999111.sig';
  const srv = http.createServer((req, res) => {
    /** @type {Buffer[]} */
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      if (req.method === 'POST' && req.url === '/auth/login') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, access_token: secretJwt, user: { id: 'u_42' } }));
        return;
      }
      if (req.method === 'GET' && req.url === '/api/me') {
        if (req.headers.authorization !== `Bearer ${secretJwt}`) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'unauthorized' }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'healthy', user: { id: 'u_42', tier: 'pro' } }));
        return;
      }
      if (req.url === '/redirect-ssrf') {
        res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
        res.end();
        return;
      }
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not_found' }));
    });
  });

  await new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve(undefined)));
  const addr = /** @type {import('net').AddressInfo} */ (srv.address());
  return {
    url: `http://127.0.0.1:${addr.port}`,
    secretJwt,
    stop: () => new Promise((resolve) => {
      if (typeof srv.closeAllConnections === 'function') srv.closeAllConnections();
      srv.close(() => resolve(undefined));
    })
  };
}

async function testSyntheticAndTlsSentinel(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'synthetic-data');
  const svc = new SyntheticSentinelService({ dataDir });
  const mockApi = await startMockApiServer();

  try {
    // 1. Save a 2-step login -> token -> protected endpoint flow with a literal password/secret to verify ZERO-SECRET persistence!
    const saved = svc.saveFlow({
      name: 'Auth + Profile E2E',
      projectId: 'proj_api',
      steps: [
        {
          name: 'login',
          method: 'POST',
          url: `${mockApi.url}/auth/login`,
          headers: {
            'X-Api-Key': 'raw-super-secret-api-key-777',
            'X-Client': 'culkibo-sentinel'
          },
          body: { email: 'bot@culkibo.dev', password: 'plaintext-password-never-persist' },
          extract: { token: 'json.access_token', uid: 'user.id' },
          assert: { status: 200, maxLatencyMs: 5000 }
        },
        {
          name: 'profile',
          method: 'GET',
          url: `${mockApi.url}/api/me`,
          headers: {
            Authorization: 'Bearer {{token}}'
          },
          assert: {
            status: 200,
            jsonPathEquals: { 'user.id': 'u_42', status: 'healthy' },
            bodyIncludes: '"tier":"pro"'
          }
        }
      ]
    });

    assert.strictEqual(saved.steps[0].headers['X-Api-Key'], '[REDACTED]', 'Sensitive literal header MUST be redacted on save');
    assert.strictEqual(saved.steps[0].body.password, '[REDACTED]', 'Sensitive body password MUST be redacted on save');
    assert.strictEqual(saved.steps[1].headers.Authorization, 'Bearer {{token}}', 'Pure {{var}} template placeholder preserved');

    // Run saved flow over REAL loopback HTTP
    const runRes = await svc.runFlow(saved.id, { allowLoopback: true });
    assert.strictEqual(runRes.ok, true, `2-step login->token flow must succeed: ${JSON.stringify(runRes)}`);
    assert.strictEqual(runRes.steps.length, 2);
    assert.deepStrictEqual(runRes.steps[0].extractedKeys, ['token', 'uid']);
    assert.strictEqual(runRes.steps[1].status, 200);
    assert.strictEqual(runRes.failedStep, null);

    // Inspect raw synthetic-flows.json on disk -> ZERO secrets or extracted token values!
    const rawDisk = fs.readFileSync(path.join(dataDir, 'synthetic-flows.json'), 'utf8');
    assert.ok(!rawDisk.includes('raw-super-secret-api-key-777'), 'API key must NEVER be persisted');
    assert.ok(!rawDisk.includes('plaintext-password-never-persist'), 'Password must NEVER be persisted');
    assert.ok(!rawDisk.includes(mockApi.secretJwt), 'Extracted JWT token value must NEVER be persisted');

    // 2. SSRF blocking: 169.254.169.254 blocked even with allowLoopback=true, loopback blocked by default, redirect-to-IMDS blocked!
    const imdsRun = await svc.runFlow({
      name: 'ssrf-imds',
      steps: [{ name: 'imds', method: 'GET', url: 'http://169.254.169.254/latest/meta-data/' }]
    }, { allowLoopback: true });
    assert.strictEqual(imdsRun.ok, false);
    assert.ok(imdsRun.steps[0].errors[0].includes('SSRF_BLOCKED'));

    const loopbackDefaultBlocked = await svc.runFlow({
      name: 'loopback-default',
      steps: [{ name: 'local', method: 'GET', url: `${mockApi.url}/api/me` }]
    });
    assert.strictEqual(loopbackDefaultBlocked.ok, false);
    assert.ok(loopbackDefaultBlocked.steps[0].errors[0].includes('SSRF_BLOCKED'));

    const redirectImds = await svc.runFlow({
      name: 'redirect-to-imds',
      steps: [{ name: 'hop', method: 'GET', url: `${mockApi.url}/redirect-ssrf` }]
    }, { allowLoopback: true });
    assert.strictEqual(redirectImds.ok, false);
    assert.ok(redirectImds.steps[0].errors[0].includes('SSRF_BLOCKED'), 'Redirect hop to 169.254.169.254 MUST be blocked');

    // CRUD list & delete
    assert.strictEqual(svc.listFlows().length, 1);
    assert.strictEqual(svc.deleteFlow(saved.id).deleted, true);
    assert.strictEqual(svc.listFlows().length, 0);

    // 3. Live TLS/SNI Sentinel: healthy wildcard cert, warning expiry, critical SAN/fingerprint/issuer drift
    const nowMs = Date.UTC(2026, 10, 27, 12, 0, 0);
    const dayMs = 86400 * 1000;

    const tlsOk = await checkTlsSentinel({
      host: 'api.culkibo.dev',
      expectedSan: 'api.culkibo.dev',
      baselineFingerprintSha256: 'AA:BB:CC:DD',
      baselineIssuer: 'CN=E6, O=Let\'s Encrypt',
      warnDays: 14,
      critDays: 3
    }, {
      nowMs,
      tlsProbeImpl: async () => ({
        protocol: 'TLSv1.3',
        cert: {
          subject: { CN: '*.culkibo.dev' },
          issuer: { CN: 'E6', O: 'Let\'s Encrypt' },
          valid_from: new Date(nowMs - 30 * dayMs).toUTCString(),
          valid_to: new Date(nowMs + 60 * dayMs).toUTCString(),
          fingerprint256: 'AA:BB:CC:DD',
          subjectaltname: 'DNS:*.culkibo.dev, DNS:culkibo.dev'
        }
      })
    });
    assert.strictEqual(tlsOk.status, 'OK');
    assert.strictEqual(tlsOk.sanMatched, true);
    assert.strictEqual(tlsOk.fingerprintDrifted, false);
    assert.strictEqual(tlsOk.issuerDrifted, false);
    assert.strictEqual(tlsOk.daysRemaining, 60);

    // Drift & Critical expiry check (2 days left + wrong SAN + fingerprint/issuer drift)
    const tlsCrit = await checkTlsSentinel({
      host: 'api.culkibo.dev',
      expectedSan: 'api.culkibo.dev',
      baselineFingerprintSha256: 'AA:BB:CC:DD',
      baselineIssuer: 'CN=E6, O=Let\'s Encrypt',
      warnDays: 14,
      critDays: 3
    }, {
      nowMs,
      tlsProbeImpl: async () => ({
        protocol: 'TLSv1.3',
        cert: {
          subject: { CN: 'other.example.org' },
          issuer: { CN: 'ZeroSSL RSA', O: 'ZeroSSL' },
          valid_from: new Date(nowMs - 88 * dayMs).toUTCString(),
          valid_to: new Date(nowMs + 2 * dayMs).toUTCString(),
          fingerprint256: 'FF:EE:DD:CC',
          subjectaltname: 'DNS:other.example.org'
        }
      })
    });
    assert.strictEqual(tlsCrit.status, 'CRITICAL');
    assert.strictEqual(tlsCrit.sanMatched, false);
    assert.strictEqual(tlsCrit.fingerprintDrifted, true);
    assert.strictEqual(tlsCrit.issuerDrifted, true);
    const alertCodes = tlsCrit.alerts.map((a) => a.code);
    assert.ok(alertCodes.includes('CERT_EXPIRING_CRITICAL'));
    assert.ok(alertCodes.includes('SAN_MISMATCH'));
    assert.ok(alertCodes.includes('FINGERPRINT_DRIFT'));
    assert.ok(alertCodes.includes('ISSUER_DRIFT'));
  } finally {
    await mockApi.stop();
  }

  console.log('  ✓ 1. Synthetic Multi-Step Flow & TLS/SNI Sentinel: 2-step login→token flow, zero-secret disk redaction, SSRF/redirect-IMDS block & TLS drift checks verified');
}

async function testWorkerAutoscaler(tmpRoot) {
  assert.strictEqual(DEFAULT_POLICY.minReplicas, 1);
  const svc = new WorkerAutoscalerService({ dataDir: path.join(tmpRoot, 'autoscaler-data') });
  const t0 = Date.UTC(2026, 10, 27, 12, 0, 0);

  // Persist custom policy
  const saved = svc.savePolicy('proj_worker', {
    minReplicas: 1,
    maxReplicas: 10,
    targetQueuePerReplica: 25,
    scaleUpQueueThreshold: 25,
    scaleDownQueueThreshold: 5,
    perReplicaRamMb: 256,
    reserveHostRamMb: 512,
    scaleUpCooldownSec: 60,
    scaleDownCooldownSec: 300,
    breakerQueueThreshold: 500,
    breakerRetryAfterSec: 45
  });
  assert.strictEqual(saved.projectId, 'proj_worker');
  assert.strictEqual(svc.listPolicies().length, 1);

  // 1. Healthy SCALE_UP when queue=100 (wants 4 replicas) and plenty of RAM (4096 MB free)
  const up = svc.evaluateAutoscaler({
    projectId: 'proj_worker',
    queueDepth: 100,
    currentReplicas: 1,
    hostFreeRamMb: 4096,
    nowMs: t0
  });
  assert.strictEqual(up.action, 'SCALE_UP');
  assert.strictEqual(up.reason, 'SCALE_UP');
  assert.strictEqual(up.targetReplicas, 4);
  assert.strictEqual(up.circuitBreaker.state, 'CLOSED');

  // 2. Cooldown anti-flapping: 20s after last scale-up (< 60s cooldown) -> HOLD COOLDOWN_ACTIVE
  const cooled = svc.evaluateAutoscaler({
    projectId: 'proj_worker',
    queueDepth: 150,
    currentReplicas: 4,
    hostFreeRamMb: 4096,
    lastScaleAtMs: t0,
    nowMs: t0 + 20 * 1000
  });
  assert.strictEqual(cooled.action, 'HOLD');
  assert.strictEqual(cooled.reason, 'COOLDOWN_ACTIVE');
  assert.strictEqual(cooled.cooldownRemainingSec, 40);

  // 3. Hysteresis deadband: queue=15 (between scaleDown=5 and scaleUp=25) -> HOLD HYSTERESIS_HOLD
  const hyst = svc.evaluateAutoscaler({
    projectId: 'proj_worker',
    queueDepth: 15,
    httpSaturationPct: 50,
    currentReplicas: 3,
    hostFreeRamMb: 4096,
    nowMs: t0 + 600 * 1000
  });
  assert.strictEqual(hyst.action, 'HOLD');
  assert.strictEqual(hyst.reason, 'HYSTERESIS_HOLD');
  assert.strictEqual(hyst.targetReplicas, 3);

  // 4. Hard VPS RAM Ceiling: queue=200 wants 8 replicas, hostFreeRamMb=1280 (1280-512=768 / 256 = maxSafeReplicas 3!)
  const capped = svc.evaluateAutoscaler({
    projectId: 'proj_worker',
    queueDepth: 200,
    currentReplicas: 1,
    hostFreeRamMb: 1280,
    nowMs: t0 + 600 * 1000
  });
  assert.strictEqual(capped.maxSafeReplicas, 3);
  assert.strictEqual(capped.desiredReplicas, 8);
  assert.strictEqual(capped.targetReplicas, 3, 'Target replicas MUST NOT exceed hard VPS RAM ceiling');
  assert.strictEqual(capped.reason, 'MEMORY_CEILING_CAPPED');

  // 5. Backpressure Circuit Breaker: 503 + Retry-After on queue >= 500 AND on hostFreeRamMb < reserveHostRamMb
  const qBreak = svc.evaluateAutoscaler({
    projectId: 'proj_worker',
    queueDepth: 550,
    currentReplicas: 3,
    hostFreeRamMb: 1280,
    nowMs: t0 + 700 * 1000
  });
  assert.strictEqual(qBreak.circuitBreaker.state, 'OPEN');
  assert.strictEqual(qBreak.circuitBreaker.httpStatus, 503);
  assert.strictEqual(qBreak.circuitBreaker.retryAfterSec, 45);
  assert.strictEqual(qBreak.circuitBreaker.headers['Retry-After'], '45');
  assert.strictEqual(qBreak.reason, 'BREAKER_OPEN');

  const ramBreak = svc.evaluateAutoscaler({
    projectId: 'proj_worker',
    queueDepth: 100,
    currentReplicas: 2,
    hostFreeRamMb: 256, // < 512 reserve!
    nowMs: t0 + 800 * 1000
  });
  assert.strictEqual(ramBreak.action, 'HOLD');
  assert.strictEqual(ramBreak.reason, 'BREAKER_OPEN');
  assert.strictEqual(ramBreak.circuitBreaker.httpStatus, 503);

  // 6. Scale-down after cooldown expires when queue <= 5 & HTTP <= 30%
  const down = svc.evaluateAutoscaler({
    projectId: 'proj_worker',
    queueDepth: 2,
    httpSaturationPct: 10,
    currentReplicas: 4,
    hostFreeRamMb: 4096,
    lastScaleAtMs: t0,
    nowMs: t0 + 400 * 1000
  });
  assert.strictEqual(down.action, 'SCALE_DOWN');
  assert.strictEqual(down.reason, 'SCALE_DOWN');
  assert.strictEqual(down.targetReplicas, 1);

  console.log('  ✓ 2. KEDA Worker Autoscaler: hysteresis deadband, cooldown anti-flapping, hard VPS RAM ceiling & 503 Retry-After circuit breaker verified');
}

async function runSyntheticAndAutoscalerTests() {
  console.log('\n🔭 Testing Synthetic Multi-Step Flow/TLS Sentinel & KEDA OOM-Safe Worker Autoscaler...\n');
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-cycle12-syn-auto-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  try {
    process.env.CULKIBO_DATA_DIR = path.join(tmpRoot, 'singleton-isolated');
    // Verify BOTH default singleton methods AND destructured exports work with zero recursion
    const { listFlows, saveFlow, deleteFlow } = syntheticSentinelService;
    const { listPolicies, getPolicy, savePolicy, evaluateAutoscaler } = workerAutoscalerService;
    assert.deepStrictEqual(syntheticSentinelService.listFlows(), []);
    assert.deepStrictEqual(listFlows(), []);
    const sFlow = saveFlow({ name: 'singleton-smoke', steps: [{ url: 'https://example.com' }] });
    assert.strictEqual(syntheticSentinelService.getFlow(sFlow.id)?.name, 'singleton-smoke');
    assert.strictEqual(deleteFlow(sFlow.id).deleted, true);

    assert.deepStrictEqual(workerAutoscalerService.listPolicies(), []);
    assert.deepStrictEqual(listPolicies(), []);
    savePolicy('singleton_proj', { maxReplicas: 6 });
    assert.strictEqual(getPolicy('singleton_proj').maxReplicas, 6);
    assert.strictEqual(evaluateAutoscaler({ projectId: 'singleton_proj', queueDepth: 0, currentReplicas: 1, hostFreeRamMb: 4096 }).action, 'HOLD');

    await testSyntheticAndTlsSentinel(tmpRoot);
    await testWorkerAutoscaler(tmpRoot);
  } finally {
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
  console.log('\n✅ All Synthetic Sentinel & Worker Autoscaler tests PASSED!\n');
}

module.exports = runSyntheticAndAutoscalerTests;

if (require.main === module) {
  runSyntheticAndAutoscalerTests().catch((err) => {
    console.error('❌ Synthetic & Autoscaler test FAILED:', err);
    process.exit(1);
  });
}
