'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const mtlsMeshService = require('../server/services/mtlsMeshService');
const apiRateLimitService = require('../server/services/apiRateLimitService');

const {
  MtlsMeshService,
  initTrustDomain,
  issueWorkloadCert,
  verifyWorkloadCert,
  revokeWorkloadCert,
  listWorkloadCerts,
  compileCaddyMtlsPolicy
} = mtlsMeshService;

const {
  ApiRateLimitService,
  PLAN_PRESETS,
  saveRateLimitPolicy,
  listRateLimitPolicies,
  consumeTokenBucket,
  simulateBurst,
  compileCaddyRateLimitConfig
} = apiRateLimitService;

const PRIVATE_KEY_MARKER = ['-----BEGIN ', 'PRIVATE KEY-----'].join('');

/**
 * Verifies SPIFFE-Lite Ed25519 CA init, cert issuance, TTL clamping, signature verification,
 * expiry & CRL revocation rejection, Caddy require_and_verify compilation, and zero CA key exposure.
 * @param {string} tmpRoot
 */
function testMtlsMeshService(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'mtls-data');
  const svc = new MtlsMeshService({ dataDir });
  const t0 = Date.UTC(2026, 10, 27, 10, 0, 0);

  // 1. Initialize trust domain
  const initRes = svc.initTrustDomain('mesh.culkibo.internal');
  assert.strictEqual(initRes.ok, true);
  assert.strictEqual(initRes.trustDomain, 'mesh.culkibo.internal');
  assert.ok(initRes.caPublicKeyPem && initRes.caPublicKeyPem.includes('BEGIN PUBLIC KEY'));
  assert.ok(!JSON.stringify(initRes).includes(PRIVATE_KEY_MARKER), 'initTrustDomain must NEVER expose CA private key');
  assert.ok(fs.existsSync(path.join(dataDir, 'mtls-ca.key')));
  assert.ok(fs.existsSync(path.join(dataDir, 'mtls-mesh.json')));

  // Verify mtls-mesh.json does NOT contain the private key
  const rawStore = fs.readFileSync(path.join(dataDir, 'mtls-mesh.json'), 'utf8');
  assert.ok(!rawStore.includes(PRIVATE_KEY_MARKER), 'mtls-mesh.json must never store CA private key');

  // 2. Issue short-lived workload cert (ttlHours clamped to 1..168)
  const issued = svc.issueWorkloadCert({
    serviceName: 'payments-api',
    namespace: 'prod',
    ttlHours: 999,
    nowMs: t0
  });
  assert.strictEqual(issued.ok, true);
  assert.strictEqual(issued.ttlHours, 168, 'ttlHours must clamp at 168h');
  assert.strictEqual(issued.spiffeId, 'spiffe://mesh.culkibo.internal/ns/prod/sa/payments-api');
  assert.ok(!JSON.stringify(issued).includes(PRIVATE_KEY_MARKER), 'issueWorkloadCert must NEVER expose private key');

  // 3. Verify valid certificate
  const valid = svc.verifyWorkloadCert({
    cert: issued.cert,
    signatureB64: issued.signatureB64,
    nowMs: t0 + 3600000
  });
  assert.strictEqual(valid.ok, true);
  assert.strictEqual(valid.valid, true);
  assert.strictEqual(valid.code, 'CERT_VALID');
  assert.strictEqual(valid.spiffeId, issued.spiffeId);
  assert.ok(valid.remainingMs > 0);

  // 4. Reject tampered payload (INVALID_SIGNATURE)
  const tampered = svc.verifyWorkloadCert({
    cert: { ...issued.cert, serviceName: 'evil-admin' },
    signatureB64: issued.signatureB64,
    nowMs: t0 + 3600000
  });
  assert.strictEqual(tampered.valid, false);
  assert.strictEqual(tampered.code, 'INVALID_SIGNATURE');

  // 5. Reject expired cert (CERT_EXPIRED)
  const expired = svc.verifyWorkloadCert({
    cert: issued.cert,
    signatureB64: issued.signatureB64,
    nowMs: t0 + 169 * 3600000
  });
  assert.strictEqual(expired.valid, false);
  assert.strictEqual(expired.code, 'CERT_EXPIRED');

  // 6. Revoke cert -> CERT_REVOKED immediately & excluded from default list
  const revokedRes = svc.revokeWorkloadCert(issued.serial, {
    reason: 'pod_compromised',
    actor: 'sec-admin',
    nowMs: t0 + 7200000
  });
  assert.strictEqual(revokedRes.ok, true);
  assert.strictEqual(revokedRes.revoked, true);

  const verifyRevoked = svc.verifyWorkloadCert({
    cert: issued.cert,
    signatureB64: issued.signatureB64,
    nowMs: t0 + 7205000
  });
  assert.strictEqual(verifyRevoked.valid, false);
  assert.strictEqual(verifyRevoked.code, 'CERT_REVOKED');

  assert.strictEqual(svc.listWorkloadCerts({ includeRevoked: false, nowMs: t0 + 7205000 }).length, 0);
  assert.strictEqual(svc.listWorkloadCerts({ includeRevoked: true, nowMs: t0 + 7205000 }).length, 1);

  // 7. Compile Caddy v2.11 require_and_verify client_authentication JSON (0 private keys!)
  const caddyPolicy = svc.compileCaddyMtlsPolicy({
    allowedSpiffeIds: [issued.spiffeId],
    mode: 'require_and_verify'
  });
  assert.strictEqual(caddyPolicy.ok, true);
  assert.strictEqual(caddyPolicy.mode, 'require_and_verify');
  assert.strictEqual(caddyPolicy.caddyClientAuth.mode, 'require_and_verify');
  assert.deepStrictEqual(caddyPolicy.allowedSpiffeIds, [issued.spiffeId]);
  assert.ok(!JSON.stringify(caddyPolicy).includes(PRIVATE_KEY_MARKER), 'Caddy mTLS policy must NEVER expose private key');
}

/**
 * Verifies dual RPM+TPM token buckets, IETF RateLimit + 429 Retry-After headers,
 * isolated AI wallet-drain burst simulation, and Caddy rate-limit compilation.
 * @param {string} tmpRoot
 */
function testApiRateLimitService(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'ratelimit-data');
  const svc = new ApiRateLimitService({ dataDir });
  const t0 = Date.UTC(2026, 10, 27, 11, 0, 0);

  assert.ok(PLAN_PRESETS.free && PLAN_PRESETS.pro && PLAN_PRESETS.enterprise);

  // 1. Save AI TPM-protected policy
  const aiPolicy = svc.saveRateLimitPolicy({
    id: 'ai-chat-free',
    projectId: 'proj_ai',
    name: 'AI Chat Free Tier',
    planTier: 'free',
    rpmLimit: 30,
    tpmLimit: 10000,
    burstMultiplier: 1.0,
    windowSec: 60
  });
  assert.strictEqual(aiPolicy.id, 'ai-chat-free');
  assert.strictEqual(svc.listRateLimitPolicies().length, 1);
  assert.ok(fs.existsSync(path.join(dataDir, 'ratelimit-policies.json')));

  // 2. Dual bucket: TPM saturates before RPM! (2 requests * 4000 = 8000 <= 10000 allowed; 3rd * 4000 -> 429 TPM_EXCEEDED!)
  const r1 = svc.consumeTokenBucket({ policyId: aiPolicy.id, clientKey: 'tenant-1', tokens: 4000, nowMs: t0 });
  assert.strictEqual(r1.allowed, true);
  assert.strictEqual(r1.httpStatus, 200);
  assert.strictEqual(r1.remainingTpm, 6000);
  assert.ok(r1.headers.RateLimit && r1.headers['RateLimit-Policy']);
  assert.strictEqual(r1.headers['Retry-After'], undefined);

  const r2 = svc.consumeTokenBucket({ policyId: aiPolicy.id, clientKey: 'tenant-1', tokens: 4000, nowMs: t0 });
  assert.strictEqual(r2.allowed, true);
  assert.strictEqual(r2.remainingTpm, 2000);

  const r3 = svc.consumeTokenBucket({ policyId: aiPolicy.id, clientKey: 'tenant-1', tokens: 4000, nowMs: t0 });
  assert.strictEqual(r3.allowed, false);
  assert.strictEqual(r3.httpStatus, 429);
  assert.strictEqual(r3.throttleReason, 'TPM_EXCEEDED');
  assert.ok(Number(r3.headers['Retry-After']) >= 1, 'HTTP 429 must emit Retry-After >= 1');
  assert.ok(r3.headers.RateLimit.includes('r=2000'));

  // Refill after 60s restores full bucket
  const rRefill = svc.consumeTokenBucket({ policyId: aiPolicy.id, clientKey: 'tenant-1', tokens: 4000, nowMs: t0 + 60000 });
  assert.strictEqual(rRefill.allowed, true);

  // 3. RPM saturation check (0 tokens, rpmLimit = 2, burst = 1.0)
  const rpmPolicy = svc.saveRateLimitPolicy({
    id: 'strict-rpm',
    name: 'Strict RPM',
    planTier: 'free',
    rpmLimit: 2,
    tpmLimit: 100000,
    burstMultiplier: 1.0,
    windowSec: 60
  });
  assert.strictEqual(svc.consumeTokenBucket({ policyId: rpmPolicy.id, clientKey: 'ip-1', tokens: 0, nowMs: t0 }).allowed, true);
  assert.strictEqual(svc.consumeTokenBucket({ policyId: rpmPolicy.id, clientKey: 'ip-1', tokens: 0, nowMs: t0 + 5 }).allowed, true);
  const rpmBlock = svc.consumeTokenBucket({ policyId: rpmPolicy.id, clientKey: 'ip-1', tokens: 0, nowMs: t0 + 10 });
  assert.strictEqual(rpmBlock.allowed, false);
  assert.strictEqual(rpmBlock.httpStatus, 429);
  assert.strictEqual(rpmBlock.throttleReason, 'RPM_EXCEEDED');
  assert.ok(Number(rpmBlock.headers['Retry-After']) >= 1);

  // 4. Isolated AI token burst simulation
  const sim = svc.simulateBurst({
    policyId: aiPolicy.id,
    requestsCount: 20,
    tokensPerRequest: 5000,
    intervalMs: 50,
    startMs: t0
  });
  assert.strictEqual(sim.ok, true);
  assert.strictEqual(sim.totalRequests, 20);
  assert.strictEqual(sim.allowedCount, 2);
  assert.strictEqual(sim.throttledCount, 18);
  assert.strictEqual(sim.first429AtIndex, 2);
  assert.strictEqual(sim.throttleReason, 'TPM_EXCEEDED');
  assert.ok(sim.estimatedWalletSavedUsd > 0);
  assert.ok(sim.sample429Headers && sim.sample429Headers['Retry-After']);
  assert.ok(sim.caddyConfig && sim.caddyConfig.caddyfile.includes('rate_limit'));

  // 5. Direct Caddy compiler check
  const caddyCfg = svc.compileCaddyRateLimitConfig(aiPolicy);
  assert.strictEqual(caddyCfg.ok, true);
  assert.strictEqual(caddyCfg.caddyJson.handler, 'rate_limit');
}

/**
 * Verifies BOTH singleton (`svc.fn`) AND destructured (`fn`) exports with dynamic `CULKIBO_DATA_DIR`.
 * @param {string} tmpRoot
 */
function testSingletonAndDestructuredExports(tmpRoot) {
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = path.join(tmpRoot, 'singleton-env');

  try {
    const t0 = Date.UTC(2026, 10, 27, 14, 0, 0);

    // MtlsMeshService singleton + destructured
    const init = mtlsMeshService.initTrustDomain('singleton.internal');
    assert.strictEqual(init.trustDomain, 'singleton.internal');

    const certRes = issueWorkloadCert({ serviceName: 'worker', namespace: 'edge', ttlHours: 12, nowMs: t0 });
    assert.strictEqual(verifyWorkloadCert({ cert: certRes.cert, signatureB64: certRes.signatureB64, nowMs: t0 + 1000 }).valid, true);
    assert.strictEqual(listWorkloadCerts({ nowMs: t0 + 1000 }).length, 1);

    const rev = revokeWorkloadCert(certRes.serial, { reason: 'test_revoke', actor: 'qa', nowMs: t0 + 2000 });
    assert.strictEqual(rev.revoked, true);
    assert.strictEqual(mtlsMeshService.verifyWorkloadCert({ cert: certRes.cert, signatureB64: certRes.signatureB64, nowMs: t0 + 3000 }).code, 'CERT_REVOKED');
    assert.strictEqual(compileCaddyMtlsPolicy({ allowedSpiffeIds: [certRes.spiffeId] }).mode, 'require_and_verify');

    // ApiRateLimitService singleton + destructured
    const pol = apiRateLimitService.saveRateLimitPolicy({
      id: 'singleton-rl',
      name: 'Singleton RL',
      planTier: 'pro',
      rpmLimit: 60,
      tpmLimit: 12000,
      burstMultiplier: 1.0
    });
    assert.strictEqual(listRateLimitPolicies().length, 1);
    const c1 = consumeTokenBucket({ policyId: pol.id, clientKey: 'c1', tokens: 6000, nowMs: t0 });
    assert.strictEqual(c1.allowed, true);
    const sim = simulateBurst({ policyId: pol.id, requestsCount: 10, tokensPerRequest: 5000, intervalMs: 50, startMs: t0 });
    assert.ok(sim.throttledCount > 0);
    assert.strictEqual(compileCaddyRateLimitConfig(pol.id).ok, true);
    assert.strictEqual(initTrustDomain('singleton.internal').ok, true);
  } finally {
    if (prevDataDir === undefined) {
      delete process.env.CULKIBO_DATA_DIR;
    } else {
      process.env.CULKIBO_DATA_DIR = prevDataDir;
    }
  }
}

async function runAllTests() {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c15-mtls-rl-'));
  try {
    testMtlsMeshService(tmpRoot);
    testApiRateLimitService(tmpRoot);
    testSingletonAndDestructuredExports(tmpRoot);
    console.log('✅ mtls-and-ratelimit.test.js PASSED (SPIFFE Ed25519 CA, CRL/expiry, Caddy mTLS, dual RPM+TPM 429, burst sim, singleton+destructured)');
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runAllTests().catch((err) => {
    console.error('❌ mtls-and-ratelimit.test.js FAILED:', err);
    process.exit(1);
  });
}

module.exports = runAllTests;
