'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const passkeyService = require('../server/services/passkeyService');
const secretLeaseService = require('../server/services/secretLeaseService');
const cveDriftService = require('../server/services/cveDriftService');

const {
  PasskeyService,
  decodeCbor,
  parseAuthenticatorData,
  coseKeyToKeyObject
} = passkeyService;

const {
  SecretLeaseService,
  MAX_BREAK_GLASS_TTL_SEC,
  DEFAULT_ROTATION_MAX_AGE_DAYS
} = secretLeaseService;

const {
  CveDriftService,
  OSV_BATCH_URL,
  MAX_BATCH_SIZE
} = cveDriftService;

// Minimal RFC 8949 CBOR encoder strictly for test fixture generation
/** @param {number} major @param {number} len */
function encodeCborHead(major, len) {
  const m = major << 5;
  if (len < 24) return Buffer.from([m | len]);
  if (len < 256) return Buffer.from([m | 24, len]);
  if (len < 65536) {
    const b = Buffer.alloc(3);
    b[0] = m | 25;
    b.writeUInt16BE(len, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = m | 26;
  b.writeUInt32BE(len, 1);
  return b;
}

/** @param {any} val @returns {Buffer} */
function encodeCbor(val) {
  if (typeof val === 'number' && Number.isInteger(val)) {
    if (val >= 0) return encodeCborHead(0, val);
    return encodeCborHead(1, -1 - val);
  }
  if (Buffer.isBuffer(val)) {
    return Buffer.concat([encodeCborHead(2, val.length), val]);
  }
  if (typeof val === 'string') {
    const b = Buffer.from(val, 'utf8');
    return Buffer.concat([encodeCborHead(3, b.length), b]);
  }
  if (Array.isArray(val)) {
    return Buffer.concat([encodeCborHead(4, val.length), ...val.map(encodeCbor)]);
  }
  if (val instanceof Map) {
    /** @type {Buffer[]} */
    const parts = [encodeCborHead(5, val.size)];
    for (const [k, v] of val.entries()) {
      parts.push(encodeCbor(k), encodeCbor(v));
    }
    return Buffer.concat(parts);
  }
  if (val === false) return Buffer.from([0xf4]);
  if (val === true) return Buffer.from([0xf5]);
  if (val === null) return Buffer.from([0xf6]);
  throw new Error(`Unsupported CBOR test fixture type: ${typeof val}`);
}

/**
 * Builds a realistic WebAuthn `attestationObject` CBOR buffer containing `authData`
 * with embedded credentialId + COSE public key.
 * @param {{ rpId: string, credentialId: Buffer, coseKeyMap: Map<any, any>, signCount?: number, flags?: number }} opts
 */
function buildMockAttestationObject({ rpId, credentialId, coseKeyMap, signCount = 1, flags = 0x45 }) {
  const rpIdHash = crypto.createHash('sha256').update(rpId, 'utf8').digest();
  const flagsBuf = Buffer.from([flags]); // UP (0x01) + UV (0x04) + AT (0x40) = 0x45
  const countBuf = Buffer.alloc(4);
  countBuf.writeUInt32BE(signCount, 0);
  const aaguid = Buffer.alloc(16, 0x11);
  const lenBuf = Buffer.alloc(2);
  lenBuf.writeUInt16BE(credentialId.length, 0);
  const coseBytes = encodeCbor(coseKeyMap);
  const authData = Buffer.concat([rpIdHash, flagsBuf, countBuf, aaguid, lenBuf, credentialId, coseBytes]);

  const attMap = new Map();
  attMap.set('fmt', 'none');
  attMap.set('attStmt', new Map());
  attMap.set('authData', authData);
  return { authData, attestationObject: encodeCbor(attMap) };
}

/**
 * Builds an assertion `authenticatorData` buffer (`rpIdHash` + `flags` + `signCount`).
 * @param {string} rpId
 * @param {number} signCount
 * @param {number} [flags]
 */
function buildAssertionAuthData(rpId, signCount, flags = 0x05) {
  const rpIdHash = crypto.createHash('sha256').update(rpId, 'utf8').digest();
  const flagsBuf = Buffer.from([flags]);
  const countBuf = Buffer.alloc(4);
  countBuf.writeUInt32BE(signCount, 0);
  return Buffer.concat([rpIdHash, flagsBuf, countBuf]);
}

async function testPasskeyService(tmpRoot) {
  const svc = new PasskeyService({ dataDir: path.join(tmpRoot, 'passkeys-data') });
  const origin = 'https://panel.culkibo.dev';
  const rpId = 'panel.culkibo.dev';

  // 1. CBOR roundtrip sanity (ints, negative ints, bytes, text, arrays, maps, bools, null)
  const sampleMap = new Map();
  sampleMap.set(1, 2);
  sampleMap.set(-7, 'ES256');
  sampleMap.set('ok', [true, false, null, Buffer.from([1, 2, 3])]);
  const decoded = decodeCbor(encodeCbor(sampleMap));
  assert.strictEqual(decoded.get(1), 2);
  assert.strictEqual(decoded.get(-7), 'ES256');
  assert.deepStrictEqual(decoded.get('ok')[3], Buffer.from([1, 2, 3]));

  // 2. Live ES256 (EC2 P-256, alg: -7) Registration + Assertion + Security Rejections
  const ecPair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const ecJwk = ecPair.publicKey.export({ format: 'jwk' });
  const ecCose = new Map([
    [1, 2],   // kty: EC2
    [3, -7],  // alg: ES256
    [-1, 1],  // crv: P-256
    [-2, Buffer.from(String(ecJwk.x), 'base64url')],
    [-3, Buffer.from(String(ecJwk.y), 'base64url')]
  ]);
  const ecKeyInfo = coseKeyToKeyObject(ecCose);
  assert.strictEqual(ecKeyInfo.alg, -7);
  assert.strictEqual(ecKeyInfo.algName, 'ES256');

  const regStart = svc.beginRegistration({ userId: 'u_alice', username: 'alice@culkibo.dev', rpId, origin });
  const ecCredId = crypto.randomBytes(32);
  const { attestationObject: ecAttObj, authData: ecAuthData } = buildMockAttestationObject({
    rpId,
    credentialId: ecCredId,
    coseKeyMap: ecCose,
    signCount: 5
  });
  const parsedAd = parseAuthenticatorData(ecAuthData);
  assert.strictEqual(parsedAd.signCount, 5);
  assert.strictEqual(parsedAd.credentialIdB64Url, ecCredId.toString('base64url'));

  const regClientData = Buffer.from(JSON.stringify({
    type: 'webauthn.create',
    challenge: regStart.challenge,
    origin
  }), 'utf8');

  const regRes = svc.finishRegistration({
    userId: 'u_alice',
    challengeId: regStart.challengeId,
    clientDataJSON: regClientData,
    attestationObject: ecAttObj,
    label: 'MacBook TouchID',
    expectedOrigin: origin,
    expectedRpId: rpId
  });
  assert.strictEqual(regRes.ok, true, `ES256 registration must succeed: ${JSON.stringify(regRes)}`);
  assert.strictEqual(regRes.credential?.alg, -7);
  assert.strictEqual(regRes.credential?.signCount, 5);

  // Challenge replay on registration MUST fail
  const regReplay = svc.finishRegistration({
    userId: 'u_alice',
    challengeId: regStart.challengeId,
    clientDataJSON: regClientData,
    attestationObject: ecAttObj,
    expectedOrigin: origin,
    expectedRpId: rpId
  });
  assert.strictEqual(regReplay.valid, false);
  assert.strictEqual(regReplay.reason, 'CHALLENGE_NOT_FOUND_OR_REPLAYED');

  // Helper to sign assertion with EC private key
  const signEcAssertion = (/** @type {string} */ challenge, /** @type {string} */ useOrigin, /** @type {string} */ useRpId, /** @type {number} */ count) => {
    const cd = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: useOrigin }), 'utf8');
    const ad = buildAssertionAuthData(useRpId, count);
    const signed = Buffer.concat([ad, crypto.createHash('sha256').update(cd).digest()]);
    const sig = crypto.sign('sha256', signed, ecPair.privateKey);
    return { cd, ad, sig };
  };

  // Valid ES256 login (signCount 5 -> 6)
  const auth1 = svc.beginAuthentication({ userId: 'u_alice', rpId, origin });
  const a1 = signEcAssertion(auth1.challenge, origin, rpId, 6);
  const auth1Res = svc.finishAuthentication({
    challengeId: auth1.challengeId,
    credentialId: ecCredId.toString('base64url'),
    clientDataJSON: a1.cd,
    authenticatorData: a1.ad,
    signature: a1.sig,
    expectedOrigin: origin,
    expectedRpId: rpId,
    requireUv: true
  });
  assert.strictEqual(auth1Res.valid, true, `ES256 assertion must pass: ${JSON.stringify(auth1Res)}`);
  assert.strictEqual(auth1Res.signCount, 6);

  // Replayed authentication challenge MUST fail
  const authReplay = svc.finishAuthentication({
    challengeId: auth1.challengeId,
    credentialId: ecCredId.toString('base64url'),
    clientDataJSON: a1.cd,
    authenticatorData: a1.ad,
    signature: a1.sig,
    expectedOrigin: origin,
    expectedRpId: rpId
  });
  assert.strictEqual(authReplay.valid, false);
  assert.strictEqual(authReplay.reason, 'CHALLENGE_NOT_FOUND_OR_REPLAYED');

  // Bad origin MUST fail
  const authBadOrigin = svc.beginAuthentication({ userId: 'u_alice', rpId, origin });
  const aBadOrigin = signEcAssertion(authBadOrigin.challenge, 'https://evil.attacker.com', rpId, 7);
  const badOriginRes = svc.finishAuthentication({
    challengeId: authBadOrigin.challengeId,
    credentialId: ecCredId.toString('base64url'),
    clientDataJSON: aBadOrigin.cd,
    authenticatorData: aBadOrigin.ad,
    signature: aBadOrigin.sig,
    expectedOrigin: origin,
    expectedRpId: rpId
  });
  assert.strictEqual(badOriginRes.valid, false);
  assert.strictEqual(badOriginRes.reason, 'ORIGIN_MISMATCH');

  // Bad rpIdHash MUST fail
  const authBadRp = svc.beginAuthentication({ userId: 'u_alice', rpId, origin });
  const aBadRp = signEcAssertion(authBadRp.challenge, origin, 'other-rp.example.com', 7);
  const badRpRes = svc.finishAuthentication({
    challengeId: authBadRp.challengeId,
    credentialId: ecCredId.toString('base64url'),
    clientDataJSON: aBadRp.cd,
    authenticatorData: aBadRp.ad,
    signature: aBadRp.sig,
    expectedOrigin: origin,
    expectedRpId: rpId
  });
  assert.strictEqual(badRpRes.valid, false);
  assert.strictEqual(badRpRes.reason, 'RP_ID_HASH_MISMATCH');

  // Regressed signCount (stored=6, received=6 -> cloned authenticator!) MUST fail
  const authCloned = svc.beginAuthentication({ userId: 'u_alice', rpId, origin });
  const aCloned = signEcAssertion(authCloned.challenge, origin, rpId, 6);
  const clonedRes = svc.finishAuthentication({
    challengeId: authCloned.challengeId,
    credentialId: ecCredId.toString('base64url'),
    clientDataJSON: aCloned.cd,
    authenticatorData: aCloned.ad,
    signature: aCloned.sig,
    expectedOrigin: origin,
    expectedRpId: rpId
  });
  assert.strictEqual(clonedRes.valid, false);
  assert.strictEqual(clonedRes.reason, 'SIGN_COUNT_REGRESSION');

  // 3. Live Ed25519 (OKP, alg: -8) Registration + Assertion
  const edPair = crypto.generateKeyPairSync('ed25519');
  const edJwk = edPair.publicKey.export({ format: 'jwk' });
  const edCose = new Map([
    [1, 1],   // kty: OKP
    [3, -8],  // alg: EdDSA (Ed25519)
    [-1, 6],  // crv: Ed25519
    [-2, Buffer.from(String(edJwk.x), 'base64url')]
  ]);
  const edRegStart = svc.beginRegistration({ userId: 'u_alice', username: 'alice@culkibo.dev', rpId, origin });
  const edCredId = crypto.randomBytes(24);
  const { attestationObject: edAttObj } = buildMockAttestationObject({
    rpId,
    credentialId: edCredId,
    coseKeyMap: edCose,
    signCount: 0
  });
  const edRegRes = svc.finishRegistration({
    userId: 'u_alice',
    challengeId: edRegStart.challengeId,
    clientDataJSON: Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: edRegStart.challenge, origin }), 'utf8'),
    attestationObject: edAttObj,
    label: 'YubiKey 5 Ed25519',
    expectedOrigin: origin,
    expectedRpId: rpId
  });
  assert.strictEqual(edRegRes.ok, true);
  assert.strictEqual(edRegRes.credential?.alg, -8);

  const edAuthStart = svc.beginAuthentication({ userId: 'u_alice', rpId, origin });
  const edCd = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: edAuthStart.challenge, origin }), 'utf8');
  const edAd = buildAssertionAuthData(rpId, 1);
  const edSig = crypto.sign(null, Buffer.concat([edAd, crypto.createHash('sha256').update(edCd).digest()]), edPair.privateKey);
  const edAuthRes = svc.finishAuthentication({
    challengeId: edAuthStart.challengeId,
    credentialId: edCredId.toString('base64url'),
    clientDataJSON: edCd,
    authenticatorData: edAd,
    signature: edSig,
    expectedOrigin: origin,
    expectedRpId: rpId
  });
  assert.strictEqual(edAuthRes.valid, true, `Ed25519 assertion must pass: ${JSON.stringify(edAuthRes)}`);
  assert.strictEqual(edAuthRes.algName, 'Ed25519');

  // List & revoke
  assert.strictEqual(svc.listPasskeys('u_alice').length, 2);
  assert.strictEqual(svc.revokePasskey(edCredId.toString('base64url'), 'u_bob').revoked, false, 'Cross-user revoke must fail');
  assert.strictEqual(svc.revokePasskey(edCredId.toString('base64url'), 'u_alice').revoked, true);
  assert.strictEqual(svc.listPasskeys('u_alice').length, 1);

  console.log('  ✓ 1. Zero-Dep WebAuthn Passkeys: RFC 8949 CBOR, ES256 (P-256) & Ed25519 registration/assertions, replay/origin/rpIdHash/signCount-regression rejections verified');
}

async function testSecretLeaseService(tmpRoot) {
  const leaseDir = path.join(tmpRoot, 'leases-data');
  const svc = new SecretLeaseService({ dataDir: leaseDir });
  const t0 = Date.UTC(2026, 10, 27, 12, 0, 0);

  // 1. Issue lease, verify ZERO plaintext token on disk, validate -> expire fail-closed -> revoke
  const issued = svc.issueLease({
    projectId: 'proj_api',
    secretKey: 'STRIPE_SECRET_KEY',
    scope: 'read',
    ttlSec: 300,
    issuedBy: 'ci-bot',
    reason: 'deploy verification',
    nowMs: t0
  });
  assert.ok(issued.token.startsWith('ckl_'));
  assert.strictEqual(issued.lease.ttlSec, 300);

  const rawDisk = fs.readFileSync(path.join(leaseDir, 'secret-leases.json'), 'utf8');
  assert.ok(!rawDisk.includes(issued.token), 'Plaintext lease token MUST NEVER be written to disk');

  const okVal = svc.validateLease(issued.token, { nowMs: t0 + 100 * 1000 });
  assert.strictEqual(okVal.valid, true);
  assert.strictEqual(okVal.lease?.secretKey, 'STRIPE_SECRET_KEY');

  // Fail closed past expiry
  const expVal = svc.validateLease(issued.token, { nowMs: t0 + 301 * 1000 });
  assert.strictEqual(expVal.valid, false);
  assert.strictEqual(expVal.reason, 'EXPIRED');

  // Renew while active, then revoke -> fail closed REVOKED
  const renewed = svc.renewLease(issued.lease.id, { extendSec: 600, nowMs: t0 + 100 * 1000 });
  assert.strictEqual(renewed.ok, true);
  const revoked = svc.revokeLease(issued.lease.id, { revokedBy: 'pablo', nowMs: t0 + 120 * 1000 });
  assert.strictEqual(revoked.revoked, true);
  const revVal = svc.validateLease(issued.token, { nowMs: t0 + 125 * 1000 });
  assert.strictEqual(revVal.valid, false);
  assert.strictEqual(revVal.reason, 'REVOKED');

  // 2. Break-glass: reject short reason, hard-clamp TTL <= 900s (15 min), trigger alert, non-renewable
  assert.strictEqual(MAX_BREAK_GLASS_TTL_SEC, 900);
  assert.throws(
    () => svc.issueBreakGlassToken({ userId: 'u_admin', username: 'pablo', reason: 'too short' }),
    (/** @type {any} */ err) => err && err.code === 'INVALID_BREAK_GLASS_REASON',
    'Break-glass reason < 10 chars MUST be rejected'
  );
  let alertFired = null;
  const bg = svc.issueBreakGlassToken({
    userId: 'u_admin',
    username: 'pablo',
    reason: 'INC-2026-42 production DB failover emergency access',
    ttlSec: 99999, // must hard-clamp to 900s!
    onAlert: (ev) => { alertFired = ev; },
    nowMs: t0
  });
  assert.strictEqual(bg.lease.ttlSec, 900, 'Break-glass TTL MUST hard-clamp to 900s (15m)');
  assert.strictEqual(bg.lease.kind, 'break_glass');
  assert.strictEqual(bg.alertDispatched, true);
  assert.ok(alertFired && alertFired.severity === 'critical');
  assert.strictEqual(svc.validateLease(bg.token, { nowMs: t0 + 600 * 1000 }).valid, true);
  assert.strictEqual(svc.validateLease(bg.token, { nowMs: t0 + 901 * 1000 }).reason, 'EXPIRED');
  assert.strictEqual(svc.renewLease(bg.lease.id, { extendSec: 300, nowMs: t0 + 100 * 1000 }).reason, 'BREAK_GLASS_NON_RENEWABLE');

  // 3. 90-day secret rotation audit (ZERO plaintext values read or returned)
  assert.strictEqual(DEFAULT_ROTATION_MAX_AGE_DAYS, 90);
  const dayMs = 24 * 60 * 60 * 1000;
  const audit = svc.auditSecretRotationAges([
    {
      id: 'proj_payments',
      name: 'Payments API',
      env: {
        OLD_STRIPE_KEY: 'sk_live_NEVER_LEAK_THIS_VALUE',
        FRESH_JWT_SECRET: 'super_secret_fresh_value'
      },
      envMeta: {
        OLD_STRIPE_KEY: { updatedAt: new Date(t0 - 140 * dayMs).toISOString() },
        FRESH_JWT_SECRET: { updatedAt: new Date(t0 - 15 * dayMs).toISOString() }
      }
    }
  ], { maxAgeDays: 90, nowMs: t0 });

  assert.strictEqual(audit.totalKeys, 2);
  assert.strictEqual(audit.staleCount, 1);
  assert.strictEqual(audit.freshCount, 1);
  assert.strictEqual(audit.staleKeys[0].key, 'OLD_STRIPE_KEY');
  assert.strictEqual(audit.staleKeys[0].ageDays, 140);
  const serializedAudit = JSON.stringify(audit);
  assert.ok(!serializedAudit.includes('sk_live_NEVER_LEAK_THIS_VALUE'), 'Rotation audit MUST NEVER leak secret values');

  console.log('  ✓ 2. Secret Leases & Break-Glass: HMAC-only disk storage, fail-closed expiry/revoke, 15m hard-cap break-glass alert & 90d rotation audit verified');
}

async function testCveDriftService(tmpRoot) {
  assert.strictEqual(OSV_BATCH_URL, 'https://api.osv.dev/v1/querybatch');
  assert.strictEqual(MAX_BATCH_SIZE, 500);

  const svc = new CveDriftService({ dataDir: path.join(tmpRoot, 'cve-data') });
  const t0 = Date.UTC(2026, 10, 27, 12, 0, 0);

  // Build 505 synthetic PURLs to prove strict <= 500-item chunking -> exact 2 OSV batch POSTs!
  const syntheticComponents = Array.from({ length: 505 }, (_, i) => ({
    name: `pkg-${String(i).padStart(4, '0')}`,
    version: '1.0.0',
    purl: `pkg:npm/pkg-${String(i).padStart(4, '0')}@1.0.0`
  }));

  /** @type {Array<{ url: string, count: number }>} */
  const batchCalls = [];
  const mockFetch = async (/** @type {string} */ url, /** @type {any} */ init) => {
    assert.strictEqual(url, OSV_BATCH_URL, 'Must only call allowlisted OSV batch URL');
    const body = JSON.parse(init.body);
    batchCalls.push({ url, count: body.queries.length });
    assert.ok(body.queries.length <= 500, 'Each OSV batch must be <= 500 items');
    const results = body.queries.map((/** @type {any} */ q) => {
      if (q.package.purl === 'pkg:npm/pkg-0001@1.0.0') {
        return {
          vulns: [{ id: 'GHSA-crit-0001', database_specific: { severity: 'CRITICAL' }, summary: 'Critical RCE test fixture' }]
        };
      }
      if (q.package.purl === 'pkg:npm/pkg-0504@1.0.0') {
        return {
          vulns: [{ id: 'GHSA-high-0504', database_specific: { severity: 'HIGH' }, summary: 'High SSRF test fixture in 2nd chunk' }]
        };
      }
      return {};
    });
    return { ok: true, status: 200, json: async () => ({ results }) };
  };

  // 1. Online batch scan across 505 PURLs -> exact 2 chunks (500 + 5), ranked critical > high
  const scan1 = await svc.scanSbom({
    components: syntheticComponents,
    allowNetwork: true,
    fetchImpl: mockFetch,
    nowMs: t0
  });
  assert.strictEqual(batchCalls.length, 2, '505 PURLs must split into exactly 2 OSV batches');
  assert.strictEqual(batchCalls[0].count, 500);
  assert.strictEqual(batchCalls[1].count, 5);
  assert.strictEqual(scan1.scannedPackages, 505);
  assert.strictEqual(scan1.vulnerablePackages, 2);
  assert.strictEqual(scan1.totalVulnerabilities, 2);
  assert.strictEqual(scan1.bySeverity.critical, 1);
  assert.strictEqual(scan1.bySeverity.high, 1);
  assert.strictEqual(scan1.findings[0].severity, 'critical', 'Findings must be ranked critical > high');
  assert.strictEqual(scan1.findings[1].severity, 'high');
  assert.strictEqual(scan1.cached, false);
  assert.strictEqual(scan1.offline, false);

  // 2. 24h Cache Hit (1 hour later -> 0 additional network calls!)
  const scanCached = await svc.scanSbom({
    components: syntheticComponents,
    allowNetwork: true,
    fetchImpl: mockFetch,
    nowMs: t0 + 60 * 60 * 1000
  });
  assert.strictEqual(batchCalls.length, 2, 'Valid 24h cache must serve without hitting OSV again');
  assert.strictEqual(scanCached.cached, true);
  assert.strictEqual(scanCached.totalVulnerabilities, 2);
  assert.ok(svc.getLastScan(), 'getLastScan() must recover persisted cache');

  // 3. Clean Offline Fallback (when allowNetwork=false on fresh uncached service)
  const freshOfflineSvc = new CveDriftService({ dataDir: path.join(tmpRoot, 'cve-offline') });
  const offlineRes = await freshOfflineSvc.scanSbom({
    components: syntheticComponents.slice(0, 10),
    allowNetwork: false,
    nowMs: t0
  });
  assert.strictEqual(offlineRes.offline, true);
  assert.strictEqual(offlineRes.cached, false);
  assert.strictEqual(offlineRes.scannedPackages, 10);
  assert.strictEqual(offlineRes.batchesSent, 0);

  console.log('  ✓ 3. Runtime SBOM CVE Drift Scanner: OSV.dev 500-item chunking (505 PURLs -> 2 batches), severity ranking, 24h disk cache & clean offline fallback verified');
}

async function runPasskeyLeaseCveTests() {
  console.log('\n🔐 Testing Zero-Dep WebAuthn Passkeys, Secret Leases/Break-Glass & OSV.dev CVE Drift Scanner...\n');
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-cycle8-sec-'));
  try {
    await testPasskeyService(tmpRoot);
    await testSecretLeaseService(tmpRoot);
    await testCveDriftService(tmpRoot);
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
  console.log('\n✅ All Passkey, Secret Lease & CVE Drift Scanner tests PASSED!\n');
}

module.exports = runPasskeyLeaseCveTests;

if (require.main === module) {
  runPasskeyLeaseCveTests().catch((err) => {
    console.error('❌ Passkey/Lease/CVE test FAILED:', err);
    process.exit(1);
  });
}
