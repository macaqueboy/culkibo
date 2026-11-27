'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const webhookEventBus = require('../server/services/webhookEventBus');
const objectStorageService = require('../server/services/objectStorageService');

const {
  WebhookEventBus,
  signStandardWebhook,
  verifyStandardWebhookSignature,
  generateWebhookSecret,
  computeBackoffMs,
  MAX_DLQ_ENTRIES,
  DEFAULT_TOLERANCE_SEC
} = webhookEventBus;

const {
  ObjectStorageService,
  S3_PRESETS,
  generatePresignedUrl,
  buildBucketCorsXml,
  buildLifecycleXml,
  MAX_PRESIGN_EXPIRES_SEC
} = objectStorageService;

/** Starts a local HTTP receiver whose status code can be toggled to test DLQ capture + replay. */
async function startMockWebhookReceiver() {
  let statusCode = 503;
  /** @type {Array<{ headers: Record<string, any>, body: string }>} */
  const received = [];

  const srv = http.createServer((req, res) => {
    /** @type {Buffer[]} */
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      received.push({ headers: { ...req.headers }, body: Buffer.concat(chunks).toString('utf8') });
      res.writeHead(statusCode, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ received: statusCode < 300 }));
    });
  });

  await new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve(undefined)));
  const addr = /** @type {import('net').AddressInfo} */ (srv.address());
  return {
    url: `http://127.0.0.1:${addr.port}/hook`,
    received,
    setStatusCode: (/** @type {number} */ code) => { statusCode = code; },
    stop: () => new Promise((resolve) => {
      if (typeof srv.closeAllConnections === 'function') srv.closeAllConnections();
      srv.close(() => resolve(undefined));
    })
  };
}

async function testWebhookEventBus(tmpRoot) {
  assert.strictEqual(MAX_DLQ_ENTRIES, 500);
  assert.strictEqual(DEFAULT_TOLERANCE_SEC, 300);

  // 1. Standard-Webhooks signing, dual-secret rotation acceptance & >300s replay rejection
  const sec1 = generateWebhookSecret();
  const sec2 = generateWebhookSecret();
  assert.ok(sec1.startsWith('whsec_') && sec2.startsWith('whsec_'));

  const nowSec = 1795780000;
  const payload = JSON.stringify({ event: 'deploy.succeeded', projectId: 'proj_1' });
  const dualHeaders = signStandardWebhook({
    msgId: 'msg_test_001',
    timestampSec: nowSec,
    payload,
    secret: sec2,
    secondarySecret: sec1
  });
  assert.ok(dualHeaders['webhook-signature'].split(' ').length === 2, 'Dual-secret header must emit 2 v1 signatures');
  assert.strictEqual(
    verifyStandardWebhookSignature(payload, dualHeaders, sec1, { nowSec }).valid,
    true,
    'Grace-window secondary secret must verify cleanly'
  );
  assert.strictEqual(
    verifyStandardWebhookSignature(payload, dualHeaders, sec2, { nowSec }).valid,
    true,
    'Primary secret must verify cleanly'
  );
  assert.strictEqual(
    verifyStandardWebhookSignature(payload, dualHeaders, generateWebhookSecret(), { nowSec }).valid,
    false,
    'Unrelated secret must fail verification'
  );

  // >300s stale timestamp rejection
  const staleRes = verifyStandardWebhookSignature(payload, dualHeaders, sec2, { nowSec: nowSec + 305, toleranceSec: 300 });
  assert.strictEqual(staleRes.valid, false);
  assert.strictEqual(staleRes.reason, 'TIMESTAMP_OUT_OF_RANGE');

  // Backoff bounds check
  const b1 = computeBackoffMs(1, { baseMs: 1000, jitterRatio: 0.2, rng: () => 0.5 });
  const b3 = computeBackoffMs(3, { baseMs: 1000, jitterRatio: 0.2, rng: () => 0.5 });
  assert.strictEqual(b1, 1000);
  assert.strictEqual(b3, 4000);

  // 2. SSRF blocking on initial dispatch AND DLQ replay (Portainer CVE-2026-134756)
  const bus = new WebhookEventBus({ dataDir: path.join(tmpRoot, 'webhooks-data') });
  let networkCalls = 0;
  const countingFetch = async () => {
    networkCalls++;
    return { ok: true, status: 200 };
  };

  // Block 127.0.0.1, 169.254.169.254, and DNS resolving to RFC1918 private IP
  const subLoopback = bus.upsertSubscription({ url: 'http://127.0.0.1:9999/internal', events: ['deploy.*'] });
  assert.strictEqual(subLoopback.created, true);
  assert.ok(subLoopback.secret && subLoopback.secret.startsWith('whsec_'));

  const subMeta = bus.upsertSubscription({ url: 'http://169.254.169.254/latest/meta-data/', events: ['*'] });
  const subRebind = bus.upsertSubscription({ url: 'https://hooks.evil-rebind.example/v1', events: ['*'] });

  // listSubscriptions MUST NOT leak raw whsec_ secrets
  const listed = bus.listSubscriptions();
  assert.strictEqual(listed.length, 3);
  const serializedList = JSON.stringify(listed);
  assert.ok(!serializedList.includes(subLoopback.secret), 'listSubscriptions MUST NEVER expose raw whsec_ secret');

  // Dispatch to 127.0.0.1 (allowLoopback=false) -> blocked
  const dLoop = await bus.dispatchEvent({
    eventType: 'deploy.failed',
    subscriptionId: subLoopback.subscription.id,
    fetchImpl: countingFetch,
    allowLoopback: false
  });
  assert.strictEqual(dLoop.ok, false);
  assert.strictEqual(dLoop.blockedCount, 1);
  assert.strictEqual(dLoop.deliveries[0].errorCode, 'SSRF_BLOCKED');

  // Dispatch to 169.254.169.254 EVEN WITH allowLoopback=true -> unconditionally blocked!
  const dMeta = await bus.dispatchEvent({
    eventType: 'deploy.failed',
    subscriptionId: subMeta.subscription.id,
    fetchImpl: countingFetch,
    allowLoopback: true
  });
  assert.strictEqual(dMeta.ok, false);
  assert.strictEqual(dMeta.blockedCount, 1);
  assert.strictEqual(dMeta.deliveries[0].errorCode, 'SSRF_BLOCKED');

  // Dispatch to DNS hostname resolving to RFC1918 10.0.0.42 -> blocked!
  const dRebind = await bus.dispatchEvent({
    eventType: 'deploy.failed',
    subscriptionId: subRebind.subscription.id,
    fetchImpl: countingFetch,
    dnsLookupImpl: async () => [{ address: '10.0.0.42', family: 4 }]
  });
  assert.strictEqual(dRebind.ok, false);
  assert.strictEqual(dRebind.blockedCount, 1);
  assert.strictEqual(dRebind.deliveries[0].errorCode, 'SSRF_BLOCKED');
  assert.strictEqual(networkCalls, 0, 'SSRF-blocked dispatches must make ZERO outbound HTTP calls');

  // DLQ replay MUST ALSO re-check DNS-resolved SSRF (DNS rebinding attack on replay!)
  const rebindDlqId = dRebind.deliveries[0].dlqId;
  const replayBlocked = await bus.replayDlqEntry(rebindDlqId, {
    fetchImpl: countingFetch,
    dnsLookupImpl: async () => [{ address: '192.168.1.10', family: 4 }]
  });
  assert.strictEqual(replayBlocked.ok, false);
  assert.strictEqual(replayBlocked.blockedBySsrf, true);
  assert.strictEqual(replayBlocked.errorCode, 'SSRF_BLOCKED');
  assert.strictEqual(networkCalls, 0, 'SSRF-blocked DLQ replay must make ZERO outbound HTTP calls');

  // 3. Live loopback receiver: 503 failure -> DLQ capture -> dual-secret rotation -> 200 replay verified!
  const receiver = await startMockWebhookReceiver();
  try {
    const liveSub = bus.upsertSubscription({ url: receiver.url, events: ['release.published'] });
    const initialSecret = /** @type {string} */ (liveSub.secret);

    receiver.setStatusCode(503);
    const failedDispatch = await bus.dispatchEvent({
      eventType: 'release.published',
      data: { version: '1.2.0' },
      subscriptionId: liveSub.subscription.id,
      allowLoopback: true,
      maxAttempts: 2
    });
    assert.strictEqual(failedDispatch.ok, false);
    assert.strictEqual(failedDispatch.dlqAddedCount, 1);
    const liveDlqId = failedDispatch.deliveries[0].dlqId;
    assert.ok(bus.listDlq({ status: 'failed' }).some((e) => e.id === liveDlqId));

    // Rotate secret before replay so replay carries BOTH new primary AND grace-window initialSecret
    const rotated = bus.rotateSecret(liveSub.subscription.id, { graceSec: 3600 });
    assert.strictEqual(rotated.ok, true);
    assert.notStrictEqual(rotated.secret, initialSecret);

    receiver.setStatusCode(200);
    const replayed = await bus.replayDlqEntry(liveDlqId, { allowLoopback: true });
    assert.strictEqual(replayed.ok, true);
    assert.strictEqual(replayed.replayed, true);
    assert.strictEqual(replayed.statusCode, 200);
    assert.strictEqual(replayed.entry?.status, 'replayed');

    const lastWire = receiver.received[receiver.received.length - 1];
    assert.strictEqual(verifyStandardWebhookSignature(lastWire.body, lastWire.headers, rotated.secret).valid, true);
    assert.strictEqual(verifyStandardWebhookSignature(lastWire.body, lastWire.headers, initialSecret).valid, true);
  } finally {
    await receiver.stop();
  }

  console.log('  ✓ 1. Standard-Webhooks Event Bus: whsec_ dual-secret rotation, >300s replay block, DNS-resolved SSRF guard (dispatch + DLQ replay) & live DLQ replay verified');
}

async function testObjectStorageService() {
  const s3 = new ObjectStorageService();

  // 1. Pinned post-MinIO presets (Garage / RustFS / SeaweedFS) with 127.0.0.1 private defaults
  const presets = s3.listPresets();
  assert.strictEqual(presets.length, 3);
  assert.strictEqual(S3_PRESETS.garage.image, 'dxflrs/garage:v1.0.1');
  assert.strictEqual(S3_PRESETS.rustfs.image, 'rustfs/rustfs:1.0.0-alpha.45');
  assert.strictEqual(S3_PRESETS.seaweedfs.image, 'chrislusf/seaweedfs:3.85');
  for (const p of presets) {
    assert.strictEqual(p.bindAddress, '127.0.0.1', `${p.id} must default to 127.0.0.1 private bind`);
    assert.strictEqual(p.publicExpose, false);
  }

  // 2. Deterministic golden AWS SigV4 query-string presigned URL verification
  const fixedDate = new Date('2026-11-27T12:00:00.000Z');
  const presigned = generatePresignedUrl({
    endpoint: 'https://s3.culkibo.internal:9000',
    region: 'us-east-1',
    bucket: 'culkibo-backups',
    key: 'pg/2026/nightly dump.sql.zst',
    method: 'GET',
    accessKeyId: 'AKIAEXAMPLE123456',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    expiresIn: 900,
    nowDate: fixedDate
  });
  assert.strictEqual(presigned.ok, true);
  assert.strictEqual(presigned.algorithm, 'AWS4-HMAC-SHA256');
  assert.match(presigned.signature, /^[0-9a-f]{64}$/);
  assert.ok(!presigned.url.includes('wJalrXUtnFEMI'), 'Secret access key MUST NEVER appear in presigned URL');

  // Recompute golden SigV4 independently from scratch to assert exact spec-compliant signature!
  const canonicalUri = '/culkibo-backups/pg/2026/nightly%20dump.sql.zst';
  const canonicalQs = [
    'X-Amz-Algorithm=AWS4-HMAC-SHA256',
    'X-Amz-Credential=AKIAEXAMPLE123456%2F20261127%2Fus-east-1%2Fs3%2Faws4_request',
    'X-Amz-Date=20261127T120000Z',
    'X-Amz-Expires=900',
    'X-Amz-SignedHeaders=host'
  ].join('&');
  const canonicalReq = `GET\n${canonicalUri}\n${canonicalQs}\nhost:s3.culkibo.internal:9000\n\nhost\nUNSIGNED-PAYLOAD`;
  const sts = `AWS4-HMAC-SHA256\n20261127T120000Z\n20261127/us-east-1/s3/aws4_request\n${crypto.createHash('sha256').update(canonicalReq).digest('hex')}`;
  const kDate = crypto.createHmac('sha256', 'AWS4wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY').update('20261127').digest();
  const kRegion = crypto.createHmac('sha256', kDate).update('us-east-1').digest();
  const kService = crypto.createHmac('sha256', kRegion).update('s3').digest();
  const kSigning = crypto.createHmac('sha256', kService).update('aws4_request').digest();
  const expectedSig = crypto.createHmac('sha256', kSigning).update(sts).digest('hex');
  assert.strictEqual(presigned.signature, expectedSig, 'Presigned SigV4 signature must match exact AWS SigV4 spec vector');
  assert.ok(presigned.url.endsWith(`&X-Amz-Signature=${expectedSig}`));

  // 3. Traversal `../`, leading `/`, and `expiresIn` bounds (`<60` or `>604800`) rejections
  assert.strictEqual(MAX_PRESIGN_EXPIRES_SEC, 604800);
  assert.throws(
    () => generatePresignedUrl({
      endpoint: 'https://s3.culkibo.internal:9000',
      bucket: 'culkibo-backups',
      key: '../etc/passwd',
      accessKeyId: 'AKIA1',
      secretAccessKey: 'SEC1',
      expiresIn: 900
    }),
    (/** @type {any} */ err) => err && err.code === 'INVALID_OBJECT_KEY',
    'Path traversal "../" in S3 key MUST be rejected'
  );
  assert.throws(
    () => generatePresignedUrl({
      endpoint: 'https://s3.culkibo.internal:9000',
      bucket: 'culkibo-backups',
      key: 'ok.txt',
      accessKeyId: 'AKIA1',
      secretAccessKey: 'SEC1',
      expiresIn: 604801
    }),
    (/** @type {any} */ err) => err && err.code === 'INVALID_EXPIRES_IN',
    'expiresIn > 604800 MUST be rejected'
  );
  assert.throws(
    () => generatePresignedUrl({
      endpoint: 'https://s3.culkibo.internal:9000',
      bucket: 'culkibo-backups',
      key: 'ok.txt',
      accessKeyId: 'AKIA1',
      secretAccessKey: 'SEC1',
      expiresIn: 30
    }),
    (/** @type {any} */ err) => err && err.code === 'INVALID_EXPIRES_IN',
    'expiresIn < 60 MUST be rejected'
  );

  // 4. Bucket CORS XML (rejects * + allowCredentials) & Lifecycle XML
  assert.throws(
    () => buildBucketCorsXml([{ allowedOrigins: ['*'], allowedMethods: ['GET'], allowCredentials: true }]),
    (/** @type {any} */ err) => err && err.code === 'CORS_WILDCARD_CREDENTIALS_BLOCKED',
    'Wildcard "*" + allowCredentials=true MUST be rejected'
  );
  const corsXml = buildBucketCorsXml([
    {
      id: 'app-uploads',
      allowedOrigins: ['https://app.culkibo.dev'],
      allowedMethods: ['GET', 'PUT', 'HEAD'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      exposeHeaders: ['ETag'],
      maxAgeSeconds: 3600
    }
  ]);
  assert.ok(corsXml.includes('<CORSConfiguration'));
  assert.ok(corsXml.includes('<AllowedOrigin>https://app.culkibo.dev</AllowedOrigin>'));
  assert.ok(corsXml.includes('<MaxAgeSeconds>3600</MaxAgeSeconds>'));

  const lifecycleXml = buildLifecycleXml([
    { id: 'expire-old-backups', prefix: 'pg/', expirationDays: 30, abortMultipartDays: 7 }
  ]);
  assert.ok(lifecycleXml.includes('<LifecycleConfiguration'));
  assert.ok(lifecycleXml.includes('<Prefix>pg/</Prefix>'));
  assert.ok(lifecycleXml.includes('<Days>30</Days>'));
  assert.ok(lifecycleXml.includes('<DaysAfterInitiation>7</DaysAfterInitiation>'));

  console.log('  ✓ 2. Post-MinIO S3 Orchestrator: Garage/RustFS/SeaweedFS presets, golden AWS SigV4 vector, traversal/TTL guards & CORS/Lifecycle XML verified');
}

async function runWebhooksAndS3Tests() {
  console.log('\n📦 Testing Standard-Webhooks Event Bus/DLQ & Post-MinIO S3 SigV4 Orchestrator...\n');
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-cycle9-wh-s3-'));
  try {
    await testWebhookEventBus(tmpRoot);
    await testObjectStorageService();
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
  console.log('\n✅ All Standard-Webhooks & S3 Object Storage tests PASSED!\n');
}

module.exports = runWebhooksAndS3Tests;

if (require.main === module) {
  runWebhooksAndS3Tests().catch((err) => {
    console.error('❌ Webhooks & S3 test FAILED:', err);
    process.exit(1);
  });
}
