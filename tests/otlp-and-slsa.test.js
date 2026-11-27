'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const zlib = require('zlib');

const otlpExporter = require('../server/services/otlpExporter');
const supplyChainAttestor = require('../server/services/supplyChainAttestor');

const {
  OtlpExporter,
  formatTraceparent,
  parseTraceparent,
  newTraceId,
  newSpanId,
  MAX_SPAN_BUFFER
} = otlpExporter;

const {
  SupplyChainAttestor,
  dssePae,
  createStatementV1,
  STATEMENT_TYPE_V1,
  SLSA_PREDICATE_TYPE_V1,
  DSSE_PAYLOAD_TYPE
} = supplyChainAttestor;

/**
 * Starts a loopback mock OTLP/HTTP JSON collector server accepting gzip-compressed
 * `/v1/traces` and `/v1/metrics` requests, with switchable HTTP status code for fault injection.
 */
async function startMockOtlpCollector() {
  /** @type {Array<{ path: string, headers: Record<string, any>, rawBytes: number, payload: any }>} */
  const received = [];
  let statusCode = 200;
  let requestCount = 0;

  const srv = http.createServer((req, res) => {
    requestCount++;
    /** @type {Buffer[]} */
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const rawBuf = Buffer.concat(chunks);
      const encoding = String(req.headers['content-encoding'] || '').toLowerCase();
      let decodedStr = '';
      let parsed = null;
      try {
        const plain = encoding === 'gzip' ? zlib.gunzipSync(rawBuf) : rawBuf;
        decodedStr = plain.toString('utf8');
        parsed = JSON.parse(decodedStr);
      } catch (e) {
        parsed = null;
      }

      received.push({
        path: req.url || '',
        headers: { ...req.headers },
        rawBytes: rawBuf.length,
        payload: parsed
      });

      res.writeHead(statusCode, { 'Content-Type': 'application/json' });
      res.end(statusCode >= 200 && statusCode < 300 ? '{}' : JSON.stringify({ error: 'injected_failure' }));
    });
  });

  await new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve(undefined)));
  const addr = /** @type {import('net').AddressInfo} */ (srv.address());
  return {
    port: addr.port,
    url: `http://127.0.0.1:${addr.port}`,
    received,
    getRequestCount: () => requestCount,
    setStatusCode: (/** @type {number} */ code) => { statusCode = code; },
    stop: () => new Promise((resolve) => {
      if (typeof srv.closeAllConnections === 'function') srv.closeAllConnections();
      srv.close(() => resolve(undefined));
    })
  };
}

async function testOtlpExporter() {
  // 1. Lowercase hex traceId/spanId & W3C traceparent roundtrip
  for (let i = 0; i < 20; i++) {
    const tid = newTraceId();
    const sid = newSpanId();
    assert.match(tid, /^[0-9a-f]{32}$/, `traceId must be 32 lowercase hex chars: ${tid}`);
    assert.match(sid, /^[0-9a-f]{16}$/, `spanId must be 16 lowercase hex chars: ${sid}`);
    assert.notStrictEqual(tid, '0'.repeat(32));
    assert.notStrictEqual(sid, '0'.repeat(16));

    const tp = formatTraceparent(tid, sid, true);
    assert.strictEqual(tp, `00-${tid}-${sid}-01`);
    const parsed = parseTraceparent(tp);
    assert.ok(parsed, 'valid traceparent must parse');
    assert.strictEqual(parsed.version, '00');
    assert.strictEqual(parsed.traceId, tid);
    assert.strictEqual(parsed.spanId, sid);
    assert.strictEqual(parsed.sampled, true);
  }

  // Strict rejection of invalid/uppercase/all-zero traceparent headers
  assert.strictEqual(parseTraceparent(`00-${'A'.repeat(32)}-${'b'.repeat(16)}-01`), null, 'uppercase hex must be rejected');
  assert.strictEqual(parseTraceparent(`00-${'0'.repeat(32)}-${'1'.repeat(16)}-01`), null, 'zero traceId must be rejected');
  assert.strictEqual(parseTraceparent(`00-${'1'.repeat(32)}-${'0'.repeat(16)}-01`), null, 'zero spanId must be rejected');
  assert.strictEqual(parseTraceparent(`ff-${'1'.repeat(32)}-${'2'.repeat(16)}-01`), null, 'version ff must be rejected');
  assert.strictEqual(parseTraceparent('not-a-traceparent'), null);

  // 2. SSRF & Loopback protection
  const ssrfExporter = new OtlpExporter();
  const blockedUrls = [
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.170.2/v2/credentials',
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://metadata.goog/computeMetadata/v1/',
    'http://100.100.100.200/latest/meta-data/',
    'http://[fd00:ec2::254]/latest/meta-data/',
    'http://[::ffff:169.254.169.254]/v1/traces',
    'http://[fe80::1]/v1/traces',
    'http://0.0.0.0:4318/v1/traces'
  ];
  for (const badUrl of blockedUrls) {
    assert.throws(
      () => ssrfExporter.configure({ endpoint: badUrl, allowLoopback: true, enabled: true }),
      (/** @type {any} */ err) => err && err.code === 'SSRF_BLOCKED',
      `Must unconditionally block SSRF metadata URL even with allowLoopback=true: ${badUrl}`
    );
  }
  assert.throws(
    () => ssrfExporter.configure({ endpoint: 'http://127.0.0.1:4318', allowLoopback: false, enabled: true }),
    (/** @type {any} */ err) => err && err.code === 'SSRF_LOOPBACK_BLOCKED',
    'Loopback must require explicit allowLoopback: true'
  );
  assert.throws(
    () => ssrfExporter.configure({ endpoint: 'file:///etc/passwd', allowLoopback: true }),
    (/** @type {any} */ err) => err && err.code === 'INVALID_ENDPOINT',
    'Non-http(s) protocol must be rejected'
  );

  // 3. Bounded 256-span ring buffer (FIFO eviction without unbounded growth)
  assert.strictEqual(MAX_SPAN_BUFFER, 256);
  const ringExp = new OtlpExporter();
  for (let i = 0; i < 300; i++) {
    const sp = ringExp.startSpan(`op.${i}`, { seq: i });
    ringExp.endSpan(sp, 'OK');
  }
  const ringStatus = ringExp.getStatus();
  assert.strictEqual(ringStatus.bufferedSpans, 256, 'Ring buffer must cap at exactly 256 spans');
  assert.strictEqual(ringStatus.totalRecordedSpans, 300);
  assert.strictEqual(ringStatus.droppedSpans, 44, 'Exactly 44 oldest spans must be evicted');
  const drained = ringExp._drainSpans();
  assert.strictEqual(drained.length, 256);
  assert.strictEqual(drained[0].name, 'op.44', 'Oldest retained span must be #44 (FIFO eviction)');
  assert.strictEqual(drained[255].name, 'op.299', 'Newest retained span must be #299');

  // 4. Live loopback OTLP/HTTP JSON export (gzip + schema + auth redaction + circuit breaker on 503)
  const collector = await startMockOtlpCollector();
  try {
    const exp = new OtlpExporter({
      endpoint: collector.url,
      allowLoopback: true,
      enabled: true,
      serviceName: 'culkibo-control-plane-test',
      headers: {
        Authorization: 'Bearer secret-honeycomb-key-xyz',
        'X-Honeycomb-Team': 'hc-secret-team-key',
        'X-Tenant': 'acme-prod'
      },
      failureThreshold: 2,
      baseBackoffMs: 250,
      maxBackoffMs: 2000
    });

    // Header redaction check
    const st = exp.getStatus();
    assert.strictEqual(st.headers.Authorization, '[REDACTED]', 'Authorization header MUST be redacted in getStatus()');
    assert.strictEqual(st.headers['X-Honeycomb-Team'], '[REDACTED]', 'API key header MUST be redacted');
    assert.strictEqual(st.headers['X-Tenant'], 'acme-prod', 'Non-sensitive header preserved');

    // Record parent + child span with W3C traceparent inheritance
    const parent = exp.startSpan('http.request', { 'http.method': 'POST', 'http.status_code': 200, 'culkibo.fastpath': true }, { kind: 'SERVER' });
    parent.addEvent('route.matched', { route: '/api/deploy' });
    const child = exp.startSpan('docker.route_swap', { 'latency.ms': 1.42 }, parent.traceparent);
    exp.endSpan(child, 'OK');
    exp.endSpan(parent, 'OK');

    const flushRes = await exp.flush({
      metricsSnapshot: {
        memoryMb: 51.0,
        heapUsedMb: 23.4,
        cpuPercent: 0.2,
        uptimeSeconds: 3600,
        totalRequests: 9432,
        latencyP50Ms: 2.4,
        latencyP99Ms: 6.52,
        activeWsClients: 4,
        activeSseClients: 1
      }
    });

    assert.strictEqual(flushRes.ok, true, `OTLP flush must succeed: ${JSON.stringify(flushRes)}`);
    assert.strictEqual(flushRes.exportedSpans, 2);
    assert.ok(flushRes.exportedMetrics >= 6, 'Must export control plane gauges + counters');
    assert.strictEqual(collector.received.length, 2, 'Must POST both /v1/traces and /v1/metrics');

    const traceReq = collector.received.find((r) => r.path === '/v1/traces');
    const metricReq = collector.received.find((r) => r.path === '/v1/metrics');
    assert.ok(traceReq, 'Collector must receive POST /v1/traces');
    assert.ok(metricReq, 'Collector must receive POST /v1/metrics');

    // Verify wire headers: gzip + JSON + auth sent on wire
    assert.strictEqual(traceReq.headers['content-encoding'], 'gzip');
    assert.strictEqual(traceReq.headers['content-type'], 'application/json');
    assert.strictEqual(traceReq.headers.authorization, 'Bearer secret-honeycomb-key-xyz');
    assert.strictEqual(metricReq.headers['content-encoding'], 'gzip');

    // Verify strict OTLP/HTTP JSON trace schema & lowercase hex IDs
    const resourceSpans = traceReq.payload?.resourceSpans;
    assert.ok(Array.isArray(resourceSpans) && resourceSpans.length === 1);
    const serviceAttr = resourceSpans[0].resource.attributes.find((/** @type {any} */ a) => a.key === 'service.name');
    assert.strictEqual(serviceAttr?.value?.stringValue, 'culkibo-control-plane-test');
    const wireSpans = resourceSpans[0].scopeSpans[0].spans;
    assert.strictEqual(wireSpans.length, 2);
    for (const ws of wireSpans) {
      assert.match(ws.traceId, /^[0-9a-f]{32}$/, 'Wire traceId MUST be 32 lowercase hex (never base64)');
      assert.match(ws.spanId, /^[0-9a-f]{16}$/, 'Wire spanId MUST be 16 lowercase hex (never base64)');
      assert.strictEqual(typeof ws.startTimeUnixNano, 'string');
      assert.strictEqual(typeof ws.endTimeUnixNano, 'string');
      assert.ok(BigInt(ws.endTimeUnixNano) >= BigInt(ws.startTimeUnixNano));
    }
    const wireChild = wireSpans.find((/** @type {any} */ s) => s.name === 'docker.route_swap');
    const wireParent = wireSpans.find((/** @type {any} */ s) => s.name === 'http.request');
    assert.strictEqual(wireChild.traceId, wireParent.traceId, 'Child span must inherit parent traceId');
    assert.strictEqual(wireChild.parentSpanId, wireParent.spanId, 'Child span must link parentSpanId');

    // Verify strict OTLP/HTTP JSON metrics schema
    const wireMetrics = metricReq.payload?.resourceMetrics?.[0]?.scopeMetrics?.[0]?.metrics;
    assert.ok(Array.isArray(wireMetrics) && wireMetrics.length >= 6);
    const rssMetric = wireMetrics.find((/** @type {any} */ m) => m.name === 'culkibo.process.memory_rss_mb');
    assert.strictEqual(rssMetric?.gauge?.dataPoints?.[0]?.asDouble, 51);
    const reqCounter = wireMetrics.find((/** @type {any} */ m) => m.name === 'culkibo.http.requests_total');
    assert.strictEqual(reqCounter?.sum?.dataPoints?.[0]?.asInt, '9432');

    // 5. Circuit breaker backoff on HTTP 503
    collector.setStatusCode(503);
    const failSpan = exp.startSpan('deploy.failing_collector');
    exp.endSpan(failSpan, 'OK');

    const f1 = await exp.flush();
    assert.strictEqual(f1.ok, false);
    assert.strictEqual(f1.statusCode, 503);
    assert.strictEqual(f1.circuitState, 'closed', '1st failure below threshold=2 stays closed');

    const f2 = await exp.flush();
    assert.strictEqual(f2.ok, false);
    assert.strictEqual(f2.statusCode, 503);
    assert.strictEqual(f2.circuitState, 'open', '2nd consecutive 503 must open circuit breaker');
    assert.ok((f2.backoffMs || 0) >= 250, 'Backoff duration must be set');

    const reqCountBeforeSkip = collector.getRequestCount();
    const f3 = await exp.flush();
    assert.strictEqual(f3.ok, false);
    assert.strictEqual(f3.skipped, true, 'Flush while circuit is open must short-circuit');
    assert.strictEqual(f3.reason, 'circuit_open');
    assert.strictEqual(collector.getRequestCount(), reqCountBeforeSkip, 'Open circuit MUST NOT send network requests');

    // Wait for backoff window to elapse -> half-open probe succeeds and closes circuit
    await new Promise((r) => setTimeout(r, 300));
    collector.setStatusCode(200);
    const recovered = await exp.flush();
    assert.strictEqual(recovered.ok, true, 'Half-open probe must succeed once collector recovers');
    assert.strictEqual(recovered.circuitState, 'closed');
    assert.strictEqual(recovered.exportedSpans, 1, 'Re-buffered span must be delivered after recovery');
  } finally {
    await collector.stop();
  }

  console.log('  ✓ 1. OTLP/HTTP JSON exporter: gzip wire format, lowercase hex IDs, W3C traceparent, 256-span ring, 503 circuit breaker & SSRF block verified');
}

async function testSupplyChainAttestor() {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-slsa-test-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;

  try {
    process.env.CULKIBO_DATA_DIR = tmpRoot;

    // 1. DSSE PAE exact byte-length verification (including multi-byte UTF-8)
    const paeAscii = dssePae(DSSE_PAYLOAD_TYPE, 'hello');
    assert.strictEqual(
      paeAscii.toString('utf8'),
      `DSSEv1 ${Buffer.byteLength(DSSE_PAYLOAD_TYPE, 'utf8')} ${DSSE_PAYLOAD_TYPE} 5 hello`
    );
    const paeUtf8 = dssePae('text/plain', '🚀');
    assert.strictEqual(
      paeUtf8.toString('utf8'),
      'DSSEv1 10 text/plain 4 🚀',
      'DSSE PAE MUST use UTF-8 byte length (4 bytes for 🚀), not JS string length (2)'
    );

    // 2. Statement v1 construction & SLSA v1.1 schema
    const imageDigestHex = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
    const stmt = createStatementV1({
      projectId: 'acme-web',
      revision: 'rel-001',
      imageDigest: `sha256:${imageDigestHex}`,
      commitSha: 'c40b3d2abcdef1234567890',
      builderId: 'https://culkibo.dev/builders/control-plane/v1',
      sbomSummary: {
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        componentCount: 93,
        rootDependencies: 6
      }
    });
    assert.strictEqual(stmt._type, STATEMENT_TYPE_V1);
    assert.strictEqual(stmt.predicateType, SLSA_PREDICATE_TYPE_V1);
    assert.strictEqual(stmt.subject[0].digest.sha256, imageDigestHex);
    assert.strictEqual(stmt.predicate.buildDefinition.internalParameters.slsaSpecVersion, '1.1');
    assert.strictEqual(stmt.predicate.buildDefinition.internalParameters.sbomSummary.specVersion, '1.6');
    assert.strictEqual(stmt.predicate.buildDefinition.internalParameters.sbomSummary.componentCount, 93);

    // 3. Sign, persist atomically under isolated CULKIBO_DATA_DIR, reload & verify
    const attestor = new SupplyChainAttestor();
    const attested = attestor.attestRelease({
      projectId: 'acme-web',
      revision: 'rel-001',
      imageDigest: `sha256:${imageDigestHex}`,
      commitSha: 'c40b3d2abcdef1234567890',
      builderId: 'https://culkibo.dev/builders/control-plane/v1',
      sbomSummary: {
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        componentCount: 93,
        rootDependencies: 6
      }
    });

    assert.strictEqual(attested.ok, true);
    assert.strictEqual(attested.algorithm, 'Ed25519');
    assert.ok(attested.storedPath && attested.storedPath.startsWith(tmpRoot), 'Attestation MUST be persisted inside isolated CULKIBO_DATA_DIR');
    assert.ok(fs.existsSync(path.join(tmpRoot, 'data', 'attestation-key.json')), 'Ed25519 keypair must persist under CULKIBO_DATA_DIR/data/attestation-key.json');
    assert.ok(fs.existsSync(attested.storedPath), 'Signed DSSE envelope file must exist on disk');

    const pubPem = attestor.getPublicKeyPem();
    assert.ok(pubPem.includes('BEGIN PUBLIC KEY'));

    // Reload from a fresh instance pointing at the same CULKIBO_DATA_DIR (simulates daemon restart)
    const reloadedAttestor = new SupplyChainAttestor();
    assert.strictEqual(reloadedAttestor.getPublicKeyPem(), pubPem, 'Persisted Ed25519 keypair must survive restarts');

    const fetched = reloadedAttestor.getAttestation('acme-web', 'rel-001');
    assert.ok(fetched, 'Persisted attestation must be retrievable by (projectId, revision)');
    assert.strictEqual(fetched.verification.valid, true);
    assert.strictEqual(fetched.verification.verified, true);
    assert.strictEqual(fetched.statement?.subject?.[0]?.digest?.sha256, imageDigestHex);

    const listed = reloadedAttestor.listAttestations('acme-web');
    assert.strictEqual(listed.length, 1);
    assert.strictEqual(listed[0].revision, 'rel-001');
    assert.strictEqual(listed[0].valid, true);

    // Verify with explicit PEM and JSON string input
    const explicitVerify = reloadedAttestor.verifyAttestation(JSON.stringify(attested.envelope), pubPem);
    assert.strictEqual(explicitVerify.valid, true);
    assert.strictEqual(explicitVerify.verified, true);
    assert.strictEqual(explicitVerify.slsaVersion, '1.1');

    // 4. Payload tamper rejection
    const decodedStmt = JSON.parse(Buffer.from(attested.envelope.payload, 'base64').toString('utf8'));
    decodedStmt.predicate.buildDefinition.externalParameters.commitSha = 'evil0000000000000000000';
    const tamperedPayloadEnv = {
      ...attested.envelope,
      payload: Buffer.from(JSON.stringify(decodedStmt), 'utf8').toString('base64')
    };
    const payloadTamperRes = reloadedAttestor.verifyAttestation(tamperedPayloadEnv);
    assert.strictEqual(payloadTamperRes.valid, false, 'Tampered payload MUST fail verification');
    assert.strictEqual(payloadTamperRes.verified, false);
    assert.strictEqual(payloadTamperRes.reason, 'INVALID_SIGNATURE');

    // 5. Signature tamper rejection (flip 1 bit in Ed25519 signature)
    const rawSig = Buffer.from(attested.envelope.signatures[0].sig, 'base64');
    rawSig[0] ^= 0xff;
    const tamperedSigEnv = {
      ...attested.envelope,
      signatures: [{ keyid: attested.envelope.signatures[0].keyid, sig: rawSig.toString('base64') }]
    };
    const sigTamperRes = reloadedAttestor.verifyAttestation(tamperedSigEnv);
    assert.strictEqual(sigTamperRes.valid, false, 'Tampered signature MUST fail verification');
    assert.strictEqual(sigTamperRes.reason, 'INVALID_SIGNATURE');

    // 6. Wrong-key rejection
    const otherKey = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    const wrongKeyRes = reloadedAttestor.verifyAttestation(attested.envelope, String(otherKey.publicKey));
    assert.strictEqual(wrongKeyRes.valid, false, 'Wrong Ed25519 public key MUST fail verification');
    assert.strictEqual(wrongKeyRes.reason, 'INVALID_SIGNATURE');

    // 7. PayloadType tamper & path-traversal rejection
    const badTypeRes = reloadedAttestor.verifyAttestation({
      ...attested.envelope,
      payloadType: 'application/json'
    });
    assert.strictEqual(badTypeRes.valid, false);
    assert.strictEqual(badTypeRes.reason, 'INVALID_PAYLOAD_TYPE');

    assert.throws(
      () => reloadedAttestor.attestRelease({ projectId: '../escape', revision: 'rel-1' }),
      /Invalid projectId/,
      'Path traversal in projectId must be rejected'
    );
  } finally {
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }

  console.log('  ✓ 2. SLSA v1.1 Ed25519 DSSE attestor: PAE byte encoding, atomic key/envelope persistence, verify pass & tamper/wrong-key rejections verified');
}

async function runOtlpAndSlsaTests() {
  console.log('\n🛡️  Testing Zero-Dep OTLP/HTTP JSON Exporter & SLSA v1.1 Ed25519 DSSE Attestor...\n');
  await testOtlpExporter();
  await testSupplyChainAttestor();
  console.log('\n✅ All OTLP & SLSA v1.1 Attestation tests PASSED!\n');
}

module.exports = runOtlpAndSlsaTests;

if (require.main === module) {
  runOtlpAndSlsaTests().catch((err) => {
    console.error('❌ OTLP & SLSA test FAILED:', err);
    process.exit(1);
  });
}
