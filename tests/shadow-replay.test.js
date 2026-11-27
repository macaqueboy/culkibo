'use strict';

const assert = require('assert');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const shadowReplayService = require('../server/services/shadowReplayService');
const {
  ShadowReplayService,
  compareJsonShape,
  computePercentile,
  MAX_STORED_REPORTS
} = shadowReplayService;

/**
 * Starts a local HTTP mock server on `127.0.0.1:0` with a custom handler.
 * @param {(req: http.IncomingMessage, res: http.ServerResponse, body: string) => void} handler
 */
async function startMockServer(handler) {
  /** @type {Array<{ method: string, url: string, headers: Record<string, any> }>} */
  const seen = [];
  const srv = http.createServer((req, res) => {
    /** @type {Buffer[]} */
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      seen.push({
        method: req.method || 'GET',
        url: req.url || '/',
        headers: { ...req.headers }
      });
      handler(req, res, Buffer.concat(chunks).toString('utf8'));
    });
  });
  await new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve(undefined)));
  const addr = /** @type {import('net').AddressInfo} */ (srv.address());
  return {
    port: addr.port,
    url: `http://127.0.0.1:${addr.port}`,
    seen,
    stop: () => new Promise((resolve) => {
      if (typeof srv.closeAllConnections === 'function') srv.closeAllConnections();
      srv.close(() => resolve(undefined));
    })
  };
}

async function runShadowReplayTests() {
  console.log('\n🪞 Testing Shadow Traffic Replay & Cutover Regression Gate...\n');

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-shadow-replay-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;

  // 1. Unit checks: compareJsonShape & computePercentile
  {
    assert.strictEqual(computePercentile([], 95), 0);
    assert.strictEqual(computePercentile([10, 20, 30, 40, 50], 50), 30);
    assert.strictEqual(computePercentile([10, 20, 30, 40, 50], 95), 50);

    // Different timestamps/IDs/array counts must NOT trigger false drift
    const sameShape = compareJsonShape(
      { id: 'req_1', timestamp: '2026-01-01T00:00:00Z', user: { name: 'Alice', role: 'admin' }, items: [{ sku: 'A', qty: 1 }] },
      { id: 'req_999', timestamp: '2026-11-27T12:00:00Z', user: { name: 'Bob', role: 'viewer' }, items: [{ sku: 'B', qty: 9 }, { sku: 'C', qty: 2 }] }
    );
    assert.strictEqual(sameShape.compatible, true);
    assert.strictEqual(sameShape.hasBreakingDrift, false);
    assert.strictEqual(sameShape.drifted, false);

    // Missing key & type change MUST trigger breaking drift
    const brokenShape = compareJsonShape(
      { user: { id: 1, email: 'a@b.com' }, total: 42 },
      { user: { id: '1' }, total: 42, extraFlag: true }
    );
    assert.strictEqual(brokenShape.compatible, false);
    assert.strictEqual(brokenShape.hasBreakingDrift, true);
    assert.ok(brokenShape.missingKeys.includes('user.email'));
    assert.ok(brokenShape.addedKeys.includes('extraFlag'));
    assert.ok(brokenShape.typeChanges.some((tc) => tc.path === 'user.id' && tc.baselineType === 'number' && tc.candidateType === 'string'));
    console.log('  ✓ 1. compareJsonShape (zero false positives on volatile values, catches missing keys & type changes) & computePercentile verified');
  }

  // 2. Live baseline vs candidate HTTP servers: PASS (PROMOTE), REGRESSION (BLOCK_CUTOVER), redaction & SSRF
  let candidateMode = 'healthy';
  const baselineSrv = await startMockServer((req, res) => {
    if (req.url === '/api/orders') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        requestId: 'base-123',
        ts: Date.now(),
        orders: [{ id: 1, currency: 'EUR', amount: 49.9 }],
        meta: { region: 'eu-central', total: 1 }
      }));
      return;
    }
    if (req.url === '/api/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, uptime: 12345 }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, path: req.url, version: 'v1' }));
  });

  const candidateSrv = await startMockServer((req, res) => {
    if (candidateMode === 'healthy') {
      if (req.url === '/api/orders') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          requestId: 'cand-987',
          ts: Date.now() + 999,
          orders: [{ id: 2, currency: 'USD', amount: 99.0 }, { id: 3, currency: 'EUR', amount: 12.0 }],
          meta: { region: 'eu-west', total: 2 }
        }));
        return;
      }
      if (req.url === '/api/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, uptime: 12 }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, path: req.url, version: 'v2' }));
      return;
    }

    // Regression mode: >10x latency spike (+65ms >> 25ms default minLatencyDeltaMs) + HTTP 500 + missing JSON key (`meta.region`)
    setTimeout(() => {
      if (req.url === '/api/orders') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          requestId: 'cand-bad',
          ts: Date.now(),
          orders: [{ id: 2, currency: 'USD', amount: 99.0 }],
          meta: { total: 2 } // missing `meta.region`!
        }));
        return;
      }
      if (req.url === '/api/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, uptime: 15 }));
        return;
      }
      if (req.url === '/api/checkout') {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'NullPointerException in payment worker' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, path: req.url, version: 'v2-slow' }));
    }, 65);
  });

  try {
    process.env.CULKIBO_DATA_DIR = tmpRoot;
    const svc = new ShadowReplayService();

    // Warm up loopback sockets & HTTP parser before timing assertions
    await svc.runReplay({
      projectId: 'warmup',
      baselineUrl: baselineSrv.url,
      candidateUrl: candidateSrv.url,
      allowLoopback: true,
      persist: false,
      requests: [{ method: 'GET', path: '/api/health' }]
    });
    baselineSrv.seen.length = 0;
    candidateSrv.seen.length = 0;

    // 2a. PASS scenario -> PROMOTE + secret redaction + hop-by-hop stripping
    candidateMode = 'healthy';
    const passReport = await svc.runReplay({
      projectId: 'shop-api',
      baselineUrl: baselineSrv.url,
      candidateUrl: candidateSrv.url,
      allowLoopback: true,
      requests: [
        {
          method: 'GET',
          path: '/api/health',
          headers: {
            Authorization: 'Bearer super-secret-prod-jwt-999',
            Cookie: 'session_id=topsecretcookie123',
            Connection: 'keep-alive, X-Custom-Hop',
            'X-Custom-Hop': 'must-be-stripped',
            'X-Trace-Tag': 'canary-check'
          }
        },
        { method: 'GET', path: '/api/orders' },
        { method: 'POST', path: '/api/checkout', body: { cartId: 'c_1' } }
      ],
      gate: { max5xxDelta: 0, maxLatencyRatio: 2.0, maxStatusMismatchPct: 5, failOnSchemaDrift: true }
    });

    assert.strictEqual(passReport.pass, true, `Healthy candidate must pass: ${JSON.stringify(passReport.blockers)}`);
    assert.strictEqual(passReport.verdict, 'PROMOTE');
    assert.strictEqual(passReport.blockers.length, 0);
    assert.strictEqual(passReport.summary.totalRequests, 3);
    assert.strictEqual(passReport.summary.statusMatches, 3);
    assert.strictEqual(passReport.summary.delta5xx, 0);
    assert.strictEqual(passReport.summary.breakingSchemaDriftCount, 0);

    // Verify hop-by-hop header (`X-Custom-Hop`) was stripped on wire while `X-Trace-Tag` arrived
    const wireHealthReq = candidateSrv.seen.find((r) => r.url === '/api/health');
    assert.ok(wireHealthReq);
    assert.strictEqual(wireHealthReq.headers['x-custom-hop'], undefined, 'Connection-listed hop-by-hop header must be stripped');
    assert.strictEqual(wireHealthReq.headers['x-trace-tag'], 'canary-check');
    assert.strictEqual(wireHealthReq.headers['x-culkibo-shadow-replay'], '1');

    // Verify Authorization & Cookie are strictly redacted in returned AND persisted report
    const healthEntry = passReport.perRequest.find((r) => r.path === '/api/health');
    assert.strictEqual(healthEntry.headers.Authorization, '[REDACTED]');
    assert.strictEqual(healthEntry.headers.Cookie, '[REDACTED]');
    assert.strictEqual(healthEntry.headers['X-Trace-Tag'], 'canary-check');

    const historyFile = path.join(tmpRoot, 'data', 'shadow-replays.json');
    assert.ok(fs.existsSync(historyFile), 'Reports must persist inside isolated CULKIBO_DATA_DIR/data/shadow-replays.json');
    const rawPersisted = fs.readFileSync(historyFile, 'utf8');
    assert.ok(!rawPersisted.includes('super-secret-prod-jwt-999'), 'Raw Authorization token MUST NEVER be persisted');
    assert.ok(!rawPersisted.includes('topsecretcookie123'), 'Raw Cookie MUST NEVER be persisted');
    console.log('  ✓ 2. Healthy shadow replay -> verdict PROMOTE, hop-by-hop stripping & Authorization/Cookie redaction verified');

    // 2b. REGRESSION scenario -> BLOCK_CUTOVER (500 error + missing JSON key + >2.5x latency spike)
    candidateMode = 'regressed';
    const failReport = await svc.runReplay({
      projectId: 'shop-api',
      baselineUrl: baselineSrv.url,
      candidateUrl: candidateSrv.url,
      allowLoopback: true,
      requests: [
        { method: 'GET', path: '/api/health' },
        { method: 'GET', path: '/api/orders' },
        { method: 'POST', path: '/api/checkout', body: { cartId: 'c_2' } }
      ],
      gate: { max5xxDelta: 0, maxLatencyRatio: 2.0, maxStatusMismatchPct: 5, failOnSchemaDrift: true }
    });

    assert.strictEqual(failReport.pass, false);
    assert.strictEqual(failReport.verdict, 'BLOCK_CUTOVER');
    const blockerCodes = failReport.blockers.map((b) => b.code);
    assert.ok(blockerCodes.includes('REGRESSION_5XX'), `Expected REGRESSION_5XX in ${JSON.stringify(blockerCodes)}`);
    assert.ok(blockerCodes.includes('STATUS_MISMATCH'), `Expected STATUS_MISMATCH in ${JSON.stringify(blockerCodes)}`);
    assert.ok(blockerCodes.includes('LATENCY_P95_SPIKE'), `Expected LATENCY_P95_SPIKE in ${JSON.stringify(blockerCodes)}`);
    assert.ok(blockerCodes.includes('JSON_SCHEMA_DRIFT'), `Expected JSON_SCHEMA_DRIFT in ${JSON.stringify(blockerCodes)}`);
    assert.strictEqual(failReport.summary.delta5xx, 1);
    assert.strictEqual(failReport.summary.breakingSchemaDriftCount, 1);
    assert.ok(failReport.summary.latencyRatioP95 >= 2.0, `Expected p95 ratio >= 2.0, got ${failReport.summary.latencyRatioP95}`);

    const ordersEntry = failReport.perRequest.find((r) => r.path === '/api/orders');
    assert.ok(ordersEntry.jsonShape.missingKeys.includes('meta.region'), 'Must report exact missing JSON key path');

    // History cap (20 max) & project filtering
    const history = svc.listReplays('shop-api');
    assert.strictEqual(history.length, 2);
    assert.strictEqual(history[0].id, failReport.id, 'Most recent report must appear first');
    assert.strictEqual(svc.getReplay(passReport.id)?.verdict, 'PROMOTE');
    assert.strictEqual(MAX_STORED_REPORTS, 20);
    console.log('  ✓ 3. Regressed candidate -> verdict BLOCK_CUTOVER with all 4 blockers (5xx, status mismatch, p95 latency spike, JSON key drift) verified');

    // 2c. Cloud metadata SSRF & loopback opt-in enforcement
    const ssrfUrls = [
      'http://169.254.169.254/latest/meta-data/',
      'http://metadata.google.internal/computeMetadata/v1/',
      'http://100.100.100.200/latest/meta-data/',
      'http://[fd00:ec2::254]/latest/',
      'http://[::ffff:169.254.169.254]/latest/',
      'http://[fe80::1]/',
      'http://0.0.0.0:8080'
    ];
    for (const bad of ssrfUrls) {
      await assert.rejects(
        () => svc.runReplay({
          projectId: 'ssrf-test',
          baselineUrl: baselineSrv.url,
          candidateUrl: bad,
          allowLoopback: true
        }),
        (/** @type {any} */ err) => err && err.code === 'SSRF_BLOCKED',
        `Must unconditionally block cloud metadata URL even with allowLoopback=true: ${bad}`
      );
    }
    await assert.rejects(
      () => svc.runReplay({
        projectId: 'loopback-test',
        baselineUrl: baselineSrv.url,
        candidateUrl: candidateSrv.url,
        allowLoopback: false
      }),
      (/** @type {any} */ err) => err && err.code === 'SSRF_LOOPBACK_BLOCKED',
      'Loopback origins must require explicit allowLoopback: true'
    );
    console.log('  ✓ 4. Unconditional cloud-metadata SSRF blocking & loopback opt-in enforcement verified');
  } finally {
    await Promise.all([baselineSrv.stop(), candidateSrv.stop()]);
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }

  console.log('\n✅ All Shadow Traffic Replay & Cutover Gate tests PASSED!\n');
}

module.exports = runShadowReplayTests;

if (require.main === module) {
  runShadowReplayTests().catch((err) => {
    console.error('❌ Shadow Replay test FAILED:', err);
    process.exit(1);
  });
}
