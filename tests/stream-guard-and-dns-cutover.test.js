'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const streamFloodGuardService = require('../server/services/streamFloodGuardService');
const dnsCutoverService = require('../server/services/dnsCutoverService');

const {
  StreamFloodGuardService,
  DEFAULT_STREAM_POLICY,
  HOP_BY_HOP_HEADERS,
  evaluateStreamAdmission,
  scrubUpgradeHeaders,
  generateCaddyStreamBlock,
  upsertStreamPolicy,
  getStreamGuardSummary
} = streamFloodGuardService;

const {
  DnsCutoverService,
  CLOUDFLARE_IPV4_CIDRS,
  isCloudflareProxyIp,
  preflightDnsCutover,
  buildTtlCutoverPlan,
  getCutoverStatus
} = dnsCutoverService;

/**
 * Verifies CVE-2026-55458 101 hop-by-hop scrubbing, WS/SSE flood & Slowloris & slow-reader guards,
 * Caddy v2.11 streaming block generation, and atomic policy/summary persistence.
 * @param {string} tmpRoot
 */
function testStreamFloodGuard(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'stream-data');
  const svc = new StreamFloodGuardService({ dataDir });

  assert.strictEqual(DEFAULT_STREAM_POLICY.maxPerIp, 20);
  assert.ok(HOP_BY_HOP_HEADERS.includes('proxy-authenticate'));
  assert.ok(HOP_BY_HOP_HEADERS.includes('alt-svc'));

  // 1. CVE-2026-55458 101 Upgrade hop-by-hop header scrub
  const scrubbed = svc.scrubUpgradeHeaders({
    Upgrade: 'websocket',
    Connection: 'Upgrade, Keep-Alive, X-Internal-Hop',
    'Sec-WebSocket-Accept': 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=',
    'Proxy-Authenticate': 'Basic realm="internal"',
    'Alt-Svc': 'h3=":443"; ma=2592000',
    'Keep-Alive': 'timeout=5',
    TE: 'trailers',
    Trailer: 'X-Checksum',
    'Transfer-Encoding': 'chunked',
    'X-Internal-Hop': 'leak-me-not',
    'X-Safe-Trace': 'trace-42'
  });
  assert.strictEqual(scrubbed.ok, true);
  assert.strictEqual(scrubbed.headers.Upgrade, 'websocket');
  assert.strictEqual(scrubbed.headers.Connection, 'Upgrade');
  assert.strictEqual(scrubbed.headers['Sec-WebSocket-Accept'], 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=');
  assert.strictEqual(scrubbed.headers['X-Safe-Trace'], 'trace-42');
  assert.strictEqual(scrubbed.headers['Proxy-Authenticate'], undefined);
  assert.strictEqual(scrubbed.headers['Alt-Svc'], undefined);
  assert.strictEqual(scrubbed.headers['Keep-Alive'], undefined);
  assert.strictEqual(scrubbed.headers.TE, undefined);
  assert.strictEqual(scrubbed.headers.Trailer, undefined);
  assert.strictEqual(scrubbed.headers['Transfer-Encoding'], undefined);
  assert.strictEqual(scrubbed.headers['X-Internal-Hop'], undefined);
  assert.ok(scrubbed.strippedCount >= 7);

  // 2. Policy upsert & rejection of heartbeat >= 45s
  const pol = svc.upsertStreamPolicy('proj_chat', { maxPerIp: 10, maxPerProject: 200, heartbeatIntervalSec: 25 });
  assert.strictEqual(pol.maxPerIp, 10);
  assert.strictEqual(pol.heartbeatIntervalSec, 25);
  assert.throws(() => svc.upsertStreamPolicy('proj_chat', { heartbeatIntervalSec: 45 }), /heartbeatIntervalSec/);

  // 3. Normal admission passes
  const okAdm = svc.evaluateStreamAdmission({
    projectId: 'proj_chat',
    clientIp: '203.0.113.5',
    protocol: 'ws',
    activePerIp: 2,
    activeProject: 20,
    headerElapsedMs: 120,
    bytesPerSec: 4096,
    bufferedBytes: 16384
  });
  assert.strictEqual(okAdm.allowed, true);
  assert.strictEqual(okAdm.httpStatus, 101);

  // 4. Per-IP flood -> 429 / WS 1013 + Retry-After
  const ipFlood = svc.evaluateStreamAdmission({
    projectId: 'proj_chat',
    clientIp: '203.0.113.5',
    protocol: 'ws',
    activePerIp: 10,
    activeProject: 20
  });
  assert.strictEqual(ipFlood.allowed, false);
  assert.strictEqual(ipFlood.code, 'PER_IP_STREAM_LIMIT');
  assert.strictEqual(ipFlood.httpStatus, 429);
  assert.strictEqual(ipFlood.wsCloseCode, 1013);
  assert.ok(ipFlood.retryAfterSec >= 1 && ipFlood.headers['Retry-After']);

  // 5. Slowloris detection (slow header OR low bytesPerSec)
  const slowloris = svc.evaluateStreamAdmission({
    projectId: 'proj_chat',
    clientIp: '203.0.113.6',
    protocol: 'sse',
    headerElapsedMs: 6500,
    bytesPerSec: 64
  });
  assert.strictEqual(slowloris.allowed, false);
  assert.strictEqual(slowloris.code, 'SLOWLORIS_DETECTED');

  // 6. Slow-reader OOM backpressure shedding
  const slowReader = svc.evaluateStreamAdmission({
    projectId: 'proj_chat',
    clientIp: '203.0.113.7',
    protocol: 'sse',
    bufferedBytes: 10 * 1024 * 1024
  });
  assert.strictEqual(slowReader.allowed, false);
  assert.strictEqual(slowReader.code, 'SLOW_READER_BACKPRESSURE');
  assert.strictEqual(slowReader.wsCloseCode, 1013);

  // 7. Caddy v2.11 streaming block verification
  const caddy = svc.generateCaddyStreamBlock(pol);
  assert.strictEqual(caddy.ok, true);
  assert.ok(caddy.heartbeatIntervalSec < 45);
  assert.ok(caddy.caddyfile.includes('read_timeout 0'));
  assert.ok(caddy.caddyfile.includes('write_timeout 0'));
  assert.ok(caddy.caddyfile.includes('flush_interval -1'));
  assert.ok(caddy.caddyfile.includes('stream_close_delay 30s'));

  const summary = svc.getStreamGuardSummary();
  assert.strictEqual(summary.policyCount, 1);
  assert.strictEqual(summary.stats.totalEvaluated, 4);
  assert.strictEqual(summary.stats.totalBlocked, 3);
  assert.ok(fs.existsSync(path.join(dataDir, 'stream-flood-guard.json')));
}

/**
 * Verifies Cloudflare Anycast proxy detection, HTTP-01 vs DNS-01 ACME handling,
 * stale _acme-challenge TXT (81058), divergent SOA serials, and 5-phase TTL cutover plans.
 * @param {string} tmpRoot
 */
function testDnsCutoverService(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'dns-data');
  const svc = new DnsCutoverService({ dataDir });

  // 1. Accurate Cloudflare CIDR matching (including 104.16.0.0/13 -> 104.21.10.5)
  assert.ok(CLOUDFLARE_IPV4_CIDRS.includes('104.16.0.0/13'));
  assert.strictEqual(svc.isCloudflareProxyIp('104.21.10.5'), true);
  assert.strictEqual(svc.isCloudflareProxyIp('172.67.140.20'), true);
  assert.strictEqual(svc.isCloudflareProxyIp('2606:4700:3031::6815:a05'), true);
  assert.strictEqual(svc.isCloudflareProxyIp('203.0.113.42'), false);

  // 2. Cloudflare proxy IP + http-01 -> CLOUDFLARE_PROXY_ACME_CONFLICT (NEVER false DNS_MISMATCH!)
  const cfConflict = svc.preflightDnsCutover({
    domain: 'app.culkibo.dev',
    targetIpv4: '203.0.113.42',
    challengeMode: 'http-01',
    recordsSnapshot: {
      a: ['104.21.10.5'],
      soaSerials: [2026112701, 2026112701]
    }
  });
  assert.strictEqual(cfConflict.ready, false);
  assert.strictEqual(cfConflict.code, 'CLOUDFLARE_PROXY_ACME_CONFLICT');
  assert.strictEqual(cfConflict.isProxied, true);
  assert.ok(!cfConflict.blockers.some((b) => b.code === 'DNS_MISMATCH'), 'Cloudflare proxy must NOT produce false DNS_MISMATCH');

  // 3. Same Cloudflare proxy IP + dns-01 + clean _acme-challenge TXT -> ready: true!
  const cfDns01Ok = svc.preflightDnsCutover({
    domain: 'app.culkibo.dev',
    targetIpv4: '203.0.113.42',
    challengeMode: 'dns-01',
    recordsSnapshot: {
      a: ['104.21.10.5'],
      acmeTxt: ['valid-acme-challenge-token-01'],
      soaSerials: [2026112702, 2026112702]
    }
  });
  assert.strictEqual(cfDns01Ok.ready, true);
  assert.strictEqual(cfDns01Ok.isProxied, true);
  assert.strictEqual(cfDns01Ok.code, 'CUTOVER_READY');

  // 4. Stale/duplicate _acme-challenge TXT -> STALE_ACME_TXT_81058
  const staleTxt = svc.preflightDnsCutover({
    domain: 'stale.culkibo.dev',
    targetIpv4: '203.0.113.42',
    challengeMode: 'dns-01',
    recordsSnapshot: {
      a: ['203.0.113.42'],
      acmeTxt: ['old-token-1', 'old-token-2']
    }
  });
  assert.strictEqual(staleTxt.ready, false);
  assert.strictEqual(staleTxt.code, 'STALE_ACME_TXT_81058');

  // 5. Divergent SOA.serial -> SOA_SERIAL_DIVERGENT
  const divSoa = svc.preflightDnsCutover({
    domain: 'split.culkibo.dev',
    targetIpv4: '203.0.113.42',
    challengeMode: 'http-01',
    recordsSnapshot: {
      a: ['203.0.113.42'],
      soaSerials: [2026112701, 2026112702]
    }
  });
  assert.strictEqual(divSoa.ready, false);
  assert.strictEqual(divSoa.code, 'SOA_SERIAL_DIVERGENT');

  // 6. 5-phase TTL cutover plan enforces minPreCutoverWaitSec = max(currentTtlSec, soaRefreshSec)
  const plan = svc.buildTtlCutoverPlan({
    domain: 'app.culkibo.dev',
    currentTtlSec: 3600,
    targetTtlSec: 60,
    targetIp: '203.0.113.42',
    acmeMode: 'dns-01',
    soaRefreshSec: 7200,
    nameserverSerials: [2026112705, 2026112705]
  });
  assert.strictEqual(plan.ok, true);
  assert.strictEqual(plan.ready, true);
  assert.strictEqual(plan.minPreCutoverWaitSec, 7200);
  assert.strictEqual(plan.phases.length, 5);

  // Divergent nameserverSerials blocks plan with SOA_SERIAL_DIVERGENT
  const blockedPlan = svc.buildTtlCutoverPlan({
    domain: 'blocked.culkibo.dev',
    currentTtlSec: 3600,
    targetTtlSec: 60,
    targetIp: '203.0.113.42',
    nameserverSerials: [100, 101]
  });
  assert.strictEqual(blockedPlan.ready, false);
  assert.strictEqual(blockedPlan.code, 'SOA_SERIAL_DIVERGENT');

  const status = svc.getCutoverStatus('app.culkibo.dev');
  assert.strictEqual(status.found, true);
  assert.ok(status.preflight && status.plan);
  assert.ok(fs.existsSync(path.join(dataDir, 'dns-cutovers.json')));
}

/**
 * Verifies BOTH singleton (`svc.fn`) AND destructured (`fn`) exports with dynamic `CULKIBO_DATA_DIR`.
 * @param {string} tmpRoot
 */
function testSingletonAndDestructuredExports(tmpRoot) {
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = path.join(tmpRoot, 'singleton-env');

  try {
    // StreamFloodGuardService singleton + destructured
    const pol = streamFloodGuardService.upsertStreamPolicy('singleton-app', { maxPerIp: 5 });
    assert.strictEqual(pol.maxPerIp, 5);
    assert.strictEqual(upsertStreamPolicy('singleton-app', { maxPerProject: 50 }).maxPerProject, 50);
    assert.strictEqual(evaluateStreamAdmission({ projectId: 'singleton-app', clientIp: '1.2.3.4', activePerIp: 5 }).httpStatus, 429);
    assert.strictEqual(scrubUpgradeHeaders({ Upgrade: 'websocket', 'Alt-Svc': 'h3=":443"' }).headers['Alt-Svc'], undefined);
    assert.ok(generateCaddyStreamBlock().caddyfile.includes('flush_interval -1'));
    assert.strictEqual(getStreamGuardSummary().policyCount, 1);

    // DnsCutoverService singleton + destructured
    assert.strictEqual(isCloudflareProxyIp('104.21.10.5'), true);
    assert.strictEqual(dnsCutoverService.isCloudflareProxyIp('104.21.10.5'), true);
    const pf = preflightDnsCutover({
      domain: 'edge.culkibo.dev',
      targetIpv4: '203.0.113.9',
      challengeMode: 'http-01',
      recordsSnapshot: { a: ['104.21.10.5'] }
    });
    assert.strictEqual(pf.code, 'CLOUDFLARE_PROXY_ACME_CONFLICT');
    const pl = buildTtlCutoverPlan({ domain: 'edge.culkibo.dev', currentTtlSec: 3600, targetTtlSec: 60, targetIp: '203.0.113.9' });
    assert.strictEqual(pl.minPreCutoverWaitSec, 3600);
    assert.strictEqual(getCutoverStatus('edge.culkibo.dev').found, true);
    assert.strictEqual(dnsCutoverService.getCutoverStatus('edge.culkibo.dev').found, true);
  } finally {
    if (prevDataDir === undefined) {
      delete process.env.CULKIBO_DATA_DIR;
    } else {
      process.env.CULKIBO_DATA_DIR = prevDataDir;
    }
  }
}

async function runAllTests() {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c16-stream-dns-'));
  try {
    testStreamFloodGuard(tmpRoot);
    testDnsCutoverService(tmpRoot);
    testSingletonAndDestructuredExports(tmpRoot);
    console.log('✅ stream-guard-and-dns-cutover.test.js PASSED (CVE-2026-55458 101 scrub, flood/Slowloris/OOM, Caddy block, Cloudflare proxy ACME, 5-phase TTL, singleton+destructured)');
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runAllTests().catch((err) => {
    console.error('❌ stream-guard-and-dns-cutover.test.js FAILED:', err);
    process.exit(1);
  });
}

module.exports = runAllTests;
