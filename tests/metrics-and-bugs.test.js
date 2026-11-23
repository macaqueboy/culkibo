const assert = require('assert');
const http = require('http');

const {
  isLoopback,
  createWsTicket,
  consumeWsTicket,
  checkAuthBruteForce,
  recordAuthFailure,
  resetAuthRateLimit
} = require('../server/middleware/auth');
const { isMetadataIp, isPrivateIp, assertSafeUrl } = require('../server/services/ssrfGuard');
const metricsCollector = require('../server/services/metricsCollector');
const systemDoctor = require('../server/services/systemDoctor');
const containerOrchestrator = require('../server/services/containerOrchestrator');
const catalogManager = require('../server/services/catalogManager');
const cloudflareService = require('../server/services/cloudflareService');
const universalImporter = require('../server/services/universalImporter');
const deployManager = require('../server/services/deployManager');

const BASE_URL = process.env.CULKIBO_TEST_URL || 'http://127.0.0.1:3030';

/** @param {string} reqPath @param {string} [method] @param {any} [body] @param {Record<string, string>} [headers] */
function httpRequest(reqPath, method = 'GET', body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(reqPath, BASE_URL);
    const payload = body == null ? null : (typeof body === 'string' ? body : JSON.stringify(body));
    const req = http.request({
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method,
      headers: {
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...headers
      }
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch (e) {}
        resolve({ status: res.statusCode, headers: res.headers, text: data, json });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function testMetricsAndBugs() {
  console.log('\n🔬 Running Observability, Doctor & Deep Bug-Regression Tests...\n');

  // 1. X-Forwarded-For leftmost spoof defense (attacker sends `127.0.0.1`, proxy appends real remote IP)
  {
    const spoofedReq = {
      socket: { remoteAddress: '127.0.0.1' },
      headers: { 'x-forwarded-for': '127.0.0.1, 203.0.113.55' }
    };
    assert.strictEqual(
      isLoopback(spoofedReq),
      false,
      'Rightmost X-Forwarded-For public IP must prevent loopback bypass even if leftmost is spoofed 127.0.0.1'
    );

    const legitLoopback = {
      socket: { remoteAddress: '127.0.0.1' },
      headers: {}
    };
    assert.strictEqual(isLoopback(legitLoopback), true, 'Direct 127.0.0.1 without proxy headers must be loopback');
    console.log('✅ 1. X-Forwarded-For leftmost spoof blocked');
  }

  // 2. Hex IPv4-mapped IPv6 metadata SSRF block (`::ffff:a9fe:a9fe` and `::ffff:169.254.169.254`)
  {
    assert.strictEqual(isMetadataIp('::ffff:169.254.169.254'), true, 'Dotted IPv4-mapped metadata IP must be blocked');
    assert.strictEqual(isMetadataIp('::ffff:a9fe:a9fe'), true, 'Hex IPv4-mapped AWS metadata IP must be blocked');
    assert.strictEqual(isPrivateIp('::ffff:7f00:0001'), true, 'Hex IPv4-mapped 127.0.0.1 must be detected as private');
    assert.strictEqual(isPrivateIp('::ffff:0a00:0001'), true, 'Hex IPv4-mapped 10.0.0.1 must be detected as private');

    let blocked = false;
    try {
      await assertSafeUrl('http://[::ffff:169.254.169.254]/latest/meta-data/', { allowPrivate: true });
    } catch (err) {
      blocked = /metadatos|metadata|bloquead|reservad/i.test(err.message);
    }
    assert.strictEqual(blocked, true, 'assertSafeUrl must block IPv4-mapped metadata URL even when allowPrivate=true');
    console.log('✅ 2. Hex & dotted IPv4-mapped IPv6 SSRF metadata blocked');
  }

  // 3. Single-use WebSocket tickets (consume once, replay rejected)
  {
    const ticketRes = createWsTicket({ socket: { remoteAddress: '127.0.0.1' }, headers: {} });
    assert.ok(ticketRes && typeof ticketRes.ticket === 'string' && ticketRes.ticket.length >= 24, 'Ticket must be generated');
    assert.strictEqual(consumeWsTicket(ticketRes.ticket), true, 'First consume of fresh ticket must succeed');
    assert.strictEqual(consumeWsTicket(ticketRes.ticket), false, 'Replaying a consumed WS ticket must fail');
    assert.strictEqual(consumeWsTicket('nonexistent-ticket'), false, 'Unknown ticket must fail');
    console.log('✅ 3. Single-use WebSocket tickets enforced (no replay)');
  }

  // 4. Auth brute-force rate limiter (locks after AUTH_FAIL_MAX=20 failures from same IP)
  {
    const fakeReq = { socket: { remoteAddress: '198.51.100.42' }, headers: {} };
    resetAuthRateLimit();
    for (let i = 0; i < 19; i++) {
      recordAuthFailure(fakeReq);
    }
    assert.strictEqual(checkAuthBruteForce(fakeReq).blocked, false, '19 failures should still remain below AUTH_FAIL_MAX=20');
    recordAuthFailure(fakeReq);
    const status = checkAuthBruteForce(fakeReq);
    assert.strictEqual(status.blocked, true, '20 consecutive auth failures from same IP must trigger lockout');
    assert.ok(status.retryAfterSec > 0, 'Lockout must report positive retryAfterSec');
    resetAuthRateLimit();
    console.log('✅ 4. Auth brute-force rate limiter triggers cleanly at threshold and resets');
  }

  // 5. containerOrchestrator.switchTraffic rejects NaN / non-numeric values safely
  {
    const before = { ...containerOrchestrator.trafficAllocation };
    await assert.rejects(
      async () => containerOrchestrator.switchTraffic('abc', 100),
      /numérico|número|válido|entre 0 y 100/i,
      'switchTraffic must reject on NaN forge percentage'
    );
    await assert.rejects(
      async () => containerOrchestrator.switchTraffic(50, NaN),
      /numérico|número|válido|entre 0 y 100/i,
      'switchTraffic must reject on NaN citadel percentage'
    );
    assert.deepStrictEqual(containerOrchestrator.trafficAllocation, before, 'Traffic allocation must stay untouched after rejected NaN');
    console.log('✅ 5. containerOrchestrator.switchTraffic rejects NaN safely');
  }

  // 6. catalogManager.redact preserves full log when maxLength=null and masks real secrets
  {
    const longLog = `${'A'.repeat(700)} database ready on port 5432 with value null and SECRET_OK_999 ${'B'.repeat(400)}`;
    const out = catalogManager.redact(longLog, { a: null, b: undefined, c: '', d: 'ab', e: 'SECRET_OK_999' }, null);
    assert.ok(out.length > 1000, 'maxLength=null must retain full multi-KB container logs without 600-char truncation');
    assert.ok(out.includes('database ready on port 5432'), 'Log line must not be corrupted by null/short secrets');
    assert.ok(!out.includes('SECRET_OK_999'), 'Real secret must still be redacted');
    assert.ok(out.includes('«oculto»'), 'Redaction mask must replace real secret with «oculto»');
    console.log('✅ 6. catalogManager.redact retains full logs (maxLength=null) and masks real secrets');
  }

  // 7. universalImporter warns about host-exposed 0.0.0.0 database ports in docker-compose.yml (including 2nd port!)
  {
    const yaml = [
      'services:',
      '  db:',
      '    image: postgres:16-alpine',
      '    ports:',
      '      - "127.0.0.1:5432:5432"',
      '      - "0.0.0.0:5433:5432"',
      '    environment:',
      '      POSTGRES_PASSWORD: supersecretpassword'
    ].join('\n');
    const parsed = universalImporter.parseDockerCompose(yaml);
    const dbWarnings = (parsed.services && parsed.services[0] && parsed.services[0].warnings) || [];
    assert.ok(Array.isArray(dbWarnings) && dbWarnings.length > 0, 'Compose parser must emit per-service warnings');
    assert.ok(
      dbWarnings.some((w) => /0\.0\.0\.0/.test(w) && /5433/.test(w)),
      `Expected warning about second 0.0.0.0 exposed DB port, got: ${JSON.stringify(dbWarnings)}`
    );
    console.log('✅ 7. universalImporter flags 0.0.0.0 exposed database ports across all port entries');
  }

  // 8. cloudflareService.saveConfig never overwrites real credentials with a masked placeholder
  {
    const orig = { ...cloudflareService.config };
    try {
      cloudflareService.config = { ...orig, apiToken: 'cf_real_token_1234567890', accountId: '1234567890abcdef1234567890abcdef' };
      const maskedView = cloudflareService.getConfigStatus();
      assert.ok(maskedView.tokenMasked && maskedView.tokenMasked.includes('••'), 'getConfigStatus must return masked tokenMasked');
      cloudflareService.saveConfig({ apiToken: maskedView.tokenMasked, accountId: '1234...cdef' });
      assert.strictEqual(
        cloudflareService.config.accountId,
        '1234567890abcdef1234567890abcdef',
        'saveConfig must preserve real accountId when UI submits masked placeholder'
      );
      assert.strictEqual(
        cloudflareService.config.apiToken,
        'cf_real_token_1234567890',
        'saveConfig must preserve real apiToken when UI submits masked placeholder'
      );
    } finally {
      cloudflareService.config = orig;
      try { cloudflareService.saveConfig(orig); } catch (e) {}
    }
    console.log('✅ 8. cloudflareService.saveConfig preserves real credentials against masked placeholders');
  }

  // 9. deployManager.drainAndRetire guards fast-rollback (will not stop container if it became active again)
  {
    let dockerStopCalled = false;
    const origRunDocker = deployManager.runDocker;
    const fakePid = `drain_guard_${Date.now()}`;
    try {
      deployManager.store[fakePid] = {
        current: { containerName: 'culkibo-live-rollback-guard' },
        previous: null,
        history: []
      };
      deployManager.runDocker = async () => {
        dockerStopCalled = true;
        return { code: 0, stdout: '', stderr: '' };
      };
      await deployManager.drainAndRetire(
        { id: 'dep_guard', projectId: fakePid, logLines: [] },
        { containerName: 'culkibo-live-rollback-guard' },
        { drainTimeoutMs: 10, stopGraceSeconds: 1 }
      );
      assert.strictEqual(dockerStopCalled, false, 'drainAndRetire must NOT stop a container that is currently active after fast rollback');
    } finally {
      deployManager.runDocker = origRunDocker;
      delete deployManager.store[fakePid];
    }
    assert.strictEqual(typeof deployManager.cancelAllDrains, 'function', 'deployManager must expose cancelAllDrains() for clean shutdown');
    console.log('✅ 9. deployManager.drainAndRetire protects active rollback containers (behavioral verification)');
  }

  // 10. Live HTTP Security Headers, /api/metrics JSON, /metrics Prometheus, /api/observability/snapshot, /api/system/doctor
  {
    const health = await httpRequest('/health');
    assert.strictEqual(health.status, 200, '/health must return 200');
    assert.strictEqual(health.headers['x-content-type-options'], 'nosniff', 'Missing X-Content-Type-Options: nosniff');
    assert.strictEqual(health.headers['x-frame-options'], 'DENY', 'Missing X-Frame-Options: DENY');
    assert.strictEqual(health.headers['referrer-policy'], 'no-referrer', 'Missing Referrer-Policy: no-referrer');
    assert.strictEqual(health.headers['cache-control'], 'no-store', 'API/health responses must set Cache-Control: no-store');

    const prom = await httpRequest('/metrics');
    assert.strictEqual(prom.status, 200, '/metrics must return 200');
    assert.ok(/text\/plain/.test(prom.headers['content-type'] || ''), '/metrics must serve Prometheus text/plain');
    assert.ok(prom.text.includes('culkibo_http_requests_total'), '/metrics must expose culkibo_http_requests_total');
    assert.ok(prom.text.includes('culkibo_http_request_duration_seconds_bucket'), '/metrics must expose HTTP latency histogram');
    assert.ok(prom.text.includes('process_resident_memory_bytes'), '/metrics must expose process_resident_memory_bytes gauge');
    assert.ok(prom.text.includes('nodejs_heap_size_used_bytes'), '/metrics must expose nodejs_heap_size_used_bytes gauge');

    const snap = await httpRequest('/api/observability/snapshot?fresh=1');
    assert.strictEqual(snap.status, 200, '/api/observability/snapshot must return 200');
    assert.ok(snap.json && snap.json.http && snap.json.http.rps && snap.json.process && snap.json.websocket, 'Snapshot must contain http, process, websocket sections');
    assert.ok(Array.isArray(snap.json.history) && snap.json.history.length >= 1, 'Snapshot must include live history points');
    assert.strictEqual(typeof snap.json.websocket.telemetryClients, 'number', 'websocket.telemetryClients must be numeric');

    const doctor = await httpRequest('/api/system/doctor');
    assert.strictEqual(doctor.status, 200, '/api/system/doctor must return 200');
    assert.ok(doctor.json && Array.isArray(doctor.json.checks) && doctor.json.checks.length === 8, 'Doctor must return 8 checks');
    assert.ok(['ok', 'warn', 'fail'].includes(doctor.json.overall), 'Doctor overall status must be valid');

    const wsTicketHttp = await httpRequest('/api/auth/ws-ticket', 'POST', {});
    assert.strictEqual(wsTicketHttp.status, 200, 'POST /api/auth/ws-ticket must return 200 on loopback');
    assert.ok(wsTicketHttp.json && typeof wsTicketHttp.json.ticket === 'string', 'HTTP ws-ticket must return a ticket string');

    // Local direct sanity on metricsCollector & systemDoctor
    assert.ok(metricsCollector.getSnapshot(false).process.memoryMb > 0, 'metricsCollector must measure real RSS > 0 MB');
    const localDoc = await systemDoctor.runDoctor();
    assert.strictEqual(localDoc.checks.length, 8, 'Local systemDoctor.runDoctor() must return 8 checks');

    console.log('✅ 10. Live security headers, Prometheus /metrics, /api/observability/snapshot, /api/system/doctor & ws-ticket verified');
  }

  console.log('\n🎉 All 10 Observability, Doctor & Deep Bug-Regression assertions PASSED!\n');
}

if (require.main === module) {
  const { ensureDaemon } = require('./helpers/daemon');
  ensureDaemon().then(async (stop) => {
    try {
      await testMetricsAndBugs();
    } finally {
      if (stop) await stop();
    }
  }).catch((err) => {
    console.error('❌ Metrics & Bug-Regression suite failed:', err);
    process.exit(1);
  });
}

module.exports = testMetricsAndBugs;
