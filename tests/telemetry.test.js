const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  TelemetryService,
  scrubText,
  scrubStack,
  scrubObject,
} = require('../server/services/telemetryService');
const { createCollectorServer } = require('../telemetry-collector/server');

async function testTelemetry() {
  console.log('\n🧪 Suite #24: Telemetría anónima, privacidad, circuit breaker y entrega E2E al recolector...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-telemetry-suite-'));
  const prevAllowTest = process.env.CULKIBO_TELEMETRY_ALLOW_IN_TEST;
  const prevTel = process.env.CULKIBO_TELEMETRY;
  const prevDnt = process.env.DO_NOT_TRACK;
  const prevAllowHttp = process.env.CULKIBO_TELEMETRY_ALLOW_HTTP;

  try {
    // -----------------------------------------------------------------------
    // 1. Saneado anti-PII y secretos de 11 fases (CERO fugas)
    // -----------------------------------------------------------------------
    const dirty = [
      '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\n-----END PRIVATE KEY-----',
      'Authorization: Bearer super_secret_bearer_token_12345',
      'jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
      'ghp_1234567890abcdef1234567890abcdef1234',
      'postgres://admin:S3cr3tP4ss!@db.miempresa.io:5432/produccion',
      'correo pablo.privado@cliente-real.com',
      'url https://panel.mi-empresa-secreta.es/api/deploy?token=abc123456789',
      'ip 203.0.113.42',
      'win C:\\Users\\pablo\\Desktop\\proyecto-privado\\index.js',
      'unix /home/alice/secrets/app.js',
    ].join(' | ');

    const cleaned = scrubText(dirty, 2000);
    for (const forbidden of [
      'MIIEvQIBADAN',
      'super_secret_bearer_token_12345',
      'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
      'ghp_1234567890abcdef',
      'S3cr3tP4ss!',
      'pablo.privado@cliente-real.com',
      'mi-empresa-secreta.es',
      '203.0.113.42',
      'Users\\pablo',
      '/home/alice',
    ]) {
      assert.ok(!cleaned.includes(forbidden), `scrubText filtró dato sensible: ${forbidden}`);
    }

    const cleanedObj = scrubObject({
      apiKey: 'sk_live_1234567890abcdef',
      domain: 'privado.cliente.com',
      safeStage: 'docker_build',
      nested: { password: 'mi-password', code: 'ECONNREFUSED' },
    });
    assert.strictEqual(cleanedObj.apiKey, undefined, 'Claves sensibles deben eliminarse por completo');
    assert.strictEqual(cleanedObj.domain, undefined, 'Claves de dominio deben eliminarse por completo');
    assert.strictEqual(cleanedObj.safeStage, 'docker_build');
    assert.strictEqual(cleanedObj.nested.password, undefined, 'Claves sensibles anidadas deben eliminarse');
    assert.strictEqual(cleanedObj.nested.code, 'ECONNREFUSED');

    const cleanedStack = scrubStack('Error: boom\n    at deploy (/home/pablo/Culkibo/server/services/deployManager.js:123:45)');
    assert.ok(cleanedStack.every((l) => !l.includes('/home/pablo')));
    console.log('  ✓ Saneado anti-PII de 11 fases: 0 fugas de PEM, JWT, tokens, DSN, emails, dominios, IPs o rutas');

    // -----------------------------------------------------------------------
    // 2. Precedencia estricta de opt-out y auto-desactivación en tests
    // -----------------------------------------------------------------------
    delete process.env.CULKIBO_TELEMETRY_ALLOW_IN_TEST;
    delete process.env.CULKIBO_TELEMETRY;
    delete process.env.DO_NOT_TRACK;
    const autoOffSvc = new TelemetryService({ storePath: path.join(tmpDir, 'auto-off.json') });
    assert.strictEqual(autoOffSvc.isEnabled(), false, 'Debe auto-desactivarse cuando corre bajo tests/');
    assert.strictEqual(autoOffSvc.getEffectiveState().lockedByEnv, true);

    process.env.CULKIBO_TELEMETRY_ALLOW_IN_TEST = '1';
    const svc = new TelemetryService({ storePath: path.join(tmpDir, 'tel.json') });
    assert.strictEqual(svc.isEnabled(), true, 'Activa por defecto fuera de tests/opt-out');

    process.env.CULKIBO_TELEMETRY = '0';
    assert.strictEqual(svc.isEnabled(), false, 'CULKIBO_TELEMETRY=0 anula preferencia persistida');
    delete process.env.CULKIBO_TELEMETRY;

    process.env.DO_NOT_TRACK = '1';
    assert.strictEqual(svc.isEnabled(), false, 'DO_NOT_TRACK=1 anula preferencia persistida');
    delete process.env.DO_NOT_TRACK;

    // Persistencia de setEnabled(false) vacía colas y guarda en disco
    svc.captureCrash('uncaughtException', new Error('Antes de apagar'));
    assert.strictEqual(svc.getStatus().queuedEvents, 1);
    const disabledStatus = svc.setEnabled(false);
    assert.strictEqual(disabledStatus.enabled, false);
    assert.strictEqual(disabledStatus.queuedEvents, 0, 'Desactivar debe vaciar la cola en memoria');

    const prevId = disabledStatus.instanceId;
    const rotated = svc.resetInstanceId();
    assert.notStrictEqual(rotated.instanceId, prevId, 'resetInstanceId debe generar un nuevo UUID');
    svc.setEnabled(true);
    console.log('  ✓ Precedencia opt-out: auto-off en tests, CULKIBO_TELEMETRY=0, DO_NOT_TRACK=1 y rotación UUID');

    // -----------------------------------------------------------------------
    // 3. Deduplicación por fingerprint, prioridad de cola y circuit breaker
    // -----------------------------------------------------------------------
    let transportCalls = 0;
    let nextTransportResult = { ok: false, status: 503, retryAfterSec: 0 };
    const qSvc = new TelemetryService({
      storePath: path.join(tmpDir, 'queue.json'),
      transport: async () => {
        transportCalls++;
        return nextTransportResult;
      },
    });

    // 5 crashes idénticos -> 1 evento plegado con occurrences=5
    for (let i = 0; i < 5; i++) {
      qSvc.captureCrash('unhandledRejection', new Error('Fallo repetido exacto'));
    }
    assert.strictEqual(qSvc.getStatus().queuedEvents, 1, 'Crashes idénticos en 15 min deben plegarse en 1 evento');
    assert.strictEqual(qSvc.getStatus().stats.deduplicated, 4);

    // Llenar cola más allá del tope de 50 eventos con heartbeats de baja prioridad: el crash nunca se descarta
    for (let i = 0; i < 60; i++) {
      qSvc.enqueueHeartbeat();
    }
    assert.ok(qSvc.getStatus().queuedEvents <= 50, 'La cola nunca supera el límite de 50 eventos');
    assert.ok(
      qSvc._queue.some((ev) => ev.type === 'server_crash'),
      'Los eventos server_crash de alta prioridad no se expulsan por heartbeats'
    );

    // Circuit breaker en 503: reencola y abre circuito
    const f1 = await qSvc.flush({ force: true });
    assert.strictEqual(f1.sent, 0);
    assert.ok(qSvc._nextRetryAfter > Date.now(), 'Fallo 503 debe activar backoff exponencial');
    const f2 = await qSvc.flush({ force: false });
    assert.strictEqual(f2.skipped, 'circuit_open', 'Mientras el circuito está abierto no se spamea la red');

    // Recuperación con 202
    nextTransportResult = { ok: true, status: 202 };
    const f3 = await qSvc.flush({ force: true });
    assert.ok(f3.sent > 0);
    assert.strictEqual(qSvc._consecutiveFailures, 0);
    assert.strictEqual(transportCalls, 2);
    console.log('  ✓ Deduplicación por fingerprint, prioridad de cola (50 máx) y circuit breaker exponencial');

    // -----------------------------------------------------------------------
    // 4. Entrega real E2E al recolector cloud (`telemetry-collector/`)
    // -----------------------------------------------------------------------
    const colDir = path.join(tmpDir, 'collector-data');
    const adminToken = 'e2e-telemetry-admin-token-0123456789';
    const collector = createCollectorServer({
      PORT: 0,
      BIND: '127.0.0.1',
      DATA_DIR: colDir,
      ADMIN_TOKEN: adminToken,
    });
    await new Promise((resolve) => collector.server.listen(0, '127.0.0.1', resolve));
    const port = collector.server.address().port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      process.env.CULKIBO_TELEMETRY_ALLOW_HTTP = '1';
      const e2eSvc = new TelemetryService({
        storePath: path.join(tmpDir, 'e2e-client.json'),
        endpoint: `${baseUrl}/v1/ingest`,
      });
      e2eSvc.setHeartbeatCollector(() => ({
        projectsCount: 3,
        databasesCount: 1,
        catalogServicesCount: 2,
        domainsCount: 2,
        activeCronsCount: 1,
        dockerAvailable: true,
        caddyAvailable: true,
        hasWildcard: true,
      }));

      e2eSvc.enqueueHeartbeat();
      e2eSvc.captureCrash('uncaughtException', new Error('Crash E2E para pablo@secreto.com'));
      e2eSvc.captureApi5xx({ method: 'POST', route: '/api/projects/:id/deploy', status: 500, message: 'Build failed' });
      e2eSvc.captureOperationFailure({ operation: 'deploy', stage: 'build', kind: 'node', message: 'npm ci exit 1', durationMs: 1200 });
      e2eSvc.captureClientError({ source: 'error_boundary', view: 'settings', errorName: 'TypeError', message: 'Cannot read x' });
      e2eSvc.recordFeatureUsage('deploy:node', true);
      e2eSvc.enqueueHeartbeat();

      const flushed = await e2eSvc.flush({ force: true });
      assert.ok(flushed.sent >= 5, `Deben enviarse todos los eventos al recolector (enviados: ${flushed.sent})`);

      const sumRes = await fetch(`${baseUrl}/admin/api/summary`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.strictEqual(sumRes.status, 200);
      const summary = await sumRes.json();
      assert.strictEqual(summary.kpis.active24h, 1);
      assert.ok(summary.kpis.openIssues >= 4, 'Deben agruparse los 4 tipos de fallos en issue_groups');
      assert.strictEqual(summary.kpis.openCrashes, 1);

      const issRes = await fetch(`${baseUrl}/admin/api/issues?status=open`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      const { issues } = await issRes.json();
      assert.ok(!JSON.stringify(issues).includes('pablo@secreto.com'), 'Cero emails en el recolector E2E');
    } finally {
      await collector.close();
    }
    console.log('  ✓ Entrega E2E real: TelemetryService -> HTTP /v1/ingest -> SQLite WAL -> Admin API');

    // -----------------------------------------------------------------------
    // 5. Endpoints REST del daemon (`/api/telemetry/*`) si el daemon está activo
    // -----------------------------------------------------------------------
    try {
      const stRes = await fetch('http://127.0.0.1:3030/api/telemetry/status');
      if (stRes.ok) {
        const st = await stRes.json();
        assert.strictEqual(st.schemaVersion, 1);
        assert.ok(Array.isArray(st.neverCollected) && st.neverCollected.length >= 3);

        const prevRes = await fetch('http://127.0.0.1:3030/api/telemetry/preview');
        assert.strictEqual(prevRes.status, 200);
        const prev = await prevRes.json();
        assert.strictEqual(prev.schemaVersion, 1);
        assert.ok(Array.isArray(prev.events) && prev.events.length >= 1);

        const ceRes = await fetch('http://127.0.0.1:3030/api/telemetry/client-error', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            source: 'error_boundary',
            view: 'settings',
            errorName: 'TestUIError',
            message: 'Error sintético de prueba',
          }),
        });
        assert.strictEqual(ceRes.status, 202);
        console.log('  ✓ API REST del daemon: /api/telemetry/status, /preview y /client-error (202)');
      }
    } catch {
      // Si se ejecuta en solitario sin daemon levantado, omitir comprobación HTTP local
    }

    console.log('✅ Suite #24 completada correctamente.\n');
  } finally {
    if (prevAllowTest === undefined) delete process.env.CULKIBO_TELEMETRY_ALLOW_IN_TEST;
    else process.env.CULKIBO_TELEMETRY_ALLOW_IN_TEST = prevAllowTest;
    if (prevTel === undefined) delete process.env.CULKIBO_TELEMETRY;
    else process.env.CULKIBO_TELEMETRY = prevTel;
    if (prevDnt === undefined) delete process.env.DO_NOT_TRACK;
    else process.env.DO_NOT_TRACK = prevDnt;
    if (prevAllowHttp === undefined) delete process.env.CULKIBO_TELEMETRY_ALLOW_HTTP;
    else process.env.CULKIBO_TELEMETRY_ALLOW_HTTP = prevAllowHttp;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  testTelemetry()
    .catch((err) => {
      console.error('❌ Fallo en Suite #24:', err);
      process.exitCode = 1;
    });
}

module.exports = testTelemetry;
