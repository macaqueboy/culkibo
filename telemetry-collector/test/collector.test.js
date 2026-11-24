'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { createCollectorServer } = require('../server');

async function startTempCollector(extra = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-collector-test-'));
  const alertsReceived = [];
  const adminToken = 'test-admin-secret-token-1234567890';
  const app = createCollectorServer({
    PORT: 0,
    BIND: '127.0.0.1',
    DATA_DIR: dir,
    ADMIN_TOKEN: adminToken,
    ALERT_WEBHOOK_URL: 'https://alerts.example.invalid/hook',
    ALERT_WEBHOOK_SECRET: 'hook-hmac-secret',
    ALERT_COOLDOWN_MS: 0,
    fetchImpl: async (url, init) => {
      alertsReceived.push({ url, headers: init.headers, body: JSON.parse(init.body) });
      return { ok: true, status: 200 };
    },
    ...extra,
  });

  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  const addr = app.server.address();
  const baseUrl = `http://127.0.0.1:${addr.port}`;
  return {
    app,
    dir,
    baseUrl,
    adminToken,
    alertsReceived,
    async cleanup() {
      await app.close();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

test('recolector: ingesta Schema v1, agrupación de fallos, segunda capa anti-PII y cero IPs almacenadas', async () => {
  const ctx = await startTempCollector();
  try {
    const instanceId = crypto.randomUUID();

    // 1. Healthcheck público
    const healthRes = await fetch(`${ctx.baseUrl}/health`);
    assert.equal(healthRes.status, 200);
    const health = await healthRes.json();
    assert.equal(health.ok, true);

    // 2. Rechaza payload inválido
    const badRes = await fetch(`${ctx.baseUrl}/v1/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ schemaVersion: 2, instanceId: 'not-a-uuid', events: [] }),
    });
    assert.equal(badRes.status, 400);

    // 3. Ingesta heartbeat + crash + feature_usage con PII deliberada (debe ser saneada en servidor)
    const ingestRes = await fetch(`${ctx.baseUrl}/v1/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        schemaVersion: 1,
        instanceId,
        appVersion: '1.0.0',
        sentAt: new Date().toISOString(),
        events: [
          {
            id: crypto.randomUUID(),
            type: 'instance_heartbeat',
            ts: new Date().toISOString(),
            occurrences: 1,
            data: {
              culkiboVersion: '1.0.0',
              nodeVersion: 'v24.14.0',
              os: { platform: 'linux', arch: 'x64' },
              ramBucket: '8-16GB',
              installMethod: 'docker',
              capabilities: { dockerAvailable: true, caddyAvailable: true },
              counts: { projects: '1-5', databases: '1-3' },
            },
          },
          {
            id: crypto.randomUUID(),
            type: 'server_crash',
            ts: new Date().toISOString(),
            fingerprint: 'aabbccdd11223344',
            occurrences: 2,
            data: {
              kind: 'uncaughtException',
              errorName: 'TypeError',
              message: 'Error para pablo@privado.com desde 198.51.100.77 con Bearer sk_live_secret1234567890',
              stack: ['at /home/pablo/app/server/index.js:42:10'],
            },
          },
          {
            id: crypto.randomUUID(),
            type: 'feature_usage',
            ts: new Date().toISOString(),
            occurrences: 1,
            data: {
              counters: { 'deploy:docker': { ok: 4, fail: 1 } },
            },
          },
        ],
      }),
    });
    assert.equal(ingestRes.status, 202);
    const ingestBody = await ingestRes.json();
    assert.equal(ingestBody.accepted, 3);
    assert.equal(ingestBody.alertsQueued, 1);

    // Esperar a que se dispare el alertador asíncrono
    await new Promise((r) => setTimeout(r, 80));
    assert.equal(ctx.alertsReceived.length, 1);
    assert.equal(ctx.alertsReceived[0].body.trigger, 'new_issue');
    assert.ok(String(ctx.alertsReceived[0].headers['X-Culkibo-Signature'] || '').startsWith('sha256='));

    // 4. Admin API exige Bearer token válido
    const unauth = await fetch(`${ctx.baseUrl}/admin/api/summary`);
    assert.equal(unauth.status, 401);
    const wrongTok = await fetch(`${ctx.baseUrl}/admin/api/summary`, {
      headers: { Authorization: 'Bearer wrong-token' },
    });
    assert.equal(wrongTok.status, 401);

    // 5. Summary y Issues con autenticación válida
    const sumRes = await fetch(`${ctx.baseUrl}/admin/api/summary`, {
      headers: { Authorization: `Bearer ${ctx.adminToken}` },
    });
    assert.equal(sumRes.status, 200);
    const summary = await sumRes.json();
    assert.equal(summary.kpis.active24h, 1);
    assert.equal(summary.kpis.openCrashes, 1);
    assert.equal(summary.capabilities.dockerYes, 1);
    assert.equal(summary.topFeatures[0].feature, 'deploy:docker');

    const issRes = await fetch(`${ctx.baseUrl}/admin/api/issues?status=open`, {
      headers: { Authorization: `Bearer ${ctx.adminToken}` },
    });
    const { issues } = await issRes.json();
    assert.equal(issues.length, 1);
    const dumped = JSON.stringify(issues[0]);
    assert.ok(!dumped.includes('pablo@privado.com'), 'Email debe ser saneado en segunda capa');
    assert.ok(!dumped.includes('198.51.100.77'), 'IP debe ser saneada en segunda capa');
    assert.ok(!dumped.includes('sk_live_secret1234567890'), 'Token debe ser saneado en segunda capa');
    assert.ok(!dumped.includes('/home/pablo'), 'Ruta home debe ser saneada en segunda capa');

    // 6. Marcar como resuelto y disparar regresión en una nueva versión 1.0.1
    const patchRes = await fetch(`${ctx.baseUrl}/admin/api/issues/aabbccdd11223344`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${ctx.adminToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ status: 'resolved' }),
    });
    assert.equal(patchRes.status, 200);

    const regRes = await fetch(`${ctx.baseUrl}/v1/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        schemaVersion: 1,
        instanceId,
        appVersion: '1.0.1',
        events: [{
          id: crypto.randomUUID(),
          type: 'server_crash',
          fingerprint: 'aabbccdd11223344',
          occurrences: 1,
          data: { kind: 'uncaughtException', errorName: 'TypeError', message: 'Reapareció en 1.0.1' },
        }],
      }),
    });
    assert.equal(regRes.status, 202);
    await new Promise((r) => setTimeout(r, 80));
    assert.equal(ctx.alertsReceived.length, 2);
    assert.equal(ctx.alertsReceived[1].body.trigger, 'regression');

    // 7. Export CSV & JSON + comprobar que no hay IP 127.0.0.1 en el archivo NDJSON
    const csvRes = await fetch(`${ctx.baseUrl}/admin/api/export?format=csv`, {
      headers: { Authorization: `Bearer ${ctx.adminToken}` },
    });
    assert.equal(csvRes.status, 200);
    const csv = await csvRes.text();
    assert.ok(csv.includes('aabbccdd11223344'));

    const archiveFiles = fs.readdirSync(path.join(ctx.dir, 'archive'));
    assert.ok(archiveFiles.length >= 1, 'Debe escribir archivo diario NDJSON');
    const archiveRaw = fs.readFileSync(path.join(ctx.dir, 'archive', archiveFiles[0]), 'utf8');
    assert.ok(!archiveRaw.includes('127.0.0.1'), 'Nunca debe persistirse la IP del cliente en disco');
  } finally {
    await ctx.cleanup();
  }
});

test('recolector: respeta límite de tamaño (413) y rate limit dual por IP e instancia (429)', async () => {
  const ctx = await startTempCollector({
    rateLimit: { ipLimit: 3, ipWindowMs: 60000, instanceLimit: 10, instanceWindowMs: 60000 },
  });
  try {
    // 413 Payload Too Large (> 64 KB)
    const huge = JSON.stringify({
      schemaVersion: 1,
      instanceId: crypto.randomUUID(),
      appVersion: '1.0.0',
      events: [{ type: 'client_error', data: { message: 'x'.repeat(70 * 1024) } }],
    });
    const bigRes = await fetch(`${ctx.baseUrl}/v1/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: huge,
    });
    assert.equal(bigRes.status, 413);

    // Rate limit por IP hasheada (límite 3; ya consumió 1 en la petición anterior)
    const validBody = JSON.stringify({
      schemaVersion: 1,
      instanceId: crypto.randomUUID(),
      appVersion: '1.0.0',
      events: [{ type: 'instance_heartbeat', data: { os: { platform: 'linux' } } }],
    });
    const r2 = await fetch(`${ctx.baseUrl}/v1/ingest`, { method: 'POST', body: validBody });
    const r3 = await fetch(`${ctx.baseUrl}/v1/ingest`, { method: 'POST', body: validBody });
    const r4 = await fetch(`${ctx.baseUrl}/v1/ingest`, { method: 'POST', body: validBody });
    assert.equal(r2.status, 202);
    assert.equal(r3.status, 202);
    assert.equal(r4.status, 429);
    assert.ok(Number(r4.headers.get('retry-after')) >= 1);
  } finally {
    await ctx.cleanup();
  }
});
