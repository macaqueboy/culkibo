const assert = require('assert');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const Project = require('../server/models/Project');
const projectManager = require('../server/services/projectManager');
const caddyManager = require('../server/services/caddyManager');
const { DeployManager, helpers: deployHelpers } = require('../server/services/deployManager');
const auditLogger = require('../server/services/auditLogger');
const systemDoctor = require('../server/services/systemDoctor');

/**
 * Crea un servidor HTTP efímero en 127.0.0.1:0 y devuelve { server, port, url, close }.
 * @param {(req: http.IncomingMessage, res: http.ServerResponse) => void} handler
 */
async function startMockServer(handler) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(undefined)));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  return {
    server,
    port,
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(() => resolve(undefined)))
  };
}

/** Instancia aislada de DeployManager sin tocar disco ni daemon real. */
function makeSandbox() {
  const dm = new DeployManager();
  dm.store = {};
  dm.saveStore = () => {};
  dm.notify = () => {};
  dm._globalFreezeWindows = [];
  dm._saveGlobalFreezeWindows = () => {};
  dm.hasBinary = async () => false;
  dm.detectDocker = async () => ({ available: true, version: 'mock-27.0', reason: null });
  return dm;
}

/** Crea un directorio temporal de fixture para pruebas de despliegue. */
function makeFixtureDir(root, name, files = { 'Dockerfile': 'FROM alpine\nEXPOSE 3000\n' }) {
  const dir = path.join(root, name);
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, 'utf8');
  }
  return dir;
}

// ---------------------------------------------------------------------------
// 1. Modelo Project y validación estricta en ProjectManager
// ---------------------------------------------------------------------------
async function testProjectModelAndValidation() {
  const def = new Project({ name: 'Default App' });
  assert.strictEqual(def.serverId, 'local', 'serverId por defecto debe ser local');
  assert.strictEqual(def.teamId, 'team_default', 'teamId por defecto debe ser team_default');
  assert.deepStrictEqual(def.smokeTests, [], 'smokeTests por defecto debe ser []');
  assert.strictEqual(def.canary.enabled, false, 'canary.enabled por defecto debe ser false');
  assert.strictEqual(def.canary.weightPercent, 10);
  assert.strictEqual(def.canary.observeSeconds, 30);
  assert.strictEqual(def.canary.maxErrorRate, 0.05);
  assert.deepStrictEqual(def.freezeWindows, [], 'freezeWindows por defecto debe ser []');

  // Campos válidos complejos
  const validPayload = {
    name: 'Prod API',
    serverId: 'eu-vps_01',
    teamId: 'team_alpha',
    smokeTests: [
      { path: '/health?full=1', expectStatus: 200, expectBodyContains: 'OK', maxLatencyMs: 800 }
    ],
    canary: { enabled: true, weightPercent: 25, observeSeconds: 45, maxErrorRate: 0.02 },
    freezeWindows: [
      { days: [5, 6], startHour: 22, endHour: 6, tz: 'Europe/Madrid', reason: 'Congelación de fin de semana' }
    ]
  };
  projectManager.validateProjectData({ ...validPayload });
  const rich = new Project(validPayload);
  assert.strictEqual(rich.serverId, 'eu-vps_01');
  assert.strictEqual(rich.teamId, 'team_alpha');
  assert.strictEqual(rich.smokeTests.length, 1);
  assert.strictEqual(rich.smokeTests[0].path, '/health?full=1');
  assert.strictEqual(rich.canary.enabled, true);
  assert.strictEqual(rich.canary.weightPercent, 25);
  assert.strictEqual(rich.freezeWindows.length, 1);
  assert.strictEqual(rich.freezeWindows[0].tz, 'Europe/Madrid');

  // Rechazos estrictos
  assert.throws(() => projectManager.validateProjectData({ serverId: '../etc/passwd' }), /Invalid serverId/);
  assert.throws(() => projectManager.validateProjectData({ serverId: 'BAD UPPER' }), /Invalid serverId/);
  assert.throws(() => projectManager.validateProjectData({ teamId: 'bad team!' }), /Invalid teamId/);
  assert.throws(() => projectManager.validateProjectData({
    smokeTests: [{ path: 'http://169.254.169.254/latest/meta-data/' }]
  }), /Invalid smokeTest path/);
  assert.throws(() => projectManager.validateProjectData({
    smokeTests: [{ path: '/../../etc/passwd' }]
  }), /Invalid smokeTest path/);
  assert.throws(() => projectManager.validateProjectData({
    smokeTests: [{ path: '//evil.example/x' }]
  }), /Invalid smokeTest path/);
  assert.throws(() => projectManager.validateProjectData({
    smokeTests: [{ path: '/ok', headers: { Host: 'evil.internal' } }]
  }), /Disallowed smokeTest header/);
  assert.throws(() => projectManager.validateProjectData({
    smokeTests: [{ path: '/ok', jsonPathEquals: { path: '__proto__.polluted', value: true } }]
  }), /jsonPathEquals/);
  assert.throws(() => projectManager.validateProjectData({
    canary: { enabled: true, weightPercent: 100 }
  }), /weightPercent/);
  assert.throws(() => projectManager.validateProjectData({
    canary: { enabled: true, maxErrorRate: 1.5 }
  }), /maxErrorRate/);
  assert.throws(() => projectManager.validateProjectData({
    freezeWindows: [{ days: [1], startHour: 9, endHour: 17, tz: 'Mars/Phobos' }]
  }), /IANA timezone/);
  assert.throws(() => projectManager.validateProjectData({
    freezeWindows: [{ days: [9], startHour: 9, endHour: 17, tz: 'UTC' }]
  }), /freezeWindow day/);
  assert.throws(() => projectManager.validateProjectData({
    freezeWindows: [{ days: [1], startHour: 25, endHour: 26, tz: 'UTC' }]
  }), /startHour/);

  // Inmutabilidad de teamId en update() genérico (evita cross-team IDOR)
  const origSave = projectManager.saveProjects;
  const origFlush = projectManager.flushToDisk;
  projectManager.saveProjects = () => {};
  projectManager.flushToDisk = async () => {};
  let created = null;
  try {
    created = projectManager.create({ name: 'Tenant Check', teamId: 'team_orig', serverId: 'eu-vps-1' });
    const updated = projectManager.update(created.id, { name: 'Tenant Renamed', teamId: 'team_hijacked' });
    assert.strictEqual(updated.name, 'Tenant Renamed');
    assert.strictEqual(updated.teamId, 'team_orig', 'teamId debe permanecer inmutable en update() genérico');
  } finally {
    if (created) projectManager.projects.delete(created.id);
    projectManager.saveProjects = origSave;
    projectManager.flushToDisk = origFlush;
  }

  console.log('  ✓ Project y ProjectManager: valores por defecto, validación estricta e inmutabilidad de teamId');
}

// ---------------------------------------------------------------------------
// 2. Caddy adminUrl override (sin mutar singleton) y buildSleepingRoute
// ---------------------------------------------------------------------------
async function testCaddyAdminOverrideAndSleepingRoute() {
  // Invariante tests/caddy.test.js:51 — buildRoute sin middleware opcional emite handle: [reverse_proxy]
  const plainRoute = caddyManager.buildRoute({
    projectId: 'inv_plain',
    hostnames: ['plain.culkibo.test'],
    upstreams: ['127.0.0.1:9101']
  });
  assert.strictEqual(plainRoute.handle.length, 1);
  assert.strictEqual(plainRoute.handle[0].handler, 'reverse_proxy');
  assert.strictEqual(plainRoute.handle[0].upstreams[0].dial, '127.0.0.1:9101');
  assert.strictEqual(plainRoute.terminal, true);

  // buildSleepingRoute (Scale-to-Zero wake-on-request)
  const sleepRoute = caddyManager.buildSleepingRoute({
    projectId: 'proj_sleep',
    hostnames: ['sleep.ejemplo.com'],
    wakeTarget: '127.0.0.1:3030',
    wakeSecret: 'wake_sec_123'
  });
  assert.strictEqual(sleepRoute['@id'], 'culkibo_proj_sleep');
  assert.deepStrictEqual(sleepRoute.match[0].host, ['sleep.ejemplo.com']);
  assert.strictEqual(sleepRoute.terminal, true);
  assert.strictEqual(sleepRoute.handle[0].handler, 'rewrite');
  assert.strictEqual(sleepRoute.handle[0].uri, '/_culkibo/wake/proj_sleep');
  assert.strictEqual(sleepRoute.handle[1].handler, 'reverse_proxy');
  assert.strictEqual(sleepRoute.handle[1].upstreams[0].dial, '127.0.0.1:3030');
  assert.deepStrictEqual(sleepRoute.handle[1].headers.request.set['X-Culkibo-Wake-Project'], ['proj_sleep']);
  assert.deepStrictEqual(sleepRoute.handle[1].headers.request.set['X-Culkibo-Wake-Path'], ['{http.request.orig_uri}']);
  assert.deepStrictEqual(sleepRoute.handle[1].headers.request.set['X-Culkibo-Wake-Uri'], ['{http.request.orig_uri}']);
  assert.deepStrictEqual(sleepRoute.handle[1].headers.request.set['X-Culkibo-Wake-Secret'], ['wake_sec_123']);

  const sleepViaKind = caddyManager.buildRoute({
    projectId: 'proj_sleep_url',
    hostnames: ['sleep2.ejemplo.com'],
    kind: 'sleeping',
    wakeTarget: 'http://127.0.0.1:4040/_culkibo/wake/custom'
  });
  assert.strictEqual(sleepViaKind.handle[0].uri, '/_culkibo/wake/custom');
  assert.strictEqual(sleepViaKind.handle[1].upstreams[0].dial, '127.0.0.1:4040');

  // Mock de Caddy remoto para verificar adminUrl override SIN mutar estado del singleton
  const remoteRoutes = new Map();
  const requestsSeen = [];
  const mockCaddy = await startMockServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const bodyStr = Buffer.concat(chunks).toString('utf8');
      requestsSeen.push({ method: req.method, url: req.url });
      if (req.method === 'GET' && req.url === '/reverse_proxy/upstreams') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify([{ address: '127.0.0.1:20010', num_requests: 1, fails: 2 }]));
        return;
      }
      if (req.method === 'GET' && req.url === '/config/apps/http/servers/culkibo/routes') {
        res.writeHead(200, { 'Content-Type': 'application/json', ETag: '"e1"' });
        res.end(JSON.stringify(Array.from(remoteRoutes.values())));
        return;
      }
      if (req.method === 'POST' && req.url === '/config/apps/http/servers/culkibo/routes') {
        const obj = JSON.parse(bodyStr);
        remoteRoutes.set(obj['@id'], obj);
        res.writeHead(200);
        res.end();
        return;
      }
      if (req.url && req.url.startsWith('/id/')) {
        const id = req.url.slice(4);
        if (req.method === 'PATCH') {
          if (!remoteRoutes.has(id)) {
            res.writeHead(404);
            res.end('unknown object ID');
            return;
          }
          remoteRoutes.set(id, JSON.parse(bodyStr));
          res.writeHead(200);
          res.end();
          return;
        }
        if (req.method === 'DELETE') {
          if (!remoteRoutes.has(id)) {
            res.writeHead(404);
            res.end('unknown object ID');
            return;
          }
          remoteRoutes.delete(id);
          res.writeHead(200);
          res.end();
          return;
        }
      }
      res.writeHead(404);
      res.end();
    });
  });

  const snapAdminUrl = caddyManager.adminUrl;
  const snapLastDetection = caddyManager.lastDetection;
  const snapAppliedKeys = Array.from(caddyManager._appliedRouteJson.keys());
  try {
    const det = await caddyManager.detect({ adminUrl: mockCaddy.url });
    assert.strictEqual(det.available, true);
    assert.strictEqual(det.adminUrl, mockCaddy.url);

    const up = await caddyManager.upsertRoute({
      projectId: 'remote_proj',
      hostnames: ['remote.ejemplo.com'],
      upstreams: ['127.0.0.1:20010']
    }, { adminUrl: mockCaddy.url });
    assert.strictEqual(up.created, true);
    assert.ok(remoteRoutes.has('culkibo_remote_proj'));

    const upstreams = await caddyManager.getUpstreamsStatus({ adminUrl: mockCaddy.url });
    assert.strictEqual(upstreams.length, 1);
    assert.strictEqual(upstreams[0].fails, 2);

    const rm = await caddyManager.removeRoute('remote_proj', { adminUrl: mockCaddy.url });
    assert.strictEqual(rm.removed, true);
    assert.ok(!remoteRoutes.has('culkibo_remote_proj'));

    // Verificar cero mutaciones en el singleton local
    assert.strictEqual(caddyManager.adminUrl, snapAdminUrl, 'adminUrl del singleton no debe mutar');
    assert.strictEqual(caddyManager.lastDetection, snapLastDetection, 'lastDetection del singleton no debe mutar');
    assert.deepStrictEqual(
      Array.from(caddyManager._appliedRouteJson.keys()),
      snapAppliedKeys,
      '_appliedRouteJson del singleton no debe mutar con adminUrl remoto'
    );
  } finally {
    await mockCaddy.close();
  }

  console.log('  ✓ CaddyManager: adminUrl override aislado, getUpstreamsStatus y buildSleepingRoute');
}

// ---------------------------------------------------------------------------
// 3. Ventanas de congelación (Freeze Windows): bloqueo, override auditado y rollback libre
// ---------------------------------------------------------------------------
async function testDeployFreezeWindows(tmpRoot) {
  const dm = makeSandbox();
  auditLogger.resetForTests();

  // Ventana nocturna viernes 22:00 -> sábado 06:00 UTC
  const overnightProject = {
    id: 'proj_freeze',
    name: 'Checkout',
    domains: ['checkout.ejemplo.com'],
    envVars: {},
    freezeWindows: [
      { days: [5], startHour: 22, endHour: 6, tz: 'UTC', reason: 'No desplegar viernes por la noche' }
    ]
  };
  const fri23Utc = new Date('2026-11-27T23:00:00Z'); // Viernes 23:00 UTC
  const sat03Utc = new Date('2026-11-28T03:00:00Z'); // Sábado 03:00 UTC (dentro de ventana nocturna del viernes!)
  const sat06Utc = new Date('2026-11-28T06:00:00Z'); // Sábado 06:00 UTC (ya terminó)
  const thu12Utc = new Date('2026-11-26T12:00:00Z'); // Jueves 12:00 UTC

  assert.strictEqual(dm.isInFreezeWindow(overnightProject, fri23Utc), true, 'Viernes 23:00 debe estar congelado');
  assert.strictEqual(dm.isInFreezeWindow(overnightProject, sat03Utc), true, 'Sábado 03:00 debe seguir dentro de ventana nocturna');
  assert.strictEqual(dm.isInFreezeWindow(overnightProject, sat06Utc), false, 'Sábado 06:00 ya está fuera');
  assert.strictEqual(dm.isInFreezeWindow(overnightProject, thu12Utc), false, 'Jueves 12:00 está fuera');

  // Helper puro exportado compartido con environmentManager
  const evalRes = deployHelpers.evaluateFreezeStatus(overnightProject, fri23Utc);
  assert.strictEqual(evalRes.frozen, true);
  assert.strictEqual(evalRes.reason, 'No desplegar viernes por la noche');
  assert.strictEqual(deployHelpers.evaluateFreezeStatus(overnightProject, { now: fri23Utc, trigger: 'rollback' }).frozen, false, 'Rollback jamás se bloquea');

  // Bloqueo en deploy() y auditoría 423
  let buildCalled = false;
  const contextDir = makeFixtureDir(tmpRoot, 'freeze-app');
  dm.detectStrategy = async () => ({
    builder: 'dockerfile', stack: 'dockerfile', dockerfile: 'Dockerfile',
    containerPort: 3000, healthPath: '/', injectHealthcheck: false, reason: 'mock'
  });
  dm.runBuild = async () => { buildCalled = true; return { ok: true }; };
  dm.ensureNetwork = async () => true;
  dm.findFreePort = async () => 23100;
  dm.resolveUpstream = async ({ containerName, containerPort }) => ({ dial: `${containerName}:${containerPort}`, mode: 'network' });
  dm.waitForHealth = async () => ({ healthy: true, attempts: 1, status: 200 });
  dm.switchRoute = async (dep) => { dep.routeSwitched = true; return { ok: true }; };
  dm.runDocker = async () => ({ code: 0, stdout: 'true\n', stderr: '' });

  await assert.rejects(
    () => dm.deploy(overnightProject, { contextDir, now: fri23Utc }),
    (err) => err && err.code === 'DEPLOY_FROZEN' && err.status === 423
  );
  assert.strictEqual(buildCalled, false, 'Un despliegue bloqueado por freeze nunca debe iniciar el build');
  const blockedAudit = auditLogger.query({ action: 'deploy.freeze_blocked', limit: 5 });
  assert.ok(blockedAudit.length >= 1, 'El bloqueo por freeze debe quedar auditado');

  // Bloqueo limpio en enqueue()
  const enq = dm.enqueue(overnightProject, { contextDir, now: fri23Utc, trigger: 'webhook' });
  assert.strictEqual(enq.started, false);
  assert.strictEqual(enq.blocked, true);
  assert.strictEqual(enq.code, 'DEPLOY_FROZEN');

  // Override explícito auditado
  const forced = await dm.deploy(overnightProject, {
    contextDir,
    now: fri23Utc,
    overrideFreeze: true,
    actor: 'pablo',
    overrideReason: 'Hotfix crítico de pagos'
  });
  assert.strictEqual(forced.status, 'activo');
  assert.strictEqual(buildCalled, true);
  assert.ok(forced.freezeOverride && forced.freezeOverride.overridden === true);
  assert.strictEqual(forced.freezeOverride.actor, 'pablo');
  const overrideAudit = auditLogger.query({ action: 'deploy.freeze_override', limit: 5 });
  assert.ok(overrideAudit.length >= 1, 'La anulación overrideFreeze debe quedar auditada');

  // Rollback nunca es bloqueado durante la congelación
  dm.store['proj_freeze'].previous = {
    deploymentId: 'dep_prev', imageTag: 'culkibo/freeze:b0', containerName: 'culkibo_freeze_b0',
    hostPort: 23099, containerPort: 3000, upstream: 'culkibo_freeze_b0:3000',
    hostnames: ['checkout.ejemplo.com'], healthPath: '/'
  };
  const rb = await dm.rollback('proj_freeze', { drainTimeoutMs: 5, stopGraceSeconds: 0 });
  await dm.awaitDrain('proj_freeze');
  assert.strictEqual(rb.status, 'activo', 'Rollback debe permitirse siempre durante ventanas de congelación');

  console.log('  ✓ Freeze Windows: overnight/tz, bloqueo 423, overrideFreeze auditado y rollback exento');
}

// ---------------------------------------------------------------------------
// 4. Smoke Tests post-despliegue (pass / fail / latency / SSRF + pipeline)
// ---------------------------------------------------------------------------
async function testPostDeploySmokeTests(tmpRoot) {
  let seenHostHeader = null;
  const appServer = await startMockServer((req, res) => {
    seenHostHeader = req.headers.host || null;
    if (req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: { ok: true }, version: 'v2-ready' }));
      return;
    }
    if (req.url === '/slow') {
      setTimeout(() => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('finally');
      }, 140);
      return;
    }
    if (req.url === '/broken') {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Internal Error');
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
  });

  try {
    const dm = makeSandbox();
    const passRes = await dm.runSmokeTests(
      `127.0.0.1:${appServer.port}`,
      [
        {
          name: 'api-health',
          path: '/health',
          expectStatus: 200,
          expectBodyContains: 'v2-ready',
          maxLatencyMs: 2000,
          jsonPathEquals: { path: 'status.ok', value: true }
        }
      ],
      { hostHeader: 'api.ejemplo.com' }
    );
    assert.strictEqual(passRes.ok, true, `Smoke test debía pasar: ${JSON.stringify(passRes)}`);
    assert.strictEqual(passRes.passed, 1);
    assert.strictEqual(seenHostHeader, 'api.ejemplo.com');

    // Fallos: status incorrecto, substring ausente, latencia excedida y ruta SSRF rechazada
    const failRes = await dm.runSmokeTests(`127.0.0.1:${appServer.port}`, [
      { name: 'bad-status', path: '/broken', expectStatus: 200 },
      { name: 'missing-body', path: '/health', expectStatus: 200, expectBodyContains: 'NO_EXISTE' },
      { name: 'too-slow', path: '/slow', expectStatus: 200, maxLatencyMs: 30 },
      { name: 'ssrf-attempt', path: 'http://169.254.169.254/latest/meta-data/' }
    ]);
    assert.strictEqual(failRes.ok, false);
    assert.strictEqual(failRes.failed, 4);
    assert.ok(/Latencia/.test(failRes.checks[2].error));
    assert.ok(/inválida/.test(failRes.checks[3].error));

    // Rechazo SSRF de hostnames de metadatos y dominios externos en upstream directo
    await assert.rejects(
      () => dm.runSmokeTests('http://metadata.google.internal:80', [{ path: '/' }]),
      /SSRF|metadatos/
    );
    await assert.rejects(
      () => dm.runSmokeTests('http://evil.example:80', [{ path: '/' }]),
      /bloqueado/
    );

    // Integración en deploy(): si falla smoke test, NO conmuta ruta y conserva versión anterior
    const contextDir = makeFixtureDir(tmpRoot, 'smoke-app');
    let switched = false;
    const removed = [];
    const oldCurrent = {
      deploymentId: 'dep_v1', imageTag: 'culkibo/smk:v1', containerName: 'culkibo_smk_v1',
      hostPort: 23200, containerPort: 3000, upstream: 'culkibo_smk_v1:3000',
      hostnames: ['smk.ejemplo.com'], healthPath: '/'
    };
    dm.store['proj_smk'] = { current: oldCurrent, previous: null, history: [] };
    dm.detectStrategy = async () => ({
      builder: 'dockerfile', stack: 'dockerfile', dockerfile: 'Dockerfile',
      containerPort: 3000, healthPath: '/', injectHealthcheck: false, reason: 'mock'
    });
    dm.runBuild = async () => ({ ok: true });
    dm.ensureNetwork = async () => true;
    dm.findFreePort = async () => appServer.port;
    dm.resolveUpstream = async ({ containerName, containerPort }) => ({ dial: `${containerName}:${containerPort}`, mode: 'network' });
    dm.waitForHealth = async () => ({ healthy: true, attempts: 1, status: 200 });
    dm.switchRoute = async (dep) => { switched = true; dep.routeSwitched = true; return { ok: true }; };
    dm.runDocker = async (args) => {
      if (args[0] === 'rm') removed.push(args[args.length - 1]);
      return { code: 0, stdout: '', stderr: '' };
    };

    const failedDep = await dm.deploy({
      id: 'proj_smk',
      name: 'Smoke Fail',
      domains: ['smk.ejemplo.com'],
      envVars: {},
      smokeTests: [{ path: '/broken', expectStatus: 200 }]
    }, { contextDir });
    assert.strictEqual(failedDep.status, 'fallido');
    assert.strictEqual(switched, false, 'Un smoke test fallido jamás debe conmutar tráfico');
    assert.strictEqual(dm.store['proj_smk'].current, oldCurrent, 'La versión anterior sigue intacta al 100%');
    assert.ok(removed.includes(failedDep.containerName), 'El contenedor candidato fallido debe retirarse');
    assert.ok(failedDep.smokeTestResults && failedDep.smokeTestResults.ok === false);

    // Smoke test exitoso promociona normalmente
    const okDep = await dm.deploy({
      id: 'proj_smk',
      name: 'Smoke Pass',
      domains: ['smk.ejemplo.com'],
      envVars: {},
      smokeTests: [{ path: '/health', expectStatus: 200, expectBodyContains: 'v2-ready', maxLatencyMs: 2000 }]
    }, { contextDir, drainTimeoutMs: 5, stopGraceSeconds: 0 });
    await dm.awaitDrain('proj_smk');
    assert.strictEqual(okDep.status, 'activo');
    assert.strictEqual(switched, true);
    assert.ok(okDep.smokeTestResults && okDep.smokeTestResults.ok === true && okDep.smokeTestResults.passed === 1);
  } finally {
    await appServer.close();
  }

  console.log('  ✓ Smoke Tests: pass/fail, latencia, SSRF bloqueado y aborto previo a cutover');
}

// ---------------------------------------------------------------------------
// 5. Canary Auto-Guard (auto-promoción y auto-rollback ante fallo)
// ---------------------------------------------------------------------------
async function testCanaryAutoGuard(tmpRoot) {
  let canaryHealthy = true;
  let canaryRequests = 0;
  const canaryServer = await startMockServer((req, res) => {
    canaryRequests++;
    if (canaryHealthy) {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('CANARY_OK');
    } else {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('CANARY_BOOM');
    }
  });

  try {
    const contextDir = makeFixtureDir(tmpRoot, 'canary-app');

    // A) Canario sano -> reparto progresivo -> auto-promoción al 100%
    const dmOk = makeSandbox();
    const eventsOk = [];
    const stableRelease = {
      deploymentId: 'dep_stable', imageTag: 'culkibo/can:v1', containerName: 'culkibo_can_v1',
      hostPort: 23300, containerPort: 3000, upstream: 'culkibo_can_v1:3000',
      hostnames: ['can.ejemplo.com'], healthPath: '/'
    };
    dmOk.store['proj_can'] = { current: stableRelease, previous: null, history: [] };
    dmOk.detectStrategy = async () => ({
      builder: 'dockerfile', stack: 'dockerfile', dockerfile: 'Dockerfile',
      containerPort: 3000, healthPath: '/', injectHealthcheck: false, reason: 'mock'
    });
    dmOk.runBuild = async () => ({ ok: true });
    dmOk.ensureNetwork = async () => true;
    dmOk.findFreePort = async () => canaryServer.port;
    dmOk.resolveUpstream = async ({ containerName, containerPort }) => ({ dial: `${containerName}:${containerPort}`, mode: 'network' });
    dmOk.waitForHealth = async () => ({ healthy: true, attempts: 1, status: 200 });
    dmOk.switchCanaryRoute = async (_dep, _hosts, { stableDial, canaryDial, canaryWeight }) => {
      eventsOk.push(`canary:${canaryWeight}:${stableDial}->${canaryDial}`);
      return { ok: true, weights: [100 - canaryWeight, canaryWeight] };
    };
    dmOk.switchRoute = async (dep, _hosts, dial) => {
      eventsOk.push(`full:${dial}`);
      dep.routeSwitched = true;
      return { ok: true };
    };
    dmOk.runDocker = async (args) => {
      if (args[0] === 'inspect') return { code: 0, stdout: 'true|false|0\n', stderr: '' };
      return { code: 0, stdout: '', stderr: '' };
    };

    canaryHealthy = true;
    const promoted = await dmOk.deploy({
      id: 'proj_can',
      name: 'Canary App',
      domains: ['can.ejemplo.com'],
      envVars: {},
      smokeTests: [{ path: '/check', expectStatus: 200, expectBodyContains: 'CANARY_OK' }],
      canary: { enabled: true, weightPercent: 20, observeSeconds: 0.04, maxErrorRate: 0, checksPerStep: 2 }
    }, { contextDir, drainTimeoutMs: 5, stopGraceSeconds: 0 });
    await dmOk.awaitDrain('proj_can');

    assert.strictEqual(promoted.status, 'activo', `Canario sano debía promocionar: ${promoted.error}`);
    assert.ok(eventsOk[0].startsWith('canary:20:'), 'Primero debe abrir tráfico canario al 20%');
    assert.ok(eventsOk[1] === `full:${promoted.containerName}:3000`, 'Después debe promocionar al 100%');
    assert.strictEqual(dmOk.store['proj_can'].current.containerName, promoted.containerName);
    assert.strictEqual(promoted.canaryResult.promoted, true);
    assert.strictEqual(promoted.canaryResult.rolledBack, false);
    assert.strictEqual(dmOk.getCanaryState('proj_can'), null, 'activeCanaries debe limpiarse tras promover');
    assert.ok(canaryRequests >= 2);

    // B) Canario fallido durante observación -> auto-rollback inmediato a stableDial
    const dmFail = makeSandbox();
    auditLogger.resetForTests();
    const eventsFail = [];
    const removedFail = [];
    dmFail.store['proj_can_fail'] = { current: { ...stableRelease }, previous: null, history: [] };
    dmFail.detectStrategy = async () => ({
      builder: 'dockerfile', stack: 'dockerfile', dockerfile: 'Dockerfile',
      containerPort: 3000, healthPath: '/', injectHealthcheck: false, reason: 'mock'
    });
    dmFail.runBuild = async () => ({ ok: true });
    dmFail.ensureNetwork = async () => true;
    dmFail.findFreePort = async () => canaryServer.port;
    dmFail.resolveUpstream = async ({ containerName, containerPort }) => ({ dial: `${containerName}:${containerPort}`, mode: 'network' });
    dmFail.waitForHealth = async () => ({ healthy: true, attempts: 1, status: 200 });
    dmFail.switchCanaryRoute = async (_dep, _hosts, { canaryWeight }) => {
      eventsFail.push(`canary:${canaryWeight}`);
      // Simular que el canario empieza a devolver 500 nada más recibir tráfico
      canaryHealthy = false;
      return { ok: true, weights: [100 - canaryWeight, canaryWeight] };
    };
    dmFail.switchRoute = async (dep, _hosts, dial) => {
      eventsFail.push(`restore:${dial}`);
      dep.routeSwitched = true;
      return { ok: true };
    };
    dmFail.runDocker = async (args) => {
      if (args[0] === 'inspect') return { code: 0, stdout: 'true|false|0\n', stderr: '' };
      if (args[0] === 'rm') removedFail.push(args[args.length - 1]);
      return { code: 0, stdout: '', stderr: '' };
    };

    canaryHealthy = true;
    const rolledBack = await dmFail.deploy({
      id: 'proj_can_fail',
      name: 'Canary Fail App',
      domains: ['canfail.ejemplo.com'],
      envVars: {},
      canary: { enabled: true, weightPercent: 15, observeSeconds: 0.04, maxErrorRate: 0, checksPerStep: 2 }
    }, { contextDir });

    assert.strictEqual(rolledBack.status, 'fallido');
    assert.deepStrictEqual(eventsFail, ['canary:15', 'restore:culkibo_can_v1:3000'], 'Debe restaurar 100% tráfico a la versión estable');
    assert.strictEqual(dmFail.store['proj_can_fail'].current.containerName, 'culkibo_can_v1', 'state.current no debe mutar tras rollback canario');
    assert.ok(removedFail.includes(rolledBack.containerName), 'El contenedor canario fallido debe eliminarse');
    assert.strictEqual(rolledBack.canaryResult.rolledBack, true);
    assert.strictEqual(dmFail.getCanaryState('proj_can_fail'), null);
    const rbAudit = auditLogger.query({ action: 'deploy.canary_rollback', limit: 5 });
    assert.ok(rbAudit.length >= 1, 'El auto-rollback canario debe quedar auditado');
  } finally {
    await canaryServer.close();
  }

  console.log('  ✓ Canary Auto-Guard: tráfico progresivo, auto-promoción al 100% y auto-rollback <5 ms');
}

// ---------------------------------------------------------------------------
// 6. Enrutamiento remoto Fleet SSH (DOCKER_HOST tras filterSafeHostEnv + túneles)
// ---------------------------------------------------------------------------
async function testRemoteFleetRouting(tmpRoot) {
  const contextDir = makeFixtureDir(tmpRoot, 'fleet-app');

  // A) serverId === 'local' JAMÁS toca fleetManager
  const dmLocal = makeSandbox();
  let fleetTouchedForLocal = false;
  dmLocal._getFleetManager = () => { fleetTouchedForLocal = true; return null; };
  dmLocal.detectStrategy = async () => ({
    builder: 'dockerfile', stack: 'dockerfile', dockerfile: 'Dockerfile',
    containerPort: 3000, healthPath: '/', injectHealthcheck: false, reason: 'mock'
  });
  dmLocal.runBuild = async () => ({ ok: true });
  dmLocal.ensureNetwork = async () => true;
  dmLocal.findFreePort = async () => 23400;
  dmLocal.resolveUpstream = async ({ containerName, containerPort }) => ({ dial: `${containerName}:${containerPort}`, mode: 'network' });
  dmLocal.waitForHealth = async () => ({ healthy: true, attempts: 1, status: 200 });
  dmLocal.switchRoute = async (dep) => { dep.routeSwitched = true; return { ok: true }; };
  dmLocal.runDocker = async () => ({ code: 0, stdout: '', stderr: '' });

  const localDep = await dmLocal.deploy({ id: 'proj_local_only', name: 'Local', domains: ['local.ejemplo.com'], serverId: 'local', envVars: {} }, { contextDir });
  assert.strictEqual(localDep.status, 'activo');
  assert.strictEqual(fleetTouchedForLocal, false, 'serverId === local nunca debe invocar serverFleetManager');
  assert.strictEqual(dmLocal.store['proj_local_only'].current.serverId, 'local');

  // B) serverId !== 'local' usa túneles Docker, Health y Caddy + inyecta DOCKER_HOST DESPUÉS de filterSafeHostEnv
  const remoteHealthApp = await startMockServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('REMOTE_OK');
  });
  const remoteCaddyRoutes = new Map();
  const remoteCaddy = await startMockServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const bodyStr = Buffer.concat(chunks).toString('utf8');
      if (req.method === 'GET' && req.url === '/reverse_proxy/upstreams') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('[]');
        return;
      }
      if (req.method === 'GET' && req.url === '/config/apps/http/servers/culkibo/routes') {
        res.writeHead(200, { 'Content-Type': 'application/json', ETag: '"rem1"' });
        res.end(JSON.stringify(Array.from(remoteCaddyRoutes.values())));
        return;
      }
      if (req.method === 'POST' && req.url === '/config/apps/http/servers/culkibo/routes') {
        const obj = JSON.parse(bodyStr);
        remoteCaddyRoutes.set(obj['@id'], obj);
        res.writeHead(200);
        res.end();
        return;
      }
      if (req.method === 'PATCH' && req.url && req.url.startsWith('/id/')) {
        const id = req.url.slice(4);
        if (!remoteCaddyRoutes.has(id)) {
          res.writeHead(404);
          res.end('unknown object ID');
          return;
        }
        remoteCaddyRoutes.set(id, JSON.parse(bodyStr));
        res.writeHead(200);
        res.end();
        return;
      }
      res.writeHead(404);
      res.end();
    });
  });

  try {
    const dmRemote = makeSandbox();
    const fleetCalls = [];
    let releasedCount = 0;
    const seenDockerHosts = [];
    const TRUSTED_TUNNEL_HOST = 'unix:///tmp/ck-eu-vps-1.sock';

    const mockFleet = {
      async acquireDockerTunnel(serverId) {
        fleetCalls.push(`docker:${serverId}`);
        return {
          dockerHost: TRUSTED_TUNNEL_HOST,
          release: async () => { releasedCount++; fleetCalls.push(`release:${serverId}`); }
        };
      },
      async allocateRemotePort(serverId) {
        fleetCalls.push(`port:${serverId}`);
        return 21999;
      },
      async withPortTunnel(serverId, remotePort, fn) {
        fleetCalls.push(`healthTunnel:${serverId}:${remotePort}`);
        return fn({ localPort: remoteHealthApp.port });
      },
      async withCaddyTunnel(serverId, fn) {
        fleetCalls.push(`caddyTunnel:${serverId}`);
        return fn({ adminUrl: remoteCaddy.url });
      }
    };
    dmRemote._getFleetManager = () => mockFleet;
    dmRemote.detectDocker = async ({ env } = {}) => {
      if (env && env.DOCKER_HOST) seenDockerHosts.push(`detect:${env.DOCKER_HOST}`);
      return { available: true, version: 'remote-27.1', reason: null };
    };
    dmRemote.runDocker = async (args, opts = {}) => {
      if (opts && opts.env && opts.env.DOCKER_HOST) {
        seenDockerHosts.push(`${args[0]}:${opts.env.DOCKER_HOST}`);
      }
      if (args[0] === 'inspect' && args.includes('culkibo-caddy')) {
        return { code: 1, stdout: '', stderr: 'not containerized' };
      }
      if (args[0] === 'inspect') {
        return { code: 0, stdout: 'true\n', stderr: '' };
      }
      return { code: 0, stdout: '', stderr: '' };
    };

    const remoteProject = {
      id: 'proj_fleet_eu',
      name: 'EU Worker',
      serverId: 'eu-vps-1',
      domains: ['eu.ejemplo.com'],
      // Intento de secuestro de DOCKER_HOST por el usuario: debe bloquearse y prevalecer el túnel de Fleet
      envVars: { DOCKER_HOST: 'tcp://attacker.evil:2375', APP_ENV: 'prod' }
    };

    const dep1 = await dmRemote.deploy(remoteProject, { contextDir });
    assert.strictEqual(dep1.status, 'activo', `Despliegue remoto falló: ${dep1.error}`);
    assert.strictEqual(dep1.serverId, 'eu-vps-1');
    assert.strictEqual(dmRemote.store['proj_fleet_eu'].current.serverId, 'eu-vps-1');
    assert.ok(fleetCalls.includes('docker:eu-vps-1'));
    assert.ok(fleetCalls.includes('port:eu-vps-1'));
    assert.ok(fleetCalls.includes('healthTunnel:eu-vps-1:21999'));
    assert.ok(fleetCalls.includes('caddyTunnel:eu-vps-1'));
    assert.ok(releasedCount >= 1, 'El lease del túnel Docker debe liberarse en finally');
    assert.ok(seenDockerHosts.includes(`build:${TRUSTED_TUNNEL_HOST}`), 'docker build debe recibir DOCKER_HOST del túnel');
    assert.ok(seenDockerHosts.includes(`run:${TRUSTED_TUNNEL_HOST}`), 'docker run debe recibir DOCKER_HOST del túnel (tras filterSafeHostEnv)');
    assert.ok(!seenDockerHosts.some((x) => x.includes('attacker.evil')), 'DOCKER_HOST malicioso del usuario jamás puede secuestrar docker');
    assert.ok(remoteCaddyRoutes.has('culkibo_proj_fleet_eu'), 'La ruta debe publicarse en el Caddy remoto a través del túnel');

    // Rollback debe enrutar de nuevo hacia eu-vps-1
    dmRemote.store['proj_fleet_eu'].previous = {
      deploymentId: 'dep_eu_v0', serverId: 'eu-vps-1', imageTag: 'culkibo/eu:v0',
      containerName: 'culkibo_eu_v0', hostPort: 21998, containerPort: 3000,
      upstream: '127.0.0.1:21998', hostnames: ['eu.ejemplo.com'], healthPath: '/'
    };
    const beforeRollbackCalls = fleetCalls.length;
    const rb = await dmRemote.rollback('proj_fleet_eu', { drainTimeoutMs: 5, stopGraceSeconds: 0 });
    await dmRemote.awaitDrain('proj_fleet_eu');
    assert.strictEqual(rb.status, 'activo');
    assert.strictEqual(rb.serverId, 'eu-vps-1');
    assert.ok(fleetCalls.slice(beforeRollbackCalls).includes('docker:eu-vps-1'), 'Rollback debe usar el túnel del nodo dueño del contenedor');
    assert.ok(fleetCalls.slice(beforeRollbackCalls).includes('caddyTunnel:eu-vps-1'), 'Rollback debe actualizar Caddy del nodo remoto');

    // Preflight rechaza montajes locales en nodos remotos
    const bindMountFail = await dmRemote.deploy({
      ...remoteProject,
      id: 'proj_fleet_bad_vol',
      volumes: ['/etc/hosts:/app/hosts']
    }, { contextDir });
    assert.strictEqual(bindMountFail.status, 'fallido');
    assert.ok(/montajes locales/.test(bindMountFail.error));

    // checkProductionHealth() debe saltar proyectos sleeping y serverId !== 'local'
    const dmHealth = makeSandbox();
    let inspectedNames = [];
    dmHealth.store['p_sleeping'] = { current: { containerName: 'c_sleep', status: 'sleeping', serverId: 'local' } };
    dmHealth.store['p_remote'] = { current: { containerName: 'c_remote', status: 'activo', serverId: 'eu-vps-1' } };
    dmHealth.store['p_local'] = { current: { containerName: 'c_local', status: 'activo', serverId: 'local' } };
    dmHealth.runDocker = async (args) => {
      if (args[0] === 'inspect') {
        inspectedNames = args.slice(3);
        return { code: 0, stdout: '/c_local|true|false|0|running\n', stderr: '' };
      }
      return { code: 0, stdout: '', stderr: '' };
    };
    const healthRes = await dmHealth.checkProductionHealth();
    assert.strictEqual(healthRes.checked, 1, 'Solo debe inspeccionar el contenedor local activo');
    assert.deepStrictEqual(inspectedNames, ['c_local']);
  } finally {
    await remoteHealthApp.close();
    await remoteCaddy.close();
  }

  console.log('  ✓ Fleet Routing: local intacto, DOCKER_HOST seguro tras filterSafeHostEnv, túneles y watchdog');
}

// ---------------------------------------------------------------------------
// 7. System Doctor Check #10 (Cost/RAM Advisor + Fleet Nodes health)
// ---------------------------------------------------------------------------
async function testSystemDoctorCheck10() {
  // Ejecución real de runDoctor() — debe incluir check #10 (`cost_ram_advisor`)
  const report = await systemDoctor.runDoctor();
  assert.ok(Array.isArray(report.checks) && report.checks.length >= 10, `Esperados >=10 checks, encontrados ${report.checks.length}`);
  const check10 = report.checks.find((c) => c.id === 'cost_ram_advisor');
  assert.ok(check10, 'runDoctor() debe incluir la comprobación #10 cost_ram_advisor');
  assert.ok(['ok', 'warn', 'fail'].includes(check10.status));
  assert.ok(typeof check10.summary === 'string' && check10.summary.length > 0);

  // Degradación limpia cuando ambos módulos no están disponibles
  const fallback = await systemDoctor.checkCostAndFleet({ sleepAdvisorMod: null, fleetManagerMod: null });
  assert.strictEqual(fallback.id, 'cost_ram_advisor');
  assert.strictEqual(fallback.metrics.advisor.source, 'builtin_fallback');
  assert.strictEqual(fallback.metrics.fleet.mode, 'local_only');

  // Con sleepAdvisor (formato canónico adv.metrics.*) y flota saludable
  const healthy = await systemDoctor.checkCostAndFleet({
    sleepAdvisorMod: {
      getDoctorSummary: async () => ({
        status: 'ok',
        summary: '256 MB recuperables (~€1.50/mes)',
        metrics: {
          reclaimableRamMb: 256,
          monthlySavingsEur: 1.5,
          idleCandidatesCount: 1,
          oomRiskCount: 0
        }
      })
    },
    fleetManagerMod: {
      listServers: () => [
        { id: 'local', name: 'Local', status: 'online' },
        { id: 'eu-1', name: 'EU-1', status: 'online' },
        { id: 'us-1', name: 'US-1', status: 'online' }
      ]
    }
  });
  assert.strictEqual(healthy.status, 'ok');
  assert.strictEqual(healthy.metrics.advisor.reclaimableMb, 256);
  assert.strictEqual(healthy.metrics.advisor.estimatedSavingsEurMonth, 1.5);
  assert.strictEqual(healthy.metrics.advisor.idleCount, 1);
  assert.strictEqual(healthy.metrics.fleet.online, 2);
  assert.ok(healthy.summary.includes('2/2'));

  // Flota con nodo caído -> warn
  const degraded = await systemDoctor.checkCostAndFleet({
    sleepAdvisorMod: null,
    fleetManagerMod: {
      listServers: () => [
        { id: 'local', name: 'Local', status: 'online' },
        { id: 'eu-1', name: 'EU-1', status: 'offline' }
      ]
    }
  });
  assert.strictEqual(degraded.status, 'warn');
  assert.strictEqual(degraded.metrics.fleet.offline, 1);

  // Flota con host_key_mismatch -> fail
  const mismatch = await systemDoctor.checkCostAndFleet({
    sleepAdvisorMod: null,
    fleetManagerMod: {
      listServers: () => [
        { id: 'eu-bad', name: 'EU-Bad', status: 'host_key_mismatch' }
      ]
    }
  });
  assert.strictEqual(mismatch.status, 'fail');
  assert.strictEqual(mismatch.metrics.fleet.hostKeyMismatch, 1);
  assert.ok(/host_key_mismatch/i.test(mismatch.summary));

  console.log('  ✓ SystemDoctor Check #10: fallback limpio, advisor + flota online/degraded/host_key_mismatch');
}

async function testCoreBoost() {
  console.log('🧪 Probando mejoras Core +70% (Smoke Tests, Canary, Freeze Windows, Fleet, Caddy, Doctor #10)...');
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-core-boost-'));
  try {
    await testProjectModelAndValidation();
    await testCaddyAdminOverrideAndSleepingRoute();
    await testDeployFreezeWindows(tmpRoot);
    await testPostDeploySmokeTests(tmpRoot);
    await testCanaryAutoGuard(tmpRoot);
    await testRemoteFleetRouting(tmpRoot);
    await testSystemDoctorCheck10();
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
  console.log('✅ Todas las pruebas Core +70% superadas!\n');
}

module.exports = { testCoreBoost };

if (require.main === module) {
  testCoreBoost().catch((err) => {
    console.error('❌ Fallo en tests/core-boost.test.js:', err);
    process.exit(1);
  });
}
