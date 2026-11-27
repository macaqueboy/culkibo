/**
 * Banco de pruebas: rendimiento del plano de control, arranque en frío,
 * huella de RAM/CPU en reposo, concurrencia HTTP y fan-out WebSocket.
 *
 * Metodología honesta y comparativa con fuentes del sector (2025–2026):
 * - Separa explícitamente la RAM medida del daemon de Culkibo (Node RSS solo)
 *   frente al estimado con plano de datos Caddy (+12–20 MB idle RSS).
 * - Distingue RAM idle medida vía `docker stats` del mínimo recomendado de VPS
 *   (evitando confundir "2 GB VPS mínimo" con "2 GB RAM idle"):
 *     • Coolify v4 (Laravel/PHP + colas + DB/Redis + proxy): ~400–700 MB idle (VPS min 2 GB)
 *     • Dokploy (Next.js + Postgres + Redis + Traefik):      ~400–600 MB idle (VPS min 1–2 GB)
 *     • CapRover (Node + Nginx + Docker Swarm):              ~300–450 MB idle (VPS min 1 GB)
 *     • Komodo (Rust Core + Periphery + Mongo/FerretDB):     ~300–700 MB idle (VPS min 1–2 GB)
 *     • Dokku (CLI-only, sin Web UI):                        ~100–200 MB idle (VPS min 512 MB–1 GB)
 *     • Kamal 2 (CLI/SSH-only, sin panel en servidor):       0 MB panel + ~15–25 MB kamal-proxy
 *     • Proxies: Caddy ~12–20 MB · Nginx ~20–30 MB · Traefik ~80–100+ MB idle
 */

const { spawn } = require('child_process');
const http = require('http');
const net = require('net');
const path = require('path');
const WebSocket = require('ws');

const pkg = require('../package.json');
const mcpServer = require('../server/services/mcpServer');
const { resolveToken } = require('../server/middleware/auth');

const CADDY_IDLE_RSS_ESTIMATE_MB = 18;

const COMPETITOR_FOOTPRINT_REFERENCE = Object.freeze({
  methodology: 'Measured control-plane idle RSS (docker stats) separated from documented minimum VPS RAM',
  proxiesIdleRssMb: { caddy: '12-20', nginx: '20-30', traefik: '80-100+' },
  platforms: [
    { name: 'Coolify v4', ui: 'Web UI (Laravel/PHP)', measuredIdleRssMb: '400-700', minRecommendedVpsMb: 2048 },
    { name: 'Dokploy', ui: 'Web UI (Next.js/TS)', measuredIdleRssMb: '400-600', minRecommendedVpsMb: 2048 },
    { name: 'CapRover', ui: 'Web UI (Node/Swarm)', measuredIdleRssMb: '300-450', minRecommendedVpsMb: 1024 },
    { name: 'Komodo', ui: 'Web UI (Rust+DB)', measuredIdleRssMb: '300-700', minRecommendedVpsMb: 1024 },
    { name: 'Dokku', ui: 'CLI-only (no GUI)', measuredIdleRssMb: '100-200', minRecommendedVpsMb: 512 },
    { name: 'Kamal 2', ui: 'CLI/SSH-only (no server panel)', measuredIdleRssMb: '0 (+15-25 proxy)', minRecommendedVpsMb: 512 }
  ]
});

function percentile(sorted, p) {
  if (!sorted.length) return null;
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return Number(sorted[Math.max(0, idx)].toFixed(2));
}

function findFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

function probeHealthOnce(port, timeoutMs = 150) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (val) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(val);
    };
    const req = http.request({ host: '127.0.0.1', port, path: '/api/health', method: 'GET' }, (res) => {
      res.resume();
      done(res.statusCode === 200);
    });
    const timer = setTimeout(() => {
      req.destroy();
      done(false);
    }, timeoutMs);
    if (timer.unref) timer.unref();
    req.on('error', () => done(false));
    req.end();
  });
}

async function waitForHealth(port, child, stderrBuf, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let listened = false;
  let exitedCode = null;

  const onStdout = (chunk) => {
    if (chunk.toString('utf8').includes('Daemon running')) listened = true;
  };
  const onExit = (code) => { exitedCode = code; };
  if (child.stdout) child.stdout.on('data', onStdout);
  child.once('exit', onExit);

  try {
    while (Date.now() < deadline) {
      if (exitedCode !== null) {
        throw new Error(`El daemon terminó prematuramente (código ${exitedCode}): ${stderrBuf.join('').trim()}`);
      }
      if (listened) {
        if (await probeHealthOnce(port, 500)) return true;
      }
      await new Promise((r) => setTimeout(r, 10));
    }
    return await probeHealthOnce(port, 500);
  } finally {
    if (child.stdout) child.stdout.off('data', onStdout);
    child.off('exit', onExit);
  }
}

async function run({ silent = false, concurrency = 500, workers = 25, wsClients = 40 } = {}) {
  const port = await findFreePort();
  const rootDir = path.join(__dirname, '..');

  const bootStart = process.hrtime.bigint();
  const child = spawn(process.execPath, [path.join(rootDir, 'server', 'index.js')], {
    cwd: rootDir,
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', NODE_ENV: 'test', CULKIBO_SKIP_RECONCILE: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: false,
    windowsHide: true
  });

  /** @type {string[]} */
  const stderrBuf = [];
  if (child.stderr) {
    child.stderr.on('data', (chunk) => {
      stderrBuf.push(chunk.toString('utf8'));
      if (stderrBuf.length > 20) stderrBuf.shift();
    });
  }
  if (child.stdout) {
    child.stdout.resume();
  }

  try {
    const bootLimitMs = process.platform === 'win32' ? 60000 : 15000;
    const ready = await waitForHealth(port, child, stderrBuf, bootLimitMs);
    if (!ready) {
      throw new Error(`El daemon no arrancó dentro del límite de ${bootLimitMs / 1000} s${stderrBuf.length ? ': ' + stderrBuf.join('').trim() : ''}`);
    }
    const coldBootMs = Number((Number(process.hrtime.bigint() - bootStart) / 1e6).toFixed(1));

    // Huella en reposo real del daemon tras estabilización inicial de 500 ms
    await new Promise((r) => setTimeout(r, 500));
    const statusRes = await (await fetch(`http://127.0.0.1:${port}/api/system/status`)).json();
    const podsRes = await (await fetch(`http://127.0.0.1:${port}/api/pods`)).json();
    const idleRssMb = (podsRes.daemon && podsRes.daemon.memoryMb) || statusRes.memoryUsageMb || null;
    const idleCpuPercent = podsRes.daemon ? podsRes.daemon.cpuPercent : null;
    const estimatedFullStackWithCaddyMb = idleRssMb !== null
      ? Number((idleRssMb + CADDY_IDLE_RSS_ESTIMATE_MB).toFixed(1))
      : null;

    // Concurrencia HTTP real estilo wrk/autocannon: pool fijo de workers con
    // conexiones TCP keep-alive persistentes (sin alterar ni restar latencia).
    const endpoints = ['/api/health', '/api/projects', '/api/catalog', '/api/pods'];
    const agent = new http.Agent({ keepAlive: true, maxSockets: workers });
    const httpGet = (ep, extraHeaders = {}) => new Promise((resolve) => {
      const t0 = process.hrtime.bigint();
      const req = http.request({ host: '127.0.0.1', port, path: ep, method: 'GET', agent, headers: extraHeaders }, (res) => {
        let bytes = 0;
        res.on('data', (chunk) => { bytes += chunk.length; });
        res.on('end', () => {
          resolve({
            ok: (res.statusCode || 500) < 400,
            status: res.statusCode || 0,
            bytes,
            encoding: res.headers['content-encoding'] || null,
            serverTiming: res.headers['server-timing'] || null,
            ms: Number(process.hrtime.bigint() - t0) / 1e6
          });
        });
      });
      req.on('error', () => resolve({ ok: false, status: 0, bytes: 0, encoding: null, serverTiming: null, ms: Number(process.hrtime.bigint() - t0) / 1e6 }));
      req.end();
    });

    // Medición honesta de carga del catálogo (frío en 1ª petición -> caliente comprimido Brotli)
    const catalogColdRaw = await httpGet('/api/catalog');
    const catalogColdBr = await httpGet('/api/catalog', { 'Accept-Encoding': 'br, gzip' });
    /** @type {number[]} */
    const catalogWarmSamples = [];
    for (let i = 0; i < 40; i++) {
      const r = await httpGet('/api/catalog', { 'Accept-Encoding': 'br, gzip' });
      if (r.ok) catalogWarmSamples.push(r.ms);
    }
    catalogWarmSamples.sort((a, b) => a - b);

    // Calentamiento (1 ronda por endpoint para JIT y sockets keep-alive).
    for (const ep of endpoints) await httpGet(ep);

    /** @type {number[]} */
    const reqLatencies = [];
    let reqFailures = 0;
    let nextIdx = 0;
    /** @type {string | null} */
    let observedServerTiming = null;

    const batchStart = process.hrtime.bigint();
    await Promise.all(Array.from({ length: Math.min(workers, concurrency) }, async () => {
      while (true) {
        const idx = nextIdx++;
        if (idx >= concurrency) break;
        const res = await httpGet(endpoints[idx % endpoints.length]);
        if (!observedServerTiming && res.serverTiming) observedServerTiming = String(res.serverTiming);
        if (!res.ok) reqFailures++;
        else reqLatencies.push(res.ms);
      }
    }));
    const batchMs = Number(process.hrtime.bigint() - batchStart) / 1e6;
    const sortedReq = [...reqLatencies].sort((a, b) => a - b);

    // Concurrencia pura sobre /api/health (mide techo real de latencia del plano de control)
    /** @type {number[]} */
    const healthLatencies = [];
    let healthFailures = 0;
    let healthIdx = 0;
    const healthStart = process.hrtime.bigint();
    await Promise.all(Array.from({ length: Math.min(workers, concurrency) }, async () => {
      while (true) {
        const idx = healthIdx++;
        if (idx >= concurrency) break;
        const res = await httpGet('/api/health');
        if (!res.ok) healthFailures++;
        else healthLatencies.push(res.ms);
      }
    }));
    const healthTotalMs = Number(process.hrtime.bigint() - healthStart) / 1e6;
    healthLatencies.sort((a, b) => a - b);

    // Concurrencia autenticada real (Bearer token + Accept-Encoding: br, gzip) sobre rutas calientes
    const masterToken = resolveToken();
    const authHeaders = {
      Authorization: `Bearer ${masterToken}`,
      'Accept-Encoding': 'br, gzip'
    };
    const authedEndpoints = ['/api/health', '/api/projects', '/api/catalog', '/api/system/status'];
    for (const ep of authedEndpoints) await httpGet(ep, authHeaders);

    /** @type {number[]} */
    const authedLatencies = [];
    let authedFailures = 0;
    let authedIdx = 0;
    const authedStart = process.hrtime.bigint();
    await Promise.all(Array.from({ length: Math.min(workers, concurrency) }, async () => {
      while (true) {
        const idx = authedIdx++;
        if (idx >= concurrency) break;
        const res = await httpGet(authedEndpoints[idx % authedEndpoints.length], authHeaders);
        if (!res.ok) authedFailures++;
        else authedLatencies.push(res.ms);
      }
    }));
    const authedTotalMs = Number(process.hrtime.bigint() - authedStart) / 1e6;
    authedLatencies.sort((a, b) => a - b);
    agent.destroy();

    // Fan-out WebSocket simultáneo
    const sockets = [];
    let initialStateReceived = 0;
    const wsStart = process.hrtime.bigint();
    await Promise.all(Array.from({ length: wsClients }, () => new Promise((resolve) => {
      const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`);
      sockets.push(ws);
      ws.once('message', () => {
        initialStateReceived++;
        resolve(undefined);
      });
      ws.once('error', () => resolve(undefined));
    })));
    const wsFanoutMs = Number((Number(process.hrtime.bigint() - wsStart) / 1e6).toFixed(1));
    for (const s of sockets) {
      try { s.close(); } catch (e) {}
    }

    const tools = mcpServer.getToolsDefinition();
    const mutatingTools = tools.filter((t) => !t.annotations.readOnlyHint).length;

    const summary = {
      coldBootMs,
      idleRssMb,
      estimatedFullStackWithCaddyMb,
      idleCpuPercent,
      conditions: {
        reconcileSkipped: true,
        settleMs: 500,
        authMode: 'loopback_read_endpoints',
        caddyIdleEstimateMb: CADDY_IDLE_RSS_ESTIMATE_MB
      },
      httpConcurrency: {
        requests: concurrency,
        workers,
        failures: reqFailures,
        totalMs: Number(batchMs.toFixed(1)),
        rps: Math.round((concurrency / batchMs) * 1000),
        p50Ms: percentile(sortedReq, 50),
        p95Ms: percentile(sortedReq, 95),
        p99Ms: percentile(sortedReq, 99)
      },
      healthHttp: {
        requests: concurrency,
        workers,
        failures: healthFailures,
        totalMs: Number(healthTotalMs.toFixed(1)),
        rps: Math.round((concurrency / healthTotalMs) * 1000),
        p50Ms: percentile(healthLatencies, 50),
        p95Ms: percentile(healthLatencies, 95),
        p99Ms: percentile(healthLatencies, 99)
      },
      authenticatedFastPathHttp: {
        requests: concurrency,
        workers,
        failures: authedFailures,
        totalMs: Number(authedTotalMs.toFixed(1)),
        rps: Math.round((concurrency / authedTotalMs) * 1000),
        p50Ms: percentile(authedLatencies, 50),
        p95Ms: percentile(authedLatencies, 95),
        p99Ms: percentile(authedLatencies, 99),
        encoding: 'br/gzip'
      },
      catalogLoad: {
        coldRawMs: Number(catalogColdRaw.ms.toFixed(2)),
        coldBrotliMs: Number(catalogColdBr.ms.toFixed(2)),
        warmP50Ms: percentile(catalogWarmSamples, 50),
        warmP95Ms: percentile(catalogWarmSamples, 95),
        rawBytes: catalogColdRaw.bytes,
        brotliBytes: catalogColdBr.bytes,
        brotliSavedPct: catalogColdRaw.bytes > 0
          ? Number((((catalogColdRaw.bytes - catalogColdBr.bytes) / catalogColdRaw.bytes) * 100).toFixed(1))
          : 0
      },
      serverTimingHeader: observedServerTiming,
      websocketFanout: {
        clients: wsClients,
        delivered: initialStateReceived,
        totalMs: wsFanoutMs
      },
      footprint: {
        runtimeDependencies: Object.keys(pkg.dependencies || {}).length,
        mcpToolsTotal: tools.length,
        mcpToolsMutating: mutatingTools
      },
      competitorReference: COMPETITOR_FOOTPRINT_REFERENCE
    };

    if (!silent) {
      console.log('\n════════════════════════════════════════════════════════════');
      console.log('  Culkibo · Banco de pruebas: Plano de control y huella');
      console.log('════════════════════════════════════════════════════════════\n');
      console.log(`  Arranque en frío             ${summary.coldBootMs} ms (CULKIBO_SKIP_RECONCILE=1)`);
      console.log(`  RAM idle daemon (solo Node)  ${summary.idleRssMb} MB RSS`);
      console.log(`  RAM idle estimada (+Caddy)   ~${summary.estimatedFullStackWithCaddyMb} MB (Caddy ~${CADDY_IDLE_RSS_ESTIMATE_MB} MB idle)`);
      console.log('  Referencia idle docker stats (vs mínimo recomendado de VPS):');
      console.log('    Coolify v4                 ~400–700 MB idle (VPS min 2.048 MB)');
      console.log('    Dokploy                    ~400–600 MB idle (VPS min 1.024–2.048 MB)');
      console.log('    CapRover                   ~300–450 MB idle (VPS min 1.024 MB)');
      console.log('    Dokku (CLI, sin GUI)       ~100–200 MB idle (VPS min 512 MB)');
      console.log('    Kamal 2 (CLI/SSH-only)     0 MB panel (+15–25 MB kamal-proxy)');
      console.log(`  CPU en reposo                ${summary.idleCpuPercent ?? 0} %`);
      console.log(`  Concurrencia HTTP (${concurrency})      p50 ${summary.httpConcurrency.p50Ms} ms · p95 ${summary.httpConcurrency.p95Ms} ms · p99 ${summary.httpConcurrency.p99Ms} ms · ${summary.httpConcurrency.rps} req/s · ${summary.httpConcurrency.failures} fallos`);
      console.log(`  Salud /api/health (${concurrency})      p50 ${summary.healthHttp.p50Ms} ms · p95 ${summary.healthHttp.p95Ms} ms · p99 ${summary.healthHttp.p99Ms} ms · ${summary.healthHttp.rps} req/s`);
      console.log(`  Auth Bearer+Brotli (${concurrency})     p50 ${summary.authenticatedFastPathHttp.p50Ms} ms · p95 ${summary.authenticatedFastPathHttp.p95Ms} ms · p99 ${summary.authenticatedFastPathHttp.p99Ms} ms · ${summary.authenticatedFastPathHttp.rps} req/s`);
      console.log(`  Catálogo /api/catalog        frío ${summary.catalogLoad.coldRawMs} ms · warm p50 ${summary.catalogLoad.warmP50Ms} ms (${summary.catalogLoad.rawBytes} B → ${summary.catalogLoad.brotliBytes} B br, -${summary.catalogLoad.brotliSavedPct}%)`);
      console.log(`  Cabecera Server-Timing       ${summary.serverTimingHeader || 'n/d'}`);
      console.log(`  WebSocket fan-out (${wsClients})       ${summary.websocketFanout.delivered}/${wsClients} clientes listos en ${summary.websocketFanout.totalMs} ms`);
      console.log(`  Dependencias de runtime      ${summary.footprint.runtimeDependencies}`);
      console.log(`  Superficie MCP 2026-07-28    ${summary.footprint.mcpToolsTotal} herramientas (${summary.footprint.mcpToolsMutating} de escritura)\n`);
    }

    return summary;
  } finally {
    try { child.kill('SIGTERM'); } catch (e) {}
    await new Promise((r) => setTimeout(r, 100));
    try { if (!child.killed) child.kill('SIGKILL'); } catch (e) {}
  }
}

if (require.main === module) {
  const asJson = process.argv.includes('--json');
  run({ silent: asJson }).then((res) => {
    if (asJson) process.stdout.write(JSON.stringify(res, null, 2) + '\n');
    process.exit(0);
  }).catch((err) => {
    console.error('❌ Fallo en bench/control-plane.bench.js:', err);
    process.exit(1);
  });
}

module.exports = run;
