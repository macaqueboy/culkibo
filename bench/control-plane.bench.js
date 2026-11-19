/**
 * Banco de pruebas: rendimiento del plano de control, arranque en frío,
 * huella de RAM/CPU en reposo, concurrencia HTTP y fan-out WebSocket.
 *
 * Compara métricas reales y reproducibles contra la sobrecarga documentada
 * de los competidores self-hosted (Coolify: >2 GB RAM + picos de CPU en reposo;
 * Dokploy: Next.js + Postgres + Redis + Traefik ~600-900 MB).
 */

const { spawn } = require('child_process');
const http = require('http');
const net = require('net');
const path = require('path');
const WebSocket = require('ws');

const pkg = require('../package.json');
const mcpServer = require('../server/services/mcpServer');

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

async function run({ silent = false, concurrency = 400, workers = 20, wsClients = 40 } = {}) {
  const port = await findFreePort();
  const rootDir = path.join(__dirname, '..');

  const bootStart = process.hrtime.bigint();
  const child = spawn(process.execPath, [path.join(rootDir, 'server', 'index.js')], {
    cwd: rootDir,
    env: { ...process.env, PORT: String(port), NODE_ENV: 'test', CULKIBO_SKIP_RECONCILE: '1' },
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
    const bootLimitMs = process.platform === 'win32' ? 30000 : 15000;
    const ready = await waitForHealth(port, child, stderrBuf, bootLimitMs);
    if (!ready) {
      throw new Error(`El daemon no arrancó dentro del límite de ${bootLimitMs / 1000} s${stderrBuf.length ? ': ' + stderrBuf.join('').trim() : ''}`);
    }
    const coldBootMs = Number((Number(process.hrtime.bigint() - bootStart) / 1e6).toFixed(1));

    // Huella en reposo real del daemon recién arrancado
    await new Promise((r) => setTimeout(r, 250));
    const statusRes = await (await fetch(`http://127.0.0.1:${port}/api/system/status`)).json();
    const podsRes = await (await fetch(`http://127.0.0.1:${port}/api/pods`)).json();
    const idleRssMb = (podsRes.daemon && podsRes.daemon.memoryMb) || statusRes.memoryUsageMb || null;
    const idleCpuPercent = podsRes.daemon ? podsRes.daemon.cpuPercent : null;

    // Concurrencia HTTP real estilo wrk/autocannon: pool fijo de workers con
    // conexiones TCP keep-alive persistentes (evita medir la cola de sockets del cliente).
    const endpoints = ['/api/health', '/api/projects', '/api/catalog', '/api/pods'];
    const agent = new http.Agent({ keepAlive: true, maxSockets: workers });
    const httpGet = (ep) => new Promise((resolve) => {
      const t0 = process.hrtime.bigint();
      const req = http.request({ host: '127.0.0.1', port, path: ep, method: 'GET', agent }, (res) => {
        res.on('data', () => {});
        res.on('end', () => {
          resolve({ ok: (res.statusCode || 500) < 400, ms: Number(process.hrtime.bigint() - t0) / 1e6 });
        });
      });
      req.on('error', () => resolve({ ok: false, ms: Number(process.hrtime.bigint() - t0) / 1e6 }));
      req.end();
    });

    // Calentamiento (1 ronda por endpoint para JIT y sockets keep-alive).
    for (const ep of endpoints) await httpGet(ep);

    /** @type {number[]} */
    const reqLatencies = [];
    let reqFailures = 0;
    let nextIdx = 0;

    const batchStart = process.hrtime.bigint();
    await Promise.all(Array.from({ length: Math.min(workers, concurrency) }, async () => {
      while (true) {
        const idx = nextIdx++;
        if (idx >= concurrency) break;
        const res = await httpGet(endpoints[idx % endpoints.length]);
        if (!res.ok) reqFailures++;
        else reqLatencies.push(res.ms);
      }
    }));
    const batchMs = Number(process.hrtime.bigint() - batchStart) / 1e6;
    agent.destroy();
    const sortedReq = [...reqLatencies].sort((a, b) => a - b);

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
      idleCpuPercent,
      httpConcurrency: {
        requests: concurrency,
        failures: reqFailures,
        totalMs: Number(batchMs.toFixed(1)),
        rps: Math.round((concurrency / batchMs) * 1000),
        p50Ms: percentile(sortedReq, 50),
        p95Ms: percentile(sortedReq, 95),
        p99Ms: percentile(sortedReq, 99)
      },
      websocketFanout: {
        clients: wsClients,
        delivered: initialStateReceived,
        totalMs: wsFanoutMs
      },
      footprint: {
        runtimeDependencies: Object.keys(pkg.dependencies || {}).length,
        mcpToolsTotal: tools.length,
        mcpToolsMutating: mutatingTools
      }
    };

    if (!silent) {
      console.log('\n════════════════════════════════════════════════════════════');
      console.log('  Culkibo · Banco de pruebas: Plano de control y huella');
      console.log('════════════════════════════════════════════════════════════\n');
      console.log(`  Arranque en frío           ${summary.coldBootMs} ms`);
      console.log(`  Memoria RAM en reposo      ${summary.idleRssMb} MB RSS  (Coolify requiere >=2.048 MB)`);
      console.log(`  CPU en reposo              ${summary.idleCpuPercent ?? 0} %`);
      console.log(`  Concurrencia HTTP (${concurrency})    p50 ${summary.httpConcurrency.p50Ms} ms · p95 ${summary.httpConcurrency.p95Ms} ms · ${summary.httpConcurrency.rps} req/s · ${summary.httpConcurrency.failures} fallos`);
      console.log(`  WebSocket fan-out (${wsClients})     ${summary.websocketFanout.delivered}/${wsClients} clientes listos en ${summary.websocketFanout.totalMs} ms`);
      console.log(`  Dependencias de runtime    ${summary.footprint.runtimeDependencies}`);
      console.log(`  Superficie MCP 2026-07-28  ${summary.footprint.mcpToolsTotal} herramientas (${summary.footprint.mcpToolsMutating} de escritura vs 3 en Coolify)\n`);
    }

    return summary;
  } finally {
    try { child.kill('SIGTERM'); } catch (e) {}
    await new Promise((r) => setTimeout(r, 100));
    try { if (!child.killed) child.kill('SIGKILL'); } catch (e) {}
  }
}

if (require.main === module) {
  run().then(() => process.exit(0)).catch((err) => {
    console.error('❌ Fallo en bench/control-plane.bench.js:', err);
    process.exit(1);
  });
}

module.exports = run;
