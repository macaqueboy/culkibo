/**
 * Banco de pruebas: sincronización en vivo (The Forge).
 *
 * Mide de principio a fin cuánto tarda una edición real en disco en llegar por
 * WebSocket persistente (/ws/sync), aplicarse de forma atómica al destino y
 * servirse por un servidor HTTP real — más la latencia real de rollback desde
 * el historial de parches en memoria y la agrupación atómica de ráfagas de IA.
 *
 * Cero `setTimeout` fabricados. Todo es disco real, red real y HTTP real.
 */

const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const liveSyncEngine = require('../server/services/liveSyncEngine');
const { LiveSyncClient } = require('../server/services/liveSyncClient');
const { ensureDaemon } = require('../tests/helpers/daemon');

const ITERATIONS = parseInt(process.env.BENCH_SYNC_ITERATIONS || '25', 10);
const WS_SYNC_URL = process.env.CULKIBO_SYNC_URL || 'ws://127.0.0.1:3030/ws/sync';

function percentile(sorted, p) {
  if (!sorted.length) return null;
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return Number(sorted[Math.max(0, idx)].toFixed(2));
}

function startOrigin(rootDir) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      const clean = String(req.url || '/').split('?')[0].replace(/^\/+/, '') || 'index.html';
      const target = path.join(rootDir, clean);
      if (fs.existsSync(target) && fs.statSync(target).isFile()) {
        res.writeHead(200, { 'Content-Type': 'text/plain', Connection: 'close' });
        res.end(fs.readFileSync(target));
      } else {
        res.writeHead(404, { Connection: 'close' });
        res.end('404');
      }
    });
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      resolve({ server: srv, port: typeof addr === 'object' && addr ? addr.port : 0 });
    });
  });
}

async function run({ silent = false } = {}) {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-bench-sync-'));
  const sourceDir = path.join(tmpRoot, 'src');
  const targetDir = path.join(tmpRoot, 'live');
  fs.mkdirSync(sourceDir, { recursive: true });
  fs.mkdirSync(targetDir, { recursive: true });
  fs.writeFileSync(path.join(sourceDir, 'index.html'), 'init', 'utf8');

  let stopDaemon = null;
  let originSrv = null;
  let client = null;
  const projectId = `bench_sync_${Date.now()}`;

  /** @type {number[]} */
  const endToEndSamples = [];
  /** @type {number[]} */
  const wireApplySamples = [];
  /** @type {number[]} */
  const rollbackSamples = [];
  let burstFrames = 0;
  let burstDurationMs = 0;

  try {
    stopDaemon = await ensureDaemon();
    const origin = await startOrigin(targetDir);
    originSrv = origin.server;
    const url = `http://127.0.0.1:${origin.port}/index.html`;

    client = new LiveSyncClient({
      projectId,
      sourceDir,
      targetDir,
      wsUrl: WS_SYNC_URL,
      quiescenceMs: 8
    });
    await client.start();
    await client.reconcileFull();

    const ackTimeout = process.platform === 'win32' ? 15000 : 5000;
    const waitFrameAck = (timeoutMs = ackTimeout) => new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        client.off('frame_ack', onAck);
        reject(new Error(`Timeout esperando frame_ack (${timeoutMs} ms)`));
      }, timeoutMs);
      const onAck = (ack) => {
        clearTimeout(timer);
        resolve(ack);
      };
      client.once('frame_ack', onAck);
    });

    // 1. Edición real en disco -> watcher -> Commit Frame -> WS -> disco -> HTTP vivo
    for (let i = 0; i < ITERATIONS + 1; i++) {
      const token = `rev_${i}_${Date.now()}_${'x'.repeat((i % 5) + 1)}`;
      const started = process.hrtime.bigint();
      const ackPromise = waitFrameAck(ackTimeout);
      fs.writeFileSync(path.join(sourceDir, 'index.html'), token, 'utf8');
      const ack = await ackPromise;
      const body = await (await fetch(url)).text();
      const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

      if (body !== token) {
        throw new Error(`Desajuste en iteración ${i}: esperado ${token}, recibido ${body}`);
      }
      if (i > 0) {
        endToEndSamples.push(elapsedMs);
        wireApplySamples.push(ack.applyMs);
      }
    }

    // 2. Ráfaga de agente de IA: 15 ficheros escritos a la vez -> agrupados en Commit Frame
    let framesSeen = 0;
    const onBurstAck = () => { framesSeen++; };
    client.on('frame_ack', onBurstAck);
    const burstStart = process.hrtime.bigint();
    const firstAck = waitFrameAck(ackTimeout);
    for (let k = 0; k < 15; k++) {
      fs.writeFileSync(path.join(sourceDir, `comp_${k}.js`), `export const c = ${k};`, 'utf8');
    }
    await firstAck;
    await new Promise((r) => setTimeout(r, 30));
    burstDurationMs = Number((Number(process.hrtime.bigint() - burstStart) / 1e6).toFixed(2));
    burstFrames = framesSeen;
    client.off('frame_ack', onBurstAck);

    // 3. Latencia real de rollback en memoria (10 reversiones consecutivas vía /ws/sync)
    for (let r = 0; r < 10; r++) {
      const t0 = process.hrtime.bigint();
      const rbRes = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          client.ws.off('message', onMsg);
          reject(new Error('Timeout esperando rollback_ack'));
        }, 5000);
        const onMsg = (raw) => {
          const msg = JSON.parse(raw.toString());
          if (msg.type === 'rollback_ack') {
            clearTimeout(timer);
            client.ws.off('message', onMsg);
            resolve(msg);
          } else if (msg.type === 'error') {
            clearTimeout(timer);
            client.ws.off('message', onMsg);
            reject(new Error(msg.error));
          }
        };
        client.ws.on('message', onMsg);
        client.ws.send(JSON.stringify({ type: 'rollback', projectId, steps: 1 }));
      });
      const rbMs = Number(process.hrtime.bigint() - t0) / 1e6;
      if (rbRes.reverted) rollbackSamples.push(rbMs);
    }

    const sortedE2E = [...endToEndSamples].sort((a, b) => a - b);
    const sortedApply = [...wireApplySamples].sort((a, b) => a - b);
    const sortedRb = [...rollbackSamples].sort((a, b) => a - b);

    const summary = {
      iterations: sortedE2E.length,
      endToEndMs: {
        min: percentile(sortedE2E, 0),
        p50: percentile(sortedE2E, 50),
        p95: percentile(sortedE2E, 95),
        p99: percentile(sortedE2E, 99),
        max: percentile(sortedE2E, 100)
      },
      serverApplyMs: {
        p50: percentile(sortedApply, 50),
        p95: percentile(sortedApply, 95)
      },
      aiBurst15Files: {
        filesWritten: 15,
        commitFramesSent: burstFrames,
        totalMs: burstDurationMs
      },
      rollbackMs: {
        samples: sortedRb.length,
        p50: percentile(sortedRb, 50),
        p95: percentile(sortedRb, 95)
      }
    };

    if (!silent) {
      console.log('\n════════════════════════════════════════════════════════════');
      console.log('  Culkibo · Banco de pruebas: Live Sync (The Forge)');
      console.log('════════════════════════════════════════════════════════════\n');
      console.log(`  Edición en disco → WS /ws/sync → HTTP sirviendo versión nueva (${summary.iterations} muestras)`);
      console.log(`    p50                ${summary.endToEndMs.p50} ms  (apply servidor p50: ${summary.serverApplyMs.p50} ms)`);
      console.log(`    p95                ${summary.endToEndMs.p95} ms`);
      console.log(`    p99                ${summary.endToEndMs.p99} ms`);
      console.log(`  Ráfaga IA (15 ficheros simultáneos): ${summary.aiBurst15Files.commitFramesSent} commit frame(s) en ${summary.aiBurst15Files.totalMs} ms`);
      console.log(`  Rollback desde historial en memoria: p50 ${summary.rollbackMs.p50} ms · p95 ${summary.rollbackMs.p95} ms\n`);
      console.log('  Referencia del sector (mismo ciclo editar -> visible en URL):');
      console.log('    Coolify (git push -> Nixpacks -> rollout)   ~240.000 ms (4 min)');
      console.log('    Vercel (git push -> build Next.js)           ~42.000 ms');
      console.log('    Zeabur / Dokploy (push -> build -> rollout)  ~30.000 ms');
      console.log(`    Culkibo Live Sync (Camino B medido, p50)        ${summary.endToEndMs.p50} ms\n`);
    }

    liveSyncEngine.resetSession(projectId);
    return summary;
  } finally {
    if (client) await client.stop().catch(() => {});
    if (originSrv) await new Promise((r) => originSrv.close(() => r(undefined)));
    if (stopDaemon) await stopDaemon().catch(() => {});
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  run().then(() => process.exit(0)).catch((err) => {
    console.error('❌ Fallo en bench/live-sync.bench.js:', err);
    process.exit(1);
  });
}

module.exports = run;
