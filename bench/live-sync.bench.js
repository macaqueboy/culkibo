/**
 * Banco de pruebas: sincronización en vivo (Live Sync 2.0 — The Forge).
 *
 * Mide de principio a fin:
 *  1. Edición real en disco → watcher → Commit Frame → WS /ws/sync → disco → HTTP vivo.
 *  2. Ráfaga de agente de IA (15 ficheros simultáneos agrupados en Commit Frame).
 *  3. Latencia real de rollback desde el historial de parches en memoria.
 *  4. Live Sync 2.0: ratio real de compresión Brotli (0x02) y Gzip (0x03) +
 *     throughput de ráfaga de 100 ficheros realistas (~200 KB de código fuente).
 *
 * Nota metodológica honesta:
 * - Esto mide el ciclo incremental en caliente (Camino B, sin reconstruir imagen).
 * - Un despliegue de producción con cambios de dependencias/Dockerfile (Camino C)
 *   ejecuta un build Docker BuildKit completo, comparable en orden de magnitud al
 *   tiempo de build de Coolify/Dokploy/Kamal en el mismo hardware.
 */

const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const liveSyncEngine = require('../server/services/liveSyncEngine');
const { decodeBinarySyncFrame, sha256 } = liveSyncEngine;
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

/**
 * Construye 100 ficheros fuente TypeScript/JSX realistas (~2 KB cada uno, ~200 KB total)
 * para medir compresión Brotli 0x02 / Gzip 0x03 y throughput real de ráfaga de 100 ficheros.
 */
function buildRealistic100FileBurst() {
  const files = [];
  let rawBytes = 0;
  for (let i = 0; i < 100; i++) {
    const lines = [
      `import React, { useMemo, useState } from 'react';`,
      `export interface PanelCard${i}Props { id: string; title: string; status: 'online' | 'degraded' | 'offline'; latencyMs: number; }`,
      `export function PanelCard${i}({ id, title, status, latencyMs }: PanelCard${i}Props) {`,
      `  const [expanded, setExpanded] = useState(false);`,
      `  const badgeClass = useMemo(() => status === 'online' ? 'bg-emerald-500/15 text-emerald-300' : 'bg-amber-500/15 text-amber-300', [status]);`,
      ...Array.from({ length: 18 }, (_, j) =>
        `  const metric_${j} = \`node-${i}-slot-${j}: \${latencyMs + ${j}}ms (\${status})\`;`
      ),
      `  return <article data-id={id} className="rounded-xl border border-zinc-800 bg-zinc-950 p-4"><h3>{title}</h3><span className={badgeClass}>{status}</span><button onClick={() => setExpanded(!expanded)}>{expanded ? 'Hide' : 'Show'}</button></article>;`,
      `}\n`
    ];
    const buf = Buffer.from(lines.join('\n'), 'utf8');
    rawBytes += buf.length;
    files.push({
      path: `src/components/PanelCard${i}.tsx`,
      op: 'upsert',
      buffer: buf,
      sha256: sha256(buf)
    });
  }
  return { files, rawBytes };
}

async function run({ silent = false } = {}) {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-bench-sync-'));
  const sourceDir = path.join(tmpRoot, 'src');
  const targetDir = path.join(tmpRoot, 'live');
  const burst100TargetDir = path.join(tmpRoot, 'burst100-live');
  fs.mkdirSync(sourceDir, { recursive: true });
  fs.mkdirSync(targetDir, { recursive: true });
  fs.mkdirSync(burst100TargetDir, { recursive: true });
  fs.writeFileSync(path.join(sourceDir, 'index.html'), 'init', 'utf8');

  let stopDaemon = null;
  let originSrv = null;
  let client = null;
  const projectId = `bench_sync_${Date.now()}`;
  const burst100ProjectId = `bench_burst100_${Date.now()}`;

  /** @type {number[]} */
  const endToEndSamples = [];
  /** @type {number[]} */
  const wireApplySamples = [];
  /** @type {number[]} */
  const rollbackSamples = [];
  let burstFrames = 0;
  let burstDurationMs = 0;

  try {
    stopDaemon = await ensureDaemon({ quiet: silent });
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

    // 4. Live Sync 2.0: Compresión Brotli (0x02) + Gzip (0x03) y ráfaga de 100 ficheros (~200 KB)
    const { files: burst100Files, rawBytes } = buildRealistic100FileBurst();
    const codecClient = new LiveSyncClient({
      projectId: burst100ProjectId,
      sourceDir,
      targetDir: burst100TargetDir,
      autoWatch: false
    });
    codecClient.supportedCodecs = ['br', 'gzip'];
    codecClient.compression = 'auto';

    liveSyncEngine.setTargetDir(burst100ProjectId, burst100TargetDir);
    const tEnc0 = process.hrtime.bigint();
    const brFrame = codecClient.encodeBinaryFrame(1, burst100Files);
    const encMs = Number(process.hrtime.bigint() - tEnc0) / 1e6;

    const tDec0 = process.hrtime.bigint();
    const decodedBr = decodeBinarySyncFrame(brFrame);
    const decMs = Number(process.hrtime.bigint() - tDec0) / 1e6;

    const tApply0 = process.hrtime.bigint();
    const applied100 = liveSyncEngine.applyCommitFrame(burst100ProjectId, {
      seq: 1,
      files: decodedBr.files,
      _wireStats: decodedBr._wireStats
    });
    const apply100Ms = Number(process.hrtime.bigint() - tApply0) / 1e6;

    // Medir también Gzip (0x03) para comparación directa
    codecClient.compression = 'gzip';
    const gzFrame = codecClient.encodeBinaryFrame(2, burst100Files);
    const total100Ms = encMs + decMs + apply100Ms;
    const brSavedPct = Number((((rawBytes - brFrame.length) / rawBytes) * 100).toFixed(1));
    const gzSavedPct = Number((((rawBytes - gzFrame.length) / rawBytes) * 100).toFixed(1));

    const sortedE2E = [...endToEndSamples].sort((a, b) => a - b);
    const sortedApply = [...wireApplySamples].sort((a, b) => a - b);
    const sortedRb = [...rollbackSamples].sort((a, b) => a - b);

    const summary = {
      iterations: sortedE2E.length,
      methodology: 'Incremental hot-sync (Camino B over loopback WS); production image rebuilds use Camino C (Docker BuildKit)',
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
      burst100FilesBrotli: {
        files: burst100Files.length,
        written: applied100.written,
        rawBytes,
        brotliWireBytes: brFrame.length,
        brotliSavedPct: brSavedPct,
        brotliRatio: Number((rawBytes / brFrame.length).toFixed(2)),
        gzipWireBytes: gzFrame.length,
        gzipSavedPct: gzSavedPct,
        encodeMs: Number(encMs.toFixed(2)),
        decodeMs: Number(decMs.toFixed(2)),
        applyMs: Number(apply100Ms.toFixed(2)),
        totalMs: Number(total100Ms.toFixed(2)),
        filesPerSec: Math.round((burst100Files.length / total100Ms) * 1000),
        rawMbPerSec: Number(((rawBytes / (1024 * 1024)) / (total100Ms / 1000)).toFixed(2))
      },
      rollbackMs: {
        samples: sortedRb.length,
        p50: percentile(sortedRb, 50),
        p95: percentile(sortedRb, 95)
      }
    };

    if (!silent) {
      console.log('\n════════════════════════════════════════════════════════════');
      console.log('  Culkibo · Banco de pruebas: Live Sync 2.0 (The Forge)');
      console.log('════════════════════════════════════════════════════════════\n');
      console.log(`  Edición local → WS /ws/sync → HTTP sirviendo versión nueva (${summary.iterations} muestras)`);
      console.log(`    p50                ${summary.endToEndMs.p50} ms  (apply servidor p50: ${summary.serverApplyMs.p50} ms)`);
      console.log(`    p95                ${summary.endToEndMs.p95} ms`);
      console.log(`    p99                ${summary.endToEndMs.p99} ms`);
      console.log(`  Ráfaga IA (15 ficheros simultáneos): ${summary.aiBurst15Files.commitFramesSent} commit frame(s) en ${summary.aiBurst15Files.totalMs} ms`);
      console.log(`  Ráfaga 100 ficheros (${(rawBytes / 1024).toFixed(1)} KB fuente TSX):`);
      console.log(`    Brotli (0x02)      ${brFrame.length} B en cable (${brSavedPct}% ahorro, ${summary.burst100FilesBrotli.brotliRatio}x) · Gzip: ${gzFrame.length} B (${gzSavedPct}%)`);
      console.log(`    Pipeline total     ${summary.burst100FilesBrotli.totalMs} ms (${summary.burst100FilesBrotli.filesPerSec} ficheros/s · ${summary.burst100FilesBrotli.rawMbPerSec} MB/s)`);
      console.log(`  Rollback desde historial en memoria: p50 ${summary.rollbackMs.p50} ms · p95 ${summary.rollbackMs.p95} ms\n`);
      console.log('  Nota honesta: Camino B (Live Sync 2.0) evita reconstruir contenedores en');
      console.log('  iteraciones de código/IA; los cambios de dependencias/Dockerfile usan');
      console.log('  Camino C (Docker BuildKit con cache mounts), comparable a otros PaaS.\n');
    }

    liveSyncEngine.resetSession(projectId);
    liveSyncEngine.resetSession(burst100ProjectId);
    return summary;
  } finally {
    if (client) await client.stop().catch(() => {});
    if (originSrv) await new Promise((r) => originSrv.close(() => r(undefined)));
    if (stopDaemon) await stopDaemon().catch(() => {});
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  const asJson = process.argv.includes('--json');
  run({ silent: asJson }).then((res) => {
    if (asJson) process.stdout.write(JSON.stringify(res, null, 2) + '\n');
    process.exit(0);
  }).catch((err) => {
    console.error('❌ Fallo en bench/live-sync.bench.js:', err);
    process.exit(1);
  });
}

module.exports = run;
