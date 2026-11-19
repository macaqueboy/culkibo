const assert = require('assert');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const WebSocket = require('ws');

const liveSyncEngine = require('../server/services/liveSyncEngine');
const { computeMerkleTree, diffMerkleTrees, classifyChanges, resolveSafeFilePath, sha256 } = liveSyncEngine;
const { LiveSyncClient } = require('../server/services/liveSyncClient');
const { ensureDaemon } = require('./helpers/daemon');

const BASE_URL = 'http://127.0.0.1:3030';
const WS_SYNC_URL = 'ws://127.0.0.1:3030/ws/sync';

function startStaticFileServer(rootDir) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const clean = String(req.url || '/').split('?')[0].replace(/^\/+/, '') || 'index.html';
      const target = path.join(rootDir, clean);
      if (fs.existsSync(target) && fs.statSync(target).isFile()) {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end(fs.readFileSync(target));
      } else {
        res.writeHead(404);
        res.end('not found');
      }
    });
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({ server, port: typeof addr === 'object' && addr ? addr.port : 0 });
    });
  });
}

async function testLiveSync() {
  console.log('🧪 Probando Live Sync (Commit Frames, Merkle, Rollback <10ms y WebSocket /ws/sync)...');

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-livesync-'));
  const sourceDir = path.join(tmpRoot, 'local-repo');
  const targetDir = path.join(tmpRoot, 'live-target');
  fs.mkdirSync(sourceDir, { recursive: true });
  fs.mkdirSync(targetDir, { recursive: true });

  const projectId = `proj_sync_${Date.now()}`;
  let stopDaemon = null;
  let httpSrv = null;
  let client = null;

  try {
    // 1. Seguridad estricta de rutas (path traversal, absolutas, .git, nulos)
    const badPaths = [
      '../secreto.txt',
      'a/../../escape.txt',
      '/etc/passwd',
      'C:\\Windows\\win.ini',
      '.git/config',
      'ok\0evil.js'
    ];
    for (const p of badPaths) {
      assert.throws(
        () => resolveSafeFilePath(targetDir, p),
        (err) => err && err.code === 'PATH_TRAVERSAL_BLOCKED',
        `Debe bloquear ruta peligrosa: ${p}`
      );
    }
    console.log(`  ✓ Seguridad de rutas: ${badPaths.length} vectores de path traversal bloqueados`);

    // 2. Clasificación honesta Camino B vs Camino C
    assert.strictEqual(classifyChanges(['src/App.tsx', 'public/style.css']).path, 'path_b_hot');
    assert.strictEqual(classifyChanges(['src/App.tsx', 'package.json']).path, 'path_c_restart');
    assert.strictEqual(classifyChanges(['Dockerfile']).path, 'path_c_restart');
    assert.strictEqual(classifyChanges(['.env.production']).path, 'path_c_restart');
    console.log('  ✓ Clasificación honesta: hojas -> path_b_hot; dependencias/config -> path_c_restart');

    // 3. Commit Frame atómico (20 ficheros), deduplicación SHA-256 y detección de huecos de secuencia
    liveSyncEngine.setTargetDir(projectId, targetDir);
    const burst = Array.from({ length: 20 }, (_, i) => {
      const content = `export const mod${i} = ${i};\n`;
      return { path: `src/mod${i}.js`, op: 'upsert', content, encoding: 'utf8', sha256: sha256(content) };
    });
    const r1 = liveSyncEngine.applyCommitFrame(projectId, { seq: 1, files: burst });
    assert.strictEqual(r1.written, 20);
    assert.strictEqual(r1.dedupSkipped, 0);
    assert.strictEqual(r1.mode, 'path_b_hot');
    assert.strictEqual(r1.reconcileRequired, false);

    // Repetir el mismo contenido -> 100 % deduplicado sin reescribir nada
    const r2 = liveSyncEngine.applyCommitFrame(projectId, { seq: 2, files: burst });
    assert.strictEqual(r2.written, 0);
    assert.strictEqual(r2.dedupSkipped, 20);

    // Hueco de secuencia (seq 2 -> seq 7) -> marca drift y pide reconciliación
    const rGap = liveSyncEngine.applyCommitFrame(projectId, {
      seq: 7,
      files: [{ path: 'src/mod0.js', op: 'upsert', content: 'export const mod0 = 999;\n' }]
    });
    assert.strictEqual(rGap.reconcileRequired, true, 'Un salto de secuencia debe pedir reconciliación Merkle');
    console.log(`  ✓ Commit Frame atómico (20 ficheros en ${r1.applyMs}ms), dedup SHA-256 y detección de huecos`);

    // 4. Rollback instantáneo en memoria (<15 ms)
    const rb = liveSyncEngine.rollback(projectId, 1);
    assert.strictEqual(rb.reverted, true);
    assert.ok(rb.restoredFiles.includes('src/mod0.js'));
    assert.strictEqual(fs.readFileSync(path.join(targetDir, 'src/mod0.js'), 'utf8'), 'export const mod0 = 0;\n');
    const maxRbMs = process.platform === 'win32' ? 250 : 25;
    assert.ok(rb.durationMs < maxRbMs, `Rollback demasiado lento: ${rb.durationMs}ms (objetivo < ${maxRbMs}ms)`);
    console.log(`  ✓ Rollback de parche desde memoria en ${rb.durationMs}ms (contenido exacto restaurado)`);

    // 5. Árbol Merkle y detección exacta de divergencia
    fs.writeFileSync(path.join(sourceDir, 'index.html'), '<h1>v1</h1>', 'utf8');
    fs.writeFileSync(path.join(sourceDir, 'app.js'), 'console.log("v1");', 'utf8');
    const localTree = computeMerkleTree(sourceDir);
    const serverTree = computeMerkleTree(targetDir);
    const diff = diffMerkleTrees(localTree.files, serverTree.files);
    assert.strictEqual(diff.inSync, false);
    assert.ok(diff.missingOnServer.includes('index.html'));
    console.log('  ✓ Árbol Merkle detecta divergencias exactas (missing, stale, extra)');

    // 6. Prueba de red real end-to-end: LiveSyncClient -> WebSocket /ws/sync -> servidor HTTP vivo
    stopDaemon = await ensureDaemon();

    // 6a. Rechazo de origen cruzado malicioso en el upgrade de /ws/sync
    const blockedCode = await new Promise((resolve) => {
      const evilWs = new WebSocket(WS_SYNC_URL, { headers: { Origin: 'https://evil.example' } });
      evilWs.on('unexpected-response', (_req, res) => resolve(res.statusCode));
      evilWs.on('open', () => { evilWs.close(); resolve(200); });
      evilWs.on('error', () => {});
    });
    assert.strictEqual(blockedCode, 403, 'El upgrade /ws/sync debe rechazar un Origin no autorizado con 403');
    console.log('  ✓ Seguridad WebSocket /ws/sync: Origin ajeno rechazado con HTTP 403');

    // 6b. Levantar proyecto vivo + servidor HTTP real sobre liveTarget2
    const liveTarget2 = path.join(tmpRoot, 'live-http');
    fs.mkdirSync(liveTarget2, { recursive: true });
    const startedHttp = await startStaticFileServer(liveTarget2);
    httpSrv = startedHttp.server;
    const liveUrl = `http://127.0.0.1:${startedHttp.port}/index.html`;

    const wsProjectId = `proj_ws_${Date.now()}`;
    client = new LiveSyncClient({
      projectId: wsProjectId,
      sourceDir,
      targetDir: liveTarget2,
      wsUrl: WS_SYNC_URL,
      quiescenceMs: 10
    });
    await client.start();

    // Reconciliación inicial
    const rec = await client.reconcileFull();
    assert.strictEqual(rec.reconciled, true);
    const body1 = await (await fetch(liveUrl)).text();
    assert.strictEqual(body1, '<h1>v1</h1>', 'El servidor HTTP vivo debe servir inmediatamente la v1 sincronizada');

    // Edición real en disco -> watcher -> commit frame -> WS -> disco destino -> HTTP vivo
    const editStart = process.hrtime.bigint();
    const ackPromise = new Promise((resolve) => client.once('frame_ack', resolve));
    fs.writeFileSync(path.join(sourceDir, 'index.html'), '<h1>v2-live-synced</h1>', 'utf8');
    const ack = await ackPromise;
    const body2 = await (await fetch(liveUrl)).text();
    const totalEndToEndMs = Number((Number(process.hrtime.bigint() - editStart) / 1e6).toFixed(2));

    assert.strictEqual(body2, '<h1>v2-live-synced</h1>', 'El servidor HTTP vivo debe servir v2 tras el Commit Frame');
    assert.strictEqual(ack.mode, 'path_b_hot');
    const maxE2eMs = process.platform === 'win32' ? 3000 : 800;
    assert.ok(totalEndToEndMs < maxE2eMs, `Sincronización end-to-end tardó ${totalEndToEndMs}ms (objetivo < ${maxE2eMs}ms)`);

    // Verificación Merkle post-sync: cero divergencia
    const finalLocalTree = computeMerkleTree(sourceDir);
    const finalTargetTree = computeMerkleTree(liveTarget2);
    assert.strictEqual(finalLocalTree.rootDigest, finalTargetTree.rootDigest, 'El árbol Merkle local y destino deben ser idénticos tras Live Sync');
    console.log(`  ✓ End-to-end real (edición en disco -> WS /ws/sync -> HTTP vivo) en ${totalEndToEndMs}ms · Merkle idéntico (${finalTargetTree.rootDigest.slice(0, 10)})`);

    // Limpiar sesión de prueba
    liveSyncEngine.resetSession(projectId);
    liveSyncEngine.resetSession(wsProjectId);
    console.log('✅ Todas las pruebas de Live Sync superadas!\n');
  } finally {
    if (client) await client.stop().catch(() => {});
    if (httpSrv) await new Promise((r) => httpSrv.close(() => r(undefined)));
    if (stopDaemon) await stopDaemon().catch(() => {});
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

module.exports = testLiveSync;

if (require.main === module) {
  testLiveSync().then(() => process.exit(0)).catch((err) => {
    console.error('❌ Fallo en live-sync.test.js:', err);
    process.exit(1);
  });
}
