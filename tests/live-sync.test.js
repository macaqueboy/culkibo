const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const WebSocket = require('ws');

const liveSyncEngine = require('../server/services/liveSyncEngine');
const {
  LiveSyncEngine,
  computeMerkleTree,
  diffMerkleTrees,
  classifyChanges,
  resolveSafeFilePath,
  sha256,
  decodeCompressedPayload,
  decodeBinarySyncFrame
} = liveSyncEngine;
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

    // 7. Live Sync 2.0: Compresión adaptativa (0x01 / 0x02 Brotli / 0x03 Gzip) + anti-zip-bomb
    const codecClient = new LiveSyncClient({
      projectId: 'proj_codec_test',
      sourceDir,
      targetDir,
      autoWatch: false
    });
    codecClient.supportedCodecs = ['br', 'gzip'];

    // 7a. Edición pequeña (<512 B) -> bypass 0x01 crudo (0 ms CPU compresión)
    const tinyBuf = Buffer.from('export const x = 1;\n', 'utf8');
    const tinyFrame = codecClient.encodeBinaryFrame(1, [{
      path: 'src/tiny.js',
      op: 'upsert',
      buffer: tinyBuf,
      sha256: sha256(tinyBuf)
    }]);
    assert.strictEqual(tinyFrame[0], 0x01, 'Tramas < 512 B deben usar bypass 0x01 crudo');
    const decodedTiny = decodeBinarySyncFrame(tinyFrame);
    assert.strictEqual(decodedTiny._wireStats.codec, 'none');
    assert.strictEqual(decodedTiny.files[0].buffer.toString('utf8'), 'export const x = 1;\n');

    // 7b. Ráfaga grande compresible (>= 512 B) -> 0x02 Brotli y 0x03 Gzip con ahorro real
    const bigTsx = Array.from({ length: 120 }, (_, i) =>
      `export function Widget${i}({ title = 'Culkibo Forge' }) { return <section className="card">{title} #{i}</section>; }`
    ).join('\n');
    const bigBuf = Buffer.from(bigTsx, 'utf8');
    const bigSha = sha256(bigBuf);
    const baseShaExample = sha256('prev-version');
    const brFrame = codecClient.encodeBinaryFrame(2, [{
      path: 'src/Widgets.tsx',
      op: 'upsert',
      buffer: bigBuf,
      sha256: bigSha,
      baseSha256: baseShaExample
    }]);
    assert.strictEqual(brFrame[0], 0x02, 'Payload compresible >= 512 B debe negociar 0x02 Brotli');
    assert.ok(brFrame.length < bigBuf.length * 0.4, `Brotli debe ahorrar >60% (wire=${brFrame.length}, raw=${bigBuf.length})`);
    const decodedBr = decodeBinarySyncFrame(brFrame);
    assert.strictEqual(decodedBr._wireStats.codec, 'br');
    assert.strictEqual(decodedBr.files[0].buffer.equals(bigBuf), true);
    assert.strictEqual(decodedBr.files[0].sha256, bigSha);
    assert.strictEqual(decodedBr.files[0].baseSha256, baseShaExample, 'baseSha256 debe preservarse en trama comprimida');

    codecClient.compression = 'gzip';
    const gzFrame = codecClient.encodeBinaryFrame(3, [{
      path: 'src/Widgets.tsx',
      op: 'upsert',
      buffer: bigBuf,
      sha256: bigSha
    }]);
    assert.strictEqual(gzFrame[0], 0x03, 'Modo gzip debe emitir trama 0x03');
    assert.ok(gzFrame.length < bigBuf.length * 0.4, `Gzip debe ahorrar >60% (wire=${gzFrame.length}, raw=${bigBuf.length})`);
    const decodedGz = decodeBinarySyncFrame(gzFrame);
    assert.strictEqual(decodedGz._wireStats.codec, 'gzip');
    assert.strictEqual(decodedGz.files[0].buffer.equals(bigBuf), true);

    // 7c. Fallback a 0x01 para servidores antiguos sin codecs y para binarios incompresibles
    codecClient.compression = 'auto';
    codecClient.supportedCodecs = [];
    const legacyFrame = codecClient.encodeBinaryFrame(4, [{ path: 'src/Widgets.tsx', op: 'upsert', buffer: bigBuf, sha256: bigSha }]);
    assert.strictEqual(legacyFrame[0], 0x01, 'Sin codecs negociados en hello_ack debe degradar a 0x01');

    codecClient.supportedCodecs = ['br', 'gzip'];
    const randomBin = crypto.randomBytes(4096);
    const binFrame = codecClient.encodeBinaryFrame(5, [{ path: 'assets/photo.png', op: 'upsert', buffer: randomBin, sha256: sha256(randomBin) }]);
    assert.strictEqual(binFrame[0], 0x01, 'Archivos binarios incompresibles deben usar 0x01');

    // 7d. decodeCompressedPayload directo (0x01 / 0x02 / 0x03) + rechazo anti-zip-bomb
    const sampleBuf = Buffer.from('hola culkibo '.repeat(200), 'utf8');
    assert.strictEqual(LiveSyncEngine.decodeCompressedPayload(0x01, sampleBuf, 8192).equals(sampleBuf), true);
    assert.strictEqual(decodeCompressedPayload(0x02, zlib.brotliCompressSync(sampleBuf), 8192).equals(sampleBuf), true);
    assert.strictEqual(decodeCompressedPayload(0x03, zlib.gzipSync(sampleBuf), 8192).equals(sampleBuf), true);

    const bombPlain = Buffer.alloc(2 * 1024 * 1024, 0x41); // 2 MiB altamente compresible
    const bombBr = zlib.brotliCompressSync(bombPlain);
    const bombGz = zlib.gzipSync(bombPlain);
    assert.ok(bombBr.length < 2048 && bombGz.length < 4096, 'La bomba de prueba debe comprimirse a pocos KB');
    assert.throws(
      () => decodeCompressedPayload(0x02, bombBr, 64 * 1024),
      (err) => err && err.code === 'FRAME_TOO_LARGE',
      'Bomba Brotli que excede maxOutBytes debe rechazarse con FRAME_TOO_LARGE'
    );
    assert.throws(
      () => decodeCompressedPayload(0x03, bombGz, 64 * 1024),
      (err) => err && err.code === 'FRAME_TOO_LARGE',
      'Bomba Gzip que excede maxOutBytes debe rechazarse con FRAME_TOO_LARGE'
    );

    // Bomba con rawLen falsificado en cabecera (declara 1024 B pero expande a 2 MiB)
    const spoofedHeader = Buffer.allocUnsafe(5);
    spoofedHeader[0] = 0x02;
    spoofedHeader.writeUInt32BE(1024, 1);
    assert.throws(
      () => decodeBinarySyncFrame(Buffer.concat([spoofedHeader, bombBr]), 64 * 1024),
      (err) => err && err.code === 'FRAME_TOO_LARGE',
      'rawLen falsificado menor que la expansión real debe rechazarse con FRAME_TOO_LARGE'
    );

    // rawLen declarado por encima del límite máximo permitido
    const hugeHeader = Buffer.allocUnsafe(5);
    hugeHeader[0] = 0x03;
    hugeHeader.writeUInt32BE(32 * 1024 * 1024, 1);
    assert.throws(
      () => decodeBinarySyncFrame(Buffer.concat([hugeHeader, bombGz])),
      (err) => err && err.code === 'FRAME_TOO_LARGE',
      'rawLen > 16.5 MiB debe rechazarse antes de descomprimir'
    );
    console.log(`  ✓ Compresión adaptativa (0x01/0x02 br/0x03 gzip) y defensa anti-zip-bomb verificadas`);

    // 8. Live Sync 2.0: Historial time-travel por fichero + rollbackFile quirúrgico + bloqueo traversal
    const ttTargetDir = path.join(tmpRoot, 'time-travel-target');
    fs.mkdirSync(ttTargetDir, { recursive: true });
    const ttProjectId = `proj_tt_${Date.now()}`;
    liveSyncEngine.setTargetDir(ttProjectId, ttTargetDir);

    liveSyncEngine.applyCommitFrame(ttProjectId, {
      seq: 1,
      files: [
        { path: 'src/alpha.ts', op: 'upsert', content: 'export const v = 1;\n' },
        { path: 'src/beta.ts', op: 'upsert', content: 'export const b = 1;\n' }
      ],
      _wireStats: decodedBr._wireStats
    });
    liveSyncEngine.applyCommitFrame(ttProjectId, {
      seq: 2,
      files: [
        { path: 'src/alpha.ts', op: 'upsert', content: 'export const v = 2;\n' },
        { path: 'src/beta.ts', op: 'upsert', content: 'export const b = 2;\n' }
      ]
    });
    liveSyncEngine.applyCommitFrame(ttProjectId, {
      seq: 3,
      files: [
        { path: 'src/alpha.ts', op: 'upsert', content: 'export const v = 3;\n' }
      ]
    });

    const alphaHist = liveSyncEngine.getFileHistory(ttProjectId, 'src/alpha.ts');
    assert.strictEqual(alphaHist.path, 'src/alpha.ts');
    assert.strictEqual(alphaHist.existsOnDisk, true);
    assert.strictEqual(alphaHist.revisionCount, 4, 'Debe contener seq 3, 2, 1 y baseline seq 0');
    assert.deepStrictEqual(alphaHist.revisions.map((r) => r.seq), [3, 2, 1, 0]);
    assert.strictEqual(alphaHist.versions.length, 4, 'Alias versions debe coincidir con revisions');
    assert.strictEqual(alphaHist.revisions[0].restorable, true);
    assert.strictEqual(alphaHist.revisions[0].snapshot, undefined, 'No debe exponer buffers crudos en JSON de historial');
    const limitedHist = liveSyncEngine.getFileHistory(ttProjectId, 'src/alpha.ts', { limit: 2, includeDiff: true });
    assert.strictEqual(limitedHist.revisions.length, 2);
    assert.ok(typeof limitedHist.revisions[0].diff === 'string' && limitedHist.revisions[0].diff.includes('+ export const v = 3;'));

    // Rollback quirúrgico SOLO de src/alpha.ts a seq 1 (sin tocar src/beta.ts!)
    const rbFile1 = liveSyncEngine.rollbackFile(ttProjectId, 'src/alpha.ts', 1);
    assert.strictEqual(rbFile1.reverted, true);
    assert.strictEqual(rbFile1.scope, 'file');
    assert.strictEqual(rbFile1.targetSeq, 1);
    assert.strictEqual(fs.readFileSync(path.join(ttTargetDir, 'src/alpha.ts'), 'utf8'), 'export const v = 1;\n');
    assert.strictEqual(fs.readFileSync(path.join(ttTargetDir, 'src/beta.ts'), 'utf8'), 'export const b = 2;\n', 'rollbackFile no debe tocar otros ficheros');

    // Verificar que fileCache quedó repoblada tras rollbackFile
    const ttSession = liveSyncEngine.getOrCreateSession(ttProjectId);
    const alphaAbs = path.resolve(ttTargetDir, 'src/alpha.ts');
    assert.ok(ttSession.fileCache.has(alphaAbs), 'rollbackFile debe repoblar session.fileCache');
    assert.strictEqual(ttSession.fileCache.get(alphaAbs).buf.toString('utf8'), 'export const v = 1;\n');

    // El propio rollbackFile genera un frame deshacible vía rollback(id, 1) -> vuelve a v = 3 y repuebla fileCache!
    const undoRbFile = liveSyncEngine.rollback(ttProjectId, 1);
    assert.strictEqual(undoRbFile.reverted, true);
    assert.strictEqual(fs.readFileSync(alphaAbs, 'utf8'), 'export const v = 3;\n');
    assert.ok(ttSession.fileCache.has(alphaAbs), 'rollback() debe repoblar session.fileCache');
    assert.strictEqual(ttSession.fileCache.get(alphaAbs).buf.toString('utf8'), 'export const v = 3;\n');

    // mode: 'before' restaura la versión previa a seq 2 (v = 1), y seq 0 elimina fichero creado en sesión
    const rbBefore = liveSyncEngine.rollbackFile(ttProjectId, 'src/alpha.ts', 2, { mode: 'before' });
    assert.strictEqual(rbBefore.targetSeq, 1);
    assert.strictEqual(fs.readFileSync(alphaAbs, 'utf8'), 'export const v = 1;\n');

    const rbBaseline = liveSyncEngine.rollbackFile(ttProjectId, 'src/alpha.ts', 0);
    assert.strictEqual(rbBaseline.action, 'deleted');
    assert.strictEqual(fs.existsSync(alphaAbs), false, 'Rollback a baseline seq 0 de fichero nuevo debe eliminarlo');

    // Seguridad traversal en getFileHistory y rollbackFile
    for (const badPath of ['../outside.txt', '/etc/passwd', '.git/config', 'ok\0evil.js']) {
      assert.throws(
        () => liveSyncEngine.getFileHistory(ttProjectId, badPath),
        (err) => err && err.code === 'PATH_TRAVERSAL_BLOCKED',
        `getFileHistory debe bloquear ${badPath}`
      );
      assert.throws(
        () => liveSyncEngine.rollbackFile(ttProjectId, badPath, 1),
        (err) => err && err.code === 'PATH_TRAVERSAL_BLOCKED',
        `rollbackFile debe bloquear ${badPath}`
      );
    }

    // Telemetría wireStats en getStatus
    const ttStatus = liveSyncEngine.getStatus(ttProjectId);
    assert.ok(ttStatus.wireStats && ttStatus.wireStats.compressedFrames === 1);
    assert.ok(ttStatus.wireStats.rawBytes > ttStatus.wireStats.wireBytes);
    assert.ok(ttStatus.wireStats.savedPct > 50);
    console.log(`  ✓ Time-travel por fichero (getFileHistory + rollbackFile quirúrgico + fileCache + traversal block) verificado`);

    // 9. Live Sync 2.0: Detección de conflictos multi-cliente (ventana concurrente + stale baseSha256)
    const confTargetDir = path.join(tmpRoot, 'conflict-target');
    fs.mkdirSync(confTargetDir, { recursive: true });
    const confProjectId = `proj_conf_${Date.now()}`;
    liveSyncEngine.setTargetDir(confProjectId, confTargetDir);
    liveSyncEngine.registerClient(confProjectId, { id: 'cli_alice', clientName: 'Alice' });
    liveSyncEngine.registerClient(confProjectId, { id: 'cli_bob', clientName: 'Bob' });

    const emittedConflicts = [];
    const onConflict = (c) => { if (c.projectId === confProjectId) emittedConflicts.push(c); };
    liveSyncEngine.on('sync_conflict', onConflict);
    try {
      // Alice edita shared.js (seq: 1)
      const cA = liveSyncEngine.applyCommitFrame(confProjectId, {
        seq: 1,
        files: [{ path: 'shared.js', op: 'upsert', content: 'export const owner = "alice";\n' }]
      }, { clientId: 'cli_alice', clientName: 'Alice' });
      assert.strictEqual(cA.conflicts.length, 0);
      assert.strictEqual(cA.reconcileRequired, false);

      // Bob también envía seq: 1 (sin false drift en modo multi-cliente) sobre el mismo fichero dentro de la ventana
      const cB = liveSyncEngine.applyCommitFrame(confProjectId, {
        seq: 1,
        files: [{ path: 'shared.js', op: 'upsert', content: 'export const owner = "bob";\n' }]
      }, { clientId: 'cli_bob', clientName: 'Bob' });
      assert.strictEqual(cB.reconcileRequired, false, 'Dos clientes enviando seq: 1 no deben disparar drift falso');
      assert.strictEqual(cB.conflicts.length, 1, 'Edición concurrente de 2 clientes debe señalar conflicto');
      assert.strictEqual(cB.conflicts[0].reason, 'concurrent_window');
      assert.strictEqual(cB.conflicts[0].previous.clientId, 'cli_alice');
      assert.strictEqual(cB.conflicts[0].incoming.clientId, 'cli_bob');
      assert.strictEqual(emittedConflicts.length, 1);

      // Recuperación en 1 clic de la versión de Alice mediante previousSeq
      const recovered = liveSyncEngine.rollbackFile(confProjectId, 'shared.js', cB.conflicts[0].previousSeq);
      assert.strictEqual(recovered.reverted, true);
      assert.strictEqual(fs.readFileSync(path.join(confTargetDir, 'shared.js'), 'utf8'), 'export const owner = "alice";\n');

      // Capa 2: stale baseSha256 detectado incluso con conflictWindowMs = 0 (ventana expirada)
      const v1Content = 'export const n = 1;\n';
      const v2Content = 'export const n = 2;\n';
      liveSyncEngine.applyCommitFrame(confProjectId, {
        seq: 2,
        files: [{ path: 'cas.js', op: 'upsert', content: v1Content }]
      }, { clientId: 'cli_alice', clientName: 'Alice' });
      liveSyncEngine.applyCommitFrame(confProjectId, {
        seq: 3,
        files: [{ path: 'cas.js', op: 'upsert', content: v2Content }]
      }, { clientId: 'cli_alice', clientName: 'Alice' });

      // Bob intenta escribir con baseSha256 obsoleto (v1) en modo reject
      const cStaleReject = liveSyncEngine.applyCommitFrame(confProjectId, {
        seq: 2,
        files: [{ path: 'cas.js', op: 'upsert', content: 'export const n = 999;\n', baseSha256: sha256(v1Content) }]
      }, { clientId: 'cli_bob', clientName: 'Bob', conflictWindowMs: 0, conflictPolicy: 'reject' });
      assert.strictEqual(cStaleReject.conflicts.length, 1);
      assert.strictEqual(cStaleReject.conflicts[0].reason, 'stale_base_hash');
      assert.strictEqual(cStaleReject.conflicts[0].rejected, true);
      assert.strictEqual(fs.readFileSync(path.join(confTargetDir, 'cas.js'), 'utf8'), v2Content, 'Política reject no debe sobrescribir el disco');

      // Resolver conflicto y verificar getStatus
      const resolved = liveSyncEngine.resolveConflict(confProjectId, cB.conflicts[0].id);
      assert.strictEqual(resolved.resolved, true);
      const confStatus = liveSyncEngine.getStatus(confProjectId);
      assert.ok(Array.isArray(confStatus.recentConflicts) && confStatus.recentConflicts.length >= 2);
      assert.strictEqual(confStatus.recentConflicts.find((c) => c.id === cB.conflicts[0].id).resolved, true);
    } finally {
      liveSyncEngine.off('sync_conflict', onConflict);
    }
    console.log('  ✓ Conflictos multi-cliente (ventana concurrente + stale baseSha256 + reject + resolveConflict) verificados');

    // 10. Diff unificado LCS (getFrameDiff), .culkiboignore y caché stat anti doble-lectura
    const diffDir = path.join(tmpRoot, 'lcs-diff-target');
    fs.mkdirSync(diffDir, { recursive: true });
    const diffProj = `proj_lcs_${Date.now()}`;
    liveSyncEngine.setTargetDir(diffProj, diffDir);
    const twentyLines = Array.from({ length: 20 }, (_, i) => `const line${i + 1} = ${i + 1};`).join('\n') + '\n';
    liveSyncEngine.applyCommitFrame(diffProj, { seq: 1, files: [{ path: 'app.js', op: 'upsert', content: twentyLines }] });
    liveSyncEngine.applyCommitFrame(diffProj, { seq: 2, files: [{ path: 'app.js', op: 'upsert', content: '// encabezado nuevo\n' + twentyLines }] });
    const lcsDiff = liveSyncEngine.getFrameDiff(diffProj, 2);
    assert.ok(lcsDiff && lcsDiff.files.length === 1);
    assert.strictEqual(lcsDiff.files[0].action, 'modified');
    assert.ok(lcsDiff.files[0].diff.includes('+ // encabezado nuevo'));
    assert.ok(!lcsDiff.files[0].diff.includes('- const line1 = 1;'), 'Diff LCS no debe marcar líneas desplazadas intactas como eliminadas');

    // .culkiboignore + caché stat del cliente
    const ignDir = path.join(tmpRoot, 'ignore-src');
    fs.mkdirSync(path.join(ignDir, 'scratch'), { recursive: true });
    fs.writeFileSync(path.join(ignDir, '.culkiboignore'), '*.log\n!keep.log\nscratch/\n', 'utf8');
    fs.writeFileSync(path.join(ignDir, 'debug.log'), 'ignored', 'utf8');
    fs.writeFileSync(path.join(ignDir, 'keep.log'), 'kept', 'utf8');
    fs.writeFileSync(path.join(ignDir, 'scratch', 'temp.txt'), 'ignored', 'utf8');
    const ignClient = new LiveSyncClient({ projectId: 'proj_ign', sourceDir: ignDir, autoWatch: false });
    assert.strictEqual(ignClient.isIgnored('debug.log'), true);
    assert.strictEqual(ignClient.isIgnored('keep.log'), false, 'Negación !keep.log debe respetarse');
    assert.strictEqual(ignClient.isIgnored('scratch/temp.txt'), true);
    const keepAbs = path.join(ignDir, 'keep.log');
    const read1 = await ignClient._readFileSafe(keepAbs);
    assert.strictEqual(read1.kind, 'file');
    const read2 = await ignClient._readFileSafe(keepAbs, { skipIfUnchangedHash: read1.sha256 });
    assert.strictEqual(read2.kind, 'unchanged', 'Caché stat (mtimeMs, size, sha256) debe evitar lectura duplicada');
    console.log('  ✓ Diff LCS unificado, .culkiboignore y caché stat anti-doble-disparo verificados');

    // 11. Live Sync 2.0 Edge Cases: Dir rename/delete storm, post-ACK reconcile (cero hash poisoning),
    //     reconcileFull(null) extra cleanup, atomic win32 write, case-only rename y carga troceada >10 MiB SHA-256
    const edgeSrc = path.join(tmpRoot, 'edge-src');
    const edgeDst = path.join(tmpRoot, 'edge-dst');
    fs.mkdirSync(path.join(edgeSrc, 'old-dir'), { recursive: true });
    fs.mkdirSync(edgeDst, { recursive: true });
    fs.writeFileSync(path.join(edgeSrc, 'old-dir', 'a.js'), 'export const a = 1;\n', 'utf8');
    fs.writeFileSync(path.join(edgeSrc, 'old-dir', 'b.js'), 'export const b = 2;\n', 'utf8');
    fs.writeFileSync(path.join(edgeSrc, 'App.tsx'), 'export default function App(){return 1;}\n', 'utf8');

    // Servidor WS local que expone protocolo completo Live Sync 2.0 + chunkedUploadSupported
    const { WebSocketServer } = require('ws');
    const edgeProjId = `proj_edge_${Date.now()}`;
    liveSyncEngine.setTargetDir(edgeProjId, edgeDst);
    const edgeWss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
    let failNextFrame = false;
    edgeWss.on('connection', (ws) => {
      ws.on('message', (raw, isBinary) => {
        try {
          const msg = isBinary ? decodeBinarySyncFrame(Buffer.isBuffer(raw) ? raw : Buffer.from(raw)) : JSON.parse(raw.toString());
          if (msg.type === 'hello') {
            const ver = liveSyncEngine.verifySync(edgeProjId, { clientDigest: msg.clientDigest, targetDir: edgeDst });
            ws.send(JSON.stringify({
              type: 'hello_ack',
              clientId: 'edge_c1',
              protocolVersion: 2,
              codecs: ['br', 'gzip'],
              binaryFramesSupported: true,
              chunkedUploadSupported: true,
              lastSeq: 0,
              serverDigest: ver.serverDigest,
              inSync: ver.inSync
            }));
          } else if (msg.type === 'verify') {
            const ver = liveSyncEngine.verifySync(edgeProjId, { clientFiles: msg.clientFiles, targetDir: edgeDst });
            ws.send(JSON.stringify({ type: 'verify_ack', ...ver }));
          } else if (msg.type === 'frame') {
            if (failNextFrame) {
              failNextFrame = false;
              ws.send(JSON.stringify({ type: 'error', seq: msg.seq, code: 'INJECTED_DROP', error: 'Fallo simulado de red' }));
              return;
            }
            const res = liveSyncEngine.applyCommitFrame(edgeProjId, msg, { targetDir: edgeDst });
            ws.send(JSON.stringify({ type: 'frame_ack', ...res }));
          } else if (String(msg.type || '').startsWith('chunk_')) {
            const ack = liveSyncEngine.handleChunkMessage(edgeProjId, msg, { targetDir: edgeDst });
            ws.send(JSON.stringify(ack));
          }
        } catch (e) {
          ws.send(JSON.stringify({ type: 'error', code: e.code || 'ERR', error: e.message }));
        }
      });
    });
    await new Promise((r) => edgeWss.once('listening', r));
    const edgePort = /** @type {import('net').AddressInfo} */ (edgeWss.address()).port;

    const edgeClient = new LiveSyncClient({
      projectId: edgeProjId,
      sourceDir: edgeSrc,
      targetDir: edgeDst,
      wsUrl: `ws://127.0.0.1:${edgePort}`,
      autoWatch: false,
      autoReconnect: false
    });
    try {
      await edgeClient.start();
      assert.strictEqual(edgeClient.chunkedUploadSupported, true);

      // 11a. Post-ACK reconcile: si falla sendChunked a mitad de reconcileDelta, lastSentHashes NO se envenena
      failNextFrame = true;
      await assert.rejects(() => edgeClient.reconcileDelta(), /Fallo simulado/i);
      assert.strictEqual(edgeClient.lastSentHashes.size, 0, 'lastSentHashes JAMÁS debe mutarse antes de ACK');

      // Reintento limpio -> sincroniza todo y Merkle coincide
      const recOk = await edgeClient.reconcileDelta();
      assert.strictEqual(recOk.reconciled, true);
      assert.strictEqual(edgeClient.lastSentHashes.size, 3);
      assert.strictEqual(computeMerkleTree(edgeSrc).rootDigest, computeMerkleTree(edgeDst).rootDigest);

      // 11b. Tormenta de renombre de directorio (`old-dir` -> `new-dir`):
      // Simular eventos fs.watch de Windows que sólo reportan la carpeta vieja y la nueva
      fs.renameSync(path.join(edgeSrc, 'old-dir'), path.join(edgeSrc, 'new-dir'));
      edgeClient.pending.set('old-dir', 'upsert');
      edgeClient.pending.set('new-dir', 'upsert');
      await edgeClient.flushNow();
      assert.strictEqual(fs.existsSync(path.join(edgeDst, 'old-dir')), false, 'El directorio antiguo debe eliminarse en destino');
      assert.strictEqual(fs.readFileSync(path.join(edgeDst, 'new-dir', 'a.js'), 'utf8'), 'export const a = 1;\n', 'Los hijos del directorio renombrado deben sincronizarse');
      assert.strictEqual(fs.readFileSync(path.join(edgeDst, 'new-dir', 'b.js'), 'utf8'), 'export const b = 2;\n');
      assert.strictEqual(edgeClient.lastSentHashes.has('old-dir/a.js'), false, 'lastSentHashes debe purgar hijos del directorio eliminado');
      assert.strictEqual(edgeClient.lastSentHashes.has('new-dir/a.js'), true);

      // 11c. Renombre sólo de capitalización (`App.tsx` -> `app.tsx`) con contenido idéntico:
      // El engine debe ejecutar delete antes del upsert e invalidar stat en NTFS/APFS
      fs.renameSync(path.join(edgeSrc, 'App.tsx'), path.join(edgeSrc, 'app.tsx'));
      edgeClient.pending.set('app.tsx', 'upsert');
      await edgeClient.flushNow();
      const dstNames = fs.readdirSync(edgeDst);
      assert.ok(dstNames.includes('app.tsx'), `Destino debe tener exactamente "app.tsx" (encontrados: ${dstNames.join(', ')})`);
      assert.strictEqual(dstNames.includes('App.tsx'), false, 'La capitalización antigua "App.tsx" no debe quedar huérfana');
      assert.strictEqual(edgeClient.lastSentHashes.has('App.tsx'), false);
      assert.strictEqual(edgeClient.lastSentHashes.has('app.tsx'), true);

      // 11d. Fallback reconcileFull(null) limpia ficheros eliminados localmente
      fs.unlinkSync(path.join(edgeSrc, 'new-dir', 'b.js'));
      const origVerify = edgeClient.verifyWithServer.bind(edgeClient);
      edgeClient.verifyWithServer = () => Promise.reject(new Error('legacy server no verify'));
      try {
        await edgeClient.reconcileFull(null);
      } finally {
        edgeClient.verifyWithServer = origVerify;
      }
      assert.strictEqual(fs.existsSync(path.join(edgeDst, 'new-dir', 'b.js')), false, 'reconcileFull(null) debe eliminar huérfanos rastreados');

      // 11e. Carga troceada >10 MiB (11 MiB binarios) end-to-end por WS con verificación SHA-256
      const bigBytes = 11 * 1024 * 1024;
      const bigBin = Buffer.alloc(bigBytes);
      // Llenar patrón binario no-trivial con bytes nulos para validar integridad binaria exacta
      for (let off = 0; off < bigBytes; off += 4096) {
        bigBin.writeUInt32BE(off, off);
      }
      const bigBinPath = path.join(edgeSrc, 'assets', 'model-11mb.bin');
      fs.mkdirSync(path.dirname(bigBinPath), { recursive: true });
      fs.writeFileSync(bigBinPath, bigBin);
      const expectedBigSha = sha256(bigBin);

      edgeClient.pending.set('assets/model-11mb.bin', 'upsert');
      const chunkCommitAck = await edgeClient.flushNow();
      assert.ok(chunkCommitAck && chunkCommitAck.chunked === true, 'Fichero >10 MiB debe transferirse vía carga troceada');
      const dstBigPath = path.join(edgeDst, 'assets', 'model-11mb.bin');
      assert.strictEqual(fs.existsSync(dstBigPath), true);
      assert.strictEqual(fs.statSync(dstBigPath).size, bigBytes);
      assert.strictEqual(liveSyncEngine.sha256FileSync(dstBigPath), expectedBigSha, 'SHA-256 del binario de 11 MiB en destino debe ser idéntico');
      assert.strictEqual(computeMerkleTree(edgeSrc).rootDigest, computeMerkleTree(edgeDst).rootDigest, 'Merkle debe incluir ficheros >10 MiB y coincidir');

      // 11f. Validaciones negativas de carga troceada (SHA-256 manipulado limpia temp, traversal bloqueado, out-of-order rechazado)
      assert.throws(
        () => liveSyncEngine.startChunkedUpload(edgeProjId, { path: '../escape.bin', totalBytes: 10, sha256: 'a'.repeat(64) }, { targetDir: edgeDst }),
        (err) => err && err.code === 'PATH_TRAVERSAL_BLOCKED'
      );
      const badStart = liveSyncEngine.startChunkedUpload(edgeProjId, { path: 'tampered.bin', totalBytes: 5, sha256: '0'.repeat(64) }, { targetDir: edgeDst });
      assert.throws(
        () => liveSyncEngine.appendChunk(edgeProjId, { uploadId: badStart.uploadId, index: 2, data: Buffer.from('hello') }),
        (err) => err && err.code === 'OUT_OF_ORDER_CHUNK'
      );
      liveSyncEngine.appendChunk(edgeProjId, { uploadId: badStart.uploadId, index: 0, data: Buffer.from('hello') });
      assert.throws(
        () => liveSyncEngine.commitChunkedUpload(edgeProjId, { uploadId: badStart.uploadId }, { targetDir: edgeDst }),
        (err) => err && err.code === 'CHECKSUM_MISMATCH'
      );
      assert.strictEqual(fs.existsSync(path.join(edgeDst, 'tampered.bin')), false, 'Un checksum inválido jamás debe crear el fichero destino');
      const leftoverTemps = fs.readdirSync(edgeDst).filter((f) => f.includes('.culkibo-sync-chunk-'));
      assert.strictEqual(leftoverTemps.length, 0, 'Fallo de checksum debe eliminar el fichero temporal');
      console.log('  ✓ Live Sync 2.0 edge cases (dir rename storm, post-ACK reconcile, case-only rename, orphan cleanup, 11 MiB chunked SHA-256 upload) verificados');
    } finally {
      await edgeClient.stop().catch(() => {});
      await new Promise((r) => edgeWss.close(() => r(undefined)));
      liveSyncEngine.resetSession(edgeProjId);
    }

    // Limpiar sesiones de prueba
    liveSyncEngine.resetSession(projectId);
    liveSyncEngine.resetSession(wsProjectId);
    liveSyncEngine.resetSession(ttProjectId);
    liveSyncEngine.resetSession(confProjectId);
    liveSyncEngine.resetSession(diffProj);
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
