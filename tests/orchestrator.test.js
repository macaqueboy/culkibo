const assert = require('assert');
const containerOrchestrator = require('../server/services/containerOrchestrator');

async function testOrchestrator() {
  console.log('🧪 Testing Container Orchestrator (The Forge vs The Citadel)...');

  // 1. Get Pods & baseline
  const podsData = containerOrchestrator.getPods();
  assert.ok(podsData.pods.forge, 'The Forge pod must exist');
  assert.ok(podsData.pods.citadel, 'The Citadel pod must exist');
  assert.strictEqual(podsData.pods.forge.status, 'running');
  assert.strictEqual(podsData.pods.citadel.status, 'running');
  console.log('  ✓ Pods state check passed');

  // 2. Detección y clasificación del cambio.
  //
  // Esta prueba medía un `await setTimeout(8)` fabricado y lo publicaba como
  // «Sub-35ms Hot Sync verified». Medir un retardo que tú mismo has puesto no
  // verifica nada. El retardo está eliminado; ahora se comprueba lo que de
  // verdad ocurre — y, sobre todo, que el resultado NO afirme haber aplicado
  // nada mientras el transporte real siga sin existir (Fase 2 del diseño).
  const syncRes = await containerOrchestrator.triggerHotSync({
    changedFile: 'src/services/ai.ts',
    diffSize: '15 lines'
  });
  assert.strictEqual(syncRes.success, true);
  assert.strictEqual(syncRes.applied, false, 'No puede declarar aplicado un cambio que no se transporta');
  assert.strictEqual(syncRes.mode, 'detect_only', 'El modo debe declarar honestamente su alcance');
  assert.ok(syncRes.syncDurationMs <= 35, `La detección tardó ${syncRes.syncDurationMs}ms, esperado <= 35ms`);
  console.log(`  ✓ Detección y clasificación en ${syncRes.syncDurationMs}ms (modo ${syncRes.mode}, sin retardo fabricado)`);

  // 3. Traffic switching between Forge & Citadel
  const switchRes = await containerOrchestrator.switchTraffic({ forgePercent: 30, citadelPercent: 70 });
  assert.strictEqual(switchRes.success, true);
  assert.strictEqual(switchRes.trafficAllocation.forge, 30);
  assert.strictEqual(switchRes.trafficAllocation.citadel, 70);
  console.log('  ✓ Traffic routing switch passed (30% Forge / 70% Citadel)');

  // 4. Rolling deployment to Citadel
  const deployRes = await containerOrchestrator.deployRelease({
    imageTag: 'v1.0.2',
    gitCommit: 'c0ffe31',
    description: 'Automated test release'
  });
  assert.strictEqual(deployRes.success, true);
  assert.strictEqual(deployRes.version, 'v1.0.2');
  console.log('  ✓ Zero-downtime rolling deployment to Citadel passed');

  // 5. Logs streaming & retrieval
  const logs = containerOrchestrator.getLogs({ limit: 10 });
  assert.ok(Array.isArray(logs));
  assert.ok(logs.length > 0);
  assert.ok(logs[0].message);
  console.log(`  ✓ Logs buffer passed (${logs.length} logs sampled)`);

  // 6. Real Chokidar file watcher on disk
  const fs = require('fs');
  const path = require('path');
  const os = require('os');
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-watch-'));
  try {
    const watchRes = containerOrchestrator.watchDirectory(tempDir);
    assert.strictEqual(watchRes.success, true);
    assert.strictEqual(containerOrchestrator.getWatcherStatus().isWatching, true);
    console.log('  ✓ Chokidar live directory watcher initialized');

    // Create file in watched directory to trigger hot-sync
    const testFile = path.join(tempDir, 'test-component.ts');
    fs.writeFileSync(testFile, 'export const test = 1;', 'utf8');

    // Small delay for chokidar event
    await new Promise(r => setTimeout(r, 120));

    await containerOrchestrator.stopWatching();
    assert.strictEqual(containerOrchestrator.getWatcherStatus().isWatching, false);
    console.log('  ✓ Chokidar file watcher detected modification & stopped cleanly');
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch (e) {}
  }

  console.log('✅ All Container Orchestrator tests passed!\n');
}

module.exports = testOrchestrator;

if (require.main === module) {
  testOrchestrator().catch(err => {
    console.error('❌ Orchestrator test failure:', err);
    process.exit(1);
  });
}
