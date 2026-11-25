const assert = require('assert');
const containerOrchestrator = require('../server/services/containerOrchestrator');

async function testOrchestrator() {
  console.log('🧪 Testing Container Orchestrator (The Forge vs The Citadel)...');

  // 1. Get Pods & baseline
  const podsData = containerOrchestrator.getPods();
  assert.ok(podsData.pods.forge, 'The Forge pod must exist');
  assert.ok(podsData.pods.citadel, 'The Citadel pod must exist');
  // Ningún pod está aprovisionado todavía, y el estado debe decirlo. Antes se
  // afirmaba 'running' para dos objetos sin contenedor detrás.
  assert.strictEqual(podsData.pods.forge.provisioned, false);
  assert.strictEqual(podsData.pods.citadel.provisioned, false);
  assert.strictEqual(podsData.pods.citadel.status, 'not_provisioned');

  // Las métricas que no se pueden medir son null, nunca un número inventado.
  assert.strictEqual(podsData.pods.citadel.cpuPercent, null, 'Sin contenedor no hay CPU que medir');
  assert.strictEqual(podsData.pods.citadel.memoryMb, null, 'Sin contenedor no hay memoria que medir');

  // Las del daemon sí se miden, porque el daemon sí existe.
  assert.ok(podsData.daemon, 'Deben publicarse las métricas del daemon');
  assert.strictEqual(podsData.daemon.measured, true);
  assert.ok(podsData.daemon.memoryMb > 0, 'La memoria residente del daemon es medible');
  assert.ok(podsData.daemon.uptimeSeconds >= 0);

  // Los contadores arrancan a cero en vez de fingir 1.248.920 peticiones.
  assert.strictEqual(typeof podsData.totalRequestsServed, 'number');
  assert.ok(podsData.totalRequestsServed < 1000, 'El contador es real, no una constante de escaparate');
  console.log(`  ✓ Pods sin aprovisionar declarados como tales; daemon medido (${podsData.daemon.memoryMb} MB RSS)`);

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

  // 3. Traffic switching between Forge & Citadel (+ negative input rejection)
  const switchRes = await containerOrchestrator.switchTraffic({ forgePercent: 30, citadelPercent: 70 });
  assert.strictEqual(switchRes.success, true);
  assert.strictEqual(switchRes.trafficAllocation.forge, 30);
  assert.strictEqual(switchRes.trafficAllocation.citadel, 70);
  await assert.rejects(
    () => containerOrchestrator.switchTraffic({}),
    /forgePercent|citadelPercent|0 y 100/i,
    'switchTraffic sin porcentajes debe rechazarse'
  );
  await assert.rejects(
    () => containerOrchestrator.switchTraffic({ forgePercent: 'not-a-number' }),
    /número|válido|0 y 100/i,
    'switchTraffic con NaN debe rechazarse'
  );
  assert.deepStrictEqual(containerOrchestrator.trafficAllocation, { forge: 30, citadel: 70 }, 'Un fallo en switchTraffic no debe mutar la asignación');
  console.log('  ✓ Traffic routing switch passed (30% Forge / 70% Citadel + NaN/empty rejected)');

  // 4. Legacy deployRelease() ya no simula despliegues falsos con setTimeout:
  //    los despliegues reales viven en deployManager.
  const deployRes = await containerOrchestrator.deployRelease({
    imageTag: 'v1.0.2',
    gitCommit: 'c0ffe31',
    description: 'Automated test release'
  });
  assert.strictEqual(deployRes.success, false, 'deployRelease legado no debe fingir un despliegue');
  assert.strictEqual(deployRes.delegatedTo, 'deployManager');
  console.log('  ✓ Legacy deployRelease() rechazado honestamente (delegado en deployManager)');

  // 5. Logs streaming & retrieval
  const logs = containerOrchestrator.getLogs({ limit: 10 });
  assert.ok(Array.isArray(logs));
  assert.ok(logs.length > 0);
  assert.ok(logs[0].message);
  console.log(`  ✓ Logs buffer passed (${logs.length} logs sampled)`);

  // 6. Real Chokidar file watcher on disk (with genuine event assertion — never a blind sleep)
  const fs = require('fs');
  const path = require('path');
  const os = require('os');
  assert.throws(() => containerOrchestrator.watchDirectory(''), /required/i);
  assert.throws(() => containerOrchestrator.watchDirectory(path.join(os.tmpdir(), `culkibo-missing-${Date.now()}`)), /does not exist/i);

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-watch-'));
  try {
    const watchRes = containerOrchestrator.watchDirectory(tempDir);
    assert.strictEqual(watchRes.success, true);
    assert.strictEqual(containerOrchestrator.getWatcherStatus().isWatching, true);

    // Wait for chokidar 'ready' before writing, so initial scan doesn't swallow the add event
    const activeWatcher = containerOrchestrator.watchers.get(path.resolve(tempDir));
    assert.ok(activeWatcher, 'Active chokidar watcher instance must be registered');
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('Chokidar watcher did not emit ready within 5s')), 5000);
      activeWatcher.once('ready', () => { clearTimeout(t); resolve(undefined); });
    });
    console.log('  ✓ Chokidar live directory watcher initialized & ready');

    // Register real event listener BEFORE writing file and assert the HOT_SYNC log actually fires
    const reloadsBefore = containerOrchestrator.pods.forge.hotReloadsCount;
    const detectedPromise = new Promise((resolve, reject) => {
      const timeoutMs = process.platform === 'win32' ? 6000 : 3000;
      const timer = setTimeout(() => {
        containerOrchestrator.off('log', onLog);
        reject(new Error(`Chokidar did not emit HOT_SYNC log for test-component.ts within ${timeoutMs}ms`));
      }, timeoutMs);
      const onLog = (entry) => {
        if (entry && entry.level === 'HOT_SYNC' && String(entry.message || '').includes('test-component.ts')) {
          clearTimeout(timer);
          containerOrchestrator.off('log', onLog);
          resolve(entry);
        }
      };
      containerOrchestrator.on('log', onLog);
    });

    const testFile = path.join(tempDir, 'test-component.ts');
    fs.writeFileSync(testFile, 'export const test = 1;', 'utf8');

    const detectedEntry = await detectedPromise;
    assert.ok(detectedEntry.message.includes('test-component.ts'), 'HOT_SYNC log must identify changed file');
    assert.ok(
      containerOrchestrator.pods.forge.hotReloadsCount > reloadsBefore,
      'hotReloadsCount must increment on real chokidar detection'
    );

    await containerOrchestrator.stopWatching();
    assert.strictEqual(containerOrchestrator.getWatcherStatus().isWatching, false);
    console.log('  ✓ Chokidar file watcher genuinely detected test-component.ts (HOT_SYNC asserted) & stopped cleanly');
  } finally {
    await containerOrchestrator.stopWatching().catch(() => {});
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
