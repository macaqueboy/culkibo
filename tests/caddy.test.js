const assert = require('assert');
const caddyManager = require('../server/services/caddyManager');

/**
 * Pruebas del plano de datos contra un Caddy REAL.
 *
 * Si no hay ninguna API de administración escuchando, la suite se salta sola en
 * vez de fallar: no todo el mundo tiene Caddy levantado, y una prueba que exige
 * un servicio externo para pasar acaba desactivándose. Para ejecutarla de
 * verdad basta con `caddy run` en otra terminal.
 */
async function testCaddy() {
  console.log('🧪 Probando el plano de datos (Caddy admin API)...');

  const detection = await caddyManager.detect({ force: true });
  if (!detection.available) {
    console.log(`  ⏭  Omitida: ${detection.reason}`);
    console.log('     Para ejecutarla: arranca `caddy run` y repite.\n');
    return;
  }
  console.log(`  ✓ Caddy detectado en ${detection.adminUrl}`);

  // ----------------------------------------------------------------
  // 1. Configuración base con TLS bajo demanda
  // ----------------------------------------------------------------
  await caddyManager.loadBaseConfig({ askEndpoint: 'http://localhost:3030/api/ingress/ask' });

  const tls = await caddyManager.get('/config/apps/tls/automation/on_demand');
  assert.ok(tls, 'Debe existir la política de TLS bajo demanda');
  assert.strictEqual(tls.permission.module, 'http', 'Debe usar el módulo permission, no el `ask` deprecado');
  assert.ok(tls.permission.endpoint.endsWith('/api/ingress/ask'));

  const server = await caddyManager.get('/config/apps/http/servers/culkibo');
  assert.ok(Array.isArray(server.routes), 'El servidor debe arrancar con un array de rutas');

  console.log('  ✓ Configuración base aceptada por Caddy (TLS bajo demanda + permission http)');

  // ----------------------------------------------------------------
  // 2. Alta de ruta
  // ----------------------------------------------------------------
  const first = await caddyManager.upsertRoute({
    projectId: 'test_alpha',
    hostnames: ['alpha.culkibo.test'],
    upstreams: ['127.0.0.1:9101']
  });
  assert.strictEqual(first.created, true);

  const stored = await caddyManager.getRoute('test_alpha');
  assert.ok(stored, 'La ruta debe ser recuperable por su @id');
  assert.deepStrictEqual(stored.match[0].host, ['alpha.culkibo.test']);
  assert.strictEqual(stored.handle[0].handler, 'reverse_proxy');
  assert.strictEqual(stored.handle[0].upstreams[0].dial, '127.0.0.1:9101');
  assert.strictEqual(stored.terminal, true, 'Una ruta no puede recibir tráfico de otro proyecto');
  console.log('  ✓ Ruta creada y direccionable por @id');

  // ----------------------------------------------------------------
  // 3. Actualización en el sitio (no duplica)
  // ----------------------------------------------------------------
  const second = await caddyManager.upsertRoute({
    projectId: 'test_alpha',
    hostnames: ['alpha.culkibo.test', 'www.alpha.culkibo.test'],
    upstreams: ['127.0.0.1:9102']
  });
  assert.strictEqual(second.created, false, 'La segunda escritura actualiza, no crea');

  const updated = await caddyManager.getRoute('test_alpha');
  assert.strictEqual(updated.handle[0].upstreams[0].dial, '127.0.0.1:9102');
  assert.strictEqual(updated.match[0].host.length, 2);
  assert.strictEqual((await caddyManager.listRoutes()).length, 1, 'No debe haber duplicados');
  console.log('  ✓ Actualización atómica en el sitio, sin duplicar');

  // ----------------------------------------------------------------
  // 4. Canario real: reparto por peso ejecutado por el proxy
  // ----------------------------------------------------------------
  await caddyManager.upsertRoute({
    projectId: 'test_canary',
    hostnames: ['canary.culkibo.test'],
    upstreams: ['127.0.0.1:3001', '127.0.0.1:8080'],
    weights: [10, 90]
  });
  const canary = await caddyManager.getRoute('test_canary');
  assert.strictEqual(canary.handle[0].load_balancing.selection_policy.policy, 'weighted_round_robin');
  assert.deepStrictEqual(canary.handle[0].load_balancing.selection_policy.weights, [10, 90]);
  console.log('  ✓ Canario 10/90 aplicado por el proxy (sustituye al Math.random() de Express)');

  // ----------------------------------------------------------------
  // 5. Rollback automático ante configuración inválida
  // ----------------------------------------------------------------
  const before = await caddyManager.get('/config/apps/http/servers/culkibo/routes');
  let rejected = false;
  try {
    await caddyManager.write('POST', '/config/apps/http/servers/culkibo/routes', {
      '@id': 'culkibo_invalido',
      handle: [{ handler: 'este_handler_no_existe' }]
    });
  } catch (e) {
    rejected = true;
  }
  assert.strictEqual(rejected, true, 'Caddy debe rechazar una configuración inválida');
  const after = await caddyManager.get('/config/apps/http/servers/culkibo/routes');
  assert.strictEqual(after.length, before.length, 'Tras el rechazo la configuración queda intacta');
  console.log('  ✓ Configuración inválida rechazada y revertida sin downtime');

  // ----------------------------------------------------------------
  // 6. Reconciliación: el estado real converge al deseado
  // ----------------------------------------------------------------
  const result = await caddyManager.reconcile([
    { projectId: 'test_alpha', hostnames: ['alpha.culkibo.test'], upstreams: ['127.0.0.1:9103'] },
    { projectId: 'test_gamma', hostnames: ['gamma.culkibo.test'], upstreams: ['127.0.0.1:9104'] }
  ]);
  assert.strictEqual(result.applied.length, 2);
  assert.ok(result.removed.includes('culkibo_test_canary'), 'La ruta sobrante debe eliminarse');

  const finalRoutes = await caddyManager.listRoutes();
  assert.strictEqual(finalRoutes.length, 2);
  console.log('  ✓ Reconciliación: converge al estado deseado y limpia lo sobrante');

  // ----------------------------------------------------------------
  // 7. Limpieza, idempotente
  // ----------------------------------------------------------------
  await caddyManager.removeRoute('test_alpha');
  await caddyManager.removeRoute('test_gamma');
  const repeated = await caddyManager.removeRoute('test_gamma');
  assert.strictEqual(repeated.removed, false, 'Borrar dos veces no debe fallar');
  assert.strictEqual((await caddyManager.listRoutes()).length, 0);
  console.log('  ✓ Borrado idempotente');

  console.log('✅ Plano de datos verificado contra Caddy real\n');
}

module.exports = testCaddy;

if (require.main === module) {
  testCaddy().catch(err => {
    console.error('❌ Fallo en las pruebas de Caddy:', err);
    process.exit(1);
  });
}
