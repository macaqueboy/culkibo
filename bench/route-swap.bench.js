/**
 * Banco de pruebas: cuánto tarda un cambio de ruta en estar SIRVIENDO.
 *
 * Por qué esta medida y no otra: es la que decide si una promoción es atómica.
 * Y es directamente comparable, porque los competidores publican su mecanismo
 * aunque no publiquen su número:
 *
 *   Traefik, proveedor de fichero : throttle de 2 s  (providersThrottleDuration)
 *   Traefik, proveedor HTTP       : poll de 5 s      (pollInterval)
 *   Caddy, admin API              : síncrono, sin poll
 *
 * No medimos "lo que tarda la API en responder" —eso es trivial y engañoso—
 * sino el ciclo completo: pedir el cambio y comprobar, sondeando, en qué
 * momento el proxy empieza de verdad a servir el destino nuevo.
 *
 * METODOLOGÍA (publicada a propósito, para que cualquiera pueda rebatirla):
 *   1. Se levantan dos servidores HTTP locales que se identifican, A y B.
 *   2. Se crea una ruta en Caddy apuntando a A y se espera a que sirva A.
 *   3. Se cronometra: se pide el cambio a B y se sondea sin pausa hasta que la
 *      respuesta venga de B.
 *   4. Se repite N veces alternando destino, descartando el primer ciclo
 *      (calentamiento de conexiones).
 *   5. Se publican p50, p95, p99, mínimo y máximo. También los fallos.
 *
 * LO QUE ESTA CIFRA NO ES: no es la latencia de un despliegue. No incluye
 * construir una imagen, ni arrancar un contenedor, ni esperar a un health
 * check. Mide exclusivamente el conmutador. Cualquier comparación que lo
 * presente como "tiempo de despliegue" es deshonesta.
 */

const http = require('http');
const caddyManager = require('../server/services/caddyManager');

const ITERATIONS = parseInt(process.env.BENCH_ITERATIONS || '30', 10);
const PORT_A = 19801;
const PORT_B = 19802;
const TEST_HOST = 'bench.culkibo.test';
const PROJECT_ID = 'bench_route_swap';

function percentile(sorted, p) {
  if (sorted.length === 0) return null;
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, idx)];
}

function startIdentityServer(port, identity) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain', Connection: 'close' });
      res.end(identity);
    });
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

/** Una petición al proxy, devolviendo qué destino respondió. */
function askProxy(caddyHttpPort) {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: caddyHttpPort,
        path: '/',
        headers: { Host: TEST_HOST, Connection: 'close' },
        timeout: 2000
      },
      (res) => {
        let body = '';
        res.on('data', (c) => { body += c; });
        res.on('end', () => resolve(body.trim()));
      }
    );
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}

async function waitUntilServing(caddyHttpPort, expected, budgetMs = 15000) {
  const deadline = Date.now() + budgetMs;
  while (Date.now() < deadline) {
    if ((await askProxy(caddyHttpPort)) === expected) return true;
  }
  return false;
}

async function run() {
  const caddyHttpPort = parseInt(process.env.BENCH_CADDY_HTTP_PORT || '18080', 10);

  console.log('\n════════════════════════════════════════════════════════════');
  console.log('  Culkibo · Banco de pruebas: conmutación de ruta');
  console.log('════════════════════════════════════════════════════════════\n');

  const detection = await caddyManager.detect({ force: true });
  if (!detection.available) {
    console.log(`  No hay Caddy escuchando: ${detection.reason}`);
    console.log('  Arranca uno y repite. Ejemplo:');
    console.log(`    caddy run\n`);
    process.exit(0);
  }

  const serverA = await startIdentityServer(PORT_A, 'DESTINO_A');
  const serverB = await startIdentityServer(PORT_B, 'DESTINO_B');

  const samples = [];
  const failures = [];

  try {
    await caddyManager.loadBaseConfig({
      askEndpoint: 'http://127.0.0.1:3030/api/ingress/ask',
      httpPort: caddyHttpPort,
      httpsPort: caddyHttpPort + 1,
      automaticHttps: false
    });

    const pointTo = (port) => caddyManager.upsertRoute({
      projectId: PROJECT_ID,
      hostnames: [TEST_HOST],
      upstreams: [`127.0.0.1:${port}`]
    });

    await pointTo(PORT_A);
    if (!(await waitUntilServing(caddyHttpPort, 'DESTINO_A'))) {
      console.log('  El proxy no llegó a servir el destino inicial. Abortado.');
      console.log(`  Comprueba que Caddy escucha en :${caddyHttpPort} (BENCH_CADDY_HTTP_PORT).\n`);
      return;
    }

    console.log(`  Caddy en ${detection.adminUrl} · proxy en :${caddyHttpPort}`);
    console.log(`  Iteraciones: ${ITERATIONS} (se descarta la primera)\n`);

    let current = 'A';
    for (let i = 0; i < ITERATIONS + 1; i++) {
      const next = current === 'A' ? 'B' : 'A';
      const nextPort = next === 'A' ? PORT_A : PORT_B;
      const expected = `DESTINO_${next}`;

      const started = process.hrtime.bigint();
      await pointTo(nextPort);
      const served = await waitUntilServing(caddyHttpPort, expected, 10000);
      const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

      if (!served) {
        failures.push(i);
      } else if (i > 0) {
        // El primer ciclo calienta conexiones y no representa el estado estable.
        samples.push(elapsedMs);
      }
      current = next;
    }
  } finally {
    try { await caddyManager.removeRoute(PROJECT_ID); } catch (e) {}
    await new Promise(r => serverA.close(r));
    await new Promise(r => serverB.close(r));
  }

  const sorted = [...samples].sort((a, b) => a - b);
  const fmt = (v) => (v == null ? 'n/d' : `${v.toFixed(1)} ms`);

  console.log('  ─────────────────────────────────────────────────────────');
  console.log('   Petición de cambio → el proxy sirve el destino nuevo');
  console.log('  ─────────────────────────────────────────────────────────');
  console.log(`   muestras válidas   ${sorted.length}`);
  console.log(`   fallos             ${failures.length}`);
  console.log(`   mínimo             ${fmt(sorted[0])}`);
  console.log(`   p50                ${fmt(percentile(sorted, 50))}`);
  console.log(`   p95                ${fmt(percentile(sorted, 95))}`);
  console.log(`   p99                ${fmt(percentile(sorted, 99))}`);
  console.log(`   máximo             ${fmt(sorted[sorted.length - 1])}`);
  console.log('  ─────────────────────────────────────────────────────────\n');

  const p50 = percentile(sorted, 50);
  if (p50 != null) {
    console.log('   Referencia del sector, por mecanismo documentado:');
    console.log('     Traefik · proveedor de fichero   throttle de 2.000 ms');
    console.log('     Traefik · proveedor HTTP         poll de 5.000 ms');
    console.log(`     Culkibo · Caddy admin API        ${fmt(p50)} medido (p50)\n`);
    console.log('   Nota honesta: esto mide SOLO el conmutador de ruta.');
    console.log('   No incluye construir la imagen, arrancar el contenedor ni');
    console.log('   esperar al health check. Presentarlo como "tiempo de');
    console.log('   despliegue" sería mentir.\n');
  }

  console.log(`   Entorno: Node ${process.version} · ${process.platform} ${process.arch}`);
  console.log(`   Fecha:   ${new Date().toISOString()}\n`);

  return { samples: sorted, failures: failures.length };
}

if (require.main === module) {
  run().then(() => process.exit(0)).catch((err) => {
    console.error('Fallo del banco de pruebas:', err.message);
    process.exit(1);
  });
}

module.exports = run;
