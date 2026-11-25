/**
 * Banco de pruebas: cuánto tarda un cambio de ruta en estar SIRVIENDO.
 *
 * Por qué esta medida y no otra: es la que decide si una promoción es atómica.
 * Comparación honesta por mecanismo documentado del plano de datos:
 *
 *   Traefik · proveedor de fichero   : throttle por defecto de 2.000 ms (providersThrottleDuration)
 *   Traefik · proveedor HTTP         : poll por defecto de 5.000 ms     (pollInterval)
 *   Traefik · proveedor Docker       : dirigido por eventos Docker (sin poll HTTP)
 *   Kamal Proxy (`kamal-proxy`)      : swap imperativo en memoria (< 1 ms tras healthcheck)
 *   Culkibo · Caddy Admin API        : síncrono, atómico, sin poll (~5–50 ms medido)
 *
 * No medimos "lo que tarda la API en responder" —eso es trivial y engañoso—
 * sino el ciclo completo: pedir el cambio y comprobar, sondeando, en qué
 * momento el proxy empieza de verdad a servir el destino nuevo.
 *
 * LO QUE ESTA CIFRA NO ES: no es la latencia de un despliegue completo. No
 * incluye construir una imagen, arrancar un contenedor ni esperar un health
 * check. Mide exclusivamente el conmutador de ruta del ingress.
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
  return Number(sorted[Math.max(0, idx)].toFixed(2));
}

function startIdentityServer(port, identity) {
  return new Promise((resolve) => {
    const server = http.createServer((_req, res) => {
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

/**
 * @param {{ silent?: boolean, iterations?: number }} [opts]
 */
async function run({ silent = false, iterations = ITERATIONS } = {}) {
  const caddyHttpPort = parseInt(process.env.BENCH_CADDY_HTTP_PORT || '18080', 10);

  if (!silent) {
    console.log('\n════════════════════════════════════════════════════════════');
    console.log('  Culkibo · Banco de pruebas: conmutación de ruta');
    console.log('════════════════════════════════════════════════════════════\n');
  }

  const detection = await caddyManager.detect({ force: true });
  if (!detection.available) {
    if (!silent) {
      console.log(`  No hay Caddy escuchando: ${detection.reason}`);
      console.log('  Arranca uno y repite. Ejemplo:');
      console.log('    caddy run\n');
    }
    return {
      skipped: true,
      reason: detection.reason || 'Caddy no estaba escuchando en :2019'
    };
  }

  const serverA = await startIdentityServer(PORT_A, 'DESTINO_A');
  const serverB = await startIdentityServer(PORT_B, 'DESTINO_B');

  /** @type {number[]} */
  const samples = [];
  /** @type {number[]} */
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
      const reason = `El proxy no llegó a servir el destino inicial en :${caddyHttpPort}`;
      if (!silent) {
        console.log(`  ${reason}. Abortado.`);
        console.log(`  Comprueba que Caddy escucha en :${caddyHttpPort} (BENCH_CADDY_HTTP_PORT).\n`);
      }
      return { skipped: true, reason };
    }

    if (!silent) {
      console.log(`  Caddy en ${detection.adminUrl} · proxy en :${caddyHttpPort}`);
      console.log(`  Iteraciones: ${iterations} (se descarta la primera)\n`);
    }

    let current = 'A';
    for (let i = 0; i < iterations + 1; i++) {
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
        samples.push(elapsedMs);
      }
      current = next;
    }
  } finally {
    try { await caddyManager.removeRoute(PROJECT_ID); } catch (e) {}
    await new Promise((r) => serverA.close(r));
    await new Promise((r) => serverB.close(r));
  }

  const sorted = [...samples].sort((a, b) => a - b);
  const summary = {
    skipped: false,
    adminUrl: detection.adminUrl,
    httpPort: caddyHttpPort,
    iterations: sorted.length,
    failures: failures.length,
    minMs: percentile(sorted, 0),
    p50Ms: percentile(sorted, 50),
    p95Ms: percentile(sorted, 95),
    p99Ms: percentile(sorted, 99),
    maxMs: percentile(sorted, 100),
    competitorReference: {
      traefikFileProviderDefaultThrottleMs: 2000,
      traefikHttpProviderDefaultPollMs: 5000,
      traefikDockerProviderNote: 'Event-driven via Docker daemon stream (no HTTP poll)',
      kamalProxySwapNote: 'Imperative in-memory swap (<1ms post-healthcheck)',
      scopeNote: 'Measures route-switch latency only — excludes build, container start, and healthcheck'
    }
  };

  if (!silent) {
    const fmt = (v) => (v == null ? 'n/d' : `${v.toFixed(1)} ms`);
    console.log('  ─────────────────────────────────────────────────────────');
    console.log('   Petición de cambio → el proxy sirve el destino nuevo');
    console.log('  ─────────────────────────────────────────────────────────');
    console.log(`   muestras válidas   ${summary.iterations}`);
    console.log(`   fallos             ${summary.failures}`);
    console.log(`   mínimo             ${fmt(summary.minMs)}`);
    console.log(`   p50                ${fmt(summary.p50Ms)}`);
    console.log(`   p95                ${fmt(summary.p95Ms)}`);
    console.log(`   p99                ${fmt(summary.p99Ms)}`);
    console.log(`   máximo             ${fmt(summary.maxMs)}`);
    console.log('  ─────────────────────────────────────────────────────────\n');

    if (summary.p50Ms != null) {
      console.log('   Referencia del sector, por mecanismo documentado:');
      console.log('     Traefik · proveedor de fichero   throttle por defecto 2.000 ms');
      console.log('     Traefik · proveedor HTTP         poll por defecto 5.000 ms');
      console.log('     Traefik · proveedor Docker       dirigido por eventos (sin poll)');
      console.log('     Kamal Proxy (kamal-proxy)        swap imperativo (< 1 ms tras healthcheck)');
      console.log(`     Culkibo · Caddy Admin API        ${fmt(summary.p50Ms)} medido (p50)\n`);
      console.log('   Nota honesta: esto mide SOLO el conmutador de ruta.');
      console.log('   No incluye construir la imagen, arrancar el contenedor ni');
      console.log('   esperar al health check.\n');
    }

    console.log(`   Entorno: Node ${process.version} · ${process.platform} ${process.arch}`);
    console.log(`   Fecha:   ${new Date().toISOString()}\n`);
  }

  return summary;
}

if (require.main === module) {
  const asJson = process.argv.includes('--json');
  run({ silent: asJson }).then((res) => {
    if (asJson) process.stdout.write(JSON.stringify(res, null, 2) + '\n');
    process.exit(0);
  }).catch((err) => {
    console.error('Fallo del banco de pruebas:', err.message);
    process.exit(1);
  });
}

module.exports = run;
