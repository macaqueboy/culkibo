const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 3030; // Need to verify actual port, assuming 3030
const BASE_URL = `http://127.0.0.1:${PORT}`;

const agent = new http.Agent({ keepAlive: true, maxSockets: 25 });

async function fetchWithTiming(path, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const start = performance.now();
    
    const payloadBuf = body ? Buffer.from(JSON.stringify(body), 'utf8') : null;
    const headers = {
      'Content-Type': 'application/json',
      ...(payloadBuf ? { 'Content-Length': payloadBuf.length } : {})
    };
    const options = {
      hostname: '127.0.0.1',
      port: PORT,
      path: new URL(path, BASE_URL).pathname,
      method: method,
      agent: agent,
      headers
    };
    
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          data,
          latency: Number((performance.now() - start).toFixed(2))
        });
      });
    });
    
    req.on('error', (err) => {
      resolve({
        status: 500,
        data: err.message,
        latency: Number((performance.now() - start).toFixed(2))
      });
    });
    
    if (payloadBuf) req.end(payloadBuf);
    else req.end();
  });
}

async function runStressTest() {
  // Reutiliza el daemon si ya está activo; si no, levanta uno para la prueba.
  // Nota: los `process.exit()` del final lo cierran igualmente.
  const { ensureDaemon } = require('./helpers/daemon');
  const stopDaemon = await ensureDaemon({ quiet: true });

  // Barrido PREVIO, no solo posterior.
  //
  // Esta prueba crea 25 proyectos y los borra al terminar, pero la latencia se
  // mide antes de ese borrado, así que cualquier residuo de una ejecución que
  // muriera a medias contamina la medición siguiente. Y se acumula: se llegaron
  // a juntar 81 proyectos de prueba, y la latencia media subió de 55 ms a 137 ms
  // sin que cambiara una línea de código. Un banco de pruebas que se degrada
  // solo no mide nada.
  const sweep = async () => {
    const res = await fetchWithTiming(`${BASE_URL}/api/projects`);
    let all = [];
    try { all = JSON.parse(res.data); } catch (e) { return 0; }
    if (!Array.isArray(all)) return 0;
    const leftovers = all.filter(p => typeof p.name === 'string' && p.name.startsWith('stress-test'));
    for (const p of leftovers) {
      try { await fetchWithTiming(`${BASE_URL}/api/projects/${p.id}`, 'DELETE'); } catch (e) {}
    }
    return leftovers.length;
  };

  const swept = await sweep();
  if (swept > 0) console.log(`Limpiados ${swept} proyectos residuales de ejecuciones anteriores`);

  console.log('Warming up connections...');
  await Promise.all([
    ...Array.from({ length: 22 }, () => fetchWithTiming(`${BASE_URL}/api/health`)),
    fetchWithTiming(`${BASE_URL}/api/system/status`),
    fetchWithTiming(`${BASE_URL}/api/projects`),
    fetchWithTiming(`${BASE_URL}/api/domains`)
  ]);
  
  console.log('Starting stress test (100 concurrent mixed read/write requests across 25 keep-alive workers)...');
  
  const tasks = [];
  for (let i = 0; i < 25; i++) {
    tasks.push(() => fetchWithTiming(`${BASE_URL}/api/projects`));
    tasks.push(() => fetchWithTiming(`${BASE_URL}/api/domains`));
    tasks.push(() => fetchWithTiming(`${BASE_URL}/api/system/status`));
    tasks.push(() => fetchWithTiming(`${BASE_URL}/api/projects`, 'POST', {
      name: `stress-test-proj-${Date.now()}-${i}`,
      type: 'node',
      repoUrl: 'https://github.com/example/repo'
    }));
  }

  // Pool fijo de 25 workers sobre conexiones keep-alive (mide latencia HTTP real sin inflar por cola de sockets del cliente)
  const WORKERS = 25;
  /** @type {Array<{ status: 'fulfilled', value: any } | { status: 'rejected', reason: any }>} */
  const results = new Array(tasks.length);
  let cursor = 0;
  await Promise.all(Array.from({ length: WORKERS }, async () => {
    while (true) {
      const idx = cursor++;
      if (idx >= tasks.length) break;
      try {
        results[idx] = { status: 'fulfilled', value: await tasks[idx]() };
      } catch (reason) {
        results[idx] = { status: 'rejected', reason };
      }
    }
  }));
  
  let successCount = 0;
  let failCount = 0;
  let totalLatency = 0;
  let maxLatency = 0;
  /** @type {number[]} */
  const latencies = [];
  
  results.forEach((result, index) => {
    if (result.status === 'fulfilled' && result.value.status >= 200 && result.value.status < 400) {
      successCount++;
      totalLatency += result.value.latency;
      latencies.push(result.value.latency);
      if (result.value.latency > maxLatency) maxLatency = result.value.latency;
    } else {
      failCount++;
      console.error(`Request ${index} failed:`, result.reason || result.value);
    }
  });

  latencies.sort((a, b) => a - b);
  const pct = (p) => latencies.length
    ? latencies[Math.min(latencies.length - 1, Math.max(0, Math.ceil((p / 100) * latencies.length) - 1))]
    : 0;

  const avgLatency = successCount > 0 ? totalLatency / successCount : 0;
  const p50Latency = pct(50);
  const p95Latency = pct(95);
  const p99Latency = pct(99);
  
  console.log('--- Results (unadjusted raw wall-clock latency) ---');
  console.log(`Total Requests: ${tasks.length}`);
  console.log(`Success: ${successCount}`);
  console.log(`Failed: ${failCount}`);
  console.log(`Avg Latency: ${avgLatency.toFixed(2)}ms`);
  console.log(`p50 Latency: ${p50Latency.toFixed(2)}ms`);
  console.log(`p95 Latency: ${p95Latency.toFixed(2)}ms`);
  console.log(`p99 Latency: ${p99Latency.toFixed(2)}ms`);
  console.log(`Max Latency: ${maxLatency.toFixed(2)}ms`);

  // Cleanup created stress test projects via API
  for (const result of results) {
    if (result.status === 'fulfilled' && result.value.data) {
      try {
        const parsed = JSON.parse(result.value.data);
        if (parsed && parsed.id && parsed.name && parsed.name.startsWith('stress-test')) {
          await fetchWithTiming(`${BASE_URL}/api/projects/${parsed.id}`, 'DELETE');
        }
      } catch (e) {}
    }
  }

  agent.destroy();

  if (stopDaemon) {
    try { await stopDaemon(); } catch (e) {}
  }

  const maxAvgMs = process.platform === 'win32' ? 250 : 200;
  const maxP95Ms = process.platform === 'win32' ? 600 : 400;

  if (failCount > 0) {
    throw new Error(`Stress test failed: ${failCount} requests failed`);
  }
  if (avgLatency > maxAvgMs) {
    throw new Error(`Stress test failed: avg latency ${avgLatency.toFixed(2)}ms exceeds ${maxAvgMs}ms`);
  }
  if (p95Latency > maxP95Ms) {
    throw new Error(`Stress test failed: p95 latency ${p95Latency.toFixed(2)}ms exceeds ${maxP95Ms}ms`);
  }
  console.log(`✅ Passed: 0 failures, avg ${avgLatency.toFixed(2)}ms (<=${maxAvgMs}ms), p95 ${p95Latency.toFixed(2)}ms (<=${maxP95Ms}ms), p99 ${p99Latency.toFixed(2)}ms.`);
}

module.exports = runStressTest;

if (require.main === module) {
  runStressTest()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌', err && err.message ? err.message : err);
      process.exit(1);
    });
}
