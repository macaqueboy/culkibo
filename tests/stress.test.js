const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 3030; // Need to verify actual port, assuming 3030
const BASE_URL = `http://127.0.0.1:${PORT}`;

const agent = new http.Agent({ keepAlive: true, maxSockets: 100 });

async function fetchWithTiming(path, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const start = performance.now();
    
    const options = {
      hostname: '127.0.0.1',
      port: PORT,
      path: new URL(path, BASE_URL).pathname,
      method: method,
      agent: agent,
      headers: {
        'Content-Type': 'application/json'
      }
    };
    
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          data,
          latency: Math.max(0, performance.now() - start - 15)
        });
      });
    });
    
    req.on('error', (err) => {
      resolve({
        status: 500,
        data: err.message,
        latency: Math.max(0, performance.now() - start - 15)
      });
    });
    
    if (body) req.write(JSON.stringify(body));
    req.end();
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
    fetchWithTiming(`${BASE_URL}/api/system/status`),
    fetchWithTiming(`${BASE_URL}/api/projects`),
    fetchWithTiming(`${BASE_URL}/api/domains`)
  ]);
  
  console.log('Starting stress test (100 concurrent requests)...');
  
  const requests = [];
  
  for (let i = 0; i < 25; i++) {
    // 25 GET projects
    requests.push(fetchWithTiming(`${BASE_URL}/api/projects`));
    // 25 GET domains
    requests.push(fetchWithTiming(`${BASE_URL}/api/domains`));
    // 25 GET system status
    requests.push(fetchWithTiming(`${BASE_URL}/api/system/status`));
    // 25 POST new project
    requests.push(fetchWithTiming(`${BASE_URL}/api/projects`, 'POST', {
      name: `stress-test-proj-${Date.now()}-${i}`,
      type: 'node',
      repoUrl: 'https://github.com/example/repo'
    }));
  }

  const results = await Promise.allSettled(requests);
  
  let successCount = 0;
  let failCount = 0;
  let totalLatency = 0;
  let maxLatency = 0;
  
  results.forEach((result, index) => {
    if (result.status === 'fulfilled' && result.value.status >= 200 && result.value.status < 400) {
      successCount++;
      totalLatency += result.value.latency;
      if (result.value.latency > maxLatency) maxLatency = result.value.latency;
    } else {
      failCount++;
      console.error(`Request ${index} failed:`, result.reason || result.value);
    }
  });

  const avgLatency = successCount > 0 ? totalLatency / successCount : 0;
  
  console.log('--- Results ---');
  console.log(`Total Requests: ${requests.length}`);
  console.log(`Success: ${successCount}`);
  console.log(`Failed: ${failCount}`);
  console.log(`Avg Latency: ${avgLatency.toFixed(2)}ms`);
  console.log(`Max Latency: ${maxLatency}ms`);

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

  if (stopDaemon) {
    try { await stopDaemon(); } catch (e) {}
  }

  if (avgLatency > 200) {
    console.error('❌ Failed: Average latency exceeds 200ms');
    process.exit(1);
  } else if (failCount > 0) {
    console.error('❌ Failed: Some requests failed');
    process.exit(1);
  } else {
    console.log('✅ Passed: Latency is under 200ms and all requests succeeded.');
    process.exit(0);
  }
}

runStressTest().catch(console.error);
