const assert = require('assert');
const http = require('http');
const { app, server } = require('../server/index');
const containerOrchestrator = require('../server/services/containerOrchestrator');
const githubService = require('../server/services/githubService');

async function testLiveServer() {
  console.log('🧪 Testing Live Server, Control Plane & Honest Ingress Status...');
  const originalGhConfig = { ...githubService.config };

  await new Promise((resolve) => {
    server.listen(3031, () => {
      resolve();
    });
  });

  try {
    // 1. Fetch system status
    const statusRes = await fetch('http://localhost:3031/api/system/status');
    const statusData = await statusRes.json();
    assert.strictEqual(statusData.version, '1.0.0');
    assert.strictEqual(statusData.name, 'Culkibo');
    console.log('  ✓ API /api/system/status responding with v1.0.0');

    // 2. Fetch root / (Dashboard HTML on direct access)
    const indexRes = await fetch('http://localhost:3031/');
    const htmlText = await indexRes.text();
    assert.ok(htmlText.includes('Culkibo'), 'Must serve built Vite index.html');
    assert.ok(htmlText.includes('assets/index-'), 'Must reference built bundle assets');
    console.log('  ✓ Web Dashboard HTML served from web/dist for management origin');

    // ----------------------------------------------------------------------
    // 3 y 4. El daemon ya NO es el plano de datos.
    //
    // Estas dos comprobaciones verificaban que un Host de un dominio
    // configurado recibía una página HTML describiendo a qué pod se habría
    // enrutado, con una cabecera `X-Culkibo-Latency: 24ms` escrita a mano. No
    // se enrutaba nada: la petición moría en Express. Ahora el proxy inverso es
    // Caddy, y lo que se fija aquí es lo contrario: que el daemon lo diga en
    // vez de fingir. 421 Misdirected Request es literalmente ese caso — el
    // servidor no puede producir una respuesta para la autoridad solicitada.
    // ----------------------------------------------------------------------
    const ingressRes = await fetch('http://localhost:3031/', {
      headers: {
        'x-forwarded-host': 'culkibo.dev',
        'Accept': 'application/json'
      }
    });
    assert.strictEqual(ingressRes.status, 421, 'Un dominio de ingress contra el plano de control debe recibir 421');
    const ingressData = await ingressRes.json();
    assert.strictEqual(ingressData.domain, 'culkibo.dev');
    assert.strictEqual(ingressData.dataPlane, 'caddy');
    assert.strictEqual(ingressData.routedByDaemon, false, 'El daemon no puede afirmar que enruta');
    assert.strictEqual(ingressRes.headers.get('x-culkibo-ingress'), null, 'La cabecera del enrutador falso debe haber desaparecido');
    assert.strictEqual(ingressRes.headers.get('x-culkibo-latency'), null, 'La latencia inventada debe haber desaparecido');
    assert.ok(!('latencyMs' in ingressData), 'La respuesta no puede inventar una latencia');
    console.log('  ✓ culkibo.dev contra el plano de control responde 421 y declara que el plano de datos es Caddy');

    // 4. Igual con un comodín: la regla casa, pero el daemon sigue sin enrutar.
    const wildcardRes = await fetch('http://localhost:3031/', {
      headers: { 'x-forwarded-host': 'preview.culkibo.dev' }
    });
    assert.strictEqual(wildcardRes.status, 421);
    assert.strictEqual(wildcardRes.headers.get('x-culkibo-data-plane'), 'caddy');
    assert.strictEqual(wildcardRes.headers.get('x-content-type-options'), 'nosniff');
    const wildcardText = await wildcardRes.text();
    assert.ok(wildcardText.includes('preview.culkibo.dev'), 'Debe decir qué dominio se pidió');
    assert.ok(wildcardText.includes('*.culkibo.dev'), 'Debe decir qué regla casó');
    assert.ok(!wildcardText.includes('<'), 'La respuesta es texto plano: sin HTML no hay reflejo del Host explotable');
    console.log('  ✓ El comodín preview.culkibo.dev también responde 421, en texto plano y sin reflejo de HTML');

    // 4b. Estado honesto del ingress: presencia real de Caddy, rutas vivas y
    // handshake TLS de verdad. Antes el panel leía `sslStatus: 'active'` de
    // nuestro propio JSON y una caducidad a 90 días inventada al "emitir".
    const ingStatusRes = await fetch('http://localhost:3031/api/ingress/status?timeout=2000');
    assert.strictEqual(ingStatusRes.status, 200);
    const ingStatus = await ingStatusRes.json();
    assert.strictEqual(ingStatus.dataPlane, 'caddy');
    assert.strictEqual(typeof ingStatus.available, 'boolean', 'Debe decir si hay Caddy de verdad, no suponerlo');
    assert.strictEqual(typeof ingStatus.routesManaged, 'number');
    assert.ok(Array.isArray(ingStatus.routes));
    assert.ok(ingStatus.drift && Array.isArray(ingStatus.drift.missing) && Array.isArray(ingStatus.drift.unexpected));
    assert.ok(Array.isArray(ingStatus.tls), 'Debe publicar el resultado de los sondeos TLS');
    assert.ok(ingStatus.message && ingStatus.message.length > 0, 'Debe explicarse en castellano');
    if (!ingStatus.available) {
      assert.ok(ingStatus.reason, 'Sin Caddy tiene que decir por qué');
      assert.ok(ingStatus.message.includes('no disponible'), 'Sin Caddy tiene que decirlo claramente');
    }
    for (const probe of ingStatus.tls) {
      assert.strictEqual(typeof probe.reachable, 'boolean');
      if (probe.reachable && probe.notAfter) {
        // Cuando hay handshake, la caducidad sale del certificado servido, no
        // de un `Date.now() + 90 días` escrito por nosotros.
        assert.ok(!Number.isNaN(Date.parse(probe.notAfter)));
        assert.strictEqual(typeof probe.trusted, 'boolean');
      } else {
        assert.ok(probe.error || probe.notAfter === null, 'Un sondeo fallido debe explicar el fallo, no inventar un certificado');
      }
    }
    console.log(`  ✓ /api/ingress/status honesto (Caddy: ${ingStatus.available ? 'presente' : 'ausente'}, ${ingStatus.routesManaged} ruta(s), ${ingStatus.tls.length} handshake(s) TLS reales)`);

    // 4c. El permiso de TLS bajo demanda sigue negando lo que no conocemos: es
    // lo que impide que un tercero apunte su dominio aquí y agote la cuota de
    // Let's Encrypt a nuestra costa.
    const askOk = await fetch('http://localhost:3031/api/ingress/ask?domain=culkibo.dev');
    assert.strictEqual(askOk.status, 200, 'Un dominio configurado debe autorizarse');
    const askKo = await fetch('http://localhost:3031/api/ingress/ask?domain=dominio-ajeno.example');
    assert.strictEqual(askKo.status, 403, 'Un dominio no configurado debe denegarse');
    console.log('  ✓ /api/ingress/ask autoriza lo configurado y deniega lo ajeno');

    // ----------------------------------------------------------------------
    // 4d. Camino completo: proyecto → dominio → ruta viva → parada → sin ruta.
    //
    // Es la comprobación que faltaba. Antes se verificaba que el middleware
    // falso DESCRIBÍA una ruta; aquí se verifica que arrancar un proyecto
    // publica de verdad un destino en Caddy hacia el puerto vivo del runner, y
    // que pararlo lo retira. Sin Caddy delante, lo que se fija es la
    // degradación: todo sigue funcionando y se dice que no hay ingress.
    // ----------------------------------------------------------------------
    const e2eHost = `e2e-${Date.now()}.culkibo.test`;
    const createRes = await fetch('http://localhost:3031/api/projects', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Proyecto de ingress E2E', description: 'Temporal para la suite de ingress' })
    });
    const e2eProject = await createRes.json();
    let e2eDomainId = null;

    try {
      const attachRes = await fetch(`http://localhost:3031/api/projects/${e2eProject.id}/domains`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname: e2eHost, autoCreateDns: false, cloudflareProxied: false })
      });
      assert.strictEqual(attachRes.status, 201, 'Vincular un dominio a un proyecto debe ser una sola llamada');
      const attached = await attachRes.json();
      e2eDomainId = attached.domain.id;
      assert.strictEqual(attached.domain.projectId, e2eProject.id, 'El registro del dominio debe guardar el proyecto');
      assert.ok(attached.project.domains.includes(e2eHost), 'El proyecto debe listar el dominio');

      const startRes = await fetch(`http://localhost:3031/api/projects/${e2eProject.id}/start-local`, { method: 'POST' });
      const started = await startRes.json();
      assert.strictEqual(started.localRunning, true, 'El proyecto debe arrancar aunque el ingress falle');
      assert.ok(started.ingress, 'Arrancar debe informar de lo que pasó con el ingress');

      if (started.ingress.available) {
        assert.strictEqual(started.ingress.applied, true);
        assert.deepStrictEqual(started.ingress.hostnames, [e2eHost]);
        assert.deepStrictEqual(started.ingress.upstreams, [`127.0.0.1:${started.localPort}`],
          'La ruta debe apuntar al puerto vivo del runner, no a un puerto inventado');

        const afterStart = await (await fetch('http://localhost:3031/api/ingress/status?probe=0')).json();
        assert.strictEqual(afterStart.routesError, null, 'Leer la configuración viva de Caddy no puede fallar');
        const published = afterStart.routes.find(r => r.hosts.includes(e2eHost));
        assert.ok(published, 'La ruta debe estar publicada en Caddy tras arrancar');
        assert.deepStrictEqual(published.upstreams, [`127.0.0.1:${started.localPort}`]);
        assert.ok(!afterStart.drift.missing.includes(started.ingress.routeId),
          'La ruta recién publicada no puede figurar como ausente');

        // La reconciliación es el mismo camino que usa el arranque del daemon
        // para que Caddy y Culkibo no puedan divergir tras un reinicio.
        const reconciled = await (await fetch('http://localhost:3031/api/ingress/reconcile', { method: 'POST' })).json();
        assert.strictEqual(reconciled.applied, true);
        const afterReconcile = await (await fetch('http://localhost:3031/api/ingress/status?probe=0')).json();
        assert.deepStrictEqual(afterReconcile.drift.missing, [], 'Tras reconciliar no puede faltar ninguna ruta');
        assert.deepStrictEqual(afterReconcile.drift.unexpected, [], 'Tras reconciliar no puede sobrar ninguna ruta');
        assert.strictEqual(afterReconcile.inSync, true);

        const stopped = await (await fetch(`http://localhost:3031/api/projects/${e2eProject.id}/stop`, { method: 'POST' })).json();
        assert.strictEqual(stopped.ingress.action, 'removed', 'Parar debe retirar la ruta');

        const afterStop = await (await fetch('http://localhost:3031/api/ingress/status?probe=0')).json();
        assert.ok(!afterStop.routes.some(r => r.hosts.includes(e2eHost)), 'Un proyecto parado no puede seguir enrutado');
        assert.ok(afterStop.skipped.some(s => s.hostnames.includes(e2eHost)),
          'El dominio sin destino debe aparecer explicado, no desaparecer en silencio');
        console.log(`  ✓ Ciclo completo: ${e2eHost} → 127.0.0.1:${started.localPort} al arrancar, sin ruta al parar`);
      } else {
        // Degradación camaleón: sin Caddy no hay ingress y se dice, pero el
        // proyecto arranca y para igual.
        assert.strictEqual(started.ingress.applied, false);
        assert.ok(started.ingress.message.includes('no disponible'));
        const stopped = await (await fetch(`http://localhost:3031/api/projects/${e2eProject.id}/stop`, { method: 'POST' })).json();
        assert.strictEqual(stopped.status, 'stopped', 'Sin ingress, parar sigue funcionando');
        console.log('  ✓ Sin Caddy: el ciclo de vida funciona igual y el ingress se declara no disponible');
      }
    } finally {
      await fetch(`http://localhost:3031/api/projects/${e2eProject.id}`, { method: 'DELETE' }).catch(() => {});
      if (e2eDomainId) {
        await fetch(`http://localhost:3031/api/domains/${e2eDomainId}`, { method: 'DELETE' }).catch(() => {});
      }
    }

    // 5. Fetch domains API & test PATCH update
    const domRes = await fetch('http://localhost:3031/api/domains');
    const domData = await domRes.json();
    assert.ok(domData.domains.length >= 2);
    const testDomId = domData.domains[0].id;

    // Toggle proxy via API
    const toggleRes = await fetch(`http://localhost:3031/api/domains/${testDomId}/toggle-proxy`, {
      method: 'POST'
    });
    const toggleData = await toggleRes.json();
    assert.strictEqual(toggleData.id, testDomId);
    console.log(`  ✓ API /api/domains/:id/toggle-proxy executed successfully (proxied: ${toggleData.cloudflareProxied})`);

    // 6. Fetch MCP tools API
    const mcpRes = await fetch('http://localhost:3031/api/mcp/tools');
    const mcpData = await mcpRes.json();
    assert.ok(mcpData.tools.length >= 7);
    console.log(`  ✓ API /api/mcp/tools responding (${mcpData.tools.length} AI tools)`);

    // 7. Live GitHub API endpoints
    const ghStatusRes = await fetch('http://localhost:3031/api/github/status');
    const ghStatusData = await ghStatusRes.json();
    assert.ok('connected' in ghStatusData);
    console.log('  ✓ API /api/github/status responding');

    const ghConnectRes = await fetch('http://localhost:3031/api/github/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'ghp_mock_live_test_token' })
    });
    const ghConnectData = await ghConnectRes.json();
    assert.strictEqual(ghConnectData.success, true);
    assert.strictEqual(ghConnectData.user.login, 'pablo-developer');
    console.log('  ✓ API /api/github/connect executed successfully');

    const ghReposRes = await fetch('http://localhost:3031/api/github/repos');
    const ghReposData = await ghReposRes.json();
    assert.ok(Array.isArray(ghReposData.repos));
    assert.ok(ghReposData.repos.length >= 3);
    console.log(`  ✓ API /api/github/repos responding with ${ghReposData.repos.length} repositories`);

    const ghDetectRes = await fetch('http://localhost:3031/api/github/auto-detect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ owner: 'pablo-developer', repo: 'culkibo-frontend', branch: 'main' })
    });
    const ghDetectData = await ghDetectRes.json();
    assert.strictEqual(ghDetectData.detected, true);
    assert.strictEqual(ghDetectData.framework, 'React (Vite)');
    console.log('  ✓ API /api/github/auto-detect responding with detected stack');

    // ----------------------------------------------------------------------
    // Control de acceso del plano de control.
    //
    // El daemon servía toda su API con cors('*') y sin credencial. El peligro
    // no era solo un VPS expuesto: cualquier web que el usuario visitase podía
    // pedirle cosas a localhost:3030 desde su propio navegador. Estas
    // aserciones fijan las dos capas —origen y token— para que no se pierdan.
    // ----------------------------------------------------------------------
    const { resolveToken } = require('../server/middleware/auth');
    const validToken = resolveToken();

    const evilRes = await fetch('http://localhost:3031/api/projects', {
      headers: { Origin: 'https://evil.example' }
    });
    assert.strictEqual(evilRes.status, 403, 'Un origen no autorizado debe recibir 403');

    const ownOriginRes = await fetch('http://localhost:3031/api/projects', {
      headers: { Origin: 'http://localhost:3030' }
    });
    assert.strictEqual(ownOriginRes.status, 200, 'El dashboard propio debe pasar');

    const badTokenRes = await fetch('http://localhost:3031/api/projects', {
      headers: { Authorization: 'Bearer token-que-no-vale' }
    });
    assert.strictEqual(badTokenRes.status, 401, 'Un token inválido debe recibir 401');

    const goodTokenRes = await fetch('http://localhost:3031/api/projects', {
      headers: { Authorization: `Bearer ${validToken}` }
    });
    assert.strictEqual(goodTokenRes.status, 200, 'Un token válido debe pasar (caso agente/CI)');

    const localRes = await fetch('http://localhost:3031/api/projects');
    assert.strictEqual(localRes.status, 200, 'El acceso local sin navegador sigue funcionando');

    const healthRes = await fetch('http://localhost:3031/health', {
      headers: { Origin: 'https://evil.example' }
    });
    assert.strictEqual(healthRes.status, 200, '/health queda abierto para monitorización');

    // El token no puede filtrarse por ninguna respuesta.
    const authStatusRes = await fetch('http://localhost:3031/api/system/status');
    const statusBody = await authStatusRes.text();
    assert.ok(!statusBody.includes(validToken), 'El token nunca debe aparecer en una respuesta');
    console.log('  ✓ Control de acceso: origen ajeno 403, token inválido 401, local y agente 200');

    console.log('✅ Live Server, Control Plane, Honest Ingress Status, Static Dashboard & GitHub APIs verified successfully!\n');
  } finally {
    if (originalGhConfig && originalGhConfig.token && !/^ghp_mock_/i.test(originalGhConfig.token)) {
      githubService.saveConfig(originalGhConfig);
    } else {
      try { await githubService.disconnect(); } catch (e) {}
    }
    await containerOrchestrator.stop();
    await new Promise((resolve) => server.close(resolve));
  }
}


testLiveServer()
  .then(() => {
    setTimeout(() => process.exit(0), 50);
  })
  .catch(err => {
    console.error('❌ Live server test failed:', err);
    process.exit(1);
  });
