const assert = require('assert');
const http = require('http');
const caddyManager = require('../server/services/caddyManager');

const {
  CaddyManager,
  DNS_PROVIDERS,
  listDnsProviders,
  buildDnsProviderConfig,
  validateSafeRedirectRegex,
  sanitizeUpstreamDial
} = caddyManager;

/**
 * Crea un servidor HTTP local que emula el contrato real de la Caddy Admin API:
 * - Protección DNS-rebinding (`Host` y `Origin` verificados cuando `requireHost` está definido)
 * - `ETag` + `If-Match` (incluyendo inyección de conflicto 412 bajo demanda)
 * - `/load`, `/config/...`, `/id/<@id>`, `/reverse_proxy/upstreams`
 * - Simulación opcional de módulos DNS faltantes (`missingDnsModule`)
 */
function createMockCaddyAdmin({
  requireHost = null,
  injectConflictOnce = false,
  missingDnsModule = null,
  rejectInvalidHandler = true
} = {}) {
  /** @type {any} */
  let config = {
    apps: {
      http: {
        servers: {
          culkibo: {
            listen: [':80', ':443'],
            protocols: ['h1', 'h2', 'h3'],
            routes: []
          }
        }
      },
      tls: {
        automation: {
          policies: []
        }
      }
    }
  };
  let etagCounter = 1;
  let conflictsRemaining = injectConflictOnce ? 1 : 0;
  /** @type {Array<{ method: string, url: string, host: string | undefined, origin: string | undefined }>} */
  const requests = [];

  const currentEtag = () => `"etag-${etagCounter}"`;

  const findRouteById = (id) => {
    const routes = config?.apps?.http?.servers?.culkibo?.routes;
    if (!Array.isArray(routes)) return { list: null, idx: -1 };
    return { list: routes, idx: routes.findIndex((r) => r && r['@id'] === id) };
  };

  const server = http.createServer((req, res) => {
    const method = req.method || 'GET';
    const urlPath = (req.url || '/').split('?')[0];
    requests.push({ method, url: urlPath, host: req.headers.host, origin: /** @type {string | undefined} */ (req.headers.origin) });

    // Emular protección DNS-rebinding real de Caddy Admin API (HTTP 403 si Host no coincide)
    if (requireHost && req.headers.host !== requireHost) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      return res.end(`Host not allowed: ${req.headers.host} (expected ${requireHost})`);
    }
    if (requireHost && req.headers.origin && req.headers.origin !== `http://${requireHost}`) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      return res.end(`Origin not allowed: ${req.headers.origin}`);
    }

    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const rawBody = Buffer.concat(chunks).toString('utf8');
      let parsedBody = null;
      if (rawBody) {
        try { parsedBody = JSON.parse(rawBody); } catch (e) {
          res.writeHead(400, { 'Content-Type': 'text/plain' });
          return res.end('invalid json');
        }
      }

      if (method === 'GET' && urlPath === '/reverse_proxy/upstreams') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify([{ address: '127.0.0.1:9101', num_requests: 3, fails: 0 }]));
      }

      if (method === 'POST' && urlPath === '/load') {
        const bodyStr = JSON.stringify(parsedBody || {});
        if (missingDnsModule && bodyStr.includes(`"name":"${missingDnsModule}"`)) {
          res.writeHead(400, { 'Content-Type': 'text/plain' });
          return res.end(`module not registered: dns.providers.${missingDnsModule}`);
        }
        config = parsedBody || {};
        etagCounter++;
        res.writeHead(200, { 'Content-Type': 'application/json', ETag: currentEtag() });
        return res.end('ok');
      }

      if (urlPath.startsWith('/id/')) {
        const id = urlPath.slice(4);
        const { list, idx } = findRouteById(id);
        if (method === 'GET') {
          if (idx < 0 || !list) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            return res.end(`unknown object ID '${id}'`);
          }
          res.writeHead(200, { 'Content-Type': 'application/json', ETag: currentEtag() });
          return res.end(JSON.stringify(list[idx]));
        }
        if (method === 'PATCH') {
          if (idx < 0 || !list) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            return res.end(`unknown object ID '${id}'`);
          }
          if (req.headers['if-match'] && req.headers['if-match'] !== currentEtag()) {
            res.writeHead(412, { 'Content-Type': 'text/plain' });
            return res.end('Precondition Failed');
          }
          list[idx] = parsedBody;
          etagCounter++;
          res.writeHead(200, { ETag: currentEtag() });
          return res.end();
        }
        if (method === 'DELETE') {
          if (idx < 0 || !list) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            return res.end(`unknown object ID '${id}'`);
          }
          list.splice(idx, 1);
          etagCounter++;
          res.writeHead(200, { ETag: currentEtag() });
          return res.end();
        }
      }

      // Rutas bajo /config/...
      if (urlPath.startsWith('/config')) {
        const rel = urlPath.replace(/^\/config\/?/, '');
        const parts = rel ? rel.split('/').filter(Boolean) : [];

        if (method === 'GET') {
          let cur = config;
          for (const p of parts) {
            if (cur && typeof cur === 'object' && p in cur) cur = cur[p];
            else {
              res.writeHead(404, { 'Content-Type': 'text/plain' });
              return res.end('not found');
            }
          }
          res.writeHead(200, { 'Content-Type': 'application/json', ETag: currentEtag() });
          return res.end(JSON.stringify(cur));
        }

        if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
          // Simular rechazo atómico de handler inexistente
          if (rejectInvalidHandler && JSON.stringify(parsedBody || {}).includes('este_handler_no_existe')) {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            return res.end('module not registered: http.handlers.este_handler_no_existe');
          }
          // Simular módulo DNS-01 faltante
          if (missingDnsModule && JSON.stringify(parsedBody || {}).includes(`"name":"${missingDnsModule}"`)) {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            return res.end(`loading tls app: module not registered: dns.providers.${missingDnsModule}`);
          }
          // Simular conflicto de ETag 412 una vez para verificar retry de mutate()
          if (conflictsRemaining > 0 && req.headers['if-match']) {
            conflictsRemaining--;
            etagCounter++;
            res.writeHead(412, { 'Content-Type': 'text/plain' });
            return res.end('Precondition Failed');
          }
          if (req.headers['if-match'] && req.headers['if-match'] !== currentEtag()) {
            res.writeHead(412, { 'Content-Type': 'text/plain' });
            return res.end('Precondition Failed');
          }

          if (parts.length === 0) {
            config = parsedBody;
          } else {
            let parent = config;
            for (let i = 0; i < parts.length - 1; i++) {
              if (!parent[parts[i]] || typeof parent[parts[i]] !== 'object') parent[parts[i]] = {};
              parent = parent[parts[i]];
            }
            const leaf = parts[parts.length - 1];
            if (method === 'POST' && Array.isArray(parent[leaf])) {
              parent[leaf].push(parsedBody);
            } else {
              parent[leaf] = parsedBody;
            }
          }
          etagCounter++;
          res.writeHead(200, { ETag: currentEtag() });
          return res.end();
        }
      }

      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('unhandled');
    });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = /** @type {import('net').AddressInfo} */ (server.address());
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        port: addr.port,
        requests,
        getConfig: () => config,
        setConfig: (next) => { config = next; etagCounter++; },
        close: () => new Promise((r) => server.close(r))
      });
    });
  });
}

async function testCaddy() {
  console.log('🧪 Probando CaddyManager (mock Admin API determinista + funciones Edge + Multi-DNS)...');

  // ----------------------------------------------------------------
  // 1. Invariante de ruta simple + CRUD + Rollback + ETag 412 Retry
  // ----------------------------------------------------------------
  const mock = await createMockCaddyAdmin({ injectConflictOnce: true });
  const cm = new CaddyManager();
  cm.adminUrl = mock.url;
  try {
    const det = await cm.detect({ force: true });
    assert.strictEqual(det.available, true);

    await cm.loadBaseConfig({ askEndpoint: 'http://127.0.0.1:3030/api/ingress/ask' });
    const tls = await cm.get('/config/apps/tls/automation/on_demand');
    assert.strictEqual(tls.permission.module, 'http');

    // Alta con conflicto ETag 412 inyectado -> mutate() debe reintentar y tener éxito
    const first = await cm.upsertRoute({
      projectId: 'test_alpha',
      hostnames: ['alpha.culkibo.test'],
      upstreams: ['127.0.0.1:9101']
    });
    assert.strictEqual(first.created, true);

    const stored = await cm.getRoute('test_alpha');
    assert.ok(stored);
    assert.deepStrictEqual(stored.match[0].host, ['alpha.culkibo.test']);
    assert.strictEqual(stored.handle[0].handler, 'reverse_proxy');
    assert.strictEqual(stored.handle[0].upstreams[0].dial, '127.0.0.1:9101');
    assert.strictEqual(stored.terminal, true);

    // Actualización idempotente + cambio de upstream en 1 PATCH
    const idem = await cm.upsertRoute({
      projectId: 'test_alpha',
      hostnames: ['alpha.culkibo.test'],
      upstreams: ['127.0.0.1:9101']
    });
    assert.strictEqual(idem.unchanged, true);

    const second = await cm.upsertRoute({
      projectId: 'test_alpha',
      hostnames: ['alpha.culkibo.test', 'www.alpha.culkibo.test'],
      upstreams: ['127.0.0.1:9102']
    });
    assert.strictEqual(second.created, false);
    assert.strictEqual((await cm.listRoutes()).length, 1);

    // Rechazo atómico de handler inválido
    const beforeLen = (await cm.get('/config/apps/http/servers/culkibo/routes')).length;
    await assert.rejects(
      () => cm.write('POST', '/config/apps/http/servers/culkibo/routes', {
        '@id': 'culkibo_invalido',
        handle: [{ handler: 'este_handler_no_existe' }]
      }),
      /400/
    );
    assert.strictEqual((await cm.get('/config/apps/http/servers/culkibo/routes')).length, beforeLen);

    // Reconcile + borrado idempotente
    const rec = await cm.reconcile([
      { projectId: 'test_alpha', hostnames: ['alpha.culkibo.test'], upstreams: ['127.0.0.1:9103'] },
      { projectId: 'test_gamma', hostnames: ['gamma.culkibo.test'], upstreams: ['127.0.0.1:9104'] }
    ]);
    assert.strictEqual(rec.applied.length, 2);
    const rm1 = await cm.removeRoute('test_gamma');
    const rm2 = await cm.removeRoute('test_gamma');
    assert.strictEqual(rm1.removed, true);
    assert.strictEqual(rm2.removed, false);
    console.log('  ✓ Mock Caddy Admin API: baseConfig, ETag 412 retry, fast-path PATCH, rollback y reconcile');
  } finally {
    await mock.close();
  }

  // ----------------------------------------------------------------
  // 2. Override Host/Origin en túnel SSH remoto (`adminUrl` -> evita HTTP 403)
  // ----------------------------------------------------------------
  const remoteDefault = await createMockCaddyAdmin({ requireHost: '127.0.0.1:2019' });
  const remoteCustom = await createMockCaddyAdmin({ requireHost: '127.0.0.1:2029' });
  const localCm = new CaddyManager();
  const prevAdmin = localCm.adminUrl;
  const prevDet = localCm.lastDetection;
  try {
    // El puerto local del mock es efímero (!= 2019), pero CaddyManager DEBE enviar Host/Origin 127.0.0.1:2019
    assert.notStrictEqual(remoteDefault.port, 2019);
    const detDef = await localCm.detect({ adminUrl: remoteDefault.url });
    assert.strictEqual(detDef.available, true, 'Túnel SSH efímero debe pasar protección DNS-rebinding con Host 127.0.0.1:2019');
    assert.strictEqual(detDef.adminUrl, remoteDefault.url);
    assert.strictEqual(remoteDefault.requests[0].host, '127.0.0.1:2019');
    assert.strictEqual(remoteDefault.requests[0].origin, 'http://127.0.0.1:2019');

    const upRemote = await localCm.upsertRoute(
      { projectId: 'fleet_app', hostnames: ['fleet.example.test'], upstreams: ['127.0.0.1:20050'] },
      { adminUrl: remoteDefault.url }
    );
    assert.strictEqual(upRemote.created, true);
    assert.strictEqual((await localCm.listRoutes({ adminUrl: remoteDefault.url })).length, 1);

    // Puerto remoto personalizado `caddyAdminPort: 2029`
    const detCust = await localCm.detect({ adminUrl: remoteCustom.url, caddyAdminPort: 2029 });
    assert.strictEqual(detCust.available, true, 'caddyAdminPort personalizado debe fijar Host/Origin 127.0.0.1:2029');
    assert.strictEqual(remoteCustom.requests[0].host, '127.0.0.1:2029');
    assert.strictEqual(remoteCustom.requests[0].origin, 'http://127.0.0.1:2029');

    // Cero mutación sobre el singleton local
    assert.strictEqual(localCm.adminUrl, prevAdmin);
    assert.strictEqual(localCm.lastDetection, prevDet);
    assert.strictEqual(localCm._appliedRouteJson.size, 0);
    console.log('  ✓ Remote Caddy SSH tunnel Host/Origin override (127.0.0.1:2019 y puerto custom 2029) sin HTTP 403');
  } finally {
    await remoteDefault.close();
    await remoteCustom.close();
  }

  // ----------------------------------------------------------------
  // 3. Multi-provider Wildcard DNS-01 (7 proveedores + degradación limpia)
  // ----------------------------------------------------------------
  const providers = listDnsProviders();
  assert.strictEqual(providers.length, 7);
  for (const id of ['cloudflare', 'hetzner', 'digitalocean', 'route53', 'porkbun', 'bunny', 'duckdns']) {
    assert.ok(DNS_PROVIDERS[id], `Falta proveedor DNS-01: ${id}`);
  }

  // Verificar nombres exactos de campo JSON de cada módulo caddy-dns/* (2025-2026)
  assert.deepStrictEqual(buildDnsProviderConfig('cloudflare').providerConfig, {
    name: 'cloudflare',
    api_token: '{env.CF_API_TOKEN}'
  });
  // Crítico: Hetzner v2 usa auth_api_token (no api_token!)
  assert.deepStrictEqual(buildDnsProviderConfig('hetzner').providerConfig, {
    name: 'hetzner',
    auth_api_token: '{env.HETZNER_AUTH_API_TOKEN}'
  });
  assert.deepStrictEqual(buildDnsProviderConfig('digitalocean').providerConfig, {
    name: 'digitalocean',
    auth_token: '{env.DO_AUTH_TOKEN}'
  });
  assert.deepStrictEqual(
    buildDnsProviderConfig('route53', { credentialsEnv: { region: 'AWS_REGION' } }).providerConfig,
    {
      name: 'route53',
      access_key_id: '{env.AWS_ACCESS_KEY_ID}',
      secret_access_key: '{env.AWS_SECRET_ACCESS_KEY}',
      region: '{env.AWS_REGION}'
    }
  );
  assert.deepStrictEqual(buildDnsProviderConfig('porkbun').providerConfig, {
    name: 'porkbun',
    api_key: '{env.PORKBUN_API_KEY}',
    api_secret_key: '{env.PORKBUN_API_SECRET_KEY}'
  });
  assert.deepStrictEqual(buildDnsProviderConfig('bunny').providerConfig, {
    name: 'bunny',
    access_key: '{env.BUNNY_ACCESS_KEY}'
  });
  assert.deepStrictEqual(buildDnsProviderConfig('duckdns').providerConfig, {
    name: 'duckdns',
    api_token: '{env.DUCKDNS_API_TOKEN}'
  });

  // Rechazos de proveedor desconocido, campo inválido y env injection
  assert.throws(() => buildDnsProviderConfig('evil_provider'), /no soportado/i);
  assert.throws(() => buildDnsProviderConfig('hetzner', { credentialsEnv: { api_token: 'H_TOK' } }), /inválido/i);
  assert.throws(() => buildDnsProviderConfig('cloudflare', { tokenEnv: 'BAD;rm -rf /' }), /inválido/i);

  // buildTlsApp con 3 proveedores distintos simultáneos
  const multiTls = localCm.buildTlsApp({
    askEndpoint: 'http://127.0.0.1:3030/api/ingress/ask',
    wildcardPolicies: [
      { rootDomain: 'hetzner-app.test', provider: 'hetzner', includeApex: true },
      { rootDomain: 'porkbun-app.test', provider: 'porkbun', includeApex: false },
      { rootDomain: 'bunny-app.test', provider: 'bunny', includeApex: true }
    ]
  });
  const hetzPol = multiTls.automation.policies.find((p) => p.subjects?.includes('*.hetzner-app.test'));
  const porkPol = multiTls.automation.policies.find((p) => p.subjects?.includes('*.porkbun-app.test'));
  const bunPol = multiTls.automation.policies.find((p) => p.subjects?.includes('*.bunny-app.test'));
  assert.strictEqual(hetzPol.issuers[0].challenges.dns.provider.name, 'hetzner');
  assert.strictEqual(hetzPol.issuers[0].challenges.dns.provider.auth_api_token, '{env.HETZNER_AUTH_API_TOKEN}');
  assert.strictEqual(porkPol.issuers[0].challenges.dns.provider.api_secret_key, '{env.PORKBUN_API_SECRET_KEY}');
  assert.strictEqual(bunPol.issuers[0].challenges.dns.provider.access_key, '{env.BUNNY_ACCESS_KEY}');

  // Degradación limpia cuando el binario Caddy carece de dns.providers.hetzner
  const mockNoHetzner = await createMockCaddyAdmin({ missingDnsModule: 'hetzner' });
  try {
    const degCm = new CaddyManager();
    degCm.adminUrl = mockNoHetzner.url;
    const deg = await degCm.reconcileTls({
      askEndpoint: 'http://127.0.0.1:3030/api/ingress/ask',
      wildcardPolicies: [{ rootDomain: 'hetzner-app.test', provider: 'hetzner' }]
    });
    assert.strictEqual(deg.applied, false);
    assert.strictEqual(deg.degraded, true);
    assert.deepStrictEqual(deg.missingDnsProviders, ['hetzner']);
    assert.ok(String(deg.error).includes('github.com/caddy-dns/hetzner/v2'));
  } finally {
    await mockNoHetzner.close();
  }
  console.log('  ✓ Multi-DNS-01 (7 proveedores con esquemas 2025-2026) + degradación segura verificados');

  // ----------------------------------------------------------------
  // 4. ForwardAuth (Authelia/Authentik) + Anti-Spoofing + SSRF guard
  // ----------------------------------------------------------------
  const faRoute = localCm.buildRoute({
    projectId: 'fa_app',
    hostnames: ['secure.example.test'],
    upstreams: ['127.0.0.1:8080'],
    forwardAuth: {
      enabled: true,
      upstream: 'authelia:9091',
      uri: '/api/verify?rd=https://auth.example.test',
      copyHeaders: ['Remote-User', 'Remote-Groups', 'Remote-Email']
    }
  });
  // Paso 0: DEBE eliminar primero las cabeceras de identidad inyectadas por el cliente
  assert.strictEqual(faRoute.handle[0].handler, 'headers');
  assert.deepStrictEqual(faRoute.handle[0].request.delete, ['Remote-User', 'Remote-Groups', 'Remote-Email']);
  // Paso 1: reverse_proxy hacia authelia con method GET + X-Forwarded-* + handle_response 2xx
  const faProxy = faRoute.handle[1];
  assert.strictEqual(faProxy.handler, 'reverse_proxy');
  assert.strictEqual(faProxy.upstreams[0].dial, 'authelia:9091');
  assert.strictEqual(faProxy.rewrite.method, 'GET');
  assert.strictEqual(faProxy.headers.request.set['X-Forwarded-Method'][0], '{http.request.method}');
  assert.strictEqual(faProxy.headers.request.set['X-Forwarded-Uri'][0], '{http.request.uri}');
  assert.deepStrictEqual(faProxy.handle_response[0].match.status_code, [2]);
  assert.strictEqual(
    faProxy.handle_response[0].routes[0].handle[0].request.set['Remote-User'][0],
    '{http.reverse_proxy.header.Remote-User}'
  );
  // extractProxyHandler DEBE devolver el backend real (8080), NO el upstream de Authelia (9091)
  const extractedApp = localCm.extractProxyHandler(faRoute);
  assert.strictEqual(extractedApp.upstreams[0].dial, '127.0.0.1:8080');

  // SSRF cloud metadata bloqueado en forwardAuth.upstream
  assert.throws(() => sanitizeUpstreamDial('169.254.169.254:80', 'forwardAuth'), /SSRF|metadatos/i);
  assert.throws(() => sanitizeUpstreamDial('[::ffff:169.254.169.254]:80', 'forwardAuth'), /SSRF|metadatos/i);
  assert.throws(() => sanitizeUpstreamDial('http://metadata.google.internal:80', 'forwardAuth'), /SSRF|metadatos/i);
  assert.throws(() => localCm.buildRoute({
    projectId: 'fa_bad',
    hostnames: ['x.example.test'],
    upstreams: ['127.0.0.1:8080'],
    forwardAuth: { enabled: true, upstream: '169.254.169.254:80', uri: '/latest/meta-data/' }
  }), /SSRF|metadatos/i);
  console.log('  ✓ ForwardAuth nativo (anti-spoofing delete previo + handle_response 2xx + bloqueo SSRF metadatos)');

  // ----------------------------------------------------------------
  // 5. CORS (OPTIONS 204, Vary: Origin, rechazo * + credentials)
  // ----------------------------------------------------------------
  assert.throws(() => localCm.buildRoute({
    projectId: 'cors_bad',
    hostnames: ['api.example.test'],
    upstreams: ['127.0.0.1:4000'],
    cors: { enabled: true, allowedOrigins: ['*'], allowCredentials: true }
  }), /allowCredentials/i);

  const corsRoute = localCm.buildRoute({
    projectId: 'cors_ok',
    hostnames: ['api.example.test'],
    upstreams: ['127.0.0.1:4000'],
    cors: {
      enabled: true,
      allowedOrigins: ['https://app.example.test', 'https://admin.example.test'],
      allowCredentials: true,
      maxAge: 7200
    }
  });
  assert.strictEqual(corsRoute.handle[0].handler, 'subroute');
  const preflight = corsRoute.handle[0].routes[0];
  assert.deepStrictEqual(preflight.match[0].method, ['OPTIONS']);
  assert.ok(preflight.match[0].header_regexp.Origin.includes('https://app\\.example\\.test'));
  assert.strictEqual(preflight.handle[0].status_code, '204');
  assert.strictEqual(preflight.handle[0].headers['Access-Control-Allow-Credentials'][0], 'true');
  assert.ok(preflight.handle[0].headers.Vary[0].includes('Origin'));
  console.log('  ✓ CORS preflight 204 + allowlist regex + Vary: Origin + rechazo * con credentials');

  // ----------------------------------------------------------------
  // 6. HSTS Preload, Path Routing + strip_path_prefix, Regex Redirects (ReDoS-safe), gRPC h2c, SSE/WS
  // ----------------------------------------------------------------
  const advancedRoute = localCm.buildRoute({
    projectId: 'adv_app',
    hostnames: ['adv.example.test'],
    upstreams: ['127.0.0.1:3000'],
    securityHeaders: true,
    hstsPreload: true,
    permissionsPolicy: 'camera=(), microphone=()',
    protocol: 'grpc',
    streamCloseDelayMs: 15000,
    pathRedirects: [
      { pattern: '^/old/([0-9]+)$', target: '/v2/$1', status: 308, isRegex: true }
    ],
    pathRoutes: [
      { path: '/api/*', upstreams: ['127.0.0.1:4001'], stripPrefix: true },
      { path: '/api/v2/*', upstreams: ['127.0.0.1:4002'], stripPrefix: '/api/v2', protocol: 'grpc', flushInterval: -1 }
    ]
  });
  const advSub = advancedRoute.handle[0];
  assert.strictEqual(advSub.handler, 'subroute');
  // Orden: redirect primero, luego /api/v2/* (más largo) ANTES que /api/*, luego fallback
  assert.strictEqual(advSub.routes[0].handle[0].status_code, '308');
  assert.strictEqual(advSub.routes[0].match[0].path_regexp.pattern, '^/old/([0-9]+)$');
  assert.deepStrictEqual(advSub.routes[1].match[0].path, ['/api/v2/*']);
  assert.strictEqual(advSub.routes[1].handle[0].handler, 'rewrite');
  assert.strictEqual(advSub.routes[1].handle[0].strip_path_prefix, '/api/v2');
  assert.deepStrictEqual(advSub.routes[1].handle[1].transport.versions, ['h2c']);
  assert.strictEqual(advSub.routes[1].handle[1].flush_interval, -1);
  assert.deepStrictEqual(advSub.routes[2].match[0].path, ['/api/*']);
  assert.strictEqual(advSub.routes[2].handle[0].strip_path_prefix, '/api');
  const defaultRp = advSub.routes[3].handle[0];
  assert.deepStrictEqual(defaultRp.transport.versions, ['h2c']);
  assert.strictEqual(defaultRp.stream_close_delay, 15000 * 1e6);
  assert.strictEqual(defaultRp.headers.response.set['Strict-Transport-Security'][0], 'max-age=63072000; includeSubDomains; preload');
  assert.strictEqual(defaultRp.headers.response.set['Permissions-Policy'][0], 'camera=(), microphone=()');

  // ReDoS & javascript: redirect rejection
  assert.strictEqual(validateSafeRedirectRegex('^(a+)+$').ok, false);
  assert.strictEqual(validateSafeRedirectRegex('^/x\\1$').ok, false);
  assert.strictEqual(validateSafeRedirectRegex('^/docs/(.*)$').ok, true);
  assert.throws(() => localCm.buildRoute({
    projectId: 'redos_bad',
    hostnames: ['r.example.test'],
    upstreams: ['127.0.0.1:3000'],
    pathRedirects: [{ pattern: '^(a+)+$', target: '/safe', status: 301, isRegex: true }]
  }), /ReDoS|anidado|rechazado/i);
  assert.throws(() => localCm.buildRoute({
    projectId: 'xss_redir',
    hostnames: ['r.example.test'],
    upstreams: ['127.0.0.1:3000'],
    pathRedirects: [{ pattern: '^/go$', target: 'javascript:alert(1)', status: 302, isRegex: true }]
  }), /bloqueado/i);
  console.log('  ✓ HSTS Preload, Path Routing/stripPrefix orden largo->corto, Regex Redirects anti-ReDoS, gRPC h2c y WS tuning');

  // ----------------------------------------------------------------
  // 7. Route Specificity Rank (redirect < maintenance/sleeping < exact < *.sub < *.root)
  // ----------------------------------------------------------------
  const rRedir = localCm.buildRoute({ projectId: 'r1', hostnames: ['www.a.test'], kind: 'redirect', redirectTo: 'a.test' });
  const rMaint = localCm.buildRoute({ projectId: 'r2', hostnames: ['a.test'], kind: 'maintenance' });
  const rSleep = localCm.buildRoute({ projectId: 'r3', hostnames: ['b.test'], kind: 'sleeping', wakeTarget: '127.0.0.1:3030' });
  const rExact = localCm.buildRoute({ projectId: 'r4', hostnames: ['api.a.test'], upstreams: ['127.0.0.1:3001'] });
  const rWildSub = localCm.buildRoute({ projectId: 'r5', hostnames: ['*.sub.a.test'], upstreams: ['127.0.0.1:3002'] });
  const rWildRoot = localCm.buildRoute({ projectId: 'r6', hostnames: ['*.a.test'], upstreams: ['127.0.0.1:3003'] });

  assert.ok(localCm.routeSpecificityRank(rRedir) < localCm.routeSpecificityRank(rMaint));
  assert.strictEqual(localCm.routeSpecificityRank(rMaint), localCm.routeSpecificityRank(rSleep));
  assert.ok(localCm.routeSpecificityRank(rSleep) < localCm.routeSpecificityRank(rExact));
  assert.ok(localCm.routeSpecificityRank(rExact) < localCm.routeSpecificityRank(rWildSub));
  assert.ok(localCm.routeSpecificityRank(rWildSub) < localCm.routeSpecificityRank(rWildRoot));
  console.log('  ✓ Clasificación de especificidad de rutas (redirect < maintenance/sleeping < exact < *.sub < *.root)');

  // ----------------------------------------------------------------
  // 8. Sondeo real de HTTP/3 QUIC (`probeHttp3`)
  // ----------------------------------------------------------------
  const h3Mock = await createMockCaddyAdmin();
  try {
    const h3Cm = new CaddyManager();
    h3Cm.adminUrl = h3Mock.url;
    const okH3 = await h3Cm.probeHttp3({ checkDockerUdp: false });
    assert.strictEqual(okH3.configured, true);
    assert.strictEqual(okH3.supported, true);
    assert.ok(okH3.protocols.includes('h3'));

    // Deshabilitar automatic_https -> HTTP/3 debe reportarse honestamente como NO soportado
    h3Mock.setConfig({
      apps: {
        http: {
          servers: {
            culkibo: { listen: [':80'], automatic_https: { disable: true }, routes: [] }
          }
        }
      }
    });
    const noH3 = await h3Cm.probeHttp3({ checkDockerUdp: false });
    assert.strictEqual(noH3.configured, false);
    assert.strictEqual(noH3.supported, false);
    assert.ok(noH3.reason);
    console.log('  ✓ probeHttp3() verifica protocolos reales y automatic_https en Caddy');
  } finally {
    await h3Mock.close();
  }

  console.log('✅ Todas las pruebas de CaddyManager (plano de datos + Edge + Multi-DNS) pasaron!\n');
}

module.exports = testCaddy;

if (require.main === module) {
  testCaddy().catch((err) => {
    console.error('❌ Fallo en las pruebas de Caddy:', err);
    process.exit(1);
  });
}
