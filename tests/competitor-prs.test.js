const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const auth = require('../server/middleware/auth');
const { hashBcrypt, verifyBcrypt, isBcryptHash } = require('../server/services/bcryptHash');
const { parseCron } = require('../server/services/cronParser');
const webhookService = require('../server/services/webhookService');
const caddyManager = require('../server/services/caddyManager');
const domainManager = require('../server/services/domainManager');
const projectManager = require('../server/services/projectManager');
const { OidcService, resolveRoleFromClaims } = require('../server/services/oidcService');
const { SslManager } = require('../server/services/sslManager');
const { DeployManager, assertDiskHeadroom, parseCgroupV2MemoryStats, readContainerCgroupV2Memory, buildComposeResourceOverride, enforceComposeResourceLimits, buildSafePruneArgs, MAX_BUILDKIT_KEEP_STORAGE_GB, getProjectNetworkName } = require('../server/services/deployManager');
const systemDoctor = require('../server/services/systemDoctor');
const { GitOpsManager } = require('../server/services/gitopsManager');
const { ServerFleetManager } = require('../server/services/serverFleetManager');
const { PreviewManager } = require('../server/services/previewManager');
const databaseManager = require('../server/services/databaseManager');
const dbBackupManager = require('../server/services/dbBackupManager');
const notificationService = require('../server/services/notificationService');
const { parseDockerCompose } = require('../server/services/universalImporter');
const mcpServer = require('../server/services/mcpServer');
const { LiveSyncEngine } = require('../server/services/liveSyncEngine');

function makeTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

async function testCompetitorPrs() {
  console.log('\n🧪 Suite #23: Regresiones de PRs y CVEs de competidores (Wave-1 + Wave-2 + Wave-3)...');

  // -------------------------------------------------------------------------
  // 1. Auth & Proxy Hardening (Coolify / Dokploy / Traefik / NPM)
  // -------------------------------------------------------------------------
  const prevRequire = process.env.CULKIBO_REQUIRE_TOKEN_ALWAYS;
  try {
    const activeToken = auth.resolveToken();
    process.env.CULKIBO_REQUIRE_TOKEN_ALWAYS = '0';

    // 1a. Localhost DNS Rebinding: loopback socket + Host: evil.attacker.test NO puede saltarse el token
    const rebindReq = {
      headers: { host: 'evil.attacker.test:3030' },
      socket: { remoteAddress: '127.0.0.1' },
      ip: '127.0.0.1',
      originalUrl: '/api/projects',
    };
    const rebindAuth = auth.authorizeRequest(rebindReq);
    assert.strictEqual(rebindAuth.ok, false, 'Host no-loopback debe bloquear el bypass localhost (DNS rebinding)');

    // 1b. Host localhost legítimo sin proxy sí entra en modo desarrollo local
    const goodLoopback = {
      headers: { host: 'localhost:3030' },
      socket: { remoteAddress: '127.0.0.1' },
      ip: '127.0.0.1',
      originalUrl: '/api/projects',
    };
    assert.strictEqual(auth.authorizeRequest(goodLoopback).ok, true, 'Loopback con Host: localhost debe pasar');

    // 1c. Petición HTTP normal con cabecera falsificada Upgrade: websocket NO acepta Sec-WebSocket-Protocol
    const smuggleReq = {
      headers: {
        host: 'panel.example.com',
        upgrade: 'websocket',
        'sec-websocket-protocol': `culkibo-token.${activeToken}`,
      },
      socket: { remoteAddress: '203.0.113.50' },
      ip: '203.0.113.50',
      originalUrl: '/api/projects',
    };
    assert.strictEqual(
      auth.authorizeRequest(smuggleReq).ok,
      false,
      'HTTP normal nunca debe aceptar credenciales en Sec-WebSocket-Protocol aunque envíe Upgrade: websocket'
    );
    assert.strictEqual(
      auth.authorizeRequest(smuggleReq, { allowWsSubprotocol: true }).ok,
      true,
      'Solo el evento WS upgrade (allowWsSubprotocol: true) debe aceptar subprotocolo de token'
    );

    // 1d. Brute-force counter en authMiddleware cuenta intentos fallidos desde IPs remotas
    const bfIp = '198.51.100.222';
    auth.resetAuthRateLimit();
    const badAuthReq = {
      headers: {
        host: 'panel.example.com',
        authorization: 'Bearer totally_invalid_token_attempt',
      },
      socket: { remoteAddress: bfIp },
      ip: bfIp,
      originalUrl: '/api/projects',
    };
    let statusCode = 0;
    const fakeRes = {
      status(c) { statusCode = c; return this; },
      setHeader() {},
      json() {},
    };
    auth.authMiddleware(badAuthReq, fakeRes, () => {});
    assert.strictEqual(statusCode, 401);
    const statsAfter = auth.getBruteForceStats();
    assert.ok(statsAfter.trackedIps >= 1, 'Los fallos de credencial deben registrarse en el contador brute-force');
    auth.resetAuthRateLimit();

    // 1e. isOriginAllowed normaliza puerto por defecto :443 y rightmost X-Forwarded-Host
    const originReq = {
      headers: {
        host: '127.0.0.1:3030',
        'x-forwarded-host': 'spoofed.evil, panel.example.com:443',
        'x-forwarded-proto': 'http, https',
      },
      socket: { remoteAddress: '127.0.0.1' },
      protocol: 'http',
    };
    assert.strictEqual(auth.isOriginAllowed('https://panel.example.com', originReq), true);
    assert.strictEqual(auth.isOriginAllowed('https://spoofed.evil', originReq), false);
  } finally {
    if (prevRequire === undefined) delete process.env.CULKIBO_REQUIRE_TOKEN_ALWAYS;
    else process.env.CULKIBO_REQUIRE_TOKEN_ALWAYS = prevRequire;
  }
  console.log('  ✓ Auth/Proxy: anti-DNS rebinding, WS subprotocol gate, brute-force tickets y rightmost XFH');

  // -------------------------------------------------------------------------
  // 2. Bcrypt, Domain Manager, Caddy & SSL (Caddy / Traefik / NPM / CapRover)
  // -------------------------------------------------------------------------
  // 2a. bcryptHash rechaza cost > 14 (DoS CPU) y verifica hash válido
  assert.strictEqual(isBcryptHash('$2b$31$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWX0123456'), false, 'Cost 31 debe rechazarse');
  assert.strictEqual(isBcryptHash('$2b$15$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWX0123456'), false, 'Cost 15 debe rechazarse');
  const h = hashBcrypt('secreto-seguro-123', 4);
  assert.strictEqual(isBcryptHash(h), true);
  assert.strictEqual(verifyBcrypt('secreto-seguro-123', h), true);

  // 2b. DomainManager: IPv4-mapped ::ffff: CIDR < /96, FQDN trailing dot, IDN punycode, canonical loop & Basic Auth
  // Limpiar cualquier dominio temporal previo de `.example.test` si una ejecución anterior se interrumpió
  domainManager.domains = domainManager.domains.filter((d) => !String(d.hostname || '').endsWith('.example.test'));
  domainManager.rebuildIndex();
  const origDomains = JSON.parse(JSON.stringify(domainManager.domains));
  try {
    const added = await domainManager.addDomain({ hostname: 'Café.Example.Test.', targetPod: 'citadel' });
    assert.strictEqual(added.hostname, 'xn--caf-dma.example.test', 'Debe quitar punto final FQDN y normalizar IDN punycode');

    await assert.rejects(
      () => domainManager.updateDomain(added.id, { ipAllowlist: ['::ffff:10.0.0.0/80'] }),
      /96|CIDR|IPv4/i,
      'Debe rechazar ::ffff: con prefijo menor a /96'
    );
    const okAllow = await domainManager.updateDomain(added.id, { ipAllowlist: ['::ffff:10.0.0.1/128', '192.0.2.0/24'] });
    assert.strictEqual(okAllow.ipAllowlist.length, 2);

    await assert.rejects(
      () => domainManager.updateDomain(added.id, {
        basicAuth: {
          enabled: true,
          accounts: [
            { username: 'admin', password: 'password123' },
            { username: 'admin', password: 'password456' },
          ],
        },
      }),
      /duplicad/i,
      'Debe rechazar usuarios Basic Auth duplicados'
    );
    await assert.rejects(
      () => domainManager.updateDomain(added.id, {
        basicAuth: {
          enabled: true,
          accounts: [{ username: 'admin', password: 'a'.repeat(80) }],
        },
      }),
      /72/,
      'Debe rechazar contraseñas > 72 bytes en bcrypt'
    );

    // Ciclo bidireccional / colisión de redirección canónica (www_to_apex reclama www.*)
    const domA = await domainManager.addDomain({ hostname: 'loop-a.example.test', targetPod: 'citadel', canonicalRedirect: 'www_to_apex' });
    assert.strictEqual(domA.canonicalRedirect, 'www_to_apex');
    await assert.rejects(
      () => domainManager.addDomain({ hostname: 'www.loop-a.example.test', targetPod: 'citadel' }),
      /bucle|ciclo|loop|redirige|acompañante|canónic/i,
      'Debe impedir registrar www. cuando la raíz ya reclama www_to_apex (evita bucle 301)'
    );
  } finally {
    domainManager.domains = origDomains;
    domainManager.rebuildIndex();
    domainManager.saveDomains();
  }

  // 2c. CaddyManager: trusted proxies no incluye RFC1918 por defecto; sys_encode minimum_length: 1024 + SSE bypass; rate_limit antes de basicAuth
  const baseCfg = caddyManager.buildBaseConfig({});
  const httpServer = Object.values(baseCfg.apps.http.servers)[0];
  const trusted = httpServer?.trusted_proxies?.ranges || [];
  assert.ok(!trusted.includes('10.0.0.0/8'), 'RFC1918 10.0.0.0/8 no debe ser trusted_proxy por defecto');
  assert.ok(!trusted.includes('192.168.0.0/16'), 'RFC1918 192.168.0.0/16 no debe ser trusted_proxy por defecto');
  const sysEncode = (httpServer?.routes || []).find((r) => r['@id'] === 'sys_encode');
  assert.ok(sysEncode && sysEncode.handle[0].minimum_length === 1024, 'sys_encode debe fijar minimum_length: 1024');
  assert.ok(JSON.stringify(sysEncode.match).includes('text/event-stream'), 'sys_encode debe excluir text/event-stream (SSE)');

  const cm = new caddyManager.CaddyManager();
  cm._capabilitiesCache = { data: { hasRateLimitPlugin: true }, at: Date.now() };
  const securedRoute = cm.buildRoute({
    projectId: 'test-order',
    hostnames: ['app.example.test'],
    upstreams: ['127.0.0.1:4100'],
    basicAuth: { enabled: true, accounts: [{ username: 'u', passwordHash: h }] },
    rateLimit: { enabled: true, requests: 60, windowSeconds: 60 },
  });
  const handlers = securedRoute.handle;
  const rlIdx = handlers.findIndex((x) => x.handler === 'rate_limit');
  const baIdx = handlers.findIndex((x) => x.handler === 'authentication');
  const rp = handlers.find((x) => x.handler === 'reverse_proxy');
  assert.ok(rlIdx >= 0 && baIdx >= 0 && rlIdx < baIdx, 'rate_limit debe ejecutarse ANTES que basicAuth');
  assert.ok(JSON.stringify(handlers[rlIdx]).includes('{http.vars.client_ip}'), 'rate_limit debe usar {http.vars.client_ip}');
  assert.ok(rp && rp.transport && rp.transport.response_header_timeout === 60000000000, 'reverse_proxy debe fijar response_header_timeout: 60s');
  const streamRoute = cm.buildRoute({
    projectId: 'test-sse',
    hostnames: ['sse.example.test'],
    upstreams: ['127.0.0.1:4101'],
    flushInterval: -1,
  });
  assert.strictEqual(streamRoute.handle[0].flush_interval, -1, 'Ruta streaming debe fijar flush_interval: -1');

  // 2d. SSL multi-block PEM validation (rechaza PEM corrupto)
  const sslTmp = makeTempDir('culkibo-ssl-pr-');
  try {
    const sslMgr = new SslManager({ dataDir: sslTmp, certsDir: path.join(sslTmp, 'certs') });
    assert.throws(
      () => sslMgr.uploadCustomCertificate({
        domain: 'bad.example.test',
        certPem: '-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----',
        keyPem: '-----BEGIN PRIVATE KEY-----\nINVALID\n-----END PRIVATE KEY-----',
      }),
      /certificado|inválido|PEM|X\.509|válido/i,
      'Debe rechazar PEM corrupto'
    );
  } finally {
    fs.rmSync(sslTmp, { recursive: true, force: true });
  }
  console.log('  ✓ Proxy/TLS: bcrypt cost<=14, ::ffff: CIDR, IDN/FQDN, anti-bucle 301, orden rate_limit<basicAuth');

  // -------------------------------------------------------------------------
  // 3. Webhooks & CronParser (Coolify / Dokploy / Kamal)
  // -------------------------------------------------------------------------
  assert.strictEqual(webhookService.normalizeRepoSlug('ssh://git@github.com/org/repo.git'), 'org/repo');
  assert.strictEqual(webhookService.matchesWatchPaths(['apps/web/**/*.ts'], ['apps/web/src/index.ts']), true);
  assert.strictEqual(webhookService.matchesWatchPaths(['apps/web/**/*.ts'], ['apps/api/main.go']), false);

  // [skip ci] en push debe omitirse sin disparar deploy
  const glSkip = await webhookService.dispatchPush({
    provider: 'gitlab',
    projects: [{ id: 'p-skip-ci', name: 'Demo', gitBranch: 'main', autoDeploy: true }],
    branch: 'main',
    commitSha: 'abcdef1234567890',
    commitMsg: 'docs: typo [skip ci]',
    author: 'dev',
    changedFiles: ['README.md'],
  });
  assert.strictEqual(glSkip.body.deployed, false, 'Commit con [skip ci] debe omitirse');
  assert.ok(/skip/i.test(String(glSkip.body.reason || glSkip.body.message || '')), 'Motivo debe mencionar skip_ci');

  // CronParser rechaza múltiples `/` o `-`
  assert.throws(() => parseCron('1/2/3 * * * *'), /inválid|formato|rango|paso/i);
  assert.throws(() => parseCron('1-5-9 * * * *'), /inválid|formato|rango/i);
  console.log('  ✓ Webhooks/Cron: ssh:// slug, globs **, [skip ci] y cronParser estricto');

  // -------------------------------------------------------------------------
  // 4. Nixpacks / Railpack Builds & Previews (Wave-2)
  // -------------------------------------------------------------------------
  const buildTmp = makeTempDir('culkibo-build-pr-');
  const dm = new DeployManager();
  try {
    // 4a. Vite estático usa puerto dinámico y Nginx
    const viteDir = path.join(buildTmp, 'vite-app');
    fs.mkdirSync(viteDir, { recursive: true });
    fs.writeFileSync(path.join(viteDir, 'package.json'), JSON.stringify({
      name: 'vite-demo',
      scripts: { build: 'vite build' },
      devDependencies: { vite: '^5.0.0' },
    }));
    const viteStrat = await dm.detectStrategy(viteDir, { containerPort: 8080 });
    const viteDf = dm.generateDockerfile(viteStrat);
    assert.ok(viteDf.includes('listen 8080') || viteDf.includes('EXPOSE 8080'), 'Vite/static debe respetar containerPort');
    assert.ok(viteDf.includes('--include=dev'), 'Build npm debe usar --include=dev incluso con NODE_ENV=production');

    // 4b. Go toma precedencia sobre package.json auxiliar y trae ca-certificates + GOTOOLCHAIN=auto
    const goDir = path.join(buildTmp, 'go-app');
    fs.mkdirSync(goDir, { recursive: true });
    fs.writeFileSync(path.join(goDir, 'go.mod'), 'module example.com/app\n\ngo 1.23\n');
    fs.writeFileSync(path.join(goDir, 'main.go'), 'package main\nfunc main(){}\n');
    fs.writeFileSync(path.join(goDir, 'package.json'), JSON.stringify({ name: 'assets', scripts: { lint: 'echo ok' } }));
    const goStrat = await dm.detectStrategy(goDir, { containerPort: 8080 });
    assert.strictEqual(goStrat.stack, 'go', 'go.mod debe tener prioridad sobre package.json auxiliar');
    const goDf = dm.generateDockerfile(goStrat);
    assert.ok(goDf.includes('ca-certificates'), 'Imagen final Go debe instalar ca-certificates');
    assert.ok(goDf.includes('GOTOOLCHAIN=auto'), 'Builder Go debe fijar GOTOOLCHAIN=auto');

    // 4c. Python pyproject.toml (FastAPI) copia el proyecto antes de pip install . y detecta uvicorn
    const pyDir = path.join(buildTmp, 'py-app');
    fs.mkdirSync(pyDir, { recursive: true });
    fs.writeFileSync(path.join(pyDir, 'pyproject.toml'), '[project]\nname="api"\ndependencies=["fastapi","uvicorn"]\n');
    fs.writeFileSync(path.join(pyDir, 'main.py'), 'from fastapi import FastAPI\napp = FastAPI()\n');
    const pyStrat = await dm.detectStrategy(pyDir, { containerPort: 8000 });
    assert.strictEqual(pyStrat.stack, 'python');
    const pyDf = dm.generateDockerfile(pyStrat);
    assert.ok(pyDf.includes('ENV PORT='), 'Python Dockerfile debe exportar ENV PORT');
    assert.ok(pyDf.includes('uvicorn'), 'Python FastAPI debe generar CMD uvicorn');

    // 4d. Next.js standalone
    const nextDir = path.join(buildTmp, 'next-app');
    fs.mkdirSync(nextDir, { recursive: true });
    fs.writeFileSync(path.join(nextDir, 'package.json'), JSON.stringify({
      name: 'next-demo',
      scripts: { build: 'next build', start: 'next start' },
      dependencies: { next: '15.0.0', react: '19.0.0' },
    }));
    fs.writeFileSync(path.join(nextDir, 'next.config.mjs'), 'export default { output: "standalone" };\n');
    const nextStrat = await dm.detectStrategy(nextDir, { containerPort: 3000 });
    const nextDf = dm.generateDockerfile(nextStrat);
    assert.ok(nextDf.includes('.next/standalone') && nextDf.includes('libc6-compat'), 'Next.js standalone debe copiar .next/standalone e incluir libc6-compat');

    // 4e. defaultDockerignore protege .env y .git
    const ignoreText = dm.defaultDockerignore('node');
    assert.ok(ignoreText.includes('.git') && ignoreText.includes('.env'));
  } finally {
    fs.rmSync(buildTmp, { recursive: true, force: true });
  }

  // 4f. PreviewManager: rechaza baseDomain no RFC-1123 (firma real) y destroyPreview acepta objeto o clave
  const pmTmp = makeTempDir('culkibo-pm-pr-');
  try {
    const pm = new PreviewManager(path.join(pmTmp, 'previews.json'));
    await assert.rejects(
      () => pm.deployPreview(
        {
          id: 'p1',
          name: 'Demo',
          gitRepo: 'https://github.com/a/b.git',
          previewDeployments: { enabled: true, baseDomain: 'not valid domain!' }
        },
        { branch: 'feat/test' }
      ),
      /Dominio base de previews inválido|RFC-1123/i,
      'deployPreview debe rechazar explícitamente baseDomain no RFC-1123 (no "Proyecto inválido")'
    );
    const missingByObj = await pm.destroyPreview('p1', { branch: 'no-existe' });
    assert.strictEqual(missingByObj.removed, false);
    const missingByKey = await pm.destroyPreview('p1', 'pr-99999');
    assert.strictEqual(missingByKey.removed, false);
  } finally {
    fs.rmSync(pmTmp, { recursive: true, force: true });
  }
  console.log('  ✓ Builds/Previews: Vite dinámico, Go>aux-pkg, Python FastAPI, Next standalone, PreviewManager');

  // -------------------------------------------------------------------------
  // 5. Backups, DR, Databases & Notifications (Backrest / Dokploy#5926)
  // -------------------------------------------------------------------------
  // 5a. dbBackupManager: checksum obligatorio, allowUnsigned, mode replace->overwrite, authTagLength/IV GCM estricto
  const unsignedSnap = { type: 'culkibo-instance-snapshot', schemaVersion: 2, data: { projects: [], domains: [] } };
  await assert.rejects(
    () => dbBackupManager.importInstanceSnapshot({ snapshot: unsignedSnap, dryRun: true }),
    /Checksum|ausente|malformado/i,
    'Snapshot sin checksum debe rechazarse por defecto'
  );
  const parsedAllowed = await dbBackupManager.importInstanceSnapshot({
    snapshot: unsignedSnap,
    mode: 'replace',
    dryRun: true,
    allowUnsigned: true,
  });
  assert.strictEqual(parsedAllowed.plan.dryRun, true);
  assert.strictEqual(parsedAllowed.plan.mode, 'overwrite', 'mode: replace debe normalizarse a overwrite');

  const badGcm = {
    type: 'culkibo-instance-snapshot',
    schemaVersion: 2,
    encrypted: true,
    data: {
      encrypted: true,
      alg: 'aes-256-gcm',
      kdf: 'scrypt',
      salt: crypto.randomBytes(16).toString('base64'),
      iv: crypto.randomBytes(8).toString('base64'), // inválido: 8 bytes en vez de 12
      tag: crypto.randomBytes(16).toString('base64'),
      ciphertext: crypto.randomBytes(16).toString('base64'),
    },
  };
  await assert.rejects(
    () => dbBackupManager.importInstanceSnapshot({ snapshot: badGcm, passphrase: 'test-passphrase-123', dryRun: true, allowUnsigned: true }),
    /iv|gcm|cifrad|12|longitud/i,
    'Debe rechazar IV distinto de 12 bytes en AES-256-GCM'
  );

  // 5b. databaseManager.planRetention excluye localDeleted/remotePendingDelete y protege la última copia S3
  const now = Date.now();
  const backupsFixture = [
    { id: 'b1', createdAt: new Date(now - 1000).toISOString(), localDeleted: true, remote: { key: 'k1' } },
    { id: 'b2', createdAt: new Date(now - 2 * 86400_000).toISOString(), remote: { key: 'k2' } },
    { id: 'b3', createdAt: new Date(now - 10 * 86400_000).toISOString(), remote: { key: 'k3' } },
    { id: 'b4', createdAt: new Date(now - 20 * 86400_000).toISOString(), remotePendingDelete: true },
  ];
  const plan = databaseManager.planRetention(backupsFixture, { daily: 1, weekly: 0, monthly: 0 });
  assert.ok(plan.keep.includes('b2'), 'Debe conservar la copia válida más reciente y no desperdiciar cuota en localDeleted');
  assert.ok(!plan.prune.includes('b4'), 'No debe intentar re-eliminar entradas con remotePendingDelete');

  // 5c. NotificationService: bloquear cambio de webhook URL sin reintroducir secretHeader (Dokploy#5926) + Telegram HTML-safe truncate
  const origNotif = JSON.parse(JSON.stringify(notificationService.config));
  try {
    notificationService.config.channels.webhook = {
      enabled: true,
      url: 'https://hooks.original.example/cb',
      secretHeader: 'super-secret-hmac-key',
    };
    assert.throws(
      () => notificationService.setConfig({
        channels: {
          webhook: { enabled: true, url: 'https://attacker.example/steal', secretHeader: '••••••••' },
        },
      }),
      /secreto|secretHeader|reintroduc|URL/i,
      'Cambiar la URL del webhook sin reintroducir el secreto debe bloquearse'
    );
    const trunc = notificationService.truncateHtmlEscaped('A & B <tag> "quote" '.repeat(30), 40);
    assert.ok(!trunc.endsWith('&') && !/&[a-z#0-9]*$/i.test(trunc), 'truncateHtmlEscaped nunca corta una entidad HTML a medias');
  } finally {
    notificationService.config = origNotif;
    notificationService.saveConfig();
  }
  console.log('  ✓ Backups/DR/Notificaciones: BOM, checksum, GCM IV/tag, GFS UTC y protección secretHeader');

  // -------------------------------------------------------------------------
  // 6. MCP, Universal Importer YAML anchors & LiveSync diff (Wave-2)
  // -------------------------------------------------------------------------
  // 6a. MCP: ping, id:0 preservado, rechazo de argumentos no-objeto y redacción de rawMeta/previewEnvVars
  const pingRes = await mcpServer.handleJsonRpc({ jsonrpc: '2.0', id: 0, method: 'ping', params: {} });
  assert.strictEqual(pingRes.id, 0, 'JSON-RPC id: 0 debe preservarse exactamente');
  assert.ok(pingRes.result && !pingRes.error, 'Método ping debe responder OK');

  const badArgs = await mcpServer.handleJsonRpc({
    jsonrpc: '2.0',
    id: 99,
    method: 'tools/call',
    params: { name: 'culkibo_list_projects', arguments: ['not', 'an', 'object'] },
  });
  assert.strictEqual(badArgs.result?.isError, true, 'Argumentos MCP que no sean objeto plano deben marcar isError: true');
  assert.strictEqual(badArgs.result?._meta?.['dev.culkibo/error']?.code, 'INVALID_ARGUMENTS');

  // 6b. Universal Importer: YAML x-common: &anchor + <<: *anchor y aviso de montaje peligroso
  const composeYaml = `
x-common: &common_env
  environment:
    APP_MODE: production
services:
  web:
    <<: *common_env
    image: nginx:1.27
    ports:
      - "8080:80"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`;
  const parsedCompose = parseDockerCompose(composeYaml);
  assert.strictEqual(parsedCompose.services.length, 1);
  assert.strictEqual(parsedCompose.services[0].envVars.APP_MODE, 'production', 'Debe resolver YAML merge <<:*anchor');
  assert.ok(
    parsedCompose.services[0].warnings.some((w) => /docker\.sock|sensible|host/i.test(w)),
    'Debe avisar sobre montajes sensibles como /var/run/docker.sock'
  );

  // 6c. LiveSyncEngine: getFrameDiff devuelve action y diff unificado
  const lsTmp = makeTempDir('culkibo-ls-pr-');
  try {
    const engine = new LiveSyncEngine();
    const res1 = engine.applyCommitFrame('pr-diff-test', {
      seq: 1,
      files: [{ path: 'hello.txt', op: 'upsert', content: Buffer.from('linea 1\nlinea 2\n').toString('base64'), encoding: 'base64' }],
    }, { targetDir: lsTmp });
    assert.strictEqual(res1.written, 1);
    const res2 = engine.applyCommitFrame('pr-diff-test', {
      seq: 2,
      files: [{ path: 'hello.txt', op: 'upsert', content: Buffer.from('linea 1\nlinea 2 editada\n').toString('base64'), encoding: 'base64' }],
    }, { targetDir: lsTmp });
    assert.strictEqual(res2.written, 1);
    const frameDiff = engine.getFrameDiff('pr-diff-test', 2);
    assert.ok(frameDiff && frameDiff.files.length === 1);
    assert.strictEqual(frameDiff.files[0].action, 'modified');
    assert.ok(typeof frameDiff.files[0].diff === 'string' && frameDiff.files[0].diff.includes('linea 2 editada'));
  } finally {
    fs.rmSync(lsTmp, { recursive: true, force: true });
  }
  console.log('  ✓ MCP/Importer/LiveSync: ping/id:0, YAML anchors+docker.sock warning y diff unificado');

  // -------------------------------------------------------------------------
  // 7. Cycle #2 Competitor-CVE Guardrails, OIDC Groups, CULKIBO_DATA_DIR & Lazy Routes
  // -------------------------------------------------------------------------
  // 7a. 100% CULKIBO_DATA_DIR store isolation (ProjectManager + DomainManager)
  const isoDir = makeTempDir('culkibo-datadir-iso-');
  const prevDataDirEnv = process.env.CULKIBO_DATA_DIR;
  try {
    process.env.CULKIBO_DATA_DIR = isoDir;
    assert.strictEqual(
      path.resolve(projectManager.resolveDefaultDataPath()),
      path.resolve(path.join(isoDir, 'projects.json')),
      'ProjectManager debe respetar CULKIBO_DATA_DIR'
    );
    assert.strictEqual(
      path.resolve(domainManager.resolveDefaultDomainsFile()),
      path.resolve(path.join(isoDir, 'domains.json')),
      'DomainManager debe respetar CULKIBO_DATA_DIR'
    );
    const isoPm = new projectManager.ProjectManager({ seedDemo: false });
    const createdIsoProj = isoPm.create({ id: 'iso_proj_1', name: 'Isolated Project' });
    await isoPm.flushToDisk(createdIsoProj.id);
    assert.ok(fs.existsSync(path.join(isoDir, 'projects.json')), 'projects.json debe persistirse dentro de CULKIBO_DATA_DIR');

    const isoDm = new domainManager.DomainManager({ seedDefaults: false });
    await isoDm.addDomain({ hostname: 'isolated.example.test', targetPod: 'citadel', projectId: 'iso_proj_1' });
    assert.ok(fs.existsSync(path.join(isoDir, 'domains.json')), 'domains.json debe persistirse dentro de CULKIBO_DATA_DIR');
  } finally {
    if (prevDataDirEnv === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDirEnv;
    fs.rmSync(isoDir, { recursive: true, force: true });
  }

  // 7b. coolify#12414: Enforce memoryMb/cpus cgroup limits on Docker Compose deployments
  const composeDir = makeTempDir('culkibo-compose-limits-');
  try {
    const composeFile = path.join(composeDir, 'docker-compose.yml');
    fs.writeFileSync(composeFile, [
      'services:',
      '  web:',
      '    image: node:22-alpine',
      '  worker:',
      '    image: node:22-alpine',
      'volumes:',
      '  pgdata:'
    ].join('\n'), 'utf8');
    const ov = buildComposeResourceOverride(fs.readFileSync(composeFile, 'utf8'), { memoryMb: 512, cpus: 1.5, pidsLimit: 256 });
    assert.deepStrictEqual(ov.services, ['web', 'worker']);
    assert.ok(ov.overrideYaml.includes('mem_limit: 512m'));
    assert.ok(ov.overrideYaml.includes('cpus: 1.5'));
    assert.ok(ov.overrideYaml.includes('memory: 512M'));
    assert.ok(ov.overrideYaml.includes('cpus: "1.5"'));

    const enforced = enforceComposeResourceLimits(composeFile, { id: 'proj_c12414', memoryMb: 768, cpus: '2.0' });
    assert.ok(fs.existsSync(enforced.overridePath), 'Debe escribir archivo override de límites Compose');
    assert.ok(enforced.composeArgs.includes('-f') && enforced.composeArgs.includes(enforced.overridePath));
  } finally {
    fs.rmSync(composeDir, { recursive: true, force: true });
  }

  // 7c. Cosmos#591: assertDiskHeadroom pre-write ENOSPC guard (HTTP 507 DISK_FULL)
  {
    const okDisk = assertDiskHeadroom(os.tmpdir(), 64 * 1024 * 1024, {
      statfsImpl: () => ({ bavail: 100000, bsize: 4096, blocks: 200000 })
    });
    assert.strictEqual(okDisk.ok, true);
    assert.throws(
      () => assertDiskHeadroom(os.tmpdir(), 64 * 1024 * 1024, {
        statfsImpl: () => ({ bavail: 1024, bsize: 4096, blocks: 200000 }) // 4 MiB free < 64 MiB
      }),
      (err) => err && err.status === 507 && err.code === 'DISK_FULL' && err.freeBytes === 4 * 1024 * 1024,
      'assertDiskHeadroom debe lanzar 507 DISK_FULL cuando el espacio libre es insuficiente'
    );
  }

  // 7d. runtipi#2445: Linux cgroup v2 accurate working-set RAM parsing (subtract inactive_file page cache)
  {
    const mb = 1024 * 1024;
    const stats = parseCgroupV2MemoryStats({
      currentRaw: String(950 * mb),
      maxRaw: String(1024 * mb),
      statRaw: `anon ${200 * mb}\nfile ${750 * mb}\nactive_file ${50 * mb}\ninactive_file ${700 * mb}\nslab ${20 * mb}\noom_kill 0\n`,
      swapCurrentRaw: '0'
    });
    assert.strictEqual(stats.cgroupVersion, 2);
    assert.strictEqual(stats.workingSetBytes, 250 * mb, 'Working set debe restar inactive_file (950-700 = 250 MiB)');
    assert.strictEqual(stats.workingSetMb, 250);
    assert.ok(stats.usagePercent > 24 && stats.usagePercent < 25, `Uso real debe ser ~24.41%, obtenido ${stats.usagePercent}`);
    assert.ok(stats.rawUsagePercent > 92, 'Uso bruto antes de descontar page cache era >92%');

    const unlim = parseCgroupV2MemoryStats({ currentRaw: String(64 * mb), maxRaw: 'max', statRaw: '' });
    assert.strictEqual(unlim.unlimited, true);
    assert.strictEqual(unlim.limitBytes, null);
    assert.strictEqual(unlim.usagePercent, null);

    const cgDir = makeTempDir('culkibo-cgv2-');
    try {
      fs.writeFileSync(path.join(cgDir, 'memory.current'), String(300 * mb), 'utf8');
      fs.writeFileSync(path.join(cgDir, 'memory.max'), String(512 * mb), 'utf8');
      fs.writeFileSync(path.join(cgDir, 'memory.stat'), `anon ${100 * mb}\ninactive_file ${150 * mb}\n`, 'utf8');
      const fromDisk = readContainerCgroupV2Memory('abcdef123456', { cgroupDir: cgDir });
      assert.ok(fromDisk && fromDisk.workingSetBytes === 150 * mb);
    } finally {
      fs.rmSync(cgDir, { recursive: true, force: true });
    }
  }

  // 7e. dokploy#2547: deployManager.fastRestartWithEnv (recreates container with new env, ZERO docker build)
  {
    const frDm = new DeployManager();
    const dockerInvocations = [];
    frDm.saveStore = () => {};
    frDm.detectDocker = async () => ({ available: true, version: '27.0.0' });
    frDm.ensureNetwork = async () => {};
    frDm.findFreePort = async () => 24567;
    frDm.resolveUpstream = async ({ hostPort }) => ({ dial: `127.0.0.1:${hostPort}` });
    frDm.waitForHealth = async () => ({ healthy: true, status: 200 });
    frDm.switchRoute = async () => ({ ok: true });
    frDm.drainAndRetire = async () => {};
    frDm.runDocker = async (args) => {
      dockerInvocations.push(args);
      if (args[0] === 'image' && args[1] === 'inspect') return { code: 0, stdout: '[]', stderr: '' };
      if (args[0] === 'run') return { code: 0, stdout: 'cid_fast_restart_123\n', stderr: '' };
      return { code: 0, stdout: '', stderr: '' };
    };
    frDm.store.proj_fr_1 = {
      current: {
        id: 'dep_orig_1',
        projectId: 'proj_fr_1',
        projectName: 'Fast Restart Demo',
        containerName: 'culkibo_proj_fr_1_v1',
        imageTag: 'culkibo/proj_fr_1:v1',
        hostPort: 24500,
        containerPort: 3000,
        upstream: '127.0.0.1:24500',
        hostnames: ['fast.example.test'],
        healthPath: '/health',
        serverId: 'local',
        status: 'activo'
      },
      previous: null,
      history: []
    };

    const dryRes = await frDm.fastRestartWithEnv(
      { id: 'proj_fr_1', name: 'Fast Restart Demo', domains: ['fast.example.test'], envVars: { FEATURE_X: '1' }, memoryMb: 512, cpus: '1.0' },
      { envVars: { FEATURE_Y: '2' }, dryRun: true }
    );
    assert.strictEqual(dryRes.dryRun, true);
    assert.strictEqual(dryRes.rebuilt, false);
    assert.ok(dryRes.envKeysApplied.includes('FEATURE_X') && dryRes.envKeysApplied.includes('FEATURE_Y'));

    const liveRes = await frDm.fastRestartWithEnv(
      { id: 'proj_fr_1', name: 'Fast Restart Demo', domains: ['fast.example.test'], envVars: { FEATURE_X: '1' }, memoryMb: 512, cpus: '1.0' },
      { envVars: { FEATURE_Y: '2' } }
    );
    assert.strictEqual(liveRes.restarted, true);
    assert.strictEqual(liveRes.rebuilt, false);
    assert.strictEqual(liveRes.imageTag, 'culkibo/proj_fr_1:v1');
    assert.strictEqual(liveRes.routeSwitched, true);
    assert.ok(!dockerInvocations.some((a) => a[0] === 'build' || a[0] === 'buildx'), 'fastRestartWithEnv JAMÁS debe ejecutar docker build');
    assert.ok(dockerInvocations.some((a) => a[0] === 'run' && a.includes('FEATURE_Y')), 'fastRestartWithEnv debe inyectar nuevas env vars en docker run');
  }

  // 7f. Enterprise OIDC groups -> RBAC role mapping & disablePasswordLogin lockout guard
  const oidcTmp = makeTempDir('culkibo-oidc-groups-');
  try {
    const oidc = new OidcService({ dataDir: oidcTmp });
    // Anti-lockout: cannot disable password login with 0 enabled SSO providers
    assert.throws(
      () => oidc.setSecuritySettings({ disablePasswordLogin: true }),
      (err) => err && err.code === 'OIDC_LOCKOUT_PREVENTED',
      'Debe impedir disablePasswordLogin sin proveedor SSO activo'
    );
    // Reject mapping any group to owner
    assert.throws(
      () => oidc.configureProvider({
        id: 'authentik',
        type: 'authentik',
        issuerUrl: 'https://auth.example.test/application/o/culkibo',
        clientId: 'cid',
        redirectUri: 'https://panel.example.test/api/auth/oidc/callback',
        groupRoleMap: { superusers: 'owner' }
      }),
      (err) => err && err.code === 'OWNER_PROVISION_FORBIDDEN',
      'groupRoleMap jamás puede asignar rol owner'
    );

    const prov = oidc.configureProvider({
      id: 'authentik',
      type: 'authentik',
      issuerUrl: 'https://auth.example.test/application/o/culkibo',
      clientId: 'cid-ent',
      redirectUri: 'https://panel.example.test/api/auth/oidc/callback',
      autoProvision: true,
      defaultRole: 'viewer',
      groupsClaim: 'groups',
      groupRoleMap: { 'platform-admins': 'admin', devs: 'developer', readonly: 'viewer' },
      disablePasswordLogin: true
    });
    assert.strictEqual(prov.groupsClaim, 'groups');
    assert.strictEqual(prov.groupRoleMap['platform-admins'], 'admin');
    assert.strictEqual(oidc.isPasswordLoginDisabled(), true);

    const rAdmin = resolveRoleFromClaims(prov, { groups: ['readonly', 'devs', 'platform-admins'] });
    assert.strictEqual(rAdmin.role, 'admin');
    assert.strictEqual(rAdmin.source, 'group_map');
    const rDev = resolveRoleFromClaims(prov, { groups: ['devs', 'unknown-team'] });
    assert.strictEqual(rDev.role, 'developer');
    const rFallback = resolveRoleFromClaims(prov, { groups: ['other-org'] });
    assert.strictEqual(rFallback.role, 'viewer');
    assert.strictEqual(rFallback.source, 'default_role');

    // Nested Keycloak claim path (`realm_access.roles`) + tampered disk `owner` ignored
    const kcProv = { defaultRole: 'viewer', groupsClaim: 'realm_access.roles', groupRoleMap: { ops: 'developer', evil: 'owner' } };
    assert.strictEqual(resolveRoleFromClaims(kcProv, { realm_access: { roles: ['ops', 'evil'] } }).role, 'developer');
    assert.strictEqual(resolveRoleFromClaims(kcProv, { realm_access: { roles: ['evil'] } }).role, 'viewer');
  } finally {
    fs.rmSync(oidcTmp, { recursive: true, force: true });
  }

  // 7g. Cosmos#616 Auth Circuit-Breaker (`X-Culkibo-Auth-Circuit: backoff`), disablePasswordLogin HTTP 403 & Cycle-2 Lazy Routes
  {
    const httpTmp = makeTempDir('culkibo-cycle2-http-');
    const rootDir = path.resolve(__dirname, '..');
    const runnerPath = path.join(httpTmp, 'cycle2-http-runner.js');
    fs.writeFileSync(runnerPath, `
const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');

const TMP_DIR = ${JSON.stringify(httpTmp)};
const ROOT_DIR = ${JSON.stringify(rootDir)};
process.env.NODE_ENV = 'test';
process.env.CULKIBO_DATA_DIR = TMP_DIR;
process.env.CULKIBO_DISABLE_AUDIT_DISK = '1';

const express = require(path.join(ROOT_DIR, 'node_modules', 'express'));
const auth = require(path.join(ROOT_DIR, 'server/middleware/auth'));
const projectManager = require(path.join(ROOT_DIR, 'server/services/projectManager'));
const databaseManager = require(path.join(ROOT_DIR, 'server/services/databaseManager'));
const deployManager = require(path.join(ROOT_DIR, 'server/services/deployManager'));
const oidcService = require(path.join(ROOT_DIR, 'server/services/oidcService'));
const apiRouter = require(path.join(ROOT_DIR, 'server/routes/api'));

function reqJson(port, method, pth, { token, body } = {}) {
  return new Promise((resolve, reject) => {
    const raw = body !== undefined ? JSON.stringify(body) : null;
    const headers = { host: 'panel.example.test' };
    if (token) headers.authorization = 'Bearer ' + token;
    if (raw !== null) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = Buffer.byteLength(raw);
    }
    const r = http.request({ hostname: '127.0.0.1', port, method, path: pth, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch (e) {}
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    r.on('error', reject);
    if (raw !== null) r.write(raw);
    r.end();
  });
}

(async () => {
  const app = express();
  app.use(express.json());
  app.use('/api', auth.authMiddleware, apiRouter);
  const srv = await new Promise((res) => { const s = app.listen(0, '127.0.0.1', () => res(s)); });
  const port = srv.address().port;
  const master = auth.resolveToken();
  try {
    // Cosmos#616: repeated 401 on /auth/verify triggers X-Culkibo-Auth-Circuit: backoff
    const f1 = await reqJson(port, 'POST', '/api/auth/verify', { body: { token: 'bad_1' } });
    assert.strictEqual(f1.status, 401);
    const f2 = await reqJson(port, 'POST', '/api/auth/verify', { body: { token: 'bad_2' } });
    assert.strictEqual(f2.status, 401);
    assert.strictEqual(f2.headers['x-culkibo-auth-circuit'], 'backoff');
    assert.strictEqual(f2.json.authCircuit, 'backoff');
    const sessBackoff = await reqJson(port, 'GET', '/api/auth/session');
    assert.strictEqual(sessBackoff.headers['x-culkibo-auth-circuit'], 'backoff');

    // Valid verify clears circuit
    const okVerify = await reqJson(port, 'POST', '/api/auth/verify', { body: { token: master } });
    assert.strictEqual(okVerify.status, 200);
    const sessClean = await reqJson(port, 'GET', '/api/auth/session');
    assert.strictEqual(sessClean.headers['x-culkibo-auth-circuit'], undefined);

    // OIDC disablePasswordLogin blocks POST /api/auth/login with 403 PASSWORD_LOGIN_DISABLED
    oidcService.configureProvider({
      id: 'corp-sso',
      type: 'authentik',
      issuerUrl: 'https://sso.example.test/o/culkibo',
      clientId: 'cid_sso',
      redirectUri: 'https://panel.example.test/api/auth/oidc/callback',
      disablePasswordLogin: true
    });
    const pubProv = await reqJson(port, 'GET', '/api/auth/oidc/providers');
    assert.strictEqual(pubProv.status, 200);
    assert.strictEqual(pubProv.json.disablePasswordLogin, true);
    const blockedLogin = await reqJson(port, 'POST', '/api/auth/login', { body: { email: 'a@b.test', password: 'Password!123' } });
    assert.strictEqual(blockedLogin.status, 403);
    assert.strictEqual(blockedLogin.json.code, 'PASSWORD_LOGIN_DISABLED');

    // Cycle-2 Lazy Routes: SmartPack, DirectPush, EdgeTunnel, SnapStream, FastRestart, Preview DB Branching
    const proj = projectManager.create({ id: 'proj_c2_api', name: 'Cycle2 API', envVars: { A: '1' } });
    deployManager.store[proj.id] = {
      current: { id: 'd1', projectId: proj.id, containerName: 'c_old', imageTag: 'culkibo/c2:v1', hostPort: 21111, containerPort: 3000, hostnames: ['c2.example.test'], status: 'activo' },
      previous: null,
      history: []
    };

    const frRes = await reqJson(port, 'POST', '/api/projects/proj_c2_api/fast-restart', {
      token: master,
      body: { dryRun: true, envVars: { B: '2' } }
    });
    assert.strictEqual(frRes.status, 200, 'fast-restart dryRun failed: ' + frRes.text);
    assert.strictEqual(frRes.json.rebuilt, false);
    assert.strictEqual(frRes.json.dryRun, true);

    const brRes = await reqJson(port, 'POST', '/api/projects/proj_c2_api/previews/42/branch-db', {
      token: master,
      body: { engine: 'postgres', sourceDbName: 'app_prod', containerName: 'culkibo_pg_main' }
    });
    assert.strictEqual(brRes.status, 200, 'branch-db failed: ' + brRes.text);
    assert.ok(brRes.json.branchDbName || brRes.json.branchName || brRes.json.engine);

    const spRes = await reqJson(port, 'POST', '/api/build/smartpack/plan', {
      token: master,
      body: { files: { 'package.json': JSON.stringify({ name: 'demo', dependencies: { next: '15.0.0' }, scripts: { build: 'next build', start: 'next start' } }) } }
    });
    assert.strictEqual(spRes.status, 200, 'smartpack plan failed: ' + spRes.text);
    assert.ok(spRes.json.stack);

    const dpRes = await reqJson(port, 'POST', '/api/deploy/direct-push/plan', {
      token: master,
      body: { image: 'culkibo/c2:v1', serverId: 'srv_eu_1', localPort: 5055 }
    });
    assert.strictEqual(dpRes.status, 200, 'direct-push plan failed: ' + dpRes.text);

    const etCreate = await reqJson(port, 'POST', '/api/edge-tunnel/tunnels', {
      token: master,
      body: { name: 'HomeNAS', targetHost: '127.0.0.1', targetPort: 8080, hostname: 'nas.example.test' }
    });
    assert.strictEqual(etCreate.status, 201, 'edge-tunnel create failed: ' + etCreate.text);
    const tid = etCreate.json.id || (etCreate.json.tunnel && etCreate.json.tunnel.id);
    assert.ok(tid);
    const etStatus = await reqJson(port, 'GET', '/api/edge-tunnel/status', { token: master });
    assert.strictEqual(etStatus.status, 200);
    const etDel = await reqJson(port, 'DELETE', '/api/edge-tunnel/tunnels/' + encodeURIComponent(tid), { token: master });
    assert.strictEqual(etDel.status, 200);

    // SnapStream SQLite capture & listGenerations
    const sqliteFile = path.join(TMP_DIR, 'sample.sqlite');
    fs.writeFileSync(sqliteFile, Buffer.from('SQLite format 3\0' + 'x'.repeat(256)));
    databaseManager.dataFile = path.join(TMP_DIR, 'databases.json');
    databaseManager.state = {
      databases: [{
        id: 'db_sqlite_c2',
        projectId: proj.id,
        engine: 'sqlite',
        name: 'SnapDB',
        username: '',
        dbName: 'snap',
        port: 0,
        containerName: 'none',
        volumeName: 'none',
        networkName: 'none',
        status: 'running',
        health: 'healthy',
        exposure: { enabled: false, bindAddress: '127.0.0.1', hostPort: null },
        schedule: { enabled: false, cron: null, nextRunAt: null, lastRunAt: null, lastStatus: null },
        retention: { keepLast: 7 },
        backups: [],
        restoreHistory: [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      }],
      s3: null
    };
    const encKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const snapCap = await reqJson(port, 'POST', '/api/databases/db_sqlite_c2/snapstream/capture', {
      token: master,
      body: { dbPath: sqliteFile, encryptionKey: encKey, destDir: path.join(TMP_DIR, 'snap-out') }
    });
    assert.strictEqual(snapCap.status, 201, 'snapstream capture failed: ' + snapCap.text);
    const snapList = await reqJson(port, 'GET', '/api/databases/db_sqlite_c2/snapstream/generations?destDir=' + encodeURIComponent(path.join(TMP_DIR, 'snap-out')), {
      token: master
    });
    assert.strictEqual(snapList.status, 200, 'snapstream generations failed: ' + snapList.text);
    assert.ok(Array.isArray(snapList.json.generations) && snapList.json.generations.length >= 1);

    // Cycle-4 Lazy Routes: version sync, OTLP, SLSA v1.1 DSSE Attestation, Migrations Plan, Micro-Wasm, PR Schema Isolation
    const sysSt = await reqJson(port, 'GET', '/api/system/status', { token: master });
    assert.strictEqual(sysSt.status, 200);
    const pkgVer = require(path.join(ROOT_DIR, 'package.json')).version;
    assert.strictEqual(sysSt.json.version, pkgVer, 'GET /api/system/status debe reportar la versión dinámica de package.json');

    const otlpGet = await reqJson(port, 'GET', '/api/observability/otlp', { token: master });
    assert.strictEqual(otlpGet.status, 200, 'GET /api/observability/otlp failed: ' + otlpGet.text);
    const otlpPut = await reqJson(port, 'PUT', '/api/observability/otlp', {
      token: master,
      body: { enabled: false, serviceName: 'culkibo-c4-test' }
    });
    assert.strictEqual(otlpPut.status, 200, 'PUT /api/observability/otlp failed: ' + otlpPut.text);
    assert.strictEqual(otlpPut.json.serviceName, 'culkibo-c4-test');
    const otlpFlush = await reqJson(port, 'POST', '/api/observability/otlp/flush', { token: master, body: {} });
    assert.strictEqual(otlpFlush.status, 200, 'POST /api/observability/otlp/flush failed: ' + otlpFlush.text);
    assert.strictEqual(otlpFlush.json.skipped, true);

    const attPost = await reqJson(port, 'POST', '/api/projects/proj_c2_api/releases/v1.0.0/attest', {
      token: master,
      body: { imageDigest: 'sha256:' + 'a'.repeat(64), commitSha: '0123456789abcdef0123456789abcdef01234567' }
    });
    assert.strictEqual(attPost.status, 201, 'POST release attest failed: ' + attPost.text);
    assert.ok(attPost.json.envelope && attPost.json.statement, 'POST release attest debe devolver envelope y statement');
    const attGet = await reqJson(port, 'GET', '/api/projects/proj_c2_api/releases/v1.0.0/attestation', { token: master });
    assert.strictEqual(attGet.status, 200, 'GET release attestation failed: ' + attGet.text);
    assert.strictEqual(attGet.json.revision, 'v1.0.0');
    assert.ok(attGet.json.verification && attGet.json.verification.valid, 'GET release attestation debe incluir verification.valid=true');
    const attVerify = await reqJson(port, 'POST', '/api/security/attestation/verify', {
      token: master,
      body: { envelope: attPost.json.envelope }
    });
    assert.strictEqual(attVerify.status, 200, 'POST attestation verify failed: ' + attVerify.text);
    assert.strictEqual(attVerify.json.valid, true);

    const migPlan = await reqJson(port, 'POST', '/api/projects/proj_c2_api/migrations/plan', {
      token: master,
      body: { command: 'npx prisma migrate deploy' }
    });
    assert.strictEqual(migPlan.status, 200, 'POST migrations/plan failed: ' + migPlan.text);
    assert.strictEqual(migPlan.json.abortCutoverOnFailure, true);
    assert.strictEqual(migPlan.json.zeroShell, true);

    const { buildMinimalHttpTestWasm } = require(path.join(ROOT_DIR, 'server/services/wasmMicroRunner'));
    const wasmRes = await reqJson(port, 'POST', '/api/projects/proj_c2_api/wasm/invoke', {
      token: master,
      body: { wasmBase64: buildMinimalHttpTestWasm().toString('base64'), exportName: 'handle', args: [21] }
    });
    assert.strictEqual(wasmRes.status, 200, 'POST wasm/invoke failed: ' + wasmRes.text);
    assert.strictEqual(wasmRes.json.status, 200);
    assert.strictEqual(typeof wasmRes.json.execMs, 'number');

    const schemaIso = await reqJson(port, 'POST', '/api/projects/proj_c2_api/previews/42/schema-isolation', {
      token: master,
      body: { engine: 'postgres', dbName: 'app_prod', containerName: 'culkibo_pg_main', databaseUrl: 'postgres://app:secretpass@127.0.0.1:5432/app_prod' }
    });
    assert.strictEqual(schemaIso.status, 200, 'POST schema-isolation failed: ' + schemaIso.text);
    assert.strictEqual(schemaIso.json.schemaName, 'pr_42');

    // Cycle-6 Lazy Routes: Shadow Replay, Whole-Stack Time-Machine, FinOps Optimizer
    const tmCreate1 = await reqJson(port, 'POST', '/api/projects/proj_c2_api/timemachine', {
      token: master,
      body: { label: 'pre-release-1' }
    });
    assert.strictEqual(tmCreate1.status, 201, 'POST timemachine #1 failed: ' + tmCreate1.text);
    const cp1Id = tmCreate1.json.id || (tmCreate1.json.checkpoint && tmCreate1.json.checkpoint.id);
    assert.ok(cp1Id, 'Expected checkpoint id from POST /timemachine');

    projectManager.update('proj_c2_api', { memoryMb: 2048 });
    const tmCreate2 = await reqJson(port, 'POST', '/api/projects/proj_c2_api/timemachine', {
      token: master,
      body: { label: 'post-scale-2' }
    });
    assert.strictEqual(tmCreate2.status, 201, 'POST timemachine #2 failed: ' + tmCreate2.text);
    const cp2Id = tmCreate2.json.id || (tmCreate2.json.checkpoint && tmCreate2.json.checkpoint.id);

    const tmList = await reqJson(port, 'GET', '/api/projects/proj_c2_api/timemachine', { token: master });
    assert.strictEqual(tmList.status, 200);
    assert.ok(Array.isArray(tmList.json.checkpoints) && tmList.json.checkpoints.length >= 2);

    const tmDiff = await reqJson(port, 'GET', '/api/projects/proj_c2_api/timemachine/diff?from=' + encodeURIComponent(cp1Id) + '&to=' + encodeURIComponent(cp2Id), { token: master });
    assert.strictEqual(tmDiff.status, 200, 'GET timemachine/diff failed: ' + tmDiff.text);

    const tmRestoreDry = await reqJson(port, 'POST', '/api/projects/proj_c2_api/timemachine/' + encodeURIComponent(cp1Id) + '/restore', {
      token: master,
      body: { dryRun: true }
    });
    assert.strictEqual(tmRestoreDry.status, 200, 'POST timemachine restore dryRun failed: ' + tmRestoreDry.text);
    assert.strictEqual(tmRestoreDry.json.dryRun, true);

    const finRep = await reqJson(port, 'GET', '/api/finops/report', { token: master });
    assert.strictEqual(finRep.status, 200, 'GET /api/finops/report failed: ' + finRep.text);
    const finCmp = await reqJson(port, 'POST', '/api/finops/compare', {
      token: master,
      body: { apps: 4, databases: 2 }
    });
    assert.strictEqual(finCmp.status, 200, 'POST /api/finops/compare failed: ' + finCmp.text);

    const srSrv = await new Promise((resolve) => {
      const s = http.createServer((_rq, rs) => {
        rs.writeHead(200, { 'Content-Type': 'application/json' });
        rs.end(JSON.stringify({ ok: true, status: 'healthy' }));
      });
      s.listen(0, '127.0.0.1', () => resolve(s));
    });
    try {
      const srPort = srSrv.address().port;
      const srRes = await reqJson(port, 'POST', '/api/projects/proj_c2_api/shadow-replay', {
        token: master,
        body: {
          baselineOrigin: 'http://127.0.0.1:' + srPort,
          candidateOrigin: 'http://127.0.0.1:' + srPort,
          allowLoopback: true,
          requests: [{ method: 'GET', path: '/health' }]
        }
      });
      assert.strictEqual(srRes.status, 200, 'POST shadow-replay failed: ' + srRes.text);
      assert.strictEqual(srRes.json.verdict, 'PROMOTE');
      const srHist = await reqJson(port, 'GET', '/api/projects/proj_c2_api/shadow-replay/history', { token: master });
      assert.strictEqual(srHist.status, 200);
      assert.ok(Array.isArray(srHist.json.replays) && srHist.json.replays.length >= 1);
    } finally {
      await new Promise((r) => srSrv.close(r));
    }

    // Cycle-7 Lazy Routes: Fleet Mesh, Cron Timeline + Heartbeats, Edge Shield Challenge, Build Healer, Container Terminal Ticket
    const meshRes = await reqJson(port, 'GET', '/api/fleet/mesh', { token: master });
    assert.strictEqual(meshRes.status, 200, 'GET /api/fleet/mesh failed: ' + meshRes.text);
    assert.strictEqual(meshRes.json.cidr, '10.88.0.0/24');
    assert.ok(!meshRes.text.includes('BEGIN PRIVATE KEY'), 'Mesh API must never expose private keys');

    const tlRes = await reqJson(port, 'GET', '/api/crons/timeline?hours=24', { token: master });
    assert.strictEqual(tlRes.status, 200, 'GET /api/crons/timeline failed: ' + tlRes.text);
    assert.strictEqual(tlRes.json.hours, 24);
    assert.strictEqual(tlRes.json.slots.length, 24);

    const shieldChal = await reqJson(port, 'GET', '/api/edge-shield/challenge?format=json&domain=app.example.test', { token: master });
    assert.strictEqual(shieldChal.status, 200, 'GET /api/edge-shield/challenge failed: ' + shieldChal.text);
    assert.ok(shieldChal.json.challengeId && shieldChal.json.salt);

    const healDiag = await reqJson(port, 'POST', '/api/projects/proj_c2_api/build-healer/diagnose', {
      token: master,
      body: { logs: 'FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory' }
    });
    assert.strictEqual(healDiag.status, 200, 'POST build-healer/diagnose failed: ' + healDiag.text);
    assert.strictEqual(healDiag.json.matched, true);
    assert.strictEqual(healDiag.json.primary.code, 'NODE_HEAP_OOM');

    const healApply = await reqJson(port, 'POST', '/api/projects/proj_c2_api/build-healer/apply', {
      token: master,
      body: { logs: 'FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory', dryRun: true }
    });
    assert.strictEqual(healApply.status, 200, 'POST build-healer/apply failed: ' + healApply.text);
    assert.strictEqual(healApply.json.dryRun, true, 'build-healer/apply must await async applyHealingPlan and return dryRun=true');
    assert.ok(healApply.json.patchPlan && typeof healApply.json.patchPlan === 'object', 'build-healer/apply must return populated patchPlan');

    const termTicket = await reqJson(port, 'POST', '/api/projects/proj_c2_api/terminal/ticket', {
      token: master,
      body: { shell: '/bin/sh', cols: 100, rows: 30 }
    });
    assert.strictEqual(termTicket.status, 201, 'POST terminal/ticket failed: ' + termTicket.text);
    assert.ok(termTicket.json.ticket && String(termTicket.json.wsPath || '').startsWith('/ws/terminal?ticket='));

    console.log('CYCLE2_HTTP_OK');
  } finally {
    await new Promise((r) => srv.close(r));
  }
})().catch((err) => { console.error(err); process.exit(1); });
`, 'utf8');
    try {
      const out = execFileSync(process.execPath, [runnerPath], { cwd: rootDir, encoding: 'utf8', timeout: 30000 });
      assert.ok(out.includes('CYCLE2_HTTP_OK'), `Cycle-2/4 HTTP check failed:\n${out}`);
    } finally {
      fs.rmSync(httpTmp, { recursive: true, force: true });
    }
  }
  console.log('  ✓ Cycle #2/#4: CULKIBO_DATA_DIR, coolify#12414 Compose limits, dokploy#2547 FastRestart, Cosmos#591/#616, runtipi#2445 cgroup v2, OIDC groups & lazy routes');

  // -------------------------------------------------------------------------
  // 8. Wave-3 Competitor-CVE Guardrails (Cycle #4: 8a - 8f)
  // -------------------------------------------------------------------------

  // 8a. coolify#10996/#12542 & kamal#1655: Protected/sleeping container label + prune exclusion + BuildKit --keep-storage cap
  {
    const dmProt = new DeployManager();
    dmProt.store = {};
    dmProt.saveStore = () => {};
    dmProt.notify = () => {};
    dmProt.detectDocker = async () => ({ available: true, version: '27.0.0', reason: null });

    const protectedRunArgs = dmProt.runArgs({
      containerName: 'culkibo_sleep_demo',
      imageTag: 'culkibo/sleep:v1',
      hostPort: 23456,
      containerPort: 3000,
      protectedContainer: true,
      sleeping: true
    });
    assert.ok(protectedRunArgs.includes('culkibo.protected=1'), 'runArgs debe etiquetar culkibo.protected=1 en contenedores protegidos/dormidos');
    assert.ok(protectedRunArgs.includes('culkibo.sleeping=1'), 'runArgs debe etiquetar culkibo.sleeping=1 en contenedores dormidos');

    const safeContainerPrune = buildSafePruneArgs('container', { untilHours: 24 });
    assert.ok(safeContainerPrune.includes('label!=culkibo.protected=1'), 'container prune debe excluir label!=culkibo.protected=1');
    const safeImagePrune = buildSafePruneArgs('image', { projectId: 'proj_w3' });
    assert.ok(safeImagePrune.includes('label!=culkibo.protected=1'), 'image prune debe excluir label!=culkibo.protected=1');

    /** @type {string[][]} */
    const seenDockerCalls = [];
    /** @type {string[]} */
    const removedInPrune = [];
    dmProt.store['proj_w3'] = {
      current: { containerName: 'c_cur', imageTag: 'culkibo/proj_w3:v3' },
      previous: { containerName: 'c_prev', imageTag: 'culkibo/proj_w3:v2' },
      history: []
    };
    dmProt.runDocker = async (args) => {
      seenDockerCalls.push(args);
      if (args[0] === 'ps' && args.some((a) => a.includes('com.culkibo.project_id='))) {
        return {
          code: 0,
          stdout: [
            'c_cur||||',
            'c_sleeping|||1|1',
            'c_protected_only|||1|',
            'c_unprotected_stale||||'
          ].join('\n'),
          stderr: ''
        };
      }
      if (args[0] === 'ps') return { code: 0, stdout: '', stderr: '' };
      if (args[0] === 'images') return { code: 0, stdout: '', stderr: '' };
      if (args[0] === 'rm') removedInPrune.push(args[args.length - 1]);
      return { code: 0, stdout: 'Total reclaimed space: 500MB', stderr: '' };
    };

    const pruneRes = await dmProt.pruneOldReleases('proj_w3', 2);
    assert.deepStrictEqual(removedInPrune, ['c_unprotected_stale'], 'pruneOldReleases JAMÁS debe borrar contenedores culkibo.protected=1 o culkibo.sleeping=1');
    assert.deepStrictEqual(pruneRes.removed, ['c_unprotected_stale']);
    assert.ok(
      seenDockerCalls.some((a) => a[0] === 'image' && a[1] === 'prune' && a.includes('label!=culkibo.protected=1')),
      'docker image prune debe incluir --filter label!=culkibo.protected=1'
    );

    /** @type {string[] | null} */
    let capturedBuilderPrune = null;
    dmProt.runDocker = async (args) => { capturedBuilderPrune = args; return { code: 0, stdout: 'ok', stderr: '' }; };
    const cappedRes = await dmProt.pruneBuildCache({ keepStorageGb: 80 });
    assert.strictEqual(cappedRes.ok, true);
    assert.strictEqual(cappedRes.capped, true);
    assert.strictEqual(cappedRes.keepStorageGb, MAX_BUILDKIT_KEEP_STORAGE_GB);
    assert.ok(
      capturedBuilderPrune && capturedBuilderPrune.includes(`${MAX_BUILDKIT_KEEP_STORAGE_GB}GB`),
      'pruneBuildCache debe acotar --keep-storage al tope seguro anti-bloat'
    );
  }

  // 8b. Dokploy BullMQ deadlock: Stale deploy-lock auto-recovery (dead PID & expired TTL)
  {
    const lockTmp = makeTempDir('culkibo-deploy-lock-');
    try {
      const dmLock = new DeployManager();
      dmLock.saveStore = () => {};
      const reapedEvents = [];
      dmLock.on('stale_lock_reaped', (ev) => reapedEvents.push(ev));

      // Lock vivo bloquea a un segundo competidor con 409 DEPLOY_LOCKED
      const l1 = dmLock.acquireDeployLock('proj_lock_1', {
        ownerId: 'worker_alive',
        pid: process.pid,
        ttlMs: 60000,
        lockDir: lockTmp
      });
      assert.strictEqual(l1.acquired, true);
      assert.throws(
        () => dmLock.acquireDeployLock('proj_lock_1', { ownerId: 'worker_b', lockDir: lockTmp }),
        (err) => err && err.code === 'DEPLOY_LOCKED' && err.status === 409,
        'Un lock vivo debe bloquear despliegues concurrentes con 409 DEPLOY_LOCKED'
      );

      // PID muerto -> auto-reap automático y nueva adquisición inmediata
      const reapedDead = dmLock.acquireDeployLock('proj_lock_1', {
        ownerId: 'worker_recovered_pid',
        pid: process.pid,
        ttlMs: 60000,
        lockDir: lockTmp,
        isPidAlive: () => false
      });
      assert.strictEqual(reapedDead.acquired, true);
      assert.strictEqual(reapedDead.reapedStale, true);
      assert.strictEqual(reapedDead.reapedReason, 'dead_pid');

      // TTL expirado -> auto-reap automático incluso si el PID sigue vivo
      const futureNow = Date.now() + 120000;
      const reapedTtl = dmLock.acquireDeployLock('proj_lock_1', {
        ownerId: 'worker_recovered_ttl',
        pid: process.pid,
        ttlMs: 60000,
        nowMs: futureNow,
        lockDir: lockTmp,
        isPidAlive: () => true
      });
      assert.strictEqual(reapedTtl.acquired, true);
      assert.strictEqual(reapedTtl.reapedStale, true);
      assert.strictEqual(reapedTtl.reapedReason, 'ttl_expired');
      assert.strictEqual(reapedEvents.length, 2);

      // Lockfile huérfano en disco dejado por un proceso caído -> recuperado en nueva instancia
      const dmFresh = new DeployManager();
      dmFresh.saveStore = () => {};
      const orphanReap = dmFresh.reapStaleDeployLock('proj_lock_1', {
        lockDir: lockTmp,
        isPidAlive: () => false
      });
      assert.strictEqual(orphanReap.reaped, true);
      assert.strictEqual(orphanReap.reason, 'dead_pid');
      dmLock.releaseDeployLock('proj_lock_1', null, { lockDir: lockTmp });
    } finally {
      fs.rmSync(lockTmp, { recursive: true, force: true });
    }
  }

  // 8c. portainer#13298: GitOps symlink rejection (file + parent dir) & pinned commitSha preservation across manual redeploys
  {
    const gitTmp = makeTempDir('culkibo-gitops-w3-');
    try {
      const repoDir = path.join(gitTmp, 'repo');
      const outsideDir = path.join(gitTmp, 'outside');
      fs.mkdirSync(repoDir, { recursive: true });
      fs.mkdirSync(outsideDir, { recursive: true });
      const secretOutside = path.join(outsideDir, 'secret.yaml');
      fs.writeFileSync(secretOutside, 'version: 1\nname: stolen\n', 'utf8');

      const mockProjects = new Map();
      const gm = new GitOpsManager({
        dataDir: path.join(gitTmp, 'state'),
        projectManager: {
          getAll: () => Array.from(mockProjects.values()),
          getById: (id) => mockProjects.get(id) || null,
          create: (data) => {
            const p = { id: data.id || `p_${mockProjects.size + 1}`, ...data };
            mockProjects.set(p.id, p);
            return p;
          },
          update: (id, patch) => {
            const cur = mockProjects.get(id);
            const next = { ...cur, ...patch };
            mockProjects.set(id, next);
            return next;
          },
          delete: (id) => mockProjects.delete(id)
        },
        domainManager: { getAll: () => [], list: () => [], addDomain: async () => {}, deleteDomain: async () => {} },
        cronManager: { list: () => [], create: () => ({ id: 'c1' }), update: () => {}, remove: () => {} },
        databaseManager: { list: () => [] },
        environmentManager: { listEnvironments: () => [], upsertEnvironment: () => {}, deleteEnvironment: () => {} },
        ingressManager: { reconcile: async () => {} },
        uptimeMonitor: { listMonitors: () => [] },
        auditLogger: { record: () => {} }
      });

      // Rechazo de symlink directo fuera del repo y directorio padre symlink
      let symlinkCreated = false;
      try {
        fs.symlinkSync(secretOutside, path.join(repoDir, 'culkibo.yaml'));
        fs.symlinkSync(outsideDir, path.join(repoDir, 'linked-dir'), process.platform === 'win32' ? 'junction' : 'dir');
        symlinkCreated = true;
      } catch (e) {
        try {
          fs.symlinkSync(outsideDir, path.join(repoDir, 'linked-dir'), 'junction');
          symlinkCreated = true;
        } catch (_) {}
      }
      if (symlinkCreated) {
        if (fs.existsSync(path.join(repoDir, 'culkibo.yaml'))) {
          assert.throws(
            () => gm.readRepoManifestSafe(repoDir, 'culkibo.yaml'),
            (err) => err && (err.code === 'GITOPS_SYMLINK_FORBIDDEN' || /symlink|enlace simbólico/i.test(err.message)),
            'readRepoManifestSafe debe rechazar culkibo.yaml symlink fuera del repo'
          );
        }
        if (fs.existsSync(path.join(repoDir, 'linked-dir'))) {
          assert.throws(
            () => gm.readRepoManifestSafe(repoDir, 'linked-dir/secret.yaml'),
            (err) => err && (err.code === 'GITOPS_SYMLINK_FORBIDDEN' || /symlink|enlace simbólico/i.test(err.message)),
            'readRepoManifestSafe debe rechazar directorios intermedios symlink'
          );
        }
      }

      // Preservación de pinnedCommitSha tras redeploy manual y reapply sin commitSha
      const pinnedSha = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
      const stackYaml = [
        'version: 1',
        'name: prod-stack',
        'projects:',
        '  - id: proj_gitops_w3',
        '    name: Web W3',
        '    gitRepo: https://github.com/acme/web-w3.git',
        '    gitBranch: main'
      ].join('\n');

      const applied1 = await gm.applyStack(stackYaml, {
        stackId: 'prod-stack',
        commitSha: pinnedSha,
        branch: 'main',
        actor: 'webhook:github'
      });
      assert.strictEqual(applied1.pinnedCommitSha, pinnedSha);

      const manualRes = gm.recordManualRedeploy('prod-stack', { actor: 'admin@acme.test', reason: 'hotfix restart' });
      assert.strictEqual(manualRes.pinnedCommitSha, pinnedSha, 'recordManualRedeploy debe preservar pinnedCommitSha intacto');
      assert.strictEqual(manualRes.preservedCommitSha, true);
      assert.strictEqual(manualRes.manualRedeployCount, 1);

      const applied2 = await gm.applyStack(stackYaml, { stackId: 'prod-stack', actor: 'operator' });
      assert.strictEqual(applied2.pinnedCommitSha, pinnedSha, 'applyStack sin commitSha no debe borrar pinnedCommitSha');

      const drift = gm.detectDrift('prod-stack');
      assert.strictEqual(drift.drifted, false, 'Un redeploy manual no debe corromper el estado GitOps ni inducir drift');
      assert.strictEqual(drift.pinnedCommitSha, pinnedSha);
    } finally {
      fs.rmSync(gitTmp, { recursive: true, force: true });
    }
  }

  // 8d. portainer#13139 & dokploy#4898: <=300s replay timestamp window, NEVER 204 on failed sync deploy, strict token redaction
  {
    const nowSec = Math.floor(Date.now() / 1000);
    assert.strictEqual(webhookService.validateWebhookTimestamp({ headers: {} }).skipped, true);
    assert.strictEqual(webhookService.validateWebhookTimestamp({ headers: { 'x-webhook-timestamp': String(nowSec - 45) } }).valid, true);
    const staleTs = webhookService.validateWebhookTimestamp({ headers: { 'x-webhook-timestamp': String(nowSec - 601) } });
    assert.strictEqual(staleTs.valid, false);
    assert.strictEqual(staleTs.status, 401);
    assert.strictEqual(staleTs.code, 'WEBHOOK_REPLAY_EXPIRED');

    const rawHookToken = 'ckh_9f8e7d6c5b4a3210fedcba9876543210abcdef12345678';
    const rawGhToken = 'ghp_SuperSecretGitHubToken998877665544';
    const redacted = webhookService.redactWebhookSecrets(
      `Deploy failed with token=${rawHookToken} Authorization: Bearer ${rawGhToken} glpat-SecretGitLab12345`,
      [rawHookToken]
    );
    assert.ok(!redacted.includes(rawHookToken) && !redacted.includes('ckh_9f8e'), 'No debe filtrar ni el token ni su prefijo');
    assert.ok(!redacted.includes(rawGhToken) && !redacted.includes('ghp_'), 'No debe filtrar prefijo ghp_');
    assert.ok(!redacted.includes('glpat-'), 'No debe filtrar prefijo glpat-');

    const hookProj = projectManager.create({
      name: 'W3 Webhook Guard Proj',
      gitRepo: 'https://gitlab.example.test/acme/w3-hook.git',
      gitBranch: 'main',
      webhookSecret: 'gl_secret_w3_999',
      deployHookToken: rawHookToken
    });
    const deployMgr = require('../server/services/deployManager');
    const origDetect = deployMgr.detectDocker;
    const origEnqueue = deployMgr.enqueue;
    try {
      const expiredHook = await webhookService.handleDeployHook({
        params: { projectId: hookProj.id },
        headers: {
          authorization: `Bearer ${rawHookToken}`,
          'x-webhook-timestamp': String(nowSec - 900)
        },
        query: {},
        body: {}
      });
      assert.strictEqual(expiredHook.status, 401);
      assert.strictEqual(expiredHook.body.code, 'WEBHOOK_REPLAY_EXPIRED');

      const expiredGl = await webhookService.handleGitLabWebhook({
        headers: {
          'x-gitlab-token': 'gl_secret_w3_999',
          'x-gitlab-event': 'Push Hook',
          'x-gitlab-event-timestamp': new Date(Date.now() - 400 * 1000).toISOString()
        },
        query: { projectId: hookProj.id },
        body: { ref: 'refs/heads/main', after: '1111111111111111111111111111111111111111', commits: [] }
      });
      assert.strictEqual(expiredGl.status, 401);
      assert.strictEqual(expiredGl.body.code, 'WEBHOOK_REPLAY_EXPIRED');

      deployMgr.detectDocker = async () => ({ available: true, version: '27.0.0' });
      deployMgr.enqueue = () => ({
        started: true,
        queued: false,
        promise: Promise.resolve({
          status: 'fallido',
          error: `Container failed auth with ${rawHookToken}`
        })
      });
      const failedSync = await webhookService.handleDeployHook({
        params: { projectId: hookProj.id },
        headers: {
          authorization: `Bearer ${rawHookToken}`,
          'x-webhook-timestamp': String(nowSec)
        },
        query: {},
        body: { sync: true }
      });
      assert.notStrictEqual(failedSync.status, 204, 'Un deploy fallido JAMÁS puede devolver HTTP 204');
      assert.strictEqual(failedSync.status, 502);
      assert.strictEqual(failedSync.body.success, false);
      assert.strictEqual(failedSync.body.code, 'DEPLOY_FAILED');
      assert.ok(!JSON.stringify(failedSync.body).includes(rawHookToken) && !JSON.stringify(failedSync.body).includes('ckh_9f8e'), 'La respuesta de error jamás debe filtrar tokens ni prefijos');
    } finally {
      deployMgr.detectDocker = origDetect;
      deployMgr.enqueue = origEnqueue;
      projectManager.delete(hookProj.id);
    }
  }

  // 8e. arcane#3855/#1485/#3620 & Cosmos#625: OIDC 5s JWKS timeout + stale-while-revalidate cached JWKS fallback
  {
    const oidcW3Tmp = makeTempDir('culkibo-oidc-jwks-w3-');
    try {
      const oidc = new OidcService({ dataDir: oidcW3Tmp });
      const prov = { id: 'corp-idp', allowInsecureLocal: true };
      const jwksUri = 'https://idp.example.test/.well-known/jwks.json';
      const staleEvents = [];
      oidc.on('jwks_stale_fallback', (ev) => staleEvents.push(ev));

      const t0 = Date.now();
      await assert.rejects(
        () => oidc._getJwks(prov, jwksUri, {
          timeoutMs: 120,
          fetchImpl: () => new Promise(() => {})
        }),
        (err) => err && err.code === 'OIDC_JWKS_TIMEOUT' && err.status === 502,
        'Debe cortar con OIDC_JWKS_TIMEOUT cuando el IdP JWKS se cuelga'
      );
      assert.ok(Date.now() - t0 < 1500, 'El timeout de JWKS debe dispararse en tiempo acotado');

      const cachedKeys = { keys: [{ kty: 'RSA', kid: 'kid-stale-1', n: 'abc', e: 'AQAB' }] };
      oidc.jwksCache.set(prov.id, { at: Date.now() - (20 * 60 * 1000), jwks: cachedKeys });
      const fallbackJwks = await oidc._getJwks(prov, jwksUri, {
        timeoutMs: 120,
        fetchImpl: () => new Promise(() => {})
      });
      assert.deepStrictEqual(fallbackJwks, cachedKeys, 'Debe servir JWKS cacheado (stale-while-revalidate) si el IdP tarda o cae');
      assert.strictEqual(staleEvents.length, 1);
      assert.strictEqual(staleEvents[0].reason, 'OIDC_JWKS_TIMEOUT');
    } finally {
      fs.rmSync(oidcW3Tmp, { recursive: true, force: true });
    }
  }

  // 8f. Clean English default local node name in ServerFleetManager + Cycle-6 container graceful stop-timeout & bounded log rotation
  {
    const fleetTmp = makeTempDir('culkibo-fleet-name-');
    try {
      const fleet = new ServerFleetManager({ dataDir: fleetTmp });
      const localNode = fleet._buildVirtualLocalServer();
      assert.strictEqual(localNode.name, 'Local Server (Primary)', 'El nodo local por defecto debe llamarse Local Server (Primary)');
    } finally {
      fs.rmSync(fleetTmp, { recursive: true, force: true });
    }

    // Cycle-6: --stop-timeout (default 30s, clamped 5..300s) & bounded --log-opt max-size/max-file anti-disk-fill guard
    const dmLife = new DeployManager();
    dmLife.saveStore = () => {};
    const defArgs = dmLife.runArgs({
      containerName: 'c_life_def',
      imageTag: 'culkibo/life:v1',
      hostPort: 23500,
      containerPort: 3000
    });
    const defJoined = defArgs.join(' ');
    assert.ok(defJoined.includes('--stop-timeout 30'), 'runArgs debe fijar --stop-timeout 30 por defecto');
    assert.ok(defJoined.includes('--log-driver json-file'), 'runArgs debe fijar --log-driver json-file');
    assert.ok(defJoined.includes('--log-opt max-size=10m'), 'runArgs debe acotar log max-size=10m por defecto');
    assert.ok(defJoined.includes('--log-opt max-file=3'), 'runArgs debe acotar log max-file=3 por defecto');

    const customArgs = dmLife.runArgs({
      containerName: 'c_life_custom',
      imageTag: 'culkibo/life:v2',
      hostPort: 23501,
      containerPort: 3000,
      stopGracePeriodSec: 90,
      logMaxSizeMb: 25,
      logMaxFiles: 5
    });
    const customJoined = customArgs.join(' ');
    assert.ok(customJoined.includes('--stop-timeout 90'));
    assert.ok(customJoined.includes('--log-opt max-size=25m'));
    assert.ok(customJoined.includes('--log-opt max-file=5'));

    // Bounds clamping: out-of-range values clamped safely (5..300s, 1..500m, 1..20 files)
    const clampedLow = dmLife.runArgs({
      containerName: 'c_life_lo',
      imageTag: 'culkibo/life:v3',
      hostPort: 23502,
      containerPort: 3000,
      stopGracePeriodSec: 1,
      logMaxSizeMb: 0,
      logMaxFiles: 0
    }).join(' ');
    assert.ok(clampedLow.includes('--stop-timeout 5'));
    assert.ok(clampedLow.includes('--log-opt max-size=1m'));
    assert.ok(clampedLow.includes('--log-opt max-file=1'));

    const clampedHigh = dmLife.runArgs({
      containerName: 'c_life_hi',
      imageTag: 'culkibo/life:v4',
      hostPort: 23503,
      containerPort: 3000,
      stopGracePeriodSec: 9999,
      logMaxSizeMb: 9999,
      logMaxFiles: 999
    }).join(' ');
    assert.ok(clampedHigh.includes('--stop-timeout 300'));
    assert.ok(clampedHigh.includes('--log-opt max-size=500m'));
    assert.ok(clampedHigh.includes('--log-opt max-file=20'));

    // Graceful cutover drain passes `docker stop -t <sec>`
    /** @type {string[] | null} */
    let capturedStopArgs = null;
    dmLife.runDocker = async (args) => {
      if (args[0] === 'stop') capturedStopArgs = args;
      return { code: 0, stdout: '', stderr: '' };
    };
    dmLife.store = {
      proj_life: {
        current: { containerName: 'c_new_active' },
        previous: { containerName: 'c_old_grace' },
        history: []
      }
    };
    dmLife.pruneOldReleases = async () => ({ removed: [], removedImages: [], keep: 2 });
    const keepLoop = setInterval(() => {}, 50);
    try {
      await dmLife.drainAndRetire(
        { projectId: 'proj_life', logLines: [] },
        { containerName: 'c_old_grace', serverId: 'local' },
        { drainTimeoutMs: 5, stopGracePeriodSec: 45 }
      );
    } finally {
      clearInterval(keepLoop);
    }
    assert.deepStrictEqual(capturedStopArgs, ['stop', '--timeout', '45', 'c_old_grace'], 'drainAndRetire debe pasar docker stop --timeout <sec> (Coolify #10791 / Dokploy #2227)');

    // Cycle-7 CVE Regressions (from docs/COMPETITOR_RADAR_CYCLE6.md §3):
    // 9a. Kamal #1709: Omit --log-opt max-size/max-file on syslog/journald log drivers
    const syslogArgs = dmLife.runArgs({
      containerName: 'c_syslog',
      imageTag: 'culkibo/life:v5',
      hostPort: 23505,
      containerPort: 3000,
      logDriver: 'syslog'
    });
    assert.ok(syslogArgs.includes('--log-driver') && syslogArgs.includes('syslog'));
    assert.ok(!syslogArgs.some((a) => a.includes('max-size=') || a.includes('max-file=')), 'syslog driver MUST NOT receive max-size/max-file log-opts (Kamal #1709)');
    const journaldArgs = dmLife.runArgs({
      containerName: 'c_journald',
      imageTag: 'culkibo/life:v6',
      hostPort: 23506,
      containerPort: 3000,
      logDriver: 'journald'
    });
    assert.ok(!journaldArgs.some((a) => a.includes('max-size=') || a.includes('max-file=')), 'journald driver MUST NOT receive max-size/max-file log-opts');
    const localArgs = dmLife.runArgs({
      containerName: 'c_local_log',
      imageTag: 'culkibo/life:v7',
      hostPort: 23507,
      containerPort: 3000,
      logDriver: 'local'
    }).join(' ');
    assert.ok(localArgs.includes('--log-driver local') && localArgs.includes('--log-opt max-size=10m'));

    // 9b. Dokploy #6028: Deterministic per-project isolated bridge network (prevents cross-project DNS collision)
    const netA = getProjectNetworkName('proj_alpha_1');
    const netB = getProjectNetworkName('proj_beta_2');
    assert.strictEqual(netA, 'culkibo-net-proj_alpha_1');
    assert.notStrictEqual(netA, netB);

    // 9c. Dokploy CVE-2026-129433: Reject shell metacharacters in DB serviceName / backup / restore paths
    for (const evilName of ['pg;id', 'db`whoami`', 'svc$(rm -rf /)', 'db|cat /etc/passwd', '../escape', 'bad name']) {
      assert.throws(
        () => databaseManager.assertSafeServiceName(evilName, 'serviceName'),
        (err) => err && err.code === 'INVALID_SERVICE_NAME',
        `Debe rechazar serviceName malicioso (CVE-2026-129433): ${evilName}`
      );
    }
    await assert.rejects(
      () => databaseManager.runBackup('db_1;id'),
      (err) => err && err.code === 'INVALID_SERVICE_NAME',
      'runBackup debe rechazar metacaracteres en databaseId antes de invocar Docker'
    );
    await assert.rejects(
      () => databaseManager.provision({ projectId: 'proj_1', engine: 'postgres', name: 'pg', bindAddress: '0.0.0.0' }),
      (err) => err && err.code === 'PUBLIC_DB_EXPOSE_FORBIDDEN',
      'provision debe impedir bind 0.0.0.0 sin publicExpose: true'
    );

    // 9d. Kamal #1856: systemDoctor.auditExposedDatabases flags 0.0.0.0 / publicExpose DBs with UFW_DOCKER_BYPASS_RISK
    const ufwAudit = systemDoctor.auditExposedDatabases([
      { id: 'db_safe', name: 'SafePG', engine: 'postgres', exposure: { enabled: false, bindAddress: '127.0.0.1', hostPort: null } },
      { id: 'db_exposed', name: 'ExposedPG', engine: 'postgres', exposure: { enabled: true, bindAddress: '0.0.0.0', hostPort: 5432 } },
      { id: 'db_pub', name: 'PublicRedis', engine: 'valkey', publicExpose: true }
    ]);
    assert.strictEqual(ufwAudit.safe, false);
    assert.strictEqual(ufwAudit.exposedCount, 2);
    assert.strictEqual(ufwAudit.findings[0].severity, 'high');
    assert.strictEqual(ufwAudit.findings[0].code, 'UFW_DOCKER_BYPASS_RISK');
    assert.ok(ufwAudit.findings[0].recommendation.includes('10.88.0.0/24'));
  }
  console.log('  ✓ Wave-3, Cycle-6 & Cycle-7 CVEs (8a-8f, 9a-9d): culkibo.protected+BuildKit cap, stale lock PID/TTL reap, GitOps symlink+commitSha, webhook replay/no-204/redact, OIDC JWKS SWR, --stop-timeout/--timeout, Kamal #1709 logDriver, Dokploy #6028/CVE-2026-129433, Kamal #1856 UFW audit');

  console.log('✅ Suite #23 completada correctamente.\n');
}

if (require.main === module) {
  testCompetitorPrs()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ Fallo en Suite #23:', err);
      process.exit(1);
    });
}

module.exports = testCompetitorPrs;
