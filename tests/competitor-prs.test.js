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

    // Cycle-8 Lazy Routes: Passkeys, Secret Leases & Break-Glass, OSV CVE Drift, Config Drift + PgBouncer, IaC Export, Maintenance, Incidents, Geo-Failover, CAA Pre-Flight
    const pkList = await reqJson(port, 'GET', '/api/auth/passkeys', { token: master });
    assert.strictEqual(pkList.status, 200, 'GET /api/auth/passkeys failed: ' + pkList.text);
    assert.ok(Array.isArray(pkList.json.passkeys));

    const pkBegin = await reqJson(port, 'POST', '/api/auth/passkeys/register/begin', {
      token: master,
      body: { username: 'owner@example.test', rpId: 'panel.example.test', origin: 'https://panel.example.test' }
    });
    assert.strictEqual(pkBegin.status, 200, 'POST /api/auth/passkeys/register/begin failed: ' + pkBegin.text);
    assert.ok(pkBegin.json.challengeId && pkBegin.json.challenge);

    const leaseCreate = await reqJson(port, 'POST', '/api/security/leases', {
      token: master,
      body: { projectId: 'proj_c2_api', secretKey: 'DATABASE_URL', scope: 'read', ttlSec: 3600, reason: 'ci-migration' }
    });
    assert.strictEqual(leaseCreate.status, 201, 'POST /api/security/leases failed: ' + leaseCreate.text);
    assert.ok(leaseCreate.json.lease && leaseCreate.json.lease.id && leaseCreate.json.token);

    const leaseList = await reqJson(port, 'GET', '/api/security/leases', { token: master });
    assert.strictEqual(leaseList.status, 200);
    assert.ok(Array.isArray(leaseList.json.leases) && leaseList.json.leases.length >= 1);

    const leaseDel = await reqJson(port, 'DELETE', '/api/security/leases/' + encodeURIComponent(leaseCreate.json.lease.id), { token: master });
    assert.strictEqual(leaseDel.status, 200, 'DELETE /api/security/leases/:id failed: ' + leaseDel.text);

    const bgRes = await reqJson(port, 'POST', '/api/security/break-glass', {
      token: master,
      body: { reason: 'Emergency production DB failover investigation', ttlSec: 900 }
    });
    assert.strictEqual(bgRes.status, 201, 'POST /api/security/break-glass failed: ' + bgRes.text);
    assert.ok(bgRes.json.lease && bgRes.json.token);

    const rotAudit = await reqJson(port, 'GET', '/api/security/rotation-audit?maxAgeDays=90', { token: master });
    assert.strictEqual(rotAudit.status, 200, 'GET /api/security/rotation-audit failed: ' + rotAudit.text);
    assert.strictEqual(typeof rotAudit.json.totalKeys, 'number');

    const cveScan = await reqJson(port, 'POST', '/api/security/cve-scan', {
      token: master,
      body: { allowNetwork: false }
    });
    assert.strictEqual(cveScan.status, 200, 'POST /api/security/cve-scan failed: ' + cveScan.text);
    assert.ok(cveScan.json.scannedPackages >= 1 && cveScan.json.bySeverity, 'cve-scan must await async scanSbom and return real summary');

    const cveLatest = await reqJson(port, 'GET', '/api/security/cve-scan/latest', { token: master });
    assert.strictEqual(cveLatest.status, 200);
    assert.strictEqual(cveLatest.json.scanned, true);

    const driftRes = await reqJson(port, 'POST', '/api/projects/proj_c2_api/drift/check', {
      token: master,
      body: {
        actualInspect: {
          Config: { Image: 'culkibo/c2:v1', Env: ['A=1', 'DRIFTED_EXTRA=2'], StopTimeout: 10 },
          HostConfig: {
            Memory: 1024 * 1024 * 1024,
            NanoCpus: 1e9,
            PortBindings: { '3000/tcp': [{ HostIp: '0.0.0.0', HostPort: '21111' }] },
            LogConfig: { Type: 'json-file' }
          }
        }
      }
    });
    assert.strictEqual(driftRes.status, 200, 'POST /drift/check failed: ' + driftRes.text);
    assert.strictEqual(driftRes.json.drifted, true, 'drift/check must await async checkProjectDrift and detect 0.0.0.0 exposure drift');
    assert.strictEqual(driftRes.json.severity, 'critical');

    const pgPreset = await reqJson(port, 'POST', '/api/databases/pgbouncer-preset', {
      token: master,
      body: { name: 'pg-main', databaseName: 'app_prod' }
    });
    assert.strictEqual(pgPreset.status, 200, 'POST /databases/pgbouncer-preset failed: ' + pgPreset.text);
    assert.strictEqual(pgPreset.json.maxPreparedStatements, 200);
    assert.ok(String(pgPreset.json.pgbouncerIni || '').includes('pool_mode = transaction'));

    const iacRes = await reqJson(port, 'POST', '/api/iac/export', {
      token: master,
      body: { format: 'all' }
    });
    assert.strictEqual(iacRes.status, 200, 'POST /api/iac/export failed: ' + iacRes.text);
    assert.strictEqual(iacRes.json.ok, true);
    assert.ok(iacRes.json.files && iacRes.json.files['main.tf'] && iacRes.json.files['docker-compose.yml']);

    const mwCreate = await reqJson(port, 'POST', '/api/uptime/maintenance', {
      token: master,
      body: { title: 'Weekly Patch', targetIds: ['*'], kind: 'recurring', startAt: new Date().toISOString(), durationMin: 30, intervalDays: 7 }
    });
    assert.strictEqual(mwCreate.status, 201, 'POST /api/uptime/maintenance failed: ' + mwCreate.text);
    assert.ok(mwCreate.json.window && mwCreate.json.window.id);
    const mwList = await reqJson(port, 'GET', '/api/uptime/maintenance', { token: master });
    assert.strictEqual(mwList.status, 200);
    assert.ok(Array.isArray(mwList.json.windows) && mwList.json.windows.length >= 1);
    const mwDel = await reqJson(port, 'DELETE', '/api/uptime/maintenance/' + encodeURIComponent(mwCreate.json.window.id), { token: master });
    assert.strictEqual(mwDel.status, 200);

    const incCreate = await reqJson(port, 'POST', '/api/uptime/incidents', {
      token: master,
      body: { title: 'API Degraded', severity: 'major', status: 'investigating', message: 'Investigating spike' }
    });
    assert.strictEqual(incCreate.status, 201, 'POST /api/uptime/incidents failed: ' + incCreate.text);
    const incPatch = await reqJson(port, 'PATCH', '/api/uptime/incidents/' + encodeURIComponent(incCreate.json.incident.id), {
      token: master,
      body: { status: 'resolved', message: 'Mitigated cleanly' }
    });
    assert.strictEqual(incPatch.status, 200, 'PATCH /api/uptime/incidents/:id failed: ' + incPatch.text);
    assert.strictEqual(incPatch.json.incident.status, 'resolved');

    const geoPlan = await reqJson(port, 'POST', '/api/uptime/geo-failover/plan', {
      token: master,
      body: { domain: 'edge.example.test', primaryIp: '203.0.113.10', secondaryIp: '198.51.100.20', consecutiveFailures: 3, ttlSec: 60 }
    });
    assert.strictEqual(geoPlan.status, 200, 'POST /api/uptime/geo-failover/plan failed: ' + geoPlan.text);
    assert.strictEqual(geoPlan.json.strategy, 'active-passive-dns-failover');
    assert.strictEqual(geoPlan.json.steps.length, 4);

    const badCaa = await reqJson(port, 'GET', '/api/domains/bad_host_no_dot/caa-preflight', { token: master });
    assert.strictEqual(badCaa.status, 400);

    // Cycle-9 Lazy Routes: White-Label Brand, Standard-Webhooks + DLQ, Read-Only DB Studio & Redis, Post-MinIO S3 + SigV4, Agency Quotas & Billing Ledger + Live Cross-Tenant 403 (Dokploy CVE-2026-116068 / CVE-2026-127212)
    const brandGet = await reqJson(port, 'GET', '/api/brand', { token: master });
    assert.strictEqual(brandGet.status, 200, 'GET /api/brand failed: ' + brandGet.text);
    assert.strictEqual(brandGet.json.brandName, 'Culkibo');

    const brandXss = await reqJson(port, 'PUT', '/api/brand', {
      token: master,
      body: { logoUrl: 'javascript:alert(1)' }
    });
    assert.strictEqual(brandXss.status, 400, 'PUT /api/brand must reject javascript: XSS');

    const brandPut = await reqJson(port, 'PUT', '/api/brand', {
      token: master,
      body: { brandName: 'Agency Cloud', accentHex: '#10b981', hidePoweredBy: true }
    });
    assert.strictEqual(brandPut.status, 200, 'PUT /api/brand failed: ' + brandPut.text);
    assert.strictEqual(brandPut.json.brandName, 'Agency Cloud');
    const brandReset = await reqJson(port, 'POST', '/api/brand/reset', { token: master, body: {} });
    assert.strictEqual(brandReset.status, 200);
    assert.strictEqual(brandReset.json.brandName, 'Culkibo');

    const whCreate = await reqJson(port, 'POST', '/api/webhooks/outbound', {
      token: master,
      body: { url: 'https://hooks.example.test/culkibo', events: ['deploy.succeeded'], description: 'CI Hook' }
    });
    assert.strictEqual(whCreate.status, 201, 'POST /api/webhooks/outbound failed: ' + whCreate.text);
    const subId = whCreate.json.id || (whCreate.json.subscription && whCreate.json.subscription.id);
    assert.ok(subId, 'Webhook subscription id expected');
    const whList = await reqJson(port, 'GET', '/api/webhooks/outbound', { token: master });
    assert.strictEqual(whList.status, 200);
    assert.ok(Array.isArray(whList.json.subscriptions) && whList.json.subscriptions.length >= 1);
    const whRot = await reqJson(port, 'POST', '/api/webhooks/outbound/' + encodeURIComponent(subId) + '/rotate-secret', {
      token: master,
      body: { graceSec: 3600 }
    });
    assert.strictEqual(whRot.status, 200, 'POST rotate-secret failed: ' + whRot.text);
    const dlqList = await reqJson(port, 'GET', '/api/webhooks/dlq', { token: master });
    assert.strictEqual(dlqList.status, 200);
    assert.ok(Array.isArray(dlqList.json.entries));

    const sqlOk = await reqJson(port, 'POST', '/api/databases/db_sqlite_c2/studio/sql', {
      token: master,
      body: { engine: 'postgres', query: 'SELECT id, email FROM users' }
    });
    assert.strictEqual(sqlOk.status, 200, 'POST studio/sql failed: ' + sqlOk.text);
    assert.strictEqual(sqlOk.json.readOnlyEnforced, true);
    const sqlEvil = await reqJson(port, 'POST', '/api/databases/db_sqlite_c2/studio/sql', {
      token: master,
      body: { engine: 'postgres', query: 'SELECT 1; DROP TABLE users' }
    });
    assert.strictEqual(sqlEvil.status, 400, 'POST studio/sql must reject mutating SQL with 400');

    const redisOk = await reqJson(port, 'POST', '/api/databases/db_sqlite_c2/studio/redis', {
      token: master,
      body: { argv: ['SCAN', '0', 'COUNT', '500'] }
    });
    assert.strictEqual(redisOk.status, 200, 'POST studio/redis failed: ' + redisOk.text);
    assert.strictEqual(redisOk.json.readOnlyEnforced, true);
    const redisEvil = await reqJson(port, 'POST', '/api/databases/db_sqlite_c2/studio/redis', {
      token: master,
      body: { argv: ['FLUSHALL'] }
    });
    assert.strictEqual(redisEvil.status, 400, 'POST studio/redis must reject FLUSHALL with 400');

    const bloatRes = await reqJson(port, 'POST', '/api/databases/db_sqlite_c2/studio/bloat', {
      token: master,
      body: { tableStats: [{ table: 'orders', liveTuples: 1000, deadTuples: 400 }] }
    });
    assert.strictEqual(bloatRes.status, 200, 'POST studio/bloat failed: ' + bloatRes.text);
    assert.strictEqual(bloatRes.json.checkedTables, 1);

    const s3Presets = await reqJson(port, 'GET', '/api/storage/presets', { token: master });
    assert.strictEqual(s3Presets.status, 200, 'GET /api/storage/presets failed: ' + s3Presets.text);
    assert.ok(Array.isArray(s3Presets.json.presets) && s3Presets.json.presets.length >= 3);

    const s3Presign = await reqJson(port, 'POST', '/api/storage/presign', {
      token: master,
      body: { endpoint: 'https://s3.example.test', bucket: 'backups-prod', key: 'db/snap.sql.gz', method: 'GET', accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', expiresIn: 900 }
    });
    assert.strictEqual(s3Presign.status, 200, 'POST /api/storage/presign failed: ' + s3Presign.text);
    assert.ok(String(s3Presign.json.url || '').includes('X-Amz-Signature='));

    const s3BadKey = await reqJson(port, 'POST', '/api/storage/presign', {
      token: master,
      body: { endpoint: 'https://s3.example.test', bucket: 'backups-prod', key: '../etc/passwd', accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', expiresIn: 900 }
    });
    assert.strictEqual(s3BadKey.status, 400, 'POST /api/storage/presign must reject ../ keys');

    const s3BadTtl = await reqJson(port, 'POST', '/api/storage/presign', {
      token: master,
      body: { endpoint: 'https://s3.example.test', bucket: 'backups-prod', key: 'ok.txt', accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', expiresIn: 999999 }
    });
    assert.strictEqual(s3BadTtl.status, 400, 'POST /api/storage/presign must reject expiresIn > 604800');

    const s3Cors = await reqJson(port, 'POST', '/api/storage/cors-xml', {
      token: master,
      body: { rules: [{ allowedOrigins: ['https://app.example.test'], allowedMethods: ['GET', 'PUT'] }] }
    });
    assert.strictEqual(s3Cors.status, 200, 'POST /api/storage/cors-xml failed: ' + s3Cors.text);
    assert.ok(String(s3Cors.json.xml || '').includes('<CORSConfiguration'));

    const s3Life = await reqJson(port, 'POST', '/api/storage/lifecycle-xml', {
      token: master,
      body: { rules: [{ id: 'expire-30d', prefix: 'tmp/', expirationDays: 30, abortMultipartDays: 7 }] }
    });
    assert.strictEqual(s3Life.status, 200, 'POST /api/storage/lifecycle-xml failed: ' + s3Life.text);
    assert.ok(String(s3Life.json.xml || '').includes('<LifecycleConfiguration'));

    const qPut = await reqJson(port, 'PUT', '/api/quotas/proj_c2_api', {
      token: master,
      body: { maxContainers: 4, maxMemoryMb: 2048, maxCpuCores: 2, maxStorageGb: 20, maxBandwidthGbMo: 250 }
    });
    assert.strictEqual(qPut.status, 200, 'PUT /api/quotas/:projectId failed: ' + qPut.text);
    const qList = await reqJson(port, 'GET', '/api/quotas', { token: master });
    assert.strictEqual(qList.status, 200);
    assert.ok(Array.isArray(qList.json.quotas));
    const qCheck = await reqJson(port, 'POST', '/api/quotas/proj_c2_api/check', {
      token: master,
      body: { containers: 10, memoryMb: 8192 }
    });
    assert.strictEqual(qCheck.status, 200);
    assert.strictEqual(qCheck.json.allowed, false);

    // CSV formula neutralization via live HTTP /api/billing/ledger?format=csv
    projectManager.create({ id: 'proj_csv_evil', name: "=CMD|' /C calc'!A0" });
    const ledJson = await reqJson(port, 'GET', '/api/billing/ledger', { token: master });
    assert.strictEqual(ledJson.status, 200, 'GET /api/billing/ledger failed: ' + ledJson.text);
    assert.ok(ledJson.json.totals);
    const ledCsv = await reqJson(port, 'GET', '/api/billing/ledger?format=csv', { token: master });
    assert.strictEqual(ledCsv.status, 200, 'GET /api/billing/ledger?format=csv failed: ' + ledCsv.text);
    assert.ok(String(ledCsv.headers['content-type'] || '').includes('text/csv'));
    assert.ok(ledCsv.text.includes("'=CMD|"), 'CSV ledger must neutralize leading = formula injection');

    // Live Cross-Tenant 403 Enforcement (Dokploy CVE-2026-116068 & CVE-2026-127212)
    const teamManager = require(path.join(ROOT_DIR, 'server/services/teamManager'));
    const bootOwner = teamManager.bootstrapOwner({ email: 'c9-owner@example.test', password: 'OwnerPassword!2026' });
    const ownerPrincipal = teamManager.verifySessionToken(bootOwner.sessionToken).principal;
    const teamB = teamManager.createTeam(ownerPrincipal, { name: 'Tenant B Org' });
    const invB = teamManager.createInvite(ownerPrincipal, { email: 'tenantb-dev@example.test', role: 'developer', teamId: teamB.id });
    const accB = teamManager.acceptInvite({ token: invB.inviteToken, email: 'tenantb-dev@example.test', password: 'TenantBPassword!2026', name: 'TenantB Dev' });
    const tenantBToken = accB.sessionToken;

    const foreignQuotaPut = await reqJson(port, 'PUT', '/api/quotas/proj_c2_api', {
      token: tenantBToken,
      body: { maxMemoryMb: 99999 }
    });
    assert.strictEqual(foreignQuotaPut.status, 403, 'Foreign tenant PUT /api/quotas/:projectId MUST return 403 (CVE-2026-116068)');
    const foreignQuotaCheck = await reqJson(port, 'POST', '/api/quotas/proj_c2_api/check', {
      token: tenantBToken,
      body: { memoryMb: 512 }
    });
    assert.strictEqual(foreignQuotaCheck.status, 403, 'Foreign tenant POST /api/quotas/:projectId/check MUST return 403');
    const foreignLedger = await reqJson(port, 'GET', '/api/billing/ledger?projectId=proj_c2_api', {
      token: tenantBToken
    });
    assert.strictEqual(foreignLedger.status, 403, 'Foreign tenant GET /api/billing/ledger?projectId=foreign MUST return 403 (CVE-2026-127212)');
    const foreignStudio = await reqJson(port, 'POST', '/api/databases/db_sqlite_c2/studio/sql', {
      token: tenantBToken,
      body: { query: 'SELECT 1' }
    });
    assert.strictEqual(foreignStudio.status, 403, 'Foreign tenant POST /api/databases/:id/studio/sql MUST return 403');

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

  // -------------------------------------------------------------------------
  // 10. Cycle #8 CVE & PR Regressions (docs/COMPETITOR_RADAR_CYCLE7.md §3)
  // -------------------------------------------------------------------------
  {
    const apiRouter = require('../server/routes/api');
    const { TeamManager, generateTotpCode } = require('../server/services/teamManager');
    const { parseSafeCommandArgv } = require('../server/services/safeCommand');
    const { diffContainerConfig } = require('../server/services/driftDetectorService');
    const { UptimeMonitor } = require('../server/services/uptimeMonitor');
    const { checkAllCaaRecords } = require('../server/services/ingressManager');
    const { PasskeyService } = require('../server/services/passkeyService');
    const { SecretLeaseService } = require('../server/services/secretLeaseService');
    const { CveDriftService } = require('../server/services/cveDriftService');

    // 10a. Dokploy CVE-2026-129315 (scripts/install.sh) & CVE-2026-133520 / GHSA-q7cq-vxv7-449c (repoPath traversal)
    const installShPath = path.resolve(__dirname, '..', 'scripts', 'install.sh');
    const installShText = fs.readFileSync(installShPath, 'utf8');
    assert.ok(!/chmod\s+(-R\s+)?0?777\b/i.test(installShText), 'scripts/install.sh JAMÁS debe usar chmod 777/0777 (Dokploy CVE-2026-129315)');
    assert.ok(!/chmod\s+(-R\s+)?a\+rwx\b/i.test(installShText), 'scripts/install.sh JAMÁS debe usar chmod a+rwx');
    assert.ok(/chmod\s+0?700\s+"\$DATA_DIR"/i.test(installShText), 'scripts/install.sh debe aplicar chmod 0700 sobre $DATA_DIR');
    assert.ok(/chmod\s+0?600\s+"\$ENV_FILE"/i.test(installShText), 'scripts/install.sh debe aplicar chmod 0600 sobre $ENV_FILE');

    const pathTmp = makeTempDir('culkibo-c8-path-');
    try {
      const tenantRoot = path.join(pathTmp, 'tenant-a');
      const otherTenant = path.join(pathTmp, 'tenant-b');
      fs.mkdirSync(path.join(tenantRoot, 'src'), { recursive: true });
      fs.mkdirSync(otherTenant, { recursive: true });
      fs.writeFileSync(path.join(tenantRoot, 'src', 'index.js'), 'ok', 'utf8');
      fs.writeFileSync(path.join(otherTenant, 'secret.env'), 'SECRET=1', 'utf8');

      // Contained path succeeds
      const okPath = apiRouter.assertRealPathContained(tenantRoot, 'src/index.js');
      assert.ok(okPath.endsWith(path.join('src', 'index.js')));

      // ../ traversal across tenants blocked (Dokploy CVE-2026-133520)
      assert.throws(
        () => apiRouter.assertRealPathContained(tenantRoot, '../tenant-b/secret.env'),
        (err) => err && err.status === 403 && err.code === 'PATH_TRAVERSAL_BLOCKED',
        'assertRealPathContained debe bloquear ../ cross-tenant traversal (CVE-2026-133520)'
      );

      // 10b. Runtipi CVE-2026-47277 (GHSA-qrqj-p7hm-4m66): escaping symlink blocked via fs.realpathSync
      let linkCreated = false;
      const linkDir = path.join(tenantRoot, 'logo-escape');
      try {
        fs.symlinkSync(otherTenant, linkDir, process.platform === 'win32' ? 'junction' : 'dir');
        linkCreated = true;
      } catch (e) {}
      if (linkCreated) {
        assert.throws(
          () => apiRouter.assertRealPathContained(tenantRoot, 'logo-escape/secret.env'),
          (err) => err && err.status === 403 && err.code === 'PATH_TRAVERSAL_BLOCKED',
          'assertRealPathContained debe bloquear enlaces simbólicos salientes (Runtipi CVE-2026-47277)'
        );
      }
    } finally {
      fs.rmSync(pathTmp, { recursive: true, force: true });
    }

    // 10b (part 2). Runtipi TOTP brute-force throttle: <=5 failed 6-digit attempts -> 15 min lockout (TOTP_RATE_LIMITED)
    const totpTmp = makeTempDir('culkibo-c8-totp-');
    try {
      const tm = new TeamManager({ dataDir: totpTmp, bcryptCost: 4 });
      const boot = tm.bootstrapOwner({ email: 'totp-owner@example.test', password: 'StrongPassword!2026' });
      const ownerPrincipal = tm.verifySessionToken(boot.sessionToken).principal;
      const setup = tm.setupTotp(ownerPrincipal, { issuer: 'CulkiboC8' });
      const baseTs = 1780000000000;
      const initCode = generateTotpCode(setup.secretBase32, { timestampMs: baseTs }).code;
      tm.enableTotp(ownerPrincipal, { code: initCode, timestampMs: baseTs, nowMs: baseTs });

      const step1 = tm.login({ email: 'totp-owner@example.test', password: 'StrongPassword!2026' });
      assert.strictEqual(step1.mfaRequired, true);

      // 4 consecutive bad attempts fail with INVALID_MFA_CODE (not locked yet)
      const tStep1 = baseTs + 60000;
      for (let i = 0; i < 4; i++) {
        assert.throws(
          () => tm.verifyMfaLogin({ mfaChallengeToken: step1.mfaChallengeToken, code: '000000', timestampMs: tStep1, nowMs: tStep1 }),
          (err) => err && err.status === 401 && err.code === 'INVALID_MFA_CODE'
        );
      }
      // Valid code on attempt 5 resets consecutive failure counter
      const validCode1 = generateTotpCode(setup.secretBase32, { timestampMs: tStep1 }).code;
      const okLogin = tm.verifyMfaLogin({ mfaChallengeToken: step1.mfaChallengeToken, code: validCode1, timestampMs: tStep1, nowMs: tStep1 });
      assert.ok(okLogin.sessionToken, 'Valid TOTP before 5th failure must succeed and reset failure counter');

      // Now 5 consecutive bad 6-digit attempts -> 5th triggers 15-min lockout (TOTP_RATE_LIMITED)
      const step2 = tm.login({ email: 'totp-owner@example.test', password: 'StrongPassword!2026' });
      const tStep2 = tStep1 + 60000;
      for (let i = 0; i < 4; i++) {
        assert.throws(
          () => tm.verifyMfaLogin({ mfaChallengeToken: step2.mfaChallengeToken, code: '111111', timestampMs: tStep2, nowMs: tStep2 }),
          (err) => err && err.status === 401 && err.code === 'INVALID_MFA_CODE'
        );
      }
      assert.throws(
        () => tm.verifyMfaLogin({ mfaChallengeToken: step2.mfaChallengeToken, code: '222222', timestampMs: tStep2, nowMs: tStep2 }),
        (err) => err && err.status === 429 && err.code === 'TOTP_RATE_LIMITED',
        '5th consecutive failed 6-digit TOTP attempt MUST lock out with 429 TOTP_RATE_LIMITED'
      );
      // Even a VALID code during the 15-minute lockout MUST be rejected with 429 TOTP_RATE_LIMITED
      const validCode2 = generateTotpCode(setup.secretBase32, { timestampMs: tStep2 }).code;
      assert.throws(
        () => tm.verifyMfaLogin({ mfaChallengeToken: step2.mfaChallengeToken, code: validCode2, timestampMs: tStep2, nowMs: tStep2 + 5 * 60 * 1000 }),
        (err) => err && err.status === 429 && err.code === 'TOTP_RATE_LIMITED',
        'Locked-out account must reject even valid TOTP codes during 15-minute cooldown'
      );
      // After 15 minutes + 1s, lockout expires cleanly
      const tAfterLock = tStep2 + 15 * 60 * 1000 + 1000;
      const step3 = tm.login({ email: 'totp-owner@example.test', password: 'StrongPassword!2026' });
      const validCode3 = generateTotpCode(setup.secretBase32, { timestampMs: tAfterLock }).code;
      const recovered = tm.verifyMfaLogin({ mfaChallengeToken: step3.mfaChallengeToken, code: validCode3, timestampMs: tAfterLock, nowMs: tAfterLock });
      assert.ok(recovered.sessionToken, 'Valid TOTP after 15-minute lockout expiry must succeed');
    } finally {
      fs.rmSync(totpTmp, { recursive: true, force: true });
    }

    // 10c. Dokku CVE-2026-54636 (cron metacharacter injection) & Kamal #1790 (silent config drift)
    for (const evilCmd of ['node job.js; id', 'php artisan > /tmp/pwn', 'python3 $(whoami).py']) {
      assert.throws(
        () => parseSafeCommandArgv(evilCmd),
        /Operador de shell|sustituciones de shell/i,
        `Cron safeCommand debe rechazar metacaracteres (Dokku CVE-2026-54636): ${evilCmd}`
      );
    }
    const digestDeclared = 'sha256:' + 'a'.repeat(64);
    const digestRunning = 'sha256:' + 'b'.repeat(64);
    const driftOut = diffContainerConfig(
      { image: 'app:1.0', imageDigest: digestDeclared, memoryLimitMb: 512, port: 3000, bindAddress: '127.0.0.1', envKeys: ['NODE_ENV'] },
      {
        Image: digestRunning,
        Config: { Image: 'app:1.0', Env: ['NODE_ENV=production', 'EXTRA=1'], StopTimeout: 30 },
        RepoDigests: [`app@${digestRunning}`],
        HostConfig: {
          Memory: 1024 * 1024 * 1024,
          PortBindings: { '3000/tcp': [{ HostIp: '0.0.0.0', HostPort: '3000' }] },
          LogConfig: { Type: 'json-file' }
        }
      }
    );
    assert.strictEqual(driftOut.drifted, true);
    assert.strictEqual(driftOut.severity, 'critical');
    assert.ok(driftOut.diffs.some((d) => d.field === 'imageDigest'));
    assert.ok(driftOut.diffs.some((d) => d.field === 'memoryLimitMb'));
    assert.ok(driftOut.diffs.some((d) => d.field === 'bindAddress' && d.severity === 'critical'));

    // 10d. Uptime Kuma #7704, #8193, #6519
    const umTmp = makeTempDir('culkibo-c8-um-');
    try {
      const um = new UptimeMonitor({
        storeFile: path.join(umTmp, 'uptime.json'),
        maintenanceFile: path.join(umTmp, 'maintenance-incidents.json'),
        autoStart: false
      });
      const startMs = Date.UTC(2026, 7, 1, 10, 0, 0);
      um.createMaintenanceWindow({
        title: 'Multi-day window',
        targetIds: ['mon_1'],
        kind: 'recurring',
        startAt: new Date(startMs).toISOString(),
        durationMin: 60,
        intervalDays: 3
      });
      assert.strictEqual(um.isInMaintenance('mon_1', startMs + 10 * 60 * 1000), true, '#7704 day-0 fires');
      assert.strictEqual(um.isInMaintenance('mon_1', startMs + 3 * 86400_000 + 10 * 60 * 1000), true, '#8193 >=2d advances');
      const caaRes = await checkAllCaaRecords('multi.example.test', {
        expectedCa: 'letsencrypt.org',
        resolveCaaImpl: async () => [{ issue: 'digicert.com' }, { issue: 'letsencrypt.org' }]
      });
      assert.strictEqual(caaRes.allowed, true, '#6519 inspects all CAA records beyond [0]');
    } finally {
      fs.rmSync(umTmp, { recursive: true, force: true });
    }

    // 10e. WebAuthn Ed25519 + Secret Lease fail-closed expiry + OSV.dev batch offline fallback
    const c8Tmp = makeTempDir('culkibo-c8-sec-');
    try {
      const pk = new PasskeyService({ dataDir: c8Tmp });
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
      const rpId = 'panel.example.test';
      const origin = 'https://panel.example.test';
      const regBegin = pk.beginRegistration({ userId: 'u_c8', username: 'u_c8@example.test', rpId, origin });
      const regClientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: regBegin.challenge, origin }));
      const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
      const flagsUp = Buffer.from([0x01]);
      const cnt0 = Buffer.alloc(4);
      const authDataReg = Buffer.concat([rpIdHash, flagsUp, cnt0]);
      const coseEd = new Map([[1, 1], [3, -8], [-1, 6], [-2, rawPub]]);
      const regFin = pk.finishRegistration({
        userId: 'u_c8',
        challengeId: regBegin.challengeId,
        credentialId: 'cred_ed_c8',
        clientDataJSON: regClientData.toString('base64url'),
        publicKeyCose: coseEd,
        expectedOrigin: origin,
        expectedRpId: rpId
      });
      assert.strictEqual(regFin.ok, true);
      assert.strictEqual(regFin.credential.alg, -8);

      const authBegin = pk.beginAuthentication({ userId: 'u_c8', rpId });
      const authClientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: authBegin.challenge, origin }));
      const cnt1 = Buffer.alloc(4);
      cnt1.writeUInt32BE(1, 0);
      const authData1 = Buffer.concat([rpIdHash, flagsUp, cnt1]);
      const clientHash1 = crypto.createHash('sha256').update(authClientData).digest();
      const sig1 = crypto.sign(null, Buffer.concat([authData1, clientHash1]), privateKey);
      const authOk = pk.finishAuthentication({
        challengeId: authBegin.challengeId,
        credentialId: 'cred_ed_c8',
        clientDataJSON: authClientData.toString('base64url'),
        authenticatorData: authData1.toString('base64url'),
        signature: sig1.toString('base64url'),
        expectedOrigin: origin,
        expectedRpId: rpId
      });
      assert.strictEqual(authOk.valid, true);
      assert.strictEqual(authOk.signCount, 1);

      // Replayed challenge MUST fail closed
      const replayRes = pk.finishAuthentication({
        challengeId: authBegin.challengeId,
        credentialId: 'cred_ed_c8',
        clientDataJSON: authClientData.toString('base64url'),
        authenticatorData: authData1.toString('base64url'),
        signature: sig1.toString('base64url'),
        expectedOrigin: origin,
        expectedRpId: rpId
      });
      assert.strictEqual(replayRes.valid, false);

      // Regressed signCount (cloning) MUST fail closed
      const authBegin2 = pk.beginAuthentication({ userId: 'u_c8', rpId });
      const authClientData2 = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: authBegin2.challenge, origin }));
      const authDataRegressed = Buffer.concat([rpIdHash, flagsUp, cnt1]); // same signCount=1 <= storedCount=1
      const clientHash2 = crypto.createHash('sha256').update(authClientData2).digest();
      const sig2 = crypto.sign(null, Buffer.concat([authDataRegressed, clientHash2]), privateKey);
      const cloneRes = pk.finishAuthentication({
        challengeId: authBegin2.challengeId,
        credentialId: 'cred_ed_c8',
        clientDataJSON: authClientData2.toString('base64url'),
        authenticatorData: authDataRegressed.toString('base64url'),
        signature: sig2.toString('base64url'),
        expectedOrigin: origin,
        expectedRpId: rpId
      });
      assert.strictEqual(cloneRes.valid, false);

      // Secret lease fails closed upon expiry
      const ls = new SecretLeaseService({ dataDir: c8Tmp });
      const now0 = Date.now();
      const issued = ls.issueLease({ projectId: 'p1', secretKey: 'API_KEY', ttlSec: 60, issuedBy: 'owner', nowMs: now0 });
      assert.strictEqual(ls.validateLease(issued.token, { nowMs: now0 + 10_000 }).valid, true);
      const expiredCheck = ls.validateLease(issued.token, { nowMs: now0 + 120_000 });
      assert.strictEqual(expiredCheck.valid, false);
      assert.strictEqual(expiredCheck.reason, 'EXPIRED');

      // OSV CVE Drift offline fallback
      const cve = new CveDriftService({ dataDir: c8Tmp });
      const scanRes = await cve.scanSbom({
        components: [{ purl: 'pkg:npm/express@4.21.2' }],
        allowNetwork: false
      });
      assert.strictEqual(scanRes.scannedPackages, 1);
      assert.strictEqual(scanRes.offline, true);
    } finally {
      fs.rmSync(c8Tmp, { recursive: true, force: true });
    }
  }
  console.log('  ✓ Cycle #8 CVEs (10a-10e): Dokploy CVE-2026-129315/133520, Runtipi CVE-2026-47277 & TOTP throttle, Dokku CVE-2026-54636 & Kamal #1790, Uptime Kuma #7704/#8193/#6519, WebAuthn/OSV/Lease');

  // -------------------------------------------------------------------------
  // 11. Cycle #9 CVE & PR Regressions (docs/COMPETITOR_RADAR_CYCLE8.md §3)
  // -------------------------------------------------------------------------
  {
    const {
      WebhookEventBus,
      signStandardWebhook,
      verifyStandardWebhookSignature,
      generateWebhookSecret
    } = require('../server/services/webhookEventBus');
    const {
      generatePresignedUrl,
      buildBucketCorsXml
    } = require('../server/services/objectStorageService');
    const {
      validateReadOnlySql,
      validateSafeRedisCommand
    } = require('../server/services/dbStudioService');
    const {
      QuotaMeteringService,
      escapeCsvCell,
      exportLedgerCsv
    } = require('../server/services/quotaMeteringService');
    const {
      BrandThemeService,
      validateBrandPatch,
      sanitizeBrandLogo
    } = require('../server/services/brandThemeService');

    const c9Tmp = makeTempDir('culkibo-c9-cve-');
    try {
      // 11a. Dokploy CVE-2026-116068 & CVE-2026-127212: Tenant ACL filtering + CSV formula neutralization
      const qm = new QuotaMeteringService({ dataDir: c9Tmp });
      qm.setQuota('proj_tenant_a', { memoryMb: 1024 });
      qm.setQuota('proj_tenant_b', { memoryMb: 4096 });
      const filteredQuotasRes = qm.listQuotas({ allowedProjectIds: ['proj_tenant_a'] });
      const filteredQuotas = Array.isArray(filteredQuotasRes) ? filteredQuotasRes : filteredQuotasRes.quotas;
      assert.strictEqual(filteredQuotas.length, 1);
      assert.ok(filteredQuotas.every((q) => q.projectId === 'proj_tenant_a'), 'listQuotas must exclude foreign tenants');
      const ledger = qm.buildUsageLedger({
        projects: [
          { id: 'proj_tenant_a', name: "=CMD|' /C calc'!A0", memoryMb: 512, cpus: 1 },
          { id: 'proj_tenant_b', name: 'ForeignSecretApp', memoryMb: 2048, cpus: 2 }
        ],
        allowedProjectIds: ['proj_tenant_a']
      });
      const ledgerRows = ledger.entries || ledger.projects || [];
      assert.strictEqual(ledgerRows.length, 1);
      assert.strictEqual(ledgerRows[0].projectId, 'proj_tenant_a');
      const csvOut = exportLedgerCsv(ledger);
      assert.ok(!csvOut.includes('ForeignSecretApp'), 'Usage ledger must never leak foreign tenant apps');
      assert.ok(escapeCsvCell("=CMD|' /C calc'!A0").startsWith("'") || escapeCsvCell("=CMD|' /C calc'!A0").startsWith("\"'"), 'CSV cell must neutralize leading = formula');
      assert.ok(escapeCsvCell('+1+1').startsWith("'"));
      assert.ok(escapeCsvCell('@SUM(A1)').startsWith("'"));

      // 11b. Portainer CVE-2026-134756: Webhook SSRF block (send + DLQ replay) + dual-secret rotation + >300s replay rejection
      const sec1 = generateWebhookSecret();
      const sec2 = generateWebhookSecret();
      const bodyStr = JSON.stringify({ event: 'deploy.succeeded' });
      const nowSec = Math.floor(Date.now() / 1000);
      const dualHeaders = signStandardWebhook({ msgId: 'msg_c9_1', timestampSec: nowSec, payload: bodyStr, secret: sec1, secondarySecret: sec2 });
      assert.strictEqual(verifyStandardWebhookSignature(bodyStr, dualHeaders, [sec1], { nowSec }).valid, true);
      assert.strictEqual(verifyStandardWebhookSignature(bodyStr, dualHeaders, [sec2], { nowSec }).valid, true);
      const staleRes = verifyStandardWebhookSignature(bodyStr, dualHeaders, [sec1], { nowSec: nowSec + 400, toleranceSec: 300 });
      assert.strictEqual(staleRes.valid, false, 'Timestamps > 300s must be rejected');

      const whBus = new WebhookEventBus({ dataDir: c9Tmp });
      const ssrfSubRes = whBus.upsertSubscription({ url: 'https://rebind.example.test/hook', events: ['*'] });
      const ssrfSubId = ssrfSubRes.id || (ssrfSubRes.subscription && ssrfSubRes.subscription.id);
      const ssrfDispatch = await whBus.dispatchEvent({
        eventType: 'deploy.failed',
        data: { id: 'd1' },
        subscriptionId: ssrfSubId,
        maxAttempts: 1,
        dnsLookupImpl: async () => [{ address: '169.254.169.254', family: 4 }],
        fetchImpl: async () => { throw new Error('fetch must NEVER be called for metadata IP'); }
      });
      assert.ok(ssrfDispatch.failedCount >= 1 || ssrfDispatch.blockedCount >= 1, 'Private/metadata DNS target must be blocked on dispatch');
      const dlqEntries = whBus.listDlq({ limit: 10 });
      assert.ok(dlqEntries.length >= 1, 'Blocked/failed delivery must be recorded in DLQ');
      const replayBlocked = await whBus.replayDlqEntry(dlqEntries[0].id, {
        dnsLookupImpl: async () => [{ address: '127.0.0.1', family: 4 }],
        fetchImpl: async () => { throw new Error('fetch must NEVER be called for 127.0.0.1 on DLQ replay'); }
      });
      assert.strictEqual(replayBlocked.ok, false, 'DLQ replay must also block SSRF loopback/metadata IPs');

      // 11c. Dokploy CVE-2026-24841: Read-Only SQL & Safe Redis Write-Guard
      for (const badSql of [
        'SELECT 1; DROP TABLE users',
        "COPY users TO PROGRAM 'id'",
        '\\! id',
        'WITH x AS (DELETE FROM users RETURNING *) SELECT * FROM x'
      ]) {
        assert.throws(() => validateReadOnlySql(badSql), /solo lectura|prohibid|bloquead|mutat|stacked|multiple|invalid|not allowed|read-only|metacomm|backslash/i, `SQL guard must block: ${badSql}`);
      }
      const safeSql = validateReadOnlySql('SELECT id FROM users');
      assert.ok(safeSql.wrappedSql.includes('BEGIN TRANSACTION READ ONLY'));
      for (const badRedis of [['FLUSHALL'], ['EVAL', 'return 1', '0'], ['KEYS', '*'], ['CONFIG', 'GET', '*']]) {
        assert.throws(() => validateSafeRedisCommand(badRedis), /permitid|prohibid|bloquead|denied|not allowed|unsafe|read-only/i, `Redis guard must block: ${badRedis[0]}`);
      }
      const safeRedis = validateSafeRedisCommand(['SCAN', '0', 'COUNT', '500']);
      const safeRedisArgv = safeRedis.normalizedArgv || safeRedis.argv;
      assert.ok(Number(safeRedisArgv[safeRedisArgv.indexOf('COUNT') + 1]) <= 100, 'SCAN COUNT must clamp <= 100');

      // 11d. SigV4 Presigned URL & Bucket CORS Hardening
      const signed = generatePresignedUrl({
        endpoint: 'https://s3.example.test',
        region: 'us-east-1',
        bucket: 'culkibo-backups',
        key: 'pg/2026.sql.gz',
        method: 'GET',
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        expiresIn: 900
      });
      assert.strictEqual(signed.ok, true);
      assert.ok(signed.url.includes('X-Amz-Signature=') && signed.algorithm === 'AWS4-HMAC-SHA256');
      assert.throws(() => generatePresignedUrl({
        endpoint: 'https://s3.example.test',
        bucket: 'culkibo-backups',
        key: '../secret.txt',
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        expiresIn: 900
      }));
      assert.throws(() => generatePresignedUrl({
        endpoint: 'https://s3.example.test',
        bucket: 'culkibo-backups',
        key: 'ok.txt',
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        expiresIn: 604801
      }));
      assert.throws(() => buildBucketCorsXml([{ allowedOrigins: ['*'], allowedMethods: ['GET'], allowCredentials: true }]));

      // 11e. White-Label XSS / CSS Injection Guard (coolify#1744)
      const bt = new BrandThemeService({ dataDir: c9Tmp });
      assert.throws(() => sanitizeBrandLogo('javascript:alert(1)'));
      assert.throws(() => sanitizeBrandLogo('data:image/svg+xml,<svg onload="alert(1)"><script>x</script></svg>'));
      assert.throws(() => validateBrandPatch({ accentHex: '#fff; background:url(https://evil.test)' }));
      const cleanBrand = bt.updateBrand({ brandName: 'Sovereign Host', accentHex: '#0ea5e9' });
      assert.strictEqual(cleanBrand.brandName, 'Sovereign Host');
    } finally {
      fs.rmSync(c9Tmp, { recursive: true, force: true });
    }
  }
  console.log('  ✓ Cycle #9 CVEs (11a-11e): Dokploy CVE-2026-116068/127212 tenant ACL+CSV, Portainer CVE-2026-134756 webhook SSRF+dual-secret, Dokploy CVE-2026-24841 SQL/Redis guard, SigV4+CORS, coolify#1744 White-Label XSS');

  // -------------------------------------------------------------------------
  // 12. Cycle #10 Milestone Regressions (docs/COMPETITOR_RADAR_CYCLE9.md §3)
  // -------------------------------------------------------------------------
  {
    const zlib = require('zlib');
    const { BackupDrillService, planCrossTargetRestore } = require('../server/services/backupDrillService');
    const { RemoteBuilderService, buildPruneArgs } = require('../server/services/remoteBuilderService');
    const { estimateVram, auditAiImageSecurity, buildAiWorkloadSpec } = require('../server/services/aiWorkloadService');
    const { SloCanaryController } = require('../server/services/sloCanaryController');
    const { LogArchiveService, assertSafeRegex } = require('../server/services/logArchiveService');

    const c10Tmp = makeTempDir('culkibo-c10-cve-');
    try {
      // 12a. Empty/Corrupt Backup & Stripped-ACL Drill (dokploy#1382, coolify#6506/#12244, dokploy#6035)
      const dr = new BackupDrillService({ dataDir: c10Tmp });
      const zeroRes = await dr.runFireDrill({ databaseId: 'db_empty', engine: 'postgres', artifactBuffer: Buffer.alloc(0) });
      assert.strictEqual(zeroRes.verdict, 'FAIL', '0 B backup must FAIL DR fire-drill');
      const gz20Res = await dr.runFireDrill({ databaseId: 'db_gz20', engine: 'postgres', artifactBuffer: zlib.gzipSync(Buffer.alloc(0)) });
      assert.strictEqual(gz20Res.verdict, 'FAIL', 'Empty 20-byte gzip backup must FAIL DR fire-drill (dokploy#1382)');
      const noAclSql = '-- PostgreSQL database dump\n-- pg_dump --no-acl --no-owner\nCREATE TABLE t (id INT);\nINSERT INTO t VALUES (1);\n';
      const aclWarnRes = await dr.runFireDrill({ databaseId: 'db_noacl', engine: 'postgres', artifactBuffer: Buffer.from(noAclSql, 'utf8'), preserveAcl: true });
      assert.ok(Array.isArray(aclWarnRes.warnings) && aclWarnRes.warnings.length >= 1, 'preserveAcl: true must flag stripped ACL/no-acl (coolify#12244)');
      const sameOrgPlan = planCrossTargetRestore({ sourceDatabaseId: 'db_prod', targetDatabaseId: 'db_dev', sourceOrgId: 'org_1', targetOrgId: 'org_1', engine: 'postgres', preserveAcl: true });
      assert.ok(sameOrgPlan && !JSON.stringify(sameOrgPlan).includes('--no-acl'), 'Same-org restore with preserveAcl: true must keep grants (dokploy#6035 / coolify#12244)');
      assert.throws(
        () => planCrossTargetRestore({ sourceDatabaseId: 'db_prod', targetDatabaseId: 'db_other', sourceOrgId: 'org_1', targetOrgId: 'org_2', engine: 'postgres' }),
        (err) => err && (err.status === 403 || err.code === 'CROSS_ORG_RESTORE_FORBIDDEN')
      );

      // 12b. In-Flight SSH Mux Pin & Preview Builder Offload (coolify#11372, dokploy#3226/#3450)
      const rb = new RemoteBuilderService({ dataDir: c10Tmp });
      rb.registerBuilder({ id: 'b_prod', name: 'Prod Builder', host: '10.88.0.10', arch: 'linux/amd64', maxConcurrency: 1, allowPreviews: false });
      rb.registerBuilder({ id: 'b_prev', name: 'Preview Builder', host: '10.88.0.11', arch: 'linux/amd64', maxConcurrency: 2, allowPreviews: true });
      const slot1 = rb.acquireBuildSlot({ builderId: 'b_prod', projectId: 'p1', arch: 'linux/amd64', isPreview: false });
      assert.strictEqual(slot1.leased, true);
      assert.strictEqual(rb.canRecycleMux('b_prod').allowed, false, 'SSH mux recycle MUST be blocked while activeBuilds > 0 (coolify#11372)');
      const prevSlot = rb.acquireBuildSlot({ projectId: 'p2', arch: 'linux/amd64', isPreview: true });
      assert.strictEqual(prevSlot.leased, true);
      assert.strictEqual(prevSlot.builderId, 'b_prev', 'PR preview must offload to allowPreviews: true builder independently of busy prod builder (dokploy#3226/#3450)');
      rb.releaseBuildSlot(slot1.leaseId);
      assert.strictEqual(rb.canRecycleMux('b_prod').allowed, true, 'SSH mux recycle allowed once activeBuilds === 0');
      const pruneArgv = buildPruneArgs({ keepStorageGb: 20 });
      assert.ok(Array.isArray(pruneArgv) && pruneArgv.includes('--keep-storage') && pruneArgv.includes('20GB'));

      // 12c. AI/GPU Security & VRAM Guard (dokploy#1621, CVE-2025-63389, CVE-2026-7482, CVE-2026-137477, CVE-2026-22778)
      const vramTooBig = estimateVram({ paramsB: 70, quantization: 'FP16', contextLen: 8192, availableVramGb: 24 });
      assert.strictEqual(vramTooBig.fits, false);
      const vulnOllama = auditAiImageSecurity({ runtime: 'ollama', imageTag: 'ollama/ollama:0.16.0', bindAddress: '0.0.0.0', authProxyEnabled: false });
      assert.strictEqual(vulnOllama.safe, false);
      assert.ok(JSON.stringify(vulnOllama).includes('CVE-2025-63389') && JSON.stringify(vulnOllama).includes('CVE-2026-7482'));
      const vulnVllm = auditAiImageSecurity({ runtime: 'vllm', imageTag: 'vllm/vllm-openai:v0.19.0', bindAddress: '127.0.0.1', authProxyEnabled: true });
      assert.strictEqual(vulnVllm.safe, false);
      assert.ok(JSON.stringify(vulnVllm).includes('CVE-2026-22778'));
      const cdiSpec = buildAiWorkloadSpec({ runtime: 'ollama', model: 'llama3.2:8b', paramsB: 8, quantization: 'Q4_K_M', availableVramGb: 16, gpuMode: 'cdi', bindAddress: '127.0.0.1', authProxyEnabled: true });
      assert.strictEqual(cdiSpec.ok, true);
      assert.ok(cdiSpec.dockerArgs.includes('nvidia.com/gpu=all'), 'CDI mode must pass --device nvidia.com/gpu=all (dokploy#1621)');

      // 12d. SLO Burn-Rate Canary Auto-Rollback (10->25->50->100 & instant 100/0 rollback)
      const sc = new SloCanaryController({ dataDir: c10Tmp });
      /** @type {number[]} */
      const appliedWeights = [];
      const applyMock = async ({ canaryWeight }) => { appliedWeights.push(canaryWeight); };
      const r1 = await sc.startRollout({
        projectId: 'p_slo_1',
        hostname: 'slo.example.test',
        stableUpstream: '127.0.0.1:5000',
        canaryUpstream: '127.0.0.1:5001',
        steps: [10, 25, 50, 100],
        applyWeightsImpl: applyMock
      });
      const r1Id = (r1.rollout || r1).id;
      for (const expectedWeight of [25, 50, 100]) {
        const ev = await sc.evaluateRollout(r1Id, { totalRequests: 1000, error5xxCount: 0, baselineP95Ms: 30, canaryP95Ms: 32, applyWeightsImpl: applyMock });
        assert.strictEqual((ev.rollout || ev).canaryWeight, expectedWeight);
      }
      assert.strictEqual(sc.getRollout(r1Id).status, 'PROMOTED');

      const r2 = await sc.startRollout({
        projectId: 'p_slo_2',
        hostname: 'slo2.example.test',
        stableUpstream: '127.0.0.1:5002',
        canaryUpstream: '127.0.0.1:5003',
        steps: [10, 25, 50, 100],
        sloTarget: 0.999,
        maxBurnRate: 14.4
      });
      const r2Id = (r2.rollout || r2).id;
      const rbEval = await sc.evaluateRollout(r2Id, { totalRequests: 1000, error5xxCount: 30, baselineP95Ms: 30, canaryP95Ms: 35 });
      assert.strictEqual((rbEval.rollout || rbEval).status, 'ROLLED_BACK');
      assert.strictEqual((rbEval.rollout || rbEval).canaryWeight, 0);

      // 12e. Compressed Log Archive Survival, Pruning & ReDoS Guard (coolify#12170)
      const la = new LogArchiveService({ dataDir: c10Tmp });
      await la.appendLogs('p_log_1', [
        { ts: '2026-11-26T10:00:00Z', level: 'info', releaseId: 'rel_1', stream: 'stdout', message: 'Pre-redeploy event alpha' }
      ], { dateStr: '2026-11-26' });
      await la.appendLogs('p_log_1', [
        { ts: '2026-11-27T10:00:00Z', level: 'error', releaseId: 'rel_2', stream: 'stderr', message: 'Post-redeploy event beta' }
      ], { dateStr: '2026-11-27' });
      const searchAll = await la.searchArchives({ projectId: 'p_log_1', query: 'redeploy' });
      assert.strictEqual(searchAll.totalMatches, 2, 'Compressed .ndjson.gz logs must survive across simulated redeploys (coolify#12170)');
      assert.throws(
        () => assertSafeRegex('(a+)+$'),
        (err) => err && err.code === 'UNSAFE_REGEX',
        'ReDoS regex MUST be rejected with UNSAFE_REGEX'
      );
    } finally {
      fs.rmSync(c10Tmp, { recursive: true, force: true });
    }
  }
  console.log('  ✓ Cycle #10 CVEs (12a-12e): dokploy#1382/#6035/coolify#12244 DR drill, coolify#11372/dokploy#3226/#3450 SSH mux pin, AI/GPU CVE-2025-63389/CVE-2026-7482/CVE-2026-22778+CDI, SLO Canary burn-rate rollback, coolify#12170 log archive+ReDoS');

  // -------------------------------------------------------------------------
  // 13. Cycle #11 Enterprise Governance & Edge Regressions (docs/COMPETITOR_RADAR_CYCLE10.md §2.5)
  // -------------------------------------------------------------------------
  {
    const { AdmissionPolicyService, evaluateSpec } = require('../server/services/admissionPolicyService');
    const { ComplianceBundleService, verifyComplianceBundle } = require('../server/services/complianceBundleService');
    const { VolumeMigrationService, validateVolumeMigrationRequest } = require('../server/services/volumeMigrationService');
    const { EdgeExperimentService, compileGeoRoutes, compileAbExperimentRoute } = require('../server/services/edgeExperimentService');

    const c11Tmp = makeTempDir('culkibo-c11-cve-');
    try {
      // 13a. Coolify CVE-2025-66213 & <=beta.420.6 Host-Root Escape + Volume Name Injection
      const ap = new AdmissionPolicyService({ dataDir: c11Tmp });
      const hostEscapeRes = ap.evaluateDeployment({
        image: 'node:22-alpine',
        privileged: true,
        volumes: ['- /:/host:rw', '/var/run/docker.sock:/var/run/docker.sock'],
        cap_add: ['SYS_ADMIN']
      });
      assert.strictEqual(hostEscapeRes.allowed, false, 'Host-root escape spec MUST be denied');
      const escIds = hostEscapeRes.enforcedViolations.map((v) => v.id);
      assert.ok(escIds.includes('no_host_root_mount'), 'Must catch - /:/host:rw (Coolify <=beta.420.6)');
      assert.ok(escIds.includes('no_docker_sock_mount'), 'Must catch /var/run/docker.sock (coolify#8847)');
      assert.ok(escIds.includes('no_privileged'), 'Must catch privileged: true');
      assert.ok(escIds.includes('no_dangerous_caps'), 'Must catch cap_add: SYS_ADMIN');

      for (const badVol of ['pgdata;rm -rf /', 'vol$(id)', 'vol`whoami`', 'vol|cat /etc/shadow']) {
        assert.throws(
          () => validateVolumeMigrationRequest({
            projectId: 'proj_sec',
            volumeName: badVol,
            mountPath: '/var/lib/postgresql/data',
            targetHost: '10.88.0.22'
          }),
          (err) => err && err.status === 400 && err.code === 'UNSAFE_VOLUME_NAME',
          `CVE-2025-66213 volumeName "${badVol}" MUST be rejected with 400 UNSAFE_VOLUME_NAME`
        );
      }

      // 13b. Dokploy #2661 Public Bind & :latest / Root UID Admission (restricted & soc2-strict vs hardened)
      const pubFail = evaluateSpec({
        image: 'postgres:latest',
        user: '0',
        ports: ['0.0.0.0:3000:3000', '0.0.0.0:5432:5432']
      }, { preset: 'restricted' });
      assert.strictEqual(pubFail.allowed, false, 'Restricted preset MUST deny 0.0.0.0:3000/5432, :latest, UID 0 & missing caps');
      const pubIds = pubFail.enforcedViolations.map((v) => v.id);
      assert.ok(pubIds.includes('no_public_db_or_panel_bind'), 'Must block 0.0.0.0:3000 & 0.0.0.0:5432 (dokploy#2661)');
      assert.ok(pubIds.includes('no_latest_tag'), 'Must block :latest tag');
      assert.ok(pubIds.includes('require_non_root_uid'), 'Must block UID 0');
      assert.ok(pubIds.includes('require_resource_limits'), 'Must require memory/CPU limits');

      const hardenedPass = evaluateSpec({
        image: 'ghcr.io/culkibo/api:2.1.0',
        privileged: false,
        user: '1000:1000',
        memoryLimitMb: 512,
        cpuLimit: 1,
        healthcheckPath: '/health',
        bindAddress: '127.0.0.1',
        port: 3000,
        attestationVerified: true
      }, { preset: 'soc2-strict' });
      assert.strictEqual(hardenedPass.allowed, true, 'Hardened spec MUST pass soc2-strict');
      assert.strictEqual(hardenedPass.score, 100);

      // 13c. Dokploy #2642 / #4360 Ed25519-Signed Compliance Bundle + 1-Byte Tamper + 0 Canary Secrets
      const cb = new ComplianceBundleService({ dataDir: c11Tmp });
      const bundle = cb.generateBundle({
        framework: 'all',
        actor: 'auditor@example.test',
        snapshot: {
          accessControl: { userCount: 2, mfaEnabledUsers: 2, passkeyCount: 1, rbacEnabled: true },
          encryption: { vaultSecretCount: 4, aes256GcmEnabled: true, fileMode0600Enforced: true },
          audit: { chainValid: true, entryCount: 42 },
          supplyChain: { sbomCycloneDx16: true, slsaEd25519Enabled: true, criticalCves: 0, highCves: 0, staleSecretsCount: 0 },
          governance: { admissionPreset: 'soc2-strict', zeroShellEnforced: true },
          disasterRecovery: { totalDrills: 3, passedDrills: 3, latestRtoMs: 120, latestRpoSec: 15 }
        }
      });
      assert.strictEqual(verifyComplianceBundle(bundle).valid, true, 'Fresh Ed25519 compliance bundle MUST verify');
      assert.ok(bundle.markdownReport.includes('SOC2-CC6.1') && bundle.markdownReport.includes('ISO27001-A.8.24') && bundle.markdownReport.includes('GDPR-Art32'));
      assert.ok(!JSON.stringify(bundle).includes('BEGIN PRIVATE KEY'), 'Private key MUST never appear in bundle');
      const tamperedBundle = JSON.parse(JSON.stringify(bundle));
      tamperedBundle.payload.actor = 'tampered@example.test';
      assert.strictEqual(verifyComplianceBundle(tamperedBundle).valid, false, '1-byte tampered compliance bundle MUST fail verify');

      // 13d. Kamal / Dokploy UID-Preserving Volume Migration Plan (999:999 & 1000:1000, traversal block, cross-tenant 403)
      const vm = new VolumeMigrationService({ dataDir: c11Tmp });
      const pgPlan = vm.planMigration({
        projectId: 'proj_pg',
        volumeName: 'pg_prod_vol',
        mountPath: '/var/lib/postgresql/data',
        sourceHost: 'vps-1',
        targetHost: 'vps-2',
        uid: 999,
        gid: 999,
        sourceOrgId: 'org_a',
        targetOrgId: 'org_a'
      });
      const railsPlan = vm.planMigration({
        projectId: 'proj_rails',
        volumeName: 'rails_storage',
        mountPath: '/rails/storage',
        sourceHost: 'vps-1',
        targetHost: 'vps-2',
        uid: 1000,
        gid: 1000,
        sourceOrgId: 'org_a',
        targetOrgId: 'org_a'
      });
      assert.strictEqual(pgPlan.uidGid, '999:999');
      assert.strictEqual(railsPlan.uidGid, '1000:1000');
      assert.ok(JSON.stringify(pgPlan.phases).includes('--numeric-owner'), 'Tar phase MUST preserve --numeric-owner');
      assert.ok(JSON.stringify(pgPlan.phases[3]).includes('sha256sum'), 'Phase 4 MUST verify SHA-256 checksum');
      assert.throws(
        () => vm.planMigration({ projectId: 'proj_pg', volumeName: 'ok_vol', mountPath: '/var/data/../../etc/shadow', targetHost: 'vps-2' }),
        (err) => err && err.status === 400
      );
      assert.throws(
        () => vm.planMigration({ projectId: 'proj_pg', volumeName: 'ok_vol', mountPath: '/var/lib/postgresql/data', targetHost: 'vps-2', sourceOrgId: 'org_a', targetOrgId: 'org_b' }),
        (err) => err && err.status === 403 && err.code === 'CROSS_TENANT_FORBIDDEN'
      );

      // 13e. Caddy v2.11 Geo-Routing & Sticky A/B Compilation + Kill-Switch
      const ee = new EdgeExperimentService({ dataDir: c11Tmp });
      assert.throws(
        () => compileGeoRoutes({ regions: [{ countries: ['XX'], upstream: '10.0.0.1:3000' }], defaultUpstream: '10.0.0.2:3000' }),
        (err) => err && err.code === 'INVALID_COUNTRY_CODE'
      );
      assert.throws(
        () => compileAbExperimentRoute({ stickyMode: 'cookie', variants: [{ name: 'a', upstream: '127.0.0.1:3001', weight: 60 }, { name: 'b', upstream: '127.0.0.1:3002', weight: 30 }] }),
        (err) => err && err.code === 'INVALID_WEIGHT_SUM'
      );
      const geoRoutes = compileGeoRoutes({
        headerName: 'CF-IPCountry',
        regions: [{ countries: ['DE', 'FR', 'ES'], upstream: '10.10.0.1:3000' }],
        defaultUpstream: '10.20.0.1:3000'
      });
      assert.deepStrictEqual(geoRoutes[0].match[0].header['CF-IPCountry'], ['DE', 'FR', 'ES']);
      const hdrRoute = compileAbExperimentRoute({
        id: 'hdr_test',
        hostname: 'hdr.example.test',
        stickyMode: 'header',
        headerField: 'X-AB-Group',
        variants: [{ name: 'ctrl', upstream: '127.0.0.1:4001', weight: 70 }, { name: 'var', upstream: '127.0.0.1:4002', weight: 30 }]
      });
      assert.strictEqual(hdrRoute.handle[0].load_balancing.selection_policy.policy, 'header');
      assert.deepStrictEqual(hdrRoute.handle[0].load_balancing.selection_policy.fallback.weights, [70, 30]);

      const savedExp = ee.upsertExperiment({
        id: 'exp_c11_kill',
        projectId: 'proj_edge',
        hostname: 'ab.example.test',
        stickyMode: 'cookie',
        variants: [{ name: 'ctrl', upstream: '127.0.0.1:4001', weight: 50 }, { name: 'var', upstream: '127.0.0.1:4002', weight: 50 }]
      });
      assert.strictEqual(savedExp.experiment.compiledCaddy.route.handle[0].load_balancing.selection_policy.policy, 'cookie');
      const killed = ee.triggerKillSwitch('exp_c11_kill', { reason: 'regression_test' });
      assert.strictEqual(killed.killed, true);
      assert.strictEqual(killed.experiment.compiledCaddy.route.handle[0].upstreams.length, 1);
      assert.strictEqual(killed.experiment.compiledCaddy.route.handle[0].upstreams[0].dial, '127.0.0.1:4001');
      assert.strictEqual(killed.experiment.compiledCaddy.route.handle[0].load_balancing, undefined);
    } finally {
      fs.rmSync(c11Tmp, { recursive: true, force: true });
    }
  }
  console.log('  ✓ Cycle #11 CVEs (13a-13e): Coolify CVE-2025-66213/<=beta.420.6 host escape, dokploy#2661 public bind/UID 0, dokploy#2642/#4360 Ed25519 compliance bundle, Kamal/Dokploy --numeric-owner volume migration, Caddy v2.11 Geo+A/B kill-switch');

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
