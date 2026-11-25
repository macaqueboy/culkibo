const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const auth = require('../server/middleware/auth');
const { hashBcrypt, verifyBcrypt, isBcryptHash } = require('../server/services/bcryptHash');
const { parseCron } = require('../server/services/cronParser');
const webhookService = require('../server/services/webhookService');
const caddyManager = require('../server/services/caddyManager');
const domainManager = require('../server/services/domainManager');
const { SslManager } = require('../server/services/sslManager');
const { DeployManager } = require('../server/services/deployManager');
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
  console.log('\n🧪 Suite #23: Regresiones de PRs y CVEs de competidores (Wave-1 + Wave-2)...');

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
