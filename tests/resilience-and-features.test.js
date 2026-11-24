const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { parseSafeCommandArgv, sanitizeWorkdir } = require('../server/services/safeCommand');
const { parseCron, nextCronRun } = require('../server/services/cronParser');
const { CronManager } = require('../server/services/cronManager');
const { computePreviewIdentity } = require('../server/services/previewManager');
const { hashBcrypt, verifyBcrypt, isBcryptHash } = require('../server/services/bcryptHash');
const caddyManager = require('../server/services/caddyManager');
const ingressManager = require('../server/services/ingressManager');
const dbBackupManager = require('../server/services/dbBackupManager');
const webhookService = require('../server/services/webhookService');
const wordpressMigrator = require('../server/services/wordpressMigrator');
const universalImporter = require('../server/services/universalImporter');
const catalogManager = require('../server/services/catalogManager');
const auditLogger = require('../server/services/auditLogger');
const { createRateLimiter, resolveRateLimitIp } = require('../server/services/rateLimiter');
const authMiddleware = require('../server/middleware/auth');

const BASE_URL = process.env.CULKIBO_TEST_URL || 'http://127.0.0.1:3030';

function authedFetch(url, opts = {}) {
  const token = authMiddleware.getToken && authMiddleware.getToken();
  const headers = { ...(opts.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  return fetch(url, { ...opts, headers });
}

async function testResilienceAndFeatures() {
  console.log('\n--- Suite #22: Resilience, Edge Hardening, DR, Cron/Previews & Multi-Git ---');

  // 1. Safe Command Tokenizer (zero shell injection)
  const argv = parseSafeCommandArgv('npx prisma migrate status --schema "./prisma/schema.prisma"');
  assert.deepStrictEqual(argv, ['npx', 'prisma', 'migrate', 'status', '--schema', './prisma/schema.prisma']);
  for (const bad of ['ls; rm -rf /', 'echo ok | sh', 'cat /etc/passwd && id', 'echo $(whoami)', 'echo `id`', 'node\nid']) {
    assert.throws(() => parseSafeCommandArgv(bad), `Debió rechazar comando peligroso: ${bad}`);
  }
  assert.strictEqual(sanitizeWorkdir('/app/backend'), '/app/backend');
  assert.throws(() => sanitizeWorkdir('../etc'));
  console.log('✓ 1. safeCommand rechaza metacaracteres de shell y valida argv/workdir');

  // 2. Cron Parser & isolated CronManager CRUD + persistence
  assert.ok(parseCron('*/15 * * * *').minute.has(30));
  assert.ok(parseCron('@daily').hour.has(0));
  assert.throws(() => parseCron('not-a-cron'));
  const nextRun = nextCronRun('0 3 * * *', new Date('2026-06-01T01:00:00.000Z'));
  assert.ok(nextRun instanceof Date && nextRun.getTime() > Date.parse('2026-06-01T01:00:00.000Z'));

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-suite22-'));
  try {
    const cronFile = path.join(tmpDir, 'crons.json');
    const cm = new CronManager(cronFile);
    const created = cm.create('proj_test_s22', {
      name: 'Limpieza nocturna',
      schedule: '0 3 * * *',
      mode: 'exec',
      command: 'node scripts/cleanup.js'
    });
    assert.ok(created.id && created.enabled === true);
    assert.strictEqual(cm.list('proj_test_s22').length, 1);

    const reloaded = new CronManager(cronFile);
    assert.strictEqual(reloaded.list('proj_test_s22').length, 1);
    assert.strictEqual(reloaded.list('proj_test_s22')[0].name, 'Limpieza nocturna');
    reloaded.update(created.id, { enabled: false });
    assert.strictEqual(reloaded.list('proj_test_s22')[0].enabled, false);
    reloaded.remove(created.id);
    assert.strictEqual(reloaded.list('proj_test_s22').length, 0);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
  console.log('✓ 2. cronParser y CronManager (CRUD, persistencia y validación)');

  // 3. Preview Deployments slugging & anti-fork PR gate
  const prId = computePreviewIdentity(
    { id: 'p1', name: 'Mi App Web', previewDeployments: { baseDomain: '*.preview.culkibo.dev' } },
    { prNumber: 42 }
  );
  assert.strictEqual(prId.key, 'pr-42');
  assert.strictEqual(prId.hostname, 'pr-42-mi-app-web.preview.culkibo.dev');

  const brId = computePreviewIdentity(
    { id: 'p1', name: 'API', previewDeployments: { baseDomain: 'staging.culkibo.dev' } },
    { branch: 'feat/Pago_Stripe#1' }
  );
  assert.ok(/^br-feat-pago-stripe-1-[a-f0-9]{5}$/.test(brId.key), `Slug inesperado: ${brId.key}`);
  assert.ok(brId.hostname.endsWith('.staging.culkibo.dev'));

  const forkRes = await webhookService.dispatchPullRequest({
    provider: 'github',
    projects: [{ id: 'p_fork_test', name: 'ForkTest', previewDeployments: { enabled: true, allowForks: false } }],
    action: 'opened',
    prNumber: 77,
    branch: 'malicious-fork',
    isFork: true
  });
  assert.strictEqual(forkRes.status, 200);
  assert.strictEqual(forkRes.body.results[0].action, 'blocked');
  assert.strictEqual(forkRes.body.results[0].reason, 'fork_pr_blocked');
  console.log('✓ 3. previewManager RFC-1123 slugging y puerta de seguridad anti-forks');

  // 4. OpenBSD bcrypt + Caddy Edge Route Hardening (Basic Auth, IP Allowlist, Body Limit, Frame Policy)
  assert.strictEqual(
    verifyBcrypt('abc', '$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i'),
    true,
    'Vector OpenBSD bcrypt falló'
  );
  const hashed = hashBcrypt('CulkiboEdge#2026', 6);
  assert.strictEqual(isBcryptHash(hashed), true);
  assert.strictEqual(verifyBcrypt('CulkiboEdge#2026', hashed), true);
  assert.strictEqual(verifyBcrypt('wrong-password', hashed), false);

  const plainRoute = caddyManager.buildRoute({
    id: 'culkibo-plain',
    hostnames: ['plain.example.com'],
    upstreams: ['127.0.0.1:4100'],
    securityHeaders: false
  });
  assert.strictEqual(plainRoute.handle.length, 1);
  assert.strictEqual(plainRoute.handle[0].handler, 'reverse_proxy');

  const hardenedRoute = caddyManager.buildRoute({
    id: 'culkibo-hardened',
    hostnames: ['admin.example.com'],
    upstreams: ['127.0.0.1:4101'],
    basicAuth: { enabled: true, accounts: [{ username: 'admin', passwordHash: hashed }] },
    ipAllowlist: ['10.0.0.0/8', '192.168.1.10'],
    maxBodySizeMb: 25,
    framePolicy: 'DENY',
    customHeaders: { response: { 'X-Culkibo-Edge': 'verified' } }
  });
  assert.strictEqual(hardenedRoute.handle[0].handler, 'subroute', 'IP allowlist debe envolver en subroute 403');
  const denyRoute = hardenedRoute.handle[0].routes[0];
  assert.strictEqual(denyRoute.handle[0].status_code, '403');
  const innerChain = hardenedRoute.handle[0].routes[1].handle;
  const innerHandlers = innerChain.map((h) => h.handler);
  assert.ok(innerHandlers.includes('request_body'), 'maxBodySizeMb debe añadir request_body');
  assert.ok(innerHandlers.includes('authentication'), 'basicAuth debe añadir authentication');
  assert.strictEqual(innerHandlers[innerHandlers.length - 1], 'reverse_proxy');
  const authHandler = innerChain.find((h) => h.handler === 'authentication');
  assert.strictEqual(authHandler.providers.http_basic.accounts[0].username, 'admin');
  const proxyHandler = innerChain[innerChain.length - 1];
  assert.deepStrictEqual(proxyHandler.headers.response.set['X-Frame-Options'], ['DENY']);
  assert.deepStrictEqual(proxyHandler.headers.response.set['X-Culkibo-Edge'], ['verified']);
  console.log('✓ 4. bcrypt OpenBSD puro y hardening de rutas Caddy (Basic Auth, IP Allowlist, Body Limit)');

  // 5. TLS Expiry Audit watchdog
  const tlsAudit = await ingressManager.checkCertificateExpiry({ warnDays: 14, probeLive: false });
  assert.ok(tlsAudit && typeof tlsAudit.checkedAt === 'string');
  assert.strictEqual(tlsAudit.warnDays, 14);
  assert.ok(Array.isArray(tlsAudit.expired) && Array.isArray(tlsAudit.expiring));
  console.log('✓ 5. ingressManager.checkCertificateExpiry devuelve auditoría TLS estructurada');

  // 6. Full-Instance Disaster Recovery Snapshot + AES-256-GCM Encryption + Checksum integrity
  const redactedSnap = await dbBackupManager.exportInstanceSnapshot({
    includeSecrets: false,
    persist: false
  });
  assert.strictEqual(redactedSnap.success, true);
  assert.strictEqual(redactedSnap.snapshot.version, '2.0.0');
  assert.strictEqual(redactedSnap.snapshot.type, 'culkibo-instance-snapshot');
  assert.strictEqual(redactedSnap.secretsRedacted, true);
  assert.ok(/^sha256:[a-f0-9]{64}$/.test(redactedSnap.checksum));

  const encSnap = await dbBackupManager.exportInstanceSnapshot({
    includeSecrets: true,
    passphrase: 'DR-Passphrase-2026!',
    persist: false
  });
  assert.strictEqual(encSnap.encrypted, true);
  assert.strictEqual(encSnap.snapshot.data.cipher, 'aes-256-gcm');
  assert.strictEqual(encSnap.snapshot.data.kdf, 'scrypt');

  await assert.rejects(
    () => dbBackupManager.importInstanceSnapshot({ snapshot: encSnap.snapshot, dryRun: true, passphrase: 'wrong-passphrase' }),
    /contraseña|passphrase|descifrar|corrupto|inválida/i
  );

  const dryPlan = await dbBackupManager.importInstanceSnapshot({
    snapshot: encSnap.snapshot,
    dryRun: true,
    mode: 'merge',
    passphrase: 'DR-Passphrase-2026!'
  });
  assert.strictEqual(dryPlan.success, true);
  assert.strictEqual(dryPlan.applied, false);
  assert.ok(dryPlan.plan && typeof dryPlan.plan.mode === 'string');

  const tampered = JSON.parse(JSON.stringify(redactedSnap.snapshot));
  tampered.source = 'Tampered-Actor';
  await assert.rejects(
    () => dbBackupManager.importInstanceSnapshot({ snapshot: tampered, dryRun: true }),
    /Checksum/i
  );
  console.log('✓ 6. Snapshot completo de instancia v2 (redacción, cifrado AES-256-GCM, dryRun, checksum SHA-256)');

  // 7. Multi-Git Webhooks helpers (HMAC, Repo Slug, Monorepo watchPaths)
  const payloadBuf = Buffer.from('{"ref":"refs/heads/main"}', 'utf8');
  const sig = crypto.createHmac('sha256', 'my-secret').update(payloadBuf).digest('hex');
  assert.strictEqual(webhookService.verifyHmacSha256(payloadBuf, 'my-secret', `sha256=${sig}`), true);
  assert.strictEqual(webhookService.verifyHmacSha256(payloadBuf, 'my-secret', sig), true);
  assert.strictEqual(webhookService.verifyHmacSha256(payloadBuf, 'other-secret', sig), false);
  assert.strictEqual(webhookService.normalizeRepoSlug('git@gitlab.com:org/sub/web-app.git'), 'org/sub/web-app');
  assert.strictEqual(webhookService.normalizeRepoSlug('https://github.com/macaqueboy/culkibo.git'), 'macaqueboy/culkibo');
  assert.strictEqual(webhookService.matchesWatchPaths(['apps/web', 'packages/*'], ['apps/web/index.tsx']), true);
  assert.strictEqual(webhookService.matchesWatchPaths(['apps/web'], ['apps/api/server.js']), false);
  console.log('✓ 7. webhookService (HMAC multi-Git, normalización de slugs y filtro monorepo watchPaths)');

  // 8. WordPress SQL sanitizer, Railway TOML importer & 23-template Catalog
  const rawSql = '\uFEFFCREATE DATABASE `old`;\nUSE `old`;\nSET @@GLOBAL.GTID_PURGED="abc:1-2";\nCREATE TABLE `wp_posts` (`id` int) COLLATE=utf8mb4_0900_ai_ci;\nINSERT INTO `wp_options` VALUES (1,"siteurl","https://old.example.com");';
  const prepared = wordpressMigrator.helpers.prepareSqlForDomain(rawSql, 'https://old.example.com', 'https://new.example.com');
  assert.ok(!prepared.sql.includes('utf8mb4_0900_ai_ci'), 'Debe normalizar collation MySQL 8');
  assert.ok(prepared.sql.includes('utf8mb4_unicode_ci'));
  assert.ok(!prepared.sql.includes('SET @@GLOBAL.GTID_PURGED='));
  assert.ok(prepared.sql.includes('https://new.example.com'));

  const railwayCfg = universalImporter.parsePlatformConfig({
    platform: 'auto',
    configText: '[build]\nbuildCommand = "npm run build"\n[deploy]\nstartCommand = "npm start"\nhealthcheckPath = "/healthz"\n'
  });
  assert.strictEqual(railwayCfg.platform, 'railway');
  assert.strictEqual(railwayCfg.buildCommand, 'npm run build');
  assert.strictEqual(railwayCfg.startCommand, 'npm start');
  assert.strictEqual(railwayCfg.healthPath, '/healthz');

  const catalogTemplates = catalogManager.listTemplates();
  const catalogCategories = catalogManager.listCategories();
  assert.ok(catalogTemplates.length >= 23, `Esperaba >= 23 plantillas, obtuve ${catalogTemplates.length}`);
  assert.ok(catalogCategories.some((c) => c.id === 'ia'), 'Debe existir la categoría IA');
  for (const tpl of catalogTemplates) {
    assert.ok(!String(tpl.image || '').endsWith(':latest'), `Imagen sin versión fijada en ${tpl.id}: ${tpl.image}`);
  }
  console.log(`✓ 8. WordPress SQL sanitizer, Railway TOML y catálogo (${catalogTemplates.length} plantillas / ${catalogCategories.length} categorías)`);

  // 9. AuditLogger secret redaction & RateLimiter trusted proxy handling
  const rec = auditLogger.record({
    source: 'system',
    action: 'suite22.test',
    detail: { safe: 'visible', apiKey: 'sk_live_secret_123', nested: { password: 'p4ss' } }
  });
  assert.strictEqual(rec.detail.safe, 'visible');
  assert.strictEqual(rec.detail.apiKey, '[REDACTED]');
  assert.strictEqual(rec.detail.nested.password, '[REDACTED]');

  const spoofedReq = { socket: { remoteAddress: '203.0.113.5' }, headers: { 'x-forwarded-for': '1.2.3.4' } };
  assert.strictEqual(resolveRateLimitIp(spoofedReq), '203.0.113.5', 'No debe confiar en XFF de peer público');
  const trustedProxyReq = { socket: { remoteAddress: '127.0.0.1' }, headers: { 'x-forwarded-for': '9.9.9.9, 198.51.100.7' } };
  assert.strictEqual(resolveRateLimitIp(trustedProxyReq), '198.51.100.7');

  const limiter = createRateLimiter({ windowMs: 10000, max: 2, bypassLoopback: true });
  assert.strictEqual(limiter.check(spoofedReq).allowed, true);
  assert.strictEqual(limiter.check(spoofedReq).allowed, true);
  assert.strictEqual(limiter.check(spoofedReq).allowed, false);
  console.log('✓ 9. auditLogger (redacción automática de secretos) y rateLimiter (anti-spoofing XFF)');

  // 10. Live HTTP checks: Runtime stats/logs return 200 (never spurious 404) + MCP 72 tools / resources / prompts
  const listRes = await authedFetch(`${BASE_URL}/api/projects`);
  assert.strictEqual(listRes.status, 200);
  const projects = await listRes.json();
  if (Array.isArray(projects) && projects.length > 0) {
    const pid = projects[0].id;
    const rtStats = await authedFetch(`${BASE_URL}/api/projects/${pid}/runtime/stats`);
    const rtLogs = await authedFetch(`${BASE_URL}/api/projects/${pid}/runtime/logs?tail=50`);
    assert.strictEqual(rtStats.status, 200, `runtime/stats no debe devolver 4xx para proyecto existente (obtuvo ${rtStats.status})`);
    assert.strictEqual(rtLogs.status, 200, `runtime/logs no debe devolver 4xx para proyecto existente (obtuvo ${rtLogs.status})`);
  }

  const mcpCall = async (id, method, params = {}) => {
    const res = await authedFetch(`${BASE_URL}/api/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        'MCP-Protocol-Version': '2026-07-28',
        'Mcp-Method': method
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id,
        method,
        params: {
          ...params,
          _meta: {
            'io.modelcontextprotocol/protocolVersion': '2026-07-28',
            'io.modelcontextprotocol/clientCapabilities': {},
            'io.modelcontextprotocol/clientInfo': { name: 'culkibo-suite22', version: '1.0.0' }
          }
        }
      })
    });
    assert.strictEqual(res.status, 200, `MCP ${method} debe responder 200 (obtuvo ${res.status})`);
    return res.json();
  };

  const mcpToolsJson = await mcpCall(1, 'tools/list');
  assert.ok(mcpToolsJson.result.tools.length >= 72, `MCP debe exponer >= 72 herramientas (obtuvo ${mcpToolsJson.result.tools.length})`);

  const mcpResJson = await mcpCall(2, 'resources/list');
  assert.ok(Array.isArray(mcpResJson.result.resources) && mcpResJson.result.resources.length >= 4);

  const mcpPromptsJson = await mcpCall(3, 'prompts/list');
  assert.ok(Array.isArray(mcpPromptsJson.result.prompts) && mcpPromptsJson.result.prompts.length >= 3);
  console.log(`✓ 10. Runtime HTTP 200 limpio y MCP (${mcpToolsJson.result.tools.length} tools, ${mcpResJson.result.resources.length} resources, ${mcpPromptsJson.result.prompts.length} prompts)`);
}

if (require.main === module) {
  const { ensureDaemon } = require('./helpers/daemon');
  ensureDaemon()
    .then(async (stop) => {
      try {
        await testResilienceAndFeatures();
        console.log('\n✅ Suite #22 completada correctamente.\n');
      } finally {
        await stop();
      }
    })
    .catch((err) => {
      console.error('❌ Suite #22 falló:', err);
      process.exit(1);
    });
}

module.exports = testResilienceAndFeatures;
