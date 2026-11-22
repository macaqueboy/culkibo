const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { isLoopback, authorizeRequest } = require('../server/middleware/auth');
const ssrfGuard = require('../server/services/ssrfGuard');
const Project = require('../server/models/Project');
const projectManager = require('../server/services/projectManager');
const localRunner = require('../server/services/localRunner');
const deployManager = require('../server/services/deployManager');
const caddyManager = require('../server/services/caddyManager');
const liveSyncEngine = require('../server/services/liveSyncEngine');
const dbBackupManager = require('../server/services/dbBackupManager');
const databaseManager = require('../server/services/databaseManager');
const mcpServer = require('../server/services/mcpServer');
const ingressManager = require('../server/services/ingressManager');
const notificationService = require('../server/services/notificationService');
const { S3Client } = require('../server/services/s3Uploader');

async function testSecurityHardening() {
  console.log('🔒 Testing Security Hardening (C1–C6, H1–H9)...');

  // C1: Proxy-aware loopback detection + DNS rebinding Origin rejection
  const spoofedProxyReq = {
    socket: { remoteAddress: '127.0.0.1' },
    headers: { 'x-forwarded-for': '203.0.113.45', host: 'localhost:3030' }
  };
  assert.strictEqual(isLoopback(spoofedProxyReq), false, 'X-Forwarded-For externo no puede pasar por loopback');

  const forwardedHeaderReq = {
    socket: { remoteAddress: '127.0.0.1' },
    headers: { forwarded: 'for=198.51.100.7;proto=https', host: 'localhost:3030' }
  };
  assert.strictEqual(isLoopback(forwardedHeaderReq), false, 'Cabecera Forwarded externa no puede pasar por loopback');

  const rebindingReq = {
    socket: { remoteAddress: '127.0.0.1' },
    headers: { origin: 'https://evil-attacker.example', host: 'localhost:3030' }
  };
  const rebindDecision = authorizeRequest(rebindingReq);
  assert.strictEqual(rebindDecision.ok, false);
  assert.strictEqual(rebindDecision.status, 403, 'Origin externo sin permitir debe responder 403');
  console.log('  ✓ C1: X-Forwarded-For / Forwarded spoofing y DNS rebinding bloqueados');

  // C2: Live Sync path traversal + invalid projectId + leaf symlink protection
  assert.throws(
    () => liveSyncEngine.resolveTargetDir('../escape'),
    /inválido/i,
    'Live Sync debe rechazar projectId con path traversal'
  );
  const tmpSyncDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-sec-sync-'));
  try {
    liveSyncEngine.setTargetDir('sec_sync_proj', tmpSyncDir);
    assert.throws(
      () => liveSyncEngine.applyCommitFrame('sec_sync_proj', {
        seq: 1,
        files: [{ path: '../../escaped.txt', op: 'upsert', contentBase64: Buffer.from('x').toString('base64') }]
      }),
      /bloqueada|traversal|fuera/i,
      'Live Sync debe bloquear rutas con ..'
    );
  } finally {
    liveSyncEngine.resetSession('sec_sync_proj');
    liveSyncEngine.targetOverrides.delete('sec_sync_proj');
    fs.rmSync(tmpSyncDir, { recursive: true, force: true });
  }
  console.log('  ✓ C2: Live Sync bloquea projectId inválido y path traversal');

  // C3: Project ID traversal, immutable id/createdAt on update, baseDirectory containment
  assert.throws(
    () => new Project({ id: '../../pwned', name: 'Bad' }),
    /invalid|inválido|traversal/i,
    'Project debe rechazar IDs con traversal'
  );
  const tmpProj = projectManager.create({ name: 'Sec Test Proj' });
  const origCreatedAt = tmpProj.createdAt;
  try {
    const updated = projectManager.update(tmpProj.id, {
      id: 'hijacked_id',
      createdAt: '1999-01-01T00:00:00.000Z',
      description: 'actualizado'
    });
    assert.strictEqual(updated.id, tmpProj.id, 'update() no puede sobrescribir id');
    assert.strictEqual(updated.createdAt, origCreatedAt, 'update() no puede sobrescribir createdAt');

    const parentTmp = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-basedir-parent-'));
    const rootDir = path.join(parentTmp, 'proj');
    const siblingDir = path.join(parentTmp, 'evil-sibling');
    fs.mkdirSync(rootDir, { recursive: true });
    fs.mkdirSync(siblingDir, { recursive: true });
    fs.writeFileSync(path.join(siblingDir, 'package.json'), '{"name":"evil"}');
    try {
      const resolved = localRunner.resolveRunnableDirectory(rootDir, '../evil-sibling');
      assert.strictEqual(path.resolve(resolved.path), path.resolve(rootDir), 'resolveRunnableDirectory jamás puede escapar fuera de projectDir');
      assert.throws(() => ssrfGuard.assertContainedPath(rootDir, '../evil-sibling'), /fuera|traversal|ruta/i);
    } finally {
      fs.rmSync(parentTmp, { recursive: true, force: true });
    }
  } finally {
    projectManager.delete(tmpProj.id);
    await projectManager.flushToDisk();
  }
  console.log('  ✓ C3: Project ID, campos inmutables y baseDirectory blindados');

  // C4: Host env filtering prevents PATH/DOCKER_HOST/LD_PRELOAD/NODE_OPTIONS hijacking
  const filteredEnv = deployManager.helpers.filterSafeHostEnv({
    PATH: '/tmp/evil',
    DOCKER_HOST: 'tcp://attacker:2375',
    LD_PRELOAD: '/tmp/evil.so',
    NODE_OPTIONS: '--require /tmp/evil.js',
    PUBLIC_API_URL: 'https://api.example.com'
  });
  assert.strictEqual(filteredEnv.PATH, undefined);
  assert.strictEqual(filteredEnv.DOCKER_HOST, undefined);
  assert.strictEqual(filteredEnv.LD_PRELOAD, undefined);
  assert.strictEqual(filteredEnv.NODE_OPTIONS, undefined);
  assert.strictEqual(filteredEnv.PUBLIC_API_URL, 'https://api.example.com');
  console.log('  ✓ C4: Variables peligrosas (PATH/DOCKER_HOST/LD_PRELOAD/NODE_OPTIONS) bloqueadas');

  // C5: Caddy startWithDocker rejects untrusted images / flags; Wildcard rejects bad tokenEnv
  await assert.rejects(
    () => caddyManager.startWithDocker({ image: 'evil/backdoor:latest' }),
    /imagen|permitid|inválid/i
  );
  await assert.rejects(
    () => caddyManager.startWithDocker({ containerName: '--privileged' }),
    /nombre|contenedor|inválid/i
  );
  await assert.rejects(
    () => caddyManager.configureWildcardDns01('example.com', { tokenEnv: 'BAD;rm -rf /' }),
    /tokenEnv|inválid/i
  );
  console.log('  ✓ C5: Caddy image/name/tokenEnv validados estrictamente');

  // C6: Git PAT scoped ONLY to github.com; file:// blocked
  const attackerEnv = localRunner.gitAuthEnv('https://attacker.example/victim/repo.git');
  assert.strictEqual(attackerEnv.CULKIBO_GIT_TOKEN, undefined, 'No se debe adjuntar el token GitHub a hosts externos');
  assert.strictEqual(attackerEnv.GIT_ASKPASS, undefined, 'No se debe adjuntar GIT_ASKPASS a hosts externos');
  assert.strictEqual(localRunner.normalizeGitUrl('file:///etc/passwd'), null, 'file:// debe ser bloqueado');
  console.log('  ✓ C6: PAT de GitHub limitado exclusivamente a github.com y file:// bloqueado');

  // H1: SSRF guard blocks cloud metadata & private IPs across services
  await assert.rejects(() => ssrfGuard.assertSafeUrl('http://169.254.169.254/latest/meta-data/'), /SSRF|metadatos|privad|bloquead/i);
  await assert.rejects(() => ssrfGuard.assertSafeUrl('http://127.0.0.1:3030/api/projects'), /SSRF|privad|bloquead/i);
  await assert.rejects(() => ssrfGuard.assertSafeUrl('http://10.0.0.1/admin'), /SSRF|privad|bloquead/i);
  assert.throws(
    () => new S3Client({ endpoint: 'http://169.254.169.254', bucket: 'b', accessKeyId: 'k', secretAccessKey: 's' }),
    /metadatos|bloquead|SSRF/i
  );
  await assert.rejects(
    () => notificationService.sendToChannel('discord', { level: 'info', title: 't', message: 'm' }),
    /.+/
  );
  const origDiscord = notificationService.config.channels.discord.webhookUrl;
  try {
    notificationService.config.channels.discord.webhookUrl = 'https://evil.example/api/webhooks/123';
    await assert.rejects(
      () => notificationService.sendToChannel('discord', { level: 'info', title: 't', message: 'm' }),
      /Discord|oficial/i
    );
  } finally {
    notificationService.config.channels.discord.webhookUrl = origDiscord;
  }
  console.log('  ✓ H1: Protección SSRF verificada (metadata, loopback, RFC1918, S3 y webhooks)');

  // H3: Backup restore confined to backupsDir by default
  await assert.rejects(
    () => dbBackupManager.restoreProject('../../package.json'),
    /fuera|backup|permitid|ruta/i,
    'restoreProject debe rechazar rutas fuera de data/backups por defecto'
  );
  console.log('  ✓ H3: restoreProject confinado a data/backups por defecto');

  // H5: MCP audit log redacts nested secrets recursively
  mcpServer.logCall(
    'culkibo_update_env',
    {
      projectId: 'p1',
      apiToken: 'super_secret_token_999',
      nested: { password: 'my_db_password_123' },
      envVars: { STRIPE_SECRET: 'sk_live_secret' }
    },
    'ok',
    true,
    2
  );
  const latestAudit = mcpServer.getAuditLog(1)[0];
  const serializedAudit = JSON.stringify(latestAudit);
  assert.ok(!serializedAudit.includes('super_secret_token_999'), 'apiToken no puede aparecer en el auditLog');
  assert.ok(!serializedAudit.includes('my_db_password_123'), 'password anidado no puede aparecer en el auditLog');
  assert.ok(!serializedAudit.includes('sk_live_secret'), 'envVars no puede aparecer en claro en el auditLog');
  console.log('  ✓ H5: Audit log MCP redacta secretos de forma recursiva');

  // H7: Database non-loopback IPv4 exposure requires explicit acknowledgeRisk
  const fakeDbId = `db_sec_${Date.now()}`;
  const fakeDbRecord = {
    id: fakeDbId,
    projectId: 'proj_sec',
    engine: 'postgres',
    name: 'SecDB',
    containerName: 'culkibo_db_sec_test',
    volumeName: 'culkibo_vol_sec_test',
    networkName: 'culkibo_net_sec_test',
    port: 5432,
    exposure: { enabled: false, bindAddress: '127.0.0.1', hostPort: null }
  };
  databaseManager.state.databases.push(fakeDbRecord);
  try {
    await assert.rejects(
      () => databaseManager.setExposure(fakeDbId, { enabled: true, bindAddress: '192.168.1.50', hostPort: 5432 }),
      /acknowledgeRisk|expone|interfaz|0\.0\.0\.0|127\.0\.0\.1/i
    );
  } finally {
    const idx = databaseManager.state.databases.findIndex((d) => d.id === fakeDbId);
    if (idx !== -1) databaseManager.state.databases.splice(idx, 1);
  }
  console.log('  ✓ H7: Exposición de BD en IPv4 no-loopback exige acknowledgeRisk: true');

  // H8: ingressManager preserves active production deployManager routes
  const prodProj = projectManager.create({ name: 'Prod Route Test', domains: ['prod-h8.example.com'] });
  const prevState = deployManager.store[prodProj.id];
  try {
    deployManager.store[prodProj.id] = {
      current: {
        containerName: 'culkibo_app_h8',
        upstream: '127.0.0.1:45123',
        status: 'activo'
      }
    };
    const upstream = ingressManager.upstreamForProject(prodProj);
    assert.strictEqual(upstream, '127.0.0.1:45123', 'ingressManager debe preservar el puerto activo de producción de deployManager');
  } finally {
    if (prevState === undefined) delete deployManager.store[prodProj.id];
    else deployManager.store[prodProj.id] = prevState;
    projectManager.delete(prodProj.id);
    await projectManager.flushToDisk();
  }
  console.log('  ✓ H8: ingressManager conserva rutas activas de producción al reconciliar');

  console.log('✅ Security Hardening Suite PASSED!\n');
}

module.exports = testSecurityHardening;

if (require.main === module) {
  testSecurityHardening()
    .then(() => { setTimeout(() => process.exit(0), 50); })
    .catch((err) => {
      console.error('❌ Security hardening failure:', err);
      process.exit(1);
    });
}
