const assert = require('assert');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const { isLoopback, authorizeRequest } = require('../server/middleware/auth');
const ssrfGuard = require('../server/services/ssrfGuard');
const { AuditLogger } = require('../server/services/auditLogger');
const secretScanner = require('../server/services/secretScanner');
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

  // S1: Advanced SSRF Bypass Matrix (128-bit IPv6, NAT64, FQDN trailing dot, cross-origin redirect header strip)
  {
    const blockedIps = [
      '0::1',
      '0:0::1',
      '::0:1',
      '0000:0000:0000:0000:0000:0000:0000:0001',
      '[0::1]',
      '::ffff:169.254.169.254',
      '::ffff:a9fe:a9fe',
      '0::ffff:127.0.0.1',
      '0:0:0:0:0:ffff:169.254.169.254',
      '::ffff:0:127.0.0.1',
      '64:ff9b::169.254.169.254',
      '64:ff9b::a9fe:a9fe',
      '2002:a9fe:a9fe::1',
      'fe80::1%eth0',
      '100::1',
      'fd00:ec2::254',
      'fd00:0ec2::0254',
      '2001:0000::1',
      '2001:db8::1'
    ];
    for (const ip of blockedIps) {
      assert.strictEqual(ssrfGuard.isPrivateIp(ip), true, `IPv6/embebida privada debe bloquearse: ${ip}`);
    }
    assert.strictEqual(ssrfGuard.isMetadataIp('64:ff9b::169.254.169.254'), true);
    assert.strictEqual(ssrfGuard.isMetadataIp('0:0:0:0:0:ffff:169.254.169.254'), true);
    assert.strictEqual(ssrfGuard.isMetadataIp('fd00:0ec2::0254'), true);
    assert.strictEqual(ssrfGuard.isPrivateIp('2606:4700:4700::1111'), false, 'IPv6 pública debe permitirse');
    assert.strictEqual(ssrfGuard.isPrivateIp('2001:4860:4860::8888'), false, 'IPv6 pública debe permitirse');

    // FQDN trailing dot & cloud metadata hostnames
    await assert.rejects(() => ssrfGuard.assertSafeUrl('http://localhost./api'), /SSRF|privad|bloquead/i);
    await assert.rejects(() => ssrfGuard.assertSafeUrl('http://metadata.google.internal./computeMetadata/v1/'), /metadatos|bloquead/i);
    await assert.rejects(() => ssrfGuard.assertSafeUrl('http://metadata.azure.com./metadata/instance'), /metadatos|bloquead/i);

    // Real HTTP redirect test: strip custom sensitive headers cross-origin + block redirect to metadata
    let receivedHeadersAtB = null;
    const srvB = await new Promise((resolve) => {
      const s = http.createServer((req, res) => {
        receivedHeadersAtB = { ...req.headers };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      });
      s.listen(0, '127.0.0.1', () => resolve(s));
    });
    const portB = /** @type {any} */ (srvB.address()).port;

    const srvA = await new Promise((resolve) => {
      const s = http.createServer((req, res) => {
        if (req.url === '/to-b') {
          res.writeHead(302, { Location: `http://127.0.0.1:${portB}/dest` });
          return res.end();
        }
        res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
        res.end();
      });
      s.listen(0, '127.0.0.1', () => resolve(s));
    });
    const portA = /** @type {any} */ (srvA.address()).port;

    try {
      const resOk = await ssrfGuard.safeFetch(`http://127.0.0.1:${portA}/to-b`, {
        allowLoopback: true,
        headers: {
          Authorization: 'Bearer secret_tok_123',
          Cookie: 'culkibo_session=cks_secret',
          'X-API-Key': 'api_key_secret',
          'Private-Token': 'glpat-secret',
          'X-Custom-Safe': 'keep-me'
        }
      });
      assert.strictEqual(resOk.status, 200);
      assert.strictEqual(receivedHeadersAtB.authorization, undefined, 'Authorization debe eliminarse en redirect cross-origin');
      assert.strictEqual(receivedHeadersAtB.cookie, undefined, 'Cookie debe eliminarse en redirect cross-origin');
      assert.strictEqual(receivedHeadersAtB['x-api-key'], undefined, 'X-API-Key debe eliminarse en redirect cross-origin');
      assert.strictEqual(receivedHeadersAtB['private-token'], undefined, 'Private-Token debe eliminarse en redirect cross-origin');
      assert.strictEqual(receivedHeadersAtB['x-custom-safe'], 'keep-me');

      await assert.rejects(
        () => ssrfGuard.safeFetch(`http://127.0.0.1:${portA}/to-meta`, { allowLoopback: true }),
        /metadatos|SSRF|bloquead/i
      );
    } finally {
      await new Promise((r) => srvA.close(r));
      await new Promise((r) => srvB.close(r));
    }
    console.log('  ✓ S1: Matriz SSRF avanzada (128-bit IPv6, NAT64, trailing dot, strip cabeceras en redirect)');
  }

  // S2: realpathSync symlink escape & sensitive home dir guard in projectManager.validateProjectData
  {
    const symParent = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-sym-guard-'));
    try {
      const targetDataDir = path.resolve(path.dirname(projectManager.dataPath));
      const linkPath = path.join(symParent, 'innocent-link');
      fs.symlinkSync(targetDataDir, linkPath, process.platform === 'win32' ? 'junction' : 'dir');
      assert.throws(
        () => projectManager.validateProjectData({ localPath: linkPath }),
        /interno|data\/|sensible/i,
        'Un symlink/junction hacia data/ debe ser bloqueado por realpathSync'
      );
      assert.throws(
        () => projectManager.validateProjectData({ localPath: path.join(os.homedir(), '.ssh') }),
        /sensible/i,
        '~/.ssh debe ser bloqueado como localPath'
      );
      assert.throws(
        () => ssrfGuard.assertContainedPath(symParent, 'backup.json\0.txt'),
        /inválida|nulos/i,
        'assertContainedPath debe rechazar bytes nulos embebidos'
      );
    } finally {
      fs.rmSync(symParent, { recursive: true, force: true });
    }
    console.log('  ✓ S2: projectManager bloquea symlinks/junctions hacia data/ y directorios sensibles (~/.ssh)');
  }

  // S3: Tamper-Evident SHA-256 Hash-Chained Audit Log + Rotation Anchor + Tamper Detection
  {
    const auditTmp = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-audit-chain-'));
    try {
      const logger = new AuditLogger({ dataDir: auditTmp, maxFileBytes: 2500 });
      for (let i = 0; i < 9; i++) {
        logger.record({
          source: 'http',
          action: `project.action_${i}`,
          method: 'POST',
          path: `/api/projects/p${i}`,
          ip: '203.0.113.5',
          authMethod: 'session',
          actor: { userId: 'usr_1', email: 'alice@example.com', role: 'admin', teamId: 'team_default', kind: 'session' },
          status: 200,
          detail: i === 0
            ? { msg: 'AKIAIOSFODNN7EXAMPLE ' + 'sk_live' + '_TESTKEY00000000000000000 postgres://admin:TopSecret99@db/prod' }
            : { index: i }
        });
        if (i === 5) logger.flushSync(); // 6 registros (~2.4 KB > 1800 B) -> rotación #1 + ancla audit.log_rotated
      }
      logger.flushSync(); // 3 registros adicionales (~1.2 KB < 1800 B) en audit.jsonl activo

      // Verificar redacción de secretos y metadatos de actor
      const queried = logger.query({ limit: 20, actor: 'alice@example.com', teamId: 'team_default' });
      assert.strictEqual(queried.length, 9);
      const allText = JSON.stringify(queried);
      assert.ok(!allText.includes('AKIAIOSFODNN7EXAMPLE'), 'AWS key debe redactarse en auditLogger');
      assert.ok(!allText.includes('sk_live' + '_TESTKEY00000000000000000'), 'Stripe key debe redactarse en auditLogger');
      assert.ok(!allText.includes('TopSecret99'), 'Contraseña DB URI debe redactarse en auditLogger');

      // Verificar cadena completa a través de la rotación (.1 + activa) y también solo activa (anchored)
      assert.ok(fs.existsSync(path.join(auditTmp, 'audit.jsonl.1')), 'Debe haberse creado audit.jsonl.1 tras rotación');
      const vFull = logger.verifyIntegrity({ includeRotated: true });
      assert.strictEqual(vFull.valid, true, `Cadena completa debe ser válida: ${JSON.stringify(vFull)}`);
      assert.strictEqual(vFull.checkedCount, 10, 'Debe incluir los 9 eventos + 1 registro ancla de rotación');
      assert.strictEqual(vFull.anchored, false, 'Con .1 incluido la cadena arranca desde GENESIS_HASH');

      const vActiveOnly = logger.verifyIntegrity({ includeRotated: false });
      assert.strictEqual(vActiveOnly.valid, true);
      assert.strictEqual(vActiveOnly.anchored, true, 'El archivo rotado activo debe reconocerse como anclado');

      // Prueba de manipulación #1: alterar 1 carácter en audit.jsonl
      const activeFile = path.join(auditTmp, 'audit.jsonl');
      const originalActive = fs.readFileSync(activeFile, 'utf8');
      const tampered1 = originalActive.replace('project.action_7', 'project.action_XX');
      assert.notStrictEqual(tampered1, originalActive);
      fs.writeFileSync(activeFile, tampered1, 'utf8');
      const vTamper1 = logger.verifyIntegrity({ includeRotated: true });
      assert.strictEqual(vTamper1.valid, false, 'Alterar 1 campo debe romper verifyIntegrity()');
      assert.strictEqual(vTamper1.reason, 'ENTRY_HASH_TAMPERED');

      // Prueba de manipulación #2: borrar una línea intermedia
      const activeLines = originalActive.trim().split('\n');
      activeLines.splice(2, 1);
      fs.writeFileSync(activeFile, activeLines.join('\n') + '\n', 'utf8');
      const vTamper2 = logger.verifyIntegrity({ includeRotated: true });
      assert.strictEqual(vTamper2.valid, false, 'Borrar una línea debe detectarse como discontinuidad');
      assert.ok(String(vTamper2.reason).includes('SEQ_DISCONTINUITY'));

      // Restaurar -> vuelve a ser válido
      fs.writeFileSync(activeFile, originalActive, 'utf8');
      assert.strictEqual(logger.verifyIntegrity({ includeRotated: true }).valid, true);
    } finally {
      fs.rmSync(auditTmp, { recursive: true, force: true });
    }
    console.log('  ✓ S3: Audit log SHA-256 hash-chained (rotación anclada, actor, redacción y detección de tampering)');
  }

  // S4: Pre-Deploy Secret Leak Scanner (AWS, Stripe, GitHub, GitLab, OpenAI, GCP, Slack, PEM, DB URI, JWT, entropy)
  {
    const sampleAws = 'AKIAIOSFODNN7EXAMPLE';
    const sampleStripe = 'sk_live' + '_TESTKEY000000000000000000000';
    const sampleGh = 'ghp_1234567890abcdefABCDEF1234567890ab';
    const sampleOpenAi = 'sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456';
    const sampleGcp = 'AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe';
    const sampleJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const sampleCustom = 'Qz9!kL2#mN8$pR4%vW7&yB3*xD6^fH1@';

    const report = secretScanner.scanDeploymentPayload({
      envVars: {
        AWS_ACCESS_KEY_ID: sampleAws,
        STRIPE_SECRET_KEY: sampleStripe,
        GITHUB_TOKEN: sampleGh,
        OPENAI_API_KEY: sampleOpenAi,
        GOOGLE_API_KEY: sampleGcp,
        AUTH_JWT: sampleJwt,
        CUSTOM_SIGNING_SECRET: sampleCustom,
        SAFE_VAULT_REF: '${vault.STRIPE_SECRET_KEY}',
        NODE_ENV: 'production',
        APP_URL: 'https://app.example.com/health',
        PLACEHOLDER_DB: 'postgres://user:changeme@localhost:5432/app'
      },
      composeYaml: [
        'services:',
        '  api:',
        '    environment:',
        '      DATABASE_URL: postgres://prod:UltraHardPass88!@db.internal:5432/app',
        '      SLACK_BOT_TOKEN: xoxb-0000000fake-0000000fake00-TestOnlyNotARealSlackToken',
        '      PRIVATE_KEY: |',
        '        -----BEGIN RSA PRIVATE KEY-----',
        '        MIIEowIBAAKCAQEA...',
        '        -----END RSA PRIVATE KEY-----'
      ].join('\n')
    }, { mode: 'block' });

    assert.strictEqual(report.clean, false);
    assert.strictEqual(report.blocked, true);
    const ruleIds = new Set(report.findings.map((f) => f.ruleId));
    for (const expected of [
      'aws-access-key-id',
      'stripe-live-key',
      'github-token',
      'openai-anthropic-key',
      'gcp-api-key',
      'jwt-token',
      'high-entropy-secret',
      'db-uri-credentials',
      'slack-token',
      'private-key-pem'
    ]) {
      assert.ok(ruleIds.has(expected), `secretScanner debe detectar ${expected}`);
    }

    // Jamás debe reflejar secretos en claro en el reporte ni disparar falsos positivos en ${vault.*}/placeholders
    const reportJson = JSON.stringify(report);
    for (const raw of [sampleAws, sampleStripe, sampleGh, sampleOpenAi, sampleGcp, sampleJwt, sampleCustom, 'UltraHardPass88!']) {
      assert.ok(!reportJson.includes(raw), `El reporte de secretScanner jamás puede incluir el secreto en claro: ${raw.slice(0, 6)}`);
    }
    assert.ok(!report.findings.some((f) => f.key === 'SAFE_VAULT_REF' || f.key === 'NODE_ENV' || f.key === 'APP_URL' || f.key === 'PLACEHOLDER_DB'));

    // assertCleanForDeploy lanza HTTP 422 SECRET_LEAK_DETECTED
    assert.throws(
      () => secretScanner.assertCleanForDeploy({ envVars: { STRIPE: sampleStripe } }),
      (err) => err.status === 422 && err.code === 'SECRET_LEAK_DETECTED'
    );

    // Payload limpio pasa sin falsos positivos
    const cleanRep = secretScanner.assertCleanForDeploy({
      envVars: { NODE_ENV: 'production', STRIPE_KEY: '${vault.STRIPE_KEY}', PORT: '3000' }
    });
    assert.strictEqual(cleanRep.clean, true);
    assert.strictEqual(cleanRep.blocked, false);
    console.log('  ✓ S4: Pre-deploy secretScanner detecta 10+ familias, enmascara salida y tiene 0 falsos positivos en ${vault.*}');
  }

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
