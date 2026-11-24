const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const envMod = require('../server/services/environmentManager');
const gitopsMod = require('../server/services/gitopsManager');
const { EnvironmentManager, encryptVaultValue, decryptVaultValue } = envMod;
const { GitOpsManager, parseSafeYaml, serializeSafeYaml } = gitopsMod;

/**
 * Crea dobles de prueba en memoria para aislar las pruebas GitOps sin tocar
 * los archivos reales `data/projects.json`, `data/domains.json`, `data/crons.json`
 * ni `data/databases.json` del espacio de trabajo.
 */
function createIsolatedManagers() {
  /** @type {Map<string, any>} */
  const projects = new Map();
  let projSeq = 1;
  const projectManager = {
    getAll: () => Array.from(projects.values()),
    getById: (id) => projects.get(id) || null,
    create: (data) => {
      const id = data.id || `proj_test_${projSeq++}`;
      const rec = {
        id,
        name: data.name || 'App',
        description: data.description || '',
        gitRepo: data.gitRepo || '',
        gitBranch: data.gitBranch || 'main',
        buildCommand: data.buildCommand || '',
        startCommand: data.startCommand || '',
        baseDirectory: data.baseDirectory || '/',
        containerPort: data.containerPort || null,
        healthPath: data.healthPath || '/',
        memoryMb: data.memoryMb || null,
        cpus: data.cpus || null,
        serverId: data.serverId || 'local',
        autoDeploy: data.autoDeploy !== false,
        maintenanceMode: Boolean(data.maintenanceMode),
        domains: Array.isArray(data.domains) ? [...data.domains] : [],
        envVars: data.envVars ? { ...data.envVars } : {},
        webhookSecret: 'whsec_SUPER_SECRET_NEVER_EXPORT_12345',
        deployHookToken: 'dhook_SUPER_SECRET_NEVER_EXPORT_67890'
      };
      projects.set(id, rec);
      return rec;
    },
    update: (id, patch) => {
      const existing = projects.get(id);
      if (!existing) throw new Error('Project not found');
      const updated = { ...existing, ...patch, id };
      projects.set(id, updated);
      return updated;
    },
    delete: (id) => projects.delete(id)
  };

  /** @type {any[]} */
  const domains = [];
  let domSeq = 1;
  const domainManager = {
    normalizeAndValidateHostname: (raw) => {
      const clean = String(raw || '').trim().toLowerCase().replace(/\.+$/, '');
      if (clean === 'localhost') return 'localhost';
      if (!clean || !/^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/.test(clean)) {
        throw new Error(`Invalid domain format: ${raw}`);
      }
      return clean;
    },
    listDomains: () => domains.map((d) => ({ ...d })),
    getByHostname: (h) => domains.find((d) => d.hostname === String(h).toLowerCase()) || null,
    addDomain: async (opts) => {
      const hostname = domainManager.normalizeAndValidateHostname(opts.hostname);
      if (domains.some((d) => d.hostname === hostname)) throw new Error('Domain exists');
      const rec = {
        id: `dom_${domSeq++}`,
        hostname,
        projectId: opts.projectId || null,
        targetPort: Number(opts.targetPort) || 3000,
        routingMode: opts.routingMode || 'direct_dns',
        cloudflareProxied: Boolean(opts.cloudflareProxied),
        canonicalRedirect: opts.canonicalRedirect || 'none',
        securityHeaders: opts.securityHeaders !== false
      };
      domains.push(rec);
      return rec;
    },
    updateDomain: async (id, patch) => {
      const idx = domains.findIndex((d) => d.id === id);
      if (idx < 0) throw new Error('Domain not found');
      domains[idx] = { ...domains[idx], ...patch, id };
      return domains[idx];
    },
    deleteDomain: async (id) => {
      const idx = domains.findIndex((d) => d.id === id);
      if (idx < 0) throw new Error('Domain not found');
      return domains.splice(idx, 1)[0];
    }
  };

  /** @type {any[]} */
  const crons = [];
  let cronSeq = 1;
  const cronManager = {
    list: (pid = null) => (pid ? crons.filter((c) => c.projectId === pid) : crons).map((c) => ({ ...c })),
    create: (projectId, data) => {
      const rec = {
        id: `cron_${cronSeq++}`,
        projectId,
        name: data.name,
        schedule: data.schedule,
        mode: data.mode || 'exec',
        command: data.command || '',
        workdir: data.workdir || null,
        httpPath: data.httpPath || '/',
        httpMethod: data.httpMethod || 'POST',
        enabled: data.enabled !== false
      };
      crons.push(rec);
      return rec;
    },
    update: (id, patch) => {
      const idx = crons.findIndex((c) => c.id === id);
      if (idx < 0) throw new Error('Cron not found');
      crons[idx] = { ...crons[idx], ...patch, id };
      return crons[idx];
    },
    remove: (id) => {
      const idx = crons.findIndex((c) => c.id === id);
      if (idx < 0) throw new Error('Cron not found');
      return crons.splice(idx, 1)[0];
    }
  };

  /** @type {any[]} */
  const databases = [];
  let dbSeq = 1;
  const databaseManager = {
    list: () => databases.map((d) => ({ ...d })),
    provision: async (opts) => {
      const rec = {
        id: `db_${dbSeq++}`,
        projectId: opts.projectId || null,
        name: opts.name || `${opts.engine}_db`,
        engine: opts.engine,
        image: opts.image || 'postgres:18-alpine',
        dbName: opts.dbName || 'app',
        username: opts.username || 'culkibo',
        password: 'SUPER_SECRET_DB_PASSWORD_NEVER_EXPORT'
      };
      databases.push(rec);
      return rec;
    },
    delete: async (id) => {
      const idx = databases.findIndex((d) => d.id === id);
      if (idx < 0) throw new Error('DB not found');
      return databases.splice(idx, 1)[0];
    }
  };

  /** @type {any[]} */
  const monitors = [];
  let monSeq = 1;
  const uptimeMonitor = {
    listMonitors: () => monitors.map((m) => ({ ...m })),
    createMonitor: async (opts) => {
      const rec = { id: `mon_${monSeq++}`, ...opts };
      monitors.push(rec);
      return rec;
    }
  };

  return { projectManager, domainManager, cronManager, databaseManager, uptimeMonitor };
}

async function testEnvironmentsGitops() {
  console.log('🧪 Probando Environments + Encrypted Vault + Promotion + Declarative GitOps (culkibo.yaml)...');
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-env-gitops-'));

  try {
    // ========================================================================
    // 1. AES-256-GCM Shared Vault, Zero-Leak Metadata & Anti-Key-Loss Guard
    // ========================================================================
    const vaultDir = path.join(tmpRoot, 'vault-test');
    let freezeState = { frozen: false, reason: '' };
    const mockDeploy = {
      evaluateFreezeStatus: () => freezeState,
      store: {}
    };
    const envMgr = new EnvironmentManager({ dataDir: vaultDir, deployManager: mockDeploy });

    // Carga perezosa: instanciar y listar en vacío NO crea `.vault.key` ni `environments.json`
    assert.deepStrictEqual(envMgr.listVaultSecrets(), [], 'Vault vacío debe devolver lista vacía');
    assert.strictEqual(fs.existsSync(envMgr.keyFile), false, 'No debe crear .vault.key antes de escribir secretos');
    assert.strictEqual(fs.existsSync(envMgr.storeFile), false, 'No debe crear environments.json antes de escribir');

    const STRIPE_SECRET = 'sk_live_9876543210_super_secret_stripe_key';
    const DB_PASS = 'P@ssw0rd_Pr0d_Ultra_Secret_99!';
    const meta1 = envMgr.setVaultSecret('STRIPE_SECRET', STRIPE_SECRET, {
      scope: 'runtime',
      description: 'Clave de producción de Stripe',
      actor: 'pablo'
    });
    envMgr.setVaultSecret('DB_PASS', DB_PASS, { scope: 'both', actor: 'pablo' });
    envMgr.setVaultSecret('BUILD_TOKEN', 'ghp_build_only_token_1234567890', { scope: 'build' });

    assert.strictEqual(meta1.key, 'STRIPE_SECRET');
    assert.ok(meta1.fingerprint.startsWith('sha256:'), 'Debe generar huella HMAC-SHA256');
    assert.strictEqual('value' in meta1, false, 'setVaultSecret jamás devuelve el valor en claro');
    assert.strictEqual('encryptedValue' in meta1, false, 'setVaultSecret jamás devuelve ciphertext');

    const listed = envMgr.listVaultSecrets();
    assert.strictEqual(listed.length, 3);
    const listedJson = JSON.stringify(listed);
    assert.ok(!listedJson.includes(STRIPE_SECRET), 'listVaultSecrets jamás expone STRIPE_SECRET');
    assert.ok(!listedJson.includes(DB_PASS), 'listVaultSecrets jamás expone DB_PASS');
    assert.ok(!listedJson.includes('v1:'), 'listVaultSecrets jamás expone ciphertext v1:');

    // Verificar cifrado AES-256-GCM real en disco (`environments.json` no tiene texto plano)
    const rawOnDisk = fs.readFileSync(envMgr.storeFile, 'utf8');
    assert.ok(rawOnDisk.includes('"v1:'), 'environments.json debe almacenar bloques cifrados v1:');
    assert.ok(!rawOnDisk.includes(STRIPE_SECRET), 'environments.json no debe contener STRIPE_SECRET en claro');
    assert.ok(!rawOnDisk.includes(DB_PASS), 'environments.json no debe contener DB_PASS en claro');

    // Verificar AAD contextual + detección de manipulación
    const rawKey = Buffer.from(fs.readFileSync(envMgr.keyFile, 'utf8').trim(), 'hex');
    assert.strictEqual(rawKey.length, 32, '.vault.key debe tener exactamente 32 bytes (256 bits)');
    const blob = encryptVaultValue('secreto-aad', rawKey, 'vault:KEY_A');
    assert.strictEqual(decryptVaultValue(blob, rawKey, 'vault:KEY_A'), 'secreto-aad');
    assert.throws(
      () => decryptVaultValue(blob, rawKey, 'vault:KEY_B'),
      'Trasplantar ciphertext a otra clave/AAD debe fallar autenticación AES-GCM'
    );
    const parts = blob.split(':');
    const tampered = `${parts[0]}:${parts[1]}:${parts[2]}:${Buffer.from('manipulado').toString('base64')}`;
    assert.throws(
      () => decryptVaultValue(tampered, rawKey, 'vault:KEY_A'),
      'Un ciphertext manipulado debe fallar autenticación AES-GCM'
    );

    // Verificar guardia anti-pérdida de clave (si falta .vault.key pero hay datos v1: en environments.json)
    const keyBackup = fs.readFileSync(envMgr.keyFile, 'utf8');
    fs.unlinkSync(envMgr.keyFile);
    const envMgrMissingKey = new EnvironmentManager({ dataDir: vaultDir });
    assert.throws(
      () => envMgrMissingKey.resolveEnvWithVault({ X: '${vault.STRIPE_SECRET}' }),
      /Falta el archivo de clave/i,
      'Debe abortar si falta .vault.key y existen secretos cifrados'
    );
    assert.strictEqual(fs.existsSync(envMgr.keyFile), false, 'Anti-key-loss jamás debe regenerar .vault.key');

    // Verificar rechazo de .vault.key corrupto
    fs.writeFileSync(envMgr.keyFile, 'deadbeef', 'utf8');
    const envMgrCorruptKey = new EnvironmentManager({ dataDir: vaultDir });
    assert.throws(
      () => envMgrCorruptKey.resolveEnvWithVault({ X: '${vault.STRIPE_SECRET}' }),
      /Clave de cifrado corrupta/i,
      'Debe rechazar una clave .vault.key truncada/corrupta sin sobrescribirla'
    );

    // Restaurar clave válida y verificar persistencia entre reinicios
    fs.writeFileSync(envMgr.keyFile, keyBackup, { encoding: 'utf8', mode: 0o600 });
    const envMgrReloaded = new EnvironmentManager({ dataDir: vaultDir, deployManager: mockDeploy });
    assert.strictEqual(envMgrReloaded.listVaultSecrets().length, 3);

    // Validación estricta de claves prohibidas
    for (const badKey of ['__proto__', 'constructor', 'prototype', 'LD_PRELOAD', 'DOCKER_HOST', '123BAD', 'BAD KEY']) {
      assert.throws(
        () => envMgrReloaded.setVaultSecret(badKey, 'x'),
        /inválid|bloqueada/i,
        `Debe rechazar clave de vault peligrosa: ${badKey}`
      );
    }
    console.log('  ✓ Vault AES-256-GCM: cifrado con AAD, metadata sin fugas, anti-tamper y guardia anti-pérdida de clave');

    // ========================================================================
    // 2. Resolución `${vault.KEY}` (una sola pasada, alcances build/runtime)
    // ========================================================================
    envMgrReloaded.setVaultSecret('RECURSIVE_TRAP', '${vault.STRIPE_SECRET}');
    const res = envMgrReloaded.resolveEnvWithVault({
      STRIPE_KEY: '${vault.STRIPE_SECRET}',
      DATABASE_URL: 'postgres://app:${vault.DB_PASS}@db:5432/prod',
      NO_RECURSION: '${vault.RECURSIVE_TRAP}',
      MISSING_REF: '${vault.DOES_NOT_EXIST}',
      PLAIN: 'hello-world'
    });
    assert.strictEqual(res.env.STRIPE_KEY, STRIPE_SECRET);
    assert.strictEqual(res.env.DATABASE_URL, `postgres://app:${DB_PASS}@db:5432/prod`);
    assert.strictEqual(res.env.NO_RECURSION, '${vault.STRIPE_SECRET}', 'No debe hacer expansión recursiva secundaria');
    assert.strictEqual(res.env.MISSING_REF, '${vault.DOES_NOT_EXIST}');
    assert.strictEqual(res.env.PLAIN, 'hello-world');
    assert.deepStrictEqual(res.missingKeys, ['DOES_NOT_EXIST']);
    assert.ok(res.resolvedKeys.includes('STRIPE_SECRET') && res.resolvedKeys.includes('DB_PASS'));
    assert.ok(res.secretValues.includes(STRIPE_SECRET) && res.secretValues.includes(DB_PASS));

    assert.throws(
      () => envMgrReloaded.resolveEnvWithVault({ X: '${vault.DOES_NOT_EXIST}' }, { strict: true }),
      /Faltan secretos/i,
      'strict: true debe fallar si falta una clave del Vault'
    );

    // Filtrado por fase (build vs runtime)
    const runtimeOnly = envMgrReloaded.resolveEnvWithVault(
      { BT: '${vault.BUILD_TOKEN}', SK: '${vault.STRIPE_SECRET}' },
      { phase: 'runtime' }
    );
    assert.strictEqual(runtimeOnly.env.SK, STRIPE_SECRET);
    assert.strictEqual(runtimeOnly.env.BT, '${vault.BUILD_TOKEN}', 'Un secreto scope=build no se inyecta en runtime');
    assert.deepStrictEqual(runtimeOnly.missingKeys, ['BUILD_TOKEN']);

    assert.strictEqual(envMgrReloaded.deleteVaultSecret('RECURSIVE_TRAP').deleted, true);
    assert.strictEqual(envMgrReloaded.hasVaultSecret('RECURSIVE_TRAP'), false);
    console.log('  ✓ Resolución ${vault.KEY}: sustitución directa e incrustada, anti-recursión y fases build/runtime');

    // ========================================================================
    // 3. Entornos Aislados por Proyecto + Diff Sólo por Hash + Promoción + Rollback
    // ========================================================================
    const pid = 'proj_billing_api';
    for (const badSlug of ['a', 'UPPER', '-bad', 'bad-', '../etc', 'a'.repeat(25), '__proto__']) {
      assert.throws(
        () => envMgrReloaded.upsertEnvironment(pid, badSlug, {}),
        /entorno inválido/i,
        `Debe rechazar slug de entorno inválido: ${badSlug}`
      );
    }

    const STAGING_JWT = 'jwt_staging_secret_value_alpha_1111';
    const PROD_JWT = 'jwt_production_secret_value_omega_9999';
    const NEW_FEATURE_SECRET = 'feat_secret_only_in_staging_7777';

    const staging = envMgrReloaded.upsertEnvironment(pid, 'staging', {
      branch: 'staging',
      domains: ['staging.billing.example.com'],
      serverId: 'eu-staging-1',
      lastRelease: { imageTag: 'culkibo/billing:sha-2222bbb', commit: '2222bbb', releaseId: 'rel_2' },
      envVars: {
        NODE_ENV: { value: 'staging', secret: false },
        JWT_SECRET: STAGING_JWT,
        STRIPE_SECRET: '${vault.STRIPE_SECRET}',
        FEATURE_FLAG_KEY: NEW_FEATURE_SECRET
      },
      actor: 'dev-alice'
    });

    const prod = envMgrReloaded.upsertEnvironment(pid, 'production', {
      branch: 'main',
      domains: ['billing.example.com'],
      serverId: 'eu-prod-1',
      protected: true,
      lastRelease: { imageTag: 'culkibo/billing:sha-1111aaa', commit: '1111aaa', releaseId: 'rel_1' },
      envVars: {
        NODE_ENV: { value: 'production', secret: false },
        JWT_SECRET: PROD_JWT,
        STRIPE_SECRET: '${vault.STRIPE_SECRET}',
        LEGACY_PROD_KEY: 'legacy_only_in_prod_8888'
      },
      actor: 'admin-bob'
    });

    assert.strictEqual(staging.name, 'staging');
    assert.strictEqual(prod.protected, true);
    // Verificar cero fugas de secretos en memoria pública y en disco
    const envDisk = fs.readFileSync(envMgrReloaded.storeFile, 'utf8');
    assert.ok(!envDisk.includes(STAGING_JWT), 'JWT de staging debe estar cifrado en disco');
    assert.ok(!envDisk.includes(PROD_JWT), 'JWT de prod debe estar cifrado en disco');
    assert.ok(!JSON.stringify(envMgrReloaded.listEnvironments(pid)).includes(PROD_JWT));

    // Entorno protegido no se puede borrar sin force: true
    assert.throws(() => envMgrReloaded.deleteEnvironment(pid, 'production'), /protegido/i);

    // Clonado de entorno con re-cifrado bajo el AAD del entorno destino + filtrado listAllEnvironments
    const qaEnv = envMgrReloaded.upsertEnvironment(pid, 'qa-eu-1', {
      branch: 'qa',
      domain: 'qa.billing.example.com',
      cloneEnvFrom: 'staging'
    });
    assert.strictEqual(qaEnv.name, 'qa-eu-1');
    assert.deepStrictEqual(qaEnv.domains, ['qa.billing.example.com']);
    assert.strictEqual(
      envMgrReloaded.resolveEnvForProject(pid, { envName: 'qa-eu-1', phase: 'runtime' }).env.JWT_SECRET,
      STAGING_JWT,
      'cloneEnvFrom debe copiar y re-cifrar variables bajo el AAD del nuevo entorno'
    );
    const allScoped = envMgrReloaded.listAllEnvironments({ projectIds: [pid] });
    assert.strictEqual(allScoped.environmentCount, 3);
    assert.strictEqual(envMgrReloaded.listAllEnvironments({ projectIds: ['other_proj'] }).environmentCount, 0);
    assert.ok(!JSON.stringify(allScoped).includes(STAGING_JWT));
    assert.strictEqual(envMgrReloaded.deleteEnvironment(pid, 'qa-eu-1').deleted, true);

    // Hash-only Diff (`diffEnvironments`)
    const diff = envMgrReloaded.diffEnvironments(pid, 'staging', 'production');
    assert.strictEqual(diff.hashAlgorithm, 'hmac-sha256');
    assert.deepStrictEqual(diff.onlyInFrom, ['FEATURE_FLAG_KEY']);
    assert.deepStrictEqual(diff.onlyInTo, ['LEGACY_PROD_KEY']);
    assert.deepStrictEqual(diff.changedKeys, ['JWT_SECRET', 'NODE_ENV']);
    assert.deepStrictEqual(diff.unchanged, ['STRIPE_SECRET']);
    assert.strictEqual(diff.metadataDiff.release.changed, true);

    const diffSerialized = JSON.stringify(diff);
    for (const secret of [STAGING_JWT, PROD_JWT, NEW_FEATURE_SECRET, 'legacy_only_in_prod_8888', STRIPE_SECRET]) {
      assert.ok(!diffSerialized.includes(secret), `diffEnvironments JAMÁS puede filtrar el valor "${secret}"`);
    }
    const jwtChange = diff.changed.find((c) => c.key === 'JWT_SECRET');
    assert.ok(jwtChange && /^[a-f0-9]{64}$/.test(jwtChange.fromHash) && /^[a-f0-9]{64}$/.test(jwtChange.toHash));
    assert.notStrictEqual(jwtChange.fromHash, jwtChange.toHash);
    console.log('  ✓ Entornos aislados + diffEnvironments: hashes HMAC-SHA256 exclusivamente (0 secretos filtrados)');

    // Dry-run promote NO muta estado ni crea snapshots
    const dryProm = envMgrReloaded.promoteEnvironment(pid, {
      fromEnv: 'staging',
      toEnv: 'production',
      includeEnvVars: true,
      dryRun: true,
      actor: 'dev-alice'
    });
    assert.strictEqual(dryProm.dryRun, true);
    assert.strictEqual(dryProm.snapshotId, null);
    assert.strictEqual(envMgrReloaded.getEnvironment(pid, 'production').lastRelease.imageTag, 'culkibo/billing:sha-1111aaa');
    assert.strictEqual(envMgrReloaded.listSnapshots(pid, 'production').length, 0);

    // Freeze window gate bloquea promoción real salvo overrideFreeze: true
    freezeState = { frozen: true, reason: 'Congelación de viernes tarde' };
    assert.throws(
      () => envMgrReloaded.promoteEnvironment(pid, { fromEnv: 'staging', toEnv: 'production', actor: 'dev-alice' }),
      /congelación/i,
      'Debe bloquear promoción durante ventana de congelación'
    );
    freezeState = { frozen: false, reason: '' };

    // Approval gate + no auto-aprobación + consumo de un solo uso
    envMgrReloaded.upsertEnvironment(pid, 'production', { requireApproval: true });
    assert.throws(
      () => envMgrReloaded.promoteEnvironment(pid, { fromEnv: 'staging', toEnv: 'production', actor: 'dev-alice' }),
      /aprobación previa/i
    );
    const reqApproval = envMgrReloaded.createApprovalRequest({
      projectId: pid,
      fromEnv: 'staging',
      toEnv: 'production',
      requestedBy: 'dev-alice',
      reason: 'Release v2'
    });
    assert.throws(
      () => envMgrReloaded.approveRequest(reqApproval.id, { actor: 'dev-alice' }),
      /auto-aprobar/i,
      'Debe bloquear auto-aprobación'
    );
    const approved = envMgrReloaded.approveRequest(reqApproval.id, { actor: 'admin-bob' });
    assert.strictEqual(approved.status, 'approved');

    // Promoción real (con envVars + instantánea automática previa)
    const promoted = envMgrReloaded.promoteEnvironment(pid, {
      fromEnv: 'staging',
      toEnv: 'production',
      includeEnvVars: true,
      approvalId: approved.id,
      actor: 'dev-alice',
      reason: 'Release v2 verificada'
    });
    assert.strictEqual(promoted.ok, true);
    assert.ok(promoted.snapshotId && promoted.snapshotId.startsWith('snap_'));
    assert.strictEqual(promoted.target.lastRelease.imageTag, 'culkibo/billing:sha-2222bbb');
    assert.strictEqual(promoted.target.lastRelease.promotedFrom, 'staging');
    assert.strictEqual(promoted.target.promotionHistory.length, 1);

    // Verificar que la aprobación fue de un solo uso (reutilizarla falla)
    assert.throws(
      () => envMgrReloaded.promoteEnvironment(pid, { fromEnv: 'staging', toEnv: 'production', approvalId: approved.id }),
      /aprobación previa/i,
      'Una aprobación consumida no puede reutilizarse'
    );

    // Verificar que las variables promocionadas se resolvieron en production (re-cifradas con su propio AAD)
    const resolvedAfterPromote = envMgrReloaded.resolveEnvForProject(pid, { envName: 'production', phase: 'runtime' });
    assert.strictEqual(resolvedAfterPromote.env.JWT_SECRET, STAGING_JWT);
    assert.strictEqual(resolvedAfterPromote.env.FEATURE_FLAG_KEY, NEW_FEATURE_SECRET);
    assert.strictEqual(resolvedAfterPromote.env.STRIPE_SECRET, STRIPE_SECRET);
    assert.strictEqual(resolvedAfterPromote.env.LEGACY_PROD_KEY, 'legacy_only_in_prod_8888');

    // Rollback exacto a la instantánea pre-promoción
    const rolledBack = envMgrReloaded.rollbackPromotion(pid, 'production', promoted.snapshotId, {
      actor: 'admin-bob',
      reason: 'Incidente en pagos'
    });
    assert.strictEqual(rolledBack.ok, true);
    assert.strictEqual(rolledBack.restoredSnapshotId, promoted.snapshotId);
    assert.strictEqual(rolledBack.environment.lastRelease.imageTag, 'culkibo/billing:sha-1111aaa');
    assert.strictEqual(rolledBack.environment.promotionHistory.length, 2);

    const resolvedAfterRollback = envMgrReloaded.resolveEnvForProject(pid, { envName: 'production', phase: 'runtime' });
    assert.strictEqual(resolvedAfterRollback.env.JWT_SECRET, PROD_JWT, 'Rollback debe restaurar JWT_SECRET original');
    assert.strictEqual(resolvedAfterRollback.env.FEATURE_FLAG_KEY, undefined, 'Rollback debe eliminar variables añadidas en promoción');
    assert.strictEqual(resolvedAfterRollback.env.STRIPE_SECRET, STRIPE_SECRET);
    console.log('  ✓ Pipeline de promoción + congelación + aprobaciones + snapshot automático + rollbackPromotion exacto');

    // ========================================================================
    // 4. YAML Parser Seguro (Rechazo de YAML Bombs, Tags y Prototype Pollution)
    // ========================================================================
    // 4a. Billion Laughs (anchors & aliases)
    const billionLaughs = [
      'version: 1',
      'a: &a ["lol", "lol", "lol", "lol"]',
      'b: &b [*a, *a, *a, *a]',
      'c: [*b, *b, *b, *b]'
    ].join('\n');
    assert.throws(() => parseSafeYaml(billionLaughs), /ancla|alias/i, 'Debe rechazar Billion Laughs (& / *)');

    // 4b. Clave de fusión `<<:`
    assert.throws(() => parseSafeYaml('version: 1\n<<: base\n'), /fusión|<<|bloqueada/i, 'Debe rechazar merge key <<');

    // 4c. Etiquetas peligrosas (`!!js/function`, `!!python/object`, `!custom`)
    for (const evilTag of [
      'version: 1\nhack: !!js/function "function(){ return 1; }"',
      'version: 1\nhack: !!python/object/apply:os.system ["id"]',
      'version: 1\nhack: !include /etc/passwd'
    ]) {
      assert.throws(() => parseSafeYaml(evilTag), /etiqueta YAML/i, `Debe rechazar tag peligroso: ${evilTag}`);
    }

    // 4d. Prototype pollution (bloque + inline flow + null prototype check)
    assert.throws(() => parseSafeYaml('version: 1\n__proto__:\n  polluted: true\n'), /prohibida/i);
    assert.throws(() => parseSafeYaml('version: 1\nconstructor:\n  prototype: 1\n'), /prohibida/i);
    assert.throws(() => parseSafeYaml('version: 1\nmeta: { __proto__: { hacked: true } }\n'), /prohibida/i);
    const safeObj = parseSafeYaml('version: 1\nname: test-stack\n');
    assert.strictEqual(Object.getPrototypeOf(safeObj), null, 'Objetos parseados deben tener prototipo null');

    // 4e. Límites de tamaño (>256 KB), líneas (>2000) y profundidad (>12 bloque e inline)
    assert.throws(() => parseSafeYaml('a: ' + 'x'.repeat(260 * 1024)), /256 KB/i, 'Debe rechazar YAML > 256 KB');
    const tooManyLines = Array.from({ length: 2005 }, (_, i) => `k${i}: v`).join('\n');
    assert.throws(() => parseSafeYaml(tooManyLines), /2000 líneas/i, 'Debe rechazar YAML > 2000 líneas');
    const deepBlock = Array.from({ length: 16 }, (_, i) => `${'  '.repeat(i)}l${i}:`).join('\n') + '\n' + '  '.repeat(16) + 'end: 1\n';
    assert.throws(() => parseSafeYaml(deepBlock), /profundidad máxima/i, 'Debe rechazar anidación > 12 en bloque');
    const deepFlow = 'version: 1\nbomb: ' + '['.repeat(16) + '1' + ']'.repeat(16) + '\n';
    assert.throws(() => parseSafeYaml(deepFlow), /profundidad máxima/i, 'Debe rechazar anidación > 12 en flujo inline');

    // 4f. Tabulaciones, multi-documento, comillas manipuladas, bomba de nodos inline y BOM UTF-8
    assert.throws(() => parseSafeYaml('version: 1\n\tname: bad\n'), /tabulaciones/i);
    assert.throws(() => parseSafeYaml('---\nversion: 1\n---\nversion: 1\n'), /multi-documento/i);
    assert.throws(() => parseSafeYaml('version: 1\nname: "foo" &a "bar"\n'), /comilla doble/i);
    const nodeBomb = 'version: 1\nitems: [' + Array.from({ length: 2010 }, () => '1').join(',') + ']\n';
    assert.throws(() => parseSafeYaml(nodeBomb), /límite máximo de nodos/i, 'Debe rechazar bomba de >2000 nodos en flujo inline');
    const bomParsed = parseSafeYaml('\uFEFFversion: 1\nname: win-bom\n');
    assert.strictEqual(bomParsed.version, 1);
    assert.strictEqual(bomParsed.name, 'win-bom');

    // 4g. Roundtrip serializer <-> parser con caracteres especiales
    const roundtripDoc = {
      version: 1,
      name: 'roundtrip-test',
      vaultRefs: ['API_KEY', 'DB_PASS'],
      projects: [
        {
          id: 'proj_1',
          name: 'App: Principal',
          schedule: '0 3 * * *',
          env: {
            PORT: '3000',
            API_KEY: '${vault.API_KEY}',
            BOOL_STR: 'true'
          },
          domains: ['*.example.com', 'app.example.com']
        }
      ]
    };
    const serialized = serializeSafeYaml(roundtripDoc) + '\n';
    const reparsed = parseSafeYaml(serialized);
    assert.strictEqual(reparsed.version, 1);
    assert.strictEqual(reparsed.projects[0].name, 'App: Principal');
    assert.strictEqual(reparsed.projects[0].schedule, '0 3 * * *');
    assert.strictEqual(reparsed.projects[0].env.PORT, '3000');
    assert.strictEqual(reparsed.projects[0].env.BOOL_STR, 'true');
    assert.strictEqual(reparsed.projects[0].env.API_KEY, '${vault.API_KEY}');
    assert.deepStrictEqual(reparsed.projects[0].domains, ['*.example.com', 'app.example.com']);
    console.log('  ✓ Parser YAML acotado: rechaza Billion Laughs, tags !, __proto__, >256KB, >2000 líneas y profundidad >12');

    // ========================================================================
    // 5. Exportación Determinista Libre de Secretos + Plan / Apply / Drift / Prune
    // ========================================================================
    const gitopsDir = path.join(tmpRoot, 'gitops-test');
    const deps = createIsolatedManagers();
    const gitopsEnvMgr = new EnvironmentManager({ dataDir: gitopsDir, domainManager: deps.domainManager });
    const gitops = new GitOpsManager({
      dataDir: gitopsDir,
      projectManager: deps.projectManager,
      domainManager: deps.domainManager,
      cronManager: deps.cronManager,
      databaseManager: deps.databaseManager,
      environmentManager: gitopsEnvMgr,
      uptimeMonitor: deps.uptimeMonitor
    });

    // Poblar estado inicial con secretos reales en proyecto, entorno y BD
    const RAW_API_SECRET = 'sk_live_plaintext_never_in_git_123456';
    const RAW_JWT_SECRET = 'jwt_super_secret_never_in_git_abcdef';
    gitopsEnvMgr.setVaultSecret('STRIPE_API_KEY', RAW_API_SECRET);

    const p1 = deps.projectManager.create({
      id: 'proj_shop',
      name: 'Tienda Web',
      description: 'Ecommerce principal',
      gitRepo: 'https://github.com/culkibo/shop.git',
      gitBranch: 'main',
      buildCommand: 'npm run build',
      startCommand: 'npm start',
      containerPort: 3000,
      healthPath: '/health',
      memoryMb: 512,
      cpus: 1,
      serverId: 'local',
      envVars: {
        NODE_ENV: 'production',
        PORT: '3000',
        STRIPE_API_KEY: RAW_API_SECRET,
        JWT_SECRET: RAW_JWT_SECRET
      }
    });
    gitopsEnvMgr.upsertEnvironment(p1.id, 'production', {
      branch: 'main',
      domains: ['shop.example.com'],
      envVars: {
        NODE_ENV: { value: 'production', secret: false },
        STRIPE_API_KEY: '${vault.STRIPE_API_KEY}',
        ADMIN_PASSWORD: 'ultra_secret_admin_pwd_999'
      }
    });
    await deps.domainManager.addDomain({
      hostname: 'shop.example.com',
      projectId: p1.id,
      targetPort: 3000,
      routingMode: 'direct_dns'
    });
    deps.cronManager.create(p1.id, {
      name: 'Limpieza nocturna',
      schedule: '0 3 * * *',
      mode: 'http',
      httpPath: '/api/cleanup',
      httpMethod: 'POST'
    });
    const db1 = await deps.databaseManager.provision({
      projectId: p1.id,
      engine: 'postgres',
      name: 'shop_pg',
      dbName: 'shop',
      username: 'shop_user'
    });
    await deps.uptimeMonitor.createMonitor({
      projectId: p1.id,
      name: 'Shop Health',
      type: 'http',
      url: 'https://shop.example.com/health',
      intervalSec: 60,
      expectedStatus: 200,
      public: true
    });

    // Exportar dos veces -> debe ser determinista byte a byte y 100% libre de secretos
    const exp1 = gitops.exportStack({ name: 'shop-stack' });
    const exp2 = gitops.exportStack({ name: 'shop-stack' });
    assert.strictEqual(exp1.yaml, exp2.yaml, 'exportStack debe ser 100% determinista');
    assert.strictEqual(exp1.manifestHash, exp2.manifestHash);
    assert.strictEqual(exp1.counts.projects, 1);
    assert.strictEqual(exp1.counts.databases, 1);
    assert.strictEqual(exp1.counts.domains, 1);
    assert.strictEqual(exp1.counts.crons, 1);
    assert.strictEqual(exp1.counts.monitors, 1);

    for (const secret of [
      RAW_API_SECRET,
      RAW_JWT_SECRET,
      'ultra_secret_admin_pwd_999',
      'SUPER_SECRET_DB_PASSWORD_NEVER_EXPORT',
      'whsec_SUPER_SECRET_NEVER_EXPORT_12345',
      'dhook_SUPER_SECRET_NEVER_EXPORT_67890'
    ]) {
      assert.ok(!exp1.yaml.includes(secret), `culkibo.yaml exportado JAMÁS puede contener "${secret}"`);
    }
    assert.ok(exp1.yaml.includes('${vault.STRIPE_API_KEY}'), 'Debe emitir ${vault.STRIPE_API_KEY}');
    assert.ok(exp1.yaml.includes('${vault.JWT_SECRET}'), 'Debe emitir ${vault.JWT_SECRET}');
    assert.ok(exp1.yaml.includes('${vault.ADMIN_PASSWORD}'), 'Debe emitir ${vault.ADMIN_PASSWORD}');
    assert.ok(exp1.yaml.includes('generateSecret: true'), 'BDs deben exportar generateSecret: true');
    assert.ok(exp1.vaultRefs.includes('STRIPE_API_KEY') && exp1.vaultRefs.includes('JWT_SECRET'));
    console.log('  ✓ exportStack: manifiesto culkibo.yaml v1 determinista y 100% libre de secretos');

    // Validación de seguridad en manifiesto (docker.sock, LD_PRELOAD, :latest, metadata URL)
    assert.throws(
      () => gitops.planApply('version: 1\nprojects:\n  - name: evil\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n'),
      /montaje privilegiado/i
    );
    assert.throws(
      () => gitops.planApply('version: 1\nprojects:\n  - name: evil\n    env:\n      LD_PRELOAD: /tmp/x.so\n'),
      /bloqueada/i
    );
    assert.throws(
      () => gitops.planApply('version: 1\nprojects: []\ndatabases:\n  - name: d\n    engine: postgres\n    image: postgres:latest\n'),
      /flotante|inválida/i
    );
    assert.throws(
      () => gitops.planApply('version: 1\nprojects: []\nmonitors:\n  - name: ssrf\n    type: http\n    url: http://169.254.169.254/latest/meta-data/\n'),
      /metadatos|SSRF/i
    );
    // Regresión sec-advisor #40: SSRF IPv6/IPv4-mapped/loopback/RFC1918 en monitors[].url y gitRepo maliciosos
    for (const ssrfUrl of [
      'http://[fd00:ec2::254]/latest/meta-data/',
      'http://[::ffff:169.254.169.254]/latest/meta-data/',
      'http://127.0.0.1:3001/api/health',
      'http://localhost:3001/health',
      'http://10.0.0.5/internal',
      'http://192.168.1.10/status'
    ]) {
      assert.throws(
        () => gitops.planApply(`version: 1\nprojects: []\nmonitors:\n  - name: ssrf\n    type: http\n    url: "${ssrfUrl}"\n`),
        /SSRF|bloquead/i,
        `Debe bloquear URL SSRF en monitor: ${ssrfUrl}`
      );
    }
    for (const evilGitRepo of [
      'ext::sh -c id',
      'file:///etc/passwd',
      '--upload-pack=touch /tmp/pwn',
      'https://user:pass@github.com/org/repo.git',
      'http://127.0.0.1/org/repo.git',
      'git@localhost:org/repo.git'
    ]) {
      assert.throws(
        () => gitops.planApply(`version: 1\nprojects:\n  - name: evil\n    gitRepo: "${evilGitRepo}"\n`),
        /gitRepo|SSRF|bloquead|permitido/i,
        `Debe rechazar gitRepo inseguro: ${evilGitRepo}`
      );
    }
    const validScpPlan = gitops.planApply('version: 1\nprojects:\n  - name: scp-ok\n    gitRepo: "git@github.com:culkibo/app.git"\n');
    assert.strictEqual(validScpPlan.valid, true, 'Debe aceptar git@host:org/repo.git válido');

    // Regresión sec-advisor #40: export -> edit -> applyStack JAMÁS sobrescribe secretos cifrados vivos del entorno con literal "${vault.KEY}"
    const editedExportManifest = JSON.parse(JSON.stringify(exp1.manifest));
    editedExportManifest.projects[0].environments.production.branch = 'release-v2';
    const editedExportYaml = serializeSafeYaml(editedExportManifest) + '\n';
    await gitops.applyStack(editedExportYaml, { dryRun: false, actor: 'sec-test' });
    assert.strictEqual(gitopsEnvMgr.getEnvironment(p1.id, 'production').branch, 'release-v2', 'Debe actualizar la rama del entorno');
    const liveProdAfterRoundtrip = gitopsEnvMgr.resolveEnvForProject(p1.id, { envName: 'production', phase: 'runtime' });
    assert.strictEqual(
      liveProdAfterRoundtrip.env.ADMIN_PASSWORD,
      'ultra_secret_admin_pwd_999',
      'applyStack NO debe sobrescribir secreto vivo del entorno con el placeholder literal "${vault.ADMIN_PASSWORD}"'
    );

    // Aplicar el YAML exportado en un entorno destino completamente limpio (roundtrip!)
    const targetDir = path.join(tmpRoot, 'gitops-target');
    const targetDeps = createIsolatedManagers();
    const targetEnvMgr = new EnvironmentManager({ dataDir: targetDir, domainManager: targetDeps.domainManager });
    targetEnvMgr.setVaultSecret('STRIPE_API_KEY', RAW_API_SECRET);
    // JWT_SECRET y ADMIN_PASSWORD faltan a propósito para comprobar warnings de Vault!
    const targetGitops = new GitOpsManager({
      dataDir: targetDir,
      projectManager: targetDeps.projectManager,
      domainManager: targetDeps.domainManager,
      cronManager: targetDeps.cronManager,
      databaseManager: targetDeps.databaseManager,
      environmentManager: targetEnvMgr,
      uptimeMonitor: targetDeps.uptimeMonitor
    });

    // planApply: dry-run puro (0 mutaciones) + avisa de claves faltantes en Vault
    const plan1 = targetGitops.planApply(exp1.yaml);
    assert.strictEqual(plan1.valid, true);
    assert.ok(plan1.create.length >= 6, 'Debe planificar creación de proyecto, entorno, BD, dominio, cron y monitor');
    assert.strictEqual(targetDeps.projectManager.getAll().length, 0, 'planApply no debe mutar estado vivo');
    assert.ok(plan1.missingVaultRefs.includes('JWT_SECRET') && plan1.missingVaultRefs.includes('ADMIN_PASSWORD'));
    assert.ok(!plan1.missingVaultRefs.includes('STRIPE_API_KEY'));
    assert.ok(!JSON.stringify(plan1).includes(RAW_API_SECRET), 'planApply jamás debe imprimir valores del Vault');

    // applyStack({ dryRun: true }) -> 0 mutaciones
    const dryApply = await targetGitops.applyStack(exp1.yaml, { dryRun: true });
    assert.strictEqual(dryApply.applied, false);
    assert.strictEqual(targetDeps.projectManager.getAll().length, 0);

    // applyStack real -> reconcilia todo y persiste hash en data/gitops.json
    const applied1 = await targetGitops.applyStack(exp1.yaml, { dryRun: false, actor: 'ci-bot' });
    assert.strictEqual(applied1.ok, true);
    assert.strictEqual(applied1.applied, true);
    assert.strictEqual(targetDeps.projectManager.getAll().length, 1);
    assert.strictEqual(targetDeps.domainManager.listDomains().length, 1);
    assert.strictEqual(targetDeps.cronManager.list().length, 1);
    assert.strictEqual(targetDeps.databaseManager.list().length, 1);
    assert.strictEqual(targetEnvMgr.listEnvironments('proj_shop').length, 1);
    assert.ok(fs.existsSync(targetGitops.storeFile), 'Debe persistir estado en data/gitops.json');

    // Idempotencia: segunda aplicación exacta produce 0 cambios
    const applied2 = await targetGitops.applyStack(exp1.yaml, { dryRun: false });
    assert.strictEqual(applied2.appliedCounts.created, 0);
    assert.strictEqual(applied2.appliedCounts.updated, 0);
    assert.strictEqual(applied2.appliedCounts.deleted, 0);

    // Detección de drift: sin cambios -> drifted: false
    const driftClean = targetGitops.detectDrift('shop-stack');
    assert.strictEqual(driftClean.drifted, false);
    assert.strictEqual(driftClean.hasDrift, false);

    // Introducir drift fuera de banda (editar memoria del proyecto + añadir dominio no declarado)
    targetDeps.projectManager.update('proj_shop', { memoryMb: 2048 });
    await targetDeps.domainManager.addDomain({
      hostname: 'rogue.example.com',
      projectId: 'proj_shop',
      targetPort: 3000
    });
    const driftDetected = targetGitops.detectDrift('shop-stack');
    assert.strictEqual(driftDetected.drifted, true, 'Debe detectar drift tras cambios manuales');
    assert.ok(driftDetected.differences.update.some((u) => u.kind === 'project' && u.changes.some((c) => c.field === 'memoryMb')));
    assert.ok(driftDetected.differences.delete.some((d) => d.kind === 'domain' && d.name === 'rogue.example.com'));

    // Reconciliar drift con prune: true -> vuelve a drifted: false
    await targetGitops.applyStack(exp1.yaml, { dryRun: false, prune: true });
    assert.strictEqual(targetDeps.projectManager.getById('proj_shop').memoryMb, 512);
    assert.strictEqual(targetDeps.domainManager.getByHostname('rogue.example.com'), null);
    assert.strictEqual(targetGitops.detectDrift('shop-stack').drifted, false);

    // Protección de borrado de BD: quitar la BD del YAML y aplicar con prune SIN confirmDestructive -> BD intacta!
    const yamlWithoutDb = serializeSafeYaml({ ...exp1.manifest, databases: [] }) + '\n';
    const prunedBlocked = await targetGitops.applyStack(yamlWithoutDb, { prune: true, confirmDestructive: false });
    assert.strictEqual(targetDeps.databaseManager.list().length, 1, 'BD jamás debe borrarse sin confirmDestructive: true');
    assert.ok(prunedBlocked.warnings.some((w) => /confirmDestructive/i.test(w)));

    // Con prune: true Y confirmDestructive: true -> la BD sí se elimina
    await targetGitops.applyStack(yamlWithoutDb, { prune: true, confirmDestructive: true });
    assert.strictEqual(targetDeps.databaseManager.list().length, 0, 'Con prune && confirmDestructive la BD se elimina');
    console.log('  ✓ GitOps planApply/applyStack/detectDrift: roundtrip idempotente, detección de drift y protección de BDs');

    // ========================================================================
    // 6. Puente con UniversalImporter (`convertExternalToCulkiboYaml`)
    // ========================================================================
    const composeInput = [
      'services:',
      '  web:',
      '    image: node:22-alpine',
      '    ports:',
      '      - "3000:3000"',
      '    environment:',
      '      NODE_ENV: production',
      '      STRIPE_SECRET_KEY: sk_live_compose_secret_987654321',
      '  db:',
      '    image: postgres:18-alpine',
      '    environment:',
      '      POSTGRES_PASSWORD: compose_db_secret_password'
    ].join('\n');

    const convertedCompose = gitops.convertExternalToCulkiboYaml('docker-compose', composeInput, { name: 'migrated-compose' });
    assert.strictEqual(convertedCompose.ok, true);
    assert.strictEqual(convertedCompose.platform, 'docker-compose');
    assert.strictEqual(convertedCompose.manifest.projects.length, 1);
    assert.strictEqual(convertedCompose.manifest.databases.length, 1);
    assert.strictEqual(convertedCompose.manifest.databases[0].engine, 'postgres');
    assert.strictEqual(convertedCompose.manifest.databases[0].generateSecret, true);
    assert.ok(!convertedCompose.yaml.includes('sk_live_compose_secret_987654321'), 'No debe filtrar secretos de Compose');
    assert.ok(!convertedCompose.yaml.includes('compose_db_secret_password'), 'No debe filtrar password de BD');
    assert.ok(convertedCompose.yaml.includes('${vault.STRIPE_SECRET_KEY}'));

    const renderInput = [
      'services:',
      '  - type: web',
      '    name: render-api',
      '    buildCommand: npm ci && npm run build',
      '    startCommand: npm start',
      '    healthCheckPath: /healthz'
    ].join('\n');
    const convertedRender = gitops.convertExternalToCulkiboYaml('render', renderInput, {
      envText: 'PORT=4000\nAPI_TOKEN=tok_render_super_secret_xyz123\nDATABASE_URL=postgres://u:p@host/db\n'
    });
    assert.strictEqual(convertedRender.ok, true);
    assert.strictEqual(convertedRender.manifest.projects[0].name, 'render-api');
    assert.ok(!convertedRender.yaml.includes('tok_render_super_secret_xyz123'));
    assert.ok(convertedRender.yaml.includes('${vault.API_TOKEN}'));
    assert.ok(convertedRender.yaml.includes('${vault.DATABASE_URL}'));
    console.log('  ✓ convertExternalToCulkiboYaml: conversión segura desde docker-compose y render.yaml sin fugas de secretos');

    // Confirmar cero dependencias npm nuevas
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
    assert.strictEqual(Object.keys(pkg.dependencies || {}).length, 6, 'package.json debe mantener exactamente 6 dependencias');

    console.log('✅ All environments & GitOps tests passed!\n');
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

module.exports = { testEnvironmentsGitops };

if (require.main === module) {
  testEnvironmentsGitops().catch((err) => {
    console.error('❌ Environments & GitOps test failure:', err);
    process.exit(1);
  });
}
