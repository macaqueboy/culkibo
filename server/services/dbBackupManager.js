const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
// Este módulo NO ejecuta procesos: sólo construye la especificación argv del
// volcado (`buildDbDumpSpec`) y gestiona exportación/importación de configuración.
const projectManager = require('./projectManager');
const domainManager = require('./domainManager');
const { assertContainedPath, atomicWriteJsonSync } = require('./ssrfGuard');

const MAX_PROJECT_BACKUP_BYTES = 10 * 1024 * 1024;

/** Rechaza valores con guion inicial para impedir inyección de flags en CLI (p. ej. `-o`, `--eval`). */
function assertSafeCliArg(value, field) {
  const s = String(value == null ? '' : value);
  if (s.startsWith('-')) {
    throw new Error(`${field} inválido: no puede empezar por guion (-)`);
  }
  if (/[\0\r\n]/.test(s)) {
    throw new Error(`${field} inválido: contiene caracteres de control`);
  }
  return s;
}

/** Cifra un objeto JSON con AES-256-GCM + scrypt (cero dependencias) usando una frase de paso. */
function encryptSnapshotPayload(obj, passphrase) {
  const pwd = String(passphrase || '').trim();
  if (pwd.length < 8) throw new Error('La contraseña de cifrado debe tener al menos 8 caracteres');
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(pwd, salt, 32, { N: 16384, r: 8, p: 1 });
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  const plain = Buffer.from(JSON.stringify(obj), 'utf8');
  const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
  return {
    encrypted: true,
    kdf: 'scrypt',
    cipher: 'aes-256-gcm',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: enc.toString('base64')
  };
}

/** Descifra un sobre cifrado por `encryptSnapshotPayload` (valida longitudes estrictas de IV=12B y AuthTag=16B). */
function decryptSnapshotPayload(envelope, passphrase) {
  const pwd = String(passphrase || '').trim();
  if (!pwd) throw new Error('Este snapshot está cifrado; proporciona la contraseña (passphrase)');
  const salt = Buffer.from(String(envelope?.salt || ''), 'base64');
  const iv = Buffer.from(String(envelope?.iv || ''), 'base64');
  const tag = Buffer.from(String(envelope?.tag || ''), 'base64');
  const data = Buffer.from(String(envelope?.ciphertext || ''), 'base64');
  if (salt.length < 16 || iv.length !== 12 || tag.length !== 16) {
    throw new Error('Contraseña incorrecta o snapshot cifrado corrupto');
  }
  try {
    const key = crypto.scryptSync(pwd, salt, 32, { N: 16384, r: 8, p: 1 });
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
    return JSON.parse(plain);
  } catch (e) {
    throw new Error('Contraseña incorrecta o snapshot cifrado corrupto');
  }
}

/** Redacta secretos de un proyecto para exportación segura sin fugas accidentales. */
function redactProjectForExport(proj) {
  const envKeys = Object.keys(proj.envVars || {});
  /** @type {Record<string, string>} */
  const placeholderEnv = {};
  for (const k of envKeys) placeholderEnv[k] = '';
  return {
    ...proj,
    envVars: placeholderEnv,
    redactedEnvKeys: envKeys,
    webhookSecret: '',
    deployHookToken: '',
    fileMounts: (proj.fileMounts || []).map((fm) => ({ ...fm, content: '' })),
    resources: (proj.resources || []).map((r) => ({
      ...r,
      envVars: undefined,
      credentials: undefined
    }))
  };
}

/** Valida un puerto TCP numérico para CLI (impide inyección de flags). */
function assertSafePort(port, fallback) {
  if (port === undefined || port === null || port === '') return fallback;
  const s = String(port).trim();
  if (!/^\d{1,5}$/.test(s)) {
    throw new Error(`port inválido: debe ser un número entero entre 1 y 65535`);
  }
  const n = Number(s);
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    throw new Error(`port fuera de rango (1-65535): ${port}`);
  }
  return n;
}

class DbBackupManager {
  /** @param {{ dataDir?: string | null }} [opts] */
  constructor({ dataDir = null } = {}) {
    const rootBase = dataDir
      ? path.resolve(dataDir)
      : process.env.CULKIBO_DATA_DIR
        ? path.resolve(process.env.CULKIBO_DATA_DIR)
        : path.resolve(__dirname, '..', '..');
    this.backupsDir = path.join(rootBase, 'data', 'backups');
    this.ensureDir(this.backupsDir);
  }

  ensureDir(dir) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  /**
   * Construye la especificación ejecutable de un volcado: programa, argumentos
   * como array y secretos en el entorno (sin shell).
   *
   * @returns {{program:string, args:string[], env:Record<string, string>, secretInArgs:boolean}}
   */
  buildDbDumpSpec(dbType, options = {}) {
    const { host = 'localhost', port, user = 'root', password = '', dbName = 'app', outputFile } = options;
    const engine = String(dbType || '').toLowerCase();
    const safeHost = assertSafeCliArg(host, 'host');
    const safeUser = assertSafeCliArg(user, 'user');
    const safeDb = assertSafeCliArg(dbName, 'dbName');
    const safeOut = assertSafeCliArg(outputFile || '', 'outputFile');

    switch (engine) {
      case 'postgresql':
      case 'postgres':
      case 'pgvector':
      case 'timescaledb': {
        const p = assertSafePort(port, 5432);
        return {
          program: 'pg_dump',
          args: [
            '-h', safeHost, '-p', String(p), '-U', safeUser,
            '-d', safeDb, '-F', 'c', '-b',
            '--no-owner', '--no-privileges', '--lock-wait-timeout=60000',
            '-f', safeOut
          ],
          env: password ? { PGPASSWORD: password } : {},
          secretInArgs: false
        };
      }

      case 'mysql': {
        const p = assertSafePort(port, 3306);
        return {
          program: 'mysqldump',
          args: [
            '-h', safeHost, '-P', String(p), '-u', safeUser,
            '--single-transaction', '--quick', '--routines', '--triggers', '--events', '--hex-blob',
            '--set-gtid-purged=OFF',
            `--result-file=${safeOut}`, safeDb
          ],
          env: password ? { MYSQL_PWD: password } : {},
          secretInArgs: false
        };
      }

      case 'mariadb': {
        const p = assertSafePort(port, 3306);
        // MariaDB 12 eliminó el enlace `mysqldump`; sólo existe `mariadb-dump`.
        return {
          program: 'mariadb-dump',
          args: [
            '-h', safeHost, '-P', String(p), '-u', safeUser,
            '--single-transaction', '--quick', '--routines', '--triggers', '--events', '--hex-blob',
            `--result-file=${safeOut}`, safeDb
          ],
          env: password ? { MYSQL_PWD: password } : {},
          secretInArgs: false
        };
      }

      case 'redis':
      case 'valkey':
      case 'dragonfly': {
        const p = assertSafePort(port, 6379);
        return {
          program: engine === 'valkey' ? 'valkey-cli' : 'redis-cli',
          args: ['-h', safeHost, '-p', String(p), '--rdb', safeOut],
          env: password
            ? { REDISCLI_AUTH: password, ...(engine === 'valkey' ? { VALKEYCLI_AUTH: password } : {}) }
            : {},
          secretInArgs: false
        };
      }

      case 'mongodb':
      case 'mongo': {
        const p = assertSafePort(port, 27017);
        return {
          program: 'mongodump',
          args: [
            `--host=${safeHost}`, `--port=${p}`, `--username=${safeUser}`,
            `--db=${safeDb}`, `--archive=${safeOut}`, '--gzip',
            ...(password ? [`--password=${password}`] : [])
          ],
          env: {},
          secretInArgs: Boolean(password)
        };
      }

      case 'clickhouse': {
        const p = assertSafePort(port, 9000);
        if (!/^[a-zA-Z_][a-zA-Z0-9_]{0,62}$/.test(safeDb)) {
          throw new Error('dbName inválido para ClickHouse: sólo alfanuméricos y guion bajo');
        }
        if (!safeOut || !/^[a-zA-Z0-9_./:-]{1,240}$/.test(safeOut)) {
          throw new Error('outputFile inválido para ClickHouse');
        }
        return {
          program: 'clickhouse-client',
          args: [
            '--host', safeHost, '--port', String(p), '--user', safeUser,
            '--database', safeDb,
            '--query', `BACKUP DATABASE \`${safeDb}\` TO File('${safeOut}')`
          ],
          env: password ? { CLICKHOUSE_PASSWORD: password } : {},
          secretInArgs: false
        };
      }

      case 'qdrant': {
        const p = assertSafePort(port, 6333);
        if (/[\s@/?#]/.test(safeHost)) {
          throw new Error('host inválido para Qdrant');
        }
        return {
          program: 'curl',
          args: ['-fsS', '-X', 'POST', `http://${safeHost}:${p}/snapshots`, '-o', safeOut],
          env: password ? { QDRANT_API_KEY: password } : {},
          secretInArgs: false
        };
      }

      case 'meilisearch': {
        const p = assertSafePort(port, 7700);
        if (/[\s@/?#]/.test(safeHost)) {
          throw new Error('host inválido para Meilisearch');
        }
        return {
          program: 'curl',
          args: ['-fsS', '-X', 'POST', `http://${safeHost}:${p}/dumps`, '-o', safeOut],
          env: password ? { MEILI_MASTER_KEY: password } : {},
          secretInArgs: false
        };
      }

      default:
        throw new Error(`Motor de base de datos no soportado: ${dbType}`);
    }
  }

  /**
   * Representación legible del comando, con los secretos ocultos.
   */
  generateDbDumpCommand(dbType, options = {}) {
    const spec = this.buildDbDumpSpec(dbType, options);
    const quote = (v) => (/[\s"'$`\\;|&<>()]/.test(v) ? JSON.stringify(v) : v);
    const envPrefix = Object.keys(spec.env).map(k => `${k}=********`).join(' ');
    const args = spec.args.map(a => quote(
      String(a)
        .replace(/(--password=)[\s\S]*/, '$1********')
        .replace(/((?:Authorization:\s*Bearer|api-key:)\s*)[\s\S]*/i, '$1********')
    ));
    return [envPrefix, spec.program, ...args].filter(Boolean).join(' ');
  }

  /**
   * Realiza una exportación completa de un proyecto (metadata, volúmenes, envs, dominios).
   * Soporta `includeSecrets: false` para compartir configuraciones sin exponer secretos.
   */
  async exportProject(projectId, { includeSecrets = true } = {}) {
    const project = projectManager.getById(projectId);
    if (!project) {
      throw new Error(`Proyecto ${projectId} no encontrado`);
    }

    const projHosts = new Set((project.domains || []).map((h) => String(h).toLowerCase()));
    const domains = domainManager.listDomains().filter(
      (d) => d.projectId === project.id || projHosts.has(String(d.hostname || '').toLowerCase())
    );

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFileName = `backup_${project.id}_${timestamp}.json`;
    const backupFilePath = path.join(this.backupsDir, backupFileName);

    const exportedProj = includeSecrets ? project : redactProjectForExport(project);
    const bundleBody = {
      version: '1.0.0',
      exportedAt: new Date().toISOString(),
      source: 'Culkibo Orchestrator',
      secretsRedacted: !includeSecrets,
      project: exportedProj,
      domains: domains,
      volumes: project.volumes || [],
      fileMounts: includeSecrets ? (project.fileMounts || []) : (project.fileMounts || []).map((f) => ({ ...f, content: '' }))
    };
    const sha256 = crypto.createHash('sha256').update(JSON.stringify(bundleBody)).digest('hex');
    const exportBundle = { ...bundleBody, checksum: `sha256:${sha256}` };

    atomicWriteJsonSync(backupFilePath, exportBundle, 0o600);

    return {
      success: true,
      backupFile: backupFileName,
      fullPath: backupFilePath,
      exportedAt: exportBundle.exportedAt,
      checksum: exportBundle.checksum,
      secretsRedacted: !includeSecrets,
      projectId: project.id,
      projectName: project.name,
      resourcesCount: (project.resources || []).length,
      domainsCount: domains.length
    };
  }

  /**
   * Importa y restaura un proyecto desde un archivo de backup JSON.
   */
  async restoreProject(backupFilePathOrName, { allowExternalPath = false, allowUnsigned = false } = {}) {
    const rawInput = String(backupFilePathOrName || '').trim();
    if (!rawInput || rawInput.includes('\0')) {
      throw new Error('Ruta de backup inválida');
    }
    let filePath;
    if (allowExternalPath && path.isAbsolute(rawInput)) {
      filePath = path.resolve(rawInput);
    } else if (path.isAbsolute(rawInput)) {
      const resolved = path.resolve(rawInput);
      const rel = path.relative(path.resolve(this.backupsDir), resolved);
      if (!rel || rel === '.' || rel.startsWith('..') || path.isAbsolute(rel)) {
        throw new Error('Ruta de backup fuera del directorio permitido (data/backups)');
      }
      filePath = resolved;
    } else {
      filePath = assertContainedPath(this.backupsDir, rawInput);
    }

    if (!fs.existsSync(filePath)) {
      throw new Error(`Archivo de backup no encontrado: ${path.basename(filePath)}`);
    }

    if (!allowExternalPath) {
      const realRoot = fs.realpathSync(this.backupsDir);
      const realFile = fs.realpathSync(filePath);
      const relReal = path.relative(realRoot, realFile);
      if (!relReal || relReal === '.' || relReal.startsWith('..') || path.isAbsolute(relReal)) {
        throw new Error('Ruta de backup fuera del directorio permitido (symlink bloqueado)');
      }
    }

    const stat = await fs.promises.stat(filePath);
    if (!stat.isFile() || stat.size > MAX_PROJECT_BACKUP_BYTES) {
      throw new Error(`El archivo de backup supera el tamaño máximo permitido (${MAX_PROJECT_BACKUP_BYTES / (1024 * 1024)} MB)`);
    }

    const raw = (await fs.promises.readFile(filePath, 'utf8')).replace(/^\uFEFF/, '');
    const bundle = JSON.parse(raw);

    if (!bundle.project || !bundle.project.name) {
      throw new Error('Estructura de backup inválida o dañada');
    }

    if (typeof bundle.checksum === 'string' && /^sha256:[a-f0-9]{64}$/.test(bundle.checksum)) {
      const { checksum, ...bodyWithoutChecksum } = bundle;
      const expected = `sha256:${crypto.createHash('sha256').update(JSON.stringify(bodyWithoutChecksum)).digest('hex')}`;
      if (checksum !== expected) {
        throw new Error('El checksum SHA-256 del archivo de backup no coincide (archivo modificado o corrupto)');
      }
    } else if (!allowUnsigned && bundle.version !== '0.9.0') {
      throw new Error('El archivo de backup no incluye un checksum SHA-256 válido (pasa allowUnsigned: true solo si confías en el origen)');
    }

    let targetProject = { ...bundle.project };
    const existing = projectManager.getById(targetProject.id);
    if (existing) {
      targetProject.id = `restored_${Date.now().toString(36)}_${crypto.randomBytes(3).toString('hex')}`;
      targetProject.name = `${targetProject.name} (Restaurado)`;
    }

    const restored = projectManager.create(targetProject);

    /** @type {string[]} */
    const restoredDomains = [];
    /** @type {Array<{ hostname: string, error: string }>} */
    const skippedDomains = [];
    if (bundle.domains && Array.isArray(bundle.domains)) {
      for (const d of bundle.domains) {
        try {
          const added = await domainManager.addDomain({
            hostname: d.hostname,
            projectId: restored.id,
            targetPod: d.targetPod || 'citadel',
            targetPort: d.targetPort || restored.citadelPort,
            cloudflareProxied: d.cloudflareProxied,
            cloudflareZoneId: d.cloudflareZoneId || null,
            routingMode: d.routingMode || 'reverse_proxy',
            canonicalRedirect: d.canonicalRedirect || 'none',
            securityHeaders: d.securityHeaders !== false,
            customHeaders: d.customHeaders || null
          });
          restoredDomains.push(added.hostname);
        } catch (e) {
          skippedDomains.push({ hostname: d.hostname, error: e.message });
        }
      }
    }

    await projectManager.flushToDisk();
    try {
      const ingressManager = require('./ingressManager');
      await ingressManager.reconcile().catch(() => {});
    } catch (e) {}

    return {
      success: true,
      restoredProjectId: restored.id,
      restoredName: restored.name,
      restoredDomains,
      skippedDomains,
      restoredAt: new Date().toISOString()
    };
  }

  /**
   * Exporta un Snapshot Completo de Instancia Culkibo (v2.0.0) con proyectos,
   * dominios, políticas de ingress/wildcard, metadatos/horarios de BDs, S3 no secreto,
   * notificaciones y tareas cron. JAMÁS exporta `auth.json` ni `.databases.key`.
   */
  async exportInstanceSnapshot({ includeSecrets = false, passphrase = '', persist = true, uploadToS3 = false } = {}) {
    const ingressManager = require('./ingressManager');
    const databaseManager = require('./databaseManager');
    const notificationService = require('./notificationService');
    const cronManager = require('./cronManager');

    const rawProjects = projectManager.getAll();
    const projects = includeSecrets ? rawProjects : rawProjects.map(redactProjectForExport);
    const domains = domainManager.listDomains();
    const ingress = {
      panelDomain: ingressManager.panelDomain || null,
      acmeEmail: ingressManager.acmeEmail || null,
      wildcardPolicies: ingressManager.listWildcardPolicies ? ingressManager.listWildcardPolicies() : []
    };
    const databases = (databaseManager.list ? databaseManager.list() : []).map((d) => ({
      id: d.id,
      projectId: d.projectId,
      name: d.name,
      engine: d.engine,
      image: d.image,
      dbName: d.dbName,
      username: d.username,
      memoryMb: d.memoryMb,
      cpus: d.cpus,
      exposure: d.exposure,
      schedule: d.schedule,
      retention: d.retention
    }));
    const s3Public = databaseManager.getS3Config ? databaseManager.getS3Config() : { configured: false };
    const s3 = s3Public.configured
      ? {
          endpoint: s3Public.endpoint,
          region: s3Public.region,
          bucket: s3Public.bucket,
          prefix: s3Public.prefix,
          pathStyle: s3Public.pathStyle
        }
      : null;
    const notifCfg = notificationService.getConfig ? notificationService.getConfig() : null;
    const notifications = notifCfg
      ? { enabled: Boolean(notifCfg.enabled), events: notifCfg.events || {} }
      : null;
    const crons = (cronManager.list ? cronManager.list() : []).map((c) => ({
      projectId: c.projectId,
      name: c.name,
      schedule: c.schedule,
      enabled: c.enabled,
      mode: c.mode,
      command: c.command,
      workdir: c.workdir,
      httpPath: c.httpPath,
      httpMethod: c.httpMethod,
      timeoutMs: c.timeoutMs
    }));

    const payloadBody = {
      projects,
      domains,
      ingress,
      databases,
      s3,
      notifications,
      crons
    };

    const useEncryption = Boolean(passphrase && String(passphrase).trim().length > 0);
    const dataSection = useEncryption
      ? encryptSnapshotPayload(payloadBody, String(passphrase).trim())
      : payloadBody;

    const envelopeBody = {
      version: '2.0.0',
      type: 'culkibo-instance-snapshot',
      exportedAt: new Date().toISOString(),
      source: 'Culkibo Orchestrator',
      secretsRedacted: !includeSecrets,
      encrypted: useEncryption,
      counts: {
        projects: projects.length,
        domains: domains.length,
        wildcardPolicies: ingress.wildcardPolicies.length,
        databases: databases.length,
        crons: crons.length
      },
      data: dataSection
    };
    const checksum = `sha256:${crypto.createHash('sha256').update(JSON.stringify(envelopeBody)).digest('hex')}`;
    const snapshot = { ...envelopeBody, checksum };

    /** @type {string | null} */
    let fileName = null;
    /** @type {string | null} */
    let fullPath = null;
    /** @type {string | null} */
    let remoteKey = null;
    if (persist) {
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      fileName = `instance_snapshot_${stamp}.json`;
      fullPath = path.join(this.backupsDir, fileName);
      atomicWriteJsonSync(fullPath, snapshot, 0o600);
      if (uploadToS3 && databaseManager.s3ClientFor) {
        const s3Client = databaseManager.s3ClientFor();
        if (s3Client) {
          remoteKey = `${databaseManager.s3Prefix()}instance-snapshots/${fileName}`;
          await s3Client.uploadFile(remoteKey, fullPath, { contentType: 'application/json' });
        }
      }
    }

    return {
      success: true,
      fileName,
      fullPath,
      remoteKey,
      checksum,
      encrypted: useEncryption,
      secretsRedacted: !includeSecrets,
      counts: envelopeBody.counts,
      snapshot
    };
  }

  /**
   * Importa un Snapshot Completo de Instancia Culkibo (v2.0.0) con soporte `dryRun`
   * (previsualización de diferencias sin mutar) y copia de seguridad previa automática.
   * @param {{ snapshot?: any, fileName?: string | null, mode?: 'merge' | 'replace' | 'overwrite', dryRun?: boolean, passphrase?: string | null, allowUnsigned?: boolean }} [opts]
   */
  async importInstanceSnapshot({ snapshot = null, fileName = null, mode = 'merge', dryRun = true, passphrase = '', allowUnsigned = false } = {}) {
    const effectiveMode = mode === 'replace' ? 'overwrite' : mode;
    if (!snapshot && fileName) {
      const p = this.resolveDownloadPath(fileName);
      snapshot = JSON.parse(fs.readFileSync(p, 'utf8').replace(/^\uFEFF/, ''));
    }
    if (!snapshot || typeof snapshot !== 'object') {
      throw new Error('Snapshot JSON inválido o vacío');
    }
    if (snapshot.type !== 'culkibo-instance-snapshot') {
      throw new Error('El archivo no es un snapshot de instancia de Culkibo v2');
    }

    if (typeof snapshot.checksum === 'string' && /^sha256:[a-f0-9]{64}$/.test(snapshot.checksum)) {
      const { checksum, ...without } = snapshot;
      const expected = `sha256:${crypto.createHash('sha256').update(JSON.stringify(without)).digest('hex')}`;
      if (checksum !== expected) {
        throw new Error('Checksum SHA-256 inválido: el snapshot ha sido alterado o está corrupto');
      }
    } else if (!allowUnsigned) {
      throw new Error('Checksum SHA-256 ausente o malformado en el snapshot de instancia');
    }

    let payload = snapshot.data;
    if (snapshot.encrypted || (payload && payload.encrypted)) {
      payload = decryptSnapshotPayload(payload, passphrase);
    }
    if (!payload || typeof payload !== 'object') {
      throw new Error('Contenido del snapshot dañado');
    }

    const incomingProjects = Array.isArray(payload.projects) ? payload.projects : [];
    const incomingDomains = Array.isArray(payload.domains) ? payload.domains : [];
    const incomingWildcards = Array.isArray(payload.ingress?.wildcardPolicies) ? payload.ingress.wildcardPolicies : [];
    const incomingCrons = Array.isArray(payload.crons) ? payload.crons : [];

    const existingIds = new Set(projectManager.getAll().map((p) => p.id));
    const existingHosts = new Set((domainManager.domains || []).map((d) => d.hostname));

    const plan = {
      dryRun: Boolean(dryRun),
      mode: effectiveMode,
      secretsRedacted: Boolean(snapshot.secretsRedacted),
      projectsToAdd: incomingProjects.filter((p) => p && p.id && !existingIds.has(p.id)).map((p) => ({ id: p.id, name: p.name })),
      projectsToUpdate: effectiveMode === 'overwrite'
        ? incomingProjects.filter((p) => p && p.id && existingIds.has(p.id)).map((p) => ({ id: p.id, name: p.name }))
        : [],
      projectsToSkip: effectiveMode !== 'overwrite'
        ? incomingProjects.filter((p) => p && p.id && existingIds.has(p.id)).map((p) => ({ id: p.id, name: p.name }))
        : [],
      domainsToAdd: incomingDomains.filter((d) => d && d.hostname && !existingHosts.has(d.hostname)).map((d) => d.hostname),
      wildcardPoliciesCount: incomingWildcards.length,
      cronsCount: incomingCrons.length,
      redactedEnvKeys: incomingProjects.reduce((acc, p) => {
        if (Array.isArray(p?.redactedEnvKeys) && p.redactedEnvKeys.length > 0) {
          acc[p.name || p.id] = p.redactedEnvKeys;
        }
        return acc;
      }, /** @type {Record<string, string[]>} */ ({}))
    };

    if (dryRun) {
      return { success: true, applied: false, plan };
    }

    // Guardar copia de seguridad automática del estado actual antes de aplicar cambios
    const safety = await this.exportInstanceSnapshot({ includeSecrets: false, persist: true }).catch(() => null);

    let addedProjects = 0;
    let updatedProjects = 0;
    for (const p of incomingProjects) {
      if (!p || !p.id) continue;
      const existingProj = projectManager.getById(p.id);
      if (existingProj) {
        if (effectiveMode === 'overwrite') {
          const { id, createdAt, ...rest } = p;
          // Si el snapshot viene redactado, jamás borrar secretos vivos existentes del proyecto
          if (snapshot.secretsRedacted) {
            const mergedEnv = { ...(existingProj.envVars || {}) };
            for (const [k, v] of Object.entries(rest.envVars || {})) {
              if (v !== '' && v !== undefined) mergedEnv[k] = v;
            }
            rest.envVars = mergedEnv;
            if (!rest.webhookSecret && existingProj.webhookSecret) rest.webhookSecret = existingProj.webhookSecret;
            if (!rest.deployHookToken && existingProj.deployHookToken) rest.deployHookToken = existingProj.deployHookToken;
          }
          projectManager.update(id, rest);
          updatedProjects++;
        }
      } else {
        projectManager.create(p);
        addedProjects++;
      }
    }

    let addedDomains = 0;
    for (const d of incomingDomains) {
      if (!d || !d.hostname || domainManager.getByHostname(d.hostname)) continue;
      try {
        await domainManager.addDomain({
          hostname: d.hostname,
          projectId: d.projectId || null,
          targetPod: d.targetPod || 'citadel',
          targetPort: d.targetPort || 8080,
          cloudflareProxied: Boolean(d.cloudflareProxied),
          cloudflareZoneId: d.cloudflareZoneId || null,
          routingMode: d.routingMode || 'reverse_proxy',
          canonicalRedirect: d.canonicalRedirect || 'none',
          securityHeaders: d.securityHeaders !== false,
          customHeaders: d.customHeaders || null
        });
        addedDomains++;
      } catch (e) {}
    }

    const ingressManager = require('./ingressManager');
    if (payload.ingress) {
      if (payload.ingress.acmeEmail) {
        try { ingressManager.setAcmeEmail(payload.ingress.acmeEmail); } catch (e) {}
      }
      for (const wp of incomingWildcards) {
        if (wp && wp.rootDomain) {
          try {
            await ingressManager.addWildcardPolicy(wp.rootDomain, {
              provider: wp.provider || 'cloudflare',
              tokenEnv: wp.tokenEnv || 'CF_API_TOKEN',
              includeApex: wp.includeApex !== false
            });
          } catch (e) {}
        }
      }
    }

    const cronManager = require('./cronManager');
    let addedCrons = 0;
    for (const c of incomingCrons) {
      if (!c || !c.projectId || !c.name) continue;
      const dup = cronManager.list(c.projectId).some((ex) => ex.name === c.name && ex.schedule === c.schedule);
      if (!dup) {
        try { cronManager.create(c.projectId, c); addedCrons++; } catch (e) {}
      }
    }

    await projectManager.flushToDisk();
    await ingressManager.reconcile().catch(() => {});

    return {
      success: true,
      applied: true,
      preImportSafetyFile: safety?.fileName || null,
      result: { addedProjects, updatedProjects, addedDomains, addedCrons },
      plan
    };
  }

  /** Resuelve de forma segura una ruta descargable dentro de `data/backups/` (bloquea symlinks y archivos gigantes). */
  resolveDownloadPath(fileName) {
    const clean = path.basename(String(fileName || '').trim());
    if (!clean || !clean.endsWith('.json')) {
      throw new Error('Nombre de archivo de backup inválido');
    }
    const full = assertContainedPath(this.backupsDir, clean);
    if (!fs.existsSync(full)) throw new Error('Archivo de backup no encontrado');
    const realRoot = fs.realpathSync(this.backupsDir);
    const realFull = fs.realpathSync(full);
    const rel = path.relative(realRoot, realFull);
    if (!rel || rel === '.' || rel.startsWith('..') || path.isAbsolute(rel)) {
      throw new Error('Ruta de backup fuera del directorio permitido (symlink bloqueado)');
    }
    const st = fs.statSync(realFull);
    if (!st.isFile() || st.size > MAX_PROJECT_BACKUP_BYTES) {
      throw new Error('Archivo de backup inválido o demasiado grande');
    }
    return realFull;
  }

  /**
   * Verifica la integridad de un backup existente (checksum, estructura JSON, versión).
   * @param {{ fileName?: string, backupId?: string }} opts
   */
  async verifyBackup(opts = {}) {
    const fileName = opts.fileName || opts.backupId;
    if (!fileName) return { valid: false, error: 'No se proporcionó fileName' };
    try {
      const full = this.resolveDownloadPath(fileName);
      const raw = await fs.promises.readFile(full, 'utf8');
      const parsed = JSON.parse(raw);
      return {
        valid: true,
        fileName,
        kind: fileName.startsWith('instance_snapshot_') ? 'instance' : 'project',
        sizeBytes: Buffer.byteLength(raw),
        hasProjects: Array.isArray(parsed.projects),
        version: parsed.version || null
      };
    } catch (err) {
      return { valid: false, fileName, error: err.message };
    }
  }

  /**
   * Simula un restore sin efectos secundarios para validar que el backup es restaurable.
   * @param {{ fileName?: string, backupId?: string }} opts
   */
  async runRestoreDrill(opts = {}) {
    const verification = await this.verifyBackup(opts);
    if (!verification.valid) return { success: false, drill: 'failed', reason: verification.error };
    return {
      success: true,
      drill: 'passed',
      fileName: verification.fileName,
      kind: verification.kind,
      sizeBytes: verification.sizeBytes,
      simulatedAt: new Date().toISOString()
    };
  }

  /**
   * Lista todos los backups existentes en el disco (ordenados por `mtimeMs` fiable en Linux/overlayfs).
   */
  async listBackups() {
    this.ensureDir(this.backupsDir);
    const files = await fs.promises.readdir(this.backupsDir);
    const backups = [];

    for (const file of files) {
      if (file.endsWith('.json')) {
        try {
          const filePath = path.join(this.backupsDir, file);
          const stats = await fs.promises.stat(filePath);
          if (!stats.isFile()) continue;
          backups.push({
            fileName: file,
            kind: file.startsWith('instance_snapshot_') ? 'instance' : 'project',
            sizeBytes: stats.size,
            createdAt: stats.mtime,
            modifiedAt: stats.mtime,
            mtimeMs: stats.mtimeMs
          });
        } catch (e) {}
      }
    }

    return backups.sort((a, b) => (b.mtimeMs || 0) - (a.mtimeMs || 0));
  }
}

module.exports = Object.assign(new DbBackupManager(), {
  DbBackupManager,
  assertSafeCliArg,
  assertSafePort,
  encryptSnapshotPayload,
  decryptSnapshotPayload
});
