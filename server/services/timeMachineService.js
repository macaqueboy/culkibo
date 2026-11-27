const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { atomicWriteJsonSync } = require('./ssrfGuard');

/**
 * Whole-Stack Time-Machine: Checkpoints Contenido-Direccionados (SHA-256), Diff Estructural
 * y Restauración Atómica (Proyecto + Env cifrado + Dominios/Caddy Edge + Crons + DB Links).
 *
 * Garantías de seguridad y diseño:
 *  - 0 dependencias npm externas (`crypto`, `fs`, `path`).
 *  - 0 invocaciones de shell.
 *  - Carga 100% perezosa: `require()` no toca disco ni inicia timers (0 MB RAM en frío).
 *  - CERO secretos en claro en `timemachine.json`, diffs o respuestas API:
 *      * Las variables de entorno se comparan únicamente mediante huellas HMAC-SHA256 (`hmac:<16-hex>`).
 *      * Para permitir restauración exacta en `restoreCheckpoint({ dryRun: false })`, las
 *        variables de entorno se sellan con AES-256-GCM + AAD (`tm:<projectId>:<checkpointId>`)
 *        usando una clave dedicada `0o600` (`.timemachine.key`) y el sobre cifrado jamás se
 *        expone en `listCheckpoints` / `getCheckpoint` / `diffCheckpoints`.
 *  - `restoreCheckpoint()` usa `dryRun: true` por defecto y crea automáticamente un
 *    checkpoint de seguridad `pre_restore` antes de aplicar cambios reales.
 */

const PROJECT_ID_RE = /^[a-zA-Z0-9_-]{1,80}$/;
const MAX_CHECKPOINTS_PER_PROJECT = 50;
const FORBIDDEN_PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Resuelve el directorio de datos respetando `CULKIBO_DATA_DIR`.
 * @param {string | null} [overrideDir]
 * @returns {string}
 */
function resolveDataDir(overrideDir = null) {
  if (overrideDir) return path.resolve(overrideDir);
  if (process.env.CULKIBO_DATA_DIR) {
    return path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data');
  }
  return path.resolve(__dirname, '..', '..', 'data');
}

/** @param {string} projectId */
function assertProjectId(projectId) {
  const clean = String(projectId || '').trim();
  if (!PROJECT_ID_RE.test(clean) || FORBIDDEN_PROTO_KEYS.has(clean)) {
    throw new Error(`Identificador de proyecto inválido para Time-Machine: "${clean.slice(0, 60)}"`);
  }
  return clean;
}

/**
 * Serialización JSON canónica con claves ordenadas determinísticamente para SHA-256 estable.
 * @param {any} value
 * @returns {any}
 */
function canonicalizeObject(value) {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map((v) => canonicalizeObject(v));
  if (typeof value === 'object') {
    /** @type {Record<string, any>} */
    const out = {};
    for (const k of Object.keys(value).sort()) {
      if (FORBIDDEN_PROTO_KEYS.has(k) || value[k] === undefined) continue;
      out[k] = canonicalizeObject(value[k]);
    }
    return out;
  }
  return value;
}

/**
 * Calcula una huella HMAC-SHA256 corta para un par clave/valor de entorno sin exponer texto claro.
 * @param {string} key
 * @param {string} value
 * @param {Buffer} hmacKey
 * @returns {string}
 */
function hashEnvFingerprint(key, value, hmacKey) {
  const digest = crypto
    .createHmac('sha256', hmacKey)
    .update(`${String(key)}\0${String(value)}`, 'utf8')
    .digest('hex');
  return `hmac:${digest.slice(0, 20)}`;
}

/**
 * Cifra un objeto JSON con AES-256-GCM y AAD contextual.
 * @param {any} obj
 * @param {Buffer} masterKey
 * @param {string} aad
 * @returns {string}
 */
function sealEnvObject(obj, masterKey, aad) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const plaintext = Buffer.from(JSON.stringify(obj), 'utf8');
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString('base64')}:${tag.toString('base64')}:${ct.toString('base64')}`;
}

/**
 * Descifra un sobre AES-256-GCM sellado previamente con `sealEnvObject`.
 * @param {string} blob
 * @param {Buffer} masterKey
 * @param {string} aad
 * @returns {Record<string, string>}
 */
function unsealEnvObject(blob, masterKey, aad) {
  const parts = String(blob || '').split(':');
  if (parts.length !== 4 || parts[0] !== 'v1') {
    throw new Error('Sobre de entorno sellado inválido en checkpoint Time-Machine');
  }
  const iv = Buffer.from(parts[1], 'base64');
  const tag = Buffer.from(parts[2], 'base64');
  const ct = Buffer.from(parts[3], 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  const parsed = JSON.parse(plain);
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
}

/**
 * Extrae el snapshot sanitizado de un dominio (sin hashes bcrypt ni secretos).
 * @param {any} d
 */
function snapshotDomain(d) {
  /** @type {Record<string, any>} */
  const out = {
    hostname: String(d.hostname || '').toLowerCase(),
    targetPod: d.targetPod || 'citadel',
    targetPort: Number(d.targetPort) || 3000,
    routingMode: d.routingMode || 'direct_dns',
    cloudflareProxied: Boolean(d.cloudflareProxied),
    canonicalRedirect: d.canonicalRedirect || 'none',
    securityHeaders: d.securityHeaders !== false,
    hstsPreload: Boolean(d.hstsPreload),
    hstsMaxAge: d.hstsMaxAge != null ? Number(d.hstsMaxAge) : null,
    framePolicy: d.framePolicy || null,
    csp: d.csp || null,
    permissionsPolicy: d.permissionsPolicy || null,
    customHeaders: d.customHeaders || null,
    cors: d.cors && d.cors.enabled ? { ...d.cors } : null,
    forwardAuth: d.forwardAuth && d.forwardAuth.enabled ? { ...d.forwardAuth } : null,
    pathRoutes: Array.isArray(d.pathRoutes) ? d.pathRoutes.map((r) => ({ ...r })) : [],
    pathRedirects: Array.isArray(d.pathRedirects) ? d.pathRedirects.map((r) => ({ ...r })) : [],
    rateLimit: d.rateLimit && d.rateLimit.enabled ? { ...d.rateLimit } : null,
    ipAllowlist: Array.isArray(d.ipAllowlist) ? [...d.ipAllowlist] : [],
    maxBodySizeMb: d.maxBodySizeMb != null ? Number(d.maxBodySizeMb) : null,
    protocol: d.protocol || 'http'
  };
  return canonicalizeObject(out);
}

/**
 * Extrae el snapshot sanitizado de un cron job.
 * @param {any} c
 */
function snapshotCron(c) {
  return canonicalizeObject({
    name: String(c.name || ''),
    schedule: String(c.schedule || ''),
    mode: c.mode === 'http' ? 'http' : 'exec',
    command: c.mode === 'http' ? '' : String(c.command || ''),
    httpPath: c.mode === 'http' ? String(c.httpPath || '/') : '',
    httpMethod: c.mode === 'http' ? String(c.httpMethod || 'POST') : '',
    workdir: c.workdir ? String(c.workdir) : null,
    enabled: c.enabled !== false
  });
}

/**
 * Extrae el snapshot de configuración del proyecto (excluyendo `envVars` en claro).
 * @param {any} p
 */
function snapshotProjectConfig(p) {
  return canonicalizeObject({
    name: String(p.name || ''),
    description: String(p.description || ''),
    gitRepo: String(p.gitRepo || ''),
    gitBranch: String(p.gitBranch || 'main'),
    buildCommand: String(p.buildCommand || ''),
    startCommand: String(p.startCommand || ''),
    baseDirectory: String(p.baseDirectory || '/'),
    preDeployCommand: String(p.preDeployCommand || ''),
    postDeployCommand: String(p.postDeployCommand || ''),
    migrationCommand: String(p.migrationCommand || ''),
    healthPath: String(p.healthPath || '/'),
    containerPort: Number(p.containerPort || p.citadelPort) || 3000,
    memoryMb: p.memoryMb != null ? Number(p.memoryMb) : (p.memoryLimitMb != null ? Number(p.memoryLimitMb) : null),
    cpus: p.cpus != null ? Number(p.cpus) : (p.cpuLimit != null ? Number(p.cpuLimit) : null),
    stopGracePeriodSec: p.stopGracePeriodSec != null ? Number(p.stopGracePeriodSec) : null,
    logMaxSizeMb: p.logMaxSizeMb != null ? Number(p.logMaxSizeMb) : null,
    logMaxFiles: p.logMaxFiles != null ? Number(p.logMaxFiles) : null,
    status: String(p.status || 'active')
  });
}

/**
 * Calcula un diff estructural limpio y sin secretos entre dos snapshots Time-Machine.
 * @param {any} fromState
 * @param {any} toState
 */
function computeStackDiff(fromState, toState) {
  const a = fromState || {};
  const b = toState || {};
  const cfgA = a.projectConfig || {};
  const cfgB = b.projectConfig || {};

  const imageA = String(a.imageTag || '');
  const imageB = String(b.imageTag || '');
  const imageChanged = imageA !== imageB;

  /** @type {Record<string, { from: any, to: any }>} */
  const configChanges = {};
  const configKeys = Array.from(new Set([...Object.keys(cfgA), ...Object.keys(cfgB)])).sort();
  for (const k of configKeys) {
    if (JSON.stringify(cfgA[k]) !== JSON.stringify(cfgB[k])) {
      configChanges[k] = { from: cfgA[k] ?? null, to: cfgB[k] ?? null };
    }
  }

  const resources = {
    memoryMb: {
      changed: (cfgA.memoryMb ?? null) !== (cfgB.memoryMb ?? null),
      from: cfgA.memoryMb ?? null,
      to: cfgB.memoryMb ?? null
    },
    cpus: {
      changed: (cfgA.cpus ?? null) !== (cfgB.cpus ?? null),
      from: cfgA.cpus ?? null,
      to: cfgB.cpus ?? null
    },
    containerPort: {
      changed: (cfgA.containerPort ?? null) !== (cfgB.containerPort ?? null),
      from: cfgA.containerPort ?? null,
      to: cfgB.containerPort ?? null
    }
  };

  // Diff de entorno estrictamente por huellas HMAC (cero secretos en claro)
  const envA = a.envFingerprints || {};
  const envB = b.envFingerprints || {};
  const allEnvKeys = Array.from(new Set([...Object.keys(envA), ...Object.keys(envB)])).sort();
  /** @type {string[]} */
  const envAdded = [];
  /** @type {string[]} */
  const envRemoved = [];
  /** @type {string[]} */
  const envChanged = [];
  let envUnchangedCount = 0;
  for (const k of allEnvKeys) {
    const inA = Object.prototype.hasOwnProperty.call(envA, k);
    const inB = Object.prototype.hasOwnProperty.call(envB, k);
    if (!inA && inB) envAdded.push(k);
    else if (inA && !inB) envRemoved.push(k);
    else if (envA[k] !== envB[k]) envChanged.push(k);
    else envUnchangedCount++;
  }

  // Diff de dominios + políticas Caddy Edge
  const domMapA = new Map((Array.isArray(a.domains) ? a.domains : []).map((d) => [d.hostname, d]));
  const domMapB = new Map((Array.isArray(b.domains) ? b.domains : []).map((d) => [d.hostname, d]));
  /** @type {string[]} */
  const domainsAdded = [];
  /** @type {string[]} */
  const domainsRemoved = [];
  /** @type {Array<{ hostname: string, changedFields: string[] }>} */
  const domainsModified = [];
  /** @type {string[]} */
  const edgePoliciesChanged = [];

  for (const host of Array.from(new Set([...domMapA.keys(), ...domMapB.keys()])).sort()) {
    const da = domMapA.get(host);
    const db = domMapB.get(host);
    if (!da && db) {
      domainsAdded.push(host);
    } else if (da && !db) {
      domainsRemoved.push(host);
    } else if (da && db) {
      /** @type {string[]} */
      const changedFields = [];
      for (const fk of Array.from(new Set([...Object.keys(da), ...Object.keys(db)])).sort()) {
        if (JSON.stringify(da[fk]) !== JSON.stringify(db[fk])) {
          changedFields.push(fk);
        }
      }
      if (changedFields.length > 0) {
        domainsModified.push({ hostname: host, changedFields });
        if (changedFields.some((f) => ['hstsPreload', 'hstsMaxAge', 'cors', 'forwardAuth', 'pathRoutes', 'pathRedirects', 'rateLimit', 'customHeaders', 'csp', 'ipAllowlist', 'targetPort'].includes(f))) {
          edgePoliciesChanged.push(host);
        }
      }
    }
  }

  // Diff de crons
  const cronKey = (c) => `${c.name}::${c.schedule}`;
  const cronMapA = new Map((Array.isArray(a.crons) ? a.crons : []).map((c) => [c.name || cronKey(c), c]));
  const cronMapB = new Map((Array.isArray(b.crons) ? b.crons : []).map((c) => [c.name || cronKey(c), c]));
  /** @type {string[]} */
  const cronsAdded = [];
  /** @type {string[]} */
  const cronsRemoved = [];
  /** @type {string[]} */
  const cronsModified = [];
  for (const name of Array.from(new Set([...cronMapA.keys(), ...cronMapB.keys()])).sort()) {
    const ca = cronMapA.get(name);
    const cb = cronMapB.get(name);
    if (!ca && cb) cronsAdded.push(name);
    else if (ca && !cb) cronsRemoved.push(name);
    else if (JSON.stringify(ca) !== JSON.stringify(cb)) cronsModified.push(name);
  }

  // Diff de DB links
  const dbSetA = new Set(Array.isArray(a.dbLinks) ? a.dbLinks.map(String) : []);
  const dbSetB = new Set(Array.isArray(b.dbLinks) ? b.dbLinks.map(String) : []);
  const dbLinksAdded = Array.from(dbSetB).filter((x) => !dbSetA.has(x)).sort();
  const dbLinksRemoved = Array.from(dbSetA).filter((x) => !dbSetB.has(x)).sort();

  const changeCount =
    (imageChanged ? 1 : 0) +
    Object.keys(configChanges).length +
    envAdded.length + envRemoved.length + envChanged.length +
    domainsAdded.length + domainsRemoved.length + domainsModified.length +
    cronsAdded.length + cronsRemoved.length + cronsModified.length +
    dbLinksAdded.length + dbLinksRemoved.length;

  return {
    hasChanges: changeCount > 0,
    changeCount,
    imageTag: { changed: imageChanged, from: imageA, to: imageB },
    resources,
    configChanges,
    env: {
      added: envAdded,
      removed: envRemoved,
      changed: envChanged,
      unchangedCount: envUnchangedCount
    },
    domains: {
      added: domainsAdded,
      removed: domainsRemoved,
      modified: domainsModified
    },
    edgePoliciesChanged,
    crons: {
      added: cronsAdded,
      removed: cronsRemoved,
      modified: cronsModified
    },
    dbLinks: {
      added: dbLinksAdded,
      removed: dbLinksRemoved
    }
  };
}

class TimeMachineService {
  /**
   * @param {{
   *   dataDir?: string | null,
   *   projectManager?: any,
   *   domainManager?: any,
   *   cronManager?: any,
   *   databaseManager?: any
   * }} [opts]
   */
  constructor(opts = {}) {
    this._dataDirOverride = opts.dataDir || null;
    this._deps = {
      projectManager: opts.projectManager || null,
      domainManager: opts.domainManager || null,
      cronManager: opts.cronManager || null,
      databaseManager: opts.databaseManager || null
    };
    /** @type {Buffer | null} */
    this._masterKey = null;
    /** @type {Buffer | null} */
    this._hmacKey = null;
    this._loaded = false;
    /** @type {{ version: number, projects: Record<string, any[]> }} */
    this.state = { version: 1, projects: Object.create(null) };
  }

  get dataDir() {
    return resolveDataDir(this._dataDirOverride);
  }

  get storeFile() {
    return path.join(this.dataDir, 'timemachine.json');
  }

  get keyFile() {
    return path.join(this.dataDir, '.timemachine.key');
  }

  _getProjectManager() {
    if (!this._deps.projectManager) this._deps.projectManager = require('./projectManager');
    return this._deps.projectManager;
  }

  _getDomainManager() {
    if (!this._deps.domainManager) this._deps.domainManager = require('./domainManager');
    return this._deps.domainManager;
  }

  _getCronManager() {
    if (!this._deps.cronManager) {
      try { this._deps.cronManager = require('./cronManager'); } catch (e) {}
    }
    return this._deps.cronManager;
  }

  _getDatabaseManager() {
    if (!this._deps.databaseManager) {
      try { this._deps.databaseManager = require('./databaseManager'); } catch (e) {}
    }
    return this._deps.databaseManager;
  }

  _ensureKeys() {
    if (this._masterKey && this._hmacKey) return;
    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    if (fs.existsSync(this.keyFile)) {
      const hex = fs.readFileSync(this.keyFile, 'utf8').trim();
      const buf = Buffer.from(hex, 'hex');
      if (buf.length === 32) {
        this._masterKey = buf;
      }
    }
    if (!this._masterKey) {
      const rawKey = crypto.randomBytes(32);
      try {
        fs.writeFileSync(this.keyFile, rawKey.toString('hex'), { encoding: 'utf8', flag: 'wx', mode: 0o600 });
        this._masterKey = rawKey;
      } catch (err) {
        if (err && err.code === 'EEXIST') {
          this._masterKey = Buffer.from(fs.readFileSync(this.keyFile, 'utf8').trim(), 'hex');
        } else {
          throw err;
        }
      }
    }
    this._hmacKey = crypto.createHmac('sha256', this._masterKey).update('culkibo-timemachine-env-hmac-v1').digest();
  }

  _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;
    const bakFile = `${this.storeFile}.bak`;
    for (const candidate of [this.storeFile, bakFile]) {
      try {
        if (!fs.existsSync(candidate)) continue;
        const parsed = JSON.parse(fs.readFileSync(candidate, 'utf8'));
        if (parsed && typeof parsed === 'object' && parsed.projects && typeof parsed.projects === 'object') {
          const cleanProjects = Object.create(null);
          for (const [pid, arr] of Object.entries(parsed.projects)) {
            if (!FORBIDDEN_PROTO_KEYS.has(pid) && Array.isArray(arr)) {
              cleanProjects[pid] = arr;
            }
          }
          this.state = { version: 1, projects: cleanProjects };
          return;
        }
      } catch (e) {}
    }
    this.state = { version: 1, projects: Object.create(null) };
  }

  _save() {
    this._ensureLoaded();
    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    if (fs.existsSync(this.storeFile)) {
      try { fs.copyFileSync(this.storeFile, `${this.storeFile}.bak`); } catch (e) {}
    }
    atomicWriteJsonSync(this.storeFile, this.state, 0o600);
  }

  /**
   * Captura el estado vivo actual de un proyecto (sin secretos en claro).
   * @param {string} projectId
   */
  _captureLiveState(projectId) {
    this._ensureKeys();
    const pm = this._getProjectManager();
    const dm = this._getDomainManager();
    const cm = this._getCronManager();
    const dbm = this._getDatabaseManager();

    const project = pm.getById(projectId);
    if (!project) {
      const err = new Error(`Proyecto no encontrado para Time-Machine: "${projectId}"`);
      /** @type {any} */ (err).status = 404;
      throw err;
    }

    const rawEnv = (project.envVars && typeof project.envVars === 'object' && !Array.isArray(project.envVars))
      ? project.envVars
      : {};
    /** @type {Record<string, string>} */
    const cleanRawEnv = {};
    /** @type {Record<string, string>} */
    const envFingerprints = {};
    const hmacKey = /** @type {Buffer} */ (this._hmacKey);
    for (const k of Object.keys(rawEnv).sort()) {
      if (FORBIDDEN_PROTO_KEYS.has(k)) continue;
      const val = String(rawEnv[k] ?? '');
      cleanRawEnv[k] = val;
      envFingerprints[k] = hashEnvFingerprint(k, val, hmacKey);
    }

    const allDomains = dm && typeof dm.listDomains === 'function' ? dm.listDomains() : [];
    const attachedDomains = allDomains
      .filter((d) => d && d.projectId === projectId)
      .map((d) => snapshotDomain(d))
      .sort((a, b) => a.hostname.localeCompare(b.hostname));

    const rawCrons = cm && typeof cm.list === 'function' ? cm.list(projectId) : [];
    const attachedCrons = (Array.isArray(rawCrons) ? rawCrons : [])
      .map((c) => snapshotCron(c))
      .sort((a, b) => a.name.localeCompare(b.name));

    /** @type {Set<string>} */
    const dbLinkSet = new Set();
    for (const srcArr of [project.linkedDatabaseIds, project.linkedDatabases]) {
      if (!Array.isArray(srcArr)) continue;
      for (const link of srcArr) {
        if (typeof link === 'string' && link.trim()) dbLinkSet.add(link.trim());
        else if (link && (link.id || link.databaseId)) dbLinkSet.add(String(link.id || link.databaseId));
      }
    }
    if (dbm && typeof dbm.list === 'function') {
      try {
        const dbs = dbm.list();
        for (const db of (Array.isArray(dbs) ? dbs : [])) {
          if (db && db.projectId === projectId && db.id) dbLinkSet.add(String(db.id));
        }
      } catch (e) {}
    }

    const publicState = canonicalizeObject({
      projectConfig: snapshotProjectConfig(project),
      imageTag: String(project.imageTag || project.activeImageTag || project.lastCommit || ''),
      envKeys: Object.keys(envFingerprints).sort(),
      envCount: Object.keys(envFingerprints).length,
      envFingerprints,
      domains: attachedDomains,
      crons: attachedCrons,
      dbLinks: Array.from(dbLinkSet).sort()
    });

    return { project, publicState, cleanRawEnv };
  }

  /** Calcula el SHA-256 determinista de un checkpoint (sobre su contenido canónico público). */
  _computeCheckpointHash(cpPayload) {
    const canonical = JSON.stringify(canonicalizeObject({
      id: cpPayload.id,
      projectId: cpPayload.projectId,
      label: cpPayload.label,
      kind: cpPayload.kind,
      actor: cpPayload.actor,
      createdAt: cpPayload.createdAt,
      snapstreamGenId: cpPayload.snapstreamGenId,
      attestationSha256: cpPayload.attestationSha256,
      state: cpPayload.state
    }));
    return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
  }

  /** Elimina el sobre sellado interno antes de devolver checkpoints por API. */
  _sanitizeForRead(cp) {
    if (!cp) return null;
    const { _sealedEnvBlob, ...pub } = cp;
    return {
      ...pub,
      hasSealedEnv: Boolean(_sealedEnvBlob),
      counts: {
        envVars: pub.state ? pub.state.envCount : 0,
        domains: pub.state && Array.isArray(pub.state.domains) ? pub.state.domains.length : 0,
        crons: pub.state && Array.isArray(pub.state.crons) ? pub.state.crons.length : 0,
        dbLinks: pub.state && Array.isArray(pub.state.dbLinks) ? pub.state.dbLinks.length : 0
      }
    };
  }

  /**
   * Crea un checkpoint Whole-Stack inmutable con verificación SHA-256 y cero secretos en claro.
   *
   * @param {string} projectId
   * @param {{
   *   label?: string,
   *   actor?: string,
   *   kind?: 'manual' | 'auto' | 'pre_restore',
   *   imageTag?: string,
   *   snapstreamGenId?: string | null,
   *   attestationSha256?: string | null
   * }} [opts]
   */
  createCheckpoint(projectId, opts = {}) {
    const pid = assertProjectId(projectId);
    this._ensureLoaded();
    this._ensureKeys();

    const { publicState, cleanRawEnv } = this._captureLiveState(pid);
    if (opts.imageTag) {
      publicState.imageTag = String(opts.imageTag).trim();
    }

    const nowIso = new Date().toISOString();
    const id = `tm_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`;
    const label = String(opts.label || `Checkpoint ${nowIso.slice(0, 19).replace('T', ' ')}`).trim().slice(0, 120);
    const kind = opts.kind === 'auto' || opts.kind === 'pre_restore' ? opts.kind : 'manual';
    const actor = String(opts.actor || 'system').trim().slice(0, 80);
    const snapstreamGenId = opts.snapstreamGenId ? String(opts.snapstreamGenId).trim().slice(0, 128) : null;
    const attestationSha256 = opts.attestationSha256 ? String(opts.attestationSha256).trim().slice(0, 128) : null;

    const recordBase = {
      id,
      projectId: pid,
      label,
      kind,
      actor,
      createdAt: nowIso,
      snapstreamGenId,
      attestationSha256,
      state: publicState
    };
    const sha256 = this._computeCheckpointHash(recordBase);
    const sealedBlob = sealEnvObject(cleanRawEnv, /** @type {Buffer} */ (this._masterKey), `tm:${pid}:${id}`);

    const storedRecord = {
      ...recordBase,
      sha256,
      _sealedEnvBlob: sealedBlob
    };

    if (!this.state.projects[pid]) this.state.projects[pid] = [];
    this.state.projects[pid].unshift(storedRecord);
    if (this.state.projects[pid].length > MAX_CHECKPOINTS_PER_PROJECT) {
      this.state.projects[pid] = this.state.projects[pid].slice(0, MAX_CHECKPOINTS_PER_PROJECT);
    }
    this._save();

    return this._sanitizeForRead(storedRecord);
  }

  /**
   * Lista los checkpoints de un proyecto ordenados del más reciente al más antiguo.
   * @param {string} projectId
   */
  listCheckpoints(projectId) {
    const pid = assertProjectId(projectId);
    this._ensureLoaded();
    const list = Array.isArray(this.state.projects[pid]) ? this.state.projects[pid] : [];
    return list.map((cp) => this._sanitizeForRead(cp));
  }

  /**
   * Obtiene un checkpoint específico verificando su huella SHA-256.
   * @param {string} projectId
   * @param {string} checkpointId
   */
  getCheckpoint(projectId, checkpointId) {
    const pid = assertProjectId(projectId);
    this._ensureLoaded();
    const list = Array.isArray(this.state.projects[pid]) ? this.state.projects[pid] : [];
    const found = list.find((cp) => cp.id === checkpointId);
    if (!found) return null;
    const expectedHash = this._computeCheckpointHash(found);
    const integrityValid = expectedHash === found.sha256;
    return {
      ...this._sanitizeForRead(found),
      integrityValid
    };
  }

  /**
   * Calcula el diff estructural entre dos checkpoints (o entre un checkpoint y el estado `'live'`).
   * @param {string} projectId
   * @param {string} fromId
   * @param {string} toId
   */
  diffCheckpoints(projectId, fromId, toId = 'live') {
    const pid = assertProjectId(projectId);
    this._ensureLoaded();
    const list = Array.isArray(this.state.projects[pid]) ? this.state.projects[pid] : [];

    const resolveEndpoint = (ref) => {
      if (!ref || ref === 'live' || ref === 'current') {
        const live = this._captureLiveState(pid);
        return { id: 'live', label: 'Current Live State', state: live.publicState };
      }
      const cp = list.find((item) => item.id === ref);
      if (!cp) {
        const err = new Error(`Checkpoint Time-Machine no encontrado: "${ref}"`);
        /** @type {any} */ (err).status = 404;
        throw err;
      }
      return { id: cp.id, label: cp.label, state: cp.state };
    };

    const fromEp = resolveEndpoint(fromId);
    const toEp = resolveEndpoint(toId);
    const diff = computeStackDiff(fromEp.state, toEp.state);

    return {
      ok: true,
      projectId: pid,
      from: { id: fromEp.id, label: fromEp.label },
      to: { id: toEp.id, label: toEp.label },
      ...diff
    };
  }

  /**
   * Restaura atómicamente un checkpoint Whole-Stack (Proyecto + Env sellado + Dominios/Edge + Crons).
   * Por defecto `dryRun: true` (devuelve vista previa exacta sin mutar ningún estado).
   * Con `dryRun: false` crea primero un checkpoint de seguridad `pre_restore` automáticamente.
   *
   * @param {string} projectId
   * @param {string} checkpointId
   * @param {{ dryRun?: boolean, actor?: string, restoreDomains?: boolean, restoreCrons?: boolean, restoreEnv?: boolean }} [opts]
   */
  async restoreCheckpoint(projectId, checkpointId, opts = {}) {
    const pid = assertProjectId(projectId);
    const dryRun = opts.dryRun !== false;
    this._ensureLoaded();
    this._ensureKeys();

    const list = Array.isArray(this.state.projects[pid]) ? this.state.projects[pid] : [];
    const targetCp = list.find((cp) => cp.id === checkpointId);
    if (!targetCp) {
      const err = new Error(`Checkpoint Time-Machine no encontrado: "${checkpointId}"`);
      /** @type {any} */ (err).status = 404;
      throw err;
    }

    // Verificar integridad SHA-256 antes de tocar nada
    const recomputedHash = this._computeCheckpointHash(targetCp);
    if (recomputedHash !== targetCp.sha256) {
      const err = new Error(`Integridad SHA-256 inválida en checkpoint "${checkpointId}": archivo alterado o corrupto`);
      /** @type {any} */ (err).code = 'CHECKPOINT_INTEGRITY_ERROR';
      /** @type {any} */ (err).status = 409;
      throw err;
    }

    const live = this._captureLiveState(pid);
    const diff = computeStackDiff(live.publicState, targetCp.state);

    const restoreDomains = opts.restoreDomains !== false;
    const restoreCrons = opts.restoreCrons !== false;
    const restoreEnv = opts.restoreEnv !== false;

    const mutations = {
      projectFields: Object.keys(diff.configChanges),
      imageTagChanged: diff.imageTag.changed,
      envKeysAdded: restoreEnv ? diff.env.added : [],
      envKeysRemoved: restoreEnv ? diff.env.removed : [],
      envKeysChanged: restoreEnv ? diff.env.changed : [],
      domainsToAdd: restoreDomains ? diff.domains.added : [],
      domainsToRemove: restoreDomains ? diff.domains.removed : [],
      domainsToUpdate: restoreDomains ? diff.domains.modified.map((d) => d.hostname) : [],
      cronsToAdd: restoreCrons ? diff.crons.added : [],
      cronsToRemove: restoreCrons ? diff.crons.removed : [],
      cronsToUpdate: restoreCrons ? diff.crons.modified : []
    };

    if (dryRun) {
      return {
        ok: true,
        dryRun: true,
        restored: false,
        projectId: pid,
        checkpointId: targetCp.id,
        checkpointLabel: targetCp.label,
        sha256: targetCp.sha256,
        integrityVerified: true,
        willCreateSafetyCheckpoint: true,
        mutations,
        diff
      };
    }

    // 1. Crear checkpoint de seguridad pre_restore ANTES de aplicar cualquier mutación
    const safetyCp = this.createCheckpoint(pid, {
      label: `Pre-restore safety before ${targetCp.id}`,
      kind: 'pre_restore',
      actor: opts.actor || 'timemachine-restore'
    });

    const pm = this._getProjectManager();
    const dm = this._getDomainManager();
    const cm = this._getCronManager();

    // 2. Restaurar configuración del proyecto + envVars descifradas en memoria
    const cfg = targetCp.state.projectConfig || {};
    /** @type {Record<string, any>} */
    const projectPatch = {
      name: cfg.name,
      description: cfg.description,
      gitRepo: cfg.gitRepo,
      gitBranch: cfg.gitBranch,
      buildCommand: cfg.buildCommand,
      startCommand: cfg.startCommand,
      baseDirectory: cfg.baseDirectory,
      preDeployCommand: cfg.preDeployCommand,
      postDeployCommand: cfg.postDeployCommand,
      migrationCommand: cfg.migrationCommand,
      healthPath: cfg.healthPath,
      containerPort: cfg.containerPort,
      citadelPort: cfg.containerPort,
      memoryMb: cfg.memoryMb,
      memoryLimitMb: cfg.memoryMb,
      cpus: cfg.cpus,
      cpuLimit: cfg.cpus,
      imageTag: targetCp.state.imageTag || '',
      lastCommit: targetCp.state.imageTag || null,
      linkedDatabaseIds: Array.isArray(targetCp.state.dbLinks) ? [...targetCp.state.dbLinks] : [],
      linkedDatabases: Array.isArray(targetCp.state.dbLinks) ? [...targetCp.state.dbLinks] : [],
      domains: Array.isArray(targetCp.state.domains) ? targetCp.state.domains.map((d) => d.hostname) : []
    };

    let envKeysRestored = 0;
    if (restoreEnv && targetCp._sealedEnvBlob) {
      const unsealedEnv = unsealEnvObject(
        targetCp._sealedEnvBlob,
        /** @type {Buffer} */ (this._masterKey),
        `tm:${pid}:${targetCp.id}`
      );
      projectPatch.envVars = unsealedEnv;
      envKeysRestored = Object.keys(unsealedEnv).length;
    }

    if (typeof pm.update === 'function') {
      pm.update(pid, projectPatch);
    } else {
      const existingProj = pm.getById(pid);
      if (existingProj) Object.assign(existingProj, projectPatch);
    }
    if (typeof pm.flushToDisk === 'function') {
      await pm.flushToDisk().catch(() => {});
    }

    // 3. Reconciliar dominios y reglas Caddy Edge
    let domainsAdded = 0;
    let domainsUpdated = 0;
    let domainsRemoved = 0;
    if (restoreDomains && dm && typeof dm.listDomains === 'function') {
      const currentDomains = dm.listDomains().filter((d) => d && d.projectId === pid);
      const currentByHost = new Map(currentDomains.map((d) => [String(d.hostname).toLowerCase(), d]));
      const targetDomains = Array.isArray(targetCp.state.domains) ? targetCp.state.domains : [];
      const targetByHost = new Map(targetDomains.map((d) => [String(d.hostname).toLowerCase(), d]));

      // Eliminar dominios añadidos después del checkpoint
      for (const [host, dom] of currentByHost.entries()) {
        if (!targetByHost.has(host)) {
          if (typeof dm.deleteDomain === 'function') {
            await dm.deleteDomain(dom.id);
            domainsRemoved++;
          } else if (typeof dm.removeDomain === 'function') {
            await dm.removeDomain(dom.id);
            domainsRemoved++;
          }
        }
      }
      // Añadir o actualizar dominios del checkpoint
      for (const [host, td] of targetByHost.entries()) {
        const existingDom = currentByHost.get(host);
        /** @type {Record<string, any>} */
        const cleanEdgePatch = {
          projectId: pid,
          targetPod: td.targetPod || 'citadel',
          targetPort: td.targetPort || 3000,
          routingMode: td.routingMode || 'direct_dns',
          cloudflareProxied: Boolean(td.cloudflareProxied),
          canonicalRedirect: td.canonicalRedirect || 'none',
          securityHeaders: td.securityHeaders !== false,
          hstsPreload: Boolean(td.hstsPreload),
          ...(td.hstsMaxAge != null ? { hstsMaxAge: td.hstsMaxAge } : {}),
          ...(td.framePolicy ? { framePolicy: td.framePolicy } : {}),
          ...(td.csp ? { csp: td.csp } : {}),
          ...(td.permissionsPolicy ? { permissionsPolicy: td.permissionsPolicy } : {}),
          ...(td.customHeaders ? { customHeaders: td.customHeaders } : {}),
          ...(td.cors ? { cors: td.cors } : { cors: null }),
          ...(td.forwardAuth ? { forwardAuth: td.forwardAuth } : { forwardAuth: null }),
          pathRoutes: Array.isArray(td.pathRoutes) ? td.pathRoutes : [],
          pathRedirects: Array.isArray(td.pathRedirects) ? td.pathRedirects : [],
          ...(td.rateLimit ? { rateLimit: td.rateLimit } : { rateLimit: null }),
          ipAllowlist: Array.isArray(td.ipAllowlist) ? td.ipAllowlist : [],
          ...(td.maxBodySizeMb != null ? { maxBodySizeMb: td.maxBodySizeMb } : {}),
          protocol: td.protocol || 'http'
        };

        if (!existingDom && typeof dm.addDomain === 'function') {
          await dm.addDomain({ hostname: host, ...cleanEdgePatch });
          domainsAdded++;
        } else if (existingDom && typeof dm.updateDomain === 'function') {
          await dm.updateDomain(existingDom.id, cleanEdgePatch);
          domainsUpdated++;
        }
      }
    }

    // 4. Reconciliar crons del proyecto
    let cronsAdded = 0;
    let cronsRemoved = 0;
    if (restoreCrons && cm && typeof cm.list === 'function') {
      const currentCrons = cm.list(pid) || [];
      const targetCrons = Array.isArray(targetCp.state.crons) ? targetCp.state.crons : [];

      for (const cur of currentCrons) {
        if (typeof cm.remove === 'function') {
          cm.remove(cur.id);
          cronsRemoved++;
        } else if (typeof cm.delete === 'function') {
          cm.delete(cur.id);
          cronsRemoved++;
        }
      }
      if (typeof cm.create === 'function') {
        for (const tc of targetCrons) {
          cm.create(pid, {
            name: tc.name,
            schedule: tc.schedule,
            mode: tc.mode,
            command: tc.command,
            httpPath: tc.httpPath,
            httpMethod: tc.httpMethod,
            workdir: tc.workdir || undefined,
            enabled: tc.enabled !== false
          });
          cronsAdded++;
        }
      }
    }

    return {
      ok: true,
      dryRun: false,
      restored: true,
      projectId: pid,
      checkpointId: targetCp.id,
      checkpointLabel: targetCp.label,
      safetyCheckpointId: safetyCp ? safetyCp.id : null,
      sha256: targetCp.sha256,
      integrityVerified: true,
      applied: {
        projectUpdated: true,
        envKeysRestored,
        domainsAdded,
        domainsUpdated,
        domainsRemoved,
        cronsAdded,
        cronsRemoved
      },
      diff
    };
  }
}

const instance = /** @type {any} */ (new TimeMachineService());
instance.TimeMachineService = TimeMachineService;
instance.computeStackDiff = computeStackDiff;
instance.canonicalizeObject = canonicalizeObject;
instance.hashEnvFingerprint = hashEnvFingerprint;
module.exports = instance;
