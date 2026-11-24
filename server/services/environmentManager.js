const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const EventEmitter = require('events');
const { atomicWriteJsonSync, loadJsonWithBackupSync } = require('./ssrfGuard');

/**
 * Gestor de Entornos Aislados, Vault Cifrado Compartido y Pipeline de Promoción.
 *
 * Garantías de diseño y seguridad:
 *  - Cero dependencias npm externas (sólo `crypto`, `fs`, `path`, `events`).
 *  - Cero invocaciones de shell.
 *  - Carga perezosa: `require()` no toca disco ni inicia temporizadores (0 MB RAM en frío).
 *  - Cifrado en reposo AES-256-GCM con IV aleatorio de 96 bits y AAD contextual
 *    (`vault:<KEY>` o `env:<projectId>:<envName>:<KEY>`) para impedir trasplantes
 *    de texto cifrado entre proyectos, entornos o claves.
 *  - Clave maestra en `data/.vault.key` (`0o600`, `flag: 'wx'`) con protección
 *    anti-pérdida de clave: si `environments.json` (o `.bak`) contiene bloques
 *    cifrados `"v1:` y falta la clave, aborta sin regenerarla jamás.
 *  - `listVaultSecrets()` devuelve únicamente nombres, metadatos y huella HMAC-SHA256
 *    (jamás valores en claro).
 *  - `diffEnvironments()` compara exclusivamente huellas HMAC-SHA256 con clave derivada
 *    (cero filtración de secretos en diffs, UI, logs o MCP).
 *  - `promoteEnvironment()` crea automáticamente una instantánea previa en el entorno
 *    destino para permitir `rollbackPromotion()` en un clic.
 */

const PROJECT_ID_RE = /^[a-zA-Z0-9_-]{1,80}$/;
const ENV_SLUG_RE = /^[a-z0-9][a-z0-9-]{0,22}[a-z0-9]$/;
const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const SERVER_ID_RE = /^[a-z0-9_-]{1,64}$/;
const BRANCH_RE = /^[A-Za-z0-9._/-]{1,120}$/;
const VAULT_REF_RE = /\$\{vault\.([A-Za-z_][A-Za-z0-9_]{0,127})\}/g;
const FULL_VAULT_REF_RE = /^\$\{vault\.([A-Za-z_][A-Za-z0-9_]{0,127})\}$/;
const ENCRYPTED_BLOB_RE = /"v1:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+"/;

const FORBIDDEN_PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const DANGEROUS_HOST_ENV_KEYS = new Set([
  'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH',
  'DOCKER_HOST', 'DOCKER_CONFIG', 'DOCKER_CONTEXT', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY',
  'BUILDKIT_HOST', 'NODE_OPTIONS', 'BASH_ENV', 'IFS',
  'GIT_SSH_COMMAND', 'GIT_ASKPASS', 'GIT_EXEC_PATH', 'COMSPEC', 'PATHEXT'
]);
const SENSITIVE_KEY_RE = /(secret|token|pass(word|wd|phrase)?|apikey|api_key|private|auth|cred(ential)?|jwt|cookie|session|cert|pem|dsn|database_url|db_url|redis_url|mongo_url|smtp|webhook|stripe|openai|anthropic|gemini|aws_|s3_|r2_|encryption|signing|master)/i;
const VALID_SCOPES = new Set(['runtime', 'build', 'both']);

const MAX_VALUE_BYTES = 64 * 1024;
const MAX_ENV_VARS_PER_ENV = 500;
const MAX_VAULT_SECRETS = 1000;
const MAX_SNAPSHOTS_PER_ENV = 20;
const MAX_PROMOTION_HISTORY = 50;
const MAX_APPROVALS = 200;

/**
 * Resuelve el directorio `data/` respetando `CULKIBO_DATA_DIR`.
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
    throw new Error(`projectId inválido: ${clean.slice(0, 40)}`);
  }
  return clean;
}

/** @param {string} envName */
function assertEnvSlug(envName) {
  const clean = String(envName || '').trim();
  if (!ENV_SLUG_RE.test(clean) || FORBIDDEN_PROTO_KEYS.has(clean)) {
    throw new Error(`Nombre de entorno inválido (debe cumplir /^[a-z0-9-]{2,24}$/ sin guiones al inicio/fin): ${clean.slice(0, 40)}`);
  }
  return clean;
}

/** @param {string} key */
function assertEnvKey(key) {
  const clean = String(key || '').trim();
  if (!ENV_KEY_RE.test(clean) || FORBIDDEN_PROTO_KEYS.has(clean)) {
    throw new Error(`Nombre de variable/secreto inválido: ${clean.slice(0, 60)}`);
  }
  if (DANGEROUS_HOST_ENV_KEYS.has(clean.toUpperCase())) {
    throw new Error(`Variable de entorno bloqueada por seguridad del host: ${clean}`);
  }
  return clean;
}

/** @param {any} value @param {string} label */
function assertEnvValue(value, label = 'valor') {
  if (value === undefined || value === null) {
    throw new Error(`El ${label} no puede ser nulo`);
  }
  const str = String(value);
  if (str.includes('\0')) {
    throw new Error(`El ${label} no puede contener bytes nulos`);
  }
  if (Buffer.byteLength(str, 'utf8') > MAX_VALUE_BYTES) {
    throw new Error(`El ${label} supera el tamaño máximo permitido (${MAX_VALUE_BYTES} bytes)`);
  }
  return str;
}

/** @param {string | undefined} scope */
function normalizeScope(scope) {
  const s = String(scope || 'both').trim().toLowerCase();
  if (!VALID_SCOPES.has(s)) {
    throw new Error(`Alcance de variable inválido: ${s} (usa runtime, build o both)`);
  }
  return /** @type {'runtime' | 'build' | 'both'} */ (s);
}

/** @param {string | undefined} branch @param {string} envName */
function normalizeBranch(branch, envName) {
  if (branch === undefined || branch === null || String(branch).trim() === '') {
    if (envName === 'production') return 'main';
    if (envName === 'staging') return 'staging';
    if (envName === 'development' || envName === 'dev') return 'develop';
    return 'main';
  }
  const clean = String(branch).trim();
  if (!BRANCH_RE.test(clean) || clean.includes('..') || clean.startsWith('-') || clean.startsWith('/')) {
    throw new Error(`Nombre de rama inválido: ${clean.slice(0, 60)}`);
  }
  return clean;
}

/** @param {string | undefined} serverId */
function normalizeServerId(serverId) {
  if (serverId === undefined || serverId === null || String(serverId).trim() === '') {
    return 'local';
  }
  const clean = String(serverId).trim();
  if (!SERVER_ID_RE.test(clean) || FORBIDDEN_PROTO_KEYS.has(clean)) {
    throw new Error(`serverId inválido: ${clean.slice(0, 40)}`);
  }
  return clean;
}

/**
 * Cifra un valor en claro con AES-256-GCM y AAD contextual obligatorio.
 * @param {string} plain
 * @param {Buffer} key
 * @param {string} aad
 * @returns {string}
 */
function encryptVaultValue(plain, key, aad) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(String(aad), 'utf8'));
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  return `v1:${iv.toString('base64')}:${cipher.getAuthTag().toString('base64')}:${enc.toString('base64')}`;
}

/**
 * Descifra un bloque `v1:<iv>:<tag>:<ct>` verificando integridad y AAD contextual.
 * @param {string} blob
 * @param {Buffer} key
 * @param {string} aad
 * @returns {string}
 */
function decryptVaultValue(blob, key, aad) {
  const parts = String(blob || '').split(':');
  if (parts.length !== 4 || parts[0] !== 'v1') {
    throw new Error('Formato de secreto cifrado inválido o corrupto');
  }
  const iv = Buffer.from(parts[1], 'base64');
  const tag = Buffer.from(parts[2], 'base64');
  const ct = Buffer.from(parts[3], 'base64');
  if (iv.length !== 12 || tag.length !== 16) {
    throw new Error('Metadatos criptográficos AES-256-GCM inválidos');
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(String(aad), 'utf8'));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

/**
 * Deriva una subclave dedicada para huellas HMAC-SHA256 (separación de dominios
 * respecto a la clave AES-256-GCM).
 * @param {Buffer} masterKey
 * @returns {Buffer}
 */
function deriveFingerprintKey(masterKey) {
  return crypto.createHmac('sha256', masterKey).update('culkibo-vault-fingerprint-v1').digest();
}

/**
 * Calcula un hash SHA-256 con clave (HMAC-SHA256) y huella corta para comparar
 * valores secretos sin exponer jamás el texto en claro.
 * @param {string} value
 * @param {Buffer} hmacKey
 * @returns {{ sha256: string, fingerprint: string }}
 */
function hashSecretValue(value, hmacKey) {
  const sha256 = crypto.createHmac('sha256', hmacKey).update(String(value), 'utf8').digest('hex');
  return {
    sha256,
    fingerprint: `sha256:${sha256.slice(0, 16)}`
  };
}

/**
 * Extrae las claves `${vault.KEY}` referenciadas dentro de un valor de entorno.
 * @param {string} val
 * @returns {string[]}
 */
function extractVaultRefs(val) {
  const refs = new Set();
  const s = String(val || '');
  VAULT_REF_RE.lastIndex = 0;
  let m;
  while ((m = VAULT_REF_RE.exec(s)) !== null) {
    refs.add(m[1]);
  }
  return Array.from(refs);
}

/**
 * Determina si una clave de entorno debe considerarse secreta por defecto.
 * @param {string} key
 * @param {string} value
 * @returns {boolean}
 */
function isLikelySecret(key, value) {
  if (SENSITIVE_KEY_RE.test(key)) return true;
  const s = String(value || '');
  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(s)) return true;
  if (/\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|glpat-[A-Za-z0-9_-]{12,}|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{12,}|ck[stihp]_[A-Za-z0-9_-]{12,})\b/.test(s)) {
    return true;
  }
  if (/(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp):\/\/[^:\s/@]+:[^@\s/]+@/i.test(s)) {
    return true;
  }
  return false;
}

class EnvironmentManager extends EventEmitter {
  /**
   * @param {{
   *   dataDir?: string | null,
   *   domainManager?: any,
   *   deployManager?: any,
   *   projectManager?: any,
   *   databaseManager?: any,
   *   auditLogger?: any,
   *   notificationService?: any
   * }} [opts]
   */
  constructor(opts = {}) {
    super();
    this._dataDirOverride = opts.dataDir || null;
    this._deps = {
      domainManager: opts.domainManager || null,
      deployManager: opts.deployManager || null,
      projectManager: opts.projectManager || null,
      databaseManager: opts.databaseManager || null,
      auditLogger: opts.auditLogger || null,
      notificationService: opts.notificationService || null
    };
    /** @type {Buffer | null} */
    this._masterKey = null;
    /** @type {Buffer | null} */
    this._hmacKey = null;
    this._loaded = false;
    this._corruptReadOnly = false;
    /** @type {{ version: number, vault: Record<string, any>, projects: Record<string, { environments: Record<string, any> }>, groups: Record<string, any>, approvals: any[] }} */
    this.state = {
      version: 1,
      vault: Object.create(null),
      projects: Object.create(null),
      groups: Object.create(null),
      approvals: []
    };
  }

  get dataDir() {
    return resolveDataDir(this._dataDirOverride);
  }

  get storeFile() {
    return path.join(this.dataDir, 'environments.json');
  }

  get keyFile() {
    return path.join(this.dataDir, '.vault.key');
  }

  _getDomainManager() {
    if (!this._deps.domainManager) {
      try { this._deps.domainManager = require('./domainManager'); } catch (e) {}
    }
    return this._deps.domainManager;
  }

  _getDeployManager() {
    if (!this._deps.deployManager) {
      try { this._deps.deployManager = require('./deployManager'); } catch (e) {}
    }
    return this._deps.deployManager;
  }

  _getProjectManager() {
    if (!this._deps.projectManager) {
      try { this._deps.projectManager = require('./projectManager'); } catch (e) {}
    }
    return this._deps.projectManager;
  }

  _getDatabaseManager() {
    if (!this._deps.databaseManager) {
      try { this._deps.databaseManager = require('./databaseManager'); } catch (e) {}
    }
    return this._deps.databaseManager;
  }

  _getAuditLogger() {
    if (!this._deps.auditLogger) {
      try { this._deps.auditLogger = require('./auditLogger'); } catch (e) {}
    }
    return this._deps.auditLogger;
  }

  _getNotificationService() {
    if (!this._deps.notificationService) {
      try { this._deps.notificationService = require('./notificationService'); } catch (e) {}
    }
    return this._deps.notificationService;
  }

  /**
   * Registra un evento en el registro de auditoría (sin secretos).
   * @param {string} action
   * @param {string | null} resourceId
   * @param {Record<string, any>} detail
   */
  _audit(action, resourceId, detail) {
    try {
      const al = this._getAuditLogger();
      if (al && typeof al.record === 'function') {
        al.record({
          source: 'system',
          action,
          resourceId,
          status: 'ok',
          detail
        });
      }
    } catch (e) {}
  }

  /**
   * Carga o crea la clave maestra `data/.vault.key` con protección anti-pérdida.
   * @returns {Buffer}
   */
  _loadOrCreateKey() {
    if (this._masterKey) return this._masterKey;

    const kf = this.keyFile;
    const sf = this.storeFile;

    // P0: Si `.vault.key` ya existe, JAMÁS regenerarla ante lecturas corruptas o errores.
    if (fs.existsSync(kf)) {
      const raw = fs.readFileSync(kf, 'utf8').trim();
      const key = Buffer.from(raw, 'hex');
      if (key.length !== 32) {
        throw new Error(`Clave de cifrado corrupta en ${kf} (esperados 32 bytes). No se regenerará automáticamente para proteger tu vault.`);
      }
      this._masterKey = key;
      this._hmacKey = deriveFingerprintKey(key);
      return key;
    }

    // Protección anti-pérdida: si environments.json o .bak contienen secretos cifrados v1:,
    // rechazar la generación de una nueva clave.
    for (const candidate of [sf, `${sf}.bak`]) {
      if (!fs.existsSync(candidate)) continue;
      let existingData = '';
      try {
        existingData = fs.readFileSync(candidate, 'utf8');
      } catch (e) {
        continue;
      }
      if (existingData.includes('"v1:') || ENCRYPTED_BLOB_RE.test(existingData)) {
        throw new Error(`Falta el archivo de clave ${kf} pero ${candidate} contiene secretos cifrados. Restaura .vault.key desde tu copia segura antes de continuar.`);
      }
    }

    const key = crypto.randomBytes(32);
    fs.mkdirSync(path.dirname(kf), { recursive: true, mode: 0o700 });
    try {
      fs.writeFileSync(kf, key.toString('hex'), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
      try { fs.chmodSync(kf, 0o600); } catch (e) {}
    } catch (err) {
      /** @type {any} */
      const e = err;
      if (e && e.code === 'EEXIST') {
        const raced = Buffer.from(fs.readFileSync(kf, 'utf8').trim(), 'hex');
        if (raced.length === 32) {
          this._masterKey = raced;
          this._hmacKey = deriveFingerprintKey(raced);
          return raced;
        }
      }
      throw err;
    }

    this._masterKey = key;
    this._hmacKey = deriveFingerprintKey(key);
    return key;
  }

  /** @returns {Buffer} */
  _getHmacKey() {
    if (!this._hmacKey) {
      this._loadOrCreateKey();
    }
    return /** @type {Buffer} */ (this._hmacKey);
  }

  _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;

    const loaded = loadJsonWithBackupSync(this.storeFile, {
      validate: (parsed) => Boolean(parsed && typeof parsed === 'object' && !Array.isArray(parsed))
    });

    if (loaded.ok && loaded.data) {
      const d = loaded.data;
      const vault = Object.create(null);
      if (d.vault && typeof d.vault === 'object' && !Array.isArray(d.vault)) {
        for (const [k, v] of Object.entries(d.vault)) {
          if (!FORBIDDEN_PROTO_KEYS.has(k) && v && typeof v === 'object') {
            vault[k] = v;
          }
        }
      }
      const projects = Object.create(null);
      if (d.projects && typeof d.projects === 'object' && !Array.isArray(d.projects)) {
        for (const [pid, pObj] of Object.entries(d.projects)) {
          if (FORBIDDEN_PROTO_KEYS.has(pid) || !pObj || typeof pObj !== 'object') continue;
          const envs = Object.create(null);
          if (pObj.environments && typeof pObj.environments === 'object') {
            for (const [en, eObj] of Object.entries(pObj.environments)) {
              if (!FORBIDDEN_PROTO_KEYS.has(en) && eObj && typeof eObj === 'object') {
                envs[en] = eObj;
              }
            }
          }
          projects[pid] = { environments: envs };
        }
      }
      const groups = Object.create(null);
      if (d.groups && typeof d.groups === 'object' && !Array.isArray(d.groups)) {
        for (const [gid, gObj] of Object.entries(d.groups)) {
          if (!FORBIDDEN_PROTO_KEYS.has(gid) && gObj && typeof gObj === 'object') {
            groups[gid] = gObj;
          }
        }
      }
      this.state = {
        version: 1,
        vault,
        projects,
        groups,
        approvals: Array.isArray(d.approvals) ? d.approvals.slice(-MAX_APPROVALS) : []
      };
      this._corruptReadOnly = false;
      return;
    }

    if (loaded.corrupt) {
      this._corruptReadOnly = true;
      console.error(`[EnvironmentManager] ${this.storeFile} corrupto (cuarentena: ${loaded.quarantinePath}). Escritura bloqueada.`);
    }
  }

  _save() {
    this._ensureLoaded();
    if (this._corruptReadOnly) {
      throw new Error('environments.json estaba corrupto al cargar; repáralo antes de guardar cambios');
    }
    atomicWriteJsonSync(this.storeFile, this.state, { mode: 0o600, backup: true });
  }

  /**
   * Normaliza un dominio usando `domainManager.normalizeAndValidateHostname` si está disponible.
   * @param {string} raw
   * @returns {string}
   */
  _validateDomain(raw) {
    const dm = this._getDomainManager();
    if (dm && typeof dm.normalizeAndValidateHostname === 'function') {
      return dm.normalizeAndValidateHostname(raw);
    }
    const clean = String(raw || '').trim().toLowerCase().replace(/\.+$/, '');
    if (!clean || clean.length > 253 || !/^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/.test(clean)) {
      if (clean === 'localhost') return 'localhost';
      throw new Error(`Formato de dominio inválido: ${raw}`);
    }
    return clean;
  }

  // =========================================================================
  // 1. SHARED ENCRYPTED ENV VAULT
  // =========================================================================

  /**
   * Proyección pública de un secreto del Vault: NUNCA incluye el valor en claro ni el ciphertext.
   * @param {any} entry
   */
  _toPublicVaultEntry(entry) {
    return {
      key: entry.key,
      fingerprint: entry.fingerprint,
      scope: entry.scope || 'both',
      secret: true,
      description: entry.description || '',
      valueLength: entry.valueLength || 0,
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt,
      updatedBy: entry.updatedBy || 'system'
    };
  }

  /**
   * Lista todos los secretos compartidos del Vault (solo nombres, metadatos y huella; JAMÁS valores).
   * @returns {Array<{ key: string, fingerprint: string, scope: string, secret: boolean, description: string, valueLength: number, createdAt: string, updatedAt: string, updatedBy: string }>}
   */
  listVaultSecrets() {
    this._ensureLoaded();
    return Object.keys(this.state.vault)
      .sort()
      .map((k) => this._toPublicVaultEntry(this.state.vault[k]));
  }

  /**
   * Comprueba si existe una clave en el Vault compartido.
   * @param {string} key
   * @returns {boolean}
   */
  hasVaultSecret(key) {
    this._ensureLoaded();
    const clean = String(key || '').trim();
    if (!ENV_KEY_RE.test(clean) || FORBIDDEN_PROTO_KEYS.has(clean)) return false;
    return Boolean(this.state.vault[clean]);
  }

  /**
   * Devuelve metadatos y huella de un secreto del Vault (nunca el valor en claro).
   * @param {string} key
   */
  getVaultSecretMeta(key) {
    this._ensureLoaded();
    const clean = assertEnvKey(key);
    const entry = this.state.vault[clean];
    return entry ? this._toPublicVaultEntry(entry) : null;
  }

  /**
   * Crea o actualiza un secreto compartido en el Vault cifrado AES-256-GCM.
   * @param {string} key
   * @param {string} value
   * @param {{ scope?: string, description?: string, actor?: string }} [opts]
   */
  setVaultSecret(key, value, opts = {}) {
    this._ensureLoaded();
    const cleanKey = assertEnvKey(key);
    const cleanVal = assertEnvValue(value, `valor del secreto "${cleanKey}"`);
    const scope = normalizeScope(opts.scope || 'both');
    const description = String(opts.description || '').replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 240);
    const actor = String(opts.actor || 'system').slice(0, 80);

    const existing = this.state.vault[cleanKey];
    if (!existing && Object.keys(this.state.vault).length >= MAX_VAULT_SECRETS) {
      throw new Error(`Límite máximo de secretos en el Vault alcanzado (${MAX_VAULT_SECRETS})`);
    }

    const masterKey = this._loadOrCreateKey();
    const hmacKey = this._getHmacKey();
    const encryptedValue = encryptVaultValue(cleanVal, masterKey, `vault:${cleanKey}`);
    const { fingerprint } = hashSecretValue(cleanVal, hmacKey);
    const now = new Date().toISOString();

    this.state.vault[cleanKey] = {
      key: cleanKey,
      encryptedValue,
      fingerprint,
      scope,
      secret: true,
      description,
      valueLength: cleanVal.length,
      createdAt: existing ? existing.createdAt : now,
      updatedAt: now,
      updatedBy: actor
    };

    this._save();
    this._audit('vault.secret_set', cleanKey, { key: cleanKey, scope, fingerprint, actor });
    const pub = this._toPublicVaultEntry(this.state.vault[cleanKey]);
    this.emit('vault_updated', { action: existing ? 'updated' : 'created', secret: pub });
    return pub;
  }

  /**
   * Elimina un secreto del Vault compartido.
   * @param {string} key
   * @param {{ actor?: string }} [opts]
   */
  deleteVaultSecret(key, opts = {}) {
    this._ensureLoaded();
    const cleanKey = assertEnvKey(key);
    if (!this.state.vault[cleanKey]) {
      return { deleted: false, key: cleanKey };
    }
    delete this.state.vault[cleanKey];
    this._save();
    this._audit('vault.secret_deleted', cleanKey, { key: cleanKey, actor: opts.actor || 'system' });
    this.emit('vault_updated', { action: 'deleted', key: cleanKey });
    return { deleted: true, key: cleanKey };
  }

  /**
   * Lectura interna descifrada de un secreto del Vault (NO exponer por API/UI/MCP).
   * @param {string} key
   * @returns {string | null}
   */
  _readVaultSecretInternal(key) {
    this._ensureLoaded();
    const entry = this.state.vault[key];
    if (!entry) return null;
    const masterKey = this._loadOrCreateKey();
    return decryptVaultValue(entry.encryptedValue, masterKey, `vault:${key}`);
  }

  /**
   * Resuelve referencias `${vault.KEY}` en un mapa de variables de entorno (una sola pasada,
   * sin re-expansión recursiva para impedir bucles o inyección secundaria).
   *
   * @param {Record<string, any> | null | undefined} envMap
   * @param {{ strict?: boolean, phase?: 'runtime' | 'build' | 'all' }} [opts]
   * @returns {{ env: Record<string, string>, resolvedKeys: string[], missingKeys: string[], secretValues: string[] }}
   */
  resolveEnvWithVault(envMap, opts = {}) {
    this._ensureLoaded();
    const strict = Boolean(opts.strict);
    const phase = opts.phase || 'all';
    /** @type {Record<string, string>} */
    const resolvedEnv = Object.create(null);
    /** @type {Set<string>} */
    const resolvedKeys = new Set();
    /** @type {Set<string>} */
    const missingKeys = new Set();
    /** @type {Set<string>} */
    const secretValues = new Set();

    if (envMap && typeof envMap === 'object') {
      for (const [rawKey, rawVal] of Object.entries(envMap)) {
        if (FORBIDDEN_PROTO_KEYS.has(rawKey)) continue;
        if (!ENV_KEY_RE.test(rawKey)) continue;
        const valStr = rawVal == null ? '' : String(rawVal);

        VAULT_REF_RE.lastIndex = 0;
        const substituted = valStr.replace(VAULT_REF_RE, (fullMatch, vaultKey) => {
          const entry = this.state.vault[vaultKey];
          if (!entry) {
            missingKeys.add(vaultKey);
            return fullMatch;
          }
          if (phase !== 'all' && entry.scope && entry.scope !== 'both' && entry.scope !== phase) {
            missingKeys.add(vaultKey);
            return fullMatch;
          }
          const secretPlain = this._readVaultSecretInternal(vaultKey);
          if (secretPlain === null) {
            missingKeys.add(vaultKey);
            return fullMatch;
          }
          resolvedKeys.add(vaultKey);
          if (secretPlain.length >= 6) secretValues.add(secretPlain);
          return secretPlain;
        });

        resolvedEnv[rawKey] = substituted;
      }
    }

    const missingArr = Array.from(missingKeys).sort();
    if (strict && missingArr.length > 0) {
      throw new Error(`Faltan secretos referenciados en el Vault: ${missingArr.join(', ')}`);
    }

    return {
      env: Object.assign({}, resolvedEnv),
      resolvedKeys: Array.from(resolvedKeys).sort(),
      missingKeys: missingArr,
      secretValues: Array.from(secretValues)
    };
  }

  // =========================================================================
  // 2. PER-PROJECT ISOLATED ENVIRONMENTS
  // =========================================================================

  /**
   * Proyección pública de un entorno: oculta secretos y `encryptedValue`.
   * @param {string} projectId
   * @param {any} envObj
   */
  _toPublicEnvironment(projectId, envObj) {
    const rawVars = envObj.envVars && typeof envObj.envVars === 'object' ? envObj.envVars : {};
    const keys = Object.keys(rawVars).sort();
    /** @type {Record<string, any>} */
    const envMeta = {};
    for (const k of keys) {
      const rec = rawVars[k];
      if (!rec) continue;
      envMeta[k] = {
        key: k,
        fingerprint: rec.fingerprint,
        secret: Boolean(rec.secret),
        scope: rec.scope || 'both',
        isVaultRef: Boolean(rec.isVaultRef),
        vaultRefs: Array.isArray(rec.vaultRefs) ? [...rec.vaultRefs] : [],
        updatedAt: rec.updatedAt || envObj.updatedAt
      };
    }

    return {
      projectId,
      name: envObj.name,
      branch: envObj.branch,
      domains: Array.isArray(envObj.domains) ? [...envObj.domains] : [],
      serverId: envObj.serverId || 'local',
      protected: Boolean(envObj.protected),
      requireApproval: Boolean(envObj.requireApproval),
      autoDeploy: envObj.autoDeploy !== false,
      envVarCount: keys.length,
      envKeys: keys,
      envMeta,
      lastRelease: envObj.lastRelease ? { ...envObj.lastRelease } : null,
      snapshotCount: Array.isArray(envObj.snapshots) ? envObj.snapshots.length : 0,
      promotionCount: Array.isArray(envObj.promotionHistory) ? envObj.promotionHistory.length : 0,
      promotionHistory: Array.isArray(envObj.promotionHistory)
        ? envObj.promotionHistory.map((h) => ({ ...h }))
        : [],
      createdAt: envObj.createdAt,
      updatedAt: envObj.updatedAt
    };
  }

  /**
   * Descifra el mapa `envVars` de un entorno en memoria para cálculo interno (diff, resolve, promote).
   * @param {string} projectId
   * @param {any} envObj
   * @param {{ phase?: 'runtime' | 'build' | 'all' }} [opts]
   * @returns {Record<string, { value: string, secret: boolean, scope: string, isVaultRef: boolean, vaultRefs: string[] }>}
   */
  _decryptEnvVarsInternal(projectId, envObj, opts = {}) {
    const phase = opts.phase || 'all';
    const rawVars = envObj && envObj.envVars && typeof envObj.envVars === 'object' ? envObj.envVars : {};
    const keys = Object.keys(rawVars);
    /** @type {Record<string, { value: string, secret: boolean, scope: string, isVaultRef: boolean, vaultRefs: string[] }>} */
    const out = Object.create(null);
    if (keys.length === 0) return out;

    const masterKey = this._loadOrCreateKey();
    for (const k of keys) {
      if (FORBIDDEN_PROTO_KEYS.has(k)) continue;
      const rec = rawVars[k];
      if (!rec || typeof rec.encryptedValue !== 'string') continue;
      const recScope = rec.scope || 'both';
      if (phase !== 'all' && recScope !== 'both' && recScope !== phase) continue;
      const plain = decryptVaultValue(rec.encryptedValue, masterKey, `env:${projectId}:${envObj.name}:${k}`);
      out[k] = {
        value: plain,
        secret: Boolean(rec.secret),
        scope: recScope,
        isVaultRef: Boolean(rec.isVaultRef),
        vaultRefs: Array.isArray(rec.vaultRefs) ? [...rec.vaultRefs] : extractVaultRefs(plain)
      };
    }
    return out;
  }

  /**
   * Lista los entornos configurados para un proyecto (sin secretos en claro).
   * @param {string} projectId
   */
  listEnvironments(projectId) {
    this._ensureLoaded();
    const pid = assertProjectId(projectId);
    const projEntry = this.state.projects[pid];
    if (!projEntry || !projEntry.environments) return [];
    const order = { development: 0, dev: 1, staging: 2, production: 3, prod: 4 };
    return Object.values(projEntry.environments)
      .sort((a, b) => {
        const oa = order[a.name] !== undefined ? order[a.name] : 99;
        const ob = order[b.name] !== undefined ? order[b.name] : 99;
        if (oa !== ob) return oa - ob;
        return String(a.name).localeCompare(String(b.name));
      })
      .map((e) => this._toPublicEnvironment(pid, e));
  }

  /** Alias de conveniencia para API/UI. */
  getProjectEnvironments(projectId) {
    return this.listEnvironments(projectId);
  }

  /**
   * Lista todos los entornos configurados a través de todos los proyectos (opcionalmente
   * filtrados por `projectIds` para aislamiento RBAC). Jamás incluye secretos en claro.
   * @param {{ projectIds?: string[] | null }} [opts]
   */
  listAllEnvironments(opts = {}) {
    this._ensureLoaded();
    const filterSet = Array.isArray(opts.projectIds) ? new Set(opts.projectIds) : null;
    /** @type {Record<string, any[]>} */
    const byProject = {};
    /** @type {any[]} */
    const environments = [];
    for (const pid of Object.keys(this.state.projects).sort()) {
      if (filterSet && !filterSet.has(pid)) continue;
      const list = this.listEnvironments(pid);
      byProject[pid] = list;
      environments.push(...list);
    }
    return {
      projectCount: Object.keys(byProject).length,
      environmentCount: environments.length,
      vaultSecretCount: Object.keys(this.state.vault).length,
      byProject,
      environments
    };
  }

  /**
   * Obtiene un entorno específico de un proyecto (sin secretos en claro).
   * @param {string} projectId
   * @param {string} envName
   */
  getEnvironment(projectId, envName) {
    this._ensureLoaded();
    const pid = assertProjectId(projectId);
    const slug = assertEnvSlug(envName);
    const envObj = this.state.projects[pid] && this.state.projects[pid].environments[slug];
    return envObj ? this._toPublicEnvironment(pid, envObj) : null;
  }

  /**
   * Crea o actualiza un entorno aislado para un proyecto.
   * Todas las variables de entorno se cifran con AES-256-GCM en reposo.
   *
   * @param {string} projectId
   * @param {string} envName
   * @param {{
   *   branch?: string,
   *   domain?: string,
   *   domains?: string[],
   *   serverId?: string,
   *   envVars?: Record<string, string | { value: string, secret?: boolean, scope?: string }>,
   *   replaceEnvVars?: boolean,
   *   unsetEnvKeys?: string[],
   *   cloneEnvFrom?: string | null,
   *   protected?: boolean,
   *   requireApproval?: boolean,
   *   autoDeploy?: boolean,
   *   lastRelease?: Record<string, any> | null,
   *   actor?: string
   * }} [payload]
   */
  upsertEnvironment(projectId, envName, payload = {}) {
    this._ensureLoaded();
    const pid = assertProjectId(projectId);
    const slug = assertEnvSlug(envName);

    if (!this.state.projects[pid]) {
      this.state.projects[pid] = { environments: Object.create(null) };
    }
    const existing = this.state.projects[pid].environments[slug] || null;
    const now = new Date().toISOString();

    const envObj = existing || {
      name: slug,
      branch: normalizeBranch(payload.branch, slug),
      domains: [],
      serverId: normalizeServerId(payload.serverId),
      protected: payload.protected !== undefined ? Boolean(payload.protected) : slug === 'production',
      requireApproval: Boolean(payload.requireApproval),
      autoDeploy: payload.autoDeploy !== undefined ? Boolean(payload.autoDeploy) : true,
      envVars: Object.create(null),
      lastRelease: null,
      snapshots: [],
      promotionHistory: [],
      createdAt: now,
      updatedAt: now
    };

    if (payload.branch !== undefined) {
      envObj.branch = normalizeBranch(payload.branch, slug);
    }
    if (payload.serverId !== undefined) {
      envObj.serverId = normalizeServerId(payload.serverId);
    }
    if (payload.domains !== undefined) {
      if (!Array.isArray(payload.domains)) {
        throw new Error('domains debe ser un array de nombres de dominio');
      }
      envObj.domains = Array.from(new Set(payload.domains.map((d) => this._validateDomain(d))));
    } else if (payload.domain !== undefined && String(payload.domain).trim() !== '') {
      const normalizedDom = this._validateDomain(String(payload.domain));
      envObj.domains = Array.from(new Set([...(envObj.domains || []), normalizedDom]));
    }
    if (payload.protected !== undefined) {
      envObj.protected = Boolean(payload.protected);
    }
    if (payload.requireApproval !== undefined) {
      envObj.requireApproval = Boolean(payload.requireApproval);
    }
    if (payload.autoDeploy !== undefined) {
      envObj.autoDeploy = Boolean(payload.autoDeploy);
    }
    if (payload.lastRelease !== undefined) {
      if (payload.lastRelease === null) {
        envObj.lastRelease = null;
      } else if (typeof payload.lastRelease === 'object' && !Array.isArray(payload.lastRelease)) {
        envObj.lastRelease = {
          imageTag: payload.lastRelease.imageTag ? String(payload.lastRelease.imageTag).slice(0, 256) : null,
          commit: payload.lastRelease.commit ? String(payload.lastRelease.commit).slice(0, 80) : null,
          releaseId: payload.lastRelease.releaseId ? String(payload.lastRelease.releaseId).slice(0, 80) : null,
          branch: payload.lastRelease.branch ? String(payload.lastRelease.branch).slice(0, 120) : envObj.branch,
          deployedAt: payload.lastRelease.deployedAt || now,
          actor: payload.lastRelease.actor ? String(payload.lastRelease.actor).slice(0, 80) : (payload.actor || 'system')
        };
      }
    }

    if (payload.replaceEnvVars) {
      envObj.envVars = Object.create(null);
    } else if (!envObj.envVars || typeof envObj.envVars !== 'object') {
      envObj.envVars = Object.create(null);
    }

    // Clonado opcional desde otro entorno del mismo proyecto (re-cifrado con AAD del nuevo entorno)
    if (payload.cloneEnvFrom) {
      const srcSlug = assertEnvSlug(payload.cloneEnvFrom);
      const srcEnv = this.state.projects[pid].environments[srcSlug];
      if (!srcEnv) {
        throw new Error(`Entorno origen "${srcSlug}" no encontrado para clonar`);
      }
      const decryptedSrc = this._decryptEnvVarsInternal(pid, srcEnv);
      const masterKey = this._loadOrCreateKey();
      const hmacKey = this._getHmacKey();
      for (const [k, item] of Object.entries(decryptedSrc)) {
        const { fingerprint } = hashSecretValue(item.value, hmacKey);
        envObj.envVars[k] = {
          encryptedValue: encryptVaultValue(item.value, masterKey, `env:${pid}:${slug}:${k}`),
          fingerprint,
          secret: item.secret,
          scope: item.scope,
          isVaultRef: item.isVaultRef,
          vaultRefs: item.vaultRefs,
          updatedAt: now
        };
      }
    }

    if (Array.isArray(payload.unsetEnvKeys)) {
      for (const rawKey of payload.unsetEnvKeys) {
        const cleanKey = assertEnvKey(rawKey);
        delete envObj.envVars[cleanKey];
      }
    }

    if (payload.envVars !== undefined) {
      if (!payload.envVars || typeof payload.envVars !== 'object' || Array.isArray(payload.envVars)) {
        throw new Error('envVars debe ser un objeto clave-valor');
      }
      const entries = Object.entries(payload.envVars);
      if (entries.length > 0) {
        const masterKey = this._loadOrCreateKey();
        const hmacKey = this._getHmacKey();
        for (const [rawKey, rawSpec] of entries) {
          const cleanKey = assertEnvKey(rawKey);
          const isObj = rawSpec !== null && typeof rawSpec === 'object' && !Array.isArray(rawSpec);
          const rawVal = isObj ? rawSpec.value : rawSpec;
          const cleanVal = assertEnvValue(rawVal, `variable "${cleanKey}"`);
          const scope = isObj && rawSpec.scope !== undefined ? normalizeScope(rawSpec.scope) : 'both';
          const vaultRefs = extractVaultRefs(cleanVal);
          const isVaultRef = FULL_VAULT_REF_RE.test(cleanVal.trim());
          const secret = isObj && rawSpec.secret !== undefined
            ? Boolean(rawSpec.secret)
            : (isVaultRef || isLikelySecret(cleanKey, cleanVal));
          const { fingerprint } = hashSecretValue(cleanVal, hmacKey);

          envObj.envVars[cleanKey] = {
            encryptedValue: encryptVaultValue(cleanVal, masterKey, `env:${pid}:${slug}:${cleanKey}`),
            fingerprint,
            secret,
            scope,
            isVaultRef,
            vaultRefs,
            updatedAt: now
          };
        }
      }
    }

    if (Object.keys(envObj.envVars).length > MAX_ENV_VARS_PER_ENV) {
      throw new Error(`Límite máximo de variables por entorno superado (${MAX_ENV_VARS_PER_ENV})`);
    }

    envObj.updatedAt = now;
    this.state.projects[pid].environments[slug] = envObj;
    this._save();

    this._audit(existing ? 'environment.updated' : 'environment.created', `${pid}:${slug}`, {
      projectId: pid,
      envName: slug,
      branch: envObj.branch,
      serverId: envObj.serverId,
      envVarCount: Object.keys(envObj.envVars).length,
      actor: payload.actor || 'system'
    });

    const pub = this._toPublicEnvironment(pid, envObj);
    this.emit('environment_updated', pub);
    return pub;
  }

  /** Alias de conveniencia. */
  saveEnvironment(projectId, envName, payload = {}) {
    return this.upsertEnvironment(projectId, envName, payload);
  }

  /**
   * Fija o actualiza una única variable en un entorno.
   * @param {string} projectId
   * @param {string} envName
   * @param {string} key
   * @param {string} value
   * @param {{ secret?: boolean, scope?: string, actor?: string }} [opts]
   */
  setEnvironmentVar(projectId, envName, key, value, opts = {}) {
    return this.upsertEnvironment(projectId, envName, {
      envVars: {
        [key]: {
          value,
          ...(opts.secret !== undefined ? { secret: opts.secret } : {}),
          ...(opts.scope !== undefined ? { scope: opts.scope } : {})
        }
      },
      actor: opts.actor
    });
  }

  /**
   * Elimina una única variable de un entorno.
   * @param {string} projectId
   * @param {string} envName
   * @param {string} key
   * @param {{ actor?: string }} [opts]
   */
  deleteEnvironmentVar(projectId, envName, key, opts = {}) {
    this._ensureLoaded();
    const pid = assertProjectId(projectId);
    const slug = assertEnvSlug(envName);
    const envObj = this.state.projects[pid] && this.state.projects[pid].environments[slug];
    if (!envObj) throw new Error(`Entorno "${slug}" no encontrado en el proyecto "${pid}"`);
    return this.upsertEnvironment(pid, slug, { unsetEnvKeys: [key], actor: opts.actor });
  }

  /**
   * Elimina un entorno completo de un proyecto (protege entornos marcados `protected` salvo `force: true`).
   * @param {string} projectId
   * @param {string} envName
   * @param {{ force?: boolean, actor?: string }} [opts]
   */
  deleteEnvironment(projectId, envName, opts = {}) {
    this._ensureLoaded();
    const pid = assertProjectId(projectId);
    const slug = assertEnvSlug(envName);
    const envObj = this.state.projects[pid] && this.state.projects[pid].environments[slug];
    if (!envObj) {
      return { deleted: false, projectId: pid, envName: slug };
    }
    if (envObj.protected && !opts.force) {
      throw new Error(`El entorno "${slug}" está protegido; pasa force: true para eliminarlo`);
    }
    delete this.state.projects[pid].environments[slug];
    if (Object.keys(this.state.projects[pid].environments).length === 0) {
      delete this.state.projects[pid];
    }
    this._save();
    this._audit('environment.deleted', `${pid}:${slug}`, { projectId: pid, envName: slug, actor: opts.actor || 'system' });
    this.emit('environment_deleted', { projectId: pid, envName: slug });
    return { deleted: true, projectId: pid, envName: slug };
  }

  /**
   * Resuelve el mapa efectivo de variables de entorno para un proyecto y fase (`runtime` | `build` | `all`),
   * combinando entorno aislado + baseEnv/project.envVars + sustitución `${vault.KEY}`.
   *
   * @param {string} projectId
   * @param {{
   *   envName?: string | null,
   *   phase?: 'runtime' | 'build' | 'all',
   *   baseEnv?: Record<string, string> | null,
   *   projectEnvVars?: Record<string, string> | null,
   *   strict?: boolean
   * }} [opts]
   * @returns {{ env: Record<string, string>, resolvedKeys: string[], missingKeys: string[], secretValues: string[] }}
   */
  resolveEnvForProject(projectId, opts = {}) {
    this._ensureLoaded();
    const pid = assertProjectId(projectId);
    const phase = opts.phase || 'runtime';
    /** @type {Record<string, string>} */
    const merged = Object.create(null);
    /** @type {Set<string>} */
    const secretValues = new Set();

    // 1. Base env (e.g. linkedDatabaseIds injectedEnv)
    if (opts.baseEnv && typeof opts.baseEnv === 'object') {
      for (const [k, v] of Object.entries(opts.baseEnv)) {
        if (!FORBIDDEN_PROTO_KEYS.has(k) && ENV_KEY_RE.test(k)) {
          merged[k] = v == null ? '' : String(v);
        }
      }
    }

    // 2. Entorno aislado del proyecto (si se especifica o existe `production`)
    const projEntry = this.state.projects[pid];
    const targetEnvName = opts.envName
      ? assertEnvSlug(opts.envName)
      : (projEntry && projEntry.environments && projEntry.environments.production ? 'production' : null);

    if (projEntry && targetEnvName && projEntry.environments[targetEnvName]) {
      const decrypted = this._decryptEnvVarsInternal(pid, projEntry.environments[targetEnvName], { phase });
      for (const [k, item] of Object.entries(decrypted)) {
        merged[k] = item.value;
        if (item.secret && !item.isVaultRef && item.value.length >= 6) {
          secretValues.add(item.value);
        }
      }
    }

    // 3. Variables propias del proyecto (máxima precedencia, 100% retrocompatible)
    let projEnv = opts.projectEnvVars || null;
    if (!projEnv) {
      const pm = this._getProjectManager();
      const proj = pm && typeof pm.getById === 'function' ? pm.getById(pid) : null;
      if (proj && proj.envVars && typeof proj.envVars === 'object') {
        projEnv = proj.envVars;
      }
    }
    if (projEnv && typeof projEnv === 'object') {
      for (const [k, v] of Object.entries(projEnv)) {
        if (!FORBIDDEN_PROTO_KEYS.has(k) && ENV_KEY_RE.test(k)) {
          merged[k] = v == null ? '' : String(v);
        }
      }
    }

    // 4. Sustitución `${vault.KEY}` en una sola pasada
    const resolved = this.resolveEnvWithVault(merged, { strict: Boolean(opts.strict), phase });
    for (const s of resolved.secretValues) secretValues.add(s);

    return {
      env: resolved.env,
      resolvedKeys: resolved.resolvedKeys,
      missingKeys: resolved.missingKeys,
      secretValues: Array.from(secretValues)
    };
  }

  /**
   * Devuelve todos los valores secretos descifrados (>= 6 chars) asociados a un proyecto
   * para redactar logs de build/ejecución en `deployManager` y `cronManager`.
   * @param {string} projectId
   * @param {string | null} [envName]
   * @returns {string[]}
   */
  getSecretValuesForProject(projectId, envName = null) {
    try {
      const res = this.resolveEnvForProject(projectId, { envName, phase: 'all', strict: false });
      return res.secretValues;
    } catch (e) {
      return [];
    }
  }

  /**
   * Lectura interna para `gitopsManager.exportStack()`: devuelve las variables de un entorno
   * con su clasificación `secret` y referencias `${vault.KEY}` para serializar sin secretos.
   * @param {string} projectId
   * @param {string} envName
   */
  _inspectEnvironmentForExport(projectId, envName) {
    this._ensureLoaded();
    const pid = assertProjectId(projectId);
    const slug = assertEnvSlug(envName);
    const envObj = this.state.projects[pid] && this.state.projects[pid].environments[slug];
    if (!envObj) return null;
    const decrypted = this._decryptEnvVarsInternal(pid, envObj);
    return {
      name: envObj.name,
      branch: envObj.branch,
      domains: Array.isArray(envObj.domains) ? [...envObj.domains] : [],
      serverId: envObj.serverId || 'local',
      protected: Boolean(envObj.protected),
      requireApproval: Boolean(envObj.requireApproval),
      autoDeploy: envObj.autoDeploy !== false,
      envVars: decrypted
    };
  }

  // =========================================================================
  // 3. ZERO-LEAK HASH-ONLY ENVIRONMENT DIFF
  // =========================================================================

  /**
   * Compara dos entornos de un mismo proyecto usando EXCLUSIVAMENTE hashes HMAC-SHA256.
   * Jamás incluye valores en claro de variables ni secretos en la respuesta.
   *
   * @param {string} projectId
   * @param {string} fromEnv
   * @param {string} toEnv
   */
  diffEnvironments(projectId, fromEnv, toEnv) {
    this._ensureLoaded();
    const pid = assertProjectId(projectId);
    const srcSlug = assertEnvSlug(fromEnv);
    const dstSlug = assertEnvSlug(toEnv);

    const projEntry = this.state.projects[pid];
    const src = projEntry && projEntry.environments[srcSlug];
    const dst = projEntry && projEntry.environments[dstSlug];
    if (!src) throw new Error(`Entorno origen "${srcSlug}" no encontrado en el proyecto "${pid}"`);
    if (!dst) throw new Error(`Entorno destino "${dstSlug}" no encontrado en el proyecto "${pid}"`);

    const srcDec = this._decryptEnvVarsInternal(pid, src);
    const dstDec = this._decryptEnvVarsInternal(pid, dst);
    const hmacKey = this._getHmacKey();

    const allKeys = Array.from(new Set([...Object.keys(srcDec), ...Object.keys(dstDec)])).sort();

    /** @type {Array<{ key: string, fromHash: string, fromFingerprint: string, scope: string, secret: boolean, isVaultRef: boolean }>} */
    const added = [];
    /** @type {Array<{ key: string, toHash: string, toFingerprint: string, scope: string, secret: boolean, isVaultRef: boolean }>} */
    const removed = [];
    /** @type {Array<{ key: string, fromHash: string, toHash: string, fromFingerprint: string, toFingerprint: string, scopeChanged: boolean, fromScope: string, toScope: string, secret: boolean }>} */
    const changed = [];
    /** @type {string[]} */
    const unchanged = [];

    for (const key of allKeys) {
      const a = srcDec[key];
      const b = dstDec[key];
      if (a && !b) {
        const ha = hashSecretValue(a.value, hmacKey);
        added.push({
          key,
          fromHash: ha.sha256,
          fromFingerprint: ha.fingerprint,
          scope: a.scope,
          secret: a.secret,
          isVaultRef: a.isVaultRef
        });
      } else if (!a && b) {
        const hb = hashSecretValue(b.value, hmacKey);
        removed.push({
          key,
          toHash: hb.sha256,
          toFingerprint: hb.fingerprint,
          scope: b.scope,
          secret: b.secret,
          isVaultRef: b.isVaultRef
        });
      } else if (a && b) {
        const ha = hashSecretValue(a.value, hmacKey);
        const hb = hashSecretValue(b.value, hmacKey);
        const valueEqual = crypto.timingSafeEqual(Buffer.from(ha.sha256, 'hex'), Buffer.from(hb.sha256, 'hex'));
        const scopeChanged = a.scope !== b.scope;
        if (!valueEqual || scopeChanged) {
          changed.push({
            key,
            fromHash: ha.sha256,
            toHash: hb.sha256,
            fromFingerprint: ha.fingerprint,
            toFingerprint: hb.fingerprint,
            scopeChanged,
            fromScope: a.scope,
            toScope: b.scope,
            secret: a.secret || b.secret
          });
        } else {
          unchanged.push(key);
        }
      }
    }

    const srcReleaseTag = (src.lastRelease && (src.lastRelease.imageTag || src.lastRelease.releaseId || src.lastRelease.commit)) || null;
    const dstReleaseTag = (dst.lastRelease && (dst.lastRelease.imageTag || dst.lastRelease.releaseId || dst.lastRelease.commit)) || null;

    const metadataDiff = {
      branch: { from: src.branch, to: dst.branch, changed: src.branch !== dst.branch },
      serverId: { from: src.serverId || 'local', to: dst.serverId || 'local', changed: (src.serverId || 'local') !== (dst.serverId || 'local') },
      domains: {
        from: Array.isArray(src.domains) ? [...src.domains] : [],
        to: Array.isArray(dst.domains) ? [...dst.domains] : [],
        changed: JSON.stringify(src.domains || []) !== JSON.stringify(dst.domains || [])
      },
      release: {
        from: src.lastRelease ? { ...src.lastRelease } : null,
        to: dst.lastRelease ? { ...dst.lastRelease } : null,
        changed: srcReleaseTag !== dstReleaseTag
      }
    };

    const hasChanges = added.length > 0 || removed.length > 0 || changed.length > 0 || metadataDiff.release.changed;

    return {
      projectId: pid,
      fromEnv: srcSlug,
      toEnv: dstSlug,
      hashAlgorithm: 'hmac-sha256',
      added,
      removed,
      changed,
      unchanged,
      unchangedCount: unchanged.length,
      onlyInFrom: added.map((x) => x.key),
      onlyInTo: removed.map((x) => x.key),
      changedKeys: changed.map((x) => x.key),
      metadataDiff,
      hasChanges
    };
  }

  // =========================================================================
  // 4. PROMOTION PIPELINE + PRE-PROMOTION SNAPSHOT + ROLLBACK
  // =========================================================================

  /**
   * Crea una instantánea completa del estado actual de un entorno (variables cifradas intactas).
   * @param {any} envObj
   * @param {{ reason: string, actor: string, fromEnv?: string | null }} meta
   */
  _captureSnapshot(envObj, meta) {
    const snapshotId = `snap_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`;
    /** @type {Record<string, any>} */
    const envVarsCopy = Object.create(null);
    for (const [k, rec] of Object.entries(envObj.envVars || {})) {
      if (FORBIDDEN_PROTO_KEYS.has(k) || !rec) continue;
      envVarsCopy[k] = {
        encryptedValue: rec.encryptedValue,
        fingerprint: rec.fingerprint,
        secret: Boolean(rec.secret),
        scope: rec.scope || 'both',
        isVaultRef: Boolean(rec.isVaultRef),
        vaultRefs: Array.isArray(rec.vaultRefs) ? [...rec.vaultRefs] : [],
        updatedAt: rec.updatedAt
      };
    }

    const snap = {
      id: snapshotId,
      createdAt: new Date().toISOString(),
      reason: String(meta.reason || 'pre-promotion').slice(0, 200),
      actor: String(meta.actor || 'system').slice(0, 80),
      fromEnv: meta.fromEnv || null,
      toEnv: envObj.name,
      branch: envObj.branch,
      domains: Array.isArray(envObj.domains) ? [...envObj.domains] : [],
      serverId: envObj.serverId || 'local',
      lastRelease: envObj.lastRelease ? { ...envObj.lastRelease } : null,
      envVars: envVarsCopy
    };

    if (!Array.isArray(envObj.snapshots)) envObj.snapshots = [];
    envObj.snapshots.push(snap);
    if (envObj.snapshots.length > MAX_SNAPSHOTS_PER_ENV) {
      envObj.snapshots = envObj.snapshots.slice(-MAX_SNAPSHOTS_PER_ENV);
    }
    return snap;
  }

  /**
   * Evalúa puertas de despliegue (ventanas de congelación vía `deployManager` + aprobaciones).
   * @param {string} projectId
   * @param {{ env?: string, fromEnv?: string, actor?: string, overrideFreeze?: boolean, approvalId?: string | null }} [opts]
   */
  evaluateDeployGate(projectId, opts = {}) {
    this._ensureLoaded();
    const pid = assertProjectId(projectId);
    const targetEnv = opts.env ? assertEnvSlug(opts.env) : null;
    const overrideFreeze = Boolean(opts.overrideFreeze);

    // 1. Freeze window check (delegado a deployManager.evaluateFreezeStatus como fuente única de verdad)
    /** @type {any} */
    let freezeStatus = null;
    try {
      const dm = this._getDeployManager();
      const pm = this._getProjectManager();
      const proj = pm && typeof pm.getById === 'function' ? pm.getById(pid) : null;
      if (dm && typeof dm.evaluateFreezeStatus === 'function') {
        freezeStatus = dm.evaluateFreezeStatus(proj || { id: pid }, new Date());
      }
    } catch (e) {}

    if (freezeStatus && freezeStatus.frozen && !overrideFreeze) {
      return {
        allowed: false,
        blockedBy: 'freeze',
        freezeWindow: freezeStatus.window || freezeStatus,
        approvalId: null,
        reason: freezeStatus.reason || 'Ventana de congelación de despliegues activa'
      };
    }

    // 2. Approval gate check si el entorno destino tiene `requireApproval: true`
    const envObj = targetEnv && this.state.projects[pid] && this.state.projects[pid].environments[targetEnv];
    if (envObj && envObj.requireApproval) {
      const approval = opts.approvalId
        ? this.state.approvals.find((a) => a.id === opts.approvalId)
        : null;
      const nowMs = Date.now();
      const validApproval = Boolean(
        approval &&
        approval.status === 'approved' &&
        !approval.consumedAt &&
        approval.projectId === pid &&
        approval.toEnv === targetEnv &&
        (!opts.fromEnv || approval.fromEnv === opts.fromEnv) &&
        (!approval.expiresAt || Date.parse(approval.expiresAt) > nowMs)
      );
      if (!validApproval) {
        return {
          allowed: false,
          blockedBy: 'approval',
          freezeWindow: null,
          approvalId: opts.approvalId || null,
          reason: `El entorno "${targetEnv}" requiere aprobación previa para promocionar`
        };
      }
    }

    return {
      allowed: true,
      blockedBy: null,
      freezeWindow: freezeStatus && freezeStatus.frozen ? freezeStatus : null,
      approvalId: opts.approvalId || null,
      overrideUsed: Boolean(freezeStatus && freezeStatus.frozen && overrideFreeze)
    };
  }

  /**
   * Promociona una release (y opcionalmente variables de entorno) de `fromEnv` -> `toEnv`.
   * Captura automáticamente una instantánea previa en `toEnv` para permitir rollback inmediato.
   *
   * @param {string} projectId
   * @param {{
   *   fromEnv: string,
   *   toEnv: string,
   *   includeEnvVars?: boolean,
   *   envKeys?: string[] | null,
   *   dryRun?: boolean,
   *   actor?: string,
   *   overrideFreeze?: boolean,
   *   approvalId?: string | null,
   *   reason?: string
   * }} opts
   */
  promoteEnvironment(projectId, opts) {
    this._ensureLoaded();
    if (!opts || typeof opts !== 'object') {
      throw new Error('Opciones de promoción obligatorias ({ fromEnv, toEnv })');
    }
    const pid = assertProjectId(projectId);
    const fromEnv = assertEnvSlug(opts.fromEnv);
    const toEnv = assertEnvSlug(opts.toEnv);
    if (fromEnv === toEnv) {
      throw new Error('El entorno origen y destino no pueden ser el mismo');
    }

    const projEntry = this.state.projects[pid];
    const src = projEntry && projEntry.environments[fromEnv];
    const dst = projEntry && projEntry.environments[toEnv];
    if (!src) throw new Error(`Entorno origen "${fromEnv}" no encontrado en el proyecto "${pid}"`);
    if (!dst) throw new Error(`Entorno destino "${toEnv}" no encontrado en el proyecto "${pid}"`);

    const includeEnvVars = Boolean(opts.includeEnvVars);
    const dryRun = Boolean(opts.dryRun);
    const actor = String(opts.actor || 'system').slice(0, 80);
    const reason = String(opts.reason || '').slice(0, 200);

    const diff = this.diffEnvironments(pid, fromEnv, toEnv);
    const gate = this.evaluateDeployGate(pid, {
      env: toEnv,
      fromEnv,
      actor,
      overrideFreeze: Boolean(opts.overrideFreeze),
      approvalId: opts.approvalId || null
    });

    /** @type {string[]} */
    const blockers = [];
    /** @type {string[]} */
    const warnings = [];
    if (!gate.allowed) {
      blockers.push(gate.blockedBy === 'freeze' ? 'DEPLOY_FREEZE_ACTIVE' : 'APPROVAL_REQUIRED');
    }
    if (gate.overrideUsed) {
      warnings.push('Se aplicó overrideFreeze sobre una ventana de congelación activa');
    }

    // Determinar claves de entorno a promocionar
    const srcDec = includeEnvVars ? this._decryptEnvVarsInternal(pid, src) : Object.create(null);
    /** @type {string[]} */
    let keysToPromote = [];
    if (includeEnvVars) {
      if (Array.isArray(opts.envKeys) && opts.envKeys.length > 0) {
        for (const rk of opts.envKeys) {
          const cleanKey = assertEnvKey(rk);
          if (!srcDec[cleanKey]) {
            warnings.push(`Clave "${cleanKey}" no existe en "${fromEnv}" y se omitirá`);
          } else {
            keysToPromote.push(cleanKey);
          }
        }
      } else {
        keysToPromote = Object.keys(srcDec).sort();
      }
    }

    // Resolver metadatos de la release inmutable a promocionar
    let sourceRelease = src.lastRelease ? { ...src.lastRelease } : null;
    if (!sourceRelease) {
      try {
        const dm = this._getDeployManager();
        const cur = dm && dm.store && dm.store[pid] && dm.store[pid].current;
        if (cur && cur.imageTag) {
          sourceRelease = {
            imageTag: cur.imageTag,
            commit: cur.commit || null,
            releaseId: cur.deploymentId || null,
            branch: src.branch
          };
        }
      } catch (e) {}
    }

    if (dryRun) {
      return {
        ok: blockers.length === 0,
        dryRun: true,
        projectId: pid,
        fromEnv,
        toEnv,
        includeEnvVars,
        promotedKeys: keysToPromote,
        wouldPromoteRelease: sourceRelease,
        diff,
        gate,
        blockers,
        warnings,
        snapshotId: null
      };
    }

    if (!gate.allowed) {
      const err = new Error(gate.reason || `Promoción bloqueada (${gate.blockedBy})`);
      /** @type {any} */ (err).code = gate.blockedBy === 'freeze' ? 'DEPLOY_FREEZE_ACTIVE' : 'APPROVAL_REQUIRED';
      /** @type {any} */ (err).status = 409;
      throw err;
    }

    if (gate.overrideUsed) {
      this._audit('environment.freeze_override', `${pid}:${toEnv}`, { projectId: pid, fromEnv, toEnv, actor, reason });
      try {
        const ns = this._getNotificationService();
        if (ns && typeof ns.notify === 'function') {
          ns.notify({ event: 'deploy_frozen', projectId: pid, actor, message: `Override de congelación al promocionar ${fromEnv} -> ${toEnv}` });
        }
      } catch (e) {}
    }

    // Consumir aprobación de un solo uso si aplicaba
    if (dst.requireApproval && opts.approvalId) {
      const approval = this.state.approvals.find((a) => a.id === opts.approvalId);
      if (approval) {
        approval.consumedAt = new Date().toISOString();
        approval.status = 'consumed';
      }
    }

    // 1. Instantánea automática previa en destino (permite rollbackPromotion exacto)
    const snapshot = this._captureSnapshot(dst, {
      reason: reason || `Pre-promoción desde ${fromEnv}`,
      actor,
      fromEnv
    });

    const now = new Date().toISOString();

    // 2. Promocionar variables de entorno (re-cifradas con AAD del entorno destino)
    if (includeEnvVars && keysToPromote.length > 0) {
      const masterKey = this._loadOrCreateKey();
      const hmacKey = this._getHmacKey();
      if (!dst.envVars || typeof dst.envVars !== 'object') {
        dst.envVars = Object.create(null);
      }
      for (const k of keysToPromote) {
        const item = srcDec[k];
        const { fingerprint } = hashSecretValue(item.value, hmacKey);
        dst.envVars[k] = {
          encryptedValue: encryptVaultValue(item.value, masterKey, `env:${pid}:${toEnv}:${k}`),
          fingerprint,
          secret: item.secret,
          scope: item.scope,
          isVaultRef: item.isVaultRef,
          vaultRefs: item.vaultRefs,
          updatedAt: now
        };
      }
    }

    // 3. Promocionar artefacto/release inmutable
    const promotedRelease = sourceRelease
      ? {
          ...sourceRelease,
          promotedFrom: fromEnv,
          promotedAt: now,
          promotedBy: actor,
          snapshotId: snapshot.id
        }
      : {
          imageTag: null,
          commit: null,
          releaseId: `rel_${Date.now().toString(36)}`,
          branch: src.branch,
          promotedFrom: fromEnv,
          promotedAt: now,
          promotedBy: actor,
          snapshotId: snapshot.id
        };

    dst.lastRelease = promotedRelease;
    dst.updatedAt = now;

    const promotionId = `prom_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`;
    const historyEntry = {
      id: promotionId,
      type: 'promote',
      fromEnv,
      toEnv,
      snapshotId: snapshot.id,
      includeEnvVars,
      promotedKeys: keysToPromote,
      promotedKeyCount: keysToPromote.length,
      release: promotedRelease,
      actor,
      reason,
      status: 'promoted',
      at: now
    };
    if (!Array.isArray(dst.promotionHistory)) dst.promotionHistory = [];
    dst.promotionHistory.push(historyEntry);
    if (dst.promotionHistory.length > MAX_PROMOTION_HISTORY) {
      dst.promotionHistory = dst.promotionHistory.slice(-MAX_PROMOTION_HISTORY);
    }

    this._save();
    this._audit('environment.promoted', `${pid}:${toEnv}`, {
      promotionId,
      projectId: pid,
      fromEnv,
      toEnv,
      snapshotId: snapshot.id,
      includeEnvVars,
      promotedKeyCount: keysToPromote.length,
      actor
    });

    const result = {
      ok: true,
      dryRun: false,
      promotionId,
      snapshotId: snapshot.id,
      projectId: pid,
      fromEnv,
      toEnv,
      includeEnvVars,
      promotedKeys: keysToPromote,
      release: promotedRelease,
      diff,
      warnings,
      target: this._toPublicEnvironment(pid, dst)
    };
    this.emit('environment_promoted', result);
    return result;
  }

  /**
   * Lista las instantáneas de rollback disponibles para un entorno (sin valores secretos).
   * @param {string} projectId
   * @param {string} envName
   */
  listSnapshots(projectId, envName) {
    this._ensureLoaded();
    const pid = assertProjectId(projectId);
    const slug = assertEnvSlug(envName);
    const envObj = this.state.projects[pid] && this.state.projects[pid].environments[slug];
    if (!envObj) throw new Error(`Entorno "${slug}" no encontrado en el proyecto "${pid}"`);
    return (envObj.snapshots || []).map((s) => ({
      id: s.id,
      createdAt: s.createdAt,
      reason: s.reason,
      actor: s.actor,
      fromEnv: s.fromEnv,
      toEnv: s.toEnv,
      branch: s.branch,
      serverId: s.serverId,
      domains: Array.isArray(s.domains) ? [...s.domains] : [],
      lastRelease: s.lastRelease ? { ...s.lastRelease } : null,
      envKeyCount: s.envVars ? Object.keys(s.envVars).length : 0,
      envKeys: s.envVars ? Object.keys(s.envVars).sort() : []
    }));
  }

  /**
   * Revierte un entorno exactamente al estado capturado en `snapshotId` (o a la última
   * instantánea previa a la promoción si se omite `snapshotId`).
   *
   * @param {string} projectId
   * @param {string} envName
   * @param {string | null} [snapshotId]
   * @param {{ actor?: string, reason?: string }} [opts]
   */
  rollbackPromotion(projectId, envName, snapshotId = null, opts = {}) {
    this._ensureLoaded();
    const pid = assertProjectId(projectId);
    const slug = assertEnvSlug(envName);
    const envObj = this.state.projects[pid] && this.state.projects[pid].environments[slug];
    if (!envObj) throw new Error(`Entorno "${slug}" no encontrado en el proyecto "${pid}"`);

    const snapshots = Array.isArray(envObj.snapshots) ? envObj.snapshots : [];
    if (snapshots.length === 0) {
      throw new Error(`No hay instantáneas disponibles para revertir el entorno "${slug}"`);
    }

    const snap = snapshotId
      ? snapshots.find((s) => s.id === snapshotId)
      : snapshots[snapshots.length - 1];
    if (!snap) {
      throw new Error(`Instantánea "${snapshotId}" no encontrada en el entorno "${slug}"`);
    }

    // Verificar integridad criptográfica (AAD de proyecto + entorno) antes de aplicar el rollback
    const masterKey = this._loadOrCreateKey();
    for (const [k, rec] of Object.entries(snap.envVars || {})) {
      if (FORBIDDEN_PROTO_KEYS.has(k) || !rec) continue;
      decryptVaultValue(rec.encryptedValue, masterKey, `env:${pid}:${slug}:${k}`);
    }

    const actor = String(opts.actor || 'system').slice(0, 80);
    const reason = String(opts.reason || `Rollback a ${snap.id}`).slice(0, 200);

    // Capturar instantánea pre-rollback para que el rollback también sea reversible
    const preRollbackSnap = this._captureSnapshot(envObj, {
      reason: `Pre-rollback (antes de restaurar ${snap.id})`,
      actor,
      fromEnv: slug
    });

    /** @type {Record<string, any>} */
    const restoredEnvVars = Object.create(null);
    for (const [k, rec] of Object.entries(snap.envVars || {})) {
      if (FORBIDDEN_PROTO_KEYS.has(k) || !rec) continue;
      restoredEnvVars[k] = {
        ...rec,
        vaultRefs: Array.isArray(rec.vaultRefs) ? [...rec.vaultRefs] : []
      };
    }

    envObj.envVars = restoredEnvVars;
    envObj.branch = snap.branch;
    envObj.domains = Array.isArray(snap.domains) ? [...snap.domains] : [];
    envObj.serverId = snap.serverId || 'local';
    envObj.lastRelease = snap.lastRelease ? { ...snap.lastRelease } : null;
    envObj.updatedAt = new Date().toISOString();

    const rollbackId = `rbk_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`;
    if (!Array.isArray(envObj.promotionHistory)) envObj.promotionHistory = [];
    envObj.promotionHistory.push({
      id: rollbackId,
      type: 'rollback',
      fromEnv: null,
      toEnv: slug,
      snapshotId: snap.id,
      preRollbackSnapshotId: preRollbackSnap.id,
      release: envObj.lastRelease,
      actor,
      reason,
      status: 'rolled_back',
      at: envObj.updatedAt
    });
    if (envObj.promotionHistory.length > MAX_PROMOTION_HISTORY) {
      envObj.promotionHistory = envObj.promotionHistory.slice(-MAX_PROMOTION_HISTORY);
    }

    this._save();
    this._audit('environment.rolled_back', `${pid}:${slug}`, {
      rollbackId,
      projectId: pid,
      envName: slug,
      restoredSnapshotId: snap.id,
      preRollbackSnapshotId: preRollbackSnap.id,
      actor
    });

    const result = {
      ok: true,
      rollbackId,
      projectId: pid,
      envName: slug,
      restoredSnapshotId: snap.id,
      preRollbackSnapshotId: preRollbackSnap.id,
      environment: this._toPublicEnvironment(pid, envObj)
    };
    this.emit('environment_rolled_back', result);
    return result;
  }

  // =========================================================================
  // 5. APPROVAL GATES & OPTIONAL ENVIRONMENT GROUPS
  // =========================================================================

  /**
   * Crea una solicitud de aprobación de un solo uso con TTL (por defecto 24h).
   * @param {{ projectId: string, fromEnv: string, toEnv: string, requestedBy?: string, reason?: string, ttlHours?: number }} opts
   */
  createApprovalRequest(opts) {
    this._ensureLoaded();
    const pid = assertProjectId(opts.projectId);
    const fromEnv = assertEnvSlug(opts.fromEnv);
    const toEnv = assertEnvSlug(opts.toEnv);
    const ttlHours = Math.min(168, Math.max(1, Number(opts.ttlHours) || 24));
    const now = Date.now();
    const approval = {
      id: `apr_${now.toString(36)}_${crypto.randomBytes(4).toString('hex')}`,
      projectId: pid,
      fromEnv,
      toEnv,
      requestedBy: String(opts.requestedBy || 'system').slice(0, 80),
      reason: String(opts.reason || '').slice(0, 240),
      status: 'pending',
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + ttlHours * 3600 * 1000).toISOString(),
      decidedAt: null,
      decidedBy: null,
      consumedAt: null
    };
    this.state.approvals.push(approval);
    if (this.state.approvals.length > MAX_APPROVALS) {
      this.state.approvals = this.state.approvals.slice(-MAX_APPROVALS);
    }
    this._save();
    return { ...approval };
  }

  /**
   * Aprueba una solicitud de promoción pendiente (bloquea auto-aprobación por defecto).
   * @param {string} approvalId
   * @param {{ actor?: string, allowSelfApprove?: boolean }} [opts]
   */
  approveRequest(approvalId, opts = {}) {
    this._ensureLoaded();
    const approval = this.state.approvals.find((a) => a.id === approvalId);
    if (!approval) throw new Error('Solicitud de aprobación no encontrada');
    if (approval.status !== 'pending') {
      throw new Error(`La solicitud ya está en estado "${approval.status}"`);
    }
    if (Date.parse(approval.expiresAt) <= Date.now()) {
      approval.status = 'expired';
      this._save();
      throw new Error('La solicitud de aprobación ha caducado');
    }
    const actor = String(opts.actor || 'admin').slice(0, 80);
    if (!opts.allowSelfApprove && approval.requestedBy && actor === approval.requestedBy && actor !== 'system') {
      throw new Error('No se permite auto-aprobar la propia solicitud de promoción');
    }
    approval.status = 'approved';
    approval.decidedBy = actor;
    approval.decidedAt = new Date().toISOString();
    this._save();
    this._audit('environment.approval_approved', approval.id, { projectId: approval.projectId, toEnv: approval.toEnv, actor });
    return { ...approval };
  }

  /**
   * Rechaza una solicitud de aprobación pendiente.
   * @param {string} approvalId
   * @param {{ actor?: string, reason?: string }} [opts]
   */
  rejectRequest(approvalId, opts = {}) {
    this._ensureLoaded();
    const approval = this.state.approvals.find((a) => a.id === approvalId);
    if (!approval) throw new Error('Solicitud de aprobación no encontrada');
    if (approval.status !== 'pending') {
      throw new Error(`La solicitud ya está en estado "${approval.status}"`);
    }
    approval.status = 'rejected';
    approval.decidedBy = String(opts.actor || 'admin').slice(0, 80);
    approval.decidedAt = new Date().toISOString();
    if (opts.reason) approval.rejectReason = String(opts.reason).slice(0, 240);
    this._save();
    this._audit('environment.approval_rejected', approval.id, { projectId: approval.projectId, toEnv: approval.toEnv, actor: approval.decidedBy });
    return { ...approval };
  }

  /**
   * Lista solicitudes de aprobación filtradas opcionalmente por proyecto o estado.
   * @param {{ projectId?: string, status?: string }} [filter]
   */
  listApprovals(filter = {}) {
    this._ensureLoaded();
    const now = Date.now();
    return this.state.approvals
      .map((a) => {
        const status = a.status === 'pending' && Date.parse(a.expiresAt) <= now ? 'expired' : a.status;
        return { ...a, status };
      })
      .filter((a) => (!filter.projectId || a.projectId === filter.projectId) && (!filter.status || a.status === filter.status));
  }

  /**
   * Crea un grupo de entornos que enlaza distintos projectIds bajo un mismo flujo (opcional, spec #13).
   * @param {{ name: string, envs?: Record<string, string>, teamId?: string }} opts
   */
  createGroup({ name, envs = {}, teamId = 'team_default' }) {
    this._ensureLoaded();
    const cleanName = String(name || '').replace(/[\x00-\x1f\x7f<>]/g, '').trim().slice(0, 80);
    if (!cleanName) throw new Error('El nombre del grupo de entornos es obligatorio');
    /** @type {Record<string, string>} */
    const cleanEnvs = {};
    for (const [envName, pid] of Object.entries(envs || {})) {
      cleanEnvs[assertEnvSlug(envName)] = assertProjectId(pid);
    }
    const id = `envgrp_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`;
    const now = new Date().toISOString();
    const group = { id, name: cleanName, teamId: String(teamId || 'team_default'), envs: cleanEnvs, createdAt: now, updatedAt: now };
    this.state.groups[id] = group;
    this._save();
    return { ...group, envs: { ...group.envs } };
  }

  listGroups() {
    this._ensureLoaded();
    return Object.values(this.state.groups).map((g) => ({ ...g, envs: { ...g.envs } }));
  }

  deleteGroup(groupId) {
    this._ensureLoaded();
    if (!this.state.groups[groupId]) return { deleted: false, id: groupId };
    delete this.state.groups[groupId];
    this._save();
    return { deleted: true, id: groupId };
  }
}

const instance = Object.assign(new EnvironmentManager(), {
  EnvironmentManager,
  encryptVaultValue,
  decryptVaultValue,
  deriveFingerprintKey,
  hashSecretValue,
  extractVaultRefs,
  isLikelySecret,
  assertEnvSlug,
  assertEnvKey,
  ENV_SLUG_RE,
  ENV_KEY_RE,
  VAULT_REF_RE
});

module.exports = instance;
