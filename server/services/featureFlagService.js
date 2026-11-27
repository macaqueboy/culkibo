const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Native Declarative Feature Flags & Instant Kill-Switch Engine (Zero-Dep).
 *
 * Inspirado en CNCF OpenFeature, Unleash y Flagsmith:
 *  - Bucketing determinista SHA-256 (`0.00..99.99%`) sin dependencias externas.
 *  - Precedencia estricta: `FLAG_NOT_FOUND` → `KILL_SWITCH_ACTIVE` → `FLAG_DISABLED` →
 *    `ENV_MISMATCH` → `TENANT_DENIED` (deny siempre gana sobre allow) → `TENANT_ALLOWED` →
 *    `ROLLOUT_MATCH` / `ROLLOUT_EXCLUDED`.
 *  - Kill-switch atómico instantáneo (`killFlag`) sin necesidad de redeploy.
 *  - Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/feature-flags.json`.
 */

const FLAG_KEY_RE = /^[a-z0-9][a-z0-9._-]{0,79}$/i;

/**
 * @typedef {object} FeatureFlagRecord
 * @property {string} key
 * @property {string} description
 * @property {boolean} enabled
 * @property {boolean} killed
 * @property {string | null} killReason
 * @property {string | null} killedBy
 * @property {string | null} killedAt
 * @property {number} rolloutPct
 * @property {string} environment
 * @property {string[]} allowTenants
 * @property {string[]} denyTenants
 * @property {Record<string, any>} payload
 * @property {string} salt
 * @property {string} updatedAt
 */

/**
 * Resuelve dinámicamente la ruta a `feature-flags.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'feature-flags.json')
    : path.join(base, 'data', 'feature-flags.json');
}

/**
 * Escritura atómica con permisos `0o600`.
 * @param {string} targetPath
 * @param {string} content
 */
function atomicWriteFileSync(targetPath, content) {
  const dir = path.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = `${targetPath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(tmpPath, content, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmpPath, targetPath);
    try { fs.chmodSync(targetPath, 0o600); } catch (e) {}
  } catch (err) {
    try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e) {}
    throw err;
  }
}

/**
 * @param {string} code
 * @param {string} msg
 * @param {number} [status]
 */
function flagError(code, msg, status = 400) {
  const err = /** @type {any} */ (new Error(msg));
  err.code = code;
  err.status = status;
  return err;
}

/**
 * Carga el store desde disco (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, flags: Record<string, FeatureFlagRecord> }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), flags: {} };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && parsed.flags && typeof parsed.flags === 'object') {
      return parsed;
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), flags: {} };
}

/**
 * Guarda el store de forma atómica (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, flags: Record<string, FeatureFlagRecord> }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Calcula un bucket determinista en el rango `0.00..99.99` vía SHA-256 `readUInt32BE(0) % 10000 / 100`.
 *
 * @param {string} flagKey
 * @param {string} subjectId
 * @param {string} [salt]
 * @returns {number}
 */
function computeDeterministicBucket(flagKey, subjectId, salt = '') {
  const digest = crypto
    .createHash('sha256')
    .update(`${String(flagKey || '')}:${String(salt || '')}:${String(subjectId || '')}`, 'utf8')
    .digest();
  return (digest.readUInt32BE(0) % 10000) / 100;
}

/**
 * Normaliza una lista de IDs de tenants (deduplicados y recortados).
 * @param {any} list
 * @returns {string[]}
 */
function normalizeTenantList(list) {
  if (!Array.isArray(list)) return [];
  return Array.from(new Set(list.map((t) => String(t || '').trim()).filter(Boolean)));
}

/**
 * Crea o actualiza una feature flag declarativa.
 *
 * @param {{
 *   key: string,
 *   description?: string,
 *   enabled?: boolean,
 *   rolloutPct?: number,
 *   environment?: string,
 *   allowTenants?: string[],
 *   denyTenants?: string[],
 *   payload?: Record<string, any>,
 *   salt?: string,
 *   killed?: boolean
 * }} input
 */
function saveFlag(input) {
  if (!input || typeof input !== 'object') {
    throw flagError('INVALID_FLAG_PAYLOAD', 'Feature flag object is required.', 400);
  }
  const key = String(input.key || '').trim();
  if (!FLAG_KEY_RE.test(key)) {
    throw flagError('INVALID_FLAG_KEY', `Invalid feature flag key "${key}".`, 400);
  }

  const rawPct = Number(input.rolloutPct);
  const rolloutPct = Number.isFinite(rawPct) ? Math.max(0, Math.min(100, rawPct)) : 0;
  const environment = String(input.environment || 'prod').trim().toLowerCase() || 'prod';
  const enabled = input.enabled !== undefined ? Boolean(input.enabled) : true;
  const killed = Boolean(input.killed);

  const store = loadStore();
  const prev = store.flags[key];

  /** @type {FeatureFlagRecord} */
  const record = {
    key,
    description: String(input.description !== undefined ? input.description : (prev ? prev.description : '')),
    enabled: killed ? false : enabled,
    killed,
    killReason: killed ? (prev && prev.killReason ? prev.killReason : 'manual_kill') : null,
    killedBy: killed ? (prev && prev.killedBy ? prev.killedBy : 'admin') : null,
    killedAt: killed ? (prev && prev.killedAt ? prev.killedAt : new Date().toISOString()) : null,
    rolloutPct,
    environment,
    allowTenants: normalizeTenantList(input.allowTenants),
    denyTenants: normalizeTenantList(input.denyTenants),
    payload: (input.payload && typeof input.payload === 'object' && !Array.isArray(input.payload))
      ? { ...input.payload }
      : {},
    salt: String(input.salt || ''),
    updatedAt: new Date().toISOString()
  };

  store.flags[key] = record;
  saveStore(store);

  return {
    ok: true,
    flag: record
  };
}

/**
 * Lista todas las feature flags ordenadas alfabéticamente por `key`.
 * @returns {FeatureFlagRecord[]}
 */
function listFlags() {
  const store = loadStore();
  return Object.values(store.flags).sort((a, b) => a.key.localeCompare(b.key));
}

/**
 * Evalúa una feature flag para `(key, subjectId, tenantId, environment)` aplicando la
 * precedencia exacta:
 * `FLAG_NOT_FOUND` → `KILL_SWITCH_ACTIVE` → `FLAG_DISABLED` → `ENV_MISMATCH` →
 * `TENANT_DENIED` → `TENANT_ALLOWED` → `ROLLOUT_MATCH` / `ROLLOUT_EXCLUDED`.
 *
 * @param {{
 *   key: string,
 *   subjectId?: string,
 *   tenantId?: string | null,
 *   environment?: string
 * }} input
 */
function evaluateFlag(input) {
  const opts = input || /** @type {any} */ ({});
  const key = String(opts.key || '').trim();
  const subjectId = String(opts.subjectId || 'anonymous');
  const tenantId = opts.tenantId !== undefined && opts.tenantId !== null
    ? String(opts.tenantId).trim()
    : null;
  const environment = String(opts.environment || 'prod').trim().toLowerCase() || 'prod';

  const store = loadStore();
  const flag = store.flags[key] || null;
  const bucket = computeDeterministicBucket(key, subjectId, flag ? flag.salt : '');

  if (!flag) {
    return {
      ok: true,
      key,
      enabled: false,
      reason: 'FLAG_NOT_FOUND',
      bucket,
      variant: 'off',
      payload: {}
    };
  }

  if (flag.killed) {
    return {
      ok: true,
      key,
      enabled: false,
      reason: 'KILL_SWITCH_ACTIVE',
      bucket,
      variant: 'killed',
      payload: {}
    };
  }

  if (!flag.enabled) {
    return {
      ok: true,
      key,
      enabled: false,
      reason: 'FLAG_DISABLED',
      bucket,
      variant: 'off',
      payload: {}
    };
  }

  if (flag.environment && flag.environment !== '*' && flag.environment !== environment) {
    return {
      ok: true,
      key,
      enabled: false,
      reason: 'ENV_MISMATCH',
      bucket,
      variant: 'off',
      payload: {}
    };
  }

  // Deny overrides allow unconditionally
  if (tenantId && flag.denyTenants.includes(tenantId)) {
    return {
      ok: true,
      key,
      enabled: false,
      reason: 'TENANT_DENIED',
      bucket,
      variant: 'off',
      payload: {}
    };
  }

  if (tenantId && flag.allowTenants.includes(tenantId)) {
    return {
      ok: true,
      key,
      enabled: true,
      reason: 'TENANT_ALLOWED',
      bucket,
      variant: 'on',
      payload: { ...(flag.payload || {}) }
    };
  }

  if (bucket < flag.rolloutPct) {
    return {
      ok: true,
      key,
      enabled: true,
      reason: 'ROLLOUT_MATCH',
      bucket,
      variant: 'on',
      payload: { ...(flag.payload || {}) }
    };
  }

  return {
    ok: true,
    key,
    enabled: false,
    reason: 'ROLLOUT_EXCLUDED',
    bucket,
    variant: 'off',
    payload: {}
  };
}

/**
 * Activa el kill-switch instantáneo sobre una flag (`killed: true, enabled: false`) sin redeploy.
 *
 * @param {string} key
 * @param {{ reason?: string, actor?: string }} [options]
 */
function killFlag(key, options = {}) {
  const cleanKey = String(key || '').trim();
  const store = loadStore();
  const flag = store.flags[cleanKey];
  if (!flag) {
    throw flagError('FLAG_NOT_FOUND', `Feature flag "${cleanKey}" not found.`, 404);
  }

  const killReason = String((options && options.reason) || 'emergency_kill');
  const actor = String((options && options.actor) || 'admin');
  const nowIso = new Date().toISOString();

  flag.killed = true;
  flag.enabled = false;
  flag.killReason = killReason;
  flag.killedBy = actor;
  flag.killedAt = nowIso;
  flag.updatedAt = nowIso;

  store.flags[cleanKey] = flag;
  saveStore(store);

  return {
    ok: true,
    key: cleanKey,
    killed: true,
    enabled: false,
    reason: 'KILL_SWITCH_ACTIVE',
    flag
  };
}

/**
 * Elimina una feature flag del store.
 * @param {string} key
 */
function deleteFlag(key) {
  const cleanKey = String(key || '').trim();
  const store = loadStore();
  if (!store.flags[cleanKey]) {
    throw flagError('FLAG_NOT_FOUND', `Feature flag "${cleanKey}" not found.`, 404);
  }
  delete store.flags[cleanKey];
  saveStore(store);
  return {
    ok: true,
    key: cleanKey,
    deleted: true
  };
}

module.exports = {
  computeDeterministicBucket,
  saveFlag,
  listFlags,
  evaluateFlag,
  killFlag,
  deleteFlag
};
