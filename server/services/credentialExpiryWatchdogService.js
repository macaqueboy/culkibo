const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Unified Credential, OAuth, GitHub App & API-Key Expiry Watchdog (100% Zero-Dep).
 *
 * Contramedida directa a `coollabsio/coolify#4702` (deriva NTP rompiendo `exp` en JWT de
 * GitHub App), `Dokploy/dokploy#2913` (permisos inseguros de clave SSH en BuildKit) y
 * `Dokploy/dokploy#5618` (tokens de instalación filtrados en logs de build).
 *
 * Invariante de seguridad absoluta:
 *  - **METADATOS ÚNICAMENTE**: JAMÁS persiste ni devuelve valores secretos (`secret`,
 *    `token`, `privateKey`, `password`, `apiKey`, `pem` son descartados antes de cualquier
 *    almacenamiento o respuesta).
 *  - Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/credential-watchdog.json`.
 */

const CREDENTIAL_KINDS = Object.freeze([
  'github_app',
  'oauth',
  's3_iam',
  'db_cert',
  'ssh_key',
  'acme_cert',
  'api_key'
]);

const FORBIDDEN_SECRET_KEYS = new Set([
  'secret',
  'token',
  'privatekey',
  'private_key',
  'password',
  'passwd',
  'apikey',
  'api_key',
  'accesskeysecret',
  'secretaccesskey',
  'pem',
  'rawvalue',
  'value'
]);

/** @type {Record<string, string>} */
const DEFAULT_RUNBOOKS = Object.freeze({
  github_app: 'Rotate GitHub App private key in GitHub Developer Settings, upload to Culkibo Vault, verify NTP drift <= 30s, and revoke previous key.',
  oauth: 'Refresh OAuth client secret with identity provider, update Vault key with dual-slot overlap, and verify login callback.',
  s3_iam: 'Create long-lived scoped IAM backup key (never ephemeral STS token), verify S3 PutObject/GetObject drill, then deactivate old key.',
  db_cert: 'Issue renewed TLS cert/CA bundle, reload Postgres/Valkey with zero-downtime SIGHUP, and verify client TLS handshake.',
  ssh_key: 'Generate new Ed25519 deploy key, set strict chmod 0600, register public key on Git host, and remove retired public key.',
  acme_cert: 'Verify DNS/ACME challenge reachability (Cloudflare proxy check) and force ACME renewal via Caddy admin API.',
  api_key: 'Generate replacement scoped API key, stage zero-downtime Vault rollout, confirm 200 responses, then revoke legacy key.'
});

/**
 * Resuelve dinámicamente la ruta a `credential-watchdog.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'credential-watchdog.json')
    : path.join(base, 'data', 'credential-watchdog.json');
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
 * Carga metadatos de credenciales desde disco (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, credentials: Record<string, any> }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), credentials: {} };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && parsed.credentials && typeof parsed.credentials === 'object') {
      return parsed;
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), credentials: {} };
}

/**
 * Guarda metadatos de credenciales atómicamente (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, credentials: Record<string, any> }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Parsea un modo POSIX (`'0600'`, `'600'`, `0o777`) a entero octal (o `null`).
 * @param {string | number | null | undefined} rawMode
 * @returns {number | null}
 */
function parsePosixMode(rawMode) {
  if (typeof rawMode === 'number' && Number.isFinite(rawMode) && rawMode >= 0) {
    return Math.floor(rawMode);
  }
  const s = String(rawMode || '').trim();
  if (!s) return null;
  if (/^0?[0-7]{3,4}$/.test(s)) {
    return parseInt(s, 8);
  }
  return null;
}

/**
 * Registra metadatos de expiración de una credencial (CERO valores secretos; por defecto `dryRun: true`).
 *
 * @param {{
 *   id?: string,
 *   projectId?: string,
 *   kind?: string,
 *   label?: string,
 *   expiresAtIso: string,
 *   clockSkewSec?: number,
 *   permissionsMode?: string | number,
 *   rotationRunbook?: string,
 *   dryRun?: boolean
 * } & Record<string, any>} input
 */
function registerCredentialMetadata(input) {
  const opts = input || /** @type {any} */ ({});
  const dryRun = opts.dryRun !== undefined ? Boolean(opts.dryRun) : true;
  const rawKind = String(opts.kind || 'api_key').trim().toLowerCase();
  const kind = CREDENTIAL_KINDS.includes(rawKind) ? rawKind : 'api_key';
  const projectId = String(opts.projectId || 'default').trim() || 'default';
  const id = String(opts.id || `cred_${crypto.randomBytes(5).toString('hex')}`).trim();
  const label = String(opts.label || `${kind}:${id}`).trim();

  const expiresAtIso = String(opts.expiresAtIso || '').trim();
  const expMs = Date.parse(expiresAtIso);
  if (!expiresAtIso || !Number.isFinite(expMs)) {
    const err = /** @type {any} */ (new Error('Valid expiresAtIso timestamp is required to register credential metadata.'));
    err.status = 400;
    err.code = 'INVALID_EXPIRY_TIMESTAMP';
    throw err;
  }

  // Detect and strip any accidentally supplied raw-secret fields (NEVER store or echo!)
  const strippedSecretFields = Object.keys(opts).filter((k) => FORBIDDEN_SECRET_KEYS.has(k.toLowerCase()));

  const record = {
    id,
    projectId,
    kind,
    label,
    expiresAtIso: new Date(expMs).toISOString(),
    clockSkewSec: Number(opts.clockSkewSec) || 0,
    permissionsMode: opts.permissionsMode !== undefined && opts.permissionsMode !== null
      ? String(opts.permissionsMode)
      : (kind === 'ssh_key' ? '0600' : null),
    rotationRunbook: String(opts.rotationRunbook || DEFAULT_RUNBOOKS[kind] || DEFAULT_RUNBOOKS.api_key),
    metadataOnly: true,
    updatedAt: new Date().toISOString()
  };

  if (!dryRun) {
    const store = loadStore();
    store.credentials[id] = record;
    saveStore(store);
  }

  return {
    ok: true,
    dryRun,
    persisted: !dryRun,
    strippedSecretFields,
    credential: record
  };
}

/**
 * Audita cuentas regresivas de expiración (`EXPIRED`, `CRITICAL <7d`, `WARNING <30d`, `HEALTHY`).
 *
 * @param {{
 *   projectId?: string,
 *   credentials?: any[],
 *   nowIso?: string | number,
 *   warnDays?: number,
 *   criticalDays?: number
 * }} [input]
 */
function auditCredentialExpiries(input = {}) {
  const opts = input || {};
  const projectId = opts.projectId ? String(opts.projectId).trim() : null;
  const warnDays = Math.max(1, Number(opts.warnDays ?? 30) || 30);
  const criticalDays = Math.max(1, Number(opts.criticalDays ?? 7) || 7);
  const nowMs = opts.nowIso !== undefined
    ? (typeof opts.nowIso === 'number' ? opts.nowIso : (Date.parse(String(opts.nowIso)) || Date.now()))
    : Date.now();

  const sourceList = Array.isArray(opts.credentials)
    ? opts.credentials
    : listTrackedCredentials(projectId || undefined);

  const counts = { EXPIRED: 0, CRITICAL: 0, WARNING: 0, HEALTHY: 0 };

  const items = sourceList.map((raw) => {
    const kindRaw = String(raw.kind || 'api_key').trim().toLowerCase();
    const kind = CREDENTIAL_KINDS.includes(kindRaw) ? kindRaw : 'api_key';
    const expMs = Date.parse(String(raw.expiresAtIso || ''));
    const daysRemaining = Number.isFinite(expMs)
      ? Math.round(((expMs - nowMs) / 86400000) * 10) / 10
      : -1;

    /** @type {'EXPIRED' | 'CRITICAL' | 'WARNING' | 'HEALTHY'} */
    let status = 'HEALTHY';
    if (daysRemaining <= 0) status = 'EXPIRED';
    else if (daysRemaining < criticalDays) status = 'CRITICAL';
    else if (daysRemaining < warnDays) status = 'WARNING';

    counts[status]++;

    return {
      id: String(raw.id || 'inline'),
      projectId: String(raw.projectId || projectId || 'default'),
      kind,
      label: String(raw.label || raw.id || kind),
      expiresAtIso: Number.isFinite(expMs) ? new Date(expMs).toISOString() : null,
      daysRemaining,
      status,
      rotationRunbook: String(raw.rotationRunbook || DEFAULT_RUNBOOKS[kind] || DEFAULT_RUNBOOKS.api_key)
    };
  });

  // Sort most urgent first (EXPIRED -> CRITICAL -> WARNING -> HEALTHY)
  /** @type {Record<string, number>} */
  const rank = { EXPIRED: 0, CRITICAL: 1, WARNING: 2, HEALTHY: 3 };
  items.sort((a, b) => (rank[a.status] - rank[b.status]) || (a.daysRemaining - b.daysRemaining));

  return {
    ok: true,
    projectId,
    healthy: counts.EXPIRED === 0 && counts.CRITICAL === 0,
    warnDays,
    criticalDays,
    total: items.length,
    counts,
    items,
    auditedAt: new Date(nowMs).toISOString()
  };
}

/**
 * Comprueba higiene operativa de reloj NTP (GitHub App JWT `exp`), permisos de clave SSH,
 * credenciales efímeras STS en backups y fuga de tokens de instalación en logs.
 *
 * @param {{
 *   clockSkewSec?: number,
 *   sshKeyMode?: string | number,
 *   usesTempStsToken?: boolean,
 *   logsContainInstallToken?: boolean
 * }} [input]
 */
function checkSshAndJwtHygiene(input = {}) {
  const opts = input || {};
  const clockSkewSec = Number(opts.clockSkewSec) || 0;
  const sshKeyModeRaw = opts.sshKeyMode !== undefined ? opts.sshKeyMode : '0600';
  const usesTempStsToken = Boolean(opts.usesTempStsToken);
  const logsContainInstallToken = Boolean(opts.logsContainInstallToken);

  /** @type {Array<{ code: string, severity: 'critical' | 'high', message: string, fix: string }>} */
  const findings = [];

  // 1. NTP clock drift breaking GitHub App JWT exp (Coolify#4702)
  if (Math.abs(clockSkewSec) > 30) {
    findings.push({
      code: 'CLOCK_SKEW_JWT_FAILURE',
      severity: 'critical',
      message: `Host NTP clock skew is ${clockSkewSec}s (> 30s) — GitHub App JWT iat/exp claims will be rejected (Coolify#4702).`,
      fix: 'Enable chrony/systemd-timesyncd NTP sync and verify host clock drift stays within ±5s.'
    });
  }

  // 2. Loose SSH key permissions failing BuildKit/OpenSSH (Dokploy#2913)
  const parsedMode = parsePosixMode(sshKeyModeRaw);
  if (parsedMode !== null && (parsedMode & 0o077) !== 0) {
    findings.push({
      code: 'INSECURE_SSH_KEY_MODE',
      severity: 'critical',
      message: `SSH private key mode "${sshKeyModeRaw}" grants group/other permissions (must be <= 0600; OpenSSH & BuildKit reject loose keys, Dokploy#2913).`,
      fix: 'Run chmod 0600 on private SSH deploy keys and mount via BuildKit --mount=type=ssh.'
    });
  }

  // 3. Ephemeral STS credentials attached to recurring backups
  if (usesTempStsToken) {
    findings.push({
      code: 'EPHEMERAL_BACKUP_CREDENTIAL',
      severity: 'high',
      message: 'Scheduled backup target is configured with an ephemeral STS session token that will expire silently between backup runs.',
      fix: 'Use a dedicated scoped IAM backup credential or automated OIDC role refresh before scheduled backup jobs.'
    });
  }

  // 4. GitHub App installation token echoed into build logs (Dokploy#5618)
  if (logsContainInstallToken) {
    findings.push({
      code: 'BUILD_LOG_INSTALL_TOKEN_LEAK',
      severity: 'critical',
      message: 'GitHub App installation token detected in build/clone logs (Dokploy#5618).',
      fix: 'Mask x-access-token URLs in Git clone stderr and pass credentials via git credential helper or askpass.'
    });
  }

  return {
    ok: true,
    safe: findings.length === 0,
    clockSkewSec,
    sshKeyMode: String(sshKeyModeRaw),
    usesTempStsToken,
    logsContainInstallToken,
    findings,
    findingCodes: findings.map((f) => f.code)
  };
}

/**
 * Lista los metadatos de credenciales registrados (CERO secretos).
 * @param {string} [projectId]
 */
function listTrackedCredentials(projectId) {
  const store = loadStore();
  const cleanId = projectId ? String(projectId).trim() : '';
  const all = Object.values(store.credentials);
  return cleanId ? all.filter((c) => c.projectId === cleanId) : all;
}

module.exports = {
  CREDENTIAL_KINDS,
  registerCredentialMetadata,
  auditCredentialExpiries,
  checkSshAndJwtHygiene,
  listTrackedCredentials
};
