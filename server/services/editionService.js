const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { atomicWriteJsonSync, loadJsonWithBackupSync } = require('./ssrfGuard');

/**
 * Culkibo Ethical Open-Core Edition & Offline Ed25519 License Verifier
 * =====================================================================
 *
 * Zero npm dependencies, zero network phone-home, zero shell execution,
 * zero background timers, and lazy disk loading (`CULKIBO_DATA_DIR`-isolated).
 *
 * Ethical Open-Core Guarantee:
 *  - Community edition (`community`) includes 100% of Culkibo's self-hosted
 *    power with ZERO artificial limits (unlimited projects, databases, domains,
 *    wildcard TLS, Live Sync, Multi-Server SSH Fleet, Multi-User RBAC, TOTP 2FA,
 *    OIDC SSO, GitOps, MCP Server, Encrypted S3 Backups & DR, Synthetic Uptime,
 *    Scale-to-Zero Auto-Sleep, Observability, Alerting, and Visual Topology).
 *  - Commercial editions (`pro`, `enterprise`, `cloud`) unlock optional
 *    enterprise/managed commercial packs verified 100% offline via Ed25519
 *    digital signatures (`CKL1.<base64url(payload)>.<base64url(sig64)>`).
 */

const LICENSE_PREFIX = 'CKL1';
const DATA_FILE_NAME = 'edition.json';
const MAX_LICENSE_KEY_BYTES = 16384;
const DEFAULT_CLOCK_SKEW_SEC = 300;
const LICENSE_ID_RE = /^[a-zA-Z0-9_-]{4,64}$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

/**
 * Clave pública Ed25519 oficial por defecto para verificación offline de licencias Culkibo.
 * Puede complementarse o sustituirse en despliegues air-gapped mediante `CULKIBO_LICENSE_PUBLIC_KEY`.
 */
const OFFICIAL_PUBLIC_KEY_PEM = [
  '-----BEGIN PUBLIC KEY-----',
  'MCowBQYDK2VwAyEAGM5zVoJ66XorZ8Bdtn2p1YvB5OzAc/hyYXGTKObUOCY=',
  '-----END PUBLIC KEY-----'
].join('\n');

const OPEN_CORE_PROMISE =
  'Community edition includes 100% of self-hosted core features with zero artificial limits. Commercial licenses only unlock optional enterprise/managed packs.';

/**
 * Capacidades troncales OSS: SIEMPRE `true` en Community y en cualquier edición.
 * Nunca pueden desactivarse ni condicionarse a licencia comercial.
 */
const CORE_OSS_FEATURES = Object.freeze({
  unlimited_projects: true,
  unlimited_databases: true,
  unlimited_domains: true,
  wildcard_tls: true,
  live_sync: true,
  multi_server_fleet: true,
  rbac_teams: true,
  totp_2fa: true,
  oidc_sso: true,
  gitops: true,
  mcp_server: true,
  encrypted_backups_s3: true,
  uptime_monitoring: true,
  auto_sleep: true,
  observability_alerts: true
});

/**
 * Catálogo de paquetes comerciales opcionales (sin capar jamás el núcleo OSS).
 * @type {Readonly<Record<string, { id: string, name: string, minEdition: 'pro' | 'enterprise' | 'cloud', description: string }>>}
 */
const COMMERCIAL_FEATURE_CATALOG = Object.freeze({
  managed_multi_region_relay: Object.freeze({
    id: 'managed_multi_region_relay',
    name: 'Managed Multi-Region Relay',
    minEdition: 'pro',
    description: 'Zero-config edge relay and geo-routing mesh across regions without managing ingress relays.'
  }),
  custom_branding: Object.freeze({
    id: 'custom_branding',
    name: 'Custom White-Label Branding',
    minEdition: 'pro',
    description: 'White-label dashboard, public status pages, and waking screens with custom brand identity.'
  }),
  priority_support_bundle: Object.freeze({
    id: 'priority_support_bundle',
    name: 'Priority Diagnostics & Support Bundle',
    minEdition: 'pro',
    description: 'Signed redaction-safe diagnostics bundle export for priority engineering support.'
  }),
  enterprise_scim_saml: Object.freeze({
    id: 'enterprise_scim_saml',
    name: 'Enterprise SCIM 2.0 & SAML 2.0 Pack',
    minEdition: 'enterprise',
    description: 'Automated Okta/Entra ID SCIM directory provisioning, group-to-RBAC sync, and SAML 2.0 assertions.'
  }),
  sla_support_export: Object.freeze({
    id: 'sla_support_export',
    name: 'SLA & Signed Compliance Export',
    minEdition: 'enterprise',
    description: 'Automated SOC2/ISO-27001 evidence packages and hash-chained audit attestation exports.'
  }),
  compliance_audit_export: Object.freeze({
    id: 'compliance_audit_export',
    name: 'Continuous SIEM / Audit Attestation Export',
    minEdition: 'enterprise',
    description: 'Signed audit trail checkpoints and continuous compliance archive export.'
  }),
  dedicated_onboarding: Object.freeze({
    id: 'dedicated_onboarding',
    name: 'Dedicated Architecture & Migration SLA',
    minEdition: 'enterprise',
    description: 'Contractual SLA, dedicated solutions engineer, and assisted fleet migrations.'
  }),
  managed_control_plane: Object.freeze({
    id: 'managed_control_plane',
    name: 'Culkibo Cloud Managed Control Plane',
    minEdition: 'cloud',
    description: 'High-availability managed control plane with automated multi-AZ failover.'
  })
});

/** @type {Readonly<Record<'community' | 'pro' | 'enterprise' | 'cloud', ReadonlyArray<string>>>} */
const EDITION_ENTITLEMENTS = Object.freeze({
  community: Object.freeze([]),
  pro: Object.freeze([
    'managed_multi_region_relay',
    'custom_branding',
    'priority_support_bundle'
  ]),
  enterprise: Object.freeze([
    'managed_multi_region_relay',
    'custom_branding',
    'priority_support_bundle',
    'enterprise_scim_saml',
    'sla_support_export',
    'compliance_audit_export',
    'dedicated_onboarding'
  ]),
  cloud: Object.freeze([
    'managed_multi_region_relay',
    'custom_branding',
    'priority_support_bundle',
    'enterprise_scim_saml',
    'sla_support_export',
    'compliance_audit_export',
    'dedicated_onboarding',
    'managed_control_plane'
  ])
});

const COMMERCIAL_EDITIONS = new Set(['pro', 'enterprise', 'cloud']);

/**
 * @param {string} message
 * @param {number} [status]
 * @param {string} [code]
 */
function editionError(message, status = 400, code = 'LICENSE_ERROR') {
  /** @type {Error & { status?: number, code?: string }} */
  const err = new Error(message);
  err.status = status;
  err.code = code;
  return err;
}

/**
 * Serialización JSON determinista con claves ordenadas (sin espacios).
 * @param {any} value
 * @returns {string}
 */
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((v) => (v === undefined ? 'null' : canonicalJson(v))).join(',') + ']';
  }
  const keys = Object.keys(value)
    .filter((k) => value[k] !== undefined && k !== '__proto__' && k !== 'constructor' && k !== 'prototype')
    .sort();
  return '{' + keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',') + '}';
}

/**
 * Calcula un `keyId` corto determinista (SHA-256 SPKI DER) para una clave pública Ed25519.
 * @param {crypto.KeyObject | string | Buffer} pubKeyInput
 * @returns {string}
 */
function computeKeyId(pubKeyInput) {
  const keyObj = typeof pubKeyInput === 'string' || Buffer.isBuffer(pubKeyInput)
    ? crypto.createPublicKey(pubKeyInput)
    : pubKeyInput;
  const der = keyObj.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex').slice(0, 16);
}

/**
 * Genera un par de claves Ed25519 listo para firmar/verificar licencias offline.
 * @returns {{ publicKeyPem: string, privateKeyPem: string, keyId: string }}
 */
function generateLicenseKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = String(publicKey.export({ type: 'spki', format: 'pem' })).trim();
  const privateKeyPem = String(privateKey.export({ type: 'pkcs8', format: 'pem' })).trim();
  return {
    publicKeyPem,
    privateKeyPem,
    keyId: computeKeyId(publicKey)
  };
}

/**
 * Emite una clave de licencia Culkibo firmada con Ed25519 (`CKL1.<payload>.<sig>`).
 * @param {{
 *   licenseId: string,
 *   edition: 'pro' | 'enterprise' | 'cloud',
 *   holder: { org: string, email?: string | null },
 *   issuedAt?: string,
 *   notBefore?: string | null,
 *   expiresAt?: string | null,
 *   maxNodes?: number | null,
 *   seats?: number | null,
 *   features?: string[],
 *   instanceId?: string | null,
 *   kid?: string | null
 * }} rawPayload
 * @param {string | Buffer | crypto.KeyObject} privateKeyPem
 * @returns {string}
 */
function mintLicense(rawPayload, privateKeyPem) {
  if (!rawPayload || typeof rawPayload !== 'object' || Array.isArray(rawPayload)) {
    throw editionError('Payload de licencia inválido', 400, 'INVALID_LICENSE_PAYLOAD');
  }
  const licenseId = String(rawPayload.licenseId || '').trim();
  if (!LICENSE_ID_RE.test(licenseId)) {
    throw editionError('licenseId inválido (esperado 4-64 caracteres alfanuméricos/_/-)', 400, 'INVALID_LICENSE_ID');
  }
  const edition = String(rawPayload.edition || '').trim().toLowerCase();
  if (!COMMERCIAL_EDITIONS.has(edition)) {
    throw editionError(`Edición comercial inválida: ${edition}`, 400, 'INVALID_LICENSE_EDITION');
  }
  const org = String(rawPayload.holder && rawPayload.holder.org ? rawPayload.holder.org : '').trim().slice(0, 120);
  if (!org) {
    throw editionError('holder.org es obligatorio en la licencia', 400, 'INVALID_LICENSE_HOLDER');
  }
  const email = rawPayload.holder && rawPayload.holder.email
    ? String(rawPayload.holder.email).trim().toLowerCase().slice(0, 160)
    : null;

  const issuedAt = rawPayload.issuedAt ? new Date(rawPayload.issuedAt).toISOString() : new Date().toISOString();
  const notBefore = rawPayload.notBefore ? new Date(rawPayload.notBefore).toISOString() : null;
  const expiresAt = rawPayload.expiresAt === null || rawPayload.expiresAt === undefined
    ? null
    : new Date(rawPayload.expiresAt).toISOString();
  if (expiresAt && Date.parse(expiresAt) <= Date.parse(issuedAt)) {
    throw editionError('expiresAt debe ser posterior a issuedAt', 400, 'INVALID_LICENSE_EXPIRY');
  }

  const privKey = typeof privateKeyPem === 'string' || Buffer.isBuffer(privateKeyPem)
    ? crypto.createPrivateKey(privateKeyPem)
    : privateKeyPem;
  if (privKey.asymmetricKeyType !== 'ed25519') {
    throw editionError('La clave de firma debe ser Ed25519', 400, 'INVALID_SIGNING_KEY');
  }
  const derivedKid = computeKeyId(crypto.createPublicKey(privKey));

  /** @type {string[]} */
  const features = Array.isArray(rawPayload.features)
    ? Array.from(new Set(rawPayload.features.map((f) => String(f || '').trim()).filter((f) => Object.prototype.hasOwnProperty.call(COMMERCIAL_FEATURE_CATALOG, f))))
    : [...EDITION_ENTITLEMENTS[/** @type {'pro' | 'enterprise' | 'cloud'} */ (edition)]];

  const payload = {
    v: 1,
    licenseId,
    edition,
    holder: {
      org,
      ...(email ? { email } : {})
    },
    issuedAt,
    ...(notBefore ? { notBefore } : {}),
    expiresAt,
    ...(rawPayload.maxNodes != null && Number.isInteger(Number(rawPayload.maxNodes)) && Number(rawPayload.maxNodes) > 0
      ? { maxNodes: Number(rawPayload.maxNodes) }
      : {}),
    ...(rawPayload.seats != null && Number.isInteger(Number(rawPayload.seats)) && Number(rawPayload.seats) > 0
      ? { seats: Number(rawPayload.seats) }
      : {}),
    features,
    ...(rawPayload.instanceId ? { instanceId: String(rawPayload.instanceId).trim().slice(0, 128) } : {}),
    kid: rawPayload.kid ? String(rawPayload.kid).trim().slice(0, 32) : derivedKid
  };

  const encodedPayload = Buffer.from(canonicalJson(payload), 'utf8').toString('base64url');
  const signingInput = Buffer.from(`${LICENSE_PREFIX}.${encodedPayload}`, 'ascii');
  const signature = crypto.sign(null, signingInput, privKey);
  return `${LICENSE_PREFIX}.${encodedPayload}.${signature.toString('base64url')}`;
}

/**
 * Convierte una lista de claves públicas PEM/KeyObject en `KeyObject[]` Ed25519 válidos.
 * @param {Array<string | Buffer | crypto.KeyObject>} inputs
 * @returns {Array<{ key: crypto.KeyObject, kid: string }>}
 */
function normalizeTrustedPublicKeys(inputs) {
  /** @type {Array<{ key: crypto.KeyObject, kid: string }>} */
  const out = [];
  const seen = new Set();
  for (const raw of inputs) {
    if (!raw) continue;
    try {
      const normalized = typeof raw === 'string' ? raw.replace(/\\n/g, '\n').trim() : raw;
      if (!normalized) continue;
      const key = typeof normalized === 'string' || Buffer.isBuffer(normalized)
        ? crypto.createPublicKey(normalized)
        : normalized;
      if (key.asymmetricKeyType !== 'ed25519') continue;
      const kid = computeKeyId(key);
      if (seen.has(kid)) continue;
      seen.add(kid);
      out.push({ key, kid });
    } catch (e) {
      // Ignorar claves malformadas en env sin abrir la verificación (fail-closed si no queda ninguna válida)
    }
  }
  return out;
}

/**
 * Verifica una licencia Culkibo 100% offline con criptografía Ed25519.
 * Comprueba: formato, tamaño, longitud exacta de firma (64 bytes), firma Ed25519,
 * integridad del payload, edición, ventanas temporales (`issuedAt`, `notBefore`, `expiresAt`)
 * y vínculo opcional a `instanceId`.
 *
 * @param {string} rawLicenseKey
 * @param {{
 *   publicKeys?: Array<string | Buffer | crypto.KeyObject>,
 *   nowMs?: number,
 *   clockSkewSec?: number,
 *   instanceId?: string | null
 * }} [opts]
 * @returns {{
 *   valid: boolean,
 *   code: string,
 *   message: string,
 *   payload: Record<string, any> | null,
 *   entitlements: string[],
 *   fingerprint: string | null,
 *   daysRemaining: number | null,
 *   verifiedKeyId: string | null
 * }}
 */
function verifyLicenseKey(rawLicenseKey, opts = {}) {
  const fail = (code, message) => ({
    valid: false,
    code,
    message,
    payload: null,
    entitlements: [],
    fingerprint: null,
    daysRemaining: null,
    verifiedKeyId: null
  });

  if (typeof rawLicenseKey !== 'string') {
    return fail('INVALID_LICENSE_FORMAT', 'La clave de licencia debe ser una cadena de texto');
  }
  const trimmed = rawLicenseKey.trim();
  if (!trimmed || trimmed.length > MAX_LICENSE_KEY_BYTES) {
    return fail('INVALID_LICENSE_FORMAT', 'Clave de licencia vacía o excede el tamaño máximo permitido');
  }

  const parts = trimmed.split('.');
  if (parts.length !== 3 || parts[0] !== LICENSE_PREFIX) {
    return fail('INVALID_LICENSE_FORMAT', `Formato de licencia inválido (esperado ${LICENSE_PREFIX}.<payload>.<firma>)`);
  }
  const [, encodedPayload, encodedSig] = parts;
  if (!encodedPayload || !encodedSig || !BASE64URL_RE.test(encodedPayload) || !BASE64URL_RE.test(encodedSig)) {
    return fail('INVALID_LICENSE_FORMAT', 'Codificación base64url inválida en la clave de licencia');
  }

  const sigBuf = Buffer.from(encodedSig, 'base64url');
  if (sigBuf.length !== 64) {
    return fail('INVALID_LICENSE_SIGNATURE', 'Longitud de firma Ed25519 inválida (esperados 64 bytes)');
  }

  const rawKeyList = Array.isArray(opts.publicKeys) && opts.publicKeys.length > 0
    ? opts.publicKeys
    : [
        ...(process.env.CULKIBO_LICENSE_PUBLIC_KEY ? [process.env.CULKIBO_LICENSE_PUBLIC_KEY] : []),
        OFFICIAL_PUBLIC_KEY_PEM
      ];
  const trusted = normalizeTrustedPublicKeys(rawKeyList);
  if (trusted.length === 0) {
    return fail('NO_TRUSTED_PUBLIC_KEYS', 'No hay claves públicas Ed25519 confiables configuradas');
  }

  const signingInput = Buffer.from(`${LICENSE_PREFIX}.${encodedPayload}`, 'ascii');
  let verifiedKeyId = /** @type {string | null} */ (null);
  for (const entry of trusted) {
    try {
      if (crypto.verify(null, signingInput, entry.key, sigBuf)) {
        verifiedKeyId = entry.kid;
        break;
      }
    } catch (e) {}
  }
  if (!verifiedKeyId) {
    return fail('INVALID_LICENSE_SIGNATURE', 'Firma criptográfica Ed25519 inválida o licencia alterada');
  }

  /** @type {any} */
  let payload;
  try {
    const jsonStr = Buffer.from(encodedPayload, 'base64url').toString('utf8');
    payload = JSON.parse(jsonStr);
  } catch (e) {
    return fail('INVALID_LICENSE_PAYLOAD', 'No se pudo decodificar el payload JSON de la licencia');
  }

  if (!payload || typeof payload !== 'object' || Array.isArray(payload) || payload.v !== 1) {
    return fail('INVALID_LICENSE_PAYLOAD', 'Versión o estructura de licencia no soportada');
  }
  if (typeof payload.licenseId !== 'string' || !LICENSE_ID_RE.test(payload.licenseId)) {
    return fail('INVALID_LICENSE_PAYLOAD', 'Identificador de licencia inválido');
  }
  const edition = typeof payload.edition === 'string' ? payload.edition.trim().toLowerCase() : '';
  if (!COMMERCIAL_EDITIONS.has(edition)) {
    return fail('INVALID_LICENSE_EDITION', `Edición desconocida en la licencia: ${edition || '(vacía)'}`);
  }
  if (!payload.holder || typeof payload.holder !== 'object' || typeof payload.holder.org !== 'string' || !payload.holder.org.trim()) {
    return fail('INVALID_LICENSE_PAYLOAD', 'Falta el titular (holder.org) en la licencia');
  }

  const nowMs = typeof opts.nowMs === 'number' && Number.isFinite(opts.nowMs) ? opts.nowMs : Date.now();
  const skewMs = Math.max(0, Math.min(3600, Number(opts.clockSkewSec ?? DEFAULT_CLOCK_SKEW_SEC))) * 1000;

  const issuedMs = Date.parse(String(payload.issuedAt || ''));
  if (!Number.isFinite(issuedMs)) {
    return fail('INVALID_LICENSE_PAYLOAD', 'Fecha de emisión (issuedAt) inválida');
  }
  if (issuedMs > nowMs + skewMs) {
    return fail('LICENSE_NOT_YET_VALID', 'La licencia fue emitida para una fecha futura');
  }

  if (payload.notBefore != null) {
    const nbfMs = Date.parse(String(payload.notBefore));
    if (!Number.isFinite(nbfMs)) {
      return fail('INVALID_LICENSE_PAYLOAD', 'Fecha notBefore inválida');
    }
    if (nowMs + skewMs < nbfMs) {
      return fail('LICENSE_NOT_YET_VALID', 'La licencia todavía no ha entrado en vigor');
    }
  }

  let daysRemaining = /** @type {number | null} */ (null);
  if (payload.expiresAt !== null && payload.expiresAt !== undefined) {
    const expMs = Date.parse(String(payload.expiresAt));
    if (!Number.isFinite(expMs)) {
      return fail('INVALID_LICENSE_PAYLOAD', 'Fecha de expiración (expiresAt) inválida');
    }
    if (nowMs >= expMs) {
      return fail('LICENSE_EXPIRED', 'La licencia comercial ha caducado; el sistema continúa en edición Community completa');
    }
    daysRemaining = Math.max(0, Math.ceil((expMs - nowMs) / 86400000));
  }

  if (payload.instanceId && opts.instanceId && String(payload.instanceId) !== String(opts.instanceId)) {
    return fail('LICENSE_INSTANCE_MISMATCH', 'La licencia está vinculada a otro instanceId');
  }

  const baseTier = EDITION_ENTITLEMENTS[/** @type {'pro' | 'enterprise' | 'cloud'} */ (edition)] || [];
  const customFeatures = Array.isArray(payload.features)
    ? payload.features
        .map((f) => String(f || '').trim())
        .filter((f) => Object.prototype.hasOwnProperty.call(COMMERCIAL_FEATURE_CATALOG, f))
    : baseTier;
  const entitlements = Array.from(new Set(customFeatures));
  const fingerprint = crypto.createHash('sha256').update(trimmed, 'ascii').digest('hex').slice(0, 16);

  return {
    valid: true,
    code: 'LICENSE_VALID',
    message: `Licencia ${edition.toUpperCase()} verificada offline (Ed25519)`,
    payload: {
      v: 1,
      licenseId: payload.licenseId,
      edition,
      holder: {
        org: String(payload.holder.org).trim().slice(0, 120),
        email: payload.holder.email ? String(payload.holder.email).trim().toLowerCase().slice(0, 160) : null
      },
      issuedAt: new Date(issuedMs).toISOString(),
      notBefore: payload.notBefore ? new Date(Date.parse(String(payload.notBefore))).toISOString() : null,
      expiresAt: payload.expiresAt ? new Date(Date.parse(String(payload.expiresAt))).toISOString() : null,
      maxNodes: Number.isInteger(payload.maxNodes) && payload.maxNodes > 0 ? payload.maxNodes : null,
      seats: Number.isInteger(payload.seats) && payload.seats > 0 ? payload.seats : null,
      instanceId: payload.instanceId ? String(payload.instanceId) : null,
      kid: payload.kid ? String(payload.kid) : verifiedKeyId
    },
    entitlements,
    fingerprint,
    daysRemaining,
    verifiedKeyId
  };
}

function resolveDefaultDataDir() {
  return process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..', 'data');
}

class EditionService {
  /**
   * @param {{
   *   dataDir?: string | null,
   *   dataFile?: string | null,
   *   trustedPublicKeys?: Array<string | Buffer | crypto.KeyObject> | null,
   *   instanceId?: string | null
   * }} [options]
   */
  constructor(options = {}) {
    this._explicitDataDir = options.dataDir ? path.resolve(options.dataDir) : null;
    this._explicitDataFile = options.dataFile ? path.resolve(options.dataFile) : null;
    this._trustedPublicKeys = Array.isArray(options.trustedPublicKeys) ? options.trustedPublicKeys : null;
    this._instanceId = options.instanceId || null;

    /** @type {{ version: number, licenseKey: string | null, activatedAt: string | null, updatedAt: string | null } | null} */
    this._stored = null;
    /** @type {string | null} */
    this._loadedPath = null;
  }

  _getFilePath() {
    if (this._explicitDataFile) return this._explicitDataFile;
    const dir = this._explicitDataDir || resolveDefaultDataDir();
    return path.join(dir, DATA_FILE_NAME);
  }

  _getPublicKeys() {
    if (this._trustedPublicKeys && this._trustedPublicKeys.length > 0) {
      return this._trustedPublicKeys;
    }
    /** @type {Array<string | Buffer | crypto.KeyObject>} */
    const keys = [];
    if (process.env.CULKIBO_LICENSE_PUBLIC_KEY) {
      keys.push(process.env.CULKIBO_LICENSE_PUBLIC_KEY);
    }
    keys.push(OFFICIAL_PUBLIC_KEY_PEM);
    return keys;
  }

  _ensureLoaded() {
    const filePath = this._getFilePath();
    if (this._stored !== null && this._loadedPath === filePath) {
      return this._stored;
    }
    this._loadedPath = filePath;
    if (!fs.existsSync(filePath)) {
      this._stored = { version: 1, licenseKey: null, activatedAt: null, updatedAt: null };
      return this._stored;
    }
    const loaded = loadJsonWithBackupSync(filePath, {
      validate: (p) => Boolean(p && typeof p === 'object' && !Array.isArray(p))
    });
    if (loaded.ok && loaded.data) {
      this._stored = {
        version: 1,
        licenseKey: typeof loaded.data.licenseKey === 'string' && loaded.data.licenseKey.trim()
          ? loaded.data.licenseKey.trim()
          : null,
        activatedAt: typeof loaded.data.activatedAt === 'string' ? loaded.data.activatedAt : null,
        updatedAt: typeof loaded.data.updatedAt === 'string' ? loaded.data.updatedAt : null
      };
      return this._stored;
    }
    // Fail-safe back to Community OSS on corrupt file (never blocks core platform)
    this._stored = { version: 1, licenseKey: null, activatedAt: null, updatedAt: null };
    return this._stored;
  }

  /**
   * Construye el mapa booleano de paquetes comerciales activos.
   * @param {string[]} activeEntitlements
   */
  _buildCommercialFeaturesMap(activeEntitlements) {
    const activeSet = new Set(activeEntitlements);
    /** @type {Record<string, boolean>} */
    const map = {};
    for (const id of Object.keys(COMMERCIAL_FEATURE_CATALOG)) {
      map[id] = activeSet.has(id);
    }
    return map;
  }

  /** Devuelve el catálogo descriptivo de paquetes comerciales opcionales. */
  getCommercialCatalog() {
    return {
      openCorePromise: OPEN_CORE_PROMISE,
      communityCoreFeatures: Object.keys(CORE_OSS_FEATURES),
      editions: ['community', 'pro', 'enterprise', 'cloud'],
      packs: Object.values(COMMERCIAL_FEATURE_CATALOG)
    };
  }

  /**
   * Resuelve el estado actual de edición y licenciamiento (verificado offline en cada consulta).
   * @param {{ nowMs?: number, includeCatalog?: boolean }} [opts]
   */
  getStatus(opts = {}) {
    const envKey = !this._explicitDataDir && !this._explicitDataFile && process.env.CULKIBO_LICENSE_KEY
      ? String(process.env.CULKIBO_LICENSE_KEY).trim()
      : '';
    const stored = this._ensureLoaded();
    const activeKey = envKey || (stored && stored.licenseKey) || '';
    const source = envKey ? 'env' : (stored && stored.licenseKey ? 'file' : null);

    if (!activeKey) {
      return {
        edition: 'community',
        commercialActive: false,
        openCorePromise: OPEN_CORE_PROMISE,
        coreFeatures: { ...CORE_OSS_FEATURES },
        commercialFeatures: this._buildCommercialFeaturesMap([]),
        entitlements: [],
        license: null,
        verification: {
          valid: true,
          code: 'COMMUNITY_OPEN_CORE',
          verifiedOffline: true,
          message: 'Edición Community Open-Core activa con el 100% de funcionalidades self-hosted.'
        },
        ...(opts.includeCatalog ? { catalog: this.getCommercialCatalog() } : {})
      };
    }

    const check = verifyLicenseKey(activeKey, {
      publicKeys: this._getPublicKeys(),
      nowMs: opts.nowMs,
      instanceId: this._instanceId
    });

    if (!check.valid || !check.payload) {
      // Fail-closed para paquetes comerciales, manteniendo 100% intacta la edición Community
      return {
        edition: 'community',
        commercialActive: false,
        openCorePromise: OPEN_CORE_PROMISE,
        coreFeatures: { ...CORE_OSS_FEATURES },
        commercialFeatures: this._buildCommercialFeaturesMap([]),
        entitlements: [],
        license: {
          source,
          activatedAt: stored ? stored.activatedAt : null,
          valid: false
        },
        verification: {
          valid: false,
          code: check.code,
          verifiedOffline: true,
          message: check.message
        },
        ...(opts.includeCatalog ? { catalog: this.getCommercialCatalog() } : {})
      };
    }

    return {
      edition: check.payload.edition,
      commercialActive: true,
      openCorePromise: OPEN_CORE_PROMISE,
      coreFeatures: { ...CORE_OSS_FEATURES },
      commercialFeatures: this._buildCommercialFeaturesMap(check.entitlements),
      entitlements: check.entitlements,
      license: {
        licenseId: check.payload.licenseId,
        edition: check.payload.edition,
        holder: check.payload.holder,
        issuedAt: check.payload.issuedAt,
        notBefore: check.payload.notBefore,
        expiresAt: check.payload.expiresAt,
        daysRemaining: check.daysRemaining,
        maxNodes: check.payload.maxNodes,
        seats: check.payload.seats,
        instanceId: check.payload.instanceId,
        keyId: check.verifiedKeyId,
        fingerprint: check.fingerprint,
        source,
        activatedAt: stored ? stored.activatedAt : null,
        verifiedOffline: true
      },
      verification: {
        valid: true,
        code: check.code,
        verifiedOffline: true,
        message: check.message
      },
      ...(opts.includeCatalog ? { catalog: this.getCommercialCatalog() } : {})
    };
  }

  /**
   * Comprueba si una funcionalidad está habilitada.
   * Las capacidades de núcleo OSS devuelven SIEMPRE `true`.
   * @param {string} featureId
   * @param {{ nowMs?: number }} [opts]
   * @returns {boolean}
   */
  hasFeature(featureId, opts = {}) {
    const key = String(featureId || '').trim();
    if (!key) return false;
    if (Object.prototype.hasOwnProperty.call(CORE_OSS_FEATURES, key)) {
      return true;
    }
    const status = this.getStatus(opts);
    return Boolean(status.commercialFeatures && status.commercialFeatures[key] === true);
  }

  /**
   * Activa una licencia comercial tras verificar estrictamente su firma Ed25519 offline.
   * Persiste atómicamente en `edition.json` (`0o600`, con respaldo `.bak`).
   * @param {string} licenseKey
   * @param {{ nowMs?: number }} [opts]
   */
  activateLicense(licenseKey, opts = {}) {
    const check = verifyLicenseKey(licenseKey, {
      publicKeys: this._getPublicKeys(),
      nowMs: opts.nowMs,
      instanceId: this._instanceId
    });
    if (!check.valid || !check.payload) {
      const status = check.code === 'LICENSE_EXPIRED' || check.code === 'LICENSE_NOT_YET_VALID' ? 422 : 400;
      throw editionError(check.message, status, check.code);
    }

    const nowIso = new Date(typeof opts.nowMs === 'number' ? opts.nowMs : Date.now()).toISOString();
    const record = {
      version: 1,
      licenseKey: String(licenseKey).trim(),
      licenseId: check.payload.licenseId,
      edition: check.payload.edition,
      fingerprint: check.fingerprint,
      activatedAt: nowIso,
      updatedAt: nowIso
    };
    const filePath = this._getFilePath();
    atomicWriteJsonSync(filePath, record, { mode: 0o600, pretty: true, backup: true });
    this._stored = {
      version: 1,
      licenseKey: record.licenseKey,
      activatedAt: nowIso,
      updatedAt: nowIso
    };
    this._loadedPath = filePath;
    return {
      activated: true,
      ...this.getStatus({ nowMs: opts.nowMs })
    };
  }

  /**
   * Elimina la licencia comercial almacenada y vuelve limpiamente a Community Edition.
   */
  deactivateLicense() {
    const filePath = this._getFilePath();
    const nowIso = new Date().toISOString();
    this._stored = { version: 1, licenseKey: null, activatedAt: null, updatedAt: nowIso };
    this._loadedPath = filePath;
    try {
      if (fs.existsSync(filePath)) {
        atomicWriteJsonSync(filePath, { version: 1, licenseKey: null, activatedAt: null, updatedAt: nowIso }, { mode: 0o600, pretty: true, backup: true });
      }
    } catch (e) {}
    return {
      deactivated: true,
      ...this.getStatus()
    };
  }
}

const defaultInstance = new EditionService();

module.exports = Object.assign(defaultInstance, {
  EditionService,
  LICENSE_PREFIX,
  OFFICIAL_PUBLIC_KEY_PEM,
  OPEN_CORE_PROMISE,
  CORE_OSS_FEATURES,
  COMMERCIAL_FEATURE_CATALOG,
  EDITION_ENTITLEMENTS,
  computeKeyId,
  generateLicenseKeyPair,
  mintLicense,
  verifyLicenseKey
});
