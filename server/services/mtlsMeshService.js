'use strict';

/**
 * Culkibo Zero-Trust SPIFFE-Lite mTLS Identity CA & Short-Lived Workload Cert Lifecycle.
 *
 * Addresses `coolify#8524`, `dokploy#2605`, and Portainer BE-only mTLS gaps in zero external deps:
 *  - Pure `node:crypto` Ed25519 trust-domain CA (`spiffe://<domain>/ns/<ns>/sa/<service>`).
 *  - Separate `0o600` CA private key (`CULKIBO_DATA_DIR/data/mtls-ca.key`) — NEVER serialized
 *    into `mtls-mesh.json` and NEVER returned by any method or HTTP endpoint.
 *  - Short-lived workload certificates (`ttlHours` clamped `1..168`) with canonical JSON signing.
 *  - Instant CRL revocation (`CERT_REVOKED`) & expiration enforcement (`CERT_EXPIRED`).
 *  - Native Caddy v2.11 `client_authentication` (`require_and_verify`) JSON policy compiler.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DEFAULT_TRUST_DOMAIN = 'culkibo.internal';
const MIN_TTL_HOURS = 1;
const MAX_TTL_HOURS = 168;
const VALID_CADDY_MODES = new Set(['require_and_verify', 'verify_if_given', 'require']);
const MAX_STORED_CERTS = 1000;

/**
 * @typedef {object} WorkloadCertDescriptor
 * @property {number} version
 * @property {string} serial
 * @property {string} spiffeId
 * @property {string} trustDomain
 * @property {string} serviceName
 * @property {string} namespace
 * @property {string} caKeyId
 * @property {string} subjectPublicKeyPem
 * @property {string} subjectKeyThumbprint
 * @property {number} ttlHours
 * @property {number} issuedAtMs
 * @property {string} issuedAt
 * @property {number} expiresAtMs
 * @property {string} expiresAt
 * @property {string[]} keyUsage
 */

/**
 * @typedef {object} StoredCertRecord
 * @property {string} serial
 * @property {string} spiffeId
 * @property {string} trustDomain
 * @property {string} serviceName
 * @property {string} namespace
 * @property {string} caKeyId
 * @property {string} subjectKeyThumbprint
 * @property {number} ttlHours
 * @property {number} issuedAtMs
 * @property {string} issuedAt
 * @property {number} expiresAtMs
 * @property {string} expiresAt
 * @property {boolean} revoked
 * @property {number | null} revokedAtMs
 * @property {string | null} revokedAt
 * @property {string | null} revocationReason
 * @property {string | null} revokedBy
 */

/**
 * @typedef {object} MtlsMeshStoreState
 * @property {number} schemaVersion
 * @property {string} updatedAt
 * @property {string} trustDomain
 * @property {string | null} caKeyId
 * @property {string | null} caPublicKeyPem
 * @property {string | null} caCreatedAt
 * @property {StoredCertRecord[]} certs
 * @property {Record<string, { serial: string, reason: string, actor: string, revokedAtMs: number, revokedAt: string }>} revocations
 */

/**
 * Atomically writes UTF-8 text to disk with `0o600` mode.
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
 * Creates an HTTP-annotated Error.
 * @param {string} code
 * @param {string} msg
 * @param {number} [status]
 */
function mtlsError(code, msg, status = 400) {
  const err = /** @type {any} */ (new Error(msg));
  err.code = code;
  err.status = status;
  return err;
}

/**
 * Deterministic canonical JSON serialization with sorted keys for Ed25519 signing/verification.
 * @param {any} value
 * @returns {string}
 */
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((item) => canonicalJson(item)).join(',') + ']';
  }
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',') + '}';
}

/**
 * Normalizes a SPIFFE trust domain string.
 * @param {any} raw
 * @returns {string}
 */
function normalizeTrustDomain(raw) {
  const val = typeof raw === 'string' && raw.trim()
    ? raw.trim().toLowerCase()
    : DEFAULT_TRUST_DOMAIN;
  if (!/^[a-z0-9](?:[a-z0-9.-]{0,126}[a-z0-9])?$/.test(val) || val.includes('..')) {
    throw mtlsError('INVALID_TRUST_DOMAIN', `Invalid SPIFFE trust domain "${val}"`);
  }
  return val;
}

/**
 * Normalizes a SPIFFE path segment (service name or namespace).
 * @param {any} raw
 * @param {string} field
 * @param {string} code
 * @returns {string}
 */
function normalizeSpiffeSegment(raw, field, code) {
  const val = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  if (!val || !/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/.test(val)) {
    throw mtlsError(code, `${field} must be a valid DNS/SPIFFE identifier (a-z, 0-9, ., _, -)`);
  }
  return val;
}

/**
 * Normalizes epoch milliseconds.
 * @param {any} raw
 * @returns {number}
 */
function normalizeNowMs(raw) {
  if (raw === undefined || raw === null) return Date.now();
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) {
    throw mtlsError('INVALID_TIMESTAMP', 'nowMs must be a finite non-negative number');
  }
  return Math.floor(n);
}

class MtlsMeshService {
  /**
   * @param {{ dataDir?: string | null }} [opts]
   */
  constructor(opts = {}) {
    /** @type {string | null} */
    this._explicitDataDir = opts && typeof opts.dataDir === 'string' && opts.dataDir.trim()
      ? path.resolve(opts.dataDir.trim())
      : null;
  }

  /** @returns {string} */
  resolveDataDir() {
    if (this._explicitDataDir) return this._explicitDataDir;
    if (process.env.CULKIBO_DATA_DIR) {
      return path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data');
    }
    return path.join(__dirname, '..', '..', 'data');
  }

  /** @returns {string} */
  getStoreFilePath() {
    return path.join(this.resolveDataDir(), 'mtls-mesh.json');
  }

  /** @returns {string} */
  getCaKeyFilePath() {
    return path.join(this.resolveDataDir(), 'mtls-ca.key');
  }

  /** @returns {MtlsMeshStoreState} */
  _loadState() {
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) {
      return {
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        trustDomain: DEFAULT_TRUST_DOMAIN,
        caKeyId: null,
        caPublicKeyPem: null,
        caCreatedAt: null,
        certs: [],
        revocations: {}
      };
    }
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      return {
        schemaVersion: 1,
        updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : new Date().toISOString(),
        trustDomain: typeof parsed.trustDomain === 'string' ? parsed.trustDomain : DEFAULT_TRUST_DOMAIN,
        caKeyId: typeof parsed.caKeyId === 'string' ? parsed.caKeyId : null,
        caPublicKeyPem: typeof parsed.caPublicKeyPem === 'string' ? parsed.caPublicKeyPem : null,
        caCreatedAt: typeof parsed.caCreatedAt === 'string' ? parsed.caCreatedAt : null,
        certs: Array.isArray(parsed.certs) ? parsed.certs : [],
        revocations: parsed && parsed.revocations && typeof parsed.revocations === 'object' ? parsed.revocations : {}
      };
    } catch (e) {
      return {
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        trustDomain: DEFAULT_TRUST_DOMAIN,
        caKeyId: null,
        caPublicKeyPem: null,
        caCreatedAt: null,
        certs: [],
        revocations: {}
      };
    }
  }

  /** @param {MtlsMeshStoreState} state */
  _saveState(state) {
    const trimmedCerts = state.certs.length > MAX_STORED_CERTS
      ? state.certs.slice(-MAX_STORED_CERTS)
      : state.certs;
    const payload = {
      schemaVersion: 1,
      updatedAt: new Date().toISOString(),
      trustDomain: state.trustDomain,
      caKeyId: state.caKeyId,
      caPublicKeyPem: state.caPublicKeyPem,
      caCreatedAt: state.caCreatedAt,
      certs: trimmedCerts,
      revocations: state.revocations
    };
    atomicWriteFileSync(this.getStoreFilePath(), JSON.stringify(payload, null, 2) + '\n');
  }

  /**
   * Ensures an Ed25519 CA keypair exists on disk (`mtls-ca.key` mode `0o600`) and
   * returns the loaded state + private KeyObject for internal signing only.
   * @param {string} [requestedDomain]
   */
  _ensureCaInternal(requestedDomain) {
    const state = this._loadState();
    const keyPath = this.getCaKeyFilePath();
    const hasKeyFile = fs.existsSync(keyPath);

    if (hasKeyFile && state.caPublicKeyPem && state.caKeyId) {
      let updated = false;
      if (requestedDomain) {
        const cleanDomain = normalizeTrustDomain(requestedDomain);
        if (state.trustDomain !== cleanDomain) {
          state.trustDomain = cleanDomain;
          updated = true;
        }
      }
      if (updated) this._saveState(state);
      const privPem = fs.readFileSync(keyPath, 'utf8');
      const privateKey = crypto.createPrivateKey(privPem);
      return { state, privateKey, created: false };
    }

    const domain = normalizeTrustDomain(requestedDomain || state.trustDomain);
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const caPublicKeyPem = /** @type {string} */ (publicKey.export({ type: 'spki', format: 'pem' }));
    const caPrivateKeyPem = /** @type {string} */ (privateKey.export({ type: 'pkcs8', format: 'pem' }));
    const pubDer = /** @type {Buffer} */ (publicKey.export({ type: 'spki', format: 'der' }));
    const caKeyId = crypto.createHash('sha256').update(pubDer).digest('hex').slice(0, 16);
    const nowIso = new Date().toISOString();

    atomicWriteFileSync(keyPath, caPrivateKeyPem);
    state.trustDomain = domain;
    state.caKeyId = caKeyId;
    state.caPublicKeyPem = caPublicKeyPem;
    state.caCreatedAt = nowIso;
    this._saveState(state);

    return { state, privateKey, created: true };
  }

  /**
   * Initializes (or updates) the SPIFFE trust domain and Ed25519 CA keypair.
   * NEVER exposes the CA private key.
   *
   * @param {string} [domain]
   */
  initTrustDomain(domain = DEFAULT_TRUST_DOMAIN) {
    const { state, created } = this._ensureCaInternal(domain);
    return {
      ok: true,
      initialized: true,
      created,
      trustDomain: state.trustDomain,
      caKeyId: state.caKeyId,
      caPublicKeyPem: state.caPublicKeyPem,
      caCreatedAt: state.caCreatedAt
    };
  }

  /**
   * Issues a short-lived Ed25519-signed SPIFFE workload certificate descriptor.
   * TTL is strictly clamped to `1..168` hours. NEVER exposes any private key.
   *
   * @param {{
   *   serviceName: string,
   *   namespace?: string,
   *   ttlHours?: number,
   *   nowMs?: number
   * }} input
   */
  issueWorkloadCert(input) {
    if (!input || typeof input !== 'object') {
      throw mtlsError('INVALID_INPUT', 'issueWorkloadCert requires an options object');
    }
    const serviceName = normalizeSpiffeSegment(input.serviceName, 'serviceName', 'INVALID_SERVICE_NAME');
    const namespace = normalizeSpiffeSegment(input.namespace ?? 'prod', 'namespace', 'INVALID_NAMESPACE');
    const rawTtl = input.ttlHours === undefined ? 24 : Number(input.ttlHours);
    if (!Number.isFinite(rawTtl)) {
      throw mtlsError('INVALID_TTL', 'ttlHours must be a finite number');
    }
    const ttlHours = Math.max(MIN_TTL_HOURS, Math.min(MAX_TTL_HOURS, Math.round(rawTtl)));
    const nowMs = normalizeNowMs(input.nowMs);
    const expiresAtMs = nowMs + ttlHours * 3600000;

    const { state, privateKey } = this._ensureCaInternal();
    const serial = crypto.randomBytes(12).toString('hex');
    const spiffeId = `spiffe://${state.trustDomain}/ns/${namespace}/sa/${serviceName}`;

    // Generate workload Ed25519 public identity key (public material only embedded in descriptor)
    const workloadPair = crypto.generateKeyPairSync('ed25519');
    const subjectPublicKeyPem = /** @type {string} */ (workloadPair.publicKey.export({ type: 'spki', format: 'pem' }));
    const subjectPubDer = /** @type {Buffer} */ (workloadPair.publicKey.export({ type: 'spki', format: 'der' }));
    const subjectKeyThumbprint = crypto.createHash('sha256').update(subjectPubDer).digest('hex').slice(0, 32);

    /** @type {WorkloadCertDescriptor} */
    const cert = {
      version: 1,
      serial,
      spiffeId,
      trustDomain: state.trustDomain,
      serviceName,
      namespace,
      caKeyId: state.caKeyId || '',
      subjectPublicKeyPem,
      subjectKeyThumbprint,
      ttlHours,
      issuedAtMs: nowMs,
      issuedAt: new Date(nowMs).toISOString(),
      expiresAtMs,
      expiresAt: new Date(expiresAtMs).toISOString(),
      keyUsage: ['clientAuth', 'serverAuth']
    };

    const payload = Buffer.from(canonicalJson(cert), 'utf8');
    const signatureB64 = crypto.sign(null, payload, privateKey).toString('base64');

    /** @type {StoredCertRecord} */
    const record = {
      serial,
      spiffeId,
      trustDomain: state.trustDomain,
      serviceName,
      namespace,
      caKeyId: cert.caKeyId,
      subjectKeyThumbprint,
      ttlHours,
      issuedAtMs: nowMs,
      issuedAt: cert.issuedAt,
      expiresAtMs,
      expiresAt: cert.expiresAt,
      revoked: false,
      revokedAtMs: null,
      revokedAt: null,
      revocationReason: null,
      revokedBy: null
    };

    state.certs.push(record);
    this._saveState(state);

    return {
      ok: true,
      serial,
      spiffeId,
      trustDomain: state.trustDomain,
      serviceName,
      namespace,
      ttlHours,
      issuedAtMs: nowMs,
      expiresAtMs,
      caKeyId: cert.caKeyId,
      caPublicKeyPem: state.caPublicKeyPem,
      cert,
      signatureB64
    };
  }

  /**
   * Verifies a workload certificate's Ed25519 CA signature, CRL revocation status, and expiry window.
   *
   * @param {{
   *   cert: Record<string, any>,
   *   signatureB64: string,
   *   nowMs?: number
   * }} input
   */
  verifyWorkloadCert(input) {
    if (!input || typeof input !== 'object') {
      throw mtlsError('INVALID_INPUT', 'verifyWorkloadCert requires { cert, signatureB64 }');
    }
    const cert = input.cert;
    const signatureB64 = typeof input.signatureB64 === 'string' ? input.signatureB64.trim() : '';
    const nowMs = normalizeNowMs(input.nowMs);

    if (!cert || typeof cert !== 'object' || !signatureB64) {
      return {
        ok: true,
        valid: false,
        code: /** @type {'INVALID_CERT_FORMAT'} */ ('INVALID_CERT_FORMAT'),
        spiffeId: null,
        serial: null,
        remainingMs: 0
      };
    }

    const state = this._loadState();
    if (!state.caPublicKeyPem) {
      return {
        ok: true,
        valid: false,
        code: /** @type {'CA_NOT_INITIALIZED'} */ ('CA_NOT_INITIALIZED'),
        spiffeId: typeof cert.spiffeId === 'string' ? cert.spiffeId : null,
        serial: typeof cert.serial === 'string' ? cert.serial : null,
        remainingMs: 0
      };
    }

    const serial = typeof cert.serial === 'string' ? cert.serial : null;
    const spiffeId = typeof cert.spiffeId === 'string' ? cert.spiffeId : null;

    let sigOk = false;
    try {
      const pubKey = crypto.createPublicKey(state.caPublicKeyPem);
      const payload = Buffer.from(canonicalJson(cert), 'utf8');
      const sigBuf = Buffer.from(signatureB64, 'base64');
      sigOk = sigBuf.length > 0 && crypto.verify(null, payload, pubKey, sigBuf);
    } catch (e) {
      sigOk = false;
    }

    if (!sigOk) {
      return {
        ok: true,
        valid: false,
        code: /** @type {'INVALID_SIGNATURE'} */ ('INVALID_SIGNATURE'),
        spiffeId,
        serial,
        remainingMs: 0
      };
    }

    if (serial) {
      const crlEntry = state.revocations[serial];
      const storedRecord = state.certs.find((c) => c.serial === serial);
      if (crlEntry || (storedRecord && storedRecord.revoked)) {
        return {
          ok: true,
          valid: false,
          code: /** @type {'CERT_REVOKED'} */ ('CERT_REVOKED'),
          spiffeId,
          serial,
          remainingMs: 0,
          revokedAt: crlEntry ? crlEntry.revokedAt : (storedRecord ? storedRecord.revokedAt : null),
          revocationReason: crlEntry ? crlEntry.reason : (storedRecord ? storedRecord.revocationReason : null)
        };
      }
    }

    const issuedAtMs = Number(cert.issuedAtMs);
    const expiresAtMs = Number(cert.expiresAtMs);
    if (!Number.isFinite(issuedAtMs) || !Number.isFinite(expiresAtMs)) {
      return {
        ok: true,
        valid: false,
        code: /** @type {'INVALID_CERT_FORMAT'} */ ('INVALID_CERT_FORMAT'),
        spiffeId,
        serial,
        remainingMs: 0
      };
    }

    if (nowMs < issuedAtMs) {
      return {
        ok: true,
        valid: false,
        code: /** @type {'CERT_NOT_YET_VALID'} */ ('CERT_NOT_YET_VALID'),
        spiffeId,
        serial,
        remainingMs: 0
      };
    }

    if (nowMs >= expiresAtMs) {
      return {
        ok: true,
        valid: false,
        code: /** @type {'CERT_EXPIRED'} */ ('CERT_EXPIRED'),
        spiffeId,
        serial,
        remainingMs: 0
      };
    }

    return {
      ok: true,
      valid: true,
      code: /** @type {'CERT_VALID'} */ ('CERT_VALID'),
      spiffeId,
      serial,
      trustDomain: cert.trustDomain || state.trustDomain,
      remainingMs: Math.max(0, expiresAtMs - nowMs),
      expiresAt: cert.expiresAt || new Date(expiresAtMs).toISOString()
    };
  }

  /**
   * Revokes a workload certificate by `serial` and records it in the atomic CRL.
   *
   * @param {string} serial
   * @param {{ reason?: string, actor?: string, nowMs?: number }} [opts]
   */
  revokeWorkloadCert(serial, opts = {}) {
    const cleanSerial = typeof serial === 'string' ? serial.trim() : '';
    if (!cleanSerial) {
      throw mtlsError('INVALID_SERIAL', 'Certificate serial is required');
    }
    const safeOpts = opts && typeof opts === 'object' ? opts : {};
    const reason = typeof safeOpts.reason === 'string' && safeOpts.reason.trim()
      ? safeOpts.reason.trim().slice(0, 128)
      : 'manual_revoke';
    const actor = typeof safeOpts.actor === 'string' && safeOpts.actor.trim()
      ? safeOpts.actor.trim().slice(0, 128)
      : 'admin';
    const nowMs = normalizeNowMs(safeOpts.nowMs);
    const nowIso = new Date(nowMs).toISOString();

    const state = this._loadState();
    const record = state.certs.find((c) => c.serial === cleanSerial);
    if (!record) {
      throw mtlsError('CERT_NOT_FOUND', `Workload certificate "${cleanSerial}" not found`, 404);
    }

    record.revoked = true;
    record.revokedAtMs = nowMs;
    record.revokedAt = nowIso;
    record.revocationReason = reason;
    record.revokedBy = actor;
    state.revocations[cleanSerial] = {
      serial: cleanSerial,
      reason,
      actor,
      revokedAtMs: nowMs,
      revokedAt: nowIso
    };
    this._saveState(state);

    return {
      ok: true,
      revoked: true,
      serial: cleanSerial,
      spiffeId: record.spiffeId,
      reason,
      actor,
      revokedAtMs: nowMs,
      revokedAt: nowIso
    };
  }

  /**
   * Lists issued workload certificates (excluding revoked unless `includeRevoked: true`), newest first.
   * NEVER returns private keys.
   *
   * @param {{ includeRevoked?: boolean, nowMs?: number }} [opts]
   */
  listWorkloadCerts(opts = {}) {
    const safeOpts = opts && typeof opts === 'object' ? opts : {};
    const includeRevoked = Boolean(safeOpts.includeRevoked);
    const nowMs = normalizeNowMs(safeOpts.nowMs);

    const state = this._loadState();
    return state.certs
      .filter((c) => includeRevoked || !c.revoked)
      .map((c) => {
        const status = c.revoked
          ? 'revoked'
          : (nowMs >= c.expiresAtMs ? 'expired' : 'active');
        return {
          ...c,
          status,
          remainingMs: status === 'active' ? Math.max(0, c.expiresAtMs - nowMs) : 0
        };
      })
      .sort((a, b) => b.issuedAtMs - a.issuedAtMs);
  }

  /**
   * Compiles a Caddy v2.11 TLS `client_authentication` JSON policy (`require_and_verify`).
   * Includes ONLY the CA public key PEM — NEVER any private key.
   *
   * @param {{ allowedSpiffeIds?: string[], mode?: string }} [opts]
   */
  compileCaddyMtlsPolicy(opts = {}) {
    const safeOpts = opts && typeof opts === 'object' ? opts : {};
    const mode = typeof safeOpts.mode === 'string' && safeOpts.mode.trim()
      ? safeOpts.mode.trim().toLowerCase()
      : 'require_and_verify';
    if (!VALID_CADDY_MODES.has(mode)) {
      throw mtlsError('INVALID_MTLS_MODE', `mode must be one of: ${Array.from(VALID_CADDY_MODES).join(', ')}`);
    }

    const { state } = this._ensureCaInternal();
    const rawIds = Array.isArray(safeOpts.allowedSpiffeIds) ? safeOpts.allowedSpiffeIds : [];
    const allowedSpiffeIds = Array.from(
      new Set(
        rawIds
          .filter((id) => typeof id === 'string' && id.trim().startsWith('spiffe://'))
          .map((id) => id.trim().slice(0, 256))
      )
    );

    const caPublicKeyPem = state.caPublicKeyPem || '';
    const caddyClientAuth = {
      mode,
      trusted_ca_certificates_pem: [caPublicKeyPem],
      verifiers: [
        {
          verifier: 'spiffe_identity',
          trust_domain: state.trustDomain,
          ca_key_id: state.caKeyId,
          allowed_spiffe_ids: allowedSpiffeIds
        }
      ]
    };

    return {
      ok: true,
      mode,
      trustDomain: state.trustDomain,
      caKeyId: state.caKeyId,
      allowedSpiffeIds,
      caPublicKeyPem,
      caddyClientAuth
    };
  }
}

const defaultMtlsMeshService = new MtlsMeshService();

const exported = Object.assign(defaultMtlsMeshService, {
  MtlsMeshService,
  DEFAULT_TRUST_DOMAIN,
  initTrustDomain: MtlsMeshService.prototype.initTrustDomain.bind(defaultMtlsMeshService),
  issueWorkloadCert: MtlsMeshService.prototype.issueWorkloadCert.bind(defaultMtlsMeshService),
  verifyWorkloadCert: MtlsMeshService.prototype.verifyWorkloadCert.bind(defaultMtlsMeshService),
  revokeWorkloadCert: MtlsMeshService.prototype.revokeWorkloadCert.bind(defaultMtlsMeshService),
  listWorkloadCerts: MtlsMeshService.prototype.listWorkloadCerts.bind(defaultMtlsMeshService),
  compileCaddyMtlsPolicy: MtlsMeshService.prototype.compileCaddyMtlsPolicy.bind(defaultMtlsMeshService)
});

module.exports = exported;
