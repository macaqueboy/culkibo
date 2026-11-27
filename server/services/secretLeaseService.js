'use strict';

/**
 * Culkibo Zero-Dep Ephemeral Secret Leases, 90-Day Rotation Audit & 15-Min Break-Glass Service.
 *
 * Security Guarantees:
 *  - 0 external npm dependencies (Node built-ins only: crypto, fs, path).
 *  - Stores ONLY HMAC-SHA256 digests of lease tokens in `CULKIBO_DATA_DIR/data/secret-leases.json`
 *    (`0o600` atomic writes) — ZERO plaintext tokens or secret values are EVER stored on disk.
 *  - Raw one-time lease tokens (`ckl_...` / `ckbg_...`) are returned ONCE at issuance time.
 *  - Constant-time HMAC validation fails closed on expired or revoked leases.
 *  - Break-Glass tokens require an audited `reason` (>= 10 chars), hard-cap TTL at `<= 900s` (15m),
 *    cannot be renewed, and immediately dispatch audit + alert notifications.
 *  - Secret rotation auditing inspects ONLY key names & timestamps (zero plaintext values).
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MIN_LEASE_TTL_SEC = 60;
const MAX_LEASE_TTL_SEC = 86400; // 24 hours
const MAX_BREAK_GLASS_TTL_SEC = 900; // 15 minutes hard cap
const DEFAULT_ROTATION_MAX_AGE_DAYS = 90;
const ALLOWED_SCOPES = new Set(['read', 'write', 'rotate', 'admin', 'break_glass']);
const SECRET_KEY_RE = /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/;

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
 * Strips internal hash fields before returning lease metadata to callers/APIs.
 * @param {any} raw
 * @param {number} [nowMs]
 */
function toPublicLease(raw, nowMs = Date.now()) {
  const expired = !raw.revokedAt && nowMs >= raw.expiresAtMs;
  const status = raw.revokedAt ? 'revoked' : (expired ? 'expired' : 'active');
  return {
    id: raw.id,
    kind: raw.kind || 'secret_lease',
    projectId: raw.projectId,
    secretKey: raw.secretKey,
    scope: raw.scope,
    tokenPrefix: raw.tokenPrefix,
    issuedBy: raw.issuedBy,
    reason: raw.reason || '',
    ttlSec: raw.ttlSec,
    createdAt: raw.createdAt,
    expiresAt: raw.expiresAt,
    expiresAtMs: raw.expiresAtMs,
    remainingSec: status === 'active' ? Math.max(0, Math.floor((raw.expiresAtMs - nowMs) / 1000)) : 0,
    revokedAt: raw.revokedAt || null,
    revokedBy: raw.revokedBy || null,
    status
  };
}

class SecretLeaseService {
  /**
   * @param {{ dataDir?: string | null, auditFn?: ((event: string, meta: Record<string, any>) => void) | null }} [opts]
   */
  constructor(opts = {}) {
    /** @type {string | null} */
    this._explicitDataDir = opts && typeof opts.dataDir === 'string' && opts.dataDir.trim()
      ? path.resolve(opts.dataDir.trim())
      : null;
    /** @type {((event: string, meta: Record<string, any>) => void) | null} */
    this._auditFn = typeof opts.auditFn === 'function' ? opts.auditFn : null;
    /** @type {{ pepperPath: string, key: Buffer } | null} */
    this._pepperCache = null;
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
    return path.join(this.resolveDataDir(), 'secret-leases.json');
  }

  /** @returns {Buffer} */
  _getPepper() {
    const pepperPath = path.join(this.resolveDataDir(), '.secret-leases.pepper');
    if (this._pepperCache && this._pepperCache.pepperPath === pepperPath) {
      return this._pepperCache.key;
    }
    if (fs.existsSync(pepperPath)) {
      try {
        const hex = fs.readFileSync(pepperPath, 'utf8').trim();
        if (/^[0-9a-f]{64}$/i.test(hex)) {
          const key = Buffer.from(hex, 'hex');
          this._pepperCache = { pepperPath, key };
          return key;
        }
      } catch (e) {}
    }
    const key = crypto.randomBytes(32);
    atomicWriteFileSync(pepperPath, key.toString('hex') + '\n');
    this._pepperCache = { pepperPath, key };
    return key;
  }

  /**
   * Computes HMAC-SHA256 hex digest of a raw lease token.
   * @param {string} rawToken
   * @returns {string}
   */
  _hashToken(rawToken) {
    return crypto.createHmac('sha256', this._getPepper()).update(String(rawToken || ''), 'utf8').digest('hex');
  }

  /** @returns {Array<any>} */
  _loadLeases() {
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) return [];
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (parsed && Array.isArray(parsed.leases)) return parsed.leases;
      return [];
    } catch (e) {
      return [];
    }
  }

  /** @param {Array<any>} leases */
  _saveLeases(leases) {
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({ schemaVersion: 1, updatedAt: new Date().toISOString(), leases }, null, 2) + '\n'
    );
  }

  /**
   * Dispatches audit event (never writes to repo-root data/ during unisolated tests).
   * @param {string} action
   * @param {Record<string, any>} detail
   */
  _audit(action, detail) {
    if (this._auditFn) {
      try { this._auditFn(action, detail); } catch (e) {}
      return;
    }
    if (process.env.NODE_ENV === 'test' && !process.env.CULKIBO_DATA_DIR && !this._explicitDataDir) return;
    try {
      const auditLogger = require('./auditLogger');
      if (auditLogger && typeof auditLogger.record === 'function') {
        auditLogger.record({
          source: 'system',
          action,
          resourceId: detail.leaseId || detail.projectId || 'secret-lease',
          actor: detail.actor || detail.issuedBy || 'system',
          detail
        });
      }
    } catch (e) {}
  }

  /**
   * Issues a time-bounded ephemeral secret lease (TTL clamped 60..86400s).
   * Stores ONLY the HMAC-SHA256 digest on disk; returns the raw one-time `ckl_...` token ONCE.
   *
   * @param {{
   *   projectId: string,
   *   secretKey: string,
   *   scope?: string,
   *   ttlSec?: number,
   *   issuedBy?: string,
   *   reason?: string,
   *   nowMs?: number
   * }} opts
   */
  issueLease(opts) {
    if (!opts || typeof opts !== 'object') {
      const err = /** @type {any} */ (new Error('issueLease requires an options object'));
      err.code = 'INVALID_REQUEST';
      err.status = 400;
      throw err;
    }
    const projectId = String(opts.projectId || '').trim().slice(0, 128);
    if (!projectId) {
      const err = /** @type {any} */ (new Error('projectId is required'));
      err.code = 'INVALID_PROJECT_ID';
      err.status = 400;
      throw err;
    }
    const secretKey = String(opts.secretKey || '').trim();
    if (!SECRET_KEY_RE.test(secretKey)) {
      const err = /** @type {any} */ (new Error(`Invalid secretKey: "${secretKey.slice(0, 48)}"`));
      err.code = 'INVALID_SECRET_KEY';
      err.status = 400;
      throw err;
    }
    const scopeRaw = String(opts.scope || 'read').trim().toLowerCase();
    const scope = ALLOWED_SCOPES.has(scopeRaw) && scopeRaw !== 'break_glass' ? scopeRaw : 'read';
    const rawTtl = Number(opts.ttlSec);
    const ttlSec = Number.isFinite(rawTtl)
      ? Math.max(MIN_LEASE_TTL_SEC, Math.min(MAX_LEASE_TTL_SEC, Math.round(rawTtl)))
      : 3600;
    const nowMs = Number.isFinite(Number(opts.nowMs)) ? Number(opts.nowMs) : Date.now();
    const expiresAtMs = nowMs + ttlSec * 1000;

    const id = `lease_${nowMs}_${crypto.randomBytes(4).toString('hex')}`;
    const token = `ckl_${crypto.randomBytes(24).toString('base64url')}`;
    const tokenHash = this._hashToken(token);
    const issuedBy = String(opts.issuedBy || 'system').trim().slice(0, 128);
    const reason = String(opts.reason || '').trim().slice(0, 300);

    const record = {
      id,
      kind: 'secret_lease',
      projectId,
      secretKey,
      scope,
      tokenHash,
      tokenPrefix: `${token.slice(0, 10)}...`,
      issuedBy,
      reason,
      ttlSec,
      createdAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(expiresAtMs).toISOString(),
      expiresAtMs,
      revokedAt: null,
      revokedBy: null
    };

    const leases = this._loadLeases();
    leases.unshift(record);
    this._saveLeases(leases.slice(0, 500));

    this._audit('security.secret_lease.issued', {
      leaseId: id,
      projectId,
      secretKey,
      scope,
      ttlSec,
      actor: issuedBy
    });

    return {
      lease: toPublicLease(record, nowMs),
      token
    };
  }

  /**
   * Constant-time HMAC lookup & validation of an ephemeral lease or break-glass token.
   * Fails closed (`EXPIRED` | `REVOKED` | `NOT_FOUND`).
   *
   * @param {string | null | undefined} token
   * @param {{ nowMs?: number }} [opts]
   */
  validateLease(token, opts = {}) {
    const raw = typeof token === 'string' ? token.trim() : '';
    if (!raw || raw.length < 16) {
      return { valid: false, reason: 'NOT_FOUND', lease: null };
    }
    const nowMs = Number.isFinite(Number(opts.nowMs)) ? Number(opts.nowMs) : Date.now();
    const candidateBuf = Buffer.from(this._hashToken(raw), 'hex');
    const leases = this._loadLeases();

    /** @type {any} */
    let matched = null;
    for (const rec of leases) {
      if (!rec || typeof rec.tokenHash !== 'string' || rec.tokenHash.length !== 64) continue;
      const storedBuf = Buffer.from(rec.tokenHash, 'hex');
      if (storedBuf.length === candidateBuf.length && crypto.timingSafeEqual(storedBuf, candidateBuf)) {
        matched = rec;
      }
    }

    if (!matched) {
      return { valid: false, reason: 'NOT_FOUND', lease: null };
    }
    const pub = toPublicLease(matched, nowMs);
    if (matched.revokedAt) {
      return { valid: false, reason: 'REVOKED', lease: pub };
    }
    if (nowMs >= matched.expiresAtMs) {
      return { valid: false, reason: 'EXPIRED', lease: pub };
    }
    return { valid: true, reason: 'OK', lease: pub, remainingSec: pub.remainingSec };
  }

  /**
   * Extends an active non-break-glass lease cleanly.
   * @param {string} leaseId
   * @param {{ extendSec?: number, nowMs?: number }} [opts]
   */
  renewLease(leaseId, opts = {}) {
    const nowMs = Number.isFinite(Number(opts.nowMs)) ? Number(opts.nowMs) : Date.now();
    const extendSec = Number.isFinite(Number(opts.extendSec))
      ? Math.max(MIN_LEASE_TTL_SEC, Math.min(MAX_LEASE_TTL_SEC, Math.round(Number(opts.extendSec))))
      : 3600;
    const leases = this._loadLeases();
    const idx = leases.findIndex((l) => l.id === String(leaseId || '').trim());
    if (idx === -1) return { ok: false, reason: 'NOT_FOUND' };
    const rec = leases[idx];
    if (rec.kind === 'break_glass') return { ok: false, reason: 'BREAK_GLASS_NON_RENEWABLE' };
    if (rec.revokedAt) return { ok: false, reason: 'REVOKED' };
    if (nowMs >= rec.expiresAtMs) return { ok: false, reason: 'EXPIRED' };

    const maxAllowedMs = nowMs + MAX_LEASE_TTL_SEC * 1000;
    const nextExp = Math.min(maxAllowedMs, Math.max(rec.expiresAtMs, nowMs) + extendSec * 1000);
    rec.expiresAtMs = nextExp;
    rec.expiresAt = new Date(nextExp).toISOString();
    rec.ttlSec = Math.round((nextExp - Date.parse(rec.createdAt)) / 1000);
    leases[idx] = rec;
    this._saveLeases(leases);

    return { ok: true, lease: toPublicLease(rec, nowMs) };
  }

  /**
   * Revokes a lease or break-glass token immediately.
   * @param {string} leaseId
   * @param {{ revokedBy?: string, nowMs?: number }} [opts]
   */
  revokeLease(leaseId, opts = {}) {
    const nowMs = Number.isFinite(Number(opts.nowMs)) ? Number(opts.nowMs) : Date.now();
    const leases = this._loadLeases();
    const idx = leases.findIndex((l) => l.id === String(leaseId || '').trim());
    if (idx === -1) return { ok: false, revoked: false, reason: 'NOT_FOUND' };
    const rec = leases[idx];
    if (!rec.revokedAt) {
      rec.revokedAt = new Date(nowMs).toISOString();
      rec.revokedBy = String(opts.revokedBy || 'admin').trim().slice(0, 128);
      leases[idx] = rec;
      this._saveLeases(leases);
      this._audit('security.secret_lease.revoked', {
        leaseId: rec.id,
        projectId: rec.projectId,
        secretKey: rec.secretKey,
        actor: rec.revokedBy
      });
    }
    return { ok: true, revoked: true, lease: toPublicLease(rec, nowMs) };
  }

  /**
   * Lists persisted leases (without ever exposing `tokenHash` or raw tokens).
   * @param {{ projectId?: string | null, includeExpired?: boolean, nowMs?: number }} [opts]
   */
  listLeases(opts = {}) {
    const nowMs = Number.isFinite(Number(opts.nowMs)) ? Number(opts.nowMs) : Date.now();
    const includeExpired = Boolean(opts.includeExpired);
    const filterProject = opts.projectId ? String(opts.projectId).trim() : null;
    const all = this._loadLeases().map((rec) => toPublicLease(rec, nowMs));
    return all.filter((l) => {
      if (filterProject && l.projectId !== filterProject) return false;
      if (!includeExpired && l.status !== 'active') return false;
      return true;
    });
  }

  /**
   * Sweeps expired leases and prunes records expired for more than 30 days.
   * @param {number} [nowMs]
   */
  sweepExpiredLeases(nowMs = Date.now()) {
    const leases = this._loadLeases();
    const pruneCutoff = nowMs - 30 * 24 * 60 * 60 * 1000;
    let expiredCount = 0;
    let activeCount = 0;
    const retained = [];
    for (const rec of leases) {
      const isExpired = !rec.revokedAt && nowMs >= rec.expiresAtMs;
      if (isExpired) expiredCount++;
      if (!rec.revokedAt && nowMs < rec.expiresAtMs) activeCount++;
      if (rec.expiresAtMs >= pruneCutoff || !isExpired) {
        retained.push(rec);
      }
    }
    if (retained.length !== leases.length) {
      this._saveLeases(retained);
    }
    return {
      sweptCount: expiredCount,
      prunedCount: leases.length - retained.length,
      activeCount,
      totalCount: retained.length
    };
  }

  /**
   * Issues an audited, non-renewable emergency Break-Glass token (hard-capped <= 900s / 15 min).
   * Requires a written incident `reason` of at least 10 characters and dispatches immediate alerts.
   *
   * @param {{
   *   userId: string,
   *   username?: string,
   *   reason: string,
   *   ttlSec?: number,
   *   onAlert?: ((payload: Record<string, any>) => void) | null,
   *   nowMs?: number
   * }} opts
   */
  issueBreakGlassToken(opts) {
    if (!opts || typeof opts !== 'object') {
      const err = /** @type {any} */ (new Error('issueBreakGlassToken requires an options object'));
      err.code = 'INVALID_REQUEST';
      err.status = 400;
      throw err;
    }
    const reason = String(opts.reason || '').trim();
    if (reason.length < 10) {
      const err = /** @type {any} */ (new Error('Break-glass requires an explicit incident reason of at least 10 characters'));
      err.code = 'INVALID_BREAK_GLASS_REASON';
      err.status = 400;
      throw err;
    }
    const userId = String(opts.userId || opts.username || '').trim();
    if (!userId) {
      const err = /** @type {any} */ (new Error('Break-glass requires userId'));
      err.code = 'INVALID_USER';
      err.status = 400;
      throw err;
    }
    const username = String(opts.username || userId).trim().slice(0, 128);
    const rawTtl = Number(opts.ttlSec);
    // Hard-clamp TTL <= 900 seconds (15 minutes maximum!)
    const ttlSec = Number.isFinite(rawTtl)
      ? Math.max(MIN_LEASE_TTL_SEC, Math.min(MAX_BREAK_GLASS_TTL_SEC, Math.round(rawTtl)))
      : MAX_BREAK_GLASS_TTL_SEC;
    const nowMs = Number.isFinite(Number(opts.nowMs)) ? Number(opts.nowMs) : Date.now();
    const expiresAtMs = nowMs + ttlSec * 1000;

    const id = `bg_${nowMs}_${crypto.randomBytes(4).toString('hex')}`;
    const token = `ckbg_${crypto.randomBytes(24).toString('base64url')}`;
    const tokenHash = this._hashToken(token);

    const record = {
      id,
      kind: 'break_glass',
      projectId: '*',
      secretKey: 'BREAK_GLASS_ADMIN',
      scope: 'break_glass',
      tokenHash,
      tokenPrefix: `${token.slice(0, 11)}...`,
      issuedBy: username,
      userId,
      reason: reason.slice(0, 500),
      ttlSec,
      createdAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(expiresAtMs).toISOString(),
      expiresAtMs,
      revokedAt: null,
      revokedBy: null
    };

    const leases = this._loadLeases();
    leases.unshift(record);
    this._saveLeases(leases.slice(0, 500));

    const alertPayload = {
      type: 'break_glass_issued',
      severity: 'critical',
      leaseId: id,
      userId,
      username,
      reason: record.reason,
      ttlSec,
      expiresAt: record.expiresAt,
      createdAt: record.createdAt
    };

    this._audit('security.break_glass.issued', { ...alertPayload, actor: username });

    let alertDispatched = false;
    if (typeof opts.onAlert === 'function') {
      try {
        opts.onAlert(alertPayload);
        alertDispatched = true;
      } catch (e) {}
    }
    if (!alertDispatched && (process.env.NODE_ENV !== 'test' || process.env.CULKIBO_DATA_DIR || this._explicitDataDir)) {
      try {
        const alertEngine = require('./alertEngine');
        if (alertEngine && typeof alertEngine.emit === 'function') {
          alertEngine.emit('security_alert', alertPayload);
          alertDispatched = true;
        }
      } catch (e) {}
    }

    return {
      lease: toPublicLease(record, nowMs),
      token,
      alertDispatched
    };
  }

  /**
   * Audits secret rotation ages across projects using ONLY key names & timestamps
   * (strictly NEVER reading, returning, or logging plaintext secret values).
   *
   * @param {Array<any>} projects
   * @param {{ maxAgeDays?: number, nowMs?: number }} [opts]
   */
  auditSecretRotationAges(projects, opts = {}) {
    const maxAgeDays = Number.isFinite(Number(opts.maxAgeDays)) && Number(opts.maxAgeDays) >= 1
      ? Math.round(Number(opts.maxAgeDays))
      : DEFAULT_ROTATION_MAX_AGE_DAYS;
    const nowMs = Number.isFinite(Number(opts.nowMs)) ? Number(opts.nowMs) : Date.now();
    const list = Array.isArray(projects) ? projects : [];

    let totalKeys = 0;
    /** @type {Array<{ projectId: string, projectName: string, key: string, ageDays: number, lastUpdatedAt: string, severity: 'critical' | 'high' | 'medium' }>} */
    const staleKeys = [];

    for (const proj of list) {
      if (!proj || typeof proj !== 'object') continue;
      const projectId = String(proj.id || proj.projectId || 'unknown');
      const projectName = String(proj.name || projectId);
      const fallbackIso = proj.secretsUpdatedAt || proj.envUpdatedAt || proj.updatedAt || proj.createdAt || new Date(nowMs).toISOString();
      const fallbackMs = Number.isFinite(Date.parse(fallbackIso)) ? Date.parse(fallbackIso) : nowMs;

      /** @type {Map<string, number>} */
      const keyTimestamps = new Map();

      // 1. Structured metadata `{ envMeta: { KEY: { updatedAt } } }` or `secretUpdatedAt: { KEY: iso }`
      const metaObj = proj.envMeta || proj.secretsMeta || proj.secretUpdatedAt || null;
      if (metaObj && typeof metaObj === 'object') {
        for (const [k, meta] of Object.entries(metaObj)) {
          if (!k) continue;
          const tsRaw = typeof meta === 'string' || typeof meta === 'number'
            ? meta
            : (meta && typeof meta === 'object' ? (meta.updatedAt || meta.rotatedAt || meta.createdAt) : null);
          const parsed = typeof tsRaw === 'number' ? tsRaw : Date.parse(String(tsRaw || ''));
          keyTimestamps.set(k, Number.isFinite(parsed) ? parsed : fallbackMs);
        }
      }

      // 2. Also inspect key NAMES ONLY from `env` / `envVars` (NEVER touch values!)
      const envObj = proj.env || proj.envVars || null;
      if (envObj && typeof envObj === 'object' && !Array.isArray(envObj)) {
        for (const k of Object.keys(envObj)) {
          if (k && !keyTimestamps.has(k)) {
            keyTimestamps.set(k, fallbackMs);
          }
        }
      } else if (Array.isArray(envObj)) {
        for (const entry of envObj) {
          const k = typeof entry === 'string' ? entry.split('=')[0] : (entry && entry.key);
          if (k && !keyTimestamps.has(k)) {
            const ts = entry && typeof entry === 'object' && entry.updatedAt ? Date.parse(entry.updatedAt) : fallbackMs;
            keyTimestamps.set(String(k), Number.isFinite(ts) ? ts : fallbackMs);
          }
        }
      }

      for (const [key, updatedMs] of keyTimestamps.entries()) {
        totalKeys++;
        const ageDays = Math.max(0, Math.floor((nowMs - updatedMs) / (24 * 60 * 60 * 1000)));
        if (ageDays > maxAgeDays) {
          const severity = ageDays >= maxAgeDays * 2 ? 'critical' : (ageDays >= Math.round(maxAgeDays * 1.5) ? 'high' : 'medium');
          staleKeys.push({
            projectId,
            projectName,
            key,
            ageDays,
            lastUpdatedAt: new Date(updatedMs).toISOString(),
            severity
          });
        }
      }
    }

    staleKeys.sort((a, b) => b.ageDays - a.ageDays);

    return {
      maxAgeDays,
      auditedAt: new Date(nowMs).toISOString(),
      totalKeys,
      staleCount: staleKeys.length,
      freshCount: Math.max(0, totalKeys - staleKeys.length),
      staleKeys
    };
  }
}

const defaultSecretLeaseService = new SecretLeaseService();

const exported = Object.assign(defaultSecretLeaseService, {
  SecretLeaseService,
  MAX_BREAK_GLASS_TTL_SEC,
  DEFAULT_ROTATION_MAX_AGE_DAYS,
  MIN_LEASE_TTL_SEC,
  MAX_LEASE_TTL_SEC
});

module.exports = exported;
