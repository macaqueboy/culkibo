'use strict';

/**
 * Culkibo Distributed Cron Idempotency & Fencing-Token Lease Guard.
 *
 * Eliminates duplicate/overlapping cron execution across multi-replica deployments,
 * slow overlapping runs, and timezone/worker offset races (`coolify#5655`, `dokploy#1475`):
 *  - Atomic `0o600` store in `CULKIBO_DATA_DIR/data/cron-leases.json` (dynamic path resolution).
 *  - Monotonic integer `fencingToken++` per `jobId` (Martin Kleppmann fencing-token semantics).
 *  - Rejects concurrent active (non-expired) lease for the same `jobId` (`ALREADY_RUNNING`).
 *  - Rejects repeat execution of an already-succeeded `scheduleSlotIso` (`ALREADY_EXECUTED_SLOT`).
 *  - Automatically reclaims expired TTL leases (`expiresAtMs <= nowMs`), issuing a higher `fencingToken`.
 *  - Rejects zombie/stale `fencingToken` or mismatched `holderId` on `completeCronLease` & `renewCronLease`.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DEFAULT_TTL_SEC = 300;
const MIN_TTL_SEC = 1;
const MAX_TTL_SEC = 86400;
const MAX_HISTORY_PER_JOB = 250;

/**
 * @typedef {'active' | 'succeeded' | 'failed' | 'expired'} CronLeaseStatus
 */

/**
 * @typedef {object} CronLeaseRecord
 * @property {string} leaseId
 * @property {string} jobId
 * @property {string | null} scheduleSlotIso
 * @property {string} holderId
 * @property {number} fencingToken
 * @property {CronLeaseStatus} status
 * @property {number} ttlSec
 * @property {number} acquiredAtMs
 * @property {string} acquiredAt
 * @property {number} expiresAtMs
 * @property {string} expiresAt
 * @property {number | null} renewedAtMs
 * @property {number | null} completedAtMs
 * @property {string | null} completedAt
 * @property {number | null} expiredAtMs
 * @property {string | null} reclaimedFromLeaseId
 */

/**
 * @typedef {object} CronLeaseStoreState
 * @property {number} schemaVersion
 * @property {string} updatedAt
 * @property {Record<string, number>} counters
 * @property {CronLeaseRecord[]} leases
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
 * Creates an HTTP-annotated validation Error.
 * @param {string} code
 * @param {string} msg
 * @param {number} [status]
 */
function leaseError(code, msg, status = 400) {
  const err = /** @type {any} */ (new Error(msg));
  err.code = code;
  err.status = status;
  return err;
}

/**
 * Computes a canonical schedule slot comparison key so `2026-11-27T00:00:00Z`
 * and `2026-11-27T00:00:00.000Z` match identically while preserving arbitrary slot strings.
 * @param {string | null | undefined} slot
 * @returns {string | null}
 */
function canonicalSlotKey(slot) {
  if (typeof slot !== 'string') return null;
  const trimmed = slot.trim();
  if (!trimmed) return null;
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(trimmed)) {
    const parsed = Date.parse(trimmed);
    if (Number.isFinite(parsed)) {
      return new Date(parsed).toISOString();
    }
  }
  return trimmed;
}

/**
 * Validates and clamps a TTL/extension duration in seconds.
 * @param {any} raw
 * @param {number} [fallback]
 * @returns {number}
 */
function normalizeTtlSec(raw, fallback = DEFAULT_TTL_SEC) {
  const value = raw === undefined || raw === null ? fallback : Number(raw);
  if (!Number.isFinite(value) || value < MIN_TTL_SEC || value > MAX_TTL_SEC) {
    throw leaseError('INVALID_TTL', `ttlSec/extendSec must be between ${MIN_TTL_SEC} and ${MAX_TTL_SEC} seconds`);
  }
  return Math.round(value);
}

/**
 * Normalizes a timestamp in epoch milliseconds.
 * @param {any} raw
 * @returns {number}
 */
function normalizeNowMs(raw) {
  if (raw === undefined || raw === null) return Date.now();
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) {
    throw leaseError('INVALID_TIMESTAMP', 'nowMs must be a finite non-negative epoch millisecond number');
  }
  return Math.floor(n);
}

/**
 * Normalizes a non-empty identifier string.
 * @param {any} raw
 * @param {string} field
 * @param {string} code
 * @returns {string}
 */
function requireId(raw, field, code) {
  const val = typeof raw === 'string' ? raw.trim().slice(0, 128) : '';
  if (!val) {
    throw leaseError(code, `${field} is required`);
  }
  return val;
}

class CronLeaseService {
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
    return path.join(this.resolveDataDir(), 'cron-leases.json');
  }

  /** @returns {CronLeaseStoreState} */
  _loadState() {
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) {
      return {
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        counters: {},
        leases: []
      };
    }
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      const counters = parsed && parsed.counters && typeof parsed.counters === 'object'
        ? parsed.counters
        : {};
      const leases = parsed && Array.isArray(parsed.leases) ? parsed.leases : [];
      return {
        schemaVersion: 1,
        updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : new Date().toISOString(),
        counters,
        leases
      };
    } catch (e) {
      return {
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        counters: {},
        leases: []
      };
    }
  }

  /**
   * Prunes very old inactive records per job while retaining all active leases and
   * recent succeeded slot receipts, then persists atomically with mode `0o600`.
   * @param {CronLeaseStoreState} state
   */
  _saveState(state) {
    /** @type {Record<string, CronLeaseRecord[]>} */
    const byJob = {};
    for (const lease of state.leases) {
      if (!byJob[lease.jobId]) byJob[lease.jobId] = [];
      byJob[lease.jobId].push(lease);
    }

    /** @type {CronLeaseRecord[]} */
    const compacted = [];
    for (const jobLeases of Object.values(byJob)) {
      if (jobLeases.length <= MAX_HISTORY_PER_JOB) {
        compacted.push(...jobLeases);
        continue;
      }
      const active = jobLeases.filter((l) => l.status === 'active');
      const inactive = jobLeases
        .filter((l) => l.status !== 'active')
        .sort((a, b) => (b.acquiredAtMs - a.acquiredAtMs) || (b.fencingToken - a.fencingToken))
        .slice(0, Math.max(0, MAX_HISTORY_PER_JOB - active.length));
      compacted.push(...active, ...inactive);
    }

    const payload = {
      schemaVersion: 1,
      updatedAt: new Date().toISOString(),
      counters: state.counters,
      leases: compacted
    };
    atomicWriteFileSync(this.getStoreFilePath(), JSON.stringify(payload, null, 2) + '\n');
  }

  /**
   * Acquires an exclusive fencing-token lease for a cron job & schedule slot.
   *
   * @param {{
   *   jobId: string,
   *   scheduleSlotIso?: string | null,
   *   holderId?: string,
   *   ttlSec?: number,
   *   nowMs?: number
   * }} input
   */
  acquireCronLease(input) {
    if (!input || typeof input !== 'object') {
      throw leaseError('INVALID_INPUT', 'acquireCronLease requires an options object');
    }

    const jobId = requireId(input.jobId, 'jobId', 'INVALID_JOB_ID');
    const holderId = typeof input.holderId === 'string' && input.holderId.trim()
      ? input.holderId.trim().slice(0, 128)
      : 'worker-default';
    const ttlSec = normalizeTtlSec(input.ttlSec, DEFAULT_TTL_SEC);
    const nowMs = normalizeNowMs(input.nowMs);
    const rawSlot = typeof input.scheduleSlotIso === 'string' && input.scheduleSlotIso.trim()
      ? input.scheduleSlotIso.trim().slice(0, 128)
      : null;
    const slotKey = canonicalSlotKey(rawSlot);

    const state = this._loadState();

    /** @type {CronLeaseRecord | null} */
    let reclaimedLease = null;
    let mutated = false;

    // 1. Reclaim any expired active leases for this job
    for (const lease of state.leases) {
      if (lease.jobId === jobId && lease.status === 'active' && lease.expiresAtMs <= nowMs) {
        lease.status = 'expired';
        lease.expiredAtMs = nowMs;
        reclaimedLease = lease;
        mutated = true;
      }
    }

    // 2. Slot idempotency guard: reject duplicate execution of an already-succeeded scheduleSlotIso
    if (slotKey) {
      const completedLease = state.leases.find(
        (l) => l.jobId === jobId && l.status === 'succeeded' && canonicalSlotKey(l.scheduleSlotIso) === slotKey
      );
      if (completedLease) {
        if (mutated) this._saveState(state);
        return {
          ok: false,
          acquired: false,
          reason: /** @type {'ALREADY_EXECUTED_SLOT'} */ ('ALREADY_EXECUTED_SLOT'),
          jobId,
          scheduleSlotIso: rawSlot,
          completedLease: { ...completedLease }
        };
      }
    }

    // 3. Concurrency guard: reject overlapping active non-expired lease for the same jobId
    const activeLease = state.leases.find(
      (l) => l.jobId === jobId && l.status === 'active' && l.expiresAtMs > nowMs
    );
    if (activeLease) {
      if (mutated) this._saveState(state);
      return {
        ok: false,
        acquired: false,
        reason: /** @type {'ALREADY_RUNNING'} */ ('ALREADY_RUNNING'),
        jobId,
        scheduleSlotIso: rawSlot,
        activeLease: { ...activeLease }
      };
    }

    // 4. Issue monotonic fencing token and persist active lease atomically
    const prevCounter = Number.isInteger(state.counters[jobId]) ? state.counters[jobId] : 0;
    const fencingToken = prevCounter + 1;
    state.counters[jobId] = fencingToken;

    const expiresAtMs = nowMs + ttlSec * 1000;
    /** @type {CronLeaseRecord} */
    const lease = {
      leaseId: `cl_${crypto.randomBytes(8).toString('hex')}`,
      jobId,
      scheduleSlotIso: rawSlot,
      holderId,
      fencingToken,
      status: 'active',
      ttlSec,
      acquiredAtMs: nowMs,
      acquiredAt: new Date(nowMs).toISOString(),
      expiresAtMs,
      expiresAt: new Date(expiresAtMs).toISOString(),
      renewedAtMs: null,
      completedAtMs: null,
      completedAt: null,
      expiredAtMs: null,
      reclaimedFromLeaseId: reclaimedLease ? reclaimedLease.leaseId : null
    };

    state.leases.push(lease);
    this._saveState(state);

    return {
      ok: true,
      acquired: true,
      reason: reclaimedLease ? 'RECLAIMED_EXPIRED_LEASE' : 'ACQUIRED',
      reclaimed: Boolean(reclaimedLease),
      leaseId: lease.leaseId,
      fencingToken: lease.fencingToken,
      lease: { ...lease }
    };
  }

  /**
   * Extends the TTL of an active lease held by `holderId`.
   *
   * @param {string} leaseId
   * @param {{ holderId: string, extendSec?: number, nowMs?: number }} [opts]
   */
  renewCronLease(leaseId, opts = /** @type {any} */ ({})) {
    const id = typeof leaseId === 'string' ? leaseId.trim() : '';
    const safeOpts = opts && typeof opts === 'object' ? opts : {};
    const holderId = typeof safeOpts.holderId === 'string' ? safeOpts.holderId.trim() : '';
    const extendSec = normalizeTtlSec(safeOpts.extendSec, DEFAULT_TTL_SEC);
    const nowMs = normalizeNowMs(safeOpts.nowMs);

    const state = this._loadState();
    const lease = state.leases.find((l) => l.leaseId === id);
    if (!lease) {
      return {
        ok: false,
        renewed: false,
        reason: /** @type {'LEASE_NOT_FOUND'} */ ('LEASE_NOT_FOUND'),
        leaseId: id
      };
    }

    const latestCounter = Number.isInteger(state.counters[lease.jobId]) ? state.counters[lease.jobId] : lease.fencingToken;
    if (lease.fencingToken < latestCounter) {
      return {
        ok: false,
        renewed: false,
        reason: /** @type {'STALE_FENCING_TOKEN'} */ ('STALE_FENCING_TOKEN'),
        leaseId: lease.leaseId,
        currentFencingToken: latestCounter,
        lease: { ...lease }
      };
    }

    if (lease.status !== 'active') {
      return {
        ok: false,
        renewed: false,
        reason: lease.status === 'expired' ? 'LEASE_EXPIRED' : 'LEASE_NOT_ACTIVE',
        leaseId: lease.leaseId,
        lease: { ...lease }
      };
    }

    if (lease.expiresAtMs <= nowMs) {
      lease.status = 'expired';
      lease.expiredAtMs = nowMs;
      this._saveState(state);
      return {
        ok: false,
        renewed: false,
        reason: /** @type {'LEASE_EXPIRED'} */ ('LEASE_EXPIRED'),
        leaseId: lease.leaseId,
        lease: { ...lease }
      };
    }

    if (!holderId || holderId !== lease.holderId) {
      return {
        ok: false,
        renewed: false,
        reason: /** @type {'HOLDER_MISMATCH'} */ ('HOLDER_MISMATCH'),
        leaseId: lease.leaseId,
        lease: { ...lease }
      };
    }

    lease.ttlSec = extendSec;
    lease.renewedAtMs = nowMs;
    lease.expiresAtMs = nowMs + extendSec * 1000;
    lease.expiresAt = new Date(lease.expiresAtMs).toISOString();
    this._saveState(state);

    return {
      ok: true,
      renewed: true,
      reason: 'RENEWED',
      leaseId: lease.leaseId,
      fencingToken: lease.fencingToken,
      lease: { ...lease }
    };
  }

  /**
   * Completes an active lease, enforcing strict `fencingToken` and `holderId` verification.
   *
   * @param {string} leaseId
   * @param {{
   *   holderId: string,
   *   fencingToken: number,
   *   status?: 'succeeded' | 'failed',
   *   nowMs?: number
   * }} [opts]
   */
  completeCronLease(leaseId, opts = /** @type {any} */ ({})) {
    const id = typeof leaseId === 'string' ? leaseId.trim() : '';
    const safeOpts = opts && typeof opts === 'object' ? opts : {};
    const holderId = typeof safeOpts.holderId === 'string' ? safeOpts.holderId.trim() : '';
    const status = safeOpts.status === undefined ? 'succeeded' : String(safeOpts.status);
    if (status !== 'succeeded' && status !== 'failed') {
      throw leaseError('INVALID_STATUS', 'status must be "succeeded" or "failed"');
    }
    const nowMs = normalizeNowMs(safeOpts.nowMs);
    const providedToken = Number(safeOpts.fencingToken);

    const state = this._loadState();
    const lease = state.leases.find((l) => l.leaseId === id);
    if (!lease) {
      return {
        ok: false,
        completed: false,
        reason: /** @type {'LEASE_NOT_FOUND'} */ ('LEASE_NOT_FOUND'),
        leaseId: id
      };
    }

    const latestCounter = Number.isInteger(state.counters[lease.jobId]) ? state.counters[lease.jobId] : lease.fencingToken;

    // Strict fencing-token check catches wrong token, superseded zombie lease, and expired lease
    if (
      !Number.isInteger(providedToken) ||
      providedToken !== lease.fencingToken ||
      lease.fencingToken < latestCounter ||
      lease.status === 'expired'
    ) {
      return {
        ok: false,
        completed: false,
        reason: /** @type {'STALE_FENCING_TOKEN'} */ ('STALE_FENCING_TOKEN'),
        leaseId: lease.leaseId,
        expectedFencingToken: latestCounter,
        lease: { ...lease }
      };
    }

    if (!holderId || holderId !== lease.holderId) {
      return {
        ok: false,
        completed: false,
        reason: /** @type {'HOLDER_MISMATCH'} */ ('HOLDER_MISMATCH'),
        leaseId: lease.leaseId,
        lease: { ...lease }
      };
    }

    if (lease.status === 'active' && lease.expiresAtMs <= nowMs) {
      lease.status = 'expired';
      lease.expiredAtMs = nowMs;
      this._saveState(state);
      return {
        ok: false,
        completed: false,
        reason: /** @type {'STALE_FENCING_TOKEN'} */ ('STALE_FENCING_TOKEN'),
        leaseId: lease.leaseId,
        expectedFencingToken: latestCounter,
        lease: { ...lease }
      };
    }

    if (lease.status !== 'active') {
      return {
        ok: false,
        completed: false,
        reason: /** @type {'ALREADY_COMPLETED'} */ ('ALREADY_COMPLETED'),
        leaseId: lease.leaseId,
        lease: { ...lease }
      };
    }

    lease.status = status;
    lease.completedAtMs = nowMs;
    lease.completedAt = new Date(nowMs).toISOString();
    this._saveState(state);

    return {
      ok: true,
      completed: true,
      reason: 'COMPLETED',
      leaseId: lease.leaseId,
      fencingToken: lease.fencingToken,
      status: lease.status,
      lease: { ...lease }
    };
  }

  /**
   * Lists persisted cron leases (optionally filtered by `jobId`), newest first.
   * Reflects effective expiration against `nowMs` without mutating disk on reads.
   *
   * @param {string | { jobId?: string, nowMs?: number } | null} [jobIdOrOpts]
   * @param {number} [nowMsArg]
   * @returns {CronLeaseRecord[]}
   */
  listCronLeases(jobIdOrOpts, nowMsArg) {
    /** @type {string | null} */
    let filterJobId = null;
    /** @type {number} */
    let nowMs = nowMsArg !== undefined ? normalizeNowMs(nowMsArg) : Date.now();

    if (typeof jobIdOrOpts === 'string' && jobIdOrOpts.trim()) {
      filterJobId = jobIdOrOpts.trim();
    } else if (jobIdOrOpts && typeof jobIdOrOpts === 'object') {
      if (typeof jobIdOrOpts.jobId === 'string' && jobIdOrOpts.jobId.trim()) {
        filterJobId = jobIdOrOpts.jobId.trim();
      }
      if (jobIdOrOpts.nowMs !== undefined) {
        nowMs = normalizeNowMs(jobIdOrOpts.nowMs);
      }
    }

    const state = this._loadState();
    return state.leases
      .filter((l) => (!filterJobId || l.jobId === filterJobId))
      .map((l) => {
        const isExpired = l.status === 'active' && l.expiresAtMs <= nowMs;
        return {
          ...l,
          status: /** @type {CronLeaseStatus} */ (isExpired ? 'expired' : l.status)
        };
      })
      .sort((a, b) => (b.acquiredAtMs - a.acquiredAtMs) || (b.fencingToken - a.fencingToken));
  }
}

const defaultCronLeaseService = new CronLeaseService();

const exported = Object.assign(defaultCronLeaseService, {
  CronLeaseService,
  DEFAULT_TTL_SEC,
  acquireCronLease: CronLeaseService.prototype.acquireCronLease.bind(defaultCronLeaseService),
  renewCronLease: CronLeaseService.prototype.renewCronLease.bind(defaultCronLeaseService),
  completeCronLease: CronLeaseService.prototype.completeCronLease.bind(defaultCronLeaseService),
  listCronLeases: CronLeaseService.prototype.listCronLeases.bind(defaultCronLeaseService)
});

module.exports = exported;
