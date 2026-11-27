'use strict';

/**
 * Culkibo Chaos Fault-Injection GameDay Simulator & Resilience Scorecard.
 *
 * Brings Toxiproxy & Chaos Mesh steady-state resilience drills into Culkibo with
 * zero external dependencies and hard production blast-radius guardrails:
 *  - Atomic `0o600` scorecard persistence in `CULKIBO_DATA_DIR/data/chaos-gamedays.json`.
 *  - 5 fault profiles: `latency_jitter`, `http_5xx`, `timeout_drop`, `dns_failure`, `bandwidth_cap`.
 *  - Hard production safety lock: `environment === 'production'` is unconditionally blocked
 *    with `PROD_CHAOS_CONFIRM_REQUIRED` unless `explicitProdConfirm === true`.
 *  - Automatic error-rate abort (`status: 'AUTO_ABORTED'`, `aborted: true`) whenever observed
 *    or simulated error rate exceeds `maxErrorAbortPct`.
 *  - Weighted `0..100` Resilience Scorecard (`A`–`F`) across Error Budget, p95 Latency SLO,
 *    and Recovery Time (`MTTR`).
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const FAULT_TYPES = Object.freeze([
  'latency_jitter',
  'http_5xx',
  'timeout_drop',
  'dns_failure',
  'bandwidth_cap'
]);

const FAULT_TYPE_SET = new Set(FAULT_TYPES);
const MAX_STORED_GAMEDAYS = 500;
const REQUEST_TIMEOUT_MS = 5000;

/**
 * @typedef {'latency_jitter' | 'http_5xx' | 'timeout_drop' | 'dns_failure' | 'bandwidth_cap'} ChaosFaultType
 */

/**
 * @typedef {object} ResilienceScoreResult
 * @property {number} resilienceScore
 * @property {'A' | 'B' | 'C' | 'D' | 'F'} grade
 * @property {{ errorScore: number, latencyScore: number, recoveryScore: number }} breakdown
 */

/**
 * @typedef {object} ChaosGameDayRecord
 * @property {string} id
 * @property {string} projectId
 * @property {string} environment
 * @property {ChaosFaultType} faultType
 * @property {boolean} dryRun
 * @property {'COMPLETED' | 'AUTO_ABORTED'} status
 * @property {boolean} aborted
 * @property {string | null} abortReason
 * @property {number} resilienceScore
 * @property {'A' | 'B' | 'C' | 'D' | 'F'} grade
 * @property {{ errorScore: number, latencyScore: number, recoveryScore: number }} breakdown
 * @property {{
 *   totalRequests: number,
 *   failedRequests: number,
 *   injectedFaults: number,
 *   errorRatePct: number,
 *   p50LatencyMs: number,
 *   p95LatencyMs: number,
 *   recoverySec: number,
 *   maxErrorAbortPct: number,
 *   sloP95Ms: number,
 *   allowedErrorRatePct: number
 * }} metrics
 * @property {{
 *   latencyMs: number,
 *   jitterMs: number,
 *   faultRatePct: number,
 *   maxErrorAbortPct: number,
 *   explicitProdConfirm: boolean
 * }} params
 * @property {string[]} recommendations
 * @property {string} executedAt
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
function chaosError(code, msg, status = 400) {
  const err = /** @type {any} */ (new Error(msg));
  err.code = code;
  err.status = status;
  return err;
}

/**
 * Computes nearest-rank percentile on a sorted ascending numeric array.
 * @param {number[]} sorted
 * @param {number} pct
 * @returns {number}
 */
function percentile(sorted, pct) {
  if (!sorted.length) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((pct / 100) * sorted.length) - 1));
  return Math.round(sorted[idx]);
}

/**
 * Deterministic bounded jitter in `[-jitterMs, +jitterMs]` for reproducible chaos simulations.
 * @param {number} index
 * @param {number} jitterMs
 * @returns {number}
 */
function deterministicJitter(index, jitterMs) {
  if (jitterMs <= 0) return 0;
  const wave = ((index * 37 + 13) % 21) / 10 - 1; // deterministic in [-1.0, +1.0]
  return Math.round(wave * jitterMs);
}

/**
 * Evaluates a weighted `0..100` Resilience Scorecard across error rate, p95 latency, and MTTR.
 *
 * @param {{
 *   errorRatePct: number,
 *   allowedErrorRatePct?: number,
 *   p95LatencyMs: number,
 *   sloP95Ms?: number,
 *   recoverySec: number,
 *   targetRecoverySec?: number
 * }} input
 * @returns {ResilienceScoreResult}
 */
function evaluateResilienceScore(input) {
  if (!input || typeof input !== 'object') {
    throw chaosError('INVALID_INPUT', 'evaluateResilienceScore requires a metrics object');
  }
  const errorRatePct = Math.max(0, Number(input.errorRatePct) || 0);
  const allowedErrorRatePct = Math.max(0.01, Number(input.allowedErrorRatePct ?? 1.0) || 1.0);
  const p95LatencyMs = Math.max(0, Number(input.p95LatencyMs) || 0);
  const sloP95Ms = Math.max(1, Number(input.sloP95Ms ?? 400) || 400);
  const recoverySec = Math.max(0, Number(input.recoverySec) || 0);
  const targetRecoverySec = Math.max(1, Number(input.targetRecoverySec ?? 30) || 30);

  let errorScore = 100;
  if (errorRatePct > allowedErrorRatePct) {
    const excess = errorRatePct - allowedErrorRatePct;
    const budgetSpan = Math.max(10, allowedErrorRatePct * 10);
    errorScore = Math.max(0, Math.round(100 - (excess / budgetSpan) * 100));
  }

  let latencyScore = 100;
  if (p95LatencyMs > sloP95Ms) {
    const excessRatio = (p95LatencyMs - sloP95Ms) / sloP95Ms;
    latencyScore = Math.max(0, Math.round(100 - excessRatio * 50));
  }

  let recoveryScore = 100;
  if (recoverySec > targetRecoverySec) {
    const excessRatio = (recoverySec - targetRecoverySec) / targetRecoverySec;
    recoveryScore = Math.max(0, Math.round(100 - excessRatio * 40));
  }

  const resilienceScore = Math.max(
    0,
    Math.min(100, Math.round(errorScore * 0.45 + latencyScore * 0.30 + recoveryScore * 0.25))
  );

  /** @type {'A' | 'B' | 'C' | 'D' | 'F'} */
  let grade = 'F';
  if (resilienceScore >= 90) grade = 'A';
  else if (resilienceScore >= 80) grade = 'B';
  else if (resilienceScore >= 70) grade = 'C';
  else if (resilienceScore >= 60) grade = 'D';

  return {
    resilienceScore,
    grade,
    breakdown: {
      errorScore,
      latencyScore,
      recoveryScore
    }
  };
}

/**
 * Builds deterministic baseline samples (100 requests, 45–85ms, HTTP 200) when caller supplies none.
 * @returns {Array<{ latencyMs: number, status: number, failed: boolean }>}
 */
function buildSyntheticBaselineSamples() {
  /** @type {Array<{ latencyMs: number, status: number, failed: boolean }>} */
  const samples = [];
  for (let i = 0; i < 100; i += 1) {
    samples.push({
      latencyMs: 45 + Math.round((i / 99) * 40),
      status: 200,
      failed: false
    });
  }
  return samples;
}

/**
 * Normalizes caller-supplied request samples (numbers or objects).
 * @param {any[]} rawSamples
 */
function normalizeRequestSamples(rawSamples) {
  /** @type {Array<{ latencyMs: number, status: number, failed: boolean }>} */
  const out = [];
  for (const item of rawSamples) {
    if (typeof item === 'number' && Number.isFinite(item)) {
      out.push({ latencyMs: Math.max(0, item), status: 200, failed: false });
    } else if (item && typeof item === 'object') {
      const latencyMs = Math.max(0, Number(item.latencyMs ?? item.durationMs ?? item.ms ?? 60) || 0);
      const status = Number.isFinite(Number(item.status)) ? Math.round(Number(item.status)) : 200;
      const failed = Boolean(item.failed) || Boolean(item.timedOut) || item.ok === false || status >= 500;
      out.push({ latencyMs, status, failed });
    }
  }
  return out;
}

class ChaosGameDayService {
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
    return path.join(this.resolveDataDir(), 'chaos-gamedays.json');
  }

  /** @returns {ChaosGameDayRecord[]} */
  _loadRecords() {
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) return [];
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      return parsed && Array.isArray(parsed.gamedays) ? parsed.gamedays : [];
    } catch (e) {
      return [];
    }
  }

  /** @param {ChaosGameDayRecord[]} records */
  _saveRecords(records) {
    const trimmed = records.slice(-MAX_STORED_GAMEDAYS);
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({ schemaVersion: 1, updatedAt: new Date().toISOString(), gamedays: trimmed }, null, 2) + '\n'
    );
  }

  /**
   * Delegates to pure resilience scorecard evaluation.
   * @param {{
   *   errorRatePct: number,
   *   allowedErrorRatePct?: number,
   *   p95LatencyMs: number,
   *   sloP95Ms?: number,
   *   recoverySec: number,
   *   targetRecoverySec?: number
   * }} input
   */
  evaluateResilienceScore(input) {
    return evaluateResilienceScore(input);
  }

  /**
   * Runs a blast-radius-guarded chaos fault-injection GameDay simulation.
   *
   * @param {{
   *   projectId: string,
   *   environment?: string,
   *   explicitProdConfirm?: boolean,
   *   faultType?: ChaosFaultType | string,
   *   latencyMs?: number,
   *   jitterMs?: number,
   *   faultRatePct?: number,
   *   maxErrorAbortPct?: number,
   *   requestSamples?: any[],
   *   recoverySec?: number,
   *   sloP95Ms?: number,
   *   allowedErrorRatePct?: number,
   *   dryRun?: boolean
   * }} input
   */
  runGameDaySimulation(input) {
    if (!input || typeof input !== 'object') {
      throw chaosError('INVALID_INPUT', 'runGameDaySimulation requires a simulation configuration object');
    }

    const projectId = String(input.projectId || '').trim().slice(0, 128);
    if (!projectId) {
      throw chaosError('INVALID_PROJECT_ID', 'projectId is required');
    }

    const environment = String(input.environment || 'staging').trim().toLowerCase().slice(0, 64) || 'staging';
    const explicitProdConfirm = input.explicitProdConfirm === true;
    const rawFaultType = String(input.faultType || 'latency_jitter').trim().toLowerCase();
    if (!FAULT_TYPE_SET.has(rawFaultType)) {
      throw chaosError('INVALID_FAULT_TYPE', `faultType must be one of: ${FAULT_TYPES.join(', ')}`);
    }
    const faultType = /** @type {ChaosFaultType} */ (rawFaultType);
    const dryRun = input.dryRun !== undefined ? Boolean(input.dryRun) : true;

    // HARD SAFETY RAIL 1: Block unconfirmed production chaos unconditionally
    if ((environment === 'production' || environment === 'prod') && !explicitProdConfirm) {
      return {
        ok: false,
        blocked: true,
        aborted: false,
        status: /** @type {'BLOCKED'} */ ('BLOCKED'),
        code: /** @type {'PROD_CHAOS_CONFIRM_REQUIRED'} */ ('PROD_CHAOS_CONFIRM_REQUIRED'),
        projectId,
        environment,
        faultType,
        dryRun,
        message: 'Production chaos drills are locked by default. Pass explicitProdConfirm: true after confirming blast-radius safeguards.'
      };
    }

    const latencyMs = Math.max(0, Math.min(30000, Number(input.latencyMs ?? 250) || 0));
    const jitterMs = Math.max(0, Math.min(10000, Number(input.jitterMs ?? 50) || 0));
    const faultRatePct = Math.max(0, Math.min(100, Number(input.faultRatePct ?? 10)));
    const maxErrorAbortPct = Math.max(0, Math.min(100, Number(input.maxErrorAbortPct ?? 15)));
    const recoverySec = Math.max(0, Math.min(3600, Number(input.recoverySec ?? 12)));
    const sloP95Ms = Math.max(1, Number(input.sloP95Ms ?? 400) || 400);
    const allowedErrorRatePct = Math.max(0.01, Number(input.allowedErrorRatePct ?? 1.0) || 1.0);

    const rawSamples = Array.isArray(input.requestSamples) ? input.requestSamples : [];
    const hasCallerSamples = rawSamples.length > 0;
    const samples = hasCallerSamples
      ? normalizeRequestSamples(rawSamples)
      : buildSyntheticBaselineSamples();

    const callerAlreadyObservedFailures = hasCallerSamples && samples.some((s) => s.failed);
    const targetFaultCount = callerAlreadyObservedFailures
      ? 0
      : Math.round((samples.length * faultRatePct) / 100);

    let injectedFaults = 0;
    const stride = targetFaultCount > 0 ? samples.length / targetFaultCount : Infinity;
    let nextInjectAt = stride > 1 ? Math.floor(stride / 2) : 0;

    const evaluated = samples.map((s, idx) => {
      let sampleLatency = s.latencyMs;
      let sampleFailed = s.failed;

      if (!callerAlreadyObservedFailures && injectedFaults < targetFaultCount && idx >= Math.floor(nextInjectAt)) {
        injectedFaults += 1;
        nextInjectAt += stride;

        if (faultType === 'latency_jitter') {
          const added = Math.max(0, latencyMs + deterministicJitter(idx, jitterMs));
          sampleLatency += added;
          if (sampleLatency >= REQUEST_TIMEOUT_MS) sampleFailed = true;
        } else if (faultType === 'bandwidth_cap') {
          const added = Math.max(120, latencyMs) + deterministicJitter(idx, jitterMs);
          sampleLatency += Math.max(0, added);
          if (sampleLatency >= REQUEST_TIMEOUT_MS) sampleFailed = true;
        } else if (faultType === 'http_5xx') {
          sampleFailed = true;
          sampleLatency += Math.min(250, Math.round(latencyMs * 0.25));
        } else if (faultType === 'timeout_drop') {
          sampleFailed = true;
          sampleLatency += Math.max(latencyMs, 1500);
        } else if (faultType === 'dns_failure') {
          sampleFailed = true;
          sampleLatency += Math.max(150, Math.round(latencyMs * 0.5));
        }
      }

      return { latencyMs: sampleLatency, failed: sampleFailed };
    });

    const totalRequests = evaluated.length;
    const failedRequests = evaluated.filter((s) => s.failed).length;
    const errorRatePct = totalRequests > 0
      ? Number(((failedRequests / totalRequests) * 100).toFixed(2))
      : 0;

    const sortedLatencies = evaluated.map((s) => s.latencyMs).sort((a, b) => a - b);
    const p50LatencyMs = percentile(sortedLatencies, 50);
    const p95LatencyMs = percentile(sortedLatencies, 95);

    // HARD SAFETY RAIL 2: Auto-abort immediately if error rate exceeds maxErrorAbortPct
    const aborted = errorRatePct > maxErrorAbortPct;
    const status = /** @type {'COMPLETED' | 'AUTO_ABORTED'} */ (aborted ? 'AUTO_ABORTED' : 'COMPLETED');
    const abortReason = aborted
      ? `Observed error rate (${errorRatePct}%) exceeded maxErrorAbortPct (${maxErrorAbortPct}%) — chaos injection aborted immediately`
      : null;

    const score = evaluateResilienceScore({
      errorRatePct,
      allowedErrorRatePct,
      p95LatencyMs,
      sloP95Ms,
      recoverySec,
      targetRecoverySec: 30
    });

    /** @type {string[]} */
    const recommendations = [];
    if (aborted) {
      recommendations.push('Add bounded retries with exponential backoff + jitter and upstream circuit breakers before re-running this fault profile.');
    }
    if (p95LatencyMs > sloP95Ms) {
      recommendations.push(`p95 latency (${p95LatencyMs} ms) breached SLO (${sloP95Ms} ms); tighten client read timeouts and enable hedged/cached fallback paths.`);
    }
    if (recoverySec > 30) {
      recommendations.push(`Recovery time (${recoverySec}s) exceeded 30s target; verify readiness probes and connection pool drain intervals.`);
    }
    if (recommendations.length === 0) {
      recommendations.push('Service absorbed injected faults within SLO error and latency budgets — ready for periodic automated GameDays.');
    }

    /** @type {ChaosGameDayRecord} */
    const record = {
      id: `chaos_${crypto.randomBytes(6).toString('hex')}`,
      projectId,
      environment,
      faultType,
      dryRun,
      status,
      aborted,
      abortReason,
      resilienceScore: score.resilienceScore,
      grade: score.grade,
      breakdown: score.breakdown,
      metrics: {
        totalRequests,
        failedRequests,
        injectedFaults,
        errorRatePct,
        p50LatencyMs,
        p95LatencyMs,
        recoverySec,
        maxErrorAbortPct,
        sloP95Ms,
        allowedErrorRatePct
      },
      params: {
        latencyMs,
        jitterMs,
        faultRatePct,
        maxErrorAbortPct,
        explicitProdConfirm
      },
      recommendations,
      executedAt: new Date().toISOString()
    };

    const records = this._loadRecords();
    records.push(record);
    this._saveRecords(records);

    return {
      ok: true,
      blocked: false,
      ...record
    };
  }

  /**
   * Lists persisted Chaos GameDay scorecards (optionally filtered by `projectId`), newest first.
   * @param {string | null} [projectId]
   * @returns {ChaosGameDayRecord[]}
   */
  listGameDays(projectId) {
    const filterId = typeof projectId === 'string' && projectId.trim() ? projectId.trim() : null;
    const records = this._loadRecords();
    return records
      .filter((r) => (!filterId || r.projectId === filterId))
      .slice()
      .reverse();
  }
}

const defaultChaosGameDayService = new ChaosGameDayService();

const exported = Object.assign(defaultChaosGameDayService, {
  ChaosGameDayService,
  FAULT_TYPES,
  evaluateResilienceScore: ChaosGameDayService.prototype.evaluateResilienceScore.bind(defaultChaosGameDayService),
  runGameDaySimulation: ChaosGameDayService.prototype.runGameDaySimulation.bind(defaultChaosGameDayService),
  listGameDays: ChaosGameDayService.prototype.listGameDays.bind(defaultChaosGameDayService)
});

module.exports = exported;
