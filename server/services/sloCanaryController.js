'use strict';

/**
 * Culkibo Zero-Dep SLO Error-Budget Canary Auto-Rollback Controller.
 *
 * Argo Rollouts / Flagger DNA directly over native Caddy v2.11 `weighted_round_robin`:
 *  - Progressive traffic splits (`10% -> 25% -> 50% -> 100%`) compiled straight into Caddy JSON.
 *  - Evaluates Google SRE error-budget burn-rate (`errorRate / (1 - sloTarget)`, default breach > 14.4x)
 *    AND p95 latency regression (`canaryP95 / max(1, baselineP95) > maxLatencyRatio` AND delta >= 25ms).
 *  - Instant `100/0` rollback (`ROLLED_BACK`) + alert + audit entry on ANY SLO breach.
 *  - Atomic `0o600` rollout history persistence (max 50) in isolated `CULKIBO_DATA_DIR/data/slo-canaries.json`.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DEFAULT_CANARY_STEPS = Object.freeze([10, 25, 50, 100]);
const DEFAULT_SLO_TARGET = 0.999;
const DEFAULT_MAX_BURN_RATE = 14.4;
const DEFAULT_MAX_LATENCY_RATIO = 2.0;
const DEFAULT_MIN_LATENCY_DELTA_MS = 25;
const MAX_STORED_ROLLOUTS = 50;

const HOSTNAME_RE = /^(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;
const UPSTREAM_DIAL_RE = /^(?:\[[0-9a-fA-F:]+\]|[a-zA-Z0-9._-]+):(\d{1,5})$/;

/**
 * Atomically writes UTF-8 text to disk with `0o600` permissions.
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
 * Validates a Caddy `dial` upstream (`host:port` or `[ipv6]:port`).
 * @param {string} raw
 * @param {string} label
 * @returns {string}
 */
function validateUpstreamDial(raw, label) {
  const clean = String(raw || '').trim();
  const m = UPSTREAM_DIAL_RE.exec(clean);
  if (!m || /[\s\r\n\0]/.test(clean)) {
    const err = /** @type {any} */ (new Error(`Invalid ${label} dial address: "${clean.slice(0, 64)}"`));
    err.code = 'INVALID_UPSTREAM';
    err.status = 400;
    throw err;
  }
  const port = Number(m[1]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    const err = /** @type {any} */ (new Error(`Invalid port in ${label}: ${port}`));
    err.code = 'INVALID_UPSTREAM';
    err.status = 400;
    throw err;
  }
  return clean;
}

/**
 * Validates a hostname for Caddy weighted canary routing.
 * @param {string} raw
 * @returns {string}
 */
function validateHostname(raw) {
  const clean = String(raw || '').trim().toLowerCase();
  if (!clean || clean.length > 253 || !HOSTNAME_RE.test(clean)) {
    const err = /** @type {any} */ (new Error(`Invalid canary hostname: "${clean.slice(0, 64)}"`));
    err.code = 'INVALID_HOSTNAME';
    err.status = 400;
    throw err;
  }
  return clean;
}

/**
 * Compiles a native Caddy v2.11 JSON route using `weighted_round_robin` load balancing
 * splitting traffic `[100 - canaryWeight, canaryWeight]` between `stableUpstream` and `canaryUpstream`.
 *
 * @param {{
 *   hostname: string,
 *   stableUpstream: string,
 *   canaryUpstream: string,
 *   canaryWeight: number
 * }} opts
 */
function buildCaddyWeightedRoute(opts) {
  const host = validateHostname(opts.hostname);
  const stable = validateUpstreamDial(opts.stableUpstream, 'stableUpstream');
  const canary = validateUpstreamDial(opts.canaryUpstream, 'canaryUpstream');
  const rawWeight = Number(opts.canaryWeight);
  const canaryWeight = Number.isFinite(rawWeight) ? Math.max(0, Math.min(100, Math.round(rawWeight))) : 0;
  const stableWeight = 100 - canaryWeight;

  return {
    match: [{ host: [host] }],
    handle: [
      {
        handler: 'reverse_proxy',
        upstreams: [
          { dial: stable },
          { dial: canary }
        ],
        load_balancing: {
          selection_policy: {
            policy: 'weighted_round_robin',
            weights: [stableWeight, canaryWeight]
          }
        }
      }
    ],
    terminal: true
  };
}

/**
 * Computes Google SRE error-budget burn rate: `burnRate = errorRate / (1 - sloTarget)`.
 *
 * @param {{
 *   totalRequests: number,
 *   error5xxCount: number,
 *   sloTarget?: number
 * }} opts
 */
function computeErrorBudgetBurnRate(opts) {
  const rawSlo = Number(opts && opts.sloTarget);
  const sloTarget = Number.isFinite(rawSlo) && rawSlo > 0.5 && rawSlo < 1
    ? rawSlo
    : DEFAULT_SLO_TARGET;
  const totalRequests = Math.max(0, Math.round(Number(opts && opts.totalRequests) || 0));
  const rawErrors = Math.max(0, Math.round(Number(opts && opts.error5xxCount) || 0));
  const error5xxCount = totalRequests > 0 ? Math.min(totalRequests, rawErrors) : rawErrors;
  const errorBudget = Number((1 - sloTarget).toFixed(8));
  const errorRate = totalRequests > 0 ? error5xxCount / totalRequests : 0;
  const burnRate = errorBudget > 0 ? Number((errorRate / errorBudget).toFixed(4)) : 0;

  return {
    totalRequests,
    error5xxCount,
    sloTarget,
    errorBudget,
    errorRate: Number(errorRate.toFixed(6)),
    burnRate
  };
}

/**
 * Normalizes progressive canary steps (`[10, 25, 50, 100]`), ensuring strictly ascending ints ending in 100.
 * @param {any} rawSteps
 * @returns {number[]}
 */
function normalizeSteps(rawSteps) {
  if (!Array.isArray(rawSteps) || rawSteps.length === 0) {
    return Array.from(DEFAULT_CANARY_STEPS);
  }
  const clean = Array.from(new Set(
    rawSteps
      .map((s) => Math.round(Number(s)))
      .filter((s) => Number.isFinite(s) && s >= 1 && s <= 100)
  )).sort((a, b) => a - b);
  if (clean.length === 0) return Array.from(DEFAULT_CANARY_STEPS);
  if (clean[clean.length - 1] !== 100) clean.push(100);
  return clean.slice(0, 10);
}

class SloCanaryController {
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
    return path.join(this.resolveDataDir(), 'slo-canaries.json');
  }

  /** @returns {Array<any>} */
  _loadRollouts() {
    const p = this.getStoreFilePath();
    if (!fs.existsSync(p)) return [];
    try {
      const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
      return parsed && Array.isArray(parsed.rollouts) ? parsed.rollouts : [];
    } catch (e) {
      return [];
    }
  }

  /** @param {Array<any>} rollouts */
  _saveRollouts(rollouts) {
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        maxStored: MAX_STORED_ROLLOUTS,
        rollouts: rollouts.slice(0, MAX_STORED_ROLLOUTS)
      }, null, 2) + '\n'
    );
  }

  /**
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
          resourceId: detail.rolloutId || detail.projectId || 'slo-canary',
          actor: 'slo-canary-controller',
          detail
        });
      }
    } catch (e) {}
  }

  /**
   * Starts a progressive SLO-guarded canary rollout at `steps[0]` (default 10%).
   *
   * @param {{
   *   projectId: string,
   *   hostname: string,
   *   stableUpstream: string,
   *   canaryUpstream: string,
   *   steps?: number[],
   *   sloTarget?: number,
   *   maxBurnRate?: number,
   *   maxLatencyRatio?: number,
   *   minLatencyDeltaMs?: number,
   *   applyWeightsImpl?: ((payload: any) => any) | null
   * }} opts
   */
  async startRollout(opts) {
    if (!opts || typeof opts !== 'object') {
      throw new Error('startRollout requires an options object');
    }
    const projectId = String(opts.projectId || '').trim().slice(0, 128);
    if (!projectId) {
      const err = /** @type {any} */ (new Error('projectId is required'));
      err.code = 'INVALID_PROJECT_ID';
      err.status = 400;
      throw err;
    }
    const hostname = validateHostname(opts.hostname);
    const stableUpstream = validateUpstreamDial(opts.stableUpstream, 'stableUpstream');
    const canaryUpstream = validateUpstreamDial(opts.canaryUpstream, 'canaryUpstream');
    const steps = normalizeSteps(opts.steps);
    const rawSlo = Number(opts.sloTarget);
    const sloTarget = Number.isFinite(rawSlo) && rawSlo > 0.5 && rawSlo < 1 ? rawSlo : DEFAULT_SLO_TARGET;
    const maxBurnRate = Number.isFinite(Number(opts.maxBurnRate)) && Number(opts.maxBurnRate) > 0
      ? Number(opts.maxBurnRate)
      : DEFAULT_MAX_BURN_RATE;
    const maxLatencyRatio = Number.isFinite(Number(opts.maxLatencyRatio)) && Number(opts.maxLatencyRatio) > 1
      ? Number(opts.maxLatencyRatio)
      : DEFAULT_MAX_LATENCY_RATIO;
    const minLatencyDeltaMs = Number.isFinite(Number(opts.minLatencyDeltaMs)) && Number(opts.minLatencyDeltaMs) >= 0
      ? Number(opts.minLatencyDeltaMs)
      : DEFAULT_MIN_LATENCY_DELTA_MS;

    const initialWeight = steps[0];
    const caddyRoute = buildCaddyWeightedRoute({
      hostname,
      stableUpstream,
      canaryUpstream,
      canaryWeight: initialWeight
    });

    const id = `canary_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const nowIso = new Date().toISOString();

    const rollout = {
      id,
      projectId,
      hostname,
      stableUpstream,
      canaryUpstream,
      steps,
      stepIndex: 0,
      canaryWeight: initialWeight,
      stableWeight: 100 - initialWeight,
      sloTarget,
      maxBurnRate,
      maxLatencyRatio,
      minLatencyDeltaMs,
      status: initialWeight >= 100 ? 'PROMOTED' : 'IN_PROGRESS',
      breachReasons: [],
      evaluations: [],
      caddyRoute,
      createdAt: nowIso,
      updatedAt: nowIso,
      completedAt: initialWeight >= 100 ? nowIso : null
    };

    if (typeof opts.applyWeightsImpl === 'function') {
      await opts.applyWeightsImpl({
        rolloutId: id,
        projectId,
        hostname,
        stableWeight: rollout.stableWeight,
        canaryWeight: rollout.canaryWeight,
        status: rollout.status,
        caddyRoute
      });
    }

    const all = this._loadRollouts();
    all.unshift(rollout);
    this._saveRollouts(all);

    this._audit('deploy.slo_canary.started', {
      rolloutId: id,
      projectId,
      hostname,
      canaryWeight: initialWeight,
      steps
    });

    return rollout;
  }

  /**
   * Evaluates live telemetry against SLO burn-rate & p95 latency thresholds.
   * Advances to next canary step (`PROMOTED` at 100%) on pass, or IMMEDIATELY
   * flips Caddy weights to `100 / 0` (`ROLLED_BACK`) + alerts on breach.
   *
   * @param {string} rolloutId
   * @param {{
   *   totalRequests?: number,
   *   error5xxCount?: number,
   *   baselineP95Ms?: number,
   *   canaryP95Ms?: number,
   *   applyWeightsImpl?: ((payload: any) => any) | null,
   *   onAlert?: ((payload: any) => void) | null
   * }} [metrics]
   */
  async evaluateRollout(rolloutId, metrics = {}) {
    const all = this._loadRollouts();
    const idx = all.findIndex((r) => r && r.id === String(rolloutId || '').trim());
    if (idx === -1) {
      const err = /** @type {any} */ (new Error(`SLO canary rollout not found: ${rolloutId}`));
      err.code = 'NOT_FOUND';
      err.status = 404;
      throw err;
    }

    const rollout = all[idx];
    if (rollout.status !== 'IN_PROGRESS') {
      const err = /** @type {any} */ (new Error(`Cannot evaluate rollout in terminal status "${rollout.status}"`));
      err.code = 'ROLLOUT_NOT_ACTIVE';
      err.status = 409;
      throw err;
    }

    const burn = computeErrorBudgetBurnRate({
      totalRequests: Number(metrics.totalRequests) || 0,
      error5xxCount: Number(metrics.error5xxCount) || 0,
      sloTarget: rollout.sloTarget
    });
    const baseP95 = Math.max(0, Number(metrics.baselineP95Ms) || 0);
    const candP95 = Math.max(0, Number(metrics.canaryP95Ms) || 0);
    const latencyRatio = Number((candP95 / Math.max(1, baseP95)).toFixed(3));
    const latencyDeltaMs = Number((candP95 - baseP95).toFixed(2));

    /** @type {Array<{ code: string, message: string, actual: number, threshold: number, deltaMs?: number }>} */
    const breaches = [];

    if (burn.burnRate > rollout.maxBurnRate) {
      breaches.push({
        code: 'SLO_BURN_RATE_BREACH',
        message: `Error budget burn rate ${burn.burnRate}x exceeds max ${rollout.maxBurnRate}x (${burn.error5xxCount}/${burn.totalRequests} 5xx)`,
        actual: burn.burnRate,
        threshold: rollout.maxBurnRate
      });
    }

    if (latencyRatio > rollout.maxLatencyRatio && latencyDeltaMs >= rollout.minLatencyDeltaMs) {
      breaches.push({
        code: 'LATENCY_P95_BREACH',
        message: `Canary p95 latency ${candP95}ms is ${latencyRatio}x baseline ${baseP95}ms (+${latencyDeltaMs}ms > ${rollout.maxLatencyRatio}x threshold)`,
        actual: latencyRatio,
        deltaMs: latencyDeltaMs,
        threshold: rollout.maxLatencyRatio
      });
    }

    const nowIso = new Date().toISOString();
    const evalRecord = {
      evaluatedAt: nowIso,
      fromWeight: rollout.canaryWeight,
      burn,
      baselineP95Ms: baseP95,
      canaryP95Ms: candP95,
      latencyRatio,
      latencyDeltaMs,
      passed: breaches.length === 0,
      breaches
    };

    if (breaches.length > 0) {
      rollout.canaryWeight = 0;
      rollout.stableWeight = 100;
      rollout.status = 'ROLLED_BACK';
      rollout.breachReasons = breaches;
      rollout.completedAt = nowIso;
      rollout.updatedAt = nowIso;
      rollout.caddyRoute = buildCaddyWeightedRoute({
        hostname: rollout.hostname,
        stableUpstream: rollout.stableUpstream,
        canaryUpstream: rollout.canaryUpstream,
        canaryWeight: 0
      });
      rollout.evaluations.push({ ...evalRecord, toWeight: 0, action: 'ROLLBACK' });

      if (typeof metrics.applyWeightsImpl === 'function') {
        await metrics.applyWeightsImpl({
          rolloutId: rollout.id,
          projectId: rollout.projectId,
          hostname: rollout.hostname,
          stableWeight: 100,
          canaryWeight: 0,
          status: 'ROLLED_BACK',
          caddyRoute: rollout.caddyRoute
        });
      }

      const alertPayload = {
        type: 'slo_canary_rollback',
        severity: 'critical',
        rolloutId: rollout.id,
        projectId: rollout.projectId,
        hostname: rollout.hostname,
        breachReasons: breaches,
        burnRate: burn.burnRate,
        latencyRatio,
        rolledBackAt: nowIso
      };
      if (typeof metrics.onAlert === 'function') {
        try { metrics.onAlert(alertPayload); } catch (e) {}
      } else if (process.env.NODE_ENV !== 'test' || process.env.CULKIBO_DATA_DIR || this._explicitDataDir) {
        try {
          const alertEngine = require('./alertEngine');
          if (alertEngine && typeof alertEngine.emit === 'function') {
            alertEngine.emit('slo_canary_rollback', alertPayload);
          }
        } catch (e) {}
      }

      this._audit('deploy.slo_canary.rolled_back', {
        rolloutId: rollout.id,
        projectId: rollout.projectId,
        hostname: rollout.hostname,
        breachCodes: breaches.map((b) => b.code),
        burnRate: burn.burnRate,
        latencyRatio
      });
    } else {
      const nextIndex = Math.min(rollout.steps.length - 1, rollout.stepIndex + 1);
      const nextWeight = rollout.steps[nextIndex];
      const isPromoted = nextWeight >= 100 || nextIndex >= rollout.steps.length - 1;

      rollout.stepIndex = nextIndex;
      rollout.canaryWeight = isPromoted ? 100 : nextWeight;
      rollout.stableWeight = 100 - rollout.canaryWeight;
      rollout.status = isPromoted ? 'PROMOTED' : 'IN_PROGRESS';
      rollout.updatedAt = nowIso;
      if (isPromoted) rollout.completedAt = nowIso;
      rollout.caddyRoute = buildCaddyWeightedRoute({
        hostname: rollout.hostname,
        stableUpstream: rollout.stableUpstream,
        canaryUpstream: rollout.canaryUpstream,
        canaryWeight: rollout.canaryWeight
      });
      rollout.evaluations.push({
        ...evalRecord,
        toWeight: rollout.canaryWeight,
        action: isPromoted ? 'PROMOTE' : 'ADVANCE'
      });

      if (typeof metrics.applyWeightsImpl === 'function') {
        await metrics.applyWeightsImpl({
          rolloutId: rollout.id,
          projectId: rollout.projectId,
          hostname: rollout.hostname,
          stableWeight: rollout.stableWeight,
          canaryWeight: rollout.canaryWeight,
          status: rollout.status,
          caddyRoute: rollout.caddyRoute
        });
      }

      this._audit(isPromoted ? 'deploy.slo_canary.promoted' : 'deploy.slo_canary.advanced', {
        rolloutId: rollout.id,
        projectId: rollout.projectId,
        hostname: rollout.hostname,
        canaryWeight: rollout.canaryWeight
      });
    }

    all[idx] = rollout;
    this._saveRollouts(all);
    return rollout;
  }

  /**
   * Manually aborts an active canary rollout, immediately restoring `100 / 0` weights.
   *
   * @param {string} rolloutId
   * @param {{ reason?: string, applyWeightsImpl?: ((payload: any) => any) | null }} [opts]
   */
  async abortRollout(rolloutId, opts = {}) {
    const all = this._loadRollouts();
    const idx = all.findIndex((r) => r && r.id === String(rolloutId || '').trim());
    if (idx === -1) {
      const err = /** @type {any} */ (new Error(`SLO canary rollout not found: ${rolloutId}`));
      err.code = 'NOT_FOUND';
      err.status = 404;
      throw err;
    }
    const rollout = all[idx];
    const nowIso = new Date().toISOString();
    const reason = String(opts.reason || 'manual_abort').trim().slice(0, 200);

    rollout.canaryWeight = 0;
    rollout.stableWeight = 100;
    rollout.status = 'ABORTED';
    rollout.abortReason = reason;
    rollout.updatedAt = nowIso;
    rollout.completedAt = nowIso;
    rollout.caddyRoute = buildCaddyWeightedRoute({
      hostname: rollout.hostname,
      stableUpstream: rollout.stableUpstream,
      canaryUpstream: rollout.canaryUpstream,
      canaryWeight: 0
    });

    if (typeof opts.applyWeightsImpl === 'function') {
      await opts.applyWeightsImpl({
        rolloutId: rollout.id,
        projectId: rollout.projectId,
        hostname: rollout.hostname,
        stableWeight: 100,
        canaryWeight: 0,
        status: 'ABORTED',
        caddyRoute: rollout.caddyRoute
      });
    }

    all[idx] = rollout;
    this._saveRollouts(all);

    this._audit('deploy.slo_canary.aborted', {
      rolloutId: rollout.id,
      projectId: rollout.projectId,
      reason
    });

    return rollout;
  }

  /**
   * Fetches a single canary rollout by ID.
   * @param {string} rolloutId
   */
  getRollout(rolloutId) {
    const id = String(rolloutId || '').trim();
    if (!id) return null;
    return this._loadRollouts().find((r) => r && r.id === id) || null;
  }

  /**
   * Lists persisted canary rollouts, optionally filtered by `projectId`.
   * @param {string | null | undefined} [projectId]
   */
  listRollouts(projectId) {
    const all = this._loadRollouts();
    if (!projectId) return all;
    const target = String(projectId).trim();
    return all.filter((r) => r && r.projectId === target);
  }
}

const defaultSloCanaryController = new SloCanaryController();

const exported = Object.assign(defaultSloCanaryController, {
  SloCanaryController,
  DEFAULT_CANARY_STEPS,
  DEFAULT_SLO_TARGET,
  DEFAULT_MAX_BURN_RATE,
  DEFAULT_MAX_LATENCY_RATIO,
  DEFAULT_MIN_LATENCY_DELTA_MS,
  MAX_STORED_ROLLOUTS,
  buildCaddyWeightedRoute,
  computeErrorBudgetBurnRate
});

module.exports = exported;
