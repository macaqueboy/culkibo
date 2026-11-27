'use strict';

/**
 * Culkibo Zero-Dep KEDA-Class Queue/Worker Autoscaler & `503 Retry-After` Backpressure Breaker.
 *
 * Answers `dokploy#6105`, `coolify#3862`, and `caprover#2164` with zero external deps:
 *  - Hysteresis deadbands (separate scale-up vs scale-down queue & HTTP saturation thresholds)
 *    eliminating oscillation/flapping.
 *  - Independent scale-up & scale-down cooldown timers (`scaleUpCooldownSec` / `scaleDownCooldownSec`).
 *  - Hard VPS RAM Ceiling (`maxSafeReplicas = max(minReplicas, floor(max(0, hostFreeRamMb - reserveHostRamMb) / perReplicaRamMb))`)
 *    making autoscaler-induced VPS OOM thrash mathematically impossible.
 *  - Backpressure Circuit Breaker emitting HTTP `503` + `Retry-After` when queue depth exceeds
 *    `breakerQueueThreshold` OR host free RAM falls below `reserveHostRamMb`.
 *  - Atomic `0o600` policy persistence in isolated `CULKIBO_DATA_DIR/data/autoscaler-policies.json`.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DEFAULT_POLICY = Object.freeze({
  enabled: true,
  minReplicas: 1,
  maxReplicas: 10,
  targetQueuePerReplica: 25,
  scaleUpQueueThreshold: 25,
  scaleDownQueueThreshold: 5,
  scaleUpHttpSaturationPct: 75,
  scaleDownHttpSaturationPct: 30,
  perReplicaRamMb: 256,
  reserveHostRamMb: 512,
  scaleUpCooldownSec: 60,
  scaleDownCooldownSec: 300,
  breakerQueueThreshold: 500,
  breakerRetryAfterSec: 30
});

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
 * @param {string} code
 * @param {string} msg
 */
function badPolicy(code, msg) {
  const err = /** @type {any} */ (new Error(msg));
  err.code = code;
  err.status = 400;
  return err;
}

/**
 * Validates and merges a partial autoscaler policy against `basePolicy`.
 * @param {Record<string, any>} partial
 * @param {Record<string, any>} [basePolicy]
 */
function normalizeAndValidatePolicy(partial, basePolicy = DEFAULT_POLICY) {
  const src = partial && typeof partial === 'object' ? partial : {};
  const merged = {
    enabled: src.enabled !== undefined ? Boolean(src.enabled) : Boolean(basePolicy.enabled),
    minReplicas: src.minReplicas !== undefined ? Math.round(Number(src.minReplicas)) : basePolicy.minReplicas,
    maxReplicas: src.maxReplicas !== undefined ? Math.round(Number(src.maxReplicas)) : basePolicy.maxReplicas,
    targetQueuePerReplica: src.targetQueuePerReplica !== undefined ? Math.round(Number(src.targetQueuePerReplica)) : basePolicy.targetQueuePerReplica,
    scaleUpQueueThreshold: src.scaleUpQueueThreshold !== undefined ? Math.round(Number(src.scaleUpQueueThreshold)) : basePolicy.scaleUpQueueThreshold,
    scaleDownQueueThreshold: src.scaleDownQueueThreshold !== undefined ? Math.round(Number(src.scaleDownQueueThreshold)) : basePolicy.scaleDownQueueThreshold,
    scaleUpHttpSaturationPct: src.scaleUpHttpSaturationPct !== undefined ? Number(src.scaleUpHttpSaturationPct) : basePolicy.scaleUpHttpSaturationPct,
    scaleDownHttpSaturationPct: src.scaleDownHttpSaturationPct !== undefined ? Number(src.scaleDownHttpSaturationPct) : basePolicy.scaleDownHttpSaturationPct,
    perReplicaRamMb: src.perReplicaRamMb !== undefined ? Math.round(Number(src.perReplicaRamMb)) : basePolicy.perReplicaRamMb,
    reserveHostRamMb: src.reserveHostRamMb !== undefined ? Math.round(Number(src.reserveHostRamMb)) : basePolicy.reserveHostRamMb,
    scaleUpCooldownSec: src.scaleUpCooldownSec !== undefined ? Math.round(Number(src.scaleUpCooldownSec)) : basePolicy.scaleUpCooldownSec,
    scaleDownCooldownSec: src.scaleDownCooldownSec !== undefined ? Math.round(Number(src.scaleDownCooldownSec)) : basePolicy.scaleDownCooldownSec,
    breakerQueueThreshold: src.breakerQueueThreshold !== undefined ? Math.round(Number(src.breakerQueueThreshold)) : basePolicy.breakerQueueThreshold,
    breakerRetryAfterSec: src.breakerRetryAfterSec !== undefined ? Math.round(Number(src.breakerRetryAfterSec)) : basePolicy.breakerRetryAfterSec
  };

  if (!Number.isInteger(merged.minReplicas) || merged.minReplicas < 0 || merged.minReplicas > 64) {
    throw badPolicy('INVALID_POLICY', 'minReplicas must be an integer 0..64');
  }
  if (!Number.isInteger(merged.maxReplicas) || merged.maxReplicas < Math.max(1, merged.minReplicas) || merged.maxReplicas > 128) {
    throw badPolicy('INVALID_POLICY', 'maxReplicas must be >= minReplicas and <= 128');
  }
  if (!Number.isInteger(merged.targetQueuePerReplica) || merged.targetQueuePerReplica < 1 || merged.targetQueuePerReplica > 100000) {
    throw badPolicy('INVALID_POLICY', 'targetQueuePerReplica must be 1..100000');
  }
  if (!Number.isInteger(merged.scaleUpQueueThreshold) || merged.scaleUpQueueThreshold < 1) {
    throw badPolicy('INVALID_POLICY', 'scaleUpQueueThreshold must be >= 1');
  }
  if (!Number.isInteger(merged.scaleDownQueueThreshold) || merged.scaleDownQueueThreshold < 0 || merged.scaleDownQueueThreshold >= merged.scaleUpQueueThreshold) {
    throw badPolicy('INVALID_POLICY', 'scaleDownQueueThreshold must be >= 0 and strictly < scaleUpQueueThreshold (hysteresis deadband)');
  }
  if (!Number.isFinite(merged.scaleUpHttpSaturationPct) || merged.scaleUpHttpSaturationPct < 10 || merged.scaleUpHttpSaturationPct > 100) {
    throw badPolicy('INVALID_POLICY', 'scaleUpHttpSaturationPct must be 10..100');
  }
  if (!Number.isFinite(merged.scaleDownHttpSaturationPct) || merged.scaleDownHttpSaturationPct < 0 || merged.scaleDownHttpSaturationPct >= merged.scaleUpHttpSaturationPct) {
    throw badPolicy('INVALID_POLICY', 'scaleDownHttpSaturationPct must be >= 0 and < scaleUpHttpSaturationPct');
  }
  if (!Number.isInteger(merged.perReplicaRamMb) || merged.perReplicaRamMb < 32 || merged.perReplicaRamMb > 65536) {
    throw badPolicy('INVALID_POLICY', 'perReplicaRamMb must be 32..65536');
  }
  if (!Number.isInteger(merged.reserveHostRamMb) || merged.reserveHostRamMb < 64 || merged.reserveHostRamMb > 65536) {
    throw badPolicy('INVALID_POLICY', 'reserveHostRamMb must be 64..65536');
  }
  if (!Number.isInteger(merged.scaleUpCooldownSec) || merged.scaleUpCooldownSec < 0 || merged.scaleUpCooldownSec > 3600) {
    throw badPolicy('INVALID_POLICY', 'scaleUpCooldownSec must be 0..3600');
  }
  if (!Number.isInteger(merged.scaleDownCooldownSec) || merged.scaleDownCooldownSec < 0 || merged.scaleDownCooldownSec > 7200) {
    throw badPolicy('INVALID_POLICY', 'scaleDownCooldownSec must be 0..7200');
  }
  if (!Number.isInteger(merged.breakerQueueThreshold) || merged.breakerQueueThreshold < merged.scaleUpQueueThreshold) {
    throw badPolicy('INVALID_POLICY', 'breakerQueueThreshold must be >= scaleUpQueueThreshold');
  }
  if (!Number.isInteger(merged.breakerRetryAfterSec) || merged.breakerRetryAfterSec < 1 || merged.breakerRetryAfterSec > 3600) {
    throw badPolicy('INVALID_POLICY', 'breakerRetryAfterSec must be 1..3600');
  }

  return merged;
}

class WorkerAutoscalerService {
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
    return path.join(this.resolveDataDir(), 'autoscaler-policies.json');
  }

  /** @returns {Record<string, any>} */
  _loadMap() {
    const p = this.getStoreFilePath();
    if (!fs.existsSync(p)) return {};
    try {
      const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
      return parsed && parsed.policies && typeof parsed.policies === 'object' ? parsed.policies : {};
    } catch (e) {
      return {};
    }
  }

  /** @param {Record<string, any>} policies */
  _saveMap(policies) {
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({ schemaVersion: 1, updatedAt: new Date().toISOString(), policies }, null, 2) + '\n'
    );
  }

  /** Lists all persisted per-project autoscaler policies. */
  listPolicies() {
    return Object.values(this._loadMap());
  }

  /**
   * Returns a project's persisted autoscaler policy (or defaults merged with `projectId`).
   * @param {string} projectId
   */
  getPolicy(projectId) {
    const id = String(projectId || 'default').trim().slice(0, 128) || 'default';
    const map = this._loadMap();
    if (map[id]) {
      return {
        projectId: id,
        ...DEFAULT_POLICY,
        ...map[id]
      };
    }
    return {
      projectId: id,
      ...DEFAULT_POLICY,
      updatedAt: null
    };
  }

  /**
   * Validates and atomically persists a project's autoscaler policy.
   * @param {string} projectId
   * @param {Record<string, any>} partial
   */
  savePolicy(projectId, partial = {}) {
    const id = String(projectId || '').trim().slice(0, 128);
    if (!id) throw badPolicy('INVALID_PROJECT_ID', 'projectId is required');
    const existing = this.getPolicy(id);
    const validated = normalizeAndValidatePolicy(partial, existing);
    const record = {
      projectId: id,
      ...validated,
      updatedAt: new Date().toISOString()
    };
    const map = this._loadMap();
    map[id] = record;
    this._saveMap(map);
    return record;
  }

  /**
   * Evaluates worker autoscaling decision with hysteresis deadbands, cooldown anti-flapping,
   * hard VPS RAM ceiling (`maxSafeReplicas`), and `503 Retry-After` backpressure circuit breaker.
   *
   * @param {{
   *   projectId?: string,
   *   queueDepth?: number,
   *   httpSaturationPct?: number,
   *   currentReplicas?: number,
   *   hostFreeRamMb: number,
   *   perReplicaRamMb?: number,
   *   lastScaleAtMs?: number,
   *   nowMs?: number
   * }} input
   * @param {Record<string, any> | null} [policyOverride]
   */
  evaluateAutoscaler(input, policyOverride = null) {
    if (!input || typeof input !== 'object') {
      throw badPolicy('INVALID_INPUT', 'evaluateAutoscaler requires an input object');
    }
    const projectId = String(input.projectId || 'default').trim().slice(0, 128) || 'default';
    const basePolicy = this.getPolicy(projectId);
    const policy = policyOverride && typeof policyOverride === 'object'
      ? normalizeAndValidatePolicy(policyOverride, basePolicy)
      : normalizeAndValidatePolicy({}, basePolicy);

    const queueDepth = Math.max(0, Number(input.queueDepth) || 0);
    const httpSaturationPct = Math.max(0, Math.min(100, Number(input.httpSaturationPct) || 0));
    const currentReplicas = Math.max(0, Math.round(Number(input.currentReplicas ?? policy.minReplicas) || 0));
    const hostFreeRamMb = Number.isFinite(Number(input.hostFreeRamMb)) ? Math.max(0, Number(input.hostFreeRamMb)) : 0;
    const perReplicaRamMb = Number.isFinite(Number(input.perReplicaRamMb)) && Number(input.perReplicaRamMb) >= 32
      ? Math.round(Number(input.perReplicaRamMb))
      : policy.perReplicaRamMb;
    const lastScaleAtMs = Number.isFinite(Number(input.lastScaleAtMs)) ? Number(input.lastScaleAtMs) : 0;
    const nowMs = Number.isFinite(Number(input.nowMs)) ? Number(input.nowMs) : Date.now();

    const memoryHeadroomMb = Math.round(hostFreeRamMb - policy.reserveHostRamMb);
    const allocatableRamMb = Math.max(0, hostFreeRamMb - policy.reserveHostRamMb);
    const maxSafeReplicas = Math.max(
      policy.minReplicas,
      Math.floor(allocatableRamMb / perReplicaRamMb)
    );

    // Backpressure Circuit Breaker: trips on queue overflow OR host RAM falling below reserve
    const ramBelowReserve = hostFreeRamMb < policy.reserveHostRamMb;
    const queueOverflow = queueDepth >= policy.breakerQueueThreshold;
    const breakerOpen = queueOverflow || ramBelowReserve;
    const circuitBreaker = breakerOpen
      ? {
          state: /** @type {'OPEN'} */ ('OPEN'),
          httpStatus: 503,
          retryAfterSec: policy.breakerRetryAfterSec,
          headers: { 'Retry-After': String(policy.breakerRetryAfterSec) },
          reason: ramBelowReserve ? 'HOST_MEMORY_BELOW_RESERVE' : 'QUEUE_BACKPRESSURE_OVERFLOW'
        }
      : {
          state: /** @type {'CLOSED'} */ ('CLOSED'),
          httpStatus: 200,
          retryAfterSec: 0,
          headers: {},
          reason: null
        };

    // Hysteresis deadband calculation for uncapped desiredReplicas
    let desiredReplicas = currentReplicas;
    const wantsScaleUp = queueDepth >= policy.scaleUpQueueThreshold || httpSaturationPct >= policy.scaleUpHttpSaturationPct;
    const wantsScaleDown = queueDepth <= policy.scaleDownQueueThreshold && httpSaturationPct <= policy.scaleDownHttpSaturationPct && currentReplicas > policy.minReplicas;

    if (wantsScaleUp) {
      const queueDemand = queueDepth >= policy.scaleUpQueueThreshold
        ? Math.ceil(queueDepth / Math.max(1, policy.targetQueuePerReplica))
        : currentReplicas;
      const httpDemand = httpSaturationPct >= policy.scaleUpHttpSaturationPct
        ? Math.max(currentReplicas + 1, Math.ceil((Math.max(1, currentReplicas) * httpSaturationPct) / Math.max(1, policy.scaleUpHttpSaturationPct - 15)))
        : currentReplicas;
      const rawDesired = Math.max(currentReplicas + 1, queueDemand, httpDemand);
      desiredReplicas = Math.min(policy.maxReplicas, Math.max(policy.minReplicas, rawDesired));
    } else if (wantsScaleDown) {
      const queueNeed = Math.max(policy.minReplicas, Math.ceil(queueDepth / Math.max(1, policy.targetQueuePerReplica)));
      desiredReplicas = Math.max(policy.minReplicas, Math.min(currentReplicas - 1, queueNeed));
    }

    const elapsedSec = lastScaleAtMs > 0 ? Math.max(0, (nowMs - lastScaleAtMs) / 1000) : Infinity;

    /** @type {'SCALE_UP' | 'SCALE_DOWN' | 'HOLD'} */
    let action = 'HOLD';
    /** @type {'SCALE_UP' | 'SCALE_DOWN' | 'COOLDOWN_ACTIVE' | 'MEMORY_CEILING_CAPPED' | 'HYSTERESIS_HOLD' | 'BREAKER_OPEN'} */
    let reason = 'HYSTERESIS_HOLD';
    let targetReplicas = currentReplicas;
    let cooldownRemainingSec = 0;

    if (!policy.enabled) {
      action = 'HOLD';
      reason = breakerOpen ? 'BREAKER_OPEN' : 'HYSTERESIS_HOLD';
      targetReplicas = currentReplicas;
    } else if (ramBelowReserve) {
      // Never scale up when host RAM is already below safety reserve!
      action = 'HOLD';
      reason = 'BREAKER_OPEN';
      targetReplicas = currentReplicas;
    } else if (desiredReplicas > currentReplicas) {
      if (lastScaleAtMs > 0 && elapsedSec < policy.scaleUpCooldownSec) {
        action = 'HOLD';
        reason = 'COOLDOWN_ACTIVE';
        targetReplicas = currentReplicas;
        cooldownRemainingSec = Math.ceil(policy.scaleUpCooldownSec - elapsedSec);
      } else {
        const cappedTarget = Math.min(desiredReplicas, maxSafeReplicas);
        if (cappedTarget <= currentReplicas) {
          action = 'HOLD';
          reason = breakerOpen ? 'BREAKER_OPEN' : 'MEMORY_CEILING_CAPPED';
          targetReplicas = currentReplicas;
        } else if (cappedTarget < desiredReplicas) {
          action = 'SCALE_UP';
          reason = 'MEMORY_CEILING_CAPPED';
          targetReplicas = cappedTarget;
        } else {
          action = 'SCALE_UP';
          reason = 'SCALE_UP';
          targetReplicas = cappedTarget;
        }
      }
    } else if (desiredReplicas < currentReplicas) {
      if (lastScaleAtMs > 0 && elapsedSec < policy.scaleDownCooldownSec) {
        action = 'HOLD';
        reason = 'COOLDOWN_ACTIVE';
        targetReplicas = currentReplicas;
        cooldownRemainingSec = Math.ceil(policy.scaleDownCooldownSec - elapsedSec);
      } else {
        action = 'SCALE_DOWN';
        reason = 'SCALE_DOWN';
        targetReplicas = Math.max(policy.minReplicas, desiredReplicas);
      }
    } else {
      action = 'HOLD';
      reason = breakerOpen ? 'BREAKER_OPEN' : 'HYSTERESIS_HOLD';
      targetReplicas = currentReplicas;
    }

    return {
      projectId,
      action,
      reason,
      currentReplicas,
      desiredReplicas,
      targetReplicas,
      maxSafeReplicas,
      memoryHeadroomMb,
      cooldownRemainingSec,
      circuitBreaker,
      policy,
      evaluatedAt: new Date(nowMs).toISOString()
    };
  }
}

const defaultWorkerAutoscalerService = new WorkerAutoscalerService();

const exported = Object.assign(defaultWorkerAutoscalerService, {
  WorkerAutoscalerService,
  DEFAULT_POLICY,
  listPolicies: WorkerAutoscalerService.prototype.listPolicies.bind(defaultWorkerAutoscalerService),
  getPolicy: WorkerAutoscalerService.prototype.getPolicy.bind(defaultWorkerAutoscalerService),
  savePolicy: WorkerAutoscalerService.prototype.savePolicy.bind(defaultWorkerAutoscalerService),
  evaluateAutoscaler: WorkerAutoscalerService.prototype.evaluateAutoscaler.bind(defaultWorkerAutoscalerService)
});

module.exports = exported;
