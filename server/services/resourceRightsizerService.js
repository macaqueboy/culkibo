'use strict';

/**
 * Culkibo Container Resource Rightsizing & VPA-Lite Telemetry Recommender.
 *
 * Goldilocks / Kubernetes 1.35 VPA-inspired rightsizer curing `Dokploy#4050` (missing DB
 * resource limits), `#927` (`< 0.001` CPU crash), and `#903` (`< 4 MiB` RAM crash) in zero deps:
 *  - Atomic `0o600` recommendation history in `CULKIBO_DATA_DIR/data/resource-rightsizing.json`.
 *  - Exact nearest-rank `computePercentile(samples, p)` for P50 / P95 / P99 telemetry.
 *  - Requires `>= 10` samples (`INSUFFICIENT_SAMPLES`) to reject restart-loop noise.
 *  - Headroom defaults: `+25%` apps, `+35%` databases; **OOM Safety Lock:** when `oomCount > 0`,
 *    forces `+50%` upscale (`action: 'UPSCALE_OOM'`) and NEVER shrinks an OOMing service!
 *  - Validates Docker Engine floors (`>= 4 MiB` RAM `BELOW_DOCKER_MEMORY_FLOOR`, `>= 0.001` CPU
 *    `BELOW_DOCKER_CPU_FLOOR`, rounded to 3 decimals) and emits uniform Compose `deploy.resources`
 *    patches for BOTH apps and databases.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DOCKER_MIN_MEMORY_MB = 4;
const DOCKER_MIN_CPU_CORES = 0.001;
const MIN_SAMPLE_COUNT = 10;
const MAX_STORED_RECOMMENDATIONS = 500;

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
function rightsizeError(code, msg, status = 400) {
  const err = /** @type {any} */ (new Error(msg));
  err.code = code;
  err.status = status;
  return err;
}

/**
 * Computes nearest-rank percentile `p` (`0..100`) on numeric telemetry samples.
 * @param {number[]} samples
 * @param {number} p
 * @returns {number}
 */
function computePercentile(samples, p) {
  if (!Array.isArray(samples) || samples.length === 0) return 0;
  const nums = samples.map(Number).filter((n) => Number.isFinite(n) && n >= 0).sort((a, b) => a - b);
  if (nums.length === 0) return 0;
  const pct = Math.max(0, Math.min(100, Number(p) || 0));
  if (pct === 0) return nums[0];
  const idx = Math.min(nums.length - 1, Math.max(0, Math.ceil((pct / 100) * nums.length) - 1));
  return nums[idx];
}

/**
 * Validates Docker Engine memory (`>= 4 MiB`) and CPU (`>= 0.001` cores, rounded to 3 decimals) floors.
 * Cures `Dokploy#903` & `Dokploy#927`.
 *
 * @param {{ memoryMb?: number, cpuCores?: number }} [input]
 */
function validateDockerLimits(input = {}) {
  const src = input && typeof input === 'object' ? input : {};
  /** @type {Array<{ code: string, field: string, message: string }>} */
  const errors = [];

  const hasMem = src.memoryMb !== undefined && src.memoryMb !== null;
  const hasCpu = src.cpuCores !== undefined && src.cpuCores !== null;

  /** @type {number | null} */
  let normMem = null;
  /** @type {number | null} */
  let normCpu = null;

  if (hasMem) {
    const m = Number(src.memoryMb);
    if (!Number.isFinite(m) || m < DOCKER_MIN_MEMORY_MB) {
      errors.push({
        code: 'BELOW_DOCKER_MEMORY_FLOOR',
        field: 'memoryMb',
        message: `Docker requires memory limit >= ${DOCKER_MIN_MEMORY_MB} MiB (received ${src.memoryMb})`
      });
    } else {
      normMem = Math.ceil(m);
    }
  }

  if (hasCpu) {
    const c = Number(src.cpuCores);
    if (!Number.isFinite(c) || c < DOCKER_MIN_CPU_CORES) {
      errors.push({
        code: 'BELOW_DOCKER_CPU_FLOOR',
        field: 'cpuCores',
        message: `Docker requires CPU limit >= ${DOCKER_MIN_CPU_CORES} cores (received ${src.cpuCores})`
      });
    } else {
      normCpu = Number(c.toFixed(3));
    }
  }

  const valid = errors.length === 0;
  return {
    ok: true,
    valid,
    code: valid ? 'DOCKER_LIMITS_VALID' : errors[0].code,
    errors,
    normalized: valid ? { memoryMb: normMem, cpuCores: normCpu } : null
  };
}

/**
 * Builds a uniform Docker Compose `deploy.resources` limits + reservations patch for
 * BOTH application containers AND database services (`Dokploy#4050` cure).
 *
 * @param {{
 *   serviceName?: string,
 *   serviceType?: string,
 *   recommendedMemoryMb: number,
 *   recommendedCpuCores: number,
 *   reservationMemoryMb?: number,
 *   reservationCpuCores?: number
 * }} recommendation
 */
function buildComposeResourcePatch(recommendation) {
  if (!recommendation || typeof recommendation !== 'object') {
    throw rightsizeError('INVALID_RECOMMENDATION', 'buildComposeResourcePatch requires a recommendation object');
  }

  const limitsCheck = validateDockerLimits({
    memoryMb: recommendation.recommendedMemoryMb,
    cpuCores: recommendation.recommendedCpuCores
  });
  if (!limitsCheck.valid || !limitsCheck.normalized) {
    throw rightsizeError(limitsCheck.code, limitsCheck.errors.map((e) => e.message).join('; '));
  }

  const serviceType = String(recommendation.serviceType || 'app').trim().toLowerCase() === 'database'
    ? 'database'
    : 'app';
  const serviceName = typeof recommendation.serviceName === 'string' && recommendation.serviceName.trim()
    ? recommendation.serviceName.trim().slice(0, 64)
    : (serviceType === 'database' ? 'postgres' : 'app');

  const limitMemMb = /** @type {number} */ (limitsCheck.normalized.memoryMb);
  const limitCpu = /** @type {number} */ (limitsCheck.normalized.cpuCores);
  const rawResMem = recommendation.reservationMemoryMb !== undefined
    ? Number(recommendation.reservationMemoryMb)
    : Math.ceil(limitMemMb * 0.5);
  const resMemMb = Math.max(DOCKER_MIN_MEMORY_MB, Math.min(limitMemMb, Math.ceil(rawResMem)));

  const rawResCpu = recommendation.reservationCpuCores !== undefined
    ? Number(recommendation.reservationCpuCores)
    : limitCpu * 0.5;
  const resCpu = Number(Math.max(DOCKER_MIN_CPU_CORES, Math.min(limitCpu, rawResCpu)).toFixed(3));

  const resources = {
    limits: {
      memory: `${limitMemMb}M`,
      cpus: limitCpu.toFixed(3)
    },
    reservations: {
      memory: `${resMemMb}M`,
      cpus: resCpu.toFixed(3)
    }
  };

  const patch = {
    services: {
      [serviceName]: {
        deploy: {
          resources
        }
      }
    }
  };

  const yaml = [
    'services:',
    `  ${serviceName}:`,
    '    deploy:',
    '      resources:',
    '        limits:',
    `          memory: "${resources.limits.memory}"`,
    `          cpus: "${resources.limits.cpus}"`,
    '        reservations:',
    `          memory: "${resources.reservations.memory}"`,
    `          cpus: "${resources.reservations.cpus}"`
  ].join('\n');

  return {
    ok: true,
    serviceName,
    serviceType,
    limits: resources.limits,
    reservations: resources.reservations,
    patch,
    yaml
  };
}

class ResourceRightsizerService {
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
    return path.join(this.resolveDataDir(), 'resource-rightsizing.json');
  }

  /** @returns {any[]} */
  _loadRecords() {
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) return [];
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      return parsed && Array.isArray(parsed.recommendations) ? parsed.recommendations : [];
    } catch (e) {
      return [];
    }
  }

  /** @param {any[]} recommendations */
  _saveRecords(recommendations) {
    const trimmed = recommendations.slice(-MAX_STORED_RECOMMENDATIONS);
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({ schemaVersion: 1, updatedAt: new Date().toISOString(), recommendations: trimmed }, null, 2) + '\n'
    );
  }

  /**
   * Delegates to `computePercentile`.
   * @param {number[]} samples
   * @param {number} p
   */
  computePercentile(samples, p) {
    return computePercentile(samples, p);
  }

  /**
   * Delegates to `validateDockerLimits`.
   * @param {{ memoryMb?: number, cpuCores?: number }} [input]
   */
  validateDockerLimits(input) {
    return validateDockerLimits(input);
  }

  /**
   * Delegates to `buildComposeResourcePatch`.
   * @param {any} recommendation
   */
  buildComposeResourcePatch(recommendation) {
    return buildComposeResourcePatch(recommendation);
  }

  /**
   * Computes VPA-lite P50/P95/P99 rightsizing recommendations with OOM `+50%` safety upscaling,
   * Docker floor enforcement, and uniform Compose `deploy.resources` patch generation.
   *
   * @param {{
   *   projectId?: string,
   *   serviceName?: string,
   *   serviceType?: 'app' | 'database' | string,
   *   currentMemoryMb: number,
   *   currentCpuCores?: number,
   *   samples?: any[],
   *   oomCount?: number,
   *   headroomPct?: number,
   *   persist?: boolean
   * }} input
   */
  recommendContainerResources(input) {
    if (!input || typeof input !== 'object') {
      throw rightsizeError('INVALID_INPUT', 'recommendContainerResources requires an options object');
    }

    const projectId = String(input.projectId || 'default').trim().slice(0, 128) || 'default';
    const rawType = String(input.serviceType || 'app').trim().toLowerCase();
    const serviceType = rawType === 'database' || rawType === 'db' ? 'database' : 'app';
    const serviceName = typeof input.serviceName === 'string' && input.serviceName.trim()
      ? input.serviceName.trim().slice(0, 64)
      : (serviceType === 'database' ? 'postgres' : 'app');

    const currentMemoryMb = Number(input.currentMemoryMb);
    const currentCpuCores = input.currentCpuCores !== undefined ? Number(input.currentCpuCores) : 1;
    const oomCount = Math.max(0, Math.round(Number(input.oomCount ?? 0) || 0));
    const defaultHeadroom = serviceType === 'database' ? 35 : 25;
    const headroomPct = input.headroomPct !== undefined && Number.isFinite(Number(input.headroomPct))
      ? Math.max(5, Math.min(200, Number(input.headroomPct)))
      : defaultHeadroom;

    const currentCheck = validateDockerLimits({ memoryMb: currentMemoryMb, cpuCores: currentCpuCores });
    if (!currentCheck.valid) {
      throw rightsizeError(currentCheck.code, currentCheck.errors.map((e) => e.message).join('; '));
    }

    const rawSamples = Array.isArray(input.samples) ? input.samples : [];
    /** @type {number[]} */
    const memSamples = [];
    /** @type {number[]} */
    const cpuSamples = [];

    for (const s of rawSamples) {
      if (typeof s === 'number' && Number.isFinite(s) && s >= 0) {
        memSamples.push(s);
      } else if (s && typeof s === 'object') {
        const m = Number(s.memoryMb ?? s.memMb ?? s.ramMb);
        if (Number.isFinite(m) && m >= 0) memSamples.push(m);
        const c = Number(s.cpuCores ?? s.cpu);
        if (Number.isFinite(c) && c >= 0) cpuSamples.push(c);
      }
    }

    // Require >= 10 samples to prevent restart-loop noise from driving bad shrinks
    if (memSamples.length < MIN_SAMPLE_COUNT) {
      return {
        ok: false,
        code: /** @type {'INSUFFICIENT_SAMPLES'} */ ('INSUFFICIENT_SAMPLES'),
        action: /** @type {'HOLD_INSUFFICIENT_SAMPLES'} */ ('HOLD_INSUFFICIENT_SAMPLES'),
        projectId,
        serviceName,
        serviceType,
        sampleCount: memSamples.length,
        minRequiredSamples: MIN_SAMPLE_COUNT,
        message: `Insufficient telemetry samples (${memSamples.length}/${MIN_SAMPLE_COUNT}); collect at least ${MIN_SAMPLE_COUNT} points before rightsizing.`
      };
    }

    const memP50 = Math.round(computePercentile(memSamples, 50));
    const memP95 = Math.round(computePercentile(memSamples, 95));
    const memP99 = Math.round(computePercentile(memSamples, 99));

    const hasCpuTelemetry = cpuSamples.length >= MIN_SAMPLE_COUNT;
    const cpuP50 = hasCpuTelemetry ? Number(computePercentile(cpuSamples, 50).toFixed(3)) : Number((currentCpuCores * 0.5).toFixed(3));
    const cpuP95 = hasCpuTelemetry ? Number(computePercentile(cpuSamples, 95).toFixed(3)) : Number(currentCpuCores.toFixed(3));
    const cpuP99 = hasCpuTelemetry ? Number(computePercentile(cpuSamples, 99).toFixed(3)) : Number(currentCpuCores.toFixed(3));

    const headroomFactor = 1 + headroomPct / 100;
    let recommendedMemoryMb = Math.max(DOCKER_MIN_MEMORY_MB, Math.ceil(memP95 * headroomFactor));
    let recommendedCpuCores = hasCpuTelemetry
      ? Number(Math.max(DOCKER_MIN_CPU_CORES, cpuP95 * headroomFactor).toFixed(3))
      : Number(Math.max(DOCKER_MIN_CPU_CORES, currentCpuCores).toFixed(3));

    /** @type {'UPSCALE_OOM' | 'UPSCALE' | 'SHRINK' | 'HOLD'} */
    let action = 'HOLD';
    let reclaimableMb = 0;
    let wastePct = 0;

    if (oomCount > 0) {
      // OOM SAFETY GUARD: ALWAYS upscale +50% and NEVER shrink an OOMing service!
      const oomBase = Math.max(currentMemoryMb, memP99, memP95);
      recommendedMemoryMb = Math.max(DOCKER_MIN_MEMORY_MB, Math.ceil(oomBase * 1.5));
      recommendedCpuCores = Number(Math.max(DOCKER_MIN_CPU_CORES, currentCpuCores, recommendedCpuCores).toFixed(3));
      action = 'UPSCALE_OOM';
      reclaimableMb = 0;
      wastePct = 0;
    } else if (recommendedMemoryMb > Math.ceil(currentMemoryMb * 1.05)) {
      action = 'UPSCALE';
      reclaimableMb = 0;
      wastePct = 0;
    } else {
      reclaimableMb = Math.max(0, Math.round(currentMemoryMb - recommendedMemoryMb));
      wastePct = currentMemoryMb > 0 ? Number(((reclaimableMb / currentMemoryMb) * 100).toFixed(1)) : 0;
      action = reclaimableMb >= Math.max(32, Math.round(currentMemoryMb * 0.1)) ? 'SHRINK' : 'HOLD';
    }

    const reservationMemoryMb = Math.max(
      DOCKER_MIN_MEMORY_MB,
      Math.min(recommendedMemoryMb, Math.ceil(Math.max(memP50 * 1.1, recommendedMemoryMb * 0.5)))
    );
    const reservationCpuCores = Number(
      Math.max(DOCKER_MIN_CPU_CORES, Math.min(recommendedCpuCores, Math.max(cpuP50, recommendedCpuCores * 0.5))).toFixed(3)
    );

    const dockerLimitsValidation = validateDockerLimits({
      memoryMb: recommendedMemoryMb,
      cpuCores: recommendedCpuCores
    });

    const composePatch = buildComposeResourcePatch({
      serviceName,
      serviceType,
      recommendedMemoryMb,
      recommendedCpuCores,
      reservationMemoryMb,
      reservationCpuCores
    });

    const record = {
      ok: true,
      id: `rs_${crypto.randomBytes(6).toString('hex')}`,
      projectId,
      serviceName,
      serviceType,
      action,
      oomCount,
      headroomPct,
      sampleCount: memSamples.length,
      currentMemoryMb,
      currentCpuCores: Number(currentCpuCores.toFixed(3)),
      p50: { memoryMb: memP50, cpuCores: cpuP50 },
      p95: { memoryMb: memP95, cpuCores: cpuP95 },
      p99: { memoryMb: memP99, cpuCores: cpuP99 },
      recommendedMemoryMb,
      recommendedCpuCores,
      reservationMemoryMb,
      reservationCpuCores,
      reclaimableMb,
      wastePct,
      dockerLimitsValidation,
      composePatch,
      analyzedAt: new Date().toISOString()
    };

    if (input.persist !== false) {
      const records = this._loadRecords();
      records.push(record);
      this._saveRecords(records);
    }

    return record;
  }

  /**
   * Lists persisted rightsizing recommendations (optionally filtered by `projectId`), newest first.
   * @param {string | null} [projectId]
   */
  listRecommendations(projectId) {
    const filterId = typeof projectId === 'string' && projectId.trim() ? projectId.trim() : null;
    return this._loadRecords()
      .filter((r) => (!filterId || r.projectId === filterId))
      .slice()
      .reverse();
  }
}

const defaultResourceRightsizerService = new ResourceRightsizerService();

const exported = Object.assign(defaultResourceRightsizerService, {
  ResourceRightsizerService,
  DOCKER_MIN_MEMORY_MB,
  DOCKER_MIN_CPU_CORES,
  MIN_SAMPLE_COUNT,
  computePercentile: ResourceRightsizerService.prototype.computePercentile.bind(defaultResourceRightsizerService),
  validateDockerLimits: ResourceRightsizerService.prototype.validateDockerLimits.bind(defaultResourceRightsizerService),
  recommendContainerResources: ResourceRightsizerService.prototype.recommendContainerResources.bind(defaultResourceRightsizerService),
  buildComposeResourcePatch: ResourceRightsizerService.prototype.buildComposeResourcePatch.bind(defaultResourceRightsizerService),
  listRecommendations: ResourceRightsizerService.prototype.listRecommendations.bind(defaultResourceRightsizerService)
});

module.exports = exported;
