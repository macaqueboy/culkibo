const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Container Heap-Slope, FD-Leak (`EMFILE`) & Event-Loop Lag Guard (100% Zero-Dep).
 *
 * Previene muertes silenciosas por `OOMKilled` (`137`), agotamiento de descriptores (`EMFILE`)
 * y congelamientos de GC en contenedores Node.js/V8:
 *  - Regresión lineal por mínimos cuadrados ordinarios (`computeLinearSlope`) sobre muestras
 *    de heap y RSS estimando `hoursToOom`.
 *  - Detecta divergencia de buffers nativos (`NATIVE_RSS_DIVERGENCE`), desajuste de
 *    `--max-old-space-size` frente al límite cgroup (`V8_HEAP_EXCEEDS_CGROUP`, recomienda
 *    `Math.floor(containerLimitMb * 0.78)`), agotamiento de FDs >=80% (`FD_EXHAUSTION_EMFILE_RISK`)
 *    y lag p99 del Event Loop >=100ms (`EVENT_LOOP_LAG_CRITICAL`).
 *  - Emite planes proactivos de rolling-drain + `--heapsnapshot-signal=SIGUSR2` (`dryRun: true`).
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/runtime-leak-guard.json`.
 */

const MAX_ANALYSES = 200;

/**
 * Resuelve dinámicamente la ruta a `runtime-leak-guard.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'runtime-leak-guard.json')
    : path.join(base, 'data', 'runtime-leak-guard.json');
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
 * Carga análisis almacenados desde disco (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, analyses: any[] }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), analyses: [] };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && Array.isArray(parsed.analyses)) {
      return parsed;
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), analyses: [] };
}

/**
 * Guarda análisis de forma atómica (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, analyses: any[] }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  if (store.analyses.length > MAX_ANALYSES) {
    store.analyses = store.analyses.slice(-MAX_ANALYSES);
  }
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Calcula la pendiente por mínimos cuadrados ordinarios (OLS) de una serie numérica.
 * Devuelve la tasa de cambio por muestra (redondeada a 3 decimales; `0` si `< 2` muestras).
 *
 * @param {number[]} samples
 * @returns {number}
 */
function computeLinearSlope(samples) {
  if (!Array.isArray(samples)) return 0;
  const nums = samples.map((v) => Number(v)).filter((v) => Number.isFinite(v));
  const n = nums.length;
  if (n < 2) return 0;

  const xMean = (n - 1) / 2;
  let ySum = 0;
  for (let i = 0; i < n; i++) ySum += nums[i];
  const yMean = ySum / n;

  let num = 0;
  let den = 0;
  for (let i = 0; i < n; i++) {
    const dx = i - xMean;
    num += dx * (nums[i] - yMean);
    den += dx * dx;
  }
  if (den === 0) return 0;
  return Math.round((num / den) * 1000) / 1000;
}

/**
 * Analiza telemetría de fugas de heap/RSS, FDs abiertos y lag del Event Loop en contenedores.
 *
 * @param {{
 *   projectId?: string,
 *   containerLimitMb?: number,
 *   configuredMaxOldSpaceMb?: number,
 *   heapSamplesMb?: number[],
 *   rssSamplesMb?: number[],
 *   sampleIntervalMinutes?: number,
 *   openFds?: number,
 *   fdLimit?: number,
 *   eventLoopLagP99Ms?: number,
 *   gcPausePct?: number,
 *   persist?: boolean
 * }} [input]
 */
function analyzeRuntimeLeakTelemetry(input = {}) {
  const opts = input || {};
  const projectId = opts.projectId ? String(opts.projectId).trim() : null;
  const containerLimitMb = Math.max(64, Number(opts.containerLimitMb) || 1024);
  const recommendedMaxOldSpaceMb = Math.floor(containerLimitMb * 0.78);
  const nodeOptions = `--max-old-space-size=${recommendedMaxOldSpaceMb} --heapsnapshot-signal=SIGUSR2`;
  const sampleIntervalMinutes = Math.max(1, Number(opts.sampleIntervalMinutes) || 60);

  const heapSamples = (Array.isArray(opts.heapSamplesMb) ? opts.heapSamplesMb : [])
    .map((v) => Number(v))
    .filter((v) => Number.isFinite(v));
  const rssSamples = (Array.isArray(opts.rssSamplesMb) ? opts.rssSamplesMb : [])
    .map((v) => Number(v))
    .filter((v) => Number.isFinite(v));

  const scaleToHour = 60 / sampleIntervalMinutes;
  const heapSlopePerSample = computeLinearSlope(heapSamples);
  const rssSlopePerSample = computeLinearSlope(rssSamples);
  const heapSlopeMbPerHour = Math.round(heapSlopePerSample * scaleToHour * 100) / 100;
  const rssSlopeMbPerHour = Math.round(rssSlopePerSample * scaleToHour * 100) / 100;

  const latestHeapMb = heapSamples.length > 0 ? heapSamples[heapSamples.length - 1] : 0;
  const latestRssMb = rssSamples.length > 0 ? rssSamples[rssSamples.length - 1] : latestHeapMb;
  const effectiveGrowthMbPerHour = Math.max(heapSlopeMbPerHour, rssSlopeMbPerHour);
  const effectiveUsedMb = Math.max(latestHeapMb, latestRssMb);

  /** @type {number | null} */
  let hoursToOom = null;
  if (effectiveGrowthMbPerHour > 0.5) {
    const remainingMb = Math.max(0, containerLimitMb - effectiveUsedMb);
    hoursToOom = remainingMb <= 0
      ? 0.01
      : Math.round((remainingMb / effectiveGrowthMbPerHour) * 100) / 100;
  }

  const openFds = Math.max(0, Math.floor(Number(opts.openFds) || 0));
  const fdLimit = Math.max(1, Math.floor(Number(opts.fdLimit) || 1024));
  const fdUtilizationPct = Math.round((openFds / fdLimit) * 1000) / 10;
  const eventLoopLagP99Ms = Math.max(0, Number(opts.eventLoopLagP99Ms) || 0);
  const gcPausePct = Math.max(0, Math.min(100, Number(opts.gcPausePct) || 0));

  /** @type {Array<{ code: string, severity: 'critical' | 'high' | 'medium', message: string, fix: string }>} */
  const findings = [];

  // 1. Monotonic V8 heap leak slope
  if (heapSlopeMbPerHour >= 10 || (heapSamples.length >= 3 && heapSlopePerSample >= 10)) {
    findings.push({
      code: 'HEAP_LEAK_SLOPE_HIGH',
      severity: 'critical',
      message: `V8 heap growing at +${heapSlopeMbPerHour} MB/hr (estimated ${hoursToOom ?? 'n/a'}h until ${containerLimitMb} MB cgroup OOM).`,
      fix: `Capture heap snapshot via kill -USR2 <pid> with NODE_OPTIONS="${nodeOptions}" and schedule proactive rolling drain.`
    });
  }

  // 2. Native / Buffer RSS divergence above JS heap
  if (rssSamples.length >= 2 && (rssSlopeMbPerHour - heapSlopeMbPerHour >= 15 || (latestHeapMb > 0 && latestRssMb > latestHeapMb * 1.8 && latestRssMb > containerLimitMb * 0.6))) {
    findings.push({
      code: 'NATIVE_RSS_DIVERGENCE',
      severity: 'high',
      message: `Container RSS (${latestRssMb} MB, +${rssSlopeMbPerHour} MB/hr) diverges sharply from V8 heap (${latestHeapMb} MB) — probable native addon/Buffer leak or glibc arena fragmentation.`,
      fix: 'Audit native C++/Sharp/Buffer pools and consider MALLOC_ARENA_MAX=2 or jemalloc.'
    });
  }

  // 3. V8 max-old-space-size exceeds cgroup container RAM limit
  if (opts.configuredMaxOldSpaceMb !== undefined && opts.configuredMaxOldSpaceMb !== null) {
    const cfg = Number(opts.configuredMaxOldSpaceMb);
    if (!Number.isFinite(cfg) || cfg <= 0 || cfg > Math.floor(containerLimitMb * 0.85)) {
      findings.push({
        code: 'V8_HEAP_EXCEEDS_CGROUP',
        severity: 'high',
        message: `Configured --max-old-space-size (${cfg} MB) is unset or exceeds 85% of ${containerLimitMb} MB cgroup limit — V8 will not GC before kernel SIGKILL (137).`,
        fix: `Set NODE_OPTIONS="${nodeOptions}" (~78% of container RAM limit).`
      });
    }
  }

  // 4. Open file descriptors >= 80% of ulimit -n (EMFILE)
  if (fdUtilizationPct >= 80) {
    findings.push({
      code: 'FD_EXHAUSTION_EMFILE_RISK',
      severity: 'critical',
      message: `Open file descriptors at ${openFds}/${fdLimit} (${fdUtilizationPct}% >= 80%) — imminent EMFILE accept()/socket failure.`,
      fix: 'Close leaked HTTP agents/streams, enforce keep-alive socket caps, and raise container nofile ulimit.'
    });
  }

  // 5. Event-loop p99 lag >= 100ms or heavy GC pause thrashing
  if (eventLoopLagP99Ms >= 100 || gcPausePct >= 25) {
    findings.push({
      code: 'EVENT_LOOP_LAG_CRITICAL',
      severity: 'critical',
      message: `Event-loop p99 lag reached ${eventLoopLagP99Ms} ms (GC pause ${gcPausePct}%) — healthchecks and request latency will time out.`,
      fix: 'Offload synchronous JSON/crypto loops, cap V8 heap to shorten Mark-Compact pauses, and proactively drain degraded replicas.'
    });
  }

  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const safe = findings.length === 0;
  const blocked = !safe;
  const status = criticalCount > 0 ? 'CRITICAL' : (findings.length > 0 ? 'WARNING' : 'HEALTHY');
  const analyzedAt = new Date().toISOString();

  const result = {
    ok: true,
    id: `leak_${crypto.randomBytes(5).toString('hex')}`,
    projectId,
    safe,
    blocked,
    status,
    containerLimitMb,
    recommendedMaxOldSpaceMb,
    nodeOptions,
    heapSlopeMbPerHour,
    rssSlopeMbPerHour,
    hoursToOom,
    openFds,
    fdLimit,
    fdUtilizationPct,
    eventLoopLagP99Ms,
    gcPausePct,
    findings,
    findingCodes: findings.map((f) => f.code),
    analyzedAt
  };

  if (opts.persist !== false) {
    const store = loadStore();
    store.analyses.push({
      id: result.id,
      projectId,
      safe,
      status,
      hoursToOom,
      recommendedMaxOldSpaceMb,
      findingCodes: result.findingCodes,
      analyzedAt
    });
    saveStore(store);
  }

  return result;
}

/**
 * Construye un plan proactivo de rolling-drain + captura de heap snapshot `SIGUSR2`
 * antes de un OOM `SIGKILL` (`dryRun: true` por defecto; acepta análisis o telemetría cruda).
 *
 * @param {any} input
 */
function buildProactiveDrainPlan(input = {}) {
  const opts = input || {};
  const dryRun = opts.dryRun !== undefined ? Boolean(opts.dryRun) : true;
  const analysis = (opts.findings && Array.isArray(opts.findings) && opts.nodeOptions)
    ? opts
    : analyzeRuntimeLeakTelemetry({ ...opts, persist: false });

  const steps = [
    {
      order: 1,
      phase: 'capture-heapsnapshot',
      action: 'Send SIGUSR2 to container PID 1 to write diagnostic .heapsnapshot to ephemeral scratch volume before drain.'
    },
    {
      order: 2,
      phase: 'provision-healthy-replica',
      action: `Start replacement container with NODE_OPTIONS="${analysis.nodeOptions}" and verify /api/health returns 200.`
    },
    {
      order: 3,
      phase: 'readiness-drain',
      action: 'Flip leaking container readiness probe to 503, wait 2x LB healthcheck interval, and drain active connections.'
    },
    {
      order: 4,
      phase: 'graceful-retire',
      action: 'Emit SIGTERM to retire the leaking replica cleanly before kernel cgroup OOM-kill (exit 137).'
    }
  ];

  return {
    ok: true,
    dryRun,
    projectId: analysis.projectId || null,
    status: analysis.status,
    hoursToOom: analysis.hoursToOom,
    recommendedMaxOldSpaceMb: analysis.recommendedMaxOldSpaceMb,
    nodeOptions: analysis.nodeOptions,
    heapSnapshotSignal: 'SIGUSR2',
    steps,
    findingCodes: analysis.findingCodes,
    plannedAt: new Date().toISOString()
  };
}

/**
 * Lista análisis históricos de fugas runtime (más recientes primero).
 * @param {string} [projectId]
 */
function listLeakAnalyses(projectId) {
  const store = loadStore();
  const cleanId = projectId ? String(projectId).trim() : '';
  const items = cleanId
    ? store.analyses.filter((a) => a.projectId === cleanId)
    : store.analyses;
  return [...items].reverse();
}

module.exports = {
  computeLinearSlope,
  analyzeRuntimeLeakTelemetry,
  buildProactiveDrainPlan,
  listLeakAnalyses
};
