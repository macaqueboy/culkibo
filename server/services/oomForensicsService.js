/**
 * Container OOM-Kill Forensics & Crash-Loop Classifier (100% Zero-Dep Pure JS).
 *
 * Distingue con precisión quirúrgica las causas reales de caída de contenedores:
 *  - `STALE_HISTORICAL_TASK_IGNORED`: cura los falsos rollbacks de Portainer Swarm
 *    ante tareas OOM históricas/obsoletas (`historicalOnly: true` → `ignoreForRollback: true`).
 *  - `CGROUP_OOM_KILL`: exit 137 con `oomKilled` o `cgroupOomKills > 0` (o firma OOM en logs),
 *    calculando recomendación de RAM segura `1.5×`.
 *  - `FORCED_SIGKILL_TIMEOUT`: exit 137 SIN OOM (timeout de `stop_grace_period` → SIGKILL).
 *  - `SEGFAULT_ARCH_OR_NATIVE`: exit 139 (SIGSEGV / incompatibilidad amd64↔arm64 / nativo).
 *  - `ABORT_HEAP_OR_ASSERT`: exit 134 (SIGABRT / fallo de heap o assertion nativa).
 *  - `GRACEFUL_SIGTERM_EXITED`: exit 143 (parada limpia por SIGTERM).
 *  - `EXEC_OR_ENTRYPOINT_MISSING`: exit 126/127 (permisos, CRLF o binario/entrypoint ausente).
 *  - `HEALTHCHECK_CRASH_LOOP`: app escuchando en logs mientras las sondas fallan (`unhealthy`).
 */

const FAILURE_CLASSES = Object.freeze([
  'STALE_HISTORICAL_TASK_IGNORED',
  'CGROUP_OOM_KILL',
  'FORCED_SIGKILL_TIMEOUT',
  'SEGFAULT_ARCH_OR_NATIVE',
  'ABORT_HEAP_OR_ASSERT',
  'GRACEFUL_SIGTERM_EXITED',
  'EXEC_OR_ENTRYPOINT_MISSING',
  'HEALTHCHECK_CRASH_LOOP'
]);

const OOM_LOG_RE = /\b(?:out of memory|oom[- ]?kill(?:ed)?|memoryerror|cannot allocate memory|javascript heap out of memory|fatal error:.*heap|memory cgroup out of memory)\b/i;
const READY_LOG_RE = /\b(?:listening on|server ready|ready on|started on|bound to|accepting connections|application startup complete|uvicorn running)\b/i;
const HEALTH_FAIL_LOG_RE = /\b(?:healthcheck|readiness|liveness|probe failed|unhealthy|connection refused)\b/i;

/**
 * Calcula un backoff exponencial acotado (5s, 10s, 20s, 40s, 80s, 160s, máx 300s).
 * @param {number} restartCount
 * @returns {number}
 */
function computeBackoffSec(restartCount) {
  const n = Math.floor(Number(restartCount) || 0);
  if (n <= 0) return 0;
  return Math.min(300, 5 * Math.pow(2, Math.min(n - 1, 10)));
}

/**
 * Clasifica el fallo de un contenedor y devuelve severidad, confianza, causa raíz,
 * recomendación de RAM y plan de remediación accionable.
 *
 * @param {{
 *   containerName?: string,
 *   exitCode?: number | null,
 *   oomKilled?: boolean,
 *   restartCount?: number,
 *   memoryLimitMb?: number,
 *   memoryPeakMb?: number,
 *   cgroupOomKills?: number,
 *   recentLogs?: string,
 *   healthStatus?: string,
 *   uptimeSec?: number,
 *   historicalOnly?: boolean
 * }} [input]
 */
function classifyContainerFailure(input = {}) {
  const opts = input || {};
  const containerName = String(opts.containerName || '');
  const exitCode = opts.exitCode === null || opts.exitCode === undefined ? null : Number(opts.exitCode);
  const oomKilled = Boolean(opts.oomKilled);
  const restartCount = Math.max(0, Math.floor(Number(opts.restartCount) || 0));
  const memoryLimitMb = Math.max(0, Number(opts.memoryLimitMb) || 0);
  const memoryPeakMb = Math.max(0, Number(opts.memoryPeakMb) || 0);
  const cgroupOomKills = Math.max(0, Math.floor(Number(opts.cgroupOomKills) || 0));
  const recentLogs = String(opts.recentLogs || '');
  const healthStatus = String(opts.healthStatus || '').trim().toLowerCase();
  const uptimeSec = Math.max(0, Number(opts.uptimeSec) || 0);
  const historicalOnly = Boolean(opts.historicalOnly);
  const backoffSec = computeBackoffSec(restartCount);

  // 1. STALE_HISTORICAL_TASK_IGNORED (highest precedence — prevents false rollbacks)
  if (historicalOnly) {
    return {
      ok: true,
      containerName,
      classification: 'STALE_HISTORICAL_TASK_IGNORED',
      severity: 'info',
      confidence: 0.99,
      rootCause: `Superseded/historical task event (exit=${exitCode ?? 'n/a'}, oomKilled=${oomKilled}) belongs to a retired container revision and must be ignored for rollback decisions.`,
      ignoreForRollback: true,
      recommendedMemoryMb: null,
      backoffSec: 0,
      remediationActions: [
        'Ignore this historical task for automated rollback triggers (active revision is unaffected).',
        'Prune exited historical containers/tasks periodically to keep inspection telemetry clean.'
      ]
    };
  }

  const hasOomLog = OOM_LOG_RE.test(recentLogs);
  const calcRecommendedRam = () => Math.ceil(Math.max(memoryLimitMb || 256, memoryPeakMb || 256) * 1.5);

  // 2. CGROUP_OOM_KILL: exit 137 + OOM evidence (kernel flag, cgroup counter, or OOM logs)
  if (
    (exitCode === 137 && (oomKilled || cgroupOomKills > 0 || hasOomLog))
    || (oomKilled && (exitCode === null || exitCode === 137))
  ) {
    const recommendedMemoryMb = calcRecommendedRam();
    return {
      ok: true,
      containerName,
      classification: 'CGROUP_OOM_KILL',
      severity: 'critical',
      confidence: oomKilled || cgroupOomKills > 0 ? 0.99 : 0.92,
      rootCause: `Linux kernel cgroup OOM-killer terminated process (exit 137, oomKilled=${oomKilled}, cgroupOomKills=${cgroupOomKills}, peak=${memoryPeakMb || 'n/a'}MB / limit=${memoryLimitMb || 'n/a'}MB).`,
      ignoreForRollback: false,
      recommendedMemoryMb,
      backoffSec,
      remediationActions: [
        `Increase container memory limit to at least ${recommendedMemoryMb} MB (1.5x current limit/peak).`,
        'Cap runtime heap inside the container (e.g. NODE_OPTIONS=--max-old-space-size or GOMEMLIMIT) to ~75% of the cgroup limit.',
        'Capture heap profile under load to verify whether growth is organic traffic or a memory leak.'
      ]
    };
  }

  // 3. FORCED_SIGKILL_TIMEOUT: exit 137 WITHOUT OOM (grace period timeout SIGKILL)
  if (exitCode === 137 && !oomKilled && cgroupOomKills === 0) {
    return {
      ok: true,
      containerName,
      classification: 'FORCED_SIGKILL_TIMEOUT',
      severity: 'high',
      confidence: 0.95,
      rootCause: `Container received forced SIGKILL (exit 137) with oomKilled=false and cgroupOomKills=0 — process ignored SIGTERM past stop_grace_period (NOT an OOM kill).`,
      ignoreForRollback: false,
      recommendedMemoryMb: null,
      backoffSec,
      remediationActions: [
        'Handle SIGTERM gracefully in PID 1 (use exec-form CMD ["node", ...] or tini/dumb-init instead of shell wrapper).',
        'Drain in-flight HTTP requests and close DB pools quickly, or raise stop_grace_period if graceful draining legitimately takes >10s.',
        'Do NOT blindly raise memory limits — this exit 137 was a forced timeout kill, not memory exhaustion.'
      ]
    };
  }

  // 4. SEGFAULT_ARCH_OR_NATIVE: exit 139 (SIGSEGV)
  if (exitCode === 139) {
    return {
      ok: true,
      containerName,
      classification: 'SEGFAULT_ARCH_OR_NATIVE',
      severity: 'critical',
      confidence: 0.96,
      rootCause: 'Process crashed with SIGSEGV (exit 139) — typically caused by amd64/arm64 binary mismatch, glibc vs musl (Alpine) native addon incompatibility, or native memory corruption.',
      ignoreForRollback: false,
      recommendedMemoryMb: null,
      backoffSec,
      remediationActions: [
        'Verify image platform architecture matches the host CPU (`linux/amd64` vs `linux/arm64`).',
        'Rebuild native C/C++/Rust addons inside the target base image (or switch Alpine musl to Debian slim glibc for prebuilt binaries).',
        'Inspect native dependency versions (sharp, bcrypt, sqlite3, prisma engines) for ABI compatibility.'
      ]
    };
  }

  // 5. ABORT_HEAP_OR_ASSERT: exit 134 (SIGABRT)
  if (exitCode === 134) {
    const recommendedMemoryMb = hasOomLog ? calcRecommendedRam() : null;
    return {
      ok: true,
      containerName,
      classification: 'ABORT_HEAP_OR_ASSERT',
      severity: 'high',
      confidence: 0.94,
      rootCause: hasOomLog
        ? 'Runtime aborted with SIGABRT (exit 134) after hitting an internal heap allocation failure (e.g. V8 max-old-space-size).'
        : 'Process aborted with SIGABRT (exit 134) due to an unhandled runtime assertion, native abort(), or heap corruption.',
      ignoreForRollback: false,
      recommendedMemoryMb,
      backoffSec,
      remediationActions: hasOomLog
        ? [
            `Raise container RAM to ${recommendedMemoryMb} MB and align NODE_OPTIONS=--max-old-space-size accordingly.`,
            'Audit recent memory spikes or large synchronous JSON/buffer allocations.'
          ]
        : [
            'Inspect stderr stack trace right before SIGABRT to locate the failing native assertion or panic.',
            'Check runtime flags, FFI bindings, and cgroup thread/file-descriptor limits.'
          ]
    };
  }

  // 6. EXEC_OR_ENTRYPOINT_MISSING: exit 126 or 127
  if (exitCode === 126 || exitCode === 127) {
    return {
      ok: true,
      containerName,
      classification: 'EXEC_OR_ENTRYPOINT_MISSING',
      severity: 'high',
      confidence: 0.97,
      rootCause: exitCode === 126
        ? 'Entrypoint/command found but could not be executed (exit 126 — missing +x permission or incompatible binary format).'
        : 'Entrypoint command, shell, or dynamic linker not found inside container image (exit 127 — missing binary, CRLF shebang, or missing /bin/sh in distroless).',
      ignoreForRollback: false,
      recommendedMemoryMb: null,
      backoffSec,
      remediationActions: [
        'Ensure entrypoint script has Unix LF line endings (not Windows CRLF) and `chmod +x` before `COPY`.',
        'In distroless/scratch images, use JSON exec-form `CMD [...]` because `/bin/sh` is intentionally absent.',
        'Verify the target binary exists on `$PATH` in the final multi-stage runtime image.'
      ]
    };
  }

  // 7. HEALTHCHECK_CRASH_LOOP: container marked unhealthy (esp. app listening while probe fails)
  if (healthStatus === 'unhealthy' && (READY_LOG_RE.test(recentLogs) || HEALTH_FAIL_LOG_RE.test(recentLogs) || restartCount >= 1 || uptimeSec >= 0)) {
    const appListening = READY_LOG_RE.test(recentLogs);
    return {
      ok: true,
      containerName,
      classification: 'HEALTHCHECK_CRASH_LOOP',
      severity: 'high',
      confidence: appListening ? 0.96 : 0.9,
      rootCause: appListening
        ? 'Application logged a ready/listening state, yet container health probes repeatedly failed (`unhealthy`) — likely port mismatch, binding to `127.0.0.1` instead of `0.0.0.0`, or missing curl/wget in slim image.'
        : 'Container repeatedly failed healthcheck probes (`healthStatus=unhealthy`), causing orchestrator restart loops.',
      ignoreForRollback: false,
      recommendedMemoryMb: null,
      backoffSec,
      remediationActions: [
        'Verify the app binds to `0.0.0.0:<PORT>` and matches the configured healthcheck path & port.',
        'Increase healthcheck `start_period` if cold boot/migrations exceed the initial probe window.',
        'Avoid shelling out to `curl`/`wget` in slim/distroless images; use a native runtime probe or TCP/HTTP check.'
      ]
    };
  }

  // 8. GRACEFUL_SIGTERM_EXITED: exit 143 (clean SIGTERM stop)
  if (exitCode === 143) {
    return {
      ok: true,
      containerName,
      classification: 'GRACEFUL_SIGTERM_EXITED',
      severity: 'info',
      confidence: 0.95,
      rootCause: 'Process exited cleanly upon receiving SIGTERM (exit 143) — standard graceful shutdown during rolling deploy, scale-down, or restart.',
      ignoreForRollback: true,
      recommendedMemoryMb: null,
      backoffSec: 0,
      remediationActions: [
        'Confirm whether this SIGTERM corresponded to an intentional deploy, autoscaler scale-down, or host maintenance.',
        'No rollback required unless restarts are unexpected and recurring.'
      ]
    };
  }

  // Secondary OOM catch if OOM signature appears in logs without exit 137
  if (hasOomLog) {
    const recommendedMemoryMb = calcRecommendedRam();
    return {
      ok: true,
      containerName,
      classification: 'CGROUP_OOM_KILL',
      severity: 'critical',
      confidence: 0.85,
      rootCause: `Memory exhaustion signature detected in container logs (exit=${exitCode ?? 'n/a'}).`,
      ignoreForRollback: false,
      recommendedMemoryMb,
      backoffSec,
      remediationActions: [
        `Increase container memory limit to at least ${recommendedMemoryMb} MB.`,
        'Review recent log trace for memory allocation spike.'
      ]
    };
  }

  // Fallback for unclassified non-zero / unknown exit codes
  return {
    ok: true,
    containerName,
    classification: exitCode === 0 ? 'GRACEFUL_SIGTERM_EXITED' : 'HEALTHCHECK_CRASH_LOOP',
    severity: exitCode === 0 ? 'info' : 'medium',
    confidence: 0.6,
    rootCause: exitCode === 0
      ? 'Container exited cleanly with code 0.'
      : `Container exited unexpectedly with code ${exitCode ?? 'unknown'} after ${uptimeSec}s (restarts=${restartCount}).`,
    ignoreForRollback: exitCode === 0,
    recommendedMemoryMb: null,
    backoffSec,
    remediationActions: [
      'Inspect the last 100 lines of container stdout/stderr for unhandled application exceptions.',
      'Verify required environment variables and downstream database/Redis connectivity.'
    ]
  };
}

module.exports = {
  FAILURE_CLASSES,
  computeBackoffSec,
  classifyContainerFailure
};
