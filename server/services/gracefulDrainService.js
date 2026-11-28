'use strict';

/**
 * Culkibo Graceful Stateful Shutdown & Zero-Drop Queue/Webhook Drain Coordinator.
 *
 * Cures `coollabsio/coolify#8627` (rolling-deploy 502/503s), `kamal-proxy` handoff races,
 * shell-form `CMD` swallowing `SIGTERM`, and abrupt 10s `SIGKILL` drops of active webhooks
 * and background payments — zero external npm dependencies:
 *  - Atomic `0o600` persistence in `CULKIBO_DATA_DIR/data/graceful-drains.json`.
 *  - `auditShutdownReadiness`: catches shell-form `CMD`/`ENTRYPOINT` (`PID1_SHELL_WRAPPER`),
 *    LB drain delay `< healthCheckIntervalSec * 2` (`LB_DRAIN_RACE`), and insufficient
 *    `stopGracePeriodSec` (`INSUFFICIENT_STOP_GRACE`).
 *  - Strict 4-phase drain state machine (`FLIP_READINESS_503 -> WAIT_LB_DRAIN ->
 *    DRAIN_INFLIGHT_JOBS -> EMIT_SIGTERM -> COMPLETED`) unconditionally refusing `EMIT_SIGTERM`
 *    while `inFlightJobs > 0 || inFlightHttp > 0 || !lbDrained` (`INFLIGHT_WORK_REMAINING`).
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DRAIN_PHASES = Object.freeze([
  'FLIP_READINESS_503',
  'WAIT_LB_DRAIN',
  'DRAIN_INFLIGHT_JOBS',
  'EMIT_SIGTERM',
  'COMPLETED'
]);

const MAX_STORED_DRAINS = 500;

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
function drainError(code, msg, status = 400) {
  const err = /** @type {any} */ (new Error(msg));
  err.code = code;
  err.status = status;
  return err;
}

/**
 * Extracts final-stage `CMD` and `ENTRYPOINT` instructions from a Dockerfile and checks
 * whether any use shell-form (which spawns `/bin/sh -c` as PID 1 and swallows `SIGTERM`).
 *
 * @param {string} dockerfile
 */
function inspectDockerfilePid1(dockerfile) {
  const raw = typeof dockerfile === 'string' ? dockerfile : '';
  if (!raw.trim()) return { hasShellWrapper: false, offendingInstructions: [], suggestedExecForm: null };

  // Inspect the final build stage only (after last FROM, if multi-stage)
  const lines = raw.split(/\r?\n/);
  let lastFromIdx = -1;
  for (let i = 0; i < lines.length; i += 1) {
    if (/^\s*FROM\s+/i.test(lines[i])) lastFromIdx = i;
  }
  const finalStageLines = lastFromIdx >= 0 ? lines.slice(lastFromIdx + 1) : lines;

  /** @type {string[]} */
  const offendingInstructions = [];
  /** @type {string | null} */
  let suggestedExecForm = null;

  for (const line of finalStageLines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const match = trimmed.match(/^(CMD|ENTRYPOINT)\s+(.+)$/i);
    if (!match) continue;
    const keyword = match[1].toUpperCase();
    const arg = match[2].trim();

    if (!arg.startsWith('[')) {
      offendingInstructions.push(`${keyword} ${arg}`);
      const tokens = arg.split(/\s+/).filter(Boolean);
      suggestedExecForm = `${keyword} ${JSON.stringify(tokens)}`;
    } else if (/^\[\s*"(?:\/bin\/)?(?:sh|bash)"\s*,\s*"-c"/i.test(arg)) {
      offendingInstructions.push(`${keyword} ${arg}`);
    }
  }

  return {
    hasShellWrapper: offendingInstructions.length > 0,
    offendingInstructions,
    suggestedExecForm
  };
}

/**
 * Audits Dockerfile PID-1 signal handling, LB drain delay vs healthcheck interval,
 * and `stop_grace_period` adequacy for active queues/webhooks.
 *
 * @param {{
 *   dockerfile?: string,
 *   stopGracePeriodSec?: number,
 *   lbDrainDelaySec?: number,
 *   healthCheckIntervalSec?: number,
 *   activeQueueDepth?: number
 * }} [input]
 */
function auditShutdownReadiness(input = {}) {
  const src = input && typeof input === 'object' ? input : {};
  const dockerfile = typeof src.dockerfile === 'string' ? src.dockerfile : '';
  const stopGracePeriodSec = Math.max(0, Number(src.stopGracePeriodSec ?? 10) || 0);
  const lbDrainDelaySec = Math.max(0, Number(src.lbDrainDelaySec ?? 0) || 0);
  const healthCheckIntervalSec = Math.max(1, Number(src.healthCheckIntervalSec ?? 5) || 5);
  const activeQueueDepth = Math.max(0, Math.round(Number(src.activeQueueDepth ?? 0) || 0));

  /** @type {Array<{ code: string, severity: 'critical' | 'high' | 'medium', message: string, remediation: string }>} */
  const findings = [];
  let penalty = 0;

  // 1. PID-1 shell-form CMD/ENTRYPOINT check
  const pid1 = inspectDockerfilePid1(dockerfile);
  if (pid1.hasShellWrapper) {
    penalty += 40;
    findings.push({
      code: 'PID1_SHELL_WRAPPER',
      severity: 'critical',
      message: `Shell-form instruction (${pid1.offendingInstructions.join('; ')}) spawns /bin/sh as PID 1, swallowing SIGTERM until Docker sends SIGKILL.`,
      remediation: pid1.suggestedExecForm
        ? `Replace with JSON exec-form: ${pid1.suggestedExecForm} (or wrap with tini/init).`
        : 'Use JSON exec-form CMD ["node", "server.js"] so the app process receives SIGTERM directly as PID 1.'
    });
  }

  // 2. Load balancer drain race check (lbDrainDelaySec must be >= healthCheckIntervalSec * 2)
  const recommendedLbDrainDelaySec = Math.max(10, Math.ceil(healthCheckIntervalSec * 2));
  if (lbDrainDelaySec < healthCheckIntervalSec * 2) {
    penalty += 30;
    findings.push({
      code: 'LB_DRAIN_RACE',
      severity: 'high',
      message: `lbDrainDelaySec (${lbDrainDelaySec}s) is less than 2× healthCheckIntervalSec (${healthCheckIntervalSec * 2}s), causing rolling-deploy 502/503s while LB still routes traffic.`,
      remediation: `Wait at least ${recommendedLbDrainDelaySec}s after flipping readiness to 503 before stopping upstream listeners.`
    });
  }

  // 3. Stop grace period check for in-flight HTTP + active worker queue depth
  const queueDrainAllowanceSec = activeQueueDepth > 0
    ? Math.max(15, Math.min(180, activeQueueDepth * 2))
    : 5;
  const recommendedStopGracePeriodSec = Math.max(recommendedLbDrainDelaySec + queueDrainAllowanceSec, 20);
  const minSafeGrace = Math.max(lbDrainDelaySec, healthCheckIntervalSec * 2) + queueDrainAllowanceSec;
  if (stopGracePeriodSec < minSafeGrace) {
    penalty += 25;
    findings.push({
      code: 'INSUFFICIENT_STOP_GRACE',
      severity: 'high',
      message: `stopGracePeriodSec (${stopGracePeriodSec}s) is too short for LB drain + ${activeQueueDepth} queued jobs (minimum safe: ${minSafeGrace}s).`,
      remediation: `Raise stop_grace_period in Compose to >= ${recommendedStopGracePeriodSec}s so in-flight webhooks/payments finish before SIGKILL.`
    });
  }

  const ready = findings.length === 0;
  const score = Math.max(0, 100 - penalty);

  return {
    ok: true,
    ready,
    score,
    findings,
    codes: findings.map((f) => f.code),
    recommendedLbDrainDelaySec,
    recommendedStopGracePeriodSec,
    suggestedExecForm: pid1.suggestedExecForm,
    auditedAt: new Date().toISOString()
  };
}

class GracefulDrainService {
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
    return path.join(this.resolveDataDir(), 'graceful-drains.json');
  }

  /** @returns {any[]} */
  _loadPlans() {
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) return [];
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      return parsed && Array.isArray(parsed.plans) ? parsed.plans : [];
    } catch (e) {
      return [];
    }
  }

  /** @param {any[]} plans */
  _savePlans(plans) {
    const trimmed = plans.slice(-MAX_STORED_DRAINS);
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({ schemaVersion: 1, updatedAt: new Date().toISOString(), plans: trimmed }, null, 2) + '\n'
    );
  }

  /**
   * Delegates to `auditShutdownReadiness`.
   * @param {Record<string, any>} [input]
   */
  auditShutdownReadiness(input) {
    return auditShutdownReadiness(input);
  }

  /**
   * Initializes an ordered 4-phase graceful shutdown drain plan starting at `FLIP_READINESS_503`.
   *
   * @param {{
   *   projectId?: string,
   *   serviceName?: string,
   *   inFlightHttp?: number,
   *   inFlightJobs?: number,
   *   lbDrainDelaySec?: number,
   *   maxDrainSec?: number,
   *   dryRun?: boolean
   * }} [input]
   */
  planOrderedDrain(input = {}) {
    const src = input && typeof input === 'object' ? input : {};
    const projectId = String(src.projectId || 'default').trim().slice(0, 128) || 'default';
    const serviceName = String(src.serviceName || 'api').trim().slice(0, 64) || 'api';
    const inFlightHttp = Math.max(0, Math.round(Number(src.inFlightHttp ?? 0) || 0));
    const inFlightJobs = Math.max(0, Math.round(Number(src.inFlightJobs ?? 0) || 0));
    const lbDrainDelaySec = Math.max(1, Math.min(300, Math.round(Number(src.lbDrainDelaySec ?? 10) || 10)));
    const maxDrainSec = Math.max(lbDrainDelaySec, Math.min(3600, Math.round(Number(src.maxDrainSec ?? 60) || 60)));
    const dryRun = src.dryRun !== undefined ? Boolean(src.dryRun) : true;

    const drainId = `drain_${crypto.randomBytes(6).toString('hex')}`;
    const nowIso = new Date().toISOString();

    const plan = {
      drainId,
      projectId,
      serviceName,
      dryRun,
      status: 'IN_PROGRESS',
      currentPhase: 'FLIP_READINESS_503',
      phaseIndex: 0,
      readinessFlipped: false,
      lbDrained: false,
      sigtermEmitted: false,
      inFlightHttp,
      inFlightJobs,
      lbDrainDelaySec,
      maxDrainSec,
      phases: [
        { phase: 'FLIP_READINESS_503', status: 'active', description: 'Flip readiness probe to HTTP 503 while preserving liveness' },
        { phase: 'WAIT_LB_DRAIN', status: 'pending', description: `Wait ${lbDrainDelaySec}s for Caddy/LB upstream pool eviction` },
        { phase: 'DRAIN_INFLIGHT_JOBS', status: 'pending', description: 'Drain all active HTTP connections & background webhook/queue jobs to 0' },
        { phase: 'EMIT_SIGTERM', status: 'pending', description: 'Emit clean SIGTERM only once LB drained and 0 in-flight work remains' }
      ],
      history: [
        { phase: 'FLIP_READINESS_503', event: 'PLAN_CREATED', at: nowIso }
      ],
      createdAt: nowIso,
      updatedAt: nowIso
    };

    const plans = this._loadPlans();
    plans.push(plan);
    this._savePlans(plans);

    return {
      ok: true,
      drainId,
      dryRun,
      currentPhase: plan.currentPhase,
      sigtermEmitted: false,
      plan
    };
  }

  /**
   * Advances a drain plan through the strict 4-phase state machine.
   * STRICTLY refuses `EMIT_SIGTERM` whenever `inFlightJobs > 0`, `inFlightHttp > 0`,
   * `!readinessFlipped`, or `!lbDrained` — returning `{ blocked: true, code: 'INFLIGHT_WORK_REMAINING' }`.
   *
   * @param {string} drainId
   * @param {{
   *   inFlightHttp?: number,
   *   inFlightJobs?: number,
   *   lbDrained?: boolean,
   *   readinessFlipped?: boolean
   * }} [telemetry]
   */
  advanceDrainState(drainId, telemetry = {}) {
    const id = typeof drainId === 'string' ? drainId.trim() : '';
    if (!id) throw drainError('INVALID_DRAIN_ID', 'drainId is required');

    const t = telemetry && typeof telemetry === 'object' ? telemetry : {};
    const plans = this._loadPlans();
    const plan = plans.find((p) => p.drainId === id);
    if (!plan) {
      throw drainError('DRAIN_NOT_FOUND', `Drain plan "${id}" not found`, 404);
    }

    const inFlightHttp = Math.max(0, Math.round(Number(t.inFlightHttp ?? 0) || 0));
    const inFlightJobs = Math.max(0, Math.round(Number(t.inFlightJobs ?? 0) || 0));
    const lbDrained = Boolean(t.lbDrained);
    const readinessFlipped = t.readinessFlipped !== undefined ? Boolean(t.readinessFlipped) : true;
    const nowIso = new Date().toISOString();

    plan.inFlightHttp = inFlightHttp;
    plan.inFlightJobs = inFlightJobs;
    plan.lbDrained = lbDrained;
    plan.readinessFlipped = readinessFlipped;
    plan.updatedAt = nowIso;

    // Gate 1: In-flight HTTP requests or background/webhook jobs MUST be 0 before SIGTERM
    if (inFlightJobs > 0 || inFlightHttp > 0) {
      plan.currentPhase = 'DRAIN_INFLIGHT_JOBS';
      plan.phaseIndex = 2;
      plan.sigtermEmitted = false;
      plan.status = 'DRAINING';
      plan.phases[0].status = readinessFlipped ? 'completed' : 'active';
      plan.phases[1].status = lbDrained ? 'completed' : 'active';
      plan.phases[2].status = 'active';
      plan.phases[3].status = 'blocked';
      plan.history.push({
        phase: 'DRAIN_INFLIGHT_JOBS',
        event: 'BLOCKED_INFLIGHT_WORK',
        inFlightHttp,
        inFlightJobs,
        at: nowIso
      });
      this._savePlans(plans);
      return {
        ok: true,
        drainId: id,
        blocked: true,
        code: /** @type {'INFLIGHT_WORK_REMAINING'} */ ('INFLIGHT_WORK_REMAINING'),
        currentPhase: plan.currentPhase,
        sigtermEmitted: false,
        canEmitSigterm: false,
        inFlightHttp,
        inFlightJobs,
        lbDrained,
        readinessFlipped,
        message: `Refusing EMIT_SIGTERM: ${inFlightHttp} HTTP requests and ${inFlightJobs} queue/webhook jobs still in flight.`,
        plan
      };
    }

    // Gate 2: Readiness must be flipped to 503 and LB drain window must have completed
    if (!readinessFlipped || !lbDrained) {
      const waitingPhase = !readinessFlipped ? 'FLIP_READINESS_503' : 'WAIT_LB_DRAIN';
      plan.currentPhase = waitingPhase;
      plan.phaseIndex = !readinessFlipped ? 0 : 1;
      plan.sigtermEmitted = false;
      plan.status = 'DRAINING';
      plan.phases[0].status = readinessFlipped ? 'completed' : 'active';
      plan.phases[1].status = !readinessFlipped ? 'pending' : 'active';
      plan.phases[2].status = 'pending';
      plan.phases[3].status = 'blocked';
      plan.history.push({
        phase: waitingPhase,
        event: !readinessFlipped ? 'BLOCKED_READINESS_NOT_FLIPPED' : 'BLOCKED_LB_DRAIN_PENDING',
        at: nowIso
      });
      this._savePlans(plans);
      return {
        ok: true,
        drainId: id,
        blocked: true,
        code: /** @type {'INFLIGHT_WORK_REMAINING'} */ ('INFLIGHT_WORK_REMAINING'),
        subReason: !readinessFlipped ? 'READINESS_NOT_FLIPPED' : 'LB_DRAIN_PENDING',
        currentPhase: plan.currentPhase,
        sigtermEmitted: false,
        canEmitSigterm: false,
        inFlightHttp: 0,
        inFlightJobs: 0,
        lbDrained,
        readinessFlipped,
        message: !readinessFlipped
          ? 'Refusing EMIT_SIGTERM: readiness probe has not flipped to HTTP 503 yet.'
          : 'Refusing EMIT_SIGTERM: load balancer drain delay has not completed yet.',
        plan
      };
    }

    // All gates satisfied: readiness 503 + LB drained + 0 HTTP + 0 jobs -> safe to EMIT_SIGTERM & COMPLETE!
    plan.currentPhase = 'COMPLETED';
    plan.phaseIndex = 4;
    plan.sigtermEmitted = true;
    plan.status = 'COMPLETED';
    for (const p of plan.phases) p.status = 'completed';
    plan.history.push({ phase: 'EMIT_SIGTERM', event: 'SIGTERM_EMITTED', dryRun: plan.dryRun, at: nowIso });
    plan.history.push({ phase: 'COMPLETED', event: 'DRAIN_COMPLETED', at: nowIso });
    this._savePlans(plans);

    return {
      ok: true,
      drainId: id,
      blocked: false,
      code: /** @type {'SIGTERM_EMITTED'} */ ('SIGTERM_EMITTED'),
      currentPhase: 'COMPLETED',
      sigtermEmitted: true,
      canEmitSigterm: true,
      inFlightHttp: 0,
      inFlightJobs: 0,
      lbDrained: true,
      readinessFlipped: true,
      message: 'All drain gates satisfied (readiness=503, lbDrained=true, inFlight=0); safe SIGTERM phase completed.',
      plan
    };
  }

  /**
   * Lists persisted drain plans (optionally filtered by `projectId`), newest first.
   * @param {string | null} [projectId]
   */
  listDrainPlans(projectId) {
    const filterId = typeof projectId === 'string' && projectId.trim() ? projectId.trim() : null;
    return this._loadPlans()
      .filter((p) => (!filterId || p.projectId === filterId))
      .slice()
      .reverse();
  }
}

const defaultGracefulDrainService = new GracefulDrainService();

const exported = Object.assign(defaultGracefulDrainService, {
  GracefulDrainService,
  DRAIN_PHASES,
  auditShutdownReadiness: GracefulDrainService.prototype.auditShutdownReadiness.bind(defaultGracefulDrainService),
  planOrderedDrain: GracefulDrainService.prototype.planOrderedDrain.bind(defaultGracefulDrainService),
  advanceDrainState: GracefulDrainService.prototype.advanceDrainState.bind(defaultGracefulDrainService),
  listDrainPlans: GracefulDrainService.prototype.listDrainPlans.bind(defaultGracefulDrainService)
});

module.exports = exported;
