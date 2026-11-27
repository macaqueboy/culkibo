'use strict';

/**
 * Culkibo Incident Deduplication, Flapping Damper & On-Call Escalation Router.
 *
 * Answers `uptime-kuma#3255` with GoAlert / Keep / Grafana OnCall reliability DNA
 * in zero runtime npm dependencies:
 *  - Atomic `0o600` persistence in `CULKIBO_DATA_DIR/data/oncall-policies.json`.
 *  - Fingerprint deduplication: collapses duplicate firing alerts into a single open incident
 *    (`occurrences++`, `deduplicated: true`, `suppressed: true`, 0 duplicate pages).
 *  - Flapping damper: `>= flappingThreshold` `firing <-> resolved` transitions inside
 *    `flappingWindowSec` sets `flapping: true`, `status: 'flapping_suppressed'`,
 *    `reason: 'FLAPPING_SUPPRESSED'`, halting notification storms & escalations.
 *  - Deterministic shift rotation: `floor((nowMs - rotationStartMs) / (shiftDurationHours * 3600000)) % responders.length`.
 *  - Tiered ack-timeout escalation (`Tier 1 -> Tier 2 -> Tier 3`), immediately frozen on `acknowledgeIncident`.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DEFAULT_POLICY_OPTIONS = Object.freeze({
  shiftDurationHours: 24,
  rotationStartMs: 0,
  ackTimeoutSec: 300,
  flappingWindowSec: 600,
  flappingThreshold: 3
});

const VALID_SEVERITIES = new Set(['critical', 'high', 'warning', 'info']);
const MAX_INCIDENTS = 1000;

/**
 * @typedef {object} OnCallTier
 * @property {number} tier
 * @property {string[]} responders
 */

/**
 * @typedef {object} OnCallPolicy
 * @property {string} id
 * @property {string} name
 * @property {number} shiftDurationHours
 * @property {number} rotationStartMs
 * @property {number} ackTimeoutSec
 * @property {number} flappingWindowSec
 * @property {number} flappingThreshold
 * @property {OnCallTier[]} tiers
 * @property {string} createdAt
 * @property {string} updatedAt
 */

/**
 * @typedef {'open' | 'acknowledged' | 'resolved' | 'flapping_suppressed'} IncidentStatus
 */

/**
 * @typedef {object} EscalationEvent
 * @property {number} fromTier
 * @property {number} toTier
 * @property {string} responder
 * @property {number} escalatedAtMs
 * @property {string} escalatedAt
 * @property {string} reason
 */

/**
 * @typedef {object} OnCallIncident
 * @property {string} id
 * @property {string} policyId
 * @property {string} fingerprint
 * @property {string | null} projectId
 * @property {string} severity
 * @property {string} title
 * @property {IncidentStatus} status
 * @property {'firing' | 'resolved'} lastState
 * @property {number} occurrences
 * @property {boolean} flapping
 * @property {number[]} stateTransitions
 * @property {number} transitionCount
 * @property {number} currentTier
 * @property {string} assignedResponder
 * @property {number} createdAtMs
 * @property {string} createdAt
 * @property {number} lastSeenAtMs
 * @property {string} lastSeenAt
 * @property {number} lastEscalatedAtMs
 * @property {string} lastEscalatedAt
 * @property {string | null} acknowledgedBy
 * @property {number | null} acknowledgedAtMs
 * @property {string | null} acknowledgedAt
 * @property {number | null} resolvedAtMs
 * @property {string | null} resolvedAt
 * @property {number | null} suppressedAtMs
 * @property {EscalationEvent[]} escalationHistory
 */

/**
 * @typedef {object} OnCallStoreState
 * @property {number} schemaVersion
 * @property {string} updatedAt
 * @property {Record<string, OnCallPolicy>} policies
 * @property {OnCallIncident[]} incidents
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
function oncallError(code, msg, status = 400) {
  const err = /** @type {any} */ (new Error(msg));
  err.code = code;
  err.status = status;
  return err;
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
    throw oncallError('INVALID_TIMESTAMP', 'nowMs must be a finite non-negative number');
  }
  return Math.floor(n);
}

/**
 * Deterministic responder resolver for a tier at `nowMs`.
 * Uses Euclidean modulo so negative offsets before `rotationStartMs` never yield undefined.
 *
 * @param {OnCallPolicy} policy
 * @param {OnCallTier} tierObj
 * @param {number} nowMs
 */
function computeTierResponder(policy, tierObj, nowMs) {
  const shiftMs = policy.shiftDurationHours * 3600000;
  const rawShift = Math.floor((nowMs - policy.rotationStartMs) / shiftMs);
  const len = tierObj.responders.length;
  const responderIndex = ((rawShift % len) + len) % len;
  const shiftEndsAtMs = policy.rotationStartMs + (rawShift + 1) * shiftMs;
  return {
    tier: tierObj.tier,
    responder: tierObj.responders[responderIndex],
    responderIndex,
    responders: [...tierObj.responders],
    shiftIndex: rawShift,
    shiftEndsAtMs,
    shiftEndsAt: new Date(shiftEndsAtMs).toISOString()
  };
}

/**
 * Validates and normalizes an on-call policy input.
 * @param {Record<string, any>} input
 * @param {OnCallPolicy | null} [existing]
 * @returns {OnCallPolicy}
 */
function normalizePolicy(input, existing = null) {
  if (!input || typeof input !== 'object') {
    throw oncallError('INVALID_POLICY', 'savePolicy requires a policy object');
  }
  const name = typeof input.name === 'string' ? input.name.trim().slice(0, 128) : '';
  if (!name) {
    throw oncallError('INVALID_POLICY', 'Policy name is required');
  }

  const rawId = typeof input.id === 'string' && input.id.trim()
    ? input.id.trim().slice(0, 128)
    : (existing ? existing.id : `oncall_${crypto.randomBytes(6).toString('hex')}`);

  const shiftDurationHours = input.shiftDurationHours !== undefined
    ? Number(input.shiftDurationHours)
    : (existing ? existing.shiftDurationHours : DEFAULT_POLICY_OPTIONS.shiftDurationHours);
  if (!Number.isFinite(shiftDurationHours) || shiftDurationHours <= 0 || shiftDurationHours > 8760) {
    throw oncallError('INVALID_POLICY', 'shiftDurationHours must be > 0 and <= 8760');
  }

  const rotationStartMs = input.rotationStartMs !== undefined
    ? Number(input.rotationStartMs)
    : (existing ? existing.rotationStartMs : DEFAULT_POLICY_OPTIONS.rotationStartMs);
  if (!Number.isFinite(rotationStartMs) || rotationStartMs < 0) {
    throw oncallError('INVALID_POLICY', 'rotationStartMs must be a finite non-negative epoch millisecond number');
  }

  const ackTimeoutSec = input.ackTimeoutSec !== undefined
    ? Math.round(Number(input.ackTimeoutSec))
    : (existing ? existing.ackTimeoutSec : DEFAULT_POLICY_OPTIONS.ackTimeoutSec);
  if (!Number.isInteger(ackTimeoutSec) || ackTimeoutSec < 1 || ackTimeoutSec > 86400) {
    throw oncallError('INVALID_POLICY', 'ackTimeoutSec must be an integer 1..86400');
  }

  const flappingWindowSec = input.flappingWindowSec !== undefined
    ? Math.round(Number(input.flappingWindowSec))
    : (existing ? existing.flappingWindowSec : DEFAULT_POLICY_OPTIONS.flappingWindowSec);
  if (!Number.isInteger(flappingWindowSec) || flappingWindowSec < 1 || flappingWindowSec > 86400) {
    throw oncallError('INVALID_POLICY', 'flappingWindowSec must be an integer 1..86400');
  }

  const flappingThreshold = input.flappingThreshold !== undefined
    ? Math.round(Number(input.flappingThreshold))
    : (existing ? existing.flappingThreshold : DEFAULT_POLICY_OPTIONS.flappingThreshold);
  if (!Number.isInteger(flappingThreshold) || flappingThreshold < 2 || flappingThreshold > 100) {
    throw oncallError('INVALID_POLICY', 'flappingThreshold must be an integer 2..100');
  }

  const rawTiers = Array.isArray(input.tiers) ? input.tiers : (existing ? existing.tiers : []);
  if (!Array.isArray(rawTiers) || rawTiers.length === 0 || rawTiers.length > 10) {
    throw oncallError('INVALID_POLICY', 'tiers must be a non-empty array of 1..10 escalation tiers');
  }

  /** @type {Set<number>} */
  const seenTierNumbers = new Set();
  /** @type {OnCallTier[]} */
  const tiers = rawTiers.map((t, idx) => {
    if (!t || typeof t !== 'object') {
      throw oncallError('INVALID_POLICY', `tiers[${idx}] must be an object`);
    }
    const tierNum = t.tier !== undefined ? Math.round(Number(t.tier)) : idx + 1;
    if (!Number.isInteger(tierNum) || tierNum < 1 || tierNum > 20) {
      throw oncallError('INVALID_POLICY', `tiers[${idx}].tier must be an integer 1..20`);
    }
    if (seenTierNumbers.has(tierNum)) {
      throw oncallError('INVALID_POLICY', `Duplicate escalation tier number: ${tierNum}`);
    }
    seenTierNumbers.add(tierNum);

    const rawResponders = Array.isArray(t.responders) ? t.responders : [];
    const responders = Array.from(
      new Set(
        rawResponders
          .filter((r) => typeof r === 'string' && r.trim().length > 0)
          .map((r) => r.trim().slice(0, 128))
      )
    );
    if (responders.length === 0) {
      throw oncallError('INVALID_POLICY', `Tier ${tierNum} must have at least one non-empty responder`);
    }
    return { tier: tierNum, responders };
  }).sort((a, b) => a.tier - b.tier);

  const nowIso = new Date().toISOString();
  return {
    id: rawId,
    name,
    shiftDurationHours,
    rotationStartMs: Math.floor(rotationStartMs),
    ackTimeoutSec,
    flappingWindowSec,
    flappingThreshold,
    tiers,
    createdAt: existing ? existing.createdAt : nowIso,
    updatedAt: nowIso
  };
}

/**
 * Shallow-clones an incident record with copied arrays so callers cannot mutate store state.
 * @param {OnCallIncident} inc
 * @returns {OnCallIncident}
 */
function cloneIncident(inc) {
  return {
    ...inc,
    stateTransitions: [...inc.stateTransitions],
    escalationHistory: inc.escalationHistory.map((e) => ({ ...e }))
  };
}

class OnCallEscalationService {
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
    return path.join(this.resolveDataDir(), 'oncall-policies.json');
  }

  /** @returns {OnCallStoreState} */
  _loadState() {
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) {
      return {
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        policies: {},
        incidents: []
      };
    }
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      return {
        schemaVersion: 1,
        updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : new Date().toISOString(),
        policies: parsed && parsed.policies && typeof parsed.policies === 'object' ? parsed.policies : {},
        incidents: parsed && Array.isArray(parsed.incidents) ? parsed.incidents : []
      };
    } catch (e) {
      return {
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        policies: {},
        incidents: []
      };
    }
  }

  /** @param {OnCallStoreState} state */
  _saveState(state) {
    let incidents = state.incidents;
    if (incidents.length > MAX_INCIDENTS) {
      const active = incidents.filter((i) => i.status !== 'resolved');
      const resolved = incidents
        .filter((i) => i.status === 'resolved')
        .sort((a, b) => b.lastSeenAtMs - a.lastSeenAtMs)
        .slice(0, Math.max(0, MAX_INCIDENTS - active.length));
      incidents = [...active, ...resolved];
    }

    const payload = {
      schemaVersion: 1,
      updatedAt: new Date().toISOString(),
      policies: state.policies,
      incidents
    };
    atomicWriteFileSync(this.getStoreFilePath(), JSON.stringify(payload, null, 2) + '\n');
  }

  /**
   * Validates and atomically persists an on-call escalation policy.
   * @param {Record<string, any>} input
   * @returns {OnCallPolicy}
   */
  savePolicy(input) {
    const state = this._loadState();
    const existingId = input && typeof input.id === 'string' && input.id.trim() ? input.id.trim() : null;
    const existing = existingId && state.policies[existingId] ? state.policies[existingId] : null;
    const policy = normalizePolicy(input, existing);
    state.policies[policy.id] = policy;
    this._saveState(state);
    return {
      ...policy,
      tiers: policy.tiers.map((t) => ({ tier: t.tier, responders: [...t.responders] }))
    };
  }

  /**
   * Lists all saved on-call escalation policies.
   * @returns {OnCallPolicy[]}
   */
  listPolicies() {
    const state = this._loadState();
    return Object.values(state.policies).map((p) => ({
      ...p,
      tiers: p.tiers.map((t) => ({ tier: t.tier, responders: [...t.responders] }))
    }));
  }

  /**
   * Deterministically resolves the active on-call responder for every tier of `policyId` at `nowMs`.
   * @param {string} policyId
   * @param {number} [nowMs]
   */
  resolveCurrentOnCall(policyId, nowMs = Date.now()) {
    const id = typeof policyId === 'string' ? policyId.trim() : '';
    const ts = normalizeNowMs(nowMs);
    const state = this._loadState();
    const policy = state.policies[id];
    if (!policy) {
      throw oncallError('POLICY_NOT_FOUND', `On-call policy "${id}" not found`, 404);
    }

    const resolvedTiers = policy.tiers.map((t) => computeTierResponder(policy, t, ts));
    const primary = resolvedTiers[0];

    return {
      policyId: policy.id,
      policyName: policy.name,
      tier: primary.tier,
      responder: primary.responder,
      primaryResponder: primary.responder,
      responderIndex: primary.responderIndex,
      shiftIndex: primary.shiftIndex,
      shiftDurationHours: policy.shiftDurationHours,
      shiftEndsAtMs: primary.shiftEndsAtMs,
      shiftEndsAt: primary.shiftEndsAt,
      evaluatedAtMs: ts,
      evaluatedAt: new Date(ts).toISOString(),
      tiers: resolvedTiers
    };
  }

  /**
   * Ingests a firing or resolved alert event with fingerprint deduplication and flapping suppression.
   *
   * @param {{
   *   policyId: string,
   *   fingerprint: string,
   *   projectId?: string | null,
   *   severity?: string,
   *   title?: string,
   *   state?: 'firing' | 'resolved',
   *   nowMs?: number
   * }} input
   */
  ingestAlert(input) {
    if (!input || typeof input !== 'object') {
      throw oncallError('INVALID_INPUT', 'ingestAlert requires an alert payload');
    }
    const policyId = typeof input.policyId === 'string' ? input.policyId.trim() : '';
    const fingerprint = typeof input.fingerprint === 'string' ? input.fingerprint.trim().slice(0, 256) : '';
    if (!fingerprint) {
      throw oncallError('INVALID_FINGERPRINT', 'Alert fingerprint is required');
    }

    const alertState = input.state === undefined ? 'firing' : String(input.state).toLowerCase();
    if (alertState !== 'firing' && alertState !== 'resolved') {
      throw oncallError('INVALID_STATE', 'Alert state must be "firing" or "resolved"');
    }

    const rawSeverity = input.severity === undefined ? 'critical' : String(input.severity).toLowerCase();
    const severity = VALID_SEVERITIES.has(rawSeverity) ? rawSeverity : 'critical';
    const title = typeof input.title === 'string' && input.title.trim()
      ? input.title.trim().slice(0, 256)
      : fingerprint;
    const projectId = typeof input.projectId === 'string' && input.projectId.trim()
      ? input.projectId.trim().slice(0, 128)
      : null;
    const nowMs = normalizeNowMs(input.nowMs);

    const store = this._loadState();
    const policy = store.policies[policyId];
    if (!policy) {
      throw oncallError('POLICY_NOT_FOUND', `On-call policy "${policyId}" not found`, 404);
    }

    const windowCutoffMs = nowMs - policy.flappingWindowSec * 1000;

    // Locate the most recent incident for (policyId, fingerprint)
    const matchingIncidents = store.incidents
      .filter((inc) => inc.policyId === policyId && inc.fingerprint === fingerprint)
      .sort((a, b) => b.lastSeenAtMs - a.lastSeenAtMs);

    /** @type {OnCallIncident | null} */
    let candidate = null;
    for (const inc of matchingIncidents) {
      if (inc.status === 'open' || inc.status === 'acknowledged') {
        candidate = inc;
        break;
      }
      if (inc.status === 'flapping_suppressed' || inc.status === 'resolved') {
        // Reuse recent incident within the flapping window so firing <-> resolved toggles are tracked accurately
        const recentTransitions = (inc.stateTransitions || []).filter((ts) => ts >= windowCutoffMs);
        if (inc.lastSeenAtMs >= windowCutoffMs || recentTransitions.length > 0) {
          candidate = inc;
          break;
        }
      }
    }

    // Case A: Resolved event with no active or recent incident
    if (!candidate && alertState === 'resolved') {
      return {
        ok: true,
        incident: null,
        created: false,
        deduplicated: false,
        suppressed: true,
        paged: false,
        flapping: false,
        reason: 'NO_OPEN_INCIDENT'
      };
    }

    const primaryTier = policy.tiers[0];
    const primaryOnCall = computeTierResponder(policy, primaryTier, nowMs);

    // Case B: Brand-new firing incident (either none existed or prior resolved incident aged out of flapping window)
    if (!candidate || (candidate.status === 'resolved' && candidate.lastSeenAtMs < windowCutoffMs && alertState === 'firing')) {
      /** @type {OnCallIncident} */
      const createdIncident = {
        id: `inc_${crypto.randomBytes(6).toString('hex')}`,
        policyId,
        fingerprint,
        projectId,
        severity,
        title,
        status: 'open',
        lastState: 'firing',
        occurrences: 1,
        flapping: false,
        stateTransitions: [],
        transitionCount: 0,
        currentTier: primaryTier.tier,
        assignedResponder: primaryOnCall.responder,
        createdAtMs: nowMs,
        createdAt: new Date(nowMs).toISOString(),
        lastSeenAtMs: nowMs,
        lastSeenAt: new Date(nowMs).toISOString(),
        lastEscalatedAtMs: nowMs,
        lastEscalatedAt: new Date(nowMs).toISOString(),
        acknowledgedBy: null,
        acknowledgedAtMs: null,
        acknowledgedAt: null,
        resolvedAtMs: null,
        resolvedAt: null,
        suppressedAtMs: null,
        escalationHistory: []
      };
      store.incidents.push(createdIncident);
      this._saveState(store);

      return {
        ok: true,
        incident: cloneIncident(createdIncident),
        created: true,
        deduplicated: false,
        suppressed: false,
        paged: true,
        flapping: false,
        currentTier: createdIncident.currentTier,
        assignedResponder: createdIncident.assignedResponder,
        reason: 'INCIDENT_CREATED'
      };
    }

    // Case C: Existing incident found — prune transitions outside flappingWindowSec
    const prunedTransitions = (candidate.stateTransitions || []).filter((ts) => ts >= windowCutoffMs);

    // If flapping suppression aged cleanly out of the window with zero toggles and a new firing arrives, recover cleanly
    if (
      candidate.status === 'flapping_suppressed' &&
      prunedTransitions.length < policy.flappingThreshold &&
      candidate.lastSeenAtMs < windowCutoffMs &&
      alertState === 'firing'
    ) {
      candidate.status = 'open';
      candidate.flapping = false;
      candidate.suppressedAtMs = null;
      candidate.stateTransitions = [];
      candidate.transitionCount = 0;
      candidate.lastState = 'firing';
      candidate.occurrences += 1;
      candidate.lastSeenAtMs = nowMs;
      candidate.lastSeenAt = new Date(nowMs).toISOString();
      candidate.lastEscalatedAtMs = nowMs;
      candidate.lastEscalatedAt = new Date(nowMs).toISOString();
      this._saveState(store);
      return {
        ok: true,
        incident: cloneIncident(candidate),
        created: false,
        deduplicated: false,
        suppressed: false,
        paged: true,
        flapping: false,
        currentTier: candidate.currentTier,
        assignedResponder: candidate.assignedResponder,
        reason: 'INCIDENT_RECOVERED_FROM_FLAPPING'
      };
    }

    const isStateTransition = candidate.lastState !== alertState;

    // Case C1: Same-state duplicate alert (firing -> firing on open/ack/flapping, or resolved -> resolved)
    if (!isStateTransition) {
      candidate.stateTransitions = prunedTransitions;
      candidate.transitionCount = prunedTransitions.length;
      candidate.lastSeenAtMs = nowMs;
      candidate.lastSeenAt = new Date(nowMs).toISOString();
      if (alertState === 'firing') {
        candidate.occurrences += 1;
      }
      if (title && title !== fingerprint) {
        candidate.title = title;
      }
      this._saveState(store);

      const isFlapping = candidate.status === 'flapping_suppressed' || candidate.flapping;
      return {
        ok: true,
        incident: cloneIncident(candidate),
        created: false,
        deduplicated: alertState === 'firing',
        suppressed: true,
        paged: false,
        flapping: isFlapping,
        currentTier: candidate.currentTier,
        assignedResponder: candidate.assignedResponder,
        reason: isFlapping ? 'FLAPPING_SUPPRESSED' : 'DEDUPLICATED'
      };
    }

    // Case C2: State toggle (`firing -> resolved` or `resolved -> firing`)
    prunedTransitions.push(nowMs);
    candidate.stateTransitions = prunedTransitions;
    candidate.transitionCount = prunedTransitions.length;
    candidate.lastState = alertState;
    candidate.lastSeenAtMs = nowMs;
    candidate.lastSeenAt = new Date(nowMs).toISOString();
    if (alertState === 'firing') {
      candidate.occurrences += 1;
    }

    // Check flapping threshold
    if (prunedTransitions.length >= policy.flappingThreshold || candidate.status === 'flapping_suppressed') {
      candidate.flapping = true;
      candidate.status = 'flapping_suppressed';
      if (candidate.suppressedAtMs === null) {
        candidate.suppressedAtMs = nowMs;
      }
      this._saveState(store);

      return {
        ok: true,
        incident: cloneIncident(candidate),
        created: false,
        deduplicated: false,
        suppressed: true,
        paged: false,
        flapping: true,
        transitionCount: prunedTransitions.length,
        currentTier: candidate.currentTier,
        assignedResponder: candidate.assignedResponder,
        reason: 'FLAPPING_SUPPRESSED'
      };
    }

    // Below flapping threshold: either resolve or reopen cleanly
    if (alertState === 'resolved') {
      candidate.status = 'resolved';
      candidate.resolvedAtMs = nowMs;
      candidate.resolvedAt = new Date(nowMs).toISOString();
      this._saveState(store);

      return {
        ok: true,
        incident: cloneIncident(candidate),
        created: false,
        deduplicated: false,
        suppressed: false,
        paged: false,
        flapping: false,
        transitionCount: prunedTransitions.length,
        currentTier: candidate.currentTier,
        assignedResponder: candidate.assignedResponder,
        reason: 'INCIDENT_RESOLVED'
      };
    }

    // Re-opened from resolved while below flapping threshold
    candidate.status = 'open';
    candidate.resolvedAtMs = null;
    candidate.resolvedAt = null;
    candidate.acknowledgedBy = null;
    candidate.acknowledgedAtMs = null;
    candidate.acknowledgedAt = null;
    candidate.currentTier = primaryTier.tier;
    candidate.assignedResponder = primaryOnCall.responder;
    candidate.lastEscalatedAtMs = nowMs;
    candidate.lastEscalatedAt = new Date(nowMs).toISOString();
    this._saveState(store);

    return {
      ok: true,
      incident: cloneIncident(candidate),
      created: false,
      deduplicated: false,
      suppressed: false,
      paged: true,
      flapping: false,
      transitionCount: prunedTransitions.length,
      currentTier: candidate.currentTier,
      assignedResponder: candidate.assignedResponder,
      reason: 'INCIDENT_REOPENED'
    };
  }

  /**
   * Acknowledges an incident, immediately freezing future tier escalations.
   *
   * @param {string} incidentId
   * @param {{ actor?: string, nowMs?: number }} [opts]
   */
  acknowledgeIncident(incidentId, opts = {}) {
    const id = typeof incidentId === 'string' ? incidentId.trim() : '';
    const safeOpts = opts && typeof opts === 'object' ? opts : {};
    const actor = typeof safeOpts.actor === 'string' && safeOpts.actor.trim()
      ? safeOpts.actor.trim().slice(0, 128)
      : 'operator';
    const nowMs = normalizeNowMs(safeOpts.nowMs);

    const store = this._loadState();
    const incident = store.incidents.find((i) => i.id === id);
    if (!incident) {
      throw oncallError('INCIDENT_NOT_FOUND', `Incident "${id}" not found`, 404);
    }

    incident.status = 'acknowledged';
    incident.acknowledgedBy = actor;
    incident.acknowledgedAtMs = nowMs;
    incident.acknowledgedAt = new Date(nowMs).toISOString();
    incident.lastSeenAtMs = Math.max(incident.lastSeenAtMs, nowMs);
    incident.lastSeenAt = new Date(incident.lastSeenAtMs).toISOString();
    this._saveState(store);

    return {
      ok: true,
      acknowledged: true,
      incidentId: incident.id,
      status: incident.status,
      acknowledgedBy: incident.acknowledgedBy,
      acknowledgedAtMs: incident.acknowledgedAtMs,
      incident: cloneIncident(incident)
    };
  }

  /**
   * Evaluates all open unacknowledged incidents at `nowMs` and escalates eligible incidents
   * to the next tier (`Tier 1 -> Tier 2 -> Tier 3`) when `nowMs - lastEscalatedAtMs >= ackTimeoutSec * 1000`.
   * NEVER escalates acknowledged, resolved, or flapping_suppressed incidents.
   *
   * @param {number} [nowMs]
   */
  evaluateEscalations(nowMs = Date.now()) {
    const ts = normalizeNowMs(nowMs);
    const store = this._loadState();

    let evaluatedCount = 0;
    /** @type {Array<{ incidentId: string, policyId: string, fingerprint: string, fromTier: number, toTier: number, assignedResponder: string, escalatedAtMs: number, incident: OnCallIncident }>} */
    const escalated = [];

    for (const incident of store.incidents) {
      // Strictly skip acknowledged, resolved, and flapping_suppressed incidents
      if (incident.status !== 'open') continue;
      evaluatedCount += 1;

      const policy = store.policies[incident.policyId];
      if (!policy || !Array.isArray(policy.tiers) || policy.tiers.length === 0) continue;

      const elapsedMs = ts - incident.lastEscalatedAtMs;
      if (elapsedMs < policy.ackTimeoutSec * 1000) continue;

      const nextTier = policy.tiers.find((t) => t.tier > incident.currentTier);
      if (!nextTier) continue;

      const resolved = computeTierResponder(policy, nextTier, ts);
      const fromTier = incident.currentTier;

      incident.currentTier = nextTier.tier;
      incident.assignedResponder = resolved.responder;
      incident.lastEscalatedAtMs = ts;
      incident.lastEscalatedAt = new Date(ts).toISOString();
      incident.escalationHistory.push({
        fromTier,
        toTier: nextTier.tier,
        responder: resolved.responder,
        escalatedAtMs: ts,
        escalatedAt: new Date(ts).toISOString(),
        reason: 'ACK_TIMEOUT'
      });

      escalated.push({
        incidentId: incident.id,
        policyId: incident.policyId,
        fingerprint: incident.fingerprint,
        fromTier,
        toTier: nextTier.tier,
        assignedResponder: resolved.responder,
        escalatedAtMs: ts,
        incident: cloneIncident(incident)
      });
    }

    if (escalated.length > 0) {
      this._saveState(store);
    }

    return {
      ok: true,
      evaluatedAtMs: ts,
      evaluatedAt: new Date(ts).toISOString(),
      evaluatedCount,
      escalatedCount: escalated.length,
      escalated
    };
  }

  /**
   * Lists incidents, newest first. When `activeOnly: true`, excludes `resolved` incidents.
   * @param {{ activeOnly?: boolean, policyId?: string }} [opts]
   * @returns {OnCallIncident[]}
   */
  listIncidents(opts = {}) {
    const safeOpts = opts && typeof opts === 'object' ? opts : {};
    const activeOnly = Boolean(safeOpts.activeOnly);
    const filterPolicyId = typeof safeOpts.policyId === 'string' && safeOpts.policyId.trim()
      ? safeOpts.policyId.trim()
      : null;

    const store = this._loadState();
    return store.incidents
      .filter((inc) => (!activeOnly || inc.status !== 'resolved'))
      .filter((inc) => (!filterPolicyId || inc.policyId === filterPolicyId))
      .sort((a, b) => (b.lastSeenAtMs - a.lastSeenAtMs) || (b.createdAtMs - a.createdAtMs))
      .map(cloneIncident);
  }
}

const defaultOnCallEscalationService = new OnCallEscalationService();

const exported = Object.assign(defaultOnCallEscalationService, {
  OnCallEscalationService,
  DEFAULT_POLICY_OPTIONS,
  savePolicy: OnCallEscalationService.prototype.savePolicy.bind(defaultOnCallEscalationService),
  listPolicies: OnCallEscalationService.prototype.listPolicies.bind(defaultOnCallEscalationService),
  resolveCurrentOnCall: OnCallEscalationService.prototype.resolveCurrentOnCall.bind(defaultOnCallEscalationService),
  ingestAlert: OnCallEscalationService.prototype.ingestAlert.bind(defaultOnCallEscalationService),
  acknowledgeIncident: OnCallEscalationService.prototype.acknowledgeIncident.bind(defaultOnCallEscalationService),
  evaluateEscalations: OnCallEscalationService.prototype.evaluateEscalations.bind(defaultOnCallEscalationService),
  listIncidents: OnCallEscalationService.prototype.listIncidents.bind(defaultOnCallEscalationService)
});

module.exports = exported;
