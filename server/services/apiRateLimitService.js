'use strict';

/**
 * Culkibo Edge API Rate-Limit & AI Wallet-Drain (Denial-of-Wallet) Dual RPM+TPM Shield.
 *
 * Enforces simultaneous Requests-Per-Minute (RPM) and Tokens-Per-Minute (TPM) token-bucket
 * quotas across plan tiers (`free`, `pro`, `enterprise`) with zero runtime npm dependencies:
 *  - Atomic `0o600` policy store in `CULKIBO_DATA_DIR/data/ratelimit-policies.json`.
 *  - Emits IETF `draft-ietf-httpapi-ratelimit-headers` (`RateLimit`, `RateLimit-Policy`)
 *    plus `X-RateLimit-*` and `Retry-After` on HTTP `429`.
 *  - Isolated `simulateBurst` tool quantifying throttled requests, first `429` index,
 *    throttle reason (`RPM_EXCEEDED` / `TPM_EXCEEDED` / `RPM_AND_TPM_EXCEEDED`), and
 *    `estimatedWalletSavedUsd` without polluting live client buckets.
 *  - Compiles ready-to-apply Caddy v2.11 edge rate-limit config.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PLAN_PRESETS = Object.freeze({
  free: Object.freeze({
    planTier: 'free',
    rpmLimit: 30,
    tpmLimit: 10000,
    burstMultiplier: 1.2,
    windowSec: 60
  }),
  pro: Object.freeze({
    planTier: 'pro',
    rpmLimit: 120,
    tpmLimit: 60000,
    burstMultiplier: 1.5,
    windowSec: 60
  }),
  enterprise: Object.freeze({
    planTier: 'enterprise',
    rpmLimit: 600,
    tpmLimit: 500000,
    burstMultiplier: 2.0,
    windowSec: 60
  })
});

const VALID_PLAN_TIERS = new Set(['free', 'pro', 'enterprise']);
const MAX_BUCKETS = 5000;
const BLENDED_USD_PER_1K_TOKENS = 0.005;

/**
 * @typedef {'free' | 'pro' | 'enterprise'} PlanTier
 */

/**
 * @typedef {object} RateLimitPolicy
 * @property {string} id
 * @property {string | null} projectId
 * @property {string} name
 * @property {PlanTier} planTier
 * @property {number} rpmLimit
 * @property {number} tpmLimit
 * @property {number} burstMultiplier
 * @property {number} windowSec
 * @property {string} createdAt
 * @property {string} updatedAt
 */

/**
 * @typedef {object} DualBucketState
 * @property {number} rpmTokens
 * @property {number} tpmTokens
 * @property {number} lastRefillMs
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
function rateLimitError(code, msg, status = 400) {
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
    throw rateLimitError('INVALID_TIMESTAMP', 'nowMs must be a finite non-negative number');
  }
  return Math.floor(n);
}

/**
 * Evaluates and updates a single dual-dimension (RPM + TPM) token bucket.
 *
 * @param {RateLimitPolicy} policy
 * @param {DualBucketState | null} prevBucket
 * @param {string} clientKey
 * @param {number} tokens
 * @param {number} nowMs
 */
function stepDualBucket(policy, prevBucket, clientKey, tokens, nowMs) {
  const rpmCapacity = Math.max(1, Math.floor(policy.rpmLimit * policy.burstMultiplier));
  const tpmCapacity = Math.max(1, Math.floor(policy.tpmLimit * policy.burstMultiplier));
  const windowMs = policy.windowSec * 1000;
  const rpmRatePerMs = policy.rpmLimit / windowMs;
  const tpmRatePerMs = policy.tpmLimit / windowMs;

  /** @type {DualBucketState} */
  const bucket = prevBucket
    ? { ...prevBucket }
    : { rpmTokens: rpmCapacity, tpmTokens: tpmCapacity, lastRefillMs: nowMs };

  const elapsedMs = Math.max(0, nowMs - bucket.lastRefillMs);
  if (elapsedMs > 0) {
    bucket.rpmTokens = Math.min(rpmCapacity, bucket.rpmTokens + elapsedMs * rpmRatePerMs);
    bucket.tpmTokens = Math.min(tpmCapacity, bucket.tpmTokens + elapsedMs * tpmRatePerMs);
    bucket.lastRefillMs = nowMs;
  }

  const rpmEnough = bucket.rpmTokens >= 1;
  const tpmEnough = tokens <= 0 || bucket.tpmTokens >= tokens;
  const allowed = rpmEnough && tpmEnough;

  if (allowed) {
    bucket.rpmTokens = Math.max(0, bucket.rpmTokens - 1);
    bucket.tpmTokens = Math.max(0, bucket.tpmTokens - tokens);
  }

  const remainingRpm = Math.max(0, Math.floor(bucket.rpmTokens));
  const remainingTpm = Math.max(0, Math.floor(bucket.tpmTokens));

  const rpmWaitSec = rpmEnough
    ? Math.max(1, Math.min(policy.windowSec, Math.ceil((rpmCapacity - bucket.rpmTokens) / Math.max(1e-9, rpmRatePerMs * 1000))))
    : Math.max(1, Math.min(policy.windowSec, Math.ceil((1 - bucket.rpmTokens) / Math.max(1e-9, rpmRatePerMs * 1000))));

  const tpmWaitSec = tpmEnough
    ? Math.max(1, Math.min(policy.windowSec, Math.ceil((tpmCapacity - bucket.tpmTokens) / Math.max(1e-9, tpmRatePerMs * 1000))))
    : Math.max(1, Math.min(policy.windowSec, Math.ceil((tokens - bucket.tpmTokens) / Math.max(1e-9, tpmRatePerMs * 1000))));

  /** @type {'RPM_EXCEEDED' | 'TPM_EXCEEDED' | 'RPM_AND_TPM_EXCEEDED' | null} */
  let throttleReason = null;
  let retryAfterSec = 0;
  if (!allowed) {
    if (!rpmEnough && !tpmEnough) {
      throttleReason = 'RPM_AND_TPM_EXCEEDED';
      retryAfterSec = Math.max(rpmWaitSec, tpmWaitSec);
    } else if (!tpmEnough) {
      throttleReason = 'TPM_EXCEEDED';
      retryAfterSec = tpmWaitSec;
    } else {
      throttleReason = 'RPM_EXCEEDED';
      retryAfterSec = rpmWaitSec;
    }
  }

  const slug = policy.id.replace(/[^a-zA-Z0-9_-]/g, '_');
  const resetSec = allowed ? rpmWaitSec : retryAfterSec;

  /** @type {Record<string, string>} */
  const headers = {
    'RateLimit': `"${slug}-rpm";r=${remainingRpm};t=${resetSec}, "${slug}-tpm";r=${remainingTpm};t=${tpmWaitSec}`,
    'RateLimit-Policy': `"${slug}-rpm";q=${policy.rpmLimit};w=${policy.windowSec}, "${slug}-tpm";q=${policy.tpmLimit};w=${policy.windowSec}`,
    'X-RateLimit-Limit': String(policy.rpmLimit),
    'X-RateLimit-Remaining': String(remainingRpm),
    'X-RateLimit-Reset': String(Math.ceil(nowMs / 1000) + resetSec),
    'X-RateLimit-Tokens-Limit': String(policy.tpmLimit),
    'X-RateLimit-Tokens-Remaining': String(remainingTpm)
  };
  if (!allowed) {
    headers['Retry-After'] = String(retryAfterSec);
  }

  return {
    nextBucket: bucket,
    result: {
      ok: true,
      allowed,
      httpStatus: allowed ? 200 : 429,
      policyId: policy.id,
      clientKey,
      tokensRequested: tokens,
      remainingRpm,
      remainingTpm,
      retryAfterSec,
      throttleReason,
      headers
    }
  };
}

/**
 * Compiles Caddy v2.11 edge rate-limit configuration for a policy.
 * @param {RateLimitPolicy} policy
 */
function buildCaddyRateLimitConfig(policy) {
  const zoneName = `culkibo_${policy.id.replace(/[^a-zA-Z0-9_]/g, '_')}`;
  const slug = policy.id.replace(/[^a-zA-Z0-9_-]/g, '_');
  const rateLimitPolicyHeader = `"${slug}-rpm";q=${policy.rpmLimit};w=${policy.windowSec}, "${slug}-tpm";q=${policy.tpmLimit};w=${policy.windowSec}`;

  const caddyJson = {
    handler: 'rate_limit',
    rate_limits: {
      [zoneName]: {
        key: '{http.request.header.X-API-Key}',
        window: `${policy.windowSec}s`,
        max_events: policy.rpmLimit,
        burst_events: Math.max(policy.rpmLimit, Math.floor(policy.rpmLimit * policy.burstMultiplier)),
        token_budget_tpm: policy.tpmLimit
      }
    },
    response_headers: {
      'RateLimit-Policy': [rateLimitPolicyHeader]
    }
  };

  const caddyfile = [
    `rate_limit {`,
    `  zone ${zoneName} {`,
    `    key {http.request.header.X-API-Key}`,
    `    events ${policy.rpmLimit}`,
    `    window ${policy.windowSec}s`,
    `  }`,
    `}`,
    `header RateLimit-Policy ${JSON.stringify(rateLimitPolicyHeader)}`
  ].join('\n');

  return {
    ok: true,
    policyId: policy.id,
    planTier: policy.planTier,
    zoneName,
    caddyJson,
    caddyfile
  };
}

/**
 * Validates and normalizes a rate-limit policy.
 * @param {Record<string, any>} input
 * @param {RateLimitPolicy | null} [existing]
 * @returns {RateLimitPolicy}
 */
function normalizeRateLimitPolicy(input, existing = null) {
  if (!input || typeof input !== 'object') {
    throw rateLimitError('INVALID_POLICY', 'saveRateLimitPolicy requires a policy object');
  }

  const rawTier = input.planTier !== undefined
    ? String(input.planTier).trim().toLowerCase()
    : (existing ? existing.planTier : 'pro');
  if (!VALID_PLAN_TIERS.has(rawTier)) {
    throw rateLimitError('INVALID_PLAN_TIER', 'planTier must be one of: free, pro, enterprise');
  }
  const planTier = /** @type {PlanTier} */ (rawTier);
  const preset = PLAN_PRESETS[planTier];

  const name = typeof input.name === 'string' && input.name.trim()
    ? input.name.trim().slice(0, 128)
    : (existing ? existing.name : `${planTier.toUpperCase()} API Shield`);

  const id = typeof input.id === 'string' && input.id.trim()
    ? input.id.trim().slice(0, 128)
    : (existing ? existing.id : `rl_${crypto.randomBytes(6).toString('hex')}`);

  const projectId = input.projectId !== undefined
    ? (typeof input.projectId === 'string' && input.projectId.trim() ? input.projectId.trim().slice(0, 128) : null)
    : (existing ? existing.projectId : null);

  const rpmLimit = input.rpmLimit !== undefined
    ? Math.round(Number(input.rpmLimit))
    : (existing ? existing.rpmLimit : preset.rpmLimit);
  if (!Number.isInteger(rpmLimit) || rpmLimit < 1 || rpmLimit > 1000000) {
    throw rateLimitError('INVALID_POLICY', 'rpmLimit must be an integer 1..1000000');
  }

  const tpmLimit = input.tpmLimit !== undefined
    ? Math.round(Number(input.tpmLimit))
    : (existing ? existing.tpmLimit : preset.tpmLimit);
  if (!Number.isInteger(tpmLimit) || tpmLimit < 1 || tpmLimit > 1000000000) {
    throw rateLimitError('INVALID_POLICY', 'tpmLimit must be an integer 1..1000000000');
  }

  const burstMultiplier = input.burstMultiplier !== undefined
    ? Number(input.burstMultiplier)
    : (existing ? existing.burstMultiplier : preset.burstMultiplier);
  if (!Number.isFinite(burstMultiplier) || burstMultiplier < 1.0 || burstMultiplier > 10.0) {
    throw rateLimitError('INVALID_POLICY', 'burstMultiplier must be 1.0..10.0');
  }

  const windowSec = input.windowSec !== undefined
    ? Math.round(Number(input.windowSec))
    : (existing ? existing.windowSec : preset.windowSec);
  if (!Number.isInteger(windowSec) || windowSec < 1 || windowSec > 86400) {
    throw rateLimitError('INVALID_POLICY', 'windowSec must be an integer 1..86400');
  }

  const nowIso = new Date().toISOString();
  return {
    id,
    projectId,
    name,
    planTier,
    rpmLimit,
    tpmLimit,
    burstMultiplier: Number(burstMultiplier.toFixed(2)),
    windowSec,
    createdAt: existing ? existing.createdAt : nowIso,
    updatedAt: nowIso
  };
}

class ApiRateLimitService {
  /**
   * @param {{ dataDir?: string | null }} [opts]
   */
  constructor(opts = {}) {
    /** @type {string | null} */
    this._explicitDataDir = opts && typeof opts.dataDir === 'string' && opts.dataDir.trim()
      ? path.resolve(opts.dataDir.trim())
      : null;
    /** @type {Map<string, DualBucketState>} */
    this._buckets = new Map();
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
    return path.join(this.resolveDataDir(), 'ratelimit-policies.json');
  }

  /** @returns {Record<string, RateLimitPolicy>} */
  _loadMap() {
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) return {};
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      return parsed && parsed.policies && typeof parsed.policies === 'object' ? parsed.policies : {};
    } catch (e) {
      return {};
    }
  }

  /** @param {Record<string, RateLimitPolicy>} policies */
  _saveMap(policies) {
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({ schemaVersion: 1, updatedAt: new Date().toISOString(), policies }, null, 2) + '\n'
    );
  }

  /**
   * Validates and atomically persists a dual RPM+TPM rate-limit policy.
   * @param {Record<string, any>} input
   * @returns {RateLimitPolicy}
   */
  saveRateLimitPolicy(input) {
    const map = this._loadMap();
    const existingId = input && typeof input.id === 'string' && input.id.trim() ? input.id.trim() : null;
    const existing = existingId && map[existingId] ? map[existingId] : null;
    const policy = normalizeRateLimitPolicy(input, existing);
    map[policy.id] = policy;
    this._saveMap(map);
    return { ...policy };
  }

  /**
   * Lists all saved rate-limit policies.
   * @returns {RateLimitPolicy[]}
   */
  listRateLimitPolicies() {
    return Object.values(this._loadMap()).map((p) => ({ ...p }));
  }

  /**
   * Consumes 1 request + `tokens` LLM tokens from the dual RPM+TPM token bucket for `(policyId, clientKey)`.
   *
   * @param {{
   *   policyId: string,
   *   clientKey?: string,
   *   tokens?: number,
   *   nowMs?: number
   * }} input
   */
  consumeTokenBucket(input) {
    if (!input || typeof input !== 'object') {
      throw rateLimitError('INVALID_INPUT', 'consumeTokenBucket requires an input object');
    }
    const policyId = typeof input.policyId === 'string' ? input.policyId.trim() : '';
    const map = this._loadMap();
    const policy = map[policyId];
    if (!policy) {
      throw rateLimitError('POLICY_NOT_FOUND', `Rate-limit policy "${policyId}" not found`, 404);
    }

    const clientKey = typeof input.clientKey === 'string' && input.clientKey.trim()
      ? input.clientKey.trim().slice(0, 128)
      : 'anonymous';
    const tokens = Math.max(0, Math.round(Number(input.tokens ?? 0) || 0));
    const nowMs = normalizeNowMs(input.nowMs);

    const bucketKey = `${this.getStoreFilePath()}::${policy.id}::${clientKey}`;
    const prev = this._buckets.get(bucketKey) || null;
    const { nextBucket, result } = stepDualBucket(policy, prev, clientKey, tokens, nowMs);

    if (this._buckets.size >= MAX_BUCKETS && !this._buckets.has(bucketKey)) {
      const oldestKey = this._buckets.keys().next().value;
      if (oldestKey !== undefined) this._buckets.delete(oldestKey);
    }
    this._buckets.set(bucketKey, nextBucket);
    return result;
  }

  /**
   * Runs an isolated burst simulation against a policy (never polluting live buckets) to
   * measure 429 trigger points, IETF headers, and estimated AI wallet spend saved.
   *
   * @param {{
   *   policyId: string,
   *   requestsCount?: number,
   *   tokensPerRequest?: number,
   *   intervalMs?: number,
   *   clientKey?: string,
   *   startMs?: number
   * }} input
   */
  simulateBurst(input) {
    if (!input || typeof input !== 'object') {
      throw rateLimitError('INVALID_INPUT', 'simulateBurst requires a simulation payload');
    }
    const policyId = typeof input.policyId === 'string' ? input.policyId.trim() : '';
    const map = this._loadMap();
    const policy = map[policyId];
    if (!policy) {
      throw rateLimitError('POLICY_NOT_FOUND', `Rate-limit policy "${policyId}" not found`, 404);
    }

    const requestsCount = Math.max(1, Math.min(5000, Math.round(Number(input.requestsCount ?? 20) || 20)));
    const tokensPerRequest = Math.max(0, Math.min(10000000, Math.round(Number(input.tokensPerRequest ?? 5000) || 0)));
    const intervalMs = Math.max(0, Math.min(60000, Math.round(Number(input.intervalMs ?? 50) || 0)));
    const clientKey = typeof input.clientKey === 'string' && input.clientKey.trim()
      ? input.clientKey.trim().slice(0, 128)
      : 'sim-client';
    const startMs = normalizeNowMs(input.startMs);

    /** @type {DualBucketState | null} */
    let simBucket = null;
    let allowedCount = 0;
    let throttledCount = 0;
    /** @type {number | null} */
    let first429AtIndex = null;
    /** @type {string | null} */
    let throttleReason = null;
    /** @type {Record<string, string> | null} */
    let sample429Headers = null;
    let blockedTokens = 0;

    for (let i = 0; i < requestsCount; i += 1) {
      const ts = startMs + i * intervalMs;
      const step = stepDualBucket(policy, simBucket, clientKey, tokensPerRequest, ts);
      simBucket = step.nextBucket;
      if (step.result.allowed) {
        allowedCount += 1;
      } else {
        throttledCount += 1;
        blockedTokens += tokensPerRequest;
        if (first429AtIndex === null) {
          first429AtIndex = i;
          throttleReason = step.result.throttleReason;
          sample429Headers = step.result.headers;
        }
      }
    }

    const estimatedWalletSavedUsd = Number(((blockedTokens / 1000) * BLENDED_USD_PER_1K_TOKENS).toFixed(4));

    return {
      ok: true,
      policyId: policy.id,
      policyName: policy.name,
      planTier: policy.planTier,
      totalRequests: requestsCount,
      allowedCount,
      throttledCount,
      first429AtIndex,
      throttleReason,
      blockedTokens,
      estimatedWalletSavedUsd,
      sample429Headers,
      caddyConfig: buildCaddyRateLimitConfig(policy)
    };
  }

  /**
   * Compiles Caddy v2.11 edge rate-limit JSON & Caddyfile config from a policy object or ID.
   * @param {RateLimitPolicy | string} policyOrId
   */
  compileCaddyRateLimitConfig(policyOrId) {
    /** @type {RateLimitPolicy | null} */
    let policy = null;
    if (typeof policyOrId === 'string') {
      const map = this._loadMap();
      policy = map[policyOrId.trim()] || null;
      if (!policy) {
        throw rateLimitError('POLICY_NOT_FOUND', `Rate-limit policy "${policyOrId}" not found`, 404);
      }
    } else if (policyOrId && typeof policyOrId === 'object') {
      policy = normalizeRateLimitPolicy(policyOrId);
    } else {
      throw rateLimitError('INVALID_POLICY', 'compileCaddyRateLimitConfig requires a policy object or policyId');
    }
    return buildCaddyRateLimitConfig(policy);
  }
}

const defaultApiRateLimitService = new ApiRateLimitService();

const exported = Object.assign(defaultApiRateLimitService, {
  ApiRateLimitService,
  PLAN_PRESETS,
  saveRateLimitPolicy: ApiRateLimitService.prototype.saveRateLimitPolicy.bind(defaultApiRateLimitService),
  listRateLimitPolicies: ApiRateLimitService.prototype.listRateLimitPolicies.bind(defaultApiRateLimitService),
  consumeTokenBucket: ApiRateLimitService.prototype.consumeTokenBucket.bind(defaultApiRateLimitService),
  simulateBurst: ApiRateLimitService.prototype.simulateBurst.bind(defaultApiRateLimitService),
  compileCaddyRateLimitConfig: ApiRateLimitService.prototype.compileCaddyRateLimitConfig.bind(defaultApiRateLimitService)
});

module.exports = exported;
