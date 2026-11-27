'use strict';

/**
 * Culkibo Edge WebSocket / SSE Connection-Flood, Slowloris & `101` Hop-by-Hop Guard.
 *
 * Cures `CVE-2026-55458` (Caddy `< v2.11.5` `101 Switching Protocols` hop-by-hop header leak),
 * `Dokploy#3033` / `#4202` (60s proxy idle drops & reload stream severing), and Slowloris /
 * slow-reader OOM attacks on single-VPS realtime AI streaming apps — zero external deps:
 *  - Atomic `0o600` persistence in `CULKIBO_DATA_DIR/data/stream-flood-guard.json`.
 *  - `scrubUpgradeHeaders`: strips RFC 7230 §6.1 hop-by-hop headers (`Proxy-Authenticate`,
 *    `Alt-Svc`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, plus any header nominated
 *    in `Connection` EXCEPT `Upgrade`) while preserving `Upgrade` & `Sec-WebSocket-Accept`.
 *  - `evaluateStreamAdmission`: enforces per-IP & per-project concurrency caps (`429` / WS `1013`),
 *    Slowloris timing/rate guards (`SLOWLORIS_DETECTED`), and slow-reader buffer OOM shedding
 *    (`SLOW_READER_BACKPRESSURE`).
 *  - `generateCaddyStreamBlock`: emits Caddy v2.11 reverse-proxy config with `read_timeout 0`,
 *    `write_timeout 0`, `flush_interval -1`, `stream_close_delay 30s`, and `< 45s` heartbeats.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DEFAULT_STREAM_POLICY = Object.freeze({
  maxPerIp: 20,
  maxPerProject: 500,
  maxHeaderElapsedMs: 5000,
  minBytesPerSec: 128,
  maxBufferBytes: 4 * 1024 * 1024,
  heartbeatIntervalSec: 30,
  streamCloseDelaySec: 30,
  retryAfterSec: 15
});

const HOP_BY_HOP_HEADERS = Object.freeze([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'trailers',
  'transfer-encoding',
  'alt-svc'
]);

const PROTECTED_UPGRADE_HEADERS = new Set([
  'upgrade',
  'sec-websocket-accept',
  'sec-websocket-protocol',
  'sec-websocket-extensions',
  'sec-websocket-version'
]);

/**
 * @typedef {object} StreamGuardPolicy
 * @property {string} projectId
 * @property {number} maxPerIp
 * @property {number} maxPerProject
 * @property {number} maxHeaderElapsedMs
 * @property {number} minBytesPerSec
 * @property {number} maxBufferBytes
 * @property {number} heartbeatIntervalSec
 * @property {number} streamCloseDelaySec
 * @property {number} retryAfterSec
 * @property {string | null} updatedAt
 */

/**
 * @typedef {object} StreamGuardStoreState
 * @property {number} schemaVersion
 * @property {string} updatedAt
 * @property {Record<string, StreamGuardPolicy>} policies
 * @property {{ totalEvaluated: number, totalAllowed: number, totalBlocked: number, blockedByCode: Record<string, number> }} stats
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
function streamError(code, msg, status = 400) {
  const err = /** @type {any} */ (new Error(msg));
  err.code = code;
  err.status = status;
  return err;
}

/**
 * Normalizes and validates a stream guard policy.
 * @param {string} projectId
 * @param {Record<string, any>} partial
 * @param {StreamGuardPolicy | null} [existing]
 * @returns {StreamGuardPolicy}
 */
function normalizeStreamPolicy(projectId, partial = {}, existing = null) {
  const src = partial && typeof partial === 'object' ? partial : {};
  const base = existing || { projectId, ...DEFAULT_STREAM_POLICY, updatedAt: null };

  const maxPerIp = src.maxPerIp !== undefined ? Math.round(Number(src.maxPerIp)) : base.maxPerIp;
  if (!Number.isInteger(maxPerIp) || maxPerIp < 1 || maxPerIp > 10000) {
    throw streamError('INVALID_POLICY', 'maxPerIp must be an integer 1..10000');
  }

  const maxPerProject = src.maxPerProject !== undefined ? Math.round(Number(src.maxPerProject)) : base.maxPerProject;
  if (!Number.isInteger(maxPerProject) || maxPerProject < maxPerIp || maxPerProject > 500000) {
    throw streamError('INVALID_POLICY', 'maxPerProject must be >= maxPerIp and <= 500000');
  }

  const maxHeaderElapsedMs = src.maxHeaderElapsedMs !== undefined ? Math.round(Number(src.maxHeaderElapsedMs)) : base.maxHeaderElapsedMs;
  if (!Number.isInteger(maxHeaderElapsedMs) || maxHeaderElapsedMs < 250 || maxHeaderElapsedMs > 60000) {
    throw streamError('INVALID_POLICY', 'maxHeaderElapsedMs must be 250..60000');
  }

  const minBytesPerSec = src.minBytesPerSec !== undefined ? Math.round(Number(src.minBytesPerSec)) : base.minBytesPerSec;
  if (!Number.isInteger(minBytesPerSec) || minBytesPerSec < 1 || minBytesPerSec > 1048576) {
    throw streamError('INVALID_POLICY', 'minBytesPerSec must be 1..1048576');
  }

  const maxBufferBytes = src.maxBufferBytes !== undefined ? Math.round(Number(src.maxBufferBytes)) : base.maxBufferBytes;
  if (!Number.isInteger(maxBufferBytes) || maxBufferBytes < 1024 || maxBufferBytes > 256 * 1024 * 1024) {
    throw streamError('INVALID_POLICY', 'maxBufferBytes must be 1024..268435456');
  }

  // Strictly < 45s to cure 60s proxy idle 1006 WebSocket disconnects (Dokploy#3033/#4202)
  const rawHb = src.heartbeatIntervalSec !== undefined ? Math.round(Number(src.heartbeatIntervalSec)) : base.heartbeatIntervalSec;
  if (!Number.isInteger(rawHb) || rawHb < 5 || rawHb >= 45) {
    throw streamError('INVALID_POLICY', 'heartbeatIntervalSec must be an integer 5..44 (strictly < 45s)');
  }

  const streamCloseDelaySec = src.streamCloseDelaySec !== undefined ? Math.round(Number(src.streamCloseDelaySec)) : base.streamCloseDelaySec;
  if (!Number.isInteger(streamCloseDelaySec) || streamCloseDelaySec < 5 || streamCloseDelaySec > 300) {
    throw streamError('INVALID_POLICY', 'streamCloseDelaySec must be 5..300');
  }

  const retryAfterSec = src.retryAfterSec !== undefined ? Math.round(Number(src.retryAfterSec)) : base.retryAfterSec;
  if (!Number.isInteger(retryAfterSec) || retryAfterSec < 1 || retryAfterSec > 3600) {
    throw streamError('INVALID_POLICY', 'retryAfterSec must be 1..3600');
  }

  return {
    projectId,
    maxPerIp,
    maxPerProject,
    maxHeaderElapsedMs,
    minBytesPerSec,
    maxBufferBytes,
    heartbeatIntervalSec: rawHb,
    streamCloseDelaySec,
    retryAfterSec,
    updatedAt: new Date().toISOString()
  };
}

/**
 * Strips RFC 7230 §6.1 hop-by-hop headers AND custom tokens nominated in `Connection`
 * (EXCEPT `Upgrade`) on `101 Switching Protocols` responses (`CVE-2026-55458`),
 * while strictly preserving `Upgrade` and `Sec-WebSocket-Accept`.
 *
 * @param {Record<string, any>} rawHeaders
 */
function scrubUpgradeHeaders(rawHeaders) {
  const input = rawHeaders && typeof rawHeaders === 'object' ? rawHeaders : {};
  /** @type {Set<string>} */
  const stripSet = new Set(HOP_BY_HOP_HEADERS);
  let hasUpgradeInConnection = false;
  /** @type {string[]} */
  const connectionNominated = [];

  for (const [key, val] of Object.entries(input)) {
    if (key.toLowerCase() === 'connection') {
      const rawVal = Array.isArray(val) ? val.join(',') : String(val || '');
      for (const token of rawVal.split(',')) {
        const clean = token.trim().toLowerCase();
        if (!clean) continue;
        if (clean === 'upgrade') {
          hasUpgradeInConnection = true;
        } else {
          stripSet.add(clean);
          connectionNominated.push(clean);
        }
      }
    }
  }

  /** @type {Record<string, any>} */
  const cleaned = {};
  /** @type {string[]} */
  const stripped = [];

  for (const [key, val] of Object.entries(input)) {
    const lower = key.toLowerCase();
    if (PROTECTED_UPGRADE_HEADERS.has(lower)) {
      cleaned[key] = val;
      continue;
    }
    if (lower === 'connection') {
      if (hasUpgradeInConnection) {
        cleaned[key] = 'Upgrade';
      } else {
        stripped.push(key);
      }
      continue;
    }
    if (stripSet.has(lower)) {
      stripped.push(key);
      continue;
    }
    cleaned[key] = val;
  }

  return {
    ok: true,
    headers: cleaned,
    stripped,
    strippedCount: stripped.length,
    connectionTokensStripped: Array.from(new Set(connectionNominated)),
    preserved: Object.keys(cleaned),
    cveMitigated: 'CVE-2026-55458'
  };
}

/**
 * Emits Caddy v2.11 streaming reverse-proxy config with zero idle read/write timeout,
 * immediate SSE flush (`flush_interval -1`), graceful `stream_close_delay`, `< 45s` heartbeat,
 * and `CVE-2026-55458` hop-by-hop response scrubs.
 *
 * @param {Record<string, any>} [policyInput]
 */
function generateCaddyStreamBlock(policyInput = {}) {
  const pol = normalizeStreamPolicy(
    String((policyInput && policyInput.projectId) || 'default'),
    policyInput && typeof policyInput === 'object' ? policyInput : {}
  );

  const caddyfile = [
    'reverse_proxy {',
    '  flush_interval -1',
    `  stream_close_delay ${pol.streamCloseDelaySec}s`,
    '  transport http {',
    '    read_timeout 0',
    '    write_timeout 0',
    `    keepalive ${pol.heartbeatIntervalSec}s`,
    '  }',
    '  header_down -Proxy-Authenticate',
    '  header_down -Proxy-Authorization',
    '  header_down -Alt-Svc',
    '  header_down -Keep-Alive',
    '  header_down -TE',
    '  header_down -Trailer',
    '}'
  ].join('\n');

  const caddyJson = {
    handler: 'reverse_proxy',
    flush_interval: -1,
    stream_close_delay: `${pol.streamCloseDelaySec}s`,
    transport: {
      protocol: 'http',
      read_timeout: 0,
      write_timeout: 0,
      keepalive: {
        idle_timeout: `${pol.heartbeatIntervalSec}s`
      }
    },
    headers: {
      response: {
        delete: ['Proxy-Authenticate', 'Proxy-Authorization', 'Alt-Svc', 'Keep-Alive', 'TE', 'Trailer']
      }
    },
    heartbeat_interval_sec: pol.heartbeatIntervalSec
  };

  return {
    ok: true,
    heartbeatIntervalSec: pol.heartbeatIntervalSec,
    streamCloseDelaySec: pol.streamCloseDelaySec,
    policy: pol,
    caddyfile,
    caddyJson
  };
}

class StreamFloodGuardService {
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
    return path.join(this.resolveDataDir(), 'stream-flood-guard.json');
  }

  /** @returns {StreamGuardStoreState} */
  _loadState() {
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) {
      return {
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        policies: {},
        stats: {
          totalEvaluated: 0,
          totalAllowed: 0,
          totalBlocked: 0,
          blockedByCode: {}
        }
      };
    }
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      const stats = parsed && parsed.stats && typeof parsed.stats === 'object'
        ? parsed.stats
        : { totalEvaluated: 0, totalAllowed: 0, totalBlocked: 0, blockedByCode: {} };
      return {
        schemaVersion: 1,
        updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : new Date().toISOString(),
        policies: parsed && parsed.policies && typeof parsed.policies === 'object' ? parsed.policies : {},
        stats: {
          totalEvaluated: Number(stats.totalEvaluated) || 0,
          totalAllowed: Number(stats.totalAllowed) || 0,
          totalBlocked: Number(stats.totalBlocked) || 0,
          blockedByCode: stats.blockedByCode && typeof stats.blockedByCode === 'object' ? stats.blockedByCode : {}
        }
      };
    } catch (e) {
      return {
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        policies: {},
        stats: { totalEvaluated: 0, totalAllowed: 0, totalBlocked: 0, blockedByCode: {} }
      };
    }
  }

  /** @param {StreamGuardStoreState} state */
  _saveState(state) {
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        policies: state.policies,
        stats: state.stats
      }, null, 2) + '\n'
    );
  }

  /**
   * Upserts a per-project WS/SSE flood & Slowloris guard policy atomically (`0o600`).
   * @param {string} projectId
   * @param {Record<string, any>} policy
   */
  upsertStreamPolicy(projectId, policy = {}) {
    const id = String(projectId || 'default').trim().slice(0, 128) || 'default';
    const state = this._loadState();
    const existing = state.policies[id] || null;
    const normalized = normalizeStreamPolicy(id, policy, existing);
    state.policies[id] = normalized;
    this._saveState(state);
    return { ...normalized };
  }

  /**
   * Evaluates admission for a WebSocket or SSE connection against per-IP/project flood caps,
   * Slowloris timing/rate thresholds, and slow-reader OOM buffer limits.
   *
   * @param {{
   *   projectId?: string,
   *   clientIp?: string,
   *   protocol?: 'ws' | 'wss' | 'sse' | string,
   *   activePerIp?: number,
   *   activeProject?: number,
   *   headerElapsedMs?: number,
   *   bytesPerSec?: number,
   *   bufferedBytes?: number,
   *   upgradeHeaders?: Record<string, any> | null
   * }} input
   */
  evaluateStreamAdmission(input = {}) {
    if (!input || typeof input !== 'object') {
      throw streamError('INVALID_INPUT', 'evaluateStreamAdmission requires an input object');
    }

    const projectId = String(input.projectId || 'default').trim().slice(0, 128) || 'default';
    const clientIp = String(input.clientIp || '0.0.0.0').trim().slice(0, 64) || '0.0.0.0';
    const rawProto = String(input.protocol || 'ws').trim().toLowerCase();
    const protocol = rawProto === 'sse' || rawProto === 'wss' ? rawProto : 'ws';

    const state = this._loadState();
    const policy = state.policies[projectId]
      ? normalizeStreamPolicy(projectId, {}, state.policies[projectId])
      : normalizeStreamPolicy(projectId, {});

    const activePerIp = Math.max(0, Math.round(Number(input.activePerIp ?? 0) || 0));
    const activeProject = Math.max(0, Math.round(Number(input.activeProject ?? 0) || 0));
    const headerElapsedMs = Math.max(0, Number(input.headerElapsedMs ?? 0) || 0);
    const bytesPerSec = Number.isFinite(Number(input.bytesPerSec))
      ? Math.max(0, Number(input.bytesPerSec))
      : 1024;
    const bufferedBytes = Math.max(0, Math.round(Number(input.bufferedBytes ?? 0) || 0));

    let allowed = true;
    let code = 'ADMITTED';
    let httpStatus = protocol === 'sse' ? 200 : 101;
    /** @type {number | null} */
    let wsCloseCode = null;
    let retryAfterSec = 0;
    let message = 'Stream connection admitted within concurrency, Slowloris, and buffer budgets.';

    if (headerElapsedMs > policy.maxHeaderElapsedMs || bytesPerSec < policy.minBytesPerSec) {
      allowed = false;
      code = 'SLOWLORIS_DETECTED';
      httpStatus = 408;
      wsCloseCode = 1008;
      retryAfterSec = policy.retryAfterSec;
      message = `Slowloris signature detected (headerElapsedMs=${headerElapsedMs}ms, bytesPerSec=${bytesPerSec})`;
    } else if (activePerIp >= policy.maxPerIp) {
      allowed = false;
      code = 'PER_IP_STREAM_LIMIT';
      httpStatus = 429;
      wsCloseCode = 1013;
      retryAfterSec = policy.retryAfterSec;
      message = `Per-IP concurrent stream limit reached (${activePerIp}/${policy.maxPerIp})`;
    } else if (activeProject >= policy.maxPerProject) {
      allowed = false;
      code = 'PROJECT_STREAM_LIMIT';
      httpStatus = 429;
      wsCloseCode = 1013;
      retryAfterSec = policy.retryAfterSec;
      message = `Project concurrent stream limit reached (${activeProject}/${policy.maxPerProject})`;
    } else if (bufferedBytes > policy.maxBufferBytes) {
      allowed = false;
      code = 'SLOW_READER_BACKPRESSURE';
      httpStatus = 503;
      wsCloseCode = 1013;
      retryAfterSec = policy.retryAfterSec;
      message = `Slow-reader outbound buffer (${bufferedBytes} B) exceeded maxBufferBytes (${policy.maxBufferBytes} B)`;
    }

    state.stats.totalEvaluated += 1;
    if (allowed) {
      state.stats.totalAllowed += 1;
    } else {
      state.stats.totalBlocked += 1;
      state.stats.blockedByCode[code] = (state.stats.blockedByCode[code] || 0) + 1;
    }
    this._saveState(state);

    /** @type {Record<string, string>} */
    const headers = allowed
      ? (protocol === 'sse' ? { 'Cache-Control': 'no-cache, no-transform', 'X-Accel-Buffering': 'no' } : {})
      : { 'Retry-After': String(retryAfterSec) };

    const scrubbed = input.upgradeHeaders && typeof input.upgradeHeaders === 'object'
      ? scrubUpgradeHeaders(input.upgradeHeaders)
      : null;

    return {
      ok: true,
      allowed,
      code,
      reason: code,
      projectId,
      clientIp,
      protocol,
      httpStatus,
      wsCloseCode,
      retryAfterSec,
      headers,
      message,
      policy,
      caddyBlock: generateCaddyStreamBlock(policy),
      ...(scrubbed ? { scrubbedHeaders: scrubbed } : {})
    };
  }

  /**
   * Delegates to `scrubUpgradeHeaders`.
   * @param {Record<string, any>} headers
   */
  scrubUpgradeHeaders(headers) {
    return scrubUpgradeHeaders(headers);
  }

  /**
   * Delegates to `generateCaddyStreamBlock`.
   * @param {Record<string, any>} [policy]
   */
  generateCaddyStreamBlock(policy) {
    return generateCaddyStreamBlock(policy);
  }

  /**
   * Returns summary of configured stream-guard policies and admission telemetry.
   */
  getStreamGuardSummary() {
    const state = this._loadState();
    const policies = Object.values(state.policies).map((p) => ({ ...p }));
    return {
      ok: true,
      defaultPolicy: { ...DEFAULT_STREAM_POLICY },
      policyCount: policies.length,
      policies,
      stats: {
        ...state.stats,
        blockedByCode: { ...state.stats.blockedByCode }
      },
      caddyDefaultBlock: generateCaddyStreamBlock(DEFAULT_STREAM_POLICY),
      updatedAt: state.updatedAt
    };
  }
}

const defaultStreamFloodGuardService = new StreamFloodGuardService();

const exported = Object.assign(defaultStreamFloodGuardService, {
  StreamFloodGuardService,
  DEFAULT_STREAM_POLICY,
  HOP_BY_HOP_HEADERS,
  evaluateStreamAdmission: StreamFloodGuardService.prototype.evaluateStreamAdmission.bind(defaultStreamFloodGuardService),
  scrubUpgradeHeaders: StreamFloodGuardService.prototype.scrubUpgradeHeaders.bind(defaultStreamFloodGuardService),
  generateCaddyStreamBlock: StreamFloodGuardService.prototype.generateCaddyStreamBlock.bind(defaultStreamFloodGuardService),
  upsertStreamPolicy: StreamFloodGuardService.prototype.upsertStreamPolicy.bind(defaultStreamFloodGuardService),
  getStreamGuardSummary: StreamFloodGuardService.prototype.getStreamGuardSummary.bind(defaultStreamFloodGuardService)
});

module.exports = exported;
