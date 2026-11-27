'use strict';

/**
 * Culkibo Zero-Dep Shadow Traffic Replay & Cutover Regression Gate.
 *
 * Replays a batch of HTTP requests concurrently against a baseline (production) origin
 * and a candidate (canary/green) origin, comparing:
 *  - HTTP status parity & 5xx regression delta
 *  - Structural JSON key-shape drift (ignores volatile timestamps/IDs, flags missing keys & type changes)
 *  - Response byte-size divergence
 *  - Latency p50 / p95 / p99 ratio (`candidateP95 / baselineP95`)
 *
 * Security & Reliability Guarantees:
 *  - 0 external npm dependencies (Node built-ins only).
 *  - Unconditional cloud-metadata SSRF blocking (`169.254.169.254`, `metadata.google.internal`,
 *    `100.100.100.200`, `fd00:ec2::254`, `fe80::/10`, `0.0.0.0`, etc.); loopback requires
 *    explicit `allowLoopback: true`.
 *  - Hop-by-hop headers stripped on replay; `Authorization`, `Cookie`, API keys & secrets
 *    are ALWAYS redacted in returned & persisted reports.
 *  - Last 20 reports persisted atomically (`0o600`) in isolated `CULKIBO_DATA_DIR/data/shadow-replays.json`.
 */

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const net = require('net');
const path = require('path');
const { performance } = require('perf_hooks');

const MAX_STORED_REPORTS = 20;
const MAX_REQUESTS_PER_RUN = 100;
const MAX_BODY_CAPTURE_BYTES = 1024 * 1024; // 1 MiB cap per response
const DEFAULT_CONCURRENCY = 6;
const DEFAULT_TIMEOUT_MS = 5000;

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'host',
  'content-length'
]);

const SENSITIVE_HEADER_RE = /(?:authorization|proxy-authorization|cookie|set-cookie|token|secret|api[-_]?key|access[-_]?key|password|session)/i;
const ALLOWED_HTTP_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);

/**
 * Computes a percentile (0..100) over a numeric array cleanly (returns 0 for empty input).
 * @param {number[]} values
 * @param {number} pct
 * @returns {number}
 */
function computePercentile(values, pct) {
  if (!Array.isArray(values) || values.length === 0) return 0;
  const sorted = values
    .map((n) => Number(n))
    .filter((n) => Number.isFinite(n))
    .sort((a, b) => a - b);
  if (sorted.length === 0) return 0;
  const clamped = Math.max(0, Math.min(100, Number(pct) || 0));
  if (clamped === 0) return Number(sorted[0].toFixed(2));
  if (clamped === 100) return Number(sorted[sorted.length - 1].toFixed(2));
  const rank = Math.ceil((clamped / 100) * sorted.length) - 1;
  const idx = Math.max(0, Math.min(sorted.length - 1, rank));
  return Number(sorted[idx].toFixed(2));
}

/**
 * Returns the JSON structural type label for any parsed value.
 * @param {any} val
 * @returns {'null' | 'array' | 'object' | 'string' | 'number' | 'boolean' | 'undefined'}
 */
function jsonTypeOf(val) {
  if (val === null) return 'null';
  if (Array.isArray(val)) return 'array';
  const t = typeof val;
  if (t === 'object' || t === 'string' || t === 'number' || t === 'boolean') return t;
  return 'undefined';
}

/**
 * Recursively compares structural JSON key shapes between baseline and candidate responses.
 * Ignores volatile scalar values (timestamps, UUIDs, counters) and array lengths while
 * catching missing keys, type changes, and non-breaking added keys.
 *
 * @param {any} baselineVal
 * @param {any} candidateVal
 * @param {{ maxDepth?: number }} [opts]
 */
function compareJsonShape(baselineVal, candidateVal, opts = {}) {
  const maxDepth = Number.isInteger(opts.maxDepth) && /** @type {number} */ (opts.maxDepth) > 0
    ? /** @type {number} */ (opts.maxDepth)
    : 12;

  /** @type {string[]} */
  const missingKeys = [];
  /** @type {string[]} */
  const addedKeys = [];
  /** @type {Array<{ path: string, baselineType: string, candidateType: string }>} */
  const typeChanges = [];

  /**
   * @param {any} base
   * @param {any} cand
   * @param {string} curPath
   * @param {number} depth
   */
  const walk = (base, cand, curPath, depth) => {
    if (depth > maxDepth) return;
    const bt = jsonTypeOf(base);
    const ct = jsonTypeOf(cand);

    if (bt !== ct) {
      typeChanges.push({ path: curPath || '$root', baselineType: bt, candidateType: ct });
      return;
    }

    if (bt === 'object') {
      const baseKeys = Object.keys(base);
      const candKeys = Object.keys(cand);
      const candSet = new Set(candKeys);
      const baseSet = new Set(baseKeys);

      for (const k of baseKeys) {
        const nextPath = curPath ? `${curPath}.${k}` : k;
        if (!candSet.has(k)) {
          missingKeys.push(nextPath);
        } else {
          walk(base[k], cand[k], nextPath, depth + 1);
        }
      }
      for (const k of candKeys) {
        if (!baseSet.has(k)) {
          addedKeys.push(curPath ? `${curPath}.${k}` : k);
        }
      }
    } else if (bt === 'array') {
      if (base.length > 0 && cand.length > 0) {
        walk(base[0], cand[0], `${curPath || '$root'}[0]`, depth + 1);
      }
    }
  };

  walk(baselineVal, candidateVal, '', 0);
  const hasBreakingDrift = missingKeys.length > 0 || typeChanges.length > 0;
  const drifted = hasBreakingDrift || addedKeys.length > 0;

  return {
    compatible: !hasBreakingDrift,
    drifted,
    hasBreakingDrift,
    missingKeys,
    addedKeys,
    typeChanges,
    baselineType: jsonTypeOf(baselineVal),
    candidateType: jsonTypeOf(candidateVal)
  };
}

/**
 * Checks whether a hostname/IP is a cloud metadata or link-local SSRF target (always blocked).
 * @param {string} hostname
 * @returns {boolean}
 */
function isBlockedMetadataHost(hostname) {
  const host = String(hostname || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!host) return true;

  if (
    host === 'metadata' ||
    host === 'metadata.google.internal' ||
    host === 'metadata.goog' ||
    host === 'metadata.azure.internal' ||
    host === 'instance-data' ||
    host === 'instance-data.ec2.internal' ||
    host.endsWith('.metadata.google.internal') ||
    host === '169.254.169.254' ||
    host === '169.254.170.2' ||
    host === '100.100.100.200' ||
    host === 'fd00:ec2::254' ||
    host === '0.0.0.0' ||
    host === '::'
  ) {
    return true;
  }

  const v4Mapped = host.startsWith('::ffff:') ? host.slice(7) : null;
  if (v4Mapped) {
    if (v4Mapped === 'a9fe:a9fe' || v4Mapped.startsWith('a9fe:') || v4Mapped === '6464:64c8') {
      return true;
    }
    if (isBlockedMetadataHost(v4Mapped)) return true;
  }

  const ipVer = net.isIP(host);
  if (ipVer === 4) {
    const parts = host.split('.').map((n) => parseInt(n, 10));
    if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n))) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 0) return true;
    if (parts[0] === 100 && parts[1] === 100 && parts[2] === 100 && parts[3] === 200) return true;
  } else if (ipVer === 6) {
    if (/^fe[89ab][0-9a-f]:/i.test(host) || host.startsWith('fd00:ec2:')) return true;
    if (host === '::' || host === '0:0:0:0:0:0:0:0') return true;
  }

  return false;
}

/**
 * Checks whether a hostname resolves syntactically to loopback.
 * @param {string} hostname
 * @returns {boolean}
 */
function isLoopbackHost(hostname) {
  const host = String(hostname || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!host) return false;
  if (host === 'localhost' || host.endsWith('.localhost') || host === '::1' || host === '0:0:0:0:0:0:0:1') {
    return true;
  }
  if (host.startsWith('::ffff:')) {
    const inner = host.slice(7);
    if (inner === '7f00:1' || inner.startsWith('7f') || isLoopbackHost(inner)) return true;
  }
  if (net.isIP(host) === 4) return host.startsWith('127.');
  return false;
}

/**
 * Validates a shadow-replay target origin URL against cloud-metadata SSRF and loopback rules.
 * @param {string} rawOrigin
 * @param {{ allowLoopback?: boolean, label?: string }} [opts]
 * @returns {{ origin: string, basePath: string, protocol: 'http:' | 'https:', hostname: string, port: string }}
 */
function validateReplayOrigin(rawOrigin, opts = {}) {
  const label = opts.label || 'origin';
  if (typeof rawOrigin !== 'string' || !rawOrigin.trim()) {
    const err = /** @type {any} */ (new Error(`Invalid ${label}: must be a non-empty http(s) URL`));
    err.code = 'INVALID_ORIGIN';
    throw err;
  }
  if (/[\r\n\0]/.test(rawOrigin)) {
    const err = /** @type {any} */ (new Error(`Invalid ${label}: contains control characters`));
    err.code = 'INVALID_ORIGIN';
    throw err;
  }

  let parsed;
  try {
    parsed = new URL(rawOrigin.trim());
  } catch (e) {
    const err = /** @type {any} */ (new Error(`Invalid ${label} URL: ${rawOrigin}`));
    err.code = 'INVALID_ORIGIN';
    throw err;
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    const err = /** @type {any} */ (new Error(`Unsupported ${label} protocol: ${parsed.protocol}`));
    err.code = 'INVALID_ORIGIN';
    throw err;
  }
  if (parsed.username || parsed.password) {
    const err = /** @type {any} */ (new Error(`${label} URL must not embed credentials`));
    err.code = 'INVALID_ORIGIN';
    throw err;
  }

  if (isBlockedMetadataHost(parsed.hostname)) {
    const err = /** @type {any} */ (new Error(`${label} blocked by SSRF metadata guard: ${parsed.hostname}`));
    err.code = 'SSRF_BLOCKED';
    throw err;
  }
  if (isLoopbackHost(parsed.hostname) && opts.allowLoopback !== true) {
    const err = /** @type {any} */ (new Error(`${label} loopback host "${parsed.hostname}" requires allowLoopback: true`));
    err.code = 'SSRF_LOOPBACK_BLOCKED';
    throw err;
  }

  return {
    origin: `${parsed.protocol}//${parsed.host}`,
    basePath: parsed.pathname.replace(/\/+$/, ''),
    protocol: /** @type {'http:' | 'https:'} */ (parsed.protocol),
    hostname: parsed.hostname,
    port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80')
  };
}

/**
 * Strips RFC 9110 hop-by-hop headers (plus Connection-listed tokens) before forwarding a shadow request.
 * @param {Record<string, any> | null | undefined} rawHeaders
 * @returns {Record<string, string>}
 */
function stripHopByHopHeaders(rawHeaders) {
  /** @type {Record<string, string>} */
  const out = {};
  if (!rawHeaders || typeof rawHeaders !== 'object') return out;

  const extraHop = new Set();
  for (const [k, v] of Object.entries(rawHeaders)) {
    if (String(k).toLowerCase() === 'connection' && typeof v === 'string') {
      for (const token of v.split(',')) {
        const clean = token.trim().toLowerCase();
        if (clean) extraHop.add(clean);
      }
    }
  }

  for (const [k, v] of Object.entries(rawHeaders)) {
    const key = String(k || '').trim();
    if (!key || !/^[A-Za-z0-9-]+$/.test(key)) continue;
    const lower = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lower) || extraHop.has(lower)) continue;
    const val = String(v ?? '').trim();
    if (/[\r\n\0]/.test(val)) continue;
    out[key] = val;
  }
  return out;
}

/**
 * Redacts Authorization, Cookie, API keys, and any secret-bearing headers for report storage.
 * @param {Record<string, any> | null | undefined} rawHeaders
 * @returns {Record<string, string>}
 */
function redactHeaders(rawHeaders) {
  /** @type {Record<string, string>} */
  const out = {};
  if (!rawHeaders || typeof rawHeaders !== 'object') return out;
  for (const [k, v] of Object.entries(rawHeaders)) {
    const key = String(k || '').trim();
    if (!key) continue;
    if (SENSITIVE_HEADER_RE.test(key)) {
      out[key] = '[REDACTED]';
    } else {
      out[key] = String(v ?? '').slice(0, 128);
    }
  }
  return out;
}

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
 * Executes one single HTTP(S) probe against an already-validated origin.
 * @param {{ protocol: 'http:' | 'https:', hostname: string, port: string, basePath: string }} target
 * @param {{ method: string, path: string, headers: Record<string, string>, bodyBuf: Buffer | null }} reqSpec
 * @param {number} timeoutMs
 * @returns {Promise<{ status: number, latencyMs: number, bytes: number, contentType: string, bodyText: string, ok: boolean, error: string | null }>}
 */
function sendProbe(target, reqSpec, timeoutMs) {
  return new Promise((resolve) => {
    const t0 = performance.now();
    const transport = target.protocol === 'https:' ? https : http;
    const reqPath = `${target.basePath}${reqSpec.path.startsWith('/') ? reqSpec.path : '/' + reqSpec.path}`;

    /** @type {Record<string, string>} */
    const wireHeaders = {
      ...reqSpec.headers,
      'X-Culkibo-Shadow-Replay': '1'
    };
    if (reqSpec.bodyBuf && reqSpec.bodyBuf.length > 0) {
      wireHeaders['Content-Length'] = String(reqSpec.bodyBuf.length);
    }

    let settled = false;
    const finish = (/** @type {any} */ res) => {
      if (settled) return;
      settled = true;
      resolve(res);
    };

    const req = transport.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port,
        path: reqPath,
        method: reqSpec.method,
        timeout: timeoutMs,
        headers: wireHeaders
      },
      (res) => {
        /** @type {Buffer[]} */
        const chunks = [];
        let totalBytes = 0;
        let capturedBytes = 0;
        res.on('data', (chunk) => {
          totalBytes += chunk.length;
          if (capturedBytes < MAX_BODY_CAPTURE_BYTES) {
            const slice = capturedBytes + chunk.length > MAX_BODY_CAPTURE_BYTES
              ? chunk.subarray(0, MAX_BODY_CAPTURE_BYTES - capturedBytes)
              : chunk;
            chunks.push(slice);
            capturedBytes += slice.length;
          }
        });
        res.on('end', () => {
          const latencyMs = Number((performance.now() - t0).toFixed(2));
          const status = res.statusCode || 0;
          const contentType = String(res.headers['content-type'] || '');
          const bodyText = Buffer.concat(chunks).toString('utf8');
          finish({
            status,
            latencyMs,
            bytes: totalBytes,
            contentType,
            bodyText,
            ok: status >= 200 && status < 400,
            error: null
          });
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error(`Shadow replay request timeout after ${timeoutMs}ms`));
    });
    req.on('error', (err) => {
      const latencyMs = Number((performance.now() - t0).toFixed(2));
      finish({
        status: 0,
        latencyMs,
        bytes: 0,
        contentType: '',
        bodyText: '',
        ok: false,
        error: err && err.message ? err.message : 'Network error'
      });
    });

    if (reqSpec.bodyBuf && reqSpec.bodyBuf.length > 0 && reqSpec.method !== 'GET' && reqSpec.method !== 'HEAD') {
      req.write(reqSpec.bodyBuf);
    }
    req.end();
  });
}

/**
 * Safely parses JSON response text when Content-Type indicates JSON or text starts with `{` / `[`.
 * @param {string} bodyText
 * @param {string} contentType
 * @returns {{ isJson: boolean, value: any }}
 */
function tryParseJsonBody(bodyText, contentType) {
  const trimmed = String(bodyText || '').trim();
  if (!trimmed) return { isJson: false, value: null };
  const looksJson = /json/i.test(contentType) || trimmed.startsWith('{') || trimmed.startsWith('[');
  if (!looksJson) return { isJson: false, value: null };
  try {
    return { isJson: true, value: JSON.parse(trimmed) };
  } catch (e) {
    return { isJson: false, value: null };
  }
}

class ShadowReplayService {
  /**
   * @param {{ dataDir?: string | null }} [opts]
   */
  constructor(opts = {}) {
    /** @type {string | null} */
    this._explicitDataDir = opts && typeof opts.dataDir === 'string' && opts.dataDir.trim()
      ? path.resolve(opts.dataDir.trim())
      : null;
  }

  /**
   * Resolves data directory dynamically, honoring constructor `dataDir` and `CULKIBO_DATA_DIR`.
   * @returns {string}
   */
  resolveDataDir() {
    if (this._explicitDataDir) return this._explicitDataDir;
    if (process.env.CULKIBO_DATA_DIR) {
      return path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data');
    }
    return path.join(__dirname, '..', '..', 'data');
  }

  /** @returns {string} */
  getHistoryFilePath() {
    return path.join(this.resolveDataDir(), 'shadow-replays.json');
  }

  /**
   * Loads persisted replay reports (most recent first, max 20).
   * @returns {Array<any>}
   */
  _loadHistory() {
    const filePath = this.getHistoryFilePath();
    if (!fs.existsSync(filePath)) return [];
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (parsed && Array.isArray(parsed.replays)) return parsed.replays;
      if (Array.isArray(parsed)) return parsed;
      return [];
    } catch (e) {
      return [];
    }
  }

  /**
   * Persists a new replay report, trimming history to the last `MAX_STORED_REPORTS` (20) entries.
   * @param {any} report
   */
  _saveReport(report) {
    const existing = this._loadHistory();
    const next = [report, ...existing].slice(0, MAX_STORED_REPORTS);
    const payload = {
      schemaVersion: 1,
      updatedAt: new Date().toISOString(),
      maxStored: MAX_STORED_REPORTS,
      replays: next
    };
    atomicWriteFileSync(this.getHistoryFilePath(), JSON.stringify(payload, null, 2) + '\n');
  }

  /**
   * Lists persisted shadow replay reports, optionally filtered by `projectId`.
   * @param {string | null | undefined} [projectId]
   * @returns {Array<any>}
   */
  listReplays(projectId) {
    const all = this._loadHistory();
    if (!projectId) return all;
    const target = String(projectId).trim();
    return all.filter((r) => r && r.projectId === target);
  }

  /**
   * Fetches one persisted replay report by `id`.
   * @param {string} replayId
   */
  getReplay(replayId) {
    const id = String(replayId || '').trim();
    if (!id) return null;
    return this._loadHistory().find((r) => r && r.id === id) || null;
  }

  /**
   * Replays requests concurrently against baseline and candidate origins, compares status,
   * 5xx regressions, JSON key-shape drift, byte-size delta, and p50/p95/p99 latency ratio,
   * evaluates the Promotion Gate, and persists the redacted report.
   *
   * @param {{
   *   projectId?: string,
   *   baselineUrl?: string,
   *   baselineOrigin?: string,
   *   candidateUrl?: string,
   *   candidateOrigin?: string,
   *   requests?: Array<{ method?: string, path?: string, headers?: Record<string, any>, body?: any }>,
   *   concurrency?: number,
   *   timeoutMs?: number,
   *   allowLoopback?: boolean,
   *   persist?: boolean,
   *   gate?: {
   *     max5xxDelta?: number,
   *     maxLatencyRatio?: number,
   *     maxStatusMismatchPct?: number,
   *     failOnSchemaDrift?: boolean,
   *     minLatencyDeltaMs?: number
   *   }
   * }} opts
   */
  async runReplay(opts) {
    if (!opts || typeof opts !== 'object') {
      throw new Error('runReplay requires an options object');
    }

    const allowLoopback = Boolean(opts.allowLoopback);
    const rawBaseline = opts.baselineUrl || opts.baselineOrigin || '';
    const rawCandidate = opts.candidateUrl || opts.candidateOrigin || '';

    const baselineTarget = validateReplayOrigin(rawBaseline, { allowLoopback, label: 'baselineUrl' });
    const candidateTarget = validateReplayOrigin(rawCandidate, { allowLoopback, label: 'candidateUrl' });

    const projectId = String(opts.projectId || 'default').trim().slice(0, 128) || 'default';
    const rawRequests = Array.isArray(opts.requests) && opts.requests.length > 0
      ? opts.requests.slice(0, MAX_REQUESTS_PER_RUN)
      : [{ method: 'GET', path: '/' }];

    const concurrency = Math.max(1, Math.min(20, Math.round(Number(opts.concurrency) || DEFAULT_CONCURRENCY)));
    const timeoutMs = Math.max(200, Math.min(30000, Math.round(Number(opts.timeoutMs) || DEFAULT_TIMEOUT_MS)));

    const rawGate = opts.gate && typeof opts.gate === 'object' ? opts.gate : {};
    const gate = {
      max5xxDelta: Number.isFinite(Number(rawGate.max5xxDelta)) ? Math.max(0, Number(rawGate.max5xxDelta)) : 0,
      maxLatencyRatio: Number.isFinite(Number(rawGate.maxLatencyRatio)) && Number(rawGate.maxLatencyRatio) > 0
        ? Number(rawGate.maxLatencyRatio)
        : 2.0,
      maxStatusMismatchPct: Number.isFinite(Number(rawGate.maxStatusMismatchPct))
        ? Math.max(0, Math.min(100, Number(rawGate.maxStatusMismatchPct)))
        : 5,
      failOnSchemaDrift: Boolean(rawGate.failOnSchemaDrift),
      minLatencyDeltaMs: Number.isFinite(Number(rawGate.minLatencyDeltaMs))
        ? Math.max(0, Number(rawGate.minLatencyDeltaMs))
        : 25
    };

    const normalizedRequests = rawRequests.map((r, index) => {
      const methodRaw = String((r && r.method) || 'GET').trim().toUpperCase();
      const method = ALLOWED_HTTP_METHODS.has(methodRaw) ? methodRaw : 'GET';
      let reqPath = String((r && r.path) || '/').trim();
      if (!reqPath.startsWith('/')) reqPath = '/' + reqPath;
      if (/[\r\n\0]/.test(reqPath)) {
        throw new Error(`Invalid request path at index ${index}`);
      }
      const forwardedHeaders = stripHopByHopHeaders(r && r.headers);
      const redactedReqHeaders = redactHeaders(r && r.headers);
      /** @type {Buffer | null} */
      let bodyBuf = null;
      if (r && r.body !== undefined && r.body !== null) {
        if (Buffer.isBuffer(r.body)) {
          bodyBuf = r.body;
        } else if (typeof r.body === 'string') {
          bodyBuf = Buffer.from(r.body, 'utf8');
        } else {
          bodyBuf = Buffer.from(JSON.stringify(r.body), 'utf8');
          if (!Object.keys(forwardedHeaders).some((k) => k.toLowerCase() === 'content-type')) {
            forwardedHeaders['Content-Type'] = 'application/json';
          }
        }
      }
      return {
        index,
        method,
        path: reqPath,
        headers: forwardedHeaders,
        redactedHeaders: redactedReqHeaders,
        bodyBuf
      };
    });

    const runStart = performance.now();
    /** @type {Array<any>} */
    const perRequest = new Array(normalizedRequests.length);
    let cursor = 0;

    const worker = async () => {
      while (cursor < normalizedRequests.length) {
        const idx = cursor++;
        const spec = normalizedRequests[idx];
        const [baseRes, candRes] = await Promise.all([
          sendProbe(baselineTarget, spec, timeoutMs),
          sendProbe(candidateTarget, spec, timeoutMs)
        ]);

        const statusMatch = baseRes.status === candRes.status && !baseRes.error && !candRes.error;
        const baseIs5xx = baseRes.status >= 500 || Boolean(baseRes.error);
        const candIs5xx = candRes.status >= 500 || Boolean(candRes.error);
        const is5xxRegression = candIs5xx && !baseIs5xx;

        const baseJson = tryParseJsonBody(baseRes.bodyText, baseRes.contentType);
        const candJson = tryParseJsonBody(candRes.bodyText, candRes.contentType);
        /** @type {any} */
        let jsonShape = null;
        if (!baseIs5xx && !candIs5xx) {
          if (baseJson.isJson && candJson.isJson) {
            jsonShape = compareJsonShape(baseJson.value, candJson.value);
          } else if (baseJson.isJson && !candJson.isJson) {
            jsonShape = {
              compatible: false,
              drifted: true,
              hasBreakingDrift: true,
              missingKeys: ['$root'],
              addedKeys: [],
              typeChanges: [{ path: '$root', baselineType: 'json', candidateType: 'non-json' }],
              baselineType: jsonTypeOf(baseJson.value),
              candidateType: 'non-json'
            };
          }
        }

        const bytesDiff = candRes.bytes - baseRes.bytes;
        const bytesDiffPct = baseRes.bytes > 0
          ? Number(((bytesDiff / baseRes.bytes) * 100).toFixed(2))
          : (candRes.bytes > 0 ? 100 : 0);
        const latencyRatio = baseRes.latencyMs > 0
          ? Number((candRes.latencyMs / baseRes.latencyMs).toFixed(3))
          : 1;

        perRequest[idx] = {
          index: spec.index,
          method: spec.method,
          path: spec.path,
          headers: spec.redactedHeaders,
          baseline: {
            status: baseRes.status,
            latencyMs: baseRes.latencyMs,
            bytes: baseRes.bytes,
            contentType: baseRes.contentType,
            error: baseRes.error
          },
          candidate: {
            status: candRes.status,
            latencyMs: candRes.latencyMs,
            bytes: candRes.bytes,
            contentType: candRes.contentType,
            error: candRes.error
          },
          statusMatch,
          is5xxRegression,
          bytesDiff,
          bytesDiffPct,
          latencyRatio,
          jsonShape
        };
      }
    };

    const workerCount = Math.min(concurrency, normalizedRequests.length);
    await Promise.all(Array.from({ length: workerCount }, () => worker()));

    const durationMs = Number((performance.now() - runStart).toFixed(2));
    const totalRequests = perRequest.length;
    let statusMatches = 0;
    let baseline5xx = 0;
    let candidate5xx = 0;
    let regressions5xx = 0;
    let schemaDriftCount = 0;
    let breakingSchemaDriftCount = 0;
    let nonBreakingAdditionsCount = 0;
    /** @type {number[]} */
    const baseLatencies = [];
    /** @type {number[]} */
    const candLatencies = [];

    for (const r of perRequest) {
      if (r.statusMatch) statusMatches++;
      if (r.baseline.status >= 500 || r.baseline.error) baseline5xx++;
      if (r.candidate.status >= 500 || r.candidate.error) candidate5xx++;
      if (r.is5xxRegression) regressions5xx++;
      if (r.jsonShape && r.jsonShape.drifted) schemaDriftCount++;
      if (r.jsonShape && r.jsonShape.hasBreakingDrift) breakingSchemaDriftCount++;
      if (r.jsonShape && Array.isArray(r.jsonShape.addedKeys) && r.jsonShape.addedKeys.length > 0) {
        nonBreakingAdditionsCount++;
      }
      baseLatencies.push(r.baseline.latencyMs);
      candLatencies.push(r.candidate.latencyMs);
    }

    const statusMismatches = totalRequests - statusMatches;
    const statusMismatchPct = totalRequests > 0
      ? Number(((statusMismatches / totalRequests) * 100).toFixed(2))
      : 0;
    const delta5xx = candidate5xx - baseline5xx;

    const avgOf = (/** @type {number[]} */ arr) => arr.length === 0
      ? 0
      : Number((arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(2));

    const baselineLatencyMs = {
      p50: computePercentile(baseLatencies, 50),
      p95: computePercentile(baseLatencies, 95),
      p99: computePercentile(baseLatencies, 99),
      avg: avgOf(baseLatencies)
    };
    const candidateLatencyMs = {
      p50: computePercentile(candLatencies, 50),
      p95: computePercentile(candLatencies, 95),
      p99: computePercentile(candLatencies, 99),
      avg: avgOf(candLatencies)
    };

    const latencyRatioP95 = baselineLatencyMs.p95 > 0
      ? Number((candidateLatencyMs.p95 / baselineLatencyMs.p95).toFixed(3))
      : (candidateLatencyMs.p95 > 0 ? Number(candidateLatencyMs.p95.toFixed(3)) : 1);
    const latencyDeltaP95Ms = Number((candidateLatencyMs.p95 - baselineLatencyMs.p95).toFixed(2));

    /** @type {Array<{ code: string, message: string, actual: number, threshold: number }>} */
    const blockers = [];

    if (delta5xx > gate.max5xxDelta || regressions5xx > gate.max5xxDelta) {
      const actual5xx = Math.max(delta5xx, regressions5xx);
      blockers.push({
        code: 'REGRESSION_5XX',
        message: `Candidate introduced ${actual5xx} new 5xx/network error(s) (baseline=${baseline5xx}, candidate=${candidate5xx}, max5xxDelta=${gate.max5xxDelta})`,
        actual: actual5xx,
        threshold: gate.max5xxDelta
      });
    }

    if (statusMismatchPct > gate.maxStatusMismatchPct) {
      blockers.push({
        code: 'STATUS_MISMATCH',
        message: `HTTP status mismatch ${statusMismatchPct}% (${statusMismatches}/${totalRequests}) exceeds threshold ${gate.maxStatusMismatchPct}%`,
        actual: statusMismatchPct,
        threshold: gate.maxStatusMismatchPct
      });
    }

    if (latencyRatioP95 > gate.maxLatencyRatio && latencyDeltaP95Ms >= gate.minLatencyDeltaMs) {
      blockers.push({
        code: 'LATENCY_P95_SPIKE',
        message: `Candidate p95 latency ${candidateLatencyMs.p95}ms is ${latencyRatioP95}x baseline ${baselineLatencyMs.p95}ms (+${latencyDeltaP95Ms}ms > ${gate.maxLatencyRatio}x threshold)`,
        actual: latencyRatioP95,
        threshold: gate.maxLatencyRatio
      });
    }

    if (gate.failOnSchemaDrift && breakingSchemaDriftCount > 0) {
      blockers.push({
        code: 'JSON_SCHEMA_DRIFT',
        message: `${breakingSchemaDriftCount} request(s) exhibited breaking JSON response schema drift (missing keys or type changes)`,
        actual: breakingSchemaDriftCount,
        threshold: 0
      });
    }

    const pass = blockers.length === 0;
    const verdict = pass ? 'PROMOTE' : 'BLOCK_CUTOVER';

    const report = {
      id: `sr_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
      schemaVersion: 'culkibo.shadow-replay/v1',
      projectId,
      createdAt: new Date().toISOString(),
      durationMs,
      baselineUrl: `${baselineTarget.origin}${baselineTarget.basePath}`,
      candidateUrl: `${candidateTarget.origin}${candidateTarget.basePath}`,
      gate,
      pass,
      verdict,
      blockers,
      summary: {
        totalRequests,
        statusMatches,
        statusMismatches,
        statusMismatchPct,
        baseline5xx,
        candidate5xx,
        delta5xx,
        regressions5xx,
        schemaDriftCount,
        breakingSchemaDriftCount,
        nonBreakingAdditionsCount,
        baselineLatencyMs,
        candidateLatencyMs,
        latencyRatioP95,
        latencyDeltaP95Ms
      },
      perRequest
    };

    if (opts.persist !== false) {
      this._saveReport(report);
    }

    return report;
  }
}

const defaultShadowReplayService = new ShadowReplayService();

const exported = Object.assign(defaultShadowReplayService, {
  ShadowReplayService,
  compareJsonShape,
  computePercentile,
  validateReplayOrigin,
  redactHeaders,
  stripHopByHopHeaders,
  MAX_STORED_REPORTS
});

module.exports = exported;
