'use strict';

/**
 * Culkibo Zero-Dep Spec-Compliant OTLP/HTTP JSON Exporter (Grafana Tempo / SigNoz / Honeycomb ready).
 *
 * Guarantees:
 *  - 0 external npm dependencies (Node built-ins only: crypto, http, https, net, os, zlib).
 *  - Strict OTLP/HTTP JSON 1.x wire format:
 *      * 32-char LOWERCASE HEX `traceId` & 16-char LOWERCASE HEX `spanId` (NEVER base64).
 *      * String-encoded uint64 nanosecond timestamps (`startTimeUnixNano`, `endTimeUnixNano`, `timeUnixNano`).
 *      * W3C Trace Context `traceparent` (`00-<traceId>-<spanId>-01`).
 *      * `Content-Type: application/json` + `Content-Encoding: gzip` (`zlib.gzipSync`).
 *  - Bounded O(1) circular ring buffer (default 256 spans) — zero unbounded RAM growth.
 *  - Unconditional cloud-metadata SSRF blocking (`169.254.169.254`, `metadata.google.internal`,
 *    `100.100.100.200`, link-local `169.254.0.0/16` / `fe80::/10`, `fd00:ec2::254`, etc.);
 *    loopback (`127.0.0.1` / `::1` / `localhost`) requires explicit `allowLoopback: true`.
 *  - Circuit-breaker exponential backoff on collector failure (5xx / network timeout).
 *  - Secret-bearing headers (Authorization, API keys, tokens) are ALWAYS redacted in `getStatus()`.
 */

const crypto = require('crypto');
const http = require('http');
const https = require('https');
const net = require('net');
const os = require('os');
const zlib = require('zlib');

let PKG_VERSION = '1.2.0';
try {
  const pkg = require('../../package.json');
  if (pkg && typeof pkg.version === 'string' && pkg.version.trim()) {
    PKG_VERSION = pkg.version.trim();
  }
} catch (e) {}

const OTLP_CONTENT_TYPE = 'application/json';
const MAX_SPAN_BUFFER = 256;
const MIN_SPAN_BUFFER = 16;
const HARD_MAX_SPAN_BUFFER = 2048;
const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_FAILURE_THRESHOLD = 2;
const DEFAULT_BASE_BACKOFF_MS = 5000;
const DEFAULT_MAX_BACKOFF_MS = 300000;

const TRACE_ID_RE = /^[0-9a-f]{32}$/;
const SPAN_ID_RE = /^[0-9a-f]{16}$/;
const ZERO_TRACE_ID = '00000000000000000000000000000000';
const ZERO_SPAN_ID = '0000000000000000';
const TRACEPARENT_RE = /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;
const SENSITIVE_HEADER_RE = /(?:authorization|proxy-authorization|cookie|token|secret|api[-_]?key|access[-_]?key|x-honeycomb-team|dd-api-key|signoz|password)/i;

/** @type {Record<string, number>} */
const SPAN_KIND_MAP = {
  UNSPECIFIED: 0,
  INTERNAL: 1,
  SERVER: 2,
  CLIENT: 3,
  PRODUCER: 4,
  CONSUMER: 5
};

/** @type {Record<string, number>} */
const STATUS_CODE_MAP = {
  UNSET: 0,
  OK: 1,
  ERROR: 2
};

// Monotonic nanosecond anchor so span durations never go backwards on wall-clock adjustments.
const EPOCH_BASE_NS = BigInt(Date.now()) * 1000000n;
const HR_BASE_NS = process.hrtime.bigint();

/**
 * Returns current UTC timestamp in unsigned 64-bit nanoseconds as a BigInt.
 * @returns {bigint}
 */
function nowUnixNanoBigInt() {
  return EPOCH_BASE_NS + (process.hrtime.bigint() - HR_BASE_NS);
}

/**
 * Generates a spec-compliant 32-character lowercase hex OTLP traceId (non-zero).
 * @returns {string}
 */
function newTraceId() {
  for (let i = 0; i < 4; i++) {
    const hex = crypto.randomBytes(16).toString('hex');
    if (hex !== ZERO_TRACE_ID) return hex;
  }
  return '10000000000000000000000000000001';
}

/**
 * Generates a spec-compliant 16-character lowercase hex OTLP spanId (non-zero).
 * @returns {string}
 */
function newSpanId() {
  for (let i = 0; i < 4; i++) {
    const hex = crypto.randomBytes(8).toString('hex');
    if (hex !== ZERO_SPAN_ID) return hex;
  }
  return '1000000000000001';
}

/**
 * Formats a W3C Trace Context `traceparent` header (`00-<traceId>-<spanId>-<flags>`).
 * @param {string} traceId
 * @param {string} spanId
 * @param {boolean | string} [sampledOrFlags]
 * @returns {string}
 */
function formatTraceparent(traceId, spanId, sampledOrFlags = true) {
  const tid = String(traceId || '').trim();
  const sid = String(spanId || '').trim();
  if (!TRACE_ID_RE.test(tid) || tid === ZERO_TRACE_ID) {
    throw new Error('Invalid OTLP traceId: must be 32 lowercase hex chars and non-zero');
  }
  if (!SPAN_ID_RE.test(sid) || sid === ZERO_SPAN_ID) {
    throw new Error('Invalid OTLP spanId: must be 16 lowercase hex chars and non-zero');
  }
  let flags = '01';
  if (typeof sampledOrFlags === 'string' && /^[0-9a-f]{2}$/.test(sampledOrFlags)) {
    flags = sampledOrFlags;
  } else {
    flags = sampledOrFlags ? '01' : '00';
  }
  return `00-${tid}-${sid}-${flags}`;
}

/**
 * Parses a W3C Trace Context `traceparent` header strictly (lowercase hex, version != ff, non-zero IDs).
 * @param {string | null | undefined} header
 * @returns {{ version: string, traceId: string, spanId: string, traceFlags: string, sampled: boolean } | null}
 */
function parseTraceparent(header) {
  if (typeof header !== 'string') return null;
  const trimmed = header.trim();
  const m = TRACEPARENT_RE.exec(trimmed);
  if (!m) return null;
  const [, version, traceId, spanId, traceFlags] = m;
  if (version === 'ff') return null;
  if (traceId === ZERO_TRACE_ID || spanId === ZERO_SPAN_ID) return null;
  const sampled = (parseInt(traceFlags, 16) & 1) === 1;
  return { version, traceId, spanId, traceFlags, sampled };
}

/**
 * Checks whether an IPv4/IPv6/hostname is a blocked cloud metadata or link-local SSRF target.
 * @param {string} hostname
 * @returns {boolean}
 */
function isBlockedMetadataHost(hostname) {
  const host = String(hostname || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!host) return true;

  // Well-known cloud IMDS hostnames (AWS/GCP/Azure/Alibaba/Oracle/DigitalOcean)
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

  // Unwrap IPv4-mapped IPv6 (`::ffff:169.254.169.254` or hex form `::ffff:a9fe:a9fe`)
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
    // 169.254.0.0/16 link-local / cloud metadata, 0.0.0.0/8 unspecified
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 0) return true;
    // Alibaba Cloud metadata 100.100.100.200
    if (parts[0] === 100 && parts[1] === 100 && parts[2] === 100 && parts[3] === 200) return true;
  } else if (ipVer === 6) {
    // Link-local fe80::/10, AWS EC2 IPv6 IMDS fd00:ec2::254, unspecified ::
    if (/^fe[89ab][0-9a-f]:/i.test(host) || host.startsWith('fd00:ec2:')) return true;
    if (host === '::' || host === '0:0:0:0:0:0:0:0') return true;
  }

  return false;
}

/**
 * Checks whether a hostname resolves syntactically to loopback (`127.0.0.0/8`, `::1`, `localhost`).
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
  if (net.isIP(host) === 4) {
    return host.startsWith('127.');
  }
  return false;
}

/**
 * Validates an OTLP HTTP(S) collector endpoint and rejects cloud metadata SSRF (and loopback unless opted in).
 * @param {string} rawEndpoint
 * @param {{ allowLoopback?: boolean }} [opts]
 * @returns {{ normalizedBase: string, tracesUrl: string, metricsUrl: string, protocol: 'http:' | 'https:', hostname: string }}
 */
function validateOtlpEndpoint(rawEndpoint, opts = {}) {
  if (typeof rawEndpoint !== 'string' || !rawEndpoint.trim()) {
    const err = /** @type {any} */ (new Error('OTLP endpoint must be a non-empty http(s) URL'));
    err.code = 'INVALID_ENDPOINT';
    throw err;
  }
  if (/[\r\n\0]/.test(rawEndpoint)) {
    const err = /** @type {any} */ (new Error('OTLP endpoint contains invalid control characters'));
    err.code = 'INVALID_ENDPOINT';
    throw err;
  }

  let parsed;
  try {
    parsed = new URL(rawEndpoint.trim());
  } catch (e) {
    const err = /** @type {any} */ (new Error(`Invalid OTLP endpoint URL: ${rawEndpoint}`));
    err.code = 'INVALID_ENDPOINT';
    throw err;
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    const err = /** @type {any} */ (new Error(`Unsupported OTLP protocol "${parsed.protocol}" (expected http: or https:)`));
    err.code = 'INVALID_ENDPOINT';
    throw err;
  }
  if (parsed.username || parsed.password) {
    const err = /** @type {any} */ (new Error('OTLP endpoint URL must not embed credentials; pass headers instead'));
    err.code = 'INVALID_ENDPOINT';
    throw err;
  }

  const host = parsed.hostname;
  if (isBlockedMetadataHost(host)) {
    const err = /** @type {any} */ (new Error(`OTLP endpoint blocked by SSRF protection (metadata/link-local host): ${host}`));
    err.code = 'SSRF_BLOCKED';
    throw err;
  }
  if (isLoopbackHost(host) && opts.allowLoopback !== true) {
    const err = /** @type {any} */ (new Error(`OTLP loopback endpoint "${host}" requires explicit allowLoopback: true`));
    err.code = 'SSRF_LOOPBACK_BLOCKED';
    throw err;
  }

  // Strip trailing /v1/traces or /v1/metrics or trailing slash to derive clean base URL
  let cleanPath = parsed.pathname.replace(/\/+$/, '');
  if (cleanPath.endsWith('/v1/traces')) {
    cleanPath = cleanPath.slice(0, -'/v1/traces'.length);
  } else if (cleanPath.endsWith('/v1/metrics')) {
    cleanPath = cleanPath.slice(0, -'/v1/metrics'.length);
  }
  const baseOriginAndPath = `${parsed.protocol}//${parsed.host}${cleanPath}`;
  return {
    normalizedBase: baseOriginAndPath,
    tracesUrl: `${baseOriginAndPath}/v1/traces`,
    metricsUrl: `${baseOriginAndPath}/v1/metrics`,
    protocol: /** @type {'http:' | 'https:'} */ (parsed.protocol),
    hostname: host
  };
}

/**
 * Redacts sensitive HTTP header values (Authorization, API keys, tokens) for safe status/API reporting.
 * @param {Record<string, string> | null | undefined} headers
 * @returns {Record<string, string>}
 */
function redactOtlpHeaders(headers) {
  /** @type {Record<string, string>} */
  const out = {};
  if (!headers || typeof headers !== 'object') return out;
  for (const [k, v] of Object.entries(headers)) {
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
 * Converts a flat key/value map into OTLP `KeyValue[]` AnyValue array.
 * @param {Record<string, any> | null | undefined} attrs
 * @returns {Array<{ key: string, value: Record<string, any> }>}
 */
function toOtlpAttributes(attrs) {
  if (!attrs || typeof attrs !== 'object') return [];
  /** @type {Array<{ key: string, value: Record<string, any> }>} */
  const list = [];
  for (const [rawKey, rawVal] of Object.entries(attrs)) {
    if (rawVal === undefined || rawVal === null) continue;
    const key = String(rawKey).trim();
    if (!key) continue;
    if (typeof rawVal === 'string') {
      list.push({ key, value: { stringValue: rawVal } });
    } else if (typeof rawVal === 'boolean') {
      list.push({ key, value: { boolValue: rawVal } });
    } else if (typeof rawVal === 'number') {
      if (!Number.isFinite(rawVal)) continue;
      if (Number.isInteger(rawVal)) {
        list.push({ key, value: { intValue: String(rawVal) } });
      } else {
        list.push({ key, value: { doubleValue: rawVal } });
      }
    } else if (Array.isArray(rawVal)) {
      const values = rawVal
        .filter((x) => x !== null && x !== undefined)
        .slice(0, 32)
        .map((x) => {
          if (typeof x === 'boolean') return { boolValue: x };
          if (typeof x === 'number' && Number.isFinite(x)) {
            return Number.isInteger(x) ? { intValue: String(x) } : { doubleValue: x };
          }
          return { stringValue: String(x) };
        });
      list.push({ key, value: { arrayValue: { values } } });
    } else {
      list.push({ key, value: { stringValue: String(rawVal) } });
    }
  }
  return list;
}

/**
 * Sanitizes custom HTTP headers (rejects CRLF injection and empty keys).
 * @param {Record<string, any> | null | undefined} rawHeaders
 * @returns {Record<string, string>}
 */
function sanitizeHeaders(rawHeaders) {
  /** @type {Record<string, string>} */
  const clean = {};
  if (!rawHeaders || typeof rawHeaders !== 'object') return clean;
  for (const [k, v] of Object.entries(rawHeaders)) {
    const key = String(k || '').trim();
    const val = String(v ?? '').trim();
    if (!key || !/^[A-Za-z0-9-]+$/.test(key)) continue;
    if (/[\r\n\0]/.test(val)) continue;
    const lower = key.toLowerCase();
    if (lower === 'host' || lower === 'content-length' || lower === 'content-encoding' || lower === 'content-type') {
      continue;
    }
    clean[key] = val;
  }
  return clean;
}

/**
 * Sends a gzip-compressed OTLP/HTTP JSON payload using native `http`/`https`.
 * @param {string} targetUrl
 * @param {object} payloadObj
 * @param {Record<string, string>} extraHeaders
 * @param {number} timeoutMs
 * @returns {Promise<{ ok: boolean, statusCode: number, bytesRaw: number, bytesGzip: number, durationMs: number, body: string, error?: string }>}
 */
function postOtlpGzipJson(targetUrl, payloadObj, extraHeaders, timeoutMs) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const jsonBuf = Buffer.from(JSON.stringify(payloadObj), 'utf8');
    const gzipBuf = zlib.gzipSync(jsonBuf, { level: 6 });

    let parsed;
    try {
      parsed = new URL(targetUrl);
    } catch (e) {
      return resolve({
        ok: false,
        statusCode: 0,
        bytesRaw: jsonBuf.length,
        bytesGzip: gzipBuf.length,
        durationMs: Date.now() - t0,
        body: '',
        error: e && /** @type {any} */ (e).message ? /** @type {any} */ (e).message : 'Invalid target URL'
      });
    }

    const transport = parsed.protocol === 'https:' ? https : http;
    let settled = false;
    const finish = (/** @type {any} */ res) => {
      if (settled) return;
      settled = true;
      resolve(res);
    };

    const req = transport.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: `${parsed.pathname}${parsed.search}`,
        method: 'POST',
        timeout: timeoutMs,
        headers: {
          ...extraHeaders,
          'Content-Type': OTLP_CONTENT_TYPE,
          'Content-Encoding': 'gzip',
          'Content-Length': String(gzipBuf.length),
          'Accept': OTLP_CONTENT_TYPE,
          'User-Agent': `culkibo-otlp/${PKG_VERSION}`
        }
      },
      (res) => {
        /** @type {Buffer[]} */
        const chunks = [];
        let total = 0;
        res.on('data', (chunk) => {
          if (total < 8192) {
            chunks.push(chunk);
            total += chunk.length;
          }
        });
        res.on('end', () => {
          const statusCode = res.statusCode || 0;
          const body = Buffer.concat(chunks).toString('utf8');
          const ok = statusCode >= 200 && statusCode < 300;
          finish({
            ok,
            statusCode,
            bytesRaw: jsonBuf.length,
            bytesGzip: gzipBuf.length,
            durationMs: Date.now() - t0,
            body,
            ...(ok ? {} : { error: `OTLP collector responded HTTP ${statusCode}` })
          });
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error(`OTLP export timeout after ${timeoutMs}ms`));
    });
    req.on('error', (err) => {
      finish({
        ok: false,
        statusCode: 0,
        bytesRaw: jsonBuf.length,
        bytesGzip: gzipBuf.length,
        durationMs: Date.now() - t0,
        body: '',
        error: err && err.message ? err.message : 'OTLP network error'
      });
    });

    req.end(gzipBuf);
  });
}

class OtlpExporter {
  /**
   * @param {{
   *   endpoint?: string | null,
   *   headers?: Record<string, string>,
   *   enabled?: boolean,
   *   serviceName?: string,
   *   serviceVersion?: string,
   *   allowLoopback?: boolean,
   *   maxBufferSize?: number,
   *   timeoutMs?: number,
   *   failureThreshold?: number,
   *   baseBackoffMs?: number,
   *   maxBackoffMs?: number
   * }} [opts]
   */
  constructor(opts = {}) {
    /** @type {string | null} */
    this.endpoint = null;
    /** @type {string | null} */
    this.tracesUrl = null;
    /** @type {string | null} */
    this.metricsUrl = null;
    /** @type {Record<string, string>} */
    this.headers = {};
    this.enabled = false;
    this.serviceName = 'culkibo-control-plane';
    this.serviceVersion = PKG_VERSION;
    this.allowLoopback = false;
    this.maxBufferSize = MAX_SPAN_BUFFER;
    this.timeoutMs = DEFAULT_TIMEOUT_MS;
    this.failureThreshold = DEFAULT_FAILURE_THRESHOLD;
    this.baseBackoffMs = DEFAULT_BASE_BACKOFF_MS;
    this.maxBackoffMs = DEFAULT_MAX_BACKOFF_MS;

    // O(1) bounded circular ring buffer for completed OTLP spans
    /** @type {Array<any>} */
    this._ring = new Array(this.maxBufferSize);
    this._ringHead = 0; // oldest slot index
    this._ringCount = 0;

    // Stats & circuit breaker state
    this.totalRecordedSpans = 0;
    this.exportedSpans = 0;
    this.droppedSpans = 0;
    this.exportedMetrics = 0;
    this.exportAttempts = 0;
    this.exportSuccesses = 0;
    this.exportFailures = 0;
    /** @type {'closed' | 'open' | 'half-open'} */
    this.circuitState = 'closed';
    this.consecutiveFailures = 0;
    this.circuitOpenUntil = 0;
    this.backoffMs = 0;
    /** @type {string | null} */
    this.lastExportAt = null;
    /** @type {string | null} */
    this.lastError = null;
    /** @type {number | null} */
    this.lastStatusCode = null;

    if (opts && Object.keys(opts).length > 0) {
      this.configure(opts);
    }
  }

  /**
   * Configures exporter target, auth headers, service metadata, buffer bounds, and circuit breaker.
   * Validates endpoint against cloud-metadata SSRF unconditionally.
   *
   * @param {{
   *   endpoint?: string | null,
   *   headers?: Record<string, string>,
   *   enabled?: boolean,
   *   serviceName?: string,
   *   serviceVersion?: string,
   *   allowLoopback?: boolean,
   *   maxBufferSize?: number,
   *   timeoutMs?: number,
   *   failureThreshold?: number,
   *   baseBackoffMs?: number,
   *   maxBackoffMs?: number
   * }} [cfg]
   */
  configure(cfg = {}) {
    if (!cfg || typeof cfg !== 'object') return this.getStatus();

    const nextAllowLoopback = cfg.allowLoopback !== undefined
      ? Boolean(cfg.allowLoopback)
      : this.allowLoopback;

    // Validate endpoint BEFORE mutating state so rejected SSRF/invalid URLs never corrupt live config
    /** @type {ReturnType<typeof validateOtlpEndpoint> | { clear: true } | null} */
    let validated = null;
    if (cfg.endpoint !== undefined) {
      if (cfg.endpoint === null || cfg.endpoint === '') {
        validated = { clear: true };
      } else {
        validated = validateOtlpEndpoint(cfg.endpoint, { allowLoopback: nextAllowLoopback });
      }
    } else if (this.endpoint && cfg.allowLoopback === false) {
      // Re-validate existing endpoint if allowLoopback was revoked
      validated = validateOtlpEndpoint(this.endpoint, { allowLoopback: false });
    }

    this.allowLoopback = nextAllowLoopback;

    if (validated) {
      if ('clear' in validated) {
        this.endpoint = null;
        this.tracesUrl = null;
        this.metricsUrl = null;
      } else {
        this.endpoint = validated.normalizedBase;
        this.tracesUrl = validated.tracesUrl;
        this.metricsUrl = validated.metricsUrl;
      }
      // Endpoint change resets circuit breaker cleanly
      this.circuitState = 'closed';
      this.consecutiveFailures = 0;
      this.circuitOpenUntil = 0;
      this.backoffMs = 0;
    }

    if (cfg.headers !== undefined) {
      this.headers = sanitizeHeaders(cfg.headers);
    }
    if (typeof cfg.serviceName === 'string' && cfg.serviceName.trim()) {
      this.serviceName = cfg.serviceName.trim().slice(0, 128);
    }
    if (typeof cfg.serviceVersion === 'string' && cfg.serviceVersion.trim()) {
      this.serviceVersion = cfg.serviceVersion.trim().slice(0, 64);
    }
    if (cfg.timeoutMs !== undefined) {
      const n = Number(cfg.timeoutMs);
      if (Number.isFinite(n) && n >= 200 && n <= 60000) this.timeoutMs = Math.round(n);
    }
    if (cfg.failureThreshold !== undefined) {
      const n = Number(cfg.failureThreshold);
      if (Number.isInteger(n) && n >= 1 && n <= 20) this.failureThreshold = n;
    }
    if (cfg.baseBackoffMs !== undefined) {
      const n = Number(cfg.baseBackoffMs);
      if (Number.isFinite(n) && n >= 50 && n <= 120000) this.baseBackoffMs = Math.round(n);
    }
    if (cfg.maxBackoffMs !== undefined) {
      const n = Number(cfg.maxBackoffMs);
      if (Number.isFinite(n) && n >= this.baseBackoffMs && n <= 600000) this.maxBackoffMs = Math.round(n);
    }
    if (cfg.maxBufferSize !== undefined) {
      const n = Number(cfg.maxBufferSize);
      if (Number.isInteger(n) && n >= MIN_SPAN_BUFFER && n <= HARD_MAX_SPAN_BUFFER && n !== this.maxBufferSize) {
        const existing = this._drainSpans();
        this.maxBufferSize = n;
        this._ring = new Array(this.maxBufferSize);
        this._ringHead = 0;
        this._ringCount = 0;
        for (const sp of existing) this._pushSpan(sp);
      }
    }
    if (cfg.enabled !== undefined) {
      this.enabled = Boolean(cfg.enabled);
    } else if (validated && !('clear' in validated) && cfg.enabled === undefined) {
      // Enabling implicitly only when explicitly passed; preserve current enabled unless cleared
      this.enabled = this.enabled;
    }
    if (!this.endpoint) {
      this.enabled = false;
    }

    return this.getStatus();
  }

  /**
   * Pushes one finalized OTLP span into the O(1) bounded circular ring buffer.
   * When full, drops the oldest span cleanly and increments `droppedSpans`.
   * @param {any} otlpSpan
   */
  _pushSpan(otlpSpan) {
    if (this._ringCount < this.maxBufferSize) {
      const tailIdx = (this._ringHead + this._ringCount) % this.maxBufferSize;
      this._ring[tailIdx] = otlpSpan;
      this._ringCount++;
    } else {
      // Overwrite oldest element in O(1)
      this._ring[this._ringHead] = otlpSpan;
      this._ringHead = (this._ringHead + 1) % this.maxBufferSize;
      this.droppedSpans++;
    }
  }

  /**
   * Drains all buffered spans in FIFO order and resets ring pointers.
   * @returns {Array<any>}
   */
  _drainSpans() {
    if (this._ringCount === 0) return [];
    const out = new Array(this._ringCount);
    for (let i = 0; i < this._ringCount; i++) {
      const idx = (this._ringHead + i) % this.maxBufferSize;
      out[i] = this._ring[idx];
      this._ring[idx] = undefined;
    }
    this._ringHead = 0;
    this._ringCount = 0;
    return out;
  }

  /**
   * Starts a new OTLP span, inheriting W3C traceparent context when supplied.
   * @param {string} name
   * @param {Record<string, any>} [attrs]
   * @param {string | { traceId?: string, spanId?: string, traceparent?: string, kind?: string | number } | null} [parentCtx]
   */
  startSpan(name, attrs = {}, parentCtx = null) {
    let traceId = '';
    let parentSpanId = '';
    let kindNum = SPAN_KIND_MAP.INTERNAL;

    if (typeof parentCtx === 'string') {
      const parsed = parseTraceparent(parentCtx);
      if (parsed) {
        traceId = parsed.traceId;
        parentSpanId = parsed.spanId;
      }
    } else if (parentCtx && typeof parentCtx === 'object') {
      if (typeof parentCtx.traceparent === 'string') {
        const parsed = parseTraceparent(parentCtx.traceparent);
        if (parsed) {
          traceId = parsed.traceId;
          parentSpanId = parsed.spanId;
        }
      }
      if (!traceId && typeof parentCtx.traceId === 'string' && TRACE_ID_RE.test(parentCtx.traceId) && parentCtx.traceId !== ZERO_TRACE_ID) {
        traceId = parentCtx.traceId;
      }
      if (!parentSpanId && typeof parentCtx.spanId === 'string' && SPAN_ID_RE.test(parentCtx.spanId) && parentCtx.spanId !== ZERO_SPAN_ID) {
        parentSpanId = parentCtx.spanId;
      }
      if (typeof parentCtx.kind === 'number' && parentCtx.kind >= 0 && parentCtx.kind <= 5) {
        kindNum = parentCtx.kind;
      } else if (typeof parentCtx.kind === 'string') {
        const mapped = SPAN_KIND_MAP[parentCtx.kind.toUpperCase()];
        if (mapped !== undefined) kindNum = mapped;
      }
    }

    if (!traceId) traceId = newTraceId();
    const spanId = newSpanId();
    const startNs = nowUnixNanoBigInt();
    const traceparent = formatTraceparent(traceId, spanId, true);

    /** @type {Record<string, any>} */
    const cleanAttrs = attrs && typeof attrs === 'object' ? { ...attrs } : {};
    /** @type {Array<{ name: string, timeUnixNano: string, attributes: Array<any> }>} */
    const events = [];

    const span = {
      traceId,
      spanId,
      parentSpanId: parentSpanId || undefined,
      traceparent,
      name: String(name || 'culkibo.span').slice(0, 256),
      kind: kindNum,
      startTimeUnixNano: startNs.toString(),
      _startNsBigInt: startNs,
      attributes: cleanAttrs,
      events,
      ended: false,
      /**
       * @param {string} k
       * @param {any} v
       */
      setAttribute(k, v) {
        if (!this.ended && k) this.attributes[String(k)] = v;
      },
      /**
       * @param {string} evName
       * @param {Record<string, any>} [evAttrs]
       */
      addEvent(evName, evAttrs = {}) {
        if (this.ended || this.events.length >= 32) return;
        this.events.push({
          name: String(evName || 'event').slice(0, 128),
          timeUnixNano: nowUnixNanoBigInt().toString(),
          attributes: toOtlpAttributes(evAttrs)
        });
      }
    };
    return span;
  }

  /**
   * Ends an active span, records it into the bounded 256-span ring buffer, and returns the OTLP JSON span.
   * @param {any} span
   * @param {string | number | { code?: string | number, message?: string } | null} [status]
   */
  endSpan(span, status = 'OK') {
    if (!span || typeof span !== 'object') {
      throw new Error('endSpan requires a valid span object returned by startSpan()');
    }
    if (span.ended && span._finalized) return span._finalized;

    let endNs = nowUnixNanoBigInt();
    const startNs = typeof span._startNsBigInt === 'bigint'
      ? span._startNsBigInt
      : BigInt(span.startTimeUnixNano || '0');
    if (endNs < startNs) endNs = startNs;

    let statusCode = STATUS_CODE_MAP.OK;
    let statusMessage = '';
    if (typeof status === 'number' && (status === 0 || status === 1 || status === 2)) {
      statusCode = status;
    } else if (typeof status === 'string') {
      const upper = status.toUpperCase();
      statusCode = STATUS_CODE_MAP[upper] !== undefined ? STATUS_CODE_MAP[upper] : STATUS_CODE_MAP.OK;
    } else if (status && typeof status === 'object') {
      if (typeof status.code === 'number') {
        statusCode = (status.code === 0 || status.code === 1 || status.code === 2) ? status.code : STATUS_CODE_MAP.OK;
      } else if (typeof status.code === 'string') {
        const mapped = STATUS_CODE_MAP[status.code.toUpperCase()];
        statusCode = mapped !== undefined ? mapped : STATUS_CODE_MAP.OK;
      }
      if (typeof status.message === 'string') {
        statusMessage = status.message.slice(0, 512);
      }
    }

    /** @type {Record<string, any>} */
    const otlpSpan = {
      traceId: span.traceId,
      spanId: span.spanId,
      name: span.name,
      kind: span.kind || SPAN_KIND_MAP.INTERNAL,
      startTimeUnixNano: startNs.toString(),
      endTimeUnixNano: endNs.toString(),
      attributes: toOtlpAttributes(span.attributes),
      status: statusMessage ? { code: statusCode, message: statusMessage } : { code: statusCode }
    };
    if (span.parentSpanId) {
      otlpSpan.parentSpanId = span.parentSpanId;
    }
    if (Array.isArray(span.events) && span.events.length > 0) {
      otlpSpan.events = span.events;
    }

    span.ended = true;
    span.endTimeUnixNano = otlpSpan.endTimeUnixNano;
    span.durationMs = Number(endNs - startNs) / 1e6;
    span._finalized = otlpSpan;

    this.totalRecordedSpans++;
    this._pushSpan(otlpSpan);
    return otlpSpan;
  }

  /**
   * Builds the standard OTLP Resource attributes object.
   */
  _buildResource() {
    return {
      attributes: toOtlpAttributes({
        'service.name': this.serviceName,
        'service.version': this.serviceVersion,
        'telemetry.sdk.name': 'culkibo-otlp-zero-dep',
        'telemetry.sdk.language': 'nodejs',
        'telemetry.sdk.version': this.serviceVersion,
        'host.name': os.hostname(),
        'process.runtime.name': 'nodejs',
        'process.runtime.version': process.version
      })
    };
  }

  /**
   * Builds a spec-compliant OTLP/HTTP JSON `ExportTraceServiceRequest` payload.
   * @param {Array<any>} spans
   */
  buildTracesPayload(spans) {
    return {
      resourceSpans: [
        {
          resource: this._buildResource(),
          scopeSpans: [
            {
              scope: {
                name: 'culkibo.control-plane',
                version: this.serviceVersion
              },
              spans: Array.isArray(spans) ? spans : []
            }
          ]
        }
      ]
    };
  }

  /**
   * Converts a Culkibo metrics snapshot into a spec-compliant OTLP/HTTP JSON `ExportMetricsServiceRequest`.
   * Accepts both flat snapshots (`{ memoryMb, cpuPercent, httpRequestsTotal, ... }`) and nested
   * `metricsCollector` snapshots (`{ process: {...}, http: {...}, security: {...} }`).
   *
   * @param {Record<string, any>} [metricsSnapshot]
   */
  buildMetricsPayload(metricsSnapshot = {}) {
    const snap = metricsSnapshot && typeof metricsSnapshot === 'object' ? metricsSnapshot : {};
    const proc = snap.process && typeof snap.process === 'object' ? snap.process : snap;
    const httpStats = snap.http && typeof snap.http === 'object' ? snap.http : snap;
    const nowNano = nowUnixNanoBigInt().toString();
    const startNano = EPOCH_BASE_NS.toString();

    /** @type {Array<any>} */
    const metrics = [];

    /**
     * @param {string} name
     * @param {string} description
     * @param {string} unit
     * @param {any} rawValue
     */
    const addGauge = (name, description, unit, rawValue) => {
      const val = Number(rawValue);
      if (!Number.isFinite(val)) return;
      metrics.push({
        name,
        description,
        unit,
        gauge: {
          dataPoints: [
            {
              timeUnixNano: nowNano,
              asDouble: val
            }
          ]
        }
      });
    };

    /**
     * @param {string} name
     * @param {string} description
     * @param {string} unit
     * @param {any} rawValue
     */
    const addCounter = (name, description, unit, rawValue) => {
      const val = Number(rawValue);
      if (!Number.isFinite(val) || val < 0) return;
      metrics.push({
        name,
        description,
        unit,
        sum: {
          aggregationTemporality: 2, // AGGREGATION_TEMPORALITY_CUMULATIVE
          isMonotonic: true,
          dataPoints: [
            {
              startTimeUnixNano: startNano,
              timeUnixNano: nowNano,
              asInt: String(Math.round(val))
            }
          ]
        }
      });
    };

    const memRss = proc.memoryMb ?? proc.memoryRssMb ?? proc.rssMb ?? (process.memoryUsage().rss / (1024 * 1024));
    const heapUsed = proc.heapUsedMb ?? (process.memoryUsage().heapUsed / (1024 * 1024));
    const cpuPct = proc.cpuPercent ?? 0;
    const uptimeSec = proc.uptimeSeconds ?? Math.floor(process.uptime());

    addGauge('culkibo.process.memory_rss_mb', 'Culkibo daemon resident set size in MiB', 'MiBy', Number(memRss.toFixed ? memRss.toFixed(2) : memRss));
    addGauge('culkibo.process.heap_used_mb', 'V8 heap used in MiB', 'MiBy', Number(heapUsed.toFixed ? heapUsed.toFixed(2) : heapUsed));
    addGauge('culkibo.process.cpu_percent', 'Control plane CPU utilization percentage', '%', cpuPct);
    addGauge('culkibo.process.uptime_seconds', 'Control plane uptime in seconds', 's', uptimeSec);

    if (httpStats.totalRequests !== undefined || httpStats.httpRequestsTotal !== undefined) {
      addCounter('culkibo.http.requests_total', 'Total HTTP requests served by control plane', '1', httpStats.totalRequests ?? httpStats.httpRequestsTotal);
    }
    if (httpStats.totalErrors !== undefined || httpStats.httpErrorsTotal !== undefined) {
      addCounter('culkibo.http.errors_total', 'Total HTTP 5xx/4xx errors', '1', httpStats.totalErrors ?? httpStats.httpErrorsTotal);
    }
    if (httpStats.latencyP50Ms !== undefined || httpStats.p50Ms !== undefined) {
      addGauge('culkibo.http.latency_p50_ms', 'HTTP p50 latency in milliseconds', 'ms', httpStats.latencyP50Ms ?? httpStats.p50Ms);
    }
    if (httpStats.latencyP95Ms !== undefined || httpStats.p95Ms !== undefined) {
      addGauge('culkibo.http.latency_p95_ms', 'HTTP p95 latency in milliseconds', 'ms', httpStats.latencyP95Ms ?? httpStats.p95Ms);
    }
    if (httpStats.latencyP99Ms !== undefined || httpStats.p99Ms !== undefined) {
      addGauge('culkibo.http.latency_p99_ms', 'HTTP p99 latency in milliseconds', 'ms', httpStats.latencyP99Ms ?? httpStats.p99Ms);
    }
    if (snap.activeWsClients !== undefined) {
      addGauge('culkibo.streams.ws_active', 'Active WebSocket stream clients', '1', snap.activeWsClients);
    }
    if (snap.activeSseClients !== undefined) {
      addGauge('culkibo.streams.sse_active', 'Active SSE stream clients', '1', snap.activeSseClients);
    }
    if (snap.activeLogStreams !== undefined) {
      addGauge('culkibo.streams.log_active', 'Active bounded log/telemetry streams', '1', snap.activeLogStreams);
    }

    return {
      resourceMetrics: [
        {
          resource: this._buildResource(),
          scopeMetrics: [
            {
              scope: {
                name: 'culkibo.metrics',
                version: this.serviceVersion
              },
              metrics
            }
          ]
        }
      ]
    };
  }

  /**
   * Records a collector export failure and updates circuit-breaker exponential backoff state.
   * @param {number} statusCode
   * @param {string} errorMessage
   */
  _recordFailure(statusCode, errorMessage) {
    this.exportFailures++;
    this.consecutiveFailures++;
    this.lastStatusCode = statusCode;
    this.lastError = errorMessage;

    if (this.consecutiveFailures >= this.failureThreshold) {
      const exponent = Math.min(8, this.consecutiveFailures - this.failureThreshold);
      this.backoffMs = Math.min(this.maxBackoffMs, this.baseBackoffMs * (2 ** exponent));
      this.circuitState = 'open';
      this.circuitOpenUntil = Date.now() + this.backoffMs;
    }
  }

  /**
   * Resets circuit breaker on a successful collector 2xx response.
   * @param {number} statusCode
   */
  _recordSuccess(statusCode) {
    this.exportSuccesses++;
    this.consecutiveFailures = 0;
    this.backoffMs = 0;
    this.circuitState = 'closed';
    this.circuitOpenUntil = 0;
    this.lastStatusCode = statusCode;
    this.lastError = null;
    this.lastExportAt = new Date().toISOString();
  }

  /**
   * Flushes buffered spans to `/v1/traces` (and optional `metricsSnapshot` to `/v1/metrics`)
   * using gzip-compressed OTLP/HTTP JSON, enforcing circuit-breaker backoff.
   *
   * @param {{ metricsSnapshot?: Record<string, any> | null }} [opts]
   */
  async flush(opts = {}) {
    if (!this.enabled || !this.endpoint || !this.tracesUrl || !this.metricsUrl) {
      return {
        ok: false,
        skipped: true,
        reason: 'disabled',
        exportedSpans: 0,
        exportedMetrics: 0,
        circuitState: this.circuitState
      };
    }

    const now = Date.now();
    if (this.circuitState === 'open') {
      if (now < this.circuitOpenUntil) {
        return {
          ok: false,
          skipped: true,
          reason: 'circuit_open',
          retryAfterMs: Math.max(0, this.circuitOpenUntil - now),
          exportedSpans: 0,
          exportedMetrics: 0,
          circuitState: 'open'
        };
      }
      this.circuitState = 'half-open';
    }

    const spans = this._drainSpans();
    const hasMetrics = Boolean(opts && opts.metricsSnapshot && typeof opts.metricsSnapshot === 'object');
    if (spans.length === 0 && !hasMetrics) {
      return {
        ok: true,
        skipped: true,
        reason: 'empty',
        exportedSpans: 0,
        exportedMetrics: 0,
        circuitState: this.circuitState
      };
    }

    let exportedSpans = 0;
    let exportedMetrics = 0;
    let totalRaw = 0;
    let totalGzip = 0;
    let lastCode = 0;
    /** @type {string | null} */
    let firstError = null;

    if (spans.length > 0) {
      this.exportAttempts++;
      const tracePayload = this.buildTracesPayload(spans);
      const traceRes = await postOtlpGzipJson(this.tracesUrl, tracePayload, this.headers, this.timeoutMs);
      totalRaw += traceRes.bytesRaw;
      totalGzip += traceRes.bytesGzip;
      lastCode = traceRes.statusCode;

      if (traceRes.ok) {
        exportedSpans = spans.length;
        this.exportedSpans += spans.length;
        this._recordSuccess(traceRes.statusCode);
      } else {
        // Re-enqueue failed spans bounded by maxBufferSize so transient collector blips do not lose telemetry
        for (const sp of spans) this._pushSpan(sp);
        firstError = traceRes.error || `HTTP ${traceRes.statusCode}`;
        this._recordFailure(traceRes.statusCode, firstError);
        return {
          ok: false,
          skipped: false,
          reason: 'collector_error',
          statusCode: traceRes.statusCode,
          error: firstError,
          exportedSpans: 0,
          exportedMetrics: 0,
          bytesRaw: totalRaw,
          bytesGzip: totalGzip,
          circuitState: this.circuitState,
          backoffMs: this.backoffMs,
          retryAfterMs: this.circuitOpenUntil > 0 ? Math.max(0, this.circuitOpenUntil - Date.now()) : 0
        };
      }
    }

    if (hasMetrics && opts.metricsSnapshot) {
      this.exportAttempts++;
      const metricsPayload = this.buildMetricsPayload(opts.metricsSnapshot);
      const metricCount = metricsPayload.resourceMetrics[0]?.scopeMetrics[0]?.metrics?.length || 0;
      const metricRes = await postOtlpGzipJson(this.metricsUrl, metricsPayload, this.headers, this.timeoutMs);
      totalRaw += metricRes.bytesRaw;
      totalGzip += metricRes.bytesGzip;
      lastCode = metricRes.statusCode;

      if (metricRes.ok) {
        exportedMetrics = metricCount;
        this.exportedMetrics += metricCount;
        this._recordSuccess(metricRes.statusCode);
      } else {
        firstError = metricRes.error || `HTTP ${metricRes.statusCode}`;
        this._recordFailure(metricRes.statusCode, firstError);
        return {
          ok: false,
          skipped: false,
          reason: 'collector_error',
          statusCode: metricRes.statusCode,
          error: firstError,
          exportedSpans,
          exportedMetrics: 0,
          bytesRaw: totalRaw,
          bytesGzip: totalGzip,
          circuitState: this.circuitState,
          backoffMs: this.backoffMs,
          retryAfterMs: this.circuitOpenUntil > 0 ? Math.max(0, this.circuitOpenUntil - Date.now()) : 0
        };
      }
    }

    return {
      ok: true,
      skipped: false,
      statusCode: lastCode,
      exportedSpans,
      exportedMetrics,
      bytesRaw: totalRaw,
      bytesGzip: totalGzip,
      circuitState: this.circuitState
    };
  }

  /**
   * Returns current exporter status and telemetry counters with all sensitive headers redacted.
   */
  getStatus() {
    const now = Date.now();
    const effectiveCircuit = (this.circuitState === 'open' && now >= this.circuitOpenUntil)
      ? 'half-open'
      : this.circuitState;
    return {
      enabled: this.enabled,
      endpoint: this.endpoint,
      tracesUrl: this.tracesUrl,
      metricsUrl: this.metricsUrl,
      protocol: 'otlp/http-json',
      contentEncoding: 'gzip',
      serviceName: this.serviceName,
      serviceVersion: this.serviceVersion,
      allowLoopback: this.allowLoopback,
      headers: redactOtlpHeaders(this.headers),
      bufferedSpans: this._ringCount,
      maxBufferSize: this.maxBufferSize,
      totalRecordedSpans: this.totalRecordedSpans,
      exportedSpans: this.exportedSpans,
      droppedSpans: this.droppedSpans,
      exportedMetrics: this.exportedMetrics,
      exportAttempts: this.exportAttempts,
      exportSuccesses: this.exportSuccesses,
      exportFailures: this.exportFailures,
      circuitState: effectiveCircuit,
      consecutiveFailures: this.consecutiveFailures,
      backoffMs: this.backoffMs,
      circuitOpenUntil: this.circuitOpenUntil || null,
      retryAfterMs: effectiveCircuit === 'open' ? Math.max(0, this.circuitOpenUntil - now) : 0,
      lastExportAt: this.lastExportAt,
      lastStatusCode: this.lastStatusCode,
      lastError: this.lastError
    };
  }

  /** Resets buffered spans, counters, and circuit breaker (keeps configuration). */
  reset() {
    this._ring = new Array(this.maxBufferSize);
    this._ringHead = 0;
    this._ringCount = 0;
    this.totalRecordedSpans = 0;
    this.exportedSpans = 0;
    this.droppedSpans = 0;
    this.exportedMetrics = 0;
    this.exportAttempts = 0;
    this.exportSuccesses = 0;
    this.exportFailures = 0;
    this.circuitState = 'closed';
    this.consecutiveFailures = 0;
    this.circuitOpenUntil = 0;
    this.backoffMs = 0;
    this.lastExportAt = null;
    this.lastStatusCode = null;
    this.lastError = null;
  }
}

const defaultOtlpExporter = new OtlpExporter();

const exported = Object.assign(defaultOtlpExporter, {
  OtlpExporter,
  formatTraceparent,
  parseTraceparent,
  newTraceId,
  newSpanId,
  validateOtlpEndpoint,
  redactOtlpHeaders,
  MAX_SPAN_BUFFER,
  OTLP_CONTENT_TYPE
});

module.exports = exported;
