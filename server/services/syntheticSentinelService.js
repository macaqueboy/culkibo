'use strict';

/**
 * Culkibo Zero-Dep Synthetic Multi-Step API Flow Monitor & Live TLS/SNI Drift Sentinel.
 *
 * Cures `uptime-kuma#5772`, `uptime-kuma#7500`, and `gatus#856`:
 *  - Executes chained 1..5-step HTTP synthetic checks (`login -> extract token -> assert JSON/latency`)
 *    with `{{var}}` interpolation across URL, headers, and body.
 *  - ZERO-SECRET PERSISTENCE: extracted variables are strictly ephemeral in-memory during a single
 *    run and NEVER persisted; sensitive headers (`Authorization`, `Cookie`, `X-Api-Key`, `X-Auth-Token`,
 *    `Proxy-Authorization`, or any key matching `secret|token|password|key`) with literal values are
 *    redacted to `[REDACTED]` in persisted flow definitions and run history.
 *  - Per-step AND per-redirect-hop SSRF validation via `ssrfGuard.js` (`allowLoopback` defaults to
 *    `false`; cloud metadata IPs like `169.254.169.254` are UNCONDITIONALLY blocked!).
 *  - Uncached live `tls.connect` TLS/SNI Sentinel detecting certificate expiry (`warnDays`/`critDays`),
 *    wildcard-aware SAN mismatches, SHA-256 fingerprint drift, and CA issuer drift.
 *  - Atomic `0o600` persistence in isolated `CULKIBO_DATA_DIR/data/synthetic-flows.json`.
 */

const crypto = require('crypto');
const dns = require('dns');
const fs = require('fs');
const net = require('net');
const path = require('path');
const tls = require('tls');
const { performance } = require('perf_hooks');

const ssrfGuard = require('./ssrfGuard');

const MAX_STEPS_PER_FLOW = 5;
const MAX_REDIRECT_HOPS = 3;
const MAX_STORED_FLOWS = 100;
const MAX_RUN_HISTORY = 20;
const DEFAULT_STEP_TIMEOUT_MS = 8000;
const DEFAULT_TLS_TIMEOUT_MS = 5000;

const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const SENSITIVE_KEY_RE = /(?:^authorization$|^proxy-authorization$|^cookie$|^set-cookie$|^x-api-key$|^x-auth-token$|secret|token|password|passwd|api[-_]?key|auth[-_]?key|credential)/i;
const PURE_TEMPLATE_RE = /^(?:Bearer\s+|Basic\s+|Token\s+)?(?:\{\{[a-zA-Z0-9_.-]+\}\}|\s)+$/i;

const BLOCKED_METADATA_HOSTS = new Set([
  'metadata',
  'metadata.google.internal',
  'metadata.goog',
  'metadata.azure.internal',
  'instance-data',
  'instance-data.ec2.internal',
  '169.254.169.254',
  '169.254.170.2',
  '100.100.100.200',
  'fd00:ec2::254',
  '0.0.0.0',
  '::'
]);

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
 * Redacts sensitive header values (preserving pure `{{var}}` placeholders so saved flows
 * can still reference runtime-extracted ephemeral tokens while NEVER persisting raw secrets).
 * @param {Record<string, any> | null | undefined} headers
 * @returns {Record<string, string>}
 */
function redactSensitiveHeaders(headers) {
  /** @type {Record<string, string>} */
  const out = {};
  if (!headers || typeof headers !== 'object') return out;
  for (const [rawKey, rawVal] of Object.entries(headers)) {
    const key = String(rawKey || '').trim();
    if (!key) continue;
    const val = String(rawVal ?? '');
    if (SENSITIVE_KEY_RE.test(key)) {
      out[key] = PURE_TEMPLATE_RE.test(val.trim()) ? val.trim() : '[REDACTED]';
    } else {
      out[key] = val;
    }
  }
  return out;
}

/**
 * Recursively redacts sensitive fields inside a request body before persisting a flow definition.
 * @param {any} body
 * @param {number} [depth]
 * @returns {any}
 */
function redactSensitiveBody(body, depth = 0) {
  if (body === null || body === undefined || depth > 8) return body;
  if (typeof body === 'string') return body;
  if (Array.isArray(body)) return body.map((item) => redactSensitiveBody(item, depth + 1));
  if (typeof body === 'object') {
    /** @type {Record<string, any>} */
    const out = {};
    for (const [k, v] of Object.entries(body)) {
      if (SENSITIVE_KEY_RE.test(k)) {
        out[k] = typeof v === 'string' && PURE_TEMPLATE_RE.test(v.trim()) ? v.trim() : '[REDACTED]';
      } else {
        out[k] = redactSensitiveBody(v, depth + 1);
      }
    }
    return out;
  }
  return body;
}

/**
 * Interpolates `{{varName}}` templates using ephemeral runtime variables.
 * @param {string} template
 * @param {Record<string, string>} vars
 * @returns {string}
 */
function interpolateString(template, vars) {
  return String(template ?? '').replace(/\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}/g, (_m, key) => {
    return Object.prototype.hasOwnProperty.call(vars, key) ? String(vars[key]) : '';
  });
}

/**
 * Recursively interpolates `{{varName}}` inside strings, arrays, or objects.
 * @param {any} value
 * @param {Record<string, string>} vars
 * @param {number} [depth]
 * @returns {any}
 */
function interpolateDeep(value, vars, depth = 0) {
  if (value === null || value === undefined || depth > 8) return value;
  if (typeof value === 'string') return interpolateString(value, vars);
  if (Array.isArray(value)) return value.map((item) => interpolateDeep(item, vars, depth + 1));
  if (typeof value === 'object') {
    /** @type {Record<string, any>} */
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = interpolateDeep(v, vars, depth + 1);
    }
    return out;
  }
  return value;
}

/**
 * Resolves a dotted JSONPath (e.g. `json.access_token`, `$.data.user.id`, `access_token`) safely.
 * @param {any} obj
 * @param {string} expr
 * @returns {any}
 */
function resolveDottedPath(obj, expr) {
  if (obj === null || obj === undefined) return undefined;
  let clean = String(expr || '').trim();
  if (clean.startsWith('$.')) clean = clean.slice(2);
  else if (clean.startsWith('json.')) clean = clean.slice(5);
  else if (clean.startsWith('body.')) clean = clean.slice(5);
  if (!clean) return obj;

  const segments = clean.split('.').filter(Boolean);
  let cur = obj;
  for (const seg of segments) {
    if (cur === null || cur === undefined || typeof cur !== 'object') return undefined;
    if (seg === '__proto__' || seg === 'constructor' || seg === 'prototype') return undefined;
    cur = cur[seg];
  }
  return cur;
}

/**
 * Validates a synthetic step or redirect URL against SSRF (`ssrfGuard.js`).
 * Cloud metadata IPs are UNCONDITIONALLY blocked even when `allowLoopback: true`.
 *
 * @param {string} rawUrl
 * @param {{ allowLoopback?: boolean, dnsLookupImpl?: ((host: string) => Promise<any>) | null }} [opts]
 * @returns {Promise<URL>}
 */
async function assertSyntheticUrlSafe(rawUrl, opts = {}) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim() || /[\r\n\0]/.test(rawUrl)) {
    const err = /** @type {any} */ (new Error('Invalid synthetic step URL'));
    err.code = 'INVALID_URL';
    err.status = 400;
    throw err;
  }

  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch (e) {
    const err = /** @type {any} */ (new Error(`Malformed synthetic URL: "${rawUrl.slice(0, 80)}"`));
    err.code = 'INVALID_URL';
    err.status = 400;
    throw err;
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    const err = /** @type {any} */ (new Error(`Unsupported synthetic protocol "${parsed.protocol}"`));
    err.code = 'INVALID_URL';
    err.status = 400;
    throw err;
  }
  if (parsed.username || parsed.password) {
    const err = /** @type {any} */ (new Error('Synthetic URL must not embed credentials'));
    err.code = 'INVALID_URL';
    err.status = 400;
    throw err;
  }

  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!host || BLOCKED_METADATA_HOSTS.has(host) || host.endsWith('.metadata.google.internal')) {
    const err = /** @type {any} */ (new Error(`Synthetic URL blocked by SSRF metadata guard: ${host}`));
    err.code = 'SSRF_BLOCKED';
    err.status = 403;
    throw err;
  }

  const allowLoopback = Boolean(opts.allowLoopback);

  /** @param {string} ip */
  const checkIp = (ip) => {
    const cleanIp = String(ip || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
    if (!cleanIp || ssrfGuard.isMetadataIp(cleanIp)) {
      const err = /** @type {any} */ (new Error(`Synthetic IP blocked by SSRF metadata guard: ${cleanIp}`));
      err.code = 'SSRF_BLOCKED';
      err.status = 403;
      throw err;
    }
    if (ssrfGuard.isLoopbackIp(cleanIp)) {
      if (!allowLoopback) {
        const err = /** @type {any} */ (new Error(`Synthetic loopback host blocked by SSRF guard: ${cleanIp}`));
        err.code = 'SSRF_BLOCKED';
        err.status = 403;
        throw err;
      }
      return;
    }
    if (ssrfGuard.isPrivateIp(cleanIp)) {
      const err = /** @type {any} */ (new Error(`Synthetic private IP blocked by SSRF guard: ${cleanIp}`));
      err.code = 'SSRF_BLOCKED';
      err.status = 403;
      throw err;
    }
  };

  if (net.isIP(host)) {
    checkIp(host);
    return parsed;
  }

  if (host === 'localhost' || host.endsWith('.localhost')) {
    if (!allowLoopback) {
      const err = /** @type {any} */ (new Error(`Synthetic localhost blocked by SSRF guard: ${host}`));
      err.code = 'SSRF_BLOCKED';
      err.status = 403;
      throw err;
    }
    return parsed;
  }

  let records;
  try {
    records = typeof opts.dnsLookupImpl === 'function'
      ? await opts.dnsLookupImpl(host)
      : await dns.promises.lookup(host, { all: true });
  } catch (e) {
    const err = /** @type {any} */ (new Error(`DNS lookup failed for "${host}": ${e && /** @type {any} */ (e).message}`));
    err.code = 'DNS_LOOKUP_FAILED';
    err.status = 502;
    throw err;
  }

  const list = Array.isArray(records) ? records : [records];
  const ips = list
    .map((r) => (typeof r === 'string' ? r.trim() : (r && typeof r.address === 'string' ? r.address.trim() : '')))
    .filter(Boolean);
  if (ips.length === 0) {
    const err = /** @type {any} */ (new Error(`No DNS records resolved for "${host}"`));
    err.code = 'DNS_LOOKUP_FAILED';
    err.status = 502;
    throw err;
  }
  for (const ip of ips) checkIp(ip);
  return parsed;
}

/**
 * Matches a hostname against a certificate SAN list (RFC 6125 single-label wildcard support).
 * @param {string} targetHost
 * @param {string[]} sanList
 * @returns {boolean}
 */
function matchSanHostname(targetHost, sanList) {
  const host = String(targetHost || '').trim().toLowerCase();
  if (!host || !Array.isArray(sanList) || sanList.length === 0) return false;
  for (const rawEntry of sanList) {
    const san = String(rawEntry || '').trim().toLowerCase().replace(/^(?:dns|ip address):/i, '');
    if (!san) continue;
    if (san === host) return true;
    if (san.startsWith('*.')) {
      const suffix = san.slice(1); // `.example.com`
      if (host.endsWith(suffix)) {
        const prefix = host.slice(0, host.length - suffix.length);
        if (prefix.length > 0 && !prefix.includes('.')) return true;
      }
    }
  }
  return false;
}

/**
 * Formats an X.509 issuer/subject object or string into a compact normalized display string.
 * @param {any} field
 * @returns {string}
 */
function formatCertEntity(field) {
  if (!field) return '';
  if (typeof field === 'string') return field.trim();
  if (typeof field === 'object') {
    const parts = [];
    if (field.CN) parts.push(`CN=${field.CN}`);
    if (field.O) parts.push(`O=${field.O}`);
    if (parts.length > 0) return parts.join(', ');
    return Object.entries(field).map(([k, v]) => `${k}=${v}`).join(', ');
  }
  return String(field);
}

/**
 * Parses `subjectaltname` string (`"DNS:example.com, DNS:*.example.com"`) or string[] into clean SAN list.
 * @param {any} rawSan
 * @returns {string[]}
 */
function parseSanList(rawSan) {
  if (Array.isArray(rawSan)) {
    return rawSan.map((s) => String(s || '').trim().replace(/^(?:DNS|IP Address):/i, '')).filter(Boolean);
  }
  if (typeof rawSan !== 'string' || !rawSan.trim()) return [];
  return rawSan
    .split(',')
    .map((part) => part.trim().replace(/^(?:DNS|IP Address):/i, ''))
    .filter(Boolean);
}

/**
 * Performs an uncached live TLS/SNI handshake check (or calls injectable `options.tlsProbeImpl`).
 * Detects certificate expiry (`warnDays` / `critDays`), SAN mismatch, SHA-256 fingerprint drift,
 * and issuer drift.
 *
 * @param {{
 *   host: string,
 *   port?: number,
 *   servername?: string,
 *   expectedSan?: string,
 *   baselineFingerprintSha256?: string,
 *   baselineIssuer?: string,
 *   warnDays?: number,
 *   critDays?: number,
 *   timeoutMs?: number
 * }} cfg
 * @param {{
 *   tlsProbeImpl?: ((params: { host: string, port: number, servername: string, timeoutMs: number }) => Promise<any>) | null,
 *   allowLoopback?: boolean,
 *   nowMs?: number
 * }} [options]
 */
async function checkTlsSentinel(cfg, options = {}) {
  if (!cfg || typeof cfg !== 'object' || !cfg.host) {
    const err = /** @type {any} */ (new Error('checkTlsSentinel requires host'));
    err.code = 'INVALID_HOST';
    err.status = 400;
    throw err;
  }

  const host = String(cfg.host).trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!host || /[\s\r\n\0]/.test(host)) {
    const err = /** @type {any} */ (new Error('Invalid TLS host'));
    err.code = 'INVALID_HOST';
    err.status = 400;
    throw err;
  }
  const isIp = net.isIP(host) !== 0;
  if (BLOCKED_METADATA_HOSTS.has(host) || host.endsWith('.metadata.google.internal') || (isIp && ssrfGuard.isMetadataIp(host))) {
    const err = /** @type {any} */ (new Error(`TLS Sentinel host blocked by SSRF metadata guard: ${host}`));
    err.code = 'SSRF_BLOCKED';
    err.status = 403;
    throw err;
  }
  if (!options.allowLoopback && (host === 'localhost' || host.endsWith('.localhost') || (isIp && (ssrfGuard.isLoopbackIp(host) || ssrfGuard.isPrivateIp(host))))) {
    const err = /** @type {any} */ (new Error(`TLS Sentinel private/loopback host blocked by SSRF guard: ${host}`));
    err.code = 'SSRF_BLOCKED';
    err.status = 403;
    throw err;
  }

  const port = Number.isInteger(Number(cfg.port)) && Number(cfg.port) >= 1 && Number(cfg.port) <= 65535
    ? Number(cfg.port)
    : 443;
  const servername = String(cfg.servername || host).trim().toLowerCase();
  const warnDays = Number.isFinite(Number(cfg.warnDays)) && Number(cfg.warnDays) >= 0 ? Number(cfg.warnDays) : 14;
  const critDays = Number.isFinite(Number(cfg.critDays)) && Number(cfg.critDays) >= 0 ? Number(cfg.critDays) : 3;
  const timeoutMs = Number.isFinite(Number(cfg.timeoutMs)) && Number(cfg.timeoutMs) >= 200
    ? Math.min(30000, Math.round(Number(cfg.timeoutMs)))
    : DEFAULT_TLS_TIMEOUT_MS;
  const nowMs = Number.isFinite(Number(options.nowMs)) ? Number(options.nowMs) : Date.now();

  let probeResult;
  if (typeof options.tlsProbeImpl === 'function') {
    probeResult = await options.tlsProbeImpl({ host, port, servername, timeoutMs });
  } else {
    probeResult = await new Promise((resolve, reject) => {
      let settled = false;
      const socket = tls.connect(
        {
          host,
          port,
          servername: net.isIP(servername) ? undefined : servername,
          rejectUnauthorized: false,
          session: undefined
        },
        () => {
          if (settled) return;
          settled = true;
          const cert = socket.getPeerCertificate(false);
          const protocol = typeof socket.getProtocol === 'function' ? socket.getProtocol() : null;
          socket.end();
          socket.destroy();
          resolve({ cert, protocol });
        }
      );
      socket.setTimeout(timeoutMs, () => {
        if (settled) return;
        settled = true;
        socket.destroy();
        reject(new Error(`TLS handshake timed out after ${timeoutMs}ms (${host}:${port})`));
      });
      socket.on('error', (err) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        reject(err);
      });
    });
  }

  const cert = (probeResult && probeResult.cert) ? probeResult.cert : (probeResult || {});
  const protocol = String(probeResult?.protocol || cert.protocol || 'unknown');
  const validFromRaw = cert.valid_from || cert.validFrom || null;
  const validToRaw = cert.valid_to || cert.validTo || null;
  const validToMs = validToRaw ? Date.parse(String(validToRaw)) : NaN;
  const daysRemaining = Number.isFinite(validToMs)
    ? Math.floor((validToMs - nowMs) / (24 * 60 * 60 * 1000))
    : -1;

  const subject = formatCertEntity(cert.subject);
  const issuer = formatCertEntity(cert.issuer);
  const fingerprintSha256 = String(cert.fingerprint256 || cert.fingerprintSha256 || '').trim().toUpperCase();
  const sanList = parseSanList(cert.subjectaltname || cert.sanList);
  const checkSanTarget = String(cfg.expectedSan || servername || host).trim().toLowerCase();
  const sanMatched = sanList.length > 0
    ? matchSanHostname(checkSanTarget, sanList)
    : (subject.toLowerCase().includes(`cn=${checkSanTarget}`));

  const normFp = (/** @type {string} */ s) => String(s || '').trim().toUpperCase().replace(/[^0-9A-F]/g, '');
  const fingerprintDrifted = Boolean(
    cfg.baselineFingerprintSha256 &&
    fingerprintSha256 &&
    normFp(cfg.baselineFingerprintSha256) !== normFp(fingerprintSha256)
  );
  const issuerDrifted = Boolean(
    cfg.baselineIssuer &&
    issuer &&
    String(cfg.baselineIssuer).trim().toLowerCase() !== issuer.toLowerCase()
  );

  /** @type {Array<{ code: string, severity: 'CRITICAL' | 'WARNING', message: string }>} */
  const alerts = [];
  if (daysRemaining <= critDays) {
    alerts.push({
      code: daysRemaining < 0 ? 'CERT_EXPIRED' : 'CERT_EXPIRING_CRITICAL',
      severity: 'CRITICAL',
      message: daysRemaining < 0
        ? `TLS certificate expired ${Math.abs(daysRemaining)} day(s) ago`
        : `TLS certificate expires in ${daysRemaining} day(s) (<= ${critDays}d critical threshold)`
    });
  } else if (daysRemaining <= warnDays) {
    alerts.push({
      code: 'CERT_EXPIRING_WARNING',
      severity: 'WARNING',
      message: `TLS certificate expires in ${daysRemaining} day(s) (<= ${warnDays}d warning threshold)`
    });
  }

  if (!sanMatched) {
    alerts.push({
      code: 'SAN_MISMATCH',
      severity: 'CRITICAL',
      message: `Expected SAN "${checkSanTarget}" not covered by certificate SANs [${sanList.join(', ')}]`
    });
  }
  if (fingerprintDrifted) {
    alerts.push({
      code: 'FINGERPRINT_DRIFT',
      severity: 'CRITICAL',
      message: `TLS certificate SHA-256 fingerprint drifted from baseline`
    });
  }
  if (issuerDrifted) {
    alerts.push({
      code: 'ISSUER_DRIFT',
      severity: 'WARNING',
      message: `TLS certificate issuer changed ("${cfg.baselineIssuer}" -> "${issuer}")`
    });
  }

  const status = alerts.some((a) => a.severity === 'CRITICAL')
    ? 'CRITICAL'
    : (alerts.some((a) => a.severity === 'WARNING') ? 'WARNING' : 'OK');

  return {
    ok: status !== 'CRITICAL',
    host,
    port,
    servername,
    daysRemaining,
    validFrom: validFromRaw ? new Date(Date.parse(String(validFromRaw))).toISOString() : null,
    validTo: Number.isFinite(validToMs) ? new Date(validToMs).toISOString() : null,
    subject,
    issuer,
    fingerprintSha256,
    protocol,
    sanList,
    sanMatched,
    fingerprintDrifted,
    issuerDrifted,
    status,
    alerts,
    checkedAt: new Date(nowMs).toISOString()
  };
}

class SyntheticSentinelService {
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
    return path.join(this.resolveDataDir(), 'synthetic-flows.json');
  }

  /** @returns {{ flows: Array<any>, runs: Array<any> }} */
  _loadStore() {
    const p = this.getStoreFilePath();
    if (!fs.existsSync(p)) return { flows: [], runs: [] };
    try {
      const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
      return {
        flows: Array.isArray(parsed && parsed.flows) ? parsed.flows : [],
        runs: Array.isArray(parsed && parsed.runs) ? parsed.runs : []
      };
    } catch (e) {
      return { flows: [], runs: [] };
    }
  }

  /** @param {{ flows: Array<any>, runs: Array<any> }} state */
  _saveStore(state) {
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        flows: state.flows.slice(0, MAX_STORED_FLOWS),
        runs: state.runs.slice(0, MAX_RUN_HISTORY)
      }, null, 2) + '\n'
    );
  }

  /** Lists all saved synthetic multi-step API flows (with sensitive fields redacted). */
  listFlows() {
    return this._loadStore().flows;
  }

  /**
   * Fetches one saved flow by ID (or `null` if not found).
   * @param {string} id
   */
  getFlow(id) {
    const clean = String(id || '').trim();
    if (!clean) return null;
    return this._loadStore().flows.find((f) => f && f.id === clean) || null;
  }

  /**
   * Validates and atomically persists a 1..5-step synthetic flow definition.
   * Redacts literal sensitive headers and sensitive body fields before writing to disk.
   *
   * @param {{
   *   id?: string,
   *   name: string,
   *   projectId?: string | null,
   *   steps: Array<{
   *     name?: string,
   *     method?: string,
   *     url: string,
   *     headers?: Record<string, any>,
   *     body?: any,
   *     timeoutMs?: number,
   *     extract?: Record<string, string>,
   *     assert?: { status?: number | number[], maxLatencyMs?: number, jsonPathEquals?: Record<string, any>, bodyIncludes?: string | string[] }
   *   }>
   * }} input
   */
  saveFlow(input) {
    if (!input || typeof input !== 'object') {
      const err = /** @type {any} */ (new Error('saveFlow requires a flow definition object'));
      err.code = 'INVALID_FLOW';
      err.status = 400;
      throw err;
    }
    const name = String(input.name || '').trim().slice(0, 120);
    if (!name) {
      const err = /** @type {any} */ (new Error('Flow name is required'));
      err.code = 'INVALID_FLOW';
      err.status = 400;
      throw err;
    }
    if (!Array.isArray(input.steps) || input.steps.length < 1 || input.steps.length > MAX_STEPS_PER_FLOW) {
      const err = /** @type {any} */ (new Error(`Synthetic flow must contain 1..${MAX_STEPS_PER_FLOW} steps`));
      err.code = 'INVALID_FLOW';
      err.status = 400;
      throw err;
    }

    const sanitizedSteps = input.steps.map((raw, i) => {
      if (!raw || typeof raw !== 'object' || typeof raw.url !== 'string' || !raw.url.trim()) {
        const err = /** @type {any} */ (new Error(`Step #${i + 1} requires a valid url`));
        err.code = 'INVALID_STEP';
        err.status = 400;
        throw err;
      }
      const methodRaw = String(raw.method || 'GET').trim().toUpperCase();
      const method = ALLOWED_METHODS.has(methodRaw) ? methodRaw : 'GET';
      return {
        name: String(raw.name || `step-${i + 1}`).trim().slice(0, 80),
        method,
        url: raw.url.trim().slice(0, 2048),
        headers: redactSensitiveHeaders(raw.headers),
        ...(raw.body !== undefined ? { body: redactSensitiveBody(raw.body) } : {}),
        timeoutMs: Number.isFinite(Number(raw.timeoutMs))
          ? Math.max(200, Math.min(30000, Math.round(Number(raw.timeoutMs))))
          : DEFAULT_STEP_TIMEOUT_MS,
        ...(raw.extract && typeof raw.extract === 'object' ? { extract: { ...raw.extract } } : {}),
        ...(raw.assert && typeof raw.assert === 'object' ? { assert: { ...raw.assert } } : {})
      };
    });

    const store = this._loadStore();
    const id = input.id ? String(input.id).trim().slice(0, 80) : `syn_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const nowIso = new Date().toISOString();
    const idx = store.flows.findIndex((f) => f && f.id === id);

    const record = {
      id,
      name,
      projectId: input.projectId ? String(input.projectId).trim().slice(0, 128) : null,
      steps: sanitizedSteps,
      createdAt: idx !== -1 ? store.flows[idx].createdAt : nowIso,
      updatedAt: nowIso,
      lastRun: idx !== -1 ? (store.flows[idx].lastRun || null) : null
    };

    if (idx !== -1) store.flows[idx] = record;
    else store.flows.unshift(record);
    this._saveStore(store);

    return record;
  }

  /**
   * Deletes a saved flow by ID.
   * @param {string} id
   */
  deleteFlow(id) {
    const clean = String(id || '').trim();
    const store = this._loadStore();
    const before = store.flows.length;
    store.flows = store.flows.filter((f) => f && f.id !== clean);
    const deleted = store.flows.length < before;
    if (deleted) this._saveStore(store);
    return { deleted, id: clean };
  }

  /**
   * Executes a multi-step synthetic HTTP API flow sequentially with `{{var}}` interpolation,
   * dotted JSONPath extraction (ephemeral in-memory ONLY — never persisted!), SSRF validation
   * on EVERY step and redirect hop, and status/latency/JSON/body assertions.
   *
   * @param {string | Record<string, any>} flowOrId
   * @param {{
   *   fetchImpl?: ((url: string, init?: any) => Promise<any>) | null,
   *   dnsLookupImpl?: ((host: string) => Promise<any>) | null,
   *   allowLoopback?: boolean,
   *   persist?: boolean,
   *   initialVars?: Record<string, string>
   * }} [options]
   */
  async runFlow(flowOrId, options = {}) {
    const flow = typeof flowOrId === 'string' ? this.getFlow(flowOrId) : flowOrId;
    if (!flow || typeof flow !== 'object' || !Array.isArray(flow.steps) || flow.steps.length === 0) {
      const err = /** @type {any} */ (new Error(`Synthetic flow not found or invalid: ${typeof flowOrId === 'string' ? flowOrId : 'inline'}`));
      err.code = 'FLOW_NOT_FOUND';
      err.status = 404;
      throw err;
    }

    const allowLoopback = Boolean(options.allowLoopback);
    const fetcher = typeof options.fetchImpl === 'function' ? options.fetchImpl : globalThis.fetch;
    /** @type {Record<string, string>} */
    const runtimeVars = options.initialVars && typeof options.initialVars === 'object'
      ? { ...options.initialVars }
      : {};

    /** @type {Array<any>} */
    const stepResults = [];
    /** @type {string | null} */
    let failedStep = null;
    const totalStart = performance.now();

    for (let i = 0; i < Math.min(flow.steps.length, MAX_STEPS_PER_FLOW); i++) {
      const step = flow.steps[i];
      const stepName = String(step.name || `step-${i + 1}`);
      const method = ALLOWED_METHODS.has(String(step.method || 'GET').toUpperCase())
        ? String(step.method || 'GET').toUpperCase()
        : 'GET';
      const stepUrl = interpolateString(step.url, runtimeVars);
      const timeoutMs = Number.isFinite(Number(step.timeoutMs))
        ? Math.max(200, Math.min(30000, Math.round(Number(step.timeoutMs))))
        : DEFAULT_STEP_TIMEOUT_MS;

      /** @type {string[]} */
      const errors = [];
      /** @type {string[]} */
      const extractedKeys = [];
      const stepStart = performance.now();
      let status = 0;
      let responseText = '';

      try {
        // Validate initial step URL AND every redirect Location hop via ssrfGuard
        let currentUrl = stepUrl;
        await assertSyntheticUrlSafe(currentUrl, {
          allowLoopback,
          dnsLookupImpl: options.dnsLookupImpl || null
        });

        /** @type {Record<string, string>} */
        const reqHeaders = {};
        if (step.headers && typeof step.headers === 'object') {
          for (const [hk, hv] of Object.entries(step.headers)) {
            reqHeaders[hk] = interpolateString(String(hv ?? ''), runtimeVars);
          }
        }

        let bodyPayload;
        if (step.body !== undefined && step.body !== null && method !== 'GET' && method !== 'HEAD') {
          const interpolated = interpolateDeep(step.body, runtimeVars);
          if (typeof interpolated === 'string') {
            bodyPayload = interpolated;
          } else {
            bodyPayload = JSON.stringify(interpolated);
            if (!Object.keys(reqHeaders).some((k) => k.toLowerCase() === 'content-type')) {
              reqHeaders['Content-Type'] = 'application/json';
            }
          }
        }

        /** @type {any} */
        let res = null;
        for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeoutMs);
          if (timer.unref) timer.unref();
          try {
            res = await fetcher(currentUrl, {
              method: hop === 0 ? method : 'GET',
              headers: hop === 0 ? reqHeaders : {},
              body: hop === 0 ? bodyPayload : undefined,
              redirect: 'manual',
              signal: controller.signal
            });
          } finally {
            clearTimeout(timer);
          }

          status = Number(res && res.status) || 0;
          if (status >= 300 && status < 400) {
            const loc = res.headers && typeof res.headers.get === 'function'
              ? res.headers.get('location')
              : (res.headers && (res.headers.location || res.headers.Location));
            if (loc) {
              if (hop === MAX_REDIRECT_HOPS) {
                errors.push(`Too many redirects (> ${MAX_REDIRECT_HOPS})`);
                break;
              }
              const nextUrl = new URL(String(loc), currentUrl).toString();
              await assertSyntheticUrlSafe(nextUrl, {
                allowLoopback,
                dnsLookupImpl: options.dnsLookupImpl || null
              });
              currentUrl = nextUrl;
              continue;
            }
          }
          break;
        }

        if (res && typeof res.text === 'function') {
          responseText = await res.text();
        } else if (res && typeof res.json === 'function') {
          responseText = JSON.stringify(await res.json());
        }
      } catch (err) {
        const errCode = err && /** @type {any} */ (err).code ? `[${/** @type {any} */ (err).code}] ` : '';
        errors.push(`${errCode}${err && /** @type {any} */ (err).message ? /** @type {any} */ (err).message : String(err)}`);
      }

      const latencyMs = Number((performance.now() - stepStart).toFixed(2));
      let parsedJson = null;
      if (responseText && responseText.trim()) {
        try { parsedJson = JSON.parse(responseText); } catch (e) { parsedJson = null; }
      }

      // Extract ephemeral variables (NEVER persisted to disk or returned as values!)
      if (errors.length === 0 && step.extract && typeof step.extract === 'object') {
        for (const [varName, pathExpr] of Object.entries(step.extract)) {
          const val = resolveDottedPath(parsedJson, String(pathExpr));
          if (val === undefined || val === null) {
            errors.push(`Extract failed for "${varName}" at path "${pathExpr}"`);
          } else {
            runtimeVars[varName] = String(val);
            extractedKeys.push(varName);
          }
        }
      }

      // Evaluate assertions
      if (errors.length === 0 && step.assert && typeof step.assert === 'object') {
        const a = step.assert;
        if (a.status !== undefined) {
          const expectedList = Array.isArray(a.status) ? a.status.map(Number) : [Number(a.status)];
          if (!expectedList.includes(status)) {
            errors.push(`Expected HTTP status ${expectedList.join('|')}, got ${status}`);
          }
        }
        if (a.maxLatencyMs !== undefined && Number.isFinite(Number(a.maxLatencyMs)) && latencyMs > Number(a.maxLatencyMs)) {
          errors.push(`Latency ${latencyMs}ms exceeded maxLatencyMs ${a.maxLatencyMs}ms`);
        }
        if (a.jsonPathEquals && typeof a.jsonPathEquals === 'object') {
          for (const [jp, expectedVal] of Object.entries(a.jsonPathEquals)) {
            const actualVal = resolveDottedPath(parsedJson, jp);
            if (actualVal !== expectedVal) {
              errors.push(`Assertion jsonPathEquals["${jp}"]: expected ${JSON.stringify(expectedVal)}, got ${JSON.stringify(actualVal)}`);
            }
          }
        }
        if (a.bodyIncludes !== undefined) {
          const needles = Array.isArray(a.bodyIncludes) ? a.bodyIncludes : [a.bodyIncludes];
          for (const needle of needles) {
            if (typeof needle === 'string' && !responseText.includes(needle)) {
              errors.push(`Response body did not include "${needle.slice(0, 60)}"`);
            }
          }
        }
      } else if (errors.length === 0 && (status < 200 || status >= 400)) {
        errors.push(`Unexpected HTTP status ${status}`);
      }

      const stepOk = errors.length === 0;
      stepResults.push({
        name: stepName,
        method,
        url: stepUrl,
        status,
        latencyMs,
        ok: stepOk,
        errors,
        extractedKeys
      });

      if (!stepOk) {
        failedStep = stepName;
        break;
      }
    }

    const totalLatencyMs = Number((performance.now() - totalStart).toFixed(2));
    const report = {
      ok: failedStep === null,
      flowId: flow.id || null,
      flowName: String(flow.name || 'inline-flow'),
      totalLatencyMs,
      failedStep,
      steps: stepResults,
      checkedAt: new Date().toISOString()
    };

    const shouldPersist = options.persist !== undefined ? Boolean(options.persist) : Boolean(flow.id);
    if (shouldPersist && flow.id) {
      const store = this._loadStore();
      const idx = store.flows.findIndex((f) => f && f.id === flow.id);
      if (idx !== -1) {
        store.flows[idx].lastRun = report;
      }
      store.runs.unshift(report);
      this._saveStore(store);
    }

    return report;
  }

  /**
   * Wrapper on service instance for `checkTlsSentinel`.
   * @param {Parameters<typeof checkTlsSentinel>[0]} cfg
   * @param {Parameters<typeof checkTlsSentinel>[1]} [options]
   */
  checkTlsSentinel(cfg, options = {}) {
    return checkTlsSentinel(cfg, options);
  }
}

const defaultSyntheticSentinelService = new SyntheticSentinelService();

const exported = Object.assign(defaultSyntheticSentinelService, {
  SyntheticSentinelService,
  checkTlsSentinel,
  assertSyntheticUrlSafe,
  redactSensitiveHeaders,
  redactSensitiveBody,
  resolveDottedPath,
  matchSanHostname,
  listFlows: SyntheticSentinelService.prototype.listFlows.bind(defaultSyntheticSentinelService),
  getFlow: SyntheticSentinelService.prototype.getFlow.bind(defaultSyntheticSentinelService),
  saveFlow: SyntheticSentinelService.prototype.saveFlow.bind(defaultSyntheticSentinelService),
  deleteFlow: SyntheticSentinelService.prototype.deleteFlow.bind(defaultSyntheticSentinelService),
  runFlow: SyntheticSentinelService.prototype.runFlow.bind(defaultSyntheticSentinelService)
});

module.exports = exported;
