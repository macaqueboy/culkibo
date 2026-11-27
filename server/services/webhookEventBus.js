'use strict';

/**
 * Culkibo Zero-Dep Standard-Webhooks Outbound Event Bus, Dual-Secret Rotation & Anti-SSRF DLQ.
 *
 * Implements the `standard-webhooks` specification natively (0 external npm deps):
 *  - Secrets formatted as `whsec_<base64(32 random bytes)>`.
 *  - HMAC-SHA256 over `${msgId}.${timestampSec}.${rawBody}` using base64-decoded secret key.
 *  - Headers: `webhook-id`, `webhook-timestamp`, `webhook-signature` (`v1,<b64>` or space-delimited
 *    `v1,<sig1> v1,<sig2>` during zero-downtime dual-secret rotation grace windows).
 *  - Per-attempt URL + DNS-resolved IP SSRF verification via `ssrfGuard` (curing Portainer
 *    `CVE-2026-134756`) enforced on EVERY initial dispatch AND EVERY DLQ replay!
 *  - Atomic `0o600` persistence under isolated `CULKIBO_DATA_DIR/data/` for subscriptions
 *    (masked previews only on list!) and Dead-Letter Queue (bounded to 500 entries).
 */

const crypto = require('crypto');
const dns = require('dns');
const fs = require('fs');
const net = require('net');
const path = require('path');

const ssrfGuard = require('./ssrfGuard');

const MAX_DLQ_ENTRIES = 500;
const DEFAULT_TOLERANCE_SEC = 300;
const DEFAULT_TIMEOUT_MS = 5000;
const MAX_RETRY_ATTEMPTS = 5;

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
 * Generates a `standard-webhooks` compliant signing secret (`whsec_<base64(32B)>`).
 * @returns {string}
 */
function generateWebhookSecret() {
  return `whsec_${crypto.randomBytes(32).toString('base64')}`;
}

/**
 * Masks a `whsec_...` secret safely for list/status display.
 * @param {string | null | undefined} secret
 * @returns {string | null}
 */
function maskWebhookSecret(secret) {
  if (typeof secret !== 'string' || !secret) return null;
  if (secret.length <= 14) return 'whsec_***';
  return `${secret.slice(0, 10)}...${secret.slice(-4)}`;
}

/**
 * Decodes a `whsec_<base64>` (or raw base64) webhook secret into its HMAC key Buffer.
 * @param {string} rawSecret
 * @returns {Buffer}
 */
function decodeWebhookSecret(rawSecret) {
  const clean = String(rawSecret || '').trim();
  if (!clean) throw new Error('Webhook secret must be non-empty');
  const b64 = clean.startsWith('whsec_') ? clean.slice('whsec_'.length) : clean;
  const keyBuf = Buffer.from(b64, 'base64');
  if (keyBuf.length === 0) throw new Error('Invalid base64 webhook secret');
  return keyBuf;
}

/**
 * Computes jittered exponential retry backoff in milliseconds.
 * @param {number} attempt 1-based attempt number
 * @param {{ baseMs?: number, maxMs?: number, jitterRatio?: number, rng?: () => number }} [opts]
 * @returns {number}
 */
function computeBackoffMs(attempt, opts = {}) {
  const n = Math.max(1, Math.round(Number(attempt) || 1));
  const baseMs = Number.isFinite(Number(opts.baseMs)) && Number(opts.baseMs) > 0 ? Number(opts.baseMs) : 1000;
  const maxMs = Number.isFinite(Number(opts.maxMs)) && Number(opts.maxMs) >= baseMs ? Number(opts.maxMs) : 60000;
  const jitterRatio = Number.isFinite(Number(opts.jitterRatio))
    ? Math.max(0, Math.min(0.5, Number(opts.jitterRatio)))
    : 0.25;
  const rng = typeof opts.rng === 'function' ? opts.rng : Math.random;

  const exp = Math.min(maxMs, baseMs * (2 ** Math.min(10, n - 1)));
  const factor = 1 + ((rng() * 2 - 1) * jitterRatio);
  return Math.max(10, Math.round(Math.min(maxMs, exp * factor)));
}

/**
 * Signs an outbound payload according to the `standard-webhooks` specification:
 * HMAC-SHA256 over `${msgId}.${timestampSec}.${body}`, emitting `v1,<b64>` (or
 * space-delimited `v1,<sig1> v1,<sig2>` when `secondarySecret` is active during rotation).
 *
 * @param {{
 *   msgId: string,
 *   timestampSec: number | string,
 *   payload: string | object,
 *   secret: string,
 *   secondarySecret?: string | null
 * }} opts
 * @returns {{ 'webhook-id': string, 'webhook-timestamp': string, 'webhook-signature': string }}
 */
function signStandardWebhook(opts) {
  const msgId = String(opts.msgId || '').trim();
  if (!msgId) throw new Error('signStandardWebhook requires msgId');
  const ts = String(Math.floor(Number(opts.timestampSec)));
  if (!/^\d+$/.test(ts)) throw new Error('signStandardWebhook requires numeric timestampSec');
  const body = typeof opts.payload === 'string' ? opts.payload : JSON.stringify(opts.payload ?? {});
  const signingInput = `${msgId}.${ts}.${body}`;

  const sig1 = crypto.createHmac('sha256', decodeWebhookSecret(opts.secret))
    .update(signingInput, 'utf8')
    .digest('base64');

  let sigHeader = `v1,${sig1}`;
  if (opts.secondarySecret && String(opts.secondarySecret).trim()) {
    const sig2 = crypto.createHmac('sha256', decodeWebhookSecret(opts.secondarySecret))
      .update(signingInput, 'utf8')
      .digest('base64');
    sigHeader = `${sigHeader} v1,${sig2}`;
  }

  return {
    'webhook-id': msgId,
    'webhook-timestamp': ts,
    'webhook-signature': sigHeader
  };
}

/**
 * Reads a header case-insensitively from a headers object.
 * @param {Record<string, any>} headers
 * @param {string} targetLower
 * @returns {string}
 */
function readHeaderCI(headers, targetLower) {
  if (!headers || typeof headers !== 'object') return '';
  for (const [k, v] of Object.entries(headers)) {
    if (String(k).toLowerCase() === targetLower) {
      return Array.isArray(v) ? String(v[0] || '') : String(v ?? '');
    }
  }
  return '';
}

/**
 * Verifies a `standard-webhooks` signature header against one or more secrets (e.g. primary
 * + grace-window secondary) with replay-window enforcement and constant-time comparison.
 *
 * @param {string | object} payload
 * @param {Record<string, any>} headers
 * @param {string | string[]} secrets
 * @param {{ toleranceSec?: number, nowSec?: number }} [opts]
 */
function verifyStandardWebhookSignature(payload, headers, secrets, opts = {}) {
  const msgId = readHeaderCI(headers, 'webhook-id').trim();
  const tsRaw = readHeaderCI(headers, 'webhook-timestamp').trim();
  const sigHeader = readHeaderCI(headers, 'webhook-signature').trim();

  if (!msgId || !tsRaw || !sigHeader) {
    return { valid: false, reason: 'MISSING_HEADERS' };
  }
  if (!/^\d+$/.test(tsRaw)) {
    return { valid: false, reason: 'INVALID_TIMESTAMP' };
  }
  const timestampSec = Number(tsRaw);
  const toleranceSec = Number.isFinite(Number(opts.toleranceSec)) && Number(opts.toleranceSec) >= 0
    ? Number(opts.toleranceSec)
    : DEFAULT_TOLERANCE_SEC;
  const nowSec = Number.isFinite(Number(opts.nowSec))
    ? Math.floor(Number(opts.nowSec))
    : Math.floor(Date.now() / 1000);

  if (Math.abs(nowSec - timestampSec) > toleranceSec) {
    return { valid: false, reason: 'TIMESTAMP_OUT_OF_RANGE', timestampSec, nowSec, toleranceSec };
  }

  const secretList = (Array.isArray(secrets) ? secrets : [secrets])
    .filter((s) => typeof s === 'string' && s.trim().length > 0);
  if (secretList.length === 0) {
    return { valid: false, reason: 'MISSING_SECRET' };
  }

  const body = typeof payload === 'string' ? payload : JSON.stringify(payload ?? {});
  const signingInput = `${msgId}.${tsRaw}.${body}`;

  const candidateB64Sigs = sigHeader
    .split(/\s+/)
    .map((tok) => tok.trim())
    .filter((tok) => tok.startsWith('v1,'))
    .map((tok) => tok.slice(3))
    .filter(Boolean);

  if (candidateB64Sigs.length === 0) {
    return { valid: false, reason: 'UNSUPPORTED_SIGNATURE_VERSION' };
  }

  for (const rawSecret of secretList) {
    let keyBuf;
    try { keyBuf = decodeWebhookSecret(rawSecret); } catch (e) { continue; }
    const expectedDigest = crypto.createHmac('sha256', keyBuf).update(signingInput, 'utf8').digest();

    for (const candB64 of candidateB64Sigs) {
      let candBuf;
      try { candBuf = Buffer.from(candB64, 'base64'); } catch (e) { continue; }
      if (candBuf.length === expectedDigest.length && crypto.timingSafeEqual(expectedDigest, candBuf)) {
        return {
          valid: true,
          reason: 'OK',
          msgId,
          timestampSec,
          matchedVersion: 'v1'
        };
      }
    }
  }

  return { valid: false, reason: 'INVALID_SIGNATURE' };
}

/**
 * Validates a webhook destination URL AND all DNS-resolved IP addresses against SSRF
 * (`127.0.0.1`, `169.254.169.254`, RFC1918 `10/8`, `172.16/12`, `192.168/16`, `::1`, `fc00::/7`,
 * `fe80::/10`, IPv4-mapped IPv6, NAT64) on EVERY delivery and replay attempt.
 *
 * @param {string} rawUrl
 * @param {{
 *   allowLoopback?: boolean,
 *   dnsLookupImpl?: ((hostname: string) => Promise<any>) | null
 * }} [opts]
 * @returns {Promise<{ parsed: URL, resolvedIps: string[] }>}
 */
async function validateWebhookUrlWithDns(rawUrl, opts = {}) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim() || /[\r\n\0]/.test(rawUrl)) {
    const err = /** @type {any} */ (new Error('Invalid webhook URL'));
    err.code = 'INVALID_URL';
    throw err;
  }

  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch (e) {
    const err = /** @type {any} */ (new Error(`Malformed webhook URL: ${rawUrl.slice(0, 80)}`));
    err.code = 'INVALID_URL';
    throw err;
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    const err = /** @type {any} */ (new Error(`Unsupported webhook protocol: ${parsed.protocol}`));
    err.code = 'INVALID_URL';
    throw err;
  }
  if (parsed.username || parsed.password) {
    const err = /** @type {any} */ (new Error('Webhook URL must not embed credentials'));
    err.code = 'INVALID_URL';
    throw err;
  }

  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!host || BLOCKED_METADATA_HOSTS.has(host) || host.endsWith('.metadata.google.internal')) {
    const err = /** @type {any} */ (new Error(`Webhook URL blocked by SSRF metadata guard: ${host}`));
    err.code = 'SSRF_BLOCKED';
    throw err;
  }

  const allowLoopback = Boolean(opts.allowLoopback);

  /** @param {string} ip */
  const assertIpAllowed = (ip) => {
    const cleanIp = String(ip || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
    if (!cleanIp || ssrfGuard.isMetadataIp(cleanIp)) {
      const err = /** @type {any} */ (new Error(`Webhook resolved IP blocked by SSRF metadata guard: ${cleanIp}`));
      err.code = 'SSRF_BLOCKED';
      throw err;
    }
    if (ssrfGuard.isLoopbackIp(cleanIp)) {
      if (!allowLoopback) {
        const err = /** @type {any} */ (new Error(`Webhook loopback destination blocked by SSRF guard: ${cleanIp}`));
        err.code = 'SSRF_BLOCKED';
        throw err;
      }
      return;
    }
    if (ssrfGuard.isPrivateIp(cleanIp)) {
      const err = /** @type {any} */ (new Error(`Webhook private/reserved IP blocked by SSRF guard: ${cleanIp}`));
      err.code = 'SSRF_BLOCKED';
      throw err;
    }
  };

  if (net.isIP(host)) {
    assertIpAllowed(host);
    return { parsed, resolvedIps: [host] };
  }

  if (host === 'localhost' || host.endsWith('.localhost')) {
    if (!allowLoopback) {
      const err = /** @type {any} */ (new Error(`Webhook localhost destination blocked by SSRF guard: ${host}`));
      err.code = 'SSRF_BLOCKED';
      throw err;
    }
    return { parsed, resolvedIps: ['127.0.0.1'] };
  }

  // Resolve DNS on EVERY attempt (stops DNS rebinding / Portainer CVE-2026-134756)
  let lookupResult;
  try {
    lookupResult = typeof opts.dnsLookupImpl === 'function'
      ? await opts.dnsLookupImpl(host)
      : await dns.promises.lookup(host, { all: true });
  } catch (e) {
    const err = /** @type {any} */ (new Error(`DNS lookup failed for webhook host "${host}": ${e && /** @type {any} */ (e).message}`));
    err.code = 'DNS_LOOKUP_FAILED';
    throw err;
  }

  /** @type {string[]} */
  const ips = [];
  const rawList = Array.isArray(lookupResult) ? lookupResult : [lookupResult];
  for (const item of rawList) {
    if (typeof item === 'string' && item.trim()) ips.push(item.trim());
    else if (item && typeof item.address === 'string' && item.address.trim()) ips.push(item.address.trim());
  }
  if (ips.length === 0) {
    const err = /** @type {any} */ (new Error(`DNS lookup returned no addresses for "${host}"`));
    err.code = 'DNS_LOOKUP_FAILED';
    throw err;
  }
  for (const ip of ips) {
    assertIpAllowed(ip);
  }
  return { parsed, resolvedIps: ips };
}

/**
 * Strips raw secrets before returning a subscription summary to API/MCP callers.
 * @param {any} sub
 * @param {number} [nowMs]
 */
function toPublicSubscription(sub, nowMs = Date.now()) {
  const secondaryActive = Boolean(
    sub.secondarySecret &&
    sub.secondaryExpiresAt &&
    Date.parse(sub.secondaryExpiresAt) > nowMs
  );
  return {
    id: sub.id,
    url: sub.url,
    events: Array.isArray(sub.events) ? sub.events : ['*'],
    description: sub.description || '',
    enabled: sub.enabled !== false,
    secretPreview: maskWebhookSecret(sub.secret),
    hasSecondarySecret: secondaryActive,
    secondaryExpiresAt: secondaryActive ? sub.secondaryExpiresAt : null,
    createdAt: sub.createdAt,
    updatedAt: sub.updatedAt
  };
}

class WebhookEventBus {
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
  getSubscriptionsFilePath() {
    return path.join(this.resolveDataDir(), 'webhook-subscriptions.json');
  }

  /** @returns {string} */
  getDlqFilePath() {
    return path.join(this.resolveDataDir(), 'webhook-dlq.json');
  }

  /** @returns {Array<any>} */
  _loadSubscriptions() {
    const p = this.getSubscriptionsFilePath();
    if (!fs.existsSync(p)) return [];
    try {
      const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
      return parsed && Array.isArray(parsed.subscriptions) ? parsed.subscriptions : [];
    } catch (e) {
      return [];
    }
  }

  /** @param {Array<any>} subscriptions */
  _saveSubscriptions(subscriptions) {
    atomicWriteFileSync(
      this.getSubscriptionsFilePath(),
      JSON.stringify({ schemaVersion: 1, updatedAt: new Date().toISOString(), subscriptions }, null, 2) + '\n'
    );
  }

  /** @returns {Array<any>} */
  _loadDlq() {
    const p = this.getDlqFilePath();
    if (!fs.existsSync(p)) return [];
    try {
      const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
      return parsed && Array.isArray(parsed.entries) ? parsed.entries : [];
    } catch (e) {
      return [];
    }
  }

  /** @param {Array<any>} entries */
  _saveDlq(entries) {
    atomicWriteFileSync(
      this.getDlqFilePath(),
      JSON.stringify({
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        maxEntries: MAX_DLQ_ENTRIES,
        entries: entries.slice(0, MAX_DLQ_ENTRIES)
      }, null, 2) + '\n'
    );
  }

  /**
   * Creates or updates an outbound webhook subscription.
   * Returns raw `secret` ONCE when creating a new subscription; subsequent `listSubscriptions()`
   * ONLY expose masked previews.
   *
   * @param {{
   *   id?: string,
   *   url: string,
   *   events?: string[],
   *   description?: string,
   *   enabled?: boolean
   * }} opts
   */
  upsertSubscription(opts) {
    if (!opts || typeof opts !== 'object') {
      throw new Error('upsertSubscription requires an options object');
    }
    const rawUrl = String(opts.url || '').trim();
    let parsedUrl;
    try {
      parsedUrl = new URL(rawUrl);
    } catch (e) {
      const err = /** @type {any} */ (new Error(`Invalid subscription URL: "${rawUrl.slice(0, 80)}"`));
      err.code = 'INVALID_URL';
      err.status = 400;
      throw err;
    }
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      const err = /** @type {any} */ (new Error(`Unsupported webhook protocol: ${parsedUrl.protocol}`));
      err.code = 'INVALID_URL';
      err.status = 400;
      throw err;
    }

    const events = Array.isArray(opts.events) && opts.events.length > 0
      ? Array.from(new Set(opts.events.map((e) => String(e || '').trim()).filter(Boolean))).slice(0, 32)
      : ['*'];
    const description = String(opts.description || '').trim().slice(0, 200);
    const enabled = opts.enabled !== false;
    const nowIso = new Date().toISOString();

    const subs = this._loadSubscriptions();
    const targetId = opts.id ? String(opts.id).trim() : null;
    const idx = targetId ? subs.findIndex((s) => s.id === targetId) : -1;

    if (idx !== -1) {
      const existing = subs[idx];
      existing.url = rawUrl;
      existing.events = events;
      existing.description = description;
      existing.enabled = enabled;
      existing.updatedAt = nowIso;
      subs[idx] = existing;
      this._saveSubscriptions(subs);
      return {
        ok: true,
        created: false,
        subscription: toPublicSubscription(existing)
      };
    }

    const id = targetId || `whsub_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const secret = generateWebhookSecret();
    const createdSub = {
      id,
      url: rawUrl,
      events,
      description,
      enabled,
      secret,
      secondarySecret: null,
      secondaryExpiresAt: null,
      createdAt: nowIso,
      updatedAt: nowIso
    };
    subs.unshift(createdSub);
    this._saveSubscriptions(subs.slice(0, 100));

    return {
      ok: true,
      created: true,
      subscription: toPublicSubscription(createdSub),
      secret
    };
  }

  /**
   * Lists outbound subscriptions with masked secret previews (ZERO raw `whsec_` leaked).
   */
  listSubscriptions() {
    return this._loadSubscriptions().map((s) => toPublicSubscription(s));
  }

  /**
   * Zero-downtime dual-secret rotation: moves active secret into `secondarySecret`
   * for `graceSec` (default 24h) and mints a fresh `whsec_` primary secret.
   *
   * @param {string} subscriptionId
   * @param {{ graceSec?: number, nowMs?: number }} [opts]
   */
  rotateSecret(subscriptionId, opts = {}) {
    const subs = this._loadSubscriptions();
    const idx = subs.findIndex((s) => s.id === String(subscriptionId || '').trim());
    if (idx === -1) {
      const err = /** @type {any} */ (new Error(`Webhook subscription not found: ${subscriptionId}`));
      err.code = 'NOT_FOUND';
      err.status = 404;
      throw err;
    }
    const nowMs = Number.isFinite(Number(opts.nowMs)) ? Number(opts.nowMs) : Date.now();
    const graceSec = Number.isFinite(Number(opts.graceSec))
      ? Math.max(60, Math.min(7 * 86400, Math.round(Number(opts.graceSec))))
      : 86400;

    const sub = subs[idx];
    const nextSecret = generateWebhookSecret();
    sub.secondarySecret = sub.secret;
    sub.secondaryExpiresAt = new Date(nowMs + graceSec * 1000).toISOString();
    sub.secret = nextSecret;
    sub.updatedAt = new Date(nowMs).toISOString();
    subs[idx] = sub;
    this._saveSubscriptions(subs);

    return {
      ok: true,
      subscriptionId: sub.id,
      secret: nextSecret,
      secretPreview: maskWebhookSecret(nextSecret),
      secondaryExpiresAt: sub.secondaryExpiresAt,
      graceSec,
      subscription: toPublicSubscription(sub, nowMs)
    };
  }

  /**
   * Resolves the active primary secret + optional grace-window secondary secret for a subscription.
   * @param {any} sub
   * @param {number} [nowMs]
   */
  _activeSecretsForSub(sub, nowMs = Date.now()) {
    const secondary = (
      sub &&
      sub.secondarySecret &&
      sub.secondaryExpiresAt &&
      Date.parse(sub.secondaryExpiresAt) > nowMs
    )
      ? sub.secondarySecret
      : null;
    return {
      primary: sub.secret,
      secondary
    };
  }

  /**
   * Executes one signed HTTP POST delivery with per-attempt DNS-resolved SSRF verification.
   * @param {{
   *   url: string,
   *   msgId: string,
   *   body: string,
   *   primarySecret: string,
   *   secondarySecret?: string | null,
   *   fetchImpl?: ((url: string, init?: any) => Promise<any>) | null,
   *   dnsLookupImpl?: ((hostname: string) => Promise<any>) | null,
   *   allowLoopback?: boolean,
   *   timeoutMs?: number
   * }} opts
   */
  async _deliverOnce(opts) {
    // Re-validate URL + DNS resolution BEFORE EVERY SINGLE NETWORK CALL
    try {
      await validateWebhookUrlWithDns(opts.url, {
        allowLoopback: Boolean(opts.allowLoopback),
        dnsLookupImpl: opts.dnsLookupImpl || null
      });
    } catch (err) {
      return {
        ok: false,
        statusCode: 0,
        blockedBySsrf: /** @type {any} */ (err).code === 'SSRF_BLOCKED',
        errorCode: /** @type {any} */ (err).code || 'SSRF_BLOCKED',
        error: err && /** @type {any} */ (err).message ? /** @type {any} */ (err).message : 'SSRF blocked'
      };
    }

    const timestampSec = Math.floor(Date.now() / 1000);
    const sigHeaders = signStandardWebhook({
      msgId: opts.msgId,
      timestampSec,
      payload: opts.body,
      secret: opts.primarySecret,
      secondarySecret: opts.secondarySecret || null
    });

    const fetcher = typeof opts.fetchImpl === 'function' ? opts.fetchImpl : globalThis.fetch;
    const timeoutMs = Number.isFinite(Number(opts.timeoutMs)) && Number(opts.timeoutMs) >= 200
      ? Math.round(Number(opts.timeoutMs))
      : DEFAULT_TIMEOUT_MS;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    if (timer.unref) timer.unref();

    try {
      const res = await fetcher(opts.url, {
        method: 'POST',
        redirect: 'manual', // Never blindly follow redirects to internal hosts!
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'culkibo-standard-webhooks/1.2',
          ...sigHeaders
        },
        body: opts.body,
        signal: controller.signal
      });
      const statusCode = Number(res && res.status) || 0;
      const ok = statusCode >= 200 && statusCode < 300;
      return {
        ok,
        statusCode,
        blockedBySsrf: false,
        errorCode: ok ? null : `HTTP_${statusCode}`,
        error: ok ? null : `Webhook receiver responded HTTP ${statusCode}`
      };
    } catch (err) {
      return {
        ok: false,
        statusCode: 0,
        blockedBySsrf: false,
        errorCode: 'NETWORK_ERROR',
        error: err && /** @type {any} */ (err).message ? /** @type {any} */ (err).message : 'Webhook network error'
      };
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Dispatches an event to all matching enabled subscriptions (or a specific `subscriptionId`),
   * re-running DNS-resolved SSRF checks on every attempt and persisting exhausted failures to DLQ.
   *
   * @param {{
   *   eventType: string,
   *   data?: Record<string, any>,
   *   subscriptionId?: string | null,
   *   fetchImpl?: ((url: string, init?: any) => Promise<any>) | null,
   *   dnsLookupImpl?: ((hostname: string) => Promise<any>) | null,
   *   allowLoopback?: boolean,
   *   maxAttempts?: number,
   *   retryDelayMs?: number,
   *   timeoutMs?: number
   * }} opts
   */
  async dispatchEvent(opts) {
    const eventType = String((opts && opts.eventType) || '').trim();
    if (!eventType) throw new Error('dispatchEvent requires eventType');

    const maxAttempts = Math.max(1, Math.min(MAX_RETRY_ATTEMPTS, Math.round(Number(opts.maxAttempts) || 2)));
    const subs = this._loadSubscriptions().filter((s) => {
      if (s.enabled === false) return false;
      if (opts.subscriptionId && s.id !== opts.subscriptionId) return false;
      const evs = Array.isArray(s.events) ? s.events : ['*'];
      return evs.some((pat) => {
        if (pat === '*' || pat === eventType) return true;
        if (pat.endsWith('.*')) return eventType.startsWith(pat.slice(0, -1));
        return false;
      });
    });

    /** @type {Array<any>} */
    const deliveries = [];
    let deliveredCount = 0;
    let failedCount = 0;
    let blockedCount = 0;
    let dlqAddedCount = 0;

    for (const sub of subs) {
      const msgId = `msg_${crypto.randomBytes(12).toString('hex')}`;
      const body = JSON.stringify({
        id: msgId,
        type: eventType,
        timestamp: new Date().toISOString(),
        data: opts.data && typeof opts.data === 'object' ? opts.data : {}
      });
      const { primary, secondary } = this._activeSecretsForSub(sub);

      let attempts = 0;
      let lastResult = { ok: false, statusCode: 0, blockedBySsrf: false, errorCode: /** @type {string | null} */ ('UNKNOWN'), error: /** @type {string | null} */ ('Unknown error') };

      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        attempts = attempt;
        lastResult = await this._deliverOnce({
          url: sub.url,
          msgId,
          body,
          primarySecret: primary,
          secondarySecret: secondary,
          fetchImpl: opts.fetchImpl || null,
          dnsLookupImpl: opts.dnsLookupImpl || null,
          allowLoopback: Boolean(opts.allowLoopback),
          timeoutMs: opts.timeoutMs
        });
        if (lastResult.ok || lastResult.blockedBySsrf) break;
        if (attempt < maxAttempts && Number(opts.retryDelayMs) > 0) {
          const delay = computeBackoffMs(attempt, { baseMs: Number(opts.retryDelayMs), maxMs: 5000 });
          await new Promise((r) => setTimeout(r, delay));
        }
      }

      if (lastResult.ok) {
        deliveredCount++;
        deliveries.push({
          subscriptionId: sub.id,
          url: sub.url,
          msgId,
          ok: true,
          attempts,
          statusCode: lastResult.statusCode
        });
      } else {
        failedCount++;
        if (lastResult.blockedBySsrf) blockedCount++;

        const dlqId = `dlq_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
        const nowIso = new Date().toISOString();
        const dlqEntry = {
          id: dlqId,
          subscriptionId: sub.id,
          url: sub.url,
          eventType,
          msgId,
          payload: body,
          status: 'failed',
          attempts,
          lastStatusCode: lastResult.statusCode,
          errorCode: lastResult.errorCode,
          lastError: lastResult.error,
          createdAt: nowIso,
          lastAttemptAt: nowIso,
          replayedAt: null
        };
        const dlq = this._loadDlq();
        dlq.unshift(dlqEntry);
        this._saveDlq(dlq);
        dlqAddedCount++;

        deliveries.push({
          subscriptionId: sub.id,
          url: sub.url,
          msgId,
          dlqId,
          ok: false,
          blockedBySsrf: lastResult.blockedBySsrf,
          attempts,
          statusCode: lastResult.statusCode,
          errorCode: lastResult.errorCode,
          error: lastResult.error
        });
      }
    }

    return {
      ok: failedCount === 0,
      eventType,
      matchedSubscriptions: subs.length,
      deliveredCount,
      failedCount,
      blockedCount,
      dlqAddedCount,
      deliveries
    };
  }

  /**
   * Lists persisted DLQ entries (most recent first, optional status filter & limit).
   * @param {{ limit?: number, status?: string | null }} [opts]
   */
  listDlq(opts = {}) {
    const limit = Math.max(1, Math.min(MAX_DLQ_ENTRIES, Math.round(Number(opts.limit) || 50)));
    const statusFilter = opts.status ? String(opts.status).trim().toLowerCase() : null;
    const all = this._loadDlq();
    const filtered = statusFilter ? all.filter((e) => e && e.status === statusFilter) : all;
    return filtered.slice(0, limit);
  }

  /**
   * Deterministically replays one DLQ entry, re-running DNS-resolved SSRF verification
   * BEFORE any outbound HTTP attempt.
   *
   * @param {string} dlqId
   * @param {{
   *   fetchImpl?: ((url: string, init?: any) => Promise<any>) | null,
   *   dnsLookupImpl?: ((hostname: string) => Promise<any>) | null,
   *   allowLoopback?: boolean,
   *   timeoutMs?: number
   * }} [opts]
   */
  async replayDlqEntry(dlqId, opts = {}) {
    const dlq = this._loadDlq();
    const idx = dlq.findIndex((e) => e && e.id === String(dlqId || '').trim());
    if (idx === -1) {
      return { ok: false, replayed: false, errorCode: 'NOT_FOUND', error: `DLQ entry not found: ${dlqId}` };
    }
    const entry = dlq[idx];
    const subs = this._loadSubscriptions();
    const sub = subs.find((s) => s.id === entry.subscriptionId);
    const targetUrl = sub ? sub.url : entry.url;
    const secrets = sub ? this._activeSecretsForSub(sub) : { primary: generateWebhookSecret(), secondary: null };

    const res = await this._deliverOnce({
      url: targetUrl,
      msgId: entry.msgId,
      body: entry.payload,
      primarySecret: secrets.primary,
      secondarySecret: secrets.secondary,
      fetchImpl: opts.fetchImpl || null,
      dnsLookupImpl: opts.dnsLookupImpl || null,
      allowLoopback: Boolean(opts.allowLoopback),
      timeoutMs: opts.timeoutMs
    });

    const nowIso = new Date().toISOString();
    entry.attempts = (Number(entry.attempts) || 0) + 1;
    entry.lastAttemptAt = nowIso;
    entry.lastStatusCode = res.statusCode;
    entry.errorCode = res.errorCode;
    entry.lastError = res.error;
    if (res.ok) {
      entry.status = 'replayed';
      entry.replayedAt = nowIso;
    }
    dlq[idx] = entry;
    this._saveDlq(dlq);

    return {
      ok: res.ok,
      replayed: res.ok,
      dlqId: entry.id,
      blockedBySsrf: res.blockedBySsrf,
      statusCode: res.statusCode,
      errorCode: res.errorCode,
      error: res.error,
      entry
    };
  }

  /**
   * Replays all currently failed DLQ entries cleanly.
   * @param {{
   *   fetchImpl?: ((url: string, init?: any) => Promise<any>) | null,
   *   dnsLookupImpl?: ((hostname: string) => Promise<any>) | null,
   *   allowLoopback?: boolean,
   *   timeoutMs?: number
   * }} [opts]
   */
  async replayAllFailed(opts = {}) {
    const failedIds = this._loadDlq()
      .filter((e) => e && e.status === 'failed')
      .map((e) => e.id);
    /** @type {Array<any>} */
    const results = [];
    let succeeded = 0;
    let failed = 0;
    for (const id of failedIds) {
      const r = await this.replayDlqEntry(id, opts);
      results.push(r);
      if (r.ok) succeeded++;
      else failed++;
    }
    return {
      ok: failed === 0,
      total: failedIds.length,
      succeeded,
      failed,
      results
    };
  }
}

const defaultWebhookEventBus = new WebhookEventBus();

const exported = Object.assign(defaultWebhookEventBus, {
  WebhookEventBus,
  signStandardWebhook,
  verifyStandardWebhookSignature,
  generateWebhookSecret,
  computeBackoffMs,
  validateWebhookUrlWithDns,
  MAX_DLQ_ENTRIES,
  DEFAULT_TOLERANCE_SEC
});

module.exports = exported;
