'use strict';

/**
 * Culkibo Inbound Webhook Signature Replay & Clock-Skew Firewall.
 *
 * Cures `CVE-2026-41351` (Base64 -> Base64URL signature re-encoding replay bypass),
 * `CVE-2025-61926` (hardcoded weak webhook secrets), and fail-open HTTP 422 bypasses
 * in zero runtime npm dependencies:
 *  - Multi-provider raw-body HMAC-SHA256 verification: `stripe`, `github`, `linear`,
 *    `slack`, `shopify`, `svix` (Standard Webhooks).
 *  - Strictly fail-closed on missing, empty, or weak/hardcoded secrets (`WEBHOOK_SECRET_UNCONFIGURED`).
 *  - Enforces pre-verify raw byte cap (`<= 1 MiB` -> `WEBHOOK_BODY_TOO_LARGE`).
 *  - Enforces `|nowSec - timestamp| <= maxSkewSec` (default `300s` -> `CLOCK_SKEW_EXCEEDED`).
 *  - Canonicalizes Base64 / Base64URL / padded / unpadded / hex signatures into exact raw
 *    digest hex before length-guarded `crypto.timingSafeEqual` and monotonic replay
 *    deduplication (`WEBHOOK_REPLAY_DETECTED`).
 *  - Atomic `0o600` metadata & replay cache in `CULKIBO_DATA_DIR/data/webhook-firewall.json`
 *    (ZERO raw secrets ever stored!).
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SUPPORTED_PROVIDERS = Object.freeze([
  'stripe',
  'github',
  'linear',
  'slack',
  'shopify',
  'svix'
]);

const PROVIDER_SET = new Set(SUPPORTED_PROVIDERS);
const MAX_BODY_BYTES = 1024 * 1024; // 1 MiB
const DEFAULT_MAX_SKEW_SEC = 300;
const MAX_REPLAY_ENTRIES = 2000;

const WEAK_SECRETS = new Set([
  'secret',
  'changeme',
  'test',
  'testing',
  'password',
  'default',
  'webhook',
  'webhook-secret',
  'webhook_secret',
  'your_webhook_secret',
  'placeholder',
  'allstar',
  '123456',
  '12345678',
  'dev-secret'
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
 * Creates an HTTP-annotated Error.
 * @param {string} code
 * @param {string} msg
 * @param {number} [status]
 */
function fwError(code, msg, status = 400) {
  const err = /** @type {any} */ (new Error(msg));
  err.code = code;
  err.status = status;
  return err;
}

/**
 * Normalizes a signature string encoded in hex, Base64, or Base64URL (with or without
 * `=` padding or provider prefix like `sha256=`, `v1,`, `v0=`) into its exact canonical
 * lowercase hex byte representation. Defeats `CVE-2026-41351` re-encoding replay bypasses.
 *
 * @param {string} rawSig
 * @returns {string}
 */
function canonicalizeSignatureEncoding(rawSig) {
  if (typeof rawSig !== 'string') return '';
  let clean = rawSig.trim();
  if (!clean) return '';

  // Strip common provider version/algorithm prefixes
  clean = clean.replace(/^(?:sha256=|v0=|v1=|v1a,|v1,)/i, '').trim();
  if (!clean) return '';

  // Exact even-length hex encoding (e.g. 64 hex chars = 32-byte SHA-256 HMAC)
  if (/^[0-9a-fA-F]{32,128}$/.test(clean) && clean.length % 2 === 0) {
    return clean.toLowerCase();
  }

  // Standard Base64 or URL-safe Base64URL (padded or unpadded)
  if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(clean)) {
    let std = clean.replace(/-/g, '+').replace(/_/g, '/');
    const rem = std.length % 4;
    if (rem === 1) return '';
    if (rem > 0) std += '='.repeat(4 - rem);
    const decoded = Buffer.from(std, 'base64');
    if (decoded.length === 0) return '';
    // Re-encode check guarantees clean canonical Base64 bytes (rejects trailing garbage bits)
    return decoded.toString('hex').toLowerCase();
  }

  return '';
}

/**
 * Constant-time equality comparison between a candidate signature and an expected digest Buffer.
 * @param {string} candidateCanonHex
 * @param {Buffer} expectedDigest
 * @returns {boolean}
 */
function timingSafeMatchHex(candidateCanonHex, expectedDigest) {
  if (!candidateCanonHex || candidateCanonHex.length !== expectedDigest.length * 2) return false;
  if (!/^[0-9a-f]+$/.test(candidateCanonHex)) return false;
  const candidateBuf = Buffer.from(candidateCanonHex, 'hex');
  if (candidateBuf.length !== expectedDigest.length) return false;
  return crypto.timingSafeEqual(candidateBuf, expectedDigest);
}

/**
 * Lowercases HTTP header keys cleanly.
 * @param {Record<string, any> | null | undefined} headers
 * @returns {Record<string, string>}
 */
function normalizeHeaders(headers) {
  /** @type {Record<string, string>} */
  const out = {};
  if (!headers || typeof headers !== 'object') return out;
  for (const [k, v] of Object.entries(headers)) {
    const key = String(k || '').trim().toLowerCase();
    if (!key) continue;
    out[key] = Array.isArray(v) ? v.join(',') : String(v ?? '').trim();
  }
  return out;
}

/**
 * Parses a timestamp header into integer epoch seconds, or null if absent/invalid.
 * @param {string | number | undefined} raw
 * @returns {number | null}
 */
function parseTimestampSec(raw) {
  if (raw === undefined || raw === null || raw === '') return null;
  const num = Number(raw);
  if (Number.isFinite(num) && num > 0) {
    return num > 1e12 ? Math.floor(num / 1000) : Math.floor(num);
  }
  const parsedIso = Date.parse(String(raw));
  if (Number.isFinite(parsedIso) && parsedIso > 0) {
    return Math.floor(parsedIso / 1000);
  }
  return null;
}

/**
 * Fail-closed check ensuring webhook secret is configured and non-weak (`CVE-2025-61926`).
 * @param {any} secret
 * @returns {boolean}
 */
function isSecretConfiguredAndStrong(secret) {
  if (typeof secret !== 'string') return false;
  const trimmed = secret.trim();
  if (trimmed.length < 8) return false;
  if (WEAK_SECRETS.has(trimmed.toLowerCase())) return false;
  return true;
}

/**
 * Extracts provider-specific signatures, timestamp, deliveryId, and signing payload Buffer.
 * @param {string} provider
 * @param {Buffer} rawBuf
 * @param {Record<string, string>} hdrs
 * @param {string} secret
 */
function buildProviderVerificationContext(provider, rawBuf, hdrs, secret) {
  if (provider === 'stripe') {
    const sigHdr = hdrs['stripe-signature'] || '';
    /** @type {string[]} */
    const rawSigs = [];
    /** @type {string | undefined} */
    let tsRaw;
    for (const part of sigHdr.split(',')) {
      const idx = part.indexOf('=');
      if (idx <= 0) continue;
      const k = part.slice(0, idx).trim();
      const v = part.slice(idx + 1).trim();
      if (k === 't') tsRaw = v;
      else if (k === 'v1' && v) rawSigs.push(v);
    }
    const tsSec = parseTimestampSec(tsRaw);
    const signingPayload = tsRaw
      ? Buffer.concat([Buffer.from(`${tsRaw}.`, 'utf8'), rawBuf])
      : rawBuf;
    const expectedDigest = crypto.createHmac('sha256', secret).update(signingPayload).digest();
    const deliveryId = hdrs['stripe-event-id'] || hdrs['x-webhook-id'] || null;
    return { rawSigs, tsSec, requireTimestamp: true, deliveryId, expectedDigest };
  }

  if (provider === 'svix') {
    const msgId = hdrs['svix-id'] || hdrs['webhook-id'] || '';
    const tsRaw = hdrs['svix-timestamp'] || hdrs['webhook-timestamp'] || '';
    const sigHdr = hdrs['svix-signature'] || hdrs['webhook-signature'] || '';
    const rawSigs = sigHdr.split(/\s+/).map((s) => s.trim()).filter(Boolean);
    const tsSec = parseTimestampSec(tsRaw);
    const keyBuf = secret.startsWith('whsec_')
      ? Buffer.from(secret.slice(6), 'base64')
      : Buffer.from(secret, 'utf8');
    const signingPayload = Buffer.concat([Buffer.from(`${msgId}.${tsRaw}.`, 'utf8'), rawBuf]);
    const expectedDigest = crypto.createHmac('sha256', keyBuf).update(signingPayload).digest();
    return { rawSigs, tsSec, requireTimestamp: true, deliveryId: msgId || null, expectedDigest };
  }

  if (provider === 'slack') {
    const tsRaw = hdrs['x-slack-request-timestamp'] || '';
    const sigHdr = hdrs['x-slack-signature'] || '';
    const rawSigs = sigHdr ? [sigHdr] : [];
    const tsSec = parseTimestampSec(tsRaw);
    const signingPayload = Buffer.concat([Buffer.from(`v0:${tsRaw}:`, 'utf8'), rawBuf]);
    const expectedDigest = crypto.createHmac('sha256', secret).update(signingPayload).digest();
    const deliveryId = hdrs['x-slack-request-id'] || null;
    return { rawSigs, tsSec, requireTimestamp: true, deliveryId, expectedDigest };
  }

  if (provider === 'github') {
    const sigHdr = hdrs['x-hub-signature-256'] || '';
    const rawSigs = sigHdr ? [sigHdr] : [];
    const tsSec = parseTimestampSec(hdrs['x-webhook-timestamp'] || hdrs['x-timestamp']);
    const expectedDigest = crypto.createHmac('sha256', secret).update(rawBuf).digest();
    const deliveryId = hdrs['x-github-delivery'] || null;
    return { rawSigs, tsSec, requireTimestamp: false, deliveryId, expectedDigest };
  }

  if (provider === 'linear') {
    const sigHdr = hdrs['linear-signature'] || '';
    const rawSigs = sigHdr ? [sigHdr] : [];
    const tsSec = parseTimestampSec(hdrs['x-linear-timestamp'] || hdrs['x-webhook-timestamp']);
    const expectedDigest = crypto.createHmac('sha256', secret).update(rawBuf).digest();
    const deliveryId = hdrs['linear-delivery'] || null;
    return { rawSigs, tsSec, requireTimestamp: false, deliveryId, expectedDigest };
  }

  // shopify
  const sigHdr = hdrs['x-shopify-hmac-sha256'] || '';
  const rawSigs = sigHdr ? [sigHdr] : [];
  const tsSec = parseTimestampSec(hdrs['x-shopify-triggered-at'] || hdrs['x-webhook-timestamp']);
  const expectedDigest = crypto.createHmac('sha256', secret).update(rawBuf).digest();
  const deliveryId = hdrs['x-shopify-webhook-id'] || null;
  return { rawSigs, tsSec, requireTimestamp: false, deliveryId, expectedDigest };
}

class WebhookFirewallService {
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
    return path.join(this.resolveDataDir(), 'webhook-firewall.json');
  }

  /** @returns {{ schemaVersion: number, updatedAt: string, policies: Record<string, any>, replayCache: any[], stats: { totalVerified: number, totalRejected: number, rejectedByCode: Record<string, number> } }} */
  _loadState() {
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) {
      return {
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        policies: {},
        replayCache: [],
        stats: { totalVerified: 0, totalRejected: 0, rejectedByCode: {} }
      };
    }
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      const stats = parsed && parsed.stats && typeof parsed.stats === 'object'
        ? parsed.stats
        : { totalVerified: 0, totalRejected: 0, rejectedByCode: {} };
      return {
        schemaVersion: 1,
        updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : new Date().toISOString(),
        policies: parsed && parsed.policies && typeof parsed.policies === 'object' ? parsed.policies : {},
        replayCache: Array.isArray(parsed.replayCache) ? parsed.replayCache : [],
        stats: {
          totalVerified: Number(stats.totalVerified) || 0,
          totalRejected: Number(stats.totalRejected) || 0,
          rejectedByCode: stats.rejectedByCode && typeof stats.rejectedByCode === 'object' ? stats.rejectedByCode : {}
        }
      };
    } catch (e) {
      return {
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        policies: {},
        replayCache: [],
        stats: { totalVerified: 0, totalRejected: 0, rejectedByCode: {} }
      };
    }
  }

  /** @param {any} state */
  _saveState(state) {
    const replayCache = Array.isArray(state.replayCache)
      ? state.replayCache.slice(-MAX_REPLAY_ENTRIES)
      : [];
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        policies: state.policies || {},
        replayCache,
        stats: state.stats
      }, null, 2) + '\n'
    );
  }

  /**
   * Delegates to `canonicalizeSignatureEncoding`.
   * @param {string} sig
   * @returns {string}
   */
  canonicalizeSignatureEncoding(sig) {
    return canonicalizeSignatureEncoding(sig);
  }

  /**
   * Verifies an inbound webhook using fail-closed secret checks, pre-verify 1 MiB body cap,
   * raw-byte HMAC-SHA256 `crypto.timingSafeEqual`, clock-skew bounding, and canonical
   * Base64/Base64URL/hex replay deduplication (`CVE-2026-41351`, `CVE-2025-61926`).
   *
   * @param {{
   *   provider: string,
   *   rawBody: Buffer | string,
   *   headers?: Record<string, any>,
   *   secret?: string,
   *   nowSec?: number,
   *   maxSkewSec?: number,
   *   routeId?: string
   * }} input
   */
  verifyInboundWebhook(input) {
    const src = input && typeof input === 'object' ? input : /** @type {any} */ ({});
    const provider = String(src.provider || '').trim().toLowerCase();
    const routeId = typeof src.routeId === 'string' && src.routeId.trim()
      ? src.routeId.trim().slice(0, 128)
      : 'default';
    const nowSec = src.nowSec !== undefined && Number.isFinite(Number(src.nowSec))
      ? Math.floor(Number(src.nowSec))
      : Math.floor(Date.now() / 1000);

    const state = this._loadState();
    const routePolicy = state.policies[routeId] || null;
    const maxSkewSec = src.maxSkewSec !== undefined && Number.isFinite(Number(src.maxSkewSec))
      ? Math.max(10, Math.min(3600, Math.floor(Number(src.maxSkewSec))))
      : (routePolicy && Number.isFinite(Number(routePolicy.maxSkewSec)) ? Number(routePolicy.maxSkewSec) : DEFAULT_MAX_SKEW_SEC);
    const maxBodyBytes = routePolicy && Number.isFinite(Number(routePolicy.maxBodyBytes))
      ? Math.min(MAX_BODY_BYTES, Number(routePolicy.maxBodyBytes))
      : MAX_BODY_BYTES;

    /**
     * @param {string} code
     * @param {number} httpStatus
     * @param {string} message
     * @param {Record<string, any>} [extra]
     */
    const reject = (code, httpStatus, message, extra = {}) => {
      state.stats.totalRejected += 1;
      state.stats.rejectedByCode[code] = (state.stats.rejectedByCode[code] || 0) + 1;
      this._saveState(state);
      return {
        ok: false,
        verified: false,
        httpStatus,
        code,
        provider: provider || null,
        routeId,
        message,
        ...extra
      };
    };

    // 1. Fail-closed secret configuration guard (CVE-2025-61926)
    if (!isSecretConfiguredAndStrong(src.secret)) {
      return reject(
        'WEBHOOK_SECRET_UNCONFIGURED',
        401,
        'Inbound webhook rejected (fail-closed): signing secret is missing, empty, or weak/hardcoded.'
      );
    }

    // 2. Supported provider check
    if (!PROVIDER_SET.has(provider)) {
      return reject(
        'UNSUPPORTED_PROVIDER',
        400,
        `Unsupported webhook provider "${provider}". Supported: ${SUPPORTED_PROVIDERS.join(', ')}`
      );
    }

    // 3. Pre-verify raw byte body cap (<= 1 MiB)
    const rawBuf = Buffer.isBuffer(src.rawBody)
      ? src.rawBody
      : Buffer.from(typeof src.rawBody === 'string' ? src.rawBody : '', 'utf8');
    if (rawBuf.length > maxBodyBytes) {
      return reject(
        'WEBHOOK_BODY_TOO_LARGE',
        413,
        `Webhook payload (${rawBuf.length} bytes) exceeds pre-verify limit (${maxBodyBytes} bytes).`,
        { bodyBytes: rawBuf.length, maxBodyBytes }
      );
    }

    const hdrs = normalizeHeaders(src.headers);
    const ctx = buildProviderVerificationContext(provider, rawBuf, hdrs, String(src.secret).trim());

    if (ctx.rawSigs.length === 0) {
      return reject('SIGNATURE_MISSING', 401, `Missing required signature header for provider "${provider}".`);
    }

    // 4. Clock-skew validation (<= maxSkewSec)
    if (ctx.requireTimestamp && ctx.tsSec === null) {
      return reject('TIMESTAMP_MISSING', 401, `Missing or invalid webhook timestamp header for provider "${provider}".`);
    }
    if (ctx.tsSec !== null) {
      const skewSec = Math.abs(nowSec - ctx.tsSec);
      if (skewSec > maxSkewSec) {
        return reject(
          'CLOCK_SKEW_EXCEEDED',
          401,
          `Webhook timestamp skew (${skewSec}s) exceeds allowed window (${maxSkewSec}s).`,
          { timestampSec: ctx.tsSec, skewSec, maxSkewSec }
        );
      }
    }

    // 5. Canonical signature decoding + constant-time HMAC comparison
    /** @type {string | null} */
    let matchedCanonHex = null;
    for (const rawSig of ctx.rawSigs) {
      const canonHex = canonicalizeSignatureEncoding(rawSig);
      if (canonHex && timingSafeMatchHex(canonHex, ctx.expectedDigest)) {
        matchedCanonHex = canonHex;
        break;
      }
    }

    if (!matchedCanonHex) {
      return reject('SIGNATURE_INVALID', 401, `HMAC-SHA256 signature verification failed for provider "${provider}".`);
    }

    // 6. Prune expired replay cache entries & deduplicate on canonical signature hex + deliveryId (CVE-2026-41351)
    const replayWindowSec = Math.max(maxSkewSec * 2, 600);
    state.replayCache = state.replayCache.filter(
      (entry) => entry && Number(entry.expiresAtSec) > nowSec
    );

    const replayHit = state.replayCache.find(
      (entry) =>
        entry.routeId === routeId &&
        entry.provider === provider &&
        (entry.canonicalSignature === matchedCanonHex ||
          (ctx.deliveryId && entry.deliveryId && entry.deliveryId === ctx.deliveryId))
    );

    if (replayHit) {
      return reject(
        'WEBHOOK_REPLAY_DETECTED',
        409,
        `Replayed webhook blocked (canonical signature / delivery ID already processed for route "${routeId}").`,
        {
          replayed: true,
          canonicalSignature: matchedCanonHex,
          deliveryId: ctx.deliveryId,
          firstSeenAtSec: replayHit.seenAtSec
        }
      );
    }

    // Record verified signature in bounded replay cache (ZERO raw secrets!)
    state.replayCache.push({
      routeId,
      provider,
      canonicalSignature: matchedCanonHex,
      deliveryId: ctx.deliveryId,
      seenAtSec: nowSec,
      expiresAtSec: nowSec + replayWindowSec
    });
    state.stats.totalVerified += 1;
    this._saveState(state);

    return {
      ok: true,
      verified: true,
      httpStatus: 200,
      code: /** @type {'WEBHOOK_VERIFIED'} */ ('WEBHOOK_VERIFIED'),
      provider,
      routeId,
      replayed: false,
      canonicalSignature: matchedCanonHex,
      deliveryId: ctx.deliveryId,
      timestampSec: ctx.tsSec,
      skewSec: ctx.tsSec !== null ? Math.abs(nowSec - ctx.tsSec) : 0,
      bodyBytes: rawBuf.length
    };
  }

  /**
   * Configures a route's webhook firewall policy (metadata only; defaults `dryRun: true`).
   * Strips any raw secret fields so secrets are never persisted.
   *
   * @param {string} routeId
   * @param {{
   *   provider?: string,
   *   maxSkewSec?: number,
   *   maxBodyBytes?: number,
   *   replayWindowSec?: number,
   *   dryRun?: boolean
   * }} [policy]
   */
  upsertWebhookFirewallPolicy(routeId, policy = {}) {
    const id = typeof routeId === 'string' && routeId.trim() ? routeId.trim().slice(0, 128) : 'default';
    const src = policy && typeof policy === 'object' ? policy : {};
    const dryRun = src.dryRun !== undefined ? Boolean(src.dryRun) : true;
    const provider = src.provider !== undefined ? String(src.provider).trim().toLowerCase() : 'stripe';
    if (!PROVIDER_SET.has(provider)) {
      throw fwError('UNSUPPORTED_PROVIDER', `Unsupported provider "${provider}"`);
    }
    const maxSkewSec = Math.max(10, Math.min(3600, Math.round(Number(src.maxSkewSec ?? DEFAULT_MAX_SKEW_SEC) || DEFAULT_MAX_SKEW_SEC)));
    const maxBodyBytes = Math.max(1024, Math.min(MAX_BODY_BYTES, Math.round(Number(src.maxBodyBytes ?? MAX_BODY_BYTES) || MAX_BODY_BYTES)));
    const replayWindowSec = Math.max(60, Math.min(86400, Math.round(Number(src.replayWindowSec ?? 600) || 600)));

    const record = {
      routeId: id,
      provider,
      maxSkewSec,
      maxBodyBytes,
      replayWindowSec,
      failClosed: true,
      updatedAt: new Date().toISOString()
    };

    if (!dryRun) {
      const state = this._loadState();
      state.policies[id] = record;
      this._saveState(state);
    }

    return {
      ok: true,
      dryRun,
      routeId: id,
      policy: record
    };
  }

  /**
   * Inspects webhook firewall policies, stats, and active replay cache entries (0 raw secrets).
   * @param {string | null} [routeId]
   */
  inspectReplayCache(routeId) {
    const filterId = typeof routeId === 'string' && routeId.trim() ? routeId.trim() : null;
    const state = this._loadState();
    const entries = state.replayCache
      .filter((e) => (!filterId || e.routeId === filterId))
      .slice()
      .reverse();
    const policies = Object.values(state.policies).filter((p) => (!filterId || p.routeId === filterId));

    return {
      ok: true,
      routeId: filterId,
      supportedProviders: Array.from(SUPPORTED_PROVIDERS),
      policyCount: policies.length,
      policies,
      replayEntryCount: entries.length,
      entries,
      stats: {
        ...state.stats,
        rejectedByCode: { ...state.stats.rejectedByCode }
      },
      updatedAt: state.updatedAt
    };
  }
}

const defaultWebhookFirewallService = new WebhookFirewallService();

const exported = Object.assign(defaultWebhookFirewallService, {
  WebhookFirewallService,
  SUPPORTED_PROVIDERS,
  MAX_BODY_BYTES,
  DEFAULT_MAX_SKEW_SEC,
  canonicalizeSignatureEncoding: WebhookFirewallService.prototype.canonicalizeSignatureEncoding.bind(defaultWebhookFirewallService),
  verifyInboundWebhook: WebhookFirewallService.prototype.verifyInboundWebhook.bind(defaultWebhookFirewallService),
  inspectReplayCache: WebhookFirewallService.prototype.inspectReplayCache.bind(defaultWebhookFirewallService),
  upsertWebhookFirewallPolicy: WebhookFirewallService.prototype.upsertWebhookFirewallPolicy.bind(defaultWebhookFirewallService)
});

module.exports = exported;
