'use strict';

/**
 * Culkibo Zero-Dep Caddy Edge Bot-Shield & Anubis-Inspired SHA-256 Hashcash PoW Gate.
 *
 * Guarantees:
 *  - 0 external npm dependencies, 0 extra Caddy plugins (compiles to 100% native Caddy v2.11 JSON).
 *  - Blocks common vulnerability scanner paths (`/.env*`, `/.git*`, `/wp-config.php`, `/xmlrpc.php`,
 *    path traversal `..`), SQLi/XSS query patterns, and abusive AI-scraper User-Agents with HTTP 403.
 *  - Optional Anubis-style SHA-256 Proof-of-Work browser challenge (`difficulty` clamped 1..6, default 4)
 *    with replay-proof single-use challenges, strict IP+UA binding, and constant-time HMAC-SHA256
 *    `ckb_shield` clearance cookie (24h TTL).
 */

const crypto = require('crypto');

const COOKIE_NAME = 'ckb_shield';
const DEFAULT_DIFFICULTY = 4;
const MIN_DIFFICULTY = 1;
const MAX_DIFFICULTY = 6;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;       // 5 minutes
const CLEARANCE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const MAX_ACTIVE_CHALLENGES = 4096;
const MAX_USED_CHALLENGES = 8192;

const DEFAULT_BLOCKED_PATHS = Object.freeze([
  '/.env',
  '/.env.*',
  '/.git/*',
  '/.git',
  '/.svn/*',
  '/.hg/*',
  '/.htaccess',
  '/.htpasswd',
  '/.DS_Store',
  '/.aws/*',
  '/.ssh/*',
  '/wp-config.php',
  '/wp-config.php*',
  '/wp-login.php',
  '/xmlrpc.php',
  '/phpmyadmin*',
  '/cgi-bin/*',
  '/backup.sql*',
  '/dump.sql*'
]);

const DEFAULT_AI_SCRAPER_UAS = Object.freeze([
  'Bytespider',
  'GPTBot',
  'CCBot',
  'ClaudeBot',
  'anthropic-ai',
  'Amazonbot',
  'Diffbot',
  'Omgilibot',
  'FacebookBot',
  'Meta-ExternalAgent',
  'Applebot-Extended',
  'PerplexityBot',
  'Scrapy',
  'sqlmap',
  'nikto',
  'masscan',
  'zgrab',
  'Nuclei'
]);

/**
 * Clamps PoW hex-zero difficulty to `[1..6]`.
 * @param {any} raw
 * @returns {number}
 */
function clampDifficulty(raw) {
  const n = Number(raw);
  if (!Number.isFinite(n)) return DEFAULT_DIFFICULTY;
  return Math.max(MIN_DIFFICULTY, Math.min(MAX_DIFFICULTY, Math.round(n)));
}

/**
 * Escapes HTML special characters safely.
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Escapes regex metacharacters for safe Caddy RE2 compilation.
 * @param {string} literal
 * @returns {string}
 */
function escapeRe2(literal) {
  return String(literal || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Normalizes client IP strings (unwraps IPv4-mapped IPv6 `::ffff:` prefix).
 * @param {string | null | undefined} ip
 * @returns {string}
 */
function normalizeClientIp(ip) {
  let clean = String(ip || '').trim().toLowerCase();
  if (clean.includes(',')) clean = clean.split(',')[0].trim();
  if (clean.startsWith('::ffff:')) clean = clean.slice(7);
  return clean.slice(0, 64);
}

/**
 * Verifies a SHA-256 Hashcash Proof-of-Work solution (`SHA-256("${salt}:${nonce}")` has
 * `difficulty` leading lowercase hex zeros, clamped `1..6`).
 *
 * @param {string} salt
 * @param {string | number} nonce
 * @param {number} [difficulty]
 * @returns {{ valid: boolean, hash: string, difficulty: number }}
 */
function verifyPowSolution(salt, nonce, difficulty = DEFAULT_DIFFICULTY) {
  const diff = clampDifficulty(difficulty);
  const s = String(salt || '');
  const n = String(nonce ?? '');
  if (!s || !n || s.length > 256 || n.length > 128) {
    return { valid: false, hash: '', difficulty: diff };
  }
  const hash = crypto.createHash('sha256').update(`${s}:${n}`, 'utf8').digest('hex');
  const prefix = '0'.repeat(diff);
  return {
    valid: hash.startsWith(prefix),
    hash,
    difficulty: diff
  };
}

/**
 * Extracts `ckb_shield` cookie value from either a bare token or a full `Cookie:` header.
 * @param {string | null | undefined} raw
 * @returns {string}
 */
function extractShieldCookieValue(raw) {
  if (typeof raw !== 'string') return '';
  const trimmed = raw.trim();
  if (!trimmed) return '';
  if (trimmed.includes('=') && (trimmed.includes(';') || trimmed.startsWith(`${COOKIE_NAME}=`))) {
    for (const part of trimmed.split(';')) {
      const idx = part.indexOf('=');
      if (idx === -1) continue;
      const k = part.slice(0, idx).trim();
      if (k === COOKIE_NAME) return part.slice(idx + 1).trim();
    }
    return '';
  }
  return trimmed;
}

/**
 * Validates `returnUrl` against open-redirect and `javascript:`/`data:` injection.
 * Only relative paths starting with single `/` are allowed.
 * @param {string | null | undefined} raw
 * @returns {string}
 */
function sanitizeReturnUrl(raw) {
  const s = String(raw || '/').trim();
  if (!s.startsWith('/') || s.startsWith('//') || s.startsWith('/\\') || /[\r\n\0]/.test(s)) {
    return '/';
  }
  if (/^\/(?:javascript|data|vbscript):/i.test(s)) return '/';
  return s.slice(0, 1024);
}

class EdgeShieldService {
  /**
   * @param {{
   *   hmacSecret?: string | Buffer | null,
   *   challengeTtlMs?: number,
   *   clearanceTtlMs?: number
   * }} [opts]
   */
  constructor(opts = {}) {
    this._hmacKey = opts.hmacSecret
      ? (Buffer.isBuffer(opts.hmacSecret) ? opts.hmacSecret : Buffer.from(String(opts.hmacSecret), 'utf8'))
      : crypto.randomBytes(32);
    this.challengeTtlMs = Number.isFinite(Number(opts.challengeTtlMs)) && Number(opts.challengeTtlMs) >= 1000
      ? Math.round(Number(opts.challengeTtlMs))
      : CHALLENGE_TTL_MS;
    this.clearanceTtlMs = Number.isFinite(Number(opts.clearanceTtlMs)) && Number(opts.clearanceTtlMs) >= 1000
      ? Math.round(Number(opts.clearanceTtlMs))
      : CLEARANCE_TTL_MS;

    /** @type {Map<string, { challengeId: string, salt: string, difficulty: number, domain: string, binding: string, expiresAtMs: number }>} */
    this._activeChallenges = new Map();
    /** @type {Set<string>} */
    this._usedChallenges = new Set();
  }

  /**
   * Computes a compact IP + User-Agent HMAC binding fingerprint.
   * @param {string} ip
   * @param {string} userAgent
   * @returns {string}
   */
  _computeBinding(ip, userAgent) {
    const normIp = normalizeClientIp(ip);
    const normUa = String(userAgent || '').trim().slice(0, 512);
    return crypto
      .createHmac('sha256', this._hmacKey)
      .update(`bind|${normIp}|${normUa}`, 'utf8')
      .digest('hex')
      .slice(0, 24);
  }

  /** Removes expired active challenges to keep memory strictly bounded. */
  _pruneExpiredChallenges() {
    const now = Date.now();
    for (const [id, ch] of this._activeChallenges.entries()) {
      if (ch.expiresAtMs <= now) {
        this._activeChallenges.delete(id);
      }
    }
  }

  /**
   * Marks a challengeId as consumed in a bounded FIFO set (replay protection).
   * @param {string} challengeId
   */
  _markUsed(challengeId) {
    if (this._usedChallenges.size >= MAX_USED_CHALLENGES) {
      const oldest = this._usedChallenges.values().next().value;
      if (oldest) this._usedChallenges.delete(oldest);
    }
    this._usedChallenges.add(challengeId);
  }

  /**
   * Issues a new SHA-256 Proof-of-Work challenge bound to `(ip, userAgent, domain)`.
   * @param {{ ip?: string, userAgent?: string, domain?: string, difficulty?: number }} [opts]
   */
  issueChallenge(opts = {}) {
    this._pruneExpiredChallenges();
    if (this._activeChallenges.size >= MAX_ACTIVE_CHALLENGES) {
      const oldest = this._activeChallenges.keys().next().value;
      if (oldest) this._activeChallenges.delete(oldest);
    }

    const difficulty = clampDifficulty(opts.difficulty);
    const domain = String(opts.domain || '').trim().toLowerCase().slice(0, 253);
    const challengeId = crypto.randomBytes(12).toString('hex');
    const salt = crypto.randomBytes(16).toString('hex');
    const expiresAtMs = Date.now() + this.challengeTtlMs;
    const binding = this._computeBinding(opts.ip || '', opts.userAgent || '');

    this._activeChallenges.set(challengeId, {
      challengeId,
      salt,
      difficulty,
      domain,
      binding,
      expiresAtMs
    });

    return {
      challengeId,
      salt,
      difficulty,
      expiresAt: new Date(expiresAtMs).toISOString(),
      expiresAtMs,
      algorithm: 'sha256',
      domain
    };
  }

  /**
   * Verifies a client's SHA-256 PoW solution, prevents replay, checks expiry & IP+UA binding,
   * and mints a signed HMAC-SHA256 `ckb_shield` clearance cookie (`24h` TTL).
   *
   * @param {{
   *   challengeId: string,
   *   salt: string,
   *   nonce: string | number,
   *   ip?: string,
   *   userAgent?: string,
   *   domain?: string,
   *   secureCookie?: boolean
   * }} opts
   */
  verifySolution(opts) {
    if (!opts || typeof opts !== 'object') {
      return { valid: false, reason: 'INVALID_REQUEST' };
    }
    const challengeId = String(opts.challengeId || '').trim();
    const salt = String(opts.salt || '').trim();
    const nonce = opts.nonce !== undefined && opts.nonce !== null ? String(opts.nonce).trim() : '';

    if (!challengeId || !salt || !nonce) {
      return { valid: false, reason: 'MISSING_FIELDS' };
    }
    if (this._usedChallenges.has(challengeId)) {
      return { valid: false, reason: 'CHALLENGE_REPLAYED' };
    }

    const challenge = this._activeChallenges.get(challengeId);
    if (!challenge) {
      return { valid: false, reason: 'CHALLENGE_NOT_FOUND' };
    }
    if (Date.now() > challenge.expiresAtMs) {
      this._activeChallenges.delete(challengeId);
      return { valid: false, reason: 'CHALLENGE_EXPIRED' };
    }
    if (salt !== challenge.salt) {
      return { valid: false, reason: 'SALT_MISMATCH' };
    }

    const reqDomain = String(opts.domain || '').trim().toLowerCase();
    if (challenge.domain && reqDomain && reqDomain !== challenge.domain) {
      return { valid: false, reason: 'DOMAIN_MISMATCH' };
    }

    const expectedBinding = Buffer.from(challenge.binding, 'utf8');
    const actualBinding = Buffer.from(this._computeBinding(opts.ip || '', opts.userAgent || ''), 'utf8');
    if (expectedBinding.length !== actualBinding.length || !crypto.timingSafeEqual(expectedBinding, actualBinding)) {
      return { valid: false, reason: 'CLIENT_BINDING_MISMATCH' };
    }

    const pow = verifyPowSolution(challenge.salt, nonce, challenge.difficulty);
    if (!pow.valid) {
      return { valid: false, reason: 'INVALID_POW', hash: pow.hash, difficulty: challenge.difficulty };
    }

    // Consume challenge atomically so replay is impossible
    this._activeChallenges.delete(challengeId);
    this._markUsed(challengeId);

    const clearanceExpiresAtMs = Date.now() + this.clearanceTtlMs;
    const cookiePayload = Buffer.from(JSON.stringify({
      v: 1,
      b: challenge.binding,
      d: challenge.domain,
      exp: clearanceExpiresAtMs,
      jti: challengeId
    }), 'utf8').toString('base64url');
    const cookieSig = crypto.createHmac('sha256', this._hmacKey).update(cookiePayload).digest('base64url');
    const cookie = `${cookiePayload}.${cookieSig}`;
    const maxAgeSec = Math.max(1, Math.floor(this.clearanceTtlMs / 1000));
    const secureFlag = opts.secureCookie === false ? '' : '; Secure';
    const cookieHeader = `${COOKIE_NAME}=${cookie}; Path=/; Max-Age=${maxAgeSec}; HttpOnly; SameSite=Lax${secureFlag}`;

    return {
      valid: true,
      hash: pow.hash,
      difficulty: challenge.difficulty,
      challengeId,
      cookieName: COOKIE_NAME,
      cookie,
      cookieHeader,
      expiresAt: new Date(clearanceExpiresAtMs).toISOString(),
      expiresAtMs: clearanceExpiresAtMs
    };
  }

  /**
   * Verifies a `ckb_shield` clearance cookie (constant-time HMAC + expiry + IP+UA binding).
   * @param {string | null | undefined} cookieValue
   * @param {{ ip?: string, userAgent?: string, domain?: string }} [ctx]
   * @returns {{ valid: boolean, reason: string, domain?: string, expiresAt?: string, challengeId?: string }}
   */
  verifyClearanceCookie(cookieValue, ctx = {}) {
    const token = extractShieldCookieValue(cookieValue);
    if (!token || !token.includes('.')) {
      return { valid: false, reason: 'MISSING_OR_MALFORMED_COOKIE' };
    }
    const parts = token.split('.');
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      return { valid: false, reason: 'MALFORMED_COOKIE' };
    }
    const [payloadB64, sigB64] = parts;
    const expectedSig = crypto.createHmac('sha256', this._hmacKey).update(payloadB64).digest();
    let providedSig;
    try {
      providedSig = Buffer.from(sigB64, 'base64url');
    } catch (e) {
      return { valid: false, reason: 'INVALID_SIGNATURE' };
    }
    if (providedSig.length !== expectedSig.length || !crypto.timingSafeEqual(expectedSig, providedSig)) {
      return { valid: false, reason: 'INVALID_SIGNATURE' };
    }

    let payload;
    try {
      payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    } catch (e) {
      return { valid: false, reason: 'INVALID_PAYLOAD' };
    }
    if (!payload || typeof payload.exp !== 'number' || typeof payload.b !== 'string') {
      return { valid: false, reason: 'INVALID_PAYLOAD' };
    }
    if (Date.now() > payload.exp) {
      return { valid: false, reason: 'COOKIE_EXPIRED' };
    }

    const expectedBinding = Buffer.from(payload.b, 'utf8');
    const actualBinding = Buffer.from(this._computeBinding(ctx.ip || '', ctx.userAgent || ''), 'utf8');
    if (expectedBinding.length !== actualBinding.length || !crypto.timingSafeEqual(expectedBinding, actualBinding)) {
      return { valid: false, reason: 'CLIENT_BINDING_MISMATCH' };
    }

    const reqDomain = String(ctx.domain || '').trim().toLowerCase();
    if (payload.d && reqDomain && reqDomain !== payload.d) {
      return { valid: false, reason: 'DOMAIN_MISMATCH' };
    }

    return {
      valid: true,
      reason: 'OK',
      domain: payload.d || '',
      expiresAt: new Date(payload.exp).toISOString(),
      challengeId: typeof payload.jti === 'string' ? payload.jti : undefined
    };
  }

  /**
   * Renders a self-contained dark-mode HTML challenge page that solves the SHA-256 PoW puzzle
   * via browser `crypto.subtle.digest('SHA-256', ...)` in <500ms and POSTs to `/api/edge-shield/verify`.
   *
   * @param {{ challengeId: string, salt: string, difficulty: number, domain?: string }} challenge
   * @param {string} [returnUrl]
   * @returns {string}
   */
  renderChallengeHtml(challenge, returnUrl = '/') {
    const safeReturn = sanitizeReturnUrl(returnUrl);
    const safeDomain = escapeHtml(challenge.domain || 'protected origin');
    const cfgJson = JSON.stringify({
      challengeId: String(challenge.challengeId || ''),
      salt: String(challenge.salt || ''),
      difficulty: clampDifficulty(challenge.difficulty),
      domain: String(challenge.domain || ''),
      returnUrl: safeReturn
    }).replace(/</g, '\\u003c');

    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex,nofollow" />
  <title>Culkibo Edge Shield — Verifying Browser</title>
  <style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; display: grid; place-items: center;
      background: #090b10; color: #e4e8f1;
      font-family: ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
    }
    .card {
      width: min(440px, 92vw); padding: 28px; border-radius: 14px;
      background: #111520; border: 1px solid #1f2738;
      box-shadow: 0 24px 60px rgba(0, 0, 0, 0.55);
    }
    .badge {
      display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px;
      border-radius: 999px; font-size: 12px; font-weight: 600;
      background: rgba(16, 185, 129, 0.14); color: #34d399; border: 1px solid rgba(52, 211, 153, 0.3);
    }
    h1 { margin: 14px 0 8px; font-size: 19px; font-weight: 600; letter-spacing: -0.01em; }
    p { margin: 0 0 18px; font-size: 13.5px; line-height: 1.5; color: #94a3b8; }
    .bar { height: 6px; width: 100%; border-radius: 999px; background: #1e293b; overflow: hidden; }
    .fill { height: 100%; width: 22%; background: linear-gradient(90deg, #10b981, #38bdf8); transition: width 160ms ease; }
    .meta {
      margin-top: 14px; display: flex; justify-content: space-between;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px; color: #64748b;
    }
    .err { margin-top: 14px; color: #f87171; font-size: 12.5px; display: none; }
  </style>
</head>
<body>
  <main class="card">
    <span class="badge">Culkibo Edge Shield · SHA-256 PoW</span>
    <h1>Checking browser integrity…</h1>
    <p>Protecting <strong>${safeDomain}</strong> against automated scrapers and credential-stuffing bots. You will be redirected automatically in a moment.</p>
    <div class="bar"><div id="fill" class="fill"></div></div>
    <div class="meta">
      <span id="status">Solving challenge…</span>
      <span id="rate">0 H/s</span>
    </div>
    <div id="err" class="err"></div>
  </main>
  <script>
  (async function () {
    const cfg = ${cfgJson};
    const fillEl = document.getElementById('fill');
    const statusEl = document.getElementById('status');
    const rateEl = document.getElementById('rate');
    const errEl = document.getElementById('err');
    const targetPrefix = '0'.repeat(cfg.difficulty);
    const enc = new TextEncoder();
    const t0 = performance.now();

    function toHex(buf) {
      const bytes = new Uint8Array(buf);
      let out = '';
      for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
      return out;
    }

    try {
      let nonce = 0;
      while (true) {
        for (let batch = 0; batch < 512; batch++, nonce++) {
          const digest = await crypto.subtle.digest('SHA-256', enc.encode(cfg.salt + ':' + nonce));
          const hex = toHex(digest);
          if (hex.startsWith(targetPrefix)) {
            fillEl.style.width = '88%';
            statusEl.textContent = 'Verifying clearance…';
            const res = await fetch('/api/edge-shield/verify', {
              method: 'POST',
              credentials: 'same-origin',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                challengeId: cfg.challengeId,
                salt: cfg.salt,
                nonce: String(nonce),
                domain: cfg.domain
              })
            });
            if (!res.ok) throw new Error('Verification failed (' + res.status + ')');
            const body = await res.json();
            if (!body || !body.valid) throw new Error((body && body.reason) || 'Invalid clearance');
            fillEl.style.width = '100%';
            statusEl.textContent = 'Verified. Redirecting…';
            window.location.replace(cfg.returnUrl || '/');
            return;
          }
        }
        const elapsed = Math.max(0.01, (performance.now() - t0) / 1000);
        rateEl.textContent = Math.round(nonce / elapsed).toLocaleString() + ' H/s';
        fillEl.style.width = Math.min(82, 22 + Math.round((nonce / 65536) * 60)) + '%';
        await new Promise((r) => setTimeout(r, 0));
      }
    } catch (e) {
      errEl.style.display = 'block';
      errEl.textContent = 'Challenge error: ' + (e && e.message ? e.message : String(e));
      statusEl.textContent = 'Failed';
    }
  })();
  </script>
</body>
</html>`;
  }

  /**
   * Compiles native Caddy v2.11 JSON subroutes (ZERO extra Caddy plugins!) blocking:
   *  1. Scanner paths (`/.env*`, `/.git*`, `/wp-config.php`, `/xmlrpc.php`) & path traversal (`..`)
   *  2. SQLi & XSS query patterns (`vars_regexp` on `{http.request.uri.query}`)
   *  3. Configurable abusive AI-scraper & vulnerability-scanner User-Agents
   *  4. Optional Anubis-style Hashcash PoW challenge redirect when `powChallenge: true`
   *
   * Accepts either a full domain config (`{ domain, edgeShield: {...} }`) or a direct
   * `edgeShield` config object (`{ enabled, powChallenge, difficulty, ... }`).
   *
   * @param {any} domainOrConfig
   * @returns {Array<any>}
   */
  compileCaddyShieldRoutes(domainOrConfig) {
    if (!domainOrConfig || typeof domainOrConfig !== 'object') return [];
    const cfg = (domainOrConfig.edgeShield && typeof domainOrConfig.edgeShield === 'object')
      ? domainOrConfig.edgeShield
      : domainOrConfig;

    if (cfg.enabled === false) return [];

    /** @type {Array<any>} */
    const subroutes = [];

    // 1. Sensitive path & traversal blocker (HTTP 403)
    const rawPaths = Array.isArray(cfg.blockedPaths) && cfg.blockedPaths.length > 0
      ? cfg.blockedPaths
      : Array.from(DEFAULT_BLOCKED_PATHS);
    const blockedPaths = rawPaths
      .map((p) => String(p || '').trim())
      .filter((p) => p.startsWith('/') && p.length <= 256 && !/[\s\r\n\0]/.test(p))
      .slice(0, 64);

    /** @type {Array<any>} */
    const pathMatchers = [];
    if (blockedPaths.length > 0) {
      pathMatchers.push({ path: blockedPaths });
    }
    pathMatchers.push({
      path_regexp: {
        name: 'ck_shield_traversal',
        pattern: '(?:\\.\\.|%2e%2e|%252e%252e)'
      }
    });

    subroutes.push({
      match: pathMatchers,
      handle: [
        {
          handler: 'static_response',
          status_code: '403',
          headers: {
            'Content-Type': ['text/plain; charset=utf-8'],
            'Cache-Control': ['no-store'],
            'X-Culkibo-Shield': ['blocked-path']
          },
          body: 'Forbidden (Culkibo Edge Shield: scanner path blocked).'
        }
      ],
      terminal: true
    });

    // 2. SQLi / XSS query-string rule (native Caddy `vars_regexp`, zero plugins)
    if (cfg.blockSqliXss !== false) {
      subroutes.push({
        match: [
          {
            vars_regexp: {
              '{http.request.uri.query}': {
                name: 'ck_shield_sqli_xss',
                pattern: '(?i)(?:union(?:%20|\\+|\\s)+select|select(?:%20|\\+|\\s)+.+(?:%20|\\+|\\s)+from|<script|%3cscript|javascript:|onerror=|onload=|benchmark\\s*\\(|sleep\\s*\\()'
              }
            }
          }
        ],
        handle: [
          {
            handler: 'static_response',
            status_code: '403',
            headers: {
              'Content-Type': ['text/plain; charset=utf-8'],
              'Cache-Control': ['no-store'],
              'X-Culkibo-Shield': ['blocked-sqli-xss']
            },
            body: 'Forbidden (Culkibo Edge Shield: suspicious query payload blocked).'
          }
        ],
        terminal: true
      });
    }

    // 3. Abusive AI-scraper & automated scanner User-Agent blocker
    const blockAiScrapers = cfg.blockAiScrapers !== false;
    const rawUas = Array.isArray(cfg.blockedUserAgents) && cfg.blockedUserAgents.length > 0
      ? cfg.blockedUserAgents
      : (blockAiScrapers ? Array.from(DEFAULT_AI_SCRAPER_UAS) : []);
    const cleanUas = rawUas
      .map((u) => String(u || '').trim())
      .filter((u) => u.length >= 2 && u.length <= 64 && !/[\r\n\0]/.test(u))
      .slice(0, 64);

    if (cleanUas.length > 0) {
      const uaPattern = `(?i)(?:${cleanUas.map((u) => escapeRe2(u)).join('|')})`;
      subroutes.push({
        match: [
          {
            header_regexp: {
              'User-Agent': {
                name: 'ck_shield_ua',
                pattern: uaPattern
              }
            }
          }
        ],
        handle: [
          {
            handler: 'static_response',
            status_code: '403',
            headers: {
              'Content-Type': ['text/plain; charset=utf-8'],
              'Cache-Control': ['no-store'],
              'X-Culkibo-Shield': ['blocked-ua']
            },
            body: 'Forbidden (Culkibo Edge Shield: automated scraper blocked).'
          }
        ],
        terminal: true
      });
    }

    // 4. Optional Anubis-style SHA-256 PoW gate redirect when `powChallenge: true`
    if (cfg.powChallenge === true) {
      const rawEndpoint = typeof cfg.challengeEndpoint === 'string' && cfg.challengeEndpoint.trim().startsWith('/')
        ? cfg.challengeEndpoint.trim().replace(/[\r\n\0]/g, '').slice(0, 256)
        : '/api/edge-shield/challenge';
      const difficulty = clampDifficulty(cfg.difficulty);
      subroutes.push({
        match: [
          {
            not: [
              {
                header_regexp: {
                  Cookie: {
                    name: 'ck_shield_cookie',
                    pattern: `(?:^|;\\s*)${COOKIE_NAME}=[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+`
                  }
                }
              },
              {
                path: ['/api/edge-shield/*', '/.well-known/*']
              }
            ]
          }
        ],
        handle: [
          {
            handler: 'static_response',
            status_code: '302',
            headers: {
              Location: [`${rawEndpoint}?domain={http.request.host}&return={http.request.uri}&difficulty=${difficulty}`],
              'Cache-Control': ['no-store'],
              'X-Culkibo-Shield': ['pow-challenge']
            }
          }
        ],
        terminal: true
      });
    }

    return subroutes;
  }

  /**
   * Returns a live Edge Shield status summary across optional domain configurations.
   * @param {Array<any> | null | undefined} [domains]
   */
  getStatus(domains) {
    this._pruneExpiredChallenges();
    const list = Array.isArray(domains) ? domains : [];
    let enabledCount = 0;
    let powEnabledCount = 0;
    for (const d of list) {
      if (d && d.edgeShield && d.edgeShield.enabled) {
        enabledCount++;
        if (d.edgeShield.powChallenge) powEnabledCount++;
      }
    }
    return {
      enabledCount,
      powEnabledCount,
      blockedPathRules: DEFAULT_BLOCKED_PATHS.length,
      blockedUaPatterns: DEFAULT_AI_SCRAPER_UAS.length,
      activeChallenges: this._activeChallenges.size,
      usedChallengesCount: this._usedChallenges.size,
      defaultDifficulty: DEFAULT_DIFFICULTY,
      cookieName: COOKIE_NAME,
      algorithm: 'sha256',
      zeroCaddyPlugins: true
    };
  }
}

const defaultEdgeShieldService = new EdgeShieldService();

const exported = Object.assign(defaultEdgeShieldService, {
  EdgeShieldService,
  DEFAULT_BLOCKED_PATHS,
  DEFAULT_AI_SCRAPER_UAS,
  verifyPowSolution,
  COOKIE_NAME,
  DEFAULT_DIFFICULTY,
  MIN_DIFFICULTY,
  MAX_DIFFICULTY,
  CHALLENGE_TTL_MS,
  CLEARANCE_TTL_MS
});

module.exports = exported;
