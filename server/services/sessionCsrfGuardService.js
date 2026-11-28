'use strict';

/**
 * Culkibo Session Cookie, Go 1.25 Fetch-Metadata (`Sec-Fetch-Site`) CSRF & OAuth 2.1 PKCE Guard.
 *
 * Implements Go 1.25 `http.CrossOriginProtection` zero-token CSRF defense, RFC 6265bis
 * `__Host-` / `HttpOnly` / `Secure` / `SameSite` cookie hygiene, and OAuth 2.1 mandatory
 * `PKCE S256` verification curing `CVE-2026-26247` (Gitea `< 1.25.5` PKCE bypass) in zero deps:
 *  - Atomic `0o600` metadata-only audit history in `CULKIBO_DATA_DIR/data/session-csrf-guard.json`
 *    (**NEVER persists or echoes raw cookie values, PKCE verifiers, or OAuth state strings!**).
 *  - Flags `CSRF_CROSS_ORIGIN_BLOCKED`, `CSRF_ORIGIN_MISMATCH`, `COOKIE_MISSING_HTTPONLY`,
 *    `COOKIE_MISSING_SECURE`, `COOKIE_MISSING_SAMESITE`, `COOKIE_HOST_PREFIX_INVALID`,
 *    `PKCE_PLAIN_FORBIDDEN`, `PKCE_VERIFIER_MISMATCH`, and `OAUTH_STATE_WEAK`.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MAX_STORED_AUDITS = 500;
const SAFE_HTTP_METHODS = Object.freeze(['GET', 'HEAD', 'OPTIONS']);
const SAFE_METHOD_SET = new Set(SAFE_HTTP_METHODS);
const WEAK_STATES = new Set(['test', 'state', '1234', '123456', 'abcdef', 'csrf', 'oauth', 'default', 'placeholder']);

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
 * Parses a `Set-Cookie` header string into cookie name & security attributes ONLY
 * (immediately discarding the cookie secret value so it is never stored or returned).
 *
 * @param {string | Record<string, any>} input
 */
function parseCookieAttributesOnly(input) {
  if (input && typeof input === 'object' && !Array.isArray(input)) {
    if (typeof input.setCookieHeader === 'string') {
      return parseCookieAttributesOnly(input.setCookieHeader);
    }
    return {
      name: String(input.name || 'session').trim(),
      httpOnly: Boolean(input.httpOnly),
      secure: Boolean(input.secure),
      sameSite: typeof input.sameSite === 'string' ? input.sameSite.trim() : null,
      path: typeof input.path === 'string' ? input.path.trim() : null,
      domain: typeof input.domain === 'string' && input.domain.trim() ? input.domain.trim() : null
    };
  }

  const raw = typeof input === 'string' ? input.trim() : '';
  const segments = raw.split(';').map((s) => s.trim()).filter(Boolean);
  const firstPair = segments[0] || '';
  const eqIdx = firstPair.indexOf('=');
  const name = (eqIdx >= 0 ? firstPair.slice(0, eqIdx) : firstPair).trim() || 'session';

  let httpOnly = false;
  let secure = false;
  /** @type {string | null} */
  let sameSite = null;
  /** @type {string | null} */
  let cookiePath = null;
  /** @type {string | null} */
  let domain = null;

  for (let i = 1; i < segments.length; i += 1) {
    const seg = segments[i];
    const idx = seg.indexOf('=');
    const attrName = (idx >= 0 ? seg.slice(0, idx) : seg).trim().toLowerCase();
    const attrVal = idx >= 0 ? seg.slice(idx + 1).trim() : '';
    if (attrName === 'httponly') httpOnly = true;
    else if (attrName === 'secure') secure = true;
    else if (attrName === 'samesite') sameSite = attrVal;
    else if (attrName === 'path') cookiePath = attrVal;
    else if (attrName === 'domain') domain = attrVal || null;
  }

  return { name, httpOnly, secure, sameSite, path: cookiePath, domain };
}

class SessionCsrfGuardService {
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
    return path.join(this.resolveDataDir(), 'session-csrf-guard.json');
  }

  /** @returns {any[]} */
  _loadAudits() {
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) return [];
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      return parsed && Array.isArray(parsed.audits) ? parsed.audits : [];
    } catch (e) {
      return [];
    }
  }

  /** @param {any[]} audits */
  _saveAudits(audits) {
    const trimmed = audits.slice(-MAX_STORED_AUDITS);
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({ schemaVersion: 1, updatedAt: new Date().toISOString(), audits: trimmed }, null, 2) + '\n'
    );
  }

  /**
   * Go 1.25 `CrossOriginProtection` zero-token CSRF check using `Sec-Fetch-Site` Fetch Metadata
   * with `Origin` vs `Host` fallback.
   *
   * @param {{
   *   method?: string,
   *   secFetchSite?: string | null,
   *   origin?: string | null,
   *   host?: string | null,
   *   trustedOrigins?: string[],
   *   persist?: boolean
   * }} [input]
   */
  evaluateCrossOriginRequest(input = {}) {
    const src = input && typeof input === 'object' ? input : {};
    const method = String(src.method || 'POST').trim().toUpperCase();
    const secFetchSite = typeof src.secFetchSite === 'string' && src.secFetchSite.trim()
      ? src.secFetchSite.trim().toLowerCase()
      : null;
    const origin = typeof src.origin === 'string' && src.origin.trim() ? src.origin.trim().replace(/\/$/, '') : null;
    const host = typeof src.host === 'string' && src.host.trim() ? src.host.trim().toLowerCase() : null;
    const trustedOrigins = Array.isArray(src.trustedOrigins)
      ? src.trustedOrigins.map((o) => String(o || '').trim().replace(/\/$/, '').toLowerCase()).filter(Boolean)
      : [];

    /** @type {Array<{ code: string, severity: 'critical' | 'high', message: string }>} */
    const findings = [];

    const isSafeMethod = SAFE_METHOD_SET.has(method);
    const isTrustedOrigin = origin ? trustedOrigins.includes(origin.toLowerCase()) : false;

    if (!isSafeMethod && !isTrustedOrigin) {
      if (secFetchSite !== null) {
        if (secFetchSite !== 'same-origin' && secFetchSite !== 'none') {
          findings.push({
            code: 'CSRF_CROSS_ORIGIN_BLOCKED',
            severity: 'critical',
            message: `Mutating ${method} request blocked by Fetch Metadata policy (Sec-Fetch-Site: "${secFetchSite}").`
          });
        }
      } else if (origin !== null) {
        if (origin.toLowerCase() === 'null') {
          findings.push({
            code: 'CSRF_ORIGIN_MISMATCH',
            severity: 'critical',
            message: `Mutating ${method} request carried opaque "Origin: null" header.`
          });
        } else if (host) {
          let originHost = '';
          try {
            originHost = new URL(origin).host.toLowerCase();
          } catch (e) {
            originHost = '';
          }
          if (!originHost || originHost !== host) {
            findings.push({
              code: 'CSRF_ORIGIN_MISMATCH',
              severity: 'critical',
              message: `Mutating ${method} request Origin host ("${originHost || 'invalid'}") does not match target Host ("${host}").`
            });
          }
        }
      }
    }

    const blocked = findings.length > 0;
    const record = {
      ok: true,
      id: `csrf_${crypto.randomBytes(6).toString('hex')}`,
      kind: 'csrf_evaluate',
      method,
      secFetchSite,
      safe: !blocked,
      allowed: !blocked,
      blocked,
      httpStatus: blocked ? 403 : 200,
      status: blocked ? 'BLOCKED' : 'SAFE',
      findings,
      findingCodes: Array.from(new Set(findings.map((f) => f.code))),
      auditedAt: new Date().toISOString()
    };

    if (src.persist !== false) {
      const audits = this._loadAudits();
      audits.push(record);
      this._saveAudits(audits);
    }

    return record;
  }

  /**
   * Audits a `Set-Cookie` header for `HttpOnly`, `Secure`, `SameSite`, and RFC 6265bis
   * `__Host-` / `__Secure-` prefix compliance. NEVER persists or returns raw cookie values.
   *
   * @param {string | Record<string, any>} setCookieHeader
   * @param {{ persist?: boolean }} [opts]
   */
  auditSessionCookie(setCookieHeader, opts = {}) {
    const attrs = parseCookieAttributesOnly(setCookieHeader);
    /** @type {Array<{ code: string, severity: 'critical' | 'high', message: string }>} */
    const findings = [];

    if (!attrs.httpOnly) {
      findings.push({
        code: 'COOKIE_MISSING_HTTPONLY',
        severity: 'high',
        message: `Session cookie "${attrs.name}" omits HttpOnly (exposed to XSS document.cookie theft).`
      });
    }
    if (!attrs.secure) {
      findings.push({
        code: 'COOKIE_MISSING_SECURE',
        severity: 'high',
        message: `Session cookie "${attrs.name}" omits Secure attribute (transmittable over cleartext HTTP).`
      });
    }
    const lowerSameSite = (attrs.sameSite || '').toLowerCase();
    if (!lowerSameSite || (lowerSameSite !== 'lax' && lowerSameSite !== 'strict' && !(lowerSameSite === 'none' && attrs.secure))) {
      findings.push({
        code: 'COOKIE_MISSING_SAMESITE',
        severity: 'high',
        message: `Session cookie "${attrs.name}" lacks safe SameSite=Lax|Strict attribute.`
      });
    }

    if (attrs.name.startsWith('__Host-')) {
      if (!attrs.secure || attrs.path !== '/' || Boolean(attrs.domain)) {
        findings.push({
          code: 'COOKIE_HOST_PREFIX_INVALID',
          severity: 'critical',
          message: `Cookie "${attrs.name}" violates RFC 6265bis __Host- rules (must have Secure, Path=/, and no Domain attribute).`
        });
      }
    } else if (attrs.name.startsWith('__Secure-') && !attrs.secure) {
      findings.push({
        code: 'COOKIE_HOST_PREFIX_INVALID',
        severity: 'critical',
        message: `Cookie "${attrs.name}" uses __Secure- prefix without Secure attribute.`
      });
    }

    const blocked = findings.length > 0;
    const record = {
      ok: true,
      id: `ck_${crypto.randomBytes(6).toString('hex')}`,
      kind: 'cookie_audit',
      cookieName: attrs.name,
      attributes: {
        httpOnly: attrs.httpOnly,
        secure: attrs.secure,
        sameSite: attrs.sameSite,
        path: attrs.path,
        hasDomain: Boolean(attrs.domain)
      },
      safe: !blocked,
      blocked,
      status: blocked ? 'BLOCKED' : 'SAFE',
      findings,
      findingCodes: Array.from(new Set(findings.map((f) => f.code))),
      auditedAt: new Date().toISOString()
    };

    if (opts && opts.persist === true) {
      const audits = this._loadAudits();
      audits.push(record);
      this._saveAudits(audits);
    }

    return record;
  }

  /**
   * Verifies an OAuth 2.1 PKCE `S256` flow (`CVE-2026-26247` defense).
   * NEVER stores or returns `codeVerifier` or `state` verbatim!
   *
   * @param {{
   *   method?: string,
   *   codeChallenge?: string,
   *   codeVerifier?: string,
   *   persistedMethod?: string,
   *   state?: string | null,
   *   persist?: boolean
   * }} [input]
   */
  verifyOAuthPkceFlow(input = {}) {
    const src = input && typeof input === 'object' ? input : {};
    const method = typeof src.method === 'string' ? src.method.trim() : '';
    const persistedMethod = src.persistedMethod !== undefined ? String(src.persistedMethod || '').trim() : method;
    const codeChallenge = typeof src.codeChallenge === 'string' ? src.codeChallenge.trim() : '';
    const codeVerifier = typeof src.codeVerifier === 'string' ? src.codeVerifier.trim() : '';

    /** @type {Array<{ code: string, severity: 'critical' | 'high', message: string }>} */
    const findings = [];

    // 1. OAuth 2.1 mandatory S256 & persisted method check (CVE-2026-26247)
    if (method !== 'S256' || persistedMethod !== 'S256') {
      findings.push({
        code: 'PKCE_PLAIN_FORBIDDEN',
        severity: 'critical',
        message: `OAuth 2.1 requires PKCE method="S256" on both request ("${method || 'missing'}") and persisted grant ("${persistedMethod || 'missing'}") (CVE-2026-26247).`
      });
    }

    // 2. Cryptographic SHA-256 Base64URL verifier -> challenge match
    let pkceMatched = false;
    if (method === 'S256' && persistedMethod === 'S256') {
      const verifierFormatOk = codeVerifier.length >= 43 && codeVerifier.length <= 128 && /^[A-Za-z0-9._~-]+$/.test(codeVerifier);
      if (verifierFormatOk && codeChallenge.length > 0) {
        const computed = crypto.createHash('sha256').update(codeVerifier, 'utf8').digest('base64url');
        const bufA = Buffer.from(computed, 'utf8');
        const bufB = Buffer.from(codeChallenge, 'utf8');
        pkceMatched = bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
      }
      if (!pkceMatched) {
        findings.push({
          code: 'PKCE_VERIFIER_MISMATCH',
          severity: 'critical',
          message: 'PKCE code_verifier SHA-256 digest does not match persisted code_challenge (or verifier length < 43).'
        });
      }
    }

    // 3. OAuth state entropy check (when supplied)
    if (src.state !== undefined) {
      const st = typeof src.state === 'string' ? src.state.trim() : '';
      const uniqueChars = new Set(st.split('')).size;
      if (st.length < 16 || WEAK_STATES.has(st.toLowerCase()) || uniqueChars < 6) {
        findings.push({
          code: 'OAUTH_STATE_WEAK',
          severity: 'high',
          message: 'OAuth "state" parameter is too short (< 16 chars) or low-entropy (CSRF login-injection risk).'
        });
      }
    }

    const blocked = findings.length > 0;
    const record = {
      ok: true,
      id: `pkce_${crypto.randomBytes(6).toString('hex')}`,
      kind: 'oauth_pkce',
      method: method || null,
      persistedMethod: persistedMethod || null,
      pkceMatched,
      safe: !blocked,
      verified: !blocked,
      blocked,
      status: blocked ? 'BLOCKED' : 'SAFE',
      findings,
      findingCodes: Array.from(new Set(findings.map((f) => f.code))),
      auditedAt: new Date().toISOString()
    };

    if (src.persist !== false) {
      const audits = this._loadAudits();
      audits.push(record);
      this._saveAudits(audits);
    }

    return record;
  }

  /**
   * Lists persisted metadata-only CSRF/cookie/PKCE audits (newest first, 0 raw secrets).
   */
  listSessionCsrfAudits() {
    return this._loadAudits().slice().reverse();
  }
}

const defaultSessionCsrfGuardService = new SessionCsrfGuardService();

const exported = Object.assign(defaultSessionCsrfGuardService, {
  SessionCsrfGuardService,
  SAFE_HTTP_METHODS,
  evaluateCrossOriginRequest: SessionCsrfGuardService.prototype.evaluateCrossOriginRequest.bind(defaultSessionCsrfGuardService),
  auditSessionCookie: SessionCsrfGuardService.prototype.auditSessionCookie.bind(defaultSessionCsrfGuardService),
  verifyOAuthPkceFlow: SessionCsrfGuardService.prototype.verifyOAuthPkceFlow.bind(defaultSessionCsrfGuardService),
  listSessionCsrfAudits: SessionCsrfGuardService.prototype.listSessionCsrfAudits.bind(defaultSessionCsrfGuardService)
});

module.exports = exported;
