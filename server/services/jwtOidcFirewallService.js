'use strict';

/**
 * Culkibo JWT Algorithm-Confusion, `jku`/`kid` & OIDC Claim Firewall.
 *
 * Cures `CVE-2026-29000` (`pac4j-jwt`, CVSS 10.0 JWE-wrapped `PlainJWT`),
 * `CVE-2026-33322` (MinIO OIDC, CVSS 9.8 `RS256 -> HS256`), `CVE-2026-22817`
 * (Hono `< 4.11.4` missing explicit JWK `alg`), and `CVE-2025-61152` — zero external deps:
 *  - Atomic `0o600` metadata-only audit log in `CULKIBO_DATA_DIR/data/jwt-oidc-firewall.json`
 *    (**NEVER stores or echoes raw JWT token strings!**).
 *  - Flags `JWT_ALG_NONE_FORBIDDEN`, `JWE_PLAIN_INNER_FORBIDDEN`, `JWT_ALG_CONFUSION_BLOCKED`,
 *    `JWK_MISSING_EXPLICIT_ALG`, `JWT_JKU_SSRF_BLOCKED`, `JWT_KID_INJECTION`, and
 *    `JWT_CLAIMS_MISMATCH`.
 *  - `auditOidcVerifierConfig` defaults `dryRun: true`.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MAX_STORED_AUDITS = 500;

const ASYMMETRIC_ALGORITHMS = Object.freeze([
  'RS256', 'RS384', 'RS512',
  'ES256', 'ES384', 'ES512',
  'PS256', 'PS384', 'PS512',
  'EdDSA'
]);

const SYMMETRIC_ALGORITHMS = Object.freeze(['HS256', 'HS384', 'HS512']);
const ASYMMETRIC_SET = new Set(ASYMMETRIC_ALGORITHMS);
const SYMMETRIC_SET = new Set(SYMMETRIC_ALGORITHMS);

const KID_INJECTION_RE = /(?:\.\.|\/|\\|['";`|$<>]|\r|\n|\0|--|\/\*|\bunion\b\s+\bselect\b)/i;

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
 * Decodes a Base64URL JSON JWT segment safely without throwing.
 * @param {string} segment
 * @returns {Record<string, any> | null}
 */
function decodeBase64UrlJson(segment) {
  if (typeof segment !== 'string' || !segment.trim()) return null;
  try {
    let std = segment.trim().replace(/-/g, '+').replace(/_/g, '/');
    const rem = std.length % 4;
    if (rem === 1) return null;
    if (rem > 0) std += '='.repeat(4 - rem);
    const decoded = Buffer.from(std, 'base64').toString('utf8');
    const parsed = JSON.parse(decoded);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch (e) {
    return null;
  }
}

/**
 * Parses a compact JWS (3 parts) or JWE (5 parts) without verifying or trusting `alg`.
 * @param {string} token
 */
function parseCompactJwt(token) {
  const trimmed = String(token || '').trim();
  const parts = trimmed.split('.');
  if (parts.length === 5) {
    return {
      format: /** @type {'JWE'} */ ('JWE'),
      header: decodeBase64UrlJson(parts[0]),
      claims: null,
      signatureSegment: parts[4]
    };
  }
  if (parts.length === 3) {
    return {
      format: /** @type {'JWS'} */ ('JWS'),
      header: decodeBase64UrlJson(parts[0]),
      claims: decodeBase64UrlJson(parts[1]),
      signatureSegment: parts[2]
    };
  }
  return {
    format: /** @type {'INVALID'} */ ('INVALID'),
    header: null,
    claims: null,
    signatureSegment: ''
  };
}

class JwtOidcFirewallService {
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
    return path.join(this.resolveDataDir(), 'jwt-oidc-firewall.json');
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
   * Inspects a JWT/JWE token (or decoded header+claims) against `CVE-2026-29000`,
   * `CVE-2026-33322`, `CVE-2026-22817`, `jku`/`x5u` SSRF, `kid` injection, and OIDC claims.
   * NEVER stores or returns the raw JWT token string!
   *
   * @param {{
   *   token?: string,
   *   innerToken?: string,
   *   innerUnsigned?: boolean,
   *   header?: Record<string, any> | null,
   *   claims?: Record<string, any> | null,
   *   expectedAlgorithms?: string[],
   *   expectedIssuer?: string | null,
   *   expectedAudience?: string | null,
   *   nowSec?: number,
   *   jwkHasExplicitAlg?: boolean,
   *   persist?: boolean
   * }} [input]
   */
  inspectJwtHeaderAndClaims(input = {}) {
    const src = input && typeof input === 'object' ? input : {};
    const expectedAlgorithms = Array.isArray(src.expectedAlgorithms) && src.expectedAlgorithms.length > 0
      ? src.expectedAlgorithms.map((a) => String(a || '').trim()).filter(Boolean)
      : ['RS256', 'ES256', 'EdDSA'];
    const nowSec = src.nowSec !== undefined && Number.isFinite(Number(src.nowSec))
      ? Math.floor(Number(src.nowSec))
      : Math.floor(Date.now() / 1000);
    const jwkHasExplicitAlg = src.jwkHasExplicitAlg !== undefined ? Boolean(src.jwkHasExplicitAlg) : true;

    let format = 'JWS';
    /** @type {Record<string, any> | null} */
    let header = src.header && typeof src.header === 'object' ? { ...src.header } : null;
    /** @type {Record<string, any> | null} */
    let claims = src.claims && typeof src.claims === 'object' ? { ...src.claims } : null;
    let signatureSegment = 'provided';
    /** @type {string | null} */
    let tokenFingerprintSha256 = null;

    if (typeof src.token === 'string' && src.token.trim()) {
      tokenFingerprintSha256 = crypto.createHash('sha256').update(src.token.trim(), 'utf8').digest('hex');
      const parsed = parseCompactJwt(src.token);
      format = parsed.format;
      header = parsed.header || header;
      claims = parsed.claims || claims;
      signatureSegment = parsed.signatureSegment;
    }

    /** @type {Array<{ code: string, severity: 'critical' | 'high', message: string, remediation: string }>} */
    const findings = [];

    if (!header || format === 'INVALID') {
      findings.push({
        code: 'JWT_MALFORMED_TOKEN',
        severity: 'critical',
        message: 'Token header is missing or malformed compact JWS/JWE.',
        remediation: 'Reject malformed bearer tokens prior to cryptographic verification.'
      });
    } else {
      const rawAlg = typeof header.alg === 'string' ? header.alg.trim() : '';
      const lowerAlg = rawAlg.toLowerCase();

      // 1. alg: none (case-insensitive) or empty unsigned JWS signature
      if (!rawAlg || lowerAlg === 'none' || (format === 'JWS' && typeof src.token === 'string' && signatureSegment === '')) {
        findings.push({
          code: 'JWT_ALG_NONE_FORBIDDEN',
          severity: 'critical',
          message: `Unsigned or alg="none" token detected (alg="${rawAlg || 'missing'}").`,
          remediation: 'Explicitly reject alg="none" and require non-empty cryptographic signatures.'
        });
      }

      // 2. CVE-2026-29000 (CVSS 10.0): JWE wrapping an unsigned PlainJWT inner token
      const isJwe = format === 'JWE' || Boolean(header.enc);
      let innerPlainDetected = Boolean(src.innerUnsigned) || (isJwe && String(header.cty || '').toLowerCase() === 'plainjwt');
      if (!innerPlainDetected && typeof src.innerToken === 'string' && src.innerToken.trim()) {
        const innerParsed = parseCompactJwt(src.innerToken);
        const innerAlg = innerParsed.header && typeof innerParsed.header.alg === 'string'
          ? innerParsed.header.alg.trim().toLowerCase()
          : '';
        if (!innerAlg || innerAlg === 'none' || innerParsed.signatureSegment === '') {
          innerPlainDetected = true;
        }
      }
      if (isJwe && innerPlainDetected) {
        findings.push({
          code: 'JWE_PLAIN_INNER_FORBIDDEN',
          severity: 'critical',
          message: 'JWE envelope wraps an unsigned PlainJWT inner token (CVE-2026-29000 CVSS 10.0 bypass).',
          remediation: 'Require an authenticated inner JWS signed with a pinned asymmetric algorithm after JWE decryption.'
        });
      }

      // 3. CVE-2026-33322 (CVSS 9.8): Algorithm confusion / unpinned alg downgrade (e.g. HS256 vs pinned RS256)
      if (rawAlg && lowerAlg !== 'none' && !isJwe && !expectedAlgorithms.includes(rawAlg)) {
        findings.push({
          code: 'JWT_ALG_CONFUSION_BLOCKED',
          severity: 'critical',
          message: `Token algorithm "${rawAlg}" is not in pinned expectedAlgorithms [${expectedAlgorithms.join(', ')}] (CVE-2026-33322).`,
          remediation: `Pin verifier strictly to [${expectedAlgorithms.join(', ')}] and never verify HMAC using an RSA/EC public key.`
        });
      }

      // 4. CVE-2026-22817: Missing explicit JWK alg parameter
      const embeddedJwkMissingAlg = header.jwk && typeof header.jwk === 'object' && !header.jwk.alg;
      if (!jwkHasExplicitAlg || embeddedJwkMissingAlg) {
        findings.push({
          code: 'JWK_MISSING_EXPLICIT_ALG',
          severity: 'high',
          message: 'Verification JWK lacks an explicit "alg" parameter (CVE-2026-22817 fallback confusion risk).',
          remediation: 'Require explicit "alg" on every JWKS entry and reject inline header "jwk" parameters.'
        });
      }

      // 5. Remote jku / x5u SSRF header injection
      if (header.jku || header.x5u) {
        findings.push({
          code: 'JWT_JKU_SSRF_BLOCKED',
          severity: 'critical',
          message: 'Token header includes untrusted remote key URL ("jku"/"x5u") enabling attacker-controlled JWKS SSRF forgery.',
          remediation: 'Strip and ignore "jku"/"x5u" headers; fetch JWKS strictly from pre-configured trusted OIDC discovery endpoints.'
        });
      }

      // 6. kid path traversal / SQLi / command injection
      if (header.kid !== undefined && header.kid !== null) {
        const kidStr = String(header.kid);
        if (kidStr.length > 128 || KID_INJECTION_RE.test(kidStr)) {
          findings.push({
            code: 'JWT_KID_INJECTION',
            severity: 'critical',
            message: 'Malicious traversal or injection characters detected inside JWT "kid" header.',
            remediation: 'Validate "kid" strictly against /^[a-zA-Z0-9._-]{1,64}$/ and resolve only via in-memory JWKS map lookup.'
          });
        }
      }
    }

    // 7. OIDC iss / aud / exp / nbf claim checks
    if (claims) {
      if (src.expectedIssuer && claims.iss !== src.expectedIssuer) {
        findings.push({
          code: 'JWT_CLAIMS_MISMATCH',
          severity: 'high',
          message: `Token issuer "${claims.iss || 'missing'}" does not match expectedIssuer "${src.expectedIssuer}".`,
          remediation: 'Enforce exact OIDC "iss" equality during JWT verification.'
        });
      }
      if (src.expectedAudience) {
        const aud = claims.aud;
        const audOk = Array.isArray(aud)
          ? aud.includes(src.expectedAudience)
          : aud === src.expectedAudience;
        if (!audOk) {
          findings.push({
            code: 'JWT_CLAIMS_MISMATCH',
            severity: 'high',
            message: `Token audience does not contain expectedAudience "${src.expectedAudience}".`,
            remediation: 'Require exact "aud" match to prevent cross-service token replay.'
          });
        }
      }
      if (claims.exp !== undefined) {
        const expNum = Number(claims.exp);
        if (!Number.isFinite(expNum) || nowSec >= expNum) {
          findings.push({
            code: 'JWT_CLAIMS_MISMATCH',
            severity: 'high',
            message: 'Token "exp" claim is expired or invalid.',
            remediation: 'Reject expired tokens and keep access-token TTLs short.'
          });
        }
      } else if (src.expectedIssuer || src.expectedAudience) {
        findings.push({
          code: 'JWT_CLAIMS_MISMATCH',
          severity: 'high',
          message: 'Token is missing required "exp" expiration claim.',
          remediation: 'Require bounded numeric "exp" on all OIDC/JWT tokens.'
        });
      }
    }

    const blocked = findings.length > 0;
    const record = {
      ok: true,
      id: `jwt_${crypto.randomBytes(6).toString('hex')}`,
      kind: 'token_inspect',
      format,
      safe: !blocked,
      blocked,
      status: blocked ? 'BLOCKED' : 'SAFE',
      headerAlg: header && typeof header.alg === 'string' ? header.alg : null,
      tokenFingerprintSha256,
      expectedAlgorithms,
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
   * Audits an OIDC / JWT verifier configuration (`dryRun: true` default).
   *
   * @param {{
   *   pinnedAlgorithms?: string[],
   *   allowAlgNone?: boolean,
   *   allowJkuHeader?: boolean,
   *   sanitizeKid?: boolean,
   *   validateIssAud?: boolean,
   *   jwksRefreshMinIntervalSec?: number,
   *   dryRun?: boolean
   * }} [config]
   */
  auditOidcVerifierConfig(config = {}) {
    const src = config && typeof config === 'object' ? config : {};
    const dryRun = src.dryRun !== undefined ? Boolean(src.dryRun) : true;
    const pinnedAlgorithms = Array.isArray(src.pinnedAlgorithms)
      ? src.pinnedAlgorithms.map((a) => String(a || '').trim()).filter(Boolean)
      : [];
    const allowAlgNone = Boolean(src.allowAlgNone);
    const allowJkuHeader = Boolean(src.allowJkuHeader);
    const sanitizeKid = src.sanitizeKid !== undefined ? Boolean(src.sanitizeKid) : true;
    const validateIssAud = src.validateIssAud !== undefined ? Boolean(src.validateIssAud) : true;
    const jwksRefreshMinIntervalSec = Math.round(Number(src.jwksRefreshMinIntervalSec ?? 60) || 0);

    /** @type {Array<{ code: string, severity: 'critical' | 'high' | 'medium', message: string }>} */
    const findings = [];

    if (allowAlgNone || pinnedAlgorithms.some((a) => a.toLowerCase() === 'none')) {
      findings.push({
        code: 'JWT_ALG_NONE_FORBIDDEN',
        severity: 'critical',
        message: 'OIDC verifier permits alg="none"; disable immediately.'
      });
    }

    const hasSym = pinnedAlgorithms.some((a) => SYMMETRIC_SET.has(a));
    const hasAsym = pinnedAlgorithms.some((a) => ASYMMETRIC_SET.has(a));
    if (pinnedAlgorithms.length === 0 || (hasSym && hasAsym)) {
      findings.push({
        code: 'JWT_ALG_CONFUSION_BLOCKED',
        severity: 'critical',
        message: pinnedAlgorithms.length === 0
          ? 'OIDC verifier has no pinnedAlgorithms allowlist (accepts arbitrary token alg).'
          : 'OIDC verifier mixes symmetric (HS*) and asymmetric (RS*/ES*/EdDSA) algorithms, risking algorithm confusion.'
      });
    }

    if (allowJkuHeader) {
      findings.push({
        code: 'JWT_JKU_SSRF_BLOCKED',
        severity: 'critical',
        message: 'OIDC verifier honors client-supplied "jku"/"x5u" URLs (SSRF key-injection risk).'
      });
    }

    if (!sanitizeKid) {
      findings.push({
        code: 'JWT_KID_INJECTION',
        severity: 'high',
        message: 'OIDC verifier does not sanitize "kid" before key lookup.'
      });
    }

    if (!validateIssAud) {
      findings.push({
        code: 'JWT_CLAIMS_MISMATCH',
        severity: 'high',
        message: 'OIDC verifier skips mandatory "iss" / "aud" claim validation.'
      });
    }

    if (jwksRefreshMinIntervalSec < 10) {
      findings.push({
        code: 'JWKS_REFRESH_DOS_RISK',
        severity: 'medium',
        message: `jwksRefreshMinIntervalSec (${jwksRefreshMinIntervalSec}s) is < 10s, allowing unknown-kid JWKS cache-busting DoS.`
      });
    }

    const blocked = findings.length > 0;
    const record = {
      ok: true,
      id: `oidc_${crypto.randomBytes(6).toString('hex')}`,
      kind: 'verifier_config',
      dryRun,
      safe: !blocked,
      blocked,
      status: blocked ? 'BLOCKED' : 'SAFE',
      pinnedAlgorithms,
      findings,
      findingCodes: Array.from(new Set(findings.map((f) => f.code))),
      auditedAt: new Date().toISOString()
    };

    if (!dryRun) {
      const audits = this._loadAudits();
      audits.push(record);
      this._saveAudits(audits);
    }

    return record;
  }

  /**
   * Lists persisted metadata-only JWT/OIDC firewall audits (newest first, 0 raw tokens).
   */
  listJwtFirewallAudits() {
    return this._loadAudits().slice().reverse();
  }
}

const defaultJwtOidcFirewallService = new JwtOidcFirewallService();

const exported = Object.assign(defaultJwtOidcFirewallService, {
  JwtOidcFirewallService,
  ASYMMETRIC_ALGORITHMS,
  SYMMETRIC_ALGORITHMS,
  inspectJwtHeaderAndClaims: JwtOidcFirewallService.prototype.inspectJwtHeaderAndClaims.bind(defaultJwtOidcFirewallService),
  auditOidcVerifierConfig: JwtOidcFirewallService.prototype.auditOidcVerifierConfig.bind(defaultJwtOidcFirewallService),
  listJwtFirewallAudits: JwtOidcFirewallService.prototype.listJwtFirewallAudits.bind(defaultJwtOidcFirewallService)
});

module.exports = exported;
