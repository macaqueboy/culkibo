'use strict';

/**
 * Culkibo Browser Security Headers, Strict CSP/SRI & Exact-Origin CORS Firewall.
 *
 * Cures `CVE-2025-34291` (Langflow CVSS 9.4 `*`/reflected CORS + credentials -> RCE),
 * `CVE-2025-63388` (Dify), and `CVE-2026-27579` (CollabPlatform) in zero external deps:
 *  - Atomic `0o600` policy store in `CULKIBO_DATA_DIR/data/edge-cors-csp.json`.
 *  - Blocks `CORS_WILDCARD_CREDENTIALS`, `CORS_REFLECTED_ORIGIN_CREDENTIALS`,
 *    `CORS_REGEX_SUFFIX_TRAP`, and `CORS_SAMESITE_NONE_UNBOUND`.
 *  - Audits strict CSP (`CSP_UNSAFE_DIRECTIVE`), external CDN script Subresource Integrity
 *    (`MISSING_SRI_HASH`), HSTS (`MISSING_HSTS`), and `COOP`/`COEP` (`MISSING_COOP_COEP`).
 *  - Always returns plain string `caddyfile` on audit, render, and upsert (`dryRun: true` default).
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const EXACT_ORIGIN_RE = /^https?:\/\/[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::\d{1,5})?$/i;
const VALID_SRI_RE = /\bsha(?:384|512)-[A-Za-z0-9+/=]{40,}\b/;

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
 * Renders a hardened Caddy v2.11 exact-origin CORS + strict CSP/HSTS/COOP/COEP header block.
 * Always returns `caddyfile` as a plain string.
 *
 * @param {{
 *   allowedOrigins?: string[],
 *   allowCredentials?: boolean,
 *   csp?: string,
 *   hstsMaxAgeSec?: number
 * }} [policy]
 */
function renderHardenedCaddyHeadersBlock(policy = {}) {
  const src = policy && typeof policy === 'object' ? policy : {};
  const rawOrigins = Array.isArray(src.allowedOrigins) ? src.allowedOrigins : [];
  const exactOrigins = Array.from(
    new Set(
      rawOrigins
        .map((o) => String(o || '').trim().replace(/\/$/, ''))
        .filter((o) => EXACT_ORIGIN_RE.test(o))
    )
  );
  const effectiveOrigins = exactOrigins.length > 0 ? exactOrigins : ['https://app.culkibo.dev'];
  const allowCredentials = Boolean(src.allowCredentials);
  const hstsMaxAgeSec = Math.max(31536000, Math.round(Number(src.hstsMaxAgeSec ?? 63072000) || 63072000));
  const csp = typeof src.csp === 'string' && src.csp.trim()
    ? src.csp.trim()
    : "default-src 'self'; script-src 'self' 'strict-dynamic'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'";

  const lines = [
    '@exact_cors_origin {',
    `  header Origin ${effectiveOrigins.join(' ')}`,
    '}',
    'header @exact_cors_origin {',
    '  Access-Control-Allow-Origin {http.request.header.Origin}',
    '  Vary Origin'
  ];
  if (allowCredentials) {
    lines.push('  Access-Control-Allow-Credentials true');
  }
  lines.push(
    '}',
    'header {',
    `  Strict-Transport-Security "max-age=${hstsMaxAgeSec}; includeSubDomains; preload"`,
    `  Content-Security-Policy "${csp}"`,
    '  Cross-Origin-Opener-Policy "same-origin"',
    '  Cross-Origin-Embedder-Policy "require-corp"',
    '  X-Content-Type-Options "nosniff"',
    '  Referrer-Policy "strict-origin-when-cross-origin"',
    '}'
  );

  return {
    ok: true,
    allowedOrigins: effectiveOrigins,
    allowCredentials,
    caddyfile: lines.join('\n')
  };
}

/**
 * Audits a CORS policy for wildcard+credentials (`CVE-2025-34291`), reflected-origin+credentials,
 * regex/suffix host traps (`evil-example.com`), and unbound `SameSite=None` cookies.
 *
 * @param {{
 *   allowedOrigins?: string[],
 *   allowCredentials?: boolean,
 *   reflectOrigin?: boolean,
 *   sameSiteCookie?: string,
 *   probeOrigin?: string | null
 * }} [input]
 */
function auditCorsPolicy(input = {}) {
  const src = input && typeof input === 'object' ? input : {};
  const allowedOrigins = Array.isArray(src.allowedOrigins)
    ? src.allowedOrigins.map((o) => String(o || '').trim()).filter(Boolean)
    : [];
  const allowCredentials = Boolean(src.allowCredentials);
  const reflectOrigin = Boolean(src.reflectOrigin);
  const sameSiteCookie = String(src.sameSiteCookie || 'Lax').trim();
  const probeOrigin = typeof src.probeOrigin === 'string' && src.probeOrigin.trim()
    ? src.probeOrigin.trim().replace(/\/$/, '')
    : null;

  /** @type {Array<{ code: string, severity: 'critical' | 'high' | 'medium', message: string, remediation: string }>} */
  const findings = [];

  const hasWildcard = allowedOrigins.some((o) => o === '*' || o.includes('://*'));
  const exactOrigins = allowedOrigins
    .map((o) => o.replace(/\/$/, ''))
    .filter((o) => EXACT_ORIGIN_RE.test(o));

  // 1. Wildcard `*` + credentials (CVE-2025-34291)
  if (allowCredentials && hasWildcard) {
    findings.push({
      code: 'CORS_WILDCARD_CREDENTIALS',
      severity: 'critical',
      message: 'CORS combines wildcard "*" origin with Access-Control-Allow-Credentials: true (CVE-2025-34291).',
      remediation: 'Replace "*" with an explicit allowlist of exact https:// origins.'
    });
  }

  // 2. Dynamic Origin reflection + credentials (CVE-2025-34291 / CVE-2025-63388)
  if (allowCredentials && reflectOrigin) {
    findings.push({
      code: 'CORS_REFLECTED_ORIGIN_CREDENTIALS',
      severity: 'critical',
      message: 'CORS reflects arbitrary request Origin headers alongside credentials, enabling full cross-origin account takeover.',
      remediation: 'Disable dynamic Origin reflection and match against an exact static allowlist.'
    });
  }

  // 3. Regex / suffix trap detection (e.g. `example.com` or `.*example\.com` matching `evil-example.com`)
  const suspectPatterns = allowedOrigins.filter((o) => o !== '*' && !EXACT_ORIGIN_RE.test(o.replace(/\/$/, '')));
  let suffixTrapTriggered = suspectPatterns.length > 0;
  if (!suffixTrapTriggered && probeOrigin) {
    try {
      const probeHost = new URL(probeOrigin).hostname.toLowerCase();
      for (const orig of allowedOrigins) {
        if (orig === '*') continue;
        const cleanHost = orig.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();
        if (cleanHost && probeHost !== cleanHost && probeHost.endsWith(cleanHost) && !probeHost.endsWith(`.${cleanHost}`)) {
          suffixTrapTriggered = true;
          break;
        }
      }
    } catch (e) {}
  }

  if (suffixTrapTriggered) {
    findings.push({
      code: 'CORS_REGEX_SUFFIX_TRAP',
      severity: 'high',
      message: `Unanchored or suffix-based CORS origin pattern detected (${suspectPatterns.join(', ') || probeOrigin}); attacker domains like evil-example.com can bypass checks.`,
      remediation: 'Use exact scheme+host(+port) origins (e.g. https://app.example.com) with strict equality checks.'
    });
  }

  // 4. SameSite=None without strict exact origin allowlist
  if (sameSiteCookie.toLowerCase() === 'none' && (exactOrigins.length === 0 || hasWildcard || reflectOrigin)) {
    findings.push({
      code: 'CORS_SAMESITE_NONE_UNBOUND',
      severity: 'high',
      message: 'SameSite=None session cookie is paired with an unbound CORS policy (missing exact origin allowlist).',
      remediation: 'Switch cookies to SameSite=Lax or bind CORS strictly to exact origins with reflectOrigin=false.'
    });
  }

  const probeAllowedExact = probeOrigin ? exactOrigins.includes(probeOrigin) : null;
  const blocked = findings.length > 0;
  const block = renderHardenedCaddyHeadersBlock({ allowedOrigins: exactOrigins, allowCredentials });

  return {
    ok: true,
    safe: !blocked,
    blocked,
    status: blocked ? 'BLOCKED' : 'SAFE',
    findings,
    findingCodes: Array.from(new Set(findings.map((f) => f.code))),
    exactOrigins,
    allowCredentials,
    reflectOrigin,
    sameSiteCookie,
    probeOrigin,
    probeAllowedExact,
    caddyfile: block.caddyfile
  };
}

/**
 * Audits HTTP security headers and third-party external `<script>` tags for unsafe CSP directives,
 * missing Subresource Integrity (`sha384-`/`sha512-`), missing HSTS, and missing COOP/COEP.
 *
 * @param {{
 *   headers?: Record<string, any>,
 *   externalScripts?: any[]
 * }} [input]
 */
function auditSecurityHeaders(input = {}) {
  const src = input && typeof input === 'object' ? input : {};
  const rawHeaders = src.headers && typeof src.headers === 'object' ? src.headers : {};
  /** @type {Record<string, string>} */
  const hdrs = {};
  for (const [k, v] of Object.entries(rawHeaders)) {
    hdrs[String(k || '').trim().toLowerCase()] = Array.isArray(v) ? v.join('; ') : String(v ?? '').trim();
  }

  const externalScripts = Array.isArray(src.externalScripts) ? src.externalScripts : [];
  /** @type {Array<{ code: string, severity: 'critical' | 'high' | 'medium', target?: string, message: string, remediation: string }>} */
  const findings = [];

  // 1. Strict CSP audit
  const csp = hdrs['content-security-policy'] || '';
  if (!csp) {
    findings.push({
      code: 'CSP_UNSAFE_DIRECTIVE',
      severity: 'high',
      target: 'Content-Security-Policy',
      message: 'Missing Content-Security-Policy header leaves frontend exposed to XSS script injection.',
      remediation: "Set Content-Security-Policy: default-src 'self'; script-src 'self' 'strict-dynamic'; object-src 'none'."
    });
  } else if (/'unsafe-inline'|'unsafe-eval'|script-src[^;]*\*/i.test(csp)) {
    findings.push({
      code: 'CSP_UNSAFE_DIRECTIVE',
      severity: 'high',
      target: 'Content-Security-Policy',
      message: 'Content-Security-Policy contains unsafe directives (\'unsafe-inline\', \'unsafe-eval\', or wildcard script-src).',
      remediation: "Remove 'unsafe-inline'/'unsafe-eval' and adopt nonce or 'strict-dynamic' script-src."
    });
  }

  // 2. External CDN script SRI hash audit (`sha384-` or `sha512-`)
  for (const item of externalScripts) {
    let srcUrl = '';
    let integrity = '';
    if (typeof item === 'string') {
      const trimmed = item.trim();
      const srcMatch = trimmed.match(/\bsrc=["']([^"']+)["']/i);
      const intMatch = trimmed.match(/\bintegrity=["']([^"']+)["']/i);
      srcUrl = srcMatch ? srcMatch[1] : trimmed;
      integrity = intMatch ? intMatch[1] : '';
    } else if (item && typeof item === 'object') {
      srcUrl = String(item.src || item.url || '').trim();
      integrity = String(item.integrity || '').trim();
    }
    const isExternal = /^(?:https?:)?\/\//i.test(srcUrl);
    if (isExternal && !VALID_SRI_RE.test(integrity)) {
      findings.push({
        code: 'MISSING_SRI_HASH',
        severity: 'high',
        target: srcUrl,
        message: `External script "${srcUrl}" lacks a valid sha384-/sha512- Subresource Integrity (SRI) hash.`,
        remediation: 'Add integrity="sha384-<hash>" crossorigin="anonymous" to every external CDN <script> tag.'
      });
    }
  }

  // 3. HSTS audit
  const hsts = hdrs['strict-transport-security'] || '';
  const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
  const maxAgeVal = maxAgeMatch ? Number(maxAgeMatch[1]) : 0;
  if (!hsts || maxAgeVal < 31536000) {
    findings.push({
      code: 'MISSING_HSTS',
      severity: 'medium',
      target: 'Strict-Transport-Security',
      message: 'Missing or weak Strict-Transport-Security header (max-age < 31536000).',
      remediation: 'Emit Strict-Transport-Security: max-age=63072000; includeSubDomains; preload.'
    });
  }

  // 4. COOP / COEP cross-origin isolation audit
  const coop = (hdrs['cross-origin-opener-policy'] || '').toLowerCase();
  const coep = (hdrs['cross-origin-embedder-policy'] || '').toLowerCase();
  if (!coop || !coep) {
    findings.push({
      code: 'MISSING_COOP_COEP',
      severity: 'medium',
      target: 'COOP/COEP',
      message: 'Missing Cross-Origin-Opener-Policy and/or Cross-Origin-Embedder-Policy isolation headers.',
      remediation: 'Add Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Embedder-Policy: require-corp.'
    });
  }

  const blocked = findings.length > 0;
  const block = renderHardenedCaddyHeadersBlock({});
  return {
    ok: true,
    safe: !blocked,
    blocked,
    status: blocked ? 'BLOCKED' : 'SAFE',
    checkedScriptCount: externalScripts.length,
    findings,
    findingCodes: Array.from(new Set(findings.map((f) => f.code))),
    caddyfile: block.caddyfile
  };
}

class EdgeCorsCspService {
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
    return path.join(this.resolveDataDir(), 'edge-cors-csp.json');
  }

  /** @returns {Record<string, any>} */
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

  /** @param {Record<string, any>} policies */
  _saveMap(policies) {
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({ schemaVersion: 1, updatedAt: new Date().toISOString(), policies }, null, 2) + '\n'
    );
  }

  /** @param {Record<string, any>} [input] */
  auditCorsPolicy(input) {
    return auditCorsPolicy(input);
  }

  /** @param {Record<string, any>} [input] */
  auditSecurityHeaders(input) {
    return auditSecurityHeaders(input);
  }

  /** @param {Record<string, any>} [policy] */
  renderHardenedCaddyHeadersBlock(policy) {
    return renderHardenedCaddyHeadersBlock(policy);
  }

  /**
   * Audits and upserts a project's CORS/CSP policy (`dryRun: true` default).
   * @param {string} projectId
   * @param {Record<string, any>} [policyInput]
   */
  upsertCorsCspPolicy(projectId, policyInput = {}) {
    const id = String(projectId || 'default').trim().slice(0, 128) || 'default';
    const src = policyInput && typeof policyInput === 'object' ? policyInput : {};
    const dryRun = src.dryRun !== undefined ? Boolean(src.dryRun) : true;

    const audit = auditCorsPolicy(src);
    const block = renderHardenedCaddyHeadersBlock({
      allowedOrigins: audit.exactOrigins,
      allowCredentials: audit.allowCredentials,
      csp: typeof src.csp === 'string' ? src.csp : undefined
    });

    const record = {
      projectId: id,
      allowedOrigins: audit.exactOrigins,
      allowCredentials: audit.allowCredentials,
      reflectOrigin: false,
      sameSiteCookie: audit.sameSiteCookie,
      csp: typeof src.csp === 'string' && src.csp.trim()
        ? src.csp.trim()
        : "default-src 'self'; script-src 'self' 'strict-dynamic'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
      safe: audit.safe,
      updatedAt: new Date().toISOString()
    };

    if (!dryRun && audit.safe) {
      const map = this._loadMap();
      map[id] = record;
      this._saveMap(map);
    }

    return {
      ok: audit.safe,
      dryRun,
      blocked: audit.blocked,
      projectId: id,
      policy: record,
      audit,
      caddyfile: block.caddyfile
    };
  }

  /**
   * Lists persisted CORS/CSP policies.
   */
  listCorsCspPolicies() {
    return Object.values(this._loadMap());
  }
}

const defaultEdgeCorsCspService = new EdgeCorsCspService();

const exported = Object.assign(defaultEdgeCorsCspService, {
  EdgeCorsCspService,
  auditCorsPolicy: EdgeCorsCspService.prototype.auditCorsPolicy.bind(defaultEdgeCorsCspService),
  auditSecurityHeaders: EdgeCorsCspService.prototype.auditSecurityHeaders.bind(defaultEdgeCorsCspService),
  renderHardenedCaddyHeadersBlock: EdgeCorsCspService.prototype.renderHardenedCaddyHeadersBlock.bind(defaultEdgeCorsCspService),
  upsertCorsCspPolicy: EdgeCorsCspService.prototype.upsertCorsCspPolicy.bind(defaultEdgeCorsCspService),
  listCorsCspPolicies: EdgeCorsCspService.prototype.listCorsCspPolicies.bind(defaultEdgeCorsCspService)
});

module.exports = exported;
