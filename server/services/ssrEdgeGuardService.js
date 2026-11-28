'use strict';

/**
 * Culkibo Next.js / RSC Middleware & SSR Cache-Poisoning Firewall.
 *
 * Cures `CVE-2025-29927` (Next.js CVSS 9.1 `x-middleware-subrequest` auth bypass),
 * `CVE-2025-55182` ("React2Shell" CVSS 10.0 React 19 RSC RCE), and `CVE-2025-49005`
 * (Next.js 15.3.0–15.3.2 omitted `Vary: RSC` cache poisoning) in zero runtime npm deps:
 *  - Atomic `0o600` audit history in `CULKIBO_DATA_DIR/data/ssr-edge-guard.json`.
 *  - Strips/blocks client-supplied internal framework headers (`SSR_INTERNAL_HEADER_SPOOF`).
 *  - Verifies `Vary` contains `RSC`, `Next-Router-State-Tree`, and `Next-Router-Prefetch`
 *    (`RSC_VARY_HEADER_MISSING`).
 *  - Flags vulnerable React 19 (`19.0.0`, `19.1.0`, `19.1.1`, `19.2.0` ->
 *    `REACT2SHELL_VULNERABLE_VERSION`) and Next.js (`<14.2.25`, `15.0..15.2.2`, `15.3.0..15.3.2`
 *    -> `NEXTJS_MIDDLEWARE_CVE_VERSION`).
 *  - Always returns plain string `caddyBlock`; `renderHardenedSsrCaddyBlock` defaults `dryRun: true`.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MAX_STORED_AUDITS = 500;

const INTERNAL_SSR_HEADERS = Object.freeze([
  'x-middleware-subrequest',
  'x-middleware-invoke',
  'x-middleware-next',
  'x-middleware-rewrite',
  'x-middleware-override-headers',
  'x-invoke-path',
  'x-invoke-query',
  'x-invoke-status',
  'x-nextjs-data',
  'x-now-route-matches'
]);

const REQUIRED_RSC_VARY_HEADERS = Object.freeze([
  'RSC',
  'Next-Router-State-Tree',
  'Next-Router-Prefetch'
]);

const INTERNAL_HEADER_SET = new Set(INTERNAL_SSR_HEADERS);
const REACT2SHELL_VULN_SET = new Set(['19.0.0', '19.1.0', '19.1.1', '19.2.0']);

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
 * Normalizes header names across `-`/`_`/`.` separator variants.
 * @param {string} name
 * @returns {string}
 */
function canonicalHeaderName(name) {
  return String(name || '').trim().toLowerCase().replace(/[\s._-]+/g, '-');
}

/**
 * Parses a loose SemVer string (`^15.2.1`, `19.1.0`, `v14.2.24`) into `[major, minor, patch]`.
 * @param {string | null | undefined} raw
 * @returns {{ major: number, minor: number, patch: number, normalized: string } | null}
 */
function parseSemver(raw) {
  if (typeof raw !== 'string') return null;
  const m = raw.trim().match(/(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  const major = Number(m[1]);
  const minor = Number(m[2]);
  const patch = Number(m[3]);
  return { major, minor, patch, normalized: `${major}.${minor}.${patch}` };
}

/**
 * Checks whether a Next.js version falls inside CVE-2025-29927 or CVE-2025-49005 ranges.
 * @param {string | null | undefined} rawVersion
 * @returns {{ vulnerable: boolean, cve: string | null, fixedIn: string | null }}
 */
function checkNextjsVersion(rawVersion) {
  const v = parseSemver(rawVersion);
  if (!v) return { vulnerable: false, cve: null, fixedIn: null };
  if (v.major === 11 || (v.major === 12 && (v.minor < 3 || (v.minor === 3 && v.patch < 5)))) {
    return { vulnerable: true, cve: 'CVE-2025-29927', fixedIn: '12.3.5+' };
  }
  if (v.major === 13 && (v.minor < 5 || (v.minor === 5 && v.patch < 9))) {
    return { vulnerable: true, cve: 'CVE-2025-29927', fixedIn: '13.5.9+' };
  }
  if (v.major === 14 && (v.minor < 2 || (v.minor === 2 && v.patch < 25))) {
    return { vulnerable: true, cve: 'CVE-2025-29927', fixedIn: '14.2.25+' };
  }
  if (v.major === 15 && (v.minor < 2 || (v.minor === 2 && v.patch < 3))) {
    return { vulnerable: true, cve: 'CVE-2025-29927', fixedIn: '15.2.3+' };
  }
  if (v.major === 15 && v.minor === 3 && v.patch < 3) {
    return { vulnerable: true, cve: 'CVE-2025-49005', fixedIn: '15.3.3+' };
  }
  return { vulnerable: false, cve: null, fixedIn: null };
}

/**
 * Emits a hardened Caddy v2.11 SSR edge block stripping internal Next.js/RSC headers
 * and enforcing `Vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch`.
 * Defaults `dryRun: true`; ALWAYS returns plain string `caddyBlock`.
 *
 * @param {{
 *   upstream?: string,
 *   extraStripHeaders?: string[],
 *   dryRun?: boolean
 * }} [opts]
 */
function renderHardenedSsrCaddyBlock(opts = {}) {
  const src = opts && typeof opts === 'object' ? opts : {};
  const dryRun = src.dryRun !== undefined ? Boolean(src.dryRun) : true;
  const upstream = typeof src.upstream === 'string' && src.upstream.trim()
    ? src.upstream.trim().slice(0, 128)
    : '127.0.0.1:3000';
  const extra = Array.isArray(src.extraStripHeaders)
    ? src.extraStripHeaders.map((h) => String(h || '').trim()).filter(Boolean)
    : [];
  const strippedHeaders = Array.from(new Set([...INTERNAL_SSR_HEADERS, ...extra]));

  const lines = [
    `reverse_proxy ${upstream} {`,
    ...strippedHeaders.map((h) => `  header_up -${h}`),
    `  header_down +Vary "${REQUIRED_RSC_VARY_HEADERS.join(', ')}"`,
    '}'
  ];

  const caddyBlock = lines.join('\n');
  return {
    ok: true,
    dryRun,
    upstream,
    strippedHeaders,
    requiredVaryHeaders: Array.from(REQUIRED_RSC_VARY_HEADERS),
    caddyBlock
  };
}

class SsrEdgeGuardService {
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
    return path.join(this.resolveDataDir(), 'ssr-edge-guard.json');
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
   * Delegates to `renderHardenedSsrCaddyBlock`.
   * @param {Record<string, any>} [opts]
   */
  renderHardenedSsrCaddyBlock(opts) {
    return renderHardenedSsrCaddyBlock(opts);
  }

  /**
   * Evaluates SSR/RSC edge security against `CVE-2025-29927`, `CVE-2025-55182` (React2Shell),
   * and `CVE-2025-49005` (`Vary: RSC` cache poisoning).
   *
   * @param {{
   *   framework?: string,
   *   nextVersion?: string | null,
   *   reactVersion?: string | null,
   *   requestHeaders?: Record<string, any>,
   *   responseHeaders?: Record<string, any>,
   *   persist?: boolean
   * }} [input]
   */
  evaluateSsrEdgeSecurity(input = {}) {
    const src = input && typeof input === 'object' ? input : {};
    const framework = String(src.framework || 'nextjs').trim().toLowerCase();
    const nextVersion = typeof src.nextVersion === 'string' && src.nextVersion.trim() ? src.nextVersion.trim() : null;
    const reactVersion = typeof src.reactVersion === 'string' && src.reactVersion.trim() ? src.reactVersion.trim() : null;
    const requestHeaders = src.requestHeaders && typeof src.requestHeaders === 'object' ? src.requestHeaders : {};
    const hasResponseHeaders = src.responseHeaders !== undefined && src.responseHeaders !== null && typeof src.responseHeaders === 'object';
    const responseHeaders = hasResponseHeaders ? /** @type {Record<string, any>} */ (src.responseHeaders) : {};

    /** @type {Array<{ code: string, severity: 'critical' | 'high', cve?: string, detail?: any, message: string, remediation: string }>} */
    const findings = [];
    /** @type {string[]} */
    const strippedHeaders = [];

    // 1. Inbound internal framework header spoof check (CVE-2025-29927)
    for (const key of Object.keys(requestHeaders)) {
      const canon = canonicalHeaderName(key);
      if (INTERNAL_HEADER_SET.has(canon)) {
        strippedHeaders.push(key);
        findings.push({
          code: 'SSR_INTERNAL_HEADER_SPOOF',
          severity: 'critical',
          cve: 'CVE-2025-29927',
          detail: { header: key },
          message: `Client supplied internal SSR/middleware header "${key}" (CVE-2025-29927 auth-bypass vector).`,
          remediation: 'Strip all x-middleware-* and x-invoke-* headers unconditionally at the Caddy reverse proxy edge.'
        });
      }
    }

    // 2. React2Shell (CVE-2025-55182 CVSS 10.0) version check
    const parsedReact = parseSemver(reactVersion);
    if (parsedReact && REACT2SHELL_VULN_SET.has(parsedReact.normalized)) {
      findings.push({
        code: 'REACT2SHELL_VULNERABLE_VERSION',
        severity: 'critical',
        cve: 'CVE-2025-55182',
        detail: { reactVersion: parsedReact.normalized },
        message: `React ${parsedReact.normalized} is vulnerable to React2Shell pre-auth RSC RCE (CVE-2025-55182 CVSS 10.0).`,
        remediation: 'Upgrade React immediately to 19.0.1+, 19.1.2+, or 19.2.1+ and re-pin lockfile.'
      });
    }

    // 3. Next.js middleware & cache-poisoning CVE version check
    const nextCheck = checkNextjsVersion(nextVersion);
    if (nextCheck.vulnerable) {
      findings.push({
        code: 'NEXTJS_MIDDLEWARE_CVE_VERSION',
        severity: 'critical',
        cve: nextCheck.cve || 'CVE-2025-29927',
        detail: { nextVersion, fixedIn: nextCheck.fixedIn },
        message: `Next.js ${nextVersion} is vulnerable to ${nextCheck.cve}; upgrade to ${nextCheck.fixedIn}.`,
        remediation: `Upgrade Next.js to ${nextCheck.fixedIn} and apply Caddy internal header scrubbing.`
      });
    }

    // 4. Response Vary: RSC header check (CVE-2025-49005)
    if (hasResponseHeaders) {
      let varyVal = '';
      for (const [k, v] of Object.entries(responseHeaders)) {
        if (k.toLowerCase() === 'vary') {
          varyVal = Array.isArray(v) ? v.join(', ') : String(v ?? '');
          break;
        }
      }
      const varyTokens = new Set(
        varyVal
          .split(',')
          .map((t) => t.trim().toLowerCase())
          .filter(Boolean)
      );
      const missingVary = varyTokens.has('*')
        ? []
        : REQUIRED_RSC_VARY_HEADERS.filter((reqHdr) => !varyTokens.has(reqHdr.toLowerCase()));
      if (missingVary.length > 0) {
        findings.push({
          code: 'RSC_VARY_HEADER_MISSING',
          severity: 'high',
          cve: 'CVE-2025-49005',
          detail: { missingVary },
          message: `SSR response Vary header omits required RSC cache keys: ${missingVary.join(', ')} (CVE-2025-49005 cache poisoning).`,
          remediation: `Emit Vary: ${REQUIRED_RSC_VARY_HEADERS.join(', ')} on all App Router/RSC responses.`
        });
      }
    }

    const blocked = findings.length > 0;
    const caddy = renderHardenedSsrCaddyBlock({ extraStripHeaders: strippedHeaders, dryRun: true });
    const record = {
      ok: true,
      id: `ssr_${crypto.randomBytes(6).toString('hex')}`,
      framework,
      nextVersion,
      reactVersion,
      safe: !blocked,
      blocked,
      status: blocked ? 'BLOCKED' : 'SAFE',
      strippedHeaders: Array.from(new Set(strippedHeaders)),
      findings,
      findingCodes: Array.from(new Set(findings.map((f) => f.code))),
      caddyBlock: caddy.caddyBlock,
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
   * Lists persisted SSR edge security audits, newest first.
   */
  listSsrEdgeAudits() {
    return this._loadAudits().slice().reverse();
  }
}

const defaultSsrEdgeGuardService = new SsrEdgeGuardService();

const exported = Object.assign(defaultSsrEdgeGuardService, {
  SsrEdgeGuardService,
  INTERNAL_SSR_HEADERS,
  REQUIRED_RSC_VARY_HEADERS,
  evaluateSsrEdgeSecurity: SsrEdgeGuardService.prototype.evaluateSsrEdgeSecurity.bind(defaultSsrEdgeGuardService),
  renderHardenedSsrCaddyBlock: SsrEdgeGuardService.prototype.renderHardenedSsrCaddyBlock.bind(defaultSsrEdgeGuardService),
  listSsrEdgeAudits: SsrEdgeGuardService.prototype.listSsrEdgeAudits.bind(defaultSsrEdgeGuardService)
});

module.exports = exported;
