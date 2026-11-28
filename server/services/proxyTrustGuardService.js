'use strict';

/**
 * Culkibo Reverse-Proxy Trust Boundary, `forward_auth` & HTTP Smuggling Guard.
 *
 * Cures `CVE-2026-30851` (Caddy `< 2.11.2` `forward_auth` identity header spoofing),
 * `CVE-2026-54764`, `CVE-2026-88008`, `CVE-2026-71324` (Traefik `ForwardAuth`/`h2c`/
 * `CONNECT` keep-alive desync), and `caddy#6783` in zero runtime npm dependencies:
 *  - Atomic `0o600` policy store in `CULKIBO_DATA_DIR/data/proxy-trust-guard.json`.
 *  - Right-to-left `X-Forwarded-For` trusted-proxy peeling (`resolveTrustedClientIp`)
 *    so client-spoofed left-most IPs never bypass IP allowlists.
 *  - Canonical `-`/`_`/`.` separator-normalized identity header spoofing guard
 *    (`X-Remote-User`, `X_Remote_User`, `X.Authenticated.User`, `authCopyHeaders` ->
 *    `FORWARD_AUTH_SPOOF_BLOCKED`).
 *  - Blocks cleartext `Upgrade: h2c` / `HTTP2-Settings` (`H2C_SMUGGLE_BLOCKED`),
 *    `CONNECT` with body on HTTP/1.1 (`CONNECT_DESYNC_BLOCKED`), and dual
 *    `Content-Length` + `Transfer-Encoding` (`TE_CL_SMUGGLE`).
 *  - Emits hardened Caddy `trusted_proxies` + `forward_auth` header-strip Caddyfile string.
 */

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const path = require('path');

const DEFAULT_TRUSTED_PROXIES = Object.freeze(['127.0.0.1/32', '::1/128']);

const BUILTIN_IDENTITY_HEADERS = Object.freeze([
  'x-remote-user',
  'x-remote-email',
  'x-remote-groups',
  'x-remote-role',
  'x-authenticated-user',
  'x-authenticated-groups',
  'x-auth-request-user',
  'x-auth-request-email',
  'x-auth-request-groups',
  'x-forwarded-user',
  'x-forwarded-email',
  'x-forwarded-groups',
  'remote-user',
  'remote-groups',
  'remote-email'
]);

const FORWARDED_META_HEADERS = new Set([
  'x-forwarded-for',
  'x-forwarded-proto',
  'x-forwarded-port',
  'x-forwarded-host',
  'x-real-ip',
  'forwarded'
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
 * Normalizes header names across `-`, `_`, and `.` separator confusion variants.
 * @param {string} name
 * @returns {string}
 */
function canonicalHeaderId(name) {
  return String(name || '').trim().toLowerCase().replace(/[\s._-]+/g, '-');
}

/**
 * Parses an IPv4 address into an unsigned 32-bit integer.
 * @param {string} ip
 * @returns {number | null}
 */
function ipv4ToInt(ip) {
  if (net.isIP(ip) !== 4) return null;
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return (((parts[0] << 24) >>> 0) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/**
 * Parses an IPv6 address into a 128-bit BigInt.
 * @param {string} rawIp
 * @returns {bigint | null}
 */
function ipv6ToBigInt(rawIp) {
  const clean = rawIp.trim().toLowerCase().replace(/^\[|\]$/g, '').split('%')[0];
  if (net.isIP(clean) !== 6) return null;
  const sides = clean.split('::');
  if (sides.length > 2) return null;
  const left = sides[0] ? sides[0].split(':').filter(Boolean) : [];
  const right = sides.length === 2 && sides[1] ? sides[1].split(':').filter(Boolean) : [];
  const missing = 8 - (left.length + right.length);
  if (missing < 0) return null;
  const groups = sides.length === 2 ? [...left, ...Array(missing).fill('0'), ...right] : left;
  if (groups.length !== 8) return null;
  let acc = 0n;
  for (const g of groups) {
    const val = parseInt(g, 16);
    if (!Number.isFinite(val) || val < 0 || val > 0xffff) return null;
    acc = (acc << 16n) | BigInt(val);
  }
  return acc;
}

/**
 * Checks whether `ip` matches a single IP or CIDR range (IPv4 or IPv6).
 * @param {string} cidr
 * @param {string} rawIp
 * @returns {boolean}
 */
function cidrContainsIp(cidr, rawIp) {
  if (typeof cidr !== 'string' || typeof rawIp !== 'string') return false;
  const ip = rawIp.trim().toLowerCase().replace(/^\[|\]$/g, '');
  const [rawBase, rawPrefix] = cidr.trim().toLowerCase().split('/');
  const base = rawBase.replace(/^\[|\]$/g, '');
  const ipVer = net.isIP(ip);
  const baseVer = net.isIP(base);
  if (ipVer === 0 || ipVer !== baseVer) return false;

  if (ipVer === 4) {
    const prefix = rawPrefix === undefined ? 32 : Number(rawPrefix);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
    const ipInt = ipv4ToInt(ip);
    const baseInt = ipv4ToInt(base);
    if (ipInt === null || baseInt === null) return false;
    if (prefix === 0) return true;
    const mask = (0xffffffff << (32 - prefix)) >>> 0;
    return ((ipInt & mask) >>> 0) === ((baseInt & mask) >>> 0);
  }

  const prefix = rawPrefix === undefined ? 128 : Number(rawPrefix);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return false;
  const ipBig = ipv6ToBigInt(ip);
  const baseBig = ipv6ToBigInt(base);
  if (ipBig === null || baseBig === null) return false;
  if (prefix === 0) return true;
  const shift = BigInt(128 - prefix);
  return (ipBig >> shift) === (baseBig >> shift);
}

/**
 * Checks whether an IP belongs to any trusted proxy CIDR.
 * @param {string} ip
 * @param {string[]} trustedProxyCidrs
 * @returns {boolean}
 */
function isIpInTrustedProxies(ip, trustedProxyCidrs) {
  if (!ip || !Array.isArray(trustedProxyCidrs) || trustedProxyCidrs.length === 0) return false;
  return trustedProxyCidrs.some((cidr) => cidrContainsIp(cidr, ip));
}

/**
 * Resolves the authoritative client IP by peeling `X-Forwarded-For` from RIGHT to LEFT,
 * stopping at the first non-trusted hop. Untrusted `remoteIp` ignores `X-Forwarded-For` entirely
 * so spoofed left-most IPs can never bypass IP allowlists (`caddy#6783`).
 *
 * @param {{
 *   remoteIp?: string,
 *   xForwardedFor?: string | string[],
 *   trustedProxyCidrs?: string[]
 * }} [input]
 */
function resolveTrustedClientIp(input = {}) {
  const src = input && typeof input === 'object' ? input : {};
  const remoteIp = String(src.remoteIp || '').trim();
  const trustedProxyCidrs = Array.isArray(src.trustedProxyCidrs)
    ? src.trustedProxyCidrs.map((c) => String(c || '').trim()).filter(Boolean)
    : Array.from(DEFAULT_TRUSTED_PROXIES);

  const remoteTrusted = isIpInTrustedProxies(remoteIp, trustedProxyCidrs);
  const rawXff = Array.isArray(src.xForwardedFor)
    ? src.xForwardedFor.join(',')
    : String(src.xForwardedFor || '');
  const xffHops = rawXff
    .split(',')
    .map((h) => h.trim())
    .filter((h) => net.isIP(h.replace(/^\[|\]$/g, '')) !== 0);

  if (!remoteTrusted) {
    return {
      ok: true,
      clientIp: remoteIp || '0.0.0.0',
      remoteIp: remoteIp || '0.0.0.0',
      remoteTrusted: false,
      spoofedXffIgnored: xffHops.length > 0,
      ignoredHops: xffHops
    };
  }

  // Walk right-to-left through XFF hops while immediate peer is a trusted proxy
  let resolved = remoteIp;
  let spoofedIgnored = false;
  /** @type {string[]} */
  const ignoredHops = [];

  for (let i = xffHops.length - 1; i >= 0; i -= 1) {
    const hop = xffHops[i];
    if (!isIpInTrustedProxies(hop, trustedProxyCidrs)) {
      resolved = hop;
      if (i > 0) {
        spoofedIgnored = true;
        ignoredHops.push(...xffHops.slice(0, i));
      }
      break;
    }
    resolved = hop;
  }

  return {
    ok: true,
    clientIp: resolved,
    remoteIp,
    remoteTrusted: true,
    spoofedXffIgnored: spoofedIgnored,
    ignoredHops
  };
}

/**
 * Renders a hardened Caddy v2.11 `trusted_proxies` + `forward_auth` header-strip block.
 * Always returns `caddyfile` as a plain string for UI/CLI parity.
 *
 * @param {{
 *   trustedProxyCidrs?: string[],
 *   authCopyHeaders?: string[],
 *   stripIdentityHeaders?: string[]
 * }} [policy]
 */
function renderHardenedProxyTrustBlock(policy = {}) {
  const src = policy && typeof policy === 'object' ? policy : {};
  const trustedProxies = Array.isArray(src.trustedProxyCidrs) && src.trustedProxyCidrs.length > 0
    ? src.trustedProxyCidrs.map((c) => String(c || '').trim()).filter(Boolean)
    : Array.from(DEFAULT_TRUSTED_PROXIES);

  const authHeaders = Array.isArray(src.authCopyHeaders) ? src.authCopyHeaders : [];
  const extraStrip = Array.isArray(src.stripIdentityHeaders) ? src.stripIdentityHeaders : [];
  const strippedHeaders = Array.from(
    new Set([
      'X-Remote-User',
      'X_Remote_User',
      'X-Authenticated-User',
      'X-Auth-Request-User',
      'X-Forwarded-User',
      'Remote-User',
      'HTTP2-Settings',
      ...authHeaders.map((h) => String(h || '').trim()).filter(Boolean),
      ...extraStrip.map((h) => String(h || '').trim()).filter(Boolean)
    ])
  );

  const lines = [
    '{',
    '  servers {',
    `    trusted_proxies static ${trustedProxies.join(' ')}`,
    '    trusted_proxies_strict',
    '    protocols h1 h2 h3',
    '  }',
    '}',
    '',
    'handle {',
    '  @h2c_or_connect {',
    '    header Upgrade *h2c*',
    '    method CONNECT',
    '  }',
    '  respond @h2c_or_connect 400',
    '  request_header {',
    ...strippedHeaders.map((h) => `    -${h}`),
    '  }',
    '}'
  ];

  const caddyfile = lines.join('\n');
  return {
    ok: true,
    trustedProxies,
    strippedHeaders,
    caddyfile
  };
}

class ProxyTrustGuardService {
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
    return path.join(this.resolveDataDir(), 'proxy-trust-guard.json');
  }

  /** @returns {{ trustedProxyCidrs: string[], authCopyHeaders: string[], blockH2c: boolean, blockConnectBody: boolean, blockTeClSmuggle: boolean, updatedAt: string | null }} */
  _loadPolicy() {
    const defaults = {
      trustedProxyCidrs: Array.from(DEFAULT_TRUSTED_PROXIES),
      authCopyHeaders: ['X-Remote-User', 'X-Remote-Groups', 'X-Authenticated-User'],
      blockH2c: true,
      blockConnectBody: true,
      blockTeClSmuggle: true,
      updatedAt: null
    };
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) return defaults;
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      const p = parsed && parsed.policy && typeof parsed.policy === 'object' ? parsed.policy : {};
      return {
        trustedProxyCidrs: Array.isArray(p.trustedProxyCidrs) && p.trustedProxyCidrs.length > 0
          ? p.trustedProxyCidrs
          : defaults.trustedProxyCidrs,
        authCopyHeaders: Array.isArray(p.authCopyHeaders) ? p.authCopyHeaders : defaults.authCopyHeaders,
        blockH2c: p.blockH2c !== undefined ? Boolean(p.blockH2c) : true,
        blockConnectBody: p.blockConnectBody !== undefined ? Boolean(p.blockConnectBody) : true,
        blockTeClSmuggle: p.blockTeClSmuggle !== undefined ? Boolean(p.blockTeClSmuggle) : true,
        updatedAt: typeof p.updatedAt === 'string' ? p.updatedAt : null
      };
    } catch (e) {
      return defaults;
    }
  }

  /**
   * Returns current proxy trust boundary policy and compiled Caddyfile snippet.
   */
  getProxyTrustPolicy() {
    const policy = this._loadPolicy();
    const block = renderHardenedProxyTrustBlock(policy);
    return {
      ok: true,
      policy,
      caddyfile: block.caddyfile
    };
  }

  /**
   * Updates proxy trust boundary policy (`dryRun: true` default).
   * @param {{
   *   trustedProxyCidrs?: string[],
   *   authCopyHeaders?: string[],
   *   blockH2c?: boolean,
   *   blockConnectBody?: boolean,
   *   blockTeClSmuggle?: boolean,
   *   dryRun?: boolean
   * }} [policyInput]
   */
  upsertProxyTrustPolicy(policyInput = {}) {
    const src = policyInput && typeof policyInput === 'object' ? policyInput : {};
    const dryRun = src.dryRun !== undefined ? Boolean(src.dryRun) : true;
    const current = this._loadPolicy();

    const trustedProxyCidrs = Array.isArray(src.trustedProxyCidrs) && src.trustedProxyCidrs.length > 0
      ? Array.from(new Set(src.trustedProxyCidrs.map((c) => String(c || '').trim()).filter(Boolean)))
      : current.trustedProxyCidrs;
    const authCopyHeaders = Array.isArray(src.authCopyHeaders)
      ? Array.from(new Set(src.authCopyHeaders.map((h) => String(h || '').trim()).filter(Boolean)))
      : current.authCopyHeaders;

    const nextPolicy = {
      trustedProxyCidrs,
      authCopyHeaders,
      blockH2c: src.blockH2c !== undefined ? Boolean(src.blockH2c) : current.blockH2c,
      blockConnectBody: src.blockConnectBody !== undefined ? Boolean(src.blockConnectBody) : current.blockConnectBody,
      blockTeClSmuggle: src.blockTeClSmuggle !== undefined ? Boolean(src.blockTeClSmuggle) : current.blockTeClSmuggle,
      updatedAt: new Date().toISOString()
    };

    if (!dryRun) {
      atomicWriteFileSync(
        this.getStoreFilePath(),
        JSON.stringify({ schemaVersion: 1, updatedAt: nextPolicy.updatedAt, policy: nextPolicy }, null, 2) + '\n'
      );
    }

    const block = renderHardenedProxyTrustBlock(nextPolicy);
    return {
      ok: true,
      dryRun,
      policy: nextPolicy,
      caddyfile: block.caddyfile
    };
  }

  /**
   * Delegates to `resolveTrustedClientIp`.
   * @param {Record<string, any>} [input]
   */
  resolveTrustedClientIp(input) {
    return resolveTrustedClientIp(input);
  }

  /**
   * Delegates to `renderHardenedProxyTrustBlock`.
   * @param {Record<string, any>} [policy]
   */
  renderHardenedProxyTrustBlock(policy) {
    return renderHardenedProxyTrustBlock(policy);
  }

  /**
   * Evaluates an inbound HTTP request against proxy trust boundaries, `forward_auth` identity
   * header spoofing (`CVE-2026-30851`/`54764`), `h2c` smuggling (`CVE-2026-88008`),
   * `CONNECT` body desync (`CVE-2026-71324`), and `TE-CL` smuggling.
   *
   * @param {{
   *   remoteIp?: string,
   *   method?: string,
   *   headers?: Record<string, any>,
   *   hasBody?: boolean,
   *   upstreamHttpVersion?: string,
   *   trustedProxyCidrs?: string[],
   *   authCopyHeaders?: string[]
   * }} [input]
   */
  evaluateProxyRequest(input = {}) {
    const src = input && typeof input === 'object' ? input : {};
    const storedPolicy = this._loadPolicy();
    const trustedProxyCidrs = Array.isArray(src.trustedProxyCidrs)
      ? src.trustedProxyCidrs.map((c) => String(c || '').trim()).filter(Boolean)
      : storedPolicy.trustedProxyCidrs;
    const authCopyHeaders = Array.isArray(src.authCopyHeaders)
      ? src.authCopyHeaders.map((h) => String(h || '').trim()).filter(Boolean)
      : storedPolicy.authCopyHeaders;

    const remoteIp = String(src.remoteIp || '').trim() || '0.0.0.0';
    const method = String(src.method || 'GET').trim().toUpperCase();
    const upstreamHttpVersion = String(src.upstreamHttpVersion || '1.1').trim();
    const rawHeaders = src.headers && typeof src.headers === 'object' ? src.headers : {};

    const sourceTrusted = isIpInTrustedProxies(remoteIp, trustedProxyCidrs);
    const identitySet = new Set([
      ...BUILTIN_IDENTITY_HEADERS,
      ...authCopyHeaders.map((h) => canonicalHeaderId(h))
    ]);

    /** @type {Array<{ code: string, severity: 'critical' | 'high', header?: string, message: string }>} */
    const findings = [];
    /** @type {string[]} */
    const strippedHeaders = [];
    /** @type {Record<string, any>} */
    const sanitizedHeaders = {};

    let hasContentLength = false;
    let hasTransferEncoding = false;
    let contentLengthValue = 0;
    let hasUpgradeH2c = false;
    let hasHttp2Settings = false;
    /** @type {string} */
    let xffRaw = '';

    for (const [key, rawVal] of Object.entries(rawHeaders)) {
      const lower = key.toLowerCase().trim();
      const canon = canonicalHeaderId(key);
      const valStr = Array.isArray(rawVal) ? rawVal.join(', ') : String(rawVal ?? '').trim();

      if (lower === 'x-forwarded-for') xffRaw = valStr;
      if (lower === 'content-length') {
        hasContentLength = true;
        const parsedLen = Number(valStr.split(',')[0]);
        if (Number.isFinite(parsedLen) && parsedLen > 0) contentLengthValue = parsedLen;
      }
      if (lower === 'transfer-encoding') hasTransferEncoding = true;
      if (lower === 'upgrade' && /\bh2c\b/i.test(valStr)) hasUpgradeH2c = true;
      if (canon === 'http2-settings') hasHttp2Settings = true;

      // 1. Identity header spoofing from untrusted source (catches -, _, . variants!)
      if (identitySet.has(canon) && !sourceTrusted) {
        strippedHeaders.push(key);
        findings.push({
          code: 'FORWARD_AUTH_SPOOF_BLOCKED',
          severity: 'critical',
          header: key,
          message: `Untrusted source ${remoteIp} attempted to inject forward_auth identity header "${key}" (CVE-2026-30851 / CVE-2026-54764).`
        });
        continue;
      }

      // Strip untrusted X-Forwarded-* headers silently so spoofed IPs are ignored
      if (FORWARDED_META_HEADERS.has(canon) && !sourceTrusted) {
        strippedHeaders.push(key);
        continue;
      }

      sanitizedHeaders[key] = rawVal;
    }

    // 2. Cleartext HTTP/2 upgrade (h2c) smuggling check (CVE-2026-88008)
    if (hasUpgradeH2c || hasHttp2Settings) {
      if (hasHttp2Settings) strippedHeaders.push('HTTP2-Settings');
      findings.push({
        code: 'H2C_SMUGGLE_BLOCKED',
        severity: 'critical',
        header: hasUpgradeH2c ? 'Upgrade' : 'HTTP2-Settings',
        message: 'Cleartext HTTP/2 upgrade (Upgrade: h2c / HTTP2-Settings) blocked to prevent reverse-proxy ACL bypass.'
      });
    }

    // 3. CONNECT with request body on HTTP/1.x shared upstream pool (CVE-2026-71324)
    const hasBody = Boolean(src.hasBody) || contentLengthValue > 0 || hasTransferEncoding;
    if (method === 'CONNECT' && hasBody && /^1\./.test(upstreamHttpVersion)) {
      findings.push({
        code: 'CONNECT_DESYNC_BLOCKED',
        severity: 'critical',
        message: `HTTP/${upstreamHttpVersion} CONNECT request carrying a body blocked to prevent keep-alive connection pool desync.`
      });
    }

    // 4. Dual Content-Length + Transfer-Encoding smuggling (TE-CL / CL-TE)
    if (hasContentLength && hasTransferEncoding) {
      findings.push({
        code: 'TE_CL_SMUGGLE',
        severity: 'critical',
        message: 'Simultaneous Transfer-Encoding and Content-Length headers detected (RFC 9112 request smuggling).'
      });
    }

    const clientIpInfo = resolveTrustedClientIp({
      remoteIp,
      xForwardedFor: xffRaw,
      trustedProxyCidrs
    });
    const block = renderHardenedProxyTrustBlock({
      trustedProxyCidrs,
      authCopyHeaders,
      stripIdentityHeaders: strippedHeaders
    });

    const blocked = findings.length > 0;
    return {
      ok: true,
      allowed: !blocked,
      blocked,
      code: blocked ? findings[0].code : 'PROXY_REQUEST_CLEAN',
      sourceTrusted,
      trustedClientIp: clientIpInfo.clientIp,
      spoofedXffIgnored: clientIpInfo.spoofedXffIgnored,
      findings,
      codes: Array.from(new Set(findings.map((f) => f.code))),
      strippedHeaders: Array.from(new Set(strippedHeaders)),
      sanitizedHeaders,
      caddyfile: block.caddyfile,
      evaluatedAt: new Date().toISOString()
    };
  }
}

const defaultProxyTrustGuardService = new ProxyTrustGuardService();

const exported = Object.assign(defaultProxyTrustGuardService, {
  ProxyTrustGuardService,
  DEFAULT_TRUSTED_PROXIES,
  BUILTIN_IDENTITY_HEADERS,
  evaluateProxyRequest: ProxyTrustGuardService.prototype.evaluateProxyRequest.bind(defaultProxyTrustGuardService),
  resolveTrustedClientIp: ProxyTrustGuardService.prototype.resolveTrustedClientIp.bind(defaultProxyTrustGuardService),
  renderHardenedProxyTrustBlock: ProxyTrustGuardService.prototype.renderHardenedProxyTrustBlock.bind(defaultProxyTrustGuardService),
  upsertProxyTrustPolicy: ProxyTrustGuardService.prototype.upsertProxyTrustPolicy.bind(defaultProxyTrustGuardService),
  getProxyTrustPolicy: ProxyTrustGuardService.prototype.getProxyTrustPolicy.bind(defaultProxyTrustGuardService)
});

module.exports = exported;
