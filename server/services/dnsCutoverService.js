'use strict';

/**
 * Culkibo Zero-Downtime DNS Cutover, Cloudflare Proxy ACME & TTL Pre-Flight Verifier.
 *
 * Cures `coolify#6271`, `#4552`, `#11831`, `#11957`, `#8987`, and `kamal-proxy#26`/`#107`
 * in zero external dependencies:
 *  - Atomic `0o600` store in `CULKIBO_DATA_DIR/data/dns-cutovers.json`.
 *  - Official Cloudflare IPv4 & IPv6 Anycast CIDR matcher (including `104.16.0.0/13` so
 *    `104.21.10.5` is recognized as Cloudflare proxied rather than a false `DNS_MISMATCH`!).
 *  - Flags `CLOUDFLARE_PROXY_ACME_CONFLICT` when Cloudflare proxy IP meets `http-01` or
 *    `tls-alpn-01`, while approving `dns-01` with clean `_acme-challenge` TXT records.
 *  - Detects stale/conflicting `_acme-challenge` TXT entries (`STALE_ACME_TXT_81058`) and
 *    divergent authoritative `SOA.serial` values (`SOA_SERIAL_DIVERGENT`).
 *  - Generates an ordered 5-phase TTL-lowering cutover plan enforcing
 *    `minPreCutoverWaitSec = Math.max(currentTtlSec, soaRefreshSec)`.
 */

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const path = require('path');

const CLOUDFLARE_IPV4_CIDRS = Object.freeze([
  '173.245.48.0/20',
  '103.21.244.0/22',
  '103.22.200.0/22',
  '103.31.4.0/22',
  '141.101.64.0/18',
  '108.162.192.0/18',
  '190.93.240.0/20',
  '188.114.96.0/20',
  '197.234.240.0/22',
  '198.41.128.0/17',
  '162.158.0.0/15',
  '104.16.0.0/13',
  '104.24.0.0/14',
  '172.64.0.0/13',
  '131.0.72.0/22'
]);

const CLOUDFLARE_IPV6_CIDRS = Object.freeze([
  '2400:cb00::/32',
  '2606:4700::/32',
  '2803:f800::/32',
  '2405:b500::/32',
  '2405:8100::/32',
  '2a06:98c0::/29',
  '2c0f:f248::/32'
]);

const VALID_CHALLENGE_MODES = new Set(['http-01', 'tls-alpn-01', 'dns-01']);

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
function dnsError(code, msg, status = 400) {
  const err = /** @type {any} */ (new Error(msg));
  err.code = code;
  err.status = status;
  return err;
}

/**
 * Normalizes a domain hostname.
 * @param {any} raw
 * @returns {string}
 */
function normalizeDomain(raw) {
  const d = typeof raw === 'string' ? raw.trim().toLowerCase().replace(/\.$/, '') : '';
  if (!d || d.length > 253 || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(d) || !d.includes('.')) {
    throw dnsError('INVALID_DOMAIN', `Invalid FQDN domain "${d}"`);
  }
  return d;
}

/**
 * Parses an IPv4 dotted quad to unsigned 32-bit integer.
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
 * Checks whether an IP falls inside an IPv4 or IPv6 CIDR.
 * @param {string} cidr
 * @param {string} ip
 * @returns {boolean}
 */
function cidrContainsIp(cidr, ip) {
  const [base, prefixStr] = cidr.split('/');
  const ipVer = net.isIP(ip);
  const baseVer = net.isIP(base);
  if (ipVer === 0 || ipVer !== baseVer) return false;
  if (ipVer === 4) {
    const prefix = Number(prefixStr);
    const ipInt = ipv4ToInt(ip);
    const baseInt = ipv4ToInt(base);
    if (ipInt === null || baseInt === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
    if (prefix === 0) return true;
    const mask = (0xffffffff << (32 - prefix)) >>> 0;
    return ((ipInt & mask) >>> 0) === ((baseInt & mask) >>> 0);
  }
  const prefix = Number(prefixStr);
  const ipBig = ipv6ToBigInt(ip);
  const baseBig = ipv6ToBigInt(base);
  if (ipBig === null || baseBig === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 128) return false;
  if (prefix === 0) return true;
  const shift = BigInt(128 - prefix);
  return (ipBig >> shift) === (baseBig >> shift);
}

/**
 * Accurately determines whether an IPv4 or IPv6 address belongs to Cloudflare's Anycast proxy ranges.
 * @param {string} rawIp
 * @returns {boolean}
 */
function isCloudflareProxyIp(rawIp) {
  if (typeof rawIp !== 'string') return false;
  const ip = rawIp.trim().toLowerCase().replace(/^\[|\]$/g, '');
  const ver = net.isIP(ip);
  if (ver === 4) return CLOUDFLARE_IPV4_CIDRS.some((c) => cidrContainsIp(c, ip));
  if (ver === 6) return CLOUDFLARE_IPV6_CIDRS.some((c) => cidrContainsIp(c, ip));
  return false;
}

class DnsCutoverService {
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
    return path.join(this.resolveDataDir(), 'dns-cutovers.json');
  }

  /** @returns {Record<string, any>} */
  _loadMap() {
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) return {};
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      return parsed && parsed.domains && typeof parsed.domains === 'object' ? parsed.domains : {};
    } catch (e) {
      return {};
    }
  }

  /** @param {Record<string, any>} domains */
  _saveMap(domains) {
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({ schemaVersion: 1, updatedAt: new Date().toISOString(), domains }, null, 2) + '\n'
    );
  }

  /**
   * Delegates to `isCloudflareProxyIp`.
   * @param {string} ip
   * @returns {boolean}
   */
  isCloudflareProxyIp(ip) {
    return isCloudflareProxyIp(ip);
  }

  /**
   * Pre-flight verification of DNS records, Cloudflare proxy ACME conflicts, stale
   * `_acme-challenge` TXT entries (`81058`), and authoritative `SOA.serial` convergence.
   *
   * @param {{
   *   domain: string,
   *   targetIpv4?: string | null,
   *   targetIpv6?: string | null,
   *   challengeMode?: 'http-01' | 'tls-alpn-01' | 'dns-01' | string,
   *   recordsSnapshot?: Record<string, any> | null
   * }} input
   */
  preflightDnsCutover(input) {
    if (!input || typeof input !== 'object') {
      throw dnsError('INVALID_INPUT', 'preflightDnsCutover requires a configuration object');
    }
    const domain = normalizeDomain(input.domain);
    const rawMode = String(input.challengeMode || 'http-01').trim().toLowerCase();
    if (!VALID_CHALLENGE_MODES.has(rawMode)) {
      throw dnsError('INVALID_CHALLENGE_MODE', 'challengeMode must be one of: http-01, tls-alpn-01, dns-01');
    }
    const challengeMode = /** @type {'http-01' | 'tls-alpn-01' | 'dns-01'} */ (rawMode);
    const targetIpv4 = typeof input.targetIpv4 === 'string' && input.targetIpv4.trim() ? input.targetIpv4.trim() : null;
    const targetIpv6 = typeof input.targetIpv6 === 'string' && input.targetIpv6.trim() ? input.targetIpv6.trim().toLowerCase() : null;

    const snap = input.recordsSnapshot && typeof input.recordsSnapshot === 'object' ? input.recordsSnapshot : {};
    /** @type {string[]} */
    const aRecords = Array.isArray(snap.a)
      ? snap.a.map((x) => String(x || '').trim()).filter(Boolean)
      : (Array.isArray(snap.A) ? snap.A.map((x) => String(x || '').trim()).filter(Boolean) : []);
    /** @type {string[]} */
    const aaaaRecords = Array.isArray(snap.aaaa)
      ? snap.aaaa.map((x) => String(x || '').trim().toLowerCase()).filter(Boolean)
      : (Array.isArray(snap.AAAA) ? snap.AAAA.map((x) => String(x || '').trim().toLowerCase()).filter(Boolean) : []);
    /** @type {string[]} */
    const rawTxt = Array.isArray(snap.acmeTxt)
      ? snap.acmeTxt
      : (Array.isArray(snap.txtAcme) ? snap.txtAcme : (Array.isArray(snap.txt) ? snap.txt : []));
    const acmeTxt = rawTxt.map((t) => String(t || '').trim()).filter(Boolean);
    const expectedAcmeTxt = typeof snap.expectedAcmeTxt === 'string' && snap.expectedAcmeTxt.trim()
      ? snap.expectedAcmeTxt.trim()
      : null;

    const rawSerials = Array.isArray(snap.soaSerials)
      ? snap.soaSerials
      : (Array.isArray(snap.nameserverSerials) ? snap.nameserverSerials : []);
    const soaSerials = Array.from(
      new Set(rawSerials.map((s) => Number(s)).filter((n) => Number.isFinite(n)))
    );

    const allIps = [...aRecords, ...aaaaRecords];
    const cloudflareIps = allIps.filter((ip) => isCloudflareProxyIp(ip));
    const isProxied = cloudflareIps.length > 0;

    /** @type {Array<{ code: string, severity: 'critical' | 'high' | 'medium', message: string, remediation: string }>} */
    const blockers = [];
    /** @type {string[]} */
    const warnings = [];

    // 1. Cloudflare orange-cloud proxy ACME conflict check (NEVER misreport as DNS_MISMATCH!)
    if (isProxied && (challengeMode === 'http-01' || challengeMode === 'tls-alpn-01')) {
      blockers.push({
        code: 'CLOUDFLARE_PROXY_ACME_CONFLICT',
        severity: 'critical',
        message: `Domain "${domain}" resolves to Cloudflare Anycast proxy (${cloudflareIps.join(', ')}), which intercepts ACME ${challengeMode} validation.`,
        remediation: 'Switch ACME challengeMode to "dns-01" (Cloudflare API token) OR temporarily set DNS proxy to DNS-Only (grey cloud) during issuance.'
      });
    }

    // 2. Authoritative SOA serial convergence check
    const soaDivergent = soaSerials.length > 1;
    if (soaDivergent) {
      blockers.push({
        code: 'SOA_SERIAL_DIVERGENT',
        severity: 'high',
        message: `Authoritative nameservers report divergent SOA serials (${soaSerials.join(' vs ')}) — zone transfer not yet converged.`,
        remediation: 'Wait for secondary nameservers to sync identical SOA.serial values before triggering DNS cutover or ACME verification.'
      });
    }

    // 3. Stale / duplicate _acme-challenge TXT collision check (Cloudflare error 81058)
    const hasExplicitStaleTxt = snap.staleAcmeTxt === true
      || acmeTxt.some((v) => /^stale\b/i.test(v))
      || (expectedAcmeTxt !== null && acmeTxt.some((v) => v !== expectedAcmeTxt));
    const hasMultiTxtConflict = acmeTxt.length > 1;
    const hasLeftoverTxtUnderNonDns = challengeMode !== 'dns-01' && acmeTxt.length > 0;

    if (hasExplicitStaleTxt || hasMultiTxtConflict || hasLeftoverTxtUnderNonDns) {
      blockers.push({
        code: 'STALE_ACME_TXT_81058',
        severity: 'high',
        message: `Detected stale or colliding _acme-challenge.${domain} TXT record(s) (${acmeTxt.length} entries) that trigger ACME/Cloudflare 81058 renewal failures.`,
        remediation: `Delete obsolete _acme-challenge.${domain} TXT records before issuing or renewing TLS certificates.`
      });
    }

    // 4. Direct origin IP match check (ONLY when NOT proxied behind Cloudflare!)
    if (!isProxied) {
      if (targetIpv4 && aRecords.length > 0 && !aRecords.includes(targetIpv4)) {
        blockers.push({
          code: 'DNS_MISMATCH',
          severity: 'high',
          message: `Observed A records (${aRecords.join(', ')}) do not include target origin IPv4 ${targetIpv4}.`,
          remediation: `Update A record for ${domain} to ${targetIpv4} after lowering TTL.`
        });
      }
      if (targetIpv6 && aaaaRecords.length > 0 && !aaaaRecords.includes(targetIpv6)) {
        blockers.push({
          code: 'DNS_MISMATCH',
          severity: 'high',
          message: `Observed AAAA records (${aaaaRecords.join(', ')}) do not include target origin IPv6 ${targetIpv6}.`,
          remediation: `Update AAAA record for ${domain} to ${targetIpv6} or remove stale AAAA records.`
        });
      }
      if ((targetIpv4 || targetIpv6) && allIps.length === 0) {
        blockers.push({
          code: 'DNS_RECORDS_MISSING',
          severity: 'high',
          message: `No A/AAAA records found in snapshot for "${domain}".`,
          remediation: `Create DNS A/AAAA records pointing "${domain}" to ${targetIpv4 || targetIpv6}.`
        });
      }
    } else if (challengeMode === 'dns-01') {
      warnings.push(`Cloudflare proxy (${cloudflareIps.join(', ')}) active — DNS-01 challenge compatible without disabling orange cloud.`);
    }

    const ready = blockers.length === 0;
    const code = ready ? 'CUTOVER_READY' : blockers[0].code;
    const checkedAt = new Date().toISOString();

    const result = {
      ok: true,
      domain,
      ready,
      code,
      challengeMode,
      isProxied,
      cloudflareIps,
      observedA: aRecords,
      observedAaaa: aaaaRecords,
      acmeTxt,
      soaSerials,
      soaConverged: !soaDivergent,
      targetIpv4,
      targetIpv6,
      blockers,
      warnings,
      checkedAt
    };

    const map = this._loadMap();
    map[domain] = {
      ...(map[domain] || {}),
      domain,
      preflight: result,
      updatedAt: checkedAt
    };
    this._saveMap(map);

    return result;
  }

  /**
   * Builds a 5-phase zero-downtime TTL-lowering DNS cutover plan enforcing
   * `minPreCutoverWaitSec = Math.max(currentTtlSec, soaRefreshSec)` and blocking divergent SOA serials.
   *
   * @param {{
   *   domain: string,
   *   currentTtlSec?: number,
   *   targetTtlSec?: number,
   *   targetIp?: string | null,
   *   acmeMode?: 'http-01' | 'tls-alpn-01' | 'dns-01' | string,
   *   soaRefreshSec?: number,
   *   nameserverSerials?: number[]
   * }} input
   */
  buildTtlCutoverPlan(input) {
    if (!input || typeof input !== 'object') {
      throw dnsError('INVALID_INPUT', 'buildTtlCutoverPlan requires a cutover options object');
    }
    const domain = normalizeDomain(input.domain);
    const currentTtlSec = Math.max(1, Math.min(604800, Math.round(Number(input.currentTtlSec ?? 3600) || 3600)));
    const targetTtlSec = Math.max(1, Math.min(86400, Math.round(Number(input.targetTtlSec ?? 60) || 60)));
    const soaRefreshSec = Math.max(0, Math.min(604800, Math.round(Number(input.soaRefreshSec ?? 0) || 0)));
    const targetIp = typeof input.targetIp === 'string' && input.targetIp.trim() ? input.targetIp.trim() : null;
    const rawAcme = String(input.acmeMode || 'dns-01').trim().toLowerCase();
    if (!VALID_CHALLENGE_MODES.has(rawAcme)) {
      throw dnsError('INVALID_ACME_MODE', 'acmeMode must be one of: http-01, tls-alpn-01, dns-01');
    }
    const acmeMode = /** @type {'http-01' | 'tls-alpn-01' | 'dns-01'} */ (rawAcme);

    const rawSerials = Array.isArray(input.nameserverSerials) ? input.nameserverSerials : [];
    const uniqueSerials = Array.from(new Set(rawSerials.map((s) => Number(s)).filter((n) => Number.isFinite(n))));
    const soaDivergent = uniqueSerials.length > 1;
    const isTargetCloudflareProxied = targetIp ? isCloudflareProxyIp(targetIp) : false;

    /** @type {Array<{ code: string, severity: 'critical' | 'high', message: string }>} */
    const blockers = [];
    if (soaDivergent) {
      blockers.push({
        code: 'SOA_SERIAL_DIVERGENT',
        severity: 'high',
        message: `Cannot execute cutover while authoritative nameservers disagree on SOA.serial (${uniqueSerials.join(' vs ')}).`
      });
    }
    if (isTargetCloudflareProxied && (acmeMode === 'http-01' || acmeMode === 'tls-alpn-01')) {
      blockers.push({
        code: 'CLOUDFLARE_PROXY_ACME_CONFLICT',
        severity: 'critical',
        message: `Target IP ${targetIp} is a Cloudflare proxy address incompatible with ${acmeMode}; use dns-01.`
      });
    }

    const minPreCutoverWaitSec = Math.max(currentTtlSec, soaRefreshSec);
    const verifyWindowSec = Math.max(300, targetTtlSec * 5);
    const restoreTtlSec = Math.max(300, currentTtlSec);

    const phases = [
      {
        phase: 1,
        action: 'lower_ttl',
        title: `Lower DNS TTL from ${currentTtlSec}s to ${targetTtlSec}s`,
        waitSec: 0,
        detail: `Update TTL on ${domain} records to ${targetTtlSec}s without changing target IP yet; purge any stale _acme-challenge.${domain} TXT records.`
      },
      {
        phase: 2,
        action: 'wait_ttl_drain',
        title: `Wait out old TTL & SOA refresh (${minPreCutoverWaitSec}s minimum)`,
        waitSec: minPreCutoverWaitSec,
        detail: `Wait >= ${minPreCutoverWaitSec}s (max(currentTtlSec=${currentTtlSec}s, soaRefreshSec=${soaRefreshSec}s)) so global recursive resolvers evict cached answers.`
      },
      {
        phase: 3,
        action: 'prewarm_origin_tls',
        title: `Pre-warm target origin TLS (${acmeMode}) & healthcheck`,
        waitSec: 30,
        detail: `Provision/verify TLS certificate via ${acmeMode} and confirm HTTP 200 readiness on ${targetIp || 'target origin'} before switching DNS.`
      },
      {
        phase: 4,
        action: 'switch_dns_records',
        title: `Switch ${domain} records to ${targetIp || 'new origin'} at ${targetTtlSec}s TTL`,
        waitSec: targetTtlSec,
        detail: `Atomically update A/AAAA/CNAME to ${targetIp || 'new origin'} and verify identical SOA.serial across all authoritative nameservers.`
      },
      {
        phase: 5,
        action: 'verify_and_restore_ttl',
        title: `Verify traffic for ${verifyWindowSec}s & restore TTL to ${restoreTtlSec}s`,
        waitSec: verifyWindowSec,
        detail: `Watch 5xx/TLS metrics on new origin with fast ${targetTtlSec}s rollback window; once healthy, restore production TTL to ${restoreTtlSec}s.`
      }
    ];

    const blocked = blockers.length > 0;
    const createdAt = new Date().toISOString();
    const plan = {
      ok: true,
      domain,
      ready: !blocked,
      blocked,
      code: blocked ? blockers[0].code : 'PLAN_READY',
      blockers,
      currentTtlSec,
      targetTtlSec,
      soaRefreshSec,
      minPreCutoverWaitSec,
      targetIp,
      acmeMode,
      isTargetCloudflareProxied,
      nameserverSerials: uniqueSerials,
      phases,
      createdAt
    };

    const map = this._loadMap();
    map[domain] = {
      ...(map[domain] || {}),
      domain,
      plan,
      updatedAt: createdAt
    };
    this._saveMap(map);

    return plan;
  }

  /**
   * Retrieves the latest persisted preflight check and cutover plan for `domain`.
   * @param {string} domain
   */
  getCutoverStatus(domain) {
    const clean = normalizeDomain(domain);
    const map = this._loadMap();
    const entry = map[clean] || null;
    return {
      ok: true,
      domain: clean,
      found: Boolean(entry),
      preflight: entry && entry.preflight ? entry.preflight : null,
      plan: entry && entry.plan ? entry.plan : null,
      updatedAt: entry && entry.updatedAt ? entry.updatedAt : null
    };
  }
}

const defaultDnsCutoverService = new DnsCutoverService();

const exported = Object.assign(defaultDnsCutoverService, {
  DnsCutoverService,
  CLOUDFLARE_IPV4_CIDRS,
  CLOUDFLARE_IPV6_CIDRS,
  isCloudflareProxyIp: DnsCutoverService.prototype.isCloudflareProxyIp.bind(defaultDnsCutoverService),
  preflightDnsCutover: DnsCutoverService.prototype.preflightDnsCutover.bind(defaultDnsCutoverService),
  buildTtlCutoverPlan: DnsCutoverService.prototype.buildTtlCutoverPlan.bind(defaultDnsCutoverService),
  getCutoverStatus: DnsCutoverService.prototype.getCutoverStatus.bind(defaultDnsCutoverService)
});

module.exports = exported;
