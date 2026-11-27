'use strict';

/**
 * Culkibo Container Egress & Firewall (`DOCKER-USER` / `nftables`) Drift Auditor.
 *
 * Addresses Docker 29 `--firewall-backend=nftables` `DOCKER-USER` regressions,
 * `firewalld` `br-*` custom-bridge bypasses, `coolify#12336`, and `dokploy#2486`
 * in zero runtime npm dependencies:
 *  - Atomic `0o600` persistence in `CULKIBO_DATA_DIR/data/egress-policies.json`.
 *  - Pure-JS IPv4/IPv6 CIDR matcher (including IPv4-mapped IPv6 `::ffff:...`).
 *  - Flags cloud metadata egress (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`),
 *    unauthorized private-LAN lateral movement (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`),
 *    and non-allowlisted outbound sockets.
 *  - Detects missing `DOCKER-USER` / `nftables` forward-drop chains and bridge drift (`docker0` vs `br-*`).
 *  - Guarantees generated `suggestedRules` ALWAYS preserve SSH (`22`), HTTP (`80`), and HTTPS (`443`)
 *    (`antiLockoutSafe: true`).
 */

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const path = require('path');

const MANDATORY_ADMIN_PORTS = Object.freeze([22, 80, 443]);

const DEFAULT_EGRESS_POLICY = Object.freeze({
  mode: 'allowlist',
  allowedCidrs: /** @type {string[]} */ ([]),
  allowedDomains: /** @type {string[]} */ ([]),
  blockMetadata: true,
  blockPrivateLan: true,
  preserveAdminPorts: [22, 80, 443]
});

const VALID_MODES = new Set(['allowlist', 'monitor', 'permissive']);
const VALID_BACKENDS = new Set(['nftables', 'iptables']);

const CLOUD_METADATA_HOSTS = new Set([
  'metadata.google.internal',
  'metadata.goog',
  'metadata',
  'instance-data',
  '169.254.169.254',
  '169.254.170.2',
  '100.100.100.200',
  'fd00:ec2::254'
]);

const PRIVATE_IPV4_CIDRS = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16'
];

const METADATA_IPV4_CIDRS = [
  '169.254.169.254/32',
  '169.254.170.2/32',
  '100.100.100.200/32'
];

const PRIVATE_IPV6_CIDRS = [
  'fc00::/7',
  'fe80::/10'
];

/**
 * @typedef {object} EgressPolicy
 * @property {string} projectId
 * @property {'allowlist' | 'monitor' | 'permissive'} mode
 * @property {string[]} allowedCidrs
 * @property {string[]} allowedDomains
 * @property {boolean} blockMetadata
 * @property {boolean} blockPrivateLan
 * @property {number[]} preserveAdminPorts
 * @property {string | null} updatedAt
 */

/**
 * @typedef {object} EgressViolation
 * @property {string} ruleId
 * @property {'critical' | 'high' | 'medium' | 'low'} severity
 * @property {string} target
 * @property {number | null} port
 * @property {string} protocol
 * @property {string} reason
 * @property {string} remediation
 */

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
 * Creates an HTTP-annotated validation Error.
 * @param {string} code
 * @param {string} msg
 * @param {number} [status]
 */
function egressError(code, msg, status = 400) {
  const err = /** @type {any} */ (new Error(msg));
  err.code = code;
  err.status = status;
  return err;
}

/**
 * Parses an IPv4 dotted quad to an unsigned 32-bit integer, or null if invalid.
 * @param {string} ip
 * @returns {number | null}
 */
function ipv4ToInt(ip) {
  if (net.isIP(ip) !== 4) return null;
  const parts = ip.split('.').map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return (((parts[0] << 24) >>> 0) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/**
 * Parses an IPv6 address (including `::` shorthand and IPv4-mapped tails) into a 128-bit BigInt.
 * @param {string} rawIp
 * @returns {bigint | null}
 */
function ipv6ToBigInt(rawIp) {
  const clean = rawIp.trim().toLowerCase().replace(/^\[|\]$/g, '').split('%')[0];
  if (net.isIP(clean) !== 6) return null;

  let expanded = clean;
  if (expanded.includes('.')) {
    const lastColon = expanded.lastIndexOf(':');
    const v4Part = expanded.slice(lastColon + 1);
    const v4Int = ipv4ToInt(v4Part);
    if (v4Int === null) return null;
    const hi = ((v4Int >>> 16) & 0xffff).toString(16);
    const lo = (v4Int & 0xffff).toString(16);
    expanded = `${expanded.slice(0, lastColon)}:${hi}:${lo}`;
  }

  const sides = expanded.split('::');
  if (sides.length > 2) return null;
  const left = sides[0] ? sides[0].split(':').filter(Boolean) : [];
  const right = sides.length === 2 && sides[1] ? sides[1].split(':').filter(Boolean) : [];
  const missing = 8 - (left.length + right.length);
  if (missing < 0) return null;

  const groups = sides.length === 2
    ? [...left, ...Array(missing).fill('0'), ...right]
    : left;
  if (groups.length !== 8) return null;

  let result = 0n;
  for (const g of groups) {
    const val = parseInt(g, 16);
    if (!Number.isFinite(val) || val < 0 || val > 0xffff) return null;
    result = (result << 16n) | BigInt(val);
  }
  return result;
}

/**
 * Extracts IPv4 from an IPv4-mapped IPv6 address (e.g. `::ffff:169.254.169.254`) if applicable.
 * @param {string} ip
 * @returns {string}
 */
function unwrapMappedIpv4(ip) {
  const clean = ip.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (net.isIP(clean) !== 6) return clean;
  const v6 = ipv6ToBigInt(clean);
  if (v6 === null) return clean;
  const prefixMask = 0xffffn << 32n;
  if ((v6 >> 32n) === 0xffffn && (v6 & prefixMask) === prefixMask) {
    const v4 = Number(v6 & 0xffffffffn);
    return `${(v4 >>> 24) & 255}.${(v4 >>> 16) & 255}.${(v4 >>> 8) & 255}.${v4 & 255}`;
  }
  return clean;
}

/**
 * Checks whether an IPv4 or IPv6 address falls inside a CIDR block (or exact IP string).
 * @param {string} cidr
 * @param {string} rawIp
 * @returns {boolean}
 */
function cidrContainsIp(cidr, rawIp) {
  if (typeof cidr !== 'string' || typeof rawIp !== 'string') return false;
  const ip = unwrapMappedIpv4(rawIp);
  const trimmedCidr = cidr.trim().toLowerCase();
  if (!trimmedCidr) return false;

  const [rawBase, rawPrefix] = trimmedCidr.split('/');
  const base = unwrapMappedIpv4(rawBase);
  const ipVer = net.isIP(ip);
  const baseVer = net.isIP(base);
  if (ipVer === 0 || baseVer === 0 || ipVer !== baseVer) return false;

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
 * Checks whether a host/IP points to a cloud instance metadata endpoint.
 * @param {string} rawHost
 * @returns {boolean}
 */
function isCloudMetadataTarget(rawHost) {
  const clean = unwrapMappedIpv4(String(rawHost || '').trim().toLowerCase().replace(/^\[|\]$/g, ''));
  if (!clean) return false;
  if (CLOUD_METADATA_HOSTS.has(clean) || clean.endsWith('.metadata.google.internal')) return true;
  const ipVer = net.isIP(clean);
  if (ipVer === 4) {
    return METADATA_IPV4_CIDRS.some((c) => cidrContainsIp(c, clean));
  }
  if (ipVer === 6) {
    return cidrContainsIp('fd00:ec2::254/128', clean) || cidrContainsIp('fe80::a9fe:a9fe/128', clean);
  }
  return false;
}

/**
 * Checks whether an IP belongs to RFC1918 / IPv6 ULA / link-local private LAN ranges.
 * @param {string} rawHost
 * @returns {boolean}
 */
function isPrivateLanIp(rawHost) {
  const clean = unwrapMappedIpv4(String(rawHost || '').trim().toLowerCase().replace(/^\[|\]$/g, ''));
  const ipVer = net.isIP(clean);
  if (ipVer === 4) {
    return PRIVATE_IPV4_CIDRS.some((c) => cidrContainsIp(c, clean));
  }
  if (ipVer === 6) {
    return PRIVATE_IPV6_CIDRS.some((c) => cidrContainsIp(c, clean));
  }
  return false;
}

/**
 * Matches a domain against exact or wildcard (`*.example.com`) allowlist entries.
 * @param {string} host
 * @param {string[]} allowedDomains
 * @returns {boolean}
 */
function matchesAllowedDomain(host, allowedDomains) {
  const clean = String(host || '').trim().toLowerCase().replace(/\.$/, '');
  if (!clean || !Array.isArray(allowedDomains) || allowedDomains.length === 0) return false;
  for (const rawPattern of allowedDomains) {
    const pattern = String(rawPattern || '').trim().toLowerCase().replace(/\.$/, '');
    if (!pattern) continue;
    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(2);
      if (suffix && (clean === suffix || clean.endsWith(`.${suffix}`))) return true;
    } else if (clean === pattern) {
      return true;
    }
  }
  return false;
}

/**
 * Validates and normalizes an IP/CIDR entry.
 * @param {string} raw
 * @returns {string}
 */
function normalizeCidr(raw) {
  const trimmed = String(raw || '').trim().toLowerCase();
  if (!trimmed) throw egressError('INVALID_CIDR', 'CIDR entry must be a non-empty string');
  const [base, prefixStr] = trimmed.split('/');
  const ipVer = net.isIP(base);
  if (ipVer === 0) throw egressError('INVALID_CIDR', `Invalid IP/CIDR "${trimmed}"`);
  if (prefixStr !== undefined) {
    const prefix = Number(prefixStr);
    const maxBits = ipVer === 4 ? 32 : 128;
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxBits) {
      throw egressError('INVALID_CIDR', `Invalid CIDR prefix "${trimmed}"`);
    }
  }
  return trimmed;
}

/**
 * Normalizes and validates a project egress policy while always preserving mandatory admin ports.
 * @param {string} projectId
 * @param {Record<string, any>} partial
 * @param {EgressPolicy | null} [existing]
 * @returns {EgressPolicy}
 */
function normalizeEgressPolicy(projectId, partial, existing = null) {
  const src = partial && typeof partial === 'object' ? partial : {};
  const base = existing || { projectId, ...DEFAULT_EGRESS_POLICY, updatedAt: null };

  const mode = src.mode !== undefined ? String(src.mode).trim().toLowerCase() : base.mode;
  if (!VALID_MODES.has(mode)) {
    throw egressError('INVALID_POLICY', `mode must be one of: ${Array.from(VALID_MODES).join(', ')}`);
  }

  const rawCidrs = src.allowedCidrs !== undefined ? src.allowedCidrs : base.allowedCidrs;
  if (!Array.isArray(rawCidrs)) {
    throw egressError('INVALID_POLICY', 'allowedCidrs must be an array of IP/CIDR strings');
  }
  const allowedCidrs = Array.from(new Set(rawCidrs.map((c) => normalizeCidr(c))));

  const rawDomains = src.allowedDomains !== undefined ? src.allowedDomains : base.allowedDomains;
  if (!Array.isArray(rawDomains)) {
    throw egressError('INVALID_POLICY', 'allowedDomains must be an array of hostnames');
  }
  const allowedDomains = Array.from(
    new Set(
      rawDomains
        .filter((d) => typeof d === 'string' && d.trim().length > 0)
        .map((d) => d.trim().toLowerCase().slice(0, 253))
    )
  );

  const blockMetadata = src.blockMetadata !== undefined ? Boolean(src.blockMetadata) : Boolean(base.blockMetadata);
  const blockPrivateLan = src.blockPrivateLan !== undefined ? Boolean(src.blockPrivateLan) : Boolean(base.blockPrivateLan);

  const rawPorts = src.preserveAdminPorts !== undefined ? src.preserveAdminPorts : base.preserveAdminPorts;
  /** @type {Set<number>} */
  const portSet = new Set(MANDATORY_ADMIN_PORTS);
  if (Array.isArray(rawPorts)) {
    for (const p of rawPorts) {
      const n = Math.round(Number(p));
      if (Number.isInteger(n) && n >= 1 && n <= 65535) portSet.add(n);
    }
  }

  return {
    projectId,
    mode: /** @type {'allowlist' | 'monitor' | 'permissive'} */ (mode),
    allowedCidrs,
    allowedDomains,
    blockMetadata,
    blockPrivateLan,
    preserveAdminPorts: Array.from(portSet).sort((a, b) => a - b),
    updatedAt: new Date().toISOString()
  };
}

/**
 * Parses an observed outbound socket (string or object) into a normalized descriptor.
 * @param {any} raw
 */
function parseObservedSocket(raw) {
  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (!trimmed) return null;
    if (/^https?:\/\//i.test(trimmed)) {
      try {
        const u = new URL(trimmed);
        const port = u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80);
        return {
          target: unwrapMappedIpv4(u.hostname),
          port,
          protocol: 'tcp'
        };
      } catch (e) {
        return null;
      }
    }
    // Bracketed IPv6 [fd00:ec2::254]:80
    const v6Match = trimmed.match(/^\[([^\]]+)\](?::(\d+))?$/);
    if (v6Match) {
      return {
        target: unwrapMappedIpv4(v6Match[1]),
        port: v6Match[2] ? Number(v6Match[2]) : null,
        protocol: 'tcp'
      };
    }
    // Bare IPv6
    if (net.isIP(trimmed) === 6) {
      return { target: unwrapMappedIpv4(trimmed), port: null, protocol: 'tcp' };
    }
    // host:port
    const colonIdx = trimmed.lastIndexOf(':');
    if (colonIdx > 0 && /^\d+$/.test(trimmed.slice(colonIdx + 1))) {
      return {
        target: unwrapMappedIpv4(trimmed.slice(0, colonIdx)),
        port: Number(trimmed.slice(colonIdx + 1)),
        protocol: 'tcp'
      };
    }
    return { target: unwrapMappedIpv4(trimmed), port: null, protocol: 'tcp' };
  }

  if (raw && typeof raw === 'object') {
    const rawTarget = raw.remoteIp || raw.remoteHost || raw.destination || raw.dest || raw.dst || raw.ip || raw.host || raw.address || '';
    const strTarget = String(rawTarget).trim();
    if (!strTarget) return null;
    const parsed = parseObservedSocket(strTarget);
    if (!parsed) return null;
    const rawPort = raw.remotePort !== undefined ? raw.remotePort : raw.port;
    const portNum = rawPort !== undefined && rawPort !== null && Number.isFinite(Number(rawPort))
      ? Math.round(Number(rawPort))
      : parsed.port;
    const protocol = typeof (raw.protocol || raw.proto) === 'string'
      ? String(raw.protocol || raw.proto).trim().toLowerCase()
      : parsed.protocol;
    return {
      target: parsed.target,
      port: portNum,
      protocol: protocol || 'tcp'
    };
  }
  return null;
}

/**
 * Generates deterministic, anti-lockout-safe `nftables` or `iptables` egress rules.
 * Always preserves SSH (`22`), HTTP (`80`), and HTTPS (`443`).
 *
 * @param {EgressPolicy} policy
 * @param {'nftables' | 'iptables'} backend
 * @returns {string[]}
 */
function buildSuggestedFirewallRules(policy, backend) {
  const ports = Array.from(new Set([...MANDATORY_ADMIN_PORTS, ...(policy.preserveAdminPorts || [])]))
    .sort((a, b) => a - b);
  const v4Allow = policy.allowedCidrs.filter((c) => net.isIP(c.split('/')[0]) === 4);
  const v6Allow = policy.allowedCidrs.filter((c) => net.isIP(c.split('/')[0]) === 6);

  if (backend === 'iptables') {
    /** @type {string[]} */
    const rules = [
      'iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
      `iptables -I INPUT 2 -p tcp -m multiport --dports ${ports.join(',')} -j ACCEPT`,
      'iptables -N DOCKER-USER',
      'iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'
    ];
    if (policy.blockMetadata) {
      rules.push('iptables -I DOCKER-USER 2 -i br-+ -d 169.254.169.254/32 -j DROP');
      rules.push('iptables -I DOCKER-USER 3 -i docker0 -d 169.254.169.254/32 -j DROP');
      rules.push('ip6tables -I DOCKER-USER 1 -d fd00:ec2::254/128 -j DROP');
    }
    for (const cidr of v4Allow) {
      rules.push(`iptables -A DOCKER-USER -d ${cidr} -j ACCEPT`);
    }
    for (const cidr of v6Allow) {
      rules.push(`ip6tables -A DOCKER-USER -d ${cidr} -j ACCEPT`);
    }
    if (policy.blockPrivateLan) {
      for (const lan of PRIVATE_IPV4_CIDRS) {
        rules.push(`iptables -A DOCKER-USER -i br-+ -d ${lan} -j DROP`);
        rules.push(`iptables -A DOCKER-USER -i docker0 -d ${lan} -j DROP`);
      }
    }
    if (policy.mode === 'allowlist') {
      rules.push('iptables -A DOCKER-USER -i br-+ ! -o br-+ -j DROP');
      rules.push('iptables -A DOCKER-USER -i docker0 ! -o docker0 -j DROP');
    }
    rules.push('iptables -A DOCKER-USER -j RETURN');
    return rules;
  }

  // Default: Docker 29+ `nftables` ruleset with explicit anti-lockout input chain & DOCKER-USER forward chain
  /** @type {string[]} */
  const nft = [
    'table inet culkibo_egress {',
    '  chain input_anti_lockout {',
    '    type filter hook input priority 0; policy accept;',
    '    ct state established,related accept',
    `    tcp dport { ${ports.join(', ')} } accept`,
    '  }',
    '  chain DOCKER-USER {',
    '    type filter hook forward priority -1; policy accept;',
    '    ct state established,related accept'
  ];
  if (policy.blockMetadata) {
    nft.push('    iifname { "docker0", "br-*" } ip daddr { 169.254.169.254, 169.254.170.2 } drop');
    nft.push('    iifname { "docker0", "br-*" } ip6 daddr fd00:ec2::254 drop');
  }
  if (v4Allow.length > 0) {
    nft.push(`    iifname { "docker0", "br-*" } ip daddr { ${v4Allow.join(', ')} } accept`);
  }
  if (v6Allow.length > 0) {
    nft.push(`    iifname { "docker0", "br-*" } ip6 daddr { ${v6Allow.join(', ')} } accept`);
  }
  if (policy.blockPrivateLan) {
    nft.push('    iifname { "docker0", "br-*" } ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } drop');
    nft.push('    iifname { "docker0", "br-*" } ip6 daddr { fc00::/7, fe80::/10 } drop');
  }
  if (policy.mode === 'allowlist') {
    nft.push('    iifname { "docker0", "br-*" } oifname != { "docker0", "br-*" } drop');
  }
  nft.push('  }');
  nft.push('}');
  return nft;
}

/**
 * Verifies generated rules explicitly allow all mandatory admin ports (`22`, `80`, `443`).
 * @param {string[]} rules
 * @param {number[]} ports
 * @returns {boolean}
 */
function verifyAntiLockoutSafe(rules, ports) {
  const joined = rules.join('\n');
  const hasAcceptRule = /(tcp dport \{[^}]+\} accept|--dports [0-9,]+ -j ACCEPT)/i.test(joined);
  if (!hasAcceptRule) return false;
  return ports.every((p) => new RegExp(`\\b${p}\\b`).test(joined));
}

class EgressFirewallService {
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
    return path.join(this.resolveDataDir(), 'egress-policies.json');
  }

  /** @returns {Record<string, EgressPolicy>} */
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

  /** @param {Record<string, EgressPolicy>} policies */
  _saveMap(policies) {
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({ schemaVersion: 1, updatedAt: new Date().toISOString(), policies }, null, 2) + '\n'
    );
  }

  /**
   * Returns a project's egress policy (or defaults merged with `projectId`).
   * @param {string} projectId
   * @returns {EgressPolicy}
   */
  getEgressPolicy(projectId) {
    const id = String(projectId || 'default').trim().slice(0, 128) || 'default';
    const map = this._loadMap();
    if (map[id]) {
      return {
        ...DEFAULT_EGRESS_POLICY,
        ...map[id],
        projectId: id,
        allowedCidrs: Array.isArray(map[id].allowedCidrs) ? [...map[id].allowedCidrs] : [],
        allowedDomains: Array.isArray(map[id].allowedDomains) ? [...map[id].allowedDomains] : [],
        preserveAdminPorts: Array.isArray(map[id].preserveAdminPorts)
          ? Array.from(new Set([...MANDATORY_ADMIN_PORTS, ...map[id].preserveAdminPorts])).sort((a, b) => a - b)
          : [...MANDATORY_ADMIN_PORTS]
      };
    }
    return {
      projectId: id,
      ...DEFAULT_EGRESS_POLICY,
      allowedCidrs: [],
      allowedDomains: [],
      preserveAdminPorts: [...MANDATORY_ADMIN_PORTS],
      updatedAt: null
    };
  }

  /**
   * Validates and atomically persists a project's egress firewall policy.
   * @param {string} projectId
   * @param {Record<string, any>} policy
   * @returns {EgressPolicy}
   */
  saveEgressPolicy(projectId, policy = {}) {
    const id = String(projectId || '').trim().slice(0, 128);
    if (!id) throw egressError('INVALID_PROJECT_ID', 'projectId is required');
    const existing = this.getEgressPolicy(id);
    const normalized = normalizeEgressPolicy(id, policy, existing);
    const map = this._loadMap();
    map[id] = normalized;
    this._saveMap(map);
    return {
      ...normalized,
      allowedCidrs: [...normalized.allowedCidrs],
      allowedDomains: [...normalized.allowedDomains],
      preserveAdminPorts: [...normalized.preserveAdminPorts]
    };
  }

  /**
   * Audits observed container outbound sockets and host `nftables`/`iptables` rules for
   * cloud metadata leaks, unauthorized private-LAN/egress connections, and missing `DOCKER-USER`
   * forward-drop chains while guaranteeing anti-lockout preservation of SSH/HTTP/HTTPS.
   *
   * @param {{
   *   projectId?: string,
   *   observedSockets?: any[],
   *   firewallRules?: string[] | string,
   *   backend?: 'nftables' | 'iptables' | string
   * }} input
   */
  auditFirewallAndEgress(input = {}) {
    if (!input || typeof input !== 'object') {
      throw egressError('INVALID_INPUT', 'auditFirewallAndEgress requires an input object');
    }

    const projectId = String(input.projectId || 'default').trim().slice(0, 128) || 'default';
    const rawBackend = input.backend === undefined ? 'nftables' : String(input.backend).trim().toLowerCase();
    if (!VALID_BACKENDS.has(rawBackend)) {
      throw egressError('INVALID_BACKEND', 'backend must be "nftables" or "iptables"');
    }
    const backend = /** @type {'nftables' | 'iptables'} */ (rawBackend);
    const policy = this.getEgressPolicy(projectId);

    const rawSockets = Array.isArray(input.observedSockets) ? input.observedSockets : [];
    const normalizedSockets = rawSockets.map(parseObservedSocket).filter(Boolean);

    const ruleLines = Array.isArray(input.firewallRules)
      ? input.firewallRules.map((r) => String(r || ''))
      : (typeof input.firewallRules === 'string' ? input.firewallRules.split(/\r?\n/) : []);
    const rulesBlob = ruleLines.join('\n');

    /** @type {EgressViolation[]} */
    const violations = [];
    /** @type {string[]} */
    const missingChains = [];
    let riskPoints = 0;

    // 1. Audit observed outbound sockets
    for (const sock of normalizedSockets) {
      if (!sock) continue;
      const target = sock.target;
      const ipVer = net.isIP(target);

      // Cloud metadata check (highest severity)
      if (policy.blockMetadata && isCloudMetadataTarget(target)) {
        riskPoints += 40;
        violations.push({
          ruleId: 'CLOUD_METADATA_EGRESS',
          severity: 'critical',
          target,
          port: sock.port,
          protocol: sock.protocol,
          reason: `Container initiated egress to cloud metadata endpoint (${target})`,
          remediation: 'Block 169.254.169.254 and fd00:ec2::254 in DOCKER-USER/nftables forward chain and require IMDSv2 hop-limit=1'
        });
        continue;
      }

      const isAllowed = ipVer !== 0
        ? policy.allowedCidrs.some((c) => cidrContainsIp(c, target))
        : matchesAllowedDomain(target, policy.allowedDomains);

      if (isAllowed) continue;

      if (policy.blockPrivateLan && ipVer !== 0 && isPrivateLanIp(target)) {
        riskPoints += 25;
        violations.push({
          ruleId: 'UNAUTHORIZED_PRIVATE_LAN_EGRESS',
          severity: 'high',
          target,
          port: sock.port,
          protocol: sock.protocol,
          reason: `Unauthorized container egress to private LAN address (${target}) not in allowedCidrs`,
          remediation: 'Deny RFC1918/ULA lateral egress from docker0 and br-* bridges or explicitly allowlist required internal CIDRs'
        });
        continue;
      }

      if (policy.mode === 'allowlist' || policy.mode === 'monitor') {
        riskPoints += 15;
        violations.push({
          ruleId: 'UNALLOWLISTED_EGRESS',
          severity: 'medium',
          target,
          port: sock.port,
          protocol: sock.protocol,
          reason: `Outbound socket to "${target}" is not permitted by project egress allowlist`,
          remediation: 'Add approved destination CIDR/domain to egress policy or drop unapproved container egress in DOCKER-USER'
        });
      }
    }

    // 2. Audit host firewall rules for missing DOCKER-USER / forward-drop chains & bridge drift
    const hasDockerUserChain = /\bDOCKER-USER\b/i.test(rulesBlob);
    if (!hasDockerUserChain) {
      missingChains.push('DOCKER-USER');
      riskPoints += 20;
      violations.push({
        ruleId: 'MISSING_DOCKER_USER_CHAIN',
        severity: 'high',
        target: `${backend}:DOCKER-USER`,
        port: null,
        protocol: 'any',
        reason: `Host ${backend} ruleset is missing the DOCKER-USER chain required to filter container egress`,
        remediation: 'Install the suggested DOCKER-USER chain covering both docker0 and br-* custom Docker bridges'
      });
    }

    const hasForwardDrop = backend === 'nftables'
      ? (/hook\s+forward[\s\S]*?\b(drop|reject)\b/i.test(rulesBlob) || /chain\s+DOCKER-USER[\s\S]*?\b(drop|reject)\b/i.test(rulesBlob))
      : (/DOCKER-USER[^\n]*-j\s+(DROP|REJECT)/i.test(rulesBlob));

    if (!hasForwardDrop) {
      const chainLabel = backend === 'nftables' ? 'nftables-forward-drop' : 'DOCKER-USER-drop';
      missingChains.push(chainLabel);
      riskPoints += 15;
      violations.push({
        ruleId: 'MISSING_EGRESS_DROP_RULE',
        severity: 'high',
        target: `${backend}:forward-drop`,
        port: null,
        protocol: 'any',
        reason: `No active forward/egress DROP rule detected in ${backend} rules (containers can bypass host firewall)`,
        remediation: 'Apply explicit metadata and default-egress drop rules in DOCKER-USER / nftables forward hook'
      });
    }

    const mentionsDocker0Only = /\bdocker0\b/i.test(rulesBlob) && !/\bbr-[*+]/i.test(rulesBlob);
    if (mentionsDocker0Only) {
      riskPoints += 10;
      violations.push({
        ruleId: 'CUSTOM_BRIDGE_DRIFT',
        severity: 'medium',
        target: 'br-*',
        port: null,
        protocol: 'any',
        reason: 'Firewall rules only match docker0; Compose/Culkibo custom bridge interfaces (br-*) bypass egress filtering',
        remediation: 'Match both "docker0" and "br-*" / "br-+" bridge interfaces in DOCKER-USER rules'
      });
    }

    // Detect dangerous existing input rules that would drop SSH/HTTP/HTTPS
    for (const port of MANDATORY_ADMIN_PORTS) {
      const dropsAdminPort = new RegExp(`(input|INPUT)[^\\n]*(dport|dports)[^\\n]*\\b${port}\\b[^\\n]*(drop|DROP|reject|REJECT)`, 'i').test(rulesBlob);
      if (dropsAdminPort) {
        riskPoints += 20;
        violations.push({
          ruleId: 'ADMIN_PORT_LOCKOUT_RISK',
          severity: 'critical',
          target: `tcp/${port}`,
          port,
          protocol: 'tcp',
          reason: `Existing firewall rules drop mandatory admin/ingress port ${port} on INPUT`,
          remediation: 'Preserve tcp ports 22, 80, and 443 in the input chain before applying any drop policy'
        });
      }
    }

    const suggestedRules = buildSuggestedFirewallRules(policy, backend);
    const antiLockoutSafe = verifyAntiLockoutSafe(suggestedRules, MANDATORY_ADMIN_PORTS.slice());
    const riskScore = Math.min(100, riskPoints);
    const compliant = violations.length === 0 && missingChains.length === 0;

    return {
      ok: true,
      projectId,
      backend,
      policy,
      compliant,
      riskScore,
      violations,
      missingChains,
      antiLockoutSafe,
      preservedAdminPorts: policy.preserveAdminPorts,
      suggestedRules,
      observedSocketCount: normalizedSockets.length,
      auditedAt: new Date().toISOString()
    };
  }
}

const defaultEgressFirewallService = new EgressFirewallService();

const exported = Object.assign(defaultEgressFirewallService, {
  EgressFirewallService,
  DEFAULT_EGRESS_POLICY,
  MANDATORY_ADMIN_PORTS,
  saveEgressPolicy: EgressFirewallService.prototype.saveEgressPolicy.bind(defaultEgressFirewallService),
  getEgressPolicy: EgressFirewallService.prototype.getEgressPolicy.bind(defaultEgressFirewallService),
  auditFirewallAndEgress: EgressFirewallService.prototype.auditFirewallAndEgress.bind(defaultEgressFirewallService)
});

module.exports = exported;
