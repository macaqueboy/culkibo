const fs = require('fs');
const net = require('net');
const path = require('path');
const { atomicWriteJsonSync } = require('./ssrfGuard');
const { hashBcrypt, isBcryptHash } = require('./bcryptHash');

/** Carga perezosa: evita arrastrar dns/ssl/cloudflare en el arranque en frío. */
/** @type {any} */
let _dns = null;
function getDns() {
  if (!_dns) _dns = require('dns').promises;
  return _dns;
}
/** @type {any} */
let _sslManager = null;
function getSslManager() {
  if (!_sslManager) _sslManager = require('./sslManager');
  return _sslManager;
}
/** @type {any} */
let _cloudflareService = null;
function getCloudflareService() {
  if (!_cloudflareService) _cloudflareService = require('./cloudflareService');
  return _cloudflareService;
}

const DOMAINS_FILE = path.join(__dirname, '..', '..', 'data', 'domains.json');
const DOMAIN_REGEX = /^(?:\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const UPDATABLE_DOMAIN_FIELDS = new Set([
  'hostname',
  'projectId',
  'targetPod',
  'targetPort',
  'cloudflareProxied',
  'cloudflareZoneId',
  'cloudflareRecordId',
  'sslStatus',
  'sslCertId',
  'sslProvider',
  'routingMode',
  'canonicalRedirect',
  'securityHeaders',
  'framePolicy',
  'customHeaders',
  'basicAuth',
  'ipAllowlist',
  'maxBodySizeMb',
  'rateLimit',
  'status',
  'serviceId',
  'serviceName',
  'lastCheckedAt',
  'migrationSource'
]);

const HOP_BY_HOP_HEADER_RE = /^(host|content-length|transfer-encoding|connection|keep-alive|upgrade|proxy-authenticate|proxy-authorization|te|trailer)$/i;

/** Valida una IP o CIDR IPv4/IPv6 para la lista blanca de Caddy `client_ip`. */
function isValidCidrOrIp(entry) {
  const clean = String(entry || '').trim();
  if (!clean) return false;
  const parts = clean.split('/');
  if (parts.length > 2) return false;
  const ipKind = net.isIP(parts[0]);
  if (ipKind !== 4 && ipKind !== 6) return false;
  if (parts.length === 2) {
    if (!/^\d{1,3}$/.test(parts[1])) return false;
    const prefix = Number(parts[1]);
    const maxBits = ipKind === 4 ? 32 : 128;
    if (prefix < 0 || prefix > maxBits) return false;
  }
  return true;
}

/** Oculta los hashes bcrypt antes de exponer un dominio en API/JSON público. */
function sanitizeBasicAuthForPublic(basicAuth) {
  if (!basicAuth || typeof basicAuth !== 'object') return null;
  const accounts = Array.isArray(basicAuth.accounts) ? basicAuth.accounts : [];
  return {
    enabled: Boolean(basicAuth.enabled && accounts.length > 0),
    realm: String(basicAuth.realm || 'Acceso protegido'),
    usernames: accounts.map((a) => a.username),
    accountCount: accounts.length
  };
}

/** Rangos CIDR IPv4 oficiales de Cloudflare (parseados a [networkInt, maskInt]). */
const CF_IPV4_RANGES = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
].map((cidr) => {
  const [ip, bitsStr] = cidr.split('/');
  const bits = Number(bitsStr);
  const parts = ip.split('.').map(Number);
  const netInt = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return [netInt & mask, mask];
});

const CF_IPV6_PREFIXES = ['2400:cb00:', '2606:4700:', '2803:f800:', '2405:b500:', '2405:8100:', '2a06:98c0:', '2c0f:f248:'];

/** @param {string} ip */
function isCloudflareIp(ip) {
  const clean = String(ip || '').trim().toLowerCase();
  if (!clean) return false;
  if (clean.includes(':')) {
    return CF_IPV6_PREFIXES.some((p) => clean.startsWith(p));
  }
  const parts = clean.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const ipInt = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  for (let i = 0; i < CF_IPV4_RANGES.length; i++) {
    if ((ipInt & CF_IPV4_RANGES[i][1]) === CF_IPV4_RANGES[i][0]) return true;
  }
  return false;
}

function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`DNS timeout after ${ms}ms`)), ms);
    if (timer.unref) timer.unref();
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

class DomainManager {
  constructor() {
    this.ensureDirectory();
    this.domains = this.loadDomains();
    /** @type {Map<string, any>} */
    this._exactIndex = new Map();
    /** @type {Map<string, any>} */
    this._byId = new Map();
    /** @type {any[]} */
    this._wildcards = [];
    this._version = 1;
    /** @type {{ sslVersion: number, at: number, etag: string, buffer: Buffer | null, wrappedBuffer: Buffer | null } | null} */
    this._serializedCache = null;
    this.rebuildIndex();
  }

  rebuildIndex() {
    this._exactIndex.clear();
    this._byId.clear();
    this._wildcards = [];
    this._serializedCache = null;
    this._version++;
    for (const d of this.domains) {
      if (!d || typeof d.hostname !== 'string') continue;
      if (d.id) this._byId.set(d.id, d);
      const host = d.hostname.toLowerCase();
      if (d.isWildcard && host.startsWith('*.')) {
        this._wildcards.push({ domain: d, root: host.slice(2), suffix: `.${host.slice(2)}` });
      } else {
        this._exactIndex.set(host, d);
      }
    }
    // Ordenar comodines por sufijo más largo primero (`*.staging.a.com` antes que `*.a.com`)
    this._wildcards.sort((a, b) => b.root.length - a.root.length);
  }

  ensureDirectory() {
    const dir = path.dirname(DOMAINS_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  loadDomains() {
    try {
      if (fs.existsSync(DOMAINS_FILE)) {
        return JSON.parse(fs.readFileSync(DOMAINS_FILE, 'utf8'));
      }
    } catch (e) {
      console.error('[DomainManager] Error loading domains:', e.message);
    }
    // Default initial seed domains
    return [
      {
        id: 'dom_culkibo_main',
        hostname: 'culkibo.dev',
        isWildcard: false,
        projectId: null,
        targetPod: 'forge',
        targetPort: 3001,
        status: 'active',
        cloudflareProxied: true,
        cloudflareZoneId: 'cf_zone_98234710293847',
        sslStatus: 'active',
        sslCertId: 'cert_culkibo_wildcard',
        sslProvider: 'lets_encrypt',
        routingMode: 'cloudflare_proxy',
        createdAt: new Date(Date.now() - 86400000 * 20).toISOString(),
        lastCheckedAt: new Date().toISOString()
      },
      {
        id: 'dom_culkibo_wildcard',
        hostname: '*.culkibo.dev',
        isWildcard: true,
        projectId: null,
        targetPod: 'forge',
        targetPort: 3001,
        status: 'active',
        cloudflareProxied: true,
        cloudflareZoneId: 'cf_zone_98234710293847',
        sslStatus: 'active',
        sslCertId: 'cert_culkibo_wildcard',
        sslProvider: 'lets_encrypt',
        routingMode: 'cloudflare_proxy',
        createdAt: new Date(Date.now() - 86400000 * 18).toISOString(),
        lastCheckedAt: new Date().toISOString()
      },
      {
        id: 'dom_sslip_preview',
        hostname: 'app-local.127-0-0-1.sslip.io',
        isWildcard: false,
        projectId: null,
        targetPod: 'citadel',
        targetPort: 8080,
        status: 'active',
        cloudflareProxied: false,
        cloudflareZoneId: null,
        sslStatus: 'active',
        sslCertId: 'cert_sslip_ondemand',
        sslProvider: 'ondemand_tls',
        routingMode: 'direct_dns',
        createdAt: new Date(Date.now() - 86400000 * 5).toISOString(),
        lastCheckedAt: new Date().toISOString()
      }
    ];
  }

  saveDomains() {
    this.ensureDirectory();
    this.rebuildIndex();
    atomicWriteJsonSync(DOMAINS_FILE, this.domains, 0o600);
  }

  listDomains() {
    // Una sola pasada de verificación sobre el registro SSL en vez de O(D × C).
    const sslManager = getSslManager();
    const certs = sslManager.listCertificates();
    const now = Date.now();
    return this.domains.map(d => {
      const cert = sslManager.matchCertificate(d.hostname, certs);
      return {
        ...d,
        ...(d.basicAuth ? { basicAuth: sanitizeBasicAuthForPublic(d.basicAuth) } : {}),
        projectId: d.projectId || null,
        certClaim: cert ? {
          verified: false,
          managedBy: cert.managedBy || null,
          issuer: cert.issuer || null,
          expiresAt: cert.expiresAt || null,
          daysRemaining: cert.expiresAt
            ? Math.max(0, Math.floor((new Date(cert.expiresAt).getTime() - now) / 86400000))
            : null,
          isWildcard: cert.type === 'wildcard_dns01'
        } : null
      };
    });
  }

  /**
   * Buffer JSON pre-serializado de `listDomains()` con ETag y TTL de 250 ms
   * (incluso cuando existen certificados propios en disco).
   * @returns {Buffer}
   */
  getAllSerialized() {
    const sslManager = getSslManager();
    const sslVer = sslManager.version || 0;
    const now = Date.now();
    const hasOnDisk = sslManager.registry.some(c => c && c.managedBy !== sslManager.MANAGED_BY_CADDY);
    if (
      this._serializedCache &&
      this._serializedCache.buffer &&
      this._serializedCache.sslVersion === sslVer &&
      (!hasOnDisk || (now - this._serializedCache.at) < 250)
    ) {
      return this._serializedCache.buffer;
    }
    const jsonStr = JSON.stringify(this.listDomains());
    const buf = Buffer.from(jsonStr, 'utf8');
    const etag = `W/"d-${this._version}-${sslVer}-${buf.length}"`;
    this._serializedCache = {
      sslVersion: sslVer,
      at: now,
      etag,
      buffer: buf,
      wrappedBuffer: this._serializedCache && this._serializedCache.sslVersion === sslVer ? null : null
    };
    return buf;
  }

  /** Buffer JSON pre-serializado con envoltorio `{"domains":[...]}` y ETag. */
  getAllWrappedSerialized() {
    const sslManager = getSslManager();
    const sslVer = sslManager.version || 0;
    const now = Date.now();
    const hasOnDisk = sslManager.registry.some(c => c && c.managedBy !== sslManager.MANAGED_BY_CADDY);
    if (
      this._serializedCache &&
      this._serializedCache.wrappedBuffer &&
      this._serializedCache.sslVersion === sslVer &&
      (!hasOnDisk || (now - this._serializedCache.at) < 250)
    ) {
      return this._serializedCache.wrappedBuffer;
    }
    const jsonStr = JSON.stringify(this.listDomains());
    const wrappedBuffer = Buffer.from(`{"domains":${jsonStr}}`, 'utf8');
    const etag = `W/"dw-${this._version}-${sslVer}-${wrappedBuffer.length}"`;
    this._serializedCache = {
      sslVersion: sslVer,
      at: now,
      etag,
      buffer: null,
      wrappedBuffer
    };
    return wrappedBuffer;
  }

  getWrappedEtag() {
    this.getAllWrappedSerialized();
    return (this._serializedCache && this._serializedCache.etag) || `W/"dw-${this._version}"`;
  }

  getByHostname(hostname) {
    const clean = String(hostname || '').trim().toLowerCase();
    if (!clean) return null;
    if (clean.startsWith('*.')) {
      const w = this._wildcards.find(x => x.domain.hostname === clean);
      return w ? w.domain : null;
    }
    return this._exactIndex.get(clean) || this.domains.find(d => d.hostname === clean) || null;
  }

  getById(id) {
    return this._byId.get(id) || this.domains.find(d => d.id === id) || null;
  }

  listByProject(projectId) {
    return this.domains.filter(d => d.projectId === projectId);
  }

  /** Vincula un dominio ya existente a un proyecto. */
  async attachProject(id, projectId) {
    return this.updateDomain(id, { projectId });
  }

  /** Desvincula el dominio sin borrarlo del registro. */
  async detachProject(id) {
    return this.updateDomain(id, { projectId: null });
  }

  /** Desvincula en lote todos los dominios de un proyecto en 1 sola escritura a disco. */
  detachByProject(projectId) {
    let detached = 0;
    const now = new Date().toISOString();
    for (const d of this.domains) {
      if (d && d.projectId === projectId) {
        d.projectId = null;
        d.updatedAt = now;
        detached++;
      }
    }
    if (detached > 0) this.saveDomains();
    return detached;
  }

  /**
   * @param {{
   *   hostname: string,
   *   targetPod?: string,
   *   targetPort?: number | string,
   *   cloudflareZoneId?: string | null,
   *   cloudflareProxied?: boolean,
   *   routingMode?: string,
   *   canonicalRedirect?: 'none' | 'www_to_apex' | 'apex_to_www',
   *   securityHeaders?: boolean,
   *   customHeaders?: { response?: Record<string, string>, request?: Record<string, string> } | null,
   *   autoCreateDns?: boolean,
   *   serverIp?: string,
   *   sslStatus?: string,
   *   sslProvider?: string,
   *   migrationSource?: string,
   *   projectId?: string | null,
   *   serviceId?: string | null,
   *   serviceName?: string | null
   * }} opts
   */
  async addDomain({
    hostname,
    targetPod = 'forge',
    targetPort = 3001,
    cloudflareZoneId = null,
    cloudflareProxied = true,
    routingMode = 'cloudflare_proxy',
    canonicalRedirect = 'none',
    securityHeaders = true,
    customHeaders = null,
    autoCreateDns = false,
    serverIp = '127.0.0.1',
    sslStatus = undefined,
    sslProvider = undefined,
    migrationSource = undefined,
    projectId = null,
    serviceId = null,
    serviceName = null
  }) {
    const cleanHost = (hostname || '').trim().toLowerCase();

    // RFC 1123 domain validation (rejects bare IPv4)
    if ((!DOMAIN_REGEX.test(cleanHost) || IPV4_RE.test(cleanHost) || cleanHost.length > 253) && cleanHost !== 'localhost') {
      throw new Error(`Invalid domain format (RFC 1123 required): ${cleanHost}`);
    }

    const isWildcard = cleanHost.startsWith('*.');
    const parsedPort = parseInt(String(targetPort), 10);
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      throw new Error(`Invalid targetPort: ${targetPort}`);
    }

    const existing = this.domains.find(d => d.hostname === cleanHost);
    if (existing) {
      throw new Error(`Domain ${cleanHost} is already configured in Culkibo`);
    }

    const safeCanonical = !isWildcard && (canonicalRedirect === 'www_to_apex' || canonicalRedirect === 'apex_to_www')
      ? canonicalRedirect
      : 'none';

    // Si piden autoCreateDns sin zoneId explícito, intentar resolver la zona en Cloudflare automáticamente.
    const cloudflareService = getCloudflareService();
    const cfStatus = cloudflareService.getConfigStatus();
    let resolvedZoneId = cloudflareZoneId || null;
    if (autoCreateDns && !resolvedZoneId && !cfStatus.useMock) {
      try {
        const zonesRes = await cloudflareService.listZones();
        const zones = Array.isArray(zonesRes && zonesRes.zones) ? zonesRes.zones : [];
        const hostWithoutWildcard = isWildcard ? cleanHost.slice(2) : cleanHost;
        const matchedZone = zones
          .filter(z => z && z.name && (hostWithoutWildcard === z.name || hostWithoutWildcard.endsWith(`.${z.name}`)))
          .sort((a, b) => b.name.length - a.name.length)[0];
        if (matchedZone && matchedZone.id) resolvedZoneId = matchedZone.id;
      } catch (err) {
        console.warn('[DomainManager] No se pudo auto-detectar la zona de Cloudflare:', err.message);
      }
    }

    const domainId = `dom_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
    const cert = getSslManager().getCertificateByDomain(cleanHost);

    /** @type {{ attempted: boolean, success: boolean, action?: string, error?: string, companionAction?: string } | null} */
    let dnsSyncResult = null;
    /** @type {string | null} */
    let cloudflareRecordId = null;

    if (resolvedZoneId && autoCreateDns) {
      const effectiveIp = String(serverIp || '').trim();
      if (cfStatus.useMock) {
        dnsSyncResult = { attempted: false, success: false, error: 'Cloudflare está en modo simulado; guarda tu API Token real en Ajustes.' };
      } else if (!effectiveIp || effectiveIp === '127.0.0.1' || effectiveIp === '::1') {
        dnsSyncResult = { attempted: false, success: false, error: 'Se requiere una IP pública real del servidor (no 127.0.0.1) para crear el registro A.' };
      } else {
        try {
          const up = await cloudflareService.upsertDnsRecord(resolvedZoneId, {
            type: 'A',
            name: cleanHost,
            content: effectiveIp,
            proxied: Boolean(cloudflareProxied),
            ttl: 1
          });
          if (up && up.success) {
            cloudflareRecordId = up.record?.id || null;
            dnsSyncResult = { attempted: true, success: true, action: up.action || 'created' };
            // Si hay redirección canónica apex ↔ www, crear/actualizar también el registro compañero
            if (safeCanonical !== 'none') {
              const companion = cleanHost.startsWith('www.') ? cleanHost.slice(4) : `www.${cleanHost}`;
              const compRes = await cloudflareService.upsertDnsRecord(resolvedZoneId, {
                type: 'A',
                name: companion,
                content: effectiveIp,
                proxied: Boolean(cloudflareProxied),
                ttl: 1
              });
              if (compRes && compRes.success) dnsSyncResult.companionAction = compRes.action || 'created';
            }
          } else {
            dnsSyncResult = {
              attempted: true,
              success: false,
              action: up?.action || 'failed',
              error: up?.error || (Array.isArray(up?.errors) && up.errors[0]?.message) || 'Cloudflare rechazó el registro DNS'
            };
          }
        } catch (err) {
          dnsSyncResult = { attempted: true, success: false, error: err.message };
          console.warn('[DomainManager] Auto DNS upsert failed:', err.message);
        }
      }
    }

    const newDomain = {
      id: domainId,
      hostname: cleanHost,
      isWildcard,
      projectId: projectId || null,
      serviceId: serviceId || null,
      serviceName: serviceName || null,
      targetPod,
      targetPort: parsedPort,
      status: cert ? 'active' : 'pending_ssl',
      cloudflareProxied: Boolean(cloudflareProxied),
      cloudflareZoneId: resolvedZoneId,
      cloudflareRecordId,
      sslStatus: sslStatus || (cert ? 'active' : 'unconfigured'),
      sslCertId: cert ? cert.id : null,
      sslProvider: sslProvider || (cert ? cert.provider : null),
      routingMode,
      canonicalRedirect: safeCanonical,
      securityHeaders: securityHeaders !== false,
      customHeaders: customHeaders || null,
      migrationSource,
      ...(dnsSyncResult ? { dnsSyncResult } : {}),
      createdAt: new Date().toISOString(),
      lastCheckedAt: new Date().toISOString()
    };

    this.domains.unshift(newDomain);
    this.saveDomains();
    return newDomain;
  }

  async deleteDomain(id) {
    const idx = this.domains.findIndex(d => d.id === id);
    if (idx < 0) {
      throw new Error('Domain not found');
    }
    const removed = this.domains.splice(idx, 1)[0];
    this.saveDomains();
    return removed;
  }

  async updateDomain(id, updates) {
    const idx = this.domains.findIndex(d => d.id === id);
    if (idx < 0) throw new Error('Domain not found');
    if (!updates || typeof updates !== 'object' || Array.isArray(updates)) {
      throw new Error('Invalid domain update payload');
    }
    /** @type {Record<string, any>} */
    const safeUpdates = {};
    for (const [k, v] of Object.entries(updates)) {
      if (!UPDATABLE_DOMAIN_FIELDS.has(k)) continue;
      safeUpdates[k] = v;
    }
    if (safeUpdates.hostname !== undefined) {
      const cleanHost = String(safeUpdates.hostname || '').trim().toLowerCase();
      if (!DOMAIN_REGEX.test(cleanHost) && cleanHost !== 'localhost') {
        throw new Error(`Invalid domain format (RFC 1123 required): ${cleanHost}`);
      }
      const conflict = this.domains.find((d, i) => i !== idx && d.hostname === cleanHost);
      if (conflict) throw new Error(`Domain ${cleanHost} is already configured in Culkibo`);
      safeUpdates.hostname = cleanHost;
      safeUpdates.isWildcard = cleanHost.startsWith('*.');
    }
    if (safeUpdates.targetPort !== undefined) {
      const parsedPort = parseInt(String(safeUpdates.targetPort), 10);
      if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
        throw new Error(`Invalid targetPort: ${safeUpdates.targetPort}`);
      }
      safeUpdates.targetPort = parsedPort;
    }
    if (safeUpdates.cloudflareProxied !== undefined) {
      safeUpdates.cloudflareProxied = Boolean(safeUpdates.cloudflareProxied);
    }

    const effectiveHostname = safeUpdates.hostname || this.domains[idx].hostname;
    const effectiveWildcard = effectiveHostname.startsWith('*.');

    // Validar redirección canónica (evita estados no-op silenciosos en Caddy)
    if (safeUpdates.canonicalRedirect !== undefined) {
      const mode = String(safeUpdates.canonicalRedirect || 'none');
      if (!['none', 'www_to_apex', 'apex_to_www'].includes(mode)) {
        throw new Error(`Modo de redirección canónica inválido: ${mode}`);
      }
      if (mode !== 'none' && effectiveWildcard) {
        throw new Error('La redirección canónica www ↔ raíz no aplica a dominios comodín (*.dominio)');
      }
      if (mode === 'www_to_apex' && effectiveHostname.startsWith('www.')) {
        throw new Error('Usa "www → raíz" en el dominio raíz (sin www.), no en www.*');
      }
      if (mode === 'apex_to_www' && !effectiveHostname.startsWith('www.')) {
        throw new Error('Usa "raíz → www" en el dominio www.*, no en el dominio raíz');
      }
      if (mode !== 'none') {
        const companion = mode === 'www_to_apex' ? `www.${effectiveHostname}` : effectiveHostname.slice(4);
        const dup = this.domains.find((d, i) => i !== idx && d.hostname === companion);
        if (dup) {
          throw new Error(`El dominio acompañante ${companion} ya está registrado por separado en Culkibo`);
        }
      }
      safeUpdates.canonicalRedirect = mode;
    }

    // Validar framePolicy
    if (safeUpdates.framePolicy !== undefined) {
      const fp = safeUpdates.framePolicy ? String(safeUpdates.framePolicy).toUpperCase() : null;
      if (fp && !['DENY', 'SAMEORIGIN', 'ALLOW'].includes(fp)) {
        throw new Error(`framePolicy inválido: ${fp}`);
      }
      safeUpdates.framePolicy = fp;
    }

    // Validar y sanear customHeaders (sin CRLF ni hop-by-hop)
    if (safeUpdates.customHeaders !== undefined) {
      if (safeUpdates.customHeaders === null) {
        safeUpdates.customHeaders = null;
      } else if (typeof safeUpdates.customHeaders === 'object') {
        /** @type {{ response?: Record<string, string>, request?: Record<string, string> }} */
        const cleanHeaders = {};
        for (const section of ['response', 'request']) {
          const src = safeUpdates.customHeaders[section];
          if (!src || typeof src !== 'object') continue;
          /** @type {Record<string, string>} */
          const map = {};
          let count = 0;
          for (const [hk, hv] of Object.entries(src)) {
            if (count >= 20) break;
            const k = String(hk).trim();
            if (!/^[A-Za-z0-9-]+$/.test(k) || HOP_BY_HOP_HEADER_RE.test(k)) continue;
            map[k] = String(hv == null ? '' : hv).replace(/[\r\n\0]/g, '').slice(0, 1024);
            count++;
          }
          if (Object.keys(map).length > 0) cleanHeaders[section] = map;
        }
        safeUpdates.customHeaders = (cleanHeaders.response || cleanHeaders.request) ? cleanHeaders : null;
      }
    }

    // Validar y cifrar con bcrypt las cuentas de HTTP Basic Auth (nunca guardar texto plano)
    if (safeUpdates.basicAuth !== undefined) {
      if (!safeUpdates.basicAuth || safeUpdates.basicAuth.enabled === false) {
        safeUpdates.basicAuth = { enabled: false, realm: 'Acceso protegido', accounts: [] };
      } else if (typeof safeUpdates.basicAuth === 'object') {
        const prevAccounts = new Map(
          ((this.domains[idx].basicAuth && this.domains[idx].basicAuth.accounts) || []).map((a) => [a.username, a.passwordHash])
        );
        const rawList = Array.isArray(safeUpdates.basicAuth.accounts)
          ? safeUpdates.basicAuth.accounts
          : (Array.isArray(safeUpdates.basicAuth.users) ? safeUpdates.basicAuth.users : []);
        /** @type {Array<{ username: string, passwordHash: string }>} */
        const hashedAccounts = [];
        for (const item of rawList.slice(0, 20)) {
          if (!item || typeof item !== 'object') continue;
          const username = String(item.username || '').trim();
          if (!username || !/^[A-Za-z0-9._@+-]{1,64}$/.test(username)) {
            throw new Error(`Usuario de Basic Auth inválido: "${username.slice(0, 30)}"`);
          }
          let passwordHash = '';
          if (typeof item.password === 'string' && item.password.length > 0) {
            passwordHash = isBcryptHash(item.password) ? item.password : hashBcrypt(item.password, 10);
          } else if (typeof item.passwordHash === 'string' && isBcryptHash(item.passwordHash)) {
            passwordHash = item.passwordHash;
          } else if (prevAccounts.has(username)) {
            passwordHash = prevAccounts.get(username);
          } else {
            throw new Error(`Debes indicar una contraseña para el usuario "${username}"`);
          }
          hashedAccounts.push({ username, passwordHash });
        }
        if (hashedAccounts.length === 0) {
          throw new Error('Activar Basic Auth requiere al menos un usuario con contraseña');
        }
        safeUpdates.basicAuth = {
          enabled: true,
          realm: String(safeUpdates.basicAuth.realm || 'Acceso protegido').replace(/[\r\n\0"]/g, '').slice(0, 80),
          accounts: hashedAccounts
        };
      }
    }

    // Validar IP Allowlist (CIDRs / IPs IPv4 e IPv6)
    if (safeUpdates.ipAllowlist !== undefined) {
      if (safeUpdates.ipAllowlist === null || (Array.isArray(safeUpdates.ipAllowlist) && safeUpdates.ipAllowlist.length === 0)) {
        safeUpdates.ipAllowlist = [];
      } else if (Array.isArray(safeUpdates.ipAllowlist)) {
        const cleanIps = [];
        for (const rawIp of safeUpdates.ipAllowlist.slice(0, 64)) {
          const s = String(rawIp || '').trim();
          if (!s) continue;
          if (!isValidCidrOrIp(s)) {
            throw new Error(`IP o rango CIDR inválido en lista blanca: "${s.slice(0, 48)}"`);
          }
          cleanIps.push(s);
        }
        safeUpdates.ipAllowlist = Array.from(new Set(cleanIps));
      } else {
        throw new Error('ipAllowlist debe ser un array de direcciones IP o rangos CIDR');
      }
    }

    // Validar maxBodySizeMb
    if (safeUpdates.maxBodySizeMb !== undefined) {
      if (safeUpdates.maxBodySizeMb === null || safeUpdates.maxBodySizeMb === '') {
        safeUpdates.maxBodySizeMb = null;
      } else {
        const mb = Number(safeUpdates.maxBodySizeMb);
        if (!Number.isFinite(mb) || mb < 1 || mb > 10240) {
          throw new Error('maxBodySizeMb debe estar entre 1 y 10240 MB');
        }
        safeUpdates.maxBodySizeMb = Math.round(mb);
      }
    }

    // Validar rateLimit por dominio
    if (safeUpdates.rateLimit !== undefined) {
      if (!safeUpdates.rateLimit || safeUpdates.rateLimit.enabled === false) {
        safeUpdates.rateLimit = { enabled: false, requests: 120, windowSeconds: 60 };
      } else if (typeof safeUpdates.rateLimit === 'object') {
        safeUpdates.rateLimit = {
          enabled: true,
          requests: Math.min(100000, Math.max(1, Math.round(Number(safeUpdates.rateLimit.requests) || 120))),
          windowSeconds: Math.min(3600, Math.max(1, Math.round(Number(safeUpdates.rateLimit.windowSeconds) || 60)))
        };
      }
    }

    this.domains[idx] = { ...this.domains[idx], ...safeUpdates, updatedAt: new Date().toISOString() };
    this.saveDomains();
    const updated = this.domains[idx];
    return updated.basicAuth ? { ...updated, basicAuth: sanitizeBasicAuthForPublic(updated.basicAuth) } : updated;
  }

  async toggleProxy(id) {
    const idx = this.domains.findIndex(d => d.id === id);
    if (idx < 0) throw new Error('Domain not found');
    const dom = this.domains[idx];
    const nextProxied = !dom.cloudflareProxied;

    // Sincronizar realmente con Cloudflare API cuando hay credenciales reales (auto-resolviendo zona si falta)
    const cloudflareService = getCloudflareService();
    const cfStatus = cloudflareService.getConfigStatus();
    let cloudflareSynced = false;
    /** @type {string | null} */
    let cloudflareError = null;
    if (!cfStatus.useMock && !dom.hostname.endsWith('.sslip.io') && !dom.hostname.endsWith('.nip.io')) {
      try {
        let zoneId = dom.cloudflareZoneId || null;
        if (!zoneId) {
          zoneId = await cloudflareService.findZoneForDomain(dom.hostname);
          if (zoneId) dom.cloudflareZoneId = zoneId;
        }
        if (zoneId) {
          let recId = dom.cloudflareRecordId || null;
          if (!recId) {
            const listed = await cloudflareService.listDnsRecords(zoneId);
            const match = (listed.records || []).find(
              (r) => String(r.name || '').toLowerCase() === dom.hostname && ['A', 'AAAA', 'CNAME'].includes(String(r.type || '').toUpperCase())
            );
            if (match && match.id) recId = match.id;
          }
          if (recId) {
            const upd = await cloudflareService.updateDnsRecord(zoneId, recId, { proxied: nextProxied });
            if (upd && upd.success) {
              dom.cloudflareRecordId = recId;
              cloudflareSynced = true;
            } else {
              cloudflareError = upd?.error || (Array.isArray(upd?.errors) && upd.errors[0]?.message) || 'Cloudflare no pudo cambiar el proxy';
            }
          }
        }
      } catch (err) {
        cloudflareError = err.message;
      }
    }

    dom.cloudflareProxied = nextProxied;
    dom.updatedAt = new Date().toISOString();
    this.saveDomains();
    return { ...dom, cloudflareSynced, ...(cloudflareError ? { cloudflareError } : {}) };
  }

  /**
   * Comprobador real de DNS (A, AAAA, CNAME, CAA).
   * Para dominios comodín (`*.empresa.com`), consulta un subdominio sintético
   * (`_culkibo-check.empresa.com`) además del ápex para evitar falsos positivos/negativos.
   *
   * @param {string} hostname
   * @param {{ expectedIp?: string | null }} [opts]
   */
  async verifyDns(hostname, { expectedIp = null } = {}) {
    const raw = String(hostname || '').trim().toLowerCase();
    const isWildcard = raw.startsWith('*.');
    const root = raw.replace(/^\*\./, '');
    const probeHost = isWildcard ? `_culkibo-check.${root}` : root;

    const result = {
      hostname: raw,
      probedHost: probeHost,
      isWildcard,
      resolvedIps: /** @type {string[]} */ ([]),
      resolvedIpv6: /** @type {string[]} */ ([]),
      apexIps: /** @type {string[]} */ ([]),
      cnames: /** @type {string[]} */ ([]),
      caa: /** @type {any[]} */ ([]),
      hasDnsRecords: false,
      isCloudflareEdge: false,
      matchesExpectedIp: /** @type {boolean | null} */ (null),
      diagnostics: /** @type {Array<{ level: 'ok' | 'warn' | 'error', message: string }>} */ ([]),
      lookupDurationMs: 0
    };

    const start = performance.now();
    try {
      const dns = getDns();
      const queries = [
        withTimeout(dns.resolve4(probeHost), 4000),
        withTimeout(dns.resolve6(probeHost), 4000),
        withTimeout(dns.resolveCname(probeHost), 4000),
        withTimeout(dns.resolveCaa(root), 4000),
        isWildcard ? withTimeout(dns.resolve4(root), 4000) : Promise.resolve([])
      ];
      const [aRes, aaaaRes, cnameRes, caaRes, apexRes] = await Promise.allSettled(queries);

      if (aRes.status === 'fulfilled' && Array.isArray(aRes.value)) {
        result.resolvedIps = aRes.value;
        if (result.resolvedIps.length > 0) result.hasDnsRecords = true;
      }
      if (aaaaRes.status === 'fulfilled' && Array.isArray(aaaaRes.value)) {
        result.resolvedIpv6 = aaaaRes.value;
        if (result.resolvedIpv6.length > 0) result.hasDnsRecords = true;
      }
      if (cnameRes.status === 'fulfilled' && Array.isArray(cnameRes.value)) {
        result.cnames = cnameRes.value;
        if (result.cnames.length > 0) result.hasDnsRecords = true;
      }
      if (caaRes.status === 'fulfilled' && Array.isArray(caaRes.value)) {
        result.caa = caaRes.value;
      }
      if (apexRes.status === 'fulfilled' && Array.isArray(apexRes.value)) {
        result.apexIps = apexRes.value;
      }

      result.isCloudflareEdge =
        result.resolvedIps.some((ip) => isCloudflareIp(ip)) ||
        result.resolvedIpv6.some((ip) => isCloudflareIp(ip));

      const cleanExpected = expectedIp ? String(expectedIp).trim() : null;
      if (cleanExpected && result.resolvedIps.length > 0) {
        result.matchesExpectedIp = result.resolvedIps.includes(cleanExpected);
      }

      // Diagnósticos en español llano
      if (!result.hasDnsRecords) {
        result.diagnostics.push({
          level: 'error',
          message: isWildcard
            ? `El registro comodín (*) de ${root} aún no resuelve en DNS. Crea un registro A con nombre * apuntando a ${cleanExpected || 'la IP de tu servidor'}.`
            : `${root} no tiene registros A/AAAA/CNAME visibles todavía. Si acabas de crearlo, espera 1–5 minutos.`
        });
      } else if (result.isCloudflareEdge) {
        result.diagnostics.push({
          level: 'ok',
          message: 'Tráfico pasando por Cloudflare Proxy (nube naranja). Asegúrate de usar modo SSL «Full (Strict)» en Cloudflare para evitar bucles de redirección.'
        });
      } else if (cleanExpected && result.matchesExpectedIp === true) {
        result.diagnostics.push({
          level: 'ok',
          message: `DNS correcto: apunta directamente a tu servidor (${cleanExpected}).`
        });
      } else if (cleanExpected && result.matchesExpectedIp === false) {
        result.diagnostics.push({
          level: 'warn',
          message: `Apunta a ${result.resolvedIps.join(', ')}, pero la IP pública de este servidor es ${cleanExpected}.`
        });
      }

      if (result.resolvedIpv6.length > 0 && !result.isCloudflareEdge && cleanExpected && !cleanExpected.includes(':')) {
        result.diagnostics.push({
          level: 'warn',
          message: `Existe un registro IPv6 (AAAA: ${result.resolvedIpv6[0]}). Si este servidor no sirve IPv6, bórralo o Let's Encrypt puede fallar al emitir el certificado.`
        });
      }

      if (result.caa.length > 0) {
        const issueTags = result.caa.filter((r) => r && (r.issue || r.issuewild));
        const allowsLeOrZero = issueTags.some((r) => /letsencrypt\.org|sectigo\.com|zerossl/i.test(String(r.issue || r.issuewild || '')));
        if (issueTags.length > 0 && !allowsLeOrZero) {
          result.diagnostics.push({
            level: 'error',
            message: 'Los registros CAA de este dominio bloquean a Let\'s Encrypt y ZeroSSL. Añade CAA issue "letsencrypt.org".'
          });
        }
      }

      result.lookupDurationMs = Math.round(performance.now() - start);
      return { success: true, ...result };
    } catch (err) {
      result.lookupDurationMs = Math.round(performance.now() - start);
      return { success: false, error: err.message, ...result };
    }
  }

  // Routing resolution: given an HTTP Host header, find destination pod (O(1) exact + RFC 6125 1-label wildcard)
  resolveRoute(hostHeader) {
    if (!hostHeader) return null;
    const host = String(hostHeader).split(':')[0].toLowerCase();

    // O(1) exact match
    const exact = this._exactIndex.get(host);
    if (exact) return exact;

    // Wildcard match with mandatory boundary dot + single-label RFC 6125 guard
    for (const entry of this._wildcards) {
      if (host.endsWith(entry.suffix) && host !== entry.root) {
        const label = host.slice(0, host.length - entry.suffix.length);
        if (label && !label.includes('.')) {
          return entry.domain;
        }
      }
    }

    return null;
  }
}

domainManagerExport: {
  const instance = Object.assign(new DomainManager(), { isCloudflareIp });
  module.exports = instance;
}
