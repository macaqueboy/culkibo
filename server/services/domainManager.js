const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const sslManager = require('./sslManager');
const cloudflareService = require('./cloudflareService');
const { atomicWriteJsonSync } = require('./ssrfGuard');

const DOMAINS_FILE = path.join(__dirname, '..', '..', 'data', 'domains.json');
const DOMAIN_REGEX = /^(?:\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
const UPDATABLE_DOMAIN_FIELDS = new Set([
  'hostname',
  'projectId',
  'targetPod',
  'targetPort',
  'cloudflareProxied',
  'cloudflareZoneId',
  'sslStatus',
  'sslCertId',
  'sslProvider',
  'routingMode',
  'status',
  'serviceId',
  'serviceName',
  'lastCheckedAt',
  'migrationSource'
]);

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
    /** @type {any[]} */
    this._wildcards = [];
    /** @type {{ sslVersion: number, buffer: Buffer } | null} */
    this._serializedCache = null;
    this.rebuildIndex();
  }

  rebuildIndex() {
    this._exactIndex.clear();
    this._wildcards = [];
    this._serializedCache = null;
    for (const d of this.domains) {
      if (!d || typeof d.hostname !== 'string') continue;
      const host = d.hostname.toLowerCase();
      if (d.isWildcard && host.startsWith('*.')) {
        this._wildcards.push({ domain: d, root: host.slice(2), suffix: `.${host.slice(2)}` });
      } else {
        this._exactIndex.set(host, d);
      }
    }
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
    const certs = sslManager.listCertificates();
    const now = Date.now();
    return this.domains.map(d => {
      const cert = sslManager.matchCertificate(d.hostname, certs);
      return {
        ...d,
        projectId: d.projectId || null,
        // `certClaim`, no `certInfo`: esto es lo que NUESTRO registro afirma,
        // no lo que un navegador recibe. El dato verificado sale del handshake
        // TLS real que hace ingressManager y se publica en /api/ingress/status.
        // Se renombró a propósito para que ningún consumidor pueda volver a
        // confundir una afirmación propia con una comprobación.
        //
        // `issuer` y `expiresAt` pueden ser `null`: una entrada delegada
        // (TLS bajo demanda de Caddy) no tiene emisor ni caducidad que
        // podamos afirmar, y desde que se eliminó la emisión falsa el
        // registro ya no se los inventa.
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
   * Buffer JSON pre-serializado de `listDomains()` cuando el registro de
   * dominios y el de SSL no han cambiado (evita recomputar bajo ráfagas).
   * @returns {Buffer}
   */
  getAllSerialized() {
    const sslVer = sslManager.version || 0;
    // Sólo usar caché cuando no hay certificados `on_disk` cuya existencia
    // en disco deba comprobarse con `statSync` en cada lectura.
    const hasOnDisk = sslManager.registry.some(c => c && c.managedBy !== sslManager.MANAGED_BY_CADDY);
    if (!hasOnDisk && this._serializedCache && this._serializedCache.sslVersion === sslVer) {
      return this._serializedCache.buffer;
    }
    const buf = Buffer.from(JSON.stringify(this.listDomains()), 'utf8');
    if (!hasOnDisk) {
      this._serializedCache = { sslVersion: sslVer, buffer: buf };
    }
    return buf;
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
    return this.domains.find(d => d.id === id) || null;
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

  /**
   * @param {{
   *   hostname: string,
   *   targetPod?: string,
   *   targetPort?: number | string,
   *   cloudflareZoneId?: string | null,
   *   cloudflareProxied?: boolean,
   *   routingMode?: string,
   *   autoCreateDns?: boolean,
   *   serverIp?: string,
   *   sslStatus?: string,
   *   sslProvider?: string,
   *   migrationSource?: string,
   *   projectId?: string | null
   * }} opts
   */
  async addDomain({ hostname, targetPod = 'forge', targetPort = 3001, cloudflareZoneId = null, cloudflareProxied = true, routingMode = 'cloudflare_proxy', autoCreateDns = false, serverIp = '127.0.0.1', sslStatus = undefined, sslProvider = undefined, migrationSource = undefined, projectId = null }) {
    const cleanHost = (hostname || '').trim().toLowerCase();
    
    // RFC 1123 domain validation
    if (!DOMAIN_REGEX.test(cleanHost) && cleanHost !== 'localhost') {
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

    // Si piden autoCreateDns sin zoneId explícito, intentar resolver la zona en Cloudflare automáticamente.
    let resolvedZoneId = cloudflareZoneId || null;
    if (autoCreateDns && !resolvedZoneId) {
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
    const cert = sslManager.getCertificateByDomain(cleanHost);

    const newDomain = {
      id: domainId,
      hostname: cleanHost,
      isWildcard,
      // El proyecto dueño del dominio. Sin esto no se puede derivar una ruta de
      // Caddy hacia el puerto vivo del proyecto, solo hacia un pod genérico.
      projectId: projectId || null,
      targetPod,
      targetPort: parsedPort,
      status: cert ? 'active' : 'pending_ssl',
      cloudflareProxied: Boolean(cloudflareProxied),
      cloudflareZoneId: resolvedZoneId,
      sslStatus: sslStatus || (cert ? 'active' : 'unconfigured'),
      sslCertId: cert ? cert.id : null,
      sslProvider: sslProvider || (cert ? cert.provider : null),
      routingMode,
      migrationSource,
      createdAt: new Date().toISOString(),
      lastCheckedAt: new Date().toISOString()
    };

    // If Cloudflare Zone is specified and autoCreateDns is requested, create record in Cloudflare
    if (resolvedZoneId && autoCreateDns) {
      try {
        const recordName = isWildcard ? cleanHost : cleanHost;
        await cloudflareService.createDnsRecord(resolvedZoneId, {
          type: 'A',
          name: recordName,
          content: serverIp,
          proxied: cloudflareProxied,
          ttl: 1
        });
      } catch (err) {
        console.warn('[DomainManager] Auto DNS creation failed:', err.message);
      }
    }

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
    this.domains[idx] = { ...this.domains[idx], ...safeUpdates, updatedAt: new Date().toISOString() };
    this.saveDomains();
    return this.domains[idx];
  }

  async toggleProxy(id) {
    const idx = this.domains.findIndex(d => d.id === id);
    if (idx < 0) throw new Error('Domain not found');
    this.domains[idx].cloudflareProxied = !this.domains[idx].cloudflareProxied;
    this.domains[idx].updatedAt = new Date().toISOString();
    this.saveDomains();
    return this.domains[idx];
  }

  // Live DNS resolution checker
  async verifyDns(hostname) {
    const clean = String(hostname || '').trim().toLowerCase().replace(/^\*\./, '');
    const result = {
      hostname: clean,
      resolvedIps: /** @type {string[]} */ ([]),
      cnames: /** @type {string[]} */ ([]),
      hasDnsRecords: false,
      isCloudflareEdge: false,
      lookupDurationMs: 0
    };

    const start = performance.now();
    try {
      const [aRes, cnameRes] = await Promise.allSettled([
        withTimeout(dns.resolve4(clean), 4000),
        withTimeout(dns.resolveCname(clean), 4000)
      ]);
      if (aRes.status === 'fulfilled' && Array.isArray(aRes.value)) {
        result.resolvedIps = aRes.value;
        result.hasDnsRecords = result.resolvedIps.length > 0;
      }
      if (cnameRes.status === 'fulfilled' && Array.isArray(cnameRes.value)) {
        result.cnames = cnameRes.value;
        if (result.cnames.length > 0) result.hasDnsRecords = true;
      }

      // Detect Cloudflare IPs (Cloudflare IP ranges 172.67.*, 104.21.*, etc.)
      result.isCloudflareEdge = result.resolvedIps.some(ip =>
        ip.startsWith('104.21.') || ip.startsWith('172.67.') || ip.startsWith('104.20.') || ip.startsWith('104.18.') || ip.startsWith('188.114.')
      );

      result.lookupDurationMs = Math.round(performance.now() - start);
      return { success: true, ...result };
    } catch (err) {
      result.lookupDurationMs = Math.round(performance.now() - start);
      return { success: false, error: err.message, ...result };
    }
  }

  // Routing resolution: given an HTTP Host header, find destination pod (O(1) exact)
  resolveRoute(hostHeader) {
    if (!hostHeader) return null;
    const host = String(hostHeader).split(':')[0].toLowerCase();

    // O(1) exact match
    const exact = this._exactIndex.get(host);
    if (exact) return exact;

    // Wildcard match with mandatory boundary dot
    for (const entry of this._wildcards) {
      if (host.endsWith(entry.suffix) && host !== entry.root) {
        return entry.domain;
      }
    }

    return null;
  }
}

module.exports = new DomainManager();
