const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const sslManager = require('./sslManager');
const cloudflareService = require('./cloudflareService');

const DOMAINS_FILE = path.join(__dirname, '..', '..', 'data', 'domains.json');

class DomainManager {
  constructor() {
    this.ensureDirectory();
    this.domains = this.loadDomains();
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
    const tempPath = DOMAINS_FILE + '.tmp';
    fs.writeFileSync(tempPath, JSON.stringify(this.domains, null, 2), 'utf8');
    fs.renameSync(tempPath, DOMAINS_FILE);
  }

  listDomains() {
    return this.domains.map(d => {
      const cert = sslManager.getCertificateByDomain(d.hostname);
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
            ? Math.max(0, Math.floor((new Date(cert.expiresAt).getTime() - Date.now()) / 86400000))
            : null,
          isWildcard: cert.type === 'wildcard_dns01'
        } : null
      };
    });
  }

  getByHostname(hostname) {
    const clean = String(hostname || '').trim().toLowerCase();
    return this.domains.find(d => d.hostname === clean) || null;
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

  async addDomain({ hostname, targetPod = 'forge', targetPort = 3001, cloudflareZoneId = null, cloudflareProxied = true, routingMode = 'cloudflare_proxy', autoCreateDns = false, serverIp = '127.0.0.1', sslStatus, sslProvider, migrationSource, projectId = null }) {
    const cleanHost = (hostname || '').trim().toLowerCase();
    
    // RFC 1123 domain validation
    const domainRegex = /^(?:\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
    if (!domainRegex.test(cleanHost) && cleanHost !== 'localhost') {
      throw new Error(`Invalid domain format (RFC 1123 required): ${cleanHost}`);
    }
    
    const isWildcard = cleanHost.startsWith('*.');

    const existing = this.domains.find(d => d.hostname === cleanHost);
    if (existing) {
      throw new Error(`Domain ${cleanHost} is already configured in Culkibo`);
    }

    const domainId = `dom_${Date.now()}`;
    const cert = sslManager.getCertificateByDomain(cleanHost);

    const newDomain = {
      id: domainId,
      hostname: cleanHost,
      isWildcard,
      // El proyecto dueño del dominio. Sin esto no se puede derivar una ruta de
      // Caddy hacia el puerto vivo del proyecto, solo hacia un pod genérico.
      projectId: projectId || null,
      targetPod,
      targetPort: parseInt(targetPort, 10),
      status: cert ? 'active' : 'pending_ssl',
      cloudflareProxied: Boolean(cloudflareProxied),
      cloudflareZoneId,
      sslStatus: sslStatus || (cert ? 'active' : 'unconfigured'),
      sslCertId: cert ? cert.id : null,
      sslProvider: sslProvider || (cert ? cert.provider : null),
      routingMode,
      migrationSource,
      createdAt: new Date().toISOString(),
      lastCheckedAt: new Date().toISOString()
    };

    // If Cloudflare Zone is specified and autoCreateDns is requested, create record in Cloudflare
    if (cloudflareZoneId && autoCreateDns) {
      try {
        const recordName = isWildcard ? cleanHost : cleanHost;
        await cloudflareService.createDnsRecord(cloudflareZoneId, {
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
    this.domains[idx] = { ...this.domains[idx], ...updates, updatedAt: new Date().toISOString() };
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
    const clean = hostname.replace(/^\*\./, '');
    const result = {
      hostname: clean,
      resolvedIps: [],
      cnames: [],
      hasDnsRecords: false,
      isCloudflareEdge: false,
      lookupDurationMs: 0
    };

    const start = performance.now();
    try {
      // Resolve A records
      try {
        result.resolvedIps = await dns.resolve4(clean);
        result.hasDnsRecords = result.resolvedIps.length > 0;
      } catch (e) {
        // A record lookup failed or domain is CNAME
      }

      // Check CNAME if no A record or as complement
      try {
        result.cnames = await dns.resolveCname(clean);
        if (result.cnames.length > 0) result.hasDnsRecords = true;
      } catch (e) {}

      // Detect Cloudflare IPs (Cloudflare IP ranges 172.67.*, 104.21.*, etc.)
      result.isCloudflareEdge = result.resolvedIps.some(ip =>
        ip.startsWith('104.21.') || ip.startsWith('172.67.') || ip.startsWith('104.20.')
      );

      result.lookupDurationMs = Math.round(performance.now() - start);
      return { success: true, ...result };
    } catch (err) {
      result.lookupDurationMs = Math.round(performance.now() - start);
      return { success: false, error: err.message, ...result };
    }
  }

  // Routing resolution: given an HTTP Host header, find destination pod
  resolveRoute(hostHeader) {
    if (!hostHeader) return null;
    const host = hostHeader.split(':')[0].toLowerCase();

    // Exact match
    let match = this.domains.find(d => d.hostname === host);
    if (match) return match;

    // Wildcard match. The boundary dot is mandatory: a bare endsWith() made
    // `*.culkibo.dev` also match `evilculkibo.dev`, letting an unrelated domain
    // (or a forged Host header) claim another tenant's ingress route.
    match = this.domains.find(d => {
      if (!d.isWildcard) return false;
      const root = d.hostname.slice(2); // remove '*.'
      return host.endsWith(`.${root}`) && host !== root;
    });

    return match || null;
  }
}

module.exports = new DomainManager();
