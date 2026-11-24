const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { atomicWriteJsonSync } = require('./ssrfGuard');

const DATA_DIR = process.env.CULKIBO_DATA_DIR
  ? path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data')
  : path.resolve(__dirname, '..', '..', 'data');
const CONFIG_FILE = path.join(DATA_DIR, 'cloudflare-config.json');
const TMP_DIR = path.join(DATA_DIR, '.tmp');
const CF_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;

function assertCfId(value, label = 'ID de Cloudflare') {
  const s = String(value || '').trim();
  if (!CF_ID_RE.test(s)) throw new Error(`${label} inválido`);
  return encodeURIComponent(s);
}

class CloudflareService {
  constructor() {
    this.apiBase = 'https://api.cloudflare.com/client/v4';
    this.config = this.loadConfig();
    this.mockZones = [
      {
        id: 'cf_zone_98234710293847',
        name: 'culkibo.dev',
        status: 'active',
        paused: false,
        type: 'full',
        name_servers: ['dora.ns.cloudflare.com', 'walt.ns.cloudflare.com'],
        original_registrar: 'Cloudflare Registrar',
        plan: { name: 'Pro Plan' }
      },
      {
        id: 'cf_zone_55410928374612',
        name: 'pablo-labs.io',
        status: 'active',
        paused: false,
        type: 'full',
        name_servers: ['ashley.ns.cloudflare.com', 'karl.ns.cloudflare.com'],
        original_registrar: 'Namecheap',
        plan: { name: 'Free Plan' }
      }
    ];

    this.mockRecords = [
      {
        id: 'rec_01',
        zone_id: 'cf_zone_98234710293847',
        type: 'A',
        name: 'culkibo.dev',
        content: '142.250.180.206',
        proxiable: true,
        proxied: true,
        ttl: 1,
        locked: false,
        created_on: new Date(Date.now() - 86400000 * 40).toISOString()
      },
      {
        id: 'rec_02',
        zone_id: 'cf_zone_98234710293847',
        type: 'CNAME',
        name: '*.culkibo.dev',
        content: 'culkibo.dev',
        proxiable: true,
        proxied: true,
        ttl: 1,
        locked: false,
        created_on: new Date(Date.now() - 86400000 * 30).toISOString()
      },
      {
        id: 'rec_03',
        zone_id: 'cf_zone_98234710293847',
        type: 'TXT',
        name: '_acme-challenge.culkibo.dev',
        content: '"culkibo-acme-dns01-challenge-verification-key-x9123"',
        proxiable: false,
        proxied: false,
        ttl: 120,
        locked: false,
        created_on: new Date(Date.now() - 86400000 * 2).toISOString()
      },
      {
        id: 'rec_04',
        zone_id: 'cf_zone_55410928374612',
        type: 'A',
        name: 'pablo-labs.io',
        content: '104.21.45.198',
        proxiable: true,
        proxied: true,
        ttl: 1,
        locked: false,
        created_on: new Date(Date.now() - 86400000 * 15).toISOString()
      }
    ];

    this.mockTunnels = [
      {
        id: 'tun_e49102c8-8921-4f99-9011-827361928374',
        name: 'culkibo-edge-forge',
        status: 'healthy',
        created_at: new Date(Date.now() - 86400000 * 12).toISOString(),
        connections: [
          { colo_name: 'MAD', is_pending_reconnect: false, uuid: 'conn_mad_01' },
          { colo_name: 'LIS', is_pending_reconnect: false, uuid: 'conn_lis_02' }
        ],
        routes: [
          { hostname: 'forge.culkibo.dev', service: 'http://localhost:3001' },
          { hostname: '*.culkibo.dev', service: 'http://localhost:3030' }
        ]
      }
    ];
  }

  loadConfig() {
    try {
      if (fs.existsSync(CONFIG_FILE)) {
        const stored = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
        const envToken = process.env.CLOUDFLARE_API_TOKEN || process.env.CF_API_TOKEN || '';
        const token = stored.apiToken || envToken;
        const isReal = Boolean(token && !this.isSimulatedToken(token));
        return {
          ...stored,
          apiToken: token,
          accountId: stored.accountId || process.env.CLOUDFLARE_ACCOUNT_ID || '',
          isConfigured: isReal,
          useMock: !isReal || stored.useMock === true
        };
      }
    } catch (e) {
      console.error('[Cloudflare] Error reading config file:', e.message);
    }
    const envToken = process.env.CLOUDFLARE_API_TOKEN || process.env.CF_API_TOKEN || '';
    const isReal = Boolean(envToken && !this.isSimulatedToken(envToken));
    return {
      apiToken: envToken,
      accountId: process.env.CLOUDFLARE_ACCOUNT_ID || '',
      defaultZoneId: '',
      isConfigured: isReal,
      useMock: !isReal
    };
  }

  isSimulatedToken(token) {
    if (!token) return true;
    const clean = String(token).toLowerCase();
    return clean === 'demo' || clean === 'mock' || clean.startsWith('demo_') || clean.startsWith('mock_');
  }

  saveConfig(newConfig) {
    if (!newConfig || typeof newConfig !== 'object') return this.config;
    const ALLOWED_KEYS = ['apiToken', 'accountId', 'defaultZoneId', 'useMock'];
    const filtered = {};
    for (const k of ALLOWED_KEYS) {
      if (newConfig[k] === undefined) continue;
      // P1-4: no sobrescribir nunca apiToken ni accountId con valores enmascarados ('...' o '••')
      if ((k === 'apiToken' || k === 'accountId') && typeof newConfig[k] === 'string') {
        const v = newConfig[k].trim();
        if (v.includes('...') || v.includes('••')) continue;
        filtered[k] = v;
      } else {
        filtered[k] = newConfig[k];
      }
    }
    this.config = { ...this.config, ...filtered };
    this.config.isConfigured = Boolean(this.config.apiToken);
    if (this.isSimulatedToken(this.config.apiToken)) {
      this.config.useMock = true;
    } else if (filtered.useMock !== undefined) {
      this.config.useMock = Boolean(filtered.useMock);
    } else {
      // Un token real recién configurado desactiva el modo simulado automáticamente.
      this.config.useMock = false;
    }
    atomicWriteJsonSync(CONFIG_FILE, this.config, 0o600);
    return this.config;
  }

  /** Estado seguro para la UI sin exponer el token en claro. */
  getConfigStatus() {
    const token = String(this.config.apiToken || '');
    const isMock = Boolean(this.config.useMock || !token || this.isSimulatedToken(token));
    return {
      isConfigured: Boolean(token && !this.isSimulatedToken(token)),
      hasToken: Boolean(token),
      hasApiToken: Boolean(token),
      useMock: isMock,
      accountId: this.config.accountId || '',
      defaultZoneId: this.config.defaultZoneId || '',
      tokenMasked: token ? (token.length > 8 ? `${token.slice(0, 4)}••••${token.slice(-4)}` : '••••••••') : null
    };
  }

  async findZoneForDomain(domain) {
    if (!domain) return null;
    const clean = String(domain).replace(/^\*\./, '').trim().toLowerCase();
    if (!clean) return null;

    const zonesRes = await this.listZones();
    if (zonesRes.success && Array.isArray(zonesRes.zones) && zonesRes.zones.length) {
      // P1-4: coincidencia por sufijo más largo (soporta .co.uk, .com.es, etc.) y jamás fallback a zones[0]
      const match = zonesRes.zones
        .filter((z) => z && z.name && (clean === z.name.toLowerCase() || clean.endsWith(`.${z.name.toLowerCase()}`)))
        .sort((a, b) => b.name.length - a.name.length)[0];
      return match ? match.id : null;
    }
    return null;
  }

  async verifyToken(apiToken = null) {
    const token = apiToken || this.config.apiToken;
    if (!token) {
      return {
        valid: false,
        status: 'unconfigured',
        message: 'No Cloudflare API token provided'
      };
    }

    if (this.isSimulatedToken(token)) {
      return {
        valid: true,
        status: 'active',
        mode: 'simulated',
        id: 'cf_token_simulated_dev',
        message: 'Simulated Cloudflare API Token active with Zone:Edit, DNS:Edit permissions',
        expires_on: null
      };
    }

    try {
      const res = await fetch(`${this.apiBase}/user/tokens/verify`, {
        method: 'GET',
        signal: AbortSignal.timeout(10000),
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      /** @type {any} */
      const data = await res.json();
      if (data.success) {
        return {
          valid: true,
          status: data.result.status,
          id: data.result.id,
          message: 'Valid Cloudflare API Token verified with live API',
          expires_on: data.result.expires_on
        };
      } else {
        return {
          valid: false,
          status: 'error',
          errors: data.errors,
          message: data.errors?.[0]?.message || 'Invalid Cloudflare API token'
        };
      }
    } catch (err) {
      return {
        valid: false,
        status: 'network_error',
        message: `Failed to reach Cloudflare API: ${err.message}`
      };
    }
  }

  async listZones() {
    if (this.config.useMock || !this.config.apiToken || this.isSimulatedToken(this.config.apiToken)) {
      return { success: true, zones: this.mockZones, count: this.mockZones.length, isMock: true };
    }

    try {
      /** @type {any[]} */
      const allZones = [];
      let page = 1;
      let totalPages = 1;
      while (page <= totalPages && page <= 10) {
        const res = await fetch(`${this.apiBase}/zones?status=active&per_page=50&page=${page}`, {
          signal: AbortSignal.timeout(10000),
          headers: {
            Authorization: `Bearer ${this.config.apiToken}`,
            'Content-Type': 'application/json'
          }
        });
        /** @type {any} */
        const data = await res.json();
        if (!data.success) {
          return { success: false, errors: data.errors, zones: allZones };
        }
        if (Array.isArray(data.result)) allZones.push(...data.result);
        totalPages = Number(data.result_info?.total_pages) || 1;
        page++;
      }
      // Autodetección sin fricción de Account ID desde la primera zona activa si todavía está vacío
      if (!this.config.accountId && allZones[0]?.account?.id && CF_ID_RE.test(String(allZones[0].account.id))) {
        this.config.accountId = String(allZones[0].account.id);
        try { atomicWriteJsonSync(CONFIG_FILE, this.config, 0o600); } catch (e) {}
      }
      return { success: true, zones: allZones, count: allZones.length, isMock: false, accountId: this.config.accountId || '' };
    } catch (err) {
      return { success: false, error: err.message, zones: [] };
    }
  }

  async listDnsRecords(zoneId) {
    if (this.config.useMock || !this.config.apiToken || this.isSimulatedToken(this.config.apiToken)) {
      const filtered = this.mockRecords.filter(r => !zoneId || r.zone_id === zoneId);
      return { success: true, records: filtered, count: filtered.length, isMock: true };
    }

    try {
      const safeZone = assertCfId(zoneId, 'Zone ID');
      /** @type {any[]} */
      const allRecords = [];
      let page = 1;
      let totalPages = 1;
      while (page <= totalPages && page <= 10) {
        const res = await fetch(`${this.apiBase}/zones/${safeZone}/dns_records?per_page=100&page=${page}`, {
          signal: AbortSignal.timeout(10000),
          headers: {
            Authorization: `Bearer ${this.config.apiToken}`,
            'Content-Type': 'application/json'
          }
        });
        /** @type {any} */
        const data = await res.json();
        if (!data.success) {
          return { success: false, errors: data.errors, records: allRecords };
        }
        if (Array.isArray(data.result)) allRecords.push(...data.result);
        totalPages = Number(data.result_info?.total_pages) || 1;
        page++;
      }
      return { success: true, records: allRecords, count: allRecords.length, isMock: false };
    } catch (err) {
      return { success: false, error: err.message, records: [] };
    }
  }

  /**
   * Crea o actualiza idempotentemente un registro DNS en Cloudflare.
   * Si ya existe un registro con el mismo nombre y tipo, lo actualiza en lugar de fallar con error 81057.
   */
  async upsertDnsRecord(zoneId, record) {
    const wantedType = String(record.type || 'A').toUpperCase();
    const wantedName = String(record.name || '').trim().toLowerCase();
    const listed = await this.listDnsRecords(zoneId);
    if (listed.success && Array.isArray(listed.records)) {
      const exact = listed.records.find(
        (r) => String(r.type || '').toUpperCase() === wantedType && String(r.name || '').toLowerCase() === wantedName
      );
      if (exact && exact.id) {
        const upd = await this.updateDnsRecord(zoneId, exact.id, {
          type: wantedType,
          name: wantedName,
          content: record.content,
          ttl: parseInt(String(record.ttl ?? 1), 10),
          proxied: Boolean(record.proxied)
        });
        return { ...upd, action: upd.success ? 'updated' : 'failed' };
      }
      if (wantedType === 'A' || wantedType === 'AAAA') {
        const conflictingCname = listed.records.find(
          (r) => String(r.type || '').toUpperCase() === 'CNAME' && String(r.name || '').toLowerCase() === wantedName
        );
        if (conflictingCname) {
          return {
            success: false,
            action: 'conflict',
            error: `Ya existe un registro CNAME para ${wantedName} apuntando a ${conflictingCname.content}. Elimínalo o cámbialo en Cloudflare primero.`
          };
        }
      }
    }
    const created = await this.createDnsRecord(zoneId, record);
    return {
      ...created,
      action: created.success ? 'created' : 'failed',
      error: created.error || (Array.isArray(created.errors) && created.errors[0]?.message) || undefined
    };
  }

  async createDnsRecord(zoneId, record) {
    const { type, name, content, ttl = 1, proxied = false, comment = 'Managed by Culkibo Orchestrator' } = record;

    if (this.config.useMock || !this.config.apiToken || this.isSimulatedToken(this.config.apiToken)) {
      const newRec = {
        id: `rec_${Date.now()}`,
        zone_id: zoneId || 'cf_zone_98234710293847',
        type: type.toUpperCase(),
        name,
        content,
        ttl: parseInt(ttl, 10),
        proxied: Boolean(proxied),
        proxiable: ['A', 'AAAA', 'CNAME'].includes(type.toUpperCase()),
        locked: false,
        comment,
        created_on: new Date().toISOString()
      };
      this.mockRecords.unshift(newRec);
      return { success: true, record: newRec, isMock: true };
    }

    try {
      const safeZone = assertCfId(zoneId, 'Zone ID');
      const res = await fetch(`${this.apiBase}/zones/${safeZone}/dns_records`, {
        method: 'POST',
        signal: AbortSignal.timeout(10000),
        headers: {
          Authorization: `Bearer ${this.config.apiToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          type: type.toUpperCase(),
          name,
          content,
          ttl: parseInt(ttl, 10),
          proxied: Boolean(proxied),
          comment
        })
      });
      /** @type {any} */
      const data = await res.json();
      if (data.success) {
        return { success: true, record: data.result, isMock: false };
      }
      return { success: false, errors: data.errors };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  async updateDnsRecord(zoneId, recordId, updates) {
    if (this.config.useMock || !this.config.apiToken || this.isSimulatedToken(this.config.apiToken)) {
      const idx = this.mockRecords.findIndex(r => r.id === recordId);
      if (idx >= 0) {
        this.mockRecords[idx] = { ...this.mockRecords[idx], ...updates, modified_on: new Date().toISOString() };
        return { success: true, record: this.mockRecords[idx], isMock: true };
      }
      return { success: false, error: 'Record not found' };
    }

    try {
      const safeZone = assertCfId(zoneId, 'Zone ID');
      const safeRec = assertCfId(recordId, 'Record ID');
      const res = await fetch(`${this.apiBase}/zones/${safeZone}/dns_records/${safeRec}`, {
        method: 'PATCH',
        signal: AbortSignal.timeout(10000),
        headers: {
          Authorization: `Bearer ${this.config.apiToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(updates)
      });
      /** @type {any} */
      const data = await res.json();
      if (data.success) {
        return { success: true, record: data.result, isMock: false };
      }
      return { success: false, errors: data.errors };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  async deleteDnsRecord(zoneId, recordId) {
    if (this.config.useMock || !this.config.apiToken || this.isSimulatedToken(this.config.apiToken)) {
      this.mockRecords = this.mockRecords.filter(r => r.id !== recordId);
      return { success: true, recordId, isMock: true };
    }

    try {
      const safeZone = assertCfId(zoneId, 'Zone ID');
      const safeRec = assertCfId(recordId, 'Record ID');
      const res = await fetch(`${this.apiBase}/zones/${safeZone}/dns_records/${safeRec}`, {
        method: 'DELETE',
        signal: AbortSignal.timeout(10000),
        headers: {
          Authorization: `Bearer ${this.config.apiToken}`,
          'Content-Type': 'application/json'
        }
      });
      /** @type {any} */
      const data = await res.json();
      if (data.success) {
        return { success: true, recordId: data.result.id, isMock: false };
      }
      return { success: false, errors: data.errors };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  // ACME DNS-01 Challenge handling for wildcard SSL:
  // Let's Encrypt requires a TXT record for `_acme-challenge.<rootDomain>`
  async createAcmeTxtRecord(zoneId, domain, challengeKey) {
    const cleanDomain = domain.replace(/^\*\./, '');
    const challengeName = `_acme-challenge.${cleanDomain}`;
    const targetZoneId = zoneId || await this.findZoneForDomain(domain);
    return this.createDnsRecord(targetZoneId, {
      type: 'TXT',
      name: challengeName,
      content: `"${challengeKey}"`,
      ttl: 120, // 2 minutes for fast propagation
      proxied: false,
      comment: `ACME DNS-01 challenge for ${domain} wildcard certificate`
    });
  }

  async listTunnels() {
    if (this.config.useMock || !this.config.apiToken || this.isSimulatedToken(this.config.apiToken)) {
      return { success: true, tunnels: this.mockTunnels, isMock: true };
    }

    try {
      const accountId = await this.ensureAccountId();
      if (!accountId) {
        return { success: false, error: 'Cloudflare Account ID required to list tunnels', tunnels: [] };
      }
      const safeAccount = assertCfId(accountId, 'Account ID');
      const res = await fetch(`${this.apiBase}/accounts/${safeAccount}/cfd_tunnel?is_deleted=false`, {
        signal: AbortSignal.timeout(10000),
        headers: {
          Authorization: `Bearer ${this.config.apiToken}`,
          'Content-Type': 'application/json'
        }
      });
      /** @type {any} */
      const data = await res.json();
      if (data.success) {
        return { success: true, tunnels: data.result, isMock: false };
      }
      return { success: false, errors: data.errors, tunnels: [] };
    } catch (err) {
      return { success: false, error: err.message, tunnels: [] };
    }
  }

  async createTunnel(name) {
    if (this.config.useMock || !this.config.apiToken || this.isSimulatedToken(this.config.apiToken)) {
      const newTunnel = {
        id: `tun_${Math.random().toString(36).substring(2, 15)}`,
        name: name || `culkibo-tunnel-${Date.now().toString(36)}`,
        status: 'healthy',
        created_at: new Date().toISOString(),
        connections: [
          { colo_name: 'MAD', is_pending_reconnect: false, uuid: 'conn_01' }
        ],
        routes: [
          { hostname: `${name || 'edge'}.culkibo.dev`, service: 'http://localhost:3030' }
        ]
      };
      this.mockTunnels.unshift(newTunnel);
      return { success: true, tunnel: newTunnel, token: 'eyJhIjoiY2YtYWNjb3VudC1kZW1vLXNpbXVsYXRlZCJ9...', isMock: true };
    }

    try {
      const accountId = await this.ensureAccountId();
      if (!accountId) throw new Error('Cloudflare Account ID required');
      const safeAccount = assertCfId(accountId, 'Account ID');
      const res = await fetch(`${this.apiBase}/accounts/${safeAccount}/cfd_tunnel`, {
        method: 'POST',
        signal: AbortSignal.timeout(10000),
        headers: {
          Authorization: `Bearer ${this.config.apiToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name: name || `culkibo-${Date.now()}`,
          config_src: 'cloudflare'
        })
      });
      /** @type {any} */
      const data = await res.json();
      if (data.success) {
        return { success: true, tunnel: data.result, token: data.result?.token || null, isMock: false };
      }
      return { success: false, errors: data.errors };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  /** Garantiza un `accountId` real consultando `/zones` o `/accounts` cuando aún no se guardó. */
  async ensureAccountId() {
    if (this.config.accountId) return this.config.accountId;
    if (this.config.useMock || !this.config.apiToken || this.isSimulatedToken(this.config.apiToken)) {
      return 'mock_account_id';
    }
    const zonesRes = await this.listZones();
    if (this.config.accountId) return this.config.accountId;
    if (zonesRes.zones && zonesRes.zones[0]?.account?.id) {
      this.config.accountId = String(zonesRes.zones[0].account.id);
      try { atomicWriteJsonSync(CONFIG_FILE, this.config, 0o600); } catch (e) {}
      return this.config.accountId;
    }
    try {
      const res = await fetch(`${this.apiBase}/accounts?per_page=5`, {
        signal: AbortSignal.timeout(10000),
        headers: { Authorization: `Bearer ${this.config.apiToken}`, 'Content-Type': 'application/json' }
      });
      /** @type {any} */
      const data = await res.json();
      if (data.success && Array.isArray(data.result) && data.result[0]?.id) {
        this.config.accountId = String(data.result[0].id);
        try { atomicWriteJsonSync(CONFIG_FILE, this.config, 0o600); } catch (e) {}
        return this.config.accountId;
      }
    } catch (e) {}
    return '';
  }

  /** Obtiene el token de conector `cloudflared` para un túnel existente. */
  async getTunnelToken(tunnelId) {
    if (this.config.useMock || !this.config.apiToken || this.isSimulatedToken(this.config.apiToken)) {
      return { success: true, tunnelId, token: 'eyJhIjoiY2YtYWNjb3VudC1kZW1vLXNpbXVsYXRlZCJ9...', isMock: true };
    }
    try {
      const accountId = await this.ensureAccountId();
      if (!accountId) throw new Error('Cloudflare Account ID requerido');
      const safeAcc = assertCfId(accountId, 'Account ID');
      const safeTun = assertCfId(tunnelId, 'Tunnel ID');
      const res = await fetch(`${this.apiBase}/accounts/${safeAcc}/cfd_tunnel/${safeTun}/token`, {
        signal: AbortSignal.timeout(10000),
        headers: { Authorization: `Bearer ${this.config.apiToken}`, 'Content-Type': 'application/json' }
      });
      /** @type {any} */
      const data = await res.json();
      if (data.success) return { success: true, tunnelId, token: String(data.result || ''), isMock: false };
      return { success: false, errors: data.errors };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  /** Lee la configuración remota de ingress del túnel. */
  async getTunnelConfig(tunnelId) {
    if (this.config.useMock || !this.config.apiToken || this.isSimulatedToken(this.config.apiToken)) {
      const t = this.mockTunnels.find((x) => x.id === tunnelId);
      const ingress = [...((t && t.routes) || []), { service: 'http_status:404' }];
      return { success: true, config: { ingress }, isMock: true };
    }
    try {
      const accountId = await this.ensureAccountId();
      if (!accountId) throw new Error('Cloudflare Account ID requerido');
      const safeAcc = assertCfId(accountId, 'Account ID');
      const safeTun = assertCfId(tunnelId, 'Tunnel ID');
      const res = await fetch(`${this.apiBase}/accounts/${safeAcc}/cfd_tunnel/${safeTun}/configurations`, {
        signal: AbortSignal.timeout(10000),
        headers: { Authorization: `Bearer ${this.config.apiToken}`, 'Content-Type': 'application/json' }
      });
      /** @type {any} */
      const data = await res.json();
      if (data.success) return { success: true, config: data.result?.config || { ingress: [] }, isMock: false };
      return { success: false, errors: data.errors };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  /** Actualiza las reglas de ingress remotas del túnel garantizando el fallback `http_status:404`. */
  async updateTunnelIngress(tunnelId, ingressRules) {
    const cleanRules = (Array.isArray(ingressRules) ? ingressRules : [])
      .filter((r) => r && typeof r === 'object' && r.service && r.hostname);
    const finalIngress = [...cleanRules, { service: 'http_status:404' }];

    if (this.config.useMock || !this.config.apiToken || this.isSimulatedToken(this.config.apiToken)) {
      const t = this.mockTunnels.find((x) => x.id === tunnelId);
      if (t) t.routes = cleanRules;
      return { success: true, ingress: finalIngress, isMock: true };
    }
    try {
      const accountId = await this.ensureAccountId();
      if (!accountId) throw new Error('Cloudflare Account ID requerido');
      const safeAcc = assertCfId(accountId, 'Account ID');
      const safeTun = assertCfId(tunnelId, 'Tunnel ID');
      const res = await fetch(`${this.apiBase}/accounts/${safeAcc}/cfd_tunnel/${safeTun}/configurations`, {
        method: 'PUT',
        signal: AbortSignal.timeout(10000),
        headers: { Authorization: `Bearer ${this.config.apiToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ config: { ingress: finalIngress } })
      });
      /** @type {any} */
      const data = await res.json();
      if (data.success) return { success: true, ingress: finalIngress, isMock: false };
      return { success: false, errors: data.errors };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  /** Flujo atómico 1 clic: conecta un hostname al túnel (CNAME proxied + regla de ingress remota). */
  async routeHostnameToTunnel({ tunnelId, zoneId = null, hostname, serviceUrl }) {
    const cleanHost = String(hostname || '').trim().toLowerCase();
    const cleanService = String(serviceUrl || '').trim();
    if (!cleanHost || !/^[a-z0-9.-]+\.[a-z0-9-]{2,}$/.test(cleanHost)) {
      throw new Error(`Hostname inválido para túnel: ${hostname}`);
    }
    if (!/^https?:\/\/[a-zA-Z0-9._:-]+$/.test(cleanService)) {
      throw new Error(`Destino serviceUrl inválido: ${serviceUrl}`);
    }

    const currentCfg = await this.getTunnelConfig(tunnelId);
    const existing = Array.isArray(currentCfg.config?.ingress) ? currentCfg.config.ingress : [];
    const nextRules = [
      ...existing.filter((r) => r && r.hostname && String(r.hostname).toLowerCase() !== cleanHost),
      { hostname: cleanHost, service: cleanService }
    ];
    const ingRes = await this.updateTunnelIngress(tunnelId, nextRules);
    if (!ingRes.success) return { ...ingRes, success: false, step: 'ingress' };

    const resolvedZoneId = zoneId || await this.findZoneForDomain(cleanHost);
    /** @type {any} */
    let dnsRes = { success: false, skipped: true };
    if (resolvedZoneId) {
      dnsRes = await this.upsertDnsRecord(resolvedZoneId, {
        type: 'CNAME',
        name: cleanHost,
        content: `${tunnelId}.cfargotunnel.com`,
        proxied: true,
        ttl: 1,
        comment: `Túnel Cloudflare gestionado por Culkibo (${tunnelId})`
      });
    }
    return {
      success: true,
      hostname: cleanHost,
      serviceUrl: cleanService,
      tunnelId,
      ingress: ingRes.ingress,
      dns: dnsRes,
      isMock: Boolean(ingRes.isMock)
    };
  }

  async deleteTunnel(tunnelId) {
    if (this.config.useMock || !this.config.apiToken || this.isSimulatedToken(this.config.apiToken)) {
      this.mockTunnels = this.mockTunnels.filter((t) => t.id !== tunnelId);
      return { success: true, deletedId: tunnelId, isMock: true };
    }
    try {
      const accountId = await this.ensureAccountId();
      if (!accountId) throw new Error('Cloudflare Account ID requerido');
      const safeAcc = assertCfId(accountId, 'Account ID');
      const safeTun = assertCfId(tunnelId, 'Tunnel ID');
      const res = await fetch(`${this.apiBase}/accounts/${safeAcc}/cfd_tunnel/${safeTun}`, {
        method: 'DELETE',
        signal: AbortSignal.timeout(10000),
        headers: { Authorization: `Bearer ${this.config.apiToken}`, 'Content-Type': 'application/json' }
      });
      /** @type {any} */
      const data = await res.json();
      if (data.success) return { success: true, deletedId: tunnelId, isMock: false };
      return { success: false, errors: data.errors };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  /**
   * Arranca el conector oficial `cloudflared` en Docker pasando el token por --env-file 0600 (nunca en argv).
   * @param {{ tunnelToken?: string, containerName?: string }} [opts]
   */
  async startCloudflaredDocker({ tunnelToken = '', containerName = 'culkibo-cloudflared' } = {}) {
    const cleanToken = String(tunnelToken || '').trim();
    if (!cleanToken || /[\r\n\0\s]/.test(cleanToken)) {
      throw new Error('Token de túnel Cloudflare inválido');
    }
    const cleanName = String(containerName || 'culkibo-cloudflared').trim();
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/.test(cleanName)) {
      throw new Error(`Nombre de contenedor inválido: ${cleanName}`);
    }

    fs.mkdirSync(TMP_DIR, { recursive: true, mode: 0o700 });
    const envFile = path.join(TMP_DIR, `cf-tunnel-${Date.now()}.env`);
    fs.writeFileSync(envFile, `TUNNEL_TOKEN=${cleanToken}\n`, { mode: 0o600 });

    const runDocker = (args) => new Promise((resolve) => {
      const child = spawn('docker', args, { shell: false, windowsHide: true });
      let err = '';
      child.stderr.on('data', (d) => { err += d.toString(); });
      child.on('error', (e) => resolve({ code: -1, stderr: e.message }));
      child.on('close', (code) => resolve({ code: code ?? -1, stderr: err.trim() }));
    });

    try {
      await runDocker(['rm', '-f', cleanName]);
      const args = [
        'run', '-d',
        '--name', cleanName,
        '--restart', 'unless-stopped',
        '--label', 'culkibo.managed=true',
        '--env-file', envFile
      ];
      if (process.platform === 'linux') {
        args.push('--network', 'host');
      } else {
        args.push('--add-host', 'host.docker.internal:host-gateway');
      }
      args.push('cloudflare/cloudflared:latest', 'tunnel', '--no-autoupdate', 'run');
      const res = await runDocker(args);
      if (res.code !== 0) {
        return { started: false, error: res.stderr || `docker run falló (código ${res.code})` };
      }
      return { started: true, containerName: cleanName };
    } finally {
      try { fs.unlinkSync(envFile); } catch (e) {}
    }
  }
}

module.exports = new CloudflareService();
