const fs = require('fs');
const path = require('path');

const CONFIG_FILE = path.join(__dirname, '..', '..', 'data', 'cloudflare-config.json');

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
        return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
      }
    } catch (e) {
      console.error('[Cloudflare] Error reading config file:', e.message);
    }
    return {
      apiToken: process.env.CLOUDFLARE_API_TOKEN || '',
      accountId: process.env.CLOUDFLARE_ACCOUNT_ID || '',
      defaultZoneId: '',
      isConfigured: false,
      useMock: true
    };
  }

  isSimulatedToken(token) {
    if (!token) return true;
    const clean = String(token).toLowerCase();
    return clean === 'demo' || clean === 'mock' || clean.startsWith('demo_') || clean.startsWith('mock_');
  }

  saveConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    this.config.isConfigured = Boolean(this.config.apiToken);
    if (this.isSimulatedToken(this.config.apiToken)) {
      this.config.useMock = true;
    } else if (newConfig.useMock !== undefined) {
      this.config.useMock = Boolean(newConfig.useMock);
    }
    const dir = path.dirname(CONFIG_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(this.config, null, 2), 'utf8');
    return this.config;
  }

  async findZoneForDomain(domain) {
    if (!domain) return this.mockZones[0].id;
    const clean = domain.replace(/^\*\./, '').toLowerCase();
    const parts = clean.split('.');
    const rootDomain = parts.length > 2 ? parts.slice(-2).join('.') : clean;

    const zonesRes = await this.listZones();
    if (zonesRes.success && zonesRes.zones?.length) {
      const match = zonesRes.zones.find(z => z.name === rootDomain || z.name === clean);
      if (match) return match.id;
      return zonesRes.zones[0].id;
    }
    return this.mockZones[0].id;
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
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
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
      const res = await fetch(`${this.apiBase}/zones?status=active&per_page=50`, {
        headers: {
          Authorization: `Bearer ${this.config.apiToken}`,
          'Content-Type': 'application/json'
        }
      });
      const data = await res.json();
      if (data.success) {
        return { success: true, zones: data.result, count: data.result.length, isMock: false };
      }
      return { success: false, errors: data.errors, zones: [] };
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
      const res = await fetch(`${this.apiBase}/zones/${zoneId}/dns_records?per_page=100`, {
        headers: {
          Authorization: `Bearer ${this.config.apiToken}`,
          'Content-Type': 'application/json'
        }
      });
      const data = await res.json();
      if (data.success) {
        return { success: true, records: data.result, count: data.result.length, isMock: false };
      }
      return { success: false, errors: data.errors, records: [] };
    } catch (err) {
      return { success: false, error: err.message, records: [] };
    }
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
        comment,
        created_on: new Date().toISOString()
      };
      this.mockRecords.unshift(newRec);
      return { success: true, record: newRec, isMock: true };
    }

    try {
      const res = await fetch(`${this.apiBase}/zones/${zoneId}/dns_records`, {
        method: 'POST',
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
      const res = await fetch(`${this.apiBase}/zones/${zoneId}/dns_records/${recordId}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${this.config.apiToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(updates)
      });
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
      const res = await fetch(`${this.apiBase}/zones/${zoneId}/dns_records/${recordId}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${this.config.apiToken}`,
          'Content-Type': 'application/json'
        }
      });
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
      const accountId = this.config.accountId;
      if (!accountId) {
        return { success: false, error: 'Cloudflare Account ID required to list tunnels', tunnels: [] };
      }
      const res = await fetch(`${this.apiBase}/accounts/${accountId}/cfd_tunnel?is_deleted=false`, {
        headers: {
          Authorization: `Bearer ${this.config.apiToken}`,
          'Content-Type': 'application/json'
        }
      });
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
      const accountId = this.config.accountId;
      if (!accountId) throw new Error('Cloudflare Account ID required');
      const res = await fetch(`${this.apiBase}/accounts/${accountId}/cfd_tunnel`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.config.apiToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name: name || `culkibo-${Date.now()}`,
          config_src: 'cloudflare'
        })
      });
      const data = await res.json();
      if (data.success) {
        return { success: true, tunnel: data.result, isMock: false };
      }
      return { success: false, errors: data.errors };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }
}

module.exports = new CloudflareService();
