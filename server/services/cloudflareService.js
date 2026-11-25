const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { atomicWriteJsonSync, isMetadataIp } = require('./ssrfGuard');

const DATA_DIR = process.env.CULKIBO_DATA_DIR
  ? path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data')
  : path.resolve(__dirname, '..', '..', 'data');
const CF_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const CONTAINER_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/;
const TUNNEL_HOST_RE = /^(?:\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
const DEFAULT_CLOUDFLARED_IMAGE = 'cloudflare/cloudflared:2026.2.0';

function assertCfId(value, label = 'ID de Cloudflare') {
  const s = String(value || '').trim();
  if (!CF_ID_RE.test(s)) throw new Error(`${label} inválido`);
  return encodeURIComponent(s);
}

function assertContainerName(containerName) {
  const cleanName = String(containerName || 'culkibo-cloudflared').trim();
  if (!CONTAINER_NAME_RE.test(cleanName)) {
    throw new Error(`Nombre de contenedor inválido: ${cleanName}`);
  }
  return cleanName;
}

/**
 * Valida un hostname de túnel (admite exactos `app.dominio.com` y comodines `*.dominio.com`).
 * @param {string} raw
 * @returns {string}
 */
function validateTunnelHostname(raw) {
  const clean = String(raw || '').trim().toLowerCase().replace(/\.+$/, '');
  if (!clean || clean.length > 253 || /[\s\r\n\0]/.test(clean) || !TUNNEL_HOST_RE.test(clean)) {
    throw new Error(`Hostname inválido para túnel: ${raw}`);
  }
  return clean;
}

/**
 * Valida la URL destino de un túnel (`http(s)://host[:port]`, IPv6 `[::1]:3000`, `http_status:404`).
 * Bloquea direcciones de metadatos cloud (SSRF).
 * @param {string} raw
 * @returns {string}
 */
function validateTunnelServiceUrl(raw) {
  const clean = String(raw || '').trim();
  if (!clean || /[\s\r\n\0]/.test(clean)) {
    throw new Error(`Destino serviceUrl inválido: ${raw}`);
  }
  if (/^http_status:(?:404|403|503)$/.test(clean)) return clean;
  let parsed;
  try {
    parsed = new URL(clean);
  } catch (err) {
    throw new Error(`Destino serviceUrl inválido: ${raw}`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Protocolo de serviceUrl no permitido: ${parsed.protocol}`);
  }
  const bareHost = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!bareHost || isMetadataIp(bareHost) || bareHost === 'metadata.google.internal' || bareHost === '169.254.169.254') {
    throw new Error(`Destino serviceUrl bloqueado por protección SSRF: ${bareHost}`);
  }
  const normalized = `${parsed.protocol}//${parsed.host}${parsed.pathname && parsed.pathname !== '/' ? parsed.pathname : ''}`;
  return normalized;
}

/**
 * Valida y normaliza `originRequest` para reglas de ingress de Cloudflare Tunnel.
 * @param {any} raw
 * @returns {Record<string, any> | undefined}
 */
function sanitizeOriginRequest(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  /** @type {Record<string, any>} */
  const out = {};
  if (raw.httpHostHeader !== undefined && raw.httpHostHeader !== null && String(raw.httpHostHeader).trim() !== '') {
    const h = String(raw.httpHostHeader).trim().toLowerCase();
    if (/[\s\r\n\0]/.test(h) || !/^[a-z0-9.-]{1,253}(?::\d{1,5})?$/.test(h)) {
      throw new Error(`originRequest.httpHostHeader inválido: ${h.slice(0, 60)}`);
    }
    out.httpHostHeader = h;
  }
  if (raw.noTLSVerify !== undefined) {
    out.noTLSVerify = Boolean(raw.noTLSVerify);
  }
  if (raw.http2Origin !== undefined) {
    out.http2Origin = Boolean(raw.http2Origin);
  }
  if (raw.disableChunkedEncoding !== undefined) {
    out.disableChunkedEncoding = Boolean(raw.disableChunkedEncoding);
  }
  if (raw.connectTimeout !== undefined && raw.connectTimeout !== null && raw.connectTimeout !== '') {
    const secs = typeof raw.connectTimeout === 'string'
      ? Number(raw.connectTimeout.replace(/s$/i, ''))
      : Number(raw.connectTimeout);
    if (!Number.isFinite(secs) || secs < 1 || secs > 300) {
      throw new Error('originRequest.connectTimeout debe estar entre 1 y 300 segundos');
    }
    out.connectTimeout = Math.round(secs);
  }
  if (raw.keepAliveTimeout !== undefined && raw.keepAliveTimeout !== null && raw.keepAliveTimeout !== '') {
    const secs = typeof raw.keepAliveTimeout === 'string'
      ? Number(raw.keepAliveTimeout.replace(/s$/i, ''))
      : Number(raw.keepAliveTimeout);
    if (!Number.isFinite(secs) || secs < 1 || secs > 600) {
      throw new Error('originRequest.keepAliveTimeout debe estar entre 1 y 600 segundos');
    }
    out.keepAliveTimeout = Math.round(secs);
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/**
 * Ordena reglas de ingress de Cloudflare Tunnel: exactos primero (path más largo antes),
 * luego comodines por sufijo más largo primero (`*.sub.a.com` antes que `*.a.com`).
 * @param {any[]} rules
 */
function sortTunnelIngressRules(rules) {
  return [...rules].sort((a, b) => {
    const ha = String(a.hostname || '').toLowerCase();
    const hb = String(b.hostname || '').toLowerCase();
    const wa = ha.startsWith('*.') ? 1 : 0;
    const wb = hb.startsWith('*.') ? 1 : 0;
    if (wa !== wb) return wa - wb;
    if (wa === 1 && hb.length !== ha.length) return hb.length - ha.length;
    const pa = String(a.path || '').length;
    const pb = String(b.path || '').length;
    if (pa !== pb) return pb - pa;
    return ha.localeCompare(hb);
  });
}

/** Redacta posibles tokens de túnel o Bearer en salidas de log de `cloudflared`. */
function redactCloudflaredOutput(text) {
  return String(text || '')
    .replace(/(TUNNEL_TOKEN\s*=\s*)[^\s"']+/gi, '$1[REDACTED]')
    .replace(/(--token\s+)[^\s"']+/gi, '$1[REDACTED]')
    .replace(/(Bearer\s+)[A-Za-z0-9._-]+/gi, '$1[REDACTED]')
    .replace(/\beyJ[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]+){0,2}\b/g, '[REDACTED_TUNNEL_TOKEN]');
}

class CloudflareService {
  /**
   * @param {{
   *   dataDir?: string | null,
   *   configFile?: string | null,
   *   tmpDir?: string | null,
   *   runCommand?: ((bin: string, args: string[]) => Promise<{ code: number, stdout: string, stderr: string }>) | null,
   *   fetch?: typeof fetch | null
   * }} [opts]
   */
  constructor(opts = {}) {
    this.apiBase = 'https://api.cloudflare.com/client/v4';
    this.dataDir = opts.dataDir ? path.resolve(opts.dataDir) : DATA_DIR;
    this.configFile = opts.configFile ? path.resolve(opts.configFile) : path.join(this.dataDir, 'cloudflare-config.json');
    this.tmpDir = opts.tmpDir ? path.resolve(opts.tmpDir) : path.join(this.dataDir, '.tmp');
    this._customRunCommand = typeof opts.runCommand === 'function' ? opts.runCommand : null;
    this._customFetch = typeof opts.fetch === 'function' ? opts.fetch : null;
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

  /** @param {string} url @param {any} [init] */
  _httpFetch(url, init) {
    const fn = this._customFetch || fetch;
    return fn(url, init);
  }

  /**
   * Ejecuta un subproceso sin shell (`shell: false`, argv estricto) con timeout seguro.
   * @param {string} bin
   * @param {string[]} args
   * @param {number} [timeoutMs]
   * @returns {Promise<{ code: number, stdout: string, stderr: string }>}
   */
  _execBin(bin, args, timeoutMs = 15000) {
    if (this._customRunCommand) {
      return this._customRunCommand(bin, args);
    }
    return new Promise((resolve) => {
      try {
        const child = spawn(bin, args, { shell: false, windowsHide: true });
        let stdout = '';
        let stderr = '';
        const timer = setTimeout(() => {
          try { child.kill(); } catch (e) {}
          resolve({ code: -1, stdout: stdout.trim(), stderr: `Timeout (${timeoutMs} ms) ejecutando ${bin}` });
        }, timeoutMs);
        if (timer.unref) timer.unref();
        child.stdout.on('data', (d) => { stdout += d.toString('utf8'); });
        child.stderr.on('data', (d) => { stderr += d.toString('utf8'); });
        child.on('error', (e) => {
          clearTimeout(timer);
          resolve({ code: -1, stdout: stdout.trim(), stderr: e.message });
        });
        child.on('close', (code) => {
          clearTimeout(timer);
          resolve({ code: code ?? -1, stdout: stdout.trim(), stderr: stderr.trim() });
        });
      } catch (err) {
        resolve({ code: -1, stdout: '', stderr: err.message });
      }
    });
  }

  loadConfig() {
    try {
      if (fs.existsSync(this.configFile)) {
        const stored = JSON.parse(fs.readFileSync(this.configFile, 'utf8'));
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
    } else if (filtered.apiToken) {
      // Un token real recién configurado desactiva el modo simulado automáticamente.
      this.config.useMock = false;
    }
    atomicWriteJsonSync(this.configFile, this.config, 0o600);
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
        try { atomicWriteJsonSync(this.configFile, this.config, 0o600); } catch (e) {}
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
      const sameTypeAndName = listed.records.filter(
        (r) => String(r.type || '').toUpperCase() === wantedType && String(r.name || '').toLowerCase() === wantedName
      );
      // Para TXT/MX/NS puede haber varios registros con el mismo nombre: priorizar coincidencia de contenido
      const multiAllowed = wantedType === 'TXT' || wantedType === 'MX' || wantedType === 'NS' || wantedType === 'SRV';
      const exact = sameTypeAndName.find((r) => String(r.content || '').trim() === String(record.content || '').trim())
        || (!multiAllowed ? sameTypeAndName[0] : null);
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
      try { atomicWriteJsonSync(this.configFile, this.config, 0o600); } catch (e) {}
      return this.config.accountId;
    }
    try {
      const res = await this._httpFetch(`${this.apiBase}/accounts?per_page=5`, {
        signal: AbortSignal.timeout(10000),
        headers: { Authorization: `Bearer ${this.config.apiToken}`, 'Content-Type': 'application/json' }
      });
      /** @type {any} */
      const data = await res.json();
      if (data.success && Array.isArray(data.result) && data.result[0]?.id) {
        this.config.accountId = String(data.result[0].id);
        try { atomicWriteJsonSync(this.configFile, this.config, 0o600); } catch (e) {}
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

  /** Actualiza las reglas de ingress remotas del túnel garantizando orden determinista y fallback `http_status:404`. */
  async updateTunnelIngress(tunnelId, ingressRules) {
    /** @type {Array<{ hostname: string, service: string, path?: string, originRequest?: Record<string, any> }>} */
    const cleanRules = [];
    for (const r of (Array.isArray(ingressRules) ? ingressRules : [])) {
      if (!r || typeof r !== 'object' || !r.hostname || !r.service) continue;
      const hostname = validateTunnelHostname(r.hostname);
      const service = validateTunnelServiceUrl(r.service);
      /** @type {{ hostname: string, service: string, path?: string, originRequest?: Record<string, any> }} */
      const entry = { hostname, service };
      if (typeof r.path === 'string' && r.path.trim()) {
        const cleanPath = r.path.trim();
        if (!cleanPath.startsWith('/') || /[\s\r\n\0]/.test(cleanPath) || cleanPath.includes('..')) {
          throw new Error(`Ruta path inválida en regla de túnel: ${cleanPath.slice(0, 60)}`);
        }
        entry.path = cleanPath;
      }
      const originReq = sanitizeOriginRequest(r.originRequest);
      if (originReq) entry.originRequest = originReq;
      cleanRules.push(entry);
    }

    const sortedRules = sortTunnelIngressRules(cleanRules);
    const finalIngress = [...sortedRules, { service: 'http_status:404' }];

    if (this.config.useMock || !this.config.apiToken || this.isSimulatedToken(this.config.apiToken)) {
      const t = this.mockTunnels.find((x) => x.id === tunnelId);
      if (t) t.routes = sortedRules;
      return { success: true, ingress: finalIngress, isMock: true };
    }
    try {
      const accountId = await this.ensureAccountId();
      if (!accountId) throw new Error('Cloudflare Account ID requerido');
      const safeAcc = assertCfId(accountId, 'Account ID');
      const safeTun = assertCfId(tunnelId, 'Tunnel ID');
      const res = await this._httpFetch(`${this.apiBase}/accounts/${safeAcc}/cfd_tunnel/${safeTun}/configurations`, {
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

  /**
   * Flujo atómico 1 clic: conecta un hostname (exacto o comodín `*.dominio.com`) al túnel
   * con `originRequest` opcional (`httpHostHeader`, `noTLSVerify`, `connectTimeout`, `http2Origin`)
   * y CNAME proxied hacia `<tunnelId>.cfargotunnel.com`.
   *
   * @param {{
   *   tunnelId: string,
   *   zoneId?: string | null,
   *   hostname: string,
   *   serviceUrl: string,
   *   path?: string | null,
   *   originRequest?: { httpHostHeader?: string, noTLSVerify?: boolean, connectTimeout?: number | string, http2Origin?: boolean, disableChunkedEncoding?: boolean, keepAliveTimeout?: number | string } | null
   * }} opts
   */
  async routeHostnameToTunnel({ tunnelId, zoneId = null, hostname, serviceUrl, path: routePath = null, originRequest = null }) {
    const cleanHost = validateTunnelHostname(hostname);
    const cleanService = validateTunnelServiceUrl(serviceUrl);
    const cleanOriginReq = sanitizeOriginRequest(originRequest);
    const cleanPath = (typeof routePath === 'string' && routePath.trim()) ? routePath.trim() : null;
    if (cleanPath && (!cleanPath.startsWith('/') || /[\s\r\n\0]/.test(cleanPath) || cleanPath.includes('..'))) {
      throw new Error(`Ruta path inválida para túnel: ${routePath}`);
    }

    const currentCfg = await this.getTunnelConfig(tunnelId);
    const existing = Array.isArray(currentCfg.config?.ingress) ? currentCfg.config.ingress : [];
    const nextRule = {
      hostname: cleanHost,
      service: cleanService,
      ...(cleanPath ? { path: cleanPath } : {}),
      ...(cleanOriginReq ? { originRequest: cleanOriginReq } : {})
    };
    const nextRules = [
      ...existing.filter((r) => {
        if (!r || !r.hostname) return false;
        const sameHost = String(r.hostname).toLowerCase() === cleanHost;
        const samePath = String(r.path || '') === String(cleanPath || '');
        return !(sameHost && samePath);
      }),
      nextRule
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
      path: cleanPath,
      originRequest: cleanOriginReq || null,
      tunnelId,
      ingress: ingRes.ingress,
      dns: dnsRes,
      isMock: Boolean(ingRes.isMock)
    };
  }

  /**
   * Retira un hostname (y opcionalmente su registro CNAME `<tunnelId>.cfargotunnel.com`)
   * de un túnel Cloudflare preservando el resto de reglas y el fallback `http_status:404`.
   *
   * @param {{ tunnelId: string, zoneId?: string | null, hostname: string, path?: string | null, removeDns?: boolean }} opts
   */
  async unrouteHostnameFromTunnel({ tunnelId, zoneId = null, hostname, path: routePath = null, removeDns = true }) {
    const cleanHost = validateTunnelHostname(hostname);
    const cleanPath = (typeof routePath === 'string' && routePath.trim()) ? routePath.trim() : null;
    const currentCfg = await this.getTunnelConfig(tunnelId);
    const existing = Array.isArray(currentCfg.config?.ingress) ? currentCfg.config.ingress : [];
    const remaining = existing.filter((r) => {
      if (!r || !r.hostname) return false;
      const sameHost = String(r.hostname).toLowerCase() === cleanHost;
      if (!sameHost) return true;
      if (cleanPath !== null) return String(r.path || '') !== cleanPath;
      return false;
    });
    const removedCount = existing.filter((r) => r && r.hostname).length - remaining.length;
    const ingRes = await this.updateTunnelIngress(tunnelId, remaining);
    if (!ingRes.success) return { ...ingRes, success: false, step: 'ingress' };

    /** @type {any} */
    let dnsRemoved = { removed: false, skipped: !removeDns };
    if (removeDns) {
      const resolvedZoneId = zoneId || await this.findZoneForDomain(cleanHost);
      if (resolvedZoneId) {
        const listed = await this.listDnsRecords(resolvedZoneId);
        const expectedTarget = `${tunnelId}.cfargotunnel.com`.toLowerCase();
        const match = (listed.records || []).find((r) =>
          String(r.type || '').toUpperCase() === 'CNAME' &&
          String(r.name || '').toLowerCase() === cleanHost &&
          String(r.content || '').toLowerCase() === expectedTarget
        );
        if (match && match.id) {
          const del = await this.deleteDnsRecord(resolvedZoneId, match.id);
          dnsRemoved = { removed: Boolean(del.success), recordId: match.id };
        }
      }
    }

    return {
      success: true,
      hostname: cleanHost,
      tunnelId,
      removedRules: removedCount,
      ingress: ingRes.ingress,
      dns: dnsRemoved,
      isMock: Boolean(ingRes.isMock)
    };
  }

  /**
   * Modo CGNAT 0-puertos-abiertos ("All Resources to Caddy", Coolify/Dokploy #4309):
   * enruta uno o varios hostnames (incluidos comodines `*.dominio.com`) hacia el plano de datos
   * Caddy local preservando cabeceras Host y creando/actualizando sus CNAMEs proxied.
   *
   * @param {{
   *   tunnelId: string,
   *   zoneId?: string | null,
   *   hostnames: string[],
   *   caddyUpstream?: string,
   *   noTLSVerify?: boolean,
   *   connectTimeout?: number
   * }} opts
   */
  async configureAllResourcesTunnel({
    tunnelId,
    zoneId = null,
    hostnames = [],
    caddyUpstream = 'http://127.0.0.1:80',
    noTLSVerify = false,
    connectTimeout = 30
  }) {
    if (!Array.isArray(hostnames) || hostnames.length === 0) {
      throw new Error('Indica al menos un hostname o comodín (*.dominio.com) para publicar por túnel');
    }
    const cleanUpstream = validateTunnelServiceUrl(caddyUpstream);
    const cleanHosts = Array.from(new Set(hostnames.map((h) => validateTunnelHostname(h))));
    const originRequest = sanitizeOriginRequest({
      noTLSVerify: Boolean(noTLSVerify),
      connectTimeout
    });

    const rules = cleanHosts.map((h) => ({
      hostname: h,
      service: cleanUpstream,
      ...(originRequest ? { originRequest } : {})
    }));
    const ingRes = await this.updateTunnelIngress(tunnelId, rules);
    if (!ingRes.success) return { ...ingRes, success: false, step: 'ingress' };

    /** @type {Array<{ hostname: string, success: boolean, action?: string, skipped?: boolean, error?: string }>} */
    const dnsResults = [];
    for (const h of cleanHosts) {
      const targetZone = zoneId || await this.findZoneForDomain(h);
      if (!targetZone) {
        dnsResults.push({ hostname: h, success: false, skipped: true });
        continue;
      }
      const res = await this.upsertDnsRecord(targetZone, {
        type: 'CNAME',
        name: h,
        content: `${tunnelId}.cfargotunnel.com`,
        proxied: true,
        ttl: 1,
        comment: `Túnel CGNAT Culkibo → Caddy (${tunnelId})`
      });
      dnsResults.push({
        hostname: h,
        success: Boolean(res.success),
        action: res.action,
        ...(res.error ? { error: res.error } : {})
      });
    }

    return {
      success: true,
      mode: 'all_to_caddy',
      tunnelId,
      caddyUpstream: cleanUpstream,
      hostnames: cleanHosts,
      ingress: ingRes.ingress,
      dns: dnsResults,
      isMock: Boolean(ingRes.isMock)
    };
  }

  /** Reconciliación declarativa de reglas de ingress de un túnel (sin borrar DNS existentes). */
  async syncTunnelRoutes(tunnelId, desiredRoutes) {
    return this.updateTunnelIngress(tunnelId, desiredRoutes);
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
      const res = await this._httpFetch(`${this.apiBase}/accounts/${safeAcc}/cfd_tunnel/${safeTun}`, {
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
   * Soporta protocolo QUIC/HTTP2 y endpoint loopback opcional de métricas para probes de salud.
   *
   * @param {{ tunnelToken?: string, containerName?: string, protocol?: 'auto' | 'quic' | 'http2', metricsPort?: number | null }} [opts]
   */
  async startCloudflaredDocker({
    tunnelToken = '',
    containerName = 'culkibo-cloudflared',
    protocol = 'auto',
    metricsPort = null
  } = {}) {
    const cleanToken = String(tunnelToken || '').trim();
    if (!cleanToken || /[\r\n\0\s]/.test(cleanToken)) {
      throw new Error('Token de túnel Cloudflare inválido');
    }
    const cleanName = assertContainerName(containerName);
    const cleanProto = String(protocol || 'auto').trim().toLowerCase();
    if (!['auto', 'quic', 'http2'].includes(cleanProto)) {
      throw new Error(`Protocolo cloudflared inválido: ${protocol} (usa auto, quic o http2)`);
    }
    /** @type {number | null} */
    let cleanMetricsPort = null;
    if (metricsPort !== null && metricsPort !== undefined && String(metricsPort) !== '') {
      const mp = Number(metricsPort);
      if (!Number.isInteger(mp) || mp < 1024 || mp > 65535) {
        throw new Error(`Puerto de métricas cloudflared inválido: ${metricsPort}`);
      }
      cleanMetricsPort = mp;
    }

    fs.mkdirSync(this.tmpDir, { recursive: true, mode: 0o700 });
    const envFile = path.join(this.tmpDir, `cf-tunnel-${Date.now()}-${crypto.randomBytes(6).toString('hex')}.env`);
    fs.writeFileSync(envFile, `TUNNEL_TOKEN=${cleanToken}\n`, { mode: 0o600 });

    try {
      await this._execBin('docker', ['rm', '-f', cleanName]);
      const args = [
        'run', '-d',
        '--name', cleanName,
        '--restart', 'unless-stopped',
        '--label', 'culkibo.managed=true',
        '--label', 'culkibo.component=cloudflared',
        '--log-driver', 'json-file',
        '--log-opt', 'max-size=10m',
        '--log-opt', 'max-file=3',
        '--env-file', envFile
      ];
      if (process.platform === 'linux') {
        args.push('--network', 'host');
      } else {
        args.push('--add-host', 'host.docker.internal:host-gateway');
        if (cleanMetricsPort) {
          args.push('-p', `127.0.0.1:${cleanMetricsPort}:${cleanMetricsPort}`);
        }
      }
      const cfImage = String(process.env.CULKIBO_CLOUDFLARED_IMAGE || DEFAULT_CLOUDFLARED_IMAGE).trim();
      if (cfImage.startsWith('-') || !/^[a-zA-Z0-9._/:@-]+$/.test(cfImage)) {
        throw new Error(`Imagen cloudflared inválida: ${cfImage}`);
      }
      const cmdArgs = ['tunnel', '--no-autoupdate'];
      if (cleanProto !== 'auto') cmdArgs.push('--protocol', cleanProto);
      if (cleanMetricsPort) cmdArgs.push('--metrics', `127.0.0.1:${cleanMetricsPort}`);
      cmdArgs.push('run');

      args.push(cfImage, ...cmdArgs);
      const res = await this._execBin('docker', args);
      if (res.code !== 0) {
        return { started: false, error: redactCloudflaredOutput(res.stderr) || `docker run falló (código ${res.code})` };
      }
      const status = await this.getCloudflaredStatus({ containerName: cleanName }).catch(() => null);
      return {
        started: true,
        containerName: cleanName,
        image: cfImage,
        protocol: cleanProto,
        ...(cleanMetricsPort ? { metricsPort: cleanMetricsPort } : {}),
        ...(status ? { status } : {})
      };
    } finally {
      try { fs.unlinkSync(envFile); } catch (e) {}
    }
  }

  /** Inspecciona el estado real del conector `cloudflared` en Docker (`shell: false`). */
  async getCloudflaredStatus({ containerName = 'culkibo-cloudflared' } = {}) {
    const cleanName = assertContainerName(containerName);
    const inspect = await this._execBin('docker', [
      'inspect',
      '--format',
      '{{.Id}}|{{.State.Running}}|{{.State.Status}}|{{.RestartCount}}|{{.State.StartedAt}}|{{.Config.Image}}',
      cleanName
    ], 5000);
    if (inspect.code !== 0 || !inspect.stdout) {
      return {
        running: false,
        exists: false,
        status: 'not_found',
        containerName: cleanName,
        image: null,
        startedAt: null,
        restartCount: 0,
        containerId: null,
        error: inspect.stderr || null
      };
    }
    const [id = '', runningStr = 'false', stateStatus = 'unknown', restartStr = '0', startedAt = '', image = ''] = inspect.stdout.split('|');
    return {
      running: runningStr.trim() === 'true',
      exists: true,
      status: stateStatus.trim() || 'unknown',
      containerName: cleanName,
      image: image.trim() || null,
      startedAt: startedAt.trim() || null,
      restartCount: Number(restartStr) || 0,
      containerId: id.trim() ? id.trim().slice(0, 12) : null,
      error: null
    };
  }

  /** Detiene (y opcionalmente elimina) el contenedor conector `cloudflared` (`shell: false`). */
  async stopCloudflaredDocker({ containerName = 'culkibo-cloudflared', remove = true } = {}) {
    const cleanName = assertContainerName(containerName);
    const args = remove ? ['rm', '-f', cleanName] : ['stop', cleanName];
    const res = await this._execBin('docker', args, 10000);
    if (res.code !== 0) {
      if (/no such container/i.test(res.stderr || '')) {
        return { stopped: true, existed: false, containerName: cleanName };
      }
      return { stopped: false, existed: true, containerName: cleanName, error: redactCloudflaredOutput(res.stderr) };
    }
    return { stopped: true, existed: true, removed: Boolean(remove), containerName: cleanName };
  }

  /** Obtiene los últimos logs del conector `cloudflared` redactando tokens (`shell: false`). */
  async getCloudflaredLogs({ containerName = 'culkibo-cloudflared', tail = 100 } = {}) {
    const cleanName = assertContainerName(containerName);
    const safeTail = Math.min(500, Math.max(1, Math.round(Number(tail) || 100)));
    const res = await this._execBin('docker', ['logs', '--tail', String(safeTail), cleanName], 8000);
    if (res.code !== 0) {
      return { ok: false, containerName: cleanName, lines: [], error: redactCloudflaredOutput(res.stderr) };
    }
    const combined = [res.stdout, res.stderr].filter(Boolean).join('\n');
    const redacted = redactCloudflaredOutput(combined);
    const lines = redacted ? redacted.split(/\r?\n/).filter(Boolean) : [];
    return { ok: true, containerName: cleanName, lines };
  }
}

const cloudflareServiceInstance = Object.assign(new CloudflareService(), {
  CloudflareService,
  assertCfId,
  validateTunnelHostname,
  validateTunnelServiceUrl,
  sanitizeOriginRequest,
  sortTunnelIngressRules,
  redactCloudflaredOutput
});
module.exports = cloudflareServiceInstance;
