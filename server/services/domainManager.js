const fs = require('fs');
const net = require('net');
const path = require('path');
const url = require('url');
const { atomicWriteJsonSync, loadJsonWithBackupSync } = require('./ssrfGuard');
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
const VALID_TLD_RE = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/;
const HEADER_NAME_RE = /^[A-Za-z0-9-]+$/;
const INVISIBLE_OR_BIDI_RE = /[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/;
const LATIN_SCRIPT_RE = /\p{Script=Latin}/u;
const CYRILLIC_SCRIPT_RE = /\p{Script=Cyrillic}/u;
const GREEK_SCRIPT_RE = /\p{Script=Greek}/u;
const CYRILLIC_CONFUSABLE_CHARS = new Set(['а', 'е', 'о', 'р', 'с', 'х', 'у', 'і', 'ј', 'ѕ', 'һ', 'ԁ', 'ԝ', 'к', 'м', 'т', 'в', 'н']);
const GREEK_CONFUSABLE_CHARS = new Set(['α', 'β', 'ε', 'ζ', 'η', 'ι', 'κ', 'μ', 'ν', 'ο', 'ρ', 'σ', 'τ', 'υ', 'χ']);

/** @type {any} */
let _caddyManager = null;
function getCaddyManager() {
  if (!_caddyManager) _caddyManager = require('./caddyManager');
  return _caddyManager;
}

/**
 * Detecta ataques de homógrafos IDN (mezcla de alfabetos Latin+Cirílico/Griego,
 * caracteres invisibles/BiDi, o etiquetas totalmente confusables bajo TLDs latinos ASCII).
 * Permite IDN legítimos de un único alfabeto (p. ej. `café.ejemplo.es` o `пример.рф`).
 *
 * @param {string} rawHostname
 * @returns {{ suspicious: boolean, reason?: string }}
 */
function detectIdnHomograph(rawHostname) {
  const clean = String(rawHostname || '').trim().toLowerCase().replace(/^\*\./, '').replace(/\.+$/, '');
  if (!clean) return { suspicious: false };
  if (INVISIBLE_OR_BIDI_RE.test(clean)) {
    return { suspicious: true, reason: 'Caracteres invisibles o de control bidireccional (BiDi) no permitidos en hostname' };
  }

  // Evaluar tanto la forma cruda Unicode como la decodificada desde punycode (`xn--...`)
  const forms = [clean];
  if (typeof url.domainToUnicode === 'function') {
    const decoded = url.domainToUnicode(clean);
    if (decoded && decoded.toLowerCase() !== clean) {
      forms.push(decoded.toLowerCase());
    }
  }

  for (const form of forms) {
    if (INVISIBLE_OR_BIDI_RE.test(form)) {
      return { suspicious: true, reason: 'Punycode decodifica caracteres invisibles/BiDi' };
    }
    const labels = form.split('.').filter(Boolean);
    const tld = labels[labels.length - 1] || '';
    const isAsciiLatinTld = /^[a-z]{2,63}$/.test(tld);

    for (const label of labels) {
      const hasLatin = LATIN_SCRIPT_RE.test(label);
      const hasCyrillic = CYRILLIC_SCRIPT_RE.test(label);
      const hasGreek = GREEK_SCRIPT_RE.test(label);

      const scriptCount = Number(hasLatin) + Number(hasCyrillic) + Number(hasGreek);
      if (scriptCount > 1) {
        return {
          suspicious: true,
          reason: `Etiqueta IDN homógrafa (mezcla de alfabetos Latin/Cirílico/Griego) detectada en "${label}"`
        };
      }

      // Spoof de etiqueta completa con caracteres visualmente idénticos a Latin bajo TLD ASCII (p. ej. `аеорс.com`)
      if (isAsciiLatinTld && (hasCyrillic || hasGreek)) {
        const letters = Array.from(label).filter((ch) => /\p{L}/u.test(ch));
        const confusableSet = hasCyrillic ? CYRILLIC_CONFUSABLE_CHARS : GREEK_CONFUSABLE_CHARS;
        if (letters.length > 0 && letters.every((ch) => confusableSet.has(ch))) {
          return {
            suspicious: true,
            reason: `Etiqueta IDN homógrafa confusable con ASCII bajo TLD .${tld} detectada en "${label}"`
          };
        }
      }
    }
  }
  return { suspicious: false };
}

/**
 * Normaliza y valida un hostname (RFC 1123 + guardia anti-homógrafos IDN + Punycode
 * + sin punto final FQDN + límite de 63 chars por etiqueta + TLD no numérico + rechazo de IPv4).
 * @param {string} raw
 * @returns {string}
 */
function normalizeAndValidateHostname(raw) {
  const rawStr = String(raw || '').trim();
  if (/[\r\n\0\s]/.test(rawStr)) {
    throw new Error(`Invalid domain format (RFC 1123 required): ${raw}`);
  }
  const homograph = detectIdnHomograph(rawStr);
  if (homograph.suspicious) {
    throw new Error(`IDN homograph rejected (${homograph.reason}): ${raw}`);
  }
  let clean = rawStr.toLowerCase().replace(/\.+$/, '');
  if (clean === 'localhost') return 'localhost';
  const isWild = clean.startsWith('*.');
  const body = isWild ? clean.slice(2) : clean;
  let ascii = body;
  if (body && typeof url.domainToASCII === 'function') {
    const conv = url.domainToASCII(body);
    if (!conv && /[^\x00-\x7f]/.test(body)) {
      throw new Error(`Invalid IDN domain format: ${raw}`);
    }
    if (conv) ascii = conv.toLowerCase().replace(/\.+$/, '');
  }
  const normalized = isWild ? `*.${ascii}` : ascii;
  if (!normalized || normalized.length > 253 || IPV4_RE.test(ascii) || !DOMAIN_REGEX.test(normalized)) {
    throw new Error(`Invalid domain format (RFC 1123 required): ${raw}`);
  }
  const labels = ascii.split('.');
  if (labels.some((lbl) => !lbl || lbl.length > 63) || !VALID_TLD_RE.test(labels[labels.length - 1])) {
    throw new Error(`Invalid domain format (RFC 1123 required): ${raw}`);
  }
  return normalized;
}
const UPDATABLE_DOMAIN_FIELDS = new Set([
  'hostname',
  'projectId',
  'targetPod',
  'targetPort',
  'cloudflareProxied',
  'cloudflareZoneId',
  'cloudflareRecordId',
  'tunnelId',
  'sslStatus',
  'sslCertId',
  'sslProvider',
  'routingMode',
  'canonicalRedirect',
  'securityHeaders',
  'hstsPreload',
  'hstsMaxAge',
  'permissionsPolicy',
  'csp',
  'framePolicy',
  'customHeaders',
  'basicAuth',
  'forwardAuth',
  'cors',
  'pathRoutes',
  'pathRedirects',
  'protocol',
  'streaming',
  'flushInterval',
  'streamCloseDelayMs',
  'responseHeaderTimeoutMs',
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

/**
 * Valida y sanea `customHeaders` (compartido por `addDomain` y `updateDomain`).
 * Rechaza estrictamente inyección CRLF/NUL, cabeceras hop-by-hop y `Host`.
 *
 * @param {any} rawHeaders
 * @returns {{ response?: Record<string, string>, request?: Record<string, string> } | null}
 */
function sanitizeCustomHeaders(rawHeaders) {
  if (rawHeaders === null || rawHeaders === undefined) return null;
  if (typeof rawHeaders !== 'object' || Array.isArray(rawHeaders)) {
    throw new Error('customHeaders debe ser un objeto con secciones response y/o request');
  }
  /** @type {{ response?: Record<string, string>, request?: Record<string, string> }} */
  const cleanHeaders = {};
  for (const section of ['response', 'request']) {
    const src = rawHeaders[section];
    if (src === undefined || src === null) continue;
    if (typeof src !== 'object' || Array.isArray(src)) {
      throw new Error(`customHeaders.${section} debe ser un objeto clave-valor`);
    }
    /** @type {Record<string, string>} */
    const map = {};
    let count = 0;
    for (const [hk, hv] of Object.entries(src)) {
      if (count >= 20) break;
      const rawKey = String(hk);
      if (/[\r\n\0]/.test(rawKey)) {
        throw new Error('Inyección CRLF/NUL rechazada en nombre de cabecera HTTP');
      }
      const k = rawKey.trim();
      if (!HEADER_NAME_RE.test(k)) {
        throw new Error(`Nombre de cabecera HTTP inválido: "${k.slice(0, 40)}"`);
      }
      if (HOP_BY_HOP_HEADER_RE.test(k)) {
        throw new Error(`Cabecera hop-by-hop o reservada no permitida: "${k}"`);
      }
      const rawVal = String(hv == null ? '' : hv);
      if (/[\r\n\0]/.test(rawVal)) {
        throw new Error(`Inyección CRLF/NUL rechazada en valor de cabecera "${k}"`);
      }
      map[k] = rawVal.slice(0, 1024);
      count++;
    }
    if (Object.keys(map).length > 0) cleanHeaders[section] = map;
  }
  return (cleanHeaders.response || cleanHeaders.request) ? cleanHeaders : null;
}

/** Valida una IP o CIDR IPv4/IPv6 para la lista blanca de Caddy `client_ip`. */
function isValidCidrOrIp(entry) {
  const clean = String(entry || '').trim();
  if (!clean) return false;
  const parts = clean.split('/');
  if (parts.length > 2) return false;
  const ipKind = net.isIP(parts[0]);
  if (ipKind !== 4 && ipKind !== 6) return false;
  const isV4MappedV6 = ipKind === 6 && /^::ffff:/i.test(parts[0]);
  if (parts.length === 2) {
    if (!/^\d{1,3}$/.test(parts[1])) return false;
    const prefix = Number(parts[1]);
    const maxBits = ipKind === 4 ? 32 : 128;
    if (prefix < 0 || prefix > maxBits) return false;
    // Evita que `::ffff:x.x.x.x/24` abra la lista blanca a TODO IPv4 (Traefik/Caddy bypass)
    if (isV4MappedV6 && prefix < 96) return false;
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

const CF_IPV6_PREFIXES = [
  '2400:cb00:', '2606:4700:', '2803:f800:', '2405:b500:', '2405:8100:',
  '2a06:98c0:', '2a06:98c1:', '2a06:98c2:', '2a06:98c3:',
  '2a06:98c4:', '2a06:98c5:', '2a06:98c6:', '2a06:98c7:',
  '2c0f:f248:'
];

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
  /**
   * @param {{
   *   dataDir?: string | null,
   *   domainsFile?: string | null,
   *   seedDefaults?: boolean,
   *   sslManager?: any,
   *   cloudflareService?: any
   * }} [opts]
   */
  constructor(opts = {}) {
    this.domainsFile = opts.domainsFile
      || (opts.dataDir ? path.join(path.resolve(opts.dataDir), 'domains.json') : null)
      || (process.env.CULKIBO_DATA_DIR ? path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data', 'domains.json') : DOMAINS_FILE);
    this._seedDefaults = opts.seedDefaults !== undefined ? Boolean(opts.seedDefaults) : true;
    this._customSslManager = opts.sslManager || null;
    this._customCloudflareService = opts.cloudflareService || null;
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

  _getSsl() {
    return this._customSslManager || getSslManager();
  }

  _getCloudflare() {
    return this._customCloudflareService || getCloudflareService();
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
    const dir = path.dirname(this.domainsFile);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  loadDomains() {
    const loaded = loadJsonWithBackupSync(this.domainsFile, {
      validate: (parsed) => Array.isArray(parsed)
    });
    if (loaded.ok && Array.isArray(loaded.data)) {
      return loaded.data;
    }
    if (loaded.corrupt) {
      // Defensa anti-borrado (CapRover #2413): nunca reemplazar un domains.json corrupto por semillas de demo
      this._corruptReadOnly = true;
      console.error(`[DomainManager] ${this.domainsFile} corrupto; archivado en ${loaded.quarantinePath}. Guardado bloqueado para proteger rutas de producción.`);
      return [];
    }
    if (!this._seedDefaults) return [];
    // Default initial seed domains (solo en instalación completamente nueva sin domains.json)
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
    if (this._corruptReadOnly) return;
    this.ensureDirectory();
    this.rebuildIndex();
    atomicWriteJsonSync(this.domainsFile, this.domains, { mode: 0o600, backup: true });
  }

  /** Valida redirección canónica bidireccionalmente (evita bucles 301 www ↔ raíz y colisiones). */
  _validateCanonicalMode(hostname, mode, excludeIdx = -1) {
    const m = String(mode || 'none');
    if (!['none', 'www_to_apex', 'apex_to_www'].includes(m)) {
      throw new Error(`Modo de redirección canónica inválido: ${m}`);
    }
    const isWild = hostname.startsWith('*.');
    if (m !== 'none' && isWild) {
      throw new Error('La redirección canónica www ↔ raíz no aplica a dominios comodín (*.dominio)');
    }
    if (m === 'www_to_apex' && hostname.startsWith('www.')) {
      throw new Error('Usa "www → raíz" en el dominio raíz (sin www.), no en www.*');
    }
    if (m === 'apex_to_www' && !hostname.startsWith('www.')) {
      throw new Error('Usa "raíz → www" en el dominio www.*, no en el dominio raíz');
    }
    if (m !== 'none') {
      const companion = m === 'www_to_apex' ? `www.${hostname}` : hostname.slice(4);
      const dup = this.domains.find((d, i) => i !== excludeIdx && d.hostname === companion);
      if (dup) {
        throw new Error(`El dominio acompañante ${companion} ya está registrado por separado en Culkibo`);
      }
    }
    // También comprobar si OTRO dominio ya reclama `hostname` como acompañante canónico (evita bucles 301)
    if (!isWild) {
      const claimedBy = this.domains.find((d, i) => {
        if (i === excludeIdx || !d || d.isWildcard) return false;
        if (d.canonicalRedirect === 'www_to_apex' && `www.${d.hostname}` === hostname) return true;
        if (d.canonicalRedirect === 'apex_to_www' && d.hostname.startsWith('www.') && d.hostname.slice(4) === hostname) return true;
        return false;
      });
      if (claimedBy) {
        throw new Error(`El dominio ${hostname} ya está reservado por la redirección canónica de ${claimedBy.hostname}`);
      }
    }
    return m;
  }

  listDomains() {
    // Una sola pasada de verificación sobre el registro SSL en vez de O(D × C).
    const sslManager = this._getSsl();
    const certs = sslManager.listCertificates();
    const now = Date.now();
    return this.domains.map(d => {
      const cert = sslManager.matchCertificate(d.hostname, certs);
      return {
        ...d,
        ...(d.basicAuth ? { basicAuth: sanitizeBasicAuthForPublic(d.basicAuth) } : {}),
        projectId: d.projectId || null,
        certClaim: cert ? {
          verified: Boolean(cert.verified && cert.managedBy === 'on_disk'),
          managedBy: cert.managedBy || null,
          issuer: cert.issuer || null,
          expiresAt: cert.expiresAt || null,
          daysRemaining: cert.expiresAt
            ? Math.max(0, Math.floor((new Date(cert.expiresAt).getTime() - now) / 86400000))
            : null,
          isWildcard: Boolean(
            cert.type === 'wildcard_dns01' ||
            cert.type === 'custom_wildcard' ||
            String(cert.domain || '').startsWith('*.')
          )
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
    const sslManager = this._getSsl();
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
    const sslManager = this._getSsl();
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
   * Valida y normaliza todos los campos de política de borde (compartido entre
   * `addDomain` y `updateDomain` para impedir inyección de cabeceras, SSRF en ForwardAuth,
   * CORS inseguro `*`+credenciales, ReDoS en redirecciones o bypasses CIDR/bcrypt).
   *
   * @param {Record<string, any>} fields
   * @param {any} [prevDomain]
   * @returns {Record<string, any>}
   */
  _validateEdgeFields(fields, prevDomain = null) {
    /** @type {Record<string, any>} */
    const out = { ...fields };
    const cm = getCaddyManager();

    // framePolicy
    if (out.framePolicy !== undefined) {
      const fp = out.framePolicy ? String(out.framePolicy).toUpperCase() : null;
      if (fp && !['DENY', 'SAMEORIGIN', 'ALLOW'].includes(fp)) {
        throw new Error(`framePolicy inválido: ${fp}`);
      }
      out.framePolicy = fp;
    }

    // HSTS Preload & cabeceras de seguridad extendidas
    if (out.hstsPreload !== undefined) {
      out.hstsPreload = Boolean(out.hstsPreload);
    }
    if (out.hstsMaxAge !== undefined) {
      if (out.hstsMaxAge === null || out.hstsMaxAge === '') {
        out.hstsMaxAge = null;
      } else {
        const age = Number(out.hstsMaxAge);
        if (!Number.isFinite(age) || age < 0 || age > 63072000) {
          throw new Error('hstsMaxAge debe estar entre 0 y 63072000 segundos');
        }
        out.hstsMaxAge = Math.round(age);
      }
    }
    if (out.permissionsPolicy !== undefined) {
      if (out.permissionsPolicy === null || out.permissionsPolicy === '') {
        out.permissionsPolicy = null;
      } else {
        const pp = String(out.permissionsPolicy);
        if (/[\r\n\0]/.test(pp)) throw new Error('Inyección CRLF/NUL rechazada en permissionsPolicy');
        out.permissionsPolicy = pp.trim().slice(0, 512) || null;
      }
    }
    if (out.csp !== undefined) {
      if (out.csp === null || out.csp === '') {
        out.csp = null;
      } else {
        const c = String(out.csp);
        if (/[\r\n\0]/.test(c)) throw new Error('Inyección CRLF/NUL rechazada en csp');
        out.csp = c.trim().slice(0, 2048) || null;
      }
    }

    // customHeaders (CRLF + hop-by-hop strict)
    if (out.customHeaders !== undefined) {
      out.customHeaders = sanitizeCustomHeaders(out.customHeaders);
    }

    // Basic Auth bcrypt
    if (out.basicAuth !== undefined) {
      if (!out.basicAuth || out.basicAuth.enabled === false) {
        out.basicAuth = { enabled: false, realm: 'Acceso protegido', accounts: [] };
      } else if (typeof out.basicAuth === 'object') {
        const prevAccounts = new Map(
          ((prevDomain && prevDomain.basicAuth && prevDomain.basicAuth.accounts) || []).map((a) => [a.username, a.passwordHash])
        );
        const rawList = Array.isArray(out.basicAuth.accounts)
          ? out.basicAuth.accounts
          : (Array.isArray(out.basicAuth.users) ? out.basicAuth.users : []);
        /** @type {Array<{ username: string, passwordHash: string }>} */
        const hashedAccounts = [];
        /** @type {Set<string>} */
        const seenUsers = new Set();
        for (const item of rawList.slice(0, 20)) {
          if (!item || typeof item !== 'object') continue;
          const username = String(item.username || '').trim();
          if (!username || !/^[A-Za-z0-9._@+-]{1,64}$/.test(username)) {
            throw new Error(`Usuario de Basic Auth inválido: "${username.slice(0, 30)}"`);
          }
          if (seenUsers.has(username)) {
            throw new Error(`Usuario de Basic Auth duplicado: "${username}" (Caddy exige usuarios únicos)`);
          }
          seenUsers.add(username);
          let passwordHash = '';
          if (typeof item.password === 'string' && item.password.length > 0) {
            if (!isBcryptHash(item.password)) {
              if (item.password.includes('\0')) {
                throw new Error(`La contraseña de "${username}" contiene caracteres nulos no permitidos`);
              }
              if (Buffer.byteLength(item.password, 'utf8') > 72) {
                throw new Error(`La contraseña de "${username}" supera el límite de 72 bytes de bcrypt`);
              }
            }
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
        out.basicAuth = {
          enabled: true,
          realm: String(out.basicAuth.realm || 'Acceso protegido').replace(/[\r\n\0"]/g, '').slice(0, 80),
          accounts: hashedAccounts
        };
      }
    }

    // ForwardAuth (Authelia / Authentik / Keycloak)
    if (out.forwardAuth !== undefined) {
      if (!out.forwardAuth || out.forwardAuth.enabled === false) {
        out.forwardAuth = { enabled: false, upstream: '', uri: '/api/verify', copyHeaders: [] };
      } else if (typeof out.forwardAuth === 'object') {
        const dial = cm.sanitizeUpstreamDial(out.forwardAuth.upstream, 'forwardAuth.upstream');
        const uri = String(out.forwardAuth.uri || '/api/verify').trim();
        if (!uri.startsWith('/') || /[\s\r\n\0]/.test(uri) || uri.includes('..')) {
          throw new Error(`URI de forwardAuth inválida: ${uri.slice(0, 80)}`);
        }
        const rawCopy = Array.isArray(out.forwardAuth.copyHeaders) && out.forwardAuth.copyHeaders.length > 0
          ? out.forwardAuth.copyHeaders
          : ['Remote-User', 'Remote-Groups', 'Remote-Name', 'Remote-Email'];
        const copyHeaders = [];
        for (const h of rawCopy.slice(0, 20)) {
          const clean = String(h || '').trim();
          if (!HEADER_NAME_RE.test(clean) || HOP_BY_HOP_HEADER_RE.test(clean)) {
            throw new Error(`Cabecera copyHeaders inválida en forwardAuth: "${clean.slice(0, 40)}"`);
          }
          copyHeaders.push(clean);
        }
        out.forwardAuth = {
          enabled: true,
          upstream: dial,
          uri,
          copyHeaders: Array.from(new Set(copyHeaders)),
          dialTimeoutMs: Number.isFinite(Number(out.forwardAuth.dialTimeoutMs))
            ? Math.min(30000, Math.max(500, Math.round(Number(out.forwardAuth.dialTimeoutMs))))
            : 3000,
          responseTimeoutMs: Number.isFinite(Number(out.forwardAuth.responseTimeoutMs))
            ? Math.min(30000, Math.max(500, Math.round(Number(out.forwardAuth.responseTimeoutMs))))
            : 5000
        };
      } else {
        throw new Error('forwardAuth debe ser un objeto de configuración');
      }
    }

    // CORS
    if (out.cors !== undefined) {
      if (!out.cors || out.cors.enabled === false) {
        out.cors = { enabled: false, allowedOrigins: [] };
      } else if (typeof out.cors === 'object') {
        const rawOrigins = Array.isArray(out.cors.allowedOrigins) ? out.cors.allowedOrigins : [];
        const origins = Array.from(new Set(rawOrigins.map((o) => cm.validateCorsOrigin(o))));
        if (origins.length === 0) {
          throw new Error('Activar CORS requiere al menos un origen en allowedOrigins');
        }
        const allowCredentials = Boolean(out.cors.allowCredentials);
        if (allowCredentials && origins.includes('*')) {
          throw new Error('Política CORS insegura bloqueada: allowCredentials=true no puede combinarse con allowedOrigins=["*"]');
        }
        const allowedMethods = (Array.isArray(out.cors.allowedMethods) && out.cors.allowedMethods.length > 0
          ? out.cors.allowedMethods
          : ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
          .map((m) => String(m || '').trim().toUpperCase())
          .filter((m) => /^[A-Z]{2,16}$/.test(m));
        const allowedHeaders = (Array.isArray(out.cors.allowedHeaders) && out.cors.allowedHeaders.length > 0
          ? out.cors.allowedHeaders
          : ['Authorization', 'Content-Type', 'X-Requested-With'])
          .map((h) => String(h || '').trim())
          .filter((h) => HEADER_NAME_RE.test(h));
        const exposedHeaders = (Array.isArray(out.cors.exposedHeaders) ? out.cors.exposedHeaders : [])
          .map((h) => String(h || '').trim())
          .filter((h) => HEADER_NAME_RE.test(h));
        const maxAge = Number.isFinite(Number(out.cors.maxAge))
          ? Math.min(86400, Math.max(0, Math.round(Number(out.cors.maxAge))))
          : 3600;
        out.cors = {
          enabled: true,
          allowedOrigins: origins,
          allowedMethods,
          allowedHeaders,
          exposedHeaders,
          allowCredentials,
          maxAge
        };
      } else {
        throw new Error('cors debe ser un objeto de configuración');
      }
    }

    // Path-based routing (`pathRoutes`)
    if (out.pathRoutes !== undefined) {
      if (out.pathRoutes === null || (Array.isArray(out.pathRoutes) && out.pathRoutes.length === 0)) {
        out.pathRoutes = [];
      } else if (Array.isArray(out.pathRoutes)) {
        const cleanPaths = [];
        for (const pr of out.pathRoutes.slice(0, 32)) {
          if (!pr || typeof pr !== 'object') throw new Error('Entrada inválida en pathRoutes');
          const p = String(pr.path || '').trim();
          if (!p.startsWith('/') || p.length > 256 || /[\s\r\n\0]/.test(p) || p.includes('..')) {
            throw new Error(`Prefijo de pathRoute inválido: "${p.slice(0, 60)}"`);
          }
          if (!Array.isArray(pr.upstreams) || pr.upstreams.length === 0) {
            throw new Error(`pathRoute "${p}" necesita al menos un upstream`);
          }
          const ups = pr.upstreams.map((u) => cm.sanitizeUpstreamDial(u, `pathRoute(${p}).upstream`));
          let stripPrefix = false;
          if (typeof pr.stripPrefix === 'string' && pr.stripPrefix.trim()) {
            const sp = pr.stripPrefix.trim();
            if (!sp.startsWith('/') || /[\s\r\n\0]/.test(sp) || sp.includes('..')) {
              throw new Error(`stripPrefix inválido en pathRoute "${p}"`);
            }
            stripPrefix = sp;
          } else if (pr.stripPrefix === true) {
            stripPrefix = true;
          }
          const proto = pr.protocol ? String(pr.protocol).trim().toLowerCase() : 'http';
          if (!['http', 'grpc', 'h2c'].includes(proto)) {
            throw new Error(`Protocolo inválido en pathRoute "${p}": ${proto}`);
          }
          cleanPaths.push({
            path: p,
            upstreams: ups,
            stripPrefix,
            protocol: proto,
            ...(pr.streaming !== undefined ? { streaming: Boolean(pr.streaming) } : {}),
            ...(pr.flushInterval !== undefined && pr.flushInterval !== null ? { flushInterval: Number(pr.flushInterval) } : {})
          });
        }
        out.pathRoutes = cleanPaths;
      } else {
        throw new Error('pathRoutes debe ser un array');
      }
    }

    // Path redirects (`pathRedirects`) con validación anti-ReDoS
    if (out.pathRedirects !== undefined) {
      if (out.pathRedirects === null || (Array.isArray(out.pathRedirects) && out.pathRedirects.length === 0)) {
        out.pathRedirects = [];
      } else if (Array.isArray(out.pathRedirects)) {
        const cleanRedirs = [];
        for (const rd of out.pathRedirects.slice(0, 32)) {
          if (!rd || typeof rd !== 'object') throw new Error('Entrada inválida en pathRedirects');
          const pattern = String(rd.pattern || '').trim();
          const target = String(rd.target || '').trim();
          const isRegex = rd.isRegex !== false;
          const status = [301, 302, 307, 308].includes(Number(rd.status)) ? Number(rd.status) : 301;
          if (!pattern || !target || /[\r\n\0]/.test(target)) {
            throw new Error('Redirección de ruta inválida (pattern/target)');
          }
          if (/^(?:javascript|data|vbscript):/i.test(target) || (!target.startsWith('/') && !/^https?:\/\//i.test(target))) {
            throw new Error(`Destino de redirección inválido o bloqueado: ${target.slice(0, 60)}`);
          }
          if (isRegex) {
            const check = cm.validateSafeRedirectRegex(pattern);
            if (!check.ok) throw new Error(`Regex de redirección rechazado: ${check.error}`);
          } else if (!pattern.startsWith('/') || /[\s\r\n\0]/.test(pattern)) {
            throw new Error(`Ruta de redirección inválida: ${pattern.slice(0, 60)}`);
          }
          cleanRedirs.push({ pattern, target, status, isRegex });
        }
        out.pathRedirects = cleanRedirs;
      } else {
        throw new Error('pathRedirects debe ser un array');
      }
    }

    // Protocolo upstream (http / grpc / h2c) y tuning SSE/WS
    if (out.protocol !== undefined) {
      const proto = String(out.protocol || 'http').trim().toLowerCase();
      if (!['http', 'grpc', 'h2c'].includes(proto)) {
        throw new Error(`Protocolo de upstream inválido: ${out.protocol} (usa http, grpc o h2c)`);
      }
      out.protocol = proto;
    }
    if (out.streaming !== undefined) {
      out.streaming = Boolean(out.streaming);
    }
    if (out.flushInterval !== undefined) {
      if (out.flushInterval === null || out.flushInterval === '') {
        out.flushInterval = null;
      } else {
        const fi = Number(out.flushInterval);
        if (!Number.isFinite(fi) || fi < -1 || fi > 60000) {
          throw new Error('flushInterval debe ser -1 o un valor en ms entre 0 y 60000');
        }
        out.flushInterval = Math.round(fi);
      }
    }
    if (out.streamCloseDelayMs !== undefined) {
      if (out.streamCloseDelayMs === null || out.streamCloseDelayMs === '') {
        out.streamCloseDelayMs = null;
      } else {
        const sc = Number(out.streamCloseDelayMs);
        if (!Number.isFinite(sc) || sc < 0 || sc > 300000) {
          throw new Error('streamCloseDelayMs debe estar entre 0 y 300000 ms');
        }
        out.streamCloseDelayMs = Math.round(sc);
      }
    }
    if (out.responseHeaderTimeoutMs !== undefined) {
      if (out.responseHeaderTimeoutMs === null || out.responseHeaderTimeoutMs === '') {
        out.responseHeaderTimeoutMs = null;
      } else {
        const rt = Number(out.responseHeaderTimeoutMs);
        if (!Number.isFinite(rt) || rt < 1000 || rt > 600000) {
          throw new Error('responseHeaderTimeoutMs debe estar entre 1000 y 600000 ms');
        }
        out.responseHeaderTimeoutMs = Math.round(rt);
      }
    }

    // tunnelId (para routingMode: 'cloudflare_tunnel')
    if (out.tunnelId !== undefined) {
      if (out.tunnelId === null || out.tunnelId === '') {
        out.tunnelId = null;
      } else {
        const tid = String(out.tunnelId).trim();
        if (!/^[a-zA-Z0-9_-]{1,64}$/.test(tid)) {
          throw new Error(`tunnelId inválido: "${tid.slice(0, 40)}"`);
        }
        out.tunnelId = tid;
      }
    }

    // IP Allowlist
    if (out.ipAllowlist !== undefined) {
      if (out.ipAllowlist === null || (Array.isArray(out.ipAllowlist) && out.ipAllowlist.length === 0)) {
        out.ipAllowlist = [];
      } else if (Array.isArray(out.ipAllowlist)) {
        const cleanIps = [];
        for (const rawIp of out.ipAllowlist.slice(0, 64)) {
          const s = String(rawIp || '').trim();
          if (!s) continue;
          if (!isValidCidrOrIp(s)) {
            throw new Error(`IP o rango CIDR inválido en lista blanca: "${s.slice(0, 48)}"`);
          }
          cleanIps.push(s);
        }
        out.ipAllowlist = Array.from(new Set(cleanIps));
      } else {
        throw new Error('ipAllowlist debe ser un array de direcciones IP o rangos CIDR');
      }
    }

    // maxBodySizeMb
    if (out.maxBodySizeMb !== undefined) {
      if (out.maxBodySizeMb === null || out.maxBodySizeMb === '') {
        out.maxBodySizeMb = null;
      } else {
        const mb = Number(out.maxBodySizeMb);
        if (!Number.isFinite(mb) || mb < 1 || mb > 10240) {
          throw new Error('maxBodySizeMb debe estar entre 1 y 10240 MB');
        }
        out.maxBodySizeMb = Math.round(mb);
      }
    }

    // rateLimit
    if (out.rateLimit !== undefined) {
      if (!out.rateLimit || out.rateLimit.enabled === false) {
        out.rateLimit = { enabled: false, requests: 120, windowSeconds: 60 };
      } else if (typeof out.rateLimit === 'object') {
        out.rateLimit = {
          enabled: true,
          requests: Math.min(100000, Math.max(1, Math.round(Number(out.rateLimit.requests) || 120))),
          windowSeconds: Math.min(3600, Math.max(1, Math.round(Number(out.rateLimit.windowSeconds) || 60)))
        };
      }
    }

    return out;
  }

  /**
   * @param {{
   *   hostname: string,
   *   targetPod?: string,
   *   targetPort?: number | string,
   *   cloudflareZoneId?: string | null,
   *   cloudflareProxied?: boolean,
   *   tunnelId?: string | null,
   *   routingMode?: string,
   *   canonicalRedirect?: 'none' | 'www_to_apex' | 'apex_to_www',
   *   securityHeaders?: boolean,
   *   hstsPreload?: boolean,
   *   hstsMaxAge?: number | null,
   *   permissionsPolicy?: string | null,
   *   csp?: string | null,
   *   framePolicy?: 'DENY' | 'SAMEORIGIN' | 'ALLOW' | null,
   *   customHeaders?: { response?: Record<string, string>, request?: Record<string, string> } | null,
   *   basicAuth?: any,
   *   forwardAuth?: any,
   *   cors?: any,
   *   pathRoutes?: any[] | null,
   *   pathRedirects?: any[] | null,
   *   protocol?: string,
   *   streaming?: boolean,
   *   flushInterval?: number | null,
   *   streamCloseDelayMs?: number | null,
   *   responseHeaderTimeoutMs?: number | null,
   *   ipAllowlist?: string[] | null,
   *   maxBodySizeMb?: number | null,
   *   rateLimit?: any,
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
  async addDomain(opts) {
    const {
      hostname,
      targetPod = 'forge',
      targetPort = 3001,
      cloudflareZoneId = null,
      cloudflareProxied = true,
      routingMode = 'cloudflare_proxy',
      canonicalRedirect = 'none',
      securityHeaders = true,
      autoCreateDns = false,
      serverIp = '127.0.0.1',
      sslStatus = undefined,
      sslProvider = undefined,
      migrationSource = undefined,
      projectId = null,
      serviceId = null,
      serviceName = null
    } = opts || /** @type {any} */ ({});

    const cleanHost = normalizeAndValidateHostname(hostname);

    const isWildcard = cleanHost.startsWith('*.');
    const parsedPort = parseInt(String(targetPort), 10);
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      throw new Error(`Invalid targetPort: ${targetPort}`);
    }

    const existing = this.domains.find(d => d.hostname === cleanHost);
    if (existing) {
      throw new Error(`Domain ${cleanHost} is already configured in Culkibo`);
    }

    const safeCanonical = this._validateCanonicalMode(cleanHost, canonicalRedirect || 'none', -1);

    // Aplicar validación compartida de políticas de borde en alta (evita inyección CRLF/hop-by-hop/CORS/ForwardAuth)
    const edgeFieldKeys = [
      'framePolicy', 'hstsPreload', 'hstsMaxAge', 'permissionsPolicy', 'csp',
      'customHeaders', 'basicAuth', 'forwardAuth', 'cors', 'pathRoutes', 'pathRedirects',
      'protocol', 'streaming', 'flushInterval', 'streamCloseDelayMs', 'responseHeaderTimeoutMs',
      'ipAllowlist', 'maxBodySizeMb', 'rateLimit', 'tunnelId'
    ];
    /** @type {Record<string, any>} */
    const rawEdge = {};
    for (const k of edgeFieldKeys) {
      if (opts && opts[k] !== undefined) rawEdge[k] = opts[k];
    }
    const validatedEdge = this._validateEdgeFields(rawEdge, null);

    // Si piden autoCreateDns sin zoneId explícito, intentar resolver la zona en Cloudflare automáticamente.
    const cloudflareService = this._getCloudflare();
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
    const cert = this._getSsl().getCertificateByDomain(cleanHost);

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

    /** @type {Record<string, any>} */
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
      customHeaders: null,
      ...validatedEdge,
      migrationSource,
      ...(dnsSyncResult ? { dnsSyncResult } : {}),
      createdAt: new Date().toISOString(),
      lastCheckedAt: new Date().toISOString()
    };

    this.domains.unshift(newDomain);
    this.saveDomains();
    return newDomain.basicAuth ? { ...newDomain, basicAuth: sanitizeBasicAuthForPublic(newDomain.basicAuth) } : newDomain;
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
      const cleanHost = normalizeAndValidateHostname(safeUpdates.hostname);
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

    // Validar redirección canónica siempre que cambie canonicalRedirect O el hostname (evita bucles 301)
    if (safeUpdates.canonicalRedirect !== undefined || safeUpdates.hostname !== undefined) {
      const candidateMode = safeUpdates.canonicalRedirect !== undefined
        ? safeUpdates.canonicalRedirect
        : (this.domains[idx].canonicalRedirect || 'none');
      safeUpdates.canonicalRedirect = this._validateCanonicalMode(effectiveHostname, candidateMode, idx);
    }

    const validatedEdge = this._validateEdgeFields(safeUpdates, this.domains[idx]);
    this.domains[idx] = { ...this.domains[idx], ...validatedEdge, updatedAt: new Date().toISOString() };
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
    const cloudflareService = this._getCloudflare();
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
    const host = String(hostHeader).split(':')[0].trim().toLowerCase().replace(/\.+$/, '');

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
  const instance = Object.assign(new DomainManager(), {
    DomainManager,
    normalizeAndValidateHostname,
    detectIdnHomograph,
    sanitizeCustomHeaders,
    isValidCidrOrIp,
    isCloudflareIp
  });
  module.exports = instance;
}
