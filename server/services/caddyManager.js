const { spawn } = require('child_process');
const crypto = require('crypto');
const http = require('http');
const fs = require('fs');
const path = require('path');
const metricsCollector = require('./metricsCollector');
const { isMetadataIp } = require('./ssrfGuard');

/** @type {typeof import('https') | null} */
let _httpsMod = null;
function getHttps() {
  if (!_httpsMod) _httpsMod = require('https');
  return _httpsMod;
}

const ENV_VAR_NAME_RE = /^[A-Z_][A-Z0-9_]{0,63}$/;
const HOP_BY_HOP_HEADER_RE = /^(host|content-length|transfer-encoding|connection|keep-alive|upgrade|proxy-authenticate|proxy-authorization|te|trailer)$/i;
const HEADER_NAME_RE = /^[A-Za-z0-9-]+$/;
const METADATA_HOSTS = new Set([
  'metadata.google.internal',
  'metadata.goog',
  'metadata',
  'instance-data',
  '169.254.169.254',
  '169.254.170.2',
  '100.100.100.200',
  'fd00:ec2::254'
]);

/**
 * Esquema verificado de proveedores DNS-01 para módulos oficiales `caddy-dns/*` (2025–2026).
 * Nota crítica: `caddy-dns/hetzner/v2` usa `auth_api_token` (ruptura Cloud API fines 2025; `api_token` devuelve HTTP 400).
 * @type {Record<string, { id: string, label: string, caddyModule: string, xcaddyModule: string, primaryField: string, fields: Array<{ key: string, defaultEnv: string, required: boolean, label: string }> }>}
 */
const DNS_PROVIDERS = Object.freeze({
  cloudflare: {
    id: 'cloudflare',
    label: 'Cloudflare',
    caddyModule: 'dns.providers.cloudflare',
    xcaddyModule: 'github.com/caddy-dns/cloudflare',
    primaryField: 'api_token',
    fields: [
      { key: 'api_token', defaultEnv: 'CF_API_TOKEN', required: true, label: 'API Token (Zone:DNS:Edit)' }
    ]
  },
  hetzner: {
    id: 'hetzner',
    label: 'Hetzner Cloud DNS (v2)',
    caddyModule: 'dns.providers.hetzner',
    xcaddyModule: 'github.com/caddy-dns/hetzner/v2',
    primaryField: 'auth_api_token',
    fields: [
      { key: 'auth_api_token', defaultEnv: 'HETZNER_AUTH_API_TOKEN', required: true, label: 'Hetzner Console API Token (auth_api_token)' }
    ]
  },
  digitalocean: {
    id: 'digitalocean',
    label: 'DigitalOcean',
    caddyModule: 'dns.providers.digitalocean',
    xcaddyModule: 'github.com/caddy-dns/digitalocean',
    primaryField: 'auth_token',
    fields: [
      { key: 'auth_token', defaultEnv: 'DO_AUTH_TOKEN', required: true, label: 'Personal Access Token (auth_token)' }
    ]
  },
  route53: {
    id: 'route53',
    label: 'AWS Route 53',
    caddyModule: 'dns.providers.route53',
    xcaddyModule: 'github.com/caddy-dns/route53',
    primaryField: 'access_key_id',
    fields: [
      { key: 'access_key_id', defaultEnv: 'AWS_ACCESS_KEY_ID', required: true, label: 'AWS Access Key ID' },
      { key: 'secret_access_key', defaultEnv: 'AWS_SECRET_ACCESS_KEY', required: true, label: 'AWS Secret Access Key' },
      { key: 'region', defaultEnv: 'AWS_REGION', required: false, label: 'AWS Region (opcional)' },
      { key: 'session_token', defaultEnv: 'AWS_SESSION_TOKEN', required: false, label: 'AWS Session Token (opcional)' }
    ]
  },
  porkbun: {
    id: 'porkbun',
    label: 'Porkbun',
    caddyModule: 'dns.providers.porkbun',
    xcaddyModule: 'github.com/caddy-dns/porkbun',
    primaryField: 'api_key',
    fields: [
      { key: 'api_key', defaultEnv: 'PORKBUN_API_KEY', required: true, label: 'Porkbun API Key' },
      { key: 'api_secret_key', defaultEnv: 'PORKBUN_API_SECRET_KEY', required: true, label: 'Porkbun Secret API Key' }
    ]
  },
  bunny: {
    id: 'bunny',
    label: 'Bunny.net',
    caddyModule: 'dns.providers.bunny',
    xcaddyModule: 'github.com/caddy-dns/bunny',
    primaryField: 'access_key',
    fields: [
      { key: 'access_key', defaultEnv: 'BUNNY_ACCESS_KEY', required: true, label: 'Bunny Access Key' }
    ]
  },
  duckdns: {
    id: 'duckdns',
    label: 'DuckDNS',
    caddyModule: 'dns.providers.duckdns',
    xcaddyModule: 'github.com/caddy-dns/duckdns',
    primaryField: 'api_token',
    fields: [
      { key: 'api_token', defaultEnv: 'DUCKDNS_API_TOKEN', required: true, label: 'DuckDNS API Token' }
    ]
  }
});

/** Lista el esquema de proveedores DNS-01 soportados para la UI y la API. */
function listDnsProviders() {
  return Object.values(DNS_PROVIDERS).map((p) => ({
    id: p.id,
    label: p.label,
    caddyModule: p.caddyModule,
    xcaddyModule: p.xcaddyModule,
    fields: p.fields.map((f) => ({ ...f }))
  }));
}

/**
 * Construye y valida el objeto JSON `provider` exacto para Caddy ACME DNS-01.
 * Soporta tanto el atajo `tokenEnv`/`apiToken` (1 campo) como mapas `credentialsEnv`/`credentials` (multicampo).
 *
 * @param {string} [providerName]
 * @param {{
 *   tokenEnv?: string | null,
 *   apiToken?: string | null,
 *   credentialsEnv?: Record<string, string> | null,
 *   credentials?: Record<string, string> | null
 * }} [opts]
 * @returns {{ providerConfig: Record<string, string>, schema: any, resolvedEnvMap: Record<string, string> }}
 */
function buildDnsProviderConfig(providerName = 'cloudflare', opts = {}) {
  const cleanName = String(providerName || 'cloudflare').trim().toLowerCase();
  const schema = DNS_PROVIDERS[cleanName];
  if (!schema) {
    throw new Error(`Proveedor DNS-01 no soportado: "${cleanName}". Soportados: ${Object.keys(DNS_PROVIDERS).join(', ')}`);
  }

  const credsEnv = (opts && opts.credentialsEnv && typeof opts.credentialsEnv === 'object') ? opts.credentialsEnv : {};
  const inlineCreds = (opts && opts.credentials && typeof opts.credentials === 'object') ? opts.credentials : {};

  // Validar que no haya claves desconocidas en credentialsEnv/credentials
  const allowedKeys = new Set(schema.fields.map((f) => f.key));
  for (const k of [...Object.keys(credsEnv), ...Object.keys(inlineCreds)]) {
    if (!allowedKeys.has(k)) {
      throw new Error(`Campo de credencial "${k}" inválido para el proveedor DNS-01 "${cleanName}"`);
    }
  }

  /** @type {Record<string, string>} */
  const providerConfig = { name: cleanName };
  /** @type {Record<string, string>} */
  const resolvedEnvMap = {};

  for (const field of schema.fields) {
    const isPrimary = field.key === schema.primaryField;
    const rawInline = inlineCreds[field.key] !== undefined
      ? inlineCreds[field.key]
      : (isPrimary && opts && opts.apiToken ? opts.apiToken : null);

    if (rawInline !== null && rawInline !== undefined && String(rawInline).trim() !== '') {
      const val = String(rawInline).trim();
      if (/[\r\n\0]/.test(val)) {
        throw new Error(`Valor de credencial inválido para ${cleanName}.${field.key}`);
      }
      providerConfig[field.key] = val;
      continue;
    }

    const explicitEnv = credsEnv[field.key] !== undefined
      ? credsEnv[field.key]
      : (isPrimary && opts && opts.tokenEnv ? opts.tokenEnv : null);

    if (explicitEnv !== null && explicitEnv !== undefined && String(explicitEnv).trim() !== '') {
      const cleanEnv = String(explicitEnv).trim();
      if (!ENV_VAR_NAME_RE.test(cleanEnv)) {
        throw new Error(`Nombre de variable de entorno inválido para ${cleanName}.${field.key}: ${explicitEnv}`);
      }
      providerConfig[field.key] = `{env.${cleanEnv}}`;
      resolvedEnvMap[field.key] = cleanEnv;
    } else if (field.required) {
      providerConfig[field.key] = `{env.${field.defaultEnv}}`;
      resolvedEnvMap[field.key] = field.defaultEnv;
    }
  }

  return { providerConfig, schema, resolvedEnvMap };
}

/**
 * Guardia anti-ReDoS para expresiones regulares de redirección de rutas (`path_regexp`).
 * Rechaza cuantificadores anidados, retroreferencias, longitud excesiva o patrones inválidos.
 * @param {string} pattern
 * @returns {{ ok: boolean, error?: string }}
 */
function validateSafeRedirectRegex(pattern) {
  const s = String(pattern || '');
  if (!s || s.length > 200) {
    return { ok: false, error: 'El patrón regex debe tener entre 1 y 200 caracteres' };
  }
  if (/[\r\n\0]/.test(s)) {
    return { ok: false, error: 'El patrón regex no puede contener saltos de línea ni NUL' };
  }
  // Retroreferencias (\1..\9) no soportadas de forma segura/lineal en RE2/Go ni JS
  if (/\\[1-9]/.test(s)) {
    return { ok: false, error: 'Retroreferencias (\\1..\\9) no permitidas en regex de redirección' };
  }
  // Cuantificadores duplicados o anidados: (a+)+, (a*)+, (a|b+)*, a**, a++
  if (/([+*?]{2,})/.test(s.replace(/\\[+*?]/g, ''))) {
    return { ok: false, error: 'Cuantificadores consecutivos detectados (posible ReDoS)' };
  }
  if (/\([^)]*[+*][^)]*\)\s*[+*?{]/.test(s)) {
    return { ok: false, error: 'Cuantificador anidado detectado (posible ReDoS)' };
  }
  const groupCount = (s.match(/(?<!\\)\(/g) || []).length;
  if (groupCount > 8) {
    return { ok: false, error: 'Demasiados grupos de captura en regex (máximo 8)' };
  }
  const altCount = (s.match(/(?<!\\)\|/g) || []).length;
  if (altCount > 12) {
    return { ok: false, error: 'Demasiadas alternancias en regex (máximo 12)' };
  }
  try {
    // eslint-disable-next-line no-new
    new RegExp(s);
  } catch (err) {
    return { ok: false, error: `Patrón regex inválido: ${err.message}` };
  }
  return { ok: true };
}

/** @param {string} str */
function escapeRegexLiteral(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Valida y normaliza una dirección upstream (`host:port` o `http(s)://host:port`)
 * bloqueando inyecciones y direcciones de metadatos cloud (SSRF).
 * @param {string} raw
 * @param {string} [label]
 * @returns {string}
 */
function sanitizeUpstreamDial(raw, label = 'upstream') {
  const s = String(raw || '').trim();
  if (!s || /[\s\r\n\0]/.test(s)) {
    throw new Error(`${label} inválido: contiene espacios o caracteres de control`);
  }
  let dial = s;
  let hostname = '';
  if (/^https?:\/\//i.test(s)) {
    let parsed;
    try {
      parsed = new URL(s);
    } catch (err) {
      throw new Error(`${label} con URL inválida: ${s.slice(0, 80)}`);
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error(`Protocolo no permitido en ${label}: ${parsed.protocol}`);
    }
    const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
    hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    dial = parsed.hostname.includes(':') && !parsed.hostname.startsWith('[')
      ? `[${parsed.hostname}]:${port}`
      : `${parsed.hostname}:${port}`;
  } else {
    dial = s.replace(/\/+$/, '');
    if (!/^[a-zA-Z0-9._\[\]:-]+$/.test(dial) || !dial.includes(':')) {
      throw new Error(`Dirección ${label} inválida (esperado host:puerto): ${dial.slice(0, 80)}`);
    }
    const lastColon = dial.lastIndexOf(':');
    const portNum = Number(dial.slice(lastColon + 1));
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      throw new Error(`Puerto inválido en ${label}: ${dial.slice(0, 80)}`);
    }
    hostname = dial.slice(0, lastColon).toLowerCase().replace(/^\[|\]$/g, '');
  }
  if (!hostname || METADATA_HOSTS.has(hostname) || isMetadataIp(hostname)) {
    throw new Error(`${label} bloqueado por protección SSRF (metadatos cloud): ${hostname}`);
  }
  return dial;
}

/**
 * Sanitiza y valida un origen CORS (`*` o `https?://host[:port]`).
 * @param {string} raw
 * @returns {string}
 */
function validateCorsOrigin(raw) {
  const s = String(raw || '').trim();
  if (s === '*') return '*';
  if (!s || /[\s\r\n\0]/.test(s)) {
    throw new Error(`Origen CORS inválido: "${s.slice(0, 60)}"`);
  }
  let parsed;
  try {
    parsed = new URL(s);
  } catch (err) {
    throw new Error(`Origen CORS mal formado: "${s.slice(0, 60)}"`);
  }
  if ((parsed.protocol !== 'http:' && parsed.protocol !== 'https:') || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new Error(`El origen CORS debe ser esquema://host[:puerto] sin ruta ni query: "${s.slice(0, 60)}"`);
  }
  return parsed.origin;
}

const EARLY_HINTS_REL_ALLOWLIST = new Set(['preload', 'preconnect', 'dns-prefetch', 'modulepreload']);
const EARLY_HINTS_AS_ALLOWLIST = new Set(['style', 'script', 'font', 'image', 'fetch', 'document']);
const DOMAIN_HOSTNAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

/**
 * Valida y formatea cabeceras RFC 8297 `Link` para `103 Early Hints` en Caddy HTTP/2 y HTTP/3.
 * Rechaza esquemas peligrosos (`javascript:`, `data:`), saltos de línea e inyección de atributos.
 *
 * @param {any} earlyHints
 * @returns {string[]}
 */
function formatEarlyHintsLinks(earlyHints) {
  if (!earlyHints) return [];
  if (typeof earlyHints === 'object' && !Array.isArray(earlyHints) && earlyHints.enabled === false) {
    return [];
  }
  const rawList = Array.isArray(earlyHints)
    ? earlyHints
    : (Array.isArray(earlyHints.links) ? earlyHints.links : []);
  if (rawList.length === 0) return [];

  /** @type {string[]} */
  const out = [];
  for (const item of rawList.slice(0, 10)) {
    if (typeof item === 'string') {
      const clean = item.trim();
      if (!clean || /[\r\n\0]/.test(clean) || clean.length > 512) {
        throw new Error(`Cabecera Link de earlyHints inválida: "${clean.slice(0, 60)}"`);
      }
      const m = clean.match(/^<([^<>\s"']+)>(.*)$/);
      if (!m) {
        throw new Error(`Formato RFC 8297 inválido en earlyHints Link: "${clean.slice(0, 60)}"`);
      }
      const href = m[1];
      if (/^(?:javascript|data|vbscript):/i.test(href) || (!href.startsWith('/') && !href.startsWith('https://'))) {
        throw new Error(`Href bloqueado en earlyHints: "${href.slice(0, 60)}"`);
      }
      if (!/;\s*rel\s*=\s*(?:"?(?:preload|preconnect|dns-prefetch|modulepreload)"?)/i.test(m[2])) {
        throw new Error(`Atributo rel inválido o ausente en earlyHints Link: "${clean.slice(0, 60)}"`);
      }
      out.push(clean);
      continue;
    }

    if (!item || typeof item !== 'object') {
      throw new Error('Entrada de earlyHints inválida');
    }
    const href = String(item.href || '').trim();
    if (!href || href.length > 384 || /[\s\r\n\0<>"']/.test(href) || /^(?:javascript|data|vbscript):/i.test(href)) {
      throw new Error(`Href inválido en earlyHints: "${href.slice(0, 60)}"`);
    }
    if (!href.startsWith('/') && !href.startsWith('https://')) {
      throw new Error(`earlyHints href debe iniciar con "/" o "https://": "${href.slice(0, 60)}"`);
    }
    const rel = String(item.rel || 'preload').trim().toLowerCase();
    if (!EARLY_HINTS_REL_ALLOWLIST.has(rel)) {
      throw new Error(`rel de earlyHints no permitido: "${rel}"`);
    }
    const parts = [`<${href}>`, `rel=${rel}`];
    if (item.as !== undefined && item.as !== null && String(item.as).trim()) {
      const asVal = String(item.as).trim().toLowerCase();
      if (!EARLY_HINTS_AS_ALLOWLIST.has(asVal)) {
        throw new Error(`Atributo "as" de earlyHints no permitido: "${asVal}"`);
      }
      parts.push(`as=${asVal}`);
    }
    if (item.crossorigin === true) {
      parts.push('crossorigin');
    } else if (typeof item.crossorigin === 'string' && /^(?:anonymous|use-credentials)$/i.test(item.crossorigin.trim())) {
      parts.push(`crossorigin=${item.crossorigin.trim().toLowerCase()}`);
    }
    if (item.nopush === true) {
      parts.push('nopush');
    }
    out.push(parts.join('; '));
  }
  return out;
}

/** Rangos CIDR oficiales de Cloudflare para restaurar la IP real del visitante en `trusted_proxies`. */
const CLOUDFLARE_CIDRS = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
  '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
  '127.0.0.1/32', '::1/128'
];

/** Resuelve rangos de proxy de confianza sin confiar en RFC1918/ULA por defecto (evita bypass de IP Allowlist por contenedores vecinos). */
function resolveTrustedProxyCidrs() {
  const extra = String(process.env.CULKIBO_TRUSTED_PROXIES || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return extra.length > 0 ? Array.from(new Set([...CLOUDFLARE_CIDRS, ...extra])) : CLOUDFLARE_CIDRS;
}

const MAINTENANCE_HTML = [
  '<!doctype html><html lang="es"><head><meta charset="utf-8">',
  '<meta name="viewport" content="width=device-width,initial-scale=1">',
  '<title>Mantenimiento programado</title>',
  '<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#fafafa;color:#18181b;font-family:system-ui,-apple-system,sans-serif;padding:24px}',
  'main{max-width:440px;background:#fff;border:1px solid #e4e4e7;border-radius:12px;padding:28px 32px}',
  'h1{margin:0 0 8px;font-size:18px;font-weight:600}p{margin:0;color:#52525b;font-size:14px;line-height:1.6}</style>',
  '</head><body><main><h1>Estamos actualizando este servicio</h1>',
  '<p>Volveremos a estar disponibles en unos instantes. Gracias por tu paciencia.</p></main></body></html>'
].join('');

/**
 * Cliente del plano de datos: Caddy.
 *
 * Por qué Caddy y no un proxy escrito en Node: no existe ningún proxy inverso
 * de Node creíble a escala de ingress, `node:quic` sigue siendo experimental y
 * undici no habla HTTP/3. Delegar el plano de datos en un binario compilado y
 * quedarnos con el plano de control es la división correcta.
 *
 * Y por qué Caddy y no Traefik: no es el rendimiento —los cuatro proxies
 * grandes miden ~0,4 ms de latencia media— sino **cómo se actualiza la
 * configuración**. La admin API de Caddy es síncrona, sin downtime y con
 * rollback automático si la configuración nueva es inválida. El proveedor de
 * fichero de Traefik tiene un throttle de 2 s y el HTTP hace poll cada 5 s: para
 * "promociono y el cambio es atómico", cinco segundos son inaceptables.
 *
 * Referencias verificadas el 2026-09-15 (ver la especificación en
 * docs/superpowers/specs/):
 *   - caddyserver.com/docs/api — endpoints, @id, ETag/If-Match, rollback
 *   - modules/caddytls/ondemand.go — contrato del permiso HTTP
 *   - caddytest/integration/reverseproxy_test.go — JSON real de upstreams
 */

const DEFAULT_ADMIN = process.env.CULKIBO_CADDY_ADMIN || 'http://localhost:2019';

/** Prefijo de los @id que gestionamos, para no tocar rutas ajenas. */
const ID_PREFIX = 'culkibo_';

class CaddyManager {
  constructor() {
    this.adminUrl = DEFAULT_ADMIN;
    this.lastDetection = null;
    this.detectionAt = 0;
    this.detectionTtlMs = 15000;
    this.lastKnownRouteCount = null;
    this.isContainerized = process.env.CULKIBO_CADDY_CONTAINERIZED === '1';
    this.containerName = process.env.CULKIBO_CADDY_CONTAINER || 'culkibo-caddy';
    /** @type {{ checkedAt: number, data: any } | null} */
    this._capabilitiesCache = null;
    /** @type {Map<string, string>} */
    this._appliedRouteJson = new Map();
    /** @type {{ url: string, dialHost: string, originHeader: string, hostHeader: string, port: number, isHttps: boolean } | null} */
    this._parsedAdmin = null;
    this.httpAgent = new http.Agent(/** @type {any} */ ({ keepAlive: true, noDelay: true, maxSockets: 8, keepAliveMsecs: 60000 }));
    /** @type {any} */
    this._httpsAgent = null;
  }

  getHttpsAgent() {
    if (!this._httpsAgent) {
      const https = getHttps();
      this._httpsAgent = new https.Agent(/** @type {any} */ ({ keepAlive: true, noDelay: true, maxSockets: 8, keepAliveMsecs: 60000 }));
    }
    return this._httpsAgent;
  }

  /**
   * Resuelve el destino de la Admin API.
   * Cuando `overrideAdminUrl` apunta a un túnel SSH efímero en loopback (`127.0.0.1:<puertoEfímero>`),
   * sobreescribe las cabeceras `Host` y `Origin` a `127.0.0.1:<caddyAdminPort>` (2019 por defecto)
   * para superar la protección DNS-rebinding del Caddy remoto (evita HTTP 403 en nodos de flota).
   *
   * @param {string | null} [overrideAdminUrl]
   * @param {{ caddyAdminPort?: number | null, remoteAdminPort?: number | null, adminHost?: string | null }} [opts]
   * @returns {{ url: string, dialHost: string, originHeader: string, hostHeader: string, port: number, isHttps: boolean, isOverride: boolean }}
   */
  _getAdminTarget(overrideAdminUrl = null, { caddyAdminPort = null, remoteAdminPort = null, adminHost = null } = {}) {
    const targetUrl = overrideAdminUrl ? String(overrideAdminUrl).trim() : this.adminUrl;
    const isOverride = Boolean(overrideAdminUrl && targetUrl !== this.adminUrl);
    if (!isOverride && !caddyAdminPort && !remoteAdminPort && !adminHost && this._parsedAdmin && this._parsedAdmin.url === this.adminUrl) {
      return { ...this._parsedAdmin, isOverride: false };
    }
    const parsed = new URL(targetUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error(`Protocolo de Caddy adminUrl no permitido: ${parsed.protocol}`);
    }
    const isHttps = parsed.protocol === 'https:';
    const port = parsed.port ? Number(parsed.port) : (isHttps ? 443 : 80);
    // Evita DNS/Happy-Eyeballs ::1 vs 127.0.0.1 en Windows cuando adminUrl usa localhost
    const dialHost = parsed.hostname === 'localhost' ? '127.0.0.1' : parsed.hostname;
    const isLoopback = parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost' || parsed.hostname === '::1' || parsed.hostname === '[::1]';

    let hostHeader = parsed.host;
    let originHeader = `${parsed.protocol}//${parsed.host}`;

    if (isOverride) {
      const explicitHost = adminHost ? String(adminHost).trim() : '';
      const queryPortRaw = parsed.searchParams.get('caddyAdminPort') || parsed.searchParams.get('remoteAdminPort');
      const requestedRemotePort = caddyAdminPort ?? remoteAdminPort ?? (queryPortRaw ? Number(queryPortRaw) : null);
      if (explicitHost && /^[a-zA-Z0-9._\[\]:-]+$/.test(explicitHost)) {
        hostHeader = explicitHost;
        originHeader = `${parsed.protocol}//${explicitHost}`;
      } else if (requestedRemotePort !== null && Number.isInteger(Number(requestedRemotePort)) && Number(requestedRemotePort) >= 1 && Number(requestedRemotePort) <= 65535) {
        hostHeader = `127.0.0.1:${Number(requestedRemotePort)}`;
        originHeader = `${parsed.protocol}//${hostHeader}`;
      } else if (isLoopback) {
        // Túnel SSH efímero hacia el Caddy Admin remoto (escuchando en 127.0.0.1:2019 en el nodo destino)
        const defaultRemotePort = 2019;
        hostHeader = `127.0.0.1:${defaultRemotePort}`;
        originHeader = `${parsed.protocol}//${hostHeader}`;
      }
    }

    const built = {
      url: targetUrl,
      dialHost,
      originHeader,
      hostHeader,
      port,
      isHttps,
      isOverride
    };
    if (!isOverride && !caddyAdminPort && !remoteAdminPort && !adminHost) {
      this._parsedAdmin = {
        url: built.url,
        dialHost: built.dialHost,
        originHeader: built.originHeader,
        hostHeader: built.hostHeader,
        port: built.port,
        isHttps: built.isHttps
      };
    }
    return built;
  }

  /**
   * Petición HTTP persistente contra la Admin API de Caddy con keep-alive real,
   * `TCP_NODELAY` a nivel de agente y drenaje garantizado del cuerpo.
   * Acepta `adminUrl` y `caddyAdminPort` opcionales para túneles SSH de flota sin mutar el singleton.
   *
   * @param {string} method
   * @param {string} reqPath
   * @param {{ headers?: Record<string, string>, body?: string | null, timeoutMs?: number, readBody?: boolean, adminUrl?: string | null, caddyAdminPort?: number | null, adminHost?: string | null }} [opts]
   * @returns {Promise<{ status: number, ok: boolean, headers: Record<string, any>, text: string }>}
   */
  adminRequest(method, reqPath, { headers = {}, body = null, timeoutMs = 10000, readBody = true, adminUrl = null, caddyAdminPort = null, adminHost = null } = {}) {
    return new Promise((resolve, reject) => {
      let admin;
      try {
        admin = this._getAdminTarget(adminUrl, { caddyAdminPort, adminHost });
      } catch (err) {
        return reject(err);
      }
      const payloadBuf = body != null ? Buffer.from(body, 'utf8') : null;
      /** @type {Record<string, string>} */
      const reqHeaders = {
        Host: admin.hostHeader,
        Origin: admin.originHeader,
        ...headers
      };
      if (payloadBuf) reqHeaders['Content-Length'] = String(payloadBuf.length);

      const req = (admin.isHttps ? getHttps() : http).request(
        {
          hostname: admin.dialHost,
          port: admin.port,
          path: reqPath.startsWith('/') ? reqPath : `/${reqPath}`,
          method,
          headers: reqHeaders,
          // Para túneles remotos efímeros (adminUrl override), cerrar el socket al terminar evita retener el puerto del túnel SSH.
          agent: admin.isOverride ? false : (admin.isHttps ? this.getHttpsAgent() : this.httpAgent)
        },
        (res) => {
          const status = res.statusCode || 0;
          const ok = status >= 200 && status < 300;
          res.once('error', (err) => {
            clearTimeout(timer);
            reject(err);
          });
          if (!readBody && ok) {
            res.resume();
            res.once('end', () => {
              clearTimeout(timer);
              resolve({ status, ok, headers: res.headers, text: '' });
            });
            return;
          }
          /** @type {Buffer[]} */
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.once('end', () => {
            clearTimeout(timer);
            const text = chunks.length === 0 ? '' : (chunks.length === 1 ? chunks[0].toString('utf8') : Buffer.concat(chunks).toString('utf8'));
            resolve({ status, ok, headers: res.headers, text });
          });
        }
      );

      const timer = setTimeout(() => {
        req.destroy(new Error(`Timeout (${timeoutMs} ms) en ${method} ${reqPath}`));
      }, timeoutMs);
      if (timer.unref) timer.unref();

      req.once('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });

      if (payloadBuf) req.end(payloadBuf);
      else req.end();
    });
  }

  /**
   * Cabeceras para hablar con la API de administración.
   */
  adminHeaders(extra = {}) {
    return { Origin: this.adminUrl, ...extra };
  }

  // ---------------------------------------------------------------------
  // Detección
  // ---------------------------------------------------------------------

  /**
   * ¿Hay un Caddy con el que hablar? 1 sola petición ligera keep-alive.
   * Si se pasa `adminUrl`, consulta ese destino remoto sin mutar el estado local del singleton.
   * @param {{ force?: boolean, adminUrl?: string | null, caddyAdminPort?: number | null }} [opts]
   */
  async detect({ force = false, adminUrl = null, caddyAdminPort = null } = {}) {
    const effectiveAdminUrl = adminUrl ? String(adminUrl).trim() : this.adminUrl;
    const isOverride = Boolean(adminUrl && effectiveAdminUrl !== this.adminUrl);
    const now = Date.now();
    if (!isOverride && !force && this.lastDetection && (now - this.detectionAt) < this.detectionTtlMs) {
      return this.lastDetection;
    }

    /** @type {{ available: boolean, adminUrl: string, version: string | null, reason: string | null }} */
    let result = { available: false, adminUrl: effectiveAdminUrl, version: null, reason: null };
    try {
      const res = await this.adminRequest('GET', '/reverse_proxy/upstreams', {
        timeoutMs: 2000,
        readBody: false,
        adminUrl: isOverride ? effectiveAdminUrl : null,
        caddyAdminPort
      });
      if (res.ok) {
        result = { available: true, adminUrl: effectiveAdminUrl, version: 'activo', reason: null };
      } else {
        // Algunos Caddy recién arrancados sin server http responden 404 a /reverse_proxy/upstreams pero 200 a /config/
        const cfgRes = await this.adminRequest('GET', '/config/', {
          timeoutMs: 2000,
          readBody: false,
          adminUrl: isOverride ? effectiveAdminUrl : null,
          caddyAdminPort
        });
        if (cfgRes.ok) {
          result = { available: true, adminUrl: effectiveAdminUrl, version: 'activo', reason: null };
        } else {
          result.reason = `La API de administración respondió ${cfgRes.status}`;
        }
      }
    } catch (err) {
      result.reason = `No hay ninguna API de administración de Caddy en ${effectiveAdminUrl}`;
    }

    if (!isOverride) {
      const wasAvailable = Boolean(this.lastDetection && this.lastDetection.available);
      this.lastDetection = result;
      this.detectionAt = now;
      // P0-4: si Caddy se cayó y volvió a arrancar, invalidar caché local de rutas aplicadas
      if (!wasAvailable && result.available) {
        this._appliedRouteJson.clear();
      }
    }
    return result;
  }

  /**
   * Estado en vivo de los upstreams HTTP (`GET /reverse_proxy/upstreams`):
   * devuelve dirección, número de peticiones activas y contador de fallos pasivos.
   * @param {{ adminUrl?: string | null, caddyAdminPort?: number | null, timeoutMs?: number }} [opts]
   * @returns {Promise<Array<{ address: string, numRequests: number, fails: number }>>}
   */
  async getUpstreamsStatus({ adminUrl = null, caddyAdminPort = null, timeoutMs = 3000 } = {}) {
    try {
      const res = await this.adminRequest('GET', '/reverse_proxy/upstreams', {
        timeoutMs,
        readBody: true,
        adminUrl,
        caddyAdminPort
      });
      if (!res.ok || !res.text) return [];
      const parsed = JSON.parse(res.text);
      if (!Array.isArray(parsed)) return [];
      return parsed
        .filter((u) => u && typeof u.address === 'string')
        .map((u) => ({
          address: String(u.address),
          numRequests: Number(u.num_requests) || 0,
          fails: Number(u.fails) || 0
        }));
    } catch (e) {
      return [];
    }
  }

  async readVersion() {
    try {
      const res = await this.adminRequest('GET', '/reverse_proxy/upstreams', { timeoutMs: 1500, readBody: false });
      return res.ok ? 'activo' : null;
    } catch (e) {
      return null;
    }
  }

  /**
   * @param {{ adminUrl?: string | null, caddyAdminPort?: number | null }} [opts]
   */
  async requireAvailable({ adminUrl = null, caddyAdminPort = null } = {}) {
    const detection = await this.detect({ adminUrl, caddyAdminPort });
    if (!detection.available) {
      const err = new Error(`Caddy no está disponible: ${detection.reason}`);
      /** @type {any} */ (err).code = 'CADDY_UNAVAILABLE';
      throw err;
    }
    return detection;
  }

  // ---------------------------------------------------------------------
  // Admin API
  // ---------------------------------------------------------------------

  /**
   * @param {string} reqPath
   * @param {{ adminUrl?: string | null, caddyAdminPort?: number | null }} [opts]
   */
  async getWithEtag(reqPath, { adminUrl = null, caddyAdminPort = null } = {}) {
    const res = await this.adminRequest('GET', reqPath, { timeoutMs: 5000, readBody: true, adminUrl, caddyAdminPort });
    if (res.status === 404 || (res.status === 400 && /invalid traversal path/i.test(res.text || ''))) {
      return { found: false, value: null, etag: null };
    }
    if (!res.ok) throw new Error(`GET ${reqPath} devolvió ${res.status}: ${res.text}`);
    const etag = res.headers.etag || null;
    return { found: true, value: res.text ? JSON.parse(res.text) : null, etag };
  }

  /**
   * @param {string} reqPath
   * @param {{ adminUrl?: string | null, caddyAdminPort?: number | null }} [opts]
   */
  async get(reqPath, opts = {}) {
    return (await this.getWithEtag(reqPath, opts)).value;
  }

  /**
   * @param {string} method
   * @param {string} reqPath
   * @param {any} body
   * @param {{ etag?: string | null, retries?: number, adminUrl?: string | null, caddyAdminPort?: number | null }} [opts]
   */
  async write(method, reqPath, body, { etag = null, retries = 3, adminUrl = null, caddyAdminPort = null } = {}) {
    for (let attempt = 0; attempt <= retries; attempt++) {
      /** @type {Record<string, string>} */
      const headers = { 'Content-Type': 'application/json' };
      if (etag) headers['If-Match'] = etag;

      const res = await this.adminRequest(method, reqPath, {
        headers,
        body: body === undefined ? null : JSON.stringify(body),
        timeoutMs: 10000,
        readBody: false,
        adminUrl,
        caddyAdminPort
      });

      if (res.ok) return true;

      if (res.status === 412 && attempt < retries) {
        const conflict = new Error('PRECONDITION_FAILED');
        /** @type {any} */ (conflict).code = 'ETAG_CONFLICT';
        throw conflict;
      }

      throw new Error(`${method} ${reqPath} devolvió ${res.status}: ${res.text}`);
    }
    return false;
  }

  /**
   * Ejecuta una modificación leer-modificar-escribir reintentando ante
   * conflicto de ETag.
   */
  async mutate(fn, { retries = 4 } = {}) {
    let lastErr = null;
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        return await fn();
      } catch (err) {
        lastErr = err;
        if (err.code !== 'ETAG_CONFLICT') throw err;
        // Espera creciente y corta antes de releer.
        await new Promise(r => setTimeout(r, 20 * (attempt + 1)));
      }
    }
    throw lastErr;
  }

  // ---------------------------------------------------------------------
  // Configuración base
  // ---------------------------------------------------------------------

  /**
   * Configuración mínima con la que Culkibo puede empezar a añadir rutas.
   *
   * El detalle importante es la política de TLS bajo demanda: en vez de
   * pre-aprovisionar certificados, Caddy pregunta a nuestro endpoint si debe
   * emitir uno para el dominio que acaba de llegar. Contrato verificado en el
   * código de Caddy: hace **GET**, con el parámetro **`domain`**; **2xx
   * autoriza** y cualquier otra cosa deniega; **no sigue redirecciones**; y el
   * timeout es de **10 segundos**.
   *
   * Consecuencia de diseño: el certificado deja de ser un campo en nuestro
   * JSON. Eso es lo que hace imposible volver a falsearlo.
   */
  /**
   * Construye el bloque `apps.tls` con soporte para múltiples políticas Wildcard
   * independientes (`*.a.com`, `*.b.com`, etc.), certificados personalizados en
   * disco (p. ej. Cloudflare Origin CA) y TLS bajo demanda con respaldo ZeroSSL.
   *
   * @param {{
   *   askEndpoint?: string,
   *   wildcardDomains?: string[],
   *   wildcardPolicies?: any[],
   *   cloudflareDnsTokenEnv?: string,
   *   acmeEmail?: string | null,
   *   customCertFiles?: Array<{ certificate: string, key: string, tags?: string[] }>,
   *   isolateInvalid?: boolean,
   *   isolatedErrors?: Array<{ scope: string, subject: string, provider?: string | null, error: string }> | null
   * }} [opts]
   */
  buildTlsApp({
    askEndpoint = '',
    wildcardDomains = [],
    wildcardPolicies = [],
    cloudflareDnsTokenEnv = 'CF_API_TOKEN',
    acmeEmail = null,
    customCertFiles = [],
    isolateInvalid = false,
    isolatedErrors = null
  } = {}) {
    /** @type {any[]} */
    const policies = [];
    /** @type {Set<string>} */
    const seenRoots = new Set();

    /**
     * @param {{
     *   rootDomain: string,
     *   provider?: string,
     *   tokenEnv?: string,
     *   apiToken?: string | null,
     *   credentialsEnv?: Record<string, string> | null,
     *   credentials?: Record<string, string> | null,
     *   includeApex?: boolean
     * }} pol
     */
    const pushWildcardPolicy = (pol) => {
      const cleanRoot = String(pol.rootDomain || '').trim().toLowerCase().replace(/^\*\./, '');
      if (!cleanRoot || seenRoots.has(cleanRoot)) return;
      if (isolateInvalid && (!DOMAIN_HOSTNAME_RE.test(cleanRoot) || /[\s\r\n\0]/.test(cleanRoot))) {
        if (Array.isArray(isolatedErrors)) {
          isolatedErrors.push({
            scope: 'wildcard_policy',
            subject: cleanRoot || String(pol.rootDomain || ''),
            provider: pol.provider ? String(pol.provider) : null,
            error: `Dominio raíz inválido para política TLS: "${String(pol.rootDomain || '').slice(0, 80)}"`
          });
        }
        return;
      }

      const providerName = String(pol.provider || 'cloudflare').trim().toLowerCase();
      let providerConfig;
      try {
        ({ providerConfig } = buildDnsProviderConfig(providerName, {
          tokenEnv: pol.tokenEnv || (providerName === 'cloudflare' ? cloudflareDnsTokenEnv : null),
          apiToken: pol.apiToken || null,
          credentialsEnv: pol.credentialsEnv || null,
          credentials: pol.credentials || null
        }));
      } catch (err) {
        // kamal-proxy#233: en modo aislado, una política TLS corrupta jamás aborta ni borra dominios sanos
        if (isolateInvalid) {
          if (Array.isArray(isolatedErrors)) {
            isolatedErrors.push({
              scope: 'wildcard_policy',
              subject: `*.${cleanRoot}`,
              provider: providerName,
              error: err && err.message ? err.message : String(err)
            });
          }
          return;
        }
        throw err;
      }
      seenRoots.add(cleanRoot);
      const subjects = pol.includeApex === false ? [`*.${cleanRoot}`] : [`*.${cleanRoot}`, cleanRoot];

      /** @type {any} */
      const acmeIssuer = {
        module: 'acme',
        challenges: {
          dns: {
            provider: providerConfig,
            resolvers: ['1.1.1.1', '8.8.8.8']
          }
        }
      };
      if (acmeEmail) acmeIssuer.email = acmeEmail;

      policies.push({
        subjects,
        issuers: [acmeIssuer]
      });
    };

    if (Array.isArray(wildcardPolicies)) {
      for (const wp of wildcardPolicies) {
        if (!wp || wp.enabled === false) continue;
        if (!wp.rootDomain) {
          if (isolateInvalid && Array.isArray(isolatedErrors)) {
            isolatedErrors.push({
              scope: 'wildcard_policy',
              subject: '(empty)',
              provider: wp.provider ? String(wp.provider) : null,
              error: 'Política wildcard sin rootDomain'
            });
          }
          continue;
        }
        pushWildcardPolicy(wp);
      }
    }

    if (Array.isArray(wildcardDomains) && wildcardDomains.length > 0) {
      const cleanSet = new Set(wildcardDomains.map((d) => String(d).trim().toLowerCase()).filter(Boolean));
      for (const d of cleanSet) {
        if (d.startsWith('*.')) {
          const root = d.slice(2);
          pushWildcardPolicy({
            rootDomain: root,
            tokenEnv: cloudflareDnsTokenEnv,
            includeApex: cleanSet.has(root)
          });
        }
      }
    }

    // Política catch-all bajo demanda con respaldo automático Let's Encrypt + ZeroSSL
    /** @type {any[]} */
    const defaultIssuers = [
      { module: 'acme', ...(acmeEmail ? { email: acmeEmail } : {}) },
      { module: 'zerossl', ...(acmeEmail ? { email: acmeEmail } : {}) }
    ];
    policies.push({
      on_demand: true,
      issuers: defaultIssuers
    });

    /** @type {any} */
    const tlsApp = {
      automation: {
        policies,
        on_demand: {
          // `ask` está deprecado ("WILL BE REMOVED SOON") en favor de
          // `permission` con el módulo http.
          permission: { module: 'http', endpoint: askEndpoint }
        }
      }
    };

    /** @type {Array<{ certificate: string, key: string, tags?: string[] }>} */
    const validCerts = [];
    if (Array.isArray(customCertFiles)) {
      for (const c of customCertFiles) {
        const certStr = c && typeof c.certificate === 'string' ? c.certificate.trim() : '';
        const keyStr = c && typeof c.key === 'string' ? c.key.trim() : '';
        const bad = !certStr || !keyStr || /[\r\n\0]/.test(certStr) || /[\r\n\0]/.test(keyStr);
        if (bad) {
          if (isolateInvalid && Array.isArray(isolatedErrors)) {
            isolatedErrors.push({
              scope: 'custom_cert',
              subject: certStr || '(missing cert)',
              provider: null,
              error: 'Certificado personalizado inválido (falta ruta de certificado/clave o contiene caracteres de control)'
            });
          }
          continue;
        }
        validCerts.push({
          certificate: certStr,
          key: keyStr,
          ...(Array.isArray(c.tags) ? { tags: c.tags } : {})
        });
      }
    }
    /** @type {Set<string>} */
    const automatedWildcardSubjects = new Set();
    for (const pol of policies) {
      if (Array.isArray(pol.subjects)) {
        for (const s of pol.subjects) {
          if (s) automatedWildcardSubjects.add(s);
        }
      }
    }
    if (validCerts.length > 0 || automatedWildcardSubjects.size > 0) {
      tlsApp.certificates = {
        ...(automatedWildcardSubjects.size > 0 ? { automate: Array.from(automatedWildcardSubjects) } : {}),
        ...(validCerts.length > 0
          ? {
              load_files: validCerts.map((c) => ({
                certificate: c.certificate,
                key: c.key,
                ...(c.tags ? { tags: c.tags } : {})
              }))
            }
          : {})
      };
    }

    return tlsApp;
  }

  /**
   * @param {{
   *   askEndpoint: string,
   *   httpPort?: number,
   *   httpsPort?: number,
   *   automaticHttps?: boolean,
   *   wildcardDomains?: string[],
   *   wildcardPolicies?: any[],
   *   cloudflareDnsTokenEnv?: string,
   *   acmeEmail?: string | null,
   *   customCertFiles?: any[],
   *   enableCompression?: boolean,
   *   containerized?: boolean | null,
   *   gracePeriodMs?: number | null,
   *   shutdownDelayMs?: number | null
   * }} opts
   */
  buildBaseConfig({
    askEndpoint,
    httpPort = 80,
    httpsPort = 443,
    automaticHttps = true,
    wildcardDomains = [],
    wildcardPolicies = [],
    cloudflareDnsTokenEnv = 'CF_API_TOKEN',
    acmeEmail = null,
    customCertFiles = [],
    enableCompression = true,
    containerized = null,
    gracePeriodMs = 10000,
    shutdownDelayMs = 2000
  }) {
    const safeGraceMs = Number.isFinite(Number(gracePeriodMs))
      ? Math.min(120000, Math.max(1000, Math.round(Number(gracePeriodMs))))
      : 10000;
    const safeShutdownDelayMs = Number.isFinite(Number(shutdownDelayMs))
      ? Math.min(30000, Math.max(0, Math.round(Number(shutdownDelayMs))))
      : 2000;
    const tlsApp = this.buildTlsApp({
      askEndpoint,
      wildcardDomains,
      wildcardPolicies,
      cloudflareDnsTokenEnv,
      acmeEmail,
      customCertFiles,
      isolateInvalid: true
    });

    const adminTarget = this._getAdminTarget();
    const adminHost = adminTarget.hostHeader;
    const isContainerizedCaddy = containerized !== null
      ? Boolean(containerized)
      : (this.isContainerized || process.env.CULKIBO_CADDY_CONTAINERIZED === '1');
    const isLoopbackAdmin = !isContainerizedCaddy && /^(localhost|127\.0\.0\.1|\[::1\]):/i.test(adminHost);
    const adminPort = String(adminTarget.port || 2019);

    /** @type {any[]} */
    const initialRoutes = [];
    if (enableCompression) {
      // Ruta no-terminal de servidor para comprimir con Zstd + Gzip sin romper SSE (`text/event-stream`) ni streaming IA (Caddy #7905).
      initialRoutes.push({
        '@id': 'sys_encode',
        match: [{ not: [{ header: { Accept: ['*text/event-stream*'] } }] }],
        handle: [{
          handler: 'encode',
          encodings: { zstd: {}, gzip: {} },
          prefer: ['zstd', 'gzip'],
          minimum_length: 1024,
          match: {
            headers: {
              'Content-Type': [
                'text/html*',
                'text/css*',
                'text/plain*',
                'text/javascript*',
                'text/xml*',
                'application/json*',
                'application/javascript*',
                'application/xml*',
                'application/xhtml+xml*',
                'image/svg+xml*'
              ]
            }
          }
        }]
      });
    }

    /** @type {any} */
    const culkiboServer = {
      listen: [`:${httpPort}`, `:${httpsPort}`],
      routes: initialRoutes,
      read_header_timeout: 10000000000,
      idle_timeout: 60000000000,
      trusted_proxies: {
        source: 'static',
        ranges: resolveTrustedProxyCidrs()
      },
      client_ip_headers: ['CF-Connecting-IP', 'X-Forwarded-For'],
      ...(automaticHttps
        ? { protocols: ['h1', 'h2', 'h3'] }
        : { automatic_https: { disable: true } })
    };

    return {
      admin: isLoopbackAdmin
        ? { listen: adminHost }
        : { listen: `0.0.0.0:${adminPort}`, origins: [adminHost, `localhost:${adminPort}`, `127.0.0.1:${adminPort}`] },
      apps: {
        http: {
          // Barrera de drenaje estilo Pingora: `shutdown_delay` retiene conexiones activas
          // antes de retirar listeners y `grace_period` drena tráfico en vuelo sin 502/503.
          grace_period: safeGraceMs * 1e6,
          ...(safeShutdownDelayMs > 0 ? { shutdown_delay: safeShutdownDelayMs * 1e6 } : {}),
          servers: {
            culkibo: culkiboServer
          }
        },
        tls: tlsApp
      }
    };
  }

  /**
   * Carga la configuración base completa. Sobrescribe lo que hubiera.
   * @param {any} options
   * @param {{ adminUrl?: string | null, caddyAdminPort?: number | null }} [adminOpts]
   */
  async loadBaseConfig(options, { adminUrl = null, caddyAdminPort = null } = {}) {
    const isOverride = Boolean(adminUrl && String(adminUrl).trim() !== this.adminUrl);
    await this.requireAvailable({ adminUrl, caddyAdminPort });
    const config = this.buildBaseConfig(options);
    const res = await this.adminRequest('POST', '/load', {
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
      timeoutMs: 15000,
      readBody: false,
      adminUrl: isOverride ? String(adminUrl).trim() : null,
      caddyAdminPort
    });
    if (!res.ok) throw new Error(`No se pudo cargar la configuración base: ${res.status} ${res.text}`);
    if (!isOverride) {
      this._appliedRouteJson.clear();
      this.lastKnownRouteCount = 0;
    }
    return config;
  }

  // ---------------------------------------------------------------------
  // Rutas
  // ---------------------------------------------------------------------

  routeId(projectId) {
    return `${ID_PREFIX}${String(projectId).replace(/[^a-zA-Z0-9_-]/g, '')}`;
  }

  /**
   * Detecta la clase lógica de una ruta ya construida de Caddy o de un spec
   * (`redirect`, `maintenance`, `sleeping`, `proxy`) sin falsos positivos.
   * @param {any} specOrRoute
   * @returns {'redirect' | 'maintenance' | 'sleeping' | 'proxy'}
   */
  _classifyRouteKind(specOrRoute) {
    if (!specOrRoute || typeof specOrRoute !== 'object') return 'proxy';
    if (typeof specOrRoute.kind === 'string') {
      if (specOrRoute.kind === 'redirect') return 'redirect';
      if (specOrRoute.kind === 'maintenance') return 'maintenance';
      if (specOrRoute.kind === 'sleeping') return 'sleeping';
    }
    const inspectHandlers = (handlers) => {
      if (!Array.isArray(handlers)) return null;
      for (const h of handlers) {
        if (!h || typeof h !== 'object') continue;
        if (h.handler === 'rewrite' && typeof h.uri === 'string' && h.uri.startsWith('/_culkibo/wake/')) {
          return 'sleeping';
        }
        if (h.handler === 'static_response') {
          const code = String(h.status_code || '');
          if (code === '503') return 'maintenance';
          if (code === '301' || code === '302' || code === '307' || code === '308') return 'redirect';
        }
        if (h.handler === 'subroute' && Array.isArray(h.routes)) {
          for (const sub of h.routes) {
            // Saltar la rama de bloqueo 403 de IP Allowlist o preflight OPTIONS 204
            const subKind = inspectHandlers(sub && sub.handle);
            if (subKind) return subKind;
          }
        }
      }
      return null;
    };
    return /** @type {'redirect' | 'maintenance' | 'sleeping' | 'proxy'} */ (inspectHandlers(specOrRoute.handle) || 'proxy');
  }

  /**
   * Orden determinista por especificidad para evitar que una ruta comodín
   * (`*.empresa.com`) capture tráfico de un subdominio exacto (`tienda.empresa.com`),
   * y garantizando prioridad para redirecciones exactas, mantenimiento/sleeping y rutas con prefijo de path.
   *
   * 0: redirecciones exactas (www -> apex / apex -> www)
   * 10: modo mantenimiento / sleeping exacto
   * 20..100: rutas exactas con matcher de path (más largo primero)
   * 200: rutas con hostnames exactos
   * 1000..: comodines ordenados por sufijo más largo primero (`*.sub.a.com` antes que `*.a.com`)
   */
  routeSpecificityRank(specOrRoute) {
    const hosts = Array.isArray(specOrRoute?.hostnames)
      ? specOrRoute.hostnames
      : (Array.isArray(specOrRoute?.match?.[0]?.host) ? specOrRoute.match[0].host : []);
    const kind = this._classifyRouteKind(specOrRoute);
    const hasWildcard = hosts.some((h) => String(h).startsWith('*.'));
    const paths = Array.isArray(specOrRoute?.match?.[0]?.path) ? specOrRoute.match[0].path : [];
    const maxPathLen = paths.length > 0 ? Math.max(...paths.map((p) => String(p).length), 0) : 0;

    if (!hasWildcard) {
      if (kind === 'redirect') return 0;
      if (kind === 'maintenance' || kind === 'sleeping') return 10;
      if (maxPathLen > 0) return 100 - Math.min(80, maxPathLen);
      return 200;
    }
    const maxLen = Math.max(...hosts.map((h) => String(h).length), 0);
    const kindOffset = kind === 'redirect' ? 0 : (kind === 'maintenance' || kind === 'sleeping' ? 1 : 2);
    return (1000 - Math.min(900, maxLen)) * 10 + kindOffset;
  }

  /**
   * Construye una ruta nativa de Caddy para proyectos hibernados (Scale-to-Zero):
   * reescribe la petición hacia el endpoint interno de despertar (`/_culkibo/wake/:projectId`)
   * y reenvía cabeceras de contexto (`X-Culkibo-Wake-Project`, `X-Culkibo-Wake-Host`,
   * `X-Culkibo-Wake-Uri` y opcionalmente `X-Culkibo-Wake-Secret`) sin exponer el endpoint al exterior.
   *
   * @param {{
   *   projectId: string,
   *   hostnames: string[],
   *   wakeTarget?: string,
   *   wakeSecret?: string | null,
   *   ipAllowlist?: string[] | null,
   *   basicAuth?: { enabled?: boolean, realm?: string, accounts?: Array<{ username: string, passwordHash: string }> } | null,
   *   maxBodySizeMb?: number | null
   * }} spec
   */
  buildSleepingRoute({
    projectId,
    hostnames,
    wakeTarget = '127.0.0.1:3030',
    wakeSecret = null,
    ipAllowlist = null,
    basicAuth = null,
    maxBodySizeMb = null
  }) {
    if (!projectId || typeof projectId !== 'string') {
      throw new Error('Una ruta sleeping necesita projectId');
    }
    if (!Array.isArray(hostnames) || hostnames.length === 0) {
      throw new Error('Una ruta sleeping necesita al menos un hostname');
    }
    const rawTarget = String(wakeTarget || '').trim();
    if (!rawTarget || /[\s\r\n\0]/.test(rawTarget)) {
      throw new Error('wakeTarget inválido para ruta sleeping');
    }

    let dial = rawTarget;
    let wakePath = `/_culkibo/wake/${encodeURIComponent(projectId)}`;
    if (/^https?:\/\//i.test(rawTarget)) {
      const parsed = new URL(rawTarget);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error(`Protocolo wakeTarget no permitido: ${parsed.protocol}`);
      }
      const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
      dial = `${parsed.hostname}:${port}`;
      if (parsed.pathname && parsed.pathname !== '/') {
        wakePath = `${parsed.pathname}${parsed.search || ''}`;
      }
    } else {
      dial = rawTarget.replace(/\/+$/, '');
      if (!/^[a-zA-Z0-9._\[\]:-]+$/.test(dial) || !dial.includes(':')) {
        throw new Error(`Dirección wakeTarget inválida: ${dial.slice(0, 80)}`);
      }
    }

    /** @type {Record<string, string[]>} */
    const wakeHeaders = {
      'X-Culkibo-Wake-Project': [String(projectId).replace(/[\r\n\0]/g, '').slice(0, 80)],
      'X-Culkibo-Wake-Host': ['{http.request.host}'],
      'X-Culkibo-Wake-Path': ['{http.request.orig_uri}'],
      'X-Culkibo-Wake-Uri': ['{http.request.orig_uri}']
    };
    if (wakeSecret && typeof wakeSecret === 'string' && !/[\r\n\0]/.test(wakeSecret)) {
      wakeHeaders['X-Culkibo-Wake-Secret'] = [wakeSecret.slice(0, 256)];
    }

    /** @type {any[]} */
    const chain = [];
    const maxMb = Number(maxBodySizeMb);
    if (Number.isFinite(maxMb) && maxMb > 0 && maxMb <= 10240) {
      chain.push({ handler: 'request_body', max_size: Math.round(maxMb * 1024 * 1024) });
    }
    if (basicAuth && basicAuth.enabled && Array.isArray(basicAuth.accounts) && basicAuth.accounts.length > 0) {
      /** @type {Map<string, { username: string, password: string }>} */
      const dedupAccounts = new Map();
      for (const a of basicAuth.accounts) {
        if (a && typeof a.username === 'string' && a.username.trim() && typeof a.passwordHash === 'string' && a.passwordHash.startsWith('$2')) {
          const uname = a.username.trim();
          dedupAccounts.set(uname, { username: uname, password: a.passwordHash });
        }
      }
      const validAccounts = Array.from(dedupAccounts.values());
      if (validAccounts.length > 0) {
        chain.push({
          handler: 'authentication',
          providers: {
            http_basic: {
              realm: String(basicAuth.realm || 'Acceso protegido').replace(/[\r\n\0"]/g, '').slice(0, 80),
              hash: { algorithm: 'bcrypt' },
              hash_cache: {},
              accounts: validAccounts
            }
          }
        });
      }
    }

    chain.push(
      {
        handler: 'rewrite',
        uri: wakePath
      },
      {
        handler: 'reverse_proxy',
        upstreams: [{ dial }],
        headers: {
          request: { set: wakeHeaders }
        },
        transport: {
          protocol: 'http',
          dial_timeout: 5000000000,
          response_header_timeout: 30000000000
        }
      }
    );

    const cleanAllowlist = Array.isArray(ipAllowlist)
      ? ipAllowlist.map((x) => String(x || '').trim()).filter(Boolean)
      : [];
    /** @type {any[]} */
    const finalHandle = cleanAllowlist.length > 0
      ? [{
          handler: 'subroute',
          routes: [
            {
              match: [{ not: [{ client_ip: { ranges: cleanAllowlist } }] }],
              handle: [{
                handler: 'static_response',
                status_code: '403',
                headers: { 'Content-Type': ['text/plain; charset=utf-8'] },
                body: 'Acceso restringido por política de IPs permitidas (Culkibo Edge).'
              }],
              terminal: true
            },
            { handle: chain }
          ]
        }]
      : chain;

    return {
      '@id': this.routeId(projectId),
      match: [{ host: hostnames }],
      handle: finalHandle,
      terminal: true
    };
  }

  /**
   * Extrae el handler `reverse_proxy` principal de una ruta (ignorando sub-peticiones
   * `forward_auth` con `handle_response`, y atravesando `subroute` de IP Allowlist/CORS/pathRoutes).
   */
  extractProxyHandler(route) {
    if (!route || !Array.isArray(route.handle)) return null;
    for (const h of route.handle) {
      if (!h) continue;
      if (h.handler === 'reverse_proxy') {
        const isForwardAuthCheck = Boolean(
          Array.isArray(h.handle_response) &&
          h.rewrite &&
          h.rewrite.method === 'GET'
        );
        if (!isForwardAuthCheck) return h;
      }
      if (h.handler === 'subroute' && Array.isArray(h.routes)) {
        // Recorrer del final al inicio para preferir la ruta principal de aplicación sobre subrutas auxiliares
        for (let i = h.routes.length - 1; i >= 0; i--) {
          const nested = this.extractProxyHandler(h.routes[i]);
          if (nested) return nested;
        }
      }
    }
    return null;
  }

  /**
   * Construye un bloque `reverse_proxy` reutilizable (para ruta principal o `pathRoutes[]`)
   * con soporte para gRPC/h2c, SSE streaming, drenaje WebSocket, HSTS preload y cabeceras seguras.
   * @param {any} opts
   */
  _buildReverseProxyHandler({
    upstreams,
    weights = null,
    protocol = 'http',
    streaming = false,
    flushInterval = null,
    streamCloseDelayMs = 5000,
    streamTimeoutMs = null,
    dialTimeoutMs = 5000,
    responseHeaderTimeoutMs = null,
    securityHeaders = false,
    hstsPreload = false,
    hstsMaxAge = null,
    permissionsPolicy = null,
    csp = null,
    framePolicy = null,
    customHeaders = null,
    earlyHints = null,
    activeHealthPath = null
  }) {
    const cleanProto = String(protocol || 'http').trim().toLowerCase();
    if (!['http', 'grpc', 'h2c'].includes(cleanProto)) {
      throw new Error(`Protocolo de upstream inválido: ${protocol} (usa http, grpc o h2c)`);
    }
    const isH2c = cleanProto === 'grpc' || cleanProto === 'h2c';
    const isStreaming = Boolean(streaming) || flushInterval === -1;
    const effectiveFlush = flushInterval !== null && flushInterval !== undefined
      ? Number(flushInterval)
      : (isStreaming ? -1 : null);

    const safeStreamCloseMs = Number.isFinite(Number(streamCloseDelayMs))
      ? Math.min(300000, Math.max(0, Math.round(Number(streamCloseDelayMs))))
      : 5000;
    const safeStreamTimeoutMs = streamTimeoutMs !== null && streamTimeoutMs !== undefined && Number.isFinite(Number(streamTimeoutMs))
      ? Math.min(3600000, Math.max(1000, Math.round(Number(streamTimeoutMs))))
      : null;
    const safeDialMs = Number.isFinite(Number(dialTimeoutMs))
      ? Math.min(60000, Math.max(500, Math.round(Number(dialTimeoutMs))))
      : 5000;

    /** @type {any} */
    const transport = {
      protocol: 'http',
      keep_alive: {
        max_idle_conns_per_host: 64,
        idle_timeout: 120000000000,
        probe_interval: 30000000000
      },
      dial_timeout: safeDialMs * 1e6
    };
    if (isH2c) {
      transport.versions = ['h2c'];
    }
    if (responseHeaderTimeoutMs !== null && responseHeaderTimeoutMs !== undefined && Number.isFinite(Number(responseHeaderTimeoutMs))) {
      const safeRespMs = Math.min(600000, Math.max(1000, Math.round(Number(responseHeaderTimeoutMs))));
      transport.response_header_timeout = safeRespMs * 1e6;
    } else if (!isStreaming && !isH2c) {
      transport.response_header_timeout = 60000000000;
    }

    /** @type {any} */
    const handler = {
      handler: 'reverse_proxy',
      upstreams: upstreams.map((u) => ({ dial: String(u) })),
      stream_close_delay: safeStreamCloseMs * 1e6,
      ...(safeStreamTimeoutMs !== null ? { stream_timeout: safeStreamTimeoutMs * 1e6 } : {}),
      ...(effectiveFlush !== null && Number.isFinite(effectiveFlush)
        ? { flush_interval: effectiveFlush < 0 ? -1 : Math.round(effectiveFlush * 1e6) }
        : {}),
      transport
    };

    if (weights && weights.length === upstreams.length && upstreams.length > 1) {
      handler.load_balancing = {
        selection_policy: { policy: 'weighted_round_robin', weights }
      };
    }

    /** @type {Record<string, string[]>} */
    const respSet = {};
    /** @type {string[]} */
    const respDel = [];
    if (securityHeaders) {
      respSet['X-Content-Type-Options'] = ['nosniff'];
      respSet['Referrer-Policy'] = ['strict-origin-when-cross-origin'];
      if (hstsPreload) {
        const age = Number.isFinite(Number(hstsMaxAge)) && Number(hstsMaxAge) >= 31536000
          ? Math.min(63072000, Math.round(Number(hstsMaxAge)))
          : 63072000;
        respSet['Strict-Transport-Security'] = [`max-age=${age}; includeSubDomains; preload`];
      } else {
        const age = Number.isFinite(Number(hstsMaxAge)) && Number(hstsMaxAge) >= 0
          ? Math.min(63072000, Math.round(Number(hstsMaxAge)))
          : 31536000;
        if (age > 0) {
          respSet['Strict-Transport-Security'] = [`max-age=${age}; includeSubDomains`];
        }
      }
      if (framePolicy === 'DENY' || framePolicy === 'SAMEORIGIN') {
        respSet['X-Frame-Options'] = [framePolicy];
      }
      respDel.push('Server', 'X-Powered-By');
    } else {
      if (hstsPreload) {
        respSet['Strict-Transport-Security'] = ['max-age=63072000; includeSubDomains; preload'];
      }
      if (framePolicy === 'DENY' || framePolicy === 'SAMEORIGIN') {
        respSet['X-Frame-Options'] = [framePolicy];
      }
    }
    if (typeof permissionsPolicy === 'string' && permissionsPolicy.trim()) {
      respSet['Permissions-Policy'] = [permissionsPolicy.replace(/[\r\n\0]/g, '').trim().slice(0, 512)];
    }
    if (typeof csp === 'string' && csp.trim()) {
      respSet['Content-Security-Policy'] = [csp.replace(/[\r\n\0]/g, '').trim().slice(0, 2048)];
    }

    if (customHeaders && customHeaders.response && typeof customHeaders.response === 'object') {
      let count = 0;
      for (const [k, v] of Object.entries(customHeaders.response)) {
        if (count >= 20) break;
        if (HEADER_NAME_RE.test(k) && !HOP_BY_HOP_HEADER_RE.test(k) && typeof v === 'string') {
          respSet[k] = [v.replace(/[\r\n\0]/g, '').slice(0, 1024)];
          count++;
        }
      }
    }
    /** @type {Record<string, string[]>} */
    const reqSet = {};
    if (customHeaders && customHeaders.request && typeof customHeaders.request === 'object') {
      let count = 0;
      for (const [k, v] of Object.entries(customHeaders.request)) {
        if (count >= 20) break;
        if (HEADER_NAME_RE.test(k) && !HOP_BY_HOP_HEADER_RE.test(k) && typeof v === 'string') {
          reqSet[k] = [v.replace(/[\r\n\0]/g, '').slice(0, 1024)];
          count++;
        }
      }
    }
    const earlyHintLinks = formatEarlyHintsLinks(earlyHints);
    /** @type {Record<string, string[]>} */
    const respAdd = earlyHintLinks.length > 0 ? { Link: earlyHintLinks } : {};

    if (Object.keys(respSet).length > 0 || Object.keys(respAdd).length > 0 || respDel.length > 0 || Object.keys(reqSet).length > 0) {
      handler.headers = {};
      if (Object.keys(respSet).length > 0 || Object.keys(respAdd).length > 0 || respDel.length > 0) {
        handler.headers.response = {
          ...(Object.keys(respSet).length > 0 ? { set: respSet } : {}),
          ...(Object.keys(respAdd).length > 0 ? { add: respAdd } : {}),
          ...(respDel.length > 0 ? { delete: respDel } : {})
        };
      }
      if (Object.keys(reqSet).length > 0) {
        handler.headers.request = { set: reqSet };
      }
    }

    handler.health_checks = {
      passive: { fail_duration: 10000000000, max_fails: 3 } // 10 s
    };
    if (
      typeof activeHealthPath === 'string' &&
      /^\/[A-Za-z0-9._~\-/]*$/.test(activeHealthPath) &&
      !activeHealthPath.includes('..')
    ) {
      handler.health_checks.active = {
        path: activeHealthPath,
        interval: 10000000000,
        timeout: 3000000000
      };
    }

    return handler;
  }

  /**
   * Construye la cadena nativa de Caddy para ForwardAuth (Authelia / Authentik / Keycloak / Tinyauth):
   * 1. ELIMINA primero cualquier cabecera `copyHeaders` suministrada por el cliente (anti-spoofing).
   * 2. Ejecuta sub-petición GET al upstream de autenticación pasando X-Forwarded-Method/Uri/Proto/Host.
   * 3. Si responde 2xx, copia las cabeceras verificadas (`{http.reverse_proxy.header.*}`) y continúa al backend;
   *    cualquier 3xx/4xx (redirect al portal SSO o 401/403) se devuelve directamente al navegador.
   *
   * @param {{
   *   enabled?: boolean,
   *   upstream: string,
   *   uri?: string,
   *   copyHeaders?: string[],
   *   dialTimeoutMs?: number,
   *   responseTimeoutMs?: number
   * }} forwardAuth
   */
  _buildForwardAuthHandlers(forwardAuth) {
    const dial = sanitizeUpstreamDial(forwardAuth.upstream, 'forwardAuth.upstream');
    const rawUri = String(forwardAuth.uri || '/api/verify').trim();
    if (!rawUri.startsWith('/') || /[\s\r\n\0]/.test(rawUri) || rawUri.includes('..')) {
      throw new Error(`URI de forwardAuth inválida: ${rawUri.slice(0, 80)}`);
    }

    const defaultHeaders = ['Remote-User', 'Remote-Groups', 'Remote-Name', 'Remote-Email'];
    const rawCopy = Array.isArray(forwardAuth.copyHeaders) && forwardAuth.copyHeaders.length > 0
      ? forwardAuth.copyHeaders
      : defaultHeaders;
    /** @type {string[]} */
    const copyHeaders = [];
    /** @type {Set<string>} */
    const seenLower = new Set();
    for (const h of rawCopy.slice(0, 20)) {
      const clean = String(h || '').trim();
      if (!HEADER_NAME_RE.test(clean) || HOP_BY_HOP_HEADER_RE.test(clean)) {
        throw new Error(`Cabecera copyHeaders inválida en forwardAuth: "${clean.slice(0, 40)}"`);
      }
      const lower = clean.toLowerCase();
      if (!seenLower.has(lower)) {
        seenLower.add(lower);
        copyHeaders.push(clean);
      }
    }

    const dialTimeoutMs = Number.isFinite(Number(forwardAuth.dialTimeoutMs))
      ? Math.min(30000, Math.max(500, Math.round(Number(forwardAuth.dialTimeoutMs))))
      : 3000;
    const responseTimeoutMs = Number.isFinite(Number(forwardAuth.responseTimeoutMs))
      ? Math.min(30000, Math.max(500, Math.round(Number(forwardAuth.responseTimeoutMs))))
      : 5000;

    /** @type {Record<string, string[]>} */
    const copySet = {};
    for (const h of copyHeaders) {
      copySet[h] = [`{http.reverse_proxy.header.${h}}`];
    }

    /** @type {any[]} */
    const handlers = [
      // Defensa anti-spoofing: purgar cualquier cabecera de identidad inyectada por el cliente antes del chequeo auth
      {
        handler: 'headers',
        request: {
          delete: copyHeaders
        }
      },
      {
        handler: 'reverse_proxy',
        upstreams: [{ dial }],
        rewrite: {
          method: 'GET',
          uri: rawUri
        },
        headers: {
          request: {
            set: {
              'X-Forwarded-Method': ['{http.request.method}'],
              'X-Forwarded-Uri': ['{http.request.uri}'],
              'X-Forwarded-Proto': ['{http.request.scheme}'],
              'X-Forwarded-Host': ['{http.request.host}']
            }
          }
        },
        transport: {
          protocol: 'http',
          dial_timeout: dialTimeoutMs * 1e6,
          response_header_timeout: responseTimeoutMs * 1e6
        },
        handle_response: [
          {
            match: { status_code: [2] },
            routes: [
              {
                handle: [
                  {
                    handler: 'headers',
                    request: {
                      set: copySet
                    }
                  }
                ]
              }
            ]
          }
        ]
      }
    ];
    return handlers;
  }

  /**
   * Envuelve la cadena de handlers con política CORS nativa en Caddy JSON:
   * - Rechaza estrictamente `allowCredentials: true` combinado con `'*'`.
   * - Nunca refleja un `Origin` arbitrario: valida contra regex exacto de orígenes permitidos.
   * - Responde preflight `OPTIONS` con 204 + `Vary: Origin` antes de auth.
   *
   * @param {{
   *   enabled?: boolean,
   *   allowedOrigins?: string[],
   *   allowedMethods?: string[],
   *   allowedHeaders?: string[],
   *   exposedHeaders?: string[],
   *   allowCredentials?: boolean,
   *   maxAge?: number
   * }} cors
   * @param {any[]} innerChain
   */
  _wrapWithCors(cors, innerChain) {
    const rawOrigins = Array.isArray(cors.allowedOrigins) ? cors.allowedOrigins : [];
    const origins = Array.from(new Set(rawOrigins.map((o) => validateCorsOrigin(o))));
    if (origins.length === 0) {
      throw new Error('Activar CORS requiere al menos un origen en allowedOrigins');
    }
    const allowCredentials = Boolean(cors.allowCredentials);
    const isWildcard = origins.includes('*');
    if (allowCredentials && isWildcard) {
      throw new Error('Política CORS insegura bloqueada: allowCredentials=true no puede combinarse con allowedOrigins=["*"]');
    }

    const allowedMethodsList = (Array.isArray(cors.allowedMethods) && cors.allowedMethods.length > 0
      ? cors.allowedMethods
      : ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
      .map((m) => String(m || '').trim().toUpperCase())
      .filter((m) => /^[A-Z]{2,16}$/.test(m));
    const allowedHeadersList = (Array.isArray(cors.allowedHeaders) && cors.allowedHeaders.length > 0
      ? cors.allowedHeaders
      : ['Authorization', 'Content-Type', 'X-Requested-With'])
      .map((h) => String(h || '').trim())
      .filter((h) => HEADER_NAME_RE.test(h));
    const exposedHeadersList = (Array.isArray(cors.exposedHeaders) ? cors.exposedHeaders : [])
      .map((h) => String(h || '').trim())
      .filter((h) => HEADER_NAME_RE.test(h));
    const maxAge = Number.isFinite(Number(cors.maxAge))
      ? Math.min(86400, Math.max(0, Math.round(Number(cors.maxAge))))
      : 3600;

    const originValue = isWildcard ? '*' : '{http.request.header.Origin}';
    const originMatcher = isWildcard
      ? null
      : {
          header_regexp: {
            Origin: `^(?:${origins.map((o) => escapeRegexLiteral(o)).join('|')})$`
          }
        };

    /** @type {Record<string, string[]>} */
    const preflightHeaders = {
      'Access-Control-Allow-Origin': [originValue],
      'Access-Control-Allow-Methods': [allowedMethodsList.join(', ')],
      'Access-Control-Allow-Headers': [allowedHeadersList.join(', ')],
      'Access-Control-Max-Age': [String(maxAge)],
      Vary: ['Origin, Access-Control-Request-Method, Access-Control-Request-Headers']
    };
    if (allowCredentials) {
      preflightHeaders['Access-Control-Allow-Credentials'] = ['true'];
    }

    /** @type {Record<string, string[]>} */
    const respCorsHeaders = {
      'Access-Control-Allow-Origin': [originValue],
      Vary: ['Origin']
    };
    if (allowCredentials) {
      respCorsHeaders['Access-Control-Allow-Credentials'] = ['true'];
    }
    if (exposedHeadersList.length > 0) {
      respCorsHeaders['Access-Control-Expose-Headers'] = [exposedHeadersList.join(', ')];
    }

    /** @type {any[]} */
    const corsRoutes = [
      {
        match: [
          {
            method: ['OPTIONS'],
            ...(originMatcher || {})
          }
        ],
        handle: [
          {
            handler: 'static_response',
            status_code: '204',
            headers: preflightHeaders
          }
        ],
        terminal: true
      }
    ];

    if (originMatcher) {
      // Añadir cabeceras CORS solo cuando la cabecera Origin coincide exactamente con la lista blanca
      corsRoutes.push({
        match: [originMatcher],
        handle: [
          {
            handler: 'headers',
            response: {
              set: respCorsHeaders
            }
          }
        ]
      });
      corsRoutes.push({
        handle: innerChain
      });
    } else {
      corsRoutes.push({
        handle: [
          {
            handler: 'headers',
            response: {
              set: respCorsHeaders
            }
          },
          ...innerChain
        ]
      });
    }

    return [{ handler: 'subroute', routes: corsRoutes }];
  }

  /**
   * Construye una ruta de Caddy:
   * - `kind === 'redirect'`: redirección canónica 301/308 (`www` ↔ apex)
   * - `kind === 'maintenance'`: modo mantenimiento atómico 503 sin detener el contenedor
   * - `kind === 'sleeping'`: wake-on-request hacia Culkibo (Scale-to-Zero)
   * - por defecto: `reverse_proxy` con drenaje de WebSockets, keep-alive, canario opcional,
   *   cabeceras de seguridad/HSTS preload/personalizadas, Basic Auth bcrypt nativo, ForwardAuth
   *   (Authelia/Authentik), CORS, IP Allowlist, maxBodySize, pathRoutes/stripPrefix/pathRedirects,
   *   gRPC/h2c y ajuste de streaming SSE/WS.
   *
   * @param {{
   *   projectId: string,
   *   hostnames: string[],
   *   upstreams?: string[],
   *   weights?: number[] | null,
   *   kind?: string,
   *   redirectTo?: string,
   *   redirectStatus?: number,
   *   wakeTarget?: string,
   *   wakeSecret?: string | null,
   *   activeHealthPath?: string | null,
   *   adminUrl?: string | null,
   *   securityHeaders?: boolean,
   *   hstsPreload?: boolean,
   *   hstsMaxAge?: number | null,
   *   permissionsPolicy?: string | null,
   *   csp?: string | null,
   *   framePolicy?: 'DENY' | 'SAMEORIGIN' | 'ALLOW' | null,
   *   customHeaders?: { response?: Record<string, string>, request?: Record<string, string> } | null,
   *   basicAuth?: { enabled?: boolean, realm?: string, accounts?: Array<{ username: string, passwordHash: string }> } | null,
   *   forwardAuth?: { enabled?: boolean, upstream: string, uri?: string, copyHeaders?: string[], dialTimeoutMs?: number, responseTimeoutMs?: number } | null,
   *   cors?: { enabled?: boolean, allowedOrigins?: string[], allowedMethods?: string[], allowedHeaders?: string[], exposedHeaders?: string[], allowCredentials?: boolean, maxAge?: number } | null,
   *   pathRoutes?: Array<{ path: string, upstreams: string[], stripPrefix?: string | boolean, protocol?: string, streaming?: boolean, flushInterval?: number | null }> | null,
   *   pathRedirects?: Array<{ pattern: string, target: string, status?: number, isRegex?: boolean }> | null,
   *   ipAllowlist?: string[] | null,
   *   maxBodySizeMb?: number | null,
   *   rateLimit?: { enabled?: boolean, requests?: number, windowSeconds?: number } | null,
   *   protocol?: string,
   *   streaming?: boolean,
   *   flushInterval?: number | null,
   *   streamCloseDelayMs?: number | null,
   *   streamTimeoutMs?: number | null,
   *   earlyHints?: any,
   *   dialTimeoutMs?: number | null,
   *   responseHeaderTimeoutMs?: number | null
   * }} spec
   */
  buildRoute(spec) {
    const {
      projectId,
      hostnames,
      upstreams = [],
      weights = null,
      kind = 'proxy',
      redirectTo = null,
      redirectStatus = 301,
      wakeTarget = undefined,
      wakeSecret = null,
      activeHealthPath = null,
      securityHeaders = false,
      hstsPreload = false,
      hstsMaxAge = null,
      permissionsPolicy = null,
      csp = null,
      framePolicy = null,
      customHeaders = null,
      basicAuth = null,
      forwardAuth = null,
      cors = null,
      pathRoutes = null,
      pathRedirects = null,
      ipAllowlist = null,
      maxBodySizeMb = null,
      rateLimit = null,
      protocol = 'http',
      streaming = false,
      flushInterval = null,
      streamCloseDelayMs = 5000,
      streamTimeoutMs = null,
      earlyHints = null,
      dialTimeoutMs = 5000,
      responseHeaderTimeoutMs = null
    } = spec;

    if (!Array.isArray(hostnames) || hostnames.length === 0) {
      throw new Error('Una ruta necesita al menos un hostname');
    }

    if (kind === 'redirect' && redirectTo) {
      const code = redirectStatus === 308 ? '308' : '301';
      return {
        '@id': this.routeId(projectId),
        match: [{ host: hostnames }],
        handle: [{
          handler: 'static_response',
          status_code: code,
          headers: {
            Location: [`https://${redirectTo}{http.request.uri}`]
          }
        }],
        terminal: true
      };
    }

    if (kind === 'maintenance') {
      return {
        '@id': this.routeId(projectId),
        match: [{ host: hostnames }],
        handle: [{
          handler: 'static_response',
          status_code: '503',
          headers: {
            'Content-Type': ['text/html; charset=utf-8'],
            'Retry-After': ['300'],
            'Cache-Control': ['no-store']
          },
          body: MAINTENANCE_HTML
        }],
        terminal: true
      };
    }

    if (kind === 'sleeping') {
      return this.buildSleepingRoute({
        projectId,
        hostnames,
        wakeTarget: wakeTarget || (Array.isArray(upstreams) && upstreams[0] ? String(upstreams[0]) : '127.0.0.1:3030'),
        wakeSecret,
        ipAllowlist,
        basicAuth,
        maxBodySizeMb
      });
    }

    if (!Array.isArray(upstreams) || upstreams.length === 0) {
      throw new Error('Una ruta necesita al menos un destino');
    }

    const isStreamingRoute = projectId === 'culkibo_panel' || Boolean(streaming) || flushInterval === -1;
    const mainProxyHandler = this._buildReverseProxyHandler({
      upstreams,
      weights,
      protocol,
      streaming: isStreamingRoute,
      flushInterval: flushInterval !== null && flushInterval !== undefined ? flushInterval : (projectId === 'culkibo_panel' ? -1 : null),
      streamCloseDelayMs: streamCloseDelayMs ?? 5000,
      streamTimeoutMs,
      dialTimeoutMs: dialTimeoutMs ?? 5000,
      responseHeaderTimeoutMs,
      securityHeaders,
      hstsPreload,
      hstsMaxAge,
      permissionsPolicy,
      csp,
      framePolicy,
      customHeaders,
      earlyHints,
      activeHealthPath
    });

    /** @type {any[]} */
    const chain = [];

    // 1. Límite de tamaño de petición nativo (`request_body`)
    const maxMb = Number(maxBodySizeMb);
    if (Number.isFinite(maxMb) && maxMb > 0 && maxMb <= 10240) {
      chain.push({ handler: 'request_body', max_size: Math.round(maxMb * 1024 * 1024) });
    }

    // 2. Rate limiting por dominio ANTES de Basic Auth / ForwardAuth (protege CPU bcrypt y usa IP real tras Cloudflare)
    if (
      rateLimit &&
      rateLimit.enabled &&
      this._capabilitiesCache &&
      this._capabilitiesCache.data &&
      this._capabilitiesCache.data.hasRateLimitPlugin === true
    ) {
      const maxEvents = Math.min(100000, Math.max(1, Math.round(Number(rateLimit.requests) || 120)));
      const winSec = Math.min(3600, Math.max(1, Math.round(Number(rateLimit.windowSeconds) || 60)));
      const zoneName = `culkibo_rl_${this.routeId(projectId).replace(/[^a-zA-Z0-9_]/g, '_')}`;
      chain.push({
        handler: 'rate_limit',
        rate_limits: {
          [zoneName]: {
            key: '{http.vars.client_ip}',
            max_events: maxEvents,
            window: winSec * 1e9
          }
        }
      });
    }

    // 3. HTTP Basic Auth nativo de Caddy v2.11 con bcrypt + hash_cache y deduplicación por username (Caddy #8315)
    if (basicAuth && basicAuth.enabled && Array.isArray(basicAuth.accounts) && basicAuth.accounts.length > 0) {
      /** @type {Map<string, { username: string, password: string }>} */
      const dedupAccounts = new Map();
      for (const a of basicAuth.accounts) {
        if (a && typeof a.username === 'string' && a.username.trim() && typeof a.passwordHash === 'string' && a.passwordHash.startsWith('$2')) {
          const uname = a.username.trim();
          dedupAccounts.set(uname, { username: uname, password: a.passwordHash });
        }
      }
      const validAccounts = Array.from(dedupAccounts.values());
      if (validAccounts.length > 0) {
        chain.push({
          handler: 'authentication',
          providers: {
            http_basic: {
              realm: String(basicAuth.realm || 'Acceso protegido').replace(/[\r\n\0"]/g, '').slice(0, 80),
              hash: { algorithm: 'bcrypt' },
              hash_cache: {},
              accounts: validAccounts
            }
          }
        });
      }
    }

    // 4. ForwardAuth nativo (Authelia / Authentik / Keycloak) con purga anti-spoofing previa
    if (forwardAuth && forwardAuth.enabled) {
      chain.push(...this._buildForwardAuthHandlers(forwardAuth));
    }

    // 5. Path Redirects (regex ReDoS-safe o prefijo) + Path-Based Routing con strip_path_prefix
    const validRedirects = Array.isArray(pathRedirects) ? pathRedirects.filter(Boolean) : [];
    const validPathRoutes = Array.isArray(pathRoutes) ? pathRoutes.filter(Boolean) : [];
    if (validRedirects.length > 0 || validPathRoutes.length > 0) {
      /** @type {any[]} */
      const dispatchRoutes = [];

      validRedirects.slice(0, 32).forEach((rd, idx) => {
        const pattern = String(rd.pattern || '').trim();
        const target = String(rd.target || '').trim();
        const isRegex = rd.isRegex !== false;
        const codeNum = Number(rd.status);
        const status = [301, 302, 307, 308].includes(codeNum) ? String(codeNum) : '301';

        if (!pattern || !target || /[\r\n\0]/.test(target)) {
          throw new Error(`Redirección de ruta inválida en índice ${idx}`);
        }
        if (/^(?:javascript|data|vbscript):/i.test(target)) {
          throw new Error(`Esquema de destino de redirección bloqueado: ${target.slice(0, 40)}`);
        }
        if (!target.startsWith('/') && !/^https?:\/\//i.test(target)) {
          throw new Error(`El destino de redirección debe empezar por "/" o http(s)://: ${target.slice(0, 60)}`);
        }

        let matchObj;
        if (isRegex) {
          const check = validateSafeRedirectRegex(pattern);
          if (!check.ok) throw new Error(`Regex de redirección rechazado: ${check.error}`);
          matchObj = { path_regexp: { name: `ck_redir_${idx}`, pattern } };
        } else {
          if (!pattern.startsWith('/') || /[\s\r\n\0]/.test(pattern)) {
            throw new Error(`Ruta de redirección inválida: ${pattern.slice(0, 60)}`);
          }
          matchObj = { path: [pattern] };
        }

        dispatchRoutes.push({
          match: [matchObj],
          handle: [{
            handler: 'static_response',
            status_code: status,
            headers: { Location: [target] }
          }],
          terminal: true
        });
      });

      // Ordenar pathRoutes por prefijo más largo primero (`/api/v2/*` antes de `/api/*`)
      const sortedPathRoutes = [...validPathRoutes.slice(0, 32)].sort((a, b) => {
        const la = String(a.path || '').replace(/\*+$/, '').length;
        const lb = String(b.path || '').replace(/\*+$/, '').length;
        return lb - la;
      });

      for (const pr of sortedPathRoutes) {
        const rawPath = String(pr.path || '').trim();
        if (!rawPath.startsWith('/') || rawPath.length > 256 || /[\s\r\n\0]/.test(rawPath) || rawPath.includes('..')) {
          throw new Error(`Prefijo de pathRoute inválido: "${rawPath.slice(0, 60)}"`);
        }
        if (!Array.isArray(pr.upstreams) || pr.upstreams.length === 0) {
          throw new Error(`pathRoute "${rawPath}" necesita al menos un upstream`);
        }
        const safeUpstreams = pr.upstreams.map((u) => sanitizeUpstreamDial(u, `pathRoute(${rawPath}).upstream`));

        /** @type {any[]} */
        const subHandlers = [];
        if (pr.stripPrefix) {
          const prefixStr = typeof pr.stripPrefix === 'string'
            ? pr.stripPrefix.trim()
            : rawPath.replace(/\/\*+$/, '').replace(/\*+$/, '');
          if (prefixStr && prefixStr !== '/') {
            if (!prefixStr.startsWith('/') || /[\s\r\n\0]/.test(prefixStr) || prefixStr.includes('..')) {
              throw new Error(`stripPrefix inválido en pathRoute "${rawPath}": "${prefixStr}"`);
            }
            subHandlers.push({
              handler: 'rewrite',
              strip_path_prefix: prefixStr
            });
          }
        }
        subHandlers.push(this._buildReverseProxyHandler({
          upstreams: safeUpstreams,
          protocol: pr.protocol || protocol,
          streaming: pr.streaming !== undefined ? Boolean(pr.streaming) : isStreamingRoute,
          flushInterval: pr.flushInterval !== undefined ? pr.flushInterval : flushInterval,
          streamCloseDelayMs: streamCloseDelayMs ?? 5000,
          dialTimeoutMs: dialTimeoutMs ?? 5000,
          responseHeaderTimeoutMs,
          securityHeaders,
          hstsPreload,
          hstsMaxAge,
          permissionsPolicy,
          csp,
          framePolicy,
          customHeaders
        }));

        dispatchRoutes.push({
          match: [{ path: [rawPath] }],
          handle: subHandlers,
          terminal: true
        });
      }

      // Ruta por defecto para el resto de paths del dominio
      dispatchRoutes.push({
        handle: [mainProxyHandler]
      });

      chain.push({
        handler: 'subroute',
        routes: dispatchRoutes
      });
    } else {
      chain.push(mainProxyHandler);
    }

    // 6. Envoltura CORS (antes de BasicAuth / ForwardAuth para permitir preflight OPTIONS 204 sin 401)
    const corsWrapped = (cors && cors.enabled)
      ? this._wrapWithCors(cors, chain)
      : chain;

    // 7. IP Allowlist nativo con `subroute` + `not.client_ip` (capa más externa, cero plugins extra)
    const cleanAllowlist = Array.isArray(ipAllowlist)
      ? ipAllowlist.map((x) => String(x || '').trim()).filter(Boolean)
      : [];
    /** @type {any[]} */
    const finalHandle = cleanAllowlist.length > 0
      ? [{
          handler: 'subroute',
          routes: [
            {
              match: [{ not: [{ client_ip: { ranges: cleanAllowlist } }] }],
              handle: [{
                handler: 'static_response',
                status_code: '403',
                headers: { 'Content-Type': ['text/plain; charset=utf-8'] },
                body: 'Acceso restringido por política de IPs permitidas (Culkibo Edge).'
              }],
              terminal: true
            },
            {
              handle: corsWrapped
            }
          ]
        }]
      : corsWrapped;

    return {
      '@id': this.routeId(projectId),
      match: [{ host: hostnames }],
      handle: finalHandle,
      terminal: true
    };
  }

  /**
   * ¿Existe ya la ruta de este proyecto?
   * @param {string} projectId
   * @param {{ adminUrl?: string | null, caddyAdminPort?: number | null }} [opts]
   */
  async getRoute(projectId, { adminUrl = null, caddyAdminPort = null } = {}) {
    const { found, value } = await this.getWithEtag(`/id/${this.routeId(projectId)}`, { adminUrl, caddyAdminPort });
    return found ? value : null;
  }

  /**
   * Crea o reemplaza la ruta de un proyecto.
   *
   * Camino rápido: intenta `PATCH /id/<id>` directamente en un único viaje de
   * ida y vuelta contra la Admin API (sin `GET` previo). Solo cuando la ruta
   * todavía no existe (404) hace el `POST` sobre `/routes` con control
   * optimista `ETag`/`If-Match`. Esto reduce a la mitad la latencia de
   * conmutación en caliente (p50 en unos pocos milisegundos).
   *
   * Acepta `adminUrl` y `caddyAdminPort` opcionales (en `opts` o `spec`) para nodos
   * remotos de flota sin mutar el estado local del singleton.
   *
   * @param {any} spec
   * @param {{ adminUrl?: string | null, caddyAdminPort?: number | null }} [opts]
   */
  async upsertRoute(spec, opts = {}) {
    const t0 = process.hrtime.bigint();
    const effectiveAdminUrl = (opts && opts.adminUrl) || (spec && spec.adminUrl) || null;
    const caddyAdminPort = (opts && opts.caddyAdminPort) || (spec && spec.caddyAdminPort) || null;
    const isOverride = Boolean(effectiveAdminUrl && String(effectiveAdminUrl).trim() !== this.adminUrl);
    const targetAdminUrl = isOverride ? String(effectiveAdminUrl).trim() : null;
    const displayAdminUrl = targetAdminUrl || this.adminUrl;

    const route = this.buildRoute(spec);
    const id = route['@id'];
    const routeJson = JSON.stringify(route);

    // Caché de digest idempotente (solo para el Caddy local del singleton).
    if (!isOverride && this._appliedRouteJson.get(id) === routeJson) {
      metricsCollector.recordCaddySwap(0, true);
      return { created: false, unchanged: true, id, route };
    }

    // Fast path directo: 1 único roundtrip HTTP keep-alive sin `requireAvailable()` previo.
    let fastRes;
    try {
      fastRes = await this.adminRequest('PATCH', `/id/${id}`, {
        headers: { 'Content-Type': 'application/json' },
        body: routeJson,
        timeoutMs: 10000,
        readBody: false,
        adminUrl: targetAdminUrl,
        caddyAdminPort
      });
    } catch (netErr) {
      if (!isOverride) {
        this._appliedRouteJson.delete(id);
        this.lastDetection = { available: false, adminUrl: this.adminUrl, reason: netErr.message };
        this.detectionAt = Date.now();
      }
      const err = new Error(`Caddy no responde en ${displayAdminUrl}: ${netErr.message}`);
      /** @type {any} */ (err).code = 'CADDY_UNAVAILABLE';
      throw err;
    }

    if (fastRes.ok) {
      if (!isOverride) {
        this._appliedRouteJson.set(id, routeJson);
        const prev = this.lastDetection;
        this.lastDetection = {
          available: true,
          adminUrl: this.adminUrl,
          version: (prev && 'version' in prev ? prev.version : null) || null,
          reason: null
        };
        this.detectionAt = Date.now();
        metricsCollector.recordCaddySwap(Number(process.hrtime.bigint() - t0) / 1e6, false);
      }
      return { created: false, id, route };
    }
    if (fastRes.status !== 404 && fastRes.status !== 400) {
      if (!/unknown object ID/i.test(fastRes.text)) {
        throw new Error(`PATCH /id/${id} devolvió ${fastRes.status}: ${fastRes.text}`);
      }
    }

    // Si el fast-path indicó que no existe, insertar respetando orden de especificidad (evita que un wildcard eclipse subdominios nuevos)
    const routesPath = '/config/apps/http/servers/culkibo/routes';
    const result = await this.mutate(async () => {
      const current = await this.getWithEtag(routesPath, { adminUrl: targetAdminUrl, caddyAdminPort });
      const list = Array.isArray(current.value) ? current.value : [];
      if (list.some((r) => r && r['@id'] === id)) {
        const existing = await this.getWithEtag(`/id/${id}`, { adminUrl: targetAdminUrl, caddyAdminPort });
        if (existing.found) {
          await this.write('PATCH', `/id/${id}`, route, { etag: existing.etag, adminUrl: targetAdminUrl, caddyAdminPort });
          return { created: false, id, route };
        }
      }
      const hasWildcardExisting = list.some((r) =>
        r && typeof r['@id'] === 'string' && r['@id'].startsWith(ID_PREFIX) &&
        Array.isArray(r.match?.[0]?.host) && r.match[0].host.some((h) => String(h).startsWith('*.'))
      );
      if (hasWildcardExisting && !spec.hostnames.some((h) => String(h).startsWith('*.'))) {
        const foreign = list.filter((r) => !(r && typeof r['@id'] === 'string' && r['@id'].startsWith(ID_PREFIX)));
        const managed = list.filter((r) => r && typeof r['@id'] === 'string' && r['@id'].startsWith(ID_PREFIX));
        managed.push(route);
        managed.sort((a, b) => this.routeSpecificityRank(a) - this.routeSpecificityRank(b));
        await this.write('PATCH', routesPath, [...foreign, ...managed], { etag: current.etag, adminUrl: targetAdminUrl, caddyAdminPort });
        return { created: true, id, route };
      }
      await this.write('POST', routesPath, route, { etag: current.etag, adminUrl: targetAdminUrl, caddyAdminPort });
      return { created: true, id, route };
    });
    if (!isOverride) {
      this._appliedRouteJson.set(id, routeJson);
      this.lastKnownRouteCount = this._appliedRouteJson.size;
      metricsCollector.recordCaddySwap(Number(process.hrtime.bigint() - t0) / 1e6, false);
    }
    return result;
  }

  /**
   * Configura o actualiza una política de certificados wildcard DNS-01 multiproveedor
   * (Cloudflare, Hetzner v2, DigitalOcean, Route53, Porkbun, Bunny, DuckDNS)
   * directamente en Caddy SIN borrar otros wildcards activos.
   *
   * @param {string} rootDomain
   * @param {{
   *   provider?: string,
   *   tokenEnv?: string | null,
   *   credentialsEnv?: Record<string, string> | null,
   *   apiToken?: string | null,
   *   credentials?: Record<string, string> | null,
   *   includeApex?: boolean,
   *   acmeEmail?: string | null,
   *   adminUrl?: string | null,
   *   caddyAdminPort?: number | null
   * }} [opts]
   */
  async configureWildcardDns01(rootDomain, {
    provider = 'cloudflare',
    tokenEnv = null,
    credentialsEnv = null,
    apiToken = null,
    credentials = null,
    includeApex = true,
    acmeEmail = null,
    adminUrl = null,
    caddyAdminPort = null
  } = {}) {
    const cleanRoot = String(rootDomain || '').trim().toLowerCase().replace(/^\*\./, '');
    if (!cleanRoot || !/^[a-z0-9.-]+\.[a-z0-9-]{2,}$/.test(cleanRoot)) {
      throw new Error(`Dominio raíz inválido para wildcard DNS-01: ${rootDomain}`);
    }
    const cleanProvider = String(provider || 'cloudflare').trim().toLowerCase();
    const { providerConfig, schema, resolvedEnvMap } = buildDnsProviderConfig(cleanProvider, {
      tokenEnv,
      credentialsEnv,
      apiToken,
      credentials
    });
    await this.requireAvailable({ adminUrl, caddyAdminPort });
    const subjects = includeApex ? [`*.${cleanRoot}`, cleanRoot] : [`*.${cleanRoot}`];
    /** @type {any} */
    const acmeIssuer = {
      module: 'acme',
      challenges: {
        dns: {
          provider: providerConfig,
          resolvers: ['1.1.1.1', '8.8.8.8']
        }
      }
    };
    if (acmeEmail) acmeIssuer.email = acmeEmail;
    const policy = {
      subjects,
      issuers: [acmeIssuer]
    };
    const policiesPath = '/config/apps/tls/automation/policies';
    return this.mutate(async () => {
      const current = await this.getWithEtag(policiesPath, { adminUrl, caddyAdminPort });
      const list = Array.isArray(current.value) ? current.value : [];
      // Preserva cualquier otro wildcard incluso si existía una política agrupada previa
      const nextExisting = [];
      for (const p of list) {
        if (!p || !Array.isArray(p.subjects)) {
          nextExisting.push(p);
          continue;
        }
        const remaining = p.subjects.filter((s) => s !== `*.${cleanRoot}` && (!includeApex || s !== cleanRoot));
        if (remaining.length > 0) {
          nextExisting.push(remaining.length === p.subjects.length ? p : { ...p, subjects: remaining });
        }
      }
      const next = [policy, ...nextExisting];
      await this.write(current.found ? 'PATCH' : 'PUT', policiesPath, next, { etag: current.etag, adminUrl, caddyAdminPort });
      return {
        applied: true,
        subjects,
        provider: cleanProvider,
        caddyModule: schema.caddyModule,
        tokenEnv: resolvedEnvMap[schema.primaryField] || null,
        credentialsEnv: resolvedEnvMap
      };
    });
  }

  /** Elimina una política wildcard específica preservando las demás y la política on_demand. */
  async removeWildcardDns01(rootDomain, { adminUrl = null, caddyAdminPort = null } = {}) {
    const cleanRoot = String(rootDomain || '').trim().toLowerCase().replace(/^\*\./, '');
    if (!cleanRoot) return { removed: false };
    await this.requireAvailable({ adminUrl, caddyAdminPort });
    const policiesPath = '/config/apps/tls/automation/policies';
    return this.mutate(async () => {
      const current = await this.getWithEtag(policiesPath, { adminUrl, caddyAdminPort });
      const list = Array.isArray(current.value) ? current.value : [];
      let changed = false;
      const next = [];
      for (const p of list) {
        if (!p || !Array.isArray(p.subjects)) {
          next.push(p);
          continue;
        }
        const remaining = p.subjects.filter((s) => s !== `*.${cleanRoot}` && s !== cleanRoot);
        if (remaining.length !== p.subjects.length) changed = true;
        if (remaining.length > 0) {
          next.push(remaining.length === p.subjects.length ? p : { ...p, subjects: remaining });
        }
      }
      if (!changed) return { removed: false };
      await this.write('PATCH', policiesPath, next, { etag: current.etag, adminUrl, caddyAdminPort });
      return { removed: true, rootDomain: cleanRoot };
    });
  }

  /**
   * Reconcilia `/config/apps/tls` completo (múltiples wildcards DNS-01 multiproveedor +
   * certificados propios `load_files` + `on_demand` con respaldo ZeroSSL).
   * Si el binario de Caddy no incluye alguno de los módulos `dns.providers.<x>`, degrada
   * de forma segura aplicando los certificados propios y `on_demand` sin romper HTTP.
   *
   * @param {any} tlsOpts
   * @param {{ adminUrl?: string | null, caddyAdminPort?: number | null }} [adminOpts]
   */
  async reconcileTls(tlsOpts, { adminUrl = null, caddyAdminPort = null } = {}) {
    await this.requireAvailable({ adminUrl, caddyAdminPort });
    /** @type {Array<{ scope: string, subject: string, provider?: string | null, error: string }>} */
    const isolatedPolicies = [];
    const inputWildcards = Array.isArray(tlsOpts.wildcardPolicies) ? [...tlsOpts.wildcardPolicies] : [];
    const inputWildcardDomains = Array.isArray(tlsOpts.wildcardDomains) ? [...tlsOpts.wildcardDomains] : [];

    // kamal-proxy#233: aislar políticas TLS inválidas por dominio para que 1 certificado roto jamás borre ni bloquee rutas sanas
    const initialTls = this.buildTlsApp({
      ...tlsOpts,
      wildcardPolicies: inputWildcards,
      wildcardDomains: inputWildcardDomains,
      isolateInvalid: true,
      isolatedErrors: isolatedPolicies
    });

    const appliedValidWildcardCount = (tlsObj) =>
      (tlsObj.automation?.policies || []).filter((p) => Array.isArray(p.subjects) && p.subjects.length > 0).length;

    const tryApplyTls = async (tlsObj) => {
      const current = await this.getWithEtag('/config/apps/tls', { adminUrl, caddyAdminPort });
      if (current.found && JSON.stringify(current.value) === JSON.stringify(tlsObj)) {
        return { unchanged: true };
      }
      await this.write(current.found ? 'PATCH' : 'PUT', '/config/apps/tls', tlsObj, { etag: current.etag, adminUrl, caddyAdminPort });
      return { unchanged: false };
    };

    try {
      const res = await tryApplyTls(initialTls);
      return {
        applied: true,
        unchanged: res.unchanged,
        partial: isolatedPolicies.length > 0,
        wildcardCount: appliedValidWildcardCount(initialTls),
        isolatedPolicies
      };
    } catch (err) {
      const msg = String(err.message || '');
      const providerMatch = msg.match(/dns\.providers\.([a-z0-9_-]+)/i);
      const missingPlugin = Boolean(providerMatch || /module not registered/i.test(msg));
      if (missingPlugin && (inputWildcards.length > 0 || inputWildcardDomains.length > 0)) {
        /** @type {Set<string>} */
        const missingSet = new Set();
        let remainingPolicies = [...inputWildcards];
        let remainingDomains = [...inputWildcardDomains];
        let lastErrMsg = msg;

        // Retirar quirúrgicamente SOLO el proveedor ausente en cada iteración conservando el resto de dominios sanos
        const maxPasses = Object.keys(DNS_PROVIDERS).length + 1;
        for (let pass = 0; pass < maxPasses; pass++) {
          const m = lastErrMsg.match(/dns\.providers\.([a-z0-9_-]+)/i);
          if (m) {
            const badProv = m[1].toLowerCase();
            missingSet.add(badProv);
            const stripped = remainingPolicies.filter((p) => String(p?.provider || 'cloudflare').trim().toLowerCase() === badProv);
            for (const sp of stripped) {
              isolatedPolicies.push({
                scope: 'wildcard_policy',
                subject: sp?.rootDomain ? `*.${String(sp.rootDomain).replace(/^\*\./, '')}` : '(unknown)',
                provider: badProv,
                error: `Módulo Caddy no instalado: dns.providers.${badProv}`
              });
            }
            remainingPolicies = remainingPolicies.filter((p) => String(p?.provider || 'cloudflare').trim().toLowerCase() !== badProv);
            if (badProv === 'cloudflare') remainingDomains = [];
          } else {
            for (const p of remainingPolicies) {
              missingSet.add(String(p?.provider || 'cloudflare').trim().toLowerCase());
            }
            remainingPolicies = [];
            remainingDomains = [];
          }

          const candidateTls = this.buildTlsApp({
            ...tlsOpts,
            wildcardPolicies: remainingPolicies,
            wildcardDomains: remainingDomains,
            isolateInvalid: true
          });
          try {
            await tryApplyTls(candidateTls);
            const missingProviders = Array.from(missingSet);
            const xcaddyHints = missingProviders
              .map((id) => DNS_PROVIDERS[id]?.xcaddyModule || `github.com/caddy-dns/${id}`)
              .map((mod) => `--with ${mod}`)
              .join(' ');
            const survivingCount = appliedValidWildcardCount(candidateTls);
            return {
              applied: survivingCount > 0,
              partial: survivingCount > 0,
              degraded: true,
              wildcardCount: survivingCount,
              isolatedPolicies,
              missingDnsProviders: missingProviders,
              missingCloudflarePlugin: missingProviders.includes('cloudflare'),
              error: `Tu binario actual de Caddy no incluye el módulo DNS-01 (${missingProviders.map((p) => `dns.providers.${p}`).join(', ')}). Compila Caddy con: xcaddy build ${xcaddyHints}`
            };
          } catch (retryErr) {
            lastErrMsg = String(retryErr && retryErr.message ? retryErr.message : retryErr);
            if (!/dns\.providers\.|module not registered/i.test(lastErrMsg) || (remainingPolicies.length === 0 && remainingDomains.length === 0)) {
              break;
            }
          }
        }

        const missingProviders = Array.from(missingSet);
        const xcaddyHints = missingProviders
          .map((id) => DNS_PROVIDERS[id]?.xcaddyModule || `github.com/caddy-dns/${id}`)
          .map((mod) => `--with ${mod}`)
          .join(' ');
        return {
          applied: false,
          degraded: true,
          wildcardCount: 0,
          isolatedPolicies,
          missingDnsProviders: missingProviders,
          missingCloudflarePlugin: missingProviders.includes('cloudflare'),
          error: `Tu binario actual de Caddy no incluye el módulo DNS-01 (${missingProviders.map((p) => `dns.providers.${p}`).join(', ')}). Compila Caddy con: xcaddy build ${xcaddyHints}`
        };
      }
      throw err;
    }
  }

  /**
   * Comprueba de forma honesta el estado real de HTTP/3 (QUIC) en el Caddy activo:
   * inspecciona `protocols`, `listen`, `automatic_https` en la Admin API y, si Caddy
   * corre en Docker en modo bridge, verifica si el puerto UDP 443 está realmente publicado.
   *
   * @param {{ adminUrl?: string | null, caddyAdminPort?: number | null, checkDockerUdp?: boolean }} [opts]
   */
  async probeHttp3({ adminUrl = null, caddyAdminPort = null, checkDockerUdp = true } = {}) {
    const isOverride = Boolean(adminUrl && String(adminUrl).trim() !== this.adminUrl);
    /** @type {{ supported: boolean, configured: boolean, protocols: string[], automaticHttpsDisabled: boolean, udp443Published: boolean | null, listen: string[], reason: string | null }} */
    const out = {
      supported: false,
      configured: false,
      protocols: [],
      automaticHttpsDisabled: false,
      udp443Published: null,
      listen: [],
      reason: null
    };

    try {
      const server = await this.get('/config/apps/http/servers/culkibo', { adminUrl, caddyAdminPort });
      if (!server || typeof server !== 'object') {
        out.reason = 'Servidor HTTP culkibo no configurado en Caddy';
        return out;
      }
      out.listen = Array.isArray(server.listen) ? server.listen.map(String) : [];
      out.automaticHttpsDisabled = Boolean(server.automatic_https && server.automatic_https.disable === true);
      // En Caddy v2, si `protocols` se omite, el valor por defecto incluye h1, h2 y h3 (cuando HTTPS está activo)
      out.protocols = Array.isArray(server.protocols)
        ? server.protocols.map((p) => String(p).toLowerCase())
        : (out.automaticHttpsDisabled ? ['h1', 'h2'] : ['h1', 'h2', 'h3']);
      out.configured = out.protocols.includes('h3') && !out.automaticHttpsDisabled;

      if (!out.configured) {
        out.reason = out.automaticHttpsDisabled
          ? 'automatic_https está desactivado: HTTP/3 (QUIC) requiere TLS activo'
          : `El servidor no incluye "h3" en protocols (${out.protocols.join(', ')})`;
        return out;
      }

      if (!isOverride && checkDockerUdp && this.isContainerized) {
        const udpOut = await new Promise((resolve) => {
          try {
            const child = spawn('docker', ['port', this.containerName, '443/udp'], { shell: false, windowsHide: true });
            let stdout = '';
            const t = setTimeout(() => { try { child.kill(); } catch (e) {} resolve(null); }, 1500);
            if (t.unref) t.unref();
            child.stdout.on('data', (d) => { stdout += d.toString('utf8'); });
            child.on('error', () => { clearTimeout(t); resolve(null); });
            child.on('close', (code) => { clearTimeout(t); resolve(code === 0 ? stdout.trim() : ''); });
          } catch (e) {
            resolve(null);
          }
        });
        if (udpOut !== null) {
          out.udp443Published = Boolean(udpOut && udpOut.length > 0);
        }
      }

      out.supported = out.configured && out.udp443Published !== false;
      if (!out.supported) {
        out.reason = 'HTTP/3 está configurado en Caddy pero el puerto 443/udp no está publicado en Docker';
      }
      return out;
    } catch (err) {
      out.reason = err.message;
      return out;
    }
  }

  /** Detecta capacidades reales del Caddy activo (módulos DNS-01 multiproveedor, rate_limit, HTTP/3, tokens). */
  async probeCapabilities({ force = false } = {}) {
    const now = Date.now();
    if (!force && this._capabilitiesCache && (now - this._capabilitiesCache.checkedAt) < 30000) {
      return this._capabilitiesCache.data;
    }
    const detection = await this.detect({ force });
    /** @type {{
     *   available: boolean,
     *   version: string | null,
     *   hasCloudflareDnsPlugin: boolean | null,
     *   installedDnsProviders: string[],
     *   supportedDnsProviders: string[],
     *   hasRateLimitPlugin: boolean | null,
     *   hasCfTokenEnv: boolean,
     *   http3: any,
     *   containerized: boolean,
     *   containerName: string
     * }} */
    const caps = {
      available: detection.available,
      version: detection.version || null,
      hasCloudflareDnsPlugin: null,
      installedDnsProviders: [],
      supportedDnsProviders: Object.keys(DNS_PROVIDERS),
      hasRateLimitPlugin: null,
      hasCfTokenEnv: Boolean(process.env.CF_API_TOKEN || process.env.CLOUDFLARE_API_TOKEN),
      http3: null,
      containerized: this.isContainerized,
      containerName: this.containerName
    };

    const runListModules = (bin, args) => new Promise((resolve) => {
      try {
        const child = spawn(bin, args, { shell: false, windowsHide: true });
        let out = '';
        const timer = setTimeout(() => { try { child.kill(); } catch (e) {} resolve(null); }, 2500);
        if (timer.unref) timer.unref();
        child.stdout.on('data', (d) => { out += d.toString('utf8'); });
        child.on('error', () => { clearTimeout(timer); resolve(null); });
        child.on('close', (code) => { clearTimeout(timer); resolve(code === 0 ? out : null); });
      } catch (e) {
        resolve(null);
      }
    });

    if (detection.available) {
      let modulesOut = await runListModules('docker', ['exec', this.containerName, 'caddy', 'list-modules']);
      if (modulesOut !== null) {
        caps.containerized = true;
        if (!caps.hasCfTokenEnv) {
          const cfEnvVal = await runListModules('docker', ['exec', this.containerName, 'printenv', 'CF_API_TOKEN']);
          if (cfEnvVal && cfEnvVal.trim()) caps.hasCfTokenEnv = true;
        }
      } else {
        modulesOut = await runListModules('caddy', ['list-modules']);
      }
      if (modulesOut !== null) {
        caps.installedDnsProviders = Object.values(DNS_PROVIDERS)
          .filter((p) => modulesOut.includes(p.caddyModule))
          .map((p) => p.id);
        caps.hasCloudflareDnsPlugin = caps.installedDnsProviders.includes('cloudflare');
        caps.hasRateLimitPlugin = modulesOut.includes('http.handlers.rate_limit');
      }
      caps.http3 = await this.probeHttp3({ checkDockerUdp: caps.containerized }).catch(() => null);
    }

    this._capabilitiesCache = { checkedAt: now, data: caps };
    return caps;
  }

  /**
   * Elimina la ruta de un proyecto en 1 RTT. Idempotente.
   * Acepta `adminUrl` y `caddyAdminPort` opcionales para nodos remotos sin mutar el singleton local.
   * @param {string} projectId
   * @param {{ adminUrl?: string | null, caddyAdminPort?: number | null }} [opts]
   */
  async removeRoute(projectId, { adminUrl = null, caddyAdminPort = null } = {}) {
    const id = this.routeId(projectId);
    const isOverride = Boolean(adminUrl && String(adminUrl).trim() !== this.adminUrl);
    const targetAdminUrl = isOverride ? String(adminUrl).trim() : null;
    const displayAdminUrl = targetAdminUrl || this.adminUrl;
    if (!isOverride) {
      this._appliedRouteJson.delete(id);
    }
    let res;
    try {
      res = await this.adminRequest('DELETE', `/id/${id}`, {
        timeoutMs: 10000,
        readBody: false,
        adminUrl: targetAdminUrl,
        caddyAdminPort
      });
    } catch (netErr) {
      if (!isOverride) {
        this.lastDetection = { available: false, adminUrl: this.adminUrl, reason: netErr.message };
        this.detectionAt = Date.now();
      }
      const err = new Error(`Caddy no responde en ${displayAdminUrl}: ${netErr.message}`);
      /** @type {any} */ (err).code = 'CADDY_UNAVAILABLE';
      throw err;
    }
    if (res.ok) {
      if (!isOverride) this.lastKnownRouteCount = this._appliedRouteJson.size;
      return { removed: true, id };
    }
    if (res.status === 404 || /unknown object ID/i.test(res.text)) {
      return { removed: false, id };
    }
    throw new Error(`DELETE /id/${id} devolvió ${res.status}: ${res.text}`);
  }

  /**
   * Rutas que gestiona Culkibo, ignorando las que haya puesto otro (como `sys_encode`).
   * @param {{ adminUrl?: string | null, caddyAdminPort?: number | null }} [opts]
   */
  async listRoutes({ adminUrl = null, caddyAdminPort = null } = {}) {
    const isOverride = Boolean(adminUrl && String(adminUrl).trim() !== this.adminUrl);
    const routes = await this.get('/config/apps/http/servers/culkibo/routes', {
      adminUrl: isOverride ? String(adminUrl).trim() : null,
      caddyAdminPort
    });
    if (!Array.isArray(routes)) {
      if (!isOverride) this.lastKnownRouteCount = 0;
      return [];
    }
    const managed = routes.filter(r => typeof r['@id'] === 'string' && r['@id'].startsWith(ID_PREFIX));
    if (!isOverride) this.lastKnownRouteCount = managed.length;
    return managed;
  }

  /**
   * Alta/actualización en lote (1 único PATCH con ETag en vez de N recargas).
   * Preserva todas las demás rutas existentes (propias y ajenas).
   * @param {any[]} specs
   * @param {{ adminUrl?: string | null, caddyAdminPort?: number | null }} [opts]
   */
  async upsertRoutesBatch(specs, { adminUrl = null, caddyAdminPort = null } = {}) {
    if (!Array.isArray(specs) || specs.length === 0) {
      return { applied: [], unchanged: true };
    }
    const isOverride = Boolean(adminUrl && String(adminUrl).trim() !== this.adminUrl);
    const targetAdminUrl = isOverride ? String(adminUrl).trim() : null;
    await this.requireAvailable({ adminUrl: targetAdminUrl, caddyAdminPort });
    const sorted = [...specs].sort((a, b) => this.routeSpecificityRank(a) - this.routeSpecificityRank(b));
    const batchMap = new Map();
    for (const s of sorted) {
      const r = this.buildRoute(s);
      batchMap.set(r['@id'], { spec: s, route: r, json: JSON.stringify(r) });
    }
    const routesPath = '/config/apps/http/servers/culkibo/routes';

    return this.mutate(async () => {
      const current = await this.getWithEtag(routesPath, { adminUrl: targetAdminUrl, caddyAdminPort });
      const existingAll = Array.isArray(current.value) ? current.value : [];
      const foreign = existingAll.filter((r) => !(r && typeof r['@id'] === 'string' && r['@id'].startsWith(ID_PREFIX)));
      const keptManaged = existingAll.filter((r) => r && typeof r['@id'] === 'string' && r['@id'].startsWith(ID_PREFIX) && !batchMap.has(r['@id']));
      const combinedManaged = [...keptManaged, ...Array.from(batchMap.values()).map((x) => x.route)];
      combinedManaged.sort((a, b) => this.routeSpecificityRank(a) - this.routeSpecificityRank(b));
      const nextRoutes = [...foreign, ...combinedManaged];
      if (JSON.stringify(existingAll) === JSON.stringify(nextRoutes)) {
        if (!isOverride) {
          for (const [id, entry] of batchMap.entries()) this._appliedRouteJson.set(id, entry.json);
        }
        return { applied: Array.from(batchMap.keys()), unchanged: true };
      }
      await this.write(current.found ? 'PATCH' : 'PUT', routesPath, nextRoutes, { etag: current.etag, adminUrl: targetAdminUrl, caddyAdminPort });
      if (!isOverride) {
        for (const [id, entry] of batchMap.entries()) this._appliedRouteJson.set(id, entry.json);
        this.lastKnownRouteCount = combinedManaged.length;
      }
      return { applied: Array.from(batchMap.keys()), unchanged: false };
    });
  }

  /**
   * Reconciliación atómica por diff en un único PUT/PATCH (en lugar de N+M recargas).
   * Ordena rutas por especificidad para que ningún comodín eclipse subdominios exactos.
   * kamal-proxy#233: cuando `isolateInvalid !== false`, una ruta individual malformada
   * se aísla en `skippedInvalid` sin tumbar ni borrar el resto de rutas sanas.
   * @param {any[]} desiredSpecs
   * @param {{ adminUrl?: string | null, caddyAdminPort?: number | null, isolateInvalid?: boolean }} [opts]
   */
  async reconcile(desiredSpecs, { adminUrl = null, caddyAdminPort = null, isolateInvalid = true } = {}) {
    const isOverride = Boolean(adminUrl && String(adminUrl).trim() !== this.adminUrl);
    const targetAdminUrl = isOverride ? String(adminUrl).trim() : null;
    await this.requireAvailable({ adminUrl: targetAdminUrl, caddyAdminPort });
    const sortedSpecs = [...desiredSpecs].sort((a, b) => this.routeSpecificityRank(a) - this.routeSpecificityRank(b));
    /** @type {Array<{ id: string, route: any, json: string }>} */
    const built = [];
    /** @type {Array<{ projectId: string | null, hostnames: any, error: string }>} */
    const skippedInvalid = [];
    for (const spec of sortedSpecs) {
      try {
        const route = this.buildRoute(spec);
        built.push({ id: route['@id'], route, json: JSON.stringify(route) });
      } catch (err) {
        if (!isolateInvalid) throw err;
        skippedInvalid.push({
          projectId: spec && spec.projectId ? String(spec.projectId) : null,
          hostnames: spec && spec.hostnames ? spec.hostnames : [],
          error: err && err.message ? err.message : String(err)
        });
      }
    }
    const desiredRoutes = built.map((b) => b.route);
    const desiredIds = new Set(built.map((b) => b.id));
    const routesPath = '/config/apps/http/servers/culkibo/routes';

    return this.mutate(async () => {
      const current = await this.getWithEtag(routesPath, { adminUrl: targetAdminUrl, caddyAdminPort });
      const existingAll = Array.isArray(current.value) ? current.value : [];
      const foreign = existingAll.filter((r) => !(r && typeof r['@id'] === 'string' && r['@id'].startsWith(ID_PREFIX)));
      const existingCulkibo = existingAll.filter((r) => r && typeof r['@id'] === 'string' && r['@id'].startsWith(ID_PREFIX));

      const removed = existingCulkibo
        .filter((r) => !desiredIds.has(r['@id']))
        .map((r) => r['@id']);
      const applied = built.map((b) => b.id);

      const nextRoutes = [...foreign, ...desiredRoutes];
      if (JSON.stringify(existingAll) === JSON.stringify(nextRoutes)) {
        if (!isOverride) {
          this._appliedRouteJson.clear();
          for (const b of built) this._appliedRouteJson.set(b.id, b.json);
          this.lastKnownRouteCount = desiredRoutes.length;
        }
        return { applied, removed, skippedInvalid, unchanged: true };
      }

      await this.write(current.found ? 'PATCH' : 'PUT', routesPath, nextRoutes, { etag: current.etag, adminUrl: targetAdminUrl, caddyAdminPort });
      if (!isOverride) {
        this._appliedRouteJson.clear();
        for (const b of built) this._appliedRouteJson.set(b.id, b.json);
        this.lastKnownRouteCount = desiredRoutes.length;
      }
      return { applied, removed, skippedInvalid, unchanged: false };
    });
  }

  // ---------------------------------------------------------------------
  // Arranque de Caddy
  // ---------------------------------------------------------------------

  /**
   * Levanta Caddy en un contenedor (con validación estricta anti inyección de flags).
   * Por defecto usa `network: 'host'` en Linux VPS y puente con HTTP/3 (443/udp) +
   * `CADDY_ADMIN=0.0.0.0:2019` en Desktop.
   */
  async startWithDocker({
    image = '',
    containerName = 'culkibo-caddy',
    httpPort = 80,
    httpsPort = 443,
    adminPort = 2019,
    network = null,
    cfApiToken = null
  } = {}) {
    let cleanImage = String(image || '').trim();
    if (!cleanImage) {
      // Si el usuario construyó la imagen local con Cloudflare DNS-01 + ratelimit, preferirla automáticamente
      const hasCustomImg = await new Promise((resolve) => {
        try {
          const probe = spawn('docker', ['image', 'inspect', 'culkibo-caddy:cloudflare'], { shell: false, windowsHide: true });
          const t = setTimeout(() => { try { probe.kill(); } catch (e) {} resolve(false); }, 2000);
          if (t.unref) t.unref();
          probe.on('error', () => { clearTimeout(t); resolve(false); });
          probe.on('close', (c) => { clearTimeout(t); resolve(c === 0); });
        } catch (e) { resolve(false); }
      });
      cleanImage = hasCustomImg ? 'culkibo-caddy:cloudflare' : 'caddy:2.11-alpine';
    }
    const cleanName = String(containerName || 'culkibo-caddy').trim();
    const pHttp = Number(httpPort);
    const pHttps = Number(httpsPort);
    const pAdmin = Number(adminPort);
    const resolvedNetwork = network || (process.platform === 'linux' ? 'host' : 'bridge');
    const useHostNet = resolvedNetwork === 'host' && process.platform === 'linux';

    if (
      cleanImage.startsWith('-') ||
      !/^(?:caddy(?::[a-zA-Z0-9._-]+)?|culkibo-caddy(?::[a-zA-Z0-9._-]+)?|(?:ghcr\.io|docker\.io)\/[a-z0-9._-]+\/caddy(?:-[a-z0-9._-]+)?:[a-zA-Z0-9._-]+)$/.test(cleanImage)
    ) {
      throw new Error(`Imagen de Caddy no permitida: ${cleanImage}`);
    }
    if (cleanName.startsWith('-') || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/.test(cleanName)) {
      throw new Error(`Nombre de contenedor inválido: ${cleanName}`);
    }
    /** @type {Array<[string, number]>} */
    const portChecks = [['httpPort', pHttp], ['httpsPort', pHttps], ['adminPort', pAdmin]];
    for (const [label, p] of portChecks) {
      if (!Number.isInteger(p) || p < 1 || p > 65535) {
        throw new Error(`Puerto inválido (${label}): ${p}`);
      }
    }

    const certsHostDir = path.join(__dirname, '..', '..', 'data', 'certs');
    try { fs.mkdirSync(certsHostDir, { recursive: true }); } catch (e) {}

    /** @type {string | null} */
    let envFile = null;
    const effectiveCfToken = String(cfApiToken || process.env.CF_API_TOKEN || process.env.CLOUDFLARE_API_TOKEN || '').trim();
    if (effectiveCfToken && !/[\r\n\0]/.test(effectiveCfToken)) {
      const tmpDir = path.join(__dirname, '..', '..', 'data', '.tmp');
      try {
        fs.mkdirSync(tmpDir, { recursive: true, mode: 0o700 });
        envFile = path.join(tmpDir, `caddy-env-${crypto.randomBytes(8).toString('hex')}.env`);
        fs.writeFileSync(envFile, `CF_API_TOKEN=${effectiveCfToken}\n`, { mode: 0o600 });
      } catch (e) {
        envFile = null;
      }
    }

    const args = [
      'run', '-d',
      '--name', cleanName,
      '--restart', 'unless-stopped',
      '--log-driver', 'json-file',
      '--log-opt', 'max-size=10m',
      '--log-opt', 'max-file=3',
      '--label', 'culkibo.managed=true'
    ];
    if (envFile) {
      args.push('--env-file', envFile);
    }
    if (useHostNet) {
      args.push('--network', 'host', '-e', `CADDY_ADMIN=127.0.0.1:${pAdmin}`);
    } else {
      args.push(
        '-p', `${pHttp}:80`,
        '-p', `${pHttps}:443`,
        '-p', `${pHttps}:443/udp`,
        '-p', `127.0.0.1:${pAdmin}:2019`,
        '--add-host', 'host.docker.internal:host-gateway',
        '-e', 'CADDY_ADMIN=0.0.0.0:2019'
      );
    }
    args.push(
      '-v', 'culkibo_caddy_data:/data',
      '-v', 'culkibo_caddy_config:/config',
      '-v', `${certsHostDir}:/etc/culkibo-certs:ro`,
      cleanImage,
      'caddy', 'run', '--resume', '--config', '/dev/null', '--adapter', 'caddyfile'
    );

    return new Promise((resolve) => {
      const child = spawn('docker', args, { shell: false, windowsHide: true });
      const stderr = [];
      child.stderr.on('data', d => stderr.push(d.toString()));
      const cleanupEnv = () => {
        if (envFile) { try { fs.unlinkSync(envFile); } catch (e) {} }
      };
      child.on('error', (err) => {
        cleanupEnv();
        resolve({ started: false, error: err.message });
      });
      child.on('close', (code) => {
        cleanupEnv();
        if (code === 0) {
          this.isContainerized = !useHostNet;
          this.containerName = cleanName;
          this._capabilitiesCache = null;
          return resolve({ started: true, containerName: cleanName, network: useHostNet ? 'host' : 'bridge', http3: true, udp443Mapped: !useHostNet });
        }
        resolve({ started: false, error: stderr.join('').trim() || `docker run terminó con código ${code}` });
      });
    });
  }
}

const caddyManagerInstance = Object.assign(new CaddyManager(), {
  CaddyManager,
  DNS_PROVIDERS,
  listDnsProviders,
  buildDnsProviderConfig,
  validateSafeRedirectRegex,
  sanitizeUpstreamDial,
  validateCorsOrigin,
  formatEarlyHintsLinks
});
module.exports = caddyManagerInstance;
