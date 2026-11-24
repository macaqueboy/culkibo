const { spawn } = require('child_process');
const crypto = require('crypto');
const http = require('http');
const fs = require('fs');
const path = require('path');
const metricsCollector = require('./metricsCollector');

/** @type {typeof import('https') | null} */
let _httpsMod = null;
function getHttps() {
  if (!_httpsMod) _httpsMod = require('https');
  return _httpsMod;
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

  _getAdminTarget() {
    if (this._parsedAdmin && this._parsedAdmin.url === this.adminUrl) {
      return this._parsedAdmin;
    }
    const parsed = new URL(this.adminUrl);
    const isHttps = parsed.protocol === 'https:';
    const port = parsed.port ? Number(parsed.port) : (isHttps ? 443 : 80);
    // Evita DNS/Happy-Eyeballs ::1 vs 127.0.0.1 en Windows cuando adminUrl usa localhost
    const dialHost = parsed.hostname === 'localhost' ? '127.0.0.1' : parsed.hostname;
    this._parsedAdmin = {
      url: this.adminUrl,
      dialHost,
      originHeader: this.adminUrl.replace(/\/+$/, ''),
      hostHeader: parsed.host,
      port,
      isHttps
    };
    return this._parsedAdmin;
  }

  /**
   * Petición HTTP persistente contra la Admin API de Caddy con keep-alive real,
   * `TCP_NODELAY` a nivel de agente y drenaje garantizado del cuerpo.
   *
   * @param {string} method
   * @param {string} reqPath
   * @param {{ headers?: Record<string, string>, body?: string | null, timeoutMs?: number, readBody?: boolean }} [opts]
   * @returns {Promise<{ status: number, ok: boolean, headers: Record<string, any>, text: string }>}
   */
  adminRequest(method, reqPath, { headers = {}, body = null, timeoutMs = 10000, readBody = true } = {}) {
    return new Promise((resolve, reject) => {
      const admin = this._getAdminTarget();
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
          agent: admin.isHttps ? this.getHttpsAgent() : this.httpAgent
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
   */
  async detect({ force = false } = {}) {
    const now = Date.now();
    if (!force && this.lastDetection && (now - this.detectionAt) < this.detectionTtlMs) {
      return this.lastDetection;
    }

    /** @type {{ available: boolean, adminUrl: string, version: string | null, reason: string | null }} */
    let result = { available: false, adminUrl: this.adminUrl, version: null, reason: null };
    try {
      const res = await this.adminRequest('GET', '/reverse_proxy/upstreams', { timeoutMs: 2000, readBody: false });
      if (res.ok) {
        result = { available: true, adminUrl: this.adminUrl, version: 'activo', reason: null };
      } else {
        // Algunos Caddy recién arrancados sin server http responden 404 a /reverse_proxy/upstreams pero 200 a /config/
        const cfgRes = await this.adminRequest('GET', '/config/', { timeoutMs: 2000, readBody: false });
        if (cfgRes.ok) {
          result = { available: true, adminUrl: this.adminUrl, version: 'activo', reason: null };
        } else {
          result.reason = `La API de administración respondió ${cfgRes.status}`;
        }
      }
    } catch (err) {
      result.reason = `No hay ninguna API de administración de Caddy en ${this.adminUrl}`;
    }

    const wasAvailable = Boolean(this.lastDetection && this.lastDetection.available);
    this.lastDetection = result;
    this.detectionAt = now;
    // P0-4: si Caddy se cayó y volvió a arrancar, invalidar caché local de rutas aplicadas
    if (!wasAvailable && result.available) {
      this._appliedRouteJson.clear();
    }
    return result;
  }

  async readVersion() {
    try {
      const res = await this.adminRequest('GET', '/reverse_proxy/upstreams', { timeoutMs: 1500, readBody: false });
      return res.ok ? 'activo' : null;
    } catch (e) {
      return null;
    }
  }

  async requireAvailable() {
    const detection = await this.detect();
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

  async getWithEtag(reqPath) {
    const res = await this.adminRequest('GET', reqPath, { timeoutMs: 5000, readBody: true });
    if (res.status === 404 || (res.status === 400 && /invalid traversal path/i.test(res.text || ''))) {
      return { found: false, value: null, etag: null };
    }
    if (!res.ok) throw new Error(`GET ${reqPath} devolvió ${res.status}: ${res.text}`);
    const etag = res.headers.etag || null;
    return { found: true, value: res.text ? JSON.parse(res.text) : null, etag };
  }

  async get(reqPath) {
    return (await this.getWithEtag(reqPath)).value;
  }

  /**
   * @param {string} method
   * @param {string} reqPath
   * @param {any} body
   * @param {{ etag?: string | null, retries?: number }} [opts]
   */
  async write(method, reqPath, body, { etag = null, retries = 3 } = {}) {
    for (let attempt = 0; attempt <= retries; attempt++) {
      /** @type {Record<string, string>} */
      const headers = { 'Content-Type': 'application/json' };
      if (etag) headers['If-Match'] = etag;

      const res = await this.adminRequest(method, reqPath, {
        headers,
        body: body === undefined ? null : JSON.stringify(body),
        timeoutMs: 10000,
        readBody: false
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
   *   customCertFiles?: Array<{ certificate: string, key: string, tags?: string[] }>
   * }} [opts]
   */
  buildTlsApp({
    askEndpoint = '',
    wildcardDomains = [],
    wildcardPolicies = [],
    cloudflareDnsTokenEnv = 'CF_API_TOKEN',
    acmeEmail = null,
    customCertFiles = []
  } = {}) {
    /** @type {any[]} */
    const policies = [];
    /** @type {Set<string>} */
    const seenRoots = new Set();

    /** @param {{ rootDomain: string, tokenEnv?: string, apiToken?: string | null, includeApex?: boolean }} pol */
    const pushWildcardPolicy = (pol) => {
      const cleanRoot = String(pol.rootDomain || '').trim().toLowerCase().replace(/^\*\./, '');
      if (!cleanRoot || seenRoots.has(cleanRoot)) return;
      seenRoots.add(cleanRoot);

      const cleanEnv = String(pol.tokenEnv || cloudflareDnsTokenEnv || 'CF_API_TOKEN').trim();
      const apiTokenExpr = pol.apiToken ? String(pol.apiToken) : `{env.${cleanEnv}}`;
      const subjects = pol.includeApex === false ? [`*.${cleanRoot}`] : [`*.${cleanRoot}`, cleanRoot];

      /** @type {any} */
      const acmeIssuer = {
        module: 'acme',
        challenges: {
          dns: {
            provider: {
              name: 'cloudflare',
              api_token: apiTokenExpr
            },
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
        if (wp && wp.enabled !== false && wp.rootDomain) {
          pushWildcardPolicy(wp);
        }
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

    const validCerts = Array.isArray(customCertFiles)
      ? customCertFiles.filter((c) => c && c.certificate && c.key)
      : [];
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
   *   containerized?: boolean | null
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
    containerized = null
  }) {
    const tlsApp = this.buildTlsApp({
      askEndpoint,
      wildcardDomains,
      wildcardPolicies,
      cloudflareDnsTokenEnv,
      acmeEmail,
      customCertFiles
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
          // Ventana de drenaje real en recargas de configuración (10 s). En
          // Linux (SO_REUSEPORT) garantiza cero peticiones cortadas al cambiar
          // de upstream.
          grace_period: 10000000000,
          servers: {
            culkibo: culkiboServer
          }
        },
        tls: tlsApp
      }
    };
  }

  /** Carga la configuración base completa. Sobrescribe lo que hubiera. */
  async loadBaseConfig(options) {
    await this.requireAvailable();
    const config = this.buildBaseConfig(options);
    const res = await this.adminRequest('POST', '/load', {
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
      timeoutMs: 15000,
      readBody: false
    });
    if (!res.ok) throw new Error(`No se pudo cargar la configuración base: ${res.status} ${res.text}`);
    this._appliedRouteJson.clear();
    this.lastKnownRouteCount = 0;
    return config;
  }

  // ---------------------------------------------------------------------
  // Rutas
  // ---------------------------------------------------------------------

  routeId(projectId) {
    return `${ID_PREFIX}${String(projectId).replace(/[^a-zA-Z0-9_-]/g, '')}`;
  }

  /**
   * Orden determinista por especificidad para evitar que una ruta comodín
   * (`*.empresa.com`) capture tráfico de un subdominio exacto (`tienda.empresa.com`).
   *
   * 0: redirecciones exactas (www -> apex / apex -> www)
   * 1: modo mantenimiento exacto
   * 2: rutas con hostnames exactos
   * 3: comodines ordenados por sufijo más largo primero (`*.sub.a.com` antes que `*.a.com`)
   */
  routeSpecificityRank(spec) {
    const hosts = Array.isArray(spec.hostnames) ? spec.hostnames : [];
    const hasWildcard = hosts.some((h) => String(h).startsWith('*.'));
    if (!hasWildcard) {
      if (spec.kind === 'redirect') return 0;
      if (spec.kind === 'maintenance') return 1;
      return 2;
    }
    const maxLen = Math.max(...hosts.map((h) => String(h).length), 0);
    return 1000 - Math.min(900, maxLen);
  }

  /** Extrae el handler `reverse_proxy` de una ruta (aunque tenga auth, request_body o subroute IP allowlist). */
  extractProxyHandler(route) {
    if (!route || !Array.isArray(route.handle)) return null;
    for (const h of route.handle) {
      if (!h) continue;
      if (h.handler === 'reverse_proxy') return h;
      if (h.handler === 'subroute' && Array.isArray(h.routes)) {
        for (const sub of h.routes) {
          const nested = this.extractProxyHandler(sub);
          if (nested) return nested;
        }
      }
    }
    return null;
  }

  /**
   * Construye una ruta de Caddy:
   * - `kind === 'redirect'`: redirección canónica 301/308 (`www` ↔ apex)
   * - `kind === 'maintenance'`: modo mantenimiento atómico 503 sin detener el contenedor
   * - por defecto: `reverse_proxy` con drenaje de WebSockets, keep-alive, canario opcional,
   *   cabeceras de seguridad/personalizadas, Basic Auth bcrypt nativo, IP Allowlist y maxBodySize.
   *
   * @param {{
   *   projectId: string,
   *   hostnames: string[],
   *   upstreams?: string[],
   *   weights?: number[] | null,
   *   kind?: string,
   *   redirectTo?: string,
   *   redirectStatus?: number,
   *   securityHeaders?: boolean,
   *   framePolicy?: 'DENY' | 'SAMEORIGIN' | 'ALLOW' | null,
   *   customHeaders?: { response?: Record<string, string>, request?: Record<string, string> } | null,
   *   basicAuth?: { enabled?: boolean, realm?: string, accounts?: Array<{ username: string, passwordHash: string }> } | null,
   *   ipAllowlist?: string[] | null,
   *   maxBodySizeMb?: number | null,
   *   rateLimit?: { enabled?: boolean, requests?: number, windowSeconds?: number } | null,
   *   flushInterval?: number | null
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
      securityHeaders = false,
      framePolicy = null,
      customHeaders = null,
      basicAuth = null,
      ipAllowlist = null,
      maxBodySizeMb = null,
      rateLimit = null,
      flushInterval = null
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

    if (!Array.isArray(upstreams) || upstreams.length === 0) {
      throw new Error('Una ruta necesita al menos un destino');
    }

    const isStreamingRoute = projectId === 'culkibo_panel' || flushInterval === -1;
    /** @type {any} */
    const handler = {
      handler: 'reverse_proxy',
      upstreams: upstreams.map(u => ({ dial: String(u) })),
      stream_close_delay: 5000000000, // 5 s, en nanosegundos
      ...(isStreamingRoute ? { flush_interval: -1 } : {}),
      transport: {
        protocol: 'http',
        keep_alive: {
          max_idle_conns_per_host: 64,
          idle_timeout: 120000000000,
          probe_interval: 30000000000
        },
        dial_timeout: 5000000000,
        ...(!isStreamingRoute ? { response_header_timeout: 60000000000 } : {})
      }
    };

    if (weights && weights.length === upstreams.length && upstreams.length > 1) {
      handler.load_balancing = {
        selection_policy: { policy: 'weighted_round_robin', weights }
      };
    }

    const HOP_BY_HOP = /^(host|content-length|transfer-encoding|connection|keep-alive|upgrade|proxy-authenticate|proxy-authorization|te|trailer)$/i;
    /** @type {Record<string, string[]>} */
    const respSet = {};
    /** @type {string[]} */
    const respDel = [];
    if (securityHeaders) {
      respSet['X-Content-Type-Options'] = ['nosniff'];
      respSet['Referrer-Policy'] = ['strict-origin-when-cross-origin'];
      respSet['Strict-Transport-Security'] = ['max-age=31536000; includeSubDomains'];
      if (framePolicy === 'DENY' || framePolicy === 'SAMEORIGIN') {
        respSet['X-Frame-Options'] = [framePolicy];
      }
      respDel.push('Server', 'X-Powered-By');
    } else if (framePolicy === 'DENY' || framePolicy === 'SAMEORIGIN') {
      respSet['X-Frame-Options'] = [framePolicy];
    }
    if (customHeaders && customHeaders.response && typeof customHeaders.response === 'object') {
      let count = 0;
      for (const [k, v] of Object.entries(customHeaders.response)) {
        if (count >= 20) break;
        if (/^[A-Za-z0-9-]+$/.test(k) && !HOP_BY_HOP.test(k) && typeof v === 'string') {
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
        if (/^[A-Za-z0-9-]+$/.test(k) && !HOP_BY_HOP.test(k) && typeof v === 'string') {
          reqSet[k] = [v.replace(/[\r\n\0]/g, '').slice(0, 1024)];
          count++;
        }
      }
    }
    if (Object.keys(respSet).length > 0 || respDel.length > 0 || Object.keys(reqSet).length > 0) {
      handler.headers = {};
      if (Object.keys(respSet).length > 0 || respDel.length > 0) {
        handler.headers.response = {
          ...(Object.keys(respSet).length > 0 ? { set: respSet } : {}),
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

    /** @type {any[]} */
    const chain = [];

    // 1. Límite de tamaño de petición nativo (`request_body`)
    const maxMb = Number(maxBodySizeMb);
    if (Number.isFinite(maxMb) && maxMb > 0 && maxMb <= 10240) {
      chain.push({ handler: 'request_body', max_size: Math.round(maxMb * 1024 * 1024) });
    }

    // 2. Rate limiting por dominio ANTES de Basic Auth (protege CPU bcrypt y usa IP real de visitante tras Cloudflare)
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

    chain.push(handler);

    // 4. IP Allowlist nativo con `subroute` + `not.client_ip` (cero plugins extra)
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
              handle: chain
            }
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

  /** ¿Existe ya la ruta de este proyecto? */
  async getRoute(projectId) {
    const { found, value } = await this.getWithEtag(`/id/${this.routeId(projectId)}`);
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
   */
  async upsertRoute(spec) {
    const t0 = process.hrtime.bigint();
    const route = this.buildRoute(spec);
    const id = route['@id'];
    const routeJson = JSON.stringify(route);

    // Caché de digest idempotente: evita recargas innecesarias cuando la ruta es idéntica.
    if (this._appliedRouteJson.get(id) === routeJson) {
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
        readBody: false
      });
    } catch (netErr) {
      this._appliedRouteJson.delete(id);
      this.lastDetection = { available: false, adminUrl: this.adminUrl, reason: netErr.message };
      this.detectionAt = Date.now();
      const err = new Error(`Caddy no responde en ${this.adminUrl}: ${netErr.message}`);
      /** @type {any} */ (err).code = 'CADDY_UNAVAILABLE';
      throw err;
    }

    if (fastRes.ok) {
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
      const current = await this.getWithEtag(routesPath);
      const list = Array.isArray(current.value) ? current.value : [];
      if (list.some((r) => r && r['@id'] === id)) {
        const existing = await this.getWithEtag(`/id/${id}`);
        if (existing.found) {
          await this.write('PATCH', `/id/${id}`, route, { etag: existing.etag });
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
        managed.sort((a, b) => {
          const ra = this.routeSpecificityRank({ hostnames: a.match?.[0]?.host || [], kind: a.handle?.[0]?.handler === 'static_response' ? 'redirect' : 'proxy' });
          const rb = this.routeSpecificityRank({ hostnames: b.match?.[0]?.host || [], kind: b.handle?.[0]?.handler === 'static_response' ? 'redirect' : 'proxy' });
          return ra - rb;
        });
        await this.write('PATCH', routesPath, [...foreign, ...managed], { etag: current.etag });
        return { created: true, id, route };
      }
      await this.write('POST', routesPath, route, { etag: current.etag });
      return { created: true, id, route };
    });
    this._appliedRouteJson.set(id, routeJson);
    this.lastKnownRouteCount = this._appliedRouteJson.size;
    metricsCollector.recordCaddySwap(Number(process.hrtime.bigint() - t0) / 1e6, false);
    return result;
  }

  /**
   * Configura o actualiza una política de certificados wildcard DNS-01 con
   * Cloudflare directamente en Caddy SIN borrar otros wildcards activos.
   */
  async configureWildcardDns01(rootDomain, { tokenEnv = 'CF_API_TOKEN', apiToken = null, includeApex = true, acmeEmail = null } = {}) {
    const cleanRoot = String(rootDomain || '').trim().toLowerCase().replace(/^\*\./, '');
    if (!cleanRoot || !/^[a-z0-9.-]+\.[a-z0-9-]{2,}$/.test(cleanRoot)) {
      throw new Error(`Dominio raíz inválido para wildcard DNS-01: ${rootDomain}`);
    }
    const cleanEnv = String(tokenEnv || 'CF_API_TOKEN').trim();
    if (!/^[A-Z_][A-Z0-9_]{0,63}$/.test(cleanEnv)) {
      throw new Error(`Nombre de variable de entorno inválido para tokenEnv DNS-01: ${tokenEnv}`);
    }
    await this.requireAvailable();
    const subjects = includeApex ? [`*.${cleanRoot}`, cleanRoot] : [`*.${cleanRoot}`];
    /** @type {any} */
    const acmeIssuer = {
      module: 'acme',
      challenges: {
        dns: {
          provider: {
            name: 'cloudflare',
            api_token: apiToken ? String(apiToken) : `{env.${cleanEnv}}`
          },
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
      const current = await this.getWithEtag(policiesPath);
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
      await this.write(current.found ? 'PATCH' : 'PUT', policiesPath, next, { etag: current.etag });
      return { applied: true, subjects, provider: 'cloudflare', tokenEnv: cleanEnv };
    });
  }

  /** Elimina una política wildcard específica preservando las demás y la política on_demand. */
  async removeWildcardDns01(rootDomain) {
    const cleanRoot = String(rootDomain || '').trim().toLowerCase().replace(/^\*\./, '');
    if (!cleanRoot) return { removed: false };
    await this.requireAvailable();
    const policiesPath = '/config/apps/tls/automation/policies';
    return this.mutate(async () => {
      const current = await this.getWithEtag(policiesPath);
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
      await this.write('PATCH', policiesPath, next, { etag: current.etag });
      return { removed: true, rootDomain: cleanRoot };
    });
  }

  /**
   * Reconcilia `/config/apps/tls` completo (múltiples wildcards DNS-01 +
   * certificados propios `load_files` + `on_demand` con respaldo ZeroSSL).
   * Si el binario de Caddy no incluye `dns.providers.cloudflare`, degrada de forma
   * segura aplicando los certificados propios y `on_demand` sin romper HTTP.
   */
  async reconcileTls(tlsOpts) {
    await this.requireAvailable();
    const fullTls = this.buildTlsApp(tlsOpts);
    try {
      const current = await this.getWithEtag('/config/apps/tls');
      if (current.found && JSON.stringify(current.value) === JSON.stringify(fullTls)) {
        return { applied: true, unchanged: true, wildcardCount: (tlsOpts.wildcardPolicies || []).length };
      }
      await this.write(current.found ? 'PATCH' : 'PUT', '/config/apps/tls', fullTls, { etag: current.etag });
      return { applied: true, unchanged: false, wildcardCount: (tlsOpts.wildcardPolicies || []).length };
    } catch (err) {
      const missingPlugin = /dns\.providers\.cloudflare|module not registered/i.test(String(err.message || ''));
      if (missingPlugin && Array.isArray(tlsOpts.wildcardPolicies) && tlsOpts.wildcardPolicies.length > 0) {
        // Degrada limpiamente: mantiene on_demand + certificados propios sin perder HTTPS individual
        const fallbackTls = this.buildTlsApp({ ...tlsOpts, wildcardPolicies: [], wildcardDomains: [] });
        try {
          const cur = await this.getWithEtag('/config/apps/tls');
          await this.write(cur.found ? 'PATCH' : 'PUT', '/config/apps/tls', fallbackTls, { etag: cur.etag });
        } catch (e) {}
        return {
          applied: false,
          missingCloudflarePlugin: true,
          error: 'Tu binario actual de Caddy no incluye el módulo dns.providers.cloudflare necesario para certificados Wildcard (*.dominio). Compila con Dockerfile.caddy o usa imagen caddy-cloudflare.'
        };
      }
      throw err;
    }
  }

  /** Detecta capacidades reales del Caddy activo (módulo Cloudflare DNS-01, versión, token). */
  async probeCapabilities({ force = false } = {}) {
    const now = Date.now();
    if (!force && this._capabilitiesCache && (now - this._capabilitiesCache.checkedAt) < 30000) {
      return this._capabilitiesCache.data;
    }
    const detection = await this.detect({ force });
    /** @type {{ available: boolean, version: string | null, hasCloudflareDnsPlugin: boolean | null, hasRateLimitPlugin: boolean | null, hasCfTokenEnv: boolean, containerized: boolean, containerName: string }} */
    const caps = {
      available: detection.available,
      version: detection.version || null,
      hasCloudflareDnsPlugin: null,
      hasRateLimitPlugin: null,
      hasCfTokenEnv: Boolean(process.env.CF_API_TOKEN || process.env.CLOUDFLARE_API_TOKEN),
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
        caps.hasCloudflareDnsPlugin = modulesOut.includes('dns.providers.cloudflare');
        caps.hasRateLimitPlugin = modulesOut.includes('http.handlers.rate_limit');
      }
    }

    this._capabilitiesCache = { checkedAt: now, data: caps };
    return caps;
  }

  /** Elimina la ruta de un proyecto en 1 RTT. Idempotente. */
  async removeRoute(projectId) {
    const id = this.routeId(projectId);
    this._appliedRouteJson.delete(id);
    let res;
    try {
      res = await this.adminRequest('DELETE', `/id/${id}`, { timeoutMs: 10000, readBody: false });
    } catch (netErr) {
      this.lastDetection = { available: false, adminUrl: this.adminUrl, reason: netErr.message };
      this.detectionAt = Date.now();
      const err = new Error(`Caddy no responde en ${this.adminUrl}: ${netErr.message}`);
      /** @type {any} */ (err).code = 'CADDY_UNAVAILABLE';
      throw err;
    }
    if (res.ok) {
      this.lastKnownRouteCount = this._appliedRouteJson.size;
      return { removed: true, id };
    }
    if (res.status === 404 || /unknown object ID/i.test(res.text)) {
      return { removed: false, id };
    }
    throw new Error(`DELETE /id/${id} devolvió ${res.status}: ${res.text}`);
  }

  /** Rutas que gestiona Culkibo, ignorando las que haya puesto otro (como `sys_encode`). */
  async listRoutes() {
    const routes = await this.get('/config/apps/http/servers/culkibo/routes');
    if (!Array.isArray(routes)) {
      this.lastKnownRouteCount = 0;
      return [];
    }
    const managed = routes.filter(r => typeof r['@id'] === 'string' && r['@id'].startsWith(ID_PREFIX));
    this.lastKnownRouteCount = managed.length;
    return managed;
  }

  /**
   * Alta/actualización en lote (1 único PATCH con ETag en vez de N recargas).
   * Preserva todas las demás rutas existentes (propias y ajenas).
   */
  async upsertRoutesBatch(specs) {
    if (!Array.isArray(specs) || specs.length === 0) {
      return { applied: [], unchanged: true };
    }
    await this.requireAvailable();
    const sorted = [...specs].sort((a, b) => this.routeSpecificityRank(a) - this.routeSpecificityRank(b));
    const batchMap = new Map();
    for (const s of sorted) {
      const r = this.buildRoute(s);
      batchMap.set(r['@id'], { spec: s, route: r, json: JSON.stringify(r) });
    }
    const routesPath = '/config/apps/http/servers/culkibo/routes';

    return this.mutate(async () => {
      const current = await this.getWithEtag(routesPath);
      const existingAll = Array.isArray(current.value) ? current.value : [];
      const foreign = existingAll.filter((r) => !(r && typeof r['@id'] === 'string' && r['@id'].startsWith(ID_PREFIX)));
      const keptManaged = existingAll.filter((r) => r && typeof r['@id'] === 'string' && r['@id'].startsWith(ID_PREFIX) && !batchMap.has(r['@id']));
      const combinedManaged = [...keptManaged, ...Array.from(batchMap.values()).map((x) => x.route)];
      combinedManaged.sort((a, b) => {
        const ra = this.routeSpecificityRank({ hostnames: a.match?.[0]?.host || [], kind: a.handle?.[0]?.handler === 'static_response' ? 'redirect' : 'proxy' });
        const rb = this.routeSpecificityRank({ hostnames: b.match?.[0]?.host || [], kind: b.handle?.[0]?.handler === 'static_response' ? 'redirect' : 'proxy' });
        return ra - rb;
      });
      const nextRoutes = [...foreign, ...combinedManaged];
      if (JSON.stringify(existingAll) === JSON.stringify(nextRoutes)) {
        for (const [id, entry] of batchMap.entries()) this._appliedRouteJson.set(id, entry.json);
        return { applied: Array.from(batchMap.keys()), unchanged: true };
      }
      await this.write(current.found ? 'PATCH' : 'PUT', routesPath, nextRoutes, { etag: current.etag });
      for (const [id, entry] of batchMap.entries()) this._appliedRouteJson.set(id, entry.json);
      this.lastKnownRouteCount = combinedManaged.length;
      return { applied: Array.from(batchMap.keys()), unchanged: false };
    });
  }

  /**
   * Reconciliación atómica por diff en un único PUT/PATCH (en lugar de N+M recargas).
   * Ordena rutas por especificidad para que ningún comodín eclipse subdominios exactos.
   */
  async reconcile(desiredSpecs) {
    await this.requireAvailable();
    const sortedSpecs = [...desiredSpecs].sort((a, b) => this.routeSpecificityRank(a) - this.routeSpecificityRank(b));
    const built = sortedSpecs.map((spec) => {
      const route = this.buildRoute(spec);
      return { id: route['@id'], route, json: JSON.stringify(route) };
    });
    const desiredRoutes = built.map((b) => b.route);
    const desiredIds = new Set(built.map((b) => b.id));
    const routesPath = '/config/apps/http/servers/culkibo/routes';

    return this.mutate(async () => {
      const current = await this.getWithEtag(routesPath);
      const existingAll = Array.isArray(current.value) ? current.value : [];
      const foreign = existingAll.filter((r) => !(r && typeof r['@id'] === 'string' && r['@id'].startsWith(ID_PREFIX)));
      const existingCulkibo = existingAll.filter((r) => r && typeof r['@id'] === 'string' && r['@id'].startsWith(ID_PREFIX));

      const removed = existingCulkibo
        .filter((r) => !desiredIds.has(r['@id']))
        .map((r) => r['@id']);
      const applied = built.map((b) => b.id);

      const nextRoutes = [...foreign, ...desiredRoutes];
      if (JSON.stringify(existingAll) === JSON.stringify(nextRoutes)) {
        this._appliedRouteJson.clear();
        for (const b of built) this._appliedRouteJson.set(b.id, b.json);
        this.lastKnownRouteCount = desiredRoutes.length;
        return { applied, removed, unchanged: true };
      }

      await this.write(current.found ? 'PATCH' : 'PUT', routesPath, nextRoutes, { etag: current.etag });
      this._appliedRouteJson.clear();
      for (const b of built) this._appliedRouteJson.set(b.id, b.json);
      this.lastKnownRouteCount = desiredRoutes.length;
      return { applied, removed, unchanged: false };
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
          return resolve({ started: true, containerName: cleanName, network: useHostNet ? 'host' : 'bridge', http3: true });
        }
        resolve({ started: false, error: stderr.join('').trim() || `docker run terminó con código ${code}` });
      });
    });
  }
}

const caddyManagerInstance = Object.assign(new CaddyManager(), { CaddyManager });
module.exports = caddyManagerInstance;
