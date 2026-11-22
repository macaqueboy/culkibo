const { spawn } = require('child_process');
const http = require('http');
const https = require('https');

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
    this.httpAgent = new http.Agent({ keepAlive: true, maxSockets: 8, keepAliveMsecs: 60000 });
    this.httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 8, keepAliveMsecs: 60000 });
  }

  /**
   * Petición HTTP persistente contra la Admin API de Caddy con keep-alive real,
   * `TCP_NODELAY` y drenaje garantizado del cuerpo (evita la fuga de sockets de undici).
   *
   * @param {string} method
   * @param {string} reqPath
   * @param {{ headers?: Record<string, string>, body?: string | null, timeoutMs?: number, readBody?: boolean }} [opts]
   * @returns {Promise<{ status: number, ok: boolean, headers: Record<string, any>, text: string }>}
   */
  adminRequest(method, reqPath, { headers = {}, body = null, timeoutMs = 10000, readBody = true } = {}) {
    return new Promise((resolve, reject) => {
      const target = new URL(reqPath, this.adminUrl);
      const isHttps = target.protocol === 'https:';
      const payloadBuf = body != null ? Buffer.from(body, 'utf8') : null;
      const reqHeaders = {
        ...this.adminHeaders(),
        ...headers,
        ...(payloadBuf ? { 'Content-Length': String(payloadBuf.length) } : {})
      };

      const req = (isHttps ? https : http).request(
        {
          hostname: target.hostname,
          port: target.port || (isHttps ? 443 : 80),
          path: `${target.pathname}${target.search}`,
          method,
          headers: reqHeaders,
          agent: isHttps ? this.httpsAgent : this.httpAgent
        },
        (res) => {
          const status = res.statusCode || 0;
          const ok = status >= 200 && status < 300;
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
            const text = chunks.length ? Buffer.concat(chunks).toString('utf8') : '';
            resolve({ status, ok, headers: res.headers, text });
          });
          res.once('error', (err) => {
            clearTimeout(timer);
            reject(err);
          });
        }
      );

      req.on('socket', (sock) => {
        if (typeof sock.setNoDelay === 'function') sock.setNoDelay(true);
      });

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

    this.lastDetection = result;
    this.detectionAt = now;
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
    if (res.status === 404) return { found: false, value: null, etag: null };
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
  buildBaseConfig({
    askEndpoint,
    httpPort = 80,
    httpsPort = 443,
    automaticHttps = true,
    wildcardDomains = [],
    cloudflareDnsTokenEnv = 'CF_API_TOKEN'
  }) {
    /** @type {any[]} */
    const policies = [];

    // Wildcard TLS real vía DNS-01 de Cloudflare (requiere Caddy compilado con
    // `caddy-dns/cloudflare`, p. ej. desde caddyserver.com/api/download o xcaddy).
    // Ni Coolify ni Dokploy traen DNS-01 integrado por defecto.
    const cleanWildcards = Array.isArray(wildcardDomains)
      ? wildcardDomains.map(d => String(d).trim().toLowerCase()).filter(Boolean)
      : [];
    if (cleanWildcards.length > 0) {
      policies.push({
        subjects: cleanWildcards,
        issuers: [{
          module: 'acme',
          challenges: {
            dns: {
              provider: {
                name: 'cloudflare',
                api_token: `{env.${cloudflareDnsTokenEnv}}`
              }
            }
          }
        }]
      });
    }

    policies.push({
      on_demand: true,
      issuers: [{ module: 'acme' }]
    });

    const adminHost = this.adminUrl.replace(/^https?:\/\//, '');
    const isLoopbackAdmin = /^(localhost|127\.0\.0\.1|\[::1\]):/i.test(adminHost);
    const adminPort = (adminHost.split(':')[1] || '2019').replace(/[^0-9]/g, '') || '2019';

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
            culkibo: {
              listen: [`:${httpPort}`, `:${httpsPort}`],
              routes: [],
              // Caddy redirige HTTP→HTTPS por su cuenta en cuanto una ruta casa
              // por nombre de dominio. Es lo correcto en producción, pero al
              // medir el conmutador convierte cada respuesta en un 308 y
              // falsea la medición. Solo el banco de pruebas lo desactiva.
              ...(automaticHttps ? {} : { automatic_https: { disable: true } })
            }
          }
        },
        tls: {
          automation: {
            policies,
            on_demand: {
              // `ask` está deprecado ("WILL BE REMOVED SOON") en favor de
              // `permission` con el módulo http.
              permission: { module: 'http', endpoint: askEndpoint }
            }
          }
        }
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
    return config;
  }

  // ---------------------------------------------------------------------
  // Rutas
  // ---------------------------------------------------------------------

  routeId(projectId) {
    return `${ID_PREFIX}${String(projectId).replace(/[^a-zA-Z0-9_-]/g, '')}`;
  }

  /**
   * Construye una ruta.
   *
   * Cuando hay dos destinos con pesos, se emite una política
   * `weighted_round_robin`: eso es el canario Forge/Citadel de verdad,
   * ejecutado por el proxy, en lugar del `Math.random()` que había en Express.
   *
   * `terminal: true` corta la evaluación en cuanto una ruta casa, para que un
   * proyecto no pueda recibir tráfico de otro por un matcher más laxo.
   */
  /**
   * @param {{ projectId: string, hostnames: string[], upstreams: string[], weights?: number[] | null }} spec
   */
  buildRoute({ projectId, hostnames, upstreams, weights = null }) {
    if (!Array.isArray(hostnames) || hostnames.length === 0) {
      throw new Error('Una ruta necesita al menos un hostname');
    }
    if (!Array.isArray(upstreams) || upstreams.length === 0) {
      throw new Error('Una ruta necesita al menos un destino');
    }

    const handler = {
      handler: 'reverse_proxy',
      upstreams: upstreams.map(u => ({ dial: String(u) })),
      // Sin esto, recargar la configuración corta las peticiones en streaming
      // —incluidos los WebSockets del HMR— y cada promoción rompería la tubería
      // que el producto entero promete mantener viva.
      // Va en el handler, no en el servidor: Caddy rechaza el campo si se pone
      // arriba, y lo descubrimos porque probamos contra un Caddy real.
      stream_close_delay: 5000000000 // 5 s, en nanosegundos
    };

    if (weights && weights.length === upstreams.length && upstreams.length > 1) {
      handler.load_balancing = {
        selection_policy: { policy: 'weighted_round_robin', weights }
      };
    }

    // Comprobaciones pasivas: un destino que falla deja de recibir tráfico sin
    // que nadie tenga que sondearlo activamente.
    handler.health_checks = {
      passive: { fail_duration: 10000000000, max_fails: 3 } // 10 s
    };

    return {
      '@id': this.routeId(projectId),
      match: [{ host: hostnames }],
      handle: [handler],
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
    await this.requireAvailable();
    const route = this.buildRoute(spec);
    const id = route['@id'];

    // Fast path: 1 solo roundtrip HTTP keep-alive cuando la ruta ya existe.
    const fastRes = await this.adminRequest('PATCH', `/id/${id}`, {
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(route),
      timeoutMs: 10000,
      readBody: false
    });
    if (fastRes.ok) {
      return { created: false, id, route };
    }
    if (fastRes.status !== 404 && fastRes.status !== 400) {
      if (!/unknown object ID/i.test(fastRes.text)) {
        throw new Error(`PATCH /id/${id} devolvió ${fastRes.status}: ${fastRes.text}`);
      }
    }

    // Si el fast-path indicó que no existe, vamos directo a POST /routes (sin GET /id redundante).
    const routesPath = '/config/apps/http/servers/culkibo/routes';
    return this.mutate(async () => {
      const current = await this.getWithEtag(routesPath);
      const list = Array.isArray(current.value) ? current.value : [];
      if (list.some((r) => r && r['@id'] === id)) {
        const existing = await this.getWithEtag(`/id/${id}`);
        if (existing.found) {
          await this.write('PATCH', `/id/${id}`, route, { etag: existing.etag });
          return { created: false, id, route };
        }
      }
      await this.write('POST', routesPath, route, { etag: current.etag });
      return { created: true, id, route };
    });
  }

  /**
   * Configura o actualiza la política de certificados wildcard DNS-01 con
   * Cloudflare directamente en Caddy (requiere módulo `dns.providers.cloudflare`).
   */
  async configureWildcardDns01(rootDomain, { tokenEnv = 'CF_API_TOKEN' } = {}) {
    const cleanRoot = String(rootDomain || '').trim().toLowerCase().replace(/^\*\./, '');
    if (!cleanRoot || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(cleanRoot)) {
      throw new Error(`Dominio raíz inválido para wildcard DNS-01: ${rootDomain}`);
    }
    const cleanEnv = String(tokenEnv || 'CF_API_TOKEN').trim();
    if (!/^[A-Z_][A-Z0-9_]{0,63}$/.test(cleanEnv)) {
      throw new Error(`Nombre de variable de entorno inválido para token DNS-01: ${tokenEnv}`);
    }
    await this.requireAvailable();
    const subjects = [`*.${cleanRoot}`, cleanRoot];
    const policy = {
      subjects,
      issuers: [{
        module: 'acme',
        challenges: {
          dns: {
            provider: {
              name: 'cloudflare',
              api_token: `{env.${cleanEnv}}`
            }
          }
        }
      }]
    };
    const policiesPath = '/config/apps/tls/automation/policies';
    return this.mutate(async () => {
      const current = await this.getWithEtag(policiesPath);
      const list = Array.isArray(current.value) ? current.value : [];
      const filtered = list.filter(p => !(Array.isArray(p.subjects) && p.subjects.includes(`*.${cleanRoot}`)));
      const next = [policy, ...filtered];
      await this.write(current.found ? 'PATCH' : 'PUT', policiesPath, next, { etag: current.etag });
      return { applied: true, subjects, provider: 'cloudflare', tokenEnv: cleanEnv };
    });
  }

  /** Elimina la ruta de un proyecto. Idempotente. */
  async removeRoute(projectId) {
    await this.requireAvailable();
    const id = this.routeId(projectId);
    return this.mutate(async () => {
      const existing = await this.getWithEtag(`/id/${id}`);
      if (!existing.found) return { removed: false, id };
      await this.write('DELETE', `/id/${id}`, undefined, { etag: existing.etag });
      return { removed: true, id };
    });
  }

  /** Rutas que gestiona Culkibo, ignorando las que haya puesto otro. */
  async listRoutes() {
    const routes = await this.get('/config/apps/http/servers/culkibo/routes');
    if (!Array.isArray(routes)) return [];
    return routes.filter(r => typeof r['@id'] === 'string' && r['@id'].startsWith(ID_PREFIX));
  }

  /**
   * Reconciliación atómica por diff en un único PUT (en lugar de N+M recargas).
   * Si las rutas deseadas ya coinciden exactamente con Caddy, 0 escrituras / 0 recargas.
   */
  async reconcile(desiredSpecs) {
    await this.requireAvailable();
    const desiredRoutes = desiredSpecs.map((spec) => this.buildRoute(spec));
    const desiredIds = new Set(desiredRoutes.map((r) => r['@id']));
    const routesPath = '/config/apps/http/servers/culkibo/routes';

    return this.mutate(async () => {
      const current = await this.getWithEtag(routesPath);
      const existingAll = Array.isArray(current.value) ? current.value : [];
      const foreign = existingAll.filter((r) => !(r && typeof r['@id'] === 'string' && r['@id'].startsWith(ID_PREFIX)));
      const existingCulkibo = existingAll.filter((r) => r && typeof r['@id'] === 'string' && r['@id'].startsWith(ID_PREFIX));

      const removed = existingCulkibo
        .filter((r) => !desiredIds.has(r['@id']))
        .map((r) => r['@id']);
      const applied = desiredRoutes.map((r) => r['@id']);

      const nextRoutes = [...foreign, ...desiredRoutes];
      if (JSON.stringify(existingAll) === JSON.stringify(nextRoutes)) {
        return { applied, removed, unchanged: true };
      }

      await this.write(current.found ? 'PATCH' : 'PUT', routesPath, nextRoutes, { etag: current.etag });
      return { applied, removed, unchanged: false };
    });
  }

  // ---------------------------------------------------------------------
  // Arranque de Caddy
  // ---------------------------------------------------------------------

  /**
   * Levanta Caddy en un contenedor (con validación estricta anti inyección de flags).
   */
  async startWithDocker({ image = 'caddy:2-alpine', containerName = 'culkibo-caddy', httpPort = 80, httpsPort = 443, adminPort = 2019 } = {}) {
    const cleanImage = String(image || 'caddy:2-alpine').trim();
    const cleanName = String(containerName || 'culkibo-caddy').trim();
    const pHttp = Number(httpPort);
    const pHttps = Number(httpsPort);
    const pAdmin = Number(adminPort);

    if (
      cleanImage.startsWith('-') ||
      !/^(?:caddy(?::[a-zA-Z0-9._-]+)?|(?:ghcr\.io|docker\.io)\/[a-z0-9._-]+\/caddy:[a-zA-Z0-9._-]+)$/.test(cleanImage)
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

    const args = [
      'run', '-d', '--name', cleanName, '--restart', 'unless-stopped',
      '-p', `${pHttp}:80`,
      '-p', `${pHttps}:443`,
      '-p', `127.0.0.1:${pAdmin}:2019`,
      '-v', 'culkibo_caddy_data:/data',
      '-v', 'culkibo_caddy_config:/config',
      cleanImage,
      'caddy', 'run', '--config', '/dev/null', '--adapter', 'caddyfile'
    ];

    return new Promise((resolve) => {
      const child = spawn('docker', args, { shell: false, windowsHide: true });
      const stderr = [];
      child.stderr.on('data', d => stderr.push(d.toString()));
      child.on('error', (err) => resolve({ started: false, error: err.message }));
      child.on('close', (code) => {
        if (code === 0) return resolve({ started: true, containerName: cleanName });
        resolve({ started: false, error: stderr.join('').trim() || `docker run terminó con código ${code}` });
      });
    });
  }
}

const caddyManagerInstance = Object.assign(new CaddyManager(), { CaddyManager });
module.exports = caddyManagerInstance;
