const { spawn } = require('child_process');

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
  }

  /**
   * Cabeceras para hablar con la API de administración.
   *
   * El `Origin` explícito no es opcional: Caddy valida ese encabezado para
   * defenderse de DNS rebinding —una web que visitaras podría, si no, reconfigurar
   * tu proxy desde tu propio navegador— y el `fetch` de Node envía un origen
   * vacío, que Caddy rechaza con `403 client is not allowed to access from
   * origin ''`. `curl` funciona porque no envía ninguno.
   */
  adminHeaders(extra = {}) {
    return { Origin: this.adminUrl, ...extra };
  }

  // ---------------------------------------------------------------------
  // Detección
  // ---------------------------------------------------------------------

  /**
   * ¿Hay un Caddy con el que hablar?
   *
   * No lanza nunca. Si no lo hay, el daemon sigue funcionando sin ingress real
   * y lo dice — el mismo principio camaleón que usamos con Docker.
   */
  async detect({ force = false } = {}) {
    const now = Date.now();
    if (!force && this.lastDetection && (now - this.detectionAt) < this.detectionTtlMs) {
      return this.lastDetection;
    }

    let result = { available: false, adminUrl: this.adminUrl, version: null, reason: null };
    try {
      const res = await fetch(`${this.adminUrl}/config/`, { headers: this.adminHeaders(), signal: AbortSignal.timeout(2500) });
      if (res.ok) {
        result = { available: true, adminUrl: this.adminUrl, version: await this.readVersion(), reason: null };
      } else {
        result.reason = `La API de administración respondió ${res.status}`;
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
      const res = await fetch(`${this.adminUrl}/reverse_proxy/upstreams`, { headers: this.adminHeaders(), signal: AbortSignal.timeout(1500) });
      return res.ok ? 'activo' : null;
    } catch (e) {
      return null;
    }
  }

  async requireAvailable() {
    const detection = await this.detect();
    if (!detection.available) {
      const err = new Error(`Caddy no está disponible: ${detection.reason}`);
      err.code = 'CADDY_UNAVAILABLE';
      throw err;
    }
    return detection;
  }

  // ---------------------------------------------------------------------
  // Admin API
  // ---------------------------------------------------------------------

  /**
   * Lectura que además devuelve el ETag, necesario para escribir sin pisar a
   * nadie.
   */
  async getWithEtag(path) {
    const res = await fetch(`${this.adminUrl}${path}`, { headers: this.adminHeaders(), signal: AbortSignal.timeout(5000) });
    if (res.status === 404) return { found: false, value: null, etag: null };
    if (!res.ok) throw new Error(`GET ${path} devolvió ${res.status}: ${await res.text()}`);
    const etag = res.headers.get('etag');
    const text = await res.text();
    return { found: true, value: text ? JSON.parse(text) : null, etag };
  }

  async get(path) {
    return (await this.getWithEtag(path)).value;
  }

  /**
   * Escritura con control de concurrencia optimista.
   *
   * Caddy da garantías ACID por petición, pero un ciclo leer-modificar-escribir
   * puede pisar un cambio concurrente. El protocolo documentado es: capturar el
   * ETag al leer, enviar `If-Match`, y reintentar desde la lectura si responde
   * 412. Lo implementamos aquí una vez para que ningún llamante tenga que
   * acordarse.
   */
  async write(method, path, body, { etag = null, retries = 3 } = {}) {
    for (let attempt = 0; attempt <= retries; attempt++) {
      const headers = this.adminHeaders({ 'Content-Type': 'application/json' });
      if (etag) headers['If-Match'] = etag;

      const res = await fetch(`${this.adminUrl}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(10000)
      });

      if (res.ok) return true;

      // 412: alguien escribió entremedias. El llamante debe releer y reintentar.
      if (res.status === 412 && attempt < retries) {
        const conflict = new Error('PRECONDITION_FAILED');
        conflict.code = 'ETAG_CONFLICT';
        throw conflict;
      }

      const detail = await res.text();
      throw new Error(`${method} ${path} devolvió ${res.status}: ${detail}`);
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
  buildBaseConfig({ askEndpoint, httpPort = 80, httpsPort = 443, automaticHttps = true }) {
    return {
      admin: { listen: this.adminUrl.replace(/^https?:\/\//, '') },
      apps: {
        http: {
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
            policies: [
              {
                on_demand: true,
                issuers: [{ module: 'acme' }]
              }
            ],
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
    const res = await fetch(`${this.adminUrl}/load`, {
      method: 'POST',
      headers: this.adminHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(config),
      signal: AbortSignal.timeout(15000)
    });
    if (!res.ok) throw new Error(`No se pudo cargar la configuración base: ${res.status} ${await res.text()}`);
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
   * PATCH sobre /id/<id> reemplaza el objeto entero de forma atómica; si no
   * existe todavía, se añade al array de rutas del servidor.
   */
  async upsertRoute(spec) {
    await this.requireAvailable();
    const route = this.buildRoute(spec);
    const id = route['@id'];

    return this.mutate(async () => {
      const existing = await this.getWithEtag(`/id/${id}`);
      if (existing.found) {
        await this.write('PATCH', `/id/${id}`, route, { etag: existing.etag });
        return { created: false, id, route };
      }

      const routesPath = '/config/apps/http/servers/culkibo/routes';
      const current = await this.getWithEtag(routesPath);
      // POST sobre un array añade al final.
      await this.write('POST', routesPath, route, { etag: current.etag });
      return { created: true, id, route };
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
   * Reconciliación: deja Caddy exactamente con las rutas que Culkibo cree que
   * debe haber.
   *
   * Hace falta porque Caddy puede reiniciarse, perder su configuración o ser
   * editado por fuera, y entonces nuestra idea del mundo y la suya divergen en
   * silencio. Dokploy tiene un fallo abierto exactamente por esto: tras un
   * reinicio sucio, los adjuntos de red no se vuelven a aplicar y el estado real
   * deja de coincidir con el modelo, sin aviso.
   */
  async reconcile(desiredSpecs) {
    await this.requireAvailable();
    const desiredIds = new Set(desiredSpecs.map(s => this.routeId(s.projectId)));
    const applied = [];
    const removed = [];

    for (const spec of desiredSpecs) {
      const result = await this.upsertRoute(spec);
      applied.push(result.id);
    }

    for (const route of await this.listRoutes()) {
      if (!desiredIds.has(route['@id'])) {
        const projectId = route['@id'].slice(ID_PREFIX.length);
        await this.removeRoute(projectId);
        removed.push(route['@id']);
      }
    }

    return { applied, removed };
  }

  // ---------------------------------------------------------------------
  // Arranque de Caddy
  // ---------------------------------------------------------------------

  /**
   * Levanta Caddy en un contenedor.
   *
   * Mantiene la promesa de "un comando": el usuario no instala nada. Si hay
   * Docker, Culkibo se trae el plano de datos solo.
   */
  async startWithDocker({ image = 'caddy:2-alpine', containerName = 'culkibo-caddy', httpPort = 80, httpsPort = 443, adminPort = 2019 } = {}) {
    const args = [
      'run', '-d', '--name', containerName, '--restart', 'unless-stopped',
      '-p', `${httpPort}:80`,
      '-p', `${httpsPort}:443`,
      // La admin API solo escucha en loopback del host: es la recomendación de
      // seguridad de Caddy y aquí es control total sobre el ingress.
      '-p', `127.0.0.1:${adminPort}:2019`,
      '-v', 'culkibo_caddy_data:/data',
      '-v', 'culkibo_caddy_config:/config',
      image,
      'caddy', 'run', '--config', '/dev/null', '--adapter', 'caddyfile'
    ];

    return new Promise((resolve) => {
      const child = spawn('docker', args, { shell: false, windowsHide: true });
      const stderr = [];
      child.stderr.on('data', d => stderr.push(d.toString()));
      child.on('error', (err) => resolve({ started: false, error: err.message }));
      child.on('close', (code) => {
        if (code === 0) return resolve({ started: true, containerName });
        resolve({ started: false, error: stderr.join('').trim() || `docker run terminó con código ${code}` });
      });
    });
  }
}

module.exports = new CaddyManager();
module.exports.CaddyManager = CaddyManager;
