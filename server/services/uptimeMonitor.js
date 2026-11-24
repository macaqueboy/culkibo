const crypto = require('crypto');
const net = require('net');
const path = require('path');
const { EventEmitter } = require('events');
const ssrfGuard = require('./ssrfGuard');

/**
 * Monitor sintético de disponibilidad (HTTP / TCP / proyecto gestionado) y
 * páginas públicas de estado cero-dependencias.
 *
 * Propiedades de seguridad y rendimiento:
 *  - Protección SSRF estricta en alta, edición y cada sondeo (`ssrfGuard.assertSafeUrl`
 *    + `safeFetch` con pinning de IP). Las comprobaciones TCP resuelven DNS antes
 *    de conectar y abren el socket directamente contra la IP fijada (`pinnedIp`),
 *    nunca contra el hostname en crudo (corta DNS rebinding TOCTOU).
 *  - `allowLocalProject: true` sólo permite sondear `127.0.0.1:<hostPort>` de un
 *    proyecto desplegado cuyo puerto esté verificado en `deployManager` y con
 *    `maxRedirects: 0` para impedir redirecciones hacia metadatos o RFC1918.
 *  - Páginas públicas `/status/:slug` con proyección estricta por lista blanca:
 *    JAMÁS exponen URLs internas, IPs, puertos, hostnames, IDs de proyecto ni
 *    mensajes de error de red. Caché acotada de buffers HTML (15 s, máx. 50 slugs).
 *  - Planificador perezoso: no arranca temporizadores al importar; sólo crea un
 *    intervalo `.unref()` cuando hay >= 1 monitor habilitado.
 */

const DATA_DIR = process.env.CULKIBO_DATA_DIR
  ? path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data')
  : path.resolve(__dirname, '..', '..', 'data');
const STORE_FILE = path.join(DATA_DIR, 'uptime.json');

const MAX_MONITORS = 100;
const MAX_CHECKS_PER_MONITOR = 288;
const MAX_DAILY_STATS = 90;
const MAX_INCIDENTS = 100;
const MAX_STATUS_PAGES = 50;
const MAX_HTML_CACHE_ENTRIES = 50;
const HTML_CACHE_TTL_MS = 15 * 1000;
const MAX_CONCURRENT_PROBES = 8;
const MAX_RESPONSE_BYTES = 64 * 1024;
const MIN_INTERVAL_SEC = 30;
const MAX_INTERVAL_SEC = 86400;
const MIN_TIMEOUT_MS = 500;
const MAX_TIMEOUT_MS = 10000;
const SCHEDULER_TICK_MS = 10 * 1000;

const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,48}$/;
const HEX_COLOR_RE = /^#[0-9a-fA-F]{6}$/;
const HOSTNAME_RE = /^[a-zA-Z0-9.-]{1,253}$/;
const METADATA_HOSTS = new Set([
  'metadata.google.internal',
  'metadata.goog',
  'metadata',
  'instance-data'
]);

const PUBLIC_STATUS_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'";

/** @type {any} */
let _notificationService = null;
function getNotificationService() {
  if (!_notificationService) {
    try { _notificationService = require('./notificationService'); } catch (e) {}
  }
  return _notificationService;
}

/** @type {any} */
let _deployManager = null;
function getDeployManager() {
  if (!_deployManager) {
    try { _deployManager = require('./deployManager'); } catch (e) {}
  }
  return _deployManager;
}

/** @type {any} */
let _projectManager = null;
function getProjectManager() {
  if (!_projectManager) {
    try { _projectManager = require('./projectManager'); } catch (e) {}
  }
  return _projectManager;
}

/**
 * Escapa texto de forma segura para HTML/SVG.
 * @param {any} text
 * @returns {string}
 */
function escapeHtml(text) {
  return String(text == null ? '' : text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Calcula un percentil (nearest-rank) sobre una lista de números positivos.
 * @param {number[]} values
 * @param {number} p
 * @returns {number | null}
 */
function percentile(values, p) {
  const nums = values.filter((n) => typeof n === 'number' && Number.isFinite(n) && n >= 0);
  if (nums.length === 0) return null;
  nums.sort((a, b) => a - b);
  const idx = Math.min(nums.length - 1, Math.max(0, Math.ceil((p / 100) * nums.length) - 1));
  return Math.round(nums[idx] * 100) / 100;
}

/**
 * Formatea una fecha UTC como `YYYY-MM-DD`.
 * @param {number} ts
 * @returns {string}
 */
function utcDateKey(ts) {
  return new Date(ts).toISOString().slice(0, 10);
}

/**
 * Sanitiza un mensaje de error interno para almacenamiento administrativo acotado.
 * @param {any} err
 * @returns {string}
 */
function formatInternalError(err) {
  const raw = err && typeof err === 'object' && 'message' in err ? String(err.message) : String(err || 'Error desconocido');
  return raw.replace(/[\r\n\0]+/g, ' ').trim().slice(0, 240);
}

/**
 * Valida y normaliza una ruta HTTP para monitores de proyecto local.
 * @param {any} rawPath
 * @returns {string}
 */
function sanitizeHealthPath(rawPath) {
  const s = String(rawPath == null || rawPath === '' ? '/' : rawPath).trim();
  if (!s.startsWith('/') || /[\r\n\0\s]/.test(s) || s.length > 512) {
    throw new Error('La ruta del monitor local debe empezar por "/" y no contener espacios ni caracteres de control');
  }
  return s;
}

class UptimeMonitor extends EventEmitter {
  /**
   * @param {{
   *   storeFile?: string,
   *   autoStart?: boolean,
   *   assertSafeUrl?: typeof ssrfGuard.assertSafeUrl,
   *   safeFetch?: typeof ssrfGuard.safeFetch,
   *   tcpProbe?: ((opts: { pinnedIp: string, port: number, timeoutMs: number }) => Promise<{ ok: boolean, latencyMs: number, error: string | null }>) | null,
   *   resolveProjectPort?: ((projectId: string) => number | null) | null,
   *   getProjectMaintenance?: ((projectId: string) => boolean) | null,
   *   notifier?: { notify: (payload: any) => Promise<any> } | null
   * }} [options]
   */
  constructor(options = {}) {
    super();
    this.storeFile = options.storeFile || STORE_FILE;
    this._autoStart = options.autoStart !== false;
    this._assertSafeUrl = options.assertSafeUrl || ssrfGuard.assertSafeUrl;
    this._safeFetch = options.safeFetch || ssrfGuard.safeFetch;
    this._tcpProbe = options.tcpProbe || null;
    this._resolveProjectPortFn = options.resolveProjectPort || null;
    this._getProjectMaintenanceFn = options.getProjectMaintenance || null;
    this._notifier = options.notifier || null;

    /** @type {Map<string, any>} */
    this.monitors = new Map();
    /** @type {Map<string, any>} */
    this.statusPages = new Map();
    /** @type {Array<any>} */
    this.incidents = [];
    /** @type {Map<string, { html: string, buffer: Buffer, etag: string, createdAt: number }>} */
    this._htmlCache = new Map();
    /** @type {Set<string>} */
    this._inFlightChecks = new Set();

    /** @type {ReturnType<typeof setInterval> | null} */
    this._timer = null;
    this._loaded = false;
    this._stopped = false;
  }

  _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;
    const res = ssrfGuard.loadJsonWithBackupSync(this.storeFile, {
      validate: (parsed) => Boolean(parsed && typeof parsed === 'object' && Array.isArray(parsed.monitors))
    });
    if (res.ok && res.data) {
      for (const m of res.data.monitors || []) {
        if (m && typeof m.id === 'string') {
          if (!Array.isArray(m.checks)) m.checks = [];
          if (m.checks.length > MAX_CHECKS_PER_MONITOR) {
            m.checks = m.checks.slice(-MAX_CHECKS_PER_MONITOR);
          }
          if (!Array.isArray(m.dailyStats)) m.dailyStats = [];
          if (m.dailyStats.length > MAX_DAILY_STATS) {
            m.dailyStats = m.dailyStats.slice(-MAX_DAILY_STATS);
          }
          this.monitors.set(m.id, m);
        }
      }
      for (const p of res.data.statusPages || []) {
        if (p && typeof p.slug === 'string' && SLUG_RE.test(p.slug)) {
          if (!Array.isArray(p.incidents)) p.incidents = [];
          this.statusPages.set(p.slug, p);
        }
      }
      if (Array.isArray(res.data.incidents)) {
        this.incidents = res.data.incidents.slice(0, MAX_INCIDENTS);
      }
    }
  }

  _save() {
    this._ensureLoaded();
    const payload = {
      version: 1,
      updatedAt: new Date().toISOString(),
      monitors: Array.from(this.monitors.values()),
      statusPages: Array.from(this.statusPages.values()),
      incidents: this.incidents.slice(0, MAX_INCIDENTS)
    };
    ssrfGuard.atomicWriteJsonSync(this.storeFile, payload, { mode: 0o600, backup: true });
  }

  /** @param {string | null} [slug] */
  _invalidateCache(slug = null) {
    if (slug) this._htmlCache.delete(slug);
    else this._htmlCache.clear();
  }

  /**
   * Resuelve el puerto local verificado de un proyecto desplegado en Culkibo.
   * Nunca confía en un puerto suministrado por el usuario.
   * @param {string} projectId
   * @returns {number | null}
   */
  _resolveLocalProjectPort(projectId) {
    if (!projectId || typeof projectId !== 'string') return null;
    if (this._resolveProjectPortFn) {
      const p = Number(this._resolveProjectPortFn(projectId));
      return Number.isInteger(p) && p >= 1 && p <= 65535 ? p : null;
    }
    const dm = getDeployManager();
    const port = Number(dm?.store?.[projectId]?.current?.hostPort);
    if (Number.isInteger(port) && port >= 1 && port <= 65535) return port;
    return null;
  }

  /**
   * @param {string | null | undefined} projectId
   * @returns {boolean}
   */
  _isProjectInMaintenance(projectId) {
    if (!projectId) return false;
    if (this._getProjectMaintenanceFn) {
      try { return Boolean(this._getProjectMaintenanceFn(projectId)); } catch (e) { return false; }
    }
    try {
      const pm = getProjectManager();
      const proj = pm && typeof pm.getById === 'function' ? pm.getById(projectId) : null;
      return Boolean(proj && proj.maintenanceMode);
    } catch (e) {
      return false;
    }
  }

  /**
   * Valida y normaliza el destino de un monitor con protección SSRF estricta.
   * @param {{
   *   type: string,
   *   url?: string | null,
   *   host?: string | null,
   *   port?: number | string | null,
   *   allowLocalProject?: boolean,
   *   projectId?: string | null,
   *   healthPath?: string | null
   * }} input
   * @returns {Promise<{
   *   type: 'http' | 'tcp',
   *   url: string,
   *   host: string | null,
   *   port: number | null,
   *   healthPath: string | null,
   *   allowLocalProject: boolean,
   *   projectId: string | null,
   *   pinnedIp: string | null
   * }>}
   */
  async _validateTarget(input) {
    const rawType = String(input.type || 'http').trim().toLowerCase();
    const isManagedAlias = rawType === 'managed_project';
    const type = rawType === 'tcp' ? 'tcp' : (rawType === 'http' || isManagedAlias ? 'http' : '');
    if (!type) {
      throw new Error('Tipo de monitor inválido: usa "http" o "tcp"');
    }

    const allowLocalProject = Boolean(input.allowLocalProject || isManagedAlias);
    const projectId = input.projectId ? String(input.projectId).trim().slice(0, 80) : null;

    if (allowLocalProject) {
      if (!projectId) {
        throw new Error('allowLocalProject requiere un projectId verificado de Culkibo');
      }
      const verifiedPort = this._resolveLocalProjectPort(projectId);
      if (!verifiedPort) {
        throw new Error(`Destino local bloqueado (SSRF): el proyecto "${projectId}" no tiene un puerto desplegado verificado`);
      }

      if (type === 'tcp') {
        if (input.host) {
          const cleanHost = String(input.host).trim().toLowerCase();
          if (cleanHost !== '127.0.0.1' && cleanHost !== 'localhost') {
            throw new Error(`Destino local bloqueado (SSRF): host no permitido "${cleanHost}" para monitor de proyecto local`);
          }
        }
        if (input.port != null && Number(input.port) !== verifiedPort) {
          throw new Error(`Destino local bloqueado (SSRF): el puerto ${input.port} no coincide con el puerto asignado al proyecto (${verifiedPort})`);
        }
        return {
          type: 'tcp',
          url: `tcp://127.0.0.1:${verifiedPort}`,
          host: '127.0.0.1',
          port: verifiedPort,
          healthPath: null,
          allowLocalProject: true,
          projectId,
          pinnedIp: '127.0.0.1'
        };
      }

      // HTTP local project monitor
      let healthPath = '/';
      if (input.url) {
        let parsed;
        try {
          parsed = new URL(String(input.url).trim());
        } catch (e) {
          throw new Error('URL de monitor local malformada');
        }
        if (parsed.protocol !== 'http:') {
          throw new Error('Los monitores locales de proyecto sólo permiten protocolo http:');
        }
        if (parsed.username || parsed.password) {
          throw new Error('No se permiten credenciales incrustadas en la URL del monitor');
        }
        const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
        if (host !== '127.0.0.1' && host !== 'localhost') {
          throw new Error(`Destino local bloqueado (SSRF): el host "${host}" no es loopback del proyecto local`);
        }
        const urlPort = parsed.port ? Number(parsed.port) : 80;
        if (urlPort !== verifiedPort) {
          throw new Error(`Destino local bloqueado (SSRF): el puerto ${urlPort} no coincide con el puerto asignado al proyecto (${verifiedPort})`);
        }
        healthPath = sanitizeHealthPath(`${parsed.pathname || '/'}${parsed.search || ''}`);
      } else if (input.healthPath) {
        healthPath = sanitizeHealthPath(input.healthPath);
      }

      const canonicalUrl = `http://127.0.0.1:${verifiedPort}${healthPath}`;
      await this._assertSafeUrl(canonicalUrl, {
        allowedProtocols: ['http:'],
        allowPrivate: false,
        allowLoopback: true
      });
      return {
        type: 'http',
        url: canonicalUrl,
        host: '127.0.0.1',
        port: verifiedPort,
        healthPath,
        allowLocalProject: true,
        projectId,
        pinnedIp: '127.0.0.1'
      };
    }

    // Monitor externo (HTTP o TCP): SSRF estricto (bloquea loopback, RFC1918, link-local y metadatos cloud)
    if (type === 'http') {
      const rawUrl = String(input.url || '').trim();
      if (!rawUrl) throw new Error('La URL es obligatoria para monitores HTTP');
      const checked = await this._assertSafeUrl(rawUrl, {
        allowedProtocols: ['https:', 'http:'],
        allowPrivate: false,
        allowLoopback: false
      });
      const pinnedIp = checked.addresses.find((a) => net.isIP(a) === 4) || checked.addresses[0] || null;
      return {
        type: 'http',
        url: checked.url.toString(),
        host: checked.url.hostname.toLowerCase().replace(/^\[|\]$/g, ''),
        port: checked.url.port ? Number(checked.url.port) : (checked.url.protocol === 'https:' ? 443 : 80),
        healthPath: null,
        allowLocalProject: false,
        projectId,
        pinnedIp
      };
    }

    // Monitor TCP externo
    let rawHost = input.host ? String(input.host).trim() : '';
    let rawPort = input.port != null ? Number(input.port) : NaN;
    if ((!rawHost || !Number.isInteger(rawPort)) && input.url) {
      const cleaned = String(input.url).trim();
      let parsedTcp;
      try {
        parsedTcp = new URL(cleaned.includes('://') ? cleaned : `tcp://${cleaned}`);
      } catch (e) {
        throw new Error('Destino TCP inválido (usa host + port o tcp://host:puerto)');
      }
      if (parsedTcp.protocol !== 'tcp:' && parsedTcp.protocol !== 'http:' && parsedTcp.protocol !== 'https:') {
        throw new Error(`Protocolo no permitido para monitor TCP: ${parsedTcp.protocol}`);
      }
      if (parsedTcp.username || parsedTcp.password) {
        throw new Error('No se permiten credenciales en destinos TCP');
      }
      rawHost = parsedTcp.hostname.replace(/^\[|\]$/g, '');
      rawPort = parsedTcp.port ? Number(parsedTcp.port) : NaN;
    }

    const host = rawHost.toLowerCase().replace(/^\[|\]$/g, '');
    if (!host || (!net.isIP(host) && !HOSTNAME_RE.test(host)) || /[\s\r\n\0]/.test(host)) {
      throw new Error('Host TCP inválido');
    }
    if (METADATA_HOSTS.has(host)) {
      throw new Error(`Host de metadatos bloqueado por seguridad: ${host}`);
    }
    if (!Number.isInteger(rawPort) || rawPort < 1 || rawPort > 65535) {
      throw new Error('El puerto TCP debe ser un entero entre 1 y 65535');
    }

    const probeUrl = `http://${net.isIP(host) === 6 ? `[${host}]` : host}:${rawPort}/`;
    const checked = await this._assertSafeUrl(probeUrl, {
      allowedProtocols: ['http:'],
      allowPrivate: false,
      allowLoopback: false
    });
    const pinnedIp = checked.addresses.find((a) => net.isIP(a) === 4) || checked.addresses[0] || null;
    if (!pinnedIp || ssrfGuard.isMetadataIp(pinnedIp) || ssrfGuard.isPrivateIp(pinnedIp)) {
      throw new Error(`Destino TCP bloqueado por protección SSRF: ${pinnedIp || host}`);
    }

    return {
      type: 'tcp',
      url: `tcp://${net.isIP(host) === 6 ? `[${host}]` : host}:${rawPort}`,
      host,
      port: rawPort,
      healthPath: null,
      allowLocalProject: false,
      projectId,
      pinnedIp
    };
  }

  /**
   * Valida y normaliza campos comunes de configuración del monitor.
   * @param {any} data
   * @param {any} [existing]
   */
  _normalizeMonitorConfig(data, existing = null) {
    const name = data.name !== undefined
      ? String(data.name || '').trim().slice(0, 80)
      : (existing ? existing.name : '');
    if (!name) throw new Error('El nombre del monitor es obligatorio');

    const publicName = data.publicName !== undefined
      ? String(data.publicName || '').trim().slice(0, 80) || name
      : (existing ? existing.publicName : name);

    const methodRaw = data.method !== undefined
      ? String(data.method || 'GET').trim().toUpperCase()
      : (existing ? existing.method : 'GET');
    if (methodRaw !== 'GET' && methodRaw !== 'HEAD') {
      throw new Error('Método HTTP de monitor inválido: usa GET o HEAD');
    }

    let expectedStatus = existing ? existing.expectedStatus : 200;
    if (data.expectedStatus !== undefined) {
      if (data.expectedStatus === null || data.expectedStatus === '' || data.expectedStatus === 0) {
        expectedStatus = null;
      } else if (Array.isArray(data.expectedStatus)) {
        const list = data.expectedStatus.map((n) => Number(n)).filter((n) => Number.isInteger(n) && n >= 100 && n <= 599);
        if (list.length === 0) throw new Error('expectedStatus debe contener códigos HTTP válidos (100-599)');
        expectedStatus = Array.from(new Set(list)).slice(0, 10);
      } else {
        const code = Number(data.expectedStatus);
        if (!Number.isInteger(code) || code < 100 || code > 599) {
          throw new Error('expectedStatus debe ser un código HTTP entero entre 100 y 599');
        }
        expectedStatus = code;
      }
    }

    const rawKeyword = data.keyword !== undefined ? data.keyword : (data.expectedBody !== undefined ? data.expectedBody : undefined);
    const keyword = rawKeyword !== undefined
      ? (rawKeyword === null || rawKeyword === '' ? null : String(rawKeyword).slice(0, 256))
      : (existing ? existing.keyword : null);

    let maxLatencyMs = existing ? existing.maxLatencyMs : null;
    if (data.maxLatencyMs !== undefined) {
      if (data.maxLatencyMs === null || data.maxLatencyMs === '') {
        maxLatencyMs = null;
      } else {
        const v = Number(data.maxLatencyMs);
        if (!Number.isFinite(v) || v < 10 || v > 60000) {
          throw new Error('maxLatencyMs debe estar entre 10 y 60000 ms');
        }
        maxLatencyMs = Math.round(v);
      }
    }

    const intervalSec = data.intervalSec !== undefined
      ? Number(data.intervalSec)
      : (existing ? existing.intervalSec : 60);
    if (!Number.isFinite(intervalSec) || intervalSec < MIN_INTERVAL_SEC || intervalSec > MAX_INTERVAL_SEC) {
      throw new Error(`intervalSec debe estar entre ${MIN_INTERVAL_SEC} y ${MAX_INTERVAL_SEC} segundos`);
    }

    const timeoutMs = data.timeoutMs !== undefined
      ? Number(data.timeoutMs)
      : (existing ? existing.timeoutMs : 5000);
    if (!Number.isFinite(timeoutMs) || timeoutMs < MIN_TIMEOUT_MS || timeoutMs > MAX_TIMEOUT_MS) {
      throw new Error(`timeoutMs debe estar entre ${MIN_TIMEOUT_MS} y ${MAX_TIMEOUT_MS} ms`);
    }

    const retries = data.retries !== undefined
      ? Number(data.retries)
      : (existing ? existing.retries : 2);
    if (!Number.isInteger(retries) || retries < 1 || retries > 5) {
      throw new Error('retries debe ser un entero entre 1 y 5');
    }

    const enabled = data.enabled !== undefined ? Boolean(data.enabled) : (existing ? existing.enabled : true);
    const isPublic = data.public !== undefined ? Boolean(data.public) : (existing ? existing.public : false);

    return {
      name,
      publicName,
      method: /** @type {'GET' | 'HEAD'} */ (methodRaw),
      expectedStatus,
      keyword,
      maxLatencyMs,
      intervalSec: Math.round(intervalSec),
      timeoutMs: Math.round(timeoutMs),
      retries,
      enabled,
      public: isPublic
    };
  }

  /**
   * Calcula métricas de disponibilidad (24h/7d/30d), latencia p50/p95 y barra de 30 puntos.
   * @param {any} monitor
   * @param {number} [now]
   */
  computeMonitorStats(monitor, now = Date.now()) {
    const checks = Array.isArray(monitor.checks) ? monitor.checks : [];
    const dailyStats = Array.isArray(monitor.dailyStats) ? monitor.dailyStats : [];

    const cutoff24h = now - 24 * 60 * 60 * 1000;
    const recent24h = checks.filter((c) => typeof c.ts === 'number' && c.ts >= cutoff24h);
    const up24h = recent24h.filter((c) => c.status !== 'down').length;
    const uptime24h = recent24h.length > 0 ? Number(((up24h / recent24h.length) * 100).toFixed(2)) : null;

    /**
     * @param {number} days
     */
    const calcWindowUptime = (days) => {
      const cutoffDate = utcDateKey(now - (days - 1) * 24 * 60 * 60 * 1000);
      let total = 0;
      let available = 0;
      for (const d of dailyStats) {
        if (d && typeof d.date === 'string' && d.date >= cutoffDate) {
          total += Number(d.total || 0);
          available += Number(d.up || 0) + Number(d.degraded || 0);
        }
      }
      if (total > 0) return Number(((available / total) * 100).toFixed(2));
      if (checks.length > 0) {
        const cutoffTs = now - days * 24 * 60 * 60 * 1000;
        const win = checks.filter((c) => typeof c.ts === 'number' && c.ts >= cutoffTs);
        if (win.length === 0) return null;
        const avail = win.filter((c) => c.status !== 'down').length;
        return Number(((avail / win.length) * 100).toFixed(2));
      }
      return null;
    };

    const uptime7d = calcWindowUptime(7);
    const uptime30d = calcWindowUptime(30);

    const latencies = checks
      .filter((c) => typeof c.latencyMs === 'number' && Number.isFinite(c.latencyMs) && c.latencyMs >= 0)
      .map((c) => c.latencyMs);
    const p50LatencyMs = percentile(latencies, 50);
    const p95LatencyMs = percentile(latencies, 95);
    const avgLatencyMs = latencies.length > 0
      ? Number((latencies.reduce((s, n) => s + n, 0) / latencies.length).toFixed(2))
      : null;
    const lastCheck = checks.length > 0 ? checks[checks.length - 1] : null;

    // 30-bar history: usa cubos diarios cuando hay > 1 día de datos, o los últimos 30 sondeos
    /** @type {Array<{ status: 'up' | 'degraded' | 'down' | 'nodata', uptimePct: number | null }>} */
    const history30 = [];
    if (dailyStats.length > 1) {
      const byDate = new Map(dailyStats.map((d) => [d.date, d]));
      for (let i = 29; i >= 0; i--) {
        const key = utcDateKey(now - i * 24 * 60 * 60 * 1000);
        const bucket = byDate.get(key);
        if (!bucket || !bucket.total) {
          history30.push({ status: 'nodata', uptimePct: null });
        } else {
          const avail = Number(bucket.up || 0) + Number(bucket.degraded || 0);
          const pct = Number(((avail / bucket.total) * 100).toFixed(2));
          /** @type {'up' | 'degraded' | 'down'} */
          const st = bucket.down > 0 && pct < 95 ? 'down' : (bucket.down > 0 || bucket.degraded > 0 ? 'degraded' : 'up');
          history30.push({ status: st, uptimePct: pct });
        }
      }
    } else {
      const slice = checks.slice(-30);
      const padCount = Math.max(0, 30 - slice.length);
      for (let i = 0; i < padCount; i++) {
        history30.push({ status: 'nodata', uptimePct: null });
      }
      for (const c of slice) {
        /** @type {'up' | 'degraded' | 'down'} */
        const st = c.status === 'down' ? 'down' : (c.status === 'degraded' ? 'degraded' : 'up');
        history30.push({ status: st, uptimePct: st === 'down' ? 0 : 100 });
      }
    }

    return {
      uptime24h,
      uptime7d,
      uptime30d,
      p50LatencyMs,
      p95LatencyMs,
      avgLatencyMs,
      lastLatencyMs: lastCheck ? lastCheck.latencyMs : null,
      checksCount: checks.length,
      history30
    };
  }

  /**
   * Proyección administrativa de un monitor (con estadísticas calculadas).
   * @param {any} m
   */
  _formatAdminMonitor(m) {
    const stats = this.computeMonitorStats(m);
    const activeIncident = m.activeIncidentId
      ? this.incidents.find((inc) => inc.id === m.activeIncidentId) || null
      : null;
    return {
      id: m.id,
      name: m.name,
      publicName: m.publicName || m.name,
      type: m.type,
      url: m.url,
      host: m.host,
      port: m.port,
      method: m.method,
      expectedStatus: m.expectedStatus,
      keyword: m.keyword,
      maxLatencyMs: m.maxLatencyMs,
      intervalSec: m.intervalSec,
      timeoutMs: m.timeoutMs,
      retries: m.retries,
      enabled: m.enabled,
      public: m.public,
      projectId: m.projectId || null,
      allowLocalProject: Boolean(m.allowLocalProject),
      healthPath: m.healthPath || null,
      status: m.status || 'unknown',
      consecutiveFailures: m.consecutiveFailures || 0,
      lastCheckedAt: m.lastCheckedAt || null,
      lastStatusCode: m.lastStatusCode ?? null,
      lastError: m.lastError || null,
      activeIncidentId: m.activeIncidentId || null,
      activeIncident,
      createdAt: m.createdAt,
      updatedAt: m.updatedAt,
      ...stats
    };
  }

  /**
   * Lista monitores (opcionalmente filtrados por `projectId` o `projectIds`).
   * @param {{ projectId?: string | null, projectIds?: string[] | null }} [opts]
   */
  listMonitors(opts = {}) {
    this._ensureLoaded();
    let list = Array.from(this.monitors.values());
    if (opts.projectId) {
      list = list.filter((m) => m.projectId === opts.projectId);
    } else if (Array.isArray(opts.projectIds)) {
      const allowed = new Set(opts.projectIds);
      list = list.filter((m) => m.projectId && allowed.has(m.projectId));
    }
    return list.map((m) => this._formatAdminMonitor(m));
  }

  /** @param {string} id */
  getMonitor(id) {
    this._ensureLoaded();
    const m = this.monitors.get(id);
    return m ? this._formatAdminMonitor(m) : null;
  }

  /**
   * Crea un monitor sintético validando estrictamente SSRF antes de persistir.
   * @param {any} data
   */
  async createMonitor(data = {}) {
    this._ensureLoaded();
    if (this.monitors.size >= MAX_MONITORS) {
      throw new Error(`Límite máximo de ${MAX_MONITORS} monitores alcanzado`);
    }

    const cfg = this._normalizeMonitorConfig(data);
    const target = await this._validateTarget({
      type: data.type || 'http',
      url: data.url,
      host: data.host,
      port: data.port,
      allowLocalProject: data.allowLocalProject,
      projectId: data.projectId,
      healthPath: data.healthPath
    });

    const nowIso = new Date().toISOString();
    const monitor = {
      id: `mon_${crypto.randomBytes(6).toString('hex')}`,
      ...cfg,
      type: target.type,
      url: target.url,
      host: target.host,
      port: target.port,
      healthPath: target.healthPath,
      allowLocalProject: target.allowLocalProject,
      projectId: target.projectId,
      status: 'unknown',
      consecutiveFailures: 0,
      lastCheckedAt: null,
      lastStatusCode: null,
      lastError: null,
      activeIncidentId: null,
      checks: [],
      dailyStats: [],
      createdAt: nowIso,
      updatedAt: nowIso
    };

    this.monitors.set(monitor.id, monitor);
    this._save();
    this._invalidateCache();
    this._syncScheduler();
    return this._formatAdminMonitor(monitor);
  }

  /**
   * Actualiza un monitor existente re-validando SSRF en cualquier cambio de destino.
   * @param {string} id
   * @param {any} patch
   */
  async updateMonitor(id, patch = {}) {
    this._ensureLoaded();
    const existing = this.monitors.get(id);
    if (!existing) {
      const err = new Error(`Monitor no encontrado: ${id}`);
      /** @type {any} */ (err).status = 404;
      throw err;
    }

    const cfg = this._normalizeMonitorConfig(patch, existing);
    const targetChanged =
      patch.type !== undefined ||
      patch.url !== undefined ||
      patch.host !== undefined ||
      patch.port !== undefined ||
      patch.allowLocalProject !== undefined ||
      patch.projectId !== undefined ||
      patch.healthPath !== undefined;

    let target = {
      type: existing.type,
      url: existing.url,
      host: existing.host,
      port: existing.port,
      healthPath: existing.healthPath,
      allowLocalProject: existing.allowLocalProject,
      projectId: existing.projectId
    };

    if (targetChanged) {
      const validated = await this._validateTarget({
        type: patch.type !== undefined ? patch.type : existing.type,
        url: patch.url !== undefined ? patch.url : existing.url,
        host: patch.host !== undefined ? patch.host : existing.host,
        port: patch.port !== undefined ? patch.port : existing.port,
        allowLocalProject: patch.allowLocalProject !== undefined ? patch.allowLocalProject : existing.allowLocalProject,
        projectId: patch.projectId !== undefined ? patch.projectId : existing.projectId,
        healthPath: patch.healthPath !== undefined ? patch.healthPath : existing.healthPath
      });
      target = validated;
    }

    Object.assign(existing, cfg, {
      type: target.type,
      url: target.url,
      host: target.host,
      port: target.port,
      healthPath: target.healthPath,
      allowLocalProject: target.allowLocalProject,
      projectId: target.projectId,
      updatedAt: new Date().toISOString()
    });

    this._save();
    this._invalidateCache();
    this._syncScheduler();
    return this._formatAdminMonitor(existing);
  }

  /**
   * Elimina un monitor y limpia su referencia de las páginas de estado.
   * @param {string} id
   */
  deleteMonitor(id) {
    this._ensureLoaded();
    const existing = this.monitors.get(id);
    if (!existing) {
      const err = new Error(`Monitor no encontrado: ${id}`);
      /** @type {any} */ (err).status = 404;
      throw err;
    }
    this.monitors.delete(id);
    for (const page of this.statusPages.values()) {
      if (Array.isArray(page.monitorIds)) {
        page.monitorIds = page.monitorIds.filter((mid) => mid !== id);
      }
    }
    this._save();
    this._invalidateCache();
    this._syncScheduler();
    return { deleted: true, id };
  }

  /**
   * Ejecuta un sondeo TCP fijado directamente a `pinnedIp` (sin re-resolución DNS).
   * @param {{ pinnedIp: string, port: number, timeoutMs: number }} opts
   * @returns {Promise<{ ok: boolean, latencyMs: number, error: string | null }>}
   */
  _executeTcpProbe({ pinnedIp, port, timeoutMs }) {
    if (this._tcpProbe) {
      return this._tcpProbe({ pinnedIp, port, timeoutMs });
    }
    const start = Date.now();
    return new Promise((resolve) => {
      let settled = false;
      const family = net.isIP(pinnedIp) === 6 ? 6 : 4;
      const socket = net.connect({ host: pinnedIp, port, family });
      const finish = (ok, error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { socket.destroy(); } catch (e) {}
        resolve({ ok, latencyMs: Math.max(0, Date.now() - start), error });
      };
      const timer = setTimeout(() => finish(false, `Tiempo de espera TCP agotado (${timeoutMs} ms)`), timeoutMs);
      if (timer.unref) timer.unref();
      socket.once('connect', () => finish(true, null));
      socket.once('error', (err) => finish(false, formatInternalError(err)));
    });
  }

  /**
   * Actualiza los agregados diarios (máx. 90 días) con el resultado del sondeo.
   * @param {any} monitor
   * @param {{ ts: number, status: 'up' | 'degraded' | 'down', latencyMs: number }} check
   */
  _recordDailyStat(monitor, check) {
    const key = utcDateKey(check.ts);
    if (!Array.isArray(monitor.dailyStats)) monitor.dailyStats = [];
    let bucket = monitor.dailyStats.length > 0 ? monitor.dailyStats[monitor.dailyStats.length - 1] : null;
    if (!bucket || bucket.date !== key) {
      bucket = monitor.dailyStats.find((d) => d.date === key) || null;
      if (!bucket) {
        bucket = { date: key, total: 0, up: 0, degraded: 0, down: 0, latencySumMs: 0, avgMs: 0, p95Ms: 0, _samples: [] };
        monitor.dailyStats.push(bucket);
        if (monitor.dailyStats.length > MAX_DAILY_STATS) {
          monitor.dailyStats = monitor.dailyStats.slice(-MAX_DAILY_STATS);
        }
      }
    }
    bucket.total += 1;
    if (check.status === 'up') bucket.up += 1;
    else if (check.status === 'degraded') bucket.degraded += 1;
    else bucket.down += 1;
    bucket.latencySumMs += check.latencyMs;
    bucket.avgMs = Number((bucket.latencySumMs / bucket.total).toFixed(2));
    if (!Array.isArray(bucket._samples)) bucket._samples = [];
    bucket._samples.push(check.latencyMs);
    if (bucket._samples.length > 64) bucket._samples = bucket._samples.slice(-64);
    bucket.p95Ms = percentile(bucket._samples, 95) ?? bucket.avgMs;
  }

  /**
   * Envía notificación sin bloquear ni propagar errores al ciclo de sondeo.
   * @param {any} payload
   */
  async _emitNotification(payload) {
    const svc = this._notifier || getNotificationService();
    if (!svc || typeof svc.notify !== 'function') return;
    try {
      await svc.notify(payload);
    } catch (e) {}
  }

  /**
   * Ejecuta un sondeo individual (re-validando SSRF en cada probe), actualiza
   * el ring buffer acotado (288), gestiona incidentes y dispara notificaciones
   * en transiciones de estado (`down` / `recovered`).
   * @param {string} id
   */
  async runCheck(id) {
    this._ensureLoaded();
    const monitor = this.monitors.get(id);
    if (!monitor) {
      const err = new Error(`Monitor no encontrado: ${id}`);
      /** @type {any} */ (err).status = 404;
      throw err;
    }

    const start = Date.now();
    /** @type {'up' | 'degraded' | 'down'} */
    let status = 'down';
    /** @type {number | null} */
    let statusCode = null;
    /** @type {string | null} */
    let errorMsg = null;
    let latencyMs = 0;

    try {
      // Re-validar SSRF y/o puerto local en CADA sondeo (corta DNS rebinding y cambios de puerto)
      const validated = await this._validateTarget({
        type: monitor.type,
        url: monitor.allowLocalProject ? undefined : monitor.url,
        host: monitor.allowLocalProject ? undefined : monitor.host,
        port: monitor.allowLocalProject ? undefined : monitor.port,
        allowLocalProject: monitor.allowLocalProject,
        projectId: monitor.projectId,
        healthPath: monitor.healthPath || '/'
      });

      if (validated.type === 'tcp') {
        const res = await this._executeTcpProbe({
          pinnedIp: validated.pinnedIp || '127.0.0.1',
          port: /** @type {number} */ (validated.port),
          timeoutMs: monitor.timeoutMs
        });
        latencyMs = res.latencyMs;
        if (res.ok) {
          status = (monitor.maxLatencyMs != null && latencyMs > monitor.maxLatencyMs) ? 'degraded' : 'up';
        } else {
          status = 'down';
          errorMsg = res.error || 'Error de conexión TCP';
        }
      } else {
        const res = await this._safeFetch(validated.url, {
          method: monitor.method || 'GET',
          timeoutMs: monitor.timeoutMs,
          maxRedirects: validated.allowLocalProject ? 0 : 2,
          maxBytes: MAX_RESPONSE_BYTES,
          allowPrivate: false,
          allowLoopback: validated.allowLocalProject,
          headers: { 'User-Agent': 'Culkibo-Uptime/1.0' }
        });
        latencyMs = Math.max(0, Date.now() - start);
        statusCode = res.status;

        let statusMatch = false;
        if (monitor.expectedStatus === null || monitor.expectedStatus === undefined) {
          statusMatch = res.status >= 200 && res.status < 300;
        } else if (Array.isArray(monitor.expectedStatus)) {
          statusMatch = monitor.expectedStatus.includes(res.status);
        } else {
          statusMatch = res.status === monitor.expectedStatus;
        }

        if (!statusMatch) {
          status = 'down';
          errorMsg = `Código HTTP inesperado: ${res.status} (esperado ${Array.isArray(monitor.expectedStatus) ? monitor.expectedStatus.join('/') : (monitor.expectedStatus ?? '2xx')})`;
        } else if (monitor.keyword) {
          const text = typeof res.text === 'function' ? res.text() : '';
          if (!text.includes(monitor.keyword)) {
            status = 'down';
            errorMsg = 'La respuesta no contiene la palabra clave esperada';
          } else {
            status = (monitor.maxLatencyMs != null && latencyMs > monitor.maxLatencyMs) ? 'degraded' : 'up';
          }
        } else {
          status = (monitor.maxLatencyMs != null && latencyMs > monitor.maxLatencyMs) ? 'degraded' : 'up';
        }
      }
    } catch (err) {
      latencyMs = Math.max(0, Date.now() - start);
      status = 'down';
      errorMsg = formatInternalError(err);
    }

    const now = Date.now();
    const nowIso = new Date(now).toISOString();
    const check = {
      ts: now,
      status,
      ok: status !== 'down',
      statusCode,
      latencyMs,
      error: errorMsg
    };

    if (!Array.isArray(monitor.checks)) monitor.checks = [];
    monitor.checks.push(check);
    if (monitor.checks.length > MAX_CHECKS_PER_MONITOR) {
      monitor.checks = monitor.checks.slice(-MAX_CHECKS_PER_MONITOR);
    }
    this._recordDailyStat(monitor, check);

    monitor.lastCheckedAt = nowIso;
    monitor.lastStatusCode = statusCode;
    monitor.lastError = errorMsg;

    /** @type {'opened' | 'resolved' | null} */
    let incidentTransition = null;
    /** @type {any} */
    let incidentRecord = null;

    if (status === 'down') {
      monitor.consecutiveFailures = (monitor.consecutiveFailures || 0) + 1;
      if (monitor.consecutiveFailures >= (monitor.retries || 2)) {
        monitor.status = 'down';
        if (!monitor.activeIncidentId) {
          incidentRecord = {
            id: `inc_${crypto.randomBytes(6).toString('hex')}`,
            monitorId: monitor.id,
            displayName: monitor.publicName || monitor.name,
            status: 'open',
            startedAt: nowIso,
            resolvedAt: null,
            durationMs: null,
            failureCount: monitor.consecutiveFailures,
            internalReason: errorMsg || 'Sondeo fallido'
          };
          this.incidents.unshift(incidentRecord);
          if (this.incidents.length > MAX_INCIDENTS) {
            this.incidents = this.incidents.slice(0, MAX_INCIDENTS);
          }
          monitor.activeIncidentId = incidentRecord.id;
          incidentTransition = 'opened';
          this.emit('incident_opened', { monitorId: monitor.id, incident: incidentRecord });
          await this._emitNotification({
            event: 'uptime_down',
            level: 'error',
            title: `Monitor caído: ${monitor.name}`,
            message: `El monitor "${monitor.name}" falló ${monitor.consecutiveFailures} comprobaciones consecutivas (${errorMsg || 'sin respuesta'}).`,
            projectId: monitor.projectId || null,
            projectName: monitor.name
          });
        } else {
          const openInc = this.incidents.find((inc) => inc.id === monitor.activeIncidentId);
          if (openInc) openInc.failureCount = monitor.consecutiveFailures;
        }
      } else {
        // Por debajo del umbral de reintentos: marcar degradado sin disparar falsa alarma
        if (monitor.status !== 'down') monitor.status = 'degraded';
      }
    } else {
      const hadOpenIncident = Boolean(monitor.activeIncidentId);
      monitor.consecutiveFailures = 0;
      monitor.status = status; // 'up' o 'degraded' (latencia alta)
      if (hadOpenIncident) {
        const openInc = this.incidents.find((inc) => inc.id === monitor.activeIncidentId);
        if (openInc) {
          openInc.status = 'resolved';
          openInc.resolvedAt = nowIso;
          openInc.durationMs = Math.max(0, now - Date.parse(openInc.startedAt));
          incidentRecord = openInc;
        }
        monitor.activeIncidentId = null;
        incidentTransition = 'resolved';
        this.emit('incident_resolved', { monitorId: monitor.id, incident: incidentRecord });
        await this._emitNotification({
          event: 'uptime_recovered',
          level: 'success',
          title: `Monitor recuperado: ${monitor.name}`,
          message: `El monitor "${monitor.name}" ha vuelto a estar operativo (${latencyMs} ms).`,
          projectId: monitor.projectId || null,
          projectName: monitor.name
        });
      }
    }

    monitor.updatedAt = nowIso;
    this._save();
    this._invalidateCache();

    const stats = this.computeMonitorStats(monitor, now);
    this.emit('check', { monitorId: monitor.id, check, status: monitor.status, incidentTransition });
    return {
      monitorId: monitor.id,
      status: monitor.status,
      check,
      incidentTransition,
      incident: incidentRecord,
      stats
    };
  }

  /**
   * Lista incidentes administrativos recientes.
   * @param {{ monitorId?: string | null, status?: string | null, limit?: number }} [opts]
   */
  listIncidents(opts = {}) {
    this._ensureLoaded();
    let list = this.incidents;
    if (opts.monitorId) list = list.filter((i) => i.monitorId === opts.monitorId);
    if (opts.status) list = list.filter((i) => i.status === opts.status);
    const limit = Math.max(1, Math.min(MAX_INCIDENTS, Number(opts.limit) || 50));
    return list.slice(0, limit).map((i) => ({ ...i }));
  }

  // -------------------------------------------------------------------------
  // Páginas públicas de estado (`/status/:slug`) — cero fugas de datos internos
  // -------------------------------------------------------------------------

  listStatusPages() {
    this._ensureLoaded();
    return Array.from(this.statusPages.values()).map((p) => ({
      ...p,
      monitorIds: [...(p.monitorIds || [])],
      incidents: [...(p.incidents || [])]
    }));
  }

  /**
   * Crea o actualiza una página pública de estado.
   * @param {any} data
   */
  saveStatusPage(data = {}) {
    this._ensureLoaded();
    const slug = String(data.slug || '').trim().toLowerCase();
    if (!SLUG_RE.test(slug)) {
      throw new Error('Slug inválido: usa entre 2 y 49 caracteres [a-z0-9-] empezando por letra o número');
    }
    const existing = this.statusPages.get(slug);
    if (!existing && this.statusPages.size >= MAX_STATUS_PAGES) {
      throw new Error(`Límite máximo de ${MAX_STATUS_PAGES} páginas de estado alcanzado`);
    }

    const title = String(data.title !== undefined ? data.title : (existing?.title || '')).trim().slice(0, 100);
    if (!title) throw new Error('El título de la página de estado es obligatorio');

    const description = String(data.description !== undefined ? data.description : (existing?.description || '')).trim().slice(0, 300);

    const accentColor = data.accentColor !== undefined
      ? String(data.accentColor).trim()
      : (existing?.accentColor || '#0f172a');
    if (!HEX_COLOR_RE.test(accentColor)) {
      throw new Error('accentColor debe ser un color hexadecimal válido (#RRGGBB)');
    }

    /** @type {string[]} */
    let monitorIds = existing ? [...(existing.monitorIds || [])] : [];
    if (data.monitorIds !== undefined) {
      if (!Array.isArray(data.monitorIds)) throw new Error('monitorIds debe ser un array');
      monitorIds = Array.from(new Set(data.monitorIds.map((x) => String(x || '').trim()).filter(Boolean))).slice(0, 50);
    }

    const customDomain = data.customDomain !== undefined
      ? (data.customDomain ? String(data.customDomain).trim().toLowerCase().slice(0, 253) : null)
      : (existing?.customDomain || null);
    if (customDomain && !HOSTNAME_RE.test(customDomain)) {
      throw new Error('customDomain inválido');
    }

    const published = data.published !== undefined ? Boolean(data.published) : (existing ? existing.published : true);
    const nowIso = new Date().toISOString();

    const page = {
      slug,
      title,
      description,
      accentColor,
      monitorIds,
      customDomain,
      published,
      incidents: existing && Array.isArray(existing.incidents) ? existing.incidents : [],
      createdAt: existing ? existing.createdAt : nowIso,
      updatedAt: nowIso
    };

    this.statusPages.set(slug, page);
    this._save();
    this._invalidateCache(slug);
    return { ...page, monitorIds: [...page.monitorIds], incidents: [...page.incidents] };
  }

  /**
   * Publica un incidente manual en una página de estado pública.
   * @param {string} slug
   * @param {{ title: string, severity?: string, message?: string }} data
   */
  publishStatusIncident(slug, data) {
    this._ensureLoaded();
    const cleanSlug = String(slug || '').trim().toLowerCase();
    const page = this.statusPages.get(cleanSlug);
    if (!page) {
      const err = new Error(`Página de estado no encontrada: ${cleanSlug}`);
      /** @type {any} */ (err).status = 404;
      throw err;
    }
    const title = String(data?.title || '').trim().slice(0, 120);
    if (!title) throw new Error('El título del incidente es obligatorio');
    const sevRaw = String(data?.severity || 'minor').toLowerCase();
    const severity = ['minor', 'major', 'critical', 'maintenance'].includes(sevRaw) ? sevRaw : 'minor';
    const message = String(data?.message || '').trim().slice(0, 500);

    const inc = {
      id: `pinc_${crypto.randomBytes(5).toString('hex')}`,
      title,
      severity,
      message,
      status: 'open',
      startedAt: new Date().toISOString(),
      resolvedAt: null
    };
    if (!Array.isArray(page.incidents)) page.incidents = [];
    page.incidents.unshift(inc);
    if (page.incidents.length > 30) page.incidents = page.incidents.slice(0, 30);
    page.updatedAt = new Date().toISOString();
    this._save();
    this._invalidateCache(cleanSlug);
    return { ...inc };
  }

  /**
   * Resuelve un incidente manual publicado en una página de estado.
   * @param {string} slug
   * @param {string} incidentId
   */
  resolveStatusIncident(slug, incidentId) {
    this._ensureLoaded();
    const cleanSlug = String(slug || '').trim().toLowerCase();
    const page = this.statusPages.get(cleanSlug);
    if (!page) {
      const err = new Error(`Página de estado no encontrada: ${cleanSlug}`);
      /** @type {any} */ (err).status = 404;
      throw err;
    }
    const inc = (page.incidents || []).find((i) => i.id === incidentId);
    if (!inc) {
      const err = new Error(`Incidente no encontrado: ${incidentId}`);
      /** @type {any} */ (err).status = 404;
      throw err;
    }
    inc.status = 'resolved';
    inc.resolvedAt = new Date().toISOString();
    page.updatedAt = new Date().toISOString();
    this._save();
    this._invalidateCache(cleanSlug);
    return { ...inc };
  }

  /** @param {string} slug */
  deleteStatusPage(slug) {
    this._ensureLoaded();
    const cleanSlug = String(slug || '').trim().toLowerCase();
    if (!this.statusPages.has(cleanSlug)) {
      const err = new Error(`Página de estado no encontrada: ${cleanSlug}`);
      /** @type {any} */ (err).status = 404;
      throw err;
    }
    this.statusPages.delete(cleanSlug);
    this._save();
    this._invalidateCache(cleanSlug);
    return { deleted: true, slug: cleanSlug };
  }

  /**
   * Construye la proyección estrictamente pública de una página de estado.
   * JAMÁS incluye URLs internas, IPs, puertos, hostnames, IDs internos ni errores crudos.
   * @param {string} slug
   */
  getPublicStatusData(slug) {
    this._ensureLoaded();
    const cleanSlug = String(slug || '').trim().toLowerCase();
    if (!SLUG_RE.test(cleanSlug)) return null;
    const page = this.statusPages.get(cleanSlug);
    if (!page || !page.published) return null;

    const now = Date.now();
    /** @type {any[]} */
    let selected = [];
    if (Array.isArray(page.monitorIds) && page.monitorIds.length > 0) {
      for (const mid of page.monitorIds) {
        const m = this.monitors.get(mid);
        if (m && m.public === true) selected.push(m);
      }
    } else {
      selected = Array.from(this.monitors.values()).filter((m) => m.public === true);
    }

    let hasDown = false;
    let hasDegraded = false;
    let hasMaintenance = false;
    /** @type {Array<{ title: string, severity: string, message: string, status: string, startedAt: string, displayName?: string }>} */
    const activeIncidents = [];

    const services = selected.map((m) => {
      const stats = this.computeMonitorStats(m, now);
      const inMaintenance = this._isProjectInMaintenance(m.projectId);
      const displayName = String(m.publicName || m.name || 'Servicio').slice(0, 80);

      /** @type {'up' | 'degraded' | 'down' | 'maintenance' | 'unknown'} */
      let publicStatus = 'unknown';
      if (inMaintenance) {
        publicStatus = 'maintenance';
        hasMaintenance = true;
      } else if (m.status === 'down') {
        publicStatus = 'down';
        hasDown = true;
      } else if (m.status === 'degraded') {
        publicStatus = 'degraded';
        hasDegraded = true;
      } else if (m.status === 'up') {
        publicStatus = 'up';
      }

      if (m.activeIncidentId && !inMaintenance) {
        const inc = this.incidents.find((i) => i.id === m.activeIncidentId && i.status === 'open');
        if (inc) {
          // Proyección segura: nunca exponer `internalReason`, URLs, IPs ni códigos de error de red
          activeIncidents.push({
            displayName,
            title: `Interrupción detectada en ${displayName}`,
            severity: 'major',
            message: 'El servicio presenta una interrupción temporal. Monitorización activa.',
            status: 'open',
            startedAt: inc.startedAt
          });
        }
      }

      return {
        displayName,
        status: publicStatus,
        uptime24h: stats.uptime24h,
        uptime7d: stats.uptime7d,
        uptime30d: stats.uptime30d,
        p50LatencyMs: stats.p50LatencyMs,
        p95LatencyMs: stats.p95LatencyMs,
        history30: stats.history30.map((bar) => ({
          status: bar.status,
          uptimePct: bar.uptimePct
        }))
      };
    });

    for (const pinc of page.incidents || []) {
      if (pinc && pinc.status === 'open') {
        if (pinc.severity === 'maintenance') hasMaintenance = true;
        else if (pinc.severity === 'critical' || pinc.severity === 'major') hasDown = true;
        else hasDegraded = true;
        activeIncidents.push({
          title: String(pinc.title || 'Aviso de estado').slice(0, 120),
          severity: String(pinc.severity || 'minor'),
          message: String(pinc.message || '').slice(0, 500),
          status: 'open',
          startedAt: pinc.startedAt
        });
      }
    }

    /** @type {'operational' | 'degraded' | 'outage' | 'maintenance'} */
    const overallStatus = hasDown
      ? 'outage'
      : (hasDegraded ? 'degraded' : (hasMaintenance ? 'maintenance' : 'operational'));

    const uptimes = services.map((s) => s.uptime30d).filter((v) => typeof v === 'number');
    const overallUptime30d = uptimes.length > 0
      ? Number((uptimes.reduce((a, b) => a + b, 0) / uptimes.length).toFixed(2))
      : null;

    return {
      slug: page.slug,
      title: page.title,
      description: page.description || '',
      accentColor: HEX_COLOR_RE.test(page.accentColor || '') ? page.accentColor : '#0f172a',
      overallStatus,
      uptime30d: overallUptime30d,
      maintenanceActive: hasMaintenance,
      services,
      activeIncidents,
      updatedAt: new Date(now).toISOString()
    };
  }

  /**
   * Construye y cachea (15 s, máx. 50 slugs) la página HTML pública cero-dependencias.
   * @param {string} slug
   * @returns {{ html: string, buffer: Buffer, etag: string, headers: Record<string, string> } | null}
   */
  renderPublicStatusResponse(slug) {
    this._ensureLoaded();
    const cleanSlug = String(slug || '').trim().toLowerCase();
    if (!SLUG_RE.test(cleanSlug)) return null;

    const now = Date.now();
    const cached = this._htmlCache.get(cleanSlug);
    if (cached && now - cached.createdAt < HTML_CACHE_TTL_MS) {
      return {
        html: cached.html,
        buffer: cached.buffer,
        etag: cached.etag,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Security-Policy': PUBLIC_STATUS_CSP,
          'Cache-Control': 'public, max-age=15',
          'X-Content-Type-Options': 'nosniff',
          'Referrer-Policy': 'no-referrer',
          'ETag': cached.etag
        }
      };
    }

    const data = this.getPublicStatusData(cleanSlug);
    if (!data) return null;

    const bannerMap = {
      operational: { label: 'Todos los sistemas operativos', bg: '#ecfdf5', border: '#a7f3d0', text: '#065f46', dot: '#10b981' },
      degraded: { label: 'Rendimiento degradado en algunos servicios', bg: '#fffbeb', border: '#fde68a', text: '#92400e', dot: '#f59e0b' },
      outage: { label: 'Interrupción activa detectada', bg: '#fef2f2', border: '#fecaca', text: '#991b1b', dot: '#ef4444' },
      maintenance: { label: 'Mantenimiento programado en curso', bg: '#eff6ff', border: '#bfdbfe', text: '#1e40af', dot: '#3b82f6' }
    };
    const banner = bannerMap[data.overallStatus] || bannerMap.operational;

    const statusBadge = (st) => {
      if (st === 'up') return { label: 'Operativo', color: '#059669', bg: '#ecfdf5' };
      if (st === 'degraded') return { label: 'Degradado', color: '#d97706', bg: '#fffbeb' };
      if (st === 'down') return { label: 'Caído', color: '#dc2626', bg: '#fef2f2' };
      if (st === 'maintenance') return { label: 'Mantenimiento', color: '#2563eb', bg: '#eff6ff' };
      return { label: 'Sin datos', color: '#64748b', bg: '#f1f5f9' };
    };

    const barColor = (st) => {
      if (st === 'up') return '#10b981';
      if (st === 'degraded') return '#f59e0b';
      if (st === 'down') return '#ef4444';
      return '#e2e8f0';
    };

    const servicesHtml = data.services.length === 0
      ? '<div class="empty">No hay servicios públicos configurados todavía.</div>'
      : data.services.map((svc) => {
          const badge = statusBadge(svc.status);
          const pctText = svc.uptime30d != null
            ? `${svc.uptime30d.toFixed(2)}%`
            : (svc.uptime24h != null ? `${svc.uptime24h.toFixed(2)}%` : '—');
          const latencyText = svc.p50LatencyMs != null ? `${Math.round(svc.p50LatencyMs)} ms p50` : '';
          const barsHtml = svc.history30
            .map((b) => `<span class="bar" style="background:${barColor(b.status)}" title="${escapeHtml(b.status)}"></span>`)
            .join('');
          return `<article class="svc">
  <div class="svc-head">
    <span class="svc-name">${escapeHtml(svc.displayName)}</span>
    <span class="badge" style="color:${badge.color};background:${badge.bg}">${escapeHtml(badge.label)}</span>
  </div>
  <div class="bars" aria-label="Historial de 30 periodos">${barsHtml}</div>
  <div class="svc-meta">
    <span>30 periodos</span>
    <span class="num">${escapeHtml(pctText)} disponibilidad${latencyText ? ` · ${escapeHtml(latencyText)}` : ''}</span>
  </div>
</article>`;
        }).join('\n');

    const incidentsHtml = data.activeIncidents.length === 0
      ? ''
      : `<section class="incidents">
  <h2>Incidentes activos</h2>
  ${data.activeIncidents.map((inc) => `<div class="inc">
    <div class="inc-title">${escapeHtml(inc.title)}</div>
    <p class="inc-msg">${escapeHtml(inc.message)}</p>
    <div class="inc-time">Inicio: ${escapeHtml(inc.startedAt)}</div>
  </div>`).join('\n')}
</section>`;

    const html = `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${PUBLIC_STATUS_CSP}">
<title>${escapeHtml(data.title)} — Estado del servicio</title>
<style>
:root{--accent:${data.accentColor};--bg:#f8fafc;--card:#ffffff;--border:#e2e8f0;--ink:#0f172a;--muted:#64748b}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Inter,sans-serif;background:var(--bg);color:var(--ink);line-height:1.5;-webkit-font-smoothing:antialiased}
.wrap{max-width:780px;margin:0 auto;padding:40px 20px 64px}
header{margin-bottom:24px}
h1{margin:0 0 6px;font-size:24px;font-weight:650;letter-spacing:-0.02em;color:var(--accent)}
.desc{margin:0;color:var(--muted);font-size:14px}
.banner{display:flex;align-items:center;gap:12px;padding:16px 20px;border-radius:12px;border:1px solid ${banner.border};background:${banner.bg};color:${banner.text};font-weight:600;margin-bottom:24px}
.dot{width:10px;height:10px;border-radius:50%;background:${banner.dot};flex-shrink:0}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;overflow:hidden}
.svc{padding:18px 20px;border-bottom:1px solid var(--border)}
.svc:last-child{border-bottom:0}
.svc-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px}
.svc-name{font-weight:600;font-size:15px}
.badge{font-size:12px;font-weight:600;padding:3px 10px;border-radius:999px}
.bars{display:grid;grid-template-columns:repeat(30,1fr);gap:3px;height:28px;margin-bottom:8px}
.bar{border-radius:3px;display:block;height:100%}
.svc-meta{display:flex;justify-content:space-between;font-size:12px;color:var(--muted)}
.num{font-variant-numeric:tabular-nums}
.incidents{margin-bottom:24px}
.incidents h2{font-size:14px;text-transform:uppercase;letter-spacing:0.05em;color:var(--muted);margin:0 0 10px}
.inc{background:var(--card);border:1px solid #fecaca;border-left:4px solid #ef4444;border-radius:10px;padding:14px 16px;margin-bottom:10px}
.inc-title{font-weight:600;font-size:14px;margin-bottom:4px}
.inc-msg{margin:0 0 6px;font-size:13px;color:#334155}
.inc-time{font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}
.empty{padding:32px 20px;text-align:center;color:var(--muted);font-size:14px}
footer{margin-top:28px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;font-size:12px;color:var(--muted)}
</style>
</head>
<body>
<main class="wrap">
  <header>
    <h1>${escapeHtml(data.title)}</h1>
    ${data.description ? `<p class="desc">${escapeHtml(data.description)}</p>` : ''}
  </header>
  <div class="banner" role="status"><span class="dot"></span><span>${escapeHtml(banner.label)}</span></div>
  ${incidentsHtml}
  <section class="card" aria-label="Servicios monitorizados">
    ${servicesHtml}
  </section>
  <footer>
    <span>Actualizado: <span class="num">${escapeHtml(data.updatedAt)}</span></span>
    <span>Culkibo Status</span>
  </footer>
</main>
</body>
</html>`;

    const buffer = Buffer.from(html, 'utf8');
    const etag = `"${crypto.createHash('sha1').update(buffer).digest('hex').slice(0, 16)}"`;

    if (this._htmlCache.size >= MAX_HTML_CACHE_ENTRIES) {
      const oldestKey = this._htmlCache.keys().next().value;
      if (oldestKey) this._htmlCache.delete(oldestKey);
    }
    this._htmlCache.set(cleanSlug, { html, buffer, etag, createdAt: now });

    return {
      html,
      buffer,
      etag,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': PUBLIC_STATUS_CSP,
        'Cache-Control': 'public, max-age=15',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'ETag': etag
      }
    };
  }

  /**
   * Devuelve el HTML público de estado para `slug` (o `null` si no existe / no publicado).
   * @param {string} slug
   * @returns {string | null}
   */
  renderPublicStatusHtml(slug) {
    const res = this.renderPublicStatusResponse(slug);
    return res ? res.html : null;
  }

  /**
   * Genera una insignia SVG pública ligera para incrustar estado en READMEs.
   * @param {string} slug
   * @returns {string | null}
   */
  renderBadgeSvg(slug) {
    const data = this.getPublicStatusData(slug);
    if (!data) return null;
    const statusMap = {
      operational: { text: 'operativo', color: '#10b981' },
      degraded: { text: 'degradado', color: '#f59e0b' },
      outage: { text: 'caído', color: '#ef4444' },
      maintenance: { text: 'mantenimiento', color: '#3b82f6' }
    };
    const meta = statusMap[data.overallStatus] || statusMap.operational;
    const rightText = data.uptime30d != null ? `${meta.text} · ${data.uptime30d.toFixed(1)}%` : meta.text;
    const leftText = 'estado';
    const leftW = 58;
    const rightW = Math.max(82, rightText.length * 7 + 16);
    const totalW = leftW + rightW;
    return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalW}" height="20" role="img" aria-label="${escapeHtml(leftText)}: ${escapeHtml(rightText)}">
  <rect width="${leftW}" height="20" rx="3" fill="#0f172a"/>
  <rect x="${leftW}" width="${rightW}" height="20" rx="3" fill="${meta.color}"/>
  <g fill="#ffffff" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">
    <text x="${Math.round(leftW / 2)}" y="14">${escapeHtml(leftText)}</text>
    <text x="${leftW + Math.round(rightW / 2)}" y="14">${escapeHtml(rightText)}</text>
  </g>
</svg>`;
  }

  // -------------------------------------------------------------------------
  // Planificador perezoso (0 timers si no hay monitores habilitados)
  // -------------------------------------------------------------------------

  _hasEnabledMonitors() {
    for (const m of this.monitors.values()) {
      if (m.enabled) return true;
    }
    return false;
  }

  _syncScheduler() {
    if (this._stopped || !this._autoStart) return;
    if (this._hasEnabledMonitors()) {
      this._startTimer();
    } else {
      this._clearTimer();
    }
  }

  _startTimer() {
    if (this._timer) return;
    this._timer = setInterval(() => {
      this._tick().catch(() => {});
    }, SCHEDULER_TICK_MS);
    if (this._timer.unref) this._timer.unref();
  }

  _clearTimer() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
  }

  /** Arranca el planificador perezosamente sólo si existe >= 1 monitor habilitado. */
  start() {
    this._stopped = false;
    this._ensureLoaded();
    if (this._hasEnabledMonitors()) {
      this._startTimer();
    }
    return { running: Boolean(this._timer), enabledMonitors: Array.from(this.monitors.values()).filter((m) => m.enabled).length };
  }

  /** Detiene limpiamente el planificador y libera temporizadores. */
  stop() {
    this._stopped = true;
    this._clearTimer();
  }

  shutdown() {
    this.stop();
  }

  async _tick() {
    if (this._stopped) return;
    this._ensureLoaded();
    const now = Date.now();
    /** @type {string[]} */
    const dueIds = [];
    for (const m of this.monitors.values()) {
      if (!m.enabled || this._inFlightChecks.has(m.id)) continue;
      const lastTs = m.lastCheckedAt ? Date.parse(m.lastCheckedAt) : 0;
      const intervalMs = Math.max(MIN_INTERVAL_SEC, Number(m.intervalSec || 60)) * 1000;
      if (!lastTs || now - lastTs >= intervalMs) {
        dueIds.push(m.id);
      }
    }
    if (dueIds.length === 0) return;

    // Concurrencia acotada (máx. 8 sondeos simultáneos)
    let cursor = 0;
    const workerCount = Math.min(MAX_CONCURRENT_PROBES, dueIds.length);
    const workers = Array.from({ length: workerCount }, async () => {
      while (cursor < dueIds.length && !this._stopped) {
        const id = dueIds[cursor++];
        this._inFlightChecks.add(id);
        try {
          await this.runCheck(id);
        } catch (e) {
        } finally {
          this._inFlightChecks.delete(id);
        }
      }
    });
    await Promise.allSettled(workers);
  }
}

const instance = /** @type {any} */ (new UptimeMonitor());
instance.UptimeMonitor = UptimeMonitor;
instance.PUBLIC_STATUS_CSP = PUBLIC_STATUS_CSP;
instance.escapeHtml = escapeHtml;
instance.SLUG_RE = SLUG_RE;

module.exports = instance;
