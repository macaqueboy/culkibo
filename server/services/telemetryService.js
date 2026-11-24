const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { atomicWriteJsonSync, loadJsonWithBackupSync, assertSafeUrl } = require('./ssrfGuard');

/**
 * Servicio de telemetría y diagnóstico automático de Culkibo (cero dependencias externas).
 *
 * Filosofía:
 *  - Activado por defecto en despliegues públicos para detectar fallos reales,
 *    crashes y puntos de mejora en campo, con opt-out instantáneo en 1 clic
 *    (Ajustes, `culkibo telemetry disable`, `CULKIBO_TELEMETRY=0` o `DO_NOT_TRACK=1`).
 *  - Privacidad por diseño: jamás recopila nombres de proyectos, dominios de usuario,
 *    variables de entorno, contraseñas, tokens, rutas locales con usuario, IPs ni emails.
 *  - Cero impacto en estabilidad: búfer circular acotado, dedup/plegado por fingerprint,
 *    circuit-breaker exponencial (hasta 6 h), timeouts cortos (4 s) y timers `.unref()`.
 *  - Auto-desactivado en tests/CI (`NODE_ENV=test`, `CI=true`) salvo bandera explícita de test.
 */

const SCHEMA_VERSION = 1;
const DEFAULT_ENDPOINT = 'https://telemetry.culkibo.dev/v1/ingest';
const APP_VERSION = (() => {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf8'));
    return String(pkg.version || '1.0.0');
  } catch (e) {
    return '1.0.0';
  }
})();

const MAX_QUEUE_EVENTS = 50;
const MAX_BATCH_BYTES = 32 * 1024;
const DEDUP_WINDOW_MS = 15 * 60 * 1000;
const FLUSH_INTERVAL_MS = 60 * 1000;
const HEARTBEAT_INITIAL_DELAY_MS = 60 * 1000;
const HEARTBEAT_INTERVAL_MS = 24 * 60 * 60 * 1000;
const HTTP_TIMEOUT_MS = 4000;

const ALLOWED_VIEWS = new Set([
  'overview', 'projects', 'project_detail', 'metrics', 'import', 'domains',
  'databases', 'catalog', 'ai', 'global_logs', 'mcp', 'observability',
  'settings', 'wordpress', 'coolify', 'importer', 'unknown'
]);

const SAFE_DOMAINS = new Set([
  'localhost', '127.0.0.1', '0.0.0.0', 'culkibo.dev', 'telemetry.culkibo.dev',
  'github.com', 'api.github.com', 'docker.io', 'ghcr.io', 'npmjs.org',
  'registry.npmjs.org', 'nodejs.org', 'caddyserver.com', 'cloudflare.com', 'api.cloudflare.com'
]);

const SENSITIVE_KEY_RE = /(token|secret|password|passwd|apikey|api_key|private|auth|cookie|passphrase|credential|envvars|webhook|email|hostname|domain|ip|dsn|connectionstring)/i;

const PRIORITY_RANK = {
  server_crash: 4,
  client_error: 3,
  operation_failure: 3,
  api_error_5xx: 2,
  instance_heartbeat: 1,
  feature_usage: 0
};

function resolveDataDir() {
  return process.env.CULKIBO_DATA_DIR
    ? path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data')
    : path.resolve(__dirname, '..', '..', 'data');
}

function isFalsyEnv(val) {
  if (val === undefined || val === null) return false;
  const s = String(val).trim().toLowerCase();
  return s === '0' || s === 'false' || s === 'off' || s === 'no' || s === 'disabled';
}

function isTruthyEnv(val) {
  if (val === undefined || val === null) return false;
  const s = String(val).trim().toLowerCase();
  return s === '1' || s === 'true' || s === 'on' || s === 'yes';
}

function isRunningUnderTests() {
  if (isTruthyEnv(process.env.CULKIBO_TELEMETRY_ALLOW_IN_TEST)) return false;
  if (process.env.NODE_ENV === 'test') return true;
  if (isTruthyEnv(process.env.CI)) return true;
  const argvJoined = (process.argv || []).join(' ').toLowerCase();
  if (/[\\/](tests|bench)[\\/]/.test(argvJoined)) return true;
  return false;
}

/**
 * Redacta en orden estricto claves PEM, tokens, credenciales en URLs, emails,
 * IPs, dominios de usuario y rutas absolutas del sistema operativo.
 * @param {any} input
 * @param {number} [maxLen]
 * @returns {string}
 */
function scrubText(input, maxLen = 400) {
  if (input === null || input === undefined) return '';
  let s = String(input);

  // 1. Claves privadas PEM
  s = s.replace(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, '<pem>');
  // 2. Cabeceras Authorization / JWT
  s = s.replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, '$1 <redacted>');
  s = s.replace(/\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, '<jwt>');
  // 3. Tokens conocidos (GitHub, GitLab, OpenAI/Anthropic, Slack, AWS, Telegram, Culkibo)
  s = s.replace(/\b(gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|glpat-[A-Za-z0-9_-]{12,}|sk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{12,}|AKIA[0-9A-Z]{16}|ckh_[a-f0-9]{16,})\b/g, '<token>');
  s = s.replace(/\b\d{6,15}:[A-Za-z0-9_-]{25,80}\b/g, '<bot_token>');
  // 4. URLs con credenciales embebidas (postgres://user:pass@host/db, https://user:pass@...)
  s = s.replace(/\b((?:https?|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|valkey|amqp|s3):\/\/)([^:\s/@]+):([^@\s/]+)@([^\s/'")]+)/gi, '$1<creds>@<host>');
  // 5. Parámetros de query sensibles
  s = s.replace(/([?&](?:token|key|secret|password|passwd|api_key|apikey|access_token|auth|signature)=)[^&\s'"]+/gi, '$1<redacted>');
  // 6. Claves/valores inline tipo `PASSWORD=...` o `secret: ...`
  s = s.replace(/\b([A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|PASSPHRASE)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi, '$1<redacted>');
  // 7. Correos electrónicos
  s = s.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '<email>');
  // 8. URLs con dominios ajenos (conservar solo dominios técnicos permitidos)
  s = s.replace(/\b(https?:\/\/)([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(:\d+)?(\/[^\s'")<>]*)?/g, (_m, proto, host, port, rest) => {
    const lower = String(host).toLowerCase();
    if (SAFE_DOMAINS.has(lower)) return `${proto}${lower}${port || ''}${rest ? rest.slice(0, 80) : ''}`;
    return `${proto}<domain>${rest ? '/<path>' : ''}`;
  });
  // 9. Direcciones IPv4 / IPv6
  s = s.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, (ip) => (ip === '127.0.0.1' || ip === '0.0.0.0' ? ip : '<ip>'));
  s = s.replace(/\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b/g, (ip) => (ip === '::1' ? '::1' : '<ip6>'));
  // 10. Rutas locales de usuario (Windows & Unix) preservando rutas relativas de Culkibo
  s = s.replace(/[A-Za-z]:\\(?:Users|Documents and Settings)\\[^\\\s'"]+\\[^\s'")<>:]+/gi, (p) => normalizeAppPath(p));
  s = s.replace(/(?:\/(?:home|Users|root|srv|opt|var|tmp))\/[^\s'")<>:]+/g, (p) => normalizeAppPath(p));
  // 11. Cadenas hex/base64 largas (>= 32 chars) que parezcan secretos crudos
  s = s.replace(/\b[a-f0-9]{32,}\b/gi, '<hex>');

  s = s.replace(/[\r\n\t]+/g, ' ').trim();
  if (s.length > maxLen) return `${s.slice(0, maxLen - 1)}…`;
  return s;
}

function normalizeAppPath(rawPath) {
  const unix = String(rawPath || '').replace(/\\/g, '/');
  const m = unix.match(/\/((?:server|bin|web|scripts)\/[^:)\s'"]+)/i);
  if (m) return `<app>/${m[1]}`;
  return '<path>';
}

/**
 * Sanea una traza de pila conservando solo líneas de código de Culkibo y módulos `node:*`,
 * eliminando directorios de usuario y argumentos sensibles.
 * @param {string | undefined | null} stack
 * @param {number} [maxFrames]
 */
function scrubStack(stack, maxFrames = 12) {
  if (!stack || typeof stack !== 'string') return [];
  const lines = stack.split(/\r?\n/).slice(0, maxFrames + 4);
  /** @type {string[]} */
  const out = [];
  for (const rawLine of lines) {
    if (out.length >= maxFrames) break;
    const trimmed = rawLine.trim();
    if (!trimmed) continue;
    if (out.length === 0 && !trimmed.startsWith('at ')) {
      out.push(scrubText(trimmed, 220));
      continue;
    }
    const cleanFrame = trimmed
      .replace(/[A-Za-z]:\\[^\s):]+/g, (p) => normalizeAppPath(p))
      .replace(/(?:\/(?:home|Users|root|srv|opt|var|tmp|app))\/[^\s):]+/g, (p) => normalizeAppPath(p));
    out.push(scrubText(cleanFrame, 220));
  }
  return out;
}

/**
 * Sanea recursivamente un objeto de metadatos: descarta claves sensibles y limpia valores.
 * @param {any} obj
 * @param {number} [depth]
 */
function scrubObject(obj, depth = 0) {
  if (obj === null || obj === undefined) return obj;
  if (depth > 3) return undefined;
  if (typeof obj === 'string') return scrubText(obj, 240);
  if (typeof obj === 'number') return Number.isFinite(obj) ? obj : null;
  if (typeof obj === 'boolean') return obj;
  if (Array.isArray(obj)) {
    return obj.slice(0, 16).map((item) => scrubObject(item, depth + 1)).filter((v) => v !== undefined);
  }
  if (typeof obj === 'object') {
    /** @type {Record<string, any>} */
    const out = {};
    for (const [k, v] of Object.entries(obj).slice(0, 24)) {
      if (SENSITIVE_KEY_RE.test(k)) continue;
      const cleaned = scrubObject(v, depth + 1);
      if (cleaned !== undefined) out[k] = cleaned;
    }
    return out;
  }
  return undefined;
}

function computeFingerprint(parts) {
  const normalized = parts
    .map((p) => String(p || '')
      .replace(/\b\d+\b/g, '#')
      .replace(/<hex>|<ip>|<ip6>|<domain>|<path>/g, '*')
      .trim()
      .toLowerCase())
    .join('|');
  return crypto.createHash('sha256').update(normalized).digest('hex').slice(0, 24);
}

function bucketRamGb(bytes) {
  const gb = bytes / (1024 ** 3);
  if (gb <= 1.2) return '<=1GB';
  if (gb <= 2.5) return '2GB';
  if (gb <= 5) return '4GB';
  if (gb <= 10) return '8GB';
  if (gb <= 20) return '16GB';
  return '32GB+';
}

function bucketCount(n) {
  const v = Number(n) || 0;
  if (v <= 0) return '0';
  if (v <= 3) return '1-3';
  if (v <= 10) return '4-10';
  if (v <= 25) return '11-25';
  return '26+';
}

function detectInstallMethod() {
  if (fs.existsSync('/.dockerenv')) return 'docker';
  if (process.env.INVOCATION_ID || process.env.JOURNAL_STREAM) return 'systemd';
  return 'local';
}

class TelemetryService {
  /** @param {{ storePath?: string | null, endpoint?: string | null, transport?: ((url: string, body: string, headers: Record<string, string>) => Promise<{ ok: boolean, status: number, retryAfterSec?: number }>) | null }} [opts] */
  constructor(opts = {}) {
    this._customStorePath = opts.storePath || null;
    this._customEndpoint = opts.endpoint || null;
    this._customTransport = opts.transport || null;
    this._loaded = false;
    /** @type {{ enabled: boolean, instanceId: string, createdAt: string, updatedAt: string }} */
    this._config = {
      enabled: true,
      instanceId: '',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    /** @type {Array<any>} */
    this._queue = [];
    /** @type {Map<string, { event: any, lastSeenAt: number }>} */
    this._dedup = new Map();
    /** @type {Map<string, { ok: number, fail: number }>} */
    this._featureCounters = new Map();

    // Circuit breaker exponencial (nunca spamea ni frena el daemon si el recolector está caído)
    this._consecutiveFailures = 0;
    this._nextRetryAfter = 0;
    this._flushing = false;
    this._started = false;
    this._stats = {
      enqueued: 0,
      sent: 0,
      dropped: 0,
      deduplicated: 0,
      lastFlushAt: /** @type {string | null} */ (null),
      lastError: /** @type {string | null} */ (null)
    };

    /** @type {ReturnType<typeof setInterval> | null} */
    this._flushTimer = null;
    /** @type {ReturnType<typeof setTimeout> | null} */
    this._crashFlushTimer = null;
    /** @type {ReturnType<typeof setTimeout> | null} */
    this._initialHeartbeatTimer = null;
    /** @type {ReturnType<typeof setInterval> | null} */
    this._heartbeatTimer = null;
    /** @type {(() => Record<string, any>) | null} */
    this._heartbeatCollector = null;
  }

  getStorePath() {
    if (this._customStorePath) return this._customStorePath;
    return path.join(resolveDataDir(), 'telemetry.json');
  }

  _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;
    const storePath = this.getStorePath();
    const res = loadJsonWithBackupSync(storePath, {
      validate: (p) => Boolean(p && typeof p === 'object' && typeof p.instanceId === 'string' && p.instanceId.length >= 16)
    });
    if (res.data) {
      this._config = {
        enabled: typeof res.data.enabled === 'boolean' ? res.data.enabled : true,
        instanceId: res.data.instanceId,
        createdAt: res.data.createdAt || new Date().toISOString(),
        updatedAt: res.data.updatedAt || new Date().toISOString()
      };
      return;
    }
    this._config = {
      enabled: true,
      instanceId: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    this._saveConfig();
  }

  _saveConfig() {
    try {
      const storePath = this.getStorePath();
      atomicWriteJsonSync(storePath, this._config, { mode: 0o600, backup: true });
    } catch (e) {
      // Nunca romper el daemon si el disco es de solo lectura
    }
  }

  getEndpoint() {
    if (this._customEndpoint) return this._customEndpoint;
    const envUrl = String(process.env.CULKIBO_TELEMETRY_URL || '').trim();
    return envUrl || DEFAULT_ENDPOINT;
  }

  /** Evalúa precedencia estricta: env opt-out > entorno test/CI > configuración persistida. */
  getEffectiveState() {
    this._ensureLoaded();
    if (isFalsyEnv(process.env.CULKIBO_TELEMETRY)) {
      return { enabled: false, lockedByEnv: true, reason: 'Desactivada mediante CULKIBO_TELEMETRY=0' };
    }
    if (isTruthyEnv(process.env.DO_NOT_TRACK)) {
      return { enabled: false, lockedByEnv: true, reason: 'Desactivada respetando DO_NOT_TRACK=1' };
    }
    if (isRunningUnderTests()) {
      return { enabled: false, lockedByEnv: true, reason: 'Auto-desactivada en entorno de pruebas/CI' };
    }
    return {
      enabled: Boolean(this._config.enabled),
      lockedByEnv: false,
      reason: this._config.enabled ? 'Activa (anónima y transparente)' : 'Desactivada por el usuario'
    };
  }

  isEnabled() {
    return this.getEffectiveState().enabled;
  }

  setEnabled(enabled) {
    this._ensureLoaded();
    this._config.enabled = Boolean(enabled);
    this._config.updatedAt = new Date().toISOString();
    this._saveConfig();
    if (!this._config.enabled) {
      this._queue.length = 0;
      this._dedup.clear();
      this._featureCounters.clear();
    }
    return this.getStatus();
  }

  resetInstanceId() {
    this._ensureLoaded();
    this._config.instanceId = crypto.randomUUID();
    this._config.updatedAt = new Date().toISOString();
    this._saveConfig();
    return this.getStatus();
  }

  getStatus() {
    this._ensureLoaded();
    const eff = this.getEffectiveState();
    return {
      schemaVersion: SCHEMA_VERSION,
      enabled: eff.enabled,
      persistedEnabled: Boolean(this._config.enabled),
      lockedByEnv: eff.lockedByEnv,
      reason: eff.reason,
      instanceId: this._config.instanceId,
      endpoint: this.getEndpoint(),
      debug: isTruthyEnv(process.env.CULKIBO_TELEMETRY_DEBUG),
      queuedEvents: this._queue.length,
      stats: { ...this._stats },
      circuitOpenUntil: this._nextRetryAfter > Date.now() ? new Date(this._nextRetryAfter).toISOString() : null,
      collectedTypes: [
        'instance_heartbeat',
        'server_crash',
        'api_error_5xx',
        'operation_failure',
        'client_error',
        'feature_usage'
      ],
      neverCollected: [
        'Nombres o URLs de repositorios, proyectos o dominios',
        'Variables de entorno, contraseñas, tokens o certificados',
        'Direcciones IP, correos electrónicos o rutas con nombre de usuario',
        'Contenido de bases de datos, backups o logs de negocio'
      ]
    };
  }

  /** @param {() => Record<string, any>} collectorFn */
  setHeartbeatCollector(collectorFn) {
    if (typeof collectorFn === 'function') this._heartbeatCollector = collectorFn;
  }

  /** Construye el payload exacto de heartbeat anónimo (también usado por la vista previa de transparencia). */
  buildHeartbeatPayload() {
    this._ensureLoaded();
    let extra = {};
    if (this._heartbeatCollector) {
      try { extra = this._heartbeatCollector() || {}; } catch (e) {}
    }
    const base = {
      culkiboVersion: APP_VERSION,
      nodeVersion: process.version,
      os: {
        platform: process.platform,
        arch: process.arch,
        releaseMajor: String(os.release() || '').split('.')[0] || '0'
      },
      cpuCores: typeof os.availableParallelism === 'function' ? os.availableParallelism() : os.cpus().length,
      ramBucket: bucketRamGb(os.totalmem()),
      uptimeHours: Number((process.uptime() / 3600).toFixed(2)),
      installMethod: detectInstallMethod(),
      counts: {
        projects: bucketCount(extra.projectsCount),
        databases: bucketCount(extra.databasesCount),
        catalogServices: bucketCount(extra.catalogServicesCount),
        domains: bucketCount(extra.domainsCount),
        activeCrons: bucketCount(extra.activeCronsCount)
      },
      capabilities: {
        dockerAvailable: extra.dockerAvailable ?? null,
        caddyAvailable: extra.caddyAvailable ?? null
      },
      features: {
        hasWildcard: Boolean(extra.hasWildcard),
        hasS3: Boolean(extra.hasS3),
        hasNotifications: Boolean(extra.hasNotifications),
        hasLiveSync: Boolean(extra.hasLiveSync),
        hasMcpUsed: Boolean(extra.hasMcpUsed),
        hasCloudflare: Boolean(extra.hasCloudflare)
      }
    };
    return base;
  }

  /** Devuelve un ejemplo exacto y en vivo del sobre JSON que Culkibo enviaría al recolector. */
  getPreviewPayload() {
    this._ensureLoaded();
    const hb = this._buildEvent('instance_heartbeat', this.buildHeartbeatPayload());
    return {
      schemaVersion: SCHEMA_VERSION,
      instanceId: this._config.instanceId,
      appVersion: APP_VERSION,
      sentAt: new Date().toISOString(),
      endpoint: this.getEndpoint(),
      events: [hb, ...this._queue.slice(0, 4)]
    };
  }

  /**
   * @param {string} type
   * @param {any} data
   * @param {string | null} [fingerprint]
   */
  _buildEvent(type, data, fingerprint = null) {
    return {
      id: crypto.randomUUID(),
      type,
      ts: new Date().toISOString(),
      ...(fingerprint ? { fingerprint } : {}),
      occurrences: 1,
      data: scrubObject(data) || {}
    };
  }

  /**
   * @param {string} type
   * @param {any} data
   * @param {string | null} [fingerprint]
   * @param {{ urgent?: boolean }} [opts]
   */
  _enqueue(type, data, fingerprint = null, { urgent = false } = {}) {
    if (!this.isEnabled()) return false;
    this._ensureLoaded();

    const now = Date.now();
    // Plegar eventos repetitivos (mismo fingerprint en 15 min) en lugar de inundar la cola
    if (fingerprint) {
      const existing = this._dedup.get(fingerprint);
      if (existing && (now - existing.lastSeenAt) < DEDUP_WINDOW_MS) {
        existing.lastSeenAt = now;
        existing.event.occurrences = Math.min(10000, (existing.event.occurrences || 1) + 1);
        existing.event.lastTs = new Date(now).toISOString();
        this._stats.deduplicated++;
        return true;
      }
      // Limpiar entradas caducadas del mapa dedup
      if (this._dedup.size > 200) {
        for (const [k, v] of this._dedup.entries()) {
          if (now - v.lastSeenAt >= DEDUP_WINDOW_MS) this._dedup.delete(k);
        }
      }
    }

    const event = this._buildEvent(type, data, fingerprint);
    if (this._queue.length >= MAX_QUEUE_EVENTS) {
      // Descartar el evento de menor prioridad (nunca descartar server_crash si hay eventos más bajos)
      let dropIdx = 0;
      let minRank = PRIORITY_RANK[this._queue[0]?.type] ?? 1;
      for (let i = 1; i < this._queue.length; i++) {
        const r = PRIORITY_RANK[this._queue[i]?.type] ?? 1;
        if (r < minRank) {
          minRank = r;
          dropIdx = i;
        }
      }
      const incomingRank = PRIORITY_RANK[type] ?? 1;
      if (incomingRank < minRank) {
        this._stats.dropped++;
        return false;
      }
      const [removed] = this._queue.splice(dropIdx, 1);
      if (removed && removed.fingerprint) this._dedup.delete(removed.fingerprint);
      this._stats.dropped++;
    }

    this._queue.push(event);
    this._stats.enqueued++;
    if (fingerprint) {
      this._dedup.set(fingerprint, { event, lastSeenAt: now });
    }

    if (urgent && !this._crashFlushTimer) {
      this._crashFlushTimer = setTimeout(() => {
        this._crashFlushTimer = null;
        this.flush().catch(() => {});
      }, 2000);
      if (this._crashFlushTimer.unref) this._crashFlushTimer.unref();
    }
    return true;
  }

  /** Registra un fallo fatal del daemon (`uncaughtException`, `unhandledRejection`, 5xx con stack). */
  captureCrash(kind, err) {
    try {
      const errorName = err && err.name ? String(err.name).slice(0, 60) : 'Error';
      const errorCode = err && err.code ? String(err.code).slice(0, 40) : null;
      const message = scrubText(err && err.message ? err.message : String(err), 300);
      const stack = scrubStack(err && err.stack ? err.stack : null, 12);
      const topFrame = stack.find((l) => l.startsWith('at ')) || stack[0] || '';
      const fp = computeFingerprint(['server_crash', kind, errorName, errorCode || '', topFrame, message.slice(0, 120)]);
      return this._enqueue('server_crash', {
        kind: String(kind || 'error').slice(0, 40),
        errorName,
        errorCode,
        message,
        stack
      }, fp, { urgent: true });
    } catch (e) {
      return false;
    }
  }

  /**
   * Registra un error HTTP 5xx usando ruta canónica (nunca IDs ni dominios reales).
   * @param {{ method?: string, route?: string, status?: number, errorCode?: string | null, message?: string }} [opts]
   */
  captureApi5xx({ method = 'GET', route = '/api', status = 500, errorCode = null, message = '' } = {}) {
    try {
      const safeMethod = String(method || 'GET').toUpperCase().slice(0, 10);
      const safeRoute = String(route || '/api').slice(0, 120);
      const safeMsg = scrubText(message, 240);
      const fp = computeFingerprint(['api_error_5xx', safeMethod, safeRoute, status, errorCode || '', safeMsg.slice(0, 100)]);
      return this._enqueue('api_error_5xx', {
        method: safeMethod,
        route: safeRoute,
        status: Number(status) || 500,
        errorCode: errorCode ? String(errorCode).slice(0, 40) : null,
        message: safeMsg
      }, fp);
    } catch (e) {
      return false;
    }
  }

  /**
   * Registra el fallo de una operación núcleo (deploy, backup, restore, ingress, catálogo, MCP).
   * @param {{ operation: string, stage?: string, kind?: string | null, errorCode?: string | null, message?: string, durationMs?: number | null }} opts
   */
  captureOperationFailure({ operation, stage = 'run', kind = null, errorCode = null, message = '', durationMs = null }) {
    try {
      const op = String(operation || 'unknown').slice(0, 48);
      const stg = String(stage || 'run').slice(0, 48);
      const k = kind ? String(kind).slice(0, 48) : null;
      const safeMsg = scrubText(message, 260);
      const fp = computeFingerprint(['operation_failure', op, stg, k || '', errorCode || '', safeMsg.slice(0, 100)]);
      return this._enqueue('operation_failure', {
        operation: op,
        stage: stg,
        kind: k,
        errorCode: errorCode ? String(errorCode).slice(0, 40) : null,
        message: safeMsg,
        durationMs: typeof durationMs === 'number' && Number.isFinite(durationMs) ? Math.round(durationMs) : null
      }, fp);
    } catch (e) {
      return false;
    }
  }

  /** Registra un error de interfaz enviado por el navegador SPA (validado y saneado en servidor). */
  captureClientError(payload = {}) {
    try {
      const source = ['error_boundary', 'window_error', 'unhandled_rejection'].includes(payload.source)
        ? payload.source
        : 'window_error';
      const view = ALLOWED_VIEWS.has(String(payload.view || '')) ? String(payload.view) : 'unknown';
      const errorName = scrubText(payload.errorName || 'Error', 60);
      const message = scrubText(payload.message || 'Unknown UI error', 300);
      const stack = scrubStack(typeof payload.stack === 'string' ? payload.stack : '', 10);
      const componentStack = scrubStack(typeof payload.componentStack === 'string' ? payload.componentStack : '', 8);
      const viewportBucket = typeof payload.viewportBucket === 'string' ? payload.viewportBucket.slice(0, 24) : 'unknown';
      const topFrame = stack[0] || componentStack[0] || '';
      const fp = computeFingerprint(['client_error', source, view, errorName, topFrame, message.slice(0, 100)]);
      return this._enqueue('client_error', {
        source,
        view,
        errorName,
        message,
        stack,
        componentStack,
        viewportBucket
      }, fp);
    } catch (e) {
      return false;
    }
  }

  /** Acumula uso agregado de funcionalidades para saber qué mejorar (sin detalles personales). */
  recordFeatureUsage(featureKey, ok = true) {
    if (!this.isEnabled()) return;
    const clean = String(featureKey || '').trim().toLowerCase().replace(/[^a-z0-9._:-]/g, '').slice(0, 64);
    if (!clean) return;
    if (this._featureCounters.size > 100 && !this._featureCounters.has(clean)) return;
    const cur = this._featureCounters.get(clean) || { ok: 0, fail: 0 };
    if (ok) cur.ok++;
    else cur.fail++;
    this._featureCounters.set(clean, cur);
  }

  enqueueHeartbeat() {
    if (!this.isEnabled()) return false;
    const hb = this.buildHeartbeatPayload();
    this._enqueue('instance_heartbeat', hb, null);
    if (this._featureCounters.size > 0) {
      /** @type {Record<string, { ok: number, fail: number }>} */
      const summary = {};
      for (const [k, v] of this._featureCounters.entries()) summary[k] = v;
      this._featureCounters.clear();
      this._enqueue('feature_usage', { counters: summary }, null);
    }
    return true;
  }

  start() {
    if (this._started) return;
    this._started = true;
    this._ensureLoaded();
    if (!this.isEnabled()) return;

    this._flushTimer = setInterval(() => {
      this.flush().catch(() => {});
    }, FLUSH_INTERVAL_MS);
    if (this._flushTimer.unref) this._flushTimer.unref();

    this._initialHeartbeatTimer = setTimeout(() => {
      this._initialHeartbeatTimer = null;
      this.enqueueHeartbeat();
      this.flush().catch(() => {});
    }, HEARTBEAT_INITIAL_DELAY_MS);
    if (this._initialHeartbeatTimer.unref) this._initialHeartbeatTimer.unref();

    this._heartbeatTimer = setInterval(() => {
      this.enqueueHeartbeat();
      this.flush().catch(() => {});
    }, HEARTBEAT_INTERVAL_MS);
    if (this._heartbeatTimer.unref) this._heartbeatTimer.unref();
  }

  stop() {
    this._started = false;
    for (const key of ['_flushTimer', '_crashFlushTimer', '_initialHeartbeatTimer', '_heartbeatTimer']) {
      if (this[key]) {
        clearInterval(this[key]);
        clearTimeout(this[key]);
        this[key] = null;
      }
    }
  }

  /** Envía un lote acotado de eventos al recolector cloud con circuit breaker y timeout estricto. */
  async flush({ force = false, timeoutMs = HTTP_TIMEOUT_MS } = {}) {
    if (!this.isEnabled()) return { sent: 0, skipped: 'disabled' };
    if (this._flushing) return { sent: 0, skipped: 'in_flight' };
    if (this._queue.length === 0) return { sent: 0, skipped: 'empty' };
    const now = Date.now();
    if (!force && now < this._nextRetryAfter) {
      return { sent: 0, skipped: 'circuit_open' };
    }

    this._ensureLoaded();
    this._flushing = true;

    // Seleccionar eventos hasta MAX_BATCH_BYTES
    /** @type {any[]} */
    const batch = [];
    let batchBytes = 256;
    while (this._queue.length > 0 && batch.length < 25) {
      const next = this._queue[0];
      const size = Buffer.byteLength(JSON.stringify(next), 'utf8');
      if (batch.length > 0 && batchBytes + size > MAX_BATCH_BYTES) break;
      batch.push(this._queue.shift());
      batchBytes += size;
    }

    const envelope = {
      schemaVersion: SCHEMA_VERSION,
      instanceId: this._config.instanceId,
      appVersion: APP_VERSION,
      sentAt: new Date().toISOString(),
      events: batch
    };
    const bodyStr = JSON.stringify(envelope);
    const endpoint = this.getEndpoint();

    if (isTruthyEnv(process.env.CULKIBO_TELEMETRY_DEBUG)) {
      console.log('[Culkibo:Telemetry:Debug]', bodyStr);
    }

    const headers = {
      'Content-Type': 'application/json',
      'User-Agent': `Culkibo/${APP_VERSION} (${process.platform}; ${process.arch})`,
      'X-Culkibo-Schema': String(SCHEMA_VERSION)
    };

    try {
      let result;
      if (this._customTransport) {
        result = await this._customTransport(endpoint, bodyStr, headers);
      } else {
        const allowHttp = isTruthyEnv(process.env.CULKIBO_TELEMETRY_ALLOW_HTTP);
        const parsed = new URL(endpoint);
        const isLocal = parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost' || parsed.hostname === '::1';
        if (!isLocal) {
          await assertSafeUrl(endpoint, { requireHttps: !allowHttp });
        } else if (!allowHttp && parsed.protocol !== 'https:') {
          throw new Error('Endpoint local HTTP requiere CULKIBO_TELEMETRY_ALLOW_HTTP=1');
        }
        const res = await fetch(endpoint, {
          method: 'POST',
          headers,
          body: bodyStr,
          redirect: 'error',
          signal: AbortSignal.timeout(timeoutMs)
        });
        const retryAfterRaw = Number(res.headers.get('retry-after') || 0);
        result = {
          ok: res.ok,
          status: res.status,
          retryAfterSec: Number.isFinite(retryAfterRaw) && retryAfterRaw > 0 ? retryAfterRaw : 0
        };
      }

      if (result && result.ok) {
        this._consecutiveFailures = 0;
        this._nextRetryAfter = 0;
        this._stats.sent += batch.length;
        this._stats.lastFlushAt = new Date().toISOString();
        this._stats.lastError = null;
        for (const ev of batch) {
          if (ev.fingerprint) this._dedup.delete(ev.fingerprint);
        }
        return { sent: batch.length, status: result.status };
      }

      // Fallo HTTP: reencolar solo si es recuperable (429 / 5xx), descartar en 400/413
      const status = result ? result.status : 0;
      const retryable = status === 429 || status >= 500 || status === 0;
      if (retryable) {
        this._requeueBatch(batch);
      } else {
        this._stats.dropped += batch.length;
      }
      this._recordTransportFailure(status ? `HTTP ${status}` : 'transport_error', result?.retryAfterSec || 0);
      return { sent: 0, status, error: this._stats.lastError };
    } catch (err) {
      this._requeueBatch(batch);
      this._recordTransportFailure(err && err.message ? err.message : 'network_error', 0);
      return { sent: 0, error: this._stats.lastError };
    } finally {
      this._flushing = false;
    }
  }

  _requeueBatch(batch) {
    for (let i = batch.length - 1; i >= 0; i--) {
      if (this._queue.length < MAX_QUEUE_EVENTS) {
        this._queue.unshift(batch[i]);
      } else {
        this._stats.dropped++;
      }
    }
  }

  _recordTransportFailure(reason, retryAfterSec = 0) {
    this._consecutiveFailures = Math.min(10, this._consecutiveFailures + 1);
    const backoffTableSec = [60, 120, 240, 900, 3600, 21600];
    const baseSec = backoffTableSec[Math.min(backoffTableSec.length - 1, this._consecutiveFailures - 1)];
    const waitSec = Math.max(baseSec, Math.min(21600, retryAfterSec || 0));
    this._nextRetryAfter = Date.now() + waitSec * 1000;
    this._stats.lastError = scrubText(reason, 120);
  }

  async flushBestEffort({ timeoutMs = 1500 } = {}) {
    this.stop();
    if (!this.isEnabled()) return;
    if (this._featureCounters.size > 0) {
      /** @type {Record<string, { ok: number, fail: number }>} */
      const summary = {};
      for (const [k, v] of this._featureCounters.entries()) summary[k] = v;
      this._featureCounters.clear();
      this._enqueue('feature_usage', { counters: summary }, null);
    }
    if (this._queue.length === 0) return;
    await this.flush({ force: true, timeoutMs }).catch(() => {});
  }
}

const instance = Object.assign(new TelemetryService(), {
  TelemetryService,
  SCHEMA_VERSION,
  DEFAULT_ENDPOINT,
  scrubText,
  scrubStack,
  scrubObject,
  computeFingerprint
});

module.exports = instance;
