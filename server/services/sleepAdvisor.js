const { execFile } = require('child_process');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const fs = require('fs');
const os = require('os');
const path = require('path');
const ssrfGuard = require('./ssrfGuard');

/**
 * Smart Scale-to-Zero Auto-Sleep + VPS Cost & RAM Advisor (cero dependencias,
 * cero invocaciones de shell).
 *
 * Propiedades clave:
 *  - Ejecuta Docker EXCLUSIVAMENTE mediante `execFile('docker', [...argv], { shell: false })`
 *    (con `_execFile` inyectable para pruebas unitarias).
 *  - Protege operaciones activas antes de suspender: comprueba bloqueos en
 *    `deployManager.locks`, sesiones conectadas en `liveSyncEngine` y tareas
 *    activas en `cronManager.runningJobs` (`excludeCrons: true`).
 *  - Mantiene estado 100% sincronizado (`deployManager.store`, `projectManager.hibernate`,
 *    `ingressManager.reconcile`) evitando la desincronización tipo Sablier.
 *  - Despertar single-flight por proyecto (`wakeProject`): coalesce N peticiones
 *    concurrentes en una única invocación Docker, con límite de tasa por IP+proyecto
 *    y secreto interno `X-Culkibo-Wake-Secret` para impedir bypass de políticas Caddy.
 *  - Analizador de costes y RAM (`analyzeResources` + `getDoctorSummary`): detecta
 *    riesgos OOM, límites `memoryMb` sobredimensionados, candidatos a auto-sleep y
 *    calcula el ahorro mensual real €/mes VPS frente a PaaS SaaS (Railway/Render/Fly).
 */

const DATA_DIR = process.env.CULKIBO_DATA_DIR
  ? path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data')
  : path.resolve(__dirname, '..', '..', 'data');
const STORE_FILE = path.join(DATA_DIR, 'sleep-policies.json');

const PROJECT_ID_RE = /^[a-zA-Z0-9_-]{1,80}$/;
const CONTAINER_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/;

const MIN_IDLE_MINUTES = 5;
const MAX_IDLE_MINUTES = 10080; // 7 días
const MIN_WAKE_TIMEOUT_MS = 2000;
const MAX_WAKE_TIMEOUT_MS = 60000;
const DEFAULT_WAKE_TIMEOUT_MS = 20000;
const SWEEP_INTERVAL_MS = 60 * 1000;
const BROWSER_HOLD_THRESHOLD_MS = 800;
const MAX_HELD_PER_PROJECT = 25;
const MAX_HELD_GLOBAL = 100;
const MAX_HELD_BODY_BYTES = 1024 * 1024; // 1 MiB
const DEFAULT_WAKE_RATE_WINDOW_MS = 60 * 1000;
const DEFAULT_WAKE_RATE_MAX = 30;
const MAX_RATE_KEYS = 2000;
const WAKING_PAGE_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'";

/** @type {typeof import('http') | null} */
let _httpMod = null;
function getHttp() {
  if (!_httpMod) _httpMod = require('http');
  return _httpMod;
}

/** @type {any} */
let _cronParser = null;
function getCronParser() {
  if (!_cronParser) {
    try { _cronParser = require('./cronParser'); } catch (e) {}
  }
  return _cronParser;
}

/** @type {any} */
let _authMod = null;
function getAuthMod() {
  if (!_authMod) {
    try { _authMod = require('../middleware/auth'); } catch (e) {}
  }
  return _authMod;
}

/**
 * Comprueba si una fecha coincide exactamente con una expresión cron de 5 campos.
 * @param {string} expression
 * @param {Date} date
 * @returns {boolean}
 */
function cronMatchesDate(expression, date) {
  const cp = getCronParser();
  if (!cp || typeof cp.parseCron !== 'function') return false;
  try {
    const parsed = cp.parseCron(expression);
    const mon = date.getMonth() + 1;
    if (!parsed.month.has(mon)) return false;
    const domMatch = parsed.dom.has(date.getDate());
    const dowMatch = parsed.dow.has(date.getDay());
    const dayOk = (!parsed.domWildcard && !parsed.dowWildcard)
      ? (domMatch || dowMatch)
      : (domMatch && dowMatch);
    if (!dayOk) return false;
    if (!parsed.hour.has(date.getHours())) return false;
    if (!parsed.minute.has(date.getMinutes())) return false;
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Escapa texto para HTML evitando XSS.
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
 * Parsea cadenas de tamaño de `docker stats` (p. ej. `128.4MiB`, `1.2GB`, `450kB`, `0B`) a bytes.
 * @param {string} raw
 * @returns {number}
 */
function parseDockerBytes(raw) {
  const s = String(raw || '').trim();
  const match = s.match(/^([\d.]+)\s*(b|kb|kib|mb|mib|gb|gib|tb|tib)?$/i);
  if (!match) return 0;
  const val = parseFloat(match[1]);
  if (!Number.isFinite(val) || val < 0) return 0;
  const unit = (match[2] || 'b').toLowerCase();
  const mult = {
    b: 1,
    kb: 1e3,
    kib: 1024,
    mb: 1e6,
    mib: 1024 ** 2,
    gb: 1e9,
    gib: 1024 ** 3,
    tb: 1e12,
    tib: 1024 ** 4
  }[unit] || 1;
  return Math.round(val * mult);
}

/**
 * Parsea porcentajes de `docker stats` (p. ej. `12.34%`) a número.
 * @param {string} raw
 * @returns {number}
 */
function parseDockerPercent(raw) {
  const val = parseFloat(String(raw || '').replace('%', '').trim());
  return Number.isFinite(val) && val >= 0 ? Number(val.toFixed(2)) : 0;
}

/**
 * Redondea MB al siguiente múltiplo de 64 MB.
 * @param {number} mb
 * @returns {number}
 */
function ceilTo64Mb(mb) {
  return Math.max(64, Math.ceil(mb / 64) * 64);
}

/**
 * Devuelve la memoria RAM realmente disponible del host en bytes.
 * En Linux lee `MemAvailable` de `/proc/meminfo` (incluye page cache recuperable
 * evitando falsas alarmas OOM de `os.freemem()`).
 * @param {(() => string | null) | null} [readProcMeminfo]
 * @returns {number}
 */
function getHostAvailableMemBytes(readProcMeminfo = null) {
  if (typeof readProcMeminfo === 'function' || process.platform === 'linux') {
    try {
      const content = typeof readProcMeminfo === 'function'
        ? readProcMeminfo()
        : fs.readFileSync('/proc/meminfo', 'utf8');
      if (typeof content === 'string') {
        const match = content.match(/^MemAvailable:\s+(\d+)\s+kB/m);
        if (match) {
          const kb = parseInt(match[1], 10);
          if (Number.isFinite(kb) && kb >= 0) return kb * 1024;
        }
      }
    } catch (e) {}
  }
  return os.freemem();
}

/**
 * Extrae la IP real del cliente detrás de Caddy (proxy de confianza verificado)
 * usando el salto más a la derecha de `X-Forwarded-For` (anti-spoofing).
 * @param {any} req
 * @returns {string}
 */
function resolveWakeClientIp(req) {
  const xff = req?.headers?.['x-forwarded-for'];
  if (xff) {
    const hops = String(xff)
      .split(',')
      .map((s) => s.trim().replace(/^::ffff:/, ''))
      .filter(Boolean);
    if (hops.length > 0) return hops[hops.length - 1];
  }
  return String(req?.socket?.remoteAddress || '127.0.0.1').replace(/^::ffff:/, '');
}

/**
 * Comparación en tiempo constante para cabeceras secretas.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function safeTimingEqual(a, b) {
  const ba = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  if (ba.length === 0 || ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/**
 * Genera el HTML ligero de marca "Despertando servicio..." sin JS inline ni dependencias.
 * @param {string} projectName
 * @param {{ retryAfterSec?: number }} [opts]
 * @returns {string}
 */
function renderWakingHtml(projectName, opts = {}) {
  const safeName = escapeHtml(String(projectName || 'Servicio').trim().slice(0, 80) || 'Servicio');
  const retrySec = Math.max(1, Math.min(15, Math.round(Number(opts.retryAfterSec) || 2)));
  return `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${WAKING_PAGE_CSP}">
<meta http-equiv="refresh" content="${retrySec}">
<title>Despertando ${safeName} — Culkibo</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f8fafc;color:#0f172a;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Inter,sans-serif;padding:24px}
.card{width:100%;max-width:420px;background:#ffffff;border:1px solid #e2e8f0;border-radius:14px;padding:32px 28px;text-align:center;box-shadow:0 4px 20px rgba(15,23,42,.04)}
.spinner{width:32px;height:32px;margin:0 auto 18px;border:3px solid #e2e8f0;border-top-color:#0f172a;border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
h1{margin:0 0 8px;font-size:18px;font-weight:650;letter-spacing:-0.01em}
p{margin:0 0 16px;font-size:14px;color:#475569;line-height:1.5}
.pill{display:inline-block;font-size:12px;font-weight:500;color:#334155;background:#f1f5f9;border:1px solid #e2e8f0;border-radius:999px;padding:4px 12px}
</style>
</head>
<body>
<main class="card" role="status" aria-live="polite">
  <div class="spinner" aria-hidden="true"></div>
  <h1>Despertando ${safeName}…</h1>
  <p>Waking service from eco-sleep. La página se recargará automáticamente en ${retrySec}s cuando el contenedor responda.</p>
  <span class="pill">Culkibo Smart Scale-to-Zero</span>
</main>
</body>
</html>`;
}

class SleepAdvisor extends EventEmitter {
  /**
   * @param {{
   *   storeFile?: string,
   *   autoStart?: boolean,
   *   execFile?: any,
   *   wakeSecret?: string,
   *   wakeRateLimitMax?: number,
   *   wakeRateWindowMs?: number,
   *   vpsMonthlyEur?: number,
   *   healthCheck?: ((ctx: { projectId: string, hostPort: number, containerName: string, timeoutMs: number }) => Promise<{ healthy: boolean, reason?: string }>) | null,
   *   deps?: {
   *     deployManager?: any,
   *     projectManager?: any,
   *     cronManager?: any,
   *     liveSyncEngine?: any,
   *     databaseManager?: any,
   *     catalogManager?: any,
   *     previewManager?: any,
   *     ingressManager?: any
   *   }
   * }} [options]
   */
  constructor(options = {}) {
    super();
    this.storeFile = options.storeFile || STORE_FILE;
    this._autoStart = options.autoStart !== false;
    /** Inyectable para pruebas unitarias: por defecto `child_process.execFile`. */
    this._execFile = options.execFile || execFile;
    this._healthCheck = options.healthCheck || null;
    this._deps = options.deps || {};

    this.wakeSecret = options.wakeSecret || crypto.randomBytes(32).toString('hex');
    this._wakeRateLimitMax = Number.isInteger(options.wakeRateLimitMax) && /** @type {number} */ (options.wakeRateLimitMax) > 0
      ? /** @type {number} */ (options.wakeRateLimitMax)
      : DEFAULT_WAKE_RATE_MAX;
    this._wakeRateWindowMs = Number.isFinite(options.wakeRateWindowMs) && /** @type {number} */ (options.wakeRateWindowMs) > 0
      ? /** @type {number} */ (options.wakeRateWindowMs)
      : DEFAULT_WAKE_RATE_WINDOW_MS;
    this._defaultVpsMonthlyEur = Number.isFinite(options.vpsMonthlyEur) && /** @type {number} */ (options.vpsMonthlyEur) >= 0
      ? /** @type {number} */ (options.vpsMonthlyEur)
      : 12;

    /** @type {Map<string, any>} */
    this.policies = new Map();
    /** @type {Map<string, Promise<any>>} */
    this._inFlightSleeps = new Map();
    /** @type {Map<string, Promise<any>>} */
    this._inFlightWakes = new Map();
    /** @type {Map<string, { count: number, resetAt: number }>} */
    this._wakeRateHits = new Map();
    /** @type {Map<string, { totalBytes: number, ts: number, bytesPerMin: number }>} */
    this._netIoTracker = new Map();
    /** @type {Map<string, any>} */
    this._lastContainerStats = new Map();
    /** @type {Map<string, number>} */
    this._heldByProject = new Map();
    this._heldGlobal = 0;

    /** @type {ReturnType<typeof setInterval> | null} */
    this._timer = null;
    this._loaded = false;
    this._stopped = false;
    this._persistedVpsMonthlyEur = this._defaultVpsMonthlyEur;
  }

  _getDep(name) {
    if (Object.prototype.hasOwnProperty.call(this._deps, name)) {
      return this._deps[name];
    }
    try {
      return require(`./${name}`);
    } catch (e) {
      return null;
    }
  }

  _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;
    const res = ssrfGuard.loadJsonWithBackupSync(this.storeFile, {
      validate: (parsed) => Boolean(parsed && typeof parsed === 'object' && parsed.policies && typeof parsed.policies === 'object')
    });
    if (res.ok && res.data) {
      if (Number.isFinite(Number(res.data.vpsMonthlyEur)) && Number(res.data.vpsMonthlyEur) >= 0) {
        this._persistedVpsMonthlyEur = Number(res.data.vpsMonthlyEur);
      }
      for (const [projectId, pol] of Object.entries(res.data.policies || {})) {
        if (PROJECT_ID_RE.test(projectId) && pol && typeof pol === 'object') {
          this.policies.set(projectId, {
            projectId,
            enabled: Boolean(pol.enabled),
            mode: pol.mode === 'stop' ? 'stop' : 'pause',
            idleMinutes: Math.max(MIN_IDLE_MINUTES, Math.min(MAX_IDLE_MINUTES, Number(pol.idleMinutes) || 15)),
            wakeTimeoutMs: Math.max(MIN_WAKE_TIMEOUT_MS, Math.min(MAX_WAKE_TIMEOUT_MS, Number(pol.wakeTimeoutMs) || DEFAULT_WAKE_TIMEOUT_MS)),
            excludeCrons: pol.excludeCrons !== false,
            excludeLiveSync: pol.excludeLiveSync !== false,
            schedule: pol.schedule || null,
            sleeping: Boolean(pol.sleeping),
            sleepMode: pol.sleepMode === 'stop' ? 'stop' : (pol.sleepMode === 'pause' ? 'pause' : null),
            sleptAt: pol.sleptAt || null,
            sleepingContainer: pol.sleepingContainer || null,
            lastHostPort: Number.isInteger(pol.lastHostPort) ? pol.lastHostPort : null,
            lastActivityAt: Number.isFinite(pol.lastActivityAt) ? pol.lastActivityAt : Date.now(),
            lastWakeLatencyMs: Number.isFinite(pol.lastWakeLatencyMs) ? pol.lastWakeLatencyMs : null,
            wakeCount: Number.isInteger(pol.wakeCount) ? pol.wakeCount : 0,
            ramSavedMb: Number.isFinite(pol.ramSavedMb) ? pol.ramSavedMb : 0,
            updatedAt: pol.updatedAt || null
          });
        }
      }
    }
  }

  _save() {
    this._ensureLoaded();
    /** @type {Record<string, any>} */
    const policiesObj = {};
    for (const [id, pol] of this.policies.entries()) {
      policiesObj[id] = pol;
    }
    const payload = {
      version: 1,
      vpsMonthlyEur: this._persistedVpsMonthlyEur,
      updatedAt: new Date().toISOString(),
      policies: policiesObj
    };
    ssrfGuard.atomicWriteJsonSync(this.storeFile, payload, { mode: 0o600, backup: true });
  }

  /**
   * Ejecuta `docker` vía `execFile('docker', args, { shell: false })`. Nunca usa shell.
   * @param {string[]} args
   * @param {number} [timeoutMs]
   * @returns {Promise<{ ok: boolean, code: number, stdout: string, stderr: string }>}
   */
  _runDocker(args, timeoutMs = 15000) {
    if (!Array.isArray(args) || args.length === 0) {
      return Promise.reject(new Error('Argumentos de Docker vacíos'));
    }
    for (const a of args) {
      if (typeof a !== 'string' || /[\0\r\n]/.test(a)) {
        return Promise.reject(new Error('Argumento de Docker inválido'));
      }
    }

    return new Promise((resolve) => {
      const opts = {
        shell: false,
        timeout: timeoutMs,
        windowsHide: true,
        maxBuffer: 4 * 1024 * 1024
      };
      let settled = false;
      const finish = (err, stdout, stderr) => {
        if (settled) return;
        settled = true;
        resolve({
          ok: !err,
          code: err ? (typeof err.code === 'number' ? err.code : 1) : 0,
          stdout: String(stdout || ''),
          stderr: String(stderr || (err && err.message ? err.message : ''))
        });
      };
      try {
        const ret = this._execFile('docker', args, opts, (err, stdout, stderr) => {
          finish(err, stdout, stderr);
        });
        if (ret && typeof ret.then === 'function') {
          ret.then(
            (res) => {
              if (res && typeof res === 'object') {
                const failed = res.ok === false || (typeof res.code === 'number' && res.code !== 0);
                finish(failed ? new Error(res.stderr || `docker exit ${res.code}`) : null, res.stdout, res.stderr);
              } else {
                finish(null, res, '');
              }
            },
            (err) => finish(err, '', err && err.message)
          );
        }
      } catch (err) {
        finish(err, '', err && err.message);
      }
    });
  }

  // -------------------------------------------------------------------------
  // Políticas de Auto-Sleep
  // -------------------------------------------------------------------------

  /**
   * Construye la política por defecto para un proyecto sin configuración guardada.
   * @param {string} projectId
   */
  _defaultPolicy(projectId) {
    return {
      projectId,
      enabled: false,
      mode: /** @type {'pause' | 'stop'} */ ('pause'),
      idleMinutes: 15,
      wakeTimeoutMs: DEFAULT_WAKE_TIMEOUT_MS,
      excludeCrons: true,
      excludeLiveSync: true,
      schedule: null,
      sleeping: false,
      sleepMode: null,
      sleptAt: null,
      sleepingContainer: null,
      lastHostPort: null,
      lastActivityAt: Date.now(),
      lastWakeLatencyMs: null,
      wakeCount: 0,
      ramSavedMb: 0,
      updatedAt: null
    };
  }

  /** @param {string} projectId */
  getPolicy(projectId) {
    this._ensureLoaded();
    const pid = String(projectId || '').trim();
    if (!PROJECT_ID_RE.test(pid)) {
      throw new Error('projectId inválido');
    }
    const pol = this.policies.get(pid);
    const base = pol ? { ...pol } : this._defaultPolicy(pid);
    const blockers = this.getActiveSleepBlockers(pid);
    return {
      ...base,
      sleeping: this.isSleeping(pid),
      activeBlockers: blockers.map((b) => b.code)
    };
  }

  /**
   * Configura o actualiza la política de Auto-Sleep para un proyecto.
   * @param {string} projectId
   * @param {any} config
   */
  setPolicy(projectId, config = {}) {
    this._ensureLoaded();
    const pid = String(projectId || '').trim();
    if (!PROJECT_ID_RE.test(pid)) {
      throw new Error('projectId inválido');
    }
    const existing = this.policies.get(pid) || this._defaultPolicy(pid);

    const modeRaw = config.mode !== undefined ? String(config.mode).trim().toLowerCase() : existing.mode;
    if (modeRaw !== 'pause' && modeRaw !== 'stop') {
      throw new Error('Modo de auto-sleep inválido: usa "pause" o "stop"');
    }

    const idleMinutes = config.idleMinutes !== undefined ? Number(config.idleMinutes) : existing.idleMinutes;
    if (!Number.isFinite(idleMinutes) || idleMinutes < MIN_IDLE_MINUTES || idleMinutes > MAX_IDLE_MINUTES) {
      throw new Error(`idleMinutes debe ser al menos ${MIN_IDLE_MINUTES} y como máximo ${MAX_IDLE_MINUTES} minutos`);
    }

    const wakeTimeoutMs = config.wakeTimeoutMs !== undefined ? Number(config.wakeTimeoutMs) : existing.wakeTimeoutMs;
    if (!Number.isFinite(wakeTimeoutMs) || wakeTimeoutMs < MIN_WAKE_TIMEOUT_MS || wakeTimeoutMs > MAX_WAKE_TIMEOUT_MS) {
      throw new Error(`wakeTimeoutMs debe estar entre ${MIN_WAKE_TIMEOUT_MS} y ${MAX_WAKE_TIMEOUT_MS} ms`);
    }

    const enabled = config.enabled !== undefined ? Boolean(config.enabled) : existing.enabled;
    const excludeCrons = config.excludeCrons !== undefined ? Boolean(config.excludeCrons) : existing.excludeCrons;
    const excludeLiveSync = config.excludeLiveSync !== undefined ? Boolean(config.excludeLiveSync) : existing.excludeLiveSync;

    let schedule = existing.schedule || null;
    if (config.schedule !== undefined) {
      if (config.schedule === null) {
        schedule = null;
      } else if (typeof config.schedule === 'object') {
        const cp = getCronParser();
        const sleepCron = config.schedule.sleepCron ? String(config.schedule.sleepCron).trim() : null;
        const wakeCron = config.schedule.wakeCron ? String(config.schedule.wakeCron).trim() : null;
        if (sleepCron && cp && typeof cp.parseCron === 'function') cp.parseCron(sleepCron);
        if (wakeCron && cp && typeof cp.parseCron === 'function') cp.parseCron(wakeCron);
        schedule = (sleepCron || wakeCron) ? { sleepCron, wakeCron } : null;
      } else {
        throw new Error('schedule debe ser un objeto { sleepCron, wakeCron } o null');
      }
    }

    const updated = {
      ...existing,
      projectId: pid,
      enabled,
      mode: /** @type {'pause' | 'stop'} */ (modeRaw),
      idleMinutes: Math.round(idleMinutes),
      wakeTimeoutMs: Math.round(wakeTimeoutMs),
      excludeCrons,
      excludeLiveSync,
      schedule,
      updatedAt: new Date().toISOString()
    };

    this.policies.set(pid, updated);
    this._save();
    this._syncScheduler();
    return this.getPolicy(pid);
  }

  /** @param {string} projectId */
  deletePolicy(projectId) {
    this._ensureLoaded();
    const pid = String(projectId || '').trim();
    const existed = this.policies.delete(pid);
    if (existed) {
      this._save();
      this._syncScheduler();
    }
    return { deleted: existed, projectId: pid };
  }

  /**
   * Lista todas las políticas configuradas (opcionalmente filtradas por ACL `projectIds`).
   * @param {{ projectIds?: string[] | null }} [opts]
   */
  listPolicies(opts = {}) {
    this._ensureLoaded();
    let ids = Array.from(this.policies.keys());
    if (Array.isArray(opts.projectIds)) {
      const allowed = new Set(opts.projectIds);
      ids = ids.filter((id) => allowed.has(id));
    }
    return ids.map((id) => this.getPolicy(id));
  }

  /**
   * Comprobación síncrona rápida usada por `ingressManager` y `deployManager.checkProductionHealth()`.
   * @param {string} projectId
   * @returns {boolean}
   */
  isSleeping(projectId) {
    this._ensureLoaded();
    const pol = this.policies.get(projectId);
    if (pol && pol.sleeping) return true;
    const dm = this._getDep('deployManager');
    if (dm?.store?.[projectId]?.current?.status === 'sleeping') return true;
    return false;
  }

  /**
   * Detecta operaciones activas que impiden suspender un proyecto con seguridad:
   *  1. Despliegue en curso (`deployManager.locks`)
   *  2. Sesión Live Sync activa (`liveSyncEngine.sessions`)
   *  3. Tarea cron en ejecución (`cronManager.runningJobs`, si `excludeCrons` está activo)
   *
   * @param {string} projectId
   * @returns {Array<{ code: 'active_deploy' | 'active_livesync' | 'active_cron', message: string }>}
   */
  getActiveSleepBlockers(projectId) {
    /** @type {Array<{ code: 'active_deploy' | 'active_livesync' | 'active_cron', message: string }>} */
    const blockers = [];
    const pol = this.policies.get(projectId);
    const excludeCrons = pol ? pol.excludeCrons !== false : true;
    const excludeLiveSync = pol ? pol.excludeLiveSync !== false : true;

    const dm = this._getDep('deployManager');
    if (dm && dm.locks && typeof dm.locks.has === 'function' && dm.locks.has(projectId)) {
      blockers.push({
        code: 'active_deploy',
        message: 'Hay un despliegue o operación de producción en curso (deployManager.locks)'
      });
    }

    if (excludeLiveSync) {
      const ls = this._getDep('liveSyncEngine');
      let connectedClients = 0;
      if (ls && ls.sessions && typeof ls.sessions.get === 'function') {
        const s = ls.sessions.get(projectId);
        if (s && Number(s.connectedClients) > 0) connectedClients = Number(s.connectedClients);
      } else if (ls && typeof ls.getStatus === 'function') {
        try {
          const st = ls.getStatus(projectId);
          if (st && Number(st.connectedClients) > 0) connectedClients = Number(st.connectedClients);
        } catch (e) {}
      }
      if (connectedClients > 0) {
        blockers.push({
          code: 'active_livesync',
          message: `Hay ${connectedClients} cliente(s) conectado(s) en Live Sync`
        });
      }
    }

    if (excludeCrons) {
      const cm = this._getDep('cronManager');
      let hasRunningCron = false;
      if (cm && cm.runningJobs && cm.runningJobs.size > 0) {
        const jobs = Array.isArray(cm.jobs) ? cm.jobs : (typeof cm.list === 'function' ? cm.list(projectId) : []);
        for (const j of jobs) {
          if (j && j.projectId === projectId && cm.runningJobs.has(j.id)) {
            hasRunningCron = true;
            break;
          }
        }
      } else if (cm && typeof cm.list === 'function') {
        try {
          const jobs = cm.list(projectId);
          if (Array.isArray(jobs) && jobs.some((j) => j && j.running === true)) {
            hasRunningCron = true;
          }
        } catch (e) {}
      }
      if (hasRunningCron) {
        blockers.push({
          code: 'active_cron',
          message: 'Hay una tarea cron ejecutándose para este proyecto'
        });
      }
    }

    return blockers;
  }

  /**
   * Suspende un proyecto (`docker pause` o `docker stop --time 10`) protegiendo
   * crons/LiveSync/deploys activos y sincronizando estado con Culkibo.
   * @param {string} projectId
   * @param {{ mode?: 'pause' | 'stop', reason?: string }} [opts]
   */
  async sleepProject(projectId, opts = {}) {
    this._ensureLoaded();
    const pid = String(projectId || '').trim();
    if (!PROJECT_ID_RE.test(pid)) {
      throw new Error('projectId inválido');
    }

    if (this._inFlightWakes.has(pid)) {
      return {
        slept: false,
        blocked: true,
        projectId: pid,
        blockers: ['active_wake'],
        reason: 'Hay una reactivación en curso para este proyecto'
      };
    }

    const existingSleep = this._inFlightSleeps.get(pid);
    if (existingSleep) {
      return existingSleep;
    }

    const flight = this._doSleep(pid, opts).finally(() => {
      if (this._inFlightSleeps.get(pid) === flight) {
        this._inFlightSleeps.delete(pid);
      }
    });
    this._inFlightSleeps.set(pid, flight);
    return flight;
  }

  /**
   * @param {string} pid
   * @param {{ mode?: 'pause' | 'stop', reason?: string }} opts
   */
  async _doSleep(pid, opts = {}) {
    const blockers = this.getActiveSleepBlockers(pid);
    if (blockers.length > 0) {
      return {
        slept: false,
        blocked: true,
        projectId: pid,
        blockers: blockers.map((b) => b.code),
        reason: blockers.map((b) => b.message).join('; ')
      };
    }

    const pol = this.policies.get(pid) || this._defaultPolicy(pid);
    const mode = opts.mode ? String(opts.mode).toLowerCase() : pol.mode;
    if (mode !== 'pause' && mode !== 'stop') {
      throw new Error('Modo de auto-sleep inválido: usa "pause" o "stop"');
    }

    if (this.isSleeping(pid)) {
      return {
        slept: true,
        alreadySleeping: true,
        blocked: false,
        projectId: pid,
        mode: pol.sleepMode || mode,
        containerName: pol.sleepingContainer || null
      };
    }

    const dm = this._getDep('deployManager');
    const current = dm?.store?.[pid]?.current || null;
    const containerName = current?.containerName ? String(current.containerName).trim() : '';
    if (!containerName || !CONTAINER_NAME_RE.test(containerName)) {
      return {
        slept: false,
        blocked: false,
        projectId: pid,
        reason: 'El proyecto no tiene un contenedor de producción activo para suspender'
      };
    }

    const dockerArgs = mode === 'stop'
      ? ['stop', '--time', '10', containerName]
      : ['pause', containerName];
    const dockerRes = await this._runDocker(dockerArgs, 25000);
    if (!dockerRes.ok) {
      return {
        slept: false,
        blocked: false,
        projectId: pid,
        containerName,
        mode,
        error: dockerRes.stderr.trim() || `docker ${mode} falló (código ${dockerRes.code})`
      };
    }

    const nowIso = new Date().toISOString();
    const cachedStat = this._lastContainerStats.get(containerName);
    const pm = this._getDep('projectManager');
    const proj = pm && typeof pm.getById === 'function' ? pm.getById(pid) : null;
    const estRamMb = cachedStat?.memUsedMb != null
      ? Math.round(cachedStat.memUsedMb)
      : (Number(proj?.memoryMb) > 0 ? Math.round(Number(proj.memoryMb) * 0.5) : 128);

    pol.sleeping = true;
    pol.sleepMode = /** @type {'pause' | 'stop'} */ (mode);
    pol.sleptAt = nowIso;
    pol.sleepingContainer = containerName;
    pol.lastHostPort = Number.isInteger(current?.hostPort) ? current.hostPort : pol.lastHostPort;
    pol.ramSavedMb = mode === 'stop' ? estRamMb : 0;
    pol.updatedAt = nowIso;
    this.policies.set(pid, pol);

    // Sincronizar deployManager + projectManager + ingress (evita desincronización tipo Sablier)
    if (current) {
      current.status = 'sleeping';
      if (typeof dm.saveStore === 'function') {
        try { dm.saveStore(); } catch (e) {}
      }
    }
    if (pm && typeof pm.hibernate === 'function' && proj) {
      try { pm.hibernate(pid); } catch (e) {}
    }

    this._save();

    const im = this._getDep('ingressManager');
    if (im && typeof im.reconcile === 'function') {
      im.reconcile().catch(() => {});
    }

    const payload = {
      slept: true,
      blocked: false,
      projectId: pid,
      mode,
      containerName,
      sleptAt: nowIso,
      ramReclaimedMb: pol.ramSavedMb,
      reason: opts.reason || 'auto_sleep'
    };
    this.emit('project_slept', payload);
    return payload;
  }

  // -------------------------------------------------------------------------
  // Despertar Single-Flight + Límite de Tasa por IP + Proxy Wake Seguro
  // -------------------------------------------------------------------------

  /**
   * Comprueba el límite de tasa por IP + proyecto (ventana fija LRU acotada).
   * @param {string} clientIp
   * @param {string} projectId
   * @returns {{ allowed: boolean, retryAfterSec: number, remaining: number }}
   */
  checkWakeRateLimit(clientIp, projectId) {
    const ip = String(clientIp || '').trim();
    if (!ip) return { allowed: true, retryAfterSec: 0, remaining: this._wakeRateLimitMax };

    const key = `${ip}:${projectId}`;
    const now = Date.now();
    let entry = this._wakeRateHits.get(key);

    if (!entry || entry.resetAt <= now) {
      if (this._wakeRateHits.size >= MAX_RATE_KEYS) {
        for (const [k, v] of this._wakeRateHits.entries()) {
          if (v.resetAt <= now) this._wakeRateHits.delete(k);
          if (this._wakeRateHits.size < MAX_RATE_KEYS) break;
        }
        if (this._wakeRateHits.size >= MAX_RATE_KEYS) {
          const oldest = this._wakeRateHits.keys().next().value;
          if (oldest) this._wakeRateHits.delete(oldest);
        }
      }
      entry = { count: 1, resetAt: now + this._wakeRateWindowMs };
      this._wakeRateHits.set(key, entry);
      return { allowed: true, retryAfterSec: 0, remaining: Math.max(0, this._wakeRateLimitMax - 1) };
    }

    entry.count += 1;
    // Refrescar orden LRU
    this._wakeRateHits.delete(key);
    this._wakeRateHits.set(key, entry);

    if (entry.count > this._wakeRateLimitMax) {
      return {
        allowed: false,
        retryAfterSec: Math.max(1, Math.ceil((entry.resetAt - now) / 1000)),
        remaining: 0
      };
    }
    return {
      allowed: true,
      retryAfterSec: 0,
      remaining: Math.max(0, this._wakeRateLimitMax - entry.count)
    };
  }

  /**
   * Despierta un proyecto dormido con coalescing single-flight por `projectId`
   * (múltiples peticiones simultáneas comparten 1 sola operación Docker).
   * @param {string} projectId
   * @param {{ clientIp?: string | null, skipHealthCheck?: boolean }} [opts]
   */
  async wakeProject(projectId, opts = {}) {
    this._ensureLoaded();
    const pid = String(projectId || '').trim();
    if (!PROJECT_ID_RE.test(pid)) {
      throw new Error('projectId inválido');
    }

    if (opts.clientIp) {
      const rl = this.checkWakeRateLimit(opts.clientIp, pid);
      if (!rl.allowed) {
        return {
          woken: false,
          rateLimited: true,
          retryAfterSec: rl.retryAfterSec,
          projectId: pid,
          coalesced: false
        };
      }
    }

    const existingFlight = this._inFlightWakes.get(pid);
    if (existingFlight) {
      const sharedRes = await existingFlight;
      return { ...sharedRes, coalesced: true };
    }

    const flight = this._doWake(pid, opts).finally(() => {
      if (this._inFlightWakes.get(pid) === flight) {
        this._inFlightWakes.delete(pid);
      }
    });
    this._inFlightWakes.set(pid, flight);
    const result = await flight;
    return { ...result, coalesced: false };
  }

  /**
   * @param {string} pid
   * @param {{ skipHealthCheck?: boolean }} opts
   */
  async _doWake(pid, opts = {}) {
    const start = Date.now();
    // Serializar con cualquier sleepProject en vuelo para no devolver alreadyAwake mientras se detiene el contenedor
    const pendingSleep = this._inFlightSleeps.get(pid);
    if (pendingSleep) {
      await pendingSleep.catch(() => {});
    }
    const pol = this.policies.get(pid) || this._defaultPolicy(pid);
    const dm = this._getDep('deployManager');
    const current = dm?.store?.[pid]?.current || null;
    const containerName = String(pol.sleepingContainer || current?.containerName || '').trim();
    const hostPort = Number.isInteger(current?.hostPort) ? current.hostPort : pol.lastHostPort;

    if (!containerName || !CONTAINER_NAME_RE.test(containerName)) {
      return {
        woken: false,
        rateLimited: false,
        projectId: pid,
        error: 'No hay contenedor asociado para despertar este proyecto'
      };
    }

    if (!this.isSleeping(pid)) {
      pol.lastActivityAt = Date.now();
      return {
        woken: true,
        alreadyAwake: true,
        rateLimited: false,
        projectId: pid,
        mode: pol.sleepMode || pol.mode,
        containerName,
        hostPort: hostPort || null,
        wakeLatencyMs: 0,
        error: null
      };
    }

    const mode = pol.sleepMode || pol.mode || 'pause';
    const wakeTimeoutMs = pol.wakeTimeoutMs || DEFAULT_WAKE_TIMEOUT_MS;
    const dockerArgs = mode === 'stop' ? ['start', containerName] : ['unpause', containerName];
    const res = await this._runDocker(dockerArgs, Math.min(30000, wakeTimeoutMs));

    if (!res.ok) {
      return {
        woken: false,
        rateLimited: false,
        projectId: pid,
        mode,
        containerName,
        hostPort: hostPort || null,
        wakeLatencyMs: Date.now() - start,
        error: res.stderr.trim() || `docker ${dockerArgs[0]} falló (código ${res.code})`
      };
    }

    // Esperar a salud tras arrancar (si procede)
    if (!opts.skipHealthCheck && hostPort) {
      if (this._healthCheck) {
        const h = await this._healthCheck({ projectId: pid, hostPort, containerName, timeoutMs: wakeTimeoutMs });
        if (!h || !h.healthy) {
          return {
            woken: false,
            rateLimited: false,
            projectId: pid,
            mode,
            containerName,
            hostPort,
            wakeLatencyMs: Date.now() - start,
            error: h?.reason || 'El contenedor no superó la comprobación de salud al despertar'
          };
        }
      } else if (mode === 'stop' && dm && typeof dm.waitForHealth === 'function') {
        const h = await dm.waitForHealth({
          hostPort,
          containerPort: current?.containerPort || null,
          healthPath: current?.healthPath || '/',
          containerName,
          timeoutMs: wakeTimeoutMs,
          intervalMs: 400
        }).catch((e) => ({ healthy: false, reason: e.message }));
        if (!h || !h.healthy) {
          return {
            woken: false,
            rateLimited: false,
            projectId: pid,
            mode,
            containerName,
            hostPort,
            wakeLatencyMs: Date.now() - start,
            error: h?.reason || 'Tiempo agotado esperando a que el contenedor responda tras despertar'
          };
        }
      }
    }

    const elapsedMs = Math.max(0, Date.now() - start);
    pol.sleeping = false;
    pol.sleptAt = null;
    pol.sleepingContainer = null;
    pol.lastActivityAt = Date.now();
    pol.lastWakeLatencyMs = elapsedMs;
    pol.wakeCount = (pol.wakeCount || 0) + 1;
    pol.ramSavedMb = 0;
    pol.updatedAt = new Date().toISOString();
    this.policies.set(pid, pol);

    if (current) {
      current.status = 'activo';
      if (typeof dm.saveStore === 'function') {
        try { dm.saveStore(); } catch (e) {}
      }
    }

    const pm = this._getDep('projectManager');
    if (pm && typeof pm.getById === 'function' && typeof pm.update === 'function') {
      try {
        const proj = pm.getById(pid);
        if (proj && proj.status === 'hibernated') {
          pm.update(pid, { status: 'running' });
        }
      } catch (e) {}
    }

    this._save();

    const im = this._getDep('ingressManager');
    if (im && typeof im.reconcile === 'function') {
      try { await im.reconcile(); } catch (e) {}
    }

    const payload = {
      woken: true,
      alreadyAwake: false,
      rateLimited: false,
      projectId: pid,
      mode,
      containerName,
      hostPort: hostPort || null,
      wakeLatencyMs: elapsedMs,
      error: null
    };
    this.emit('project_woken', payload);
    return payload;
  }

  /** Devuelve el secreto interno que Caddy debe inyectar en `X-Culkibo-Wake-Secret`. */
  getWakeSecret() {
    return this.wakeSecret;
  }

  /**
   * Valida que la petición `/_culkibo/wake/:projectId` venga de un proxy local/privado
   * de confianza Y porte la cabecera interna `X-Culkibo-Wake-Secret` (impide bypass de
   * `ipAllowlist` / `basicAuth` / `rateLimit` de Caddy).
   * @param {any} req
   * @returns {{ ok: boolean, reason: string | null }}
   */
  verifyWakeRequest(req) {
    const peer = String(req?.socket?.remoteAddress || req?.ip || '').replace(/^::ffff:/, '');
    const auth = getAuthMod();
    const isTrustedPeer = auth && typeof auth.isPrivateProxyPeer === 'function'
      ? auth.isPrivateProxyPeer(peer)
      : (peer === '127.0.0.1' || peer === '::1');
    if (!isTrustedPeer) {
      return { ok: false, reason: 'Origen de wake proxy no autorizado' };
    }
    const headerSecret = String(req?.headers?.['x-culkibo-wake-secret'] || '');
    if (!safeTimingEqual(headerSecret, this.wakeSecret)) {
      return { ok: false, reason: 'Cabecera X-Culkibo-Wake-Secret inválida o ausente' };
    }
    return { ok: true, reason: null };
  }

  /**
   * Genera HTML de espera "Despertando servicio...".
   * @param {string} projectName
   * @param {{ retryAfterSec?: number }} [opts]
   */
  renderWakingHtml(projectName, opts = {}) {
    return renderWakingHtml(projectName, opts);
  }

  /**
   * Manejador HTTP nativo para `/_culkibo/wake/:projectId`:
   *  - Verifica proxy de confianza + `X-Culkibo-Wake-Secret`.
   *  - Limita peticiones retenidas (25/proyecto, 100 global) y cuerpos > 1 MB.
   *  - Para navegadores (`Accept: text/html`), devuelve HTML ligero si tarda > 800 ms.
   *  - Para APIs/JSON, retiene hasta `wakeTimeoutMs` y reenvía únicamente a `127.0.0.1:<verifiedPort>`.
   * @param {any} req
   * @param {any} res
   * @param {string} projectId
   */
  async handleWakeRequest(req, res, projectId) {
    const verification = this.verifyWakeRequest(req);
    if (!verification.ok) {
      res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ error: verification.reason }));
      return;
    }

    const pid = String(projectId || '').trim();
    if (!PROJECT_ID_RE.test(pid)) {
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: 'projectId inválido' }));
      return;
    }

    const dm = this._getDep('deployManager');
    const pm = this._getDep('projectManager');
    const current = dm?.store?.[pid]?.current || null;
    const project = pm && typeof pm.getById === 'function' ? pm.getById(pid) : null;
    if (!current && !project) {
      res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: 'Proyecto no registrado' }));
      return;
    }

    const methodUpper = String(req?.method || 'GET').toUpperCase();
    const hasTransferEncoding = Boolean(req?.headers?.['transfer-encoding']);
    const contentLength = Number(req?.headers?.['content-length'] || 0);
    if (
      (hasTransferEncoding && methodUpper !== 'GET' && methodUpper !== 'HEAD') ||
      (Number.isFinite(contentLength) && contentLength > MAX_HELD_BODY_BYTES)
    ) {
      res.writeHead(503, { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': '2', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ error: 'Servicio despertando; reintenta en 2 segundos (cuerpo chunked o > 1 MiB no retenido)' }));
      return;
    }

    const heldForProj = this._heldByProject.get(pid) || 0;
    if (heldForProj >= MAX_HELD_PER_PROJECT || this._heldGlobal >= MAX_HELD_GLOBAL) {
      res.writeHead(503, { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': '2', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ error: 'Demasiadas peticiones en cola mientras despierta el servicio' }));
      return;
    }

    this._heldGlobal++;
    this._heldByProject.set(pid, heldForProj + 1);

    try {
      const clientIp = resolveWakeClientIp(req);
      const accept = String(req?.headers?.accept || '');
      const isBrowser = accept.includes('text/html');
      const projectName = String(project?.name || current?.projectName || pid);

      const wakePromise = this.wakeProject(pid, { clientIp });
      wakePromise.catch(() => {});

      if (isBrowser) {
        /** @type {any} */
        const raced = await Promise.race([
          wakePromise.then((w) => ({ kind: 'done', wake: w })),
          new Promise((resolve) => {
            const t = setTimeout(() => resolve({ kind: 'still_waking' }), BROWSER_HOLD_THRESHOLD_MS);
            if (t.unref) t.unref();
          })
        ]);

        if (raced.kind === 'still_waking') {
          const html = this.renderWakingHtml(projectName, { retryAfterSec: 2 });
          res.writeHead(503, {
            'Content-Type': 'text/html; charset=utf-8',
            'Content-Security-Policy': WAKING_PAGE_CSP,
            'Retry-After': '2',
            'Cache-Control': 'no-store'
          });
          res.end(html);
          return;
        }

        if (raced.wake?.rateLimited) {
          res.writeHead(429, { 'Content-Type': 'text/plain; charset=utf-8', 'Retry-After': String(raced.wake.retryAfterSec || 10) });
          res.end('Demasiadas peticiones de activación. Espera unos segundos.');
          return;
        }
        if (!raced.wake?.woken || !raced.wake?.hostPort) {
          res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': WAKING_PAGE_CSP, 'Retry-After': '3', 'Cache-Control': 'no-store' });
          res.end(this.renderWakingHtml(projectName, { retryAfterSec: 3 }));
          return;
        }
        await this._proxyToLocalPort(req, res, raced.wake.hostPort);
        return;
      }

      const wakeRes = await wakePromise;
      if (wakeRes.rateLimited) {
        res.writeHead(429, { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': String(wakeRes.retryAfterSec || 10) });
        res.end(JSON.stringify({ error: 'Límite de tasa excedido al despertar el servicio', retryAfterSec: wakeRes.retryAfterSec }));
        return;
      }
      if (!wakeRes.woken || !wakeRes.hostPort) {
        res.writeHead(503, { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': '2', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify({ error: wakeRes.error || 'No se pudo despertar el servicio' }));
        return;
      }
      await this._proxyToLocalPort(req, res, wakeRes.hostPort);
    } finally {
      this._heldGlobal = Math.max(0, this._heldGlobal - 1);
      const rem = (this._heldByProject.get(pid) || 1) - 1;
      if (rem <= 0) this._heldByProject.delete(pid);
      else this._heldByProject.set(pid, rem);
    }
  }

  /**
   * Reenvía una petición retenida únicamente hacia `127.0.0.1:<verifiedPort>`.
   * @param {any} req
   * @param {any} res
   * @param {number} hostPort
   */
  _proxyToLocalPort(req, res, hostPort) {
    const port = Number(hostPort);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: 'Puerto de destino inválido' }));
      return Promise.resolve();
    }
    const http = getHttp();
    return /** @type {Promise<void>} */ (new Promise((resolve) => {
      const headers = { ...(req.headers || {}) };
      delete headers['x-culkibo-wake-secret'];
      const origHost = req.headers?.['x-culkibo-wake-host'];
      if (origHost && typeof origHost === 'string' && !/[\r\n\0]/.test(origHost)) {
        headers.host = origHost;
      }
      delete headers['x-culkibo-wake-host'];
      const rawWakePath = req.headers?.['x-culkibo-wake-path'];
      delete headers['x-culkibo-wake-path'];
      const targetPath = (typeof rawWakePath === 'string' && rawWakePath.startsWith('/') && !/[\r\n\0]/.test(rawWakePath))
        ? rawWakePath
        : (req.originalUrl || req.url || '/');

      let settled = false;
      /** @type {any} */
      let activeProxyRes = null;
      const cleanup = () => {
        if (typeof req.off === 'function') {
          req.off('aborted', onClientAbort);
          req.off('data', onReqData);
          req.off('end', onReqEnd);
          req.off('error', onClientAbort);
        }
        if (typeof res.off === 'function') {
          res.off('close', onResClose);
        }
      };
      const done = () => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve();
      };
      const onClientAbort = () => {
        try { proxyReq.destroy(); } catch (e) {}
        try { if (activeProxyRes) activeProxyRes.destroy(); } catch (e) {}
        done();
      };
      const onResClose = () => {
        if (!res.writableEnded) {
          onClientAbort();
        } else {
          done();
        }
      };

      const proxyReq = http.request({
        hostname: '127.0.0.1',
        port,
        method: req.method || 'GET',
        path: targetPath,
        headers,
        timeout: 15000
      }, (proxyRes) => {
        activeProxyRes = proxyRes;
        if (!res.headersSent) {
          res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
        }
        proxyRes.pipe(res);
        proxyRes.once('end', done);
        proxyRes.once('error', done);
      });

      proxyReq.on('timeout', () => {
        proxyReq.destroy(new Error('Tiempo de espera agotado conectando con el contenedor despertado'));
      });
      proxyReq.on('error', () => {
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ error: 'No se pudo conectar con el contenedor recién despertado' }));
        }
        done();
      });

      if (typeof req.once === 'function') {
        req.once('aborted', onClientAbort);
        req.once('error', onClientAbort);
      }
      if (typeof res.once === 'function') {
        res.once('close', onResClose);
      }

      let streamedBytes = 0;
      const onReqData = (chunk) => {
        streamedBytes += Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(String(chunk));
        if (streamedBytes > MAX_HELD_BODY_BYTES) {
          proxyReq.destroy(new Error('Cuerpo de petición excede 1 MiB durante wake proxy'));
          if (!res.headersSent) {
            res.writeHead(413, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
            res.end(JSON.stringify({ error: 'El cuerpo de la petición excede el límite de 1 MiB' }));
          }
          done();
          return;
        }
        proxyReq.write(chunk);
      };
      const onReqEnd = () => {
        if (!settled) proxyReq.end();
      };

      const method = String(req.method || 'GET').toUpperCase();
      if (typeof req.on === 'function' && method !== 'GET' && method !== 'HEAD' && !req.readableEnded) {
        req.on('data', onReqData);
        req.once('end', onReqEnd);
      } else {
        proxyReq.end();
      }
    }));
  }

  // -------------------------------------------------------------------------
  // Barrido de inactividad (NetIO deltas) + Planificador perezoso
  // -------------------------------------------------------------------------

  /**
   * Consulta `docker stats --no-stream --format {{json .}}` en una sola invocación
   * (sin shell) y actualiza deltas de tráfico NetIO por contenedor.
   * @returns {Promise<{ available: boolean, containers: Array<any>, error: string | null }>}
   */
  async collectContainerStats() {
    const res = await this._runDocker(['stats', '--no-stream', '--format', '{{json .}}'], 10000);
    if (!res.ok) {
      return { available: false, containers: [], error: res.stderr.trim() || 'Docker no disponible' };
    }

    const now = Date.now();
    const containers = [];
    const lines = res.stdout.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);

    for (const line of lines) {
      let row;
      try {
        row = JSON.parse(line);
      } catch (e) {
        continue;
      }
      const name = String(row.Name || row.Container || '').trim().replace(/^\//, '');
      if (!name) continue;

      const memParts = String(row.MemUsage || '0B / 0B').split('/');
      const memUsedBytes = parseDockerBytes(memParts[0] || '0B');
      const memLimitBytes = parseDockerBytes(memParts[1] || '0B');
      const memUsedMb = Number((memUsedBytes / (1024 * 1024)).toFixed(1));
      const memLimitMb = Number((memLimitBytes / (1024 * 1024)).toFixed(1));
      const memPct = row.MemPerc
        ? parseDockerPercent(row.MemPerc)
        : (memLimitBytes > 0 ? Number(((memUsedBytes / memLimitBytes) * 100).toFixed(2)) : 0);
      const cpuPct = parseDockerPercent(row.CPUPerc || '0%');

      const netParts = String(row.NetIO || '0B / 0B').split('/');
      const netRxBytes = parseDockerBytes(netParts[0] || '0B');
      const netTxBytes = parseDockerBytes(netParts[1] || '0B');
      const netTotalBytes = netRxBytes + netTxBytes;

      const prev = this._netIoTracker.get(name);
      let netBytesPerMin = 0;
      let deltaBytes = 0;
      if (prev && now > prev.ts) {
        deltaBytes = Math.max(0, netTotalBytes - prev.totalBytes);
        const elapsedMin = Math.max(0.05, (now - prev.ts) / 60000);
        netBytesPerMin = Math.round(deltaBytes / elapsedMin);
      } else {
        // Primera observación: usar tráfico acumulado bajo como señal inicial si < 64 KB
        netBytesPerMin = netTotalBytes < 64 * 1024 ? Math.round(netTotalBytes / 10) : 2048;
      }
      this._netIoTracker.set(name, { totalBytes: netTotalBytes, ts: now, bytesPerMin: netBytesPerMin });

      const entry = {
        name,
        id: String(row.ID || row.Container || '').trim(),
        cpuPct,
        memUsedMb,
        memLimitMb,
        memPct,
        netRxBytes,
        netTxBytes,
        netTotalBytes,
        netDeltaBytes: deltaBytes,
        netBytesPerMin,
        pids: parseInt(String(row.PIDs || '0'), 10) || 0,
        sampledAt: now
      };
      this._lastContainerStats.set(name, entry);
      containers.push(entry);
    }

    return { available: true, containers, error: null };
  }

  /**
   * Evalúa horarios cron (`schedule.sleepCron` / `schedule.wakeCron`) e inactividad
   * de todos los proyectos con Auto-Sleep habilitado.
   * @param {{ now?: number }} [opts]
   */
  async checkIdleProjects(opts = {}) {
    this._ensureLoaded();
    const now = Number.isFinite(Number(opts.now)) ? Number(opts.now) : Date.now();
    const nowDate = new Date(now);
    const allEnabled = Array.from(this.policies.values()).filter((p) => p.enabled);
    if (allEnabled.length === 0) return { checked: 0, slept: [], woken: [] };

    /** @type {string[]} */
    const slept = [];
    /** @type {string[]} */
    const woken = [];

    // 1. Evaluar horarios programados (`schedule.sleepCron` / `schedule.wakeCron`)
    for (const pol of allEnabled) {
      if (!pol.schedule || typeof pol.schedule !== 'object') continue;
      if (pol.sleeping && pol.schedule.wakeCron && cronMatchesDate(pol.schedule.wakeCron, nowDate)) {
        const res = await this.wakeProject(pol.projectId).catch(() => null);
        if (res && res.woken) woken.push(pol.projectId);
      } else if (!pol.sleeping && pol.schedule.sleepCron && cronMatchesDate(pol.schedule.sleepCron, nowDate)) {
        const res = await this.sleepProject(pol.projectId, { reason: 'cron_schedule' }).catch(() => null);
        if (res && res.slept) slept.push(pol.projectId);
      }
    }

    // 2. Evaluar proyectos activos por umbral de inactividad NetIO/CPU
    const awakePolicies = allEnabled.filter((p) => !p.sleeping && !slept.includes(p.projectId));
    if (awakePolicies.length === 0) return { checked: allEnabled.length, slept, woken };

    const stats = await this.collectContainerStats();
    if (!stats.available) {
      return { checked: allEnabled.length, slept, woken, skippedReason: stats.error || 'docker_unavailable' };
    }
    const statsByName = new Map(stats.containers.map((c) => [c.name, c]));
    const dm = this._getDep('deployManager');

    for (const pol of awakePolicies) {
      const current = dm?.store?.[pol.projectId]?.current;
      if (!current || !current.containerName || current.status === 'sleeping' || current.status === 'detenido') {
        continue;
      }
      const stat = statsByName.get(current.containerName);
      if (!stat) {
        // Sin telemetría confirmada del contenedor: nunca suspender a ciegas
        continue;
      }
      if (stat.netDeltaBytes >= 1024 || stat.cpuPct >= 5) {
        pol.lastActivityAt = now;
        continue;
      }
      const idleMs = now - (pol.lastActivityAt || now);
      if (idleMs >= pol.idleMinutes * 60 * 1000) {
        const res = await this.sleepProject(pol.projectId, { reason: 'idle_timeout' }).catch(() => null);
        if (res && res.slept) slept.push(pol.projectId);
      }
    }

    return { checked: allEnabled.length, slept, woken };
  }

  // -------------------------------------------------------------------------
  // VPS Cost & RAM Advisor (`analyzeResources`, `getSleepCandidates`, `getDoctorSummary`)
  // -------------------------------------------------------------------------

  /**
   * Construye el índice de metadatos de Culkibo (proyectos, DBs, catálogo, previews)
   * mapeados por nombre de contenedor.
   */
  _collectWorkloadCatalog() {
    const dm = this._getDep('deployManager');
    const pm = this._getDep('projectManager');
    const dbm = this._getDep('databaseManager');
    const cm = this._getDep('catalogManager');
    const prevm = this._getDep('previewManager');

    /** @type {Map<string, any>} */
    const byContainer = new Map();
    /** @type {Array<any>} */
    const workloads = [];

    const projects = pm && typeof pm.getAll === 'function' ? pm.getAll() : [];
    const projById = new Map(projects.map((p) => [p.id, p]));

    for (const [projectId, state] of Object.entries(dm?.store || {})) {
      const cur = state?.current;
      if (!cur) continue;
      const proj = projById.get(projectId);
      const rec = {
        kind: 'project',
        projectId,
        name: proj?.name || cur.projectName || projectId,
        containerName: cur.containerName || null,
        status: cur.status || 'activo',
        memoryMb: Number(proj?.memoryMb) || 512,
        cpus: Number(proj?.cpus) || 0.5,
        oomKilled: Boolean(cur.oomKilled),
        sleeping: this.isSleeping(projectId)
      };
      workloads.push(rec);
      if (rec.containerName) byContainer.set(rec.containerName, rec);
    }

    if (dbm && typeof dbm.list === 'function') {
      try {
        for (const db of dbm.list()) {
          if (!db) continue;
          const rec = {
            kind: 'database',
            projectId: db.projectId || null,
            name: db.name || db.id,
            containerName: db.containerName || null,
            status: db.status || 'running',
            memoryMb: Number(db.memoryMb) || 512,
            cpus: Number(db.cpus) || 0.5,
            oomKilled: false,
            sleeping: false
          };
          workloads.push(rec);
          if (rec.containerName) byContainer.set(rec.containerName, rec);
        }
      } catch (e) {}
    }

    if (cm) {
      try {
        const installs = typeof cm.list === 'function'
          ? cm.list()
          : (typeof cm.listInstallations === 'function' ? cm.listInstallations() : []);
        for (const inst of installs || []) {
          if (!inst) continue;
          const cName = inst.containerName || inst.appContainer || null;
          const rec = {
            kind: 'catalog',
            projectId: inst.projectId || null,
            name: inst.name || inst.templateId || inst.id,
            containerName: cName,
            status: inst.status || 'running',
            memoryMb: Number(inst.memoryMb) || 512,
            cpus: Number(inst.cpus) || 0.5,
            oomKilled: false,
            sleeping: false
          };
          workloads.push(rec);
          if (cName) byContainer.set(cName, rec);
        }
      } catch (e) {}
    }

    if (prevm && typeof prevm.list === 'function') {
      try {
        for (const prev of prevm.list()) {
          if (!prev) continue;
          const rec = {
            kind: 'preview',
            projectId: prev.projectId || null,
            name: prev.name || prev.branch || prev.id,
            containerName: prev.containerName || null,
            status: prev.status || 'running',
            memoryMb: Number(prev.memoryMb) || 256,
            cpus: Number(prev.cpus) || 0.25,
            oomKilled: false,
            sleeping: false
          };
          workloads.push(rec);
          if (rec.containerName) byContainer.set(rec.containerName, rec);
        }
      } catch (e) {}
    }

    return { workloads, byContainer };
  }

  /**
   * Devuelve candidatos actuales a Auto-Sleep (síncrono, listo para `systemDoctor` y UI).
   * @param {{ projectIds?: string[] | null }} [opts]
   */
  getSleepCandidates(opts = {}) {
    this._ensureLoaded();
    const allowedSet = Array.isArray(opts.projectIds) ? new Set(opts.projectIds) : null;
    const { workloads } = this._collectWorkloadCatalog();
    /** @type {Array<any>} */
    const candidates = [];

    for (const w of workloads) {
      if (w.kind !== 'project' || !w.projectId) continue;
      if (allowedSet && !allowedSet.has(w.projectId)) continue;
      if (w.sleeping || w.status === 'sleeping' || w.status === 'detenido') continue;

      const pol = this.policies.get(w.projectId);
      if (pol && pol.enabled) continue;

      const stat = w.containerName ? this._lastContainerStats.get(w.containerName) : null;
      const netBytesPerMin = stat ? stat.netBytesPerMin : 0;
      const cpuPct = stat ? stat.cpuPct : 0;
      const memUsedMb = stat ? stat.memUsedMb : Math.round(w.memoryMb * 0.4);

      const isIdle = stat ? (netBytesPerMin < 1024 && cpuPct < 2) : true;
      if (!isIdle) continue;

      candidates.push({
        projectId: w.projectId,
        projectName: w.name,
        containerName: w.containerName,
        memUsedMb: Math.round(memUsedMb),
        cpuPct,
        netBytesPerMin,
        reclaimableRamMb: Math.round(memUsedMb),
        suggestedMode: 'stop',
        suggestedIdleMinutes: 15
      });
    }

    candidates.sort((a, b) => b.reclaimableRamMb - a.reclaimableRamMb);
    return candidates;
  }

  /**
   * Guarda la configuración del asesor (p. ej. coste mensual del VPS en EUR).
   * @param {{ vpsMonthlyEur?: number }} [cfg]
   */
  setAdvisorConfig(cfg = {}) {
    this._ensureLoaded();
    if (cfg.vpsMonthlyEur !== undefined) {
      const parsed = Number(cfg.vpsMonthlyEur);
      if (!Number.isFinite(parsed) || parsed < 0 || parsed > 100000) {
        throw new Error('vpsMonthlyEur debe ser un número entre 0 y 100000');
      }
      this._persistedVpsMonthlyEur = Number(parsed.toFixed(2));
      this._save();
    }
    return { vpsMonthlyEur: this._persistedVpsMonthlyEur };
  }

  /**
   * Analizador completo de RAM, CPU, riesgos OOM, límites sobredimensionados,
   * candidatos a Auto-Sleep y comparativa real €/mes VPS vs PaaS SaaS.
   *
   * @param {{ vpsMonthlyEur?: number, projectIds?: string[] | null }} [opts]
   */
  async analyzeResources(opts = {}) {
    this._ensureLoaded();
    let vpsMonthlyEur = this._persistedVpsMonthlyEur;
    if (opts.vpsMonthlyEur !== undefined && opts.vpsMonthlyEur !== null) {
      const parsed = Number(opts.vpsMonthlyEur);
      if (!Number.isFinite(parsed) || parsed < 0 || parsed > 100000) {
        throw new Error('vpsMonthlyEur debe ser un número entre 0 y 100000');
      }
      vpsMonthlyEur = Number(parsed.toFixed(2));
    }

    const totalMemMb = Math.round(os.totalmem() / (1024 * 1024));
    const freeMemMb = Math.round(getHostAvailableMemBytes() / (1024 * 1024));
    const usedMemMb = Math.max(0, totalMemMb - freeMemMb);
    const freeMemPct = totalMemMb > 0 ? Number(((freeMemMb / totalMemMb) * 100).toFixed(1)) : 100;
    const usedMemPct = totalMemMb > 0 ? Number(((usedMemMb / totalMemMb) * 100).toFixed(1)) : 0;
    const cpuCount = os.cpus().length || 1;
    const loadAvg1m = Number((os.loadavg()[0] || 0).toFixed(2));
    const daemonRssMb = Math.round(process.memoryUsage().rss / (1024 * 1024));

    const dockerStats = await this.collectContainerStats();
    const { workloads, byContainer } = this._collectWorkloadCatalog();
    const allowedSet = Array.isArray(opts.projectIds) ? new Set(opts.projectIds) : null;

    /** @type {Array<any>} */
    const containers = [];
    /** @type {Array<any>} */
    const recommendations = [];
    /** @type {Array<any>} */
    const oomRisks = [];
    /** @type {Array<any>} */
    const idleCandidates = [];
    /** @type {Array<any>} */
    const oversizedCaps = [];

    let totalContainerMemUsedMb = 0;

    for (const stat of dockerStats.containers) {
      const meta = byContainer.get(stat.name) || null;
      if (allowedSet && (!meta || !meta.projectId || !allowedSet.has(meta.projectId))) {
        continue;
      }
      totalContainerMemUsedMb += stat.memUsedMb;

      const configuredLimitMb = meta?.memoryMb || (stat.memLimitMb > 0 && stat.memLimitMb < totalMemMb * 0.95 ? stat.memLimitMb : 0);
      const effectiveLimitMb = configuredLimitMb > 0 ? configuredLimitMb : stat.memLimitMb;
      const effectiveMemPct = effectiveLimitMb > 0
        ? Number(((stat.memUsedMb / effectiveLimitMb) * 100).toFixed(1))
        : stat.memPct;

      const item = {
        containerName: stat.name,
        projectId: meta?.projectId || null,
        name: meta?.name || stat.name,
        kind: meta?.kind || 'container',
        cpuPct: stat.cpuPct,
        memUsedMb: stat.memUsedMb,
        memLimitMb: Math.round(effectiveLimitMb),
        memPct: effectiveMemPct,
        netBytesPerMin: stat.netBytesPerMin,
        pids: stat.pids,
        oomKilled: Boolean(meta?.oomKilled),
        sleepEnabled: Boolean(meta?.projectId && this.policies.get(meta.projectId)?.enabled)
      };
      containers.push(item);

      // 1. Riesgo de OOM (>85% de su límite de memoria o OOMKilled reciente)
      if (item.oomKilled || (item.memLimitMb > 0 && effectiveMemPct >= 85)) {
        const severity = (item.oomKilled || effectiveMemPct >= 92) ? 'critical' : 'high';
        const recommendedMemoryMb = ceilTo64Mb(Math.max(item.memLimitMb * 1.5, item.memUsedMb * 1.6));
        const rec = {
          id: `oom:${item.projectId || item.containerName}`,
          type: 'oom_risk',
          category: 'oom_risk',
          severity,
          projectId: item.projectId,
          projectName: item.name,
          target: item.name,
          containerName: item.containerName,
          title: `Riesgo OOM en ${item.name} (${effectiveMemPct}% de ${item.memLimitMb} MB)`,
          detail: item.oomKilled
            ? `El contenedor sufrió OOMKill recientemente. Sube memoryMb a ${recommendedMemoryMb} MB.`
            : `Uso de RAM al ${effectiveMemPct}% (${item.memUsedMb} / ${item.memLimitMb} MB). Sube el límite a ${recommendedMemoryMb} MB para evitar reinicios.`,
          reclaimableRamMb: 0,
          estimatedMonthlySavingsEur: 0,
          recommendedMemoryMb,
          actionLabel: item.projectId ? `Subir a ${recommendedMemoryMb} MB` : null,
          action: { kind: 'resize_memory', projectId: item.projectId, recommendedMemoryMb }
        };
        oomRisks.push(rec);
        recommendations.push(rec);
      }

      // 2. Candidatos a Auto-Sleep (proyectos activos sin sleep y con tráfico < 1 KB/min)
      if (meta?.kind === 'project' && meta.projectId && !item.sleepEnabled && !meta.sleeping) {
        if (stat.netBytesPerMin < 1024 && stat.cpuPct < 2) {
          const reclaimMb = Math.max(16, Math.round(stat.memUsedMb));
          const ramShareEur = totalMemMb > 0 ? Number(((reclaimMb / totalMemMb) * vpsMonthlyEur).toFixed(2)) : 0;
          const rec = {
            id: `sleep:${meta.projectId}`,
            type: 'auto_sleep_candidate',
            category: 'auto_sleep',
            severity: reclaimMb >= 256 ? 'high' : 'medium',
            projectId: meta.projectId,
            projectName: item.name,
            target: item.name,
            containerName: item.containerName,
            title: `Activar Auto-Sleep en ${item.name} (${reclaimMb} MB recuperables)`,
            detail: `Tráfico casi nulo (${stat.netBytesPerMin} B/min, CPU ${stat.cpuPct}%). Activar auto-sleep en modo "stop" libera ~${reclaimMb} MB de RAM.`,
            reclaimableRamMb: reclaimMb,
            estimatedMonthlySavingsEur: ramShareEur,
            actionLabel: 'Activar Auto-Sleep',
            action: { kind: 'enable_sleep', projectId: meta.projectId, suggestedMode: 'stop', suggestedIdleMinutes: 15 }
          };
          idleCandidates.push(rec);
          recommendations.push(rec);
        }
      }

      // 3. Límites `memoryMb` sobredimensionados (<20% de uso con límite >= 256 MB)
      if (configuredLimitMb >= 256 && stat.memUsedMb > 0 && (stat.memUsedMb / configuredLimitMb) < 0.20) {
        const recommendedMemoryMb = Math.max(128, ceilTo64Mb(stat.memUsedMb * 2.5));
        if (recommendedMemoryMb < configuredLimitMb) {
          const headroomMb = Math.round(configuredLimitMb - recommendedMemoryMb);
          const rec = {
            id: `oversized:${item.projectId || item.containerName}`,
            type: 'oversized_memory_cap',
            category: 'oversized_ram',
            severity: 'low',
            projectId: item.projectId,
            projectName: item.name,
            target: item.name,
            containerName: item.containerName,
            title: `Límite RAM sobredimensionado en ${item.name} (${Math.round(stat.memUsedMb)} / ${configuredLimitMb} MB)`,
            detail: `Consume sólo el ${effectiveMemPct}% de su tope. Ajustar memoryMb a ${recommendedMemoryMb} MB libera ${headroomMb} MB de presupuesto reservado.`,
            reclaimableRamMb: headroomMb,
            estimatedMonthlySavingsEur: totalMemMb > 0 ? Number(((headroomMb / totalMemMb) * vpsMonthlyEur * 0.5).toFixed(2)) : 0,
            recommendedMemoryMb,
            actionLabel: item.projectId ? `Ajustar a ${recommendedMemoryMb} MB` : null,
            action: { kind: 'resize_memory', projectId: item.projectId, recommendedMemoryMb }
          };
          oversizedCaps.push(rec);
          recommendations.push(rec);
        }
      }
    }

    // Presión de RAM a nivel de host (<12% libre o <256 MB libres)
    if (freeMemPct < 12 || freeMemMb < 256) {
      const severity = (freeMemPct < 6 || freeMemMb < 128) ? 'critical' : 'high';
      const hostRisk = {
        type: 'host_memory_pressure',
        severity,
        projectId: null,
        target: 'host',
        containerName: null,
        title: `Presión de memoria en el VPS (${freeMemMb} MB / ${freeMemPct}% libres)`,
        detail: 'La RAM libre del servidor está por debajo del 12%. Activa Auto-Sleep en proyectos inactivos o amplía el VPS/swap.',
        reclaimableRamMb: 0,
        estimatedMonthlySavingsEur: 0,
        action: { kind: 'review_sleep_candidates' }
      };
      oomRisks.push(hostRisk);
      recommendations.push(hostRisk);
    }

    // Ordenar recomendaciones por severidad y MB recuperables
    const sevRank = { critical: 4, high: 3, medium: 2, low: 1 };
    recommendations.sort((a, b) => {
      const diff = (sevRank[b.severity] || 0) - (sevRank[a.severity] || 0);
      if (diff !== 0) return diff;
      return (b.reclaimableRamMb || 0) - (a.reclaimableRamMb || 0);
    });

    // Libro de ahorro SaaS vs VPS (€/mes)
    const activeWorkloads = workloads.filter((w) => {
      if (allowedSet && (!w.projectId || !allowedSet.has(w.projectId))) return false;
      return w.status !== 'detenido' && !w.sleeping;
    });

    let totalVcpu = 0;
    let totalAllocRamGb = 0;
    let renderEur = 0;
    const workloadCount = Math.max(activeWorkloads.length, containers.length);

    if (activeWorkloads.length > 0) {
      for (const w of activeWorkloads) {
        const vcpu = Math.max(0.25, Number(w.cpus) || 0.5);
        const ramMb = Math.max(128, Number(w.memoryMb) || 512);
        totalVcpu += vcpu;
        totalAllocRamGb += ramMb / 1024;
        renderEur += ramMb <= 512 ? 6.5 : (ramMb <= 2048 ? 23 : 78);
      }
    } else if (containers.length > 0) {
      for (const c of containers) {
        const ramMb = Math.max(128, c.memLimitMb > 0 && c.memLimitMb < totalMemMb ? c.memLimitMb : Math.max(256, c.memUsedMb * 2));
        totalVcpu += 0.5;
        totalAllocRamGb += ramMb / 1024;
        renderEur += ramMb <= 512 ? 6.5 : (ramMb <= 2048 ? 23 : 78);
      }
    }

    const railwayEur = Number((totalVcpu * 18.4 + totalAllocRamGb * 9.2).toFixed(2));
    const flyEur = Number((totalVcpu * 5.5 + totalAllocRamGb * 4.6 + workloadCount * 1.8).toFixed(2));
    renderEur = Number(renderEur.toFixed(2));

    const saasAverageMonthlyEur = workloadCount > 0
      ? Number(((railwayEur + renderEur + flyEur) / 3).toFixed(2))
      : 0;
    const monthlySavingsEur = Number((saasAverageMonthlyEur - vpsMonthlyEur).toFixed(2));
    const annualSavingsEur = Number((monthlySavingsEur * 12).toFixed(2));
    const savingsPct = saasAverageMonthlyEur > 0
      ? Number(((monthlySavingsEur / saasAverageMonthlyEur) * 100).toFixed(1))
      : 0;

    const totalReclaimableRamMb = idleCandidates.reduce((s, r) => s + (r.reclaimableRamMb || 0), 0);
    const potentialAdditionalSavingsEur = Number(
      idleCandidates.reduce((s, r) => s + (r.estimatedMonthlySavingsEur || 0), 0).toFixed(2)
    );

    const scopedPolicies = Array.from(this.policies.values()).filter(
      (p) => !allowedSet || allowedSet.has(p.projectId)
    );
    const sleepingProjectsCount = scopedPolicies.filter((p) => p.sleeping).length;
    const activeRamSavedBySleepMb = scopedPolicies.reduce((s, p) => s + (p.sleeping ? (p.ramSavedMb || 0) : 0), 0);

    return {
      generatedAt: new Date().toISOString(),
      dockerAvailable: dockerStats.available,
      host: {
        totalMemMb,
        freeMemMb,
        usedMemMb,
        usedMemPct,
        freeMemPct,
        cpuCount,
        loadAvg1m,
        daemonRssMb
      },
      summary: {
        containersCount: containers.length,
        activeWorkloadsCount: workloadCount,
        sleepingProjectsCount,
        activeRamSavedBySleepMb,
        totalContainerMemUsedMb: Number(totalContainerMemUsedMb.toFixed(1)),
        oomRiskCount: oomRisks.length,
        idleCandidatesCount: idleCandidates.length,
        oversizedCapsCount: oversizedCaps.length,
        reclaimableRamMb: totalReclaimableRamMb
      },
      containers,
      oomRisks,
      idleCandidates,
      oversizedCaps,
      recommendations,
      costLedger: {
        currency: 'EUR',
        vpsMonthlyEur,
        activeVcpu: Number(totalVcpu.toFixed(2)),
        activeRamGb: Number(totalAllocRamGb.toFixed(2)),
        activeServicesCount: workloadCount,
        providers: {
          railwayEur,
          renderEur,
          flyEur
        },
        saasAverageMonthlyEur,
        monthlySavingsEur,
        annualSavingsEur,
        savingsPct,
        potentialAdditionalSavingsEur
      }
    };
  }

  /**
   * Resumen compacto compatible con `systemDoctor.js` (check #10 `cost_ram_advisor`).
   * @param {{ vpsMonthlyEur?: number }} [opts]
   */
  async getDoctorSummary(opts = {}) {
    const analysis = await this.analyzeResources(opts);
    const { host, summary, costLedger } = analysis;

    const hasCritical = analysis.oomRisks.some((r) => r.severity === 'critical');
    const hasWarn = analysis.oomRisks.length > 0 || summary.idleCandidatesCount > 0;
    /** @type {'ok' | 'warn' | 'fail'} */
    const status = hasCritical ? 'fail' : (hasWarn ? 'warn' : 'ok');

    const savingsLabel = costLedger.monthlySavingsEur > 0
      ? `Ahorro estimado: €${costLedger.monthlySavingsEur}/mes vs SaaS`
      : `VPS €${costLedger.vpsMonthlyEur}/mes`;

    const summaryText = status === 'fail'
      ? `${summary.oomRiskCount} riesgo(s) OOM crítico(s) · RAM libre ${host.freeMemMb} MB (${host.freeMemPct}%)`
      : `${summary.containersCount} contenedor(es) · ${summary.reclaimableRamMb} MB recuperables con Auto-Sleep · ${savingsLabel}`;

    const detail = analysis.recommendations.length > 0
      ? analysis.recommendations.slice(0, 3).map((r) => r.title).join(' · ')
      : 'Sin riesgos de memoria OOM ni contenedores inactivos desaprovechando RAM.';

    return {
      id: 'cost_ram_advisor',
      name: 'Asesor de costes VPS, RAM y Auto-Sleep',
      status,
      summary: summaryText,
      detail,
      fixAction: summary.idleCandidatesCount > 0 ? 'review_sleep_candidates' : null,
      fixLabel: summary.idleCandidatesCount > 0 ? 'Revisar Auto-Sleep' : null,
      metrics: {
        hostFreeMb: host.freeMemMb,
        hostTotalMb: host.totalMemMb,
        hostFreePct: host.freeMemPct,
        daemonRssMb: host.daemonRssMb,
        containersCount: summary.containersCount,
        sleepingProjectsCount: summary.sleepingProjectsCount,
        oomRiskCount: summary.oomRiskCount,
        idleCandidatesCount: summary.idleCandidatesCount,
        reclaimableRamMb: summary.reclaimableRamMb,
        vpsMonthlyEur: costLedger.vpsMonthlyEur,
        saasAverageMonthlyEur: costLedger.saasAverageMonthlyEur,
        monthlySavingsEur: costLedger.monthlySavingsEur,
        annualSavingsEur: costLedger.annualSavingsEur
      }
    };
  }

  // -------------------------------------------------------------------------
  // Planificador perezoso (0 timers si no hay políticas habilitadas)
  // -------------------------------------------------------------------------

  _hasEnabledPolicies() {
    for (const p of this.policies.values()) {
      if (p.enabled) return true;
    }
    return false;
  }

  _syncScheduler() {
    if (this._stopped || !this._autoStart) return;
    if (this._hasEnabledPolicies()) {
      this._startTimer();
    } else {
      this._clearTimer();
    }
  }

  _startTimer() {
    if (this._timer) return;
    this._timer = setInterval(() => {
      this.checkIdleProjects().catch(() => {});
    }, SWEEP_INTERVAL_MS);
    if (this._timer.unref) this._timer.unref();
  }

  _clearTimer() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
  }

  start() {
    this._stopped = false;
    this._ensureLoaded();
    if (this._hasEnabledPolicies()) {
      this._startTimer();
    }
    return { running: Boolean(this._timer), enabledPolicies: Array.from(this.policies.values()).filter((p) => p.enabled).length };
  }

  stop() {
    this._stopped = true;
    this._clearTimer();
  }

  shutdown() {
    this.stop();
  }
}

const instance = /** @type {any} */ (new SleepAdvisor());
instance.SleepAdvisor = SleepAdvisor;
instance.renderWakingHtml = renderWakingHtml;
instance.parseDockerBytes = parseDockerBytes;
instance.getHostAvailableMemBytes = getHostAvailableMemBytes;
instance.resolveWakeClientIp = resolveWakeClientIp;
instance.WAKING_PAGE_CSP = WAKING_PAGE_CSP;

module.exports = instance;
