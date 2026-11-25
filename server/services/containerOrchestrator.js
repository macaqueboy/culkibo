const { EventEmitter } = require('events');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const metricsCollector = require('./metricsCollector');

const LOG_ROTATE_MAX_BYTES = 2 * 1024 * 1024; // 2 MiB rotated NDJSON ring (zero disk bloat)
const MAX_REGEX_LENGTH = 160;
const ANSI_ESCAPE_RE = /\x1B\[[0-9;]*[a-zA-Z]/g;

function resolveDefaultLogFile() {
  const dataDir = process.env.CULKIBO_DATA_DIR
    ? path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data')
    : path.resolve(__dirname, '..', '..', 'data');
  return path.join(dataDir, 'logs.ndjson');
}

function isRunningInTestMode() {
  if (process.env.NODE_ENV === 'test') return true;
  const argvJoined = (process.argv || []).join(' ').toLowerCase();
  return /[\\/](tests|bench)[\\/]/.test(argvJoined);
}

/**
 * Strips ANSI color escape codes from log messages.
 * @param {string} str
 */
function stripAnsi(str) {
  return String(str || '').replace(ANSI_ESCAPE_RE, '');
}

/**
 * Compiles a user-supplied regex safely with strict ReDoS protection.
 * Rejects nested quantifiers, backreferences, lookbehinds, excessive length/alternation.
 * @param {string} rawPattern
 * @param {string} [flags]
 * @returns {RegExp}
 */
function compileSafeRegex(rawPattern, flags = 'i') {
  const pattern = String(rawPattern || '');
  if (!pattern) throw new Error('Patrón regex vacío');
  if (pattern.length > MAX_REGEX_LENGTH) {
    const err = new Error(`Expresión regular demasiado larga (máx. ${MAX_REGEX_LENGTH} caracteres)`);
    /** @type {any} */ (err).status = 400;
    throw err;
  }
  // Reject backreferences (\1..\9) and lookbehind assertions
  if (/\\[1-9]/.test(pattern) || /\(\?<[=!]/.test(pattern)) {
    const err = new Error('Expresión regular rechazada por seguridad (backreferences/lookbehind no permitidos)');
    /** @type {any} */ (err).status = 400;
    throw err;
  }
  // Reject nested quantifiers inside capturing/non-capturing groups, e.g. (a+)+, (\w*)*, (a|aa)+, (.+){2,}
  if (/\([^)]*[+*?}][^)]*\)\s*[+*{]/.test(pattern) || /(\.\*){2,}/.test(pattern)) {
    const err = new Error('Expresión regular rechazada por riesgo de ReDoS (cuantificadores anidados)');
    /** @type {any} */ (err).status = 400;
    throw err;
  }
  // Reject excessive alternation branches
  const pipes = (pattern.match(/\|/g) || []).length;
  if (pipes > 12) {
    const err = new Error('Expresión regular rechazada por exceso de ramas de alternancia (máx. 12)');
    /** @type {any} */ (err).status = 400;
    throw err;
  }
  // Reject giant repetition ranges like {1,1000}
  const repMatch = pattern.match(/\{\s*(\d+)\s*(?:,\s*(\d*))?\s*\}/g);
  if (repMatch) {
    for (const r of repMatch) {
      const nums = r.match(/\d+/g) || [];
      if (nums.some((n) => Number(n) > 32)) {
        const err = new Error('Expresión regular rechazada por cuantificador excesivo (máx. 32)');
        /** @type {any} */ (err).status = 400;
        throw err;
      }
    }
  }
  const safeFlags = String(flags || 'i').replace(/[^ims]/g, '');
  try {
    return new RegExp(pattern, safeFlags);
  } catch (e) {
    const err = new Error(`Expresión regular inválida: ${e.message}`);
    /** @type {any} */ (err).status = 400;
    throw err;
  }
}

/**
 * Parses relative time windows (`5m`, `1h`, `24h`, `7d`) or ISO/epoch timestamps into epoch ms.
 * @param {string | number | null | undefined} input
 * @param {number} [now]
 * @returns {number | null}
 */
function parseTimeBoundary(input, now = Date.now()) {
  if (input === null || input === undefined || input === '') return null;
  if (typeof input === 'number' && Number.isFinite(input)) return input;
  const raw = String(input).trim();
  if (!raw) return null;
  if (/^\d{10,13}$/.test(raw)) {
    const num = Number(raw);
    return raw.length === 10 ? num * 1000 : num;
  }
  const rel = raw.match(/^(\d+)\s*(s|m|h|d)$/i);
  if (rel) {
    const qty = Number(rel[1]);
    const unit = rel[2].toLowerCase();
    const mult = unit === 's' ? 1000 : unit === 'm' ? 60000 : unit === 'h' ? 3600000 : 86400000;
    return now - qty * mult;
  }
  const parsed = Date.parse(raw);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * Extracts flat structured attributes from JSON log lines or `key=value` tokens.
 * Bounded to 12 scalar fields so memory stays tiny.
 * @param {string} message
 * @returns {Record<string, string | number | boolean> | null}
 */
function extractLogFields(message) {
  const clean = stripAnsi(message).trim();
  if (!clean) return null;
  /** @type {Record<string, string | number | boolean>} */
  const fields = {};
  let count = 0;

  // 1. JSON object log line (common in Pino, Winston, Zap, Go slog, Railway JSON logs)
  if (clean.startsWith('{') && clean.endsWith('}') && clean.length <= 8192) {
    try {
      const parsed = JSON.parse(clean);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        for (const [k, v] of Object.entries(parsed)) {
          if (count >= 12) break;
          if (!/^[a-zA-Z0-9_.-]{1,32}$/.test(k)) continue;
          if (typeof v === 'string') {
            fields[k] = v.slice(0, 120);
            count++;
          } else if (typeof v === 'number' && Number.isFinite(v)) {
            fields[k] = v;
            count++;
          } else if (typeof v === 'boolean') {
            fields[k] = v;
            count++;
          }
        }
        return count > 0 ? fields : null;
      }
    } catch (e) {}
  }

  // 2. Lightweight `key=value` tokens (e.g. `status=500 method=POST durationMs=42`)
  const kvRe = /\b([a-zA-Z][a-zA-Z0-9_]{1,24})=([^\s,;\]"']{1,64})/g;
  let m;
  while ((m = kvRe.exec(clean)) !== null && count < 12) {
    const k = m[1];
    const v = m[2];
    if (/(pass|secret|token|key|auth)/i.test(k)) continue;
    fields[k] = /^-?\d+(?:\.\d+)?$/.test(v) ? Number(v) : v;
    count++;
  }
  return count > 0 ? fields : null;
}

/** @type {any} */
let _chokidar = null;
function getChokidar() {
  if (!_chokidar) _chokidar = require('chokidar');
  return _chokidar;
}

class ContainerOrchestrator extends EventEmitter {
  constructor() {
    super();
    this.trafficAllocation = {
      forge: 0,
      citadel: 100
    };

    // Ring-buffer con índice descendente en push (O(1) en addLog, sin unshift O(N)).
    this.logs = [];
    this.maxLogs = 2000;
    /** @type {Map<string, any[]>} Buffer dedicado por proyecto (500 líneas/proyecto) para que un proyecto ruidoso no borre los logs de otros. */
    this.projectLogs = new Map();
    this.maxProjectLogs = 500;
    // Persistencia rotada NDJSON en disco (desactivada por defecto en tests sobre `data/` real)
    this._logPersistenceEnabled = !isRunningInTestMode();
    /** @type {string | null} */
    this._customLogFile = null;
    this._logMaxBytes = LOG_ROTATE_MAX_BYTES;
    /** @type {string[]} */
    this._pendingLogLines = [];
    /** @type {ReturnType<typeof setTimeout> | null} */
    this._logFlushTimer = null;
    this.watcher = null;
    this.watchedDirectory = null;
    this.debounceTimer = null;
    this.metricsTimer = null;

    // Contadores reales, no constantes de escaparate.
    this.requestsServed = 0;
    this.connectionCounter = () => 0;
    this.lastCpuSample = null;
    /** @type {{ at: number, data: any } | null} */
    this._metricsCache = null;
    /** @type {{ at: number, buffer: Buffer } | null} */
    this._podsSerializedCache = null;
    /** @type {any} */
    this._localRunner = null;

    // Se creaban perezosamente con `if (!this.x) this.x = new Map()` repartido
    // por varios métodos, así que había caminos que los tocaban sin inicializar.
    // El comprobador de tipos lo señaló en tres sitios.
    this.watchers = new Map();
    this.debounceTimers = new Map();
    this.contentHashes = new Map();

    // Ningún pod está aprovisionado todavía: no hay contenedores detrás de
    // estos objetos. Los campos medibles se rellenan en tiempo de ejecución;
    // los que no, quedan a null en lugar de mostrar un número inventado.
    // `provisioned` es la bandera que el panel debe mirar antes de dibujar
    // cualquier métrica.
    this.pods = {
      forge: {
        id: 'pod_forge',
        name: 'The Forge',
        role: 'development_hot_pod',
        provisioned: false,
        status: 'idle',
        health: 'unknown',
        port: 3001,
        latencyMs: null,
        cpuPercent: null,
        memoryMb: null,
        memoryLimitMb: null,
        uptimeSeconds: null,
        hotReloadsCount: 0,
        lastHotReloadMs: /** @type {number | null} */ (null),
        fileWatchersActive: 0,
        localProcesses: 0,
        localPorts: /** @type {number[]} */ ([]),
        environment: 'development',
        note: 'Sin contenedor aprovisionado. Refleja los procesos locales que gestiona el daemon.'
      },
      citadel: {
        id: 'pod_citadel',
        name: 'The Citadel',
        role: 'production_hardened_pod',
        provisioned: false,
        status: 'not_provisioned',
        health: 'unknown',
        port: 8080,
        latencyMs: null,
        cpuPercent: null,
        memoryMb: null,
        memoryLimitMb: null,
        uptimeSeconds: null,
        hotReloadsCount: 0,
        lastHotReloadMs: null,
        fileWatchersActive: 0,
        environment: 'production',
        note: 'Sin contenedor aprovisionado. El pod de producción es trabajo pendiente.'
      }
    };

    this.loadPersistedLogs();
    if (this.logs.length === 0) {
      this.initSampleLogs();
    }
    this.startMetricsCollection();
  }

  getLogFilePath() {
    return this._customLogFile || resolveDefaultLogFile();
  }

  /**
   * Configures rotated NDJSON log persistence (used by daemon & isolated tests).
   * @param {{ filePath?: string | null, enabled?: boolean, maxBytes?: number, reload?: boolean }} [opts]
   */
  configureLogPersistence(opts = {}) {
    if (opts.filePath !== undefined) this._customLogFile = opts.filePath || null;
    if (typeof opts.enabled === 'boolean') this._logPersistenceEnabled = opts.enabled;
    if (typeof opts.maxBytes === 'number' && opts.maxBytes >= 1024) this._logMaxBytes = opts.maxBytes;
    if (opts.reload) {
      this.logs = [];
      this.projectLogs.clear();
      this._pendingLogLines = [];
      this.loadPersistedLogs();
    }
  }

  /** Loads recent persisted NDJSON logs on boot so history survives daemon restarts. */
  loadPersistedLogs() {
    if (!this._logPersistenceEnabled) return 0;
    const file = this.getLogFilePath();
    if (!fs.existsSync(file)) return 0;
    try {
      const raw = fs.readFileSync(file, 'utf8');
      const lines = raw.split(/\r?\n/).filter(Boolean);
      const tail = lines.slice(-this.maxLogs);
      let loaded = 0;
      for (const line of tail) {
        try {
          const entry = JSON.parse(line);
          if (!entry || typeof entry.message !== 'string' || typeof entry.timestamp !== 'string') continue;
          this.logs.push(entry);
          if (entry.projectId && entry.projectId !== 'global') {
            let bucket = this.projectLogs.get(entry.projectId);
            if (!bucket) {
              bucket = [];
              this.projectLogs.set(entry.projectId, bucket);
            }
            bucket.push(entry);
            if (bucket.length > this.maxProjectLogs) {
              bucket.splice(0, bucket.length - this.maxProjectLogs);
            }
          }
          loaded++;
        } catch (e) {}
      }
      return loaded;
    } catch (e) {
      return 0;
    }
  }

  /** Flushes buffered log lines to the rotated NDJSON ring file (`logs.ndjson` / `.1`). */
  flushLogsToDisk() {
    if (this._logFlushTimer) {
      clearTimeout(this._logFlushTimer);
      this._logFlushTimer = null;
    }
    if (!this._logPersistenceEnabled || this._pendingLogLines.length === 0) return 0;
    const batch = this._pendingLogLines.splice(0, this._pendingLogLines.length);
    const file = this.getLogFilePath();
    try {
      const dir = path.dirname(file);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      try {
        const st = fs.statSync(file);
        if (st.size >= this._logMaxBytes) {
          const rotated = `${file}.1`;
          try { if (fs.existsSync(rotated)) fs.unlinkSync(rotated); } catch (e) {}
          fs.renameSync(file, rotated);
        }
      } catch (e) {}
      fs.appendFileSync(file, `${batch.join('\n')}\n`, { mode: 0o600 });
      return batch.length;
    } catch (e) {
      return 0;
    }
  }

  initSampleLogs() {
    // Estas líneas eran un decorado: anunciaban un servidor HTTP/2 en el 8080,
    // un certificado wildcard montado en el proxy, 184 descriptores vigilados y
    // un hot-reload compilado en 28 ms. Nada de eso ocurría, pero salía en el
    // visor de logs como si sí. Ahora el arranque cuenta lo que de verdad pasa
    // y nombra explícitamente lo que falta.
    const nodeVersion = process.version;
    const initialLogs = [
      { level: 'INFO', pod: 'edge', message: `[Culkibo] Daemon iniciado sobre Node ${nodeVersion} en ${process.platform}.` },
      { level: 'INFO', pod: 'edge', message: '[Culkibo] Plano de control listo: API REST, WebSocket (/ws, /ws/sync) y servidor MCP 2026-07-28.' },
      { level: 'INFO', pod: 'forge', message: '[Forge] Motor de sincronización en vivo (Commit Frames + Merkle + rollback <10 ms) listo en /ws/sync.' },
      { level: 'INFO', pod: 'citadel', message: '[Citadel] Despliegues de producción gestionados por deployManager (Docker BuildKit + Caddy zero-downtime).' },
      { level: 'INFO', pod: 'edge', message: '[Edge:Ingress] Plano de datos delegado en Caddy (Admin API síncrona + TLS automático).' }
    ];

    initialLogs.forEach(l => {
      this.addLog(l.level, l.pod, l.message, new Date(Date.now() - 1000 * (10 - this.logs.length)));
    });
  }

  addLog(level, pod, message, timestamp = new Date(), projectId = 'global', meta = null) {
    const parsedFields = (meta && typeof meta === 'object' && !Array.isArray(meta))
      ? meta
      : extractLogFields(message);
    const logEntry = {
      id: `log_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      timestamp: (timestamp instanceof Date ? timestamp : new Date(timestamp)).toISOString(),
      level: String(level || 'INFO').toUpperCase(),
      pod,
      projectId,
      message,
      ...(parsedFields ? { fields: parsedFields } : {})
    };

    // Almacenamos cronológicamente al final (O(1) amortized) y leemos en reverso.
    this.logs.push(logEntry);
    if (this.logs.length > this.maxLogs + 250) {
      this.logs.splice(0, this.logs.length - this.maxLogs);
    }

    if (projectId && projectId !== 'global') {
      let bucket = this.projectLogs.get(projectId);
      if (!bucket) {
        bucket = [];
        this.projectLogs.set(projectId, bucket);
        // Evitar crecimiento ilimitado de buckets si se crean/borran cientos de proyectos
        if (this.projectLogs.size > 120) {
          const oldestKey = this.projectLogs.keys().next().value;
          if (oldestKey !== undefined && oldestKey !== projectId) {
            this.projectLogs.delete(oldestKey);
          }
        }
      }
      bucket.push(logEntry);
      if (bucket.length > this.maxProjectLogs + 100) {
        bucket.splice(0, bucket.length - this.maxProjectLogs);
      }
    }

    if (this._logPersistenceEnabled) {
      this._pendingLogLines.push(JSON.stringify(logEntry));
      if (this._pendingLogLines.length >= 25) {
        this.flushLogsToDisk();
      } else if (!this._logFlushTimer) {
        this._logFlushTimer = setTimeout(() => {
          this.flushLogsToDisk();
        }, 1500);
        if (this._logFlushTimer.unref) this._logFlushTimer.unref();
      }
    }

    this.emit('log', logEntry);
    return logEntry;
  }

  /** Cuenta una petición servida. Lo llama el daemon por cada petición real. */
  recordRequest() {
    this.requestsServed++;
  }

  /**
   * El daemon inyecta aquí cómo contar los clientes WebSocket vivos, para no
   * crear una dependencia circular con server/index.js.
   */
  setConnectionCounter(fn) {
    if (typeof fn === 'function') this.connectionCounter = fn;
  }

  getPods() {
    // `totalRequestsServed: 1248920` y `activeConnections: 142` eran constantes
    // escritas a mano que el panel mostraba como telemetría. Ahora son
    // contadores de verdad, y empiezan en cero en cada arranque porque eso es
    // lo que son.
    return {
      pods: this.pods,
      trafficAllocation: this.trafficAllocation,
      totalRequestsServed: this.requestsServed,
      activeConnections: this.connectionCounter(),
      daemon: this.getDaemonMetrics(),
      localProcesses: this.getLocalProcessStats()
    };
  }

  /** Buffer JSON pre-serializado de `getPods()` con TTL de 250 ms para ráfagas. */
  getPodsSerialized() {
    const now = Date.now();
    if (this._podsSerializedCache && (now - this._podsSerializedCache.at) < 250) {
      return this._podsSerializedCache.buffer;
    }
    const buf = Buffer.from(JSON.stringify(this.getPods()), 'utf8');
    this._podsSerializedCache = { at: now, buffer: buf };
    return buf;
  }

  /**
   * Queries structured logs with ReDoS-safe regex, relative/ISO `since`/`until`,
   * multi-level, structured JSON/kv attribute filter (`attr`), and RBAC `projectIds` ACL.
   *
   * @param {{
   *   pod?: string | null,
   *   level?: string | string[] | null,
   *   limit?: number,
   *   search?: string,
   *   regex?: boolean | string,
   *   since?: string | number | null,
   *   until?: string | number | null,
   *   attr?: string | Record<string, any> | null,
   *   projectId?: string | null,
   *   projectIds?: string[] | null
   * }} [opts]
   */
  getLogs({
    pod = null,
    level = null,
    limit = 100,
    search = '',
    regex = false,
    since = null,
    until = null,
    attr = null,
    projectId = null,
    projectIds = null
  } = {}) {
    const cap = Math.max(1, Math.min(2000, Number(limit) || 100));
    const allowedProjects = Array.isArray(projectIds) ? new Set(projectIds) : null;
    if (projectId && allowedProjects && !allowedProjects.has(projectId)) {
      return [];
    }

    /** @type {Set<string> | null} */
    let levelSet = null;
    if (Array.isArray(level)) {
      const cleaned = level.map((lv) => String(lv || '').trim().toUpperCase()).filter((lv) => lv && lv !== 'ALL');
      if (cleaned.length > 0) levelSet = new Set(cleaned);
    } else if (typeof level === 'string' && level.trim() && level.trim().toLowerCase() !== 'all') {
      const cleaned = level.split(',').map((lv) => lv.trim().toUpperCase()).filter((lv) => lv && lv !== 'ALL');
      if (cleaned.length > 0) levelSet = new Set(cleaned);
    }

    const sinceMs = parseTimeBoundary(since);
    const untilMs = parseTimeBoundary(until);

    /** @type {RegExp | null} */
    let compiledRe = null;
    let plainQuery = '';
    const rawSearch = typeof regex === 'string' && regex.trim() ? regex.trim() : String(search || '').trim();
    const useRegex = Boolean(regex === true || (typeof regex === 'string' && regex.trim()));
    if (rawSearch) {
      if (useRegex) {
        compiledRe = compileSafeRegex(rawSearch, 'i');
      } else {
        plainQuery = rawSearch.toLowerCase();
      }
    }

    /** @type {Array<[string, string]>} */
    const attrPairs = [];
    if (typeof attr === 'string' && attr.trim()) {
      for (const tok of attr.trim().split(/\s+/)) {
        const cleanTok = tok.replace(/^@/, '');
        const sepIdx = cleanTok.search(/[:=]/);
        if (sepIdx > 0) {
          attrPairs.push([cleanTok.slice(0, sepIdx).trim().toLowerCase(), cleanTok.slice(sepIdx + 1).trim().toLowerCase()]);
        }
      }
    } else if (attr && typeof attr === 'object') {
      for (const [k, v] of Object.entries(attr)) {
        if (k && v !== undefined && v !== null) {
          attrPairs.push([String(k).toLowerCase(), String(v).toLowerCase()]);
        }
      }
    }

    const source = (projectId && projectId !== 'global' && this.projectLogs.has(projectId))
      ? /** @type {any[]} */ (this.projectLogs.get(projectId))
      : this.logs;

    /** @type {any[]} */
    const out = [];
    for (let i = source.length - 1; i >= 0 && out.length < cap; i--) {
      const l = source[i];
      if (!l) continue;
      if (projectId && l.projectId !== projectId) continue;
      if (allowedProjects && (!l.projectId || l.projectId === 'global' || !allowedProjects.has(l.projectId))) {
        continue;
      }
      if (pod && pod !== 'all' && l.pod !== pod) continue;
      if (levelSet && !levelSet.has(l.level)) continue;

      if (sinceMs !== null || untilMs !== null) {
        const tsMs = Date.parse(l.timestamp);
        if (!Number.isFinite(tsMs)) continue;
        if (sinceMs !== null && tsMs < sinceMs) continue;
        if (untilMs !== null && tsMs > untilMs) continue;
      }

      if (attrPairs.length > 0) {
        const fields = l.fields || extractLogFields(l.message);
        if (!fields) continue;
        let allMatch = true;
        for (const [ak, av] of attrPairs) {
          const entryKey = Object.keys(fields).find((fk) => fk.toLowerCase() === ak);
          if (!entryKey || String(fields[entryKey]).toLowerCase() !== av) {
            allMatch = false;
            break;
          }
        }
        if (!allMatch) continue;
      }

      if (compiledRe) {
        if (!compiledRe.test(stripAnsi(l.message))) continue;
      } else if (plainQuery) {
        if (!stripAnsi(l.message).toLowerCase().includes(plainQuery)) continue;
      }

      out.push(l);
    }
    return out;
  }

  /**
   * Exports filtered logs as `.log` (chronological plain text), `.ndjson`, or `.json`.
   * @param {Parameters<ContainerOrchestrator['getLogs']>[0] & { format?: 'log' | 'ndjson' | 'json' }} [opts]
   */
  exportLogs(opts = {}) {
    const format = ['log', 'ndjson', 'json'].includes(String(opts.format || 'log').toLowerCase())
      ? String(opts.format || 'log').toLowerCase()
      : 'log';
    const recentFirst = this.getLogs({ ...opts, limit: Math.min(2000, Number(opts.limit) || 2000) });
    const ordered = [...recentFirst].reverse();
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const scope = opts.projectId ? `-${String(opts.projectId).replace(/[^a-zA-Z0-9_-]/g, '')}` : '';

    if (format === 'ndjson') {
      return {
        format: 'ndjson',
        contentType: 'application/x-ndjson; charset=utf-8',
        filename: `culkibo-logs${scope}-${stamp}.ndjson`,
        count: ordered.length,
        content: ordered.map((l) => JSON.stringify(l)).join('\n')
      };
    }
    if (format === 'json') {
      return {
        format: 'json',
        contentType: 'application/json; charset=utf-8',
        filename: `culkibo-logs${scope}-${stamp}.json`,
        count: ordered.length,
        content: JSON.stringify({ exportedAt: new Date().toISOString(), count: ordered.length, logs: ordered }, null, 2)
      };
    }
    const text = ordered
      .map((l) => `[${l.timestamp}] [${l.level}] [${l.pod || 'system'}]${l.projectId && l.projectId !== 'global' ? ` [${l.projectId}]` : ''} ${stripAnsi(l.message)}`)
      .join('\n');
    return {
      format: 'log',
      contentType: 'text/plain; charset=utf-8',
      filename: `culkibo-logs${scope}-${stamp}.log`,
      count: ordered.length,
      content: text
    };
  }

  // Detección de un cambio de fichero. Todavía no lo transporta ni lo aplica.
  async triggerHotSync({ changedFile = 'src/app.ts', diffSize = '4 lines modified' } = {}) {
    const startTime = performance.now();
    this.pods.forge.status = 'hot_syncing';
    this.emit('pod_change', { pod: 'forge', status: 'hot_syncing' });

    this.addLog('HOT_SYNC', 'forge', `[Forge:HotSync] Delta detectado en ${changedFile} (${diffSize})`);

    // Aquí NO se aplica nada todavía: el transporte al proceso remoto y el
    // intercambio de módulo son la Fase 2 del diseño (ver
    // docs/superpowers/specs/2026-09-12-culkibo-forge-citadel-design.md).
    //
    // Antes había un `await setTimeout(8)` fabricado cuyo único efecto era
    // producir el «<35 ms» que aparecía en el package.json. Un número inventado
    // no es un número: eliminado. Lo que se mide ahora es el coste real de
    // detectar y clasificar el cambio, y `applied` dice la verdad sobre si algo
    // llegó a aplicarse.
    const durationMs = Math.round(performance.now() - startTime);
    this.pods.forge.status = 'running';
    this.pods.forge.hotReloadsCount += 1;
    this.pods.forge.lastHotReloadMs = durationMs;

    this.addLog('INFO', 'forge', `[Forge:HotSync] Cambio detectado y clasificado en ${durationMs}ms (sin aplicar: transporte pendiente).`);
    this.emit('pod_change', { pod: 'forge', ...this.pods.forge });

    return {
      success: true,
      syncDurationMs: durationMs,
      /** Hoy siempre false: se detecta el cambio, no se aplica. */
      applied: false,
      mode: 'detect_only',
      targetPod: 'forge',
      changedFile,
      reloadsTotal: this.pods.forge.hotReloadsCount
    };
  }

  /**
   * Switch Traffic Instantly between The Forge and The Citadel
   * @param {{ forgePercent?: number | string, citadelPercent?: number | string }} [opts]
   */
  async switchTraffic({ forgePercent, citadelPercent } = {}) {
    const startTime = performance.now();
    /** @type {number} */
    let forge;
    if (forgePercent !== undefined && forgePercent !== null && forgePercent !== '') {
      forge = Number(forgePercent);
    } else if (citadelPercent !== undefined && citadelPercent !== null && citadelPercent !== '') {
      forge = 100 - Number(citadelPercent);
    } else {
      throw new Error('Debes indicar forgePercent o citadelPercent entre 0 y 100');
    }
    if (!Number.isFinite(forge)) {
      throw new Error('El porcentaje de tráfico debe ser un número válido entre 0 y 100');
    }
    forge = Math.max(0, Math.min(100, Math.round(forge)));
    const citadel = 100 - forge;

    this.trafficAllocation = { forge, citadel };
    const durationMs = (performance.now() - startTime).toFixed(2);

    this.addLog('INFO', 'edge', `[Edge:Router] Traffic re-routed: ${forge}% to The Forge (Dev), ${citadel}% to The Citadel (Prod) in ${durationMs}ms.`);
    this.emit('traffic_change', this.trafficAllocation);

    return {
      success: true,
      trafficAllocation: this.trafficAllocation,
      switchDurationMs: parseFloat(durationMs)
    };
  }

  // Los despliegues reales a producción corren en `deployManager.deploy()`
  // (Docker + healthcheck + conmutación atómica de ruta en Caddy + drenaje).
  // Este método antiguo simulaba el despliegue con tres `setTimeout`; se
  // elimina la simulación para no falsear jamás un estado de producción.
  async deployRelease({ imageTag = 'v1.0.1', gitCommit = 'head', description = '' } = {}) {
    this.addLog(
      'WARN',
      'citadel',
      `[Citadel:Deploy] deployRelease() legado desactivado (no simula despliegues). Usa POST /api/projects/:id/deploy o MCP culkibo_deploy_production.`
    );
    return {
      success: false,
      simulated: false,
      delegatedTo: 'deployManager',
      requestedImageTag: imageTag,
      requestedGitCommit: gitCommit,
      description,
      message: 'Los despliegues reales se ejecutan vía deployManager (POST /api/projects/:id/deploy).'
    };
  }

  watchDirectory(dirPath, watchPaths = []) {
    if (!dirPath) throw new Error('Directory path is required');
    const targetDir = path.resolve(dirPath);
    if (!fs.existsSync(targetDir)) {
      throw new Error(`Directory does not exist: ${targetDir}`);
    }

    if (!this.watchers) this.watchers = new Map();
    
    if (this.watchers.has(targetDir)) {
      try { this.watchers.get(targetDir).close(); } catch(e) {}
      this.watchers.delete(targetDir);
    }
    this.watchedDirectory = targetDir;
    
    /** @type {string | string[]} */
    let pathsToWatch = targetDir;
    if (watchPaths && watchPaths.length > 0) {
      pathsToWatch = watchPaths.map(p => path.join(targetDir, p).replace(/\\/g, '/'));
    }

    this.addLog('INFO', 'forge', `[Forge:Watcher] Initializing Chokidar on ${Array.isArray(pathsToWatch) ? pathsToWatch.join(', ') : targetDir}`);

    // NO usar `awaitWriteFinish`. Su propia documentación advierte de que hace
    // el watcher "mucho menos reactivo": con stabilityThreshold 40 + el debounce
    // de 30 ms imponía un suelo de 70-80 ms ANTES de que la sincronización
    // pudiera siquiera empezar — más de la mitad del presupuesto total.
    // La escritura parcial se descarta comparando el hash del contenido, no
    // esperando a que el fichero se quede quieto.
    const watcher = getChokidar().watch(pathsToWatch, {
      ignored: /(^|[\/\\])\..|node_modules|dist|\.git|\.next|data[\\\/]certs/,
      persistent: false,
      ignoreInitial: true
    });
    this.watchers.set(targetDir, watcher);

    let filesCount = 0;
    watcher.on('add', () => {
      filesCount++;
      this.pods.forge.fileWatchersActive = filesCount;
    });
    watcher.on('unlink', () => {
      filesCount = Math.max(0, filesCount - 1);
      this.pods.forge.fileWatchersActive = filesCount;
    });

    // Chokidar emits 'error' (EPERM, ENOSPC, EBUSY on Windows) on the watcher
    // itself. An EventEmitter with no 'error' listener throws and kills the
    // daemon, so every watcher gets one.
    watcher.on('error', (/** @type {any} */ err) => {
      this.addLog('ERROR', 'forge', `[Forge:Watcher] Error observando ${targetDir}: ${err && err.message ? err.message : err}`);
    });

    // One debounce timer PER watched directory. A single shared timer let a
    // change in project A cancel the pending hot-sync of project B.
    if (!this.debounceTimers) this.debounceTimers = new Map();
    if (!this.contentHashes) this.contentHashes = new Map();

    const handleFileDelta = (filePath, action) => {
      // Editores y herramientas disparan varios eventos por un solo guardado, y
      // un agente de IA reescribe un fichero con el mismo contenido a menudo.
      // Comparar el hash descarta ambos casos sin costar latencia, que es lo
      // que hacía `awaitWriteFinish` a cambio de 40 ms por evento.
      if (action !== 'deleted' && !this.hasContentChanged(filePath)) return;

      const pending = this.debounceTimers.get(targetDir);
      if (pending) clearTimeout(pending);

      // 5 ms: suficiente para agrupar la ráfaga de eventos de un guardado,
      // despreciable frente al presupuesto total.
      const timer = setTimeout(async () => {
        this.debounceTimers.delete(targetDir);
        const relativePath = path.relative(targetDir, filePath);
        try {
          await this.triggerHotSync({
            changedFile: relativePath || filePath,
            diffSize: `${action} detected`
          });
        } catch (err) {
          this.addLog('ERROR', 'forge', `[Forge:HotSync] Fallo al sincronizar ${relativePath || filePath}: ${err.message}`);
        }
      }, 5);
      if (timer.unref) timer.unref();
      this.debounceTimers.set(targetDir, timer);
    };

    watcher.on('change', (fp) => handleFileDelta(fp, 'modified'));
    watcher.on('add', (fp) => handleFileDelta(fp, 'created'));
    watcher.on('unlink', (fp) => handleFileDelta(fp, 'deleted'));

    watcher.on('ready', () => {
      const watched = watcher.getWatched();
      let totalPaths = 0;
      for (const dir in watched) {
        totalPaths += watched[dir].length;
      }
      this.pods.forge.fileWatchersActive = Math.max(totalPaths, 1);
      this.addLog('SUCCESS', 'forge', `[Forge:Watcher] Active and watching ${this.pods.forge.fileWatchersActive} paths in ${targetDir}`);
      this.emit('pod_change', { pod: 'forge', fileWatchersActive: this.pods.forge.fileWatchersActive });
    });

    return {
      success: true,
      directory: targetDir,
      fileWatchersActive: this.pods.forge.fileWatchersActive
    };
  }

  /** @param {string | null} [dirPath] */
  async stopWatching(dirPath = null) {
    if (!this.watchers) this.watchers = new Map();
    if (!this.debounceTimers) this.debounceTimers = new Map();

    if (dirPath) {
      const targetDir = path.resolve(dirPath);
      const pending = this.debounceTimers.get(targetDir);
      if (pending) {
        clearTimeout(pending);
        this.debounceTimers.delete(targetDir);
      }
      if (this.watchers.has(targetDir)) {
        const w = this.watchers.get(targetDir);
        // Borrar ANTES del await para no eliminar un watcher nuevo registrado concurrentemente.
        this.watchers.delete(targetDir);
        try { await w.close(); } catch(e) {}
      }
    } else {
      for (const timer of this.debounceTimers.values()) clearTimeout(timer);
      this.debounceTimers.clear();
      const snapshot = Array.from(this.watchers.values());
      this.watchers.clear();
      this.watchedDirectory = null;
      const closePromises = [];
      for (const watcher of snapshot) {
        try { closePromises.push(watcher.close()); } catch(e) {}
      }
      await Promise.all(closePromises).catch(() => {});
    }
    
    if (this.watchers.size === 0) this.pods.forge.fileWatchersActive = 0;
    this.addLog('INFO', 'forge', `[Forge:Watcher] Stopped file watching`);
    this.emit('pod_change', { pod: 'forge', fileWatchersActive: this.pods.forge.fileWatchersActive });
    return { success: true };
  }

  /**
   * ¿Ha cambiado de verdad el contenido del fichero desde la última vez?
   *
   * Sustituye a `awaitWriteFinish`: en lugar de esperar 40 ms a que el fichero
   * "se estabilice", se lee y se compara el hash. Una escritura a medias produce
   * un hash distinto del final, así que el segundo evento —el bueno— pasa igual;
   * lo que se descarta son los eventos duplicados y las reescrituras idénticas.
   *
   * Ante la duda (fichero ilegible, demasiado grande) devuelve `true`: perder un
   * cambio real es mucho peor que procesar uno de más.
   */
  hasContentChanged(filePath) {
    if (!this.contentHashes) this.contentHashes = new Map();
    const MAX_HASHED_BYTES = 4 * 1024 * 1024;

    try {
      const stat = fs.statSync(filePath);
      if (!stat.isFile()) return true;

      // Para ficheros grandes, tamaño + mtimeMs es señal suficiente
      // y evita leer megabytes en el camino caliente.
      const signature = stat.size > MAX_HASHED_BYTES
        ? `size:${stat.size}:${stat.mtimeMs}`
        : crypto.createHash('sha1').update(fs.readFileSync(filePath)).digest('hex');

      if (this.contentHashes.get(filePath) === signature) return false;
      this.contentHashes.set(filePath, signature);

      // Cota superior para que un árbol enorme no haga crecer el mapa sin fin.
      if (this.contentHashes.size > 20000) this.contentHashes.clear();
      return true;
    } catch (e) {
      return true;
    }
  }

  getWatcherStatus() {
    if (!this.watchers) this.watchers = new Map();
    return {
      isWatching: this.watchers.size > 0,
      directory: this.watchedDirectory,
      fileWatchersActive: this.pods.forge.fileWatchersActive
    };
  }

  /**
   * Métricas reales del proceso del daemon (comparte caché de 250 ms con `metricsCollector`).
   */
  getDaemonMetrics() {
    const proc = metricsCollector.sampleProcess();
    return {
      cpuPercent: proc.cpuPercent,
      memoryMb: proc.memoryMb,
      heapUsedMb: proc.heapUsedMb,
      uptimeSeconds: proc.uptimeSeconds,
      measured: true
    };
  }

  /** Registra localRunner cuando se carga (evita arrastrarlo a memoria en reposo). */
  registerLocalRunner(runner) {
    if (runner) this._localRunner = runner;
  }

  /** Procesos que el runner local tiene realmente en marcha (sin require() en reposo). */
  getLocalProcessStats() {
    if (!this._localRunner || !this._localRunner.activeRunners) {
      return { count: 0, ports: [], types: {} };
    }
    try {
      const runners = Array.from(this._localRunner.activeRunners.values());
      if (runners.length === 0) return { count: 0, ports: [], types: {} };
      return {
        count: runners.length,
        ports: runners.map(r => r.port).filter(Boolean),
        types: runners.reduce((acc, r) => { acc[r.type] = (acc[r.type] || 0) + 1; return acc; }, {})
      };
    } catch (e) {
      return { count: 0, ports: [], types: {} };
    }
  }

  startMetricsCollection() {
    if (this.metricsTimer) clearInterval(this.metricsTimer);
    this.metricsTimer = setInterval(() => {
      // Cero CPU en reposo cuando no hay clientes WebSocket conectados.
      if (this.connectionCounter() === 0) return;

      const local = this.getLocalProcessStats();

      this.pods.forge.localProcesses = local.count;
      this.pods.forge.localPorts = local.ports;
      this.pods.forge.status = local.count > 0 ? 'running' : 'idle';

      this.emit('metrics', {
        forge: this.pods.forge,
        citadel: this.pods.citadel,
        daemon: this.getDaemonMetrics(),
        localProcesses: local,
        trafficAllocation: this.trafficAllocation
      });
    }, 3000);

    // CRITICAL: Unref the timer so it doesn't prevent clean test/process exit
    if (this.metricsTimer.unref) {
      this.metricsTimer.unref();
    }
  }

  async stop() {
    if (this.metricsTimer) {
      clearInterval(this.metricsTimer);
      this.metricsTimer = null;
    }
    this.flushLogsToDisk();
    await this.stopWatching();
  }
}

const orchestratorInstance = Object.assign(new ContainerOrchestrator(), {
  compileSafeRegex,
  extractLogFields,
  parseTimeBoundary,
  stripAnsi
});
module.exports = orchestratorInstance;
