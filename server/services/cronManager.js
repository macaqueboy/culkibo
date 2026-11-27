const { EventEmitter } = require('events');
const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { parseCron, nextCronRun } = require('./cronParser');
const { parseSafeCommandArgv, sanitizeWorkdir } = require('./safeCommand');
const { atomicWriteJsonSync } = require('./ssrfGuard');

function resolveDefaultDataDir() {
  return process.env.CULKIBO_DATA_DIR
    ? path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data')
    : path.resolve(__dirname, '..', '..', 'data');
}
const DATA_DIR = resolveDefaultDataDir();
const STORE_FILE = path.join(DATA_DIR, 'crons.json');
const STORE_BAK_FILE = `${STORE_FILE}.bak`;
const MAX_HISTORY_PER_JOB = 25;
const MAX_OUTPUT_BYTES = 8 * 1024;
const TICK_INTERVAL_MS = 30 * 1000;
const COLLISION_WINDOW_MS = 5 * 60 * 1000;

/** @type {any} */
let _alertEngine = null;
function getAlertEngine() {
  if (!_alertEngine) {
    try { _alertEngine = require('./alertEngine'); } catch (e) {}
  }
  return _alertEngine;
}

/** @type {any} */
let _databaseManager = null;
function getDatabaseManager() {
  if (!_databaseManager) {
    try { _databaseManager = require('./databaseManager'); } catch (e) {}
  }
  return _databaseManager;
}

/**
 * Comparación en tiempo constante para tokens de heartbeat (evita timing attacks).
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function timingSafeTokenEqual(a, b) {
  const ba = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  if (ba.length === 0 || ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/** @type {any} */
let _deployManager = null;
function getDeployManager() {
  if (!_deployManager) _deployManager = require('./deployManager');
  return _deployManager;
}

/** @type {any} */
let _projectManager = null;
function getProjectManager() {
  if (!_projectManager) _projectManager = require('./projectManager');
  return _projectManager;
}

/** @type {any} */
let _notificationService = null;
function getNotificationService() {
  if (!_notificationService) {
    try { _notificationService = require('./notificationService'); } catch (e) {}
  }
  return _notificationService;
}

function sanitizeHttpPath(raw) {
  const s = String(raw || '/').trim();
  if (!s.startsWith('/') || /[\r\n\0\s]/.test(s) || s.length > 300) {
    throw new Error('La ruta HTTP del cron debe empezar por "/" sin espacios ni caracteres de control');
  }
  return s;
}

function sanitizeHeaders(raw) {
  /** @type {Record<string, string>} */
  const out = {};
  if (!raw || typeof raw !== 'object') return out;
  for (const [k, v] of Object.entries(raw).slice(0, 16)) {
    const key = String(k).trim();
    const val = String(v == null ? '' : v).replace(/[\r\n\0]/g, '').trim();
    if (!key || !/^[A-Za-z0-9-]+$/.test(key)) continue;
    if (/^(host|content-length|transfer-encoding)$/i.test(key)) continue;
    out[key] = val.slice(0, 512);
  }
  return out;
}

function redactOutput(text, project) {
  // Redactar ANTES de truncar para evitar cortes a mitad de un secreto (Dokploy/Coolify)
  let out = String(text || '');
  /** @type {Set<string>} */
  const secrets = new Set();
  const envVars = (project && project.envVars) || {};
  for (const val of Object.values(envVars)) {
    const s = String(val || '');
    if (s.length >= 6) secrets.add(s);
  }
  try {
    const dm = getDeployManager();
    if (dm && typeof dm._secretValuesForProject === 'function' && project) {
      for (const s of dm._secretValuesForProject(project)) {
        if (s && s.length >= 6) secrets.add(s);
      }
    }
  } catch (e) {}
  for (const s of secrets) {
    if (out.includes(s)) out = out.split(s).join('[REDACTED]');
  }
  if (out.length > MAX_OUTPUT_BYTES) {
    const head = out.slice(0, Math.floor(MAX_OUTPUT_BYTES * 0.6));
    const tail = out.slice(-Math.floor(MAX_OUTPUT_BYTES * 0.35));
    out = `${head}\n... [salida truncada] ...\n${tail}`;
  }
  return out;
}

/** Lee el cuerpo de una respuesta HTTP acotado en bytes (evita OOM en cron HTTP). */
async function readBoundedText(res, maxBytes = 32 * 1024) {
  if (!res.body || typeof res.body.getReader !== 'function') {
    return (await res.text().catch(() => '')).slice(0, maxBytes);
  }
  const reader = res.body.getReader();
  /** @type {Uint8Array[]} */
  const chunks = [];
  let total = 0;
  try {
    while (total < maxBytes) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) {
        const remaining = maxBytes - total;
        chunks.push(value.byteLength > remaining ? value.subarray(0, remaining) : value);
        total += Math.min(value.byteLength, remaining);
      }
    }
    if (total >= maxBytes) {
      try { await reader.cancel(); } catch (e) {}
    }
  } catch (e) {}
  return Buffer.concat(chunks.map((c) => Buffer.from(c.buffer, c.byteOffset, c.byteLength))).toString('utf8');
}

class CronManager extends EventEmitter {
  /**
   * @param {string} [storeFile]
   * @param {{ heartbeatsFile?: string | null }} [opts]
   */
  constructor(storeFile = STORE_FILE, opts = {}) {
    super();
    this._explicitStoreFile = storeFile !== STORE_FILE ? path.resolve(storeFile) : null;
    this.storeFile = storeFile;
    this.storeBakFile = `${storeFile}.bak`;
    this._explicitHeartbeatsFile = opts && opts.heartbeatsFile ? path.resolve(opts.heartbeatsFile) : null;
    this.heartbeatsFile = this._explicitHeartbeatsFile || path.join(path.dirname(storeFile), 'heartbeats.json');
    /** @type {Array<any>} */
    this.jobs = [];
    /** @type {Array<any>} */
    this.heartbeats = [];
    /** @type {Set<string>} */
    this.runningJobs = new Set();
    /** @type {ReturnType<typeof setInterval> | null} */
    this._timer = null;
    this._loaded = false;
    this._heartbeatsLoaded = false;
    this._heartbeatsLoadedPath = null;
  }

  _resolveHeartbeatsFile() {
    if (this._explicitHeartbeatsFile) return this._explicitHeartbeatsFile;
    if (this._explicitStoreFile) return path.join(path.dirname(this._explicitStoreFile), 'heartbeats.json');
    return path.join(resolveDefaultDataDir(), 'heartbeats.json');
  }

  _ensureHeartbeatsLoaded() {
    const target = this._resolveHeartbeatsFile();
    if (this._heartbeatsLoaded && this._heartbeatsLoadedPath === target) return;
    this._heartbeatsLoaded = true;
    this._heartbeatsLoadedPath = target;
    this.heartbeatsFile = target;
    try {
      if (fs.existsSync(target)) {
        const parsed = JSON.parse(fs.readFileSync(target, 'utf8'));
        if (Array.isArray(parsed)) {
          this.heartbeats = parsed;
          return;
        }
        if (parsed && Array.isArray(parsed.heartbeats)) {
          this.heartbeats = parsed.heartbeats;
          return;
        }
      }
    } catch (e) {
      console.warn('[CronManager] Error leyendo heartbeats.json:', e.message);
    }
    this.heartbeats = [];
  }

  _saveHeartbeats() {
    this._ensureHeartbeatsLoaded();
    const target = this._resolveHeartbeatsFile();
    try {
      atomicWriteJsonSync(target, { version: 1, heartbeats: this.heartbeats }, 0o600);
    } catch (e) {
      console.error('[CronManager] No se pudo guardar heartbeats.json:', e.message);
    }
  }

  _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;
    for (const candidate of [this.storeFile, this.storeBakFile]) {
      try {
        if (!fs.existsSync(candidate)) continue;
        const parsed = JSON.parse(fs.readFileSync(candidate, 'utf8'));
        if (Array.isArray(parsed)) {
          this.jobs = parsed;
          return;
        }
        if (parsed && Array.isArray(parsed.jobs)) {
          this.jobs = parsed.jobs;
          return;
        }
      } catch (e) {
        console.warn(`[CronManager] Error leyendo ${path.basename(candidate)}:`, e.message);
      }
    }
    this.jobs = [];
  }

  save() {
    this._ensureLoaded();
    try {
      if (fs.existsSync(this.storeFile)) {
        try { fs.copyFileSync(this.storeFile, this.storeBakFile); } catch (e) {}
      }
      atomicWriteJsonSync(this.storeFile, { version: 1, jobs: this.jobs }, 0o600);
    } catch (e) {
      console.error('[CronManager] No se pudo guardar crons.json:', e.message);
    }
  }

  list(projectId = null) {
    this._ensureLoaded();
    const list = projectId ? this.jobs.filter((j) => j.projectId === projectId) : this.jobs;
    return list.map((j) => ({
      ...j,
      running: this.runningJobs.has(j.id),
      historyCount: (j.history || []).length
    }));
  }

  getById(jobId) {
    this._ensureLoaded();
    return this.jobs.find((j) => j.id === jobId) || null;
  }

  /**
   * Crea una nueva tarea programada para un proyecto.
   */
  create(projectId, data = {}) {
    this._ensureLoaded();
    if (!projectId || typeof projectId !== 'string') throw new Error('projectId obligatorio');
    const name = String(data.name || '').trim().slice(0, 80);
    if (!name) throw new Error('El nombre de la tarea cron es obligatorio');

    const scheduleRaw = String(data.schedule || '').trim();
    const parsedCron = parseCron(scheduleRaw);
    const mode = data.mode === 'http' ? 'http' : 'exec';

    /** @type {string} */
    let command = '';
    /** @type {string | null} */
    let workdir = null;
    /** @type {string} */
    let httpPath = '/';
    /** @type {'GET' | 'POST'} */
    let httpMethod = 'POST';
    /** @type {Record<string, string>} */
    let httpHeaders = {};

    if (mode === 'exec') {
      const argv = parseSafeCommandArgv(data.command);
      command = Array.isArray(data.command) ? argv.join(' ') : String(data.command).trim();
      workdir = sanitizeWorkdir(data.workdir);
    } else {
      httpPath = sanitizeHttpPath(data.httpPath || '/');
      httpMethod = String(data.httpMethod || 'POST').toUpperCase() === 'GET' ? 'GET' : 'POST';
      httpHeaders = sanitizeHeaders(data.httpHeaders);
    }

    const timeoutMs = Math.min(600000, Math.max(1000, Number(data.timeoutMs) || 60000));
    const enabled = data.enabled !== undefined ? Boolean(data.enabled) : true;
    const nextRunAt = enabled ? nextCronRun(parsedCron.expression).toISOString() : null;

    const job = {
      id: `cron_${Date.now().toString(36)}_${crypto.randomBytes(3).toString('hex')}`,
      projectId,
      name,
      schedule: parsedCron.expression,
      enabled,
      mode,
      command,
      workdir,
      httpPath,
      httpMethod,
      httpHeaders,
      timeoutMs,
      nextRunAt,
      lastRunAt: null,
      lastStatus: null,
      lastDurationMs: null,
      consecutiveFailures: 0,
      history: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    this.jobs.push(job);
    this.save();
    if (enabled) this.startScheduler();
    return { ...job, running: false };
  }

  update(jobId, patch = {}) {
    this._ensureLoaded();
    const job = this.getById(jobId);
    if (!job) throw new Error('Tarea cron no encontrada');

    if (patch.name !== undefined) {
      const name = String(patch.name || '').trim().slice(0, 80);
      if (!name) throw new Error('El nombre no puede estar vacío');
      job.name = name;
    }
    if (patch.schedule !== undefined) {
      const parsed = parseCron(String(patch.schedule || '').trim());
      job.schedule = parsed.expression;
    }
    if (patch.mode !== undefined) {
      job.mode = patch.mode === 'http' ? 'http' : 'exec';
    }
    if (job.mode === 'exec') {
      if (patch.command !== undefined) {
        const argv = parseSafeCommandArgv(patch.command);
        job.command = Array.isArray(patch.command) ? argv.join(' ') : String(patch.command).trim();
      } else if (!job.command) {
        throw new Error('El comando es obligatorio en modo exec');
      }
      if (patch.workdir !== undefined) {
        job.workdir = sanitizeWorkdir(patch.workdir);
      }
    } else {
      if (patch.httpPath !== undefined) job.httpPath = sanitizeHttpPath(patch.httpPath);
      if (patch.httpMethod !== undefined) {
        job.httpMethod = String(patch.httpMethod).toUpperCase() === 'GET' ? 'GET' : 'POST';
      }
      if (patch.httpHeaders !== undefined) job.httpHeaders = sanitizeHeaders(patch.httpHeaders);
    }
    if (patch.timeoutMs !== undefined) {
      job.timeoutMs = Math.min(600000, Math.max(1000, Number(patch.timeoutMs) || 60000));
    }
    if (patch.enabled !== undefined) {
      job.enabled = Boolean(patch.enabled);
    }

    job.nextRunAt = job.enabled ? nextCronRun(job.schedule).toISOString() : null;
    job.updatedAt = new Date().toISOString();
    this.save();
    if (job.enabled) this.startScheduler();
    return { ...job, running: this.runningJobs.has(job.id) };
  }

  remove(jobId) {
    this._ensureLoaded();
    const idx = this.jobs.findIndex((j) => j.id === jobId);
    if (idx === -1) return false;
    this.jobs.splice(idx, 1);
    this.save();
    return true;
  }

  forgetProject(projectId) {
    this._ensureLoaded();
    const before = this.jobs.length;
    this.jobs = this.jobs.filter((j) => j.projectId !== projectId);
    if (this.jobs.length !== before) this.save();
    return before - this.jobs.length;
  }

  getRuns(jobId) {
    const job = this.getById(jobId);
    if (!job) throw new Error('Tarea cron no encontrada');
    return job.history || [];
  }

  /**
   * Ejecuta una tarea cron ahora mismo (manual o desde el planificador).
   * @param {string} jobId
   * @param {{ trigger?: 'manual' | 'schedule' }} [opts]
   */
  async runNow(jobId, { trigger = 'manual' } = {}) {
    this._ensureLoaded();
    const job = this.getById(jobId);
    if (!job) throw new Error('Tarea cron no encontrada');
    if (this.runningJobs.has(job.id)) {
      const err = new Error(`La tarea "${job.name}" ya está en ejecución`);
      /** @type {any} */ (err).status = 409;
      throw err;
    }

    this.runningJobs.add(job.id);
    const started = Date.now();
    /** @type {any} */
    const runRecord = {
      id: `run_${Date.now().toString(36)}_${crypto.randomBytes(2).toString('hex')}`,
      trigger,
      startedAt: new Date().toISOString(),
      finishedAt: null,
      durationMs: 0,
      status: 'running',
      exitCode: null,
      httpStatus: null,
      output: '',
      error: null
    };

    try {
      const pm = getProjectManager();
      const project = pm && typeof pm.getById === 'function' ? pm.getById(job.projectId) : null;
      const dm = getDeployManager();
      const state = dm.getState(job.projectId);
      const current = state && state.current;

      if (!current || current.status === 'detenido' || current.status === 'stopped') {
        runRecord.status = 'skipped';
        runRecord.error = 'El proyecto no tiene un contenedor de producción activo';
        return this._finalizeRun(job, runRecord, started, project);
      }

      if (job.mode === 'http') {
        const isContainerized = fs.existsSync('/.dockerenv');
        const targetHost = isContainerized && current.containerName
          ? `${current.containerName}:${current.containerPort || 3000}`
          : `127.0.0.1:${current.hostPort}`;
        const url = `http://${targetHost}${job.httpPath}`;
        const res = await fetch(url, {
          method: job.httpMethod || 'POST',
          redirect: 'manual',
          headers: {
            'User-Agent': 'Culkibo-Cron/1.0',
            'X-Culkibo-Cron-Id': job.id,
            ...(job.httpHeaders || {})
          },
          signal: AbortSignal.timeout(job.timeoutMs)
        });
        const text = await readBoundedText(res, 32 * 1024);
        runRecord.httpStatus = res.status;
        runRecord.output = redactOutput(text, project);
        if (res.status >= 200 && res.status < 400) {
          runRecord.status = 'ok';
        } else {
          runRecord.status = 'failed';
          runRecord.error = `Respuesta HTTP ${res.status}`;
        }
      } else {
        const argv = parseSafeCommandArgv(job.command);
        const dockerArgs = ['exec'];
        if (job.workdir) dockerArgs.push('-w', job.workdir);
        dockerArgs.push(current.containerName, ...argv);

        const execRes = await this._spawnExec(dockerArgs, job.timeoutMs);
        runRecord.exitCode = execRes.code;
        const combined = [execRes.stdout, execRes.stderr].filter(Boolean).join('\n').trim();
        runRecord.output = redactOutput(combined, project);
        if (execRes.code === 0) {
          runRecord.status = 'ok';
        } else {
          runRecord.status = 'failed';
          runRecord.error = execRes.timedOut
            ? `Tiempo de espera agotado (${Math.round(job.timeoutMs / 1000)} s)`
            : `Código de salida ${execRes.code}`;
        }
      }

      return this._finalizeRun(job, runRecord, started, project);
    } catch (err) {
      runRecord.status = 'failed';
      runRecord.error = err.message || 'Error ejecutando tarea cron';
      const pm = getProjectManager();
      const project = pm && typeof pm.getById === 'function' ? pm.getById(job.projectId) : null;
      return this._finalizeRun(job, runRecord, started, project);
    } finally {
      this.runningJobs.delete(job.id);
    }
  }

  _spawnExec(args, timeoutMs) {
    return new Promise((resolve) => {
      let child;
      try {
        child = spawn('docker', args, { shell: false, windowsHide: true });
      } catch (err) {
        return resolve({ code: -1, stdout: '', stderr: err.message, timedOut: false });
      }
      let out = '';
      let errText = '';
      let timedOut = false;
      const cap = MAX_OUTPUT_BYTES * 2;
      child.stdout.on('data', (d) => { if (out.length < cap) out += d.toString(); });
      child.stderr.on('data', (d) => { if (errText.length < cap) errText += d.toString(); });

      const timer = setTimeout(() => {
        timedOut = true;
        try { child.kill('SIGTERM'); } catch (e) {}
        setTimeout(() => { try { child.kill('SIGKILL'); } catch (e) {} }, 3000).unref?.();
      }, timeoutMs);
      if (timer.unref) timer.unref();

      child.on('error', (err) => {
        clearTimeout(timer);
        resolve({ code: -1, stdout: out, stderr: err.message, timedOut: false });
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        resolve({ code: timedOut ? -2 : (code ?? -1), stdout: out, stderr: errText, timedOut });
      });
    });
  }

  _finalizeRun(job, runRecord, startedMs, project) {
    runRecord.finishedAt = new Date().toISOString();
    runRecord.durationMs = Date.now() - startedMs;

    job.lastRunAt = runRecord.finishedAt;
    job.lastStatus = runRecord.status;
    job.lastDurationMs = runRecord.durationMs;

    const prevFailures = job.consecutiveFailures || 0;
    if (runRecord.status === 'failed') {
      job.consecutiveFailures = prevFailures + 1;
    } else if (runRecord.status === 'ok') {
      job.consecutiveFailures = 0;
    }

    job.history = Array.isArray(job.history) ? job.history : [];
    job.history.unshift(runRecord);
    if (job.history.length > MAX_HISTORY_PER_JOB) job.history.length = MAX_HISTORY_PER_JOB;
    job.updatedAt = runRecord.finishedAt;
    this.save();

    this.emit('cron_run', {
      projectId: job.projectId,
      jobId: job.id,
      jobName: job.name,
      run: runRecord
    });

    const ns = getNotificationService();
    if (ns && typeof ns.notify === 'function') {
      if (runRecord.status === 'failed' && (job.consecutiveFailures === 1 || job.consecutiveFailures % 5 === 0)) {
        ns.notify({
          event: 'cron_failed',
          level: 'error',
          title: `Cron fallido: ${job.name}`,
          message: `${(project && project.name) || job.projectId}: ${runRecord.error || 'Fallo en ejecución'}${job.consecutiveFailures > 1 ? ` (${job.consecutiveFailures} fallos seguidos)` : ''}`,
          projectId: job.projectId,
          projectName: (project && project.name) || job.projectId
        }).catch(() => {});
      } else if (runRecord.status === 'ok' && prevFailures > 0) {
        ns.notify({
          event: 'cron_failed',
          level: 'success',
          title: `Cron recuperado: ${job.name}`,
          message: `${(project && project.name) || job.projectId}: la tarea volvió a ejecutarse correctamente tras ${prevFailures} fallo(s).`,
          projectId: job.projectId,
          projectName: (project && project.name) || job.projectId
        }).catch(() => {});
      }
    }

    return runRecord;
  }

  tick() {
    this._ensureLoaded();
    const now = Date.now();
    for (const job of this.jobs) {
      if (!job.enabled) continue;
      if (this.runningJobs.has(job.id)) continue;
      const dueAt = job.nextRunAt ? Date.parse(job.nextRunAt) : 0;
      if (!dueAt || Number.isNaN(dueAt)) {
        try {
          job.nextRunAt = nextCronRun(job.schedule).toISOString();
          this.save();
        } catch (e) {
          job.enabled = false;
          this.save();
        }
        continue;
      }
      if (dueAt <= now) {
        try {
          job.nextRunAt = nextCronRun(job.schedule, new Date(now)).toISOString();
          this.save();
        } catch (e) {
          job.enabled = false;
          this.save();
          continue;
        }
        this.runNow(job.id, { trigger: 'schedule' }).catch(() => {});
      }
    }
    try {
      this.checkMissedHeartbeats(now);
    } catch (e) {}
  }

  // =========================================================================
  // 24h Visual Collision Heatmap & Dead-Man's-Switch Heartbeats (Cycle #7)
  // =========================================================================

  /**
   * Proyecta las próximas `hours` (1..168, por defecto 24) de ejecuciones programadas
   * combinando crons de proyectos y horarios de backup de bases de datos, agrupando
   * en franjas horarias (`slots[]`) y detectando colisiones de I/O (`collisionWarnings[]`
   * cuando >= 2 tareas coinciden en la misma ventana de 5 minutos).
   *
   * @param {{ hours?: number, projectIds?: string[] | Set<string> | null, nowMs?: number, includeDatabases?: boolean, databases?: any[] | null }} [opts]
   */
  getTimeline(opts = {}) {
    this._ensureLoaded();
    const hours = Math.max(1, Math.min(168, Math.round(Number(opts.hours) || 24)));
    const startMs = opts.nowMs != null && Number.isFinite(Number(opts.nowMs)) ? Number(opts.nowMs) : Date.now();
    const endMs = startMs + hours * 3600 * 1000;
    const allowedSet = opts.projectIds
      ? (opts.projectIds instanceof Set ? opts.projectIds : new Set(opts.projectIds))
      : null;

    /** @type {Array<{ id: string, kind: 'cron' | 'db_backup', name: string, projectId: string | null, schedule: string, heavyIo: boolean }>} */
    const sources = [];
    for (const job of this.jobs) {
      if (!job || !job.enabled || !job.schedule) continue;
      if (allowedSet && !allowedSet.has(job.projectId)) continue;
      sources.push({
        id: job.id,
        kind: 'cron',
        name: job.name || job.id,
        projectId: job.projectId || null,
        schedule: job.schedule,
        heavyIo: job.mode === 'exec'
      });
    }

    if (opts.includeDatabases !== false) {
      /** @type {any[]} */
      let dbs = [];
      if (Array.isArray(opts.databases)) {
        dbs = opts.databases;
      } else {
        try {
          const dbm = getDatabaseManager();
          if (dbm && typeof dbm.list === 'function') dbs = dbm.list();
        } catch (e) {}
      }
      for (const db of dbs) {
        if (!db || !db.schedule || !db.schedule.enabled || !db.schedule.cron) continue;
        if (allowedSet && db.projectId && !allowedSet.has(db.projectId)) continue;
        if (allowedSet && !db.projectId) continue;
        sources.push({
          id: `db_backup_${db.id}`,
          kind: 'db_backup',
          name: `Backup ${db.name || db.id}`,
          projectId: db.projectId || null,
          schedule: db.schedule.cron,
          heavyIo: true
        });
      }
    }

    /** @type {Array<{ hourIndex: number, startAt: string, endAt: string, count: number, runs: any[] }>} */
    const slots = [];
    for (let h = 0; h < hours; h++) {
      const sMs = startMs + h * 3600 * 1000;
      slots.push({
        hourIndex: h,
        startAt: new Date(sMs).toISOString(),
        endAt: new Date(sMs + 3600 * 1000).toISOString(),
        count: 0,
        runs: []
      });
    }

    /** @type {Array<{ id: string, kind: string, name: string, projectId: string | null, schedule: string, runAt: string, runMs: number, heavyIo: boolean }>} */
    const allRuns = [];
    const MAX_OCCURRENCES_PER_JOB = 250;

    for (const src of sources) {
      let cursor = new Date(startMs - 1000);
      let occ = 0;
      while (occ < MAX_OCCURRENCES_PER_JOB) {
        let nextDate;
        try {
          nextDate = nextCronRun(src.schedule, cursor);
        } catch (e) {
          break;
        }
        const runMs = nextDate.getTime();
        if (!Number.isFinite(runMs) || runMs > endMs) break;
        if (runMs >= startMs) {
          const hourIdx = Math.min(hours - 1, Math.floor((runMs - startMs) / (3600 * 1000)));
          const runObj = {
            id: src.id,
            kind: src.kind,
            name: src.name,
            projectId: src.projectId,
            schedule: src.schedule,
            runAt: nextDate.toISOString(),
            runMs,
            heavyIo: src.heavyIo
          };
          slots[hourIdx].runs.push({
            id: runObj.id,
            kind: runObj.kind,
            name: runObj.name,
            projectId: runObj.projectId,
            schedule: runObj.schedule,
            runAt: runObj.runAt,
            heavyIo: runObj.heavyIo
          });
          slots[hourIdx].count++;
          allRuns.push(runObj);
        }
        cursor = new Date(runMs + 60 * 1000);
        occ++;
      }
    }

    allRuns.sort((a, b) => a.runMs - b.runMs);

    /** @type {Map<number, typeof allRuns>} */
    const buckets = new Map();
    for (const r of allRuns) {
      const bucketId = Math.floor(r.runMs / COLLISION_WINDOW_MS);
      let arr = buckets.get(bucketId);
      if (!arr) {
        arr = [];
        buckets.set(bucketId, arr);
      }
      arr.push(r);
    }

    /** @type {Array<any>} */
    const collisionWarnings = [];
    for (const [bucketId, runsInWin] of buckets.entries()) {
      const uniqueIds = new Set(runsInWin.map((r) => r.id));
      if (uniqueIds.size < 2) continue;
      const winStartMs = bucketId * COLLISION_WINDOW_MS;
      const winEndMs = winStartMs + COLLISION_WINDOW_MS;
      const heavyCount = runsInWin.filter((r) => r.heavyIo).length;
      collisionWarnings.push({
        windowStart: new Date(winStartMs).toISOString(),
        windowEnd: new Date(winEndMs).toISOString(),
        count: uniqueIds.size,
        heavyIoCount: heavyCount,
        severity: uniqueIds.size >= 3 || heavyCount >= 2 ? 'high' : 'medium',
        jobs: runsInWin.map((r) => ({
          id: r.id,
          kind: r.kind,
          name: r.name,
          projectId: r.projectId,
          runAt: r.runAt
        })),
        suggestion: 'Stagger overlapping cron or backup schedules by 10–15 minutes to prevent concurrent CPU/disk IO spikes.'
      });
      if (collisionWarnings.length >= 50) break;
    }

    return {
      hours,
      generatedAt: new Date(startMs).toISOString(),
      jobCount: sources.length,
      totalScheduledRuns: allRuns.length,
      slots,
      collisionWarnings
    };
  }

  /**
   * Crea un monitor Dead-Man's-Switch (estilo Healthchecks.io) con token aleatorio de 24 bytes hex.
   * @param {{ name: string, projectId?: string | null, periodSec?: number, graceSec?: number }} opts
   */
  createHeartbeat(opts) {
    this._ensureHeartbeatsLoaded();
    const name = String((opts && opts.name) || '').trim().slice(0, 80);
    if (!name) {
      const err = new Error('El nombre del heartbeat es obligatorio');
      /** @type {any} */ (err).status = 400;
      throw err;
    }
    const projectId = opts && opts.projectId ? String(opts.projectId).trim().slice(0, 80) : null;
    const periodSec = Math.max(1, Math.min(2592000, Math.round(Number(opts && opts.periodSec) || 3600)));
    const graceRaw = opts && opts.graceSec !== undefined ? Number(opts.graceSec) : 300;
    const graceSec = Number.isFinite(graceRaw) ? Math.max(0, Math.min(86400, Math.round(graceRaw))) : 300;
    const token = crypto.randomBytes(24).toString('hex');
    const nowIso = new Date().toISOString();

    const hb = {
      id: `hb_${Date.now().toString(36)}_${crypto.randomBytes(3).toString('hex')}`,
      name,
      projectId,
      token,
      pingUrl: `/api/heartbeat/${token}`,
      periodSec,
      graceSec,
      status: 'new',
      startedAt: null,
      lastPingAt: null,
      lastDurationMs: null,
      lastMessage: '',
      alertActive: false,
      missedAt: null,
      resolvedAt: null,
      createdAt: nowIso,
      updatedAt: nowIso
    };

    this.heartbeats.push(hb);
    this._saveHeartbeats();
    return { ...hb };
  }

  /**
   * Lista monitores Dead-Man's-Switch filtrados opcionalmente por `projectIds`.
   * @param {{ projectIds?: string[] | Set<string> | null }} [opts]
   */
  listHeartbeats(opts = {}) {
    this._ensureHeartbeatsLoaded();
    const allowedSet = opts && opts.projectIds
      ? (opts.projectIds instanceof Set ? opts.projectIds : new Set(opts.projectIds))
      : null;
    return this.heartbeats
      .filter((hb) => !allowedSet || (hb.projectId && allowedSet.has(hb.projectId)))
      .map((hb) => ({ ...hb, pingUrl: `/api/heartbeat/${hb.token}` }));
  }

  /** @param {string} id */
  getHeartbeatById(id) {
    this._ensureHeartbeatsLoaded();
    return this.heartbeats.find((hb) => hb.id === id) || null;
  }

  /** @param {string} id */
  deleteHeartbeat(id) {
    this._ensureHeartbeatsLoaded();
    const idx = this.heartbeats.findIndex((hb) => hb.id === id);
    if (idx === -1) return { deleted: false, id };
    this.heartbeats.splice(idx, 1);
    this._saveHeartbeats();
    return { deleted: true, id };
  }

  /**
   * Registra un check-in (`start`, `ok`, `fail`) buscando el token en tiempo constante (`timingSafeEqual`).
   * @param {string} token
   * @param {{ state?: 'start' | 'ok' | 'fail' | string, message?: string, nowMs?: number }} [opts]
   */
  recordPing(token, opts = {}) {
    this._ensureHeartbeatsLoaded();
    const cleanToken = String(token || '').trim();
    if (!cleanToken) {
      return { ok: false, found: false, status: 404, error: 'Token de heartbeat inválido' };
    }

    // Búsqueda en tiempo constante recorriendo todos los heartbeats sin cortar en el primer fallo
    /** @type {any} */
    let matched = null;
    for (const hb of this.heartbeats) {
      if (timingSafeTokenEqual(hb.token, cleanToken)) {
        matched = hb;
      }
    }
    if (!matched) {
      return { ok: false, found: false, status: 404, error: 'Heartbeat no encontrado' };
    }

    const rawState = String((opts && opts.state) || 'ok').trim().toLowerCase();
    if (rawState !== 'ok' && rawState !== 'start' && rawState !== 'fail') {
      return { ok: false, found: true, status: 400, error: `Estado de heartbeat inválido: "${rawState}" (usa start, ok o fail)` };
    }

    const nowMs = opts && opts.nowMs != null && Number.isFinite(Number(opts.nowMs)) ? Number(opts.nowMs) : Date.now();
    const nowIso = new Date(nowMs).toISOString();
    const message = String((opts && opts.message) || '').replace(/[\r\n\0]+/g, ' ').trim().slice(0, 300);
    let autoResolved = false;

    if (rawState === 'start') {
      matched.startedAt = nowMs;
      matched.status = 'running';
      matched.lastMessage = message;
      matched.updatedAt = nowIso;
    } else if (rawState === 'ok') {
      if (typeof matched.startedAt === 'number' && Number.isFinite(matched.startedAt)) {
        matched.lastDurationMs = Math.max(0, nowMs - matched.startedAt);
        matched.startedAt = null;
      }
      matched.lastPingAt = nowMs;
      matched.status = 'up';
      matched.lastMessage = message;
      matched.updatedAt = nowIso;
      if (matched.alertActive) {
        matched.alertActive = false;
        matched.resolvedAt = nowIso;
        autoResolved = true;
        this.emit('heartbeat_recovered', {
          heartbeatId: matched.id,
          name: matched.name,
          projectId: matched.projectId,
          resolvedAt: nowIso
        });
      }
    } else {
      matched.lastPingAt = nowMs;
      matched.startedAt = null;
      matched.status = 'down';
      matched.lastMessage = message;
      matched.alertActive = true;
      matched.updatedAt = nowIso;
      const failIncident = {
        type: 'heartbeat_fail',
        heartbeatId: matched.id,
        name: matched.name,
        projectId: matched.projectId,
        message: message || `Heartbeat "${matched.name}" reported failure`,
        at: nowIso
      };
      this.emit('heartbeat_failed', failIncident);
      try {
        const ae = getAlertEngine();
        if (ae && typeof ae.emit === 'function') ae.emit('heartbeat_alert', failIncident);
      } catch (e) {}
    }

    this._saveHeartbeats();
    return {
      ok: true,
      found: true,
      status: 200,
      state: rawState,
      autoResolved,
      heartbeat: { ...matched, pingUrl: `/api/heartbeat/${matched.token}` }
    };
  }

  /**
   * Detecta heartbeats que superaron `lastPingAt + (periodSec + graceSec) * 1000`,
   * los marca como `missed` y dispara una alerta deduplicada una sola vez hasta recuperación.
   *
   * @param {number} [nowMs]
   * @param {{ onAlert?: (incident: any) => void }} [opts]
   */
  checkMissedHeartbeats(nowMs = Date.now(), opts = {}) {
    this._ensureHeartbeatsLoaded();
    const checkMs = Number.isFinite(Number(nowMs)) ? Number(nowMs) : Date.now();
    /** @type {Array<any>} */
    const missed = [];
    let dirty = false;

    for (const hb of this.heartbeats) {
      if (hb.lastPingAt == null) continue;
      const deadlineMs = Number(hb.lastPingAt) + (Number(hb.periodSec) + Number(hb.graceSec)) * 1000;
      if (checkMs > deadlineMs) {
        const wasAlertActive = Boolean(hb.alertActive);
        if (hb.status !== 'missed') {
          hb.status = 'missed';
          hb.missedAt = new Date(checkMs).toISOString();
          hb.updatedAt = hb.missedAt;
          dirty = true;
        }
        const incident = {
          type: 'heartbeat_missed',
          heartbeatId: hb.id,
          name: hb.name,
          projectId: hb.projectId,
          overdueSec: Math.round((checkMs - deadlineMs) / 1000),
          deadlineAt: new Date(deadlineMs).toISOString(),
          detectedAt: new Date(checkMs).toISOString(),
          deduplicated: wasAlertActive
        };
        missed.push(incident);

        if (!wasAlertActive) {
          hb.alertActive = true;
          dirty = true;
          this.emit('heartbeat_missed', incident);
          if (opts && typeof opts.onAlert === 'function') {
            try { opts.onAlert(incident); } catch (e) {}
          }
          try {
            const ae = getAlertEngine();
            if (ae && typeof ae.emit === 'function') ae.emit('heartbeat_alert', incident);
          } catch (e) {}
        }
      }
    }

    if (dirty) this._saveHeartbeats();
    return { checked: this.heartbeats.length, missed };
  }

  startScheduler() {
    if (this._timer) return;
    this._timer = setInterval(() => this.tick(), TICK_INTERVAL_MS);
    if (this._timer.unref) this._timer.unref();
  }

  stopScheduler() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
  }
}

const instance = /** @type {any} */ (new CronManager());
instance.CronManager = CronManager;
module.exports = instance;
