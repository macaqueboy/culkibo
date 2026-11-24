const { EventEmitter } = require('events');
const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { parseCron, nextCronRun } = require('./cronParser');
const { parseSafeCommandArgv, sanitizeWorkdir } = require('./safeCommand');
const { atomicWriteJsonSync } = require('./ssrfGuard');

const DATA_DIR = process.env.CULKIBO_DATA_DIR
  ? path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data')
  : path.resolve(__dirname, '..', '..', 'data');
const STORE_FILE = path.join(DATA_DIR, 'crons.json');
const STORE_BAK_FILE = `${STORE_FILE}.bak`;
const MAX_HISTORY_PER_JOB = 25;
const MAX_OUTPUT_BYTES = 8 * 1024;
const TICK_INTERVAL_MS = 30 * 1000;

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
  let out = String(text || '');
  if (out.length > MAX_OUTPUT_BYTES) {
    out = out.slice(0, MAX_OUTPUT_BYTES) + '\n... [salida truncada]';
  }
  const envVars = (project && project.envVars) || {};
  for (const val of Object.values(envVars)) {
    const s = String(val || '');
    if (s.length >= 8 && out.includes(s)) {
      out = out.split(s).join('[REDACTED]');
    }
  }
  return out;
}

class CronManager extends EventEmitter {
  constructor(storeFile = STORE_FILE) {
    super();
    this.storeFile = storeFile;
    this.storeBakFile = `${storeFile}.bak`;
    /** @type {Array<any>} */
    this.jobs = [];
    /** @type {Set<string>} */
    this.runningJobs = new Set();
    /** @type {ReturnType<typeof setInterval> | null} */
    this._timer = null;
    this._loaded = false;
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
        const isContainerized = process.env.CULKIBO_CADDY_CONTAINERIZED === '1' || fs.existsSync('/.dockerenv');
        const targetHost = isContainerized && current.containerName
          ? `${current.containerName}:${current.containerPort || 3000}`
          : `127.0.0.1:${current.hostPort}`;
        const url = `http://${targetHost}${job.httpPath}`;
        const res = await fetch(url, {
          method: job.httpMethod || 'POST',
          headers: {
            'User-Agent': 'Culkibo-Cron/1.0',
            'X-Culkibo-Cron-Id': job.id,
            ...(job.httpHeaders || {})
          },
          signal: AbortSignal.timeout(job.timeoutMs)
        });
        const text = await res.text().catch(() => '');
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
