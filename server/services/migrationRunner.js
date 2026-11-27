const { execFile } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { parseSafeCommandArgv, sanitizeWorkdir } = require('./safeCommand');

/**
 * Motor de Migraciones Pre-Despliegue Atómicas con Líder Único (Cero Shell, Cero Dependencias).
 *
 * Resuelve dos fallos críticos de producción en PaaS modernos:
 *  - `kamal#1513`: carreras de migración cuando múltiples réplicas arrancan en paralelo
 *    (garantiza exclusión mutua con lease atómico en memoria + disco `wx` y recuperación
 *    automática ante PIDs muertos o TTL vencido).
 *  - `dokploy#4154`: migraciones sin snapshot previo ni aborto del cutover ante código != 0
 *    (obliga a `abortCutover: true` cuando la migración falla, protegiendo el contenedor vivo).
 *
 * Invariantes:
 *  - 0 dependencias npm externas (`child_process.execFile`, `crypto`, `fs`, `path`).
 *  - 0 invocaciones de shell (`shell: false` estricto; prohíbe `;`, `|`, `&`, `` ` ``, `$(`, `>`, `<`, `\n`, `\0`).
 *  - Aislamiento completo vía `CULKIBO_DATA_DIR` o `opts.leaseDir` (0 escrituras en disco al hacer `require()`).
 */

const SHELL_METACHAR_RE = /[;|&`><\r\n\0]|\$\(/;
const FORBIDDEN_SHELL_BINS = new Set([
  'sh', 'bash', 'zsh', 'dash', 'ksh', 'csh', 'fish',
  'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe',
  '/bin/sh', '/bin/bash', '/bin/zsh', '/usr/bin/sh', '/usr/bin/bash'
]);
const SAFE_DOCKER_TOKEN_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}$/;
const DEFAULT_TIMEOUT_MS = 120 * 1000;
const MIN_TIMEOUT_MS = 1000;
const MAX_TIMEOUT_MS = 30 * 60 * 1000;
const MAX_OUTPUT_BYTES = 64 * 1024;

/**
 * Resuelve el directorio por defecto de leases respetando `CULKIBO_DATA_DIR`.
 * @param {string | null} [overrideDir]
 * @returns {string}
 */
function resolveLeaseDir(overrideDir = null) {
  if (overrideDir) return path.resolve(overrideDir);
  if (process.env.CULKIBO_DATA_DIR) {
    return path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data', 'migration-leases');
  }
  return path.resolve(__dirname, '..', '..', 'data', 'migration-leases');
}

/**
 * Normaliza un identificador para nombre de archivo / clave de lock seguro.
 * @param {string} raw
 * @returns {string}
 */
function sanitizeLockSlug(raw) {
  const clean = String(raw || '')
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 64);
  if (!clean) throw new Error('Identificador de proyecto inválido para lease de migración');
  return clean;
}

/**
 * Comprueba de forma portátil si un PID sigue vivo en el SO actual.
 * `process.kill(pid, 0)` no envía señal real: lanza `ESRCH` si murió y `EPERM` si vive bajo otro usuario.
 * @param {number} pid
 * @returns {boolean}
 */
function isPidAlive(pid) {
  const num = Number(pid);
  if (!Number.isInteger(num) || num <= 0) return false;
  try {
    process.kill(num, 0);
    return true;
  } catch (err) {
    if (err && err.code === 'EPERM') return true;
    return false;
  }
}

/**
 * Valida y convierte un comando de migración en `argv: string[]` estrictamente sin shell.
 * Rechaza cualquier metacarácter de shell (`;`, `|`, `&`, `` ` ``, `$(`, `>`, `<`, `\n`, `\0`)
 * tanto en cadenas como en argumentos individuales de arrays, así como intérpretes de shell.
 *
 * @param {string | string[] | null | undefined} cmd
 * @returns {string[]}
 */
function parseSafeMigrationArgv(cmd) {
  if (cmd == null) {
    throw new Error('Comando de migración vacío');
  }
  if (typeof cmd === 'string') {
    if (SHELL_METACHAR_RE.test(cmd)) {
      throw new Error('Inyección de shell rechazada en comando de migración: metacaracteres prohibidos');
    }
  } else if (Array.isArray(cmd)) {
    for (const part of cmd) {
      if (typeof part !== 'string') {
        throw new Error('Todos los argumentos de migración deben ser cadenas de texto');
      }
      if (SHELL_METACHAR_RE.test(part)) {
        throw new Error('Inyección de shell rechazada en argumento de migración: metacaracteres prohibidos');
      }
    }
  } else {
    throw new Error('Formato de comando de migración inválido (debe ser string o string[])');
  }

  const argv = parseSafeCommandArgv(cmd, { maxArgs: 48, maxLength: 1024 });
  for (const token of argv) {
    if (SHELL_METACHAR_RE.test(token)) {
      throw new Error('Inyección de shell rechazada en token de migración');
    }
  }

  const normalizedBin = String(argv[0] || '').trim().toLowerCase().replace(/\\/g, '/');
  const baseBin = path.posix.basename(normalizedBin);
  if (FORBIDDEN_SHELL_BINS.has(normalizedBin) || FORBIDDEN_SHELL_BINS.has(baseBin)) {
    throw new Error(`Intérprete de shell prohibido en migraciones atómicas: "${argv[0]}"`);
  }

  return argv;
}

/**
 * Redacta secretos conocidos en la salida textual de la migración antes de truncar.
 * @param {string} text
 * @param {any} project
 * @param {string[]} [extraSecrets]
 * @returns {string}
 */
function redactMigrationOutput(text, project, extraSecrets = []) {
  let out = String(text || '');
  /** @type {Set<string>} */
  const secrets = new Set();
  const envVars = (project && project.envVars && typeof project.envVars === 'object') ? project.envVars : {};
  for (const [k, v] of Object.entries(envVars)) {
    if (typeof v !== 'string' || v.length < 6) continue;
    if (/(secret|token|pass|key|auth|pwd|dsn|url|cred)/i.test(k)) {
      secrets.add(v);
    }
  }
  for (const s of extraSecrets) {
    if (typeof s === 'string' && s.length >= 6) secrets.add(s);
  }
  for (const s of secrets) {
    out = out.split(s).join('[REDACTED]');
  }
  if (out.length > MAX_OUTPUT_BYTES) {
    return `${out.slice(0, MAX_OUTPUT_BYTES)}\n...[output truncated]`;
  }
  return out;
}

class MigrationRunner {
  /**
   * @param {{
   *   leaseDir?: string | null,
   *   defaultTimeoutMs?: number,
   *   isPidAliveFn?: (pid: number) => boolean
   * }} [opts]
   */
  constructor(opts = {}) {
    this._leaseDirOverride = opts.leaseDir || null;
    this.defaultTimeoutMs = Math.min(
      MAX_TIMEOUT_MS,
      Math.max(MIN_TIMEOUT_MS, Number(opts.defaultTimeoutMs) || DEFAULT_TIMEOUT_MS)
    );
    this._isPidAlive = typeof opts.isPidAliveFn === 'function' ? opts.isPidAliveFn : isPidAlive;
    /**
     * Registro en memoria de leases activos en el proceso actual (evita condiciones
     * de carrera intra-proceso cuando dos despliegues comparten el mismo PID).
     * @type {Map<string, { leaseId: string, lockKey: string, projectId: string, pid: number, acquiredAt: string, expiresAt: string }>}
     */
    this._activeLeases = new Map();
  }

  get leaseDir() {
    return resolveLeaseDir(this._leaseDirOverride);
  }

  /** @param {string} lockKey */
  _lockFilePath(lockKey) {
    const safeKey = sanitizeLockSlug(lockKey);
    return path.join(this.leaseDir, `${safeKey}.lock.json`);
  }

  /**
   * Comprueba si un lease existente está vencido o pertenece a un PID muerto.
   * @param {{ pid?: number, expiresAt?: string } | null} record
   * @param {number} nowMs
   * @returns {{ stale: boolean, reason: string | null }}
   */
  _inspectStaleRecord(record, nowMs) {
    if (!record || typeof record !== 'object') {
      return { stale: true, reason: 'corrupt_lease_record' };
    }
    const expMs = Date.parse(String(record.expiresAt || ''));
    if (!Number.isFinite(expMs) || expMs <= nowMs) {
      return { stale: true, reason: 'ttl_expired' };
    }
    const holderPid = Number(record.pid);
    if (!Number.isInteger(holderPid) || holderPid <= 0 || !this._isPidAlive(holderPid)) {
      return { stale: true, reason: 'dead_pid' };
    }
    return { stale: false, reason: null };
  }

  /**
   * Adquiere un lease exclusivo de líder único por proyecto con recuperación automática
   * de bloqueos huérfanos por PID caído o TTL expirado.
   *
   * @param {string} lockKey
   * @param {{ projectId?: string, ttlMs?: number, pid?: number }} [opts]
   */
  acquireLease(lockKey, opts = {}) {
    const safeKey = sanitizeLockSlug(lockKey);
    const nowMs = Date.now();
    const ttlMs = Math.min(MAX_TIMEOUT_MS + 60000, Math.max(2000, Number(opts.ttlMs) || (this.defaultTimeoutMs + 30000)));
    const pid = Number.isInteger(Number(opts.pid)) && Number(opts.pid) > 0 ? Number(opts.pid) : process.pid;
    const projectId = String(opts.projectId || safeKey);

    /** @type {{ previousPid: number | null, previousLeaseId: string | null, reason: string } | null} */
    let recoveredStaleLease = null;

    // 1. Verificar lease en memoria
    const memLease = this._activeLeases.get(safeKey);
    if (memLease) {
      const check = this._inspectStaleRecord(memLease, nowMs);
      if (check.stale) {
        recoveredStaleLease = {
          previousPid: memLease.pid || null,
          previousLeaseId: memLease.leaseId || null,
          reason: check.reason || 'stale_memory_lease'
        };
        this._activeLeases.delete(safeKey);
        try { fs.unlinkSync(this._lockFilePath(safeKey)); } catch (e) {}
      } else {
        const err = new Error(`Migración ya en curso para "${projectId}" (lock ${safeKey}, PID ${memLease.pid})`);
        /** @type {any} */ (err).code = 'MIGRATION_LOCKED';
        /** @type {any} */ (err).status = 409;
        /** @type {any} */ (err).lockKey = safeKey;
        /** @type {any} */ (err).holderPid = memLease.pid;
        throw err;
      }
    }

    // 2. Adquirir lockfile atómico en disco (`flag: 'wx'`) con recuperación ante huérfano
    const dir = this.leaseDir;
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const lockFile = this._lockFilePath(safeKey);

    const leaseId = `mig_${nowMs.toString(36)}_${crypto.randomBytes(6).toString('hex')}`;
    const record = {
      leaseId,
      lockKey: safeKey,
      projectId,
      pid,
      acquiredAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(nowMs + ttlMs).toISOString()
    };

    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        fs.writeFileSync(lockFile, JSON.stringify(record, null, 2), { encoding: 'utf8', flag: 'wx', mode: 0o600 });
        this._activeLeases.set(safeKey, record);
        return { ...record, lockFile, recoveredStaleLease };
      } catch (err) {
        if (!err || err.code !== 'EEXIST') throw err;

        /** @type {any} */
        let existing = null;
        try {
          existing = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
        } catch (parseErr) {
          existing = null;
        }

        const check = this._inspectStaleRecord(existing, nowMs);
        if (!check.stale) {
          const lockErr = new Error(
            `Migración ya en curso para "${projectId}" (lock ${safeKey}, PID ${existing && existing.pid ? existing.pid : 'desconocido'})`
          );
          /** @type {any} */ (lockErr).code = 'MIGRATION_LOCKED';
          /** @type {any} */ (lockErr).status = 409;
          /** @type {any} */ (lockErr).lockKey = safeKey;
          /** @type {any} */ (lockErr).holderPid = existing ? existing.pid : null;
          throw lockErr;
        }

        recoveredStaleLease = {
          previousPid: existing && existing.pid ? Number(existing.pid) : null,
          previousLeaseId: existing && existing.leaseId ? String(existing.leaseId) : null,
          reason: check.reason || 'stale_disk_lease'
        };
        try { fs.unlinkSync(lockFile); } catch (e) {}
      }
    }

    const busyErr = new Error(`No se pudo adquirir el lease exclusivo de migración para "${projectId}"`);
    /** @type {any} */ (busyErr).code = 'MIGRATION_LOCKED';
    /** @type {any} */ (busyErr).status = 409;
    /** @type {any} */ (busyErr).lockKey = safeKey;
    throw busyErr;
  }

  /**
   * Libera un lease únicamente si pertenece al `leaseId` indicado (evita liberar locks ajenos).
   * @param {string} lockKey
   * @param {string} [leaseId]
   */
  releaseLease(lockKey, leaseId) {
    const safeKey = sanitizeLockSlug(lockKey);
    const mem = this._activeLeases.get(safeKey);
    if (mem && (!leaseId || mem.leaseId === leaseId)) {
      this._activeLeases.delete(safeKey);
    }

    const lockFile = this._lockFilePath(safeKey);
    try {
      if (fs.existsSync(lockFile)) {
        if (leaseId) {
          try {
            const diskRec = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
            if (diskRec && diskRec.leaseId && diskRec.leaseId !== leaseId) {
              return { released: false, reason: 'lease_owner_mismatch' };
            }
          } catch (e) {}
        }
        fs.unlinkSync(lockFile);
      }
    } catch (e) {
      return { released: false, reason: e.message };
    }
    return { released: true, lockKey: safeKey };
  }

  /**
   * Construye el plan determinista y seguro (cero shell) para una migración pre-despliegue.
   *
   * @param {any} project
   * @param {{
   *   command?: string | string[],
   *   snapshotRequired?: boolean,
   *   timeoutMs?: number,
   *   containerName?: string | null,
   *   imageTag?: string | null,
   *   network?: string | null,
   *   workdir?: string | null
   * }} [opts]
   */
  planMigration(project, opts = {}) {
    if (!project || !project.id) {
      throw new Error('planMigration requiere un proyecto válido con id');
    }

    const rawCmd = opts.command !== undefined
      ? opts.command
      : (project.migrationCommand || project.preDeployCommand || '');
    const argv = parseSafeMigrationArgv(rawCmd);
    const projectSlug = sanitizeLockSlug(project.id);
    const lockKey = `mig_${projectSlug}`;
    const timeoutMs = Math.min(
      MAX_TIMEOUT_MS,
      Math.max(MIN_TIMEOUT_MS, Number(opts.timeoutMs) || this.defaultTimeoutMs)
    );
    const snapshotRequired = opts.snapshotRequired !== undefined ? Boolean(opts.snapshotRequired) : true;
    const workdir = sanitizeWorkdir(opts.workdir || project.migrationWorkdir || null);

    const containerName = opts.containerName ? String(opts.containerName).trim() : null;
    if (containerName && !SAFE_DOCKER_TOKEN_RE.test(containerName)) {
      throw new Error(`Nombre de contenedor inválido para migración: "${containerName.slice(0, 60)}"`);
    }
    const imageTag = String(opts.imageTag || project.imageTag || `culkibo/${projectSlug}:latest`).trim();
    if (!SAFE_DOCKER_TOKEN_RE.test(imageTag)) {
      throw new Error(`Imagen Docker inválida para migración: "${imageTag.slice(0, 80)}"`);
    }
    const network = opts.network ? String(opts.network).trim() : null;
    if (network && !SAFE_DOCKER_TOKEN_RE.test(network)) {
      throw new Error(`Red Docker inválida para migración: "${network.slice(0, 60)}"`);
    }

    /** @type {string[]} */
    let dockerArgs;
    if (containerName) {
      dockerArgs = ['exec', ...(workdir ? ['-w', workdir] : []), containerName, ...argv];
    } else {
      dockerArgs = [
        'run', '--rm',
        '--label', 'culkibo.managed=true',
        '--label', 'culkibo.migration=true',
        '--label', `culkibo.project=${projectSlug}`,
        ...(network ? ['--network', network] : []),
        ...(workdir ? ['-w', workdir] : []),
        imageTag,
        ...argv
      ];
    }

    return {
      ok: true,
      projectId: String(project.id),
      command: argv.join(' '),
      argv,
      binary: argv[0],
      snapshotRequired,
      lockKey,
      timeoutMs,
      abortCutoverOnFailure: true,
      zeroShell: true,
      dockerCommand: { program: 'docker', args: dockerArgs },
      dockerArgs
    };
  }

  /**
   * Ejecuta una migración pre-despliegue atómica:
   *  1. Valida plan y `argv` sin shell (fail-fast).
   *  2. Adquiere lease de líder único (recupera locks de PIDs muertos/expirados).
   *  3. Ejecuta hook `onBeforeSnapshot()` cuando `snapshotRequired !== false`.
   *  4. Lanza el comando vía `opts.runner` o `execFile(..., { shell: false })` con timeout estricto.
   *  5. Libera el lease SIEMPRE en `finally` y marca `abortCutover: !ok`.
   *
   * @param {any} project
   * @param {{
   *   command?: string | string[],
   *   snapshotRequired?: boolean,
   *   timeoutMs?: number,
   *   leaseTtlMs?: number,
   *   pid?: number,
   *   containerName?: string | null,
   *   imageTag?: string | null,
   *   network?: string | null,
   *   workdir?: string | null,
   *   cwd?: string,
   *   env?: Record<string, string>,
   *   redactValues?: string[],
   *   directExec?: boolean,
   *   onBeforeSnapshot?: (ctx: { project: any, plan: any, lease: any }) => Promise<string | { snapshotId?: string, id?: string } | null | void>,
   *   runner?: (plan: any, ctx: { lease: any, timeoutMs: number }) => Promise<{ exitCode?: number, code?: number, stdout?: string, stderr?: string, output?: string, timedOut?: boolean }>
   * }} [opts]
   */
  async runMigration(project, opts = {}) {
    const plan = this.planMigration(project, opts);
    const lease = this.acquireLease(plan.lockKey, {
      projectId: plan.projectId,
      ttlMs: opts.leaseTtlMs || Math.max(plan.timeoutMs + 30000, 60000),
      pid: opts.pid
    });

    const startedAt = Date.now();
    /** @type {string | null} */
    let snapshotId = null;

    try {
      // 1. Pre-migration snapshot hook (aborta ANTES de tocar el esquema si el snapshot falla)
      if (plan.snapshotRequired && typeof opts.onBeforeSnapshot === 'function') {
        const snapRes = await opts.onBeforeSnapshot({ project, plan, lease });
        if (typeof snapRes === 'string') {
          snapshotId = snapRes;
        } else if (snapRes && typeof snapRes === 'object') {
          snapshotId = String(snapRes.snapshotId || snapRes.id || '') || null;
        }
      }

      // 2. Ejecutar comando sin shell (custom runner o execFile directo con shell: false)
      /** @type {{ exitCode: number, output: string, timedOut: boolean, error: string | null }} */
      let execRes;
      if (typeof opts.runner === 'function') {
        const r = await opts.runner(plan, { lease, timeoutMs: plan.timeoutMs });
        const rawCode = r && r.exitCode !== undefined ? r.exitCode : (r && r.code !== undefined ? r.code : 0);
        const exitCode = Number.isInteger(Number(rawCode)) ? Number(rawCode) : 1;
        const combined = r && r.output !== undefined
          ? String(r.output)
          : [r && r.stdout ? r.stdout : '', r && r.stderr ? r.stderr : ''].filter(Boolean).join('\n');
        execRes = {
          exitCode,
          output: combined,
          timedOut: Boolean(r && r.timedOut),
          error: exitCode === 0 && !(r && r.timedOut) ? null : `Migration exited with code ${exitCode}`
        };
      } else {
        const program = opts.directExec ? plan.argv[0] : 'docker';
        const args = opts.directExec ? plan.argv.slice(1) : plan.dockerArgs;
        execRes = await new Promise((resolve) => {
          execFile(
            program,
            args,
            {
              shell: false,
              timeout: plan.timeoutMs,
              maxBuffer: 2 * 1024 * 1024,
              cwd: opts.cwd || undefined,
              env: opts.env ? { ...process.env, ...opts.env } : process.env,
              windowsHide: true
            },
            (err, stdout, stderr) => {
              const combined = [stdout || '', stderr || ''].filter(Boolean).join('\n');
              if (!err) {
                resolve({ exitCode: 0, output: combined, timedOut: false, error: null });
                return;
              }
              const timedOut = Boolean(err.killed && err.signal);
              const numericCode = typeof err.code === 'number' ? err.code : 1;
              resolve({
                exitCode: timedOut ? 124 : numericCode,
                output: combined || err.message,
                timedOut,
                error: err.message || `Migration failed (${numericCode})`
              });
            }
          );
        });
      }

      const durationMs = Math.max(0, Date.now() - startedAt);
      const ok = execRes.exitCode === 0 && !execRes.timedOut;
      const safeOutput = redactMigrationOutput(execRes.output, project, opts.redactValues || []);

      return {
        ok,
        exitCode: execRes.exitCode,
        timedOut: execRes.timedOut,
        durationMs,
        abortCutover: !ok,
        snapshotId,
        lockKey: plan.lockKey,
        recoveredStaleLease: lease.recoveredStaleLease,
        output: safeOutput,
        error: ok ? null : (execRes.error || `Migration failed with exit code ${execRes.exitCode}`),
        plan
      };
    } catch (err) {
      const durationMs = Math.max(0, Date.now() - startedAt);
      return {
        ok: false,
        exitCode: 1,
        timedOut: false,
        durationMs,
        abortCutover: true,
        snapshotId,
        lockKey: plan.lockKey,
        recoveredStaleLease: lease.recoveredStaleLease,
        output: '',
        error: err && err.message ? err.message : 'Migration execution error',
        plan
      };
    } finally {
      this.releaseLease(plan.lockKey, lease.leaseId);
    }
  }
}

const instance = /** @type {any} */ (new MigrationRunner());
instance.MigrationRunner = MigrationRunner;
instance.parseSafeMigrationArgv = parseSafeMigrationArgv;
instance.isPidAlive = isPidAlive;
module.exports = instance;
