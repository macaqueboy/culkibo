const { spawn, execFileSync } = require('child_process');
const net = require('net');
const os = require('os');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { assertContainedPath, isPrivateIp, isMetadataIp } = require('./ssrfGuard');
const { parseSafeCommandArgv } = require('./safeCommand');
const portRegistry = require('./portRegistry');

const ROOT_BASE_DIR = process.env.CULKIBO_DATA_DIR
  ? path.resolve(process.env.CULKIBO_DATA_DIR)
  : path.resolve(__dirname, '..', '..');
const PROJECTS_ROOT = path.resolve(ROOT_BASE_DIR, 'projects');

const ANSI_ESCAPE_RE = /\x1B\[[0-9;?]*[ -/]*[@-~]|\x1B\][^\x07]*\x07/g;
function stripAnsi(s) {
  return String(s == null ? '' : s).replace(ANSI_ESCAPE_RE, '');
}

const OFFLINE_PAGE_CSS = `
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#fafafa;color:#18181b;font-family:system-ui,-apple-system,'Segoe UI',sans-serif;padding:24px;}
  .card{max-width:560px;width:100%;background:#fff;border:1px solid #e4e4e7;border-radius:12px;padding:28px;box-shadow:0 1px 3px rgba(24,24,27,.06);}
  h1{margin:0 0 6px;font-size:18px;font-weight:600;color:#18181b;}
  .pill{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;padding:3px 10px;border-radius:999px;border:1px solid #e4e4e7;background:#f4f4f5;color:#3f3f46;}
  .pill.warn{background:#fffbeb;border-color:#fde68a;color:#92400e;}
  .pill.err{background:#fef2f2;border-color:#fecaca;color:#991b1b;}
  .pill.ok{background:#ecfdf5;border-color:#a7f3d0;color:#065f46;}
  p{font-size:14px;color:#52525b;line-height:1.55;margin:14px 0;}
  code{background:#f4f4f5;border:1px solid #e4e4e7;border-radius:6px;padding:1px 6px;font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#18181b;}
  pre{background:#fafafa;border:1px solid #e4e4e7;border-radius:8px;padding:12px;font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#27272a;overflow:auto;max-height:220px;white-space:pre-wrap;word-break:break-word;margin:10px 0 0;}
  details{margin:14px 0;border:1px solid #e4e4e7;border-radius:8px;padding:10px 12px;background:#fafafa;}
  summary{cursor:pointer;font-size:12px;font-weight:600;color:#52525b;}
  .actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:16px;}
  .btn{display:inline-block;text-decoration:none;background:#18181b;color:#fff;padding:9px 14px;border-radius:8px;font-size:13px;font-weight:600;border:0;cursor:pointer;}
  .btn:hover{background:#27272a;}
  .btn-ghost{display:inline-block;text-decoration:none;background:#fff;color:#3f3f46;padding:8px 14px;border-radius:8px;font-size:13px;font-weight:500;border:1px solid #e4e4e7;}
  .btn-ghost:hover{background:#f4f4f5;color:#18181b;}
  .foot{margin-top:18px;padding-top:14px;border-top:1px solid #f4f4f5;display:flex;justify-content:space-between;align-items:center;font-size:12px;color:#71717a;}
`;

/** Traduce errores técnicos de git a un mensaje claro y accionable en español. */
function explainGitError(rawMsg) {
  const s = String(rawMsg || '').toLowerCase();
  if (s.includes('invalid username or token') || s.includes('authentication failed') || s.includes('could not read username') || s.includes('password authentication is not supported')) {
    return 'GitHub rechazó el acceso: el repositorio es privado, no existe o el Personal Access Token guardado en Ajustes → Integraciones ha caducado o no tiene permiso «repo».';
  }
  if (s.includes('repository not found') || s.includes('not found')) {
    return 'No se encontró el repositorio Git. Comprueba que la URL del proyecto en Configuración es correcta y accesible.';
  }
  if (s.includes('could not resolve host') || s.includes('unable to access') || s.includes('timed out')) {
    return 'No se pudo conectar con el servidor Git remoto. Revisa tu conexión a Internet o un posible proxy/cortafuegos.';
  }
  return 'Ocurrió un error al preparar el código local del proyecto. Revisa el diagnóstico técnico o la URL del repositorio en Configuración.';
}

/** Puertos reservados del sistema/infraestructura que `killProcessOnPort` JAMÁS debe matar. */
const RESERVED_PORTS = new Set([22, 53, 80, 443, 2019, 2375, 2376, 3306, 5432, 6379, 27017]);

/** Variables del entorno del host que un proyecto no fiable NO puede heredar ni sobreescribir. */
const SAFE_HOST_ENV_ALLOWLIST = [
  'PATH', 'Path', 'PATHEXT', 'COMSPEC', 'ComSpec', 'SystemRoot', 'SYSTEMROOT',
  'SystemDrive', 'HOMEDRIVE', 'HOMEPATH',
  'WINDIR', 'TEMP', 'TMP', 'TMPDIR', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA',
  'LANG', 'LC_ALL', 'LC_CTYPE', 'TERM', 'TZ', 'OS', 'NUMBER_OF_PROCESSORS',
  'ProgramFiles', 'ProgramFiles(x86)', 'CommonProgramFiles', 'PROGRAMDATA',
  'GOPATH', 'GOROOT', 'PNPM_HOME', 'BUN_INSTALL', 'CARGO_HOME', 'VIRTUAL_ENV'
];

const BLOCKED_PROJECT_ENV_KEYS = new Set([
  'PATH', 'PATHEXT', 'COMSPEC', 'SYSTEMROOT', 'WINDIR',
  'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH',
  'NODE_OPTIONS', 'BASH_ENV', 'ENV', 'IFS',
  'DOCKER_HOST', 'DOCKER_CONFIG', 'DOCKER_CONTEXT', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY',
  'GIT_SSH_COMMAND', 'GIT_ASKPASS', 'GIT_EXEC_PATH'
]);

/** Construye un entorno limpio para subprocesos de usuario (sin secretos del daemon ni secuestro de PATH/LD_PRELOAD). */
function buildSafeChildEnv(extraEnv = {}, projectEnvVars = {}) {
  /** @type {Record<string, string>} */
  const env = {};
  const isWin = process.platform === 'win32';
  const seenUpper = new Set();

  for (const key of SAFE_HOST_ENV_ALLOWLIST) {
    if (process.env[key] === undefined) continue;
    const upper = key.toUpperCase();
    if (isWin && seenUpper.has(upper)) continue;
    seenUpper.add(upper);
    env[key] = String(process.env[key]);
  }
  for (const [k, v] of Object.entries(projectEnvVars || {})) {
    if (!k || BLOCKED_PROJECT_ENV_KEYS.has(k.toUpperCase())) continue;
    if (/^CULKIBO_/i.test(k)) continue;
    env[k] = String(v == null ? '' : v);
  }
  for (const [k, v] of Object.entries(extraEnv || {})) {
    if (v !== undefined) env[k] = String(v);
  }
  return env;
}

/** Lazy require para evitar dependencias circulares al actualizar estado o consultar BDs. */
function getProjectManager() {
  try { return require('./projectManager'); } catch (e) { return null; }
}
function getDatabaseManager() {
  try { return require('./databaseManager'); } catch (e) { return null; }
}

/**
 * Metacaracteres que cmd.exe interpreta incluso dentro de comillas dobles.
 *
 * En Windows no existe forma de lanzar un `.cmd`/`.bat` (npm, npx, vite...) sin
 * pasar por `cmd.exe /c`: desde la corrección de CVE-2024-27980, Node lanza
 * EINVAL si se intenta con `spawn` directo. Como `cmd.exe` vuelve a parsear la
 * línea que Node construye, la única defensa real es rechazar los argumentos
 * que contengan algo que cmd.exe pueda leer como separador. En POSIX no hace
 * falta: allí se lanza el binario directamente, sin shell intermedio.
 */
const CMD_METACHARS = /[&|<>^"%\r\n]/;

/**
 * Lanza una herramienta sin construir jamás una cadena de shell.
 *
 * POSIX: `spawn(bin, argv)` — no hay shell.
 * Windows: `cmd.exe /c bin ...argv` con los argumentos verificados uno a uno.
 * Devuelve el ChildProcess para que el llamante gestione stdio y señales.
 */
function spawnTool(bin, args, options = {}) {
  const argv = args.map(String);
  if (process.platform === 'win32') {
    for (const a of [bin, ...argv]) {
      if (CMD_METACHARS.test(a)) {
        throw new Error(`Argumento rechazado por contener metacaracteres de cmd.exe: ${JSON.stringify(a)}`);
      }
    }
    return spawn('cmd.exe', ['/c', bin, ...argv], { ...options, shell: false });
  }
  return spawn(bin, argv, { ...options, shell: false });
}

/** @type {any} */
let containerOrchestrator = null;
try {
  containerOrchestrator = require('./containerOrchestrator');
} catch(e) {}

/** @type {any} */
let notificationService = null;
try {
  notificationService = require('./notificationService');
} catch(e) {}

/** Dispara una alerta saliente sin bloquear ni poder fallar hacia el llamante. */
function alert(payload) {
  if (!notificationService) return;
  Promise.resolve(notificationService.notify(payload)).catch(() => {});
}

/**
 * Escape a value before interpolating it into one of the HTML notice pages
 * this module serves. Project names, git URLs and error output are all
 * attacker-influenceable (a repo name, an npm error message, an env var).
 */
function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

class LocalRunner {
  constructor() {
    this.activeRunners = new Map(); // projectId -> { type, child, server, port, startTime, projectDir }
    this.cloningLocks = new Map(); // projectId -> Promise
    this.runGenerations = new Map(); // projectId -> number
    this.startLocks = new Map(); // projectId -> Promise (serialises concurrent start())
    this._syncRestartTimers = new Map(); // projectId -> Timeout
    /** @type {{ mtimeMs: number, token: string | null } | null} */
    this._gitTokenCache = null;
    portRegistry.registerProvider('localRunner', () =>
      Array.from(this.activeRunners.values()).map((r) => r && r.port).filter(Boolean)
    );
  }

  /**
   * Resuelve el directorio de un proyecto:
   * - Si recibe un objeto `project` con `localPath` válido y existente, lo usa directamente.
   * - En caso contrario, confina `projects/<id>` dentro de `PROJECTS_ROOT`.
   * @param {string | { id: string, localPath?: string | null }} projectOrId
   */
  resolveProjectDir(projectOrId) {
    if (projectOrId && typeof projectOrId === 'object') {
      const lp = typeof projectOrId.localPath === 'string' ? projectOrId.localPath.trim() : '';
      if (lp && !lp.includes('\0')) {
        const resolved = path.resolve(lp);
        const rootParsed = path.parse(resolved).root;
        if (resolved !== rootParsed && fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) {
          return resolved;
        }
      }
      return this.resolveProjectDir(projectOrId.id);
    }
    const id = String(projectOrId || '').trim();
    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(id)) {
      throw new Error(`Identificador de proyecto inválido: ${id.slice(0, 40)}`);
    }
    return assertContainedPath(PROJECTS_ROOT, id);
  }

  /**
   * Construye el entorno efectivo para ejecución local fusionando:
   * BDs vinculadas expuestas < envVars de recursos < project.envVars < PORT/HOST/PYTHONUNBUFFERED.
   */
  resolveLocalEnv(project, port, extra = {}) {
    /** @type {Record<string, string>} */
    const merged = {};

    // 1. Variables de conexión a bases de datos gestionadas vinculadas al proyecto
    try {
      const dbm = getDatabaseManager();
      if (dbm && typeof dbm.list === 'function' && project?.id) {
        const dbs = dbm.list({ projectId: project.id });
        for (const db of dbs) {
          if (!db || !db.id || typeof dbm.getCredentials !== 'function') continue;
          const creds = dbm.getCredentials(db.id);
          const url = creds?.externalUrl || creds?.internalUrl || null;
          if (!url) continue;
          if (db.engine === 'redis' || db.engine === 'valkey') {
            if (!merged.REDIS_URL) merged.REDIS_URL = url;
          } else if (db.engine === 'mongodb') {
            if (!merged.MONGODB_URI) merged.MONGODB_URI = url;
            if (!merged.DATABASE_URL) merged.DATABASE_URL = url;
          } else {
            if (!merged.DATABASE_URL) merged.DATABASE_URL = url;
          }
        }
      }
    } catch (e) {}

    // 2. Variables declaradas en recursos del proyecto (Coolify/Compose)
    if (Array.isArray(project?.resources)) {
      for (const r of project.resources) {
        if (r && r.envVars && typeof r.envVars === 'object') {
          for (const [k, v] of Object.entries(r.envVars)) {
            if (k && v !== undefined && v !== null) merged[k] = String(v);
          }
        }
      }
    }

    // 3. Variables explícitas del proyecto (prioridad más alta del usuario)
    if (project?.envVars && typeof project.envVars === 'object') {
      for (const [k, v] of Object.entries(project.envVars)) {
        if (k && v !== undefined && v !== null) merged[k] = String(v);
      }
    }

    return buildSafeChildEnv({
      PORT: String(port),
      HOST: '0.0.0.0',
      HOSTNAME: '0.0.0.0',
      NODE_ENV: merged.NODE_ENV || 'development',
      PYTHONUNBUFFERED: '1',
      ...extra
    }, merged);
  }

  /** Redacta tanto el token Git como cualquier secreto largo (>=8 chars) del entorno del proyecto. */
  redactProjectSecrets(text, project) {
    let out = this.redactSecrets(text);
    const values = new Set();
    const collect = (obj) => {
      if (!obj || typeof obj !== 'object') return;
      for (const [k, v] of Object.entries(obj)) {
        const s = String(v == null ? '' : v);
        if (s.length >= 8 && (/secret|token|key|pass|auth|jwt|dsn|url|uri|cred/i.test(k) || s.includes('://'))) {
          values.add(s);
        }
      }
    };
    collect(project?.envVars);
    if (Array.isArray(project?.resources)) {
      for (const r of project.resources) collect(r?.envVars);
    }
    for (const secret of values) {
      out = out.split(secret).join('********');
    }
    return out;
  }

  currentGeneration(projectId) {
    return this.runGenerations.get(projectId) || 0;
  }

  bumpGeneration(projectId) {
    const next = this.currentGeneration(projectId) + 1;
    this.runGenerations.set(projectId, next);
    return next;
  }

  isStale(projectId, generation) {
    return this.currentGeneration(projectId) !== generation;
  }

  async closeServer(server) {
    if (!server) return;
    try {
      if (typeof server.closeAllConnections === 'function') {
        server.closeAllConnections();
      }
    } catch (e) {}
    await new Promise((/** @type {(value?: void) => void} */ resolve) => {
      let done = false;
      const finish = () => { if (!done) { done = true; resolve(); } };
      try { server.close(finish); } catch (e) { return finish(); }
      const t = setTimeout(finish, 2000);
      if (t.unref) t.unref();
    });
  }

  /** Detecta qué runtime ejecutable existe en un directorio concreto. */
  detectRuntimeInDir(dir) {
    if (!dir || !fs.existsSync(dir)) return null;
    if (fs.existsSync(path.join(dir, 'artisan')) || fs.existsSync(path.join(dir, 'composer.json')) || fs.existsSync(path.join(dir, 'index.php')) || fs.existsSync(path.join(dir, 'public', 'index.php'))) {
      return { type: 'php', path: dir, framework: fs.existsSync(path.join(dir, 'artisan')) ? 'laravel' : 'php' };
    }
    if (fs.existsSync(path.join(dir, 'package.json'))) {
      return { type: 'node', path: dir };
    }
    if (
      fs.existsSync(path.join(dir, 'manage.py')) ||
      fs.existsSync(path.join(dir, 'pyproject.toml')) ||
      fs.existsSync(path.join(dir, 'requirements.txt')) ||
      fs.existsSync(path.join(dir, 'main.py')) ||
      fs.existsSync(path.join(dir, 'app.py'))
    ) {
      return { type: 'python', path: dir };
    }
    if (fs.existsSync(path.join(dir, 'go.mod')) || fs.existsSync(path.join(dir, 'main.go'))) {
      return { type: 'go', path: dir };
    }
    if (
      fs.existsSync(path.join(dir, 'index.html')) ||
      fs.existsSync(path.join(dir, 'public', 'index.html')) ||
      fs.existsSync(path.join(dir, 'dist', 'index.html'))
    ) {
      return { type: 'static', path: dir };
    }
    return null;
  }

  /** Comprueba si un directorio no tiene ningún fichero relevante (ignorando .git). */
  isDirectoryEmpty(dir) {
    try {
      if (!fs.existsSync(dir)) return true;
      const entries = fs.readdirSync(dir).filter((e) => e !== '.git' && e !== '.DS_Store');
      return entries.length === 0;
    } catch (e) {
      return true;
    }
  }

  /**
   * Intelligently resolve the runnable directory of a project.
   * Supports: custom startCommand, preferredBaseDir, root, common subdirs & monorepo apps/*,
   * and Node, PHP/Laravel, Python, Go, Static HTML and Dockerfile.
   * @param {string} projectDir
   * @param {string | null | undefined} [preferredBaseDir]
   * @param {any} [project]
   */
  resolveRunnableDirectory(projectDir, preferredBaseDir = null, project = null) {
    if (!fs.existsSync(projectDir)) return { type: 'none', path: projectDir };

    // 1. Resolve preferredBaseDir first if configured
    /** @type {string | null} */
    let customBasePath = null;
    if (preferredBaseDir && preferredBaseDir !== '/') {
      const cleanBase = String(preferredBaseDir).replace(/^\/+/, '').replace(/\/+$/, '');
      if (cleanBase && !cleanBase.includes('\0') && !cleanBase.split(/[\\/]+/).includes('..')) {
        try {
          const candidate = assertContainedPath(projectDir, cleanBase);
          if (fs.existsSync(candidate)) customBasePath = candidate;
        } catch (e) {}
      }
    }

    // 1b. Explicit user startCommand takes precedence when code directory exists
    if (project?.startCommand && String(project.startCommand).trim() && !this.isDirectoryEmpty(customBasePath || projectDir)) {
      return { type: 'custom', path: customBasePath || projectDir, startCommand: String(project.startCommand).trim() };
    }

    if (customBasePath) {
      const hit = this.detectRuntimeInDir(customBasePath);
      if (hit) return hit;
    }

    // 2. Check root
    const rootHit = this.detectRuntimeInDir(projectDir);
    if (rootHit) return rootHit;

    // 3. Check common subdirectories for fullstack / monorepos
    const candidateDirs = ['backend', 'server', 'web', 'frontend', 'app', 'client', 'src'];
    for (const sub of candidateDirs) {
      const subPath = path.join(projectDir, sub);
      const hit = this.detectRuntimeInDir(subPath);
      if (hit) return hit;
    }

    // 3b. Check monorepo apps/* or packages/*
    for (const group of ['apps', 'services']) {
      const groupDir = path.join(projectDir, group);
      if (fs.existsSync(groupDir) && fs.statSync(groupDir).isDirectory()) {
        try {
          for (const child of fs.readdirSync(groupDir).sort()) {
            const hit = this.detectRuntimeInDir(path.join(groupDir, child));
            if (hit) return hit;
          }
        } catch (e) {}
      }
    }

    // 4. Check for Dockerfile
    if (fs.existsSync(path.join(projectDir, 'Dockerfile'))) {
      return { type: 'docker', path: projectDir };
    }

    return { type: 'unknown', path: projectDir };
  }

  /**
   * Safely clean a directory on Windows handling read-only git files
   */
  cleanDirectory(dir) {
    if (!fs.existsSync(dir)) return;
    try {
      if (process.platform === 'win32') {
        // Git deja los objetos del paquete en sólo-lectura y `fs.rmSync` falla
        // con EPERM. `attrib` los libera. Va por argv (`execFileSync`): `dir`
        // es una ruta derivada del id del proyecto y nunca debe poder cerrar
        // unas comillas dentro de un comando.
        try {
          execFileSync('attrib', ['-r', '-s', '-h', path.join(dir, '*'), '/s', '/d'], {
            stdio: 'ignore', timeout: 5000, windowsHide: true, shell: false
          });
        } catch(e) {}
      }
      if (fs.existsSync(dir)) {
        // Antes había aquí un `rmdir /s /q` por cmd.exe. `fs.rmSync` con
        // reintentos hace lo mismo sin shell: los reintentos cubren el EBUSY
        // transitorio de Windows cuando un antivirus o un proceso recién
        // muerto todavía tiene un handle abierto.
        fs.rmSync(dir, { recursive: true, force: true, maxRetries: 8, retryDelay: 150 });
      }
    } catch(e) {
      console.warn(`[LocalRunner] Warning cleaning ${dir}:`, e.message);
    }
  }

  /**
   * The port the daemon itself listens on. Nothing here may ever touch it.
   */
  daemonPort() {
    const port = parseInt(process.env.PORT || '3030', 10);
    return isNaN(port) ? 3030 : port;
  }

  /**
   * Ensure port is free by killing any lingering zombie process on that port
   *
   * Refuses to touch the daemon's own port. `start-local` assigns unset project
   * ports with `Math.random()` over 3000-9000, which includes 3030: when that
   * came up, getAvailablePort() called this and Culkibo killed its own control
   * plane. The in-process guard below (`pid !== process.pid`) does not catch it,
   * because a daemon started separately from the caller is a different process —
   * which is exactly the normal deployment shape.
   */
  async killProcessOnPort(port) {
    if (!port) return;
    const numPort = parseInt(port, 10);
    if (isNaN(numPort) || numPort < 1024 || numPort > 65535) return;
    if (numPort === this.daemonPort() || RESERVED_PORTS.has(numPort)) {
      console.warn(`[LocalRunner] Se ignora la petición de liberar el puerto reservado ${numPort}`);
      return;
    }
    // Nunca matar el puerto de otro runner activo ni un puerto reservado por deploy/catálogo/BD.
    for (const runner of this.activeRunners.values()) {
      if (runner && runner.port === numPort) return;
    }
    if (portRegistry.isProtectedPort(numPort, 'localRunner')) {
      console.warn(`[LocalRunner] Se ignora la petición de liberar el puerto ${numPort} (protegido por portRegistry)`);
      return;
    }

    try {
      if (process.platform === 'win32') {
        const pids = new Set();

        // 1. Query via PowerShell Get-NetTCPConnection.
        //    `execFileSync` lanza powershell.exe directamente: no hay cmd.exe
        //    de por medio. El script sí es texto, pero lo único que se
        //    interpola es `numPort`, ya normalizado a entero por el parseInt de
        //    arriba, así que no hay nada que un llamante pueda inyectar.
        try {
          const psOut = execFileSync('powershell', [
            '-NoProfile', '-NonInteractive', '-Command',
            `(Get-NetTCPConnection -LocalPort ${numPort} -ErrorAction SilentlyContinue).OwningProcess`
          ], { timeout: 3000, windowsHide: true, shell: false }).toString().trim();
          psOut.split(/\r?\n/).forEach(s => {
            const p = parseInt(s.trim(), 10);
            if (!isNaN(p) && p > 4 && p !== process.pid) pids.add(p);
          });
        } catch(e) {}

        // 2. Fallback via netstat
        try {
          const netstatOut = execFileSync('netstat', ['-ano'], { timeout: 3000, windowsHide: true, shell: false }).toString().trim();
          netstatOut.split(/\r?\n/).forEach(line => {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 4) {
              const localAddr = parts[1] || '';
              if (localAddr.endsWith(`:${numPort}`) || localAddr.endsWith(`]:${numPort}`)) {
                const pid = parseInt(parts[parts.length - 1], 10);
                if (!isNaN(pid) && pid > 4 && pid !== process.pid) pids.add(pid);
              }
            }
          });
        } catch(e) {}

        for (const pid of pids) {
          try {
            execFileSync('taskkill', ['/pid', String(pid), '/T', '/F'], {
              timeout: 4000, stdio: 'ignore', windowsHide: true, shell: false
            });
            console.log(`[LocalRunner] Killed process ${pid} on port ${numPort}`);
          } catch(e) {}
        }
      } else {
        const pids = new Set();

        // lsof is not installed on minimal Debian/Ubuntu VPS images, which is
        // exactly where Culkibo is deployed. Try lsof, then ss, then fuser.
        //
        // Antes esto era una lista de cadenas ejecutadas con `shell: '/bin/sh'`
        // —incluido un `2>/dev/null` que obligaba a tener shell—. Ahora cada
        // sonda es un argv y la redirección de stderr se hace con `stdio`.
        const probes = [
          { bin: 'lsof', args: ['-ti', `tcp:${numPort}`] },
          { bin: 'ss', args: ['-lptnH', `sport = :${numPort}`] },
          { bin: 'fuser', args: [`${numPort}/tcp`] }
        ];
        for (const probe of probes) {
          try {
            const out = execFileSync(probe.bin, probe.args, {
              timeout: 3000,
              shell: false,
              stdio: ['ignore', 'pipe', 'ignore']
            }).toString();
            // ss prints users:(("node",pid=1234,fd=23)); lsof/fuser print bare pids.
            const matches = out.match(/pid=(\d+)/g) || [];
            matches.forEach(m => pids.add(parseInt(m.slice(4), 10)));
            if (matches.length === 0) {
              out.split(/\s+/).forEach(tok => {
                const p = parseInt(tok, 10);
                if (!isNaN(p) && p > 1 && String(p) === tok.trim()) pids.add(p);
              });
            }
            if (pids.size > 0) break;
          } catch (e) {}
        }

        for (const pid of pids) {
          if (!pid || pid === process.pid || pid <= 1) continue;
          // Kill the whole process group first (dev servers fork workers), then
          // the pid itself in case it was never a group leader.
          try { process.kill(-pid, 'SIGKILL'); } catch (e) {}
          try { process.kill(pid, 'SIGKILL'); } catch (e) {}
        }
      }
    } catch(e) {}
  }

  /**
   * Find an available port starting from desiredPort (never kills unknown host processes).
   */
  async getAvailablePort(desiredPort) {
    const reservedActive = portRegistry.getAllReservedPorts();
    for (const r of this.activeRunners.values()) {
      if (r && r.port) reservedActive.add(Number(r.port));
    }
    const isPortFree = (port) => new Promise((resolve) => {
      const tester = net.createServer()
        .once('error', () => resolve(false))
        .once('listening', () => {
          tester.once('close', () => resolve(true)).close();
        })
        .listen(port, '0.0.0.0');
    });

    let port = Math.max(1024, parseInt(String(desiredPort || 3001), 10) || 3001);
    while (port < 65535) {
      if (port !== this.daemonPort() && !RESERVED_PORTS.has(port) && !reservedActive.has(port) && await isPortFree(port)) {
        return port;
      }
      port++;
    }
    throw new Error('No se encontró ningún puerto libre disponible en el host');
  }

  /**
   * Start a project locally
   */
  async start(project, opts = {}) {
    if (!project || !project.id) throw new Error('Proyecto inválido');

    // P1-13: bucle `while` (no `if`) para serializar >=3 llamadas concurrentes
    while (this.startLocks.has(project.id)) {
      try { await this.startLocks.get(project.id); } catch (e) {}
    }

    const task = this._startInternal(project, opts).finally(() => {
      if (this.startLocks.get(project.id) === task) {
        this.startLocks.delete(project.id);
      }
    });
    this.startLocks.set(project.id, task);
    return task;
  }

  async _startInternal(project, { justCloned = false } = {}) {
    await this.stop(project.id);

    const port = await this.getAvailablePort(project.localPort || project.forgePort || 3001);
    project.localPort = port;
    project.localRunning = true;

    const projectDir = this.resolveProjectDir(project);
    const resolved = this.resolveRunnableDirectory(projectDir, project.baseDirectory, project);

    // Case 0: Explicit user startCommand
    if (resolved.type === 'custom' && resolved.startCommand) {
      return this.startCustomCommandProject(project, resolved.path, port, resolved.startCommand);
    }

    // Case 1: PHP / Laravel project
    if (resolved.type === 'php') {
      if (this.checkCommand('php')) {
        return this.startPhpProject(project, resolved.path, port, resolved.framework);
      }
      return this.startPhpRequirementsServer(project, resolved.path, port);
    }

    // Case 2: Node / Next.js / Vite / Express / Nest / Astro
    if (resolved.type === 'node') {
      return this.startNodeProject(project, resolved.path, port, projectDir);
    }

    // Case 3: Python (Django / FastAPI / Flask / script)
    if (resolved.type === 'python') {
      return this.startPythonProject(project, resolved.path, port);
    }

    // Case 4: Go
    if (resolved.type === 'go') {
      return this.startGoProject(project, resolved.path, port);
    }

    // Case 5: Static HTML / Frontend
    if (resolved.type === 'static') {
      return this.startStaticProject(project, resolved.path, port);
    }

    // Case 6: Only clone if directory does NOT exist or is empty (never loop on existing code/Dockerfile!)
    const gitUrl = this.extractProjectGitUrl(project);
    const shouldClone = Boolean(gitUrl) && !justCloned && (!fs.existsSync(projectDir) || this.isDirectoryEmpty(projectDir));
    if (shouldClone) {
      return this.cloneAndStartProject(project, projectDir, gitUrl, port);
    }

    // Case 7: Dockerfile-only or unrecognized local code -> informative fallback (never deletes existing code)
    return this.startFallbackServer(project, projectDir, port, resolved.type);
  }

  /**
   * Check if a CLI command exists on the machine
   */
  checkCommand(cmd) {
    try {
      execFileSync(process.platform === 'win32' ? 'where' : 'which', [String(cmd)], {
        stdio: 'ignore', timeout: 5000, windowsHide: true, shell: false
      });
      return true;
    } catch(e) {
      return false;
    }
  }

  /** Detecta el gestor de paquetes JS más adecuado según lockfiles en el directorio o la raíz del monorepo. */
  detectPackageManager(cwd, rootDir = cwd) {
    const dirs = rootDir && rootDir !== cwd ? [cwd, rootDir] : [cwd];
    for (const dir of dirs) {
      if (fs.existsSync(path.join(dir, 'pnpm-lock.yaml')) && this.checkCommand('pnpm')) return 'pnpm';
      if ((fs.existsSync(path.join(dir, 'bun.lockb')) || fs.existsSync(path.join(dir, 'bun.lock'))) && this.checkCommand('bun')) return 'bun';
      if (fs.existsSync(path.join(dir, 'yarn.lock')) && this.checkCommand('yarn')) return 'yarn';
    }
    return 'npm';
  }

  /** Comprueba si existe node_modules en `cwd` o elevado (hoisted) en el monorepo hasta `rootDir`. */
  hasNodeModules(cwd, rootDir = cwd) {
    let cur = path.resolve(cwd);
    const stopAt = path.resolve(rootDir || cwd);
    for (let i = 0; i < 6; i++) {
      if (fs.existsSync(path.join(cur, 'node_modules'))) return true;
      if (cur === stopAt) break;
      const parent = path.dirname(cur);
      if (parent === cur) break;
      cur = parent;
    }
    return false;
  }

  /**
   * Instala dependencias JS (`pnpm`/`yarn`/`bun`/`npm`) sin shell, haciendo streaming de progreso a LiveLogs.
   */
  npmInstall(cwd, { timeout = 300000, rootDir = cwd, projectId = null, project = null } = {}) {
    const pm = this.detectPackageManager(cwd, rootDir);
    const installArgs = pm === 'npm'
      ? ['install', '--prefer-offline', '--no-audit']
      : (pm === 'pnpm' ? ['install'] : (pm === 'bun' ? ['install'] : ['install']));

    return new Promise((resolve) => {
      let child;
      try {
        child = spawnTool(pm, installArgs, {
          cwd,
          env: buildSafeChildEnv(),
          windowsHide: true,
          stdio: ['ignore', 'pipe', 'pipe']
        });
      } catch (err) {
        return resolve({ ok: false, pm, error: err.message });
      }

      const tail = [];
      const pushLine = (level, text) => {
        const clean = this.redactProjectSecrets(stripAnsi(text), project).trim();
        if (!clean) return;
        tail.push(clean);
        if (tail.length > 80) tail.shift();
        if (containerOrchestrator && projectId) {
          containerOrchestrator.addLog(level, 'forge', clean, new Date(), projectId);
        }
      };

      child.stdout.on('data', (d) => pushLine('INFO', d.toString()));
      child.stderr.on('data', (d) => pushLine('WARN', d.toString()));

      const timer = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch (e) {}
      }, timeout);
      if (timer.unref) timer.unref();

      child.on('error', (err) => {
        clearTimeout(timer);
        resolve({ ok: false, pm, error: err.message });
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        if (code === 0) return resolve({ ok: true, pm });
        resolve({ ok: false, pm, error: tail.slice(-25).join('\n').trim() || `${pm} install terminó con código ${code}` });
      });
    });
  }

  /**
   * Espera de forma real a que el puerto TCP acepte conexiones (o a que el proceso muera antes).
   * @param {number} port
   * @param {{ child?: import('child_process').ChildProcess | null, timeoutMs?: number }} [opts]
   */
  waitForPortReady(port, { child = null, timeoutMs = 8000 } = {}) {
    return new Promise((resolve) => {
      const deadline = Date.now() + timeoutMs;
      let done = false;
      const finish = (ready) => {
        if (done) return;
        done = true;
        resolve(ready);
      };

      if (child) {
        child.once('close', () => finish(false));
      }

      const probe = () => {
        if (done) return;
        const sock = net.createConnection({ host: '127.0.0.1', port });
        sock.setTimeout(350);
        sock.once('connect', () => {
          sock.destroy();
          finish(true);
        });
        const retry = () => {
          sock.destroy();
          if (done) return;
          if (Date.now() >= deadline) return finish(false);
          const t = setTimeout(probe, 180);
          if (t.unref) t.unref();
        };
        sock.once('error', retry);
        sock.once('timeout', retry);
      };
      probe();
    });
  }

  /**
   * Arranca y monitoriza un proceso de desarrollo local (Node, PHP, Python, Go o comando personalizado)
   * con captura combinada stdout/stderr redactada, detección de cierre y página de diagnóstico HTTP 503.
   */
  async spawnManagedProcess(project, projectDir, port, { cmd, args, runtime = 'process', extraEnv = {} }) {
    console.log(`[LocalRunner] Starting ${runtime} for ${project.name}: ${cmd} ${args.join(' ')} on port ${port} (cwd: ${projectDir})`);

    const env = this.resolveLocalEnv(project, port, extraEnv);
    const isWin = process.platform === 'win32';
    const child = spawnTool(cmd, args, {
      cwd: projectDir,
      env,
      detached: !isWin,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    child.on('error', (err) => {
      const safe = this.redactProjectSecrets(err.message, project);
      console.error(`[LocalRunner] Spawn error for ${project.name}:`, safe);
      if (containerOrchestrator) {
        containerOrchestrator.addLog('ERROR', 'forge', `Error al lanzar el proceso: ${safe}`, new Date(), project.id);
      }
    });

    const outputTail = [];
    const spawnTime = Date.now();
    const recordChunk = (level, data) => {
      const lines = stripAnsi(data.toString()).split(/\r?\n/);
      for (const raw of lines) {
        const line = this.redactProjectSecrets(raw, project).trim();
        if (!line) continue;
        outputTail.push(line);
        if (outputTail.length > 40) outputTail.shift();
        if (containerOrchestrator) {
          containerOrchestrator.addLog(level, 'forge', line, new Date(), project.id);
        }
      }
    };

    if (child.stdout) child.stdout.on('data', (d) => recordChunk('INFO', d));
    if (child.stderr) child.stderr.on('data', (d) => recordChunk('WARN', d));

    const generation = this.currentGeneration(project.id);

    child.on('close', async (code) => {
      console.log(`[LocalRunner] Process for ${project.name} exited with code ${code}`);
      if (this.activeRunners.get(project.id)?.child === child) {
        this.activeRunners.delete(project.id);
      }

      if (this.isStale(project.id, generation)) return;

      const lifetime = Date.now() - spawnTime;
      if (code !== 0 && lifetime < 30000) {
        console.warn(`[LocalRunner] Early crash detected for ${project.name} (${lifetime}ms). Activating diagnostics fallback on port ${port}...`);
        const details = outputTail.join('\n') || `El proceso finalizó inesperadamente con código de salida ${code}`;
        alert({
          event: 'service_down',
          level: 'error',
          title: 'Servicio local caído',
          message: `El proceso local (${runtime}) terminó con código ${code} a los ${lifetime} ms.\n\n${details.slice(0, 600)}`,
          projectId: project.id,
          projectName: project.name,
          url: `http://localhost:${port}`
        });
        await this.startCrashDiagnosticsServer(project, projectDir, port, details, generation);
        return;
      }

      // Sincronizar estado localRunning = false en ProjectManager si el proceso se cerró inesperadamente
      project.localRunning = false;
      try {
        const pm = getProjectManager();
        if (pm && typeof pm.update === 'function') {
          pm.update(project.id, { localRunning: false });
        }
      } catch (e) {}
    });

    this.activeRunners.set(project.id, {
      type: 'process',
      runtime,
      child,
      port,
      projectDir,
      startTime: Date.now()
    });

    const ready = await this.waitForPortReady(port, { child, timeoutMs: 8000 });
    return { port, success: true, ready, type: 'real_process', runtime };
  }

  /**
   * Start a real Node / Next.js / Vite / Express development server
   */
  async startNodeProject(project, projectDir, port, rootDir = projectDir) {
    if (!this.hasNodeModules(projectDir, rootDir)) {
      console.log(`[LocalRunner] node_modules missing for ${project.name}. Starting dependency installer...`);
      return this.installDepsAndStart(project, projectDir, port, rootDir);
    }

    return this.spawnNodeDevProcess(project, projectDir, port, rootDir);
  }

  /**
   * Serve a loading page while installing dependencies, then spawn the real process
   */
  async installDepsAndStart(project, projectDir, port, rootDir = projectDir) {
    /** @type {http.Server} */
    let tempServer;
    const pm = this.detectPackageManager(projectDir, rootDir);
    let statusMessage = `Instalando dependencias necesarias (${pm} install)...`;
    let isError = false;

    tempServer = http.createServer((req, res) => {
      const reqUrl = String(req.url || '/');
      if (isError && reqUrl.includes('retry=1')) {
        res.writeHead(302, { Location: '/' });
        res.end();
        setImmediate(async () => {
          await this.closeServer(tempServer);
          this.activeRunners.delete(project.id);
          await this.start(project).catch(() => {});
        });
        return;
      }
      const dPort = this.daemonPort();
      res.writeHead(isError ? 503 : 200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>${isError ? 'Error al instalar' : 'Instalando dependencias'} — ${escapeHtml(project.name)}</title>
  <style>${OFFLINE_PAGE_CSS}</style>
</head>
<body>
  <div class="card">
    <h1>${isError ? `No se pudo iniciar ${escapeHtml(project.name)}` : `Instalando ${escapeHtml(project.name)}`}</h1>
    <span class="pill ${isError ? 'err' : 'warn'}">${isError ? 'Error de instalación' : 'Instalando dependencias'}</span>
    <p>${isError ? `Falló la instalación de dependencias (${escapeHtml(pm)} install) antes de arrancar el servidor local.` : `Instalando paquetes (${escapeHtml(pm)} install). Esta página se actualizará automáticamente al terminar.`}</p>
    ${isError
      ? `<details open><summary>Detalle técnico</summary><pre>${escapeHtml(statusMessage)}</pre></details>
         <div class="actions">
           <a href="/?retry=1" class="btn">Reintentar</a>
           <a href="http://localhost:${dPort}/#/projects/${encodeURIComponent(project.id)}" class="btn-ghost">Abrir proyecto en Culkibo</a>
         </div>`
      : `<pre>${escapeHtml(statusMessage)}</pre><script>setTimeout(() => window.location.reload(), 4000);</script>`}
    <div class="foot">
      <span>Culkibo Local Runner</span>
      <a href="http://localhost:${dPort}" style="color:#18181b;font-weight:600;text-decoration:none;">Volver a Culkibo &rarr;</a>
    </div>
  </div>
</body>
</html>`);
    });

    await new Promise((/** @type {(value?: void) => void} */ resolve, reject) => {
      tempServer.once('error', reject);
      tempServer.listen(port, '0.0.0.0', () => resolve());
    });

    this.activeRunners.set(project.id, {
      type: 'temporary_loading',
      server: tempServer,
      port,
      projectDir,
      startTime: Date.now()
    });

    const generation = this.currentGeneration(project.id);

    (async () => {
      try {
        if (containerOrchestrator) {
          containerOrchestrator.addLog('INFO', 'forge', `Instalando dependencias (${pm} install) para ${project.name}...`, new Date(), project.id);
        }
        const install = await this.npmInstall(projectDir, { timeout: 300000, rootDir, projectId: project.id, project });
        if (!install.ok) throw new Error(install.error);

        if (this.isStale(project.id, generation)) {
          await this.closeServer(tempServer);
          return;
        }

        await this.closeServer(tempServer);
        this.activeRunners.delete(project.id);
        await this.spawnNodeDevProcess(project, projectDir, port, rootDir);
      } catch (err) {
        const safeErr = this.redactProjectSecrets(err.message, project);
        console.error(`[LocalRunner] Dependency install failed for ${project.name}:`, safeErr);
        isError = true;
        statusMessage = `Error al instalar dependencias: ${safeErr}`;
        alert({
          event: 'deploy_failed',
          level: 'error',
          title: 'Fallo al instalar dependencias',
          message: `${pm} install falló para ${project.name}.\n\n${safeErr.slice(0, 600)}`,
          projectId: project.id,
          projectName: project.name
        });
      }
    })();

    return { port, success: true, type: 'installing_deps' };
  }

  /** Resuelve binario local en `node_modules/.bin` si existe (más rápido y 100% offline). */
  resolveLocalNodeBin(projectDir, rootDir, binName) {
    const ext = process.platform === 'win32' ? '.cmd' : '';
    const dirs = rootDir && rootDir !== projectDir ? [projectDir, rootDir] : [projectDir];
    for (const d of dirs) {
      const candidate = path.join(d, 'node_modules', '.bin', `${binName}${ext}`);
      if (fs.existsSync(candidate)) return candidate;
    }
    return null;
  }

  /**
   * Spawn native Node/Next/Vite/Express dev server process with crash recovery and live logs
   */
  async spawnNodeDevProcess(project, projectDir, port, rootDir = projectDir) {
    let pkg = {};
    try {
      pkg = JSON.parse(fs.readFileSync(path.join(projectDir, 'package.json'), 'utf8'));
    } catch(e) {}

    const scripts = pkg.scripts || {};
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    const pm = this.detectPackageManager(projectDir, rootDir);
    const devScript = String(scripts['dev'] || '');

    let cmd = pm;
    let args = ['run', 'dev'];

    if (deps['next'] || /\bnext\s+dev\b/.test(devScript)) {
      const localNext = this.resolveLocalNodeBin(projectDir, rootDir, 'next');
      cmd = localNext || 'npx';
      args = localNext ? ['dev', '-H', '0.0.0.0', '-p', String(port)] : ['next', 'dev', '-H', '0.0.0.0', '-p', String(port)];
    } else if (/\bvite\b/.test(devScript) && !/\bconcurrently\b|\b&&\b/.test(devScript)) {
      const localVite = this.resolveLocalNodeBin(projectDir, rootDir, 'vite');
      cmd = localVite || 'npx';
      args = localVite
        ? ['--port', String(port), '--host', '0.0.0.0', '--strictPort']
        : ['vite', '--port', String(port), '--host', '0.0.0.0', '--strictPort'];
    } else if (deps['vite'] && !scripts['dev'] && !scripts['start']) {
      const localVite = this.resolveLocalNodeBin(projectDir, rootDir, 'vite');
      cmd = localVite || 'npx';
      args = localVite
        ? ['--port', String(port), '--host', '0.0.0.0', '--strictPort']
        : ['vite', '--port', String(port), '--host', '0.0.0.0', '--strictPort'];
    } else if (scripts['dev']) {
      // No pasar `-- -p <port>` a ciegas: muchos scripts (Express, Fastify, Nest, tsx) leen PORT del env y fallan con `-p`.
      cmd = pm;
      args = ['run', 'dev'];
    } else if (scripts['start']) {
      cmd = pm;
      args = ['run', 'start'];
    } else if (pkg.main) {
      /** @type {string | null} */
      let safeMain = null;
      try {
        safeMain = assertContainedPath(projectDir, String(pkg.main));
      } catch (e) {
        safeMain = null;
      }
      if (safeMain && fs.existsSync(safeMain)) {
        cmd = 'node';
        args = [path.relative(projectDir, safeMain)];
      }
    }

    return this.spawnManagedProcess(project, projectDir, port, { cmd, args, runtime: 'node' });
  }

  /** Ejecuta un comando de inicio personalizado definido por el usuario (sin shell). */
  async startCustomCommandProject(project, projectDir, port, startCommand) {
    const argv = parseSafeCommandArgv(startCommand);
    const [cmd, ...args] = argv;
    return this.spawnManagedProcess(project, projectDir, port, { cmd, args, runtime: 'custom' });
  }

  /** Ejecuta PHP o Laravel directamente en local cuando `php` está instalado en el sistema. */
  async startPhpProject(project, projectDir, port, framework = 'php') {
    if (framework === 'laravel' && fs.existsSync(path.join(projectDir, 'artisan'))) {
      return this.spawnManagedProcess(project, projectDir, port, {
        cmd: 'php',
        args: ['artisan', 'serve', '--host=0.0.0.0', `--port=${port}`],
        runtime: 'php-laravel'
      });
    }
    const docRoot = fs.existsSync(path.join(projectDir, 'public')) ? 'public' : '.';
    return this.spawnManagedProcess(project, projectDir, port, {
      cmd: 'php',
      args: ['-S', `0.0.0.0:${port}`, '-t', docRoot],
      runtime: 'php'
    });
  }

  /** Ejecuta proyectos Python (Django, FastAPI/Uvicorn, Flask o script directo) buscando `.venv` o `python3`/`python`. */
  async startPythonProject(project, projectDir, port) {
    const isWin = process.platform === 'win32';
    const venvCandidates = [
      path.join(projectDir, '.venv', isWin ? 'Scripts' : 'bin', isWin ? 'python.exe' : 'python'),
      path.join(projectDir, 'venv', isWin ? 'Scripts' : 'bin', isWin ? 'python.exe' : 'python')
    ];
    let pyBin = venvCandidates.find((p) => fs.existsSync(p)) || null;
    if (!pyBin) {
      if (this.checkCommand('python3')) pyBin = 'python3';
      else if (this.checkCommand('python')) pyBin = 'python';
    }
    if (!pyBin) {
      return this.startRuntimeRequirementsServer(project, projectDir, port, {
        label: 'Aplicación Python',
        binary: 'Python 3',
        detail: 'Este proyecto es una aplicación Python. Para ejecutarlo en local instala Python 3 (o crea un entorno .venv), o bien inicia Docker Desktop para desplegarlo en contenedor.'
      });
    }

    if (fs.existsSync(path.join(projectDir, 'manage.py'))) {
      return this.spawnManagedProcess(project, projectDir, port, {
        cmd: pyBin,
        args: ['manage.py', 'runserver', `0.0.0.0:${port}`],
        runtime: 'python-django'
      });
    }

    const reqText = fs.existsSync(path.join(projectDir, 'requirements.txt'))
      ? fs.readFileSync(path.join(projectDir, 'requirements.txt'), 'utf8').toLowerCase()
      : '';
    const pyprojText = fs.existsSync(path.join(projectDir, 'pyproject.toml'))
      ? fs.readFileSync(path.join(projectDir, 'pyproject.toml'), 'utf8').toLowerCase()
      : '';
    const combined = `${reqText}\n${pyprojText}`;

    if ((combined.includes('fastapi') || combined.includes('uvicorn')) && (fs.existsSync(path.join(projectDir, 'main.py')) || fs.existsSync(path.join(projectDir, 'app.py')))) {
      const mod = fs.existsSync(path.join(projectDir, 'main.py')) ? 'main:app' : 'app:app';
      return this.spawnManagedProcess(project, projectDir, port, {
        cmd: pyBin,
        args: ['-m', 'uvicorn', mod, '--host', '0.0.0.0', '--port', String(port)],
        runtime: 'python-fastapi'
      });
    }

    if (combined.includes('flask')) {
      return this.spawnManagedProcess(project, projectDir, port, {
        cmd: pyBin,
        args: ['-m', 'flask', 'run', '--host=0.0.0.0', `--port=${port}`],
        runtime: 'python-flask'
      });
    }

    const entry = ['main.py', 'app.py', 'server.py'].find((f) => fs.existsSync(path.join(projectDir, f)));
    if (entry) {
      return this.spawnManagedProcess(project, projectDir, port, {
        cmd: pyBin,
        args: [entry],
        runtime: 'python'
      });
    }

    return this.startRuntimeRequirementsServer(project, projectDir, port, {
      label: 'Aplicación Python',
      binary: 'comando de inicio',
      detail: 'Se detectó un proyecto Python pero no un punto de entrada estándar (manage.py, main.py, app.py). Configura el «Comando de inicio» en Configuración del proyecto.'
    });
  }

  /** Ejecuta proyectos Go (`go run .`) cuando Go está instalado en el sistema. */
  async startGoProject(project, projectDir, port) {
    if (!this.checkCommand('go')) {
      return this.startRuntimeRequirementsServer(project, projectDir, port, {
        label: 'Aplicación Go',
        binary: 'Go',
        detail: 'Este proyecto es una aplicación Go. Para ejecutarlo en local instala Go en tu sistema, o inicia Docker Desktop para construir y ejecutar su contenedor.'
      });
    }
    return this.spawnManagedProcess(project, projectDir, port, {
      cmd: 'go',
      args: ['run', '.'],
      runtime: 'go'
    });
  }

  /** Página informativa limpia cuando falta un runtime nativo (Python/Go/etc.) en la máquina local. */
  async startRuntimeRequirementsServer(project, projectDir, port, { label, binary, detail }) {
    const dPort = this.daemonPort();
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>${escapeHtml(project.name)} — ${escapeHtml(label)}</title>
  <style>${OFFLINE_PAGE_CSS}</style>
</head>
<body>
  <div class="card">
    <h1>${escapeHtml(project.name)}</h1>
    <span class="pill warn">${escapeHtml(label)} · Requiere ${escapeHtml(binary)}</span>
    <p>${escapeHtml(detail)}</p>
    <div class="actions">
      <a href="http://localhost:${dPort}/#/projects/${encodeURIComponent(project.id)}" class="btn">Abrir proyecto en Culkibo</a>
    </div>
    <div class="foot">
      <span>Culkibo Local Runner</span>
      <a href="http://localhost:${dPort}" style="color:#18181b;font-weight:600;text-decoration:none;">Volver a Culkibo &rarr;</a>
    </div>
  </div>
</body>
</html>`);
    });

    return new Promise((resolve, reject) => {
      server.listen(port, '0.0.0.0', () => {
        this.activeRunners.set(project.id, {
          type: 'runtime_notice',
          server,
          port,
          projectDir,
          startTime: Date.now()
        });
        resolve({ port, success: true, type: 'runtime_notice' });
      });
      server.on('error', reject);
    });
  }

  /**
   * Diagnostic fallback server shown when a development process fails on boot (HTTP 503 + retry).
   */
  async startCrashDiagnosticsServer(project, projectDir, port, errorDetails, generation = null) {
    if (generation !== null && this.isStale(project.id, generation)) {
      return { port, success: false, stale: true };
    }
    await this.killProcessOnPort(port);
    if (generation !== null && this.isStale(project.id, generation)) {
      return { port, success: false, stale: true };
    }

    const dPort = this.daemonPort();
    const safeDetails = this.redactProjectSecrets(stripAnsi(errorDetails || 'Sin detalles de error reportados'), project);
    /** @type {http.Server} */
    let server;
    server = http.createServer((req, res) => {
      const reqUrl = String(req.url || '/');
      if (reqUrl.includes('retry=1')) {
        res.writeHead(302, { Location: '/' });
        res.end();
        setImmediate(async () => {
          await this.closeServer(server);
          this.activeRunners.delete(project.id);
          await this.start(project).catch(() => {});
        });
        return;
      }
      res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Error al iniciar — ${escapeHtml(project.name)}</title>
  <style>${OFFLINE_PAGE_CSS}</style>
</head>
<body>
  <div class="card">
    <h1>${escapeHtml(project.name)}</h1>
    <span class="pill err">El proceso local se detuvo (:${port})</span>
    <p>El servidor de desarrollo terminó de forma inesperada. Revisa la salida capturada o las variables de entorno del proyecto:</p>
    <pre>${escapeHtml(safeDetails)}</pre>
    <div class="actions">
      <a href="/?retry=1" class="btn">Reintentar</a>
      <a href="http://localhost:${dPort}/#/projects/${encodeURIComponent(project.id)}" class="btn-ghost">Ver proyecto en Culkibo</a>
    </div>
    <div class="foot">
      <span>Culkibo Local Runner</span>
      <a href="http://localhost:${dPort}" style="color:#18181b;font-weight:600;text-decoration:none;">Volver a Culkibo &rarr;</a>
    </div>
  </div>
</body>
</html>`);
    });

    return new Promise((resolve) => {
      server.listen(port, '0.0.0.0', () => {
        if (generation !== null && this.isStale(project.id, generation)) {
          try { server.close(); } catch (e) {}
          return resolve({ port, success: false, stale: true });
        }
        this.activeRunners.set(project.id, {
          type: 'crash_diagnostics',
          server,
          port,
          projectDir,
          startTime: Date.now()
        });
        resolve({ port, success: true, type: 'crash_diagnostics' });
      });
      server.on('error', () => resolve({ port, success: false }));
    });
  }

  /**
   * Diagnostic server for PHP / Laravel projects when PHP is not installed locally
   */
  async startPhpRequirementsServer(project, projectDir, port) {
    const dPort = this.daemonPort();
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>${escapeHtml(project.name)} — Aplicación PHP / Laravel</title>
  <style>${OFFLINE_PAGE_CSS}</style>
</head>
<body>
  <div class="card">
    <h1>${escapeHtml(project.name)}</h1>
    <span class="pill warn">Aplicación PHP / Laravel</span>
    <p>Este proyecto es una aplicación PHP/Laravel y no se detectó el binario <code>php</code> en tu PATH. Para ejecutarlo en local instala <strong>PHP</strong> o inicia <strong>Docker Desktop</strong> y despliega el contenedor.</p>
    <div class="actions">
      <a href="http://localhost:${dPort}/#/projects/${encodeURIComponent(project.id)}" class="btn">Abrir proyecto en Culkibo</a>
    </div>
    <div class="foot">
      <span>Culkibo Local Runner</span>
      <a href="http://localhost:${dPort}" style="color:#18181b;font-weight:600;text-decoration:none;">Volver a Culkibo &rarr;</a>
    </div>
  </div>
</body>
</html>`);
    });

    return new Promise((resolve, reject) => {
      server.listen(port, '0.0.0.0', () => {
        this.activeRunners.set(project.id, {
          type: 'php_notice',
          server,
          port,
          projectDir,
          startTime: Date.now()
        });
        resolve({ port, success: true, type: 'php_notice' });
      });
      server.on('error', reject);
    });
  }

  /**
   * Serve static files directly with full modern MIME types and Cache-Control: no-store
   */
  async startStaticProject(project, projectDir, port) {
    const publicDir = fs.existsSync(path.join(projectDir, 'public', 'index.html'))
      ? path.join(projectDir, 'public')
      : (fs.existsSync(path.join(projectDir, 'dist', 'index.html'))
        ? path.join(projectDir, 'dist')
        : projectDir);

    const rootDir = path.resolve(publicDir);
    const realRoot = fs.existsSync(rootDir) ? fs.realpathSync(rootDir) : rootDir;

    const mimeTypes = {
      '.html': 'text/html; charset=utf-8',
      '.htm': 'text/html; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.mjs': 'application/javascript; charset=utf-8',
      '.cjs': 'application/javascript; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.json': 'application/json; charset=utf-8',
      '.map': 'application/json; charset=utf-8',
      '.wasm': 'application/wasm',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.gif': 'image/gif',
      '.webp': 'image/webp',
      '.avif': 'image/avif',
      '.ico': 'image/x-icon',
      '.svg': 'image/svg+xml',
      '.woff': 'font/woff',
      '.woff2': 'font/woff2',
      '.ttf': 'font/ttf',
      '.otf': 'font/otf',
      '.mp4': 'video/mp4',
      '.webm': 'video/webm',
      '.mp3': 'audio/mpeg',
      '.txt': 'text/plain; charset=utf-8',
      '.xml': 'application/xml; charset=utf-8',
      '.pdf': 'application/pdf'
    };

    const streamFile = (targetPath, contentType, res) => {
      try {
        const realTarget = fs.realpathSync(targetPath);
        const rel = path.relative(realRoot, realTarget);
        if (rel.startsWith('..') || path.isAbsolute(rel)) {
          res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
          return res.end('403 Forbidden');
        }
      } catch (e) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('404 Not Found');
      }
      res.writeHead(200, { 'Content-Type': contentType, 'Cache-Control': 'no-store' });
      const rs = fs.createReadStream(targetPath);
      rs.on('error', () => {
        if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end();
      });
      return rs.pipe(res);
    };

    const server = http.createServer((req, res) => {
      let reqPath = (req.url || '/').split('?')[0].split('#')[0];
      try {
        reqPath = decodeURIComponent(reqPath);
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('400 Bad Request');
      }
      if (reqPath.includes('\0')) {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('400 Bad Request');
      }

      const filePath = path.resolve(rootDir, '.' + path.posix.normalize('/' + reqPath.replace(/\\/g, '/')));
      const relative = path.relative(rootDir, filePath);
      if (relative.startsWith('..') || path.isAbsolute(relative)) {
        res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('403 Forbidden');
      }

      if (reqPath !== '/' && fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        const ext = path.extname(filePath).toLowerCase();
        return streamFile(filePath, mimeTypes[ext] || 'application/octet-stream', res);
      }

      const fallbackIndex = path.join(publicDir, 'index.html');
      if (fs.existsSync(fallbackIndex)) {
        return streamFile(fallbackIndex, 'text/html; charset=utf-8', res);
      }

      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('404 Not Found');
    });

    return new Promise((resolve, reject) => {
      server.listen(port, '0.0.0.0', () => {
        console.log(`[LocalRunner] Static server for ${project.name} on http://localhost:${port}`);
        this.activeRunners.set(project.id, {
          type: 'static',
          server,
          port,
          projectDir,
          startTime: Date.now()
        });
        resolve({ port, success: true, type: 'static_server' });
      });

      server.on('error', reject);
    });
  }

  /**
   * Normalize Git URLs to authenticated or standard HTTPS format.
   * Rejects `file://`, local filesystem paths and SSRF metadata/private IPs.
   */
  normalizeGitUrl(rawUrl) {
    if (!rawUrl) return null;
    const url = String(rawUrl).trim();
    if (!url || /[\x00-\x1f\x7f\s]/.test(url)) return null;

    // The credential username is safe to embed: it is a fixed literal, not a
    // secret. Embedding it means git only ever prompts for the password, which
    // keeps the askpass helper trivial and portable. The token itself NEVER
    // appears here — see gitAuthEnv() for how it is supplied.
    const user = this.readGitToken() ? 'x-access-token@' : '';
    const gh = (owner, repo) => `https://${user}github.com/${owner}/${repo.replace(/\.git$/, '')}.git`;

    // "owner/repo" or "owner/repo.git"
    const slugMatch = url.match(/^([a-zA-Z0-9_-]+)\/([a-zA-Z0-9_.-]+)$/);
    if (slugMatch) return gh(slugMatch[1], slugMatch[2]);

    // git@github.com:owner/repo.git
    const sshMatch = url.match(/^git@github\.com:([a-zA-Z0-9_-]+)\/([a-zA-Z0-9_.-]+)$/);
    if (sshMatch) return gh(sshMatch[1], sshMatch[2]);

    // https://github.com/owner/repo(.git)?
    const httpMatch = url.match(/^https?:\/\/(?:[^@\s/]+@)?github\.com\/([a-zA-Z0-9_-]+)\/([a-zA-Z0-9_.-]+)$/);
    if (httpMatch) return gh(httpMatch[1], httpMatch[2]);

    // Reject file:// and local paths unless explicitly enabled for hermetic tests.
    if (/^file:/i.test(url) || /^[a-zA-Z]:[\\/]/.test(url) || url.startsWith('/') || url.startsWith('\\\\')) {
      if (process.env.CULKIBO_ALLOW_LOCAL_GIT === '1') return url;
      return null;
    }

    // Generic HTTPS/HTTP Git remotes (GitLab, Bitbucket, Gitea, self-hosted)
    if (/^https?:\/\//i.test(url)) {
      try {
        const parsed = new URL(url);
        const host = parsed.hostname.toLowerCase();
        if (host === 'localhost' || host.endsWith('.local') || isMetadataIp(host) || (net.isIP(host) && isPrivateIp(host))) {
          if (process.env.CULKIBO_ALLOW_LOCAL_GIT !== '1') return null;
        }
        return parsed.toString();
      } catch (e) {
        return null;
      }
    }

    // Standard SSH remote (git@gitlab.com:org/repo.git)
    if (/^git@[a-zA-Z0-9.-]+:[a-zA-Z0-9_./-]+$/.test(url)) {
      return url;
    }

    return null;
  }

  /** ¿Esta URL pertenece a github.com? Sólo a ella se le entrega el PAT de GitHub. */
  isGitHubRemote(cloneUrl) {
    if (!cloneUrl) return true; // Compatibilidad con llamadas sin URL (p.ej. tests heredados)
    try {
      const parsed = new URL(String(cloneUrl));
      return parsed.protocol === 'https:' && parsed.hostname.toLowerCase() === 'github.com';
    } catch (e) {
      return false;
    }
  }

  /** Read the stored GitHub PAT, or null (stat-cached). Never log or interpolate the result. */
  readGitToken() {
    try {
      const preferred = path.join(ROOT_BASE_DIR, 'data', 'github.json');
      const fallback = path.join(process.cwd(), 'data', 'github.json');
      const ghFile = fs.existsSync(preferred) ? preferred : fallback;
      const stat = fs.statSync(ghFile);
      if (this._gitTokenCache && this._gitTokenCache.mtimeMs === stat.mtimeMs) {
        return this._gitTokenCache.token;
      }
      const gh = JSON.parse(fs.readFileSync(ghFile, 'utf8'));
      const rawToken = gh.token || null;
      const token = rawToken && !/^ghp_mock_/i.test(String(rawToken)) ? rawToken : null;
      this._gitTokenCache = { mtimeMs: stat.mtimeMs, token };
      return token;
    } catch (e) {
      this._gitTokenCache = null;
      return null;
    }
  }

  /** @param {string | null} [cloneUrl] */
  gitAuthEnv(cloneUrl = null) {
    const token = this.isGitHubRemote(cloneUrl) ? this.readGitToken() : null;
    /** @type {Record<string, any>} */
    const env = { ...process.env, GIT_TERMINAL_PROMPT: '0' };

    env.GIT_CONFIG_COUNT = '1';
    env.GIT_CONFIG_KEY_0 = 'credential.helper';
    env.GIT_CONFIG_VALUE_0 = '';

    if (!token) return { env, cleanup: () => {} };

    const isWin = process.platform === 'win32';
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-git-'));
    const helper = path.join(dir, isWin ? 'askpass.cmd' : 'askpass.sh');

    fs.writeFileSync(
      helper,
      isWin
        ? '@echo off\r\nsetlocal EnableDelayedExpansion\r\necho(!CULKIBO_GIT_TOKEN!\r\n'
        : '#!/bin/sh\nprintf \'%s\' "$CULKIBO_GIT_TOKEN"\n',
      { mode: 0o700 }
    );

    env.GIT_ASKPASS = helper;
    env.CULKIBO_GIT_TOKEN = token;

    return {
      env,
      cleanup: () => {
        try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) {}
      }
    };
  }

  /**
   * Clone a repository without a shell.
   *
   * @param {string} cloneUrl
   * @param {string} targetDir
   * @param {{ timeout?: number, depth?: number | null, branch?: string | null, onLine?: ((line: string) => void) | null, useAuth?: boolean }} [opts]
   */
  async gitClone(cloneUrl, targetDir, { timeout = 180000, depth = null, branch = null, onLine = null, useAuth = true } = {}) {
    if (!cloneUrl || /^file:/i.test(cloneUrl) && process.env.CULKIBO_ALLOW_LOCAL_GIT !== '1') {
      throw new Error('URL de repositorio rechazada por política de seguridad');
    }
    const effectiveUrl = useAuth
      ? cloneUrl
      : String(cloneUrl).replace(/^https:\/\/x-access-token@github\.com\//i, 'https://github.com/');
    const willTryAuth = useAuth && this.isGitHubRemote(effectiveUrl) && Boolean(this.readGitToken());
    const { env, cleanup } = willTryAuth
      ? this.gitAuthEnv(effectiveUrl)
      : {
          env: {
            ...process.env,
            GIT_TERMINAL_PROMPT: '0',
            GIT_CONFIG_COUNT: '1',
            GIT_CONFIG_KEY_0: 'credential.helper',
            GIT_CONFIG_VALUE_0: ''
          },
          cleanup: () => {}
        };

    const args = ['clone', '--progress'];

    const depthNum = parseInt(String(depth ?? ''), 10);
    if (Number.isInteger(depthNum) && depthNum > 0) {
      args.push('--depth', String(depthNum), '--single-branch');
    }

    if (branch != null && branch !== '') {
      const name = String(branch);
      if (!/^[A-Za-z0-9._/-]+$/.test(name) || name.startsWith('-') || name.includes('..')) {
        cleanup();
        throw new Error(`Nombre de rama no válido: «${name}»`);
      }
      args.push('--branch', name);
    }

    args.push('--', effectiveUrl, targetDir);

    try {
      await new Promise((/** @type {(value?: void) => void} */ resolve, reject) => {
        const child = spawn('git', args, {
          env,
          shell: false,
          windowsHide: true
        });

        const stderr = [];
        let buffered = '';
        child.stderr.on('data', (d) => {
          const text = d.toString();
          stderr.push(text);
          if (stderr.length > 50) stderr.shift();
          if (!onLine) return;
          buffered += text;
          const lines = buffered.split(/[\r\n]+/);
          buffered = lines.pop() || '';
          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed) onLine(this.redactSecrets(trimmed));
          }
        });

        const timer = setTimeout(() => {
          try { child.kill('SIGKILL'); } catch (e) {}
        }, timeout);
        if (timer.unref) timer.unref();

        const finish = (err) => {
          clearTimeout(timer);
          cleanup();
          if (onLine && buffered.trim()) onLine(this.redactSecrets(buffered.trim()));
          if (err) reject(err); else resolve();
        };

        child.on('error', (err) => finish(err));
        child.on('close', (code) => {
          if (code === 0) return finish();
          finish(new Error(this.redactSecrets(stderr.join('').trim()) || `git clone terminó con código ${code}`));
        });
      });
    } catch (err) {
      if (willTryAuth && /invalid username or token|authentication failed|could not read username|403/i.test(String(err?.message || ''))) {
        this.cleanDirectory(targetDir);
        return this.gitClone(effectiveUrl, targetDir, { timeout, depth, branch, onLine, useAuth: false });
      }
      throw err;
    }
  }

  /** Strip anything that looks like a credential out of text bound for a log or UI. */
  redactSecrets(text) {
    const token = this.readGitToken();
    let out = String(text == null ? '' : text).replace(/(https?|ssh):\/\/[^@\s/]+@/gi, '$1://***@');
    if (token) out = out.split(token).join('***');
    return out;
  }

  /**
   * Clone repository and launch when ready
   */
  async cloneAndStartProject(project, projectDir, rawGitUrl, port) {
    if (this.cloningLocks.has(project.id)) {
      console.log(`[LocalRunner] Project ${project.name} is already cloning/preparing, returning existing task.`);
      return this.cloningLocks.get(project.id);
    }

    const cloneUrl = this.normalizeGitUrl(rawGitUrl);
    if (!cloneUrl) {
      throw new Error(`URL de repositorio Git inválida: ${rawGitUrl}`);
    }
    const displayUrl = this.redactSecrets(rawGitUrl);
    const generation = this.currentGeneration(project.id);

    /** @type {http.Server} */
    let tempServer;
    let statusMessage = `Clonando repositorio ${displayUrl}…`;
    let friendlyHint = '';
    let isError = false;

    tempServer = http.createServer((req, res) => {
      const reqUrl = String(req.url || '/');
      if (isError && reqUrl.includes('retry=1')) {
        res.writeHead(302, { Location: '/' });
        res.end();
        setImmediate(async () => {
          await this.closeServer(tempServer);
          this.activeRunners.delete(project.id);
          this.cloningLocks.delete(project.id);
          await this.start(project).catch(() => {});
        });
        return;
      }
      const dPort = this.daemonPort();
      res.writeHead(isError ? 503 : 200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>${isError ? 'Error al preparar' : 'Preparando'} ${escapeHtml(project.name)} — Culkibo</title>
  <style>${OFFLINE_PAGE_CSS}</style>
</head>
<body>
  <div class="card">
    <h1>${isError ? `No se pudo preparar ${escapeHtml(project.name)}` : `Preparando ${escapeHtml(project.name)}`}</h1>
    <span class="pill ${isError ? 'err' : 'warn'}">${isError ? 'Error al preparar proyecto' : 'Clonando e instalando en local'}</span>
    ${isError ? `
      <p>${escapeHtml(friendlyHint || explainGitError(statusMessage))}</p>
      <details open>
        <summary>Ver diagnóstico técnico</summary>
        <pre>${escapeHtml(statusMessage)}</pre>
      </details>
      <div class="actions">
        <a href="/?retry=1" class="btn">Reintentar</a>
        <a href="http://localhost:${dPort}/#/settings" class="btn-ghost">Revisar token GitHub</a>
        <a href="http://localhost:${dPort}/#/projects/${encodeURIComponent(project.id)}" class="btn-ghost">Ir al proyecto</a>
      </div>
    ` : `
      <p>Descargando el código desde <code>${escapeHtml(displayUrl)}</code>. Esta página se actualizará automáticamente en cuanto arranque el servidor local.</p>
      <pre>${escapeHtml(statusMessage)}</pre>
      <script>setTimeout(() => window.location.reload(), 3000);</script>
    `}
    <div class="foot">
      <span>Culkibo Local Runner</span>
      <a href="http://localhost:${dPort}" style="color:#18181b;font-weight:600;text-decoration:none;">Volver a Culkibo &rarr;</a>
    </div>
  </div>
</body>
</html>`);
    });

    await new Promise((/** @type {(value?: void) => void} */ resolve, reject) => {
      tempServer.once('error', reject);
      tempServer.listen(port, '0.0.0.0', () => resolve());
    });

    this.activeRunners.set(project.id, {
      type: 'temporary_loading',
      server: tempServer,
      port,
      projectDir,
      startTime: Date.now()
    });

    const clonePromise = (async () => {
      try {
        console.log(`[LocalRunner] Cloning ${displayUrl} into ${projectDir}`);
        if (containerOrchestrator) {
          containerOrchestrator.addLog('INFO', 'forge', `Clonando repositorio ${displayUrl} en local...`, new Date(), project.id);
        }

        const parentDir = path.dirname(projectDir);
        if (!fs.existsSync(parentDir)) {
          fs.mkdirSync(parentDir, { recursive: true });
        }

        this.cleanDirectory(projectDir);

        await this.gitClone(cloneUrl, projectDir, {
          timeout: 180000,
          branch: project.gitBranch || null,
          onLine: (line) => {
            statusMessage = line;
            if (containerOrchestrator) containerOrchestrator.addLog('INFO', 'forge', line, new Date(), project.id);
          }
        });

        const resolved = this.resolveRunnableDirectory(projectDir, project.baseDirectory, project);

        if (resolved.type === 'node' && !this.hasNodeModules(resolved.path, projectDir)) {
          const pm = this.detectPackageManager(resolved.path, projectDir);
          statusMessage = `Instalando dependencias (${pm} install) en ${path.relative(projectDir, resolved.path) || 'raíz'}...`;
          if (containerOrchestrator) {
            containerOrchestrator.addLog('INFO', 'forge', statusMessage, new Date(), project.id);
          }
          const install = await this.npmInstall(resolved.path, { timeout: 300000, rootDir: projectDir, projectId: project.id, project });
          if (!install.ok) {
            friendlyHint = `El repositorio se clonó correctamente, pero falló la instalación de dependencias (${pm} install).`;
            throw new Error(install.error || `${pm} install falló`);
          }
        }

        if (this.isStale(project.id, generation)) {
          await this.closeServer(tempServer);
          this.activeRunners.delete(project.id);
          this.cloningLocks.delete(project.id);
          if (containerOrchestrator) {
            containerOrchestrator.addLog('INFO', 'forge', `Preparación cancelada para ${project.name}: el proyecto fue detenido durante la clonación.`, new Date(), project.id);
          }
          return;
        }

        await this.closeServer(tempServer);
        this.activeRunners.delete(project.id);
        this.cloningLocks.delete(project.id);
        await this.start(project, { justCloned: true });
      } catch (err) {
        console.error(`[LocalRunner] Error cloning/setting up ${project.name}:`, err.message);
        isError = true;
        this.cloningLocks.delete(project.id);
        const safeMessage = this.redactProjectSecrets(err.message, project);
        if (!friendlyHint) friendlyHint = explainGitError(safeMessage);
        statusMessage = safeMessage;
        alert({
          event: 'deploy_failed',
          level: 'error',
          title: 'Fallo al preparar el repositorio',
          message: `No se pudo preparar ${project.name} desde ${displayUrl}.\n\n${safeMessage.slice(0, 600)}`,
          projectId: project.id,
          projectName: project.name
        });
      }
    })();

    this.cloningLocks.set(project.id, clonePromise);
    return { port, success: true, type: 'cloning' };
  }

  /**
   * Pre-prepare a project in the background upon import or creation
   */
  async prepareProject(project) {
    if (!project || !project.id) return;
    if (this.cloningLocks.has(project.id)) return this.cloningLocks.get(project.id);
    const projectDir = this.resolveProjectDir(project);
    if (fs.existsSync(projectDir) && !this.isDirectoryEmpty(projectDir)) return;

    const gitUrl = this.extractProjectGitUrl(project);
    if (!gitUrl) return;

    const cloneUrl = this.normalizeGitUrl(gitUrl);
    if (!cloneUrl) return;
    /** @type {Promise<void> | null} */
    let task = null;
    task = (async () => {
      console.log(`[LocalRunner] Auto-preparing project ${project.name} in background...`);
      try {
        this.cleanDirectory(projectDir);
        await this.gitClone(cloneUrl, projectDir, { timeout: 180000, branch: project.gitBranch || null });

        const resolved = this.resolveRunnableDirectory(projectDir, project.baseDirectory, project);
        if (resolved.type === 'node' && !this.hasNodeModules(resolved.path, projectDir)) {
          await this.npmInstall(resolved.path, { timeout: 180000, rootDir: projectDir, projectId: project.id, project });
        }
        console.log(`[LocalRunner] Auto-preparation complete for ${project.name}`);
      } catch (e) {
        console.warn(`[LocalRunner] Auto-preparation warning for ${project.name}:`, e.message);
      } finally {
        if (this.cloningLocks.get(project.id) === task) {
          this.cloningLocks.delete(project.id);
        }
      }
    })();
    this.cloningLocks.set(project.id, task);
    return task;
  }

  extractProjectGitUrl(project) {
    if (!project) return null;
    if (project.gitRepo && String(project.gitRepo).trim()) {
      return String(project.gitRepo).trim();
    }
    if (!Array.isArray(project.resources)) return null;
    for (const r of project.resources) {
      if (!r || !r.gitRepo) continue;
      const repo = String(r.gitRepo).trim();
      const isDockerImg = r.buildConfig?.build_pack === 'dockerimage' || Boolean(r.gitDetails?.docker_registry_image_name);
      if (isDockerImg && /^(?:https?:\/\/github\.com\/)?coollabsio\/coolify(?:\.git)?$/i.test(repo)) {
        continue;
      }
      if (repo) return repo;
    }
    return null;
  }

  extractDockerImage(project) {
    if (!project || !Array.isArray(project.resources)) return null;
    for (const r of project.resources) {
      const name = r?.gitDetails?.docker_registry_image_name || r?.image;
      if (r?.buildConfig?.build_pack === 'dockerimage' && name) {
        const tag = r?.gitDetails?.docker_registry_image_tag || 'latest';
        return name.includes(':') && !name.startsWith('localhost:') ? name : `${name}:${tag}`;
      }
    }
    return null;
  }

  /**
   * Fallback sandbox server for apps without local code or Dockerfile-only projects (100% offline CSS)
   */
  async startFallbackServer(project, projectDir, port, detectedType = 'unknown') {
    const dockerImage = this.extractDockerImage(project);
    const isDockerOnly = detectedType === 'docker';
    const dPort = this.daemonPort();
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>${escapeHtml(project.name)} — Servidor local (:${port})</title>
  <style>${OFFLINE_PAGE_CSS}</style>
</head>
<body>
  <div class="card">
    <h1>${escapeHtml(project.name)}</h1>
    ${dockerImage
      ? `<span class="pill warn">Imagen Docker precompilada (:${port})</span>
         <p>Este proyecto usa la imagen Docker <code>${escapeHtml(dockerImage)}</code> y no tiene código fuente local.</p>
         <p>Para ejecutarlo, arranca <strong>Docker Desktop</strong> y despliega el contenedor en producción, o añade la URL Git en <strong>Configuración</strong>.</p>`
      : isDockerOnly
        ? `<span class="pill warn">Proyecto con Dockerfile (:${port})</span>
           <p>Se encontró un <code>Dockerfile</code> en <code>${escapeHtml(projectDir)}</code> sin un servidor de desarrollo nativo (Node/Python/Go/PHP).</p>
           <p>Para ejecutarlo usa <strong>Desplegar con Docker</strong> desde la pestaña Despliegues, o define un <em>Comando de inicio</em> en Configuración.</p>`
        : `<span class="pill ok">Ejecutándose en local :${port}</span>
           <p>Este proyecto todavía no tiene un punto de entrada ejecutable en <code>${escapeHtml(projectDir)}</code>. Sincroniza tu carpeta con <code>culkibo sync</code>, vincula una <em>Carpeta local</em> en Configuración o añade un <code>index.html</code> / <code>package.json</code>.</p>`}
    <div class="actions">
      <a href="http://localhost:${dPort}/#/projects/${encodeURIComponent(project.id)}" class="btn">Configurar en Culkibo</a>
    </div>
    <div class="foot">
      <span>Culkibo v1.0.0 Local Runner</span>
      <a href="http://localhost:${dPort}" style="color:#18181b;font-weight:600;text-decoration:none;">Volver a Culkibo &rarr;</a>
    </div>
  </div>
</body>
</html>`);
    });

    return new Promise((resolve, reject) => {
      server.listen(port, '0.0.0.0', () => {
        console.log(`[LocalRunner] Fallback server for ${project.name} listening on http://localhost:${port}`);
        this.activeRunners.set(project.id, {
          type: 'fallback',
          server,
          port,
          projectDir,
          startTime: Date.now()
        });
        resolve({ port, success: true, type: 'fallback' });
      });

      server.on('error', reject);
    });
  }

  /**
   * Hook invocado cuando Live Sync aplica un frame en disco:
   * - Si el runner está en `fallback` y acaban de llegar archivos ejecutables, lo promueve automáticamente.
   * - Si el runner está ejecutando un proceso y cambiaron ficheros de servidor/configuración, reinicia con debounce.
   */
  onLiveSyncApplied(data = {}) {
    const projectId = data?.projectId;
    if (!projectId) return;
    const runner = this.activeRunners.get(projectId);
    if (!runner) return;

    const files = Array.isArray(data.changedFiles) ? data.changedFiles.map(String) : [];
    const needsRestart = runner.type === 'fallback' || (
      runner.type === 'process' && (
        data.route === 'path_c_restart' ||
        files.some((f) => /(?:^|\/)(?:package\.json|\.env(?:\..*)?|next\.config\.|vite\.config\.|astro\.config\.|nuxt\.config\.|server\.[^/]+|app\.py|main\.py|manage\.py|go\.mod|composer\.json)$|\.(?:py|go|php)$/i.test(f))
      )
    );
    if (!needsRestart) return;

    const prev = this._syncRestartTimers.get(projectId);
    if (prev) clearTimeout(prev);

    const timer = setTimeout(() => {
      this._syncRestartTimers.delete(projectId);
      const pm = getProjectManager();
      const project = pm && typeof pm.getById === 'function' ? pm.getById(projectId) : null;
      if (!project || !this.activeRunners.has(projectId)) return;
      if (containerOrchestrator) {
        containerOrchestrator.addLog('INFO', 'forge', `Live Sync actualizó archivos críticos — reiniciando servidor local de ${project.name}...`, new Date(), projectId);
      }
      this.start(project).catch((e) => {
        console.warn(`[LocalRunner] Error al reiniciar ${project.name} tras Live Sync:`, e.message);
      });
    }, 650);
    if (timer.unref) timer.unref();
    this._syncRestartTimers.set(projectId, timer);
  }

  /**
   * Stop a running project and cleanly kill all child processes and free ports
   */
  async stop(projectId, port = null) {
    this.bumpGeneration(projectId);

    const pendingRestart = this._syncRestartTimers.get(projectId);
    if (pendingRestart) {
      clearTimeout(pendingRestart);
      this._syncRestartTimers.delete(projectId);
    }

    const runner = this.activeRunners.get(projectId);
    const portsToKill = new Set();
    if (port) portsToKill.add(port);
    if (runner?.port) portsToKill.add(runner.port);

    if (runner) {
      if (runner.type === 'process' && runner.child && runner.child.pid) {
        console.log(`[LocalRunner] Killing process tree for project ${projectId} (PID: ${runner.child.pid})`);
        try {
          if (process.platform === 'win32') {
            try {
              execFileSync('taskkill', ['/pid', String(runner.child.pid), '/T', '/F'], {
                timeout: 4000, stdio: 'ignore', windowsHide: true, shell: false
              });
            } catch(e) {}
          } else {
            try { process.kill(-runner.child.pid, 'SIGKILL'); } catch(e) {}
            try { process.kill(runner.child.pid, 'SIGKILL'); } catch(e) {}
          }
        } catch(e) {}
      }

      if (runner.server) {
        try {
          await this.closeServer(runner.server);
        } catch(e) {}
      }

      this.activeRunners.delete(projectId);
      console.log(`[LocalRunner] Stopped runner for project ${projectId}`);
    }

    for (const p of portsToKill) {
      await this.killProcessOnPort(p);
    }

    if (this.cloningLocks && this.cloningLocks.has(projectId)) {
      this.cloningLocks.delete(projectId);
    }

    return { success: true, ports: Array.from(portsToKill) };
  }

  isRunning(projectId) {
    return this.activeRunners.has(projectId);
  }

  getPort(projectId) {
    return this.activeRunners.get(projectId)?.port || null;
  }
}

const localRunnerInstance = new LocalRunner();
try {
  const co = require('./containerOrchestrator');
  if (co && typeof co.registerLocalRunner === 'function') {
    co.registerLocalRunner(localRunnerInstance);
  }
} catch (e) {}
module.exports = localRunnerInstance;
