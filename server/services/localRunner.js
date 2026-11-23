const { spawn, execFileSync } = require('child_process');
const net = require('net');
const os = require('os');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { assertContainedPath, isPrivateIp, isMetadataIp } = require('./ssrfGuard');
const portRegistry = require('./portRegistry');

const ROOT_BASE_DIR = process.env.CULKIBO_DATA_DIR
  ? path.resolve(process.env.CULKIBO_DATA_DIR)
  : path.resolve(__dirname, '..', '..');
const PROJECTS_ROOT = path.resolve(ROOT_BASE_DIR, 'projects');

const OFFLINE_PAGE_CSS = `
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#fafafa;color:#18181b;font-family:system-ui,-apple-system,'Segoe UI',sans-serif;padding:24px;}
  .card{max-width:560px;width:100%;background:#fff;border:1px solid #e4e4e7;border-radius:12px;padding:28px;box-shadow:0 1px 3px rgba(24,24,27,.06);}
  h1{margin:0 0 6px;font-size:18px;font-weight:600;color:#18181b;}
  .pill{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;padding:3px 10px;border-radius:999px;border:1px solid #e4e4e7;background:#f4f4f5;color:#3f3f46;}
  .pill.warn{background:#fffbeb;border-color:#fde68a;color:#92400e;}
  .pill.ok{background:#ecfdf5;border-color:#a7f3d0;color:#065f46;}
  p{font-size:14px;color:#52525b;line-height:1.55;margin:14px 0;}
  code{background:#f4f4f5;border:1px solid #e4e4e7;border-radius:6px;padding:1px 6px;font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#18181b;}
  pre{background:#fafafa;border:1px solid #e4e4e7;border-radius:8px;padding:12px;font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#27272a;overflow:auto;max-height:240px;white-space:pre-wrap;margin:14px 0;}
  .btn{display:inline-block;text-decoration:none;background:#18181b;color:#fff;padding:9px 14px;border-radius:8px;font-size:13px;font-weight:600;}
  .btn:hover{background:#27272a;}
  .foot{margin-top:18px;padding-top:14px;border-top:1px solid #f4f4f5;display:flex;justify-content:space-between;align-items:center;font-size:12px;color:#71717a;}
`;

/** Puertos reservados del sistema/infraestructura que `killProcessOnPort` JAMÁS debe matar. */
const RESERVED_PORTS = new Set([22, 53, 80, 443, 2019, 2375, 2376, 3306, 5432, 6379, 27017]);

/** Variables del entorno del host que un proyecto no fiable NO puede heredar ni sobreescribir. */
const SAFE_HOST_ENV_ALLOWLIST = [
  'PATH', 'Path', 'PATHEXT', 'COMSPEC', 'ComSpec', 'SystemRoot', 'SYSTEMROOT',
  'WINDIR', 'TEMP', 'TMP', 'TMPDIR', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA',
  'LANG', 'LC_ALL', 'LC_CTYPE', 'TERM', 'TZ', 'OS', 'NUMBER_OF_PROCESSORS',
  'ProgramFiles', 'ProgramFiles(x86)', 'CommonProgramFiles', 'PROGRAMDATA'
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
  for (const key of SAFE_HOST_ENV_ALLOWLIST) {
    if (process.env[key] !== undefined) env[key] = String(process.env[key]);
  }
  for (const [k, v] of Object.entries(projectEnvVars || {})) {
    if (!k || BLOCKED_PROJECT_ENV_KEYS.has(k.toUpperCase())) continue;
    if (/^(CULKIBO_|CLOUDFLARE_|GITHUB_TOKEN)/i.test(k)) continue;
    env[k] = String(v == null ? '' : v);
  }
  for (const [k, v] of Object.entries(extraEnv || {})) {
    if (v !== undefined) env[k] = String(v);
  }
  return env;
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
    this.activeRunners = new Map(); // projectId -> { type: 'process'|'static'|'fallback', child, server, port, startTime }
    this.cloningLocks = new Map(); // projectId -> Promise
    // Monotonically increasing token per project. Every stop() bumps it, so any
    // in-flight clone/install continuation can detect that it was superseded and
    // abort instead of resurrecting a project the user just stopped.
    this.runGenerations = new Map(); // projectId -> number
    this.startLocks = new Map(); // projectId -> Promise (serialises concurrent start())
    /** @type {{ mtimeMs: number, token: string | null } | null} */
    this._gitTokenCache = null;
    portRegistry.registerProvider('localRunner', () =>
      Array.from(this.activeRunners.values()).map((r) => r && r.port).filter(Boolean)
    );
  }

  /** Resuelve y confina el directorio de un proyecto dentro de `projects/`. */
  resolveProjectDir(projectId) {
    const id = String(projectId || '').trim();
    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(id)) {
      throw new Error(`Identificador de proyecto inválido: ${id.slice(0, 40)}`);
    }
    return assertContainedPath(PROJECTS_ROOT, id);
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

  /**
   * Close an http.Server and forcibly drop keep-alive sockets.
   * `server.close()` alone waits for idle connections to end, so a browser tab
   * left open on the loading page would hold the port indefinitely.
   */
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

  /**
   * Intelligently resolve the runnable directory of a project
   * Supports: root, project.baseDirectory, /backend, /frontend, /web, /src, /app, /client, /server
   */
  resolveRunnableDirectory(projectDir, preferredBaseDir) {
    if (!fs.existsSync(projectDir)) return { type: 'none', path: projectDir };

    // 1. Check if preferredBaseDir is specified (e.g. from Coolify base_directory)
    if (preferredBaseDir && preferredBaseDir !== '/') {
      const cleanBase = String(preferredBaseDir).replace(/^\/+/, '').replace(/\/+$/, '');
      if (cleanBase && !cleanBase.includes('\0') && !cleanBase.split(/[\\/]+/).includes('..')) {
        /** @type {string | null} */
        let customPath = null;
        try {
          customPath = assertContainedPath(projectDir, cleanBase);
        } catch (e) {
          customPath = null;
        }
        if (customPath && fs.existsSync(customPath)) {
          if (fs.existsSync(path.join(customPath, 'package.json'))) {
            return { type: 'node', path: customPath };
          }
          if (fs.existsSync(path.join(customPath, 'index.html')) || fs.existsSync(path.join(customPath, 'public', 'index.html'))) {
            return { type: 'static', path: customPath };
          }
        }
      }
    }

    // 2. Check root
    if (fs.existsSync(path.join(projectDir, 'artisan'))) {
      return { type: 'php', path: projectDir };
    }
    if (fs.existsSync(path.join(projectDir, 'package.json'))) {
      return { type: 'node', path: projectDir };
    }
    if (fs.existsSync(path.join(projectDir, 'index.html')) || fs.existsSync(path.join(projectDir, 'public', 'index.html'))) {
      return { type: 'static', path: projectDir };
    }

    // 3. Check common subdirectories for fullstack / monorepos
    const candidateDirs = ['backend', 'server', 'web', 'frontend', 'app', 'client', 'src'];
    for (const sub of candidateDirs) {
      const subPath = path.join(projectDir, sub);
      if (fs.existsSync(subPath)) {
        if (fs.existsSync(path.join(subPath, 'package.json'))) {
          return { type: 'node', path: subPath };
        }
        if (fs.existsSync(path.join(subPath, 'index.html')) || fs.existsSync(path.join(subPath, 'public', 'index.html'))) {
          return { type: 'static', path: subPath };
        }
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
  async start(project) {
    if (!project || !project.id) throw new Error('Proyecto inválido');

    // P1-13: bucle `while` (no `if`) para serializar >=3 llamadas concurrentes
    while (this.startLocks.has(project.id)) {
      try { await this.startLocks.get(project.id); } catch (e) {}
    }

    const task = this._startInternal(project).finally(() => {
      if (this.startLocks.get(project.id) === task) {
        this.startLocks.delete(project.id);
      }
    });
    this.startLocks.set(project.id, task);
    return task;
  }

  async _startInternal(project) {
    // If already running, stop first (this also invalidates any in-flight clone)
    await this.stop(project.id);

    const port = await this.getAvailablePort(project.localPort || project.forgePort || 3001);
    project.localPort = port;
    project.localRunning = true;

    const projectDir = this.resolveProjectDir(project.id);
    const resolved = this.resolveRunnableDirectory(projectDir, project.baseDirectory);

    // Case 0: PHP / Laravel project detected
    if (resolved.type === 'php') {
      if (!this.checkCommand('php')) {
        return this.startPhpRequirementsServer(project, resolved.path, port);
      }
    }

    // Case 1: Real Node / Next.js / Vite / Express App detected (in root or subfolder)
    if (resolved.type === 'node') {
      return this.startNodeProject(project, resolved.path, port);
    }

    // Case 2: Static HTML / Frontend detected (in root or subfolder)
    if (resolved.type === 'static') {
      return this.startStaticProject(project, resolved.path, port);
    }

    // Case 3: Project directory does not exist or has no code, but git repository is configured
    const gitUrl = project.gitRepo || (project.resources && project.resources.find(r => r.gitRepo)?.gitRepo);
    if (gitUrl) {
      return this.cloneAndStartProject(project, projectDir, gitUrl, port);
    }

    // Case 4: General placeholder/standalone app with local API server
    return this.startFallbackServer(project, projectDir, port);
  }

  /**
   * Check if a CLI command exists on the machine
   */
  checkCommand(cmd) {
    try {
      // `where`/`which` por argv: si `cmd` llegara a contener `; rm -rf /`, con
      // una cadena de shell se ejecutaría; con argv es sólo un nombre que no se
      // encuentra y la función devuelve false.
      execFileSync(process.platform === 'win32' ? 'where' : 'which', [String(cmd)], {
        stdio: 'ignore', timeout: 5000, windowsHide: true, shell: false
      });
      return true;
    } catch(e) {
      return false;
    }
  }

  /**
   * `npm install` sin shell.
   *
   * Los argumentos son constantes, pero `exec()` seguía entregando la cadena a
   * cmd.exe / sh: una invariante que sólo se mantiene si no hay ni una sola
   * excepción. Resuelve siempre (nunca rechaza) porque los tres llamantes ya
   * trataban el fallo de instalación como no fatal.
   */
  npmInstall(cwd, { timeout = 300000 } = {}) {
    return new Promise((resolve) => {
      let child;
      try {
        child = spawnTool('npm', ['install', '--prefer-offline', '--no-audit'], {
          cwd,
          env: buildSafeChildEnv(),
          windowsHide: true,
          stdio: ['ignore', 'pipe', 'pipe']
        });
      } catch (err) {
        return resolve({ ok: false, error: err.message });
      }

      // Se conserva sólo la cola de stderr: un `npm install` real supera de
      // largo el maxBuffer de 1 MB que hacía fallar a `exec` DESPUÉS de haber
      // instalado correctamente.
      const stderr = [];
      child.stderr.on('data', (d) => {
        stderr.push(d.toString());
        if (stderr.length > 80) stderr.shift();
      });
      child.stdout.on('data', () => {});

      const timer = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch (e) {}
      }, timeout);
      if (timer.unref) timer.unref();

      child.on('error', (err) => {
        clearTimeout(timer);
        resolve({ ok: false, error: err.message });
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        if (code === 0) return resolve({ ok: true });
        resolve({ ok: false, error: stderr.join('').trim() || `npm install terminó con código ${code}` });
      });
    });
  }

  /**
   * Start a real Node / Next.js / Vite development server
   */
  async startNodeProject(project, projectDir, port) {
    const hasNodeModules = fs.existsSync(path.join(projectDir, 'node_modules'));

    // If node_modules is missing, install dependencies first with real-time feedback
    if (!hasNodeModules) {
      console.log(`[LocalRunner] node_modules missing for ${project.name}. Starting dependency installer...`);
      return this.installDepsAndStart(project, projectDir, port);
    }

    return this.spawnNodeDevProcess(project, projectDir, port);
  }

  /**
   * Serve a loading page while installing dependencies, then spawn the real process
   */
  async installDepsAndStart(project, projectDir, port) {
    /** @type {http.Server} */
    let tempServer;
    let statusMessage = 'Instalando dependencias necesarias (npm install)...';
    let isError = false;

    tempServer = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      const actionsHtml = isError
        ? `<div class="space-y-2">
            <button onclick="window.location.reload()" class="w-full px-4 py-2.5 bg-slate-900 text-white rounded-xl text-xs font-semibold hover:bg-slate-800 transition-colors">
              Reintentar
            </button>
            <a href="http://localhost:3030" class="block text-xs text-slate-500 hover:text-slate-800">Volver a Culkibo</a>
          </div>`
        : `<div class="text-xs text-slate-400">Instalando paquetes de Node.js. Esta página se actualizará automáticamente en unos segundos.</div>
          <script>setTimeout(() => window.location.reload(), 4000);</script>`;

      res.end(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Instalando dependencias — ${escapeHtml(project.name)}</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50 flex items-center justify-center min-h-screen font-sans p-4">
  <div class="bg-white p-8 rounded-2xl border border-slate-200 shadow-sm max-w-md w-full text-center space-y-4">
    <div class="w-12 h-12 rounded-2xl ${isError ? 'bg-rose-50 text-rose-600' : 'bg-blue-50 text-blue-600 animate-bounce'} flex items-center justify-center text-2xl mx-auto">
      ${isError ? '⚠️' : '⚡'}
    </div>
    <h1 class="text-lg font-bold text-slate-900">${escapeHtml(project.name)}</h1>
    <p class="text-xs text-slate-600 font-mono bg-slate-50 p-3 rounded-xl border border-slate-100 break-all">${escapeHtml(statusMessage)}</p>
    ${actionsHtml}
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
          containerOrchestrator.addLog('INFO', 'forge', `Instalando dependencias (npm install) para ${project.name}...`, new Date(), project.id);
        }
        const install = await this.npmInstall(projectDir, { timeout: 300000 });
        if (!install.ok) throw new Error(install.error);

        // The user may have pressed Stop while npm was running. Do not resurrect.
        if (this.isStale(project.id, generation)) {
          await this.closeServer(tempServer);
          return;
        }

        // Close temp server and launch real dev server
        await this.closeServer(tempServer);
        this.activeRunners.delete(project.id);
        await this.spawnNodeDevProcess(project, projectDir, port);
      } catch (err) {
        console.error(`[LocalRunner] Dependency install failed for ${project.name}:`, err.message);
        isError = true;
        statusMessage = `Error al instalar dependencias: ${err.message}`;
        alert({
          event: 'deploy_failed',
          level: 'error',
          title: 'Fallo al instalar dependencias',
          message: `npm install falló para ${project.name}.\n\n${String(err.message).slice(0, 600)}`,
          projectId: project.id,
          projectName: project.name
        });
      }
    })();

    return { port, success: true, type: 'installing_deps' };
  }

  /**
   * Spawn native dev server process with crash recovery and live logs
   */
  async spawnNodeDevProcess(project, projectDir, port) {
    let pkg = {};
    try {
      pkg = JSON.parse(fs.readFileSync(path.join(projectDir, 'package.json'), 'utf8'));
    } catch(e) {}

    const scripts = pkg.scripts || {};
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };

    let cmd = 'npm';
    let args = ['run', 'dev'];

    // Check framework specific optimal dev command
    if (deps['next'] || scripts['dev']?.includes('next dev')) {
      cmd = 'npx';
      args = ['next', 'dev', '-p', String(port)];
    } else if (deps['vite'] || scripts['dev']?.includes('vite')) {
      cmd = 'npx';
      args = ['vite', '--port', String(port), '--host', '0.0.0.0'];
    } else if (scripts['dev']) {
      cmd = 'npm';
      args = ['run', 'dev', '--', '-p', String(port)];
    } else if (scripts['start']) {
      cmd = 'npm';
      args = ['run', 'start', '--', '-p', String(port)];
    } else if (pkg.main) {
      // P1-13: confinar pkg.main al directorio del proyecto (impide ../../escape.js)
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

    console.log(`[LocalRunner] Starting real process for ${project.name}: ${cmd} ${args.join(' ')} on port ${port} (cwd: ${projectDir})`);

    const env = buildSafeChildEnv({
      PORT: String(port),
      HOST: '0.0.0.0',
      NODE_ENV: 'development'
    }, project.envVars || {});

    const isWin = process.platform === 'win32';
    const child = spawnTool(cmd, args, {
      cwd: projectDir,
      env,
      detached: !isWin,
      windowsHide: true
    });

    child.on('error', (err) => {
      console.error(`[LocalRunner] Spawn error for ${project.name}:`, err.message);
      if (containerOrchestrator) {
        containerOrchestrator.addLog('ERROR', 'forge', `Error al lanzar el proceso: ${err.message}`, new Date(), project.id);
      }
    });

    const stderrBuffer = [];
    const spawnTime = Date.now();

    child.stdout.on('data', (data) => {
      const msg = data.toString();
      if (containerOrchestrator) {
        containerOrchestrator.addLog('INFO', 'forge', msg.trim(), new Date(), project.id);
      }
      console.log(`[${project.name}:${port}] ${msg.trim()}`);
    });

    child.stderr.on('data', (data) => {
      const msg = data.toString();
      stderrBuffer.push(msg.trim());
      if (stderrBuffer.length > 25) stderrBuffer.shift();
      if (containerOrchestrator) {
        containerOrchestrator.addLog('WARN', 'forge', msg.trim(), new Date(), project.id);
      }
      console.error(`[${project.name}:${port}:err] ${msg.trim()}`);
    });

    const generation = this.currentGeneration(project.id);

    child.on('close', async (code) => {
      console.log(`[LocalRunner] Process for ${project.name} exited with code ${code}`);
      if (this.activeRunners.get(project.id)?.child === child) {
        this.activeRunners.delete(project.id);
      }

      // A deliberate stop() also makes the child exit non-zero. Without this
      // guard the diagnostics server below would re-bind the port the user just
      // asked us to free, recreating the zombie-port symptom.
      if (this.isStale(project.id, generation)) return;

      // If the process crashed early (within 30 seconds of starting), activate diagnostics server on that port
      const lifetime = Date.now() - spawnTime;
      if (code !== 0 && lifetime < 30000) {
        console.warn(`[LocalRunner] Early crash detected for ${project.name} (${lifetime}ms). Activating diagnostics fallback on port ${port}...`);
        const details = stderrBuffer.join('\n') || `El proceso finalizó inesperadamente con código de salida ${code}`;
        alert({
          event: 'service_down',
          level: 'error',
          title: 'Servicio caído',
          message: `El proceso de desarrollo terminó con código ${code} a los ${lifetime} ms.\n\n${details.slice(0, 600)}`,
          projectId: project.id,
          projectName: project.name,
          url: `http://localhost:${port}`
        });
        await this.startCrashDiagnosticsServer(project, projectDir, port, details, generation);
      }
    });

    this.activeRunners.set(project.id, {
      type: 'process',
      child,
      port,
      projectDir,
      startTime: Date.now()
    });

    // Wait a brief moment for the port to start listening
    await new Promise(r => setTimeout(r, 2000));
    return { port, success: true, type: 'real_process' };
  }

  /**
   * Diagnostic fallback server shown when a development process fails on boot
   */
  async startCrashDiagnosticsServer(project, projectDir, port, errorDetails, generation = null) {
    if (generation !== null && this.isStale(project.id, generation)) {
      return { port, success: false, stale: true };
    }
    await this.killProcessOnPort(port);
    if (generation !== null && this.isStale(project.id, generation)) {
      return { port, success: false, stale: true };
    }

    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Aviso de ejecución — ${escapeHtml(project.name)}</title>
  <style>${OFFLINE_PAGE_CSS}</style>
</head>
<body>
  <div class="card">
    <h1>${escapeHtml(project.name)}</h1>
    <span class="pill warn">Error en el servidor de desarrollo (:${port})</span>
    <p>El proceso local se detuvo con el siguiente diagnóstico:</p>
    <pre>${escapeHtml(errorDetails || 'Sin detalles de error reportados')}</pre>
    <a href="http://localhost:${this.daemonPort()}" class="btn">Volver a Culkibo</a>
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
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>${escapeHtml(project.name)} — Aplicación PHP / Laravel</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50 min-h-screen flex items-center justify-center font-sans p-4">
  <div class="max-w-xl w-full bg-white p-8 rounded-2xl border border-slate-200 shadow-sm space-y-4">
    <div class="flex items-center gap-3">
      <div class="w-12 h-12 rounded-2xl bg-indigo-50 text-indigo-600 flex items-center justify-center text-2xl">
        🐘
      </div>
      <div>
        <h1 class="text-xl font-bold text-slate-900">${escapeHtml(project.name)}</h1>
        <span class="text-xs text-indigo-800 bg-indigo-50 border border-indigo-200 px-2 py-0.5 rounded-full font-semibold">
          Aplicación PHP / Laravel
        </span>
      </div>
    </div>
    <p class="text-sm text-slate-600">Este proyecto es una aplicación PHP/Laravel. Para ejecutarla en local, inicia <strong>Docker Desktop</strong> o instala <strong>PHP</strong> en tu sistema.</p>
    <div class="pt-2 border-t border-slate-100 flex justify-between items-center text-xs text-slate-400">
      <span>Culkibo v1.0.0 Local Runner</span>
      <a href="http://localhost:3030" class="text-blue-600 hover:underline">Volver a Culkibo &rarr;</a>
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
   * Serve static files directly
   */
  async startStaticProject(project, projectDir, port) {
    const publicDir = fs.existsSync(path.join(projectDir, 'public')) 
      ? path.join(projectDir, 'public') 
      : projectDir;

    const rootDir = path.resolve(publicDir);
    const realRoot = fs.existsSync(rootDir) ? fs.realpathSync(rootDir) : rootDir;

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
      res.writeHead(200, { 'Content-Type': contentType });
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
      // P1-13: bloquear bytes nulos (%00) que lanzarían ERR_INVALID_ARG_VALUE en fs.existsSync
      if (reqPath.includes('\0')) {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('400 Bad Request');
      }

      // Contain the resolved path inside the served root. Without this, a raw
      // request line such as `GET /../../data/github.json` (or its percent-encoded
      // form) reads any file on the host, including the stored GitHub PAT.
      const filePath = path.resolve(rootDir, '.' + path.posix.normalize('/' + reqPath.replace(/\\/g, '/')));
      const relative = path.relative(rootDir, filePath);
      if (relative.startsWith('..') || path.isAbsolute(relative)) {
        res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('403 Forbidden');
      }

      if (reqPath !== '/' && fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        const ext = path.extname(filePath).toLowerCase();
        const mimeTypes = {
          '.html': 'text/html; charset=utf-8',
          '.js': 'application/javascript',
          '.css': 'text/css',
          '.json': 'application/json',
          '.png': 'image/png',
          '.jpg': 'image/jpeg',
          '.svg': 'image/svg+xml'
        };
        return streamFile(filePath, mimeTypes[ext] || 'application/octet-stream', res);
      }

      // SPA Fallback to index.html
      const fallbackIndex = path.join(publicDir, 'index.html');
      if (fs.existsSync(fallbackIndex)) {
        return streamFile(fallbackIndex, 'text/html; charset=utf-8', res);
      }

      res.writeHead(404, { 'Content-Type': 'text/plain' });
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
      const ghFile = path.join(process.cwd(), 'data', 'github.json');
      const stat = fs.statSync(ghFile);
      if (this._gitTokenCache && this._gitTokenCache.mtimeMs === stat.mtimeMs) {
        return this._gitTokenCache.token;
      }
      const gh = JSON.parse(fs.readFileSync(ghFile, 'utf8'));
      const token = gh.token || null;
      this._gitTokenCache = { mtimeMs: stat.mtimeMs, token };
      return token;
    } catch (e) {
      this._gitTokenCache = null;
      return null;
    }
  }

  /**
   * Build the environment for a git subprocess so the PAT is supplied over
   * GIT_ASKPASS ONLY for github.com remotes instead of leaking to arbitrary URLs.
   *
   * Returns { env, cleanup }. Always call cleanup().
   */
  /** @param {string | null} [cloneUrl] */
  gitAuthEnv(cloneUrl = null) {
    const token = this.isGitHubRemote(cloneUrl) ? this.readGitToken() : null;
    /** @type {Record<string, any>} */
    const env = { ...process.env, GIT_TERMINAL_PROMPT: '0' };

    // Desactivar cualquier ayudante de credenciales configurado en la máquina.
    env.GIT_CONFIG_COUNT = '1';
    env.GIT_CONFIG_KEY_0 = 'credential.helper';
    env.GIT_CONFIG_VALUE_0 = '';

    if (!token) return { env, cleanup: () => {} };

    const isWin = process.platform === 'win32';
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-git-'));
    const helper = path.join(dir, isWin ? 'askpass.cmd' : 'askpass.sh');

    // En Windows, EnableDelayedExpansion con `!CULKIBO_GIT_TOKEN!` evita que
    // caracteres especiales (`&`, `|`, `%`) dentro de un token se interpreten.
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
   * @param {{ timeout?: number, depth?: number | null, branch?: string | null, onLine?: ((line: string) => void) | null }} [opts]
   */
  gitClone(cloneUrl, targetDir, { timeout = 180000, depth = null, branch = null, onLine = null } = {}) {
    if (!cloneUrl || /^file:/i.test(cloneUrl) && process.env.CULKIBO_ALLOW_LOCAL_GIT !== '1') {
      return Promise.reject(new Error('URL de repositorio rechazada por política de seguridad'));
    }
    const { env, cleanup } = this.gitAuthEnv(cloneUrl);

    const args = ['clone', '--progress'];

    // Shallow + single-branch. A deploy builds exactly one commit; the rest of
    // the history is bytes the build never reads. On a repo with a few thousand
    // commits this is the difference between seconds and minutes.
    const depthNum = parseInt(String(depth ?? ''), 10);
    if (Number.isInteger(depthNum) && depthNum > 0) {
      args.push('--depth', String(depthNum), '--single-branch');
    }

    if (branch != null && branch !== '') {
      const name = String(branch);
      // The branch name reaches argv. There is no shell to inject into, but git
      // itself would happily read `--upload-pack=...` as a flag, so anything
      // that could be mistaken for an option is refused outright.
      if (!/^[A-Za-z0-9._/-]+$/.test(name) || name.startsWith('-') || name.includes('..')) {
        cleanup();
        return Promise.reject(new Error(`Nombre de rama no válido: «${name}»`));
      }
      args.push('--branch', name);
    }

    // `--` closes the option list: after it, the URL is a URL even if someone
    // manages to store a repository whose name starts with a dash.
    args.push('--', cloneUrl, targetDir);

    return new Promise((/** @type {(value?: void) => void} */ resolve, reject) => {
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
        // git reports clone progress on stderr; forwarding it line by line is
        // what turns a two-minute silence into a visible build log.
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
    let statusMessage = `Clonando repositorio ${displayUrl}...`;
    let isError = false;

    tempServer = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Preparando ${escapeHtml(project.name)} en Local</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50 flex items-center justify-center min-h-screen font-sans p-4">
  <div class="bg-white p-8 rounded-2xl border border-slate-200 shadow-sm max-w-md w-full text-center space-y-4">
    <div class="w-12 h-12 rounded-2xl ${isError ? 'bg-rose-50 text-rose-600' : 'bg-blue-50 text-blue-600 animate-bounce'} flex items-center justify-center text-2xl mx-auto">
      ${isError ? '⚠️' : '⚡'}
    </div>
    <h1 class="text-lg font-bold text-slate-900">Preparando ${escapeHtml(project.name)}</h1>
    <p class="text-xs text-slate-600 font-mono bg-slate-50 p-3 rounded-xl border border-slate-100 break-all">${escapeHtml(statusMessage)}</p>
    ${isError ? `
      <div class="space-y-2">
        <button onclick="window.location.reload()" class="w-full px-4 py-2.5 bg-slate-900 text-white rounded-xl text-xs font-semibold hover:bg-slate-800 transition-colors">
          Reintentar
        </button>
        <a href="http://localhost:3030" class="block text-xs text-slate-500 hover:text-slate-800">Volver a Culkibo</a>
      </div>
    ` : `
      <div class="text-xs text-slate-400">Esta página se actualizará automáticamente cuando el servidor esté listo.</div>
      <script>setTimeout(() => window.location.reload(), 3000);</script>
    `}
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

    // Run git clone asynchronously with promise stored in cloningLocks
    const clonePromise = (async () => {
      try {
        console.log(`[LocalRunner] Cloning ${displayUrl} into ${projectDir}`);
        if (containerOrchestrator) {
          containerOrchestrator.addLog('INFO', 'forge', `Clonando repositorio ${displayUrl} en local...`, new Date(), project.id);
        }
        
        // Ensure parent directory exists
        const parentDir = path.dirname(projectDir);
        if (!fs.existsSync(parentDir)) {
          fs.mkdirSync(parentDir, { recursive: true });
        }

        // Safely clean any broken folder
        this.cleanDirectory(projectDir);

        await this.gitClone(cloneUrl, projectDir, { timeout: 180000 });

        // Resolve runnable directory (handles monorepos, subfolders like /backend, /web, /src)
        const resolved = this.resolveRunnableDirectory(projectDir, project.baseDirectory);

        if (resolved.type === 'node') {
          statusMessage = `Instalando dependencias (npm install) en ${path.relative(projectDir, resolved.path) || 'raíz'}...`;
          if (containerOrchestrator) {
            containerOrchestrator.addLog('INFO', 'forge', `Instalando dependencias en ${resolved.path}...`, new Date(), project.id);
          }
          await this.npmInstall(resolved.path, { timeout: 180000 });
        }

        // The clone can take minutes. If the user stopped (or restarted) the
        // project meanwhile, this continuation is superseded: tear down the
        // loading server and return instead of bringing the project back to life.
        if (this.isStale(project.id, generation)) {
          await this.closeServer(tempServer);
          this.activeRunners.delete(project.id);
          this.cloningLocks.delete(project.id);
          if (containerOrchestrator) {
            containerOrchestrator.addLog('INFO', 'forge', `Preparación cancelada para ${project.name}: el proyecto fue detenido durante la clonación.`, new Date(), project.id);
          }
          return;
        }

        // Close temp server and launch real project
        await this.closeServer(tempServer);
        this.activeRunners.delete(project.id);
        this.cloningLocks.delete(project.id);
        await this.start(project);
      } catch (err) {
        console.error(`[LocalRunner] Error cloning/setting up ${project.name}:`, err.message);
        isError = true;
        this.cloningLocks.delete(project.id);
        // Strip any token from error message
        const safeMessage = this.redactSecrets(err.message);
        statusMessage = `Error al preparar: ${safeMessage}`;
        alert({
          event: 'deploy_failed',
          level: 'error',
          title: 'Fallo al clonar el repositorio',
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
    const projectDir = this.resolveProjectDir(project.id);
    if (fs.existsSync(projectDir)) return; // Already present

    const gitUrl = project.gitRepo || (project.resources && project.resources.find(r => r.gitRepo)?.gitRepo);
    if (!gitUrl) return;

    const cloneUrl = this.normalizeGitUrl(gitUrl);
    if (!cloneUrl) return;
    /** @type {Promise<void> | null} */
    let task = null;
    task = (async () => {
      console.log(`[LocalRunner] Auto-preparing project ${project.name} in background...`);
      try {
        this.cleanDirectory(projectDir);
        await this.gitClone(cloneUrl, projectDir, { timeout: 180000 });

        const resolved = this.resolveRunnableDirectory(projectDir, project.baseDirectory);
        if (resolved.type === 'node') {
          await this.npmInstall(resolved.path, { timeout: 180000 });
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

  /**
   * Fallback sandbox server for apps without local code (100% offline CSS)
   */
  async startFallbackServer(project, projectDir, port) {
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
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
    <span class="pill ok">Ejecutándose en local :${port}</span>
    <p>Este proyecto todavía no tiene código en el directorio local de Culkibo. Clona su repositorio o añade archivos en <code>${escapeHtml(projectDir)}</code>.</p>
    <div class="foot">
      <span>Culkibo v1.0.0 Local Runner</span>
      <a href="http://localhost:${this.daemonPort()}" style="color:#18181b;font-weight:600;text-decoration:none;">Volver a Culkibo &rarr;</a>
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
   * Stop a running project and cleanly kill all child processes and free ports
   */
  async stop(projectId, port = null) {
    // Invalidate any background clone/install continuation for this project
    // BEFORE tearing anything down, so it cannot restart what we are stopping.
    this.bumpGeneration(projectId);

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
            // Process group first (spawned with detached:true so the child leads
            // its own group), then the pid itself as a belt-and-braces fallback.
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

    // Always ensure all assigned ports are cleanly freed
    for (const p of portsToKill) {
      await this.killProcessOnPort(p);
    }

    if (this.cloningLocks && this.cloningLocks.has(projectId)) {
      this.cloningLocks.delete(projectId);
    }

    return { success: true, ports: Array.from(portsToKill) };
  }

  /**
   * Check if running
   */
  isRunning(projectId) {
    return this.activeRunners.has(projectId);
  }

  /**
   * Get active port
   */
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
