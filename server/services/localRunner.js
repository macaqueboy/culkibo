const { spawn, exec } = require('child_process');
const net = require('net');
const os = require('os');
const path = require('path');
const fs = require('fs');
const http = require('http');

let containerOrchestrator = null;
try {
  containerOrchestrator = require('./containerOrchestrator');
} catch(e) {}

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
    await new Promise((resolve) => {
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
      const cleanBase = preferredBaseDir.replace(/^\/+/, '').replace(/\/+$/, '');
      const customPath = path.join(projectDir, cleanBase);
      if (fs.existsSync(customPath)) {
        if (fs.existsSync(path.join(customPath, 'package.json'))) {
          return { type: 'node', path: customPath };
        }
        if (fs.existsSync(path.join(customPath, 'index.html')) || fs.existsSync(path.join(customPath, 'public', 'index.html'))) {
          return { type: 'static', path: customPath };
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
        const { execSync } = require('child_process');
        try {
          execSync(`attrib -r -s -h "${dir}\\*" /s /d`, { stdio: 'ignore', timeout: 5000 });
        } catch(e) {}
        try {
          execSync(`rmdir /s /q "${dir}"`, { stdio: 'ignore', timeout: 10000 });
        } catch(e) {}
      }
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    } catch(e) {
      console.warn(`[LocalRunner] Warning cleaning ${dir}:`, e.message);
    }
  }

  /**
   * Ensure port is free by killing any lingering zombie process on that port
   */
  async killProcessOnPort(port) {
    if (!port) return;
    const numPort = parseInt(port, 10);
    if (isNaN(numPort) || numPort <= 0) return;

    try {
      if (process.platform === 'win32') {
        const { execSync } = require('child_process');
        const pids = new Set();

        // 1. Query via PowerShell Get-NetTCPConnection
        try {
          const psOut = execSync(`powershell -NoProfile -Command "(Get-NetTCPConnection -LocalPort ${numPort} -ErrorAction SilentlyContinue).OwningProcess"`, { timeout: 3000 }).toString().trim();
          psOut.split(/\r?\n/).forEach(s => {
            const p = parseInt(s.trim(), 10);
            if (!isNaN(p) && p > 4 && p !== process.pid) pids.add(p);
          });
        } catch(e) {}

        // 2. Fallback via netstat
        try {
          const netstatOut = execSync(`netstat -ano`, { timeout: 3000 }).toString().trim();
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
            execSync(`taskkill /pid ${pid} /T /F`, { timeout: 4000, stdio: 'ignore' });
            console.log(`[LocalRunner] Killed process ${pid} on port ${numPort}`);
          } catch(e) {}
        }
      } else {
        const { execSync } = require('child_process');
        const pids = new Set();

        // lsof is not installed on minimal Debian/Ubuntu VPS images, which is
        // exactly where Culkibo is deployed. Try lsof, then ss, then fuser.
        const probes = [
          `lsof -ti tcp:${numPort}`,
          `ss -lptnH 'sport = :${numPort}'`,
          `fuser ${numPort}/tcp 2>/dev/null`
        ];
        for (const probe of probes) {
          try {
            const out = execSync(probe, { timeout: 3000, shell: '/bin/sh' }).toString();
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
   * Find an available port starting from desiredPort
   */
  async getAvailablePort(desiredPort) {
    await this.killProcessOnPort(desiredPort);

    const isPortFree = (port) => new Promise((resolve) => {
      const tester = net.createServer()
        .once('error', () => resolve(false))
        .once('listening', () => {
          tester.once('close', () => resolve(true)).close();
        })
        .listen(port);
    });

    let port = desiredPort || 3001;
    while (port < 65535) {
      if (await isPortFree(port)) {
        return port;
      }
      port++;
    }
    return Math.floor(Math.random() * (9000 - 3100 + 1)) + 3100;
  }

  /**
   * Start a project locally
   */
  async start(project) {
    if (!project || !project.id) throw new Error('Proyecto inválido');

    // Two concurrent POST /start-local for the same project used to race through
    // getAvailablePort() and spawn two processes on the same port. Serialise them.
    const inFlight = this.startLocks.get(project.id);
    if (inFlight) {
      try { await inFlight; } catch (e) {}
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

    const projectDir = path.join(process.cwd(), 'projects', project.id);
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
      const { execSync } = require('child_process');
      execSync(process.platform === 'win32' ? `where ${cmd}` : `which ${cmd}`, { stdio: 'ignore' });
      return true;
    } catch(e) {
      return false;
    }
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
    let tempServer = null;
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

    await new Promise((resolve) => tempServer.listen(port, '0.0.0.0', resolve));

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
        await new Promise((resolve, reject) => {
          // A real `npm install` easily exceeds the 1 MB default maxBuffer and
          // would fail with ERR_CHILD_PROCESS_STDIO_MAXBUFFER after succeeding.
          exec('npm install --prefer-offline --no-audit', {
            cwd: projectDir,
            timeout: 300000,
            maxBuffer: 32 * 1024 * 1024
          }, (err, stdout, stderr) => {
            if (err) return reject(new Error(stderr || err.message));
            resolve();
          });
        });

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
    } else if (pkg.main && fs.existsSync(path.join(projectDir, pkg.main))) {
      cmd = 'node';
      args = [pkg.main];
    }

    console.log(`[LocalRunner] Starting real process for ${project.name}: ${cmd} ${args.join(' ')} on port ${port} (cwd: ${projectDir})`);

    const env = {
      ...process.env,
      PORT: String(port),
      HOST: '0.0.0.0',
      NODE_ENV: 'development',
      ...(project.envVars || {})
    };

    const isWin = process.platform === 'win32';
    // On POSIX, stop() kills the whole tree with `process.kill(-pid)`. That only
    // works if the child is its own process-group leader, which requires
    // detached:true — with detached:false the negative-pid kill throws ESRCH and
    // the dev server (plus its forked workers) survives the "stop", leaving a
    // zombie listener on the port. Windows uses `taskkill /T` instead.
    const child = isWin
      ? spawn('cmd.exe', ['/c', cmd, ...args], { cwd: projectDir, env, detached: false })
      : spawn(cmd, args, { cwd: projectDir, env, detached: true });

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
        await this.startCrashDiagnosticsServer(project, projectDir, port, details);
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
  async startCrashDiagnosticsServer(project, projectDir, port, errorDetails) {
    await this.killProcessOnPort(port);

    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Aviso de Ejecución — ${escapeHtml(project.name)}</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50 min-h-screen flex items-center justify-center font-sans p-4">
  <div class="max-w-xl w-full bg-white p-8 rounded-2xl border border-slate-200 shadow-sm space-y-4">
    <div class="flex items-center gap-3">
      <div class="w-12 h-12 rounded-2xl bg-amber-50 text-amber-600 flex items-center justify-center text-2xl font-bold">
        ⚠️
      </div>
      <div>
        <h1 class="text-xl font-bold text-slate-900">${escapeHtml(project.name)}</h1>
        <span class="text-xs text-amber-800 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded-full font-semibold">
          Error en el servidor de desarrollo (: ${port})
        </span>
      </div>
    </div>
    <p class="text-sm text-slate-600">El proceso local se detuvo con el siguiente mensaje de diagnóstico:</p>
    <pre class="bg-slate-900 text-slate-100 p-4 rounded-xl text-xs font-mono overflow-x-auto max-h-56 whitespace-pre-wrap">${escapeHtml(errorDetails || 'Sin detalles de error reportados')}</pre>
    <div class="space-y-2 pt-2">
      <div class="flex gap-3">
        <a href="http://localhost:3030" class="flex-1 text-center px-4 py-2.5 bg-slate-900 text-white rounded-xl text-xs font-semibold hover:bg-slate-800 transition-colors">
          Volver a Culkibo
        </a>
      </div>
    </div>
  </div>
</body>
</html>`);
    });

    return new Promise((resolve) => {
      server.listen(port, '0.0.0.0', () => {
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

    const server = http.createServer((req, res) => {
      let reqPath = req.url.split('?')[0].split('#')[0];
      try {
        reqPath = decodeURIComponent(reqPath);
      } catch (e) {
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
        res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'application/octet-stream' });
        return fs.createReadStream(filePath).pipe(res);
      }

      // SPA Fallback to index.html
      const fallbackIndex = path.join(publicDir, 'index.html');
      if (fs.existsSync(fallbackIndex)) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return fs.createReadStream(fallbackIndex).pipe(res);
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
   * Normalize Git URLs to authenticated or standard HTTPS format
   */
  normalizeGitUrl(rawUrl) {
    if (!rawUrl) return null;
    const url = String(rawUrl).trim();

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
    const httpMatch = url.match(/^https?:\/\/github\.com\/([a-zA-Z0-9_-]+)\/([a-zA-Z0-9_.-]+)$/);
    if (httpMatch) return gh(httpMatch[1], httpMatch[2]);

    return url;
  }

  /** Read the stored GitHub PAT, or null. Never log or interpolate the result. */
  readGitToken() {
    try {
      const ghFile = path.join(process.cwd(), 'data', 'github.json');
      if (!fs.existsSync(ghFile)) return null;
      const gh = JSON.parse(fs.readFileSync(ghFile, 'utf8'));
      return gh.token || null;
    } catch (e) {
      return null;
    }
  }

  /**
   * Build the environment for a git subprocess so the PAT is supplied over
   * GIT_ASKPASS instead of being embedded in the clone URL.
   *
   * A token in the URL leaks into `ps` output, into the cloned repo's
   * .git/config, into git's own error messages, and into any log that echoes
   * the command. Via askpass it lives only in the child's environment.
   *
   * Returns { env, cleanup }. Always call cleanup().
   */
  gitAuthEnv() {
    const token = this.readGitToken();
    const env = { ...process.env, GIT_TERMINAL_PROMPT: '0' };
    if (!token) return { env, cleanup: () => {} };

    const isWin = process.platform === 'win32';
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-git-'));
    const helper = path.join(dir, isWin ? 'askpass.cmd' : 'askpass.sh');

    // git invokes the helper with the prompt as argv[1] and reads the secret
    // from stdout. Because the URL already carries the username, the only
    // prompt is for the password.
    fs.writeFileSync(
      helper,
      isWin
        ? '@echo off\r\necho %CULKIBO_GIT_TOKEN%\r\n'
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
   * `exec()` runs the string through cmd.exe / sh, so any metacharacter in a
   * repository URL becomes command injection — the exact class that produced
   * 21 critical advisories in Coolify and 34 in Dokploy. spawn() with an argv
   * array has no shell to inject into.
   */
  gitClone(cloneUrl, targetDir, { timeout = 180000 } = {}) {
    const { env, cleanup } = this.gitAuthEnv();

    return new Promise((resolve, reject) => {
      const child = spawn('git', ['clone', '--progress', cloneUrl, targetDir], {
        env,
        shell: false,
        windowsHide: true
      });

      const stderr = [];
      child.stderr.on('data', (d) => {
        stderr.push(d.toString());
        if (stderr.length > 50) stderr.shift();
      });

      const timer = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch (e) {}
      }, timeout);
      if (timer.unref) timer.unref();

      const finish = (err) => {
        clearTimeout(timer);
        cleanup();
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
    let out = String(text == null ? '' : text).replace(/https:\/\/[^@\s/]+@/g, 'https://***@');
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
    const displayUrl = this.redactSecrets(rawGitUrl);
    const generation = this.currentGeneration(project.id);

    let tempServer = null;
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

    await new Promise((resolve) => tempServer.listen(port, '0.0.0.0', resolve));

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
          await new Promise((resolve) => {
            exec('npm install --prefer-offline --no-audit', {
              cwd: resolved.path,
              timeout: 180000,
              maxBuffer: 10 * 1024 * 1024
            }, () => resolve());
          });
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
    const projectDir = path.join(process.cwd(), 'projects', project.id);
    if (fs.existsSync(projectDir)) return; // Already present

    const gitUrl = project.gitRepo || (project.resources && project.resources.find(r => r.gitRepo)?.gitRepo);
    if (!gitUrl) return;

    console.log(`[LocalRunner] Auto-preparing project ${project.name} in background...`);
    const cloneUrl = this.normalizeGitUrl(gitUrl);
    try {
      this.cleanDirectory(projectDir);
      await this.gitClone(cloneUrl, projectDir, { timeout: 180000 });

      const resolved = this.resolveRunnableDirectory(projectDir, project.baseDirectory);
      if (resolved.type === 'node') {
        await new Promise((resolve) => {
          exec('npm install --prefer-offline --no-audit', { cwd: resolved.path, timeout: 180000 }, () => resolve());
        });
      }
      console.log(`[LocalRunner] Auto-preparation complete for ${project.name}`);
    } catch(e) {
      console.warn(`[LocalRunner] Auto-preparation warning for ${project.name}:`, e.message);
    }
  }

  /**
   * Fallback sandbox server for apps without local code
   */
  async startFallbackServer(project, projectDir, port) {
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>${escapeHtml(project.name)} — Servidor Local (: ${port})</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50 min-h-screen flex flex-col items-center justify-center font-sans p-4">
  <div class="max-w-xl w-full bg-white p-8 rounded-2xl border border-slate-200 shadow-sm space-y-4">
    <div class="flex items-center gap-3">
      <div class="text-3xl">${escapeHtml(project.icon || '🚀')}</div>
      <div>
        <h1 class="text-xl font-bold text-slate-900">${escapeHtml(project.name)}</h1>
        <span class="inline-flex items-center gap-1.5 text-xs text-emerald-700 bg-emerald-50 px-2.5 py-0.5 rounded-full font-semibold border border-emerald-200">
          ● Ejecutándose en local :${port}
        </span>
      </div>
    </div>
    <p class="text-sm text-slate-600">Este proyecto no contiene archivos en el directorio local de Culkibo. Puedes clonar su repositorio o añadir código en <code class="bg-slate-100 px-2 py-0.5 rounded text-blue-700 font-mono">${escapeHtml(projectDir)}</code>.</p>
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
            const { execSync } = require('child_process');
            try {
              execSync(`taskkill /pid ${runner.child.pid} /T /F`, { timeout: 4000, stdio: 'ignore' });
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

module.exports = new LocalRunner();
