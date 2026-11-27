#!/usr/bin/env node

const { Command } = require('commander');
const crypto = require('crypto');
const readline = require('readline');
const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const net = require('net');
const { spawn } = require('child_process');

// Evitar crash por EPIPE al encadenar salida CLI con `head`, `jq` o pipes cerrados
for (const stream of [process.stdout, process.stderr]) {
  stream.on('error', (err) => {
    if (err && err.code === 'EPIPE') process.exit(0);
  });
}

// Carga perezosa de servicios: comandos ligeros (`--version`, `status`, `update`)
// arrancan al instante sin levantar timers ni leer JSONs innecesarios.
const svc = {
  get containerOrchestrator() { return require('../server/services/containerOrchestrator'); },
  get domainManager() { return require('../server/services/domainManager'); },
  get sslManager() { return require('../server/services/sslManager'); },
  get cloudflareService() { return require('../server/services/cloudflareService'); },
  get mcpServer() { return require('../server/services/mcpServer'); },
  get dockerManager() { return require('../server/services/dockerManager'); },
  get dbBackupManager() { return require('../server/services/dbBackupManager'); },
  get databaseManager() { return require('../server/services/databaseManager'); },
  get projectManager() { return require('../server/services/projectManager'); },
  get environmentManager() { return require('../server/services/environmentManager'); },
  get gitopsManager() { return require('../server/services/gitopsManager'); },
  get universalImporter() { return require('../server/services/universalImporter'); },
  get caddyManager() { return require('../server/services/caddyManager'); },
  get deployManager() { return require('../server/services/deployManager'); },
  get catalogManager() { return require('../server/services/catalogManager'); },
  get telemetryService() { return require('../server/services/telemetryService'); },
  get LiveSyncClient() { return require('../server/services/liveSyncClient').LiveSyncClient; },
  get smartPackBuilder() { return require('../server/services/smartPackBuilder'); },
  get directPushRegistry() { return require('../server/services/directPushRegistry'); },
  get edgeTunnelService() { return require('../server/services/edgeTunnelService'); },
  get supplyChainAttestor() { return require('../server/services/supplyChainAttestor'); },
  get releaseProvenance() { return require('../scripts/release-provenance'); },
  get shadowReplayService() { return require('../server/services/shadowReplayService'); },
  get timeMachineService() { return require('../server/services/timeMachineService'); },
  get finopsOptimizer() { return require('../server/services/finopsOptimizer'); },
  get metricsCollector() { return require('../server/services/metricsCollector'); },
  get sleepAdvisor() { return require('../server/services/sleepAdvisor'); },
  get buildHealerService() { return require('../server/services/buildHealerService'); },
  get fleetMeshService() { return require('../server/services/fleetMeshService'); },
  get iacExporter() { return require('../server/services/iacExporter'); },
  get cveDriftService() { return require('../server/services/cveDriftService'); }
};

function runSpawnStep(bin, args, cwd) {
  return new Promise((/** @type {(v?: void) => void} */ resolve, reject) => {
    const isWin = process.platform === 'win32';
    const cmd = isWin && bin === 'npm' ? 'cmd.exe' : bin;
    const argv = isWin && bin === 'npm' ? ['/c', 'npm', ...args] : args;
    const child = spawn(cmd, argv, { cwd, stdio: 'inherit', shell: false });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${bin} ${args.join(' ')} terminó con código ${code}`));
    });
  });
}

const program = new Command();

program
  .name('culkibo')
  .description('Culkibo — Orquestador cloud autohospedado para desarrollar con agentes de IA')
  .version('1.0.0')
  .option('--json', 'Salida estructurada en JSON (scripts, CI/CD y agentes de IA)')
  .option('--api-url <url>', 'URL del daemon/VPS Culkibo remoto (o env CULKIBO_API_URL)')
  .option('--token <token>', 'Token Bearer de autenticación (o env CULKIBO_TOKEN)');

/** @param {any} [cmdOpts] */
function isJsonMode(cmdOpts) {
  return Boolean((cmdOpts && cmdOpts.json) || program.opts().json);
}

/** @param {any} payload */
function printJson(payload) {
  process.stdout.write(JSON.stringify(payload, null, 2) + '\n');
}

/** @param {any} err @param {any} [cmdOpts] */
function failCli(err, cmdOpts) {
  const message = err && err.message ? err.message : String(err);
  const code = err && err.code ? String(err.code) : 'CLI_ERROR';
  if (isJsonMode(cmdOpts)) {
    printJson({ ok: false, error: message, code });
  } else {
    console.error(`\x1b[31m❌ ${message}\x1b[0m`);
  }
  process.exitCode = 1;
}

/** @param {any} [cmdOpts] */
function getRemoteConfig(cmdOpts) {
  const rootOpts = program.opts();
  const rawUrl = String((cmdOpts && cmdOpts.apiUrl) || rootOpts.apiUrl || process.env.CULKIBO_API_URL || '').trim().replace(/\/+$/, '');
  const token = String((cmdOpts && cmdOpts.token) || rootOpts.token || process.env.CULKIBO_TOKEN || '').trim();
  return { apiUrl: rawUrl || null, token: token || null };
}

/**
 * Invoca la API HTTP del daemon/VPS Culkibo cuando `CULKIBO_API_URL` o `--api-url` está activo.
 * @param {{ apiUrl: string | null, token: string | null }} remote
 * @param {string} method
 * @param {string} apiPath
 * @param {any} [body]
 * @returns {Promise<any>}
 */
async function remoteApiRequest(remote, method, apiPath, body) {
  const base = String(remote.apiUrl || '').replace(/\/api$/, '');
  const url = `${base}${apiPath.startsWith('/') ? apiPath : `/${apiPath}`}`;
  /** @type {Record<string, string>} */
  const headers = { Accept: 'application/json' };
  if (remote.token) headers.Authorization = `Bearer ${remote.token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(url, {
    method,
    headers,
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(30000)
  });
  const text = await res.text();
  /** @type {any} */
  let parsed = null;
  try { parsed = text ? JSON.parse(text) : null; } catch (e) { parsed = { raw: text }; }
  if (!res.ok) {
    const err = new Error((parsed && (parsed.error || parsed.message)) || `HTTP ${res.status} en ${method} ${apiPath}`);
    /** @type {any} */ (err).status = res.status;
    /** @type {any} */ (err).code = (parsed && parsed.code) || `HTTP_${res.status}`;
    throw err;
  }
  return parsed;
}

/** Lee stdin completo (para `culkibo env set <project> --stdin KEY`). */
function readStdinText() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => resolve(data.replace(/\r?\n$/, '')));
    process.stdin.on('error', reject);
  });
}

/** Parsea pares `KEY=VALUE` de argumentos CLI. @param {string[]} pairs */
function parseEnvAssignments(pairs) {
  /** @type {Record<string, string>} */
  const out = {};
  for (const raw of pairs || []) {
    const str = String(raw || '');
    const eq = str.indexOf('=');
    if (eq <= 0) {
      throw new Error(`Formato inválido "${str}". Usa CLAVE=VALOR.`);
    }
    const key = str.slice(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(key)) {
      throw new Error(`Nombre de variable inválido: "${key}"`);
    }
    out[key] = str.slice(eq + 1);
  }
  return out;
}

/**
 * Autodetecta el stack de un directorio local (Node/Next/Nuxt/SvelteKit/Astro/Vite/Bun,
 * Python uv/Poetry/pip, Go, Rust, Deno, PHP/Laravel, Elixir, Java, Dockerfile, Compose,
 * Fly.io, Render, Heroku) sin dependencias externas.
 * @param {string} targetDir
 */
function detectLocalStack(targetDir) {
  const dir = path.resolve(targetDir || process.cwd());
  const entries = fs.existsSync(dir) ? fs.readdirSync(dir) : [];
  const lowerSet = new Set(entries.map((e) => e.toLowerCase()));
  const baseName = path.basename(dir) || 'culkibo-app';
  const cleanName = baseName.replace(/[^a-zA-Z0-9 _-]/g, '-').trim().slice(0, 80) || 'culkibo-app';
  const slugId = `proj_${baseName.toLowerCase().replace(/[^a-z0-9_-]+/g, '_').replace(/^[^a-z0-9]+|_+$/g, '').slice(0, 48) || 'app'}`;

  /** @type {any} */
  const info = {
    dir,
    id: slugId,
    name: cleanName,
    framework: 'generic',
    runtime: 'unknown',
    packageManager: null,
    buildCommand: '',
    startCommand: '',
    containerPort: 3000,
    healthPath: '/',
    detectedFiles: [],
    recommendedDatabases: [],
    env: {},
    vaultRefs: []
  };

  if (lowerSet.has('bun.lockb') || lowerSet.has('bun.lock')) info.packageManager = 'bun';
  else if (lowerSet.has('pnpm-lock.yaml')) info.packageManager = 'pnpm';
  else if (lowerSet.has('yarn.lock')) info.packageManager = 'yarn';
  else if (lowerSet.has('package-lock.json')) info.packageManager = 'npm';

  const runPrefix = info.packageManager === 'bun' ? 'bun run'
    : info.packageManager === 'pnpm' ? 'pnpm'
    : info.packageManager === 'yarn' ? 'yarn'
    : 'npm run';

  if (lowerSet.has('dockerfile')) {
    info.framework = 'Dockerfile';
    info.runtime = 'docker';
    info.containerPort = 8080;
    info.detectedFiles.push('Dockerfile');
  }

  if (lowerSet.has('package.json')) {
    info.detectedFiles.push('package.json');
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
      if (pkg.name && typeof pkg.name === 'string') {
        info.name = pkg.name.replace(/^@[^/]+\//, '').slice(0, 80) || info.name;
      }
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      const scripts = pkg.scripts || {};
      info.runtime = info.packageManager === 'bun' ? 'bun' : 'node';
      if (deps.next || lowerSet.has('next.config.js') || lowerSet.has('next.config.mjs') || lowerSet.has('next.config.ts')) {
        info.framework = 'Next.js';
        info.buildCommand = scripts.build ? `${runPrefix} build` : 'npm run build';
        info.startCommand = scripts.start ? `${runPrefix} start` : 'npm start';
        info.containerPort = 3000;
      } else if (deps.nuxt || lowerSet.has('nuxt.config.ts') || lowerSet.has('nuxt.config.js')) {
        info.framework = 'Nuxt';
        info.buildCommand = `${runPrefix} build`;
        info.startCommand = 'node .output/server/index.mjs';
        info.containerPort = 3000;
      } else if (deps['@sveltejs/kit'] || lowerSet.has('svelte.config.js')) {
        info.framework = 'SvelteKit';
        info.buildCommand = `${runPrefix} build`;
        info.startCommand = 'node build/index.js';
        info.containerPort = 3000;
      } else if (deps.astro || lowerSet.has('astro.config.mjs') || lowerSet.has('astro.config.ts')) {
        info.framework = 'Astro';
        info.buildCommand = `${runPrefix} build`;
        info.startCommand = scripts.start ? `${runPrefix} start` : 'node ./dist/server/entry.mjs';
        info.containerPort = 4321;
      } else if (deps.vite || lowerSet.has('vite.config.ts') || lowerSet.has('vite.config.js')) {
        info.framework = 'Vite';
        info.buildCommand = `${runPrefix} build`;
        info.startCommand = scripts.preview ? `${runPrefix} preview` : '';
        info.containerPort = 4173;
      } else if (info.framework === 'generic') {
        info.framework = 'Node.js';
        if (scripts.build) info.buildCommand = `${runPrefix} build`;
        info.startCommand = scripts.start ? (info.packageManager === 'npm' || !info.packageManager ? 'npm start' : `${runPrefix} start`) : (pkg.main ? `node ${pkg.main}` : 'node index.js');
        info.containerPort = 3000;
      }
    } catch (e) {}
  } else if (lowerSet.has('pyproject.toml') || lowerSet.has('requirements.txt')) {
    info.runtime = 'python';
    info.framework = lowerSet.has('uv.lock') ? 'Python (uv)' : lowerSet.has('poetry.lock') ? 'Python (Poetry)' : 'Python';
    info.containerPort = 8000;
    info.buildCommand = lowerSet.has('uv.lock') ? 'uv sync --frozen' : 'pip install -r requirements.txt';
    info.startCommand = lowerSet.has('manage.py') ? 'gunicorn app.wsgi:application --bind 0.0.0.0:8000' : 'uvicorn main:app --host 0.0.0.0 --port 8000';
    info.detectedFiles.push(lowerSet.has('pyproject.toml') ? 'pyproject.toml' : 'requirements.txt');
  } else if (lowerSet.has('go.mod')) {
    info.runtime = 'go';
    info.framework = 'Go';
    info.buildCommand = 'go build -o server .';
    info.startCommand = './server';
    info.containerPort = 8080;
    info.detectedFiles.push('go.mod');
  } else if (lowerSet.has('cargo.toml')) {
    info.runtime = 'rust';
    info.framework = 'Rust';
    info.buildCommand = 'cargo build --release';
    info.startCommand = './target/release/app';
    info.containerPort = 8080;
    info.detectedFiles.push('Cargo.toml');
  } else if (lowerSet.has('deno.json') || lowerSet.has('deno.jsonc')) {
    info.runtime = 'deno';
    info.framework = 'Deno';
    info.startCommand = 'deno run --allow-net --allow-env main.ts';
    info.containerPort = 8000;
    info.detectedFiles.push('deno.json');
  } else if (lowerSet.has('composer.json')) {
    info.runtime = 'php';
    info.framework = lowerSet.has('artisan') ? 'Laravel' : 'PHP';
    info.containerPort = 8080;
    info.detectedFiles.push('composer.json');
  } else if (lowerSet.has('mix.exs')) {
    info.runtime = 'elixir';
    info.framework = 'Elixir / Phoenix';
    info.containerPort = 4000;
    info.detectedFiles.push('mix.exs');
  } else if (lowerSet.has('pom.xml') || lowerSet.has('build.gradle') || lowerSet.has('build.gradle.kts')) {
    info.runtime = 'java';
    info.framework = lowerSet.has('pom.xml') ? 'Java (Maven)' : 'Java (Gradle)';
    info.containerPort = 8080;
    info.detectedFiles.push(lowerSet.has('pom.xml') ? 'pom.xml' : 'build.gradle');
  } else if (lowerSet.has('index.html')) {
    info.runtime = 'static';
    info.framework = 'Static HTML';
    info.containerPort = 80;
    info.detectedFiles.push('index.html');
  }

  // Enriquecer con configuración existente de plataforma si existe en el directorio
  for (const candidate of ['fly.toml', 'Procfile', 'render.yaml', 'railway.toml', 'railway.json']) {
    const p = path.join(dir, candidate);
    if (fs.existsSync(p) && fs.statSync(p).isFile()) {
      info.detectedFiles.push(candidate);
      try {
        const parsed = svc.universalImporter.parsePlatformConfig({ platform: 'auto', configText: fs.readFileSync(p, 'utf8') });
        if (parsed.healthPath && parsed.healthPath !== '/') info.healthPath = parsed.healthPath;
        if (parsed.port && info.framework === 'generic') info.containerPort = parsed.port;
        if (parsed.startCommand && !info.startCommand) info.startCommand = parsed.startCommand;
        if (parsed.buildCommand && !info.buildCommand) info.buildCommand = parsed.buildCommand;
      } catch (e) {}
    }
  }

  // Leer claves de .env.example o .env (JÁMAS escribir secretos en claro en culkibo.yaml)
  for (const envName of ['.env.example', '.env']) {
    const ep = path.join(dir, envName);
    if (fs.existsSync(ep) && fs.statSync(ep).isFile()) {
      info.detectedFiles.push(envName);
      try {
        const { envVars, recommendedDatabases } = svc.universalImporter.parseEnvText(fs.readFileSync(ep, 'utf8'));
        for (const db of recommendedDatabases) {
          if (!info.recommendedDatabases.some((d) => d.engine === db.engine)) {
            info.recommendedDatabases.push(db);
          }
        }
        const gitops = svc.gitopsManager;
        for (const [k, v] of Object.entries(envVars)) {
          if (info.env[k] !== undefined) continue;
          if (gitops.shouldRedactEnvForGit(k, v, false)) {
            info.env[k] = `\${vault.${k}}`;
            if (!info.vaultRefs.includes(k)) info.vaultRefs.push(k);
          } else {
            info.env[k] = v;
          }
        }
      } catch (e) {}
    }
  }

  info.vaultRefs.sort();
  return info;
}

/** Genera un manifiesto `culkibo.yaml` v1 seguro y validado a partir de la detección local. */
function generateStarterManifest(detected, opts = {}) {
  const gitops = svc.gitopsManager;
  const projectName = String(opts.name || detected.name || 'culkibo-app').trim().slice(0, 80);
  const projectId = `proj_${projectName.toLowerCase().replace(/[^a-z0-9_-]+/g, '_').replace(/^[^a-z0-9]+|_+$/g, '').slice(0, 48) || 'app'}`;
  const stackName = `${projectName.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 56) || 'app'}-stack`;

  /** @type {Record<string, any>} */
  const proj = {
    id: projectId,
    name: projectName,
    gitBranch: 'main',
    serverId: 'local',
    autoDeploy: true,
    containerPort: Number(detected.containerPort) || 3000
  };
  if (detected.buildCommand) proj.buildCommand = detected.buildCommand;
  if (detected.startCommand) proj.startCommand = detected.startCommand;
  if (detected.healthPath && detected.healthPath !== '/') proj.healthPath = detected.healthPath;
  if (detected.env && Object.keys(detected.env).length > 0) proj.env = detected.env;

  const databases = (detected.recommendedDatabases || [])
    .filter((d) => ['postgres', 'mysql', 'mariadb', 'valkey', 'redis', 'mongodb'].includes(d.engine))
    .map((d) => ({
      name: `${projectId.replace(/^proj_/, '').slice(0, 32)}_${d.engine}`,
      engine: d.engine,
      projectId,
      generateSecret: true
    }));

  /** @type {Record<string, any>} */
  const manifest = {
    version: 1,
    name: stackName,
    ...(detected.vaultRefs && detected.vaultRefs.length > 0 ? { vaultRefs: detected.vaultRefs } : {}),
    projects: [proj],
    ...(databases.length > 0 ? { databases } : {})
  };

  const schemaUrl = opts.schemaUrl || 'http://127.0.0.1:3030/api/gitops/schema.json';
  const yaml = `# yaml-language-server: $schema=${schemaUrl}\n${gitops.serializeSafeYaml(manifest, 0)}\n`;
  // Auto-validar con nuestro parser estricto
  gitops.validateManifest(gitops.parseSafeYaml(yaml));
  return { manifest, yaml, projectId, stackName };
}

// Comando start
program
  .command('start')
  .description('Inicia el demonio de Culkibo Orchestrator y el panel de control web')
  .option('-p, --port <port>', 'Puerto del servidor', '3030')
  .option('-w, --watch [dir]', 'Activar la vigilancia de ficheros para el entorno de Desarrollo')
  .action(async (options) => {
    process.env.PORT = options.port;
    if (options.watch) {
      process.env.CULKIBO_WATCH_DIR = options.watch === true ? process.cwd() : options.watch;
    }
    const { startServer, shutdown } = require('../server/index');
    const bindHost = process.env.CULKIBO_BIND || process.env.HOST || process.env.CULKIBO_HOST || '127.0.0.1';
    try {
      await startServer(parseInt(options.port, 10) || 3030, bindHost);
      for (const sig of ['SIGINT', 'SIGTERM']) {
        process.once(sig, () => {
          shutdown(sig).finally(() => process.exit(0));
        });
      }
    } catch (err) {
      console.error(`\x1b[31m❌ No se pudo iniciar el demonio de Culkibo:\x1b[0m`, err.message);
      process.exit(1);
    }
  });

// Comando status
program
  .command('status')
  .description('Muestra el estado operativo del demonio de Culkibo')
  .option('-p, --port <port>', 'Puerto del daemon', process.env.PORT || '3030')
  .option('--json', 'Salida JSON')
  .action(async (options) => {
    const port = parseInt(options.port, 10) || 3030;
    const remote = getRemoteConfig(options);
    const targetUrl = remote.apiUrl ? `${remote.apiUrl.replace(/\/api$/, '')}/api/health` : `http://127.0.0.1:${port}/api/health`;
    /** @type {Record<string, string>} */
    const headers = remote.token ? { Authorization: `Bearer ${remote.token}` } : {};
    try {
      const res = await fetch(targetUrl, { headers, signal: AbortSignal.timeout(5000) });
      const data = await res.json().catch(() => ({}));
      if (isJsonMode(options)) {
        printJson({ ok: res.ok, status: res.status, url: targetUrl, health: data });
        if (!res.ok) process.exitCode = 1;
        return;
      }
      if (res.ok) {
        console.log(`\x1b[32m✅ Culkibo está en ejecución y saludable en ${targetUrl.replace('/api/health', '')} (HTTP 200).\x1b[0m`);
      } else {
        console.log(`\x1b[33m⚠️ Culkibo responde en ${targetUrl} pero reporta estado HTTP ${res.status}.\x1b[0m`);
        process.exitCode = 1;
      }
    } catch (err) {
      if (isJsonMode(options)) {
        printJson({ ok: false, url: targetUrl, error: err && err.message ? err.message : String(err) });
      } else {
        console.log(`\x1b[31m❌ Culkibo está detenido o inalcanzable en ${targetUrl}.\x1b[0m`);
      }
      process.exitCode = 1;
    }
  });

// Comando token (rotación / verificación segura por SSH)
const tokenCmd = program.command('token').description('Gestiona el token maestro del plano de control');
tokenCmd
  .command('rotate')
  .description('Rota de forma atómica el token maestro en data/auth.json')
  .action(() => {
    try {
      const { rotateToken } = require('../server/middleware/auth');
      const res = rotateToken();
      console.log('\x1b[32m✅ Token maestro rotado correctamente.\x1b[0m');
      console.log(`   Origen:     ${res.tokenSource}`);
      console.log(`   Rotado en:  ${res.rotatedAt}`);
      console.log(`   Nuevo token: ${res.token}`);
      console.log('   Nota: Si el daemon está corriendo en otro proceso, reinícialo o rota desde el panel web.\n');
    } catch (err) {
      console.error(`\x1b[31m❌ No se pudo rotar el token:\x1b[0m ${err.message}`);
      process.exit(1);
    }
  });

// Comando stop
program
  .command('stop')
  .description('Instrucciones para detener el demonio de Culkibo')
  .action(() => {
    console.log('\x1b[33m🛑 Para detener el servidor, presione Ctrl+C en la terminal activa o termine el proceso de Node con Stop-Process / kill.\x1b[0m');
  });

// Comando doctor (reutiliza systemDoctor.runDoctor() con opción --fix y --json)
program
  .command('doctor')
  .description('Ejecuta el diagnóstico real completo del sistema (Node, Docker, Caddy, disco, RAM, TLS, seguridad)')
  .option('--fix <action>', 'Ejecuta una remediación automática (reconcile_caddy | start_caddy | clean_tmp | clean_orphans | prune_buildkit)')
  .option('--json', 'Salida JSON estructurada (exit code 1 si hay fallos)')
  .action(async (options) => {
    const remote = getRemoteConfig(options);
    if (options.fix) {
      try {
        const fixRes = remote.apiUrl
          ? await remoteApiRequest(remote, 'POST', '/api/system/doctor/fix', { action: options.fix })
          : await require('../server/services/systemDoctor').applyFix(options.fix);
        if (isJsonMode(options)) {
          printJson({ ok: true, action: options.fix, ...fixRes });
        } else {
          console.log(`\x1b[32m✅ ${fixRes.message}\x1b[0m`);
        }
      } catch (err) {
        failCli(err, options);
      }
      return;
    }

    try {
      const report = remote.apiUrl
        ? await remoteApiRequest(remote, 'GET', '/api/system/doctor')
        : await require('../server/services/systemDoctor').runDoctor();
      const failCount = Number(report?.summary?.fail || 0);
      if (isJsonMode(options)) {
        printJson({ ok: failCount === 0, ...report });
        if (failCount > 0) process.exitCode = 1;
        return;
      }
      console.log('\n\x1b[36m🩺 DIAGNÓSTICO INTEGRAL DE CULKIBO\x1b[0m');
      console.log('==================================================');
      for (const c of report.checks || []) {
        const badge = c.status === 'ok'
          ? '\x1b[32m  ✓\x1b[0m'
          : c.status === 'warn'
            ? '\x1b[33m  ⚠\x1b[0m'
            : '\x1b[31m  ✗\x1b[0m';
        console.log(`${badge} \x1b[1m${c.name}:\x1b[0m ${c.summary}`);
        if (c.status !== 'ok') {
          console.log(`      ${c.detail}`);
          if (c.fixAction) {
            console.log(`      \x1b[36m→ Solución 1 clic:\x1b[0m culkibo doctor --fix ${c.fixAction}`);
          }
        }
      }
      console.log('==================================================');
      console.log(`Resumen: ${report.summary.ok} OK · ${report.summary.warn} avisos · ${failCount} fallos (${report.durationMs} ms)\n`);
      if (failCount > 0) process.exitCode = 1;
    } catch (err) {
      failCli(err, options);
    }
  });

// Comando watch
program
  .command('watch [directorio]')
  .description('Vigila un directorio y notifica los cambios al entorno de Desarrollo')
  .action((directorio = process.cwd()) => {
    try {
      const containerOrchestrator = svc.containerOrchestrator;
      const res = containerOrchestrator.watchDirectory(directorio);
      console.log(`\n⚡ [Desarrollo] Monitoreando ${res.directory} (${res.fileWatchersActive} rutas vigiladas)`);
      console.log(`   Vigilancia activa. Los cambios se detectan y registran; para sincronizar con un daemon usa "culkibo sync <projectId>".\n`);

      containerOrchestrator.on('pod_change', (pod) => {
        if (pod.lastHotReloadMs) {
          console.log(`✨ Delta sincronizado en ${pod.lastHotReloadMs}ms | Recargas totales: ${pod.hotReloadsCount}`);
        }
      });
      containerOrchestrator.on('log', (log) => {
        if (log.level === 'HOT_SYNC' || log.level === 'SUCCESS') {
          console.log(`  [${log.level}] ${log.message}`);
        }
      });
    } catch (err) {
      console.error(`❌ Error en el observador: ${err.message}`);
      process.exit(1);
    }
  });

// Grupo de comandos para Pods / Entornos
const podCmd = program.command('pod').description('Gestión de entornos de Desarrollo y Producción');

podCmd
  .command('list')
  .description('Muestra el estado y métricas en tiempo real de los entornos')
  .option('--json', 'Salida JSON')
  .action(async (options) => {
    try {
      const remote = getRemoteConfig(options);
      const data = remote.apiUrl
        ? await remoteApiRequest(remote, 'GET', '/api/pods')
        : svc.containerOrchestrator.getPods();
      if (isJsonMode(options)) return printJson({ ok: true, ...data });
      console.log('\n--- Estado de Entornos Culkibo ---');
      console.table([
        {
          Entorno: 'Desarrollo (:3001)',
          Estado: data.pods.forge.status === 'running' ? 'Activo' : data.pods.forge.status,
          Latencia: `${data.pods.forge.latencyMs}ms`,
          CPU: `${data.pods.forge.cpuPercent}%`,
          Memoria: `${data.pods.forge.memoryMb}MB`,
          Puerto: data.pods.forge.port,
          Tráfico: `${data.trafficAllocation.forge}%`
        },
        {
          Entorno: 'Producción (:8080)',
          Estado: data.pods.citadel.status === 'running' ? 'Activo' : data.pods.citadel.status,
          Latencia: `${data.pods.citadel.latencyMs}ms`,
          CPU: `${data.pods.citadel.cpuPercent}%`,
          Memoria: `${data.pods.citadel.memoryMb}MB`,
          Puerto: data.pods.citadel.port,
          Tráfico: `${data.trafficAllocation.citadel}%`
        }
      ]);
    } catch (err) {
      failCli(err, options);
    }
  });

podCmd
  .command('sync')
  .description('Dispara manualmente la detección de un cambio')
  .option('-f, --file <file>', 'Archivo modificado', 'src/app.ts')
  .action(async (options) => {
    console.log(`[Culkibo CLI] Disparando sincronización en caliente para ${options.file}...`);
    const res = await svc.containerOrchestrator.triggerHotSync({ changedFile: options.file });
    console.log(`✨ Sincronizado en ${res.syncDurationMs}ms. Recargas totales: ${res.reloadsTotal}`);
  });

podCmd
  .command('switch <objetivo>')
  .description('Conmuta el tráfico: "desarrollo", "produccion", o reparto e.g. "50/50"')
  .action(async (objetivo) => {
    let forge = 0;
    let citadel = 100;
    const lower = objetivo.toLowerCase();
    if (lower === 'desarrollo' || lower === 'forge') {
      forge = 100;
      citadel = 0;
    } else if (lower === 'produccion' || lower === 'citadel') {
      forge = 0;
      citadel = 100;
    } else if (objetivo.includes('/')) {
      const parts = objetivo.split('/');
      forge = parseInt(parts[0], 10) || 0;
      citadel = parseInt(parts[1], 10) || (100 - forge);
    }
    const res = await svc.containerOrchestrator.switchTraffic({ forgePercent: forge, citadelPercent: citadel });
    console.log(`Tráfico enrutado: ${res.trafficAllocation.citadel}% Producción / ${res.trafficAllocation.forge}% Desarrollo (en ${res.switchDurationMs}ms)`);
  });

// Grupo de comandos para Dominios y SSL
const domainCmd = program.command('domain').description('Gestión de dominios, Cloudflare y certificados SSL');

domainCmd
  .command('list')
  .description('Lista los dominios configurados y el estado de sus certificados')
  .option('--json', 'Salida JSON')
  .action(async (options) => {
    try {
      const remote = getRemoteConfig(options);
      const raw = remote.apiUrl
        ? await remoteApiRequest(remote, 'GET', '/api/domains')
        : svc.domainManager.listDomains();
      const domains = Array.isArray(raw) ? raw : (raw?.domains || []);
      if (isJsonMode(options)) return printJson({ ok: true, count: domains.length, domains });
      console.log('\n--- Dominios Configurados en Culkibo ---');
      console.table(domains.map(d => ({
        Dominio: d.hostname,
        Entorno: d.targetPod === 'forge' ? 'Desarrollo' : 'Producción',
        Puerto: d.targetPort,
        Cloudflare: d.cloudflareProxied ? 'Proxy Activo (Nube Naranja ☁️)' : 'Solo DNS',
        SSL: d.sslStatus === 'active' ? 'Activo' : d.sslStatus,
        Validez: d.certClaim && d.certClaim.daysRemaining != null ? `${d.certClaim.daysRemaining} días` : 'N/D'
      })));
    } catch (err) {
      failCli(err, options);
    }
  });

domainCmd
  .command('add <hostname>')
  .description('Añade un nuevo dominio o subdominio comodín (*.dominio.com)')
  .option('--pod <pod>', 'Entorno destino (forge o citadel)', 'citadel')
  .option('--port <port>', 'Puerto destino', '8080')
  .option('--no-proxy', 'Desactivar proxy de Cloudflare')
  .action(async (hostname, options) => {
    try {
      const res = await svc.domainManager.addDomain({
        hostname,
        targetPod: options.pod,
        targetPort: options.port,
        cloudflareProxied: options.proxy
      });
      console.log(`✨ Dominio ${res.hostname} añadido con éxito.`);
    } catch (err) {
      console.error(`❌ Error al añadir dominio: ${err.message}`);
      process.exitCode = 1;
    }
  });

domainCmd
  .command('issue-wildcard <dominio>')
  .description('(No implementado) Emisión de comodín por ACME DNS-01')
  .action(async (dominio) => {
    const res = await svc.sslManager.issueWildcardCertificate({ domain: dominio });
    console.error(`❌ ${res.error}`);
    console.error('\n   Alternativa: configura Wildcard DNS-01 en Caddy con POST /api/ingress/wildcard-dns01 o desde el panel Dominios.');
    process.exitCode = 1;
  });

domainCmd
  .command('toggle-proxy <idODominio>')
  .description('Alterna el proxy de Cloudflare (Nube Naranja vs Solo DNS)')
  .action(async (idODominio) => {
    try {
      const domains = svc.domainManager.listDomains();
      const match = domains.find(d => d.id === idODominio || d.hostname === idODominio);
      if (!match) {
        console.error(`❌ Dominio "${idODominio}" no encontrado.`);
        process.exit(1);
      }
      const updated = await svc.domainManager.toggleProxy(match.id);
      console.log(`✨ Dominio ${updated.hostname}: ${updated.cloudflareProxied ? 'Proxy Cloudflare Activado (Nube Naranja ☁️)' : 'Solo DNS (Nube Gris ☁️)'}`);
    } catch (err) {
      console.error(`❌ Error al alternar proxy: ${err.message}`);
      process.exitCode = 1;
    }
  });

domainCmd
  .command('delete <idODominio>')
  .description('Elimina un dominio configurado')
  .action(async (idODominio) => {
    try {
      const domains = svc.domainManager.listDomains();
      const match = domains.find(d => d.id === idODominio || d.hostname === idODominio);
      if (!match) {
        console.error(`❌ Dominio "${idODominio}" no encontrado.`);
        process.exit(1);
      }
      await svc.domainManager.deleteDomain(match.id);
      console.log(`✨ Dominio ${match.hostname} eliminado con éxito.`);
    } catch (err) {
      console.error(`❌ Error al eliminar dominio: ${err.message}`);
      process.exitCode = 1;
    }
  });

// Comandos de Backup y Restauración (proyectos + bases de datos gestionadas)
program
  .command('backup [projectId]')
  .description('Genera o lista respaldos exportables de un proyecto o base de datos (--db <dbId>)')
  .option('--db <dbId>', 'Ejecutar o listar respaldo de una base de datos gestionada')
  .option('--list', 'Listar respaldos existentes sin crear uno nuevo')
  .option('--json', 'Salida JSON')
  .action(async (projectId, options) => {
    try {
      const remote = getRemoteConfig(options);
      if (options.db) {
        const dbId = String(options.db).trim();
        if (options.list) {
          const backups = remote.apiUrl
            ? await remoteApiRequest(remote, 'GET', `/api/databases/${encodeURIComponent(dbId)}/backups`)
            : svc.databaseManager.listBackups(dbId);
          if (isJsonMode(options)) return printJson({ ok: true, dbId, backups });
          const rows = Array.isArray(backups) ? backups : (backups?.backups || []);
          console.table(rows.map((b) => ({
            ID: b.id,
            Archivo: b.fileName || b.name || '—',
            TamanoBytes: b.sizeBytes ?? '—',
            Cifrado: b.encrypted ? 'AES-GCM' : 'no',
            Fecha: b.createdAt || '—'
          })));
          return;
        }
        const res = remote.apiUrl
          ? await remoteApiRequest(remote, 'POST', `/api/databases/${encodeURIComponent(dbId)}/backups`, { trigger: 'cli' })
          : await svc.databaseManager.runBackup(dbId, { trigger: 'cli' });
        if (isJsonMode(options)) return printJson({ ok: true, dbId, backup: res });
        console.log(`\x1b[32m✅ Backup de BD ${dbId} generado:\x1b[0m ${res.fileName || res.id || 'OK'}`);
        return;
      }

      if (options.list) {
        const backups = remote.apiUrl
          ? await remoteApiRequest(remote, 'GET', '/api/backup/list')
          : await svc.dbBackupManager.listBackups();
        if (isJsonMode(options)) return printJson({ ok: true, backups });
        const rows = Array.isArray(backups) ? backups : (backups?.backups || []);
        console.table(rows.map((b) => ({
          Archivo: b.fileName || b.name || b,
          Proyecto: b.projectId || '—',
          Tamano: b.sizeBytes ?? '—',
          Fecha: b.createdAt || '—'
        })));
        return;
      }

      if (!projectId) {
        throw new Error('Especifica <projectId>, --db <dbId> o --list');
      }
      if (!isJsonMode(options)) console.log(`[Culkibo Backup] Exportando proyecto ${projectId}...`);
      const res = remote.apiUrl
        ? await remoteApiRequest(remote, 'POST', `/api/backup/export/${encodeURIComponent(projectId)}`, {})
        : await svc.dbBackupManager.exportProject(projectId);
      if (isJsonMode(options)) return printJson({ ok: true, ...res });
      console.log(`\x1b[32m✅ Respaldo generado con éxito:\x1b[0m ${res.fullPath || res.fileName || 'OK'}`);
      console.log(`   Recursos: ${res.resourcesCount ?? 0} | Dominios: ${res.domainsCount ?? 0}`);
    } catch (err) {
      failCli(err, options);
    }
  });

program
  .command('restore <archivoBackup>')
  .description('Restaura un proyecto a partir de un archivo de respaldo JSON')
  .action(async (archivoBackup) => {
    try {
      console.log(`[Culkibo Restore] Restaurando desde ${archivoBackup}...`);
      const res = await svc.dbBackupManager.restoreProject(archivoBackup, { allowExternalPath: true });
      console.log(`\x1b[32m✅ Proyecto restaurado con éxito:\x1b[0m ${res.restoredName} (ID: ${res.restoredProjectId})`);
    } catch (err) {
      console.error(`❌ Error al restaurar proyecto:`, err.message);
      process.exitCode = 1;
    }
  });

// Grupo Docker
const dockerCmd = program.command('docker').description('Comandos de inspección del motor Docker');

dockerCmd
  .command('status')
  .description('Comprueba la conexión con el daemon de Docker')
  .option('--json', 'Salida JSON')
  .action(async (options) => {
    try {
      const status = await svc.dockerManager.checkDockerStatus(true);
      if (isJsonMode(options)) return printJson({ ok: true, ...status });
      console.log('\n--- Estado del Motor Docker ---');
      console.log(`Modo:         ${status.mode === 'docker_native' ? '\x1b[32mNativo (Docker Daemon)\x1b[0m' : '\x1b[33mSandbox de Procesos Ultrarrápido\x1b[0m'}`);
      console.log(`Versión:      ${status.clientVersion || 'N/D'}`);
      console.log(`Contenedores: ${status.containersRunning || 0} activos`);
      console.log(`Mensaje:      ${status.message}\n`);
    } catch (err) {
      failCli(err, options);
    }
  });

dockerCmd
  .command('list')
  .description('Lista contenedores en ejecución')
  .option('--json', 'Salida JSON')
  .action(async (options) => {
    try {
      const list = await svc.dockerManager.listContainers({ all: false });
      if (isJsonMode(options)) return printJson({ ok: true, count: list.length, containers: list });
      console.log('\n--- Contenedores Activos ---');
      console.table(list.map(c => ({
        ID: c.id?.substring(0, 12) || 'N/D',
        Imagen: c.image || 'N/D',
        Estado: c.status || c.state || 'Up',
        Puertos: c.ports || 'N/D',
        Modo: c.mode || 'N/D'
      })));
    } catch (err) {
      failCli(err, options);
    }
  });

// Ingress resolution inspector
program
  .command('ingress <hostname>')
  .description('Inspecciona el enrutamiento y SSL para una cabecera Host entrante')
  .action((hostname) => {
    const route = svc.domainManager.resolveRoute(hostname);
    if (!route) {
      console.log(`\n❌ No hay ruta asignada para "${hostname}".`);
      return;
    }
    const cert = svc.sslManager.getCertificateByDomain(hostname);
    const traffic = svc.containerOrchestrator.trafficAllocation;
    console.log(`\n--- Inspector de Enrutamiento Ingress: ${hostname} ---`);
    console.table([
      {
        HostEntrada: hostname,
        Regla: route.hostname,
        Tipo: route.isWildcard ? 'Comodín (*)' : 'Exacto',
        Entorno: route.targetPod === 'forge' ? 'Desarrollo (:3001)' : 'Producción (:8080)',
        Cloudflare: route.cloudflareProxied ? 'Proxy (Nube Naranja ☁️)' : 'Solo DNS',
        TLS: cert
          ? (cert.managedBy ? 'Delegado en Caddy (bajo demanda)' : `En disco (${cert.issuer || 'emisor desconocido'})`)
          : 'Sin anotación en el registro',
        RepartoTráfico: `${traffic.citadel}% Prod / ${traffic.forge}% Dev`
      }
    ]);
  });

// Live Sync (The Forge): sincronización local -> daemon en milisegundos
program
  .command('sync <projectId> [directorio]')
  .description('Sincroniza un directorio local en tiempo real vía Commit Frames + Merkle hacia el daemon')
  .option('-u, --url <wsUrl>', 'URL del WebSocket del daemon', process.env.CULKIBO_SYNC_URL || 'ws://127.0.0.1:3030/ws/sync')
  .option('-t, --token <token>', 'Token de autenticación (CULKIBO_TOKEN)', process.env.CULKIBO_TOKEN || '')
  .option('--ticket <ticket>', 'Ticket temporal de un solo uso para Live Sync')
  .option('-q, --quiescence <ms>', 'Ventana de agrupación de ráfagas en ms', '12')
  .option('--no-reconcile', 'Omitir la reconciliación Merkle inicial al conectar')
  .action(async (projectId, directorio = process.cwd(), options) => {
    const client = new svc.LiveSyncClient({
      projectId,
      sourceDir: directorio,
      wsUrl: options.url,
      token: options.ticket ? null : (options.token || null),
      ticket: options.ticket || null,
      quiescenceMs: parseInt(options.quiescence, 10) || 12
    });

    client.on('frame_ack', (ack) => {
      const comp = ack.wireStats && ack.wireStats.savedPct > 0 ? ` · compresión -${ack.wireStats.savedPct}% (${ack.wireStats.codec})` : '';
      console.log(`⚡ [Forge] Frame #${ack.seq} · ${ack.written} escritos, ${ack.deleted} borrados, ${ack.dedupSkipped} sin cambios · ${ack.applyMs} ms [${ack.mode}]${comp}`);
    });
    client.on('sync_conflict', (conflict) => {
      console.warn(`\x1b[33m⚠️  [Forge:Conflicto] ${conflict.path} modificado también por ${conflict.otherClientName || 'otro cliente'} (rev #${conflict.previousSeq || '?'})\x1b[0m`);
    });
    client.on('sync_error', (err) => {
      console.error(`❌ [Forge] ${err.message}`);
    });
    client.on('error', (err) => {
      console.error(`❌ [Forge:Watcher] ${err.message}`);
    });

    const stopSync = async () => {
      await client.stop();
      process.exit(0);
    };

    try {
      await client.start();
      console.log(`\n⚡ Culkibo Live Sync activo`);
      console.log(`   Proyecto:   ${projectId}`);
      console.log(`   Directorio: ${path.resolve(directorio)}`);
      console.log(`   Destino:    ${options.url}`);
      if (options.reconcile) {
        const rec = await client.reconcileFull();
        console.log(`   Merkle:     ${rec.rootDigest.slice(0, 12)} (${rec.changed} ficheros sincronizados)\n`);
      }
      process.once('SIGINT', stopSync);
      process.once('SIGTERM', stopSync);
    } catch (err) {
      console.error(`❌ No se pudo iniciar Live Sync: ${err.message}`);
      process.exit(1);
    }
  });

// Despliegue a producción y rollback instantáneo
program
  .command('deploy <projectId>')
  .description('Despliega un proyecto a producción (Docker BuildKit + healthcheck + swap Caddy)')
  .option('--no-git-sync', 'Desplegar el árbol local tal cual (promoción desde Forge)')
  .option('--json', 'Salida JSON')
  .action(async (projectId, options) => {
    try {
      const remote = getRemoteConfig(options);
      if (remote.apiUrl) {
        const res = await remoteApiRequest(remote, 'POST', `/api/projects/${encodeURIComponent(projectId)}/deploy`, {
          gitSync: options.gitSync
        });
        if (isJsonMode(options)) return printJson({ ok: true, remote: true, ...res });
        console.log(`\x1b[32m✅ Despliegue remoto lanzado para ${projectId}\x1b[0m (${res.message || res.status || 'en curso'})`);
        return;
      }
      const project = svc.projectManager.getById(projectId);
      if (!project) {
        failCli(new Error(`Proyecto "${projectId}" no encontrado.`), options);
        return;
      }
      const result = await svc.deployManager.deploy(project, { gitSync: options.gitSync, trigger: 'cli' });
      if (result.status === 'activo') {
        if (isJsonMode(options)) {
          printJson({ ok: true, deployment: result });
        } else {
          console.log(`\x1b[32m✅ Despliegue ${result.id} activo en ${result.durationMs} ms (${result.upstream || 'sin ruta'})\x1b[0m`);
        }
        // Esperar al drenaje para no dejar el contenedor anterior vivo al terminar el proceso CLI
        await svc.deployManager.awaitDrain(project.id);
      } else {
        failCli(new Error(`Despliegue fallido: ${result.error}`), options);
      }
    } catch (err) {
      failCli(err, options);
    }
  });

program
  .command('rollback <projectId>')
  .description('Revierte un proyecto a la versión de producción anterior o a un --release específico')
  .option('-r, --release <deploymentId>', 'ID exacto de release histórica a restaurar')
  .option('--json', 'Salida JSON')
  .action(async (projectId, options) => {
    try {
      const remote = getRemoteConfig(options);
      const rbOpts = options.release ? { deploymentId: String(options.release).trim() } : {};
      if (remote.apiUrl) {
        const res = await remoteApiRequest(remote, 'POST', `/api/projects/${encodeURIComponent(projectId)}/rollback`, rbOpts);
        if (isJsonMode(options)) return printJson({ ok: true, remote: true, ...res });
        console.log(`\x1b[32m✅ Rollback remoto completado (${res.id || res.deploymentId || 'OK'})\x1b[0m`);
        return;
      }
      const project = svc.projectManager.getById(projectId);
      if (!project) {
        failCli(new Error(`Proyecto "${projectId}" no encontrado.`), options);
        return;
      }
      const result = await svc.deployManager.rollback(project.id, rbOpts);
      if (isJsonMode(options)) {
        printJson({ ok: true, rollback: result });
      } else {
        console.log(`\x1b[32m✅ Rollback completado (${result.id})\x1b[0m`);
      }
      await svc.deployManager.awaitDrain(project.id);
    } catch (err) {
      failCli(err, options);
    }
  });

program
  .command('releases <projectId>')
  .description('Lista el historial de despliegues/releases de un proyecto (compatible con rollback --release)')
  .option('-n, --limit <n>', 'Número máximo de releases a listar', '20')
  .option('--json', 'Salida JSON')
  .action(async (projectId, options) => {
    try {
      const limit = Math.max(1, Math.min(100, parseInt(options.limit, 10) || 20));
      const remote = getRemoteConfig(options);
      const raw = remote.apiUrl
        ? await remoteApiRequest(remote, 'GET', `/api/projects/${encodeURIComponent(projectId)}/deployments?limit=${limit}`)
        : svc.deployManager.listDeployments(projectId, limit);
      const deployments = Array.isArray(raw) ? raw : (raw?.deployments || raw?.history || []);
      if (isJsonMode(options)) return printJson({ ok: true, projectId, count: deployments.length, releases: deployments });
      if (deployments.length === 0) {
        console.log(`Sin despliegues registrados para "${projectId}".`);
        return;
      }
      console.table(deployments.map((d) => ({
        ID: d.id,
        Estado: d.status || '—',
        Version: d.version || '—',
        Commit: d.git?.commit ? String(d.git.commit).slice(0, 7) : '—',
        DuracionMs: d.durationMs ?? '—',
        Fecha: d.finishedAt || d.startedAt || '—'
      })));
    } catch (err) {
      failCli(err, options);
    }
  });

// Catálogo de servicios
const catalogCmd = program.command('catalog').description('Catálogo de servicios autohospedados de un clic');
catalogCmd
  .command('list')
  .description('Lista las plantillas disponibles en el catálogo')
  .option('--json', 'Salida JSON')
  .action((options) => {
    const templates = svc.catalogManager.listTemplates();
    if (isJsonMode(options)) return printJson({ ok: true, count: templates.length, templates });
    console.table(templates.map(t => ({
      ID: t.id,
      Nombre: t.name,
      Categoría: t.categoryLabel,
      Imagen: t.image,
      RAM_Total: `${t.totalMemoryMb} MB`,
      BD: t.database ? t.database.engine : '—'
    })));
  });

// Auto-actualización atómica sin shell con respaldo y rollback automático si algo falla
program
  .command('update')
  .description('Actualiza Culkibo desde GitHub con respaldo previo y rollback automático en caso de error')
  .option('--branch <branch>', 'Rama de origen', 'main')
  .option('--keep-web-deps', 'Conservar web/node_modules tras compilar el panel')
  .action(async (options) => {
    const rootDir = path.resolve(__dirname, '..');
    const dataDir = path.join(rootDir, 'data');
    const webDist = path.join(rootDir, 'web', 'dist');
    const webDistBak = path.join(rootDir, 'web', '.dist.bak');
    const rawBranch = String(options.branch || 'main').trim();
    if (!/^[a-zA-Z0-9._/#+-]+$/.test(rawBranch) || rawBranch.startsWith('-') || rawBranch.includes('..')) {
      console.error(`\x1b[31m❌ Nombre de rama inválido:\x1b[0m ${rawBranch}`);
      process.exit(1);
    }
    const branch = rawBranch;

    const captureGit = (args) => new Promise((resolve, reject) => {
      const child = spawn('git', args, { cwd: rootDir, shell: false, windowsHide: true });
      let out = '';
      let err = '';
      child.stdout.on('data', (d) => { out += d.toString(); });
      child.stderr.on('data', (d) => { err += d.toString(); });
      child.on('error', reject);
      child.on('close', (code) => code === 0 ? resolve(out.trim()) : reject(new Error(err.trim() || `git ${args[0]} code ${code}`)));
    });

    console.log(`\n🔄 Actualizando Culkibo desde origin/${branch} (con protección de rollback)...`);
    let prevSha = '';
    try {
      // 1. Verificar espacio libre mínimo (>= 512 MB)
      if (typeof fs.statfsSync === 'function') {
        const st = fs.statfsSync(rootDir);
        const freeMb = Math.round((st.bavail * st.bsize) / (1024 * 1024));
        if (freeMb < 512) {
          throw new Error(`Espacio libre insuficiente (${freeMb} MB; mínimo 512 MB para actualizar con seguridad)`);
        }
      }
      prevSha = await captureGit(['rev-parse', 'HEAD']);

      // 2. Snapshot de configuración data/*.json (excluyendo auth.json y telemetry.json) + copia de web/dist
      const preUpdateDir = path.join(dataDir, 'backups', `pre-update-${Date.now()}`);
      if (fs.existsSync(dataDir)) {
        fs.mkdirSync(preUpdateDir, { recursive: true, mode: 0o700 });
        for (const f of fs.readdirSync(dataDir)) {
          if (f.endsWith('.json') && f !== 'auth.json' && f !== 'telemetry.json') {
            try {
              const dst = path.join(preUpdateDir, f);
              fs.copyFileSync(path.join(dataDir, f), dst);
              if (process.platform !== 'win32') fs.chmodSync(dst, 0o600);
            } catch (e) {}
          }
        }
      }
      if (fs.existsSync(webDist)) {
        fs.rmSync(webDistBak, { recursive: true, force: true });
        fs.cpSync(webDist, webDistBak, { recursive: true });
      }

      // 3. Descargar y aplicar cambios (`reset --hard FETCH_HEAD` soporta clones shallow y reescrituras)
      await runSpawnStep('git', ['fetch', '--depth', '1', 'origin', branch], rootDir);
      await runSpawnStep('git', ['reset', '--hard', 'FETCH_HEAD'], rootDir);
      await runSpawnStep('npm', ['ci', '--omit=dev', '--no-audit', '--no-fund'], rootDir).catch(() =>
        runSpawnStep('npm', ['install', '--omit=dev', '--no-audit', '--no-fund'], rootDir)
      );
      await runSpawnStep('npm', ['--prefix', 'web', 'ci', '--include=dev', '--no-audit', '--no-fund'], rootDir);
      await runSpawnStep('npm', ['run', 'web:build'], rootDir);

      // 4. Verificación de integridad antes de confirmar
      if (!fs.existsSync(path.join(webDist, 'index.html'))) {
        throw new Error('La compilación del panel no generó web/dist/index.html');
      }
      await runSpawnStep(process.execPath, ['--check', path.join(rootDir, 'server', 'index.js')], rootDir);

      fs.rmSync(webDistBak, { recursive: true, force: true });
      if (!options.keepWebDeps && process.env.NODE_ENV === 'production') {
        fs.rmSync(path.join(rootDir, 'web', 'node_modules'), { recursive: true, force: true });
      }
      console.log('\x1b[32m✅ Culkibo actualizado y verificado. Reinicia el servicio (p. ej. systemctl restart culkibo) para aplicar cambios.\x1b[0m\n');
    } catch (err) {
      console.error(`\x1b[31m❌ Error al actualizar Culkibo:\x1b[0m ${err.message}`);
      if (prevSha) {
        console.log(`\x1b[33m↩️  Revirtiendo automáticamente al commit estable ${prevSha.slice(0, 7)}...\x1b[0m`);
        try {
          await runSpawnStep('git', ['reset', '--hard', prevSha], rootDir);
          if (fs.existsSync(webDistBak)) {
            fs.rmSync(webDist, { recursive: true, force: true });
            fs.renameSync(webDistBak, webDist);
          }
          await runSpawnStep('npm', ['ci', '--omit=dev', '--no-audit', '--no-fund'], rootDir).catch(() => {});
          console.log('\x1b[32m✅ Estado anterior restaurado limpiamente.\x1b[0m\n');
        } catch (rbErr) {
          console.error(`\x1b[31m❌ Fallo durante la reversión:\x1b[0m ${rbErr.message}`);
        }
      }
      process.exit(1);
    }
  });

// Gestión transparente de telemetría anónima y diagnóstico
const telemetryCmd = program.command('telemetry').description('Gestiona la telemetría anónima y envío de diagnósticos de fallos');

telemetryCmd
  .command('status')
  .description('Muestra el estado actual de telemetría, instanceId y estadísticas')
  .action(() => {
    const st = svc.telemetryService.getStatus();
    console.log('\n📊 Telemetría y diagnósticos de Culkibo');
    console.log(`   Estado efectivo: ${st.enabled ? '\x1b[32mACTIVA\x1b[0m' : '\x1b[33mDESACTIVADA\x1b[0m'} (${st.reason})`);
    console.log(`   Instance ID:     ${st.instanceId}`);
    console.log(`   Endpoint:        ${st.endpoint}`);
    console.log(`   Bloqueada env:   ${st.lockedByEnv ? 'sí' : 'no'}`);
    console.log(`   En cola / Env.:  ${st.queuedEvents} / ${st.stats.sent}\n`);
  });

telemetryCmd
  .command('enable')
  .description('Activa la telemetría anónima de fallos y mejoras')
  .action(() => {
    const st = svc.telemetryService.setEnabled(true);
    console.log(st.lockedByEnv
      ? `\x1b[33m⚠️ Preferencia guardada como activa, pero anulada por entorno: ${st.reason}\x1b[0m`
      : '\x1b[32m✅ Telemetría anónima activada.\x1b[0m');
  });

telemetryCmd
  .command('disable')
  .description('Desactiva por completo el envío de telemetría y vacía la cola')
  .action(() => {
    svc.telemetryService.setEnabled(false);
    console.log('\x1b[32m✅ Telemetría desactivada y cola local vaciada.\x1b[0m');
  });

telemetryCmd
  .command('preview')
  .description('Imprime el JSON exacto que Culkibo enviaría (100% auditable)')
  .action(() => {
    console.log(JSON.stringify(svc.telemetryService.getPreviewPayload(), null, 2));
  });

telemetryCmd
  .command('reset')
  .description('Rota el identificador anónimo aleatorio (instanceId)')
  .action(() => {
    const st = svc.telemetryService.resetInstanceId();
    console.log(`\x1b[32m✅ Nuevo instanceId generado:\x1b[0m ${st.instanceId}`);
  });

/**
 * Realiza un POST HTTP/HTTPS sin pool keep-alive (`agent: false`, `Connection: close`)
 * para el puente MCP stdio remoto, evitando carreras de teardown de sockets/libuv en Windows.
 * @param {string} urlStr
 * @param {Record<string, string>} headers
 * @param {string} bodyStr
 * @returns {Promise<{ status: number, contentType: string, bodyText: string }>}
 */
function postMcpRemote(urlStr, headers, bodyStr) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(urlStr);
    const transport = parsed.protocol === 'https:' ? https : http;
    const payload = Buffer.from(bodyStr, 'utf8');
    const req = transport.request({
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: `${parsed.pathname}${parsed.search}`,
      method: 'POST',
      agent: false,
      headers: {
        ...headers,
        'Content-Length': String(payload.length),
        'Connection': 'close'
      }
    }, (res) => {
      /** @type {Buffer[]} */
      const chunks = [];
      res.on('data', (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      res.on('end', () => {
        resolve({
          status: res.statusCode || 0,
          contentType: String(res.headers['content-type'] || '').toLowerCase(),
          bodyText: Buffer.concat(chunks).toString('utf8')
        });
      });
      res.on('error', reject);
    });
    req.setTimeout(60000, () => {
      req.destroy(new Error(`Timeout (60s) conectando con ${urlStr}`));
    });
    req.on('error', reject);
    req.end(payload);
  });
}

// Transporte stdio MCP (con puente HTTP automático hacia VPS remoto cuando CULKIBO_API_URL está definido)
program
  .command('mcp')
  .description('Ejecuta el servidor MCP sobre entrada/salida estándar (stdio local o puente remoto HTTP, soporta CULKIBO_MCP_PROFILE)')
  .option('-p, --profile <profile>', 'Perfil de herramientas MCP (core|deploy|ops|security|all; default env CULKIBO_MCP_PROFILE o all)')
  .action((options) => {
    const toStderr = (...args) => {
      try { process.stderr.write(args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ') + '\n'); } catch (e) {}
    };
    console.log = toStderr;
    console.info = toStderr;
    console.warn = toStderr;

    const remoteApiUrl = (process.env.CULKIBO_API_URL || '').trim().replace(/\/+$/, '');
    const remoteToken = (process.env.CULKIBO_TOKEN || '').trim();
    const mcpProfile = String((options && options.profile) || process.env.CULKIBO_MCP_PROFILE || 'all').trim().toLowerCase() || 'all';
    const mcpServer = remoteApiUrl ? null : svc.mcpServer;

    const rl = readline.createInterface({
      input: process.stdin,
      terminal: false
    });

    let inFlight = 0;
    let stdinClosed = false;
    let exiting = false;
    const maybeExit = () => {
      if (!stdinClosed || inFlight > 0 || exiting) return;
      exiting = true;
      try { rl.close(); } catch (e) {}
      if (remoteApiUrl) {
        // Sin agent keep-alive ni process.exit() brusco: el bucle de eventos drena limpio en 0 ms (cero carreras libuv en Windows)
        process.exitCode = process.exitCode || 0;
        return;
      }
      Promise.resolve(svc.projectManager.flushToDisk()).catch(() => {}).finally(() => {
        process.exitCode = process.exitCode || 0;
        // Fallback unref'd solo si algún servicio local mantiene un handle abierto tras drenar
        const fallback = setTimeout(() => process.exit(0), 150);
        if (fallback.unref) fallback.unref();
      });
    };

    const writeStdLine = (obj) => {
      process.stdout.write(JSON.stringify(obj) + '\n');
    };

    rl.on('line', async (line) => {
      if (!line.trim()) return;
      inFlight++;
      /** @type {any} */
      let parsedId = null;
      try {
        const request = JSON.parse(line);
        if (request && typeof request === 'object' && 'id' in request && request.id !== undefined) {
          parsedId = request.id;
        }
        if (!('id' in request) || request.id === undefined) return;

        if (remoteApiUrl) {
          const metaVer = request.params?._meta?.['io.modelcontextprotocol/protocolVersion']
            || request._meta?.['io.modelcontextprotocol/protocolVersion']
            || null;
          const isModern = metaVer === '2026-07-28' || request.method === 'server/discover';
          const nameVal = request.method === 'resources/read' ? request.params?.uri : request.params?.name;
          const baseOrigin = remoteApiUrl.replace(/\/api\/mcp(?:\/message)?(?:\?.*)?$/, '');
          const profileQuery = mcpProfile && mcpProfile !== 'all'
            ? `?profile=${encodeURIComponent(mcpProfile)}`
            : '';
          const endpoint = isModern
            ? `${baseOrigin}/api/mcp${profileQuery}`
            : `${baseOrigin}/api/mcp/message`;
          const outboundRequest = (!isModern && request.method === 'tools/list' && mcpProfile && mcpProfile !== 'all' && !(request.params && request.params.profile))
            ? { ...request, params: { ...(request.params || {}), profile: mcpProfile } }
            : request;
          const headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
            ...(isModern ? {
              'MCP-Protocol-Version': '2026-07-28',
              ...(request.method ? { 'Mcp-Method': String(request.method) } : {}),
              ...(nameVal ? { 'Mcp-Name': String(nameVal) } : {})
            } : {}),
            ...(remoteToken ? { 'Authorization': `Bearer ${remoteToken}` } : {})
          };
          const res = await postMcpRemote(endpoint, headers, JSON.stringify(outboundRequest));
          const ct = res.contentType;
          const bodyText = res.bodyText;
          if (ct.includes('text/event-stream')) {
            // Extraer último evento `data: {...}` JSON-RPC del stream SSE
            const dataLines = bodyText.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trim()).filter(Boolean);
            const finalMsg = dataLines[dataLines.length - 1];
            if (finalMsg) {
              process.stdout.write(finalMsg + '\n');
            } else {
              writeStdLine({ jsonrpc: '2.0', id: request.id, error: { code: -32000, message: `Stream SSE remoto sin respuesta final (HTTP ${res.status})` } });
            }
          } else if (bodyText.trim()) {
            process.stdout.write(bodyText.trim() + '\n');
          } else {
            writeStdLine({
              jsonrpc: '2.0',
              id: request.id,
              error: { code: -32000, message: `Servidor remoto MCP respondió HTTP ${res.status}` }
            });
          }
          return;
        }

        if (!mcpServer) return;
        const useModern = request.method === 'server/discover'
          || request.params?._meta?.['io.modelcontextprotocol/protocolVersion'] === '2026-07-28'
          || request._meta?.['io.modelcontextprotocol/protocolVersion'] === '2026-07-28';
        const response = useModern && typeof mcpServer.handleModernRpc === 'function'
          ? await mcpServer.handleModernRpc(request, { transport: 'stdio', profile: mcpProfile })
          : await mcpServer.handleJsonRpc(request, { transport: 'stdio', profile: mcpProfile });
        if (response !== null) writeStdLine(response);
      } catch (err) {
        writeStdLine({
          jsonrpc: '2.0',
          id: parsedId,
          error: { code: parsedId === null ? -32700 : -32603, message: `Error MCP stdio: ${err.message}` }
        });
      } finally {
        inFlight--;
        maybeExit();
      }
    });

    rl.on('close', () => {
      stdinClosed = true;
      maybeExit();
    });
  });

/**
 * Escribe de forma segura e idempotente los archivos drop-in del kit de agente MCP
 * (fusionando `mcpServers`/`servers` en JSON existentes y delimitando bloques en CLAUDE.md/TOML),
 * verificando siempre que JAMÁS se incrusten tokens reales en disco.
 * @param {any} kitResult
 * @param {string} targetDir
 * @param {{ dryRun?: boolean, force?: boolean }} [opts]
 */
function writeAgentKitFiles(kitResult, targetDir, opts = {}) {
  const dir = path.resolve(targetDir || process.cwd());
  const dryRun = Boolean(opts.dryRun);
  const force = Boolean(opts.force);
  const activeEnvToken = String(process.env.CULKIBO_TOKEN || '').trim();

  /** @type {Array<{ path: string, target: string, format: string, action: string, fullPath: string, reason?: string }>} */
  const results = [];
  /** @type {string[]} */
  const written = [];
  /** @type {string[]} */
  const skipped = [];

  for (const kit of Object.values(kitResult.kits || {})) {
    for (const file of (kit.files || [])) {
      const relPath = String(file.path);
      const fullPath = path.resolve(dir, relPath);
      const relCheck = path.relative(dir, fullPath);
      if (relCheck.startsWith('..') || path.isAbsolute(relCheck)) {
        throw new Error(`Ruta de destino fuera del directorio de trabajo: ${relPath}`);
      }
      const rawContent = String(file.content || '');
      if (activeEnvToken.length >= 8 && rawContent.includes(activeEnvToken)) {
        throw new Error('Bloqueo de seguridad: el archivo generado contiene un token real en claro.');
      }

      const exists = fs.existsSync(fullPath);
      let finalContent = rawContent;
      let action = exists ? 'update' : 'create';
      /** @type {string | undefined} */
      let skipReason;

      if (exists && file.format === 'json' && file.mergeKey) {
        try {
          const existingObj = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
          const incomingObj = JSON.parse(rawContent);
          const mergeKey = String(file.mergeKey);
          const existingBucket = existingObj && typeof existingObj[mergeKey] === 'object' ? existingObj[mergeKey] : {};
          if (existingBucket && Object.prototype.hasOwnProperty.call(existingBucket, 'culkibo') && !force) {
            action = 'skip';
            skipReason = 'culkibo ya existe en el archivo (usa --force para sobrescribir)';
          } else {
            const merged = {
              ...(existingObj && typeof existingObj === 'object' ? existingObj : {}),
              [mergeKey]: {
                ...existingBucket,
                ...(incomingObj[mergeKey] || {})
              }
            };
            finalContent = JSON.stringify(merged, null, 2) + '\n';
            action = existingBucket && Object.prototype.hasOwnProperty.call(existingBucket, 'culkibo') ? 'overwrite' : 'merge';
          }
        } catch (e) {
          if (!force) {
            action = 'skip';
            skipReason = 'JSON existente no parseable (usa --force para sobrescribir)';
          } else {
            action = 'overwrite';
          }
        }
      } else if (exists && file.format === 'markdown' && file.markerStart && file.markerEnd) {
        const existingText = fs.readFileSync(fullPath, 'utf8');
        const startIdx = existingText.indexOf(file.markerStart);
        const endIdx = existingText.indexOf(file.markerEnd);
        if (startIdx >= 0 && endIdx > startIdx) {
          if (!force) {
            action = 'skip';
            skipReason = 'bloque culkibo-mcp-ops ya presente (usa --force para actualizar)';
          } else {
            const before = existingText.slice(0, startIdx);
            const after = existingText.slice(endIdx + file.markerEnd.length).replace(/^\r?\n/, '');
            finalContent = `${before}${rawContent}${after}`;
            action = 'overwrite';
          }
        } else {
          const sep = existingText.endsWith('\n') ? '\n' : '\n\n';
          finalContent = `${existingText}${sep}${rawContent}`;
          action = 'append';
        }
      } else if (exists && file.format === 'toml' && file.sectionHeader) {
        const existingText = fs.readFileSync(fullPath, 'utf8');
        if (existingText.includes(file.sectionHeader)) {
          if (!force) {
            action = 'skip';
            skipReason = `${file.sectionHeader} ya presente (usa --force para sobrescribir)`;
          } else {
            const sectionRe = /(?:# Culkibo MCP 2026[^\n]*\n(?:#[^\n]*\n)*)?\[mcp_servers\.culkibo\][\s\S]*?(?=\n\[|$)/;
            finalContent = existingText.replace(sectionRe, rawContent.trimEnd()) + '\n';
            action = 'overwrite';
          }
        } else {
          const sep = existingText.endsWith('\n') ? '\n' : '\n\n';
          finalContent = `${existingText}${sep}${rawContent}`;
          action = 'append';
        }
      } else if (exists && !force) {
        action = 'skip';
        skipReason = 'archivo ya existente (usa --force para sobrescribir)';
      }

      if (action === 'skip') {
        skipped.push(relPath);
      } else {
        if (!dryRun) {
          fs.mkdirSync(path.dirname(fullPath), { recursive: true });
          fs.writeFileSync(fullPath, finalContent, 'utf8');
        }
        written.push(relPath);
      }

      results.push({
        path: relPath,
        target: kit.id,
        format: file.format,
        action,
        fullPath,
        ...(skipReason ? { reason: skipReason } : {})
      });
    }
  }

  return { directory: dir, dryRun, results, written, skipped };
}

// culkibo agent-init [target]: generador 1-clic de kits MCP drop-in (Antigravity, Claude Code, Cursor, Windsurf, Codex CLI, VS Code)
program
  .command('agent-init [target]')
  .description('Genera configuraciones MCP 1-clic (antigravity, claude-code, cursor, windsurf, codex, vscode, all) con ?profile=core y ${CULKIBO_TOKEN}')
  .option('-d, --dir <dir>', 'Directorio destino del workspace', process.cwd())
  .option('-p, --profile <profile>', 'Perfil MCP de herramientas (core|deploy|ops|security|all)', 'core')
  .option('--url <serverUrl>', 'URL del servidor Culkibo (por defecto --api-url, CULKIBO_API_URL o http://127.0.0.1:3030)')
  .option('--project <projectId>', 'ID de proyecto opcional para personalizar CLAUDE.md')
  .option('--no-ops-guide', 'Omitir el bloque operativo CLAUDE.md al inicializar Claude Code')
  .option('--dry-run', 'Previsualizar los archivos a generar sin escribir en disco')
  .option('--force', 'Sobrescribir entradas culkibo existentes')
  .option('--json', 'Salida JSON estructurada')
  .action((target = 'all', options) => {
    try {
      const targetDir = path.resolve(options.dir || process.cwd());
      if (!fs.existsSync(targetDir) || !fs.statSync(targetDir).isDirectory()) {
        throw new Error(`El directorio destino no existe: ${targetDir}`);
      }
      const remote = getRemoteConfig(options);
      const serverUrl = String(options.url || remote.apiUrl || `http://127.0.0.1:${process.env.PORT || 3030}`).trim();
      const kit = svc.mcpServer.buildAgentKit({
        target: String(target || 'all'),
        profile: String(options.profile || 'core'),
        serverUrl,
        projectId: options.project ? String(options.project) : null,
        includeOpsGuide: options.opsGuide !== false
      });

      const writeRes = writeAgentKitFiles(kit, targetDir, {
        dryRun: Boolean(options.dryRun),
        force: Boolean(options.force)
      });

      const payload = {
        ok: true,
        target: kit.target,
        profile: kit.profile,
        endpoint: kit.endpoint,
        tokenPlaceholder: kit.tokenPlaceholder,
        containsPlaintextSecrets: false,
        tokenSavings: kit.tokenSavings,
        dryRun: writeRes.dryRun,
        directory: writeRes.directory,
        written: writeRes.written,
        skipped: writeRes.skipped,
        files: writeRes.results,
        kits: kit.kits
      };

      if (isJsonMode(options)) {
        return printJson(payload);
      }

      console.log(`\n\x1b[32m🤖 Culkibo Agent Kit (${kit.target}) — perfil "${kit.profile}"\x1b[0m`);
      console.log(`   Endpoint:    ${kit.endpoint}`);
      console.log(`   Contexto:    ${kit.tokenSavings.profileToolsCount}/${kit.tokenSavings.allToolsCount} herramientas (~${(kit.tokenSavings.estimatedTokens / 1000).toFixed(1)}k tok, -${kit.tokenSavings.savedPct}%)`);
      console.log(`   Token:       placeholder ${kit.tokenPlaceholder} (0 secretos en claro)`);
      for (const r of writeRes.results) {
        const verb = r.action === 'skip'
          ? `\x1b[33momitido\x1b[0m (${r.reason})`
          : (writeRes.dryRun ? `\x1b[36m[dry-run] ${r.action}\x1b[0m` : `\x1b[32m${r.action}\x1b[0m`);
        console.log(`   · ${r.path} → ${verb}`);
      }
      console.log(`\n   Siguiente paso: export CULKIBO_TOKEN="<tu_token_rbac>" y abre tu agente IA.\n`);
    } catch (err) {
      failCli(err, options);
    }
  });

// ===========================================================================
// DX CLOUD-NATIVE: init, up, logs, env, exec
// ===========================================================================

// culkibo init [dir]: autodetecta stack y genera culkibo.yaml + .culkiboignore
program
  .command('init [directorio]')
  .description('Autodetecta el stack local y genera un manifiesto declarativo culkibo.yaml + .culkiboignore')
  .option('-n, --name <nombre>', 'Nombre del proyecto')
  .option('--force', 'Sobrescribir culkibo.yaml si ya existe')
  .option('--schema-url <url>', 'URL de JSON Schema para autocompletado en IDE')
  .option('--json', 'Salida JSON')
  .action((directorio = process.cwd(), options) => {
    try {
      const targetDir = path.resolve(directorio);
      if (!fs.existsSync(targetDir) || !fs.statSync(targetDir).isDirectory()) {
        throw new Error(`El directorio no existe: ${targetDir}`);
      }
      const manifestPath = path.join(targetDir, 'culkibo.yaml');
      if (fs.existsSync(manifestPath) && !options.force) {
        throw new Error(`Ya existe ${manifestPath}. Usa --force para sobrescribirlo.`);
      }
      const detected = detectLocalStack(targetDir);
      const generated = generateStarterManifest(detected, {
        name: options.name,
        schemaUrl: options.schemaUrl
      });
      fs.writeFileSync(manifestPath, generated.yaml, 'utf8');

      const ignorePath = path.join(targetDir, '.culkiboignore');
      let createdIgnore = false;
      if (!fs.existsSync(ignorePath) || options.force) {
        const defaultIgnore = [
          '# Generado por culkibo init — ficheros excluidos de Live Sync',
          '.env',
          '.env.*.local',
          '*.log',
          'tmp/',
          '.DS_Store',
          'Thumbs.db',
          ''
        ].join('\n');
        fs.writeFileSync(ignorePath, defaultIgnore, 'utf8');
        createdIgnore = true;
      }

      const payload = {
        ok: true,
        directory: targetDir,
        manifestPath,
        ignorePath: createdIgnore ? ignorePath : null,
        projectId: generated.projectId,
        stackName: generated.stackName,
        framework: detected.framework,
        runtime: detected.runtime,
        containerPort: detected.containerPort,
        vaultRefs: detected.vaultRefs,
        databases: (generated.manifest.databases || []).map((d) => d.engine)
      };
      if (isJsonMode(options)) return printJson(payload);
      console.log(`\n\x1b[32m✅ Proyecto inicializado con Culkibo\x1b[0m`);
      console.log(`   Stack detectado: ${detected.framework} (puerto ${detected.containerPort})`);
      console.log(`   Manifiesto:      ${manifestPath}`);
      if (createdIgnore) console.log(`   Ignore Sync:     ${ignorePath}`);
      if (detected.vaultRefs.length > 0) {
        console.log(`   Secretos Vault:  ${detected.vaultRefs.join(', ')} (referenciados como \${vault.*})`);
      }
      console.log(`   Siguiente paso:  culkibo up\n`);
    } catch (err) {
      failCli(err, options);
    }
  });

// culkibo up [dir]: reconcilia culkibo.yaml + despliega o inicia Live Sync en 1 comando
program
  .command('up [directorio]')
  .description('Reconcilia culkibo.yaml y despliega (o sincroniza con --sync) el proyecto en un solo comando')
  .option('-f, --file <file>', 'Ruta al manifiesto declarativo', 'culkibo.yaml')
  .option('-p, --project <projectId>', 'Proyecto concreto del manifiesto a desplegar')
  .option('--dry-run', 'Simula el plan GitOps sin aplicar cambios ni desplegar')
  .option('--no-deploy', 'Aplicar sólo el manifiesto GitOps sin lanzar build/deploy')
  .option('--no-git-sync', 'Desplegar el árbol local tal cual sin git pull')
  .option('--sync', 'Iniciar Live Sync en vivo tras reconciliar el manifiesto')
  .option('--prune', 'Eliminar recursos no declarados en culkibo.yaml')
  .option('--confirm-destructive', 'Confirmar eliminaciones destructivas con --prune')
  .option('--json', 'Salida JSON')
  .action(async (directorio = process.cwd(), options) => {
    try {
      const baseDir = path.resolve(directorio);
      const manifestPath = path.isAbsolute(options.file) ? options.file : path.join(baseDir, options.file);
      if (!fs.existsSync(manifestPath)) {
        throw new Error(`No se encontró ${manifestPath}. Ejecuta "culkibo init" primero.`);
      }
      const yamlText = fs.readFileSync(manifestPath, 'utf8');
      const remote = getRemoteConfig(options);

      if (options.dryRun) {
        const plan = remote.apiUrl
          ? await remoteApiRequest(remote, 'POST', '/api/gitops/plan', { yamlText, prune: Boolean(options.prune) })
          : svc.gitopsManager.planApply(yamlText, { prune: Boolean(options.prune), confirmDestructive: Boolean(options.confirmDestructive) });
        if (isJsonMode(options)) return printJson({ ok: true, dryRun: true, plan });
        console.log(`\n🔍 Plan GitOps (${plan.stackName || 'stack'}): +${plan.summary?.create ?? 0} crear · ~${plan.summary?.update ?? 0} actualizar · -${plan.summary?.delete ?? 0} eliminar\n`);
        return;
      }

      const applied = remote.apiUrl
        ? await remoteApiRequest(remote, 'POST', '/api/gitops/apply', {
          yamlText,
          dryRun: false,
          prune: Boolean(options.prune),
          confirmDestructive: Boolean(options.confirmDestructive)
        })
        : await svc.gitopsManager.applyStack(yamlText, {
          dryRun: false,
          prune: Boolean(options.prune),
          confirmDestructive: Boolean(options.confirmDestructive),
          actor: 'cli:up'
        });

      const targetProjectId = options.project
        || (applied.managedResources && applied.managedResources.projectIds && applied.managedResources.projectIds[0])
        || null;

      if (options.sync) {
        if (!targetProjectId) throw new Error('No se encontró ningún proyecto en culkibo.yaml para iniciar Live Sync');
        const wsUrl = remote.apiUrl
          ? remote.apiUrl.replace(/^http/i, 'ws').replace(/\/api$/, '') + '/ws/sync'
          : (process.env.CULKIBO_SYNC_URL || 'ws://127.0.0.1:3030/ws/sync');
        const client = new svc.LiveSyncClient({
          projectId: targetProjectId,
          sourceDir: baseDir,
          wsUrl,
          token: remote.token || null
        });
        await client.start();
        const rec = await client.reconcileFull();
        if (isJsonMode(options)) {
          printJson({ ok: true, applied, sync: { projectId: targetProjectId, wsUrl, merkle: rec.rootDigest, changed: rec.changed } });
        } else {
          console.log(`\x1b[32m✅ Stack reconciliado + Live Sync activo para ${targetProjectId}\x1b[0m (Merkle ${rec.rootDigest.slice(0, 12)})`);
        }
        const stopSync = async () => { await client.stop(); process.exit(0); };
        process.once('SIGINT', stopSync);
        process.once('SIGTERM', stopSync);
        return;
      }

      /** @type {any} */
      let deployment = null;
      if (options.deploy !== false && targetProjectId) {
        if (remote.apiUrl) {
          deployment = await remoteApiRequest(remote, 'POST', `/api/projects/${encodeURIComponent(targetProjectId)}/deploy`, {
            gitSync: options.gitSync
          });
        } else {
          const project = svc.projectManager.getById(targetProjectId);
          if (project) {
            if (!project.localPath && !project.gitRepo) {
              svc.projectManager.update(project.id, { localPath: baseDir });
            }
            const refreshed = svc.projectManager.getById(targetProjectId) || project;
            deployment = await svc.deployManager.deploy(refreshed, { gitSync: options.gitSync, trigger: 'cli:up' });
            if (deployment.status === 'activo') {
              await svc.deployManager.awaitDrain(refreshed.id);
            }
          }
        }
      }

      if (isJsonMode(options)) {
        return printJson({ ok: true, stackId: applied.stackId, appliedCounts: applied.appliedCounts, projectId: targetProjectId, deployment });
      }
      console.log(`\x1b[32m✅ Stack "${applied.stackName || applied.stackId}" reconciliado\x1b[0m (+${applied.appliedCounts?.created ?? 0} ~${applied.appliedCounts?.updated ?? 0} -${applied.appliedCounts?.deleted ?? 0})`);
      if (deployment) {
        console.log(`   Despliegue (${targetProjectId}): ${deployment.status || deployment.message || 'iniciado'}`);
      }
    } catch (err) {
      failCli(err, options);
    }
  });

// culkibo logs <projectId>: inspecciona o sigue en tiempo real los logs del contenedor
program
  .command('logs <projectId>')
  .description('Muestra o sigue en vivo (-f) los logs de ejecución de un proyecto')
  .option('-f, --follow', 'Seguir los logs en tiempo real')
  .option('-n, --tail <lines>', 'Número de líneas recientes', '100')
  .option('--since <since>', 'Filtrar desde marca temporal o duración (ej. 10m, 1h)')
  .option('--previous', 'Leer logs del contenedor de la release anterior')
  .option('--no-timestamps', 'Omitir marcas de tiempo')
  .option('--json', 'Salida JSON / NDJSON')
  .action(async (projectId, options) => {
    try {
      const tail = Math.max(1, Math.min(5000, parseInt(options.tail, 10) || 100));
      const target = options.previous ? 'previous' : 'current';
      const remote = getRemoteConfig(options);

      if (options.follow) {
        if (remote.apiUrl) {
          const base = remote.apiUrl.replace(/\/api$/, '');
          const streamUrl = `${base}/api/projects/${encodeURIComponent(projectId)}/runtime/logs/stream?tail=${tail}&target=${target}`;
          /** @type {Record<string, string>} */
          const headers = { Accept: 'text/event-stream' };
          if (remote.token) headers.Authorization = `Bearer ${remote.token}`;
          const ac = new AbortController();
          process.once('SIGINT', () => ac.abort());
          process.once('SIGTERM', () => ac.abort());
          const res = await fetch(streamUrl, { headers, signal: ac.signal });
          if (!res.ok || !res.body) throw new Error(`Error abriendo stream SSE (HTTP ${res.status})`);
          const decoder = new TextDecoder();
          let buf = '';
          for await (const chunk of res.body) {
            buf += decoder.decode(chunk, { stream: true });
            const lines = buf.split(/\r?\n/);
            buf = lines.pop() || '';
            for (const ln of lines) {
              if (!ln.startsWith('data:')) continue;
              const rawData = ln.slice(5).trim();
              if (!rawData) continue;
              if (isJsonMode(options)) {
                process.stdout.write(rawData + '\n');
              } else {
                try {
                  const parsed = JSON.parse(rawData);
                  if (parsed.line !== undefined) console.log(parsed.line);
                } catch (e) {
                  console.log(rawData);
                }
              }
            }
          }
          return;
        }

        const stream = svc.deployManager.streamRuntimeLogs(projectId, {
          tail,
          target,
          onLine: (payload) => {
            if (isJsonMode(options)) {
              process.stdout.write(JSON.stringify(payload) + '\n');
            } else {
              console.log(typeof payload === 'string' ? payload : (payload.line ?? JSON.stringify(payload)));
            }
          },
          onEnd: () => process.exit(0)
        });
        const stop = () => { try { stream.close(); } catch (e) {} process.exit(0); };
        process.once('SIGINT', stop);
        process.once('SIGTERM', stop);
        return;
      }

      let result;
      if (remote.apiUrl) {
        const qs = new URLSearchParams({ tail: String(tail), target, timestamps: options.timestamps === false ? '0' : '1' });
        if (options.since) qs.set('since', String(options.since));
        result = await remoteApiRequest(remote, 'GET', `/api/projects/${encodeURIComponent(projectId)}/runtime/logs?${qs.toString()}`);
      } else {
        result = await svc.deployManager.getRuntimeLogs(projectId, {
          tail,
          since: options.since || null,
          timestamps: options.timestamps !== false,
          target
        });
      }
      if (isJsonMode(options)) return printJson({ ok: result.ok !== false, projectId, ...result });
      const lines = Array.isArray(result.lines) ? result.lines : (typeof result.logs === 'string' ? result.logs.split(/\r?\n/) : []);
      if (lines.length === 0) {
        console.log(result.error || `Sin logs disponibles para ${projectId}.`);
        if (result.ok === false) process.exitCode = 1;
        return;
      }
      for (const l of lines) console.log(typeof l === 'string' ? l : (l.line || JSON.stringify(l)));
    } catch (err) {
      failCli(err, options);
    }
  });

// culkibo env <list|set|unset|push|pull>: gestión segura de variables y Vault cifrado
const envCmd = program.command('env').description('Gestiona variables de entorno y secretos cifrados del Vault (list, set, unset, push, pull)');

envCmd
  .command('list <projectId>')
  .description('Lista claves de entorno (valores sensibles enmascarados por defecto)')
  .option('-e, --env <slug>', 'Entorno aislado (ej. production, staging)')
  .option('--vault', 'Listar secretos compartidos del Vault AES-256-GCM (solo metadatos/huellas)')
  .option('--reveal', 'Mostrar valores en claro de variables del proyecto')
  .option('--json', 'Salida JSON')
  .action(async (projectId, options) => {
    try {
      const remote = getRemoteConfig(options);
      if (options.vault) {
        const secrets = remote.apiUrl
          ? await remoteApiRequest(remote, 'GET', '/api/vault')
          : svc.environmentManager.listVaultSecrets();
        const list = Array.isArray(secrets) ? secrets : (secrets?.secrets || []);
        if (isJsonMode(options)) return printJson({ ok: true, vault: true, count: list.length, secrets: list });
        console.table(list.map((s) => ({ Key: s.key, Scope: s.scope || 'both', Fingerprint: s.fingerprint, UpdatedAt: s.updatedAt || '—' })));
        return;
      }

      if (options.env) {
        const envSlug = String(options.env).trim();
        if (remote.apiUrl) {
          const envs = await remoteApiRequest(remote, 'GET', `/api/projects/${encodeURIComponent(projectId)}/environments`);
          const found = (envs?.environments || envs || []).find((e) => e.name === envSlug);
          if (!found) throw new Error(`Entorno "${envSlug}" no encontrado en ${projectId}`);
          if (isJsonMode(options)) return printJson({ ok: true, projectId, environment: envSlug, keys: found.envKeys || [] });
          console.table((found.envKeys || []).map((k) => ({ Key: k, Value: '[encrypted]' })));
          return;
        }
        const envObj = svc.environmentManager.getEnvironment(projectId, envSlug);
        if (!envObj) throw new Error(`Entorno "${envSlug}" no encontrado en ${projectId}`);
        const keys = Array.isArray(envObj.envKeys) ? envObj.envKeys : [];
        if (isJsonMode(options)) return printJson({ ok: true, projectId, environment: envSlug, count: keys.length, keys });
        console.table(keys.map((k) => ({ Key: k, Value: '[encrypted:AES-256-GCM]' })));
        return;
      }

      const project = remote.apiUrl
        ? await remoteApiRequest(remote, 'GET', `/api/projects/${encodeURIComponent(projectId)}`)
        : svc.projectManager.getById(projectId);
      if (!project) throw new Error(`Proyecto "${projectId}" no encontrado.`);
      const rawEnv = project.envVars || {};
      const gitops = svc.gitopsManager;
      /** @type {Record<string, string>} */
      const displayEnv = {};
      for (const k of Object.keys(rawEnv).sort()) {
        const v = String(rawEnv[k] ?? '');
        const isSecret = gitops.shouldRedactEnvForGit(k, v, false);
        displayEnv[k] = (options.reveal || !isSecret) ? v : '[REDACTED]';
      }
      if (isJsonMode(options)) return printJson({ ok: true, projectId, count: Object.keys(displayEnv).length, env: displayEnv });
      console.table(Object.entries(displayEnv).map(([Key, Value]) => ({ Key, Value })));
    } catch (err) {
      failCli(err, options);
    }
  });

envCmd
  .command('set <projectId> [pairs...]')
  .description('Establece variables KEY=VALUE (o lee un secreto por --stdin KEY)')
  .option('-e, --env <slug>', 'Entorno aislado destino (ej. production, staging)')
  .option('--vault', 'Guardar directamente en el Vault compartido AES-256-GCM')
  .option('--scope <scope>', 'Alcance en Vault (runtime | build | both)', 'both')
  .option('--stdin <key>', 'Leer el valor de esta clave desde stdin (sin exponerlo en argv)')
  .option('--json', 'Salida JSON')
  .action(async (projectId, pairs, options) => {
    try {
      const updates = parseEnvAssignments(pairs || []);
      if (options.stdin) {
        const key = String(options.stdin).trim();
        if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(key)) throw new Error(`Clave --stdin inválida: "${key}"`);
        updates[key] = await readStdinText();
      }
      const keys = Object.keys(updates);
      if (keys.length === 0) throw new Error('Proporciona al menos un par CLAVE=VALOR o --stdin CLAVE');

      const remote = getRemoteConfig(options);
      if (options.vault) {
        /** @type {any[]} */
        const saved = [];
        for (const [k, v] of Object.entries(updates)) {
          const meta = remote.apiUrl
            ? await remoteApiRequest(remote, 'PUT', `/api/vault/${encodeURIComponent(k)}`, { value: v, scope: options.scope })
            : svc.environmentManager.setVaultSecret(k, v, { scope: options.scope, actor: 'cli' });
          saved.push({ key: k, fingerprint: meta.fingerprint || meta.secret?.fingerprint || null });
        }
        if (isJsonMode(options)) return printJson({ ok: true, vault: true, updated: keys, secrets: saved });
        console.log(`\x1b[32m✅ ${keys.length} secreto(s) cifrado(s) en Vault:\x1b[0m ${keys.join(', ')}`);
        return;
      }

      if (options.env) {
        const envSlug = String(options.env).trim();
        if (remote.apiUrl) {
          await remoteApiRequest(remote, 'PUT', `/api/projects/${encodeURIComponent(projectId)}/environments/${encodeURIComponent(envSlug)}`, {
            envVars: updates
          });
        } else {
          svc.environmentManager.upsertEnvironment(projectId, envSlug, { envVars: updates, actor: 'cli' });
        }
        if (isJsonMode(options)) return printJson({ ok: true, projectId, environment: envSlug, updated: keys });
        console.log(`\x1b[32m✅ ${keys.length} variable(s) actualizadas en ${projectId}/${envSlug}:\x1b[0m ${keys.join(', ')}`);
        return;
      }

      if (remote.apiUrl) {
        const cur = await remoteApiRequest(remote, 'GET', `/api/projects/${encodeURIComponent(projectId)}`);
        const merged = { ...(cur?.envVars || {}), ...updates };
        await remoteApiRequest(remote, 'PUT', `/api/projects/${encodeURIComponent(projectId)}`, { envVars: merged });
      } else {
        const project = svc.projectManager.getById(projectId);
        if (!project) throw new Error(`Proyecto "${projectId}" no encontrado.`);
        svc.projectManager.update(project.id, { envVars: { ...(project.envVars || {}), ...updates } });
        await svc.projectManager.flushToDisk();
      }
      if (isJsonMode(options)) return printJson({ ok: true, projectId, updated: keys });
      console.log(`\x1b[32m✅ ${keys.length} variable(s) guardadas en ${projectId}:\x1b[0m ${keys.join(', ')}`);
    } catch (err) {
      failCli(err, options);
    }
  });

envCmd
  .command('unset <projectId> <keys...>')
  .description('Elimina una o más variables de entorno (o secretos con --vault)')
  .option('-e, --env <slug>', 'Entorno aislado')
  .option('--vault', 'Eliminar del Vault compartido')
  .option('--json', 'Salida JSON')
  .action(async (projectId, keys, options) => {
    try {
      const remote = getRemoteConfig(options);
      if (options.vault) {
        for (const k of keys) {
          if (remote.apiUrl) await remoteApiRequest(remote, 'DELETE', `/api/vault/${encodeURIComponent(k)}`);
          else svc.environmentManager.deleteVaultSecret(k, { actor: 'cli' });
        }
        if (isJsonMode(options)) return printJson({ ok: true, vault: true, removed: keys });
        console.log(`\x1b[32m✅ Eliminado(s) del Vault:\x1b[0m ${keys.join(', ')}`);
        return;
      }

      if (options.env) {
        const envSlug = String(options.env).trim();
        if (remote.apiUrl) {
          await remoteApiRequest(remote, 'PUT', `/api/projects/${encodeURIComponent(projectId)}/environments/${encodeURIComponent(envSlug)}`, {
            unsetEnvKeys: keys
          });
        } else {
          svc.environmentManager.upsertEnvironment(projectId, envSlug, { unsetEnvKeys: keys, actor: 'cli' });
        }
        if (isJsonMode(options)) return printJson({ ok: true, projectId, environment: envSlug, removed: keys });
        console.log(`\x1b[32m✅ Eliminadas de ${projectId}/${envSlug}:\x1b[0m ${keys.join(', ')}`);
        return;
      }

      if (remote.apiUrl) {
        const cur = await remoteApiRequest(remote, 'GET', `/api/projects/${encodeURIComponent(projectId)}`);
        const nextEnv = { ...(cur?.envVars || {}) };
        for (const k of keys) delete nextEnv[k];
        await remoteApiRequest(remote, 'PUT', `/api/projects/${encodeURIComponent(projectId)}`, { envVars: nextEnv });
      } else {
        const project = svc.projectManager.getById(projectId);
        if (!project) throw new Error(`Proyecto "${projectId}" no encontrado.`);
        const nextEnv = { ...(project.envVars || {}) };
        for (const k of keys) delete nextEnv[k];
        svc.projectManager.update(project.id, { envVars: nextEnv });
        await svc.projectManager.flushToDisk();
      }
      if (isJsonMode(options)) return printJson({ ok: true, projectId, removed: keys });
      console.log(`\x1b[32m✅ Eliminadas de ${projectId}:\x1b[0m ${keys.join(', ')}`);
    } catch (err) {
      failCli(err, options);
    }
  });

envCmd
  .command('push <projectId>')
  .description('Importa un fichero .env local hacia un proyecto, entorno (--env) o Vault (--vault)')
  .option('-f, --file <path>', 'Ruta del fichero .env', '.env')
  .option('-e, --env <slug>', 'Entorno aislado destino')
  .option('--vault', 'Cifrar todas las claves en el Vault compartido')
  .option('--json', 'Salida JSON')
  .action(async (projectId, options) => {
    try {
      const envPath = path.resolve(options.file || '.env');
      if (!fs.existsSync(envPath)) throw new Error(`No existe el fichero ${envPath}`);
      const { envVars } = svc.universalImporter.parseEnvText(fs.readFileSync(envPath, 'utf8'));
      const keys = Object.keys(envVars);
      if (keys.length === 0) throw new Error(`No se encontraron variables válidas en ${envPath}`);

      const remote = getRemoteConfig(options);
      if (options.vault) {
        for (const [k, v] of Object.entries(envVars)) {
          if (remote.apiUrl) await remoteApiRequest(remote, 'PUT', `/api/vault/${encodeURIComponent(k)}`, { value: v });
          else svc.environmentManager.setVaultSecret(k, v, { actor: 'cli:env-push' });
        }
      } else if (options.env) {
        const envSlug = String(options.env).trim();
        if (remote.apiUrl) {
          await remoteApiRequest(remote, 'PUT', `/api/projects/${encodeURIComponent(projectId)}/environments/${encodeURIComponent(envSlug)}`, { envVars });
        } else {
          svc.environmentManager.upsertEnvironment(projectId, envSlug, { envVars, actor: 'cli:env-push' });
        }
      } else {
        if (remote.apiUrl) {
          const cur = await remoteApiRequest(remote, 'GET', `/api/projects/${encodeURIComponent(projectId)}`);
          await remoteApiRequest(remote, 'PUT', `/api/projects/${encodeURIComponent(projectId)}`, { envVars: { ...(cur?.envVars || {}), ...envVars } });
        } else {
          const project = svc.projectManager.getById(projectId);
          if (!project) throw new Error(`Proyecto "${projectId}" no encontrado.`);
          svc.projectManager.update(project.id, { envVars: { ...(project.envVars || {}), ...envVars } });
          await svc.projectManager.flushToDisk();
        }
      }
      if (isJsonMode(options)) return printJson({ ok: true, projectId, file: envPath, target: options.vault ? 'vault' : (options.env || 'project'), pushedCount: keys.length, keys });
      console.log(`\x1b[32m✅ ${keys.length} variable(s) subidas desde ${envPath}\x1b[0m`);
    } catch (err) {
      failCli(err, options);
    }
  });

envCmd
  .command('pull <projectId>')
  .description('Descarga las variables del proyecto o entorno a un fichero .env local (modo seguro por defecto)')
  .option('-f, --file <path>', 'Ruta del fichero de salida', '.env.culkibo')
  .option('-e, --env <slug>', 'Entorno aislado origen')
  .option('--reveal', 'Escribir valores reales (sin enmascarar secretos como ${vault.KEY})')
  .option('--json', 'Salida JSON (nunca imprime valores secretos sin --reveal)')
  .action(async (projectId, options) => {
    try {
      const outPath = path.resolve(options.file || '.env.culkibo');
      const remote = getRemoteConfig(options);
      /** @type {Record<string, string>} */
      let sourceEnv = {};

      if (options.env) {
        const envSlug = String(options.env).trim();
        if (remote.apiUrl) {
          throw new Error('env pull sobre --env cifrado remoto requiere descarga vía panel web o acceso local con .vault.key');
        }
        const resolved = svc.environmentManager.resolveEnvForProject(projectId, { envName: envSlug, phase: 'runtime' });
        sourceEnv = resolved.env || {};
      } else {
        const project = remote.apiUrl
          ? await remoteApiRequest(remote, 'GET', `/api/projects/${encodeURIComponent(projectId)}`)
          : svc.projectManager.getById(projectId);
        if (!project) throw new Error(`Proyecto "${projectId}" no encontrado.`);
        sourceEnv = project.envVars || {};
      }

      const gitops = svc.gitopsManager;
      /** @type {string[]} */
      const lines = ['# Generado por culkibo env pull'];
      /** @type {string[]} */
      const redactedKeys = [];
      const keys = Object.keys(sourceEnv).sort();
      for (const k of keys) {
        const rawVal = String(sourceEnv[k] ?? '');
        const isSecret = gitops.shouldRedactEnvForGit(k, rawVal, false);
        let writtenVal = rawVal;
        if (isSecret && !options.reveal) {
          writtenVal = `\${vault.${k}}`;
          redactedKeys.push(k);
        }
        const needsQuote = /[\s#"'\r\n]/.test(writtenVal);
        lines.push(`${k}=${needsQuote ? JSON.stringify(writtenVal) : writtenVal}`);
      }
      fs.writeFileSync(outPath, lines.join('\n') + '\n', { encoding: 'utf8', mode: 0o600 });
      if (isJsonMode(options)) {
        return printJson({ ok: true, projectId, file: outPath, count: keys.length, redactedCount: redactedKeys.length, revealed: Boolean(options.reveal) });
      }
      console.log(`\x1b[32m✅ ${keys.length} variable(s) escritas en ${outPath}\x1b[0m${redactedKeys.length > 0 ? ` (${redactedKeys.length} secreto(s) redactados como \${vault.*}; usa --reveal para incluir valores)` : ''}`);
    } catch (err) {
      failCli(err, options);
    }
  });

// culkibo exec <projectId> <command...>: ejecuta un comando seguro sin shell en el contenedor
program
  .command('exec <projectId> <command...>')
  .description('Ejecuta un comando de mantenimiento dentro del contenedor de producción (argv seguro, 0 shell)')
  .option('-w, --workdir <dir>', 'Directorio de trabajo dentro del contenedor')
  .option('--timeout <ms>', 'Tiempo máximo en ms', '30000')
  .option('--json', 'Salida JSON')
  .action(async (projectId, commandParts, options) => {
    try {
      const cmdStr = Array.isArray(commandParts) ? commandParts.join(' ') : String(commandParts || '');
      const timeoutMs = Math.max(1000, Math.min(300000, parseInt(options.timeout, 10) || 30000));
      const remote = getRemoteConfig(options);
      const res = remote.apiUrl
        ? await remoteApiRequest(remote, 'POST', `/api/projects/${encodeURIComponent(projectId)}/runtime/exec`, {
          command: cmdStr,
          workdir: options.workdir || null,
          timeoutMs
        })
        : await svc.deployManager.execInContainer(projectId, {
          command: cmdStr,
          workdir: options.workdir || null,
          timeoutMs
        });
      if (isJsonMode(options)) {
        printJson({ ok: res.ok !== false && (res.exitCode === undefined || res.exitCode === 0), projectId, ...res });
        if (res.exitCode && res.exitCode !== 0) process.exitCode = res.exitCode;
        return;
      }
      if (res.stdout) process.stdout.write(res.stdout.endsWith('\n') ? res.stdout : `${res.stdout}\n`);
      if (res.stderr) process.stderr.write(res.stderr.endsWith('\n') ? res.stderr : `${res.stderr}\n`);
      if (res.exitCode && res.exitCode !== 0) process.exitCode = res.exitCode;
    } catch (err) {
      failCli(err, options);
    }
  });

// Flota Multi-Servidor (SSH sin shell)
program
  .command('fleet <action> [serverId]')
  .description('Gestiona nodos VPS remotos por SSH (list, probe, keys)')
  .option('--json', 'Salida JSON')
  .action(async (action, serverId, options) => {
    try {
      const fleet = require('../server/services/serverFleetManager');
      if (action === 'list') {
        const list = fleet.listServers({ includeLocal: true });
        if (isJsonMode(options)) return printJson({ ok: true, count: list.length, servers: list });
        console.table(list.map((s) => ({
          ID: s.id,
          Nombre: s.name,
          Host: s.host || '127.0.0.1',
          Estado: s.status,
          Region: s.region || '—',
          Docker: s.resources?.dockerVersion || '—'
        })));
      } else if (action === 'probe' && serverId) {
        const res = await fleet.probeServer(serverId, { force: true });
        printJson(res);
      } else if (action === 'keys') {
        const keys = fleet.listKeys();
        if (isJsonMode(options)) return printJson({ ok: true, count: keys.length, keys });
        console.table(keys.map((k) => ({
          ID: k.id,
          Nombre: k.name,
          Tipo: k.keyType,
          Huella: k.fingerprint
        })));
      } else {
        failCli(new Error('Acción inválida. Usa: list | probe <serverId> | keys'), options);
      }
    } catch (err) {
      failCli(err, options);
    }
  });

// GitOps declarativo (culkibo.yaml)
program
  .command('gitops <action> [file]')
  .description('Exporta, valida, simula, aplica o inspecciona pilas declarativas (export, plan <file>, apply <file>, drift, schema)')
  .option('--prune', 'Eliminar recursos no declarados en el manifiesto')
  .option('--confirm-destructive', 'Confirmar operaciones destructivas con --prune')
  .option('--json', 'Salida JSON')
  .action(async (action, file, options) => {
    try {
      const remote = getRemoteConfig(options);
      const gitops = svc.gitopsManager;
      if (action === 'schema') {
        printJson(gitops.getJsonSchema());
      } else if (action === 'export') {
        const res = remote.apiUrl
          ? await remoteApiRequest(remote, 'POST', '/api/gitops/export', {})
          : gitops.exportStack({});
        if (isJsonMode(options)) printJson(res);
        else console.log(res.yaml);
      } else if (action === 'plan' && file) {
        const yamlText = fs.readFileSync(path.resolve(file), 'utf8');
        const res = remote.apiUrl
          ? await remoteApiRequest(remote, 'POST', '/api/gitops/plan', { yamlText, prune: Boolean(options.prune) })
          : gitops.planApply(yamlText, { prune: Boolean(options.prune) });
        printJson(res);
      } else if (action === 'apply' && file) {
        const yamlText = fs.readFileSync(path.resolve(file), 'utf8');
        const res = remote.apiUrl
          ? await remoteApiRequest(remote, 'POST', '/api/gitops/apply', {
            yamlText,
            dryRun: false,
            prune: Boolean(options.prune),
            confirmDestructive: Boolean(options.confirmDestructive)
          })
          : await gitops.applyStack(yamlText, {
            dryRun: false,
            prune: Boolean(options.prune),
            confirmDestructive: Boolean(options.confirmDestructive)
          });
        printJson(res);
      } else if (action === 'drift') {
        const res = remote.apiUrl
          ? await remoteApiRequest(remote, 'GET', '/api/gitops/drift')
          : gitops.detectDrift();
        printJson(res);
      } else {
        failCli(new Error('Acción inválida. Usa: export | plan <archivo.yaml> | apply <archivo.yaml> | drift | schema'), options);
      }
    } catch (err) {
      failCli(err, options);
    }
  });

// Monitorización Uptime y Asesor de Costes/RAM
program
  .command('uptime <action> [id]')
  .description('Consulta monitores sintéticos y páginas públicas de estado (list, check <id>, pages)')
  .option('--json', 'Salida JSON')
  .action(async (action, id, options) => {
    try {
      const um = require('../server/services/uptimeMonitor');
      if (action === 'list') {
        const monitors = um.listMonitors();
        if (isJsonMode(options)) return printJson({ ok: true, count: monitors.length, monitors });
        console.table(monitors.map((m) => ({
          ID: m.id,
          Nombre: m.name,
          Tipo: m.type,
          Estado: m.status,
          Uptime24h: m.stats?.uptime24h != null ? `${m.stats.uptime24h}%` : '—',
          P95ms: m.stats?.p95Ms ?? '—'
        })));
      } else if (action === 'check' && id) {
        printJson(await um.runCheck(id));
      } else if (action === 'pages') {
        const pages = um.listStatusPages();
        if (isJsonMode(options)) return printJson({ ok: true, count: pages.length, pages });
        console.table(pages.map((p) => ({ Slug: p.slug, Titulo: p.title, URL: `/status/${p.slug}` })));
      } else {
        failCli(new Error('Acción inválida. Usa: list | check <monitorId> | pages'), options);
      }
    } catch (err) {
      failCli(err, options);
    }
  });

// ===========================================================================
// PIONEER CLI: smartpack, pussh (DirectPush OCI v2), tunnel-agent (EdgeTunnel)
// ===========================================================================

program
  .command('smartpack [dir]')
  .description('SmartPack: analiza un repo y emite un build-plan.json determinista + .dockerignore implícito + límites BuildKit')
  .option('--zstd', 'Activar flags OCI zstd:chunked para capas de arranque rápido')
  .option('--dockerfile', 'Imprimir también el Dockerfile multi-stage renderizado')
  .option('--write-ignore', 'Escribir .dockerignore implícito en el directorio si no existe')
  .option('--json', 'Salida JSON estructurada')
  .action((dir = process.cwd(), options) => {
    try {
      const targetDir = path.resolve(dir || process.cwd());
      if (!fs.existsSync(targetDir) || !fs.statSync(targetDir).isDirectory()) {
        throw new Error(`El directorio no existe: ${targetDir}`);
      }
      const sp = svc.smartPackBuilder;
      const plan = sp.generateBuildPlan(targetDir, { zstdChunked: Boolean(options.zstd) });
      const ignoreObj = plan.dockerignore || sp.generateImplicitDockerignore(plan.stack);
      const ignorePatterns = Array.isArray(ignoreObj?.patterns) ? ignoreObj.patterns : [];
      const ignoreContent = typeof ignoreObj?.content === 'string'
        ? ignoreObj.content
        : ignorePatterns.join('\n') + '\n';

      let wroteIgnore = false;
      const ignorePath = path.join(targetDir, '.dockerignore');
      if (options.writeIgnore && !fs.existsSync(ignorePath)) {
        fs.writeFileSync(ignorePath, ignoreContent, 'utf8');
        wroteIgnore = true;
      }

      const payload = {
        ok: true,
        directory: targetDir,
        stack: plan.stack,
        label: plan.label,
        runtime: plan.runtime,
        containerPort: plan.containerPort,
        deterministicHash: plan.deterministicHash,
        plan,
        dockerignore: ignorePatterns,
        resourceLimits: plan.resourceLimits,
        dockerfile: plan.dockerfile,
        wroteIgnore
      };

      if (isJsonMode(options)) {
        return printJson(payload);
      }

      console.log(`\n\x1b[32m⚡ Culkibo SmartPack — ${plan.label || plan.stack}\x1b[0m`);
      console.log(`   Directorio:     ${targetDir}`);
      console.log(`   Stack/Runtime:  ${plan.stack} (${plan.runtime}${plan.runtimeVersion ? ` ${plan.runtimeVersion}` : ''})`);
      console.log(`   Puerto:         ${plan.containerPort}`);
      console.log(`   Base/Runtime:   ${plan.baseImage} → ${plan.runtimeImage}`);
      console.log(`   Hash plan:      ${String(plan.deterministicHash || '').slice(0, 16)}`);
      if (plan.resourceLimits) {
        console.log(`   BuildKit caps:  memory=${plan.resourceLimits.memory || 'auto'} · cpus=${plan.resourceLimits.cpus || 'auto'}`);
      }
      console.log(`   .dockerignore:  ${ignorePatterns.length} patrones implícitos${wroteIgnore ? ` (escrito en ${ignorePath})` : ''}`);
      if (options.dockerfile && plan.dockerfile) {
        console.log('\n--- Dockerfile generado ---\n' + plan.dockerfile);
      }
      console.log('');
    } catch (err) {
      failCli(err, options);
    }
  });

program
  .command('pussh <image>')
  .description('DirectPush: transfiere capas delta OCI v2 a un nodo SSH sin registro externo (cero Docker Hub/GHCR)')
  .option('-s, --server <id>', 'ID del servidor destino de la flota (default local)', 'local')
  .option('-p, --port <port>', 'Puerto loopback local del túnel OCI v2', '5055')
  .option('--ssh-host <host>', 'Sobrescribir host SSH destino')
  .option('--ssh-user <user>', 'Sobrescribir usuario SSH destino')
  .option('--ssh-port <port>', 'Sobrescribir puerto SSH destino')
  .option('--dry-run', 'Mostrar plan de túnel SSH y pasos argv sin ejecutar')
  .option('--json', 'Salida JSON estructurada')
  .action(async (image, options) => {
    try {
      const dp = svc.directPushRegistry;
      const localPort = parseInt(String(options.port || '5055'), 10);
      const sshPort = options.sshPort ? parseInt(String(options.sshPort), 10) : undefined;
      const plan = dp.planDirectPush({
        image: String(image),
        serverId: String(options.server || 'local'),
        localPort,
        ...(options.sshHost ? { sshHost: String(options.sshHost) } : {}),
        ...(options.sshUser ? { sshUser: String(options.sshUser) } : {}),
        ...(sshPort !== undefined ? { sshPort } : {})
      });

      if (options.dryRun) {
        if (isJsonMode(options)) {
          return printJson({ ok: true, dryRun: true, plan });
        }
        console.log(`\n\x1b[36m🚀 DirectPush Plan (${plan.sourceImage} → ${plan.targetImageRef})\x1b[0m`);
        console.log(`   Servidor: ${plan.serverId} (${plan.tunnel.sshUser}@${plan.tunnel.sshHost}:${plan.tunnel.sshPort})`);
        for (const step of plan.steps || []) {
          const tag = step.skippedForLocal ? ' [omitido en local]' : '';
          console.log(`   ${step.step}. ${step.id}${tag}: ${step.bin} ${(step.argv || []).join(' ')}`);
        }
        console.log('');
        return;
      }

      // Ejecución real sin shell (spawn con argv explícito y shell: false)
      /** @type {import('child_process').ChildProcess | null} */
      let sshTunnelProc = null;
      const tunnelStep = (plan.steps || []).find((s) => s.id === 'open_ssh_tunnel');
      const dockerSteps = (plan.steps || []).filter((s) => s.id !== 'open_ssh_tunnel');

      try {
        if (tunnelStep && !tunnelStep.skippedForLocal) {
          sshTunnelProc = spawn(tunnelStep.bin, tunnelStep.argv, { stdio: 'ignore', shell: false, windowsHide: true });
          await new Promise((resolve) => setTimeout(resolve, 600));
        }
        for (const step of dockerSteps) {
          await runSpawnStep(step.bin, step.argv, process.cwd());
        }
        if (isJsonMode(options)) {
          return printJson({ ok: true, dryRun: false, pushed: true, plan });
        }
        console.log(`\x1b[32m✅ DirectPush completado:\x1b[0m ${plan.sourceImage} → ${plan.targetImageRef}`);
      } finally {
        if (sshTunnelProc && !sshTunnelProc.killed) {
          try { sshTunnelProc.kill('SIGTERM'); } catch (e) {}
        }
      }
    } catch (err) {
      failCli(err, options);
    }
  });

program
  .command('tunnel-agent')
  .description('Ejecuta el agente saliente Culkibo EdgeTunnel para exponer un servicio local tras CGNAT sin puertos abiertos')
  .option('--url <wsUrl>', 'URL WebSocket del servidor EdgeTunnel (o env CULKIBO_TUNNEL_URL)')
  .option('--token <token>', 'Token HMAC del túnel (o env CULKIBO_TUNNEL_TOKEN; nunca se imprime en logs)')
  .option('--tunnel-id <id>', 'ID del túnel EdgeTunnel (o query ?tunnelId= en --url)')
  .option('--target <hostPort>', 'Destino loopback local en formato host:port (ej. 127.0.0.1:3000)')
  .option('--dry-run', 'Validar configuración y mostrar plan de conexión redactado sin conectar')
  .option('--json', 'Salida JSON estructurada')
  .action(async (options) => {
    try {
      const rawUrl = String(options.url || process.env.CULKIBO_TUNNEL_URL || '').trim();
      const rawToken = String(options.token || program.opts().token || process.env.CULKIBO_TUNNEL_TOKEN || '').trim();
      const rawTarget = String(options.target || '').trim();
      if (!rawUrl) throw new Error('Especifica --url <ws(s)://...> o define CULKIBO_TUNNEL_URL.');
      const parsedUrl = new URL(rawUrl);
      if (parsedUrl.protocol !== 'ws:' && parsedUrl.protocol !== 'wss:') {
        throw new Error(`Protocolo inválido en --url: "${parsedUrl.protocol}" (usa ws:// o wss://).`);
      }
      const tunnelId = String(options.tunnelId || parsedUrl.searchParams.get('tunnelId') || process.env.CULKIBO_TUNNEL_ID || 'tun_default').trim();
      if (!rawToken) throw new Error('Especifica --token <tok> o define CULKIBO_TUNNEL_TOKEN.');
      if (!rawTarget || !rawTarget.includes(':')) {
        throw new Error('Especifica --target <host:port> (ej. 127.0.0.1:3000).');
      }
      const lastColon = rawTarget.lastIndexOf(':');
      const targetHost = rawTarget.slice(0, lastColon).replace(/^\[|\]$/g, '').trim() || '127.0.0.1';
      const targetPort = parseInt(rawTarget.slice(lastColon + 1).trim(), 10);

      const et = svc.edgeTunnelService;
      const validated = et.validateTunnelTarget(targetHost, targetPort);

      const safeSummary = {
        ok: true,
        dryRun: Boolean(options.dryRun),
        protocol: 'culkibo-edgetunnel/v1',
        serverUrl: `${parsedUrl.protocol}//${parsedUrl.host}${parsedUrl.pathname}`,
        tunnelId,
        token: '[REDACTED]',
        targetHost: validated.targetHost,
        targetPort: validated.targetPort
      };

      if (options.dryRun) {
        if (isJsonMode(options)) return printJson(safeSummary);
        console.log(`\n\x1b[36m🚇 Culkibo EdgeTunnel Agent (dry-run)\x1b[0m`);
        console.log(`   Servidor WS: ${safeSummary.serverUrl}`);
        console.log(`   Túnel ID:    ${safeSummary.tunnelId}`);
        console.log(`   Token:       [REDACTED]`);
        console.log(`   Destino:     ${safeSummary.targetHost}:${safeSummary.targetPort}\n`);
        return;
      }

      const client = new et.EdgeTunnelClient({
        serverUrl: rawUrl,
        tunnelId,
        token: rawToken,
        targetHost: validated.targetHost,
        targetPort: validated.targetPort
      });
      await client.connect();
      if (isJsonMode(options)) {
        printJson({ ...safeSummary, connected: true });
      } else {
        console.log(`\x1b[32m✅ EdgeTunnel conectado\x1b[0m (${safeSummary.tunnelId} → ${safeSummary.targetHost}:${safeSummary.targetPort})`);
      }
      const stopAgent = () => {
        try { client.close(); } catch (e) {}
        process.exitCode = 0;
      };
      process.once('SIGINT', stopAgent);
      process.once('SIGTERM', stopAgent);
    } catch (err) {
      failCli(err, options);
    }
  });

// ===========================================================================
// PIONEER CYCLE-4 CLI: verify (SHA-256 + SLSA v1.1 DSSE) & demo (<200ms sandbox)
// ===========================================================================

/**
 * Resuelve una clave pública Ed25519 desde ruta de archivo o PEM directo.
 * @param {string | undefined | null} rawPubKey
 * @returns {string | undefined}
 */
function resolvePublicKeyPemInput(rawPubKey) {
  if (!rawPubKey) return undefined;
  const trimmed = String(rawPubKey).trim();
  if (!trimmed) return undefined;
  if (trimmed.includes('BEGIN PUBLIC KEY')) return trimmed;
  const resolved = path.resolve(trimmed);
  if (!fs.existsSync(resolved)) {
    throw new Error(`No se encontró el archivo de clave pública Ed25519: ${resolved}`);
  }
  return fs.readFileSync(resolved, 'utf8').trim();
}

/**
 * Detecta si un objeto JSON corresponde a un sobre DSSE v1 (o wrapper `{ envelope }`).
 * @param {any} parsed
 */
function isDsseEnvelopeObject(parsed) {
  if (!parsed || typeof parsed !== 'object') return false;
  const env = parsed.envelope && typeof parsed.envelope === 'object' ? parsed.envelope : parsed;
  return typeof env.payloadType === 'string' && typeof env.payload === 'string' && Array.isArray(env.signatures);
}

/**
 * Verificación offline unificada de `CHECKSUMS.sha256`, `provenance.json` o sobres
 * SLSA v1.1 Ed25519 DSSE (`.dsse.json` / `.json`).
 * @param {string | undefined} dirOrFile
 * @param {{ root?: string, publicKey?: string }} [options]
 */
function runOfflineVerification(dirOrFile, options = {}) {
  const defaultRoot = path.resolve(__dirname, '..');
  const rootDir = options.root ? path.resolve(String(options.root)) : defaultRoot;
  const pubKeyPem = resolvePublicKeyPemInput(options.publicKey);
  const provMod = svc.releaseProvenance;

  // Sin argumento explícito: comprobar `dist-release/` si existe o autoverificar árbol local
  if (!dirOrFile) {
    const defaultDist = path.join(rootDir, 'dist-release');
    if (fs.existsSync(path.join(defaultDist, 'CHECKSUMS.sha256'))) {
      dirOrFile = defaultDist;
    } else {
      const generated = provMod.generateChecksums({ rootDir });
      const check = provMod.verifyChecksums(generated.text, { rootDir });
      const sbom = provMod.generateCycloneDxSbom({ rootDir });
      const rootPkg = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8'));
      return {
        ok: check.valid,
        valid: check.valid,
        mode: 'self-integrity',
        rootDir,
        checked: check.checked,
        missing: check.missing,
        mismatched: check.mismatched,
        malformed: check.malformed,
        sbom: {
          bomFormat: sbom.bomFormat,
          specVersion: sbom.specVersion,
          components: Array.isArray(sbom.components) ? sbom.components.length : 0,
          rootDeps: Object.keys(rootPkg.dependencies || {}).length
        },
        version: String(rootPkg.version || '1.2.0')
      };
    }
  }

  const target = path.resolve(String(dirOrFile));
  if (!fs.existsSync(target)) {
    throw new Error(`La ruta a verificar no existe: ${target}`);
  }
  const stat = fs.statSync(target);

  if (stat.isFile()) {
    const ext = path.extname(target).toLowerCase();
    if (ext === '.json') {
      const parsed = JSON.parse(fs.readFileSync(target, 'utf8'));
      if (isDsseEnvelopeObject(parsed)) {
        const sca = svc.supplyChainAttestor;
        const verification = sca.verifyAttestation(parsed, pubKeyPem);
        return {
          ...verification,
          ok: Boolean(verification.valid),
          valid: Boolean(verification.valid),
          mode: 'slsa-dsse',
          file: target
        };
      }
      if (parsed && parsed.schema === 'culkibo-release-provenance/v1') {
        const dir = path.dirname(target);
        const csFile = path.join(dir, String(parsed.artifacts?.checksums?.file || 'CHECKSUMS.sha256'));
        const sbomFile = path.join(dir, String(parsed.artifacts?.sbom?.file || 'sbom.cdx.json'));
        if (!fs.existsSync(csFile)) {
          throw new Error(`Falta ${csFile} referenciado por provenance.json`);
        }
        const csBuf = fs.readFileSync(csFile);
        const csSha = crypto.createHash('sha256').update(csBuf).digest('hex');
        const expectedCsSha = parsed.artifacts?.checksums?.sha256 || null;
        const csDigestOk = !expectedCsSha || csSha === expectedCsSha;

        let sbomDigestOk = true;
        /** @type {string | null} */
        let sbomSha = null;
        if (fs.existsSync(sbomFile)) {
          sbomSha = crypto.createHash('sha256').update(fs.readFileSync(sbomFile)).digest('hex');
          const expectedSbomSha = parsed.artifacts?.sbom?.sha256 || null;
          sbomDigestOk = !expectedSbomSha || sbomSha === expectedSbomSha;
        }
        const csRes = provMod.verifyChecksums(csFile, { rootDir });
        const valid = Boolean(csRes.valid && csDigestOk && sbomDigestOk);
        return {
          ok: valid,
          valid,
          mode: 'release-provenance',
          file: target,
          version: parsed.version || null,
          rootDir,
          checksums: csRes,
          artifacts: {
            checksumsDigestValid: csDigestOk,
            checksumsSha256: csSha,
            sbomDigestValid: sbomDigestOk,
            sbomSha256: sbomSha
          }
        };
      }
      throw new Error(`JSON no reconocido en ${target}. Se esperaba un sobre SLSA v1.1 DSSE o provenance.json.`);
    }

    // Archivo CHECKSUMS.sha256
    const csRes = provMod.verifyChecksums(target, { rootDir });
    return {
      ...csRes,
      ok: Boolean(csRes.valid),
      valid: Boolean(csRes.valid),
      mode: 'checksums',
      file: target,
      rootDir
    };
  }

  // Directorio: buscar provenance.json / CHECKSUMS.sha256 / *.dsse.json
  const provPath = path.join(target, 'provenance.json');
  const csPath = path.join(target, 'CHECKSUMS.sha256');
  const dsseFiles = fs.readdirSync(target)
    .filter((f) => f.endsWith('.dsse.json'))
    .sort()
    .map((f) => path.join(target, f));

  if (fs.existsSync(provPath)) {
    const base = runOfflineVerification(provPath, options);
    if (dsseFiles.length > 0) {
      const sca = svc.supplyChainAttestor;
      const attestations = dsseFiles.map((fp) => ({
        file: fp,
        ...sca.verifyAttestation(JSON.parse(fs.readFileSync(fp, 'utf8')), pubKeyPem)
      }));
      const allValid = Boolean(base.valid && attestations.every((a) => a.valid));
      return { ...base, ok: allValid, valid: allValid, attestations };
    }
    return base;
  }

  if (fs.existsSync(csPath)) {
    const csRes = provMod.verifyChecksums(csPath, { rootDir });
    return {
      ...csRes,
      ok: Boolean(csRes.valid),
      valid: Boolean(csRes.valid),
      mode: 'checksums',
      file: csPath,
      rootDir
    };
  }

  if (dsseFiles.length > 0) {
    const sca = svc.supplyChainAttestor;
    const attestations = dsseFiles.map((fp) => ({
      file: fp,
      ...sca.verifyAttestation(JSON.parse(fs.readFileSync(fp, 'utf8')), pubKeyPem)
    }));
    const valid = attestations.every((a) => a.valid);
    return {
      ok: valid,
      valid,
      mode: 'slsa-dsse-dir',
      directory: target,
      count: attestations.length,
      attestations
    };
  }

  // Si es un directorio de código fuente Culkibo (contiene package.json), hacer autoverificación
  if (fs.existsSync(path.join(target, 'package.json'))) {
    const generated = provMod.generateChecksums({ rootDir: target });
    const check = provMod.verifyChecksums(generated.text, { rootDir: target });
    return {
      ...check,
      ok: Boolean(check.valid),
      valid: Boolean(check.valid),
      mode: 'self-integrity',
      rootDir: target
    };
  }

  throw new Error(`No se encontró CHECKSUMS.sha256, provenance.json ni sobres .dsse.json en ${target}`);
}

program
  .command('verify [dirOrFile]')
  .description('Verificación offline de CHECKSUMS.sha256, provenance.json o atestaciones SLSA v1.1 Ed25519 DSSE')
  .option('--root <dir>', 'Directorio raíz contra el que comprobar rutas de CHECKSUMS.sha256')
  .option('--public-key <pemOrPath>', 'Clave pública Ed25519 SPKI PEM (cadena o ruta de archivo) para sobres DSSE')
  .option('--json', 'Salida JSON estructurada')
  .action((dirOrFile, options) => {
    try {
      const result = runOfflineVerification(dirOrFile, {
        root: options.root,
        publicKey: options.publicKey
      });
      if (!result.valid) process.exitCode = 1;
      if (isJsonMode(options)) {
        return printJson(result);
      }
      if (result.valid) {
        console.log(`\n\x1b[32m✅ Culkibo Verify PASS\x1b[0m (mode: ${result.mode})`);
        if (result.mode === 'slsa-dsse') {
          console.log(`   Algoritmo: ${result.algorithm} · KeyId: ${result.keyId}`);
          console.log(`   SLSA:      v${result.slsaVersion} (${result.predicateType})`);
          console.log(`   Builder:   ${result.builderId || 'n/a'}`);
        } else if (typeof result.checked === 'number') {
          console.log(`   Archivos SHA-256 verificados: ${result.checked} (0 alterados, 0 faltantes)`);
        } else if (result.checksums) {
          console.log(`   Release v${result.version}: ${result.checksums.checked} archivos SHA-256 + artefactos verificados`);
        }
        console.log('');
      } else {
        console.error(`\n\x1b[31m❌ Culkibo Verify FAILED\x1b[0m (mode: ${result.mode}${result.reason ? `, reason: ${result.reason}` : ''})`);
        if (Array.isArray(result.mismatched) && result.mismatched.length > 0) {
          console.error(`   Archivos alterados: ${result.mismatched.map((m) => m.path).join(', ')}`);
        }
        console.error('');
      }
    } catch (err) {
      failCli(err, options);
    }
  });

const DEMO_MIME_TYPES = Object.freeze({
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8'
});

/**
 * Abre una URL HTTP/HTTPS en el navegador predeterminado sin invocar jamás shell ni cmd/powershell.
 * @param {string} targetUrl
 */
function openBrowserSafe(targetUrl) {
  try {
    if (process.platform === 'darwin') {
      const child = spawn('open', [targetUrl], { detached: true, stdio: 'ignore', shell: false });
      child.unref();
    } else if (process.platform === 'win32') {
      const child = spawn('rundll32.exe', ['url.dll,FileProtocolHandler', targetUrl], { detached: true, stdio: 'ignore', shell: false, windowsHide: true });
      child.unref();
    } else {
      const child = spawn('xdg-open', [targetUrl], { detached: true, stdio: 'ignore', shell: false });
      child.unref();
    }
  } catch (e) {}
}

program
  .command('demo')
  .description('Lanza o imprime el sandbox interactivo instantáneo de Culkibo (?demo=1&lang=en&theme=dark) en <200 ms')
  .option('-p, --port <port>', 'Puerto loopback del sandbox interactivo', '3030')
  .option('--host <host>', 'Dirección loopback de escucha', '127.0.0.1')
  .option('--no-open', 'No abrir automáticamente el navegador')
  .option('--dry-run', 'Mostrar configuración del sandbox sin iniciar servidor HTTP')
  .option('--serve', 'Forzar inicio del servidor HTTP demo incluso en modo --json')
  .option('--json', 'Salida JSON estructurada instantánea (<200 ms)')
  .action(async (options) => {
    const startedAt = performance.now();
    try {
      const rawPort = parseInt(String(options.port ?? '3030'), 10);
      const allowZero = Boolean(options.serve);
      if (!Number.isInteger(rawPort) || rawPort < (allowZero ? 0 : 1) || rawPort > 65535) {
        throw new Error(`Puerto inválido para culkibo demo: "${options.port}"`);
      }
      const host = String(options.host || '127.0.0.1').trim() || '127.0.0.1';
      process.env.CULKIBO_DEMO = '1';

      const repoRoot = path.resolve(__dirname, '..');
      const webDistDir = path.join(repoRoot, 'web', 'dist');
      const indexHtmlPath = path.join(webDistDir, 'index.html');
      const uiBuilt = fs.existsSync(indexHtmlPath);
      const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));
      const version = String(pkg.version || '1.2.0');

      const buildPayload = (boundPort) => {
        const url = `http://${host}:${boundPort}/?demo=1&lang=en&theme=dark`;
        return {
          ok: true,
          mode: 'demo',
          demo: true,
          version,
          env: { CULKIBO_DEMO: '1' },
          host,
          port: boundPort,
          url,
          sandboxUrl: url,
          uiBuilt,
          readOnly: true,
          bootMs: Math.max(1, Math.round(performance.now() - startedAt)),
          openBrowser: Boolean(options.open !== false && !options.dryRun && !isJsonMode(options) && !process.env.CI),
          datasets: {
            projects: 3,
            databases: 2,
            domains: 4,
            edgeTunnels: 1,
            mcpTools: 125,
            mcpApps: 3,
            topologyNodes: 7
          },
          highlights: [
            'Zero-install interactive sandbox (?demo=1&lang=en&theme=dark)',
            '3 sample projects, 2 managed DBs, 4 HTTPS domains + 1 Sovereign EdgeTunnel',
            '125 MCP tools + 3 sandboxed MCP Apps (ui://culkibo/*) + Async Tasks + Triage Playbook',
            'WebAuthn Passkeys, Secret Leases, OSV CVE Scan, Drift+PgBouncer, OpenTofu IaC, Mesh & Terminal'
          ]
        };
      };

      if ((isJsonMode(options) && !options.serve) || options.dryRun) {
        const payload = buildPayload(rawPort);
        if (isJsonMode(options)) return printJson(payload);
        console.log(`\n\x1b[36m⚡ Culkibo Interactive Demo Sandbox (v${version})\x1b[0m`);
        console.log(`   URL:      ${payload.url}`);
        console.log(`   Env:      CULKIBO_DEMO=1 (read-only · 0 mutations to data/)`);
        console.log(`   UI build: ${payload.uiBuilt ? 'ready (web/dist)' : 'run `npm run web:build` first'}`);
        console.log(`   Ready in: ${payload.bootMs} ms\n`);
        return;
      }

      const fallbackHtml = `<!doctype html><html lang="en"><head><meta charset="utf-8"/><title>Culkibo Demo Sandbox</title></head><body style="background:#09090b;color:#f4f4f5;font-family:system-ui;padding:2rem"><h1>Culkibo Interactive Demo Sandbox (v${version})</h1><p><code>CULKIBO_DEMO=1</code> active. Run <code>npm run web:build</code> to serve the full Obsidian UI bundle.</p></body></html>`;

      const demoServer = http.createServer((req, res) => {
        const parsed = new URL(req.url || '/', `http://${host}`);
        if (parsed.pathname === '/api/health') {
          res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
          res.end(JSON.stringify({ ok: true, mode: 'demo', demo: true, version }));
          return;
        }
        if (!uiBuilt) {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(fallbackHtml);
          return;
        }
        const safeRel = decodeURIComponent(parsed.pathname || '/').replace(/^\/+/, '');
        let filePath = safeRel ? path.resolve(webDistDir, safeRel) : indexHtmlPath;
        const relBack = path.relative(webDistDir, filePath);
        if (relBack.startsWith('..') || path.isAbsolute(relBack) || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
          filePath = indexHtmlPath;
        }
        const ext = path.extname(filePath).toLowerCase();
        res.writeHead(200, {
          'Content-Type': DEMO_MIME_TYPES[ext] || 'application/octet-stream',
          'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600'
        });
        fs.createReadStream(filePath).pipe(res);
      });

      await new Promise((resolve, reject) => {
        demoServer.once('error', reject);
        demoServer.listen(rawPort, host, () => {
          demoServer.removeListener('error', reject);
          resolve(undefined);
        });
      });

      const addr = /** @type {import('net').AddressInfo} */ (demoServer.address());
      const payload = buildPayload(addr && typeof addr === 'object' ? addr.port : rawPort);

      if (isJsonMode(options)) {
        printJson(payload);
      } else {
        console.log(`\n\x1b[32m⚡ Culkibo Interactive Demo Sandbox ready in ${payload.bootMs} ms\x1b[0m`);
        console.log(`   URL:   ${payload.url}`);
        console.log(`   Mode:  CULKIBO_DEMO=1 (read-only · 0 Docker/DB required · 0 data/ writes)`);
        console.log(`   Stop:  Press Ctrl+C\n`);
      }

      if (payload.openBrowser) {
        openBrowserSafe(payload.url);
      }

      const stopDemo = () => {
        demoServer.close(() => {
          process.exitCode = 0;
        });
      };
      process.once('SIGINT', stopDemo);
      process.once('SIGTERM', stopDemo);
    } catch (err) {
      failCli(err, options);
    }
  });

// ===========================================================================
// PIONEER CYCLE-6 CLI: timemachine (Whole-Stack Checkpoints) & finops (Savings)
// ===========================================================================

program
  .command('timemachine <action> <projectId>')
  .description('Whole-Stack Time-Machine: list | create | diff | restore checkpoints (Project + Domains + Crons)')
  .option('--id <cpId>', 'ID del checkpoint objetivo (para restore)')
  .option('--from <aId>', 'ID del checkpoint origen (para diff)')
  .option('--to <bId>', 'ID del checkpoint destino (para diff)')
  .option('-l, --label <label>', 'Etiqueta descriptiva al crear un checkpoint')
  .option('-r, --reason <reason>', 'Motivo operativo al crear un checkpoint')
  .option('--apply', 'Aplicar restauración real (por defecto restore corre en dry-run seguro)')
  .option('--json', 'Salida JSON estructurada')
  .action(async (action, projectId, options) => {
    try {
      const act = String(action || '').toLowerCase();
      if (!['list', 'create', 'diff', 'restore'].includes(act)) {
        throw new Error(`Acción inválida "${action}". Usa: list | create | diff | restore`);
      }
      const remote = getRemoteConfig(options);
      if (remote.apiUrl) {
        /** @type {any} */
        let remoteRes;
        if (act === 'list') {
          remoteRes = await remoteApiRequest(remote, 'GET', `/api/projects/${encodeURIComponent(projectId)}/timemachine`);
        } else if (act === 'create') {
          remoteRes = await remoteApiRequest(remote, 'POST', `/api/projects/${encodeURIComponent(projectId)}/timemachine`, {
            ...(options.label ? { label: String(options.label) } : {}),
            ...(options.reason ? { reason: String(options.reason) } : {})
          });
        } else if (act === 'diff') {
          if (!options.from || !options.to) throw new Error('diff requiere --from <aId> y --to <bId>.');
          remoteRes = await remoteApiRequest(
            remote,
            'GET',
            `/api/projects/${encodeURIComponent(projectId)}/timemachine/diff?from=${encodeURIComponent(options.from)}&to=${encodeURIComponent(options.to)}`
          );
        } else {
          if (!options.id) throw new Error('restore requiere --id <cpId>.');
          remoteRes = await remoteApiRequest(
            remote,
            'POST',
            `/api/projects/${encodeURIComponent(projectId)}/timemachine/${encodeURIComponent(options.id)}/restore`,
            { dryRun: !options.apply }
          );
        }
        if (isJsonMode(options)) return printJson({ ok: true, action: act, projectId, ...remoteRes });
        printJson(remoteRes);
        return;
      }

      const tms = svc.timeMachineService;
      if (act === 'list') {
        const checkpoints = tms.listCheckpoints(projectId);
        const payload = { ok: true, action: 'list', projectId, count: checkpoints.length, checkpoints };
        if (isJsonMode(options)) return printJson(payload);
        console.log(`\n\x1b[36m🕰️  Culkibo Time-Machine — ${projectId} (${checkpoints.length} checkpoints)\x1b[0m`);
        if (checkpoints.length === 0) {
          console.log('   (Sin checkpoints todavía. Ejecuta `culkibo timemachine create ' + projectId + ' --label pre-release`)\n');
        } else {
          console.table(checkpoints.map((c) => ({
            ID: c.id,
            Label: c.label || '—',
            Image: c.state?.imageTag || '—',
            EnvKeys: c.counts?.envVars ?? 0,
            Domains: c.counts?.domains ?? 0,
            CreatedAt: c.createdAt
          })));
        }
      } else if (act === 'create') {
        const checkpoint = tms.createCheckpoint(projectId, {
          ...(options.label ? { label: String(options.label) } : {}),
          ...(options.reason ? { reason: String(options.reason) } : {}),
          actor: 'cli'
        });
        const payload = { ok: true, action: 'create', projectId, checkpoint };
        if (isJsonMode(options)) return printJson(payload);
        console.log(`\n\x1b[32m✅ Checkpoint Time-Machine creado:\x1b[0m ${checkpoint.id} (${checkpoint.label || 'manual'})\n`);
      } else if (act === 'diff') {
        if (!options.from || !options.to) {
          throw new Error('diff requiere --from <aId> y --to <bId>.');
        }
        const diff = tms.diffCheckpoints(projectId, String(options.from), String(options.to));
        const payload = { ok: true, action: 'diff', projectId, fromId: String(options.from), toId: String(options.to), diff };
        if (isJsonMode(options)) return printJson(payload);
        console.log(`\n\x1b[36m🔍 Time-Machine Diff (${options.from} → ${options.to})\x1b[0m`);
        printJson(diff);
      } else {
        if (!options.id) {
          throw new Error('restore requiere --id <cpId> (añade --apply para ejecutar restauración real).');
        }
        const dryRun = !options.apply;
        const result = await tms.restoreCheckpoint(projectId, String(options.id), { dryRun, actor: 'cli' });
        const payload = {
          ...result,
          ok: true,
          action: 'restore',
          projectId,
          checkpointId: String(options.id),
          dryRun
        };
        if (isJsonMode(options)) return printJson(payload);
        if (dryRun) {
          console.log(`\n\x1b[33m🧪 Time-Machine Restore Dry-Run (sin mutaciones)\x1b[0m — checkpoint ${options.id}`);
          console.log('   Añade `--apply` para restaurar atómicamente Proyecto + Dominios + Crons (crea checkpoint de seguridad automático).\n');
        } else {
          console.log(`\n\x1b[32m✅ Time-Machine Restore completado:\x1b[0m ${projectId} → ${options.id}\n`);
        }
      }
    } catch (err) {
      failCli(err, options);
    }
  });

program
  .command('finops')
  .description('FinOps & Right-Sizing: analiza tus apps y calcula el ahorro anual honesto vs Vercel Pro, Railway, Render y Managed Postgres')
  .option('--apps <n>', 'Número de aplicaciones para la comparativa Cloud vs Self-Hosted')
  .option('--dbs <n>', 'Número de bases de datos gestionadas para la comparativa')
  .option('--ram-mb <mb>', 'RAM media estimada por app en MB', '512')
  .option('--bandwidth-gb <gb>', 'Tráfico mensual saliente estimado en GB', '250')
  .option('--json', 'Salida JSON estructurada')
  .action(async (options) => {
    try {
      const finops = svc.finopsOptimizer;
      const projects = svc.projectManager.getAll();
      const databases = svc.databaseManager.list();
      const metricsHistory = typeof svc.metricsCollector.getHistory === 'function'
        ? svc.metricsCollector.getHistory()
        : [];
      let sleepCandidates = [];
      try {
        if (typeof svc.sleepAdvisor.getSleepCandidates === 'function') {
          sleepCandidates = svc.sleepAdvisor.getSleepCandidates({}) || [];
        }
      } catch (e) {}

      const analysis = finops.analyzeFleetAndProjects({
        projects,
        databases,
        metricsHistory,
        sleepCandidates
      });

      const appsCount = options.apps !== undefined
        ? Math.max(0, parseInt(String(options.apps), 10) || 0)
        : Math.max(1, projects.length);
      const dbsCount = options.dbs !== undefined
        ? Math.max(0, parseInt(String(options.dbs), 10) || 0)
        : databases.length;
      const avgRamMbPerApp = Math.max(64, parseInt(String(options.ramMb || '512'), 10) || 512);
      const monthlyBandwidthGb = Math.max(0, Number(options.bandwidthGb || 250) || 0);

      const comparison = finops.compareCloudCosts({
        apps: appsCount,
        databases: dbsCount,
        avgRamMbPerApp,
        monthlyBandwidthGb
      });

      const payload = {
        ok: true,
        inputs: { apps: appsCount, databases: dbsCount, avgRamMbPerApp, monthlyBandwidthGb },
        analysis,
        comparison
      };

      if (isJsonMode(options)) return printJson(payload);

      console.log(`\n\x1b[32m💰 Culkibo FinOps — Cloud vs Self-Hosted Savings (${appsCount} app(s), ${dbsCount} DB(s))\x1b[0m`);
      console.log(`   Self-Hosted est.:  $${comparison.monthlySelfHostedUsd}/mo${comparison.recommendedVps?.name ? ` (${comparison.recommendedVps.provider} ${comparison.recommendedVps.name})` : ''}`);
      console.log(`   Cloud PaaS est.:   $${comparison.monthlyCloudUsd}/mo (Vercel Pro / Railway / Render + Managed DB)`);
      console.log(`   Annual savings:    \x1b[32m$${comparison.annualSavingsUsd}/yr (${comparison.savingsPct}% saved)\x1b[0m`);
      if (Array.isArray(analysis?.recommendations) && analysis.recommendations.length > 0) {
        console.log(`   Right-sizing tips: ${analysis.recommendations.length} recomendación(es) detectadas`);
      }
      console.log('');
    } catch (err) {
      failCli(err, options);
    }
  });

// ===========================================================================
// PIONEER CYCLE-7 CLI: heal (20-Pattern Build Healer) & mesh (WireGuard Mesh)
// ===========================================================================

program
  .command('heal [logFile]')
  .description('Build Auto-Healer determinista (20 patrones, 0 LLM, 100% offline): diagnostica logs y genera parches seguros')
  .option('-t, --text <str>', 'Texto de log directamente como argumento (sin archivo)')
  .option('-p, --project <id>', 'ID de proyecto opcional para generar/aplicar plan de curación')
  .option('--apply', 'Aplicar cambios seguros sobre --project (por defecto corre en dry-run)')
  .option('--json', 'Salida JSON estructurada')
  .action(async (logFile, options) => {
    try {
      let logsText = '';
      if (typeof options.text === 'string' && options.text.length > 0) {
        logsText = options.text;
      } else if (logFile === '-' || (!logFile && !process.stdin.isTTY)) {
        logsText = fs.readFileSync(0, 'utf8');
      } else if (logFile) {
        const resolved = path.resolve(String(logFile));
        if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
          throw new Error(`El archivo de logs no existe: ${resolved}`);
        }
        logsText = fs.readFileSync(resolved, 'utf8');
      } else {
        throw new Error('Proporciona un archivo de logs (`culkibo heal build.log`), `--text "..."` o stdin (`culkibo heal -`).');
      }

      const bh = svc.buildHealerService;
      const projectId = options.project ? String(options.project) : null;
      const diagnosis = bh.diagnoseLogs(logsText, projectId ? { projectId } : {});
      /** @type {any} */
      let healingPlan = null;
      if (projectId) {
        healingPlan = await bh.applyHealingPlan(projectId, {
          logs: logsText,
          ...(diagnosis?.primary?.code ? { code: diagnosis.primary.code } : {}),
          dryRun: !options.apply
        });
      }

      const payload = {
        ok: true,
        projectId,
        dryRun: !options.apply,
        matched: Boolean(diagnosis && diagnosis.matched),
        diagnosis,
        healingPlan
      };

      if (isJsonMode(options)) return printJson(payload);

      if (!diagnosis || !diagnosis.matched) {
        console.log(`\n\x1b[33m🩺 Culkibo Build Healer:\x1b[0m No se detectaron patrones conocidos en ${diagnosis?.analyzedLines ?? 0} línea(s) (${diagnosis?.analyzedMs ?? 0} ms).\n`);
        return;
      }
      const p = diagnosis.primary;
      console.log(`\n\x1b[32m🩺 Culkibo Build Auto-Healer — ${p.code} (${p.severity}, ${Math.round((p.confidence || 0) * 100)}% confianza)\x1b[0m`);
      console.log(`   Título:      ${p.title}`);
      console.log(`   Causa raíz:  ${p.rootCause}`);
      if (p.matchedLine) console.log(`   Evidencia:   ${String(p.matchedLine).slice(0, 140)}`);
      if (p.patchPreview) {
        console.log('\n--- Patch Preview ---\n' + p.patchPreview);
      }
      if (healingPlan) {
        console.log(`\n   Plan (${options.apply ? 'APLICADO' : 'DRY-RUN'}): proyecto ${projectId}`);
      }
      console.log('');
    } catch (err) {
      failCli(err, options);
    }
  });

program
  .command('mesh <action>')
  .description('Zero-Config WireGuard Fleet Mesh (10.88.0.0/24, x25519 AES-256-GCM): status | plan | rotate')
  .option('--node <id>', 'ID del nodo objetivo (para action="rotate")')
  .option('--apply', 'Ejecutar rotación real de clave x25519 (por defecto rotate corre en dry-run seguro)')
  .option('--json', 'Salida JSON estructurada')
  .action(async (action, options) => {
    try {
      const act = String(action || '').toLowerCase();
      if (!['status', 'plan', 'rotate'].includes(act)) {
        throw new Error(`Acción inválida "${action}". Usa: status | plan | rotate`);
      }

      const remote = getRemoteConfig(options);
      if (remote.apiUrl) {
        /** @type {any} */
        let remoteRes;
        if (act === 'status') {
          remoteRes = await remoteApiRequest(remote, 'GET', '/api/fleet/mesh');
        } else if (act === 'plan') {
          remoteRes = await remoteApiRequest(remote, 'POST', '/api/fleet/mesh/plan', { dryRun: true });
        } else {
          if (!options.node) throw new Error('rotate requiere --node <nodeId>.');
          remoteRes = await remoteApiRequest(remote, 'POST', '/api/fleet/mesh/rotate', {
            nodeId: String(options.node),
            dryRun: !options.apply
          });
        }
        const payload = { ok: true, action: act, ...remoteRes };
        if (isJsonMode(options)) return printJson(payload);
        printJson(payload);
        return;
      }

      const fm = svc.fleetMeshService;
      if (act === 'status') {
        const status = fm.getStatus();
        const payload = { ok: true, action: 'status', ...status };
        if (isJsonMode(options)) return printJson(payload);
        console.log(`\n\x1b[36m🕸️  Culkibo WireGuard Fleet Mesh — ${status.cidr || '10.88.0.0/24'} (${status.interfaceName || 'wg0'})\x1b[0m`);
        console.table((status.peers || []).map((p) => ({
          Node: p.nodeId,
          Name: p.name || '—',
          MeshIP: p.meshIp,
          PublicKey: p.publicKey ? `${String(p.publicKey).slice(0, 16)}…` : '—',
          Port: p.listenPort || 51820,
          Status: p.status || 'ready'
        })));
      } else if (act === 'plan') {
        const plan = fm.planMesh(undefined, { dryRun: true });
        const payload = { ok: true, action: 'plan', dryRun: true, ...plan };
        if (isJsonMode(options)) return printJson(payload);
        console.log(`\n\x1b[36m📋 Culkibo WireGuard Mesh Plan (dry-run · 0 private keys exposed)\x1b[0m`);
        printJson(plan);
      } else {
        if (!options.node) {
          throw new Error('rotate requiere --node <nodeId> (añade --apply para ejecutar rotación real).');
        }
        const dryRun = !options.apply;
        const rotation = fm.rotatePeerKey(String(options.node), { dryRun });
        const payload = { ...rotation, ok: true, action: 'rotate', nodeId: String(options.node), dryRun };
        if (isJsonMode(options)) return printJson(payload);
        if (dryRun) {
          console.log(`\n\x1b[33m🧪 WireGuard Key Rotation Dry-Run\x1b[0m — nodo ${options.node} (añade --apply para rotar)\n`);
        } else {
          console.log(`\n\x1b[32m✅ Clave x25519 rotada\x1b[0m — nodo ${options.node}\n`);
        }
      }
    } catch (err) {
      failCli(err, options);
    }
  });

// ===========================================================================
// PIONEER CYCLE-8 CLI: export-iac (OpenTofu/Compose) & cve-scan (OSV.dev SBOM)
// ===========================================================================

program
  .command('export-iac')
  .description('Zero Lock-In IaC Exporter: genera OpenTofu/Terraform (.tf) + docker-compose.yml + .env.example con 0 secretos en claro')
  .option('-f, --format <fmt>', 'Formato a exportar: all | terraform | compose', 'all')
  .option('-o, --out <dir>', 'Directorio destino opcional donde escribir atómicamente los archivos generados')
  .option('-p, --project <id>', 'Exportar únicamente un projectId concreto')
  .option('--json', 'Salida JSON estructurada')
  .action((options) => {
    try {
      const rawFmt = String(options.format || 'all').toLowerCase();
      if (rawFmt !== 'all' && rawFmt !== 'terraform' && rawFmt !== 'compose') {
        throw new Error(`Formato IaC inválido "${options.format}". Usa: all | terraform | compose`);
      }
      /** @type {'all' | 'terraform' | 'compose'} */
      const fmt = rawFmt;
      const iac = svc.iacExporter;
      const exported = iac.exportEstate({
        format: fmt,
        ...(options.project ? { projectIds: [String(options.project)] } : {})
      });
      /** @type {string[]} */
      const writtenFiles = [];
      if (options.out) {
        const outDir = path.resolve(String(options.out));
        fs.mkdirSync(outDir, { recursive: true });
        for (const [name, content] of Object.entries(exported.files || {})) {
          if (!name || name.includes('..') || name.includes('/') || name.includes('\\')) continue;
          const dest = path.resolve(outDir, name);
          const rel = path.relative(outDir, dest);
          if (rel.startsWith('..') || path.isAbsolute(rel)) continue;
          const tmp = `${dest}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
          fs.writeFileSync(tmp, String(content || ''), { encoding: 'utf8', mode: 0o644 });
          fs.renameSync(tmp, dest);
          writtenFiles.push(dest);
        }
      }

      const payload = {
        ...exported,
        ok: true,
        format: fmt,
        writtenFiles
      };
      if (isJsonMode(options)) return printJson(payload);

      console.log(`\n\x1b[32m📦 Culkibo Zero-Lock-In IaC Export (${fmt})\x1b[0m`);
      console.log(`   Archivos:   ${Object.keys(exported.files || {}).join(', ')}`);
      if (exported.stats) {
        console.log(`   Recursos:   ${exported.stats.projects ?? 0} proyectos · ${exported.stats.databases ?? 0} BDs · ${exported.stats.domains ?? 0} dominios · ${exported.stats.crons ?? 0} crons`);
      }
      console.log(`   Secretos:   ${exported.secretsRedactedCount ?? 0} secretos redactados (0 valores en claro)`);
      if (writtenFiles.length > 0) {
        console.log(`   Escritos:   ${writtenFiles.length} archivo(s) en ${path.resolve(String(options.out))}`);
      }
      console.log('');
    } catch (err) {
      failCli(err, options);
    }
  });

program
  .command('cve-scan')
  .description('Runtime SBOM CVE Drift Scanner: audita CycloneDX 1.6 contra OSV.dev (offline/caché por defecto; --online para consulta live)')
  .option('--online', 'Habilitar consulta saliente por lotes a https://api.osv.dev/v1/querybatch')
  .option('--refresh', 'Ignorar caché local de 24h al ejecutar con --online')
  .option('--json', 'Salida JSON estructurada')
  .action(async (options) => {
    try {
      const cveSvc = svc.cveDriftService;
      const report = await cveSvc.scanSbom({
        allowNetwork: Boolean(options.online),
        forceRefresh: Boolean(options.refresh)
      });
      const scannedComponents = Number(report?.scannedPackages ?? report?.scannedComponents ?? 0);
      const vulnerableCount = Number(report?.totalVulnerabilities ?? report?.vulnerableCount ?? 0);
      const severityCounts = report?.bySeverity || report?.severityCounts || { critical: 0, high: 0, medium: 0, low: 0 };
      const mode = String(report?.source || report?.mode || (report?.offline ? 'offline_fallback' : (options.online ? 'osv.dev' : 'offline_fallback')));
      const payload = {
        ...report,
        ok: report && report.ok !== false,
        mode,
        scannedComponents,
        vulnerableCount,
        severityCounts
      };
      if (isJsonMode(options)) return printJson(payload);

      console.log(`\n\x1b[36m🛡️  Culkibo Runtime SBOM CVE Scan (${mode})\x1b[0m`);
      console.log(`   Componentes: ${scannedComponents}`);
      console.log(`   Hallazgos:   ${vulnerableCount} (critical=${severityCounts.critical ?? 0}, high=${severityCounts.high ?? 0}, medium=${severityCounts.medium ?? 0}, low=${severityCounts.low ?? 0})`);
      if (report.cached) console.log(`   Caché:       hit (24h TTL)`);
      console.log('');
    } catch (err) {
      failCli(err, options);
    }
  });

if (require.main === module) {
  program.parseAsync(process.argv).catch((err) => {
    failCli(err, program.opts());
    process.exit(1);
  });
}

module.exports = {
  program,
  detectLocalStack,
  generateStarterManifest,
  parseEnvAssignments,
  remoteApiRequest,
  writeAgentKitFiles,
  runOfflineVerification
};
