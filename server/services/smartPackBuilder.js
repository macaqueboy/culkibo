const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

/**
 * Culkibo SmartPack — Railpack-inspired zero-dependency build intelligence.
 *
 * Inspects a repository (or virtual file/descriptor payload), detects 16+ modern
 * runtimes/frameworks, computes host-aware BuildKit cgroup caps to prevent VPS OOMs,
 * synthesizes an implicit `.dockerignore`, and emits a deterministic, inspectable
 * `build-plan.json` + BuildKit 1.7 multi-stage Dockerfile with cache mounts and
 * optional `zstd:chunked` OCI export flags.
 *
 * Security & cache invariants:
 * - Zero shell construction (`shell: false` argv flags only).
 * - Zero volatile `ARG`s injected (preserves 100% BuildKit layer caching).
 * - Zero secret values ever embedded in plans or rendered Dockerfiles.
 */

const PLAN_SCHEMA_VERSION = 'culkibo.smartpack/v1';

const SUPPORTED_STACKS = Object.freeze([
  'dockerfile',
  'nextjs',
  'nuxt',
  'sveltekit',
  'astro',
  'vite',
  'node',
  'bun',
  'deno',
  'python-uv',
  'python-poetry',
  'python',
  'go',
  'rust',
  'php-frankenphp',
  'elixir',
  'java',
  'static'
]);

const BASE_IMPLICIT_DOCKERIGNORE = Object.freeze([
  '# Auto-synthesized by Culkibo SmartPack (implicit .dockerignore)',
  '.git',
  '.gitignore',
  '.gitattributes',
  '.DS_Store',
  'Thumbs.db',
  '.env',
  '.env.*',
  '!.env.example',
  '*.log',
  'npm-debug.log*',
  'yarn-debug.log*',
  'yarn-error.log*',
  'pnpm-debug.log*',
  'node_modules',
  '.venv',
  'venv',
  '__pycache__',
  '*.py[cod]',
  '.pytest_cache',
  '.mypy_cache',
  'target',
  '.idea',
  '.vscode',
  'coverage',
  '.nyc_output',
  '.next',
  '.nuxt',
  '.output',
  '.svelte-kit',
  '.astro',
  'tmp',
  '.tmp',
  '*.sqlite-journal',
  '*.sqlite-wal',
  '*.sqlite-shm'
]);

/** @type {Record<string, string[]>} */
const STACK_EXTRA_DOCKERIGNORE = Object.freeze({
  nextjs: ['out'],
  vite: ['dist'],
  astro: ['dist'],
  sveltekit: ['build'],
  node: ['dist'],
  bun: ['dist'],
  'php-frankenphp': ['vendor', 'storage/logs/*', 'bootstrap/cache/*'],
  elixir: ['_build', 'deps'],
  java: ['.gradle', 'build'],
  go: ['bin']
});

const SAFE_PKG_NAME_RE = /^[a-z0-9][a-z0-9.+_-]{0,63}$/i;
const SAFE_VERSION_RE = /^[0-9]+(?:\.[0-9]+){0,2}$/;
const DANGEROUS_CMD_CHARS_RE = /[\r\n\0`]|(?:\$\()/;

/**
 * Sanitizes a package list (apt/apk) to prevent Dockerfile injection.
 * @param {any} list
 * @returns {string[]}
 */
function sanitizePackages(list) {
  if (!Array.isArray(list)) return [];
  /** @type {string[]} */
  const out = [];
  const seen = new Set();
  for (const raw of list) {
    const pkg = String(raw || '').trim();
    if (!pkg || seen.has(pkg) || !SAFE_PKG_NAME_RE.test(pkg)) continue;
    seen.add(pkg);
    out.push(pkg);
  }
  return out;
}

/**
 * Sanitizes a container port into a valid TCP range (1..65535).
 * @param {any} rawPort
 * @param {number} fallback
 * @returns {number}
 */
function sanitizePort(rawPort, fallback) {
  const n = Number(rawPort);
  if (Number.isInteger(n) && n >= 1 && n <= 65535) return n;
  return fallback;
}

/**
 * Parses a safe Dockerfile RUN command string (rejects control chars and command substitution).
 * @param {any} raw
 * @param {string} fallback
 * @returns {string}
 */
function sanitizeCommandLine(raw, fallback) {
  if (typeof raw !== 'string') return fallback;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 400 || DANGEROUS_CMD_CHARS_RE.test(trimmed)) return fallback;
  return trimmed;
}

/**
 * Extracts a safe Node.js major version from `.nvmrc` or `package.json#engines.node`.
 * @param {string | null} raw
 * @returns {string}
 */
function parseNodeMajor(raw) {
  const s = String(raw || '').trim();
  const m = s.match(/(\d{2})/);
  if (m) {
    const num = Number(m[1]);
    if (num >= 18 && num <= 26) return String(num);
  }
  return '22';
}

/**
 * Extracts a safe Go version (e.g. `1.24`) from `go.mod`.
 * @param {string | null} goModText
 * @returns {string}
 */
function parseGoVersion(goModText) {
  const m = String(goModText || '').match(/^\s*go\s+(\d+\.\d+)(?:\.\d+)?/m);
  if (m && SAFE_VERSION_RE.test(m[1])) return m[1];
  return '1.24';
}

/**
 * Extracts a safe Rust binary crate name from `Cargo.toml`.
 * @param {string | null} cargoText
 * @returns {string}
 */
function parseRustBinaryName(cargoText) {
  const text = String(cargoText || '');
  const binMatch = text.match(/\[\[bin\]\][\s\S]{0,200}?name\s*=\s*"([a-zA-Z0-9_-]{1,64})"/);
  if (binMatch) return binMatch[1];
  const pkgMatch = text.match(/\[package\][\s\S]{0,300}?name\s*=\s*"([a-zA-Z0-9_-]{1,64})"/);
  if (pkgMatch) return pkgMatch[1];
  return 'app';
}

/**
 * Extracts Python version (e.g. `3.12`) from `.python-version` or `pyproject.toml`.
 * @param {string | null} pyVerText
 * @param {string | null} pyprojectText
 * @returns {string}
 */
function parsePythonVersion(pyVerText, pyprojectText) {
  const raw = String(pyVerText || '').trim();
  const m1 = raw.match(/(3\.(?:9|1[0-4]))/);
  if (m1) return m1[1];
  const m2 = String(pyprojectText || '').match(/requires-python\s*=\s*["'][^"']*?(3\.(?:9|1[0-4]))/);
  if (m2) return m2[1];
  return '3.12';
}

/**
 * Computes host-aware BuildKit cgroup `--memory` / `--cpus` caps and optional
 * `zstd:chunked` OCI export flags so concurrent image builds never OOM-kill a VPS.
 *
 * @param {{
 *   hostMemoryMb?: number | null,
 *   hostCpus?: number | null,
 *   memoryMb?: number | null,
 *   cpus?: number | string | null,
 *   zstdChunked?: boolean
 * }} [opts]
 */
function computeBuildKitResourceLimits(opts = {}) {
  const detectedMemMb = Math.max(256, Math.round(os.totalmem() / (1024 * 1024)));
  const detectedCpus = typeof os.availableParallelism === 'function'
    ? os.availableParallelism()
    : (os.cpus().length || 1);

  const hostMemoryMb = Number.isFinite(Number(opts.hostMemoryMb)) && Number(opts.hostMemoryMb) >= 256
    ? Math.round(Number(opts.hostMemoryMb))
    : detectedMemMb;
  const hostCpus = Number.isFinite(Number(opts.hostCpus)) && Number(opts.hostCpus) >= 1
    ? Math.round(Number(opts.hostCpus))
    : Math.max(1, detectedCpus);

  let defaultBuildMemMb;
  let defaultBuildCpus;
  let maxParallelStages;

  if (hostMemoryMb <= 2048) {
    // Small VPS (512 MB - 2 GB): strictly reserve headroom for OS + daemon + Caddy + DBs
    defaultBuildMemMb = Math.max(256, Math.min(1024, Math.floor(hostMemoryMb * 0.55)));
    defaultBuildCpus = Math.max(1, hostCpus > 1 ? hostCpus - 1 : 1);
    maxParallelStages = 1;
  } else if (hostMemoryMb <= 8192) {
    defaultBuildMemMb = Math.max(512, Math.min(4096, Math.floor(hostMemoryMb * 0.65)));
    defaultBuildCpus = Math.max(1, Math.min(hostCpus - 1 || 1, Math.ceil(hostCpus * 0.75)));
    maxParallelStages = 2;
  } else {
    defaultBuildMemMb = Math.max(1024, Math.min(8192, Math.floor(hostMemoryMb * 0.70)));
    defaultBuildCpus = Math.max(1, hostCpus - 1);
    maxParallelStages = 3;
  }

  const reqMem = Number(opts.memoryMb);
  const buildMemoryMb = Number.isFinite(reqMem) && reqMem >= 128
    ? Math.min(Math.max(256, Math.floor(hostMemoryMb * 0.85)), Math.round(reqMem))
    : defaultBuildMemMb;

  const reqCpus = Number(opts.cpus);
  const buildCpus = Number.isFinite(reqCpus) && reqCpus >= 0.25
    ? Number(Math.min(hostCpus, reqCpus).toFixed(2))
    : defaultBuildCpus;

  const zstdChunked = opts.zstdChunked !== false;
  const dockerBuildFlags = [
    '--memory', `${buildMemoryMb}m`,
    '--cpus', String(buildCpus)
  ];
  const zstdChunkedFlags = zstdChunked
    ? ['--output', 'type=image,compression=zstd,compression-level=3,force-compression=true,oci-mediatypes=true']
    : [];

  return {
    hostMemoryMb,
    hostCpus,
    buildMemoryMb,
    buildCpus,
    memory: `${buildMemoryMb}m`,
    cpus: buildCpus,
    maxParallelStages,
    reservedHeadroomMb: Math.max(0, hostMemoryMb - buildMemoryMb),
    dockerBuildFlags,
    zstdChunked,
    zstdChunkedFlags
  };
}

/**
 * Generates an implicit `.dockerignore` tailored to the detected stack so `.git`,
 * `node_modules`, `.venv`, `target`, `.env*`, and `*.log` never bloat build contexts
 * or leak local secrets into Docker layers.
 *
 * @param {string} [stackOrDir]
 * @param {{ stack?: string, existingContent?: string | null, extraPatterns?: string[], keepPatterns?: string[] }} [opts]
 */
function generateImplicitDockerignore(stackOrDir = 'node', opts = {}) {
  const effectiveStack = (opts && typeof opts.stack === 'string' && opts.stack.trim())
    ? opts.stack.trim()
    : stackOrDir;
  let existing = typeof opts.existingContent === 'string' ? opts.existingContent : '';
  if (!existing && opts && typeof opts.stack === 'string' && stackOrDir && stackOrDir !== opts.stack) {
    try {
      const candidate = path.join(String(stackOrDir), '.dockerignore');
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        existing = fs.readFileSync(candidate, 'utf8');
      }
    } catch (e) {}
  }
  const hasExisting = existing.trim().length > 0;
  const extraForStack = STACK_EXTRA_DOCKERIGNORE[String(effectiveStack || '').toLowerCase()] || [];

  /** @type {string[]} */
  const lines = [];
  const seen = new Set();

  const addLine = (raw) => {
    const clean = String(raw || '').replace(/[\r\n\0]/g, '').trim();
    if (!clean || seen.has(clean)) return;
    seen.add(clean);
    lines.push(clean);
  };

  if (hasExisting) {
    for (const ln of existing.split(/\r?\n/)) {
      const clean = ln.replace(/\0/g, '').trim();
      if (clean) addLine(clean);
    }
    addLine('# Appended safety exclusions by Culkibo SmartPack');
  }

  for (const ln of BASE_IMPLICIT_DOCKERIGNORE) addLine(ln);
  for (const ln of extraForStack) addLine(ln);
  if (Array.isArray(opts.extraPatterns)) {
    for (const ln of opts.extraPatterns) addLine(ln);
  }
  if (Array.isArray(opts.keepPatterns)) {
    for (const kp of opts.keepPatterns) {
      const clean = String(kp || '').replace(/[\r\n\0]/g, '').trim();
      if (clean) addLine(clean.startsWith('!') ? clean : `!${clean}`);
    }
  }

  const patterns = lines.filter((l) => !l.startsWith('#'));
  return {
    implicit: !hasExisting,
    mergedWithExisting: hasExisting,
    patterns,
    excludedCount: patterns.length,
    content: `${lines.join('\n')}\n`
  };
}

/**
 * Builds a unified read helper over either a real filesystem directory or an
 * in-memory virtual files map (`{ 'package.json': '...', ... }`).
 *
 * @param {string | null} dirPath
 * @param {Record<string, string> | null} virtualFiles
 */
function createContextReader(dirPath, virtualFiles) {
  /** @type {Map<string, string>} */
  const vMap = new Map();
  if (virtualFiles && typeof virtualFiles === 'object') {
    for (const [k, v] of Object.entries(virtualFiles)) {
      const norm = String(k || '').replace(/\\/g, '/').replace(/^\/+/, '');
      if (norm && typeof v === 'string') vMap.set(norm, v);
    }
  }

  const has = (rel) => {
    const norm = String(rel || '').replace(/\\/g, '/').replace(/^\/+/, '');
    if (vMap.has(norm)) return true;
    if (dirPath) {
      try { return fs.existsSync(path.join(dirPath, norm)); } catch (e) { return false; }
    }
    return false;
  };

  const readText = (rel, maxBytes = 128 * 1024) => {
    const norm = String(rel || '').replace(/\\/g, '/').replace(/^\/+/, '');
    if (vMap.has(norm)) return String(vMap.get(norm) || '').slice(0, maxBytes);
    if (dirPath) {
      try {
        const abs = path.join(dirPath, norm);
        if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) return null;
        return fs.readFileSync(abs, 'utf8').slice(0, maxBytes);
      } catch (e) {
        return null;
      }
    }
    return null;
  };

  const readJson = (rel) => {
    const raw = readText(rel);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch (e) { return null; }
  };

  return { has, readText, readJson };
}

/**
 * Detects JS package manager and install/run commands from lockfiles and `package.json`.
 * @param {ReturnType<typeof createContextReader>} reader
 * @param {any} pkg
 */
function detectJsPackageManager(reader, pkg) {
  const pmField = String((pkg && pkg.packageManager) || '').toLowerCase();
  if (reader.has('bun.lock') || reader.has('bun.lockb') || reader.has('bunfig.toml') || pmField.startsWith('bun@')) {
    return {
      name: 'bun',
      lockfiles: [reader.has('bun.lock') ? 'bun.lock' : (reader.has('bun.lockb') ? 'bun.lockb' : null)].filter(Boolean),
      installCmd: 'bun install --frozen-lockfile || bun install',
      runPrefix: 'bun run',
      cacheMount: { id: 'culkibo-bun-cache', target: '/root/.bun/install/cache', sharing: 'locked' },
      enableCorepack: false
    };
  }
  if (reader.has('pnpm-lock.yaml') || pmField.startsWith('pnpm@')) {
    return {
      name: 'pnpm',
      lockfiles: ['pnpm-lock.yaml'],
      installCmd: 'pnpm install --frozen-lockfile',
      runPrefix: 'pnpm run',
      cacheMount: { id: 'culkibo-pnpm-store', target: '/root/.local/share/pnpm/store', sharing: 'locked' },
      enableCorepack: true
    };
  }
  if (reader.has('yarn.lock') || pmField.startsWith('yarn@')) {
    return {
      name: 'yarn',
      lockfiles: ['yarn.lock'],
      installCmd: 'yarn install --frozen-lockfile',
      runPrefix: 'yarn',
      cacheMount: { id: 'culkibo-yarn-cache', target: '/usr/local/share/.cache/yarn', sharing: 'locked' },
      enableCorepack: true
    };
  }
  const hasNpmLock = reader.has('package-lock.json') || reader.has('npm-shrinkwrap.json');
  return {
    name: 'npm',
    lockfiles: hasNpmLock ? ['package-lock.json'] : [],
    installCmd: hasNpmLock ? 'npm ci' : 'npm install',
    runPrefix: 'npm run',
    cacheMount: { id: 'culkibo-npm-cache', target: '/root/.npm', sharing: 'locked' },
    enableCorepack: false
  };
}

/**
 * Renders a deterministic BuildKit 1.7 multi-stage Dockerfile from a SmartPack build plan.
 * Zero volatile `ARG`s; strict JSON-array `CMD`; BuildKit cache mounts on every dep/build layer.
 *
 * @param {any} plan
 * @returns {string}
 */
function renderDockerfileFromPlan(plan) {
  if (!plan || typeof plan !== 'object') {
    throw new Error('renderDockerfileFromPlan requires a valid SmartPack build plan');
  }
  if (plan.stack === 'dockerfile') {
    return '# Existing repository Dockerfile detected — SmartPack preserves user Dockerfile with BuildKit cgroup caps & implicit .dockerignore.\n';
  }

  const lines = [
    '# syntax=docker/dockerfile:1.7',
    `# Generated deterministically by Culkibo SmartPack (${plan.stack} / ${plan.runtime} ${plan.runtimeVersion || ''})`.trim()
  ];

  const stages = Array.isArray(plan.stages) ? plan.stages : [];
  for (let sIdx = 0; sIdx < stages.length; sIdx++) {
    const st = stages[sIdx];
    lines.push('');
    lines.push(st.name ? `FROM ${st.from} AS ${st.name}` : `FROM ${st.from}`);
    if (st.workdir) lines.push(`WORKDIR ${st.workdir}`);

    if (st.env && typeof st.env === 'object') {
      for (const [k, v] of Object.entries(st.env)) {
        if (/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(k) && !/[\r\n\0]/.test(String(v))) {
          lines.push(`ENV ${k}=${String(v)}`);
        }
      }
    }

    const apk = sanitizePackages(st.apkPackages);
    if (apk.length > 0) {
      lines.push(`RUN apk add --no-cache ${apk.join(' ')}`);
    }
    const apt = sanitizePackages(st.aptPackages);
    if (apt.length > 0) {
      lines.push(
        `RUN --mount=type=cache,target=/var/cache/apt,sharing=locked ` +
        `--mount=type=cache,target=/var/lib/apt,sharing=locked ` +
        `apt-get update && apt-get install -y --no-install-recommends ${apt.join(' ')}`
      );
    }

    if (Array.isArray(st.steps)) {
      for (const step of st.steps) {
        if (!step) continue;
        if (step.type === 'copy') {
          const fromPart = step.fromStage ? `--from=${step.fromStage} ` : '';
          lines.push(`COPY ${fromPart}${step.src} ${step.dest}`);
        } else if (step.type === 'run') {
          const mounts = Array.isArray(step.cacheMounts)
            ? step.cacheMounts.map((m) => `--mount=type=cache,id=${m.id},target=${m.target}${m.sharing ? `,sharing=${m.sharing}` : ''}`).join(' ')
            : '';
          const mountPrefix = mounts ? `${mounts} ` : '';
          lines.push(`RUN ${mountPrefix}${step.command}`);
        }
      }
    }

    const isLastStage = sIdx === stages.length - 1;
    if (isLastStage) {
      if (plan.containerPort) {
        lines.push(`EXPOSE ${sanitizePort(plan.containerPort, 3000)}`);
      }
      if (Array.isArray(plan.startCommand) && plan.startCommand.length > 0) {
        lines.push(`CMD ${JSON.stringify(plan.startCommand)}`);
      }
    }
  }

  return `${lines.join('\n')}\n`;
}

/**
 * Generates a deterministic, inspectable SmartPack `build-plan.json` for a directory
 * or descriptor payload.
 *
 * @param {string | {
 *   dirPath?: string | null,
 *   contextDir?: string | null,
 *   stack?: string | null,
 *   files?: Record<string, string> | null,
 *   packageJson?: Record<string, any> | null,
 *   port?: number | null,
 *   containerPort?: number | null,
 *   buildCommand?: string | null,
 *   startCommand?: string | string[] | null,
 *   aptPackages?: string[],
 *   apkPackages?: string[],
 *   zstdChunked?: boolean,
 *   hostMemoryMb?: number | null,
 *   hostCpus?: number | null,
 *   memoryMb?: number | null,
 *   cpus?: number | string | null,
 *   ignoreExistingDockerfile?: boolean
 * }} input
 * @param {Record<string, any>} [extraOpts]
 */
function generateBuildPlan(input, extraOpts = {}) {
  const opts = typeof input === 'string'
    ? { ...extraOpts, dirPath: input }
    : { ...extraOpts, ...(input && typeof input === 'object' ? input : {}) };

  const dirPath = opts.dirPath || opts.contextDir ? path.resolve(String(opts.dirPath || opts.contextDir)) : null;
  /** @type {Record<string, string>} */
  const virtualFiles = opts.files && typeof opts.files === 'object' ? { ...opts.files } : {};
  if (opts.packageJson && typeof opts.packageJson === 'object' && !virtualFiles['package.json']) {
    virtualFiles['package.json'] = JSON.stringify(opts.packageJson);
  }

  const reader = createContextReader(dirPath, virtualFiles);
  const pkg = reader.readJson('package.json');
  const allJsDeps = pkg
    ? { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) }
    : {};
  const scripts = (pkg && pkg.scripts && typeof pkg.scripts === 'object') ? pkg.scripts : {};

  const forcedStack = opts.stack ? String(opts.stack).trim().toLowerCase() : null;
  let stack = forcedStack && SUPPORTED_STACKS.includes(/** @type {any} */ (forcedStack)) ? forcedStack : '';
  const detectedSignals = [];

  if (!stack) {
    if (reader.has('Dockerfile') && opts.ignoreExistingDockerfile !== true) {
      stack = 'dockerfile';
      detectedSignals.push('Dockerfile');
    } else if (reader.has('deno.json') || reader.has('deno.jsonc') || reader.has('deno.lock')) {
      stack = 'deno';
      detectedSignals.push(reader.has('deno.json') ? 'deno.json' : 'deno.jsonc');
    } else if (pkg) {
      if (allJsDeps.next || reader.has('next.config.js') || reader.has('next.config.mjs') || reader.has('next.config.ts')) {
        stack = 'nextjs';
        detectedSignals.push('package.json:next');
      } else if (allJsDeps.nuxt || reader.has('nuxt.config.ts') || reader.has('nuxt.config.js')) {
        stack = 'nuxt';
        detectedSignals.push('package.json:nuxt');
      } else if (allJsDeps['@sveltejs/kit'] || reader.has('svelte.config.js') || reader.has('svelte.config.ts')) {
        stack = 'sveltekit';
        detectedSignals.push('package.json:@sveltejs/kit');
      } else if (allJsDeps.astro || reader.has('astro.config.mjs') || reader.has('astro.config.ts')) {
        stack = 'astro';
        detectedSignals.push('package.json:astro');
      } else if (allJsDeps.vite && !scripts.start) {
        stack = 'vite';
        detectedSignals.push('package.json:vite');
      } else if (reader.has('bun.lock') || reader.has('bun.lockb') || reader.has('bunfig.toml')) {
        stack = 'bun';
        detectedSignals.push('bun.lock');
      } else {
        stack = 'node';
        detectedSignals.push('package.json');
      }
    } else if (reader.has('uv.lock') || (reader.has('pyproject.toml') && /\[tool\.uv\]/i.test(reader.readText('pyproject.toml') || ''))) {
      stack = 'python-uv';
      detectedSignals.push(reader.has('uv.lock') ? 'uv.lock' : 'pyproject.toml:[tool.uv]');
    } else if (reader.has('poetry.lock') || (reader.has('pyproject.toml') && /\[tool\.poetry\]/i.test(reader.readText('pyproject.toml') || ''))) {
      stack = 'python-poetry';
      detectedSignals.push(reader.has('poetry.lock') ? 'poetry.lock' : 'pyproject.toml:[tool.poetry]');
    } else if (reader.has('requirements.txt') || reader.has('pyproject.toml') || reader.has('Pipfile') || reader.has('main.py') || reader.has('app.py')) {
      stack = 'python';
      detectedSignals.push(reader.has('requirements.txt') ? 'requirements.txt' : 'pyproject.toml');
    } else if (reader.has('go.mod')) {
      stack = 'go';
      detectedSignals.push('go.mod');
    } else if (reader.has('Cargo.toml')) {
      stack = 'rust';
      detectedSignals.push('Cargo.toml');
    } else if (reader.has('composer.json') || reader.has('index.php') || reader.has('public/index.php')) {
      stack = 'php-frankenphp';
      detectedSignals.push(reader.has('composer.json') ? 'composer.json' : 'index.php');
    } else if (reader.has('mix.exs')) {
      stack = 'elixir';
      detectedSignals.push('mix.exs');
    } else if (reader.has('pom.xml') || reader.has('build.gradle') || reader.has('build.gradle.kts')) {
      stack = 'java';
      detectedSignals.push(reader.has('pom.xml') ? 'pom.xml' : 'build.gradle');
    } else if (reader.has('index.html') || reader.has('public/index.html')) {
      stack = 'static';
      detectedSignals.push('index.html');
    } else {
      stack = 'node';
      detectedSignals.push('fallback:node');
    }
  } else {
    detectedSignals.push(`explicit:${stack}`);
  }

  const extraApt = sanitizePackages(opts.aptPackages);
  const extraApk = sanitizePackages(opts.apkPackages);
  const requestedPort = opts.port !== undefined && opts.port !== null ? opts.port : opts.containerPort;
  const resourceLimits = computeBuildKitResourceLimits({
    hostMemoryMb: opts.hostMemoryMb,
    hostCpus: opts.hostCpus,
    memoryMb: opts.memoryMb,
    cpus: opts.cpus,
    zstdChunked: opts.zstdChunked !== false
  });
  const existingIgnore = reader.readText('.dockerignore');
  const dockerignore = generateImplicitDockerignore(stack, {
    existingContent: existingIgnore,
    keepPatterns: stack === 'static' ? ['dist', 'build'] : []
  });

  const nodeMajor = parseNodeMajor(reader.readText('.nvmrc') || reader.readText('.node-version') || pkg?.engines?.node);
  const jsPm = detectJsPackageManager(reader, pkg);

  /** @type {any} */
  let spec;

  if (stack === 'dockerfile') {
    spec = {
      label: 'Custom Dockerfile',
      runtime: 'dockerfile',
      runtimeVersion: 'custom',
      packageManager: null,
      containerPort: sanitizePort(requestedPort, 3000),
      baseImage: 'custom',
      runtimeImage: 'custom',
      aptPackages: extraApt,
      apkPackages: extraApk,
      cacheMounts: [],
      installCommand: null,
      buildCommand: null,
      startCommand: null,
      stages: [],
      warnings: []
    };
  } else if (stack === 'nextjs') {
    const nextCfg = reader.readText('next.config.mjs') || reader.readText('next.config.ts') || reader.readText('next.config.js') || '';
    const isStandalone = /output\s*:\s*['"]standalone['"]/.test(nextCfg);
    const buildCmd = sanitizeCommandLine(opts.buildCommand, `${jsPm.runPrefix} build`);
    const baseImg = jsPm.name === 'bun' ? 'oven/bun:1-alpine' : `node:${nodeMajor}-alpine`;
    const copyManifests = ['package.json', ...jsPm.lockfiles].join(' ');
    const runtimeSteps = isStandalone
      ? [
          { type: 'copy', fromStage: 'builder', src: '/app/public', dest: './public' },
          { type: 'copy', fromStage: 'builder', src: '/app/.next/standalone', dest: './' },
          { type: 'copy', fromStage: 'builder', src: '/app/.next/static', dest: './.next/static' }
        ]
      : [
          { type: 'copy', fromStage: 'builder', src: '/app/package.json', dest: './package.json' },
          { type: 'copy', fromStage: 'builder', src: '/app/node_modules', dest: './node_modules' },
          { type: 'copy', fromStage: 'builder', src: '/app/.next', dest: './.next' },
          { type: 'copy', fromStage: 'builder', src: '/app/public', dest: './public' }
        ];
    const startCmd = isStandalone ? ['node', 'server.js'] : [jsPm.name === 'bun' ? 'bun' : 'npm', 'run', 'start'];
    const cacheMounts = [jsPm.cacheMount, { id: 'culkibo-next-cache', target: '/app/.next/cache', sharing: 'locked' }];
    spec = {
      label: isStandalone ? 'Next.js (Standalone)' : 'Next.js',
      runtime: jsPm.name === 'bun' ? 'bun' : 'node',
      runtimeVersion: jsPm.name === 'bun' ? '1' : nodeMajor,
      packageManager: jsPm.name,
      containerPort: sanitizePort(requestedPort, 3000),
      baseImage: baseImg,
      runtimeImage: baseImg,
      aptPackages: extraApt,
      apkPackages: sanitizePackages(['libc6-compat', ...extraApk]),
      cacheMounts,
      installCommand: jsPm.installCmd,
      buildCommand: buildCmd,
      startCommand: startCmd,
      stages: [
        {
          name: 'builder',
          from: baseImg,
          workdir: '/app',
          env: { NEXT_TELEMETRY_DISABLED: '1' },
          apkPackages: sanitizePackages(['libc6-compat', ...extraApk]),
          steps: [
            ...(jsPm.enableCorepack ? [{ type: 'run', command: 'corepack enable' }] : []),
            { type: 'copy', src: copyManifests, dest: './' },
            { type: 'run', cacheMounts: [jsPm.cacheMount], command: jsPm.installCmd },
            { type: 'copy', src: '.', dest: '.' },
            { type: 'run', cacheMounts: [{ id: 'culkibo-next-cache', target: '/app/.next/cache', sharing: 'locked' }], command: buildCmd }
          ]
        },
        {
          name: 'runtime',
          from: baseImg,
          workdir: '/app',
          env: { NODE_ENV: 'production', HOSTNAME: '0.0.0.0', PORT: String(sanitizePort(requestedPort, 3000)), NEXT_TELEMETRY_DISABLED: '1' },
          steps: runtimeSteps
        }
      ],
      warnings: isStandalone ? [] : ['Tip: set `output: "standalone"` in next.config to shrink image size by ~70%.']
    };
  } else if (stack === 'nuxt') {
    const baseImg = `node:${nodeMajor}-alpine`;
    const buildCmd = sanitizeCommandLine(opts.buildCommand, `${jsPm.runPrefix} build`);
    const port = sanitizePort(requestedPort, 3000);
    spec = {
      label: 'Nuxt (Nitro)',
      runtime: 'node',
      runtimeVersion: nodeMajor,
      packageManager: jsPm.name,
      containerPort: port,
      baseImage: baseImg,
      runtimeImage: baseImg,
      aptPackages: extraApt,
      apkPackages: extraApk,
      cacheMounts: [jsPm.cacheMount],
      installCommand: jsPm.installCmd,
      buildCommand: buildCmd,
      startCommand: ['node', '.output/server/index.mjs'],
      stages: [
        {
          name: 'builder',
          from: baseImg,
          workdir: '/app',
          apkPackages: extraApk,
          steps: [
            ...(jsPm.enableCorepack ? [{ type: 'run', command: 'corepack enable' }] : []),
            { type: 'copy', src: ['package.json', ...jsPm.lockfiles].join(' '), dest: './' },
            { type: 'run', cacheMounts: [jsPm.cacheMount], command: jsPm.installCmd },
            { type: 'copy', src: '.', dest: '.' },
            { type: 'run', command: buildCmd }
          ]
        },
        {
          name: 'runtime',
          from: baseImg,
          workdir: '/app',
          env: { NODE_ENV: 'production', NITRO_HOST: '0.0.0.0', NITRO_PORT: String(port) },
          steps: [{ type: 'copy', fromStage: 'builder', src: '/app/.output', dest: './.output' }]
        }
      ],
      warnings: []
    };
  } else if (stack === 'sveltekit') {
    const baseImg = `node:${nodeMajor}-alpine`;
    const buildCmd = sanitizeCommandLine(opts.buildCommand, `${jsPm.runPrefix} build`);
    const port = sanitizePort(requestedPort, 3000);
    spec = {
      label: 'SvelteKit',
      runtime: 'node',
      runtimeVersion: nodeMajor,
      packageManager: jsPm.name,
      containerPort: port,
      baseImage: baseImg,
      runtimeImage: baseImg,
      aptPackages: extraApt,
      apkPackages: extraApk,
      cacheMounts: [jsPm.cacheMount],
      installCommand: jsPm.installCmd,
      buildCommand: buildCmd,
      startCommand: ['node', 'build'],
      stages: [
        {
          name: 'builder',
          from: baseImg,
          workdir: '/app',
          apkPackages: extraApk,
          steps: [
            ...(jsPm.enableCorepack ? [{ type: 'run', command: 'corepack enable' }] : []),
            { type: 'copy', src: ['package.json', ...jsPm.lockfiles].join(' '), dest: './' },
            { type: 'run', cacheMounts: [jsPm.cacheMount], command: jsPm.installCmd },
            { type: 'copy', src: '.', dest: '.' },
            { type: 'run', command: buildCmd }
          ]
        },
        {
          name: 'runtime',
          from: baseImg,
          workdir: '/app',
          env: { NODE_ENV: 'production', HOST: '0.0.0.0', PORT: String(port) },
          steps: [
            { type: 'copy', fromStage: 'builder', src: '/app/package.json', dest: './package.json' },
            { type: 'copy', fromStage: 'builder', src: '/app/node_modules', dest: './node_modules' },
            { type: 'copy', fromStage: 'builder', src: '/app/build', dest: './build' }
          ]
        }
      ],
      warnings: []
    };
  } else if (stack === 'astro' || stack === 'vite') {
    const isAstroNode = stack === 'astro' && Boolean(allJsDeps['@astrojs/node']);
    const baseImg = `node:${nodeMajor}-alpine`;
    const runtimeImg = isAstroNode ? baseImg : 'caddy:2.11-alpine';
    const buildCmd = sanitizeCommandLine(opts.buildCommand, `${jsPm.runPrefix} build`);
    const port = sanitizePort(requestedPort, isAstroNode ? 4321 : 8080);
    spec = {
      label: stack === 'astro' ? (isAstroNode ? 'Astro (SSR Node)' : 'Astro (Static)') : 'Vite SPA (Caddy Static)',
      runtime: isAstroNode ? 'node' : 'caddy-static',
      runtimeVersion: isAstroNode ? nodeMajor : '2.11',
      packageManager: jsPm.name,
      containerPort: port,
      baseImage: baseImg,
      runtimeImage: runtimeImg,
      aptPackages: extraApt,
      apkPackages: extraApk,
      cacheMounts: [jsPm.cacheMount],
      installCommand: jsPm.installCmd,
      buildCommand: buildCmd,
      startCommand: isAstroNode
        ? ['node', './dist/server/entry.mjs']
        : ['caddy', 'file-server', '--root', '/srv', '--listen', `:${port}`],
      stages: [
        {
          name: 'builder',
          from: baseImg,
          workdir: '/app',
          apkPackages: extraApk,
          steps: [
            ...(jsPm.enableCorepack ? [{ type: 'run', command: 'corepack enable' }] : []),
            { type: 'copy', src: ['package.json', ...jsPm.lockfiles].join(' '), dest: './' },
            { type: 'run', cacheMounts: [jsPm.cacheMount], command: jsPm.installCmd },
            { type: 'copy', src: '.', dest: '.' },
            { type: 'run', command: buildCmd }
          ]
        },
        {
          name: 'runtime',
          from: runtimeImg,
          workdir: isAstroNode ? '/app' : '/srv',
          env: isAstroNode ? { HOST: '0.0.0.0', PORT: String(port), NODE_ENV: 'production' } : {},
          steps: isAstroNode
            ? [
                { type: 'copy', fromStage: 'builder', src: '/app/dist', dest: './dist' },
                { type: 'copy', fromStage: 'builder', src: '/app/node_modules', dest: './node_modules' }
              ]
            : [{ type: 'copy', fromStage: 'builder', src: '/app/dist', dest: '/srv' }]
        }
      ],
      warnings: []
    };
  } else if (stack === 'bun') {
    const baseImg = 'oven/bun:1-alpine';
    const port = sanitizePort(requestedPort, 3000);
    const hasBuild = Boolean(scripts.build);
    const buildCmd = hasBuild ? sanitizeCommandLine(opts.buildCommand, 'bun run build') : null;
    const entry = reader.has('src/index.ts') ? 'src/index.ts' : (reader.has('index.ts') ? 'index.ts' : 'index.js');
    const startCmd = scripts.start ? ['bun', 'run', 'start'] : ['bun', 'run', entry];
    const cacheMount = { id: 'culkibo-bun-cache', target: '/root/.bun/install/cache', sharing: 'locked' };
    spec = {
      label: 'Bun',
      runtime: 'bun',
      runtimeVersion: '1',
      packageManager: 'bun',
      containerPort: port,
      baseImage: baseImg,
      runtimeImage: baseImg,
      aptPackages: extraApt,
      apkPackages: extraApk,
      cacheMounts: [cacheMount],
      installCommand: 'bun install --frozen-lockfile || bun install',
      buildCommand: buildCmd,
      startCommand: startCmd,
      stages: [
        {
          name: 'runtime',
          from: baseImg,
          workdir: '/app',
          env: { NODE_ENV: 'production', PORT: String(port) },
          apkPackages: extraApk,
          steps: [
            { type: 'copy', src: ['package.json', ...jsPm.lockfiles].join(' '), dest: './' },
            { type: 'run', cacheMounts: [cacheMount], command: 'bun install --frozen-lockfile || bun install' },
            { type: 'copy', src: '.', dest: '.' },
            ...(buildCmd ? [{ type: 'run', command: buildCmd }] : [])
          ]
        }
      ],
      warnings: []
    };
  } else if (stack === 'deno') {
    const baseImg = 'denoland/deno:alpine-2';
    const port = sanitizePort(requestedPort, 8000);
    const entry = reader.has('main.ts') ? 'main.ts' : (reader.has('src/main.ts') ? 'src/main.ts' : 'server.ts');
    const cacheMount = { id: 'culkibo-deno-cache', target: '/deno-dir', sharing: 'locked' };
    spec = {
      label: 'Deno 2',
      runtime: 'deno',
      runtimeVersion: '2',
      packageManager: 'deno',
      containerPort: port,
      baseImage: baseImg,
      runtimeImage: baseImg,
      aptPackages: extraApt,
      apkPackages: extraApk,
      cacheMounts: [cacheMount],
      installCommand: `deno cache ${entry}`,
      buildCommand: null,
      startCommand: ['deno', 'run', '--allow-net', '--allow-env', '--allow-read', entry],
      stages: [
        {
          name: 'runtime',
          from: baseImg,
          workdir: '/app',
          env: { DENO_DIR: '/deno-dir', PORT: String(port) },
          steps: [
            { type: 'copy', src: '.', dest: '.' },
            { type: 'run', cacheMounts: [cacheMount], command: `deno cache ${entry}` }
          ]
        }
      ],
      warnings: []
    };
  } else if (stack === 'python-uv' || stack === 'python-poetry' || stack === 'python') {
    const pyVer = parsePythonVersion(reader.readText('.python-version'), reader.readText('pyproject.toml'));
    const pyproject = reader.readText('pyproject.toml') || '';
    const reqTxt = reader.readText('requirements.txt') || '';
    const combinedPy = `${pyproject}\n${reqTxt}`.toLowerCase();
    const port = sanitizePort(requestedPort, 8000);

    let startCmd = ['python', 'main.py'];
    if (combinedPy.includes('uvicorn') || combinedPy.includes('fastapi')) {
      const appMod = reader.has('app/main.py') ? 'app.main:app' : 'main:app';
      startCmd = stack === 'python-uv'
        ? ['uv', 'run', 'uvicorn', appMod, '--host', '0.0.0.0', '--port', String(port)]
        : ['uvicorn', appMod, '--host', '0.0.0.0', '--port', String(port)];
    } else if (combinedPy.includes('gunicorn')) {
      startCmd = ['gunicorn', '--bind', `0.0.0.0:${port}`, 'app:app'];
    } else if (reader.has('manage.py')) {
      startCmd = ['python', 'manage.py', 'runserver', `0.0.0.0:${port}`];
    }

    if (stack === 'python-uv') {
      const baseImg = `ghcr.io/astral-sh/uv:python${pyVer}-bookworm-slim`;
      const cacheMount = { id: 'culkibo-uv-cache', target: '/root/.cache/uv', sharing: 'locked' };
      const installCmd = reader.has('uv.lock') ? 'uv sync --frozen --no-dev' : 'uv sync --no-dev';
      spec = {
        label: 'Python (uv)',
        runtime: 'python',
        runtimeVersion: pyVer,
        packageManager: 'uv',
        containerPort: port,
        baseImage: baseImg,
        runtimeImage: baseImg,
        aptPackages: extraApt,
        apkPackages: [],
        cacheMounts: [cacheMount],
        installCommand: installCmd,
        buildCommand: null,
        startCommand: startCmd,
        stages: [
          {
            name: 'runtime',
            from: baseImg,
            workdir: '/app',
            env: { UV_COMPILE_BYTECODE: '1', UV_LINK_MODE: 'copy', PORT: String(port) },
            aptPackages: extraApt,
            steps: [
              { type: 'copy', src: reader.has('uv.lock') ? 'pyproject.toml uv.lock' : 'pyproject.toml', dest: './' },
              { type: 'run', cacheMounts: [cacheMount], command: `${installCmd} --no-install-project` },
              { type: 'copy', src: '.', dest: '.' },
              { type: 'run', cacheMounts: [cacheMount], command: installCmd }
            ]
          }
        ],
        warnings: []
      };
    } else if (stack === 'python-poetry') {
      const baseImg = `python:${pyVer}-slim`;
      const cacheMount = { id: 'culkibo-poetry-cache', target: '/root/.cache/pypoetry', sharing: 'locked' };
      spec = {
        label: 'Python (Poetry)',
        runtime: 'python',
        runtimeVersion: pyVer,
        packageManager: 'poetry',
        containerPort: port,
        baseImage: baseImg,
        runtimeImage: baseImg,
        aptPackages: extraApt,
        apkPackages: [],
        cacheMounts: [cacheMount],
        installCommand: 'poetry install --only main --no-interaction --no-ansi',
        buildCommand: null,
        startCommand: startCmd,
        stages: [
          {
            name: 'runtime',
            from: baseImg,
            workdir: '/app',
            env: { POETRY_VIRTUALENVS_CREATE: 'false', PYTHONUNBUFFERED: '1', PORT: String(port) },
            aptPackages: extraApt,
            steps: [
              { type: 'run', cacheMounts: [{ id: 'culkibo-pip-cache', target: '/root/.cache/pip', sharing: 'locked' }], command: 'pip install --no-cache-dir poetry' },
              { type: 'copy', src: reader.has('poetry.lock') ? 'pyproject.toml poetry.lock' : 'pyproject.toml', dest: './' },
              { type: 'run', cacheMounts: [cacheMount], command: 'poetry install --only main --no-interaction --no-ansi --no-root' },
              { type: 'copy', src: '.', dest: '.' }
            ]
          }
        ],
        warnings: []
      };
    } else {
      const baseImg = `python:${pyVer}-slim`;
      const cacheMount = { id: 'culkibo-pip-cache', target: '/root/.cache/pip', sharing: 'locked' };
      const installCmd = reader.has('requirements.txt') ? 'pip install -r requirements.txt' : 'pip install .';
      spec = {
        label: 'Python (pip)',
        runtime: 'python',
        runtimeVersion: pyVer,
        packageManager: 'pip',
        containerPort: port,
        baseImage: baseImg,
        runtimeImage: baseImg,
        aptPackages: extraApt,
        apkPackages: [],
        cacheMounts: [cacheMount],
        installCommand: installCmd,
        buildCommand: null,
        startCommand: startCmd,
        stages: [
          {
            name: 'runtime',
            from: baseImg,
            workdir: '/app',
            env: { PYTHONUNBUFFERED: '1', PORT: String(port) },
            aptPackages: extraApt,
            steps: [
              ...(reader.has('requirements.txt') ? [{ type: 'copy', src: 'requirements.txt', dest: './' }] : []),
              ...(reader.has('requirements.txt') ? [{ type: 'run', cacheMounts: [cacheMount], command: installCmd }] : []),
              { type: 'copy', src: '.', dest: '.' },
              ...(!reader.has('requirements.txt') ? [{ type: 'run', cacheMounts: [cacheMount], command: installCmd }] : [])
            ]
          }
        ],
        warnings: []
      };
    }
  } else if (stack === 'go') {
    const goVer = parseGoVersion(reader.readText('go.mod'));
    const buildImg = `golang:${goVer}-alpine`;
    const runtimeImg = 'alpine:3.21';
    const port = sanitizePort(requestedPort, 8080);
    const modCache = { id: 'culkibo-go-mod', target: '/go/pkg/mod', sharing: 'locked' };
    const buildCache = { id: 'culkibo-go-build', target: '/root/.cache/go-build', sharing: 'locked' };
    const buildCmd = sanitizeCommandLine(opts.buildCommand, 'CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server .');
    spec = {
      label: `Go ${goVer} (Static Multi-Stage)`,
      runtime: 'go',
      runtimeVersion: goVer,
      packageManager: 'go-mod',
      containerPort: port,
      baseImage: buildImg,
      runtimeImage: runtimeImg,
      aptPackages: [],
      apkPackages: sanitizePackages(['ca-certificates', 'tzdata', ...extraApk]),
      cacheMounts: [modCache, buildCache],
      installCommand: 'go mod download',
      buildCommand: buildCmd,
      startCommand: ['/app/server'],
      stages: [
        {
          name: 'builder',
          from: buildImg,
          workdir: '/src',
          steps: [
            { type: 'copy', src: reader.has('go.sum') ? 'go.mod go.sum' : 'go.mod', dest: './' },
            { type: 'run', cacheMounts: [modCache], command: 'go mod download' },
            { type: 'copy', src: '.', dest: '.' },
            { type: 'run', cacheMounts: [modCache, buildCache], command: buildCmd }
          ]
        },
        {
          name: 'runtime',
          from: runtimeImg,
          workdir: '/app',
          env: { PORT: String(port) },
          apkPackages: sanitizePackages(['ca-certificates', 'tzdata', ...extraApk]),
          steps: [{ type: 'copy', fromStage: 'builder', src: '/out/server', dest: '/app/server' }]
        }
      ],
      warnings: []
    };
  } else if (stack === 'rust') {
    const binName = parseRustBinaryName(reader.readText('Cargo.toml'));
    const buildImg = 'rust:1.85-slim-bookworm';
    const runtimeImg = 'debian:bookworm-slim';
    const port = sanitizePort(requestedPort, 8080);
    const cargoReg = { id: 'culkibo-cargo-reg', target: '/usr/local/cargo/registry', sharing: 'locked' };
    const cargoTarget = { id: 'culkibo-cargo-target', target: '/src/target', sharing: 'locked' };
    const buildCmd = sanitizeCommandLine(
      opts.buildCommand,
      `cargo build --release && cp /src/target/release/${binName} /out/server`
    );
    spec = {
      label: 'Rust (Release Multi-Stage)',
      runtime: 'rust',
      runtimeVersion: '1.85',
      packageManager: 'cargo',
      containerPort: port,
      baseImage: buildImg,
      runtimeImage: runtimeImg,
      aptPackages: sanitizePackages(['ca-certificates', ...extraApt]),
      apkPackages: [],
      cacheMounts: [cargoReg, cargoTarget],
      installCommand: 'cargo fetch',
      buildCommand: buildCmd,
      startCommand: ['/app/server'],
      stages: [
        {
          name: 'builder',
          from: buildImg,
          workdir: '/src',
          aptPackages: sanitizePackages(['pkg-config', 'libssl-dev', ...extraApt]),
          steps: [
            { type: 'copy', src: '.', dest: '.' },
            { type: 'run', cacheMounts: [cargoReg, cargoTarget], command: `mkdir -p /out && ${buildCmd}` }
          ]
        },
        {
          name: 'runtime',
          from: runtimeImg,
          workdir: '/app',
          env: { PORT: String(port), RUST_LOG: 'info' },
          aptPackages: ['ca-certificates'],
          steps: [{ type: 'copy', fromStage: 'builder', src: '/out/server', dest: '/app/server' }]
        }
      ],
      warnings: []
    };
  } else if (stack === 'php-frankenphp') {
    const composer = reader.readJson('composer.json');
    const isLaravel = Boolean(reader.has('artisan') || composer?.require?.['laravel/framework']);
    const baseImg = 'dunglas/frankenphp:1-php8.4-alpine';
    const port = sanitizePort(requestedPort, 8080);
    const composerCache = { id: 'culkibo-composer-cache', target: '/root/.composer/cache', sharing: 'locked' };
    const docRoot = (isLaravel || reader.has('public/index.php')) ? '/app/public' : '/app';
    spec = {
      label: isLaravel ? 'PHP / Laravel (FrankenPHP HTTP/3)' : 'PHP (FrankenPHP HTTP/3)',
      runtime: 'frankenphp',
      runtimeVersion: '8.4',
      packageManager: reader.has('composer.json') ? 'composer' : null,
      containerPort: port,
      baseImage: baseImg,
      runtimeImage: baseImg,
      aptPackages: [],
      apkPackages: extraApk,
      cacheMounts: reader.has('composer.json') ? [composerCache] : [],
      installCommand: reader.has('composer.json') ? 'composer install --no-dev --optimize-autoloader --no-interaction' : null,
      buildCommand: null,
      startCommand: ['frankenphp', 'php-server', '--root', docRoot, '--listen', `:${port}`],
      stages: [
        {
          name: 'runtime',
          from: baseImg,
          workdir: '/app',
          env: { SERVER_NAME: `:${port}`, CADDY_GLOBAL_OPTIONS: 'auto_https off' },
          apkPackages: extraApk,
          steps: [
            ...(reader.has('composer.json')
              ? [
                  { type: 'copy', fromStage: 'composer:2', src: '/usr/bin/composer', dest: '/usr/bin/composer' },
                  { type: 'copy', src: reader.has('composer.lock') ? 'composer.json composer.lock' : 'composer.json', dest: './' },
                  { type: 'run', cacheMounts: [composerCache], command: 'composer install --no-dev --optimize-autoloader --no-interaction --no-scripts' }
                ]
              : []),
            { type: 'copy', src: '.', dest: '.' }
          ]
        }
      ],
      warnings: []
    };
  } else if (stack === 'elixir') {
    const buildImg = 'hexpm/elixir:1.18.2-erlang-27.2.4-alpine-3.21.3';
    const runtimeImg = 'alpine:3.21';
    const port = sanitizePort(requestedPort, 4000);
    const hexCache = { id: 'culkibo-hex-cache', target: '/root/.hex', sharing: 'locked' };
    const mixCache = { id: 'culkibo-mix-deps', target: '/app/deps', sharing: 'locked' };
    spec = {
      label: 'Elixir / Phoenix (OTP Release)',
      runtime: 'elixir',
      runtimeVersion: '1.18',
      packageManager: 'mix',
      containerPort: port,
      baseImage: buildImg,
      runtimeImage: runtimeImg,
      aptPackages: [],
      apkPackages: sanitizePackages(['libstdc++', 'openssl', 'ncurses-libs', ...extraApk]),
      cacheMounts: [hexCache, mixCache],
      installCommand: 'mix local.hex --force && mix local.rebar --force && mix deps.get --only prod',
      buildCommand: 'MIX_ENV=prod mix release --path /out/rel',
      startCommand: ['/app/bin/server'],
      stages: [
        {
          name: 'builder',
          from: buildImg,
          workdir: '/app',
          env: { MIX_ENV: 'prod' },
          apkPackages: ['build-base', 'git'],
          steps: [
            { type: 'copy', src: reader.has('mix.lock') ? 'mix.exs mix.lock' : 'mix.exs', dest: './' },
            { type: 'run', cacheMounts: [hexCache], command: 'mix local.hex --force && mix local.rebar --force && mix deps.get --only prod' },
            { type: 'copy', src: '.', dest: '.' },
            { type: 'run', cacheMounts: [hexCache], command: 'mix compile && mix release --path /out/rel' }
          ]
        },
        {
          name: 'runtime',
          from: runtimeImg,
          workdir: '/app',
          env: { PHX_SERVER: 'true', PORT: String(port) },
          apkPackages: sanitizePackages(['libstdc++', 'openssl', 'ncurses-libs', ...extraApk]),
          steps: [{ type: 'copy', fromStage: 'builder', src: '/out/rel', dest: '/app' }]
        }
      ],
      warnings: []
    };
  } else if (stack === 'java') {
    const isMaven = reader.has('pom.xml');
    const buildImg = isMaven ? 'maven:3.9-eclipse-temurin-21-alpine' : 'gradle:8-jdk21-alpine';
    const runtimeImg = 'eclipse-temurin:21-jre-alpine';
    const port = sanitizePort(requestedPort, 8080);
    const cacheMount = isMaven
      ? { id: 'culkibo-maven-m2', target: '/root/.m2', sharing: 'locked' }
      : { id: 'culkibo-gradle-cache', target: '/home/gradle/.gradle', sharing: 'locked' };
    const buildCmd = isMaven
      ? 'mvn -B -DskipTests package && cp target/*.jar /out/app.jar'
      : 'gradle bootJar --no-daemon && cp build/libs/*.jar /out/app.jar';
    spec = {
      label: isMaven ? 'Java 21 (Maven)' : 'Java 21 (Gradle)',
      runtime: 'java',
      runtimeVersion: '21',
      packageManager: isMaven ? 'maven' : 'gradle',
      containerPort: port,
      baseImage: buildImg,
      runtimeImage: runtimeImg,
      aptPackages: [],
      apkPackages: extraApk,
      cacheMounts: [cacheMount],
      installCommand: isMaven ? 'mvn -B dependency:go-offline' : 'gradle dependencies --no-daemon',
      buildCommand: buildCmd,
      startCommand: ['java', '-XX:MaxRAMPercentage=75.0', '-jar', '/app/app.jar'],
      stages: [
        {
          name: 'builder',
          from: buildImg,
          workdir: '/src',
          steps: [
            { type: 'copy', src: '.', dest: '.' },
            { type: 'run', cacheMounts: [cacheMount], command: `mkdir -p /out && ${buildCmd}` }
          ]
        },
        {
          name: 'runtime',
          from: runtimeImg,
          workdir: '/app',
          env: { PORT: String(port) },
          apkPackages: extraApk,
          steps: [{ type: 'copy', fromStage: 'builder', src: '/out/app.jar', dest: '/app/app.jar' }]
        }
      ],
      warnings: []
    };
  } else if (stack === 'static') {
    const port = sanitizePort(requestedPort, 8080);
    const runtimeImg = 'caddy:2.11-alpine';
    spec = {
      label: 'Static Site (Caddy HTTP/3)',
      runtime: 'caddy-static',
      runtimeVersion: '2.11',
      packageManager: null,
      containerPort: port,
      baseImage: runtimeImg,
      runtimeImage: runtimeImg,
      aptPackages: [],
      apkPackages: [],
      cacheMounts: [],
      installCommand: null,
      buildCommand: null,
      startCommand: ['caddy', 'file-server', '--root', '/srv', '--listen', `:${port}`],
      stages: [
        {
          name: 'runtime',
          from: runtimeImg,
          workdir: '/srv',
          steps: [{ type: 'copy', src: '.', dest: '/srv' }]
        }
      ],
      warnings: []
    };
  } else {
    // Generic Node.js (Express, Fastify, NestJS, Hono, Koa, etc.)
    const baseImg = `node:${nodeMajor}-alpine`;
    const port = sanitizePort(requestedPort, 3000);
    const hasBuild = Boolean(scripts.build);
    const buildCmd = hasBuild ? sanitizeCommandLine(opts.buildCommand, `${jsPm.runPrefix} build`) : null;
    const startCmd = scripts.start
      ? [jsPm.name, 'run', 'start']
      : ['node', String((pkg && pkg.main) || 'index.js').replace(/[\r\n\0]/g, '')];
    spec = {
      label: `Node.js ${nodeMajor}`,
      runtime: 'node',
      runtimeVersion: nodeMajor,
      packageManager: jsPm.name,
      containerPort: port,
      baseImage: baseImg,
      runtimeImage: baseImg,
      aptPackages: extraApt,
      apkPackages: extraApk,
      cacheMounts: [jsPm.cacheMount],
      installCommand: jsPm.installCmd,
      buildCommand: buildCmd,
      startCommand: startCmd,
      stages: [
        {
          name: 'runtime',
          from: baseImg,
          workdir: '/app',
          env: { NODE_ENV: 'production', PORT: String(port) },
          apkPackages: extraApk,
          steps: [
            ...(jsPm.enableCorepack ? [{ type: 'run', command: 'corepack enable' }] : []),
            ...(pkg ? [{ type: 'copy', src: ['package.json', ...jsPm.lockfiles].join(' '), dest: './' }] : []),
            ...(pkg ? [{ type: 'run', cacheMounts: [jsPm.cacheMount], command: jsPm.installCmd }] : []),
            { type: 'copy', src: '.', dest: '.' },
            ...(buildCmd ? [{ type: 'run', command: buildCmd }] : [])
          ]
        }
      ],
      warnings: []
    };
  }

  const layers = spec.stages.map((st, idx) => ({
    index: idx,
    name: st.name || `stage-${idx}`,
    from: st.from,
    stepCount: Array.isArray(st.steps) ? st.steps.length : 0,
    cached: Array.isArray(st.steps) && st.steps.some((s) => Array.isArray(s.cacheMounts) && s.cacheMounts.length > 0)
  }));

  const corePlan = {
    schemaVersion: PLAN_SCHEMA_VERSION,
    stack,
    label: spec.label,
    runtime: spec.runtime,
    runtimeVersion: spec.runtimeVersion,
    packageManager: spec.packageManager,
    detectedSignals,
    containerPort: spec.containerPort,
    baseImage: spec.baseImage,
    runtimeImage: spec.runtimeImage,
    aptPackages: spec.aptPackages,
    apkPackages: spec.apkPackages,
    cacheMounts: spec.cacheMounts,
    installCommand: spec.installCommand,
    buildCommand: spec.buildCommand,
    startCommand: spec.startCommand,
    layers,
    stages: spec.stages,
    ociExport: {
      zstdChunked: resourceLimits.zstdChunked,
      compression: resourceLimits.zstdChunked ? 'zstd' : 'gzip',
      flags: resourceLimits.zstdChunkedFlags
    },
    resourceLimits,
    dockerignore,
    warnings: spec.warnings
  };

  const dockerfile = renderDockerfileFromPlan(corePlan);
  // Deterministic SHA-256 over canonical build spec + Dockerfile (independent of timestamps)
  const deterministicHash = crypto
    .createHash('sha256')
    .update(JSON.stringify({
      schemaVersion: corePlan.schemaVersion,
      stack: corePlan.stack,
      runtime: corePlan.runtime,
      runtimeVersion: corePlan.runtimeVersion,
      packageManager: corePlan.packageManager,
      containerPort: corePlan.containerPort,
      stages: corePlan.stages,
      ociExport: corePlan.ociExport,
      dockerignorePatterns: corePlan.dockerignore.patterns,
      dockerfile
    }))
    .digest('hex');

  return {
    ...corePlan,
    deterministicHash,
    dockerfile
  };
}

module.exports = {
  PLAN_SCHEMA_VERSION,
  SUPPORTED_STACKS,
  generateBuildPlan,
  generateImplicitDockerignore,
  computeBuildKitResourceLimits,
  renderDockerfileFromPlan
};
