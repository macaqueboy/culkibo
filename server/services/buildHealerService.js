const { performance } = require('perf_hooks');

/**
 * Motor Determinista de Auto-Curación de Builds y Runtime (20 Patrones Reales, Cero LLM, Cero Shell).
 *
 * Analiza logs de compilación/contenedor en `<2 ms` con 20 clasificadores de producción
 * (Node OOM, bind `127.0.0.1`, `kamal#1709` log-driver mismatch, drift de lockfile,
 * Next.js standalone, Alpine musl/glibc, `pg_wal` bloat, Postgres max connections,
 * Docker Hub 429, Python PEP 668, Rust linker OOM, Go CGO, Exit 137, etc.) y genera
 * planes de parche seguros con `dryRun: true` por defecto (jamás ejecuta shell).
 */

const MAX_LOG_CHARS = 256 * 1024;
const MAX_LINES = 4000;
const SEVERITY_RANK = Object.freeze({ critical: 4, high: 3, medium: 2, low: 1 });

/**
 * Catálogo de 20 patrones deterministas de fallo de build y runtime en producción.
 * @type {ReadonlyArray<{
 *   code: string,
 *   title: string,
 *   severity: 'critical' | 'high' | 'medium' | 'low',
 *   confidence: number,
 *   regex: RegExp,
 *   rootCause: string,
 *   patchPreview: string,
 *   autoFixAction: {
 *     kind: string,
 *     envAdditions?: Record<string, string>,
 *     memoryLimitMb?: number,
 *     logDriver?: string,
 *     smartPackHint?: string,
 *     summary: string
 *   }
 * }>}
 */
const FAILURE_PATTERNS = Object.freeze([
  Object.freeze({
    code: 'NODE_HEAP_OOM',
    title: 'Node.js V8 Heap Out of Memory',
    severity: 'critical',
    confidence: 0.97,
    regex: /FATAL ERROR:.*(?:Reached heap limit|JavaScript heap out of memory|Allocation failed - JavaScript heap)|JavaScript heap out of memory/i,
    rootCause: 'The Node.js build or runtime process hit the default V8 heap ceiling during bundling (Next.js/Vite/TypeScript) or high memory allocation.',
    patchPreview: [
      '--- a/culkibo.project.env',
      '+++ b/culkibo.project.env',
      '+NODE_OPTIONS=--max-old-space-size=1536',
      '--- a/culkibo.project.resources',
      '+++ b/culkibo.project.resources',
      '+memoryMb: 2048'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'env_and_memory_bump',
      envAdditions: Object.freeze({ NODE_OPTIONS: '--max-old-space-size=1536' }),
      memoryLimitMb: 2048,
      smartPackHint: 'node-heap-headroom',
      summary: 'Inject NODE_OPTIONS=--max-old-space-size=1536 and raise container memoryMb to >=2048 MB.'
    })
  }),
  Object.freeze({
    code: 'CONTAINER_BIND_LOCALHOST',
    title: 'Container Bound to 127.0.0.1 / localhost',
    severity: 'high',
    confidence: 0.94,
    regex: /(?:listening|running|started|ready|serving)\s+(?:on|at)\s+(?:https?:\/\/)?(?:127\.0\.0\.1|localhost):\d{2,5}|bind(?:ing)?\s+to\s+127\.0\.0\.1/i,
    rootCause: 'The application server bound exclusively to loopback (127.0.0.1/localhost) inside the container, making it unreachable from Caddy reverse proxy and healthchecks.',
    patchPreview: [
      '--- a/culkibo.project.env',
      '+++ b/culkibo.project.env',
      '+HOST=0.0.0.0',
      '+HOSTNAME=0.0.0.0'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'env_patch',
      envAdditions: Object.freeze({ HOST: '0.0.0.0', HOSTNAME: '0.0.0.0' }),
      smartPackHint: 'bind-all-interfaces',
      summary: 'Set HOST=0.0.0.0 and HOSTNAME=0.0.0.0 so the app accepts ingress traffic from Caddy.'
    })
  }),
  Object.freeze({
    code: 'DOCKER_LOG_OPT_DRIVER_MISMATCH',
    title: 'Docker Log Driver Incompatible with --log-opt max-size (kamal#1709)',
    severity: 'high',
    confidence: 0.98,
    regex: /unknown log opt ['"]?(?:max-size|max-file)['"]? for (?:syslog|journald|awslogs|splunk|fluentd|gcplogs|gelf|none) log driver|failed to initialize logging driver.*max-size/i,
    rootCause: 'Host Docker daemon uses syslog/journald (or non-json-file driver), which rejects --log-opt max-size/max-file flags unless json-file or local driver is explicitly selected (kamal#1709).',
    patchPreview: [
      '--- a/culkibo.deploy.logging',
      '+++ b/culkibo.deploy.logging',
      '-logDriver: inherited-host-driver',
      '+logDriver: json-file # bounded max-size=10m max-file=3 (or omit max-size for syslog/journald)'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'log_driver_override',
      logDriver: 'json-file',
      smartPackHint: 'explicit-json-file-log-driver',
      summary: 'Explicitly set container logDriver to json-file (or omit max-size/max-file when using syslog/journald).'
    })
  }),
  Object.freeze({
    code: 'NPM_CI_LOCKFILE_DRIFT',
    title: 'npm ci Lockfile Out of Sync with package.json',
    severity: 'high',
    confidence: 0.97,
    regex: /`?npm ci`?\s+can only install packages when your package\.json and package-lock\.json.*in sync|Missing:.*from lock file|ERR_PNPM_OUTDATED_LOCKFILE/i,
    rootCause: 'package.json dependencies were modified without regenerating package-lock.json / pnpm-lock.yaml, causing frozen-lockfile installs to abort.',
    patchPreview: [
      '--- a/Dockerfile',
      '+++ b/Dockerfile',
      '-RUN npm ci',
      '+RUN npm install --no-audit --no-fund # or commit updated package-lock.json locally'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'smartpack_hint',
      smartPackHint: 'sync-lockfile-or-fallback-install',
      summary: 'Run npm install locally to sync package-lock.json, or enable SmartPack lockfile-drift fallback.'
    })
  }),
  Object.freeze({
    code: 'NEXTJS_MISSING_STANDALONE',
    title: 'Next.js Production Build Missing output: "standalone"',
    severity: 'medium',
    confidence: 0.93,
    regex: /Cannot find module ['"]\.\/server\.js['"]|COPY --from=builder.*\/\.next\/standalone.*not found|next\.config.*output.*standalone/i,
    rootCause: 'The Dockerfile expects .next/standalone/server.js, but next.config.(js|mjs|ts) does not configure output: "standalone".',
    patchPreview: [
      '--- a/next.config.mjs',
      '+++ b/next.config.mjs',
      ' const nextConfig = {',
      '+  output: "standalone",',
      ' };'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'smartpack_hint',
      smartPackHint: 'nextjs-standalone-output',
      summary: 'Add output: "standalone" to next.config.* or switch SmartPack to next start mode.'
    })
  }),
  Object.freeze({
    code: 'NATIVE_BUILD_TOOLCHAIN_MISSING',
    title: 'Missing Native C/C++/Python Toolchain (node-gyp)',
    severity: 'high',
    confidence: 0.95,
    regex: /gyp ERR!|node-gyp rebuild.*failed|not found:\s*(?:python3?|make|g\+\+|gcc)|Can't find Python executable/i,
    rootCause: 'A native npm addon (bcrypt, sharp, better-sqlite3, canvas) triggered node-gyp compilation inside a minimal image lacking python3, make, and g++.',
    patchPreview: [
      '--- a/Dockerfile',
      '+++ b/Dockerfile',
      '+RUN apk add --no-cache python3 make g++ # or apt-get install -y python3 make g++'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'smartpack_hint',
      smartPackHint: 'install-native-build-toolchain',
      summary: 'Add python3, make, and g++ in the builder stage of SmartPack Dockerfile.'
    })
  }),
  Object.freeze({
    code: 'PORT_EADDRINUSE',
    title: 'Port Already In Use (EADDRINUSE)',
    severity: 'high',
    confidence: 0.95,
    regex: /EADDRINUSE|address already in use|port is already allocated/i,
    rootCause: 'Another process or lingering container is already listening on the configured host or container port.',
    patchPreview: [
      '--- a/culkibo.project.network',
      '+++ b/culkibo.project.network',
      '+Let Culkibo portRegistry auto-allocate a free host port & bind app to process.env.PORT'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'smartpack_hint',
      smartPackHint: 'dynamic-port-allocation',
      summary: 'Respect process.env.PORT inside the app and allow Culkibo portRegistry to assign an unused host port.'
    })
  }),
  Object.freeze({
    code: 'POSTGRES_PG_WAL_BLOAT',
    title: 'PostgreSQL pg_wal Disk Bloat / Stale Replication Slot',
    severity: 'critical',
    confidence: 0.96,
    regex: /pg_wal.*no space left|could not write to file ["']pg_wal\/|replication slot.*retaining.*wal|WAL directory.*full/i,
    rootCause: 'Unconsumed logical/physical replication slots or failing archive_command caused PostgreSQL pg_wal segments to grow unbounded until disk exhaustion.',
    patchPreview: [
      '-- Run inside PostgreSQL container:',
      'SELECT slot_name, active, pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) FROM pg_replication_slots;',
      '-- Drop orphaned inactive slots and enforce max_slot_wal_keep_size = 2GB;'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'smartpack_hint',
      smartPackHint: 'postgres-wal-retention-cap',
      summary: 'Inspect inactive pg_replication_slots, drop orphaned slots, and cap max_slot_wal_keep_size.'
    })
  }),
  Object.freeze({
    code: 'POSTGRES_MAX_CONNECTIONS',
    title: 'PostgreSQL Connection Pool Exhausted (too many clients)',
    severity: 'high',
    confidence: 0.97,
    regex: /FATAL:\s+sorry, too many clients already|remaining connection slots are reserved|too many connections for role/i,
    rootCause: 'Application instances or serverless/worker concurrency opened more direct connections than PostgreSQL max_connections allows.',
    patchPreview: [
      '--- a/culkibo.database.pooling',
      '+++ b/culkibo.database.pooling',
      '+pgbouncer: enabled (transaction pooling mode, pool_size=25)'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'smartpack_hint',
      smartPackHint: 'enable-pgbouncer-transaction-pooling',
      summary: 'Enable Culkibo co-located PgBouncer (transaction mode) and cap Prisma/ORM connection_limit.'
    })
  }),
  Object.freeze({
    code: 'ALPINE_MUSL_BINARY_MISMATCH',
    title: 'Alpine musl vs glibc Prebuilt Binary Mismatch',
    severity: 'high',
    confidence: 0.96,
    regex: /Error relocating .*symbol not found|libc\.musl|GLIBC_\d+\.\d+\s+not found|linux-musl.*cannot open shared object/i,
    rootCause: 'A native binary (Prisma engine, Sharp, Playwright, SWC, or Rust/C++ addon) linked against glibc failed to load on Alpine Linux (musl libc).',
    patchPreview: [
      '--- a/Dockerfile',
      '+++ b/Dockerfile',
      '-FROM node:22-alpine',
      '+FROM node:22-bookworm-slim'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'smartpack_hint',
      smartPackHint: 'use-debian-bookworm-slim-base',
      summary: 'Switch SmartPack base image from Alpine (musl) to Debian bookworm-slim (glibc).'
    })
  }),
  Object.freeze({
    code: 'DOCKER_HUB_RATE_LIMIT',
    title: 'Docker Hub Pull Rate Limit Exceeded (429 toomanyrequests)',
    severity: 'high',
    confidence: 0.98,
    regex: /toomanyrequests:.*pull rate limit|429 Too Many Requests.*registry-1\.docker\.io/i,
    rootCause: 'Anonymous pulls from Docker Hub exceeded the IP quota (100 pulls / 6h) on this VPS.',
    patchPreview: [
      '--- a/Dockerfile',
      '+++ b/Dockerfile',
      '-FROM node:22-alpine',
      '+FROM public.ecr.aws/docker/library/node:22-alpine # or configure authenticated registry mirror'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'smartpack_hint',
      smartPackHint: 'use-registry-mirror-or-ecr-public',
      summary: 'Configure Docker Hub credentials or switch base images to public.ecr.aws/docker/library/* mirror.'
    })
  }),
  Object.freeze({
    code: 'PYTHON_PEP668_EXTERNALLY_MANAGED',
    title: 'Python PEP 668 Externally-Managed Environment Block',
    severity: 'medium',
    confidence: 0.97,
    regex: /error:\s+externally-managed-environment|PEP 668/i,
    rootCause: 'Debian/Ubuntu/Alpine Python 3.11+ blocks global pip install into system site-packages under PEP 668.',
    patchPreview: [
      '--- a/Dockerfile',
      '+++ b/Dockerfile',
      '-RUN pip install -r requirements.txt',
      '+RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt',
      '+ENV PATH="/opt/venv/bin:$PATH"'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'smartpack_hint',
      smartPackHint: 'python-venv-isolation',
      summary: 'Install Python dependencies inside a dedicated /opt/venv virtual environment.'
    })
  }),
  Object.freeze({
    code: 'MISSING_PACKAGE_JSON',
    title: 'Missing package.json (Incorrect Monorepo Base Directory)',
    severity: 'high',
    confidence: 0.95,
    regex: /ENOENT:\s+no such file or directory, open ['"][^'"]*package\.json['"]|Could not read package\.json/i,
    rootCause: 'Build executed in a directory that does not contain package.json (common in monorepos where baseDirectory needs to point to apps/web or packages/api).',
    patchPreview: [
      '--- a/culkibo.project',
      '+++ b/culkibo.project',
      '-baseDirectory: /',
      '+baseDirectory: /apps/web # set to the subdirectory containing package.json'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'smartpack_hint',
      smartPackHint: 'verify-base-directory',
      summary: 'Update project baseDirectory to the subdirectory containing package.json.'
    })
  }),
  Object.freeze({
    code: 'OOM_KILLED_EXIT_137',
    title: 'Container OOMKilled by Linux Kernel (Exit Code 137)',
    severity: 'critical',
    confidence: 0.96,
    regex: /exit(?:ed)?(?:\s+with)?\s+code\s+137|OOMKilled|Killed\s+npm|SIGKILL\s*\(137\)/i,
    rootCause: 'The container exceeded its cgroup memory limit and was terminated by the Linux kernel OOM killer (SIGKILL = 128 + 9 = 137).',
    patchPreview: [
      '--- a/culkibo.project.resources',
      '+++ b/culkibo.project.resources',
      '+memoryMb: 1536 # bump memory ceiling above peak build/runtime RSS'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'memory_bump',
      memoryLimitMb: 1536,
      smartPackHint: 'raise-memory-limit',
      summary: 'Increase container memoryMb limit (e.g. 2x current cap up to 4096 MB) to stop kernel OOMKills.'
    })
  }),
  Object.freeze({
    code: 'TLS_CERT_VERIFY_FAILED',
    title: 'TLS Certificate Verification Failed (Missing CA Bundle or Expired Cert)',
    severity: 'high',
    confidence: 0.94,
    regex: /UNABLE_TO_VERIFY_LEAF_SIGNATURE|CERT_HAS_EXPIRED|SELF_SIGNED_CERT_IN_CHAIN|x509:\s+certificate signed by unknown authority/i,
    rootCause: 'Minimal container images (scratch/distroless/slim) lack system ca-certificates, or an upstream endpoint presents an expired/untrusted certificate.',
    patchPreview: [
      '--- a/Dockerfile',
      '+++ b/Dockerfile',
      '+RUN apk add --no-cache ca-certificates && update-ca-certificates # or apt-get install -y ca-certificates'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'smartpack_hint',
      smartPackHint: 'install-ca-certificates',
      summary: 'Install ca-certificates package in the runtime stage and verify upstream TLS expiry.'
    })
  }),
  Object.freeze({
    code: 'RUST_LINKER_OOM',
    title: 'Rust Cargo/Linker Killed by OOM (signal 9 during cargo build)',
    severity: 'critical',
    confidence: 0.94,
    regex: /error:\s+could not compile .*signal:\s*9,\s*SIGKILL|collect2:\s+fatal error:.*ld terminated with signal 9|cargo.*signal:\s*9/i,
    rootCause: 'Parallel rustc/ld LTO linking exhausted available RAM on a constrained VPS.',
    patchPreview: [
      '--- a/culkibo.project.env',
      '+++ b/culkibo.project.env',
      '+CARGO_BUILD_JOBS=2',
      '+CARGO_PROFILE_RELEASE_LTO=thin',
      '--- a/culkibo.project.resources',
      '+++ b/culkibo.project.resources',
      '+memoryMb: 2048'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'env_and_memory_bump',
      envAdditions: Object.freeze({ CARGO_BUILD_JOBS: '2', CARGO_PROFILE_RELEASE_LTO: 'thin' }),
      memoryLimitMb: 2048,
      smartPackHint: 'rust-bounded-cargo-jobs',
      summary: 'Throttle CARGO_BUILD_JOBS=2, use thin LTO, and increase build memoryMb to >=2048 MB.'
    })
  }),
  Object.freeze({
    code: 'GO_CGO_DYNAMIC_LINK',
    title: 'Go Binary Dynamically Linked Against Missing libc (CGO_ENABLED=1)',
    severity: 'high',
    confidence: 0.94,
    regex: /exec \/.*:\s+no such file or directory|standard_init_linux\.go.*exec user process caused: no such file|exec format error/i,
    rootCause: 'A Go binary compiled with CGO_ENABLED=1 (or mismatched GOARCH) failed to execute inside an Alpine/scratch runtime image missing dynamic glibc.',
    patchPreview: [
      '--- a/Dockerfile',
      '+++ b/Dockerfile',
      '-RUN go build -o /app/server .',
      '+RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/server .'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'env_patch',
      envAdditions: Object.freeze({ CGO_ENABLED: '0' }),
      smartPackHint: 'go-static-cgo-disabled',
      summary: 'Build Go binary statically with CGO_ENABLED=0 for scratch/Alpine compatibility.'
    })
  }),
  Object.freeze({
    code: 'DISK_SPACE_EXHAUSTED',
    title: 'Host Disk Space Exhausted During Build (ENOSPC)',
    severity: 'critical',
    confidence: 0.95,
    regex: /ENOSPC|no space left on device|failed to register layer.*no space left/i,
    rootCause: 'Uncapped Docker BuildKit cache or dangling images filled the VPS disk (coolify#12542).',
    patchPreview: [
      '# Run safe protected prune (preserves culkibo.protected=1 sleeping containers):',
      'docker builder prune --keep-storage 4GB --force',
      'docker image prune --filter "label!=culkibo.protected=1" --force'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'smartpack_hint',
      smartPackHint: 'prune-buildkit-cache-keep-4gb',
      summary: 'Reclaim disk space using BuildKit --keep-storage prune while preserving sleeping containers.'
    })
  }),
  Object.freeze({
    code: 'HEALTHCHECK_PORT_MISMATCH',
    title: 'Healthcheck Connection Refused / Port Mismatch',
    severity: 'high',
    confidence: 0.92,
    regex: /healthcheck.*(?:connection refused|unhealthy|failed on port)|connect ECONNREFUSED (?:127\.0\.0\.1|::1):\d{2,5}/i,
    rootCause: 'The container listened on a different port than project.containerPort / healthPath, or bound only to loopback.',
    patchPreview: [
      '--- a/culkibo.project.env',
      '+++ b/culkibo.project.env',
      '+HOST=0.0.0.0',
      '# Ensure app listens on process.env.PORT matching Culkibo containerPort & healthPath'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'env_patch',
      envAdditions: Object.freeze({ HOST: '0.0.0.0' }),
      smartPackHint: 'align-container-port-healthcheck',
      summary: 'Set HOST=0.0.0.0 and align project containerPort/healthPath with the listening port.'
    })
  }),
  Object.freeze({
    code: 'ENV_MISSING_REQUIRED_VAR',
    title: 'Missing Required Runtime Environment Variable',
    severity: 'high',
    confidence: 0.93,
    regex: /Missing required environment variable|Environment variable not found:\s*[A-Z0-9_]+|(?:DATABASE_URL|REDIS_URL|JWT_SECRET|NEXTAUTH_SECRET)\s+(?:is not defined|must be set|is required)/i,
    rootCause: 'The container started without a required secret or database connection URL configured in Culkibo Environment/Vault.',
    patchPreview: [
      '--- a/culkibo.project.env',
      '+++ b/culkibo.project.env',
      '# Link your managed database (injects DATABASE_URL) or add ${vault.<SECRET_KEY>} in Vault AES-256-GCM.'
    ].join('\n'),
    autoFixAction: Object.freeze({
      kind: 'smartpack_hint',
      smartPackHint: 'inject-required-vault-or-db-env',
      summary: 'Link the managed database or populate the missing ${vault.*} secret before redeploying.'
    })
  })
]);

class BuildHealerService {
  /**
   * @param {{ projectManager?: any }} [opts]
   */
  constructor(opts = {}) {
    this._projectManagerOverride = opts.projectManager || null;
  }

  _getProjectManager(override = null) {
    if (override) return override;
    if (this._projectManagerOverride) return this._projectManagerOverride;
    try {
      return require('./projectManager');
    } catch (e) {
      return null;
    }
  }

  /**
   * Clasifica determinísticamente logs de build/runtime contra los 20 patrones de producción
   * sin invocar LLMs externos ni ejecutar comandos de shell.
   *
   * @param {string} logsText
   * @param {{ project?: any, maxMatches?: number }} [context]
   */
  diagnoseLogs(logsText, context = {}) {
    const t0 = performance.now();
    const raw = String(logsText || '').slice(-MAX_LOG_CHARS);
    const lines = raw.split(/\r?\n/).slice(-MAX_LINES);
    const maxMatches = Math.min(20, Math.max(1, Number(context.maxMatches) || 10));

    /** @type {Array<{ code: string, title: string, severity: string, rootCause: string, confidence: number, matchedLine: string, matchedLineNumber: number, patchPreview: string, autoFixAction: any }>} */
    const matches = [];

    for (const pat of FAILURE_PATTERNS) {
      let matchedLine = '';
      let matchedLineNumber = 0;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!line) continue;
        if (pat.regex.test(line)) {
          matchedLine = line.trim().slice(0, 320);
          matchedLineNumber = i + 1;
          break;
        }
      }

      if (matchedLine) {
        matches.push({
          code: pat.code,
          title: pat.title,
          severity: pat.severity,
          rootCause: pat.rootCause,
          confidence: pat.confidence,
          matchedLine,
          matchedLineNumber,
          patchPreview: pat.patchPreview,
          autoFixAction: {
            ...pat.autoFixAction,
            ...(pat.autoFixAction.envAdditions ? { envAdditions: { ...pat.autoFixAction.envAdditions } } : {})
          }
        });
      }
    }

    matches.sort((a, b) => {
      const rankDiff = (SEVERITY_RANK[/** @type {keyof typeof SEVERITY_RANK} */ (b.severity)] || 0)
        - (SEVERITY_RANK[/** @type {keyof typeof SEVERITY_RANK} */ (a.severity)] || 0);
      if (rankDiff !== 0) return rankDiff;
      return b.confidence - a.confidence;
    });

    const capped = matches.slice(0, maxMatches);
    const analyzedMs = Number((performance.now() - t0).toFixed(3));

    return {
      ok: true,
      matched: capped.length > 0,
      totalMatches: capped.length,
      patternCatalogSize: FAILURE_PATTERNS.length,
      primary: capped[0] || null,
      matches: capped,
      analyzedLines: lines.length,
      analyzedMs
    };
  }

  /**
   * Genera (y opcionalmente aplica con `dryRun: false`) un plan de parche seguro y
   * no destructivo sobre los metadatos de un proyecto (env seguros, memoryMb, logDriver,
   * smartPackHint). Nunca ejecuta comandos de shell arbitrarios.
   *
   * @param {string} projectId
   * @param {{
   *   logs?: string,
   *   code?: string,
   *   dryRun?: boolean,
   *   projectManager?: any
   * }} [opts]
   */
  async applyHealingPlan(projectId, opts = {}) {
    const dryRun = opts.dryRun !== false;
    const pm = this._getProjectManager(opts.projectManager || null);
    if (!pm || typeof pm.getById !== 'function') {
      throw new Error('ProjectManager no disponible para applyHealingPlan');
    }

    const project = pm.getById(projectId);
    if (!project) {
      const err = new Error(`Proyecto no encontrado: "${projectId}"`);
      /** @type {any} */ (err).status = 404;
      throw err;
    }

    /** @type {any} */
    let selectedMatch = null;
    /** @type {any} */
    let diagnosis = null;

    if (opts.code) {
      const targetCode = String(opts.code).trim().toUpperCase();
      const pat = FAILURE_PATTERNS.find((p) => p.code === targetCode);
      if (!pat) {
        const err = new Error(`Patrón de auto-curación desconocido: "${targetCode}"`);
        /** @type {any} */ (err).status = 400;
        throw err;
      }
      selectedMatch = {
        code: pat.code,
        title: pat.title,
        severity: pat.severity,
        rootCause: pat.rootCause,
        confidence: pat.confidence,
        matchedLine: `(explicit pattern ${pat.code})`,
        matchedLineNumber: 0,
        patchPreview: pat.patchPreview,
        autoFixAction: {
          ...pat.autoFixAction,
          ...(pat.autoFixAction.envAdditions ? { envAdditions: { ...pat.autoFixAction.envAdditions } } : {})
        }
      };
      diagnosis = {
        ok: true,
        matched: true,
        totalMatches: 1,
        patternCatalogSize: FAILURE_PATTERNS.length,
        primary: selectedMatch,
        matches: [selectedMatch],
        analyzedLines: 0,
        analyzedMs: 0
      };
    } else {
      diagnosis = this.diagnoseLogs(opts.logs || '', { project });
      selectedMatch = diagnosis.primary;
    }

    if (!selectedMatch) {
      return {
        ok: true,
        dryRun,
        applied: false,
        projectId: project.id,
        diagnosis,
        patchPlan: null,
        mutationsSummary: ['No known failure pattern matched the provided logs.']
      };
    }

    const action = selectedMatch.autoFixAction || {};
    const existingEnv = (project.envVars && typeof project.envVars === 'object') ? project.envVars : {};
    /** @type {Record<string, string>} */
    const envAdditions = {};
    if (action.envAdditions && typeof action.envAdditions === 'object') {
      for (const [k, v] of Object.entries(action.envAdditions)) {
        if (!existingEnv[k] || existingEnv[k] !== v) {
          envAdditions[k] = String(v);
        }
      }
    }

    const currentMemMb = Number(project.memoryMb || project.memoryLimitMb || 0) || 512;
    /** @type {number | null} */
    let memoryLimitMb = null;
    if (action.memoryLimitMb) {
      const bumped = Math.min(4096, Math.max(Number(action.memoryLimitMb), currentMemMb * 2));
      if (bumped > currentMemMb) {
        memoryLimitMb = bumped;
      }
    }

    const logDriver = action.logDriver ? String(action.logDriver) : null;
    const smartPackHint = action.smartPackHint ? String(action.smartPackHint) : null;

    /** @type {string[]} */
    const mutationsSummary = [];
    if (Object.keys(envAdditions).length > 0) {
      mutationsSummary.push(`Merge safe env vars: ${Object.keys(envAdditions).join(', ')}`);
    }
    if (memoryLimitMb != null) {
      mutationsSummary.push(`Raise memoryMb: ${currentMemMb} MB -> ${memoryLimitMb} MB`);
    }
    if (logDriver) {
      mutationsSummary.push(`Set container logDriver hint: ${logDriver}`);
    }
    if (smartPackHint) {
      mutationsSummary.push(`Record SmartPack remediation hint: ${smartPackHint}`);
    }

    const patchPlan = {
      code: selectedMatch.code,
      title: selectedMatch.title,
      severity: selectedMatch.severity,
      envAdditions,
      memoryLimitMb,
      logDriver,
      smartPackHint,
      patchPreview: selectedMatch.patchPreview,
      zeroShell: true
    };

    if (dryRun) {
      return {
        ok: true,
        dryRun: true,
        applied: false,
        projectId: project.id,
        diagnosis,
        patchPlan,
        mutationsSummary
      };
    }

    /** @type {Record<string, any>} */
    const projectPatch = {};
    /** @type {string[]} */
    const appliedFields = [];

    if (Object.keys(envAdditions).length > 0) {
      projectPatch.envVars = { ...existingEnv, ...envAdditions };
      appliedFields.push('envVars');
    }
    if (memoryLimitMb != null) {
      projectPatch.memoryMb = memoryLimitMb;
      appliedFields.push('memoryMb');
    }

    if (appliedFields.length > 0 && typeof pm.update === 'function') {
      pm.update(project.id, projectPatch);
      if (typeof pm.flushToDisk === 'function') {
        await pm.flushToDisk().catch(() => {});
      }
    }

    return {
      ok: true,
      dryRun: false,
      applied: true,
      projectId: project.id,
      diagnosis,
      patchPlan,
      appliedFields,
      mutationsSummary
    };
  }
}

const instance = /** @type {any} */ (new BuildHealerService());
instance.BuildHealerService = BuildHealerService;
instance.FAILURE_PATTERNS = FAILURE_PATTERNS;
module.exports = instance;
