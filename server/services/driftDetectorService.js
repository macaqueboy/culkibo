const { execFile } = require('child_process');
const crypto = require('crypto');

/**
 * Detector de Drift de Configuración de Contenedores/BDs (cura `kamal#1790`) +
 * Generador de Preset Inteligente PgBouncer (Prisma/Drizzle-safe `max_prepared_statements=200`).
 *
 * Garantías:
 *  - 0 dependencias npm externas (`child_process.execFile`, `crypto`).
 *  - 0 invocaciones de shell (`shell: false` estricto).
 *  - CERO valores de variables de entorno en claro: `computeEnvKeySetHash()` hashea
 *    EXCLUSIVAMENTE los nombres de clave ordenados (jamás lee, almacena o emite valores).
 */

const SAFE_PG_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/;
const SAFE_PG_DB_RE = /^[a-zA-Z_][a-zA-Z0-9_-]{0,62}$/;
const SAFE_HOST_RE = /^[a-zA-Z0-9._-]{1,128}$/;
const SAFE_CONTAINER_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/;
const FORBIDDEN_METACHARS_RE = /[;|&`$<>'"\\\r\n\0\s]|\.\./;
const VALID_POOL_MODES = new Set(['transaction', 'session', 'statement']);

const BASE_IMAGE_ENV_NOISE = new Set([
  'PATH', 'HOME', 'HOSTNAME', 'TERM', 'PWD', 'SHLVL', 'LANG', 'LC_ALL',
  'NODE_VERSION', 'YARN_VERSION', 'GPG_KEY', 'PYTHON_VERSION', 'PIP_VERSION',
  'GOLANG_VERSION', 'RUST_VERSION', 'DEBIAN_FRONTEND'
]);

const SEVERITY_RANK = Object.freeze({ none: 0, low: 1, medium: 2, high: 3, critical: 4 });

/**
 * Extrae únicamente los nombres de clave (sin valores) desde un array de strings (`KEY` o `KEY=val`)
 * o desde un objeto `{ KEY: val }`, ordenados determinísticamente y sin duplicados.
 *
 * @param {string[] | Record<string, any> | null | undefined} keysOrObj
 * @returns {string[]}
 */
function extractSortedEnvKeys(keysOrObj) {
  /** @type {Set<string>} */
  const set = new Set();
  if (Array.isArray(keysOrObj)) {
    for (const entry of keysOrObj) {
      if (typeof entry !== 'string') continue;
      const eqIdx = entry.indexOf('=');
      const rawKey = (eqIdx >= 0 ? entry.slice(0, eqIdx) : entry).trim();
      if (rawKey) set.add(rawKey);
    }
  } else if (keysOrObj && typeof keysOrObj === 'object') {
    for (const k of Object.keys(keysOrObj)) {
      const clean = String(k || '').trim();
      if (clean) set.add(clean);
    }
  }
  return Array.from(set).sort();
}

/**
 * Calcula un hash SHA-256 determinista sobre el CONJUNTO DE NOMBRES DE CLAVE de entorno
 * ordenados alfabéticamente. Jamás hashea ni retiene valores en claro.
 *
 * @param {string[] | Record<string, any> | null | undefined} keysOrObj
 * @returns {string}
 */
function computeEnvKeySetHash(keysOrObj) {
  const sortedKeys = extractSortedEnvKeys(keysOrObj);
  return crypto.createHash('sha256').update(sortedKeys.join('\n'), 'utf8').digest('hex');
}

/**
 * Extrae el digest sha256 normalizado de un contenedor desde `actualInspect`.
 * @param {any} actualInspect
 * @returns {string | null}
 */
function extractActualDigest(actualInspect) {
  if (!actualInspect || typeof actualInspect !== 'object') return null;
  if (Array.isArray(actualInspect.RepoDigests)) {
    for (const rd of actualInspect.RepoDigests) {
      const m = String(rd || '').match(/(sha256:[a-f0-9]{16,64})/i);
      if (m) return m[1].toLowerCase();
    }
  }
  if (typeof actualInspect.Image === 'string' && actualInspect.Image.trim()) {
    return actualInspect.Image.trim().toLowerCase();
  }
  return null;
}

/**
 * Compara la especificación declarada de un proyecto o BD frente a un objeto con la forma
 * de `docker inspect` y produce un diagnóstico estructurado de drift + plan de reconciliación.
 *
 * @param {{
 *   image?: string | null,
 *   imageDigest?: string | null,
 *   memoryLimitMb?: number | null,
 *   cpuLimit?: number | null,
 *   port?: number | null,
 *   bindAddress?: string | null,
 *   envKeys?: string[] | Record<string, any> | null,
 *   logDriver?: string | null,
 *   stopGracePeriodSec?: number | null
 * }} declared
 * @param {any} actualInspect
 */
function diffContainerConfig(declared, actualInspect) {
  const decl = declared || {};
  const actual = actualInspect && typeof actualInspect === 'object' ? actualInspect : {};
  const cfg = actual.Config && typeof actual.Config === 'object' ? actual.Config : {};
  const hostCfg = actual.HostConfig && typeof actual.HostConfig === 'object' ? actual.HostConfig : {};

  /** @type {Array<{ field: string, severity: 'critical' | 'high' | 'medium' | 'low', declared: any, actual: any, message: string }>} */
  const diffs = [];
  /** @type {Array<{ field: string, severity: string, action: string, description: string }>} */
  const actions = [];

  // 1. Image reference & digest drift
  const actualImage = typeof cfg.Image === 'string' ? cfg.Image.trim() : null;
  if (decl.image && actualImage && decl.image !== actualImage) {
    diffs.push({
      field: 'image',
      severity: 'high',
      declared: decl.image,
      actual: actualImage,
      message: `Container image drifted: declared "${decl.image}" vs running "${actualImage}".`
    });
    actions.push({
      field: 'image',
      severity: 'high',
      action: 'recreate_container',
      description: `Redeploy container from declared image "${decl.image}".`
    });
  }

  const actualDigest = extractActualDigest(actual);
  if (decl.imageDigest && actualDigest) {
    const normDecl = String(decl.imageDigest).trim().toLowerCase();
    const digestMatches = actualDigest === normDecl
      || (Array.isArray(actual.RepoDigests) && actual.RepoDigests.some((r) => String(r).toLowerCase().includes(normDecl)));
    if (!digestMatches) {
      diffs.push({
        field: 'imageDigest',
        severity: 'critical',
        declared: normDecl,
        actual: actualDigest,
        message: `Image digest drift detected (possible unverified manual pull/tag mutation): declared ${normDecl.slice(0, 24)} vs running ${actualDigest.slice(0, 24)}.`
      });
      actions.push({
        field: 'imageDigest',
        severity: 'critical',
        action: 'redeploy_pinned_digest',
        description: `Re-pin and redeploy container to verified digest ${normDecl.slice(0, 24)}.`
      });
    }
  }

  // 2. Port & unexpected public 0.0.0.0 exposure (critical — cures kamal#1856 / manual docker edit)
  const portBindings = hostCfg.PortBindings && typeof hostCfg.PortBindings === 'object' ? hostCfg.PortBindings : {};
  const boundEntries = Object.entries(portBindings);
  const declaredBind = decl.bindAddress ? String(decl.bindAddress).trim() : null;
  if (boundEntries.length > 0) {
    let foundDeclaredPort = decl.port == null;
    for (const [portProto, bindings] of boundEntries) {
      const containerPortNum = parseInt(String(portProto).split('/')[0], 10);
      if (decl.port != null && containerPortNum === Number(decl.port)) {
        foundDeclaredPort = true;
      }
      if (!Array.isArray(bindings)) continue;
      for (const b of bindings) {
        const hostIp = String((b && b.HostIp) || '').trim();
        const isPublicBind = hostIp === '' || hostIp === '0.0.0.0' || hostIp === '::';
        const wantsPrivateBind = declaredBind != null && declaredBind !== '0.0.0.0' && declaredBind !== '::';
        if (wantsPrivateBind && isPublicBind) {
          diffs.push({
            field: 'bindAddress',
            severity: 'critical',
            declared: declaredBind,
            actual: hostIp || '0.0.0.0',
            message: `CRITICAL public exposure drift on ${portProto}: declared bind "${declaredBind}" but container is exposed on "${hostIp || '0.0.0.0'}" (bypasses UFW via Docker iptables NAT).`
          });
          actions.push({
            field: 'bindAddress',
            severity: 'critical',
            action: 'rebind_private_interface',
            description: `Recreate container binding ${portProto} strictly to ${declaredBind} (or WireGuard wg0 10.88.0.0/24).`
          });
        } else if (declaredBind && hostIp && hostIp !== declaredBind && !isPublicBind) {
          diffs.push({
            field: 'bindAddress',
            severity: 'high',
            declared: declaredBind,
            actual: hostIp,
            message: `Bind address drifted on ${portProto}: declared "${declaredBind}" vs actual "${hostIp}".`
          });
          actions.push({
            field: 'bindAddress',
            severity: 'high',
            action: 'rebind_interface',
            description: `Restore declared bind address "${declaredBind}" on ${portProto}.`
          });
        }
      }
    }
    if (!foundDeclaredPort && decl.port != null) {
      const actualPorts = boundEntries.map(([k]) => parseInt(k.split('/')[0], 10)).filter(Number.isFinite);
      diffs.push({
        field: 'port',
        severity: 'high',
        declared: Number(decl.port),
        actual: actualPorts[0] ?? null,
        message: `Container port drifted: declared ${decl.port} not found in running bindings (${boundEntries.map(([k]) => k).join(', ')}).`
      });
      actions.push({
        field: 'port',
        severity: 'high',
        action: 'reconcile_port_binding',
        description: `Align container port mapping to declared port ${decl.port}.`
      });
    }
  }

  // 3. Memory limit drift (MiB)
  if (decl.memoryLimitMb != null && Number(decl.memoryLimitMb) > 0 && hostCfg.Memory !== undefined) {
    const declMb = Math.round(Number(decl.memoryLimitMb));
    const actualMb = Math.round(Number(hostCfg.Memory || 0) / (1024 * 1024));
    if (actualMb !== declMb) {
      diffs.push({
        field: 'memoryLimitMb',
        severity: 'high',
        declared: declMb,
        actual: actualMb,
        message: actualMb === 0
          ? `Memory cgroup limit removed (running uncapped vs declared ${declMb} MB).`
          : `Memory limit drifted: declared ${declMb} MB vs running ${actualMb} MB.`
      });
      actions.push({
        field: 'memoryLimitMb',
        severity: 'high',
        action: 'update_memory_limit',
        description: `Apply cgroup memory cap of ${declMb} MB.`
      });
    }
  }

  // 4. CPU limit drift (NanoCpus -> cores)
  if (decl.cpuLimit != null && Number(decl.cpuLimit) > 0 && hostCfg.NanoCpus !== undefined) {
    const declCpu = Number(decl.cpuLimit);
    const actualCpu = Number(((Number(hostCfg.NanoCpus || 0)) / 1e9).toFixed(3));
    if (Math.abs(actualCpu - declCpu) > 0.01) {
      diffs.push({
        field: 'cpuLimit',
        severity: 'high',
        declared: declCpu,
        actual: actualCpu,
        message: `CPU limit drifted: declared ${declCpu} vCPU vs running ${actualCpu} vCPU.`
      });
      actions.push({
        field: 'cpuLimit',
        severity: 'high',
        action: 'update_cpu_limit',
        description: `Apply cgroup CPU quota of ${declCpu} vCPU.`
      });
    }
  }

  // 5. Env key-set drift (KEY NAMES ONLY — ZERO plaintext values ever inspected or returned!)
  const declaredKeys = extractSortedEnvKeys(decl.envKeys);
  const declaredKeySet = new Set(declaredKeys);
  const rawActualKeys = extractSortedEnvKeys(cfg.Env);
  const filteredActualKeys = rawActualKeys.filter((k) => declaredKeySet.has(k) || !BASE_IMAGE_ENV_NOISE.has(k));
  const actualKeySet = new Set(filteredActualKeys);

  const declaredEnvKeyHash = computeEnvKeySetHash(declaredKeys);
  const actualEnvKeyHash = computeEnvKeySetHash(filteredActualKeys);

  if (decl.envKeys != null && Array.isArray(cfg.Env) && declaredEnvKeyHash !== actualEnvKeyHash) {
    const missingKeys = declaredKeys.filter((k) => !actualKeySet.has(k));
    const unexpectedKeys = filteredActualKeys.filter((k) => !declaredKeySet.has(k));
    diffs.push({
      field: 'envKeys',
      severity: 'high',
      declared: { keyCount: declaredKeys.length, keySetHash: declaredEnvKeyHash },
      actual: { keyCount: filteredActualKeys.length, keySetHash: actualEnvKeyHash, missingKeys, unexpectedKeys },
      message: `Environment key-set drifted (missing: [${missingKeys.join(', ') || 'none'}], unexpected: [${unexpectedKeys.join(', ') || 'none'}]).`
    });
    actions.push({
      field: 'envKeys',
      severity: 'high',
      action: 'reconcile_env_keys',
      description: `Re-sync container environment keys from Culkibo Vault (${missingKeys.length} missing, ${unexpectedKeys.length} unexpected).`
    });
  }

  // 6. Log driver drift (kamal#1709 awareness)
  const actualLogDriver = hostCfg.LogConfig && typeof hostCfg.LogConfig.Type === 'string'
    ? hostCfg.LogConfig.Type.trim()
    : null;
  if (decl.logDriver && actualLogDriver && decl.logDriver !== actualLogDriver) {
    diffs.push({
      field: 'logDriver',
      severity: 'medium',
      declared: decl.logDriver,
      actual: actualLogDriver,
      message: `Docker log driver drifted: declared "${decl.logDriver}" vs running "${actualLogDriver}".`
    });
    actions.push({
      field: 'logDriver',
      severity: 'medium',
      action: 'reconcile_log_driver',
      description: `Restore declared log driver "${decl.logDriver}" with bounded log rotation.`
    });
  }

  // 7. Stop grace timeout drift
  if (decl.stopGracePeriodSec != null && cfg.StopTimeout !== undefined) {
    const declStop = Number(decl.stopGracePeriodSec);
    const actualStop = Number(cfg.StopTimeout);
    if (Number.isFinite(declStop) && Number.isFinite(actualStop) && declStop !== actualStop) {
      diffs.push({
        field: 'stopGracePeriodSec',
        severity: 'medium',
        declared: declStop,
        actual: actualStop,
        message: `Graceful stop timeout drifted: declared ${declStop}s vs running ${actualStop}s.`
      });
      actions.push({
        field: 'stopGracePeriodSec',
        severity: 'medium',
        action: 'reconcile_stop_timeout',
        description: `Set container StopTimeout to ${declStop}s for zero-truncation drain.`
      });
    }
  }

  let maxSeverity = /** @type {'none' | 'low' | 'medium' | 'high' | 'critical'} */ ('none');
  for (const d of diffs) {
    if (SEVERITY_RANK[d.severity] > SEVERITY_RANK[maxSeverity]) {
      maxSeverity = d.severity;
    }
  }

  return {
    ok: true,
    drifted: diffs.length > 0,
    severity: maxSeverity,
    checkedAt: new Date().toISOString(),
    declaredEnvKeyHash,
    actualEnvKeyHash,
    diffs,
    reconcilePlan: {
      dryRunDefault: true,
      actionCount: actions.length,
      requiresContainerRecreate: diffs.some((d) => ['image', 'imageDigest', 'bindAddress', 'port', 'envKeys', 'logDriver'].includes(d.field)),
      actions
    }
  };
}

/**
 * Genera un preset seguro y listo para producción de PgBouncer en modo `transaction`
 * con `max_prepared_statements = 200` (PgBouncer 1.21+ protocol-level prepared statements)
 * para eliminar fallos de Prisma/Drizzle y saturación de conexiones en PostgreSQL.
 *
 * @param {{
 *   name: string,
 *   databaseName?: string,
 *   upstreamHost?: string,
 *   upstreamPort?: number,
 *   listenPort?: number,
 *   poolMode?: 'transaction' | 'session' | 'statement',
 *   maxPreparedStatements?: number,
 *   defaultPoolSize?: number,
 *   maxClientConn?: number,
 *   reservePoolSize?: number
 * }} opts
 */
function buildPgBouncerPreset(opts) {
  const rawName = String((opts && opts.name) || '').trim();
  if (!rawName || FORBIDDEN_METACHARS_RE.test(rawName) || !SAFE_PG_NAME_RE.test(rawName)) {
    throw new Error(`Nombre de preset PgBouncer inválido o inseguro: "${rawName.slice(0, 60)}"`);
  }
  const databaseName = String((opts && opts.databaseName) || 'app').trim();
  if (!databaseName || FORBIDDEN_METACHARS_RE.test(databaseName) || !SAFE_PG_DB_RE.test(databaseName)) {
    throw new Error(`Nombre de base de datos inválido para PgBouncer: "${databaseName.slice(0, 60)}"`);
  }
  const upstreamHost = String((opts && opts.upstreamHost) || '127.0.0.1').trim();
  if (!upstreamHost || FORBIDDEN_METACHARS_RE.test(upstreamHost) || !SAFE_HOST_RE.test(upstreamHost)) {
    throw new Error(`Host upstream inválido para PgBouncer: "${upstreamHost.slice(0, 60)}"`);
  }

  const upstreamPort = Math.min(65535, Math.max(1, Math.round(Number((opts && opts.upstreamPort) ?? 5432) || 5432)));
  const listenPort = Math.min(65535, Math.max(1024, Math.round(Number((opts && opts.listenPort) ?? 6432) || 6432)));
  const rawPoolMode = String((opts && opts.poolMode) || 'transaction').trim().toLowerCase();
  if (!VALID_POOL_MODES.has(rawPoolMode)) {
    throw new Error(`poolMode inválido para PgBouncer: "${rawPoolMode}" (usa transaction, session o statement)`);
  }
  const poolMode = /** @type {'transaction' | 'session' | 'statement'} */ (rawPoolMode);

  const maxPreparedStatements = Math.min(2000, Math.max(0, Math.round(Number((opts && opts.maxPreparedStatements) ?? 200))));
  const defaultPoolSize = Math.min(500, Math.max(1, Math.round(Number((opts && opts.defaultPoolSize) ?? 25) || 25)));
  const maxClientConn = Math.min(10000, Math.max(10, Math.round(Number((opts && opts.maxClientConn) ?? 200) || 200)));
  const reservePoolSize = Math.min(100, Math.max(0, Math.round(Number((opts && opts.reservePoolSize) ?? 5))));

  const pgbouncerIni = [
    '; Culkibo Managed PgBouncer Smart Pool Preset (Prisma & Drizzle Safe)',
    '[databases]',
    `${databaseName} = host=${upstreamHost} port=${upstreamPort} dbname=${databaseName}`,
    '',
    '[pgbouncer]',
    'listen_addr = 127.0.0.1',
    `listen_port = ${listenPort}`,
    'auth_type = scram-sha-256',
    'auth_file = /etc/pgbouncer/userlist.txt',
    `pool_mode = ${poolMode}`,
    `max_prepared_statements = ${maxPreparedStatements}`,
    `default_pool_size = ${defaultPoolSize}`,
    `max_client_conn = ${maxClientConn}`,
    `reserve_pool_size = ${reservePoolSize}`,
    'reserve_pool_timeout = 3',
    'server_idle_timeout = 300',
    'server_reset_query = DISCARD ALL',
    'ignore_startup_parameters = extra_float_digits,options',
    'admin_users = postgres',
    ''
  ].join('\n');

  const safeSlug = rawName.toLowerCase().replace(/[^a-z0-9_-]+/g, '-');
  const containerName = `culkibo_pgbouncer_${safeSlug}`.slice(0, 64);

  return {
    ok: true,
    preset: 'pgbouncer-smart-pool',
    name: rawName,
    databaseName,
    upstreamHost,
    upstreamPort,
    listenPort,
    poolMode,
    maxPreparedStatements,
    defaultPoolSize,
    maxClientConn,
    reservePoolSize,
    pgbouncerIni,
    dockerSpec: {
      image: 'edoburu/pgbouncer:v1.23.1-p3',
      containerName,
      bindAddress: '127.0.0.1',
      listenPort,
      memoryMb: 128,
      cpus: 0.5,
      env: {
        DB_HOST: upstreamHost,
        DB_PORT: String(upstreamPort),
        DB_NAME: databaseName,
        LISTEN_PORT: String(listenPort),
        POOL_MODE: poolMode,
        MAX_PREPARED_STATEMENTS: String(maxPreparedStatements),
        DEFAULT_POOL_SIZE: String(defaultPoolSize),
        MAX_CLIENT_CONN: String(maxClientConn),
        RESERVE_POOL_SIZE: String(reservePoolSize),
        AUTH_TYPE: 'scram-sha-256'
      }
    },
    ormHints: {
      prisma: `postgresql://<user>:<password>@127.0.0.1:${listenPort}/${databaseName}?pgbouncer=true&connection_limit=10`,
      drizzle: `Use { prepare: false } or rely on PgBouncer >=1.21 protocol-level max_prepared_statements=${maxPreparedStatements} (enabled).`
    }
  };
}

class DriftDetectorService {
  /**
   * @param {{ projectManager?: any, inspectContainerFn?: (containerName: string) => Promise<any> }} [opts]
   */
  constructor(opts = {}) {
    this._projectManagerOverride = opts.projectManager || null;
    this._inspectContainerOverride = typeof opts.inspectContainerFn === 'function' ? opts.inspectContainerFn : null;
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
   * Inspecciona un contenedor en vivo con `execFile('docker', ['inspect', name], { shell: false })`.
   * @param {string} containerName
   */
  async _probeDockerInspect(containerName) {
    if (this._inspectContainerOverride) {
      return this._inspectContainerOverride(containerName);
    }
    const clean = String(containerName || '').trim();
    if (!SAFE_CONTAINER_RE.test(clean)) {
      throw new Error(`Nombre de contenedor inválido para drift probe: "${clean.slice(0, 60)}"`);
    }
    return new Promise((resolve, reject) => {
      execFile(
        'docker',
        ['inspect', clean],
        { shell: false, timeout: 4000, maxBuffer: 2 * 1024 * 1024, windowsHide: true },
        (err, stdout) => {
          if (err) {
            reject(err);
            return;
          }
          try {
            const parsed = JSON.parse(String(stdout || '[]'));
            resolve(Array.isArray(parsed) ? parsed[0] || null : parsed);
          } catch (parseErr) {
            reject(parseErr);
          }
        }
      );
    });
  }

  /**
   * Comprueba el drift de configuración de un proyecto frente a su estado en ejecución
   * (usando `opts.actualInspect` si se inyecta, o sondeando Docker de forma segura sin shell).
   * Si Docker está offline devuelve `{ ok: true, runtimeOffline: true, ... }` limpiamente.
   *
   * @param {string} projectId
   * @param {{
   *   actualInspect?: any,
   *   containerName?: string,
   *   declaredOverrides?: Record<string, any>,
   *   projectManager?: any
   * }} [opts]
   */
  async checkProjectDrift(projectId, opts = {}) {
    const pm = this._getProjectManager(opts.projectManager || null);
    if (!pm || typeof pm.getById !== 'function') {
      throw new Error('ProjectManager no disponible para checkProjectDrift');
    }
    const project = pm.getById(projectId);
    if (!project) {
      const err = new Error(`Proyecto no encontrado para drift check: "${projectId}"`);
      /** @type {any} */ (err).status = 404;
      throw err;
    }

    const declared = {
      image: project.imageTag || project.activeImageTag || null,
      imageDigest: project.imageDigest || null,
      memoryLimitMb: project.memoryMb || project.memoryLimitMb || null,
      cpuLimit: project.cpus || project.cpuLimit || null,
      port: project.containerPort || project.citadelPort || null,
      bindAddress: '127.0.0.1',
      envKeys: Object.keys((project.envVars && typeof project.envVars === 'object') ? project.envVars : {}),
      logDriver: project.logDriver || 'json-file',
      stopGracePeriodSec: project.stopGracePeriodSec != null ? Number(project.stopGracePeriodSec) : 30,
      ...(opts.declaredOverrides || {})
    };

    if (opts.actualInspect && typeof opts.actualInspect === 'object') {
      const result = diffContainerConfig(declared, opts.actualInspect);
      return {
        ...result,
        projectId: project.id,
        projectName: project.name,
        runtimeOffline: false
      };
    }

    const slug = String(project.id).toLowerCase().replace(/[^a-z0-9_-]+/g, '_');
    const containerName = opts.containerName || `culkibo_${slug}_citadel`;

    try {
      const inspected = await this._probeDockerInspect(containerName);
      if (!inspected) {
        return {
          ok: true,
          projectId: project.id,
          projectName: project.name,
          runtimeOffline: true,
          drifted: false,
          severity: 'none',
          checkedAt: new Date().toISOString(),
          declaredEnvKeyHash: computeEnvKeySetHash(declared.envKeys),
          actualEnvKeyHash: null,
          diffs: [],
          reconcilePlan: { dryRunDefault: true, actionCount: 0, requiresContainerRecreate: false, actions: [] },
          reason: `Container "${containerName}" is not currently running on Docker.`
        };
      }
      const result = diffContainerConfig(declared, inspected);
      return {
        ...result,
        projectId: project.id,
        projectName: project.name,
        containerName,
        runtimeOffline: false
      };
    } catch (err) {
      return {
        ok: true,
        projectId: project.id,
        projectName: project.name,
        containerName,
        runtimeOffline: true,
        drifted: false,
        severity: 'none',
        checkedAt: new Date().toISOString(),
        declaredEnvKeyHash: computeEnvKeySetHash(declared.envKeys),
        actualEnvKeyHash: null,
        diffs: [],
        reconcilePlan: { dryRunDefault: true, actionCount: 0, requiresContainerRecreate: false, actions: [] },
        reason: `Docker runtime unreachable or container offline (${err && err.message ? err.message.slice(0, 120) : 'offline'}).`
      };
    }
  }

  /** @param {any} opts */
  buildPgBouncerPreset(opts) {
    return buildPgBouncerPreset(opts);
  }
}

const instance = /** @type {any} */ (new DriftDetectorService());
instance.DriftDetectorService = DriftDetectorService;
instance.computeEnvKeySetHash = computeEnvKeySetHash;
instance.buildPgBouncerPreset = buildPgBouncerPreset;
instance.diffContainerConfig = diffContainerConfig;
module.exports = instance;
