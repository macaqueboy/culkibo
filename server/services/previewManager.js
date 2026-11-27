const { EventEmitter } = require('events');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const portRegistry = require('./portRegistry');
const { atomicWriteJsonSync, assertContainedPath, formatDockerEnvFile } = require('./ssrfGuard');

const PREVIEW_DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const SAFE_PG_IDENT_RE = /^[a-z][a-z0-9_]{0,62}$/;
const SAFE_DOCKER_CONTAINER_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/;

/** Normaliza un fragmento para identificador SQL seguro (PostgreSQL <= 63 chars). */
function pgIdentSlug(raw, maxLen = 24) {
  const clean = String(raw || '')
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .replace(/_{2,}/g, '_')
    .slice(0, maxLen)
    .replace(/_+$/g, '');
  return clean || 'app';
}

/** Valida estrictamente un identificador PostgreSQL (`^[a-z][a-z0-9_]{0,62}$`). */
function assertSafePgIdent(val, label) {
  const s = String(val || '').trim();
  if (!SAFE_PG_IDENT_RE.test(s)) {
    throw new Error(`Identificador PostgreSQL inválido para ${label}: "${s.slice(0, 48)}"`);
  }
  return s;
}

const ROOT_BASE_DIR = process.env.CULKIBO_DATA_DIR
  ? path.resolve(process.env.CULKIBO_DATA_DIR)
  : path.resolve(__dirname, '..', '..');
const DATA_DIR = path.join(ROOT_BASE_DIR, 'data');
const STORE_FILE = path.join(DATA_DIR, 'previews.json');
const STORE_BAK_FILE = `${STORE_FILE}.bak`;
const PREVIEWS_WORK_DIR = path.join(ROOT_BASE_DIR, 'projects', '.previews');

/** @type {any} */
let _deployManager = null;
function getDeployManager() {
  if (!_deployManager) _deployManager = require('./deployManager');
  return _deployManager;
}

/** @type {any} */
let _ingressManager = null;
function getIngressManager() {
  if (!_ingressManager) _ingressManager = require('./ingressManager');
  return _ingressManager;
}

/** @type {any} */
let _repoSync = null;
function getRepoSync() {
  if (!_repoSync) _repoSync = require('./repoSync');
  return _repoSync;
}

/** @param {string} raw @param {number} [maxLen] */
function dnsLabel(raw, maxLen = 28) {
  const clean = String(raw || '')
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-')
    .slice(0, maxLen)
    .replace(/-+$/g, '');
  return clean || 'prev';
}

/**
 * Construye una clave y hostname RFC-1123 deterministas para una vista previa.
 * @param {any} project
 * @param {{ prNumber?: number | string | null, branch?: string | null }} target
 */
function computePreviewIdentity(project, { prNumber = null, branch = null } = {}) {
  const baseDomain = String(project?.previewDeployments?.baseDomain || '').trim().toLowerCase().replace(/^\*\./, '').replace(/\.+$/, '');
  if (baseDomain && !PREVIEW_DOMAIN_RE.test(baseDomain)) {
    throw new Error(`Dominio base de previews inválido (debe cumplir RFC-1123): «${baseDomain}»`);
  }
  const projSlug = dnsLabel(project?.name || project?.id || 'app', 20);
  let key;
  if (prNumber != null && String(prNumber).trim() !== '') {
    const num = String(prNumber).replace(/[^0-9]/g, '');
    if (!num) throw new Error('Número de PR inválido');
    key = `pr-${num}`;
  } else if (branch && String(branch).trim()) {
    const brClean = dnsLabel(branch, 22);
    const shortHash = crypto.createHash('sha1').update(String(branch)).digest('hex').slice(0, 5);
    key = `br-${brClean}-${shortHash}`;
  } else {
    throw new Error('Debes indicar una rama o un número de Pull Request');
  }

  const leftLabel = dnsLabel(`${key}-${projSlug}`, 60);
  const hostname = baseDomain ? `${leftLabel}.${baseDomain}` : '';
  return { key, hostname, baseDomain };
}

class PreviewManager extends EventEmitter {
  /**
   * @param {string | { storeFile?: string, dataDir?: string, workDir?: string }} [storeFileOrOpts]
   */
  constructor(storeFileOrOpts = STORE_FILE) {
    super();
    if (storeFileOrOpts && typeof storeFileOrOpts === 'object') {
      const baseDataDir = storeFileOrOpts.dataDir ? path.resolve(storeFileOrOpts.dataDir) : DATA_DIR;
      this.storeFile = storeFileOrOpts.storeFile ? path.resolve(storeFileOrOpts.storeFile) : path.join(baseDataDir, 'previews.json');
      this.workDir = storeFileOrOpts.workDir ? path.resolve(storeFileOrOpts.workDir) : path.join(baseDataDir, '.previews');
      this.tmpDir = path.join(baseDataDir, '.tmp');
    } else {
      this.storeFile = typeof storeFileOrOpts === 'string' && storeFileOrOpts ? storeFileOrOpts : STORE_FILE;
      this.workDir = PREVIEWS_WORK_DIR;
      this.tmpDir = path.join(DATA_DIR, '.tmp');
    }
    this.storeBakFile = `${this.storeFile}.bak`;
    this.branchStoreFile = path.join(path.dirname(this.storeFile), 'preview-db-branches.json');
    /** @type {Record<string, Record<string, any>>} */
    this.store = {};
    /** @type {Record<string, any>} */
    this._dbBranches = {};
    this._branchesLoaded = false;
    /** @type {Set<string>} */
    this.inFlightKeys = new Set();
    /**
     * Construcciones preview activas por `projectId:key` con `AbortController` propio
     * (permite cancelar al cerrar PR sin dejar huérfanos y reemplazar en pushes rápidos).
     * @type {Map<string, { controller: AbortController, cancelled: boolean, destroyed: boolean, superseded: boolean, containerName: string, imageTag: string, promise: Promise<any> | null }>}
     */
    this._activeBuilds = new Map();
    /** Ganchos inyectables para pruebas aisladas sin mutar singletons globales. */
    this._getDeployManager = () => getDeployManager();
    this._getIngressManager = () => getIngressManager();
    this._getRepoSync = () => getRepoSync();
    /** @type {ReturnType<typeof setInterval> | null} */
    this._reaperTimer = null;
    this._loaded = false;

    portRegistry.registerProvider('previewManager', () => {
      this._ensureLoaded();
      /** @type {number[]} */
      const ports = [];
      for (const projMap of Object.values(this.store)) {
        for (const prev of Object.values(projMap || {})) {
          if (prev && prev.hostPort) ports.push(Number(prev.hostPort));
        }
      }
      return ports;
    });
  }

  _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;
    for (const candidate of [this.storeFile, this.storeBakFile]) {
      try {
        if (!fs.existsSync(candidate)) continue;
        const parsed = JSON.parse(fs.readFileSync(candidate, 'utf8'));
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          this.store = parsed;
          return;
        }
      } catch (e) {
        console.warn(`[PreviewManager] Error leyendo ${path.basename(candidate)}:`, e.message);
      }
    }
    this.store = {};
  }

  save() {
    this._ensureLoaded();
    try {
      if (fs.existsSync(this.storeFile)) {
        try { fs.copyFileSync(this.storeFile, this.storeBakFile); } catch (e) {}
      }
      atomicWriteJsonSync(this.storeFile, this.store, 0o600);
    } catch (e) {
      console.error('[PreviewManager] No se pudo guardar previews.json:', e.message);
    }
  }

  list(projectId = null) {
    this._ensureLoaded();
    if (projectId) {
      return Object.values(this.store[projectId] || {}).sort((a, b) =>
        Date.parse(b.updatedAt || b.createdAt || 0) - Date.parse(a.updatedAt || a.createdAt || 0)
      );
    }
    /** @type {any[]} */
    const all = [];
    for (const projMap of Object.values(this.store)) {
      for (const p of Object.values(projMap || {})) all.push(p);
    }
    return all.sort((a, b) =>
      Date.parse(b.updatedAt || b.createdAt || 0) - Date.parse(a.updatedAt || a.createdAt || 0)
    );
  }

  get(projectId, key) {
    this._ensureLoaded();
    return (this.store[projectId] && this.store[projectId][key]) || null;
  }

  /** Rehidrata las rutas activas de preview en ingressManager tras un reinicio. */
  hydrateIngressRoutes(ingressManager) {
    this._ensureLoaded();
    if (!ingressManager || !ingressManager.previewRoutes) return 0;
    let count = 0;
    for (const projMap of Object.values(this.store)) {
      for (const prev of Object.values(projMap || {})) {
        if (prev && prev.status === 'active' && prev.hostname && prev.upstream) {
          ingressManager.previewRoutes.set(`${prev.projectId}_${prev.key}`, {
            hostname: prev.hostname,
            upstream: prev.upstream,
            projectId: prev.projectId,
            prNumber: prev.prNumber || prev.key
          });
          count++;
        }
      }
    }
    return count;
  }

  /**
   * Despliega o actualiza una vista previa efímera para una rama o Pull Request.
   * Soporta cancelación cooperativa (`AbortController`) al cerrar la PR sin huérfanos,
   * reemplazo automático (`supersede`) ante pushes rápidos, variables de entorno
   * específicas de preview (`previewDeployments.envVars`), `buildSecrets` y `phaseTimings`.
   *
   * @param {any} project
   * @param {{ branch?: string, prNumber?: number | string | null, commit?: string | null, isFork?: boolean, title?: string | null, supersede?: boolean, buildSecrets?: Record<string, string> | null }} [opts]
   */
  async deployPreview(project, { branch = '', prNumber = null, commit = null, isFork = false, title = null, supersede = true, buildSecrets = null } = {}) {
    this._ensureLoaded();
    if (!project || !project.id) throw new Error('Proyecto inválido');
    const cfg = project.previewDeployments || {};
    if (isFork && !cfg.allowForks) {
      const err = new Error('Vista previa bloqueada por seguridad: Pull Request desde fork externo (allowForks=false)');
      /** @type {any} */ (err).status = 403;
      throw err;
    }

    const identity = computePreviewIdentity(project, { prNumber, branch });
    if (!identity.hostname) {
      throw new Error('Configura un dominio base de previews (ej. previews.tudominio.com) en los ajustes del proyecto');
    }

    const lockKey = `${project.id}:${identity.key}`;
    while (this._activeBuilds.has(lockKey) || this.inFlightKeys.has(lockKey)) {
      const prevActive = this._activeBuilds.get(lockKey);
      if (!supersede || !prevActive) {
        const err = new Error(`Ya hay un despliegue preview en curso para ${identity.key}`);
        /** @type {any} */ (err).status = 409;
        throw err;
      }
      prevActive.cancelled = true;
      prevActive.superseded = true;
      try { prevActive.controller.abort(new Error('Vista previa reemplazada por un nuevo push')); } catch (e) {}
      if (prevActive.promise) {
        await prevActive.promise.catch(() => {});
      } else {
        break;
      }
    }

    const dm = this._getDeployManager();
    const dmDefaults = dm.DEFAULTS || getDeployManager().DEFAULTS;
    const dmHelpers = dm.helpers || getDeployManager().helpers;
    const ing = this._getIngressManager();
    const rs = this._getRepoSync();

    if (!this.store[project.id]) this.store[project.id] = {};
    const existing = this.store[project.id][identity.key];

    // Aplicar cuota maxPreviews (evitar saturar el host)
    const maxPreviews = Math.min(20, Math.max(1, Number(cfg.maxPreviews) || 5));
    const currentEntries = Object.values(this.store[project.id]).filter((p) => p.key !== identity.key);
    if (currentEntries.length >= maxPreviews) {
      currentEntries.sort((a, b) => Date.parse(a.updatedAt || a.createdAt || 0) - Date.parse(b.updatedAt || b.createdAt || 0));
      const oldest = currentEntries[0];
      if (oldest) {
        await this.destroyPreview(project.id, oldest.key).catch(() => {});
      }
    }

    const ttlHours = Math.min(720, Math.max(1, Number(cfg.ttlHours) || 168));
    const suffix = crypto.randomBytes(3).toString('hex');
    const safeProj = dnsLabel(project.id, 24).replace(/-/g, '_');
    const safeKey = dnsLabel(identity.key, 20).replace(/-/g, '_');
    const containerName = `culkibo_prev_${safeProj}_${safeKey}_${suffix}`;
    const imageTag = `culkibo/prev-${dnsLabel(project.id, 24)}:${dnsLabel(identity.key, 24)}`;
    const checkoutDir = path.join(this.workDir, project.id, identity.key);

    const controller = new AbortController();
    /** @type {{ controller: AbortController, cancelled: boolean, destroyed: boolean, superseded: boolean, containerName: string, imageTag: string, promise: Promise<any> | null }} */
    const buildEntry = {
      controller,
      cancelled: false,
      destroyed: false,
      superseded: false,
      containerName,
      imageTag,
      promise: null
    };

    const runPreviewBuild = async () => {
      /** @type {any} */
      const record = {
        key: identity.key,
        projectId: project.id,
        projectName: project.name || project.id,
        branch: String(branch || project.gitBranch || 'main'),
        prNumber: prNumber != null ? Number(prNumber) || String(prNumber) : null,
        title: title ? String(title).slice(0, 140) : null,
        commit: commit || null,
        hostname: identity.hostname,
        url: `https://${identity.hostname}`,
        status: 'building',
        containerName,
        imageTag,
        hostPort: null,
        containerPort: null,
        upstream: null,
        phaseTimings: {},
        error: null,
        createdAt: existing?.createdAt || new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + ttlHours * 3600 * 1000).toISOString()
      };
      const previousRecord = existing ? { ...existing } : null;
      if (!this.store[project.id]) this.store[project.id] = {};
      this.store[project.id][identity.key] = record;
      this.save();
      this.emit('preview_event', { action: 'building', preview: record });

      /** @type {{ name: string, startedAtMs: number } | null} */
      let activePhase = null;
      const closePhase = (nowMs = Date.now()) => {
        if (!activePhase) return;
        const entry = record.phaseTimings[activePhase.name];
        if (entry && entry.finishedAt === null) {
          entry.finishedAt = new Date(nowMs).toISOString();
          entry.durationMs = Math.max(0, nowMs - activePhase.startedAtMs);
        }
        activePhase = null;
      };
      const enterPhase = (name) => {
        const nowMs = Date.now();
        closePhase(nowMs);
        record.phaseTimings[name] = {
          startedAt: new Date(nowMs).toISOString(),
          finishedAt: null,
          durationMs: null
        };
        activePhase = { name, startedAtMs: nowMs };
      };

      const checkAborted = () => {
        if (buildEntry.cancelled || controller.signal.aborted) {
          const msg = buildEntry.superseded
            ? 'Vista previa reemplazada por un nuevo push'
            : 'Vista previa cancelada durante la construcción';
          const err = new Error(msg);
          /** @type {any} */ (err).code = buildEntry.superseded ? 'PREVIEW_SUPERSEDED' : 'PREVIEW_ABORTED';
          throw err;
        }
      };

      /** @type {number | null} */
      let hostPort = null;
      /** @type {string | null} */
      let envFile = null;
      let containerStarted = false;
      const portOwner = `prev_${identity.key}_${suffix}`;
      try {
        const docker = await dm.detectDocker({ force: true });
        if (!docker.available) throw new Error(docker.reason || 'Docker no disponible');
        checkAborted();

        // 1. Clonar / sincronizar rama en directorio aislado de previews
        enterPhase('sync');
        fs.mkdirSync(path.dirname(checkoutDir), { recursive: true });
        const sync = await rs.sync({ ...project, gitBranch: record.branch }, {
          targetDir: checkoutDir,
          commit: commit || null,
          signal: controller.signal
        });
        checkAborted();
        if (sync.aborted) {
          buildEntry.cancelled = true;
          checkAborted();
        }
        if (!sync.ok) throw new Error(sync.error || 'Error obteniendo código de la rama preview');
        if (sync.commit) record.commit = sync.shortCommit || sync.commit.slice(0, 7);

        // Conservar raíz si es monorepo (pnpm/yarn/turbo/nx) para no cortar lockfiles/packages
        let contextDir = checkoutDir;
        /** @type {any} */
        let monorepoCtx = null;
        if (project.baseDirectory && project.baseDirectory !== '/' && project.baseDirectory !== '.') {
          monorepoCtx = typeof dm.detectMonorepoContext === 'function'
            ? dm.detectMonorepoContext(checkoutDir, project.baseDirectory)
            : null;
          if (!monorepoCtx) {
            contextDir = assertContainedPath(checkoutDir, String(project.baseDirectory).replace(/^\/+/, ''));
          }
        }

        // 2. Estrategia + build protegido por el semáforo global de deployManager
        enterPhase('detect');
        const strategy = await dm.detectStrategy(contextDir, project, {
          workspacePath: monorepoCtx ? monorepoCtx.workspacePath : null,
          workspaceTool: monorepoCtx ? monorepoCtx.workspaceTool : null,
          workspacePackageName: monorepoCtx ? monorepoCtx.workspacePackageName : null
        });
        checkAborted();
        if (strategy.builder === 'generated' && strategy.stack === 'desconocido') {
          throw new Error('No se detectó Dockerfile ni stack compatible para construir la preview');
        }

        const linkedDb = dm.resolveLinkedDatabases(project);
        /** @type {any} */
        let provisionedDbBranch = null;
        if (cfg.branchDatabase && record.prNumber != null) {
          const branchCfg = typeof cfg.branchDatabase === 'object' ? cfg.branchDatabase : {};
          const branchPlan = this.planPreviewDbBranch(project, record.prNumber, {
            ...branchCfg,
            execute: branchCfg.engine === 'sqlite' || branchCfg.engine === 'sqlite3'
          });
          if (branchPlan.engine === 'postgres' && branchCfg.execute !== false && Array.isArray(branchPlan.createArgv)) {
            const branchRun = await dm.runDocker(branchPlan.createArgv, { timeoutMs: 30000, signal: controller.signal });
            if (branchRun && branchRun.code === 0) branchPlan.provisioned = true;
          }
          provisionedDbBranch = branchPlan;
          record.dbBranch = branchPlan;
        }
        const scopedPreviewEnv = (cfg.envVars && typeof cfg.envVars === 'object' && !Array.isArray(cfg.envVars))
          ? cfg.envVars
          : {};
        const envVars = {
          ...linkedDb.injectedEnv,
          ...(project.envVars || {}),
          ...scopedPreviewEnv,
          ...(provisionedDbBranch && provisionedDbBranch.envOverride ? provisionedDbBranch.envOverride : {}),
          CULKIBO_PREVIEW: '1',
          CULKIBO_PREVIEW_BRANCH: record.branch,
          CULKIBO_PREVIEW_URL: record.url
        };
        const mergedBuildSecrets = {
          ...(project.buildSecrets && typeof project.buildSecrets === 'object' ? project.buildSecrets : {}),
          ...(cfg.buildSecrets && typeof cfg.buildSecrets === 'object' ? cfg.buildSecrets : {}),
          ...(buildSecrets && typeof buildSecrets === 'object' ? buildSecrets : {})
        };
        const effectiveProject = Object.keys(mergedBuildSecrets).length > 0
          ? { ...project, buildSecrets: mergedBuildSecrets }
          : project;

        enterPhase('queue');
        await dm.acquireBuildSlot(project.id, `prev_${identity.key}`, { signal: controller.signal });
        try {
          checkAborted();
          enterPhase('build');
          const fakeDep = {
            id: portOwner,
            projectId: project.id,
            projectName: project.name,
            imageTag,
            logLines: []
          };
          const buildRes = await dm.runBuild(fakeDep, {
            strategy,
            contextDir,
            project: effectiveProject,
            opts: dmDefaults,
            envVars,
            signal: controller.signal
          });
          checkAborted();
          if (buildRes.aborted) {
            buildEntry.cancelled = true;
            checkAborted();
          }
          if (!buildRes.ok) throw new Error(buildRes.error || 'Error construyendo imagen preview');
        } finally {
          dm.releaseBuildSlot();
        }

        checkAborted();

        // 3. Arrancar contenedor preview con límites estrictos (sin fugar env del host)
        enterPhase('start');
        await dm.ensureNetwork(dmDefaults.network);
        hostPort = await dm.findFreePort(20000, portOwner);
        record.hostPort = hostPort;
        record.containerPort = strategy.containerPort;

        const memCap = Math.min(Number(cfg.memoryMb) || 512, Number(project.memoryMb) || 512);
        const validEnvNames = Object.keys(envVars).filter(dmHelpers.isValidEnvName);
        const blocklist = dmHelpers.HOST_HIJACK_ENV_BLOCKLIST || new Set();
        const inlineEnvNames = validEnvNames.filter((k) => !blocklist.has(k.toUpperCase()));
        const fileOnlyEnvNames = validEnvNames.filter((k) => blocklist.has(k.toUpperCase()));

        if (fileOnlyEnvNames.length > 0) {
          fs.mkdirSync(this.tmpDir, { recursive: true, mode: 0o700 });
          envFile = path.join(this.tmpDir, `prevenv_${crypto.randomBytes(8).toString('hex')}`);
          /** @type {Record<string, any>} */
          const fileOnlyObj = {};
          for (const k of fileOnlyEnvNames) fileOnlyObj[k] = envVars[k];
          fs.writeFileSync(envFile, formatDockerEnvFile(fileOnlyObj), { encoding: 'utf8', mode: 0o600 });
        }

        const healthStartPeriodSec = dmHelpers.sanitizeBoundedInt
          ? dmHelpers.sanitizeBoundedInt(cfg.healthStartPeriodSec ?? project.healthStartPeriodSec, dmDefaults.healthStartPeriodSec || 10, 0, 300)
          : 10;
        const healthyThreshold = dmHelpers.sanitizeBoundedInt
          ? dmHelpers.sanitizeBoundedInt(cfg.healthyThreshold ?? project.healthyThreshold, dmDefaults.healthyThreshold || 1, 1, 5)
          : 1;

        const runArgs = dm.runArgs({
          containerName,
          imageTag,
          hostPort,
          containerPort: strategy.containerPort,
          envNames: inlineEnvNames,
          envFile,
          network: dmDefaults.network,
          memoryMb: Math.max(64, memCap),
          cpus: '0.5',
          pidsLimit: 256,
          healthStartPeriodSec,
          labels: {
            'culkibo.managed': 'true',
            'com.culkibo.project': dmHelpers.safeSlug(project.id),
            'com.culkibo.project_id': project.id,
            'com.culkibo.preview': 'true',
            'com.culkibo.preview_key': identity.key
          }
        });

        const safeEnv = { ...process.env, ...dmHelpers.filterSafeHostEnv(envVars) };
        const run = await dm.runDocker(runArgs, { timeoutMs: 60000, env: safeEnv, signal: controller.signal });
        if (run.code === 0) containerStarted = true;
        checkAborted();
        if (run.code !== 0) {
          throw new Error((run.stderr || '').trim().slice(0, 400) || `docker run terminó con código ${run.code}`);
        }

        for (const dbNet of linkedDb.networks || []) {
          if (dbNet !== dmDefaults.network) {
            await dm.runDocker(['network', 'connect', dbNet, containerName], { timeoutMs: 10000 }).catch(() => {});
          }
        }

        // 4. Healthcheck
        enterPhase('health');
        const healthTimeoutMs = Math.min(180000, Math.max(5000, Number(cfg.healthTimeoutMs) || 30000));
        const health = await dm.waitForHealth({
          hostPort,
          containerPort: strategy.containerPort,
          healthPath: strategy.healthPath,
          containerName,
          hostHeader: record.hostname,
          timeoutMs: healthTimeoutMs,
          intervalMs: 1000,
          healthStartPeriodSec,
          healthyThreshold,
          signal: controller.signal
        });
        checkAborted();
        if (!health.healthy) {
          await dm.runDocker(['rm', '-f', containerName], { timeoutMs: 15000 }).catch(() => {});
          containerStarted = false;
          throw new Error(`Preview no pasó el healthcheck: ${health.reason}`);
        }

        enterPhase('route');
        const upstream = await dm.resolveUpstream({
          containerName,
          containerPort: strategy.containerPort,
          hostPort,
          network: dmDefaults.network
        });
        checkAborted();

        record.upstream = upstream.dial;
        record.status = 'active';
        record.error = null;
        record.updatedAt = new Date().toISOString();
        closePhase();

        if (!this.store[project.id]) this.store[project.id] = {};
        this.store[project.id][identity.key] = record;
        this.save();

        // 5. Publicar ruta en ingressManager + Caddy
        ing.previewRoutes.set(`${project.id}_${identity.key}`, {
          hostname: record.hostname,
          upstream: record.upstream,
          projectId: project.id,
          prNumber: record.prNumber || identity.key
        });
        await ing.reconcile().catch(() => {});

        // Retirar contenedor preview anterior de esta misma clave si existía
        if (previousRecord && previousRecord.containerName && previousRecord.containerName !== containerName) {
          await dm.runDocker(['rm', '-f', previousRecord.containerName], { timeoutMs: 15000 }).catch(() => {});
        }

        this.emit('preview_event', { action: 'active', preview: record });
        return record;
      } catch (err) {
        closePhase();
        // Si fue cancelado/destruido/reemplazado, limpiar cualquier contenedor arrancado sin dejar huérfanos
        if (containerStarted) {
          await dm.runDocker(['rm', '-f', containerName], { timeoutMs: 15000 }).catch(() => {});
          containerStarted = false;
        }
        // Si falló o se abortó antes de activar, limpiar rama de BD preview recién creada (cura coolify#12458)
        if (record.dbBranch && (!previousRecord || previousRecord.status !== 'active')) {
          await this.teardownPreviewDbBranch(`${project.id}:${identity.key}`, { branchPlan: record.dbBranch }).catch(() => {});
        }
        const isAborted = buildEntry.cancelled || err?.code === 'PREVIEW_ABORTED' || err?.code === 'PREVIEW_SUPERSEDED';
        if (isAborted) {
          if (buildEntry.destroyed) {
            ing.previewRoutes.delete(`${project.id}_${identity.key}`);
            if (this.store[project.id]) {
              delete this.store[project.id][identity.key];
              if (Object.keys(this.store[project.id]).length === 0) delete this.store[project.id];
            }
            this.save();
          }
          throw err;
        }
        // Si ya existía una preview activa sana, preservar su containerName/upstream para no dejar huérfanos
        if (!this.store[project.id]) this.store[project.id] = {};
        if (previousRecord && previousRecord.status === 'active' && previousRecord.containerName) {
          this.store[project.id][identity.key] = {
            ...previousRecord,
            lastBuildError: err.message || 'Error reconstruyendo vista previa',
            updatedAt: new Date().toISOString()
          };
        } else {
          record.status = 'failed';
          record.error = err.message || 'Error en vista previa';
          record.updatedAt = new Date().toISOString();
          this.store[project.id][identity.key] = record;
        }
        this.save();
        this.emit('preview_event', { action: 'failed', preview: this.store[project.id][identity.key] });
        throw err;
      } finally {
        if (envFile) { try { fs.unlinkSync(envFile); } catch (e) {} }
        if (hostPort) {
          if (dm._pendingPorts) dm._pendingPorts.delete(hostPort);
          portRegistry.release(hostPort, portOwner);
        }
        if (this._activeBuilds.get(lockKey) === buildEntry) {
          this._activeBuilds.delete(lockKey);
        }
        this.inFlightKeys.delete(lockKey);
      }
    };

    this.inFlightKeys.add(lockKey);
    const taskPromise = runPreviewBuild();
    buildEntry.promise = taskPromise;
    this._activeBuilds.set(lockKey, buildEntry);
    return taskPromise;
  }

  /**
   * Destruye una vista previa (cancela build activo si existe + ruta Caddy + contenedor + imagen + directorio).
   * Acepta clave string (`"pr-42"`) o descriptor `{ key, prNumber, branch, project }`.
   */
  async destroyPreview(projectId, keyOrTarget) {
    this._ensureLoaded();

    let key = typeof keyOrTarget === 'string' ? keyOrTarget : null;
    if (!key && keyOrTarget && typeof keyOrTarget === 'object') {
      if (typeof keyOrTarget.key === 'string' && keyOrTarget.key.trim()) {
        key = keyOrTarget.key.trim();
      } else if (keyOrTarget.prNumber != null && String(keyOrTarget.prNumber).trim() !== '') {
        key = `pr-${String(keyOrTarget.prNumber).replace(/[^0-9]/g, '')}`;
      } else if (keyOrTarget.branch) {
        try {
          key = computePreviewIdentity({ id: projectId }, { branch: keyOrTarget.branch }).key;
        } catch (e) {
          key = null;
        }
      }
    }
    if (!key) return { removed: false };

    // Si hay un build en vuelo para esta preview (ej. PR cerrada a mitad del build),
    // abortarlo y esperar a que termine la limpieza para evitar contenedores/rutas huérfanas.
    const lockKey = `${projectId}:${key}`;
    const active = this._activeBuilds.get(lockKey);
    let abortedBuild = false;
    /** @type {string | null} */
    let activeContainer = null;
    /** @type {string | null} */
    let activeImage = null;
    if (active) {
      abortedBuild = true;
      activeContainer = active.containerName;
      activeImage = active.imageTag;
      active.cancelled = true;
      active.destroyed = true;
      try { active.controller.abort(new Error('Vista previa destruida durante la construcción')); } catch (e) {}
      if (active.promise) {
        await active.promise.catch(() => {});
      }
    }

    const projMap = this.store[projectId];
    const prev = projMap ? projMap[key] : null;
    if (!prev && !abortedBuild) return { removed: false };

    const dm = this._getDeployManager();
    const ing = this._getIngressManager();

    ing.previewRoutes.delete(`${projectId}_${key}`);
    await ing.reconcile().catch(() => {});

    const containersToRm = new Set([prev?.containerName, activeContainer].filter(Boolean));
    for (const cName of containersToRm) {
      await dm.runDocker(['rm', '-f', cName], { timeoutMs: 20000 }).catch(() => {});
    }
    const imagesToRm = new Set([prev?.imageTag, activeImage].filter(Boolean));
    for (const imgTag of imagesToRm) {
      await dm.runDocker(['rmi', imgTag], { timeoutMs: 20000 }).catch(() => {});
    }

    const checkoutDir = path.join(this.workDir, projectId, key);
    try { fs.rmSync(checkoutDir, { recursive: true, force: true }); } catch (e) {}

    if (projMap && prev) {
      delete projMap[key];
      if (Object.keys(projMap).length === 0) delete this.store[projectId];
      this.save();
    }

    // Limpieza automática e idempotente de ramas de BD de preview (cura coolify#12458 zombie leaks)
    /** @type {any} */
    let dbBranchTeardown = null;
    try {
      dbBranchTeardown = await this.teardownPreviewDbBranch(`${projectId}:${key}`, {
        branchPlan: prev?.dbBranch || null
      });
    } catch (e) {}

    this.emit('preview_event', { action: 'destroyed', projectId, key, abortedBuild, dbBranchTeardown });
    return { removed: true, abortedBuild, key, dbBranchTeardown };
  }

  _ensureBranchesLoaded() {
    if (this._branchesLoaded) return;
    this._branchesLoaded = true;
    try {
      if (fs.existsSync(this.branchStoreFile)) {
        const parsed = JSON.parse(fs.readFileSync(this.branchStoreFile, 'utf8'));
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          this._dbBranches = parsed;
          return;
        }
      }
    } catch (e) {}
    this._dbBranches = {};
  }

  _saveBranches() {
    this._ensureBranchesLoaded();
    try {
      fs.mkdirSync(path.dirname(this.branchStoreFile), { recursive: true });
      atomicWriteJsonSync(this.branchStoreFile, this._dbBranches, 0o600);
    } catch (e) {
      console.error('[PreviewManager] No se pudo guardar preview-db-branches.json:', e.message);
    }
  }

  /**
   * Planifica (y opcionalmente aprovisiona si `dbConfig.execute === true`) una rama de BD
   * aislada para una Pull Request (PostgreSQL `CREATE DATABASE ... WITH TEMPLATE ...` vía
   * `psql -v` parametrizado sin shell, o SQLite Copy-on-Write con `COPYFILE_FICLONE`).
   *
   * @param {any} project
   * @param {number | string} prNumber
   * @param {{
   *   engine?: string,
   *   sourceDb?: string,
   *   dbName?: string,
   *   username?: string,
   *   containerName?: string,
   *   host?: string,
   *   port?: number | string,
   *   sourcePath?: string,
   *   dbPath?: string,
   *   execute?: boolean,
   *   executor?: (argv: string[]) => Promise<{ code: number, stdout?: string, stderr?: string }>
   * }} [dbConfig]
   */
  planPreviewDbBranch(project, prNumber, dbConfig = {}) {
    if (!project || !project.id) {
      throw new Error('planPreviewDbBranch requiere un proyecto válido con id');
    }
    const cleanPr = String(prNumber == null ? '' : prNumber).replace(/^pr-/i, '').trim();
    if (!/^[1-9][0-9]{0,7}$/.test(cleanPr)) {
      throw new Error(`Número de PR inválido para branch DB: "${String(prNumber)}"`);
    }
    const key = `pr-${cleanPr}`;
    const previewId = `${project.id}:${key}`;
    const rawEngine = String(dbConfig.engine || 'postgres').trim().toLowerCase();

    if (rawEngine === 'sqlite' || rawEngine === 'sqlite3') {
      const sourcePathRaw = String(dbConfig.sourcePath || dbConfig.dbPath || '').trim();
      if (!sourcePathRaw || /[\0\r\n]/.test(sourcePathRaw)) {
        throw new Error('La rama SQLite requiere dbConfig.sourcePath válido');
      }
      const sourcePath = path.resolve(sourcePathRaw);
      const safeProjDir = dnsLabel(project.id, 32);
      const branchDir = assertContainedPath(this.workDir, path.join(safeProjDir, key));
      const branchPath = assertContainedPath(branchDir, 'branch.sqlite');
      const cleanupFiles = [branchPath, `${branchPath}-wal`, `${branchPath}-shm`];

      /** @type {any} */
      const plan = {
        ok: true,
        previewId,
        projectId: project.id,
        key,
        prNumber: Number(cleanPr),
        engine: 'sqlite',
        strategy: 'sqlite_cow_clone',
        zeroShell: true,
        idempotentTeardown: true,
        sourcePath,
        branchPath,
        cleanupFiles,
        envOverride: {
          DATABASE_URL: `file:${branchPath}`,
          CULKIBO_PREVIEW_DB_BRANCH: previewId
        },
        provisioned: false,
        createdAt: new Date().toISOString()
      };

      if (dbConfig.execute) {
        if (!fs.existsSync(sourcePath)) {
          throw new Error(`Archivo SQLite origen no encontrado: ${sourcePath}`);
        }
        fs.mkdirSync(branchDir, { recursive: true, mode: 0o700 });
        try {
          fs.copyFileSync(sourcePath, branchPath, fs.constants.COPYFILE_FICLONE);
        } catch (e) {
          fs.copyFileSync(sourcePath, branchPath);
        }
        const srcWal = `${sourcePath}-wal`;
        if (fs.existsSync(srcWal)) {
          try {
            fs.copyFileSync(srcWal, `${branchPath}-wal`, fs.constants.COPYFILE_FICLONE);
          } catch (e) {
            fs.copyFileSync(srcWal, `${branchPath}-wal`);
          }
        }
        plan.provisioned = true;
        this._ensureBranchesLoaded();
        this._dbBranches[previewId] = plan;
        this._saveBranches();
      }
      return plan;
    }

    if (!['postgres', 'postgresql', 'pgvector', 'timescaledb'].includes(rawEngine)) {
      throw new Error(`Motor no soportado para Preview DB Branching: "${rawEngine}" (usa postgres o sqlite)`);
    }

    const sourceDbName = assertSafePgIdent(dbConfig.sourceDb || dbConfig.dbName || 'app', 'sourceDb');
    const username = assertSafePgIdent(dbConfig.username || 'postgres', 'username');
    const containerName = String(dbConfig.containerName || 'culkibo-postgres').trim();
    if (!SAFE_DOCKER_CONTAINER_RE.test(containerName)) {
      throw new Error(`Nombre de contenedor PostgreSQL inválido: "${containerName.slice(0, 60)}"`);
    }
    const host = String(dbConfig.host || containerName).trim();
    if (!/^[a-zA-Z0-9._-]+$/.test(host)) {
      throw new Error(`Host PostgreSQL inválido: "${host.slice(0, 60)}"`);
    }
    const port = Number(dbConfig.port || 5432);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(`Puerto PostgreSQL inválido: "${dbConfig.port}"`);
    }

    const branchDbName = assertSafePgIdent(
      `culkibo_prev_${pgIdentSlug(project.id, 28)}_pr${cleanPr}`,
      'branchDbName'
    );

    // Zero-shell: argumentos parametrizados con variables `psql -v` e identificadores `:"var"`
    const createSql = 'CREATE DATABASE :"branch_db" WITH TEMPLATE :"template_db" OWNER :"db_owner";';
    const dropSql = 'DROP DATABASE IF EXISTS :"branch_db" WITH (FORCE);';

    const createArgv = [
      'exec', '-i', containerName,
      'psql', '-v', 'ON_ERROR_STOP=1',
      '-v', `branch_db=${branchDbName}`,
      '-v', `template_db=${sourceDbName}`,
      '-v', `db_owner=${username}`,
      '-U', username, '-d', 'postgres',
      '-c', createSql
    ];
    const teardownArgv = [
      'exec', '-i', containerName,
      'psql', '-v', 'ON_ERROR_STOP=1',
      '-v', `branch_db=${branchDbName}`,
      '-U', username, '-d', 'postgres',
      '-c', dropSql
    ];

    const plan = {
      ok: true,
      previewId,
      projectId: project.id,
      key,
      prNumber: Number(cleanPr),
      engine: 'postgres',
      strategy: 'postgres_create_database_template',
      zeroShell: true,
      idempotentTeardown: true,
      containerName,
      sourceDbName,
      branchDbName,
      username,
      host,
      port,
      sqlTemplates: {
        createSql,
        dropSql
      },
      createCommand: { program: 'docker', args: createArgv },
      teardownCommand: { program: 'docker', args: teardownArgv },
      createArgv,
      teardownArgv,
      envOverride: {
        DATABASE_URL: `postgresql://${username}:\${vault.DB_PASSWORD}@${host}:${port}/${branchDbName}`,
        PGDATABASE: branchDbName,
        CULKIBO_PREVIEW_DB_BRANCH: previewId
      },
      provisioned: false,
      createdAt: new Date().toISOString()
    };

    // Registrar en el almacén de ramas para que teardownPreviewDbBranch pueda limpiar tras reinicios
    this._ensureBranchesLoaded();
    this._dbBranches[previewId] = plan;
    this._saveBranches();

    return plan;
  }

  /**
   * Destruye de forma 100% idempotente la rama de base de datos asociada a una vista previa
   * (cura `coolify#12458` evitando fugas de BDs huérfanas al cerrar o fallar una PR).
   *
   * @param {string | { projectId: string, key?: string, prNumber?: number | string }} previewIdOrTarget
   * @param {{
   *   branchPlan?: any,
   *   dryRun?: boolean,
   *   executor?: (argv: string[]) => Promise<{ code: number, stdout?: string, stderr?: string }>
   * }} [opts]
   */
  async teardownPreviewDbBranch(previewIdOrTarget, opts = {}) {
    this._ensureBranchesLoaded();
    let previewId = '';
    if (typeof previewIdOrTarget === 'string') {
      previewId = previewIdOrTarget.trim();
    } else if (previewIdOrTarget && typeof previewIdOrTarget === 'object') {
      const k = previewIdOrTarget.key
        || (previewIdOrTarget.prNumber != null ? `pr-${String(previewIdOrTarget.prNumber).replace(/[^0-9]/g, '')}` : '');
      if (previewIdOrTarget.projectId && k) previewId = `${previewIdOrTarget.projectId}:${k}`;
    }
    if (!previewId) {
      return { ok: true, previewId: '', destroyed: false, alreadyCleaned: true };
    }

    const branch = this._dbBranches[previewId] || opts.branchPlan || null;
    if (!branch) {
      return { ok: true, previewId, destroyed: false, alreadyCleaned: true };
    }

    if (branch.engine === 'sqlite') {
      /** @type {string[]} */
      const removedFiles = [];
      const files = Array.isArray(branch.cleanupFiles) && branch.cleanupFiles.length > 0
        ? branch.cleanupFiles
        : [branch.branchPath, `${branch.branchPath}-wal`, `${branch.branchPath}-shm`];
      if (!opts.dryRun) {
        for (const fp of files) {
          if (!fp) continue;
          try {
            if (fs.existsSync(fp)) {
              fs.unlinkSync(fp);
              removedFiles.push(fp);
            }
          } catch (e) {}
        }
        delete this._dbBranches[previewId];
        this._saveBranches();
      }
      return {
        ok: true,
        previewId,
        engine: 'sqlite',
        destroyed: !opts.dryRun,
        alreadyCleaned: false,
        dryRun: Boolean(opts.dryRun),
        removedFiles
      };
    }

    // PostgreSQL teardown (idempotente gracias a DROP DATABASE IF EXISTS ... WITH (FORCE))
    const teardownArgv = Array.isArray(branch.teardownArgv) ? branch.teardownArgv : null;
    /** @type {any} */
    let execResult = null;
    if (!opts.dryRun && teardownArgv) {
      const runner = typeof opts.executor === 'function'
        ? opts.executor
        : (argv) => this._getDeployManager().runDocker(argv, { timeoutMs: 20000 });
      try {
        execResult = await runner(teardownArgv);
      } catch (err) {
        execResult = { code: -1, stderr: err.message };
      }
    }

    if (!opts.dryRun) {
      delete this._dbBranches[previewId];
      this._saveBranches();
    }

    return {
      ok: true,
      previewId,
      engine: branch.engine || 'postgres',
      branchDbName: branch.branchDbName || null,
      destroyed: !opts.dryRun,
      alreadyCleaned: false,
      dryRun: Boolean(opts.dryRun),
      teardownCommand: { program: 'docker', args: teardownArgv || [] },
      execResult
    };
  }

  async destroyProjectPreviews(projectId) {
    this._ensureLoaded();
    const keys = new Set(Object.keys(this.store[projectId] || {}));
    for (const lk of this._activeBuilds.keys()) {
      if (lk.startsWith(`${projectId}:`)) keys.add(lk.slice(projectId.length + 1));
    }
    let count = 0;
    for (const k of keys) {
      const r = await this.destroyPreview(projectId, k).catch(() => ({ removed: false }));
      if (r.removed) count++;
    }
    try {
      const projectPreviewDir = assertContainedPath(this.workDir, String(projectId));
      fs.rmSync(projectPreviewDir, { recursive: true, force: true });
    } catch (e) {}
    return count;
  }

  async getLogs(projectId, key, tail = 150) {
    const prev = this.get(projectId, key);
    if (!prev || !prev.containerName) throw new Error('Vista previa no encontrada');
    const dm = this._getDeployManager();
    const safeTail = Math.min(2000, Math.max(10, Number(tail) || 150));
    const res = await dm.runDocker(['logs', '--tail', String(safeTail), '--timestamps', prev.containerName], { timeoutMs: 10000 });
    const secrets = typeof dm._secretValuesForProject === 'function' ? dm._secretValuesForProject(projectId) : [];
    const rawLogs = [res.stdout, res.stderr].filter(Boolean).join('\n');
    return {
      key,
      containerName: prev.containerName,
      logs: typeof dm.redact === 'function' ? dm.redact(rawLogs, secrets) : rawLogs
    };
  }

  /** Limpia vistas previas caducadas por TTL. */
  async reapExpired() {
    this._ensureLoaded();
    const now = Date.now();
    /** @type {Array<{ projectId: string, key: string }>} */
    const expired = [];
    for (const [projectId, projMap] of Object.entries(this.store)) {
      for (const [key, prev] of Object.entries(projMap || {})) {
        if (prev && prev.expiresAt && Date.parse(prev.expiresAt) <= now) {
          expired.push({ projectId, key });
        }
      }
    }
    for (const item of expired) {
      await this.destroyPreview(item.projectId, item.key).catch(() => {});
    }
    return expired.length;
  }

  startReaper() {
    if (this._reaperTimer) return;
    this._reaperTimer = setInterval(() => {
      this.reapExpired().catch(() => {});
    }, 60 * 60 * 1000);
    if (this._reaperTimer.unref) this._reaperTimer.unref();
  }

  stopReaper() {
    if (this._reaperTimer) {
      clearInterval(this._reaperTimer);
      this._reaperTimer = null;
    }
  }
}

const instance = /** @type {any} */ (new PreviewManager());
instance.PreviewManager = PreviewManager;
instance.computePreviewIdentity = computePreviewIdentity;
module.exports = instance;
