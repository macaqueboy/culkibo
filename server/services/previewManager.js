const { EventEmitter } = require('events');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const portRegistry = require('./portRegistry');
const { atomicWriteJsonSync } = require('./ssrfGuard');

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
  const baseDomain = String(project?.previewDeployments?.baseDomain || '').trim().toLowerCase().replace(/^\*\./, '');
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
  constructor(storeFile = STORE_FILE) {
    super();
    this.storeFile = storeFile;
    this.storeBakFile = `${storeFile}.bak`;
    /** @type {Record<string, Record<string, any>>} */
    this.store = {};
    /** @type {Set<string>} */
    this.inFlightKeys = new Set();
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
   * @param {any} project
   * @param {{ branch?: string, prNumber?: number | string | null, commit?: string | null, isFork?: boolean, title?: string | null }} [opts]
   */
  async deployPreview(project, { branch = '', prNumber = null, commit = null, isFork = false, title = null } = {}) {
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
    if (this.inFlightKeys.has(lockKey)) {
      const err = new Error(`Ya hay un despliegue preview en curso para ${identity.key}`);
      /** @type {any} */ (err).status = 409;
      throw err;
    }
    this.inFlightKeys.add(lockKey);

    const dm = getDeployManager();
    const ing = getIngressManager();
    const rs = getRepoSync();

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
    const checkoutDir = path.join(PREVIEWS_WORK_DIR, project.id, identity.key);

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
      error: null,
      createdAt: existing?.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + ttlHours * 3600 * 1000).toISOString()
    };
    this.store[project.id][identity.key] = record;
    this.save();
    this.emit('preview_event', { action: 'building', preview: record });

    /** @type {number | null} */
    let hostPort = null;
    try {
      const docker = await dm.detectDocker({ force: true });
      if (!docker.available) throw new Error(docker.reason || 'Docker no disponible');

      // 1. Clonar / sincronizar rama en directorio aislado de previews
      fs.mkdirSync(path.dirname(checkoutDir), { recursive: true });
      const sync = await rs.sync({ ...project, gitBranch: record.branch }, {
        targetDir: checkoutDir,
        commit: commit || null
      });
      if (!sync.ok) throw new Error(sync.error || 'Error obteniendo código de la rama preview');
      if (sync.commit) record.commit = sync.shortCommit || sync.commit.slice(0, 7);

      const contextDir = project.baseDirectory && project.baseDirectory !== '/' && project.baseDirectory !== '.'
        ? path.resolve(checkoutDir, String(project.baseDirectory).replace(/^\/+/, ''))
        : checkoutDir;

      // 2. Estrategia + build protegido por el semáforo global de deployManager
      const strategy = await dm.detectStrategy(contextDir, project);
      if (strategy.builder === 'generated' && strategy.stack === 'desconocido') {
        throw new Error('No se detectó Dockerfile ni stack compatible para construir la preview');
      }

      const linkedDb = dm.resolveLinkedDatabases(project);
      const envVars = {
        ...linkedDb.injectedEnv,
        ...(project.envVars || {}),
        CULKIBO_PREVIEW: '1',
        CULKIBO_PREVIEW_BRANCH: record.branch,
        CULKIBO_PREVIEW_URL: record.url
      };

      await dm.acquireBuildSlot(project.id, `prev_${identity.key}`);
      try {
        const fakeDep = {
          id: `prev_${identity.key}_${suffix}`,
          projectId: project.id,
          projectName: project.name,
          imageTag,
          logLines: []
        };
        const buildRes = await dm.runBuild(fakeDep, {
          strategy,
          contextDir,
          project,
          opts: dm.DEFAULTS,
          envVars
        });
        if (!buildRes.ok) throw new Error(buildRes.error || 'Error construyendo imagen preview');
      } finally {
        dm.releaseBuildSlot();
      }

      // 3. Arrancar contenedor preview con límites estrictos
      await dm.ensureNetwork(dm.DEFAULTS.network);
      hostPort = await dm.findFreePort(20000, `prev_${identity.key}_${suffix}`);
      record.hostPort = hostPort;
      record.containerPort = strategy.containerPort;

      const memCap = Math.min(Number(cfg.memoryMb) || 512, Number(project.memoryMb) || 512);
      const envNames = Object.keys(envVars).filter(dm.helpers.isValidEnvName);
      const runArgs = dm.runArgs({
        containerName,
        imageTag,
        hostPort,
        containerPort: strategy.containerPort,
        envNames,
        network: dm.DEFAULTS.network,
        memoryMb: Math.max(64, memCap),
        cpus: '0.5',
        pidsLimit: 256,
        labels: {
          'culkibo.managed': 'true',
          'com.culkibo.project': dm.helpers.safeSlug(project.id),
          'com.culkibo.project_id': project.id,
          'com.culkibo.preview': 'true',
          'com.culkibo.preview_key': identity.key
        }
      });

      const safeEnv = { ...process.env, ...dm.helpers.filterSafeHostEnv(envVars) };
      const run = await dm.runDocker(runArgs, { timeoutMs: 60000, env: safeEnv });
      if (run.code !== 0) {
        throw new Error((run.stderr || '').trim().slice(0, 400) || `docker run terminó con código ${run.code}`);
      }

      // 4. Healthcheck
      const health = await dm.waitForHealth({
        hostPort,
        containerPort: strategy.containerPort,
        healthPath: strategy.healthPath,
        containerName,
        timeoutMs: 30000,
        intervalMs: 1000
      });
      if (!health.healthy) {
        await dm.runDocker(['rm', '-f', containerName], { timeoutMs: 15000 }).catch(() => {});
        throw new Error(`Preview no pasó el healthcheck: ${health.reason}`);
      }

      const upstream = await dm.resolveUpstream({
        containerName,
        containerPort: strategy.containerPort,
        hostPort,
        network: dm.DEFAULTS.network
      });
      record.upstream = upstream.dial;
      record.status = 'active';
      record.error = null;
      record.updatedAt = new Date().toISOString();
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
      if (existing && existing.containerName && existing.containerName !== containerName) {
        await dm.runDocker(['rm', '-f', existing.containerName], { timeoutMs: 15000 }).catch(() => {});
      }

      this.emit('preview_event', { action: 'active', preview: record });
      return record;
    } catch (err) {
      record.status = 'failed';
      record.error = err.message || 'Error en vista previa';
      record.updatedAt = new Date().toISOString();
      this.save();
      this.emit('preview_event', { action: 'failed', preview: record });
      throw err;
    } finally {
      if (hostPort) portRegistry.release(hostPort, `prev_${identity.key}_${suffix}`);
      this.inFlightKeys.delete(lockKey);
    }
  }

  /**
   * Destruye una vista previa (ruta Caddy + contenedor + imagen + directorio temporal).
   */
  async destroyPreview(projectId, key) {
    this._ensureLoaded();
    const projMap = this.store[projectId];
    const prev = projMap && projMap[key];
    if (!prev) return { removed: false };

    const dm = getDeployManager();
    const ing = getIngressManager();

    ing.previewRoutes.delete(`${projectId}_${key}`);
    await ing.reconcile().catch(() => {});

    if (prev.containerName) {
      await dm.runDocker(['rm', '-f', prev.containerName], { timeoutMs: 20000 }).catch(() => {});
    }
    if (prev.imageTag) {
      await dm.runDocker(['rmi', prev.imageTag], { timeoutMs: 20000 }).catch(() => {});
    }

    const checkoutDir = path.join(PREVIEWS_WORK_DIR, projectId, key);
    try { fs.rmSync(checkoutDir, { recursive: true, force: true }); } catch (e) {}

    delete projMap[key];
    if (Object.keys(projMap).length === 0) delete this.store[projectId];
    this.save();
    this.emit('preview_event', { action: 'destroyed', projectId, key });
    return { removed: true, key };
  }

  async destroyProjectPreviews(projectId) {
    this._ensureLoaded();
    const keys = Object.keys(this.store[projectId] || {});
    let count = 0;
    for (const k of keys) {
      const r = await this.destroyPreview(projectId, k).catch(() => ({ removed: false }));
      if (r.removed) count++;
    }
    return count;
  }

  async getLogs(projectId, key, tail = 150) {
    const prev = this.get(projectId, key);
    if (!prev || !prev.containerName) throw new Error('Vista previa no encontrada');
    const dm = getDeployManager();
    const safeTail = Math.min(2000, Math.max(10, Number(tail) || 150));
    const res = await dm.runDocker(['logs', '--tail', String(safeTail), '--timestamps', prev.containerName], { timeoutMs: 10000 });
    return {
      key,
      containerName: prev.containerName,
      logs: [res.stdout, res.stderr].filter(Boolean).join('\n')
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
