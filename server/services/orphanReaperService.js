const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Docker-29-Immune Orphaned PR-Preview Auto-Reaper & Dangling Resource GC (Zero-Dep).
 *
 * Cura las regresiones reales de fuga de disco y purgas peligrosas en PaaS:
 *  - `coolify#11441` (volúmenes `-pr-<n>` huérfanos tras cerrar un PR)
 *  - `coolify#12148` (Docker 29 rompió los parsers `awk` de prune — aquí usamos `--format '{{json .}}'` + `shell: false`)
 *  - `dokploy#4203` / `#4893` (contenedores/servicios de preview huérfanos tras race de cierre o borrado del proyecto padre)
 *  - `dokploy#3973` (`image prune -a -f` destruyendo imágenes sidecar de Compose activas)
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/orphan-reaper.json`.
 */

const DEFAULT_REAPER_POLICY = Object.freeze({
  minOrphanAgeHours: 1,
  danglingImageMaxAgeHours: 72,
  maxReapPerRun: 20,
  protectComposeSidecars: true,
  protectDatabaseVolumes: true,
  reapClosedPrVolumes: true,
  dryRunDefault: true
});

const DOCKER_INSPECT_ARGV = Object.freeze({
  containers: Object.freeze(['docker', 'ps', '-a', '--format', '{{json .}}']),
  services: Object.freeze(['docker', 'service', 'ls', '--format', '{{json .}}']),
  volumes: Object.freeze(['docker', 'volume', 'ls', '--format', '{{json .}}']),
  images: Object.freeze(['docker', 'images', '--format', '{{json .}}'])
});

const DB_VOLUME_RE = /(?:pgdata|postgres|mysql|mariadb|mongo|redis|dragonfly|clickhouse|db[-_]?data)/i;
const PR_SUFFIX_RE = /(?:^|[-_])pr[-_](\d+)(?:$|[-_])/i;
const PREVIEW_PARENT_RE = /^preview-([a-z0-9_]+)-/i;

/**
 * Resuelve dinámicamente la ruta a `orphan-reaper.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'orphan-reaper.json')
    : path.join(base, 'data', 'orphan-reaper.json');
}

/**
 * Escritura atómica con permisos `0o600`.
 * @param {string} targetPath
 * @param {string} content
 */
function atomicWriteFileSync(targetPath, content) {
  const dir = path.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = `${targetPath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(tmpPath, content, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmpPath, targetPath);
    try { fs.chmodSync(targetPath, 0o600); } catch (e) {}
  } catch (err) {
    try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e) {}
    throw err;
  }
}

/**
 * Carga política y ledger de purgas desde disco (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, policy: Record<string, any>, ledger: any[] }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), policy: { ...DEFAULT_REAPER_POLICY }, ledger: [] };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && typeof parsed === 'object') {
      return {
        schemaVersion: 1,
        updatedAt: parsed.updatedAt || new Date().toISOString(),
        policy: { ...DEFAULT_REAPER_POLICY, ...(parsed.policy || {}) },
        ledger: Array.isArray(parsed.ledger) ? parsed.ledger : []
      };
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), policy: { ...DEFAULT_REAPER_POLICY }, ledger: [] };
}

/**
 * Guarda política y ledger atómicamente (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, policy: Record<string, any>, ledger: any[] }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  if (store.ledger.length > 200) {
    store.ledger = store.ledger.slice(-200);
  }
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Devuelve la política actual del Auto-Reaper.
 */
function getReaperPolicy() {
  const store = loadStore();
  return {
    ok: true,
    policy: { ...DEFAULT_REAPER_POLICY, ...(store.policy || {}) },
    recentRuns: [...store.ledger].reverse().slice(0, 20)
  };
}

/**
 * Actualiza la política persistida del Auto-Reaper.
 * @param {Record<string, any>} policy
 */
function upsertReaperPolicy(policy = {}) {
  const store = loadStore();
  /** @type {Record<string, any>} */
  const merged = {
    ...DEFAULT_REAPER_POLICY,
    ...(store.policy || {}),
    ...(policy && typeof policy === 'object' ? policy : {})
  };
  merged.minOrphanAgeHours = Math.max(0, Number(merged.minOrphanAgeHours) || 0);
  merged.danglingImageMaxAgeHours = Math.max(0, Number(merged.danglingImageMaxAgeHours) || 0);
  merged.maxReapPerRun = Math.max(1, Math.min(500, Math.floor(Number(merged.maxReapPerRun) || 20)));
  store.policy = merged;
  saveStore(store);
  return {
    ok: true,
    policy: merged
  };
}

/**
 * Normaliza un conjunto de strings a minúsculas.
 * @param {any} arr
 * @returns {Set<string>}
 */
function toLowerSet(arr) {
  /** @type {Set<string>} */
  const out = new Set();
  if (!Array.isArray(arr)) return out;
  for (const item of arr) {
    if (typeof item === 'string' && item.trim()) {
      out.add(item.trim().toLowerCase());
    } else if (item && typeof item === 'object') {
      if (item.id) out.add(String(item.id).trim().toLowerCase());
      if (item.name) out.add(String(item.name).trim().toLowerCase());
      if (item.pr !== undefined && item.pr !== null) {
        const prNum = String(item.pr).trim().toLowerCase();
        out.add(prNum);
        out.add(`pr-${prNum}`);
        if (item.project) out.add(`${String(item.project).trim().toLowerCase()}:pr-${prNum}`);
      }
    }
  }
  return out;
}

/**
 * Comprueba si un PR / preview está activo en `activePreviewSet`.
 * @param {Set<string>} activePreviewSet
 * @param {string | null} prNum
 * @param {string} name
 * @param {string} project
 */
function isPreviewActive(activePreviewSet, prNum, name, project) {
  const lowerName = String(name || '').toLowerCase();
  const lowerProj = String(project || '').toLowerCase();
  if (lowerName && activePreviewSet.has(lowerName)) return true;
  if (prNum) {
    const p = String(prNum).toLowerCase();
    if (activePreviewSet.has(p) || activePreviewSet.has(`pr-${p}`)) return true;
    if (lowerProj && (activePreviewSet.has(`${lowerProj}:${p}`) || activePreviewSet.has(`${lowerProj}:pr-${p}`))) {
      return true;
    }
  }
  return false;
}

/**
 * Escanea un snapshot JSON de Docker (contenedores, servicios Swarm, volúmenes e imágenes)
 * para identificar huérfanos de PR previews y recursos dangling protegiendo sidecars y DBs.
 *
 * @param {{
 *   dockerSnapshot?: { containers?: any[], services?: any[], volumes?: any[], images?: any[] },
 *   activeProjects?: any[],
 *   activePreviews?: any[],
 *   policy?: Record<string, any>
 * }} [input]
 */
function scanOrphans(input = {}) {
  const opts = input || {};
  const snap = (opts.dockerSnapshot && typeof opts.dockerSnapshot === 'object') ? opts.dockerSnapshot : {};
  const stored = loadStore();
  const policy = { ...DEFAULT_REAPER_POLICY, ...(stored.policy || {}), ...(opts.policy || {}) };

  const activeProjectSet = toLowerSet(opts.activeProjects);
  const activePreviewSet = toLowerSet(opts.activePreviews);

  const containers = Array.isArray(snap.containers) ? snap.containers : [];
  const services = Array.isArray(snap.services) ? snap.services : [];
  const volumes = Array.isArray(snap.volumes) ? snap.volumes : [];
  const images = Array.isArray(snap.images) ? snap.images : [];

  /** @type {Array<{ resourceType: string, id: string, name: string, project: string | null, prNumber: string | null, reason: string, sizeBytes: number, argv: string[] }>} */
  const orphans = [];
  /** @type {Array<{ resourceType: string, id: string, name: string, protectedReasons: string[] }>} */
  const protectedItems = [];

  /**
   * Evalúa un contenedor o servicio Swarm.
   * @param {any} item
   * @param {'container' | 'service'} resourceType
   */
  const inspectWorkload = (item, resourceType) => {
    const labels = (item && item.labels && typeof item.labels === 'object') ? item.labels : {};
    const id = String(item.id || item.name || '').trim();
    const name = String(item.name || item.id || '').trim();
    const composeProject = String(labels['com.docker.compose.project'] || '').trim().toLowerCase();
    const culkiboProject = String(labels['culkibo.project'] || '').trim().toLowerCase();
    const managed = String(labels['culkibo.managed'] || '').toLowerCase() === 'true';
    const explicitProtect = String(labels['culkibo.protect'] || '').toLowerCase() === 'true';
    const labelPr = labels['culkibo.preview.pr'] !== undefined && labels['culkibo.preview.pr'] !== null
      ? String(labels['culkibo.preview.pr']).trim()
      : null;
    const namePrMatch = name.match(PR_SUFFIX_RE);
    const prNumber = labelPr || (namePrMatch ? namePrMatch[1] : null);
    const previewParentMatch = name.match(PREVIEW_PARENT_RE);
    const inferredParent = culkiboProject || composeProject || (previewParentMatch ? previewParentMatch[1].toLowerCase() : '');
    const sizeBytes = Math.max(0, Number(item.sizeBytes) || 0);
    const removeArgv = resourceType === 'service' ? ['docker', 'service', 'rm', id] : ['docker', 'rm', '-f', id];

    if (explicitProtect) {
      protectedItems.push({ resourceType, id, name, protectedReasons: ['EXPLICIT_PROTECT_LABEL'] });
      return;
    }

    // 1. PR Preview workload (label or -pr-<n> naming)
    if (prNumber) {
      const parentAlive = !inferredParent || activeProjectSet.has(inferredParent);
      if (parentAlive && isPreviewActive(activePreviewSet, prNumber, name, inferredParent)) {
        protectedItems.push({ resourceType, id, name, protectedReasons: ['ACTIVE_PR_PREVIEW'] });
      } else {
        orphans.push({
          resourceType,
          id,
          name,
          project: inferredParent || null,
          prNumber,
          reason: parentAlive ? 'CLOSED_PR_PREVIEW_CONTAINER' : 'DELETED_PARENT_PROJECT_PREVIEW',
          sizeBytes,
          argv: removeArgv
        });
      }
      return;
    }

    // 2. Preview naming (`preview-<parent>-<hash>`) whose parent project was deleted (dokploy#4893)
    if (previewParentMatch) {
      const parent = previewParentMatch[1].toLowerCase();
      if (!activeProjectSet.has(parent) && !isPreviewActive(activePreviewSet, null, name, parent)) {
        orphans.push({
          resourceType,
          id,
          name,
          project: parent,
          prNumber: null,
          reason: 'DELETED_PARENT_PROJECT_PREVIEW',
          sizeBytes,
          argv: removeArgv
        });
        return;
      }
      protectedItems.push({ resourceType, id, name, protectedReasons: ['ACTIVE_PR_PREVIEW'] });
      return;
    }

    // 3. Active Compose sidecar protection (dokploy#3973)
    if (policy.protectComposeSidecars && composeProject && activeProjectSet.has(composeProject)) {
      protectedItems.push({ resourceType, id, name, protectedReasons: ['ACTIVE_COMPOSE_SIDECAR'] });
      return;
    }

    // 4. Managed resource belonging to deleted parent project
    if (managed && culkiboProject && !activeProjectSet.has(culkiboProject)) {
      orphans.push({
        resourceType,
        id,
        name,
        project: culkiboProject,
        prNumber: null,
        reason: 'DELETED_PARENT_PROJECT_RESOURCE',
        sizeBytes,
        argv: removeArgv
      });
      return;
    }

    if (culkiboProject && activeProjectSet.has(culkiboProject)) {
      protectedItems.push({ resourceType, id, name, protectedReasons: ['ACTIVE_PROJECT_RESOURCE'] });
    }
  };

  for (const c of containers) inspectWorkload(c, 'container');
  for (const s of services) inspectWorkload(s, 'service');

  // Volumes: reap leaked closed-PR `-pr-<n>` volumes (coolify#11441) while shielding active & prod DB volumes
  for (const vol of volumes) {
    const labels = (vol && vol.labels && typeof vol.labels === 'object') ? vol.labels : {};
    const name = String(vol.name || vol.id || '').trim();
    const explicitProtect = String(labels['culkibo.protect'] || '').toLowerCase() === 'true';
    const culkiboProject = String(labels['culkibo.project'] || labels['com.docker.compose.project'] || '').trim().toLowerCase();
    const labelPr = labels['culkibo.preview.pr'] !== undefined && labels['culkibo.preview.pr'] !== null
      ? String(labels['culkibo.preview.pr']).trim()
      : null;
    const namePrMatch = name.match(PR_SUFFIX_RE);
    const prNumber = labelPr || (namePrMatch ? namePrMatch[1] : null);
    const sizeBytes = Math.max(0, Number(vol.sizeBytes) || 0);

    if (explicitProtect) {
      protectedItems.push({ resourceType: 'volume', id: name, name, protectedReasons: ['EXPLICIT_PROTECT_LABEL'] });
      continue;
    }

    if (prNumber && policy.reapClosedPrVolumes) {
      if (isPreviewActive(activePreviewSet, prNumber, name, culkiboProject)) {
        protectedItems.push({ resourceType: 'volume', id: name, name, protectedReasons: ['ACTIVE_PR_PREVIEW_VOLUME'] });
      } else {
        orphans.push({
          resourceType: 'volume',
          id: name,
          name,
          project: culkiboProject || null,
          prNumber,
          reason: 'LEAKED_PR_PREVIEW_VOLUME',
          sizeBytes,
          argv: ['docker', 'volume', 'rm', name]
        });
      }
      continue;
    }

    // Shield production / non-PR DB volumes unconditionally!
    const isDbVol = DB_VOLUME_RE.test(name) || String(labels['culkibo.db'] || '').toLowerCase() === 'true';
    if (policy.protectDatabaseVolumes && isDbVol) {
      protectedItems.push({ resourceType: 'volume', id: name, name, protectedReasons: ['PROTECTED_DATABASE_VOLUME'] });
      continue;
    }

    if (culkiboProject && activeProjectSet.has(culkiboProject)) {
      protectedItems.push({ resourceType: 'volume', id: name, name, protectedReasons: ['ACTIVE_PROJECT_VOLUME'] });
    }
  }

  // Images: shield active Compose sidecar images (dokploy#3973); only reap aged dangling/unused layers
  for (const img of images) {
    const labels = (img && img.labels && typeof img.labels === 'object') ? img.labels : {};
    const id = String(img.id || img.tag || img.name || '').trim();
    const name = String(img.tag || img.name || img.id || '').trim();
    const composeProject = String(labels['com.docker.compose.project'] || labels['culkibo.project'] || '').trim().toLowerCase();
    const explicitProtect = String(labels['culkibo.protect'] || '').toLowerCase() === 'true';
    const isSidecar = Boolean(img.sidecar || img.inUseBySidecar)
      || (composeProject && activeProjectSet.has(composeProject));
    const dangling = Boolean(img.dangling) || name.startsWith('<none>');
    const ageHours = Math.max(0, Number(img.ageHours) || 0);
    const sizeBytes = Math.max(0, Number(img.sizeBytes) || 0);

    if (explicitProtect) {
      protectedItems.push({ resourceType: 'image', id, name, protectedReasons: ['EXPLICIT_PROTECT_LABEL'] });
      continue;
    }
    if (policy.protectComposeSidecars && isSidecar) {
      protectedItems.push({ resourceType: 'image', id, name, protectedReasons: ['ACTIVE_COMPOSE_SIDECAR_IMAGE'] });
      continue;
    }
    if (dangling && ageHours >= policy.danglingImageMaxAgeHours) {
      orphans.push({
        resourceType: 'image',
        id,
        name,
        project: composeProject || null,
        prNumber: null,
        reason: 'AGED_DANGLING_IMAGE',
        sizeBytes,
        argv: ['docker', 'image', 'rm', id]
      });
    } else {
      protectedItems.push({ resourceType: 'image', id, name, protectedReasons: ['RETAINED_ACTIVE_OR_RECENT_IMAGE'] });
    }
  }

  const totalReclaimableBytes = orphans.reduce((acc, o) => acc + (o.sizeBytes || 0), 0);

  return {
    ok: true,
    scannedAt: new Date().toISOString(),
    counts: {
      containers: containers.length,
      services: services.length,
      volumes: volumes.length,
      images: images.length
    },
    orphans,
    protected: protectedItems,
    totalReclaimableBytes,
    inspectArgvTemplates: DOCKER_INSPECT_ARGV
  };
}

/**
 * Ordena y acota las acciones de purga (`containers → services → volumes → images`)
 * con comandos `argv` sin shell.
 *
 * @param {{ scanResult: ReturnType<typeof scanOrphans>, maxReapPerRun?: number }} input
 */
function planReap(input) {
  const opts = input || /** @type {any} */ ({});
  const scan = opts.scanResult || { orphans: [], protected: [] };
  const cap = Math.max(1, Math.floor(Number(opts.maxReapPerRun) || DEFAULT_REAPER_POLICY.maxReapPerRun));

  /** @type {Record<string, number>} */
  const orderWeight = { container: 1, service: 2, volume: 3, image: 4 };
  const sorted = [...(Array.isArray(scan.orphans) ? scan.orphans : [])].sort((a, b) => (
    (orderWeight[a.resourceType] || 9) - (orderWeight[b.resourceType] || 9)
  ));

  const actions = sorted.slice(0, cap).map((item, idx) => ({
    order: idx + 1,
    resourceType: item.resourceType,
    id: item.id,
    name: item.name,
    reason: item.reason,
    sizeBytes: item.sizeBytes || 0,
    argv: [...item.argv]
  }));

  const reclaimableBytes = actions.reduce((acc, a) => acc + a.sizeBytes, 0);

  return {
    ok: true,
    planId: `reap_${crypto.randomBytes(6).toString('hex')}`,
    actions,
    skippedCount: Math.max(0, sorted.length - actions.length),
    reclaimableBytes,
    protectedCount: Array.isArray(scan.protected) ? scan.protected.length : 0,
    createdAt: new Date().toISOString()
  };
}

/**
 * Ejecuta (o simula con `dryRun: true` por defecto) un plan de purga de huérfanos,
 * registrando la auditoría de bytes liberados en `orphan-reaper.json`.
 *
 * @param {{
 *   plan: ReturnType<typeof planReap>,
 *   dryRun?: boolean,
 *   executor?: ((argv: string[], action: any) => any) | null
 * }} input
 */
function executeReap(input) {
  const opts = input || /** @type {any} */ ({});
  const plan = opts.plan || { planId: 'empty', actions: [], reclaimableBytes: 0, protectedCount: 0 };
  const dryRun = opts.dryRun !== undefined ? Boolean(opts.dryRun) : true;
  const actions = Array.isArray(plan.actions) ? plan.actions : [];
  const executedAt = new Date().toISOString();

  if (dryRun) {
    const ledgerEntry = {
      planId: plan.planId,
      dryRun: true,
      plannedCount: actions.length,
      executedCount: 0,
      reclaimedBytes: 0,
      estimatedReclaimableBytes: plan.reclaimableBytes || 0,
      protectedCount: plan.protectedCount || 0,
      timestamp: executedAt
    };
    return {
      ok: true,
      dryRun: true,
      planId: plan.planId,
      plannedCount: actions.length,
      executedCount: 0,
      failedCount: 0,
      reclaimedBytes: 0,
      estimatedReclaimableBytes: plan.reclaimableBytes || 0,
      results: actions.map((a) => ({ ...a, status: 'DRY_RUN_PLANNED' })),
      ledgerEntry
    };
  }

  let executedCount = 0;
  let failedCount = 0;
  let reclaimedBytes = 0;
  /** @type {any[]} */
  const results = [];

  for (const action of actions) {
    try {
      if (typeof opts.executor === 'function') {
        opts.executor(action.argv, action);
      }
      executedCount++;
      reclaimedBytes += action.sizeBytes || 0;
      results.push({ ...action, status: 'REAPED' });
    } catch (err) {
      failedCount++;
      results.push({ ...action, status: 'FAILED', error: err && err.message ? err.message : String(err) });
    }
  }

  const ledgerEntry = {
    planId: plan.planId,
    dryRun: false,
    plannedCount: actions.length,
    executedCount,
    failedCount,
    reclaimedBytes,
    protectedCount: plan.protectedCount || 0,
    timestamp: executedAt
  };

  const store = loadStore();
  store.ledger.push(ledgerEntry);
  saveStore(store);

  return {
    ok: true,
    dryRun: false,
    planId: plan.planId,
    plannedCount: actions.length,
    executedCount,
    failedCount,
    reclaimedBytes,
    estimatedReclaimableBytes: plan.reclaimableBytes || 0,
    results,
    ledgerEntry
  };
}

module.exports = {
  DEFAULT_REAPER_POLICY,
  DOCKER_INSPECT_ARGV,
  scanOrphans,
  planReap,
  executeReap,
  upsertReaperPolicy,
  getReaperPolicy
};
