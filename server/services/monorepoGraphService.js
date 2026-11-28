const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Monorepo Affected-Graph Selective Builder & Topological Rollout Planner (100% Zero-Dep).
 *
 * Contramedida directa a `Dokploy/dokploy#5547` (PR previews ignorando `watchPaths` y
 * reconstruyendo cada app del monorepo) y despliegues desordenados en Coolify:
 *  - Construye un DAG puro JS desde descriptores `{ name, dir, deps[], watchPaths[] }`.
 *  - Mapea `changedFiles[]` a servicios afectados directos + transitivos (`skippedServices[]`
 *    ahorrados de rebuilds innecesarios!).
 *  - Ejecuta el algoritmo de Kahn detectando ciclos (`WORKSPACE_CYCLE_DETECTED`) y emitiendo
 *    olas ordenadas `deployWaves[][]` (dependencias primero) + `rollbackWaves[][]` (inverso).
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/monorepo-graphs.json`.
 */

const MAX_PLANS = 200;
const DEFAULT_ROOT_TRIGGERS = Object.freeze([
  'package.json',
  'package-lock.json',
  'pnpm-lock.yaml',
  'pnpm-workspace.yaml',
  'yarn.lock',
  'turbo.json',
  'nx.json'
]);

/**
 * Resuelve dinámicamente la ruta a `monorepo-graphs.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'monorepo-graphs.json')
    : path.join(base, 'data', 'monorepo-graphs.json');
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
 * Carga planes almacenados desde disco (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, plans: any[] }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), plans: [] };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && Array.isArray(parsed.plans)) {
      return parsed;
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), plans: [] };
}

/**
 * Guarda planes de forma atómica (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, plans: any[] }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  if (store.plans.length > MAX_PLANS) {
    store.plans = store.plans.slice(-MAX_PLANS);
  }
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Normaliza una ruta POSIX relativa sin `./` ni barras sobrantes.
 * @param {string} raw
 */
function normPath(raw) {
  return String(raw || '')
    .replace(/\\/g, '/')
    .replace(/^\.\/+/, '')
    .replace(/^\/+/, '')
    .replace(/\/+$/, '');
}

/**
 * Normaliza descriptores de workspaces.
 * @param {any[]} workspaces
 */
function normalizeWorkspaces(workspaces) {
  return (Array.isArray(workspaces) ? workspaces : [])
    .filter((w) => w && typeof w === 'object' && String(w.name || '').trim())
    .map((w) => ({
      name: String(w.name).trim(),
      dir: normPath(w.dir || w.path || w.name),
      deps: Array.isArray(w.deps)
        ? Array.from(new Set(w.deps.map((d) => String(d || '').trim()).filter(Boolean)))
        : (Array.isArray(w.dependencies) ? Array.from(new Set(w.dependencies.map((d) => String(d || '').trim()).filter(Boolean))) : []),
      watchPaths: Array.isArray(w.watchPaths)
        ? w.watchPaths.map((p) => normPath(p)).filter(Boolean)
        : []
    }));
}

/**
 * Comprueba si `filePath` coincide con un prefijo/patrón `watchPath` (soporta `*` y `**`).
 * @param {string} filePath
 * @param {string} pattern
 */
function matchesWatchPath(filePath, pattern) {
  const f = normPath(filePath);
  const p = normPath(pattern);
  if (!f || !p) return false;
  if (p.includes('*')) {
    const escaped = p
      .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, '.*')
      .replace(/\*/g, '[^/]*');
    return new RegExp(`^${escaped}$`).test(f);
  }
  return f === p || f.startsWith(`${p}/`);
}

/**
 * Detecta ciclos de dependencias en el grafo de workspaces usando el algoritmo de Kahn.
 *
 * @param {any[]} workspaces
 */
function detectWorkspaceCycles(workspaces) {
  const ws = normalizeWorkspaces(workspaces);
  const nameSet = new Set(ws.map((w) => w.name));
  /** @type {Map<string, number>} */
  const inDegree = new Map();
  /** @type {Map<string, string[]>} */
  const dependents = new Map();

  for (const w of ws) {
    inDegree.set(w.name, 0);
    dependents.set(w.name, []);
  }

  for (const w of ws) {
    for (const dep of w.deps) {
      if (!nameSet.has(dep)) continue;
      const list = dependents.get(dep);
      if (list) list.push(w.name);
      inDegree.set(w.name, (inDegree.get(w.name) || 0) + 1);
    }
  }

  /** @type {string[]} */
  const queue = [];
  for (const [name, deg] of inDegree.entries()) {
    if (deg === 0) queue.push(name);
  }

  let visited = 0;
  while (queue.length > 0) {
    const cur = /** @type {string} */ (queue.shift());
    visited++;
    for (const next of (dependents.get(cur) || [])) {
      const nextDeg = (inDegree.get(next) || 0) - 1;
      inDegree.set(next, nextDeg);
      if (nextDeg === 0) queue.push(next);
    }
  }

  const cycleNodes = Array.from(inDegree.entries())
    .filter(([, deg]) => deg > 0)
    .map(([name]) => name)
    .sort();

  const hasCycle = visited < ws.length;
  return {
    ok: true,
    hasCycle,
    code: hasCycle ? 'WORKSPACE_CYCLE_DETECTED' : 'ACYCLIC_DAG',
    cycleNodes
  };
}

/**
 * Mapea `changedFiles[]` a servicios afectados directos + transitivos (`skippedServices[]` ahorrados).
 *
 * @param {{
 *   workspaces?: any[],
 *   changedFiles?: string[],
 *   rootTriggerFiles?: string[]
 * }} [input]
 */
function resolveAffectedServices(input = {}) {
  const opts = input || {};
  const ws = normalizeWorkspaces(opts.workspaces || []);
  const changed = (Array.isArray(opts.changedFiles) ? opts.changedFiles : []).map(normPath).filter(Boolean);
  const rootTriggers = new Set(
    (Array.isArray(opts.rootTriggerFiles) && opts.rootTriggerFiles.length > 0
      ? opts.rootTriggerFiles
      : [...DEFAULT_ROOT_TRIGGERS]
    ).map(normPath)
  );

  const rootTriggered = changed.some((f) => rootTriggers.has(f));

  /** @type {Set<string>} */
  const directSet = new Set();
  if (rootTriggered) {
    for (const w of ws) directSet.add(w.name);
  } else {
    for (const f of changed) {
      for (const w of ws) {
        const hitDir = w.dir && (f === w.dir || f.startsWith(`${w.dir}/`));
        const hitWatch = w.watchPaths.some((wp) => matchesWatchPath(f, wp));
        if (hitDir || hitWatch) directSet.add(w.name);
      }
    }
  }

  // Reverse adjacency map: dep -> [services depending on dep]
  /** @type {Map<string, string[]>} */
  const revAdj = new Map();
  for (const w of ws) {
    for (const dep of w.deps) {
      const list = revAdj.get(dep) || [];
      list.push(w.name);
      revAdj.set(dep, list);
    }
  }

  /** @type {Set<string>} */
  const affectedSet = new Set(directSet);
  const bfsQueue = Array.from(directSet);
  while (bfsQueue.length > 0) {
    const cur = /** @type {string} */ (bfsQueue.shift());
    for (const parent of (revAdj.get(cur) || [])) {
      if (!affectedSet.has(parent)) {
        affectedSet.add(parent);
        bfsQueue.push(parent);
      }
    }
  }

  const directlyAffected = Array.from(directSet).sort();
  const affectedNames = Array.from(affectedSet).sort();
  const transitivelyAffected = affectedNames.filter((n) => !directSet.has(n));
  const skippedServices = ws.map((w) => w.name).filter((n) => !affectedSet.has(n)).sort();

  return {
    ok: true,
    rootTriggered,
    changedFilesCount: changed.length,
    directlyAffected,
    transitivelyAffected,
    affectedNames,
    skippedServices,
    savedBuildsCount: skippedServices.length
  };
}

/**
 * Calcula olas topológicas de despliegue (`deployWaves[][]`) y rollback inverso (`rollbackWaves[][]`)
 * mediante Kahn's algorithm.
 *
 * @param {{ workspaces?: any[], affectedNames?: string[] }} [input]
 */
function computeTopologicalDeployWaves(input = {}) {
  const opts = input || {};
  const allWs = normalizeWorkspaces(opts.workspaces || []);
  const filterSet = Array.isArray(opts.affectedNames)
    ? new Set(opts.affectedNames.map((n) => String(n || '').trim()).filter(Boolean))
    : null;
  const ws = filterSet ? allWs.filter((w) => filterSet.has(w.name)) : allWs;

  const activeNames = new Set(ws.map((w) => w.name));
  /** @type {Map<string, number>} */
  const inDegree = new Map();
  /** @type {Map<string, string[]>} */
  const outgoing = new Map();

  for (const w of ws) {
    inDegree.set(w.name, 0);
    outgoing.set(w.name, []);
  }
  for (const w of ws) {
    for (const dep of w.deps) {
      if (!activeNames.has(dep)) continue;
      const list = outgoing.get(dep);
      if (list) list.push(w.name);
      inDegree.set(w.name, (inDegree.get(w.name) || 0) + 1);
    }
  }

  /** @type {string[][]} */
  const deployWaves = [];
  let processed = 0;

  let frontier = Array.from(inDegree.entries())
    .filter(([, deg]) => deg === 0)
    .map(([name]) => name)
    .sort();

  while (frontier.length > 0) {
    deployWaves.push(frontier);
    processed += frontier.length;
    /** @type {string[]} */
    const nextFrontier = [];
    for (const node of frontier) {
      for (const target of (outgoing.get(node) || [])) {
        const deg = (inDegree.get(target) || 0) - 1;
        inDegree.set(target, deg);
        if (deg === 0) nextFrontier.push(target);
      }
    }
    frontier = nextFrontier.sort();
  }

  if (processed < ws.length) {
    const cycleNodes = Array.from(inDegree.entries())
      .filter(([, deg]) => deg > 0)
      .map(([name]) => name)
      .sort();
    return {
      ok: true,
      hasCycle: true,
      code: 'WORKSPACE_CYCLE_DETECTED',
      cycleNodes,
      deployWaves: /** @type {string[][]} */ ([]),
      rollbackWaves: /** @type {string[][]} */ ([]),
      totalWaves: 0
    };
  }

  const rollbackWaves = [...deployWaves].reverse().map((wave) => [...wave]);
  return {
    ok: true,
    hasCycle: false,
    code: 'VALID_DAG',
    cycleNodes: /** @type {string[]} */ ([]),
    deployWaves,
    rollbackWaves,
    totalWaves: deployWaves.length
  };
}

/**
 * Planifica un rollout selectivo de monorepo (verificando ciclos, calculando afectados y olas,
 * `dryRun: true` por defecto).
 *
 * @param {{
 *   projectId?: string,
 *   workspaces?: any[],
 *   changedFiles?: string[],
 *   rootTriggerFiles?: string[],
 *   dryRun?: boolean
 * }} [input]
 */
function planMonorepoRollout(input = {}) {
  const opts = input || {};
  const projectId = String(opts.projectId || 'default').trim() || 'default';
  const dryRun = opts.dryRun !== undefined ? Boolean(opts.dryRun) : true;
  const workspaces = Array.isArray(opts.workspaces) ? opts.workspaces : [];

  const cycleCheck = detectWorkspaceCycles(workspaces);
  if (cycleCheck.hasCycle) {
    return {
      ok: true,
      projectId,
      safe: false,
      blocked: true,
      dryRun,
      persisted: false,
      code: 'WORKSPACE_CYCLE_DETECTED',
      cycleNodes: cycleCheck.cycleNodes,
      affectedNames: /** @type {string[]} */ ([]),
      skippedServices: /** @type {string[]} */ ([]),
      deployWaves: /** @type {string[][]} */ ([]),
      rollbackWaves: /** @type {string[][]} */ ([]),
      savedBuildsCount: 0,
      plannedAt: new Date().toISOString()
    };
  }

  const affected = resolveAffectedServices({
    workspaces,
    changedFiles: opts.changedFiles,
    rootTriggerFiles: opts.rootTriggerFiles
  });
  const waves = computeTopologicalDeployWaves({
    workspaces,
    affectedNames: affected.affectedNames
  });

  const plannedAt = new Date().toISOString();
  const plan = {
    id: `mono_${crypto.randomBytes(5).toString('hex')}`,
    projectId,
    safe: true,
    blocked: false,
    code: 'ROLLOUT_PLANNED',
    cycleNodes: /** @type {string[]} */ ([]),
    directlyAffected: affected.directlyAffected,
    transitivelyAffected: affected.transitivelyAffected,
    affectedNames: affected.affectedNames,
    skippedServices: affected.skippedServices,
    savedBuildsCount: affected.savedBuildsCount,
    deployWaves: waves.deployWaves,
    rollbackWaves: waves.rollbackWaves,
    totalWaves: waves.totalWaves,
    plannedAt
  };

  if (!dryRun) {
    const store = loadStore();
    store.plans.push(plan);
    saveStore(store);
  }

  return {
    ok: true,
    dryRun,
    persisted: !dryRun,
    ...plan
  };
}

/**
 * Lista planes de despliegue monorepo almacenados (más recientes primero).
 * @param {string} [projectId]
 */
function listMonorepoPlans(projectId) {
  const store = loadStore();
  const cleanId = projectId ? String(projectId).trim() : '';
  const items = cleanId
    ? store.plans.filter((p) => p.projectId === cleanId)
    : store.plans;
  return [...items].reverse();
}

module.exports = {
  resolveAffectedServices,
  computeTopologicalDeployWaves,
  detectWorkspaceCycles,
  planMonorepoRollout,
  listMonorepoPlans
};
