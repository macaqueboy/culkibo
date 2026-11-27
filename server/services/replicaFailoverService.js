const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Blue/Green DB Read-Replica Promotion & Split-Brain Fencing Orchestrator (Zero-Dep).
 *
 * Cura las regresiones reales de bases de datos HA en PaaS/Kubernetes:
 *  - `cloudnative-pg#8701` (promoción de standby rezagado + pérdida WAL en `pg_rewind`)
 *  - `cloudnative-pg#7407` / `#7462` y `patroni#3474` (split-brain por primario sin fencing)
 *  - `dokploy#429` / `#1633` (gestión segura de réplicas de lectura con filtrado por lag)
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/replica-topologies.json`
 * con resolución dinámica de ruta para aislar 100% los tests de `data/` en vivo.
 */

const DEFAULT_MAX_READ_LAG_MS = 500;
const DEFAULT_MAX_ACCEPTABLE_LAG_BYTES = 1048576; // 1 MiB

/**
 * @typedef {object} ReplicaNode
 * @property {string} id
 * @property {string} host
 * @property {number} port
 * @property {string} role
 * @property {number} timeline
 * @property {number} lagBytes
 * @property {number} lagMs
 * @property {boolean} healthy
 * @property {boolean} fenced
 * @property {string} syncState
 */

/**
 * @typedef {object} ReplicaTopologyRecord
 * @property {string} dbId
 * @property {ReplicaNode} primary
 * @property {ReplicaNode[]} replicas
 * @property {string} updatedAt
 */

/**
 * Resuelve dinámicamente la ruta al store `replica-topologies.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'replica-topologies.json')
    : path.join(base, 'data', 'replica-topologies.json');
}

/**
 * Escritura atómica con permisos estrictos `0o600`.
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
 * @param {string} code
 * @param {string} msg
 * @param {number} [status]
 */
function failoverError(code, msg, status = 400) {
  const err = /** @type {any} */ (new Error(msg));
  err.code = code;
  err.status = status;
  return err;
}

/**
 * Carga el mapa completo de topologías desde disco (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, topologies: Record<string, ReplicaTopologyRecord> }}
 */
function loadStore() {
  const storePath = resolveStorePath();
  if (!fs.existsSync(storePath)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), topologies: {} };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(storePath, 'utf8'));
    if (parsed && parsed.topologies && typeof parsed.topologies === 'object') {
      return parsed;
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), topologies: {} };
}

/**
 * Persiste el mapa completo de topologías de forma atómica (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, topologies: Record<string, ReplicaTopologyRecord> }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Normaliza un nodo primario o réplica.
 * @param {any} raw
 * @param {'primary' | 'replica'} defaultRole
 * @param {number} fallbackTimeline
 * @returns {ReplicaNode}
 */
function normalizeNode(raw, defaultRole, fallbackTimeline = 1) {
  const node = (raw && typeof raw === 'object') ? raw : {};
  const id = String(node.id || '').trim();
  if (!id) {
    throw failoverError('INVALID_NODE_ID', `Each ${defaultRole} node requires a non-empty id.`, 400);
  }
  const host = String(node.host || `${id}.internal`).trim();
  const port = Number(node.port) > 0 ? Math.floor(Number(node.port)) : 5432;
  const timeline = Number(node.timeline) > 0 ? Math.floor(Number(node.timeline)) : fallbackTimeline;
  return {
    id,
    host,
    port,
    role: defaultRole,
    timeline,
    lagBytes: defaultRole === 'primary' ? 0 : Math.max(0, Number(node.lagBytes) || 0),
    lagMs: defaultRole === 'primary' ? 0 : Math.max(0, Number(node.lagMs) || 0),
    healthy: node.healthy !== undefined ? Boolean(node.healthy) : true,
    fenced: Boolean(node.fenced),
    syncState: String(node.syncState || (defaultRole === 'primary' ? 'primary' : 'async'))
  };
}

/**
 * Guarda o actualiza la topología primario + réplicas de una base de datos.
 *
 * @param {string} dbId
 * @param {{ primary: any, replicas?: any[] }} input
 */
function saveTopology(dbId, input) {
  const cleanId = String(dbId || '').trim();
  if (!cleanId) {
    throw failoverError('INVALID_DB_ID', 'dbId is required to save replica topology.', 400);
  }
  if (!input || typeof input !== 'object' || !input.primary || typeof input.primary !== 'object') {
    throw failoverError('INVALID_TOPOLOGY', 'primary node configuration is required.', 400);
  }

  const primary = normalizeNode(input.primary, 'primary', 1);
  const rawReplicas = Array.isArray(input.replicas) ? input.replicas : [];
  const replicas = rawReplicas.map((r) => normalizeNode(r, 'replica', primary.timeline));

  const record = {
    dbId: cleanId,
    primary,
    replicas,
    updatedAt: new Date().toISOString()
  };

  const store = loadStore();
  store.topologies[cleanId] = record;
  saveStore(store);

  return {
    ok: true,
    dbId: cleanId,
    primary: record.primary,
    replicas: record.replicas,
    updatedAt: record.updatedAt
  };
}

/**
 * Obtiene la topología guardada para `dbId` (o `null` si no existe).
 * @param {string} dbId
 * @returns {ReplicaTopologyRecord | null}
 */
function getTopology(dbId) {
  const cleanId = String(dbId || '').trim();
  if (!cleanId) return null;
  const store = loadStore();
  return store.topologies[cleanId] || null;
}

/**
 * Evalúa el enrutamiento Lectura/Escritura filtrando réplicas no sanas o con lag
 * superior a `maxReadLagMs`, haciendo fallback seguro al primario si 0 réplicas son válidas.
 *
 * @param {string} dbId
 * @param {{ maxReadLagMs?: number }} [options]
 */
function evaluateReadWriteSplit(dbId, options = {}) {
  const cleanId = String(dbId || '').trim();
  const topology = getTopology(cleanId);
  if (!topology) {
    throw failoverError('TOPOLOGY_NOT_FOUND', `Replica topology not found for database "${cleanId}".`, 404);
  }

  const maxReadLagMs = Number(options && options.maxReadLagMs) >= 0
    ? Number(options.maxReadLagMs)
    : DEFAULT_MAX_READ_LAG_MS;

  const writeTarget = {
    id: topology.primary.id,
    host: topology.primary.host,
    port: topology.primary.port,
    role: 'primary',
    timeline: topology.primary.timeline,
    healthy: topology.primary.healthy,
    fenced: topology.primary.fenced
  };

  /** @type {Array<ReplicaNode>} */
  const eligibleReplicas = [];
  /** @type {Array<ReplicaNode & { reason: string }>} */
  const excludedLagging = [];

  for (const rep of topology.replicas) {
    if (!rep.healthy) {
      excludedLagging.push({ ...rep, reason: 'REPLICA_UNHEALTHY' });
    } else if (rep.lagMs > maxReadLagMs) {
      excludedLagging.push({ ...rep, reason: 'READ_LAG_EXCEEDED' });
    } else {
      eligibleReplicas.push({ ...rep });
    }
  }

  const fallbackToPrimary = eligibleReplicas.length === 0;
  const readTargets = fallbackToPrimary ? [writeTarget] : eligibleReplicas;

  return {
    ok: true,
    dbId: cleanId,
    maxReadLagMs,
    writeTarget,
    readTargets,
    excludedLagging,
    fallbackToPrimary
  };
}

/**
 * Planifica (y opcionalmente ejecuta cuando `dryRun === false`) la promoción Blue/Green
 * de una réplica de lectura a primario, imponiendo guardrails anti-pérdida WAL y anti-split-brain.
 *
 * @param {string} dbId
 * @param {{
 *   targetReplicaId?: string,
 *   maxAcceptableLagBytes?: number,
 *   requireOldPrimaryFenced?: boolean,
 *   dryRun?: boolean
 * }} [options]
 */
function planReplicaPromotion(dbId, options = {}) {
  const cleanId = String(dbId || '').trim();
  const topology = getTopology(cleanId);
  if (!topology) {
    throw failoverError('TOPOLOGY_NOT_FOUND', `Replica topology not found for database "${cleanId}".`, 404);
  }

  const maxAcceptableLagBytes = options && options.maxAcceptableLagBytes !== undefined
    ? Math.max(0, Number(options.maxAcceptableLagBytes) || 0)
    : DEFAULT_MAX_ACCEPTABLE_LAG_BYTES;
  const requireOldPrimaryFenced = options && options.requireOldPrimaryFenced !== undefined
    ? Boolean(options.requireOldPrimaryFenced)
    : true;
  const dryRun = options && options.dryRun !== undefined ? Boolean(options.dryRun) : true;
  const requestedId = options && options.targetReplicaId ? String(options.targetReplicaId).trim() : '';

  let target = requestedId
    ? topology.replicas.find((r) => r.id === requestedId) || null
    : null;

  if (!target && !requestedId && topology.replicas.length > 0) {
    const sorted = [...topology.replicas].sort((a, b) => {
      if (a.healthy !== b.healthy) return a.healthy ? -1 : 1;
      return a.lagBytes - b.lagBytes;
    });
    target = sorted[0];
  }

  /** @type {Array<{ code: string, message: string, details?: Record<string, any> }>} */
  const blockers = [];
  const baseTimeline = Math.max(
    Number(topology.primary.timeline) || 1,
    target ? (Number(target.timeline) || 1) : 1
  );
  const timelineNext = baseTimeline + 1;

  if (!target) {
    blockers.push({
      code: 'TARGET_REPLICA_NOT_FOUND',
      message: requestedId
        ? `Target replica "${requestedId}" does not exist in topology "${cleanId}".`
        : `No standby replicas registered in topology "${cleanId}".`
    });
  } else {
    if (!target.healthy) {
      blockers.push({
        code: 'TARGET_REPLICA_UNHEALTHY',
        message: `Standby replica "${target.id}" is unhealthy and cannot safely assume primary role.`
      });
    }
    if (target.lagBytes > maxAcceptableLagBytes) {
      blockers.push({
        code: 'REPLICA_LAG_TOO_HIGH',
        message: `Standby "${target.id}" replication lag (${target.lagBytes} B) exceeds maxAcceptableLagBytes (${maxAcceptableLagBytes} B) — promoting now risks WAL loss / pg_rewind divergence (cloudnative-pg#8701).`,
        details: { lagBytes: target.lagBytes, maxAcceptableLagBytes }
      });
    }
  }

  if (requireOldPrimaryFenced && !topology.primary.fenced) {
    blockers.push({
      code: 'OLD_PRIMARY_NOT_FENCED',
      message: `Old primary "${topology.primary.id}" is NOT fenced — promoting standby risks dual-write split-brain (cloudnative-pg#7407 / patroni#3474).`,
      details: { primaryId: topology.primary.id, fenced: false }
    });
  }

  const allowed = blockers.length === 0 && target !== null;

  /** @type {Array<{ order: number, phase: 'drain' | 'fence' | 'promote' | 're-route', target: string, action: string }>} */
  const steps = allowed && target
    ? [
        {
          order: 1,
          phase: 'drain',
          target: topology.primary.id,
          action: `Drain active write/read pools targeting "${topology.primary.host}:${topology.primary.port}" (PgBouncer PAUSE / app graceful drain).`
        },
        {
          order: 2,
          phase: 'fence',
          target: topology.primary.id,
          action: `Verify STONITH / read-only fence on old primary "${topology.primary.id}" so zero post-cutover writes can commit.`
        },
        {
          order: 3,
          phase: 'promote',
          target: target.id,
          action: `Promote standby "${target.id}" (${target.host}:${target.port}) to read-write primary on timeline ${timelineNext}.`
        },
        {
          order: 4,
          phase: 're-route',
          target: target.id,
          action: `Re-route write endpoint to "${target.host}:${target.port}" and repoint remaining standbys to follow timeline ${timelineNext}.`
        }
      ]
    : [];

  /** @type {ReplicaNode | null} */
  const promotedNode = allowed && target
    ? {
        ...target,
        role: 'primary',
        timeline: timelineNext,
        lagBytes: 0,
        lagMs: 0,
        fenced: false,
        syncState: 'primary'
      }
    : null;

  // Commit live topology transition when allowed and dryRun === false
  if (allowed && !dryRun && promotedNode && target) {
    const demotedPrimary = {
      ...topology.primary,
      role: 'replica',
      fenced: true,
      healthy: false,
      syncState: 'demoted'
    };
    const remainingReplicas = topology.replicas
      .filter((r) => r.id !== target.id)
      .map((r) => ({ ...r }));
    remainingReplicas.push(demotedPrimary);

    const store = loadStore();
    store.topologies[cleanId] = {
      dbId: cleanId,
      primary: promotedNode,
      replicas: remainingReplicas,
      updatedAt: new Date().toISOString()
    };
    saveStore(store);
  }

  return {
    ok: true,
    dbId: cleanId,
    allowed,
    blockers,
    steps,
    promotedNode,
    timelineNext,
    dryRun
  };
}

module.exports = {
  saveTopology,
  getTopology,
  evaluateReadWriteSplit,
  planReplicaPromotion
};
