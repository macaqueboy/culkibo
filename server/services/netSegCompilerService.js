const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Container Network Micro-Segmentation & Lateral-Movement Policy Compiler (Zero-Dep).
 *
 * Contramedida directa a `Dokploy/dokploy#2798` (red plana compartida `dokploy-network`
 * exponiendo bases de datos a frontends comprometidos) y `Dokploy/dokploy#2987`
 * (aislamiento ingenuo rompiendo conectividad API → DB):
 *  - Audita grafos de red Docker/Compose detectando `LATERAL_DB_EXPOSURE` y `UNISOLATED_DATA_TIER`.
 *  - Compila topologías de mínimo privilegio: `edge_ingress` (solo proxy/frontend),
 *    `app_internal` (`internal: true`) y puentes dedicados `data_<db>` (`internal: true`)
 *    accesibles ÚNICAMENTE por APIs/workers autorizados (0 rutas directas frontend → DB).
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/network-segmentation.json`.
 */

const DATA_TIERS = new Set(['database', 'cache', 'db', 'datastore']);
const INGRESS_TIERS = new Set(['ingress', 'frontend', 'public', 'proxy', 'edge']);

/**
 * Resuelve dinámicamente la ruta a `network-segmentation.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'network-segmentation.json')
    : path.join(base, 'data', 'network-segmentation.json');
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
 * Carga políticas almacenadas desde disco (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, policies: Record<string, any> }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), policies: {} };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && parsed.policies && typeof parsed.policies === 'object') {
      return parsed;
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), policies: {} };
}

/**
 * Guarda políticas de forma atómica (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, policies: Record<string, any> }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Infiere el tier de seguridad de un servicio si no viene explícito.
 * @param {any} svc
 */
function inferServiceTier(svc) {
  const explicit = String(svc.tier || svc.role || '').trim().toLowerCase();
  if (explicit) return explicit;
  const name = String(svc.name || svc.id || '').toLowerCase();
  if (/(?:postgres|pg|mysql|mariadb|mongo|clickhouse|sqlite|db)/.test(name)) return 'database';
  if (/(?:redis|keydb|dragonfly|memcached|valkey|cache)/.test(name)) return 'cache';
  if (/(?:web|frontend|ui|client|caddy|nginx|traefik|proxy|ingress)/.test(name) || svc.public === true) return 'frontend';
  if (/(?:worker|cron|queue|scheduler|consumer)/.test(name)) return 'worker';
  return 'api';
}

/**
 * Normaliza un descriptor de servicio.
 * @param {any} raw
 * @param {string} [defaultNet]
 */
function normalizeService(raw, defaultNet = '') {
  if (typeof raw === 'string') {
    const name = raw.trim();
    return {
      name,
      tier: inferServiceTier({ name }),
      public: INGRESS_TIERS.has(inferServiceTier({ name })),
      networks: defaultNet ? [defaultNet] : []
    };
  }
  const obj = (raw && typeof raw === 'object') ? raw : {};
  const name = String(obj.name || obj.id || '').trim();
  const tier = inferServiceTier(obj);
  const nets = Array.isArray(obj.networks)
    ? obj.networks.map((n) => String(n || '').trim()).filter(Boolean)
    : (defaultNet ? [defaultNet] : []);
  return {
    name,
    tier,
    public: obj.public !== undefined ? Boolean(obj.public) : INGRESS_TIERS.has(tier),
    networks: nets
  };
}

/**
 * Audita un grafo de red Docker/Compose para detectar exposición lateral hacia bases de datos/cachés.
 *
 * @param {{
 *   services?: any[],
 *   networks?: Record<string, { internal?: boolean, external?: boolean }>,
 *   sharedNetworkName?: string
 * }} [input]
 */
function auditLateralMovement(input = {}) {
  const opts = input || {};
  const sharedNetworkName = String(opts.sharedNetworkName || 'dokploy-network').trim();
  const networkDefs = (opts.networks && typeof opts.networks === 'object') ? opts.networks : {};
  const services = (Array.isArray(opts.services) ? opts.services : [])
    .map((s) => normalizeService(s, sharedNetworkName))
    .filter((s) => s.name);

  /** @type {Map<string, Array<ReturnType<typeof normalizeService>>>} */
  const membersByNet = new Map();
  for (const svc of services) {
    for (const net of svc.networks) {
      const list = membersByNet.get(net) || [];
      list.push(svc);
      membersByNet.set(net, list);
    }
  }

  /** @type {Array<{ code: string, severity: 'critical' | 'high', network: string, service: string, peer?: string, message: string, fix: string }>} */
  const violations = [];

  for (const [netName, members] of membersByNet.entries()) {
    const netMeta = networkDefs[netName] || {};
    const isInternal = Boolean(netMeta.internal);
    const dataMembers = members.filter((m) => DATA_TIERS.has(m.tier));
    const publicMembers = members.filter((m) => m.public || INGRESS_TIERS.has(m.tier));

    // 1. LATERAL_DB_EXPOSURE: public/frontend service shares bridge with database/cache
    for (const dbSvc of dataMembers) {
      for (const pubSvc of publicMembers) {
        if (dbSvc.name === pubSvc.name) continue;
        violations.push({
          code: 'LATERAL_DB_EXPOSURE',
          severity: 'critical',
          network: netName,
          service: dbSvc.name,
          peer: pubSvc.name,
          message: `Public/frontend container "${pubSvc.name}" shares flat bridge "${netName}" with data-tier service "${dbSvc.name}" (Dokploy#2798 lateral movement risk).`,
          fix: `Move "${dbSvc.name}" onto an isolated internal: true bridge (data_${dbSvc.name}) attached only to authorized API/worker services.`
        });
      }

      // 2. UNISOLATED_DATA_TIER: database/cache attached to a non-internal / shared proxy bridge
      if (!isInternal || netName === sharedNetworkName) {
        violations.push({
          code: 'UNISOLATED_DATA_TIER',
          severity: 'high',
          network: netName,
          service: dbSvc.name,
          message: `Data-tier service "${dbSvc.name}" is attached to non-internal bridge "${netName}" (lacks internal: true isolation).`,
          fix: `Set internal: true on dedicated data network data_${dbSvc.name} and detach "${dbSvc.name}" from "${netName}".`
        });
      }
    }
  }

  return {
    ok: true,
    safe: violations.length === 0,
    sharedNetworkName,
    servicesAudited: services.length,
    violations,
    findings: violations,
    summary: violations.length === 0
      ? 'Zero lateral-movement exposures detected; data tiers are properly isolated.'
      : `Detected ${violations.length} network segmentation violation(s) across ${services.length} services.`
  };
}

/**
 * Renderiza la sección `services` + `networks` de Docker Compose con `internal: true`.
 *
 * @param {{ networks: Record<string, { driver?: string, internal: boolean, members?: string[] }>, serviceNetworks: Record<string, string[]> }} policy
 * @returns {string}
 */
function renderComposeNetworks(policy) {
  const p = policy || { networks: {}, serviceNetworks: {} };
  const lines = ['services:'];
  for (const [svcName, nets] of Object.entries(p.serviceNetworks || {})) {
    lines.push(`  ${svcName}:`);
    lines.push('    networks:');
    for (const n of (Array.isArray(nets) ? nets : [])) {
      lines.push(`      - ${n}`);
    }
  }
  lines.push('', 'networks:');
  for (const [netName, def] of Object.entries(p.networks || {})) {
    lines.push(`  ${netName}:`);
    lines.push(`    driver: ${(def && def.driver) || 'bridge'}`);
    lines.push(`    internal: ${Boolean(def && def.internal)}`);
  }
  return lines.join('\n');
}

/**
 * Compila una política de micro-segmentación de mínimo privilegio (`edge_ingress`,
 * `app_internal` `internal: true`, y `data_<db>` `internal: true`).
 *
 * @param {{
 *   projectId?: string,
 *   services?: any[],
 *   allowedEdges?: Array<{ from: string, to: string } | string>,
 *   ingressServices?: string[],
 *   persist?: boolean
 * }} [input]
 */
function compileSegmentationPolicy(input = {}) {
  const opts = input || {};
  const projectId = String(opts.projectId || 'default').trim() || 'default';
  const services = (Array.isArray(opts.services) ? opts.services : [])
    .map((s) => normalizeService(s))
    .filter((s) => s.name);

  const explicitIngress = new Set(
    (Array.isArray(opts.ingressServices) ? opts.ingressServices : []).map((s) => String(s || '').trim())
  );
  const ingressSet = new Set(
    services
      .filter((s) => explicitIngress.has(s.name) || (explicitIngress.size === 0 && (s.public || INGRESS_TIERS.has(s.tier))))
      .map((s) => s.name)
  );

  /** @type {Array<{ from: string, to: string }>} */
  const edges = [];
  for (const rawEdge of (Array.isArray(opts.allowedEdges) ? opts.allowedEdges : [])) {
    if (typeof rawEdge === 'string' && rawEdge.includes('->')) {
      const [from, to] = rawEdge.split('->').map((x) => x.trim());
      if (from && to) edges.push({ from, to });
    } else if (rawEdge && typeof rawEdge === 'object' && rawEdge.from && rawEdge.to) {
      edges.push({ from: String(rawEdge.from).trim(), to: String(rawEdge.to).trim() });
    }
  }

  /** @type {Record<string, { driver: string, internal: boolean, members: string[] }>} */
  const networks = {
    edge_ingress: { driver: 'bridge', internal: false, members: [] },
    app_internal: { driver: 'bridge', internal: true, members: [] }
  };

  /** @type {Record<string, Set<string>>} */
  const svcNetSets = {};
  for (const s of services) svcNetSets[s.name] = new Set();

  const dataServices = services.filter((s) => DATA_TIERS.has(s.tier));
  const backendServices = services.filter((s) => !DATA_TIERS.has(s.tier) && !ingressSet.has(s.name));

  // 1. Attach ingress/frontend services to edge_ingress + app_internal
  for (const s of services) {
    if (ingressSet.has(s.name)) {
      networks.edge_ingress.members.push(s.name);
      svcNetSets[s.name].add('edge_ingress');
      if (backendServices.length > 0) {
        networks.app_internal.members.push(s.name);
        svcNetSets[s.name].add('app_internal');
      }
    }
  }

  // 2. Attach non-data backend (api/worker) services to app_internal
  for (const b of backendServices) {
    networks.app_internal.members.push(b.name);
    svcNetSets[b.name].add('app_internal');
  }

  // 3. Dedicated per-DB internal: true bridge `data_<db>` reachable ONLY by authorized non-ingress backends
  for (const db of dataServices) {
    const slug = db.name.toLowerCase().replace(/[^a-z0-9_]+/g, '_');
    const netName = `data_${slug}`;
    /** @type {Set<string>} */
    const members = new Set([db.name]);
    svcNetSets[db.name].add(netName);

    const explicitCallers = edges
      .filter((e) => e.to === db.name && !ingressSet.has(e.from))
      .map((e) => e.from);

    const authorizedCallers = explicitCallers.length > 0
      ? explicitCallers
      : backendServices.map((b) => b.name);

    for (const caller of authorizedCallers) {
      if (!svcNetSets[caller] || ingressSet.has(caller)) continue;
      members.add(caller);
      svcNetSets[caller].add(netName);
    }

    networks[netName] = {
      driver: 'bridge',
      internal: true,
      members: Array.from(members)
    };
  }

  /** @type {Record<string, string[]>} */
  const serviceNetworks = {};
  for (const [k, setVal] of Object.entries(svcNetSets)) {
    serviceNetworks[k] = Array.from(setVal);
  }

  // Mathematical verification: zero ingress service shares any network with any data service
  let frontendToDbIsolated = true;
  for (const db of dataServices) {
    const dbNets = svcNetSets[db.name] || new Set();
    for (const ing of ingressSet) {
      const ingNets = svcNetSets[ing] || new Set();
      for (const n of dbNets) {
        if (ingNets.has(n)) {
          frontendToDbIsolated = false;
          break;
        }
      }
    }
  }

  const composeYaml = renderComposeNetworks({ networks, serviceNetworks });
  const createdAt = new Date().toISOString();

  const policyRecord = {
    projectId,
    networks,
    serviceNetworks,
    frontendToDbIsolated,
    composeYaml,
    createdAt
  };

  if (opts.persist === true) {
    const store = loadStore();
    store.policies[projectId] = policyRecord;
    saveStore(store);
  }

  return {
    ok: true,
    ...policyRecord
  };
}

/**
 * Lista las políticas de micro-segmentación almacenadas.
 * @param {string} [projectId]
 */
function listSegmentationPolicies(projectId) {
  const store = loadStore();
  const cleanId = projectId ? String(projectId).trim() : '';
  if (cleanId) {
    return store.policies[cleanId] ? [store.policies[cleanId]] : [];
  }
  return Object.values(store.policies);
}

module.exports = {
  auditLateralMovement,
  compileSegmentationPolicy,
  renderComposeNetworks,
  listSegmentationPolicies
};
