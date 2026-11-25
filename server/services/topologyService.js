/**
 * Visual Service Topology & Dependency Map builder (zero npm deps, zero shell, RBAC-scoped).
 *
 * Correlates live Culkibo state across:
 *   Domains (TLS/Proxy) -> Projects (Prod/Local/Sleeping) -> Managed DBs / Redis / Catalog -> Servers (Local/Fleet)
 *   + Synthetic Uptime Monitors -> Projects / Domains
 *
 * Security invariants:
 *  - Strict RBAC projection via `allowedProjectIds`: non-superadmins only receive nodes and edges
 *    belonging to projects they can read (never cross-team projects, DBs, domains, or monitors).
 *  - Zero credential leakage: inspects project `envVars` strictly to detect references to known
 *    managed database hostnames/container names and emits only the env key name (never values).
 */

const CACHE_ENGINES = new Set(['redis', 'valkey', 'dragonfly', 'memcached']);

/**
 * Safely calls a dependency loader only when available.
 * @param {Record<string, any>} deps
 * @param {string} name
 */
function getDep(deps, name) {
  if (deps && Object.prototype.hasOwnProperty.call(deps, name)) {
    return deps[name];
  }
  try {
    return require(`./${name}`);
  } catch (e) {
    return null;
  }
}

/**
 * Normalizes a service status into a consistent visual health state.
 * @param {string | null | undefined} status
 * @returns {'healthy' | 'degraded' | 'down' | 'sleeping' | 'unknown'}
 */
function normalizeHealth(status) {
  const s = String(status || '').toLowerCase();
  if (['running', 'active', 'activo', 'online', 'up', 'healthy', 'operational'].includes(s)) return 'healthy';
  if (['sleeping', 'hibernated', 'paused'].includes(s)) return 'sleeping';
  if (['degraded', 'warning', 'draining', 'building', 'construyendo', 'restarting'].includes(s)) return 'degraded';
  if (['down', 'error', 'failed', 'offline', 'stopped', 'detenido', 'unhealthy', 'host_key_mismatch'].includes(s)) return 'down';
  return 'unknown';
}

/**
 * Builds the RBAC-filtered visual service topology graph.
 * @param {{
 *   allowedProjectIds?: string[] | null,
 *   isSuperAdmin?: boolean,
 *   deps?: {
 *     projectManager?: any,
 *     databaseManager?: any,
 *     domainManager?: any,
 *     catalogManager?: any,
 *     deployManager?: any,
 *     serverFleetManager?: any,
 *     uptimeMonitor?: any,
 *     sleepAdvisor?: any
 *   }
 * }} [options]
 */
function buildTopology(options = {}) {
  const deps = options.deps || {};
  const isSuperAdmin = options.isSuperAdmin !== false && !Array.isArray(options.allowedProjectIds);
  const allowedSet = Array.isArray(options.allowedProjectIds) ? new Set(options.allowedProjectIds) : null;

  const pm = getDep(deps, 'projectManager');
  const dbm = getDep(deps, 'databaseManager');
  const domm = getDep(deps, 'domainManager');
  const cm = getDep(deps, 'catalogManager');
  const depm = getDep(deps, 'deployManager');
  const fleet = getDep(deps, 'serverFleetManager');
  const um = getDep(deps, 'uptimeMonitor');
  const sa = getDep(deps, 'sleepAdvisor');

  /** @type {Map<string, any>} */
  const nodesMap = new Map();
  /** @type {Array<{ id: string, from: string, to: string, kind: string, label: string, status: string }>} */
  const edges = [];
  const edgeKeys = new Set();

  const addNode = (node) => {
    if (!nodesMap.has(node.id)) nodesMap.set(node.id, node);
  };
  const addEdge = (from, to, kind, label = '', status = 'healthy') => {
    if (!from || !to || from === to) return;
    const key = `${from}|${to}|${kind}|${label}`;
    if (edgeKeys.has(key)) return;
    edgeKeys.add(key);
    edges.push({
      id: `edge_${edges.length + 1}`,
      from,
      to,
      kind,
      label,
      status
    });
  };

  // 1. Collect Servers (local + remote fleet)
  /** @type {Map<string, any>} */
  const serverRecords = new Map();
  serverRecords.set('local', {
    id: 'local',
    name: 'Servidor Local',
    host: 'localhost',
    status: 'online',
    region: 'local'
  });
  if (fleet && typeof fleet.listServers === 'function') {
    try {
      for (const s of fleet.listServers() || []) {
        if (s && s.id) serverRecords.set(s.id, s);
      }
    } catch (e) {}
  }

  // 2. Collect Projects (filtered by RBAC)
  const rawProjects = pm && typeof pm.getAll === 'function' ? (pm.getAll() || []) : [];
  const visibleProjects = allowedSet
    ? rawProjects.filter((p) => p && allowedSet.has(p.id))
    : rawProjects.filter(Boolean);
  const visibleProjectIds = new Set(visibleProjects.map((p) => p.id));
  const usedServerIds = new Set();

  const deployStore = (depm && depm.store && typeof depm.store === 'object') ? depm.store : {};

  for (const proj of visibleProjects) {
    const depState = deployStore[proj.id]?.current || null;
    const isSleeping = Boolean(
      (sa && typeof sa.isSleeping === 'function' && sa.isSleeping(proj.id)) ||
      depState?.status === 'sleeping' ||
      proj.status === 'hibernated' ||
      proj.status === 'sleeping'
    );
    const rawStatus = isSleeping ? 'sleeping' : (depState?.status || proj.status || 'unknown');
    const serverId = proj.serverId || 'local';
    usedServerIds.add(serverId);

    const projNodeId = `project:${proj.id}`;
    addNode({
      id: projNodeId,
      kind: 'project',
      entityId: proj.id,
      label: proj.name || proj.id,
      sublabel: proj.framework || proj.type || (depState ? 'producción' : 'proyecto'),
      status: rawStatus,
      health: depState?.oomKilled ? 'down' : normalizeHealth(rawStatus),
      meta: {
        projectId: proj.id,
        serverId,
        memoryMb: Number(proj.memoryMb) || 512,
        port: depState?.hostPort || proj.port || null,
        oomKilled: Boolean(depState?.oomKilled),
        restartCount: Number(depState?.restartCount || 0),
        sleeping: isSleeping
      }
    });

    const srv = serverRecords.get(serverId) || { id: serverId, name: serverId, status: 'unknown' };
    const srvNodeId = `server:${srv.id}`;
    addNode({
      id: srvNodeId,
      kind: 'server',
      entityId: srv.id,
      label: srv.name || srv.id,
      sublabel: srv.region || (srv.id === 'local' ? 'nodo principal' : 'nodo remoto'),
      status: srv.status || 'online',
      health: normalizeHealth(srv.status || 'online'),
      meta: {
        serverId: srv.id,
        isLocal: srv.id === 'local',
        maintenanceState: srv.maintenanceState || 'active'
      }
    });
    addEdge(projNodeId, srvNodeId, 'runs_on', srv.id === 'local' ? 'local' : 'ssh', normalizeHealth(srv.status || 'online'));
  }

  // Superadmin also sees idle/unused fleet servers on the topology map
  if (isSuperAdmin) {
    for (const srv of serverRecords.values()) {
      const srvNodeId = `server:${srv.id}`;
      addNode({
        id: srvNodeId,
        kind: 'server',
        entityId: srv.id,
        label: srv.name || srv.id,
        sublabel: srv.region || (srv.id === 'local' ? 'nodo principal' : 'nodo remoto'),
        status: srv.status || 'online',
        health: normalizeHealth(srv.status || 'online'),
        meta: {
          serverId: srv.id,
          isLocal: srv.id === 'local',
          maintenanceState: srv.maintenanceState || 'active'
        }
      });
    }
  }

  // 3. Collect Managed Databases & Caches (Redis/Valkey/Dragonfly)
  const rawDbs = dbm && typeof dbm.list === 'function' ? (() => { try { return dbm.list() || []; } catch (e) { return []; } })() : [];
  const visibleDbs = rawDbs.filter((d) => {
    if (!d || !d.id) return false;
    if (isSuperAdmin) return true;
    return Boolean(d.projectId && visibleProjectIds.has(d.projectId));
  });

  /** @type {Array<{ nodeId: string, containerName: string, name: string, engine: string, isCache: boolean, health: string }>} */
  const dbIndex = [];

  for (const db of visibleDbs) {
    const engine = String(db.engine || 'postgres').toLowerCase();
    const isCache = CACHE_ENGINES.has(engine);
    const dbNodeId = `database:${db.id}`;
    const health = normalizeHealth(db.status || 'running');
    addNode({
      id: dbNodeId,
      kind: isCache ? 'cache' : 'database',
      entityId: db.id,
      label: db.name || db.id,
      sublabel: `${engine}${db.version ? ` ${db.version}` : ''}`,
      status: db.status || 'running',
      health,
      meta: {
        databaseId: db.id,
        projectId: db.projectId || null,
        engine,
        memoryMb: Number(db.memoryMb) || 512,
        backupScheduled: Boolean(db.schedule && db.schedule.enabled)
      }
    });

    dbIndex.push({
      nodeId: dbNodeId,
      containerName: String(db.containerName || '').toLowerCase(),
      name: String(db.name || '').toLowerCase(),
      engine,
      isCache,
      health
    });

    if (db.projectId && visibleProjectIds.has(db.projectId)) {
      addEdge(`project:${db.projectId}`, dbNodeId, isCache ? 'uses_cache' : 'uses_database', engine, health);
    }
  }

  // Infer cross-project DB/Redis links via project envVars (key-name only, NEVER expose values!)
  for (const proj of visibleProjects) {
    const envVars = proj.envVars && typeof proj.envVars === 'object' ? proj.envVars : null;
    if (!envVars) continue;
    const projNodeId = `project:${proj.id}`;
    for (const [key, rawVal] of Object.entries(envVars)) {
      if (typeof rawVal !== 'string' || rawVal.length === 0) continue;
      const lowerVal = rawVal.toLowerCase();
      for (const dbInfo of dbIndex) {
        if (dbInfo.containerName && lowerVal.includes(dbInfo.containerName)) {
          addEdge(
            projNodeId,
            dbInfo.nodeId,
            dbInfo.isCache ? 'uses_cache' : 'uses_database',
            `${dbInfo.engine} (${key})`,
            dbInfo.health
          );
        }
      }
    }
  }

  // 4. Collect Catalog Services
  const rawCatalog = cm
    ? (() => {
        try {
          if (typeof cm.listInstallations === 'function') return cm.listInstallations() || [];
          if (typeof cm.list === 'function') return cm.list() || [];
        } catch (e) {}
        return [];
      })()
    : [];
  const visibleCatalog = rawCatalog.filter((inst) => {
    if (!inst || !inst.id) return false;
    if (isSuperAdmin) return true;
    return Boolean(inst.projectId && visibleProjectIds.has(inst.projectId));
  });
  const visibleCatalogIds = new Set(visibleCatalog.map((i) => i.id));

  for (const inst of visibleCatalog) {
    const catNodeId = `catalog:${inst.id}`;
    const health = normalizeHealth(inst.status || 'running');
    addNode({
      id: catNodeId,
      kind: 'catalog',
      entityId: inst.id,
      label: inst.name || inst.templateId || inst.id,
      sublabel: inst.templateId || 'servicio catálogo',
      status: inst.status || 'running',
      health,
      meta: {
        serviceId: inst.id,
        templateId: inst.templateId || null,
        projectId: inst.projectId || null
      }
    });
    if (inst.projectId && visibleProjectIds.has(inst.projectId)) {
      addEdge(`project:${inst.projectId}`, catNodeId, 'uses_service', inst.templateId || 'servicio', health);
    }
  }

  // 5. Collect Domains (linked to projects or catalog services)
  const rawDomains = domm && typeof domm.listDomains === 'function'
    ? (() => { try { return domm.listDomains() || []; } catch (e) { return []; } })()
    : [];
  const visibleDomains = rawDomains.filter((d) => {
    if (!d || !d.hostname) return false;
    if (isSuperAdmin) return true;
    if (d.projectId && visibleProjectIds.has(d.projectId)) return true;
    if (d.serviceId && visibleCatalogIds.has(d.serviceId)) return true;
    return false;
  });

  /** @type {Map<string, string>} */
  const domainNodeByHost = new Map();

  for (const dom of visibleDomains) {
    const domId = `domain:${dom.id || dom.hostname}`;
    const tlsStatus = dom.sslStatus || (dom.tlsEnabled === false ? 'http' : 'tls');
    const health = dom.status === 'disabled' ? 'degraded' : 'healthy';
    addNode({
      id: domId,
      kind: 'domain',
      entityId: dom.id || dom.hostname,
      label: dom.hostname,
      sublabel: dom.cloudflareProxied ? 'Cloudflare Proxy' : (dom.isWildcard ? 'Wildcard TLS' : 'Caddy TLS'),
      status: dom.status || 'active',
      health,
      meta: {
        hostname: dom.hostname,
        isWildcard: Boolean(dom.isWildcard),
        cloudflareProxied: Boolean(dom.cloudflareProxied),
        tlsStatus,
        projectId: dom.projectId || null,
        serviceId: dom.serviceId || null
      }
    });
    domainNodeByHost.set(String(dom.hostname).toLowerCase(), domId);

    if (dom.projectId && visibleProjectIds.has(dom.projectId)) {
      addEdge(domId, `project:${dom.projectId}`, 'routes_to', dom.cloudflareProxied ? 'CF → HTTPS' : 'HTTPS', health);
    } else if (dom.serviceId && visibleCatalogIds.has(dom.serviceId)) {
      addEdge(domId, `catalog:${dom.serviceId}`, 'routes_to', 'HTTPS', health);
    }
  }

  // 6. Collect Synthetic Uptime Monitors
  const rawMonitors = um && typeof um.listMonitors === 'function'
    ? (() => {
        try {
          return um.listMonitors(allowedSet ? { projectIds: Array.from(allowedSet) } : {}) || [];
        } catch (e) {
          return [];
        }
      })()
    : [];

  for (const mon of rawMonitors) {
    if (!mon || !mon.id) continue;
    if (!isSuperAdmin && (!mon.projectId || !visibleProjectIds.has(mon.projectId))) continue;
    const monId = `monitor:${mon.id}`;
    const health = normalizeHealth(mon.status || 'unknown');
    addNode({
      id: monId,
      kind: 'monitor',
      entityId: mon.id,
      label: mon.name,
      sublabel: mon.uptime24h != null ? `${mon.uptime24h}% · ${mon.p50LatencyMs != null ? `${Math.round(mon.p50LatencyMs)}ms` : '—'}` : mon.type,
      status: mon.status || 'unknown',
      health,
      meta: {
        monitorId: mon.id,
        type: mon.type,
        projectId: mon.projectId || null,
        uptime24h: mon.uptime24h ?? null,
        p95LatencyMs: mon.p95LatencyMs ?? null
      }
    });

    if (mon.projectId && visibleProjectIds.has(mon.projectId)) {
      addEdge(monId, `project:${mon.projectId}`, 'monitors', `${mon.intervalSec || 60}s`, health);
    } else if (mon.host && domainNodeByHost.has(String(mon.host).toLowerCase())) {
      addEdge(monId, domainNodeByHost.get(String(mon.host).toLowerCase()), 'monitors', `${mon.intervalSec || 60}s`, health);
    }
  }

  const nodes = Array.from(nodesMap.values());
  const countKind = (k) => nodes.filter((n) => n.kind === k).length;
  const unhealthyNodes = nodes.filter((n) => n.health === 'down' || n.health === 'degraded').length;

  return {
    generatedAt: new Date().toISOString(),
    scoped: !isSuperAdmin,
    nodes,
    edges,
    summary: {
      totalNodes: nodes.length,
      totalEdges: edges.length,
      servers: countKind('server'),
      projects: countKind('project'),
      databases: countKind('database') + countKind('cache'),
      catalogServices: countKind('catalog'),
      domains: countKind('domain'),
      monitors: countKind('monitor'),
      unhealthyNodes
    }
  };
}

module.exports = { buildTopology, normalizeHealth };
