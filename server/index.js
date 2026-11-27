const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');
const crypto = require('crypto');
const { performance } = require('perf_hooks');

const BOOT_START_MS = performance.now();

// Carga nativa de .env (C++ en Node >= 20.12) sin pagar el arranque de dotenv (~23 ms / 1.1 MB RSS).
(function loadEnvFast() {
  const envPath = path.join(__dirname, '..', '.env');
  if (!fs.existsSync(envPath)) return;
  try {
    if (typeof process.loadEnvFile === 'function') {
      process.loadEnvFile(envPath);
      return;
    }
  } catch (e) {}
  try { require('dotenv').config({ path: envPath }); } catch (e) {}
})();

const containerOrchestrator = require('./services/containerOrchestrator');
const projectManager = require('./services/projectManager');
const metricsCollector = require('./services/metricsCollector');
const auditLogger = require('./services/auditLogger');
const telemetryService = require('./services/telemetryService');
const {
  authMiddleware,
  authorizeRequest,
  extractCredentials,
  corsDelegate,
  resolveToken,
  onTokenRotated,
  onPrincipalRevoked,
  authStatus,
  isLoopback,
  isPrivateProxyPeer,
  isOriginAllowed,
  addAllowedOrigin,
  clientIp,
  checkAuthBruteForce,
  recordAuthFailure
} = require('./middleware/auth');
const { createRateLimiter } = require('./services/rateLimiter');

const PORT = Number(process.env.PORT) || 3030;
const APP_VERSION = String((() => {
  try { return require('../package.json').version; } catch (e) { return '1.2.0'; }
})() || '1.2.0');
const MCP_PROTOCOL_VERSION = '2026-07-28';
const MCP_LEGACY_PROTOCOL_VERSION = '2024-11-05';
const ROOT_BASE_DIR = process.env.CULKIBO_DATA_DIR
  ? path.resolve(process.env.CULKIBO_DATA_DIR)
  : path.resolve(__dirname, '..');
const DATA_DIR = path.join(ROOT_BASE_DIR, 'data');
const INGRESS_CONFIG_FILE = path.join(DATA_DIR, 'ingress.json');

const fastProjectsLimiter = createRateLimiter({
  windowMs: 60000,
  max: 60,
  bypassLoopback: true,
  label: 'fast_projects_create',
  onLimit: () => metricsCollector.recordSecurityEvent('rateLimited429')
});
const fastAskLimiter = createRateLimiter({
  windowMs: 60000,
  max: 240,
  bypassLoopback: false,
  label: 'ingress_ask',
  onLimit: () => metricsCollector.recordSecurityEvent('rateLimited429')
});

// ---------------------------------------------------------------------------
// Global crash barrier + circuit-breaker (evita estados zombi/deadlock en VPS).
// ---------------------------------------------------------------------------
/** @type {number[]} */
const recentFatalTimestamps = [];
function reportFatal(kind, err) {
  const detail = err && err.stack ? err.stack : String(err);
  console.error(`[Culkibo:${kind}]`, detail);
  try {
    containerOrchestrator.addLog('ERROR', 'edge', `[Daemon:${kind}] ${err && err.message ? err.message : String(err)}`);
  } catch (e) {}
  try {
    telemetryService.captureCrash(kind, err);
  } catch (e) {}
  if (kind === 'uncaughtException' && require.main === module) {
    const now = Date.now();
    recentFatalTimestamps.push(now);
    while (recentFatalTimestamps.length > 0 && now - recentFatalTimestamps[0] > 10000) {
      recentFatalTimestamps.shift();
    }
    if (recentFatalTimestamps.length >= 3) {
      console.error('[Culkibo] Múltiples excepciones fatales en 10 s; iniciando cierre ordenado para reinicio limpio.');
      shutdown('uncaughtException').finally(() => process.exit(1));
    }
  }
}

process.on('uncaughtException', (err) => reportFatal('uncaughtException', err));
process.on('unhandledRejection', (reason) => reportFatal('unhandledRejection', reason));

// ---------------------------------------------------------------------------
// Registro perezoso de servicios (arranque en frío ~150-210 ms, <60 MB RSS)
// Cada servicio se carga solo cuando alguien lo invoca, conectando sus eventos
// al broadcast WebSocket una única vez.
// ---------------------------------------------------------------------------
/** @type {Record<string, any>} */
const loadedServices = Object.create(null);

function getService(name) {
  if (loadedServices[name]) return loadedServices[name];
  let svc;
  switch (name) {
    case 'domainManager':
      svc = require('./services/domainManager');
      break;
    case 'catalogManager':
      svc = require('./services/catalogManager');
      svc.on('service_progress', (data) => broadcast('service_progress', data));
      svc.on('service_installed', (data) => broadcast('service_installed', data));
      svc.on('service_failed', (data) => broadcast('service_failed', data));
      svc.on('service_removed', (data) => broadcast('service_removed', data));
      break;
    case 'databaseManager':
      svc = require('./services/databaseManager');
      svc.on('backup_completed', (data) => broadcast('backup_completed', data));
      svc.on('backup_failed', (data) => broadcast('backup_failed', data));
      svc.on('database_created', (data) => broadcast('database_created', data));
      svc.on('database_deleted', (data) => broadcast('database_deleted', data));
      break;
    case 'deployManager':
      svc = require('./services/deployManager');
      svc.on('deploy_event', (data) => {
        broadcast('deploy_event', data);
        if (data && (data.phase === 'cutover_done' || data.phase === 'rollback_done')) {
          try { metricsCollector.recordDeployMarker(data); } catch (e) {}
        }
      });
      svc.on('deploy_log', (data) => broadcast('deploy_log', data));
      break;
    case 'ingressManager':
      svc = require('./services/ingressManager');
      break;
    case 'caddyManager':
      svc = require('./services/caddyManager');
      break;
    case 'localRunner':
      svc = require('./services/localRunner');
      containerOrchestrator.registerLocalRunner(svc);
      break;
    case 'mcpServer':
      svc = require('./services/mcpServer');
      if (typeof svc.setMaxListeners === 'function') {
        svc.setMaxListeners(MAX_LOG_STREAMS_GLOBAL + 10);
      }
      svc.on('mcp_call', (data) => broadcast('mcp_call', data));
      break;
    case 'mcpStreamableHttp':
      svc = require('./services/mcpStreamableHttp');
      break;
    case 'liveSyncEngine':
      svc = require('./services/liveSyncEngine');
      svc.on('sync_applied', (data) => {
        broadcast('sync_applied', data);
        if (containerOrchestrator.pods && containerOrchestrator.pods.forge) {
          containerOrchestrator.pods.forge.hotReloadsCount = (containerOrchestrator.pods.forge.hotReloadsCount || 0) + 1;
          containerOrchestrator.pods.forge.lastHotReloadMs = Number(data.applyMs || 0);
        }
        containerOrchestrator.addLog(
          'HOT_SYNC',
          'forge',
          `[Forge:LiveSync] Frame #${data.seq} (${data.written} escritos, ${data.deleted} borrados, ${data.dedupSkipped} sin cambios) aplicado en ${data.applyMs}ms [${data.mode}]`,
          new Date(),
          data.projectId
        );
        // Auto-reiniciar localRunner en Path C (package.json / .env / next.config / vite.config)
        // o promocionar un fallback placeholder cuando llegan los primeros archivos del proyecto.
        if (data.projectId && (data.mode === 'path_c_restart' || data.written > 0)) {
          try {
            const lr = loadedServices.localRunner || containerOrchestrator._localRunner;
            if (lr && typeof lr.onLiveSyncApplied === 'function') {
              lr.onLiveSyncApplied(data);
            }
          } catch (e) {}
        }
      });
      svc.on('sync_rollback', (data) => {
        broadcast('sync_rollback', data);
        // Notificar también a los clientes CLI conectados a `/ws/sync` para invalidar su hash cache
        for (const ws of syncClients) {
          if (ws.readyState === 1 && /** @type {any} */ (ws)._projectId === data.projectId) {
            safeWsSend(ws, { type: 'rollback_notice', ...data });
          }
        }
        containerOrchestrator.addLog(
          'INFO',
          'forge',
          `[Forge:Rollback] Revertidos ${data.restoredFiles.length} fichero(s) en ${data.durationMs}ms`,
          new Date(),
          data.projectId
        );
      });
      svc.on('sync_conflict', (conflict) => {
        broadcast('sync_conflict', conflict);
        for (const ws of syncClients) {
          if (ws.readyState === 1 && /** @type {any} */ (ws)._projectId === conflict.projectId) {
            safeWsSend(ws, { type: 'conflict_notice', ...conflict });
          }
        }
      });
      break;
    case 'cronManager':
      svc = require('./services/cronManager');
      svc.on('cron_run', (data) => broadcast('cron_run', data));
      break;
    case 'previewManager':
      svc = require('./services/previewManager');
      svc.on('preview_event', (data) => broadcast('preview_event', data));
      break;
    case 'serverFleetManager':
      svc = require('./services/serverFleetManager');
      break;
    case 'teamManager':
      svc = require('./services/teamManager');
      break;
    case 'environmentManager':
      svc = require('./services/environmentManager');
      break;
    case 'gitopsManager':
      svc = require('./services/gitopsManager');
      break;
    case 'uptimeMonitor':
      svc = require('./services/uptimeMonitor');
      break;
    case 'sleepAdvisor':
      svc = require('./services/sleepAdvisor');
      break;
    case 'metricsHistory':
      svc = require('./services/metricsHistory');
      break;
    case 'alertEngine':
      svc = require('./services/alertEngine');
      svc.on('alert_fired', (data) => broadcast('alert_fired', data));
      svc.on('alert_resolved', (data) => broadcast('alert_resolved', data));
      break;
    case 'topologyService':
      svc = require('./services/topologyService');
      break;
    case 'oidcService':
      svc = require('./services/oidcService');
      break;
    case 'secretScanner':
      svc = require('./services/secretScanner');
      break;
    default:
      throw new Error(`Servicio desconocido: ${name}`);
  }
  loadedServices[name] = svc;
  return svc;
}

// ---------------------------------------------------------------------------
// Cabeceras HTTP de seguridad (CSP, HSTS, Clickjacking, Referrer, No-Store)
// ---------------------------------------------------------------------------
const SPA_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data: https://avatars.githubusercontent.com",
  "connect-src 'self' ws: wss:",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'"
].join('; ');

/** Determina de forma segura si la petición llegó por HTTPS (solo confía en X-Forwarded-Proto desde proxy de confianza). */
function isHttpsRequest(req) {
  if (req.socket && req.socket.encrypted) return true;
  if (!isPrivateProxyPeer(req.socket?.remoteAddress || '')) return false;
  const proto = req.headers['x-forwarded-proto'];
  if (!proto) return false;
  const hops = String(proto).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  return hops.length > 0 && hops[hops.length - 1] === 'https';
}

function applySecurityHeaders(req, res, isApiOrMetrics) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  if (isHttpsRequest(req)) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  if (isApiOrMetrics) {
    res.setHeader('Cache-Control', 'no-store');
  }
}

// ---------------------------------------------------------------------------
// Estado WebSocket y límite estricto de streams SSE/WS (dokploy#2974 anti-EMFILE)
// ---------------------------------------------------------------------------
const clients = new Set();
const syncClients = new Set();
/** @type {Set<any>} */
const activeSseResponses = new Set();
let activeSseClients = 0;
let wsConnectionsTotal = 0;
let wsBroadcastsTotal = 0;
const MAX_LOG_STREAMS_PER_PRINCIPAL = 10;
const MAX_LOG_STREAMS_GLOBAL = 50;
const MAX_SSE_CLIENTS = MAX_LOG_STREAMS_GLOBAL;

/**
 * Controlador acotado de descriptores/streams SSE y WS por principal y global (`dokploy#2974`).
 * Garantiza liberación idempotente en close/error/revocation/shutdown para evitar fugas FD / EMFILE.
 * @param {{ maxPerPrincipal?: number, maxGlobal?: number }} [opts]
 */
function createLogStreamTracker({
  maxPerPrincipal = MAX_LOG_STREAMS_PER_PRINCIPAL,
  maxGlobal = MAX_LOG_STREAMS_GLOBAL
} = {}) {
  /** @type {Set<any>} */
  const globalSet = new Set();
  /** @type {Map<string, Set<any>>} */
  const byPrincipal = new Map();

  /**
   * @param {any} req
   * @param {any} [principal]
   */
  const resolvePrincipalKey = (req, principal = null) => {
    const p = principal || (req && req.auth && req.auth.principal) || (req && req._wsPrincipal) || null;
    if (p && p.userId) return `user:${p.userId}`;
    if (p && p.tokenId) return `token:${p.tokenId}`;
    if (p && p.kind === 'master') return `master:${clientIp(req)}`;
    return `ip:${clientIp(req)}`;
  };

  /**
   * @param {string} principalKey
   * @param {any} handle
   * @param {{ enforcePerPrincipal?: boolean }} [acquireOpts]
   */
  const acquire = (principalKey, handle, acquireOpts = {}) => {
    const enforcePerPrincipal = acquireOpts.enforcePerPrincipal !== false;
    if (globalSet.size >= maxGlobal) {
      return {
        ok: false,
        status: 503,
        code: 'MAX_GLOBAL_STREAMS',
        error: `Límite global de streams SSE/WS alcanzado (${maxGlobal})`
      };
    }
    const existingBucket = byPrincipal.get(principalKey);
    if (enforcePerPrincipal && existingBucket && existingBucket.size >= maxPerPrincipal) {
      return {
        ok: false,
        status: 429,
        code: 'MAX_PRINCIPAL_STREAMS',
        error: `Límite de streams simultáneos por usuario alcanzado (${maxPerPrincipal})`
      };
    }

    globalSet.add(handle);
    let bucket = existingBucket;
    if (!bucket) {
      bucket = new Set();
      byPrincipal.set(principalKey, bucket);
    }
    bucket.add(handle);

    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      globalSet.delete(handle);
      const b = byPrincipal.get(principalKey);
      if (b) {
        b.delete(handle);
        if (b.size === 0) byPrincipal.delete(principalKey);
      }
    };
    return { ok: true, principalKey, release };
  };

  const getStats = () => {
    /** @type {Record<string, number>} */
    const perPrincipalCounts = {};
    for (const [k, set] of byPrincipal.entries()) {
      perPrincipalCounts[k] = set.size;
    }
    return {
      activeGlobal: globalSet.size,
      activePrincipals: byPrincipal.size,
      maxPerPrincipal,
      maxGlobal,
      perPrincipalCounts
    };
  };

  const releaseAll = () => {
    globalSet.clear();
    byPrincipal.clear();
  };

  return { resolvePrincipalKey, acquire, getStats, releaseAll };
}

const logStreamTracker = createLogStreamTracker({
  maxPerPrincipal: MAX_LOG_STREAMS_PER_PRINCIPAL,
  maxGlobal: MAX_LOG_STREAMS_GLOBAL
});

// Revocar todas las sesiones WS, Live Sync, SSE y caché fast-auth al rotar el token maestro
onTokenRotated(() => {
  invalidateFastAuthCaches();
  for (const ws of Array.from(clients)) {
    try { ws.close(4001, 'Token rotated'); } catch (e) {}
  }
  for (const ws of Array.from(syncClients)) {
    try { ws.close(4001, 'Token rotated'); } catch (e) {}
  }
  for (const res of Array.from(activeSseResponses)) {
    try {
      if (typeof /** @type {any} */ (res)._streamCleanup === 'function') {
        /** @type {any} */ (res)._streamCleanup();
      }
      res.end();
    } catch (e) {}
  }
  activeSseResponses.clear();
});

if (typeof onPrincipalRevoked === 'function') {
  onPrincipalRevoked((ev) => {
    invalidateFastAuthCaches();
    if (!ev) return;
    const matches = (target) => {
      const p = /** @type {any} */ (target)._authPrincipal;
      if (!p) return false;
      if (ev.masterToken) return p.kind === 'master';
      if (p.isSuperAdmin) return false;
      // Revocación acotada por sessionId: jamás desconectar api_token (p.sessionId === null)
      if (ev.sessionId) {
        return Boolean(p.sessionId && p.sessionId === ev.sessionId);
      }
      // Revocación acotada por tokenId: jamás desconectar sesiones de navegador (p.tokenId === null)
      if (ev.tokenId) {
        return Boolean(p.tokenId && p.tokenId === ev.tokenId);
      }
      if (ev.userId && p.userId === ev.userId) {
        return true;
      }
      if (ev.teamId && !ev.userId && p.teamId === ev.teamId) {
        return true;
      }
      return false;
    };
    for (const pool of [clients, syncClients]) {
      for (const ws of Array.from(pool)) {
        if (matches(ws)) {
          try { ws.close(4001, 'Session revoked'); } catch (e) {}
        }
      }
    }
    for (const res of Array.from(activeSseResponses)) {
      if (matches(res)) {
        try {
          if (typeof /** @type {any} */ (res)._streamCleanup === 'function') {
            /** @type {any} */ (res)._streamCleanup();
          } else {
            activeSseResponses.delete(res);
          }
          res.end();
        } catch (e) {}
      }
    }
  });
}

/** @type {any} */
let _wss = null;
/** @type {any} */
let _syncWss = null;
/** @type {ReturnType<typeof setInterval> | null} */
let heartbeatTimer = null;

// Conexiones activas reales y telemetría lazy
containerOrchestrator.setConnectionCounter(() => clients.size);
metricsCollector.setWsStatsGetter(() => ({
  telemetryClients: clients.size,
  syncClients: syncClients.size,
  sseClients: activeSseClients,
  connectionsTotal: wsConnectionsTotal,
  broadcastsTotal: wsBroadcastsTotal
}));
metricsCollector.setLiveSyncGetter(() => {
  const lse = loadedServices.liveSyncEngine;
  if (!lse) return null;
  const sum = lse.getGlobalSummary();
  let filesWritten = 0;
  let dedupSkipped = 0;
  let bytesSynced = 0;
  let rollbacksCount = 0;
  for (const s of lse.sessions.values()) {
    filesWritten += s.filesWritten || 0;
    dedupSkipped += s.dedupSkipped || 0;
    bytesSynced += s.bytesSynced || 0;
    rollbacksCount += s.rollbacksCount || 0;
  }
  return {
    loaded: true,
    activeSessions: sum.activeSessions,
    connectedClients: sum.connectedClients,
    framesApplied: sum.totalFramesApplied,
    filesWritten,
    dedupSkipped,
    bytesSynced,
    rollbacksCount,
    applyLatencyMs: sum.latencyMs
  };
});
metricsCollector.setCaddyGetter(() => {
  const cm = loadedServices.caddyManager;
  if (!cm) return null;
  return {
    available: cm.lastDetection ? Boolean(cm.lastDetection.available) : null,
    version: cm.lastDetection?.version || null,
    managedRoutes: cm.lastKnownRouteCount
  };
});

const WS_TEXT_OPTS = { binary: false };
const WS_MAX_BUFFERED_BYTES = 1024 * 1024;

/**
 * Filtra y redacta un evento de difusión WS para un principal multi-tenant no-superadmin.
 * Devuelve `{ send: false }` si el principal no debe ver el evento, o `{ send: true, data }`
 * con secretos redactados según permisos.
 * @param {any} principal
 * @param {string} type
 * @param {any} data
 */
function scopeWsEventForPrincipal(principal, type, data) {
  const tm = getService('teamManager');
  if (type === 'project_update' || type === 'project_created') {
    if (!data || !data.id) return { send: false };
    if (!tm.authorizeProject(principal, data.id, 'projects:read', data).allowed) {
      return { send: false };
    }
    return { send: true, data: tm.redactProjectForPrincipal(principal, data) };
  }
  if (type === 'project_deleted') {
    const pid = data && (data.id || data.projectId);
    if (pid && !tm.authorizeProject(principal, pid, 'projects:read').allowed) {
      return { send: false };
    }
    return { send: true, data };
  }
  if (type === 'mcp_call') {
    if (!tm.authorizeAction(principal, 'mcp:read').allowed) return { send: false };
    if (data && data.teamId && principal.teamId && data.teamId !== principal.teamId) return { send: false };
    if (data && data.projectId) {
      const proj = projectManager.getById(data.projectId);
      if (!tm.authorizeProject(principal, data.projectId, 'projects:read', proj).allowed) return { send: false };
    } else if (Array.isArray(principal.projectIds)) {
      return { send: false };
    }
    return { send: true, data };
  }
  if (
    type.startsWith('sync_') ||
    type.startsWith('deploy_') ||
    type.startsWith('sleep_') ||
    type.startsWith('env_') ||
    type === 'github_deploy'
  ) {
    const pid = data && (data.projectId || data.id);
    if (pid) {
      const proj = projectManager.getById(pid);
      if (!tm.authorizeProject(principal, pid, 'projects:read', proj).allowed) return { send: false };
      if (data && typeof data === 'object' && ('envVars' in data || 'secrets' in data)) {
        if (!tm.authorizeProject(principal, pid, 'secrets:read', proj).allowed) {
          const { envVars: _dropEnv, secrets: _dropSec, ...safeRest } = data;
          return { send: true, data: safeRest };
        }
      }
    } else if (Array.isArray(principal.projectIds)) {
      return { send: false };
    }
    return { send: true, data };
  }
  if (type.startsWith('fleet_')) {
    if (!tm.authorizeAction(principal, 'fleet:read').allowed) return { send: false };
    if (data && data.teamId && principal.teamId && data.teamId !== principal.teamId) return { send: false };
    return { send: true, data };
  }
  if (type.startsWith('uptime_')) {
    if (!tm.authorizeAction(principal, 'uptime:read').allowed) return { send: false };
    const pid = data && data.projectId;
    if (pid) {
      const proj = projectManager.getById(pid);
      if (!tm.authorizeProject(principal, pid, 'projects:read', proj).allowed) return { send: false };
    } else if (Array.isArray(principal.projectIds)) {
      return { send: false };
    }
    return { send: true, data };
  }
  if (type === 'log') {
    if (!tm.authorizeAction(principal, 'logs:read').allowed) return { send: false };
    if (data && data.teamId && principal.teamId && data.teamId !== principal.teamId) return { send: false };
    const pid = data && data.projectId;
    if (pid && pid !== 'global') {
      const proj = projectManager.getById(pid);
      if (!tm.authorizeProject(principal, pid, 'projects:read', proj).allowed) return { send: false };
    } else if (Array.isArray(principal.projectIds)) {
      return { send: false };
    }
    return { send: true, data };
  }
  return { send: true, data };
}

/** @param {string} type @param {any} data */
function broadcast(type, data) {
  if (clients.size === 0) return;
  wsBroadcastsTotal++;
  const timestamp = new Date().toISOString();
  // Pre-codifica una única vez como Buffer UTF-8 (`binary: false` -> opcode texto 0x01) para superadmins
  const payload = Buffer.from(JSON.stringify({ type, data, timestamp }), 'utf8');
  for (const client of clients) {
    if (client.readyState === 1) {
      // Backpressure: no encolar sobre pestañas lentas/colgadas (>1 MB pendiente)
      if (client.bufferedAmount > WS_MAX_BUFFERED_BYTES) continue;
      const principal = /** @type {any} */ (client)._authPrincipal;
      let outBuf = payload;
      if (principal && !principal.isSuperAdmin) {
        const scoped = scopeWsEventForPrincipal(principal, type, data);
        if (!scoped.send) continue;
        if (scoped.data !== data) {
          outBuf = Buffer.from(JSON.stringify({ type, data: scoped.data, timestamp }), 'utf8');
        }
      }
      client.send(outBuf, WS_TEXT_OPTS, (err) => {
        if (err) clients.delete(client);
      });
    } else if (client.readyState === 2 || client.readyState === 3) {
      clients.delete(client);
    }
  }
}

// Eventos de los servicios núcleo ya cargados
containerOrchestrator.on('metrics', (data) => broadcast('metrics', data));
containerOrchestrator.on('log', (data) => broadcast('log', data));
containerOrchestrator.on('pod_change', (data) => broadcast('pod_change', data));
containerOrchestrator.on('traffic_change', (data) => broadcast('traffic_change', data));
containerOrchestrator.on('ssl_progress', (data) => broadcast('ssl_progress', data));
containerOrchestrator.on('github_deploy', (data) => broadcast('github_deploy', data));
projectManager.on('project_update', (data) => broadcast('project_update', data));
projectManager.on('project_created', (data) => broadcast('project_created', data));
projectManager.on('project_deleted', (data) => broadcast('project_deleted', data));

// Caché de 150 ms del payload inicial de `/ws` como Buffer UTF-8 (solo superadmins)
/** @type {{ at: number, buf: Buffer } | null} */
let cachedInitialState = null;
/** @param {any} [principal] */
function getInitialWsPayloadBuf(principal = null) {
  if (principal && !principal.isSuperAdmin) {
    const tm = getService('teamManager');
    const canMcp = tm.authorizeAction(principal, 'mcp:read').allowed;
    const canLogs = tm.authorizeAction(principal, 'logs:read').allowed;
    const mcpAudit = canMcp && loadedServices.mcpServer
      ? loadedServices.mcpServer.getAuditLog(20, principal)
      : [];
    return Buffer.from(JSON.stringify({
      type: 'initial_state',
      data: {
        pods: containerOrchestrator.getPods(),
        logs: canLogs ? containerOrchestrator.getLogs({ limit: 40 }) : [],
        mcpAudit
      }
    }), 'utf8');
  }
  const now = Date.now();
  if (cachedInitialState && now - cachedInitialState.at < 150) {
    return cachedInitialState.buf;
  }
  const mcpAudit = loadedServices.mcpServer ? loadedServices.mcpServer.getAuditLog(20) : [];
  const buf = Buffer.from(JSON.stringify({
    type: 'initial_state',
    data: {
      pods: containerOrchestrator.getPods(),
      logs: containerOrchestrator.getLogs({ limit: 40 }),
      mcpAudit
    }
  }), 'utf8');
  cachedInitialState = { at: now, buf };
  return buf;
}

/** Valida si un targetDir explícito está permitido en /ws/sync (anti-escritura arbitraria y anti-symlink). */
function resolveAllowedSyncTargetDir(rawDir, req) {
  if (!rawDir) return null;
  if (process.env.CULKIBO_ALLOW_SYNC_TARGET_DIR === '1') {
    return path.resolve(String(rawDir));
  }
  if (!isLoopback(req)) {
    const err = new Error('No se permite especificar targetDir desde conexiones remotas');
    /** @type {any} */ (err).code = 'TARGET_DIR_FORBIDDEN';
    throw err;
  }
  const resolved = path.resolve(String(rawDir));
  // Resolver realpath si existe (o de su directorio padre si todavía no se ha creado) para bloquear symlinks
  let canonical = resolved;
  try {
    if (fs.existsSync(resolved)) {
      canonical = fs.realpathSync(resolved);
    } else {
      const parent = path.dirname(resolved);
      if (fs.existsSync(parent)) {
        canonical = path.join(fs.realpathSync(parent), path.basename(resolved));
      }
    }
  } catch (e) {}

  const dataRoot = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..');
  const rawAllowedRoots = [
    path.resolve(dataRoot, 'projects'),
    path.resolve(process.cwd(), 'projects'),
    ...(process.env.NODE_ENV === 'test' ? [path.resolve(os.tmpdir())] : [])
  ];
  const allowedRoots = rawAllowedRoots.map((r) => {
    try { return fs.existsSync(r) ? fs.realpathSync(r) : r; } catch (e) { return r; }
  });
  const tmpReal = (() => { try { return fs.realpathSync(os.tmpdir()); } catch (e) { return path.resolve(os.tmpdir()); } })();
  const relFromTmp = path.relative(tmpReal, canonical);
  const isCulkiboTempDir = Boolean(relFromTmp) && !relFromTmp.startsWith('..') && !path.isAbsolute(relFromTmp) && /^culkibo-(?:livesync|bench-sync)-[^\\/]+(?:[\\/]|$)/.test(relFromTmp);
  const inside = isCulkiboTempDir || allowedRoots.some((root) => {
    const rel = path.relative(root, canonical);
    return rel && rel !== '.' && !rel.startsWith('..') && !path.isAbsolute(rel);
  });
  if (!inside) {
    const err = new Error('targetDir fuera de los directorios de trabajo permitidos');
    /** @type {any} */ (err).code = 'TARGET_DIR_FORBIDDEN';
    throw err;
  }
  return canonical;
}

function safeWsSend(ws, obj) {
  if (ws.readyState !== 1) return;
  try {
    ws.send(JSON.stringify(obj), (err) => {
      if (err) {
        try { ws.terminate(); } catch (e) {}
      }
    });
  } catch (e) {
    try { ws.terminate(); } catch (e2) {}
  }
}

function selectSafeWsProtocol(protocols) {
  // Jamás devolver culkibo-token.* ni culkibo-ticket.* en la cabecera 101 Sec-WebSocket-Protocol
  if (!protocols) return false;
  if (protocols.has('culkibo.v1')) return 'culkibo.v1';
  for (const p of protocols) {
    if (!p.startsWith('culkibo-token.') && !p.startsWith('culkibo-ticket.')) return p;
  }
  return false;
}

function ensureWsServers() {
  if (_wss && _syncWss) return { wss: _wss, syncWss: _syncWss };
  const { WebSocketServer } = require('ws');
  _wss = new WebSocketServer({
    noServer: true,
    clientTracking: false,
    maxPayload: 64 * 1024,
    perMessageDeflate: false,
    handleProtocols: selectSafeWsProtocol
  });
  _syncWss = new WebSocketServer({
    noServer: true,
    clientTracking: false,
    maxPayload: 16 * 1024 * 1024,
    perMessageDeflate: false,
    handleProtocols: selectSafeWsProtocol
  });

  _syncWss.on('connection', (ws, req) => {
    syncClients.add(ws);
    wsConnectionsTotal++;
    ws.isAlive = true;
    /** @type {any} */ (ws)._authPrincipal = /** @type {any} */ (req)._wsPrincipal || null;
    ws.on('pong', () => { ws.isAlive = true; });

    const liveSyncEngine = getService('liveSyncEngine');
    /** @type {string | null} */
    let boundProjectId = null;
    /** @type {string | null} */
    let boundClientName = null;
    const clientId = `sc_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
    /** @type {{ rawDir: any, safeDir: string | null } | null} */
    let cachedDirCheck = null;

    const assertSyncAccess = (pid, perm) => {
      const principal = /** @type {any} */ (ws)._authPrincipal;
      if (!principal || principal.isSuperAdmin) return;
      const tm = getService('teamManager');
      if (!tm.isPrincipalStillValid(principal)) {
        const err = new Error('Sesión o token revocado');
        /** @type {any} */ (err).code = 'AUTH_REVOKED';
        throw err;
      }
      const proj = projectManager.getById(pid);
      const check = tm.authorizeProject(principal, pid, perm, proj);
      if (!check.allowed) {
        const err = new Error(check.reason || 'Sin permiso para sincronizar este proyecto');
        /** @type {any} */ (err).code = 'FORBIDDEN';
        throw err;
      }
    };

    const resolveDirCached = (rawDir) => {
      if (!rawDir) return null;
      if (cachedDirCheck && cachedDirCheck.rawDir === rawDir) return cachedDirCheck.safeDir;
      const safeDir = resolveAllowedSyncTargetDir(rawDir, req);
      cachedDirCheck = { rawDir, safeDir };
      return safeDir;
    };

    const cleanupSync = () => {
      syncClients.delete(ws);
      if (boundProjectId) {
        const prev = boundProjectId;
        boundProjectId = null;
        try {
          liveSyncEngine.unregisterClient(prev, clientId);
          const status = liveSyncEngine.sessions.get(prev);
          broadcast('sync_client', { projectId: prev, connected: false, connectedClients: status ? status.connectedClients : 0 });
        } catch (e) {}
      }
    };

    ws.on('error', () => {
      cleanupSync();
      try { ws.terminate(); } catch (e) {}
    });

    ws.on('message', (raw, isBinary) => {
      let msg;
      try {
        if (isBinary) {
          const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(/** @type {any} */ (raw));
          msg = liveSyncEngine.decodeBinarySyncFrame(buf);
        } else {
          msg = JSON.parse(raw.toString());
        }
      } catch (e) {
        safeWsSend(ws, { type: 'error', code: (e && e.code) || 'BAD_FRAME', error: e.message || 'Mensaje inválido' });
        return;
      }

      try {
        if (msg.type === 'hello') {
          if (!msg.projectId) throw new Error('hello requiere projectId');
          const nextPid = String(msg.projectId);
          assertSyncAccess(nextPid, 'projects:read');
          // P1-16: validar targetDir y projectId ANTES de mutar boundProjectId o connectedClients
          const safeDir = resolveDirCached(msg.targetDir);
          liveSyncEngine.resolveTargetDir(nextPid, safeDir);
          if (safeDir) liveSyncEngine.setTargetDir(nextPid, safeDir);
          const verification = liveSyncEngine.verifySync(nextPid, {
            clientDigest: msg.clientDigest || null,
            targetDir: safeDir
          });
          boundClientName = msg.clientName ? String(msg.clientName).slice(0, 80) : null;
          const clientMeta = {
            id: clientId,
            clientName: boundClientName,
            sourceDir: msg.sourceDir || null,
            pid: typeof msg.pid === 'number' ? msg.pid : null
          };
          let session;
          if (boundProjectId === nextPid) {
            session = liveSyncEngine.getOrCreateSession(nextPid);
          } else {
            if (boundProjectId) liveSyncEngine.unregisterClient(boundProjectId, clientId);
            boundProjectId = nextPid;
            /** @type {any} */ (ws)._projectId = boundProjectId;
            session = liveSyncEngine.registerClient(boundProjectId, clientMeta);
          }
          safeWsSend(ws, {
            type: 'hello_ack',
            clientId,
            protocolVersion: 2,
            codecs: ['br', 'gzip'],
            compressionSupported: ['br', 'gzip'],
            projectId: boundProjectId,
            lastSeq: session.lastSeq,
            serverDigest: verification.serverDigest,
            inSync: verification.inSync,
            fileCount: verification.fileCount,
            targetDir: verification.targetDir,
            binaryFramesSupported: true,
            chunkedUploadSupported: true
          });
          broadcast('sync_client', { projectId: boundProjectId, connected: true, connectedClients: session.connectedClients });
          return;
        }

        if (msg.type === 'frame') {
          const pid = String(msg.projectId || boundProjectId || '');
          if (!pid) throw new Error('frame requiere projectId');
          assertSyncAccess(pid, 'projects:write');
          const safeDir = resolveDirCached(msg.targetDir);
          const result = liveSyncEngine.applyCommitFrame(pid, msg, {
            targetDir: safeDir || undefined,
            deferEmit: true,
            clientId,
            clientName: boundClientName,
            wireStats: msg._wireStats || null
          });
          safeWsSend(ws, { type: 'frame_ack', ...result });
          setImmediate(() => liveSyncEngine.emitApplied(result));
          return;
        }

        if (msg.type === 'verify') {
          const pid = String(msg.projectId || boundProjectId || '');
          if (!pid) throw new Error('verify requiere projectId');
          assertSyncAccess(pid, 'projects:read');
          const safeDir = resolveDirCached(msg.targetDir);
          const result = liveSyncEngine.verifySync(pid, {
            clientDigest: msg.clientDigest || null,
            clientFiles: msg.clientFiles || null,
            targetDir: safeDir
          });
          safeWsSend(ws, { type: 'verify_ack', ...result });
          return;
        }

        if (msg.type === 'rollback') {
          const pid = String(msg.projectId || boundProjectId || '');
          if (!pid) throw new Error('rollback requiere projectId');
          assertSyncAccess(pid, 'projects:write');
          const result = liveSyncEngine.rollback(pid, msg.steps || 1);
          safeWsSend(ws, { type: 'rollback_ack', ...result });
          return;
        }

        if (msg.type === 'file_history') {
          const pid = String(msg.projectId || boundProjectId || '');
          if (!pid) throw new Error('file_history requiere projectId');
          assertSyncAccess(pid, 'projects:read');
          const safeDir = resolveDirCached(msg.targetDir);
          const result = liveSyncEngine.getFileHistory(pid, msg.path, {
            targetDir: safeDir || undefined,
            limit: msg.limit,
            includeDiff: Boolean(msg.includeDiff)
          });
          safeWsSend(ws, { type: 'file_history_ack', ...result });
          return;
        }

        if (msg.type === 'rollback_file') {
          const pid = String(msg.projectId || boundProjectId || '');
          if (!pid) throw new Error('rollback_file requiere projectId');
          assertSyncAccess(pid, 'projects:write');
          const safeDir = resolveDirCached(msg.targetDir);
          const result = liveSyncEngine.rollbackFile(pid, msg.path, msg.seq, {
            targetDir: safeDir || undefined,
            mode: msg.mode,
            clientId,
            clientName: boundClientName
          });
          safeWsSend(ws, { type: 'rollback_file_ack', ...result });
          return;
        }

        if (typeof msg.type === 'string' && msg.type.startsWith('chunk_')) {
          const pid = String(msg.projectId || boundProjectId || '');
          if (!pid) throw new Error(`${msg.type} requiere projectId`);
          assertSyncAccess(pid, 'projects:write');
          const safeDir = resolveDirCached(msg.targetDir);
          const result = liveSyncEngine.handleChunkMessage(pid, msg, {
            targetDir: safeDir || undefined,
            clientId,
            clientName: boundClientName
          });
          safeWsSend(ws, result);
          return;
        }

        safeWsSend(ws, { type: 'error', code: 'UNKNOWN_TYPE', error: `Tipo de mensaje no soportado: ${msg.type}` });
      } catch (err) {
        safeWsSend(ws, {
          type: 'error',
          seq: msg && msg.seq ? msg.seq : null,
          code: (err && err.code) || 'SYNC_ERROR',
          error: err && err.message ? err.message : String(err)
        });
      }
    });

    ws.on('close', cleanupSync);
  });

  _wss.on('connection', (ws, req) => {
    clients.add(ws);
    wsConnectionsTotal++;
    ws.isAlive = true;
    /** @type {any} */ (ws)._authPrincipal = /** @type {any} */ (req)._wsPrincipal || null;
    const releaseSlot = typeof /** @type {any} */ (req)._wsStreamRelease === 'function'
      ? /** @type {any} */ (req)._wsStreamRelease
      : () => {};
    let wsCleaned = false;
    const cleanupWs = () => {
      if (wsCleaned) return;
      wsCleaned = true;
      clients.delete(ws);
      try { releaseSlot(); } catch (e) {}
    };
    /** @type {any} */ (ws)._streamCleanup = cleanupWs;
    ws.on('pong', () => { ws.isAlive = true; });

    ws.on('error', () => {
      cleanupWs();
      try { ws.terminate(); } catch (e) {}
    });

    try {
      ws.send(getInitialWsPayloadBuf(/** @type {any} */ (ws)._authPrincipal), { binary: false });
    } catch (e) {
      cleanupWs();
    }

    ws.on('message', (message) => {
      try {
        const parsed = JSON.parse(message.toString());
        if (parsed.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
        }
      } catch (e) {}
    });

    ws.on('close', cleanupWs);
  });

  if (!heartbeatTimer) {
    heartbeatTimer = setInterval(() => {
      for (const pool of [clients, syncClients]) {
        for (const ws of pool) {
          if (ws.isAlive === false) {
            pool.delete(ws);
            if (typeof /** @type {any} */ (ws)._streamCleanup === 'function') {
              try { /** @type {any} */ (ws)._streamCleanup(); } catch (e) {}
            }
            try { ws.terminate(); } catch (e) {}
            continue;
          }
          ws.isAlive = false;
          try { ws.ping(); } catch (e) {
            pool.delete(ws);
            if (typeof /** @type {any} */ (ws)._streamCleanup === 'function') {
              try { /** @type {any} */ (ws)._streamCleanup(); } catch (e2) {}
            }
            try { ws.terminate(); } catch (e2) {}
          }
        }
      }
    }, 30000);
    if (heartbeatTimer.unref) heartbeatTimer.unref();
  }

  return { wss: _wss, syncWss: _syncWss };
}

// ---------------------------------------------------------------------------
// Fast-Path HTTP (O(1) tabla precompilada + caché LRU de auth por HMAC + zero-copy)
// ---------------------------------------------------------------------------
// Clave HMAC efímera por proceso: la caché LRU nunca almacena tokens en claro en RAM
// y se invalida al instante en `onTokenRotated`, `onPrincipalRevoked` y mutaciones auth/teams.
const FAST_AUTH_HMAC_KEY = crypto.randomBytes(32);
const FAST_AUTH_CACHE_MAX = 256;
const FAST_AUTH_TOKEN_TTL_MS = 5000;
const FAST_LOOPBACK_POLICY_TTL_MS = 500;
const STRUCTURED_LOGS_QUERY_RE = /(?:^|&)(?:regex|since|until|attr)=/i;

/** @type {Map<string, { decision: any, expiresAt: number }>} */
const fastAuthCache = new Map();
/** @type {Map<string, { decision: any, expiresAt: number }>} */
const loopbackPolicyCache = new Map();
/** @type {{ at: number, dataDir: string, envTok: string, data: any } | null} */
let cachedAuthStatus = null;

function invalidateFastAuthCaches() {
  fastAuthCache.clear();
  loopbackPolicyCache.clear();
  cachedAuthStatus = null;
  systemStatusCache = null;
}

function getAuthStatusCached() {
  const now = Date.now();
  const dataDir = process.env.CULKIBO_DATA_DIR || '';
  const envTok = process.env.CULKIBO_TOKEN || '';
  if (
    cachedAuthStatus &&
    (now - cachedAuthStatus.at) < 1000 &&
    cachedAuthStatus.dataDir === dataDir &&
    cachedAuthStatus.envTok === envTok
  ) {
    return cachedAuthStatus.data;
  }
  const data = authStatus();
  cachedAuthStatus = { at: now, dataDir, envTok, data };
  return data;
}

/**
 * Verificación de autenticación acelerada para el fast-path HTTP (cero relajación de seguridad):
 * - Siempre comprueba `Origin` antes de consultar la caché.
 * - Indexa tokens por HMAC-SHA256 efímero + IP efectiva + env (`CULKIBO_TOKEN`, `CULKIBO_DATA_DIR`).
 * - Solo cachea decisiones positivas (`ok: true`) con TTL corto e invalidación inmediata en revocación/rotación.
 * - En loopback sin credencial, evita `fs.existsSync(data/teams.json)` por petición durante 500 ms.
 * @param {any} req
 */
function authorizeRequestFast(req) {
  const headers = req.headers || {};
  const origin = headers.origin;
  if (origin && !isOriginAllowed(origin, req)) {
    return {
      ok: false,
      status: 403,
      error: 'Origen no permitido',
      detail: `El origen ${origin} no está autorizado a hablar con este daemon. Añádelo a CULKIBO_ALLOWED_ORIGINS si es tuyo.`
    };
  }

  // Extraer token explícito sin parsear cookies si viene cabecera Bearer / X-Culkibo-Token
  /** @type {string | null} */
  let rawToken = null;
  const authHeader = headers.authorization;
  if (authHeader && authHeader.length > 7 && (authHeader.startsWith('Bearer ') || authHeader.startsWith('bearer ') || authHeader.slice(0, 7).toLowerCase() === 'bearer ')) {
    rawToken = authHeader.slice(7).trim();
  } else if (headers['x-culkibo-token']) {
    rawToken = String(headers['x-culkibo-token']).trim();
  }

  const now = Date.now();
  const dataDirEnv = process.env.CULKIBO_DATA_DIR || '';

  if (rawToken) {
    const ip = clientIp(req);
    const tokHmac = crypto.createHmac('sha256', FAST_AUTH_HMAC_KEY).update(rawToken, 'utf8').digest('base64');
    const cacheKey = `${tokHmac}|${ip}|${process.env.CULKIBO_TOKEN || ''}|${dataDirEnv}`;
    const hit = fastAuthCache.get(cacheKey);
    if (hit) {
      if (hit.expiresAt > now) {
        // Refrescar posición LRU
        fastAuthCache.delete(cacheKey);
        fastAuthCache.set(cacheKey, hit);
        return hit.decision;
      }
      fastAuthCache.delete(cacheKey);
    }
    const decision = authorizeRequest(req, { allowWsSubprotocol: false });
    if (decision.ok && (decision.method === 'token' || decision.method === 'session' || decision.method === 'api_token')) {
      if (fastAuthCache.size >= FAST_AUTH_CACHE_MAX) {
        const oldest = fastAuthCache.keys().next().value;
        if (oldest !== undefined) fastAuthCache.delete(oldest);
      }
      fastAuthCache.set(cacheKey, { decision, expiresAt: now + FAST_AUTH_TOKEN_TTL_MS });
    }
    return decision;
  }

  // Camino rápido loopback sin credenciales ni cookies ni enforceOnLoopback cargado
  if (
    !headers.cookie &&
    !headers['x-forwarded-for'] &&
    !headers.forwarded &&
    process.env.CULKIBO_REQUIRE_TOKEN !== '1' &&
    !(loadedServices.teamManager && typeof loadedServices.teamManager.isEnforceOnLoopback === 'function' && loadedServices.teamManager.isEnforceOnLoopback())
  ) {
    const peer = req.socket?.remoteAddress || '';
    if (peer === '127.0.0.1' || peer === '::1' || peer === '::ffff:127.0.0.1') {
      const host = headers.host || '';
      const lbKey = `${dataDirEnv}|${origin || ''}|${host}|${peer}`;
      const lbHit = loopbackPolicyCache.get(lbKey);
      if (lbHit) {
        if (lbHit.expiresAt > now) return lbHit.decision;
        loopbackPolicyCache.delete(lbKey);
      }
      const decision = authorizeRequest(req, { allowWsSubprotocol: false });
      if (decision.ok && (decision.method === 'loopback' || decision.method === 'loopback_origin')) {
        if (loopbackPolicyCache.size >= 64) {
          const oldest = loopbackPolicyCache.keys().next().value;
          if (oldest !== undefined) loopbackPolicyCache.delete(oldest);
        }
        loopbackPolicyCache.set(lbKey, { decision, expiresAt: now + FAST_LOOPBACK_POLICY_TTL_MS });
      }
      return decision;
    }
  }

  return authorizeRequest(req, { allowWsSubprotocol: false });
}

/** @type {{ at: number, buf: Buffer } | null} */
let healthBufCache = null;
function getHealthBuffer() {
  const now = Date.now();
  if (healthBufCache && (now - healthBufCache.at) < 50) return healthBufCache.buf;
  const buf = Buffer.from(`{"status":"healthy","timestamp":"${new Date(now).toISOString()}"}`, 'utf8');
  healthBufCache = { at: now, buf };
  return buf;
}

/** @type {{ at: number, buf: Buffer } | null} */
let systemStatusCache = null;
function getSystemStatusBuffer() {
  const now = Date.now();
  if (systemStatusCache && (now - systemStatusCache.at) < 250) return systemStatusCache.buf;
  const proc = metricsCollector.sampleProcess();
  const payload = {
    name: 'Culkibo',
    status: 'operational',
    version: APP_VERSION,
    platform: process.platform,
    arch: process.arch,
    nodeVersion: process.version,
    uptimeSeconds: proc.uptimeSeconds,
    memoryUsageMb: proc.memoryMb,
    heapUsedMb: proc.heapUsedMb,
    cpuPercent: proc.cpuPercent,
    auth: getAuthStatusCached(),
    capabilities: {
      liveSyncBinary: true,
      merkleVerify: true,
      mcpProtocolVersion: MCP_PROTOCOL_VERSION,
      caddyAvailable: loadedServices.caddyManager?.lastDetection?.available ?? null,
      dockerChecked: Boolean(loadedServices.deployManager || loadedServices.databaseManager)
    }
  };
  const buf = Buffer.from(JSON.stringify(payload), 'utf8');
  systemStatusCache = { at: now, buf };
  return buf;
}

const EMPTY_SYNC_SUMMARY_BUF = Buffer.from(JSON.stringify({
  activeSessions: 0,
  connectedClients: 0,
  totalFramesApplied: 0,
  latencyMs: { samples: 0, min: null, mean: null, p50: null, p95: null, p99: null, max: null },
  sessions: []
}), 'utf8');

const ERR_BODY_TOO_LARGE_BUF = Buffer.from('{"error":"El cuerpo supera el límite permitido (1 MB)"}', 'utf8');
const ERR_BAD_JSON_BUF = Buffer.from('{"error":"JSON malformado en el cuerpo de la petición"}', 'utf8');
const ERR_PROJECT_NOT_FOUND_BUF = Buffer.from('{"error":"Proyecto no encontrado"}', 'utf8');
const ASK_OK_BUF = Buffer.from('ok', 'utf8');
const ASK_FORBIDDEN_LOCAL_BUF = Buffer.from('acceso restringido al plano de datos local', 'utf8');
const ASK_MISSING_DOMAIN_BUF = Buffer.from('falta el parámetro domain', 'utf8');
const ASK_INVALID_DOMAIN_BUF = Buffer.from('parámetro domain inválido', 'utf8');
const MANAGEMENT_HOSTS_FAST = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1', '']);
const API_COMPRESS_MIN_BYTES = 512;

/** @type {typeof import('zlib') | null} */
let _zlib = null;
function getZlib() {
  if (!_zlib) _zlib = require('zlib');
  return _zlib;
}

/** Caché WeakMap por Buffer fuente: auto-GC cuando el Buffer rota, cero fugas de RAM. */
/** @type {WeakMap<Buffer, { etag?: string, br?: Buffer, zstd?: Buffer, gzip?: Buffer }>} */
const compressedApiCache = new WeakMap();

/** Comprueba si `Accept-Encoding` acepta `coding` con q > 0 (RFC 9110), con fast-path sin asignaciones. */
function acceptsEncoding(aeHeader, coding) {
  if (!aeHeader || typeof aeHeader !== 'string') return false;
  if (aeHeader === coding) return true;
  // Fast-path sin `;` (sin pesos q): comprueba token exacto sin split ni regex
  if (aeHeader.indexOf(';') === -1) {
    const lower = aeHeader.toLowerCase();
    let idx = lower.indexOf(coding);
    while (idx !== -1) {
      const before = idx === 0 ? ',' : lower[idx - 1];
      const after = idx + coding.length === lower.length ? ',' : lower[idx + coding.length];
      if ((before === ',' || before === ' ' || before === '\t') && (after === ',' || after === ' ' || after === '\t')) {
        return true;
      }
      idx = lower.indexOf(coding, idx + 1);
    }
    return false;
  }
  const parts = aeHeader.toLowerCase().split(',');
  for (let i = 0; i < parts.length; i++) {
    const seg = parts[i].trim();
    if (!seg) continue;
    const pieces = seg.split(';');
    const name = pieces[0].trim();
    if (name !== coding) continue;
    let q = 1;
    for (let j = 1; j < pieces.length; j++) {
      const m = pieces[j].trim().match(/^q\s*=\s*([0-9.]+)$/);
      if (m) q = Number(m[1]);
    }
    return Number.isFinite(q) && q > 0;
  }
  return false;
}

/** Comprueba `If-None-Match` (soporta weak `W/"..."`, listas separadas por coma y `*`). */
function etagMatches(inmHeader, etag) {
  if (!inmHeader || !etag) return false;
  const raw = String(inmHeader).trim();
  if (raw === '*') return true;
  if (raw === etag) return true;
  const cleanTarget = etag.replace(/^W\//i, '').trim();
  const candidates = raw.split(',');
  for (let i = 0; i < candidates.length; i++) {
    const c = candidates[i].trim().replace(/^W\//i, '').trim();
    if (c === cleanTarget) return true;
  }
  return false;
}

function pickApiEncoding(req) {
  const ae = req.headers['accept-encoding'];
  if (!ae || typeof ae !== 'string') return null;
  if (ae === 'br' || ae === 'gzip, deflate, br' || ae === 'gzip, deflate, br, zstd') return 'br';
  if (ae === 'gzip' || ae === 'gzip, deflate') return 'gzip';
  if (acceptsEncoding(ae, 'br')) return 'br';
  if (acceptsEncoding(ae, 'zstd')) {
    const z = getZlib();
    if (typeof z.zstdCompressSync === 'function') return 'zstd';
  }
  if (acceptsEncoding(ae, 'gzip')) return 'gzip';
  return null;
}

function getOrCreateCacheSlot(buf) {
  let entry = compressedApiCache.get(buf);
  if (!entry) {
    entry = {};
    compressedApiCache.set(buf, entry);
  }
  return entry;
}

function getBufferEtag(buf) {
  const entry = getOrCreateCacheSlot(buf);
  if (!entry.etag) {
    entry.etag = `"${crypto.createHash('sha1').update(buf).digest('base64url').slice(0, 16)}"`;
  }
  return entry.etag;
}

function getCompressedEntry(buf, encoding) {
  if (!encoding || buf.length < API_COMPRESS_MIN_BYTES) {
    return { body: buf, encoding: null };
  }
  const entry = getOrCreateCacheSlot(buf);
  if (encoding === 'br') {
    if (!entry.br) {
      const z = getZlib();
      const c = z.brotliCompressSync(buf, {
        params: {
          [z.constants.BROTLI_PARAM_MODE]: z.constants.BROTLI_MODE_TEXT,
          [z.constants.BROTLI_PARAM_QUALITY]: 4
        }
      });
      entry.br = c.length < buf.length ? c : buf;
    }
    return { body: entry.br, encoding: entry.br === buf ? null : 'br' };
  }
  if (encoding === 'zstd') {
    if (!entry.zstd) {
      const z = getZlib();
      if (typeof z.zstdCompressSync === 'function') {
        const c = z.zstdCompressSync(buf);
        entry.zstd = c.length < buf.length ? c : buf;
      } else {
        entry.zstd = buf;
      }
    }
    return { body: entry.zstd, encoding: entry.zstd === buf ? null : 'zstd' };
  }
  if (encoding === 'gzip') {
    if (!entry.gzip) {
      const z = getZlib();
      const c = z.gzipSync(buf, { level: 6 });
      entry.gzip = c.length < buf.length ? c : buf;
    }
    return { body: entry.gzip, encoding: entry.gzip === buf ? null : 'gzip' };
  }
  return { body: buf, encoding: null };
}

/**
 * @param {any} req
 * @param {any} res
 * @param {number} statusCode
 * @param {string} contentType
 * @param {Buffer} buf
 * @param {string} canonicalRoute
 * @param {number} t0Ms
 * @param {{ cacheControl?: string, etag?: string | null, compress?: boolean, csp?: boolean, closeConnection?: boolean }} [opts]
 */
function sendFastBuffer(req, res, statusCode, contentType, buf, canonicalRoute, t0Ms, opts = {}) {
  const allowCompress = Boolean(opts.compress) && statusCode === 200 && buf.length >= API_COMPRESS_MIN_BYTES;
  const sendEtag = statusCode === 200 && Boolean(opts.cacheControl && opts.cacheControl !== 'no-store');

  let body = buf;
  /** @type {string | null} */
  let contentEncoding = null;
  /** @type {string | null} */
  let etag = typeof opts.etag === 'string' ? opts.etag : null;

  /** @type {Record<string, string | number>} */
  const headers = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-Permitted-Cross-Domain-Policies': 'none',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cache-Control': opts.cacheControl || 'no-store'
  };
  if (opts.csp) {
    headers['Content-Security-Policy'] = SPA_CSP;
  }
  if (opts.closeConnection) {
    headers['Connection'] = 'close';
  }
  const origin = req.headers.origin;
  let vary = '';
  if (origin && isOriginAllowed(origin, req)) {
    headers['Access-Control-Allow-Origin'] = origin;
    vary = 'Origin';
  }
  if (allowCompress) {
    vary = vary ? `${vary}, Accept-Encoding` : 'Accept-Encoding';
  }
  if (vary) headers['Vary'] = vary;

  if (isHttpsRequest(req)) {
    headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
  }

  // Comprobar 304 ANTES de comprimir (ahorra CPU y evita SHA-1 innecesarios en rutas no-store)
  if (sendEtag) {
    if (!etag) etag = getBufferEtag(buf);
    headers['ETag'] = etag;
    if (etagMatches(req.headers['if-none-match'], etag)) {
      const dur304 = Math.max(0, performance.now() - t0Ms);
      headers['Server-Timing'] = `cp;dur=${dur304.toFixed(2)}`;
      res.writeHead(304, headers);
      res.end();
      metricsCollector.recordFastPath(req.method, canonicalRoute, 304, dur304);
      return;
    }
  }

  if (allowCompress) {
    const enc = pickApiEncoding(req);
    if (enc) {
      const comp = getCompressedEntry(buf, enc);
      body = comp.body;
      contentEncoding = comp.encoding;
    }
  }

  headers['Content-Type'] = contentType;
  headers['Content-Length'] = body.length;
  if (contentEncoding) headers['Content-Encoding'] = contentEncoding;
  const durMs = Math.max(0, performance.now() - t0Ms);
  headers['Server-Timing'] = `cp;dur=${durMs.toFixed(2)}`;

  res.writeHead(statusCode, headers);
  res.end(req.method === 'HEAD' ? undefined : body);
  metricsCollector.recordFastPath(req.method, canonicalRoute, statusCode, durMs);
}

// ---------------------------------------------------------------------------
// Fast-Path estático en RAM con pre-compresión Brotli/Gzip (evita cargar Express al navegar el panel)
// ---------------------------------------------------------------------------
const STATIC_MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.txt': 'text/plain; charset=utf-8'
};

/** @type {Map<string, { mime: string, etag: string, immutable: boolean, isHtml: boolean, raw: Buffer, br: Buffer | null, gz: Buffer | null }> | null} */
let staticAssetCache = null;
let staticDistChecked = false;
let staticDistExists = false;

function ensureStaticCache() {
  if (staticDistChecked) return staticDistExists;
  staticDistChecked = true;
  const distDir = path.join(__dirname, '..', 'web', 'dist');
  if (!fs.existsSync(distDir) || !fs.existsSync(path.join(distDir, 'index.html'))) {
    staticDistExists = false;
    return false;
  }
  const cache = new Map();
  let totalBytes = 0;
  const MAX_STATIC_CACHE_BYTES = 12 * 1024 * 1024;

  const walk = (dir, prefix) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      const urlRel = prefix ? `${prefix}/${entry.name}` : `/${entry.name}`;
      if (entry.isDirectory()) {
        walk(full, urlRel);
      } else if (entry.isFile()) {
        if (entry.name.endsWith('.br') || entry.name.endsWith('.gz')) continue;
        const ext = path.extname(entry.name).toLowerCase();
        const mime = STATIC_MIME[ext] || 'application/octet-stream';
        const raw = fs.readFileSync(full);
        if (totalBytes + raw.length > MAX_STATIC_CACHE_BYTES) continue;
        /** @type {Buffer | null} */
        let br = null;
        /** @type {Buffer | null} */
        let gz = null;
        try { if (fs.existsSync(`${full}.br`)) br = fs.readFileSync(`${full}.br`); } catch (e) {}
        try { if (fs.existsSync(`${full}.gz`)) gz = fs.readFileSync(`${full}.gz`); } catch (e) {}
        totalBytes += raw.length + (br ? br.length : 0) + (gz ? gz.length : 0);
        const etag = `"${crypto.createHash('sha1').update(raw).digest('base64url').slice(0, 16)}"`;
        cache.set(urlRel, {
          mime,
          etag,
          immutable: urlRel.startsWith('/assets/'),
          isHtml: ext === '.html',
          raw,
          br,
          gz
        });
      }
    }
  };
  try {
    walk(distDir, '');
    staticAssetCache = cache;
    staticDistExists = cache.has('/index.html');
  } catch (e) {
    staticAssetCache = null;
    staticDistExists = false;
  }
  return staticDistExists;
}

function tryServeStaticFastPath(req, res, pathname) {
  if (!ensureStaticCache() || !staticAssetCache) return false;
  if (pathname.startsWith('/api') || pathname === '/ws' || pathname === '/ws/sync' || pathname === '/health' || pathname === '/metrics') {
    return false;
  }

  // Comprobación 421 plano de control vs plano de datos antes de servir el panel SPA
  // Solo confiar en X-Forwarded-Host (último salto) si el peer inmediato es un proxy de confianza
  const trustProxyHost = isPrivateProxyPeer(req.socket?.remoteAddress || '');
  const forwarded = trustProxyHost ? req.headers['x-forwarded-host'] : null;
  const host = extractHostnameClean(forwarded || req.headers.host || '', Boolean(forwarded));
  const activePanelDomain = (loadedServices.ingressManager?.panelDomain || cachedPanelDomain || '').toLowerCase();
  const isPanelOrLocal = (activePanelDomain && host === activePanelDomain) || (MANAGEMENT_HOSTS_FAST.has(host) && !forwarded);
  if (!isPanelOrLocal) {
    const dm = getService('domainManager');
    if (dm.resolveRoute(host)) {
      // Dejar que Express sirva la respuesta 421 detallada o gestionarla allí sin duplicar código
      return false;
    }
  }

  const t0 = performance.now();
  containerOrchestrator.recordRequest();

  let asset = staticAssetCache.get(pathname);
  if (!asset) {
    // Petición de fichero estático inexistente (con extensión) -> 404; rutas SPA -> index.html
    if (pathname.startsWith('/assets/') || /\.[a-z0-9]{1,8}$/i.test(pathname)) {
      sendFastBuffer(req, res, 404, 'text/plain; charset=utf-8', Buffer.from('Not Found', 'utf8'), '/static', t0);
      return true;
    }
    asset = staticAssetCache.get('/index.html');
  }
  if (!asset) return false;

  const ae = String(req.headers['accept-encoding'] || '');
  /** @type {Buffer} */
  let body = asset.raw;
  /** @type {string | null} */
  let encoding = null;
  if (asset.br && acceptsEncoding(ae, 'br')) {
    body = asset.br;
    encoding = 'br';
  } else if (asset.gz && acceptsEncoding(ae, 'gzip')) {
    body = asset.gz;
    encoding = 'gzip';
  }

  /** @type {Record<string, string | number>} */
  const headers = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-Permitted-Cross-Domain-Policies': 'none',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cache-Control': asset.immutable ? 'public, max-age=31536000, immutable' : 'no-cache, no-store, must-revalidate',
    'Vary': 'Accept-Encoding'
  };
  if (asset.isHtml) {
    headers['Content-Security-Policy'] = SPA_CSP;
  } else {
    headers['ETag'] = asset.etag;
    if (etagMatches(req.headers['if-none-match'], asset.etag)) {
      const dur304 = Math.max(0, performance.now() - t0);
      headers['Server-Timing'] = `cp;dur=${dur304.toFixed(2)}`;
      res.writeHead(304, headers);
      res.end();
      metricsCollector.recordFastPath(req.method, '/static', 304, dur304);
      return true;
    }
  }
  if (isHttpsRequest(req)) {
    headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
  }
  headers['Content-Type'] = asset.mime;
  headers['Content-Length'] = body.length;
  if (encoding) headers['Content-Encoding'] = encoding;
  const durMs = Math.max(0, performance.now() - t0);
  headers['Server-Timing'] = `cp;dur=${durMs.toFixed(2)}`;

  res.writeHead(200, headers);
  res.end(req.method === 'HEAD' ? undefined : body);
  metricsCollector.recordFastPath(req.method, '/static', 200, durMs);
  return true;
}

function sendFastAuthError(req, res, decision, canonicalRoute, t0Ms) {
  const body = Buffer.from(JSON.stringify({
    error: decision.error,
    ...(decision.detail ? { detail: decision.detail } : {})
  }), 'utf8');
  sendFastBuffer(req, res, decision.status || 401, 'application/json; charset=utf-8', body, canonicalRoute, t0Ms);
}

function tryHandleFastPath(req, res) {
  const method = req.method;
  const rawUrl = req.url || '/';
  const qIdx = rawUrl.indexOf('?');
  const pathname = qIdx === -1 ? rawUrl : rawUrl.slice(0, qIdx);
  const queryStr = qIdx === -1 ? '' : rawUrl.slice(qIdx + 1);

  // Endpoint interno de Wake-on-Request para proyectos en Auto-Sleep (protegido por proxy privado + wake secret)
  if (pathname.startsWith('/_culkibo/wake/')) {
    let pid = '';
    try {
      pid = decodeURIComponent(pathname.slice('/_culkibo/wake/'.length).split('/')[0] || '');
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end('{"error":"projectId con codificación URL inválida"}');
      return true;
    }
    if (!pid) {
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end('{"error":"Falta projectId"}');
      return true;
    }
    try {
      const sa = getService('sleepAdvisor');
      Promise.resolve(sa.handleWakeRequest(req, res, pid)).catch(() => {
        if (!res.headersSent) {
          res.writeHead(503, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end('{"error":"No se pudo despertar el servicio"}');
        }
      });
    } catch (e) {
      res.writeHead(503, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end('{"error":"Servicio de Auto-Sleep no disponible"}');
    }
    return true;
  }

  // Páginas públicas de estado (`/status/:slug`, `/status/:slug.json`, `/status/:slug/status.json`, `/status/:slug.svg`, `/status/:slug/badge.svg`) — cero fugas internas
  if ((method === 'GET' || method === 'HEAD') && pathname.startsWith('/status/')) {
    const rest = pathname.slice(8).replace(/\/+$/, '');
    const parts = rest ? rest.split('/') : [];
    let slug = '';
    /** @type {'html' | 'json' | 'svg' | null} */
    let format = null;
    if (parts.length === 1 && parts[0]) {
      const seg = parts[0];
      try {
        if (seg.endsWith('.json')) {
          slug = decodeURIComponent(seg.slice(0, -5));
          format = 'json';
        } else if (seg.endsWith('.svg')) {
          slug = decodeURIComponent(seg.slice(0, -4));
          format = 'svg';
        } else {
          slug = decodeURIComponent(seg);
          format = 'html';
        }
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Slug inválido');
        return true;
      }
    } else if (parts.length === 2 && parts[0] && (parts[1] === 'status.json' || parts[1] === 'badge.svg')) {
      try {
        slug = decodeURIComponent(parts[0]);
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Slug inválido');
        return true;
      }
      format = parts[1] === 'status.json' ? 'json' : 'svg';
    }
    if (format && slug) {
      try {
        const um = getService('uptimeMonitor');
        if (format === 'json') {
          const data = um.getPublicStatusData(slug);
          if (!data) {
            res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
            res.end('{"error":"Página de estado no encontrada"}');
            return true;
          }
          const body = Buffer.from(JSON.stringify(data), 'utf8');
          res.writeHead(200, {
            'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'public, max-age=15',
            'X-Content-Type-Options': 'nosniff',
            'Content-Length': body.length
          });
          res.end(method === 'HEAD' ? undefined : body);
          return true;
        }
        if (format === 'svg') {
          const svg = um.renderBadgeSvg(slug);
          if (!svg) {
            res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('Not Found');
            return true;
          }
          const body = Buffer.from(svg, 'utf8');
          res.writeHead(200, {
            'Content-Type': 'image/svg+xml; charset=utf-8',
            'Cache-Control': 'public, max-age=30',
            'X-Content-Type-Options': 'nosniff',
            'Content-Length': body.length
          });
          res.end(method === 'HEAD' ? undefined : body);
          return true;
        }
        const resp = um.renderPublicStatusResponse(slug);
        if (!resp) {
          res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
          res.end('Página de estado no encontrada');
          return true;
        }
        res.writeHead(resp.status || 200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Security-Policy': um.PUBLIC_STATUS_CSP || "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'Referrer-Policy': 'no-referrer',
          'Cache-Control': 'public, max-age=15',
          'Content-Length': resp.body.length
        });
        res.end(method === 'HEAD' ? undefined : resp.body);
        return true;
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Error al renderizar página de estado');
        return true;
      }
    }
  }

  // Fast-path nativo para POST /api/projects (evita bloquear el event loop cargando
  // Express y 18 servicios auxiliares en la primera alta concurrente).
  if (method === 'POST' && pathname === '/api/projects') {
    const t0 = performance.now();
    containerOrchestrator.recordRequest();

    const rl = fastProjectsLimiter.check(req);
    if (!rl.allowed) {
      res.setHeader('Retry-After', String(rl.retryAfterSec));
      sendFastAuthError(req, res, { status: 429, error: 'Demasiadas peticiones. Espera unos segundos antes de reintentar.' }, pathname, t0);
      return true;
    }

    const bf = checkAuthBruteForce(req);
    if (bf.blocked) {
      metricsCollector.recordSecurityEvent('authBlocked429');
      res.setHeader('Retry-After', String(bf.retryAfterSec));
      sendFastAuthError(req, res, { status: 429, error: 'Demasiados intentos de autenticación fallidos.' }, pathname, t0);
      return true;
    }

    const decision = authorizeRequestFast(req);
    if (!decision.ok) {
      if (decision.status === 403) metricsCollector.recordSecurityEvent('originRejected403');
      const creds = extractCredentials(req, { allowWsSubprotocol: false });
      if (decision.status === 401 && (creds.token || creds.ticket || creds.cookieToken)) {
        recordAuthFailure(req);
        metricsCollector.recordSecurityEvent('authFailures');
      }
      sendFastAuthError(req, res, decision, pathname, t0);
      return true;
    }
    // En modo multiusuario/token con alcance limitado, delegar en Express para aplicar RBAC y teamId
    if (decision.principal && !decision.principal.isSuperAdmin) {
      return false;
    }

    const limitBytes = 1 * 1024 * 1024;
    const declaredLen = Number(req.headers['content-length'] || 0);
    if (declaredLen > limitBytes) {
      sendFastBuffer(req, res, 413, 'application/json; charset=utf-8', ERR_BODY_TOO_LARGE_BUF, pathname, t0, { closeConnection: true });
      req.resume();
      return true;
    }

    /** @type {Buffer[]} */
    const chunks = [];
    let total = 0;
    let aborted = false;

    req.on('data', (chunk) => {
      if (aborted) return;
      total += chunk.length;
      if (total > limitBytes) {
        aborted = true;
        sendFastBuffer(req, res, 413, 'application/json; charset=utf-8', ERR_BODY_TOO_LARGE_BUF, pathname, t0, { closeConnection: true });
        req.resume();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (aborted) return;
      let body = {};
      if (total > 0) {
        try {
          body = JSON.parse(Buffer.concat(chunks, total).toString('utf8'));
        } catch (e) {
          sendFastBuffer(req, res, 400, 'application/json; charset=utf-8', ERR_BAD_JSON_BUF, pathname, t0);
          return;
        }
      }
      try {
        const project = projectManager.create(body);
        auditLogger.record({
          source: 'http',
          action: 'project.create',
          method: 'POST',
          path: '/api/projects',
          resourceId: project.id,
          ip: clientIp(req),
          authMethod: decision.method || null,
          status: 201,
          durationMs: performance.now() - t0,
          detail: { name: project.name, source: project.source }
        });
        if (project.gitRepo) {
          setImmediate(() => {
            try {
              getService('localRunner').prepareProject(project).catch((err) => {
                console.warn(`[AutoPrepare] Could not auto-prepare ${project.name}:`, err.message);
              });
            } catch (e) {}
          });
        }
        sendFastBuffer(req, res, 201, 'application/json; charset=utf-8', Buffer.from(JSON.stringify(project), 'utf8'), pathname, t0);
      } catch (err) {
        sendFastBuffer(req, res, 400, 'application/json; charset=utf-8', Buffer.from(JSON.stringify({ error: err.message }), 'utf8'), pathname, t0);
      }
    });

    req.on('error', () => {
      if (!aborted) {
        aborted = true;
        try { res.destroy(); } catch (e) {}
      }
    });
    return true;
  }

  if (method !== 'GET' && method !== 'HEAD') return false;
  return tryHandleFastPathGet(req, res, pathname, queryStr);
}

// Tabla precompilada O(1) de rutas públicas y autenticadas del fast-path HTTP
/** @type {Map<string, (req: any, res: any, pathname: string, queryStr: string) => boolean>} */
const FAST_PUBLIC_GET_ROUTES = new Map([
  ['/health', (req, res, pathname) => {
    const t0 = performance.now();
    containerOrchestrator.recordRequest();
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', getHealthBuffer(), pathname, t0);
    return true;
  }],
  ['/api/health', (req, res, pathname) => {
    const t0 = performance.now();
    containerOrchestrator.recordRequest();
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', getHealthBuffer(), pathname, t0);
    return true;
  }],
  ['/api/auth/session', (req, res, pathname) => {
    const t0 = performance.now();
    containerOrchestrator.recordRequest();
    if (req.headers.origin && !isOriginAllowed(req.headers.origin, req)) {
      metricsCollector.recordSecurityEvent('originRejected403');
      sendFastAuthError(req, res, { status: 403, error: 'Origen no permitido' }, pathname, t0);
      return true;
    }
    const decision = authorizeRequestFast(req);
    const st = getAuthStatusCached();
    const body = Buffer.from(JSON.stringify({
      authenticated: decision.ok,
      method: decision.method || null,
      requireTokenAlways: st.requireTokenAlways,
      tokenConfigured: st.tokenConfigured,
      tokenSource: st.tokenSource
    }), 'utf8');
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', body, pathname, t0);
    return true;
  }],
  ['/api/ingress/ask', (req, res, pathname, queryStr) => {
    const t0 = performance.now();
    containerOrchestrator.recordRequest();
    const askRl = fastAskLimiter.check(req);
    if (!askRl.allowed) {
      res.setHeader('Retry-After', String(askRl.retryAfterSec));
      sendFastBuffer(req, res, 429, 'text/plain; charset=utf-8', Buffer.from('demasiadas consultas', 'utf8'), pathname, t0);
      return true;
    }
    // P0: Caddy habla directamente con Culkibo sin cabeceras de proxy; rechazar tráfico reenviado desde internet vía panelDomain
    if ((req.headers['x-forwarded-for'] || req.headers.forwarded) && process.env.NODE_ENV !== 'test') {
      sendFastBuffer(req, res, 403, 'text/plain; charset=utf-8', ASK_FORBIDDEN_LOCAL_BUF, pathname, t0);
      return true;
    }
    const remoteIp = String(req.socket?.remoteAddress || '').replace(/^::ffff:/, '');
    const { isPrivateIp } = require('./services/ssrfGuard');
    const isLocalOrPrivate = remoteIp === '127.0.0.1' || remoteIp === '::1' || isPrivateIp(remoteIp);
    if (!isLocalOrPrivate && process.env.NODE_ENV !== 'test') {
      sendFastBuffer(req, res, 403, 'text/plain; charset=utf-8', ASK_FORBIDDEN_LOCAL_BUF, pathname, t0);
      return true;
    }
    const params = new URLSearchParams(queryStr);
    const domain = String(params.get('domain') || '').trim().toLowerCase().replace(/\.+$/, '');
    if (!domain) {
      sendFastBuffer(req, res, 400, 'text/plain; charset=utf-8', ASK_MISSING_DOMAIN_BUF, pathname, t0);
      return true;
    }
    if (!/^[a-z0-9.-]{1,253}$/.test(domain)) {
      sendFastBuffer(req, res, 400, 'text/plain; charset=utf-8', ASK_INVALID_DOMAIN_BUF, pathname, t0);
      return true;
    }
    const im = getService('ingressManager');
    if (!im.isHostnameAuthorizedForTls(domain)) {
      sendFastBuffer(req, res, 403, 'text/plain; charset=utf-8', Buffer.from(`dominio no configurado en Culkibo: ${domain}`, 'utf8'), pathname, t0);
      return true;
    }
    const dm = getService('domainManager');
    // Solo bloquear por `disabled` cuando existe coincidencia exacta para ese hostname
    // (evita que un wildcard *.ejemplo.com deshabilitado bloquee www.ejemplo.com de un redirect canónico activo)
    const exactMatch = typeof dm.getByHostname === 'function' ? dm.getByHostname(domain) : null;
    if (exactMatch && exactMatch.status === 'disabled') {
      sendFastBuffer(req, res, 403, 'text/plain; charset=utf-8', Buffer.from(`dominio deshabilitado: ${domain}`, 'utf8'), pathname, t0);
      return true;
    }
    sendFastBuffer(req, res, 200, 'text/plain; charset=utf-8', ASK_OK_BUF, pathname, t0);
    return true;
  }]
]);

/** @type {Map<string, (req: any, res: any, pathname: string, queryStr: string, fresh: boolean, t0: number) => boolean>} */
const FAST_AUTHED_GET_ROUTES = new Map([
  ['/metrics', (req, res, pathname, _q, fresh, t0) => {
    sendFastBuffer(req, res, 200, 'text/plain; version=0.0.4; charset=utf-8', metricsCollector.getPrometheusBuffer(fresh), pathname, t0, { compress: true });
    return true;
  }],
  ['/api/metrics', (req, res, pathname, _q, fresh, t0) => {
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', metricsCollector.getSnapshotBuffer(fresh), pathname, t0, { compress: true });
    return true;
  }],
  ['/api/observability/snapshot', (req, res, pathname, _q, fresh, t0) => {
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', metricsCollector.getSnapshotBuffer(fresh), pathname, t0, { compress: true });
    return true;
  }],
  ['/api/pods', (req, res, pathname, _q, _fresh, t0) => {
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', containerOrchestrator.getPodsSerialized(), pathname, t0, { compress: true });
    return true;
  }],
  ['/api/projects', (req, res, pathname, _q, _fresh, t0) => {
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', projectManager.getAllSerialized(), pathname, t0, {
      cacheControl: 'private, no-cache',
      etag: projectManager.getAllEtag(),
      compress: true
    });
    return true;
  }],
  ['/api/catalog', (req, res, pathname, _q, _fresh, t0) => {
    const cm = getService('catalogManager');
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', cm.getCatalogSerialized(), pathname, t0, {
      cacheControl: 'private, no-cache',
      compress: true
    });
    return true;
  }],
  ['/api/domains', (req, res, pathname, _q, _fresh, t0) => {
    const dm = getService('domainManager');
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', dm.getAllWrappedSerialized(), pathname, t0, {
      cacheControl: 'private, no-cache',
      etag: typeof dm.getWrappedEtag === 'function' ? dm.getWrappedEtag() : null,
      compress: true
    });
    return true;
  }],
  ['/api/logs', (req, res, pathname, queryStr, _fresh, t0) => {
    const params = queryStr ? new URLSearchParams(queryStr) : null;
    const logs = containerOrchestrator.getLogs({
      pod: params?.get('pod') || null,
      level: params?.get('level') || null,
      limit: params?.get('limit') ? parseInt(String(params.get('limit')), 10) : 100,
      search: params?.get('search') || '',
      projectId: params?.get('projectId') || null
    });
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', Buffer.from(JSON.stringify({ logs }), 'utf8'), pathname, t0, { compress: true });
    return true;
  }],
  ['/api/system/status', (req, res, pathname, _q, _fresh, t0) => {
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', getSystemStatusBuffer(), pathname, t0, { compress: true });
    return true;
  }],
  ['/api/sync/summary', (req, res, pathname, _q, _fresh, t0) => {
    const buf = loadedServices.liveSyncEngine
      ? Buffer.from(JSON.stringify(loadedServices.liveSyncEngine.getGlobalSummary()), 'utf8')
      : EMPTY_SYNC_SUMMARY_BUF;
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', buf, pathname, t0, { compress: true });
    return true;
  }]
]);

function tryHandleFastPathGet(req, res, pathname, queryStr) {
  // Fast-path estático para el panel web pre-comprimido (cero carga de Express al abrir el dashboard)
  if (!pathname.startsWith('/api') && pathname !== '/health' && pathname !== '/metrics' && pathname !== '/ws' && pathname !== '/ws/sync') {
    if (tryServeStaticFastPath(req, res, pathname)) return true;
    return false;
  }

  // O(1) rutas públicas precompiladas (`/health`, `/api/health`, `/api/auth/session`, `/api/ingress/ask`)
  const publicHandler = FAST_PUBLIC_GET_ROUTES.get(pathname);
  if (publicHandler) {
    return publicHandler(req, res, pathname, queryStr);
  }

  // O(1) rutas autenticadas precompiladas + `GET /api/projects/:id`
  const authedHandler = FAST_AUTHED_GET_ROUTES.get(pathname) || null;
  /** @type {string | null} */
  let projectByIdMatch = null;
  if (!authedHandler) {
    if (pathname.startsWith('/api/projects/') && pathname.indexOf('/', 14) === -1) {
      const seg = pathname.slice(14);
      if (seg && seg !== 'active') {
        try { projectByIdMatch = decodeURIComponent(seg); } catch (e) { projectByIdMatch = seg; }
      }
    }
    if (!projectByIdMatch) return false;
  }

  // Filtros avanzados o consultas estructuradas de logs pasan a Express (regex/since/until/attr, search, category)
  if (queryStr) {
    if (pathname === '/api/projects' || pathname === '/api/catalog' || pathname === '/api/domains') {
      return false;
    }
    if (pathname === '/api/logs' && STRUCTURED_LOGS_QUERY_RE.test(queryStr)) {
      return false;
    }
  }

  const t0 = performance.now();
  const canonicalRoute = projectByIdMatch ? '/api/projects/:id' : pathname;
  containerOrchestrator.recordRequest();

  const bf = checkAuthBruteForce(req);
  if (bf.blocked) {
    metricsCollector.recordSecurityEvent('authBlocked429');
    res.setHeader('Retry-After', String(bf.retryAfterSec));
    sendFastAuthError(req, res, { status: 429, error: 'Demasiados intentos de autenticación fallidos.' }, canonicalRoute, t0);
    return true;
  }

  const decision = authorizeRequestFast(req);
  if (!decision.ok) {
    if (decision.status === 403) metricsCollector.recordSecurityEvent('originRejected403');
    const creds = extractCredentials(req, { allowWsSubprotocol: false });
    if (decision.status === 401 && (creds.token || creds.ticket || creds.cookieToken)) {
      recordAuthFailure(req);
      metricsCollector.recordSecurityEvent('authFailures');
    }
    sendFastAuthError(req, res, decision, canonicalRoute, t0);
    return true;
  }

  // Aislamiento multi-tenant estricto: todo principal no-superadmin pasa por Express RBAC + filtrado por equipo/ACL
  if (decision.principal && !decision.principal.isSuperAdmin) {
    return false;
  }

  if (projectByIdMatch) {
    const entry = projectManager.getByIdSerializedEntry(projectByIdMatch);
    if (!entry) {
      sendFastBuffer(req, res, 404, 'application/json; charset=utf-8', ERR_PROJECT_NOT_FOUND_BUF, '/api/projects/:id', t0);
      return true;
    }
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', entry.buf, '/api/projects/:id', t0, {
      cacheControl: 'private, no-cache',
      etag: entry.etag,
      compress: true
    });
    return true;
  }

  const fresh = Boolean(queryStr) && queryStr.includes('fresh=1');
  return authedHandler ? authedHandler(req, res, pathname, queryStr, fresh, t0) : false;
}

// ---------------------------------------------------------------------------
// Parser nativo UTF-8 sin `iconv-lite` ni copia duplicada de `qs`
// ---------------------------------------------------------------------------
function resolveBodyLimitBytes(reqPath) {
  if (/^\/api\/(?:migrate|import)\/wordpress\/[^/]+\/import-sql$/.test(reqPath) || reqPath === '/api/import/wordpress/import-sql') {
    return 55 * 1024 * 1024; // 55 MB para volcados SQL grandes (MAX_SQL_BYTES = 50 MB)
  }
  if (reqPath.startsWith('/api/webhooks/')) {
    return 25 * 1024 * 1024; // 25 MB para webhooks GitHub/GitLab grandes (commits masivos)
  }
  if (/^\/api\/projects\/[^/]+\/sync\/frame$/.test(reqPath)) {
    return 16 * 1024 * 1024; // 16 MB para Commit Frames HTTP
  }
  if (reqPath === '/api/backup/instance/import' || reqPath === '/api/backup/restore-upload') {
    return 10 * 1024 * 1024; // 10 MB para snapshots completos de instancia
  }
  if (reqPath.startsWith('/api/import/compose')) {
    return 2 * 1024 * 1024;
  }
  if (reqPath === '/api/telemetry/client-error') {
    return 16 * 1024; // 16 KB máximo para reportes de error del cliente SPA
  }
  return 1 * 1024 * 1024; // 1 MB por defecto (corta DoS de memoria)
}

function nativeBodyParser(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  if (req.body !== undefined) return next();

  const ct = String(req.headers['content-type'] || '').toLowerCase();
  const mediaType = ct.split(';')[0].trim();
  const isJson = mediaType === 'application/json' || (mediaType.startsWith('application/') && mediaType.endsWith('+json'));
  const isForm = mediaType === 'application/x-www-form-urlencoded';
  const isText = mediaType === 'text/plain';
  if (!isJson && !isForm && !isText) {
    req.body = {};
    return next();
  }

  const rawPath = (req.originalUrl || req.url || '').split('?')[0];
  const limitBytes = resolveBodyLimitBytes(rawPath);
  const declaredLen = Number(req.headers['content-length'] || 0);
  if (declaredLen > limitBytes) {
    req.resume();
    const err = new Error(`El cuerpo supera el límite permitido (${Math.max(1, Math.round(limitBytes / (1024 * 1024)))} MB)`);
    /** @type {any} */ (err).status = 413;
    /** @type {any} */ (err).type = 'entity.too.large';
    return next(err);
  }

  /** @type {Buffer[]} */
  const chunks = [];
  let total = 0;
  let aborted = false;

  req.on('data', (chunk) => {
    if (aborted) return;
    total += chunk.length;
    if (total > limitBytes) {
      aborted = true;
      req.resume();
      const err = new Error(`El cuerpo supera el límite permitido (${Math.max(1, Math.round(limitBytes / (1024 * 1024)))} MB)`);
      /** @type {any} */ (err).status = 413;
      /** @type {any} */ (err).type = 'entity.too.large';
      return next(err);
    }
    chunks.push(chunk);
  });

  req.on('end', () => {
    if (aborted) return;
    const buf = total > 0 ? Buffer.concat(chunks, total) : Buffer.alloc(0);
    if (rawPath.startsWith('/api/webhooks/')) {
      req.rawBody = buf;
    }
    if (buf.length === 0) {
      req.body = isText ? '' : {};
      return next();
    }
    const text = buf.toString('utf8');
    if (isJson) {
      try {
        req.body = JSON.parse(text);
        return next();
      } catch (e) {
        const err = new Error('JSON malformado en el cuerpo de la petición');
        /** @type {any} */ (err).status = 400;
        /** @type {any} */ (err).type = 'entity.parse.failed';
        return next(err);
      }
    }
    if (isForm) {
      const params = new URLSearchParams(text);
      /** @type {Record<string, string>} */
      const obj = {};
      for (const [k, v] of params.entries()) obj[k] = v;
      req.body = obj;
      return next();
    }
    req.body = text;
    return next();
  });

  req.on('error', (err) => {
    if (!aborted) {
      aborted = true;
      next(err);
    }
  });
}

// ---------------------------------------------------------------------------
// Extrae hostname limpio desde Host / X-Forwarded-Host (soporta IPv6 [::1]:3030,
// punto final FQDN y listas separadas por comas — usa el último salto si es X-Forwarded-Host).
// ---------------------------------------------------------------------------
function extractHostnameClean(rawHeader, useRightmost = false) {
  const parts = String(rawHeader || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  const chosen = useRightmost ? (parts[parts.length - 1] || '') : (parts[0] || '');
  if (!chosen) return '';
  if (chosen.startsWith('[')) {
    const end = chosen.indexOf(']');
    return (end !== -1 ? chosen.slice(1, end) : chosen).replace(/\.+$/, '');
  }
  const colon = chosen.indexOf(':');
  const hostOnly = colon === -1 ? chosen : chosen.slice(0, colon);
  return hostOnly.replace(/\.+$/, '');
}

/** @type {string | null} */
let cachedPanelDomain = null;
function loadPersistedPanelDomain() {
  if (process.env.CULKIBO_PANEL_DOMAIN) {
    cachedPanelDomain = String(process.env.CULKIBO_PANEL_DOMAIN).trim().toLowerCase();
  }
  try {
    if (fs.existsSync(INGRESS_CONFIG_FILE)) {
      const cfg = JSON.parse(fs.readFileSync(INGRESS_CONFIG_FILE, 'utf8'));
      if (cfg && typeof cfg.panelDomain === 'string' && cfg.panelDomain.trim()) {
        cachedPanelDomain = cfg.panelDomain.trim().toLowerCase();
      }
    }
  } catch (e) {}
  if (cachedPanelDomain) {
    addAllowedOrigin(`https://${cachedPanelDomain}`);
    addAllowedOrigin(`http://${cachedPanelDomain}`);
  }
}
loadPersistedPanelDomain();

// ---------------------------------------------------------------------------
// Express App (cargada perezosamente al primer request fuera del fast-path)
// ---------------------------------------------------------------------------
/** @type {any} */
let _app = null;
/** @type {Buffer | null} */
let cachedIndexHtmlBuf = null;

function getApp() {
  if (_app) return _app;

  const express = require('express');
  const cors = require('cors');
  const apiRouter = require('./routes/api');

  // Conectar eventos WS de servicios que apiRouter pudo importar
  for (const name of ['catalogManager', 'databaseManager', 'deployManager', 'mcpServer', 'liveSyncEngine', 'domainManager', 'ingressManager', 'caddyManager']) {
    try { getService(name); } catch (e) {}
  }

  const app = express();
  app.disable('x-powered-by');
  app.set('etag', false);
  app.set('trust proxy', process.env.CULKIBO_TRUST_PROXY || 'loopback');

  app.use((req, res, next) => {
    const isApi = req.path.startsWith('/api') || req.path === '/metrics';
    applySecurityHeaders(req, res, isApi);
    containerOrchestrator.recordRequest();
    const t0 = process.hrtime.bigint();
    metricsCollector.onRequestStart();
    let ended = false;
    const finish = () => {
      if (ended) return;
      ended = true;
      const rawUrl = req.originalUrl || req.url;
      metricsCollector.onRequestEnd(req.method, rawUrl, res.statusCode, Number(process.hrtime.bigint() - t0) / 1e6);
      if (res.statusCode >= 500 && isApi) {
        try {
          telemetryService.captureApi5xx({
            method: req.method,
            route: metricsCollector.canonicalizeRoute(rawUrl),
            status: res.statusCode,
            message: res.locals?.telemetryErrorMessage || `HTTP ${res.statusCode}`
          });
        } catch (e) {}
      }
    };
    res.once('finish', finish);
    res.once('close', finish);
    next();
  });

  app.use(cors(corsDelegate));
  app.use(nativeBodyParser);

  app.get('/health', (_req, res) => {
    const buf = getHealthBuffer();
    res.status(200).set('Content-Type', 'application/json; charset=utf-8').send(buf);
  });
  app.get('/api/health', (_req, res) => {
    const buf = getHealthBuffer();
    res.status(200).set('Content-Type', 'application/json; charset=utf-8').send(buf);
  });
  app.get('/metrics', authMiddleware, (req, res) => {
    const fresh = req.query.fresh === '1';
    res.status(200).set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8').send(metricsCollector.getPrometheusBuffer(fresh));
  });

  app.use('/api', authMiddleware);
  app.use('/api', apiRouter);

  // DEPRECADO — transporte HTTP+SSE de la revisión 2024-11-05 (P1-17 + dokploy#2974 cap por principal y global).
  app.get('/api/mcp/sse', (req, res) => {
    const ssePrincipal = (/** @type {any} */ (req).auth && /** @type {any} */ (req).auth.principal) || null;
    const principalKey = logStreamTracker.resolvePrincipalKey(req, ssePrincipal);
    const slot = logStreamTracker.acquire(principalKey, res, { enforcePerPrincipal: true });
    if (!slot.ok) {
      if (slot.status === 429) metricsCollector.recordSecurityEvent('rateLimited429');
      return res.status(slot.status).json({ error: slot.error, code: slot.code });
    }
    const releaseStream = slot.release;
    if (typeof req.setTimeout === 'function') req.setTimeout(0);
    if (typeof res.setTimeout === 'function') res.setTimeout(0);
    const mcpServer = getService('mcpServer');
    const mcpStreamableHttp = getService('mcpStreamableHttp');
    /** @type {any} */ (res)._authPrincipal = ssePrincipal;
    activeSseClients++;
    activeSseResponses.add(res);
    mcpStreamableHttp.markLegacyTransport(res, 'GET /api/mcp/sse');
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no'
    });

    let cleaned = false;
    /** @type {ReturnType<typeof setInterval> | null} */
    let keepalive = null;
    const onMcp = (entry) => {
      if (ssePrincipal && !ssePrincipal.isSuperAdmin) {
        const scoped = scopeWsEventForPrincipal(ssePrincipal, 'mcp_call', entry);
        if (!scoped.send) return;
        safeWrite(`event: mcp_event\ndata: ${JSON.stringify(scoped.data)}\n\n`);
        return;
      }
      safeWrite(`event: mcp_event\ndata: ${JSON.stringify(entry)}\n\n`);
    };
    const cleanup = () => {
      if (cleaned) return;
      cleaned = true;
      if (keepalive) { clearInterval(keepalive); keepalive = null; }
      activeSseResponses.delete(res);
      activeSseClients = Math.max(0, activeSseClients - 1);
      mcpServer.off('mcp_call', onMcp);
      try { if (typeof releaseStream === 'function') releaseStream(); } catch (e) {}
    };
    /** @type {any} */ (res)._streamCleanup = cleanup;
    const safeWrite = (chunk) => {
      if (res.writableEnded || res.destroyed) return;
      try { res.write(chunk); } catch (e) { cleanup(); }
    };

    keepalive = setInterval(() => safeWrite(': keepalive\n\n'), 25000);
    if (keepalive.unref) keepalive.unref();
    safeWrite(`event: endpoint\ndata: /api/mcp/message\n\n`);
    mcpServer.on('mcp_call', onMcp);
    req.on('close', cleanup);
    req.on('aborted', cleanup);
    res.on('close', cleanup);
    res.on('finish', cleanup);
    res.on('error', cleanup);
  });

  // 404 JSON explícito para rutas desconocidas bajo /api/*
  app.use('/api', (_req, res) => {
    res.status(404).json({ error: 'Endpoint de API no encontrado' });
  });

  // Plano de control vs Plano de datos (421 Misdirected Request)
  const MANAGEMENT_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1', '']);

  app.use((req, res, next) => {
    if (req.path.startsWith('/api') || req.path === '/ws' || req.path === '/health' || req.path === '/metrics') {
      return next();
    }

    const trustProxyHost = isPrivateProxyPeer(req.socket?.remoteAddress || '');
    const forwarded = trustProxyHost ? req.headers['x-forwarded-host'] : null;
    const host = extractHostnameClean(forwarded || req.headers.host || '', Boolean(forwarded));

    // Acceso directo de gestión (localhost / IPv4 / IPv6 ::1) o dominio oficial del panel (P0-8)
    const activePanelDomain = (loadedServices.ingressManager?.panelDomain || cachedPanelDomain || '').toLowerCase();
    if (activePanelDomain && host === activePanelDomain) {
      return next();
    }
    if (MANAGEMENT_HOSTS.has(host) && !forwarded) {
      return next();
    }

    const domainManager = getService('domainManager');
    const matchedRoute = domainManager.resolveRoute(host);
    if (!matchedRoute) {
      return next();
    }

    const isAuthed = authorizeRequest(req, { allowWsSubprotocol: false }).ok;
    res.status(421);
    res.setHeader('X-Culkibo-Data-Plane', 'caddy');
    res.setHeader('X-Content-Type-Options', 'nosniff');

    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      return res.json({
        error: 'Petición dirigida al plano de control',
        dataPlane: 'caddy',
        domain: host,
        ...(isAuthed ? { matchedRoute: matchedRoute.hostname, isWildcard: Boolean(matchedRoute.isWildcard) } : {}),
        routedByDaemon: false,
        message: `El daemon de Culkibo no enruta tráfico. ${host} lo sirve Caddy en los puertos 80/443. Consulta /api/ingress/status para ver si hay ruta y qué certificado se está sirviendo de verdad.`
      });
    }

    return res.type('text/plain').send(
      `Culkibo: este puerto es el plano de control, no el plano de datos.\n\n` +
      `Dominio solicitado: ${host}\n` +
      (isAuthed ? `Regla configurada:  ${matchedRoute.hostname}\n\n` : '\n') +
      `El tráfico de este dominio lo sirve Caddy en los puertos 80 y 443.\n` +
      `Comprueba el estado real del ingress en /api/ingress/status.\n`
    );
  });

  // Frontend static build (con caché en memoria de index.html + CSP)
  const webDistPath = path.join(__dirname, '..', 'web', 'dist');
  const indexHtmlPath = path.join(webDistPath, 'index.html');
  if (fs.existsSync(webDistPath)) {
    try {
      if (fs.existsSync(indexHtmlPath)) {
        cachedIndexHtmlBuf = fs.readFileSync(indexHtmlPath);
      }
    } catch (e) {}

    app.use(express.static(webDistPath, {
      index: false,
      setHeaders: (res, filePath) => {
        if (filePath.includes('/assets/') || filePath.includes('\\assets\\')) {
          res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        } else if (filePath.endsWith('index.html')) {
          res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
          res.setHeader('Content-Security-Policy', SPA_CSP);
        }
      }
    }));

    app.use((req, res, next) => {
      if (!req.path.startsWith('/api') && req.method === 'GET') {
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Content-Security-Policy', SPA_CSP);
        if (cachedIndexHtmlBuf) {
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          return res.status(200).send(cachedIndexHtmlBuf);
        }
        return res.sendFile(indexHtmlPath);
      }
      next();
    });
  } else {
    app.get('/', (_req, res) => {
      res.setHeader('Content-Security-Policy', SPA_CSP);
      res.send(`
        <html lang="es">
          <head><meta charset="utf-8"><title>Daemon de Culkibo v${APP_VERSION}</title><style>body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#fafafa;color:#18181b;padding:40px;text-align:center;}code{background:#f4f4f5;border:1px solid #e4e4e7;border-radius:6px;padding:1px 5px;}</style></head>
          <body>
            <h1>Daemon de Culkibo v${APP_VERSION} en marcha</h1>
            <p>API REST y WebSocket escuchando en el puerto ${PORT}.</p>
            <p>Compila el panel con <code>npm run build</code>, o arráncalo en modo desarrollo en el puerto 5173.</p>
          </body>
        </html>
      `);
    });
  }

  // Manejador de errores limpio (sin reportFatal para 400/413, sanitizado en producción)
  app.use((err, req, res, next) => {
    const status = err.status || err.statusCode || 500;
    const reqPath = String(req?.originalUrl || req?.url || '').split('?')[0];
    if (err.type === 'entity.parse.failed') {
      if (res.headersSent) return next(err);
      if (reqPath === '/api/mcp' || reqPath === '/api/mcp/message') {
        return res.status(400).json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error: JSON malformado' } });
      }
      return res.status(400).json({ error: 'JSON malformado en el cuerpo de la petición' });
    }
    if (err.type === 'entity.too.large' || status === 413) {
      if (res.headersSent) return next(err);
      res.setHeader('Connection', 'close');
      return res.status(413).json({ error: err.message || 'El tamaño de la petición supera el límite permitido' });
    }
    const errorId = crypto.randomBytes(4).toString('hex');
    if (status >= 500) {
      reportFatal(`requestError:${errorId}`, err);
    }
    if (res.headersSent) return next(err);
    const isProd = process.env.NODE_ENV === 'production';
    res.status(status).json({
      error: (isProd && status >= 500) ? 'Error interno del servidor' : (err.message || 'Error interno del servidor'),
      ...(status >= 500 ? { errorId } : {})
    });
  });

  _app = app;
  return _app;
}

// ---------------------------------------------------------------------------
// Servidor HTTP híbrido (fast-path crudo O(1) + fallback Express perezoso)
// ---------------------------------------------------------------------------
const server = http.createServer(
  { noDelay: true, keepAlive: true, keepAliveInitialDelay: 30000 },
  (req, res) => {
    if (shuttingDown) {
      res.writeHead(503, {
        'Content-Type': 'application/json; charset=utf-8',
        'Connection': 'close'
      });
      res.end('{"error":"Servidor cerrándose ordenadamente"}');
      return;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      const u = req.url || '';
      if (u.startsWith('/api/auth/') || u.startsWith('/api/teams')) {
        invalidateFastAuthCaches();
      }
    }
    if (tryHandleFastPath(req, res)) return;
    getApp()(req, res);
  }
);
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;
server.requestTimeout = 300000;

server.on('upgrade', (req, socket, head) => {
  if (shuttingDown) {
    socket.write('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }
  const rawUrl = req.url || '/';
  const qIdx = rawUrl.indexOf('?');
  const pathname = qIdx === -1 ? rawUrl : rawUrl.slice(0, qIdx);

  if (pathname !== '/ws' && pathname !== '/ws/sync') {
    socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }

  // P0: aplicar protección anti fuerza bruta también en upgrades WebSocket
  const bf = checkAuthBruteForce(req);
  if (bf.blocked) {
    metricsCollector.recordSecurityEvent('authBlocked429');
    metricsCollector.recordSecurityEvent('wsAuthRejected');
    socket.write(`HTTP/1.1 429 Too Many Requests\r\nRetry-After: ${bf.retryAfterSec}\r\nConnection: close\r\n\r\n`);
    socket.destroy();
    return;
  }

  const decision = authorizeRequest(req, { allowWsSubprotocol: true });
  if (!decision.ok) {
    metricsCollector.recordSecurityEvent('wsAuthRejected');
    if (decision.status === 403) {
      metricsCollector.recordSecurityEvent('originRejected403');
    } else if (decision.status === 401) {
      recordAuthFailure(req);
      metricsCollector.recordSecurityEvent('authFailures');
      auditLogger.record({
        source: 'ws',
        action: 'ws.auth_rejected',
        path: pathname,
        ip: clientIp(req),
        status: 401,
        detail: { reason: decision.error }
      });
    }
    const code = decision.status === 403 ? '403 Forbidden' : '401 Unauthorized';
    socket.write(`HTTP/1.1 ${code}\r\nConnection: close\r\n\r\n`);
    socket.destroy();
    return;
  }

  /** @type {any} */ (req)._wsPrincipal = decision.principal || null;

  // dokploy#2974: limitar streams WS de telemetría/logs por principal (10) y global (50) con limpieza garantizada
  if (pathname === '/ws') {
    const queryStr = qIdx === -1 ? '' : rawUrl.slice(qIdx + 1);
    const isExplicitLogStream = /(?:^|&)(?:channel|stream)=logs(?:&|$)/i.test(queryStr);
    const enforcePerPrincipal =
      isExplicitLogStream ||
      process.env.CULKIBO_STRICT_WS_CAP === '1' ||
      (decision.method !== 'loopback' && decision.method !== 'loopback_origin');
    const principalKey = logStreamTracker.resolvePrincipalKey(req, decision.principal);
    const slot = logStreamTracker.acquire(principalKey, socket, { enforcePerPrincipal });
    if (!slot.ok) {
      if (slot.status === 429) metricsCollector.recordSecurityEvent('rateLimited429');
      const statusLine = slot.status === 429 ? '429 Too Many Requests' : '503 Service Unavailable';
      socket.write(`HTTP/1.1 ${statusLine}\r\nX-Culkibo-Stream-Cap: ${slot.code}\r\nConnection: close\r\n\r\n`);
      socket.destroy();
      return;
    }
    const releaseWsSlot = slot.release;
    if (typeof releaseWsSlot === 'function') {
      /** @type {any} */ (req)._wsStreamRelease = releaseWsSlot;
      socket.once('close', releaseWsSlot);
      socket.once('error', releaseWsSlot);
    }
  }

  const { wss, syncWss } = ensureWsServers();
  const target = pathname === '/ws/sync' ? syncWss : wss;
  // Coalescencia 101 Switching Protocols + initial_state en 1 solo segmento TCP
  if (typeof socket.cork === 'function') socket.cork();
  try {
    target.handleUpgrade(req, socket, head, (ws) => {
      target.emit('connection', ws, req);
    });
  } finally {
    if (typeof socket.uncork === 'function') socket.uncork();
  }
});

// ---------------------------------------------------------------------------
// Arranque, watchdogs silenciosos y apagado limpio
// ---------------------------------------------------------------------------
function hasScheduledDatabaseBackups() {
  try {
    const dbFile = path.join(DATA_DIR, 'databases.json');
    if (!fs.existsSync(dbFile)) return false;
    const parsed = JSON.parse(fs.readFileSync(dbFile, 'utf8'));
    const list = Array.isArray(parsed) ? parsed : (Array.isArray(parsed?.databases) ? parsed.databases : []);
    return list.some((d) => Boolean(d && d.schedule && d.schedule.enabled));
  } catch (e) {
    return false;
  }
}

function hasEnabledCronJobs() {
  try {
    const cronFile = path.join(DATA_DIR, 'crons.json');
    if (!fs.existsSync(cronFile)) return false;
    const parsed = JSON.parse(fs.readFileSync(cronFile, 'utf8'));
    const list = Array.isArray(parsed) ? parsed : (Array.isArray(parsed?.jobs) ? parsed.jobs : []);
    return list.some((j) => Boolean(j && j.enabled));
  } catch (e) {
    return false;
  }
}

function sweepStaleTmpFiles() {
  const cutoff = Date.now() - 3600 * 1000;
  const dirs = [
    { dir: path.join(DATA_DIR, '.tmp'), prefix: null },
    { dir: path.join(DATA_DIR, 'tmp'), prefix: null },
    { dir: os.tmpdir(), prefix: 'culkibo-git-' }
  ];
  for (const { dir, prefix } of dirs) {
    try {
      if (!fs.existsSync(dir)) continue;
      for (const f of fs.readdirSync(dir)) {
        if (prefix && !f.startsWith(prefix)) continue;
        try {
          const p = path.join(dir, f);
          if (fs.statSync(p).mtimeMs < cutoff) {
            fs.rmSync(p, { recursive: true, force: true });
          }
        } catch (e) {}
      }
    } catch (e) {}
  }
}

/** @type {Array<ReturnType<typeof setInterval> | ReturnType<typeof setTimeout>>} */
const backgroundTimers = [];
/** @type {string | null} */
let lastWatchdogAt = null;
let lastDiskAlertAt = 0;
let lastTlsAuditAt = 0;

function trackTimer(t) {
  if (t && typeof t.unref === 'function') t.unref();
  backgroundTimers.push(t);
  return t;
}

/**
 * @param {number} port
 * @param {string} host
 * @param {{ reconcileIngress?: boolean, startWatchdogs?: boolean }} [options]
 */
function startServer(port = PORT, host = '127.0.0.1', {
  reconcileIngress = process.env.CULKIBO_SKIP_RECONCILE !== '1',
  startWatchdogs
} = {}) {
  const isTestOrBenchArgv = /[\\/](?:tests|bench)[\\/]/.test((process.argv || []).join(' ').toLowerCase());
  const enableWatchdogs = startWatchdogs !== undefined
    ? Boolean(startWatchdogs)
    : (process.env.NODE_ENV !== 'test' && reconcileIngress !== false && !isTestOrBenchArgv);
  shuttingDown = false;
  shutdownPromise = null;
  return new Promise((resolve, reject) => {
    server.listen(port, host, () => {
      console.log(`\n========================================================`);
      console.log(`🚀 Culkibo Orchestrator v${APP_VERSION} Daemon running`);
      console.log(`📡 REST API:          http://localhost:${port}/api`);
      console.log(`📊 Prometheus:        http://localhost:${port}/metrics`);
      console.log(`🤖 MCP ${MCP_PROTOCOL_VERSION}:     POST http://localhost:${port}/api/mcp`);
      console.log(`   MCP ${MCP_LEGACY_PROTOCOL_VERSION}:      http://localhost:${port}/api/mcp/sse  (deprecado)`);
      console.log(`⚡ WebSocket Stream:  ws://localhost:${port}/ws`);
      console.log(`✨ Dashboard:         http://localhost:${port}`);

      const auth = authStatus();
      resolveToken();
      console.log(`--------------------------------------------------------`);
      console.log(`🔐 Acceso: token en ${auth.tokenSource}`);
      metricsCollector.setBootMs(performance.now() - BOOT_START_MS);
      console.log(`   Orígenes permitidos: ${auth.allowedOrigins.join(', ')}`);
      if (host !== '127.0.0.1' && host !== 'localhost' && !auth.requireTokenAlways) {
        console.log(`   ⚠  Escuchando en ${host}. Si el puerto es alcanzable desde fuera,`);
        console.log(`      exige token siempre con CULKIBO_REQUIRE_TOKEN=1`);
      }
      console.log(`========================================================\n`);

      // Tareas post-arranque no bloqueantes (WS y servicios pesados se cargan estrictamente bajo demanda)
      setImmediate(() => {
        sweepStaleTmpFiles();

        if (process.env.CULKIBO_WATCH_DIR) {
          try {
            containerOrchestrator.watchDirectory(process.env.CULKIBO_WATCH_DIR);
          } catch (e) {
            console.warn('[Watcher] No se pudo observar CULKIBO_WATCH_DIR:', e.message);
          }
        }

        if (hasScheduledDatabaseBackups()) {
          try {
            getService('databaseManager').startScheduler();
          } catch (e) {
            console.warn('[Databases] No se pudo arrancar el planificador de copias:', e.message);
          }
        }

        if (hasEnabledCronJobs()) {
          try {
            getService('cronManager').startScheduler();
          } catch (e) {
            console.warn('[Cron] No se pudo arrancar el planificador cron:', e.message);
          }
        }

        if (fs.existsSync(path.join(DATA_DIR, 'previews.json'))) {
          try {
            const pm = getService('previewManager');
            pm.startReaper();
            if (loadedServices.ingressManager) pm.hydrateIngressRoutes(loadedServices.ingressManager);
          } catch (e) {}
        }

        if (fs.existsSync(path.join(DATA_DIR, 'uptime.json'))) {
          try { getService('uptimeMonitor').start(); } catch (e) {}
        }
        if (fs.existsSync(path.join(DATA_DIR, 'sleep-policies.json'))) {
          try { getService('sleepAdvisor').start(); } catch (e) {}
        }
        if (fs.existsSync(path.join(DATA_DIR, 'servers.json'))) {
          try { getService('serverFleetManager').startMonitor(); } catch (e) {}
        }

        if (reconcileIngress) {
          try {
            const im = getService('ingressManager');
            if (fs.existsSync(path.join(DATA_DIR, 'previews.json'))) {
              try { getService('previewManager').hydrateIngressRoutes(im); } catch (e) {}
            }
            im.bootstrap({ port }).catch((err) => {
              console.warn('[Edge:Ingress] La reconciliación de arranque falló:', err.message);
            });
          } catch (e) {}
        }

        // Telemetría anónima y reporte automático de fallos (cero bloqueo en arranque)
        try {
          telemetryService.setHeartbeatCollector(() => {
            const projects = projectManager.getAll ? projectManager.getAll() : [];
            const dbs = loadedServices.databaseManager?.list ? loadedServices.databaseManager.list() : [];
            const svcs = loadedServices.catalogManager?.listInstallations ? loadedServices.catalogManager.listInstallations() : [];
            const doms = loadedServices.domainManager?.listDomains ? loadedServices.domainManager.listDomains() : [];
            const crons = loadedServices.cronManager?.list ? loadedServices.cronManager.list().filter((c) => c.enabled) : [];
            const wildcards = loadedServices.ingressManager?.listWildcardPolicies ? loadedServices.ingressManager.listWildcardPolicies() : [];
            const s3Cfg = loadedServices.databaseManager?.getS3Config ? loadedServices.databaseManager.getS3Config() : null;
            return {
              projectsCount: projects.length,
              databasesCount: dbs.length,
              catalogServicesCount: svcs.length,
              domainsCount: doms.length,
              activeCronsCount: crons.length,
              dockerAvailable: loadedServices.deployManager?.dockerChecked ? Boolean(loadedServices.deployManager?.dockerAvailable) : null,
              caddyAvailable: loadedServices.caddyManager?.lastDetection ? Boolean(loadedServices.caddyManager.lastDetection.available) : null,
              hasWildcard: wildcards.length > 0,
              hasS3: Boolean(s3Cfg && s3Cfg.configured),
              hasNotifications: Boolean(loadedServices.notificationService?.config?.enabled),
              hasLiveSync: Boolean(loadedServices.liveSyncEngine && loadedServices.liveSyncEngine.sessions.size > 0),
              hasMcpUsed: Boolean(loadedServices.mcpServer && loadedServices.mcpServer.auditLog.length > 0),
              hasCloudflare: doms.some((d) => Boolean(d.cloudflareProxied))
            };
          });
          telemetryService.start();
        } catch (e) {}

        // Limpieza periódica no intrusiva de sesiones Live Sync inactivas (cada 5 min)
        trackTimer(setInterval(() => {
          if (loadedServices.liveSyncEngine && typeof loadedServices.liveSyncEngine.evictIdleSessions === 'function') {
            loadedServices.liveSyncEngine.evictIdleSessions();
          }
        }, 5 * 60 * 1000));

        // Watchdogs silenciosos de producción, observabilidad v1.1, disco, temporales y TLS (no activos en tests/bench)
        if (enableWatchdogs) {
          try { const mh = getService('metricsHistory'); if (typeof mh.start === 'function') mh.start(); } catch (e) {}
          try { const ae = getService('alertEngine'); if (typeof ae.start === 'function') ae.start(); } catch (e) {}
          const runProdWatchdog = async () => {
            lastWatchdogAt = new Date().toISOString();
            try {
              const hasDeployStore = Boolean(loadedServices.deployManager) || fs.existsSync(path.join(DATA_DIR, 'deployments.json'));
              if (hasDeployStore) {
                await getService('deployManager').checkProductionHealth();
              }
            } catch (e) {}
            try {
              if (loadedServices.caddyManager && loadedServices.caddyManager.lastDetection?.available && loadedServices.ingressManager) {
                const det = await loadedServices.caddyManager.detect({ force: true });
                if (det && det.available) {
                  const st = await loadedServices.ingressManager.status();
                  if (st && st.inSync === false) {
                    await loadedServices.ingressManager.reconcile().catch(() => {});
                  }
                }
              }
            } catch (e) {}
          };

          const runSystemHygieneWatchdog = async () => {
            sweepStaleTmpFiles();
            const now = Date.now();
            // 1. Alerta de disco bajo (cooldown 6 horas)
            if (typeof fs.statfsSync === 'function' && (now - lastDiskAlertAt >= 6 * 3600 * 1000)) {
              try {
                const st = fs.statfsSync(DATA_DIR);
                const totalGb = (st.blocks * st.bsize) / (1024 ** 3);
                const freeGb = (st.bavail * st.bsize) / (1024 ** 3);
                const usedPct = totalGb > 0 ? Math.round(((totalGb - freeGb) / totalGb) * 100) : 0;
                if (freeGb < 5 || usedPct >= 85) {
                  lastDiskAlertAt = now;
                  const ns = /** @type {any} */ (require('./services/notificationService'));
                  ns.notify({
                    event: 'disk_warning',
                    level: freeGb < 2 || usedPct >= 92 ? 'error' : 'warning',
                    title: freeGb < 2 ? 'Disco crítico en el servidor' : 'Poco espacio libre en disco',
                    message: `Quedan ${freeGb.toFixed(1)} GB libres (${usedPct}% usado). Ejecuta la limpieza de caché BuildKit desde Ajustes → Doctor.`,
                    cooldownMs: 6 * 3600 * 1000
                  }).catch(() => {});
                }
              } catch (e) {}
            }
            // 2. Auditoría de caducidad TLS cada 6 horas
            if (now - lastTlsAuditAt >= 6 * 3600 * 1000) {
              lastTlsAuditAt = now;
              try {
                const im = getService('ingressManager');
                if (typeof im.checkCertificateExpiry === 'function') {
                  await im.checkCertificateExpiry({ warnDays: 14 });
                }
              } catch (e) {}
            }
          };

          trackTimer(setTimeout(() => { runProdWatchdog().catch(() => {}); }, 30000));
          trackTimer(setInterval(() => { runProdWatchdog().catch(() => {}); }, 60000));
          trackTimer(setTimeout(() => { runSystemHygieneWatchdog().catch(() => {}); }, 90000));
          trackTimer(setInterval(() => { runSystemHygieneWatchdog().catch(() => {}); }, 15 * 60 * 1000));
        }
      });

      resolve(server);
    }).on('error', (err) => {
      console.error(`❌ Failed to start server on port ${port}:`, err.message);
      reject(err);
    });
  });
}

let shuttingDown = false;
/** @type {Promise<void> | null} */
let shutdownPromise = null;

function shutdown(signal = 'SIGTERM') {
  if (shutdownPromise) return shutdownPromise;
  shuttingDown = true;
  shutdownPromise = (async () => {
    console.log(`\n[Culkibo] Recibida señal ${signal}; cerrando limpiamente...`);

    // 1. Parar temporizadores, watchdogs y planificadores
    for (const t of backgroundTimers) {
      try { clearInterval(t); clearTimeout(t); } catch (e) {}
    }
    backgroundTimers.length = 0;
    try { if (heartbeatTimer) { clearInterval(heartbeatTimer); heartbeatTimer = null; } } catch (e) {}
    try { metricsCollector.stop(); } catch (e) {}
    try { if (loadedServices.databaseManager) loadedServices.databaseManager.stopScheduler(); } catch (e) {}
    try { if (loadedServices.cronManager) loadedServices.cronManager.stopScheduler(); } catch (e) {}
    try { if (loadedServices.previewManager) loadedServices.previewManager.stopReaper(); } catch (e) {}
    try { if (loadedServices.uptimeMonitor) loadedServices.uptimeMonitor.shutdown(); } catch (e) {}
    try { if (loadedServices.sleepAdvisor) loadedServices.sleepAdvisor.shutdown(); } catch (e) {}
    try {
      if (loadedServices.metricsHistory) {
        if (typeof loadedServices.metricsHistory.shutdown === 'function') loadedServices.metricsHistory.shutdown();
        else if (typeof loadedServices.metricsHistory.stop === 'function') loadedServices.metricsHistory.stop();
      }
    } catch (e) {}
    try {
      if (loadedServices.alertEngine) {
        if (typeof loadedServices.alertEngine.shutdown === 'function') loadedServices.alertEngine.shutdown();
        else if (typeof loadedServices.alertEngine.stop === 'function') loadedServices.alertEngine.stop();
      }
    } catch (e) {}
    try { if (loadedServices.serverFleetManager) await loadedServices.serverFleetManager.shutdown(); } catch (e) {}

    // 2. Dejar de aceptar nuevas conexiones y cerrar WS/SSE activos (sin cortar peticiones HTTP en vuelo)
    const serverClosed = new Promise((resolve) => {
      try {
        server.close(() => resolve(undefined));
        if (typeof server.closeIdleConnections === 'function') server.closeIdleConnections();
      } catch (e) { resolve(undefined); }
    });

    try {
      for (const ws of [...clients, ...syncClients]) {
        if (typeof /** @type {any} */ (ws)._streamCleanup === 'function') {
          try { /** @type {any} */ (ws)._streamCleanup(); } catch (e) {}
        }
        try { ws.close(1001, 'Server shutting down'); } catch (e) {}
      }
      for (const res of Array.from(activeSseResponses)) {
        if (typeof /** @type {any} */ (res)._streamCleanup === 'function') {
          try { /** @type {any} */ (res)._streamCleanup(); } catch (e) {}
        }
        try { res.end(); } catch (e) {}
      }
      activeSseResponses.clear();
      logStreamTracker.releaseAll();
      if (_wss) _wss.close();
      if (_syncWss) _syncWss.close();
    } catch (e) {}

    // 3. Drenar peticiones HTTP en vuelo (máx 4 s)
    const drainDeadline = Date.now() + 4000;
    while (metricsCollector.inFlight > 0 && Date.now() < drainDeadline) {
      await new Promise((r) => setTimeout(r, 50));
    }

    // 4. Parar orquestador, procesos locales y drenajes de despliegue (deteniendo contenedores salientes)
    try { await containerOrchestrator.stop(); } catch (e) {}
    try {
      if (containerOrchestrator._localRunner && containerOrchestrator._localRunner.activeRunners) {
        const localRunner = containerOrchestrator._localRunner;
        const stops = [];
        for (const [pid, runner] of Array.from(localRunner.activeRunners.entries())) {
          stops.push(localRunner.stop(pid, runner.port).catch(() => {}));
        }
        await Promise.allSettled(stops);
      }
    } catch (e) {}
    try {
      const dm = loadedServices.deployManager;
      if (dm) {
        if (typeof dm.flushDrainsForShutdown === 'function') {
          await dm.flushDrainsForShutdown({ timeoutMs: 3500 });
        } else if (typeof dm.cancelAllDrains === 'function') {
          dm.cancelAllDrains();
        }
      }
    } catch (e) {}
    try {
      if (loadedServices.caddyManager && loadedServices.caddyManager.httpAgent) {
        loadedServices.caddyManager.httpAgent.destroy();
      }
    } catch (e) {}

    // 5. Volcado final atómico a disco + envío best-effort de telemetría de sesión/fallos (máx 1.5 s)
    try { await telemetryService.flushBestEffort({ timeoutMs: 1500 }); } catch (e) {}
    try { containerOrchestrator.flushLogsToDisk(); } catch (e) {}
    try { await projectManager.flushToDisk(); } catch (e) {}
    try { auditLogger.flushSync(); } catch (e) {}

    // 6. Cierre final de conexiones remanentes
    await Promise.race([
      serverClosed,
      new Promise((resolve) => {
        const t = setTimeout(() => {
          try { if (typeof server.closeAllConnections === 'function') server.closeAllConnections(); } catch (e) {}
          resolve(undefined);
        }, 1500);
        if (t.unref) t.unref();
      })
    ]);
  })();
  return shutdownPromise;
}

if (require.main === module) {
  const bindHost = process.env.CULKIBO_BIND || process.env.HOST || process.env.CULKIBO_HOST || '127.0.0.1';
  startServer(PORT, bindHost).catch(() => {
    process.exit(1);
  });
  for (const sig of ['SIGTERM', 'SIGINT']) {
    process.on(sig, () => {
      const failsafe = setTimeout(() => process.exit(1), 25000);
      if (failsafe.unref) failsafe.unref();
      shutdown(sig).finally(() => process.exit(0));
    });
  }
}

const exported = {
  server,
  broadcast,
  startServer,
  shutdown,
  getApp,
  logStreamTracker,
  createLogStreamTracker,
  MAX_LOG_STREAMS_PER_PRINCIPAL,
  MAX_LOG_STREAMS_GLOBAL,
  getRuntimeMeta: () => ({
    lastWatchdogAt,
    activeWsClients: clients.size,
    activeSyncClients: syncClients.size,
    activeSseClients,
    logStreams: logStreamTracker.getStats()
  })
};
Object.defineProperty(exported, 'app', { get: getApp, enumerable: true });
Object.defineProperty(exported, 'wss', { get: () => ensureWsServers().wss, enumerable: true });
Object.defineProperty(exported, 'syncWss', { get: () => ensureWsServers().syncWss, enumerable: true });
module.exports = exported;
