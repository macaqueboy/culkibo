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
const {
  authMiddleware,
  authorizeRequest,
  corsDelegate,
  resolveToken,
  authStatus,
  isLoopback,
  isOriginAllowed,
  addAllowedOrigin,
  checkAuthBruteForce,
  recordAuthFailure
} = require('./middleware/auth');

const PORT = Number(process.env.PORT) || 3030;
const MCP_PROTOCOL_VERSION = '2026-07-28';
const MCP_LEGACY_PROTOCOL_VERSION = '2024-11-05';
const DATA_DIR = path.join(__dirname, '..', 'data');
const INGRESS_CONFIG_FILE = path.join(DATA_DIR, 'ingress.json');

// ---------------------------------------------------------------------------
// Global crash barrier (supervisa procesos hijos, watchers y sockets).
// ---------------------------------------------------------------------------
function reportFatal(kind, err) {
  const detail = err && err.stack ? err.stack : String(err);
  console.error(`[Culkibo:${kind}]`, detail);
  try {
    containerOrchestrator.addLog('ERROR', 'edge', `[Daemon:${kind}] ${err && err.message ? err.message : String(err)}`);
  } catch (e) {}
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
      svc.on('deploy_event', (data) => broadcast('deploy_event', data));
      svc.on('deploy_log', (data) => broadcast('deploy_log', data));
      break;
    case 'ingressManager':
      svc = require('./services/ingressManager');
      break;
    case 'caddyManager':
      svc = require('./services/caddyManager');
      break;
    case 'mcpServer':
      svc = require('./services/mcpServer');
      svc.on('mcp_call', (data) => broadcast('mcp_call', data));
      break;
    case 'mcpStreamableHttp':
      svc = require('./services/mcpStreamableHttp');
      break;
    case 'liveSyncEngine':
      svc = require('./services/liveSyncEngine');
      svc.on('sync_applied', (data) => {
        broadcast('sync_applied', data);
        containerOrchestrator.addLog(
          'HOT_SYNC',
          'forge',
          `[Forge:LiveSync] Frame #${data.seq} (${data.written} escritos, ${data.deleted} borrados, ${data.dedupSkipped} sin cambios) aplicado en ${data.applyMs}ms [${data.mode}]`,
          new Date(),
          data.projectId
        );
      });
      svc.on('sync_rollback', (data) => {
        broadcast('sync_rollback', data);
        containerOrchestrator.addLog(
          'INFO',
          'forge',
          `[Forge:Rollback] Revertidos ${data.restoredFiles.length} fichero(s) en ${data.durationMs}ms`,
          new Date(),
          data.projectId
        );
      });
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
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'"
].join('; ');

function applySecurityHeaders(req, res, isApiOrMetrics) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  const proto = req.headers['x-forwarded-proto'];
  if ((req.socket && req.socket.encrypted) || (proto && String(proto).split(',')[0].trim() === 'https')) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  if (isApiOrMetrics) {
    res.setHeader('Cache-Control', 'no-store');
  }
}

// ---------------------------------------------------------------------------
// Estado WebSocket (carga perezosa de `ws` al primer upgrade)
// ---------------------------------------------------------------------------
const clients = new Set();
const syncClients = new Set();
let activeSseClients = 0;
let wsConnectionsTotal = 0;
let wsBroadcastsTotal = 0;
const MAX_SSE_CLIENTS = 50;

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

/** @param {string} type @param {any} data */
function broadcast(type, data) {
  if (clients.size === 0) return;
  wsBroadcastsTotal++;
  // Pre-codifica una única vez como Buffer UTF-8 (`binary: false` -> opcode texto 0x01)
  const payload = Buffer.from(JSON.stringify({ type, data, timestamp: new Date().toISOString() }), 'utf8');
  for (const client of clients) {
    if (client.readyState === 1) {
      client.send(payload, { binary: false }, (err) => {
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

// Caché de 150 ms del payload inicial de `/ws` como Buffer UTF-8
/** @type {{ at: number, buf: Buffer } | null} */
let cachedInitialState = null;
function getInitialWsPayloadBuf() {
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

/** Valida si un targetDir explícito está permitido en /ws/sync (anti-escritura arbitraria). */
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
  const dataRoot = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..');
  const allowedRoots = [path.resolve(dataRoot, 'projects'), path.resolve(process.cwd(), 'projects'), path.resolve(os.tmpdir())];
  const inside = allowedRoots.some((root) => {
    const rel = path.relative(root, resolved);
    return rel && rel !== '.' && !rel.startsWith('..') && !path.isAbsolute(rel);
  });
  if (!inside) {
    const err = new Error('targetDir fuera de los directorios de trabajo permitidos');
    /** @type {any} */ (err).code = 'TARGET_DIR_FORBIDDEN';
    throw err;
  }
  return resolved;
}

/**
 * Decodifica una trama binaria rápida de Commit Frame (`/ws/sync`):
 * `[1B magic 0x01][4B uint32BE metaLen][JSON meta][buffers concatenados]`
 * @param {Buffer} buf
 */
function decodeBinarySyncFrame(buf) {
  if (buf.length < 5 || buf[0] !== 0x01) {
    throw new Error('Trama binaria de sincronización inválida');
  }
  const metaLen = buf.readUInt32BE(1);
  const headerEnd = 5 + metaLen;
  if (headerEnd > buf.length) {
    throw new Error('Cabecera de trama binaria truncada');
  }
  const meta = JSON.parse(buf.subarray(5, headerEnd).toString('utf8'));
  let offset = headerEnd;
  const files = (meta.files || []).map((f) => {
    if (f.op === 'delete') return { path: f.path, op: 'delete' };
    const byteLen = Number(f.byteLength || 0);
    if (!Number.isInteger(byteLen) || byteLen < 0 || offset + byteLen > buf.length) {
      throw new Error(`Longitud binaria inválida para ${f.path}`);
    }
    const contentBuf = buf.subarray(offset, offset + byteLen);
    offset += byteLen;
    return {
      path: f.path,
      op: 'upsert',
      buffer: contentBuf,
      sha256: f.sha256
    };
  });
  return { ...meta, type: 'frame', files };
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

function ensureWsServers() {
  if (_wss && _syncWss) return { wss: _wss, syncWss: _syncWss };
  const { WebSocketServer } = require('ws');
  _wss = new WebSocketServer({ noServer: true, clientTracking: false, maxPayload: 64 * 1024, perMessageDeflate: false });
  _syncWss = new WebSocketServer({ noServer: true, clientTracking: false, maxPayload: 16 * 1024 * 1024, perMessageDeflate: false });

  _syncWss.on('connection', (ws, req) => {
    syncClients.add(ws);
    wsConnectionsTotal++;
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });

    const liveSyncEngine = getService('liveSyncEngine');
    /** @type {string | null} */
    let boundProjectId = null;
    /** @type {{ rawDir: any, safeDir: string | null } | null} */
    let cachedDirCheck = null;

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
          liveSyncEngine.unregisterClient(prev);
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
          msg = decodeBinarySyncFrame(buf);
        } else {
          msg = JSON.parse(raw.toString());
        }
      } catch (e) {
        safeWsSend(ws, { type: 'error', code: 'BAD_FRAME', error: e.message || 'Mensaje inválido' });
        return;
      }

      try {
        if (msg.type === 'hello') {
          if (!msg.projectId) throw new Error('hello requiere projectId');
          const nextPid = String(msg.projectId);
          // P1-16: validar targetDir y projectId ANTES de mutar boundProjectId o connectedClients
          const safeDir = resolveDirCached(msg.targetDir);
          liveSyncEngine.resolveTargetDir(nextPid, safeDir);
          if (safeDir) liveSyncEngine.setTargetDir(nextPid, safeDir);
          const verification = liveSyncEngine.verifySync(nextPid, {
            clientDigest: msg.clientDigest || null,
            targetDir: safeDir
          });
          let session;
          if (boundProjectId === nextPid) {
            session = liveSyncEngine.getOrCreateSession(nextPid);
          } else {
            if (boundProjectId) liveSyncEngine.unregisterClient(boundProjectId);
            boundProjectId = nextPid;
            session = liveSyncEngine.registerClient(boundProjectId);
          }
          safeWsSend(ws, {
            type: 'hello_ack',
            projectId: boundProjectId,
            lastSeq: session.lastSeq,
            serverDigest: verification.serverDigest,
            inSync: verification.inSync,
            fileCount: verification.fileCount,
            targetDir: verification.targetDir,
            binaryFramesSupported: true
          });
          broadcast('sync_client', { projectId: boundProjectId, connected: true, connectedClients: session.connectedClients });
          return;
        }

        if (msg.type === 'frame') {
          const pid = String(msg.projectId || boundProjectId || '');
          if (!pid) throw new Error('frame requiere projectId');
          const safeDir = resolveDirCached(msg.targetDir);
          const result = liveSyncEngine.applyCommitFrame(pid, msg, { targetDir: safeDir || undefined, deferEmit: true });
          safeWsSend(ws, { type: 'frame_ack', ...result });
          setImmediate(() => liveSyncEngine.emitApplied(result));
          return;
        }

        if (msg.type === 'verify') {
          const pid = String(msg.projectId || boundProjectId || '');
          if (!pid) throw new Error('verify requiere projectId');
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
          const result = liveSyncEngine.rollback(pid, msg.steps || 1);
          safeWsSend(ws, { type: 'rollback_ack', ...result });
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

  _wss.on('connection', (ws) => {
    clients.add(ws);
    wsConnectionsTotal++;
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });

    ws.on('error', () => {
      clients.delete(ws);
      try { ws.terminate(); } catch (e) {}
    });

    try {
      ws.send(getInitialWsPayloadBuf(), { binary: false });
    } catch (e) {
      clients.delete(ws);
    }

    ws.on('message', (message) => {
      try {
        const parsed = JSON.parse(message.toString());
        if (parsed.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
        }
      } catch (e) {}
    });

    ws.on('close', () => {
      clients.delete(ws);
    });
  });

  if (!heartbeatTimer) {
    heartbeatTimer = setInterval(() => {
      for (const pool of [clients, syncClients]) {
        for (const ws of pool) {
          if (ws.isAlive === false) {
            pool.delete(ws);
            try { ws.terminate(); } catch (e) {}
            continue;
          }
          ws.isAlive = false;
          try { ws.ping(); } catch (e) {
            pool.delete(ws);
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
// Fast-Path HTTP (O(1) sin capas de Express ni regex de rutas)
// ---------------------------------------------------------------------------
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
    version: '1.0.0',
    platform: process.platform,
    arch: process.arch,
    nodeVersion: process.version,
    uptimeSeconds: proc.uptimeSeconds,
    memoryUsageMb: proc.memoryMb,
    heapUsedMb: proc.heapUsedMb,
    cpuPercent: proc.cpuPercent,
    auth: authStatus(),
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

function sendFastBuffer(req, res, statusCode, contentType, buf, canonicalRoute, t0Ns) {
  /** @type {Record<string, string | number>} */
  const headers = {
    'Content-Type': contentType,
    'Content-Length': buf.length,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cache-Control': 'no-store'
  };
  const origin = req.headers.origin;
  if (origin && isOriginAllowed(origin, req)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Vary'] = 'Origin';
  }
  const proto = req.headers['x-forwarded-proto'];
  if ((req.socket && req.socket.encrypted) || (proto && String(proto).startsWith('https'))) {
    headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
  }
  res.writeHead(statusCode, headers);
  res.end(req.method === 'HEAD' ? undefined : buf);
  metricsCollector.recordFastPath(req.method, canonicalRoute, statusCode, Number(process.hrtime.bigint() - t0Ns) / 1e6);
}

function sendFastAuthError(req, res, decision, canonicalRoute, t0Ns) {
  const body = Buffer.from(JSON.stringify({
    error: decision.error,
    ...(decision.detail ? { detail: decision.detail } : {})
  }), 'utf8');
  sendFastBuffer(req, res, decision.status || 401, 'application/json; charset=utf-8', body, canonicalRoute, t0Ns);
}

function tryHandleFastPath(req, res) {
  const method = req.method;
  const rawUrl = req.url || '/';
  const qIdx = rawUrl.indexOf('?');
  const pathname = qIdx === -1 ? rawUrl : rawUrl.slice(0, qIdx);
  const queryStr = qIdx === -1 ? '' : rawUrl.slice(qIdx + 1);

  // Fast-path nativo para POST /api/projects (evita bloquear el event loop cargando
  // Express y 18 servicios auxiliares en la primera alta concurrente).
  if (method === 'POST' && pathname === '/api/projects') {
    const t0 = process.hrtime.bigint();
    containerOrchestrator.recordRequest();

    const bf = checkAuthBruteForce(req);
    if (bf.blocked) {
      res.setHeader('Retry-After', String(bf.retryAfterSec));
      sendFastAuthError(req, res, { status: 429, error: 'Demasiados intentos de autenticación fallidos.' }, pathname, t0);
      return true;
    }

    const decision = authorizeRequest(req);
    if (!decision.ok) {
      if (decision.status === 401 && (req.headers.authorization || req.headers['x-culkibo-token'])) {
        recordAuthFailure(req);
      }
      sendFastAuthError(req, res, decision, pathname, t0);
      return true;
    }

    const limitBytes = 1 * 1024 * 1024;
    const declaredLen = Number(req.headers['content-length'] || 0);
    if (declaredLen > limitBytes) {
      sendFastBuffer(req, res, 413, 'application/json; charset=utf-8', Buffer.from('{"error":"El cuerpo supera el límite permitido (1 MB)"}', 'utf8'), pathname, t0);
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
        sendFastBuffer(req, res, 413, 'application/json; charset=utf-8', Buffer.from('{"error":"El cuerpo supera el límite permitido (1 MB)"}', 'utf8'), pathname, t0);
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
          sendFastBuffer(req, res, 400, 'application/json; charset=utf-8', Buffer.from('{"error":"JSON malformado en el cuerpo de la petición"}', 'utf8'), pathname, t0);
          return;
        }
      }
      try {
        const project = projectManager.create(body);
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

  if (pathname === '/health' || pathname === '/api/health') {
    const t0 = process.hrtime.bigint();
    containerOrchestrator.recordRequest();
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', getHealthBuffer(), pathname, t0);
    return true;
  }

  if (
    pathname !== '/metrics' &&
    pathname !== '/api/metrics' &&
    pathname !== '/api/observability/snapshot' &&
    pathname !== '/api/pods' &&
    pathname !== '/api/projects' &&
    pathname !== '/api/catalog' &&
    pathname !== '/api/domains' &&
    pathname !== '/api/system/status' &&
    pathname !== '/api/sync/summary'
  ) {
    return false;
  }

  // `/api/projects?search=...` o `/api/catalog?category=...` pasan a Express si hay filtros de consulta
  if (queryStr && (pathname === '/api/projects' || pathname === '/api/catalog' || pathname === '/api/domains')) {
    return false;
  }

  const t0 = process.hrtime.bigint();
  containerOrchestrator.recordRequest();

  const bf = checkAuthBruteForce(req);
  if (bf.blocked) {
    res.setHeader('Retry-After', String(bf.retryAfterSec));
    sendFastAuthError(req, res, { status: 429, error: 'Demasiados intentos de autenticación fallidos.' }, pathname, t0);
    return true;
  }

  const decision = authorizeRequest(req);
  if (!decision.ok) {
    if (decision.status === 401 && (req.headers.authorization || req.headers['x-culkibo-token'])) {
      recordAuthFailure(req);
    }
    sendFastAuthError(req, res, decision, pathname, t0);
    return true;
  }

  const fresh = queryStr.includes('fresh=1');

  if (pathname === '/metrics') {
    sendFastBuffer(req, res, 200, 'text/plain; version=0.0.4; charset=utf-8', metricsCollector.getPrometheusBuffer(fresh), pathname, t0);
    return true;
  }
  if (pathname === '/api/metrics' || pathname === '/api/observability/snapshot') {
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', metricsCollector.getSnapshotBuffer(fresh), pathname, t0);
    return true;
  }
  if (pathname === '/api/pods') {
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', containerOrchestrator.getPodsSerialized(), pathname, t0);
    return true;
  }
  if (pathname === '/api/projects') {
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', projectManager.getAllSerialized(), pathname, t0);
    return true;
  }
  if (pathname === '/api/catalog') {
    const cm = getService('catalogManager');
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', cm.getCatalogSerialized(), pathname, t0);
    return true;
  }
  if (pathname === '/api/domains') {
    const dm = getService('domainManager');
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', dm.getAllWrappedSerialized(), pathname, t0);
    return true;
  }
  if (pathname === '/api/system/status') {
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', getSystemStatusBuffer(), pathname, t0);
    return true;
  }
  if (pathname === '/api/sync/summary') {
    const buf = loadedServices.liveSyncEngine
      ? Buffer.from(JSON.stringify(loadedServices.liveSyncEngine.getGlobalSummary()), 'utf8')
      : EMPTY_SYNC_SUMMARY_BUF;
    sendFastBuffer(req, res, 200, 'application/json; charset=utf-8', buf, pathname, t0);
    return true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// Parser nativo UTF-8 sin `iconv-lite` ni copia duplicada de `qs`
// ---------------------------------------------------------------------------
function resolveBodyLimitBytes(reqPath) {
  if (/^\/api\/(?:migrate|import)\/wordpress\/[^/]+\/import-sql$/.test(reqPath) || reqPath === '/api/import/wordpress/import-sql') {
    return 55 * 1024 * 1024; // 55 MB para volcados SQL grandes (MAX_SQL_BYTES = 50 MB)
  }
  if (/^\/api\/projects\/[^/]+\/sync\/frame$/.test(reqPath)) {
    return 16 * 1024 * 1024; // 16 MB para Commit Frames HTTP
  }
  if (reqPath.startsWith('/api/import/compose')) {
    return 2 * 1024 * 1024;
  }
  return 1 * 1024 * 1024; // 1 MB por defecto (corta DoS de memoria)
}

function nativeBodyParser(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  if (req.body !== undefined) return next();

  const ct = String(req.headers['content-type'] || '').toLowerCase();
  const isJson = ct.includes('application/json') || ct.includes('+json');
  const isForm = ct.includes('application/x-www-form-urlencoded');
  const isText = ct.includes('text/plain');
  if (!isJson && !isForm && !isText) {
    req.body = {};
    return next();
  }

  const rawPath = (req.originalUrl || req.url || '').split('?')[0];
  const limitBytes = resolveBodyLimitBytes(rawPath);
  const declaredLen = Number(req.headers['content-length'] || 0);
  if (declaredLen > limitBytes) {
    const err = new Error(`El cuerpo supera el límite permitido (${Math.round(limitBytes / (1024 * 1024))} MB)`);
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
      const err = new Error(`El cuerpo supera el límite permitido (${Math.round(limitBytes / (1024 * 1024))} MB)`);
      /** @type {any} */ (err).status = 413;
      /** @type {any} */ (err).type = 'entity.too.large';
      return next(err);
    }
    chunks.push(chunk);
  });

  req.on('end', () => {
    if (aborted) return;
    const buf = total > 0 ? Buffer.concat(chunks, total) : Buffer.alloc(0);
    if (rawPath.startsWith('/api/webhooks/github')) {
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
// Extrae hostname limpio desde Host / X-Forwarded-Host (soporta IPv6 [::1]:3030
// y listas separadas por comas — corrige P0-8).
// ---------------------------------------------------------------------------
function extractHostnameClean(rawHeader) {
  const first = String(rawHeader || '').split(',')[0].trim().toLowerCase();
  if (!first) return '';
  if (first.startsWith('[')) {
    const end = first.indexOf(']');
    return end !== -1 ? first.slice(1, end) : first;
  }
  const colon = first.indexOf(':');
  return colon === -1 ? first : first.slice(0, colon);
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
      metricsCollector.onRequestEnd(req.method, req.originalUrl || req.url, res.statusCode, Number(process.hrtime.bigint() - t0) / 1e6);
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

  // DEPRECADO — transporte HTTP+SSE de la revisión 2024-11-05 (P1-17: cleanup antes de safeWrite).
  app.get('/api/mcp/sse', (req, res) => {
    if (activeSseClients >= MAX_SSE_CLIENTS) {
      return res.status(503).json({ error: 'Demasiados clientes SSE conectados simultáneamente' });
    }
    const mcpServer = getService('mcpServer');
    const mcpStreamableHttp = getService('mcpStreamableHttp');
    activeSseClients++;
    mcpStreamableHttp.markLegacyTransport(res, 'GET /api/mcp/sse');
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no'
    });

    let cleaned = false;
    const onMcp = (entry) => {
      safeWrite(`event: mcp_event\ndata: ${JSON.stringify(entry)}\n\n`);
    };
    const cleanup = () => {
      if (cleaned) return;
      cleaned = true;
      activeSseClients = Math.max(0, activeSseClients - 1);
      mcpServer.off('mcp_call', onMcp);
    };
    const safeWrite = (chunk) => {
      if (res.writableEnded || res.destroyed) return;
      try { res.write(chunk); } catch (e) { cleanup(); }
    };

    safeWrite(`event: endpoint\ndata: /api/mcp/message\n\n`);
    mcpServer.on('mcp_call', onMcp);
    req.on('close', cleanup);
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

    const forwarded = req.headers['x-forwarded-host'] || req.headers['x-culkibo-host'];
    const host = extractHostnameClean(forwarded || req.headers.host || '');

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

    res.status(421);
    res.setHeader('X-Culkibo-Data-Plane', 'caddy');
    res.setHeader('X-Content-Type-Options', 'nosniff');

    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      return res.json({
        error: 'Petición dirigida al plano de control',
        dataPlane: 'caddy',
        domain: host,
        matchedRoute: matchedRoute.hostname,
        isWildcard: Boolean(matchedRoute.isWildcard),
        routedByDaemon: false,
        message: `El daemon de Culkibo no enruta tráfico. ${host} lo sirve Caddy en los puertos 80/443. Consulta /api/ingress/status para ver si hay ruta y qué certificado se está sirviendo de verdad.`
      });
    }

    return res.type('text/plain').send(
      `Culkibo: este puerto es el plano de control, no el plano de datos.\n\n` +
      `Dominio solicitado: ${host}\n` +
      `Regla configurada:  ${matchedRoute.hostname}\n\n` +
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
          <head><meta charset="utf-8"><title>Daemon de Culkibo v1.0.0</title><style>body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#fafafa;color:#18181b;padding:40px;text-align:center;}code{background:#f4f4f5;border:1px solid #e4e4e7;border-radius:6px;padding:1px 5px;}</style></head>
          <body>
            <h1>Daemon de Culkibo v1.0.0 en marcha</h1>
            <p>API REST y WebSocket escuchando en el puerto ${PORT}.</p>
            <p>Compila el panel con <code>npm run build</code>, o arráncalo en modo desarrollo en el puerto 5173.</p>
          </body>
        </html>
      `);
    });
  }

  // Manejador de errores limpio (sin reportFatal para 400/413, sanitizado en producción)
  app.use((err, _req, res, next) => {
    const status = err.status || err.statusCode || 500;
    if (err.type === 'entity.parse.failed') {
      if (res.headersSent) return next(err);
      return res.status(400).json({ error: 'JSON malformado en el cuerpo de la petición' });
    }
    if (err.type === 'entity.too.large' || status === 413) {
      if (res.headersSent) return next(err);
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
    if (tryHandleFastPath(req, res)) return;
    getApp()(req, res);
  }
);
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;
server.requestTimeout = 300000;

server.on('upgrade', (req, socket, head) => {
  const rawUrl = req.url || '/';
  const qIdx = rawUrl.indexOf('?');
  const pathname = qIdx === -1 ? rawUrl : rawUrl.slice(0, qIdx);

  if (pathname !== '/ws' && pathname !== '/ws/sync') {
    socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }

  const decision = authorizeRequest(req);
  if (!decision.ok) {
    const code = decision.status === 403 ? '403 Forbidden' : '401 Unauthorized';
    socket.write(`HTTP/1.1 ${code}\r\nConnection: close\r\n\r\n`);
    socket.destroy();
    return;
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
// Arranque y apagado limpio
// ---------------------------------------------------------------------------
function hasScheduledDatabaseBackups() {
  try {
    const dbFile = path.join(DATA_DIR, 'databases.json');
    if (!fs.existsSync(dbFile)) return false;
    const raw = fs.readFileSync(dbFile, 'utf8');
    return raw.includes('"enabled":true') || raw.includes('"enabled": true');
  } catch (e) {
    return false;
  }
}

function sweepStaleTmpFiles() {
  try {
    const tmpDir = path.join(DATA_DIR, '.tmp');
    if (!fs.existsSync(tmpDir)) return;
    const cutoff = Date.now() - 3600 * 1000;
    for (const f of fs.readdirSync(tmpDir)) {
      try {
        const p = path.join(tmpDir, f);
        if (fs.statSync(p).mtimeMs < cutoff) {
          fs.rmSync(p, { recursive: true, force: true });
        }
      } catch (e) {}
    }
  } catch (e) {}
}

/**
 * @param {number} port
 * @param {string} host
 * @param {{ reconcileIngress?: boolean }} [options]
 */
function startServer(port = PORT, host = '127.0.0.1', { reconcileIngress = process.env.CULKIBO_SKIP_RECONCILE !== '1' } = {}) {
  return new Promise((resolve, reject) => {
    server.listen(port, host, () => {
      console.log(`\n========================================================`);
      console.log(`🚀 Culkibo Orchestrator v1.0.0 Daemon running`);
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

      // Tareas post-arranque no bloqueantes (no penalizan el tiempo al primer byte)
      const warmWsTimer = setTimeout(() => {
        try { ensureWsServers(); } catch (e) {}
      }, 100);
      if (warmWsTimer.unref) warmWsTimer.unref();

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

        if (reconcileIngress) {
          try {
            getService('ingressManager').bootstrap({ port }).catch((err) => {
              console.warn('[Edge:Ingress] La reconciliación de arranque falló:', err.message);
            });
          } catch (e) {}
          try {
            getService('deployManager').reconcileRoutes()
              .then((result) => {
                if (result.applied && result.applied.length > 0) {
                  console.log(`[Culkibo] Rutas de ingress repuestas: ${result.applied.join(', ')}`);
                }
              })
              .catch(() => {});
          } catch (e) {}
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
async function shutdown(signal = 'SIGTERM') {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`\n[Culkibo] Recibida señal ${signal}; cerrando limpiamente...`);
  try { if (heartbeatTimer) clearInterval(heartbeatTimer); } catch (e) {}
  try { metricsCollector.stop(); } catch (e) {}
  try { if (loadedServices.databaseManager) loadedServices.databaseManager.stopScheduler(); } catch (e) {}
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
    for (const ws of [...clients, ...syncClients]) {
      try { ws.close(1001, 'Server shutting down'); } catch (e) {}
    }
    if (_wss) _wss.close();
    if (_syncWss) _syncWss.close();
  } catch (e) {}
  try {
    const dm = loadedServices.deployManager;
    if (dm) {
      if (typeof dm.cancelAllDrains === 'function') dm.cancelAllDrains();
      if (dm.drains && dm.drains.size > 0) {
        await Promise.race([
          Promise.allSettled(Array.from(dm.drains.values())),
          new Promise((r) => setTimeout(r, 4000))
        ]);
      }
    }
  } catch (e) {}
  try { await projectManager.flushToDisk(); } catch (e) {}
  await new Promise((resolve) => {
    try {
      if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
      server.close(() => resolve(undefined));
      const t = setTimeout(() => resolve(undefined), 2000);
      if (t.unref) t.unref();
    } catch (e) { resolve(undefined); }
  });
}

if (require.main === module) {
  const bindHost = process.env.CULKIBO_BIND || process.env.HOST || process.env.CULKIBO_HOST || '127.0.0.1';
  startServer(PORT, bindHost).catch(() => {
    process.exit(1);
  });
  for (const sig of ['SIGTERM', 'SIGINT']) {
    process.on(sig, () => {
      shutdown(sig).finally(() => process.exit(0));
    });
  }
}

const exported = { server, broadcast, startServer, shutdown, getApp };
Object.defineProperty(exported, 'app', { get: getApp, enumerable: true });
Object.defineProperty(exported, 'wss', { get: () => ensureWsServers().wss, enumerable: true });
Object.defineProperty(exported, 'syncWss', { get: () => ensureWsServers().syncWss, enumerable: true });
module.exports = exported;
