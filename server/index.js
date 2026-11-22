require('dotenv').config();
const http = require('http');
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { WebSocketServer } = require('ws');

const apiRouter = require('./routes/api');
const containerOrchestrator = require('./services/containerOrchestrator');
const domainManager = require('./services/domainManager');
const mcpServer = require('./services/mcpServer');
const mcpStreamableHttp = require('./services/mcpStreamableHttp');
const projectManager = require('./services/projectManager');
const databaseManager = require('./services/databaseManager');
const ingressManager = require('./services/ingressManager');
const deployManager = require('./services/deployManager');
const catalogManager = require('./services/catalogManager');
const liveSyncEngine = require('./services/liveSyncEngine');

const app = express();
app.disable('x-powered-by');
app.set('etag', false);
const server = http.createServer(app);
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;
server.requestTimeout = 300000;
server.on('connection', (socket) => socket.setNoDelay(true));
// Número, no `string | number`: se pasa a `server.listen()` y a comparaciones
// numéricas. Un PORT no numérico en el entorno cae al valor por defecto en
// lugar de propagarse como cadena hasta el listen.
const PORT = Number(process.env.PORT) || 3030;

// ---------------------------------------------------------------------------
// Global crash barrier.
// The daemon supervises long-lived child processes, file watchers and sockets.
// A single unhandled error anywhere in that surface must never take the whole
// orchestrator down: log it, surface it on the live log stream, keep serving.
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

// Middleware
const { authMiddleware, authorizeRequest, corsOptions, resolveToken, authStatus, isLoopback } = require('./middleware/auth');

// `cors({ origin: '*' })` dejaba que cualquier web que el usuario visitase
// pilotara el daemon desde su propio navegador. Ahora la lista de orígenes es
// explícita y el resto del control de acceso vive en authMiddleware.
app.use(cors(corsOptions()));
app.set('trust proxy', 'loopback');

// El panel mostraba «1.248.920 peticiones servidas» y «142 conexiones activas»:
// dos constantes escritas a mano. Ahora se cuentan de verdad.
app.use((req, res, next) => {
  containerOrchestrator.recordRequest();
  next();
});
// Pre-cargar el decodificador UTF-8 de body-parser al arranque para que el
// primer POST en caliente no bloquee el bucle de eventos con un require() tardío.
try {
  /** @type {any} */
  const iconv = require('iconv-lite');
  if (typeof iconv.getDecoder === 'function') iconv.getDecoder('utf8');
} catch (e) {}

const captureWebhookRawBody = (req, _res, buf) => {
  if (req.url && req.url.startsWith('/api/webhooks/github')) {
    req.rawBody = buf;
  }
};
const jsonParser = express.json({
  limit: '10mb',
  verify: captureWebhookRawBody
});
const urlencodedParser = express.urlencoded({
  extended: true,
  limit: '2mb',
  verify: captureWebhookRawBody
});
app.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  return jsonParser(req, res, next);
});
app.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  return urlencodedParser(req, res, next);
});

// REST API routes
app.get('/health', (req, res) => res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() }));
app.get('/api/health', (req, res) => res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() }));
app.use('/api', authMiddleware);

app.use('/api', apiRouter);

// DEPRECADO — transporte HTTP+SSE de la revisión 2024-11-05.
let activeSseClients = 0;
const MAX_SSE_CLIENTS = 50;
app.get('/api/mcp/sse', (req, res) => {
  if (activeSseClients >= MAX_SSE_CLIENTS) {
    return res.status(503).json({ error: 'Demasiados clientes SSE conectados simultáneamente' });
  }
  activeSseClients++;
  mcpStreamableHttp.markLegacyTransport(res, 'GET /api/mcp/sse');
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });

  const safeWrite = (chunk) => {
    if (res.writableEnded || res.destroyed) return;
    try { res.write(chunk); } catch (e) { cleanup(); }
  };

  safeWrite(`event: endpoint\ndata: /api/mcp/message\n\n`);

  const onMcp = (entry) => {
    safeWrite(`event: mcp_event\ndata: ${JSON.stringify(entry)}\n\n`);
  };

  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    activeSseClients = Math.max(0, activeSseClients - 1);
    mcpServer.off('mcp_call', onMcp);
  };

  mcpServer.on('mcp_call', onMcp);
  req.on('close', cleanup);
  res.on('error', cleanup);
});

// ---------------------------------------------------------------------------
// Este puerto es el plano de CONTROL. El de datos es Caddy.
//
// Aquí vivía un "Edge Ingress Router" que, ante una cabecera Host de un dominio
// configurado, devolvía una página HTML describiendo a qué pod habría enrutado,
// con una latencia de `24ms` escrita a mano. No enrutaba nada: ninguna petición
// salía de Node. Se ha borrado. El reparto por peso, el TLS y el proxy inverso
// los hace Caddy (ver services/caddyManager.js e ingressManager.js).
//
// Lo único que queda en Node es decirlo en voz alta cuando una petición de un
// dominio de ingress llega al puerto equivocado: 421 Misdirected Request es
// exactamente ese caso —el servidor no puede producir una respuesta para la
// autoridad solicitada—. Callar y servir el panel haría creer que el dominio
// está atendido.
// ---------------------------------------------------------------------------
const MANAGEMENT_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1', '']);

app.use((req, res, next) => {
  if (req.path.startsWith('/api') || req.path === '/ws' || req.path === '/health') {
    return next();
  }

  const forwarded = req.headers['x-forwarded-host'] || req.headers['x-culkibo-host'];
  const rawHost = forwarded || req.headers.host || '';
  const host = String(rawHost).split(':')[0].toLowerCase();

  // Acceso directo de gestión (localhost / IP): se sirve el panel.
  if (MANAGEMENT_HOSTS.has(host) && !forwarded) {
    return next();
  }

  const matchedRoute = domainManager.resolveRoute(host);
  if (!matchedRoute) {
    return next();
  }

  res.status(421);
  res.setHeader('X-Culkibo-Data-Plane', 'caddy');
  // El Host lo controla el cliente y se refleja en la respuesta. Con
  // `text/plain` explícito y nosniff no hay forma de que el navegador lo
  // interprete como marcado.
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

// Serve frontend static build if available
const webDistPath = path.join(__dirname, '..', 'web', 'dist');
if (fs.existsSync(webDistPath)) {
  app.use(express.static(webDistPath, {
    index: false,
    setHeaders: (res, filePath) => {
      if (filePath.includes('/assets/') || filePath.includes('\\assets\\')) {
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      } else if (filePath.endsWith('index.html')) {
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      }
    }
  }));
  app.use((req, res, next) => {
    if (!req.path.startsWith('/api') && req.method === 'GET') {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      return res.sendFile(path.join(webDistPath, 'index.html'));
    }
    next();
  });
} else {
  // Página de respaldo cuando el panel no está compilado. Modo claro, como el
  // resto del producto: era la única superficie que seguía en oscuro.
  app.get('/', (req, res) => {
    res.send(`
      <html lang="es">
        <head><meta charset="utf-8"><title>Daemon de Culkibo v1.0.0</title><style>body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#f8fafc;color:#0f172a;padding:40px;text-align:center;}code{background:#f1f5f9;border:1px solid #e2e8f0;border-radius:6px;padding:1px 5px;}</style></head>
        <body>
          <h1>Daemon de Culkibo v1.0.0 en marcha</h1>
          <p>API REST y WebSocket escuchando en el puerto ${PORT}.</p>
          <p>Compila el panel con <code>npm run build</code>, o arráncalo en modo desarrollo en el puerto 5173.</p>
        </body>
      </html>
    `);
  });
}

// Terminal error handler: turns a thrown/next(err) anywhere in the middleware
// chain into a JSON 500 instead of an unhandled rejection.
app.use((err, req, res, next) => {
  reportFatal('requestError', err);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ error: err.message || 'Error interno del servidor' });
});

// WebSocket servers:
//  - `/ws`      telemetría y logs en vivo del panel
//  - `/ws/sync` tubería persistente de Commit Frames de Live Sync (The Forge)
// Ambos pasan por la misma autorización (Origin + Token) antes del upgrade.
const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });
const syncWss = new WebSocketServer({ noServer: true, maxPayload: 16 * 1024 * 1024, perMessageDeflate: false });
const clients = new Set();
const syncClients = new Set();

/** Valida si un targetDir explícito está permitido en /ws/sync (anti-escritura arbitraria). */
function resolveAllowedSyncTargetDir(rawDir, req) {
  if (!rawDir) return null;
  if (process.env.CULKIBO_ALLOW_SYNC_TARGET_DIR === '1') {
    return path.resolve(String(rawDir));
  }
  // Nunca permitir que un cliente remoto sobreescriba rutas arbitrarias del host.
  if (!isLoopback(req)) {
    const err = new Error('No se permite especificar targetDir desde conexiones remotas');
    /** @type {any} */ (err).code = 'TARGET_DIR_FORBIDDEN';
    throw err;
  }
  const resolved = path.resolve(String(rawDir));
  const allowedRoots = [path.resolve(process.cwd(), 'projects'), path.resolve(os.tmpdir())];
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
 * Evita base64 (+33%) y parseo de cadenas gigantes.
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

server.on('upgrade', (req, socket, head) => {
  const pathname = (req.url || '/').split('?')[0];
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

  const target = pathname === '/ws/sync' ? syncWss : wss;
  target.handleUpgrade(req, socket, head, (ws) => {
    target.emit('connection', ws, req);
  });
});

// Conexiones activas reales, para que getPods() deje de inventarlas.
containerOrchestrator.setConnectionCounter(() => clients.size);

// Tubería persistente de Live Sync (/ws/sync): Commit Frames atómicos (JSON o binario) + Merkle.
syncWss.on('connection', (ws, req) => {
  syncClients.add(ws);
  ws.isAlive = true;
  if (ws._socket && typeof ws._socket.setNoDelay === 'function') {
    ws._socket.setNoDelay(true);
  }
  ws.on('pong', () => { ws.isAlive = true; });

  /** @type {string | null} */
  let boundProjectId = null;

  const cleanupSync = () => {
    syncClients.delete(ws);
    if (boundProjectId) {
      const prev = boundProjectId;
      boundProjectId = null;
      liveSyncEngine.unregisterClient(prev);
      broadcast('sync_client', { projectId: prev, connected: false, connectedClients: liveSyncEngine.getStatus(prev).connectedClients });
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
        const safeDir = resolveAllowedSyncTargetDir(msg.targetDir, req);
        if (boundProjectId && boundProjectId !== nextPid) {
          liveSyncEngine.unregisterClient(boundProjectId);
        }
        boundProjectId = nextPid;
        if (safeDir) liveSyncEngine.setTargetDir(boundProjectId, safeDir);
        const session = liveSyncEngine.registerClient(boundProjectId);
        const verification = liveSyncEngine.verifySync(boundProjectId, {
          clientDigest: msg.clientDigest || null,
          targetDir: safeDir
        });
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
        const safeDir = resolveAllowedSyncTargetDir(msg.targetDir, req);
        const result = liveSyncEngine.applyCommitFrame(pid, msg, { targetDir: safeDir || undefined, deferEmit: true });
        safeWsSend(ws, { type: 'frame_ack', ...result });
        setImmediate(() => liveSyncEngine.emitApplied(result));
        return;
      }

      if (msg.type === 'verify') {
        const pid = String(msg.projectId || boundProjectId || '');
        if (!pid) throw new Error('verify requiere projectId');
        const safeDir = resolveAllowedSyncTargetDir(msg.targetDir, req);
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

// Caché de 150 ms del payload inicial de `/ws` para fan-out concurrente sin
// repetir JSON.stringify N veces cuando decenas de pestañas conectan a la vez.
/** @type {{ at: number, payload: string } | null} */
let cachedInitialState = null;
function getInitialWsPayload() {
  const now = Date.now();
  if (cachedInitialState && now - cachedInitialState.at < 150) {
    return cachedInitialState.payload;
  }
  const payload = JSON.stringify({
    type: 'initial_state',
    data: {
      pods: containerOrchestrator.getPods(),
      logs: containerOrchestrator.getLogs({ limit: 40 }),
      mcpAudit: mcpServer.getAuditLog(20)
    }
  });
  cachedInitialState = { at: now, payload };
  return payload;
}

wss.on('connection', (ws) => {
  clients.add(ws);

  // Liveness flag for the heartbeat sweep below.
  ws.isAlive = true;
  if (ws._socket && typeof ws._socket.setNoDelay === 'function') {
    ws._socket.setNoDelay(true);
  }
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('error', () => {
    clients.delete(ws);
    try { ws.terminate(); } catch (e) {}
  });

  // Send initial snapshot safely
  try {
    ws.send(getInitialWsPayload());
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

// Half-open TCP connections never emit 'close', so sweep both `/ws` and `/ws/sync`.
const WS_HEARTBEAT_MS = 30000;
const heartbeatTimer = setInterval(() => {
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
}, WS_HEARTBEAT_MS);
if (heartbeatTimer.unref) heartbeatTimer.unref();

function broadcast(type, data) {
  if (clients.size === 0) return;
  const payload = JSON.stringify({ type, data, timestamp: new Date().toISOString() });
  for (const client of clients) {
    if (client.readyState === 1) { // OPEN
      client.send(payload, (err) => {
        if (err) clients.delete(client);
      });
    } else if (client.readyState === 2 || client.readyState === 3) {
      clients.delete(client);
    }
  }
}

// Wire orchestrator, projectManager & MCP events to WebSocket broadcast
containerOrchestrator.on('metrics', (data) => broadcast('metrics', data));
containerOrchestrator.on('log', (data) => broadcast('log', data));
containerOrchestrator.on('pod_change', (data) => broadcast('pod_change', data));
containerOrchestrator.on('traffic_change', (data) => broadcast('traffic_change', data));
containerOrchestrator.on('ssl_progress', (data) => broadcast('ssl_progress', data));
containerOrchestrator.on('github_deploy', (data) => broadcast('github_deploy', data));
projectManager.on('project_update', (data) => broadcast('project_update', data));
projectManager.on('project_created', (data) => broadcast('project_created', data));
projectManager.on('project_deleted', (data) => broadcast('project_deleted', data));
mcpServer.on('mcp_call', (data) => broadcast('mcp_call', data));
// El progreso de un despliegue viaja por dos canales: las líneas de build van
// al flujo de logs normal (deployManager las mete por containerOrchestrator, ya
// etiquetadas con el projectId) y el cambio de fase va por aquí, estructurado,
// para que el panel pinte la barra de progreso sin tener que parsear texto.
deployManager.on('deploy_event', (data) => broadcast('deploy_event', data));
// Y las líneas del build, además, etiquetadas con su deploymentId. El flujo
// `log` general las lleva sin esa etiqueta, así que el visor de una build
// concreta no podría separar las suyas de las de otro despliegue simultáneo.
deployManager.on('deploy_log', (data) => broadcast('deploy_log', data));

databaseManager.on('backup_completed', (data) => broadcast('backup_completed', data));
databaseManager.on('backup_failed', (data) => broadcast('backup_failed', data));
databaseManager.on('database_created', (data) => broadcast('database_created', data));
databaseManager.on('database_deleted', (data) => broadcast('database_deleted', data));
catalogManager.on('service_progress', (data) => broadcast('service_progress', data));
catalogManager.on('service_installed', (data) => broadcast('service_installed', data));
catalogManager.on('service_failed', (data) => broadcast('service_failed', data));
catalogManager.on('service_removed', (data) => broadcast('service_removed', data));
liveSyncEngine.on('sync_applied', (data) => {
  broadcast('sync_applied', data);
  containerOrchestrator.addLog(
    'HOT_SYNC',
    'forge',
    `[Forge:LiveSync] Frame #${data.seq} (${data.written} escritos, ${data.deleted} borrados, ${data.dedupSkipped} sin cambios) aplicado en ${data.applyMs}ms [${data.mode}]`,
    new Date(),
    data.projectId
  );
});
liveSyncEngine.on('sync_rollback', (data) => {
  broadcast('sync_rollback', data);
  containerOrchestrator.addLog(
    'INFO',
    'forge',
    `[Forge:Rollback] Revertidos ${data.restoredFiles.length} fichero(s) en ${data.durationMs}ms`,
    new Date(),
    data.projectId
  );
});

/**
 * @param {number} port
 * @param {string} host
 * @param {{ reconcileIngress?: boolean }} [options]
 *   `reconcileIngress: false` arranca el daemon sin reponer las rutas de los
 *   despliegues en Caddy. Lo usan las pruebas: comparten un único Caddy y
 *   `tests/caddy.test.js` cuenta rutas absolutas, así que un daemon que añade
 *   las suyas al arrancar haría fallar esa suite en cuanto la máquina tuviera
 *   un despliegue real. En producción se reponen siempre.
 */
function startServer(port = PORT, host = '0.0.0.0', { reconcileIngress = process.env.CULKIBO_SKIP_RECONCILE !== '1' } = {}) {
  return new Promise((resolve, reject) => {
    server.listen(port, host, () => {
      console.log(`\n========================================================`);
      console.log(`🚀 Culkibo Orchestrator v1.0.0 Daemon running`);
      console.log(`📡 REST API:          http://localhost:${port}/api`);
      console.log(`🤖 MCP ${mcpServer.protocol.PROTOCOL_VERSION}:     POST http://localhost:${port}/api/mcp`);
      console.log(`   MCP ${mcpServer.protocol.LEGACY_PROTOCOL_VERSION}:      http://localhost:${port}/api/mcp/sse  (deprecado)`);
      console.log(`⚡ WebSocket Stream:  ws://localhost:${port}/ws`);
      console.log(`✨ Dashboard:         http://localhost:${port}`);

      const auth = authStatus();
      resolveToken(); // fuerza la creación del token en el primer arranque
      console.log(`--------------------------------------------------------`);
      console.log(`🔐 Acceso: token en ${auth.tokenSource}`);
      console.log(`   Orígenes permitidos: ${auth.allowedOrigins.join(', ')}`);
      if (host !== '127.0.0.1' && host !== 'localhost' && !auth.requireTokenAlways) {
        console.log(`   ⚠  Escuchando en ${host}. Si el puerto es alcanzable desde fuera,`);
        console.log(`      exige token siempre con CULKIBO_REQUIRE_TOKEN=1`);
      }
      console.log(`========================================================\n`);

      // El planificador de copias arranca con el daemon y sólo con el daemon.
      // Su temporizador va con unref(), así que jamás impide que el proceso
      // termine (importante en las pruebas y en `culkibo` de un solo comando).
      try {
        databaseManager.startScheduler();
      } catch (e) {
        console.warn('[Databases] No se pudo arrancar el planificador de copias:', e.message);
      }
      // Reconciliación de arranque del ingress.
      //
      // Va aquí, después de escuchar, porque Caddy necesita poder llamar a
      // /api/ingress/ask para autorizar certificados en cuanto existan rutas.
      // No se espera a que termine: si no hay Caddy, el daemon tiene que
      // arrancar igual — la misma regla camaleón que con Docker.
      // Las dos reconciliaciones son complementarias —una repone las rutas de
      // los proyectos, la otra las de los despliegues— y ambas tienen que
      // respetar el flag: un daemon de pruebas que añade rutas al Caddy
      // compartido hace fallar a caddy.test.js, que cuenta rutas absolutas.
      if (reconcileIngress) {
        ingressManager.bootstrap({ port }).catch((err) => {
          console.warn('[Edge:Ingress] La reconciliación de arranque falló:', err.message);
        });
      }
      // Repone en Caddy las rutas de los despliegues que Culkibo cree activos.
      // Si Caddy se reinició y perdió su configuración, el tráfico vuelve solo
      // sin que nadie tenga que redesplegar. Es aditiva (nunca borra rutas
      // ajenas) y no hace nada si no hay despliegues, así que no puede
      // entorpecer el arranque.
      if (reconcileIngress) {
        deployManager.reconcileRoutes()
          .then((result) => {
            if (result.applied && result.applied.length > 0) {
              console.log(`[Culkibo] Rutas de ingress repuestas: ${result.applied.join(', ')}`);
            }
          })
          .catch(() => {});
      }

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
  try { clearInterval(heartbeatTimer); } catch (e) {}
  try { databaseManager.stopScheduler(); } catch (e) {}
  try { containerOrchestrator.stop(); } catch (e) {}
  try {
    const localRunner = require('./services/localRunner');
    if (localRunner && localRunner.activeRunners) {
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
    wss.close();
    syncWss.close();
  } catch (e) {}
  try {
    if (deployManager && deployManager.drains && deployManager.drains.size > 0) {
      await Promise.race([
        Promise.allSettled(Array.from(deployManager.drains.values())),
        new Promise((r) => setTimeout(r, 4000))
      ]);
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
  const bindHost = process.env.HOST || process.env.CULKIBO_HOST || '0.0.0.0';
  startServer(PORT, bindHost);
  for (const sig of ['SIGTERM', 'SIGINT']) {
    process.on(sig, () => {
      shutdown(sig).finally(() => process.exit(0));
    });
  }
}

module.exports = { app, server, wss, syncWss, broadcast, startServer, shutdown };
