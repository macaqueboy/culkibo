require('dotenv').config();
const http = require('http');
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { WebSocketServer } = require('ws');

const apiRouter = require('./routes/api');
const containerOrchestrator = require('./services/containerOrchestrator');
const domainManager = require('./services/domainManager');
const mcpServer = require('./services/mcpServer');
const mcpStreamableHttp = require('./services/mcpStreamableHttp');
const projectManager = require('./services/projectManager');
const databaseManager = require('./services/databaseManager');
const ingressManager = require('./services/ingressManager');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3030;

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
const { authMiddleware, corsOptions, resolveToken, authStatus } = require('./middleware/auth');

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
app.use(express.json({
  limit: '10mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ extended: true }));

// REST API routes
app.get('/health', (req, res) => res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() }));
app.get('/api/health', (req, res) => res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() }));
// Todo lo que cuelga de /api pasa por el control de acceso — incluido el
// endpoint SSE del MCP, que se declara más abajo. Queda fuera a propósito el
// router de ingress: esas peticiones vienen de internet contra un dominio
// enrutado y no llevan credencial, que es justo lo que se espera.
// /health y el webhook de GitHub están exentos dentro del propio middleware.
app.use('/api', authMiddleware);

app.use('/api', apiRouter);

// DEPRECADO — transporte HTTP+SSE de la revisión 2024-11-05.
//
// El endpoint vivo es POST /api/mcp (Streamable HTTP, revisión 2026-07-28), que
// se declara en routes/api.js. Este se mantiene solo para que las
// configuraciones de Cursor, Windsurf y Claude Desktop ya instaladas sigan
// funcionando: HTTP+SSE está deprecado desde la revisión 2025-03-26 y es el
// primero de la lista para desaparecer de la especificación.
app.get('/api/mcp/sse', (req, res) => {
  mcpStreamableHttp.markLegacyTransport(res, 'GET /api/mcp/sse');
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*'
  });

  res.write(`event: endpoint\ndata: /api/mcp/message\n\n`);

  const onMcp = (entry) => {
    res.write(`event: mcp_event\ndata: ${JSON.stringify(entry)}\n\n`);
  };

  mcpServer.on('mcp_call', onMcp);

  req.on('close', () => {
    mcpServer.off('mcp_call', onMcp);
  });
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

// WebSocket server for ultra-fast telemetry & log streaming
const wss = new WebSocketServer({ server, path: '/ws' });
const clients = new Set();

// Conexiones activas reales, para que getPods() deje de inventarlas.
containerOrchestrator.setConnectionCounter(() => clients.size);

wss.on('connection', (ws) => {
  clients.add(ws);

  // Liveness flag for the heartbeat sweep below.
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('error', () => {
    clients.delete(ws);
    try { ws.terminate(); } catch (e) {}
  });

  // Send initial snapshot safely
  try {
    ws.send(JSON.stringify({
      type: 'initial_state',
      data: {
        pods: containerOrchestrator.getPods(),
        logs: containerOrchestrator.getLogs({ limit: 40 }),
        mcpAudit: mcpServer.getAuditLog(20)
      }
    }));
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

// Half-open TCP connections never emit 'close', so a laptop that sleeps or a
// network that drops would leak an entry in `clients` forever. Sweep them.
const WS_HEARTBEAT_MS = 30000;
const heartbeatTimer = setInterval(() => {
  for (const ws of clients) {
    if (ws.isAlive === false) {
      clients.delete(ws);
      try { ws.terminate(); } catch (e) {}
      continue;
    }
    ws.isAlive = false;
    try { ws.ping(); } catch (e) {
      clients.delete(ws);
      try { ws.terminate(); } catch (e2) {}
    }
  }
}, WS_HEARTBEAT_MS);
if (heartbeatTimer.unref) heartbeatTimer.unref();

function broadcast(type, data) {
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

databaseManager.on('backup_completed', (data) => broadcast('backup_completed', data));
databaseManager.on('backup_failed', (data) => broadcast('backup_failed', data));
databaseManager.on('database_created', (data) => broadcast('database_created', data));
databaseManager.on('database_deleted', (data) => broadcast('database_deleted', data));

function startServer(port = PORT, host = '0.0.0.0') {
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
      ingressManager.bootstrap({ port }).catch((err) => {
        console.warn('[Edge:Ingress] La reconciliación de arranque falló:', err.message);
      });

      resolve(server);
    }).on('error', (err) => {
      console.error(`❌ Failed to start server on port ${port}:`, err.message);
      reject(err);
    });
  });
}

if (require.main === module) {
  startServer(PORT, '0.0.0.0');
}

module.exports = { app, server, wss, broadcast, startServer };
