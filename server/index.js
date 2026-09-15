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
const sslManager = require('./services/sslManager');
const mcpServer = require('./services/mcpServer');
const projectManager = require('./services/projectManager');

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

// Escape untrusted values before interpolating them into an HTML response.
// The ingress router echoes the client-controlled Host header back to the browser.
function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

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

// Model Context Protocol SSE Endpoint for AI Agents (Cursor, Windsurf, Claude Desktop)
app.get('/api/mcp/sse', (req, res) => {
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

// Edge Ingress Reverse Router Middleware
// When requests arrive with a configured domain or wildcard Host header,
// Culkibo routes the ingress traffic to the appropriate Pod (The Forge or The Citadel)
app.use((req, res, next) => {
  if (req.path.startsWith('/api') || req.path === '/ws') {
    return next();
  }

  const rawHost = req.headers['x-forwarded-host'] || req.headers['x-culkibo-host'] || req.headers.host || '';
  const host = rawHost.split(':')[0].toLowerCase();

  // Direct server management access via localhost/IP serves the dashboard
  if ((host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0' || host === '::1' || host === '') && !req.headers['x-forwarded-host'] && !req.headers['x-culkibo-host']) {
    return next();
  }

  const matchedRoute = domainManager.resolveRoute(host);
  if (matchedRoute) {
    const traffic = containerOrchestrator.trafficAllocation;
    let targetPod = matchedRoute.targetPod;
    // If traffic allocation is split, apply dynamic canary routing
    if (traffic.forge > 0 && traffic.citadel > 0) {
      targetPod = (Math.random() * 100 < traffic.citadel) ? 'citadel' : 'forge';
    }
    const targetPort = targetPod === 'forge' ? 3001 : 8080;
    const cert = sslManager.getCertificateByDomain(host);

    res.setHeader('X-Culkibo-Ingress', '1');
    res.setHeader('X-Culkibo-Pod', targetPod);
    res.setHeader('X-Culkibo-Port', String(targetPort));
    res.setHeader('X-Culkibo-Domain', matchedRoute.hostname);
    res.setHeader('X-Culkibo-SSL', cert ? 'active' : 'unconfigured');
    res.setHeader('X-Culkibo-Latency', `${targetPod === 'forge' ? 24 : 14}ms`);

    // Ingress response payload for routed apps or API consumers
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      return res.json({
        ingress: 'Culkibo Edge Ingress v1.0.0',
        domain: host,
        routedPod: targetPod,
        targetPort,
        trafficSplit: traffic,
        sslActive: Boolean(cert),
        latencyMs: targetPod === 'forge' ? 24 : 14,
        timestamp: new Date().toISOString()
      });
    }

    const safeHost = escapeHtml(host);
    const safeRule = escapeHtml(matchedRoute.hostname);
    return res.send(`<!DOCTYPE html>
<html lang="es">
  <head>
    <meta charset="utf-8">
    <title>${safeHost} — Culkibo Ingress</title>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; color: #0f172a; padding: 40px; text-align: center; }
      .badge { display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: bold; font-family: monospace; }
      .forge { background: #fef3c7; color: #b45309; border: 1px solid #fde68a; }
      .citadel { background: #dbeafe; color: #1d4ed8; border: 1px solid #bfdbfe; }
      .card { max-width: 600px; margin: 30px auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 16px; padding: 24px; text-align: left; box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1); }
    </style>
  </head>
  <body>
    <h2 style="color: #0f172a;">⚡ Enrutado por Culkibo Edge Ingress</h2>
    <div class="card">
      <p><strong>Dominio:</strong> <code>${safeHost}</code></p>
      <p><strong>Regla Coincidente:</strong> <code>${safeRule}</code> (${matchedRoute.isWildcard ? 'Comodín Wildcard' : 'Exacta'})</p>
      <p><strong>Entorno Activo:</strong> <span class="badge ${targetPod}">${targetPod === 'forge' ? 'DESARROLLO (:3001)' : 'PRODUCCIÓN (:8080)'}</span></p>
      <p><strong>Distribución de Tráfico:</strong> <code>${traffic.citadel}% Producción / ${traffic.forge}% Desarrollo</code></p>
      <p><strong>Estado SSL / TLS:</strong> <span style="color: ${cert ? '#059669' : '#d97706'}">${cert ? `Activo (${cert.issuer})` : 'Certificado Pendiente'}</span></p>
    </div>
  </body>
</html>`);
  }

  next();
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
  // Development fallback route
  app.get('/', (req, res) => {
    res.send(`
      <html>
        <head><title>Culkibo Daemon v1.0.0</title><style>body{font-family:sans-serif;background:#0b0e14;color:#f3f4f6;padding:40px;text-align:center;}</style></head>
        <body>
          <h1>⚡ Culkibo Daemon v1.0.0 Live</h1>
          <p>REST API & WebSocket listening on port ${PORT}.</p>
          <p>Vite dashboard can be built via <code>npm run build</code> or started in dev mode on port 5173.</p>
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

function startServer(port = PORT, host = '0.0.0.0') {
  return new Promise((resolve, reject) => {
    server.listen(port, host, () => {
      console.log(`\n========================================================`);
      console.log(`🚀 Culkibo Orchestrator v1.0.0 Daemon running`);
      console.log(`📡 REST API & MCP:    http://localhost:${port}/api`);
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
