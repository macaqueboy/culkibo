const express = require('express');
const router = express.Router();

const containerOrchestrator = require('../services/containerOrchestrator');
const domainManager = require('../services/domainManager');
const sslManager = require('../services/sslManager');
const cloudflareService = require('../services/cloudflareService');
const mcpServer = require('../services/mcpServer');
const mcpStreamableHttp = require('../services/mcpStreamableHttp');
const projectManager = require('../services/projectManager');
const coolifyMigrator = require('../services/coolifyMigrator');
const dockerManager = require('../services/dockerManager');
const dbBackupManager = require('../services/dbBackupManager');
const databaseManager = require('../services/databaseManager');
const crypto = require('crypto');
const githubService = require('../services/githubService');
const localRunner = require('../services/localRunner');
const notificationService = require('../services/notificationService');
const caddyManager = require('../services/caddyManager');

// In-memory rate limiting for sensitive endpoints (O(1) Fixed Window)
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60000;
const MAX_REQUESTS_PER_WINDOW = 500;

function rateLimiter(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1' || process.env.NODE_ENV === 'test') {
    return next();
  }
  const now = Date.now();
  let entry = rateLimitMap.get(ip);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
    rateLimitMap.set(ip, entry);
  }
  entry.count++;
  if (entry.count > MAX_REQUESTS_PER_WINDOW) {
    return res.status(429).json({ error: 'Demasiadas peticiones. Por favor, inténtelo de nuevo en un minuto.' });
  }
  next();
}

router.use('/projects', rateLimiter);
router.use('/import/coolify', rateLimiter);
router.use('/databases', rateLimiter);

// --- PROJECTS ---
router.get('/projects', (req, res) => {
  try {
    res.json(projectManager.getAll());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/projects', (req, res) => {
  try {
    const project = projectManager.create(req.body);
    // Automatically pre-clone and prepare dependencies in the background
    if (project.gitRepo) {
      localRunner.prepareProject(project).catch(err => {
        console.warn(`[AutoPrepare] Could not auto-prepare ${project.name}:`, err.message);
      });
    }
    res.status(201).json(project);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/projects/:id', (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    res.json(project);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.put('/projects/:id', (req, res) => {
  try {
    const project = projectManager.update(req.params.id, req.body);
    res.json(project);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.delete('/projects/:id', (req, res) => {
  try {
    projectManager.delete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.post('/projects/:id/activate', (req, res) => {
  try {
    const project = projectManager.activate(req.params.id);
    res.json(project);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.post('/projects/:id/hibernate', async (req, res) => {
  try {
    let project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });

    // Stop live local HTTP server & free port
    try {
      await localRunner.stop(project.id, project.localPort);
    } catch(err) {
      console.error('[LocalRunner] Could not stop server on hibernate:', err.message);
    }

    // Stop docker containers for resources if possible & free their ports
    try {
      if (project.resources && Array.isArray(project.resources)) {
        for (const res of project.resources) {
          if (res.localPort) {
            await localRunner.killProcessOnPort(res.localPort);
          }
          const containerName = `culkibo_local_${project.id}_${(res.name || 'res').replace(/[^a-zA-Z0-9]/g, '')}`;
          try {
            await dockerManager.stopContainer(containerName);
          } catch(e) {}
        }
      }
    } catch(e) {}

    const updated = projectManager.hibernate(req.params.id);
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/projects/:id/start-local', async (req, res) => {
  try {
    let project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    
    // Assign local ports if not present
    if (!project.localPort) {
      project.localPort = Math.floor(Math.random() * (9000 - 3000 + 1)) + 3000;
    }
    
    if (project.resources && Array.isArray(project.resources)) {
      project.resources.forEach(r => {
        if (!r.localPort) r.localPort = Math.floor(Math.random() * (9000 - 3000 + 1)) + 3000;
      });
    }

    // Start live local HTTP server for this project
    try {
      await localRunner.start(project);
    } catch(err) {
      console.error('[LocalRunner] Could not bind server:', err.message);
    }

    // Start docker containers for resources if possible
    try {
      if (project.resources && Array.isArray(project.resources)) {
        for (const res of project.resources) {
          const containerName = `culkibo_local_${project.id}_${(res.name || 'res').replace(/[^a-zA-Z0-9]/g, '')}`;
          try {
            await dockerManager.startContainer(containerName);
          } catch(e) {}
        }
      }
    } catch(e) {}

    project.status = 'active';
    project.localRunning = true;
    project = projectManager.update(req.params.id, project);
    res.json(project);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const handleStopProject = async (req, res) => {
  try {
    let project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    
    // Stop live local HTTP server & free port
    try {
      await localRunner.stop(project.id, project.localPort);
    } catch(err) {
      console.error('[LocalRunner] Could not stop server:', err.message);
    }

    // Stop docker containers for resources & free their ports
    try {
      if (project.resources && Array.isArray(project.resources)) {
        for (const res of project.resources) {
          if (res.localPort) {
            await localRunner.killProcessOnPort(res.localPort);
          }
          const containerName = `culkibo_local_${project.id}_${(res.name || 'res').replace(/[^a-zA-Z0-9]/g, '')}`;
          try {
            await dockerManager.stopContainer(containerName);
          } catch(e) {}
        }
      }
    } catch(e) {}

    const updated = projectManager.stop(req.params.id);
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

router.post('/projects/:id/stop', handleStopProject);
router.post('/projects/:id/stop-local', handleStopProject);

// --- COOLIFY IMPORT ---
router.post('/import/coolify/preview', async (req, res) => {
  try {
    const { apiUrl, apiToken } = req.body;
    const preview = await coolifyMigrator.previewMigration(apiUrl, apiToken);
    res.json(preview);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/import/coolify', async (req, res) => {
  try {
    const { apiUrl, apiToken, selectedApps, selectedDbs, selectedServices } = req.body;
    const result = await coolifyMigrator.executeMigration(apiUrl, apiToken, {
      apps: selectedApps,
      dbs: selectedDbs,
      services: selectedServices
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/import/coolify/migrate-domain', async (req, res) => {
  try {
    const { hostname, serverIp, autoCloudflare } = req.body;
    let zoneId = null;
    let dnsResult = null;
    
    if (autoCloudflare && serverIp) {
      zoneId = await cloudflareService.findZoneForDomain(hostname);
      if (zoneId) {
        dnsResult = await cloudflareService.createDnsRecord(zoneId, {
          type: 'A',
          name: hostname,
          content: serverIp,
          proxied: true,
          ttl: 1
        });
      }
    }

    const domain = domainManager.domains.find(d => d.hostname === hostname);
    if (domain) {
      const updates = { 
        sslStatus: 'pending_ssl',
        cloudflareZoneId: zoneId || domain.cloudflareZoneId
      };
      if (dnsResult && dnsResult.success) {
        updates.cloudflareProxied = true;
      }
      await domainManager.updateDomain(domain.id, updates);
      
      sslManager.issueWildcardCertificate({
        domain: hostname,
        zoneId: zoneId || domain.cloudflareZoneId,
        provider: 'lets_encrypt'
      }).catch(err => console.error('[Migrate Domain] SSL error:', err));
    }
    
    res.json({ success: true, hostname, dnsResult });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/import/coolify/migrate-domains-batch', async (req, res) => {
  try {
    const { domains, serverIp, autoCloudflare } = req.body;
    const results = [];
    for (const hostname of domains) {
      try {
        let zoneId = null;
        let dnsResult = null;
        if (autoCloudflare && serverIp) {
           zoneId = await cloudflareService.findZoneForDomain(hostname);
           if (zoneId) {
             dnsResult = await cloudflareService.createDnsRecord(zoneId, {
               type: 'A',
               name: hostname,
               content: serverIp,
               proxied: true,
               ttl: 1
             });
           }
        }
        const domain = domainManager.domains.find(d => d.hostname === hostname);
        if (domain) {
          const updates = { sslStatus: 'pending_ssl', cloudflareZoneId: zoneId || domain.cloudflareZoneId };
          if (dnsResult && dnsResult.success) updates.cloudflareProxied = true;
          await domainManager.updateDomain(domain.id, updates);
          
          sslManager.issueWildcardCertificate({
            domain: hostname,
            zoneId: zoneId || domain.cloudflareZoneId,
            provider: 'lets_encrypt'
          }).catch(err => console.error(err));
        }
        results.push({ hostname, success: true });
      } catch (e) {
        results.push({ hostname, success: false, error: e.message });
      }
      await new Promise(r => setTimeout(r, 1000));
    }
    res.json({ success: true, results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- SYSTEM & HEALTH ---
router.get('/server/ip', async (req, res) => {
  try {
    const response = await fetch('https://api.ipify.org?format=json');
    const data = await response.json();
    res.json({ ip: data.ip });
  } catch (err) {
    res.json({ ip: null });
  }
});

router.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

router.get('/system/status', (req, res) => {
  try {
    res.json({
      name: 'Culkibo',
      version: '1.0.0',
      tagline: 'The AI-Era Cloud Orchestrator',
      nodeVersion: process.version,
      uptimeSeconds: Math.floor(process.uptime()),
      memoryUsageMb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
      features: {
        hotReloadImplemented: false, // la detección funciona; el transporte y la aplicación son trabajo pendiente
        acmeDns01Wildcard: true,
        cloudflareTunnels: true,
        nativeMcp: true,
        onDemandTls: true,
        dualDockerMode: true,
        backupRestoreEngine: true
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- PODS & TRAFFIC ---
router.get('/pods', (req, res) => {
  try {
    res.json(containerOrchestrator.getPods());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/pods/hot-sync', async (req, res) => {
  try {
    const result = await containerOrchestrator.triggerHotSync(req.body);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/pods/switch-traffic', async (req, res) => {
  try {
    const result = await containerOrchestrator.switchTraffic(req.body);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/pods/deploy', async (req, res) => {
  try {
    const result = await containerOrchestrator.deployRelease(req.body);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- DOMAINS ---
router.get('/domains', (req, res) => {
  try {
    res.json({ domains: domainManager.listDomains() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/domains', async (req, res) => {
  try {
    const newDomain = await domainManager.addDomain(req.body);
    res.status(201).json(newDomain);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/domains/:id', async (req, res) => {
  try {
    const removed = await domainManager.deleteDomain(req.params.id);
    res.json({ success: true, removed });
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.patch('/domains/:id', async (req, res) => {
  try {
    const updated = await domainManager.updateDomain(req.params.id, req.body);
    res.json(updated);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.post('/domains/:id/toggle-proxy', async (req, res) => {
  try {
    const updated = await domainManager.toggleProxy(req.params.id);
    res.json(updated);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.post('/domains/verify-dns', async (req, res) => {
  try {
    const result = await domainManager.verifyDns(req.body.hostname);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/ingress/resolve', (req, res) => {
  try {
    const hostname = req.query.hostname || req.headers.host;
    const route = domainManager.resolveRoute(hostname);
    if (!route) {
      return res.status(404).json({ found: false, message: `No hay ruta asignada para ${hostname}` });
    }
    const traffic = containerOrchestrator.trafficAllocation;
    const effectivePod = route.targetPod;
    res.json({
      found: true,
      hostname,
      matchedRoute: route.hostname,
      isWildcard: route.isWildcard,
      configuredPod: route.targetPod,
      effectivePod,
      targetPort: effectivePod === 'forge' ? 3001 : 8080,
      cloudflareProxied: route.cloudflareProxied,
      trafficAllocation: traffic
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- WATCHER ---
router.get('/watcher/status', (req, res) => {
  try {
    res.json(containerOrchestrator.getWatcherStatus());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/watcher/start', (req, res) => {
  try {
    const { directory } = req.body;
    const result = containerOrchestrator.watchDirectory(directory || process.cwd());
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/watcher/stop', async (req, res) => {
  try {
    const result = await containerOrchestrator.stopWatching();
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- SSL CERTIFICATES ---
router.get('/ssl/certificates', (req, res) => {
  try {
    res.json({ certificates: sslManager.listCertificates() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/ssl/issue-wildcard', async (req, res) => {
  try {
    const { domain, zoneId, provider } = req.body;
    if (!domain) return res.status(400).json({ error: 'El dominio es obligatorio' });

    const result = await sslManager.issueWildcardCertificate({
      domain,
      zoneId,
      provider: provider || 'lets_encrypt',
      onProgress: (progressData) => {
        containerOrchestrator.emit('ssl_progress', progressData);
      }
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/ssl/issue-ondemand-sslip', async (req, res) => {
  try {
    const result = await sslManager.issueOnDemandSslip(req.body);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/ssl/certificates/:id', (req, res) => {
  try {
    const result = sslManager.revokeCertificate(req.params.id);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- CLOUDFLARE ---
router.get('/cloudflare/config', (req, res) => {
  try {
    const cfg = cloudflareService.config;
    res.json({
      isConfigured: Boolean(cfg.apiToken),
      accountId: cfg.accountId ? `${cfg.accountId.slice(0, 4)}...${cfg.accountId.slice(-4)}` : '',
      hasToken: Boolean(cfg.apiToken),
      useMock: cfg.useMock
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/cloudflare/config', (req, res) => {
  try {
    const updated = cloudflareService.saveConfig(req.body);
    res.json({ success: true, config: { isConfigured: Boolean(updated.apiToken), useMock: updated.useMock } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/cloudflare/verify-token', async (req, res) => {
  try {
    const result = await cloudflareService.verifyToken(req.body.apiToken);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/cloudflare/zones', async (req, res) => {
  try {
    const result = await cloudflareService.listZones();
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/cloudflare/zones/:zoneId/dns-records', async (req, res) => {
  try {
    const result = await cloudflareService.listDnsRecords(req.params.zoneId);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/cloudflare/zones/:zoneId/dns-records', async (req, res) => {
  try {
    const result = await cloudflareService.createDnsRecord(req.params.zoneId, req.body);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/cloudflare/zones/:zoneId/dns-records/:recordId', async (req, res) => {
  try {
    const result = await cloudflareService.deleteDnsRecord(req.params.zoneId, req.params.recordId);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/cloudflare/tunnels', async (req, res) => {
  try {
    const result = await cloudflareService.listTunnels();
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/cloudflare/tunnels', async (req, res) => {
  try {
    const result = await cloudflareService.createTunnel(req.body.name);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- LOGS ---
router.get('/logs', (req, res) => {
  try {
    const { pod, level, limit, search, projectId } = req.query;
    const logs = containerOrchestrator.getLogs({
      pod,
      level,
      limit: limit ? parseInt(limit, 10) : 100,
      search,
      projectId
    });
    res.json({ logs });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- MCP ---
// Endpoint MCP de la revisión 2026-07-28 (Streamable HTTP). Cuelga de /api, así
// que hereda el control de origen y de token de authMiddleware: la
// especificación exige validar `Origin` y responder 403, y eso ya lo hace él.
router.post('/mcp', mcpStreamableHttp.handlePost);
// GET y DELETE eran el stream independiente y el cierre de sesión del
// transporte anterior. Esta revisión los eliminó: 405 con la cabecera Allow.
router.all('/mcp', mcpStreamableHttp.handleMethodNotAllowed);

router.get('/mcp/tools', (req, res) => {
  try {
    res.json({ tools: mcpServer.getToolsDefinition() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DEPRECADO: endpoint de mensajes del transporte HTTP+SSE (revisión
// 2024-11-05). Se mantiene para no romper las configuraciones ya instaladas.
router.post('/mcp/message', async (req, res) => {
  try {
    mcpStreamableHttp.markLegacyTransport(res, 'POST /api/mcp/message');
    const response = await mcpServer.handleJsonRpc(req.body);
    res.json(response);
  } catch (err) {
    res.status(500).json({ jsonrpc: '2.0', id: req.body?.id || null, error: { code: -32603, message: err.message } });
  }
});

router.get('/mcp/audit', (req, res) => {
  try {
    res.json({ auditLog: mcpServer.getAuditLog(req.query.limit ? parseInt(req.query.limit, 10) : 50) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/mcp/config', (req, res) => {
  try {
    const protocol = req.protocol;
    const host = req.get('host');
    const serverUrl = `${protocol}://${host}`;
    res.json(mcpServer.getClientConfigs(serverUrl));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- DOCKER ENGINE ---
router.get('/docker/status', async (req, res) => {
  try {
    const status = await dockerManager.checkDockerStatus(req.query.refresh === 'true');
    res.json(status);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/docker/containers', async (req, res) => {
  try {
    const containers = await dockerManager.listContainers({
      all: req.query.all !== 'false',
      projectId: req.query.projectId
    });
    res.json({ containers });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/docker/containers/:id/stats', async (req, res) => {
  try {
    const stats = await dockerManager.getContainerStats(req.params.id);
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/docker/containers/:id/start', async (req, res) => {
  try {
    const result = await dockerManager.startContainer(req.params.id);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/docker/containers/:id/stop', async (req, res) => {
  try {
    const result = await dockerManager.stopContainer(req.params.id);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/docker/containers/:id/restart', async (req, res) => {
  try {
    const result = await dockerManager.restartContainer(req.params.id);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/docker/containers/:id/logs', async (req, res) => {
  try {
    const lines = req.query.lines ? parseInt(req.query.lines, 10) : 100;
    const logs = await dockerManager.getLogs(req.params.id, lines);
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- DATABASE & PROJECT BACKUP/RESTORE ---
router.post('/backup/export/:projectId', async (req, res) => {
  try {
    const result = await dbBackupManager.exportProject(req.params.projectId);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/backup/restore', async (req, res) => {
  try {
    const { backupFilePath } = req.body;
    if (!backupFilePath) return res.status(400).json({ error: 'Ruta de archivo de backup requerida' });
    const result = await dbBackupManager.restoreProject(backupFilePath);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/backup/list', async (req, res) => {
  try {
    const backups = await dbBackupManager.listBackups();
    res.json({ backups });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/backup/dump-command', async (req, res) => {
  try {
    const { dbType, options } = req.body;
    const cmd = await dbBackupManager.generateDbDumpCommand(dbType, options);
    res.json({ command: cmd });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --- BASES DE DATOS GESTIONADAS ---
//
// Orden importante: las rutas literales (/engines, /status, /storage) van antes
// que /:id, porque Express resuelve por orden de registro y `:id` capturaría
// "engines" como identificador.

router.get('/databases/engines', (req, res) => {
  try {
    res.json({ engines: databaseManager.listEngines() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/databases/status', async (req, res) => {
  try {
    res.json(await databaseManager.dockerStatus());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/databases/storage', (req, res) => {
  try {
    res.json(databaseManager.getS3Config());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.put('/databases/storage', (req, res) => {
  try {
    res.json(databaseManager.setS3Config(req.body));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/databases/storage/test', async (req, res) => {
  try {
    res.json(await databaseManager.testS3());
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/databases', (req, res) => {
  try {
    res.json({ databases: databaseManager.list({ projectId: req.query.projectId }) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Aprovisionamiento. Devuelve la cadena de conexión UNA sola vez: a partir de
// aquí hay que pedirla en /credentials.
router.post('/databases', async (req, res) => {
  try {
    res.status(201).json(await databaseManager.provision(req.body));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/databases/:id', (req, res) => {
  try {
    res.json(databaseManager.get(req.params.id));
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.delete('/databases/:id', async (req, res) => {
  try {
    // Borrar el volumen es destructivo e irreversible: nunca por defecto.
    const result = await databaseManager.remove(req.params.id, {
      deleteVolume: req.query.deleteVolume === 'true',
      deleteBackups: req.query.deleteBackups === 'true'
    });
    res.json(result);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

/**
 * Único endpoint que devuelve la contraseña en claro. Deliberadamente aparte
 * del listado y del detalle: así una captura de pantalla del panel, un log de
 * proxy o un `curl /api/databases` no filtran nada.
 */
router.get('/databases/:id/credentials', (req, res) => {
  try {
    res.json(databaseManager.getCredentials(req.params.id));
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.get('/databases/:id/health', async (req, res) => {
  try {
    res.json(await databaseManager.refreshHealth(req.params.id));
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.post('/databases/:id/start', async (req, res) => {
  try {
    res.json(await databaseManager.start(req.params.id));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/databases/:id/stop', async (req, res) => {
  try {
    res.json(await databaseManager.stop(req.params.id));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/databases/:id/restart', async (req, res) => {
  try {
    res.json(await databaseManager.restart(req.params.id));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/**
 * Publicar el puerto en el host. Sin `acknowledgeRisk: true` el servicio se
 * niega a enlazar en 0.0.0.0, y la respuesta trae el aviso que la interfaz debe
 * mostrar tal cual.
 */
router.post('/databases/:id/exposure', async (req, res) => {
  try {
    res.json(await databaseManager.setExposure(req.params.id, req.body || {}));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/databases/:id/backups', (req, res) => {
  try {
    res.json({ backups: databaseManager.listBackups(req.params.id) });
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.post('/databases/:id/backups', async (req, res) => {
  try {
    res.json(await databaseManager.runBackup(req.params.id, { trigger: 'manual' }));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/databases/:id/restore', async (req, res) => {
  try {
    const { backupId, remoteKey } = req.body || {};
    if (!backupId && !remoteKey) {
      return res.status(400).json({ error: 'Indique backupId o remoteKey' });
    }
    res.json(await databaseManager.restore(req.params.id, { backupId, remoteKey }));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.put('/databases/:id/schedule', (req, res) => {
  try {
    const { enabled, cron } = req.body || {};
    res.json(databaseManager.setSchedule(req.params.id, { enabled, cron }));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.put('/databases/:id/retention', (req, res) => {
  try {
    const { daily, weekly } = req.body || {};
    res.json(databaseManager.setRetention(req.params.id, { daily, weekly }));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/databases/:id/retention/apply', async (req, res) => {
  try {
    res.json(await databaseManager.applyRetention(req.params.id));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --- INGRESS: autorización de certificados bajo demanda ---
//
// Caddy llama aquí en el primer handshake TLS de un dominio que no conoce,
// antes de pedir el certificado. Contrato verificado en el código de Caddy
// (modules/caddytls/ondemand.go): hace GET con el parámetro `domain`, un 2xx
// autoriza, cualquier otro código deniega, no sigue redirecciones y abandona a
// los 10 segundos.
//
// Es el punto que impide que alguien apunte su dominio a este servidor y nos
// haga emitir certificados a su costa, agotando la cuota de Let's Encrypt. Por
// eso Caddy considera obligatorio configurarlo.
//
// Sin autenticación a propósito: quien llama es Caddy, que no tiene token. Solo
// revela si un dominio está configurado, que es información que cualquiera
// puede deducir resolviendo el DNS.
router.get('/ingress/ask', (req, res) => {
  const domain = String(req.query.domain || '').trim().toLowerCase();

  if (!domain) {
    return res.status(400).type('text/plain').send('falta el parámetro domain');
  }

  const route = domainManager.resolveRoute(domain);
  if (!route) {
    // 403, no 404: es una denegación deliberada, no un despiste.
    return res.status(403).type('text/plain').send(`dominio no configurado en Culkibo: ${domain}`);
  }
  if (route.status === 'disabled') {
    return res.status(403).type('text/plain').send(`dominio deshabilitado: ${domain}`);
  }

  containerOrchestrator.addLog('INFO', 'edge', `[Edge:TLS] Certificado autorizado para ${domain} (regla: ${route.hostname})`);
  return res.status(200).type('text/plain').send('ok');
});

router.get('/ingress/status', async (req, res) => {
  try {
    const detection = await caddyManager.detect({ force: req.query.force === '1' });
    let routes = [];
    if (detection.available) {
      try { routes = await caddyManager.listRoutes(); } catch (e) { /* configuración aún sin cargar */ }
    }
    res.json({
      ...detection,
      routesManaged: routes.length,
      routes: routes.map(r => ({ id: r['@id'], hosts: r.match?.[0]?.host || [] }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- NOTIFICACIONES (Telegram / Discord / Slack / Webhook) ---
router.get('/notifications/config', (req, res) => {
  try {
    res.json(notificationService.getConfig());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/notifications/config', (req, res) => {
  try {
    res.json(notificationService.setConfig(req.body || {}));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/notifications/history', (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 30, 100);
    res.json({ notifications: notificationService.getHistory(limit) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/notifications/test', async (req, res) => {
  try {
    const result = await notificationService.notify({
      event: 'info',
      level: 'info',
      title: 'Prueba de notificaciones',
      message: 'Si lees esto, Culkibo puede avisarte por este canal cuando un servicio se caiga o falle un despliegue.',
      force: true
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- GITHUB INTEGRATION ---
router.get('/github/status', (req, res) => {
  try {
    const status = githubService.getStatus();
    res.json(status);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/github/connect', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ error: 'El token de GitHub es obligatorio' });
    }
    const result = await githubService.connect(token);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/github/disconnect', async (req, res) => {
  try {
    const result = await githubService.disconnect();
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/github/repos', async (req, res) => {
  try {
    const { page, perPage, per_page, search, sort } = req.query;
    const result = await githubService.getRepositories({
      page: page ? parseInt(page, 10) : 1,
      perPage: (perPage || per_page) ? parseInt(perPage || per_page, 10) : 30,
      search: search || '',
      sort: sort || 'updated'
    });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/github/repos/:owner/:repo/branches', async (req, res) => {
  try {
    const { owner, repo } = req.params;
    const branches = await githubService.getBranches(owner, repo);
    res.json(branches);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/github/auto-detect', async (req, res) => {
  try {
    const { owner, repo, branch } = req.body;
    if (!owner || !repo) {
      return res.status(400).json({ error: 'Propietario (owner) y repositorio (repo) son obligatorios' });
    }
    const analysis = await githubService.autoDetectRepo(owner, repo, branch || 'main');
    res.json(analysis);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Helper to normalize and extract owner/repo slug
function extractRepoSlug(gitUrl) {
  if (!gitUrl || typeof gitUrl !== 'string') return null;
  const clean = gitUrl.trim().toLowerCase().replace(/\.git$/, '');
  const match = clean.match(/(?:github\.com[/:])([^/]+)\/([^/]+)$/i) || clean.match(/^([^/]+)\/([^/]+)$/);
  if (match) {
    return `${match[1]}/${match[2]}`.toLowerCase();
  }
  return null;
}

// --- GITHUB WEBHOOKS & AUTO-DEPLOY ---
router.post('/webhooks/github', async (req, res) => {
  try {
    const signature = req.headers['x-hub-signature-256'];
    const event = req.headers['x-github-event'] || 'push';
    const projectId = req.query.projectId || req.body?.projectId;

    let bodyData = req.body;
    if (bodyData && typeof bodyData.payload === 'string') {
      try {
        bodyData = JSON.parse(bodyData.payload);
      } catch (e) {}
    }

    // Resolve target project
    let project = null;
    if (projectId) {
      project = projectManager.getById(projectId);
      if (!project) {
        return res.status(404).json({ error: `Proyecto con ID '${projectId}' no encontrado` });
      }
    }

    const payloadRepo = bodyData?.repository;
    if (!project && payloadRepo) {
      const allProjects = projectManager.getAll();
      const targetSlug = (payloadRepo.full_name || '').toLowerCase();
      const repoHtml = (payloadRepo.html_url || '').toLowerCase().replace(/\.git$/, '');
      const repoClone = (payloadRepo.clone_url || '').toLowerCase().replace(/\.git$/, '');

      project = allProjects.find(p => {
        if (p.githubOwner && p.githubRepo) {
          const pSlug = `${p.githubOwner}/${p.githubRepo}`.toLowerCase();
          if (pSlug === targetSlug) return true;
        }
        if (p.gitRepo) {
          const pSlug = extractRepoSlug(p.gitRepo);
          if (pSlug && pSlug === targetSlug) return true;
          const cleanGit = p.gitRepo.toLowerCase().replace(/\.git$/, '');
          if (cleanGit === repoHtml || cleanGit === repoClone) return true;
        }
        return false;
      });
    }

    // HMAC SHA-256 signature verification if project has secret or if signature is sent
    const secret = project?.webhookSecret || process.env.GITHUB_WEBHOOK_SECRET;
    if (secret) {
      if (!signature || typeof signature !== 'string') {
        return res.status(401).json({ error: 'Cabecera x-hub-signature-256 ausente o inválida' });
      }
      const rawPayload = req.rawBody || Buffer.from(JSON.stringify(req.body));
      const hmac = crypto.createHmac('sha256', secret);
      hmac.update(rawPayload);
      const expectedSignature = `sha256=${hmac.digest('hex')}`.toLowerCase();
      const clientSignature = signature.trim().toLowerCase();

      const sigBuffer = Buffer.from(clientSignature);
      const expectedBuffer = Buffer.from(expectedSignature);
      if (sigBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
        return res.status(401).json({ error: 'Firma de webhook inválida (HMAC SHA-256 mismatch)' });
      }
    }

    // Handle Ping event
    if (event === 'ping') {
      if (project) {
        containerOrchestrator.addLog('INFO', 'citadel', `[GitHub:Webhook] Conexión de webhook verificada con éxito para ${project.name}`, new Date(), project.id);
      }
      return res.json({
        success: true,
        message: 'Pong! Webhook de GitHub verificado correctamente.',
        zen: bodyData?.zen,
        hookId: bodyData?.hook_id,
        projectId: project?.id || null
      });
    }

    // Handle Push event
    if (event === 'push') {
      if (!project) {
        return res.status(404).json({ error: 'No se encontró un proyecto asociado a este repositorio' });
      }

      const ref = bodyData?.ref || '';
      const pushedBranch = ref.replace(/^refs\/heads\//, '');
      const configuredBranch = project.gitBranch || 'main';

      if (pushedBranch && pushedBranch !== configuredBranch) {
        containerOrchestrator.addLog('INFO', 'citadel', `[GitHub:Webhook] Push ignorado en rama '${pushedBranch}'. El proyecto '${project.name}' está configurado para la rama '${configuredBranch}'.`, new Date(), project.id);
        return res.json({
          success: true,
          deployed: false,
          reason: `Rama '${pushedBranch}' no coincide con la rama configurada '${configuredBranch}'`
        });
      }

      if (project.autoDeploy === false) {
        containerOrchestrator.addLog('INFO', 'citadel', `[GitHub:Webhook] Push recibido pero el auto-despliegue está deshabilitado para '${project.name}'.`, new Date(), project.id);
        return res.json({
          success: true,
          deployed: false,
          reason: 'Auto-despliegue deshabilitado para este proyecto'
        });
      }

      const commitSha = bodyData?.after || bodyData?.head_commit?.id || `c_${Date.now().toString(36)}`;
      const shortSha = commitSha.substring(0, 7);
      const commitMsg = bodyData?.head_commit?.message || 'Push automático desde GitHub';
      const author = bodyData?.head_commit?.author?.name || bodyData?.pusher?.name || 'GitHub';
      const repoName = payloadRepo?.full_name || project.gitRepo || project.name;
      const now = new Date().toISOString();

      containerOrchestrator.addLog('INFO', 'citadel', `[GitHub:Webhook] 🚀 Push recibido en ${repoName} (${pushedBranch}) por ${author}: "${commitMsg.trim()}" (${shortSha})`, new Date(), project.id);
      containerOrchestrator.addLog('INFO', 'citadel', `[Citadel:Deploy] Iniciando despliegue automatizado para ${project.name}...`, new Date(), project.id);

      // Trigger deployment in orchestrator
      await containerOrchestrator.deployRelease({
        imageTag: `gh-${shortSha}`,
        gitCommit: shortSha,
        description: `GitHub Auto-Deploy: ${commitMsg.trim()}`
      });

      // Hot sync trigger on Forge
      await containerOrchestrator.triggerHotSync({
        changedFile: `git:push [${shortSha}]`,
        diffSize: `${(bodyData?.commits || []).length || 1} commit(s)`
      });

      // Update project record
      const lastCommit = {
        sha: shortSha,
        message: commitMsg.trim(),
        author,
        timestamp: now
      };
      projectManager.update(project.id, {
        lastDeployedAt: now,
        lastCommit
      });

      // Emit real-time webhook deploy event for WebSocket broadcast
      containerOrchestrator.emit('github_deploy', {
        projectId: project.id,
        projectName: project.name,
        branch: pushedBranch,
        commit: shortSha,
        author,
        message: commitMsg.trim(),
        timestamp: now
      });

      containerOrchestrator.addLog('SUCCESS', 'citadel', `[GitHub:Webhook] ✅ Despliegue completado para ${project.name} (${shortSha})`, new Date(), project.id);

      return res.json({
        success: true,
        deployed: true,
        projectId: project.id,
        branch: pushedBranch,
        commit: shortSha,
        deployedAt: now
      });
    }

    res.json({ success: true, message: `Evento ${event} recibido sin acción requerida.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
