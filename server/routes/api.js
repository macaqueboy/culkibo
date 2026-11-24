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
const ingressManager = require('../services/ingressManager');
const deployManager = require('../services/deployManager');
const catalogManager = require('../services/catalogManager');
const liveSyncEngine = require('../services/liveSyncEngine');
const wordpressMigrator = require('../services/wordpressMigrator');
const universalImporter = require('../services/universalImporter');
const metricsCollector = require('../services/metricsCollector');
const systemDoctor = require('../services/systemDoctor');
const auditLogger = require('../services/auditLogger');
const cronManager = require('../services/cronManager');
const previewManager = require('../services/previewManager');
const webhookService = require('../services/webhookService');
const {
  authorizeRequest,
  authStatus,
  tokenMatches,
  addAllowedOrigin,
  createWsTicket,
  rotateToken,
  clientIp,
  checkAuthBruteForce,
  recordAuthFailure,
  getBruteForceStats
} = require('../middleware/auth');
const { createRateLimiter: createSharedLimiter } = require('../services/rateLimiter');
const { isPrivateIp, assertContainedPath } = require('../services/ssrfGuard');
const path = require('path');
const fs = require('fs');
const os = require('os');

const ROOT_BASE_DIR = process.env.CULKIBO_DATA_DIR
  ? path.resolve(process.env.CULKIBO_DATA_DIR)
  : path.resolve(__dirname, '..', '..');

const IS_TEST_ENV = process.env.NODE_ENV === 'test';
function createRateLimiter({ max = 500, windowMs = 60000, prefix = 'global', bypassLoopback = true } = {}) {
  const shared = createSharedLimiter({
    max,
    windowMs,
    bypassLoopback,
    label: prefix,
    onLimit: () => metricsCollector.recordSecurityEvent('rateLimited429')
  });
  return function rateLimiterMiddleware(req, res, next) {
    if (IS_TEST_ENV || process.env.NODE_ENV === 'test') return next();
    return shared(req, res, next);
  };
}

const rateLimiter = createRateLimiter();
const authVerifyLimiter = createRateLimiter({ max: 15, windowMs: 60000, prefix: 'auth', bypassLoopback: false });
const authSessionLimiter = createRateLimiter({ max: 60, windowMs: 60000, prefix: 'auth_sess', bypassLoopback: true });
const sensitiveAuthLimiter = createRateLimiter({ max: 10, windowMs: 60000, prefix: 'auth_sensitive', bypassLoopback: false });
const wsTicketLimiter = createRateLimiter({ max: 30, windowMs: 60000, prefix: 'ws_ticket', bypassLoopback: true });
const webhookLimiter = createRateLimiter({ max: 60, windowMs: 60000, prefix: 'webhook', bypassLoopback: true });
const askLimiter = createRateLimiter({ max: 120, windowMs: 60000, prefix: 'ask', bypassLoopback: false });
const importLimiter = createRateLimiter({ max: 30, windowMs: 60000, prefix: 'import', bypassLoopback: true });
const sqlImportLimiter = createRateLimiter({ max: 4, windowMs: 60000, prefix: 'wp_sql', bypassLoopback: false });
const heavyOpLimiter = createRateLimiter({ max: 15, windowMs: 60000, prefix: 'heavy_op', bypassLoopback: true });
const execLimiter = createRateLimiter({ max: 20, windowMs: 60000, prefix: 'runtime_exec', bypassLoopback: false });
const certAndAdminLimiter = createRateLimiter({ max: 30, windowMs: 60000, prefix: 'admin_ops', bypassLoopback: true });
const mcpLimiter = createRateLimiter({ max: 180, windowMs: 60000, prefix: 'mcp', bypassLoopback: true });

// Auditoría automática de todas las mutaciones del plano de control y lecturas de secretos
router.use((req, res, next) => {
  const isMutation = req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'OPTIONS';
  const isSecretRead = req.method === 'GET' && (/\/credentials$/.test(req.path) || /\/secrets$/.test(req.path));
  if (!isMutation && !isSecretRead) return next();
  const t0 = Date.now();
  res.once('finish', () => {
    try {
      auditLogger.record({
        source: 'http',
        action: `${req.method} ${req.path}`,
        method: req.method,
        path: req.path,
        ip: clientIp(req),
        status: res.statusCode,
        durationMs: Date.now() - t0
      });
    } catch (e) {}
  });
  next();
});

router.use('/projects', rateLimiter);
router.use('/import/wordpress/import-sql', sqlImportLimiter);
router.use('/import', importLimiter);
router.use('/migrate', importLimiter);
router.use('/databases', rateLimiter);
router.use('/domains', rateLimiter);
router.use('/docker', rateLimiter);
router.use('/github', rateLimiter);
router.use('/cloudflare', rateLimiter);
router.use('/backup', rateLimiter);
router.use('/ssl', certAndAdminLimiter);
router.use('/system', certAndAdminLimiter);
router.use('/notifications', certAndAdminLimiter);
router.use('/watcher', certAndAdminLimiter);
router.use('/pods', certAndAdminLimiter);
router.use('/deploy/prune-cache', heavyOpLimiter);
router.use('/mcp', mcpLimiter);
router.use('/auth/verify', authVerifyLimiter);
router.use('/auth/rotate', sensitiveAuthLimiter);
router.use('/auth/ws-ticket', wsTicketLimiter);
router.use('/auth/session', authSessionLimiter);
router.use('/webhooks', webhookLimiter);
router.use('/ingress/ask', askLimiter);
router.use('/ingress', certAndAdminLimiter);

let _cachedPublicIp = { at: 0, ip: /** @type {string | null} */ (null) };
const _askLogThrottle = new Map();

async function detectPublicIp() {
  const now = Date.now();
  if (_cachedPublicIp.ip && (now - _cachedPublicIp.at) < 300000) {
    return _cachedPublicIp.ip;
  }
  const providers = [
    async () => {
      const r = await fetch('https://api.ipify.org?format=json', { signal: AbortSignal.timeout(4000) });
      /** @type {any} */ const d = await r.json();
      return d && typeof d.ip === 'string' ? d.ip.trim() : null;
    },
    async () => {
      const r = await fetch('https://ipv4.icanhazip.com', { signal: AbortSignal.timeout(4000) });
      return (await r.text()).trim();
    },
    async () => {
      const r = await fetch('https://ifconfig.me/ip', { signal: AbortSignal.timeout(4000) });
      return (await r.text()).trim();
    }
  ];
  for (const probe of providers) {
    try {
      const ip = await probe();
      if (ip && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
        _cachedPublicIp = { at: now, ip };
        return ip;
      }
    } catch (e) {}
  }
  return _cachedPublicIp.ip || null;
}

// --- PROJECTS ---
router.get('/projects', (req, res) => {
  try {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.send(projectManager.getAllSerialized());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/projects', async (req, res) => {
  try {
    const project = projectManager.create(req.body);
    // Automatically pre-clone and prepare dependencies in the background
    if (project.gitRepo) {
      localRunner.prepareProject(project).catch(err => {
        console.warn(`[AutoPrepare] Could not auto-prepare ${project.name}:`, err.message);
      });
    }
    // `projectManager.create()` ya programa un volcado atómico agrupado (15 ms);
    // no bloqueamos la respuesta HTTP en I/O de disco igual que PUT /projects/:id.
    res.status(201).json(project);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/projects/:id', (req, res) => {
  try {
    const serialized = projectManager.getByIdSerialized(req.params.id);
    if (!serialized) return res.status(404).json({ error: 'Proyecto no encontrado' });
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.send(serialized);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.put('/projects/:id', (req, res) => {
  try {
    if (!projectManager.getById(req.params.id)) {
      return res.status(404).json({ error: 'Proyecto no encontrado' });
    }
    const project = projectManager.update(req.params.id, req.body);
    res.json(project);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/projects/:id', async (req, res) => {
  try {
    const projectId = req.params.id;
    const existing = projectManager.getById(projectId);
    if (!existing) return res.status(404).json({ error: 'Proyecto no encontrado' });

    try { await localRunner.stop(projectId, existing.localPort); } catch (e) {}
    try { liveSyncEngine.resetSession(projectId); } catch (e) {}
    try { cronManager.forgetProject(projectId); } catch (e) {}
    try { await previewManager.destroyProjectPreviews(projectId); } catch (e) {}

    const attached = domainManager.listByProject(projectId);
    if (attached.length > 0) {
      domainManager.detachByProject(projectId);
    }
    const projectDbs = databaseManager.list ? databaseManager.list({ projectId }) : [];
    projectManager.delete(projectId);
    await projectManager.flushToDisk(projectId);
    try { deployManager.forget(projectId); } catch (e) {}
    try { githubService.forgetDeliveries(projectId); } catch (e) {}

    // Limpiar directorio clonado bajo projects/<id> (nunca tocar un localPath externo del usuario)
    try {
      const clonedDir = path.join(ROOT_BASE_DIR, 'projects', projectId);
      if (fs.existsSync(clonedDir) && typeof localRunner.cleanDirectory === 'function') {
        localRunner.cleanDirectory(clonedDir);
      }
    } catch (e) {}

    const ingress = attached.length > 0
      ? await ingressManager.reconcile()
      : await ingressManager.removeProject(projectId);
    res.json({
      success: true,
      detachedDomains: attached.map(d => d.hostname),
      remainingDatabases: projectDbs.map(d => ({ id: d.id, name: d.name, engine: d.engine })),
      ingress
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/projects/:id/activate', async (req, res) => {
  try {
    const project = projectManager.activate(req.params.id);
    await projectManager.flushToDisk(req.params.id);
    res.json(project);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.post('/projects/:id/hibernate', async (req, res) => {
  try {
    let project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });

    try {
      await localRunner.stop(project.id, project.localPort);
    } catch(err) {
      console.error('[LocalRunner] Could not stop server on hibernate:', err.message);
    }

    try {
      if (project.resources && Array.isArray(project.resources)) {
        for (const r of project.resources) {
          const containerName = `culkibo_local_${project.id}_${(r.name || 'res').replace(/[^a-zA-Z0-9]/g, '')}`;
          try {
            await dockerManager.stopContainer(containerName);
          } catch(e) {}
        }
      }
    } catch(e) {}

    const updated = projectManager.hibernate(req.params.id);
    await projectManager.flushToDisk(req.params.id);
    // P1-1: syncProject conserva la ruta de producción en Caddy si sigue viva y la retira si no
    const ingress = await ingressManager.syncProject(req.params.id);
    res.json({ ...updated, ingress });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/projects/:id/start-local', async (req, res) => {
  try {
    let project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });

    if (!project.localPort) {
      project.localPort = await localRunner.getAvailablePort(project.forgePort || 3001);
    }

    // P1-14: propagar error real si localRunner.start falla (no devolver 200 active falso)
    await localRunner.start(project);

    try {
      if (project.resources && Array.isArray(project.resources)) {
        for (const r of project.resources) {
          const containerName = `culkibo_local_${project.id}_${(r.name || 'res').replace(/[^a-zA-Z0-9]/g, '')}`;
          try {
            await dockerManager.startContainer(containerName);
          } catch(e) {}
        }
      }
    } catch(e) {}

    project.status = 'active';
    project.localRunning = true;
    project = projectManager.update(req.params.id, project);

    const ingress = await ingressManager.syncProject(project.id);

    await projectManager.flushToDisk(req.params.id);
    res.json({ ...project, ingress });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const handleStopProject = async (req, res) => {
  try {
    let project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });

    try {
      await localRunner.stop(project.id, project.localPort);
    } catch(err) {
      console.error('[LocalRunner] Could not stop server:', err.message);
    }

    // P1-14: detener contenedores del proyecto sin matar puertos ajenos no iniciados por Culkibo
    try {
      if (project.resources && Array.isArray(project.resources)) {
        for (const r of project.resources) {
          const containerName = `culkibo_local_${project.id}_${(r.name || 'res').replace(/[^a-zA-Z0-9]/g, '')}`;
          try {
            await dockerManager.stopContainer(containerName);
          } catch(e) {}
        }
      }
    } catch(e) {}

    const updated = projectManager.stop(req.params.id);
    await projectManager.flushToDisk(req.params.id);
    // P1-1: syncProject evita borrar la ruta de producción en Caddy al detener solo el servidor local
    const ingress = await ingressManager.syncProject(req.params.id);
    res.json({ ...updated, ingress });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

router.post('/projects/:id/stop', handleStopProject);
router.post('/projects/:id/stop-local', handleStopProject);

// --- DESPLIEGUE A PRODUCCIÓN ---
//
// `start-local` levanta un servidor de desarrollo; esto construye una imagen y
// deja un servicio durable detrás del proxy. Son cosas distintas y conviven.

/**
 * Detección en seco: qué haría Culkibo con este proyecto, sin construir nada.
 * Es lo que alimenta la vista previa del panel antes de pulsar «Desplegar».
 */
router.get('/projects/:id/deploy/strategy', async (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });

    const rootDir = (project.localPath && fs.existsSync(project.localPath))
      ? project.localPath
      : path.join(ROOT_BASE_DIR, 'projects', project.id);
    let contextDir = rootDir;
    if (project.baseDirectory && project.baseDirectory !== '/' && project.baseDirectory !== '.') {
      try {
        contextDir = assertContainedPath(rootDir, String(project.baseDirectory).replace(/^\/+/, ''));
      } catch (e) {}
    }
    if (!fs.existsSync(contextDir)) {
      return res.json({
        available: false,
        reason: 'El proyecto todavía no tiene código clonado en este host',
        contextDir
      });
    }
    const strategy = await deployManager.detectStrategy(contextDir, project);
    const dockerfile = strategy.builder === 'generated' ? deployManager.generateDockerfile(strategy) : null;
    res.json({
      available: true,
      contextDir,
      docker: await deployManager.detectDocker(),
      hostnames: deployManager.hostnamesFor(project),
      strategy,
      generatedDockerfile: dockerfile
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * Lanza un despliegue. Responde en cuanto arranca con `deploymentId` preasignado.
 */
router.post('/projects/:id/deploy', heavyOpLimiter, async (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    if (deployManager.locks.has(project.id)) {
      return res.status(409).json({ error: 'Ya hay un despliegue en curso para este proyecto' });
    }

    const deploymentId = `dep_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const options = { deploymentId };
    if (req.body && typeof req.body === 'object') {
      for (const key of ['healthTimeoutMs', 'drainTimeoutMs', 'healthIntervalMs', 'buildTimeoutMs', 'keepReleases']) {
        const value = Number(req.body[key]);
        if (Number.isFinite(value) && value > 0) options[key] = value;
      }
      if (req.body.memoryMb != null) {
        const mem = Math.round(Number(req.body.memoryMb));
        if (Number.isFinite(mem) && mem >= 32 && mem <= 65536) options.memoryMb = mem;
      }
      if (typeof req.body.version === 'string') options.version = req.body.version;
      if (typeof req.body.commit === 'string' && /^[0-9a-f]{7,40}$/i.test(req.body.commit.trim())) {
        options.commit = req.body.commit.trim();
      }
      if (req.body.gitSync === false) options.gitSync = false;
      if (req.body.skipHooks === true) options.skipHooks = true;
    }
    options.trigger = 'manual';

    const started = deployManager.deploy(project, options);
    started.catch(() => {});

    res.status(202).json({
      accepted: true,
      deploymentId,
      message: 'Despliegue iniciado. Sigue el progreso en los logs en vivo.',
      projectId: project.id
    });
  } catch (err) {
    res.status(409).json({ error: err.message });
  }
});

router.post('/projects/:id/deploy/cancel', (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const result = deployManager.cancelDeploy(project.id, {
      reason: (req.body && req.body.reason) || 'Cancelado desde el panel'
    });
    if (!result.cancelled) {
      return res.status(result.status || 404).json(result);
    }
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/projects/:id/deployments', (req, res) => {
  try {
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const history = deployManager.listDeployments(req.params.id, limit)
      .map(({ logLines, ...rest }) => ({ ...rest, logLineCount: (logLines || []).length }));
    res.json({ deployments: history });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/projects/:id/deployments/:deployId', (req, res) => {
  try {
    const deployment = deployManager.getDeployment(req.params.id, req.params.deployId);
    if (!deployment) return res.status(404).json({ error: 'Despliegue no encontrado' });
    res.json(deployment);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/projects/:id/deploy/status', async (req, res) => {
  try {
    res.json(await deployManager.status(req.params.id));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/projects/:id/rollback', heavyOpLimiter, async (req, res) => {
  try {
    const opts = {};
    if (req.body && typeof req.body.deploymentId === 'string' && req.body.deploymentId.trim()) {
      opts.deploymentId = req.body.deploymentId.trim();
    }
    const result = await deployManager.rollback(req.params.id, opts);
    const { logLines, ...rest } = result;
    res.json({ ...rest, logLines });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --- LOGS, STATS Y EXEC SEGURO DEL CONTENEDOR DE PRODUCCIÓN ---
router.get('/projects/:id/runtime/logs', async (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const result = await deployManager.getRuntimeLogs(project.id, {
      tail: req.query.tail,
      since: req.query.since || null,
      timestamps: req.query.timestamps !== '0',
      target: req.query.target === 'previous' ? 'previous' : 'current'
    });
    if (!result.ok && result.status) return res.status(result.status).json(result);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/projects/:id/runtime/logs/stream', (req, res) => {
  const project = projectManager.getById(req.params.id);
  if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
  try {
    res.setTimeout(0);
    const stream = deployManager.streamRuntimeLogs(project.id, {
      tail: req.query.tail || 100,
      target: req.query.target === 'previous' ? 'previous' : 'current',
      onLine: (payload) => {
        if (!res.writableEnded && !res.destroyed) {
          res.write(`event: log\ndata: ${JSON.stringify(payload)}\n\n`);
        }
      },
      onEnd: () => {
        clearInterval(ka);
        clearTimeout(maxLife);
        if (!res.writableEnded && !res.destroyed) {
          res.write(`event: end\ndata: {"ended":true}\n\n`);
          res.end();
        }
      }
    });
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no'
    });
    res.write(`event: ready\ndata: ${JSON.stringify({ containerName: stream.containerName })}\n\n`);
    const ka = setInterval(() => {
      if (!res.writableEnded && !res.destroyed) res.write(': keepalive\n\n');
    }, 15000);
    if (ka.unref) ka.unref();
    const maxLife = setTimeout(() => { stream.close(); }, 30 * 60 * 1000);
    if (maxLife.unref) maxLife.unref();
    const stopAll = () => {
      clearInterval(ka);
      clearTimeout(maxLife);
      stream.close();
    };
    req.on('close', stopAll);
    res.on('error', stopAll);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

router.get('/projects/:id/runtime/stats', async (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const result = await deployManager.getRuntimeStats(project.id);
    if (!result.ok && result.status) return res.status(result.status).json(result);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/projects/:id/runtime/exec', execLimiter, async (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const { command, workdir, timeoutMs } = req.body || {};
    const result = await deployManager.execInContainer(project.id, { command, workdir, timeoutMs });
    res.json(result);
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message });
  }
});

// --- TAREAS PROGRAMADAS CRON POR PROYECTO ---
router.get('/projects/:id/crons', (req, res) => {
  const project = projectManager.getById(req.params.id);
  if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
  res.json({ jobs: cronManager.list(project.id) });
});

router.post('/projects/:id/crons', (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const job = cronManager.create(project.id, req.body || {});
    res.status(201).json(job);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.put('/projects/:id/crons/:jobId', (req, res) => {
  try {
    const existing = cronManager.getById(req.params.jobId);
    if (!existing || existing.projectId !== req.params.id) {
      return res.status(404).json({ error: 'Tarea cron no encontrada' });
    }
    const updated = cronManager.update(req.params.jobId, req.body || {});
    res.json(updated);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/projects/:id/crons/:jobId', (req, res) => {
  const existing = cronManager.getById(req.params.jobId);
  if (!existing || existing.projectId !== req.params.id) {
    return res.status(404).json({ error: 'Tarea cron no encontrada' });
  }
  cronManager.remove(req.params.jobId);
  res.json({ deleted: true, id: req.params.jobId });
});

router.post('/projects/:id/crons/:jobId/run', heavyOpLimiter, async (req, res) => {
  try {
    const existing = cronManager.getById(req.params.jobId);
    if (!existing || existing.projectId !== req.params.id) {
      return res.status(404).json({ error: 'Tarea cron no encontrada' });
    }
    const run = await cronManager.runNow(req.params.jobId, { trigger: 'manual' });
    res.json({ run });
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message });
  }
});

router.get('/projects/:id/crons/:jobId/runs', (req, res) => {
  const existing = cronManager.getById(req.params.jobId);
  if (!existing || existing.projectId !== req.params.id) {
    return res.status(404).json({ error: 'Tarea cron no encontrada' });
  }
  res.json({ runs: cronManager.getRuns(req.params.jobId) });
});

// --- VISTAS PREVIAS (PREVIEW DEPLOYMENTS POR RAMA / PR) ---
router.get('/projects/:id/previews', (req, res) => {
  const project = projectManager.getById(req.params.id);
  if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
  res.json({
    config: project.previewDeployments,
    previews: previewManager.list(project.id)
  });
});

router.post('/projects/:id/previews', heavyOpLimiter, async (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const { branch, prNumber, commit, title } = req.body || {};
    if (!branch && !prNumber) {
      return res.status(400).json({ error: 'Indica una rama (branch) o un número de PR (prNumber)' });
    }
    const preview = await previewManager.deployPreview(project, {
      branch: branch || project.gitBranch || 'main',
      prNumber: prNumber ?? null,
      commit: commit || null,
      title: title || null
    });
    res.status(201).json(preview);
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message });
  }
});

router.delete('/projects/:id/previews/:key', async (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const result = await previewManager.destroyPreview(project.id, req.params.key);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/projects/:id/previews/:key/logs', async (req, res) => {
  try {
    const result = await previewManager.getLogs(req.params.id, req.params.key, req.query.tail);
    res.json(result);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.post('/projects/:id/deploy/stop', async (req, res) => {
  try {
    res.json(await deployManager.stopProduction(req.params.id));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * El «deshacer» de detener: vuelve a levantar el contenedor de la versión
 * actual y repone su ruta. Sin este endpoint, «Detener» sería irreversible
 * desde el panel y tendría que pedir confirmación; con él es un interruptor.
 */
router.post('/projects/:id/deploy/start', async (req, res) => {
  try {
    res.json(await deployManager.startProduction(req.params.id));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * Poda manual de la caché de BuildKit. Manual a propósito: podar tras cada
 * despliegue es exactamente cómo Coolify pasó de 1 a 4,5 minutos de build.
 */
router.post('/deploy/prune-cache', async (req, res) => {
  try {
    const keepStorageGb = Number((req.body && req.body.keepStorageGb) ?? 10);
    const untilHours = /** @type {number | null} */ (req.body && req.body.untilHours != null ? Number(req.body.untilHours) : null);
    res.json(await deployManager.pruneBuildCache({ keepStorageGb, untilHours }));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- COOLIFY IMPORT ---
router.post('/import/coolify/preview', async (req, res) => {
  try {
    const { apiUrl, apiToken } = req.body;
    const preview = await coolifyMigrator.previewMigration(apiUrl, apiToken);
    res.json(preview);
  } catch (err) {
    const isClientErr = /SSRF|inválida|malformada|protocolo|metadatos|privada|obligatori/i.test(String(err.message || ''));
    res.status(isClientErr ? 400 : 500).json({ error: err.message });
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
    const isClientErr = /SSRF|inválida|malformada|protocolo|metadatos|privada|obligatori/i.test(String(err.message || ''));
    res.status(isClientErr ? 400 : 500).json({ error: err.message });
  }
});

router.post('/import/coolify/migrate-domain', async (req, res) => {
  try {
    const { hostname, serverIp, autoCloudflare } = req.body;
    let zoneId = null;
    /** @type {any} */
    let dnsResult = null;
    
    if (autoCloudflare && serverIp) {
      zoneId = await cloudflareService.findZoneForDomain(hostname);
      if (zoneId) {
        dnsResult = await cloudflareService.upsertDnsRecord(zoneId, {
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
      /** @type {any} */
      const updates = { 
        sslStatus: 'pending_ssl',
        cloudflareZoneId: zoneId || domain.cloudflareZoneId
      };
      if (dnsResult && dnsResult.success) {
        updates.cloudflareProxied = true;
      }
      await domainManager.updateDomain(domain.id, updates);
      // Aquí se lanzaba una emisión de comodín en segundo plano cuyo único
      // efecto real era escribir un PEM inventado. El certificado lo emite
      // Caddy en la primera conexión HTTPS al dominio migrado.
    }

    res.json({ success: true, hostname, dnsResult, tls: 'on_demand' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/import/coolify/migrate-domains-batch', async (req, res) => {
  try {
    const { domains, serverIp, autoCloudflare } = req.body || {};
    if (!Array.isArray(domains) || domains.length === 0) {
      return res.status(400).json({ error: 'Se requiere una lista no vacía de dominios' });
    }
    if (domains.length > 50) {
      return res.status(400).json({ error: 'Máximo 50 dominios por lote' });
    }
    const results = [];
    for (const hostname of domains) {
      try {
        let zoneId = null;
        /** @type {any} */
        let dnsResult = null;
        if (autoCloudflare && serverIp) {
           zoneId = await cloudflareService.findZoneForDomain(hostname);
           if (zoneId) {
             dnsResult = await cloudflareService.upsertDnsRecord(zoneId, {
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
          /** @type {any} */
          const updates = { sslStatus: 'pending_ssl', cloudflareZoneId: zoneId || domain.cloudflareZoneId };
          if (dnsResult && dnsResult.success) updates.cloudflareProxied = true;
          await domainManager.updateDomain(domain.id, updates);
        }
        results.push({ hostname, success: true });
      } catch (e) {
        results.push({ hostname, success: false, error: e.message });
      }
      await new Promise(r => setTimeout(r, 250));
    }
    res.json({ success: true, results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- MIGRADOR WORDPRESS + IMPORTADOR UNIVERSAL (COMPOSE / GIT / PLATAFORMAS) ---
router.post('/import/wordpress/analyze', async (req, res) => {
  try {
    const { url } = req.body || {};
    if (!url) return res.status(400).json({ error: 'Indica la URL de tu web WordPress' });
    const analysis = await wordpressMigrator.analyzeSite(url);
    res.json(analysis);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/import/wordpress/provision', async (req, res) => {
  try {
    const { name, domain, sourceUrl, useSslip, serverIp } = req.body || {};
    const effectiveIp = serverIp || (useSslip ? await detectPublicIp() : null);
    const result = await wordpressMigrator.provisionWordPress({
      name,
      domain,
      sourceUrl,
      useSslip: Boolean(useSslip),
      serverIp: effectiveIp
    });
    res.status(202).json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/import/wordpress/import-sql', async (req, res) => {
  try {
    req.setTimeout(0);
    res.setTimeout(0);
    const { installationId, sqlContent, oldDomain, newDomain } = req.body || {};
    if (!installationId || !sqlContent) {
      return res.status(400).json({ error: 'Se requieren installationId y el contenido SQL' });
    }
    const result = await wordpressMigrator.importSqlDump({ installationId, sqlContent, oldDomain, newDomain });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Subida directa binaria (.sql o .sql.gz hasta 50 MB) sin inflar JSON ni congelar el navegador
router.post('/import/wordpress/import-sql/upload', heavyOpLimiter, async (req, res) => {
  req.setTimeout(0);
  res.setTimeout(0);
  const installationId = String(req.query.installationId || req.headers['x-installation-id'] || '').trim();
  const oldDomain = String(req.query.oldDomain || '').trim();
  const newDomain = String(req.query.newDomain || '').trim();
  if (!installationId) {
    return res.status(400).json({ error: 'Falta el parámetro installationId' });
  }
  const MAX_BYTES = 50 * 1024 * 1024;
  /** @type {Buffer[]} */
  const chunks = [];
  let total = 0;
  try {
    await new Promise((resolve, reject) => {
      req.on('data', (c) => {
        total += c.length;
        if (total > MAX_BYTES) return reject(new Error('El archivo SQL supera el límite de 50 MB'));
        chunks.push(c);
      });
      req.on('error', reject);
      req.on('aborted', () => reject(new Error('Subida cancelada')));
      req.on('end', () => resolve(undefined));
    });
    const sqlBuffer = Buffer.concat(chunks);
    const result = await wordpressMigrator.importSqlDump({ installationId, sqlBuffer, oldDomain, newDomain });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/import/compose/parse', (req, res) => {
  try {
    const { yamlText } = req.body || {};
    res.json(universalImporter.parseDockerCompose(yamlText));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/import/compose/apply', async (req, res) => {
  try {
    const { yamlText, projectName, selectedServices } = req.body || {};
    const result = await universalImporter.importDockerCompose({ yamlText, projectName, selectedServices });
    await projectManager.flushToDisk();
    res.status(201).json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/import/git/inspect', async (req, res) => {
  try {
    const { gitUrl, branch } = req.body || {};
    res.json(await universalImporter.inspectGitUrl(gitUrl, { branch }));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/import/platform/parse', (req, res) => {
  try {
    res.json(universalImporter.parsePlatformConfig(req.body || {}));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/import/universal/create', async (req, res) => {
  try {
    const result = await universalImporter.createImportedProject(req.body || {});
    await projectManager.flushToDisk();
    if (result.project && result.project.gitRepo) {
      localRunner.prepareProject(result.project).catch(() => {});
    }
    res.status(201).json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --- SYSTEM & HEALTH ---
router.get('/server/ip', async (req, res) => {
  res.json({ ip: await detectPublicIp() });
});

// --- OBSERVABILIDAD, MÉTRICAS REALES Y DOCTOR 1-CLIC ---
router.get('/metrics', (req, res) => {
  try {
    const fresh = req.query.fresh === '1';
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.send(metricsCollector.getSnapshotBuffer(fresh));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/observability/snapshot', (req, res) => {
  try {
    const fresh = req.query.fresh === '1';
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.send(metricsCollector.getSnapshotBuffer(fresh));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/system/doctor', async (_req, res) => {
  try {
    const report = await systemDoctor.runDoctor();
    res.json(report);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/system/doctor/fix', async (req, res) => {
  try {
    const action = String((req.body && req.body.action) || '').trim();
    if (!action) return res.status(400).json({ error: 'Indica la acción de remediación (`action`)' });
    const result = await systemDoctor.applyFix(action);
    res.json(result);
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message });
  }
});

router.get('/system/status', (req, res) => {
  try {
    const proc = metricsCollector.sampleProcess();
    res.json({
      name: 'Culkibo',
      status: 'operational',
      version: '1.0.0',
      tagline: 'Orquestador cloud autohospedado',
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version,
      uptimeSeconds: proc.uptimeSeconds,
      memoryUsageMb: proc.memoryMb,
      heapUsedMb: proc.heapUsedMb,
      cpuPercent: proc.cpuPercent,
      panelDomain: ingressManager.panelDomain || null,
      auth: authStatus(),
      capabilities: {
        liveSyncBinary: true,
        merkleVerify: true,
        mcpProtocolVersion: mcpServer.protocol.PROTOCOL_VERSION,
        caddyAvailable: caddyManager.lastDetection ? Boolean(caddyManager.lastDetection.available) : null,
        dockerAvailable: dockerManager.cachedStatus ? Boolean(dockerManager.cachedStatus.available) : null
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/system/audit', (req, res) => {
  try {
    const events = auditLogger.query({
      limit: req.query.limit ? parseInt(String(req.query.limit), 10) : 50,
      source: req.query.source ? String(req.query.source) : '',
      action: req.query.action ? String(req.query.action) : ''
    });
    res.json({ events });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

let _healthSummaryCache = { at: 0, data: /** @type {any} */ (null) };
router.get('/system/health-summary', (req, res) => {
  try {
    const now = Date.now();
    if (!req.query.fresh && _healthSummaryCache.data && (now - _healthSummaryCache.at) < 5000) {
      return res.json(_healthSummaryCache.data);
    }
    const snap = metricsCollector.getSnapshot(false);
    const disk = systemDoctor.checkDiskSpace();
    const permCheck = systemDoctor.checkKeyFilePermissions();
    const auth = authStatus();
    const bf = getBruteForceStats();
    const dbs = databaseManager.list ? databaseManager.list() : [];
    const exposedDbs = dbs.filter((d) => d.exposure && d.exposure.enabled && d.exposure.bindAddress !== '127.0.0.1').length;
    const failedBackups = dbs.filter((d) => d.schedule && d.schedule.lastStatus === 'error').length;
    const certs = sslManager.listCertificates ? sslManager.listCertificates() : [];
    const lastTlsAudit = /** @type {any} */ (ingressManager).lastTlsAudit || null;
    const tlsExpiringSoon = certs.filter((c) => c.isExpired || c.isExpiringSoon).length
      + (lastTlsAudit ? ((lastTlsAudit.expiring?.length || 0) + (lastTlsAudit.expired?.length || 0)) : 0);

    const hostTotalMb = Math.round(os.totalmem() / 1024 / 1024);
    const hostFreeMb = Math.round(os.freemem() / 1024 / 1024);
    const hostMemUsedPct = hostTotalMb > 0 ? Math.round(((hostTotalMb - hostFreeMb) / hostTotalMb) * 100) : 0;

    /** @type {{ lastWatchdogAt: string | null, activeWsClients: number, activeSyncClients: number, activeSseClients: number }} */
    let runtimeMeta = { lastWatchdogAt: null, activeWsClients: 0, activeSyncClients: 0, activeSseClients: 0 };
    try {
      const idx = require('../index');
      if (idx && typeof idx.getRuntimeMeta === 'function') runtimeMeta = idx.getRuntimeMeta();
    } catch (e) {}

    const summary = {
      status: (disk.status === 'fail' || failedBackups > 0) ? 'degraded' : 'healthy',
      timestamp: new Date(now).toISOString(),
      version: '1.0.0',
      uptimeSeconds: snap.uptimeSeconds,
      resources: {
        cpuPercent: snap.process.cpuPercent,
        rssMb: snap.process.memoryMb,
        hostMemUsedPct,
        diskFreeGb: disk.metrics?.freeGb ?? null,
        diskUsedPct: disk.metrics?.usedPct ?? null,
        eventLoopLagP95Ms: snap.eventLoop.p95Ms ?? 0
      },
      security: {
        bindHost: process.env.CULKIBO_BIND || process.env.HOST || process.env.CULKIBO_HOST || '127.0.0.1',
        requireTokenAlways: auth.requireTokenAlways,
        tokenSource: auth.tokenSource,
        tokenRotatedAt: auth.tokenRotatedAt || null,
        activeBruteForceBlocks: bf.activeBlocks,
        authFailuresTotal: snap.security?.authFailures || 0,
        rateLimitedTotal: snap.security?.rateLimited429 || 0,
        originRejectedTotal: snap.security?.originRejected403 || 0,
        exposedDatabases: exposedDbs,
        keyFilePermissionsOk: permCheck.ok,
        activeClients: {
          ws: runtimeMeta.activeWsClients,
          sync: runtimeMeta.activeSyncClients,
          sse: runtimeMeta.activeSseClients
        }
      },
      resilience: {
        caddyAvailable: caddyManager.lastDetection ? Boolean(caddyManager.lastDetection.available) : null,
        dockerAvailable: dockerManager.cachedStatus ? Boolean(dockerManager.cachedStatus.available) : null,
        lastWatchdogAt: runtimeMeta.lastWatchdogAt,
        tlsExpiringSoon,
        failedBackups,
        cronJobsEnabled: cronManager.list().filter((j) => j.enabled).length,
        activePreviews: previewManager.list().filter((p) => p.status === 'active').length
      },
      recentAudit: auditLogger.query({ limit: 15 })
    };
    _healthSummaryCache = { at: now, data: summary };
    res.json(summary);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/system/remote-access', async (req, res) => {
  try {
    const [serverIp, caddy, tunnelsRes] = await Promise.all([
      detectPublicIp(),
      caddyManager.detect(),
      cloudflareService.listTunnels().catch(() => ({ success: false, tunnels: [], isMock: false }))
    ]);
    /** @type {any} */
    const tunnelsInfo = tunnelsRes;
    const protocol = req.protocol;
    const host = req.get('host');
    const baseUrl = ingressManager.panelDomain ? `https://${ingressManager.panelDomain}` : `${protocol}://${host}`;
    res.json({
      panelDomain: ingressManager.panelDomain || null,
      currentOrigin: `${protocol}://${host}`,
      recommendedUrl: baseUrl,
      serverIp,
      auth: authStatus(),
      caddy,
      cloudflare: cloudflareService.getConfigStatus(),
      tunnels: Array.isArray(tunnelsInfo.tunnels) ? tunnelsInfo.tunnels : [],
      tunnelsMock: Boolean(tunnelsInfo.isMock),
      clientConfigs: mcpServer.getClientConfigs(baseUrl, { includeAuthPlaceholder: Boolean(ingressManager.panelDomain) }),
      cliUpdateCommand: 'culkibo update'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/system/panel-domain', async (req, res) => {
  try {
    const raw = String((req.body && req.body.domain) || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!raw) {
      ingressManager.setPanelDomain(null);
      const ingress = await ingressManager.reconcile();
      return res.json({ success: true, panelDomain: null, ingress });
    }
    if (!/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/.test(raw)) {
      return res.status(400).json({ error: `Dominio de panel inválido: «${raw}»` });
    }
    ingressManager.setPanelDomain(raw);
    addAllowedOrigin(`https://${raw}`);
    addAllowedOrigin(`http://${raw}`);
    const ingress = await ingressManager.reconcile();
    res.json({
      success: true,
      panelDomain: raw,
      url: `https://${raw}`,
      ingress
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --- PODS & TRAFFIC ---
router.get('/pods', (req, res) => {
  try {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.send(containerOrchestrator.getPodsSerialized());
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
    // El reparto de tráfico solo existe si lo ejecuta el proxy. Reconciliar
    // reescribe los pesos `weighted_round_robin` de las rutas afectadas.
    const ingress = await ingressManager.reconcile();
    res.json({ ...result, ingress });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/pods/deploy', async (req, res) => {
  try {
    const result = await containerOrchestrator.deployRelease(req.body);
    const ingress = await ingressManager.reconcile();
    res.json({ ...result, ingress });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- DOMAINS ---
router.get('/domains', (req, res) => {
  try {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.send(domainManager.getAllWrappedSerialized());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** Sincroniza `project.domains[]` cuando cambia la vinculación de un dominio (fuente única de verdad). */
function syncProjectDomainsList(projectId, hostname, action) {
  if (!projectId || !hostname) return;
  const proj = projectManager.getById(projectId);
  if (!proj) return;
  const current = Array.isArray(proj.domains) ? proj.domains : [];
  const next = action === 'add'
    ? Array.from(new Set([...current, hostname]))
    : current.filter((d) => d !== hostname);
  if (JSON.stringify(current) !== JSON.stringify(next)) {
    projectManager.update(projectId, { domains: next });
  }
}

router.post('/domains', async (req, res) => {
  try {
    const body = { ...(req.body || {}) };
    if (body.autoCreateDns && (!body.serverIp || body.serverIp === '127.0.0.1')) {
      const detected = await detectPublicIp();
      if (detected) body.serverIp = detected;
    }
    const newDomain = await domainManager.addDomain(body);
    if (newDomain.projectId) {
      syncProjectDomainsList(newDomain.projectId, newDomain.hostname, 'add');
    }
    const ingress = await ingressManager.reconcile();
    res.status(201).json({ ...newDomain, ingress });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/domains/:id', async (req, res) => {
  try {
    const removed = await domainManager.deleteDomain(req.params.id);
    if (removed.projectId) {
      syncProjectDomainsList(removed.projectId, removed.hostname, 'remove');
    }
    if (typeof catalogManager.syncDomainRemoved === 'function') {
      catalogManager.syncDomainRemoved(req.params.id);
    }
    const ingress = await ingressManager.reconcile();
    res.json({ success: true, removed, ingress });
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.patch('/domains/:id', async (req, res) => {
  try {
    const prev = domainManager.getById(req.params.id);
    if (!prev) {
      return res.status(404).json({ error: 'Dominio no encontrado' });
    }
    const updated = await domainManager.updateDomain(req.params.id, req.body);
    if (prev.projectId && (prev.projectId !== updated.projectId || prev.hostname !== updated.hostname)) {
      syncProjectDomainsList(prev.projectId, prev.hostname, 'remove');
    }
    if (updated.projectId) {
      syncProjectDomainsList(updated.projectId, updated.hostname, 'add');
    }
    const ingress = await ingressManager.reconcile();
    res.json({ ...updated, ingress });
  } catch (err) {
    const isConflict = /already configured/i.test(String(err.message || ''));
    res.status(isConflict ? 409 : 400).json({ error: err.message });
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

router.post('/domains/:id/diagnose', async (req, res) => {
  try {
    const expectedIp = (req.body && req.body.serverIp) || await detectPublicIp();
    const report = await ingressManager.diagnoseDomain(req.params.id, { expectedIp });
    res.json(report);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/projects/:id/domains', async (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });

    const hostname = String(req.body.hostname || '').trim().toLowerCase();
    if (!hostname) return res.status(400).json({ error: 'El nombre de dominio es obligatorio' });

    let domain = domainManager.getByHostname(hostname);
    if (domain) {
      if (domain.projectId && domain.projectId !== project.id) {
        return res.status(409).json({ error: `El dominio ${hostname} ya está vinculado a otro proyecto` });
      }
      domain = await domainManager.updateDomain(domain.id, {
        projectId: project.id,
        ...(req.body.canonicalRedirect !== undefined ? { canonicalRedirect: req.body.canonicalRedirect } : {}),
        ...(req.body.securityHeaders !== undefined ? { securityHeaders: Boolean(req.body.securityHeaders) } : {})
      });
    } else {
      let effectiveIp = req.body.serverIp;
      if (req.body.autoCreateDns && (!effectiveIp || effectiveIp === '127.0.0.1')) {
        effectiveIp = await detectPublicIp();
      }
      domain = await domainManager.addDomain({
        hostname,
        projectId: project.id,
        targetPod: req.body.targetPod || 'forge',
        targetPort: req.body.targetPort || project.localPort || project.forgePort || 3001,
        cloudflareZoneId: req.body.cloudflareZoneId || null,
        cloudflareProxied: req.body.cloudflareProxied !== false,
        autoCreateDns: Boolean(req.body.autoCreateDns),
        serverIp: effectiveIp,
        canonicalRedirect: req.body.canonicalRedirect || 'none',
        securityHeaders: req.body.securityHeaders !== false,
        customHeaders: req.body.customHeaders || null,
        routingMode: req.body.routingMode || 'cloudflare_proxy'
      });
    }

    const domains = Array.from(new Set([...(project.domains || []), hostname]));
    const updatedProject = projectManager.update(project.id, { domains });

    // Si hay redirección canónica (www ↔ apex), reconciliar para publicar también la ruta de redirección
    const ingress = domain.canonicalRedirect && domain.canonicalRedirect !== 'none'
      ? await ingressManager.reconcile()
      : await ingressManager.syncProject(project.id);
    res.status(201).json({ domain, project: updatedProject, ingress });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/projects/:id/domains/:domainId', async (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });

    const domain = domainManager.getById(req.params.domainId);
    if (!domain) return res.status(404).json({ error: 'Dominio no encontrado' });

    const keep = req.query.keepDomain === '1';
    if (keep) {
      await domainManager.detachProject(domain.id);
    } else {
      await domainManager.deleteDomain(domain.id);
    }

    const domains = (project.domains || []).filter(d => d !== domain.hostname);
    const updatedProject = projectManager.update(project.id, { domains });

    const ingress = await ingressManager.reconcile();
    res.json({ success: true, hostname: domain.hostname, kept: keep, project: updatedProject, ingress });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/domains/verify-dns', async (req, res) => {
  try {
    const expectedIp = (req.body && req.body.serverIp) || await detectPublicIp();
    const result = await domainManager.verifyDns(req.body.hostname, { expectedIp });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Qué regla de Culkibo casa con un Host, y —lo que de verdad decide -si hay o
// no una ruta equivalente publicada en Caddy. La regla configurada sin ruta
// publicada no sirve tráfico, y decirlo es la diferencia entre un simulador y
// un diagnóstico.
router.get('/ingress/resolve', async (req, res) => {
  try {
    const hostname = req.query.hostname || req.headers.host;
    const route = domainManager.resolveRoute(hostname);
    if (!route) {
      return res.status(404).json({ found: false, message: `No hay ninguna regla configurada para ${hostname}` });
    }

    const state = ingressManager.buildDesiredState();
    const desired = state.specs.find(s => s.hostnames.includes(route.hostname)) || null;
    const skipped = state.skipped.find(s => s.hostnames.includes(route.hostname)) || null;

    /** @type {any} */
    let liveRoute = null;
    let ingressAvailable = false;
    const detection = await caddyManager.detect();
    ingressAvailable = detection.available;
    if (detection.available && desired) {
      try {
        const stored = await caddyManager.getRoute(desired.projectId);
        if (stored) {
          liveRoute = {
            id: stored['@id'],
            hosts: (stored.match && stored.match[0] && stored.match[0].host) || [],
            upstreams: ((stored.handle && stored.handle[0] && stored.handle[0].upstreams) || []).map(u => u.dial)
          };
        }
      } catch (e) { /* la ruta no existe todavía */ }
    }

    res.json({
      found: true,
      hostname,
      matchedRoute: route.hostname,
      isWildcard: route.isWildcard,
      configuredPod: route.targetPod,
      configuredPort: route.targetPort,
      projectId: route.projectId || null,
      cloudflareProxied: route.cloudflareProxied,
      trafficAllocation: containerOrchestrator.trafficAllocation,
      ingressAvailable,
      // Lo que se serviría de verdad, o por qué no se sirve nada.
      servedByCaddy: Boolean(liveRoute),
      liveRoute,
      desiredUpstreams: desired ? desired.upstreams : [],
      notServedReason: liveRoute
        ? null
        : (skipped ? skipped.reason
          : (!ingressAvailable ? `Ingress no disponible: ${detection.reason}` : 'La ruta todavía no está publicada en Caddy'))
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
    const rawDir = req.body && req.body.directory;
    let targetDir = process.cwd();
    if (rawDir) {
      if (process.env.CULKIBO_ALLOW_ARBITRARY_WATCH === '1') {
        targetDir = path.resolve(String(rawDir));
      } else {
        const projectsRoot = path.resolve(__dirname, '..', '..', 'projects');
        const cwdResolved = path.resolve(process.cwd());
        const resolved = path.resolve(String(rawDir));
        const inProjects = !path.relative(projectsRoot, resolved).startsWith('..') && !path.isAbsolute(path.relative(projectsRoot, resolved));
        const inCwd = !path.relative(cwdResolved, resolved).startsWith('..') && !path.isAbsolute(path.relative(cwdResolved, resolved));
        if (!inProjects && !inCwd) {
          return res.status(403).json({ error: 'Solo se permite observar directorios dentro del espacio de trabajo de Culkibo (define CULKIBO_ALLOW_ARBITRARY_WATCH=1 para rutas externas).' });
        }
        targetDir = resolved;
      }
    }
    const result = containerOrchestrator.watchDirectory(targetDir);
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

// Emisión de comodín: 501, no 200 con un certificado inventado.
//
// Hasta v1.0.0 este endpoint respondía `{ success: true, cert }` con un PEM
// fabricado. Ahora `sslManager` devuelve siempre `implemented: false`, y el
// código HTTP tiene que decir lo mismo que el cuerpo: 501 Not Implemented. El
// TLS real lo emite Caddy bajo demanda (ver /api/tls/ask y /api/ingress/status).
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
    res.status(result.success ? 200 : 501).json(result);
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

router.post('/ssl/certificates/upload', async (req, res) => {
  try {
    const result = sslManager.uploadCustomCertificate(req.body || {});
    const ingress = await ingressManager.reconcile();
    notificationService.notify({
      event: 'ssl_issued',
      level: 'success',
      title: 'Certificado TLS instalado',
      message: `Se instaló un certificado personalizado para ${result.cert?.domain || 'el dominio'} y se reconcilió Caddy.`
    }).catch(() => {});
    res.status(201).json({ ...result, ingress });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/ssl/certificates/:id', async (req, res) => {
  try {
    const result = sslManager.revokeCertificate(req.params.id);
    if (!result || result.success === false) {
      return res.status(404).json({ error: result?.error || 'Certificado no encontrado' });
    }
    const ingress = await ingressManager.reconcile();
    res.json({ ...result, ingress });
  } catch (err) {
    res.status(err.message && /no encontrado|not found/i.test(err.message) ? 404 : 500).json({ error: err.message });
  }
});

// --- CLOUDFLARE ---
router.get('/cloudflare/config', (req, res) => {
  try {
    const status = cloudflareService.getConfigStatus();
    // P0-2 / P1-4: accountId es un ID de cuenta (no un secreto); devolverlo íntegro evita
    // que re-guardar Ajustes sobrescriba el ID real con "abcd...1234" y rompa los túneles.
    res.json({
      ...status,
      hasToken: Boolean(cloudflareService.config.apiToken),
      hasApiToken: Boolean(cloudflareService.config.apiToken)
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

router.get('/cloudflare/tunnels/:tunnelId/token', async (req, res) => {
  try {
    const result = await cloudflareService.getTunnelToken(req.params.tunnelId);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/cloudflare/tunnels/:tunnelId/config', async (req, res) => {
  try {
    const result = await cloudflareService.getTunnelConfig(req.params.tunnelId);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/cloudflare/tunnels/:tunnelId/route', async (req, res) => {
  try {
    const { hostname, serviceUrl, zoneId } = req.body || {};
    const result = await cloudflareService.routeHostnameToTunnel({
      tunnelId: req.params.tunnelId,
      zoneId: zoneId || null,
      hostname,
      serviceUrl
    });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/cloudflare/tunnels/:tunnelId', async (req, res) => {
  try {
    const result = await cloudflareService.deleteTunnel(req.params.tunnelId);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/cloudflare/tunnels/connector/start', heavyOpLimiter, async (req, res) => {
  try {
    const { tunnelToken, containerName } = req.body || {};
    const result = await cloudflareService.startCloudflaredDocker({ tunnelToken, containerName });
    if (!result.started) return res.status(502).json(result);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
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
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.send(mcpServer.getToolsSerialized());
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

// Una referencia con mala forma es un error del cliente, no del servidor.
// `dockerManager.assertRef()` la rechaza igualmente (es la barrera real), pero
// atrapándola aquí se devuelve 400 en vez de 500 y el mensaje llega en español.
function badDockerRef(res, id) {
  try {
    dockerManager.assertRef(id);
    return false;
  } catch (e) {
    res.status(400).json({ error: `Identificador de contenedor inválido: ${String(id)}` });
    return true;
  }
}

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
    if (badDockerRef(res, req.params.id)) return;
    const stats = await dockerManager.getContainerStats(req.params.id);
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/docker/containers/:id/start', async (req, res) => {
  try {
    if (badDockerRef(res, req.params.id)) return;
    const result = await dockerManager.startContainer(req.params.id);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/docker/containers/:id/stop', async (req, res) => {
  try {
    if (badDockerRef(res, req.params.id)) return;
    const result = await dockerManager.stopContainer(req.params.id);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/docker/containers/:id/restart', async (req, res) => {
  try {
    if (badDockerRef(res, req.params.id)) return;
    const result = await dockerManager.restartContainer(req.params.id);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/docker/containers/:id/logs', async (req, res) => {
  try {
    if (badDockerRef(res, req.params.id)) return;
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
    const result = await dbBackupManager.exportProject(req.params.projectId, {
      includeSecrets: Boolean(req.body && req.body.includeSecrets)
    });
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

router.post('/backup/instance/export', heavyOpLimiter, async (req, res) => {
  try {
    req.setTimeout(0);
    res.setTimeout(0);
    const { includeSecrets = false, passphrase = '', uploadToS3 = false } = req.body || {};
    const result = await dbBackupManager.exportInstanceSnapshot({
      includeSecrets: Boolean(includeSecrets),
      passphrase: passphrase ? String(passphrase) : '',
      uploadToS3: Boolean(uploadToS3)
    });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/backup/instance/import', heavyOpLimiter, async (req, res) => {
  try {
    req.setTimeout(0);
    res.setTimeout(0);
    const { snapshot = null, fileName = null, passphrase = '', dryRun = false, mode = 'merge' } = req.body || {};
    const result = await dbBackupManager.importInstanceSnapshot({
      snapshot,
      fileName,
      passphrase: passphrase ? String(passphrase) : '',
      dryRun: Boolean(dryRun),
      mode: (mode === 'replace' || mode === 'overwrite') ? 'overwrite' : 'merge'
    });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/backup/download/:fileName', (req, res) => {
  try {
    req.setTimeout(0);
    res.setTimeout(0);
    const filePath = dbBackupManager.resolveDownloadPath(req.params.fileName);
    const stat = fs.statSync(filePath);
    const safeName = path.basename(filePath).replace(/["\r\n]/g, '_');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Length', String(stat.size));
    res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);
    res.setHeader('Cache-Control', 'no-store');
    const rs = fs.createReadStream(filePath);
    rs.on('error', () => { if (!res.headersSent) res.status(500).end(); else res.end(); });
    rs.pipe(res);
  } catch (err) {
    res.status(404).json({ error: err.message });
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

router.get('/databases/storage/objects', async (req, res) => {
  try {
    const prefix = req.query.prefix !== undefined ? String(req.query.prefix) : null;
    const maxKeys = Math.min(500, Math.max(1, parseInt(String(req.query.maxKeys || '200'), 10) || 200));
    res.json(await databaseManager.listRemoteObjects({ prefix, maxKeys }));
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

router.post('/databases/:id/backups', heavyOpLimiter, async (req, res) => {
  try {
    req.setTimeout(0);
    res.setTimeout(0);
    res.json(await databaseManager.runBackup(req.params.id, { trigger: 'manual' }));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/databases/:id/inspect', async (req, res) => {
  try {
    res.json(await databaseManager.inspectDatabase(req.params.id));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/databases/:id/recover', heavyOpLimiter, async (req, res) => {
  try {
    res.json(await databaseManager.recoverContainer(req.params.id));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/databases/:id/backups/:backupId/download', async (req, res) => {
  try {
    req.setTimeout(0);
    res.setTimeout(0);
    const { filePath, fileName, sizeBytes } = await databaseManager.getBackupFilePath(req.params.id, req.params.backupId);
    const safeName = path.basename(fileName).replace(/["\r\n]/g, '_');
    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader('Content-Length', String(sizeBytes));
    res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);
    res.setHeader('Cache-Control', 'no-store');
    const rs = fs.createReadStream(filePath);
    rs.on('error', () => { if (!res.headersSent) res.status(500).end(); else res.end(); });
    rs.pipe(res);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.delete('/databases/:id/backups/:backupId', async (req, res) => {
  try {
    const deleteRemote = req.query.deleteRemote === 'true' || req.query.deleteRemote === '1';
    res.json(await databaseManager.deleteBackup(req.params.id, req.params.backupId, { deleteRemote }));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/databases/:id/backups/upload', heavyOpLimiter, async (req, res) => {
  req.setTimeout(0);
  res.setTimeout(0);
  const MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024; // 2 GiB
  const fileName = String(req.headers['x-backup-filename'] || req.query.fileName || 'uploaded.sql.gz');
  const tmpDir = path.join(process.env.CULKIBO_DATA_DIR ? path.resolve(process.env.CULKIBO_DATA_DIR) : path.resolve(__dirname, '..', '..'), 'data', '.tmp');
  fs.mkdirSync(tmpDir, { recursive: true });
  const tempPath = path.join(tmpDir, `db_upload_${Date.now()}_${crypto.randomBytes(6).toString('hex')}.bin`);

  let totalBytes = 0;
  let aborted = false;
  const hash = crypto.createHash('sha256');
  const ws = fs.createWriteStream(tempPath, { mode: 0o600 });

  const cleanupTemp = () => {
    try { ws.destroy(); } catch (e) {}
    try { if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath); } catch (e) {}
  };

  try {
    await new Promise((resolve, reject) => {
      req.on('data', (chunk) => {
        if (aborted) return;
        totalBytes += chunk.length;
        if (totalBytes > MAX_UPLOAD_BYTES) {
          aborted = true;
          reject(new Error('El archivo supera el límite máximo de 2 GiB'));
          return;
        }
        hash.update(chunk);
        if (!ws.write(chunk)) {
          req.pause();
          ws.once('drain', () => req.resume());
        }
      });
      req.on('error', (err) => reject(err));
      req.on('aborted', () => reject(new Error('Subida cancelada por el cliente')));
      ws.on('error', (err) => reject(err));
      req.on('end', () => {
        ws.end(() => resolve(undefined));
      });
    });

    const entry = await databaseManager.registerUploadedBackup(req.params.id, {
      fileName,
      tempPath,
      sha256: hash.digest('hex'),
      sizeBytes: totalBytes
    });

    if (req.query.restore === '1' || req.query.restore === 'true') {
      const restored = await databaseManager.restore(req.params.id, {
        backupId: entry.id,
        createSafetySnapshot: req.query.safety !== '0'
      });
      return res.status(201).json({ success: true, backup: entry, restored });
    }
    res.status(201).json({ success: true, backup: entry });
  } catch (err) {
    cleanupTemp();
    res.status(400).json({ error: err.message, safetyBackupId: err.safetyBackupId || null });
  }
});

router.post('/databases/:id/restore', heavyOpLimiter, async (req, res) => {
  try {
    req.setTimeout(0);
    res.setTimeout(0);
    const { backupId, remoteKey, createSafetySnapshot } = req.body || {};
    if (!backupId && !remoteKey) {
      return res.status(400).json({ error: 'Indique backupId o remoteKey' });
    }
    res.json(await databaseManager.restore(req.params.id, {
      backupId,
      remoteKey,
      createSafetySnapshot: createSafetySnapshot !== false
    }));
  } catch (err) {
    res.status(400).json({ error: err.message, safetyBackupId: err.safetyBackupId || null });
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
    const { hourly, daily, weekly } = req.body || {};
    res.json(databaseManager.setRetention(req.params.id, { hourly, daily, weekly }));
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
  // P0: Caddy habla directamente con Culkibo sin cabeceras proxy; rechazar peticiones reenviadas desde internet
  if ((req.headers['x-forwarded-for'] || req.headers.forwarded) && process.env.NODE_ENV !== 'test') {
    return res.status(403).type('text/plain').send('acceso restringido al plano de datos local');
  }
  const remoteIp = String(req.socket?.remoteAddress || '').replace(/^::ffff:/, '');
  const isLocalOrPrivate = remoteIp === '127.0.0.1' || remoteIp === '::1' || isPrivateIp(remoteIp);
  if (!isLocalOrPrivate && process.env.NODE_ENV !== 'test') {
    return res.status(403).type('text/plain').send('acceso restringido al plano de datos local');
  }

  const domain = String(req.query.domain || '').trim().toLowerCase();

  if (!domain) {
    return res.status(400).type('text/plain').send('falta el parámetro domain');
  }
  if (!/^[a-z0-9.-]{1,253}$/.test(domain)) {
    return res.status(400).type('text/plain').send('parámetro domain inválido');
  }

  if (!ingressManager.isHostnameAuthorizedForTls(domain)) {
    return res.status(403).type('text/plain').send(`dominio no configurado en Culkibo: ${domain}`);
  }
  const exactMatch = domainManager.getByHostname(domain);
  if (exactMatch && exactMatch.status === 'disabled') {
    return res.status(403).type('text/plain').send(`dominio deshabilitado: ${domain}`);
  }
  const route = domainManager.resolveRoute(domain);

  const now = Date.now();
  const lastLog = _askLogThrottle.get(domain) || 0;
  if (now - lastLog > 60000) {
    if (_askLogThrottle.size > 500) _askLogThrottle.clear();
    _askLogThrottle.set(domain, now);
    containerOrchestrator.addLog('INFO', 'edge', `[Edge:TLS] Certificado autorizado para ${domain} (regla: ${route ? route.hostname : 'panel/redirección/wildcard'})`);
  }
  return res.status(200).type('text/plain').send('ok');
});

router.post('/ingress/tls-audit', async (req, res) => {
  try {
    const warnDays = Math.min(90, Math.max(1, Number(req.body?.warnDays) || 14));
    const audit = await ingressManager.checkCertificateExpiry({ warnDays, probeLive: req.body?.probeLive !== false });
    res.json(audit);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Estado honesto del ingress.
//
// Devuelve lo que hay REALMENTE en Caddy, en qué difiere de lo que Culkibo
// cree que debería haber, y —lo importante— el resultado de un handshake TLS
// real contra cada dominio configurado, con el emisor y el `notAfter` que el
// servidor presenta. El registro propio (sslManager) se inventaba
// `status: 'active'` y 90 días de caducidad al "emitir"; un campo en nuestro
// JSON no puede demostrar nada sobre lo que recibe un navegador.
//
// `?probe=0` salta los sondeos cuando solo interesa el estado de las rutas.
router.get('/ingress/status', async (req, res) => {
  try {
    const status = await ingressManager.status({
      probe: req.query.probe !== '0',
      force: req.query.force === '1',
      probeTimeoutMs: Math.min(parseInt(req.query.timeout, 10) || 3000, 10000)
    });
    res.json(status);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Fuerza la convergencia del plano de datos al estado deseado. Es el botón que
// arregla a mano la deriva que `bootstrap()` arregla en cada arranque.
router.post('/ingress/reconcile', async (req, res) => {
  try {
    res.json(await ingressManager.reconcile());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Levanta el plano de datos con Docker cuando no hay ninguno. Mantiene la
// promesa de "un comando": el usuario no instala Caddy a mano.
router.post('/ingress/start', async (req, res) => {
  try {
    const detection = await caddyManager.detect({ force: true });
    if (detection.available) {
      return res.json({ started: false, alreadyRunning: true, message: 'Caddy ya está en marcha.' });
    }
    const cfStatus = cloudflareService.getConfigStatus();
    const startOpts = {
      ...(req.body || {}),
      ...(!cfStatus.useMock && cloudflareService.config.apiToken ? { cfApiToken: cloudflareService.config.apiToken } : {})
    };
    const result = await caddyManager.startWithDocker(startOpts);
    if (!result.started) {
      return res.status(502).json({ ...result, message: `No se pudo levantar Caddy: ${result.error}` });
    }
    for (let i = 0; i < 10; i++) {
      const check = await caddyManager.detect({ force: true });
      if (check.available) break;
      await new Promise(r => setTimeout(r, 400));
    }
    const ingress = await ingressManager.reconcile();
    res.json({ ...result, ingress, message: 'Caddy levantado y rutas reconciliadas.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/ingress/capabilities', async (req, res) => {
  try {
    const caps = await caddyManager.probeCapabilities({ force: req.query.force === '1' });
    res.json({
      ...caps,
      wildcardPolicies: ingressManager.listWildcardPolicies(),
      acmeEmail: ingressManager.acmeEmail,
      cloudflareConfigured: Boolean(!cloudflareService.getConfigStatus().useMock)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.put('/ingress/acme-email', async (req, res) => {
  try {
    const email = ingressManager.setAcmeEmail(req.body?.email || null);
    const ingress = await ingressManager.reconcile();
    res.json({ acmeEmail: email, ingress });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/ingress/tls', async (req, res) => {
  try {
    const hostname = String(req.query.hostname || '').trim();
    if (!hostname) return res.status(400).json({ error: 'Falta el parámetro hostname' });
    res.json(await ingressManager.probeTls(hostname, {
      timeoutMs: Math.min(parseInt(req.query.timeout, 10) || 3000, 10000),
      fresh: req.query.fresh === '1'
    }));
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

    const verifyHmac = (secretValue) => {
      if (!signature || typeof signature !== 'string') {
        return { ok: false, error: 'Cabecera x-hub-signature-256 ausente o inválida' };
      }
      const rawPayload = req.rawBody || Buffer.from(JSON.stringify(req.body));
      const hmac = crypto.createHmac('sha256', secretValue);
      hmac.update(rawPayload);
      const expectedSignature = `sha256=${hmac.digest('hex')}`.toLowerCase();
      const clientSignature = signature.trim().toLowerCase();
      const sigBuffer = Buffer.from(clientSignature);
      const expectedBuffer = Buffer.from(expectedSignature);
      if (sigBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
        return { ok: false, error: 'Firma de webhook inválida (HMAC SHA-256 mismatch)' };
      }
      return { ok: true };
    };

    // Resolver proyecto(s) destino — soporta monorepos con varios proyectos apuntando al mismo repo
    /** @type {any[]} */
    let matchedProjects = [];
    if (projectId) {
      const found = projectManager.getById(projectId);
      if (!found) {
        // Verificar primero secreto global si existe para evitar enumeración de IDs sin firma válida
        if (process.env.GITHUB_WEBHOOK_SECRET) {
          const check = verifyHmac(process.env.GITHUB_WEBHOOK_SECRET);
          if (!check.ok) return res.status(401).json({ error: check.error });
        }
        return res.status(404).json({ error: `Proyecto con ID '${projectId}' no encontrado` });
      }
      matchedProjects = [found];
    }

    const payloadRepo = bodyData?.repository;
    if (matchedProjects.length === 0 && payloadRepo) {
      const allProjects = projectManager.getAll();
      const targetSlug = (payloadRepo.full_name || '').toLowerCase();
      const repoHtml = (payloadRepo.html_url || '').toLowerCase().replace(/\.git$/, '');
      const repoClone = (payloadRepo.clone_url || '').toLowerCase().replace(/\.git$/, '');

      matchedProjects = allProjects.filter(p => {
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

    const project = matchedProjects[0] || null;

    // Verificación HMAC SHA-256 estricta POR PROYECTO (evita que en un monorepo un hermano
    // con otro secreto autorice el despliegue de un proyecto diferente).
    const globalSecret = process.env.GITHUB_WEBHOOK_SECRET || null;
    const globalValid = Boolean(globalSecret && verifyHmac(globalSecret).ok);
    const hasAnySecret = Boolean(globalSecret) || matchedProjects.some((p) => Boolean(p?.webhookSecret));

    if (hasAnySecret) {
      matchedProjects = matchedProjects.filter((p) => {
        if (p?.webhookSecret) return verifyHmac(p.webhookSecret).ok;
        return globalValid;
      });
      if (matchedProjects.length === 0) {
        const firstSecret = globalSecret || project?.webhookSecret || '';
        const firstErr = firstSecret ? verifyHmac(firstSecret).error : 'Firma de webhook inválida';
        return res.status(401).json({ error: firstErr });
      }
    }

    const authorizedProject = matchedProjects[0] || null;

    // Handle Ping event
    if (event === 'ping') {
      if (authorizedProject) {
        containerOrchestrator.addLog('INFO', 'citadel', `[GitHub:Webhook] Conexión de webhook verificada con éxito para ${authorizedProject.name}`, new Date(), authorizedProject.id);
      }
      return res.json({
        success: true,
        message: 'Pong! Webhook de GitHub verificado correctamente.',
        zen: bodyData?.zen,
        hookId: bodyData?.hook_id,
        projectId: authorizedProject?.id || null
      });
    }

    // Handle Pull Request event -> Preview Deployments (con puerta anti-forks)
    if (event === 'pull_request' && bodyData?.pull_request) {
      if (!authorizedProject) {
        return res.status(404).json({ error: 'No se encontró un proyecto asociado a este repositorio' });
      }
      const pr = bodyData.pull_request;
      const isFork = Boolean(pr.head?.repo?.full_name && pr.base?.repo?.full_name && pr.head.repo.full_name !== pr.base.repo.full_name);
      const out = await webhookService.dispatchPullRequest({
        provider: 'github',
        projects: matchedProjects,
        action: String(bodyData.action || ''),
        prNumber: pr.number,
        branch: pr.head?.ref || '',
        commitSha: pr.head?.sha || null,
        isFork
      });
      return res.status(out.status).json(out.body);
    }

    // Handle Push event
    if (event === 'push') {
      if (!authorizedProject) {
        return res.status(404).json({ error: 'No se encontró un proyecto asociado a este repositorio' });
      }

      if (bodyData?.deleted === true || bodyData?.after === '0000000000000000000000000000000000000000') {
        return res.json({ success: true, deployed: false, reason: 'Eliminación de rama ignorada' });
      }

      const ref = String(bodyData?.ref || '');
      const pushedBranch = ref.startsWith('refs/heads/') ? ref.slice('refs/heads/'.length) : ref.replace(/^refs\/heads\//, '');

      if (!pushedBranch) {
        return res.json({ success: true, deployed: false, reason: 'Push sin rama (ref vacío) ignorado' });
      }

      const commits = Array.isArray(bodyData?.commits) ? bodyData.commits : [];
      const changedFiles = commits.flatMap((c) => [...(c?.added || []), ...(c?.modified || []), ...(c?.removed || [])]);

      const out = await webhookService.dispatchPush({
        provider: 'github',
        projects: matchedProjects,
        branch: pushedBranch,
        commitSha: bodyData?.after || bodyData?.head_commit?.id || `c_${Date.now().toString(36)}`,
        commitMsg: bodyData?.head_commit?.message || 'Push automático desde GitHub',
        author: bodyData?.head_commit?.author?.name || bodyData?.pusher?.name || 'GitHub',
        deliveryId: req.headers['x-github-delivery'] || null,
        changedFiles
      });
      return res.status(out.status).json(out.body);
    }

    res.json({ success: true, message: `Evento ${event} recibido sin acción requerida.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- MULTI-GIT WEBHOOKS (GITLAB, GITEA/FORGEJO, BITBUCKET) & CI/CD DEPLOY HOOK ---
router.post('/webhooks/gitlab', async (req, res) => {
  try {
    const out = await webhookService.handleGitLabWebhook(req);
    res.status(out.status).json(out.body);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/webhooks/gitea', async (req, res) => {
  try {
    const out = await webhookService.handleGiteaWebhook(req);
    res.status(out.status).json(out.body);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/webhooks/bitbucket', async (req, res) => {
  try {
    const out = await webhookService.handleBitbucketWebhook(req);
    res.status(out.status).json(out.body);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/webhooks/deploy/:projectId', heavyOpLimiter, async (req, res) => {
  try {
    const out = await webhookService.handleDeployHook(req);
    res.status(out.status).json(out.body);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/projects/:id/deploy-hook/rotate', async (req, res) => {
  try {
    const result = await webhookService.rotateDeployHookToken(req.params.id);
    res.json(result);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

// UX P0-7: prueba autenticada de webhook desde el panel sin exponer el secreto HMAC en el navegador
router.post('/projects/:id/webhook/test', async (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const branch = project.gitBranch || 'main';
    const shortSha = crypto.randomBytes(4).toString('hex').slice(0, 7);
    const now = new Date().toISOString();
    containerOrchestrator.addLog('INFO', 'citadel', `[GitHub:Webhook] Prueba manual de webhook para ${project.name} (rama ${branch}, commit ${shortSha})`, new Date(), project.id);
    containerOrchestrator.emit('github_deploy', {
      projectId: project.id,
      projectName: project.name,
      branch,
      commit: shortSha,
      author: 'Prueba desde el panel',
      message: 'Simulación verificada de webhook',
      timestamp: now
    });
    res.json({
      success: true,
      deployed: true,
      simulated: true,
      projectId: project.id,
      branch,
      commit: shortSha,
      message: `Webhook verificado para ${project.name} en la rama ${branch}`
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- CATÁLOGO DE SERVICIOS DE UN CLIC ---
router.use('/catalog', rateLimiter);

router.get('/catalog', (req, res) => {
  try {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.send(catalogManager.getCatalogSerialized());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/catalog/installations', (req, res) => {
  try {
    res.json({ installations: catalogManager.list() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/catalog/installations/:id', (req, res) => {
  try {
    res.json(catalogManager.get(req.params.id));
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.post('/catalog/install', async (req, res) => {
  try {
    const result = await catalogManager.install(req.body || {});
    res.status(202).json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/catalog/installations/:id/secrets', (req, res) => {
  try {
    res.json(catalogManager.getSecrets(req.params.id));
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.get('/catalog/installations/:id/logs', async (req, res) => {
  try {
    const lines = Math.min(2000, Math.max(10, parseInt(String(req.query.lines || '200'), 10) || 200));
    const role = req.query.role ? String(req.query.role) : 'app';
    const output = await catalogManager.logs(req.params.id, { lines, role });
    res.json(typeof output === 'string' ? { output } : output);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/catalog/installations/:id/env', (req, res) => {
  try {
    res.json(catalogManager.getEnv(req.params.id));
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.put('/catalog/installations/:id/env', heavyOpLimiter, async (req, res) => {
  try {
    const overrides = (req.body && (req.body.env || req.body.overrides || req.body)) || {};
    res.json(await catalogManager.updateEnv(req.params.id, overrides));
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message });
  }
});

router.get('/catalog/installations/:id/stats', async (req, res) => {
  try {
    res.json(await catalogManager.getStats(req.params.id));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/catalog/installations/:id/update', heavyOpLimiter, async (req, res) => {
  try {
    req.setTimeout(0);
    res.setTimeout(0);
    const image = req.body && req.body.image;
    if (!image) return res.status(400).json({ error: 'Indica la nueva imagen fijada (p. ej. imagen:1.2.3)' });
    res.json(await catalogManager.updateImage(req.params.id, image));
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message });
  }
});

router.post('/catalog/installations/:id/start', async (req, res) => {
  try {
    res.json(await catalogManager.start(req.params.id));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/catalog/installations/:id/stop', async (req, res) => {
  try {
    res.json(await catalogManager.stop(req.params.id));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/catalog/installations/:id/restart', async (req, res) => {
  try {
    res.json(await catalogManager.restart(req.params.id));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/catalog/installations/:id/health', async (req, res) => {
  try {
    res.json(await catalogManager.refreshHealth(req.params.id));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/catalog/installations/:id/domain', async (req, res) => {
  try {
    const hostname = req.body && (req.body.domain || req.body.hostname);
    if (!hostname) return res.status(400).json({ error: 'Indica un dominio válido' });
    res.json(await catalogManager.attachDomain(req.params.id, hostname));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/catalog/installations/:id', async (req, res) => {
  try {
    const deleteVolumes = req.query.deleteVolumes === '1' || req.query.deleteVolumes === 'true' || Boolean(req.body && req.body.deleteVolumes);
    res.json(await catalogManager.remove(req.params.id, { deleteVolumes }));
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message });
  }
});

// --- AUTENTICACIÓN DEL PANEL REMOTO ---
router.get('/auth/session', (req, res) => {
  const decision = authorizeRequest(req);
  const status = authStatus();
  res.json({
    authenticated: decision.ok,
    method: decision.method || null,
    requireTokenAlways: status.requireTokenAlways,
    tokenConfigured: status.tokenConfigured,
    tokenSource: status.tokenSource
  });
});

router.post('/auth/verify', (req, res) => {
  const bf = checkAuthBruteForce(req);
  if (bf.blocked) {
    metricsCollector.recordSecurityEvent('authBlocked429');
    res.setHeader('Retry-After', String(bf.retryAfterSec));
    return res.status(429).json({ valid: false, error: 'Demasiados intentos de autenticación fallidos.' });
  }
  const token = (req.body && req.body.token) || '';
  if (!tokenMatches(token)) {
    recordAuthFailure(req);
    metricsCollector.recordSecurityEvent('authFailures');
    return res.status(401).json({ valid: false, error: 'Token inválido' });
  }
  res.json({ valid: true });
});

router.post('/auth/ws-ticket', (req, res) => {
  try {
    res.json(createWsTicket(req));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/auth/rotate', (req, res) => {
  try {
    const rotated = rotateToken();
    auditLogger.record({
      source: 'auth',
      action: 'auth.token_rotated',
      method: 'POST',
      path: '/api/auth/rotate',
      ip: clientIp(req),
      status: 200
    });
    res.json(rotated);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --- LIVE SYNC (THE FORGE): SINCRONIZACIÓN SUB-SEGUNDO + MERKLE + ROLLBACK ---
router.get('/sync/summary', (req, res) => {
  res.json(liveSyncEngine.getGlobalSummary());
});

router.get('/projects/:id/sync/status', (req, res) => {
  const project = projectManager.getById(req.params.id);
  if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
  res.json(liveSyncEngine.getStatus(project.id));
});

router.post('/projects/:id/sync/frame', (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const result = liveSyncEngine.applyCommitFrame(project.id, req.body || {});
    res.json(result);
  } catch (err) {
    const status = err && err.code === 'PATH_TRAVERSAL_BLOCKED' ? 400 : 400;
    res.status(status).json({ error: err.message, code: (err && err.code) || 'SYNC_ERROR' });
  }
});

router.post('/projects/:id/sync/verify', (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const result = liveSyncEngine.verifySync(project.id, req.body || {});
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/projects/:id/sync/rollback', (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const steps = Number(req.body && req.body.steps) || 1;
    res.json(liveSyncEngine.rollback(project.id, steps));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/projects/:id/sync/frames/:seq/diff', (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const diff = liveSyncEngine.getFrameDiff(project.id, Number(req.params.seq));
    if (!diff) return res.status(404).json({ error: 'Commit Frame no encontrado en el historial activo de memoria' });
    res.json(diff);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/projects/:id/sync/token', (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const ticket = createWsTicket(req);
    const host = req.headers.host || '127.0.0.1:3030';
    const proto = (req.socket && /** @type {any} */ (req.socket).encrypted) ? 'wss' : 'ws';
    res.json({
      projectId: project.id,
      ticket: ticket.ticket,
      expiresAt: ticket.expiresAt,
      wsUrl: `${proto}://${host}/ws/sync`,
      command: `culkibo sync --project ${project.id}`
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * D3 — Promoción de lo ya probado: construye y despliega en Citadel el árbol
 * exacto sincronizado en disco (sin requerir un `git push` previo).
 * Con `?async=1` o `{ async: true }` devuelve 202 inmediatamente evitando timeouts HTTP.
 */
router.post('/projects/:id/sync/promote', heavyOpLimiter, async (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const targetDir = liveSyncEngine.resolveTargetDir(project.id);
    const verification = liveSyncEngine.verifySync(project.id);
    const isAsync = req.query.async === '1' || req.query.async === 'true' || Boolean(req.body && req.body.async);
    if (isAsync) {
      const queued = deployManager.enqueue(project, {
        contextDir: targetDir,
        gitSync: false,
        trigger: 'forge_promote'
      });
      return res.status(202).json({
        accepted: true,
        ...queued,
        workspaceDigest: verification.serverDigest
      });
    }
    const deployment = await deployManager.deploy(project, {
      contextDir: targetDir,
      gitSync: false,
      trigger: 'forge_promote'
    });
    res.status(deployment.status === 'activo' ? 200 : 422).json({
      promoted: deployment.status === 'activo',
      ...(deployment.status !== 'activo' ? { error: deployment.error || 'El despliegue de promoción falló' } : {}),
      workspaceDigest: verification.serverDigest,
      deployment
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --- WILDCARD TLS NATIVO PERSISTIDO (MÚLTIPLES DOMINIOS COMODÍN) VÍA CADDY + CLOUDFLARE DNS-01 ---
router.get('/ingress/wildcard-dns01', (_req, res) => {
  res.json({ policies: ingressManager.listWildcardPolicies() });
});

router.post('/ingress/wildcard-dns01', async (req, res) => {
  try {
    const { domain, tokenEnv, includeApex } = req.body || {};
    if (!domain) return res.status(400).json({ error: 'Indica el dominio raíz (p. ej. midominio.com)' });
    const result = await ingressManager.addWildcardPolicy(domain, {
      tokenEnv: tokenEnv || 'CF_API_TOKEN',
      includeApex: includeApex !== false
    });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/ingress/wildcard-dns01/:domain', async (req, res) => {
  try {
    const result = await ingressManager.removeWildcardPolicy(req.params.domain);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --- COLA GLOBAL DE DESPLIEGUES, ENLACE PROYECTO<->BD Y MODO MANTENIMIENTO ---
router.get('/deploy/queue', (_req, res) => {
  res.json(deployManager.getQueueStatus());
});

router.post('/projects/:id/databases/:dbId/link', async (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const db = databaseManager.get(req.params.dbId);
    const nextIds = Array.from(new Set([...(Array.isArray(project.linkedDatabaseIds) ? project.linkedDatabaseIds : []), db.id]));
    const updated = projectManager.update(project.id, { linkedDatabaseIds: nextIds });
    await projectManager.flushToDisk();
    res.json({
      success: true,
      project: updated,
      database: db,
      note: 'Base de datos vinculada: al redesplegar se adjuntará su red Docker aislada y se inyectará la URL de conexión sin guardar contraseñas en disco.'
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/projects/:id/databases/:dbId/link', async (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const nextIds = (Array.isArray(project.linkedDatabaseIds) ? project.linkedDatabaseIds : []).filter((x) => x !== req.params.dbId);
    const updated = projectManager.update(project.id, { linkedDatabaseIds: nextIds });
    await projectManager.flushToDisk();
    res.json({ success: true, project: updated });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/projects/:id/maintenance', async (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const enabled = req.body && typeof req.body.enabled === 'boolean'
      ? req.body.enabled
      : !project.maintenanceMode;
    const updated = projectManager.update(project.id, { maintenanceMode: enabled });
    await projectManager.flushToDisk();
    const ingress = await ingressManager.reconcile();
    res.json({ success: true, maintenanceMode: enabled, project: updated, ingress });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

module.exports = router;
