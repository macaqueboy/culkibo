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

router.post('/projects', async (req, res) => {
  try {
    const project = projectManager.create(req.body);
    // Automatically pre-clone and prepare dependencies in the background
    if (project.gitRepo) {
      localRunner.prepareProject(project).catch(err => {
        console.warn(`[AutoPrepare] Could not auto-prepare ${project.name}:`, err.message);
      });
    }
    await projectManager.flushToDisk();
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

router.delete('/projects/:id', async (req, res) => {
  try {
    const projectId = req.params.id;
    // Los dominios del proyecto se quedarían apuntando a un proyecto que ya no
    // existe y su ruta seguiría viva en Caddy: se desvinculan antes de borrar.
    const attached = domainManager.listByProject(projectId);
    for (const domain of attached) {
      try { await domainManager.detachProject(domain.id); } catch (e) {}
    }
    projectManager.delete(projectId);
    // El historial de despliegues y las entregas de webhook ya atendidas son
    // estado de un proyecto que acaba de dejar de existir.
    try { deployManager.forget(projectId); } catch (e) {}
    try { githubService.forgetDeliveries(projectId); } catch (e) {}
    const ingress = await ingressManager.removeProject(projectId);
    // Los dominios desvinculados vuelven a su destino de pod, si lo tenían.
    if (attached.length > 0) await ingressManager.reconcile();
    res.json({ success: true, detachedDomains: attached.map(d => d.hostname), ingress });
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.post('/projects/:id/activate', async (req, res) => {
  try {
    const project = projectManager.activate(req.params.id);
    // No se responde hasta que el cambio está en disco: si no, un cliente que
    // lea inmediatamente después puede ver todavía el estado anterior.
    await projectManager.flushToDisk();
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
    await projectManager.flushToDisk();
    // Sin proceso detrás, la ruta apuntaría a un puerto muerto: se retira.
    const ingress = await ingressManager.removeProject(req.params.id);
    // Misma corrección que en handleStopProject: una sola respuesta.
    res.json({ ...updated, ingress });
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

    // El proyecto ya tiene un puerto vivo: es el momento de publicar (o
    // refrescar) su ruta en Caddy. Sin Caddy esto devuelve `applied: false` y
    // el arranque local sigue siendo válido.
    const ingress = await ingressManager.syncProject(project.id);

    await projectManager.flushToDisk();
    res.json({ ...project, ingress });
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
    await projectManager.flushToDisk();
    // Un proyecto parado no puede seguir teniendo una ruta viva: Caddy
    // devolvería 502 y el panel diría que el dominio está servido.
    const ingress = await ingressManager.removeProject(req.params.id);
    // Había aquí un segundo `res.json(updated)`. Express lanzaba
    // ERR_HTTP_HEADERS_SENT, el `catch` intentaba responder 500 y volvía a
    // lanzar: cada parada dejaba un unhandledRejection en el log del daemon.
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

    const path = require('path');
    const fs = require('fs');
    const contextDir = path.join(process.cwd(), 'projects', project.id);
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
 * Lanza un despliegue. Responde en cuanto arranca, no al terminar: una build
 * puede tardar minutos y dejar colgada una petición HTTP tanto tiempo es una
 * forma garantizada de que un proxy intermedio la corte. El progreso va por
 * WebSocket (`deploy_event` y el flujo de logs normal).
 */
router.post('/projects/:id/deploy', async (req, res) => {
  try {
    const project = projectManager.getById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });

    const options = {};
    if (req.body && typeof req.body === 'object') {
      // Lista blanca explícita: nada de volcar el cuerpo de la petición dentro
      // de las opciones del desplegador.
      for (const key of ['healthTimeoutMs', 'drainTimeoutMs', 'healthIntervalMs', 'buildTimeoutMs', 'memoryMb', 'keepReleases']) {
        const value = Number(req.body[key]);
        if (Number.isFinite(value) && value > 0) options[key] = value;
      }
      if (typeof req.body.version === 'string') options.version = req.body.version;
      // Redesplegar un commit concreto (reintentar un despliegue viejo sin
      // tocar la rama). Se valida aquí y se vuelve a validar en repoSync.
      if (typeof req.body.commit === 'string' && /^[0-9a-f]{7,40}$/i.test(req.body.commit.trim())) {
        options.commit = req.body.commit.trim();
      }
      if (req.body.gitSync === false) options.gitSync = false;
    }
    options.trigger = 'manual';

    const started = deployManager.deploy(project, options);
    // Se registra el fallo pero no se deja escapar: el resultado ya queda en el
    // historial del despliegue y en el flujo de logs.
    started.catch(() => {});

    projectManager.update(project.id, { lastDeployedAt: new Date().toISOString() });
    res.status(202).json({
      accepted: true,
      message: 'Despliegue iniciado. Sigue el progreso en los logs en vivo.',
      projectId: project.id
    });
  } catch (err) {
    res.status(409).json({ error: err.message });
  }
});

router.get('/projects/:id/deployments', (req, res) => {
  try {
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 20));
    // Se devuelven sin las líneas de log: el historial completo con logs de
    // veinte builds es del orden de megabytes por petición.
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

router.post('/projects/:id/rollback', async (req, res) => {
  try {
    const result = await deployManager.rollback(req.params.id);
    const { logLines, ...rest } = result;
    res.json({ ...rest, logLines });
  } catch (err) {
    res.status(400).json({ error: err.message });
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
          // Misma razón que en /migrate-domain: el certificado lo emite Caddy
          // bajo demanda, no este bucle escribiendo PEMs inventados.
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
    res.json({ domains: domainManager.listDomains() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/domains', async (req, res) => {
  try {
    const newDomain = await domainManager.addDomain(req.body);
    // Dar de alta el dominio y publicar su ruta es UNA sola acción: un registro
    // en nuestro JSON sin ruta en Caddy es exactamente la divergencia que este
    // trabajo elimina.
    const ingress = await ingressManager.reconcile();
    res.status(201).json({ ...newDomain, ingress });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/domains/:id', async (req, res) => {
  try {
    const removed = await domainManager.deleteDomain(req.params.id);
    await ingressManager.removeDomain(req.params.id);
    const ingress = await ingressManager.reconcile();
    res.json({ success: true, removed, ingress });
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.patch('/domains/:id', async (req, res) => {
  try {
    const updated = await domainManager.updateDomain(req.params.id, req.body);
    const ingress = await ingressManager.reconcile();
    res.json({ ...updated, ingress });
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

// --- VINCULACIÓN DOMINIO ↔ PROYECTO ---
//
// Una sola llamada: crea (o reutiliza) el registro del dominio, lo vincula al
// proyecto y publica la ruta en Caddy. Antes eran tres pasos en sitios
// distintos —añadir dominio, editar `project.domains` desde el panel y esperar
// a que algo enrutase— y el tercero no existía.
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
      domain = await domainManager.attachProject(domain.id, project.id);
    } else {
      domain = await domainManager.addDomain({
        hostname,
        projectId: project.id,
        targetPod: req.body.targetPod || 'forge',
        targetPort: req.body.targetPort || project.localPort || project.forgePort || 3001,
        cloudflareZoneId: req.body.cloudflareZoneId || null,
        cloudflareProxied: req.body.cloudflareProxied !== false,
        autoCreateDns: Boolean(req.body.autoCreateDns),
        serverIp: req.body.serverIp,
        routingMode: req.body.routingMode || 'cloudflare_proxy'
      });
    }

    const domains = Array.from(new Set([...(project.domains || []), hostname]));
    const updatedProject = projectManager.update(project.id, { domains });

    const ingress = await ingressManager.syncProject(project.id);
    res.status(201).json({ domain, project: updatedProject, ingress });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Desvincular: quita el hostname del proyecto, borra el registro del dominio y
// retira la ruta. Las dos mitades caen juntas o no cae ninguna.
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

    const ingress = await ingressManager.syncProject(project.id);
    if (keep) await ingressManager.reconcile();

    res.json({ success: true, hostname: domain.hostname, kept: keep, project: updatedProject, ingress });
  } catch (err) {
    res.status(400).json({ error: err.message });
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
    const result = await caddyManager.startWithDocker(req.body || {});
    if (!result.started) {
      return res.status(502).json({ ...result, message: `No se pudo levantar Caddy: ${result.error}` });
    }
    // Espera corta a que la admin API responda antes de reconciliar.
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

// Handshake TLS suelto contra un dominio cualquiera, sin pasar por el registro.
router.get('/ingress/tls', async (req, res) => {
  try {
    const hostname = String(req.query.hostname || '').trim();
    if (!hostname) return res.status(400).json({ error: 'Falta el parámetro hostname' });
    res.json(await ingressManager.probeTls(hostname, {
      timeoutMs: Math.min(parseInt(req.query.timeout, 10) || 3000, 10000)
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

      // Idempotencia. GitHub reentrega: por reintento automático cuando la
      // respuesta tarda, y a mano desde «Redeliver». Sin esta puerta, un push
      // arranca dos builds del mismo commit y la segunda choca con el bloqueo
      // del proyecto, dejando un «fallido» en el historial que no lo es.
      const claim = githubService.claimDelivery(project.id, {
        deliveryId: req.headers['x-github-delivery'] || null,
        commitSha
      });
      if (!claim.fresh) {
        containerOrchestrator.addLog('INFO', 'citadel', `[GitHub:Webhook] ${claim.reason} (${shortSha}); no se relanza el despliegue.`, new Date(), project.id);
        return res.json({
          success: true,
          deployed: false,
          duplicate: true,
          projectId: project.id,
          commit: shortSha,
          reason: claim.reason
        });
      }

      containerOrchestrator.addLog('INFO', 'citadel', `[GitHub:Webhook] 🚀 Push recibido en ${repoName} (${pushedBranch}) por ${author}: "${commitMsg.trim()}" (${shortSha})`, new Date(), project.id);
      containerOrchestrator.addLog('INFO', 'citadel', `[Citadel:Deploy] Iniciando despliegue automatizado para ${project.name}...`, new Date(), project.id);

      // --- Construcción real ------------------------------------------------
      //
      // Hasta aquí el webhook solo anotaba el push. Ahora dispara el mismo
      // camino que el botón «Desplegar»: traer el commit exacto que GitHub
      // acaba de anunciar, construir la imagen, verificar salud y conmutar la
      // ruta. NO se espera al resultado: una build dura minutos y GitHub corta
      // la entrega a los 10 s. El progreso va por WebSocket (`deploy_event`) y
      // queda en el historial del proyecto.
      let pipeline = { dispatched: false, queued: false, reason: null };
      const dockerProbe = await deployManager.detectDocker();
      if (!project.gitRepo) {
        pipeline.reason = 'El proyecto no tiene repositorio configurado';
      } else if (!dockerProbe.available) {
        pipeline.reason = dockerProbe.reason;
      } else {
        try {
          const started = deployManager.enqueue(project, {
            // El SHA del payload, no «la punta de la rama»: entre el push y el
            // build puede haber entrado otro commit, y desplegar uno distinto
            // del que se anunció hace que el historial mienta.
            commit: /^[0-9a-f]{7,40}$/i.test(commitSha) ? commitSha : null,
            version: `gh-${shortSha}`,
            trigger: 'webhook'
          });
          pipeline = { dispatched: started.started, queued: started.queued, reason: null };
        } catch (err) {
          pipeline.reason = err.message;
        }
      }

      if (pipeline.reason) {
        containerOrchestrator.addLog('WARN', 'citadel', `[Citadel:Deploy] No se lanza la construcción de imagen: ${pipeline.reason}.`, new Date(), project.id);
      } else if (pipeline.queued) {
        containerOrchestrator.addLog('INFO', 'citadel', `[Citadel:Deploy] Ya hay un despliegue en curso; ${shortSha} queda en cola y se construirá al terminar.`, new Date(), project.id);
      }

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

      // El mensaje dice la verdad en cada caso: con pipeline real la build
      // sigue corriendo cuando esta respuesta ya ha salido hacia GitHub.
      containerOrchestrator.addLog(
        'SUCCESS',
        'citadel',
        pipeline.dispatched || pipeline.queued
          ? `[GitHub:Webhook] ✅ Despliegue en curso para ${project.name} (${shortSha}); sigue el progreso en la pestaña Despliegues.`
          : `[GitHub:Webhook] ✅ Despliegue completado para ${project.name} (${shortSha})`,
        new Date(),
        project.id
      );

      return res.json({
        success: true,
        deployed: true,
        projectId: project.id,
        branch: pushedBranch,
        commit: shortSha,
        deployedAt: now,
        // Qué pasó de verdad, para que el que integre el webhook no tenga que
        // adivinarlo: `building` significa que hay una imagen construyéndose.
        pipeline: pipeline.dispatched ? 'building' : pipeline.queued ? 'queued' : 'registro',
        pipelineReason: pipeline.reason
      });
    }

    res.json({ success: true, message: `Evento ${event} recibido sin acción requerida.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
