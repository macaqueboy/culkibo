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
const telemetryService = require('../services/telemetryService');
const {
  authorizeRequest,
  authStatus,
  tokenMatches,
  addAllowedOrigin,
  createWsTicket,
  rotateToken,
  onTokenRotated,
  onPrincipalRevoked,
  isPrivateProxyPeer,
  canBootstrapRequest,
  clientIp,
  checkAuthBruteForce,
  recordAuthFailure,
  getBruteForceStats,
  requireRouteRbac,
  formatSessionCookie,
  formatClearSessionCookie,
  isHttpsRequest
} = require('../middleware/auth');
const Project = require('../models/Project');
const APP_VERSION = (() => {
  try { return String(require('../../package.json').version || '1.2.0'); } catch (e) { return '1.2.0'; }
})();

// Carga perezosa de los módulos v2 (0 impacto en RAM al arrancar en 1 solo VPS)
/** @type {Record<string, any>} */
const _lazyV2 = Object.create(null);
function getFleetManager() { return _lazyV2.fleet || (_lazyV2.fleet = require('../services/serverFleetManager')); }
function getTeamManager() { return _lazyV2.team || (_lazyV2.team = require('../services/teamManager')); }
function getEnvironmentManager() { return _lazyV2.env || (_lazyV2.env = require('../services/environmentManager')); }
function getGitOpsManager() { return _lazyV2.gitops || (_lazyV2.gitops = require('../services/gitopsManager')); }
function getUptimeMonitor() { return _lazyV2.uptime || (_lazyV2.uptime = require('../services/uptimeMonitor')); }
function getSleepAdvisor() { return _lazyV2.sleep || (_lazyV2.sleep = require('../services/sleepAdvisor')); }
function getMetricsHistory() { return _lazyV2.mh || (_lazyV2.mh = require('../services/metricsHistory')); }
function getAlertEngine() { return _lazyV2.ae || (_lazyV2.ae = require('../services/alertEngine')); }
function getTopologyService() { return _lazyV2.topo || (_lazyV2.topo = require('../services/topologyService')); }
function getOidcService() { return _lazyV2.oidc || (_lazyV2.oidc = require('../services/oidcService')); }
function getSecretScanner() { return _lazyV2.scanner || (_lazyV2.scanner = require('../services/secretScanner')); }
function getEditionService() { return _lazyV2.edition || (_lazyV2.edition = require('../services/editionService')); }
function getBundleArchiver() { return _lazyV2.bundle || (_lazyV2.bundle = require('../services/bundleArchiver')); }
function getSmartPackBuilder() { return _lazyV2.smartpack || (_lazyV2.smartpack = require('../services/smartPackBuilder')); }
function getDirectPushRegistry() { return _lazyV2.directpush || (_lazyV2.directpush = require('../services/directPushRegistry')); }
function getEdgeTunnelService() { return _lazyV2.edgetunnel || (_lazyV2.edgetunnel = require('../services/edgeTunnelService')); }
function getSqliteStreamBackup() { return _lazyV2.snapstream || (_lazyV2.snapstream = require('../services/sqliteStreamBackup')); }
function getReleaseProvenance() { return _lazyV2.provenance || (_lazyV2.provenance = require('../../scripts/release-provenance')); }
function getOtlpExporter() { return _lazyV2.otlp || (_lazyV2.otlp = require('../services/otlpExporter')); }
function getSupplyChainAttestor() { return _lazyV2.attestor || (_lazyV2.attestor = require('../services/supplyChainAttestor')); }
function getMigrationRunner() { return _lazyV2.migrations || (_lazyV2.migrations = require('../services/migrationRunner')); }
function getWasmMicroRunner() { return _lazyV2.wasm || (_lazyV2.wasm = require('../services/wasmMicroRunner')); }
function getShadowReplayService() { return _lazyV2.shadow || (_lazyV2.shadow = require('../services/shadowReplayService')); }
function getTimeMachineService() { return _lazyV2.timemachine || (_lazyV2.timemachine = require('../services/timeMachineService')); }
function getFinOpsOptimizer() { return _lazyV2.finops || (_lazyV2.finops = require('../services/finopsOptimizer')); }
function getContainerTerminalService() { return _lazyV2.terminal || (_lazyV2.terminal = require('../services/containerTerminalService')); }
function getFleetMeshService() { return _lazyV2.mesh || (_lazyV2.mesh = require('../services/fleetMeshService')); }
function getEdgeShieldService() { return _lazyV2.shield || (_lazyV2.shield = require('../services/edgeShieldService')); }
function getBuildHealerService() { return _lazyV2.healer || (_lazyV2.healer = require('../services/buildHealerService')); }

/**
 * Circuito anti-autobaneo SPA en 401 repetidos (Cosmos#616):
 * Emite `X-Culkibo-Auth-Circuit: backoff` y `X-Culkibo-Auth-Backoff-Ms` cuando una IP acumula
 * fallos de autenticación consecutivos para que el polling del frontend se detenga antes de
 * activar el bloqueo brute-force 429 contra el propio administrador.
 */
/** @type {Map<string, { count: number, resetAt: number }>} */
const _authCircuitByIp = new Map();
const AUTH_CIRCUIT_WINDOW_MS = 5 * 60 * 1000;
const AUTH_CIRCUIT_CAP = 1000;

/** @param {any} req */
function peekAuthCircuit(req) {
  const ip = clientIp(req);
  const now = Date.now();
  const entry = _authCircuitByIp.get(ip);
  if (!entry || entry.resetAt <= now) {
    if (entry) _authCircuitByIp.delete(ip);
    return { active: false, failures: 0, backoffMs: 0 };
  }
  const active = entry.count >= 2;
  const backoffMs = active ? Math.min(60000, 1000 * Math.pow(2, Math.min(6, entry.count - 1))) : 0;
  return { active, failures: entry.count, backoffMs };
}

/**
 * @param {any} req
 * @param {any} res
 * @param {{ blocked?: boolean, retryAfterSec?: number }} [opts]
 */
function recordAuthCircuitFailure(req, res, opts = {}) {
  const ip = clientIp(req);
  const now = Date.now();
  let entry = _authCircuitByIp.get(ip);
  if (!entry || entry.resetAt <= now) {
    if (_authCircuitByIp.size >= AUTH_CIRCUIT_CAP) {
      for (const [k, v] of _authCircuitByIp.entries()) {
        if (v.resetAt <= now) _authCircuitByIp.delete(k);
        if (_authCircuitByIp.size < AUTH_CIRCUIT_CAP) break;
      }
      if (_authCircuitByIp.size >= AUTH_CIRCUIT_CAP) {
        const oldest = _authCircuitByIp.keys().next().value;
        if (oldest) _authCircuitByIp.delete(oldest);
      }
    }
    entry = { count: 1, resetAt: now + AUTH_CIRCUIT_WINDOW_MS };
  } else {
    entry.count++;
    entry.resetAt = now + AUTH_CIRCUIT_WINDOW_MS;
    _authCircuitByIp.delete(ip);
  }
  _authCircuitByIp.set(ip, entry);

  const shouldBackoff = Boolean(opts.blocked || entry.count >= 2);
  const backoffMs = opts.blocked && opts.retryAfterSec
    ? Math.max(2000, Number(opts.retryAfterSec) * 1000)
    : (shouldBackoff ? Math.min(60000, 1000 * Math.pow(2, Math.min(6, entry.count - 1))) : 0);

  if (shouldBackoff && res && typeof res.setHeader === 'function') {
    res.setHeader('X-Culkibo-Auth-Circuit', 'backoff');
    res.setHeader('X-Culkibo-Auth-Backoff-Ms', String(backoffMs));
    res.setHeader('X-Culkibo-Auth-Failures', String(entry.count));
  }
  return { authCircuit: shouldBackoff ? 'backoff' : 'ok', failures: entry.count, backoffMs };
}

/** @param {any} req */
function clearAuthCircuit(req) {
  const ip = clientIp(req);
  _authCircuitByIp.delete(ip);
}

/**
 * Adjunta una cookie de sesión `HttpOnly; SameSite=Strict` (o `Lax` en OIDC redirect)
 * manteniendo 100% compatibilidad con clientes Bearer / X-Culkibo-Token.
 * @param {any} req
 * @param {any} res
 * @param {string | null | undefined} sessionToken
 * @param {{ maxAgeSec?: number, sameSite?: 'Strict' | 'Lax' }} [opts]
 */
function attachSessionCookie(req, res, sessionToken, opts = {}) {
  if (typeof sessionToken === 'string' && sessionToken.startsWith('cks_')) {
    res.append('Set-Cookie', formatSessionCookie(sessionToken, req, opts));
  }
}

/**
 * Emite una cookie marcadora `HttpOnly; SameSite=Strict` en `/auth/verify` cuando
 * se verifica el token maestro (sin escribir jamás el token maestro en claro en la cookie).
 * @param {any} req
 * @param {any} res
 */
function attachVerifiedAuthCookie(req, res) {
  const secure = isHttpsRequest(req);
  const name = secure ? '__Host-culkibo_auth' : 'culkibo_auth';
  const attrs = [
    `${name}=verified`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    'Max-Age=86400'
  ];
  if (secure) attrs.push('Secure');
  res.append('Set-Cookie', attrs.join('; '));
}

/**
 * Borra las cookies de sesión/verificación al cerrar sesión.
 * @param {any} req
 * @param {any} res
 */
function clearSessionCookies(req, res) {
  for (const cookie of formatClearSessionCookie(req)) {
    res.append('Set-Cookie', cookie);
  }
  res.append('Set-Cookie', 'culkibo_auth=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
  if (isHttpsRequest(req)) {
    res.append('Set-Cookie', '__Host-culkibo_auth=; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=0');
  }
}

/**
 * Construye el descriptor de actor sanitizado para `auditLogger.record(...)`.
 * @param {any} req
 */
function getAuditActor(req) {
  const authCtx = req && req.auth ? req.auth : null;
  const principal = authCtx && authCtx.principal ? authCtx.principal : null;
  if (!principal) return { actor: null, authMethod: null };
  return {
    authMethod: authCtx.method || null,
    actor: {
      userId: principal.userId || null,
      email: principal.email || null,
      role: principal.role || null,
      teamId: principal.teamId || null,
      tokenId: principal.tokenId || null,
      kind: principal.kind || null
    }
  };
}

/**
 * Redacta secretos del proyecto (incluyendo `buildSecrets` y `previewDeployments.buildSecrets`)
 * cuando el llamador no tiene `secrets:read` sobre el proyecto.
 * @param {any} req
 * @param {any} proj
 */
function redactProjectOutput(req, proj) {
  if (!proj || typeof proj !== 'object') return proj;
  const principal = getPrincipal(req);
  if (principal.isSuperAdmin) return proj;
  const tm = getTeamManager();
  const redacted = tm.redactProjectForPrincipal(principal, proj);
  if (redacted && redacted._secretsRedacted) {
    return Project.redactForUnprivileged(redacted, { includeSecrets: false });
  }
  return redacted;
}

/**
 * Devuelve la lista de IDs de proyectos visibles para un principal no-superadmin (o `null` para superadmin).
 * @param {any} req
 * @returns {string[] | null}
 */
function getAllowedProjectIds(req) {
  const principal = getPrincipal(req);
  if (principal.isSuperAdmin) return null;
  return getTeamManager()
    .filterProjects(principal, projectManager.getAll(), { redact: false })
    .map((p) => p.id);
}

/**
 * Impide que un no-owner establezca o modifique `localPath` del host (Coolify CVE-2026-34153).
 * @param {any} req
 * @param {any} res
 * @param {string} [teamId]
 * @returns {boolean}
 */
function assertHostLocalPathAllowed(req, res, teamId) {
  const principal = getPrincipal(req);
  if (principal.isSuperAdmin) return true;
  const check = getTeamManager().doesPrincipalSatisfyRole(principal, 'owner', teamId || principal.teamId);
  if (!check || !check.allowed) {
    res.status(403).json({
      error: 'Solo un owner puede configurar rutas locales del host (localPath)',
      code: 'LOCAL_PATH_OWNER_REQUIRED'
    });
    return false;
  }
  return true;
}

/**
 * Evita sobrescribir secretos reales en `buildSecrets` con el marcador literal `'[REDACTED]'`.
 * @param {Record<string, string> | null | undefined} existingMap
 * @param {Record<string, any> | null | undefined} incomingMap
 */
function mergeRedactedSecretMap(existingMap, incomingMap) {
  if (!incomingMap || typeof incomingMap !== 'object' || Array.isArray(incomingMap)) return incomingMap;
  const prev = existingMap && typeof existingMap === 'object' ? existingMap : {};
  /** @type {Record<string, any>} */
  const next = { ...incomingMap };
  for (const [k, v] of Object.entries(next)) {
    if (v === '[REDACTED]' && Object.prototype.hasOwnProperty.call(prev, k)) {
      next[k] = prev[k];
    }
  }
  return next;
}

/**
 * Verifica autorización multi-tenant + ACL por proyecto sobre un dominio.
 * @param {any} req
 * @param {any} res
 * @param {string} domainId
 * @param {string} [perm]
 * @returns {any | null}
 */
function assertDomainAccess(req, res, domainId, perm = 'domains:write') {
  const principal = getPrincipal(req);
  const domain = domainManager.getById(domainId);
  if (!domain) {
    res.status(404).json({ error: 'Dominio no encontrado' });
    return null;
  }
  if (!principal.isSuperAdmin) {
    if (domain.projectId) {
      const proj = assertProjectAccess(req, res, domain.projectId, perm);
      if (!proj) return null;
    } else if (denyProjectScopedToken(req, res, 'dominios globales sin proyecto')) {
      return null;
    } else if (principal.teamId && principal.teamId !== 'team_default') {
      res.status(404).json({ error: 'Dominio no encontrado' });
      return null;
    }
  }
  return domain;
}

/**
 * Verifica autorización multi-tenant + ACL por proyecto sobre una base de datos gestionada.
 * @param {any} req
 * @param {any} res
 * @param {string} dbId
 * @param {string} [perm]
 * @returns {any | null}
 */
function assertDatabaseAccess(req, res, dbId, perm = 'databases:read') {
  const principal = getPrincipal(req);
  /** @type {any} */
  let db = null;
  try {
    db = databaseManager.get(dbId);
  } catch (e) {
    res.status(404).json({ error: e.message || 'Base de datos no encontrada' });
    return null;
  }
  if (!db) {
    res.status(404).json({ error: 'Base de datos no encontrada' });
    return null;
  }
  if (!principal.isSuperAdmin) {
    if (db.projectId) {
      const proj = assertProjectAccess(req, res, db.projectId, perm);
      if (!proj) return null;
    } else if (denyProjectScopedToken(req, res, 'bases de datos sin proyecto')) {
      return null;
    } else if (principal.teamId && principal.teamId !== 'team_default') {
      res.status(404).json({ error: 'Base de datos no encontrada' });
      return null;
    }
  }
  return db;
}

/** @param {any} req */
function getPrincipal(req) {
  return (req && req.auth && req.auth.principal) || {
    kind: 'legacy',
    isSuperAdmin: true,
    role: 'owner',
    teamId: 'team_default',
    projectIds: null,
    scopes: ['*']
  };
}

/**
 * Verifica existencia del proyecto y autorización multi-tenant + ACL por proyecto.
 * Devuelve el proyecto si está autorizado, o responde 404/403 y devuelve null.
 * @param {any} req
 * @param {any} res
 * @param {string} projectId
 * @param {string} [perm]
 * @returns {any | null}
 */
function assertProjectAccess(req, res, projectId, perm = 'projects:read') {
  const principal = getPrincipal(req);
  const project = projectManager.getById(projectId);
  if (!project) {
    res.status(404).json({ error: 'Proyecto no encontrado' });
    return null;
  }
  if (!principal.isSuperAdmin) {
    const check = getTeamManager().authorizeProject(principal, project.id, perm, project);
    if (!check.allowed) {
      if (check.status === 404) {
        res.status(404).json({ error: 'Proyecto no encontrado' });
        return null;
      }
      res.status(check.status || 403).json({
        error: check.error || 'Sin permisos sobre este proyecto',
        code: check.code || 'PROJECT_FORBIDDEN'
      });
      return null;
    }
  }
  return project;
}

/**
 * Deniega mutaciones globales sin proyecto a tokens API acotados a `projectIds`.
 * @param {any} req
 * @param {any} res
 * @param {string} [label]
 * @returns {boolean}
 */
function denyProjectScopedToken(req, res, label = 'esta acción global') {
  const principal = getPrincipal(req);
  if (!principal.isSuperAdmin && Array.isArray(principal.projectIds)) {
    res.status(403).json({
      error: `Un token acotado a proyectos concretos no puede ejecutar ${label}`,
      code: 'SCOPED_TOKEN_GLOBAL_DENIED'
    });
    return true;
  }
  return false;
}

/**
 * Protege recursos globales de instancia (`/vault`, `/gitops/(plan|apply|drift)`) frente a:
 *  - tokens API acotados a `projectIds`,
 *  - tenants de equipos secundarios (`teamId !== 'team_default'`),
 *  - o admins no-owner cuando existen múltiples equipos activos (`teamsCount > 1`).
 * @param {any} req
 * @param {any} res
 * @param {string} label
 * @returns {boolean} true si fue denegado (ya respondió HTTP 403)
 */
function denyInstanceGlobalForTenant(req, res, label) {
  if (denyProjectScopedToken(req, res, label)) return true;
  const principal = getPrincipal(req);
  if (principal.isSuperAdmin) return false;
  const tm = getTeamManager();
  if (principal.teamId && principal.teamId !== 'team_default') {
    res.status(403).json({
      error: `Solo el equipo principal puede acceder a ${label}`,
      code: 'INSTANCE_GLOBAL_FORBIDDEN'
    });
    return true;
  }
  const summary = typeof tm.getStatusSummary === 'function' ? tm.getStatusSummary() : null;
  if (summary && Number(summary.teamsCount) > 1) {
    const ownerCheck = tm.doesPrincipalSatisfyRole(principal, 'owner', 'team_default');
    if (!ownerCheck.allowed) {
      res.status(403).json({
        error: `En instancias multi-equipo solo un owner del equipo principal puede ejecutar ${label}`,
        code: 'INSTANCE_GLOBAL_OWNER_REQUIRED'
      });
      return true;
    }
  }
  return false;
}

/** @param {any} err @param {any} res @param {number} [fallbackStatus] */
function sendServiceError(err, res, fallbackStatus = 400) {
  const status = (err && Number.isInteger(err.statusCode) && err.statusCode >= 400 && err.statusCode < 600)
    ? err.statusCode
    : (err && Number.isInteger(err.status) && err.status >= 400 && err.status < 600)
      ? err.status
      : fallbackStatus;
  return res.status(status).json({
    error: (err && err.message) || 'Error procesando la solicitud',
    ...(err && err.code ? { code: err.code } : {})
  });
}
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
      const { actor, authMethod } = getAuditActor(req);
      auditLogger.record({
        source: 'http',
        action: `${req.method} ${req.path}`,
        method: req.method,
        path: req.path,
        ip: clientIp(req),
        authMethod,
        actor,
        status: res.statusCode,
        durationMs: Date.now() - t0
      });
    } catch (e) {}
  });
  next();
});

// Política RBAC catch-all default-deny para principals no-superadmin (coste O(1) en modo single-admin)
const RBAC_PUBLIC_PATHS = new Set([
  '/health',
  '/auth/session',
  '/auth/verify',
  '/auth/bootstrap',
  '/auth/login',
  '/auth/invites/accept',
  '/ingress/ask',
  '/webhooks/github',
  '/webhooks/gitlab',
  '/webhooks/gitea',
  '/webhooks/bitbucket',
  '/auth/2fa/verify',
  '/auth/oidc/start',
  '/auth/oidc/authorize',
  '/auth/oidc/callback',
  '/auth/oidc/providers'
]);
const rbacGuard = requireRouteRbac();
router.use((req, res, next) => {
  if (RBAC_PUBLIC_PATHS.has(req.path) || /^\/webhooks\/deploy\/[a-zA-Z0-9_-]{1,80}$/.test(req.path)) {
    return next();
  }
  return rbacGuard(req, res, next);
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
    const principal = getPrincipal(req);
    if (!principal.isSuperAdmin) {
      const tm = getTeamManager();
      const visible = tm.filterProjects(principal, projectManager.getAll(), { redact: false })
        .map((p) => redactProjectOutput(req, p));
      res.setHeader('Cache-Control', 'private, no-store');
      return res.json(visible);
    }
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.send(projectManager.getAllSerialized());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/projects', async (req, res) => {
  try {
    if (denyProjectScopedToken(req, res, 'crear proyectos')) return;
    const principal = getPrincipal(req);
    const body = req.body && typeof req.body === 'object' ? { ...req.body } : {};
    if (!principal.isSuperAdmin) {
      body.teamId = principal.teamId || 'team_default';
      if (body.localPath !== undefined && body.localPath !== null && String(body.localPath).trim() !== '') {
        if (!assertHostLocalPathAllowed(req, res, body.teamId)) return;
      }
    }
    const project = projectManager.create(body);
    // Automatically pre-clone and prepare dependencies in the background
    if (project.gitRepo) {
      localRunner.prepareProject(project).catch(err => {
        console.warn(`[AutoPrepare] Could not auto-prepare ${project.name}:`, err.message);
      });
    }
    // `projectManager.create()` ya programa un volcado atómico agrupado (15 ms);
    // no bloqueamos la respuesta HTTP en I/O de disco igual que PUT /projects/:id.
    res.status(201).json(redactProjectOutput(req, project));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/projects/:id', (req, res) => {
  try {
    const principal = getPrincipal(req);
    if (!principal.isSuperAdmin) {
      const proj = assertProjectAccess(req, res, req.params.id, 'projects:read');
      if (!proj) return;
      res.setHeader('Cache-Control', 'private, no-store');
      return res.json(redactProjectOutput(req, proj));
    }
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
    const existing = assertProjectAccess(req, res, req.params.id, 'projects:write');
    if (!existing) return;
    const principal = getPrincipal(req);
    const body = req.body && typeof req.body === 'object' ? { ...req.body } : {};
    if (!principal.isSuperAdmin) {
      delete body.teamId;
      if (body.localPath !== undefined && String(body.localPath || '').trim() !== String(existing.localPath || '').trim()) {
        if (String(body.localPath || '').trim() !== '' && !assertHostLocalPathAllowed(req, res, existing.teamId)) return;
      }
    }
    if (body.buildSecrets && typeof body.buildSecrets === 'object') {
      body.buildSecrets = mergeRedactedSecretMap(existing.buildSecrets, body.buildSecrets);
    }
    if (body.previewDeployments && typeof body.previewDeployments === 'object' && body.previewDeployments.buildSecrets) {
      body.previewDeployments = {
        ...body.previewDeployments,
        buildSecrets: mergeRedactedSecretMap(existing.previewDeployments && existing.previewDeployments.buildSecrets, body.previewDeployments.buildSecrets)
      };
    }
    const project = projectManager.update(req.params.id, body);
    res.json(redactProjectOutput(req, project));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/projects/:id', async (req, res) => {
  try {
    const projectId = req.params.id;
    const existing = assertProjectAccess(req, res, projectId, 'projects:delete');
    if (!existing) return;

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
    const existing = assertProjectAccess(req, res, req.params.id, 'projects:write');
    if (!existing) return;
    const project = projectManager.activate(existing.id);
    await projectManager.flushToDisk(existing.id);
    res.json(redactProjectOutput(req, project));
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.post('/projects/:id/hibernate', async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:write');
    if (!project) return;

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

    const updated = projectManager.hibernate(project.id);
    await projectManager.flushToDisk(project.id);
    // P1-1: syncProject conserva la ruta de producción en Caddy si sigue viva y la retira si no
    const ingress = await ingressManager.syncProject(project.id);
    res.json({ ...redactProjectOutput(req, updated), ingress });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/projects/:id/start-local', async (req, res) => {
  try {
    let project = assertProjectAccess(req, res, req.params.id, 'projects:write');
    if (!project) return;

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
    project = projectManager.update(project.id, project);

    const ingress = await ingressManager.syncProject(project.id);

    await projectManager.flushToDisk(project.id);
    res.json({ ...redactProjectOutput(req, project), ingress });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const handleStopProject = async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:write');
    if (!project) return;

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

    const updated = projectManager.stop(project.id);
    await projectManager.flushToDisk(project.id);
    // P1-1: syncProject evita borrar la ruta de producción en Caddy al detener solo el servidor local
    const ingress = await ingressManager.syncProject(project.id);
    res.json({ ...redactProjectOutput(req, updated), ingress });
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
    const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
    if (!project) return;

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
    const project = assertProjectAccess(req, res, req.params.id, 'deployments:write');
    if (!project) return;
    const principal = getPrincipal(req);
    if (deployManager.locks.has(project.id)) {
      return res.status(409).json({ error: 'Ya hay un despliegue en curso para este proyecto' });
    }

    const deploymentId = `dep_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    /** @type {Record<string, any>} */
    const options = {
      deploymentId,
      trigger: 'manual',
      actor: principal.email || principal.kind || 'operator',
      actorIp: clientIp(req),
      auditSource: 'http'
    };
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    for (const key of ['healthTimeoutMs', 'drainTimeoutMs', 'healthIntervalMs', 'buildTimeoutMs', 'keepReleases', 'healthStartPeriodSec', 'healthRetries', 'healthyThreshold']) {
      if (body[key] !== undefined && body[key] !== null && body[key] !== '') {
        const value = Number(body[key]);
        if (Number.isFinite(value) && value >= 0) options[key] = value;
      }
    }
    if (body.memoryMb != null) {
      const mem = Math.round(Number(body.memoryMb));
      if (Number.isFinite(mem) && mem >= 32 && mem <= 65536) options.memoryMb = mem;
    }
    if (typeof body.version === 'string') options.version = body.version;
    if (typeof body.commit === 'string' && /^[0-9a-f]{7,40}$/i.test(body.commit.trim())) {
      options.commit = body.commit.trim();
    }
    if (body.gitSync === false) options.gitSync = false;
    if (body.skipHooks === true) options.skipHooks = true;
    if (body.buildSecrets && typeof body.buildSecrets === 'object' && !Array.isArray(body.buildSecrets)) {
      options.buildSecrets = Project.normalizeKeyValueMap(body.buildSecrets);
    }

    // Ventana de congelación: comprobar ANTES de devolver 202 y exigir rol admin/owner para overrideFreeze
    if (body.overrideFreeze) {
      if (!principal.isSuperAdmin) {
        const adminCheck = getTeamManager().doesPrincipalSatisfyRole(principal, 'admin', project.teamId || principal.teamId);
        if (!adminCheck.allowed) {
          return res.status(403).json({
            error: 'Solo un administrador u owner puede anular una ventana de congelación (overrideFreeze)',
            code: 'FREEZE_OVERRIDE_FORBIDDEN'
          });
        }
      }
      options.overrideFreeze = true;
      if (typeof body.overrideReason === 'string' && body.overrideReason.trim()) {
        options.overrideReason = body.overrideReason.trim().slice(0, 300);
      }
    }
    const freezeCheck = deployManager.evaluateFreezeStatus(project, { trigger: 'manual' });
    if (freezeCheck.frozen && !options.overrideFreeze) {
      const { actor, authMethod } = getAuditActor(req);
      try {
        auditLogger.record({
          source: 'http',
          action: 'deploy.freeze_blocked',
          method: 'POST',
          path: req.path,
          resourceId: project.id,
          ip: clientIp(req),
          authMethod,
          actor,
          status: 423,
          detail: { projectName: project.name || project.id, reason: freezeCheck.reason, window: freezeCheck.window }
        });
      } catch (e) {}
      return res.status(423).json({
        error: `Despliegue bloqueado por ventana de congelación: ${freezeCheck.reason || 'ventana activa'}`,
        code: 'DEPLOY_FROZEN',
        freezeWindow: freezeCheck.window || null
      });
    }

    // Escáner pre-despliegue de fugas de secretos (modo `warn` por defecto; `block` si se activa)
    /** @type {any} */
    let secretScanReport = null;
    if (body.skipSecretScan !== true) {
      const scanMode = (body.secretScanMode === 'block' || process.env.CULKIBO_BLOCK_SECRET_LEAKS === '1')
        ? 'block'
        : 'warn';
      secretScanReport = getSecretScanner().scanDeploymentPayload(
        {
          envVars: project.envVars || {},
          buildArgs: project.buildArgs || {}
        },
        { mode: scanMode }
      );
      if (secretScanReport.blocked) {
        return res.status(422).json({
          error: `Despliegue bloqueado: se detectaron ${secretScanReport.summary.critical + secretScanReport.summary.high} secreto(s) en claro. Mueve las credenciales a \${vault.KEY} antes de desplegar.`,
          code: 'SECRET_LEAK_DETECTED',
          secretScan: secretScanReport
        });
      }
      if (!secretScanReport.clean) {
        containerOrchestrator.addLog(
          'WARN',
          'citadel',
          `[SecretScanner] ${secretScanReport.summary.total} posible(s) secreto(s) en claro en ${project.name} (${secretScanReport.findings.map((f) => f.ruleId).slice(0, 4).join(', ')}). Considera usar \${vault.KEY}.`,
          new Date(),
          project.id
        );
      }
    }

    const started = deployManager.deploy(project, options);
    started.catch(() => {});

    res.status(202).json({
      accepted: true,
      deploymentId,
      message: 'Despliegue iniciado. Sigue el progreso en los logs en vivo.',
      projectId: project.id,
      ...(options.overrideFreeze ? { freezeOverridden: true } : {}),
      ...(secretScanReport && !secretScanReport.clean
        ? {
            secretScanWarnings: {
              total: secretScanReport.summary.total,
              critical: secretScanReport.summary.critical,
              high: secretScanReport.summary.high,
              findings: secretScanReport.findings
            }
          }
        : {})
    });
  } catch (err) {
    res.status(err.status || 409).json({ error: err.message, ...(err.code ? { code: err.code } : {}) });
  }
});

router.post('/projects/:id/deploy/cancel', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'deployments:write');
    if (!project) return;
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
    if (!getPrincipal(req).isSuperAdmin && !assertProjectAccess(req, res, req.params.id, 'projects:read')) return;
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
    if (!getPrincipal(req).isSuperAdmin && !assertProjectAccess(req, res, req.params.id, 'projects:read')) return;
    const deployment = deployManager.getDeployment(req.params.id, req.params.deployId);
    if (!deployment) return res.status(404).json({ error: 'Despliegue no encontrado' });
    res.json(deployment);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/projects/:id/deploy/status', async (req, res) => {
  try {
    if (!getPrincipal(req).isSuperAdmin && !assertProjectAccess(req, res, req.params.id, 'projects:read')) return;
    res.json(await deployManager.status(req.params.id));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/projects/:id/rollback', heavyOpLimiter, async (req, res) => {
  try {
    if (!getPrincipal(req).isSuperAdmin && !assertProjectAccess(req, res, req.params.id, 'deployments:write')) return;
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
    const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
    if (!project) return;
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
  const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
  if (!project) return;
  const principal = getPrincipal(req);
  try {
    if (typeof req.setTimeout === 'function') req.setTimeout(0);
    if (typeof res.setTimeout === 'function') res.setTimeout(0);
    /** @type {ReturnType<typeof setInterval> | null} */
    let ka = null;
    /** @type {ReturnType<typeof setTimeout> | null} */
    let maxLife = null;
    /** @type {{ containerName: string, close: () => void } | null} */
    let stream = null;
    /** @type {(() => void) | null} */
    let unsubRotate = null;
    /** @type {(() => void) | null} */
    let unsubRevoke = null;
    let closed = false;

    const safeWrite = (chunk) => {
      if (closed || res.writableEnded || res.destroyed) return false;
      try {
        res.write(chunk);
        return true;
      } catch (e) {
        stopAll();
        return false;
      }
    };

    const stopAll = () => {
      if (closed) return;
      closed = true;
      if (ka) { clearInterval(ka); ka = null; }
      if (maxLife) { clearTimeout(maxLife); maxLife = null; }
      if (unsubRotate) { try { unsubRotate(); } catch (e) {} unsubRotate = null; }
      if (unsubRevoke) { try { unsubRevoke(); } catch (e) {} unsubRevoke = null; }
      if (stream) { try { stream.close(); } catch (e) {} }
      if (!res.writableEnded && !res.destroyed) {
        try { res.end(); } catch (e) {}
      }
    };

    const activeStream = deployManager.streamRuntimeLogs(project.id, {
      tail: req.query.tail || 100,
      target: req.query.target === 'previous' ? 'previous' : 'current',
      onLine: (payload) => {
        safeWrite(`event: log\ndata: ${JSON.stringify(payload)}\n\n`);
      },
      onEnd: () => {
        safeWrite(`event: end\ndata: {"ended":true}\n\n`);
        stopAll();
      }
    });
    stream = activeStream;
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no'
    });
    safeWrite(`event: ready\ndata: ${JSON.stringify({ containerName: activeStream.containerName })}\n\n`);
    ka = setInterval(() => { safeWrite(': keepalive\n\n'); }, 15000);
    if (ka.unref) ka.unref();
    maxLife = setTimeout(() => { stopAll(); }, 30 * 60 * 1000);
    if (maxLife.unref) maxLife.unref();
    unsubRotate = onTokenRotated(() => stopAll());
    unsubRevoke = onPrincipalRevoked((evt) => {
      if (!evt) return;
      if (evt.masterToken) return stopAll();
      if (principal.isSuperAdmin) return;
      if (evt.tokenId && principal.kind === 'api_token' && evt.tokenId === principal.tokenId) return stopAll();
      if (evt.sessionId && principal.kind === 'session' && evt.sessionId === principal.sessionId) return stopAll();
      if (evt.userId && !evt.sessionId && !evt.tokenId && evt.userId === principal.userId) return stopAll();
    });
    req.on('close', stopAll);
    res.on('close', stopAll);
    res.on('error', stopAll);
  } catch (err) {
    if (!res.headersSent) res.status(err.status || 500).json({ error: err.message });
  }
});

router.get('/projects/:id/runtime/stats', async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
    if (!project) return;
    const result = await deployManager.getRuntimeStats(project.id);
    if (!result.ok && result.status) return res.status(result.status).json(result);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/projects/:id/runtime/exec', execLimiter, async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'runtime:exec');
    if (!project) return;
    const { command, workdir, timeoutMs } = req.body || {};
    const result = await deployManager.execInContainer(project.id, { command, workdir, timeoutMs });
    res.json(result);
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message });
  }
});

// --- TAREAS PROGRAMADAS CRON POR PROYECTO ---
router.get('/projects/:id/crons', (req, res) => {
  const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
  if (!project) return;
  res.json({ jobs: cronManager.list(project.id) });
});

router.post('/projects/:id/crons', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'crons:write');
    if (!project) return;
    const job = cronManager.create(project.id, req.body || {});
    res.status(201).json(job);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.put('/projects/:id/crons/:jobId', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'crons:write');
    if (!project) return;
    const existing = cronManager.getById(req.params.jobId);
    if (!existing || existing.projectId !== project.id) {
      return res.status(404).json({ error: 'Tarea cron no encontrada' });
    }
    const updated = cronManager.update(req.params.jobId, req.body || {});
    res.json(updated);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/projects/:id/crons/:jobId', (req, res) => {
  const project = assertProjectAccess(req, res, req.params.id, 'crons:write');
  if (!project) return;
  const existing = cronManager.getById(req.params.jobId);
  if (!existing || existing.projectId !== project.id) {
    return res.status(404).json({ error: 'Tarea cron no encontrada' });
  }
  cronManager.remove(req.params.jobId);
  res.json({ deleted: true, id: req.params.jobId });
});

router.post('/projects/:id/crons/:jobId/run', heavyOpLimiter, async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'crons:write');
    if (!project) return;
    const existing = cronManager.getById(req.params.jobId);
    if (!existing || existing.projectId !== project.id) {
      return res.status(404).json({ error: 'Tarea cron no encontrada' });
    }
    const run = await cronManager.runNow(req.params.jobId, { trigger: 'manual' });
    res.json({ run });
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message });
  }
});

router.get('/projects/:id/crons/:jobId/runs', (req, res) => {
  const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
  if (!project) return;
  const existing = cronManager.getById(req.params.jobId);
  if (!existing || existing.projectId !== project.id) {
    return res.status(404).json({ error: 'Tarea cron no encontrada' });
  }
  res.json({ runs: cronManager.getRuns(req.params.jobId) });
});

// --- VISTAS PREVIAS (PREVIEW DEPLOYMENTS POR RAMA / PR) ---
router.get('/projects/:id/previews', (req, res) => {
  const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
  if (!project) return;
  const safeProj = redactProjectOutput(req, project);
  res.json({
    config: safeProj.previewDeployments,
    previews: previewManager.list(project.id)
  });
});

router.post('/projects/:id/previews', heavyOpLimiter, async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'previews:write');
    if (!project) return;
    const { branch, prNumber, commit, title, supersede, buildSecrets } = req.body || {};
    if (!branch && !prNumber) {
      return res.status(400).json({ error: 'Indica una rama (branch) o un número de PR (prNumber)' });
    }
    const preview = await previewManager.deployPreview(project, {
      branch: branch || project.gitBranch || 'main',
      prNumber: prNumber ?? null,
      commit: commit || null,
      title: title || null,
      ...(supersede !== undefined ? { supersede: Boolean(supersede) } : {}),
      ...(buildSecrets && typeof buildSecrets === 'object' && !Array.isArray(buildSecrets)
        ? { buildSecrets: Project.normalizeKeyValueMap(buildSecrets) }
        : {})
    });
    res.status(201).json(preview);
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message });
  }
});

router.delete('/projects/:id/previews/:key', async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'previews:write');
    if (!project) return;
    const result = await previewManager.destroyPreview(project.id, req.params.key);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/projects/:id/previews/:key/logs', async (req, res) => {
  try {
    if (!getPrincipal(req).isSuperAdmin && !assertProjectAccess(req, res, req.params.id, 'projects:read')) return;
    const result = await previewManager.getLogs(req.params.id, req.params.key, req.query.tail);
    res.json(result);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

// PR Preview Database Branching (opt-in Postgres TEMPLATE / SQLite CoW, 0 shell)
router.post('/projects/:id/previews/:prNumber/branch-db', heavyOpLimiter, (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'previews:write');
    if (!project) return;
    const prNumber = parseInt(String(req.params.prNumber || ''), 10);
    if (!Number.isInteger(prNumber) || prNumber < 1 || prNumber > 999999) {
      return res.status(400).json({ error: 'prNumber debe ser un entero positivo (1..999999)' });
    }
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    /** @type {Record<string, any>} */
    const dbConfig = { ...body };
    if (body.databaseId) {
      const db = assertDatabaseAccess(req, res, String(body.databaseId), 'databases:read');
      if (!db) return;
      dbConfig.engine = dbConfig.engine || db.engine;
      dbConfig.sourceDbName = dbConfig.sourceDbName || db.dbName;
      dbConfig.containerName = dbConfig.containerName || db.containerName;
      dbConfig.username = dbConfig.username || db.username;
    }
    const pmAny = /** @type {any} */ (previewManager);
    if (typeof pmAny.planPreviewDbBranch !== 'function') {
      return res.status(501).json({ error: 'Preview DB Branching no disponible en este runtime' });
    }
    const plan = pmAny.planPreviewDbBranch(project, prNumber, dbConfig);
    res.json(plan);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

// Per-PR Postgres Schema Isolation (dokploy#2462, zero-shell parameterized psql -v)
router.post('/projects/:id/previews/:prNumber/schema-isolation', heavyOpLimiter, (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'previews:write');
    if (!project) return;
    const prNumber = parseInt(String(req.params.prNumber || ''), 10);
    if (!Number.isInteger(prNumber) || prNumber < 1 || prNumber > 999999) {
      return res.status(400).json({ error: 'prNumber debe ser un entero positivo (1..999999)' });
    }
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    /** @type {Record<string, any>} */
    const dbConfig = { ...body };
    if (body.databaseId) {
      const db = assertDatabaseAccess(req, res, String(body.databaseId), 'databases:read');
      if (!db) return;
      dbConfig.engine = dbConfig.engine || db.engine;
      dbConfig.sourceDbName = dbConfig.sourceDbName || db.dbName;
      dbConfig.dbName = dbConfig.dbName || db.dbName;
      dbConfig.containerName = dbConfig.containerName || db.containerName;
      dbConfig.username = dbConfig.username || db.username;
    }
    const pmAny = /** @type {any} */ (previewManager);
    if (typeof pmAny.planPreviewSchemaIsolation !== 'function') {
      return res.status(501).json({ error: 'Preview Schema Isolation no disponible en este runtime' });
    }
    const plan = pmAny.planPreviewSchemaIsolation(project, prNumber, dbConfig);
    res.json(plan);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

// Runtime-only Fast Restart con variables actualizadas sin reconstruir imagen (dokploy#2547)
router.post('/projects/:id/fast-restart', heavyOpLimiter, async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'deployments:write');
    if (!project) return;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const principal = getPrincipal(req);
    const freezeCheck = deployManager.evaluateFreezeStatus(project, { trigger: 'fast_restart' });
    if (freezeCheck && freezeCheck.frozen) {
      if (!body.overrideFreeze) {
        return res.status(423).json({
          error: `Reinicio bloqueado por ventana de congelación: ${freezeCheck.reason || 'ventana activa'}`,
          code: 'DEPLOY_FROZEN',
          freezeWindow: freezeCheck.window
        });
      }
      if (!principal.isSuperAdmin && !getTeamManager().doesPrincipalSatisfyRole(principal, 'admin', project.teamId || principal.teamId).allowed) {
        return res.status(403).json({
          error: 'Solo un admin u owner puede anular una ventana de congelación de despliegues',
          code: 'FREEZE_OVERRIDE_FORBIDDEN'
        });
      }
    }

    const incomingEnv = body.envVars && typeof body.envVars === 'object' && !Array.isArray(body.envVars)
      ? body.envVars
      : undefined;
    const scanMode = body.secretScanMode === 'block' ? 'block' : 'warn';
    /** @type {any} */
    let secretScan = null;
    if (incomingEnv && Object.keys(incomingEnv).length > 0) {
      secretScan = getSecretScanner().scanDeploymentPayload({ envVars: incomingEnv }, { mode: scanMode });
      if (secretScan && secretScan.blocked) {
        return res.status(422).json({
          error: 'Reinicio bloqueado: el escáner detectó secretos en claro en envVars (usa ${vault.KEY})',
          code: 'SECRET_LEAK_DETECTED',
          secretScan
        });
      }
    }

    const result = await deployManager.fastRestartWithEnv(project, {
      envVars: incomingEnv,
      persistEnv: Boolean(body.persistEnv),
      dryRun: Boolean(body.dryRun),
      memoryMb: body.memoryMb != null ? Number(body.memoryMb) : undefined,
      cpus: body.cpus != null ? body.cpus : undefined,
      actor: principal.email || principal.kind || 'operator',
      actorIp: clientIp(req)
    });
    const status = result.status || (result.restarted || result.dryRun ? 200 : 400);
    res.status(status).json(secretScan ? { ...result, secretScan } : result);
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.post('/projects/:id/deploy/stop', async (req, res) => {
  try {
    if (!getPrincipal(req).isSuperAdmin && !assertProjectAccess(req, res, req.params.id, 'deployments:write')) return;
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
    if (!getPrincipal(req).isSuperAdmin && !assertProjectAccess(req, res, req.params.id, 'deployments:write')) return;
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
    if (denyInstanceGlobalForTenant(req, res, 'podar la caché global de BuildKit')) return;
    const keepStorageGb = Number((req.body && req.body.keepStorageGb) ?? 10);
    const untilHours = /** @type {number | null} */ (req.body && req.body.untilHours != null ? Number(req.body.untilHours) : null);
    const force = Boolean(req.body && req.body.force);
    const result = await deployManager.pruneBuildCache({ keepStorageGb, untilHours, force });
    if (result && result.busy === true) {
      return res.status(409).json(result);
    }
    res.json(result);
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

router.post('/import/coolify/plan', heavyOpLimiter, async (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'planificar migración desde Coolify')) return;
    const body = req.body || {};
    const selectedApps = body.apps !== undefined ? body.apps : body.selectedApps;
    const selectedDbs = body.dbs !== undefined ? body.dbs : body.selectedDbs;
    const selectedServices = body.services !== undefined ? body.services : body.selectedServices;

    // Modo offline snapshot (JSON exportado de Coolify sin conexión en vivo)
    if (body.snapshot && typeof body.snapshot === 'object') {
      const plan = coolifyMigrator.buildMigrationPlan(body.snapshot, {
        selectedApps: selectedApps !== undefined ? selectedApps : null,
        selectedDbs: selectedDbs !== undefined ? selectedDbs : null,
        selectedServices: selectedServices !== undefined ? selectedServices : null
      });
      return res.json(plan);
    }

    const { apiUrl, apiToken } = body;
    if (!apiUrl || !apiToken) {
      return res.status(400).json({ error: 'Indica apiUrl y apiToken de Coolify, o envía un objeto snapshot offline' });
    }
    const plan = await coolifyMigrator.planMigration(apiUrl, apiToken, {
      apps: selectedApps !== undefined ? selectedApps : null,
      dbs: selectedDbs !== undefined ? selectedDbs : null,
      services: selectedServices !== undefined ? selectedServices : null
    });
    res.json(plan);
  } catch (err) {
    const status = err && (err.status === 401 || err.status === 403)
      ? err.status
      : (/SSRF|inválida|malformada|protocolo|metadatos|privada|obligatori/i.test(String(err.message || '')) ? 400 : 500);
    res.status(status).json({ error: err.message });
  }
});

router.post('/import/coolify/verify', heavyOpLimiter, async (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'verificar paridad de migración Coolify')) return;
    const { targets, plan, domains, targetIp, dryRun, timeoutMs } = req.body || {};
    const targetsOrPlan = Array.isArray(targets)
      ? targets
      : (plan && typeof plan === 'object' ? plan : (Array.isArray(domains) ? { domains } : null));
    if (!targetsOrPlan) {
      return res.status(400).json({ error: 'Proporciona targets (array) o plan/domains para verificar paridad' });
    }
    const targetCount = Array.isArray(targetsOrPlan)
      ? targetsOrPlan.length
      : (Array.isArray(targetsOrPlan.domains) ? targetsOrPlan.domains.length : 0);
    if (targetCount > 50) {
      return res.status(400).json({ error: 'Máximo 50 objetivos por verificación de paridad' });
    }
    const report = await coolifyMigrator.verifyMigratedStack(targetsOrPlan, {
      targetIp: targetIp ? String(targetIp) : undefined,
      dryRun: Boolean(dryRun),
      timeoutMs: timeoutMs != null ? Number(timeoutMs) : undefined
    });
    res.json(report);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/import/coolify/stream-plan', heavyOpLimiter, (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'generar plan de streaming de volúmenes y bases de datos Coolify')) return;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const snapshot = (body.snapshot && typeof body.snapshot === 'object') ? body.snapshot : body;
    const options = (body.options && typeof body.options === 'object')
      ? body.options
      : {
          ...(body.sourceHost ? { sourceHost: body.sourceHost } : {}),
          ...(body.sourceUser ? { sourceUser: body.sourceUser } : {}),
          ...(body.targetHost ? { targetHost: body.targetHost } : {}),
          ...(body.targetUser ? { targetUser: body.targetUser } : {}),
          ...(body.helperImage ? { helperImage: body.helperImage } : {})
        };
    const plan = coolifyMigrator.buildVolumeAndDbStreamPlan(snapshot, options);
    res.json(plan);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

// --- PORTABLE STACK BUNDLES (.zip / .ckb.gz, zero-dep, AES-256-GCM Vault) ---
const MAX_BUNDLE_BASE64_CHARS = 35 * 1024 * 1024;

router.post('/bundles/export', heavyOpLimiter, (req, res) => {
  try {
    const body = req.body || {};
    const format = body.format === 'ckb.gz' ? 'ckb.gz' : 'zip';
    if (body.format && body.format !== 'zip' && body.format !== 'ckb.gz') {
      return res.status(400).json({ error: 'Formato de bundle inválido (usa "zip" o "ckb.gz")' });
    }
    const principal = getPrincipal(req);
    const requestedIds = Array.isArray(body.projectIds) ? body.projectIds.map((id) => String(id)) : null;

    /** @type {any[]} */
    let exportProjects;
    if (principal.isSuperAdmin) {
      const allProjects = projectManager.getAll();
      exportProjects = requestedIds ? allProjects.filter((p) => requestedIds.includes(p.id)) : allProjects;
    } else {
      if (requestedIds) {
        for (const pid of requestedIds) {
          if (!assertProjectAccess(req, res, pid, 'projects:read')) return;
        }
      }
      const visible = getTeamManager().filterProjects(principal, projectManager.getAll(), { redact: false });
      exportProjects = requestedIds ? visible.filter((p) => requestedIds.includes(p.id)) : visible;
    }

    const exportedIdSet = new Set(exportProjects.map((p) => p.id).filter(Boolean));
    const allDomains = domainManager.listDomains();
    const exportDomains = (principal.isSuperAdmin && !requestedIds)
      ? allDomains
      : allDomains.filter((d) => d.projectId && exportedIdSet.has(d.projectId));

    const allCrons = cronManager.list();
    const exportCrons = (principal.isSuperAdmin && !requestedIds)
      ? allCrons
      : allCrons.filter((c) => c.projectId && exportedIdSet.has(c.projectId));

    const allDbs = databaseManager.list();
    const exportDbs = (principal.isSuperAdmin && !requestedIds)
      ? allDbs
      : allDbs.filter((db) => db.projectId && exportedIdSet.has(db.projectId));

    const panelUrl = `${req.protocol || 'http'}://${req.get('host') || 'localhost:3030'}`;
    const bundle = getBundleArchiver().exportStackBundle({
      stackName: body.stackName ? String(body.stackName) : 'culkibo-stack',
      format,
      passphrase: body.passphrase ? String(body.passphrase) : null,
      panelUrl,
      projects: exportProjects,
      domains: exportDomains,
      crons: exportCrons,
      databases: exportDbs
    });

    res.setHeader('Cache-Control', 'private, no-store');
    if (req.query.download === '1' || body.download === true) {
      const safeName = String(bundle.filename || `culkibo-stack.${format}`).replace(/[^a-zA-Z0-9._-]/g, '_');
      res.setHeader('Content-Type', format === 'ckb.gz' ? 'application/gzip' : 'application/zip');
      res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);
      res.setHeader('X-Culkibo-Bundle-Sha256', bundle.sha256);
      return res.send(bundle.buffer);
    }

    res.json({
      ok: true,
      format: bundle.format,
      bundleId: bundle.bundleId,
      filename: bundle.filename,
      byteLength: bundle.byteLength,
      sha256: bundle.sha256,
      manifest: bundle.manifest,
      stats: bundle.stats,
      bundleBase64: bundle.buffer.toString('base64')
    });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/bundles/inspect', heavyOpLimiter, (req, res) => {
  try {
    const { bundleBase64, passphrase } = req.body || {};
    if (typeof bundleBase64 !== 'string' || !bundleBase64.trim()) {
      return res.status(400).json({ error: 'Proporciona bundleBase64 para inspeccionar el bundle' });
    }
    if (bundleBase64.length > MAX_BUNDLE_BASE64_CHARS) {
      return res.status(413).json({ error: 'El bundle supera el tamaño máximo permitido (25 MB)' });
    }
    const buf = Buffer.from(bundleBase64.trim(), 'base64');
    const report = getBundleArchiver().inspectStackBundle(buf, {
      passphrase: passphrase ? String(passphrase) : null
    });
    res.setHeader('Cache-Control', 'private, no-store');
    res.json(report);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/bundles/import', heavyOpLimiter, async (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'importar un stack bundle portátil')) return;
    const { bundleBase64, passphrase, dryRun, selectedProjectIds } = req.body || {};
    if (typeof bundleBase64 !== 'string' || !bundleBase64.trim()) {
      return res.status(400).json({ error: 'Proporciona bundleBase64 para importar el bundle' });
    }
    if (bundleBase64.length > MAX_BUNDLE_BASE64_CHARS) {
      return res.status(413).json({ error: 'El bundle supera el tamaño máximo permitido (25 MB)' });
    }
    const buf = Buffer.from(bundleBase64.trim(), 'base64');
    const result = await getBundleArchiver().importStackBundle(buf, {
      passphrase: passphrase ? String(passphrase) : null,
      dryRun: Boolean(dryRun),
      selectedProjectIds: Array.isArray(selectedProjectIds) ? selectedProjectIds.map((id) => String(id)) : null
    });
    res.json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
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
  let overflowed = false;
  try {
    await new Promise((resolve, reject) => {
      req.on('data', (c) => {
        if (overflowed) return;
        total += c.length;
        if (total > MAX_BYTES) {
          overflowed = true;
          chunks.length = 0;
          req.resume();
          const err = new Error('El archivo SQL supera el límite de 50 MB');
          /** @type {any} */ (err).status = 413;
          return reject(err);
        }
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
    if (err.status === 413) res.setHeader('Connection', 'close');
    res.status(err.status || 400).json({ error: err.message });
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
      version: APP_VERSION,
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

router.get('/system/audit/verify', (req, res) => {
  try {
    const includeRotated = req.query.includeRotated !== '0' && req.query.includeRotated !== 'false';
    res.json(auditLogger.verifyIntegrity({ includeRotated }));
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

// --- OPEN-CORE EDITION & OFFLINE ED25519 LICENSE VERIFIER ---
router.get('/system/sbom', (_req, res) => {
  try {
    const sbom = getReleaseProvenance().generateCycloneDxSbom();
    res.setHeader('Content-Type', 'application/vnd.cyclonedx+json; charset=utf-8');
    res.setHeader('Cache-Control', 'private, max-age=60');
    res.status(200).send(JSON.stringify(sbom, null, 2));
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.get('/system/edition', (req, res) => {
  try {
    const includeCatalog = req.query.includeCatalog === '1' || req.query.includeCatalog === 'true';
    res.json(getEditionService().getStatus({ includeCatalog }));
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.post('/system/edition/activate', certAndAdminLimiter, (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'activar o modificar la licencia de la instancia')) return;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const { actor, authMethod } = getAuditActor(req);
    if (body.deactivate === true || body.licenseKey === null) {
      const result = getEditionService().deactivateLicense();
      auditLogger.record({
        source: 'http',
        action: 'edition.license_deactivated',
        method: 'POST',
        path: '/api/system/edition/activate',
        ip: clientIp(req),
        authMethod,
        actor,
        status: 200
      });
      return res.json(result);
    }
    const licenseKey = typeof body.licenseKey === 'string'
      ? body.licenseKey
      : (typeof body.license === 'string' ? body.license : '');
    const result = getEditionService().activateLicense(licenseKey);
    auditLogger.record({
      source: 'http',
      action: 'edition.license_activated',
      method: 'POST',
      path: '/api/system/edition/activate',
      ip: clientIp(req),
      authMethod,
      actor,
      status: 200,
      detail: {
        edition: result.edition,
        licenseId: result.license && result.license.licenseId ? result.license.licenseId : null
      }
    });
    res.json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.delete('/system/edition/license', certAndAdminLimiter, (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'desactivar la licencia de la instancia')) return;
    const result = getEditionService().deactivateLicense();
    const { actor, authMethod } = getAuditActor(req);
    auditLogger.record({
      source: 'http',
      action: 'edition.license_deactivated',
      method: 'DELETE',
      path: '/api/system/edition/license',
      ip: clientIp(req),
      authMethod,
      actor,
      status: 200
    });
    res.json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
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
    const principal = getPrincipal(req);
    if (!principal.isSuperAdmin) {
      const allowedSet = new Set(getAllowedProjectIds(req) || []);
      const allowGlobal = !Array.isArray(principal.projectIds) && (!principal.teamId || principal.teamId === 'team_default');
      const filtered = domainManager.listDomains().filter((d) => {
        if (!d) return false;
        if (d.projectId) return allowedSet.has(d.projectId);
        return allowGlobal;
      });
      res.setHeader('Cache-Control', 'private, no-store');
      return res.json({ domains: filtered });
    }
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
    const principal = getPrincipal(req);
    const body = { ...(req.body || {}) };
    if (!principal.isSuperAdmin) {
      if (body.projectId) {
        const proj = assertProjectAccess(req, res, String(body.projectId), 'domains:write');
        if (!proj) return;
      } else if (denyProjectScopedToken(req, res, 'dominios globales sin proyecto')) {
        return;
      } else if (principal.teamId && principal.teamId !== 'team_default') {
        return res.status(403).json({ error: 'Indica un projectId de tu equipo al crear un dominio', code: 'PROJECT_ID_REQUIRED' });
      }
    }
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
    const existing = assertDomainAccess(req, res, req.params.id, 'domains:write');
    if (!existing) return;
    const removed = await domainManager.deleteDomain(existing.id);
    if (removed.projectId) {
      syncProjectDomainsList(removed.projectId, removed.hostname, 'remove');
    }
    if (typeof catalogManager.syncDomainRemoved === 'function') {
      catalogManager.syncDomainRemoved(existing.id);
    }
    const ingress = await ingressManager.reconcile();
    res.json({ success: true, removed, ingress });
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.patch('/domains/:id', async (req, res) => {
  try {
    const prev = assertDomainAccess(req, res, req.params.id, 'domains:write');
    if (!prev) return;
    if (req.body && req.body.projectId && String(req.body.projectId) !== String(prev.projectId || '')) {
      const nextProj = assertProjectAccess(req, res, String(req.body.projectId), 'domains:write');
      if (!nextProj) return;
    }
    const updated = await domainManager.updateDomain(prev.id, req.body);
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
    const existing = assertDomainAccess(req, res, req.params.id, 'domains:write');
    if (!existing) return;
    const updated = await domainManager.toggleProxy(existing.id);
    res.json(updated);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.post('/domains/:id/diagnose', async (req, res) => {
  try {
    const existing = assertDomainAccess(req, res, req.params.id, 'domains:read');
    if (!existing) return;
    const expectedIp = (req.body && req.body.serverIp) || await detectPublicIp();
    const report = await ingressManager.diagnoseDomain(existing.id, { expectedIp });
    res.json(report);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/projects/:id/domains', async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'domains:write');
    if (!project) return;

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
    res.status(201).json({ domain, project: redactProjectOutput(req, updatedProject), ingress });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/projects/:id/domains/:domainId', async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'domains:write');
    if (!project) return;

    const domain = domainManager.getById(req.params.domainId);
    if (!domain || (domain.projectId && domain.projectId !== project.id)) {
      return res.status(404).json({ error: 'Dominio no encontrado' });
    }

    const keep = req.query.keepDomain === '1';
    if (keep) {
      await domainManager.detachProject(domain.id);
    } else {
      await domainManager.deleteDomain(domain.id);
    }

    const domains = (project.domains || []).filter(d => d !== domain.hostname);
    const updatedProject = projectManager.update(project.id, { domains });

    const ingress = await ingressManager.reconcile();
    res.json({ success: true, hostname: domain.hostname, kept: keep, project: redactProjectOutput(req, updatedProject), ingress });
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
          const proxyHandler = caddyManager.extractProxyHandler(stored);
          liveRoute = {
            id: stored['@id'],
            hosts: (stored.match && stored.match[0] && stored.match[0].host) || [],
            upstreams: ((proxyHandler && proxyHandler.upstreams) || []).map(u => u.dial)
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
    // Eliminar los ficheros PEM reemplazados SOLO tras reconciliar Caddy (evita dejar TLS roto si Caddy falla)
    if (Array.isArray(result.replacedEntries) && result.replacedEntries.length > 0 && typeof sslManager.cleanupReplacedEntries === 'function') {
      try { sslManager.cleanupReplacedEntries(result.replacedEntries); } catch (e) {}
    }
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

router.get('/cloudflare/tunnels/status', async (_req, res) => {
  try {
    res.json(await ingressManager.getTunnelStatus());
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.post('/cloudflare/tunnels/config', (req, res) => {
  try {
    res.json(ingressManager.configureCloudflareTunnel(req.body || {}));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/cloudflare/tunnels/sync', heavyOpLimiter, async (req, res) => {
  try {
    res.json(await ingressManager.syncTunnelIngress(req.body || {}));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/cloudflare/tunnels/connector/status', async (req, res) => {
  try {
    res.json(await cloudflareService.getCloudflaredStatus(req.query));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/cloudflare/tunnels/connector/logs', async (req, res) => {
  try {
    res.json(await cloudflareService.getCloudflaredLogs(req.query));
  } catch (err) {
    sendServiceError(err, res, 400);
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

router.post('/cloudflare/tunnels/connector/stop', async (req, res) => {
  try {
    res.json(await cloudflareService.stopCloudflaredDocker(req.body || {}));
  } catch (err) {
    sendServiceError(err, res, 400);
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
    const { hostname, serviceUrl, zoneId, path: routePath, originRequest } = req.body || {};
    const result = await cloudflareService.routeHostnameToTunnel({
      tunnelId: req.params.tunnelId,
      zoneId: zoneId || null,
      hostname,
      serviceUrl,
      path: routePath || null,
      originRequest: originRequest || null
    });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/cloudflare/tunnels/:tunnelId/route', async (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const result = await cloudflareService.unrouteHostnameFromTunnel({
      tunnelId: req.params.tunnelId,
      zoneId: body.zoneId || (req.query.zoneId ? String(req.query.zoneId) : null),
      hostname: body.hostname || (req.query.hostname ? String(req.query.hostname) : ''),
      path: body.path || (req.query.path ? String(req.query.path) : null),
      removeDns: body.removeDns !== false
    });
    res.json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/cloudflare/tunnels/:tunnelId/all-to-caddy', async (req, res) => {
  try {
    res.json(await cloudflareService.configureAllResourcesTunnel({
      tunnelId: req.params.tunnelId,
      ...(req.body || {})
    }));
  } catch (err) {
    sendServiceError(err, res, 400);
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

// --- LOGS ---
/** @param {any} req @param {any} res */
function handleLogsExport(req, res) {
  try {
    const principal = getPrincipal(req);
    const requestedProjectId = req.query.projectId ? String(req.query.projectId) : null;
    if (requestedProjectId && requestedProjectId !== 'global' && !principal.isSuperAdmin) {
      if (!assertProjectAccess(req, res, requestedProjectId, 'projects:read')) return;
    }
    const allowedProjectIds = getAllowedProjectIds(req);
    const exported = containerOrchestrator.exportLogs({
      pod: req.query.pod ? String(req.query.pod) : null,
      level: req.query.level ? String(req.query.level) : null,
      limit: req.query.limit ? parseInt(String(req.query.limit), 10) : 2000,
      search: req.query.search ? String(req.query.search) : (req.query.q ? String(req.query.q) : ''),
      regex: req.query.regex ? String(req.query.regex) : false,
      since: req.query.since ? String(req.query.since) : null,
      until: req.query.until ? String(req.query.until) : null,
      attr: req.query.attr ? String(req.query.attr) : null,
      projectId: requestedProjectId,
      projectIds: allowedProjectIds,
      format: /** @type {'log' | 'ndjson' | 'json'} */ (req.query.format ? String(req.query.format).toLowerCase() : 'log')
    });
    res.setHeader('Content-Type', exported.contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${exported.filename}"`);
    res.setHeader('X-Culkibo-Logs-Count', String(exported.count));
    res.setHeader('Cache-Control', 'private, no-store');
    res.send(exported.content);
  } catch (err) {
    sendServiceError(err, res, err && err.status === 400 ? 400 : 500);
  }
}

router.get('/logs', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const { pod, level, limit, search, q, regex, since, until, attr, projectId } = req.query;
    const requestedProjectId = projectId ? String(projectId) : null;
    if (requestedProjectId && requestedProjectId !== 'global' && !principal.isSuperAdmin) {
      if (!assertProjectAccess(req, res, requestedProjectId, 'projects:read')) return;
    }
    const allowedProjectIds = getAllowedProjectIds(req);
    const logs = containerOrchestrator.getLogs({
      pod: pod ? String(pod) : null,
      level: level ? String(level) : null,
      limit: limit ? parseInt(String(limit), 10) : 100,
      search: search ? String(search) : (q ? String(q) : ''),
      regex: regex ? String(regex) : false,
      since: since ? String(since) : null,
      until: until ? String(until) : null,
      attr: attr ? String(attr) : null,
      projectId: requestedProjectId,
      projectIds: allowedProjectIds
    });
    res.json({ logs });
  } catch (err) {
    sendServiceError(err, res, err && err.status === 400 ? 400 : 500);
  }
});

router.get('/logs/export', handleLogsExport);

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
    const authCtx = /** @type {any} */ (req).auth || null;
    const principal = mcpServer.normalizePrincipal(authCtx);
    const profile = mcpServer.normalizeProfile(req.query.profile ? String(req.query.profile) : 'all');
    if (!principal.isSuperAdmin) {
      res.setHeader('Cache-Control', 'private, no-store');
    }
    res.setHeader('X-Culkibo-Mcp-Profile', profile);
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.send(mcpServer.getToolsSerialized(authCtx, { profile }));
  } catch (err) {
    if (err && err.code === 'INVALID_ARGUMENT') {
      return res.status(400).json({ error: err.message, code: err.code, remediation: err.remediation || null });
    }
    res.status(500).json({ error: err.message });
  }
});

// DEPRECADO: endpoint de mensajes del transporte HTTP+SSE (revisión
// 2024-11-05). Se mantiene para no romper las configuraciones ya instaladas.
router.post('/mcp/message', async (req, res) => {
  try {
    mcpStreamableHttp.markLegacyTransport(res, 'POST /api/mcp/message');
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
    }
    let profile = 'all';
    if (req.query.profile !== undefined) {
      try {
        profile = mcpServer.normalizeProfile(String(req.query.profile));
      } catch (pErr) {
        return res.status(400).json({
          jsonrpc: '2.0',
          id: body.id ?? null,
          error: { code: -32602, message: pErr.message }
        });
      }
    }
    res.setHeader('X-Culkibo-Mcp-Profile', profile);
    const isNotification = body.id === undefined && typeof body.method === 'string';
    const response = await mcpServer.handleJsonRpc(body, {
      auth: /** @type {any} */ (req).auth || null,
      profile
    });
    if (isNotification || response === null) {
      return res.status(202).end();
    }
    res.json(response);
  } catch (err) {
    res.status(500).json({ jsonrpc: '2.0', id: req.body?.id ?? null, error: { code: -32603, message: err.message } });
  }
});

router.get('/mcp/audit', (req, res) => {
  try {
    const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 50;
    res.json({ auditLog: mcpServer.getAuditLog(limit, /** @type {any} */ (req).auth || null) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/mcp/config', (req, res) => {
  try {
    const protocol = req.protocol;
    const host = req.get('host');
    const serverUrl = `${protocol}://${host}`;
    const profile = mcpServer.normalizeProfile(req.query.profile ? String(req.query.profile) : 'all');
    res.setHeader('X-Culkibo-Mcp-Profile', profile);
    res.json(mcpServer.getClientConfigs(serverUrl, { profile }));
  } catch (err) {
    if (err && err.code === 'INVALID_ARGUMENT') {
      return res.status(400).json({ error: err.message, code: err.code, remediation: err.remediation || null });
    }
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
    const includeSecrets = Boolean(req.body && req.body.includeSecrets);
    const project = assertProjectAccess(req, res, req.params.projectId, includeSecrets ? 'secrets:read' : 'projects:read');
    if (!project) return;
    const result = await dbBackupManager.exportProject(project.id, { includeSecrets });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/backup/restore', async (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'restaurar backups desde disco')) return;
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
    if (denyInstanceGlobalForTenant(req, res, 'exportar instantánea de instancia')) return;
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
    if (denyInstanceGlobalForTenant(req, res, 'importar instantánea de instancia')) return;
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
    if (denyInstanceGlobalForTenant(req, res, 'descargar archivos de backup')) return;
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
    if (denyInstanceGlobalForTenant(req, res, 'listar backups globales')) return;
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
// Orden importante: las rutas literales (/engines, /status, /storage, /backup-*) van antes
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
    if (denyInstanceGlobalForTenant(req, res, 'configuración S3 global')) return;
    res.json(databaseManager.getS3Config());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.put('/databases/storage', (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'configuración S3 global')) return;
    res.json(databaseManager.setS3Config(req.body));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/databases/storage/test', async (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'probar almacenamiento S3 global')) return;
    res.json(await databaseManager.testS3());
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/databases/storage/objects', async (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'listar objetos S3 globales')) return;
    const prefix = req.query.prefix !== undefined ? String(req.query.prefix) : null;
    const maxKeys = Math.min(500, Math.max(1, parseInt(String(req.query.maxKeys || '200'), 10) || 200));
    res.json(await databaseManager.listRemoteObjects({ prefix, maxKeys }));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/databases/backup-health', (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'salud global de copias de seguridad')) return;
    res.json(databaseManager.checkBackupHealth({ notify: false }));
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.get('/databases/backup-encryption', (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'configuración de cifrado de copias')) return;
    res.json(databaseManager.getBackupEncryptionConfig());
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.put('/databases/backup-encryption', certAndAdminLimiter, (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'configuración de cifrado de copias')) return;
    res.json(databaseManager.setBackupEncryption(req.body || {}));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/databases/backup-encryption/rotate', certAndAdminLimiter, (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'rotar clave de cifrado de copias')) return;
    res.json(databaseManager.rotateBackupEncryptionKey(req.body || {}));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.put('/databases/s3/lifecycle', certAndAdminLimiter, async (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'reglas de ciclo de vida S3')) return;
    const s3Client = databaseManager.s3ClientFor();
    if (!s3Client) {
      return res.status(400).json({ error: 'Configura primero el almacenamiento S3 para gestionar reglas de ciclo de vida' });
    }
    const rules = (req.body && req.body.rules) || [];
    res.json(await s3Client.putBucketLifecycle(rules));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/databases', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const filterProjectId = req.query.projectId ? String(req.query.projectId) : undefined;
    if (!principal.isSuperAdmin) {
      if (filterProjectId) {
        if (!assertProjectAccess(req, res, filterProjectId, 'databases:read')) return;
        return res.json({ databases: databaseManager.list({ projectId: filterProjectId }) });
      }
      const allowedSet = new Set(getAllowedProjectIds(req) || []);
      const allowGlobal = !Array.isArray(principal.projectIds) && (!principal.teamId || principal.teamId === 'team_default');
      const visible = databaseManager.list().filter((d) => {
        if (!d) return false;
        if (d.projectId) return allowedSet.has(d.projectId);
        return allowGlobal;
      });
      res.setHeader('Cache-Control', 'private, no-store');
      return res.json({ databases: visible });
    }
    res.json({ databases: databaseManager.list({ projectId: filterProjectId }) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Aprovisionamiento. Devuelve la cadena de conexión UNA sola vez: a partir de
// aquí hay que pedirla en /credentials.
router.post('/databases', async (req, res) => {
  try {
    const principal = getPrincipal(req);
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    if (!principal.isSuperAdmin) {
      if (body.projectId) {
        if (!assertProjectAccess(req, res, String(body.projectId), 'databases:write')) return;
      } else if (denyProjectScopedToken(req, res, 'bases de datos globales sin proyecto')) {
        return;
      } else if (principal.teamId && principal.teamId !== 'team_default') {
        return res.status(403).json({ error: 'Indica un projectId de tu equipo al aprovisionar una base de datos', code: 'PROJECT_ID_REQUIRED' });
      }
    }
    res.status(201).json(await databaseManager.provision(body));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/databases/:id', (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:read');
    if (!db) return;
    res.json(db);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.delete('/databases/:id', async (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:admin');
    if (!db) return;
    // Borrar el volumen es destructivo e irreversible: nunca por defecto.
    const result = await databaseManager.remove(db.id, {
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
    const db = assertDatabaseAccess(req, res, req.params.id, 'secrets:read');
    if (!db) return;
    res.setHeader('Cache-Control', 'private, no-store');
    res.json(databaseManager.getCredentials(db.id));
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.get('/databases/:id/health', async (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:read');
    if (!db) return;
    res.json(await databaseManager.refreshHealth(db.id));
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.post('/databases/:id/start', async (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:write');
    if (!db) return;
    res.json(await databaseManager.start(db.id));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/databases/:id/stop', async (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:write');
    if (!db) return;
    res.json(await databaseManager.stop(db.id));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/databases/:id/restart', async (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:write');
    if (!db) return;
    res.json(await databaseManager.restart(db.id));
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
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:write');
    if (!db) return;
    res.json(await databaseManager.setExposure(db.id, req.body || {}));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/databases/:id/backups', (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:read');
    if (!db) return;
    res.json({ backups: databaseManager.listBackups(db.id) });
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.post('/databases/:id/backups', heavyOpLimiter, async (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:write');
    if (!db) return;
    req.setTimeout(0);
    res.setTimeout(0);
    res.json(await databaseManager.runBackup(db.id, { trigger: 'manual' }));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/databases/:id/inspect', async (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:read');
    if (!db) return;
    res.json(await databaseManager.inspectDatabase(db.id));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/databases/:id/recover', heavyOpLimiter, async (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:write');
    if (!db) return;
    res.json(await databaseManager.recoverContainer(db.id));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/databases/:id/backups/:backupId/download', async (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'secrets:read');
    if (!db) return;
    req.setTimeout(0);
    res.setTimeout(0);
    const { filePath, fileName, sizeBytes } = await databaseManager.getBackupFilePath(db.id, req.params.backupId);
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

router.post('/databases/:id/backups/:backupId/verify', heavyOpLimiter, async (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:write');
    if (!db) return;
    res.json(await databaseManager.verifyBackup(db.id, req.params.backupId, req.body || {}));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.delete('/databases/:id/backups/:backupId', async (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:admin');
    if (!db) return;
    const deleteRemote = req.query.deleteRemote === 'true' || req.query.deleteRemote === '1';
    res.json(await databaseManager.deleteBackup(db.id, req.params.backupId, { deleteRemote }));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/databases/:id/backups/upload', heavyOpLimiter, async (req, res) => {
  const db = assertDatabaseAccess(req, res, req.params.id, 'databases:write');
  if (!db) return;
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

    const entry = await databaseManager.registerUploadedBackup(db.id, {
      fileName,
      tempPath,
      sha256: hash.digest('hex'),
      sizeBytes: totalBytes
    });

    if (req.query.restore === '1' || req.query.restore === 'true') {
      const restored = await databaseManager.restore(db.id, {
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
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:write');
    if (!db) return;
    req.setTimeout(0);
    res.setTimeout(0);
    const { backupId, remoteKey, createSafetySnapshot } = req.body || {};
    if (!backupId && !remoteKey) {
      return res.status(400).json({ error: 'Indique backupId o remoteKey' });
    }
    res.json(await databaseManager.restore(db.id, {
      backupId,
      remoteKey,
      createSafetySnapshot: createSafetySnapshot !== false
    }));
  } catch (err) {
    res.status(400).json({ error: err.message, safetyBackupId: err.safetyBackupId || null });
  }
});

router.post('/databases/:id/tuning', async (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:write');
    if (!db) return;
    res.json(await databaseManager.setTuning(db.id, req.body || {}));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/databases/:id/pooler', async (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:write');
    if (!db) return;
    res.json(await databaseManager.configurePooler(db.id, req.body || {}));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/databases/:id/clone', heavyOpLimiter, async (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:write');
    if (!db) return;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    if (body.projectId && String(body.projectId) !== String(db.projectId || '')) {
      if (!assertProjectAccess(req, res, String(body.projectId), 'databases:write')) return;
    }
    res.status(201).json(await databaseManager.cloneDatabase(db.id, body));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/databases/:id/drill', heavyOpLimiter, async (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:write');
    if (!db) return;
    res.json(await databaseManager.runRestoreDrill(db.id, req.body || {}));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/databases/:id/history', (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:read');
    if (!db) return;
    res.json({
      restores: databaseManager.listRestoreHistory(db.id),
      verifications: databaseManager.listVerificationHistory(db.id)
    });
  } catch (err) {
    sendServiceError(err, res, 404);
  }
});

router.put('/databases/:id/schedule', (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:write');
    if (!db) return;
    const { enabled, cron } = req.body || {};
    res.json(databaseManager.setSchedule(db.id, { enabled, cron }));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.put('/databases/:id/retention', (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:write');
    if (!db) return;
    const { hourly, daily, weekly } = req.body || {};
    res.json(databaseManager.setRetention(db.id, { hourly, daily, weekly }));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/databases/:id/retention/apply', async (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:write');
    if (!db) return;
    res.json(await databaseManager.applyRetention(db.id));
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

    // Verificación HMAC SHA-256 estricta POR PROYECTO (fail-closed: Coolify CVE-2025-22608).
    // Jamás se permite ejecutar un webhook sin secreto configurado (de proyecto o GITHUB_WEBHOOK_SECRET).
    const globalSecret = process.env.GITHUB_WEBHOOK_SECRET || null;
    const globalValid = Boolean(globalSecret && verifyHmac(globalSecret).ok);

    if (matchedProjects.length > 0) {
      const anyConfigured = Boolean(globalSecret) || matchedProjects.some((p) => Boolean(p?.webhookSecret));
      if (!anyConfigured) {
        return res.status(401).json({ error: 'Webhook sin secreto configurado: define webhookSecret en el proyecto o GITHUB_WEBHOOK_SECRET' });
      }
      matchedProjects = matchedProjects.filter((p) => {
        if (p?.webhookSecret) return verifyHmac(p.webhookSecret).ok;
        return globalValid;
      });
      if (matchedProjects.length === 0) {
        const firstSecret = globalSecret || project?.webhookSecret || '';
        const firstErr = firstSecret ? verifyHmac(firstSecret).error : 'Firma de webhook inválida';
        return res.status(401).json({ error: firstErr });
      }
    } else if (!globalValid) {
      return res.status(401).json({ error: globalSecret ? verifyHmac(globalSecret).error : 'Firma de webhook ausente o proyecto sin secreto configurado' });
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

    // Handle Pull Request event -> Preview Deployments (puerta anti-forks fail-closed)
    if (event === 'pull_request' && bodyData?.pull_request) {
      if (!authorizedProject) {
        return res.status(404).json({ error: 'No se encontró un proyecto asociado a este repositorio' });
      }
      const pr = bodyData.pull_request;
      const headFull = String(pr.head?.repo?.full_name || '').trim().toLowerCase();
      const baseFull = String(pr.base?.repo?.full_name || '').trim().toLowerCase();
      const isFork = !headFull || !baseFull || headFull !== baseFull;
      const out = await webhookService.dispatchPullRequest({
        provider: 'github',
        projects: matchedProjects,
        action: String(bodyData.action || ''),
        prNumber: pr.number,
        branch: pr.head?.ref || '',
        commitSha: pr.head?.sha || null,
        deliveryId: req.headers['x-github-delivery'] || null,
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
    if (!getPrincipal(req).isSuperAdmin && !assertProjectAccess(req, res, req.params.id, 'projects:write')) return;
    const result = await webhookService.rotateDeployHookToken(req.params.id);
    res.json(result);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

// UX P0-7: prueba autenticada de webhook desde el panel sin exponer el secreto HMAC en el navegador
router.post('/projects/:id/webhook/test', async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:write');
    if (!project) return;
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

router.get('/catalog/drift', (_req, res) => {
  try {
    res.json(catalogManager.checkImageDrift());
  } catch (err) {
    sendServiceError(err, res, 500);
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

router.get('/catalog/installations/:id/drift', (req, res) => {
  try {
    res.json(catalogManager.checkImageDrift(req.params.id));
  } catch (err) {
    sendServiceError(err, res, 404);
  }
});

router.get('/catalog/installations/:id/backups', (req, res) => {
  try {
    res.json({ backups: catalogManager.listVolumeBackups(req.params.id) });
  } catch (err) {
    sendServiceError(err, res, 404);
  }
});

router.post('/catalog/installations/:id/backups', heavyOpLimiter, async (req, res) => {
  try {
    const label = req.body && req.body.label ? String(req.body.label) : null;
    res.status(201).json(await catalogManager.backupVolumes(req.params.id, /** @type {any} */ ({ label })));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/catalog/installations/:id/backups/:backupId/restore', heavyOpLimiter, async (req, res) => {
  try {
    const volumeKey = req.body && req.body.volumeKey ? String(req.body.volumeKey) : null;
    res.json(await catalogManager.restoreVolume(req.params.id, req.params.backupId, /** @type {any} */ ({ volumeKey })));
  } catch (err) {
    sendServiceError(err, res, 400);
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
    res.json(await catalogManager.updateImage(req.params.id, image, {
      allowRepoChange: Boolean(req.body && req.body.allowRepoChange)
    }));
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
  const circuit = !decision.ok ? peekAuthCircuit(req) : { active: false, failures: 0, backoffMs: 0 };
  if (circuit.active) {
    res.setHeader('X-Culkibo-Auth-Circuit', 'backoff');
    res.setHeader('X-Culkibo-Auth-Backoff-Ms', String(circuit.backoffMs));
    res.setHeader('X-Culkibo-Auth-Failures', String(circuit.failures));
  }
  res.json({
    authenticated: decision.ok,
    method: decision.method || null,
    requireTokenAlways: status.requireTokenAlways,
    tokenConfigured: status.tokenConfigured,
    tokenSource: status.tokenSource,
    authCircuit: circuit.active ? 'backoff' : 'ok',
    ...(circuit.active ? { backoffMs: circuit.backoffMs } : {})
  });
});

router.post('/auth/verify', (req, res) => {
  const bf = checkAuthBruteForce(req);
  if (bf.blocked) {
    metricsCollector.recordSecurityEvent('authBlocked429');
    res.setHeader('Retry-After', String(bf.retryAfterSec));
    const circuit = recordAuthCircuitFailure(req, res, { blocked: true, retryAfterSec: bf.retryAfterSec });
    return res.status(429).json({
      valid: false,
      error: 'Demasiados intentos de autenticación fallidos.',
      authCircuit: circuit.authCircuit,
      backoffMs: circuit.backoffMs
    });
  }
  const token = String((req.body && req.body.token) || '').trim();
  if (token.startsWith('cks_')) {
    const verified = getTeamManager().verifySessionToken(token);
    if (verified && verified.ok) {
      clearAuthCircuit(req);
      attachSessionCookie(req, res, token);
      return res.json({ valid: true, method: 'session' });
    }
    recordAuthFailure(req);
    metricsCollector.recordSecurityEvent('authFailures');
    const circuit = recordAuthCircuitFailure(req, res);
    return res.status(401).json({
      valid: false,
      error: 'Token inválido',
      authCircuit: circuit.authCircuit,
      backoffMs: circuit.backoffMs
    });
  }
  if (!tokenMatches(token)) {
    recordAuthFailure(req);
    metricsCollector.recordSecurityEvent('authFailures');
    const circuit = recordAuthCircuitFailure(req, res);
    return res.status(401).json({
      valid: false,
      error: 'Token inválido',
      authCircuit: circuit.authCircuit,
      backoffMs: circuit.backoffMs
    });
  }
  clearAuthCircuit(req);
  attachVerifiedAuthCookie(req, res);
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
    const { actor, authMethod } = getAuditActor(req);
    auditLogger.record({
      source: 'auth',
      action: 'auth.token_rotated',
      method: 'POST',
      path: '/api/auth/rotate',
      ip: clientIp(req),
      authMethod,
      actor,
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
  const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
  if (!project) return;
  res.json(liveSyncEngine.getStatus(project.id));
});

router.post('/projects/:id/sync/frame', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'sync:write');
    if (!project) return;
    const result = liveSyncEngine.applyCommitFrame(project.id, req.body || {});
    res.json(result);
  } catch (err) {
    const status = err && err.code === 'PATH_TRAVERSAL_BLOCKED' ? 400 : 400;
    res.status(status).json({ error: err.message, code: (err && err.code) || 'SYNC_ERROR' });
  }
});

router.post('/projects/:id/sync/verify', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
    if (!project) return;
    const result = liveSyncEngine.verifySync(project.id, req.body || {});
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/projects/:id/sync/rollback', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'sync:write');
    if (!project) return;
    const steps = Number(req.body && req.body.steps) || 1;
    res.json(liveSyncEngine.rollback(project.id, steps));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/projects/:id/sync/frames/:seq/diff', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
    if (!project) return;
    const diff = liveSyncEngine.getFrameDiff(project.id, Number(req.params.seq));
    if (!diff) return res.status(404).json({ error: 'Commit Frame no encontrado en el historial activo de memoria' });
    res.json(diff);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/projects/:id/sync/token', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'sync:write');
    if (!project) return;
    const ticket = createWsTicket(req);
    const trustFwd = isPrivateProxyPeer(req.socket?.remoteAddress || '');
    const fwdProto = trustFwd ? String(req.headers['x-forwarded-proto'] || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean).pop() : '';
    const fwdHost = trustFwd ? String(req.headers['x-forwarded-host'] || '').split(',').map((s) => s.trim()).filter(Boolean).pop() : '';
    const host = fwdHost || req.headers.host || '127.0.0.1:3030';
    const isHttps = Boolean((req.socket && /** @type {any} */ (req.socket).encrypted) || fwdProto === 'https');
    const proto = isHttps ? 'wss' : 'ws';
    const expiresAt = new Date(Date.now() + (ticket.expiresInMs || 30000)).toISOString();
    res.json({
      projectId: project.id,
      ticket: ticket.ticket,
      expiresInMs: ticket.expiresInMs,
      expiresAt,
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
    const project = assertProjectAccess(req, res, req.params.id, 'deployments:write');
    if (!project) return;
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

// --- WILDCARD TLS NATIVO PERSISTIDO (MÚLTIPLES DOMINIOS COMODÍN) VÍA CADDY + DNS-01 MULTI-PROVEEDOR ---
router.get('/ingress/wildcard-dns01', (_req, res) => {
  res.json({ policies: ingressManager.listWildcardPolicies() });
});

router.post('/ingress/wildcard-dns01', async (req, res) => {
  try {
    const { domain, provider, tokenEnv, credentialsEnv, includeApex } = req.body || {};
    if (!domain) return res.status(400).json({ error: 'Indica el dominio raíz (p. ej. midominio.com)' });
    const result = await ingressManager.addWildcardPolicy(domain, {
      provider: provider ? String(provider) : 'cloudflare',
      tokenEnv: tokenEnv || (provider && provider !== 'cloudflare' ? null : 'CF_API_TOKEN'),
      credentialsEnv: credentialsEnv && typeof credentialsEnv === 'object' ? credentialsEnv : null,
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
    const project = assertProjectAccess(req, res, req.params.id, 'projects:write');
    if (!project) return;
    const db = assertDatabaseAccess(req, res, req.params.dbId, 'databases:read');
    if (!db) return;
    const nextIds = Array.from(new Set([...(Array.isArray(project.linkedDatabaseIds) ? project.linkedDatabaseIds : []), db.id]));
    const updated = projectManager.update(project.id, { linkedDatabaseIds: nextIds });
    await projectManager.flushToDisk();
    res.json({
      success: true,
      project: redactProjectOutput(req, updated),
      database: db,
      note: 'Base de datos vinculada: al redesplegar se adjuntará su red Docker aislada y se inyectará la URL de conexión sin guardar contraseñas en disco.'
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/projects/:id/databases/:dbId/link', async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:write');
    if (!project) return;
    const nextIds = (Array.isArray(project.linkedDatabaseIds) ? project.linkedDatabaseIds : []).filter((x) => x !== req.params.dbId);
    const updated = projectManager.update(project.id, { linkedDatabaseIds: nextIds });
    await projectManager.flushToDisk();
    res.json({ success: true, project: redactProjectOutput(req, updated) });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --- TELEMETRÍA ANÓNIMA Y REPORTE DE FALLOS ---
const clientTelemetryLimiter = createRateLimiter({ max: 30, windowMs: 60000, prefix: 'telemetry_client', bypassLoopback: false });

router.get('/telemetry/status', (_req, res) => {
  try {
    res.json(telemetryService.getStatus());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.put('/telemetry/config', (req, res) => {
  try {
    const { enabled } = req.body || {};
    if (typeof enabled !== 'boolean') {
      return res.status(400).json({ error: 'Debes enviar un booleano `enabled`' });
    }
    const status = telemetryService.setEnabled(enabled);
    const { actor, authMethod } = getAuditActor(req);
    auditLogger.record({
      source: 'http',
      action: enabled ? 'telemetry.enable' : 'telemetry.disable',
      method: 'PUT',
      path: '/api/telemetry/config',
      ip: clientIp(req),
      authMethod,
      actor,
      status: 200
    });
    res.json(status);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/telemetry/preview', (_req, res) => {
  try {
    res.json(telemetryService.getPreviewPayload());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/telemetry/reset-id', (req, res) => {
  try {
    const status = telemetryService.resetInstanceId();
    const { actor, authMethod } = getAuditActor(req);
    auditLogger.record({
      source: 'http',
      action: 'telemetry.reset_id',
      method: 'POST',
      path: '/api/telemetry/reset-id',
      ip: clientIp(req),
      authMethod,
      actor,
      status: 200
    });
    res.json(status);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/telemetry/client-error', clientTelemetryLimiter, (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const accepted = telemetryService.captureClientError(body);
    res.status(202).json({ accepted });
  } catch (err) {
    res.status(202).json({ accepted: false });
  }
});

router.post('/projects/:id/maintenance', async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:write');
    if (!project) return;
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

// ===========================================================================
// MULTI-SERVER FLEET (SSH Orchestration + AES-256-GCM Key Vault)
// ===========================================================================
router.get('/servers', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const servers = fleet.listServers({
      teamId: principal.isSuperAdmin ? (req.query.teamId ? String(req.query.teamId) : undefined) : principal.teamId,
      tag: req.query.tag ? String(req.query.tag) : undefined,
      region: req.query.region ? String(req.query.region) : undefined,
      includeLocal: req.query.includeLocal !== '0'
    });
    res.json({ servers, summary: fleet.getFleetSummary() });
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.post('/servers', certAndAdminLimiter, async (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const payload = { ...(req.body || {}) };
    if (!principal.isSuperAdmin) payload.teamId = principal.teamId;
    const server = await fleet.addServer(payload);
    res.status(201).json({ success: true, server });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/servers/select', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const body = req.body && typeof req.body === 'object' ? { ...req.body } : {};
    if (!principal.isSuperAdmin) body.teamId = principal.teamId;
    res.json(getFleetManager().selectBestServer(body));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/servers/:id', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const server = fleet.getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'Servidor no encontrado' });
    if (!principal.isSuperAdmin && server.id !== 'local' && server.teamId && server.teamId !== principal.teamId) {
      return res.status(404).json({ error: 'Servidor no encontrado' });
    }
    res.json({ server });
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.post('/servers/:id/maintenance', certAndAdminLimiter, (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const existing = fleet.getServer(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Servidor no encontrado' });
    if (!principal.isSuperAdmin && existing.teamId && existing.teamId !== principal.teamId) {
      return res.status(404).json({ error: 'Servidor no encontrado' });
    }
    res.json(fleet.setServerMaintenance(req.params.id, req.body || {}));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/servers/:id/bootstrap', certAndAdminLimiter, (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const existing = fleet.getServer(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Servidor no encontrado' });
    if (!principal.isSuperAdmin && existing.teamId && existing.teamId !== principal.teamId) {
      return res.status(404).json({ error: 'Servidor no encontrado' });
    }
    res.json(fleet.generateBootstrapScript(req.params.id, req.body || {}));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/servers/:id/caddy/sync', certAndAdminLimiter, async (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const existing = fleet.getServer(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Servidor no encontrado' });
    if (!principal.isSuperAdmin && existing.teamId && existing.teamId !== principal.teamId) {
      return res.status(404).json({ error: 'Servidor no encontrado' });
    }
    res.json(await fleet.syncRemoteCaddy(req.params.id, req.body || {}));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/servers/:id/containers/:containerId/logs', async (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const existing = fleet.getServer(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Servidor no encontrado' });
    if (!principal.isSuperAdmin && existing.teamId && existing.teamId !== principal.teamId) {
      return res.status(404).json({ error: 'Servidor no encontrado' });
    }
    res.json(await fleet.remoteContainerLogs(req.params.id, req.params.containerId, req.query || {}));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/servers/:id/containers/:containerId/stats', async (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const existing = fleet.getServer(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Servidor no encontrado' });
    if (!principal.isSuperAdmin && existing.teamId && existing.teamId !== principal.teamId) {
      return res.status(404).json({ error: 'Servidor no encontrado' });
    }
    res.json(await fleet.remoteContainerStats(req.params.id, req.params.containerId));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/servers/:id/containers/:containerId/exec', execLimiter, async (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const existing = fleet.getServer(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Servidor no encontrado' });
    if (!principal.isSuperAdmin && existing.teamId && existing.teamId !== principal.teamId) {
      return res.status(404).json({ error: 'Servidor no encontrado' });
    }
    res.json(await fleet.remoteContainerExec(req.params.id, req.params.containerId, req.body || {}));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.put('/servers/:id', certAndAdminLimiter, async (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const existing = fleet.getServer(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Servidor no encontrado' });
    if (!principal.isSuperAdmin && existing.teamId && existing.teamId !== principal.teamId) {
      return res.status(404).json({ error: 'Servidor no encontrado' });
    }
    const server = await fleet.updateServer(req.params.id, req.body || {});
    res.json({ success: true, server });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.delete('/servers/:id', certAndAdminLimiter, async (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const existing = fleet.getServer(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Servidor no encontrado' });
    if (!principal.isSuperAdmin && existing.teamId && existing.teamId !== principal.teamId) {
      return res.status(404).json({ error: 'Servidor no encontrado' });
    }
    const assignedProjectIds = projectManager.getAll()
      .filter((p) => p && p.serverId === req.params.id)
      .map((p) => p.id);
    const force = req.query.force === '1' || req.query.force === 'true' || Boolean(req.body?.force);
    const result = await fleet.deleteServer(req.params.id, { force, assignedProjectIds });
    res.json({ success: true, deleted: true, ...result });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/servers/:id/probe', certAndAdminLimiter, async (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const existing = fleet.getServer(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Servidor no encontrado' });
    if (!principal.isSuperAdmin && existing.id !== 'local' && existing.teamId && existing.teamId !== principal.teamId) {
      return res.status(404).json({ error: 'Servidor no encontrado' });
    }
    const result = await fleet.probeServer(req.params.id, { force: req.body?.force !== false });
    res.json({ ...result, probe: result.resources || null });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/servers/:id/repin-host-key', certAndAdminLimiter, async (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const existing = fleet.getServer(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Servidor no encontrado' });
    if (!principal.isSuperAdmin && existing.teamId && existing.teamId !== principal.teamId) {
      return res.status(404).json({ error: 'Servidor no encontrado' });
    }
    const result = await fleet.repinHostKey(req.params.id, { expectedFingerprint: req.body?.expectedFingerprint });
    res.json({ success: true, ...result });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/fleet/keys', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const keys = fleet.listKeys({ teamId: principal.isSuperAdmin ? undefined : principal.teamId });
    res.json({ keys });
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.post('/fleet/keys', certAndAdminLimiter, async (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const body = req.body || {};
    const teamId = principal.isSuperAdmin ? (body.teamId || 'team_default') : principal.teamId;
    const isImport = body.mode === 'import' || Boolean(body.privateKeyPem || body.privateKey);
    const key = isImport
      ? await fleet.importKey({ name: body.name, privateKeyPem: body.privateKeyPem || body.privateKey, teamId })
      : await fleet.generateKeyPair({ name: body.name, teamId });
    res.status(201).json({ success: true, key });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.delete('/fleet/keys/:id', certAndAdminLimiter, (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const key = fleet.getKey(req.params.id);
    if (!key) return res.status(404).json({ error: 'Llave SSH no encontrada' });
    if (!principal.isSuperAdmin && key.teamId && key.teamId !== principal.teamId) {
      return res.status(404).json({ error: 'Llave SSH no encontrada' });
    }
    fleet.deleteKey(req.params.id);
    res.json({ success: true, deleted: true });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

// ===========================================================================
// MULTI-USER AUTH, TEAMS, RBAC, INVITES, PROJECT ACL & SCOPED TOKENS
// ===========================================================================
router.post('/auth/bootstrap', sensitiveAuthLimiter, (req, res) => {
  try {
    if (!canBootstrapRequest(req)) {
      return res.status(403).json({ error: 'El bootstrap inicial solo está permitido desde localhost o con el token maestro' });
    }
    const tm = getTeamManager();
    const result = tm.bootstrapOwner({
      ...(req.body || {}),
      ip: clientIp(req),
      ua: req.headers['user-agent'] || ''
    });
    attachSessionCookie(req, res, result.sessionToken);
    res.status(201).json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/auth/login', authVerifyLimiter, (req, res) => {
  const bf = checkAuthBruteForce(req);
  if (bf.blocked) {
    res.setHeader('Retry-After', String(bf.retryAfterSec));
    const circuit = recordAuthCircuitFailure(req, res, { blocked: true, retryAfterSec: bf.retryAfterSec });
    return res.status(429).json({
      error: 'Demasiados intentos de autenticación fallidos. Espera antes de reintentar.',
      code: 'AUTH_RATE_LIMITED',
      retryAfterSec: bf.retryAfterSec,
      authCircuit: circuit.authCircuit,
      backoffMs: circuit.backoffMs
    });
  }
  try {
    if (getOidcService().isPasswordLoginDisabled()) {
      return res.status(403).json({
        error: 'El inicio de sesión con contraseña está deshabilitado por política SSO/OIDC',
        code: 'PASSWORD_LOGIN_DISABLED'
      });
    }
    const tm = getTeamManager();
    const result = tm.login({
      ...(req.body || {}),
      ip: clientIp(req),
      ua: req.headers['user-agent'] || ''
    });
    clearAuthCircuit(req);
    if (result && result.sessionToken) {
      attachSessionCookie(req, res, result.sessionToken);
    }
    res.json(result);
  } catch (err) {
    recordAuthFailure(req);
    metricsCollector.recordSecurityEvent('authFailures');
    recordAuthCircuitFailure(req, res);
    sendServiceError(err, res, 401);
  }
});

router.post('/auth/invites/accept', authVerifyLimiter, (req, res) => {
  const bf = checkAuthBruteForce(req);
  if (bf.blocked) {
    res.setHeader('Retry-After', String(bf.retryAfterSec));
    return res.status(429).json({
      error: 'Demasiados intentos de autenticación fallidos. Espera antes de reintentar.',
      code: 'AUTH_RATE_LIMITED',
      retryAfterSec: bf.retryAfterSec
    });
  }
  try {
    const tm = getTeamManager();
    const result = tm.acceptInvite({
      ...(req.body || {}),
      ip: clientIp(req),
      ua: req.headers['user-agent'] || ''
    });
    if (result && result.sessionToken) {
      attachSessionCookie(req, res, result.sessionToken);
    }
    res.status(201).json(result);
  } catch (err) {
    recordAuthFailure(req);
    metricsCollector.recordSecurityEvent('authFailures');
    sendServiceError(err, res, 400);
  }
});

router.post('/auth/logout', (req, res) => {
  try {
    const principal = getPrincipal(req);
    if (principal.kind === 'session' && principal.userId && principal.sessionId) {
      getTeamManager().logoutSession(principal.userId, principal.sessionId);
    }
    clearSessionCookies(req, res);
    res.json({ success: true });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/auth/logout-all', (req, res) => {
  try {
    const principal = getPrincipal(req);
    if (principal.userId) {
      getTeamManager().logoutAll(principal.userId);
    }
    clearSessionCookies(req, res);
    res.json({ success: true });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/auth/password', sensitiveAuthLimiter, (req, res) => {
  try {
    const principal = getPrincipal(req);
    if (!principal.userId) return res.status(400).json({ error: 'No hay una cuenta de usuario activa en esta sesión' });
    const result = getTeamManager().changePassword(principal.userId, {
      ...(req.body || {}),
      teamId: principal.teamId,
      ip: clientIp(req),
      ua: req.headers['user-agent'] || ''
    });
    res.json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/auth/me', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const summary = getTeamManager().getStatusSummary();
    res.json({
      isSuperAdmin: Boolean(principal.isSuperAdmin),
      kind: principal.kind || 'legacy',
      userId: principal.userId || null,
      email: principal.email || null,
      name: principal.name || (principal.isSuperAdmin ? 'Administrador local' : null),
      role: principal.role || 'owner',
      teamId: principal.teamId || 'team_default',
      scopes: principal.scopes || ['*'],
      projectIds: principal.projectIds ?? null,
      multiUserEnabled: Boolean(summary.multiUserEnabled),
      usersCount: summary.usersCount,
      teamsCount: summary.teamsCount
    });
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.get('/teams', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const teams = getTeamManager().listTeams(principal);
    res.json({ teams });
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.post('/teams', certAndAdminLimiter, (req, res) => {
  try {
    const principal = getPrincipal(req);
    const team = getTeamManager().createTeam(principal, req.body || {});
    res.status(201).json({ success: true, team });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/teams/:teamId/members', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const tm = getTeamManager();
    if (!tm.getStatusSummary().multiUserEnabled && req.params.teamId === 'team_default') {
      return res.json({ members: [], invites: [] });
    }
    const members = tm.listMembers(principal, req.params.teamId);
    let invites = [];
    try { invites = tm.listInvites(principal, req.params.teamId); } catch (e) {}
    res.json({ members, invites });
  } catch (err) {
    sendServiceError(err, res, 403);
  }
});

router.patch('/teams/:teamId/members/:id', certAndAdminLimiter, (req, res) => {
  try {
    const principal = getPrincipal(req);
    const tm = getTeamManager();
    const body = req.body || {};
    let member = null;
    if (body.role !== undefined) {
      member = tm.updateMemberRole(principal, req.params.teamId, req.params.id, body.role);
    }
    if (body.projectIds !== undefined) {
      const normalized = body.projectIds === '*' ? null : body.projectIds;
      member = tm.updateMemberProjects(principal, req.params.teamId, req.params.id, normalized);
    }
    res.json({ success: true, member });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.delete('/teams/:teamId/members/:id', certAndAdminLimiter, (req, res) => {
  try {
    const principal = getPrincipal(req);
    const result = getTeamManager().removeMember(principal, req.params.teamId, req.params.id);
    res.json({ success: true, removed: true, ...result });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/teams/:teamId/invites', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const invites = getTeamManager().listInvites(principal, req.params.teamId);
    res.json({ invites });
  } catch (err) {
    sendServiceError(err, res, 403);
  }
});

router.post('/teams/:teamId/invites', certAndAdminLimiter, (req, res) => {
  try {
    const principal = getPrincipal(req);
    const result = getTeamManager().createInvite(principal, {
      ...(req.body || {}),
      teamId: req.params.teamId
    });
    res.status(201).json({
      ...result,
      token: result.inviteToken || result.token
    });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.delete('/teams/:teamId/invites/:inviteId', certAndAdminLimiter, (req, res) => {
  try {
    const principal = getPrincipal(req);
    const result = getTeamManager().revokeInvite(principal, req.params.teamId, req.params.inviteId);
    res.json({ success: true, revoked: true, ...result });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.put('/teams/:teamId/security-policy', certAndAdminLimiter, (req, res) => {
  try {
    const principal = getPrincipal(req);
    const result = getTeamManager().setTeamSecurityPolicy(principal, req.params.teamId, req.body || {});
    res.json({ success: true, ...result });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/projects/:id/acl', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
    if (!project) return;
    const acl = getTeamManager().getProjectAcl(principal, project.id, project.teamId || 'team_default');
    res.json(acl);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.put('/projects/:id/acl', certAndAdminLimiter, (req, res) => {
  try {
    const principal = getPrincipal(req);
    const project = assertProjectAccess(req, res, req.params.id, 'projects:acl');
    if (!project) return;
    const body = req.body || {};
    const result = getTeamManager().setProjectAcl(principal, project.id, {
      userId: body.userId,
      role: body.role,
      teamId: project.teamId || 'team_default'
    });
    res.json({ success: true, ...result });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.delete('/projects/:id/acl/:userId', certAndAdminLimiter, (req, res) => {
  try {
    const principal = getPrincipal(req);
    const project = assertProjectAccess(req, res, req.params.id, 'projects:acl');
    if (!project) return;
    const result = getTeamManager().removeProjectAcl(principal, project.id, req.params.userId, project.teamId || 'team_default');
    res.json({ success: true, removed: true, ...result });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/auth/tokens', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const tokens = getTeamManager().listApiTokens(principal);
    res.json({ tokens });
  } catch (err) {
    sendServiceError(err, res, 403);
  }
});

router.post('/auth/tokens', sensitiveAuthLimiter, (req, res) => {
  try {
    const principal = getPrincipal(req);
    const body = req.body || {};
    const projectIds = body.projectIds === '*' ? null : body.projectIds;
    const result = getTeamManager().createApiToken(principal, { ...body, projectIds });
    res.status(201).json({
      ...result,
      token: result.token || result.rawToken,
      meta: result.record || result.apiToken || result.meta
    });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.delete('/auth/tokens/:id', sensitiveAuthLimiter, (req, res) => {
  try {
    const principal = getPrincipal(req);
    const result = getTeamManager().revokeApiToken(principal, req.params.id);
    res.json({ success: true, revoked: true, ...result });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

// ===========================================================================
// ENVIRONMENTS, SHARED ENCRYPTED VAULT & PROMOTION PIPELINE
// ===========================================================================
router.get('/vault', (req, res) => {
  try {
    if (denyProjectScopedToken(req, res, 'listar la bóveda global')) return;
    const secrets = getEnvironmentManager().listVaultSecrets();
    res.json({ secrets });
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.put('/vault/:key', certAndAdminLimiter, (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'escribir en la bóveda global')) return;
    const principal = getPrincipal(req);
    const body = req.body || {};
    const secret = getEnvironmentManager().setVaultSecret(req.params.key, body.value, {
      scope: body.scope || 'both',
      description: body.description || '',
      actor: principal.email || principal.kind
    });
    res.json({ success: true, secret });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.delete('/vault/:key', certAndAdminLimiter, (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'eliminar secretos de la bóveda global')) return;
    const principal = getPrincipal(req);
    const deleted = getEnvironmentManager().deleteVaultSecret(req.params.key, { actor: principal.email || principal.kind });
    res.json({ success: true, deleted: Boolean(deleted) });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/projects/:id/environments', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
    if (!project) return;
    const environments = getEnvironmentManager().listEnvironments(project.id);
    res.json({ environments });
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.get('/projects/:id/environments/diff', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
    if (!project) return;
    const fromEnv = String(req.query.from || 'staging');
    const toEnv = String(req.query.to || 'production');
    const diff = getEnvironmentManager().diffEnvironments(project.id, fromEnv, toEnv);
    res.json(diff);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/projects/:id/environments/promote', certAndAdminLimiter, async (req, res) => {
  try {
    const principal = getPrincipal(req);
    const project = assertProjectAccess(req, res, req.params.id, 'environments:write');
    if (!project) return;
    const body = req.body || {};
    if (body.overrideFreeze && !principal.isSuperAdmin) {
      const tm = getTeamManager();
      if (!tm.doesPrincipalSatisfyRole(principal, 'admin').allowed) {
        return res.status(403).json({
          error: 'Solo un administrador u owner puede anular una ventana de congelación (overrideFreeze)',
          code: 'FREEZE_OVERRIDE_FORBIDDEN'
        });
      }
    }
    const result = await getEnvironmentManager().promoteEnvironment(project.id, {
      fromEnv: body.fromEnv || 'staging',
      toEnv: body.toEnv || 'production',
      includeEnvVars: body.includeEnvVars !== false,
      envKeys: body.envKeys,
      dryRun: Boolean(body.dryRun),
      overrideFreeze: Boolean(body.overrideFreeze),
      approvalId: body.approvalId,
      reason: body.reason,
      actor: principal.email || principal.kind
    });
    res.json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/projects/:id/environments/:env/rollback', certAndAdminLimiter, (req, res) => {
  try {
    const principal = getPrincipal(req);
    const project = assertProjectAccess(req, res, req.params.id, 'environments:write');
    if (!project) return;
    const result = getEnvironmentManager().rollbackPromotion(project.id, req.params.env, req.body?.snapshotId, {
      actor: principal.email || principal.kind,
      reason: req.body?.reason
    });
    res.json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.put('/projects/:id/environments/:env', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const project = assertProjectAccess(req, res, req.params.id, 'environments:write');
    if (!project) return;
    const environment = getEnvironmentManager().upsertEnvironment(project.id, req.params.env, {
      ...(req.body || {}),
      actor: principal.email || principal.kind
    });
    res.json({ success: true, environment });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.delete('/projects/:id/environments/:env', certAndAdminLimiter, (req, res) => {
  try {
    const principal = getPrincipal(req);
    const project = assertProjectAccess(req, res, req.params.id, 'environments:write');
    if (!project) return;
    const deleted = getEnvironmentManager().deleteEnvironment(project.id, req.params.env, {
      force: req.query.force === '1',
      actor: principal.email || principal.kind
    });
    res.json({ success: true, deleted: Boolean(deleted) });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

// ===========================================================================
// DECLARATIVE GITOPS (`culkibo.yaml` Export / Plan / Apply / Drift)
// ===========================================================================
router.post('/gitops/export', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const body = { ...(req.body || {}) };
    if (!principal.isSuperAdmin) {
      const allowedProjects = getTeamManager().filterProjects(principal, projectManager.getAll(), { redact: false });
      const allowedSet = new Set(allowedProjects.map((p) => p.id));
      if (Array.isArray(body.projectIds) && body.projectIds.length > 0) {
        const forbidden = body.projectIds.filter((pid) => !allowedSet.has(String(pid)));
        if (forbidden.length > 0) {
          return res.status(403).json({
            error: 'No tienes acceso a uno o más proyectos solicitados en gitops/export',
            code: 'PROJECT_FORBIDDEN'
          });
        }
      } else {
        body.projectIds = Array.from(allowedSet);
      }
    }
    const result = getGitOpsManager().exportStack(body);
    res.json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/gitops/plan', (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'gitops/plan')) return;
    const body = req.body || {};
    const yamlText = String(body.yamlText ?? body.yaml ?? '');
    const result = getGitOpsManager().planApply(yamlText, {
      prune: Boolean(body.prune),
      confirmDestructive: Boolean(body.confirmDestructive),
      stackId: body.stackId
    });
    res.json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/gitops/apply', certAndAdminLimiter, async (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'gitops/apply')) return;
    const principal = getPrincipal(req);
    const body = req.body || {};
    const yamlText = String(body.yamlText ?? body.yaml ?? '');
    const result = await getGitOpsManager().applyStack(yamlText, {
      dryRun: Boolean(body.dryRun),
      prune: Boolean(body.prune),
      confirmDestructive: Boolean(body.confirmDestructive),
      stackId: body.stackId,
      actor: principal.email || principal.kind
    });
    res.json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/gitops/drift', (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'gitops/drift')) return;
    const stackId = req.query.stackId ? String(req.query.stackId) : undefined;
    const result = getGitOpsManager().detectDrift(stackId);
    res.json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

// ===========================================================================
// SYNTHETIC UPTIME MONITORS & PUBLIC STATUS PAGES
// ===========================================================================
/** @param {any} principal @param {any} monitor */
function canAccessMonitor(principal, monitor, perm = 'projects:read') {
  if (!principal || principal.isSuperAdmin) return true;
  if (monitor && monitor.projectId) {
    const proj = projectManager.getById(monitor.projectId);
    return getTeamManager().authorizeProject(principal, monitor.projectId, perm, proj).allowed;
  }
  return !Array.isArray(principal.projectIds);
}

router.get('/uptime/monitors', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const filterProjectId = req.query.projectId ? String(req.query.projectId) : undefined;
    if (filterProjectId && !principal.isSuperAdmin) {
      const proj = assertProjectAccess(req, res, filterProjectId, 'projects:read');
      if (!proj) return;
    }
    const raw = getUptimeMonitor().listMonitors({
      projectId: filterProjectId,
      projectIds: !principal.isSuperAdmin && Array.isArray(principal.projectIds) ? principal.projectIds : undefined
    });
    const monitors = principal.isSuperAdmin
      ? raw
      : raw.filter((m) => canAccessMonitor(principal, m, 'projects:read'));
    res.json({ monitors });
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.post('/uptime/monitors', async (req, res) => {
  try {
    const body = req.body || {};
    if (body.projectId) {
      const proj = assertProjectAccess(req, res, String(body.projectId), 'uptime:write');
      if (!proj) return;
    } else if (denyProjectScopedToken(req, res, 'monitores globales sin proyecto')) {
      return;
    }
    const monitor = await getUptimeMonitor().createMonitor(body);
    res.status(201).json({ success: true, monitor });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.put('/uptime/monitors/:id', async (req, res) => {
  try {
    const principal = getPrincipal(req);
    const existing = getUptimeMonitor().getMonitor(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Monitor no encontrado' });
    if (!principal.isSuperAdmin) {
      if (existing.projectId) {
        const proj = assertProjectAccess(req, res, existing.projectId, 'uptime:write');
        if (!proj) return;
      } else if (denyProjectScopedToken(req, res, 'monitores globales sin proyecto')) {
        return;
      }
      if (req.body && req.body.projectId && String(req.body.projectId) !== existing.projectId) {
        const nextProj = assertProjectAccess(req, res, String(req.body.projectId), 'uptime:write');
        if (!nextProj) return;
      }
    }
    const monitor = await getUptimeMonitor().updateMonitor(req.params.id, req.body || {});
    res.json({ success: true, monitor });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.delete('/uptime/monitors/:id', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const existing = getUptimeMonitor().getMonitor(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Monitor no encontrado' });
    if (!principal.isSuperAdmin) {
      if (existing.projectId) {
        const proj = assertProjectAccess(req, res, existing.projectId, 'uptime:write');
        if (!proj) return;
      } else if (denyProjectScopedToken(req, res, 'monitores globales sin proyecto')) {
        return;
      }
    }
    const deleted = getUptimeMonitor().deleteMonitor(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Monitor no encontrado' });
    res.json({ success: true, deleted: true });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/uptime/monitors/:id/check', async (req, res) => {
  try {
    const principal = getPrincipal(req);
    const existing = getUptimeMonitor().getMonitor(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Monitor no encontrado' });
    if (!principal.isSuperAdmin) {
      if (existing.projectId) {
        const proj = assertProjectAccess(req, res, existing.projectId, 'uptime:write');
        if (!proj) return;
      } else if (denyProjectScopedToken(req, res, 'monitores globales sin proyecto')) {
        return;
      }
    }
    const result = await getUptimeMonitor().runCheck(req.params.id);
    res.json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/uptime/incidents', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const um = getUptimeMonitor();
    const rawIncidents = um.listIncidents({
      monitorId: req.query.monitorId ? String(req.query.monitorId) : undefined,
      status: req.query.status ? String(req.query.status) : undefined,
      limit: req.query.limit ? parseInt(String(req.query.limit), 10) : 50
    });
    if (principal.isSuperAdmin) {
      return res.json({ incidents: rawIncidents });
    }
    const allowedMonitorIds = new Set(
      um.listMonitors().filter((m) => canAccessMonitor(principal, m, 'projects:read')).map((m) => m.id)
    );
    const incidents = rawIncidents.filter((inc) => allowedMonitorIds.has(inc.monitorId));
    res.json({ incidents });
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.get('/uptime/pages', (req, res) => {
  try {
    if (denyProjectScopedToken(req, res, 'páginas públicas de estado')) return;
    const pages = getUptimeMonitor().listStatusPages();
    res.json({ pages });
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.post('/uptime/pages', (req, res) => {
  try {
    if (denyProjectScopedToken(req, res, 'páginas públicas de estado')) return;
    const principal = getPrincipal(req);
    const body = req.body || {};
    if (!principal.isSuperAdmin) {
      const um = getUptimeMonitor();
      const cleanSlug = typeof body.slug === 'string' ? body.slug.trim().toLowerCase() : '';
      if (cleanSlug) {
        const existingPage = um.listStatusPages().find((p) => p.slug === cleanSlug);
        if (existingPage && Array.isArray(existingPage.monitorIds)) {
          for (const mid of existingPage.monitorIds) {
            const m = um.getMonitor(String(mid));
            if (m && !canAccessMonitor(principal, m, 'uptime:write')) {
              return res.status(403).json({
                error: 'No tienes permisos para sobrescribir esta página de estado',
                code: 'PROJECT_FORBIDDEN'
              });
            }
          }
        }
      }
      if (Array.isArray(body.monitorIds)) {
        for (const mid of body.monitorIds) {
          const m = um.getMonitor(String(mid));
          if (m && !canAccessMonitor(principal, m, 'uptime:write')) {
            return res.status(403).json({
              error: 'No tienes permisos sobre todos los monitores de esta página de estado',
              code: 'PROJECT_FORBIDDEN'
            });
          }
        }
      }
    }
    const page = getUptimeMonitor().saveStatusPage(body);
    res.status(201).json({ success: true, page });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.delete('/uptime/pages/:slug', (req, res) => {
  try {
    if (denyProjectScopedToken(req, res, 'páginas públicas de estado')) return;
    const principal = getPrincipal(req);
    const um = getUptimeMonitor();
    const cleanSlug = String(req.params.slug || '').trim().toLowerCase();
    if (!principal.isSuperAdmin) {
      const existingPage = um.listStatusPages().find((p) => p.slug === cleanSlug);
      if (existingPage && Array.isArray(existingPage.monitorIds)) {
        for (const mid of existingPage.monitorIds) {
          const m = um.getMonitor(String(mid));
          if (m && !canAccessMonitor(principal, m, 'uptime:write')) {
            return res.status(403).json({
              error: 'No tienes permisos para eliminar esta página de estado',
              code: 'PROJECT_FORBIDDEN'
            });
          }
        }
      }
    }
    const deleted = um.deleteStatusPage(req.params.slug);
    if (!deleted) return res.status(404).json({ error: 'Página de estado no encontrada' });
    res.json({ success: true, deleted: true });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/uptime/pages/:slug/incidents', (req, res) => {
  try {
    if (denyProjectScopedToken(req, res, 'incidentes de páginas de estado')) return;
    const principal = getPrincipal(req);
    const um = getUptimeMonitor();
    const cleanSlug = String(req.params.slug || '').trim().toLowerCase();
    if (!principal.isSuperAdmin) {
      const existingPage = um.listStatusPages().find((p) => p.slug === cleanSlug);
      if (existingPage && Array.isArray(existingPage.monitorIds)) {
        for (const mid of existingPage.monitorIds) {
          const m = um.getMonitor(String(mid));
          if (m && !canAccessMonitor(principal, m, 'uptime:write')) {
            return res.status(403).json({ error: 'No tienes permisos sobre esta página de estado', code: 'PROJECT_FORBIDDEN' });
          }
        }
      }
    }
    const incident = um.publishStatusIncident(req.params.slug, req.body || {});
    res.status(201).json({ success: true, incident });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/uptime/pages/:slug/incidents/:id/resolve', (req, res) => {
  try {
    if (denyProjectScopedToken(req, res, 'resolver incidentes de páginas de estado')) return;
    const principal = getPrincipal(req);
    const um = getUptimeMonitor();
    const cleanSlug = String(req.params.slug || '').trim().toLowerCase();
    if (!principal.isSuperAdmin) {
      const existingPage = um.listStatusPages().find((p) => p.slug === cleanSlug);
      if (existingPage && Array.isArray(existingPage.monitorIds)) {
        for (const mid of existingPage.monitorIds) {
          const m = um.getMonitor(String(mid));
          if (m && !canAccessMonitor(principal, m, 'uptime:write')) {
            return res.status(403).json({ error: 'No tienes permisos sobre esta página de estado', code: 'PROJECT_FORBIDDEN' });
          }
        }
      }
    }
    const incident = um.resolveStatusIncident(req.params.slug, req.params.id, req.body || {});
    res.json({ success: true, incident });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

// ===========================================================================
// SCALE-TO-ZERO AUTO-SLEEP & VPS COST/RAM ADVISOR
// ===========================================================================
router.get('/sleep', (req, res) => {
  try {
    const allowedProjectIds = getAllowedProjectIds(req);
    const policies = getSleepAdvisor().listPolicies({ projectIds: allowedProjectIds || undefined });
    res.json({ policies });
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.get('/sleep/:projectId', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.projectId, 'projects:read');
    if (!project) return;
    const policy = getSleepAdvisor().getPolicy(project.id);
    res.json(policy || { projectId: project.id, enabled: false, idleMinutes: 30, mode: 'pause', excludeCrons: true, sleeping: false });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.put('/sleep/:projectId', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.projectId, 'sleep:write');
    if (!project) return;
    const policy = getSleepAdvisor().setPolicy(project.id, req.body || {});
    res.json(policy);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/sleep/:projectId/sleep', async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.projectId, 'sleep:write');
    if (!project) return;
    const result = await getSleepAdvisor().sleepProject(project.id, { force: Boolean(req.body?.force) });
    res.json({ success: Boolean(result && result.slept), sleeping: Boolean(result && result.slept), ...result });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/sleep/:projectId/wake', async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.projectId, 'sleep:write');
    if (!project) return;
    const result = await getSleepAdvisor().wakeProject(project.id);
    res.json({ success: Boolean(result && result.woken), awake: Boolean(result && result.woken), ...result });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/advisor/resources', async (req, res) => {
  try {
    const principal = getPrincipal(req);
    const vpsMonthlyEur = req.query.vpsMonthlyEur !== undefined ? Number(req.query.vpsMonthlyEur) : undefined;
    const scopedProjectIds = principal.isSuperAdmin
      ? undefined
      : getTeamManager().filterProjects(principal, projectManager.getAll(), { redact: false }).map((p) => p.id);
    const report = await getSleepAdvisor().analyzeResources({
      vpsMonthlyEur: Number.isFinite(vpsMonthlyEur) ? vpsMonthlyEur : undefined,
      projectIds: scopedProjectIds
    });
    res.json(report);
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

// ===========================================================================
// LIVE SYNC 2.0 (Per-File Time-Travel & Multi-Client Conflicts)
// ===========================================================================
router.get('/projects/:id/sync/files/history', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
    if (!project) return;
    const filePath = String(req.query.path || '').trim();
    if (!filePath) return res.status(400).json({ error: 'Falta el parámetro path' });
    const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 20;
    const includeDiff = req.query.includeDiff === '1' || req.query.includeDiff === 'true';
    const history = liveSyncEngine.getFileHistory(project.id, filePath, { limit, includeDiff });
    res.json(history);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/projects/:id/sync/files/rollback', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const project = assertProjectAccess(req, res, req.params.id, 'sync:write');
    if (!project) return;
    const body = req.body || {};
    const result = liveSyncEngine.rollbackFile(project.id, body.path, Number(body.seq), {
      mode: body.mode || 'to',
      actor: principal.email || principal.kind
    });
    res.json({ success: true, ...result, reverted: true });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/projects/:id/sync/conflicts/:conflictId/resolve', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'sync:write');
    if (!project) return;
    const result = liveSyncEngine.resolveConflict(project.id, req.params.conflictId);
    res.json({ success: true, ...result, resolved: true });
  } catch (err) {
    sendServiceError(err, res, err && err.code === 'CONFLICT_NOT_FOUND' ? 404 : 400);
  }
});

// ===========================================================================
// DEPLOY FREEZE WINDOWS, POST-DEPLOY SMOKE TESTS & CANARY CONTROL
// ===========================================================================
router.get('/deploy/freeze-windows', (_req, res) => {
  try {
    res.json({ windows: deployManager.listFreezeWindows() });
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.post('/deploy/freeze-windows', certAndAdminLimiter, (req, res) => {
  try {
    const body = req.body || {};
    if (body.projectId) {
      const proj = assertProjectAccess(req, res, String(body.projectId), 'deployments:write');
      if (!proj) return;
    } else if (denyProjectScopedToken(req, res, 'ventanas globales de congelación')) {
      return;
    }
    const created = deployManager.addFreezeWindow(body);
    res.status(201).json({ success: true, window: created });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.delete('/deploy/freeze-windows/:id', certAndAdminLimiter, (req, res) => {
  try {
    if (denyProjectScopedToken(req, res, 'eliminar ventanas de congelación')) return;
    const removed = deployManager.removeFreezeWindow(req.params.id);
    if (!removed) return res.status(404).json({ error: 'Ventana de congelación no encontrada' });
    res.json({ success: true, deleted: true });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/deploy/freeze-status', (req, res) => {
  try {
    const projectId = req.query.projectId ? String(req.query.projectId) : null;
    if (projectId) {
      const proj = assertProjectAccess(req, res, projectId, 'projects:read');
      if (!proj) return;
    }
    res.json(deployManager.evaluateFreezeStatus(projectId));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/projects/:id/smoke-test', async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'deployments:write');
    if (!project) return;
    const result = await deployManager.runSmokeTestsForProject(project.id, req.body || {});
    res.json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/projects/:id/canary/promote', certAndAdminLimiter, async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'deployments:write');
    if (!project) return;
    const result = await deployManager.promoteCanary(project.id);
    res.json({ success: true, ...result });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/projects/:id/canary/abort', certAndAdminLimiter, async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'deployments:write');
    if (!project) return;
    const result = await deployManager.abortCanary(project.id, req.body?.reason || 'Abortado manualmente');
    res.json({ success: true, ...result });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

// ===== v1.1 ENDPOINTS =====

/** Mapea alias de condición del frontend (`gt`/`lt`/`gte`/`lte`/`eq`) al operador nativo de `alertEngine`. */
function normalizeAlertRulePayload(raw) {
  const body = raw && typeof raw === 'object' ? { ...raw } : {};
  const condMap = { gt: '>', gte: '>=', lt: '<', lte: '<=', eq: '==' };
  if (!body.operator && typeof body.condition === 'string') {
    const mapped = condMap[body.condition.trim().toLowerCase()];
    body.operator = mapped || body.condition;
  }
  if (body.cooldownMs === undefined && body.cooldownSec !== undefined) {
    body.cooldownMs = Math.round(Number(body.cooldownSec) * 1000);
  }
  return body;
}

// --- OBSERVABILITY v1.1 ---
router.get('/observability/history', (req, res) => {
  try {
    const data = getMetricsHistory().query({
      range: req.query.range ? String(req.query.range) : '1h'
    });
    res.json(data);
  } catch (err) { sendServiceError(err, res); }
});

router.get('/observability/metrics/history', (req, res) => {
  try {
    const data = getMetricsHistory().query({
      range: req.query.range ? String(req.query.range) : '24h'
    });
    res.json(data);
  } catch (err) { sendServiceError(err, res); }
});

router.get('/alerts/rules', (_req, res) => {
  try { res.json({ rules: getAlertEngine().listRules() }); }
  catch (err) { sendServiceError(err, res, 500); }
});
router.post('/alerts/rules', (req, res) => {
  try { res.status(201).json({ rule: getAlertEngine().createRule(normalizeAlertRulePayload(req.body)) }); }
  catch (err) { sendServiceError(err, res); }
});
router.put('/alerts/rules/:id', (req, res) => {
  try { res.json({ rule: getAlertEngine().updateRule(req.params.id, normalizeAlertRulePayload(req.body)) }); }
  catch (err) { sendServiceError(err, res); }
});
router.delete('/alerts/rules/:id', (req, res) => {
  try { res.json(getAlertEngine().deleteRule(req.params.id)); }
  catch (err) { sendServiceError(err, res); }
});
router.post('/alerts/rules/:id/silence', (req, res) => {
  try {
    const mins = req.body && req.body.durationMinutes !== undefined ? Number(req.body.durationMinutes) : 60;
    res.json({ rule: getAlertEngine().silenceRule(req.params.id, mins) });
  } catch (err) { sendServiceError(err, res); }
});
router.get('/alerts/active', (req, res) => {
  try {
    const projectIds = getAllowedProjectIds(req);
    const alerts = getAlertEngine().getActiveAlerts({ projectIds });
    res.json({ alerts, summary: getAlertEngine().getSummary({ projectIds }) });
  } catch (err) { sendServiceError(err, res, 500); }
});
router.post('/alerts/active/:id/ack', (req, res) => {
  try { res.json({ success: true, alert: getAlertEngine().acknowledgeAlert(req.params.id) }); }
  catch (err) { sendServiceError(err, res); }
});
router.get('/alerts/history', (req, res) => {
  try {
    const projectIds = getAllowedProjectIds(req);
    const history = getAlertEngine().getHistory({
      limit: req.query.limit ? parseInt(String(req.query.limit), 10) : 50,
      ruleId: req.query.ruleId ? String(req.query.ruleId) : null,
      status: req.query.status ? String(req.query.status) : null,
      projectIds
    });
    res.json({ alerts: history, history });
  } catch (err) { sendServiceError(err, res, 500); }
});
router.post('/alerts/evaluate', async (_req, res) => {
  try { res.json(await getAlertEngine().evaluateLive()); }
  catch (err) { sendServiceError(err, res, 500); }
});

// Aliases `/observability/alerts/*` usados por `web/src/lib/api.ts`
router.get('/observability/alerts/rules', (_req, res) => {
  try { res.json({ rules: getAlertEngine().listRules() }); }
  catch (err) { sendServiceError(err, res, 500); }
});
router.post('/observability/alerts/rules', (req, res) => {
  try { res.status(201).json({ rule: getAlertEngine().createRule(normalizeAlertRulePayload(req.body)) }); }
  catch (err) { sendServiceError(err, res); }
});
router.put('/observability/alerts/rules/:id', (req, res) => {
  try { res.json({ rule: getAlertEngine().updateRule(req.params.id, normalizeAlertRulePayload(req.body)) }); }
  catch (err) { sendServiceError(err, res); }
});
router.delete('/observability/alerts/rules/:id', (req, res) => {
  try { res.json(getAlertEngine().deleteRule(req.params.id)); }
  catch (err) { sendServiceError(err, res); }
});
router.get('/observability/alerts/history', (req, res) => {
  try {
    const projectIds = getAllowedProjectIds(req);
    const history = getAlertEngine().getHistory({
      limit: req.query.limit ? parseInt(String(req.query.limit), 10) : 50,
      ruleId: req.query.ruleId ? String(req.query.ruleId) : null,
      status: req.query.status ? String(req.query.status) : null,
      projectIds
    });
    res.json({ alerts: history, history });
  } catch (err) { sendServiceError(err, res, 500); }
});
router.get('/observability/alerts', (req, res) => {
  try {
    const projectIds = getAllowedProjectIds(req);
    res.json({ alerts: getAlertEngine().getActiveAlerts({ projectIds }), rules: getAlertEngine().listRules() });
  } catch (err) { sendServiceError(err, res, 500); }
});
router.post('/observability/alerts', (req, res) => {
  try { res.status(201).json(getAlertEngine().createRule(normalizeAlertRulePayload(req.body))); }
  catch (err) { sendServiceError(err, res); }
});
router.put('/observability/alerts/:id', (req, res) => {
  try { res.json(getAlertEngine().updateRule(req.params.id, normalizeAlertRulePayload(req.body))); }
  catch (err) { sendServiceError(err, res); }
});
router.delete('/observability/alerts/:id', (req, res) => {
  try { res.json(getAlertEngine().deleteRule(req.params.id)); }
  catch (err) { sendServiceError(err, res); }
});
router.post('/observability/alerts/:id/acknowledge', (req, res) => {
  try { res.json({ success: true, alert: getAlertEngine().acknowledgeAlert(req.params.id) }); }
  catch (err) { sendServiceError(err, res); }
});

/** @param {any} req @param {any} res */
function handleTopologyRequest(req, res) {
  try {
    const principal = getPrincipal(req);
    const allowedProjectIds = getAllowedProjectIds(req);
    res.json(getTopologyService().buildTopology({
      isSuperAdmin: Boolean(principal.isSuperAdmin),
      allowedProjectIds
    }));
  } catch (err) {
    sendServiceError(err, res, 500);
  }
}
router.get('/topology', handleTopologyRequest);
router.get('/observability/topology', handleTopologyRequest);

router.get('/observability/logs/search', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const requestedProjectId = req.query.projectId ? String(req.query.projectId) : null;
    if (requestedProjectId && requestedProjectId !== 'global' && !principal.isSuperAdmin) {
      if (!assertProjectAccess(req, res, requestedProjectId, 'projects:read')) return;
    }
    const allowedProjectIds = getAllowedProjectIds(req);
    const logs = containerOrchestrator.getLogs({
      pod: req.query.pod ? String(req.query.pod) : null,
      search: req.query.q ? String(req.query.q) : (req.query.search ? String(req.query.search) : ''),
      regex: req.query.regex ? String(req.query.regex) : false,
      level: req.query.level ? String(req.query.level) : null,
      projectId: requestedProjectId,
      projectIds: allowedProjectIds,
      since: req.query.since ? String(req.query.since) : null,
      until: req.query.until ? String(req.query.until) : null,
      attr: req.query.attr ? String(req.query.attr) : null,
      limit: Math.min(Number(req.query.limit) || 100, 1000)
    });
    res.json({ logs });
  } catch (err) { sendServiceError(err, res, err && err.status === 400 ? 400 : 500); }
});

router.get('/observability/logs/export', handleLogsExport);

// --- EDGE / INGRESS v1.1 ---
router.get('/ingress/dns-providers', (_req, res) => {
  try { res.json({ providers: caddyManager.listDnsProviders() }); }
  catch (err) { sendServiceError(err, res); }
});
router.get('/ingress/http3', async (_req, res) => {
  try { res.json(await caddyManager.probeHttp3()); }
  catch (err) { sendServiceError(err, res); }
});

// --- SECURITY v1.1 (TOTP 2FA RFC 6238, OIDC PKCE+JWKS, Audit Verify & Secret Scanner) ---
router.get('/auth/2fa/status', (req, res) => {
  try { res.json(getTeamManager().getTotpStatus(getPrincipal(req))); }
  catch (err) { sendServiceError(err, res); }
});
router.post('/auth/2fa/setup', sensitiveAuthLimiter, (req, res) => {
  try { res.json(getTeamManager().setupTotp(getPrincipal(req), req.body || {})); }
  catch (err) { sendServiceError(err, res); }
});
router.post('/auth/2fa/enable', sensitiveAuthLimiter, (req, res) => {
  try { res.json(getTeamManager().enableTotp(getPrincipal(req), req.body || {})); }
  catch (err) { sendServiceError(err, res); }
});
router.post('/auth/2fa/disable', sensitiveAuthLimiter, (req, res) => {
  try { res.json(getTeamManager().disableTotp(getPrincipal(req), req.body || {})); }
  catch (err) { sendServiceError(err, res); }
});
router.post('/auth/2fa/recovery-codes', sensitiveAuthLimiter, (req, res) => {
  try { res.json(getTeamManager().regenerateRecoveryCodes(getPrincipal(req), req.body || {})); }
  catch (err) { sendServiceError(err, res); }
});
router.post('/auth/2fa/verify', sensitiveAuthLimiter, (req, res) => {
  const bf = checkAuthBruteForce(req);
  if (bf.blocked) {
    res.setHeader('Retry-After', String(bf.retryAfterSec));
    return res.status(429).json({ error: 'Demasiados intentos de autenticación fallidos.', code: 'AUTH_RATE_LIMITED' });
  }
  try {
    const result = getTeamManager().verifyMfaLogin({
      ...(req.body || {}),
      ip: clientIp(req),
      ua: req.headers['user-agent'] || ''
    });
    if (result && result.sessionToken) {
      attachSessionCookie(req, res, result.sessionToken);
    }
    res.json(result);
  } catch (err) {
    recordAuthFailure(req);
    metricsCollector.recordSecurityEvent('authFailures');
    sendServiceError(err, res, 401);
  }
});

router.get('/auth/oidc/providers', (_req, res) => {
  try {
    const oidc = getOidcService();
    res.json({
      providers: oidc.listPublicProviders(),
      disablePasswordLogin: oidc.isPasswordLoginDisabled()
    });
  } catch (err) { sendServiceError(err, res); }
});
router.get('/auth/oidc/config', (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'configuración OIDC')) return;
    const oidc = getOidcService();
    res.json({
      providers: oidc.listProviders(),
      settings: oidc.getSecuritySettings()
    });
  } catch (err) { sendServiceError(err, res); }
});
router.put('/auth/oidc/settings', certAndAdminLimiter, (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'política de seguridad OIDC')) return;
    res.json({ settings: getOidcService().setSecuritySettings(req.body || {}) });
  } catch (err) { sendServiceError(err, res); }
});
router.post('/auth/oidc/config', certAndAdminLimiter, (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'configuración OIDC')) return;
    res.status(201).json({ provider: getOidcService().configureProvider(req.body || {}) });
  } catch (err) { sendServiceError(err, res); }
});
router.delete('/auth/oidc/config/:id', certAndAdminLimiter, (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'eliminar proveedor OIDC')) return;
    res.json(getOidcService().deleteProvider(req.params.id));
  } catch (err) { sendServiceError(err, res); }
});
router.post('/auth/oidc/start', authVerifyLimiter, async (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const providerId = String(body.providerId || body.provider || '').trim();
    const out = await getOidcService().createAuthorizationUrl(providerId, {
      redirectUri: body.redirectUri ? String(body.redirectUri) : undefined,
      teamId: body.teamId ? String(body.teamId) : undefined,
      ip: clientIp(req)
    });
    res.json(out);
  } catch (err) { sendServiceError(err, res); }
});
router.get('/auth/oidc/authorize', authVerifyLimiter, async (req, res) => {
  try {
    const providerId = String(req.query.providerId || req.query.provider || '').trim();
    const out = await getOidcService().createAuthorizationUrl(providerId, {
      redirectUri: req.query.redirectUri ? String(req.query.redirectUri) : undefined,
      teamId: req.query.teamId ? String(req.query.teamId) : undefined,
      ip: clientIp(req)
    });
    res.json(out);
  } catch (err) { sendServiceError(err, res); }
});
/** @param {any} req @param {any} res */
async function handleOidcCallback(req, res) {
  try {
    const src = req.method === 'GET' ? (req.query || {}) : (req.body || {});
    const identity = await getOidcService().handleCallback({
      state: String(src.state || ''),
      code: String(src.code || ''),
      ip: clientIp(req)
    });
    const loginResult = getTeamManager().loginWithOidc(identity, {
      teamId: identity.teamId,
      autoProvision: identity.autoProvision,
      defaultRole: identity.defaultRole,
      ip: clientIp(req),
      ua: req.headers['user-agent'] || ''
    });
    if (loginResult && loginResult.sessionToken) {
      clearAuthCircuit(req);
      attachSessionCookie(req, res, loginResult.sessionToken, {
        sameSite: req.method === 'GET' ? 'Lax' : 'Strict'
      });
    }
    res.json(loginResult);
  } catch (err) {
    recordAuthFailure(req);
    metricsCollector.recordSecurityEvent('authFailures');
    recordAuthCircuitFailure(req, res);
    sendServiceError(err, res, 401);
  }
}
router.get('/auth/oidc/callback', authVerifyLimiter, handleOidcCallback);
router.post('/auth/oidc/callback', authVerifyLimiter, handleOidcCallback);

router.get('/security/audit-log', (req, res) => {
  try {
    const principal = getPrincipal(req);
    if (!principal.isSuperAdmin && !getTeamManager().canAccess(principal, 'audit:read')) {
      return res.status(403).json({ error: 'Solo administradores', code: 'FORBIDDEN' });
    }
    res.json({
      entries: auditLogger.query({
        limit: Math.min(Number(req.query.limit) || 100, 1000),
        source: req.query.source ? String(req.query.source) : '',
        action: req.query.action ? String(req.query.action) : ''
      })
    });
  } catch (err) { sendServiceError(err, res); }
});
router.post('/security/audit-log/verify', (req, res) => {
  try {
    const principal = getPrincipal(req);
    if (!principal.isSuperAdmin && !getTeamManager().canAccess(principal, 'audit:read')) {
      return res.status(403).json({ error: 'Solo administradores', code: 'FORBIDDEN' });
    }
    const includeRotated = !(req.body && req.body.includeRotated === false);
    res.json(auditLogger.verifyIntegrity({ includeRotated }));
  } catch (err) { sendServiceError(err, res); }
});
router.post('/security/scan-secrets', (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const mode = body.mode === 'block' ? 'block' : 'warn';
    res.json(getSecretScanner().scanDeploymentPayload(body, { mode }));
  } catch (err) { sendServiceError(err, res); }
});

// --- GITOPS v1.1 ---
router.get('/gitops/schema.json', (_req, res) => {
  try { res.json(getGitOpsManager().getJsonSchema()); }
  catch (err) { sendServiceError(err, res); }
});

// --- BACKUP DR ALIASES v1.1 ---
router.post('/backup/verify', heavyOpLimiter, async (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    if (!body.databaseId || !body.backupId) {
      return res.status(400).json({ error: 'Indica databaseId y backupId para verificar la copia' });
    }
    const db = assertDatabaseAccess(req, res, String(body.databaseId), 'databases:write');
    if (!db) return;
    res.json(await databaseManager.verifyBackup(db.id, String(body.backupId), body));
  } catch (err) { sendServiceError(err, res); }
});
router.post('/backup/restore-drill', heavyOpLimiter, async (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    if (!body.databaseId) {
      return res.status(400).json({ error: 'Indica databaseId para ejecutar el simulacro de restauración' });
    }
    const db = assertDatabaseAccess(req, res, String(body.databaseId), 'databases:write');
    if (!db) return;
    res.json(await databaseManager.runRestoreDrill(db.id, body));
  } catch (err) { sendServiceError(err, res); }
});

// --- FLEET ALIASES v1.1 ---
router.post('/fleet/servers/:id/maintenance', certAndAdminLimiter, (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const existing = fleet.getServer(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Servidor no encontrado' });
    if (!principal.isSuperAdmin && existing.teamId && existing.teamId !== principal.teamId) {
      return res.status(404).json({ error: 'Servidor no encontrado' });
    }
    res.json(fleet.setServerMaintenance(req.params.id, req.body || {}));
  } catch (err) { sendServiceError(err, res); }
});
router.post('/fleet/servers/:id/drain', certAndAdminLimiter, (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const existing = fleet.getServer(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Servidor no encontrado' });
    if (!principal.isSuperAdmin && existing.teamId && existing.teamId !== principal.teamId) {
      return res.status(404).json({ error: 'Servidor no encontrado' });
    }
    res.json(fleet.setServerMaintenance(req.params.id, { ...(req.body || {}), state: 'draining' }));
  } catch (err) { sendServiceError(err, res); }
});
router.get('/fleet/bootstrap', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const fleet = getFleetManager();
    const serverId = String(req.query.serverId || req.query.id || '').trim();
    if (!serverId) return res.status(400).json({ error: 'Indica el parámetro serverId' });
    const existing = fleet.getServer(serverId);
    if (!existing) return res.status(404).json({ error: 'Servidor no encontrado' });
    if (!principal.isSuperAdmin && existing.teamId && existing.teamId !== principal.teamId) {
      return res.status(404).json({ error: 'Servidor no encontrado' });
    }
    const generated = fleet.generateBootstrapScript(serverId, req.query || {});
    if (req.query.format === 'json') return res.json(generated);
    res.setHeader('Content-Type', 'text/x-shellscript; charset=utf-8');
    res.send(generated.script || '');
  } catch (err) { sendServiceError(err, res); }
});
router.post('/fleet/placement', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const body = req.body && typeof req.body === 'object' ? { ...req.body } : {};
    if (!principal.isSuperAdmin) body.teamId = principal.teamId;
    res.json(getFleetManager().selectBestServer(body));
  } catch (err) { sendServiceError(err, res); }
});

// --- CYCLE #2 PIONEER LAZY ROUTES (SmartPack, DirectPush, EdgeTunnel, SnapStream) ---

router.post('/build/smartpack/plan', (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    /** @type {Record<string, any>} */
    const opts = { ...body };
    if (body.projectId) {
      const project = assertProjectAccess(req, res, String(body.projectId), 'projects:read');
      if (!project) return;
      if (!opts.dirPath && !opts.dir && !opts.files) {
        opts.dirPath = project.localPath || undefined;
      }
      if (opts.containerPort === undefined && project.containerPort) opts.containerPort = project.containerPort;
      if (opts.memoryMb === undefined && project.memoryMb) opts.memoryMb = project.memoryMb;
      if (opts.cpus === undefined && project.cpus) opts.cpus = project.cpus;
    }
    const targetDir = opts.dirPath || opts.dir || opts.localPath || null;
    if (targetDir) {
      if (!assertHostLocalPathAllowed(req, res)) return;
      opts.dirPath = String(targetDir);
    }
    const plan = getSmartPackBuilder().generateBuildPlan(opts);
    res.json(plan);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/deploy/direct-push/plan', (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    if (body.projectId) {
      if (!assertProjectAccess(req, res, String(body.projectId), 'deployments:write')) return;
    } else if (denyInstanceGlobalForTenant(req, res, 'planificar despliegue DirectPush SSH')) {
      return;
    }
    const plan = getDirectPushRegistry().planDirectPush(body);
    res.json(plan);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/edge-tunnel/status', (req, res) => {
  try {
    if (denyProjectScopedToken(req, res, 'estado global de EdgeTunnel')) return;
    res.json(getEdgeTunnelService().getStatus());
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.post('/edge-tunnel/tunnels', certAndAdminLimiter, (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'crear túnel EdgeTunnel')) return;
    const created = getEdgeTunnelService().createTunnel(req.body || {});
    res.setHeader('Cache-Control', 'private, no-store');
    res.status(201).json(created);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.delete('/edge-tunnel/tunnels/:id', certAndAdminLimiter, (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'revocar túnel EdgeTunnel')) return;
    const result = getEdgeTunnelService().revokeTunnel(req.params.id);
    if (!result || !result.revoked) {
      return res.status(404).json({ error: 'Túnel EdgeTunnel no encontrado', id: req.params.id });
    }
    res.json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/databases/:id/snapstream/capture', heavyOpLimiter, async (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:write');
    if (!db) return;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const dbPath = String(body.dbPath || db.dataFile || '').trim();
    if (!dbPath) {
      return res.status(400).json({ error: 'Indica dbPath del archivo SQLite para capturar generación SnapStream' });
    }
    if (body.dbPath && !assertHostLocalPathAllowed(req, res)) return;
    if (body.destDir && !assertHostLocalPathAllowed(req, res)) return;
    const result = await getSqliteStreamBackup().captureGeneration(db.id, dbPath, {
      encryptionKey: body.encryptionKey,
      destDir: body.destDir || null,
      s3Config: body.s3Config || null
    });
    res.status(201).json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/databases/:id/snapstream/generations', (req, res) => {
  try {
    const db = assertDatabaseAccess(req, res, req.params.id, 'databases:read');
    if (!db) return;
    const destDir = req.query.destDir ? String(req.query.destDir) : null;
    if (destDir && !assertHostLocalPathAllowed(req, res)) return;
    const snap = getSqliteStreamBackup();
    const generations = snap.listGenerations(db.id, { destDir });
    const status = snap.getStatus(db.id, { destDir });
    res.json({ databaseId: db.id, generations, status });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

// --- CYCLE #4 PIONEER LAZY ROUTES (OTLP, SLSA v1.1 DSSE Attestation, Atomic Migrations, Micro-Wasm) ---

router.get('/observability/otlp', (req, res) => {
  try {
    if (denyProjectScopedToken(req, res, 'estado global de exportación OTLP')) return;
    res.json(getOtlpExporter().getStatus());
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.put('/observability/otlp', certAndAdminLimiter, (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'configurar exportador OTLP')) return;
    const status = getOtlpExporter().configure(req.body || {});
    res.json(status);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/observability/otlp/flush', heavyOpLimiter, async (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'enviar lote OTLP')) return;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const snapshot = body.metricsSnapshot || JSON.parse(metricsCollector.getSnapshotBuffer(true).toString('utf8'));
    const out = await getOtlpExporter().flush({ ...body, metricsSnapshot: snapshot });
    res.json(out);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/projects/:id/releases/:rev/attestation', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
    if (!project) return;
    const att = getSupplyChainAttestor().getAttestation(project.id, req.params.rev);
    if (!att) {
      return res.json({
        found: false,
        attestation: null,
        projectId: project.id,
        revision: req.params.rev
      });
    }
    res.json({ found: true, attestation: att, ...att });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/projects/:id/releases/:rev/attest', heavyOpLimiter, (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'deployments:write');
    if (!project) return;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const att = getSupplyChainAttestor().attestRelease({
      ...body,
      projectId: project.id,
      revision: req.params.rev
    });
    res.status(201).json(att);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/security/attestation/verify', (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const envelope = body.envelope !== undefined ? body.envelope : body;
    const publicKeyPem = typeof body.publicKeyPem === 'string' && body.publicKeyPem.trim()
      ? body.publicKeyPem
      : undefined;
    const result = getSupplyChainAttestor().verifyAttestation(envelope, publicKeyPem);
    res.json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/projects/:id/migrations/plan', heavyOpLimiter, (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'deployments:write');
    if (!project) return;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const plan = getMigrationRunner().planMigration(project, body);
    res.json(plan);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/projects/:id/wasm/invoke', heavyOpLimiter, async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:write');
    if (!project) return;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const wasmRunner = getWasmMicroRunner();
    if (body.smokeTest === true) {
      const smokeArgs = Array.isArray(body.args)
        ? body.args
        : (body.arg !== undefined && Number.isFinite(Number(body.arg)) ? [Number(body.arg)] : [21]);
      const result = await wasmRunner.invoke({
        wasmBytes: wasmRunner.buildMinimalHttpTestWasm(),
        exportName: typeof body.exportName === 'string' && body.exportName.trim() ? body.exportName.trim() : 'handle',
        args: smokeArgs,
        input: body.input,
        timeoutMs: body.timeoutMs
      });
      return res.json({ ...result, smokeTest: true, projectId: project.id });
    }
    if (body.wasmPath && !project.localPath) {
      if (!assertHostLocalPathAllowed(req, res, project.teamId)) return;
    }
    const result = await wasmRunner.invokeProject(project, body);
    res.json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

// --- CYCLE #6 PIONEER LAZY ROUTES (Shadow Replay, Whole-Stack Time-Machine, FinOps Optimizer) ---

router.post('/projects/:id/shadow-replay', heavyOpLimiter, async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:write');
    if (!project) return;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const result = await getShadowReplayService().runReplay({
      ...body,
      projectId: project.id
    });
    res.json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/projects/:id/shadow-replay/history', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
    if (!project) return;
    const replays = getShadowReplayService().listReplays(project.id);
    res.json({ projectId: project.id, replays });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/projects/:id/timemachine', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
    if (!project) return;
    const checkpoints = getTimeMachineService().listCheckpoints(project.id);
    res.json({ projectId: project.id, checkpoints });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/projects/:id/timemachine', heavyOpLimiter, (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:write');
    if (!project) return;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const principal = getPrincipal(req);
    const checkpoint = getTimeMachineService().createCheckpoint(project.id, {
      actor: principal.email || principal.kind || 'operator',
      ...body
    });
    res.status(201).json(checkpoint);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/projects/:id/timemachine/diff', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
    if (!project) return;
    const fromId = String(req.query.from || '').trim();
    const toId = String(req.query.to || '').trim();
    if (!fromId || !toId) {
      return res.status(400).json({ error: 'Indica los parámetros query `from` y `to` para comparar checkpoints' });
    }
    const diff = getTimeMachineService().diffCheckpoints(project.id, fromId, toId);
    res.json(diff);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/projects/:id/timemachine/:checkpointId/restore', heavyOpLimiter, async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:write');
    if (!project) return;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const principal = getPrincipal(req);
    const dryRun = body.dryRun !== false;
    const result = await getTimeMachineService().restoreCheckpoint(project.id, req.params.checkpointId, {
      ...body,
      dryRun,
      actor: principal.email || principal.kind || 'operator'
    });
    res.json(result);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/finops/report', (req, res) => {
  try {
    const principal = getPrincipal(req);
    const allProjects = projectManager.getAll();
    const projects = principal.isSuperAdmin
      ? allProjects
      : getTeamManager().filterProjects(principal, allProjects, { redact: true });
    const allowedIds = new Set(projects.map((p) => p.id));
    const allDbs = databaseManager.list();
    const databases = principal.isSuperAdmin
      ? allDbs
      : allDbs.filter((d) => d.projectId && allowedIds.has(d.projectId));

    /** @type {any[]} */
    let metricsHistorySamples = [];
    try {
      const mh = getMetricsHistory();
      if (mh && typeof mh.getHistory === 'function') {
        const h = mh.getHistory({ limit: 60 });
        metricsHistorySamples = Array.isArray(h) ? h : (Array.isArray(h && h.samples) ? h.samples : []);
      }
    } catch (e) {}

    /** @type {any[]} */
    let sleepCandidates = [];
    try {
      const adv = getSleepAdvisor();
      if (adv && typeof adv.analyze === 'function') {
        const analysis = adv.analyze();
        if (analysis && Array.isArray(analysis.recommendations)) {
          sleepCandidates = principal.isSuperAdmin
            ? analysis.recommendations
            : analysis.recommendations.filter((r) => r && r.projectId && allowedIds.has(r.projectId));
        }
      }
    } catch (e) {}

    const report = getFinOpsOptimizer().analyzeFleetAndProjects({
      projects,
      databases,
      metricsHistory: metricsHistorySamples,
      sleepCandidates
    });
    res.json(report);
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.post('/finops/compare', (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const finops = getFinOpsOptimizer();
    const comparison = typeof finops.compareCloudCosts === 'function'
      ? finops.compareCloudCosts(body)
      : finops.analyzeFleetAndProjects(body);
    res.json(comparison);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

// --- CYCLE #7 PIONEER LAZY ROUTES (Terminal, WireGuard Fleet Mesh, Cron Heatmap/Heartbeats, Edge Shield, Build Healer) ---

router.post('/projects/:id/terminal/ticket', heavyOpLimiter, (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:write');
    if (!project) return;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const principal = getPrincipal(req);
    const depState = deployManager.getState(project.id);
    const defaultContainer = (depState && depState.current && depState.current.containerName)
      ? depState.current.containerName
      : `culkibo_${String(project.id).replace(/[^a-zA-Z0-9_.-]/g, '_')}`;
    const containerName = typeof body.containerName === 'string' && body.containerName.trim()
      ? body.containerName.trim()
      : defaultContainer;
    const ticket = getContainerTerminalService().issueTicket({
      projectId: project.id,
      containerName,
      userId: String(principal.userId || principal.kind || 'owner'),
      username: String(principal.email || principal.kind || 'operator'),
      shell: typeof body.shell === 'string' && body.shell.trim() ? body.shell.trim() : '/bin/sh',
      cols: body.cols !== undefined ? Number(body.cols) : 120,
      rows: body.rows !== undefined ? Number(body.rows) : 32
    });
    res.setHeader('Cache-Control', 'private, no-store');
    res.status(201).json(ticket);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/terminal/sessions', (req, res) => {
  try {
    const allowedIds = getAllowedProjectIds(req);
    const reqProjectId = req.query.projectId ? String(req.query.projectId).trim() : null;
    if (reqProjectId && allowedIds && !allowedIds.includes(reqProjectId)) {
      return res.status(404).json({ error: 'Proyecto no encontrado' });
    }
    const allSessions = getContainerTerminalService().listSessions(reqProjectId || undefined);
    const sessions = allowedIds
      ? allSessions.filter((s) => s && s.projectId && allowedIds.includes(s.projectId))
      : allSessions;
    res.json({ sessions });
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.get('/fleet/mesh', (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'consultar malla WireGuard de flota')) return;
    res.json(getFleetMeshService().getStatus());
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.post('/fleet/mesh/plan', certAndAdminLimiter, (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'planificar malla WireGuard de flota')) return;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const dryRun = body.dryRun !== false;
    res.json(getFleetMeshService().planMesh(Array.isArray(body.servers) ? body.servers : undefined, { dryRun }));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/fleet/mesh/rotate', certAndAdminLimiter, (req, res) => {
  try {
    if (denyInstanceGlobalForTenant(req, res, 'rotar clave WireGuard de flota')) return;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const nodeId = String(body.nodeId || 'local').trim();
    const dryRun = body.dryRun !== false;
    res.json(getFleetMeshService().rotatePeerKey(nodeId, { dryRun }));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/crons/timeline', (req, res) => {
  try {
    const allowedIds = getAllowedProjectIds(req);
    const hours = req.query.hours !== undefined ? Number(req.query.hours) : 24;
    const timeline = cronManager.getTimeline({ hours, projectIds: allowedIds });
    res.json(timeline);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.get('/heartbeats', (req, res) => {
  try {
    const allowedIds = getAllowedProjectIds(req);
    res.json({ heartbeats: cronManager.listHeartbeats({ projectIds: allowedIds }) });
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.post('/heartbeats', (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    if (body.projectId) {
      if (!assertProjectAccess(req, res, String(body.projectId), 'projects:write')) return;
    } else if (denyProjectScopedToken(req, res, 'crear heartbeat global')) {
      return;
    }
    const hb = cronManager.createHeartbeat(body);
    res.status(201).json(hb);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.delete('/heartbeats/:id', (req, res) => {
  try {
    const existing = cronManager.getHeartbeatById(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Heartbeat no encontrado' });
    if (existing.projectId) {
      if (!assertProjectAccess(req, res, existing.projectId, 'projects:write')) return;
    } else if (denyProjectScopedToken(req, res, 'eliminar heartbeat global')) {
      return;
    }
    res.json(cronManager.deleteHeartbeat(existing.id));
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

/** @param {any} req @param {any} res */
const handleRouterHeartbeatPing = (req, res) => {
  try {
    const state = req.params.state ? String(req.params.state) : 'ok';
    const message = (req.body && typeof req.body === 'object' && req.body.message)
      ? String(req.body.message)
      : (req.query && req.query.msg ? String(req.query.msg) : '');
    const result = cronManager.recordPing(req.params.token, { state, message });
    return res.status(result.status || (result.ok ? 200 : 404)).json(result);
  } catch (err) {
    sendServiceError(err, res, 500);
  }
};
router.get('/heartbeat/:token', handleRouterHeartbeatPing);
router.post('/heartbeat/:token', handleRouterHeartbeatPing);
router.get('/heartbeat/:token/:state', handleRouterHeartbeatPing);
router.post('/heartbeat/:token/:state', handleRouterHeartbeatPing);

router.get('/edge-shield/status', (req, res) => {
  try {
    if (denyProjectScopedToken(req, res, 'estado global de Edge Shield')) return;
    res.json(getEdgeShieldService().getStatus(domainManager.listDomains()));
  } catch (err) {
    sendServiceError(err, res, 500);
  }
});

router.get('/edge-shield/challenge', (req, res) => {
  try {
    const shield = getEdgeShieldService();
    const domain = String(req.query.domain || req.headers.host || 'localhost').trim().slice(0, 253);
    const difficulty = req.query.difficulty !== undefined ? Number(req.query.difficulty) : undefined;
    const challenge = shield.issueChallenge({
      ip: clientIp(req),
      userAgent: String(req.headers['user-agent'] || ''),
      domain,
      ...(Number.isFinite(difficulty) ? { difficulty } : {})
    });
    const wantsHtml = req.query.format === 'html'
      || (req.query.format !== 'json' && String(req.headers.accept || '').includes('text/html') && !String(req.headers.accept || '').includes('application/json'));
    if (wantsHtml && typeof shield.renderChallengeHtml === 'function') {
      const returnUrl = typeof req.query.returnUrl === 'string' && req.query.returnUrl.startsWith('/') ? req.query.returnUrl : '/';
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.status(200).send(shield.renderChallengeHtml(challenge, returnUrl));
    }
    res.json(challenge);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/edge-shield/verify', (req, res) => {
  try {
    const shield = getEdgeShieldService();
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const out = shield.verifySolution({
      ...body,
      ip: clientIp(req),
      userAgent: String(req.headers['user-agent'] || '')
    });
    if (out && out.valid && out.cookieHeader) {
      res.append('Set-Cookie', out.cookieHeader);
      return res.status(200).json(out);
    }
    res.status(403).json(out || { valid: false, reason: 'Invalid PoW solution' });
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/projects/:id/build-healer/diagnose', (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:read');
    if (!project) return;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    let logsText = typeof body.logs === 'string' ? body.logs : (typeof body.text === 'string' ? body.text : '');
    if (!logsText) {
      const recent = deployManager.listDeployments(project.id, 1);
      if (recent && recent[0] && Array.isArray(recent[0].logLines)) {
        logsText = recent[0].logLines.map((l) => l.message || '').join('\n');
      }
    }
    const diagnosis = getBuildHealerService().diagnoseLogs(logsText, { projectId: project.id, project });
    res.json(diagnosis);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

router.post('/projects/:id/build-healer/apply', heavyOpLimiter, async (req, res) => {
  try {
    const project = assertProjectAccess(req, res, req.params.id, 'projects:write');
    if (!project) return;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const dryRun = body.dryRun !== false;
    const out = await getBuildHealerService().applyHealingPlan(project.id, {
      logs: typeof body.logs === 'string' ? body.logs : (typeof body.text === 'string' ? body.text : ''),
      code: typeof body.code === 'string' ? body.code : undefined,
      dryRun
    });
    res.json(out);
  } catch (err) {
    sendServiceError(err, res, 400);
  }
});

module.exports = router;
