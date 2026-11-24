const os = require('os');
const path = require('path');
const { EventEmitter } = require('events');
const containerOrchestrator = require('./containerOrchestrator');
const domainManager = require('./domainManager');
const sslManager = require('./sslManager');
const cloudflareService = require('./cloudflareService');
const projectManager = require('./projectManager');
const dockerManager = require('./dockerManager');
const dbBackupManager = require('./dbBackupManager');
const githubService = require('./githubService');
const ingressManager = require('./ingressManager');
const caddyManager = require('./caddyManager');
const deployManager = require('./deployManager');
const databaseManager = require('./databaseManager');
const catalogManager = require('./catalogManager');
const liveSyncEngine = require('./liveSyncEngine');
const coolifyMigrator = require('./coolifyMigrator');
const wordpressMigrator = require('./wordpressMigrator');
const universalImporter = require('./universalImporter');
const metricsCollector = require('./metricsCollector');
const systemDoctor = require('./systemDoctor');
const notificationService = require('./notificationService');
const cronManager = require('./cronManager');
const previewManager = require('./previewManager');
const webhookService = require('./webhookService');

// Servicios v2 cargados estrictamente bajo demanda para preservar ~61 MB de RAM en reposo.
const ALLOWED_LAZY_SERVICES = new Set([
  'serverFleetManager',
  'teamManager',
  'environmentManager',
  'gitopsManager',
  'uptimeMonitor',
  'sleepAdvisor'
]);
/** @type {Map<string, any>} */
const _lazyServices = new Map();

/**
 * Carga diferida de servicios v2 con allowlist cerrada.
 * Si un servicio aún no existe en disco, devuelve `null` sin cachear el fallo.
 * @param {string} name
 * @returns {any}
 */
function lazySvc(name) {
  if (!ALLOWED_LAZY_SERVICES.has(name)) return null;
  if (_lazyServices.has(name)) return _lazyServices.get(name);
  const fullPath = path.join(__dirname, `${name}.js`);
  try {
    const mod = require(fullPath);
    _lazyServices.set(name, mod);
    return mod;
  } catch (err) {
    if (err && err.code === 'MODULE_NOT_FOUND') return null;
    throw err;
  }
}

const SENSITIVE_KEY_RE = /(token|password|passwd|secret|apikey|api_key|authorization|credential|connectionstring|envvars|passphrase|privatekey|private_key|sshkey|ssh_key|invitetoken|invite_token|tokenhash|token_hash|signingsecret|signing_secret|masterkey|master_key)/i;
const SENSITIVE_VALUE_RE = /(ghp_|gho_|github_pat_|sk_|bearer\s+|ck[stihp]_[A-Za-z0-9_-]{6,}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)/i;
const REDACTED_RESULT_TOOLS = new Set([
  'culkibo_database_credentials',
  'culkibo_github_connect',
  'culkibo_create_database',
  'culkibo_set_project_env',
  'culkibo_migrate_coolify',
  'culkibo_manage_webhook',
  'culkibo_set_domain_basic_auth',
  'culkibo_export_instance_snapshot',
  'culkibo_fleet_add_server',
  'culkibo_team_invite_member',
  'culkibo_rbac_manage_token'
]);

/** @type {Record<string, number>} */
const ROLE_RANK = Object.freeze({
  viewer: 10,
  developer: 20,
  admin: 30,
  owner: 40
});

/** Herramientas no destructivas que también soportan `dryRun: true` (25 destructivas + 2 = 27). */
const EXTRA_DRY_RUN_TOOLS = new Set([
  'culkibo_deploy_production',
  'culkibo_rollback_deployment'
]);

/**
 * Mapa paralelo de políticas RBAC para las 104 herramientas MCP (no se filtra al JSON Schema).
 * @type {Record<string, { minRole: 'viewer' | 'developer' | 'admin' | 'owner', scope: string, projectScoped?: boolean, secretSensitive?: boolean }>}
 */
const TOOL_POLICIES = Object.freeze({
  // Core 72
  culkibo_create_project: { minRole: 'developer', scope: 'projects:write', projectScoped: false },
  culkibo_add_resource: { minRole: 'developer', scope: 'projects:write', projectScoped: true },
  culkibo_list_projects: { minRole: 'viewer', scope: 'projects:read', projectScoped: false },
  culkibo_get_project: { minRole: 'viewer', scope: 'projects:read', projectScoped: true },
  culkibo_set_project_env: { minRole: 'developer', scope: 'projects:write', projectScoped: true, secretSensitive: true },
  culkibo_deploy_project: { minRole: 'developer', scope: 'deployments:write', projectScoped: true },
  culkibo_list_pods: { minRole: 'viewer', scope: 'pods:read', projectScoped: false },
  culkibo_hot_sync: { minRole: 'developer', scope: 'sync:write', projectScoped: false },
  culkibo_switch_traffic: { minRole: 'admin', scope: 'ingress:write', projectScoped: false },
  culkibo_manage_domain: { minRole: 'admin', scope: 'domains:write', projectScoped: true },
  culkibo_inspect_ingress: { minRole: 'viewer', scope: 'ingress:read', projectScoped: false },
  culkibo_manage_watcher: { minRole: 'admin', scope: 'system:write', projectScoped: false },
  culkibo_issue_wildcard_ssl: { minRole: 'viewer', scope: 'ssl:read', projectScoped: false },
  culkibo_create_sslip_domain: { minRole: 'admin', scope: 'domains:write', projectScoped: false },
  culkibo_get_logs: { minRole: 'viewer', scope: 'logs:read', projectScoped: false },
  culkibo_docker_status: { minRole: 'viewer', scope: 'docker:read', projectScoped: false },
  culkibo_docker_containers: { minRole: 'viewer', scope: 'docker:read', projectScoped: false },
  culkibo_export_backup: { minRole: 'admin', scope: 'backups:write', projectScoped: true, secretSensitive: true },
  culkibo_restore_backup: { minRole: 'admin', scope: 'backups:write', projectScoped: false },
  culkibo_github_status: { minRole: 'viewer', scope: 'github:read', projectScoped: false },
  culkibo_github_connect: { minRole: 'admin', scope: 'github:write', projectScoped: false, secretSensitive: true },
  culkibo_github_disconnect: { minRole: 'admin', scope: 'github:write', projectScoped: false },
  culkibo_github_list_repos: { minRole: 'viewer', scope: 'github:read', projectScoped: false },
  culkibo_github_get_branches: { minRole: 'viewer', scope: 'github:read', projectScoped: false },
  culkibo_github_auto_detect: { minRole: 'viewer', scope: 'github:read', projectScoped: false },
  culkibo_create_project_from_github: { minRole: 'developer', scope: 'projects:write', projectScoped: false },
  culkibo_deploy_strategy: { minRole: 'viewer', scope: 'deployments:read', projectScoped: true },
  culkibo_deploy_production: { minRole: 'developer', scope: 'deployments:write', projectScoped: true },
  culkibo_list_deployments: { minRole: 'viewer', scope: 'deployments:read', projectScoped: true },
  culkibo_rollback_deployment: { minRole: 'developer', scope: 'deployments:write', projectScoped: true },
  culkibo_prune_build_cache: { minRole: 'admin', scope: 'docker:write', projectScoped: false },
  culkibo_list_databases: { minRole: 'viewer', scope: 'databases:read', projectScoped: false },
  culkibo_create_database: { minRole: 'developer', scope: 'databases:write', projectScoped: true, secretSensitive: true },
  culkibo_database_backup: { minRole: 'developer', scope: 'databases:write', projectScoped: true },
  culkibo_database_credentials: { minRole: 'developer', scope: 'databases:credentials', projectScoped: true, secretSensitive: true },
  culkibo_delete_database: { minRole: 'admin', scope: 'databases:write', projectScoped: true },
  culkibo_list_catalog_templates: { minRole: 'viewer', scope: 'catalog:read', projectScoped: false },
  culkibo_install_catalog_service: { minRole: 'admin', scope: 'catalog:write', projectScoped: false },
  culkibo_list_catalog_installations: { minRole: 'viewer', scope: 'catalog:read', projectScoped: false },
  culkibo_uninstall_catalog_service: { minRole: 'admin', scope: 'catalog:write', projectScoped: true },
  culkibo_verify_sync: { minRole: 'viewer', scope: 'sync:read', projectScoped: true },
  culkibo_rollback_sync: { minRole: 'developer', scope: 'sync:write', projectScoped: true },
  culkibo_promote_forge: { minRole: 'developer', scope: 'deployments:write', projectScoped: true },
  culkibo_migrate_coolify: { minRole: 'admin', scope: 'migrations:write', projectScoped: false, secretSensitive: true },
  culkibo_analyze_wordpress: { minRole: 'viewer', scope: 'migrations:read', projectScoped: false },
  culkibo_import_compose: { minRole: 'developer', scope: 'projects:write', projectScoped: false },
  culkibo_get_remote_access: { minRole: 'viewer', scope: 'system:read', projectScoped: false },
  culkibo_get_observability: { minRole: 'viewer', scope: 'observability:read', projectScoped: false },
  culkibo_system_doctor: { minRole: 'viewer', scope: 'system:read', projectScoped: false },
  culkibo_link_database: { minRole: 'developer', scope: 'databases:write', projectScoped: true },
  culkibo_toggle_maintenance: { minRole: 'developer', scope: 'deployments:write', projectScoped: true },
  culkibo_get_deploy_queue: { minRole: 'viewer', scope: 'deployments:read', projectScoped: false },
  culkibo_get_container_logs: { minRole: 'viewer', scope: 'logs:read', projectScoped: true },
  culkibo_get_deployment_logs: { minRole: 'viewer', scope: 'logs:read', projectScoped: true },
  culkibo_cancel_deployment: { minRole: 'developer', scope: 'deployments:write', projectScoped: true },
  culkibo_diagnose_domain: { minRole: 'viewer', scope: 'domains:read', projectScoped: false },
  culkibo_ingress_status: { minRole: 'viewer', scope: 'ingress:read', projectScoped: false },
  culkibo_reconcile_ingress: { minRole: 'admin', scope: 'ingress:write', projectScoped: false },
  culkibo_manage_production_service: { minRole: 'developer', scope: 'deployments:write', projectScoped: true },
  culkibo_system_doctor_fix: { minRole: 'admin', scope: 'system:write', projectScoped: false },
  culkibo_database_schedule: { minRole: 'developer', scope: 'databases:write', projectScoped: true },
  culkibo_database_restore: { minRole: 'admin', scope: 'databases:write', projectScoped: true },
  culkibo_database_list_backups: { minRole: 'viewer', scope: 'databases:read', projectScoped: true },
  culkibo_database_inspect: { minRole: 'viewer', scope: 'databases:read', projectScoped: true },
  culkibo_list_backups: { minRole: 'viewer', scope: 'backups:read', projectScoped: false },
  culkibo_export_instance_snapshot: { minRole: 'admin', scope: 'backups:write', projectScoped: false, secretSensitive: true },
  culkibo_manage_wildcard_dns01: { minRole: 'admin', scope: 'ssl:write', projectScoped: false },
  culkibo_set_domain_basic_auth: { minRole: 'admin', scope: 'domains:write', projectScoped: true, secretSensitive: true },
  culkibo_notifications: { minRole: 'admin', scope: 'notifications:write', projectScoped: false },
  culkibo_manage_webhook: { minRole: 'developer', scope: 'webhooks:write', projectScoped: true, secretSensitive: true },
  culkibo_manage_crons: { minRole: 'developer', scope: 'crons:write', projectScoped: true },
  culkibo_manage_previews: { minRole: 'developer', scope: 'previews:write', projectScoped: true },
  // MCP 2.0 (+32 = 104)
  culkibo_fleet_list_servers: { minRole: 'viewer', scope: 'fleet:read', projectScoped: false },
  culkibo_fleet_add_server: { minRole: 'admin', scope: 'fleet:write', projectScoped: false, secretSensitive: true },
  culkibo_fleet_probe_server: { minRole: 'viewer', scope: 'fleet:read', projectScoped: false },
  culkibo_fleet_remove_server: { minRole: 'admin', scope: 'fleet:write', projectScoped: false },
  culkibo_fleet_assign_project: { minRole: 'admin', scope: 'fleet:write', projectScoped: true },
  culkibo_rbac_whoami: { minRole: 'viewer', scope: 'rbac:read', projectScoped: false },
  culkibo_team_list_members: { minRole: 'viewer', scope: 'teams:read', projectScoped: false },
  culkibo_team_invite_member: { minRole: 'admin', scope: 'teams:write', projectScoped: false, secretSensitive: true },
  culkibo_team_update_member: { minRole: 'admin', scope: 'teams:write', projectScoped: false },
  culkibo_rbac_list_tokens: { minRole: 'admin', scope: 'tokens:read', projectScoped: false },
  culkibo_rbac_manage_token: { minRole: 'admin', scope: 'tokens:write', projectScoped: false, secretSensitive: true },
  culkibo_env_list: { minRole: 'viewer', scope: 'environments:read', projectScoped: true },
  culkibo_env_create: { minRole: 'developer', scope: 'environments:write', projectScoped: true },
  culkibo_env_diff: { minRole: 'viewer', scope: 'environments:read', projectScoped: true },
  culkibo_env_promote: { minRole: 'developer', scope: 'environments:promote', projectScoped: true },
  culkibo_uptime_list_monitors: { minRole: 'viewer', scope: 'uptime:read', projectScoped: false },
  culkibo_uptime_upsert_monitor: { minRole: 'developer', scope: 'uptime:write', projectScoped: true },
  culkibo_uptime_delete_monitor: { minRole: 'developer', scope: 'uptime:write', projectScoped: true },
  culkibo_status_page_manage: { minRole: 'admin', scope: 'statuspage:write', projectScoped: false },
  culkibo_gitops_export: { minRole: 'viewer', scope: 'gitops:read', projectScoped: true },
  culkibo_gitops_plan: { minRole: 'viewer', scope: 'gitops:read', projectScoped: false },
  culkibo_gitops_apply: { minRole: 'admin', scope: 'gitops:write', projectScoped: false },
  culkibo_cost_advisor: { minRole: 'viewer', scope: 'advisor:read', projectScoped: false },
  culkibo_sleep_status: { minRole: 'viewer', scope: 'sleep:read', projectScoped: true },
  culkibo_sleep_manage: { minRole: 'developer', scope: 'sleep:write', projectScoped: true },
  culkibo_sync_file_history: { minRole: 'viewer', scope: 'sync:read', projectScoped: true },
  culkibo_sync_rollback_file: { minRole: 'developer', scope: 'sync:write', projectScoped: true },
  culkibo_sync_conflicts: { minRole: 'viewer', scope: 'sync:read', projectScoped: true },
  culkibo_smoke_test_configure: { minRole: 'developer', scope: 'deployments:write', projectScoped: true },
  culkibo_smoke_test_run: { minRole: 'viewer', scope: 'deployments:read', projectScoped: true },
  culkibo_canary_rollout: { minRole: 'developer', scope: 'deployments:write', projectScoped: true },
  culkibo_deploy_freeze: { minRole: 'admin', scope: 'deployments:freeze', projectScoped: true }
});

/**
 * Normaliza `req.auth`, un principal directo o ausencia de contexto (legacy/loopback)
 * en un principal RBAC canónico. Sin `context.auth` mantiene compatibilidad 100% owner.
 * @param {any} authOrPrincipal
 */
function normalizePrincipal(authOrPrincipal) {
  if (!authOrPrincipal || typeof authOrPrincipal !== 'object') {
    return {
      method: 'legacy',
      kind: 'master',
      userId: null,
      email: null,
      role: 'owner',
      teamId: null,
      sessionId: null,
      tokenId: null,
      tokenVersion: null,
      projectIds: null,
      scopes: ['*'],
      isSuperAdmin: true,
      isScoped: false
    };
  }
  // Fail-closed: un resultado de autenticación rechazado (`{ ok: false }`) NUNCA puede escalar a superadmin.
  if (authOrPrincipal.ok === false) {
    return {
      method: 'unauthenticated',
      kind: 'denied',
      userId: null,
      email: null,
      role: 'none',
      teamId: null,
      sessionId: null,
      tokenId: null,
      tokenVersion: null,
      projectIds: [],
      scopes: [],
      isSuperAdmin: false,
      isScoped: true
    };
  }
  const hasNested = Boolean(authOrPrincipal.principal && typeof authOrPrincipal.principal === 'object');
  const raw = hasNested ? authOrPrincipal.principal : authOrPrincipal;
  const method = String(authOrPrincipal.method || raw.method || raw.kind || 'legacy');

  const isLegacyEnvelope = authOrPrincipal.ok === true && !hasNested && !raw.role && !raw.userId && !raw.id && !raw.kind && !raw.scopes && !raw.projectIds &&
    (method === 'token' || method === 'loopback' || method === 'loopback_origin' || method === 'ws_ticket');

  const projectIds = Array.isArray(raw.projectIds)
    ? raw.projectIds.map(String)
    : null;
  const scopes = Array.isArray(raw.scopes)
    ? raw.scopes.map(String)
    : ['*'];
  const hasProjectRestriction = projectIds !== null;
  const hasScopeRestriction = !scopes.includes('*');

  if (isLegacyEnvelope) {
    return {
      method,
      kind: 'master',
      userId: null,
      email: null,
      role: 'owner',
      teamId: null,
      sessionId: null,
      tokenId: null,
      tokenVersion: null,
      projectIds: null,
      scopes: ['*'],
      isSuperAdmin: true,
      isScoped: false
    };
  }

  const rawRole = String(raw.role || (raw.isSuperAdmin ? 'owner' : 'viewer')).toLowerCase();
  const role = ROLE_RANK[rawRole] ? rawRole : 'viewer';
  const isSuperAdmin = (raw.isSuperAdmin === true || (role === 'owner' && !raw.teamId && method !== 'api_token')) &&
    !hasProjectRestriction && !hasScopeRestriction;

  return {
    method,
    kind: raw.kind ? String(raw.kind) : (method === 'api_token' ? 'api_token' : 'session'),
    userId: raw.userId || raw.id || null,
    email: raw.email || null,
    role,
    teamId: raw.teamId ? String(raw.teamId) : null,
    sessionId: raw.sessionId || null,
    tokenId: raw.tokenId || null,
    tokenVersion: raw.tokenVersion ?? null,
    projectIds,
    scopes,
    isSuperAdmin,
    isScoped: !isSuperAdmin || hasProjectRestriction || hasScopeRestriction
  };
}

/**
 * Comprueba si los scopes del token autorizan un scope de herramienta concreto.
 * No existe comodín `mcp:write`: toda escritura exige el scope de dominio explícito o `*`.
 * @param {string[]} scopes
 * @param {string} requiredScope
 * @param {string} toolName
 * @param {boolean} secretSensitive
 */
function scopeMatches(scopes, requiredScope, toolName, secretSensitive) {
  if (!Array.isArray(scopes) || scopes.length === 0) return false;
  if (scopes.includes('*')) return true;
  if (scopes.includes(requiredScope) || scopes.includes(toolName)) return true;
  const [domain, action] = String(requiredScope || '').split(':');
  if (!secretSensitive && domain && scopes.includes(`${domain}:*`)) return true;
  if (!secretSensitive && action === 'read' && (scopes.includes('*:read') || scopes.includes('mcp:read') || scopes.includes('read'))) {
    return true;
  }
  return false;
}

/**
 * Evalúa si una herramienta concreta es visible/ejecutable por `principal`.
 * @param {ReturnType<typeof normalizePrincipal>} principal
 * @param {string} toolName
 * @param {any} [toolObj]
 */
function isToolAllowedForPrincipal(principal, toolName, toolObj = null) {
  if (principal.isSuperAdmin) return true;
  const policy = TOOL_POLICIES[toolName];
  if (!policy) return false;
  const callerRank = ROLE_RANK[principal.role] || 0;
  const minRank = ROLE_RANK[policy.minRole] || ROLE_RANK.owner;
  if (callerRank < minRank) return false;
  // Un token acotado a proyectos concretos no puede ver ni invocar mutaciones globales.
  if (Array.isArray(principal.projectIds) && !policy.projectScoped && toolObj && !toolObj.annotations?.readOnlyHint) {
    return false;
  }
  return scopeMatches(principal.scopes, policy.scope, toolName, Boolean(policy.secretSensitive));
}

/**
 * Resuelve el rol efectivo del principal sobre un proyecto concreto, integrando
 * los overrides per-project ACL de `teamManager` (`none` o degradación a `viewer`)
 * cuando el modo multi-usuario está activo.
 * @param {ReturnType<typeof normalizePrincipal>} principal
 * @param {string | null | undefined} projectId
 * @param {any} [projectObj]
 * @returns {string | null}
 */
function resolveEffectiveProjectRole(principal, projectId, projectObj = null) {
  if (principal.isSuperAdmin) return 'owner';
  if (!projectId) {
    return Array.isArray(principal.projectIds) ? null : principal.role;
  }
  if (Array.isArray(principal.projectIds) && !principal.projectIds.includes(String(projectId))) {
    return null;
  }
  const proj = projectObj || projectManager.getById(String(projectId));
  if (principal.teamId) {
    if (!proj) return null;
    const projTeam = proj.teamId || 'team_default';
    if (projTeam !== principal.teamId) return null;
  }
  if (principal.userId) {
    const tm = lazySvc('teamManager');
    if (tm && typeof tm.isMultiUserEnabled === 'function' && tm.isMultiUserEnabled() && typeof tm.resolveProjectRole === 'function') {
      const resolved = tm.resolveProjectRole(principal, proj || String(projectId));
      return resolved ? String(resolved).toLowerCase() : null;
    }
  }
  return principal.role;
}

/**
 * Evalúa si `principal` tiene acceso al proyecto `projectId` (ACL explícito + teamId + overrides per-project).
 * Un token acotado a `projectIds` concretos no puede acceder a recursos globales (`projectId == null`).
 * @param {ReturnType<typeof normalizePrincipal>} principal
 * @param {string | null | undefined} projectId
 * @param {any} [projectObj]
 */
function canAccessProject(principal, projectId, projectObj = null) {
  return resolveEffectiveProjectRole(principal, projectId, projectObj) !== null;
}

/** Sanea un registro de servidor de flota para no exponer jamás claves privadas ni líneas raw. */
function sanitizeFleetServer(server) {
  if (!server || typeof server !== 'object') return server;
  const {
    privateKey: _pk,
    privateKeyEnc: _pke,
    privateKeyPem: _pkp,
    hostKeyLine: _hkl,
    ...rest
  } = server;
  return rest;
}

/** Sanea un objeto de entorno para exponer claves y metadatos sin secretos en claro. */
function sanitizeEnvObject(env) {
  if (!env || typeof env !== 'object') return env;
  const { envVars, encryptedEnvVars: _enc, ...rest } = env;
  const keys = envVars && typeof envVars === 'object' ? Object.keys(envVars) : (Array.isArray(env.envVarKeys) ? env.envVarKeys : []);
  return { ...rest, envVarKeys: keys };
}

/** Valida rutas de smoke checks (sin URLs completas, sin traversal, sin CRLF/nulos). */
function sanitizeSmokeChecks(checks) {
  if (!Array.isArray(checks) || checks.length === 0 || checks.length > 10) {
    throw new McpToolError('INVALID_ARGUMENT', 'checks debe ser un array de entre 1 y 10 comprobaciones smoke.', {
      retryable: true,
      remediation: 'Pasa entre 1 y 10 objetos { path: "/health", expectedStatus: 200 }.'
    });
  }
  return checks.map((c, idx) => {
    if (!c || typeof c !== 'object') {
      throw new McpToolError('INVALID_ARGUMENT', `Smoke check #${idx + 1} debe ser un objeto.`, { retryable: true });
    }
    const rawPath = String(c.path || '/').trim();
    if (!rawPath.startsWith('/') || rawPath.length > 512 || /\.\.|[\s\r\n\0]/.test(rawPath)) {
      throw new McpToolError('INVALID_ARGUMENT', `Ruta smoke inválida en check #${idx + 1}: '${rawPath}'.`, {
        retryable: true,
        remediation: 'Usa una ruta relativa empezando por "/" (sin URLs completas, ".." ni saltos de línea).'
      });
    }
    const method = String(c.method || 'GET').toUpperCase();
    if (!['GET', 'HEAD', 'POST'].includes(method)) {
      throw new McpToolError('INVALID_ARGUMENT', `Método HTTP no permitido en smoke check #${idx + 1}: '${method}'.`, { retryable: true });
    }
    return {
      name: c.name ? String(c.name).slice(0, 64) : `check-${idx + 1}`,
      method,
      path: rawPath,
      expectedStatus: c.expectedStatus ?? c.expectStatus ?? 200,
      ...(c.bodyContains || c.expectBodyContains ? { bodyContains: String(c.bodyContains || c.expectBodyContains).slice(0, 256) } : {}),
      ...(c.maxLatencyMs !== undefined ? { maxLatencyMs: Math.min(30000, Math.max(50, Number(c.maxLatencyMs) || 5000)) } : {})
    };
  });
}

/** Consulta el evaluador de ventanas de freeze en deployManager si está disponible. */
function evaluateProjectFreeze(project) {
  try {
    if (typeof deployManager.evaluateFreezeStatus === 'function') {
      return deployManager.evaluateFreezeStatus(project);
    }
    if (typeof deployManager.isInFreezeWindow === 'function') {
      const res = deployManager.isInFreezeWindow(project);
      if (typeof res === 'boolean') return { frozen: res, activeWindow: null };
      return res || { frozen: false, activeWindow: null };
    }
  } catch (e) {}
  return { frozen: false, activeWindow: null };
}

/** Enmascara secretos de proyecto (envVars, buildArgs, webhookSecret, deployHookToken, credenciales de recursos) antes de exponerlos por MCP. */
function redactProjectSecrets(project) {
  if (!project || typeof project !== 'object') return project;
  const maskMap = (obj) => {
    if (!obj || typeof obj !== 'object') return {};
    /** @type {Record<string, string>} */
    const out = {};
    for (const k of Object.keys(obj)) out[k] = '[oculto]';
    return out;
  };
  return {
    ...project,
    webhookSecret: project.webhookSecret ? '[oculto]' : undefined,
    deployHookToken: project.deployHookToken ? '[oculto]' : undefined,
    envVars: maskMap(project.envVars),
    envVarsKeys: Object.keys(project.envVars || {}),
    buildArgs: maskMap(project.buildArgs),
    buildArgsKeys: Object.keys(project.buildArgs || {}),
    resources: Array.isArray(project.resources)
      ? project.resources.map((r) => {
          if (!r || typeof r !== 'object') return r;
          const { rawMeta: _dropRawMeta, ...rest } = r;
          return {
            ...rest,
            envVars: r.envVars ? maskMap(r.envVars) : undefined,
            previewEnvVars: r.previewEnvVars ? maskMap(r.previewEnvVars) : undefined,
            credentials: r.credentials ? maskMap(r.credentials) : undefined
          };
        })
      : []
  };
}

/** Redacta recursivamente tokens, contraseñas y secretos antes de guardar o emitir auditoría MCP. */
function redactForAudit(value, depth = 0) {
  if (depth > 5) return '[…]';
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') {
    if (SENSITIVE_VALUE_RE.test(value)) return '***';
    return value.length > 240 ? `${value.slice(0, 240)}…` : value;
  }
  if (typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.slice(0, 25).map(v => redactForAudit(v, depth + 1));
  /** @type {Record<string, any>} */
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (SENSITIVE_KEY_RE.test(k)) {
      out[k] = typeof v === 'object' && v !== null ? '[oculto]' : '***';
    } else {
      out[k] = redactForAudit(v, depth + 1);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Revisiones del protocolo.
//
// 2026-07-28 eliminó el handshake `initialize`: ya no hay negociación por
// conexión, cada petición declara su propia versión en
// `_meta["io.modelcontextprotocol/protocolVersion"]` y, sobre HTTP, también en
// la cabecera `MCP-Protocol-Version`. Por eso el servidor valida por petición
// y no guarda estado de sesión.
//
// `LEGACY_PROTOCOL_VERSION` es la era anterior (handshake `initialize`), que
// seguimos sirviendo en /api/mcp/message y /api/mcp/sse para no romper las
// configuraciones de Cursor y Claude Desktop ya instaladas. Está deprecada.
// ---------------------------------------------------------------------------
const PROTOCOL_VERSION = '2026-07-28';
const SUPPORTED_PROTOCOL_VERSIONS = [PROTOCOL_VERSION];
const LEGACY_PROTOCOL_VERSION = '2024-11-05';

const META_PROTOCOL_VERSION = 'io.modelcontextprotocol/protocolVersion';
const META_CLIENT_INFO = 'io.modelcontextprotocol/clientInfo';
const META_CLIENT_CAPABILITIES = 'io.modelcontextprotocol/clientCapabilities';
const META_SERVER_INFO = 'io.modelcontextprotocol/serverInfo';

// Prefijo propio para metadatos que no define la especificación. La segunda
// etiqueta no puede ser `mcp` ni `modelcontextprotocol`: esas están reservadas.
const META_CULKIBO_ERROR = 'dev.culkibo/error';

const SERVER_INFO = { name: 'culkibo-mcp-orchestrator', version: '1.0.0' };

// -32020..-32099 es el rango que la especificación se reserva. Solo se emiten
// los códigos que ella define, y solo con su significado.
const ERROR_CODES = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  HEADER_MISMATCH: -32020,
  MISSING_REQUIRED_CLIENT_CAPABILITY: -32021,
  UNSUPPORTED_PROTOCOL_VERSION: -32022
};

// Métodos que sirve el transporte moderno. Cualquier otro es 404 + -32601.
const MODERN_METHODS = [
  'ping',
  'server/discover',
  'tools/list',
  'tools/call',
  'resources/list',
  'resources/read',
  'prompts/list',
  'prompts/get'
];

// Métodos que obligan a enviar la cabecera `Mcp-Name`.
const NAME_BEARING_METHODS = ['tools/call', 'resources/read', 'prompts/get'];

/**
 * Error de ejecución de herramienta con forma accionable.
 *
 * El cliente primario de Culkibo es un agente, no una persona leyendo un log.
 * Un `Error` pelado le obliga a adivinar del texto si puede reintentar o si
 * debe cambiar de argumentos; este lleva el código estable, si es reintentable
 * y qué hacer a continuación.
 */
class McpToolError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {{ retryable?: boolean, remediation?: string | null, details?: Record<string, any> }} [opts]
   */
  constructor(code, message, { retryable = false, remediation = null, details = {} } = {}) {
    super(message);
    this.name = 'McpToolError';
    this.code = code;
    this.retryable = retryable;
    this.remediation = remediation;
    this.details = details;
  }
}

function jsonType(value) {
  if (Array.isArray(value)) return 'array';
  if (value === null) return 'null';
  if (Number.isInteger(value)) return 'integer';
  return typeof value;
}

function matchesSchemaType(value, expected) {
  switch (expected) {
    case 'string': return typeof value === 'string';
    case 'number': return typeof value === 'number' && Number.isFinite(value);
    case 'integer': return Number.isInteger(value);
    case 'boolean': return typeof value === 'boolean';
    case 'array': return Array.isArray(value);
    case 'object': return value !== null && typeof value === 'object' && !Array.isArray(value);
    default: return true;
  }
}

/**
 * Validación de argumentos contra el `inputSchema` declarado.
 *
 * Se hace aquí y no en cada `case` porque el fallo de un agente casi siempre es
 * el mismo —falta un campo obligatorio o mete un valor fuera del enum— y ese
 * fallo se corrige solo si la respuesta dice exactamente qué falta. Antes se
 * colaba hasta el servicio y volvía como un `TypeError` ilegible.
 */
function validateToolArguments(tool, args) {
  const schema = tool.inputSchema || {};
  const properties = schema.properties || {};
  const required = Array.isArray(schema.required) ? schema.required : [];

  const missing = required.filter((key) => {
    const val = args[key];
    if (val === undefined || val === null) return true;
    const spec = properties[key];
    if (spec && spec.type === 'string' && typeof val === 'string' && val.trim() === '') return true;
    return false;
  });
  if (missing.length > 0) {
    throw new McpToolError(
      'MISSING_ARGUMENT',
      `Faltan argumentos obligatorios en ${tool.name}: ${missing.join(', ')}.`,
      {
        retryable: true,
        remediation: `Repite la llamada incluyendo ${missing.join(', ')}.`,
        details: { missing, required, received: Object.keys(args) }
      }
    );
  }

  for (const [key, value] of Object.entries(args)) {
    const spec = properties[key];
    if (!spec || value === undefined || value === null) continue;

    if (Array.isArray(spec.enum) && !spec.enum.includes(value)) {
      throw new McpToolError(
        'INVALID_ARGUMENT',
        `El argumento '${key}' de ${tool.name} no admite el valor ${JSON.stringify(value)}.`,
        {
          retryable: true,
          remediation: `Usa uno de estos valores para '${key}': ${spec.enum.join(', ')}.`,
          details: { argument: key, received: value, allowed: spec.enum }
        }
      );
    }

    if (spec.type && !matchesSchemaType(value, spec.type)) {
      throw new McpToolError(
        'INVALID_ARGUMENT',
        `El argumento '${key}' de ${tool.name} debe ser de tipo ${spec.type}.`,
        {
          retryable: true,
          remediation: `Convierte '${key}' a ${spec.type} y vuelve a llamar.`,
          details: { argument: key, expectedType: spec.type, receivedType: jsonType(value) }
        }
      );
    }
  }
}

// Fallos de «no existe». Un agente los resuelve solo si la respuesta le dice
// con qué herramienta obtener el identificador bueno, así que siempre lo dice.
function projectNotFoundError(projectId) {
  return new McpToolError('PROJECT_NOT_FOUND', `No existe ningún proyecto con el identificador '${projectId}'.`, {
    retryable: false,
    remediation: 'Llama a culkibo_list_projects y usa el campo id de uno de los proyectos devueltos.',
    details: { projectId: projectId ?? null }
  });
}

function resourceNotFoundError(projectId, resourceId) {
  return new McpToolError('RESOURCE_NOT_FOUND', `El proyecto '${projectId}' no tiene ningún recurso llamado '${resourceId}'.`, {
    retryable: false,
    remediation: 'Llama a culkibo_get_project y usa el id o el name de uno de los recursos listados.',
    details: { projectId: projectId ?? null, resourceId: resourceId ?? null }
  });
}

function domainNotFoundError({ hostname, id }) {
  return new McpToolError('DOMAIN_NOT_FOUND', `No hay ningún dominio configurado que coincida con '${hostname || id}'.`, {
    retryable: false,
    remediation: 'Llama a culkibo_manage_domain con action "list" para ver los dominios registrados y sus id.',
    details: { hostname: hostname ?? null, id: id ?? null }
  });
}

/**
 * Exige un servicio v2 cargado bajo demanda; si aún no existe en disco,
 * devuelve un McpToolError estructurado y reintentable en lugar de fallar en frío.
 * @param {string} name
 * @param {string} featureLabel
 */
function requireLazySvc(name, featureLabel) {
  const svc = lazySvc(name);
  if (!svc) {
    throw new McpToolError(
      'SERVICE_UNAVAILABLE',
      `El servicio '${name}' (${featureLabel}) no está disponible todavía en esta instancia.`,
      {
        retryable: true,
        remediation: `Verifica que server/services/${name}.js esté cargado y comprueba el estado con culkibo_system_doctor.`,
        details: { service: name }
      }
    );
  }
  return svc;
}

class McpServer extends EventEmitter {
  constructor() {
    super();
    this.auditLog = [];
    this.maxAuditLogs = 500;
    /** @type {any[] | null} */
    this._toolsCache = null;
    /** @type {Map<string, any> | null} */
    this._toolsByName = null;
    /** @type {Buffer | null} */
    this._toolsSerializedCache = null;
    /** @type {any | null} */
    this._discoverCache = null;
  }

  getToolsDefinition() {
    if (this._toolsCache) return this._toolsCache;
    this._toolsCache = [
      {
        name: 'culkibo_create_project',
        title: 'Crear proyecto',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        description: 'Permite a la IA crear un nuevo proyecto (nombre, descripción, icono, gitRepo, puertos, etc.).',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            description: { type: 'string' },
            icon: { type: 'string' },
            gitRepo: { type: 'string' },
            forgePort: { type: 'number' },
            citadelPort: { type: 'number' }
          },
          required: ['name']
        }
      },
      {
        name: 'culkibo_add_resource',
        title: 'Añadir recurso a un proyecto',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        description: 'Permite a la IA añadir un recurso a un proyecto (tipo: app, database, service).',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string' },
            type: { type: 'string', enum: ['app', 'database', 'service'] },
            name: { type: 'string' },
            image: { type: 'string' },
            envVars: { type: 'object' },
            ports: { type: 'array', items: { type: 'string' } },
            credentials: { type: 'object' }
          },
          required: ['projectId', 'type', 'name']
        }
      },
      {
        name: 'culkibo_list_projects',
        title: 'Listar proyectos',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            projects: { type: 'array', description: 'Proyectos con sus recursos y estado.' }
          }
        },
        description: 'Lista todos los proyectos con sus recursos y estados.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'culkibo_get_project',
        title: 'Ver un proyecto',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Obtiene los detalles completos de un proyecto.',
        inputSchema: {
          type: 'object',
          properties: { projectId: { type: 'string' } },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_set_project_env',
        title: 'Inyectar variables de entorno',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Permite a la IA inyectar o actualizar variables de entorno de un proyecto o recurso específico.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string' },
            resourceId: { type: 'string', description: 'Opcional. ID o nombre del recurso específico (app, database, service) para inyectar variables de entorno.' },
            envVars: { type: 'object' }
          },
          required: ['projectId', 'envVars']
        }
      },
      {
        name: 'culkibo_deploy_project',
        title: 'Desplegar proyecto',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
        description: 'Despliega o publica un proyecto.',
        inputSchema: {
          type: 'object',
          properties: { projectId: { type: 'string' } },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_list_pods',
        title: 'Estado de los pods',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            pods: { type: 'object', description: 'Estado de The Forge y The Citadel.' },
            trafficAllocation: { type: 'object', description: 'Reparto de tráfico en porcentaje.' },
            totalRequestsServed: { type: 'number' },
            activeConnections: { type: 'number' },
            daemon: { type: 'object' },
            localProcesses: { type: 'object' }
          }
        },
        description: 'Inspect live status, metrics (CPU, RAM, latency), and traffic split between The Forge (hot-pod) and The Citadel (production).',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      },
      {
        name: 'culkibo_hot_sync',
        title: 'Registrar cambio en The Forge',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        description: 'Register a code change against The Forge. NOTE: detection and classification only — the change is not yet transported to or applied on the pod. Returns applied:false.',
        inputSchema: {
          type: 'object',
          properties: {
            changedFile: { type: 'string', description: 'Relative path of the modified file (e.g. src/app.ts)' },
            diffSize: { type: 'string', description: 'Brief description of changes (e.g. 12 lines added)' }
          }
        }
      },
      {
        name: 'culkibo_switch_traffic',
        title: 'Repartir tráfico entre Forge y Citadel',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Instantly re-route incoming traffic between The Forge (dev) and The Citadel (prod).',
        inputSchema: {
          type: 'object',
          properties: {
            forgePercent: { type: 'number', description: 'Percentage of traffic to The Forge (0-100)' },
            citadelPercent: { type: 'number', description: 'Percentage of traffic to The Citadel (0-100)' }
          },
          required: ['citadelPercent']
        }
      },
      {
        name: 'culkibo_manage_domain',
        title: 'Gestionar dominios',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
        description: 'Add or configure custom domain, wildcard domain, or Cloudflare edge routing.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['add', 'delete', 'list', 'toggle_proxy', 'update'], description: 'Action to perform' },
            hostname: { type: 'string', description: 'Domain name (e.g. api.domain.com or *.domain.com)' },
            id: { type: 'string', description: 'Domain ID' },
            targetPod: { type: 'string', enum: ['forge', 'citadel'], description: 'Target pod to route traffic to' },
            cloudflareProxied: { type: 'boolean', description: 'Enable Cloudflare Orange Cloud (CDN/WAF/Edge)' },
            cloudflareZoneId: { type: 'string', description: 'Cloudflare Zone ID if applicable' }
          },
          required: ['action']
        }
      },
      {
        name: 'culkibo_inspect_ingress',
        title: 'Inspeccionar el enrutado de ingress',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            hostname: { type: 'string' },
            found: { type: 'boolean' },
            matchedRoute: { type: ['string', 'null'] },
            isWildcard: { type: 'boolean' },
            targetPod: { type: ['string', 'null'] },
            targetPort: { type: ['number', 'null'] },
            projectId: { type: ['string', 'null'] },
            cloudflareProxied: { type: 'boolean' },
            dataPlane: { type: 'string' },
            ingressAvailable: { type: 'boolean' },
            ingressReason: { type: ['string', 'null'] },
            tls: { type: 'object' },
            trafficSplit: { type: 'object' }
          }
        },
        description: 'Inspect edge ingress route resolution and TLS status for an incoming Host header.',
        inputSchema: {
          type: 'object',
          properties: {
            hostname: { type: 'string', description: 'Incoming hostname (e.g. preview.culkibo.dev)' }
          },
          required: ['hostname']
        }
      },
      {
        name: 'culkibo_manage_watcher',
        title: 'Gestionar el vigilante de ficheros',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        description: 'Start, stop, or inspect the directory watcher that detects code changes for The Forge.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['status', 'start', 'stop'], description: 'Watcher action' },
            directory: { type: 'string', description: 'Absolute or relative directory to watch (for start action)' }
          },
          required: ['action']
        }
      },
      {
        name: 'culkibo_issue_wildcard_ssl',
        title: 'Emitir certificado wildcard (NO IMPLEMENTADO)',
        // `readOnlyHint: true`: la herramienta ya no cambia nada. Un agente no
        // debe creer que invocarla tiene efecto — antes escribía un PEM falso.
        // Sin `destructiveHint`/`idempotentHint`: sólo significan algo cuando la
        // herramienta muta, y ésta no muta.
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'NOT IMPLEMENTED. Culkibo does not issue wildcard certificates: TLS is issued on demand by Caddy at the first handshake of each host, and certificates live in Caddy\'s volume, not in data/certs/. This tool always returns an explanatory error; it never issues anything. Use culkibo_create_sslip_domain or query /api/ingress/status for the real TLS state.',
        inputSchema: {
          type: 'object',
          properties: {
            domain: { type: 'string', description: 'Domain name (e.g. *.culkibo.dev or culkibo.dev)' },
            zoneId: { type: 'string', description: 'Cloudflare Zone ID' },
            provider: { type: 'string', enum: ['lets_encrypt', 'zerossl'], description: 'ACME Certificate Authority' }
          },
          required: ['domain']
        }
      },
      {
        name: 'culkibo_create_sslip_domain',
        title: 'Crear dominio comodín instantáneo',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        description: 'Register an instant Zero-Config wildcard hostname (e.g. *.127-0-0-1.sslip.io) whose certificate Caddy issues on demand at the first HTTPS handshake. Culkibo stores no key material and cannot report the certificate\'s issuer or expiry; query /api/ingress/status for the verified handshake.',
        inputSchema: {
          type: 'object',
          properties: {
            ip: { type: 'string', description: 'Server IP address (default 127.0.0.1)' },
            service: { type: 'string', enum: ['sslip.io', 'nip.io'], description: 'Wildcard DNS service' }
          }
        }
      },
      {
        name: 'culkibo_get_logs',
        title: 'Leer logs de los pods',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            logs: { type: 'array', description: 'Líneas de log más recientes, de la más nueva a la más antigua.' }
          }
        },
        description: 'Retrieve real-time streaming or historical container logs from pods.',
        inputSchema: {
          type: 'object',
          properties: {
            pod: { type: 'string', enum: ['forge', 'citadel', 'all'], description: 'Target pod' },
            limit: { type: 'number', description: 'Number of recent log lines to retrieve' },
            search: { type: 'string', description: 'Filter keyword' }
          }
        }
      },
      {
        name: 'culkibo_docker_status',
        title: 'Estado del motor Docker',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Comprueba el estado del motor Docker (modo nativo vs simulación sandbox), límites de memoria y contenedores.',
        inputSchema: {
          type: 'object',
          properties: {
            refresh: { type: 'boolean', description: 'Forzar recarga en vivo del estado de Docker' }
          }
        }
      },
      {
        name: 'culkibo_docker_containers',
        title: 'Listar contenedores Docker',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            containers: { type: 'array' }
          }
        },
        description: 'Lista los contenedores Docker activos o en modo sandbox con sus puertos, estados y métricas.',
        inputSchema: {
          type: 'object',
          properties: {
            all: { type: 'boolean', description: 'Incluir contenedores detenidos' },
            projectId: { type: 'string', description: 'Filtrar por ID de proyecto' }
          }
        }
      },
      {
        name: 'culkibo_export_backup',
        title: 'Exportar backup de un proyecto',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        description: 'Genera un backup exportable completo de un proyecto (metadata, volúmenes, envs, dominios).',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto a respaldar' }
          },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_restore_backup',
        title: 'Restaurar un proyecto desde backup',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
        description: 'Restaura un proyecto completo a partir de un archivo de backup JSON.',
        inputSchema: {
          type: 'object',
          properties: {
            backupFilePath: { type: 'string', description: 'Ruta absoluta o nombre del archivo de backup' }
          },
          required: ['backupFilePath']
        }
      },
      {
        name: 'culkibo_github_status',
        title: 'Estado de la conexión con GitHub',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Obtiene el estado de conexión con GitHub y el usuario vinculado en Culkibo.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'culkibo_github_connect',
        title: 'Conectar una cuenta de GitHub',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
        description: 'Conecta un Personal Access Token (PAT) de GitHub con permisos de repo a Culkibo.',
        inputSchema: {
          type: 'object',
          properties: {
            token: { type: 'string', description: 'GitHub Personal Access Token (ghp_...)' }
          },
          required: ['token']
        }
      },
      {
        name: 'culkibo_github_disconnect',
        title: 'Desconectar la cuenta de GitHub',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Desvincula la cuenta de GitHub de Culkibo.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'culkibo_github_list_repos',
        title: 'Listar repositorios de GitHub',
        annotations: { readOnlyHint: true, openWorldHint: true },
        description: 'Lista los repositorios accesibles en la cuenta de GitHub conectada con soporte de búsqueda y paginación.',
        inputSchema: {
          type: 'object',
          properties: {
            search: { type: 'string', description: 'Término de búsqueda o filtro de repositorio' },
            page: { type: 'number', description: 'Número de página' },
            perPage: { type: 'number', description: 'Repositorios por página' }
          }
        }
      },
      {
        name: 'culkibo_github_get_branches',
        title: 'Listar ramas de un repositorio',
        annotations: { readOnlyHint: true, openWorldHint: true },
        description: 'Lista las ramas disponibles en un repositorio de GitHub.',
        inputSchema: {
          type: 'object',
          properties: {
            owner: { type: 'string', description: 'Propietario u organización del repositorio' },
            repo: { type: 'string', description: 'Nombre del repositorio' }
          },
          required: ['owner', 'repo']
        }
      },
      {
        name: 'culkibo_github_auto_detect',
        title: 'Autodetectar el stack de un repositorio',
        annotations: { readOnlyHint: true, openWorldHint: true },
        description: 'Analiza automáticamente el código fuente de un repositorio de GitHub para inferir su stack tecnológico, comandos de build/start y puertos.',
        inputSchema: {
          type: 'object',
          properties: {
            owner: { type: 'string', description: 'Propietario del repositorio' },
            repo: { type: 'string', description: 'Nombre del repositorio' },
            branch: { type: 'string', description: 'Rama a inspeccionar (por defecto main)' }
          },
          required: ['owner', 'repo']
        }
      },
      {
        name: 'culkibo_create_project_from_github',
        title: 'Importar y desplegar desde GitHub',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        description: 'Importa, autodetecta y despliega automáticamente un proyecto directamente desde GitHub.',
        inputSchema: {
          type: 'object',
          properties: {
            owner: { type: 'string', description: 'Propietario del repo en GitHub' },
            repo: { type: 'string', description: 'Nombre del repositorio' },
            branch: { type: 'string', description: 'Rama a desplegar (default main)' },
            name: { type: 'string', description: 'Nombre personalizado para el proyecto (opcional)' },
            description: { type: 'string', description: 'Descripción opcional' },
            autoDeploy: { type: 'boolean', description: 'Activar auto-despliegue en cada push (default true)' }
          },
          required: ['owner', 'repo']
        }
      },

      // --- Producción (deployManager: Docker BuildKit + Caddy zero-downtime) ---
      {
        name: 'culkibo_deploy_strategy',
        title: 'Analizar estrategia de despliegue',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Inspecciona en seco el repositorio del proyecto (Dockerfile, railpack, nixpacks o Dockerfile generado con BuildKit) sin construir nada.',
        inputSchema: {
          type: 'object',
          properties: { projectId: { type: 'string', description: 'ID del proyecto' } },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_deploy_production',
        title: 'Desplegar a producción (zero-downtime)',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        description: 'Construye la imagen Docker con caché BuildKit, verifica salud en el nuevo contenedor, conmuta la ruta atómica en Caddy y drena el contenedor anterior sin caídas.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            commit: { type: 'string', description: 'Hash de commit específico opcional' },
            gitSync: { type: 'boolean', description: 'Si false, despliega el árbol ya presente en disco (default true)' },
            overrideFreeze: { type: 'boolean', description: 'Omitir una ventana de freeze activa (solo admin/owner, auditado)' },
            serverId: { type: 'string', description: 'Opcional: sobrescribir el nodo de flota destino para este despliegue' }
          },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_list_deployments',
        title: 'Listar despliegues de producción',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Devuelve el estado actual de producción (Citadel) y el historial reciente de despliegues de un proyecto.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            limit: { type: 'number', description: 'Máximo de entradas (default 10)' }
          },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_rollback_deployment',
        title: 'Revertir despliegue en producción',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        description: 'Revierte a la release anterior conmutando la ruta en Caddy (sin reconstruir la imagen cuando el contenedor anterior sigue en reserva).',
        inputSchema: {
          type: 'object',
          properties: { projectId: { type: 'string', description: 'ID del proyecto' } },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_prune_build_cache',
        title: 'Podar caché de construcción Docker',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Libera espacio de caché de Docker BuildKit bajo demanda (nunca se ejecuta automáticamente).',
        inputSchema: {
          type: 'object',
          properties: {
            keepStorageGb: { type: 'number', description: 'GB de caché a conservar (default 10)' },
            untilHours: { type: 'number', description: 'Opcional: podar entradas con más de N horas de antigüedad' }
          }
        }
      },

      // --- Bases de datos gestionadas + copias S3/R2 ---
      {
        name: 'culkibo_list_databases',
        title: 'Listar bases de datos gestionadas',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Lista las bases de datos gestionadas (PostgreSQL 18, MySQL 9, MariaDB 12.3, Valkey, Redis, MongoDB 8) con su salud y copias programadas. Nunca expone contraseñas.',
        inputSchema: {
          type: 'object',
          properties: { projectId: { type: 'string', description: 'Filtrar opcionalmente por proyecto' } }
        }
      },
      {
        name: 'culkibo_create_database',
        title: 'Aprovisionar base de datos gestionada',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        description: 'Aprovisiona en un clic una base de datos aislada en la red del proyecto con contraseña de 192 bits cifrada en AES-256-GCM y cero puertos expuestos por defecto.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto propietario' },
            engine: { type: 'string', enum: ['postgres', 'mysql', 'mariadb', 'valkey', 'redis', 'mongodb'], description: 'Motor de base de datos' },
            name: { type: 'string', description: 'Nombre legible de la base de datos' },
            dbName: { type: 'string', description: 'Nombre lógico del esquema (opcional)' },
            memoryMb: { type: 'number', description: 'Límite de RAM en MB (opcional)' }
          },
          required: ['projectId', 'engine']
        }
      },
      {
        name: 'culkibo_database_backup',
        title: 'Ejecutar copia de seguridad de base de datos',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        description: 'Genera un volcado comprimido en disco y lo sube automáticamente a S3/R2 si hay almacenamiento remoto configurado.',
        inputSchema: {
          type: 'object',
          properties: { databaseId: { type: 'string', description: 'ID de la base de datos' } },
          required: ['databaseId']
        }
      },
      {
        name: 'culkibo_database_credentials',
        title: 'Consultar credenciales de base de datos',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Devuelve explícitamente las credenciales descifradas y la cadena de conexión interna de una base de datos gestionada.',
        inputSchema: {
          type: 'object',
          properties: { databaseId: { type: 'string', description: 'ID de la base de datos' } },
          required: ['databaseId']
        }
      },
      {
        name: 'culkibo_delete_database',
        title: 'Eliminar base de datos gestionada',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Elimina una base de datos gestionada y opcionalmente su volumen persistente de datos.',
        inputSchema: {
          type: 'object',
          properties: {
            databaseId: { type: 'string', description: 'ID de la base de datos' },
            deleteVolume: { type: 'boolean', description: 'Borrar también el volumen persistente (irreversible, default false)' }
          },
          required: ['databaseId']
        }
      },

      // --- Catálogo de servicios de un clic ---
      {
        name: 'culkibo_list_catalog_templates',
        title: 'Explorar catálogo de servicios de un clic',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Lista todas las plantillas curadas y con versiones fijadas del catálogo de servicios de un clic (IA, bases de datos, automatización, analítica, monitorización, contenido, productividad, seguridad, documentación, media y mensajería).',
        inputSchema: {
          type: 'object',
          properties: { category: { type: 'string', description: 'Filtrar opcionalmente por categoría' } }
        }
      },
      {
        name: 'culkibo_install_catalog_service',
        title: 'Instalar servicio del catálogo en un clic',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        description: 'Instala un servicio del catálogo con red aislada, base de datos gestionada, secretos criptográficos y ruta HTTPS automática en Caddy.',
        inputSchema: {
          type: 'object',
          properties: {
            templateId: { type: 'string', description: 'ID de plantilla (p. ej. n8n, ghost, uptime-kuma, plausible)' },
            name: { type: 'string', description: 'Nombre de la instalación (opcional)' },
            domain: { type: 'string', description: 'Dominio público opcional para HTTPS automático' }
          },
          required: ['templateId']
        }
      },
      {
        name: 'culkibo_list_catalog_installations',
        title: 'Listar servicios instalados del catálogo',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Lista todos los servicios instalados desde el catálogo junto con su estado, salud y URL.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'culkibo_uninstall_catalog_service',
        title: 'Desinstalar servicio del catálogo',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Desinstala un servicio del catálogo, retirando contenedores, red y ruta de ingress.',
        inputSchema: {
          type: 'object',
          properties: {
            installationId: { type: 'string', description: 'ID de la instalación' },
            deleteVolumes: { type: 'boolean', description: 'Borrar también los volúmenes persistentes y BD (default false)' }
          },
          required: ['installationId']
        }
      },

      // --- Sincronización en vivo (The Forge: Commit Frames + Merkle + Rollback + Promoción) ---
      {
        name: 'culkibo_verify_sync',
        title: 'Verificar integridad de sincronización (Merkle)',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Calcula el árbol Merkle real en disco de un proyecto y reporta estado de sincronización, divergencia y percentiles reales de latencia (p50/p95/p99).',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            clientDigest: { type: 'string', description: 'Digest SHA-256 raíz opcional del árbol local del agente para comprobar cero divergencia' }
          },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_rollback_sync',
        title: 'Revertir parche en vivo (<10 ms)',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        description: 'Revierte los últimos commit frames de sincronización en vivo directamente desde el historial de parches en memoria sin reconstruir.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            steps: { type: 'number', description: 'Número de commit frames a revertir (default 1)' }
          },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_promote_forge',
        title: 'Promocionar Forge verificado a Citadel',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        description: 'Congela el árbol exacto verificado en The Forge y lo despliega a producción (The Citadel) con zero-downtime sin requerir un git push previo.',
        inputSchema: {
          type: 'object',
          properties: { projectId: { type: 'string', description: 'ID del proyecto' } },
          required: ['projectId']
        }
      },

      // --- Migrador de Coolify v4 vía MCP ---
      {
        name: 'culkibo_migrate_coolify',
        title: 'Migrar proyectos desde Coolify v4',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        description: 'Conecta con la API v4 de una instancia de Coolify para previsualizar (`mode: "preview"`) o importar (`mode: "import"`) todos sus proyectos, apps, bases de datos, variables y volúmenes.',
        inputSchema: {
          type: 'object',
          properties: {
            coolifyUrl: { type: 'string', description: 'URL base de Coolify (p. ej. https://coolify.midominio.com)' },
            apiToken: { type: 'string', description: 'API Token de Coolify v4' },
            mode: { type: 'string', enum: ['preview', 'import'], description: 'preview solo inspecciona; import crea los proyectos en Culkibo (default preview)' },
            apps: { type: 'array', items: { type: 'string' }, description: 'UUIDs de aplicaciones a importar (omitir para todas; [] para ninguna)' },
            dbs: { type: 'array', items: { type: 'string' }, description: 'UUIDs de bases de datos a importar (omitir para todas; [] para ninguna)' },
            services: { type: 'array', items: { type: 'string' }, description: 'UUIDs de servicios Compose a importar (omitir para todos; [] para ninguno)' }
          },
          required: ['coolifyUrl', 'apiToken']
        }
      },

      // --- Migrador de WordPress, Importador Compose y Acceso Remoto ---
      {
        name: 'culkibo_analyze_wordpress',
        title: 'Analizar web WordPress para migración',
        annotations: { readOnlyHint: true, openWorldHint: true },
        description: 'Inspecciona una web WordPress en vivo (HTML + /wp-json) para detectar versión, tema, plugins, WooCommerce, Cloudflare y generar un plan de migración sin cortes a Culkibo.',
        inputSchema: {
          type: 'object',
          properties: {
            url: { type: 'string', description: 'URL pública del sitio WordPress (p. ej. https://mitienda.com)' }
          },
          required: ['url']
        }
      },
      {
        name: 'culkibo_import_compose',
        title: 'Importar stack desde Docker Compose',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        description: 'Analiza un archivo docker-compose.yml (mode: "parse") o lo importa como proyecto Culkibo (mode: "import"), detectando bases de datos y avisos de producción.',
        inputSchema: {
          type: 'object',
          properties: {
            yamlText: { type: 'string', description: 'Contenido completo del archivo docker-compose.yml' },
            projectName: { type: 'string', description: 'Nombre del proyecto en Culkibo (opcional)' },
            mode: { type: 'string', enum: ['parse', 'import'], description: 'parse solo analiza; import crea el proyecto (default parse)' }
          },
          required: ['yamlText']
        }
      },
      {
        name: 'culkibo_get_remote_access',
        title: 'Consultar configuración de acceso remoto y agentes',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Devuelve el estado de acceso remoto del daemon (dominio del panel, túneles Cloudflare, endpoints MCP/WebSocket y plantillas listas para clientes de IA).',
        inputSchema: {
          type: 'object',
          properties: {
            serverUrl: { type: 'string', description: 'URL base del servidor Culkibo (opcional)' }
          }
        }
      },
      {
        name: 'culkibo_get_observability',
        title: 'Consultar telemetría y latencia real en vivo',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Devuelve métricas reales medidas en tiempo de ejecución: latencia HTTP (p50/p95/p99), RPS, event-loop lag, RAM/heap, WebSockets, Live Sync y estado de Caddy.',
        inputSchema: {
          type: 'object',
          properties: {
            fresh: { type: 'boolean', description: 'Forzar muestreo sin caché de 250 ms (opcional)' }
          }
        }
      },
      {
        name: 'culkibo_system_doctor',
        title: 'Ejecutar diagnóstico completo del sistema',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Ejecuta el diagnóstico integral del servidor (Node, Docker, Caddy, disco/RAM, postura de seguridad, dominios, copias de seguridad y residuos temporales) con recomendaciones concretas.',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      },
      {
        name: 'culkibo_link_database',
        title: 'Vincular o desvincular base de datos a proyecto',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        description: 'Vincula (action: "link") o desvincula (action: "unlink") una base de datos gestionada a un proyecto para conectar su red Docker aislada e inyectar DATABASE_URL/REDIS_URL/MONGODB_URI cifradas en tiempo de despliegue sin guardar contraseñas en claro en projects.json.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            databaseId: { type: 'string', description: 'ID de la base de datos gestionada' },
            action: { type: 'string', enum: ['link', 'unlink'], description: 'link para vincular (default), unlink para desvincular' }
          },
          required: ['projectId', 'databaseId']
        }
      },
      {
        name: 'culkibo_toggle_maintenance',
        title: 'Activar o desactivar modo mantenimiento (<10 ms)',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Activa o desactiva el modo mantenimiento atómico en Caddy (HTTP 503 elegante con Retry-After) para todos los dominios de un proyecto sin detener su contenedor.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            enabled: { type: 'boolean', description: 'true para activar modo mantenimiento, false para volver a tráfico normal' }
          },
          required: ['projectId', 'enabled']
        }
      },
      {
        name: 'culkibo_get_deploy_queue',
        title: 'Consultar cola de despliegues y concurrencia',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Muestra los builds Docker activos en paralelo, el límite global del semáforo de RAM/CPU y la cola de despliegues en espera.',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      },

      // --- 20 herramientas avanzadas de operación, diagnóstico, DR, edge, crons y previews ---
      {
        name: 'culkibo_get_container_logs',
        title: 'Leer logs en vivo del contenedor de producción',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Obtiene las últimas líneas de stdout/stderr del contenedor activo en Citadel de un proyecto (con secretos redactados).',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            lines: { type: 'number', description: 'Número de líneas (10–2000, default 200)' }
          },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_get_deployment_logs',
        title: 'Leer log completo de un despliegue',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Devuelve las líneas de build/despliegue de un deploymentId concreto (o el más reciente del proyecto).',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            deploymentId: { type: 'string', description: 'ID del despliegue (opcional: el más reciente si se omite)' },
            tail: { type: 'number', description: 'Últimas N líneas a devolver (default 200)' }
          },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_cancel_deployment',
        title: 'Cancelar build o despliegue en curso',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Aborta de forma limpia un build Docker/git clone en curso y libera su ranura del semáforo.',
        inputSchema: {
          type: 'object',
          properties: { projectId: { type: 'string', description: 'ID del proyecto' } },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_diagnose_domain',
        title: 'Diagnosticar DNS, NAT, TLS y ruta Caddy de un dominio',
        annotations: { readOnlyHint: true, openWorldHint: true },
        description: 'Ejecuta un diagnóstico integral paso a paso de un dominio (DNS A/AAAA, detección de Cloudflare Origin CA, CGNAT/puertos, handshake TLS real y ruta en Caddy).',
        inputSchema: {
          type: 'object',
          properties: { hostname: { type: 'string', description: 'Nombre de dominio completo (p. ej. app.midominio.com)' } },
          required: ['hostname']
        }
      },
      {
        name: 'culkibo_ingress_status',
        title: 'Estado completo del plano de datos Caddy e ingress',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Devuelve estado de Caddy, rutas activas, deriva (missing/extra/modified), políticas wildcard y capacidades instaladas.',
        inputSchema: {
          type: 'object',
          properties: { probe: { type: 'boolean', description: 'Sondear TLS real de los dominios (default false para rapidez)' } }
        }
      },
      {
        name: 'culkibo_reconcile_ingress',
        title: 'Reconciliar rutas y TLS en Caddy',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        description: 'Sincroniza atómicamente todas las rutas de dominios, redirecciones, Basic Auth, IP allowlist y políticas TLS en Caddy.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'culkibo_manage_production_service',
        title: 'Iniciar, detener, reiniciar o hibernar producción',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
        description: 'Controla el ciclo de vida del contenedor de producción en Citadel (`start`, `stop`, `restart` o `hibernate`).',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            action: { type: 'string', enum: ['start', 'stop', 'restart', 'hibernate'], description: 'Acción sobre el contenedor' }
          },
          required: ['projectId', 'action']
        }
      },
      {
        name: 'culkibo_system_doctor_fix',
        title: 'Aplicar reparación automática de System Doctor',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        description: 'Ejecuta una reparación segura en 1 clic detectada por el Doctor del sistema (`reconcile_caddy`, `clean_tmp`, `start_caddy`, `clean_orphans`, `prune_build_cache`).',
        inputSchema: {
          type: 'object',
          properties: {
            action: {
              type: 'string',
              enum: ['reconcile_caddy', 'clean_tmp', 'start_caddy', 'clean_orphans', 'prune_build_cache'],
              description: 'Acción de auto-reparación a ejecutar'
            }
          },
          required: ['action']
        }
      },
      {
        name: 'culkibo_database_schedule',
        title: 'Configurar copias programadas y retención de BD',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        description: 'Configura la expresión cron de copias automáticas y/o la política de retención (horarias, diarias y semanales) de una base de datos gestionada.',
        inputSchema: {
          type: 'object',
          properties: {
            databaseId: { type: 'string', description: 'ID de la base de datos' },
            enabled: { type: 'boolean', description: 'Activar o desactivar programación cron' },
            cron: { type: 'string', description: 'Expresión cron de 5 campos o alias (@hourly, @daily, @weekly)' },
            hourly: { type: 'number', description: 'Número de copias horarias a conservar (0–168)' },
            daily: { type: 'number', description: 'Número de copias diarias a conservar (0–365)' },
            weekly: { type: 'number', description: 'Número de copias semanales a conservar (0–260)' }
          },
          required: ['databaseId']
        }
      },
      {
        name: 'culkibo_database_restore',
        title: 'Restaurar base de datos (con snapshot previo)',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
        description: 'Restaura una base de datos desde un backupId o remoteKey S3 creando antes automáticamente una instantánea local `pre-restore` para deshacer si algo sale mal.',
        inputSchema: {
          type: 'object',
          properties: {
            databaseId: { type: 'string', description: 'ID de la base de datos' },
            backupId: { type: 'string', description: 'ID de copia del historial local' },
            remoteKey: { type: 'string', description: 'Clave remota en S3/R2 (alternativa a backupId)' },
            createSafetySnapshot: { type: 'boolean', description: 'Crear snapshot pre-restore antes de tocar la BD (default true)' }
          },
          required: ['databaseId']
        }
      },
      {
        name: 'culkibo_database_list_backups',
        title: 'Listar copias de seguridad de una BD',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Lista todas las copias locales y en S3/R2 de una base de datos gestionada con tamaño, SHA-256 y estado.',
        inputSchema: {
          type: 'object',
          properties: { databaseId: { type: 'string', description: 'ID de la base de datos' } },
          required: ['databaseId']
        }
      },
      {
        name: 'culkibo_database_inspect',
        title: 'Inspeccionar salud, latencia y tablas de una BD',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Ejecuta una sonda autenticada en vivo contra la base de datos devolviendo latencia, versión del motor, tamaño lógico, tamaño de volumen y top 15 tablas/colecciones.',
        inputSchema: {
          type: 'object',
          properties: { databaseId: { type: 'string', description: 'ID de la base de datos' } },
          required: ['databaseId']
        }
      },
      {
        name: 'culkibo_list_backups',
        title: 'Listar snapshots y copias de proyectos/instancia',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Lista todos los archivos de copia de proyecto y snapshots completos de instancia guardados en disco.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'culkibo_export_instance_snapshot',
        title: 'Exportar snapshot completo de la instancia Culkibo',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        description: 'Genera un snapshot completo v2.0.0 (proyectos, dominios, notificaciones, políticas TLS, metadatos de BDs/catálogo), redactado por defecto u opcionalmente cifrado con AES-256-GCM.',
        inputSchema: {
          type: 'object',
          properties: {
            includeSecrets: { type: 'boolean', description: 'Incluir secretos (requiere passphrase recomendada, default false)' },
            passphrase: { type: 'string', description: 'Contraseña para cifrar el snapshot con scrypt+AES-256-GCM (opcional)' },
            uploadToS3: { type: 'boolean', description: 'Subir también el snapshot al bucket S3/R2 configurado (default false)' }
          }
        }
      },
      {
        name: 'culkibo_manage_wildcard_dns01',
        title: 'Gestionar políticas TLS wildcard DNS-01',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        description: 'Lista, añade o elimina políticas wildcard DNS-01 (`*.midominio.com`) en Caddy + Cloudflare.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['list', 'add', 'remove'], description: 'Operación a realizar' },
            domain: { type: 'string', description: 'Dominio raíz (requerido para add/remove)' },
            includeApex: { type: 'boolean', description: 'Incluir el dominio raíz además de *.dominio (default true)' }
          },
          required: ['action']
        }
      },
      {
        name: 'culkibo_set_domain_basic_auth',
        title: 'Activar o quitar Basic Auth nativo en un dominio',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        description: 'Protege un dominio en Caddy con autenticación HTTP Basic Auth (hash bcrypt generado localmente) o la desactiva.',
        inputSchema: {
          type: 'object',
          properties: {
            domainId: { type: 'string', description: 'ID del dominio (o hostname)' },
            enabled: { type: 'boolean', description: 'true para activar, false para desactivar' },
            username: { type: 'string', description: 'Usuario HTTP Basic Auth (requerido si enabled=true)' },
            password: { type: 'string', description: 'Contraseña HTTP Basic Auth (requerido si enabled=true)' }
          },
          required: ['domainId', 'enabled']
        }
      },
      {
        name: 'culkibo_notifications',
        title: 'Consultar historial o probar alertas salientes',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        description: 'Consulta la configuración redactada de canales (Telegram/Discord/Slack/Webhook), lee el historial reciente o envía una alerta de prueba.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['get', 'history', 'test'], description: 'Acción: get, history o test' },
            limit: { type: 'number', description: 'Límite de entradas para history (default 20)' }
          },
          required: ['action']
        }
      },
      {
        name: 'culkibo_manage_webhook',
        title: 'Consultar estado de webhooks o rotar Deploy Hook',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        description: 'Muestra las URLs de webhook multi-Git (GitHub/GitLab/Gitea/Bitbucket/CI Deploy Hook) de un proyecto o rota su `deployHookToken`.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            action: { type: 'string', enum: ['status', 'rotate_deploy_hook'], description: 'status para consultar, rotate_deploy_hook para generar nuevo token CI/CD' }
          },
          required: ['projectId', 'action']
        }
      },
      {
        name: 'culkibo_manage_crons',
        title: 'Gestionar tareas programadas (Cron Jobs) por proyecto',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        description: 'Lista, crea, activa/desactiva, ejecuta manualmente o elimina Cron Jobs de un proyecto (`exec` dentro del contenedor o `http`).',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            action: { type: 'string', enum: ['list', 'create', 'toggle', 'run', 'delete'], description: 'Acción a realizar' },
            cronId: { type: 'string', description: 'ID del cron (para toggle/run/delete)' },
            name: { type: 'string', description: 'Nombre del cron (para create)' },
            schedule: { type: 'string', description: 'Expresión cron de 5 campos (para create)' },
            kind: { type: 'string', enum: ['exec', 'http'], description: 'Tipo de tarea (default exec)' },
            command: { type: 'string', description: 'Comando sin shell dentro del contenedor (si kind=exec)' },
            url: { type: 'string', description: 'URL destino (si kind=http)' },
            enabled: { type: 'boolean', description: 'Estado activo (para create/toggle)' }
          },
          required: ['projectId', 'action']
        }
      },
      {
        name: 'culkibo_manage_previews',
        title: 'Gestionar Preview Deployments por rama o PR',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        description: 'Lista, despliega o destruye entornos de previsualización aislados por Pull Request o rama de un proyecto.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            action: { type: 'string', enum: ['list', 'deploy', 'destroy'], description: 'Acción sobre previews' },
            branch: { type: 'string', description: 'Rama Git del preview (para deploy/destroy)' },
            prNumber: { type: 'number', description: 'Número de PR/MR (opcional)' },
            previewId: { type: 'string', description: 'ID del preview (para destroy)' }
          },
          required: ['projectId', 'action']
        }
      },

      // --- MCP 2.0: A. Flota Multi-Servidor (5) ---
      {
        name: 'culkibo_fleet_list_servers',
        title: 'Listar servidores de la flota',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            servers: { type: 'array', description: 'Nodo local y nodos SSH remotos con etiquetas, región, estado y huella fijada.' },
            total: { type: 'number' }
          }
        },
        description: 'Lista el nodo local y todos los nodos SSH remotos de la flota con etiquetas, región, estado, huella TOFU fijada y recursos cacheados (nunca expone claves privadas).',
        inputSchema: {
          type: 'object',
          properties: {
            tag: { type: 'string', description: 'Filtrar opcionalmente por etiqueta' },
            region: { type: 'string', description: 'Filtrar opcionalmente por región' }
          }
        }
      },
      {
        name: 'culkibo_fleet_add_server',
        title: 'Registrar servidor SSH en la flota',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        description: 'Registra un servidor remoto por SSH en la flota con clave ed25519 cifrada en AES-256-GCM (importada o generada) y fijación TOFU de host-key.',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Nombre legible del nodo' },
            host: { type: 'string', description: 'IP o hostname RFC1123 del servidor remoto (sin metadatos ni loopback)' },
            port: { type: 'number', description: 'Puerto SSH (default 22)' },
            user: { type: 'string', description: 'Usuario SSH (default root)' },
            privateKey: { type: 'string', description: 'Clave privada OpenSSH/PEM sin passphrase (opcional)' },
            keyId: { type: 'string', description: 'ID de clave SSH existente en el vault de la flota (opcional)' },
            generateKey: { type: 'boolean', description: 'Generar nuevo par ed25519 cifrado si no se aporta keyId/privateKey' },
            tags: { type: 'array', items: { type: 'string' }, description: 'Etiquetas del servidor (p. ej. ["eu", "prod"])' },
            region: { type: 'string', description: 'Región lógica (p. ej. eu-west)' },
            expectedFingerprint: { type: 'string', description: 'Huella SHA-256 esperada del host para verificación estricta' }
          },
          required: ['name', 'host']
        }
      },
      {
        name: 'culkibo_fleet_probe_server',
        title: 'Sondear servidor remoto por SSH',
        annotations: { readOnlyHint: true, openWorldHint: true },
        description: 'Ejecuta una sonda SSH de un solo salto sobre un nodo de la flota devolviendo versiones de Docker/Caddy, CPU/RAM/disco, RTT y verificación TOFU.',
        inputSchema: {
          type: 'object',
          properties: {
            serverId: { type: 'string', description: 'ID del servidor (o "local")' },
            refresh: { type: 'boolean', description: 'Forzar sonda en vivo ignorando caché (default false)' }
          },
          required: ['serverId']
        }
      },
      {
        name: 'culkibo_fleet_remove_server',
        title: 'Eliminar servidor remoto de la flota',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Elimina un servidor remoto de la flota. Bloquea si hay proyectos activos asignados salvo que se indique force: true.',
        inputSchema: {
          type: 'object',
          properties: {
            serverId: { type: 'string', description: 'ID del servidor remoto a eliminar' },
            force: { type: 'boolean', description: 'Forzar eliminación aunque existan proyectos asignados (default false)' }
          },
          required: ['serverId']
        }
      },
      {
        name: 'culkibo_fleet_assign_project',
        title: 'Asignar proyecto a un nodo de la flota',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Fija o mueve un proyecto hacia el nodo local o un servidor remoto de la flota (soporta dryRun para previsualizar el impacto).',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            serverId: { type: 'string', description: 'ID del servidor destino ("local" o ID de nodo remoto)' }
          },
          required: ['projectId', 'serverId']
        }
      },

      // --- MCP 2.0: B. Equipos y RBAC (6) ---
      {
        name: 'culkibo_rbac_whoami',
        title: 'Consultar identidad y permisos del llamante',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            method: { type: 'string' },
            userId: { type: ['string', 'null'] },
            role: { type: 'string' },
            teamId: { type: ['string', 'null'] },
            projectIds: { type: ['array', 'null'] },
            scopes: { type: 'array' },
            isSuperAdmin: { type: 'boolean' },
            allowedToolsCount: { type: 'number' }
          }
        },
        description: 'Devuelve la identidad efectiva del cliente MCP actual: método de autenticación, usuario, rol, equipo, ACL de proyectos, scopes y número de herramientas autorizadas.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'culkibo_team_list_members',
        title: 'Listar miembros, roles e invitaciones del equipo',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Lista los miembros del equipo con sus roles (owner/admin/developer/viewer), ACLs de proyectos e invitaciones pendientes con tokens redactados.',
        inputSchema: {
          type: 'object',
          properties: {
            teamId: { type: 'string', description: 'ID del equipo (opcional; por defecto el del llamante o team_default)' }
          }
        }
      },
      {
        name: 'culkibo_team_invite_member',
        title: 'Crear invitación de un solo uso para miembro',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        description: 'Genera una invitación temporal de un solo uso vinculada al email y rol indicados (los no-owners nunca pueden invitar como owner ni superar su rol).',
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string', description: 'Email del miembro a invitar' },
            role: { type: 'string', enum: ['owner', 'admin', 'developer', 'viewer'], description: 'Rol asignado' },
            teamId: { type: 'string', description: 'ID del equipo (opcional)' },
            projectIds: { type: 'array', items: { type: 'string' }, description: 'ACL opcional de IDs de proyectos permitidos' },
            ttlHours: { type: 'number', description: 'Validez en horas (default 48, máx 168)' }
          },
          required: ['email', 'role']
        }
      },
      {
        name: 'culkibo_team_update_member',
        title: 'Actualizar rol, ACL de proyectos o eliminar miembro',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Modifica el rol o los proyectos permitidos de un miembro, o lo expulsa del equipo revocando inmediatamente sus sesiones activas.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['update_role', 'set_projects', 'remove'], description: 'Acción sobre la membresía' },
            memberId: { type: 'string', description: 'ID del miembro o usuario' },
            teamId: { type: 'string', description: 'ID del equipo (opcional)' },
            role: { type: 'string', enum: ['owner', 'admin', 'developer', 'viewer'], description: 'Nuevo rol (requerido para update_role)' },
            projectIds: { type: 'array', items: { type: 'string' }, description: 'Lista de proyectos permitidos (para set_projects)' }
          },
          required: ['action', 'memberId']
        }
      },
      {
        name: 'culkibo_rbac_list_tokens',
        title: 'Listar tokens API/MCP con alcance restringido',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Lista los tokens API/MCP con alcance restringido mostrando solo metadatos, prefijo, caducidad y scopes (nunca hashes ni secretos).',
        inputSchema: {
          type: 'object',
          properties: {
            teamId: { type: 'string', description: 'Filtrar opcionalmente por equipo' }
          }
        }
      },
      {
        name: 'culkibo_rbac_manage_token',
        title: 'Crear o revocar token API/MCP con alcance',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
        description: 'Emite un nuevo token API/MCP con rol/scopes/projectIds acotados (sin superar jamás el rol del llamante) o revoca un token existente.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['create', 'revoke'], description: 'create o revoke' },
            name: { type: 'string', description: 'Nombre descriptivo del token (para create)' },
            role: { type: 'string', enum: ['owner', 'admin', 'developer', 'viewer'], description: 'Rol máximo del token' },
            scopes: { type: 'array', items: { type: 'string' }, description: 'Lista de scopes autorizados (p. ej. ["projects:read"])' },
            projectIds: { type: 'array', items: { type: 'string' }, description: 'Restricción opcional de proyectos' },
            expiresInDays: { type: 'number', description: 'Días hasta expiración (opcional)' },
            tokenId: { type: 'string', description: 'ID del token (requerido para revoke)' },
            teamId: { type: 'string', description: 'ID del equipo (opcional)' }
          },
          required: ['action']
        }
      },

      // --- MCP 2.0: C. Entornos y Promoción (4) ---
      {
        name: 'culkibo_env_list',
        title: 'Listar entornos y deriva de un proyecto',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string' },
            environments: { type: 'array' }
          }
        },
        description: 'Lista los entornos configurados de un proyecto (development, staging, production o personalizados) con rama, servidor, release activa y claves de entorno redactadas.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' }
          },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_env_create',
        title: 'Crear entorno aislado en un proyecto',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        description: 'Crea un entorno aislado para un proyecto (p. ej. staging o qa) con su propia rama, servidor destino, dominio y variables cifradas.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            name: { type: 'string', description: 'Slug del entorno (p. ej. development, staging, production)' },
            branch: { type: 'string', description: 'Rama Git asociada' },
            serverId: { type: 'string', description: 'Nodo de flota destino (default local)' },
            cloneEnvFrom: { type: 'string', description: 'Entorno origen del que clonar variables (opcional)' },
            domain: { type: 'string', description: 'Dominio público asociado al entorno (opcional)' },
            autoDeploy: { type: 'boolean', description: 'Activar despliegue automático en push' },
            envVars: { type: 'object', description: 'Variables de entorno iniciales (se cifran en reposo)' }
          },
          required: ['projectId', 'name']
        }
      },
      {
        name: 'culkibo_env_diff',
        title: 'Comparar dos entornos de un proyecto',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Compara dos entornos (fromEnv vs toEnv) mostrando diferencias de imagen/commit, dominios y claves de entorno mediante hashes SHA-256 sin exponer jamás valores secretos.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            fromEnv: { type: 'string', description: 'Entorno origen (p. ej. staging)' },
            toEnv: { type: 'string', description: 'Entorno destino (p. ej. production)' }
          },
          required: ['projectId', 'fromEnv', 'toEnv']
        }
      },
      {
        name: 'culkibo_env_promote',
        title: 'Promocionar release inmutable entre entornos',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
        description: 'Promociona la release verificada de un entorno a otro con snapshot previo, comprobación de ventanas freeze y control de rol para producción.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            fromEnv: { type: 'string', description: 'Entorno origen' },
            toEnv: { type: 'string', description: 'Entorno destino' },
            includeEnvVars: { type: 'boolean', description: 'Copiar también variables de entorno (default false)' },
            overrideFreeze: { type: 'boolean', description: 'Omitir ventana de freeze activa (solo admin/owner)' }
          },
          required: ['projectId', 'fromEnv', 'toEnv']
        }
      },

      // --- MCP 2.0: D. Uptime y Páginas de Estado (4) ---
      {
        name: 'culkibo_uptime_list_monitors',
        title: 'Listar monitores de uptime, SLA y páginas de estado',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            monitors: { type: 'array' },
            statusPages: { type: 'array' }
          }
        },
        description: 'Lista los monitores sintéticos HTTP/TCP con SLA 24h/7d/30d, latencias p50/p95, incidentes abiertos y páginas de estado públicas.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'Filtrar opcionalmente por proyecto' }
          }
        }
      },
      {
        name: 'culkibo_uptime_upsert_monitor',
        title: 'Crear o actualizar monitor sintético de uptime',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        description: 'Crea o actualiza un monitor HTTP/TCP con protección SSRF estricta, código esperado, palabra clave y umbral de latencia.',
        inputSchema: {
          type: 'object',
          properties: {
            monitorId: { type: 'string', description: 'ID existente para actualizar (omitir para crear)' },
            projectId: { type: 'string', description: 'ID del proyecto asociado (opcional)' },
            name: { type: 'string', description: 'Nombre público del monitor' },
            type: { type: 'string', enum: ['http', 'tcp'], description: 'Tipo de sonda (default http)' },
            url: { type: 'string', description: 'URL pública a monitorizar (validada con ssrfGuard)' },
            host: { type: 'string', description: 'Host destino (para tipo tcp)' },
            port: { type: 'number', description: 'Puerto destino (para tipo tcp)' },
            intervalSec: { type: 'number', description: 'Intervalo en segundos (default 60)' },
            timeoutMs: { type: 'number', description: 'Timeout en ms (default 5000)' },
            expectedStatus: { type: 'number', description: 'Código HTTP esperado (default 200)' },
            expectedBody: { type: 'string', description: 'Subcadena literal esperada en la respuesta (opcional)' },
            enabled: { type: 'boolean', description: 'Monitor activo (default true)' },
            allowLocalProject: { type: 'boolean', description: 'Permitir sonda local ligada al puerto verificado del projectId' }
          }
        }
      },
      {
        name: 'culkibo_uptime_delete_monitor',
        title: 'Eliminar monitor de uptime',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Elimina permanentemente un monitor sintético de uptime y detiene su programación.',
        inputSchema: {
          type: 'object',
          properties: {
            monitorId: { type: 'string', description: 'ID del monitor a eliminar' }
          },
          required: ['monitorId']
        }
      },
      {
        name: 'culkibo_status_page_manage',
        title: 'Gestionar páginas de estado públicas e incidentes',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        description: 'Configura páginas de estado públicas (/status/:slug) con aislamiento cero-fugas o publica/resuelve incidentes manuales.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['configure', 'publish_incident', 'resolve_incident', 'delete'], description: 'Operación sobre la página de estado' },
            slug: { type: 'string', description: 'Identificador URL público (p. ej. "status-prod")' },
            customDomain: { type: 'string', description: 'Dominio personalizado opcional' },
            title: { type: 'string', description: 'Título público de la página' },
            description: { type: 'string', description: 'Descripción pública opcional' },
            monitorIds: { type: 'array', items: { type: 'string' }, description: 'IDs de monitores visibles en la página' },
            incidentId: { type: 'string', description: 'ID del incidente (para resolve_incident)' },
            incidentTitle: { type: 'string', description: 'Título del incidente (para publish_incident)' },
            severity: { type: 'string', enum: ['minor', 'major', 'critical', 'maintenance'], description: 'Gravedad del incidente' },
            message: { type: 'string', description: 'Actualización de estado del incidente' }
          },
          required: ['action', 'slug']
        }
      },

      // --- MCP 2.0: E. GitOps culkibo.yaml (3) ---
      {
        name: 'culkibo_gitops_export',
        title: 'Exportar estado a manifiesto culkibo.yaml',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Exporta de forma determinista el stack actual a un manifiesto declarativo culkibo.yaml sustituyendo todos los secretos por referencias ${vault.KEY}.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'Exportar un único proyecto (opcional)' },
            projectIds: { type: 'array', items: { type: 'string' }, description: 'Lista opcional de proyectos a exportar' },
            name: { type: 'string', description: 'Nombre del stack exportado (opcional)' }
          }
        }
      },
      {
        name: 'culkibo_gitops_plan',
        title: 'Calcular plan de reconciliación GitOps (dry-run)',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            create: { type: 'array' },
            update: { type: 'array' },
            delete: { type: 'array' },
            warnings: { type: 'array' }
          }
        },
        description: 'Parsea de forma segura culkibo.yaml (protegido contra YAML bombs y prototipos) y calcula el diff estructurado create/update/delete frente al estado vivo.',
        inputSchema: {
          type: 'object',
          properties: {
            yamlText: { type: 'string', description: 'Contenido completo del manifiesto culkibo.yaml' },
            prune: { type: 'boolean', description: 'Incluir recursos ausentes del manifiesto en delete[] (default false)' }
          },
          required: ['yamlText']
        }
      },
      {
        name: 'culkibo_gitops_apply',
        title: 'Aplicar manifiesto declarativo culkibo.yaml',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
        description: 'Reconcilia idempotentemente los recursos vivos con culkibo.yaml (soporta dryRun para previsualizar sin aplicar cambios).',
        inputSchema: {
          type: 'object',
          properties: {
            yamlText: { type: 'string', description: 'Contenido completo del manifiesto culkibo.yaml' },
            prune: { type: 'boolean', description: 'Eliminar recursos no declarados en el manifiesto (default false)' },
            confirmDestructive: { type: 'boolean', description: 'Confirmación explícita para permitir borrado destructivo con prune (default false)' }
          },
          required: ['yamlText']
        }
      },

      // --- MCP 2.0: F. Smart Sleep y Cost/RAM Advisor (3) ---
      {
        name: 'culkibo_cost_advisor',
        title: 'Analizar ahorro de RAM y coste mensual del VPS',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            summary: { type: 'object' },
            recommendations: { type: 'array' },
            reclaimableRamMb: { type: 'number' },
            estimatedMonthlySavingsEur: { type: 'number' }
          }
        },
        description: 'Analiza consumo real de RAM, contenedores inactivos, límites sobredimensionados, riesgo OOM y caché de builds calculando RAM recuperable y ahorro en €/mes.',
        inputSchema: {
          type: 'object',
          properties: {
            monthlyServerCostEur: { type: 'number', description: 'Coste mensual actual del VPS en EUR (opcional)' },
            vpsMonthlyEur: { type: 'number', description: 'Alias opcional de monthlyServerCostEur' }
          }
        }
      },
      {
        name: 'culkibo_sleep_status',
        title: 'Consultar estado de Smart Sleep (scale-to-zero)',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Consulta las políticas de auto-hibernación (scale-to-zero), estado despierto/dormido, tiempo de inactividad y RAM ahorrada.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto (opcional; si se omite lista todos los permitidos)' }
          }
        }
      },
      {
        name: 'culkibo_sleep_manage',
        title: 'Configurar, dormir o despertar servicio (Smart Sleep)',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Configura la política Smart Sleep de un proyecto o ejecuta una hibernación/despertar manual con protección de crons y despliegues activos.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            action: { type: 'string', enum: ['configure', 'sleep', 'wake'], description: 'Acción: configure, sleep o wake' },
            enabled: { type: 'boolean', description: 'Activar auto-sleep (para configure)' },
            mode: { type: 'string', enum: ['pause', 'stop'], description: 'Modo de suspensión del contenedor (default stop)' },
            idleMinutes: { type: 'number', description: 'Minutos de inactividad antes de dormir (mínimo 5)' },
            wakeTimeoutMs: { type: 'number', description: 'Timeout de despertar en ms (opcional)' },
            excludeCrons: { type: 'boolean', description: 'Evitar dormir mientras haya crons activos (default true)' }
          },
          required: ['projectId', 'action']
        }
      },

      // --- MCP 2.0: G. LiveSync 2.0 Time-Travel y Conflictos (3) ---
      {
        name: 'culkibo_sync_file_history',
        title: 'Consultar historial por archivo en Live Sync 2.0',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Devuelve el historial de versiones de un archivo concreto en The Forge con número de secuencia, timestamp, SHA-256, cliente autor y diff opcional.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            filePath: { type: 'string', description: 'Ruta relativa del archivo dentro del proyecto' },
            limit: { type: 'number', description: 'Máximo de versiones a devolver (default 20)' },
            includeDiff: { type: 'boolean', description: 'Incluir diff unificado de cada versión (default false)' }
          },
          required: ['projectId', 'filePath']
        }
      },
      {
        name: 'culkibo_sync_rollback_file',
        title: 'Revertir un archivo individual (time-travel)',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
        description: 'Revierte quirúrgicamente un solo archivo a una secuencia histórica sin tocar los demás archivos del proyecto (soporta dryRun con preview de diff).',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            filePath: { type: 'string', description: 'Ruta relativa del archivo a revertir' },
            seq: { type: 'number', description: 'Número de secuencia objetivo del historial' }
          },
          required: ['projectId', 'filePath', 'seq']
        }
      },
      {
        name: 'culkibo_sync_conflicts',
        title: 'Listar conflictos optimistas multi-cliente de Live Sync',
        annotations: { readOnlyHint: true, openWorldHint: false },
        description: 'Lista los conflictos recientes de edición concurrente detectados entre varios clientes/agentes conectados a Live Sync 2.0.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            limit: { type: 'number', description: 'Máximo de conflictos a listar (default 20)' }
          },
          required: ['projectId']
        }
      },

      // --- MCP 2.0: H. Smoke Tests, Canary Auto-Guard y Deploy Freeze (4) ---
      {
        name: 'culkibo_smoke_test_configure',
        title: 'Configurar pruebas smoke post-despliegue',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        description: 'Define comprobaciones HTTP smoke relativas al contenedor (ruta, código esperado, subcadena literal y latencia máxima) ejecutadas antes de promocionar tráfico.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            enabled: { type: 'boolean', description: 'Activar ejecución automática en cada deploy (default true)' },
            failPolicy: { type: 'string', enum: ['rollback', 'abort', 'warn'], description: 'Política ante fallo (default rollback)' },
            checks: {
              type: 'array',
              items: { type: 'object' },
              description: 'Lista de 1 a 10 checks ({ path, method, expectedStatus, bodyContains, maxLatencyMs })'
            }
          },
          required: ['projectId', 'checks']
        }
      },
      {
        name: 'culkibo_smoke_test_run',
        title: 'Ejecutar pruebas smoke en vivo contra un proyecto',
        annotations: { readOnlyHint: true, openWorldHint: true },
        description: 'Ejecuta las pruebas smoke configuradas (o ad-hoc) en vivo contra Citadel, Forge o Canary devolviendo resultado y latencia en ms.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            target: { type: 'string', enum: ['citadel', 'forge', 'canary'], description: 'Objetivo de las pruebas (default citadel)' },
            checks: { type: 'array', items: { type: 'object' }, description: 'Checks opcionales ad-hoc (sobrescriben los guardados para esta ejecución)' }
          },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_canary_rollout',
        title: 'Controlar despliegue progresivo Canary Auto-Guard',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
        description: 'Inicia, avanza, promociona al 100%, aborta o consulta un despliegue progresivo con pesos en Caddy y auto-rollback si fallan los smoke checks.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', description: 'ID del proyecto' },
            action: { type: 'string', enum: ['start', 'advance', 'promote', 'abort', 'status'], description: 'Acción sobre el rollout canario' },
            steps: { type: 'array', items: { type: 'number' }, description: 'Pasos ascendentes de porcentaje canario (p. ej. [10, 50, 100])' },
            stepIntervalSec: { type: 'number', description: 'Segundos de observación por paso (default 15)' },
            weightPercent: { type: 'number', description: 'Peso canario explícito opcional (1-100)' },
            autoRollbackOnSmokeFail: { type: 'boolean', description: 'Revertir automáticamente al 100% estable ante fallo (default true)' }
          },
          required: ['projectId', 'action']
        }
      },
      {
        name: 'culkibo_deploy_freeze',
        title: 'Gestionar ventanas de congelación de despliegues (Freeze)',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Lista, configura o elimina ventanas de congelación horaria (globales o por proyecto) que bloquean despliegues y promociones salvo override explícito de admin/owner.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['list', 'set', 'remove'], description: 'Acción: list, set o remove' },
            projectId: { type: 'string', description: 'ID del proyecto (omitir para ventanas globales)' },
            windows: {
              type: 'array',
              items: { type: 'object' },
              description: 'Ventanas [{ days, startUtc, endUtc, startHour, endHour, tz, reason }] (para set)'
            },
            windowId: { type: 'string', description: 'ID de ventana a eliminar (opcional para remove)' }
          },
          required: ['action']
        }
      }
    ];

    // Inyección automática del parámetro opcional `dryRun` en todas las herramientas
    // destructivas (25) + deploy_production y rollback_deployment (27 en total).
    for (const tool of this._toolsCache) {
      if (tool.annotations?.destructiveHint === true || EXTRA_DRY_RUN_TOOLS.has(tool.name)) {
        if (!tool.inputSchema) tool.inputSchema = { type: 'object', properties: {} };
        if (!tool.inputSchema.properties) tool.inputSchema.properties = {};
        if (!tool.inputSchema.properties.dryRun) {
          tool.inputSchema.properties.dryRun = {
            type: 'boolean',
            description: 'Si es true, previsualiza el plan y radio de impacto (DryRunPlan) sin mutar estado ni enviar webhooks.'
          };
        }
      }
    }

    this._toolsByName = new Map(this._toolsCache.map((t) => [t.name, t]));
    return this._toolsCache;
  }

  /**
   * Devuelve las herramientas visibles para un principal RBAC concreto.
   * @param {any} [authOrPrincipal]
   */
  getToolsForPrincipal(authOrPrincipal = null) {
    const all = this.getToolsDefinition();
    const principal = normalizePrincipal(authOrPrincipal);
    if (principal.isSuperAdmin) return all;
    return all.filter((tool) => isToolAllowedForPrincipal(principal, tool.name, tool));
  }

  /**
   * Indica si una herramienta soporta previsualización universal `dryRun: true`.
   * @param {string} toolName
   */
  supportsDryRun(toolName) {
    const tool = this.getToolByName(toolName);
    if (!tool) return false;
    return Boolean(tool.annotations?.destructiveHint === true || EXTRA_DRY_RUN_TOOLS.has(toolName));
  }

  /**
   * Buffer JSON pre-serializado para GET /api/mcp/tools.
   * Si el principal no es superadmin o está acotado por scopes/proyectos,
   * NUNCA reutiliza el caché global público y responde con `cacheScope: 'private'`.
   * @param {any} [authOrPrincipal]
   */
  getToolsSerialized(authOrPrincipal = null) {
    const principal = normalizePrincipal(authOrPrincipal);
    if (principal.isSuperAdmin) {
      if (!this._toolsSerializedCache) {
        const tools = this.getToolsDefinition();
        this._toolsSerializedCache = Buffer.from(JSON.stringify({
          protocolVersion: PROTOCOL_VERSION,
          tools,
          count: tools.length,
          cacheScope: 'public'
        }), 'utf8');
      }
      return this._toolsSerializedCache;
    }
    const tools = this.getToolsForPrincipal(principal);
    return Buffer.from(JSON.stringify({
      protocolVersion: PROTOCOL_VERSION,
      tools,
      count: tools.length,
      cacheScope: 'private'
    }), 'utf8');
  }

  getToolByName(toolName) {
    if (!this._toolsByName) this.getToolsDefinition();
    return (this._toolsByName && this._toolsByName.get(toolName)) || null;
  }

  /**
   * Resuelve referencias directas e indirectas a proyectos para aplicar ACL anti-IDOR.
   * @param {string} toolName
   * @param {any} args
   */
  resolveTargetRefs(toolName, args) {
    /** @type {Array<{ projectId: string | null, resourceKind: string, missing: boolean }>} */
    const refs = [];
    if (args.projectId) {
      refs.push({ projectId: String(args.projectId), resourceKind: 'project', missing: !projectManager.getById(String(args.projectId)) });
    }
    if (args.databaseId) {
      const allDbs = databaseManager.list();
      const db = allDbs.find((d) => d.id === args.databaseId);
      refs.push({ projectId: db?.projectId || null, resourceKind: 'database', missing: !db });
    }
    if (args.cronId) {
      const allCrons = cronManager.list();
      const cron = Array.isArray(allCrons) ? allCrons.find((c) => c.id === args.cronId) : null;
      refs.push({ projectId: cron?.projectId || null, resourceKind: 'cron', missing: !cron });
    }
    if ((toolName === 'culkibo_manage_domain' && args.action !== 'list' && args.action !== 'add') || toolName === 'culkibo_set_domain_basic_auth') {
      const lookupId = args.domainId || args.id || args.hostname;
      if (lookupId) {
        const list = domainManager.listDomains();
        const dom = list.find((d) => d.id === lookupId || d.hostname === lookupId);
        refs.push({ projectId: dom?.projectId || null, resourceKind: 'domain', missing: !dom });
      }
    }
    if (args.monitorId) {
      const um = lazySvc('uptimeMonitor');
      const mons = um && typeof um.listMonitors === 'function' ? um.listMonitors() : [];
      const mon = Array.isArray(mons) ? mons.find((m) => m.id === args.monitorId) : null;
      refs.push({ projectId: mon?.projectId || null, resourceKind: 'monitor', missing: !mon });
    }
    if (toolName === 'culkibo_status_page_manage' && Array.isArray(args.monitorIds) && args.monitorIds.length > 0) {
      const um = lazySvc('uptimeMonitor');
      const mons = um && typeof um.listMonitors === 'function' ? um.listMonitors() : [];
      for (const mid of args.monitorIds) {
        const mon = Array.isArray(mons) ? mons.find((m) => m.id === String(mid)) : null;
        refs.push({ projectId: mon?.projectId || null, resourceKind: 'monitor', missing: !mon });
      }
    }
    if (args.installationId) {
      const insts = catalogManager.list();
      const inst = Array.isArray(insts) ? insts.find((i) => i.id === args.installationId) : null;
      refs.push({ projectId: inst?.projectId || null, resourceKind: 'catalog_installation', missing: !inst });
    }
    return refs;
  }

  /**
   * Puerta RBAC + ACL por proyecto/recurso. Se ejecuta SIEMPRE antes de `dryRun` y
   * antes del despachador para impedir sondeos IDOR vía `dryRun: true`.
   * @param {ReturnType<typeof normalizePrincipal>} principal
   * @param {string} toolName
   * @param {any} args
   */
  assertAuthorized(principal, toolName, args) {
    if (principal.isSuperAdmin) return;

    const tool = this.getToolByName(toolName);
    const policy = TOOL_POLICIES[toolName];
    if (!policy || !isToolAllowedForPrincipal(principal, toolName, tool)) {
      throw new McpToolError('FORBIDDEN', `Acceso denegado: tu rol '${principal.role}' o los scopes del token no autorizan '${toolName}'.`, {
        retryable: false,
        remediation: 'Consulta tus permisos efectivos con culkibo_rbac_whoami o solicita un token con el alcance adecuado.'
      });
    }

    // Reglas anti-escalada de privilegios
    const callerRank = ROLE_RANK[principal.role] || 0;
    if (toolName === 'culkibo_team_invite_member' || toolName === 'culkibo_team_update_member' || toolName === 'culkibo_rbac_manage_token') {
      if (args.role) {
        const targetRank = ROLE_RANK[String(args.role).toLowerCase()] || 999;
        if (String(args.role).toLowerCase() === 'owner' && principal.role !== 'owner') {
          throw new McpToolError('FORBIDDEN', 'Solo un owner puede otorgar o gestionar el rol owner.', { retryable: false });
        }
        if (toolName === 'culkibo_rbac_manage_token' && targetRank > callerRank) {
          throw new McpToolError('FORBIDDEN', 'No puedes emitir un token con un rol superior al tuyo.', { retryable: false });
        }
        if (toolName !== 'culkibo_rbac_manage_token' && principal.role !== 'owner' && targetRank >= callerRank) {
          throw new McpToolError('FORBIDDEN', 'Un admin solo puede gestionar o invitar roles developer y viewer.', { retryable: false });
        }
      }
    }

    if (toolName === 'culkibo_export_instance_snapshot' && args.includeSecrets === true && principal.role !== 'owner') {
      throw new McpToolError('FORBIDDEN', 'Exportar snapshots de instancia con secretos sin redactar requiere rol owner.', { retryable: false });
    }

    // Aislamiento de equipo en argumentos explícitos (teamId y serverId) antes de dryRun
    if (principal.teamId && args.teamId && String(args.teamId) !== principal.teamId) {
      throw new McpToolError('FORBIDDEN', 'No tienes acceso al equipo especificado.', { retryable: false });
    }
    if (principal.teamId && args.serverId && String(args.serverId) !== 'local') {
      const fleet = lazySvc('serverFleetManager');
      if (fleet && typeof fleet.getServer === 'function') {
        const srv = fleet.getServer(String(args.serverId));
        if (!srv || (srv.teamId && srv.teamId !== principal.teamId)) {
          throw new McpToolError('FORBIDDEN', 'No tienes acceso al servidor especificado.', { retryable: false });
        }
      }
    }

    // Verificación ACL directa e indirecta (sin revelar existencia de IDs ajenos: anti-IDOR)
    const refs = this.resolveTargetRefs(toolName, args);

    // Un token acotado a `projectIds` concretos NUNCA puede escapar a mutaciones globales sin proyecto objetivo.
    if (Array.isArray(principal.projectIds) && tool && !tool.annotations?.readOnlyHint && refs.length === 0) {
      throw new McpToolError('FORBIDDEN', 'Un token acotado a proyectos concretos no puede ejecutar mutaciones globales.', {
        retryable: false
      });
    }

    const minRank = ROLE_RANK[policy.minRole] || ROLE_RANK.owner;
    const hasRestrictedScope = Array.isArray(principal.projectIds) || Boolean(principal.teamId);
    let minEffectiveProjectRank = callerRank;
    for (const ref of refs) {
      if (ref.missing && hasRestrictedScope) {
        throw new McpToolError('FORBIDDEN', 'No tienes acceso al recurso especificado.', { retryable: false });
      }
      const effRole = resolveEffectiveProjectRole(principal, ref.projectId);
      if (!effRole) {
        throw new McpToolError('FORBIDDEN', 'No tienes acceso al proyecto especificado.', { retryable: false });
      }
      const effRank = ROLE_RANK[effRole] || 0;
      if (effRank < minRank) {
        throw new McpToolError('FORBIDDEN', `Tu rol efectivo ('${effRole}') sobre el proyecto no autoriza '${toolName}'.`, {
          retryable: false
        });
      }
      if (effRank < minEffectiveProjectRank) minEffectiveProjectRank = effRank;
    }

    if ((toolName === 'culkibo_deploy_production' || toolName === 'culkibo_env_promote') && args.overrideFreeze === true && minEffectiveProjectRank < ROLE_RANK.admin) {
      throw new McpToolError('FORBIDDEN', 'Solo admin u owner pueden omitir una ventana de deploy freeze.', { retryable: false });
    }

    if (toolName === 'culkibo_env_promote' && String(args.toEnv || '').toLowerCase() === 'production' && minEffectiveProjectRank < ROLE_RANK.admin) {
      const em = lazySvc('environmentManager');
      const envs = em && typeof em.listEnvironments === 'function' ? em.listEnvironments(args.projectId) : null;
      const prodEnv = Array.isArray(envs) ? envs.find((e) => e.name === 'production') : null;
      if (!prodEnv || prodEnv.protected !== false) {
        throw new McpToolError('FORBIDDEN', 'Promocionar a producción protegida requiere rol admin u owner.', { retryable: false });
      }
    }
  }

  /**
   * Genera un plan estructurado `DryRunPlan` inspeccionando estado real sin mutar nada ni disparar webhooks.
   * @param {string} toolName
   * @param {any} args
   * @param {ReturnType<typeof normalizePrincipal>} principal
   */
  async previewToolPlan(toolName, args, principal) {
    /** @type {string[]} */
    const effects = [];
    /** @type {string[]} */
    const blockers = [];
    /** @type {string[]} */
    const warnings = [];
    /** @type {Record<string, any>} */
    const target = {};
    /** @type {Record<string, any>} */
    const preview = {};
    /** @type {'high' | 'medium' | 'low'} */
    let riskLevel = 'medium';
    let reversible = true;

    const project = args.projectId ? projectManager.getById(String(args.projectId)) : null;

    switch (toolName) {
      case 'culkibo_deploy_production':
      case 'culkibo_deploy_project': {
        if (!project) throw projectNotFoundError(args.projectId);
        const freeze = evaluateProjectFreeze(project);
        const targetServer = args.serverId || project.serverId || 'local';
        Object.assign(target, { projectId: project.id, projectName: project.name, serverId: targetServer });
        effects.push(`Construirá/desplegará '${project.name}' en nodo '${targetServer}' y conmutará el tráfico en Caddy.`);
        if (freeze.frozen && !args.overrideFreeze) {
          blockers.push('DEPLOY_FREEZE_ACTIVE');
          warnings.push(`Ventana de deploy freeze activa${freeze.activeWindow?.reason ? `: ${freeze.activeWindow.reason}` : ''}.`);
        }
        if (project.maintenanceMode) warnings.push('El proyecto está actualmente en modo mantenimiento (503).');
        const linkedDbs = Array.isArray(project.linkedDatabaseIds) ? project.linkedDatabaseIds : [];
        if (targetServer !== 'local' && linkedDbs.length > 0) {
          warnings.push(`El proyecto tiene ${linkedDbs.length} BD(s) locales vinculadas; verifica conectividad desde '${targetServer}'.`);
        }
        preview.freeze = freeze;
        preview.linkedDatabases = linkedDbs.length;
        preview.domains = domainManager.listDomains().filter((d) => d.projectId === project.id).map((d) => d.hostname);
        riskLevel = 'high';
        reversible = true;
        break;
      }

      case 'culkibo_rollback_deployment': {
        if (!project) throw projectNotFoundError(args.projectId);
        const status = await deployManager.status(project.id);
        Object.assign(target, { projectId: project.id, projectName: project.name });
        effects.push(`Revertirá la release activa en Citadel de '${project.name}' a la versión anterior.`);
        if (!status?.previous) {
          blockers.push('NO_PREVIOUS_RELEASE');
          warnings.push('No existe una release previa registrada para revertir.');
        }
        preview.currentStatus = status;
        riskLevel = 'medium';
        reversible = true;
        break;
      }

      case 'culkibo_fleet_remove_server': {
        const assigned = projectManager.getAll().filter((p) => (p.serverId || 'local') === args.serverId);
        Object.assign(target, { serverId: args.serverId, assignedProjects: assigned.map((p) => p.id) });
        effects.push(`Eliminará el nodo remoto '${args.serverId}' del registro de la flota.`);
        if (args.serverId === 'local') blockers.push('CANNOT_REMOVE_LOCAL_SERVER');
        if (assigned.length > 0 && !args.force) {
          blockers.push('ACTIVE_PROJECTS_ON_SERVER');
          warnings.push(`Hay ${assigned.length} proyecto(s) asignados a este servidor; reasígnalos o usa force: true.`);
        }
        preview.assignedProjectCount = assigned.length;
        riskLevel = 'high';
        reversible = false;
        break;
      }

      case 'culkibo_fleet_assign_project': {
        if (!project) throw projectNotFoundError(args.projectId);
        const fromServer = project.serverId || 'local';
        Object.assign(target, { projectId: project.id, fromServerId: fromServer, toServerId: args.serverId });
        effects.push(`Reasignará '${project.name}' del nodo '${fromServer}' al nodo '${args.serverId}'.`);
        if (args.serverId !== 'local' && Array.isArray(project.linkedDatabaseIds) && project.linkedDatabaseIds.length > 0) {
          warnings.push('El proyecto tiene bases de datos locales vinculadas que no serán accesibles desde un nodo remoto sin red compartida.');
        }
        riskLevel = 'medium';
        reversible = true;
        break;
      }

      case 'culkibo_env_promote': {
        if (!project) throw projectNotFoundError(args.projectId);
        const freeze = evaluateProjectFreeze(project);
        Object.assign(target, { projectId: project.id, fromEnv: args.fromEnv, toEnv: args.toEnv });
        effects.push(`Promocionará release de '${args.fromEnv}' a '${args.toEnv}' en '${project.name}'${args.includeEnvVars ? ' incluyendo variables de entorno' : ''}.`);
        if (freeze.frozen && !args.overrideFreeze) blockers.push('DEPLOY_FREEZE_ACTIVE');
        const em = lazySvc('environmentManager');
        if (em && typeof em.diffEnvironments === 'function') {
          try {
            preview.envDiff = em.diffEnvironments(project.id, args.fromEnv, args.toEnv);
          } catch (e) {
            warnings.push(`No se pudo calcular diff de entornos: ${e.message}`);
          }
        }
        preview.freeze = freeze;
        riskLevel = String(args.toEnv).toLowerCase() === 'production' ? 'high' : 'medium';
        reversible = true;
        break;
      }

      case 'culkibo_gitops_apply': {
        Object.assign(target, { prune: Boolean(args.prune), confirmDestructive: Boolean(args.confirmDestructive) });
        const gm = lazySvc('gitopsManager');
        if (gm && typeof gm.planApply === 'function') {
          const plan = gm.planApply(args.yamlText, { prune: Boolean(args.prune) });
          preview.gitopsPlan = plan;
          effects.push(`Reconciliará culkibo.yaml: +${(plan.create || []).length} crear, ~${(plan.update || []).length} actualizar, -${(plan.delete || []).length} eliminar.`);
          if (Array.isArray(plan.warnings)) warnings.push(...plan.warnings);
        } else {
          blockers.push('SERVICE_UNAVAILABLE');
          warnings.push('gitopsManager no está disponible todavía.');
        }
        riskLevel = args.prune ? 'high' : 'medium';
        reversible = !args.prune;
        break;
      }

      case 'culkibo_sync_rollback_file': {
        if (!project) throw projectNotFoundError(args.projectId);
        Object.assign(target, { projectId: project.id, filePath: args.filePath, seq: Number(args.seq) });
        effects.push(`Revertirá únicamente '${args.filePath}' a la secuencia #${args.seq} en The Forge.`);
        if (typeof liveSyncEngine.getFileHistory === 'function') {
          try {
            const hist = liveSyncEngine.getFileHistory(project.id, args.filePath, { limit: 50, includeDiff: true });
            const versions = Array.isArray(hist?.versions) ? hist.versions : (Array.isArray(hist) ? hist : []);
            const match = versions.find((v) => Number(v.seq) === Number(args.seq));
            preview.currentVersion = versions[0] || null;
            preview.targetVersion = match || null;
            if (!match) blockers.push('SYNC_SEQ_NOT_FOUND');
          } catch (e) {
            warnings.push(`Historial no disponible para preview: ${e.message}`);
          }
        } else {
          warnings.push('LiveSync 2.0 getFileHistory no está disponible para generar diff.');
        }
        riskLevel = 'medium';
        reversible = true;
        break;
      }

      case 'culkibo_delete_database': {
        const db = databaseManager.list().find((d) => d.id === args.databaseId);
        const dependents = projectManager.getAll().filter((p) => Array.isArray(p.linkedDatabaseIds) && p.linkedDatabaseIds.includes(args.databaseId));
        Object.assign(target, { databaseId: args.databaseId, name: db?.name || null, deleteVolume: Boolean(args.deleteVolume) });
        effects.push(`Eliminará la base de datos '${db?.name || args.databaseId}'${args.deleteVolume ? ' Y SU VOLUMEN PERSISTENTE (IRREVERSIBLE)' : ''}.`);
        if (dependents.length > 0) {
          warnings.push(`Hay ${dependents.length} proyecto(s) vinculados a esta BD: ${dependents.map((p) => p.id).join(', ')}.`);
        }
        preview.dependentProjects = dependents.map((p) => ({ id: p.id, name: p.name }));
        riskLevel = 'high';
        reversible = !args.deleteVolume;
        break;
      }

      case 'culkibo_set_project_env': {
        if (!project) throw projectNotFoundError(args.projectId);
        const existingKeys = Object.keys(project.envVars || {});
        const incomingKeys = Object.keys(args.envVars || {});
        const overwritten = incomingKeys.filter((k) => existingKeys.includes(k));
        const added = incomingKeys.filter((k) => !existingKeys.includes(k));
        Object.assign(target, { projectId: project.id, resourceId: args.resourceId || null });
        effects.push(`Añadirá ${added.length} clave(s) y sobrescribirá ${overwritten.length} clave(s) en '${project.name}' (valores redactados).`);
        preview.addedKeys = added;
        preview.overwrittenKeys = overwritten;
        riskLevel = overwritten.length > 0 ? 'medium' : 'low';
        reversible = false;
        break;
      }

      case 'culkibo_toggle_maintenance': {
        if (!project) throw projectNotFoundError(args.projectId);
        const domains = domainManager.listDomains().filter((d) => d.projectId === project.id).map((d) => d.hostname);
        Object.assign(target, { projectId: project.id, enabled: Boolean(args.enabled), domains });
        effects.push(args.enabled
          ? `Activará HTTP 503 de mantenimiento en ${domains.length} dominio(s) de '${project.name}'.`
          : `Restaurará tráfico normal en ${domains.length} dominio(s) de '${project.name}'.`);
        riskLevel = args.enabled ? 'high' : 'low';
        reversible = true;
        break;
      }

      case 'culkibo_team_update_member': {
        Object.assign(target, { action: args.action, memberId: args.memberId, role: args.role || null });
        effects.push(`Ejecutará '${args.action}' sobre miembro '${args.memberId}' y revocará sus sesiones activas.`);
        riskLevel = args.action === 'remove' ? 'high' : 'medium';
        reversible = args.action !== 'remove';
        break;
      }

      case 'culkibo_rbac_manage_token': {
        Object.assign(target, { action: args.action, tokenId: args.tokenId || null, role: args.role || principal.role });
        effects.push(args.action === 'revoke'
          ? `Revocará inmediatamente el token '${args.tokenId}'.`
          : `Creará un nuevo token API/MCP '${args.name || 'MCP Token'}' con scopes ${(args.scopes || ['*']).join(', ')}.`);
        riskLevel = args.action === 'revoke' ? 'high' : 'medium';
        reversible = false;
        break;
      }

      case 'culkibo_uptime_delete_monitor': {
        Object.assign(target, { monitorId: args.monitorId });
        effects.push(`Eliminará el monitor sintético '${args.monitorId}' y su historial de comprobaciones.`);
        riskLevel = 'medium';
        reversible = false;
        break;
      }

      case 'culkibo_sleep_manage': {
        if (!project) throw projectNotFoundError(args.projectId);
        Object.assign(target, { projectId: project.id, action: args.action, mode: args.mode || 'stop' });
        effects.push(`Ejecutará Smart Sleep '${args.action}' sobre '${project.name}'.`);
        riskLevel = args.action === 'sleep' ? 'medium' : 'low';
        reversible = true;
        break;
      }

      case 'culkibo_canary_rollout': {
        if (!project) throw projectNotFoundError(args.projectId);
        Object.assign(target, { projectId: project.id, action: args.action, steps: args.steps || null });
        effects.push(`Ejecutará operación Canary '${args.action}' sobre el enrutado Caddy de '${project.name}'.`);
        if (typeof deployManager.getCanaryState === 'function') {
          preview.activeCanary = deployManager.getCanaryState(project.id);
        }
        riskLevel = args.action === 'status' ? 'low' : 'high';
        reversible = true;
        break;
      }

      case 'culkibo_deploy_freeze': {
        Object.assign(target, { action: args.action, projectId: args.projectId || 'global' });
        effects.push(`Ejecutará '${args.action}' sobre ventanas de deploy freeze (${args.projectId || 'instancia global'}).`);
        riskLevel = 'medium';
        reversible = true;
        break;
      }

      default: {
        Object.assign(target, redactForAudit(args));
        effects.push(`Ejecutará la herramienta destructiva '${toolName}' con los parámetros validados.`);
        if (toolName === 'culkibo_restore_backup' || toolName === 'culkibo_database_restore' || toolName === 'culkibo_uninstall_catalog_service') {
          riskLevel = 'high';
          reversible = false;
        }
        break;
      }
    }

    return {
      dryRun: true,
      tool: toolName,
      wouldExecute: blockers.length === 0,
      riskLevel,
      reversible,
      target,
      effects,
      blockers,
      warnings,
      preview,
      nextStep: blockers.length > 0
        ? `Resuelve los bloqueos (${blockers.join(', ')}) antes de ejecutar '${toolName}' sin dryRun.`
        : `Revisa el plan y vuelve a invocar '${toolName}' sin dryRun (o con dryRun: false) para aplicar los cambios.`
    };
  }

  /**
   * @param {string} toolName
   * @param {any} args
   * @param {any} result
   * @param {boolean} [success]
   * @param {number} [durationMs]
   * @param {string} [transport]
   * @param {any} [clientInfo]
   * @param {{ dryRun?: boolean, principal?: ReturnType<typeof normalizePrincipal> | null }} [meta]
   */
  logCall(toolName, args, result, success = true, durationMs = 0, transport = 'MCP stdio/sse', clientInfo = null, meta = {}) {
    const safeArgs = redactForAudit(args);
    const isDryRun = Boolean(meta && meta.dryRun);
    let resultSummary;
    if (REDACTED_RESULT_TOOLS.has(toolName) && success && !isDryRun) {
      resultSummary = '[resultado sensible ocultado en auditoría]';
    } else if (typeof result === 'object' && result !== null) {
      resultSummary = JSON.stringify(redactForAudit(result)).slice(0, 160);
    } else {
      resultSummary = String(redactForAudit(result));
    }
    const clientLabel = clientInfo && clientInfo.name
      ? `${String(clientInfo.name).slice(0, 60)}${clientInfo.version ? ` v${String(clientInfo.version).slice(0, 20)}` : ''}`
      : 'AI Assistant';
    const principal = meta && meta.principal ? meta.principal : null;
    const entry = {
      id: `mcp_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      toolName,
      args: safeArgs,
      resultSummary,
      success,
      dryRun: isDryRun,
      durationMs: Math.round(durationMs),
      transport,
      actor: principal
        ? { userId: principal.userId, role: principal.role, teamId: principal.teamId, method: principal.method }
        : { userId: null, role: 'owner', teamId: null, method: 'legacy' },
      agent: `${clientLabel} (${transport})`
    };
    this.auditLog.unshift(entry);
    if (this.auditLog.length > this.maxAuditLogs) this.auditLog.pop();
    this.emit('mcp_call', entry);
    return entry;
  }

  /**
   * Devuelve el registro de auditoría MCP acotado al principal si no es superadmin.
   * @param {number} [limit]
   * @param {any} [authOrPrincipal]
   */
  getAuditLog(limit = 50, authOrPrincipal = null) {
    const principal = normalizePrincipal(authOrPrincipal);
    if (principal.isSuperAdmin) {
      return this.auditLog.slice(0, limit);
    }
    const filtered = this.auditLog.filter((entry) => {
      const actor = entry.actor || {};
      if (principal.userId && actor.userId === principal.userId) return true;
      if (principal.role === 'admin' && principal.teamId && actor.teamId === principal.teamId) return true;
      const argProjectId = entry.args && typeof entry.args === 'object' ? entry.args.projectId : null;
      if (argProjectId && canAccessProject(principal, argProjectId)) return true;
      return false;
    });
    return filtered.slice(0, limit);
  }

  /**
   * @param {string} toolName
   * @param {any} args
   * @param {{ transport?: string, clientInfo?: any, signal?: AbortSignal, onProgress?: (msg: string) => void, auth?: any }} [context]
   */
  async executeTool(toolName, args = {}, context = {}) {
    const start = performance.now();
    const transport = context.transport || 'MCP stdio/sse';
    const clientInfo = context.clientInfo || null;
    const principal = normalizePrincipal(context.auth);
    const tool = this.getToolByName(toolName);
    let isDryRun = false;
    try {
      if (context.signal && context.signal.aborted) {
        throw new McpToolError('CANCELLED', 'La invocación de herramienta fue cancelada por el cliente.', { retryable: true });
      }
      if (!tool) {
        throw new McpToolError('UNKNOWN_TOOL', `Esta instalación de Culkibo no expone ninguna herramienta llamada '${toolName}'.`, {
          retryable: false,
          remediation: 'Llama a tools/list para ver el catálogo vigente y usa uno de esos nombres.',
          details: { requested: toolName }
        });
      }
      if (!args || typeof args !== 'object' || Array.isArray(args)) {
        throw new McpToolError('INVALID_ARGUMENTS', 'Los argumentos de la herramienta deben ser un objeto JSON plano.', {
          retryable: true,
          remediation: 'Envía un objeto JSON (por ejemplo `{}` si la herramienta no requiere parámetros).'
        });
      }
      validateToolArguments(tool, args);

      // Puerta RBAC + ACL por proyecto/recurso ANTES de `dryRun` (impide sondeo IDOR vía dryRun).
      this.assertAuthorized(principal, toolName, args);

      // Intercepción universal `dryRun: true` (cero mutaciones, cero webhooks, auditado).
      if (args.dryRun === true && this.supportsDryRun(toolName)) {
        isDryRun = true;
        const plan = await this.previewToolPlan(toolName, args, principal);
        const durationMs = performance.now() - start;
        this.logCall(toolName, args, plan, true, durationMs, transport, clientInfo, { dryRun: true, principal });
        try { require('./telemetryService').recordFeatureUsage(`mcp:${toolName}:dry_run`, true); } catch (e) {}
        return {
          content: [{ type: 'text', text: JSON.stringify(plan, null, 2) }],
          isError: false,
          structuredContent: plan
        };
      }

      let res;
      switch (toolName) {
        case 'culkibo_create_project': {
          const created = projectManager.create({
            name: args.name,
            description: args.description,
            icon: args.icon,
            gitRepo: args.gitRepo,
            forgePort: args.forgePort,
            citadelPort: args.citadelPort,
            ...(principal.teamId ? { teamId: principal.teamId } : {})
          });
          await projectManager.flushToDisk();
          res = redactProjectSecrets(created);
          break;
        }

        case 'culkibo_add_resource': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          const resource = {
            id: `res_${Date.now()}`,
            type: args.type,
            name: args.name,
            image: args.image,
            envVars: args.envVars || {},
            ports: args.ports || [],
            credentials: args.credentials || {},
            status: 'active'
          };
          project.resources = project.resources || [];
          project.resources.push(resource);
          const updated = projectManager.update(args.projectId, { resources: project.resources });
          await projectManager.flushToDisk();
          res = redactProjectSecrets(updated);
          break;
        }

        case 'culkibo_list_projects': {
          const visible = projectManager.getAll().filter((p) => canAccessProject(principal, p.id, p));
          res = {
            projects: visible.map((p) => redactProjectSecrets(p))
          };
          break;
        }

        case 'culkibo_get_project': {
          const p = projectManager.getById(args.projectId);
          if (!p) throw projectNotFoundError(args.projectId);
          res = redactProjectSecrets(p);
          break;
        }

        case 'culkibo_set_project_env': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          if (args.resourceId) {
            const resource = project.resources?.find(r => r.id === args.resourceId || r.name === args.resourceId);
            if (!resource) throw resourceNotFoundError(args.projectId, args.resourceId);
            resource.envVars = { ...(resource.envVars || {}), ...args.envVars };
          } else {
            project.envVars = { ...(project.envVars || {}), ...args.envVars };
          }
          const updated = projectManager.update(args.projectId, { envVars: project.envVars, resources: project.resources });
          await projectManager.flushToDisk();
          res = redactProjectSecrets(updated);
          break;
        }

        case 'culkibo_deploy_project':
          res = projectManager.activate(args.projectId); // Simplified deploy
          break;

        case 'culkibo_list_pods':
          res = containerOrchestrator.getPods();
          break;

        case 'culkibo_hot_sync':
          res = await containerOrchestrator.triggerHotSync({
            changedFile: args.changedFile || 'src/main.ts',
            diffSize: args.diffSize || 'hot sync'
          });
          break;

        case 'culkibo_switch_traffic':
          res = await containerOrchestrator.switchTraffic({
            forgePercent: args.forgePercent !== undefined ? args.forgePercent : 100 - (args.citadelPercent || 0),
            citadelPercent: args.citadelPercent !== undefined ? args.citadelPercent : 100
          });
          res = { ...res, ingress: await ingressManager.reconcile() };
          break;

        case 'culkibo_manage_domain':
          if (args.action === 'list') {
            res = {
              domains: domainManager.listDomains().filter((d) => canAccessProject(principal, d.projectId))
            };
          } else if (args.action === 'add') {
            res = await domainManager.addDomain({
              hostname: args.hostname,
              targetPod: args.targetPod || 'forge',
              cloudflareProxied: args.cloudflareProxied ?? true,
              cloudflareZoneId: args.cloudflareZoneId
            });
          } else if (args.action === 'delete') {
            const list = domainManager.listDomains();
            const found = list.find(d => d.hostname === args.hostname || d.id === args.id);
            if (!found) throw domainNotFoundError(args);
            res = await domainManager.deleteDomain(found.id);
          } else if (args.action === 'toggle_proxy') {
            const list = domainManager.listDomains();
            const found = list.find(d => d.hostname === args.hostname || d.id === args.id);
            if (!found) throw domainNotFoundError(args);
            res = await domainManager.toggleProxy(found.id);
          } else if (args.action === 'update') {
            const list = domainManager.listDomains();
            const found = list.find(d => d.hostname === args.hostname || d.id === args.id);
            if (!found) throw domainNotFoundError(args);
            const updates = {};
            if (args.targetPod) updates.targetPod = args.targetPod;
            if (args.targetPort) updates.targetPort = args.targetPort;
            if (args.cloudflareProxied !== undefined) updates.cloudflareProxied = args.cloudflareProxied;
            res = await domainManager.updateDomain(found.id, updates);
          }
          // Cualquier cambio en el registro de dominios tiene que llegar al
          // plano de datos en el mismo paso, o el agente creerá haber publicado
          // algo que no está publicado.
          if (args.action && args.action !== 'list') {
            res = { ...res, ingress: await ingressManager.reconcile() };
          }
          break;

        case 'culkibo_inspect_ingress': {
          const hostname = args.hostname;
          const route = domainManager.resolveRoute(hostname);
          // `tlsIssuer`/`tlsActive` salían del registro propio de certificados,
          // que se inventaba el emisor y la caducidad. Un agente que pregunte
          // por el TLS de un dominio tiene que recibir el handshake real, no
          // nuestra propia afirmación.
          const tls = await ingressManager.probeTls(hostname, { timeoutMs: 3000 });
          const detection = await caddyManager.detect();
          res = {
            hostname,
            found: Boolean(route),
            matchedRoute: route?.hostname || null,
            isWildcard: route?.isWildcard || false,
            targetPod: route?.targetPod || null,
            targetPort: route?.targetPort || null,
            projectId: route?.projectId || null,
            cloudflareProxied: route?.cloudflareProxied || false,
            dataPlane: 'caddy',
            ingressAvailable: detection.available,
            ingressReason: detection.reason,
            tls,
            trafficSplit: containerOrchestrator.trafficAllocation
          };
          break;
        }

        case 'culkibo_manage_watcher':
          if (args.action === 'start') {
            let watchDir = process.cwd();
            if (args.directory) {
              const resolved = path.resolve(String(args.directory));
              if (process.env.CULKIBO_ALLOW_ARBITRARY_WATCH !== '1') {
                const projectsRoot = path.resolve(__dirname, '..', '..', 'projects');
                const cwdRoot = path.resolve(process.cwd());
                const inProjects = !path.relative(projectsRoot, resolved).startsWith('..') && !path.isAbsolute(path.relative(projectsRoot, resolved));
                const inCwd = !path.relative(cwdRoot, resolved).startsWith('..') && !path.isAbsolute(path.relative(cwdRoot, resolved));
                if (!inProjects && !inCwd) {
                  throw new Error('Solo se permite observar directorios dentro del espacio de trabajo de Culkibo');
                }
              }
              watchDir = resolved;
            }
            res = containerOrchestrator.watchDirectory(watchDir);
          } else if (args.action === 'stop') {
            res = await containerOrchestrator.stopWatching();
          } else {
            res = containerOrchestrator.getWatcherStatus();
          }
          break;

        case 'culkibo_issue_wildcard_ssl':
          res = await sslManager.issueWildcardCertificate({
            domain: args.domain,
            zoneId: args.zoneId,
            provider: args.provider || 'lets_encrypt'
          });
          break;

        case 'culkibo_create_sslip_domain':
          const sslRes = await sslManager.issueOnDemandSslip({
            ip: args.ip || '127.0.0.1',
            service: args.service || 'sslip.io'
          });
          const newDom = await domainManager.addDomain({
            hostname: `app.${sslRes.cert.rootDomain}`,
            targetPod: 'forge',
            targetPort: 3001,
            routingMode: 'direct_dns'
          });
          res = { success: true, certificate: sslRes.cert, domain: newDom, ingress: await ingressManager.reconcile() };
          break;

        case 'culkibo_get_logs':
          res = {
            logs: containerOrchestrator.getLogs({
              pod: args.pod === 'all' ? null : args.pod,
              limit: args.limit || 50,
              search: args.search || ''
            })
          };
          break;

        case 'culkibo_docker_status':
          res = await dockerManager.checkDockerStatus(args.refresh);
          break;

        case 'culkibo_docker_containers': {
          /** @type {any[]} */
          const allContainers = await dockerManager.listContainers({
            all: args.all !== false,
            projectId: args.projectId
          });
          res = {
            containers: principal.isSuperAdmin
              ? allContainers
              : allContainers.filter((c) => canAccessProject(principal, c?.projectId))
          };
          break;
        }

        case 'culkibo_export_backup':
          res = await dbBackupManager.exportProject(args.projectId);
          break;

        case 'culkibo_restore_backup':
          res = await dbBackupManager.restoreProject(args.backupFilePath);
          break;

        case 'culkibo_github_status':
          res = githubService.getStatus();
          break;

        case 'culkibo_github_connect':
          res = await githubService.connect(args.token);
          break;

        case 'culkibo_github_disconnect':
          res = await githubService.disconnect();
          break;

        case 'culkibo_github_list_repos':
          res = await githubService.getRepositories({
            page: args.page || 1,
            perPage: args.perPage || 30,
            search: args.search || ''
          });
          break;

        case 'culkibo_github_get_branches':
          res = await githubService.getBranches(args.owner, args.repo);
          break;

        case 'culkibo_github_auto_detect':
          res = await githubService.autoDetectRepo(args.owner, args.repo, args.branch || 'main');
          break;

        case 'culkibo_create_project_from_github': {
          const analysis = await githubService.autoDetectRepo(args.owner, args.repo, args.branch || 'main');
          const project = projectManager.create({
            name: args.name || args.repo,
            description: args.description || `Proyecto importado desde ${args.owner}/${args.repo}`,
            icon: analysis.icon || '🚀',
            forgePort: analysis.port || 3000,
            citadelPort: Math.floor(Math.random() * (9000 - 8000) + 8000),
            trafficSplit: { forge: 100, citadel: 0 },
            gitRepo: `https://github.com/${args.owner}/${args.repo}.git`,
            gitBranch: args.branch || 'main',
            githubOwner: args.owner,
            githubRepo: args.repo,
            source: 'github',
            buildCommand: analysis.buildCommand || '',
            startCommand: analysis.startCommand || '',
            watchPaths: analysis.watchPaths || ['src/**', 'public/**'],
            envVars: analysis.envVars || {},
            autoDeploy: args.autoDeploy !== false,
            ...(principal.teamId ? { teamId: principal.teamId } : {})
          });
          projectManager.activate(project.id);
          await projectManager.flushToDisk();
          res = { success: true, project: redactProjectSecrets(project), analysis };
          break;
        }

        case 'culkibo_deploy_strategy': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          const contextDir = liveSyncEngine.resolveTargetDir(project.id);
          const strategy = await deployManager.detectStrategy(contextDir, project);
          res = { projectId: project.id, contextDir, strategy };
          break;
        }

        case 'culkibo_deploy_production': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          const onProg = context.onProgress;
          const stageListener = onProg
            ? (ev) => {
                if (ev && ev.projectId === project.id && ev.stage) {
                  onProg(`Despliegue ${project.name}: fase «${ev.stage}»`);
                }
              }
            : null;
          if (stageListener) deployManager.on('stage', stageListener);
          try {
            const targetProject = args.serverId ? { ...project, serverId: String(args.serverId) } : project;
            res = await deployManager.deploy(targetProject, {
              commit: args.commit || null,
              gitSync: args.gitSync !== false,
              overrideFreeze: Boolean(args.overrideFreeze),
              serverId: args.serverId ? String(args.serverId) : undefined,
              trigger: 'mcp'
            });
          } finally {
            if (stageListener) deployManager.off('stage', stageListener);
          }
          break;
        }

        case 'culkibo_list_deployments': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          const rawDeps = deployManager.listDeployments(project.id, Number(args.limit) || 10);
          res = {
            projectId: project.id,
            status: await deployManager.status(project.id),
            // Omitir logLines masivos en el listado; usar culkibo_get_deployment_logs bajo demanda
            deployments: rawDeps.map(({ logLines, ...summary }) => ({
              ...summary,
              logLineCount: Array.isArray(logLines) ? logLines.length : 0
            }))
          };
          break;
        }

        case 'culkibo_rollback_deployment': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw new McpToolError('NOT_FOUND', `Proyecto '${args.projectId}' no encontrado.`, { remediation: 'Usa culkibo_list_projects para obtener un projectId válido.' });
          res = await deployManager.rollback(project.id);
          break;
        }

        case 'culkibo_prune_build_cache': {
          res = await deployManager.pruneBuildCache({
            keepStorageGb: args.keepStorageGb !== undefined ? Number(args.keepStorageGb) : 10,
            untilHours: args.untilHours !== undefined ? Number(args.untilHours) : null
          });
          break;
        }

        case 'culkibo_list_databases': {
          const allDbs = databaseManager.list({ projectId: args.projectId || undefined });
          res = {
            engines: databaseManager.listEngines(),
            databases: principal.isSuperAdmin
              ? allDbs
              : allDbs.filter((d) => canAccessProject(principal, d.projectId))
          };
          break;
        }

        case 'culkibo_create_database': {
          res = await databaseManager.provision({
            projectId: args.projectId,
            engine: args.engine,
            name: args.name,
            dbName: args.dbName,
            memoryMb: args.memoryMb
          });
          break;
        }

        case 'culkibo_database_backup': {
          res = await databaseManager.runBackup(args.databaseId, { trigger: 'mcp' });
          break;
        }

        case 'culkibo_database_credentials': {
          res = databaseManager.getCredentials(args.databaseId);
          break;
        }

        case 'culkibo_delete_database': {
          res = await databaseManager.remove(args.databaseId, { deleteVolume: Boolean(args.deleteVolume) });
          break;
        }

        case 'culkibo_list_catalog_templates': {
          const all = catalogManager.listTemplates();
          const templates = args.category ? all.filter((t) => t.category === args.category) : all;
          res = { categories: catalogManager.listCategories(), templates };
          break;
        }

        case 'culkibo_install_catalog_service': {
          res = await catalogManager.install({
            templateId: args.templateId,
            name: args.name,
            domain: args.domain || null
          });
          break;
        }

        case 'culkibo_list_catalog_installations': {
          const allInsts = catalogManager.list();
          res = {
            installations: principal.isSuperAdmin
              ? allInsts
              : allInsts.filter((i) => canAccessProject(principal, i.projectId))
          };
          break;
        }

        case 'culkibo_uninstall_catalog_service': {
          res = await catalogManager.remove(args.installationId, { deleteVolumes: Boolean(args.deleteVolumes) });
          break;
        }

        case 'culkibo_verify_sync': {
          const verification = liveSyncEngine.verifySync(args.projectId, {
            clientDigest: args.clientDigest || null
          });
          res = { ...verification, telemetry: liveSyncEngine.getStatus(args.projectId) };
          break;
        }

        case 'culkibo_rollback_sync': {
          res = liveSyncEngine.rollback(args.projectId, Number(args.steps) || 1);
          break;
        }

        case 'culkibo_promote_forge': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw new McpToolError('NOT_FOUND', `Proyecto '${args.projectId}' no encontrado.`, { remediation: 'Usa culkibo_list_projects para obtener un projectId válido.' });
          const targetDir = liveSyncEngine.resolveTargetDir(project.id);
          const verification = liveSyncEngine.verifySync(project.id);
          const deployment = await deployManager.deploy(project, {
            contextDir: targetDir,
            gitSync: false,
            trigger: 'mcp_forge_promote'
          });
          res = { promoted: deployment.status === 'activo', workspaceDigest: verification.serverDigest, deployment };
          break;
        }

        case 'culkibo_migrate_coolify': {
          const mode = args.mode === 'import' ? 'import' : 'preview';
          if (mode === 'preview') {
            const preview = await coolifyMigrator.previewMigration(args.coolifyUrl, args.apiToken);
            res = { mode: 'preview', ...preview };
          } else {
            const migration = await coolifyMigrator.executeMigration(args.coolifyUrl, args.apiToken, {
              ...(Array.isArray(args.apps) ? { apps: args.apps } : {}),
              ...(Array.isArray(args.dbs) ? { dbs: args.dbs } : {}),
              ...(Array.isArray(args.services) ? { services: args.services } : {})
            });
            await projectManager.flushToDisk();
            res = { mode: 'import', ...migration };
          }
          break;
        }

        case 'culkibo_analyze_wordpress': {
          res = await wordpressMigrator.analyzeSite(args.url);
          break;
        }

        case 'culkibo_import_compose': {
          if (args.mode === 'import') {
            res = await universalImporter.importDockerCompose({
              yamlText: args.yamlText,
              projectName: args.projectName || ''
            });
            await projectManager.flushToDisk();
          } else {
            res = universalImporter.parseDockerCompose(args.yamlText);
          }
          break;
        }

        case 'culkibo_get_remote_access': {
          const base = args.serverUrl || (ingressManager.panelDomain ? `https://${ingressManager.panelDomain}` : `http://localhost:${process.env.PORT || 3030}`);
          res = {
            panelDomain: ingressManager.panelDomain || null,
            caddy: await caddyManager.detect(),
            cloudflare: cloudflareService.getConfigStatus(),
            clientConfigs: this.getClientConfigs(base)
          };
          break;
        }

        case 'culkibo_get_observability': {
          res = metricsCollector.getSnapshot(Boolean(args.fresh));
          break;
        }

        case 'culkibo_system_doctor': {
          res = await systemDoctor.runDoctor();
          break;
        }

        case 'culkibo_link_database': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          const db = databaseManager.get(args.databaseId);
          const current = new Set(Array.isArray(project.linkedDatabaseIds) ? project.linkedDatabaseIds : []);
          const action = args.action === 'unlink' ? 'unlink' : 'link';
          if (action === 'link') current.add(db.id);
          else current.delete(db.id);
          const updated = projectManager.update(project.id, { linkedDatabaseIds: Array.from(current) });
          await projectManager.flushToDisk();
          res = {
            success: true,
            action,
            projectId: project.id,
            databaseId: db.id,
            databaseName: db.name,
            linkedDatabaseIds: updated.linkedDatabaseIds,
            note: action === 'link'
              ? 'Base de datos vinculada. Redespliega el proyecto para adjuntar la red aislada e inyectar la URL de conexión.'
              : 'Base de datos desvinculada. Redespliega para aplicar los cambios.'
          };
          break;
        }

        case 'culkibo_toggle_maintenance': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          const enabled = Boolean(args.enabled);
          projectManager.update(project.id, { maintenanceMode: enabled });
          await projectManager.flushToDisk();
          const ingress = await ingressManager.reconcile();
          res = {
            success: true,
            projectId: project.id,
            maintenanceMode: enabled,
            ingress
          };
          break;
        }

        case 'culkibo_get_deploy_queue': {
          res = deployManager.getQueueStatus();
          break;
        }

        case 'culkibo_get_container_logs': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          res = await deployManager.getRuntimeLogs(project.id, { lines: Number(args.lines) || 200 });
          break;
        }

        case 'culkibo_get_deployment_logs': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          const all = deployManager.listDeployments(project.id, 30);
          const dep = args.deploymentId
            ? all.find((d) => d.id === args.deploymentId)
            : all[0];
          if (!dep) throw new McpToolError('NOT_FOUND', 'Despliegue no encontrado para este proyecto.', { remediation: 'Usa culkibo_list_deployments para consultar los IDs.' });
          const tail = Math.min(2000, Math.max(10, Number(args.tail) || 200));
          const lines = Array.isArray(dep.logLines) ? dep.logLines.slice(-tail) : [];
          res = { projectId: project.id, deploymentId: dep.id, status: dep.status, stage: dep.stage, totalLines: (dep.logLines || []).length, lines };
          break;
        }

        case 'culkibo_cancel_deployment': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          res = await deployManager.cancelDeploy(project.id);
          break;
        }

        case 'culkibo_diagnose_domain': {
          res = await ingressManager.diagnoseDomain(String(args.hostname));
          break;
        }

        case 'culkibo_ingress_status': {
          res = await ingressManager.status({ probe: Boolean(args.probe) });
          break;
        }

        case 'culkibo_reconcile_ingress': {
          res = await ingressManager.reconcile();
          break;
        }

        case 'culkibo_manage_production_service': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          if (args.action === 'stop' || args.action === 'hibernate') {
            res = await deployManager.stop(project.id);
          } else if (args.action === 'start' || args.action === 'restart') {
            res = await deployManager.restart(project.id);
          }
          break;
        }

        case 'culkibo_system_doctor_fix': {
          res = await systemDoctor.applyFix(String(args.action));
          break;
        }

        case 'culkibo_database_schedule': {
          /** @type {any} */
          let db = databaseManager.get(args.databaseId);
          if (args.enabled !== undefined || args.cron !== undefined) {
            db = databaseManager.setSchedule(args.databaseId, {
              enabled: args.enabled !== undefined ? Boolean(args.enabled) : db.schedule?.enabled,
              cron: args.cron !== undefined ? String(args.cron) : db.schedule?.cron
            });
          }
          if (args.hourly !== undefined || args.daily !== undefined || args.weekly !== undefined) {
            db = databaseManager.setRetention(args.databaseId, {
              hourly: args.hourly ?? db.retention?.hourly ?? 0,
              daily: args.daily ?? db.retention?.daily ?? 7,
              weekly: args.weekly ?? db.retention?.weekly ?? 4
            });
          }
          res = { success: true, database: db };
          break;
        }

        case 'culkibo_database_restore': {
          if (!args.backupId && !args.remoteKey) {
            throw new McpToolError('MISSING_ARGUMENT', 'Debes indicar backupId o remoteKey.', {
              retryable: true,
              remediation: 'Consulta copias con culkibo_database_list_backups y pasa backupId.'
            });
          }
          res = await databaseManager.restore(args.databaseId, {
            backupId: args.backupId || null,
            remoteKey: args.remoteKey || null,
            createSafetySnapshot: args.createSafetySnapshot !== false
          });
          break;
        }

        case 'culkibo_database_list_backups': {
          res = { databaseId: args.databaseId, backups: databaseManager.listBackups(args.databaseId) };
          break;
        }

        case 'culkibo_database_inspect': {
          res = await databaseManager.inspectDatabase(args.databaseId);
          break;
        }

        case 'culkibo_list_backups': {
          res = { backups: await dbBackupManager.listBackups() };
          break;
        }

        case 'culkibo_export_instance_snapshot': {
          const exported = await dbBackupManager.exportInstanceSnapshot({
            includeSecrets: Boolean(args.includeSecrets),
            passphrase: args.passphrase ? String(args.passphrase) : '',
            uploadToS3: Boolean(args.uploadToS3)
          });
          // No volcar el JSON completo de la instancia si tiene secretos; devolver resumen + fileName
          res = {
            success: exported.success,
            fileName: exported.fileName,
            remoteKey: exported.remoteKey,
            checksum: exported.checksum,
            encrypted: exported.encrypted,
            secretsRedacted: exported.secretsRedacted,
            counts: exported.counts
          };
          break;
        }

        case 'culkibo_manage_wildcard_dns01': {
          if (args.action === 'list') {
            res = { policies: ingressManager.listWildcardPolicies() };
          } else if (args.action === 'add') {
            if (!args.domain) throw new McpToolError('MISSING_ARGUMENT', 'Falta domain para añadir política wildcard.', { retryable: true });
            res = await ingressManager.addWildcardPolicy(args.domain, { includeApex: args.includeApex !== false });
          } else if (args.action === 'remove') {
            if (!args.domain) throw new McpToolError('MISSING_ARGUMENT', 'Falta domain para eliminar política wildcard.', { retryable: true });
            res = await ingressManager.removeWildcardPolicy(args.domain);
          }
          break;
        }

        case 'culkibo_set_domain_basic_auth': {
          const dom = domainManager.getById(args.domainId) || domainManager.getByHostname(args.domainId);
          if (!dom) throw new McpToolError('NOT_FOUND', `Dominio '${args.domainId}' no encontrado.`, { remediation: 'Usa culkibo_manage_domain con action "list" para listar los dominios.' });
          const basicAuth = args.enabled
            ? { enabled: true, users: [{ username: String(args.username || ''), password: String(args.password || '') }] }
            : { enabled: false, users: [] };
          const updated = await domainManager.updateDomain(dom.id, { basicAuth });
          const ingress = await ingressManager.reconcile();
          res = { success: true, domain: updated, ingress };
          break;
        }

        case 'culkibo_notifications': {
          if (args.action === 'get') {
            res = notificationService.getConfig();
          } else if (args.action === 'history') {
            res = { notifications: notificationService.getHistory(Math.min(100, Number(args.limit) || 20)) };
          } else if (args.action === 'test') {
            res = await notificationService.notify({
              event: 'info',
              level: 'info',
              title: 'Prueba de alerta desde MCP',
              message: 'Notificación de prueba disparada por un agente MCP conectado a Culkibo.',
              force: true
            });
          }
          break;
        }

        case 'culkibo_manage_webhook': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          if (args.action === 'rotate_deploy_hook') {
            res = await webhookService.rotateDeployHookToken(project.id);
          } else {
            res = {
              projectId: project.id,
              autoDeploy: project.autoDeploy !== false,
              branch: project.gitBranch || 'main',
              hasWebhookSecret: Boolean(project.webhookSecret),
              hasDeployHookToken: Boolean(project.deployHookToken),
              endpoints: {
                github: `/api/webhooks/github?projectId=${project.id}`,
                gitlab: `/api/webhooks/gitlab?projectId=${project.id}`,
                gitea: `/api/webhooks/gitea?projectId=${project.id}`,
                bitbucket: `/api/webhooks/bitbucket?projectId=${project.id}`,
                deployHook: `/api/webhooks/deploy/${project.id}`
              }
            };
          }
          break;
        }

        case 'culkibo_manage_crons': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          if (args.action === 'list') {
            res = { projectId: project.id, crons: cronManager.list(project.id) };
          } else if (args.action === 'create') {
            const rawMode = String(args.mode || args.kind || 'exec').toLowerCase();
            const mode = rawMode === 'http' ? 'http' : 'exec';
            let httpPath = args.httpPath;
            if (!httpPath && typeof args.url === 'string' && args.url.trim()) {
              const trimmedUrl = args.url.trim();
              if (trimmedUrl.startsWith('/')) {
                httpPath = trimmedUrl;
              } else {
                try {
                  const u = new URL(trimmedUrl);
                  httpPath = `${u.pathname}${u.search}`;
                } catch (e) {
                  httpPath = trimmedUrl;
                }
              }
            }
            res = cronManager.create(project.id, {
              name: args.name,
              schedule: args.schedule,
              mode,
              command: args.command,
              httpPath: httpPath || '/',
              httpMethod: args.httpMethod || 'POST',
              enabled: args.enabled !== false
            });
          } else if (args.action === 'toggle') {
            if (!args.cronId) throw new McpToolError('MISSING_ARGUMENT', 'Falta cronId para toggle.', { retryable: true });
            const ownsCron = cronManager.list(project.id).some((c) => c.id === args.cronId);
            if (!ownsCron) {
              throw new McpToolError(principal.isSuperAdmin ? 'NOT_FOUND' : 'FORBIDDEN', `El cron '${args.cronId}' no pertenece al proyecto '${project.id}'.`, { retryable: false });
            }
            res = cronManager.update(args.cronId, { enabled: Boolean(args.enabled) });
          } else if (args.action === 'run') {
            if (!args.cronId) throw new McpToolError('MISSING_ARGUMENT', 'Falta cronId para run.', { retryable: true });
            const ownsCron = cronManager.list(project.id).some((c) => c.id === args.cronId);
            if (!ownsCron) {
              throw new McpToolError(principal.isSuperAdmin ? 'NOT_FOUND' : 'FORBIDDEN', `El cron '${args.cronId}' no pertenece al proyecto '${project.id}'.`, { retryable: false });
            }
            res = await cronManager.runNow(args.cronId);
          } else if (args.action === 'delete') {
            if (!args.cronId) throw new McpToolError('MISSING_ARGUMENT', 'Falta cronId para delete.', { retryable: true });
            const ownsCron = cronManager.list(project.id).some((c) => c.id === args.cronId);
            if (!ownsCron) {
              throw new McpToolError(principal.isSuperAdmin ? 'NOT_FOUND' : 'FORBIDDEN', `El cron '${args.cronId}' no pertenece al proyecto '${project.id}'.`, { retryable: false });
            }
            res = cronManager.remove(args.cronId);
          }
          break;
        }

        case 'culkibo_manage_previews': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          if (args.action === 'list') {
            res = { projectId: project.id, previews: previewManager.list(project.id) };
          } else if (args.action === 'deploy') {
            res = await previewManager.deployPreview(project, {
              branch: args.branch,
              prNumber: args.prNumber || null
            });
          } else if (args.action === 'destroy') {
            res = await previewManager.destroyPreview(project.id, {
              previewId: args.previewId || null,
              branch: args.branch || null,
              prNumber: args.prNumber || null
            });
          }
          break;
        }

        // --- MCP 2.0: A. Multi-Server Fleet (5) ---
        case 'culkibo_fleet_list_servers': {
          const fleet = lazySvc('serverFleetManager');
          if (!fleet) {
            const localProjects = projectManager.getAll().filter((p) => canAccessProject(principal, p.id, p) && (p.serverId || 'local') === 'local');
            res = {
              servers: [
                {
                  id: 'local',
                  name: 'Local (este servidor)',
                  host: '127.0.0.1',
                  port: 22,
                  region: 'local',
                  tags: ['local'],
                  status: 'online',
                  isLocal: true,
                  projectCount: localProjects.length
                }
              ],
              total: 1,
              fleetServiceAvailable: false
            };
            break;
          }
          const rawServers = fleet.listServers({
            ...(args.tag ? { tag: String(args.tag) } : {}),
            ...(args.region ? { region: String(args.region) } : {})
          });
          const filtered = (Array.isArray(rawServers) ? rawServers : [])
            .filter((s) => principal.isSuperAdmin || s.id === 'local' || !principal.teamId || !s.teamId || s.teamId === principal.teamId)
            .map((s) => sanitizeFleetServer(s));
          res = { servers: filtered, total: filtered.length };
          break;
        }

        case 'culkibo_fleet_add_server': {
          const fleet = requireLazySvc('serverFleetManager', 'Flota Multi-Servidor');
          let keyId = args.keyId ? String(args.keyId) : null;
          let publicKey = null;
          const teamId = principal.teamId || 'team_default';
          if (!keyId && args.privateKey && typeof fleet.importKey === 'function') {
            const imported = await fleet.importKey({
              name: `${String(args.name).slice(0, 40)}-key`,
              privateKeyPem: String(args.privateKey),
              teamId
            });
            keyId = imported?.id || imported?.key?.id || null;
            publicKey = imported?.publicKey || imported?.key?.publicKey || null;
          } else if (!keyId && args.generateKey && typeof fleet.generateKeyPair === 'function') {
            const generated = await fleet.generateKeyPair({
              name: `${String(args.name).slice(0, 40)}-key`,
              teamId
            });
            keyId = generated?.id || generated?.key?.id || null;
            publicKey = generated?.publicKey || generated?.key?.publicKey || null;
          }
          const addFn = fleet.addServer || fleet.createServer;
          const server = await addFn.call(fleet, {
            name: String(args.name),
            host: String(args.host),
            port: args.port !== undefined ? Number(args.port) : 22,
            user: args.user ? String(args.user) : 'root',
            ...(keyId ? { keyId } : {}),
            tags: Array.isArray(args.tags) ? args.tags.map(String) : [],
            region: args.region ? String(args.region) : 'default',
            ...(args.expectedFingerprint ? { expectedFingerprint: String(args.expectedFingerprint) } : {}),
            teamId
          });
          res = {
            success: true,
            server: sanitizeFleetServer(server),
            ...(publicKey ? { publicKey } : {})
          };
          break;
        }

        case 'culkibo_fleet_probe_server': {
          const fleet = lazySvc('serverFleetManager');
          if (args.serverId === 'local' && !fleet) {
            res = {
              serverId: 'local',
              status: 'online',
              docker: await dockerManager.checkDockerStatus(Boolean(args.refresh)),
              caddy: await caddyManager.detect(),
              memory: { totalMb: Math.round(os.totalmem() / 1048576), freeMb: Math.round(os.freemem() / 1048576) }
            };
            break;
          }
          const fleetSvc = requireLazySvc('serverFleetManager', 'Flota Multi-Servidor');
          const probe = await fleetSvc.probeServer(String(args.serverId), {
            force: Boolean(args.refresh),
            refresh: Boolean(args.refresh)
          });
          res = sanitizeFleetServer(probe);
          break;
        }

        case 'culkibo_fleet_remove_server': {
          if (args.serverId === 'local') {
            throw new McpToolError('INVALID_ARGUMENT', 'No se puede eliminar el nodo local.', { retryable: false });
          }
          const fleet = requireLazySvc('serverFleetManager', 'Flota Multi-Servidor');
          const assigned = projectManager.getAll().filter((p) => (p.serverId || 'local') === args.serverId);
          if (assigned.length > 0 && !args.force) {
            throw new McpToolError('SERVER_IN_USE', `El servidor '${args.serverId}' tiene ${assigned.length} proyecto(s) asignados.`, {
              retryable: false,
              remediation: 'Reasigna los proyectos con culkibo_fleet_assign_project o pasa force: true.',
              details: { serverId: args.serverId, projectIds: assigned.map((p) => p.id) }
            });
          }
          const delFn = fleet.deleteServer || fleet.removeServer;
          res = await delFn.call(fleet, String(args.serverId), { force: Boolean(args.force) });
          break;
        }

        case 'culkibo_fleet_assign_project': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          const targetServerId = String(args.serverId).trim();
          if (targetServerId !== 'local') {
            const fleet = requireLazySvc('serverFleetManager', 'Flota Multi-Servidor');
            const found = typeof fleet.getServer === 'function'
              ? fleet.getServer(targetServerId)
              : (fleet.listServers?.() || []).find((s) => s.id === targetServerId);
            if (!found) {
              throw new McpToolError('SERVER_NOT_FOUND', `No existe ningún servidor con id '${targetServerId}'.`, {
                retryable: false,
                remediation: 'Llama a culkibo_fleet_list_servers para consultar los serverId disponibles.'
              });
            }
          }
          const previousServerId = project.serverId || 'local';
          projectManager.update(project.id, { serverId: targetServerId });
          await projectManager.flushToDisk();
          res = {
            success: true,
            projectId: project.id,
            previousServerId,
            serverId: targetServerId,
            note: 'Asignación guardada. Ejecuta culkibo_deploy_production para desplegar en el nodo destino.'
          };
          break;
        }

        // --- MCP 2.0: B. Equipos y RBAC (6) ---
        case 'culkibo_rbac_whoami': {
          const allowedTools = this.getToolsForPrincipal(principal);
          res = {
            method: principal.method,
            userId: principal.userId,
            email: principal.email,
            role: principal.role,
            teamId: principal.teamId,
            projectIds: principal.projectIds,
            scopes: principal.scopes,
            isSuperAdmin: principal.isSuperAdmin,
            allowedToolsCount: allowedTools.length,
            totalToolsCount: this.getToolsDefinition().length
          };
          break;
        }

        case 'culkibo_team_list_members': {
          const tm = lazySvc('teamManager');
          const targetTeamId = principal.isSuperAdmin
            ? (args.teamId ? String(args.teamId) : 'team_default')
            : (principal.teamId || 'team_default');
          if (!tm) {
            res = { teamId: targetTeamId, multiUserEnabled: false, members: [], pendingInvites: [] };
            break;
          }
          const actorAuth = context.auth || { ok: true, method: principal.method, principal };
          const members = tm.listMembers(actorAuth, targetTeamId);
          let pendingInvites = [];
          if ((ROLE_RANK[principal.role] || 0) >= ROLE_RANK.admin && typeof tm.listInvites === 'function') {
            try {
              const rawInvites = tm.listInvites(actorAuth, targetTeamId);
              pendingInvites = (Array.isArray(rawInvites) ? rawInvites : []).map((inv) => {
                const { token: _t, inviteToken: _it, tokenHash: _th, ...safe } = inv || {};
                return safe;
              });
            } catch (e) {
              pendingInvites = [];
            }
          }
          res = {
            teamId: targetTeamId,
            multiUserEnabled: typeof tm.isMultiUserEnabled === 'function' ? tm.isMultiUserEnabled() : true,
            members,
            pendingInvites
          };
          break;
        }

        case 'culkibo_team_invite_member': {
          const tm = requireLazySvc('teamManager', 'Equipos y RBAC');
          const actorAuth = context.auth || { ok: true, method: principal.method, principal };
          const teamId = principal.isSuperAdmin
            ? (args.teamId ? String(args.teamId) : 'team_default')
            : (principal.teamId || 'team_default');
          res = tm.createInvite(actorAuth, {
            email: String(args.email),
            role: String(args.role),
            teamId,
            projectIds: Array.isArray(args.projectIds) ? args.projectIds.map(String) : null,
            ttlHours: args.ttlHours !== undefined ? Number(args.ttlHours) : 48
          });
          break;
        }

        case 'culkibo_team_update_member': {
          const tm = requireLazySvc('teamManager', 'Equipos y RBAC');
          const actorAuth = context.auth || { ok: true, method: principal.method, principal };
          const teamId = principal.isSuperAdmin
            ? (args.teamId ? String(args.teamId) : 'team_default')
            : (principal.teamId || 'team_default');
          if (args.action === 'update_role') {
            if (!args.role) throw new McpToolError('MISSING_ARGUMENT', 'Falta role para update_role.', { retryable: true });
            res = tm.updateMemberRole(actorAuth, teamId, String(args.memberId), String(args.role));
          } else if (args.action === 'set_projects') {
            res = tm.updateMemberProjects(actorAuth, teamId, String(args.memberId), Array.isArray(args.projectIds) ? args.projectIds.map(String) : null);
          } else if (args.action === 'remove') {
            res = tm.removeMember(actorAuth, teamId, String(args.memberId));
          }
          break;
        }

        case 'culkibo_rbac_list_tokens': {
          const tm = lazySvc('teamManager');
          if (!tm) {
            res = { tokens: [], multiUserEnabled: false };
            break;
          }
          const actorAuth = context.auth || { ok: true, method: principal.method, principal };
          const rawTokens = tm.listApiTokens(actorAuth, {
            ...(args.teamId ? { teamId: String(args.teamId) } : (principal.teamId ? { teamId: principal.teamId } : {}))
          });
          const tokens = (Array.isArray(rawTokens) ? rawTokens : []).map((t) => {
            const { token: _t, tokenHash: _th, secret: _s, ...safe } = t || {};
            return safe;
          });
          res = { tokens, count: tokens.length };
          break;
        }

        case 'culkibo_rbac_manage_token': {
          const tm = requireLazySvc('teamManager', 'Tokens RBAC');
          const actorAuth = context.auth || { ok: true, method: principal.method, principal };
          if (args.action === 'create') {
            const teamId = principal.isSuperAdmin
              ? (args.teamId ? String(args.teamId) : 'team_default')
              : (principal.teamId || 'team_default');
            res = tm.createApiToken(actorAuth, {
              name: args.name ? String(args.name) : 'MCP Token',
              role: args.role ? String(args.role) : principal.role,
              scopes: Array.isArray(args.scopes) ? args.scopes.map(String) : ['*'],
              projectIds: Array.isArray(args.projectIds) ? args.projectIds.map(String) : null,
              expiresInDays: args.expiresInDays !== undefined ? Number(args.expiresInDays) : undefined,
              teamId
            });
          } else if (args.action === 'revoke') {
            if (!args.tokenId) throw new McpToolError('MISSING_ARGUMENT', 'Falta tokenId para revoke.', { retryable: true });
            res = tm.revokeApiToken(actorAuth, String(args.tokenId));
          }
          break;
        }

        // --- MCP 2.0: C. Entornos y Promoción (4) ---
        case 'culkibo_env_list': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          const em = lazySvc('environmentManager');
          if (!em) {
            res = {
              projectId: project.id,
              environments: [
                {
                  name: 'production',
                  branch: project.gitBranch || 'main',
                  serverId: project.serverId || 'local',
                  envVarKeys: Object.keys(project.envVars || {})
                }
              ],
              environmentServiceAvailable: false
            };
            break;
          }
          const rawEnvs = em.listEnvironments(project.id);
          res = {
            projectId: project.id,
            environments: (Array.isArray(rawEnvs) ? rawEnvs : []).map((e) => sanitizeEnvObject(e))
          };
          break;
        }

        case 'culkibo_env_create': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          const em = requireLazySvc('environmentManager', 'Entornos y Vault');
          const saveFn = em.saveEnvironment || em.upsertEnvironment;
          const created = saveFn.call(em, project.id, String(args.name), {
            branch: args.branch ? String(args.branch) : undefined,
            serverId: args.serverId ? String(args.serverId) : (project.serverId || 'local'),
            cloneEnvFrom: args.cloneEnvFrom ? String(args.cloneEnvFrom) : undefined,
            domains: args.domain ? [String(args.domain)] : undefined,
            domain: args.domain ? String(args.domain) : undefined,
            autoDeploy: args.autoDeploy !== undefined ? Boolean(args.autoDeploy) : undefined,
            envVars: args.envVars && typeof args.envVars === 'object' ? args.envVars : undefined
          });
          res = { success: true, projectId: project.id, environment: sanitizeEnvObject(created) };
          break;
        }

        case 'culkibo_env_diff': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          const em = requireLazySvc('environmentManager', 'Entornos y Vault');
          res = em.diffEnvironments(project.id, String(args.fromEnv), String(args.toEnv));
          break;
        }

        case 'culkibo_env_promote': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          const freeze = evaluateProjectFreeze(project);
          if (freeze.frozen && !args.overrideFreeze) {
            throw new McpToolError('DEPLOY_FREEZE_ACTIVE', 'Promoción bloqueada por una ventana de deploy freeze activa.', {
              retryable: false,
              remediation: 'Espera a que finalice la ventana o pasa overrideFreeze: true con rol admin/owner.',
              details: { freeze }
            });
          }
          const em = requireLazySvc('environmentManager', 'Entornos y Vault');
          const promoteFn = em.promoteEnvironment || em.promote;
          res = await promoteFn.call(em, project.id, {
            fromEnv: String(args.fromEnv),
            toEnv: String(args.toEnv),
            includeEnvVars: Boolean(args.includeEnvVars),
            overrideFreeze: Boolean(args.overrideFreeze),
            dryRun: false,
            actor: principal.userId || principal.role
          });
          break;
        }

        // --- MCP 2.0: D. Uptime y Páginas de Estado (4) ---
        case 'culkibo_uptime_list_monitors': {
          const um = lazySvc('uptimeMonitor');
          if (!um) {
            res = { monitors: [], statusPages: [], uptimeServiceAvailable: false };
            break;
          }
          const allMonitors = um.listMonitors(args.projectId ? { projectId: String(args.projectId) } : {});
          const monitors = (Array.isArray(allMonitors) ? allMonitors : []).filter((m) => {
            if (args.projectId && m.projectId !== args.projectId) return false;
            return canAccessProject(principal, m.projectId);
          });
          const statusPages = typeof um.listStatusPages === 'function' ? um.listStatusPages() : [];
          res = { monitors, statusPages };
          break;
        }

        case 'culkibo_uptime_upsert_monitor': {
          const um = requireLazySvc('uptimeMonitor', 'Monitores de Uptime');
          const payload = {
            ...(args.projectId !== undefined ? { projectId: String(args.projectId) } : {}),
            ...(args.name !== undefined ? { name: String(args.name) } : {}),
            ...(args.type !== undefined ? { type: String(args.type) } : {}),
            ...(args.url !== undefined ? { url: String(args.url) } : {}),
            ...(args.host !== undefined ? { host: String(args.host) } : {}),
            ...(args.port !== undefined ? { port: Number(args.port) } : {}),
            ...(args.intervalSec !== undefined ? { intervalSec: Number(args.intervalSec) } : {}),
            ...(args.timeoutMs !== undefined ? { timeoutMs: Number(args.timeoutMs) } : {}),
            ...(args.expectedStatus !== undefined ? { expectedStatus: Number(args.expectedStatus) } : {}),
            ...(args.expectedBody !== undefined ? { expectedBody: String(args.expectedBody) } : {}),
            ...(args.enabled !== undefined ? { enabled: Boolean(args.enabled) } : {}),
            ...(args.allowLocalProject !== undefined ? { allowLocalProject: Boolean(args.allowLocalProject) } : {})
          };
          if (args.monitorId) {
            res = await um.updateMonitor(String(args.monitorId), payload);
          } else {
            res = await um.createMonitor(payload);
          }
          break;
        }

        case 'culkibo_uptime_delete_monitor': {
          const um = requireLazySvc('uptimeMonitor', 'Monitores de Uptime');
          res = um.deleteMonitor(String(args.monitorId));
          break;
        }

        case 'culkibo_status_page_manage': {
          const um = requireLazySvc('uptimeMonitor', 'Páginas de Estado');
          if (args.action === 'configure') {
            res = um.saveStatusPage({
              slug: String(args.slug),
              title: args.title ? String(args.title) : String(args.slug),
              description: args.description ? String(args.description) : '',
              customDomain: args.customDomain ? String(args.customDomain) : undefined,
              monitorIds: Array.isArray(args.monitorIds) ? args.monitorIds.map(String) : []
            });
          } else if (args.action === 'publish_incident') {
            if (!args.incidentTitle) throw new McpToolError('MISSING_ARGUMENT', 'Falta incidentTitle para publish_incident.', { retryable: true });
            res = um.publishStatusIncident(String(args.slug), {
              title: String(args.incidentTitle),
              severity: args.severity ? String(args.severity) : 'minor',
              message: args.message ? String(args.message) : ''
            });
          } else if (args.action === 'resolve_incident') {
            if (!args.incidentId) throw new McpToolError('MISSING_ARGUMENT', 'Falta incidentId para resolve_incident.', { retryable: true });
            res = um.resolveStatusIncident(String(args.slug), String(args.incidentId));
          } else if (args.action === 'delete') {
            res = um.deleteStatusPage(String(args.slug));
          }
          break;
        }

        // --- MCP 2.0: E. GitOps culkibo.yaml (3) ---
        case 'culkibo_gitops_export': {
          const gm = requireLazySvc('gitopsManager', 'Motor GitOps culkibo.yaml');
          /** @type {string[] | undefined} */
          let projectIds = undefined;
          if (args.projectId) {
            projectIds = [String(args.projectId)];
          } else if (Array.isArray(args.projectIds)) {
            projectIds = args.projectIds.map(String).filter((id) => canAccessProject(principal, id));
          } else if (!principal.isSuperAdmin) {
            projectIds = projectManager.getAll().filter((p) => canAccessProject(principal, p.id, p)).map((p) => p.id);
          }
          res = gm.exportStack({
            ...(projectIds !== undefined ? { projectIds } : {}),
            ...(args.name ? { name: String(args.name) } : {})
          });
          break;
        }

        case 'culkibo_gitops_plan': {
          const gm = requireLazySvc('gitopsManager', 'Motor GitOps culkibo.yaml');
          res = gm.planApply(String(args.yamlText), { prune: Boolean(args.prune) });
          break;
        }

        case 'culkibo_gitops_apply': {
          const gm = requireLazySvc('gitopsManager', 'Motor GitOps culkibo.yaml');
          res = await gm.applyStack(String(args.yamlText), {
            dryRun: false,
            prune: Boolean(args.prune),
            confirmDestructive: Boolean(args.confirmDestructive)
          });
          break;
        }

        // --- MCP 2.0: F. Smart Sleep y VPS Cost/RAM Advisor (3) ---
        case 'culkibo_cost_advisor': {
          const sa = lazySvc('sleepAdvisor');
          const vpsMonthlyEur = args.monthlyServerCostEur !== undefined
            ? Number(args.monthlyServerCostEur)
            : (args.vpsMonthlyEur !== undefined ? Number(args.vpsMonthlyEur) : undefined);
          if (sa && typeof sa.analyzeResources === 'function') {
            const report = await sa.analyzeResources(vpsMonthlyEur !== undefined ? { vpsMonthlyEur } : {});
            res = {
              summary: report.summary || report,
              recommendations: Array.isArray(report.recommendations) ? report.recommendations : [],
              reclaimableRamMb: Number(report.reclaimableRamMb ?? report.summary?.reclaimableRamMb ?? 0),
              estimatedMonthlySavingsEur: Number(report.estimatedMonthlySavingsEur ?? report.summary?.estimatedMonthlySavingsEur ?? 0),
              ...report
            };
          } else {
            const totalRamMb = Math.round(os.totalmem() / 1048576);
            const freeRamMb = Math.round(os.freemem() / 1048576);
            res = {
              summary: { totalRamMb, freeRamMb, usedRamMb: totalRamMb - freeRamMb, projectsCount: projectManager.getAll().length },
              recommendations: [],
              reclaimableRamMb: 0,
              estimatedMonthlySavingsEur: 0,
              sleepServiceAvailable: false
            };
          }
          break;
        }

        case 'culkibo_sleep_status': {
          const sa = lazySvc('sleepAdvisor');
          if (args.projectId) {
            const project = projectManager.getById(args.projectId);
            if (!project) throw projectNotFoundError(args.projectId);
            res = {
              projectId: project.id,
              sleeping: sa && typeof sa.isSleeping === 'function' ? Boolean(sa.isSleeping(project.id)) : false,
              policy: sa && typeof sa.getPolicy === 'function' ? sa.getPolicy(project.id) : null,
              sleepServiceAvailable: Boolean(sa)
            };
          } else if (sa && typeof sa.listPolicies === 'function') {
            const allPolicies = sa.listPolicies();
            const policies = (Array.isArray(allPolicies) ? allPolicies : []).filter((p) => canAccessProject(principal, p.projectId));
            res = {
              policies,
              candidates: typeof sa.getSleepCandidates === 'function' ? sa.getSleepCandidates() : []
            };
          } else {
            res = { policies: [], candidates: [], sleepServiceAvailable: false };
          }
          break;
        }

        case 'culkibo_sleep_manage': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          const sa = requireLazySvc('sleepAdvisor', 'Smart Sleep');
          if (args.action === 'configure') {
            res = sa.setPolicy(project.id, {
              ...(args.enabled !== undefined ? { enabled: Boolean(args.enabled) } : {}),
              ...(args.mode !== undefined ? { mode: String(args.mode) } : {}),
              ...(args.idleMinutes !== undefined ? { idleMinutes: Number(args.idleMinutes) } : {}),
              ...(args.wakeTimeoutMs !== undefined ? { wakeTimeoutMs: Number(args.wakeTimeoutMs) } : {}),
              ...(args.excludeCrons !== undefined ? { excludeCrons: Boolean(args.excludeCrons) } : {})
            });
          } else if (args.action === 'sleep') {
            res = await sa.sleepProject(project.id, { trigger: 'mcp' });
          } else if (args.action === 'wake') {
            res = await sa.wakeProject(project.id, { trigger: 'mcp' });
          }
          break;
        }

        // --- MCP 2.0: G. LiveSync 2.0 Time-Travel y Conflictos (3) ---
        case 'culkibo_sync_file_history': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          if (typeof liveSyncEngine.getFileHistory === 'function') {
            res = liveSyncEngine.getFileHistory(project.id, String(args.filePath), {
              limit: Math.min(100, Math.max(1, Number(args.limit) || 20)),
              includeDiff: Boolean(args.includeDiff)
            });
          } else {
            res = { projectId: project.id, filePath: String(args.filePath), versions: [], available: false };
          }
          break;
        }

        case 'culkibo_sync_rollback_file': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          if (typeof liveSyncEngine.rollbackFile !== 'function') {
            throw new McpToolError('SERVICE_UNAVAILABLE', 'LiveSync 2.0 rollbackFile no está disponible en esta versión.', { retryable: true });
          }
          res = liveSyncEngine.rollbackFile(project.id, String(args.filePath), Number(args.seq), {
            actor: principal.userId || 'mcp'
          });
          break;
        }

        case 'culkibo_sync_conflicts': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          const status = liveSyncEngine.getStatus(project.id);
          const limit = Math.min(100, Math.max(1, Number(args.limit) || 20));
          const allConflicts = Array.isArray(status?.recentConflicts) ? status.recentConflicts : [];
          res = {
            projectId: project.id,
            conflicts: allConflicts.slice(0, limit),
            count: allConflicts.length,
            wireStats: status?.wireStats || null
          };
          break;
        }

        // --- MCP 2.0: H. Smoke Tests, Canary Auto-Guard y Deploy Freeze (4) ---
        case 'culkibo_smoke_test_configure': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          const checks = sanitizeSmokeChecks(args.checks);
          const smokeConfig = {
            enabled: args.enabled !== false,
            failPolicy: args.failPolicy ? String(args.failPolicy) : 'rollback',
            checks
          };
          projectManager.update(project.id, { smokeTests: smokeConfig });
          await projectManager.flushToDisk();
          res = { success: true, projectId: project.id, smokeTests: smokeConfig };
          break;
        }

        case 'culkibo_smoke_test_run': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          const target = args.target ? String(args.target) : 'citadel';
          const configuredChecks = Array.isArray(project.smokeTests)
            ? project.smokeTests
            : (Array.isArray(project.smokeTests?.checks) ? project.smokeTests.checks : []);
          const checks = Array.isArray(args.checks) ? sanitizeSmokeChecks(args.checks) : configuredChecks;
          if (!checks || checks.length === 0) {
            throw new McpToolError('MISSING_ARGUMENT', 'No hay smoke checks configurados ni proporcionados para este proyecto.', {
              retryable: true,
              remediation: 'Configúralos primero con culkibo_smoke_test_configure o pásalos en checks[].'
            });
          }
          if (typeof deployManager.runSmokeTests !== 'function') {
            throw new McpToolError('SERVICE_UNAVAILABLE', 'El ejecutor runSmokeTests de deployManager no está disponible todavía.', { retryable: true });
          }
          let upstream = `http://127.0.0.1:${project.forgePort || 3000}`;
          if (target === 'citadel') {
            const st = await deployManager.status(project.id);
            const port = st?.current?.hostPort || project.citadelPort || 3000;
            upstream = `http://127.0.0.1:${port}`;
          } else if (target === 'canary' && typeof deployManager.getCanaryState === 'function') {
            const canary = deployManager.getCanaryState(project.id);
            if (!canary?.canaryDial) {
              throw new McpToolError('CANARY_NOT_ACTIVE', `No hay un despliegue canario activo para '${project.id}'.`, { retryable: false });
            }
            upstream = canary.canaryDial.startsWith('http') ? canary.canaryDial : `http://${canary.canaryDial}`;
          }
          const smokeResult = await deployManager.runSmokeTests(upstream, checks, { target });
          res = { projectId: project.id, target, upstream, ...smokeResult };
          break;
        }

        case 'culkibo_canary_rollout': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          if (args.action === 'status') {
            res = {
              projectId: project.id,
              config: project.canary || null,
              active: typeof deployManager.getCanaryState === 'function' ? deployManager.getCanaryState(project.id) : null
            };
          } else if (args.action === 'start') {
            const canaryCfg = {
              enabled: true,
              steps: Array.isArray(args.steps) && args.steps.length > 0 ? args.steps.map(Number) : [10, 50, 100],
              stepDurationMs: Math.max(3000, (Number(args.stepIntervalSec) || 15) * 1000),
              weightPercent: args.weightPercent !== undefined ? Number(args.weightPercent) : undefined,
              autoRollback: args.autoRollbackOnSmokeFail !== false
            };
            projectManager.update(project.id, { canary: canaryCfg });
            await projectManager.flushToDisk();
            if (typeof deployManager.startCanary === 'function') {
              res = await deployManager.startCanary(project, canaryCfg);
            } else {
              res = await deployManager.deploy(project, { canary: canaryCfg, trigger: 'mcp_canary' });
            }
          } else if (args.action === 'advance') {
            if (typeof deployManager.advanceCanary !== 'function') {
              throw new McpToolError('SERVICE_UNAVAILABLE', 'advanceCanary no está disponible todavía en deployManager.', { retryable: true });
            }
            res = await deployManager.advanceCanary(project.id);
          } else if (args.action === 'promote') {
            if (typeof deployManager.promoteCanary !== 'function') {
              throw new McpToolError('SERVICE_UNAVAILABLE', 'promoteCanary no está disponible todavía en deployManager.', { retryable: true });
            }
            res = await deployManager.promoteCanary(project.id);
          } else if (args.action === 'abort') {
            if (typeof deployManager.abortCanary === 'function') {
              res = await deployManager.abortCanary(project.id);
            } else {
              res = await deployManager.cancelDeploy(project.id);
            }
          }
          break;
        }

        case 'culkibo_deploy_freeze': {
          const project = args.projectId ? projectManager.getById(args.projectId) : null;
          if (args.projectId && !project) throw projectNotFoundError(args.projectId);
          const dm = /** @type {any} */ (deployManager);
          if (args.action === 'list') {
            const status = evaluateProjectFreeze(project);
            const globalWindows = typeof dm.listFreezeWindows === 'function' ? dm.listFreezeWindows() : [];
            const windows = project ? (project.freezeWindows || []) : globalWindows;
            res = { scope: project ? project.id : 'global', ...status, windows, globalWindows };
          } else if (args.action === 'set') {
            const windows = Array.isArray(args.windows) ? args.windows : [];
            if (project) {
              projectManager.update(project.id, { freezeWindows: windows });
              await projectManager.flushToDisk();
              res = { success: true, projectId: project.id, windows };
            } else if (typeof dm.addFreezeWindow === 'function') {
              const added = windows.map((w) => dm.addFreezeWindow(w));
              res = { success: true, scope: 'global', added, windows: dm.listFreezeWindows() };
            } else {
              throw new McpToolError('SERVICE_UNAVAILABLE', 'Las ventanas freeze globales no están disponibles todavía en deployManager.', { retryable: true });
            }
          } else if (args.action === 'remove') {
            if (project) {
              const nextWindows = args.windowId
                ? (project.freezeWindows || []).filter((w) => w.id !== args.windowId)
                : [];
              projectManager.update(project.id, { freezeWindows: nextWindows });
              await projectManager.flushToDisk();
              res = { success: true, projectId: project.id, windows: nextWindows };
            } else if (typeof dm.removeFreezeWindow === 'function' && args.windowId) {
              res = dm.removeFreezeWindow(String(args.windowId));
            } else if (typeof dm.listFreezeWindows === 'function' && typeof dm.removeFreezeWindow === 'function') {
              const existing = dm.listFreezeWindows();
              for (const w of existing) {
                if (w && w.id) dm.removeFreezeWindow(w.id);
              }
              res = { success: true, scope: 'global', removedCount: existing.length, windows: [] };
            } else {
              res = { success: true, scope: 'global', windows: [] };
            }
          }
          break;
        }

        default:
          // Inalcanzable: `tool` ya se resolvió contra el catálogo más arriba.
          throw new McpToolError('UNKNOWN_TOOL', `La herramienta '${toolName}' está declarada pero no implementada.`, {
            retryable: false,
            remediation: 'Repórtalo como fallo de Culkibo: el catálogo y el despachador no coinciden.',
            details: { requested: toolName }
          });
      }

      const durationMs = performance.now() - start;
      this.logCall(toolName, args, res, true, durationMs, transport, clientInfo, { dryRun: isDryRun, principal });
      try { require('./telemetryService').recordFeatureUsage(`mcp:${toolName}`, true); } catch (e) {}

      const MAX_MCP_TEXT_BYTES = 256 * 1024;
      let serialized = JSON.stringify(res, null, 2);
      if (serialized && Buffer.byteLength(serialized, 'utf8') > MAX_MCP_TEXT_BYTES) {
        serialized = `${serialized.slice(0, MAX_MCP_TEXT_BYTES - 128)}\n... [salida MCP truncada a 256 KB]`;
      }
      const result = {
        content: [{ type: 'text', text: serialized }],
        isError: false
      };
      if (res !== null && typeof res === 'object') result.structuredContent = res;
      return result;
    } catch (err) {
      const durationMs = performance.now() - start;
      const envelope = this.describeToolFailure(toolName, tool, err, durationMs);
      this.logCall(toolName, args, { error: envelope.code, message: envelope.message }, false, durationMs, transport, clientInfo, { dryRun: isDryRun, principal });
      try {
        const ts = require('./telemetryService');
        ts.recordFeatureUsage(`mcp:${toolName}`, false);
        ts.captureOperationFailure({
          operation: 'mcp_tool',
          stage: 'execute',
          kind: toolName,
          errorCode: envelope.code,
          message: envelope.message,
          durationMs: Math.round(durationMs)
        });
      } catch (e) {}
      return {
        isError: true,
        content: [{ type: 'text', text: JSON.stringify(envelope, null, 2) }],
        _meta: { [META_CULKIBO_ERROR]: envelope }
      };
    }
  }

  // -------------------------------------------------------------------------
  // MCP Resources & Prompts (2026-07-28 + 2024-11-05)
  // -------------------------------------------------------------------------

  /**
   * Lista recursos MCP filtrando por scopes del principal cuando está acotado.
   * @param {any} [authOrPrincipal]
   */
  listResources(authOrPrincipal = null) {
    const all = [
      {
        uri: 'culkibo://projects',
        name: 'Proyectos de Culkibo',
        description: 'Listado redactado en tiempo real de todos los proyectos, dominios y puertos.',
        mimeType: 'application/json'
      },
      {
        uri: 'culkibo://pods',
        name: 'Estado de Pods y Telemetría',
        description: 'Estado vivo de The Forge, The Citadel, reparto de tráfico y métricas del daemon.',
        mimeType: 'application/json'
      },
      {
        uri: 'culkibo://doctor',
        name: 'Informe System Doctor',
        description: 'Diagnóstico completo de salud de Node, Docker, Caddy, disco, TLS y seguridad.',
        mimeType: 'application/json'
      },
      {
        uri: 'culkibo://domains',
        name: 'Mapa de Dominios e Ingress',
        description: 'Todos los dominios, comodines, redirecciones y protecciones de borde configuradas.',
        mimeType: 'application/json'
      },
      {
        uri: 'culkibo://fleet',
        name: 'Flota Multi-Servidor SSH',
        description: 'Servidores local y remotos, regiones, etiquetas, huellas fijadas TOFU, salud y asignación de proyectos (sin claves privadas).',
        mimeType: 'application/json'
      },
      {
        uri: 'culkibo://uptime',
        name: 'Monitores de Uptime y Páginas de Estado',
        description: 'Monitores HTTP/TCP, porcentajes SLA 24h/7d/30d, latencias, incidentes abiertos y páginas de estado públicas.',
        mimeType: 'application/json'
      },
      {
        uri: 'culkibo://environments',
        name: 'Entornos, Promoción, Canarios y Freeze Windows',
        description: 'Entornos por proyecto (secretos redactados), deriva de promoción, pesos canarios activos y ventanas de deploy freeze.',
        mimeType: 'application/json'
      }
    ];
    const principal = normalizePrincipal(authOrPrincipal);
    if (principal.isSuperAdmin || principal.scopes.includes('*')) return all;
    /** @type {Record<string, string>} */
    const scopeByUri = {
      'culkibo://projects': 'projects:read',
      'culkibo://pods': 'pods:read',
      'culkibo://doctor': 'system:read',
      'culkibo://domains': 'domains:read',
      'culkibo://fleet': 'fleet:read',
      'culkibo://uptime': 'uptime:read',
      'culkibo://environments': 'environments:read'
    };
    return all.filter((r) => scopeMatches(principal.scopes, scopeByUri[r.uri] || 'system:read', r.uri, false));
  }

  /**
   * Lee un recurso MCP filtrando por ACL/RBAC del principal y redactando secretos.
   * @param {string} uri
   * @param {{ auth?: any }} [context]
   */
  async readResource(uri, context = {}) {
    const clean = String(uri || '').trim();
    const principal = normalizePrincipal(context.auth);
    /** @type {Record<string, string>} */
    const resourceScopes = {
      'culkibo://projects': 'projects:read',
      'culkibo://pods': 'pods:read',
      'culkibo://doctor': 'system:read',
      'culkibo://domains': 'domains:read',
      'culkibo://fleet': 'fleet:read',
      'culkibo://uptime': 'uptime:read',
      'culkibo://environments': 'environments:read'
    };
    const reqScope = resourceScopes[clean];
    if (reqScope && !principal.isSuperAdmin && !scopeMatches(principal.scopes, reqScope, clean, false)) {
      throw new McpToolError('FORBIDDEN', `Acceso denegado al recurso '${clean}' para los scopes del token.`, { retryable: false });
    }
    /** @type {any} */
    let data = null;
    if (clean === 'culkibo://projects') {
      const visible = projectManager.getAll().filter((p) => canAccessProject(principal, p.id, p));
      data = { projects: visible.map((p) => redactProjectSecrets(p)) };
    } else if (clean === 'culkibo://pods') {
      data = containerOrchestrator.getPods();
    } else if (clean === 'culkibo://doctor') {
      data = await systemDoctor.runDoctor();
    } else if (clean === 'culkibo://domains') {
      const domains = domainManager.listDomains().filter((d) => canAccessProject(principal, d.projectId));
      data = { domains, wildcardPolicies: ingressManager.listWildcardPolicies() };
    } else if (clean === 'culkibo://fleet') {
      const fleet = lazySvc('serverFleetManager');
      const visibleProjects = projectManager.getAll().filter((p) => canAccessProject(principal, p.id, p));
      const placements = visibleProjects.map((p) => ({
        projectId: p.id,
        name: p.name,
        serverId: p.serverId || 'local'
      }));
      if (fleet && typeof fleet.listServers === 'function') {
        const rawServers = fleet.listServers();
        const servers = (Array.isArray(rawServers) ? rawServers : [])
          .filter((s) => principal.isSuperAdmin || s.id === 'local' || !principal.teamId || !s.teamId || s.teamId === principal.teamId)
          .map((s) => sanitizeFleetServer(s));
        data = { servers, placements };
      } else {
        data = {
          servers: [{ id: 'local', name: 'Local', host: '127.0.0.1', region: 'local', tags: ['local'], status: 'online', isLocal: true }],
          placements,
          fleetServiceAvailable: false
        };
      }
    } else if (clean === 'culkibo://uptime') {
      const um = lazySvc('uptimeMonitor');
      if (um && typeof um.listMonitors === 'function') {
        const allMonitors = um.listMonitors();
        const monitors = (Array.isArray(allMonitors) ? allMonitors : [])
          .filter((m) => canAccessProject(principal, m.projectId));
        const statusPages = typeof um.listStatusPages === 'function' ? um.listStatusPages() : [];
        const openIncidents = typeof um.listIncidents === 'function'
          ? (um.listIncidents({ status: 'open' }) || []).filter((inc) => canAccessProject(principal, inc.projectId))
          : [];
        data = { monitors, openIncidents, statusPages };
      } else {
        data = { monitors: [], openIncidents: [], statusPages: [], uptimeServiceAvailable: false };
      }
    } else if (clean === 'culkibo://environments') {
      const em = lazySvc('environmentManager');
      const visibleProjects = projectManager.getAll().filter((p) => canAccessProject(principal, p.id, p));
      const items = visibleProjects.map((p) => {
        const rawEnvs = em && typeof em.listEnvironments === 'function' ? em.listEnvironments(p.id) : [];
        const environments = Array.isArray(rawEnvs) && rawEnvs.length > 0
          ? rawEnvs.map((e) => sanitizeEnvObject(e))
          : [{ name: 'production', branch: p.gitBranch || 'main', serverId: p.serverId || 'local', envVarKeys: Object.keys(p.envVars || {}) }];
        return {
          projectId: p.id,
          name: p.name,
          serverId: p.serverId || 'local',
          environments,
          canary: typeof deployManager.getCanaryState === 'function' ? deployManager.getCanaryState(p.id) : null,
          freeze: evaluateProjectFreeze(p)
        };
      });
      data = { projects: items };
    } else {
      throw new McpToolError('RESOURCE_NOT_FOUND', `Recurso desconocido: '${clean}'.`, {
        retryable: false,
        remediation: 'Llama a resources/list para consultar los URIs disponibles.'
      });
    }
    return {
      contents: [
        { uri: clean, mimeType: 'application/json', text: JSON.stringify(data, null, 2) }
      ]
    };
  }

  listPrompts() {
    return [
      {
        name: 'debug-failed-deploy',
        description: 'Guía paso a paso para diagnosticar un despliegue fallido, leer sus logs, comprobar Docker/disco y proponer un fix seguro.',
        arguments: [
          { name: 'projectId', description: 'ID del proyecto que falló al desplegar', required: true }
        ]
      },
      {
        name: 'zero-downtime-release',
        description: 'Checklist operativo para lanzar una nueva versión en producción sin cortes y con plan de rollback instantáneo.',
        arguments: [
          { name: 'projectId', description: 'ID del proyecto a liberar en Citadel', required: true }
        ]
      },
      {
        name: 'audit-security-tls',
        description: 'Audita la postura de seguridad del servidor: TLS/HTTPS, Basic Auth, exposición de BDs, Doctor del sistema y alertas.',
        arguments: []
      },
      {
        name: 'culkibo_multi_server_rollout',
        description: 'Orquesta un despliegue progresivo multi-servidor verificando flota SSH, ventanas de freeze, previsualización dryRun, canary y smoke tests con auto-rollback.',
        arguments: [
          { name: 'projectId', description: 'ID del proyecto a desplegar en la flota', required: true },
          { name: 'targetServers', description: 'Lista opcional separada por comas de serverIds objetivo', required: false },
          { name: 'canarySteps', description: 'Pasos canarios opcionales (p. ej. "10,50,100")', required: false }
        ]
      },
      {
        name: 'culkibo_incident_triage',
        description: 'Triaje sistemático de incidentes en producción usando uptime, pods, flota, diagnóstico de dominio, logs, cost advisor y conflictos de LiveSync.',
        arguments: [
          { name: 'projectId', description: 'ID del proyecto afectado (opcional)', required: false },
          { name: 'hostname', description: 'Dominio afectado (opcional)', required: false }
        ]
      }
    ];
  }

  getPrompt(name, args = {}) {
    const pid = args && args.projectId ? String(args.projectId) : '<projectId>';
    if (name === 'debug-failed-deploy') {
      return {
        description: 'Diagnóstico sistemático de despliegue fallido en Culkibo',
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Diagnostica el fallo de despliegue del proyecto ${pid}: 1) Llama a culkibo_list_deployments y culkibo_get_deployment_logs para leer el error exacto; 2) Llama a culkibo_get_project y culkibo_system_doctor para descartar disco lleno, Docker caído o variables ausentes; 3) Explica la causa raíz y los pasos exactos para resolverlo.`
            }
          }
        ]
      };
    }
    if (name === 'zero-downtime-release') {
      return {
        description: 'Flujo seguro de publicación zero-downtime en Citadel',
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Prepara el lanzamiento sin cortes del proyecto ${pid}: 1) Verifica el proyecto con culkibo_get_project y culkibo_deploy_strategy; 2) Si tiene bases de datos vinculadas, sugiere o crea copia previa con culkibo_database_backup; 3) Despliega con culkibo_deploy_production (o culkibo_promote_forge si viene de Live Sync); 4) Confirma salud en culkibo_ingress_status y culkibo_get_container_logs.`
            }
          }
        ]
      };
    }
    if (name === 'audit-security-tls') {
      return {
        description: 'Auditoría integral de seguridad, TLS y copias',
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: 'Realiza una auditoría completa de esta instancia de Culkibo: 1) Ejecuta culkibo_system_doctor; 2) Revisa culkibo_ingress_status (con probe: true) y culkibo_manage_wildcard_dns01 (action: list); 3) Verifica en culkibo_list_databases que ninguna BD esté expuesta innecesariamente en 0.0.0.0 y que tengan copias programadas; 4) Resume hallazgos por prioridad P0-P2.'
            }
          }
        ]
      };
    }
    if (name === 'culkibo_multi_server_rollout') {
      const targetServers = args && args.targetServers ? String(args.targetServers) : 'los nodos configurados en la flota';
      const canarySteps = args && args.canarySteps ? String(args.canarySteps) : '10, 50, 100';
      return {
        description: 'Despliegue progresivo multi-servidor con canary, smoke tests y dryRun',
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Ejecuta un rollout multi-servidor seguro para el proyecto ${pid} hacia ${targetServers} con pasos canarios [${canarySteps}]: 1) Lee el recurso culkibo://fleet y sondea cada nodo objetivo con culkibo_fleet_probe_server (verificando Docker/Caddy/RAM y huella TOFU); 2) Comprueba ventanas de congelación con culkibo_deploy_freeze (action: "list"); 3) Previsualiza el impacto con culkibo_deploy_production (dryRun: true) y culkibo_fleet_assign_project (dryRun: true); 4) Tras confirmar el plan, despliega progresivamente con culkibo_canary_rollout y verifica cada paso con culkibo_smoke_test_run activando autoRollbackOnSmokeFail: true.`
            }
          }
        ]
      };
    }
    if (name === 'culkibo_incident_triage') {
      const hostHint = args && args.hostname ? ` y dominio ${String(args.hostname)}` : '';
      return {
        description: 'Triaje sistemático de incidentes en producción con rollback seguro',
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Realiza el triaje del incidente para el proyecto ${pid}${hostHint}: 1) Lee los recursos culkibo://uptime, culkibo://pods y culkibo://fleet; 2) Ejecuta culkibo_diagnose_domain (si aplica), culkibo_get_container_logs, culkibo_get_deployment_logs y culkibo_cost_advisor para detectar OOM, saturación de disco/RAM o errores recientes; 3) Comprueba cambios recientes o colisiones en LiveSync con culkibo_sync_conflicts y culkibo_sync_file_history; 4) Previsualiza un rollback seguro con culkibo_rollback_deployment (dryRun: true) o culkibo_sync_rollback_file (dryRun: true); 5) Pide confirmación explícita antes de activar culkibo_toggle_maintenance o publicar un incidente con culkibo_status_page_manage.`
            }
          }
        ]
      };
    }
    throw new McpToolError('PROMPT_NOT_FOUND', `Prompt desconocido: '${name}'.`, {
      retryable: false,
      remediation: 'Llama a prompts/list para ver los prompts disponibles.'
    });
  }

  /**
   * Convierte cualquier excepción en un sobre que un agente pueda accionar.
   *
   * Los errores que no vienen ya tipados se clasifican por la anotación
   * `openWorldHint` de la herramienta: si habla con un tercero (Cloudflare,
   * GitHub, una CA ACME) el fallo es casi siempre transitorio y reintentarlo
   * tiene sentido; si es local, reintentar sin cambiar nada solo repite el
   * fallo.
   */
  describeToolFailure(toolName, tool, err, durationMs) {
    const typed = err instanceof McpToolError;
    const openWorld = Boolean(tool && tool.annotations && tool.annotations.openWorldHint);
    return {
      ok: false,
      tool: toolName,
      code: typed ? err.code : (openWorld ? 'UPSTREAM_ERROR' : 'INTERNAL_ERROR'),
      message: err && err.message ? err.message : String(err),
      retryable: typed ? err.retryable : openWorld,
      remediation: typed
        ? err.remediation
        : (openWorld
          ? 'El servicio externo falló o no respondió. Reintenta en unos segundos; si persiste, comprueba credenciales y conectividad.'
          : 'Revisa los argumentos y el estado del daemon con culkibo_docker_status o culkibo_list_pods antes de reintentar.'),
      details: typed ? err.details : {},
      durationMs: Math.round(durationMs),
      timestamp: new Date().toISOString()
    };
  }

  // -------------------------------------------------------------------------
  // Era antigua (2024-11-05): handshake `initialize` y sesión implícita.
  //
  // DEPRECADO. Se mantiene porque romper las configuraciones ya instaladas de
  // Cursor y Claude Desktop sería peor que arrastrarlo, pero no recibe
  // funciones nuevas: lo nuevo vive en `handleModernRpc`.
  // -------------------------------------------------------------------------
  /**
   * @param {any} request
   * @param {{ auth?: any, transport?: string }} [context]
   */
  async handleJsonRpc(request, context = {}) {
    if (!request || typeof request !== 'object' || Array.isArray(request) || typeof request.method !== 'string') {
      return { jsonrpc: '2.0', id: null, error: { code: ERROR_CODES.INVALID_REQUEST, message: 'Invalid JSON-RPC request' } };
    }
    const { id, method, params } = request;
    const safeId = id === undefined ? null : id;

    if (id === undefined && method.startsWith('notifications/')) {
      return null;
    }

    if (method === 'ping') {
      return { jsonrpc: '2.0', id: safeId, result: {} };
    }

    if (method === 'initialize') {
      return {
        jsonrpc: '2.0',
        id: safeId,
        result: {
          protocolVersion: LEGACY_PROTOCOL_VERSION,
          capabilities: { tools: {}, resources: {}, prompts: {} },
          serverInfo: SERVER_INFO,
          instructions: `Este endpoint habla la revisión ${LEGACY_PROTOCOL_VERSION}, deprecada. Culkibo ya sirve la revisión ${PROTOCOL_VERSION} en POST /api/mcp (Streamable HTTP, sin handshake).`
        }
      };
    }

    if (method === 'tools/list') {
      return {
        jsonrpc: '2.0',
        id: safeId,
        result: {
          tools: this.getToolsForPrincipal(context.auth)
        }
      };
    }

    if (method === 'tools/call') {
      const toolName = params?.name;
      const args = params?.arguments === undefined ? {} : params.arguments;
      const toolResult = await this.executeTool(toolName, args, {
        transport: context.transport || `MCP ${LEGACY_PROTOCOL_VERSION} (deprecado)`,
        auth: context.auth
      });
      return {
        jsonrpc: '2.0',
        id: safeId,
        result: toolResult
      };
    }

    if (method === 'resources/list') {
      return { jsonrpc: '2.0', id, result: { resources: this.listResources(context.auth) } };
    }

    if (method === 'resources/read') {
      try {
        return { jsonrpc: '2.0', id, result: await this.readResource(params?.uri, { auth: context.auth }) };
      } catch (err) {
        return { jsonrpc: '2.0', id, error: { code: ERROR_CODES.INVALID_PARAMS, message: err.message } };
      }
    }

    if (method === 'prompts/list') {
      return { jsonrpc: '2.0', id, result: { prompts: this.listPrompts() } };
    }

    if (method === 'prompts/get') {
      try {
        return { jsonrpc: '2.0', id, result: this.getPrompt(params?.name, params?.arguments || {}) };
      } catch (err) {
        return { jsonrpc: '2.0', id, error: { code: ERROR_CODES.INVALID_PARAMS, message: err.message } };
      }
    }

    return {
      jsonrpc: '2.0',
      id,
      error: {
        code: ERROR_CODES.METHOD_NOT_FOUND,
        message: `Method '${method}' not found`,
        data: {
          supported: ['initialize', 'tools/list', 'tools/call', 'resources/list', 'resources/read', 'prompts/list', 'prompts/get'],
          hint: `Este endpoint sirve la revisión ${LEGACY_PROTOCOL_VERSION}. Para ${PROTOCOL_VERSION} usa POST /api/mcp.`
        }
      }
    };
  }

  // -------------------------------------------------------------------------
  // Era moderna (2026-07-28): sin handshake, sin sesión, versión por petición.
  // -------------------------------------------------------------------------

  /**
   * Respuesta de `server/discover`: versiones, capacidades e identidad en una
   * sola llamada. La especificación la hace obligatoria.
   */
  getDiscoverResult() {
    if (!this._discoverCache) {
      this._discoverCache = {
        supportedVersions: SUPPORTED_PROTOCOL_VERSIONS,
        capabilities: {
          tools: { listChanged: false },
          resources: { listChanged: false },
          prompts: { listChanged: false }
        },
        instructions: [
          'Culkibo es un orquestador cloud autohospedado (MCP 2.0: 104 herramientas anotadas, 7 recursos y 5 prompts). Gestiona proyectos, pods (The Forge y The Citadel), flota multi-servidor SSH, equipos/RBAC, entornos y promoción, uptime y páginas de estado, GitOps (culkibo.yaml), Smart Sleep y Cost Advisor, LiveSync 2.0 time-travel, smoke tests, canary auto-guard, deploy freeze, dominios, TLS, BDs y migraciones.',
          'Empieza por culkibo_rbac_whoami, culkibo_list_projects y culkibo_list_pods (o lee culkibo://projects, culkibo://fleet, culkibo://uptime y culkibo://environments) antes de modificar nada.',
          'Las herramientas destructivas y de despliegue soportan dryRun: true para previsualizar el radio de impacto (DryRunPlan) sin mutar estado ni disparar webhooks; confírmalas siempre con la persona usuaria antes de aplicarlas.',
          'Cuando una llamada falla, el bloque de texto del resultado es un JSON con code, retryable y remediation: úsalo para decidir si reintentar o corregir los argumentos.'
        ].join(' '),
        ttlMs: 300000,
        cacheScope: 'public'
      };
    }
    return this._discoverCache;
  }

  /**
   * Despacha una petición JSON-RPC de la revisión 2026-07-28.
   *
   * @param {any} request mensaje JSON-RPC completo
   * @param {{ transport?: string, clientInfo?: any, isCancelled?: () => boolean, signal?: AbortSignal, onProgress?: (msg: string) => void, auth?: any }} context
   */
  async handleModernRpc(request, context = {}) {
    if (!request || typeof request !== 'object' || Array.isArray(request) || typeof request.method !== 'string') {
      return { jsonrpc: '2.0', id: null, error: { code: ERROR_CODES.INVALID_REQUEST, message: 'Invalid JSON-RPC request' } };
    }
    const { id, method, params } = request;
    const transport = context.transport || `MCP ${PROTOCOL_VERSION}`;
    const clientInfo = context.clientInfo || params?._meta?.[META_CLIENT_INFO] || null;
    const principal = normalizePrincipal(context.auth);

    const ok = (result) => ({
      jsonrpc: '2.0',
      id,
      result: {
        resultType: 'complete',
        ...result,
        _meta: { ...(result._meta || {}), [META_SERVER_INFO]: SERVER_INFO }
      }
    });

    if (method === 'ping') {
      return ok({});
    }

    if (method === 'server/discover') {
      return ok(this.getDiscoverResult());
    }

    if (method === 'tools/list') {
      const tools = this.getToolsForPrincipal(principal);
      return ok({
        tools,
        ttlMs: principal.isSuperAdmin ? 60000 : 0,
        cacheScope: principal.isSuperAdmin ? 'public' : 'private'
      });
    }

    if (method === 'tools/call') {
      const toolName = params?.name;
      const args = params?.arguments === undefined ? {} : params.arguments;
      const toolResult = await this.executeTool(toolName, args, {
        transport,
        clientInfo,
        signal: context.signal,
        onProgress: context.onProgress,
        auth: context.auth
      });
      return ok(toolResult);
    }

    if (method === 'resources/list') {
      return ok({
        resources: this.listResources(principal),
        ttlMs: principal.isSuperAdmin ? 60000 : 0,
        cacheScope: principal.isSuperAdmin ? 'public' : 'private'
      });
    }

    if (method === 'resources/read') {
      try {
        return ok(await this.readResource(params?.uri, { auth: context.auth }));
      } catch (err) {
        return {
          jsonrpc: '2.0',
          id,
          error: { code: ERROR_CODES.INVALID_PARAMS, message: err.message, data: { uri: params?.uri } }
        };
      }
    }

    if (method === 'prompts/list') {
      return ok({ prompts: this.listPrompts(), ttlMs: 60000, cacheScope: 'public' });
    }

    if (method === 'prompts/get') {
      try {
        return ok(this.getPrompt(params?.name, params?.arguments || {}));
      } catch (err) {
        return {
          jsonrpc: '2.0',
          id,
          error: { code: ERROR_CODES.INVALID_PARAMS, message: err.message, data: { name: params?.name } }
        };
      }
    }

    return {
      jsonrpc: '2.0',
      id,
      error: {
        code: ERROR_CODES.METHOD_NOT_FOUND,
        message: `Este servidor no implementa el método '${method}'.`,
        data: { method, supported: MODERN_METHODS }
      }
    };
  }

  getClientConfigs(serverUrl = 'http://localhost:3030', { includeAuthPlaceholder = false } = {}) {
    const cleanUrl = String(serverUrl || 'http://localhost:3030').replace(/\/+$/, '');
    const cliEntry = path.resolve(__dirname, '..', '..', 'bin', 'culkibo.js');
    const isRemote = !/^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/i.test(cleanUrl);
    const needAuth = includeAuthPlaceholder || isRemote;
    const remoteHeaders = needAuth ? { Authorization: 'Bearer TU_CULKIBO_TOKEN' } : undefined;

    return {
      claudeDesktop: {
        mcpServers: {
          culkibo: {
            command: 'node',
            args: [cliEntry, 'mcp'],
            env: {
              CULKIBO_API_URL: cleanUrl,
              ...(needAuth ? { CULKIBO_TOKEN: 'TU_CULKIBO_TOKEN' } : {})
            }
          }
        }
      },
      // Clientes con transporte HTTP: el endpoint moderno, un solo POST.
      cursorOrWindsurf: {
        mcpServers: {
          culkibo: {
            url: `${cleanUrl}/api/mcp`,
            ...(remoteHeaders ? { headers: remoteHeaders } : {})
          }
        }
      },
      vscodeCopilot: {
        servers: {
          culkibo: {
            type: 'http',
            url: `${cleanUrl}/api/mcp`,
            ...(remoteHeaders ? { headers: remoteHeaders } : {})
          }
        }
      },
      claudeCodeCli: needAuth
        ? `claude mcp add --transport http culkibo ${cleanUrl}/api/mcp --header "Authorization: Bearer TU_CULKIBO_TOKEN"`
        : `claude mcp add --transport http culkibo ${cleanUrl}/api/mcp`,
      // Solo para clientes que aún no hablan 2026-07-28. Ver README.
      legacySse: {
        deprecated: true,
        protocolVersion: LEGACY_PROTOCOL_VERSION,
        note: `Transporte HTTP+SSE deprecado desde la revisión 2025-03-26. Migra a ${cleanUrl}/api/mcp.`,
        mcpServers: {
          culkibo: {
            url: `${cleanUrl}/api/mcp/sse`,
            ...(remoteHeaders ? { headers: remoteHeaders } : {})
          }
        }
      },
      protocol: {
        current: PROTOCOL_VERSION,
        supported: SUPPORTED_PROTOCOL_VERSIONS,
        endpoint: `${cleanUrl}/api/mcp`,
        legacyEndpoint: `${cleanUrl}/api/mcp/sse`,
        wsUrl: `${cleanUrl.replace(/^http/, 'ws')}/ws/sync`
      }
    };
  }
}

const mcpServer = Object.assign(new McpServer(), {
  // Constantes del protocolo, para que el transporte no las duplique.
  protocol: {
    PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
    LEGACY_PROTOCOL_VERSION,
    META_PROTOCOL_VERSION,
    META_CLIENT_INFO,
    META_CLIENT_CAPABILITIES,
    META_SERVER_INFO,
    ERROR_CODES,
    MODERN_METHODS,
    NAME_BEARING_METHODS,
    SERVER_INFO
  },
  McpToolError,
  TOOL_POLICIES,
  normalizePrincipal,
  lazySvc,
  redactForAudit
});

module.exports = mcpServer;
