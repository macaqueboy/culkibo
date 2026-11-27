const os = require('os');
const path = require('path');
const crypto = require('crypto');
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
  'sleepAdvisor',
  'secretScanner',
  'auditLogger'
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

const SENSITIVE_KEY_RE = /(token|password|passwd|secret|apikey|api_key|authorization|credential|connectionstring|envvars|passphrase|privatekey|private_key|sshkey|ssh_key|invitetoken|invite_token|tokenhash|token_hash|signingsecret|signing_secret|masterkey|master_key|confirmtoken|confirm_token)/i;
const SENSITIVE_VALUE_RE = /(ghp_|gho_|github_pat_|sk_|bearer\s+|ck[stihpr]_[A-Za-z0-9_-]{6,}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)/i;
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

/** Herramientas no destructivas que también soportan `dryRun: true` (33 destructivas + 2 = 35). */
const EXTRA_DRY_RUN_TOOLS = new Set([
  'culkibo_deploy_production',
  'culkibo_rollback_deployment'
]);

/** Perfiles de herramientas MCP para reducir el consumo de contexto en >=80% bajo demanda. */
const VALID_TOOL_PROFILES = Object.freeze(['all', 'core', 'deploy', 'ops', 'security']);

/** @type {Record<string, Set<string>>} */
const TOOL_PROFILES = Object.freeze({
  core: new Set([
    'culkibo_search_tools',
    'culkibo_rbac_whoami',
    'culkibo_list_projects',
    'culkibo_get_project',
    'culkibo_create_project',
    'culkibo_set_project_env',
    'culkibo_deploy_production',
    'culkibo_ship_and_verify',
    'culkibo_list_deployments',
    'culkibo_rollback_deployment',
    'culkibo_get_container_logs',
    'culkibo_get_deployment_logs',
    'culkibo_manage_domain',
    'culkibo_list_databases',
    'culkibo_system_doctor',
    'culkibo_diagnose_incident',
    'culkibo_auto_remediate'
  ]),
  deploy: new Set([
    'culkibo_search_tools',
    'culkibo_export_agent_kit',
    'culkibo_rbac_whoami',
    'culkibo_list_projects',
    'culkibo_get_project',
    'culkibo_create_project',
    'culkibo_add_resource',
    'culkibo_set_project_env',
    'culkibo_deploy_strategy',
    'culkibo_deploy_production',
    'culkibo_ship_and_verify',
    'culkibo_list_deployments',
    'culkibo_rollback_deployment',
    'culkibo_cancel_deployment',
    'culkibo_get_deploy_queue',
    'culkibo_get_deployment_logs',
    'culkibo_get_container_logs',
    'culkibo_manage_previews',
    'culkibo_smoke_test_configure',
    'culkibo_smoke_test_run',
    'culkibo_canary_rollout',
    'culkibo_deploy_freeze',
    'culkibo_env_list',
    'culkibo_env_promote'
  ]),
  ops: new Set([
    'culkibo_search_tools',
    'culkibo_export_agent_kit',
    'culkibo_rbac_whoami',
    'culkibo_list_projects',
    'culkibo_get_project',
    'culkibo_list_pods',
    'culkibo_get_logs',
    'culkibo_get_container_logs',
    'culkibo_get_observability',
    'culkibo_system_doctor',
    'culkibo_system_doctor_fix',
    'culkibo_docker_status',
    'culkibo_docker_containers',
    'culkibo_manage_production_service',
    'culkibo_toggle_maintenance',
    'culkibo_diagnose_domain',
    'culkibo_ingress_status',
    'culkibo_reconcile_ingress',
    'culkibo_uptime_list_monitors',
    'culkibo_status_page_manage',
    'culkibo_cost_advisor',
    'culkibo_sleep_status',
    'culkibo_sleep_manage',
    'culkibo_fleet_list_servers',
    'culkibo_diagnose_incident',
    'culkibo_auto_remediate'
  ]),
  security: new Set([
    'culkibo_search_tools',
    'culkibo_export_agent_kit',
    'culkibo_rbac_whoami',
    'culkibo_team_list_members',
    'culkibo_team_invite_member',
    'culkibo_team_update_member',
    'culkibo_rbac_list_tokens',
    'culkibo_rbac_manage_token',
    'culkibo_system_doctor',
    'culkibo_system_doctor_fix',
    'culkibo_diagnose_domain',
    'culkibo_ingress_status',
    'culkibo_manage_wildcard_dns01',
    'culkibo_set_domain_basic_auth',
    'culkibo_manage_webhook',
    'culkibo_deploy_freeze',
    'culkibo_list_databases',
    'culkibo_database_list_backups',
    'culkibo_export_instance_snapshot',
    'culkibo_diagnose_incident'
  ])
});

/** Sinónimos bilingües ES/EN para mejorar el ranking de `culkibo_search_tools` y `tools/list` (`params.query`). */
const SEARCH_SYNONYMS = Object.freeze({
  oom: ['memory', 'memoria', 'ram', 'crash', 'incident', 'advisor', 'cost', 'diagnose'],
  ram: ['memory', 'memoria', 'oom', 'advisor', 'sleep', 'cost'],
  memory: ['ram', 'memoria', 'oom', 'advisor', 'sleep'],
  ssl: ['tls', 'cert', 'wildcard', 'https', 'caddy', 'domain', 'ingress'],
  tls: ['ssl', 'cert', 'wildcard', 'https', 'caddy', 'domain', 'ingress'],
  db: ['database', 'postgres', 'mysql', 'mariadb', 'redis', 'valkey', 'mongodb', 'backup'],
  database: ['db', 'postgres', 'mysql', 'redis', 'backup', 'restore', 'credentials'],
  crash: ['incident', 'diagnose', 'remediate', 'rollback', 'logs', 'oom', 'restart'],
  incident: ['diagnose', 'remediate', 'uptime', 'status', 'rollback', 'logs', 'crash', 'oom'],
  heal: ['remediate', 'diagnose', 'doctor', 'fix', 'rollback', 'restart'],
  fix: ['remediate', 'doctor', 'diagnose', 'reconcile', 'rollback'],
  deploy: ['production', 'release', 'build', 'rollback', 'canary', 'smoke', 'freeze', 'preview', 'ship'],
  ship: ['deploy', 'verify', 'smoke', 'rollback', 'secret', 'production'],
  verify: ['ship', 'smoke', 'diagnose', 'sync', 'health'],
  secret: ['vault', 'env', 'ship', 'scan', 'redact'],
  rollback: ['revert', 'sync', 'deploy', 'remediate', 'ship'],
  auth: ['rbac', 'token', 'team', 'basic', 'whoami', 'security'],
  ssh: ['fleet', 'server', 'remote', 'node', 'probe'],
  sleep: ['hibernate', 'scale', 'idle', 'wake', 'cost', 'ram'],
  yaml: ['gitops', 'compose', 'manifest', 'plan', 'apply', 'export'],
  agent: ['kit', 'mcp', 'claude', 'cursor', 'windsurf', 'antigravity', 'codex', 'vscode', 'config'],
  claude: ['agent', 'kit', 'mcp', 'config', 'export'],
  cursor: ['agent', 'kit', 'mcp', 'config', 'export'],
  antigravity: ['agent', 'kit', 'mcp', 'config', 'export'],
  windsurf: ['agent', 'kit', 'mcp', 'config', 'export'],
  codex: ['agent', 'kit', 'mcp', 'config', 'export'],
  kit: ['agent', 'export', 'mcp', 'config']
});

const AUTO_REMEDIATE_ACTIONS = Object.freeze([
  'rollback_release',
  'restart_service',
  'wake_service',
  'toggle_maintenance',
  'reconcile_ingress',
  'doctor_fix'
]);

const GLOBAL_REMEDIATE_ACTIONS = new Set(['reconcile_ingress', 'doctor_fix']);
const DOCTOR_FIX_CANONICAL_ACTIONS = Object.freeze([
  'reconcile_caddy',
  'clean_tmp',
  'start_caddy',
  'clean_orphans',
  'prune_buildkit'
]);
const REMEDIATION_TOKEN_TTL_MS = 5 * 60 * 1000;
const MAX_PENDING_REMEDIATIONS = 200;

/**
 * Mapa paralelo de políticas RBAC para las 107 herramientas MCP (no se filtra al JSON Schema).
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
  culkibo_deploy_freeze: { minRole: 'admin', scope: 'deployments:freeze', projectScoped: true },
  // MCP 2.1: Meta-Discovery & Autonomous Self-Healing Ops (+3 = 107)
  culkibo_search_tools: { minRole: 'viewer', scope: 'tools:read', projectScoped: false },
  culkibo_diagnose_incident: { minRole: 'viewer', scope: 'observability:read', projectScoped: true },
  culkibo_auto_remediate: { minRole: 'developer', scope: 'deployments:write', projectScoped: true },
  // MCP 2026 Pioneer: Autonomous Ship-and-Verify & 1-Click Agent Kit Generator (+2 = 109)
  culkibo_ship_and_verify: { minRole: 'developer', scope: 'deployments:write', projectScoped: true },
  culkibo_export_agent_kit: { minRole: 'viewer', scope: 'tools:read', projectScoped: false }
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
      throw new McpToolError('INVALID_ARGUMENT', `Smoke check #${idx + 1} debe ser un objeto.`, {
        retryable: true,
        remediation: 'Cada elemento de checks[] debe ser un objeto { path: "/health", expectedStatus: 200 }.'
      });
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
      throw new McpToolError('INVALID_ARGUMENT', `Método HTTP no permitido en smoke check #${idx + 1}: '${method}'.`, {
        retryable: true,
        remediation: 'Usa uno de los métodos permitidos para smoke checks: GET, HEAD o POST.'
      });
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
/** @type {Record<string, string>} */
const DEFAULT_ERROR_REMEDIATIONS = Object.freeze({
  FORBIDDEN: 'Consulta tus permisos efectivos con culkibo_rbac_whoami o solicita un token con el rol y scopes necesarios.',
  MISSING_ARGUMENT: 'Revisa el inputSchema de la herramienta (o usa culkibo_search_tools) y repite la llamada con los parámetros obligatorios.',
  INVALID_ARGUMENT: 'Ajusta el tipo, rango o patrón del argumento según el inputSchema y vuelve a llamar.',
  INVALID_ARGUMENTS: 'Envía un objeto JSON plano en params.arguments.',
  NOT_FOUND: 'Verifica el identificador llamando primero a la herramienta de listado correspondiente.',
  SERVICE_UNAVAILABLE: 'Comprueba el estado de los servicios con culkibo_system_doctor antes de reintentar.',
  CANCELLED: 'La petición fue cancelada por el cliente; vuelve a invocarla si aún necesitas el resultado.',
  CONFIRMATION_REQUIRED: 'Ejecuta primero la herramienta con dryRun: true para revisar el plan y obtener un confirmToken válido de un solo uso.',
  CONFIRM_TOKEN_INVALID: 'Solicita un nuevo confirmToken ejecutando culkibo_auto_remediate con dryRun: true.',
  CONFIRM_TOKEN_EXPIRED: 'El confirmToken caducó (5 min); genera uno nuevo con culkibo_auto_remediate y dryRun: true.',
  CONFIRM_TOKEN_REPLAYED: 'Cada confirmToken es de un solo uso; ejecuta dryRun: true para generar uno nuevo si necesitas repetir la acción.',
  CONFIRM_TOKEN_MISMATCH: 'El confirmToken está vinculado al llamante, acción, proyecto y parámetros exactos del dryRun; solicita uno nuevo para estos parámetros.',
  SECRET_LEAK_DETECTED: 'Mueve los secretos detectados al Vault cifrado de Culkibo (${vault.KEY}) o a secretos de entorno antes de desplegar.',
  CANARY_NOT_ACTIVE: 'Inicia primero un despliegue canario con culkibo_canary_rollout (action: "start") o consulta su estado con action: "status".',
  FORBIDDEN_PATH: 'Usa un directorio dentro del workspace actual o de la carpeta projects/ de Culkibo.'
});

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
    this.remediation = remediation || DEFAULT_ERROR_REMEDIATIONS[code] || 'Revisa los parámetros y ejecuta culkibo_system_doctor o culkibo_diagnose_incident si el problema persiste.';
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
  if (Array.isArray(expected)) {
    return expected.some((t) => matchesSchemaType(value, t));
  }
  switch (expected) {
    case 'string': return typeof value === 'string';
    case 'number': return typeof value === 'number' && Number.isFinite(value);
    case 'integer': return Number.isInteger(value);
    case 'boolean': return typeof value === 'boolean';
    case 'array': return Array.isArray(value);
    case 'object': return value !== null && typeof value === 'object' && !Array.isArray(value);
    case 'null': return value === null;
    default: return true;
  }
}

/**
 * Valida recursivamente un valor contra su especificación JSON Schema
 * (tipo, enum, minimum/maximum, minLength/maxLength/pattern, items, properties/required).
 * @param {string} toolName
 * @param {string} propPath
 * @param {any} value
 * @param {any} spec
 * @param {number} [depth]
 */
function validatePropertyValue(toolName, propPath, value, spec, depth = 0) {
  if (!spec || typeof spec !== 'object' || depth > 4 || value === undefined || value === null) return;

  if (Array.isArray(spec.enum) && !spec.enum.includes(value)) {
    throw new McpToolError(
      'INVALID_ARGUMENT',
      `El argumento '${propPath}' de ${toolName} no admite el valor ${JSON.stringify(value)}.`,
      {
        retryable: true,
        remediation: `Usa uno de estos valores para '${propPath}': ${spec.enum.join(', ')}.`,
        details: { argument: propPath, received: value, allowed: spec.enum }
      }
    );
  }

  if (spec.type && !matchesSchemaType(value, spec.type)) {
    throw new McpToolError(
      'INVALID_ARGUMENT',
      `El argumento '${propPath}' de ${toolName} debe ser de tipo ${Array.isArray(spec.type) ? spec.type.join('|') : spec.type}.`,
      {
        retryable: true,
        remediation: `Convierte '${propPath}' a ${Array.isArray(spec.type) ? spec.type.join('|') : spec.type} y vuelve a llamar.`,
        details: { argument: propPath, expectedType: spec.type, receivedType: jsonType(value) }
      }
    );
  }

  if (typeof value === 'number') {
    if (typeof spec.minimum === 'number' && value < spec.minimum) {
      throw new McpToolError(
        'INVALID_ARGUMENT',
        `El argumento '${propPath}' de ${toolName} debe ser >= ${spec.minimum} (recibido ${value}).`,
        {
          retryable: true,
          remediation: `Usa un valor numérico para '${propPath}' entre ${spec.minimum}${typeof spec.maximum === 'number' ? ` y ${spec.maximum}` : ' o superior'}.`,
          details: { argument: propPath, minimum: spec.minimum, maximum: spec.maximum ?? null, received: value }
        }
      );
    }
    if (typeof spec.maximum === 'number' && value > spec.maximum) {
      throw new McpToolError(
        'INVALID_ARGUMENT',
        `El argumento '${propPath}' de ${toolName} debe ser <= ${spec.maximum} (recibido ${value}).`,
        {
          retryable: true,
          remediation: `Usa un valor numérico para '${propPath}' <= ${spec.maximum}.`,
          details: { argument: propPath, minimum: spec.minimum ?? null, maximum: spec.maximum, received: value }
        }
      );
    }
    if (typeof spec.exclusiveMinimum === 'number' && value <= spec.exclusiveMinimum) {
      throw new McpToolError(
        'INVALID_ARGUMENT',
        `El argumento '${propPath}' de ${toolName} debe ser estrictamente > ${spec.exclusiveMinimum}.`,
        {
          retryable: true,
          remediation: `Usa un valor numérico mayor que ${spec.exclusiveMinimum} para '${propPath}'.`,
          details: { argument: propPath, exclusiveMinimum: spec.exclusiveMinimum, received: value }
        }
      );
    }
    if (typeof spec.exclusiveMaximum === 'number' && value >= spec.exclusiveMaximum) {
      throw new McpToolError(
        'INVALID_ARGUMENT',
        `El argumento '${propPath}' de ${toolName} debe ser estrictamente < ${spec.exclusiveMaximum}.`,
        {
          retryable: true,
          remediation: `Usa un valor numérico menor que ${spec.exclusiveMaximum} para '${propPath}'.`,
          details: { argument: propPath, exclusiveMaximum: spec.exclusiveMaximum, received: value }
        }
      );
    }
  }

  if (typeof value === 'string') {
    if (typeof spec.minLength === 'number' && value.length < spec.minLength) {
      throw new McpToolError(
        'INVALID_ARGUMENT',
        `El argumento '${propPath}' de ${toolName} debe tener al menos ${spec.minLength} caracteres.`,
        {
          retryable: true,
          remediation: `Proporciona un texto de al menos ${spec.minLength} caracteres para '${propPath}'.`,
          details: { argument: propPath, minLength: spec.minLength, receivedLength: value.length }
        }
      );
    }
    if (typeof spec.maxLength === 'number' && value.length > spec.maxLength) {
      throw new McpToolError(
        'INVALID_ARGUMENT',
        `El argumento '${propPath}' de ${toolName} excede la longitud máxima de ${spec.maxLength} caracteres.`,
        {
          retryable: true,
          remediation: `Acorta '${propPath}' a un máximo de ${spec.maxLength} caracteres.`,
          details: { argument: propPath, maxLength: spec.maxLength, receivedLength: value.length }
        }
      );
    }
    if (typeof spec.pattern === 'string' && spec.pattern.length > 0) {
      const re = new RegExp(spec.pattern);
      if (!re.test(value)) {
        throw new McpToolError(
          'INVALID_ARGUMENT',
          `El argumento '${propPath}' de ${toolName} no cumple el formato esperado (${spec.pattern}).`,
          {
            retryable: true,
            remediation: `Formatea '${propPath}' para que coincida con el patrón ${spec.pattern}.`,
            details: { argument: propPath, pattern: spec.pattern }
          }
        );
      }
    }
  }

  if (Array.isArray(value)) {
    if (typeof spec.minItems === 'number' && value.length < spec.minItems) {
      throw new McpToolError(
        'INVALID_ARGUMENT',
        `El array '${propPath}' de ${toolName} requiere al menos ${spec.minItems} elemento(s).`,
        {
          retryable: true,
          remediation: `Incluye al menos ${spec.minItems} elemento(s) en '${propPath}'.`,
          details: { argument: propPath, minItems: spec.minItems, receivedLength: value.length }
        }
      );
    }
    if (typeof spec.maxItems === 'number' && value.length > spec.maxItems) {
      throw new McpToolError(
        'INVALID_ARGUMENT',
        `El array '${propPath}' de ${toolName} admite como máximo ${spec.maxItems} elemento(s).`,
        {
          retryable: true,
          remediation: `Reduce '${propPath}' a un máximo de ${spec.maxItems} elemento(s).`,
          details: { argument: propPath, maxItems: spec.maxItems, receivedLength: value.length }
        }
      );
    }
    if (spec.items && typeof spec.items === 'object') {
      for (let i = 0; i < value.length; i++) {
        if (value[i] === undefined || value[i] === null) {
          throw new McpToolError(
            'INVALID_ARGUMENT',
            `El elemento '${propPath}[${i}]' de ${toolName} no puede ser nulo.`,
            {
              retryable: true,
              remediation: `Elimina valores nulos de '${propPath}' y vuelve a llamar.`,
              details: { argument: `${propPath}[${i}]` }
            }
          );
        }
        validatePropertyValue(toolName, `${propPath}[${i}]`, value[i], spec.items, depth + 1);
      }
    }
  }

  if (value && typeof value === 'object' && !Array.isArray(value) && spec.properties && typeof spec.properties === 'object') {
    const nestedReq = Array.isArray(spec.required) ? spec.required : [];
    for (const rk of nestedReq) {
      if (value[rk] === undefined || value[rk] === null || (spec.properties[rk]?.type === 'string' && typeof value[rk] === 'string' && value[rk].trim() === '')) {
        throw new McpToolError(
          'MISSING_ARGUMENT',
          `Falta el campo obligatorio '${propPath}.${rk}' en ${toolName}.`,
          {
            retryable: true,
            remediation: `Incluye '${rk}' dentro de '${propPath}' y vuelve a llamar.`,
            details: { argument: `${propPath}.${rk}` }
          }
        );
      }
    }
    for (const [nk, nv] of Object.entries(value)) {
      if (spec.properties[nk]) {
        validatePropertyValue(toolName, `${propPath}.${nk}`, nv, spec.properties[nk], depth + 1);
      }
    }
  }
}

/**
 * Validación de argumentos contra el `inputSchema` declarado.
 *
 * Se hace aquí y no en cada `case` porque el fallo de un agente casi siempre es
 * el mismo —falta un campo obligatorio, mete un valor fuera del enum/rango o
 * rompe un patrón/elemento de array— y ese fallo se corrige solo si la
 * respuesta dice exactamente qué falta.
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
    validatePropertyValue(tool.name, key, value, spec, 0);
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

/**
 * Esquemas de salida estructurada (`outputSchema`, MCP 2026-07-28) para herramientas core, RO y ops.
 * Garantizan contratos máquina-verificables en `structuredContent` sin inflar el catálogo.
 * @type {Record<string, Record<string, any>>}
 */
const DEFAULT_OUTPUT_SCHEMAS = Object.freeze({
  culkibo_get_project: { type: 'object', properties: { id: { type: 'string' }, name: { type: 'string' }, status: { type: 'string' }, envVarsKeys: { type: 'array' }, resources: { type: 'array' } } },
  culkibo_create_project: { type: 'object', properties: { id: { type: 'string' }, name: { type: 'string' }, status: { type: 'string' } } },
  culkibo_add_resource: { type: 'object', properties: { id: { type: 'string' }, name: { type: 'string' }, resources: { type: 'array' } } },
  culkibo_set_project_env: { type: 'object', properties: { id: { type: 'string' }, envVarsKeys: { type: 'array' } } },
  culkibo_deploy_project: { type: 'object', properties: { id: { type: 'string' }, status: { type: 'string' } } },
  culkibo_docker_status: { type: 'object', properties: { available: { type: 'boolean' }, mode: { type: 'string' }, containersRunning: { type: 'number' } } },
  culkibo_github_status: { type: 'object', properties: { connected: { type: 'boolean' } } },
  culkibo_github_list_repos: { type: 'object', properties: { repos: { type: 'array' } } },
  culkibo_github_get_branches: { type: 'object', properties: { branches: { type: 'array' } } },
  culkibo_github_auto_detect: { type: 'object', properties: { stack: { type: 'string' }, port: { type: 'number' } } },
  culkibo_deploy_strategy: { type: 'object', properties: { projectId: { type: 'string' }, contextDir: { type: 'string' }, strategy: { type: 'object' } } },
  culkibo_deploy_production: { type: 'object', properties: { id: { type: 'string' }, status: { type: 'string' } } },
  culkibo_list_deployments: { type: 'object', properties: { projectId: { type: 'string' }, status: { type: 'object' }, deployments: { type: 'array' } } },
  culkibo_rollback_deployment: { type: 'object', properties: { id: { type: 'string' }, status: { type: 'string' } } },
  culkibo_list_databases: { type: 'object', properties: { engines: { type: 'array' }, databases: { type: 'array' } } },
  culkibo_database_credentials: { type: 'object', properties: { engine: { type: 'string' }, connectionString: { type: 'string' } } },
  culkibo_list_catalog_templates: { type: 'object', properties: { categories: { type: 'array' }, templates: { type: 'array' } } },
  culkibo_list_catalog_installations: { type: 'object', properties: { installations: { type: 'array' } } },
  culkibo_verify_sync: { type: 'object', properties: { inSync: { type: 'boolean' }, serverDigest: { type: 'string' }, telemetry: { type: 'object' } } },
  culkibo_analyze_wordpress: { type: 'object', properties: { url: { type: 'string' }, isWordPress: { type: 'boolean' } } },
  culkibo_get_remote_access: { type: 'object', properties: { panelDomain: { type: ['string', 'null'] }, caddy: { type: 'object' }, cloudflare: { type: 'object' }, clientConfigs: { type: 'object' } } },
  culkibo_get_observability: { type: 'object', properties: { timestamp: { type: 'string' }, memory: { type: 'object' }, http: { type: 'object' } } },
  culkibo_system_doctor: { type: 'object', properties: { checks: { type: 'array' }, summary: { type: 'object' }, durationMs: { type: 'number' } } },
  culkibo_system_doctor_fix: { type: 'object', properties: { ok: { type: 'boolean' }, action: { type: 'string' }, message: { type: 'string' } } },
  culkibo_get_deploy_queue: { type: 'object', properties: { activeBuilds: { type: 'number' }, maxConcurrentBuilds: { type: 'number' }, queuedBuilds: { type: 'array' } } },
  culkibo_get_container_logs: { type: 'object', properties: { containerName: { type: ['string', 'null'] }, lines: { type: 'array' } } },
  culkibo_get_deployment_logs: { type: 'object', properties: { projectId: { type: 'string' }, deploymentId: { type: 'string' }, status: { type: 'string' }, totalLines: { type: 'number' }, lines: { type: 'array' } } },
  culkibo_diagnose_domain: { type: 'object', properties: { hostname: { type: 'string' }, checks: { type: 'array' } } },
  culkibo_ingress_status: { type: 'object', properties: { available: { type: 'boolean' }, routes: { type: 'array' } } },
  culkibo_reconcile_ingress: { type: 'object', properties: { ok: { type: 'boolean' } } },
  culkibo_manage_production_service: { type: 'object', properties: { projectId: { type: 'string' }, action: { type: 'string' } } },
  culkibo_toggle_maintenance: { type: 'object', properties: { success: { type: 'boolean' }, projectId: { type: 'string' }, maintenanceMode: { type: 'boolean' } } },
  culkibo_database_list_backups: { type: 'object', properties: { databaseId: { type: 'string' }, backups: { type: 'array' } } },
  culkibo_database_inspect: { type: 'object', properties: { healthy: { type: 'boolean' }, latencyMs: { type: 'number' } } },
  culkibo_list_backups: { type: 'object', properties: { backups: { type: 'array' } } },
  culkibo_fleet_probe_server: { type: 'object', properties: { serverId: { type: 'string' }, status: { type: 'string' } } },
  culkibo_team_list_members: { type: 'object', properties: { teamId: { type: 'string' }, multiUserEnabled: { type: 'boolean' }, members: { type: 'array' }, pendingInvites: { type: 'array' } } },
  culkibo_rbac_list_tokens: { type: 'object', properties: { tokens: { type: 'array' }, count: { type: 'number' } } },
  culkibo_env_diff: { type: 'object', properties: { fromEnv: { type: 'string' }, toEnv: { type: 'string' } } },
  culkibo_gitops_export: { type: 'object', properties: { yaml: { type: 'string' } } },
  culkibo_sleep_status: { type: 'object', properties: { sleeping: { type: 'boolean' }, policies: { type: 'array' }, candidates: { type: 'array' } } },
  culkibo_sync_file_history: { type: 'object', properties: { projectId: { type: 'string' }, filePath: { type: 'string' }, versions: { type: 'array' } } },
  culkibo_sync_conflicts: { type: 'object', properties: { projectId: { type: 'string' }, conflicts: { type: 'array' }, count: { type: 'number' } } },
  culkibo_smoke_test_run: { type: 'object', properties: { projectId: { type: 'string' }, target: { type: 'string' }, passed: { type: 'boolean' }, results: { type: 'array' } } },
  culkibo_canary_rollout: { type: 'object', properties: { projectId: { type: 'string' }, ok: { type: 'boolean' } } },
  culkibo_deploy_freeze: { type: 'object', properties: { scope: { type: 'string' }, frozen: { type: 'boolean' }, windows: { type: 'array' } } },
  culkibo_issue_wildcard_ssl: { type: 'object', properties: { implemented: { type: 'boolean' }, error: { type: 'string' } } }
});

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
    /** @type {Map<string, Buffer>} */
    this._profileSerializedCache = new Map();
    /** @type {any | null} */
    this._discoverCache = null;
    /** Clave efímera HMAC-SHA256 en memoria para tokens de confirmación de un solo uso (`culkibo_auto_remediate`). */
    this._remediationHmacKey = crypto.randomBytes(32);
    /** @type {Map<string, { exp: number, used: boolean, principalKey: string, action: string, projectId: string | null, paramsHash: string }>} */
    this._pendingRemediations = new Map();
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
            name: { type: 'string', minLength: 1, maxLength: 120, description: 'Nombre del proyecto' },
            description: { type: 'string', maxLength: 500, description: 'Descripción opcional del proyecto' },
            icon: { type: 'string', maxLength: 32, description: 'Emoji o icono del proyecto' },
            gitRepo: { type: 'string', maxLength: 512, description: 'URL del repositorio Git asociado' },
            forgePort: { type: 'integer', minimum: 1, maximum: 65535, description: 'Puerto interno para The Forge' },
            citadelPort: { type: 'integer', minimum: 1, maximum: 65535, description: 'Puerto interno para The Citadel' }
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
            projectId: { type: 'string', minLength: 1, description: 'ID del proyecto propietario' },
            type: { type: 'string', enum: ['app', 'database', 'service'], description: 'Tipo de recurso' },
            name: { type: 'string', minLength: 1, maxLength: 120, description: 'Nombre del recurso' },
            image: { type: 'string', maxLength: 256, description: 'Imagen Docker opcional del recurso' },
            envVars: { type: 'object', description: 'Variables de entorno iniciales del recurso' },
            ports: { type: 'array', items: { type: 'string' }, maxItems: 32, description: 'Mapeos de puertos del recurso' },
            credentials: { type: 'object', description: 'Credenciales opcionales del recurso (se redactan en auditoría)' }
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
          properties: { projectId: { type: 'string', minLength: 1, description: 'ID del proyecto' } },
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
            projectId: { type: 'string', minLength: 1, description: 'ID del proyecto' },
            resourceId: { type: 'string', description: 'Opcional. ID o nombre del recurso específico (app, database, service) para inyectar variables de entorno.' },
            envVars: { type: 'object', description: 'Mapa clave-valor de variables de entorno a inyectar o actualizar' }
          },
          required: ['projectId', 'envVars']
        }
      },
      {
        name: 'culkibo_deploy_project',
        title: 'Desplegar proyecto',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
        description: 'Activa o publica un proyecto (para despliegue completo Docker BuildKit + Caddy zero-downtime usa culkibo_deploy_production).',
        inputSchema: {
          type: 'object',
          properties: { projectId: { type: 'string', minLength: 1, description: 'ID del proyecto' } },
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
            forgePercent: { type: 'number', minimum: 0, maximum: 100, description: 'Percentage of traffic to The Forge (0-100)' },
            citadelPercent: { type: 'number', minimum: 0, maximum: 100, description: 'Percentage of traffic to The Citadel (0-100)' }
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
            hostname: { type: 'string', minLength: 1, maxLength: 253, description: 'Domain name (e.g. api.domain.com or *.domain.com)' },
            id: { type: 'string', description: 'Domain ID' },
            projectId: { type: 'string', description: 'Optional project ID to associate the domain with' },
            targetPod: { type: 'string', enum: ['forge', 'citadel'], description: 'Target pod to route traffic to' },
            targetPort: { type: 'integer', minimum: 1, maximum: 65535, description: 'Optional upstream target port (1-65535)' },
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
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
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
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
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
            projectId: { type: 'string', minLength: 1, description: 'ID del proyecto' },
            lines: { type: 'number', minimum: 10, maximum: 2000, description: 'Número de líneas (10–2000, default 200)' }
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
            projectId: { type: 'string', minLength: 1, description: 'ID del proyecto' },
            deploymentId: { type: 'string', description: 'ID del despliegue (opcional: el más reciente si se omite)' },
            tail: { type: 'number', minimum: 10, maximum: 2000, description: 'Últimas N líneas a devolver (10–2000, default 200)' }
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
        description: 'Ejecuta una reparación segura en 1 clic detectada por el Doctor del sistema (`reconcile_caddy`, `clean_tmp`, `start_caddy`, `clean_orphans`, `prune_buildkit`).',
        inputSchema: {
          type: 'object',
          properties: {
            action: {
              type: 'string',
              enum: ['reconcile_caddy', 'clean_tmp', 'start_caddy', 'clean_orphans', 'prune_buildkit', 'prune_build_cache'],
              description: 'Acción de auto-reparación a ejecutar (prune_build_cache actúa como alias compatible de prune_buildkit)'
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
            databaseId: { type: 'string', minLength: 1, description: 'ID de la base de datos' },
            enabled: { type: 'boolean', description: 'Activar o desactivar programación cron' },
            cron: { type: 'string', description: 'Expresión cron de 5 campos o alias (@hourly, @daily, @weekly)' },
            hourly: { type: 'number', minimum: 0, maximum: 168, description: 'Número de copias horarias a conservar (0–168)' },
            daily: { type: 'number', minimum: 0, maximum: 365, description: 'Número de copias diarias a conservar (0–365)' },
            weekly: { type: 'number', minimum: 0, maximum: 260, description: 'Número de copias semanales a conservar (0–260)' }
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
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
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
            domainId: { type: 'string', minLength: 1, description: 'ID del dominio (o hostname)' },
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
            limit: { type: 'number', minimum: 1, maximum: 100, description: 'Límite de entradas para history (1–100, default 20)' }
          },
          required: ['action']
        }
      },
      {
        name: 'culkibo_manage_webhook',
        title: 'Consultar estado de webhooks o rotar Deploy Hook',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
        description: 'Muestra las URLs de webhook multi-Git (GitHub/GitLab/Gitea/Bitbucket/CI Deploy Hook) de un proyecto o rota su `deployHookToken`.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', minLength: 1, description: 'ID del proyecto' },
            action: { type: 'string', enum: ['status', 'rotate_deploy_hook'], description: 'status para consultar, rotate_deploy_hook para generar nuevo token CI/CD' }
          },
          required: ['projectId', 'action']
        }
      },
      {
        name: 'culkibo_manage_crons',
        title: 'Gestionar tareas programadas (Cron Jobs) por proyecto',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
        description: 'Lista, crea, activa/desactiva, ejecuta manualmente o elimina Cron Jobs de un proyecto (`exec` dentro del contenedor o `http`).',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', minLength: 1, description: 'ID del proyecto' },
            action: { type: 'string', enum: ['list', 'create', 'toggle', 'run', 'delete'], description: 'Acción a realizar' },
            cronId: { type: 'string', description: 'ID del cron (para toggle/run/delete)' },
            name: { type: 'string', maxLength: 120, description: 'Nombre del cron (para create)' },
            schedule: { type: 'string', description: 'Expresión cron de 5 campos (para create)' },
            kind: { type: 'string', enum: ['exec', 'http'], description: 'Tipo de tarea (default exec)' },
            mode: { type: 'string', enum: ['exec', 'http'], description: 'Alias de kind (exec o http)' },
            command: { type: 'string', description: 'Comando sin shell dentro del contenedor (si kind=exec)' },
            url: { type: 'string', description: 'URL o ruta destino (si kind=http)' },
            httpPath: { type: 'string', description: 'Ruta HTTP relativa dentro del contenedor (ej. /api/cron, si mode=http)' },
            httpMethod: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'], description: 'Método HTTP para cron http (default POST)' },
            enabled: { type: 'boolean', description: 'Estado activo (para create/toggle)' }
          },
          required: ['projectId', 'action']
        }
      },
      {
        name: 'culkibo_manage_previews',
        title: 'Gestionar Preview Deployments por rama o PR',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
        description: 'Lista, despliega o destruye entornos de previsualización aislados por Pull Request o rama de un proyecto.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', minLength: 1, description: 'ID del proyecto' },
            action: { type: 'string', enum: ['list', 'deploy', 'destroy'], description: 'Acción sobre previews' },
            branch: { type: 'string', description: 'Rama Git del preview (para deploy/destroy)' },
            prNumber: { type: 'number', minimum: 1, description: 'Número de PR/MR (opcional)' },
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
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
        description: 'Configura páginas de estado públicas (/status/:slug) con aislamiento cero-fugas o publica/resuelve incidentes manuales.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['configure', 'publish_incident', 'resolve_incident', 'delete'], description: 'Operación sobre la página de estado' },
            slug: { type: 'string', minLength: 2, maxLength: 49, pattern: '^[a-z0-9][a-z0-9-]{1,48}$', description: 'Identificador URL público (p. ej. "status-prod")' },
            customDomain: { type: 'string', description: 'Dominio personalizado opcional' },
            title: { type: 'string', maxLength: 120, description: 'Título público de la página' },
            description: { type: 'string', maxLength: 500, description: 'Descripción pública opcional' },
            monitorIds: { type: 'array', items: { type: 'string' }, description: 'IDs de monitores visibles en la página' },
            incidentId: { type: 'string', description: 'ID del incidente (para resolve_incident)' },
            incidentTitle: { type: 'string', maxLength: 160, description: 'Título del incidente (para publish_incident)' },
            severity: { type: 'string', enum: ['minor', 'major', 'critical', 'maintenance'], description: 'Gravedad del incidente' },
            message: { type: 'string', maxLength: 1000, description: 'Actualización de estado del incidente' }
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
            monthlyServerCostEur: { type: 'number', minimum: 0, maximum: 100000, description: 'Coste mensual actual del VPS en EUR (opcional)' },
            vpsMonthlyEur: { type: 'number', minimum: 0, maximum: 100000, description: 'Alias opcional de monthlyServerCostEur' }
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
            projectId: { type: 'string', minLength: 1, description: 'ID del proyecto' },
            action: { type: 'string', enum: ['configure', 'sleep', 'wake'], description: 'Acción: configure, sleep o wake' },
            enabled: { type: 'boolean', description: 'Activar auto-sleep (para configure)' },
            mode: { type: 'string', enum: ['pause', 'stop'], description: 'Modo de suspensión del contenedor (default stop)' },
            idleMinutes: { type: 'number', minimum: 5, maximum: 10080, description: 'Minutos de inactividad antes de dormir (mínimo 5)' },
            wakeTimeoutMs: { type: 'number', minimum: 1000, maximum: 120000, description: 'Timeout de despertar en ms (opcional)' },
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
            projectId: { type: 'string', minLength: 1, description: 'ID del proyecto' },
            action: { type: 'string', enum: ['start', 'advance', 'promote', 'abort', 'status'], description: 'Acción sobre el rollout canario' },
            steps: { type: 'array', items: { type: 'number', minimum: 1, maximum: 100 }, minItems: 1, maxItems: 10, description: 'Pasos ascendentes de porcentaje canario (p. ej. [10, 50, 100])' },
            stepIntervalSec: { type: 'number', minimum: 3, maximum: 3600, description: 'Segundos de observación por paso (default 15)' },
            weightPercent: { type: 'number', minimum: 1, maximum: 100, description: 'Peso canario explícito opcional (1-100)' },
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
              maxItems: 32,
              description: 'Ventanas [{ days, startUtc, endUtc, startHour, endHour, tz, reason }] (para set)'
            },
            windowId: { type: 'string', description: 'ID de ventana a eliminar (opcional para remove)' }
          },
          required: ['action']
        }
      },

      // --- MCP 2.1: I. Meta-Discovery y Autocuración Autónoma (3 -> 107) ---
      {
        name: 'culkibo_search_tools',
        title: 'Buscar herramientas MCP bajo demanda (meta-discovery)',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string' },
            profile: { type: 'string' },
            totalAuthorized: { type: 'number' },
            matchedCount: { type: 'number' },
            tools: { type: 'array' },
            profiles: { type: 'object' }
          }
        },
        description: 'Busca semánticamente (ES/EN) entre las 109 herramientas autorizadas de Culkibo para descubrir sus esquemas bajo demanda sin saturar la ventana de contexto (ideal con ?profile=core).',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', maxLength: 120, description: 'Palabras clave o intención (p. ej. "postgres backup", "ssl wildcard", "oom", "canary")' },
            profile: { type: 'string', enum: ['all', 'core', 'deploy', 'ops', 'security'], description: 'Restringir la búsqueda a un perfil concreto (default all)' },
            readOnlyOnly: { type: 'boolean', description: 'Si true, devuelve solo herramientas de solo lectura' },
            includeSchema: { type: 'boolean', description: 'Incluir inputSchema y outputSchema completos (default true)' },
            limit: { type: 'integer', minimum: 1, maximum: 25, description: 'Máximo de herramientas devueltas (1–25, default 8)' }
          }
        }
      },
      {
        name: 'culkibo_diagnose_incident',
        title: 'Diagnosticar incidente autónomo y proponer plan de reparación',
        annotations: { readOnlyHint: true, openWorldHint: true },
        outputSchema: {
          type: 'object',
          properties: {
            incidentId: { type: 'string' },
            diagnosedAt: { type: 'string' },
            scope: { type: 'string' },
            severity: { type: 'string' },
            summary: { type: 'string' },
            signals: { type: 'object' },
            rootCauses: { type: 'array' },
            remediationPlan: { type: 'array' }
          }
        },
        description: 'Correlaciona en una sola llamada crashes/OOM del contenedor, despliegues recientes, logs redactados, monitores de uptime, RAM/disco/Smart Sleep, System Doctor, dominio/TLS, flota SSH y conflictos de LiveSync en causas raíz priorizadas y un plan seguro ejecutable con culkibo_auto_remediate.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', minLength: 1, description: 'ID del proyecto a diagnosticar (opcional; si se omite evalúa los proyectos accesibles y la salud global)' },
            hostname: { type: 'string', maxLength: 253, description: 'Dominio afectado opcional para sondear DNS/TLS/Caddy' },
            logLines: { type: 'integer', minimum: 10, maximum: 500, description: 'Líneas recientes de log del contenedor a inspeccionar (10–500, default 80)' },
            includeDoctor: { type: 'boolean', description: 'Incluir informe de System Doctor (default true)' },
            probeDomain: { type: 'boolean', description: 'Ejecutar sonda activa DNS/TLS contra hostname (default false salvo hostname explícito)' }
          }
        }
      },
      {
        name: 'culkibo_auto_remediate',
        title: 'Ejecutar remediación autónoma segura (dryRun + confirmToken)',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            executed: { type: 'boolean' },
            dryRun: { type: 'boolean' },
            action: { type: 'string' },
            projectId: { type: ['string', 'null'] },
            confirmToken: { type: 'string' },
            postVerification: { type: ['object', 'null'] }
          }
        },
        description: 'Ejecuta una acción de auto-reparación segura y permitida (`rollback_release`, `restart_service`, `wake_service`, `toggle_maintenance`, `reconcile_ingress`, `doctor_fix`). EXIGE flujo en dos pasos: primero `dryRun: true` para obtener `confirmToken` HMAC-SHA256 de un solo uso (5 min) y después confirmar pasando ese `confirmToken` con `dryRun: false`.',
        inputSchema: {
          type: 'object',
          properties: {
            action: {
              type: 'string',
              enum: ['rollback_release', 'restart_service', 'wake_service', 'toggle_maintenance', 'reconcile_ingress', 'doctor_fix'],
              description: 'Acción de remediación segura a ejecutar'
            },
            projectId: { type: 'string', minLength: 1, description: 'ID del proyecto (obligatorio para rollback_release, restart_service, wake_service y toggle_maintenance)' },
            confirmToken: { type: 'string', minLength: 16, maxLength: 512, description: 'Token HMAC-SHA256 de un solo uso emitido por esta misma herramienta con dryRun: true (obligatorio para aplicar)' },
            doctorFixAction: {
              type: 'string',
              enum: ['reconcile_caddy', 'clean_tmp', 'start_caddy', 'clean_orphans', 'prune_buildkit'],
              description: 'Subacción de System Doctor cuando action="doctor_fix"'
            },
            maintenanceEnabled: { type: 'boolean', description: 'Activar (true) o desactivar (false) modo mantenimiento cuando action="toggle_maintenance" (default true)' },
            verifyAfter: { type: 'boolean', description: 'Ejecutar verificación de salud/smoke checks tras aplicar el fix (default true)' }
          },
          required: ['action']
        }
      },

      // --- MCP 2026 Pioneer: Autonomous Ship-and-Verify & 1-Click Agent Kit Generator (+2 -> 109) ---
      {
        name: 'culkibo_ship_and_verify',
        title: 'Desplegar y verificar de forma autónoma (Ship & Verify)',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
        outputSchema: {
          type: 'object',
          properties: {
            phase: { type: 'string' },
            executed: { type: 'boolean' },
            dryRun: { type: 'boolean' },
            verified: { type: 'boolean' },
            wouldExecute: { type: 'boolean' },
            projectId: { type: 'string' },
            confirmToken: { type: 'string' },
            confirmTokenExpiresAt: { type: 'string' },
            secretScan: { type: 'object' },
            rollbackReadiness: { type: 'object' },
            deployment: { type: ['object', 'null'] },
            smokeVerification: { type: ['object', 'null'] },
            metricsSnapshot: { type: ['object', 'null'] },
            rollbackExecuted: { type: 'boolean' },
            rollbackResult: { type: ['object', 'null'] },
            blockers: { type: 'array' },
            warnings: { type: 'array' },
            nextStep: { type: 'string' }
          }
        },
        description: 'Despliegue autónomo en 2 fases: (1) dryRun: true ejecuta pre-flight secret scan, comprueba freeze/rollback readiness y emite confirmToken HMAC-SHA256 (5 min); (2) dryRun: false + confirmToken despliega, verifica smoke/métricas y hace auto-rollback si falla.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', minLength: 1, description: 'ID del proyecto' },
            confirmToken: { type: 'string', minLength: 16, maxLength: 512, description: 'Token HMAC de un solo uso emitido en dryRun: true' },
            commit: { type: 'string', maxLength: 64, description: 'Commit SHA o rama opcional' },
            gitSync: { type: 'boolean', description: 'Sincronizar Git antes de construir (default true)' },
            serverId: { type: 'string', maxLength: 64, description: 'Nodo destino de flota SSH' },
            secretScanMode: { type: 'string', enum: ['block', 'warn'], description: 'Política secret scan (default block; warn exige admin)' },
            runSmokeTests: { type: 'boolean', description: 'Ejecutar smoke checks post-deploy (default true)' },
            smokeChecks: {
              type: 'array',
              items: { type: 'object' },
              maxItems: 10,
              description: 'Smoke checks ad-hoc opcionales'
            },
            autoRollbackOnFailure: { type: 'boolean', description: 'Auto-rollback si fallan los smoke checks (default true)' },
            overrideFreeze: { type: 'boolean', description: 'Omitir deploy freeze (solo admin/owner)' }
          },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_export_agent_kit',
        title: 'Exportar kit de conexión MCP 1-clic para agentes IA',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            protocolVersion: { type: 'string' },
            profile: { type: 'string' },
            target: { type: 'string' },
            serverUrl: { type: 'string' },
            endpoint: { type: 'string' },
            tokenPlaceholder: { type: 'string' },
            containsPlaintextSecrets: { type: 'boolean' },
            tokenSavings: { type: 'object' },
            kits: { type: 'object' },
            playbooks: { type: 'array' }
          }
        },
        description: 'Genera configuraciones listas para copiar/escribir (drop-in) para Antigravity, Claude Code (.mcp.json + CLAUDE.md), Cursor (.cursor/mcp.json), Windsurf, OpenAI Codex CLI y VS Code Copilot usando ?profile=core por defecto (-82% tokens de contexto) y placeholders ${CULKIBO_TOKEN} sin incrustar jamás tokens maestros en claro.',
        inputSchema: {
          type: 'object',
          properties: {
            target: {
              type: 'string',
              enum: ['all', 'antigravity', 'claude-code', 'cursor', 'windsurf', 'codex', 'vscode'],
              description: 'Agente IA objetivo (default all)'
            },
            profile: {
              type: 'string',
              enum: ['core', 'deploy', 'ops', 'security', 'all'],
              description: 'Perfil de herramientas MCP (default core para ahorrar >80% de contexto)'
            },
            serverUrl: {
              type: 'string',
              maxLength: 256,
              description: 'URL base del servidor Culkibo (opcional; autodetecta dominio del panel o localhost)'
            },
            projectId: {
              type: 'string',
              minLength: 1,
              description: 'ID de proyecto opcional para personalizar el snippet CLAUDE.md'
            },
            includeOpsGuide: {
              type: 'boolean',
              description: 'Incluir guía operativa CLAUDE.md con playbooks y protocolo dryRun/confirmToken (default true)'
            }
          }
        }
      }
    ];

    // Inyección automática de `outputSchema` estructurados y del parámetro opcional `dryRun`
    // en todas las herramientas destructivas (33) + deploy_production y rollback_deployment (35 en total).
    for (const tool of this._toolsCache) {
      if (!tool.outputSchema && DEFAULT_OUTPUT_SCHEMAS[tool.name]) {
        tool.outputSchema = DEFAULT_OUTPUT_SCHEMAS[tool.name];
      }
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
   * Normaliza y valida un nombre de perfil MCP (`all | core | deploy | ops | security`).
   * @param {any} rawProfile
   * @returns {'all' | 'core' | 'deploy' | 'ops' | 'security'}
   */
  normalizeProfile(rawProfile) {
    if (rawProfile === undefined || rawProfile === null || String(rawProfile).trim() === '') {
      return 'all';
    }
    const clean = String(rawProfile).trim().toLowerCase();
    if (!VALID_TOOL_PROFILES.includes(/** @type {any} */ (clean))) {
      throw new McpToolError('INVALID_ARGUMENT', `Perfil MCP desconocido: '${rawProfile}'.`, {
        retryable: true,
        remediation: `Usa uno de los perfiles soportados: ${VALID_TOOL_PROFILES.join(', ')}.`,
        details: { received: rawProfile, allowed: VALID_TOOL_PROFILES }
      });
    }
    return /** @type {'all' | 'core' | 'deploy' | 'ops' | 'security'} */ (clean);
  }

  /**
   * Calcula puntuación de relevancia ES/EN de una herramienta para un texto de consulta.
   * @param {any} tool
   * @param {string} rawQuery
   * @returns {number}
   */
  scoreToolForQuery(tool, rawQuery) {
    const q = String(rawQuery || '').trim().toLowerCase();
    if (!q) return 1;
    const rawTokens = q.split(/[\s,._:/-]+/).filter((t) => t.length >= 2);
    if (rawTokens.length === 0) return 1;

    const name = String(tool.name || '').toLowerCase();
    const title = String(tool.title || '').toLowerCase();
    const desc = String(tool.description || '').toLowerCase();
    const scope = String(TOOL_POLICIES[tool.name]?.scope || '').toLowerCase();
    const paramNames = Object.keys(tool.inputSchema?.properties || {}).join(' ').toLowerCase();
    const haystack = `${name} ${title} ${desc} ${scope} ${paramNames}`;

    let score = 0;
    if (name === q || name === `culkibo_${q}`) score += 200;
    else if (name.includes(q)) score += 90;

    for (const tok of rawTokens) {
      let tokScore = 0;
      if (name.includes(tok)) tokScore += 40;
      if (scope.includes(tok)) tokScore += 22;
      if (title.includes(tok)) tokScore += 20;
      if (desc.includes(tok)) tokScore += 14;
      if (paramNames.includes(tok)) tokScore += 8;
      const syns = SEARCH_SYNONYMS[tok];
      if (tokScore === 0 && Array.isArray(syns)) {
        for (const syn of syns) {
          if (haystack.includes(syn)) {
            tokScore += 10;
            break;
          }
        }
      }
      score += tokScore;
    }
    return score;
  }

  /**
   * Devuelve las herramientas visibles para un principal RBAC concreto, opcionalmente
   * filtradas por perfil (`core|deploy|ops|security|all`), búsqueda textual (`query`),
   * `readOnlyOnly` y `limit`.
   * @param {any} [authOrPrincipal]
   * @param {{ profile?: string | null, query?: string | null, readOnlyOnly?: boolean, limit?: number | null }} [opts]
   */
  getToolsForPrincipal(authOrPrincipal = null, opts = {}) {
    const all = this.getToolsDefinition();
    const principal = normalizePrincipal(authOrPrincipal);
    let list = principal.isSuperAdmin
      ? all
      : all.filter((tool) => isToolAllowedForPrincipal(principal, tool.name, tool));

    const profile = this.normalizeProfile(opts && opts.profile);
    if (profile !== 'all') {
      const allowedSet = TOOL_PROFILES[profile];
      list = list.filter((tool) => allowedSet.has(tool.name));
    }

    if (opts && opts.readOnlyOnly === true) {
      list = list.filter((tool) => tool.annotations?.readOnlyHint === true);
    }

    if (opts && typeof opts.query === 'string' && opts.query.trim()) {
      const q = opts.query.trim();
      list = list
        .map((tool) => ({ tool, score: this.scoreToolForQuery(tool, q) }))
        .filter((x) => x.score > 0)
        .sort((a, b) => b.score - a.score || a.tool.name.localeCompare(b.tool.name))
        .map((x) => x.tool);
    }

    if (opts && typeof opts.limit === 'number' && Number.isFinite(opts.limit) && opts.limit > 0) {
      list = list.slice(0, Math.min(all.length, Math.floor(opts.limit)));
    }

    return list;
  }

  /**
   * Meta-discovery bajo demanda (`culkibo_search_tools`): busca solo dentro de las
   * herramientas autorizadas para `principal`, devolviendo esquemas completos bajo petición.
   * @param {ReturnType<typeof normalizePrincipal>} principal
   * @param {any} args
   */
  searchTools(principal, args = {}) {
    const profile = this.normalizeProfile(args.profile || 'all');
    const query = typeof args.query === 'string' ? args.query.trim() : '';
    const limit = Math.min(25, Math.max(1, Number(args.limit) || 8));
    const includeSchema = args.includeSchema !== false;
    const authorizedAll = this.getToolsForPrincipal(principal);
    const matched = this.getToolsForPrincipal(principal, {
      profile,
      query,
      readOnlyOnly: Boolean(args.readOnlyOnly),
      limit
    });

    const profileCounts = {
      all: authorizedAll.length,
      core: authorizedAll.filter((t) => TOOL_PROFILES.core.has(t.name)).length,
      deploy: authorizedAll.filter((t) => TOOL_PROFILES.deploy.has(t.name)).length,
      ops: authorizedAll.filter((t) => TOOL_PROFILES.ops.has(t.name)).length,
      security: authorizedAll.filter((t) => TOOL_PROFILES.security.has(t.name)).length
    };

    return {
      query,
      profile,
      totalAuthorized: authorizedAll.length,
      matchedCount: matched.length,
      tools: matched.map((t) => ({
        name: t.name,
        title: t.title,
        description: t.description,
        annotations: t.annotations,
        scope: TOOL_POLICIES[t.name]?.scope || null,
        supportsDryRun: this.supportsDryRun(t.name),
        ...(includeSchema ? { inputSchema: t.inputSchema, ...(t.outputSchema ? { outputSchema: t.outputSchema } : {}) } : {})
      })),
      profiles: profileCounts
    };
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
   * @param {{ profile?: string | null }} [opts]
   */
  getToolsSerialized(authOrPrincipal = null, opts = {}) {
    const principal = normalizePrincipal(authOrPrincipal);
    const profile = this.normalizeProfile(opts && opts.profile);
    if (principal.isSuperAdmin) {
      if (profile === 'all' && this._toolsSerializedCache) {
        return this._toolsSerializedCache;
      }
      if (this._profileSerializedCache.has(profile)) {
        return /** @type {Buffer} */ (this._profileSerializedCache.get(profile));
      }
      const tools = this.getToolsForPrincipal(principal, { profile });
      const buf = Buffer.from(JSON.stringify({
        protocolVersion: PROTOCOL_VERSION,
        profile,
        tools,
        count: tools.length,
        cacheScope: 'public'
      }), 'utf8');
      this._profileSerializedCache.set(profile, buf);
      if (profile === 'all') this._toolsSerializedCache = buf;
      return buf;
    }
    const tools = this.getToolsForPrincipal(principal, { profile });
    return Buffer.from(JSON.stringify({
      protocolVersion: PROTOCOL_VERSION,
      profile,
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
   * Devuelve la lista de IDs de proyectos accesibles para `principal` (o `null` si superadmin).
   * @param {ReturnType<typeof normalizePrincipal>} principal
   * @returns {string[] | null}
   */
  _accessibleProjectIds(principal) {
    if (principal.isSuperAdmin) return null;
    return projectManager.getAll()
      .filter((p) => canAccessProject(principal, p.id, p))
      .map((p) => p.id);
  }

  /**
   * Identificador estable del principal para vincular tokens de confirmación HMAC-SHA256.
   * @param {ReturnType<typeof normalizePrincipal>} principal
   */
  _principalKey(principal) {
    return `${principal.method}:${principal.userId || 'anon'}:${principal.role}:${principal.teamId || 'global'}:${principal.tokenId || ''}`;
  }

  /**
   * Hash determinista de parámetros relevantes de `culkibo_auto_remediate` o `culkibo_ship_and_verify`.
   * @param {any} args
   */
  _remediationParamsHash(args) {
    const action = String(args.action || '');
    const canonical = action === 'ship_and_verify'
      ? JSON.stringify({
          action: 'ship_and_verify',
          projectId: args.projectId ? String(args.projectId) : null,
          commit: args.commit ? String(args.commit) : null,
          gitSync: args.gitSync !== false,
          serverId: args.serverId ? String(args.serverId) : null,
          secretScanMode: args.secretScanMode === 'warn' ? 'warn' : 'block',
          runSmokeTests: args.runSmokeTests !== false,
          autoRollbackOnFailure: args.autoRollbackOnFailure !== false,
          overrideFreeze: Boolean(args.overrideFreeze),
          smokeChecksCount: Array.isArray(args.smokeChecks) ? args.smokeChecks.length : 0
        })
      : JSON.stringify({
          action,
          projectId: args.projectId ? String(args.projectId) : null,
          doctorFixAction: args.doctorFixAction ? String(args.doctorFixAction) : null,
          maintenanceEnabled: action === 'toggle_maintenance' ? (args.maintenanceEnabled !== false) : null
        });
    return crypto.createHash('sha256').update(canonical).digest('hex').slice(0, 24);
  }

  /** Limpia tokens caducados y acota la tabla en memoria sin timers en segundo plano. */
  _prunePendingRemediations() {
    const now = Date.now();
    for (const [nonce, rec] of this._pendingRemediations.entries()) {
      if (now > rec.exp + 60000) {
        this._pendingRemediations.delete(nonce);
      }
    }
    while (this._pendingRemediations.size >= MAX_PENDING_REMEDIATIONS) {
      const oldestKey = this._pendingRemediations.keys().next().value;
      if (!oldestKey) break;
      this._pendingRemediations.delete(oldestKey);
    }
  }

  /**
   * Emite un token HMAC-SHA256 de un solo uso (TTL 5 min) vinculado a principal + acción + proyecto + parámetros.
   * @param {ReturnType<typeof normalizePrincipal>} principal
   * @param {any} args
   * @param {number} [ttlMs]
   */
  mintRemediationToken(principal, args, ttlMs = REMEDIATION_TOKEN_TTL_MS) {
    this._prunePendingRemediations();
    const nonce = crypto.randomBytes(12).toString('base64url');
    const clampedTtl = Math.min(REMEDIATION_TOKEN_TTL_MS, Math.max(1, Number(ttlMs) || REMEDIATION_TOKEN_TTL_MS));
    const exp = Date.now() + clampedTtl;
    const principalKey = this._principalKey(principal);
    const action = String(args.action || '');
    const projectId = args.projectId ? String(args.projectId) : null;
    const paramsHash = this._remediationParamsHash(args);

    const payload = Buffer.from(JSON.stringify({ n: nonce, e: exp, a: action, p: projectId, h: paramsHash }), 'utf8').toString('base64url');
    const sig = crypto
      .createHmac('sha256', this._remediationHmacKey)
      .update(`${payload}.${principalKey}`)
      .digest('base64url');

    this._pendingRemediations.set(nonce, {
      exp,
      used: false,
      principalKey,
      action,
      projectId,
      paramsHash
    });

    return {
      confirmToken: `ckr_${payload}.${sig}`,
      confirmTokenExpiresAt: new Date(exp).toISOString()
    };
  }

  /**
   * Valida firma HMAC-SHA256 en tiempo constante, expiración, vinculación y un solo uso.
   * @param {string} rawToken
   * @param {ReturnType<typeof normalizePrincipal>} principal
   * @param {any} args
   */
  verifyAndConsumeRemediationToken(rawToken, principal, args) {
    this._prunePendingRemediations();
    if (typeof rawToken !== 'string' || !rawToken.startsWith('ckr_')) {
      throw new McpToolError('CONFIRM_TOKEN_INVALID', 'El confirmToken proporcionado no tiene formato válido.', {
        retryable: true,
        remediation: 'Ejecuta culkibo_auto_remediate con dryRun: true para obtener un confirmToken válido.'
      });
    }
    const body = rawToken.slice(4);
    const dotIdx = body.lastIndexOf('.');
    if (dotIdx <= 0) {
      throw new McpToolError('CONFIRM_TOKEN_INVALID', 'El confirmToken está truncado o malformado.', {
        retryable: true,
        remediation: 'Ejecuta culkibo_auto_remediate con dryRun: true para obtener un nuevo confirmToken.'
      });
    }
    const payloadB64 = body.slice(0, dotIdx);
    const providedSig = body.slice(dotIdx + 1);
    let decoded;
    try {
      decoded = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    } catch (e) {
      throw new McpToolError('CONFIRM_TOKEN_INVALID', 'No se pudo decodificar el confirmToken.', {
        retryable: true,
        remediation: 'Ejecuta culkibo_auto_remediate con dryRun: true para obtener un nuevo confirmToken.'
      });
    }
    const nonce = decoded && typeof decoded.n === 'string' ? decoded.n : '';
    const record = nonce ? this._pendingRemediations.get(nonce) : null;
    if (!record) {
      throw new McpToolError('CONFIRM_TOKEN_INVALID', 'El confirmToken no existe o ya expiró.', {
        retryable: true,
        remediation: 'Genera un nuevo confirmToken ejecutando culkibo_auto_remediate con dryRun: true.'
      });
    }
    if (record.used) {
      throw new McpToolError('CONFIRM_TOKEN_REPLAYED', 'Este confirmToken ya fue consumido (un solo uso).', {
        retryable: false,
        remediation: 'Genera un nuevo confirmToken con dryRun: true si deseas ejecutar una nueva remediación.'
      });
    }

    const callerKey = this._principalKey(principal);
    const expectedSig = crypto
      .createHmac('sha256', this._remediationHmacKey)
      .update(`${payloadB64}.${callerKey}`)
      .digest('base64url');
    const bufA = Buffer.from(providedSig, 'utf8');
    const bufB = Buffer.from(expectedSig, 'utf8');
    if (bufA.length !== bufB.length || !crypto.timingSafeEqual(bufA, bufB) || record.principalKey !== callerKey) {
      throw new McpToolError('CONFIRM_TOKEN_MISMATCH', 'El confirmToken no pertenece a tu sesión/principal o fue alterado.', {
        retryable: false,
        remediation: 'Solicita tu propio confirmToken ejecutando culkibo_auto_remediate con dryRun: true.'
      });
    }

    const reqAction = String(args.action || '');
    const reqProjectId = args.projectId ? String(args.projectId) : null;
    const reqParamsHash = this._remediationParamsHash(args);
    if (record.action !== reqAction || record.projectId !== reqProjectId || record.paramsHash !== reqParamsHash) {
      throw new McpToolError('CONFIRM_TOKEN_MISMATCH', 'El confirmToken no coincide con la acción, proyecto o parámetros solicitados.', {
        retryable: true,
        remediation: 'Usa exactamente la misma acción, projectId y parámetros que en el dryRun, o solicita un nuevo confirmToken.',
        details: { expectedAction: record.action, receivedAction: reqAction }
      });
    }

    if (Date.now() > record.exp) {
      this._pendingRemediations.delete(nonce);
      throw new McpToolError('CONFIRM_TOKEN_EXPIRED', 'El confirmToken ha caducado (validez máxima 5 minutos).', {
        retryable: true,
        remediation: 'Ejecuta culkibo_auto_remediate con dryRun: true para obtener un confirmToken fresco.'
      });
    }

    record.used = true;
    return { nonce, exp: record.exp };
  }

  /**
   * Diagnóstico autónomo correlacionado (`culkibo_diagnose_incident`).
   * @param {ReturnType<typeof normalizePrincipal>} principal
   * @param {any} args
   */
  async diagnoseIncident(principal, args = {}) {
    const incidentId = `inc_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const diagnosedAt = new Date().toISOString();
    const logLines = Math.min(500, Math.max(10, Number(args.logLines) || 80));
    const includeDoctor = args.includeDoctor !== false;

    const project = args.projectId ? projectManager.getById(String(args.projectId)) : null;
    if (args.projectId && !project) {
      throw projectNotFoundError(args.projectId);
    }

    const allowedProjectIds = this._accessibleProjectIds(principal);
    /** @type {Array<{ code: string, confidence: number, severity: 'critical' | 'high' | 'warning', title: string, evidence: string, affectedComponent: string }>} */
    const rootCauses = [];
    /** @type {Array<{ step: number, action: string, safe: boolean, automated: boolean, tool: string, args: Record<string, any>, dryRunRequired: boolean, rationale: string }>} */
    const remediationPlan = [];
    const plannedKeys = new Set();
    const addFix = (entry) => {
      const key = `${entry.tool}:${entry.action}:${JSON.stringify(entry.args)}`;
      if (plannedKeys.has(key)) return;
      plannedKeys.add(key);
      remediationPlan.push({ step: remediationPlan.length + 1, ...entry });
    };

    /** @type {Record<string, any>} */
    const signals = {
      container: null,
      deployments: null,
      logs: null,
      uptime: null,
      resources: null,
      doctor: null,
      domain: null,
      fleet: null,
      liveSync: null
    };

    // 1. Contenedor + Despliegues + Logs redactados + LiveSync (cuando hay projectId)
    if (project) {
      if (project.maintenanceMode) {
        rootCauses.push({
          code: 'MAINTENANCE_MODE_ACTIVE',
          confidence: 0.98,
          severity: 'warning',
          title: 'Proyecto en modo mantenimiento (HTTP 503)',
          evidence: `El proyecto '${project.name}' tiene maintenanceMode=true en Caddy.`,
          affectedComponent: 'ingress'
        });
        addFix({
          action: 'toggle_maintenance',
          safe: true,
          automated: true,
          tool: 'culkibo_auto_remediate',
          args: { action: 'toggle_maintenance', projectId: project.id, maintenanceEnabled: false, dryRun: true },
          dryRunRequired: true,
          rationale: 'Restaurar tráfico normal cuando finalice el mantenimiento.'
        });
      }

      const [depStatus, runtimeStats, runtimeLogs] = await Promise.all([
        deployManager.status(project.id).catch((e) => ({ error: e.message })),
        typeof deployManager.getRuntimeStats === 'function'
          ? deployManager.getRuntimeStats(project.id).catch((e) => ({ ok: false, error: e.message }))
          : Promise.resolve(null),
        typeof deployManager.getRuntimeLogs === 'function'
          ? deployManager.getRuntimeLogs(project.id, { lines: logLines }).catch((e) => ({ lines: [], error: e.message }))
          : Promise.resolve({ lines: [] })
      ]);

      const recentDeps = deployManager.listDeployments(project.id, 5).map(({ logLines: _ll, ...summary }) => summary);
      const latestDep = recentDeps[0] || null;
      signals.container = runtimeStats;
      signals.deployments = {
        current: depStatus?.current || null,
        previous: depStatus?.previous || null,
        recent: recentDeps
      };

      const rawLogLines = Array.isArray(runtimeLogs?.lines) ? runtimeLogs.lines : [];
      const oomLogHits = rawLogLines.filter((l) => /out of memory|oom|enomem|heap limit|allocation failed/i.test(String(l)));
      const crashLogHits = rawLogLines.filter((l) => /fatal|panic|unhandledpromiserejection|uncaughtexception|traceback|segfault|eaddrinuse/i.test(String(l)));
      const connLogHits = rawLogLines.filter((l) => /econnrefused|etimedout|econnreset|connection refused|too many connections|502|503|504/i.test(String(l)));
      signals.logs = {
        inspectedLines: rawLogLines.length,
        oomHits: oomLogHits.length,
        crashHits: crashLogHits.length,
        connectionHits: connLogHits.length,
        excerpts: [...oomLogHits.slice(-2), ...crashLogHits.slice(-2), ...connLogHits.slice(-2)].slice(0, 5)
      };

      if (runtimeStats?.oomKilled === true || oomLogHits.length > 0) {
        rootCauses.push({
          code: 'CONTAINER_OOM_KILLED',
          confidence: runtimeStats?.oomKilled === true ? 0.96 : 0.85,
          severity: 'critical',
          title: 'Contenedor terminado por falta de memoria (OOMKilled)',
          evidence: runtimeStats?.oomKilled === true
            ? `Docker reporta OOMKilled=true (restarts=${runtimeStats.restartCount ?? 0}).`
            : `Se detectaron ${oomLogHits.length} trazas OOM/heap en los últimos logs.`,
          affectedComponent: 'container'
        });
        if (depStatus?.previous) {
          addFix({
            action: 'rollback_release',
            safe: true,
            automated: true,
            tool: 'culkibo_auto_remediate',
            args: { action: 'rollback_release', projectId: project.id, dryRun: true },
            dryRunRequired: true,
            rationale: 'Revertir a la release anterior estable si la fuga de RAM empezó en el último despliegue.'
          });
        }
        addFix({
          action: 'restart_service',
          safe: true,
          automated: true,
          tool: 'culkibo_auto_remediate',
          args: { action: 'restart_service', projectId: project.id, dryRun: true },
          dryRunRequired: true,
          rationale: 'Reiniciar el contenedor tras revisar el límite de RAM con culkibo_cost_advisor.'
        });
      }

      if (Number(runtimeStats?.restartCount || 0) >= 3) {
        rootCauses.push({
          code: 'CONTAINER_CRASH_LOOP',
          confidence: 0.92,
          severity: 'critical',
          title: 'Bucle de reinicios del contenedor (CrashLoop)',
          evidence: `El contenedor acumula ${runtimeStats.restartCount} reinicios (status=${runtimeStats.status || 'unknown'}).`,
          affectedComponent: 'container'
        });
        if (depStatus?.previous) {
          addFix({
            action: 'rollback_release',
            safe: true,
            automated: true,
            tool: 'culkibo_auto_remediate',
            args: { action: 'rollback_release', projectId: project.id, dryRun: true },
            dryRunRequired: true,
            rationale: 'Revertir a la versión previa sana para cortar el bucle de reinicios.'
          });
        }
      } else if (depStatus?.current && runtimeStats && runtimeStats.running === false) {
        rootCauses.push({
          code: 'CONTAINER_STOPPED',
          confidence: 0.88,
          severity: 'critical',
          title: 'Contenedor de producción detenido',
          evidence: `Existe release activa (${depStatus.current.id || depStatus.current.containerName}) pero running=false.`,
          affectedComponent: 'container'
        });
        addFix({
          action: 'restart_service',
          safe: true,
          automated: true,
          tool: 'culkibo_auto_remediate',
          args: { action: 'restart_service', projectId: project.id, dryRun: true },
          dryRunRequired: true,
          rationale: 'Arrancar el contenedor de producción detenido y restaurar su ruta en Caddy.'
        });
      }

      if (runtimeStats?.health === 'unhealthy') {
        rootCauses.push({
          code: 'CONTAINER_UNHEALTHY',
          confidence: 0.87,
          severity: 'high',
          title: 'Healthcheck del contenedor en estado unhealthy',
          evidence: `Docker health=${runtimeStats.health} en ${runtimeStats.containerName || project.id}.`,
          affectedComponent: 'container'
        });
        addFix({
          action: 'restart_service',
          safe: true,
          automated: true,
          tool: 'culkibo_auto_remediate',
          args: { action: 'restart_service', projectId: project.id, dryRun: true },
          dryRunRequired: true,
          rationale: 'Reiniciar el servicio y ejecutar smoke checks post-reinicio.'
        });
      }

      if (latestDep && (latestDep.status === 'error' || latestDep.status === 'failed' || latestDep.status === 'fallido')) {
        rootCauses.push({
          code: 'RECENT_DEPLOY_FAILED',
          confidence: 0.9,
          severity: 'high',
          title: 'El despliegue más reciente falló',
          evidence: `Despliegue ${latestDep.id} falló en fase '${latestDep.stage || 'unknown'}'${latestDep.commit ? ` (commit ${String(latestDep.commit).slice(0, 8)})` : ''}: ${latestDep.error || 'ver logs'}.`,
          affectedComponent: 'deployment'
        });
        if (depStatus?.previous) {
          addFix({
            action: 'rollback_release',
            safe: true,
            automated: true,
            tool: 'culkibo_auto_remediate',
            args: { action: 'rollback_release', projectId: project.id, dryRun: true },
            dryRunRequired: true,
            rationale: 'Garantizar tráfico en la release anterior verificada mientras se corrige el commit fallido.'
          });
        }
      }

      if (connLogHits.length > 0) {
        rootCauses.push({
          code: 'UPSTREAM_OR_DB_CONNECTION_ERROR',
          confidence: 0.78,
          severity: 'high',
          title: 'Errores de conexión a base de datos o upstream en logs',
          evidence: `${connLogHits.length} líneas con ECONNREFUSED/ETIMEDOUT/502-504.`,
          affectedComponent: 'network'
        });
      } else if (crashLogHits.length > 0 && rootCauses.every((r) => r.code !== 'CONTAINER_CRASH_LOOP')) {
        rootCauses.push({
          code: 'APPLICATION_RUNTIME_ERRORS',
          confidence: 0.75,
          severity: 'high',
          title: 'Excepciones fatales en stdout/stderr de la aplicación',
          evidence: `${crashLogHits.length} líneas fatales detectadas en los últimos ${logLines} logs.`,
          affectedComponent: 'application'
        });
      }

      // LiveSync 2.0 conflictos
      try {
        const syncStatus = liveSyncEngine.getStatus(project.id);
        const conflicts = Array.isArray(syncStatus?.recentConflicts) ? syncStatus.recentConflicts : [];
        signals.liveSync = { conflictCount: conflicts.length, recentConflicts: conflicts.slice(0, 5) };
        if (conflicts.length > 0) {
          rootCauses.push({
            code: 'LIVESYNC_CONFLICTS_DETECTED',
            confidence: 0.7,
            severity: 'warning',
            title: 'Conflictos concurrentes en LiveSync 2.0',
            evidence: `${conflicts.length} conflicto(s) reciente(s) en The Forge.`,
            affectedComponent: 'sync'
          });
        }
      } catch (e) {
        signals.liveSync = { conflictCount: 0 };
      }

      // Flota SSH (si el proyecto corre en nodo remoto)
      const serverId = project.serverId || 'local';
      if (serverId !== 'local') {
        const fleet = lazySvc('serverFleetManager');
        const srv = fleet && typeof fleet.getServer === 'function' ? sanitizeFleetServer(fleet.getServer(serverId)) : null;
        signals.fleet = srv || { id: serverId, status: 'unknown' };
        if (srv && srv.status && srv.status !== 'online' && srv.status !== 'healthy') {
          rootCauses.push({
            code: 'FLEET_NODE_UNHEALTHY',
            confidence: 0.93,
            severity: 'critical',
            title: `Nodo remoto de flota '${srv.name || serverId}' degradado (${srv.status})`,
            evidence: `El proyecto está asignado al nodo '${serverId}' cuyo estado es '${srv.status}'.`,
            affectedComponent: 'fleet'
          });
        }
      } else {
        signals.fleet = { id: 'local', status: 'online' };
      }
    }

    // 2. Monitores de Uptime e incidentes abiertos
    const um = lazySvc('uptimeMonitor');
    if (um && typeof um.listMonitors === 'function') {
      const rawMons = um.listMonitors(project ? { projectId: project.id } : {});
      const monitors = (Array.isArray(rawMons) ? rawMons : []).filter((m) => {
        if (project && m.projectId !== project.id) return false;
        return canAccessProject(principal, m.projectId);
      });
      const openIncidents = typeof um.listIncidents === 'function'
        ? (um.listIncidents({ status: 'open' }) || []).filter((inc) => {
            if (project && inc.projectId && inc.projectId !== project.id) return false;
            return canAccessProject(principal, inc.projectId);
          })
        : [];
      const downMonitors = monitors.filter((m) => m.status === 'down' || m.lastStatus === 'down');
      signals.uptime = {
        totalMonitors: monitors.length,
        downCount: downMonitors.length,
        downMonitors: downMonitors.map((m) => ({ id: m.id, name: m.name, url: m.url || m.host, status: m.status })),
        openIncidents: openIncidents.slice(0, 10)
      };
      if (downMonitors.length > 0 || openIncidents.length > 0) {
        rootCauses.push({
          code: 'UPTIME_MONITOR_DOWN',
          confidence: 0.91,
          severity: 'critical',
          title: `${downMonitors.length || openIncidents.length} monitor(es) de uptime caídos o incidente abierto`,
          evidence: downMonitors.length > 0
            ? `Monitores caídos: ${downMonitors.map((m) => m.name || m.id).join(', ')}.`
            : `${openIncidents.length} incidente(s) abiertos en uptimeMonitor.`,
          affectedComponent: 'uptime'
        });
        if (project) {
          addFix({
            action: 'restart_service',
            safe: true,
            automated: true,
            tool: 'culkibo_auto_remediate',
            args: { action: 'restart_service', projectId: project.id, dryRun: true },
            dryRunRequired: true,
            rationale: 'Reiniciar el servicio para recuperar el endpoint monitorizado.'
          });
        }
      }
    }

    // 3. Smart Sleep + Cost/RAM Advisor
    const sa = lazySvc('sleepAdvisor');
    const isSleeping = project && sa && typeof sa.isSleeping === 'function' ? Boolean(sa.isSleeping(project.id)) : false;
    if (isSleeping && project) {
      rootCauses.push({
        code: 'PROJECT_SLEEPING',
        confidence: 0.97,
        severity: 'warning',
        title: 'El proyecto está hibernado por Smart Sleep',
        evidence: `sleepAdvisor.isSleeping('${project.id}') === true.`,
        affectedComponent: 'sleep'
      });
      addFix({
        action: 'wake_service',
        safe: true,
        automated: true,
        tool: 'culkibo_auto_remediate',
        args: { action: 'wake_service', projectId: project.id, dryRun: true },
        dryRunRequired: true,
        rationale: 'Despertar el contenedor desde Smart Sleep sin reconstruir.'
      });
    }
    if (sa && typeof sa.analyzeResources === 'function') {
      try {
        const advisor = await sa.analyzeResources(allowedProjectIds !== null ? { projectIds: allowedProjectIds } : {});
        signals.resources = {
          sleeping: isSleeping,
          freeRamPct: advisor?.host?.freeMemPct ?? advisor?.summary?.freeMemPct ?? null,
          reclaimableRamMb: advisor?.reclaimableRamMb ?? 0,
          recommendationsCount: Array.isArray(advisor?.recommendations) ? advisor.recommendations.length : 0
        };
        const freePct = Number(signals.resources.freeRamPct);
        if (Number.isFinite(freePct) && freePct >= 0 && freePct < 10) {
          rootCauses.push({
            code: 'HOST_MEMORY_PRESSURE',
            confidence: 0.89,
            severity: 'critical',
            title: `Presión severa de memoria en el host (${freePct}% RAM libre)`,
            evidence: `Queda menos de 10% de RAM libre en el servidor (recuperable: ${signals.resources.reclaimableRamMb} MB).`,
            affectedComponent: 'host'
          });
          addFix({
            action: 'doctor_fix',
            safe: true,
            automated: true,
            tool: 'culkibo_auto_remediate',
            args: { action: 'doctor_fix', doctorFixAction: 'prune_buildkit', dryRun: true },
            dryRunRequired: true,
            rationale: 'Liberar caché/contenedores huérfanos y evaluar Smart Sleep para recuperar RAM.'
          });
        }
      } catch (e) {
        signals.resources = { sleeping: isSleeping, error: e.message };
      }
    } else {
      signals.resources = {
        sleeping: isSleeping,
        totalRamMb: Math.round(os.totalmem() / 1048576),
        freeRamMb: Math.round(os.freemem() / 1048576)
      };
    }

    // 4. System Doctor (Caddy, Docker, disco, seguridad)
    if (includeDoctor) {
      try {
        const doc = await systemDoctor.runDoctor();
        const failing = (doc.checks || []).filter((c) => c.status === 'fail' || c.status === 'warn');
        signals.doctor = {
          summary: doc.summary,
          issues: failing.map((c) => ({ name: c.name, status: c.status, summary: c.summary, fixAction: c.fixAction || null }))
        };
        for (const issue of failing) {
          if (issue.status === 'fail' || issue.fixAction) {
            rootCauses.push({
              code: `DOCTOR_${String(issue.name || 'CHECK').toUpperCase().replace(/[^A-Z0-9]+/g, '_')}`,
              confidence: issue.status === 'fail' ? 0.88 : 0.72,
              severity: issue.status === 'fail' ? 'high' : 'warning',
              title: `System Doctor: ${issue.name} (${issue.status})`,
              evidence: issue.summary || issue.detail || '',
              affectedComponent: 'system'
            });
            if (issue.fixAction && DOCTOR_FIX_CANONICAL_ACTIONS.includes(/** @type {any} */ (issue.fixAction))) {
              addFix({
                action: 'doctor_fix',
                safe: true,
                automated: true,
                tool: 'culkibo_auto_remediate',
                args: { action: 'doctor_fix', doctorFixAction: issue.fixAction, dryRun: true },
                dryRunRequired: true,
                rationale: `Aplicar reparación oficial '${issue.fixAction}' sugerida por System Doctor.`
              });
            }
          }
        }
      } catch (e) {
        signals.doctor = { error: e.message };
      }
    }

    // 5. Dominio e Ingress
    const targetHostname = args.hostname
      ? String(args.hostname).trim()
      : (project ? domainManager.listDomains().find((d) => d.projectId === project.id)?.hostname || null : null);
    if (targetHostname) {
      const route = domainManager.resolveRoute(targetHostname);
      if (args.probeDomain === true || Boolean(args.hostname)) {
        try {
          const diag = await ingressManager.diagnoseDomain(targetHostname);
          signals.domain = { hostname: targetHostname, hasRoute: Boolean(route), diagnosis: diag };
          const failedChecks = (diag?.checks || []).filter((c) => c.status === 'fail');
          if (!route || failedChecks.length > 0) {
            rootCauses.push({
              code: 'DOMAIN_INGRESS_FAILURE',
              confidence: 0.86,
              severity: 'high',
              title: `Fallo de enrutado o TLS en '${targetHostname}'`,
              evidence: !route ? 'No hay ruta registrada en domainManager.' : `${failedChecks.length} comprobación(es) fallidas en diagnoseDomain.`,
              affectedComponent: 'ingress'
            });
            addFix({
              action: 'reconcile_ingress',
              safe: true,
              automated: true,
              tool: 'culkibo_auto_remediate',
              args: { action: 'reconcile_ingress', dryRun: true },
              dryRunRequired: true,
              rationale: 'Reconciliar atómicamente rutas y TLS en Caddy.'
            });
          }
        } catch (e) {
          signals.domain = { hostname: targetHostname, hasRoute: Boolean(route), error: e.message };
        }
      } else {
        signals.domain = { hostname: targetHostname, hasRoute: Boolean(route), probed: false };
      }
    }

    const sevRank = { critical: 3, high: 2, warning: 1 };
    rootCauses.sort((a, b) => (sevRank[b.severity] - sevRank[a.severity]) || (b.confidence - a.confidence));

    const severity = rootCauses.some((r) => r.severity === 'critical')
      ? 'critical'
      : rootCauses.some((r) => r.severity === 'high')
        ? 'degraded'
        : rootCauses.length > 0
          ? 'warning'
          : 'healthy';

    const summary = rootCauses.length === 0
      ? `Sin anomalías críticas detectadas${project ? ` en '${project.name}'` : ' en la instancia'}.`
      : `Detectadas ${rootCauses.length} causa(s) probable(s) [${severity}]: principal '${rootCauses[0].code}' — ${rootCauses[0].title}.`;

    return {
      incidentId,
      diagnosedAt,
      scope: project ? project.id : 'instance',
      severity,
      summary,
      signals,
      rootCauses,
      remediationPlan
    };
  }

  /**
   * Ejecución real de `culkibo_auto_remediate` tras validar `confirmToken` HMAC-SHA256 de un solo uso.
   * @param {ReturnType<typeof normalizePrincipal>} principal
   * @param {any} args
   */
  async executeAutoRemediate(principal, args) {
    const action = String(args.action || '');
    if (!AUTO_REMEDIATE_ACTIONS.includes(/** @type {any} */ (action))) {
      throw new McpToolError('INVALID_ARGUMENT', `Acción de remediación no permitida: '${action}'.`, {
        retryable: true,
        remediation: `Usa una acción permitida: ${AUTO_REMEDIATE_ACTIONS.join(', ')}.`
      });
    }

    if (!args.confirmToken) {
      throw new McpToolError(
        'CONFIRMATION_REQUIRED',
        `culkibo_auto_remediate requiere previsualización dryRun: true y un confirmToken HMAC-SHA256 de un solo uso antes de ejecutar '${action}'.`,
        {
          retryable: true,
          remediation: `Llama primero a culkibo_auto_remediate con { action: "${action}"${args.projectId ? `, projectId: "${args.projectId}"` : ''}, dryRun: true } para obtener confirmToken y luego repítelo con dryRun: false.`
        }
      );
    }

    if (!GLOBAL_REMEDIATE_ACTIONS.has(action) && !args.projectId) {
      throw new McpToolError('MISSING_ARGUMENT', `La acción '${action}' requiere projectId.`, {
        retryable: true,
        remediation: 'Pasa projectId obtenido desde culkibo_list_projects o culkibo_diagnose_incident.'
      });
    }

    this.verifyAndConsumeRemediationToken(String(args.confirmToken), principal, args);

    const project = args.projectId ? projectManager.getById(String(args.projectId)) : null;
    if (!GLOBAL_REMEDIATE_ACTIONS.has(action) && !project) {
      throw projectNotFoundError(args.projectId);
    }

    /** @type {any} */
    let actionResult = null;
    if (action === 'rollback_release' && project) {
      actionResult = await deployManager.rollback(project.id);
    } else if (action === 'restart_service' && project) {
      /** @type {any} */
      let stopped = null;
      try { stopped = await deployManager.stopProduction(project.id); } catch (e) { stopped = { stopped: false, error: e.message }; }
      const started = await deployManager.startProduction(project.id);
      actionResult = { restarted: Boolean(started && started.started !== false), stop: stopped, start: started };
    } else if (action === 'wake_service' && project) {
      const sa = requireLazySvc('sleepAdvisor', 'Smart Sleep');
      actionResult = await sa.wakeProject(project.id, { trigger: 'mcp_auto_remediate' });
    } else if (action === 'toggle_maintenance' && project) {
      const enabled = args.maintenanceEnabled !== false;
      projectManager.update(project.id, { maintenanceMode: enabled });
      await projectManager.flushToDisk();
      const ingress = await ingressManager.reconcile();
      actionResult = { success: true, projectId: project.id, maintenanceMode: enabled, ingress };
    } else if (action === 'reconcile_ingress') {
      actionResult = await ingressManager.reconcile();
    } else if (action === 'doctor_fix') {
      const rawFix = String(args.doctorFixAction || '');
      const fixAct = rawFix === 'prune_build_cache' ? 'prune_buildkit' : rawFix;
      if (!DOCTOR_FIX_CANONICAL_ACTIONS.includes(/** @type {any} */ (fixAct))) {
        throw new McpToolError('MISSING_ARGUMENT', 'Falta doctorFixAction válido para action="doctor_fix".', {
          retryable: true,
          remediation: `Pasa doctorFixAction con uno de: ${DOCTOR_FIX_CANONICAL_ACTIONS.join(', ')}.`
        });
      }
      actionResult = await systemDoctor.applyFix(fixAct);
    }

    // Verificación post-remediación opcional
    /** @type {any} */
    let postVerification = null;
    if (args.verifyAfter !== false && project) {
      try {
        const checks = Array.isArray(project.smokeTests)
          ? project.smokeTests
          : (Array.isArray(project.smokeTests?.checks) ? project.smokeTests.checks : []);
        if (checks.length > 0 && typeof deployManager.runSmokeTestsForProject === 'function') {
          postVerification = { kind: 'smoke_tests', ...(await deployManager.runSmokeTestsForProject(project.id)) };
        } else {
          const st = await deployManager.status(project.id);
          postVerification = { kind: 'deploy_status', maintenanceMode: Boolean(projectManager.getById(project.id)?.maintenanceMode), current: st?.current || null };
        }
      } catch (e) {
        postVerification = { kind: 'verification_error', error: e.message };
      }
    }

    return {
      executed: true,
      dryRun: false,
      action,
      projectId: project ? project.id : null,
      result: actionResult,
      postVerification
    };
  }

  /**
   * Ejecuta escaneo pre-despliegue de fugas de secretos sobre la configuración de un proyecto
   * sin exponer jamás valores en claro (solo previews enmascarados de `secretScanner`).
   * @param {any} project
   * @param {'block' | 'warn'} [mode]
   */
  _scanProjectSecrets(project, mode = 'block') {
    const scanner = lazySvc('secretScanner');
    const cleanMode = mode === 'warn' ? 'warn' : 'block';
    if (!scanner || typeof scanner.scanDeploymentPayload !== 'function') {
      return {
        clean: true,
        blocked: false,
        mode: cleanMode,
        scannerAvailable: false,
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
        findings: []
      };
    }
    const payload = {
      envVars: project && typeof project.envVars === 'object' ? project.envVars : undefined,
      buildArgs: project && typeof project.buildArgs === 'object' ? project.buildArgs : undefined,
      composeYaml: typeof project?.composeYaml === 'string' ? project.composeYaml : undefined,
      culkiboYaml: typeof project?.culkiboYaml === 'string' ? project.culkiboYaml : undefined,
      dockerfile: typeof project?.dockerfile === 'string' ? project.dockerfile : undefined
    };
    const report = scanner.scanDeploymentPayload(payload, { mode: cleanMode, includeEntropy: true });
    return {
      scannerAvailable: true,
      ...report
    };
  }

  /**
   * Ejecuta el flujo autónomo `culkibo_ship_and_verify` (Fase 2: requiere `confirmToken` de `dryRun: true`).
   * Correlaciona escaneo pre-despliegue de secretos + despliegue + smoke/health verification + auto-rollback.
   * @param {ReturnType<typeof normalizePrincipal>} principal
   * @param {any} args
   * @param {{ onProgress?: (msg: string) => void }} [context]
   */
  async executeShipAndVerify(principal, args, context = {}) {
    const project = projectManager.getById(String(args.projectId || ''));
    if (!project) throw projectNotFoundError(args.projectId);

    const tokenArgs = { ...args, action: 'ship_and_verify' };
    if (!args.confirmToken) {
      throw new McpToolError(
        'CONFIRMATION_REQUIRED',
        `culkibo_ship_and_verify exige previsualización dryRun: true (con secret scan y rollback readiness) y un confirmToken HMAC-SHA256 de un solo uso antes de desplegar '${project.name}'.`,
        {
          retryable: true,
          remediation: `Ejecuta primero culkibo_ship_and_verify con { projectId: "${project.id}", dryRun: true } para revisar el plan y obtener confirmToken, luego confirma con dryRun: false y confirmToken.`
        }
      );
    }

    this.verifyAndConsumeRemediationToken(String(args.confirmToken), principal, tokenArgs);

    const freeze = evaluateProjectFreeze(project);
    if (freeze.frozen && !args.overrideFreeze) {
      throw new McpToolError('DEPLOY_FREEZE_ACTIVE', `Despliegue de '${project.name}' bloqueado por una ventana de deploy freeze activa.`, {
        retryable: false,
        remediation: 'Espera a que finalice la ventana con culkibo_deploy_freeze (action: "list") o repite el flujo con overrideFreeze: true (admin/owner).',
        details: { projectId: project.id, freeze }
      });
    }

    const secretScanMode = args.secretScanMode === 'warn' ? 'warn' : 'block';
    const secretScan = this._scanProjectSecrets(project, secretScanMode);
    if (secretScan.blocked) {
      throw new McpToolError(
        'SECRET_LEAK_DETECTED',
        `Ship & Verify bloqueado: se detectaron ${secretScan.summary.critical + secretScan.summary.high} secreto(s) en claro en '${project.name}'.`,
        {
          retryable: false,
          remediation: 'Sustituye los literales detectados por referencias ${vault.KEY} usando culkibo_set_project_env o el Vault cifrado y vuelve a ejecutar dryRun: true.',
          details: { projectId: project.id, summary: secretScan.summary, findings: secretScan.findings.slice(0, 10) }
        }
      );
    }

    const onProg = typeof context.onProgress === 'function' ? context.onProgress : null;
    if (onProg) onProg(`Ship & Verify [${project.name}]: pre-flight secret scan OK (${secretScan.summary.total} hallazgos). Iniciando despliegue…`);

    const preStatus = await deployManager.status(project.id).catch(() => null);
    const linkedDbs = Array.isArray(project.linkedDatabaseIds) ? project.linkedDatabaseIds : [];
    const rollbackReadiness = {
      canRollback: Boolean(preStatus?.current || preStatus?.previous),
      currentReleaseId: preStatus?.current?.id || null,
      previousReleaseId: preStatus?.previous?.id || null,
      linkedDatabasesCount: linkedDbs.length
    };

    const stageListener = onProg
      ? (ev) => {
          if (ev && ev.projectId === project.id && ev.stage) {
            onProg(`Ship & Verify [${project.name}]: fase «${ev.stage}»`);
          }
        }
      : null;
    if (stageListener) deployManager.on('stage', stageListener);

    /** @type {any} */
    let deployment = null;
    try {
      const targetProject = args.serverId ? { ...project, serverId: String(args.serverId) } : project;
      deployment = await deployManager.deploy(targetProject, {
        commit: args.commit || null,
        gitSync: args.gitSync !== false,
        overrideFreeze: Boolean(args.overrideFreeze),
        serverId: args.serverId ? String(args.serverId) : undefined,
        trigger: 'mcp_ship_and_verify'
      });
    } finally {
      if (stageListener) deployManager.off('stage', stageListener);
    }

    const deploySucceeded = Boolean(
      deployment &&
      deployment.status !== 'error' &&
      deployment.status !== 'failed' &&
      deployment.status !== 'fallido' &&
      deployment.status !== 'cancelado'
    );

    const warnings = [];
    if (secretScan.summary.total > 0) {
      warnings.push(`Escáner de secretos detectó ${secretScan.summary.total} aviso(s) en modo '${secretScanMode}'.`);
    }

    /** @type {any} */
    let smokeVerification = null;
    let verified = deploySucceeded;
    let rollbackExecuted = false;
    /** @type {any} */
    let rollbackResult = null;

    if (deploySucceeded && args.runSmokeTests !== false) {
      if (onProg) onProg(`Ship & Verify [${project.name}]: ejecutando smoke checks y verificación de salud…`);
      const configuredChecks = Array.isArray(project.smokeTests)
        ? project.smokeTests
        : (Array.isArray(project.smokeTests?.checks) ? project.smokeTests.checks : []);
      const checks = Array.isArray(args.smokeChecks) && args.smokeChecks.length > 0
        ? sanitizeSmokeChecks(args.smokeChecks)
        : (configuredChecks.length > 0
          ? configuredChecks
          : [{ name: 'default-health', method: 'GET', path: project.healthPath || '/', expectedStatus: 200 }]);

      if (typeof deployManager.runSmokeTests === 'function') {
        try {
          const postStatus = await deployManager.status(project.id).catch(() => null);
          const port = deployment?.hostPort || postStatus?.current?.hostPort || project.citadelPort || 3000;
          const upstream = `http://127.0.0.1:${port}`;
          const smokeRes = await deployManager.runSmokeTests(upstream, checks, { target: 'citadel' });
          const passed = smokeRes?.passed !== false && smokeRes?.ok !== false;
          smokeVerification = { upstream, checksCount: checks.length, passed, ...smokeRes };
          if (!passed) {
            verified = false;
            warnings.push('Los smoke checks post-despliegue fallaron.');
            if (args.autoRollbackOnFailure !== false && rollbackReadiness.canRollback) {
              if (onProg) onProg(`Ship & Verify [${project.name}]: smoke checks fallaron — ejecutando auto-rollback…`);
              try {
                rollbackResult = await deployManager.rollback(project.id);
                rollbackExecuted = true;
              } catch (rbErr) {
                rollbackResult = { ok: false, error: rbErr.message };
                warnings.push(`Auto-rollback falló: ${rbErr.message}`);
              }
            }
          }
        } catch (smokeErr) {
          smokeVerification = { passed: false, error: smokeErr.message };
          verified = false;
          warnings.push(`Error ejecutando smoke checks: ${smokeErr.message}`);
          if (args.autoRollbackOnFailure !== false && rollbackReadiness.canRollback) {
            try {
              rollbackResult = await deployManager.rollback(project.id);
              rollbackExecuted = true;
            } catch (rbErr) {
              rollbackResult = { ok: false, error: rbErr.message };
              warnings.push(`Auto-rollback falló: ${rbErr.message}`);
            }
          }
        }
      } else {
        smokeVerification = { skipped: true, reason: 'runSmokeTests no disponible en deployManager' };
      }
    }

    /** @type {any} */
    let metricsSnapshot = null;
    try {
      const [runtimeStats, obs] = await Promise.all([
        typeof deployManager.getRuntimeStats === 'function'
          ? deployManager.getRuntimeStats(project.id).catch(() => null)
          : Promise.resolve(null),
        Promise.resolve().then(() => metricsCollector.getSnapshot(false)).catch(() => null)
      ]);
      metricsSnapshot = {
        runtime: runtimeStats,
        hostMemory: obs?.memory || null,
        capturedAt: new Date().toISOString()
      };
    } catch (e) {
      metricsSnapshot = null;
    }

    const phase = !deploySucceeded
      ? 'failed'
      : verified
        ? 'shipped_verified'
        : rollbackExecuted
          ? 'shipped_rolled_back'
          : 'failed';

    return {
      phase,
      executed: true,
      dryRun: false,
      verified,
      wouldExecute: true,
      projectId: project.id,
      secretScan,
      rollbackReadiness,
      deployment,
      smokeVerification,
      metricsSnapshot,
      rollbackExecuted,
      rollbackResult,
      blockers: [],
      warnings,
      nextStep: verified
        ? `Release verificada en producción para '${project.name}'. Supervisa logs con culkibo_get_container_logs o monitores con culkibo_uptime_list_monitors.`
        : rollbackExecuted
          ? `Se ejecutó auto-rollback tras fallo de smoke checks. Diagnostica la causa con culkibo_diagnose_incident({ projectId: "${project.id}" }).`
          : `Despliegue no verificado. Inspecciona logs con culkibo_get_deployment_logs({ projectId: "${project.id}" }) o culkibo_diagnose_incident.`
    };
  }

  /**
   * Genera el kit de conexión 1-clic multi-agente (Antigravity, Claude Code, Cursor, Windsurf,
   * OpenAI Codex CLI, VS Code Copilot) por defecto con `?profile=core` y placeholders `${CULKIBO_TOKEN}`
   * (JAMÁS incrusta tokens maestros en claro).
   * @param {{
   *   target?: string,
   *   profile?: string,
   *   serverUrl?: string,
   *   projectId?: string | null,
   *   projectName?: string | null,
   *   includeOpsGuide?: boolean
   * }} [opts]
   */
  buildAgentKit(opts = {}) {
    const validTargets = ['all', 'antigravity', 'claude-code', 'cursor', 'windsurf', 'codex', 'vscode'];
    const rawTarget = String(opts.target || 'all').trim().toLowerCase();
    const targetAliases = {
      claude: 'claude-code',
      'claude_code': 'claude-code',
      'codex-cli': 'codex',
      'openai-codex': 'codex',
      copilot: 'vscode',
      'vscode-copilot': 'vscode'
    };
    const normalizedTarget = targetAliases[rawTarget] || rawTarget;
    if (!validTargets.includes(normalizedTarget)) {
      throw new McpToolError('INVALID_ARGUMENT', `Agente objetivo no soportado: '${opts.target}'.`, {
        retryable: true,
        remediation: `Usa uno de los objetivos soportados: ${validTargets.join(', ')}.`
      });
    }

    const profile = this.normalizeProfile(opts.profile !== undefined ? opts.profile : 'core');
    const defaultUrl = ingressManager.panelDomain
      ? `https://${ingressManager.panelDomain}`
      : `http://127.0.0.1:${process.env.PORT || 3030}`;
    const serverUrl = String(opts.serverUrl || defaultUrl).trim().replace(/\/+$/, '').replace(/\/api\/mcp(?:\?.*)?$/i, '');
    const endpoint = profile !== 'all' ? `${serverUrl}/api/mcp?profile=${profile}` : `${serverUrl}/api/mcp`;
    const tokenPlaceholder = '${CULKIBO_TOKEN}';
    const includeOpsGuide = opts.includeOpsGuide !== false;

    // Medición exacta en tiempo real del ahorro de contexto respecto al catálogo completo
    const allTools = this.getToolsDefinition();
    const profileTools = this.getToolsForPrincipal(null, { profile });
    const allBytes = Buffer.byteLength(JSON.stringify(allTools), 'utf8');
    const profileBytes = Buffer.byteLength(JSON.stringify(profileTools), 'utf8');
    const savedPct = allBytes > 0 ? Number(((1 - profileBytes / allBytes) * 100).toFixed(1)) : 0;
    const tokenSavings = {
      profile,
      profileToolsCount: profileTools.length,
      allToolsCount: allTools.length,
      profileBytes,
      allBytes,
      estimatedTokens: Math.round(profileBytes / 4),
      fullEstimatedTokens: Math.round(allBytes / 4),
      savedPct
    };

    const projectHint = opts.projectId
      ? `\n- Proyecto por defecto: \`${String(opts.projectId)}\`${opts.projectName ? ` (${String(opts.projectName)})` : ''}`
      : '';

    const claudeMdSnippet = [
      '<!-- culkibo-mcp-ops:start -->',
      '## Culkibo AI-Native PaaS Operations (MCP 2026)',
      '',
      `- Endpoint MCP: \`${endpoint}\` (perfil \`${profile}\`: **${profileTools.length}/${allTools.length}** herramientas, **-${savedPct}%** tokens de contexto).`,
      '- Autenticación segura: exporta `CULKIBO_TOKEN` en tu entorno local; **nunca** pegues tokens maestros en repositorios Git.' + projectHint,
      '',
      '### Reglas de operación autónoma',
      '1. **Meta-Discovery bajo demanda**: con `?profile=core` arrancas con las herramientas esenciales. Si necesitas bases de datos, flota SSH, GitOps, Canary o DNS-01, llama a `culkibo_search_tools({ query: "..." })` para cargar solo esos esquemas.',
      '2. **Protocolo de seguridad 2 fases (`dryRun` → `confirmToken`)**:',
      '   - Para desplegar con red de seguridad completa usa `culkibo_ship_and_verify({ projectId, dryRun: true })` (escaneo de secretos + freeze + rollback readiness) → revisa el plan → confirma con `dryRun: false` y el `confirmToken` de un solo uso.',
      '   - Para incidentes ejecuta `culkibo_diagnose_incident` y aplica fixes mediante `culkibo_auto_remediate` (`dryRun: true` → `confirmToken` → `dryRun: false`).',
      '3. **Higiene de secretos**: referencia secretos en `culkibo.yaml` y `.env` siempre como `${vault.KEY}` y verifica con el escáner pre-despliegue.',
      '4. **Playbooks nativos (`prompts/list`)**: `deploy_safely`, `migrate_from_coolify`, `debug_production_crash`, `zero_downtime_db_upgrade`, `security_audit_stack`, `setup_wildcard_tls_and_tunnel`, `optimize_ram_and_costs`, `disaster_recovery_drill`.',
      '<!-- culkibo-mcp-ops:end -->',
      ''
    ].join('\n');

    const antigravityConfig = {
      mcpServers: {
        culkibo: {
          serverUrl: endpoint,
          headers: {
            Authorization: `Bearer ${tokenPlaceholder}`
          }
        }
      }
    };

    const claudeCodeMcpJson = {
      mcpServers: {
        culkibo: {
          type: 'http',
          url: endpoint,
          headers: {
            Authorization: `Bearer ${tokenPlaceholder}`
          }
        }
      }
    };

    const cursorMcpJson = {
      mcpServers: {
        culkibo: {
          url: endpoint,
          headers: {
            Authorization: `Bearer ${tokenPlaceholder}`
          }
        }
      }
    };

    const windsurfMcpJson = {
      mcpServers: {
        culkibo: {
          serverUrl: endpoint,
          headers: {
            Authorization: `Bearer ${tokenPlaceholder}`
          }
        }
      }
    };

    const codexToml = [
      '# Culkibo MCP 2026 — OpenAI Codex CLI',
      `# Profile: ${profile} (${profileTools.length}/${allTools.length} tools, -${savedPct}% context tokens)`,
      '# Set CULKIBO_TOKEN in your shell environment; never commit plaintext tokens.',
      '[mcp_servers.culkibo]',
      `url = "${endpoint}"`,
      'bearer_token_env_var = "CULKIBO_TOKEN"',
      '',
      '# Optional stdio bridge (works with CULKIBO_API_URL + CULKIBO_MCP_PROFILE):',
      '# [mcp_servers.culkibo]',
      '# command = "culkibo"',
      '# args = ["mcp"]',
      `# env = { CULKIBO_API_URL = "${serverUrl}", CULKIBO_MCP_PROFILE = "${profile}", CULKIBO_TOKEN = "${tokenPlaceholder}" }`,
      ''
    ].join('\n');

    const vscodeMcpJson = {
      servers: {
        culkibo: {
          type: 'http',
          url: endpoint,
          headers: {
            Authorization: `Bearer ${tokenPlaceholder}`
          }
        }
      }
    };

    /** @type {Record<string, any>} */
    const allKits = {
      antigravity: {
        id: 'antigravity',
        name: 'Antigravity',
        transport: `Streamable HTTP (${PROTOCOL_VERSION})`,
        primaryFile: '.antigravity/mcp.json',
        globalPath: '~/.gemini/antigravity/mcp_config.json',
        cliCommand: `culkibo agent-init antigravity --profile ${profile} --url "${serverUrl}"`,
        config: antigravityConfig,
        files: [
          {
            path: '.antigravity/mcp.json',
            format: 'json',
            mergeKey: 'mcpServers',
            content: JSON.stringify(antigravityConfig, null, 2) + '\n'
          }
        ],
        notes: 'Exporta CULKIBO_TOKEN en tu entorno antes de abrir Antigravity; el endpoint usa Streamable HTTP nativo sin handshake.'
      },
      'claude-code': {
        id: 'claude-code',
        name: 'Claude Code',
        transport: `Streamable HTTP (${PROTOCOL_VERSION})`,
        primaryFile: '.mcp.json',
        globalPath: '~/.claude.json',
        cliCommand: `claude mcp add --transport http culkibo "${endpoint}" --header "Authorization: Bearer \${CULKIBO_TOKEN}"`,
        config: claudeCodeMcpJson,
        claudeMdSnippet,
        files: [
          {
            path: '.mcp.json',
            format: 'json',
            mergeKey: 'mcpServers',
            content: JSON.stringify(claudeCodeMcpJson, null, 2) + '\n'
          },
          ...(includeOpsGuide ? [{
            path: 'CLAUDE.md',
            format: 'markdown',
            markerStart: '<!-- culkibo-mcp-ops:start -->',
            markerEnd: '<!-- culkibo-mcp-ops:end -->',
            content: claudeMdSnippet
          }] : [])
        ],
        notes: 'Genera .mcp.json listo para equipo + guía operativa CLAUDE.md con los 8 playbooks y protocolo dryRun/confirmToken.'
      },
      cursor: {
        id: 'cursor',
        name: 'Cursor',
        transport: `Streamable HTTP (${PROTOCOL_VERSION})`,
        primaryFile: '.cursor/mcp.json',
        globalPath: '~/.cursor/mcp.json',
        cliCommand: `culkibo agent-init cursor --profile ${profile} --url "${serverUrl}"`,
        config: cursorMcpJson,
        files: [
          {
            path: '.cursor/mcp.json',
            format: 'json',
            mergeKey: 'mcpServers',
            content: JSON.stringify(cursorMcpJson, null, 2) + '\n'
          }
        ],
        notes: 'Coloca .cursor/mcp.json en la raíz del proyecto y define CULKIBO_TOKEN en tu shell.'
      },
      windsurf: {
        id: 'windsurf',
        name: 'Windsurf',
        transport: `Streamable HTTP (${PROTOCOL_VERSION})`,
        primaryFile: '.windsurf/mcp_config.json',
        globalPath: '~/.codeium/windsurf/mcp_config.json',
        cliCommand: `culkibo agent-init windsurf --profile ${profile} --url "${serverUrl}"`,
        config: windsurfMcpJson,
        files: [
          {
            path: '.windsurf/mcp_config.json',
            format: 'json',
            mergeKey: 'mcpServers',
            content: JSON.stringify(windsurfMcpJson, null, 2) + '\n'
          }
        ],
        notes: 'Compatible con Windsurf Cascade usando serverUrl y cabecera Authorization con ${CULKIBO_TOKEN}.'
      },
      codex: {
        id: 'codex',
        name: 'OpenAI Codex CLI',
        transport: `Streamable HTTP (${PROTOCOL_VERSION}) + TOML`,
        primaryFile: '.codex/config.toml',
        globalPath: '~/.codex/config.toml',
        cliCommand: `codex mcp add culkibo --url "${endpoint}" --bearer-token-env-var CULKIBO_TOKEN`,
        config: codexToml,
        files: [
          {
            path: '.codex/config.toml',
            format: 'toml',
            sectionHeader: '[mcp_servers.culkibo]',
            content: codexToml
          }
        ],
        notes: 'Usa bearer_token_env_var = "CULKIBO_TOKEN" para leer el token desde la variable de entorno sin guardarlo en disco.'
      },
      vscode: {
        id: 'vscode',
        name: 'VS Code Copilot',
        transport: `Streamable HTTP (${PROTOCOL_VERSION})`,
        primaryFile: '.vscode/mcp.json',
        globalPath: '.vscode/mcp.json',
        cliCommand: `culkibo agent-init vscode --profile ${profile} --url "${serverUrl}"`,
        config: vscodeMcpJson,
        files: [
          {
            path: '.vscode/mcp.json',
            format: 'json',
            mergeKey: 'servers',
            content: JSON.stringify(vscodeMcpJson, null, 2) + '\n'
          }
        ],
        notes: 'Compatible con GitHub Copilot Agent Mode en VS Code (sustituye ${CULKIBO_TOKEN} por ${env:CULKIBO_TOKEN} si tu versión de VS Code exige prefijo env:).'
      }
    };

    const kits = normalizedTarget === 'all'
      ? allKits
      : { [normalizedTarget]: allKits[normalizedTarget] };

    const playbooks = this.listPrompts().slice(0, 8).map((p) => ({
      name: p.name,
      title: p.title || p.name,
      description: p.description,
      arguments: p.arguments || []
    }));

    return {
      protocolVersion: PROTOCOL_VERSION,
      profile,
      target: normalizedTarget,
      serverUrl,
      endpoint,
      tokenPlaceholder,
      containsPlaintextSecrets: false,
      tokenSavings,
      kits,
      playbooks
    };
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
          throw new McpToolError('FORBIDDEN', 'Solo un owner puede otorgar o gestionar el rol owner.', {
            retryable: false,
            remediation: 'Usa un rol <= admin o pide a un owner que realice esta operación.'
          });
        }
        if (toolName === 'culkibo_rbac_manage_token' && targetRank > callerRank) {
          throw new McpToolError('FORBIDDEN', 'No puedes emitir un token con un rol superior al tuyo.', {
            retryable: false,
            remediation: `Emite el token con rol '${principal.role}' o inferior.`
          });
        }
        if (toolName !== 'culkibo_rbac_manage_token' && principal.role !== 'owner' && targetRank >= callerRank) {
          throw new McpToolError('FORBIDDEN', 'Un admin solo puede gestionar o invitar roles developer y viewer.', {
            retryable: false,
            remediation: 'Indica role "developer" o "viewer", o solicita la operación a un owner.'
          });
        }
      }
    }

    if (toolName === 'culkibo_export_instance_snapshot' && args.includeSecrets === true && principal.role !== 'owner') {
      throw new McpToolError('FORBIDDEN', 'Exportar snapshots de instancia con secretos sin redactar requiere rol owner.', {
        retryable: false,
        remediation: 'Usa includeSecrets: false para exportar un snapshot redactado o autentícate como owner.'
      });
    }

    if (toolName === 'culkibo_auto_remediate' && GLOBAL_REMEDIATE_ACTIONS.has(String(args.action || ''))) {
      if (callerRank < ROLE_RANK.admin || Array.isArray(principal.projectIds)) {
        throw new McpToolError('FORBIDDEN', `La remediación global '${args.action}' requiere rol admin/owner sin restricción de proyectos.`, {
          retryable: false,
          remediation: 'Usa una acción por proyecto (rollback_release, restart_service, wake_service, toggle_maintenance) o autentícate como admin/owner.'
        });
      }
    }

    // Aislamiento de equipo en argumentos explícitos (teamId y serverId) antes de dryRun
    if (principal.teamId && args.teamId && String(args.teamId) !== principal.teamId) {
      throw new McpToolError('FORBIDDEN', 'No tienes acceso al equipo especificado.', {
        retryable: false,
        remediation: 'Omite teamId o usa el teamId que devuelve culkibo_rbac_whoami.'
      });
    }
    if (principal.teamId && args.serverId && String(args.serverId) !== 'local') {
      const fleet = lazySvc('serverFleetManager');
      if (fleet && typeof fleet.getServer === 'function') {
        const srv = fleet.getServer(String(args.serverId));
        if (!srv || (srv.teamId && srv.teamId !== principal.teamId)) {
          throw new McpToolError('FORBIDDEN', 'No tienes acceso al servidor especificado.', {
            retryable: false,
            remediation: 'Consulta los servidores accesibles con culkibo_fleet_list_servers.'
          });
        }
      }
    }

    // Verificación ACL directa e indirecta (sin revelar existencia de IDs ajenos: anti-IDOR)
    const refs = this.resolveTargetRefs(toolName, args);

    // Un token acotado a `projectIds` concretos NUNCA puede escapar a mutaciones globales sin proyecto objetivo.
    if (Array.isArray(principal.projectIds) && tool && !tool.annotations?.readOnlyHint && refs.length === 0) {
      throw new McpToolError('FORBIDDEN', 'Un token acotado a proyectos concretos no puede ejecutar mutaciones globales.', {
        retryable: false,
        remediation: 'Incluye un projectId autorizado por tu token o utiliza un token sin restricción de projectIds.'
      });
    }

    const minRank = ROLE_RANK[policy.minRole] || ROLE_RANK.owner;
    const hasRestrictedScope = Array.isArray(principal.projectIds) || Boolean(principal.teamId);
    let minEffectiveProjectRank = callerRank;
    for (const ref of refs) {
      if (ref.missing && hasRestrictedScope) {
        throw new McpToolError('FORBIDDEN', 'No tienes acceso al recurso especificado.', {
          retryable: false,
          remediation: 'Verifica los recursos autorizados con culkibo_list_projects o culkibo_rbac_whoami.'
        });
      }
      const effRole = resolveEffectiveProjectRole(principal, ref.projectId);
      if (!effRole) {
        throw new McpToolError('FORBIDDEN', 'No tienes acceso al proyecto especificado.', {
          retryable: false,
          remediation: 'Usa culkibo_list_projects para listar únicamente los proyectos accesibles por tu credencial.'
        });
      }
      const effRank = ROLE_RANK[effRole] || 0;
      if (effRank < minRank) {
        throw new McpToolError('FORBIDDEN', `Tu rol efectivo ('${effRole}') sobre el proyecto no autoriza '${toolName}'.`, {
          retryable: false,
          remediation: `Esta operación exige rol '${policy.minRole}' sobre el proyecto; consulta tus permisos con culkibo_rbac_whoami.`
        });
      }
      if (effRank < minEffectiveProjectRank) minEffectiveProjectRank = effRank;
    }

    if ((toolName === 'culkibo_deploy_production' || toolName === 'culkibo_env_promote' || toolName === 'culkibo_ship_and_verify') && args.overrideFreeze === true && minEffectiveProjectRank < ROLE_RANK.admin) {
      throw new McpToolError('FORBIDDEN', 'Solo admin u owner pueden omitir una ventana de deploy freeze.', {
        retryable: false,
        remediation: 'Espera a que termine la ventana con culkibo_deploy_freeze (action: "list") o pide override a un admin/owner.'
      });
    }

    if (toolName === 'culkibo_ship_and_verify' && args.secretScanMode === 'warn' && minEffectiveProjectRank < ROLE_RANK.admin) {
      throw new McpToolError('FORBIDDEN', 'Solo admin u owner pueden degradar secretScanMode a "warn" en culkibo_ship_and_verify.', {
        retryable: false,
        remediation: 'Usa secretScanMode: "block" (por defecto) y mueve los secretos detectados al Vault cifrado (${vault.KEY}).'
      });
    }

    if (toolName === 'culkibo_env_promote' && String(args.toEnv || '').toLowerCase() === 'production' && minEffectiveProjectRank < ROLE_RANK.admin) {
      const em = lazySvc('environmentManager');
      const envs = em && typeof em.listEnvironments === 'function' ? em.listEnvironments(args.projectId) : null;
      const prodEnv = Array.isArray(envs) ? envs.find((e) => e.name === 'production') : null;
      if (!prodEnv || prodEnv.protected !== false) {
        throw new McpToolError('FORBIDDEN', 'Promocionar a producción protegida requiere rol admin u owner.', {
          retryable: false,
          remediation: 'Solicita la promoción a un admin/owner o promociona primero a staging.'
        });
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

      case 'culkibo_auto_remediate': {
        const action = String(args.action || '');
        const isGlobal = GLOBAL_REMEDIATE_ACTIONS.has(action);
        Object.assign(target, { action, projectId: project ? project.id : (args.projectId || null), doctorFixAction: args.doctorFixAction || null });
        if (!isGlobal && !project) {
          blockers.push('PROJECT_REQUIRED');
          warnings.push(`La acción '${action}' requiere un projectId válido.`);
        }
        if (action === 'rollback_release' && project) {
          const st = await deployManager.status(project.id);
          effects.push(`Revertirá la release activa de '${project.name}' a la versión previa en Caddy.`);
          if (!st?.previous) {
            blockers.push('NO_PREVIOUS_RELEASE');
            warnings.push('No existe una release previa registrada para revertir.');
          }
          preview.currentStatus = st;
          riskLevel = 'high';
          reversible = true;
        } else if (action === 'restart_service' && project) {
          effects.push(`Detendrá y arrancará el contenedor de producción de '${project.name}' (stopProduction + startProduction).`);
          riskLevel = 'medium';
          reversible = true;
        } else if (action === 'wake_service' && project) {
          effects.push(`Despertará el servicio '${project.name}' desde Smart Sleep.`);
          riskLevel = 'low';
          reversible = true;
        } else if (action === 'toggle_maintenance' && project) {
          const en = args.maintenanceEnabled !== false;
          const domains = domainManager.listDomains().filter((d) => d.projectId === project.id).map((d) => d.hostname);
          effects.push(en
            ? `Activará modo mantenimiento HTTP 503 en ${domains.length} dominio(s) de '${project.name}'.`
            : `Restaurará tráfico normal en ${domains.length} dominio(s) de '${project.name}'.`);
          preview.domains = domains;
          riskLevel = en ? 'high' : 'low';
          reversible = true;
        } else if (action === 'reconcile_ingress') {
          effects.push('Reconciliará atómicamente todas las rutas y políticas TLS en Caddy.');
          riskLevel = 'medium';
          reversible = true;
        } else if (action === 'doctor_fix') {
          const rawFix = String(args.doctorFixAction || '');
          const fixAct = rawFix === 'prune_build_cache' ? 'prune_buildkit' : rawFix;
          if (!DOCTOR_FIX_CANONICAL_ACTIONS.includes(/** @type {any} */ (fixAct))) {
            blockers.push('MISSING_DOCTOR_ACTION');
            warnings.push(`Indica doctorFixAction: ${DOCTOR_FIX_CANONICAL_ACTIONS.join(', ')}.`);
          } else {
            effects.push(`Ejecutará la reparación de System Doctor '${fixAct}'.`);
          }
          riskLevel = fixAct === 'prune_buildkit' || fixAct === 'clean_orphans' ? 'medium' : 'low';
          reversible = fixAct === 'reconcile_caddy' || fixAct === 'start_caddy';
        }
        if (blockers.length === 0) {
          const minted = this.mintRemediationToken(principal, args);
          return {
            dryRun: true,
            executed: false,
            tool: toolName,
            action,
            projectId: project ? project.id : null,
            wouldExecute: true,
            riskLevel,
            reversible,
            target,
            effects,
            blockers,
            warnings,
            preview,
            confirmToken: minted.confirmToken,
            confirmTokenExpiresAt: minted.confirmTokenExpiresAt,
            postVerification: null,
            nextStep: `Confirma el plan y llama a culkibo_auto_remediate con los mismos parámetros, dryRun: false y confirmToken: "${minted.confirmToken}" antes de ${minted.confirmTokenExpiresAt}.`
          };
        }
        return {
          dryRun: true,
          executed: false,
          tool: toolName,
          action,
          projectId: project ? project.id : null,
          wouldExecute: false,
          riskLevel,
          reversible,
          target,
          effects,
          blockers,
          warnings,
          preview,
          postVerification: null,
          nextStep: `Resuelve los bloqueos (${blockers.join(', ')}) antes de ejecutar culkibo_auto_remediate.`
        };
      }

      case 'culkibo_ship_and_verify': {
        if (!project) throw projectNotFoundError(args.projectId);
        const freeze = evaluateProjectFreeze(project);
        const targetServer = args.serverId || project.serverId || 'local';
        const secretScanMode = args.secretScanMode === 'warn' ? 'warn' : 'block';
        const secretScan = this._scanProjectSecrets(project, secretScanMode);
        const depStatus = await deployManager.status(project.id).catch(() => null);
        const domains = domainManager.listDomains().filter((d) => d.projectId === project.id).map((d) => d.hostname);
        const linkedDbs = Array.isArray(project.linkedDatabaseIds) ? project.linkedDatabaseIds : [];
        const configuredChecks = Array.isArray(project.smokeTests)
          ? project.smokeTests
          : (Array.isArray(project.smokeTests?.checks) ? project.smokeTests.checks : []);
        const plannedSmokeChecks = Array.isArray(args.smokeChecks) && args.smokeChecks.length > 0
          ? sanitizeSmokeChecks(args.smokeChecks)
          : (configuredChecks.length > 0
            ? configuredChecks
            : [{ name: 'default-health', method: 'GET', path: project.healthPath || '/', expectedStatus: 200 }]);

        const rollbackReadiness = {
          canRollback: Boolean(depStatus?.current || depStatus?.previous),
          currentReleaseId: depStatus?.current?.id || null,
          previousReleaseId: depStatus?.previous?.id || null,
          linkedDatabasesCount: linkedDbs.length,
          autoRollbackOnFailure: args.autoRollbackOnFailure !== false
        };

        Object.assign(target, {
          projectId: project.id,
          projectName: project.name,
          serverId: targetServer,
          commit: args.commit || null,
          secretScanMode
        });
        effects.push(`Ejecutará pre-flight secret scan (${secretScanMode}), desplegará '${project.name}' en '${targetServer}', correrá ${plannedSmokeChecks.length} smoke check(s) y capturará métricas post-despliegue.`);
        if (rollbackReadiness.canRollback && args.autoRollbackOnFailure !== false) {
          effects.push(`Rollback automático listo hacia release '${rollbackReadiness.currentReleaseId || rollbackReadiness.previousReleaseId}' si los smoke checks fallan.`);
        }
        if (secretScan.blocked) {
          blockers.push('SECRET_LEAK_DETECTED');
          warnings.push(`Secret scanner detectó ${secretScan.summary.critical} hallazgo(s) críticos y ${secretScan.summary.high} altos. Mueve los secretos a \${vault.KEY}.`);
        } else if (secretScan.summary.total > 0) {
          warnings.push(`Secret scanner reportó ${secretScan.summary.total} aviso(s) no bloqueantes.`);
        }
        if (freeze.frozen && !args.overrideFreeze) {
          blockers.push('DEPLOY_FREEZE_ACTIVE');
          warnings.push(`Ventana de deploy freeze activa${freeze.activeWindow?.reason ? `: ${freeze.activeWindow.reason}` : ''}.`);
        }
        if (!rollbackReadiness.canRollback) {
          warnings.push('No existe release previa activa: es el primer despliegue (no habrá rollback automático disponible hasta completar el primero).');
        }
        if (project.maintenanceMode) {
          warnings.push('El proyecto está en modo mantenimiento (HTTP 503).');
        }

        preview.freeze = freeze;
        preview.domains = domains;
        preview.plannedSmokeChecks = plannedSmokeChecks;
        riskLevel = 'high';
        reversible = rollbackReadiness.canRollback;

        if (blockers.length === 0) {
          const minted = this.mintRemediationToken(principal, { ...args, action: 'ship_and_verify' });
          return {
            phase: 'dry_run_plan',
            dryRun: true,
            executed: false,
            verified: false,
            tool: toolName,
            projectId: project.id,
            wouldExecute: true,
            riskLevel,
            reversible,
            target,
            effects,
            blockers,
            warnings,
            preview,
            secretScan,
            rollbackReadiness,
            deployment: null,
            smokeVerification: null,
            metricsSnapshot: null,
            rollbackExecuted: false,
            rollbackResult: null,
            confirmToken: minted.confirmToken,
            confirmTokenExpiresAt: minted.confirmTokenExpiresAt,
            nextStep: `Plan verificado (0 secretos bloqueantes). Confirma y ejecuta culkibo_ship_and_verify con los mismos parámetros, dryRun: false y confirmToken: "${minted.confirmToken}" antes de ${minted.confirmTokenExpiresAt}.`
          };
        }
        return {
          phase: 'dry_run_plan',
          dryRun: true,
          executed: false,
          verified: false,
          tool: toolName,
          projectId: project.id,
          wouldExecute: false,
          riskLevel,
          reversible,
          target,
          effects,
          blockers,
          warnings,
          preview,
          secretScan,
          rollbackReadiness,
          deployment: null,
          smokeVerification: null,
          metricsSnapshot: null,
          rollbackExecuted: false,
          rollbackResult: null,
          nextStep: `Resuelve los bloqueos (${blockers.join(', ')}) antes de confirmar culkibo_ship_and_verify.`
        };
      }

      case 'culkibo_manage_production_service': {
        if (!project) throw projectNotFoundError(args.projectId);
        Object.assign(target, { projectId: project.id, projectName: project.name, action: args.action });
        effects.push(`Ejecutará '${args.action}' sobre el contenedor Citadel de '${project.name}' usando stopProduction/startProduction.`);
        preview.deployStatus = await deployManager.status(project.id);
        riskLevel = args.action === 'stop' || args.action === 'hibernate' ? 'high' : 'medium';
        reversible = true;
        break;
      }

      case 'culkibo_manage_crons': {
        if (!project) throw projectNotFoundError(args.projectId);
        Object.assign(target, { projectId: project.id, action: args.action, cronId: args.cronId || null });
        effects.push(`Ejecutará '${args.action}' sobre Cron Jobs de '${project.name}'.`);
        riskLevel = args.action === 'delete' ? 'high' : 'low';
        reversible = args.action !== 'delete';
        break;
      }

      case 'culkibo_manage_previews': {
        if (!project) throw projectNotFoundError(args.projectId);
        Object.assign(target, { projectId: project.id, action: args.action, branch: args.branch || null, previewId: args.previewId || null });
        effects.push(`Ejecutará '${args.action}' sobre Preview Deployments de '${project.name}'.`);
        riskLevel = args.action === 'destroy' ? 'high' : 'medium';
        reversible = args.action !== 'destroy';
        break;
      }

      case 'culkibo_status_page_manage': {
        Object.assign(target, { action: args.action, slug: args.slug });
        effects.push(`Ejecutará '${args.action}' sobre la página de estado pública '/status/${args.slug}'.`);
        riskLevel = args.action === 'delete' ? 'high' : 'medium';
        reversible = args.action !== 'delete';
        break;
      }

      case 'culkibo_manage_domain': {
        Object.assign(target, { action: args.action, hostname: args.hostname || null, id: args.id || null, projectId: args.projectId || null });
        effects.push(`Ejecutará '${args.action}' sobre dominio '${args.hostname || args.id || '(list)'}' y reconciliará Caddy.`);
        riskLevel = args.action === 'delete' ? 'high' : 'medium';
        reversible = args.action !== 'delete';
        break;
      }

      case 'culkibo_switch_traffic': {
        const citadel = Number(args.citadelPercent ?? 100);
        const forge = args.forgePercent !== undefined ? Number(args.forgePercent) : Math.max(0, 100 - citadel);
        Object.assign(target, { forgePercent: forge, citadelPercent: citadel });
        effects.push(`Conmutará el tráfico a ${citadel}% Citadel / ${forge}% Forge y reconciliará Caddy.`);
        riskLevel = 'high';
        reversible = true;
        break;
      }

      case 'culkibo_database_restore': {
        const db = databaseManager.list().find((d) => d.id === args.databaseId);
        Object.assign(target, { databaseId: args.databaseId, name: db?.name || null, backupId: args.backupId || null, remoteKey: args.remoteKey || null });
        if (!args.backupId && !args.remoteKey) blockers.push('MISSING_BACKUP_REF');
        effects.push(`Restaurará la base de datos '${db?.name || args.databaseId}'${args.createSafetySnapshot !== false ? ' creando snapshot de seguridad previo' : ' SIN snapshot de seguridad'}.`);
        riskLevel = 'high';
        reversible = args.createSafetySnapshot !== false;
        break;
      }

      case 'culkibo_uninstall_catalog_service': {
        Object.assign(target, { installationId: args.installationId, deleteVolumes: Boolean(args.deleteVolumes) });
        effects.push(`Desinstalará servicio del catálogo '${args.installationId}'${args.deleteVolumes ? ' incluyendo volúmenes persistentes (IRREVERSIBLE)' : ''}.`);
        riskLevel = 'high';
        reversible = !args.deleteVolumes;
        break;
      }

      case 'culkibo_cancel_deployment': {
        if (!project) throw projectNotFoundError(args.projectId);
        Object.assign(target, { projectId: project.id, projectName: project.name });
        effects.push(`Abortará el despliegue/build en curso de '${project.name}' y liberará la ranura del semáforo.`);
        riskLevel = 'medium';
        reversible = true;
        break;
      }

      case 'culkibo_prune_build_cache': {
        Object.assign(target, { keepStorageGb: args.keepStorageGb ?? 10, untilHours: args.untilHours ?? null });
        effects.push(`Podará la caché BuildKit de Docker conservando ${args.keepStorageGb ?? 10} GB.`);
        riskLevel = 'medium';
        reversible = false;
        break;
      }

      case 'culkibo_manage_webhook': {
        if (!project) throw projectNotFoundError(args.projectId);
        Object.assign(target, { projectId: project.id, action: args.action });
        effects.push(args.action === 'rotate_deploy_hook'
          ? `Rotará el deployHookToken de '${project.name}' invalidando el token CI/CD anterior.`
          : `Consultará los endpoints webhook de '${project.name}'.`);
        riskLevel = args.action === 'rotate_deploy_hook' ? 'high' : 'low';
        reversible = args.action !== 'rotate_deploy_hook';
        break;
      }

      case 'culkibo_manage_wildcard_dns01': {
        Object.assign(target, { action: args.action, domain: args.domain || null });
        effects.push(`Ejecutará '${args.action}' sobre política TLS wildcard DNS-01${args.domain ? ` de '${args.domain}'` : ''}.`);
        riskLevel = args.action === 'remove' ? 'high' : 'medium';
        reversible = true;
        break;
      }

      case 'culkibo_link_database': {
        if (!project) throw projectNotFoundError(args.projectId);
        Object.assign(target, { projectId: project.id, databaseId: args.databaseId, action: args.action || 'link' });
        effects.push(`${args.action === 'unlink' ? 'Desvinculará' : 'Vinculará'} la base de datos '${args.databaseId}' de '${project.name}'.`);
        riskLevel = args.action === 'unlink' ? 'high' : 'low';
        reversible = true;
        break;
      }

      case 'culkibo_manage_watcher': {
        Object.assign(target, { action: args.action, directory: args.directory || null });
        effects.push(`Ejecutará '${args.action}' sobre el vigilante de ficheros de The Forge.`);
        riskLevel = args.action === 'stop' ? 'medium' : 'low';
        reversible = true;
        break;
      }

      default: {
        Object.assign(target, redactForAudit(args));
        effects.push(`Ejecutará la herramienta destructiva '${toolName}' con los parámetros validados.`);
        if (toolName === 'culkibo_restore_backup') {
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
        throw new McpToolError('CANCELLED', 'La invocación de herramienta fue cancelada por el cliente.', {
          retryable: true,
          remediation: 'Reintenta la invocación cuando el cliente esté listo para recibir la respuesta.'
        });
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

        case 'culkibo_deploy_project': {
          const project = projectManager.getById(args.projectId);
          if (!project) throw projectNotFoundError(args.projectId);
          res = redactProjectSecrets(projectManager.activate(args.projectId));
          break;
        }

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
              domains: domainManager.listDomains().filter((d) => {
                if (principal.isSuperAdmin) return true;
                if (!d.projectId) return false;
                return canAccessProject(principal, d.projectId);
              })
            };
          } else if (args.action === 'add') {
            res = await domainManager.addDomain({
              hostname: args.hostname,
              ...(args.projectId ? { projectId: String(args.projectId) } : {}),
              targetPod: args.targetPod || 'forge',
              ...(args.targetPort !== undefined ? { targetPort: Number(args.targetPort) } : {}),
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
                  throw new McpToolError('FORBIDDEN_PATH', 'Solo se permite observar directorios dentro del espacio de trabajo de Culkibo.', {
                    retryable: false,
                    remediation: 'Pasa una ruta dentro del directorio actual o de la carpeta projects/ de Culkibo.'
                  });
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
          if (principal.isSuperAdmin) {
            res = { containers: allContainers };
            break;
          }
          // Fail-closed: `dockerManager.listContainers` no incluye `projectId` por defecto, así que
          // asociamos cada contenedor por `c.projectId` o por nombre/prefijo registrado del proyecto permitido.
          const allowedProjects = projectManager.getAll().filter((p) => canAccessProject(principal, p.id, p));
          const allowedProjectIdSet = new Set(allowedProjects.map((p) => p.id));
          const allowedContainerNames = new Set();
          for (const p of allowedProjects) {
            const st = deployManager.getState(p.id);
            if (st?.current?.containerName) allowedContainerNames.add(String(st.current.containerName).replace(/^\/+/, ''));
            if (st?.previous?.containerName) allowedContainerNames.add(String(st.previous.containerName).replace(/^\/+/, ''));
          }
          const matchesAllowedContainer = (c) => {
            if (!c || typeof c !== 'object') return false;
            if (c.projectId) return allowedProjectIdSet.has(String(c.projectId));
            const names = Array.isArray(c.names) ? c.names : (c.name ? [c.name] : []);
            for (const rawName of names) {
              const cleanName = String(rawName || '').replace(/^\/+/, '');
              if (!cleanName) continue;
              if (allowedContainerNames.has(cleanName)) return true;
              for (const pid of allowedProjectIdSet) {
                const safePid = String(pid).toLowerCase().replace(/[^a-z0-9_-]/g, '_');
                if (cleanName.includes(pid) || cleanName.startsWith(`culkibo_${safePid}`) || cleanName.startsWith(`culkibo-${safePid}`) || cleanName.startsWith(`culkibo_prev_${safePid}`)) {
                  return true;
                }
              }
            }
            return false;
          };
          res = {
            containers: allContainers.filter(matchesAllowedContainer)
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
            if (principal.teamId && res?.project?.id) {
              projectManager.update(res.project.id, { teamId: principal.teamId });
            }
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
            const stopRes = await deployManager.stopProduction(project.id);
            res = { projectId: project.id, action: args.action, ...stopRes };
          } else if (args.action === 'start') {
            const startRes = await deployManager.startProduction(project.id);
            res = { projectId: project.id, action: 'start', ...startRes };
          } else if (args.action === 'restart') {
            /** @type {any} */
            let stopRes = null;
            try { stopRes = await deployManager.stopProduction(project.id); } catch (e) { stopRes = { stopped: false, error: e.message }; }
            const startRes = await deployManager.startProduction(project.id);
            res = { projectId: project.id, action: 'restart', restarted: Boolean(startRes && startRes.started !== false), stop: stopRes, start: startRes };
          }
          break;
        }

        case 'culkibo_system_doctor_fix': {
          const rawAction = String(args.action);
          const mappedAction = rawAction === 'prune_build_cache' ? 'prune_buildkit' : rawAction;
          res = await systemDoctor.applyFix(mappedAction);
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
            if (!args.domain) throw new McpToolError('MISSING_ARGUMENT', 'Falta domain para añadir política wildcard.', { retryable: true, remediation: 'Pasa domain (p. ej. "midominio.com") junto a action: "add".' });
            res = await ingressManager.addWildcardPolicy(args.domain, { includeApex: args.includeApex !== false });
          } else if (args.action === 'remove') {
            if (!args.domain) throw new McpToolError('MISSING_ARGUMENT', 'Falta domain para eliminar política wildcard.', { retryable: true, remediation: 'Lista políticas con action: "list" y pasa el domain exacto con action: "remove".' });
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
            if (!args.cronId) throw new McpToolError('MISSING_ARGUMENT', 'Falta cronId para toggle.', { retryable: true, remediation: 'Lista los cron jobs con action: "list" y pasa el campo id en cronId.' });
            const ownsCron = cronManager.list(project.id).some((c) => c.id === args.cronId);
            if (!ownsCron) {
              throw new McpToolError(principal.isSuperAdmin ? 'NOT_FOUND' : 'FORBIDDEN', `El cron '${args.cronId}' no pertenece al proyecto '${project.id}'.`, { retryable: false, remediation: 'Consulta los cronId válidos del proyecto con culkibo_manage_crons (action: "list").' });
            }
            res = cronManager.update(args.cronId, { enabled: Boolean(args.enabled) });
          } else if (args.action === 'run') {
            if (!args.cronId) throw new McpToolError('MISSING_ARGUMENT', 'Falta cronId para run.', { retryable: true, remediation: 'Lista los cron jobs con action: "list" y pasa el campo id en cronId.' });
            const ownsCron = cronManager.list(project.id).some((c) => c.id === args.cronId);
            if (!ownsCron) {
              throw new McpToolError(principal.isSuperAdmin ? 'NOT_FOUND' : 'FORBIDDEN', `El cron '${args.cronId}' no pertenece al proyecto '${project.id}'.`, { retryable: false, remediation: 'Consulta los cronId válidos del proyecto con culkibo_manage_crons (action: "list").' });
            }
            res = await cronManager.runNow(args.cronId);
          } else if (args.action === 'delete') {
            if (!args.cronId) throw new McpToolError('MISSING_ARGUMENT', 'Falta cronId para delete.', { retryable: true, remediation: 'Lista los cron jobs con action: "list" y pasa el campo id en cronId.' });
            const ownsCron = cronManager.list(project.id).some((c) => c.id === args.cronId);
            if (!ownsCron) {
              throw new McpToolError(principal.isSuperAdmin ? 'NOT_FOUND' : 'FORBIDDEN', `El cron '${args.cronId}' no pertenece al proyecto '${project.id}'.`, { retryable: false, remediation: 'Consulta los cronId válidos del proyecto con culkibo_manage_crons (action: "list").' });
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
            throw new McpToolError('INVALID_ARGUMENT', 'No se puede eliminar el nodo local.', {
              retryable: false,
              remediation: 'Usa culkibo_fleet_list_servers para elegir un serverId remoto distinto de "local".'
            });
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
            if (!args.role) throw new McpToolError('MISSING_ARGUMENT', 'Falta role para update_role.', { retryable: true, remediation: 'Pasa role ("viewer", "developer", "admin" u "owner") junto a action: "update_role".' });
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
            if (!args.tokenId) throw new McpToolError('MISSING_ARGUMENT', 'Falta tokenId para revoke.', { retryable: true, remediation: 'Consulta los IDs con culkibo_rbac_list_tokens y pasa tokenId.' });
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
          const rawPages = typeof um.listStatusPages === 'function' ? um.listStatusPages() : [];
          let statusPages = Array.isArray(rawPages) ? rawPages : [];
          if (!principal.isSuperAdmin) {
            const visibleMonitorIds = new Set(
              (Array.isArray(um.listMonitors({})) ? um.listMonitors({}) : [])
                .filter((m) => canAccessProject(principal, m.projectId))
                .map((m) => m.id)
            );
            statusPages = statusPages.filter((page) => {
              const mids = Array.isArray(page?.monitorIds) ? page.monitorIds : [];
              return mids.length > 0 && mids.every((id) => visibleMonitorIds.has(id));
            });
          }
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
            if (!args.incidentTitle) throw new McpToolError('MISSING_ARGUMENT', 'Falta incidentTitle para publish_incident.', { retryable: true, remediation: 'Incluye incidentTitle y opcionalmente severity/message.' });
            res = um.publishStatusIncident(String(args.slug), {
              title: String(args.incidentTitle),
              severity: args.severity ? String(args.severity) : 'minor',
              message: args.message ? String(args.message) : ''
            });
          } else if (args.action === 'resolve_incident') {
            if (!args.incidentId) throw new McpToolError('MISSING_ARGUMENT', 'Falta incidentId para resolve_incident.', { retryable: true, remediation: 'Consulta los incidentes con culkibo_uptime_list_monitors o culkibo://uptime y pasa incidentId.' });
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
          const rawPlan = gm.planApply(String(args.yamlText), { prune: Boolean(args.prune) });
          if (principal.isSuperAdmin) {
            res = rawPlan;
            break;
          }
          // Anti-IDOR / anti-enumeración: filtrar `create`/`update`/`delete` para no filtrar recursos ajenos al ACL
          const accessibleProjects = projectManager.getAll().filter((p) => canAccessProject(principal, p.id, p));
          const allowedIds = new Set(accessibleProjects.map((p) => p.id));
          const allowedNames = new Set(accessibleProjects.map((p) => String(p.name || '').toLowerCase()));
          const allProjectIds = new Set(projectManager.getAll().map((p) => p.id));
          const allProjectNames = new Set(projectManager.getAll().map((p) => String(p.name || '').toLowerCase()));
          const keepPlanItem = (item, isDelete = false) => {
            if (!item || typeof item !== 'object') return false;
            const pid = item.projectId || (item.kind === 'project' ? item.id : null);
            const pname = item.projectName || (item.kind === 'project' ? item.name : null);
            if (pid) {
              if (allowedIds.has(String(pid))) return true;
              if (allProjectIds.has(String(pid))) return false;
              return !isDelete;
            }
            if (pname) {
              const lc = String(pname).toLowerCase();
              if (allowedNames.has(lc)) return true;
              if (allProjectNames.has(lc)) return false;
              return !isDelete;
            }
            // Recursos sin proyecto asociado en delete[] se ocultan siempre a principales restringidos
            return !isDelete && !Array.isArray(principal.projectIds);
          };
          res = {
            ...rawPlan,
            create: Array.isArray(rawPlan.create) ? rawPlan.create.filter((it) => keepPlanItem(it, false)) : [],
            update: Array.isArray(rawPlan.update) ? rawPlan.update.filter((it) => keepPlanItem(it, false)) : [],
            delete: Array.isArray(rawPlan.delete) ? rawPlan.delete.filter((it) => keepPlanItem(it, true)) : [],
            scopedToPrincipal: true
          };
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
          const allowedProjectIds = this._accessibleProjectIds(principal);
          if (sa && typeof sa.analyzeResources === 'function') {
            const report = await sa.analyzeResources({
              ...(vpsMonthlyEur !== undefined ? { vpsMonthlyEur } : {}),
              ...(allowedProjectIds !== null ? { projectIds: allowedProjectIds } : {})
            });
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
            const projectsCount = allowedProjectIds !== null ? allowedProjectIds.length : projectManager.getAll().length;
            res = {
              summary: { totalRamMb, freeRamMb, usedRamMb: totalRamMb - freeRamMb, projectsCount },
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
          const allowedProjectIds = this._accessibleProjectIds(principal);
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
            const allPolicies = sa.listPolicies(allowedProjectIds !== null ? { projectIds: allowedProjectIds } : {});
            const policies = (Array.isArray(allPolicies) ? allPolicies : []).filter((p) => canAccessProject(principal, p.projectId));
            const rawCandidates = typeof sa.getSleepCandidates === 'function'
              ? sa.getSleepCandidates(allowedProjectIds !== null ? { projectIds: allowedProjectIds } : {})
              : [];
            const candidates = (Array.isArray(rawCandidates) ? rawCandidates : [])
              .filter((c) => principal.isSuperAdmin || (c?.projectId && canAccessProject(principal, c.projectId)));
            res = {
              policies,
              candidates
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
            throw new McpToolError('SERVICE_UNAVAILABLE', 'LiveSync 2.0 rollbackFile no está disponible en esta versión.', {
              retryable: true,
              remediation: 'Comprueba la versión del daemon con culkibo_system_doctor o usa culkibo_rollback_sync.'
            });
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
            throw new McpToolError('SERVICE_UNAVAILABLE', 'El ejecutor runSmokeTests de deployManager no está disponible todavía.', {
              retryable: true,
              remediation: 'Verifica el estado del servicio con culkibo_system_doctor.'
            });
          }
          let upstream = `http://127.0.0.1:${project.forgePort || 3000}`;
          if (target === 'citadel') {
            const st = await deployManager.status(project.id);
            const port = st?.current?.hostPort || project.citadelPort || 3000;
            upstream = `http://127.0.0.1:${port}`;
          } else if (target === 'canary' && typeof deployManager.getCanaryState === 'function') {
            const canary = deployManager.getCanaryState(project.id);
            if (!canary?.canaryDial) {
              throw new McpToolError('CANARY_NOT_ACTIVE', `No hay un despliegue canario activo para '${project.id}'.`, {
                retryable: false,
                remediation: 'Inicia un despliegue canario con culkibo_canary_rollout (action: "start") o usa target: "citadel".'
              });
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
              ok: true,
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
            const depRes = await deployManager.deploy(project, { canary: canaryCfg, trigger: 'mcp_canary' });
            res = { projectId: project.id, ok: depRes?.status !== 'error' && depRes?.status !== 'failed', ...depRes };
          } else if (args.action === 'advance') {
            const canary = typeof deployManager.getCanaryState === 'function' ? deployManager.getCanaryState(project.id) : null;
            if (!canary) {
              throw new McpToolError('CANARY_NOT_ACTIVE', `No hay ningún despliegue canario activo para '${project.id}'.`, {
                retryable: false,
                remediation: 'Inicia primero un rollout canario con culkibo_canary_rollout (action: "start").'
              });
            }
            const steps = Array.isArray(canary.steps) && canary.steps.length > 0 ? canary.steps : [10, 50, 100];
            const currentWeight = Number(canary.weight || 0);
            const nextStepWeight = args.weightPercent !== undefined
              ? Math.min(100, Math.max(1, Number(args.weightPercent)))
              : (steps.find((w) => Number(w) > currentWeight) ?? 100);
            if (nextStepWeight >= 100) {
              const promoted = await deployManager.promoteCanary(project.id);
              res = { projectId: project.id, action: 'advance', promoted: true, previousWeight: currentWeight, nextWeight: 100, ...promoted };
            } else {
              const hostnames = typeof deployManager.hostnamesFor === 'function'
                ? deployManager.hostnamesFor(project.id)
                : domainManager.listDomains().filter((d) => d.projectId === project.id).map((d) => d.hostname);
              const routeRes = await deployManager.switchCanaryRoute(
                { id: canary.deploymentId, projectId: project.id },
                hostnames,
                { stableDial: canary.stableDial, canaryDial: canary.canaryDial, canaryWeight: nextStepWeight },
                project
              );
              const liveRef = /** @type {any} */ (deployManager).activeCanaries?.get?.(project.id);
              if (liveRef && routeRes?.ok !== false) {
                liveRef.weight = nextStepWeight;
                const matchedIdx = steps.findIndex((w) => Number(w) >= nextStepWeight);
                if (matchedIdx >= 0) liveRef.stepIndex = matchedIdx;
              }
              res = {
                projectId: project.id,
                action: 'advance',
                ok: routeRes?.ok !== false,
                deploymentId: canary.deploymentId,
                previousWeight: currentWeight,
                nextWeight: nextStepWeight,
                route: routeRes
              };
            }
          } else if (args.action === 'promote') {
            if (typeof deployManager.promoteCanary !== 'function') {
              throw new McpToolError('SERVICE_UNAVAILABLE', 'promoteCanary no está disponible todavía en deployManager.', {
                retryable: true,
                remediation: 'Comprueba la versión del daemon con culkibo_system_doctor.'
              });
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
              throw new McpToolError('SERVICE_UNAVAILABLE', 'Las ventanas freeze globales no están disponibles todavía en deployManager.', {
                retryable: true,
                remediation: 'Indica projectId para configurar ventanas de freeze a nivel de proyecto.'
              });
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

        // --- MCP 2.1: I. Meta-Discovery y Autocuración Autónoma (3) ---
        case 'culkibo_search_tools': {
          res = this.searchTools(principal, args);
          break;
        }

        case 'culkibo_diagnose_incident': {
          res = await this.diagnoseIncident(principal, args);
          break;
        }

        case 'culkibo_auto_remediate': {
          res = await this.executeAutoRemediate(principal, args);
          break;
        }

        // --- MCP 2026 Pioneer: Ship-and-Verify & Agent Kit Generator (2) ---
        case 'culkibo_ship_and_verify': {
          res = await this.executeShipAndVerify(principal, args, context);
          break;
        }

        case 'culkibo_export_agent_kit': {
          const targetProject = args.projectId ? projectManager.getById(String(args.projectId)) : null;
          if (args.projectId && !targetProject) throw projectNotFoundError(args.projectId);
          res = this.buildAgentKit({
            target: args.target || 'all',
            profile: args.profile || 'core',
            serverUrl: args.serverUrl || undefined,
            projectId: targetProject ? targetProject.id : null,
            projectName: targetProject ? targetProject.name : null,
            includeOpsGuide: args.includeOpsGuide !== false
          });
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
      throw new McpToolError('FORBIDDEN', `Acceso denegado al recurso '${clean}' para los scopes del token.`, {
        retryable: false,
        remediation: 'Consulta tus scopes efectivos con culkibo_rbac_whoami o solicita un token con el scope de lectura correspondiente.'
      });
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
      const domains = domainManager.listDomains().filter((d) => {
        if (principal.isSuperAdmin) return true;
        if (!d.projectId) return false;
        return canAccessProject(principal, d.projectId);
      });
      data = { domains, wildcardPolicies: principal.isSuperAdmin ? ingressManager.listWildcardPolicies() : [] };
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
        const rawPages = typeof um.listStatusPages === 'function' ? um.listStatusPages() : [];
        const visibleMonitorIds = new Set(monitors.map((m) => m.id));
        const statusPages = principal.isSuperAdmin
          ? (Array.isArray(rawPages) ? rawPages : [])
          : (Array.isArray(rawPages) ? rawPages : []).filter((page) => {
              const mids = Array.isArray(page?.monitorIds) ? page.monitorIds : [];
              return mids.length > 0 && mids.every((id) => visibleMonitorIds.has(id));
            });
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

  /**
   * Sanea un argumento de prompt (longitud acotada, sin caracteres de control ni secretos).
   * @param {any} raw
   * @param {string} fallback
   */
  _sanitizePromptArg(raw, fallback) {
    if (raw === undefined || raw === null) return fallback;
    const cleaned = String(raw).replace(/[\r\n\t\0\x1b]+/g, ' ').trim().slice(0, 120);
    if (!cleaned) return fallback;
    if (SENSITIVE_VALUE_RE.test(cleaned)) return '[REDACTED]';
    return cleaned;
  }

  /**
   * Lista los prompts interactivos MCP (8 playbooks de ingeniería MCP 2026 + 5 prompts heredados).
   * @param {any} [authOrPrincipal]
   */
  listPrompts(authOrPrincipal = null) {
    const principal = normalizePrincipal(authOrPrincipal);
    if (principal.role === 'none') return [];
    return [
      // --- 8 Battle-Tested Interactive Engineering Playbooks (MCP 2026) ---
      {
        name: 'deploy_safely',
        title: 'Deploy Safely (Pre-Flight Secret Scan → Ship → Smoke → Metrics)',
        description: 'Playbook completo de despliegue seguro: escaneo pre-despliegue de secretos, verificación de freeze/rollback readiness, despliegue con culkibo_ship_and_verify, smoke checks y validación de métricas.',
        arguments: [
          { name: 'projectId', description: 'ID del proyecto a desplegar con red de seguridad', required: true },
          { name: 'targetEnv', description: 'Entorno objetivo opcional (p. ej. production, staging)', required: false },
          { name: 'canary', description: 'Usar despliegue canario progresivo ("true" | "false")', required: false }
        ]
      },
      {
        name: 'migrate_from_coolify',
        title: 'Migrate from Coolify (Scan → Magic Vars & Traefik → Plan → Verify)',
        description: 'Migración asistida sin pérdida desde Coolify: inventario read-only, traducción de variables mágicas (SERVICE_FQDN_*/SERVICE_PASSWORD_*) y etiquetas Traefik a Caddy, plan de migración y verificación.',
        arguments: [
          { name: 'coolifyUrl', description: 'URL base de la instancia Coolify de origen', required: true },
          { name: 'targetServerId', description: 'ID del nodo destino en la flota (default local)', required: false }
        ]
      },
      {
        name: 'debug_production_crash',
        title: 'Debug Production Crash (Correlate OOM/Logs/Restarts → Safe Remediate)',
        description: 'Diagnóstico autónomo de caídas en producción con culkibo_diagnose_incident, correlación de OOMKilled/logs/restarts/uptime y remediación segura en 2 fases (dryRun + confirmToken).',
        arguments: [
          { name: 'projectId', description: 'ID del proyecto afectado (opcional para diagnóstico global)', required: false },
          { name: 'hostname', description: 'Dominio afectado opcional para sondear DNS/TLS/Caddy', required: false }
        ]
      },
      {
        name: 'zero_downtime_db_upgrade',
        title: 'Zero-Downtime DB Upgrade (Backup + Verify + DR Drill → Clone/Pooler → Cutover)',
        description: 'Actualización de motor de base de datos sin cortes: backup cifrado + verificación + ensayo DR no destructivo, clonado/pooler en paralelo y conmutación con plan de vuelta atrás.',
        arguments: [
          { name: 'databaseId', description: 'ID de la base de datos gestionada a actualizar', required: true },
          { name: 'targetVersion', description: 'Versión o imagen objetivo (p. ej. postgres:17)', required: false }
        ]
      },
      {
        name: 'security_audit_stack',
        title: 'Security Audit Stack (Audit Chain + Secret Scan + RBAC/2FA/OIDC + TLS)',
        description: 'Auditoría integral de seguridad: integridad de cadena SHA-256 de auditoría, escaneo de secretos en proyectos, postura RBAC/2FA/OIDC/tokens, exposición de BDs y caducidad TLS.',
        arguments: [
          { name: 'scope', description: 'Alcance opcional ("instance" o projectId concreto)', required: false }
        ]
      },
      {
        name: 'setup_wildcard_tls_and_tunnel',
        title: 'Setup Wildcard TLS & Zero-Open-Ports Tunnel (Multi-DNS-01 / Cloudflare CGNAT)',
        description: 'Configura certificados comodín *.dominio.com por ACME DNS-01 multi-dominio en Caddy o acceso sin puertos abiertos tras CGNAT con Cloudflare Tunnel y verificación TLS real.',
        arguments: [
          { name: 'rootDomain', description: 'Dominio raíz para wildcard/túnel (p. ej. miempresa.com)', required: true },
          { name: 'mode', description: 'Modo deseado: "dns01", "tunnel" o "hybrid"', required: false }
        ]
      },
      {
        name: 'optimize_ram_and_costs',
        title: 'Optimize RAM & VPS Costs (Sleep Advisor + Cost Advisor + Right-Sizing)',
        description: 'Reduce consumo de RAM y factura VPS combinando culkibo_cost_advisor, políticas Smart Sleep para servicios inactivos, ajuste de límites de contenedores y poda segura de BuildKit.',
        arguments: [
          { name: 'monthlyServerCostEur', description: 'Coste mensual actual del VPS en EUR para estimar ahorro real', required: false }
        ]
      },
      {
        name: 'disaster_recovery_drill',
        title: 'Disaster Recovery Drill (AES-256-GCM Verify + Non-Destructive Restore)',
        description: 'Simulacro no destructivo de recuperación ante desastres: verifica backups cifrados AES-256-GCM y checksums SHA-256, ejecuta dryRun de restauración y valida RTO/RPO sin tocar producción.',
        arguments: [
          { name: 'databaseId', description: 'ID de base de datos objetivo para el simulacro DR (opcional)', required: false },
          { name: 'projectId', description: 'ID de proyecto opcional para verificar respaldo integral', required: false }
        ]
      },

      // --- 5 Prompts heredados (compatibilidad 100% con clientes previos) ---
      {
        name: 'debug-failed-deploy',
        title: 'Debug Failed Deploy (Legacy)',
        description: 'Guía paso a paso para diagnosticar un despliegue fallido, leer sus logs, comprobar Docker/disco y proponer un fix seguro.',
        arguments: [
          { name: 'projectId', description: 'ID del proyecto que falló al desplegar', required: true }
        ]
      },
      {
        name: 'zero-downtime-release',
        title: 'Zero-Downtime Release (Legacy)',
        description: 'Checklist operativo para lanzar una nueva versión en producción sin cortes y con plan de rollback instantáneo.',
        arguments: [
          { name: 'projectId', description: 'ID del proyecto a liberar en Citadel', required: true }
        ]
      },
      {
        name: 'audit-security-tls',
        title: 'Audit Security & TLS (Legacy)',
        description: 'Audita la postura de seguridad del servidor: TLS/HTTPS, Basic Auth, exposición de BDs, Doctor del sistema y alertas.',
        arguments: []
      },
      {
        name: 'culkibo_multi_server_rollout',
        title: 'Multi-Server Progressive Rollout',
        description: 'Orquesta un despliegue progresivo multi-servidor verificando flota SSH, ventanas de freeze, previsualización dryRun, canary y smoke tests con auto-rollback.',
        arguments: [
          { name: 'projectId', description: 'ID del proyecto a desplegar en la flota', required: true },
          { name: 'targetServers', description: 'Lista opcional separada por comas de serverIds objetivo', required: false },
          { name: 'canarySteps', description: 'Pasos canarios opcionales (p. ej. "10,50,100")', required: false }
        ]
      },
      {
        name: 'culkibo_incident_triage',
        title: 'Production Incident Triage',
        description: 'Triaje sistemático de incidentes en producción usando uptime, pods, flota, diagnóstico de dominio, logs, cost advisor y conflictos de LiveSync.',
        arguments: [
          { name: 'projectId', description: 'ID del proyecto afectado (opcional)', required: false },
          { name: 'hostname', description: 'Dominio afectado (opcional)', required: false }
        ]
      }
    ];
  }

  /**
   * Devuelve el guion paso a paso de un prompt/playbook MCP con argumentos saneados.
   * @param {string} name
   * @param {Record<string, any>} [args]
   * @param {{ auth?: any }} [context]
   */
  getPrompt(name, args = {}, context = {}) {
    const principal = normalizePrincipal(context && context.auth ? context.auth : null);
    if (principal.role === 'none') {
      throw new McpToolError('FORBIDDEN', 'Acceso denegado a prompts/get para credencial no autenticada o revocada.', {
        retryable: false,
        remediation: 'Autentícate con un token válido antes de consultar playbooks MCP.'
      });
    }
    const safeArgs = args && typeof args === 'object' ? args : {};
    const pid = this._sanitizePromptArg(safeArgs.projectId, '<projectId>');

    if (name === 'deploy_safely') {
      const envName = this._sanitizePromptArg(safeArgs.targetEnv, 'production');
      const useCanary = String(safeArgs.canary || '').toLowerCase() === 'true';
      return {
        description: 'Playbook de despliegue seguro: secret scan pre-despliegue → ship → smoke check → verificación de métricas',
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: [
                `Ejecuta el playbook **deploy_safely** para el proyecto \`${pid}\` (entorno \`${envName}\`${useCanary ? ', modo canary progresivo' : ''}):`,
                '1) **Inspección previa**: llama a `culkibo_get_project`, `culkibo_deploy_strategy` y `culkibo_deploy_freeze` (`action: "list"`) para confirmar configuración, estrategia y ausencia de ventanas de congelación.',
                '2) **Pre-flight Secret Scan y Plan (Fase 1)**: llama a `culkibo_ship_and_verify` con `{ projectId: "' + pid + '", dryRun: true, secretScanMode: "block" }`. Verifica que `secretScan.blocked === false` (0 secretos hardcoded; si hay fugas, muévelas a `${vault.KEY}`), comprueba `rollbackReadiness` y revisa el `confirmToken` HMAC-SHA256 emitido.',
                '3) **Resguardo de BDs**: si el proyecto tiene bases de datos vinculadas (`culkibo_list_databases`), crea copia previa con `culkibo_database_backup`.',
                useCanary
                  ? '4) **Rollout progresivo + Smoke Guard**: tras confirmación explícita del usuario, lanza `culkibo_canary_rollout` (`action: "start"`, `steps: [10, 50, 100]`, `autoRollbackOnSmokeFail: true`) validando cada paso con `culkibo_smoke_test_run`.'
                  : '4) **Despliegue y verificación autónoma (Fase 2)**: tras confirmación explícita del usuario, llama a `culkibo_ship_and_verify` con `dryRun: false`, el `confirmToken` recibido, `runSmokeTests: true` y `autoRollbackOnFailure: true`.',
                '5) **Validación final**: revisa `smokeVerification`, `metricsSnapshot`, `culkibo_get_container_logs` y `culkibo_get_observability`. Resume estado de la release, latencia smoke y comando de rollback listo (`culkibo_rollback_deployment`).'
              ].join('\n')
            }
          }
        ]
      };
    }

    if (name === 'migrate_from_coolify') {
      const coolifyUrl = this._sanitizePromptArg(safeArgs.coolifyUrl, 'https://coolify.tu-dominio.com');
      const targetServerId = this._sanitizePromptArg(safeArgs.targetServerId, 'local');
      return {
        description: 'Migración paso a paso desde Coolify con traducción de variables mágicas y Traefik → Caddy',
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: [
                `Ejecuta el playbook **migrate_from_coolify** desde \`${coolifyUrl}\` hacia el nodo \`${targetServerId}\`:`,
                '1) **Inventario en solo lectura**: solicita al usuario el API token de Coolify (nunca lo guardes en archivos ni logs) y ejecuta `culkibo_migrate_coolify` con `{ coolifyUrl: "' + coolifyUrl + '", mode: "preview" }` para listar aplicaciones, bases de datos y servicios Compose.',
                '2) **Revisión de traducción mágica y Traefik**: analiza el preview verificando cómo se traducen variables mágicas (`SERVICE_FQDN_*`, `SERVICE_URL_*`, `SERVICE_PASSWORD_*`, `SERVICE_USER_*`) y reglas Traefik (`traefik.http.routers.*`, middlewares, strip-prefix, Basic Auth) hacia rutas nativas Caddy + `${vault.KEY}`.',
                '3) **Capacidad y plan de corte**: sondea el nodo destino con `culkibo_fleet_probe_server` (`serverId: "' + targetServerId + '"`) y `culkibo_cost_advisor`; presenta al usuario el plan exacto (qué apps, BDs y servicios importar) para aprobación.',
                '4) **Importación selectiva**: ejecuta `culkibo_migrate_coolify` con `mode: "import"` sobre los recursos aprobados, vincula bases de datos con `culkibo_link_database` y verifica que no existan secretos en claro en `culkibo_gitops_export`.',
                '5) **Verificación post-migración**: reconcilia Caddy con `culkibo_reconcile_ingress`, comprueba DNS/TLS real con `culkibo_diagnose_domain` y ejecuta `culkibo_smoke_test_run` sobre cada app antes de cambiar DNS definitivo.'
              ].join('\n')
            }
          }
        ]
      };
    }

    if (name === 'debug_production_crash') {
      const hostHint = safeArgs.hostname ? ` y dominio \`${this._sanitizePromptArg(safeArgs.hostname, '')}\`` : '';
      return {
        description: 'Diagnóstico autónomo de crash en producción: correlación OOM/logs/restarts y remediación segura',
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: [
                `Ejecuta el playbook **debug_production_crash** para \`${pid}\`${hostHint}:`,
                '1) **Diagnóstico correlacionado**: ejecuta `culkibo_diagnose_incident` (con `projectId`, `hostname` si aplica, `logLines: 150`, `includeDoctor: true`) para correlacionar `OOMKilled`, `RestartCount`, estado de healthcheck, último despliegue, logs redactados, monitores de uptime, presión de RAM/Smart Sleep, System Doctor, flota SSH y conflictos LiveSync.',
                '2) **Aislamiento de causa raíz**: si aparece `CONTAINER_OOM_KILLED`, `CONTAINER_CRASH_LOOP` o `RECENT_DEPLOY_FAILED`, inspecciona los logs exactos con `culkibo_get_container_logs` y `culkibo_get_deployment_logs`, y evalúa presión de memoria con `culkibo_cost_advisor`.',
                '3) **Plan de remediación seguro (Fase 1)**: selecciona la acción recomendada (`rollback_release`, `restart_service`, `wake_service`, `toggle_maintenance`, `reconcile_ingress` o `doctor_fix`) y llama a `culkibo_auto_remediate` con `dryRun: true` para inspeccionar el radio de impacto y obtener el `confirmToken` HMAC-SHA256.',
                '4) **Aplicación y verificación (Fase 2)**: explica la causa raíz con evidencia al usuario, pide confirmación explícita, aplica `culkibo_auto_remediate` con `dryRun: false`, `confirmToken` y `verifyAfter: true`, y confirma estabilidad con `culkibo_uptime_list_monitors` y `culkibo_get_observability`.'
              ].join('\n')
            }
          }
        ]
      };
    }

    if (name === 'zero_downtime_db_upgrade') {
      const dbId = this._sanitizePromptArg(safeArgs.databaseId, '<databaseId>');
      const targetVer = this._sanitizePromptArg(safeArgs.targetVersion, '<targetVersion>');
      return {
        description: 'Actualización de base de datos sin cortes: backup + verificación + DR drill → clon/pooler → cutover',
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: [
                `Ejecuta el playbook **zero_downtime_db_upgrade** para la base de datos \`${dbId}\` hacia \`${targetVer}\`:`,
                '1) **Inspección de línea base**: llama a `culkibo_list_databases`, `culkibo_database_inspect` (`databaseId: "' + dbId + '"`) y `culkibo_list_projects` para mapear versión actual, tamaño, tablas críticas y proyectos vinculados.',
                '2) **Backup cifrado + Verificación**: ejecuta `culkibo_database_backup` (`databaseId: "' + dbId + '"`) y confirma con `culkibo_database_list_backups` que existe un archivo reciente con checksum SHA-256 y cifrado AES-256-GCM.',
                '3) **Ensayo DR + Clonado en paralelo**: crea una instancia clon/staging con la versión objetivo (`culkibo_create_database`) y valida la restauración y compatibilidad de esquema/pooler antes de tocar producción (usa `culkibo_database_restore` con `dryRun: true` para planificar).',
                '4) **Cutover controlado**: previsualiza el reenlace con `culkibo_link_database` (`dryRun: true`); si se requiere ventana breve de consistencia de escritura, coordina `culkibo_toggle_maintenance` (`dryRun: true`), conmuta el enlace a la nueva BD, redespliega con `culkibo_ship_and_verify` (`dryRun: true` → `dryRun: false`) y valida con `culkibo_smoke_test_run` + `culkibo_database_inspect`.',
                '5) **Período de garantía**: mantén la instancia anterior detenida pero intacta (sin `deleteVolume: true`) hasta confirmar 24–72 h sin regresiones.'
              ].join('\n')
            }
          }
        ]
      };
    }

    if (name === 'security_audit_stack') {
      const scope = this._sanitizePromptArg(safeArgs.scope, 'instance');
      return {
        description: 'Auditoría integral de seguridad: cadena hash de auditoría, secretos, RBAC/2FA/OIDC y TLS',
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: [
                `Ejecuta el playbook **security_audit_stack** (alcance: \`${scope}\`):`,
                '1) **Salud y endurecimiento base**: llama a `culkibo_system_doctor` y lee `culkibo://doctor` para detectar fallos de permisos, Docker, Caddy, disco o configuración insegura.',
                '2) **Postura RBAC, Equipos, 2FA/OIDC y Tokens**: llama a `culkibo_rbac_whoami`, `culkibo_team_list_members` y `culkibo_rbac_list_tokens`. Verifica principio de mínimo privilegio (tokens acotados por `projectIds` y scopes específicos, sin tokens caducados/huérfanos, revisión de 2FA/OIDC para cuentas admin/owner).',
                '3) **Integridad de auditoría encadenada y Escaneo de Secretos**: verifica la integridad criptográfica SHA-256 de la cadena de auditoría (`GET /api/audit/verify`), revisa `culkibo_list_projects` y ejecuta `culkibo_ship_and_verify` con `dryRun: true` (modo `block`) por proyecto para detectar credenciales hardcoded o claves de alta entropía; valida también que `culkibo_gitops_export` use `${vault.KEY}` y cero secretos en claro.',
                '4) **TLS, Borde y Exposición de Datos**: llama a `culkibo_ingress_status` (`probe: true`), `culkibo_manage_wildcard_dns01` (`action: "list"`) y `culkibo_list_databases` para detectar certificados próximos a caducar (<14 días), dominios sin protección o bases de datos expuestas innecesariamente en `0.0.0.0`.',
                '5) **Informe priorizado**: entrega una tabla de hallazgos P0 (crítico) a P3 (mejora) indicando la herramienta MCP exacta (`dryRun: true`) para remediar cada punto.'
              ].join('\n')
            }
          }
        ]
      };
    }

    if (name === 'setup_wildcard_tls_and_tunnel') {
      const rootDomain = this._sanitizePromptArg(safeArgs.rootDomain, 'example.com');
      const mode = this._sanitizePromptArg(safeArgs.mode, 'dns01');
      return {
        description: 'Configuración de TLS Wildcard Multi-DNS-01 o Cloudflare Tunnel CGNAT sin puertos abiertos',
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: [
                `Ejecuta el playbook **setup_wildcard_tls_and_tunnel** para \`${rootDomain}\` (modo: \`${mode}\`):`,
                '1) **Diagnóstico de capacidades**: llama a `culkibo_ingress_status`, `culkibo_get_remote_access` y `culkibo_system_doctor` para comprobar si Caddy tiene plugin DNS-01 disponible, si el servidor tiene IP pública o está detrás de CGNAT, y el estado de Cloudflare.',
                '2) **Opción A — Wildcard Multi-DNS-01 (`*.' + rootDomain + '`)**: revisa políticas actuales con `culkibo_manage_wildcard_dns01` (`action: "list"`), previsualiza con `culkibo_manage_wildcard_dns01` (`action: "add"`, `domain: "' + rootDomain + '"`, `includeApex: true`, `dryRun: true`) asegurándote de referenciar el token por variable de entorno (`CF_API_TOKEN`) y nunca en claro.',
                '3) **Opción B — CGNAT / Zero-Open-Ports (Cloudflare Tunnel)**: verifica túneles activos en `culkibo_get_remote_access`, registra los hostnames con `culkibo_manage_domain` (`cloudflareProxied: true`, `dryRun: true` → aplicar) sin abrir puertos 80/443 en el firewall del host.',
                '4) **Reconciliación y sonda TLS real**: ejecuta `culkibo_reconcile_ingress` (tras confirmación) y verifica DNS + cadena X.509 real con `culkibo_diagnose_domain` y `culkibo_inspect_ingress` sobre `' + rootDomain + '` y un subdominio de prueba (`app.' + rootDomain + '`).'
              ].join('\n')
            }
          }
        ]
      };
    }

    if (name === 'optimize_ram_and_costs') {
      const costHint = safeArgs.monthlyServerCostEur
        ? ` (coste VPS actual: ${this._sanitizePromptArg(safeArgs.monthlyServerCostEur, '20')} EUR/mes)`
        : '';
      return {
        description: 'Optimización de RAM y costes VPS con Cost Advisor, Smart Sleep y ajuste de límites',
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: [
                `Ejecuta el playbook **optimize_ram_and_costs**${costHint}:`,
                '1) **Telemetría y análisis económico**: ejecuta `culkibo_cost_advisor`' + (safeArgs.monthlyServerCostEur ? ` con \`monthlyServerCostEur: ${Number(safeArgs.monthlyServerCostEur) || 20}\`` : '') + ' junto a `culkibo_get_observability` para cuantificar RAM libre, RAM recuperable (`reclaimableRamMb`) y ahorro mensual estimado.',
                '2) **Inventario de servicios inactivos y límites**: llama a `culkibo_sleep_status`, `culkibo_docker_containers` y `culkibo_list_databases` para identificar previews/staging ociosos, contenedores sobredimensionados y caché BuildKit acumulada.',
                '3) **Simulación sin riesgo**: para cada candidato seguro (evitando servicios críticos con tráfico continuo), previsualiza Smart Sleep con `culkibo_sleep_manage` (`action: "configure"`, `idleMinutes: 30`, `dryRun: true`) y limpieza de caché con `culkibo_prune_build_cache` (`dryRun: true`).',
                '4) **Plan de right-sizing**: presenta al usuario el ahorro total proyectado en MB y EUR/mes, los límites `memoryMb`/CPU recomendados por contenedor y solicita aprobación antes de aplicar cada cambio.'
              ].join('\n')
            }
          }
        ]
      };
    }

    if (name === 'disaster_recovery_drill') {
      const dbId = this._sanitizePromptArg(safeArgs.databaseId, '<databaseId>');
      return {
        description: 'Simulacro no destructivo de Disaster Recovery: verificación AES-256-GCM y restore drill',
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: [
                `Ejecuta el playbook **disaster_recovery_drill** (BD: \`${dbId}\`, proyecto: \`${pid}\`):`,
                '1) **Auditoría de backups existentes**: llama a `culkibo_list_backups`, `culkibo_list_databases` y `culkibo_database_list_backups` para comprobar frecuencia programada (`schedule`), retención, disponibilidad local/S3, cifrado AES-256-GCM y checksum SHA-256.',
                '2) **Snapshot de verificación**: genera un backup fresco con `culkibo_database_backup` (y opcionalmente un snapshot de configuración redactado con `culkibo_export_instance_snapshot`, `includeSecrets: false`).',
                '3) **Simulacro de restauración NO destructivo**: ejecuta primero `culkibo_database_restore` con `dryRun: true` y `createSafetySnapshot: true` para verificar referencias y validar que producción no se sobrescribe sin snapshot de seguridad; para ensayo real completo, aprovisiona una BD temporal aislada (`culkibo_create_database`), restaura en ella y verifica tablas/latencia con `culkibo_database_inspect`.',
                '4) **Informe RTO/RPO y limpieza**: documenta tiempos de backup/restore (RTO real), antigüedad del último respaldo (RPO real), integridad verificada y elimina la BD temporal de ensayo con `culkibo_delete_database` (`dryRun: true` → confirmar).'
              ].join('\n')
            }
          }
        ]
      };
    }

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
      const targetServers = this._sanitizePromptArg(safeArgs.targetServers, 'los nodos configurados en la flota');
      const canarySteps = this._sanitizePromptArg(safeArgs.canarySteps, '10, 50, 100');
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
      const hostHint = safeArgs.hostname ? ` y dominio ${this._sanitizePromptArg(safeArgs.hostname, '')}` : '';
      return {
        description: 'Triaje sistemático de incidentes en producción con diagnóstico correlacionado y remediación segura',
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Realiza el triaje del incidente para el proyecto ${pid}${hostHint}: 1) Ejecuta culkibo_diagnose_incident para correlacionar contenedor (OOM/CrashLoop), despliegues recientes, logs redactados, uptime, RAM/disco, System Doctor, dominio, flota y LiveSync; 2) Amplía detalle si hace falta con culkibo_cost_advisor, culkibo_get_deployment_logs y culkibo_sync_conflicts; 3) Previsualiza el fix recomendado con culkibo_auto_remediate (dryRun: true) para obtener el plan y el confirmToken de un solo uso; 4) Pide confirmación explícita antes de aplicar culkibo_auto_remediate con dryRun: false y confirmToken.`
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
   * @param {{ auth?: any, transport?: string, profile?: string | null }} [context]
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
          capabilities: {
            tools: { listChanged: false },
            resources: { listChanged: false },
            prompts: { listChanged: false }
          },
          serverInfo: SERVER_INFO,
          instructions: `Este endpoint habla la revisión ${LEGACY_PROTOCOL_VERSION}, deprecada. Culkibo ya sirve la revisión ${PROTOCOL_VERSION} en POST /api/mcp (Streamable HTTP, sin handshake).`
        }
      };
    }

    if (method === 'tools/list') {
      try {
        const profile = params?.profile || context.profile || 'all';
        const tools = this.getToolsForPrincipal(context.auth, {
          profile,
          query: typeof params?.query === 'string' ? params.query : null,
          readOnlyOnly: params?.readOnlyOnly === true,
          limit: typeof params?.limit === 'number' ? params.limit : null
        });
        return {
          jsonrpc: '2.0',
          id: safeId,
          result: {
            tools
          }
        };
      } catch (err) {
        return {
          jsonrpc: '2.0',
          id: safeId,
          error: { code: ERROR_CODES.INVALID_PARAMS, message: err.message, data: err.details || {} }
        };
      }
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
      return { jsonrpc: '2.0', id, result: { prompts: this.listPrompts(context.auth) } };
    }

    if (method === 'prompts/get') {
      try {
        return { jsonrpc: '2.0', id, result: this.getPrompt(params?.name, params?.arguments || {}, { auth: context.auth }) };
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
          tools: { listChanged: false, filtering: true },
          resources: { listChanged: false },
          prompts: { listChanged: false }
        },
        instructions: [
          'Culkibo es un orquestador cloud AI-native autohospedado (MCP 2026: 109 herramientas anotadas, 7 recursos y 13 prompts incluyendo 8 playbooks de ingeniería). Gestiona proyectos, pods (The Forge y The Citadel), flota multi-servidor SSH, equipos/RBAC, entornos y promoción, uptime y páginas de estado, GitOps (culkibo.yaml), Smart Sleep y Cost Advisor, LiveSync 2.0 time-travel, smoke tests, canary auto-guard, deploy freeze, despliegue autónomo Ship & Verify, diagnóstico de incidentes, remediación segura y generación 1-clic de kits de agente.',
          'Para reducir el consumo de contexto en >80%, conecta con POST /api/mcp?profile=core|deploy|ops|security|all (o env CULKIBO_MCP_PROFILE=core sobre stdio), usa tools/list con params.query o descubre cualquier herramienta bajo demanda con culkibo_search_tools.',
          'Para desplegar con escaneo pre-despliegue de secretos, smoke checks y rollback automático usa culkibo_ship_and_verify (dryRun: true -> confirmToken HMAC-SHA256 de un solo uso -> dryRun: false). Para incidentes usa culkibo_diagnose_incident + culkibo_auto_remediate.',
          'Usa prompts/list para acceder a los 8 playbooks interactivos (deploy_safely, migrate_from_coolify, debug_production_crash, zero_downtime_db_upgrade, security_audit_stack, setup_wildcard_tls_and_tunnel, optimize_ram_and_costs, disaster_recovery_drill) y culkibo_export_agent_kit para generar configs drop-in sin secretos en claro.',
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
   * @param {{ transport?: string, clientInfo?: any, isCancelled?: () => boolean, signal?: AbortSignal, onProgress?: (msg: string) => void, auth?: any, profile?: string | null }} context
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
      try {
        const rawProfile = params?.profile !== undefined ? params.profile : (context.profile || 'all');
        const profile = this.normalizeProfile(rawProfile);
        const query = typeof params?.query === 'string' ? params.query.trim() : null;
        const readOnlyOnly = params?.readOnlyOnly === true;
        const limit = typeof params?.limit === 'number' && Number.isFinite(params.limit) ? params.limit : null;
        const tools = this.getToolsForPrincipal(principal, { profile, query, readOnlyOnly, limit });
        return ok({
          tools,
          ...(profile !== 'all' || query ? { profile } : {}),
          ttlMs: principal.isSuperAdmin && !query ? 60000 : 0,
          cacheScope: principal.isSuperAdmin && !query ? 'public' : 'private'
        });
      } catch (err) {
        return {
          jsonrpc: '2.0',
          id,
          error: {
            code: ERROR_CODES.INVALID_PARAMS,
            message: err.message,
            data: err.details || { allowedProfiles: VALID_TOOL_PROFILES }
          }
        };
      }
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
      return ok({
        prompts: this.listPrompts(principal),
        ttlMs: principal.isSuperAdmin ? 60000 : 0,
        cacheScope: principal.isSuperAdmin ? 'public' : 'private'
      });
    }

    if (method === 'prompts/get') {
      try {
        return ok(this.getPrompt(params?.name, params?.arguments || {}, { auth: context.auth }));
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

  getClientConfigs(serverUrl = 'http://localhost:3030', { includeAuthPlaceholder = false, profile = 'core' } = {}) {
    const cleanUrl = String(serverUrl || 'http://localhost:3030').replace(/\/+$/, '');
    const cliEntry = path.resolve(__dirname, '..', '..', 'bin', 'culkibo.js');
    const isRemote = !/^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/i.test(cleanUrl);
    const needAuth = includeAuthPlaceholder || isRemote;
    const tokenPlaceholder = '${CULKIBO_TOKEN}';
    const remoteHeaders = needAuth ? { Authorization: `Bearer ${tokenPlaceholder}` } : undefined;
    const safeProfile = VALID_TOOL_PROFILES.includes(/** @type {any} */ (String(profile || 'core').toLowerCase()))
      ? String(profile || 'core').toLowerCase()
      : 'core';
    const mcpEndpoint = safeProfile !== 'all'
      ? `${cleanUrl}/api/mcp?profile=${safeProfile}`
      : `${cleanUrl}/api/mcp`;
    const kit = this.buildAgentKit({ target: 'all', profile: safeProfile, serverUrl: cleanUrl, includeOpsGuide: true });

    return {
      claudeDesktop: {
        mcpServers: {
          culkibo: {
            command: 'node',
            args: [cliEntry, 'mcp'],
            env: {
              CULKIBO_API_URL: cleanUrl,
              ...(safeProfile !== 'all' ? { CULKIBO_MCP_PROFILE: safeProfile } : {}),
              ...(needAuth ? { CULKIBO_TOKEN: tokenPlaceholder } : {})
            }
          }
        }
      },
      // Clientes con transporte HTTP: el endpoint moderno, un solo POST.
      antigravity: kit.kits.antigravity.config,
      cursorOrWindsurf: {
        mcpServers: {
          culkibo: {
            url: mcpEndpoint,
            ...(remoteHeaders ? { headers: remoteHeaders } : {})
          }
        }
      },
      windsurf: kit.kits.windsurf.config,
      vscodeCopilot: {
        servers: {
          culkibo: {
            type: 'http',
            url: mcpEndpoint,
            ...(remoteHeaders ? { headers: remoteHeaders } : {})
          }
        }
      },
      claudeCodeMcpJson: kit.kits['claude-code'].config,
      claudeMdSnippet: kit.kits['claude-code'].claudeMdSnippet,
      codexCli: {
        toml: kit.kits.codex.config,
        command: kit.kits.codex.cliCommand
      },
      claudeCodeCli: needAuth
        ? `claude mcp add --transport http culkibo "${mcpEndpoint}" --header "Authorization: Bearer ${tokenPlaceholder}"`
        : `claude mcp add --transport http culkibo "${mcpEndpoint}"`,
      agentKit: kit,
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
        endpoint: mcpEndpoint,
        profile: safeProfile,
        profiles: VALID_TOOL_PROFILES,
        tokenPlaceholder,
        tokenSavings: kit.tokenSavings,
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
    SERVER_INFO,
    VALID_TOOL_PROFILES
  },
  McpToolError,
  TOOL_POLICIES,
  TOOL_PROFILES,
  VALID_TOOL_PROFILES,
  normalizePrincipal,
  lazySvc,
  redactForAudit
});

module.exports = mcpServer;
