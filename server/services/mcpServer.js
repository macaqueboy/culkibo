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
const mcpAppsRenderer = require('./mcpAppsRenderer');

// Servicios v2 cargados estrictamente bajo demanda para preservar ~61 MB de RAM en reposo.
const ALLOWED_LAZY_SERVICES = new Set([
  'serverFleetManager',
  'teamManager',
  'environmentManager',
  'gitopsManager',
  'uptimeMonitor',
  'sleepAdvisor',
  'secretScanner',
  'auditLogger',
  'smartPackBuilder',
  'directPushRegistry',
  'edgeTunnelService',
  'topologyService',
  'supplyChainAttestor',
  'otlpExporter',
  'shadowReplayService',
  'timeMachineService',
  'finopsOptimizer',
  'buildHealerService',
  'fleetMeshService',
  'edgeShieldService',
  'cveDriftService',
  'secretLeaseService',
  'driftDetectorService',
  'iacExporter',
  'webhookEventBus',
  'dbStudioService',
  'objectStorageService',
  'quotaMeteringService',
  'brandThemeService',
  'backupDrillService',
  'sloCanaryController',
  'aiWorkloadService',
  'remoteBuilderService',
  'logArchiveService',
  'admissionPolicyService',
  'edgeExperimentService',
  'complianceBundleService',
  'volumeMigrationService',
  'syntheticSentinelService',
  'workerAutoscalerService',
  'sqlMigrationLinter',
  'licenseAuditorService',
  'seccompProfileService',
  'imageBloatAuditor',
  'cronLeaseService',
  'piiMaskerService',
  'oomForensicsService',
  'oncallEscalationService',
  'egressFirewallService',
  'replicaFailoverService',
  'preDeploySecretGate',
  'multiArchPlannerService',
  'chaosGameDayService'
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
const SENSITIVE_VALUE_RE = /(ghp_|gho_|github_pat_|sk_|bearer\s+|whsec_[A-Za-z0-9+/=_-]{8,}|ck(?:[stihprl]|et|bg)_[A-Za-z0-9_-]{6,}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)/i;
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
  'culkibo_rbac_manage_token',
  'culkibo_edge_tunnel',
  'culkibo_otlp_status',
  'culkibo_shadow_replay',
  'culkibo_fleet_mesh',
  'culkibo_export_iac',
  'culkibo_secret_lease',
  'culkibo_webhook_dlq',
  'culkibo_s3_storage',
  'culkibo_compliance_bundle',
  'culkibo_synthetic_sentinel',
  'culkibo_audit_image_bloat',
  'culkibo_mask_preview_pii',
  'culkibo_secret_gate'
]);

/** @type {Record<string, number>} */
const ROLE_RANK = Object.freeze({
  viewer: 10,
  developer: 20,
  admin: 30,
  owner: 40
});

/** Herramientas no destructivas (y destructivas con plan propio) que soportan `dryRun: true` (41 destructivas + 13 = 54). */
const EXTRA_DRY_RUN_TOOLS = new Set([
  'culkibo_deploy_production',
  'culkibo_rollback_deployment',
  'culkibo_heal_build_failure',
  'culkibo_secret_lease',
  'culkibo_webhook_dlq',
  'culkibo_brand_theme',
  'culkibo_slo_canary',
  'culkibo_remote_builder',
  'culkibo_admission_check',
  'culkibo_edge_experiment',
  'culkibo_synthetic_sentinel',
  'culkibo_worker_autoscaler',
  'culkibo_cron_lease',
  'culkibo_oncall_router',
  'culkibo_egress_firewall',
  'culkibo_replica_failover',
  'culkibo_chaos_gameday'
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
    'culkibo_smartpack_plan',
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
    'culkibo_env_promote',
    'culkibo_verify_attestation',
    'culkibo_shadow_replay',
    'culkibo_time_machine',
    'culkibo_heal_build_failure',
    'culkibo_triage_playbook',
    'culkibo_drift_check',
    'culkibo_export_iac',
    'culkibo_webhook_dlq',
    'culkibo_db_studio',
    'culkibo_s3_storage',
    'culkibo_slo_canary',
    'culkibo_ai_workload',
    'culkibo_remote_builder',
    'culkibo_admission_check',
    'culkibo_volume_migrate',
    'culkibo_edge_experiment',
    'culkibo_lint_sql_migration',
    'culkibo_worker_autoscaler',
    'culkibo_seccomp_profile',
    'culkibo_audit_image_bloat',
    'culkibo_mask_preview_pii',
    'culkibo_oom_forensics',
    'culkibo_secret_gate',
    'culkibo_multiarch_planner',
    'culkibo_replica_failover'
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
    'culkibo_otlp_status',
    'culkibo_system_doctor',
    'culkibo_system_doctor_fix',
    'culkibo_docker_status',
    'culkibo_docker_containers',
    'culkibo_manage_production_service',
    'culkibo_toggle_maintenance',
    'culkibo_diagnose_domain',
    'culkibo_ingress_status',
    'culkibo_reconcile_ingress',
    'culkibo_edge_tunnel',
    'culkibo_edge_shield',
    'culkibo_uptime_list_monitors',
    'culkibo_status_page_manage',
    'culkibo_cron_timeline',
    'culkibo_cost_advisor',
    'culkibo_finops_report',
    'culkibo_shadow_replay',
    'culkibo_time_machine',
    'culkibo_heal_build_failure',
    'culkibo_triage_playbook',
    'culkibo_cve_scan',
    'culkibo_drift_check',
    'culkibo_export_iac',
    'culkibo_webhook_dlq',
    'culkibo_db_studio',
    'culkibo_s3_storage',
    'culkibo_agency_ledger',
    'culkibo_brand_theme',
    'culkibo_dr_drill',
    'culkibo_slo_canary',
    'culkibo_ai_workload',
    'culkibo_remote_builder',
    'culkibo_log_archive_search',
    'culkibo_volume_migrate',
    'culkibo_edge_experiment',
    'culkibo_security_posture',
    'culkibo_synthetic_sentinel',
    'culkibo_lint_sql_migration',
    'culkibo_worker_autoscaler',
    'culkibo_audit_image_bloat',
    'culkibo_cron_lease',
    'culkibo_oom_forensics',
    'culkibo_oncall_router',
    'culkibo_egress_firewall',
    'culkibo_replica_failover',
    'culkibo_multiarch_planner',
    'culkibo_chaos_gameday',
    'culkibo_sleep_status',
    'culkibo_sleep_manage',
    'culkibo_fleet_list_servers',
    'culkibo_fleet_mesh',
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
    'culkibo_edge_tunnel',
    'culkibo_edge_shield',
    'culkibo_fleet_mesh',
    'culkibo_set_domain_basic_auth',
    'culkibo_manage_webhook',
    'culkibo_webhook_dlq',
    'culkibo_deploy_freeze',
    'culkibo_list_databases',
    'culkibo_database_list_backups',
    'culkibo_export_instance_snapshot',
    'culkibo_diagnose_incident',
    'culkibo_triage_playbook',
    'culkibo_verify_attestation',
    'culkibo_cve_scan',
    'culkibo_secret_lease',
    'culkibo_brand_theme',
    'culkibo_dr_drill',
    'culkibo_admission_check',
    'culkibo_compliance_bundle',
    'culkibo_security_posture',
    'culkibo_synthetic_sentinel',
    'culkibo_audit_licenses',
    'culkibo_seccomp_profile',
    'culkibo_audit_image_bloat',
    'culkibo_mask_preview_pii',
    'culkibo_egress_firewall',
    'culkibo_secret_gate'
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
  kit: ['agent', 'export', 'mcp', 'config'],
  smartpack: ['build', 'plan', 'dockerfile', 'dockerignore', 'railpack', 'deploy'],
  railpack: ['smartpack', 'build', 'plan', 'dockerfile'],
  dockerfile: ['smartpack', 'build', 'plan', 'deploy'],
  tunnel: ['edge', 'cgnat', 'ingress', 'cloudflare', 'edgetunnel'],
  cgnat: ['tunnel', 'edge', 'ingress', 'cloudflare'],
  edgetunnel: ['tunnel', 'edge', 'cgnat', 'ingress'],
  slsa: ['attestation', 'verify', 'provenance', 'dsse', 'sbom', 'ed25519', 'security'],
  attestation: ['slsa', 'verify', 'provenance', 'dsse', 'sbom', 'ed25519', 'security'],
  dsse: ['slsa', 'attestation', 'verify', 'provenance', 'ed25519'],
  provenance: ['slsa', 'attestation', 'verify', 'sbom', 'dsse'],
  sbom: ['slsa', 'attestation', 'provenance', 'security'],
  otlp: ['observability', 'traces', 'metrics', 'tempo', 'signoz', 'honeycomb', 'telemetry'],
  tempo: ['otlp', 'observability', 'traces'],
  signoz: ['otlp', 'observability', 'traces', 'metrics'],
  honeycomb: ['otlp', 'observability', 'traces'],
  traces: ['otlp', 'observability', 'metrics'],
  shadow: ['replay', 'canary', 'cutover', 'regression', 'traffic', 'baseline', 'candidate'],
  replay: ['shadow', 'canary', 'cutover', 'regression', 'traffic'],
  timemachine: ['checkpoint', 'snapshot', 'restore', 'diff', 'rollback', 'stack'],
  checkpoint: ['timemachine', 'snapshot', 'restore', 'diff', 'rollback'],
  finops: ['cost', 'savings', 'vercel', 'railway', 'render', 'vps', 'hetzner', 'rightsizing', 'advisor'],
  savings: ['finops', 'cost', 'vercel', 'railway', 'render', 'vps', 'advisor'],
  vercel: ['finops', 'cost', 'savings', 'compare'],
  railway: ['finops', 'cost', 'savings', 'compare'],
  wireguard: ['mesh', 'fleet', 'x25519', 'vpn', 'ufw', 'firewall'],
  mesh: ['wireguard', 'fleet', 'x25519', 'vpn'],
  healer: ['heal', 'build', 'diagnose', 'oom', 'dockerfile', 'logs'],
  heartbeat: ['cron', 'timeline', 'deadman', 'schedule', 'uptime'],
  timeline: ['cron', 'heartbeat', 'heatmap', 'collision', 'schedule'],
  shield: ['waf', 'bot', 'pow', 'anubis', 'scraper', 'edge', 'caddy'],
  pow: ['shield', 'waf', 'bot', 'anubis', 'challenge'],
  waf: ['shield', 'bot', 'pow', 'edge', 'caddy'],
  cve: ['osv', 'sbom', 'vulnerability', 'security', 'scan', 'triage'],
  osv: ['cve', 'sbom', 'vulnerability', 'security', 'scan'],
  drift: ['config', 'inspect', 'pgbouncer', 'triage', 'reconcile'],
  pgbouncer: ['drift', 'postgres', 'pool', 'database'],
  terraform: ['iac', 'opentofu', 'hcl', 'compose', 'export'],
  opentofu: ['iac', 'terraform', 'hcl', 'compose', 'export'],
  iac: ['terraform', 'opentofu', 'hcl', 'compose', 'export'],
  lease: ['secret', 'breakglass', 'rotation', 'vault', 'ephemeral'],
  triage: ['incident', 'heal', 'drift', 'cve', 'playbook', 'diagnose'],
  dlq: ['webhook', 'replay', 'outbound', 'event', 'rotate'],
  webhook: ['dlq', 'replay', 'outbound', 'event', 'rotate', 'hook'],
  studio: ['sql', 'redis', 'bloat', 'explain', 'database', 'postgres'],
  sql: ['studio', 'database', 'postgres', 'explain', 'bloat'],
  redis: ['studio', 'valkey', 'database', 'scan', 'cache'],
  s3: ['storage', 'garage', 'rustfs', 'seaweedfs', 'minio', 'presign', 'sigv4', 'cors', 'lifecycle'],
  garage: ['s3', 'storage', 'minio', 'presign', 'sigv4'],
  rustfs: ['s3', 'storage', 'minio', 'presign', 'sigv4'],
  seaweedfs: ['s3', 'storage', 'minio', 'presign', 'sigv4'],
  minio: ['s3', 'storage', 'garage', 'rustfs', 'seaweedfs', 'presign'],
  presign: ['s3', 'storage', 'sigv4', 'bucket'],
  ledger: ['billing', 'quota', 'agency', 'csv', 'finops', 'usage', 'cost'],
  billing: ['ledger', 'quota', 'agency', 'csv', 'finops', 'cost'],
  quota: ['ledger', 'billing', 'agency', 'limit', 'tenant'],
  brand: ['whitelabel', 'theme', 'logo', 'login', 'accent'],
  whitelabel: ['brand', 'theme', 'logo', 'login', 'agency'],
  drill: ['backup', 'restore', 'dr', 'recovery', 'checksum', 'sql'],
  dr: ['drill', 'backup', 'restore', 'recovery', 'disaster'],
  slo: ['canary', 'burn', 'rollback', 'budget', 'progressive', 'caddy'],
  canary: ['slo', 'burn', 'rollback', 'budget', 'progressive', 'weight'],
  gpu: ['ai', 'llm', 'vram', 'ollama', 'vllm', 'llamacpp', 'cuda', 'cdi'],
  vram: ['ai', 'gpu', 'llm', 'ollama', 'vllm', 'llamacpp', 'quantization'],
  llm: ['ai', 'gpu', 'vram', 'ollama', 'vllm', 'llamacpp'],
  ollama: ['ai', 'gpu', 'vram', 'llm', 'vllm', 'llamacpp'],
  vllm: ['ai', 'gpu', 'vram', 'llm', 'ollama', 'llamacpp'],
  builder: ['remote', 'buildx', 'offload', 'mux', 'ssh', 'prune', 'preview'],
  archive: ['logs', 'ndjson', 'gzip', 'search', 'retention', 'history'],
  admission: ['policy', 'cis', 'pss', 'opa', 'kyverno', 'guardrail', 'security', 'privileged'],
  policy: ['admission', 'cis', 'pss', 'opa', 'kyverno', 'compliance', 'posture'],
  soc2: ['compliance', 'bundle', 'iso27001', 'gdpr', 'ed25519', 'posture', 'audit'],
  iso27001: ['compliance', 'bundle', 'soc2', 'gdpr', 'ed25519', 'posture'],
  gdpr: ['compliance', 'bundle', 'soc2', 'iso27001', 'ed25519', 'posture'],
  compliance: ['bundle', 'soc2', 'iso27001', 'gdpr', 'posture', 'admission'],
  volume: ['migrate', 'snapshot', 'tar', 'uid', 'stateful', 'vps', 'fleet'],
  geo: ['experiment', 'country', 'ab', 'sticky', 'cookie', 'edge', 'caddy'],
  experiment: ['ab', 'geo', 'sticky', 'cookie', 'killswitch', 'edge', 'caddy'],
  posture: ['security', 'compliance', 'admission', 'cve', 'drill', 'rotation', 'scorecard'],
  synthetic: ['sentinel', 'flow', 'uptime', 'tls', 'sni', 'probe', 'monitor'],
  sentinel: ['synthetic', 'flow', 'tls', 'sni', 'cert', 'expiry', 'uptime'],
  migration: ['sql', 'lint', 'ddl', 'lock', 'concurrently', 'postgres', 'database'],
  lint: ['sql', 'migration', 'ddl', 'lock', 'concurrently'],
  autoscale: ['worker', 'autoscaler', 'keda', 'queue', 'backpressure', 'breaker', 'replicas'],
  autoscaler: ['worker', 'autoscale', 'keda', 'queue', 'backpressure', 'breaker', 'replicas'],
  keda: ['worker', 'autoscaler', 'queue', 'backpressure', 'replicas'],
  license: ['spdx', 'agpl', 'sspl', 'sbom', 'compliance', 'audit'],
  spdx: ['license', 'agpl', 'sspl', 'sbom', 'compliance', 'audit'],
  seccomp: ['runc', 'syscall', 'io_uring', 'kernel', 'security', 'profile'],
  runc: ['seccomp', 'cve', 'container', 'syscall', 'security'],
  bloat: ['image', 'dockerfile', 'layers', 'dive', 'dockle', 'hadolint', 'secret', 'slimming'],
  layers: ['image', 'bloat', 'dockerfile', 'dive', 'dockle', 'secret'],
  fencing: ['cron', 'lease', 'idempotency', 'duplicate', 'lock', 'schedule'],
  pii: ['mask', 'anonymize', 'gdpr', 'preview', 'snaplet', 'neosync', 'database', 'sql'],
  anonymize: ['pii', 'mask', 'gdpr', 'preview', 'database', 'sql'],
  forensics: ['oom', 'exit', '137', 'sigkill', 'sigsegv', 'crash', 'rollback', 'memory'],
  oncall: ['escalation', 'incident', 'flapping', 'dedup', 'pager', 'rotation', 'uptime'],
  flapping: ['oncall', 'escalation', 'dedup', 'incident', 'uptime', 'alert'],
  egress: ['firewall', 'nftables', 'iptables', 'docker-user', 'metadata', 'sockets', 'security'],
  nftables: ['egress', 'firewall', 'docker-user', 'security', 'drift'],
  replica: ['failover', 'fencing', 'split-brain', 'database', 'postgres', 'promote', 'lag'],
  failover: ['replica', 'fencing', 'split-brain', 'database', 'promote'],
  entropy: ['secret', 'gate', 'gitleaks', 'trufflehog', 'scan', 'predeploy', 'security'],
  multiarch: ['arm64', 'amd64', 'manifest', 'buildx', 'qemu', 'exec', 'platform'],
  arm64: ['multiarch', 'amd64', 'manifest', 'buildx', 'qemu', 'platform'],
  chaos: ['gameday', 'toxiproxy', 'fault', 'resilience', 'latency', 'jitter', 'abort'],
  gameday: ['chaos', 'toxiproxy', 'fault', 'resilience', 'scorecard']
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
  culkibo_export_agent_kit: { minRole: 'viewer', scope: 'tools:read', projectScoped: false },
  // MCP 2026 Cycle-2: SmartPack Build Intelligence & Sovereign EdgeTunnel (+2 = 111)
  culkibo_smartpack_plan: { minRole: 'viewer', scope: 'deployments:read', projectScoped: true },
  culkibo_edge_tunnel: { minRole: 'admin', scope: 'ingress:write', projectScoped: false, secretSensitive: true },
  // MCP 2026 Cycle-4: SLSA v1.1 Attestation Verification & Native OTLP/HTTP Export (+2 = 113)
  culkibo_verify_attestation: { minRole: 'viewer', scope: 'security:read', projectScoped: true },
  culkibo_otlp_status: { minRole: 'admin', scope: 'observability:write', projectScoped: false, secretSensitive: true },
  // MCP 2026 Cycle-6: Shadow Traffic Replay, Whole-Stack Time-Machine & FinOps Savings (+3 = 116)
  culkibo_shadow_replay: { minRole: 'developer', scope: 'deployments:write', projectScoped: true, secretSensitive: true },
  culkibo_time_machine: { minRole: 'developer', scope: 'deployments:write', projectScoped: true, secretSensitive: true },
  culkibo_finops_report: { minRole: 'viewer', scope: 'advisor:read', projectScoped: false },
  // MCP 2026 Cycle-7: Build Auto-Healer, WireGuard Fleet Mesh, Cron Timeline & Edge Bot-Shield (+4 = 120)
  culkibo_heal_build_failure: { minRole: 'developer', scope: 'deployments:write', projectScoped: true },
  culkibo_fleet_mesh: { minRole: 'admin', scope: 'fleet:write', projectScoped: false, secretSensitive: true },
  culkibo_cron_timeline: { minRole: 'viewer', scope: 'crons:read', projectScoped: false },
  culkibo_edge_shield: { minRole: 'developer', scope: 'domains:write', projectScoped: false },
  // MCP 2026 Cycle-8: Autonomous Triage, SBOM CVE Drift, Config Drift + PgBouncer, IaC Export & Secret Leases (+5 = 125)
  culkibo_triage_playbook: { minRole: 'viewer', scope: 'observability:read', projectScoped: true },
  culkibo_cve_scan: { minRole: 'viewer', scope: 'security:read', projectScoped: false },
  culkibo_drift_check: { minRole: 'developer', scope: 'deployments:read', projectScoped: true },
  culkibo_export_iac: { minRole: 'developer', scope: 'gitops:read', projectScoped: false, secretSensitive: true },
  culkibo_secret_lease: { minRole: 'admin', scope: 'security:write', projectScoped: false, secretSensitive: true },
  // MCP 2026 Cycle-9: Standard-Webhooks DLQ, Read-Only DB Studio, Post-MinIO S3, Agency Ledger & White-Label Brand (+5 = 130)
  culkibo_webhook_dlq: { minRole: 'developer', scope: 'webhooks:write', projectScoped: false, secretSensitive: true },
  culkibo_db_studio: { minRole: 'developer', scope: 'databases:read', projectScoped: true },
  culkibo_s3_storage: { minRole: 'developer', scope: 'storage:read', projectScoped: false, secretSensitive: true },
  culkibo_agency_ledger: { minRole: 'viewer', scope: 'observability:read', projectScoped: true },
  culkibo_brand_theme: { minRole: 'viewer', scope: 'system:read', projectScoped: false },
  // MCP 2026 Cycle-10: DR Fire-Drill, SLO Canary Auto-Rollback, AI/GPU LLM, Remote Builder & Compressed Log Archive (+5 = 135)
  culkibo_dr_drill: { minRole: 'developer', scope: 'databases:write', projectScoped: true },
  culkibo_slo_canary: { minRole: 'developer', scope: 'deployments:write', projectScoped: true },
  culkibo_ai_workload: { minRole: 'developer', scope: 'projects:read', projectScoped: false },
  culkibo_remote_builder: { minRole: 'admin', scope: 'fleet:write', projectScoped: false },
  culkibo_log_archive_search: { minRole: 'viewer', scope: 'logs:read', projectScoped: true },
  // MCP 2026 Cycle-11: Policy-as-Code Admission, Ed25519 Compliance Bundle, Volume Migration, Edge Geo/A-B & Security Posture (+5 = 140)
  culkibo_admission_check: { minRole: 'developer', scope: 'security:read', projectScoped: false },
  culkibo_compliance_bundle: { minRole: 'admin', scope: 'security:read', projectScoped: false, secretSensitive: true },
  culkibo_volume_migrate: { minRole: 'developer', scope: 'fleet:write', projectScoped: true },
  culkibo_edge_experiment: { minRole: 'developer', scope: 'domains:write', projectScoped: true },
  culkibo_security_posture: { minRole: 'viewer', scope: 'security:read', projectScoped: false },
  // MCP 2026 Cycle-12: Synthetic API/TLS Sentinel, SQL Migration Linter, KEDA Worker Autoscaler, SPDX License Auditor & Seccomp/runc Guard (+5 = 145)
  culkibo_synthetic_sentinel: { minRole: 'developer', scope: 'uptime:write', projectScoped: false, secretSensitive: true },
  culkibo_lint_sql_migration: { minRole: 'viewer', scope: 'databases:read', projectScoped: false },
  culkibo_worker_autoscaler: { minRole: 'developer', scope: 'deployments:write', projectScoped: true },
  culkibo_audit_licenses: { minRole: 'viewer', scope: 'security:read', projectScoped: false },
  culkibo_seccomp_profile: { minRole: 'developer', scope: 'security:read', projectScoped: false },
  // MCP 2026 Cycle-13 (150 MCP Tools Milestone!): Image Bloat/Secret Auditor, Cron Fencing Leases, PR-Preview PII Masker, OOM Forensics & On-Call Router (+5 = 150)
  culkibo_audit_image_bloat: { minRole: 'developer', scope: 'deployments:read', projectScoped: false, secretSensitive: true },
  culkibo_cron_lease: { minRole: 'developer', scope: 'crons:write', projectScoped: false },
  culkibo_mask_preview_pii: { minRole: 'developer', scope: 'databases:read', projectScoped: false, secretSensitive: true },
  culkibo_oom_forensics: { minRole: 'developer', scope: 'observability:read', projectScoped: true },
  culkibo_oncall_router: { minRole: 'developer', scope: 'uptime:write', projectScoped: false },
  // MCP 2026 Cycle-14 (155 MCP Tools!): Egress/nftables Drift Auditor, Replica Split-Brain Fencing, Shannon-Entropy Secret Gate, Multi-Arch Planner & Chaos GameDay (+5 = 155)
  culkibo_egress_firewall: { minRole: 'developer', scope: 'security:write', projectScoped: true },
  culkibo_replica_failover: { minRole: 'developer', scope: 'databases:write', projectScoped: false },
  culkibo_secret_gate: { minRole: 'developer', scope: 'security:read', projectScoped: false, secretSensitive: true },
  culkibo_multiarch_planner: { minRole: 'developer', scope: 'deployments:read', projectScoped: false },
  culkibo_chaos_gameday: { minRole: 'developer', scope: 'deployments:write', projectScoped: true }
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
  // Fail-closed: un resultado de autenticación rechazado (`{ ok: false }`) o un principal ya denegado (`role: 'none'` / `kind: 'denied'`) NUNCA puede escalar a viewer/superadmin (idempotente).
  if (
    authOrPrincipal.ok === false ||
    authOrPrincipal.role === 'none' ||
    authOrPrincipal.kind === 'denied' ||
    (authOrPrincipal.principal && (authOrPrincipal.principal.role === 'none' || authOrPrincipal.principal.kind === 'denied'))
  ) {
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
const META_ELICITATION = 'io.modelcontextprotocol/elicitation';
const META_RELATED_TASK = 'io.modelcontextprotocol/related-task';

// Límites acotados del almacén en memoria de MCP Async Tasks (2026-07-28, cero crecimiento sin cota)
const MAX_ASYNC_TASKS = 128;
const DEFAULT_TASK_TTL_MS = 60000;
const MIN_TASK_TTL_MS = 100;
const MAX_TASK_TTL_MS = 300000;
const DEFAULT_TASK_POLL_INTERVAL_MS = 1000;
const DEFAULT_TASK_RESULT_WAIT_MS = 30000;

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
  'prompts/get',
  'tasks/list',
  'tasks/get',
  'tasks/result',
  'tasks/cancel'
];

// Métodos que obligan a enviar la cabecera `Mcp-Name`.
const NAME_BEARING_METHODS = ['tools/call', 'resources/read', 'prompts/get'];

/**
 * Construye una solicitud estructurada `elicitation/create` conforme a MCP 2026
 * para que clientes compatibles rendericen formularios interactivos de remediación
 * (confirmación HMAC, secreto faltante o override de deploy freeze).
 * @param {{ message: string, requestedSchema: Record<string, any>, action?: string | null, projectId?: string | null, mode?: 'form' | 'url' }} opts
 */
function buildElicitationRequest({ message, requestedSchema, action = null, projectId = null, mode = 'form' }) {
  const safeMessage = String(message || 'Additional confirmation or structured input is required to continue.').slice(0, 500);
  const rawSchema = requestedSchema && typeof requestedSchema === 'object' ? requestedSchema : { type: 'object', properties: {} };
  const schema = {
    type: 'object',
    properties: rawSchema.properties && typeof rawSchema.properties === 'object' ? rawSchema.properties : {},
    ...(Array.isArray(rawSchema.required) && rawSchema.required.length > 0 ? { required: rawSchema.required } : {})
  };
  /** @type {Record<string, any>} */
  const meta = {};
  if (action) meta.action = String(action);
  if (projectId) meta.projectId = String(projectId);
  return {
    method: 'elicitation/create',
    params: {
      mode: mode === 'url' ? 'url' : 'form',
      message: safeMessage,
      requestedSchema: schema,
      ...(Object.keys(meta).length > 0 ? { _meta: meta } : {})
    }
  };
}

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
  MISSING_SECRET: 'Almacena el secreto requerido en el Vault cifrado de Culkibo (${vault.KEY}) o mediante culkibo_set_project_env antes de reintentar.',
  SECRET_LEAK_DETECTED: 'Mueve los secretos detectados al Vault cifrado de Culkibo (${vault.KEY}) o a secretos de entorno antes de desplegar.',
  DEPLOY_FROZEN: 'Espera a que finalice la ventana con culkibo_deploy_freeze (action: "list") o repite el flujo con overrideFreeze: true (admin/owner).',
  DEPLOY_FREEZE_ACTIVE: 'Espera a que finalice la ventana con culkibo_deploy_freeze (action: "list") o repite el flujo con overrideFreeze: true (admin/owner).',
  TASK_NOT_FOUND: 'Verifica el taskId con tasks/list (cada tarea es estrictamente privada para el principal que la creó y expira tras su TTL).',
  TASK_CANCELLED: 'La tarea asíncrona fue cancelada; vuelve a lanzar tools/call con params.task si deseas reiniciar la ejecución.',
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
    /** Almacén acotado (<=128) con TTL por principal para MCP 2026-07-28 Async Tasks (`io.modelcontextprotocol/tasks`). */
    /** @type {Map<string, any>} */
    this._tasks = new Map();
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
        description: 'Busca semánticamente (ES/EN) entre las 111 herramientas autorizadas de Culkibo para descubrir sus esquemas bajo demanda sin saturar la ventana de contexto (ideal con ?profile=core).',
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
      },

      // --- MCP 2026 Cycle-2: SmartPack Build Intelligence & Sovereign EdgeTunnel (+2 -> 111) ---
      {
        name: 'culkibo_smartpack_plan',
        title: 'Generar plan determinista de build (SmartPack)',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            directory: { type: 'string' },
            projectId: { type: ['string', 'null'] },
            stack: { type: 'string' },
            plan: { type: 'object' },
            dockerignore: { type: 'array' },
            resourceLimits: { type: 'object' },
            dockerfile: { type: ['string', 'null'] }
          }
        },
        description: 'Analiza un directorio o proyecto con Culkibo SmartPack (cero deps) para emitir un build-plan.json determinista (14+ stacks, cache mounts BuildKit, zstd:chunked, límites cgroup --memory/--cpus, .dockerignore implícito y Dockerfile generado).',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', minLength: 1, description: 'ID de proyecto opcional (resuelve su localPath o directorio en projects/)' },
            directory: { type: 'string', maxLength: 512, description: 'Ruta local dentro del workspace o projects/ (opcional si se pasa projectId)' },
            includeDockerfile: { type: 'boolean', description: 'Incluir Dockerfile renderizado desde el build plan (default true)' },
            zstdChunked: { type: 'boolean', description: 'Activar flags OCI zstd:chunked en el plan de exportación (default false)' }
          }
        }
      },
      {
        name: 'culkibo_edge_tunnel',
        title: 'Gestionar túneles CGNAT soberanos (EdgeTunnel)',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string' },
            status: { type: 'object' },
            tunnels: { type: 'array' },
            tunnel: { type: 'object' },
            revoked: { type: 'boolean' },
            id: { type: 'string' }
          }
        },
        description: 'Lista, inspecciona, crea o revoca túneles WebSocket multiplexados soberanos (Culkibo EdgeTunnel) para exponer servicios tras CGNAT sin puertos abiertos ni dependencia de Cloudflare (solo admin/owner; soporta dryRun: true).',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['status', 'list', 'create', 'revoke'], description: 'Acción sobre EdgeTunnel' },
            tunnelId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID del túnel a revocar (requerido para action="revoke")' },
            name: { type: 'string', minLength: 1, maxLength: 80, description: 'Nombre descriptivo del túnel (para action="create")' },
            targetHost: { type: 'string', maxLength: 253, description: 'Host loopback destino del agente (default 127.0.0.1)' },
            targetPort: { type: 'integer', minimum: 1, maximum: 65535, description: 'Puerto destino del servicio local (requerido para action="create")' },
            hostname: { type: 'string', maxLength: 253, description: 'Dominio público opcional asociado al túnel (RFC 1123)' }
          },
          required: ['action']
        }
      },

      // --- MCP 2026 Cycle-4: SLSA v1.1 Attestations & Native OTLP/HTTP Export (+2 -> 113) ---
      {
        name: 'culkibo_verify_attestation',
        title: 'Verificar atestación SLSA v1.1 Ed25519 DSSE',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string' },
            valid: { type: 'boolean' },
            projectId: { type: ['string', 'null'] },
            revision: { type: ['string', 'null'] },
            count: { type: 'number' },
            attestations: { type: 'array' },
            attestation: { type: ['object', 'null'] },
            verification: { type: ['object', 'null'] },
            publicKeyPem: { type: 'string' }
          }
        },
        description: 'Inspecciona, lista o verifica criptográficamente sobres DSSE Ed25519 con proveniencia SLSA v1.1 (in-toto Statement v1 + CycloneDX 1.6 SBOM summary) por proyecto/revisión o sobre un sobre DSSE aportado.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['verify', 'get', 'list', 'public_key'], description: 'Operación sobre atestaciones SLSA v1.1 (default automático según parámetros)' },
            projectId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID de proyecto opcional para consultar o verificar atestaciones persistidas' },
            revision: { type: 'string', minLength: 1, maxLength: 128, description: 'Revisión o etiqueta del despliegue a inspeccionar/verificar' },
            envelope: { type: 'object', description: 'Sobre DSSE v1 raw ({ payloadType, payload, signatures }) para verificación directa' },
            publicKeyPem: { type: 'string', maxLength: 4096, description: 'Clave pública Ed25519 SPKI PEM opcional para verificar sobres firmados externamente' }
          }
        }
      },
      {
        name: 'culkibo_otlp_status',
        title: 'Estado y configuración de OTLP/HTTP nativo',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        outputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string' },
            configured: { type: 'boolean' },
            status: { type: 'object' },
            flush: { type: 'object' }
          }
        },
        description: 'Consulta el estado del exportador OTLP/HTTP JSON nativo sin dependencias (Grafana Tempo, SigNoz, Honeycomb; IDs hex en minúsculas, gzip, circuit breaker y cabeceras redactadas), configura su endpoint/cabeceras o fuerza un flush manual (admin/owner).',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['status', 'configure', 'flush'], description: 'Acción sobre el exportador OTLP (default "status")' },
            endpoint: { type: ['string', 'null'], maxLength: 512, description: 'URL base OTLP/HTTP destino (ej. https://tempo.acme.dev:4318) o null para limpiar (solo action="configure")' },
            headers: { type: 'object', description: 'Cabeceras HTTP opcionales para autenticación OTLP (siempre redactadas en status y auditoría)' },
            enabled: { type: 'boolean', description: 'Activar o desactivar exportación OTLP (solo action="configure")' },
            serviceName: { type: 'string', minLength: 1, maxLength: 128, description: 'Nombre del servicio OTLP (resource attribute service.name)' },
            allowLoopback: { type: 'boolean', description: 'Permitir colector OTLP en loopback local (127.0.0.1/::1; metadatos cloud siempre bloqueados)' },
            timeoutMs: { type: 'integer', minimum: 200, maximum: 60000, description: 'Timeout HTTP del colector en milisegundos' }
          }
        }
      },

      // --- MCP 2026 Cycle-6: Shadow Traffic Replay, Whole-Stack Time-Machine & FinOps Savings (+3 -> 116) ---
      {
        name: 'culkibo_shadow_replay',
        title: 'Shadow Traffic Replay y puerta de cutover',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        outputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string' },
            projectId: { type: ['string', 'null'] },
            pass: { type: 'boolean' },
            verdict: { type: 'string' },
            blockers: { type: 'array' },
            summary: { type: 'object' },
            perRequest: { type: 'array' },
            replays: { type: 'array' },
            count: { type: 'number' }
          }
        },
        description: 'Reproduce peticiones HTTP de forma concurrente contra baseline (producción) y candidate (canary/green), compara paridad de status, regresiones 5xx, deriva estructural JSON y ratio p95, y devuelve el veredicto de cutover PROMOTE o BLOCK_CUTOVER (o consulta historial).',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['run', 'history'], description: 'Ejecutar replay comparativo ("run", default) o listar historial ("history")' },
            projectId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID de proyecto asociado (recomendado para ACL y trazabilidad)' },
            baselineUrl: { type: 'string', maxLength: 512, description: 'URL origen baseline/producción (ej. http://127.0.0.1:4000)' },
            candidateUrl: { type: 'string', maxLength: 512, description: 'URL origen candidate/canary (ej. http://127.0.0.1:4001)' },
            requests: {
              type: 'array',
              maxItems: 100,
              description: 'Peticiones HTTP a reproducir ([{ method, path, headers, body }])',
              items: { type: 'object' }
            },
            thresholds: {
              type: 'object',
              description: 'Umbrales del Promotion Gate ({ max5xxDelta, maxLatencyRatio, maxStatusMismatchPct, failOnSchemaDrift })'
            },
            gate: {
              type: 'object',
              description: 'Alias de thresholds para configurar el Promotion Gate'
            },
            allowLoopback: { type: 'boolean', description: 'Permitir destinos loopback locales (127.0.0.1/::1; metadatos cloud siempre bloqueados)' },
            timeoutMs: { type: 'integer', minimum: 200, maximum: 60000, description: 'Timeout HTTP por petición en ms' }
          }
        }
      },
      {
        name: 'culkibo_time_machine',
        title: 'Checkpoints Time-Machine de stack completo',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string' },
            projectId: { type: 'string' },
            dryRun: { type: 'boolean' },
            checkpoint: { type: 'object' },
            checkpoints: { type: 'array' },
            count: { type: 'number' },
            diff: { type: 'object' },
            restored: { type: 'boolean' },
            safetyCheckpointId: { type: ['string', 'null'] }
          }
        },
        description: 'Crea, lista, compara (diff estructural de imagen, claves env, dominios, crons y límites) o restaura atómicamente checkpoints Time-Machine de un stack completo. En action="restore", dryRun es true por defecto para exigir previsualización previa antes de aplicar.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['list', 'create', 'diff', 'restore'], description: 'Operación Time-Machine sobre el proyecto' },
            projectId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID del proyecto propietario del stack' },
            label: { type: 'string', maxLength: 120, description: 'Etiqueta descriptiva opcional al crear checkpoint (action="create")' },
            reason: { type: 'string', maxLength: 240, description: 'Motivo operativo opcional al crear checkpoint' },
            checkpointId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID del checkpoint objetivo para action="restore"' },
            fromId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID del checkpoint origen para action="diff"' },
            toId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID del checkpoint destino para action="diff"' }
          },
          required: ['action', 'projectId']
        }
      },
      {
        name: 'culkibo_finops_report',
        title: 'Informe FinOps de ahorro Cloud vs Self-Hosted',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string' },
            analysis: { type: 'object' },
            comparison: { type: 'object' },
            scopedProjectsCount: { type: 'number' }
          }
        },
        description: 'Analiza proyectos y bases de datos accesibles por RBAC para generar recomendaciones de right-sizing RAM/CPU, estimación mensual de VPS (Hetzner/DO/Vultr/OVH) y comparativa honesta de ahorro anual frente a Vercel Pro, Railway, Render y Managed Postgres.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['report', 'compare'], description: 'Analizar proyectos actuales ("report", default) o ejecutar calculadora pura ("compare")' },
            apps: { type: 'integer', minimum: 0, maximum: 500, description: 'Número de aplicaciones para comparativa pura (compareCloudCosts)' },
            databases: { type: 'integer', minimum: 0, maximum: 200, description: 'Número de bases de datos para comparativa pura' },
            avgRamMbPerApp: { type: 'integer', minimum: 64, maximum: 65536, description: 'RAM media estimada por app en MB (default 512)' },
            monthlyBandwidthGb: { type: 'number', minimum: 0, maximum: 1000000, description: 'Tráfico mensual saliente estimado en GB (default 250)' }
          }
        }
      },

      // --- MCP 2026 Cycle-7: Build Auto-Healer, WireGuard Fleet Mesh, Cron Timeline & Edge Bot-Shield (+4 -> 120) ---
      {
        name: 'culkibo_heal_build_failure',
        title: 'Diagnosticar y sanar fallos de build/runtime',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            projectId: { type: ['string', 'null'] },
            matched: { type: 'boolean' },
            dryRun: { type: 'boolean' },
            applied: { type: 'boolean' },
            diagnosis: { type: 'object' },
            healingPlan: { type: ['object', 'null'] }
          }
        },
        description: 'Clasifica logs fallidos de build o runtime contra 20 patrones deterministas (sin LLM: Node OOM, bind 127.0.0.1, log-driver mismatch kamal#1709, lockfile drift, pg_wal, musl/glibc, Exit 137, etc.) y planifica o aplica parches seguros de configuración (dryRun: true por defecto).',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID de proyecto opcional para vincular plan de remediación y control ACL' },
            logs: { type: 'string', minLength: 1, maxLength: 200000, description: 'Salida stderr/stdout del build o contenedor fallido' },
            apply: { type: 'boolean', description: 'Generar/aplicar plan de remediación sobre projectId (por defecto solo diagnostica; con dryRun: false aplica cambios seguros)' },
            code: { type: 'string', maxLength: 80, description: 'Código de patrón opcional para forzar una estrategia de curación concreta' }
          },
          required: ['logs']
        }
      },
      {
        name: 'culkibo_fleet_mesh',
        title: 'Gestionar malla WireGuard cero-configuración',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string' },
            dryRun: { type: 'boolean' },
            cidr: { type: 'string' },
            interfaceName: { type: 'string' },
            peerCount: { type: 'number' },
            peers: { type: 'array' },
            plan: { type: ['object', 'null'] },
            rotation: { type: ['object', 'null'] }
          }
        },
        description: 'Inspecciona, planifica (wg0.conf redactado + reglas UFW anti-bypass kamal#1856) o rota claves x25519 de la malla privada WireGuard 10.88.0.0/24 entre nodos de la flota (solo admin/owner; claves privadas cifradas AES-256-GCM y jamás devueltas; dryRun: true por defecto en rotate).',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['status', 'plan', 'rotate'], description: 'Operación sobre la malla WireGuard (default "status")' },
            nodeId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID del nodo cuya clave x25519 se rotará (requerido en action="rotate")' }
          }
        }
      },
      {
        name: 'culkibo_cron_timeline',
        title: 'Heatmap 24h de Crons y Heartbeats Dead-Man-Switch',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            hours: { type: 'number' },
            slots: { type: 'array' },
            collisionWarnings: { type: 'array' },
            heartbeats: { type: 'array' },
            heartbeatCount: { type: 'number' }
          }
        },
        description: 'Proyecta el mapa de calor de ejecuciones cron/backups para las próximas 1..168 horas detectando ventanas de colisión IO, junto con el estado de monitores Dead-Man-Switch Heartbeats acotados por ACL de proyectos.',
        inputSchema: {
          type: 'object',
          properties: {
            hours: { type: 'integer', minimum: 1, maximum: 168, description: 'Ventana de proyección en horas (default 24, máx 168)' },
            includeHeartbeats: { type: 'boolean', description: 'Incluir listado de monitores Dead-Man-Switch Heartbeats (default true)' }
          }
        }
      },
      {
        name: 'culkibo_edge_shield',
        title: 'Edge Bot-Shield y puerta Hashcash PoW',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string' },
            domain: { type: ['string', 'null'] },
            status: { type: ['object', 'null'] },
            routes: { type: 'array' },
            challenge: { type: ['object', 'null'] }
          }
        },
        description: 'Consulta estado del escudo anti-bots/AI-scrapers, compila subrutas nativas Caddy v2.11 sin plugins (bloqueo /.env, /.git, SQLi/XSS, UAs abusivos) o emite un reto SHA-256 Hashcash Proof-of-Work estilo Anubis.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['status', 'compile', 'challenge'], description: 'Acción sobre Edge Bot-Shield (default "status")' },
            domain: { type: 'string', maxLength: 253, description: 'Dominio objetivo para compilar subrutas o emitir reto PoW' },
            powChallenge: { type: 'boolean', description: 'Incluir puerta de redirección Hashcash PoW al compilar subrutas Caddy' },
            difficulty: { type: 'integer', minimum: 1, maximum: 6, description: 'Dificultad en ceros hexadecimales del reto SHA-256 PoW (default 4, rango 1..6)' }
          }
        }
      },

      // --- MCP 2026 Cycle-8: Autonomous Triage, SBOM CVE Drift, Config Drift + PgBouncer, IaC Export & Secret Leases (+5 -> 125) ---
      {
        name: 'culkibo_triage_playbook',
        title: 'Triaje autónomo unificado (incidente + healer + drift + CVE)',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string' },
            projectName: { type: 'string' },
            severity: { type: 'string' },
            summary: { type: 'string' },
            incident: { type: 'object' },
            healer: { type: ['object', 'null'] },
            drift: { type: ['object', 'null'] },
            cve: { type: ['object', 'null'] },
            rootCauses: { type: 'array' },
            remediationSteps: { type: 'array' }
          }
        },
        description: 'Encadena diagnóstico de incidentes, clasificación determinista de logs (20 patrones Build Healer), detección de drift de configuración (kamal#1790) y escaneo SBOM CVE offline en un único dossier priorizado con pasos dryRun seguros (estrictamente filtrado por ACL de proyecto).',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID del proyecto a diagnosticar (controlado por ACL)' },
            logs: { type: 'string', maxLength: 200000, description: 'Logs opcionales de build/runtime para clasificar con Build Auto-Healer' },
            actualInspect: { type: 'object', description: 'Objeto opcional tipo docker inspect para comparar config viva contra estado declarado' },
            includeCveScan: { type: 'boolean', description: 'Incluir resumen SBOM CVE offline/cacheado en el dossier (default true)' }
          },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_cve_scan',
        title: 'Escanear drift CVE del SBOM CycloneDX (OSV.dev)',
        annotations: { readOnlyHint: true, openWorldHint: true },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            mode: { type: 'string' },
            scannedComponents: { type: 'number' },
            vulnerableCount: { type: 'number' },
            severityCounts: { type: 'object' },
            vulnerabilities: { type: 'array' }
          }
        },
        description: 'Analiza el SBOM CycloneDX 1.6 en busca de CVEs conocidos vía API batch OSV.dev (24h caché local; por defecto allowNetwork: false para ejecución offline instantánea en MCP).',
        inputSchema: {
          type: 'object',
          properties: {
            allowNetwork: { type: 'boolean', description: 'Permitir consulta HTTP saliente a api.osv.dev/v1/querybatch (default false: modo offline/caché)' },
            forceRefresh: { type: 'boolean', description: 'Ignorar caché local de 24h cuando allowNetwork es true (default false)' }
          }
        }
      },
      {
        name: 'culkibo_drift_check',
        title: 'Detectar drift de contenedor/BD y preset PgBouncer',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            projectId: { type: ['string', 'null'] },
            drift: { type: ['object', 'null'] },
            pgbouncerPreset: { type: ['object', 'null'] }
          }
        },
        description: 'Compara el estado declarado de un proyecto contra un docker inspect vivo o aportado (digest de imagen, RAM/CPU, exposición 0.0.0.0, hash SHA-256 de nombres de claves env sin secretos, logDriver, stopTimeout — cura kamal#1790) y/o genera un preset gestionado PgBouncer listo para Prisma/Drizzle.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID del proyecto a auditar contra drift (controlado por ACL)' },
            actualInspect: { type: 'object', description: 'Payload docker inspect opcional para evaluación determinista offline' },
            pgbouncerPreset: {
              type: 'object',
              description: 'Parámetros opcionales para generar preset PgBouncer ({ name, databaseName, poolMode, maxPreparedStatements, defaultPoolSize })'
            }
          }
        }
      },
      {
        name: 'culkibo_export_iac',
        title: 'Exportar infraestructura a OpenTofu/Terraform y Compose',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            format: { type: 'string' },
            files: { type: 'object' },
            stats: { type: 'object' },
            secretsRedactedCount: { type: 'number' }
          }
        },
        description: 'Genera sin vendor lock-in bundles OpenTofu/Terraform 1.6+ (main.tf, variables.tf con sensitive=true, outputs.tf), docker-compose.yml portable y .env.example estrictamente acotados por ACL de proyectos y con CERO secretos en claro.',
        inputSchema: {
          type: 'object',
          properties: {
            format: { type: 'string', enum: ['all', 'terraform', 'compose'], description: 'Formato IaC a exportar (default "all")' },
            projectIds: {
              type: 'array',
              maxItems: 100,
              items: { type: 'string', minLength: 1, maxLength: 128 },
              description: 'Lista opcional de IDs de proyecto a incluir (validada contra ACL del llamante)'
            }
          }
        }
      },
      {
        name: 'culkibo_secret_lease',
        title: 'Gestionar leases efímeros de secretos y Break-Glass',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string' },
            dryRun: { type: 'boolean' },
            leases: { type: 'array' },
            lease: { type: ['object', 'null'] },
            audit: { type: ['object', 'null'] },
            revoked: { type: 'boolean' }
          }
        },
        description: 'Lista leases efímeros de secretos, audita antigüedad de rotación (>90 días sin leer valores), emite/revoca leases temporales o tokens Break-Glass auditados (máx. 15 min) con dryRun: true por defecto (solo admin/owner; resultados redactados en auditoría).',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['list', 'audit_rotation', 'issue', 'revoke', 'break_glass'], description: 'Operación sobre secret leases (default "list")' },
            projectId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID del proyecto asociado (para list/issue)' },
            secretKey: { type: 'string', minLength: 1, maxLength: 128, description: 'Nombre de la clave de secreto (requerido para action="issue")' },
            scope: { type: 'string', enum: ['read', 'write', 'admin'], description: 'Alcance del lease (default "read")' },
            leaseId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID del lease a revocar (requerido para action="revoke")' },
            ttlSec: { type: 'integer', minimum: 60, maximum: 86400, description: 'Duración en segundos (60..86400; break_glass acotado a <=900s)' },
            reason: { type: 'string', maxLength: 240, description: 'Justificación auditada (obligatoria >=10 chars para break_glass)' },
            maxAgeDays: { type: 'integer', minimum: 1, maximum: 3650, description: 'Umbral de antigüedad en días para audit_rotation (default 90)' },
            includeExpired: { type: 'boolean', description: 'Incluir leases caducados en action="list" (default false)' }
          }
        }
      },

      // --- MCP 2026 Cycle-9: Standard-Webhooks DLQ, Read-Only DB Studio, Post-MinIO S3, Agency Ledger & White-Label Brand (+5 = 130) ---
      {
        name: 'culkibo_webhook_dlq',
        title: 'Gestionar bus Standard-Webhooks, DLQ y rotación dual-secret',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
        outputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string' },
            dryRun: { type: 'boolean' },
            entries: { type: 'array' },
            subscriptions: { type: 'array' },
            count: { type: 'integer' },
            replayed: { type: 'boolean' },
            rotated: { type: 'boolean' }
          }
        },
        description: 'Inspecciona suscripciones Standard-Webhooks (sin secretos whsec_ en claro) y cola DLQ de entregas fallidas, o reintenta entregas (anti-SSRF en cada replay) y rota secretos duales con ventana de gracia (dryRun: true por defecto en replay/rotate_secret; resultados redactados en auditoría).',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['list_dlq', 'list_subscriptions', 'replay', 'rotate_secret'], description: 'Operación sobre Standard-Webhooks y DLQ (default "list_dlq")' },
            dlqId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID de entrada DLQ a reintentar (o "all" para reintentar todas las fallidas; requerido para action="replay")' },
            subscriptionId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID de suscripción para rotación dual-secret (requerido para action="rotate_secret")' },
            limit: { type: 'integer', minimum: 1, maximum: 200, description: 'Máximo de entradas DLQ a devolver (default 50)' },
            status: { type: 'string', maxLength: 32, description: 'Filtro opcional de estado DLQ (ej. failed, replayed)' },
            graceSec: { type: 'integer', minimum: 60, maximum: 604800, description: 'Ventana de gracia en segundos para el secreto secundario al rotar (default 86400)' }
          }
        }
      },
      {
        name: 'culkibo_db_studio',
        title: 'Ejecutar DB Studio solo lectura (SQL / Redis / Bloat)',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            mode: { type: 'string' },
            databaseId: { type: ['string', 'null'] },
            readOnlyEnforced: { type: 'boolean' },
            result: { type: 'object' }
          }
        },
        description: 'DB Studio sin sidecars y estrictamente de solo lectura: valida y envuelve SQL en BEGIN TRANSACTION READ ONLY + timeout 5s + LIMIT <=200 (bloqueando DDL/DML/CTEs mutadoras/psql metacommands), inspecciona Redis/Valkey con allowlist segura (bloquea KEYS/FLUSHALL/EVAL/CONFIG) o diagnostica table bloat de PostgreSQL (ACL estricto por proyecto/BD).',
        inputSchema: {
          type: 'object',
          properties: {
            databaseId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID de la base de datos gestionada (validado contra ACL del proyecto)' },
            mode: { type: 'string', enum: ['sql', 'redis', 'bloat'], description: 'Modo de inspección: sql, redis o bloat (default "sql")' },
            query: { type: 'string', minLength: 1, maxLength: 16384, description: 'Consulta SQL de solo lectura (SELECT/EXPLAIN/SHOW/WITH) para mode="sql"' },
            maxRows: { type: 'integer', minimum: 1, maximum: 200, description: 'Límite máximo de filas (1..200, default 200)' },
            argv: { description: 'Comando Redis/Valkey seguro como array de strings o cadena separada por espacios (ej. ["SCAN","0","COUNT","50"])' },
            tableStats: { type: 'array', maxItems: 500, description: 'Estadísticas de tablas/índices PostgreSQL para mode="bloat"' }
          }
        }
      },
      {
        name: 'culkibo_s3_storage',
        title: 'Orquestar S3 Post-MinIO (Garage/RustFS/SeaweedFS) y SigV4',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            presets: { type: 'array' },
            preset: { type: ['object', 'null'] },
            presigned: { type: ['object', 'null'] },
            xml: { type: ['string', 'null'] }
          }
        },
        description: 'Lista presets pineados 2026 Post-MinIO (Garage Rust CRDT, RustFS Apache-2.0, SeaweedFS) con red privada 127.0.0.1 por defecto, genera URLs prefirmadas AWS SigV4 (AWS4-HMAC-SHA256) en crypto puro sin deps y construye XML seguro de CORS (rechaza * + credentials) o Lifecycle (secretAccessKey y resultados siempre redactados en auditoría).',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['presets', 'presign', 'cors_xml', 'lifecycle_xml'], description: 'Operación S3 (default "presets")' },
            presetId: { type: 'string', enum: ['garage', 'rustfs', 'seaweedfs'], description: 'Preset concreto a consultar en action="presets"' },
            endpoint: { type: 'string', maxLength: 512, description: 'URL endpoint S3 (ej. https://s3.acme.internal) para action="presign"' },
            region: { type: 'string', maxLength: 64, description: 'Región SigV4 (default "us-east-1")' },
            bucket: { type: 'string', maxLength: 64, description: 'Nombre del bucket S3 RFC-compliant' },
            key: { type: 'string', maxLength: 1024, description: 'Clave de objeto S3 (sin traversal "..")' },
            method: { type: 'string', enum: ['GET', 'PUT', 'HEAD', 'DELETE'], description: 'Método HTTP para presign (default "GET")' },
            accessKeyId: { type: 'string', maxLength: 128, description: 'Access Key ID S3 para action="presign"' },
            secretAccessKey: { type: 'string', maxLength: 256, description: 'Secret Access Key S3 (redactada automáticamente en auditoría)' },
            expiresIn: { type: 'integer', minimum: 60, maximum: 604800, description: 'Validez de URL prefirmada en segundos (60..604800, default 900)' },
            rules: { type: 'array', maxItems: 100, description: 'Reglas para action="cors_xml" o action="lifecycle_xml"' }
          }
        }
      },
      {
        name: 'culkibo_agency_ledger',
        title: 'Consultar cuotas multi-tenant y ledger de facturación',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            ledger: { type: ['object', 'null'] },
            csv: { type: ['string', 'null'] },
            quotas: { type: 'array' },
            check: { type: ['object', 'null'] }
          }
        },
        description: 'Calcula el ledger de uso facturable por proyecto/cliente (CPU-hrs, RAM GB-hrs, almacenamiento, ancho de banda y coste estimado USD), exporta CSV neutralizado contra inyección de fórmulas (=,+,-,@), lista cuotas multi-tenant o evalúa límites fail-closed (ACL estricto por tenant/proyecto, cero fugas cross-tenant).',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['ledger', 'csv', 'list_quotas', 'check_quota'], description: 'Operación de cuotas/ledger (default "ledger")' },
            projectId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID de proyecto opcional (obligatorio para action="check_quota"; validado por ACL)' },
            periodDays: { type: 'integer', minimum: 1, maximum: 365, description: 'Ventana de facturación en días (1..365, default 30)' },
            requested: { type: 'object', description: 'Recursos solicitados para action="check_quota" ({ containers, memoryMb, cpuCores, storageGb, bandwidthGbMo })' }
          }
        }
      },
      {
        name: 'culkibo_brand_theme',
        title: 'Consultar o personalizar tema white-label de la instancia',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string' },
            dryRun: { type: 'boolean' },
            updated: { type: 'boolean' },
            brand: { type: 'object' }
          }
        },
        description: 'Lee la configuración de marca white-label open-core (permitido a cualquier rol autenticado) o actualiza/restablece marca, color acento hex, logo HTTPS/SVG sanitizado y tagline con validación estricta anti-XSS/CSS-injection (solo admin/owner; dryRun: true por defecto en update/reset).',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['get', 'update', 'reset'], description: 'Operación sobre marca white-label (default "get")' },
            patch: {
              type: 'object',
              description: 'Campos a actualizar en action="update" ({ brandName, tagline, accentHex, logoUrl, supportUrl, hidePoweredBy })'
            }
          }
        }
      },

      // --- MCP 2026 Cycle-10: DR Fire-Drill, SLO Canary Auto-Rollback, AI/GPU LLM, Remote Builder & Log Archive (+5 = 135) ---
      {
        name: 'culkibo_dr_drill',
        title: 'Ejecutar DR Fire-Drill de backups y planificar restore',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            verdict: { type: ['string', 'null'] },
            drill: { type: ['object', 'null'] },
            drills: { type: 'array' },
            restorePlan: { type: ['object', 'null'] }
          }
        },
        description: 'Audita backups reales mediante DR Fire-Drills (rechaza dumps vacíos 0B/20B gzip, checksum SHA-256 corrupto, detecta --no-acl en Supabase y registra scorecards RTO/RPO), lista drills históricos filtrados por ACL o planifica restauraciones cross-target (misma org permitida, cross-org bloqueada 403).',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['list_drills', 'run_drill', 'cross_restore_plan'], description: 'Operación DR Fire-Drill (default "list_drills")' },
            databaseId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID de base de datos objetivo (validado por ACL)' },
            projectId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID de proyecto asociado (validado por ACL)' },
            engine: { type: 'string', enum: ['postgres', 'mysql', 'sqlite'], description: 'Motor SQL del backup (default "postgres")' },
            sqlSample: { type: 'string', maxLength: 262144, description: 'Contenido SQL de muestra para verificación en memoria (para action="run_drill")' },
            artifactBase64: { type: 'string', maxLength: 524288, description: 'Payload .sql o .sql.gz codificado en base64 para action="run_drill"' },
            artifactPath: { type: 'string', maxLength: 512, description: 'Ruta opcional del artefacto de backup local' },
            expectedSha256: { type: 'string', maxLength: 128, description: 'Checksum SHA-256 esperado para verificar integridad' },
            preserveAcl: { type: 'boolean', description: 'Exigir preservación de ACL/GRANTs sin --no-acl (default true)' },
            sourceMajorVersion: { type: 'integer', minimum: 1, maximum: 99, description: 'Versión mayor origen para detectar downgrades' },
            targetMajorVersion: { type: 'integer', minimum: 1, maximum: 99, description: 'Versión mayor destino para detectar downgrades' },
            sourceDatabaseId: { type: 'string', minLength: 1, maxLength: 128, description: 'BD origen para action="cross_restore_plan"' },
            targetDatabaseId: { type: 'string', minLength: 1, maxLength: 128, description: 'BD destino para action="cross_restore_plan"' },
            sourceOrgId: { type: 'string', minLength: 1, maxLength: 128, description: 'Organización origen para action="cross_restore_plan"' },
            targetOrgId: { type: 'string', minLength: 1, maxLength: 128, description: 'Organización destino para action="cross_restore_plan"' }
          }
        }
      },
      {
        name: 'culkibo_slo_canary',
        title: 'Controlar despliegues SLO Canary con auto-rollback Caddy',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            dryRun: { type: 'boolean' },
            rollout: { type: ['object', 'null'] },
            rollouts: { type: 'array' },
            caddyRoute: { type: ['object', 'null'] }
          }
        },
        description: 'Orquesta canarios progresivos (10→25→50→100%) sobre Caddy v2.11 weighted_round_robin con Google SRE error-budget burn rate (>14.4x) y p95 latency gate: en cualquier brecha revierte al instante a 100/0 (ROLLED_BACK). Soporta dryRun: true por defecto en start y abort (ACL estricto por proyecto).',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['list', 'start', 'evaluate', 'abort'], description: 'Operación del controlador SLO Canary (default "list")' },
            projectId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID del proyecto (obligatorio para start; validado por ACL)' },
            rolloutId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID del rollout activo (obligatorio para evaluate/abort)' },
            hostname: { type: 'string', maxLength: 253, description: 'Dominio público del servicio para compilar ruta Caddy' },
            stableUpstream: { type: 'string', maxLength: 253, description: 'Upstream estable (ej. 127.0.0.1:4101)' },
            canaryUpstream: { type: 'string', maxLength: 253, description: 'Upstream canario (ej. 127.0.0.1:4102)' },
            steps: { type: 'array', maxItems: 10, items: { type: 'integer', minimum: 1, maximum: 100 }, description: 'Pasos de peso canario (default [10, 25, 50, 100])' },
            sloTarget: { type: 'number', minimum: 0.9, maximum: 0.99999, description: 'Objetivo SLO (default 0.999)' },
            maxBurnRate: { type: 'number', minimum: 1, maximum: 1000, description: 'Burn rate máximo tolerado antes de rollback (default 14.4)' },
            maxLatencyRatio: { type: 'number', minimum: 1.1, maximum: 20, description: 'Ratio máximo p95 canario/estable (default 2.0)' },
            totalRequests: { type: 'integer', minimum: 0, maximum: 100000000, description: 'Total de peticiones observadas en la ventana (para evaluate)' },
            error5xxCount: { type: 'integer', minimum: 0, maximum: 100000000, description: 'Total de errores 5xx en la ventana (para evaluate)' },
            baselineP95Ms: { type: 'number', minimum: 0, maximum: 600000, description: 'Latencia p95 estable en ms (para evaluate)' },
            canaryP95Ms: { type: 'number', minimum: 0, maximum: 600000, description: 'Latencia p95 canaria en ms (para evaluate)' },
            reason: { type: 'string', maxLength: 240, description: 'Motivo de aborto manual (para abort)' }
          }
        }
      },
      {
        name: 'culkibo_ai_workload',
        title: 'Planificar cargas AI/GPU y LLM locales (Ollama/vLLM/llama.cpp)',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            presets: { type: 'array' },
            vram: { type: ['object', 'null'] },
            security: { type: ['object', 'null'] },
            spec: { type: ['object', 'null'] }
          }
        },
        description: 'Calcula requisitos de VRAM y KV-cache para LLMs locales (Ollama, vLLM, llama.cpp), audita etiquetas vulnerables (Ollama CVE-2026-7482, vLLM CVE-2026-22778/137477) y compila especificaciones Docker con NVIDIA CDI (--device nvidia.com/gpu=all) o legacy (--gpus all), bloqueando fail-closed el overflow de VRAM y la exposición pública 0.0.0.0:11434 sin proxy Bearer (CVE-2025-63389).',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['presets', 'vram_estimate', 'plan', 'audit_image'], description: 'Operación AI/GPU (default "presets")' },
            runtime: { type: 'string', enum: ['ollama', 'vllm', 'llamacpp'], description: 'Motor LLM local (default "ollama")' },
            model: { type: 'string', maxLength: 160, description: 'Identificador del modelo (ej. llama3.2:8b, Qwen/Qwen2.5-14B-Instruct)' },
            imageTag: { type: 'string', maxLength: 200, description: 'Etiqueta Docker explícita para auditar o planificar' },
            paramsB: { type: 'number', minimum: 0.1, maximum: 1000, description: 'Miles de millones de parámetros del modelo (default 7)' },
            quantization: { type: 'string', enum: ['Q4_K_M', 'Q5_K_M', 'Q6_K', 'Q8_0', 'FP16', 'BF16', 'FP32'], description: 'Cuantización del modelo (default "Q4_K_M")' },
            contextLen: { type: 'integer', minimum: 256, maximum: 1048576, description: 'Longitud de contexto en tokens (default 8192)' },
            batchSize: { type: 'integer', minimum: 1, maximum: 256, description: 'Tamaño de lote concurrente (default 1)' },
            availableVramGb: { type: 'number', minimum: 1, maximum: 2048, description: 'VRAM GPU disponible en GB para comprobación fail-closed' },
            gpuMode: { type: 'string', enum: ['cdi', 'legacy', 'cpu'], description: 'Modo GPU Docker: cdi, legacy o cpu (default "cdi")' },
            bindAddress: { type: 'string', maxLength: 64, description: 'Dirección de escucha (default "127.0.0.1"; 0.0.0.0 sin authProxy se bloquea)' },
            authProxyEnabled: { type: 'boolean', description: 'Si el proxy Bearer de Caddy protege el endpoint (default true)' }
          }
        }
      },
      {
        name: 'culkibo_remote_builder',
        title: 'Orquestar nodos remotos de build y pinning SSH mux',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            dryRun: { type: 'boolean' },
            builders: { type: 'array' },
            builder: { type: ['object', 'null'] },
            lease: { type: ['object', 'null'] },
            muxStatus: { type: ['object', 'null'] },
            pruneArgs: { type: 'array' }
          }
        },
        description: 'Gestiona nodos remotos de compilación distribuida (colas de concurrencia independientes por nodo, offload de PR previews, protección SSH mux ref-count pinning para impedir cierres en mitad de builds y comandos buildx prune sin shell; solo admin/owner, dryRun: true por defecto en register y schedule).',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['list', 'register', 'schedule', 'can_recycle_mux', 'prune_plan'], description: 'Operación sobre remote builders (default "list")' },
            builderId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID del builder (para schedule/can_recycle_mux)' },
            name: { type: 'string', minLength: 1, maxLength: 120, description: 'Nombre del nodo builder (para register)' },
            host: { type: 'string', minLength: 1, maxLength: 253, description: 'Host/IP del nodo builder remoto (para register)' },
            arch: { type: 'string', enum: ['linux/amd64', 'linux/arm64'], description: 'Arquitectura destino (default "linux/amd64")' },
            maxConcurrency: { type: 'integer', minimum: 1, maximum: 64, description: 'Builds concurrentes máximos por builder (default 2)' },
            allowPreviews: { type: 'boolean', description: 'Permitir offload de PR previews en este builder (default true)' },
            isPreview: { type: 'boolean', description: 'Indica si el build a planificar es un PR preview (para schedule)' },
            projectId: { type: 'string', minLength: 1, maxLength: 128, description: 'Proyecto propietario del build (para schedule)' },
            keepStorageGb: { type: 'integer', minimum: 1, maximum: 2000, description: 'Almacenamiento caché BuildKit a conservar en GB (default 20)' }
          }
        }
      },
      {
        name: 'culkibo_log_archive_search',
        title: 'Buscar en archivo comprimido .ndjson.gz de logs persistentes',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            projectId: { type: ['string', 'null'] },
            stats: { type: ['object', 'null'] },
            search: { type: ['object', 'null'] }
          }
        },
        description: 'Consulta estadísticas o busca en archivos comprimidos .ndjson.gz persistentes que sobreviven a cada redespliegue, filtrando por fecha, nivel, releaseId, subcadena o regex con guardia estricta anti-ReDoS (rechaza cuantificadores anidados con UNSAFE_REGEX) y ACL estricto por proyecto.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['stats', 'search'], description: 'Operación sobre el archivo comprimido de logs (default "search")' },
            projectId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID del proyecto (obligatorio para search; validado estrictamente por ACL)' },
            since: { type: 'string', maxLength: 64, description: 'Fecha/ISO mínima opcional (ej. 2026-11-01)' },
            until: { type: 'string', maxLength: 64, description: 'Fecha/ISO máxima opcional' },
            level: { type: 'string', maxLength: 32, description: 'Nivel de log opcional (info, warn, error, fatal)' },
            releaseId: { type: 'string', maxLength: 128, description: 'ID de release concreto a filtrar' },
            query: { type: 'string', maxLength: 256, description: 'Subcadena case-insensitive a buscar' },
            regex: { type: 'string', maxLength: 120, description: 'Expresión regular validada contra ReDoS (máx. 120 chars)' },
            limit: { type: 'integer', minimum: 1, maximum: 500, description: 'Máximo de entradas devueltas (default 200)' }
          }
        }
      },

      // --- MCP 2026 Cycle-11: Policy-as-Code Admission, Ed25519 Compliance, Volume Migration, Edge Geo/A-B & Security Posture (+5 = 140) ---
      {
        name: 'culkibo_admission_check',
        title: 'Evaluar y configurar Policy-as-Code Admission (10 reglas CIS/PSS)',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            dryRun: { type: 'boolean' },
            policy: { type: ['object', 'null'] },
            evaluation: { type: ['object', 'null'] }
          }
        },
        description: 'Motor declarativo Policy-as-Code (Kyverno/OPA-lite) con 10 reglas CIS/PSS (bloquea - /:/host:rw, docker.sock, privileged, SYS_ADMIN, :latest, UID 0 y bindings públicos 0.0.0.0:3000/5432). Permite get_policy y evaluate a developer/admin; apply_preset (baseline|restricted|soc2-strict) exige admin y corre en dryRun: true por defecto.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['get_policy', 'evaluate', 'apply_preset'], description: 'Operación sobre políticas de admisión (default "evaluate")' },
            preset: { type: 'string', enum: ['baseline', 'restricted', 'soc2-strict'], description: 'Preset de política a evaluar o aplicar' },
            spec: { type: 'object', description: 'Especificación de despliegue a evaluar en action="evaluate" ({ image, privileged, mounts, capAdd, uid, user, memoryLimitMb, cpuLimit, healthcheck, healthcheckPath, attestationVerified, ports, bindAddress })' }
          }
        }
      },
      {
        name: 'culkibo_compliance_bundle',
        title: 'Generar y verificar Compliance Bundle Ed25519 (SOC2/ISO27001/GDPR)',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            bundle: { type: ['object', 'null'] },
            verification: { type: ['object', 'null'] }
          }
        },
        description: 'Genera o verifica criptográficamente un expediente de evidencia SOC 2 / ISO 27001 / GDPR firmado con Ed25519 (JSON canónico + SHA-256 + reporte Markdown, 0 secretos en claro y 0 claves privadas expuestas; solo admin/owner, redactado en auditoría).',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['generate', 'verify', 'latest'], description: 'Operación de compliance bundle (default "generate")' },
            framework: { type: 'string', enum: ['all', 'soc2', 'iso27001', 'gdpr'], description: 'Marco normativo objetivo (default "all")' },
            snapshot: { type: 'object', description: 'Snapshot agregado opcional para generación determinista' },
            bundle: { type: 'object', description: 'Bundle firmado a verificar criptográficamente en action="verify"' }
          }
        }
      },
      {
        name: 'culkibo_volume_migrate',
        title: 'Planificar migración stateful de volúmenes entre VPS (4 fases)',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            migrations: { type: 'array' },
            migration: { type: ['object', 'null'] }
          }
        },
        description: 'Planifica migraciones stateful cross-VPS en 4 fases sin shell (Pre-Sync → Quiesce + tar --numeric-owner + SHA-256 → SSH ControlMaster → Verificación UID/checksum), curando Coolify CVE-2025-66213 (inyección de nombre de volumen) y errores 999:999 de Postgres (ACL estricto por proyecto).',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['list', 'plan'], description: 'Operación sobre migraciones de volumen (default "list")' },
            projectId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID del proyecto propietario (obligatorio para plan; validado por ACL)' },
            volumeName: { type: 'string', minLength: 1, maxLength: 128, description: 'Nombre seguro del volumen Docker (sin metacaracteres shell)' },
            mountPath: { type: 'string', minLength: 1, maxLength: 256, description: 'Ruta de montaje del volumen dentro del contenedor (sin .. ni raíces host)' },
            sourceHost: { type: 'string', maxLength: 253, description: 'Nodo origen (default "local")' },
            targetHost: { type: 'string', maxLength: 253, description: 'Nodo VPS destino (debe diferir de sourceHost)' },
            uid: { type: 'integer', minimum: 0, maximum: 65534, description: 'UID numérico a preservar con --numeric-owner (default 999)' },
            gid: { type: 'integer', minimum: 0, maximum: 65534, description: 'GID numérico a preservar con --numeric-owner (default 999)' },
            containerName: { type: 'string', maxLength: 128, description: 'Contenedor a pausar brevemente en fase 2' },
            estimatedMb: { type: 'number', minimum: 1, maximum: 1048576, description: 'Tamaño estimado del volumen en MB (default 256)' },
            sourceOrgId: { type: 'string', maxLength: 128, description: 'ID de organización origen para validación cross-tenant' },
            targetOrgId: { type: 'string', maxLength: 128, description: 'ID de organización destino para validación cross-tenant' }
          }
        }
      },
      {
        name: 'culkibo_edge_experiment',
        title: 'Orquestar Geo-Routing y experimentos A/B sticky en Caddy v2.11',
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            dryRun: { type: 'boolean' },
            experiments: { type: 'array' },
            experiment: { type: ['object', 'null'] },
            compiledRoutes: { type: ['object', 'array', 'null'] }
          }
        },
        description: 'Compila y gestiona enrutado Geo-IP por país ISO-3166 (CF-IPCountry/X-Country) y splits A/B sticky (cookie/header + weighted_round_robin con pesos sumando 100) directamente en Caddy v2.11 sin plugins, incluyendo kill-switch 1-clic a 100% control (dryRun: true por defecto en upsert y kill_switch; ACL estricto por proyecto).',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['list', 'upsert', 'compile', 'kill_switch'], description: 'Operación sobre experimentos Edge (default "list")' },
            experimentId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID del experimento (obligatorio para kill_switch)' },
            projectId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID del proyecto (obligatorio para upsert; validado por ACL)' },
            hostname: { type: 'string', maxLength: 253, description: 'Dominio público del experimento' },
            kind: { type: 'string', enum: ['ab', 'geo'], description: 'Tipo de compilación: "ab" o "geo" (default "ab")' },
            stickyMode: { type: 'string', enum: ['cookie', 'header', 'weighted'], description: 'Modo de afinidad A/B (default "cookie")' },
            cookieName: { type: 'string', maxLength: 64, description: 'Nombre de cookie sticky (ej. ckb_ab_checkout)' },
            headerField: { type: 'string', maxLength: 64, description: 'Cabecera para stickyMode="header" (default "X-AB-Group")' },
            headerName: { type: 'string', enum: ['CF-IPCountry', 'X-Country'], description: 'Cabecera Geo-IP para kind="geo" (default "CF-IPCountry")' },
            variants: { type: 'array', maxItems: 10, description: 'Variantes A/B [{ name, upstream, weight }] cuyos pesos deben sumar 100' },
            regions: { type: 'array', maxItems: 20, description: 'Regiones Geo-IP [{ countries: ["DE","FR"], upstream }]' },
            defaultUpstream: { type: 'string', maxLength: 253, description: 'Upstream fallback por defecto para kind="geo"' },
            reason: { type: 'string', maxLength: 240, description: 'Motivo operativo para action="kill_switch"' }
          }
        }
      },
      {
        name: 'culkibo_security_posture',
        title: 'Consultar scorecard ejecutivo de postura de seguridad y gobernanza',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            generatedAt: { type: 'string' },
            postureScore: { type: 'number' },
            grade: { type: 'string' },
            pillars: { type: 'object' }
          }
        },
        description: 'Scorecard ejecutivo unificado de solo lectura que agrega en una sola llamada el preset Policy-as-Code Admission, último Compliance Bundle Ed25519, resumen SBOM CVE Drift, rotación de secretos (>90 días) y tasa de éxito de DR Fire-Drills (sin secretos en claro; respetando RBAC/ACL).',
        inputSchema: {
          type: 'object',
          properties: {
            maxSecretAgeDays: { type: 'integer', minimum: 1, maximum: 3650, description: 'Umbral en días para secretos obsoletos (default 90)' }
          }
        }
      },

      // --- MCP 2026 Cycle-12: Synthetic API/TLS Sentinel, SQL DDL Linter, Worker Autoscaler, SPDX License Auditor & Seccomp/runc (+5 = 145) ---
      {
        name: 'culkibo_synthetic_sentinel',
        title: 'Ejecutar flujos sintéticos multi-paso y sonda TLS/SNI',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            dryRun: { type: 'boolean' },
            flows: { type: 'array' },
            flow: { type: ['object', 'null'] },
            run: { type: ['object', 'null'] },
            tls: { type: ['object', 'null'] }
          }
        },
        description: 'Gestiona y ejecuta flujos HTTP sintéticos encadenados (1..5 pasos con extracción JSONPath sin persistir secretos) y sondas TLS/SNI sin caché (caducidad, SAN wildcard, deriva de issuer/huella SHA-256). Fuerza allowLoopback: false y guardia SSRF en cada paso; save_flow exige admin y corre en dryRun: true por defecto (resultados redactados en auditoría).',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['list_flows', 'save_flow', 'run_flow', 'check_tls'], description: 'Operación del centinela sintético/TLS (default "list_flows")' },
            flowId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID de flujo guardado para action="run_flow"' },
            flow: { type: 'object', description: 'Definición del flujo ({ id?, name, steps: [{ name, method, url, headers?, body?, extract?, assert? }] })' },
            host: { type: 'string', maxLength: 253, description: 'Host objetivo para action="check_tls"' },
            port: { type: 'integer', minimum: 1, maximum: 65535, description: 'Puerto TLS (default 443)' },
            servername: { type: 'string', maxLength: 253, description: 'SNI servername opcional' },
            expectedSan: { type: 'string', maxLength: 253, description: 'SAN esperado para validar coincidencia de certificado' },
            baselineFingerprintSha256: { type: 'string', maxLength: 128, description: 'Huella SHA-256 previa para detectar deriva' },
            baselineIssuer: { type: 'string', maxLength: 256, description: 'Emisor CA previo para detectar deriva de CA' },
            warnDays: { type: 'integer', minimum: 1, maximum: 365, description: 'Días de aviso de caducidad TLS (default 14)' },
            critDays: { type: 'integer', minimum: 0, maximum: 90, description: 'Días críticos de caducidad TLS (default 3)' }
          }
        }
      },
      {
        name: 'culkibo_lint_sql_migration',
        title: 'Auditar migraciones SQL zero-downtime (10 reglas DDL)',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            safe: { type: 'boolean' },
            score: { type: 'number' },
            blockers: { type: 'array' },
            warnings: { type: 'array' },
            rewriteHints: { type: 'array' },
            analyzedStatements: { type: 'integer' }
          }
        },
        description: 'Linter estático SQL DDL (estilo Squawk / Strong Migrations sin deps) que detecta 10 fallos de bloqueo en producción (CREATE/DROP INDEX sin CONCURRENTLY, falta de lock_timeout, FK/CHECK sin NOT VALID, DROP COLUMN/TABLE, ALTER COLUMN TYPE, SET NOT NULL directo, defaults volátiles) devolviendo puntuación y sugerencias expand-contract.',
        inputSchema: {
          type: 'object',
          properties: {
            sql: { type: 'string', minLength: 1, maxLength: 262144, description: 'Script SQL DDL de migración a analizar' }
          },
          required: ['sql']
        }
      },
      {
        name: 'culkibo_worker_autoscaler',
        title: 'Evaluar y configurar autoscaler de workers OOM-safe (KEDA)',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            dryRun: { type: 'boolean' },
            projectId: { type: 'string' },
            policy: { type: ['object', 'null'] },
            decision: { type: ['object', 'null'] }
          }
        },
        description: 'Gestiona políticas de autoescalado de colas/workers con bandas de histéresis, cooldowns anti-flapping, techo estricto de RAM del VPS (maxSafeReplicas anti-OOM) y circuit breaker 503 Retry-After (ACL estricto por proyecto; set_policy corre en dryRun: true por defecto).',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['get_policy', 'evaluate', 'set_policy'], description: 'Operación del autoscaler (default "get_policy")' },
            projectId: { type: 'string', minLength: 1, maxLength: 128, description: 'ID del proyecto (obligatorio; validado estrictamente por ACL)' },
            policy: { type: 'object', description: 'Parche de política para action="set_policy" ({ minReplicas, maxReplicas, targetQueueDepth, reserveHostRamMb, perReplicaRamMb, scaleUpCooldownSec, scaleDownCooldownSec, breakerQueueThreshold, breakerRetryAfterSec })' },
            queueDepth: { type: 'integer', minimum: 0, maximum: 10000000, description: 'Profundidad actual de cola para action="evaluate"' },
            httpSaturationPct: { type: 'number', minimum: 0, maximum: 100, description: 'Saturación HTTP (%) actual para action="evaluate"' },
            currentReplicas: { type: 'integer', minimum: 0, maximum: 500, description: 'Réplicas actuales del worker (default 1)' },
            hostFreeRamMb: { type: 'number', minimum: 0, maximum: 1048576, description: 'RAM libre del host VPS en MB (para cálculo OOM-safe maxSafeReplicas)' },
            perReplicaRamMb: { type: 'number', minimum: 32, maximum: 131072, description: 'RAM estimada por réplica en MB' },
            lastScaleAtMs: { type: 'number', minimum: 0, description: 'Timestamp epoch ms del último escalado (para evaluar cooldown)' }
          },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_audit_licenses',
        title: 'Auditar licencias SPDX en CycloneDX 1.6 / lockfile',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            compliant: { type: 'boolean' },
            policy: { type: 'string' },
            score: { type: 'number' },
            totalComponents: { type: 'integer' },
            countsByCategory: { type: 'object' },
            violations: { type: 'array' },
            warnings: { type: 'array' }
          }
        },
        description: 'Audita expresiones SPDX compuestas (AND/OR) y LicenseRef-* sobre CycloneDX 1.6 o el lockfile del proyecto para detectar licencias AGPL, GPL, SSPL, BSL o desconocidas bajo políticas saas-strict, oss-permissive o audit-only.',
        inputSchema: {
          type: 'object',
          properties: {
            policy: { type: 'string', enum: ['saas-strict', 'oss-permissive', 'audit-only'], description: 'Política de cumplimiento SPDX (default "saas-strict")' },
            sbom: { type: 'object', description: 'Documento CycloneDX 1.6 opcional a auditar en memoria' }
          }
        }
      },
      {
        name: 'culkibo_seccomp_profile',
        title: 'Generar perfiles OCI seccomp mínimos y auditar CVEs de runc',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            generated: { type: ['object', 'null'] },
            validation: { type: ['object', 'null'] },
            runcAudit: { type: ['object', 'null'] }
          }
        },
        description: 'Genera perfiles OCI seccomp.json de mínimo privilegio (SCMP_ACT_ERRNO bloqueando io_uring/ptrace/mount/bpf/unshare) por stack (node, python, go, rust, static-caddy; prohíbe unconfined), valida especificaciones existentes o audita versiones de runc contra CVE-2025-31133, CVE-2025-52565 y CVE-2025-52881.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['generate', 'validate', 'audit_runc'], description: 'Operación seccomp/runc (default "generate")' },
            stack: { type: 'string', maxLength: 64, description: 'Stack destino (node|python|go|rust|static-caddy; "unconfined" bloqueado)' },
            mode: { type: 'string', maxLength: 64, description: 'Modo opcional ("unconfined" bloqueado con SECCOMP_UNCONFINED_FORBIDDEN)' },
            spec: { description: 'Especificación seccomp (objeto OCI JSON o cadena) a validar en action="validate"' },
            version: { type: 'string', maxLength: 160, description: 'Salida o semver de `runc --version` para action="audit_runc"' }
          }
        }
      },
      // --- MCP 2026 Cycle-13 (150 MCP Tools Milestone!): Image Bloat/Secrets, Cron Leases, PII Masker, OOM Forensics & On-Call Router (+5 = 150) ---
      {
        name: 'culkibo_audit_image_bloat',
        title: 'Auditar bloat de capas OCI y secretos en Dockerfile',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            efficiencyScore: { type: 'number' },
            estimatedSavingsMb: { type: 'number' },
            wastedBytes: { type: 'number' },
            secretLeaks: { type: 'array' },
            findings: { type: 'array' },
            slimmingRecommendations: { type: 'array' },
            multiStageTemplate: { type: 'string' }
          }
        },
        description: 'Audita Dockerfiles y capas OCI (8 reglas estilo Dive/Dockle/Hadolint) para detectar secretos horneados en ENV/ARG/.npmrc (coolify#7019/#5328), borrados cross-layer, caché apt/apk/pip, bases pesadas y falta de multi-stage/non-root, redactando siempre los secretos detectados.',
        inputSchema: {
          type: 'object',
          properties: {
            dockerfile: { type: 'string', maxLength: 100000, description: 'Contenido textual del Dockerfile a auditar' },
            historyLayers: { type: 'array', description: 'Lista opcional de capas `docker history` ({ createdBy, sizeBytes })' },
            stack: { type: 'string', enum: ['node', 'python', 'go', 'rust'], description: 'Stack para la plantilla multi-stage recomendada (default "node")' }
          }
        }
      },
      {
        name: 'culkibo_cron_lease',
        title: 'Gestionar leases distribuidos con fencing tokens para Crons',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            dryRun: { type: 'boolean' },
            leases: { type: 'array' },
            result: { type: ['object', 'null'] }
          }
        },
        description: 'Coordina leases atómicos con fencing tokens monotónicos para Crons distribuidos (cura coolify#5655 y dokploy#1475): bloquea ejecuciones concurrentes (ALREADY_RUNNING) y repeticiones del mismo slot horario (ALREADY_EXECUTED_SLOT). Mutaciones usan dryRun: true por defecto.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['list', 'acquire', 'renew', 'complete'], description: 'Operación de lease distribuido (default "list")' },
            jobId: { type: 'string', maxLength: 128, description: 'ID del cron job' },
            scheduleSlotIso: { type: 'string', maxLength: 64, description: 'Slot horario ISO para idempotencia (ej. 2026-11-27T00:00:00Z)' },
            holderId: { type: 'string', maxLength: 128, description: 'Identificador del worker/réplica que solicita el lease' },
            leaseId: { type: 'string', maxLength: 128, description: 'ID del lease (requerido en renew/complete)' },
            fencingToken: { type: 'integer', minimum: 1, description: 'Fencing token monotónico (requerido en complete)' },
            ttlSec: { type: 'integer', minimum: 5, maximum: 86400, description: 'TTL del lease en segundos (default 300)' },
            extendSec: { type: 'integer', minimum: 5, maximum: 86400, description: 'Segundos de extensión para renew (default 300)' },
            status: { type: 'string', enum: ['succeeded', 'failed'], description: 'Estado de cierre en complete (default "succeeded")' },
            nowMs: { type: 'number', minimum: 0, description: 'Timestamp epoch ms opcional para evaluación determinista' },
            dryRun: { type: 'boolean', description: 'En acquire/renew/complete es true por defecto; pasa dryRun: false para aplicar.' }
          }
        }
      },
      {
        name: 'culkibo_mask_preview_pii',
        title: 'Enmascarar PII determinísticamente para bases de datos PR-Preview',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            maskedRows: { type: ['array', 'null'] },
            maskedSql: { type: ['string', 'null'] },
            maskedCount: { type: 'integer' },
            fieldsMasked: { type: 'array' },
            zeroPiiLeaked: { type: 'boolean' },
            pgAnonDdl: { type: 'string' }
          }
        },
        description: 'Motor Post-Snaplet/Post-Neosync de seudonimización determinista HMAC-SHA256 (misma semilla preserva joins FK) sobre filas JSON o dumps SQL: enmascara emails, teléfonos, SSN, tarjetas Luhn-safe, IBAN, IPs y tokens JWT/API sin persistir PII raw, y emite DDL compatible con pg_anonymizer.',
        inputSchema: {
          type: 'object',
          properties: {
            rows: { type: 'array', description: 'Array de filas JSON a enmascarar en memoria' },
            sqlDump: { type: 'string', maxLength: 200000, description: 'Fragmento o dump SQL a enmascarar' },
            seed: { type: 'string', maxLength: 128, description: 'Semilla determinista HMAC-SHA256 (default "culkibo-preview-seed")' },
            rules: { type: 'object', description: 'Reglas explícitas por columna (hash_email | fake_name | redact | nullify | preserve)' },
            autoDetect: { type: 'boolean', description: 'Activar autodetección de patrones PII (default true)' }
          }
        }
      },
      {
        name: 'culkibo_oom_forensics',
        title: 'Clasificar OOM-Kills, Exit Codes y Crash-Loops de contenedores',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            projectId: { type: 'string' },
            classification: { type: 'string' },
            severity: { type: 'string' },
            confidence: { type: 'number' },
            rootCause: { type: 'string' },
            ignoreForRollback: { type: 'boolean' },
            recommendedMemoryMb: { type: ['number', 'null'] },
            backoffSec: { type: 'number' },
            remediationActions: { type: 'array' }
          }
        },
        description: 'Clasificador forense de 8 clases para fallos de contenedores (CGROUP_OOM_KILL 137+oomKilled vs FORCED_SIGKILL_TIMEOUT 137+!oomKilled, SEGFAULT 139, ABORT 134, SIGTERM 143, EXEC 126/127, HEALTHCHECK_CRASH_LOOP y STALE_HISTORICAL_TASK_IGNORED) con recomendación de RAM y ACL estricto por proyecto.',
        inputSchema: {
          type: 'object',
          properties: {
            projectId: { type: 'string', maxLength: 128, description: 'ID del proyecto propietario del contenedor (ACL estricto)' },
            containerName: { type: 'string', maxLength: 128, description: 'Nombre del contenedor opcional' },
            exitCode: { type: 'integer', minimum: 0, maximum: 255, description: 'Código de salida del contenedor (ej. 137, 139, 134, 143, 127)' },
            oomKilled: { type: 'boolean', description: 'Flag Docker State.OOMKilled' },
            restartCount: { type: 'integer', minimum: 0, maximum: 10000, description: 'Número de reinicios consecutivos' },
            memoryLimitMb: { type: 'number', minimum: 0, maximum: 1048576, description: 'Límite actual de memoria del contenedor en MB' },
            memoryPeakMb: { type: 'number', minimum: 0, maximum: 1048576, description: 'Pico de memoria observado en MB' },
            cgroupOomKills: { type: 'integer', minimum: 0, description: 'Contador cgroups memory.events oom_kill' },
            recentLogs: { type: 'string', maxLength: 50000, description: 'Últimas líneas de logs del contenedor' },
            healthStatus: { type: 'string', maxLength: 32, description: 'Estado de healthcheck (healthy | unhealthy | starting)' },
            uptimeSec: { type: 'number', minimum: 0, description: 'Segundos vivo antes de salir' },
            historicalOnly: { type: 'boolean', description: 'True si pertenece a una tarea histórica/antigua (marca ignoreForRollback: true)' }
          },
          required: ['projectId', 'exitCode']
        }
      },
      {
        name: 'culkibo_oncall_router',
        title: 'Deduplicar incidentes, amortiguar flapping y escalar On-Call',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            dryRun: { type: 'boolean' },
            policies: { type: 'array' },
            incidents: { type: 'array' },
            result: { type: ['object', 'array', 'null'] }
          }
        },
        description: 'Enrutador On-Call estilo GoAlert/Keep (cura uptime-kuma#3255): deduplica alertas por fingerprint, suprime flapping (>=3 transiciones), rota guardias y escala Tier 1→2→3 tras ackTimeoutSec. save_policy exige admin; mutaciones usan dryRun: true por defecto.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['list_policies', 'list_incidents', 'resolve_oncall', 'save_policy', 'ingest_alert', 'ack_incident', 'evaluate_escalations'], description: 'Operación On-Call (default "list_incidents")' },
            policyId: { type: 'string', maxLength: 128, description: 'ID de política de escalado' },
            policy: { type: 'object', description: 'Definición de política (name, shiftDurationHours, ackTimeoutSec, flappingWindowSec, flappingThreshold, tiers[]) para save_policy' },
            fingerprint: { type: 'string', maxLength: 200, description: 'Huella de deduplicación de la alerta' },
            projectId: { type: 'string', maxLength: 128, description: 'ID de proyecto asociado opcional' },
            severity: { type: 'string', enum: ['info', 'warning', 'high', 'critical'], description: 'Severidad de la alerta (default "critical")' },
            title: { type: 'string', maxLength: 240, description: 'Título de la alerta para ingest_alert' },
            state: { type: 'string', enum: ['firing', 'resolved'], description: 'Estado de la alerta (default "firing")' },
            incidentId: { type: 'string', maxLength: 128, description: 'ID del incidente para ack_incident' },
            actor: { type: 'string', maxLength: 128, description: 'Actor que reconoce el incidente en ack_incident' },
            activeOnly: { type: 'boolean', description: 'Filtrar solo incidentes activos en list_incidents' },
            nowMs: { type: 'number', minimum: 0, description: 'Timestamp epoch ms opcional para evaluación determinista' },
            dryRun: { type: 'boolean', description: 'En acciones mutadoras es true por defecto; pasa dryRun: false para aplicar.' }
          }
        }
      },
      // --- MCP 2026 Cycle-14 (155 MCP Tools!): Egress/nftables, Replica Fencing, Secret Gate, Multi-Arch & Chaos GameDay (+5 = 155) ---
      {
        name: 'culkibo_egress_firewall',
        title: 'Auditar egress de contenedores y drift DOCKER-USER/nftables',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            dryRun: { type: 'boolean' },
            projectId: { type: 'string' },
            policy: { type: ['object', 'null'] },
            audit: { type: ['object', 'null'] }
          }
        },
        description: 'Gestiona políticas de egress por proyecto y audita sockets salientes / reglas DOCKER-USER y nftables (coolify#12336, dokploy#2486, Docker 29): bloquea metadatos cloud (169.254.169.254) y LAN privada preservando puertos anti-lockout (22/80/443). save_policy exige admin y dryRun: true por defecto.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['get_policy', 'save_policy', 'audit'], description: 'Operación de egress/firewall (default "get_policy")' },
            projectId: { type: 'string', maxLength: 128, description: 'ID del proyecto objetivo (ACL estricto)' },
            policy: { type: 'object', description: 'Política de egress (mode, allowedCidrs, allowedDomains, blockMetadata, blockPrivateLan, preserveAdminPorts)' },
            observedSockets: { type: 'array', description: 'Lista de sockets/destinos salientes observados para action="audit"' },
            firewallRules: { type: 'array', description: 'Reglas/cadenas firewall actuales del host para detectar drift' },
            backend: { type: 'string', enum: ['nftables', 'iptables'], description: 'Backend de firewall del host (default "nftables")' },
            dryRun: { type: 'boolean', description: 'En save_policy es true por defecto; pasa dryRun: false para persistir.' }
          },
          required: ['projectId']
        }
      },
      {
        name: 'culkibo_replica_failover',
        title: 'Orquestar failover Blue/Green de réplicas DB con fencing anti split-brain',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            dryRun: { type: 'boolean' },
            dbId: { type: 'string' },
            topology: { type: ['object', 'null'] },
            split: { type: ['object', 'null'] },
            promotion: { type: ['object', 'null'] }
          }
        },
        description: 'Gestiona topologías primary + read-replicas (cloudnative-pg#8701/#7407, patroni#3474): excluye réplicas con lag del pool de lectura y bloquea promociones con lag excesivo (REPLICA_LAG_TOO_HIGH) o primary sin fencing (OLD_PRIMARY_NOT_FENCED). save_topology/promote exigen admin y dryRun: true por defecto.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['get_topology', 'save_topology', 'evaluate_split', 'promote'], description: 'Operación de failover/réplicas (default "get_topology")' },
            dbId: { type: 'string', maxLength: 128, description: 'ID de la base de datos gestionada' },
            primary: { type: 'object', description: 'Descriptor del nodo primary para save_topology' },
            replicas: { type: 'array', description: 'Lista de réplicas de lectura para save_topology' },
            maxReadLagMs: { type: 'number', minimum: 0, maximum: 600000, description: 'Lag máximo permitido en ms para evaluate_split (default 500)' },
            targetReplicaId: { type: 'string', maxLength: 128, description: 'ID de la réplica candidata a promover' },
            maxAcceptableLagBytes: { type: 'number', minimum: 0, description: 'Lag máximo aceptable en bytes para promote (default 1048576)' },
            requireOldPrimaryFenced: { type: 'boolean', description: 'Exigir que el primary antiguo esté fenced antes de promover (default true)' },
            dryRun: { type: 'boolean', description: 'En save_topology y promote es true por defecto; pasa dryRun: false para aplicar.' }
          },
          required: ['dbId']
        }
      },
      {
        name: 'culkibo_secret_gate',
        title: 'Ejecutar puerta pre-despliegue de secretos por entropía de Shannon y 12 reglas',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            allowed: { type: 'boolean' },
            mode: { type: 'string' },
            scannedItems: { type: 'integer' },
            blockedCount: { type: 'integer' },
            findings: { type: 'array' }
          }
        },
        description: 'Escáner shift-left estilo Gitleaks/TruffleHog (12 reglas + entropía de Shannon >=4.2) sobre ficheros, diffs y mapas .env ignorando UUIDs/SHA-256 benignos y pragmas # culkibo:allow-secret. Nunca devuelve ni registra valores secretos en claro (solo preview redactado + fingerprintSha256).',
        inputSchema: {
          type: 'object',
          properties: {
            files: { type: 'array', description: 'Lista de archivos ({ path, content }) a escanear' },
            diffText: { type: 'string', maxLength: 200000, description: 'Texto git diff o snippet a escanear' },
            envMap: { type: 'object', description: 'Mapa clave/valor de variables .env a auditar' },
            mode: { type: 'string', enum: ['enforce', 'warn'], description: 'Modo de puerta: enforce (bloquea si hay hallazgos) o warn (default "enforce")' },
            allowlistFingerprints: { type: 'array', items: { type: 'string' }, description: 'Lista opcional de fingerprintSha256 explícitamente permitidos' }
          }
        }
      },
      {
        name: 'culkibo_multiarch_planner',
        title: 'Verificar compatibilidad OCI amd64/arm64 y planificar matriz nativa',
        annotations: { readOnlyHint: true, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            verification: { type: ['object', 'null'] },
            plan: { type: ['object', 'null'] }
          }
        },
        description: 'Detecta incompatibilidades de arquitectura antes de desplegar (EXEC_FORMAT_MISMATCH arm64 vs amd64), valida registros OCI estrictos con atestaciones y planifica matrices multi-arch priorizando builders nativos sobre QEMU con argv zero-shell.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['verify', 'plan'], description: 'Operación multi-arch (default "verify")' },
            imageArch: { type: 'string', maxLength: 32, description: 'Arquitectura de la imagen (amd64 | arm64 | x86_64 | aarch64)' },
            imageOs: { type: 'string', maxLength: 32, description: 'SO de la imagen (default "linux")' },
            manifestPlatforms: { type: 'array', items: { type: 'string' }, description: 'Lista de plataformas del manifest OCI (ej. ["linux/amd64", "linux/arm64"])' },
            hostArch: { type: 'string', maxLength: 32, description: 'Arquitectura del host destino' },
            strictOciRegistry: { type: 'boolean', description: 'Activar advertencia de registros OCI estrictos con atestaciones' },
            includeAttestations: { type: 'boolean', description: 'Indica si la imagen incluye atestaciones BuildKit (default true)' },
            targetPlatforms: { type: 'array', items: { type: 'string' }, description: 'Plataformas destino para action="plan"' },
            builders: { type: 'array', description: 'Nodos builder disponibles ({ id, arch, host }) para enrutamiento nativo' },
            preferNativeOverQemu: { type: 'boolean', description: 'Priorizar builders nativos sobre QEMU (default true)' },
            imageTag: { type: 'string', maxLength: 200, description: 'Tag destino de la imagen (default "app:latest")' }
          }
        }
      },
      {
        name: 'culkibo_chaos_gameday',
        title: 'Simular GameDays de Chaos Engineering con bloqueo prod y auto-abort',
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
        outputSchema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            action: { type: 'string' },
            dryRun: { type: 'boolean' },
            projectId: { type: 'string' },
            gamedays: { type: 'array' },
            result: { type: ['object', 'null'] }
          }
        },
        description: 'Simulador GameDay estilo Toxiproxy/Chaos Mesh (latency_jitter, http_5xx, timeout_drop, dns_failure, bandwidth_cap) con bloqueo duro en producción sin explicitProdConfirm (PROD_CHAOS_CONFIRM_REQUIRED), auto-abort por tasa de error (AUTO_ABORTED) y scorecard 0..100. ACL estricto por proyecto y dryRun: true por defecto en simulate.',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['list', 'score', 'simulate'], description: 'Operación Chaos GameDay (default "list")' },
            projectId: { type: 'string', maxLength: 128, description: 'ID del proyecto objetivo (ACL estricto)' },
            environment: { type: 'string', enum: ['development', 'staging', 'production'], description: 'Entorno del experimento (default "staging")' },
            explicitProdConfirm: { type: 'boolean', description: 'Confirmación explícita obligatoria para permitir environment="production"' },
            faultType: { type: 'string', enum: ['latency_jitter', 'http_5xx', 'timeout_drop', 'dns_failure', 'bandwidth_cap'], description: 'Tipo de fallo inyectado (default "latency_jitter")' },
            latencyMs: { type: 'number', minimum: 0, maximum: 60000, description: 'Latencia inyectada en ms' },
            jitterMs: { type: 'number', minimum: 0, maximum: 30000, description: 'Jitter en ms' },
            faultRatePct: { type: 'number', minimum: 0, maximum: 100, description: 'Porcentaje de tráfico afectado (0..100)' },
            maxErrorAbortPct: { type: 'number', minimum: 0, maximum: 100, description: 'Umbral de error que dispara AUTO_ABORTED (default 15)' },
            requestSamples: { type: 'array', description: 'Muestras observadas opcionales ({ status, latencyMs })' },
            errorRatePct: { type: 'number', minimum: 0, maximum: 100, description: 'Tasa de error % para action="score"' },
            allowedErrorRatePct: { type: 'number', minimum: 0, maximum: 100, description: 'Presupuesto de error % permitido (default 1.0)' },
            p95LatencyMs: { type: 'number', minimum: 0, description: 'Latencia p95 observada en ms para action="score"' },
            sloP95Ms: { type: 'number', minimum: 1, description: 'Objetivo SLO p95 en ms (default 400)' },
            recoverySec: { type: 'number', minimum: 0, description: 'Tiempo de recuperación en segundos (default 12)' },
            targetRecoverySec: { type: 'number', minimum: 1, description: 'Objetivo de recuperación en segundos (default 30)' },
            dryRun: { type: 'boolean', description: 'En simulate es true por defecto; pasa dryRun: false para persistir el scorecard.' }
          },
          required: ['projectId']
        }
      }
    ];

    // Inyección automática de `outputSchema`, `_meta.ui` (MCP Apps 2026-01-26) y del parámetro opcional `dryRun`
    // en todas las herramientas destructivas (35) + deploy_production y rollback_deployment (37 en total).
    for (const tool of this._toolsCache) {
      if (!tool.outputSchema && DEFAULT_OUTPUT_SCHEMAS[tool.name]) {
        tool.outputSchema = DEFAULT_OUTPUT_SCHEMAS[tool.name];
      }
      const uiResourceUri = mcpAppsRenderer.TOOL_UI_RESOURCE_MAP[tool.name];
      if (uiResourceUri) {
        tool._meta = {
          ...(tool._meta || {}),
          ui: { resourceUri: uiResourceUri }
        };
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
   * Clave estricta por llamante para aislar MCP Async Tasks (`tasks/list|get|result|cancel`).
   * Incluye restricciones de `projectIds` y `scopes` para impedir cualquier lectura cruzada entre tokens/tenants.
   * @param {ReturnType<typeof normalizePrincipal>} principal
   */
  _taskPrincipalKey(principal) {
    const base = this._principalKey(principal);
    const projScope = Array.isArray(principal.projectIds) ? [...principal.projectIds].sort().join(',') : '*';
    const scopeSig = Array.isArray(principal.scopes) ? [...principal.scopes].sort().join(',') : '*';
    return `${base}|p:${projScope}|s:${scopeSig}`;
  }

  /**
   * Construye una solicitud `elicitation/create` conforme a MCP 2026.
   * @param {{ message: string, requestedSchema: Record<string, any>, action?: string | null, projectId?: string | null, mode?: 'form' | 'url' }} opts
   */
  buildElicitationRequest(opts) {
    return buildElicitationRequest(opts);
  }

  /**
   * Genera metadatos estructurados `io.modelcontextprotocol/elicitation` para rutas
   * de remediación interactiva (`CONFIRMATION_REQUIRED`, `MISSING_SECRET`, `SECRET_LEAK_DETECTED`,
   * `DEPLOY_FROZEN`, `DEPLOY_FREEZE_ACTIVE`) o payloads explícitos en `err.details.elicitation`.
   * @param {string} toolName
   * @param {any} args
   * @param {any} envelope
   * @param {any} err
   */
  _buildErrorElicitation(toolName, args, envelope, err) {
    if (err instanceof McpToolError && err.details && err.details.elicitation && typeof err.details.elicitation === 'object') {
      return err.details.elicitation;
    }
    const code = String(envelope?.code || '');
    const projectId = args && typeof args === 'object' && args.projectId ? String(args.projectId) : (envelope?.details?.projectId ? String(envelope.details.projectId) : null);
    const action = (args && typeof args === 'object' && args.action ? String(args.action) : toolName) || toolName;

    if (code === 'CONFIRMATION_REQUIRED') {
      return buildElicitationRequest({
        message: envelope.message || `Confirm execution of '${toolName}' with a single-use HMAC confirmToken from dryRun: true.`,
        action,
        projectId,
        requestedSchema: {
          type: 'object',
          properties: {
            confirm: {
              type: 'boolean',
              title: 'Confirm execution',
              description: `I reviewed the dry-run plan for ${toolName} and approve applying the change.`,
              default: false
            },
            confirmToken: {
              type: 'string',
              title: 'Single-use confirmToken (ckr_...)',
              description: 'HMAC-SHA256 confirmation token issued by calling this tool with dryRun: true.',
              minLength: 10
            },
            reason: {
              type: 'string',
              title: 'Audit justification (optional)',
              maxLength: 200
            }
          },
          required: ['confirm', 'confirmToken']
        }
      });
    }

    if (code === 'MISSING_SECRET' || code === 'SECRET_LEAK_DETECTED') {
      const missingKey = envelope?.details?.secretKey || envelope?.details?.key || '';
      return buildElicitationRequest({
        message: envelope.message || `Secret remediation required for '${projectId || toolName}'. Store secrets encrypted in Culkibo Vault (\${vault.KEY}).`,
        action,
        projectId,
        requestedSchema: code === 'MISSING_SECRET'
          ? {
              type: 'object',
              properties: {
                secretKey: {
                  type: 'string',
                  title: 'Missing secret key',
                  description: 'Environment or Vault key name (e.g. DATABASE_URL, STRIPE_SECRET_KEY).',
                  ...(missingKey ? { default: String(missingKey) } : {}),
                  minLength: 1,
                  maxLength: 128
                },
                storeInVault: {
                  type: 'boolean',
                  title: 'Store encrypted in Culkibo Vault (AES-256-GCM)',
                  default: true
                },
                vaultRef: {
                  type: 'string',
                  title: 'Vault reference placeholder',
                  description: 'Use ${vault.KEY} syntax instead of plaintext literals in config/logs.',
                  ...(missingKey ? { default: `\${vault.${String(missingKey)}}` } : {})
                }
              },
              required: ['secretKey', 'storeInVault']
            }
          : {
              type: 'object',
              properties: {
                remediationStrategy: {
                  type: 'string',
                  title: 'Secret remediation action',
                  enum: ['move_to_vault', 'rotate_and_vault', 'admin_warn_override'],
                  default: 'move_to_vault'
                },
                acknowledgeVaultPolicy: {
                  type: 'boolean',
                  title: 'Confirm secrets will be referenced via ${vault.KEY}',
                  default: true
                }
              },
              required: ['remediationStrategy', 'acknowledgeVaultPolicy']
            }
      });
    }

    if (code === 'DEPLOY_FROZEN' || code === 'DEPLOY_FREEZE_ACTIVE') {
      return buildElicitationRequest({
        message: envelope.message || `Deployment is blocked by an active deploy freeze window${projectId ? ` on '${projectId}'` : ''}.`,
        action,
        projectId,
        requestedSchema: {
          type: 'object',
          properties: {
            overrideFreeze: {
              type: 'boolean',
              title: 'Override active deploy freeze (admin/owner only)',
              description: 'Set true only for emergency hotfixes authorized by an admin or owner.',
              default: false
            },
            incidentTicket: {
              type: 'string',
              title: 'Incident / Change Ticket ID',
              description: 'Tracking ticket authorizing emergency freeze override (e.g. INC-402).',
              maxLength: 80
            },
            reason: {
              type: 'string',
              title: 'Override justification',
              minLength: 5,
              maxLength: 240
            }
          },
          required: ['overrideFreeze', 'reason']
        }
      });
    }

    return null;
  }

  /** Limpia tareas expiradas y mantiene el almacén acotado a `MAX_ASYNC_TASKS` (128) sin timers en reposo. */
  _pruneTasks() {
    const now = Date.now();
    for (const [taskId, task] of this._tasks.entries()) {
      if (now > task.expiresAt) {
        if (task.status === 'working') {
          try { task.abortController.abort(); } catch (e) {}
          if (task.startTimer) {
            clearImmediate(task.startTimer);
            task.startTimer = null;
          }
          task.status = 'cancelled';
          task.statusMessage = 'Task TTL expired';
          task.lastUpdatedAt = new Date(now).toISOString();
          if (typeof task.resolveDone === 'function') task.resolveDone(task);
        }
        this._tasks.delete(taskId);
      }
    }
    while (this._tasks.size >= MAX_ASYNC_TASKS) {
      /** @type {string | null} */
      let victimId = null;
      for (const [tid, t] of this._tasks.entries()) {
        if (t.status !== 'working') {
          victimId = tid;
          break;
        }
      }
      if (!victimId) {
        victimId = this._tasks.keys().next().value || null;
      }
      if (!victimId) break;
      const victim = this._tasks.get(victimId);
      if (victim && victim.status === 'working') {
        try { victim.abortController.abort(); } catch (e) {}
        if (victim.startTimer) {
          clearImmediate(victim.startTimer);
          victim.startTimer = null;
        }
        if (typeof victim.resolveDone === 'function') victim.resolveDone(victim);
      }
      this._tasks.delete(victimId);
    }
  }

  /** Serializa una tarea MCP 2026-07-28 sin filtrar campos internos ni identidad de otros tenants. */
  _serializeTask(task) {
    return {
      taskId: task.taskId,
      status: task.status,
      statusMessage: task.statusMessage,
      createdAt: task.createdAt,
      lastUpdatedAt: task.lastUpdatedAt,
      ttl: task.ttl,
      pollInterval: task.pollInterval
    };
  }

  /**
   * Encola una llamada `tools/call` como MCP Async Task (`io.modelcontextprotocol/tasks`),
   * devolviendo inmediatamente `{ taskId, status: 'working', createdAt, lastUpdatedAt, ttl, pollInterval }`.
   * @param {string} toolName
   * @param {any} args
   * @param {any} taskOpts
   * @param {{ transport?: string, clientInfo?: any, auth?: any, onProgress?: (msg: string) => void }} [context]
   */
  enqueueToolTask(toolName, args, taskOpts = {}, context = {}) {
    const principal = normalizePrincipal(context.auth);
    if (principal.role === 'none') {
      throw new McpToolError('FORBIDDEN', 'Autenticación inválida o revocada para crear tareas MCP.', {
        retryable: false,
        remediation: 'Proporciona un token Bearer o sesión válida antes de usar MCP Async Tasks.'
      });
    }
    this._pruneTasks();

    const rawTtl = taskOpts && typeof taskOpts === 'object' ? Number(taskOpts.ttl) : NaN;
    const ttl = Number.isFinite(rawTtl)
      ? Math.min(MAX_TASK_TTL_MS, Math.max(MIN_TASK_TTL_MS, Math.round(rawTtl)))
      : DEFAULT_TASK_TTL_MS;
    const now = Date.now();
    const nowIso = new Date(now).toISOString();
    const taskId = `tsk_${crypto.randomBytes(12).toString('hex')}`;
    const abortController = new AbortController();

    /** @type {(v: any) => void} */
    let resolveDone = () => {};
    const donePromise = new Promise((resolve) => {
      resolveDone = resolve;
    });

    /** @type {any} */
    const task = {
      taskId,
      principalKey: this._taskPrincipalKey(principal),
      toolName: String(toolName || ''),
      status: 'working',
      statusMessage: `Executing '${toolName}'...`,
      createdAt: nowIso,
      lastUpdatedAt: nowIso,
      ttl,
      expiresAt: now + ttl,
      pollInterval: DEFAULT_TASK_POLL_INTERVAL_MS,
      abortController,
      result: null,
      error: null,
      donePromise,
      resolveDone,
      startTimer: null
    };

    this._tasks.set(taskId, task);

    const run = async () => {
      task.startTimer = null;
      if (task.status !== 'working' || abortController.signal.aborted) {
        if (task.status === 'working') {
          task.status = 'cancelled';
          task.statusMessage = 'Task cancelled before execution';
          task.lastUpdatedAt = new Date().toISOString();
        }
        resolveDone(task);
        return;
      }
      try {
        const toolResult = await this.executeTool(toolName, args, {
          transport: context.transport || `MCP ${PROTOCOL_VERSION} (async-task)`,
          clientInfo: context.clientInfo || null,
          signal: abortController.signal,
          onProgress: (msg) => {
            if (task.status === 'working') {
              task.statusMessage = String(msg || '').slice(0, 240);
              task.lastUpdatedAt = new Date().toISOString();
            }
            if (typeof context.onProgress === 'function') context.onProgress(msg);
          },
          auth: context.auth
        });
        if (task.status === 'cancelled' || abortController.signal.aborted) {
          task.status = 'cancelled';
          task.statusMessage = 'Cancelled by client';
          task.lastUpdatedAt = new Date().toISOString();
        } else if (toolResult && toolResult.isError) {
          task.status = 'failed';
          task.statusMessage = `Tool '${toolName}' returned an error`;
          task.result = toolResult;
          task.lastUpdatedAt = new Date().toISOString();
        } else {
          task.status = 'completed';
          task.statusMessage = `Completed '${toolName}'`;
          task.result = toolResult;
          task.lastUpdatedAt = new Date().toISOString();
        }
      } catch (err) {
        if (task.status !== 'cancelled') {
          task.status = 'failed';
          task.statusMessage = err && err.message ? String(err.message).slice(0, 240) : 'Async task execution failed';
          task.error = { code: ERROR_CODES.INTERNAL_ERROR, message: task.statusMessage };
          task.lastUpdatedAt = new Date().toISOString();
        }
      } finally {
        resolveDone(task);
      }
    };

    task.startTimer = setImmediate(() => {
      run().catch(() => {});
    });
    if (task.startTimer && typeof task.startTimer.unref === 'function') {
      task.startTimer.unref();
    }

    return this._serializeTask(task);
  }

  /**
   * Lista las tareas asíncronas visibles ÚNICAMENTE para el principal invocador.
   * @param {any} [authOrPrincipal]
   */
  listTasks(authOrPrincipal = null) {
    const principal = normalizePrincipal(authOrPrincipal);
    if (principal.role === 'none') {
      throw new McpToolError('FORBIDDEN', 'Autenticación inválida o revocada para listar tareas MCP.');
    }
    this._pruneTasks();
    const callerKey = this._taskPrincipalKey(principal);
    const items = [];
    for (const task of this._tasks.values()) {
      if (task.principalKey === callerKey) {
        items.push(this._serializeTask(task));
      }
    }
    return items;
  }

  /**
   * Resuelve una tarea propiedad exclusiva del principal; devuelve error `TASK_NOT_FOUND`
   * si no existe, expiró o pertenece a otro principal (cero fuga cross-tenant).
   * @param {string} taskId
   * @param {any} [authOrPrincipal]
   */
  _getOwnedTask(taskId, authOrPrincipal = null) {
    const principal = normalizePrincipal(authOrPrincipal);
    if (principal.role === 'none') {
      throw new McpToolError('FORBIDDEN', 'Autenticación inválida o revocada para consultar tareas MCP.');
    }
    this._pruneTasks();
    const cleanId = typeof taskId === 'string' ? taskId.trim() : '';
    if (!cleanId) {
      throw new McpToolError('MISSING_ARGUMENT', 'Falta el parámetro obligatorio taskId.');
    }
    const task = this._tasks.get(cleanId);
    const callerKey = this._taskPrincipalKey(principal);
    if (!task || task.principalKey !== callerKey) {
      throw new McpToolError('TASK_NOT_FOUND', `Tarea MCP no encontrada o sin acceso: '${cleanId}'.`);
    }
    return task;
  }

  /** @param {string} taskId @param {any} [authOrPrincipal] */
  getTask(taskId, authOrPrincipal = null) {
    const task = this._getOwnedTask(taskId, authOrPrincipal);
    return this._serializeTask(task);
  }

  /**
   * Espera hasta que la tarea alcance estado terminal y devuelve su resultado con `_meta['io.modelcontextprotocol/related-task']`.
   * @param {string} taskId
   * @param {any} [authOrPrincipal]
   * @param {{ timeoutMs?: number }} [opts]
   */
  async getTaskResult(taskId, authOrPrincipal = null, opts = {}) {
    const task = this._getOwnedTask(taskId, authOrPrincipal);
    if (task.status === 'working') {
      const waitMs = Math.min(MAX_TASK_TTL_MS, Math.max(100, Number(opts.timeoutMs) || Math.min(task.ttl, DEFAULT_TASK_RESULT_WAIT_MS)));
      /** @type {any} */
      let timer = null;
      await Promise.race([
        task.donePromise,
        new Promise((resolve) => {
          timer = setTimeout(resolve, waitMs);
          if (timer && typeof timer.unref === 'function') timer.unref();
        })
      ]);
      if (timer) clearTimeout(timer);
    }
    if (task.status === 'cancelled') {
      throw new McpToolError('TASK_CANCELLED', `La tarea '${task.taskId}' fue cancelada y no tiene resultado.`);
    }
    if (task.status === 'working') {
      throw new McpToolError('TASK_IN_PROGRESS', `La tarea '${task.taskId}' sigue en ejecución; vuelve a consultar con tasks/get o tasks/result.`, {
        retryable: true,
        details: { task: this._serializeTask(task) }
      });
    }
    if (task.result && typeof task.result === 'object') {
      return {
        ...task.result,
        _meta: {
          ...(task.result._meta || {}),
          [META_RELATED_TASK]: { taskId: task.taskId }
        }
      };
    }
    throw new McpToolError('INTERNAL_ERROR', task.error?.message || `La tarea '${task.taskId}' finalizó sin resultado.`);
  }

  /**
   * Cancela una tarea `working` propiedad del principal; rechaza cancelar tareas ya terminales.
   * @param {string} taskId
   * @param {any} [authOrPrincipal]
   */
  cancelTask(taskId, authOrPrincipal = null) {
    const task = this._getOwnedTask(taskId, authOrPrincipal);
    if (task.status !== 'working') {
      throw new McpToolError('INVALID_ARGUMENT', `No se puede cancelar la tarea '${task.taskId}' en estado terminal '${task.status}'.`, {
        retryable: false,
        remediation: 'Solo las tareas en estado "working" pueden cancelarse.'
      });
    }
    if (task.startTimer) {
      clearImmediate(task.startTimer);
      task.startTimer = null;
    }
    task.status = 'cancelled';
    task.statusMessage = 'Cancelled by client';
    task.lastUpdatedAt = new Date().toISOString();
    try { task.abortController.abort(); } catch (e) {}
    if (typeof task.resolveDone === 'function') task.resolveDone(task);
    return this._serializeTask(task);
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
    if (args.databaseId || args.dbId) {
      const targetDbId = String(args.databaseId || args.dbId);
      const allDbs = databaseManager.list();
      const db = allDbs.find((d) => d.id === targetDbId);
      if (args.databaseId || db) {
        refs.push({ projectId: db?.projectId || null, resourceKind: 'database', missing: !db });
      }
    }
    if (args.sourceDatabaseId) {
      const allDbs = databaseManager.list();
      const db = allDbs.find((d) => d.id === args.sourceDatabaseId);
      refs.push({ projectId: db?.projectId || null, resourceKind: 'database', missing: !db });
    }
    if (args.rolloutId) {
      const slo = lazySvc('sloCanaryController');
      const r = slo && typeof slo.getRollout === 'function' ? slo.getRollout(String(args.rolloutId)) : null;
      refs.push({ projectId: r?.projectId || null, resourceKind: 'slo_rollout', missing: !r });
    }
    if (args.experimentId) {
      const expSvc = lazySvc('edgeExperimentService');
      const exp = expSvc && typeof expSvc.getExperiment === 'function' ? expSvc.getExperiment(String(args.experimentId)) : null;
      refs.push({ projectId: exp?.projectId || null, resourceKind: 'edge_experiment', missing: !exp });
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

    if (toolName === 'culkibo_brand_theme' && (args.action === 'update' || args.action === 'reset')) {
      if (callerRank < ROLE_RANK.admin || Array.isArray(principal.projectIds)) {
        throw new McpToolError('FORBIDDEN', `La acción '${args.action}' de culkibo_brand_theme requiere rol admin/owner sin restricción de proyectos.`, {
          retryable: false,
          remediation: 'Usa action: "get" para leer la marca actual o autentícate como admin/owner.'
        });
      }
    }

    if (toolName === 'culkibo_admission_check' && args.action === 'apply_preset') {
      if (callerRank < ROLE_RANK.admin || Array.isArray(principal.projectIds)) {
        throw new McpToolError('FORBIDDEN', 'Cambiar el preset global de Policy-as-Code (apply_preset) requiere rol admin/owner sin restricción de proyectos.', {
          retryable: false,
          remediation: 'Usa action: "get_policy" o "evaluate" para evaluar specs, o autentícate como admin/owner.'
        });
      }
    }

    if (toolName === 'culkibo_synthetic_sentinel' && args.action === 'save_flow') {
      if (callerRank < ROLE_RANK.admin || Array.isArray(principal.projectIds)) {
        throw new McpToolError('FORBIDDEN', 'Guardar o modificar flujos sintéticos globales (save_flow) requiere rol admin/owner sin restricción de proyectos.', {
          retryable: false,
          remediation: 'Usa action: "list_flows", "run_flow" o "check_tls", o autentícate como admin/owner.'
        });
      }
    }

    if (toolName === 'culkibo_oncall_router' && args.action === 'save_policy') {
      if (callerRank < ROLE_RANK.admin || Array.isArray(principal.projectIds)) {
        throw new McpToolError('FORBIDDEN', 'Guardar o modificar políticas globales de escalado On-Call (save_policy) requiere rol admin/owner sin restricción de proyectos.', {
          retryable: false,
          remediation: 'Usa action: "list_policies", "list_incidents", "resolve_oncall", "ingest_alert", "ack_incident" o autentícate como admin/owner.'
        });
      }
    }

    if (toolName === 'culkibo_egress_firewall' && args.action === 'save_policy') {
      if (callerRank < ROLE_RANK.admin || Array.isArray(principal.projectIds)) {
        throw new McpToolError('FORBIDDEN', 'Guardar o modificar políticas de egress firewall (save_policy) requiere rol admin/owner sin restricción de proyectos.', {
          retryable: false,
          remediation: 'Usa action: "get_policy" o "audit" para auditar egress, o autentícate como admin/owner.'
        });
      }
    }

    if (toolName === 'culkibo_replica_failover' && (args.action === 'save_topology' || args.action === 'promote')) {
      if (callerRank < ROLE_RANK.admin || Array.isArray(principal.projectIds)) {
        throw new McpToolError('FORBIDDEN', `La acción '${args.action}' de culkibo_replica_failover requiere rol admin/owner sin restricción de proyectos.`, {
          retryable: false,
          remediation: 'Usa action: "get_topology" o "evaluate_split" para consultar lag de réplicas, o autentícate como admin/owner.'
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

      case 'culkibo_edge_tunnel': {
        const action = String(args.action || 'status');
        Object.assign(target, {
          action,
          tunnelId: args.tunnelId || null,
          name: args.name || null,
          targetHost: args.targetHost || '127.0.0.1',
          targetPort: args.targetPort ?? null,
          hostname: args.hostname || null
        });
        if (action === 'create') {
          if (!args.targetPort) blockers.push('MISSING_TARGET_PORT');
          effects.push(`Creará túnel CGNAT soberano '${args.name || `tunnel-${args.targetPort || '?'}`}' hacia ${args.targetHost || '127.0.0.1'}:${args.targetPort || '?'} y emitirá un token HMAC cket_ de visualización única.`);
          riskLevel = 'medium';
          reversible = true;
        } else if (action === 'revoke') {
          if (!args.tunnelId) blockers.push('MISSING_TUNNEL_ID');
          effects.push(`Revocará inmediatamente el túnel EdgeTunnel '${args.tunnelId || '?'}' y cerrará sus streams WebSocket activos.`);
          riskLevel = 'high';
          reversible = false;
        } else {
          effects.push(`Consultará '${action}' de los túneles soberanos EdgeTunnel sin mutar estado.`);
          riskLevel = 'low';
          reversible = true;
        }
        break;
      }

      case 'culkibo_time_machine': {
        const action = String(args.action || 'list');
        if (!project) throw projectNotFoundError(args.projectId);
        Object.assign(target, {
          action,
          projectId: project.id,
          projectName: project.name,
          checkpointId: args.checkpointId || null,
          fromId: args.fromId || null,
          toId: args.toId || null
        });
        if (action === 'restore') {
          if (!args.checkpointId) {
            blockers.push('MISSING_CHECKPOINT_ID');
          } else {
            const tmSvc = lazySvc('timeMachineService');
            if (tmSvc && typeof tmSvc.restoreCheckpoint === 'function') {
              try {
                const tmPreview = await tmSvc.restoreCheckpoint(project.id, String(args.checkpointId), { dryRun: true });
                if (tmPreview && typeof tmPreview === 'object') Object.assign(preview, tmPreview);
              } catch (e) {
                blockers.push('CHECKPOINT_NOT_FOUND');
                warnings.push(e.message);
              }
            }
          }
          effects.push(`Restaurará atómicamente el stack completo de '${project.name}' (Proyecto + Dominios + Crons) al checkpoint '${args.checkpointId || '?'}', creando antes un checkpoint de seguridad automático.`);
          riskLevel = 'high';
          reversible = true;
        } else if (action === 'create') {
          effects.push(`Creará un checkpoint Time-Machine de stack completo para '${project.name}'${args.label ? ` (${args.label})` : ''} sin almacenar secretos en claro.`);
          riskLevel = 'low';
          reversible = true;
        } else {
          effects.push(`Ejecutará '${action}' de Time-Machine en solo lectura sobre '${project.name}'.`);
          riskLevel = 'low';
          reversible = true;
        }
        break;
      }

      case 'culkibo_heal_build_failure': {
        Object.assign(target, {
          projectId: args.projectId || null,
          apply: Boolean(args.apply),
          code: args.code || null,
          logsLength: typeof args.logs === 'string' ? args.logs.length : 0
        });
        const bh = lazySvc('buildHealerService');
        if (bh && typeof bh.diagnoseLogs === 'function') {
          const diagnosis = bh.diagnoseLogs(String(args.logs || ''), { projectId: args.projectId || undefined });
          let healingPlan = null;
          if (args.projectId && typeof bh.applyHealingPlan === 'function') {
            try {
              healingPlan = await bh.applyHealingPlan(String(args.projectId), {
                logs: String(args.logs || ''),
                ...(args.code ? { code: String(args.code) } : {}),
                dryRun: true
              });
            } catch (e) {
              warnings.push(e.message);
            }
          }
          Object.assign(preview, { diagnosis, healingPlan });
        }
        effects.push(`Analizará los logs de build/runtime contra 20 patrones deterministas${args.projectId ? ` y previsualizará parches seguros para '${args.projectId}'` : ''} sin mutar estado.`);
        riskLevel = 'low';
        reversible = true;
        break;
      }

      case 'culkibo_fleet_mesh': {
        const action = String(args.action || 'status');
        Object.assign(target, { action, nodeId: args.nodeId || null });
        const fm = lazySvc('fleetMeshService');
        if (action === 'rotate') {
          if (!args.nodeId) {
            blockers.push('MISSING_NODE_ID');
          } else if (fm && typeof fm.rotatePeerKey === 'function') {
            try {
              const rotPreview = fm.rotatePeerKey(String(args.nodeId), { dryRun: true });
              if (rotPreview && typeof rotPreview === 'object') Object.assign(preview, rotPreview);
            } catch (e) {
              blockers.push('MESH_NODE_NOT_FOUND');
              warnings.push(e.message);
            }
          }
          effects.push(`Rotará el par de claves x25519 WireGuard del nodo '${args.nodeId || '?'}' (almacenado AES-256-GCM; requiere distribuir nueva clave pública al resto de peers).`);
          riskLevel = 'high';
          reversible = false;
        } else {
          effects.push(`Consultará '${action}' de la malla privada WireGuard 10.88.0.0/24 sin mutar claves ni archivos.`);
          riskLevel = 'low';
          reversible = true;
        }
        break;
      }

      case 'culkibo_secret_lease': {
        const action = String(args.action || 'list');
        const clampedTtl = action === 'break_glass'
          ? Math.min(900, Math.max(60, Number(args.ttlSec) || 900))
          : Math.min(86400, Math.max(60, Number(args.ttlSec) || 3600));
        Object.assign(target, {
          action,
          projectId: args.projectId || null,
          secretKey: args.secretKey || null,
          leaseId: args.leaseId || null,
          ttlSec: clampedTtl
        });
        if (action === 'issue') {
          if (!args.projectId) blockers.push('MISSING_PROJECT_ID');
          if (!args.secretKey) blockers.push('MISSING_SECRET_KEY');
          effects.push(`Emitirá un lease temporal (${clampedTtl}s) para '${args.secretKey || '?'}' en '${args.projectId || '?'}' (almacena solo hash HMAC-SHA256 en disco).`);
          riskLevel = 'medium';
          reversible = true;
        } else if (action === 'revoke') {
          if (!args.leaseId) blockers.push('MISSING_LEASE_ID');
          effects.push(`Revocará inmediatamente el lease '${args.leaseId || '?'}' invalidando su token.`);
          riskLevel = 'medium';
          reversible = false;
        } else if (action === 'break_glass') {
          if (!args.reason || String(args.reason).trim().length < 10) blockers.push('MISSING_AUDIT_REASON');
          effects.push(`Emitirá un token Break-Glass de emergencia (máx ${clampedTtl}s <= 15m) disparando alerta de seguridad y entrada inmutable de auditoría.`);
          riskLevel = 'high';
          reversible = true;
        } else {
          effects.push(`Consultará '${action}' de secret leases sin mutar estado.`);
          riskLevel = 'low';
          reversible = true;
        }
        break;
      }

      case 'culkibo_webhook_dlq': {
        const action = String(args.action || 'list_dlq');
        const graceSec = Math.min(604800, Math.max(60, Number(args.graceSec) || 86400));
        Object.assign(target, {
          action,
          dlqId: args.dlqId || null,
          subscriptionId: args.subscriptionId || null,
          graceSec
        });
        if (action === 'replay') {
          if (!args.dlqId) blockers.push('MISSING_DLQ_ID');
          effects.push(`Reintentará la entrega DLQ '${args.dlqId || '?'}' re-validando DNS/SSRF antes de firmar con Standard-Webhooks.`);
          riskLevel = 'medium';
          reversible = true;
        } else if (action === 'rotate_secret') {
          if (!args.subscriptionId) blockers.push('MISSING_SUBSCRIPTION_ID');
          effects.push(`Rotará el secreto whsec_ de la suscripción '${args.subscriptionId || '?'}' manteniendo el secreto previo activo durante ${graceSec}s de gracia dual-secret.`);
          riskLevel = 'high';
          reversible = true;
        } else {
          effects.push(`Consultará '${action}' de Standard-Webhooks sin mutar suscripciones ni disparar entregas.`);
          riskLevel = 'low';
          reversible = true;
        }
        break;
      }

      case 'culkibo_brand_theme': {
        const action = String(args.action || 'get');
        Object.assign(target, {
          action,
          patchKeys: args.patch && typeof args.patch === 'object' ? Object.keys(args.patch) : []
        });
        if (action === 'update') {
          if (!args.patch || typeof args.patch !== 'object' || Array.isArray(args.patch)) {
            blockers.push('MISSING_BRAND_PATCH');
          } else {
            const bt = lazySvc('brandThemeService');
            if (bt && typeof bt.validateBrandPatch === 'function') {
              try {
                const validated = bt.validateBrandPatch(args.patch);
                if (validated && validated.valid === false) {
                  throw new McpToolError('INVALID_BRAND_PATCH', validated.error || 'Configuración de marca rechazada por validación anti-XSS/CSS.', {
                    retryable: true,
                    remediation: 'Usa accentHex #RRGGBB, supportUrl https:// y logoUrl https:// o data:image/svg+xml sin scripts ni handlers.'
                  });
                }
                Object.assign(preview, { validatedPatch: validated });
              } catch (e) {
                if (e instanceof McpToolError) throw e;
                throw new McpToolError('INVALID_BRAND_PATCH', e.message || 'Configuración de marca inválida.', {
                  retryable: true,
                  remediation: 'Corrige los campos rechazados (brandName, tagline, accentHex #RRGGBB, supportUrl https://, logoUrl seguro).'
                });
              }
            }
          }
          effects.push('Actualizará la configuración de marca white-label (brand-theme.json) con validación estricta anti-XSS/CSS.');
          riskLevel = 'low';
          reversible = true;
        } else if (action === 'reset') {
          effects.push('Restablecerá la marca white-label a los valores por defecto de Culkibo.');
          riskLevel = 'low';
          reversible = true;
        } else {
          effects.push('Leerá la marca white-label actual sin mutar estado.');
          riskLevel = 'low';
          reversible = true;
        }
        break;
      }

      case 'culkibo_slo_canary': {
        const action = String(args.action || 'list');
        Object.assign(target, {
          action,
          projectId: args.projectId || null,
          rolloutId: args.rolloutId || null,
          hostname: args.hostname || null,
          steps: Array.isArray(args.steps) ? args.steps : [10, 25, 50, 100]
        });
        if (action === 'start') {
          if (!args.projectId) blockers.push('MISSING_PROJECT_ID');
          if (!args.hostname) blockers.push('MISSING_HOSTNAME');
          if (!args.stableUpstream) blockers.push('MISSING_STABLE_UPSTREAM');
          if (!args.canaryUpstream) blockers.push('MISSING_CANARY_UPSTREAM');
          const sloSvc = lazySvc('sloCanaryController');
          const firstWeight = Array.isArray(args.steps) && args.steps.length > 0 ? Number(args.steps[0]) : 10;
          if (sloSvc && typeof sloSvc.buildCaddyWeightedRoute === 'function' && args.hostname && args.stableUpstream && args.canaryUpstream) {
            preview.caddyRoute = sloSvc.buildCaddyWeightedRoute({
              hostname: String(args.hostname),
              stableUpstream: String(args.stableUpstream),
              canaryUpstream: String(args.canaryUpstream),
              canaryWeight: firstWeight
            });
          }
          effects.push(`Iniciará un rollout SLO Canary (${firstWeight}% inicial) sobre '${args.hostname || '?'}' con auto-rollback inmediato a 100/0 si el burn rate > ${args.maxBurnRate ?? 14.4}x.`);
          riskLevel = 'high';
          reversible = true;
        } else if (action === 'abort') {
          if (!args.rolloutId) blockers.push('MISSING_ROLLOUT_ID');
          effects.push(`Abortará el rollout canario '${args.rolloutId || '?'}' devolviendo 100% del tráfico al upstream estable.`);
          riskLevel = 'medium';
          reversible = true;
        } else {
          effects.push(`Ejecutará '${action}' en el controlador SLO Canary sin mutar pesos activos.`);
          riskLevel = 'low';
          reversible = true;
        }
        break;
      }

      case 'culkibo_remote_builder': {
        const action = String(args.action || 'list');
        Object.assign(target, {
          action,
          builderId: args.builderId || null,
          name: args.name || null,
          host: args.host || null,
          arch: args.arch || 'linux/amd64',
          isPreview: Boolean(args.isPreview),
          projectId: args.projectId || null
        });
        if (action === 'register') {
          if (!args.name) blockers.push('MISSING_BUILDER_NAME');
          if (!args.host) blockers.push('MISSING_BUILDER_HOST');
          effects.push(`Registrará el nodo remote builder '${args.name || '?'}' (${args.host || '?'}, ${args.arch || 'linux/amd64'}) con concurrencia máxima ${args.maxConcurrency ?? 2}.`);
          riskLevel = 'medium';
          reversible = true;
        } else if (action === 'schedule') {
          effects.push(`Reservará una ranura de build remoto (${args.arch || 'linux/amd64'}${args.isPreview ? ', PR preview' : ''}) fijando SSH mux ref-count hasta liberar el lease.`);
          riskLevel = 'low';
          reversible = true;
        } else {
          effects.push(`Consultará '${action}' de remote builders sin modificar nodos ni ranuras activas.`);
          riskLevel = 'low';
          reversible = true;
        }
        break;
      }

      case 'culkibo_admission_check': {
        const action = String(args.action || 'evaluate');
        Object.assign(target, { action, preset: args.preset || null });
        if (action === 'apply_preset') {
          if (!args.preset) blockers.push('MISSING_PRESET');
          effects.push(`Aplicará el preset global de Policy-as-Code Admission '${args.preset || '?'}' (10 reglas CIS/PSS) en admission-policies.json.`);
          riskLevel = 'medium';
          reversible = true;
        } else {
          effects.push(`Ejecutará '${action}' en Policy-as-Code Admission sin mutar políticas activas.`);
          riskLevel = 'low';
          reversible = true;
        }
        break;
      }

      case 'culkibo_edge_experiment': {
        const action = String(args.action || 'list');
        Object.assign(target, {
          action,
          experimentId: args.experimentId || null,
          projectId: args.projectId || null,
          hostname: args.hostname || null,
          kind: args.kind || 'ab'
        });
        if (action === 'upsert') {
          if (!args.projectId) blockers.push('MISSING_PROJECT_ID');
          if (!args.hostname) blockers.push('MISSING_HOSTNAME');
          effects.push(`Guardará y compilará el experimento Edge (${args.kind || 'ab'}) en '${args.hostname || '?'}' para Caddy v2.11.`);
          riskLevel = 'medium';
          reversible = true;
        } else if (action === 'kill_switch') {
          if (!args.experimentId) blockers.push('MISSING_EXPERIMENT_ID');
          effects.push(`Activará kill-switch inmediato sobre '${args.experimentId || '?'}' revirtiendo 100% del tráfico a la variante de control.`);
          riskLevel = 'high';
          reversible = true;
        } else {
          effects.push(`Ejecutará '${action}' de Edge Geo/A-B sin modificar experimentos activos.`);
          riskLevel = 'low';
          reversible = true;
        }
        break;
      }

      case 'culkibo_synthetic_sentinel': {
        const action = String(args.action || 'list_flows');
        Object.assign(target, {
          action,
          flowId: args.flowId || args.flow?.id || null,
          host: args.host || null
        });
        if (action === 'save_flow') {
          if (!args.flow || typeof args.flow !== 'object') blockers.push('MISSING_FLOW_DEFINITION');
          effects.push(`Guardará el flujo sintético '${args.flow?.name || '(sin nombre)'}' redactando cabeceras y secretos antes de escribir en synthetic-flows.json.`);
          riskLevel = 'low';
          reversible = true;
        } else {
          effects.push(`Ejecutará '${action}' del centinela sintético/TLS con allowLoopback=false y guardia SSRF sin mutar flujos guardados.`);
          riskLevel = 'low';
          reversible = true;
        }
        break;
      }

      case 'culkibo_worker_autoscaler': {
        const action = String(args.action || 'get_policy');
        Object.assign(target, {
          action,
          projectId: args.projectId || null,
          policyKeys: args.policy && typeof args.policy === 'object' ? Object.keys(args.policy) : []
        });
        if (action === 'set_policy') {
          if (!args.projectId) blockers.push('MISSING_PROJECT_ID');
          if (!args.policy || typeof args.policy !== 'object') blockers.push('MISSING_AUTOSCALER_POLICY');
          effects.push(`Actualizará la política KEDA/OOM-safe del autoscaler de '${args.projectId || '?'}' en autoscaler-policies.json.`);
          riskLevel = 'medium';
          reversible = true;
        } else {
          effects.push(`Ejecutará '${action}' del autoscaler sobre '${args.projectId || '?'}' sin mutar políticas.`);
          riskLevel = 'low';
          reversible = true;
        }
        break;
      }

      case 'culkibo_cron_lease': {
        const action = String(args.action || 'list');
        Object.assign(target, {
          action,
          jobId: args.jobId || null,
          scheduleSlotIso: args.scheduleSlotIso || null,
          leaseId: args.leaseId || null
        });
        if (action === 'acquire') {
          if (!args.jobId) blockers.push('MISSING_JOB_ID');
          effects.push(`Adquirirá lease distribuido con fencingToken monotónico para '${args.jobId || '?'}' (slot ${args.scheduleSlotIso || 'auto'}) en cron-leases.json.`);
          riskLevel = 'low';
          reversible = true;
        } else if (action === 'renew' || action === 'complete') {
          if (!args.leaseId) blockers.push('MISSING_LEASE_ID');
          if (action === 'complete' && args.fencingToken === undefined) blockers.push('MISSING_FENCING_TOKEN');
          effects.push(`Ejecutará '${action}' sobre el lease '${args.leaseId || '?'}' validando holderId y fencingToken.`);
          riskLevel = 'low';
          reversible = true;
        } else {
          effects.push(`Listará leases de cron${args.jobId ? ` para '${args.jobId}'` : ''} sin mutar estado.`);
          riskLevel = 'low';
          reversible = true;
        }
        break;
      }

      case 'culkibo_oncall_router': {
        const action = String(args.action || 'list_incidents');
        Object.assign(target, {
          action,
          policyId: args.policyId || args.policy?.id || null,
          incidentId: args.incidentId || null,
          fingerprint: args.fingerprint || null
        });
        if (action === 'save_policy') {
          if (!args.policy || typeof args.policy !== 'object') blockers.push('MISSING_ONCALL_POLICY');
          effects.push(`Guardará la política On-Call '${args.policy?.name || '(sin nombre)'}' en oncall-policies.json.`);
          riskLevel = 'medium';
          reversible = true;
        } else if (action === 'ingest_alert') {
          if (!args.fingerprint) blockers.push('MISSING_FINGERPRINT');
          effects.push(`Ingerirá alerta '${args.fingerprint || '?'}' (${args.state || 'firing'}) aplicando deduplicación y amortiguación de flapping.`);
          riskLevel = 'low';
          reversible = true;
        } else if (action === 'ack_incident') {
          if (!args.incidentId) blockers.push('MISSING_INCIDENT_ID');
          effects.push(`Reconocerá el incidente '${args.incidentId || '?'}' deteniendo escalados Tier 1→2→3.`);
          riskLevel = 'low';
          reversible = true;
        } else if (action === 'evaluate_escalations') {
          effects.push('Evaluará timeouts de reconocimiento y escalará incidentes sin ACK al siguiente Tier.');
          riskLevel = 'low';
          reversible = true;
        } else {
          effects.push(`Consultará '${action}' del enrutador On-Call sin mutar estado.`);
          riskLevel = 'low';
          reversible = true;
        }
        break;
      }

      case 'culkibo_egress_firewall': {
        const action = String(args.action || 'get_policy');
        Object.assign(target, {
          action,
          projectId: args.projectId || null,
          backend: args.backend || 'nftables'
        });
        if (action === 'save_policy') {
          if (!args.projectId) blockers.push('MISSING_PROJECT_ID');
          if (!args.policy || typeof args.policy !== 'object') blockers.push('MISSING_EGRESS_POLICY');
          effects.push(`Guardará la política de egress firewall de '${args.projectId || '?'}' preservando puertos anti-lockout (22/80/443).`);
          riskLevel = 'medium';
          reversible = true;
        } else {
          effects.push(`Ejecutará '${action}' de auditoría egress/nftables sobre '${args.projectId || '?'}' sin mutar políticas.`);
          riskLevel = 'low';
          reversible = true;
        }
        break;
      }

      case 'culkibo_replica_failover': {
        const action = String(args.action || 'get_topology');
        Object.assign(target, {
          action,
          dbId: args.dbId || null,
          targetReplicaId: args.targetReplicaId || null
        });
        if (action === 'save_topology') {
          if (!args.dbId) blockers.push('MISSING_DB_ID');
          if (!args.primary || typeof args.primary !== 'object') blockers.push('MISSING_PRIMARY_NODE');
          effects.push(`Guardarará la topología primary + ${Array.isArray(args.replicas) ? args.replicas.length : 0} réplica(s) de '${args.dbId || '?'}'.`);
          riskLevel = 'medium';
          reversible = true;
        } else if (action === 'promote') {
          if (!args.dbId) blockers.push('MISSING_DB_ID');
          if (!args.targetReplicaId) blockers.push('MISSING_TARGET_REPLICA_ID');
          effects.push(`Planificará/ejecutará la promoción de la réplica '${args.targetReplicaId || '?'}' con guardias de lag y fencing anti split-brain.`);
          riskLevel = 'high';
          reversible = true;
        } else {
          effects.push(`Ejecutará '${action}' de topología/read-write split sobre '${args.dbId || '?'}' sin mutar estado.`);
          riskLevel = 'low';
          reversible = true;
        }
        break;
      }

      case 'culkibo_chaos_gameday': {
        const action = String(args.action || 'list');
        Object.assign(target, {
          action,
          projectId: args.projectId || null,
          environment: args.environment || 'staging',
          faultType: args.faultType || 'latency_jitter'
        });
        if (action === 'simulate') {
          if (!args.projectId) blockers.push('MISSING_PROJECT_ID');
          if (args.environment === 'production' && args.explicitProdConfirm !== true) {
            blockers.push('PROD_CHAOS_CONFIRM_REQUIRED');
          }
          effects.push(`Simulará un GameDay Chaos (${args.faultType || 'latency_jitter'}) en '${args.environment || 'staging'}' para '${args.projectId || '?'}' con auto-abort a >${args.maxErrorAbortPct ?? 15}% error.`);
          riskLevel = args.environment === 'production' ? 'high' : 'low';
          reversible = true;
        } else {
          effects.push(`Ejecutará '${action}' de Chaos GameDay sobre '${args.projectId || '?'}' sin mutar estado.`);
          riskLevel = 'low';
          reversible = true;
        }
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

        // --- MCP 2026 Cycle-2: SmartPack & Sovereign EdgeTunnel (2) ---
        case 'culkibo_smartpack_plan': {
          const sp = requireLazySvc('smartPackBuilder', 'Culkibo SmartPack');
          let targetDir = process.cwd();
          let resolvedProjectId = null;
          if (args.projectId) {
            const project = projectManager.getById(String(args.projectId));
            if (!project) throw projectNotFoundError(args.projectId);
            resolvedProjectId = project.id;
            targetDir = project.localPath
              ? path.resolve(String(project.localPath))
              : path.resolve(__dirname, '..', '..', 'projects', project.id);
          } else if (args.directory) {
            const resolved = path.resolve(String(args.directory));
            if (process.env.CULKIBO_ALLOW_ARBITRARY_SMARTPACK !== '1') {
              const projectsRoot = path.resolve(__dirname, '..', '..', 'projects');
              const cwdRoot = path.resolve(process.cwd());
              const relProj = path.relative(projectsRoot, resolved);
              const relCwd = path.relative(cwdRoot, resolved);
              const inProjects = !relProj.startsWith('..') && !path.isAbsolute(relProj);
              const inCwd = !relCwd.startsWith('..') && !path.isAbsolute(relCwd);
              if (!inProjects && !inCwd) {
                throw new McpToolError('FORBIDDEN_PATH', 'Solo se permite analizar directorios dentro del workspace o projects/ de Culkibo.', {
                  retryable: false,
                  remediation: 'Pasa un projectId válido o una ruta dentro del directorio actual o projects/.'
                });
              }
            }
            targetDir = resolved;
          }
          const plan = sp.generateBuildPlan(targetDir, { zstdChunked: Boolean(args.zstdChunked) });
          const dockerignoreObj = plan && plan.dockerignore && typeof plan.dockerignore === 'object'
            ? plan.dockerignore
            : (typeof sp.generateImplicitDockerignore === 'function' ? sp.generateImplicitDockerignore(plan?.stack || 'node') : null);
          const dockerignore = Array.isArray(dockerignoreObj?.patterns)
            ? dockerignoreObj.patterns
            : (Array.isArray(dockerignoreObj) ? dockerignoreObj : String(dockerignoreObj || '').split(/\r?\n/).filter(Boolean));
          const resourceLimits = plan?.resourceLimits || (typeof sp.computeBuildKitResourceLimits === 'function'
            ? sp.computeBuildKitResourceLimits()
            : {});
          const dockerfile = args.includeDockerfile !== false
            ? (typeof plan?.dockerfile === 'string'
                ? plan.dockerfile
                : (typeof sp.renderDockerfileFromPlan === 'function' ? sp.renderDockerfileFromPlan(plan) : null))
            : null;
          res = {
            directory: targetDir,
            projectId: resolvedProjectId,
            stack: String(plan?.stack || plan?.framework || 'generic'),
            plan,
            dockerignore,
            resourceLimits,
            dockerfile
          };
          break;
        }

        case 'culkibo_edge_tunnel': {
          const et = requireLazySvc('edgeTunnelService', 'Culkibo EdgeTunnel');
          const action = String(args.action || 'status');
          if (action === 'status') {
            const st = et.getStatus();
            res = { action: 'status', status: st, tunnels: st.tunnels || [] };
          } else if (action === 'list') {
            const tunnels = et.listTunnels();
            res = { action: 'list', tunnels, count: tunnels.length };
          } else if (action === 'create') {
            if (!args.targetPort) {
              throw new McpToolError('MISSING_ARGUMENT', 'Falta targetPort para crear un túnel EdgeTunnel.', {
                retryable: true,
                remediation: 'Indica targetPort (1-65535), opcionalmente name, targetHost (default 127.0.0.1) y hostname.'
              });
            }
            const tunnel = et.createTunnel({
              name: args.name ? String(args.name) : `tunnel-${args.targetPort}`,
              targetHost: args.targetHost ? String(args.targetHost) : '127.0.0.1',
              targetPort: Number(args.targetPort),
              ...(args.hostname ? { hostname: String(args.hostname) } : {})
            });
            res = { action: 'create', tunnel };
          } else if (action === 'revoke') {
            if (!args.tunnelId) {
              throw new McpToolError('MISSING_ARGUMENT', 'Falta tunnelId para revocar un túnel EdgeTunnel.', {
                retryable: true,
                remediation: 'Consulta los IDs con culkibo_edge_tunnel({ action: "list" }) y pasa tunnelId.'
              });
            }
            const rev = et.revokeTunnel(String(args.tunnelId));
            res = { action: 'revoke', ...rev };
          }
          break;
        }

        case 'culkibo_verify_attestation': {
          const sca = requireLazySvc('supplyChainAttestor', 'SLSA v1.1 Supply Chain Attestor');
          const resolvedAction = args.action
            ? String(args.action)
            : (args.envelope
                ? 'verify'
                : (args.projectId && args.revision ? 'verify' : (args.projectId ? 'list' : 'public_key')));

          if (resolvedAction === 'public_key') {
            const publicKeyPem = sca.getPublicKeyPem();
            res = {
              action: 'public_key',
              valid: true,
              projectId: null,
              revision: null,
              publicKeyPem
            };
          } else if (resolvedAction === 'list') {
            /** @type {any[]} */
            let items = [];
            try {
              items = sca.listAttestations(args.projectId ? String(args.projectId) : undefined);
            } catch (e) {
              throw new McpToolError('INVALID_ARGUMENT', e.message, {
                retryable: true,
                remediation: 'Usa un projectId válido (alfanumérico, ".", "_" o "-").'
              });
            }
            if (!principal.isSuperAdmin) {
              items = items.filter((item) => canAccessProject(principal, item.projectId));
            }
            res = {
              action: 'list',
              valid: items.every((i) => i.valid !== false),
              projectId: args.projectId ? String(args.projectId) : null,
              revision: null,
              count: items.length,
              attestations: items
            };
          } else if (resolvedAction === 'get') {
            if (!args.projectId || !args.revision) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="get" requiere projectId y revision.', {
                retryable: true,
                remediation: 'Lista atestaciones disponibles con culkibo_verify_attestation({ action: "list", projectId }) y pasa revision.'
              });
            }
            /** @type {any} */
            let att = null;
            try {
              att = sca.getAttestation(String(args.projectId), String(args.revision));
            } catch (e) {
              throw new McpToolError('INVALID_ARGUMENT', e.message, {
                retryable: true,
                remediation: 'Usa identificadores projectId y revision válidos sin separadores de ruta.'
              });
            }
            if (!att) {
              throw new McpToolError('NOT_FOUND', `No existe atestación SLSA para '${args.projectId}@${args.revision}'.`, {
                retryable: false,
                remediation: 'Consulta las revisiones atestadas con culkibo_verify_attestation({ action: "list", projectId }).'
              });
            }
            res = {
              action: 'get',
              valid: Boolean(att.verification?.valid),
              projectId: String(args.projectId),
              revision: String(args.revision),
              attestation: att,
              verification: att.verification || null
            };
          } else {
            // action === 'verify'
            /** @type {any} */
            let targetEnvelope = args.envelope || null;
            if (!targetEnvelope) {
              if (!args.projectId || !args.revision) {
                throw new McpToolError('MISSING_ARGUMENT', 'Indica envelope (DSSE JSON) o projectId + revision para verificar la atestación SLSA v1.1.', {
                  retryable: true,
                  remediation: 'Pasa { envelope } para verificar offline o { projectId, revision } para verificar una release persistida.'
                });
              }
              /** @type {any} */
              let stored = null;
              try {
                stored = sca.getAttestation(String(args.projectId), String(args.revision));
              } catch (e) {
                throw new McpToolError('INVALID_ARGUMENT', e.message, {
                  retryable: true,
                  remediation: 'Usa identificadores projectId y revision válidos.'
                });
              }
              if (!stored) {
                throw new McpToolError('NOT_FOUND', `No existe atestación SLSA para '${args.projectId}@${args.revision}'.`, {
                  retryable: false,
                  remediation: 'Lista atestaciones disponibles con culkibo_verify_attestation({ action: "list", projectId }).'
                });
              }
              targetEnvelope = stored.envelope || stored;
            }
            const verification = sca.verifyAttestation(targetEnvelope, args.publicKeyPem ? String(args.publicKeyPem) : undefined);
            res = {
              action: 'verify',
              valid: Boolean(verification && verification.valid),
              projectId: args.projectId ? String(args.projectId) : null,
              revision: args.revision ? String(args.revision) : null,
              verification
            };
          }
          break;
        }

        case 'culkibo_otlp_status': {
          const otlp = requireLazySvc('otlpExporter', 'OpenTelemetry OTLP/HTTP Exporter');
          const action = String(args.action || 'status');
          if (action === 'configure') {
            /** @type {Record<string, any>} */
            const cfg = {};
            if (args.endpoint !== undefined) cfg.endpoint = args.endpoint;
            if (args.headers !== undefined) cfg.headers = args.headers;
            if (args.enabled !== undefined) cfg.enabled = Boolean(args.enabled);
            if (args.serviceName !== undefined) cfg.serviceName = String(args.serviceName);
            if (args.allowLoopback !== undefined) cfg.allowLoopback = Boolean(args.allowLoopback);
            if (args.timeoutMs !== undefined) cfg.timeoutMs = Number(args.timeoutMs);
            /** @type {any} */
            let status;
            try {
              status = otlp.configure(cfg);
            } catch (e) {
              throw new McpToolError('INVALID_ARGUMENT', e.message, {
                retryable: true,
                remediation: 'Proporciona un endpoint OTLP/HTTP válido (Grafana Tempo, SigNoz o Honeycomb) que no apunte a metadatos cloud.'
              });
            }
            res = { action: 'configure', configured: true, status };
          } else if (action === 'flush') {
            const flush = await otlp.flush();
            res = { action: 'flush', configured: Boolean(otlp.getStatus().enabled), flush, status: otlp.getStatus() };
          } else {
            const status = otlp.getStatus();
            res = { action: 'status', configured: Boolean(status.enabled), status };
          }
          break;
        }

        case 'culkibo_shadow_replay': {
          const sr = requireLazySvc('shadowReplayService', 'Shadow Traffic Replay & Cutover Gate');
          const action = String(args.action || 'run');
          if (action === 'history') {
            let replays = sr.listReplays(args.projectId ? String(args.projectId) : undefined);
            if (!principal.isSuperAdmin && !args.projectId) {
              replays = replays.filter((r) => !r.projectId || canAccessProject(principal, r.projectId));
            }
            res = {
              action: 'history',
              projectId: args.projectId ? String(args.projectId) : null,
              count: replays.length,
              replays
            };
          } else {
            if (!args.baselineUrl || !args.candidateUrl) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="run" requiere baselineUrl y candidateUrl.', {
                retryable: true,
                remediation: 'Indica baselineUrl (producción), candidateUrl (canary/green) y requests ([{ method, path }]).'
              });
            }
            if (!Array.isArray(args.requests) || args.requests.length === 0) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="run" requiere un array requests con al menos 1 petición HTTP.', {
                retryable: true,
                remediation: 'Pasa requests: [{ method: "GET", path: "/health" }] para comparar baseline vs candidate.'
              });
            }
            /** @type {any} */
            let report;
            try {
              const gateOpts = (args.gate && typeof args.gate === 'object')
                ? args.gate
                : ((args.thresholds && typeof args.thresholds === 'object') ? args.thresholds : undefined);
              report = await sr.runReplay({
                ...(args.projectId ? { projectId: String(args.projectId) } : {}),
                baselineUrl: String(args.baselineUrl),
                candidateUrl: String(args.candidateUrl),
                requests: args.requests,
                ...(gateOpts ? { gate: gateOpts } : {}),
                ...(args.allowLoopback !== undefined ? { allowLoopback: Boolean(args.allowLoopback) } : {}),
                ...(args.timeoutMs !== undefined ? { timeoutMs: Number(args.timeoutMs) } : {})
              });
            } catch (e) {
              throw new McpToolError('INVALID_ARGUMENT', e.message, {
                retryable: true,
                remediation: 'Verifica que baselineUrl/candidateUrl sean HTTP(S) válidos (metadatos cloud bloqueados; usa allowLoopback: true en hosts locales).'
              });
            }
            res = {
              action: 'run',
              projectId: args.projectId ? String(args.projectId) : null,
              ...report
            };
          }
          break;
        }

        case 'culkibo_time_machine': {
          const tms = requireLazySvc('timeMachineService', 'Whole-Stack Time-Machine');
          const project = projectManager.getById(String(args.projectId || ''));
          if (!project) throw projectNotFoundError(args.projectId);
          const action = String(args.action || 'list');

          if (action === 'list') {
            const checkpoints = tms.listCheckpoints(project.id);
            res = {
              action: 'list',
              projectId: project.id,
              dryRun: false,
              count: checkpoints.length,
              checkpoints
            };
          } else if (action === 'create') {
            const checkpoint = tms.createCheckpoint(project.id, {
              ...(args.label ? { label: String(args.label) } : {}),
              ...(args.reason ? { reason: String(args.reason) } : {}),
              actor: principal.email || principal.userId || principal.role || 'mcp'
            });
            res = {
              action: 'create',
              projectId: project.id,
              dryRun: false,
              checkpoint
            };
          } else if (action === 'diff') {
            if (!args.fromId || !args.toId) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="diff" requiere fromId y toId.', {
                retryable: true,
                remediation: 'Consulta los IDs con culkibo_time_machine({ action: "list", projectId }) y pasa fromId y toId.'
              });
            }
            /** @type {any} */
            let diff;
            try {
              diff = tms.diffCheckpoints(project.id, String(args.fromId), String(args.toId));
            } catch (e) {
              throw new McpToolError('NOT_FOUND', e.message, {
                retryable: false,
                remediation: 'Verifica que ambos checkpoint IDs existan para este proyecto con action="list".'
              });
            }
            res = {
              action: 'diff',
              projectId: project.id,
              dryRun: false,
              diff
            };
          } else {
            // action === 'restore' — dryRun defaults to true unless explicitly set to false!
            if (!args.checkpointId) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="restore" requiere checkpointId.', {
                retryable: true,
                remediation: 'Lista los checkpoints disponibles con culkibo_time_machine({ action: "list", projectId }) y pasa checkpointId.'
              });
            }
            const dryRun = args.dryRun !== false;
            /** @type {any} */
            let restoreRes;
            try {
              restoreRes = await tms.restoreCheckpoint(project.id, String(args.checkpointId), {
                dryRun,
                actor: principal.email || principal.userId || principal.role || 'mcp'
              });
            } catch (e) {
              throw new McpToolError('NOT_FOUND', e.message, {
                retryable: false,
                remediation: 'Verifica el checkpointId con culkibo_time_machine({ action: "list", projectId }).'
              });
            }
            res = {
              ...restoreRes,
              action: 'restore',
              projectId: project.id,
              dryRun,
              restored: Boolean(!dryRun && restoreRes && restoreRes.restored !== false),
              safetyCheckpointId: restoreRes?.safetyCheckpointId || restoreRes?.safetyCheckpoint?.id || null
            };
          }
          break;
        }

        case 'culkibo_finops_report': {
          const finops = requireLazySvc('finopsOptimizer', 'FinOps Cloud-vs-Self-Hosted Optimizer');
          const action = String(args.action || 'report');
          const allProjects = projectManager.getAll();
          const scopedProjects = principal.isSuperAdmin
            ? allProjects
            : allProjects.filter((p) => canAccessProject(principal, p.id, p));
          const allowedIds = new Set(scopedProjects.map((p) => p.id));
          const allDbs = databaseManager.list();
          const scopedDbs = principal.isSuperAdmin
            ? allDbs
            : allDbs.filter((d) => d.projectId && allowedIds.has(d.projectId));

          const sa = lazySvc('sleepAdvisor');
          let sleepCandidates = [];
          try {
            if (sa && typeof sa.getSleepCandidates === 'function') {
              const rawCands = sa.getSleepCandidates(principal.isSuperAdmin ? {} : { projectIds: Array.from(allowedIds) });
              sleepCandidates = Array.isArray(rawCands) ? rawCands : [];
            }
          } catch (e) {}

          const metricsHistory = typeof metricsCollector.getHistory === 'function'
            ? metricsCollector.getHistory()
            : [];

          const analysis = action === 'compare'
            ? null
            : finops.analyzeFleetAndProjects({
                projects: scopedProjects,
                databases: scopedDbs,
                metricsHistory,
                sleepCandidates
              });

          const hasCompareInputs = action === 'compare' || args.apps !== undefined || args.databases !== undefined || args.avgRamMbPerApp !== undefined || args.monthlyBandwidthGb !== undefined;
          const comparison = hasCompareInputs
            ? finops.compareCloudCosts({
                apps: args.apps !== undefined ? Number(args.apps) : Math.max(1, scopedProjects.length),
                databases: args.databases !== undefined ? Number(args.databases) : scopedDbs.length,
                ...(args.avgRamMbPerApp !== undefined ? { avgRamMbPerApp: Number(args.avgRamMbPerApp) } : {}),
                ...(args.monthlyBandwidthGb !== undefined ? { monthlyBandwidthGb: Number(args.monthlyBandwidthGb) } : {})
              })
            : (analysis?.costComparison || finops.compareCloudCosts({
                apps: Math.max(1, scopedProjects.length),
                databases: scopedDbs.length
              }));

          res = {
            action,
            scopedProjectsCount: scopedProjects.length,
            ...(analysis ? { analysis } : {}),
            comparison
          };
          break;
        }

        case 'culkibo_heal_build_failure': {
          const bh = requireLazySvc('buildHealerService', 'Deterministic 20-Pattern Build Auto-Healer');
          const logsText = String(args.logs || '');
          const project = args.projectId ? projectManager.getById(String(args.projectId)) : null;
          if (args.projectId && !project) throw projectNotFoundError(args.projectId);

          const diagnosis = bh.diagnoseLogs(logsText, {
            ...(project ? { projectId: project.id, projectName: project.name } : {})
          });

          const wantsApply = Boolean(args.apply);
          const dryRun = wantsApply ? (args.dryRun !== false) : true;
          /** @type {any} */
          let healingPlan = null;
          if (project) {
            try {
              healingPlan = await bh.applyHealingPlan(project.id, {
                logs: logsText,
                ...(args.code ? { code: String(args.code) } : (diagnosis?.primary?.code ? { code: String(diagnosis.primary.code) } : {})),
                dryRun
              });
            } catch (e) {
              throw new McpToolError('INVALID_ARGUMENT', e.message, {
                retryable: true,
                remediation: 'Revisa los parámetros projectId, logs o code y vuelve a intentarlo con dryRun: true.'
              });
            }
          } else if (wantsApply) {
            throw new McpToolError('MISSING_ARGUMENT', 'apply: true requiere indicar projectId para aplicar el plan de curación.', {
              retryable: true,
              remediation: 'Pasa projectId obtenido desde culkibo_list_projects junto con apply: true.'
            });
          }

          res = {
            projectId: project ? project.id : null,
            matched: Boolean(diagnosis && diagnosis.matched),
            dryRun,
            applied: Boolean(wantsApply && !dryRun && healingPlan && healingPlan.applied !== false),
            diagnosis,
            healingPlan
          };
          break;
        }

        case 'culkibo_fleet_mesh': {
          const fm = requireLazySvc('fleetMeshService', 'Zero-Config WireGuard Fleet Mesh');
          const action = String(args.action || 'status');
          const stripMeshSecrets = (val, depth = 0) => {
            if (depth > 6 || val === null || val === undefined || typeof val !== 'object') return val;
            if (Array.isArray(val)) return val.map((item) => stripMeshSecrets(item, depth + 1));
            /** @type {Record<string, any>} */
            const clean = {};
            for (const [k, v] of Object.entries(val)) {
              if (/^(?:privateKey|privateKeyPem|privateKeyEnc|_sealedPrivateKey|sealedPrivateKey)$/i.test(k)) continue;
              clean[k] = stripMeshSecrets(v, depth + 1);
            }
            return clean;
          };

          if (action === 'plan') {
            const plan = stripMeshSecrets(fm.planMesh(undefined, { dryRun: true }));
            const status = stripMeshSecrets(fm.getStatus());
            res = {
              action: 'plan',
              dryRun: true,
              cidr: status.cidr || '10.88.0.0/24',
              interfaceName: status.interfaceName || 'wg0',
              peerCount: Number(status.peerCount || (Array.isArray(status.peers) ? status.peers.length : 0)),
              peers: Array.isArray(status.peers) ? status.peers : [],
              plan,
              rotation: null
            };
          } else if (action === 'rotate') {
            if (!args.nodeId) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="rotate" requiere nodeId.', {
                retryable: true,
                remediation: 'Consulta los nodeId disponibles con culkibo_fleet_mesh({ action: "status" }) y pasa nodeId.'
              });
            }
            const dryRun = args.dryRun !== false;
            /** @type {any} */
            let rotation;
            try {
              rotation = stripMeshSecrets(fm.rotatePeerKey(String(args.nodeId), { dryRun }));
            } catch (e) {
              throw new McpToolError('NOT_FOUND', e.message, {
                retryable: false,
                remediation: 'Consulta los peers existentes con culkibo_fleet_mesh({ action: "status" }).'
              });
            }
            const status = stripMeshSecrets(fm.getStatus());
            res = {
              action: 'rotate',
              dryRun,
              cidr: status.cidr || '10.88.0.0/24',
              interfaceName: status.interfaceName || 'wg0',
              peerCount: Number(status.peerCount || (Array.isArray(status.peers) ? status.peers.length : 0)),
              peers: Array.isArray(status.peers) ? status.peers : [],
              plan: null,
              rotation
            };
          } else {
            const status = stripMeshSecrets(fm.getStatus());
            res = {
              action: 'status',
              dryRun: false,
              ...status,
              cidr: status.cidr || '10.88.0.0/24',
              interfaceName: status.interfaceName || 'wg0',
              peerCount: Number(status.peerCount || (Array.isArray(status.peers) ? status.peers.length : 0)),
              peers: Array.isArray(status.peers) ? status.peers : [],
              plan: null,
              rotation: null
            };
          }
          break;
        }

        case 'culkibo_cron_timeline': {
          const hours = Math.min(168, Math.max(1, Number(args.hours) || 24));
          const includeHeartbeats = args.includeHeartbeats !== false;
          const allowedProjectIds = this._accessibleProjectIds(principal);

          const timeline = typeof cronManager.getTimeline === 'function'
            ? cronManager.getTimeline({ hours, projectIds: allowedProjectIds })
            : { hours, slots: [], collisionWarnings: [] };

          let heartbeats = [];
          if (includeHeartbeats && typeof cronManager.listHeartbeats === 'function') {
            const rawHbs = cronManager.listHeartbeats(allowedProjectIds !== null ? { projectIds: allowedProjectIds } : {});
            const allowSet = allowedProjectIds !== null ? new Set(allowedProjectIds) : null;
            heartbeats = (Array.isArray(rawHbs) ? rawHbs : [])
              .filter((hb) => !allowSet || (hb && hb.projectId && allowSet.has(String(hb.projectId))))
              .map((hb) => {
                const { token: _tok, pingUrl: _url, ...safeHb } = hb || {};
                return {
                  ...safeHb,
                  hasToken: Boolean(_tok),
                  pingUrl: '/api/heartbeat/[REDACTED]'
                };
              });
          }

          res = {
            ...timeline,
            hours: Number(timeline?.hours || hours),
            slots: Array.isArray(timeline?.slots) ? timeline.slots : [],
            collisionWarnings: Array.isArray(timeline?.collisionWarnings) ? timeline.collisionWarnings : [],
            heartbeats,
            heartbeatCount: heartbeats.length
          };
          break;
        }

        case 'culkibo_edge_shield': {
          const es = requireLazySvc('edgeShieldService', 'Edge Bot-Shield & Hashcash PoW Gate');
          const action = String(args.action || 'status');
          const domainName = args.domain ? String(args.domain).trim() : null;
          const difficulty = args.difficulty !== undefined ? Math.min(6, Math.max(1, Math.round(Number(args.difficulty) || 4))) : 4;

          if (action === 'compile') {
            const targetDomain = domainName || 'example.com';
            const compiled = es.compileCaddyShieldRoutes({
              hostname: targetDomain,
              edgeShield: {
                enabled: true,
                powChallenge: Boolean(args.powChallenge),
                difficulty
              }
            });
            const routes = Array.isArray(compiled) ? compiled : (Array.isArray(compiled?.routes) ? compiled.routes : []);
            res = {
              action: 'compile',
              domain: targetDomain,
              status: null,
              routes,
              ruleCount: routes.length,
              challenge: null
            };
          } else if (action === 'challenge') {
            const challenge = es.issueChallenge({
              ip: '127.0.0.1',
              userAgent: 'culkibo-mcp-client',
              domain: domainName || 'default',
              difficulty
            });
            res = {
              action: 'challenge',
              domain: domainName || 'default',
              status: null,
              routes: [],
              challenge
            };
          } else {
            const domains = domainManager.listDomains();
            const status = es.getStatus(domains);
            res = {
              action: 'status',
              domain: domainName,
              status,
              routes: [],
              challenge: null
            };
          }
          break;
        }

        case 'culkibo_triage_playbook': {
          const project = projectManager.getById(String(args.projectId || ''));
          if (!project) throw projectNotFoundError(args.projectId);

          const incident = await this.diagnoseIncident(principal, {
            projectId: project.id,
            includeDoctor: false,
            logLines: 50
          });

          /** @type {any} */
          let healer = null;
          if (typeof args.logs === 'string' && args.logs.trim().length > 0) {
            const bh = lazySvc('buildHealerService');
            if (bh && typeof bh.diagnoseLogs === 'function') {
              healer = bh.diagnoseLogs(args.logs, { projectId: project.id, projectName: project.name });
            }
          }

          /** @type {any} */
          let drift = null;
          const dd = lazySvc('driftDetectorService');
          if (dd && typeof dd.checkProjectDrift === 'function') {
            try {
              drift = await dd.checkProjectDrift(project.id, args.actualInspect ? { actualInspect: args.actualInspect } : {});
            } catch (e) {
              drift = { ok: false, drifted: false, error: e.message };
            }
          }

          /** @type {any} */
          let cve = null;
          if (args.includeCveScan !== false) {
            const cveSvc = lazySvc('cveDriftService');
            if (cveSvc && typeof cveSvc.scanSbom === 'function') {
              try {
                cve = await cveSvc.scanSbom({ allowNetwork: false });
              } catch (e) {
                cve = { ok: false, vulnerableCount: 0, error: e.message };
              }
            }
          }

          /** @type {Array<{ source: string, code: string, severity: string, title: string }>} */
          const rootCauses = [];
          /** @type {Array<{ priority: number, tool: string, arguments: Record<string, any>, rationale: string }>} */
          const remediationSteps = [];

          if (Array.isArray(incident?.rootCauses)) {
            for (const rc of incident.rootCauses) {
              rootCauses.push({
                source: 'incident',
                code: String(rc.code || 'INCIDENT'),
                severity: String(rc.severity || 'warning'),
                title: String(rc.title || rc.code || 'Incident detected')
              });
            }
          }
          if (healer && healer.matched && healer.primary) {
            rootCauses.push({
              source: 'build_healer',
              code: String(healer.primary.code),
              severity: String(healer.primary.severity || 'high'),
              title: String(healer.primary.title || healer.primary.code)
            });
            remediationSteps.push({
              priority: 1,
              tool: 'culkibo_heal_build_failure',
              arguments: { projectId: project.id, code: healer.primary.code, logs: String(args.logs || '').slice(0, 4000), apply: true, dryRun: true },
              rationale: `Previsualizar parche seguro para ${healer.primary.code}: ${healer.primary.rootCause || healer.primary.title}`
            });
          }
          if (drift && drift.drifted && Array.isArray(drift.diffs) && drift.diffs.length > 0) {
            rootCauses.push({
              source: 'config_drift',
              code: 'CONFIG_DRIFT_DETECTED',
              severity: String(drift.severity || 'high'),
              title: `${drift.diffs.length} diferencia(s) de configuración entre contenedor vivo y estado declarado`
            });
            remediationSteps.push({
              priority: 2,
              tool: 'culkibo_time_machine',
              arguments: { action: 'list', projectId: project.id },
              rationale: 'Inspeccionar último checkpoint sano o reconciliar configuración declarada sin cortes (dryRun).'
            });
          }
          const cveCount = Number(cve?.totalVulnerabilities ?? cve?.vulnerableCount ?? 0);
          const cveCritCount = Number(cve?.bySeverity?.critical ?? cve?.severityCounts?.critical ?? 0);
          if (cve && cveCount > 0) {
            rootCauses.push({
              source: 'sbom_cve',
              code: 'SBOM_CVE_DRIFT',
              severity: cveCritCount > 0 ? 'critical' : 'high',
              title: `${cveCount} vulnerabilidad(es) CVE reportadas en el SBOM CycloneDX`
            });
            remediationSteps.push({
              priority: 3,
              tool: 'culkibo_cve_scan',
              arguments: { allowNetwork: true, forceRefresh: true },
              rationale: 'Refrescar estado OSV.dev y planificar actualización de dependencias afectadas.'
            });
          }
          if (remediationSteps.length === 0) {
            remediationSteps.push({
              priority: 1,
              tool: 'culkibo_auto_remediate',
              arguments: { action: 'restart_service', projectId: project.id, dryRun: true },
              rationale: 'Sin fallos críticos inmediatos; usa dryRun antes de cualquier reinicio o rollback preventivo.'
            });
          }

          const sevOrder = { critical: 4, high: 3, degraded: 2, warning: 1, healthy: 0 };
          let topSev = String(incident?.severity || 'healthy');
          for (const rc of rootCauses) {
            if ((sevOrder[/** @type {keyof typeof sevOrder} */ (rc.severity)] || 0) > (sevOrder[/** @type {keyof typeof sevOrder} */ (topSev)] || 0)) {
              topSev = rc.severity;
            }
          }

          res = {
            projectId: project.id,
            projectName: project.name,
            severity: topSev,
            summary: rootCauses.length === 0
              ? `Triaje unificado limpio para '${project.name}' (0 fallos críticos en incidente, healer, drift y SBOM CVE).`
              : `Triaje unificado para '${project.name}' [${topSev}]: ${rootCauses.length} hallazgo(s) correlacionados y ${remediationSteps.length} paso(s) dryRun recomendados.`,
            incident,
            healer,
            drift,
            cve,
            rootCauses,
            remediationSteps
          };
          break;
        }

        case 'culkibo_cve_scan': {
          const cveSvc = requireLazySvc('cveDriftService', 'Runtime SBOM CVE Drift Scanner');
          const scan = await cveSvc.scanSbom({
            allowNetwork: Boolean(args.allowNetwork),
            forceRefresh: Boolean(args.forceRefresh)
          });
          res = {
            ...scan,
            ok: scan && scan.ok !== false,
            mode: String(scan?.source || scan?.mode || (scan?.offline ? 'offline_fallback' : (args.allowNetwork ? 'osv.dev' : 'offline_fallback'))),
            scannedComponents: Number(scan?.scannedPackages ?? scan?.scannedComponents ?? 0),
            vulnerableCount: Number(scan?.totalVulnerabilities ?? scan?.vulnerableCount ?? 0),
            severityCounts: scan?.bySeverity || scan?.severityCounts || { critical: 0, high: 0, medium: 0, low: 0 },
            vulnerabilities: Array.isArray(scan?.findings)
              ? scan.findings
              : (Array.isArray(scan?.vulnerabilities) ? scan.vulnerabilities : [])
          };
          break;
        }

        case 'culkibo_drift_check': {
          const dd = requireLazySvc('driftDetectorService', 'Container/DB Config Drift Detector');
          if (!args.projectId && !args.pgbouncerPreset) {
            throw new McpToolError('MISSING_ARGUMENT', 'Indica projectId (para auditar drift) y/o pgbouncerPreset (para generar configuración PgBouncer).', {
              retryable: true,
              remediation: 'Pasa projectId obtenido de culkibo_list_projects o un objeto pgbouncerPreset.'
            });
          }

          /** @type {any} */
          let drift = null;
          if (args.projectId) {
            const project = projectManager.getById(String(args.projectId));
            if (!project) throw projectNotFoundError(args.projectId);
            drift = await dd.checkProjectDrift(project.id, args.actualInspect ? { actualInspect: args.actualInspect } : {});
          }

          /** @type {any} */
          let pgbouncerPreset = null;
          if (args.pgbouncerPreset && typeof args.pgbouncerPreset === 'object') {
            try {
              pgbouncerPreset = dd.buildPgBouncerPreset(args.pgbouncerPreset);
            } catch (e) {
              throw new McpToolError('INVALID_ARGUMENT', e.message, {
                retryable: true,
                remediation: 'Usa identificadores alfanuméricos válidos para name/databaseName y puertos/límites numéricos en pgbouncerPreset.'
              });
            }
          }

          res = {
            projectId: args.projectId ? String(args.projectId) : null,
            drift,
            pgbouncerPreset
          };
          break;
        }

        case 'culkibo_export_iac': {
          const iac = requireLazySvc('iacExporter', 'OpenTofu/Terraform & Compose IaC Exporter');
          const rawFmt = String(args.format || 'all');
          /** @type {'all' | 'terraform' | 'compose'} */
          const format = rawFmt === 'terraform' ? 'terraform' : (rawFmt === 'compose' ? 'compose' : 'all');
          const accessibleIds = this._accessibleProjectIds(principal);
          /** @type {string[] | null} */
          let effectiveProjectIds = accessibleIds;

          if (Array.isArray(args.projectIds) && args.projectIds.length > 0) {
            const requested = args.projectIds.map((id) => String(id));
            if (accessibleIds !== null) {
              const allowSet = new Set(accessibleIds);
              for (const reqId of requested) {
                if (!allowSet.has(reqId)) {
                  throw new McpToolError('FORBIDDEN', 'No tienes acceso a uno o más proyectos solicitados para exportar IaC.', {
                    retryable: false,
                    remediation: 'Omite projectIds o incluye únicamente proyectos devueltos por culkibo_list_projects.'
                  });
                }
              }
            }
            effectiveProjectIds = requested;
          }

          const exported = iac.exportEstate({
            format,
            projectIds: effectiveProjectIds
          });
          res = {
            ...exported,
            ok: true,
            format,
            files: exported?.files || {},
            stats: exported?.stats || {},
            secretsRedactedCount: Number(exported?.secretsRedactedCount || 0)
          };
          break;
        }

        case 'culkibo_secret_lease': {
          const sls = requireLazySvc('secretLeaseService', 'Ephemeral Secret Leases & Break-Glass');
          const action = String(args.action || 'list');

          if (action === 'list') {
            const leases = sls.listLeases({
              ...(args.projectId ? { projectId: String(args.projectId) } : {}),
              includeExpired: Boolean(args.includeExpired)
            });
            res = {
              action: 'list',
              dryRun: false,
              leases: Array.isArray(leases) ? leases : [],
              lease: null,
              audit: null,
              revoked: false
            };
          } else if (action === 'audit_rotation') {
            const audit = sls.auditSecretRotationAges(projectManager.getAll(), {
              maxAgeDays: Math.max(1, Number(args.maxAgeDays) || 90)
            });
            res = {
              action: 'audit_rotation',
              dryRun: false,
              leases: [],
              lease: null,
              audit,
              revoked: false
            };
          } else if (action === 'issue') {
            if (!args.projectId || !args.secretKey) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="issue" requiere projectId y secretKey.', {
                retryable: true,
                remediation: 'Indica projectId y secretKey (y dryRun: false tras confirmar el plan).'
              });
            }
            const dryRun = args.dryRun !== false;
            const ttlSec = Math.min(86400, Math.max(60, Number(args.ttlSec) || 3600));
            const scope = ['read', 'write', 'admin'].includes(String(args.scope || 'read')) ? String(args.scope || 'read') : 'read';
            if (dryRun) {
              res = {
                action: 'issue',
                dryRun: true,
                issued: false,
                leases: [],
                lease: null,
                audit: null,
                revoked: false,
                wouldIssue: { projectId: String(args.projectId), secretKey: String(args.secretKey), scope, ttlSec }
              };
            } else {
              const issued = sls.issueLease({
                projectId: String(args.projectId),
                secretKey: String(args.secretKey),
                scope,
                ttlSec,
                issuedBy: principal.email || principal.userId || principal.role || 'mcp-admin',
                reason: args.reason ? String(args.reason) : 'Issued via MCP culkibo_secret_lease'
              });
              res = {
                action: 'issue',
                dryRun: false,
                issued: true,
                leases: [],
                lease: issued.lease || null,
                token: issued.token,
                audit: null,
                revoked: false
              };
            }
          } else if (action === 'revoke') {
            if (!args.leaseId) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="revoke" requiere leaseId.', {
                retryable: true,
                remediation: 'Consulta los IDs con culkibo_secret_lease({ action: "list" }) y pasa leaseId.'
              });
            }
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              res = {
                action: 'revoke',
                dryRun: true,
                leases: [],
                lease: null,
                audit: null,
                revoked: false,
                wouldRevokeLeaseId: String(args.leaseId)
              };
            } else {
              const rev = sls.revokeLease(String(args.leaseId), {
                revokedBy: principal.email || principal.userId || principal.role || 'mcp-admin'
              });
              res = {
                action: 'revoke',
                dryRun: false,
                leases: [],
                lease: rev?.lease || null,
                audit: null,
                revoked: Boolean(rev && rev.revoked !== false)
              };
            }
          } else {
            // action === 'break_glass'
            const reason = String(args.reason || '').trim();
            if (reason.length < 10) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="break_glass" exige reason de al menos 10 caracteres para auditoría.', {
                retryable: true,
                remediation: 'Proporciona un motivo operativo detallado (ej. "INC-402 emergency production DB recovery").'
              });
            }
            const dryRun = args.dryRun !== false;
            const ttlSec = Math.min(900, Math.max(60, Number(args.ttlSec) || 900));
            if (dryRun) {
              res = {
                action: 'break_glass',
                dryRun: true,
                issued: false,
                leases: [],
                lease: null,
                audit: null,
                revoked: false,
                wouldIssueBreakGlass: { ttlSec, reason }
              };
            } else {
              const bg = sls.issueBreakGlassToken({
                userId: principal.userId || 'owner',
                username: principal.email || principal.userId || 'mcp-admin',
                reason,
                ttlSec
              });
              res = {
                action: 'break_glass',
                dryRun: false,
                issued: true,
                leases: [],
                lease: bg.lease || null,
                token: bg.token,
                audit: null,
                revoked: false
              };
            }
          }
          break;
        }

        case 'culkibo_webhook_dlq': {
          const whBus = requireLazySvc('webhookEventBus', 'Standard-Webhooks Event Bus & DLQ');
          const action = String(args.action || 'list_dlq');

          if (action === 'list_dlq') {
            const entries = whBus.listDlq({
              limit: Math.min(200, Math.max(1, Number(args.limit) || 50)),
              ...(args.status ? { status: String(args.status) } : {})
            });
            const list = Array.isArray(entries) ? entries : [];
            res = {
              action: 'list_dlq',
              dryRun: false,
              entries: list,
              subscriptions: [],
              count: list.length,
              replayed: false,
              rotated: false
            };
          } else if (action === 'list_subscriptions') {
            const subs = whBus.listSubscriptions();
            const list = Array.isArray(subs) ? subs : [];
            res = {
              action: 'list_subscriptions',
              dryRun: false,
              entries: [],
              subscriptions: list,
              count: list.length,
              replayed: false,
              rotated: false
            };
          } else if (action === 'replay') {
            if (!args.dlqId) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="replay" requiere dlqId (o "all").', {
                retryable: true,
                remediation: 'Lista la cola con culkibo_webhook_dlq({ action: "list_dlq" }) y pasa dlqId.'
              });
            }
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              res = {
                action: 'replay',
                dryRun: true,
                dlqId: String(args.dlqId),
                entries: [],
                subscriptions: [],
                count: 0,
                replayed: false,
                rotated: false,
                wouldReplay: { dlqId: String(args.dlqId) }
              };
            } else {
              try {
                const replayRes = String(args.dlqId) === 'all'
                  ? await whBus.replayAllFailed()
                  : await whBus.replayDlqEntry(String(args.dlqId));
                res = {
                  action: 'replay',
                  dryRun: false,
                  dlqId: String(args.dlqId),
                  entries: [],
                  subscriptions: [],
                  count: 0,
                  replayed: Boolean(replayRes && replayRes.ok !== false && replayRes.delivered !== false),
                  rotated: false,
                  result: replayRes
                };
              } catch (e) {
                throw new McpToolError(e.code || 'WEBHOOK_REPLAY_FAILED', e.message || 'No se pudo reintentar la entrega DLQ.', {
                  retryable: true,
                  remediation: 'Verifica que el dlqId exista y que la URL destino no apunte a direcciones internas bloqueadas por SSRF.'
                });
              }
            }
          } else {
            // action === 'rotate_secret'
            if (!args.subscriptionId) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="rotate_secret" requiere subscriptionId.', {
                retryable: true,
                remediation: 'Consulta IDs con culkibo_webhook_dlq({ action: "list_subscriptions" }) y pasa subscriptionId.'
              });
            }
            const dryRun = args.dryRun !== false;
            const graceSec = Math.min(604800, Math.max(60, Number(args.graceSec) || 86400));
            if (dryRun) {
              res = {
                action: 'rotate_secret',
                dryRun: true,
                subscriptionId: String(args.subscriptionId),
                graceSec,
                entries: [],
                subscriptions: [],
                count: 0,
                replayed: false,
                rotated: false,
                wouldRotate: { subscriptionId: String(args.subscriptionId), graceSec }
              };
            } else {
              try {
                const rot = whBus.rotateSecret(String(args.subscriptionId), { graceSec });
                res = {
                  action: 'rotate_secret',
                  dryRun: false,
                  subscriptionId: String(args.subscriptionId),
                  graceSec,
                  entries: [],
                  subscriptions: [],
                  count: 0,
                  replayed: false,
                  rotated: Boolean(rot && rot.ok !== false),
                  rotation: rot
                };
              } catch (e) {
                throw new McpToolError(e.code || 'WEBHOOK_ROTATE_FAILED', e.message || 'No se pudo rotar el secreto del webhook.', {
                  retryable: false,
                  remediation: 'Comprueba que subscriptionId exista mediante action="list_subscriptions".'
                });
              }
            }
          }
          break;
        }

        case 'culkibo_db_studio': {
          const dbStudio = requireLazySvc('dbStudioService', 'Read-Only Live DB Studio & Safe Redis Inspector');
          const mode = String(args.mode || 'sql');
          const db = args.databaseId ? databaseManager.list().find((d) => d.id === String(args.databaseId)) : null;
          if (args.databaseId && !db) {
            throw new McpToolError('DATABASE_NOT_FOUND', `Base de datos '${args.databaseId}' no encontrada.`, {
              retryable: false,
              remediation: 'Lista las bases de datos autorizadas con culkibo_list_databases.'
            });
          }
          if (db && !principal.isSuperAdmin && !canAccessProject(principal, db.projectId)) {
            throw new McpToolError('FORBIDDEN', `No tienes acceso a la base de datos '${db.id}'.`, {
              retryable: false,
              remediation: 'Usa un databaseId perteneciente a tus proyectos autorizados.'
            });
          }

          if (mode === 'sql') {
            if (!args.query || typeof args.query !== 'string') {
              throw new McpToolError('MISSING_ARGUMENT', 'mode="sql" requiere una consulta SQL de solo lectura en query.', {
                retryable: true,
                remediation: 'Pasa una consulta SELECT, EXPLAIN, SHOW o WITH en el argumento query.'
              });
            }
            try {
              const out = await dbStudio.runReadOnlyQuery({
                databaseId: db ? db.id : (args.databaseId ? String(args.databaseId) : 'studio'),
                engine: db?.engine || 'postgres',
                query: args.query,
                maxRows: Math.min(200, Math.max(1, Number(args.maxRows) || 200))
              });
              if (out && out.ok === false) {
                throw new McpToolError(out.code || 'SQL_WRITE_BLOCKED', out.error || out.message || 'Consulta SQL bloqueada por la puerta de solo lectura.', {
                  retryable: false,
                  remediation: 'Elimina cualquier sentencia de escritura, DDL/DML, comentario ofuscado, metacomando psql o sentencia apilada.'
                });
              }
              res = {
                ok: true,
                mode: 'sql',
                databaseId: db ? db.id : null,
                readOnlyEnforced: true,
                result: out
              };
            } catch (e) {
              if (e instanceof McpToolError) throw e;
              throw new McpToolError(e.code || 'SQL_WRITE_BLOCKED', e.message || 'Consulta SQL bloqueada por la puerta de solo lectura.', {
                retryable: false,
                remediation: 'Usa únicamente consultas SELECT, EXPLAIN, SHOW o WITH de solo lectura (LIMIT <= 200, sin sentencias apiladas).'
              });
            }
          } else if (mode === 'redis') {
            if (!args.argv || (typeof args.argv !== 'string' && !Array.isArray(args.argv))) {
              throw new McpToolError('MISSING_ARGUMENT', 'mode="redis" requiere argv (ej. ["SCAN", "0", "COUNT", "50"] o "INFO memory").', {
                retryable: true,
                remediation: 'Pasa un comando seguro de solo lectura en argv (SCAN, TYPE, TTL, DBSIZE, INFO, GET, etc.).'
              });
            }
            try {
              const out = await dbStudio.runSafeRedisInspect({
                databaseId: db ? db.id : (args.databaseId ? String(args.databaseId) : 'redis'),
                argv: args.argv
              });
              if (out && out.ok === false) {
                throw new McpToolError(out.code || 'REDIS_COMMAND_BLOCKED', out.error || out.message || 'Comando Redis bloqueado por política de solo lectura.', {
                  retryable: false,
                  remediation: 'Usa solo comandos de la allowlist segura (SCAN, TYPE, TTL, PTTL, DBSIZE, INFO, STRLEN, LLEN, HLEN, SCARD, ZCARD, GET).'
                });
              }
              res = {
                ok: true,
                mode: 'redis',
                databaseId: db ? db.id : null,
                readOnlyEnforced: true,
                result: out
              };
            } catch (e) {
              if (e instanceof McpToolError) throw e;
              throw new McpToolError(e.code || 'REDIS_COMMAND_BLOCKED', e.message || 'Comando Redis bloqueado por política de solo lectura.', {
                retryable: false,
                remediation: 'Evita KEYS/FLUSHALL/CONFIG/EVAL y utiliza SCAN (COUNT <= 100), INFO, DBSIZE, TTL o GET.'
              });
            }
          } else {
            const bloat = dbStudio.analyzePostgresBloat(Array.isArray(args.tableStats) ? args.tableStats : []);
            res = {
              ok: true,
              mode: 'bloat',
              databaseId: db ? db.id : null,
              readOnlyEnforced: true,
              result: bloat
            };
          }
          break;
        }

        case 'culkibo_s3_storage': {
          const s3Svc = requireLazySvc('objectStorageService', 'Post-MinIO S3 Storage Orchestrator & SigV4 Presigner');
          const action = String(args.action || 'presets');

          if (action === 'presets') {
            if (args.presetId) {
              const preset = s3Svc.getPreset(String(args.presetId));
              if (!preset) {
                throw new McpToolError('PRESET_NOT_FOUND', `Preset S3 desconocido: '${args.presetId}'.`, {
                  retryable: true,
                  remediation: 'Usa uno de los presets soportados: garage, rustfs o seaweedfs.'
                });
              }
              res = { ok: true, action: 'presets', presets: [preset], preset, presigned: null, xml: null };
            } else {
              const presets = s3Svc.listPresets();
              res = { ok: true, action: 'presets', presets: Array.isArray(presets) ? presets : [], preset: null, presigned: null, xml: null };
            }
          } else if (action === 'presign') {
            if (!args.endpoint || !args.bucket || !args.key || !args.accessKeyId || !args.secretAccessKey) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="presign" requiere endpoint, bucket, key, accessKeyId y secretAccessKey.', {
                retryable: true,
                remediation: 'Proporciona endpoint, bucket, key, accessKeyId y secretAccessKey (nunca se registran secretos en auditoría).'
              });
            }
            try {
              const presigned = s3Svc.generatePresignedUrl({
                endpoint: String(args.endpoint),
                region: String(args.region || 'us-east-1'),
                bucket: String(args.bucket),
                key: String(args.key),
                method: String(args.method || 'GET'),
                accessKeyId: String(args.accessKeyId),
                secretAccessKey: String(args.secretAccessKey),
                expiresIn: args.expiresIn !== undefined ? Number(args.expiresIn) : 900
              });
              res = { ok: true, action: 'presign', presets: [], preset: null, presigned, xml: null };
            } catch (e) {
              throw new McpToolError(e.code || 'INVALID_S3_PRESIGN', e.message || 'Parámetros SigV4 inválidos.', {
                retryable: true,
                remediation: 'Valida bucket RFC, key sin "..", método GET/PUT/HEAD/DELETE y expiresIn entre 60 y 604800.'
              });
            }
          } else if (action === 'cors_xml') {
            try {
              const out = s3Svc.buildBucketCorsXml(Array.isArray(args.rules) ? args.rules : []);
              const xml = typeof out === 'string' ? out : String(out?.xml || '');
              res = { ok: true, action: 'cors_xml', presets: [], preset: null, presigned: null, xml };
            } catch (e) {
              throw new McpToolError(e.code || 'INVALID_S3_CORS', e.message || 'Reglas CORS S3 inválidas.', {
                retryable: true,
                remediation: 'Proporciona orígenes/métodos válidos y nunca combines origen "*" con allowCredentials: true.'
              });
            }
          } else {
            // action === 'lifecycle_xml'
            try {
              const out = s3Svc.buildLifecycleXml(Array.isArray(args.rules) ? args.rules : []);
              const xml = typeof out === 'string' ? out : String(out?.xml || '');
              res = { ok: true, action: 'lifecycle_xml', presets: [], preset: null, presigned: null, xml };
            } catch (e) {
              throw new McpToolError(e.code || 'INVALID_S3_LIFECYCLE', e.message || 'Reglas Lifecycle S3 inválidas.', {
                retryable: true,
                remediation: 'Define reglas con id, prefix y expirationDays o abortMultipartDays positivos.'
              });
            }
          }
          break;
        }

        case 'culkibo_agency_ledger': {
          const quotaSvc = requireLazySvc('quotaMeteringService', 'Agency Multi-Tenant Quotas & Billing Usage Ledger');
          const action = String(args.action || 'ledger');
          const allowedProjectIds = this._accessibleProjectIds(principal);

          if (args.projectId && !principal.isSuperAdmin && !canAccessProject(principal, String(args.projectId))) {
            throw new McpToolError('FORBIDDEN', `No tienes acceso al proyecto '${args.projectId}'.`, {
              retryable: false,
              remediation: 'Omite projectId o indica un proyecto autorizado desde culkibo_list_projects.'
            });
          }

          const visibleProjects = projectManager.getAll().filter((p) => canAccessProject(principal, p.id, p));
          const scopedProjects = args.projectId
            ? visibleProjects.filter((p) => p.id === String(args.projectId))
            : visibleProjects;
          const visibleDbs = databaseManager.list().filter((d) => {
            if (!principal.isSuperAdmin && !canAccessProject(principal, d.projectId)) return false;
            if (args.projectId && d.projectId !== String(args.projectId)) return false;
            return true;
          });
          const effectiveAllowed = args.projectId ? [String(args.projectId)] : allowedProjectIds;
          const periodDays = Math.min(365, Math.max(1, Number(args.periodDays) || 30));

          if (action === 'ledger' || action === 'csv') {
            const ledger = quotaSvc.buildUsageLedger({
              projects: scopedProjects,
              databases: visibleDbs,
              allowedProjectIds: effectiveAllowed,
              periodDays
            });
            const csv = action === 'csv' ? quotaSvc.exportLedgerCsv(ledger) : null;
            res = { ok: true, action, ledger, csv, quotas: [], check: null };
          } else if (action === 'list_quotas') {
            const qRes = quotaSvc.listQuotas({ allowedProjectIds: effectiveAllowed });
            const quotasList = Array.isArray(qRes) ? qRes : (Array.isArray(qRes?.quotas) ? qRes.quotas : []);
            res = { ok: true, action: 'list_quotas', ledger: null, csv: null, quotas: quotasList, defaults: qRes?.defaults || null, check: null };
          } else {
            // action === 'check_quota'
            if (!args.projectId) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="check_quota" requiere projectId.', {
                retryable: true,
                remediation: 'Pasa projectId obtenido de culkibo_list_projects junto con requested.'
              });
            }
            const check = quotaSvc.checkQuotaAllowance(String(args.projectId), args.requested && typeof args.requested === 'object' ? args.requested : {});
            res = { ok: true, action: 'check_quota', ledger: null, csv: null, quotas: [], check };
          }
          break;
        }

        case 'culkibo_brand_theme': {
          const brandSvc = requireLazySvc('brandThemeService', 'Open-Core White-Label Brand & Custom Login Theme');
          const action = String(args.action || 'get');

          if (action === 'get') {
            const brand = brandSvc.getBrand();
            res = { action: 'get', dryRun: false, updated: false, brand };
          } else if (action === 'update') {
            if (!principal.isSuperAdmin && ((ROLE_RANK[principal.role] || 0) < ROLE_RANK.admin || Array.isArray(principal.projectIds))) {
              throw new McpToolError('FORBIDDEN', 'Actualizar la marca white-label requiere rol admin/owner sin restricción de proyectos.', {
                retryable: false,
                remediation: 'Autentícate como admin/owner o usa action: "get".'
              });
            }
            if (!args.patch || typeof args.patch !== 'object' || Array.isArray(args.patch)) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="update" requiere un objeto patch.', {
                retryable: true,
                remediation: 'Pasa patch con campos válidos ({ brandName, tagline, accentHex, logoUrl, supportUrl, hidePoweredBy }).'
              });
            }
            try {
              const validation = brandSvc.validateBrandPatch(args.patch);
              if (validation && validation.valid === false) {
                throw new McpToolError('INVALID_BRAND_PATCH', validation.error || 'Configuración de marca rechazada por validación anti-XSS/CSS.', {
                  retryable: true,
                  remediation: 'Usa accentHex #RRGGBB, supportUrl https:// y logoUrl https:// o data:image/svg+xml sanitizado.'
                });
              }
            } catch (e) {
              if (e instanceof McpToolError) throw e;
              throw new McpToolError(e.code || 'INVALID_BRAND_PATCH', e.message || 'Configuración de marca inválida.', {
                retryable: true,
                remediation: 'Corrige los campos rechazados para cumplir las reglas estrictas anti-XSS y anti-CSS-injection.'
              });
            }
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              res = {
                action: 'update',
                dryRun: true,
                updated: false,
                brand: brandSvc.getBrand(),
                previewPatch: args.patch
              };
            } else {
              const actor = principal.email || principal.userId || principal.role || 'mcp-admin';
              const brand = brandSvc.updateBrand(args.patch, { actor });
              res = { action: 'update', dryRun: false, updated: true, brand };
            }
          } else {
            // action === 'reset'
            if (!principal.isSuperAdmin && ((ROLE_RANK[principal.role] || 0) < ROLE_RANK.admin || Array.isArray(principal.projectIds))) {
              throw new McpToolError('FORBIDDEN', 'Restablecer la marca white-label requiere rol admin/owner sin restricción de proyectos.', {
                retryable: false,
                remediation: 'Autentícate como admin/owner o usa action: "get".'
              });
            }
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              res = {
                action: 'reset',
                dryRun: true,
                updated: false,
                brand: brandSvc.getBrand(),
                wouldResetToDefault: true
              };
            } else {
              const actor = principal.email || principal.userId || principal.role || 'mcp-admin';
              const brand = brandSvc.resetBrand({ actor });
              res = { action: 'reset', dryRun: false, updated: true, brand };
            }
          }
          break;
        }

        case 'culkibo_dr_drill': {
          const drSvc = requireLazySvc('backupDrillService', 'Automated DR Backup Fire-Drill Verifier');
          const action = String(args.action || 'list_drills');

          if (action === 'list_drills') {
            const raw = drSvc.listDrills(args.databaseId ? String(args.databaseId) : undefined);
            const allDrills = Array.isArray(raw) ? raw : (Array.isArray(raw?.drills) ? raw.drills : []);
            const accessibleDbIds = new Set(
              databaseManager.list()
                .filter((d) => principal.isSuperAdmin || canAccessProject(principal, d.projectId))
                .map((d) => d.id)
            );
            const filtered = principal.isSuperAdmin
              ? allDrills
              : allDrills.filter((d) => {
                  if (d.projectId) return canAccessProject(principal, d.projectId);
                  if (d.databaseId && accessibleDbIds.has(d.databaseId)) return true;
                  return false;
                });
            res = { ok: true, action: 'list_drills', verdict: null, drill: null, drills: filtered, restorePlan: null };
          } else if (action === 'run_drill') {
            const db = args.databaseId ? databaseManager.list().find((d) => d.id === String(args.databaseId)) : null;
            if (db && !principal.isSuperAdmin && !canAccessProject(principal, db.projectId)) {
              throw new McpToolError('FORBIDDEN', `No tienes acceso a la base de datos '${db.id}'.`, {
                retryable: false,
                remediation: 'Usa un databaseId perteneciente a tus proyectos autorizados.'
              });
            }
            const targetProjectId = args.projectId ? String(args.projectId) : (db?.projectId || '');
            if (targetProjectId && !principal.isSuperAdmin && !canAccessProject(principal, targetProjectId)) {
              throw new McpToolError('FORBIDDEN', `No tienes acceso al proyecto '${targetProjectId}'.`, {
                retryable: false,
                remediation: 'Indica un projectId autorizado desde culkibo_list_projects.'
              });
            }
            /** @type {Buffer | undefined} */
            let artifactBuffer;
            if (typeof args.artifactBase64 === 'string') {
              artifactBuffer = Buffer.from(args.artifactBase64, 'base64');
            } else if (typeof args.sqlSample === 'string') {
              artifactBuffer = Buffer.from(args.sqlSample, 'utf8');
            }
            if (artifactBuffer === undefined && !args.artifactPath) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="run_drill" requiere sqlSample, artifactBase64 o artifactPath.', {
                retryable: true,
                remediation: 'Pasa artifactBase64, sqlSample o artifactPath del backup a verificar.'
              });
            }
            try {
              const drill = await drSvc.runFireDrill({
                databaseId: args.databaseId ? String(args.databaseId) : (db?.id || 'db_drill'),
                projectId: targetProjectId,
                engine: String(args.engine || db?.engine || 'postgres'),
                ...(artifactBuffer !== undefined ? { artifactBuffer } : {}),
                ...(args.artifactPath ? { artifactPath: String(args.artifactPath) } : {}),
                ...(args.expectedSha256 ? { expectedSha256: String(args.expectedSha256) } : {}),
                preserveAcl: args.preserveAcl !== false,
                ...(args.sourceMajorVersion !== undefined ? { sourceMajorVersion: Number(args.sourceMajorVersion) } : {}),
                ...(args.targetMajorVersion !== undefined ? { targetMajorVersion: Number(args.targetMajorVersion) } : {})
              });
              res = {
                ok: drill.verdict === 'PASS',
                action: 'run_drill',
                verdict: drill.verdict,
                drill,
                drills: [],
                restorePlan: null
              };
            } catch (e) {
              throw new McpToolError(e.code || 'DR_DRILL_ERROR', e.message || 'Error ejecutando DR Fire-Drill.', {
                retryable: false,
                remediation: 'Revisa la ruta/payload del backup y los parámetros del motor SQL.'
              });
            }
          } else {
            // action === 'cross_restore_plan'
            if (!args.sourceDatabaseId || !args.targetDatabaseId || !args.sourceOrgId || !args.targetOrgId) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="cross_restore_plan" requiere sourceDatabaseId, targetDatabaseId, sourceOrgId y targetOrgId.', {
                retryable: true,
                remediation: 'Especifica ambos databaseId y ambos orgId para validar aislamiento organizativo.'
              });
            }
            try {
              const restorePlan = drSvc.planCrossTargetRestore({
                sourceDatabaseId: String(args.sourceDatabaseId),
                targetDatabaseId: String(args.targetDatabaseId),
                sourceOrgId: String(args.sourceOrgId),
                targetOrgId: String(args.targetOrgId),
                engine: String(args.engine || 'postgres'),
                preserveAcl: args.preserveAcl !== false
              });
              res = { ok: true, action: 'cross_restore_plan', verdict: 'ALLOWED', drill: null, drills: [], restorePlan };
            } catch (e) {
              throw new McpToolError(e.code || 'CROSS_ORG_RESTORE_FORBIDDEN', e.message || 'Restauración cross-target rechazada.', {
                retryable: false,
                remediation: 'Solo se permiten restauraciones cross-target dentro de la misma organización (sourceOrgId === targetOrgId).'
              });
            }
          }
          break;
        }

        case 'culkibo_slo_canary': {
          const sloSvc = requireLazySvc('sloCanaryController', 'SLO Error-Budget Canary Auto-Rollback Controller');
          const action = String(args.action || 'list');

          if (action === 'list') {
            const raw = sloSvc.listRollouts(args.projectId ? String(args.projectId) : undefined);
            const list = (Array.isArray(raw) ? raw : []).filter((r) => principal.isSuperAdmin || canAccessProject(principal, r.projectId));
            res = { ok: true, action: 'list', dryRun: false, rollout: null, rollouts: list, caddyRoute: null };
          } else if (action === 'start') {
            if (!args.projectId || !args.hostname || !args.stableUpstream || !args.canaryUpstream) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="start" requiere projectId, hostname, stableUpstream y canaryUpstream.', {
                retryable: true,
                remediation: 'Proporciona projectId, hostname, stableUpstream y canaryUpstream (dryRun: true por defecto).'
              });
            }
            const steps = Array.isArray(args.steps) && args.steps.length > 0 ? args.steps.map(Number) : [10, 25, 50, 100];
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              const caddyRoute = sloSvc.buildCaddyWeightedRoute({
                hostname: String(args.hostname),
                stableUpstream: String(args.stableUpstream),
                canaryUpstream: String(args.canaryUpstream),
                canaryWeight: steps[0]
              });
              res = {
                ok: true,
                action: 'start',
                dryRun: true,
                started: false,
                rollout: null,
                rollouts: [],
                caddyRoute
              };
            } else {
              try {
                const rollout = await sloSvc.startRollout({
                  projectId: String(args.projectId),
                  hostname: String(args.hostname),
                  stableUpstream: String(args.stableUpstream),
                  canaryUpstream: String(args.canaryUpstream),
                  steps,
                  ...(args.sloTarget !== undefined ? { sloTarget: Number(args.sloTarget) } : {}),
                  ...(args.maxBurnRate !== undefined ? { maxBurnRate: Number(args.maxBurnRate) } : {}),
                  ...(args.maxLatencyRatio !== undefined ? { maxLatencyRatio: Number(args.maxLatencyRatio) } : {})
                });
                res = {
                  ok: true,
                  action: 'start',
                  dryRun: false,
                  started: true,
                  rollout,
                  rollouts: [],
                  caddyRoute: rollout?.caddyRoute || null
                };
              } catch (e) {
                throw new McpToolError(e.code || 'SLO_CANARY_START_FAILED', e.message || 'No se pudo iniciar el rollout SLO Canary.', {
                  retryable: true,
                  remediation: 'Revisa los upstreams (host:puerto) y pasos de peso canario (1..100).'
                });
              }
            }
          } else if (action === 'evaluate') {
            if (!args.rolloutId) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="evaluate" requiere rolloutId.', {
                retryable: true,
                remediation: 'Lista rollouts con culkibo_slo_canary({ action: "list" }) y pasa rolloutId.'
              });
            }
            const existing = sloSvc.getRollout(String(args.rolloutId));
            if (!existing) {
              throw new McpToolError('ROLLOUT_NOT_FOUND', `Rollout SLO Canary '${args.rolloutId}' no encontrado.`, {
                retryable: false,
                remediation: 'Consulta rollouts activos con action="list".'
              });
            }
            if (!principal.isSuperAdmin && !canAccessProject(principal, existing.projectId)) {
              throw new McpToolError('FORBIDDEN', `No tienes acceso al rollout '${args.rolloutId}'.`, {
                retryable: false,
                remediation: 'Solo puedes evaluar rollouts de tus proyectos autorizados.'
              });
            }
            try {
              const evalRes = await sloSvc.evaluateRollout(String(args.rolloutId), {
                totalRequests: Number(args.totalRequests ?? 1000),
                error5xxCount: Number(args.error5xxCount ?? 0),
                baselineP95Ms: Number(args.baselineP95Ms ?? 50),
                canaryP95Ms: Number(args.canaryP95Ms ?? 50)
              });
              res = {
                ok: true,
                action: 'evaluate',
                dryRun: false,
                rollout: evalRes?.rollout || evalRes,
                rollouts: [],
                caddyRoute: evalRes?.caddyRoute || evalRes?.rollout?.caddyRoute || null,
                evaluation: evalRes
              };
            } catch (e) {
              throw new McpToolError(e.code || 'SLO_CANARY_EVAL_FAILED', e.message || 'Error evaluando rollout SLO Canary.', {
                retryable: false,
                remediation: 'Verifica que el rollout esté en estado IN_PROGRESS.'
              });
            }
          } else {
            // action === 'abort'
            if (!args.rolloutId) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="abort" requiere rolloutId.', {
                retryable: true,
                remediation: 'Lista rollouts con culkibo_slo_canary({ action: "list" }) y pasa rolloutId.'
              });
            }
            const existing = sloSvc.getRollout(String(args.rolloutId));
            if (!existing) {
              throw new McpToolError('ROLLOUT_NOT_FOUND', `Rollout SLO Canary '${args.rolloutId}' no encontrado.`, {
                retryable: false,
                remediation: 'Consulta rollouts activos con action="list".'
              });
            }
            if (!principal.isSuperAdmin && !canAccessProject(principal, existing.projectId)) {
              throw new McpToolError('FORBIDDEN', `No tienes acceso al rollout '${args.rolloutId}'.`, {
                retryable: false,
                remediation: 'Solo puedes abortar rollouts de tus proyectos autorizados.'
              });
            }
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              res = {
                ok: true,
                action: 'abort',
                dryRun: true,
                aborted: false,
                rollout: existing,
                rollouts: [],
                caddyRoute: null
              };
            } else {
              const aborted = await sloSvc.abortRollout(String(args.rolloutId), {
                reason: args.reason ? String(args.reason) : 'mcp_manual_abort'
              });
              res = {
                ok: true,
                action: 'abort',
                dryRun: false,
                aborted: true,
                rollout: aborted?.rollout || aborted,
                rollouts: [],
                caddyRoute: aborted?.caddyRoute || aborted?.rollout?.caddyRoute || null
              };
            }
          }
          break;
        }

        case 'culkibo_ai_workload': {
          const aiSvc = requireLazySvc('aiWorkloadService', 'Self-Hosted AI/GPU & Local LLM Workload Orchestrator');
          const action = String(args.action || 'presets');

          if (action === 'presets') {
            const rawPresets = aiSvc.AI_RUNTIME_PRESETS ? Object.values(aiSvc.AI_RUNTIME_PRESETS) : [];
            res = { ok: true, action: 'presets', presets: rawPresets, vram: null, security: null, spec: null };
          } else if (action === 'vram_estimate') {
            const vram = aiSvc.estimateVram({
              paramsB: args.paramsB !== undefined ? Number(args.paramsB) : 7,
              quantization: String(args.quantization || 'Q4_K_M'),
              contextLen: args.contextLen !== undefined ? Number(args.contextLen) : 8192,
              batchSize: args.batchSize !== undefined ? Number(args.batchSize) : 1,
              availableVramGb: args.availableVramGb !== undefined ? Number(args.availableVramGb) : null
            });
            res = { ok: true, action: 'vram_estimate', presets: [], vram, security: null, spec: null };
          } else if (action === 'audit_image') {
            const security = aiSvc.auditAiImageSecurity({
              runtime: String(args.runtime || 'ollama'),
              imageTag: args.imageTag ? String(args.imageTag) : undefined,
              bindAddress: String(args.bindAddress || '127.0.0.1'),
              authProxyEnabled: args.authProxyEnabled !== false
            });
            res = { ok: Boolean(security && security.safe), action: 'audit_image', presets: [], vram: null, security, spec: null };
          } else {
            // action === 'plan'
            try {
              const spec = aiSvc.buildAiWorkloadSpec({
                runtime: String(args.runtime || 'ollama'),
                model: String(args.model || 'llama3.2:8b'),
                paramsB: args.paramsB !== undefined ? Number(args.paramsB) : 8,
                quantization: String(args.quantization || 'Q4_K_M'),
                contextLen: args.contextLen !== undefined ? Number(args.contextLen) : 8192,
                availableVramGb: args.availableVramGb !== undefined ? Number(args.availableVramGb) : 16,
                gpuMode: String(args.gpuMode || 'cdi'),
                bindAddress: String(args.bindAddress || '127.0.0.1'),
                authProxyEnabled: args.authProxyEnabled !== false,
                ...(args.imageTag ? { imageTag: String(args.imageTag) } : {})
              });
              if (spec && spec.ok === false) {
                throw new McpToolError(spec.code || 'AI_WORKLOAD_BLOCKED', spec.error || 'Especificación AI/GPU rechazada por guardrails de VRAM o seguridad.', {
                  retryable: true,
                  remediation: 'Ajusta cuantización/contextLen/availableVramGb o vincula a 127.0.0.1 con authProxyEnabled: true.',
                  details: { vram: spec.vram || null, security: spec.security || null }
                });
              }
              res = { ok: true, action: 'plan', presets: [], vram: spec?.vram || null, security: spec?.security || null, spec };
            } catch (e) {
              if (e instanceof McpToolError) throw e;
              throw new McpToolError(e.code || 'AI_WORKLOAD_BLOCKED', e.message || 'Especificación AI/GPU bloqueada por guardrails.', {
                retryable: true,
                remediation: 'Verifica VRAM suficiente, imagen sin CVEs críticos y bindAddress="127.0.0.1" (o authProxyEnabled: true).'
              });
            }
          }
          break;
        }

        case 'culkibo_remote_builder': {
          const rbSvc = requireLazySvc('remoteBuilderService', 'Distributed Remote Build-Node Offloader');
          const action = String(args.action || 'list');

          if (action === 'list') {
            const rawB = rbSvc.listBuilders();
            const builders = Array.isArray(rawB) ? rawB : (Array.isArray(rawB?.builders) ? rawB.builders : []);
            res = { ok: true, action: 'list', dryRun: false, builders, builder: null, lease: null, muxStatus: null, pruneArgs: [] };
          } else if (action === 'register') {
            if (!args.name || !args.host) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="register" requiere name y host.', {
                retryable: true,
                remediation: 'Indica name y host del nodo builder remoto (dryRun: true por defecto).'
              });
            }
            const dryRun = args.dryRun !== false;
            const cfg = {
              ...(args.builderId ? { id: String(args.builderId) } : {}),
              name: String(args.name),
              host: String(args.host),
              arch: String(args.arch || 'linux/amd64'),
              maxConcurrency: Math.min(64, Math.max(1, Number(args.maxConcurrency) || 2)),
              allowPreviews: args.allowPreviews !== false,
              keepStorageGb: Math.min(2000, Math.max(1, Number(args.keepStorageGb) || 20))
            };
            if (dryRun) {
              res = { ok: true, action: 'register', dryRun: true, registered: false, builders: [], builder: null, lease: null, muxStatus: null, pruneArgs: [], wouldRegister: cfg };
            } else {
              try {
                const builder = rbSvc.registerBuilder(cfg);
                res = { ok: true, action: 'register', dryRun: false, registered: true, builders: [], builder, lease: null, muxStatus: null, pruneArgs: [] };
              } catch (e) {
                throw new McpToolError(e.code || 'REMOTE_BUILDER_REGISTER_FAILED', e.message || 'Error registrando remote builder.', {
                  retryable: true,
                  remediation: 'Verifica name, host y arquitectura (linux/amd64 o linux/arm64).'
                });
              }
            }
          } else if (action === 'schedule') {
            const dryRun = args.dryRun !== false;
            const req = {
              ...(args.builderId ? { builderId: String(args.builderId) } : {}),
              arch: String(args.arch || 'linux/amd64'),
              isPreview: Boolean(args.isPreview),
              projectId: args.projectId ? String(args.projectId) : 'default'
            };
            if (dryRun) {
              res = { ok: true, action: 'schedule', dryRun: true, leased: false, builders: [], builder: null, lease: null, muxStatus: null, pruneArgs: [], wouldSchedule: req };
            } else {
              try {
                const lease = rbSvc.acquireBuildSlot(req);
                res = { ok: true, action: 'schedule', dryRun: false, leased: Boolean(lease && lease.leased), builders: [], builder: null, lease, muxStatus: null, pruneArgs: [] };
              } catch (e) {
                throw new McpToolError(e.code || 'REMOTE_BUILDER_SCHEDULE_FAILED', e.message || 'No se pudo planificar build remoto.', {
                  retryable: true,
                  remediation: 'Registra al menos un nodo compatible con action="register" y revisa concurrencia.'
                });
              }
            }
          } else if (action === 'can_recycle_mux') {
            if (!args.builderId) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="can_recycle_mux" requiere builderId.', {
                retryable: true,
                remediation: 'Lista nodos con action="list" y pasa builderId.'
              });
            }
            const muxStatus = rbSvc.canRecycleMux(String(args.builderId));
            res = { ok: true, action: 'can_recycle_mux', dryRun: false, builders: [], builder: null, lease: null, muxStatus, pruneArgs: [] };
          } else {
            // action === 'prune_plan'
            const pruneArgs = rbSvc.buildPruneArgs({ keepStorageGb: Math.min(2000, Math.max(1, Number(args.keepStorageGb) || 20)) });
            res = { ok: true, action: 'prune_plan', dryRun: true, builders: [], builder: null, lease: null, muxStatus: null, pruneArgs };
          }
          break;
        }

        case 'culkibo_log_archive_search': {
          const logArch = requireLazySvc('logArchiveService', 'Compressed Persistent Log Archive & ReDoS-Safe Search');
          const action = String(args.action || 'search');

          if (args.projectId && !principal.isSuperAdmin && !canAccessProject(principal, String(args.projectId))) {
            throw new McpToolError('FORBIDDEN', `No tienes acceso a los logs archivados del proyecto '${args.projectId}'.`, {
              retryable: false,
              remediation: 'Indica un projectId autorizado desde culkibo_list_projects.'
            });
          }

          if (action === 'stats') {
            if (args.projectId) {
              const stats = logArch.getArchiveStats(String(args.projectId));
              res = { ok: true, action: 'stats', projectId: String(args.projectId), stats, search: null };
            } else {
              const rawStats = logArch.getArchiveStats();
              if (!principal.isSuperAdmin && rawStats && typeof rawStats === 'object' && Array.isArray(rawStats.projects)) {
                const allowed = new Set(this._accessibleProjectIds(principal) || []);
                const scoped = rawStats.projects.filter((p) => p && allowed.has(String(p.projectId)));
                res = {
                  ok: true,
                  action: 'stats',
                  projectId: null,
                  stats: { ...rawStats, projects: scoped, totalProjects: scoped.length },
                  search: null
                };
              } else {
                res = { ok: true, action: 'stats', projectId: null, stats: rawStats, search: null };
              }
            }
          } else {
            // action === 'search'
            if (!args.projectId) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="search" requiere projectId.', {
                retryable: true,
                remediation: 'Indica el projectId obtenido desde culkibo_list_projects.'
              });
            }
            try {
              const search = logArch.searchArchives({
                projectId: String(args.projectId),
                ...(args.since ? { since: String(args.since) } : {}),
                ...(args.until ? { until: String(args.until) } : {}),
                ...(args.level ? { level: String(args.level) } : {}),
                ...(args.releaseId ? { releaseId: String(args.releaseId) } : {}),
                ...(args.query ? { query: String(args.query) } : {}),
                ...(args.regex ? { regex: String(args.regex) } : {}),
                limit: Math.min(500, Math.max(1, Number(args.limit) || 200))
              });
              res = { ok: true, action: 'search', projectId: String(args.projectId), stats: null, search };
            } catch (e) {
              throw new McpToolError(e.code || 'UNSAFE_REGEX', e.message || 'Patrón de búsqueda o parámetro de archivo rechazado.', {
                retryable: true,
                remediation: 'Usa regex simples sin cuantificadores anidados (<=120 chars) o busca con el parámetro literal query.'
              });
            }
          }
          break;
        }

        case 'culkibo_admission_check': {
          const admSvc = requireLazySvc('admissionPolicyService', 'Declarative Policy-as-Code Admission Engine');
          const action = String(args.action || 'evaluate');

          if (action === 'get_policy') {
            const policy = admSvc.getPolicy();
            res = { ok: true, action: 'get_policy', dryRun: false, policy, evaluation: null };
          } else if (action === 'apply_preset') {
            if (!principal.isSuperAdmin && ((ROLE_RANK[principal.role] || 0) < ROLE_RANK.admin || Array.isArray(principal.projectIds))) {
              throw new McpToolError('FORBIDDEN', 'Cambiar el preset global Policy-as-Code requiere rol admin/owner sin restricción de proyectos.', {
                retryable: false,
                remediation: 'Autentícate como admin/owner o usa action: "evaluate".'
              });
            }
            if (!args.preset) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="apply_preset" requiere preset (baseline|restricted|soc2-strict).', {
                retryable: true,
                remediation: 'Indica preset: "baseline", "restricted" o "soc2-strict".'
              });
            }
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              res = {
                ok: true,
                action: 'apply_preset',
                dryRun: true,
                applied: false,
                policy: admSvc.getPolicy(),
                evaluation: null,
                wouldApplyPreset: String(args.preset)
              };
            } else {
              try {
                const policy = admSvc.applyPreset(String(args.preset));
                res = { ok: true, action: 'apply_preset', dryRun: false, applied: true, policy, evaluation: null };
              } catch (e) {
                throw new McpToolError(e.code || 'INVALID_ADMISSION_PRESET', e.message || 'Preset de admisión inválido.', {
                  retryable: true,
                  remediation: 'Usa uno de los presets soportados: baseline, restricted o soc2-strict.'
                });
              }
            }
          } else {
            // action === 'evaluate'
            const spec = args.spec && typeof args.spec === 'object' ? args.spec : {};
            try {
              const evaluation = admSvc.evaluateDeployment(spec, args.preset ? { preset: String(args.preset) } : {});
              res = {
                ok: Boolean(evaluation && evaluation.allowed !== false),
                action: 'evaluate',
                dryRun: false,
                policy: null,
                evaluation
              };
            } catch (e) {
              throw new McpToolError(e.code || 'ADMISSION_EVAL_ERROR', e.message || 'Error evaluando política de admisión.', {
                retryable: true,
                remediation: 'Pasa un objeto spec válido y un preset soportado (baseline|restricted|soc2-strict).'
              });
            }
          }
          break;
        }

        case 'culkibo_compliance_bundle': {
          const compSvc = requireLazySvc('complianceBundleService', 'Ed25519-Signed SOC2/ISO27001/GDPR Compliance Bundle');
          const action = String(args.action || 'generate');

          if (action === 'latest') {
            const bundle = compSvc.getLatestBundle();
            res = { ok: true, action: 'latest', bundle: bundle || null, verification: null };
          } else if (action === 'verify') {
            if (!args.bundle || typeof args.bundle !== 'object') {
              throw new McpToolError('MISSING_ARGUMENT', 'action="verify" requiere el objeto bundle a verificar.', {
                retryable: true,
                remediation: 'Pasa el bundle generado por action="generate" o action="latest".'
              });
            }
            const verification = compSvc.verifyComplianceBundle(args.bundle);
            res = {
              ok: Boolean(verification && verification.valid),
              action: 'verify',
              bundle: null,
              verification
            };
          } else {
            // action === 'generate'
            const actor = principal.email || principal.userId || principal.role || 'mcp-admin';
            const bundle = await compSvc.generateBundle({
              framework: String(args.framework || 'all'),
              actor,
              ...(args.snapshot && typeof args.snapshot === 'object' ? { snapshot: args.snapshot } : {})
            });
            res = { ok: true, action: 'generate', bundle, verification: null };
          }
          break;
        }

        case 'culkibo_volume_migrate': {
          const volSvc = requireLazySvc('volumeMigrationService', 'Stateful Volume Snapshot Cloner & Cross-VPS Migration Planner');
          const action = String(args.action || 'list');

          if (action === 'list') {
            const allowedIds = this._accessibleProjectIds(principal);
            const effectiveIds = args.projectId
              ? [String(args.projectId)]
              : allowedIds;
            const rawM = volSvc.listMigrations(effectiveIds !== null ? { projectIds: effectiveIds } : {});
            const migrations = Array.isArray(rawM) ? rawM : (Array.isArray(rawM?.migrations) ? rawM.migrations : []);
            res = { ok: true, action: 'list', migrations, migration: null };
          } else {
            // action === 'plan'
            if (!args.projectId || !args.volumeName || !args.mountPath || !args.targetHost) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="plan" requiere projectId, volumeName, mountPath y targetHost.', {
                retryable: true,
                remediation: 'Indica projectId autorizado, volumeName seguro (sin shell chars), mountPath no-raíz y targetHost.'
              });
            }
            if (!principal.isSuperAdmin && !canAccessProject(principal, String(args.projectId))) {
              throw new McpToolError('FORBIDDEN', `No tienes acceso al proyecto '${args.projectId}'.`, {
                retryable: false,
                remediation: 'Usa un projectId autorizado desde culkibo_list_projects.'
              });
            }
            try {
              const migration = volSvc.planMigration({
                projectId: String(args.projectId),
                volumeName: String(args.volumeName),
                mountPath: String(args.mountPath),
                sourceHost: String(args.sourceHost || 'local'),
                targetHost: String(args.targetHost),
                uid: args.uid !== undefined ? Number(args.uid) : 999,
                gid: args.gid !== undefined ? Number(args.gid) : 999,
                containerName: args.containerName ? String(args.containerName) : '',
                estimatedMb: args.estimatedMb !== undefined ? Number(args.estimatedMb) : 256,
                ...(args.sourceOrgId ? { sourceOrgId: String(args.sourceOrgId) } : {}),
                ...(args.targetOrgId ? { targetOrgId: String(args.targetOrgId) } : {})
              });
              res = { ok: true, action: 'plan', migrations: [], migration };
            } catch (e) {
              throw new McpToolError(e.code || 'INVALID_VOLUME_MIGRATION', e.message || 'Solicitud de migración de volumen rechazada.', {
                retryable: false,
                remediation: 'Verifica volumeName alfanumérico (CVE-2025-66213), mountPath sin traversal, hosts distintos y misma organización.'
              });
            }
          }
          break;
        }

        case 'culkibo_edge_experiment': {
          const expSvc = requireLazySvc('edgeExperimentService', 'Multi-Region Caddy v2.11 Geo-Routing & Sticky A/B Experiment Compiler');
          const action = String(args.action || 'list');

          if (action === 'list') {
            const rawE = expSvc.listExperiments(args.projectId ? String(args.projectId) : undefined);
            const allE = Array.isArray(rawE) ? rawE : (Array.isArray(rawE?.experiments) ? rawE.experiments : []);
            const filtered = allE.filter((e) => principal.isSuperAdmin || canAccessProject(principal, e.projectId));
            res = { ok: true, action: 'list', dryRun: false, experiments: filtered, experiment: null, compiledRoutes: null };
          } else if (action === 'compile') {
            const kind = String(args.kind || 'ab');
            try {
              const compiledRoutes = kind === 'geo'
                ? expSvc.compileGeoRoutes({
                    hostname: String(args.hostname || 'app.example.com'),
                    headerName: String(args.headerName || 'CF-IPCountry'),
                    regions: Array.isArray(args.regions) ? args.regions : [],
                    defaultUpstream: String(args.defaultUpstream || '127.0.0.1:3000')
                  })
                : expSvc.compileAbExperimentRoute({
                    id: String(args.experimentId || 'exp_preview'),
                    hostname: String(args.hostname || 'app.example.com'),
                    stickyMode: String(args.stickyMode || 'cookie'),
                    ...(args.cookieName ? { cookieName: String(args.cookieName) } : {}),
                    ...(args.headerField ? { headerField: String(args.headerField) } : {}),
                    variants: Array.isArray(args.variants) ? args.variants : [],
                    killed: false
                  });
              res = { ok: true, action: 'compile', dryRun: true, experiments: [], experiment: null, compiledRoutes };
            } catch (e) {
              throw new McpToolError(e.code || 'INVALID_EDGE_EXPERIMENT', e.message || 'Configuración de Geo-Routing o A/B inválida.', {
                retryable: true,
                remediation: 'Usa códigos país ISO-3166 alpha-2 válidos y pesos enteros positivos que sumen exactamente 100.'
              });
            }
          } else if (action === 'upsert') {
            if (!args.projectId || !args.hostname) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="upsert" requiere projectId y hostname.', {
                retryable: true,
                remediation: 'Proporciona projectId autorizado, hostname y variants (sum=100) o regions Geo-IP.'
              });
            }
            const cfg = {
              ...(args.experimentId ? { id: String(args.experimentId) } : {}),
              projectId: String(args.projectId),
              hostname: String(args.hostname),
              kind: String(args.kind || 'ab'),
              stickyMode: String(args.stickyMode || 'cookie'),
              ...(args.cookieName ? { cookieName: String(args.cookieName) } : {}),
              ...(args.headerField ? { headerField: String(args.headerField) } : {}),
              ...(args.headerName ? { headerName: String(args.headerName) } : {}),
              ...(Array.isArray(args.variants) ? { variants: args.variants } : {}),
              ...(Array.isArray(args.regions) ? { regions: args.regions } : {}),
              ...(args.defaultUpstream ? { defaultUpstream: String(args.defaultUpstream) } : {})
            };
            const dryRun = args.dryRun !== false;
            try {
              if (typeof expSvc.validateExperimentConfig === 'function') {
                expSvc.validateExperimentConfig(cfg);
              }
            } catch (e) {
              throw new McpToolError(e.code || 'INVALID_EDGE_EXPERIMENT', e.message || 'Configuración de experimento Edge inválida.', {
                retryable: true,
                remediation: 'Corrige códigos ISO-3166, upstreams host:port o suma de pesos == 100.'
              });
            }
            if (dryRun) {
              res = { ok: true, action: 'upsert', dryRun: true, upserted: false, experiments: [], experiment: null, compiledRoutes: null, wouldUpsert: cfg };
            } else {
              try {
                const upserted = expSvc.upsertExperiment(cfg);
                res = {
                  ok: true,
                  action: 'upsert',
                  dryRun: false,
                  upserted: true,
                  experiments: [],
                  experiment: upserted?.experiment || upserted,
                  compiledRoutes: upserted?.experiment?.compiledCaddy || upserted?.compiledRoutes || upserted?.caddyRoute || null
                };
              } catch (e) {
                throw new McpToolError(e.code || 'INVALID_EDGE_EXPERIMENT', e.message || 'No se pudo guardar el experimento Edge.', {
                  retryable: true,
                  remediation: 'Revisa los parámetros de variantes o regiones Geo-IP.'
                });
              }
            }
          } else {
            // action === 'kill_switch'
            if (!args.experimentId) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="kill_switch" requiere experimentId.', {
                retryable: true,
                remediation: 'Lista experimentos con action="list" y pasa experimentId.'
              });
            }
            const existing = expSvc.getExperiment(String(args.experimentId));
            if (!existing) {
              throw new McpToolError('EXPERIMENT_NOT_FOUND', `Experimento Edge '${args.experimentId}' no encontrado.`, {
                retryable: false,
                remediation: 'Consulta experimentos activos con action="list".'
              });
            }
            if (!principal.isSuperAdmin && !canAccessProject(principal, existing.projectId)) {
              throw new McpToolError('FORBIDDEN', `No tienes acceso al experimento '${args.experimentId}'.`, {
                retryable: false,
                remediation: 'Solo puedes revertir experimentos de tus proyectos autorizados.'
              });
            }
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              res = { ok: true, action: 'kill_switch', dryRun: true, killed: false, experiments: [], experiment: existing, compiledRoutes: null };
            } else {
              const killed = expSvc.triggerKillSwitch(String(args.experimentId), {
                reason: args.reason ? String(args.reason) : 'mcp_kill_switch'
              });
              res = {
                ok: true,
                action: 'kill_switch',
                dryRun: false,
                killed: true,
                experiments: [],
                experiment: killed?.experiment || killed,
                compiledRoutes: killed?.experiment?.compiledCaddy || killed?.compiledRoutes || killed?.caddyRoute || null
              };
            }
          }
          break;
        }

        case 'culkibo_security_posture': {
          const maxSecretAgeDays = Math.min(3650, Math.max(1, Number(args.maxSecretAgeDays) || 90));
          const visibleProjects = projectManager.getAll().filter((p) => canAccessProject(principal, p.id, p));

          const admSvc = lazySvc('admissionPolicyService');
          const compSvc = lazySvc('complianceBundleService');
          const cveSvc = lazySvc('cveDriftService');
          const sls = lazySvc('secretLeaseService');
          const drSvc = lazySvc('backupDrillService');

          const admPolicy = admSvc && typeof admSvc.getPolicy === 'function' ? admSvc.getPolicy() : null;
          const latestBundle = compSvc && typeof compSvc.getLatestBundle === 'function' ? compSvc.getLatestBundle() : null;
          /** @type {any} */
          let cveSummary = null;
          if (cveSvc && typeof cveSvc.scanSbom === 'function') {
            try {
              const scan = await cveSvc.scanSbom({ allowNetwork: false });
              cveSummary = {
                mode: scan?.source || 'offline_fallback',
                scannedPackages: Number(scan?.scannedPackages ?? scan?.scannedComponents ?? 0),
                totalVulnerabilities: Number(scan?.totalVulnerabilities ?? scan?.vulnerableCount ?? 0),
                bySeverity: scan?.bySeverity || { critical: 0, high: 0, medium: 0, low: 0 }
              };
            } catch (e) {}
          }
          const rotAudit = sls && typeof sls.auditSecretRotationAges === 'function'
            ? sls.auditSecretRotationAges(visibleProjects, { maxAgeDays: maxSecretAgeDays })
            : null;
          const rawDrills = drSvc && typeof drSvc.listDrills === 'function'
            ? drSvc.listDrills(principal.isSuperAdmin ? null : { allowedProjectIds: visibleProjects.map((p) => p.id) })
            : null;
          const drillsArr = Array.isArray(rawDrills) ? rawDrills : (Array.isArray(rawDrills?.drills) ? rawDrills.drills : []);
          const drillsPassed = drillsArr.filter((d) => d && d.verdict === 'PASS').length;
          const drPassRatePct = drillsArr.length > 0 ? Math.round((drillsPassed / drillsArr.length) * 100) : 100;

          // Weighted executive governance score (0..100)
          const admScore = admPolicy?.preset === 'soc2-strict' ? 100 : (admPolicy?.preset === 'restricted' ? 95 : 85);
          const compScore = Number(latestBundle?.overallScore ?? latestBundle?.payload?.overallScore ?? 92);
          const cveCrit = Number(cveSummary?.bySeverity?.critical ?? 0);
          const cveHigh = Number(cveSummary?.bySeverity?.high ?? 0);
          const cveScore = Math.max(0, 100 - cveCrit * 25 - cveHigh * 10);
          const staleCount = Number(rotAudit?.staleCount ?? 0);
          const rotScore = staleCount === 0 ? 100 : Math.max(40, 100 - staleCount * 10);
          const postureScore = Math.round((admScore * 0.25) + (compScore * 0.25) + (cveScore * 0.2) + (rotScore * 0.15) + (drPassRatePct * 0.15));
          const grade = postureScore >= 95 ? 'A+' : (postureScore >= 88 ? 'A' : (postureScore >= 75 ? 'B' : (postureScore >= 60 ? 'C' : 'D')));

          res = {
            ok: true,
            generatedAt: new Date().toISOString(),
            postureScore,
            grade,
            pillars: {
              admission: {
                preset: admPolicy?.preset || 'baseline',
                score: admScore
              },
              compliance: {
                hasBundle: Boolean(latestBundle),
                overallScore: compScore,
                signedAlgorithm: latestBundle ? 'Ed25519' : null,
                generatedAt: latestBundle?.generatedAt || latestBundle?.payload?.generatedAt || null
              },
              cveDrift: cveSummary,
              secretRotation: {
                maxAgeDays: maxSecretAgeDays,
                totalKeys: Number(rotAudit?.totalKeys ?? 0),
                staleCount
              },
              drDrills: {
                totalDrills: drillsArr.length,
                passedDrills: drillsPassed,
                passRatePct: drPassRatePct
              }
            }
          };
          break;
        }

        case 'culkibo_synthetic_sentinel': {
          const synthSvc = requireLazySvc('syntheticSentinelService', 'Synthetic Multi-Step API Flow & Live TLS/SNI Sentinel');
          const action = String(args.action || 'list_flows');

          if (action === 'list_flows') {
            const rawF = synthSvc.listFlows();
            const flows = Array.isArray(rawF) ? rawF : (Array.isArray(rawF?.flows) ? rawF.flows : []);
            res = { ok: true, action: 'list_flows', dryRun: false, flows, flow: null, run: null, tls: null };
          } else if (action === 'save_flow') {
            if (!principal.isSuperAdmin && ((ROLE_RANK[principal.role] || 0) < ROLE_RANK.admin || Array.isArray(principal.projectIds))) {
              throw new McpToolError('FORBIDDEN', 'Guardar flujos sintéticos requiere rol admin/owner sin restricción de proyectos.', {
                retryable: false,
                remediation: 'Autentícate como admin/owner o usa action: "list_flows" / "run_flow" / "check_tls".'
              });
            }
            if (!args.flow || typeof args.flow !== 'object' || Array.isArray(args.flow)) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="save_flow" requiere un objeto flow con name y steps (1..5).', {
                retryable: true,
                remediation: 'Pasa flow: { name, steps: [...] } (dryRun: true por defecto).'
              });
            }
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              res = {
                ok: true,
                action: 'save_flow',
                dryRun: true,
                saved: false,
                flows: [],
                flow: null,
                run: null,
                tls: null,
                wouldSave: {
                  name: String(args.flow.name || ''),
                  stepsCount: Array.isArray(args.flow.steps) ? args.flow.steps.length : 0
                }
              };
            } else {
              try {
                const saved = synthSvc.saveFlow(args.flow);
                res = { ok: true, action: 'save_flow', dryRun: false, saved: true, flows: [], flow: saved, run: null, tls: null };
              } catch (e) {
                throw new McpToolError(e.code || 'INVALID_SYNTHETIC_FLOW', e.message || 'Flujo sintético inválido.', {
                  retryable: true,
                  remediation: 'Define entre 1 y 5 pasos HTTP válidos con URLs públicas permitidas por SSRF.'
                });
              }
            }
          } else if (action === 'run_flow') {
            const target = args.flow && typeof args.flow === 'object' ? args.flow : (args.flowId ? String(args.flowId) : null);
            if (!target) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="run_flow" requiere flowId o un objeto flow inline.', {
                retryable: true,
                remediation: 'Lista flujos con action="list_flows" o pasa flow inline (allowLoopback siempre forzado a false).'
              });
            }
            try {
              const run = await synthSvc.runFlow(target, { allowLoopback: false, persist: Boolean(args.flowId) });
              res = { ok: Boolean(run && run.ok), action: 'run_flow', dryRun: false, flows: [], flow: null, run, tls: null };
            } catch (e) {
              throw new McpToolError(e.code || 'SYNTHETIC_FLOW_BLOCKED', e.message || 'Ejecución de flujo sintético bloqueada o fallida.', {
                retryable: false,
                remediation: 'Verifica que el flowId exista y que todas las URLs cumplan la guardia anti-SSRF (sin loopback ni metadatos cloud).'
              });
            }
          } else {
            // action === 'check_tls'
            const host = String(args.host || '').trim();
            if (!host) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="check_tls" requiere host.', {
                retryable: true,
                remediation: 'Proporciona un dominio público en el parámetro host (ej. example.com).'
              });
            }
            const ssrf = require('./ssrfGuard');
            try {
              await ssrf.assertSafeUrl(`https://${host}:${Number(args.port) || 443}/`, { allowLoopback: false });
            } catch (e) {
              if (e instanceof McpToolError) throw e;
              throw new McpToolError(e.code || 'SSRF_BLOCKED', e.message || `Host bloqueado por SSRF: '${host}'.`, {
                retryable: false,
                remediation: 'Proporciona un hostname público válido (loopback/RFC1918/169.254.169.254 bloqueados).'
              });
            }
            try {
              const tls = await synthSvc.checkTlsSentinel({
                host,
                port: args.port !== undefined ? Number(args.port) : 443,
                ...(args.servername ? { servername: String(args.servername) } : {}),
                ...(args.expectedSan ? { expectedSan: String(args.expectedSan) } : {}),
                ...(args.baselineFingerprintSha256 ? { baselineFingerprintSha256: String(args.baselineFingerprintSha256) } : {}),
                ...(args.baselineIssuer ? { baselineIssuer: String(args.baselineIssuer) } : {}),
                warnDays: args.warnDays !== undefined ? Number(args.warnDays) : 14,
                critDays: args.critDays !== undefined ? Number(args.critDays) : 3
              }, { allowLoopback: false });
              res = { ok: tls?.status !== 'CRITICAL', action: 'check_tls', dryRun: false, flows: [], flow: null, run: null, tls };
            } catch (e) {
              throw new McpToolError(e.code || 'TLS_SENTINEL_ERROR', e.message || 'Error sondeando certificado TLS/SNI.', {
                retryable: true,
                remediation: 'Verifica conectividad TCP al puerto 443 y que el host responda TLS.'
              });
            }
          }
          break;
        }

        case 'culkibo_lint_sql_migration': {
          const sqlLint = requireLazySvc('sqlMigrationLinter', 'Zero-Downtime SQL Migration Linter');
          const out = sqlLint.lintSqlMigration(String(args.sql || ''));
          res = {
            ...out,
            ok: Boolean(out && out.safe)
          };
          break;
        }

        case 'culkibo_worker_autoscaler': {
          const autoSvc = requireLazySvc('workerAutoscalerService', 'OOM-Safe Queue/Worker Autoscaler & Circuit Breaker');
          const action = String(args.action || 'get_policy');
          const pid = String(args.projectId || '').trim();
          if (!pid) {
            throw new McpToolError('MISSING_ARGUMENT', 'culkibo_worker_autoscaler requiere projectId.', {
              retryable: true,
              remediation: 'Indica projectId obtenido de culkibo_list_projects.'
            });
          }
          if (!principal.isSuperAdmin && !canAccessProject(principal, pid)) {
            throw new McpToolError('FORBIDDEN', `No tienes acceso al autoscaler del proyecto '${pid}'.`, {
              retryable: false,
              remediation: 'Usa un projectId perteneciente a tus proyectos autorizados.'
            });
          }

          if (action === 'get_policy') {
            const policy = autoSvc.getPolicy(pid);
            res = { ok: true, action: 'get_policy', dryRun: false, projectId: pid, policy, decision: null };
          } else if (action === 'set_policy') {
            if (!args.policy || typeof args.policy !== 'object' || Array.isArray(args.policy)) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="set_policy" requiere el objeto policy.', {
                retryable: true,
                remediation: 'Pasa policy con los umbrales deseados (dryRun: true por defecto).'
              });
            }
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              res = {
                ok: true,
                action: 'set_policy',
                dryRun: true,
                saved: false,
                projectId: pid,
                policy: autoSvc.getPolicy(pid),
                decision: null,
                previewPolicy: args.policy
              };
            } else {
              try {
                const saved = autoSvc.savePolicy(pid, args.policy);
                res = { ok: true, action: 'set_policy', dryRun: false, saved: true, projectId: pid, policy: saved, decision: null };
              } catch (e) {
                throw new McpToolError(e.code || 'INVALID_AUTOSCALER_POLICY', e.message || 'Política de autoscaler inválida.', {
                  retryable: true,
                  remediation: 'Revisa los límites minReplicas <= maxReplicas, cooldowns y reserveHostRamMb.'
                });
              }
            }
          } else {
            // action === 'evaluate'
            const hostFreeRamMb = args.hostFreeRamMb !== undefined
              ? Number(args.hostFreeRamMb)
              : Math.round(os.freemem() / (1024 * 1024));
            const decision = autoSvc.evaluateAutoscaler({
              projectId: pid,
              queueDepth: args.queueDepth !== undefined ? Number(args.queueDepth) : 0,
              httpSaturationPct: args.httpSaturationPct !== undefined ? Number(args.httpSaturationPct) : 0,
              currentReplicas: args.currentReplicas !== undefined ? Number(args.currentReplicas) : 1,
              hostFreeRamMb,
              ...(args.perReplicaRamMb !== undefined ? { perReplicaRamMb: Number(args.perReplicaRamMb) } : {}),
              lastScaleAtMs: args.lastScaleAtMs !== undefined ? Number(args.lastScaleAtMs) : 0
            }, args.policy && typeof args.policy === 'object' ? args.policy : undefined);
            res = {
              ok: true,
              action: 'evaluate',
              dryRun: false,
              projectId: pid,
              policy: decision?.policy || autoSvc.getPolicy(pid),
              decision
            };
          }
          break;
        }

        case 'culkibo_audit_licenses': {
          const licSvc = requireLazySvc('licenseAuditorService', 'CycloneDX 1.6 SPDX License Risk Auditor');
          const policy = String(args.policy || 'saas-strict');
          try {
            const audit = licSvc.auditLicenses({
              policy,
              ...(args.sbom && typeof args.sbom === 'object' ? { sbom: args.sbom } : {})
            });
            res = {
              ...audit,
              ok: Boolean(audit && audit.compliant)
            };
          } catch (e) {
            throw new McpToolError(e.code || 'LICENSE_AUDIT_ERROR', e.message || 'Error auditando licencias SPDX.', {
              retryable: true,
              remediation: 'Usa policy saas-strict, oss-permissive o audit-only y un SBOM CycloneDX 1.6 válido.'
            });
          }
          break;
        }

        case 'culkibo_seccomp_profile': {
          const secSvc = requireLazySvc('seccompProfileService', 'Tailored OCI Seccomp Profile Generator & runc CVE Guard');
          const action = String(args.action || 'generate');

          if (action === 'generate') {
            try {
              const generated = secSvc.generateSeccompProfile(
                String(args.stack || 'node'),
                args.mode ? { mode: String(args.mode) } : {}
              );
              res = { ok: true, action: 'generate', generated, validation: null, runcAudit: null };
            } catch (e) {
              throw new McpToolError(e.code || 'SECCOMP_UNCONFINED_FORBIDDEN', e.message || 'Perfil seccomp rechazado.', {
                retryable: false,
                remediation: 'Usa uno de los stacks soportados (node, python, go, rust, static-caddy) y jamás mode="unconfined".'
              });
            }
          } else if (action === 'validate') {
            if (args.spec === undefined || args.spec === null) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="validate" requiere spec (objeto OCI seccomp JSON o cadena).', {
                retryable: true,
                remediation: 'Pasa la especificación seccomp en el argumento spec.'
              });
            }
            const validation = secSvc.validateSeccompSpec(args.spec);
            res = { ok: Boolean(validation && validation.safe), action: 'validate', generated: null, validation, runcAudit: null };
          } else {
            // action === 'audit_runc'
            const runcAudit = secSvc.auditRuncVersion(String(args.version || ''));
            res = { ok: Boolean(runcAudit && !runcAudit.vulnerable), action: 'audit_runc', generated: null, validation: null, runcAudit };
          }
          break;
        }

        case 'culkibo_audit_image_bloat': {
          const imgAud = requireLazySvc('imageBloatAuditor', 'Container Image Layer Bloat & Secret-in-Layer Auditor');
          const audit = imgAud.auditDockerfileAndLayers({
            dockerfile: typeof args.dockerfile === 'string' ? args.dockerfile : '',
            historyLayers: Array.isArray(args.historyLayers) ? args.historyLayers : [],
            stack: typeof args.stack === 'string' ? args.stack : 'node'
          });
          res = {
            ...audit,
            ok: Boolean(audit && audit.ok !== false)
          };
          break;
        }

        case 'culkibo_cron_lease': {
          const cronLease = requireLazySvc('cronLeaseService', 'Distributed Cron Idempotency & Fencing-Token Lease Guard');
          const action = String(args.action || 'list');

          if (action === 'list') {
            const rawL = cronLease.listCronLeases(args.jobId ? String(args.jobId) : undefined);
            const leases = Array.isArray(rawL) ? rawL : (Array.isArray(rawL?.leases) ? rawL.leases : []);
            res = { ok: true, action: 'list', dryRun: false, leases, result: null };
          } else if (action === 'acquire') {
            const jobId = String(args.jobId || '').trim();
            if (!jobId) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="acquire" requiere jobId.', {
                retryable: true,
                remediation: 'Indica jobId, scheduleSlotIso y holderId (dryRun: true por defecto).'
              });
            }
            const scheduleSlotIso = String(args.scheduleSlotIso || new Date().toISOString().slice(0, 16) + ':00Z');
            const holderId = String(args.holderId || principal.userId || 'mcp-worker');
            const ttlSec = args.ttlSec !== undefined ? Number(args.ttlSec) : 300;
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              res = {
                ok: true,
                action: 'acquire',
                dryRun: true,
                leases: [],
                result: { acquired: false, wouldAcquire: { jobId, scheduleSlotIso, holderId, ttlSec } }
              };
            } else {
              const out = cronLease.acquireCronLease({
                jobId,
                scheduleSlotIso,
                holderId,
                ttlSec,
                ...(args.nowMs !== undefined ? { nowMs: Number(args.nowMs) } : {})
              });
              res = { ok: Boolean(out && out.acquired), action: 'acquire', dryRun: false, leases: [], result: out };
            }
          } else if (action === 'renew') {
            const leaseId = String(args.leaseId || '').trim();
            if (!leaseId) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="renew" requiere leaseId.', {
                retryable: true,
                remediation: 'Consulta leaseId activos con action="list".'
              });
            }
            const holderId = String(args.holderId || principal.userId || 'mcp-worker');
            const extendSec = args.extendSec !== undefined ? Number(args.extendSec) : (args.ttlSec !== undefined ? Number(args.ttlSec) : 300);
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              res = { ok: true, action: 'renew', dryRun: true, leases: [], result: { renewed: false, leaseId, holderId, extendSec } };
            } else {
              const out = cronLease.renewCronLease(leaseId, {
                holderId,
                extendSec,
                ...(args.nowMs !== undefined ? { nowMs: Number(args.nowMs) } : {})
              });
              res = { ok: Boolean(out && (out.ok || out.renewed)), action: 'renew', dryRun: false, leases: [], result: out };
            }
          } else {
            // action === 'complete'
            const leaseId = String(args.leaseId || '').trim();
            if (!leaseId || args.fencingToken === undefined) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="complete" requiere leaseId y fencingToken.', {
                retryable: true,
                remediation: 'Pasa el leaseId y fencingToken exactos devueltos por action="acquire".'
              });
            }
            const holderId = String(args.holderId || principal.userId || 'mcp-worker');
            const fencingToken = Number(args.fencingToken);
            const status = args.status === 'failed' ? 'failed' : 'succeeded';
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              res = { ok: true, action: 'complete', dryRun: true, leases: [], result: { completed: false, leaseId, holderId, fencingToken, status } };
            } else {
              const out = cronLease.completeCronLease(leaseId, {
                holderId,
                fencingToken,
                status,
                ...(args.nowMs !== undefined ? { nowMs: Number(args.nowMs) } : {})
              });
              res = { ok: Boolean(out && out.ok), action: 'complete', dryRun: false, leases: [], result: out };
            }
          }
          break;
        }

        case 'culkibo_mask_preview_pii': {
          const piiSvc = requireLazySvc('piiMaskerService', 'PR-Preview DB PII Masking & Anonymization Engine');
          if (!Array.isArray(args.rows) && typeof args.sqlDump !== 'string') {
            throw new McpToolError('MISSING_ARGUMENT', 'culkibo_mask_preview_pii requiere rows (array JSON) o sqlDump (string).', {
              retryable: true,
              remediation: 'Pasa rows: [...] o sqlDump: "INSERT INTO ..." junto a un seed opcional.'
            });
          }
          const out = piiSvc.maskDataset({
            ...(Array.isArray(args.rows) ? { rows: args.rows } : {}),
            ...(typeof args.sqlDump === 'string' ? { sqlDump: args.sqlDump } : {}),
            ...(typeof args.seed === 'string' && args.seed.trim() ? { seed: args.seed.trim() } : {}),
            ...(args.rules && typeof args.rules === 'object' ? { rules: args.rules } : {}),
            autoDetect: args.autoDetect !== false
          });
          res = {
            ...out,
            ok: Boolean(out && out.ok !== false && out.zeroPiiLeaked !== false),
            maskedRows: out?.maskedRows ?? null,
            maskedSql: out?.maskedSql ?? null
          };
          break;
        }

        case 'culkibo_oom_forensics': {
          const oomSvc = requireLazySvc('oomForensicsService', 'Container OOM-Kill Forensics & Crash-Loop Classifier');
          const pid = String(args.projectId || '').trim();
          if (!pid) {
            throw new McpToolError('MISSING_ARGUMENT', 'culkibo_oom_forensics requiere projectId.', {
              retryable: true,
              remediation: 'Indica projectId obtenido de culkibo_list_projects.'
            });
          }
          if (!principal.isSuperAdmin && !canAccessProject(principal, pid)) {
            throw new McpToolError('FORBIDDEN', `No tienes acceso al diagnóstico forense del proyecto '${pid}'.`, {
              retryable: false,
              remediation: 'Usa un projectId perteneciente a tus proyectos autorizados.'
            });
          }
          const report = oomSvc.classifyContainerFailure({
            containerName: args.containerName ? String(args.containerName) : '',
            exitCode: Number(args.exitCode),
            oomKilled: Boolean(args.oomKilled),
            restartCount: args.restartCount !== undefined ? Number(args.restartCount) : 0,
            memoryLimitMb: args.memoryLimitMb !== undefined ? Number(args.memoryLimitMb) : 0,
            memoryPeakMb: args.memoryPeakMb !== undefined ? Number(args.memoryPeakMb) : 0,
            cgroupOomKills: args.cgroupOomKills !== undefined ? Number(args.cgroupOomKills) : 0,
            recentLogs: typeof args.recentLogs === 'string' ? args.recentLogs : '',
            healthStatus: typeof args.healthStatus === 'string' ? args.healthStatus : '',
            uptimeSec: args.uptimeSec !== undefined ? Number(args.uptimeSec) : 0,
            historicalOnly: Boolean(args.historicalOnly)
          });
          res = {
            ...report,
            ok: Boolean(report && report.ok !== false),
            projectId: pid
          };
          break;
        }

        case 'culkibo_oncall_router': {
          const oncallSvc = requireLazySvc('oncallEscalationService', 'Incident Dedup, Flapping Damper & On-Call Escalation Router');
          const action = String(args.action || 'list_incidents');

          if (action === 'list_policies') {
            const rawP = oncallSvc.listPolicies();
            const policies = Array.isArray(rawP) ? rawP : (Array.isArray(rawP?.policies) ? rawP.policies : []);
            res = { ok: true, action: 'list_policies', dryRun: false, policies, incidents: [], result: null };
          } else if (action === 'list_incidents') {
            const rawI = oncallSvc.listIncidents({ activeOnly: Boolean(args.activeOnly) });
            const incidents = Array.isArray(rawI) ? rawI : (Array.isArray(rawI?.incidents) ? rawI.incidents : []);
            res = { ok: true, action: 'list_incidents', dryRun: false, policies: [], incidents, result: null };
          } else if (action === 'resolve_oncall') {
            const policyId = String(args.policyId || '').trim();
            if (!policyId) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="resolve_oncall" requiere policyId.', {
                retryable: true,
                remediation: 'Consulta policyId disponibles con action="list_policies".'
              });
            }
            const resolved = oncallSvc.resolveCurrentOnCall(policyId, args.nowMs !== undefined ? Number(args.nowMs) : undefined);
            res = { ok: Boolean(resolved), action: 'resolve_oncall', dryRun: false, policies: [], incidents: [], result: resolved };
          } else if (action === 'save_policy') {
            if (!principal.isSuperAdmin && ((ROLE_RANK[principal.role] || 0) < ROLE_RANK.admin || Array.isArray(principal.projectIds))) {
              throw new McpToolError('FORBIDDEN', 'Guardar políticas On-Call (save_policy) requiere rol admin/owner sin restricción de proyectos.', {
                retryable: false,
                remediation: 'Autentícate como admin/owner para crear o modificar políticas de guardia.'
              });
            }
            if (!args.policy || typeof args.policy !== 'object' || Array.isArray(args.policy)) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="save_policy" requiere el objeto policy.', {
                retryable: true,
                remediation: 'Pasa policy: { name, tiers: [{ tier: 1, responders: [...] }] } (dryRun: true por defecto).'
              });
            }
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              res = { ok: true, action: 'save_policy', dryRun: true, policies: [], incidents: [], result: { saved: false, wouldSave: { name: String(args.policy.name || '') } } };
            } else {
              const saved = oncallSvc.savePolicy(args.policy);
              res = { ok: true, action: 'save_policy', dryRun: false, policies: [], incidents: [], result: { saved: true, policy: saved } };
            }
          } else if (action === 'ingest_alert') {
            if (args.projectId && !principal.isSuperAdmin && !canAccessProject(principal, String(args.projectId))) {
              throw new McpToolError('FORBIDDEN', `No tienes acceso al proyecto '${args.projectId}' para ingerir alertas.`, {
                retryable: false,
                remediation: 'Usa un projectId autorizado.'
              });
            }
            if (!args.fingerprint) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="ingest_alert" requiere fingerprint.', {
                retryable: true,
                remediation: 'Proporciona fingerprint, title y policyId opcional.'
              });
            }
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              res = {
                ok: true,
                action: 'ingest_alert',
                dryRun: true,
                policies: [],
                incidents: [],
                result: { ingested: false, fingerprint: String(args.fingerprint), state: String(args.state || 'firing') }
              };
            } else {
              const ingested = oncallSvc.ingestAlert({
                policyId: args.policyId ? String(args.policyId) : undefined,
                fingerprint: String(args.fingerprint),
                ...(args.projectId ? { projectId: String(args.projectId) } : {}),
                severity: args.severity ? String(args.severity) : 'critical',
                title: args.title ? String(args.title) : `Alert ${args.fingerprint}`,
                state: args.state === 'resolved' ? 'resolved' : 'firing',
                ...(args.nowMs !== undefined ? { nowMs: Number(args.nowMs) } : {})
              });
              res = { ok: true, action: 'ingest_alert', dryRun: false, policies: [], incidents: [], result: ingested };
            }
          } else if (action === 'ack_incident') {
            const incId = String(args.incidentId || '').trim();
            if (!incId) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="ack_incident" requiere incidentId.', {
                retryable: true,
                remediation: 'Lista incidentes activos con action="list_incidents".'
              });
            }
            const actor = String(args.actor || principal.email || principal.userId || 'mcp-operator');
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              res = { ok: true, action: 'ack_incident', dryRun: true, policies: [], incidents: [], result: { acknowledged: false, incidentId: incId, actor } };
            } else {
              const acked = oncallSvc.acknowledgeIncident(incId, {
                actor,
                ...(args.nowMs !== undefined ? { nowMs: Number(args.nowMs) } : {})
              });
              res = { ok: Boolean(acked && (acked.ok !== false)), action: 'ack_incident', dryRun: false, policies: [], incidents: [], result: acked };
            }
          } else {
            // action === 'evaluate_escalations'
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              res = { ok: true, action: 'evaluate_escalations', dryRun: true, policies: [], incidents: [], result: { evaluated: false } };
            } else {
              const escalated = oncallSvc.evaluateEscalations(args.nowMs !== undefined ? Number(args.nowMs) : undefined);
              res = { ok: true, action: 'evaluate_escalations', dryRun: false, policies: [], incidents: [], result: escalated };
            }
          }
          break;
        }

        case 'culkibo_egress_firewall': {
          const egressSvc = requireLazySvc('egressFirewallService', 'Container Egress & Firewall Drift Auditor');
          const action = String(args.action || 'get_policy');
          const pid = String(args.projectId || '').trim();
          if (!pid) {
            throw new McpToolError('MISSING_ARGUMENT', 'culkibo_egress_firewall requiere projectId.', {
              retryable: true,
              remediation: 'Indica projectId obtenido de culkibo_list_projects.'
            });
          }
          if (!principal.isSuperAdmin && !canAccessProject(principal, pid)) {
            throw new McpToolError('FORBIDDEN', `No tienes acceso a la política de egress del proyecto '${pid}'.`, {
              retryable: false,
              remediation: 'Usa un projectId perteneciente a tus proyectos autorizados.'
            });
          }

          if (action === 'get_policy') {
            const policy = egressSvc.getEgressPolicy(pid);
            res = { ok: true, action: 'get_policy', dryRun: false, projectId: pid, policy, audit: null };
          } else if (action === 'save_policy') {
            if (!principal.isSuperAdmin && ((ROLE_RANK[principal.role] || 0) < ROLE_RANK.admin || Array.isArray(principal.projectIds))) {
              throw new McpToolError('FORBIDDEN', 'Guardar políticas de egress firewall requiere rol admin/owner sin restricción de proyectos.', {
                retryable: false,
                remediation: 'Autentícate como admin/owner o usa action: "get_policy" / "audit".'
              });
            }
            if (!args.policy || typeof args.policy !== 'object' || Array.isArray(args.policy)) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="save_policy" requiere el objeto policy.', {
                retryable: true,
                remediation: 'Pasa policy con mode, allowedCidrs/allowedDomains, blockMetadata y preserveAdminPorts.'
              });
            }
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              res = {
                ok: true,
                action: 'save_policy',
                dryRun: true,
                saved: false,
                projectId: pid,
                policy: egressSvc.getEgressPolicy(pid),
                audit: null,
                previewPolicy: args.policy
              };
            } else {
              const saved = egressSvc.saveEgressPolicy(pid, args.policy);
              res = { ok: true, action: 'save_policy', dryRun: false, saved: true, projectId: pid, policy: saved, audit: null };
            }
          } else {
            // action === 'audit'
            const audit = egressSvc.auditFirewallAndEgress({
              projectId: pid,
              observedSockets: Array.isArray(args.observedSockets) ? args.observedSockets : [],
              firewallRules: Array.isArray(args.firewallRules) ? args.firewallRules : [],
              backend: args.backend === 'iptables' ? 'iptables' : 'nftables'
            });
            res = {
              ok: Boolean(audit && audit.compliant),
              action: 'audit',
              dryRun: false,
              projectId: pid,
              policy: egressSvc.getEgressPolicy(pid),
              audit
            };
          }
          break;
        }

        case 'culkibo_replica_failover': {
          const repSvc = requireLazySvc('replicaFailoverService', 'Blue/Green DB Read-Replica Promotion & Split-Brain Fencing');
          const action = String(args.action || 'get_topology');
          const dbId = String(args.dbId || '').trim();
          if (!dbId) {
            throw new McpToolError('MISSING_ARGUMENT', 'culkibo_replica_failover requiere dbId.', {
              retryable: true,
              remediation: 'Indica dbId obtenido de culkibo_list_databases.'
            });
          }

          if (action === 'get_topology') {
            const topology = repSvc.getTopology(dbId);
            res = { ok: true, action: 'get_topology', dryRun: false, dbId, topology, split: null, promotion: null };
          } else if (action === 'evaluate_split') {
            const split = repSvc.evaluateReadWriteSplit(dbId, {
              ...(args.maxReadLagMs !== undefined ? { maxReadLagMs: Number(args.maxReadLagMs) } : {})
            });
            res = { ok: Boolean(split && split.ok !== false), action: 'evaluate_split', dryRun: false, dbId, topology: null, split, promotion: null };
          } else if (action === 'save_topology') {
            if (!principal.isSuperAdmin && ((ROLE_RANK[principal.role] || 0) < ROLE_RANK.admin || Array.isArray(principal.projectIds))) {
              throw new McpToolError('FORBIDDEN', 'Guardar topologías de réplicas DB (save_topology) requiere rol admin/owner.', {
                retryable: false,
                remediation: 'Autentícate como admin/owner o usa action: "get_topology" / "evaluate_split".'
              });
            }
            if (!args.primary || typeof args.primary !== 'object') {
              throw new McpToolError('MISSING_ARGUMENT', 'action="save_topology" requiere el objeto primary.', {
                retryable: true,
                remediation: 'Pasa primary: { id, host, fenced } y replicas: [...] (dryRun: true por defecto).'
              });
            }
            const dryRun = args.dryRun !== false;
            if (dryRun) {
              res = {
                ok: true,
                action: 'save_topology',
                dryRun: true,
                saved: false,
                dbId,
                topology: repSvc.getTopology(dbId),
                split: null,
                promotion: null
              };
            } else {
              const saved = repSvc.saveTopology(dbId, {
                primary: args.primary,
                replicas: Array.isArray(args.replicas) ? args.replicas : []
              });
              res = { ok: true, action: 'save_topology', dryRun: false, saved: true, dbId, topology: saved, split: null, promotion: null };
            }
          } else {
            // action === 'promote'
            if (!principal.isSuperAdmin && ((ROLE_RANK[principal.role] || 0) < ROLE_RANK.admin || Array.isArray(principal.projectIds))) {
              throw new McpToolError('FORBIDDEN', 'Promover una réplica de lectura (promote) requiere rol admin/owner.', {
                retryable: false,
                remediation: 'Autentícate como admin/owner para planificar o ejecutar failover.'
              });
            }
            if (!args.targetReplicaId) {
              throw new McpToolError('MISSING_ARGUMENT', 'action="promote" requiere targetReplicaId.', {
                retryable: true,
                remediation: 'Consulta las réplicas disponibles con action="get_topology".'
              });
            }
            const dryRun = args.dryRun !== false;
            const promotion = repSvc.planReplicaPromotion(dbId, {
              targetReplicaId: String(args.targetReplicaId),
              ...(args.maxAcceptableLagBytes !== undefined ? { maxAcceptableLagBytes: Number(args.maxAcceptableLagBytes) } : {}),
              requireOldPrimaryFenced: args.requireOldPrimaryFenced !== false,
              dryRun
            });
            res = {
              ok: Boolean(promotion && promotion.allowed),
              action: 'promote',
              dryRun,
              dbId,
              topology: null,
              split: null,
              promotion
            };
          }
          break;
        }

        case 'culkibo_secret_gate': {
          const gateSvc = requireLazySvc('preDeploySecretGate', 'Pre-Deploy Shannon-Entropy & Pattern Secret Gate');
          const out = gateSvc.scanPreDeployPayload({
            files: Array.isArray(args.files) ? args.files : [],
            diffText: typeof args.diffText === 'string' ? args.diffText : '',
            envMap: args.envMap && typeof args.envMap === 'object' && !Array.isArray(args.envMap) ? args.envMap : {},
            mode: args.mode === 'warn' ? 'warn' : 'enforce',
            allowlistFingerprints: Array.isArray(args.allowlistFingerprints) ? args.allowlistFingerprints.map(String) : []
          });
          res = {
            ...out,
            ok: Boolean(out && out.allowed)
          };
          break;
        }

        case 'culkibo_multiarch_planner': {
          const maSvc = requireLazySvc('multiArchPlannerService', 'Multi-Arch OCI Manifest & Matrix Planner');
          const action = String(args.action || 'verify');
          if (action === 'plan') {
            const plan = maSvc.planBuildMatrix({
              ...(Array.isArray(args.targetPlatforms) ? { targetPlatforms: args.targetPlatforms.map(String) } : {}),
              builders: Array.isArray(args.builders) ? args.builders : [],
              preferNativeOverQemu: args.preferNativeOverQemu !== false,
              ...(typeof args.imageTag === 'string' && args.imageTag.trim() ? { imageTag: args.imageTag.trim() } : {})
            });
            res = { ok: Boolean(plan && plan.ok !== false), action: 'plan', verification: null, plan };
          } else {
            const verification = maSvc.verifyManifestCompatibility({
              ...(args.imageArch ? { imageArch: String(args.imageArch) } : {}),
              ...(args.imageOs ? { imageOs: String(args.imageOs) } : {}),
              manifestPlatforms: Array.isArray(args.manifestPlatforms) ? args.manifestPlatforms.map(String) : [],
              ...(args.hostArch ? { hostArch: String(args.hostArch) } : {}),
              strictOciRegistry: Boolean(args.strictOciRegistry),
              includeAttestations: args.includeAttestations !== false
            });
            res = { ok: Boolean(verification && verification.compatible), action: 'verify', verification, plan: null };
          }
          break;
        }

        case 'culkibo_chaos_gameday': {
          const chaosSvc = requireLazySvc('chaosGameDayService', 'Chaos Fault-Injection GameDay Simulator & Resilience Scorecard');
          const action = String(args.action || 'list');
          const pid = String(args.projectId || '').trim();
          if (!pid) {
            throw new McpToolError('MISSING_ARGUMENT', 'culkibo_chaos_gameday requiere projectId.', {
              retryable: true,
              remediation: 'Indica projectId obtenido de culkibo_list_projects.'
            });
          }
          if (!principal.isSuperAdmin && !canAccessProject(principal, pid)) {
            throw new McpToolError('FORBIDDEN', `No tienes acceso a Chaos GameDays del proyecto '${pid}'.`, {
              retryable: false,
              remediation: 'Usa un projectId perteneciente a tus proyectos autorizados.'
            });
          }

          if (action === 'list') {
            const rawG = chaosSvc.listGameDays(pid);
            const gamedays = Array.isArray(rawG) ? rawG : (Array.isArray(rawG?.gamedays) ? rawG.gamedays : []);
            res = { ok: true, action: 'list', dryRun: false, projectId: pid, gamedays, result: null };
          } else if (action === 'score') {
            const scored = chaosSvc.evaluateResilienceScore({
              errorRatePct: args.errorRatePct !== undefined ? Number(args.errorRatePct) : 0,
              ...(args.allowedErrorRatePct !== undefined ? { allowedErrorRatePct: Number(args.allowedErrorRatePct) } : {}),
              p95LatencyMs: args.p95LatencyMs !== undefined ? Number(args.p95LatencyMs) : 120,
              ...(args.sloP95Ms !== undefined ? { sloP95Ms: Number(args.sloP95Ms) } : {}),
              recoverySec: args.recoverySec !== undefined ? Number(args.recoverySec) : 10,
              ...(args.targetRecoverySec !== undefined ? { targetRecoverySec: Number(args.targetRecoverySec) } : {})
            });
            res = { ok: true, action: 'score', dryRun: false, projectId: pid, gamedays: [], result: scored };
          } else {
            // action === 'simulate'
            const dryRun = args.dryRun !== false;
            const sim = chaosSvc.runGameDaySimulation({
              projectId: pid,
              environment: args.environment ? String(args.environment) : 'staging',
              explicitProdConfirm: Boolean(args.explicitProdConfirm),
              faultType: args.faultType ? String(args.faultType) : 'latency_jitter',
              ...(args.latencyMs !== undefined ? { latencyMs: Number(args.latencyMs) } : {}),
              ...(args.jitterMs !== undefined ? { jitterMs: Number(args.jitterMs) } : {}),
              ...(args.faultRatePct !== undefined ? { faultRatePct: Number(args.faultRatePct) } : {}),
              ...(args.maxErrorAbortPct !== undefined ? { maxErrorAbortPct: Number(args.maxErrorAbortPct) } : {}),
              ...(Array.isArray(args.requestSamples) ? { requestSamples: args.requestSamples } : {}),
              ...(args.recoverySec !== undefined ? { recoverySec: Number(args.recoverySec) } : {}),
              ...(args.sloP95Ms !== undefined ? { sloP95Ms: Number(args.sloP95Ms) } : {}),
              ...(args.allowedErrorRatePct !== undefined ? { allowedErrorRatePct: Number(args.allowedErrorRatePct) } : {}),
              dryRun
            });
            res = {
              ok: Boolean(sim && sim.ok !== false && !sim.blocked),
              action: 'simulate',
              dryRun,
              projectId: pid,
              gamedays: [],
              result: sim
            };
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
      const attachedUiUri = mcpAppsRenderer.TOOL_UI_RESOURCE_MAP[toolName];
      if (attachedUiUri) {
        result._meta = { ui: { resourceUri: attachedUiUri } };
      }
      return result;
    } catch (err) {
      const durationMs = performance.now() - start;
      const envelope = this.describeToolFailure(toolName, tool, err, durationMs);
      const elicitation = this._buildErrorElicitation(toolName, args, envelope, err);
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
        _meta: {
          [META_CULKIBO_ERROR]: envelope,
          ...(elicitation ? { [META_ELICITATION]: elicitation } : {})
        }
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
    const principal = normalizePrincipal(authOrPrincipal);
    if (principal.role === 'none') return [];
    const dataResources = [
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
    const uiResources = mcpAppsRenderer.MCP_APP_RESOURCES.map((app) => ({
      uri: app.uri,
      name: app.name,
      title: app.title,
      description: app.description,
      mimeType: app.mimeType,
      _meta: app._meta
    }));
    const all = [...dataResources, ...uiResources];
    if (principal.isSuperAdmin || principal.scopes.includes('*')) return all;
    /** @type {Record<string, string>} */
    const scopeByUri = {
      'culkibo://projects': 'projects:read',
      'culkibo://pods': 'pods:read',
      'culkibo://doctor': 'system:read',
      'culkibo://domains': 'domains:read',
      'culkibo://fleet': 'fleet:read',
      'culkibo://uptime': 'uptime:read',
      'culkibo://environments': 'environments:read',
      'ui://culkibo/topology': 'projects:read',
      'ui://culkibo/incident-remediator': 'observability:read',
      'ui://culkibo/coolify-migration-diff': 'migrations:read'
    };
    return all.filter((r) => scopeMatches(principal.scopes, scopeByUri[r.uri] || 'system:read', r.uri, false));
  }

  /**
   * Lee un recurso MCP (JSON `culkibo://*` o MCP App interactiva `ui://culkibo/*`)
   * filtrando por ACL/RBAC del principal y redactando secretos.
   * @param {string} uri
   * @param {{ auth?: any }} [context]
   */
  async readResource(uri, context = {}) {
    const clean = String(uri || '').trim();
    const principal = normalizePrincipal(context.auth);
    if (principal.role === 'none') {
      throw new McpToolError('FORBIDDEN', `Acceso denegado al recurso '${clean}' para credencial no autenticada o revocada.`, {
        retryable: false,
        remediation: 'Autentícate con un token válido antes de leer recursos MCP.'
      });
    }
    /** @type {Record<string, string>} */
    const resourceScopes = {
      'culkibo://projects': 'projects:read',
      'culkibo://pods': 'pods:read',
      'culkibo://doctor': 'system:read',
      'culkibo://domains': 'domains:read',
      'culkibo://fleet': 'fleet:read',
      'culkibo://uptime': 'uptime:read',
      'culkibo://environments': 'environments:read',
      'ui://culkibo/topology': 'projects:read',
      'ui://culkibo/incident-remediator': 'observability:read',
      'ui://culkibo/coolify-migration-diff': 'migrations:read'
    };
    const reqScope = resourceScopes[clean];
    if (reqScope && !principal.isSuperAdmin && !scopeMatches(principal.scopes, reqScope, clean, false)) {
      throw new McpToolError('FORBIDDEN', `Acceso denegado al recurso '${clean}' para los scopes del token.`, {
        retryable: false,
        remediation: 'Consulta tus scopes efectivos con culkibo_rbac_whoami o solicita un token con el scope de lectura correspondiente.'
      });
    }

    // --- MCP Apps (`ui://culkibo/*`, modelcontextprotocol/ext-apps 2026-01-26) ---
    if (clean === 'ui://culkibo/topology') {
      const allowedProjectIds = this._accessibleProjectIds(principal);
      const topoSvc = lazySvc('topologyService');
      /** @type {any} */
      let topology = null;
      if (topoSvc && typeof topoSvc.buildTopology === 'function') {
        topology = topoSvc.buildTopology({ allowedProjectIds, isSuperAdmin: principal.isSuperAdmin });
      } else {
        const visible = projectManager.getAll().filter((p) => canAccessProject(principal, p.id, p));
        topology = {
          nodes: visible.map((p) => ({
            id: `project:${p.id}`,
            kind: 'project',
            entityId: p.id,
            label: p.name || p.id,
            status: p.status || 'active',
            health: 'healthy'
          })),
          edges: []
        };
      }
      const rendered = mcpAppsRenderer.renderMcpApp(clean, topology);
      return { contents: [rendered] };
    }
    if (clean === 'ui://culkibo/incident-remediator') {
      const diag = await this.diagnoseIncident(principal, { includeDoctor: false, probeDomain: false });
      const rendered = mcpAppsRenderer.renderMcpApp(clean, diag);
      return { contents: [rendered] };
    }
    if (clean === 'ui://culkibo/coolify-migration-diff') {
      const visibleProjects = projectManager.getAll()
        .filter((p) => canAccessProject(principal, p.id, p))
        .map((p) => ({ id: p.id, name: p.name, status: p.status || 'active', migrationSource: p.migrationSource || null }));
      const visibleDbs = databaseManager.list()
        .filter((d) => principal.isSuperAdmin || canAccessProject(principal, d.projectId))
        .map((d) => ({ id: d.id, name: d.name, engine: d.engine }));
      const rendered = mcpAppsRenderer.renderMcpApp(clean, {
        parityScore: 100,
        resources: {
          apps: visibleProjects.filter((p) => p.migrationSource === 'coolify' || visibleProjects.length <= 20),
          databases: visibleDbs,
          services: []
        }
      });
      return { contents: [rendered] };
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
            prompts: { listChanged: false },
            tasks: {
              list: {},
              cancel: {},
              requests: {
                tools: {
                  call: {}
                }
              }
            },
            extensions: {
              'io.modelcontextprotocol/ui': {
                mimeTypes: [mcpAppsRenderer.MCP_APP_MIME_TYPE],
                specVersion: mcpAppsRenderer.MCP_APPS_SPEC_VERSION
              }
            }
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
      if (params && params.task && typeof params.task === 'object' && !Array.isArray(params.task)) {
        try {
          const task = this.enqueueToolTask(toolName, args, params.task, {
            transport: context.transport || `MCP ${LEGACY_PROTOCOL_VERSION} (async-task)`,
            auth: context.auth
          });
          return {
            jsonrpc: '2.0',
            id: safeId,
            result: {
              task,
              _meta: { [META_RELATED_TASK]: { taskId: task.taskId } }
            }
          };
        } catch (err) {
          return {
            jsonrpc: '2.0',
            id: safeId,
            error: { code: ERROR_CODES.INVALID_PARAMS, message: err.message, data: { code: err.code || 'TASK_ERROR' } }
          };
        }
      }
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

    if (method === 'tasks/list') {
      try {
        return { jsonrpc: '2.0', id: safeId, result: { tasks: this.listTasks(context.auth) } };
      } catch (err) {
        return { jsonrpc: '2.0', id: safeId, error: { code: ERROR_CODES.INVALID_PARAMS, message: err.message, data: { code: err.code || 'TASK_ERROR' } } };
      }
    }

    if (method === 'tasks/get') {
      try {
        return { jsonrpc: '2.0', id: safeId, result: this.getTask(params?.taskId, context.auth) };
      } catch (err) {
        return { jsonrpc: '2.0', id: safeId, error: { code: ERROR_CODES.INVALID_PARAMS, message: err.message, data: { code: err.code || 'TASK_NOT_FOUND', taskId: params?.taskId } } };
      }
    }

    if (method === 'tasks/result') {
      try {
        return { jsonrpc: '2.0', id: safeId, result: await this.getTaskResult(params?.taskId, context.auth) };
      } catch (err) {
        return { jsonrpc: '2.0', id: safeId, error: { code: ERROR_CODES.INVALID_PARAMS, message: err.message, data: { code: err.code || 'TASK_ERROR', taskId: params?.taskId } } };
      }
    }

    if (method === 'tasks/cancel') {
      try {
        return { jsonrpc: '2.0', id: safeId, result: this.cancelTask(params?.taskId, context.auth) };
      } catch (err) {
        return { jsonrpc: '2.0', id: safeId, error: { code: ERROR_CODES.INVALID_PARAMS, message: err.message, data: { code: err.code || 'TASK_ERROR', taskId: params?.taskId } } };
      }
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
          supported: ['initialize', 'tools/list', 'tools/call', 'resources/list', 'resources/read', 'prompts/list', 'prompts/get', 'tasks/list', 'tasks/get', 'tasks/result', 'tasks/cancel'],
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
          prompts: { listChanged: false },
          tasks: {
            list: {},
            cancel: {},
            requests: {
              tools: {
                call: {}
              }
            }
          },
          extensions: {
            'io.modelcontextprotocol/ui': {
              mimeTypes: [mcpAppsRenderer.MCP_APP_MIME_TYPE],
              specVersion: mcpAppsRenderer.MCP_APPS_SPEC_VERSION
            }
          }
        },
        instructions: [
          'Culkibo es un orquestador cloud AI-native autohospedado (MCP 2026-07-28: 155 herramientas anotadas, Async Tasks oficiales tasks/list|get|result|cancel, elicitation/create en rutas de remediación, 10 recursos incluyendo 3 MCP Apps interactivas ui://culkibo/* y 13 prompts con 8 playbooks de ingeniería). Gestiona proyectos, pods (The Forge y The Citadel), SmartPack build intelligence, túneles CGNAT soberanos EdgeTunnel, atestaciones SLSA v1.1 Ed25519 DSSE (culkibo_verify_attestation), exportación OTLP/HTTP nativa sin deps (culkibo_otlp_status), Shadow Traffic Replay con puerta de cutover (culkibo_shadow_replay), Time-Machine de stack completo (culkibo_time_machine), FinOps Cloud vs Self-Hosted (culkibo_finops_report), Auto-Healer determinista de 20 patrones (culkibo_heal_build_failure), malla WireGuard cero-configuración (culkibo_fleet_mesh), heatmap 24h de Crons y Dead-Man-Switch Heartbeats (culkibo_cron_timeline), Edge Bot-Shield + Hashcash PoW (culkibo_edge_shield), triaje autónomo unificado (culkibo_triage_playbook), escaneo SBOM CVE OSV.dev (culkibo_cve_scan), detector de drift y PgBouncer (culkibo_drift_check), exportador IaC OpenTofu/Compose sin lock-in (culkibo_export_iac), leases efímeros de secretos y Break-Glass (culkibo_secret_lease), bus Standard-Webhooks con DLQ y dual-secret (culkibo_webhook_dlq), DB Studio de solo lectura y Redis seguro (culkibo_db_studio), orquestador S3 Post-MinIO Garage/RustFS/SeaweedFS + SigV4 (culkibo_s3_storage), cuotas multi-tenant y ledger facturable CSV-safe (culkibo_agency_ledger), tema white-label open-core (culkibo_brand_theme), DR Fire-Drills de backups (culkibo_dr_drill), SLO Error-Budget Canary Auto-Rollback (culkibo_slo_canary), orquestador AI/GPU LLM local (culkibo_ai_workload), remote build-node offloader (culkibo_remote_builder), archivo comprimido .ndjson.gz de logs (culkibo_log_archive_search), Policy-as-Code Admission de 10 reglas CIS/PSS (culkibo_admission_check), expedientes SOC2/ISO27001/GDPR firmados Ed25519 (culkibo_compliance_bundle), planificador de migración stateful cross-VPS en 4 fases (culkibo_volume_migrate), Geo-Routing y A/B sticky en Caddy v2.11 (culkibo_edge_experiment), scorecard ejecutivo de seguridad (culkibo_security_posture), flujos sintéticos multi-paso y sonda TLS/SNI (culkibo_synthetic_sentinel), linter SQL zero-downtime de 10 reglas DDL (culkibo_lint_sql_migration), autoscaler de workers OOM-safe y circuit breaker 503 (culkibo_worker_autoscaler), auditor de licencias SPDX CycloneDX 1.6 (culkibo_audit_licenses), perfiles OCI seccomp mínimos y guardia runc CVE (culkibo_seccomp_profile), auditor de bloat/secretos en capas OCI (culkibo_audit_image_bloat), leases distribuidos de Cron con fencing tokens (culkibo_cron_lease), enmascarador determinista PII para PR-Preview + pg_anonymizer (culkibo_mask_preview_pii), clasificador forense OOM/Exit-Code de 8 clases (culkibo_oom_forensics), enrutador On-Call con dedup y amortiguación de flapping (culkibo_oncall_router), auditor de egress y drift DOCKER-USER/nftables (culkibo_egress_firewall), failover Blue/Green de réplicas DB con fencing anti split-brain (culkibo_replica_failover), puerta pre-despliegue de secretos por entropía de Shannon (culkibo_secret_gate), planificador multi-arch amd64/arm64 OCI (culkibo_multiarch_planner), simulador Chaos Engineering GameDay con auto-abort (culkibo_chaos_gameday), flota multi-servidor SSH, equipos/RBAC, entornos y promoción, uptime y páginas de estado, GitOps (culkibo.yaml), Smart Sleep y Cost Advisor, LiveSync 2.0 time-travel, smoke tests, canary auto-guard, deploy freeze, despliegue autónomo Ship & Verify, diagnóstico de incidentes, remediación segura y generación 1-clic de kits de agente.',
          'Para reducir el consumo de contexto en >80%, conecta con POST /api/mcp?profile=core|deploy|ops|security|all (o env CULKIBO_MCP_PROFILE=core sobre stdio), usa tools/list con params.query o descubre cualquier herramienta bajo demanda con culkibo_search_tools.',
          'Para operaciones largas usa Async Tasks enviando params.task ({ ttl: 60000 }) en tools/call y consulta tasks/list, tasks/get, tasks/result o tasks/cancel (aisladas estrictamente por principal RBAC).',
          'Para desplegar con escaneo pre-despliegue de secretos, smoke checks y rollback automático usa culkibo_ship_and_verify (dryRun: true -> confirmToken HMAC-SHA256 de un solo uso -> dryRun: false). Para incidentes usa culkibo_diagnose_incident + culkibo_auto_remediate.',
          'Las herramientas culkibo_list_projects, culkibo_list_pods, culkibo_diagnose_incident y culkibo_migrate_coolify enlazan MCP Apps nativas (ui://culkibo/topology, ui://culkibo/incident-remediator, ui://culkibo/coolify-migration-diff) con mimeType text/html;profile=mcp-app y CSP estricta.',
          'Usa prompts/list para acceder a los 8 playbooks interactivos y culkibo_export_agent_kit para generar configs drop-in sin secretos en claro.',
          'Cuando una llamada falla, el bloque de texto del resultado es un JSON con code, retryable y remediation (y _meta["io.modelcontextprotocol/elicitation"] en confirmación/secretos/freeze).'
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
      if (params && params.task && typeof params.task === 'object' && !Array.isArray(params.task)) {
        try {
          const task = this.enqueueToolTask(toolName, args, params.task, {
            transport,
            clientInfo,
            onProgress: context.onProgress,
            auth: context.auth
          });
          return ok({
            task,
            cacheScope: 'private',
            _meta: { [META_RELATED_TASK]: { taskId: task.taskId } }
          });
        } catch (err) {
          return {
            jsonrpc: '2.0',
            id,
            error: {
              code: ERROR_CODES.INVALID_PARAMS,
              message: err.message,
              data: { code: err.code || 'TASK_ERROR' }
            }
          };
        }
      }
      const toolResult = await this.executeTool(toolName, args, {
        transport,
        clientInfo,
        signal: context.signal,
        onProgress: context.onProgress,
        auth: context.auth
      });
      return ok(toolResult);
    }

    if (method === 'tasks/list') {
      try {
        return ok({
          tasks: this.listTasks(principal),
          ttlMs: 0,
          cacheScope: 'private'
        });
      } catch (err) {
        return {
          jsonrpc: '2.0',
          id,
          error: { code: ERROR_CODES.INVALID_PARAMS, message: err.message, data: { code: err.code || 'TASK_ERROR' } }
        };
      }
    }

    if (method === 'tasks/get') {
      try {
        return ok({
          ...this.getTask(params?.taskId, principal),
          cacheScope: 'private'
        });
      } catch (err) {
        return {
          jsonrpc: '2.0',
          id,
          error: { code: ERROR_CODES.INVALID_PARAMS, message: err.message, data: { code: err.code || 'TASK_NOT_FOUND', taskId: params?.taskId } }
        };
      }
    }

    if (method === 'tasks/result') {
      try {
        const taskResult = await this.getTaskResult(params?.taskId, principal);
        return ok({
          ...taskResult,
          cacheScope: 'private'
        });
      } catch (err) {
        return {
          jsonrpc: '2.0',
          id,
          error: { code: ERROR_CODES.INVALID_PARAMS, message: err.message, data: { code: err.code || 'TASK_ERROR', taskId: params?.taskId } }
        };
      }
    }

    if (method === 'tasks/cancel') {
      try {
        return ok({
          ...this.cancelTask(params?.taskId, principal),
          cacheScope: 'private'
        });
      } catch (err) {
        return {
          jsonrpc: '2.0',
          id,
          error: { code: ERROR_CODES.INVALID_PARAMS, message: err.message, data: { code: err.code || 'TASK_ERROR', taskId: params?.taskId } }
        };
      }
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
    META_ELICITATION,
    META_RELATED_TASK,
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
  redactForAudit,
  buildElicitationRequest
});

module.exports = mcpServer;
