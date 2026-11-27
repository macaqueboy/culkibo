import React, { useState, useEffect, useMemo } from 'react';
import {
  Play,
  Copy,
  Check,
  Terminal,
  Zap,
  Shield,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Search,
  Radio,
  AlertTriangle,
  Loader2,
  BookOpen,
  Sparkles,
  Eye,
  KeyRound,
  Rocket,
  FileCode2,
  ChevronRight,
  Layers,
} from 'lucide-react';
import type { McpAuditEntry, RemoteAccessInfo } from '../lib/api';
import { api, apiFetch } from '../lib/api';
import { liveEvents } from '../lib/liveEvents';
import { copyToClipboard } from '../lib/clipboard';
import { HelpTip } from './HelpTip';

type AgentCardId = 'antigravity' | 'claude-code' | 'cursor' | 'windsurf' | 'codex' | 'vscode' | 'claude-desktop';
type ClaudeSubTab = 'mcp-json' | 'claude-md' | 'cli';
type McpProfile = 'core' | 'deploy' | 'ops' | 'security' | 'all';

interface McpPromptArg {
  name: string;
  description?: string;
  required?: boolean;
}

interface McpPromptSpec {
  name: string;
  title?: string;
  description: string;
  arguments?: McpPromptArg[];
}

interface McpAppResourceSpec {
  uri: string;
  name: string;
  title?: string;
  description: string;
  mimeType: string;
  _meta?: {
    ui?: {
      csp?: { policy?: string };
      prefersBorder?: boolean;
      specVersion?: string;
    };
  };
}

const FALLBACK_MCP_APPS: ReadonlyArray<McpAppResourceSpec> = [
  {
    uri: 'ui://culkibo/topology',
    name: 'Culkibo Live Topology App',
    title: 'Interactive Service, DB, Domain & Fleet Topology',
    description: 'Mapa interactivo en vivo de dominios, proyectos, bases de datos y flota SSH con puente de diagnóstico y despliegue seguro.',
    mimeType: 'text/html;profile=mcp-app',
    _meta: { ui: { csp: { policy: "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'" }, prefersBorder: true, specVersion: '2026-01-26' } },
  },
  {
    uri: 'ui://culkibo/incident-remediator',
    name: 'Culkibo Incident Remediator App',
    title: 'Live OOM/Crash Diagnostics & 2-Phase Safe Remediator',
    description: 'Correlaciona OOMKilled, CrashLoop, logs y uptime con remediación interactiva en 2 fases (dryRun → confirmToken HMAC).',
    mimeType: 'text/html;profile=mcp-app',
    _meta: { ui: { csp: { policy: "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'" }, prefersBorder: true, specVersion: '2026-01-26' } },
  },
  {
    uri: 'ui://culkibo/coolify-migration-diff',
    name: 'Culkibo Coolify v4 Migration Diff App',
    title: 'Coolify v4 Parity Score & Traefik → Caddy Edge Diff',
    description: 'Visualiza el Parity Score de Coolify v4, traducción redactada de Magic Vars (${vault.*}) y diff Traefik → Caddy.',
    mimeType: 'text/html;profile=mcp-app',
    _meta: { ui: { csp: { policy: "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'" }, prefersBorder: true, specVersion: '2026-01-26' } },
  },
];

const PROFILE_OPTIONS: ReadonlyArray<{ id: McpProfile; label: string; short: string; hint: string }> = [
  { id: 'core', label: 'Core (Recomendado)', short: 'Core', hint: '17 herramientas esenciales + culkibo_ship_and_verify + culkibo_search_tools (>81% ahorro)' },
  { id: 'deploy', label: 'Deploy & CI/CD', short: 'Deploy', hint: 'Despliegues, Ship & Verify, Canary, Smoke, Previews, Freeze y Entornos' },
  { id: 'ops', label: 'Ops & Self-Healing', short: 'Ops', hint: 'Diagnóstico autónomo, remediación, logs, Docker, Uptime y Smart Sleep' },
  { id: 'security', label: 'Security & RBAC', short: 'Security', hint: 'Equipos, tokens, TLS/wildcard, Basic Auth, snapshots y System Doctor' },
  { id: 'all', label: 'Todas', short: 'Todas', hint: 'Catálogo completo sin filtrado de perfil' },
];

const PROFILE_TOOL_SETS: Record<Exclude<McpProfile, 'all'>, ReadonlySet<string>> = {
  core: new Set([
    'culkibo_search_tools', 'culkibo_rbac_whoami', 'culkibo_list_projects', 'culkibo_get_project',
    'culkibo_create_project', 'culkibo_set_project_env', 'culkibo_deploy_production', 'culkibo_ship_and_verify',
    'culkibo_list_deployments', 'culkibo_rollback_deployment', 'culkibo_get_container_logs', 'culkibo_get_deployment_logs',
    'culkibo_manage_domain', 'culkibo_list_databases', 'culkibo_system_doctor', 'culkibo_diagnose_incident',
    'culkibo_auto_remediate',
  ]),
  deploy: new Set([
    'culkibo_search_tools', 'culkibo_export_agent_kit', 'culkibo_rbac_whoami', 'culkibo_list_projects',
    'culkibo_get_project', 'culkibo_create_project', 'culkibo_add_resource', 'culkibo_set_project_env',
    'culkibo_deploy_strategy', 'culkibo_smartpack_plan', 'culkibo_deploy_production', 'culkibo_ship_and_verify',
    'culkibo_list_deployments', 'culkibo_rollback_deployment', 'culkibo_cancel_deployment', 'culkibo_get_deploy_queue',
    'culkibo_get_deployment_logs', 'culkibo_get_container_logs', 'culkibo_manage_previews', 'culkibo_smoke_test_configure',
    'culkibo_smoke_test_run', 'culkibo_canary_rollout', 'culkibo_deploy_freeze', 'culkibo_env_list', 'culkibo_env_promote',
  ]),
  ops: new Set([
    'culkibo_search_tools', 'culkibo_export_agent_kit', 'culkibo_rbac_whoami', 'culkibo_list_projects',
    'culkibo_get_project', 'culkibo_list_pods', 'culkibo_get_logs', 'culkibo_get_container_logs',
    'culkibo_get_observability', 'culkibo_system_doctor', 'culkibo_system_doctor_fix', 'culkibo_docker_status',
    'culkibo_docker_containers', 'culkibo_manage_production_service', 'culkibo_toggle_maintenance', 'culkibo_diagnose_domain',
    'culkibo_ingress_status', 'culkibo_reconcile_ingress', 'culkibo_edge_tunnel', 'culkibo_uptime_list_monitors',
    'culkibo_status_page_manage', 'culkibo_cost_advisor', 'culkibo_sleep_status', 'culkibo_sleep_manage',
    'culkibo_fleet_list_servers', 'culkibo_diagnose_incident', 'culkibo_auto_remediate',
  ]),
  security: new Set([
    'culkibo_search_tools', 'culkibo_export_agent_kit', 'culkibo_rbac_whoami', 'culkibo_team_list_members',
    'culkibo_team_invite_member', 'culkibo_team_update_member', 'culkibo_rbac_list_tokens', 'culkibo_rbac_manage_token',
    'culkibo_system_doctor', 'culkibo_system_doctor_fix', 'culkibo_diagnose_domain', 'culkibo_ingress_status',
    'culkibo_manage_wildcard_dns01', 'culkibo_edge_tunnel', 'culkibo_set_domain_basic_auth', 'culkibo_manage_webhook',
    'culkibo_deploy_freeze', 'culkibo_list_databases', 'culkibo_database_list_backups', 'culkibo_export_instance_snapshot',
    'culkibo_diagnose_incident',
  ]),
};

const CORE_PLAYBOOK_META: Record<string, { badge: string; tone: string; steps: string }> = {
  deploy_safely: {
    badge: 'Deploy',
    tone: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    steps: 'Secret scan → Ship & Verify → Smoke → Métricas',
  },
  migrate_from_coolify: {
    badge: 'Migration',
    tone: 'bg-sky-50 text-sky-700 border-sky-200',
    steps: 'Scan Coolify → Magic vars & Traefik → Plan → Verify',
  },
  debug_production_crash: {
    badge: 'Incident',
    tone: 'bg-rose-50 text-rose-700 border-rose-200',
    steps: 'Diagnose → Correlate OOM/Logs → Safe Remediate',
  },
  zero_downtime_db_upgrade: {
    badge: 'Database',
    tone: 'bg-amber-50 text-amber-800 border-amber-200',
    steps: 'Backup + DR Drill → Clone/Pooler → Cutover',
  },
  security_audit_stack: {
    badge: 'Security',
    tone: 'bg-indigo-50 text-indigo-700 border-indigo-200',
    steps: 'Audit Chain → Secret Scan → RBAC/2FA/OIDC → TLS',
  },
  setup_wildcard_tls_and_tunnel: {
    badge: 'TLS / Edge',
    tone: 'bg-cyan-50 text-cyan-800 border-cyan-200',
    steps: 'Multi-DNS-01 *.dominio o Cloudflare CGNAT 0 puertos',
  },
  optimize_ram_and_costs: {
    badge: 'FinOps',
    tone: 'bg-teal-50 text-teal-800 border-teal-200',
    steps: 'Cost Advisor → Smart Sleep → Right-Sizing',
  },
  disaster_recovery_drill: {
    badge: 'DR Drill',
    tone: 'bg-violet-50 text-violet-800 border-violet-200',
    steps: 'AES-256-GCM Verify → Restore No Destructivo → RTO/RPO',
  },
};

const FALLBACK_PLAYBOOKS: ReadonlyArray<McpPromptSpec> = [
  {
    name: 'deploy_safely',
    title: 'Deploy Safely',
    description: 'Escaneo pre-despliegue de secretos, despliegue seguro con culkibo_ship_and_verify, smoke checks y verificación de métricas.',
    arguments: [
      { name: 'projectId', description: 'ID del proyecto', required: true },
      { name: 'targetEnv', description: 'Entorno objetivo', required: false },
    ],
  },
  {
    name: 'migrate_from_coolify',
    title: 'Migrate from Coolify',
    description: 'Inventario read-only de Coolify, traducción de magic vars y Traefik a Caddy, plan e importación verificada.',
    arguments: [
      { name: 'coolifyUrl', description: 'URL de Coolify', required: true },
      { name: 'targetServerId', description: 'Nodo destino', required: false },
    ],
  },
  {
    name: 'debug_production_crash',
    title: 'Debug Production Crash',
    description: 'Ejecuta culkibo_diagnose_incident, correlaciona OOM/logs/restarts y propone remediación segura con confirmToken.',
    arguments: [
      { name: 'projectId', description: 'ID del proyecto', required: false },
      { name: 'hostname', description: 'Dominio afectado', required: false },
    ],
  },
  {
    name: 'zero_downtime_db_upgrade',
    title: 'Zero-Downtime DB Upgrade',
    description: 'Backup cifrado + verificación + ensayo DR, clon/pooler paralelo y cutover controlado.',
    arguments: [
      { name: 'databaseId', description: 'ID de la base de datos', required: true },
      { name: 'targetVersion', description: 'Versión objetivo', required: false },
    ],
  },
  {
    name: 'security_audit_stack',
    title: 'Security Audit Stack',
    description: 'Verifica cadena hash de auditoría, escaneo de secretos, postura RBAC/2FA/OIDC y caducidad TLS.',
    arguments: [{ name: 'scope', description: 'Alcance (instance o projectId)', required: false }],
  },
  {
    name: 'setup_wildcard_tls_and_tunnel',
    title: 'Setup Wildcard TLS & Tunnel',
    description: 'Configura wildcard multi-DNS-01 o Cloudflare Tunnel CGNAT con cero puertos abiertos.',
    arguments: [
      { name: 'rootDomain', description: 'Dominio raíz', required: true },
      { name: 'mode', description: 'dns01 | tunnel | hybrid', required: false },
    ],
  },
  {
    name: 'optimize_ram_and_costs',
    title: 'Optimize RAM & Costs',
    description: 'Combina Sleep Advisor, Cost Advisor y right-sizing de límites de contenedores.',
    arguments: [{ name: 'monthlyServerCostEur', description: 'Coste VPS mensual (EUR)', required: false }],
  },
  {
    name: 'disaster_recovery_drill',
    title: 'Disaster Recovery Drill',
    description: 'Verificación de backups AES-256-GCM y simulacro de restauración no destructivo con RTO/RPO.',
    arguments: [
      { name: 'databaseId', description: 'ID de BD', required: false },
      { name: 'projectId', description: 'ID de proyecto', required: false },
    ],
  },
];

function appendProfileToUrl(rawUrl: string, profile: McpProfile): string {
  if (!rawUrl || profile === 'all') return rawUrl;
  const cleaned = rawUrl.replace(/([?&])profile=[^&]*(&?)/, (_m, sep, trail) => (trail ? sep : '')).replace(/[?&]$/, '');
  const joiner = cleaned.includes('?') ? '&' : '?';
  return `${cleaned}${joiner}profile=${profile}`;
}

function resolveBaseOrigin(cfg: any, scope: 'local' | 'remote', remoteInfo: RemoteAccessInfo | null): string {
  const fromProto = typeof cfg?.protocol?.endpoint === 'string'
    ? cfg.protocol.endpoint.replace(/\/api\/mcp(?:\?.*)?$/i, '')
    : '';
  if (scope === 'remote') {
    if (remoteInfo?.recommendedUrl) return remoteInfo.recommendedUrl.replace(/\/+$/, '');
    if (fromProto) return fromProto;
  }
  if (fromProto) return fromProto;
  return typeof window !== 'undefined' && window.location?.origin
    ? window.location.origin.replace(/\/+$/, '')
    : 'http://127.0.0.1:3030';
}

function buildAgentSnippets(
  baseUrl: string,
  profile: McpProfile,
  profileStats: { count: number; total: number; savedPct: number },
  baseConfigs: any
) {
  const endpoint = appendProfileToUrl(`${baseUrl}/api/mcp`, profile);
  const tokenPlaceholder = '${CULKIBO_TOKEN}';

  const antigravity = JSON.stringify(
    {
      mcpServers: {
        culkibo: {
          serverUrl: endpoint,
          headers: { Authorization: `Bearer ${tokenPlaceholder}` },
        },
      },
    },
    null,
    2
  );

  const claudeCodeJson = JSON.stringify(
    {
      mcpServers: {
        culkibo: {
          type: 'http',
          url: endpoint,
          headers: { Authorization: `Bearer ${tokenPlaceholder}` },
        },
      },
    },
    null,
    2
  );

  const claudeMd = [
    '<!-- culkibo-mcp-ops:start -->',
    '## Culkibo AI-Native PaaS Operations (MCP 2026)',
    '',
    `- Endpoint MCP: \`${endpoint}\` (perfil \`${profile}\`: **${profileStats.count}/${profileStats.total || 111}** herramientas, **-${profileStats.savedPct}%** contexto).`,
    '- Exporta `CULKIBO_TOKEN` en tu entorno local; nunca guardes tokens maestros en Git.',
    '- Usa `culkibo_search_tools` para descubrir herramientas fuera del perfil activo bajo demanda.',
    '- Usa `culkibo_ship_and_verify` (`dryRun: true` → `confirmToken` → `dryRun: false`) para desplegar con escaneo de secretos, smoke checks y auto-rollback.',
    '- Usa `culkibo_diagnose_incident` + `culkibo_auto_remediate` para autocuración segura.',
    '<!-- culkibo-mcp-ops:end -->',
  ].join('\n');

  const claudeCodeCli = `claude mcp add --transport http culkibo "${endpoint}" --header "Authorization: Bearer ${tokenPlaceholder}"`;

  const cursor = JSON.stringify(
    {
      mcpServers: {
        culkibo: {
          url: endpoint,
          headers: { Authorization: `Bearer ${tokenPlaceholder}` },
        },
      },
    },
    null,
    2
  );

  const windsurf = JSON.stringify(
    {
      mcpServers: {
        culkibo: {
          serverUrl: endpoint,
          headers: { Authorization: `Bearer ${tokenPlaceholder}` },
        },
      },
    },
    null,
    2
  );

  const codexToml = [
    '# Culkibo MCP 2026 — OpenAI Codex CLI',
    `# Profile: ${profile} (${profileStats.count}/${profileStats.total || 111} tools, -${profileStats.savedPct}% context)`,
    '[mcp_servers.culkibo]',
    `url = "${endpoint}"`,
    'bearer_token_env_var = "CULKIBO_TOKEN"',
  ].join('\n');

  const codexCliCmd = `codex mcp add culkibo --url "${endpoint}" --bearer-token-env-var CULKIBO_TOKEN`;

  const vscode = JSON.stringify(
    {
      servers: {
        culkibo: {
          type: 'http',
          url: endpoint,
          headers: { Authorization: `Bearer ${tokenPlaceholder}` },
        },
      },
    },
    null,
    2
  );

  const desktopCfg = baseConfigs?.claudeDesktop
    ? JSON.parse(JSON.stringify(baseConfigs.claudeDesktop))
    : {
        mcpServers: {
          culkibo: {
            command: 'culkibo',
            args: ['mcp'],
            env: { CULKIBO_API_URL: baseUrl, CULKIBO_TOKEN: tokenPlaceholder },
          },
        },
      };
  if (desktopCfg?.mcpServers?.culkibo?.env) {
    desktopCfg.mcpServers.culkibo.env.CULKIBO_API_URL = baseUrl;
    desktopCfg.mcpServers.culkibo.env.CULKIBO_TOKEN = tokenPlaceholder;
    if (profile === 'all') delete desktopCfg.mcpServers.culkibo.env.CULKIBO_MCP_PROFILE;
    else desktopCfg.mcpServers.culkibo.env.CULKIBO_MCP_PROFILE = profile;
  }

  return {
    endpoint,
    antigravity,
    claudeCodeJson,
    claudeMd,
    claudeCodeCli,
    cursor,
    windsurf,
    codexToml,
    codexCliCmd,
    vscode,
    claudeDesktop: JSON.stringify(desktopCfg, null, 2),
  };
}

function extractMcpErrorEnvelope(toolResult: any): { code?: string; message?: string; remediation?: string | null; retryable?: boolean } | null {
  if (!toolResult || typeof toolResult !== 'object') return null;
  const metaErr = toolResult?.result?._meta?.['dev.culkibo/error'] || toolResult?._meta?.['dev.culkibo/error'];
  if (metaErr && typeof metaErr === 'object') return metaErr;
  if (toolResult?.result?.isError && Array.isArray(toolResult?.result?.content)) {
    const firstText = toolResult.result.content[0]?.text;
    if (typeof firstText === 'string') {
      try {
        const parsed = JSON.parse(firstText);
        if (parsed && typeof parsed === 'object') return parsed;
      } catch {
        // Texto plano sin JSON estructurado
      }
    }
  }
  const fallbackRem = toolResult?.remediation || toolResult?.result?.remediation || toolResult?.error?.data?.remediation;
  if (fallbackRem) {
    return {
      code: toolResult?.error?.code ? String(toolResult.error.code) : undefined,
      remediation: String(fallbackRem),
    };
  }
  return null;
}

function classifyMcpToolGroup(name: string): string {
  const n = name.toLowerCase();
  if (n.includes('ship_and_verify') || n.includes('export_agent_kit') || n.includes('smartpack') || n.includes('edge_tunnel')) return 'MCP 2026 Pioneer (Ship, SmartPack, EdgeTunnel & Kits)';
  if (n.includes('diagnose_incident') || n.includes('auto_remediate') || n.includes('search_tools')) return 'Autocuración y Descubrimiento IA';
  if (n.includes('fleet_')) return 'Flota Multi-Servidor (SSH)';
  if (n.includes('rbac_') || n.includes('team_')) return 'Equipos, RBAC y Tokens';
  if (n.includes('uptime_') || n.includes('status_page')) return 'Uptime y Páginas de Estado';
  if (n.includes('gitops_') || n.includes('_env_')) return 'GitOps y Entornos';
  if (n.includes('sleep_') || n.includes('cost_advisor')) return 'Smart Sleep y Cost Advisor';
  if (n.includes('smoke_') || n.includes('canary_') || n.includes('freeze')) return 'Smoke Tests, Canary y Freeze';
  if (n.includes('sync') || n.includes('forge') || n.includes('merkle')) return 'Live Sync (The Forge)';
  if (n.includes('domain') || n.includes('ssl') || n.includes('tls') || n.includes('caddy') || n.includes('ingress') || n.includes('wildcard') || n.includes('tunnel') || n.includes('cloudflare')) return 'Dominios, TLS y Caddy';
  if (n.includes('database') || n.includes('_db') || n.includes('backup') || n.includes('snapshot') || n.includes('restore') || n.includes('s3')) return 'Bases de datos y Backups';
  if (n.includes('catalog') || n.includes('service') || n.includes('install')) return 'Catálogo de servicios';
  if (n.includes('deploy') || n.includes('rollback') || n.includes('cron') || n.includes('preview') || n.includes('runtime') || n.includes('container') || n.includes('traffic')) return 'Despliegues, Cron y Previews';
  if (n.includes('wordpress') || n.includes('coolify') || n.includes('compose') || n.includes('import')) return 'Migradores e Importadores';
  if (n.includes('project') || n.includes('env') || n.includes('webhook')) return 'Proyectos y Variables';
  return 'Sistema, Métricas y Auditoría';
}

function buildDefaultArgsFromSchema(spec: any): Record<string, unknown> {
  const props = spec?.inputSchema?.properties || {};
  const required = new Set<string>(spec?.inputSchema?.required || []);
  const out: Record<string, unknown> = {};
  for (const [key, def] of Object.entries<any>(props)) {
    if (!required.has(key) && key !== 'action' && key !== 'limit') continue;
    if (def?.default !== undefined) {
      out[key] = def.default;
    } else if (Array.isArray(def?.enum) && def.enum.length > 0) {
      out[key] = def.enum[0];
    } else if (def?.type === 'number' || def?.type === 'integer') {
      out[key] = key === 'limit' ? 20 : 1;
    } else if (def?.type === 'boolean') {
      out[key] = false;
    } else if (def?.type === 'array') {
      out[key] = [];
    } else if (def?.type === 'object') {
      out[key] = {};
    } else {
      out[key] = key.toLowerCase().includes('url') ? 'https://tuweb.com' : '';
    }
  }
  return out;
}

async function callMcpModernRpc(method: string, params: Record<string, unknown> = {}, mcpName?: string): Promise<any> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    'MCP-Protocol-Version': '2026-07-28',
    'Mcp-Method': method,
  };
  if (mcpName) headers['Mcp-Name'] = mcpName;
  const res = await apiFetch('/api/mcp', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: `ui_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
      method,
      params: {
        ...params,
        _meta: {
          'io.modelcontextprotocol/protocolVersion': '2026-07-28',
          'io.modelcontextprotocol/clientCapabilities': {},
          'io.modelcontextprotocol/clientInfo': { name: 'culkibo-web-dashboard', version: '1.1.0' },
        },
      },
    }),
  });
  return res.json();
}

export const AiAgentHub: React.FC<{ onNotify?: (msg: string, type?: 'info' | 'success' | 'error') => void }> = ({ onNotify }) => {
  const [tools, setTools] = useState<any[]>([]);
  const [prompts, setPrompts] = useState<McpPromptSpec[]>([...FALLBACK_PLAYBOOKS]);
  const [mcpApps, setMcpApps] = useState<McpAppResourceSpec[]>([...FALLBACK_MCP_APPS]);
  const [activeAppUri, setActiveAppUri] = useState<string | null>(null);
  const [activeAppHtml, setActiveAppHtml] = useState<string>('');
  const [loadingApp, setLoadingApp] = useState(false);
  const [showAllPrompts, setShowAllPrompts] = useState(false);
  const [activePlaybook, setActivePlaybook] = useState<McpPromptSpec | null>(null);
  const [playbookArgs, setPlaybookArgs] = useState<Record<string, string>>({});
  const [playbookPreviewText, setPlaybookPreviewText] = useState<string>('');
  const [loadingPlaybook, setLoadingPlaybook] = useState(false);

  const [auditLog, setAuditLog] = useState<McpAuditEntry[]>([]);
  const [mcpConfig, setMcpConfig] = useState<any>(null);
  const [remoteInfo, setRemoteInfo] = useState<RemoteAccessInfo | null>(null);
  const [connectionScope, setConnectionScope] = useState<'local' | 'remote'>('local');
  const [selectedProfile, setSelectedProfile] = useState<McpProfile>('core');
  const [selectedAgent, setSelectedAgent] = useState<AgentCardId>('antigravity');
  const [claudeSubTab, setClaudeSubTab] = useState<ClaudeSubTab>('mcp-json');

  const [toolSearch, setToolSearch] = useState('');
  const [selectedTool, setSelectedTool] = useState<string>('culkibo_ship_and_verify');
  const [toolArgs, setToolArgs] = useState<string>('{\n  "projectId": "",\n  "dryRun": true\n}');
  const [dryRunMode, setDryRunMode] = useState<boolean>(true);
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [toolResult, setToolResult] = useState<any>(null);
  const [executing, setExecuting] = useState(false);
  const [confirmDestructive, setConfirmDestructive] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const loadMcpData = async () => {
    try {
      const [toolsRes, auditRes, cfgRes, remRes, promptsRes, resourcesRes] = await Promise.all([
        api.getMcpTools(),
        api.getMcpAudit(),
        api.getMcpConfig(),
        api.getRemoteAccess().catch(() => null),
        callMcpModernRpc('prompts/list').catch(() => null),
        callMcpModernRpc('resources/list').catch(() => null),
      ]);
      setTools(toolsRes.tools || []);
      setAuditLog(auditRes.auditLog || []);
      setMcpConfig(cfgRes);
      setRemoteInfo(remRes);
      const livePrompts = promptsRes?.result?.prompts;
      if (Array.isArray(livePrompts) && livePrompts.length > 0) {
        setPrompts(livePrompts);
      }
      const liveResources = resourcesRes?.result?.resources;
      if (Array.isArray(liveResources)) {
        const uiApps = liveResources.filter((r: any) => typeof r?.uri === 'string' && r.uri.startsWith('ui://culkibo/'));
        if (uiApps.length > 0) setMcpApps(uiApps);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    let active = true;
    Promise.all([
      api.getMcpTools(),
      api.getMcpAudit(),
      api.getMcpConfig(),
      api.getRemoteAccess().catch(() => null),
      callMcpModernRpc('prompts/list').catch(() => null),
      callMcpModernRpc('resources/list').catch(() => null),
    ])
      .then(([toolsRes, auditRes, cfgRes, remRes, promptsRes, resourcesRes]) => {
        if (!active) return;
        setTools(toolsRes.tools || []);
        setAuditLog(auditRes.auditLog || []);
        setMcpConfig(cfgRes);
        setRemoteInfo(remRes);
        const livePrompts = promptsRes?.result?.prompts;
        if (Array.isArray(livePrompts) && livePrompts.length > 0) {
          setPrompts(livePrompts);
        }
        const liveResources = resourcesRes?.result?.resources;
        if (Array.isArray(liveResources)) {
          const uiApps = liveResources.filter((r: any) => typeof r?.uri === 'string' && r.uri.startsWith('ui://culkibo/'));
          if (uiApps.length > 0) setMcpApps(uiApps);
        }
      })
      .catch((e) => console.error(e));

    const offMcp = liveEvents.onMcpCall((entry) => {
      setAuditLog((prev) => [entry, ...prev].slice(0, 60));
    });
    return () => {
      active = false;
      offMcp();
    };
  }, []);

  const handleToggleMcpAppPreview = async (uri: string) => {
    if (activeAppUri === uri) {
      setActiveAppUri(null);
      setActiveAppHtml('');
      return;
    }
    setActiveAppUri(uri);
    setActiveAppHtml('');
    setLoadingApp(true);
    try {
      const res = await callMcpModernRpc('resources/read', { uri }, uri);
      const html = res?.result?.contents?.[0]?.text;
      if (typeof html === 'string' && html.trim()) {
        setActiveAppHtml(html);
      } else {
        setActiveAppHtml('<!DOCTYPE html><html><body style="font-family:system-ui;padding:16px;color:#475569">No se pudo cargar el recurso MCP App desde POST /api/mcp.</body></html>');
      }
    } catch {
      setActiveAppHtml('<!DOCTYPE html><html><body style="font-family:system-ui;padding:16px;color:#b91c1c">Error leyendo el recurso MCP App.</body></html>');
    } finally {
      setLoadingApp(false);
    }
  };

  const filteredTools = useMemo(() => {
    const q = toolSearch.trim().toLowerCase();
    if (!q) return tools;
    return tools.filter((t) =>
      String(t.name || '').toLowerCase().includes(q) ||
      String(t.description || '').toLowerCase().includes(q)
    );
  }, [tools, toolSearch]);

  const effectiveToolName = useMemo(() => {
    if (filteredTools.some((t) => t.name === selectedTool)) return selectedTool;
    return filteredTools[0]?.name || selectedTool;
  }, [filteredTools, selectedTool]);

  const currentToolSpec = useMemo(
    () => tools.find((t) => t.name === effectiveToolName) || null,
    [tools, effectiveToolName]
  );

  const groupedTools = useMemo(() => {
    const map = new Map<string, any[]>();
    for (const t of filteredTools) {
      const g = classifyMcpToolGroup(String(t.name || ''));
      if (!map.has(g)) map.set(g, []);
      map.get(g)!.push(t);
    }
    return Array.from(map.entries());
  }, [filteredTools]);

  const handleSelectTool = (toolName: string) => {
    setSelectedTool(toolName);
    setConfirmDestructive(false);
    setJsonError(null);
    const spec = tools.find((t) => t.name === toolName);
    const defaults = buildDefaultArgsFromSchema(spec);
    const canDryRun = Boolean(spec?.inputSchema?.properties?.dryRun);
    const defaultDry = canDryRun && Boolean(
      spec?.annotations?.destructiveHint ||
      toolName === 'culkibo_auto_remediate' ||
      toolName === 'culkibo_ship_and_verify'
    );
    setDryRunMode(defaultDry);
    if (defaultDry) {
      defaults.dryRun = true;
    }
    setToolArgs(Object.keys(defaults).length > 0 ? JSON.stringify(defaults, null, 2) : '{}');
  };

  const isDestructive = Boolean(currentToolSpec?.annotations?.destructiveHint);
  const isReadOnly = Boolean(currentToolSpec?.annotations?.readOnlyHint);
  const supportsDryRun = Boolean(currentToolSpec?.inputSchema?.properties?.dryRun);

  const handleToggleDryRun = (enabled: boolean) => {
    setDryRunMode(enabled);
    setConfirmDestructive(false);
    try {
      const parsed = JSON.parse(toolArgs || '{}');
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        if (enabled) parsed.dryRun = true;
        else delete parsed.dryRun;
        setToolArgs(JSON.stringify(parsed, null, 2));
        setJsonError(null);
      }
    } catch {
      // JSON en edición
    }
  };

  const handleExecuteTool = async () => {
    setJsonError(null);
    let parsedArgs: Record<string, unknown> = {};
    try {
      parsedArgs = JSON.parse(toolArgs || '{}');
    } catch (err: any) {
      setJsonError(`JSON inválido: ${err.message}`);
      return;
    }
    if (supportsDryRun && dryRunMode) {
      parsedArgs = { ...parsedArgs, dryRun: true };
    }
    const effectiveDryRun = Boolean(supportsDryRun && parsedArgs.dryRun === true);

    if (isDestructive && !effectiveDryRun && !confirmDestructive) {
      setConfirmDestructive(true);
      return;
    }
    setConfirmDestructive(false);

    setExecuting(true);
    setToolResult(null);
    try {
      const res = await api.callMcpModern(effectiveToolName, parsedArgs);
      setToolResult(res);
    } catch (err: any) {
      setToolResult({ error: err?.message || 'Error ejecutando la herramienta' });
    } finally {
      setExecuting(false);
    }
  };

  const handleLoadConfirmToken = (token: string) => {
    setDryRunMode(false);
    setConfirmDestructive(false);
    try {
      const parsed = JSON.parse(toolArgs || '{}');
      const next = { ...(parsed && typeof parsed === 'object' ? parsed : {}), dryRun: false, confirmToken: token };
      setToolArgs(JSON.stringify(next, null, 2));
      setJsonError(null);
    } catch {
      setToolArgs(JSON.stringify({ dryRun: false, confirmToken: token }, null, 2));
    }
  };

  const copyText = async (text: string, key: string, label = 'Configuración copiada al portapapeles') => {
    if (!text) return;
    const ok = await copyToClipboard(text);
    if (!ok) {
      onNotify?.('No se pudo copiar al portapapeles', 'error');
      return;
    }
    setCopiedKey(key);
    window.setTimeout(() => setCopiedKey(null), 2000);
    onNotify?.(label, 'success');
  };

  const fetchPlaybookText = async (prompt: McpPromptSpec, argValues: Record<string, string> = {}): Promise<string> => {
    const cleanArgs: Record<string, string> = {};
    for (const [k, v] of Object.entries(argValues)) {
      if (v.trim()) cleanArgs[k] = v.trim();
    }
    try {
      const res = await callMcpModernRpc('prompts/get', { name: prompt.name, arguments: cleanArgs }, prompt.name);
      const txt = res?.result?.messages?.[0]?.content?.text;
      if (typeof txt === 'string' && txt.trim()) return txt;
    } catch {
      // Fallback descriptivo si el servidor aún no soporta el playbook
    }
    return `Ejecuta el playbook MCP "${prompt.name}" en Culkibo: ${prompt.description}`;
  };

  const handleOpenPlaybook = async (prompt: McpPromptSpec) => {
    setActivePlaybook(prompt);
    const initialArgs: Record<string, string> = {};
    for (const a of prompt.arguments || []) initialArgs[a.name] = '';
    setPlaybookArgs(initialArgs);
    setLoadingPlaybook(true);
    try {
      const txt = await fetchPlaybookText(prompt, initialArgs);
      setPlaybookPreviewText(txt);
    } finally {
      setLoadingPlaybook(false);
    }
  };

  const handleRefreshPlaybookPreview = async () => {
    if (!activePlaybook) return;
    setLoadingPlaybook(true);
    try {
      const txt = await fetchPlaybookText(activePlaybook, playbookArgs);
      setPlaybookPreviewText(txt);
    } finally {
      setLoadingPlaybook(false);
    }
  };

  const handleCopyPlaybook = async (prompt: McpPromptSpec, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    const argsToUse = activePlaybook?.name === prompt.name ? playbookArgs : {};
    const txt = activePlaybook?.name === prompt.name && playbookPreviewText
      ? playbookPreviewText
      : await fetchPlaybookText(prompt, argsToUse);
    await copyText(txt, `playbook_${prompt.name}`, `Playbook "${prompt.name}" copiado al portapapeles`);
  };

  const baseConfigs = connectionScope === 'remote' && remoteInfo?.clientConfigs
    ? remoteInfo.clientConfigs
    : mcpConfig;

  const profileStats = useMemo(() => {
    const allBytes = tools.length > 0 ? JSON.stringify({ tools }).length : 0;
    const subset = selectedProfile === 'all'
      ? tools
      : tools.filter((t) => PROFILE_TOOL_SETS[selectedProfile].has(String(t.name || '')));
    const subBytes = subset.length > 0 ? JSON.stringify({ tools: subset }).length : 0;
    const estTokens = Math.round(subBytes / 4);
    const fullTokens = Math.round(allBytes / 4);
    const savedPct = allBytes > 0 ? Math.max(0, Math.round((1 - subBytes / allBytes) * 100)) : 82;
    const usedPct = allBytes > 0 ? Math.min(100, Math.max(4, Math.round((subBytes / allBytes) * 100))) : 18;
    return { count: subset.length, total: tools.length, estTokens, fullTokens, savedPct, usedPct };
  }, [tools, selectedProfile]);

  const baseOrigin = useMemo(
    () => resolveBaseOrigin(baseConfigs, connectionScope, remoteInfo),
    [baseConfigs, connectionScope, remoteInfo]
  );

  const snippets = useMemo(
    () => buildAgentSnippets(baseOrigin, selectedProfile, profileStats, baseConfigs),
    [baseOrigin, selectedProfile, profileStats, baseConfigs]
  );

  const primaryAgentCards: ReadonlyArray<{
    id: AgentCardId;
    name: string;
    badge: string;
    file: string;
    copyPayload: string;
    cliInitTarget: string;
  }> = [
    {
      id: 'antigravity',
      name: 'Antigravity',
      badge: 'HTTP 2026',
      file: '.antigravity/mcp.json',
      copyPayload: snippets.antigravity,
      cliInitTarget: 'antigravity',
    },
    {
      id: 'claude-code',
      name: 'Claude Code',
      badge: '.mcp + CLAUDE.md',
      file: '.mcp.json',
      copyPayload: snippets.claudeCodeJson,
      cliInitTarget: 'claude-code',
    },
    {
      id: 'cursor',
      name: 'Cursor',
      badge: 'HTTP 2026',
      file: '.cursor/mcp.json',
      copyPayload: snippets.cursor,
      cliInitTarget: 'cursor',
    },
    {
      id: 'windsurf',
      name: 'Windsurf',
      badge: 'Cascade',
      file: '.windsurf/mcp_config.json',
      copyPayload: snippets.windsurf,
      cliInitTarget: 'windsurf',
    },
    {
      id: 'codex',
      name: 'Codex CLI',
      badge: 'TOML + CLI',
      file: '.codex/config.toml',
      copyPayload: snippets.codexToml,
      cliInitTarget: 'codex',
    },
  ];

  const activeAgentDetail = useMemo(() => {
    if (selectedAgent === 'antigravity') {
      return {
        title: 'Antigravity (.antigravity/mcp.json)',
        subtitle: `Pega en .antigravity/mcp.json o ~/.gemini/antigravity/mcp_config.json (perfil ${selectedProfile}, cero secretos en claro):`,
        code: snippets.antigravity,
        cliInit: `culkibo agent-init antigravity --profile ${selectedProfile} --url "${baseOrigin}"`,
      };
    }
    if (selectedAgent === 'claude-code') {
      const code = claudeSubTab === 'mcp-json'
        ? snippets.claudeCodeJson
        : claudeSubTab === 'claude-md'
          ? snippets.claudeMd
          : snippets.claudeCodeCli;
      const subtitle = claudeSubTab === 'mcp-json'
        ? 'Coloca .mcp.json en la raíz de tu repo (compartible en Git gracias a ${CULKIBO_TOKEN}):'
        : claudeSubTab === 'claude-md'
          ? 'Añade este bloque a CLAUDE.md para que Claude Code domine Ship & Verify y los 8 playbooks:'
          : 'Registra Culkibo desde terminal con un único comando:';
      return {
        title: claudeSubTab === 'mcp-json' ? 'Claude Code (.mcp.json)' : claudeSubTab === 'claude-md' ? 'Claude Code (CLAUDE.md ops)' : 'Claude Code CLI',
        subtitle,
        code,
        cliInit: `culkibo agent-init claude-code --profile ${selectedProfile} --url "${baseOrigin}"`,
      };
    }
    if (selectedAgent === 'cursor') {
      return {
        title: 'Cursor (.cursor/mcp.json)',
        subtitle: `Pega en .cursor/mcp.json o ~/.cursor/mcp.json (Streamable HTTP 2026 · perfil ${selectedProfile}):`,
        code: snippets.cursor,
        cliInit: `culkibo agent-init cursor --profile ${selectedProfile} --url "${baseOrigin}"`,
      };
    }
    if (selectedAgent === 'windsurf') {
      return {
        title: 'Windsurf (.windsurf/mcp_config.json)',
        subtitle: `Compatible con Windsurf Cascade (serverUrl Streamable HTTP · perfil ${selectedProfile}):`,
        code: snippets.windsurf,
        cliInit: `culkibo agent-init windsurf --profile ${selectedProfile} --url "${baseOrigin}"`,
      };
    }
    if (selectedAgent === 'codex') {
      return {
        title: 'OpenAI Codex CLI (.codex/config.toml)',
        subtitle: `Añade a ~/.codex/config.toml o ejecuta: ${snippets.codexCliCmd}`,
        code: snippets.codexToml,
        cliInit: `culkibo agent-init codex --profile ${selectedProfile} --url "${baseOrigin}"`,
      };
    }
    if (selectedAgent === 'vscode') {
      return {
        title: 'VS Code / GitHub Copilot (.vscode/mcp.json)',
        subtitle: 'Crea o edita .vscode/mcp.json en tu workspace:',
        code: snippets.vscode,
        cliInit: `culkibo agent-init vscode --profile ${selectedProfile} --url "${baseOrigin}"`,
      };
    }
    return {
      title: 'Claude Desktop (puente stdio con CULKIBO_MCP_PROFILE)',
      subtitle: 'Usa el puente stdio oficial de Culkibo con filtrado de perfil en cliente/servidor:',
      code: snippets.claudeDesktop,
      cliInit: `CULKIBO_MCP_PROFILE=${selectedProfile} CULKIBO_API_URL="${baseOrigin}" culkibo mcp`,
    };
  }, [selectedAgent, claudeSubTab, selectedProfile, snippets, baseOrigin]);

  const displayedPlaybooks = useMemo(() => {
    if (showAllPrompts) return prompts;
    const coreOnly = prompts.filter((p) => Boolean(CORE_PLAYBOOK_META[p.name]));
    return coreOnly.length >= 8 ? coreOnly : prompts.slice(0, 8);
  }, [prompts, showAllPrompts]);

  const schemaProps = currentToolSpec?.inputSchema?.properties
    ? Object.entries(currentToolSpec.inputSchema.properties)
    : [];
  const requiredProps = new Set<string>(currentToolSpec?.inputSchema?.required || []);

  return (
    <div className="space-y-5">
      {/* Cabecera fuera de tarjeta */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5 flex-wrap">
            <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">Agentes de IA (MCP)</h1>
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              MCP {mcpConfig?.protocol?.current || '2026-07-28'}
            </span>
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-indigo-50 text-indigo-700 border border-indigo-200 tabular-nums">
              <Sparkles className="w-3 h-3" />
              3 MCP Apps · 8 playbooks
            </span>
            <HelpTip title="Model Context Protocol (MCP 2026 + MCP Apps)">
              <p>Conecta Antigravity, Claude Code, Cursor, Windsurf o Codex CLI en 1 clic con perfiles de contexto (?profile=core ahorra &gt;81% de tokens) y cero secretos en claro.</p>
              <p>Incluye {tools.length || 111} herramientas anotadas, 3 MCP Apps interactivas (ui://culkibo/*), Ship &amp; Verify autónomo con confirmToken, 7 recursos JSON en vivo y {prompts.length} playbooks.</p>
            </HelpTip>
          </div>
          <p className="text-sm text-slate-500 mt-1">
            PaaS nativo para IA: conecta tu agente en 1 clic, previsualiza MCP Apps interactivas (ext-apps 2026-01-26) y ejecuta despliegues verificados.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <span className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-white text-slate-700 border border-slate-200 tabular-nums">
            {tools.length || 111} herramientas · {mcpApps.length} apps · {prompts.length} prompts
          </span>
          <button
            type="button"
            aria-label="Actualizar herramientas, playbooks y auditoría"
            onClick={() => void loadMcpData()}
            className="p-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-600 cursor-pointer"
            title="Actualizar"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* 1. Conecta tu agente de IA (1-Click Cards + Live ?profile= + Token-Savings Meter) */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <Zap className="w-4 h-4 text-emerald-600" />
              1. Conecta tu agente de IA en 1 clic
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Todas las configuraciones usan <code className="font-mono text-slate-700">{'${CULKIBO_TOKEN}'}</code> y nunca incrustan tokens maestros en claro.
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <span className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-medium bg-slate-50 text-slate-600 border border-slate-200">
              <KeyRound className="w-3 h-3 text-emerald-600" />
              Zero plaintext tokens
            </span>
            <div className="flex items-center bg-slate-100 p-0.5 rounded-lg border border-slate-200 text-[11px]">
              <button
                type="button"
                onClick={() => setConnectionScope('local')}
                className={`px-2.5 py-1 rounded-md font-medium cursor-pointer ${connectionScope === 'local' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600'}`}
              >
                Local
              </button>
              <button
                type="button"
                onClick={() => setConnectionScope('remote')}
                className={`px-2.5 py-1 rounded-md font-medium cursor-pointer ${connectionScope === 'remote' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600'}`}
              >
                Remoto (VPS)
              </button>
            </div>
          </div>
        </div>

        {/* Live ?profile= switcher + visual token-savings meter */}
        <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
              <span className="text-slate-600 font-medium mr-1">Perfil <code className="font-mono">?profile=</code></span>
              {PROFILE_OPTIONS.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  title={p.hint}
                  onClick={() => setSelectedProfile(p.id)}
                  className={`px-2.5 py-1 rounded-md font-medium border cursor-pointer transition-colors ${
                    selectedProfile === p.id
                      ? 'bg-emerald-600 text-white border-emerald-600'
                      : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-100'
                  }`}
                >
                  {p.id === 'all' ? `${p.label} (${tools.length || 111})` : p.label}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-2 text-[11px] tabular-nums">
              <span className="text-slate-600 font-medium">
                {profileStats.count}/{profileStats.total || 111} tools · ~{(profileStats.estTokens / 1000).toFixed(1)}k tok
              </span>
              {profileStats.savedPct > 0 ? (
                <span className="px-2 py-0.5 rounded-full font-semibold bg-emerald-100 text-emerald-800 border border-emerald-200">
                  -{profileStats.savedPct}% contexto ahorrado
                </span>
              ) : (
                <span className="px-2 py-0.5 rounded-full font-medium bg-amber-50 text-amber-800 border border-amber-200">
                  Catálogo completo
                </span>
              )}
            </div>
          </div>

          <div className="space-y-1">
            <div className="w-full h-2 rounded-full bg-slate-200 overflow-hidden flex">
              <div
                className={`h-full transition-[width] duration-300 ${selectedProfile === 'all' ? 'bg-amber-500' : 'bg-emerald-600'}`}
                style={{ width: `${profileStats.usedPct}%` }}
              />
            </div>
            <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono">
              <span>{snippets.endpoint}</span>
              <span className="tabular-nums">
                {profileStats.fullTokens > 0
                  ? `${(profileStats.estTokens / 1000).toFixed(1)}k / ${(profileStats.fullTokens / 1000).toFixed(1)}k tok estimados`
                  : 'Listo con culkibo_search_tools bajo demanda'}
              </span>
            </div>
          </div>
        </div>

        {/* 5 Crisp 1-Click Agent Cards: Antigravity, Claude Code, Cursor, Windsurf, Codex CLI */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {primaryAgentCards.map((card) => {
            const isSelected = selectedAgent === card.id;
            const copyId = `card_${card.id}`;
            return (
              <div
                key={card.id}
                role="button"
                tabIndex={0}
                onClick={() => setSelectedAgent(card.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    setSelectedAgent(card.id);
                  }
                }}
                className={`p-3.5 rounded-xl border text-left transition-colors cursor-pointer flex flex-col justify-between gap-3 ${
                  isSelected
                    ? 'bg-slate-900 text-white border-slate-900 shadow-xs'
                    : 'bg-white text-slate-900 border-slate-200 hover:border-slate-300 hover:bg-slate-50/70'
                }`}
              >
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-1.5">
                    <span className="text-xs font-semibold tracking-tight">{card.name}</span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                        isSelected
                          ? 'bg-white/15 text-emerald-300'
                          : 'bg-slate-100 text-slate-600'
                      }`}
                    >
                      {card.badge}
                    </span>
                  </div>
                  <div className={`text-[11px] font-mono truncate ${isSelected ? 'text-slate-300' : 'text-slate-500'}`}>
                    {card.file}
                  </div>
                </div>

                <div className="flex items-center justify-between gap-2 pt-1">
                  <span className={`text-[10px] inline-flex items-center gap-0.5 ${isSelected ? 'text-slate-300' : 'text-slate-500'}`}>
                    Ver config <ChevronRight className="w-3 h-3" />
                  </span>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedAgent(card.id);
                      void copyText(card.copyPayload, copyId, `Config de ${card.name} (${selectedProfile}) copiada`);
                    }}
                    className={`inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-medium cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-emerald-500 hover:bg-emerald-400 text-slate-950'
                        : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
                    }`}
                  >
                    {copiedKey === copyId ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === copyId ? 'Copiado' : '1-clic'}</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>

        {/* Secondary editor tabs + Drop-in Config Inspector + CLI agent-init bar */}
        <div className="space-y-3 pt-1">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-semibold text-slate-800 flex items-center gap-1.5">
                <FileCode2 className="w-3.5 h-3.5 text-slate-500" />
                {activeAgentDetail.title}
              </span>
              {selectedAgent === 'claude-code' && (
                <div className="flex items-center bg-slate-100 p-0.5 rounded-md border border-slate-200 text-[11px]">
                  {([
                    { id: 'mcp-json', label: '.mcp.json' },
                    { id: 'claude-md', label: 'CLAUDE.md' },
                    { id: 'cli', label: 'CLI add' },
                  ] as const).map((sub) => (
                    <button
                      key={sub.id}
                      type="button"
                      onClick={() => setClaudeSubTab(sub.id)}
                      className={`px-2 py-0.5 rounded font-medium cursor-pointer ${
                        claudeSubTab === sub.id ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600'
                      }`}
                    >
                      {sub.label}
                    </button>
                  ))}
                </div>
              )}
            </div>

            <div className="flex items-center gap-1.5 text-[11px]">
              <button
                type="button"
                onClick={() => setSelectedAgent('vscode')}
                className={`px-2 py-1 rounded-md border cursor-pointer ${
                  selectedAgent === 'vscode' ? 'bg-slate-900 text-white border-slate-900' : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                }`}
              >
                VS Code Copilot
              </button>
              <button
                type="button"
                onClick={() => setSelectedAgent('claude-desktop')}
                className={`px-2 py-1 rounded-md border cursor-pointer ${
                  selectedAgent === 'claude-desktop' ? 'bg-slate-900 text-white border-slate-900' : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                }`}
              >
                Claude Desktop (stdio)
              </button>
              <button
                type="button"
                onClick={() => void copyText(activeAgentDetail.code, `detail_${selectedAgent}_${claudeSubTab}`)}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-100 hover:bg-slate-200 text-xs font-medium text-slate-700 border border-slate-200 cursor-pointer"
              >
                {copiedKey === `detail_${selectedAgent}_${claudeSubTab}` ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedKey === `detail_${selectedAgent}_${claudeSubTab}` ? 'Copiado' : 'Copiar'}</span>
              </button>
            </div>
          </div>

          <p className="text-xs text-slate-500">{activeAgentDetail.subtitle}</p>
          <pre className="p-3.5 bg-slate-50 border border-slate-200 text-slate-800 rounded-xl text-xs font-mono overflow-x-auto leading-relaxed">
            {activeAgentDetail.code}
          </pre>

          <div className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-slate-900 text-slate-100 text-xs font-mono">
            <div className="truncate">
              <span className="text-emerald-400 select-none">$ </span>
              <span>{activeAgentDetail.cliInit}</span>
            </div>
            <button
              type="button"
              onClick={() => void copyText(activeAgentDetail.cliInit, `cli_init_${selectedAgent}`, 'Comando culkibo agent-init copiado')}
              className="inline-flex items-center gap-1 px-2 py-1 rounded bg-white/10 hover:bg-white/20 text-[11px] font-sans text-white shrink-0 cursor-pointer"
            >
              {copiedKey === `cli_init_${selectedAgent}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedKey === `cli_init_${selectedAgent}` ? 'Copiado' : 'Copiar CLI'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* 2. Galería de Interactive MCP Apps (ui://culkibo/* — ext-apps 2026-01-26) */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2 flex-wrap">
              <Layers className="w-4 h-4 text-emerald-600" />
              <span>2. Interactive MCP Apps (<code className="font-mono text-xs text-slate-600">ui://culkibo/*</code>)</span>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                ext-apps 2026-01-26
              </span>
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Tarjetas interactivas HTML (<code className="font-mono text-slate-700">text/html;profile=mcp-app</code>) con CSP estricta (<code className="font-mono text-slate-700">default-src &apos;none&apos;</code>) y 0 peticiones externas que Claude, Antigravity y Cursor renderizan inline.
            </p>
          </div>
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-medium bg-slate-50 text-slate-600 border border-slate-200 shrink-0">
            <Shield className="w-3.5 h-3.5 text-emerald-600" />
            Sandboxed iframe · 0 external URLs
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {mcpApps.map((app) => {
            const isOpen = activeAppUri === app.uri;
            const copyId = `app_uri_${app.uri}`;
            return (
              <div
                key={app.uri}
                className={`p-4 rounded-xl border transition-colors flex flex-col justify-between gap-3 ${
                  isOpen
                    ? 'border-emerald-500 bg-emerald-50/30 ring-1 ring-emerald-500/20'
                    : 'border-slate-200 bg-white hover:border-slate-300'
                }`}
              >
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <code className="px-2 py-0.5 rounded bg-slate-900 text-emerald-300 font-mono text-[10px] truncate">
                      {app.uri}
                    </code>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-slate-100 text-slate-600 shrink-0">
                      CSP strict
                    </span>
                  </div>
                  <h3 className="text-xs font-semibold text-slate-900 leading-snug">
                    {app.title || app.name}
                  </h3>
                  <p className="text-[11px] text-slate-600 leading-relaxed">
                    {app.description}
                  </p>
                </div>

                <div className="flex items-center justify-between gap-2 pt-2 border-t border-slate-100">
                  <button
                    type="button"
                    onClick={() => void handleToggleMcpAppPreview(app.uri)}
                    className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium cursor-pointer transition-colors ${
                      isOpen
                        ? 'bg-emerald-600 hover:bg-emerald-700 text-white'
                        : 'bg-slate-900 hover:bg-slate-800 text-white'
                    }`}
                  >
                    <Eye className="w-3 h-3" />
                    <span>{isOpen ? 'Ocultar preview' : 'Previsualizar App'}</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => void copyText(app.uri, copyId, `URI ${app.uri} copiada`)}
                    className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-medium bg-slate-100 hover:bg-slate-200 text-slate-700 cursor-pointer"
                  >
                    {copiedKey === copyId ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === copyId ? 'Copiado' : 'Copiar URI'}</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>

        {activeAppUri && (
          <div className="rounded-xl border border-emerald-200 bg-slate-50 overflow-hidden">
            <div className="px-4 py-2.5 bg-slate-900 text-slate-100 flex items-center justify-between gap-2 flex-wrap text-xs">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400" />
                <span className="font-mono">{activeAppUri}</span>
                <span className="text-[10px] text-slate-400">sandbox=&quot;&quot; · text/html;profile=mcp-app</span>
              </div>
              <button
                type="button"
                onClick={() => {
                  setActiveAppUri(null);
                  setActiveAppHtml('');
                }}
                className="px-2 py-0.5 rounded bg-white/10 hover:bg-white/20 text-[11px] text-white cursor-pointer"
              >
                Cerrar
              </button>
            </div>
            {loadingApp ? (
              <div className="py-12 flex items-center justify-center gap-2 text-xs text-slate-500">
                <Loader2 className="w-4 h-4 animate-spin text-emerald-600" />
                <span>Cargando recurso MCP App desde POST /api/mcp (resources/read)…</span>
              </div>
            ) : (
              <iframe
                title={`Culkibo MCP App preview: ${activeAppUri}`}
                sandbox=""
                srcDoc={activeAppHtml}
                className="w-full h-[420px] bg-white border-0 block"
              />
            )}
          </div>
        )}
      </div>

      {/* 3. Galería interactiva de MCP Playbooks (prompts/list) */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <BookOpen className="w-4 h-4 text-indigo-600" />
              3. Playbooks interactivos MCP (<code className="font-mono text-xs text-slate-600">prompts/list</code>)
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              8 flujos de ingeniería probados en batalla listos para invocar desde Claude Code, Antigravity, Cursor o copiar en 1 clic.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setShowAllPrompts((v) => !v)}
              className="px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-50 hover:bg-slate-100 text-slate-700 border border-slate-200 cursor-pointer"
            >
              {showAllPrompts ? 'Ver solo 8 Playbooks Core' : `Ver todos (${prompts.length})`}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
          {displayedPlaybooks.map((prompt) => {
            const meta = CORE_PLAYBOOK_META[prompt.name];
            const isActive = activePlaybook?.name === prompt.name;
            const copyKey = `playbook_${prompt.name}`;
            return (
              <div
                key={prompt.name}
                onClick={() => void handleOpenPlaybook(prompt)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    void handleOpenPlaybook(prompt);
                  }
                }}
                className={`p-3.5 rounded-xl border transition-colors cursor-pointer flex flex-col justify-between gap-3 ${
                  isActive
                    ? 'border-indigo-500 bg-indigo-50/40 ring-1 ring-indigo-500/20'
                    : 'border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50/60'
                }`}
              >
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium border ${meta?.tone || 'bg-slate-100 text-slate-700 border-slate-200'}`}>
                      {meta?.badge || 'Legacy'}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400 truncate">{prompt.name}</span>
                  </div>
                  <h3 className="text-xs font-semibold text-slate-900 leading-snug">
                    {prompt.title || prompt.name}
                  </h3>
                  <p className="text-[11px] text-slate-600 leading-relaxed line-clamp-2">
                    {meta?.steps || prompt.description}
                  </p>
                  {prompt.arguments && prompt.arguments.length > 0 && (
                    <div className="flex flex-wrap gap-1 pt-0.5">
                      {prompt.arguments.map((arg) => (
                        <span
                          key={arg.name}
                          className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 font-mono text-[10px]"
                        >
                          {arg.name}{arg.required ? '*' : ''}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <div className="flex items-center justify-between gap-1.5 pt-1 border-t border-slate-100">
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      void handleOpenPlaybook(prompt);
                    }}
                    className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-medium text-indigo-700 hover:bg-indigo-50 cursor-pointer"
                  >
                    <Eye className="w-3 h-3" />
                    <span>Previsualizar</span>
                  </button>
                  <button
                    type="button"
                    onClick={(e) => void handleCopyPlaybook(prompt, e)}
                    className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-medium bg-slate-100 hover:bg-slate-200 text-slate-700 cursor-pointer"
                  >
                    {copiedKey === copyKey ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === copyKey ? 'Copiado' : 'Copiar'}</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>

        {/* Drawer inline de previsualización en vivo de prompts/get */}
        {activePlaybook && (
          <div className="p-4 rounded-xl bg-slate-50 border border-indigo-200 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2 flex-wrap">
                <Rocket className="w-4 h-4 text-indigo-600" />
                <span className="text-xs font-semibold text-slate-900">{activePlaybook.title || activePlaybook.name}</span>
                <code className="px-1.5 py-0.5 rounded bg-white border border-slate-200 text-[10px] font-mono text-slate-600">
                  prompts/get · {activePlaybook.name}
                </code>
              </div>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => void handleCopyPlaybook(activePlaybook)}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-medium cursor-pointer"
                >
                  {copiedKey === `playbook_${activePlaybook.name}` ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedKey === `playbook_${activePlaybook.name}` ? 'Copiado' : 'Copiar playbook'}</span>
                </button>
                <button
                  type="button"
                  onClick={() => setActivePlaybook(null)}
                  className="px-2 py-1 rounded-lg bg-white hover:bg-slate-100 border border-slate-200 text-xs text-slate-600 cursor-pointer"
                >
                  Cerrar
                </button>
              </div>
            </div>

            {activePlaybook.arguments && activePlaybook.arguments.length > 0 && (
              <div className="flex flex-wrap items-end gap-2">
                {activePlaybook.arguments.map((arg) => (
                  <label key={arg.name} className="flex-1 min-w-[160px] space-y-1">
                    <span className="block text-[11px] font-medium text-slate-700 font-mono">
                      {arg.name}{arg.required ? ' *' : ''}
                    </span>
                    <input
                      type="text"
                      value={playbookArgs[arg.name] || ''}
                      onChange={(e) => setPlaybookArgs((prev) => ({ ...prev, [arg.name]: e.target.value }))}
                      placeholder={arg.description || arg.name}
                      className="w-full px-2.5 py-1.5 rounded-lg bg-white border border-slate-200 text-xs font-mono text-slate-800"
                    />
                  </label>
                ))}
                <button
                  type="button"
                  onClick={() => void handleRefreshPlaybookPreview()}
                  disabled={loadingPlaybook}
                  className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50"
                >
                  {loadingPlaybook ? 'Renderizando…' : 'Aplicar args'}
                </button>
              </div>
            )}

            <pre className="p-3.5 rounded-xl bg-white border border-slate-200 text-xs font-mono text-slate-800 whitespace-pre-wrap leading-relaxed max-h-60 overflow-y-auto">
              {loadingPlaybook ? 'Cargando playbook desde POST /api/mcp (prompts/get)…' : playbookPreviewText}
            </pre>
          </div>
        )}
      </div>

      {/* 4. Probador interactivo + 5. Registro de auditoría */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* 4. Probador interactivo */}
        <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-slate-600" />
              4. Probar herramienta en vivo
            </h2>
            <span className="text-[11px] font-mono text-slate-400">POST /api/mcp</span>
          </div>

          <div className="space-y-3">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={toolSearch}
                onChange={(e) => setToolSearch(e.target.value)}
                placeholder="Filtrar herramientas (ej. ship, agent_kit, doctor, diagnose, domain…)"
                className="w-full pl-8 pr-3 py-2 bg-white border border-slate-200 rounded-lg text-xs"
              />
            </div>

            <select
              aria-label="Seleccionar herramienta MCP"
              value={effectiveToolName}
              onChange={(e) => handleSelectTool(e.target.value)}
              className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs font-mono text-slate-800"
            >
              {groupedTools.map(([groupName, groupItems]) => (
                <optgroup key={groupName} label={`${groupName} (${groupItems.length})`}>
                  {groupItems.map((t) => (
                    <option key={t.name} value={t.name}>
                      {t.name}
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>

            {currentToolSpec && (
              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs space-y-1.5">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <span className="font-mono text-[11px] font-semibold text-slate-800">{currentToolSpec.name}</span>
                  <div className="flex items-center gap-1.5">
                    {isReadOnly && (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
                        Solo lectura
                      </span>
                    )}
                    {isDestructive && (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-red-50 text-red-700 border border-red-200">
                        Acción destructiva
                      </span>
                    )}
                  </div>
                </div>
                <p className="text-slate-700 leading-relaxed">{currentToolSpec.description}</p>
                {schemaProps.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {schemaProps.map(([paramName, schema]: [string, any]) => (
                      <span
                        key={paramName}
                        title={schema?.description || ''}
                        className="px-1.5 py-0.5 rounded bg-white border border-slate-200 font-mono text-[10px] text-slate-600"
                      >
                        {paramName}
                        {requiredProps.has(paramName) ? '*' : ''}
                        {schema?.type ? `: ${schema.type}` : ''}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}

            <div className="space-y-2">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <label className="block text-xs font-medium text-slate-700">Argumentos (JSON)</label>
                {supportsDryRun && (
                  <label className="inline-flex items-center gap-1.5 text-[11px] font-medium text-slate-700 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={dryRunMode}
                      onChange={(e) => handleToggleDryRun(e.target.checked)}
                      className="rounded border-slate-300 text-slate-900 focus:ring-slate-500 cursor-pointer"
                    />
                    <span>Simular sin cambios (`dryRun`)</span>
                  </label>
                )}
              </div>
              <textarea
                value={toolArgs}
                onChange={(e) => {
                  const next = e.target.value;
                  setToolArgs(next);
                  setConfirmDestructive(false);
                  try {
                    const parsed = JSON.parse(next || '{}');
                    if (supportsDryRun && parsed && typeof parsed === 'object') {
                      setDryRunMode(parsed.dryRun === true);
                    }
                  } catch {
                    // JSON parcial mientras escribe
                  }
                }}
                rows={4}
                className="w-full p-3 bg-white border border-slate-200 rounded-lg text-xs font-mono text-slate-800"
              />
            </div>

            {jsonError && (
              <div role="alert" className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-xs text-red-700 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                <span>{jsonError}</span>
              </div>
            )}

            {confirmDestructive && (
              <div role="alert" className="p-3 rounded-lg bg-amber-50 border border-amber-200 text-xs text-amber-900 flex items-center justify-between gap-2">
                <span>Esta herramienta modifica o borra recursos reales. Pulsa de nuevo para confirmar.</span>
                <button
                  type="button"
                  onClick={() => setConfirmDestructive(false)}
                  className="text-slate-600 hover:text-slate-900 underline shrink-0 cursor-pointer"
                >
                  Cancelar
                </button>
              </div>
            )}

            <button
              type="button"
              onClick={() => void handleExecuteTool()}
              disabled={executing || !effectiveToolName}
              className={`w-full py-2 px-4 rounded-lg text-white font-medium text-xs flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 ${
                confirmDestructive
                  ? 'bg-red-600 hover:bg-red-700'
                  : (supportsDryRun && dryRunMode ? 'bg-indigo-600 hover:bg-indigo-700' : 'bg-slate-900 hover:bg-slate-800')
              }`}
            >
              {executing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
              <span>
                {executing
                  ? 'Ejecutando…'
                  : confirmDestructive
                    ? 'Confirmar y ejecutar acción destructiva'
                    : (supportsDryRun && dryRunMode ? 'Previsualizar plan (dryRun)' : 'Ejecutar herramienta')}
              </span>
            </button>

            {toolResult && (() => {
              const errEnv = extractMcpErrorEnvelope(toolResult);
              const remediation = errEnv?.remediation || null;
              const mintedToken = toolResult?.result?.structuredContent?.confirmToken || null;
              return (
                <div className="space-y-2">
                  {remediation && (
                    <div className="p-3 rounded-lg bg-amber-50 border border-amber-200 text-xs text-amber-900 space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <strong>Cómo solucionarlo:</strong>
                        {errEnv?.code && (
                          <span className="px-1.5 py-0.5 rounded bg-amber-100 border border-amber-300 font-mono text-[10px]">
                            {errEnv.code}
                          </span>
                        )}
                        {errEnv?.retryable !== undefined && (
                          <span className="px-1.5 py-0.5 rounded bg-white border border-amber-200 text-[10px]">
                            {errEnv.retryable ? 'Reintentable' : 'No reintentable'}
                          </span>
                        )}
                      </div>
                      <p>{String(remediation)}</p>
                    </div>
                  )}
                  {typeof mintedToken === 'string' && mintedToken.startsWith('ckr_') && (
                    <div className="p-2.5 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-900 flex items-center justify-between gap-2 flex-wrap">
                      <span>Plan validado con token de confirmación de un solo uso (5 min).</span>
                      <button
                        type="button"
                        onClick={() => handleLoadConfirmToken(mintedToken)}
                        className="px-2.5 py-1 rounded-md bg-emerald-700 hover:bg-emerald-800 text-white font-medium text-[11px] cursor-pointer"
                      >
                        Cargar confirmToken (dryRun: false)
                      </button>
                    </div>
                  )}
                  <pre className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono text-slate-800 max-h-56 overflow-y-auto">
                    {JSON.stringify(toolResult, null, 2)}
                  </pre>
                </div>
              );
            })()}
          </div>
        </div>

        {/* 5. Registro de auditoría en tiempo real */}
        <div className="bg-white rounded-xl border border-slate-200 overflow-hidden flex flex-col">
          <div className="px-5 py-3.5 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-2 flex-wrap">
            <div className="flex items-center gap-2">
              <Radio className="w-4 h-4 text-emerald-600" />
              <h2 className="text-xs font-semibold text-slate-900">5. Actividad del agente en directo</h2>
            </div>
            <div className="flex items-center gap-1.5 text-xs text-slate-500 tabular-nums">
              <Shield className="w-3.5 h-3.5 text-slate-400" />
              <span>
                Secretos redactados · {auditLog.length} {auditLog.length === 1 ? 'llamada' : 'llamadas'}
              </span>
            </div>
          </div>

          <div className="overflow-x-auto flex-1">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50/70 text-[11px] font-medium text-slate-500">
                  <th className="py-2.5 px-3">Hora</th>
                  <th className="py-2.5 px-3">Herramienta</th>
                  <th className="py-2.5 px-3">Latencia</th>
                  <th className="py-2.5 px-3">Estado</th>
                  <th className="py-2.5 px-3">Resumen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {auditLog.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-50/70">
                    <td className="py-2.5 px-3 text-slate-500 font-mono tabular-nums whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleTimeString('es-ES')}
                    </td>
                    <td className="py-2.5 px-3 font-mono font-medium text-slate-900 whitespace-nowrap">{log.toolName}</td>
                    <td className="py-2.5 px-3 text-emerald-700 font-mono font-medium tabular-nums whitespace-nowrap">{log.durationMs} ms</td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      {log.success !== false ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
                          <CheckCircle2 className="w-3 h-3" /> OK
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-red-50 text-red-700 border border-red-200">
                          <XCircle className="w-3 h-3" /> Error
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-slate-500 truncate max-w-[180px] font-mono text-[11px]">
                      {log.resultSummary}
                    </td>
                  </tr>
                ))}
                {auditLog.length === 0 && (
                  <tr>
                    <td colSpan={5} className="py-10 text-center text-slate-500">
                      Todavía no hay llamadas registradas. Conecta tu agente arriba o ejecuta una herramienta de prueba.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
