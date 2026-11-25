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
} from 'lucide-react';
import type { McpAuditEntry, RemoteAccessInfo } from '../lib/api';
import { api } from '../lib/api';
import { liveEvents } from '../lib/liveEvents';
import { copyToClipboard } from '../lib/clipboard';
import { HelpTip } from './HelpTip';

type ClientTab = 'cursor' | 'claude' | 'vscode' | 'cli';
type McpProfile = 'core' | 'deploy' | 'ops' | 'security' | 'all';

const PROFILE_OPTIONS: ReadonlyArray<{ id: McpProfile; label: string; hint: string }> = [
  { id: 'core', label: 'Core (Recomendado)', hint: '16 herramientas esenciales + culkibo_search_tools (-82% contexto)' },
  { id: 'deploy', label: 'Deploy & CI/CD', hint: 'Despliegues, Canary, Smoke, Previews, Freeze y Entornos' },
  { id: 'ops', label: 'Ops & Self-Healing', hint: 'Diagnóstico autónomo, remediación, logs, Docker, Uptime y Sleep' },
  { id: 'security', label: 'Security & RBAC', hint: 'Equipos, tokens, TLS/wildcard, Basic Auth, snapshots y Doctor' },
  { id: 'all', label: 'Todas (107)', hint: 'Catálogo completo sin filtrado de perfil' },
];

const PROFILE_TOOL_SETS: Record<Exclude<McpProfile, 'all'>, ReadonlySet<string>> = {
  core: new Set([
    'culkibo_search_tools', 'culkibo_rbac_whoami', 'culkibo_list_projects', 'culkibo_get_project',
    'culkibo_create_project', 'culkibo_set_project_env', 'culkibo_deploy_production', 'culkibo_list_deployments',
    'culkibo_rollback_deployment', 'culkibo_get_container_logs', 'culkibo_get_deployment_logs', 'culkibo_manage_domain',
    'culkibo_list_databases', 'culkibo_system_doctor', 'culkibo_diagnose_incident', 'culkibo_auto_remediate',
  ]),
  deploy: new Set([
    'culkibo_search_tools', 'culkibo_rbac_whoami', 'culkibo_list_projects', 'culkibo_get_project',
    'culkibo_create_project', 'culkibo_add_resource', 'culkibo_set_project_env', 'culkibo_deploy_strategy',
    'culkibo_deploy_production', 'culkibo_list_deployments', 'culkibo_rollback_deployment', 'culkibo_cancel_deployment',
    'culkibo_get_deploy_queue', 'culkibo_get_deployment_logs', 'culkibo_get_container_logs', 'culkibo_manage_previews',
    'culkibo_smoke_test_configure', 'culkibo_smoke_test_run', 'culkibo_canary_rollout', 'culkibo_deploy_freeze',
    'culkibo_env_list', 'culkibo_env_promote',
  ]),
  ops: new Set([
    'culkibo_search_tools', 'culkibo_rbac_whoami', 'culkibo_list_projects', 'culkibo_get_project',
    'culkibo_list_pods', 'culkibo_get_logs', 'culkibo_get_container_logs', 'culkibo_get_observability',
    'culkibo_system_doctor', 'culkibo_system_doctor_fix', 'culkibo_docker_status', 'culkibo_docker_containers',
    'culkibo_manage_production_service', 'culkibo_toggle_maintenance', 'culkibo_diagnose_domain', 'culkibo_ingress_status',
    'culkibo_reconcile_ingress', 'culkibo_uptime_list_monitors', 'culkibo_status_page_manage', 'culkibo_cost_advisor',
    'culkibo_sleep_status', 'culkibo_sleep_manage', 'culkibo_fleet_list_servers', 'culkibo_diagnose_incident',
    'culkibo_auto_remediate',
  ]),
  security: new Set([
    'culkibo_search_tools', 'culkibo_rbac_whoami', 'culkibo_team_list_members', 'culkibo_team_invite_member',
    'culkibo_team_update_member', 'culkibo_rbac_list_tokens', 'culkibo_rbac_manage_token', 'culkibo_system_doctor',
    'culkibo_system_doctor_fix', 'culkibo_diagnose_domain', 'culkibo_ingress_status', 'culkibo_manage_wildcard_dns01',
    'culkibo_set_domain_basic_auth', 'culkibo_manage_webhook', 'culkibo_deploy_freeze', 'culkibo_list_databases',
    'culkibo_database_list_backups', 'culkibo_export_instance_snapshot', 'culkibo_diagnose_incident',
  ]),
};

function appendProfileToUrl(rawUrl: string, profile: McpProfile): string {
  if (!rawUrl || profile === 'all') return rawUrl;
  const cleaned = rawUrl.replace(/([?&])profile=[^&]*(&?)/, (_m, sep, trail) => (trail ? sep : '')).replace(/[?&]$/, '');
  const joiner = cleaned.includes('?') ? '&' : '?';
  return `${cleaned}${joiner}profile=${profile}`;
}

function applyProfileToClientConfig(cfg: any, profile: McpProfile): any {
  if (!cfg || typeof cfg !== 'object') return cfg;
  const clone = JSON.parse(JSON.stringify(cfg));
  if (clone.cursorOrWindsurf?.mcpServers?.culkibo?.url) {
    clone.cursorOrWindsurf.mcpServers.culkibo.url = appendProfileToUrl(clone.cursorOrWindsurf.mcpServers.culkibo.url, profile);
  }
  if (clone.vscodeCopilot?.servers?.culkibo?.url) {
    clone.vscodeCopilot.servers.culkibo.url = appendProfileToUrl(clone.vscodeCopilot.servers.culkibo.url, profile);
  }
  if (typeof clone.claudeCodeCli === 'string') {
    clone.claudeCodeCli = clone.claudeCodeCli.replace(/https?:\/\/[^\s"]+api\/mcp(?:\?profile=[a-z]+)?/i, (u: string) => appendProfileToUrl(u, profile));
  }
  if (clone.claudeDesktop?.mcpServers?.culkibo?.env) {
    if (profile === 'all') delete clone.claudeDesktop.mcpServers.culkibo.env.CULKIBO_MCP_PROFILE;
    else clone.claudeDesktop.mcpServers.culkibo.env.CULKIBO_MCP_PROFILE = profile;
  }
  return clone;
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

export const AiAgentHub: React.FC<{ onNotify?: (msg: string, type?: 'info' | 'success' | 'error') => void }> = ({ onNotify }) => {
  const [tools, setTools] = useState<any[]>([]);
  const [auditLog, setAuditLog] = useState<McpAuditEntry[]>([]);
  const [mcpConfig, setMcpConfig] = useState<any>(null);
  const [remoteInfo, setRemoteInfo] = useState<RemoteAccessInfo | null>(null);
  const [connectionScope, setConnectionScope] = useState<'local' | 'remote'>('local');
  const [selectedProfile, setSelectedProfile] = useState<McpProfile>('core');
  const [clientTab, setClientTab] = useState<ClientTab>('cursor');
  const [toolSearch, setToolSearch] = useState('');
  const [selectedTool, setSelectedTool] = useState<string>('culkibo_list_projects');
  const [toolArgs, setToolArgs] = useState<string>('{}');
  const [dryRunMode, setDryRunMode] = useState<boolean>(false);
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [toolResult, setToolResult] = useState<any>(null);
  const [executing, setExecuting] = useState(false);
  const [confirmDestructive, setConfirmDestructive] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const loadMcpData = async () => {
    try {
      const [toolsRes, auditRes, cfgRes, remRes] = await Promise.all([
        api.getMcpTools(),
        api.getMcpAudit(),
        api.getMcpConfig(),
        api.getRemoteAccess().catch(() => null),
      ]);
      setTools(toolsRes.tools || []);
      setAuditLog(auditRes.auditLog || []);
      setMcpConfig(cfgRes);
      setRemoteInfo(remRes);
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
    ])
      .then(([toolsRes, auditRes, cfgRes, remRes]) => {
        if (!active) return;
        setTools(toolsRes.tools || []);
        setAuditLog(auditRes.auditLog || []);
        setMcpConfig(cfgRes);
        setRemoteInfo(remRes);
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

  const filteredTools = useMemo(() => {
    const q = toolSearch.trim().toLowerCase();
    if (!q) return tools;
    return tools.filter((t) =>
      String(t.name || '').toLowerCase().includes(q) ||
      String(t.description || '').toLowerCase().includes(q)
    );
  }, [tools, toolSearch]);

  // P1-17: si el filtro oculta la herramienta activa, usar la primera visible
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
    const defaultDry = canDryRun && Boolean(spec?.annotations?.destructiveHint || toolName === 'culkibo_auto_remediate');
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
      // Si el JSON estaba a medio editar, el valor se aplicará al ejecutar
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

  const copyText = async (text: string, key: string) => {
    if (!text) return;
    const ok = await copyToClipboard(text);
    if (!ok) {
      onNotify?.('No se pudo copiar al portapapeles', 'error');
      return;
    }
    setCopiedKey(key);
    window.setTimeout(() => setCopiedKey(null), 2000);
    onNotify?.('Configuración copiada al portapapeles', 'success');
  };

  const baseConfigs = connectionScope === 'remote' && remoteInfo?.clientConfigs
    ? remoteInfo.clientConfigs
    : mcpConfig;
  const activeConfigs = useMemo(
    () => applyProfileToClientConfig(baseConfigs, selectedProfile),
    [baseConfigs, selectedProfile]
  );

  const profileStats = useMemo(() => {
    const allBytes = tools.length > 0 ? JSON.stringify({ tools }).length : 0;
    const subset = selectedProfile === 'all'
      ? tools
      : tools.filter((t) => PROFILE_TOOL_SETS[selectedProfile].has(String(t.name || '')));
    const subBytes = subset.length > 0 ? JSON.stringify({ tools: subset }).length : 0;
    const estTokens = Math.round(subBytes / 4);
    const savedPct = allBytes > 0 ? Math.max(0, Math.round((1 - subBytes / allBytes) * 100)) : 0;
    return { count: subset.length, total: tools.length, estTokens, savedPct };
  }, [tools, selectedProfile]);

  const snippetByTab: Record<ClientTab, { title: string; subtitle: string; code: string }> = {
    cursor: {
      title: 'Cursor / Windsurf / Antigravity (Streamable HTTP)',
      subtitle: `Pégalo en la configuración MCP de tu editor (protocolo MCP 2026-07-28 · perfil ${selectedProfile}):`,
      code: activeConfigs ? JSON.stringify(activeConfigs.cursorOrWindsurf || {}, null, 2) : 'Cargando configuración…',
    },
    claude: {
      title: 'Claude Desktop (claude_desktop_config.json)',
      subtitle: connectionScope === 'remote'
        ? 'Usa este bloque con el puente stdio de Culkibo para conectar Claude Desktop a tu servidor remoto:'
        : 'Abre Ajustes → Desarrollador → Editar configuración y pega este bloque:',
      code: activeConfigs ? JSON.stringify(activeConfigs.claudeDesktop || {}, null, 2) : 'Cargando configuración…',
    },
    vscode: {
      title: 'VS Code / GitHub Copilot (.vscode/mcp.json)',
      subtitle: 'Crea o edita .vscode/mcp.json en tu workspace:',
      code: activeConfigs ? JSON.stringify(activeConfigs.vscodeCopilot || {}, null, 2) : 'Cargando configuración…',
    },
    cli: {
      title: 'Claude Code CLI',
      subtitle: 'Ejecútalo en tu terminal para registrar Culkibo:',
      code: activeConfigs?.claudeCodeCli || `claude mcp add --transport http culkibo "${appendProfileToUrl(`${window.location.origin}/api/mcp`, selectedProfile)}"`,
    },
  };

  const currentSnippet = snippetByTab[clientTab];
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
            <HelpTip title="Model Context Protocol (MCP)">
              <p>Permite que Claude, Cursor, Windsurf o VS Code lean estado, desplieguen o diagnostiquen tu servidor sin copiar comandos manualmente.</p>
              <p>Culkibo expone {tools.length} herramientas con anotaciones de seguridad, recursos de solo lectura y prompts guiados.</p>
            </HelpTip>
          </div>
          <p className="text-sm text-slate-500 mt-1">
            Conecta Claude, Cursor, Windsurf, VS Code o Antigravity para operar despliegues, dominios, bases de datos y diagnóstico en directo.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <span className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-white text-slate-700 border border-slate-200 tabular-nums">
            {tools.length} {tools.length === 1 ? 'herramienta' : 'herramientas'}
          </span>
          <button
            type="button"
            aria-label="Actualizar herramientas y auditoría"
            onClick={() => void loadMcpData()}
            className="p-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-600 cursor-pointer"
            title="Actualizar"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* 1. Conexión rápida */}
        <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <Zap className="w-4 h-4 text-slate-600" />
              1. Conecta tu agente
            </h2>
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

          <div className="space-y-2">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <span className="text-[11px] font-medium text-slate-600">Perfil de contexto (`?profile=`)</span>
              {profileStats.total > 0 && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-indigo-50 text-indigo-700 border border-indigo-200 tabular-nums">
                  {profileStats.count}/{profileStats.total} herramientas · ~{(profileStats.estTokens / 1000).toFixed(1)}k tok
                  {profileStats.savedPct > 0 ? ` (-${profileStats.savedPct}%)` : ''}
                </span>
              )}
            </div>
            <div className="flex flex-wrap gap-1.5 text-[11px]">
              {PROFILE_OPTIONS.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  title={p.hint}
                  onClick={() => setSelectedProfile(p.id)}
                  className={`px-2 py-1 rounded-md font-medium border cursor-pointer transition-colors ${
                    selectedProfile === p.id
                      ? 'bg-emerald-600 text-white border-emerald-600'
                      : 'bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100'
                  }`}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          <div className="flex flex-wrap gap-1.5 text-xs">
            {([
              { id: 'cursor', label: 'Cursor / Windsurf' },
              { id: 'claude', label: 'Claude Desktop' },
              { id: 'vscode', label: 'VS Code / Copilot' },
              { id: 'cli', label: 'Claude Code CLI' },
            ] as const).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setClientTab(tab.id)}
                className={`px-2.5 py-1.5 rounded-lg font-medium border cursor-pointer transition-colors ${
                  clientTab === tab.id
                    ? 'bg-slate-900 text-white border-slate-900'
                    : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-medium text-slate-800">{currentSnippet.title}</span>
              <button
                type="button"
                disabled={!activeConfigs}
                onClick={() => void copyText(currentSnippet.code, clientTab)}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-xs font-medium text-slate-700 border border-slate-200 cursor-pointer disabled:opacity-40"
              >
                {copiedKey === clientTab ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedKey === clientTab ? 'Copiado' : 'Copiar'}</span>
              </button>
            </div>
            <p className="text-xs text-slate-500">{currentSnippet.subtitle}</p>
            <pre className="p-3.5 bg-slate-50 border border-slate-200 text-slate-800 rounded-xl text-xs font-mono overflow-x-auto leading-relaxed">
              {currentSnippet.code}
            </pre>
          </div>
        </div>

        {/* 2. Probador interactivo */}
        <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-slate-600" />
              2. Probar herramienta en vivo
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
                placeholder="Filtrar herramientas (ej. doctor, metrics, wordpress, domain…)"
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
                rows={3}
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
                  <pre className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono text-slate-800 max-h-48 overflow-y-auto">
                    {JSON.stringify(toolResult, null, 2)}
                  </pre>
                </div>
              );
            })()}
          </div>
        </div>
      </div>

      {/* 3. Registro de auditoría en tiempo real */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="px-5 py-3.5 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-emerald-600" />
            <h2 className="text-xs font-semibold text-slate-900">Actividad del agente en directo</h2>
          </div>
          <div className="flex items-center gap-1.5 text-xs text-slate-500 tabular-nums">
            <Shield className="w-3.5 h-3.5 text-slate-400" />
            <span>
              Secretos redactados · {auditLog.length} {auditLog.length === 1 ? 'llamada' : 'llamadas'}
            </span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50/70 text-[11px] font-medium text-slate-500">
                <th className="py-2.5 px-4">Hora</th>
                <th className="py-2.5 px-4">Herramienta</th>
                <th className="py-2.5 px-4">Agente</th>
                <th className="py-2.5 px-4">Latencia</th>
                <th className="py-2.5 px-4">Estado</th>
                <th className="py-2.5 px-4">Resumen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {auditLog.map((log) => (
                <tr key={log.id} className="hover:bg-slate-50/70">
                  <td className="py-2.5 px-4 text-slate-500 font-mono tabular-nums whitespace-nowrap">
                    {new Date(log.timestamp).toLocaleTimeString('es-ES')}
                  </td>
                  <td className="py-2.5 px-4 font-mono font-medium text-slate-900 whitespace-nowrap">{log.toolName}</td>
                  <td className="py-2.5 px-4 text-slate-600 whitespace-nowrap">{log.agent || 'MCP'}</td>
                  <td className="py-2.5 px-4 text-emerald-700 font-mono font-medium tabular-nums whitespace-nowrap">{log.durationMs} ms</td>
                  <td className="py-2.5 px-4 whitespace-nowrap">
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
                  <td className="py-2.5 px-4 text-slate-500 truncate max-w-xs font-mono text-[11px]">
                    {log.resultSummary}
                  </td>
                </tr>
              ))}
              {auditLog.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    Todavía no hay llamadas registradas. Conecta tu agente arriba o ejecuta una herramienta de prueba.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
