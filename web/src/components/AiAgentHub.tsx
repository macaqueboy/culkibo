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

type ClientTab = 'cursor' | 'claude' | 'vscode' | 'cli';

export const AiAgentHub: React.FC<{ onNotify?: (msg: string, type?: 'info' | 'success' | 'error') => void }> = ({ onNotify }) => {
  const [tools, setTools] = useState<any[]>([]);
  const [auditLog, setAuditLog] = useState<McpAuditEntry[]>([]);
  const [mcpConfig, setMcpConfig] = useState<any>(null);
  const [remoteInfo, setRemoteInfo] = useState<RemoteAccessInfo | null>(null);
  const [connectionScope, setConnectionScope] = useState<'local' | 'remote'>('local');
  const [clientTab, setClientTab] = useState<ClientTab>('cursor');
  const [toolSearch, setToolSearch] = useState('');
  const [selectedTool, setSelectedTool] = useState<string>('culkibo_list_projects');
  const [toolArgs, setToolArgs] = useState<string>('{}');
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [toolResult, setToolResult] = useState<any>(null);
  const [executing, setExecuting] = useState(false);
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

  const handleSelectTool = (toolName: string) => {
    setSelectedTool(toolName);
    setJsonError(null);
    if (toolName === 'culkibo_analyze_wordpress') {
      setToolArgs(JSON.stringify({ url: 'https://tuweb.com' }, null, 2));
    } else if (toolName === 'culkibo_manage_domain') {
      setToolArgs(JSON.stringify({ action: 'list' }, null, 2));
    } else if (toolName === 'culkibo_get_logs') {
      setToolArgs(JSON.stringify({ limit: 20 }, null, 2));
    } else {
      setToolArgs('{}');
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

  const activeConfigs = connectionScope === 'remote' && remoteInfo?.clientConfigs
    ? remoteInfo.clientConfigs
    : mcpConfig;

  const snippetByTab: Record<ClientTab, { title: string; subtitle: string; code: string }> = {
    cursor: {
      title: 'Cursor / Windsurf / Antigravity (Streamable HTTP)',
      subtitle: 'Pégalo en la configuración MCP de tu editor (protocolo MCP 2026-07-28):',
      code: activeConfigs ? JSON.stringify(activeConfigs.cursorOrWindsurf || {}, null, 2) : 'Cargando configuración…',
    },
    claude: {
      title: 'Claude Desktop (claude_desktop_config.json)',
      subtitle: connectionScope === 'remote'
        ? 'Usa este bloque con mcp-remote para conectar Claude Desktop a tu servidor remoto:'
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
      code: activeConfigs?.claudeCodeCli || `claude mcp add --transport http culkibo ${window.location.origin}/api/mcp`,
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
              {filteredTools.map((t) => (
                <option key={t.name} value={t.name}>
                  {t.name}
                </option>
              ))}
            </select>

            {currentToolSpec && (
              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs space-y-1.5">
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

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">Argumentos (JSON)</label>
              <textarea
                value={toolArgs}
                onChange={(e) => setToolArgs(e.target.value)}
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

            <button
              type="button"
              onClick={() => void handleExecuteTool()}
              disabled={executing || !effectiveToolName}
              className="w-full py-2 px-4 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium text-xs flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
            >
              {executing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
              <span>{executing ? 'Ejecutando…' : 'Ejecutar herramienta'}</span>
            </button>

            {toolResult && (
              <pre className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono text-slate-800 max-h-48 overflow-y-auto">
                {JSON.stringify(toolResult, null, 2)}
              </pre>
            )}
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
