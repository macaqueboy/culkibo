import React, { useState, useEffect, useMemo } from 'react';
import {
  Bot,
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
  AlertTriangle
} from 'lucide-react';
import type { McpAuditEntry, RemoteAccessInfo } from '../lib/api';
import { api } from '../lib/api';
import { liveEvents } from '../lib/liveEvents';

type ClientTab = 'cursor' | 'claude' | 'vscode' | 'cli';

export const AiAgentHub: React.FC<{ onNotify?: (msg: string) => void }> = ({ onNotify }) => {
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
  const [livePulse, setLivePulse] = useState(false);

  const loadMcpData = async () => {
    try {
      const [toolsRes, auditRes, cfgRes, remRes] = await Promise.all([
        api.getMcpTools(),
        api.getMcpAudit(),
        api.getMcpConfig(),
        api.getRemoteAccess().catch(() => null)
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
      api.getRemoteAccess().catch(() => null)
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
      setLivePulse(true);
      setTimeout(() => setLivePulse(false), 1800);
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
      const res = await api.callMcpModern(selectedTool, parsedArgs);
      setToolResult(res);
    } catch (err: any) {
      setToolResult({ error: err?.message || 'Error ejecutando la herramienta' });
    } finally {
      setExecuting(false);
    }
  };

  const copyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
    onNotify?.('Configuración copiada al portapapeles');
  };

  const activeConfigs = connectionScope === 'remote' && remoteInfo?.clientConfigs
    ? remoteInfo.clientConfigs
    : mcpConfig;

  const snippetByTab: Record<ClientTab, { title: string; subtitle: string; code: string }> = {
    cursor: {
      title: 'Cursor / Windsurf / Antigravity (Streamable HTTP)',
      subtitle: 'Pégalo en la configuración MCP de tu editor (soporta protocolo MCP 2026-07-28):',
      code: JSON.stringify(activeConfigs?.cursorOrWindsurf || {}, null, 2)
    },
    claude: {
      title: 'Claude Desktop (claude_desktop_config.json)',
      subtitle: 'Abre Ajustes → Desarrollador → Editar configuración y pega este bloque:',
      code: JSON.stringify(activeConfigs?.claudeDesktop || {}, null, 2)
    },
    vscode: {
      title: 'VS Code / GitHub Copilot (.vscode/mcp.json)',
      subtitle: 'Crea o edita .vscode/mcp.json en tu workspace:',
      code: JSON.stringify(activeConfigs?.vscodeCopilot || {}, null, 2)
    },
    cli: {
      title: 'Claude Code CLI (1 solo comando)',
      subtitle: 'Ejecútalo en tu terminal para registrar Culkibo al instante:',
      code: activeConfigs?.claudeCodeCli || `claude mcp add --transport http culkibo ${window.location.origin}/api/mcp`
    }
  };

  const currentSnippet = snippetByTab[clientTab];

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Banner principal */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className={`p-3 rounded-xl border transition-colors ${
            livePulse ? 'bg-blue-100 border-blue-300 text-blue-700' : 'bg-blue-50 border-blue-100 text-blue-600'
          }`}>
            <Bot className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-xl font-bold text-slate-900 tracking-tight">Enlace en directo con tu Agente IA</h1>
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                <span className={`w-2 h-2 rounded-full bg-emerald-500 ${livePulse ? 'animate-ping' : ''}`} />
                MCP {mcpConfig?.protocol?.current || '2026-07-28'} listo
              </span>
            </div>
            <p className="text-sm text-slate-500 mt-0.5">
              Conecta Claude, Cursor, Windsurf, VS Code o Antigravity para que desplieguen, gestionen dominios, analicen WordPress y depuren en directo.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <span className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200 tabular-nums">
            {tools.length} herramientas
          </span>
          <button
            type="button"
            onClick={() => void loadMcpData()}
            className="p-2 rounded-xl bg-slate-100 hover:bg-slate-200 border border-slate-200 text-slate-600 cursor-pointer"
            title="Refrescar"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 1. Conexión en 1 clic */}
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 space-y-4">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Zap className="w-4 h-4 text-blue-600" />
              1. Conecta tu agente en 1 clic
            </h2>
            <div className="flex items-center bg-slate-100 p-0.5 rounded-lg border border-slate-200 text-[11px]">
              <button
                type="button"
                onClick={() => setConnectionScope('local')}
                className={`px-2.5 py-1 rounded-md font-semibold cursor-pointer ${connectionScope === 'local' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600'}`}
              >
                Local
              </button>
              <button
                type="button"
                onClick={() => setConnectionScope('remote')}
                className={`px-2.5 py-1 rounded-md font-semibold cursor-pointer ${connectionScope === 'remote' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600'}`}
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
              { id: 'cli', label: 'Claude Code CLI' }
            ] as const).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setClientTab(tab.id)}
                className={`px-3 py-1.5 rounded-lg font-medium border cursor-pointer ${
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
              <span className="text-xs font-semibold text-slate-800">{currentSnippet.title}</span>
              <button
                type="button"
                onClick={() => copyText(currentSnippet.code, clientTab)}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-xs font-medium text-slate-700 border border-slate-200 cursor-pointer"
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

        {/* 2. Probador interactivo MCP 2026-07-28 */}
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-blue-600" />
              2. Probar herramientas en vivo (POST /api/mcp)
            </h2>
            <span className="text-[11px] font-mono text-slate-400">2026-07-28</span>
          </div>

          <div className="space-y-3">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={toolSearch}
                onChange={(e) => setToolSearch(e.target.value)}
                placeholder="Filtrar herramientas (ej. wordpress, domain, deploy…)"
                className="w-full pl-8 pr-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs focus:bg-white focus:outline-none"
              />
            </div>

            <select
              value={selectedTool}
              onChange={(e) => handleSelectTool(e.target.value)}
              className="w-full px-3 py-2.5 bg-slate-50 border border-slate-300 rounded-xl text-xs font-mono text-slate-800"
            >
              {filteredTools.map((t) => (
                <option key={t.name} value={t.name}>
                  {t.name} — {String(t.description || '').slice(0, 62)}
                </option>
              ))}
            </select>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">Argumentos (JSON)</label>
              <textarea
                value={toolArgs}
                onChange={(e) => setToolArgs(e.target.value)}
                rows={3}
                className="w-full p-3 bg-slate-50 border border-slate-300 rounded-xl text-xs font-mono text-slate-800"
              />
            </div>

            {jsonError && (
              <div className="p-2.5 rounded-lg bg-rose-50 border border-rose-200 text-xs text-rose-700 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                <span>{jsonError}</span>
              </div>
            )}

            <button
              type="button"
              onClick={handleExecuteTool}
              disabled={executing}
              className="w-full py-2.5 px-4 rounded-xl bg-slate-900 hover:bg-slate-800 text-white font-semibold text-xs flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
            >
              <Play className={`w-3.5 h-3.5 ${executing ? 'animate-spin' : ''}`} />
              <span>{executing ? 'Ejecutando…' : 'Ejecutar ahora'}</span>
            </button>

            {toolResult && (
              <pre className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono text-slate-800 max-h-48 overflow-y-auto">
                {JSON.stringify(toolResult, null, 2)}
              </pre>
            )}
          </div>
        </div>
      </div>

      {/* 3. Feed en directo de llamadas del Agente IA */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
        <div className="px-6 py-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Radio className={`w-4 h-4 ${livePulse ? 'text-blue-600 animate-ping' : 'text-emerald-600'}`} />
            <h2 className="text-sm font-bold text-slate-900">Actividad del agente en tiempo real</h2>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <Shield className="w-3.5 h-3.5 text-slate-400" />
            <span>Secretos redactados automáticamente · {auditLog.length} llamadas</span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50/70 text-[11px] font-semibold text-slate-600">
                <th className="py-3 px-4">Hora</th>
                <th className="py-3 px-4">Herramienta</th>
                <th className="py-3 px-4">Agente</th>
                <th className="py-3 px-4">Latencia</th>
                <th className="py-3 px-4">Estado</th>
                <th className="py-3 px-4">Resumen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {auditLog.map((log) => (
                <tr key={log.id} className="hover:bg-slate-50/70">
                  <td className="py-2.5 px-4 text-slate-500 font-mono tabular-nums">
                    {new Date(log.timestamp).toLocaleTimeString('es-ES')}
                  </td>
                  <td className="py-2.5 px-4 font-mono font-semibold text-blue-700">{log.toolName}</td>
                  <td className="py-2.5 px-4 text-slate-600">{log.agent || 'MCP'}</td>
                  <td className="py-2.5 px-4 text-emerald-700 font-mono font-semibold tabular-nums">{log.durationMs} ms</td>
                  <td className="py-2.5 px-4">
                    {log.success !== false ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                        <CheckCircle2 className="w-3 h-3" /> OK
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-rose-50 text-rose-700 border border-rose-200">
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
                    Aún no hay llamadas registradas. Conecta tu agente arriba o prueba una herramienta en vivo.
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
