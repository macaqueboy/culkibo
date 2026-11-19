import React, { useState, useEffect } from 'react';
import { Bot, Play, Copy, Check, Terminal, Zap, Shield, RefreshCw, CheckCircle2 } from 'lucide-react';
import type { McpAuditEntry } from '../lib/api';
import { api } from '../lib/api';

export const McpInspector: React.FC = () => {
  const [tools, setTools] = useState<any[]>([]);
  const [auditLog, setAuditLog] = useState<McpAuditEntry[]>([]);
  const [mcpConfig, setMcpConfig] = useState<any>(null);
  const [selectedTool, setSelectedTool] = useState<string>('culkibo_list_pods');
  const [toolArgs, setToolArgs] = useState<string>('{}');
  const [toolResult, setToolResult] = useState<any>(null);
  const [executing, setExecuting] = useState(false);
  const [copiedType, setCopiedType] = useState<string | null>(null);

  const loadMcpData = async () => {
    try {
      const [toolsRes, auditRes, cfgRes] = await Promise.all([
        api.getMcpTools(),
        api.getMcpAudit(),
        api.getMcpConfig()
      ]);
      setTools(toolsRes.tools || []);
      setAuditLog(auditRes.auditLog || []);
      setMcpConfig(cfgRes);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    let active = true;
    Promise.all([api.getMcpTools(), api.getMcpAudit(), api.getMcpConfig()])
      .then(([toolsRes, auditRes, cfgRes]) => {
        if (!active) return;
        setTools(toolsRes.tools || []);
        setAuditLog(auditRes.auditLog || []);
        setMcpConfig(cfgRes);
      })
      .catch((e) => console.error(e));
    return () => { active = false; };
  }, []);

  const handleSelectTool = (toolName: string) => {
    setSelectedTool(toolName);
    if (toolName === 'culkibo_hot_sync') {
      setToolArgs(JSON.stringify({ changedFile: 'src/App.tsx', diffSize: '12 lines added' }, null, 2));
    } else if (toolName === 'culkibo_switch_traffic') {
      setToolArgs(JSON.stringify({ forgePercent: 20, citadelPercent: 80 }, null, 2));
    } else if (toolName === 'culkibo_issue_wildcard_ssl') {
      setToolArgs(JSON.stringify({ domain: '*.pablo-test.dev', provider: 'lets_encrypt' }, null, 2));
    } else if (toolName === 'culkibo_create_sslip_domain') {
      setToolArgs(JSON.stringify({ ip: '127.0.0.1', service: 'sslip.io' }, null, 2));
    } else {
      setToolArgs('{}');
    }
  };

  const handleExecuteTool = async () => {
    setExecuting(true);
    setToolResult(null);
    try {
      let parsedArgs = {};
      try {
        parsedArgs = JSON.parse(toolArgs);
      } catch (err: any) {
        alert(`JSON no válido: ${err.message}`);
        setExecuting(false);
        return;
      }

      const res = await api.executeMcpTool(selectedTool, parsedArgs);
      setToolResult(res);
      loadMcpData();
    } catch (err: any) {
      setToolResult({ error: err.message });
    } finally {
      setExecuting(false);
    }
  };

  const copyToClipboard = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2500);
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header Banner */}
      <div className="bg-white rounded-2xl border border-slate-200/90 shadow-sm p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="p-3 rounded-xl bg-blue-50 border border-blue-100 text-blue-600">
            <Bot className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-900 tracking-tight">
              Conexión Nativa con tu IA (MCP)
            </h2>
            <p className="text-sm text-slate-600">
              Permite a Cursor, Windsurf, Claude o Antigravity controlar tu servidor y publicar cambios al instante.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            {tools.length} herramientas listas
          </span>
          <button
            onClick={loadMcpData}
            title="Refrescar herramientas"
            className="p-2 rounded-xl bg-slate-100 hover:bg-slate-200 border border-slate-200 text-slate-600 transition-colors cursor-pointer"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Two Column: Setup Snippets & Interactive Tester */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: AI Client Setup Configurations */}
        <div className="bg-white rounded-2xl border border-slate-200/90 shadow-sm p-6 space-y-5">
          <div className="flex items-center gap-2">
            <Zap className="w-5 h-5 text-blue-600" />
 <h3 className="text-sm font-bold text-slate-900">
              1. Cómo Configurar tu Editor con 1 Clic
            </h3>
          </div>

          <p className="text-xs text-slate-600">
            Copia esta configuración y pégala en tu archivo de configuración de MCP para que tu IA tenga superpoderes en Culkibo:
          </p>

          {/* Claude Desktop Config */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-800">
                Claude Desktop (<code className="font-mono text-[11px] text-slate-600">claude_desktop_config.json</code>)
              </span>
              <button
                onClick={() => copyToClipboard(JSON.stringify(mcpConfig?.claudeDesktop || {}, null, 2), 'claude')}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-xs font-medium text-slate-700 border border-slate-200 cursor-pointer transition-colors"
              >
                {copiedType === 'claude' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
                <span>{copiedType === 'claude' ? '¡Copiado!' : 'Copiar Config'}</span>
              </button>
            </div>
            <pre className="p-3.5 bg-slate-100 border border-slate-200 text-slate-800 rounded-xl text-xs font-mono overflow-x-auto">
              {JSON.stringify(mcpConfig?.claudeDesktop || {}, null, 2)}
            </pre>
          </div>

          {/* Cursor / Windsurf Config */}
          <div className="space-y-2 pt-3 border-t border-slate-100">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-800">
                Cursor / Windsurf (Streamable HTTP · MCP {mcpConfig?.protocol?.current || '2026-07-28'})
              </span>
              <button
                onClick={() => copyToClipboard(`${window.location.protocol}//${window.location.host}/api/mcp`, 'cursor')}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-xs font-medium text-slate-700 border border-slate-200 cursor-pointer transition-colors"
              >
                {copiedType === 'cursor' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
                <span>{copiedType === 'cursor' ? '¡Copiado!' : 'Copiar URL'}</span>
              </button>
            </div>
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono text-blue-700 font-semibold select-all">
              {`${window.location.protocol}//${window.location.host}/api/mcp`}
            </div>
            <p className="text-[11px] text-slate-500 leading-relaxed">
              El endpoint antiguo <code className="font-mono">/api/mcp/sse</code> (revisión 2024-11-05) sigue
              funcionando para los clientes ya configurados, pero está deprecado: migra en cuanto tu editor
              hable Streamable HTTP.
            </p>
          </div>
        </div>

        {/* Right: Interactive MCP Tool Runner */}
        <div className="bg-white rounded-2xl border border-slate-200/90 shadow-sm p-6 space-y-4">
          <div className="flex items-center justify-between">
 <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-blue-600" />
              2. Probar Herramientas de IA
            </h3>
            <span className="text-xs text-slate-500">
              Prueba en vivo
            </span>
          </div>

          <div className="space-y-3.5">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                Selecciona una Herramienta:
              </label>
              <select
                value={selectedTool}
                onChange={(e) => handleSelectTool(e.target.value)}
                className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-300 rounded-xl text-xs font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
              >
                {tools.map((t) => (
                  <option key={t.name} value={t.name}>
                    {t.name} — {t.description.slice(0, 60)}...
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                Parámetros de Entrada (JSON):
              </label>
              <textarea
                value={toolArgs}
                onChange={(e) => setToolArgs(e.target.value)}
                rows={3}
                className="w-full p-3 bg-slate-50 border border-slate-300 rounded-xl text-xs font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
              />
            </div>

            <button
              onClick={handleExecuteTool}
              disabled={executing}
              className="w-full py-2.5 px-4 rounded-xl bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-semibold text-xs shadow-sm flex items-center justify-center gap-2 cursor-pointer transition-colors"
            >
              <Play className={`w-3.5 h-3.5 ${executing ? 'animate-spin' : ''}`} />
              <span>{executing ? 'Ejecutando herramienta...' : 'Ejecutar Herramienta Ahora'}</span>
            </button>

            {toolResult && (
              <div className="space-y-1.5 pt-2">
                <span className="text-xs font-semibold text-slate-700">Resultado:</span>
                <pre className="p-3.5 bg-slate-100 border border-slate-200 rounded-xl text-xs font-mono text-emerald-700 max-h-48 overflow-y-auto">
                  {JSON.stringify(toolResult, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* AI Agents Live Audit Trail */}
      <div className="bg-white rounded-2xl border border-slate-200/90 shadow-sm p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-blue-600" />
            <h3 className="text-base font-bold text-slate-900">
              Historial de Comandos Ejecutados por la IA
            </h3>
          </div>
          <span className="text-xs text-slate-500 font-medium">
            {auditLog.length} llamadas registradas
          </span>
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-200">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
 <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-semibold text-slate-600">
                <th className="py-3 px-4">Hora</th>
                <th className="py-3 px-4">Herramienta</th>
                <th className="py-3 px-4">Agente</th>
                <th className="py-3 px-4">Latencia</th>
                <th className="py-3 px-4">Estado</th>
                <th className="py-3 px-4">Detalles</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {auditLog.map((log) => (
                <tr key={log.id} className="hover:bg-slate-50/70">
                  <td className="py-2.5 px-4 text-slate-500 font-mono">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-2.5 px-4 font-mono font-semibold text-blue-700">
                    {log.toolName}
                  </td>
                  <td className="py-2.5 px-4 text-slate-600">
                    {log.agent}
                  </td>
                  <td className="py-2.5 px-4 text-emerald-700 font-mono font-semibold">
                    {log.durationMs}ms
                  </td>
                  <td className="py-2.5 px-4">
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                      <CheckCircle2 className="w-3 h-3" />
                      ÉXITO
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-slate-500 truncate max-w-xs font-mono text-[11px]">
                    {log.resultSummary}
                  </td>
                </tr>
              ))}

              {auditLog.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No hay llamadas de herramientas registradas aún. ¡Prueba ejecutar una arriba!
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
