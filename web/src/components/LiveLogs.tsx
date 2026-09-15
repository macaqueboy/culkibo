import React, { useState, useEffect, useRef } from 'react';
import { Play, Pause, Trash2, Download, Search, Terminal } from 'lucide-react';
import type { LogEntry } from '../lib/api';
import { api } from '../lib/api';

interface LiveLogsProps {
  incomingLog?: LogEntry | null;
  projectId?: string;
}

export const LiveLogs: React.FC<LiveLogsProps> = ({ incomingLog, projectId }) => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [selectedPod, setSelectedPod] = useState<string>('all');
  const [selectedLevel, setSelectedLevel] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const params: any = { limit: 120 };
    if (projectId) params.projectId = projectId;
    api.getLogs(params).then((res) => {
      setLogs(res.logs || []);
    });
  }, [projectId]);

  useEffect(() => {
    if (incomingLog && !isPaused) {
      setLogs((prev) => [incomingLog, ...prev.slice(0, 500)]);
    }
  }, [incomingLog, isPaused]);

  const filteredLogs = logs.filter((log) => {
    if (selectedPod !== 'all' && log.pod !== selectedPod) return false;
    if (selectedLevel !== 'all' && log.level !== selectedLevel.toUpperCase()) return false;
    if (searchQuery && !log.message.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  const handleDownload = () => {
    const text = filteredLogs.map((l) => `[${l.timestamp}] [${l.level}] [${l.pod === 'forge' ? 'Desarrollo' : l.pod === 'citadel' ? 'Producción' : l.pod === 'edge' ? 'Enrutador' : l.pod}] ${l.message}`).join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `culkibo-logs-${Date.now()}.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getLevelBadge = (level: string) => {
    switch (level) {
      case 'ERROR':
        return 'text-rose-700 bg-rose-50 border-rose-200';
      case 'WARN':
        return 'text-amber-700 bg-amber-50 border-amber-200';
      case 'HOT_SYNC':
        return 'text-blue-700 bg-blue-50 border-blue-200';
      case 'SUCCESS':
        return 'text-emerald-700 bg-emerald-50 border-emerald-200';
      case 'INFO':
        return 'text-slate-700 bg-slate-100 border-slate-200';
      default:
        return 'text-slate-600 bg-slate-100 border-slate-200';
    }
  };

  return (
    <div className="flex flex-col h-full space-y-4">
      {/* Controls Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 rounded-xl bg-white border border-slate-200 shadow-sm">
        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Pod Filter */}
          <select
            value={selectedPod}
            onChange={(e) => setSelectedPod(e.target.value)}
            className="px-3 py-1.5 bg-white border border-slate-200 rounded-lg text-sm font-medium text-slate-700 focus:outline-none focus:ring-2 focus:ring-slate-900/10 cursor-pointer shadow-sm hover:bg-slate-50 transition-colors"
          >
            <option value="all">Todos los Entornos</option>
            <option value="forge">Entorno de Desarrollo</option>
            <option value="citadel">Entorno de Producción</option>
            <option value="edge">Enrutador</option>
          </select>

          {/* Level Filter */}
          <select
            value={selectedLevel}
            onChange={(e) => setSelectedLevel(e.target.value)}
            className="px-3 py-1.5 bg-white border border-slate-200 rounded-lg text-sm font-medium text-slate-700 focus:outline-none focus:ring-2 focus:ring-slate-900/10 cursor-pointer shadow-sm hover:bg-slate-50 transition-colors"
          >
            <option value="all">Todos los Niveles</option>
            <option value="info">INFO</option>
            <option value="hot_sync">HOT_SYNC</option>
            <option value="success">SUCCESS</option>
            <option value="warn">WARN</option>
            <option value="error">ERROR</option>
          </select>

          {/* Search */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-2.5 top-2" />
            <input
              type="text"
              placeholder="Buscar en logs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 pr-3 py-1.5 bg-white border border-slate-200 rounded-lg text-sm text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-900/10 w-64 shadow-sm"
            />
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          {/* Pause / Resume */}
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium border transition-colors shadow-sm ${
              isPaused
                ? 'bg-amber-50 text-amber-700 border-amber-200 hover:bg-amber-100'
                : 'bg-white text-slate-700 hover:bg-slate-50 border-slate-200'
            }`}
          >
            {isPaused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
            <span>{isPaused ? 'Reanudar' : 'Pausar'}</span>
          </button>

          {/* Clear */}
          <button
            onClick={() => setLogs([])}
            className="p-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-500 hover:text-red-600 transition-colors shadow-sm"
            title="Limpiar logs"
          >
            <Trash2 className="w-4 h-4" />
          </button>

          {/* Download */}
          <button
            onClick={handleDownload}
            className="p-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-500 hover:text-slate-800 transition-colors shadow-sm"
            title="Exportar logs"
          >
            <Download className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Terminal Display */}
      <div className="flex-1 rounded-xl bg-white border border-slate-200 shadow-sm flex flex-col overflow-hidden">
        {/* Terminal Titlebar */}
        <div className="flex items-center justify-between px-4 py-2.5 bg-slate-50 border-b border-slate-200">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-slate-500" />
            <span className="text-sm font-semibold text-slate-700">
              Registros en tiempo real
            </span>
          </div>

          <div className="flex items-center gap-3 text-xs font-medium text-slate-500">
            <span>{filteredLogs.length} eventos</span>
            {!isPaused && (
              <span className="flex items-center gap-1.5 text-emerald-600">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                EN VIVO
              </span>
            )}
          </div>
        </div>

        {/* Log Lines Console */}
        <div className="flex-1 p-3 overflow-y-auto bg-white font-mono text-[13px] leading-relaxed">
          {filteredLogs.length === 0 ? (
            <div className="flex h-full items-center justify-center text-slate-400 font-sans text-sm">
              No hay logs para mostrar.
            </div>
          ) : (
            <div className="space-y-0.5">
              {filteredLogs.map((log) => {
                const time = new Date(log.timestamp).toLocaleTimeString();
                return (
                  <div
                    key={log.id}
                    className="flex items-start gap-3 hover:bg-slate-50/80 px-2 py-1 rounded transition-colors group"
                  >
                    <span className="text-slate-400 shrink-0 select-none w-20">{time}</span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border shrink-0 w-16 text-center ${getLevelBadge(log.level)}`}>
                      {log.level}
                    </span>
                    <span className="text-slate-500 shrink-0 font-medium w-24 truncate" title={log.pod}>
                      [{log.pod === 'forge' ? 'Dev' : log.pod === 'citadel' ? 'Prod' : log.pod === 'edge' ? 'Router' : log.pod}]
                    </span>
                    <span className="break-all text-slate-800">
                      {log.message}
                    </span>
                  </div>
                );
              })}
              <div ref={terminalEndRef} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
