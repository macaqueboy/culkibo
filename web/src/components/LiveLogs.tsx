import React, { useState, useEffect, useRef, useDeferredValue, useMemo } from 'react';
import { Play, Pause, Trash2, Download, Search, Terminal, Copy, Check } from 'lucide-react';
import type { LogEntry } from '../lib/api';
import { api } from '../lib/api';
import { liveEvents } from '../lib/liveEvents';
import { copyToClipboard } from '../lib/clipboard';

interface LiveLogsProps {
  incomingLog?: LogEntry | null;
  projectId?: string;
}

const MAX_RENDERED_LOGS = 1000;
const TIME_FORMATTER = new Intl.DateTimeFormat('es-ES', {
  hour12: false,
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
});

function formatLogTime(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return '--:--:--';
  return TIME_FORMATTER.format(d);
}

function stripAnsi(input: string): string {
  // eslint-disable-next-line no-control-regex
  return String(input || '').replace(/\x1B\[[0-9;]*[a-zA-Z]/g, '');
}

function formatPodLabel(pod: string): string {
  if (pod === 'forge') return 'Local';
  if (pod === 'citadel') return 'Prod';
  if (pod === 'edge') return 'Caddy';
  return pod || 'Sistema';
}

export const LiveLogs: React.FC<LiveLogsProps> = ({ incomingLog, projectId }) => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [selectedPod, setSelectedPod] = useState<string>('all');
  const [selectedLevel, setSelectedLevel] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const deferredSearch = useDeferredValue(searchQuery);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [pausedBuffered, setPausedBuffered] = useState<number>(0);
  const [copiedAi, setCopiedAi] = useState<boolean>(false);
  const [stickToBottom, setStickToBottom] = useState<boolean>(true);
  const containerRef = useRef<HTMLDivElement>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const isPausedRef = useRef<boolean>(false);
  const stickRef = useRef<boolean>(true);
  const seenIdsRef = useRef<Set<string>>(new Set());
  const pausedQueueRef = useRef<LogEntry[]>([]);
  const pendingRef = useRef<LogEntry[]>([]);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    isPausedRef.current = isPaused;
  }, [isPaused]);

  useEffect(() => {
    let active = true;
    const params: { limit: number; projectId?: string } = { limit: 150 };
    if (projectId) params.projectId = projectId;
    api.getLogs(params)
      .then((res) => {
        if (!active) return;
        // El backend devuelve recientes primero; ordenamos cronológicamente (antiguo → nuevo)
        const ordered = [...(res.logs || [])].reverse();
        const nextSeen = new Set<string>();
        const unique: LogEntry[] = [];
        for (const item of ordered) {
          if (item.id && nextSeen.has(item.id)) continue;
          if (item.id) nextSeen.add(item.id);
          unique.push(item);
        }
        seenIdsRef.current = nextSeen;
        setLogs(unique.slice(-MAX_RENDERED_LOGS));
      })
      .catch(() => {});
    return () => { active = false; };
  }, [projectId]);

  const flushPending = () => {
    const batch = pendingRef.current;
    pendingRef.current = [];
    if (batch.length === 0) return;
    setLogs((prev) => {
      const next = [...prev, ...batch];
      return next.length > MAX_RENDERED_LOGS ? next.slice(next.length - MAX_RENDERED_LOGS) : next;
    });
    if (stickRef.current && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ block: 'end' });
    }
  };

  const enqueueLog = (entry: LogEntry) => {
    if (projectId && entry.projectId !== projectId) {
      return;
    }
    if (entry.id && seenIdsRef.current.has(entry.id)) {
      return;
    }
    if (entry.id) {
      seenIdsRef.current.add(entry.id);
      if (seenIdsRef.current.size > MAX_RENDERED_LOGS * 3) {
        const keep = Array.from(seenIdsRef.current).slice(-MAX_RENDERED_LOGS);
        seenIdsRef.current = new Set(keep);
      }
    }
    if (isPausedRef.current) {
      pausedQueueRef.current.push(entry);
      if (pausedQueueRef.current.length > MAX_RENDERED_LOGS) {
        pausedQueueRef.current = pausedQueueRef.current.slice(-MAX_RENDERED_LOGS);
      }
      setPausedBuffered(pausedQueueRef.current.length);
      return;
    }
    pendingRef.current.push(entry);
    if (rafRef.current === null) {
      rafRef.current = window.requestAnimationFrame(() => {
        rafRef.current = null;
        flushPending();
      });
    }
  };

  useEffect(() => {
    return liveEvents.onLog((entry) => {
      enqueueLog(entry);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  useEffect(() => {
    if (!incomingLog) return;
    enqueueLog(incomingLog);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incomingLog]);

  useEffect(() => () => {
    if (rafRef.current !== null) window.cancelAnimationFrame(rafRef.current);
  }, []);

  const filteredLogs = useMemo(() => {
    const q = deferredSearch.trim().toLowerCase();
    const upperLevel = selectedLevel.toUpperCase();
    return logs.filter((log) => {
      if (selectedPod !== 'all' && log.pod !== selectedPod) return false;
      if (selectedLevel !== 'all' && log.level !== upperLevel) return false;
      if (q && !stripAnsi(log.message).toLowerCase().includes(q)) return false;
      return true;
    });
  }, [logs, selectedPod, selectedLevel, deferredSearch]);

  const handleTogglePause = () => {
    setIsPaused((prev) => {
      if (prev) {
        const buffered = pausedQueueRef.current;
        pausedQueueRef.current = [];
        setPausedBuffered(0);
        if (buffered.length > 0) {
          setLogs((curr) => [...curr, ...buffered].slice(-MAX_RENDERED_LOGS));
        }
      }
      return !prev;
    });
  };

  const handleDownload = () => {
    const text = filteredLogs
      .map((l) => `[${l.timestamp}] [${l.level}] [${formatPodLabel(l.pod)}] ${l.message}`)
      .join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `culkibo-logs-${Date.now()}.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyForAi = async () => {
    const problemLines = filteredLogs
      .filter((l) => l.level === 'ERROR' || l.level === 'WARN')
      .slice(0, 30);
    const sample = problemLines.length > 0 ? problemLines : filteredLogs.slice(0, 30);
    const body = sample
      .map((l) => `[${formatLogTime(l.timestamp)}] [${l.level}] [${formatPodLabel(l.pod)}] ${l.message}`)
      .join('\n');
    const prompt = [
      `Estoy depurando ${projectId ? `el proyecto "${projectId}"` : 'el servidor'} en Culkibo.`,
      problemLines.length > 0
        ? 'Estos son los últimos errores y avisos registrados:'
        : 'Estos son los últimos eventos registrados:',
      '```log',
      body || '(sin líneas)',
      '```',
      'Explícame qué está fallando y qué cambio concreto debo aplicar.',
    ].join('\n');
    const ok = await copyToClipboard(prompt);
    if (ok) {
      setCopiedAi(true);
      window.setTimeout(() => setCopiedAi(false), 2200);
    }
  };

  const getLevelBadge = (level: string) => {
    switch (level) {
      case 'ERROR':
        return 'text-red-700 bg-red-50 border-red-200';
      case 'WARN':
        return 'text-amber-800 bg-amber-50 border-amber-200';
      case 'HOT_SYNC':
        return 'text-slate-800 bg-slate-100 border-slate-200';
      case 'SUCCESS':
        return 'text-emerald-700 bg-emerald-50 border-emerald-200';
      default:
        return 'text-slate-600 bg-slate-100 border-slate-200';
    }
  };

  return (
    <div className="flex flex-col h-full space-y-3">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 p-2.5 rounded-xl bg-white border border-slate-200">
        <div className="flex flex-wrap items-center gap-2">
          <select
            aria-label="Filtrar por origen"
            value={selectedPod}
            onChange={(e) => setSelectedPod(e.target.value)}
            className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-medium text-slate-700 cursor-pointer hover:bg-slate-50 transition-colors"
          >
            <option value="all">Todos los orígenes</option>
            <option value="forge">Desarrollo (Live Sync)</option>
            <option value="citadel">Producción</option>
            <option value="edge">Enrutador (Caddy)</option>
          </select>

          <select
            aria-label="Filtrar por nivel"
            value={selectedLevel}
            onChange={(e) => setSelectedLevel(e.target.value)}
            className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-medium text-slate-700 cursor-pointer hover:bg-slate-50 transition-colors"
          >
            <option value="all">Todos los niveles</option>
            <option value="info">INFO</option>
            <option value="hot_sync">HOT_SYNC</option>
            <option value="success">SUCCESS</option>
            <option value="warn">WARN</option>
            <option value="error">ERROR</option>
          </select>

          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
            <input
              type="text"
              placeholder="Buscar en registros…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-white border border-slate-200 rounded-lg text-xs text-slate-800 placeholder-slate-400 w-52 sm:w-60"
            />
          </div>
        </div>

        <div className="flex items-center gap-1.5 flex-wrap">
          <button
            type="button"
            onClick={() => void handleCopyForAi()}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700 transition-colors cursor-pointer"
            title="Copia los últimos errores listos para pegar en un agente de IA"
          >
            {copiedAi ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
            <span>{copiedAi ? 'Copiado para IA' : 'Copiar errores para IA'}</span>
          </button>

          <button
            type="button"
            onClick={handleTogglePause}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer tabular-nums ${
              isPaused
                ? 'bg-amber-50 text-amber-800 border-amber-200 hover:bg-amber-100'
                : 'bg-white text-slate-700 hover:bg-slate-50 border-slate-200'
            }`}
          >
            {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            <span>{isPaused ? (pausedBuffered > 0 ? `Reanudar (+${pausedBuffered})` : 'Reanudar') : 'Pausar'}</span>
          </button>

          <button
            type="button"
            onClick={() => setLogs([])}
            aria-label="Limpiar vista de registros"
            className="p-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-500 hover:text-red-600 transition-colors cursor-pointer"
            title="Limpiar vista"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>

          <button
            type="button"
            onClick={handleDownload}
            aria-label="Descargar archivo de registros"
            className="p-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-500 hover:text-slate-900 transition-colors cursor-pointer"
            title="Descargar archivo .log"
          >
            <Download className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div className="flex-1 rounded-xl bg-white border border-slate-200 flex flex-col overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2.5 bg-slate-50 border-b border-slate-200">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-slate-500" />
            <span className="text-xs font-semibold text-slate-800">Registros en tiempo real</span>
          </div>

          <div className="flex items-center gap-3 text-xs text-slate-500">
            <span className="tabular-nums">
              {filteredLogs.length} {filteredLogs.length === 1 ? 'evento' : 'eventos'}
            </span>
            {!isPaused && (
              <span className="flex items-center gap-1.5 text-emerald-700 font-medium">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                En vivo
              </span>
            )}
          </div>
        </div>

        <div
          ref={containerRef}
          onScroll={(e) => {
            const el = e.currentTarget;
            const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 48;
            stickRef.current = atBottom;
            setStickToBottom(atBottom);
          }}
          className="flex-1 p-3 overflow-y-auto bg-white font-mono text-xs leading-relaxed relative"
        >
          {filteredLogs.length === 0 ? (
            <div className="flex h-full items-center justify-center text-slate-400 font-sans text-xs">
              Todavía no hay registros que coincidan con este filtro.
            </div>
          ) : (
            <div className="space-y-0.5">
              {filteredLogs.map((log) => (
                <div
                  key={log.id}
                  className="flex flex-col sm:flex-row sm:items-start gap-1 sm:gap-2.5 hover:bg-slate-50 px-2 py-1.5 sm:py-1 rounded transition-colors"
                >
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-slate-400 shrink-0 select-none w-16 tabular-nums">{formatLogTime(log.timestamp)}</span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border shrink-0 w-16 text-center ${getLevelBadge(log.level)}`}>
                      {log.level}
                    </span>
                    <span className="text-slate-500 shrink-0 font-medium w-16 truncate" title={log.pod}>
                      [{formatPodLabel(log.pod)}]
                    </span>
                  </div>
                  <span className="whitespace-pre-wrap break-words text-slate-800 min-w-0 flex-1">{stripAnsi(log.message)}</span>
                </div>
              ))}
              <div ref={terminalEndRef} />
            </div>
          )}
          {!stickToBottom && filteredLogs.length > 0 && (
            <button
              type="button"
              onClick={() => {
                stickRef.current = true;
                setStickToBottom(true);
                terminalEndRef.current?.scrollIntoView({ block: 'end', behavior: 'smooth' });
              }}
              className="sticky bottom-2 float-right px-2.5 py-1 rounded-full bg-slate-900 text-white text-[11px] font-sans font-medium shadow-md hover:bg-slate-800 cursor-pointer"
            >
              Ir al final ↓
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
