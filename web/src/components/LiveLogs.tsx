import React, { useState, useEffect, useRef, useDeferredValue, useMemo, useCallback } from 'react';
import {
  Play,
  Pause,
  Trash2,
  Download,
  Search,
  Terminal,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  RefreshCw,
  Archive,
  ShieldCheck,
  ShieldAlert,
  Loader2,
} from 'lucide-react';
import type { LogEntry, Project, LogArchiveStatsResult, LogArchiveSearchResult } from '../lib/api';
import { api, apiFetch } from '../lib/api';
import { liveEvents } from '../lib/liveEvents';
import { copyToClipboard } from '../lib/clipboard';
import { useI18n } from '../lib/i18n';

interface LiveLogsProps {
  incomingLog?: LogEntry | null;
  projectId?: string;
}

interface ExtendedLogEntry extends LogEntry {
  fields?: Record<string, string | number | boolean>;
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

function parseSinceMs(since: string): number | null {
  const rel = since.match(/^(\d+)(m|h|d)$/);
  if (!rel) return null;
  const qty = Number(rel[1]);
  const mult = rel[2] === 'm' ? 60000 : rel[2] === 'h' ? 3600000 : 86400000;
  return Date.now() - qty * mult;
}

function compileClientSafeRegex(pattern: string): { regex: RegExp | null; error: string | null } {
  if (!pattern) return { regex: null, error: null };
  if (pattern.length > 160) return { regex: null, error: 'Regex demasiado larga (máx. 160 caracteres)' };
  if (/\\[1-9]/.test(pattern) || /\(\?<[=!]/.test(pattern) || /\([^)]*[+*?}][^)]*\)\s*[+*{]/.test(pattern)) {
    return { regex: null, error: 'Regex rechazada por seguridad (cuantificadores anidados)' };
  }
  try {
    return { regex: new RegExp(pattern, 'i'), error: null };
  } catch (e: any) {
    return { regex: null, error: e?.message || 'Regex inválida' };
  }
}

function tryParseJsonMessage(msg: string): Record<string, any> | null {
  const clean = stripAnsi(msg).trim();
  if (!clean.startsWith('{') || !clean.endsWith('}') || clean.length > 8192) return null;
  try {
    const parsed = JSON.parse(clean);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
  } catch {}
  return null;
}

export const LiveLogs: React.FC<LiveLogsProps> = ({ incomingLog, projectId }) => {
  const { t } = useI18n();
  const [logs, setLogs] = useState<ExtendedLogEntry[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>(projectId || 'all');

  // Cycle-10 Compressed Persistent Log Archive (.ndjson.gz) state
  const [archiveOpen, setArchiveOpen] = useState<boolean>(true);
  const [archiveStats, setArchiveStats] = useState<LogArchiveStatsResult | null>(null);
  const [archiveQuery, setArchiveQuery] = useState<string>('');
  const [archiveLevel, setArchiveLevel] = useState<string>('ALL');
  const [archiveUseRegex, setArchiveUseRegex] = useState<boolean>(false);
  const [archiveResult, setArchiveResult] = useState<LogArchiveSearchResult | null>(null);
  const [archiveError, setArchiveError] = useState<string | null>(null);
  const [archiveBusy, setArchiveBusy] = useState<boolean>(false);
  const [selectedPod, setSelectedPod] = useState<string>('all');
  const [selectedLevel, setSelectedLevel] = useState<string>('all');
  const [sinceWindow, setSinceWindow] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [regexMode, setRegexMode] = useState<boolean>(false);
  const [attrFilter, setAttrFilter] = useState<string>('');
  const [expandedIds, setExpandedIds] = useState<Record<string, boolean>>({});
  const deferredSearch = useDeferredValue(searchQuery);
  const deferredAttr = useDeferredValue(attrFilter);

  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [pausedBuffered, setPausedBuffered] = useState<number>(0);
  const [copiedAi, setCopiedAi] = useState<boolean>(false);
  const [exporting, setExporting] = useState<boolean>(false);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [stickToBottom, setStickToBottom] = useState<boolean>(true);
  const containerRef = useRef<HTMLDivElement>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const isPausedRef = useRef<boolean>(false);
  const stickRef = useRef<boolean>(true);
  const seenIdsRef = useRef<Set<string>>(new Set());
  const pausedQueueRef = useRef<ExtendedLogEntry[]>([]);
  const pendingRef = useRef<ExtendedLogEntry[]>([]);
  const rafRef = useRef<number | null>(null);

  const effectiveProjectId = projectId || (selectedProjectId !== 'all' ? selectedProjectId : undefined);
  const archiveTargetProjectId = effectiveProjectId || projects[0]?.id || 'proj_acme_web';

  useEffect(() => {
    let active = true;
    api.getLogArchiveStats(archiveTargetProjectId)
      .then((res) => {
        if (active && res) setArchiveStats(res);
      })
      .catch(() => {
        if (active) setArchiveStats(null);
      });
    return () => { active = false; };
  }, [archiveTargetProjectId]);

  const handleSearchArchive = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setArchiveBusy(true);
    setArchiveError(null);
    try {
      const payload: { query?: string; regex?: string; level?: string; limit: number } = { limit: 100 };
      if (archiveLevel !== 'ALL') payload.level = archiveLevel;
      const cleanQ = archiveQuery.trim();
      if (cleanQ) {
        if (archiveUseRegex) payload.regex = cleanQ;
        else payload.query = cleanQ;
      }
      const res = await api.searchLogArchive(archiveTargetProjectId, payload);
      setArchiveResult(res);
    } catch (err: unknown) {
      setArchiveResult(null);
      setArchiveError(err instanceof Error ? err.message : 'Compressed log archive search rejected');
    } finally {
      setArchiveBusy(false);
    }
  };

  useEffect(() => {
    isPausedRef.current = isPaused;
  }, [isPaused]);

  useEffect(() => {
    if (projectId) return;
    let active = true;
    api.getProjects()
      .then((list) => {
        if (active && Array.isArray(list)) setProjects(list);
      })
      .catch(() => {});
    return () => { active = false; };
  }, [projectId]);

  const fetchServerLogs = useCallback(async () => {
    setRefreshing(true);
    try {
      const qs = new URLSearchParams({ limit: '400' });
      if (effectiveProjectId) qs.set('projectId', effectiveProjectId);
      if (selectedPod !== 'all') qs.set('pod', selectedPod);
      if (selectedLevel !== 'all') qs.set('level', selectedLevel);
      if (sinceWindow !== 'all') qs.set('since', sinceWindow);
      if (attrFilter.trim()) qs.set('attr', attrFilter.trim());
      if (searchQuery.trim()) {
        if (regexMode) qs.set('regex', searchQuery.trim());
        else qs.set('search', searchQuery.trim());
      }
      const res = await apiFetch(`/api/logs?${qs.toString()}`);
      if (!res.ok) return;
      const data = await res.json();
      const ordered = [...((data.logs || []) as ExtendedLogEntry[])].reverse();
      const nextSeen = new Set<string>();
      const unique: ExtendedLogEntry[] = [];
      for (const item of ordered) {
        if (item.id && nextSeen.has(item.id)) continue;
        if (item.id) nextSeen.add(item.id);
        unique.push(item);
      }
      seenIdsRef.current = nextSeen;
      setLogs(unique.slice(-MAX_RENDERED_LOGS));
    } catch {
      // Fallback to api.getLogs if custom query failed
      api.getLogs({ limit: 250, projectId: effectiveProjectId })
        .then((res) => {
          const ordered = [...((res.logs || []) as ExtendedLogEntry[])].reverse();
          setLogs(ordered.slice(-MAX_RENDERED_LOGS));
        })
        .catch(() => {});
    } finally {
      setRefreshing(false);
    }
  }, [effectiveProjectId, selectedPod, selectedLevel, sinceWindow, attrFilter, searchQuery, regexMode]);

  useEffect(() => {
    void fetchServerLogs();
  }, [effectiveProjectId, sinceWindow]); // eslint-disable-line react-hooks/exhaustive-deps

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

  const enqueueLog = (entry: ExtendedLogEntry) => {
    if (effectiveProjectId && entry.projectId !== effectiveProjectId) {
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
  }, [effectiveProjectId]);

  useEffect(() => {
    if (!incomingLog) return;
    enqueueLog(incomingLog);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incomingLog]);

  useEffect(() => () => {
    if (rafRef.current !== null) window.cancelAnimationFrame(rafRef.current);
  }, []);

  const regexCompiled = useMemo(
    () => (regexMode ? compileClientSafeRegex(deferredSearch.trim()) : { regex: null, error: null }),
    [regexMode, deferredSearch]
  );

  const filteredLogs = useMemo(() => {
    const q = deferredSearch.trim().toLowerCase();
    const upperLevel = selectedLevel.toUpperCase();
    const sinceMs = sinceWindow !== 'all' ? parseSinceMs(sinceWindow) : null;

    const attrPairs: Array<[string, string]> = [];
    if (deferredAttr.trim()) {
      for (const tok of deferredAttr.trim().split(/\s+/)) {
        const clean = tok.replace(/^@/, '');
        const sep = clean.search(/[:=]/);
        if (sep > 0) {
          attrPairs.push([clean.slice(0, sep).trim().toLowerCase(), clean.slice(sep + 1).trim().toLowerCase()]);
        }
      }
    }

    return logs.filter((log) => {
      if (effectiveProjectId && log.projectId !== effectiveProjectId) return false;
      if (selectedPod !== 'all' && log.pod !== selectedPod) return false;
      if (selectedLevel !== 'all' && log.level !== upperLevel) return false;
      if (sinceMs !== null) {
        const tsMs = Date.parse(log.timestamp);
        if (Number.isFinite(tsMs) && tsMs < sinceMs) return false;
      }
      if (attrPairs.length > 0) {
        const fields = log.fields || tryParseJsonMessage(log.message);
        if (!fields) return false;
        for (const [ak, av] of attrPairs) {
          const fk = Object.keys(fields).find((k) => k.toLowerCase() === ak);
          if (!fk || String(fields[fk]).toLowerCase() !== av) return false;
        }
      }
      if (regexMode) {
        if (regexCompiled.regex && !regexCompiled.regex.test(stripAnsi(log.message))) return false;
      } else if (q) {
        if (!stripAnsi(log.message).toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [logs, effectiveProjectId, selectedPod, selectedLevel, sinceWindow, deferredSearch, deferredAttr, regexMode, regexCompiled]);

  const errorCount = useMemo(() => filteredLogs.filter((l) => l.level === 'ERROR').length, [filteredLogs]);
  const warnCount = useMemo(() => filteredLogs.filter((l) => l.level === 'WARN').length, [filteredLogs]);

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

  const handleDownload = async (format: 'log' | 'ndjson' = 'log') => {
    setExporting(true);
    try {
      const qs = new URLSearchParams({ format, limit: '2000' });
      if (effectiveProjectId) qs.set('projectId', effectiveProjectId);
      if (selectedPod !== 'all') qs.set('pod', selectedPod);
      if (selectedLevel !== 'all') qs.set('level', selectedLevel);
      if (sinceWindow !== 'all') qs.set('since', sinceWindow);
      if (attrFilter.trim()) qs.set('attr', attrFilter.trim());
      if (searchQuery.trim()) {
        if (regexMode) qs.set('regex', searchQuery.trim());
        else qs.set('search', searchQuery.trim());
      }

      const res = await apiFetch(`/api/logs/export?${qs.toString()}`);
      if (res.ok) {
        const text = await res.text();
        const blob = new Blob([text], { type: format === 'ndjson' ? 'application/x-ndjson' : 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `culkibo-logs-${Date.now()}.${format}`;
        a.click();
        URL.revokeObjectURL(url);
        return;
      }
    } catch {
      // Fallback below
    } finally {
      setExporting(false);
    }

    // Client-side fallback if server export route isn't active yet
    const text = format === 'ndjson'
      ? filteredLogs.map((l) => JSON.stringify(l)).join('\n')
      : filteredLogs
          .map((l) => `[${l.timestamp}] [${l.level}] [${formatPodLabel(l.pod)}] ${stripAnsi(l.message)}`)
          .join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `culkibo-logs-${Date.now()}.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Fixed: slice(-30) takes the LATEST 30 errors/events instead of oldest 30!
  const handleCopyForAi = async () => {
    const problemLines = filteredLogs
      .filter((l) => l.level === 'ERROR' || l.level === 'WARN')
      .slice(-30);
    const sample = problemLines.length > 0 ? problemLines : filteredLogs.slice(-30);
    const body = sample
      .map((l) => `[${formatLogTime(l.timestamp)}] [${l.level}] [${formatPodLabel(l.pod)}] ${stripAnsi(l.message)}`)
      .join('\n');
    const prompt = [
      `Estoy depurando ${effectiveProjectId ? `el proyecto "${effectiveProjectId}"` : 'el servidor'} en Culkibo.`,
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
      <div className="flex flex-col gap-2.5 p-2.5 rounded-xl bg-white border border-slate-200">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
          <div className="flex flex-wrap items-center gap-2">
            {!projectId && projects.length > 0 && (
              <select
                aria-label="Filtrar por proyecto"
                value={selectedProjectId}
                onChange={(e) => setSelectedProjectId(e.target.value)}
                className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-medium text-slate-700 cursor-pointer hover:bg-slate-50 transition-colors"
              >
                <option value="all">Todos los proyectos</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            )}

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

            <select
              aria-label="Ventana de tiempo"
              value={sinceWindow}
              onChange={(e) => setSinceWindow(e.target.value)}
              className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-medium text-slate-700 cursor-pointer hover:bg-slate-50 transition-colors"
            >
              <option value="all">Todo el historial</option>
              <option value="5m">Últimos 5m</option>
              <option value="15m">Últimos 15m</option>
              <option value="1h">Última 1h</option>
              <option value="6h">Últimas 6h</option>
              <option value="24h">Últimas 24h</option>
            </select>

            <div className="relative flex items-center">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 pointer-events-none" />
              <input
                type="text"
                placeholder={regexMode ? 'Regex p. ej. timeout|50[0-4]…' : 'Buscar en registros…'}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') void fetchServerLogs();
                }}
                className="pl-8 pr-10 py-1.5 bg-white border border-slate-200 rounded-lg text-xs text-slate-800 placeholder-slate-400 w-52 sm:w-60 font-mono"
              />
              <button
                type="button"
                onClick={() => setRegexMode((v) => !v)}
                aria-label="Alternar búsqueda por expresión regular"
                title="Activar/desactivar búsqueda Regex (protegida contra ReDoS)"
                className={`absolute right-1.5 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold cursor-pointer border ${
                  regexMode
                    ? 'bg-slate-900 text-white border-slate-900'
                    : 'bg-slate-50 text-slate-500 border-slate-200 hover:text-slate-900'
                }`}
              >
                .*
              </button>
            </div>

            <input
              type="text"
              placeholder="@status:500 method=POST"
              value={attrFilter}
              onChange={(e) => setAttrFilter(e.target.value)}
              aria-label="Filtrar por atributos JSON estructurados"
              className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-mono text-slate-800 placeholder-slate-400 w-40"
              title="Filtra campos JSON o key=value (ej. status=500)"
            />
          </div>

          <div className="flex items-center gap-1.5 flex-wrap">
            <button
              type="button"
              onClick={() => void fetchServerLogs()}
              disabled={refreshing}
              aria-label="Consultar historial en servidor"
              title="Consultar historial persistente del servidor"
              className="p-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-500 hover:text-slate-900 transition-colors cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            </button>

            <button
              type="button"
              onClick={() => void handleCopyForAi()}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700 transition-colors cursor-pointer"
              title="Copia los últimos 30 errores más recientes listos para pegar en un agente de IA"
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
              disabled={exporting}
              onClick={() => void handleDownload('log')}
              aria-label="Exportar registros en formato .log"
              className="flex items-center gap-1 px-2 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-600 hover:text-slate-900 transition-colors cursor-pointer disabled:opacity-50"
              title="Exportar historial filtrado (.log)"
            >
              <Download className="w-3.5 h-3.5" />
              <span>.log</span>
            </button>
          </div>
        </div>

        {regexMode && regexCompiled.error && (
          <div className="text-[11px] text-red-700 bg-red-50 border border-red-200 rounded-lg px-2.5 py-1">
            {regexCompiled.error}
          </div>
        )}
      </div>

      {/* Cycle-10 Collapsible Persistent Log Archive (.ndjson.gz) Search Panel */}
      <section className="culkibo-surface rounded-xl overflow-hidden text-xs">
        <div className="px-4 py-2.5 bg-slate-50 border-b border-slate-200 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 flex-wrap min-w-0">
            <Archive className="w-3.5 h-3.5 text-slate-600 shrink-0" />
            <span className="font-semibold text-slate-900">{t('logs.archiveTitle')}</span>
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
              <ShieldCheck className="w-3 h-3" />
              {t('logs.archiveBadge')}
            </span>
            {archiveStats && (
              <span className="font-mono text-[11px] text-slate-500 tabular-nums">
                {archiveStats.shardCount ?? archiveStats.filesCount ?? archiveStats.totalFiles ?? 0} shards ·{' '}
                {archiveStats.totalBytes != null
                  ? `${(archiveStats.totalBytes / 1024).toFixed(1)} KB gz`
                  : '0 KB gz'}
                {archiveStats.retentionDays ? ` · ${archiveStats.retentionDays}d cap` : ''}
              </span>
            )}
          </div>
          <button
            type="button"
            onClick={() => setArchiveOpen((v) => !v)}
            className="inline-flex items-center gap-1 px-2 py-1 rounded-md border border-slate-200 bg-white hover:bg-slate-100 text-[11px] font-medium text-slate-700 cursor-pointer shrink-0"
          >
            {archiveOpen ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            <span>{archiveOpen ? 'Hide' : 'Search'}</span>
          </button>
        </div>

        {archiveOpen && (
          <div className="p-3.5 space-y-2.5 bg-white">
            <p className="text-[11px] text-slate-500">{t('logs.archiveDesc')}</p>
            <form onSubmit={(e) => void handleSearchArchive(e)} className="flex flex-wrap items-center gap-2">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="text"
                  value={archiveQuery}
                  onChange={(e) => setArchiveQuery(e.target.value)}
                  placeholder={t('logs.archivePlaceholder')}
                  className="w-full pl-8 pr-10 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-xs text-slate-900"
                />
                <button
                  type="button"
                  onClick={() => setArchiveUseRegex((v) => !v)}
                  title="Toggle ReDoS-safe regex mode"
                  className={`absolute right-1.5 top-1/2 -translate-y-1/2 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold border cursor-pointer ${
                    archiveUseRegex
                      ? 'bg-slate-900 text-white border-slate-900'
                      : 'bg-slate-50 text-slate-500 border-slate-200 hover:text-slate-900'
                  }`}
                >
                  .*
                </button>
              </div>
              <select
                aria-label="Archive level filter"
                value={archiveLevel}
                onChange={(e) => setArchiveLevel(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-xs text-slate-700"
              >
                <option value="ALL">All levels</option>
                <option value="INFO">INFO</option>
                <option value="WARN">WARN</option>
                <option value="ERROR">ERROR</option>
              </select>
              <button
                type="submit"
                disabled={archiveBusy}
                className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                {archiveBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
                <span>{archiveBusy ? t('logs.archiveSearching') : t('logs.archiveSearch')}</span>
              </button>
            </form>

            {archiveError && (
              <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700 font-mono text-[11px] flex items-center gap-2">
                <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
                <span>{archiveError}</span>
              </div>
            )}

            {archiveResult ? (
              <div className="border border-slate-200 rounded-lg overflow-hidden">
                <div className="px-3 py-1.5 bg-slate-50 border-b border-slate-200 font-mono text-[10px] text-slate-500 flex items-center justify-between tabular-nums">
                  <span>{archiveResult.totalMatches ?? (Array.isArray(archiveResult.entries) ? archiveResult.entries.length : 0)} matches across {archiveResult.filesScanned ?? 0} .ndjson.gz shard(s)</span>
                  <span>ReDoS-Safe Engine</span>
                </div>
                {Array.isArray(archiveResult.entries) && archiveResult.entries.length > 0 ? (
                  <div className="divide-y divide-slate-100 max-h-44 overflow-y-auto font-mono text-[11px]">
                    {archiveResult.entries.slice(0, 30).map((entry, idx) => (
                      <div key={idx} className="px-3 py-1.5 flex flex-wrap items-start gap-2">
                        <span className="text-slate-400 tabular-nums shrink-0">{formatLogTime(entry.ts)}</span>
                        <span className={`px-1.5 py-0.2 rounded text-[10px] font-semibold border shrink-0 ${getLevelBadge(entry.level)}`}>
                          {entry.level}
                        </span>
                        {entry.releaseId && (
                          <span className="px-1.5 py-0.2 rounded bg-slate-100 border border-slate-200 text-slate-600 text-[10px] shrink-0">
                            {entry.releaseId}
                          </span>
                        )}
                        <span className="text-slate-800 break-words flex-1 min-w-0">{entry.message}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-3 text-center text-slate-400">0 archived matches found.</div>
                )}
              </div>
            ) : (
              <div className="text-[11px] text-slate-400">{t('logs.archiveEmpty')}</div>
            )}
          </div>
        )}
      </section>

      <div className="flex-1 rounded-xl bg-white border border-slate-200 flex flex-col overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2.5 bg-slate-50 border-b border-slate-200">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-slate-500" />
            <span className="text-xs font-semibold text-slate-800">Explorador de registros estructurados</span>
          </div>

          <div className="flex items-center gap-3 text-xs text-slate-500">
            {errorCount > 0 && (
              <button
                type="button"
                onClick={() => setSelectedLevel((l) => (l === 'error' ? 'all' : 'error'))}
                className="px-1.5 py-0.5 rounded bg-red-50 border border-red-200 text-red-700 font-mono text-[10px] font-semibold cursor-pointer tabular-nums"
              >
                {errorCount} ERR
              </button>
            )}
            {warnCount > 0 && (
              <button
                type="button"
                onClick={() => setSelectedLevel((l) => (l === 'warn' ? 'all' : 'warn'))}
                className="px-1.5 py-0.5 rounded bg-amber-50 border border-amber-200 text-amber-800 font-mono text-[10px] font-semibold cursor-pointer tabular-nums"
              >
                {warnCount} WARN
              </button>
            )}
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
              {filteredLogs.map((log) => {
                const jsonObj = tryParseJsonMessage(log.message);
                const fields = log.fields || jsonObj;
                const isExpanded = Boolean(expandedIds[log.id]);
                const fieldEntries = fields ? Object.entries(fields).slice(0, 5) : [];
                return (
                  <div
                    key={log.id}
                    className="hover:bg-slate-50 px-2 py-1.5 sm:py-1 rounded transition-colors"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-start gap-1 sm:gap-2.5">
                      <div className="flex items-center gap-2 shrink-0">
                        {jsonObj ? (
                          <button
                            type="button"
                            onClick={() => setExpandedIds((prev) => ({ ...prev, [log.id]: !prev[log.id] }))}
                            aria-label="Expandir JSON"
                            className="text-slate-400 hover:text-slate-700 cursor-pointer"
                          >
                            {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                          </button>
                        ) : (
                          <span className="w-3.5 hidden sm:inline-block" />
                        )}
                        <span className="text-slate-400 shrink-0 select-none w-16 tabular-nums">{formatLogTime(log.timestamp)}</span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border shrink-0 w-16 text-center ${getLevelBadge(log.level)}`}>
                          {log.level}
                        </span>
                        <span className="text-slate-500 shrink-0 font-medium w-16 truncate" title={log.pod}>
                          [{formatPodLabel(log.pod)}]
                        </span>
                      </div>
                      <div className="min-w-0 flex-1">
                        <span className="whitespace-pre-wrap break-words text-slate-800">{stripAnsi(log.message)}</span>
                        {fieldEntries.length > 0 && !isExpanded && (
                          <div className="flex flex-wrap items-center gap-1 mt-1">
                            {fieldEntries.map(([k, v]) => (
                              <button
                                key={k}
                                type="button"
                                onClick={() => setAttrFilter(`${k}=${String(v)}`)}
                                title={`Filtrar por ${k}=${String(v)}`}
                                className="px-1.5 py-0.2 rounded bg-slate-100 hover:bg-slate-200 text-slate-600 text-[10px] font-mono cursor-pointer"
                              >
                                {k}={String(v).slice(0, 28)}
                              </button>
                            ))}
                          </div>
                        )}
                        {jsonObj && isExpanded && (
                          <pre className="mt-1.5 p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-[11px] text-slate-700 overflow-x-auto">
                            {JSON.stringify(jsonObj, null, 2)}
                          </pre>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
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
