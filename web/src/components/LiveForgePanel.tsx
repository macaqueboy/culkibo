import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Zap,
  ShieldCheck,
  RotateCcw,
  Rocket,
  Copy,
  Check,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Radio,
  Terminal,
  Loader2,
  ChevronDown,
  ChevronRight,
  KeyRound,
  FolderOpen,
} from 'lucide-react';
import { api, type LiveSyncStatus, type LiveSyncRecentFrame, type LiveSyncFrameDiff } from '../lib/api';
import { liveEvents } from '../lib/liveEvents';
import { copyToClipboard } from '../lib/clipboard';
import { HelpTip } from './HelpTip';

interface LiveForgePanelProps {
  projectId: string;
  projectName: string;
  onNotify: (msg: string, type?: 'info' | 'success' | 'error') => void;
}

function formatBytes(bytes: number): string {
  if (!bytes) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatFrameTime(frame: LiveSyncRecentFrame & { appliedAt?: string }): string {
  const raw = frame.at || frame.appliedAt;
  if (!raw) return '—';
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleTimeString('es-ES');
}

export const LiveForgePanel: React.FC<LiveForgePanelProps> = ({ projectId, projectName, onNotify }) => {
  const [status, setStatus] = useState<LiveSyncStatus | null>(null);
  const [frames, setFrames] = useState<LiveSyncRecentFrame[]>([]);
  const [merkle, setMerkle] = useState<{ inSync: boolean; verifiedAgainstClient: boolean; serverDigest: string; fileCount: number } | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyAction, setBusyAction] = useState<'verify' | 'rollback' | 'promote' | 'token' | null>(null);
  const [cmdMode, setCmdMode] = useState<'local' | 'remote'>('local');
  const [copiedCmd, setCopiedCmd] = useState(false);
  const [tempToken, setTempToken] = useState<{ ticket: string; wsUrl: string; expiresAt: string } | null>(null);
  const [expandedSeq, setExpandedSeq] = useState<number | null>(null);
  const [frameDiffs, setFrameDiffs] = useState<Record<number, LiveSyncFrameDiff | null>>({});
  const [loadingDiffSeq, setLoadingDiffSeq] = useState<number | null>(null);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const loadStatus = useCallback(async () => {
    try {
      const s = await api.getSyncStatus(projectId);
      setStatus(s);
      if (Array.isArray(s.recentFrames)) setFrames(s.recentFrames);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  const scheduleLoadStatus = useCallback(() => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(() => {
      refreshTimerRef.current = null;
      void loadStatus();
    }, 250);
  }, [loadStatus]);

  useEffect(() => {
    let active = true;
    api.getSyncStatus(projectId)
      .then((s) => {
        if (!active) return;
        setStatus(s);
        if (Array.isArray(s.recentFrames)) setFrames(s.recentFrames);
      })
      .catch((err) => console.error(err))
      .finally(() => { if (active) setLoading(false); });

    const offApplied = liveEvents.onSyncApplied((ev) => {
      if (ev.projectId !== projectId) return;
      setFrames((prev) => [
        {
          seq: ev.seq,
          written: ev.written,
          deleted: ev.deleted,
          dedupSkipped: ev.dedupSkipped,
          applyMs: ev.applyMs,
          mode: ev.mode,
          reason: ev.reason,
          at: ev.timestamp || new Date().toISOString(),
        },
        ...prev,
      ].slice(0, 25));
      scheduleLoadStatus();
    });
    const offRollback = liveEvents.onSyncRollback((ev) => {
      if (ev.projectId !== projectId) return;
      scheduleLoadStatus();
    });
    const offClient = liveEvents.onSyncClient((ev) => {
      if (ev.projectId !== projectId) return;
      setStatus((prev) => (prev ? { ...prev, connectedClients: ev.connectedClients } : prev));
    });
    return () => {
      active = false;
      if (refreshTimerRef.current) {
        clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = null;
      }
      offApplied();
      offRollback();
      offClient();
    };
  }, [projectId, scheduleLoadStatus]);

  const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.port === '5173' ? '127.0.0.1:3030' : window.location.host;
  const syncCommand = cmdMode === 'local'
    ? `npx culkibo sync ${projectId}`
    : tempToken
      ? `npx culkibo sync ${projectId} --url ${tempToken.wsUrl} --ticket ${tempToken.ticket}`
      : `npx culkibo sync ${projectId} --url ${wsProto}//${host}/ws/sync --token TU_CULKIBO_TOKEN`;

  const displaySyncCommand = cmdMode === 'remote' && tempToken
    ? `npx culkibo sync ${projectId} --url ${tempToken.wsUrl} --ticket ${tempToken.ticket.slice(0, 8)}••••••••`
    : syncCommand;

  const handleGenerateSyncToken = async () => {
    setBusyAction('token');
    try {
      const res = await api.createSyncToken(projectId);
      setTempToken({ ticket: res.ticket, wsUrl: res.wsUrl, expiresAt: res.expiresAt });
      setCmdMode('remote');
      onNotify('Ticket temporal de Live Sync generado (caduca en 30 s)', 'success');
    } catch (err: any) {
      onNotify(err?.message || 'No se pudo generar el token temporal', 'error');
    } finally {
      setBusyAction(null);
    }
  };

  const toggleFrameDiff = async (seq: number) => {
    if (expandedSeq === seq) {
      setExpandedSeq(null);
      return;
    }
    setExpandedSeq(seq);
    if (frameDiffs[seq] !== undefined) return;
    setLoadingDiffSeq(seq);
    try {
      const diff = await api.getSyncFrameDiff(projectId, seq);
      setFrameDiffs((prev) => ({ ...prev, [seq]: diff }));
    } catch {
      setFrameDiffs((prev) => ({ ...prev, [seq]: null }));
    } finally {
      setLoadingDiffSeq(null);
    }
  };

  const handleCopyCmd = async () => {
    const ok = await copyToClipboard(syncCommand);
    if (!ok) {
      onNotify('No se pudo copiar al portapapeles', 'error');
      return;
    }
    setCopiedCmd(true);
    window.setTimeout(() => setCopiedCmd(false), 1800);
    onNotify('Comando de sincronización copiado', 'success');
  };

  const handleVerify = async () => {
    setBusyAction('verify');
    try {
      const res = await api.verifyProjectSync(projectId);
      const count = res.fileCount || 0;
      const verifiedAgainstClient = Boolean(res.verifiedAgainstClient);
      setMerkle({
        inSync: Boolean(res.inSync),
        verifiedAgainstClient,
        serverDigest: res.serverDigest || '',
        fileCount: count,
      });
      onNotify(
        verifiedAgainstClient
          ? (res.inSync
            ? `Integridad cliente↔servidor verificada (${count} ${count === 1 ? 'archivo' : 'archivos'})`
            : `Se detectaron diferencias al comprobar ${count} ${count === 1 ? 'archivo' : 'archivos'}`)
          : `Árbol Merkle del servidor calculado (${count} ${count === 1 ? 'archivo' : 'archivos'})`,
        res.inSync ? 'success' : 'info'
      );
    } catch (err: any) {
      onNotify(err?.message || 'Error al verificar integridad', 'error');
    } finally {
      setBusyAction(null);
    }
  };

  const handleRollback = async () => {
    setBusyAction('rollback');
    try {
      const res = await api.rollbackProjectSync(projectId, 1);
      const count = (res.restoredFiles || []).length;
      onNotify(
        `Reversión aplicada en ${res.durationMs ?? '<1'} ms (${count} ${count === 1 ? 'archivo' : 'archivos'})`,
        'success'
      );
      await loadStatus();
    } catch (err: any) {
      onNotify(err?.message || 'No hay cambios recientes para revertir', 'error');
    } finally {
      setBusyAction(null);
    }
  };

  const handlePromote = async () => {
    setBusyAction('promote');
    try {
      const res = await api.promoteForge(projectId, { async: true });
      onNotify(
        res.promoted
          ? `${projectName} promocionado a producción sin cortes.`
          : 'Promoción encolada. Sigue el avance en tiempo real en la pestaña Despliegues.',
        'success'
      );
    } catch (err: any) {
      onNotify(err?.message || 'No se pudo promocionar a producción', 'error');
    } finally {
      setBusyAction(null);
    }
  };

  if (loading) {
    return (
      <div className="p-10 bg-white rounded-xl border border-slate-200 text-center text-xs text-slate-500 flex items-center justify-center gap-2">
        <Loader2 className="w-4 h-4 animate-spin" /> Cargando telemetría de sincronización…
      </div>
    );
  }

  const clientCount = status?.connectedClients || 0;
  const connected = clientCount > 0;
  const historyDepth = status?.historyDepth ?? 0;

  return (
    <div className="space-y-5">
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className={`w-9 h-9 rounded-lg flex items-center justify-center border shrink-0 ${
              connected ? 'bg-emerald-50 border-emerald-200 text-emerald-700' : 'bg-slate-100 border-slate-200 text-slate-600'
            }`}>
              <Zap className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold text-slate-900">Sincronización en vivo</h3>
                <HelpTip title="Cómo funciona Live Sync">
                  <p>Cada vez que guardas en tu editor local, solo viajan los archivos cambiados por WebSocket binario en menos de 10 ms.</p>
                  <p>Cuando te guste el resultado, pulsa <strong>Promocionar a producción</strong> para compilar exactamente lo que probaste sin hacer git push.</p>
                </HelpTip>
                <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium border tabular-nums ${
                  connected
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : 'bg-slate-100 text-slate-600 border-slate-200'
                }`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-emerald-500' : 'bg-slate-400'}`} />
                  {connected
                    ? `${clientCount} ${clientCount === 1 ? 'cliente conectado' : 'clientes conectados'}`
                    : 'Esperando conexión'}
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                Cada cambio en tu editor o agente de IA llega al servidor por tramas binarias WebSocket, con comprobación Merkle y reversión en memoria.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap shrink-0">
            <button
              type="button"
              onClick={handleVerify}
              disabled={busyAction !== null}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-700 cursor-pointer disabled:opacity-50"
            >
              {busyAction === 'verify' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5 text-slate-600" />}
              <span>Verificar Merkle</span>
            </button>
            <button
              type="button"
              onClick={handleRollback}
              disabled={busyAction !== null || historyDepth === 0}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-700 cursor-pointer disabled:opacity-50"
            >
              {busyAction === 'rollback' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RotateCcw className="w-3.5 h-3.5 text-slate-600" />}
              <span>Revertir último paso</span>
            </button>
            <button
              type="button"
              onClick={handlePromote}
              disabled={busyAction !== null}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50"
            >
              {busyAction === 'promote' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Rocket className="w-3.5 h-3.5" />}
              <span>Promocionar a producción</span>
            </button>
          </div>
        </div>

        {/* Métricas reales */}
        <div className="bg-slate-50/60 border border-slate-200 rounded-xl grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-slate-200 text-xs">
          <div className="p-3.5">
            <div className="text-slate-500">Latencia p50 / p95</div>
            <div className="font-mono font-semibold text-slate-900 text-sm mt-1 tabular-nums">
              {status?.latencyMs?.p50 != null ? `${status.latencyMs.p50} / ${status.latencyMs.p95} ms` : '—'}
            </div>
          </div>
          <div className="p-3.5">
            <div className="text-slate-500">Envíos aplicados</div>
            <div className="font-mono font-semibold text-slate-900 text-sm mt-1 tabular-nums">
              {status?.framesApplied ?? 0}
            </div>
          </div>
          <div className="p-3.5">
            <div className="text-slate-500">Archivos sincronizados</div>
            <div className="font-mono font-semibold text-slate-900 text-sm mt-1 tabular-nums">
              {status?.filesWritten ?? 0}{' '}
              <span className="text-xs font-normal text-slate-400">({formatBytes(status?.bytesSynced || 0)})</span>
            </div>
          </div>
          <div className="p-3.5">
            <div className="text-slate-500">Historial de reversión</div>
            <div className="font-mono font-semibold text-slate-900 text-sm mt-1 tabular-nums">
              {historyDepth} {historyDepth === 1 ? 'paso' : 'pasos'}
            </div>
          </div>
        </div>

        {status?.targetDir && (
          <div className="flex flex-wrap items-center justify-between gap-2 px-3.5 py-2 rounded-lg bg-slate-50 border border-slate-200 text-[11px] text-slate-600">
            <span className="inline-flex items-center gap-1.5 min-w-0">
              <FolderOpen className="w-3.5 h-3.5 text-slate-400 shrink-0" />
              <span className="text-slate-500">Carpeta de destino en servidor:</span>
              <code className="font-mono text-slate-800 truncate">{status.targetDir}</code>
            </span>
            {Array.isArray(status.clients) && status.clients.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5">
                {status.clients.map((c, i) => (
                  <span key={c.id || i} className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-800 font-mono text-[10px]">
                    {c.clientName || 'CLI'}{c.sourceDir ? ` · ${c.sourceDir}` : ''}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        {merkle && (
          <div
            className={`p-3.5 rounded-xl border text-xs flex items-center justify-between gap-3 flex-wrap ${
              merkle.inSync
                ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
                : 'bg-amber-50 border-amber-200 text-amber-900'
            }`}
          >
            <div className="flex items-center gap-2">
              {merkle.inSync ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
              )}
              <span>
                {merkle.verifiedAgainstClient
                  ? (merkle.inSync ? 'Integridad cliente↔servidor verificada' : 'Diferencias detectadas')
                  : 'Árbol Merkle del servidor calculado'} ({merkle.fileCount}{' '}
                {merkle.fileCount === 1 ? 'archivo' : 'archivos'})
              </span>
            </div>
            <span className="font-mono text-[11px] bg-white px-2 py-0.5 rounded border border-slate-200 truncate max-w-xs">
              Merkle: {merkle.serverDigest.slice(0, 20)}…
            </span>
          </div>
        )}

        {/* Comando CLI */}
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <span className="text-xs font-medium text-slate-800 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-slate-500" />
              Conecta tu carpeta local con este servidor:
            </span>
            <div className="flex items-center gap-2 flex-wrap">
              <button
                type="button"
                onClick={() => void handleGenerateSyncToken()}
                disabled={busyAction !== null}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-white hover:bg-slate-100 border border-slate-200 text-[11px] font-medium text-slate-700 cursor-pointer disabled:opacity-50"
              >
                {busyAction === 'token' ? <Loader2 className="w-3 h-3 animate-spin" /> : <KeyRound className="w-3 h-3 text-slate-500" />}
                <span>{tempToken ? 'Renovar ticket' : 'Generar ticket temporal'}</span>
              </button>
              <div className="flex items-center gap-1 bg-white p-0.5 rounded-lg border border-slate-200 text-[11px]">
                <button
                  type="button"
                  onClick={() => setCmdMode('local')}
                  className={`px-2.5 py-1 rounded-md font-medium cursor-pointer ${cmdMode === 'local' ? 'bg-slate-900 text-white' : 'text-slate-600'}`}
                >
                  Este equipo
                </button>
                <button
                  type="button"
                  onClick={() => setCmdMode('remote')}
                  className={`px-2.5 py-1 rounded-md font-medium cursor-pointer ${cmdMode === 'remote' ? 'bg-slate-900 text-white' : 'text-slate-600'}`}
                >
                  Servidor remoto (VPS)
                </button>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 bg-white border border-slate-200 rounded-lg px-3 py-2">
            <code className="flex-1 text-xs font-mono text-slate-800 overflow-x-auto whitespace-nowrap">{displaySyncCommand}</code>
            <button
              type="button"
              onClick={() => void handleCopyCmd()}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-slate-100 hover:bg-slate-200 text-xs font-medium text-slate-700 cursor-pointer shrink-0"
            >
              {copiedCmd ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedCmd ? 'Copiado' : 'Copiar'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Historial de envíos en vivo con inspector de diff */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="px-5 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-800">
            <Radio className="w-3.5 h-3.5 text-slate-500" />
            <span>Últimos envíos recibidos (haz clic para ver diff)</span>
          </div>
          <button
            type="button"
            aria-label="Actualizar historial de sincronización"
            onClick={() => void loadStatus()}
            className="p-1.5 rounded-lg text-slate-500 hover:text-slate-900 hover:bg-slate-200/70 cursor-pointer"
            title="Actualizar"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        {frames.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500 space-y-1">
            <p className="font-medium text-slate-700">Todavía no ha llegado ningún envío en vivo.</p>
            <p>Ejecuta el comando de arriba en tu carpeta de código y guarda cualquier archivo para verlo aquí al instante.</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-100 text-xs">
            {frames.map((f, idx) => {
              const isOpen = expandedSeq === f.seq;
              const diff = frameDiffs[f.seq];
              return (
                <div key={`${f.seq}-${f.at || idx}`}>
                  <button
                    type="button"
                    onClick={() => void toggleFrameDiff(f.seq)}
                    className="w-full px-5 py-3 flex items-center justify-between gap-3 hover:bg-slate-50/70 text-left cursor-pointer"
                  >
                    <div className="flex items-center gap-2.5 min-w-0 flex-wrap">
                      {isOpen ? <ChevronDown className="w-3.5 h-3.5 text-slate-400 shrink-0" /> : <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />}
                      <span className="font-mono font-semibold text-slate-800 bg-slate-100 border border-slate-200 px-2 py-0.5 rounded tabular-nums">
                        #{f.seq}
                      </span>
                      <span className="text-slate-700 tabular-nums">
                        <strong>{f.written}</strong> escritos · <strong>{f.deleted}</strong> borrados · {f.dedupSkipped} sin cambios
                      </span>
                      <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200 text-[10px] font-medium">
                        {f.mode === 'path_b_hot' ? 'En caliente' : f.mode === 'path_c_restart' ? 'Reinicio' : f.mode}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 shrink-0 font-mono text-slate-500 tabular-nums">
                      <span className="text-emerald-700 font-medium">{f.applyMs} ms</span>
                      <span>{formatFrameTime(f)}</span>
                    </div>
                  </button>
                  {isOpen && (
                    <div className="px-5 pb-4 pt-2 bg-slate-50/70 border-t border-slate-100 space-y-2.5">
                      {loadingDiffSeq === f.seq ? (
                        <div className="text-slate-500 flex items-center gap-1.5 py-2">
                          <Loader2 className="w-3.5 h-3.5 animate-spin" /> Cargando diferencias del frame #{f.seq}…
                        </div>
                      ) : diff && Array.isArray(diff.files) && diff.files.length > 0 ? (
                        diff.files.map((file) => (
                          <div key={file.path} className="bg-white border border-slate-200 rounded-lg overflow-hidden">
                            <div className="px-3 py-1.5 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-2 font-mono text-[11px]">
                              <span className="text-slate-800 truncate">{file.path}</span>
                              <span className="text-slate-500 shrink-0">{file.action}</span>
                            </div>
                            {file.diff ? (
                              <pre className="p-3 text-[11px] font-mono text-slate-700 overflow-x-auto max-h-56 leading-relaxed whitespace-pre">
                                {file.diff}
                              </pre>
                            ) : (
                              <div className="px-3 py-2 text-[11px] text-slate-400">
                                {file.binary ? 'Archivo binario sincronizado' : 'Sin diff textual disponible en memoria.'}
                              </div>
                            )}
                          </div>
                        ))
                      ) : (
                        <div className="text-slate-500 py-1">
                          Este frame ya salió de la ventana de memoria de diffs o no tuvo cambios de contenido.
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
