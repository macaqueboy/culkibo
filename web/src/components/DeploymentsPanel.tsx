import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Rocket,
  RotateCcw,
  Square,
  Play,
  GitCommit,
  GitBranch,
  Clock,
  AlertTriangle,
  Terminal,
  ChevronDown,
  ChevronRight,
  Globe,
  Package,
  CheckCircle2,
  XCircle,
  Loader2,
  Undo2,
  Copy,
  Check,
  Activity,
  CalendarClock,
  Eye,
  Plus,
  Trash2,
  ExternalLink,
  RefreshCw,
  X,
} from 'lucide-react';
import {
  api,
  type Deployment,
  type DeployStatus,
  type DeployGitInfo,
  type DeployLogLine,
  type DeployStrategyPreview,
  type CronJobItem,
  type CronRunItem,
  type PreviewDeploymentItem,
} from '../lib/api';
import { deployStream } from '../lib/deployStream';
import { liveEvents } from '../lib/liveEvents';
import { copyToClipboard } from '../lib/clipboard';
import { Modal } from './Modal';
import { HelpTip } from './HelpTip';

interface Props {
  projectId: string;
  projectName: string;
  gitBranch: string;
  onNotify: (msg: string, type?: 'info' | 'success' | 'error') => void;
}

const FASES: Record<string, { etiqueta: string; progreso: number; tono: string; punto: string }> = {
  pendiente:     { etiqueta: 'Pendiente',     progreso: 5,   tono: 'text-slate-600 bg-slate-100 border-slate-200',       punto: 'bg-slate-400' },
  en_cola:       { etiqueta: 'En cola',       progreso: 8,   tono: 'text-amber-800 bg-amber-50 border-amber-200',        punto: 'bg-amber-500 animate-pulse' },
  sincronizando: { etiqueta: 'Sincronizando', progreso: 15,  tono: 'text-slate-700 bg-slate-100 border-slate-200',       punto: 'bg-slate-600 animate-pulse' },
  construyendo:  { etiqueta: 'Construyendo',  progreso: 45,  tono: 'text-amber-800 bg-amber-50 border-amber-200',        punto: 'bg-amber-500 animate-pulse' },
  arrancando:    { etiqueta: 'Arrancando',    progreso: 65,  tono: 'text-amber-800 bg-amber-50 border-amber-200',        punto: 'bg-amber-500 animate-pulse' },
  verificando:   { etiqueta: 'Verificando',   progreso: 80,  tono: 'text-slate-700 bg-slate-100 border-slate-200',       punto: 'bg-slate-600 animate-pulse' },
  promocionando: { etiqueta: 'Promocionando', progreso: 92,  tono: 'text-slate-700 bg-slate-100 border-slate-200',       punto: 'bg-slate-600 animate-pulse' },
  drenando:      { etiqueta: 'Drenando',      progreso: 97,  tono: 'text-slate-700 bg-slate-100 border-slate-200',       punto: 'bg-slate-600 animate-pulse' },
  activo:        { etiqueta: 'Activo',        progreso: 100, tono: 'text-emerald-700 bg-emerald-50 border-emerald-200',  punto: 'bg-emerald-500' },
  fallido:       { etiqueta: 'Fallido',       progreso: 100, tono: 'text-red-700 bg-red-50 border-red-200',              punto: 'bg-red-500' },
  cancelado:     { etiqueta: 'Cancelado',     progreso: 0,   tono: 'text-slate-600 bg-slate-100 border-slate-200',       punto: 'bg-slate-400' },
  inactivo:      { etiqueta: 'Inactivo',      progreso: 0,   tono: 'text-slate-600 bg-slate-100 border-slate-200',       punto: 'bg-slate-400' },
};

const EN_CURSO = new Set(['pendiente', 'en_cola', 'sincronizando', 'construyendo', 'arrancando', 'verificando', 'promocionando', 'drenando']);

function diagnoseFailureHint(errText: string): string {
  const s = (errText || '').toLowerCase();
  if (s.includes('137') || s.includes('oom') || s.includes('out of memory')) {
    return 'El proceso superó el límite de RAM del contenedor (código 137 / OOM). Sube el límite de memoria en Configuración y vuelve a desplegar.';
  }
  if (s.includes('health') || s.includes('salud') || s.includes('econnrefused') || s.includes('puerto')) {
    return 'El contenedor arrancó pero no respondió en el puerto o ruta de salud esperados. Comprueba que la app escuche en 0.0.0.0:$PORT.';
  }
  if (s.includes('auth') || s.includes('repository not found') || s.includes('permission denied') || s.includes('403')) {
    return 'Error de acceso al repositorio Git. Verifica que tu token de GitHub en Ajustes tenga permisos de lectura sobre el repositorio.';
  }
  if (s.includes('enoent') || s.includes('dockerfile') || s.includes('build')) {
    return 'Error durante la fase de compilación. Revisa las dependencias, versión de Node/runtime o el comando de compilación en Configuración.';
  }
  return 'Revisa el registro de construcción o copia el diagnóstico para resolverlo en segundos con tu agente de IA.';
}

function fase(estado: string) {
  return FASES[estado] || { etiqueta: estado, progreso: 50, tono: 'text-slate-600 bg-slate-100 border-slate-200', punto: 'bg-slate-400' };
}

function translateContainerStatus(status: string): string {
  const s = (status || '').toLowerCase();
  if (s === 'running') return 'en ejecución';
  if (s === 'exited' || s === 'stopped') return 'detenido';
  if (s === 'restarting') return 'reiniciando';
  if (s === 'created') return 'creado';
  if (s === 'paused') return 'pausado';
  return status;
}

function translateHealth(health: string): string {
  const h = (health || '').toLowerCase();
  if (h === 'healthy') return 'saludable';
  if (h === 'unhealthy') return 'con fallos';
  if (h === 'starting') return 'arrancando';
  return health;
}

function formatTrigger(trigger?: string): string {
  if (trigger === 'webhook' || trigger === 'github') return 'Webhook GitHub';
  if (trigger === 'gitlab') return 'Webhook GitLab';
  if (trigger === 'gitea') return 'Webhook Gitea';
  if (trigger === 'bitbucket') return 'Webhook Bitbucket';
  if (trigger === 'deploy_hook') return 'Deploy Hook CI/CD';
  if (trigger === 'forge_promote') return 'Promoción en vivo';
  if (trigger === 'mcp') return 'Agente IA (MCP)';
  if (trigger === 'rollback') return 'Reversión';
  return 'Manual';
}

function formatFecha(iso: string | null | undefined): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('es-ES', { dateStyle: 'short', timeStyle: 'short' });
}

function formatDuracion(ms: number | null | undefined): string {
  if (ms == null) return '—';
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)} s`;
  const m = Math.floor(s / 60);
  return `${m} min ${Math.round(s - m * 60)} s`;
}

const COLOR_NIVEL: Record<string, string> = {
  ERROR: 'text-red-600',
  WARN: 'text-amber-700',
  SUCCESS: 'text-emerald-600',
  INFO: 'text-slate-500',
};

const Commit: React.FC<{ git: DeployGitInfo | null; ramaPorDefecto?: string }> = ({ git, ramaPorDefecto }) => {
  if (!git || !git.shortCommit) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-slate-400">
        <GitCommit className="w-3.5 h-3.5 shrink-0" />
        Sin commit registrado
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-2 min-w-0 text-xs text-slate-600">
      <span className="inline-flex items-center gap-1 shrink-0">
        <GitBranch className="w-3.5 h-3.5 text-slate-400" />
        <span className="font-medium">{git.branch || ramaPorDefecto || 'main'}</span>
      </span>
      <span className="font-mono bg-slate-100 border border-slate-200 rounded px-1.5 py-0.5 shrink-0">{git.shortCommit}</span>
      {git.subject && <span className="truncate text-slate-500" title={git.subject}>{git.subject}</span>}
      {git.author && <span className="shrink-0 text-slate-400">· {git.author}</span>}
    </span>
  );
};

export const DeploymentsPanel: React.FC<Props> = ({ projectId, projectName, gitBranch, onNotify }) => {
  const [estado, setEstado] = useState<DeployStatus | null>(null);
  const [strategyPreview, setStrategyPreview] = useState<DeployStrategyPreview | null>(null);
  const [deployQueue, setDeployQueue] = useState<{ maxConcurrentBuilds: number; activeBuilds: number; queuedBuilds: Array<{ position: number; projectId: string; deploymentId: string; waitingMs: number }> } | null>(null);
  const [historial, setHistorial] = useState<Deployment[]>([]);
  const [cargando, setCargando] = useState(true);
  const [ocupado, setOcupado] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedLogs, setCopiedLogs] = useState(false);

  const [visorId, setVisorId] = useState<string | null>(null);
  const [visorEstado, setVisorEstado] = useState<string>('inactivo');
  const [abierto, setAbierto] = useState<string | null>(null);
  const [confirmarRollback, setConfirmarRollback] = useState(false);
  const [subTab, setSubTab] = useState<'deploys' | 'runtime' | 'crons' | 'previews'>('deploys');

  // Runtime stats, logs & safe exec
  const [runtimeStats, setRuntimeStats] = useState<any>(null);
  const [runtimeLogs, setRuntimeLogs] = useState<string>('');
  const [runtimeLoading, setRuntimeLoading] = useState(false);
  const [execCmd, setExecCmd] = useState('');
  const [execBusy, setExecBusy] = useState(false);
  const [execResult, setExecResult] = useState<{ exitCode: number; stdout: string; stderr: string; durationMs: number } | null>(null);

  // Cron Jobs
  const [crons, setCrons] = useState<CronJobItem[]>([]);
  const [cronFormOpen, setCronFormOpen] = useState(false);
  const [cronForm, setCronForm] = useState({ name: '', schedule: '0 3 * * *', command: '', timeoutSec: 120 });
  const [cronBusyId, setCronBusyId] = useState<string | null>(null);
  const [cronRunsOpenId, setCronRunsOpenId] = useState<string | null>(null);
  const [cronRuns, setCronRuns] = useState<Record<string, CronRunItem[]>>({});

  // Preview Deployments
  const [previews, setPreviews] = useState<PreviewDeploymentItem[]>([]);
  const [previewBranch, setPreviewBranch] = useState('');
  const [previewPr, setPreviewPr] = useState('');
  const [previewBusy, setPreviewBusy] = useState(false);
  const [previewLogKey, setPreviewLogKey] = useState<string | null>(null);
  const [previewLogText, setPreviewLogText] = useState('');

  const [detenidoOptimista, setDetenidoOptimista] = useState<boolean | null>(null);
  const [deshacerParada, setDeshacerParada] = useState(false);
  const temporizadorDeshacer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const consolaRef = useRef<HTMLDivElement | null>(null);
  const finConsolaRef = useRef<HTMLDivElement | null>(null);
  const bufferRef = useRef<DeployLogLine[]>([]);
  const lineasRef = useRef<DeployLogLine[]>([]);
  const frameRef = useRef<number | null>(null);
  const autoScrollRef = useRef(true);
  const [, forzarPintado] = useState(0);

  const cargar = useCallback(async (conSpinner = false) => {
    if (conSpinner) setCargando(true);
    try {
      const [st, hist, strat, q] = await Promise.all([
        api.getDeployStatus(projectId),
        api.getDeployments(projectId, 20),
        api.getDeployStrategy(projectId).catch(() => null),
        api.getDeployQueue().catch(() => null),
      ]);
      setEstado(st);
      setHistorial(hist.deployments);
      if (strat) setStrategyPreview(strat);
      if (q) setDeployQueue(q);
      setError(null);
      setDetenidoOptimista(null);
      if (!visorId && hist.deployments.length > 0) {
        setVisorId(hist.deployments[0].id);
        setVisorEstado(hist.deployments[0].status);
      } else if (!st.inProgress && hist.deployments.length === 0) {
        setVisorEstado('inactivo');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al leer el estado del despliegue');
    } finally {
      setCargando(false);
    }
  }, [projectId, visorId]);

  useEffect(() => {
    setVisorId(null);
    setVisorEstado('inactivo');
    lineasRef.current = [];
    bufferRef.current = [];
    void cargar(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  useEffect(() => () => {
    if (frameRef.current != null) cancelAnimationFrame(frameRef.current);
    if (temporizadorDeshacer.current) clearTimeout(temporizadorDeshacer.current);
  }, []);

  const programarVolcado = useCallback(() => {
    if (frameRef.current != null) return;
    frameRef.current = requestAnimationFrame(() => {
      frameRef.current = null;
      if (bufferRef.current.length === 0) return;
      const siguientes = lineasRef.current.concat(bufferRef.current);
      bufferRef.current = [];
      lineasRef.current = siguientes.length > 3000 ? siguientes.slice(siguientes.length - 3000) : siguientes;
      forzarPintado((n) => n + 1);
      if (autoScrollRef.current && finConsolaRef.current) {
        finConsolaRef.current.scrollIntoView({ block: 'end' });
      }
    });
  }, []);

  useEffect(() => {
    return deployStream.onLog((linea) => {
      if (linea.projectId !== projectId) return;
      if (visorId && linea.deploymentId !== visorId) return;
      bufferRef.current.push({ at: linea.at, level: linea.level, message: linea.message });
      programarVolcado();
    });
  }, [projectId, visorId, programarVolcado]);

  useEffect(() => {
    return deployStream.onEvent((evento) => {
      if (evento.projectId !== projectId) return;
      if (!visorId || evento.deploymentId !== visorId) {
        if (EN_CURSO.has(evento.status)) {
          lineasRef.current = [];
          bufferRef.current = [];
          setVisorId(evento.deploymentId);
        }
      }
      setVisorEstado(evento.status);
      if (!EN_CURSO.has(evento.status)) {
        if (evento.status === 'activo') onNotify(`Despliegue completado en ${projectName}`, 'success');
        if (evento.status === 'fallido') onNotify(`Despliegue fallido en ${projectName}: ${evento.error || 'sin detalle'}`, 'error');
        void cargar();
      }
    });
  }, [projectId, projectName, visorId, cargar, onNotify]);

  const enCurso = EN_CURSO.has(visorEstado) || Boolean(estado?.inProgress);

  const verLogsDe = async (deployment: Deployment) => {
    setVisorId(deployment.id);
    setVisorEstado(deployment.status);
    lineasRef.current = [];
    bufferRef.current = [];
    forzarPintado((n) => n + 1);
    try {
      const completo = await api.getDeployment(projectId, deployment.id);
      lineasRef.current = completo.logLines || [];
      forzarPintado((n) => n + 1);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudieron cargar los registros', 'error');
    }
  };

  const desplegar = async () => {
    const prevId = visorId;
    const prevStatus = visorEstado;
    setOcupado('desplegar');
    lineasRef.current = [];
    bufferRef.current = [];
    setVisorId(null);
    setVisorEstado('pendiente');
    try {
      await api.startDeploy(projectId);
      onNotify('Despliegue iniciado', 'info');
      await cargar();
    } catch (err) {
      setVisorId(prevId);
      setVisorEstado(prevStatus);
      onNotify(err instanceof Error ? err.message : 'No se pudo iniciar el despliegue', 'error');
    } finally {
      setOcupado(null);
    }
  };

  const loadRuntime = useCallback(async () => {
    setRuntimeLoading(true);
    try {
      const [st, lg] = await Promise.all([
        api.getRuntimeStats(projectId).catch(() => null),
        api.getRuntimeLogs(projectId, { tail: 200 }).catch(() => null),
      ]);
      setRuntimeStats(st);
      setRuntimeLogs(lg?.output || (Array.isArray(lg?.lines) ? lg.lines.join('\n') : '') || '');
    } finally {
      setRuntimeLoading(false);
    }
  }, [projectId]);

  const loadCrons = useCallback(async () => {
    try {
      const res = await api.getProjectCrons(projectId);
      setCrons(res.jobs || []);
    } catch {
      // ignorar
    }
  }, [projectId]);

  const loadPreviews = useCallback(async () => {
    try {
      const res = await api.getProjectPreviews(projectId);
      setPreviews(res.previews || []);
    } catch {
      // ignorar
    }
  }, [projectId]);

  useEffect(() => {
    void loadCrons();
    void loadPreviews();
    const offCron = liveEvents.onCronRun((ev) => {
      if (ev.projectId !== projectId) return;
      void loadCrons();
      if (ev.jobId) {
        setCronRuns((prev) => ({
          ...prev,
          [ev.jobId]: [ev.run as CronRunItem, ...(prev[ev.jobId] || [])].slice(0, 20),
        }));
      }
    });
    const offPreview = liveEvents.onPreviewEvent((ev) => {
      if (ev.projectId !== projectId) return;
      void loadPreviews();
    });
    return () => {
      offCron();
      offPreview();
    };
  }, [projectId, loadCrons, loadPreviews]);

  useEffect(() => {
    if (subTab === 'runtime') void loadRuntime();
  }, [subTab, loadRuntime]);

  const cancelarBuild = async () => {
    setOcupado('cancelar');
    try {
      const res = await api.cancelDeploy(projectId);
      onNotify(res.cancelled ? 'Construcción cancelada correctamente' : (res.reason || 'No había ninguna construcción activa'), 'info');
      await cargar();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudo cancelar el despliegue', 'error');
    } finally {
      setOcupado(null);
    }
  };

  const revertir = async (targetDeploymentId?: string) => {
    setConfirmarRollback(false);
    setOcupado('revertir');
    try {
      const resultado = await api.rollbackDeploy(projectId, targetDeploymentId ? { targetDeploymentId } : {});
      if (resultado.status === 'fallido') {
        onNotify(`No se pudo revertir: ${resultado.error || 'sin detalle'}`, 'error');
      } else {
        onNotify(`Revertido a ${resultado.git?.shortCommit || resultado.imageTag}`, 'success');
      }
      await cargar();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudo revertir', 'error');
    } finally {
      setOcupado(null);
    }
  };

  const alternarServicio = async (detener: boolean) => {
    setDetenidoOptimista(detener);
    setOcupado('servicio');
    try {
      const resultado = detener ? await api.stopDeploy(projectId) : await api.resumeDeploy(projectId);
      const ok = detener ? (resultado as any).stopped : (resultado as any).started;
      if (!ok) {
        setDetenidoOptimista(null);
        onNotify((resultado as any).error || (resultado as any).reason || 'La acción no se pudo completar', 'error');
      } else {
        onNotify(detener ? 'Servicio detenido y ruta retirada' : 'Servicio reanudado y ruta repuesta', 'success');
        if (detener) {
          setDeshacerParada(true);
          if (temporizadorDeshacer.current) clearTimeout(temporizadorDeshacer.current);
          temporizadorDeshacer.current = setTimeout(() => setDeshacerParada(false), 12000);
        } else {
          setDeshacerParada(false);
        }
      }
      await cargar();
    } catch (err) {
      setDetenidoOptimista(null);
      onNotify(err instanceof Error ? err.message : 'La acción no se pudo completar', 'error');
    } finally {
      setOcupado(null);
    }
  };

  const handleCopyBuildLogs = async () => {
    const tail = lineasRef.current.slice(-60);
    const body = tail.map((l) => `[${l.level}] ${l.message}`).join('\n');
    const prompt = [
      `Estoy depurando un despliegue de "${projectName}" en Culkibo (${visorId || 'último despliegue'}).`,
      'Últimas líneas de la construcción:',
      '```log',
      body || '(sin líneas)',
      '```',
      '¿Cuál es el error y cómo lo soluciono?',
    ].join('\n');
    const ok = await copyToClipboard(prompt);
    if (ok) {
      setCopiedLogs(true);
      onNotify('Registros de construcción copiados para IA', 'success');
      window.setTimeout(() => setCopiedLogs(false), 2000);
    }
  };

  const actual = estado?.current || null;
  const anterior = estado?.previous || null;
  const contenedorParado = estado?.containerState ? estado.containerState.status !== 'running' : false;
  const parado = detenidoOptimista != null ? detenidoOptimista : contenedorParado;
  const lineas = lineasRef.current;

  if (cargando) {
    return (
      <div className="bg-white p-10 rounded-xl border border-slate-200 text-center text-slate-500 text-xs">
        Cargando el estado del despliegue…
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {estado?.docker && !estado.docker.available && (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex items-start gap-3">
          <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
          <div className="text-xs min-w-0">
            <p className="font-semibold text-amber-900">Docker no está disponible</p>
            <p className="text-amber-800 mt-0.5">
              {estado.docker.reason || 'Desplegar a producción construye una imagen de contenedor y requiere Docker en ejecución.'}
            </p>
          </div>
        </div>
      )}

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-xs text-red-800">{error}</div>
      )}

      {/* Cola global de builds (semáforo anti-OOM) */}
      {deployQueue && (deployQueue.activeBuilds > 0 || deployQueue.queuedBuilds.length > 0) && (
        <div className="bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-700">
          <div className="flex items-center gap-2">
            <Loader2 className="w-3.5 h-3.5 animate-spin text-amber-600 shrink-0" />
            <span className="font-medium text-slate-900">Cola global de compilación</span>
            <span className="text-slate-500 tabular-nums">
              {deployQueue.activeBuilds}/{deployQueue.maxConcurrentBuilds} builds en curso
              {deployQueue.queuedBuilds.length > 0 ? ` · ${deployQueue.queuedBuilds.length} en espera` : ''}
            </span>
          </div>
          {(() => {
            const pos = deployQueue.queuedBuilds.find((b) => b.projectId === projectId)?.position;
            return pos ? (
              <span className="px-2 py-0.5 rounded-full bg-amber-50 text-amber-800 border border-amber-200 font-medium tabular-nums">
                Tu posición en cola: #{pos}
              </span>
            ) : null;
          })()}
        </div>
      )}

      {/* Banner de diagnóstico ante despliegue fallido */}
      {(() => {
        const failedDeploy =
          (visorId ? historial.find((d) => d.id === visorId && d.status === 'fallido') : null) ||
          (historial[0]?.status === 'fallido' && !enCurso ? historial[0] : null);
        if (!failedDeploy) return null;
        const errMsg = failedDeploy.error || 'La construcción o verificación de salud falló.';
        return (
          <div role="alert" className="bg-red-50 border border-red-200 rounded-xl p-4 flex flex-col sm:flex-row sm:items-start justify-between gap-3">
            <div className="flex items-start gap-2.5 min-w-0">
              <XCircle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
              <div className="text-xs min-w-0 space-y-1">
                <div className="font-semibold text-red-900">Último despliegue fallido</div>
                <p className="font-mono text-[11px] text-red-800 break-words">{errMsg}</p>
                <p className="text-red-700 leading-relaxed">{diagnoseFailureHint(errMsg)}</p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => void handleCopyBuildLogs()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-red-100/60 border border-red-200 text-red-800 text-xs font-medium shrink-0 self-start cursor-pointer"
            >
              {copiedLogs ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedLogs ? 'Copiado' : 'Copiar diagnóstico para IA'}</span>
            </button>
          </div>
        );
      })()}

      {/* Versión en producción */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="p-5 flex flex-col lg:flex-row lg:items-start gap-5">
          <div className="flex-1 min-w-0 space-y-3">
            <div className="flex items-center gap-2.5 flex-wrap">
              <h3 className="font-semibold text-slate-900 text-base flex items-center gap-2">
                <Rocket className="w-4 h-4 text-slate-600" /> Versión en producción
              </h3>
              {enCurso ? (
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${fase(visorEstado).tono}`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${fase(visorEstado).punto}`} />
                  {fase(visorEstado).etiqueta}
                </span>
              ) : actual ? (
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${
                  parado ? 'text-slate-600 bg-slate-100 border-slate-200' : 'text-emerald-700 bg-emerald-50 border-emerald-200'
                }`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${parado ? 'bg-slate-400' : 'bg-emerald-500'}`} />
                  {parado ? 'Detenido' : 'Sirviendo tráfico'}
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border text-slate-600 bg-slate-100 border-slate-200">
                  <span className="w-1.5 h-1.5 rounded-full bg-slate-400" /> Nunca desplegado
                </span>
              )}
              {estado?.queued && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs border text-slate-600 bg-slate-50 border-slate-200">
                  Hay otro commit en cola
                </span>
              )}
            </div>

            {actual ? (
              <div className="space-y-2 min-w-0">
                <Commit git={actual.git} ramaPorDefecto={gitBranch} />
                <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 text-xs text-slate-500 min-w-0">
                  <span className="inline-flex items-center gap-1.5 min-w-0">
                    <Package className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                    <span className="font-mono truncate" title={actual.imageTag}>{actual.imageTag}</span>
                  </span>
                  <span className="inline-flex items-center gap-1.5 tabular-nums">
                    <Clock className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                    Promocionada {formatFecha(actual.promotedAt)}
                  </span>
                  {actual.hostnames.length > 0 && (
                    <span className="inline-flex items-center gap-1.5 min-w-0">
                      <Globe className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                      <span className="truncate font-mono" title={actual.hostnames.join(', ')}>{actual.hostnames.join(', ')}</span>
                    </span>
                  )}
                  {estado?.containerState && (
                    <span className="inline-flex items-center gap-1.5">
                      Contenedor: <strong className="text-slate-700 font-medium">{translateContainerStatus(estado.containerState.status)}</strong>
                      {estado.containerState.health && estado.containerState.health !== 'sin-healthcheck' && (
                        <> · salud <strong className="text-slate-700 font-medium">{translateHealth(estado.containerState.health)}</strong></>
                      )}
                    </span>
                  )}
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                <p className="text-xs text-slate-500 max-w-prose leading-relaxed">
                  Este proyecto todavía no tiene una versión en producción. Al desplegar se usará la rama{' '}
                  <strong className="text-slate-700 font-mono">{gitBranch || 'main'}</strong>, se construirá la imagen, se verificará que responde y se cambiará el tráfico sin cortes.
                </p>
                {strategyPreview?.strategy && (
                  <div className="inline-flex flex-wrap items-center gap-2 text-[11px] bg-slate-50 border border-slate-200 rounded-lg px-2.5 py-1.5 text-slate-600">
                    <span>Estrategia detectada:</span>
                    <span className="font-medium text-slate-900">{strategyPreview.strategy.stack}</span>
                    <span>·</span>
                    <span className="font-mono">:{strategyPreview.strategy.containerPort}</span>
                    <span>·</span>
                    <span className="font-mono">{strategyPreview.strategy.healthPath}</span>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2 lg:justify-end shrink-0">
            <button
              type="button"
              onClick={desplegar}
              disabled={ocupado !== null || enCurso || estado?.docker?.available === false}
              className="inline-flex items-center gap-1.5 bg-slate-900 hover:bg-slate-800 text-white px-3.5 py-2 rounded-lg text-xs font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              {enCurso
                ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Desplegando…</>
                : <><Rocket className="w-3.5 h-3.5" /> Desplegar</>}
            </button>

            {enCurso && (
              <button
                type="button"
                onClick={() => void cancelarBuild()}
                disabled={ocupado === 'cancelar'}
                className="inline-flex items-center gap-1.5 bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 px-3 py-2 rounded-lg text-xs font-medium transition-colors disabled:opacity-50 cursor-pointer"
              >
                <X className="w-3.5 h-3.5" /> Cancelar build
              </button>
            )}

            <button
              type="button"
              onClick={() => setConfirmarRollback(true)}
              disabled={ocupado !== null || enCurso || !estado?.canRollback}
              title={estado?.canRollback ? 'Volver a la versión anterior' : 'No hay versión anterior disponible'}
              className="inline-flex items-center gap-1.5 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 px-3 py-2 rounded-lg text-xs font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5 text-slate-500" /> Revertir
            </button>

            <button
              type="button"
              onClick={() => void alternarServicio(!parado)}
              disabled={ocupado !== null || enCurso || !actual}
              className="inline-flex items-center gap-1.5 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 px-3 py-2 rounded-lg text-xs font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              {parado
                ? <><Play className="w-3.5 h-3.5 text-emerald-600" /> Reanudar</>
                : <><Square className="w-3.5 h-3.5 text-slate-500" /> Detener</>}
            </button>
          </div>
        </div>

        {enCurso && (
          <div className="h-1 bg-slate-100">
            <div
              className="h-1 bg-slate-900 transition-all duration-500 ease-out"
              style={{ width: `${fase(visorEstado).progreso}%` }}
            />
          </div>
        )}

        {deshacerParada && parado && (
          <div className="border-t border-slate-200 bg-slate-50 px-5 py-3 flex items-center justify-between gap-4">
            <span className="text-xs text-slate-600">
              Servicio detenido y ruta pública retirada. La imagen y el contenedor se conservan.
            </span>
            <button
              type="button"
              onClick={() => void alternarServicio(false)}
              disabled={ocupado !== null}
              className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-800 bg-white border border-slate-200 px-3 py-1.5 rounded-lg hover:bg-slate-50 disabled:opacity-50 shrink-0 cursor-pointer"
            >
              <Undo2 className="w-3.5 h-3.5" /> Deshacer
            </button>
          </div>
        )}
      </div>

      {/* Confirmación de rollback */}
      <Modal
        open={confirmarRollback}
        onClose={() => setConfirmarRollback(false)}
        title="Revertir a la versión anterior"
        subtitle="Se arrancará el contenedor anterior, se verificará su salud y se conmutará la ruta sin reconstruir."
        maxWidthClass="max-w-lg"
      >
        <div className="p-5 space-y-4">
          <div className="rounded-xl border border-slate-200 divide-y divide-slate-100 overflow-hidden">
            <div className="p-3.5 bg-slate-50/70">
              <div className="text-[11px] text-slate-400 mb-1">Ahora en producción</div>
              <Commit git={actual?.git || null} ramaPorDefecto={gitBranch} />
              <div className="font-mono text-[11px] text-slate-400 mt-1 truncate">{actual?.imageTag}</div>
            </div>
            <div className="p-3.5">
              <div className="text-[11px] text-slate-400 mb-1">Quedará en producción</div>
              <Commit git={anterior?.git || null} ramaPorDefecto={gitBranch} />
              <div className="font-mono text-[11px] text-slate-400 mt-1 truncate">{anterior?.imageTag}</div>
            </div>
          </div>

          <p className="text-xs text-slate-500 leading-relaxed">
            Las bases de datos y los volúmenes no se modifican: revertir cambia el código servido, no los datos.
          </p>

          <div className="flex justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={() => setConfirmarRollback(false)}
              className="text-xs font-medium text-slate-600 border border-slate-200 px-3.5 py-2 rounded-lg hover:bg-slate-50 cursor-pointer"
            >
              Cancelar
            </button>
            <button
              type="button"
              onClick={() => void revertir()}
              className="inline-flex items-center gap-1.5 text-xs font-medium bg-slate-900 text-white px-4 py-2 rounded-lg hover:bg-slate-800 cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Revertir a {anterior?.git?.shortCommit || anterior?.version || 'la versión anterior'}
            </button>
          </div>
        </div>
      </Modal>

      {/* Sub-navegación limpia: Despliegues / Contenedor / Cron / Previews */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="inline-flex items-center bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs overflow-x-auto no-scrollbar">
          {([
            { id: 'deploys', label: 'Build e historial', icon: Terminal, count: historial.length },
            { id: 'runtime', label: 'Contenedor en vivo', icon: Activity },
            { id: 'crons', label: 'Tareas Cron', icon: CalendarClock, count: crons.length },
            { id: 'previews', label: 'Vistas previas', icon: Eye, count: previews.length },
          ] as Array<{ id: 'deploys' | 'runtime' | 'crons' | 'previews'; label: string; icon: React.ComponentType<{ className?: string }>; count?: number }>).map((item) => {
            const Icon = item.icon;
            const active = subTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setSubTab(item.id)}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium whitespace-nowrap transition-colors cursor-pointer ${
                  active ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{item.label}</span>
                {typeof item.count === 'number' && item.count > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full bg-slate-100 text-slate-600 text-[10px] font-mono tabular-nums">
                    {item.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
        <HelpTip title="Producción, Cron y Previews" align="right">
          <p><strong>Contenedor en vivo:</strong> consulta CPU/RAM, logs reales del contenedor y ejecuta comandos puntuales (ej. migraciones).</p>
          <p><strong>Tareas Cron:</strong> programa scripts periódicos dentro del contenedor de producción.</p>
          <p><strong>Vistas previas:</strong> despliega ramas o PRs aislados con URL propia para probar antes de fusionar.</p>
        </HelpTip>
      </div>

      {subTab === 'deploys' && (
      <>
      {/* Consola de construcción */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2.5 bg-slate-50 border-b border-slate-200 gap-3 flex-wrap">
          <div className="flex items-center gap-2 min-w-0">
            <Terminal className="w-4 h-4 text-slate-500 shrink-0" />
            <span className="text-xs font-semibold text-slate-800 shrink-0">Registro de construcción</span>
            {visorId && (
              <span className="font-mono text-[11px] text-slate-400 truncate" title={visorId}>{visorId}</span>
            )}
          </div>
          <div className="flex items-center gap-3 text-xs text-slate-500 shrink-0">
            <span className="tabular-nums">{lineas.length} {lineas.length === 1 ? 'línea' : 'líneas'}</span>
            {lineas.length > 0 && (
              <button
                type="button"
                onClick={() => void handleCopyBuildLogs()}
                className="inline-flex items-center gap-1 px-2 py-1 rounded-md border border-slate-200 bg-white hover:bg-slate-100 text-[11px] font-medium text-slate-700 cursor-pointer"
              >
                {copiedLogs ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                {copiedLogs ? 'Copiado' : 'Copiar para IA'}
              </button>
            )}
            {enCurso && (
              <span className="flex items-center gap-1.5 text-emerald-700 font-medium">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" /> En vivo
              </span>
            )}
          </div>
        </div>
        <div
          ref={consolaRef}
          onScroll={(e) => {
            const el = e.currentTarget;
            autoScrollRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
          }}
          className="h-72 overflow-y-auto bg-white px-4 py-3 font-mono text-xs leading-relaxed"
        >
          {lineas.length === 0 ? (
            <div className="h-full flex items-center justify-center text-slate-400 font-sans text-xs text-center px-6">
              {enCurso
                ? 'Esperando salida de construcción…'
                : 'Sin registros todavía. Al desplegar, la salida aparecerá aquí en tiempo real.'}
            </div>
          ) : (
            <>
              {lineas.map((linea, i) => (
                <div key={`${linea.at}-${i}`} className="flex items-start gap-2.5 hover:bg-slate-50 px-1 rounded">
                  <span className="text-slate-400 shrink-0 select-none tabular-nums">
                    {new Date(linea.at).toLocaleTimeString('es-ES')}
                  </span>
                  <span className={`shrink-0 w-14 font-semibold ${COLOR_NIVEL[linea.level] || 'text-slate-400'}`}>
                    {linea.level}
                  </span>
                  <span className="text-slate-800 whitespace-pre-wrap break-all">{linea.message}</span>
                </div>
              ))}
              <div ref={finConsolaRef} />
            </>
          )}
        </div>
      </div>

      {/* Historial */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="px-5 py-3 bg-slate-50 border-b border-slate-200">
          <h3 className="font-semibold text-slate-800 text-xs">Historial de despliegues</h3>
        </div>

        {historial.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-xs">Todavía no hay despliegues registrados.</div>
        ) : (
          <div className="divide-y divide-slate-100">
            {historial.map((d) => {
              const f = fase(d.status);
              const desplegado = abierto === d.id;
              return (
                <div key={d.id}>
                  <div className="px-4 py-3 flex items-center gap-3 hover:bg-slate-50/70 transition-colors">
                    <button
                      type="button"
                      onClick={() => setAbierto(desplegado ? null : d.id)}
                      aria-label={desplegado ? 'Contraer detalle' : 'Ver detalle'}
                      className="text-slate-400 hover:text-slate-700 shrink-0 cursor-pointer"
                    >
                      {desplegado ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                    </button>

                    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium border shrink-0 ${f.tono}`}>
                      {d.status === 'activo'
                        ? <CheckCircle2 className="w-3 h-3" />
                        : d.status === 'fallido'
                          ? <XCircle className="w-3 h-3" />
                          : <span className={`w-1.5 h-1.5 rounded-full ${f.punto}`} />}
                      {f.etiqueta}
                    </span>

                    {d.kind === 'rollback' && (
                      <span className="text-[11px] text-slate-500 bg-slate-100 border border-slate-200 rounded px-1.5 py-0.5 shrink-0">
                        Reversión
                      </span>
                    )}

                    <div className="flex-1 min-w-0">
                      <Commit git={d.git} ramaPorDefecto={gitBranch} />
                    </div>

                    <span className="text-xs text-slate-400 shrink-0 hidden sm:block">
                      {formatTrigger(d.trigger)}
                    </span>
                    <span className="text-xs text-slate-500 shrink-0 tabular-nums w-16 text-right">{formatDuracion(d.durationMs)}</span>
                    <span className="text-xs text-slate-400 shrink-0 hidden md:block w-32 text-right tabular-nums">{formatFecha(d.startedAt)}</span>

                    <button
                      type="button"
                      onClick={() => void verLogsDe(d)}
                      className="text-xs font-medium text-slate-600 hover:text-slate-900 border border-slate-200 px-2.5 py-1 rounded-lg shrink-0 bg-white cursor-pointer"
                    >
                      Registro
                    </button>
                    {d.status === 'activo' && actual && d.id !== actual.deploymentId && (
                      <button
                        type="button"
                        onClick={() => void revertir(d.id)}
                        disabled={ocupado !== null || enCurso}
                        title="Revertir a esta versión concreta"
                        className="text-xs font-medium text-slate-700 hover:text-slate-900 border border-slate-200 px-2.5 py-1 rounded-lg shrink-0 bg-slate-50 hover:bg-slate-100 disabled:opacity-40 cursor-pointer"
                      >
                        Restaurar
                      </button>
                    )}
                  </div>

                  {desplegado && (
                    <div className="px-5 pb-4 pt-2 bg-slate-50/60 border-t border-slate-100 text-xs text-slate-600 grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2">
                      <div className="min-w-0">
                        <span className="text-slate-400">Imagen</span>
                        <div className="font-mono truncate text-slate-700" title={d.imageTag}>{d.imageTag}</div>
                      </div>
                      <div className="min-w-0">
                        <span className="text-slate-400">Contenedor</span>
                        <div className="font-mono truncate text-slate-700" title={d.containerName}>{d.containerName}</div>
                      </div>
                      {d.strategy && (
                        <div className="min-w-0 md:col-span-2">
                          <span className="text-slate-400">Estrategia de construcción</span>
                          <div className="text-slate-700">{d.strategy.reason}</div>
                        </div>
                      )}
                      {d.hostnames.length > 0 && (
                        <div className="min-w-0 md:col-span-2">
                          <span className="text-slate-400">Dominios</span>
                          <div className="text-slate-700 font-mono truncate" title={d.hostnames.join(', ')}>{d.hostnames.join(', ')}</div>
                        </div>
                      )}
                      {d.error && (
                        <div className="md:col-span-2 bg-red-50 border border-red-200 rounded-lg p-3 text-red-800">
                          <span className="font-semibold">Motivo del fallo: </span>{d.error}
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
      </>
      )}

      {subTab === 'runtime' && (
        <div className="space-y-4">
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <div>
                <h3 className="text-sm font-semibold text-slate-900">Estadísticas y logs del contenedor</h3>
                <p className="text-xs text-slate-500 mt-0.5">Lectura directa de Docker sin agentes externos.</p>
              </div>
              <button
                type="button"
                onClick={() => void loadRuntime()}
                disabled={runtimeLoading}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-xs font-medium text-slate-700 cursor-pointer disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${runtimeLoading ? 'animate-spin' : ''}`} />
                Actualizar
              </button>
            </div>

            {runtimeStats?.ok ? (
              <div className="bg-slate-50/70 border border-slate-200 rounded-xl grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-slate-200 text-xs">
                <div className="p-3.5">
                  <div className="text-slate-500">CPU</div>
                  <div className="font-mono font-semibold text-slate-900 text-sm mt-1 tabular-nums">
                    {runtimeStats.cpuPercent != null ? `${runtimeStats.cpuPercent}%` : '—'}
                  </div>
                </div>
                <div className="p-3.5">
                  <div className="text-slate-500">Memoria</div>
                  <div className="font-mono font-semibold text-slate-900 text-sm mt-1 tabular-nums">
                    {runtimeStats.memoryUsage || '—'}
                  </div>
                </div>
                <div className="p-3.5">
                  <div className="text-slate-500">Red (E/S)</div>
                  <div className="font-mono font-semibold text-slate-900 text-sm mt-1 tabular-nums">
                    {runtimeStats.netIO || '—'}
                  </div>
                </div>
                <div className="p-3.5">
                  <div className="text-slate-500">Procesos (PIDs)</div>
                  <div className="font-mono font-semibold text-slate-900 text-sm mt-1 tabular-nums">
                    {runtimeStats.pids || '—'}
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-500">
                {runtimeStats?.error || 'No hay ningún contenedor de producción en ejecución para este proyecto.'}
              </div>
            )}

            <div className="border border-slate-200 rounded-xl overflow-hidden">
              <div className="px-4 py-2 bg-slate-50 border-b border-slate-200 text-xs font-medium text-slate-700">
                Salida reciente (stdout / stderr)
              </div>
              <pre className="p-3.5 h-56 overflow-y-auto bg-white font-mono text-xs text-slate-800 whitespace-pre-wrap break-words leading-relaxed">
                {runtimeLogs || 'Sin salida disponible todavía.'}
              </pre>
            </div>
          </div>

          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-3">
            <h4 className="text-xs font-semibold text-slate-900">Ejecutar comando puntual en el contenedor</h4>
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                if (!execCmd.trim()) return;
                setExecBusy(true);
                try {
                  const res = await api.execRuntimeCommand(projectId, { command: execCmd.trim() });
                  setExecResult(res);
                  onNotify(res.exitCode === 0 ? 'Comando ejecutado correctamente' : `El comando terminó con código ${res.exitCode}`, res.exitCode === 0 ? 'success' : 'error');
                } catch (err: any) {
                  onNotify(err?.message || 'Error al ejecutar el comando', 'error');
                } finally {
                  setExecBusy(false);
                }
              }}
              className="flex gap-2"
            >
              <input
                type="text"
                value={execCmd}
                onChange={(e) => setExecCmd(e.target.value)}
                placeholder="Ej. npx prisma migrate status"
                className="flex-1 px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs font-mono"
              />
              <button
                type="submit"
                disabled={execBusy || !execCmd.trim() || !actual}
                className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium disabled:opacity-50 cursor-pointer shrink-0"
              >
                {execBusy ? 'Ejecutando…' : 'Ejecutar'}
              </button>
            </form>
            {execResult && (
              <div className="border border-slate-200 rounded-lg overflow-hidden text-xs">
                <div className="px-3 py-1.5 bg-slate-50 border-b border-slate-200 flex items-center justify-between text-[11px] font-mono">
                  <span className={execResult.exitCode === 0 ? 'text-emerald-700' : 'text-red-700'}>
                    exit {execResult.exitCode}
                  </span>
                  <span className="text-slate-500 tabular-nums">{execResult.durationMs} ms</span>
                </div>
                <pre className="p-3 bg-white font-mono text-[11px] text-slate-800 whitespace-pre-wrap break-words max-h-48 overflow-y-auto">
                  {[execResult.stdout, execResult.stderr].filter(Boolean).join('\n') || '(sin salida)'}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {subTab === 'crons' && (
        <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
          <div className="px-5 py-3.5 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-2 flex-wrap">
            <div>
              <h3 className="text-sm font-semibold text-slate-900">Tareas programadas (Cron)</h3>
              <p className="text-xs text-slate-500">Se ejecutan de forma segura dentro del contenedor de producción.</p>
            </div>
            <button
              type="button"
              onClick={() => setCronFormOpen((v) => !v)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" /> {cronFormOpen ? 'Cerrar' : 'Nueva tarea'}
            </button>
          </div>

          {cronFormOpen && (
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                try {
                  await api.createProjectCron(projectId, cronForm);
                  setCronForm({ name: '', schedule: '0 3 * * *', command: '', timeoutSec: 120 });
                  setCronFormOpen(false);
                  onNotify('Tarea cron creada', 'success');
                  await loadCrons();
                } catch (err: any) {
                  onNotify(err?.message || 'Error al crear tarea cron', 'error');
                }
              }}
              className="p-4 bg-slate-50/70 border-b border-slate-200 grid grid-cols-1 sm:grid-cols-4 gap-2.5 text-xs"
            >
              <input
                required
                value={cronForm.name}
                onChange={(e) => setCronForm({ ...cronForm, name: e.target.value })}
                placeholder="Nombre (ej. Limpiar sesiones)"
                className="px-3 py-2 bg-white border border-slate-200 rounded-lg"
              />
              <input
                required
                value={cronForm.schedule}
                onChange={(e) => setCronForm({ ...cronForm, schedule: e.target.value })}
                placeholder="0 3 * * * o @daily"
                className="px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
              />
              <input
                required
                value={cronForm.command}
                onChange={(e) => setCronForm({ ...cronForm, command: e.target.value })}
                placeholder="Comando (ej. node scripts/cleanup.js)"
                className="px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
              />
              <button
                type="submit"
                className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer"
              >
                Guardar tarea
              </button>
            </form>
          )}

          {crons.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500">
              No hay tareas cron configuradas todavía. Úsalas para limpiezas, reportes o sincronizaciones periódicas.
            </div>
          ) : (
            <div className="divide-y divide-slate-100 text-xs">
              {crons.map((job) => {
                const isOpen = cronRunsOpenId === job.id;
                const runs = cronRuns[job.id] || [];
                return (
                  <div key={job.id} className="p-4 space-y-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-semibold text-slate-900">{job.name}</span>
                          <span className="font-mono text-[11px] bg-slate-100 border border-slate-200 px-1.5 py-0.5 rounded text-slate-700">
                            {job.schedule}
                          </span>
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium border ${
                            job.enabled ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-slate-100 text-slate-500 border-slate-200'
                          }`}>
                            {job.enabled ? 'Activa' : 'Pausada'}
                          </span>
                        </div>
                        <div className="font-mono text-[11px] text-slate-500 mt-1 truncate">{job.command}</div>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <button
                          type="button"
                          disabled={cronBusyId === job.id}
                          onClick={async () => {
                            setCronBusyId(job.id);
                            try {
                              await api.runProjectCron(projectId, job.id);
                              onNotify(`Tarea «${job.name}» ejecutada`, 'success');
                              const r = await api.getProjectCronRuns(projectId, job.id);
                              setCronRuns((prev) => ({ ...prev, [job.id]: r.runs || [] }));
                              setCronRunsOpenId(job.id);
                              await loadCrons();
                            } catch (err: any) {
                              onNotify(err?.message || 'Error al ejecutar cron', 'error');
                            } finally {
                              setCronBusyId(null);
                            }
                          }}
                          className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
                        >
                          {cronBusyId === job.id ? 'Ejecutando…' : 'Ejecutar ahora'}
                        </button>
                        <button
                          type="button"
                          onClick={async () => {
                            await api.updateProjectCron(projectId, job.id, { enabled: !job.enabled });
                            await loadCrons();
                          }}
                          className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-600 cursor-pointer"
                        >
                          {job.enabled ? 'Pausar' : 'Activar'}
                        </button>
                        <button
                          type="button"
                          onClick={async () => {
                            if (isOpen) {
                              setCronRunsOpenId(null);
                              return;
                            }
                            setCronRunsOpenId(job.id);
                            const r = await api.getProjectCronRuns(projectId, job.id).catch(() => ({ runs: [] }));
                            setCronRuns((prev) => ({ ...prev, [job.id]: r.runs || [] }));
                          }}
                          className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-600 cursor-pointer"
                        >
                          Historial
                        </button>
                        <button
                          type="button"
                          aria-label={`Eliminar tarea ${job.name}`}
                          onClick={async () => {
                            await api.deleteProjectCron(projectId, job.id);
                            onNotify('Tarea eliminada', 'info');
                            await loadCrons();
                          }}
                          className="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 cursor-pointer"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                    {isOpen && (
                      <div className="bg-slate-50 border border-slate-200 rounded-lg divide-y divide-slate-200/70">
                        {runs.length === 0 ? (
                          <div className="p-3 text-slate-500">Sin ejecuciones registradas todavía.</div>
                        ) : (
                          runs.slice(0, 8).map((r) => (
                            <div key={r.id} className="p-2.5 flex items-center justify-between gap-2 text-[11px]">
                              <span className={r.status === 'ok' || r.exitCode === 0 ? 'text-emerald-700 font-medium' : 'text-red-700 font-medium'}>
                                {r.status} (exit {r.exitCode ?? '—'})
                              </span>
                              <span className="font-mono text-slate-500 truncate flex-1">{r.output || '—'}</span>
                              <span className="text-slate-400 tabular-nums shrink-0">{formatDuracion(r.durationMs)}</span>
                            </div>
                          ))
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {subTab === 'previews' && (
        <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
          <div className="px-5 py-3.5 bg-slate-50 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-slate-900">Vistas previas por rama o PR</h3>
              <p className="text-xs text-slate-500">Contenedores temporales aislados con limpieza automática y protección frente a forks.</p>
            </div>
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                if (!previewBranch.trim() && !previewPr.trim()) return;
                setPreviewBusy(true);
                try {
                  await api.deployProjectPreview(projectId, {
                    branch: previewBranch.trim() || undefined,
                    prNumber: previewPr.trim() ? Number(previewPr.trim()) : null,
                  });
                  setPreviewBranch('');
                  setPreviewPr('');
                  onNotify('Vista previa desplegada', 'success');
                  await loadPreviews();
                } catch (err: any) {
                  onNotify(err?.message || 'Error al desplegar vista previa', 'error');
                } finally {
                  setPreviewBusy(false);
                }
              }}
              className="flex items-center gap-2 flex-wrap"
            >
              <input
                type="text"
                value={previewBranch}
                onChange={(e) => setPreviewBranch(e.target.value)}
                placeholder="Rama (ej. feat/login)"
                className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-mono w-48 sm:w-52"
              />
              <input
                type="number"
                value={previewPr}
                onChange={(e) => setPreviewPr(e.target.value)}
                placeholder="PR #"
                className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-mono w-20"
              />
              <button
                type="submit"
                disabled={previewBusy || (!previewBranch.trim() && !previewPr.trim())}
                className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium disabled:opacity-50 cursor-pointer"
              >
                {previewBusy ? 'Desplegando…' : 'Lanzar preview'}
              </button>
            </form>
          </div>

          {previews.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500">
              No hay vistas previas activas. Lanza una arriba indicando una rama o número de Pull Request.
            </div>
          ) : (
            <div className="divide-y divide-slate-100 text-xs">
              {previews.map((pv) => (
                <div key={pv.key} className="p-4 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0 flex-wrap">
                      <span className="font-mono font-semibold text-slate-900">{pv.branch}</span>
                      {pv.prNumber && (
                        <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[11px]">
                          PR #{pv.prNumber}
                        </span>
                      )}
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium border ${
                        pv.status === 'active' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-slate-100 text-slate-600 border-slate-200'
                      }`}>
                        {pv.status}
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      {pv.url && (
                        <a
                          href={pv.url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium"
                        >
                          Abrir <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                      <button
                        type="button"
                        onClick={async () => {
                          if (previewLogKey === pv.key) {
                            setPreviewLogKey(null);
                            return;
                          }
                          setPreviewLogKey(pv.key);
                          const res = await api.getProjectPreviewLogs(projectId, pv.key).catch(() => ({ output: 'Sin registros.' }));
                          setPreviewLogText(res.output || 'Sin registros.');
                        }}
                        className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-600 cursor-pointer"
                      >
                        Logs
                      </button>
                      <button
                        type="button"
                        onClick={async () => {
                          await api.destroyProjectPreview(projectId, pv.key);
                          onNotify(`Vista previa ${pv.branch} eliminada`, 'info');
                          await loadPreviews();
                        }}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 cursor-pointer"
                        aria-label={`Eliminar vista previa ${pv.branch}`}
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                  {previewLogKey === pv.key && (
                    <pre className="p-3 bg-slate-50 border border-slate-200 rounded-lg font-mono text-[11px] text-slate-700 max-h-48 overflow-y-auto whitespace-pre-wrap">
                      {previewLogText}
                    </pre>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
