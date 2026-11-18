import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Rocket, RotateCcw, Square, Play, GitCommit, GitBranch, Clock, AlertTriangle,
  Terminal, ChevronDown, ChevronRight, Globe, Package, CheckCircle2, XCircle,
  Loader2, Undo2, ShieldAlert
} from 'lucide-react';
import { api, type Deployment, type DeployStatus, type DeployGitInfo, type DeployLogLine } from '../lib/api';
import { deployStream } from '../lib/deployStream';

interface Props {
  projectId: string;
  projectName: string;
  gitBranch: string;
  onNotify: (msg: string) => void;
}

/**
 * Fases del despliegue, en el orden real del proceso.
 *
 * El nombre viene del servidor en español; aquí solo se le pone color y peso.
 * `progreso` alimenta la barra: no es un porcentaje medido —no se puede saber
 * cuánto queda de un `docker build`— sino la posición en la secuencia, que es
 * lo que de verdad responde a «¿por dónde va?».
 */
const FASES: Record<string, { etiqueta: string; progreso: number; tono: string; punto: string }> = {
  pendiente:      { etiqueta: 'En cola',        progreso: 5,   tono: 'text-slate-600 bg-slate-100 border-slate-200',        punto: 'bg-slate-400' },
  sincronizando:  { etiqueta: 'Sincronizando',  progreso: 15,  tono: 'text-slate-700 bg-slate-100 border-slate-200',        punto: 'bg-slate-500 animate-pulse' },
  construyendo:   { etiqueta: 'Construyendo',   progreso: 45,  tono: 'text-amber-700 bg-amber-50 border-amber-200',         punto: 'bg-amber-500 animate-pulse' },
  arrancando:     { etiqueta: 'Arrancando',     progreso: 65,  tono: 'text-amber-700 bg-amber-50 border-amber-200',         punto: 'bg-amber-500 animate-pulse' },
  verificando:    { etiqueta: 'Verificando',    progreso: 80,  tono: 'text-sky-700 bg-sky-50 border-sky-200',               punto: 'bg-sky-500 animate-pulse' },
  promocionando:  { etiqueta: 'Promocionando',  progreso: 92,  tono: 'text-sky-700 bg-sky-50 border-sky-200',               punto: 'bg-sky-500 animate-pulse' },
  drenando:       { etiqueta: 'Drenando',       progreso: 97,  tono: 'text-sky-700 bg-sky-50 border-sky-200',               punto: 'bg-sky-500 animate-pulse' },
  activo:         { etiqueta: 'Activo',         progreso: 100, tono: 'text-emerald-700 bg-emerald-50 border-emerald-200',   punto: 'bg-emerald-500' },
  fallido:        { etiqueta: 'Fallido',        progreso: 100, tono: 'text-rose-700 bg-rose-50 border-rose-200',            punto: 'bg-rose-500' }
};

const EN_CURSO = new Set(['pendiente', 'sincronizando', 'construyendo', 'arrancando', 'verificando', 'promocionando', 'drenando']);

function fase(estado: string) {
  return FASES[estado] || { etiqueta: estado, progreso: 50, tono: 'text-slate-600 bg-slate-100 border-slate-200', punto: 'bg-slate-400' };
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
  ERROR: 'text-rose-600',
  WARN: 'text-amber-600',
  SUCCESS: 'text-emerald-600',
  INFO: 'text-slate-500'
};

/** Identidad del código: rama + commit + asunto, truncando el valor y nunca el rótulo. */
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
      <span className="inline-flex items-center gap-1.5 shrink-0">
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
  const [historial, setHistorial] = useState<Deployment[]>([]);
  const [cargando, setCargando] = useState(true);
  const [ocupado, setOcupado] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Despliegue que se está mirando en el visor de logs.
  const [visorId, setVisorId] = useState<string | null>(null);
  const [visorEstado, setVisorEstado] = useState<string>('pendiente');
  const [abierto, setAbierto] = useState<string | null>(null);

  // Confirmación de rollback: nombra el commit destino ANTES de ejecutar.
  const [confirmarRollback, setConfirmarRollback] = useState(false);

  // Detener es reversible, así que es un interruptor optimista con deshacer y
  // sin diálogo. `detenidoOptimista` pinta el resultado antes de que el
  // servidor conteste; si falla, se revierte.
  const [detenidoOptimista, setDetenidoOptimista] = useState<boolean | null>(null);
  const [deshacerParada, setDeshacerParada] = useState(false);
  const temporizadorDeshacer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const consolaRef = useRef<HTMLDivElement | null>(null);
  const finConsolaRef = useRef<HTMLDivElement | null>(null);
  // Amortiguador de líneas: se acumulan aquí y se vuelcan al DOM una vez por
  // frame. Ver web/src/lib/deployStream.ts para el porqué.
  const bufferRef = useRef<DeployLogLine[]>([]);
  const lineasRef = useRef<DeployLogLine[]>([]);
  const frameRef = useRef<number | null>(null);
  const autoScrollRef = useRef(true);
  const [, forzarPintado] = useState(0);

  const cargar = useCallback(async (conSpinner = false) => {
    if (conSpinner) setCargando(true);
    try {
      const [st, hist] = await Promise.all([
        api.getDeployStatus(projectId),
        api.getDeployments(projectId, 20)
      ]);
      setEstado(st);
      setHistorial(hist.deployments);
      setError(null);
      // El servidor manda: si contesta, la vista optimista deja de mandar.
      setDetenidoOptimista(null);
      if (!visorId && hist.deployments.length > 0) {
        setVisorId(hist.deployments[0].id);
        setVisorEstado(hist.deployments[0].status);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al leer el estado del despliegue');
    } finally {
      setCargando(false);
    }
  }, [projectId, visorId]);

  useEffect(() => {
    setVisorId(null);
    lineasRef.current = [];
    bufferRef.current = [];
    cargar(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  useEffect(() => () => {
    if (frameRef.current != null) cancelAnimationFrame(frameRef.current);
    if (temporizadorDeshacer.current) clearTimeout(temporizadorDeshacer.current);
  }, []);

  /** Vuelca el amortiguador al DOM. Un solo render por frame, lleguen las que lleguen. */
  const programarVolcado = useCallback(() => {
    if (frameRef.current != null) return;
    frameRef.current = requestAnimationFrame(() => {
      frameRef.current = null;
      if (bufferRef.current.length === 0) return;
      const siguientes = lineasRef.current.concat(bufferRef.current);
      bufferRef.current = [];
      // Techo duro: un build con 200.000 líneas no puede llevarse la pestaña
      // por delante. Se conserva la cola, que es donde está el fallo.
      lineasRef.current = siguientes.length > 3000 ? siguientes.slice(siguientes.length - 3000) : siguientes;
      forzarPintado((n) => n + 1);
      if (autoScrollRef.current && finConsolaRef.current) {
        finConsolaRef.current.scrollIntoView({ block: 'end' });
      }
    });
  }, []);

  // Líneas de build en vivo.
  useEffect(() => {
    return deployStream.onLog((linea) => {
      if (linea.projectId !== projectId) return;
      // Una línea de un despliegue que no se está mirando abre el visor en él:
      // es lo que pasa cuando un push de GitHub arranca una build mientras el
      // usuario tiene la pestaña abierta.
      if (visorId && linea.deploymentId !== visorId) return;
      bufferRef.current.push({ at: linea.at, level: linea.level, message: linea.message });
      programarVolcado();
    });
  }, [projectId, visorId, programarVolcado]);

  // Cambios de fase. Son pocos y espaciados, así que aquí sí vale el estado.
  useEffect(() => {
    return deployStream.onEvent((evento) => {
      if (evento.projectId !== projectId) return;
      if (!visorId || evento.deploymentId !== visorId) {
        // Despliegue nuevo (botón de otro cliente, o push de GitHub): se pasa a
        // seguirlo en vivo, con la consola limpia.
        if (EN_CURSO.has(evento.status)) {
          lineasRef.current = [];
          bufferRef.current = [];
          setVisorId(evento.deploymentId);
        }
      }
      setVisorEstado(evento.status);
      if (!EN_CURSO.has(evento.status)) {
        if (evento.status === 'activo') onNotify(`Despliegue completado en ${projectName}`);
        if (evento.status === 'fallido') onNotify(`Despliegue fallido en ${projectName}: ${evento.error || 'sin detalle'}`);
        cargar();
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
      onNotify(err instanceof Error ? err.message : 'No se pudieron cargar los registros');
    }
  };

  const desplegar = async () => {
    setOcupado('desplegar');
    lineasRef.current = [];
    bufferRef.current = [];
    // Se suelta el despliegue que se estaba mirando ANTES de pedir el nuevo: el
    // id del nuevo todavía no se conoce, y con el viejo puesto el filtro tiraría
    // las primeras líneas de la build.
    setVisorId(null);
    setVisorEstado('pendiente');
    try {
      await api.startDeploy(projectId);
      onNotify('Despliegue iniciado');
      await cargar();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudo iniciar el despliegue');
    } finally {
      setOcupado(null);
    }
  };

  const revertir = async () => {
    setConfirmarRollback(false);
    setOcupado('revertir');
    try {
      const resultado = await api.rollbackDeploy(projectId);
      if (resultado.status === 'fallido') {
        onNotify(`No se pudo revertir: ${resultado.error || 'sin detalle'}`);
      } else {
        onNotify(`Revertido a ${resultado.git?.shortCommit || resultado.imageTag}`);
      }
      await cargar();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudo revertir');
    } finally {
      setOcupado(null);
    }
  };

  /** Detener y reanudar comparten camino: interruptor optimista con deshacer. */
  const alternarServicio = async (detener: boolean) => {
    setDetenidoOptimista(detener);
    setOcupado('servicio');
    try {
      const resultado = detener ? await api.stopDeploy(projectId) : await api.resumeDeploy(projectId);
      const ok = detener ? (resultado as any).stopped : (resultado as any).started;
      if (!ok) {
        setDetenidoOptimista(null);
        onNotify((resultado as any).error || (resultado as any).reason || 'La acción no se pudo completar');
      } else {
        onNotify(detener ? 'Servicio detenido y ruta retirada' : 'Servicio reanudado y ruta repuesta');
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
      onNotify(err instanceof Error ? err.message : 'La acción no se pudo completar');
    } finally {
      setOcupado(null);
    }
  };

  const actual = estado?.current || null;
  const anterior = estado?.previous || null;
  const contenedorParado = estado?.containerState ? estado.containerState.status !== 'running' : false;
  const parado = detenidoOptimista != null ? detenidoOptimista : contenedorParado;
  const lineas = lineasRef.current;

  if (cargando) {
    return (
      <div className="bg-white p-10 rounded-2xl border border-slate-200 shadow-sm text-center text-slate-500 text-sm">
        Cargando el estado del despliegue…
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {estado?.docker && !estado.docker.available && (
        <div className="bg-amber-50 border border-amber-200 rounded-2xl p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
          <div className="text-sm min-w-0">
            <p className="font-semibold text-amber-900">Docker no está disponible</p>
            <p className="text-amber-800">
              {estado.docker.reason || 'Desplegar a producción construye una imagen, y para eso hace falta un daemon de Docker activo.'}
            </p>
          </div>
        </div>
      )}

      {error && (
        <div className="bg-rose-50 border border-rose-200 rounded-2xl p-4 text-sm text-rose-800">{error}</div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* Versión en producción                                               */}
      {/* ------------------------------------------------------------------ */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
        <div className="p-6 flex flex-col lg:flex-row lg:items-start gap-5">
          <div className="flex-1 min-w-0 space-y-3">
            <div className="flex items-center gap-2.5 flex-wrap">
              <h3 className="font-bold text-slate-900 text-lg flex items-center gap-2">
                <Rocket className="w-5 h-5 text-slate-700" /> Versión en producción
              </h3>
              {enCurso ? (
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${fase(visorEstado).tono}`}>
                  <span className={`w-2 h-2 rounded-full ${fase(visorEstado).punto}`} />
                  {fase(visorEstado).etiqueta}
                </span>
              ) : actual ? (
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${
                  parado ? 'text-slate-600 bg-slate-100 border-slate-200' : 'text-emerald-700 bg-emerald-50 border-emerald-200'
                }`}>
                  <span className={`w-2 h-2 rounded-full ${parado ? 'bg-slate-400' : 'bg-emerald-500'}`} />
                  {parado ? 'Detenido' : 'Sirviendo tráfico'}
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border text-slate-600 bg-slate-100 border-slate-200">
                  <span className="w-2 h-2 rounded-full bg-slate-400" /> Nunca desplegado
                </span>
              )}
              {estado?.queued && (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border text-slate-600 bg-slate-50 border-slate-200">
                  Hay otro commit esperando turno
                </span>
              )}
            </div>

            {actual ? (
              <div className="space-y-2.5 min-w-0">
                <Commit git={actual.git} ramaPorDefecto={gitBranch} />
                <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 text-xs text-slate-500 min-w-0">
                  <span className="inline-flex items-center gap-1.5 min-w-0">
                    <Package className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                    <span className="font-mono truncate" title={actual.imageTag}>{actual.imageTag}</span>
                  </span>
                  <span className="inline-flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                    Promocionada el {formatFecha(actual.promotedAt)}
                  </span>
                  {actual.hostnames.length > 0 && (
                    <span className="inline-flex items-center gap-1.5 min-w-0">
                      <Globe className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                      <span className="truncate" title={actual.hostnames.join(', ')}>{actual.hostnames.join(', ')}</span>
                    </span>
                  )}
                  {estado?.containerState && (
                    <span className="inline-flex items-center gap-1.5">
                      Contenedor: <strong className="text-slate-700 font-medium">{estado.containerState.status}</strong>
                      {estado.containerState.health && estado.containerState.health !== 'sin-healthcheck' && (
                        <> · salud <strong className="text-slate-700 font-medium">{estado.containerState.health}</strong></>
                      )}
                    </span>
                  )}
                </div>
              </div>
            ) : (
              <p className="text-sm text-slate-500 max-w-prose">
                Este proyecto todavía no tiene ninguna versión en producción. Al desplegar se traerá la rama
                <strong className="text-slate-700"> {gitBranch || 'main'}</strong>, se construirá una imagen, se comprobará que
                responde y solo entonces se moverá la ruta pública.
              </p>
            )}
          </div>

          {/* Acciones. Se dejan crecer: en español «Revertir al commit anterior»
              ocupa casi el doble que su equivalente en inglés. */}
          <div className="flex flex-wrap items-center gap-2 lg:justify-end shrink-0">
            <button
              onClick={desplegar}
              disabled={ocupado !== null || enCurso || estado?.docker?.available === false}
              className="inline-flex items-center gap-2 bg-slate-900 hover:bg-slate-800 text-white px-4 py-2.5 rounded-xl text-sm font-semibold transition-colors shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {enCurso
                ? <><Loader2 className="w-4 h-4 animate-spin" /> Desplegando…</>
                : <><Rocket className="w-4 h-4" /> Desplegar</>}
            </button>

            <button
              onClick={() => setConfirmarRollback(true)}
              disabled={ocupado !== null || enCurso || !estado?.canRollback}
              title={estado?.canRollback ? 'Volver a la versión anterior' : 'No hay ninguna versión anterior a la que volver'}
              className="inline-flex items-center gap-2 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 px-4 py-2.5 rounded-xl text-sm font-medium transition-colors shadow-2xs disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <RotateCcw className="w-4 h-4 text-slate-500" /> Revertir
            </button>

            <button
              onClick={() => alternarServicio(!parado)}
              disabled={ocupado !== null || enCurso || !actual}
              className="inline-flex items-center gap-2 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 px-4 py-2.5 rounded-xl text-sm font-medium transition-colors shadow-2xs disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {parado
                ? <><Play className="w-4 h-4 text-emerald-600" /> Reanudar</>
                : <><Square className="w-4 h-4 text-slate-500" /> Detener</>}
            </button>
          </div>
        </div>

        {/* Barra de fase */}
        {enCurso && (
          <div className="h-1 bg-slate-100">
            <div
              className="h-1 bg-slate-900 transition-all duration-500 ease-out"
              style={{ width: `${fase(visorEstado).progreso}%` }}
            />
          </div>
        )}

        {/* Deshacer la parada. Sin diálogo: la acción es reversible y el
            deshacer está aquí, que es donde el usuario mira después de pulsar. */}
        {deshacerParada && parado && (
          <div className="border-t border-slate-100 bg-slate-50/70 px-6 py-3 flex items-center justify-between gap-4">
            <span className="text-xs text-slate-600">
              El servicio está detenido y su ruta pública retirada. La imagen y el contenedor se conservan.
            </span>
            <button
              onClick={() => alternarServicio(false)}
              disabled={ocupado !== null}
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-800 bg-white border border-slate-200 px-3 py-1.5 rounded-lg hover:bg-slate-50 disabled:opacity-50 shrink-0"
            >
              <Undo2 className="w-3.5 h-3.5" /> Deshacer
            </button>
          </div>
        )}
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Confirmación de rollback: dice a QUÉ vuelve antes de hacerlo        */}
      {/* ------------------------------------------------------------------ */}
      {confirmarRollback && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/20 p-4">
          <div className="bg-white rounded-2xl border border-slate-200 shadow-xl max-w-lg w-full p-6 space-y-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-xl bg-amber-50 border border-amber-100 flex items-center justify-center shrink-0">
                <ShieldAlert className="w-5 h-5 text-amber-600" />
              </div>
              <div className="min-w-0">
                <h4 className="font-bold text-slate-900">Revertir a la versión anterior</h4>
                <p className="text-sm text-slate-500 mt-0.5">
                  No se reconstruye nada: se arranca el contenedor anterior, se comprueba que responde y se mueve la ruta.
                </p>
              </div>
            </div>

            <div className="rounded-xl border border-slate-200 divide-y divide-slate-100 overflow-hidden">
              <div className="p-3.5 bg-slate-50/60">
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

            <p className="text-xs text-slate-500">
              Las bases de datos y los volúmenes no se tocan: revertir cambia el código que se sirve, no los datos.
              Si esa versión trajo una migración, revertirla no la deshace.
            </p>

            <div className="flex justify-end gap-2 pt-1">
              <button
                onClick={() => setConfirmarRollback(false)}
                className="text-sm font-medium text-slate-600 border border-slate-200 px-4 py-2 rounded-lg hover:bg-slate-50"
              >
                Cancelar
              </button>
              <button
                onClick={revertir}
                className="inline-flex items-center gap-2 text-sm font-semibold bg-slate-900 text-white px-4 py-2 rounded-lg hover:bg-slate-800"
              >
                <RotateCcw className="w-4 h-4" />
                Revertir a {anterior?.git?.shortCommit || anterior?.version || 'la versión anterior'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* Consola de construcción                                             */}
      {/* ------------------------------------------------------------------ */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
        <div className="flex items-center justify-between px-5 py-3 bg-slate-50 border-b border-slate-200 gap-4">
          <div className="flex items-center gap-2 min-w-0">
            <Terminal className="w-4 h-4 text-slate-500 shrink-0" />
            <span className="text-sm font-semibold text-slate-700 shrink-0">Registro de construcción</span>
            {visorId && (
              <span className="font-mono text-[11px] text-slate-400 truncate" title={visorId}>{visorId}</span>
            )}
          </div>
          <div className="flex items-center gap-3 text-xs text-slate-500 shrink-0">
            <span>{lineas.length} líneas</span>
            {enCurso && (
              <span className="flex items-center gap-1.5 text-emerald-600">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" /> En vivo
              </span>
            )}
          </div>
        </div>
        <div
          ref={consolaRef}
          onScroll={(e) => {
            const el = e.currentTarget;
            // Si el usuario sube a leer un error, el visor deja de arrastrarlo
            // al final; vuelve a seguir en cuanto baja del todo.
            autoScrollRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
          }}
          className="h-80 overflow-y-auto bg-white px-4 py-3 font-mono text-[12.5px] leading-relaxed"
        >
          {lineas.length === 0 ? (
            <div className="h-full flex items-center justify-center text-slate-400 font-sans text-sm text-center px-6">
              {enCurso
                ? 'Esperando la salida de la construcción…'
                : 'Sin registros todavía. Al desplegar, cada línea de la construcción aparecerá aquí en vivo.'}
            </div>
          ) : (
            <>
              {lineas.map((linea, i) => (
                <div key={`${linea.at}-${i}`} className="flex items-start gap-3 hover:bg-slate-50/80 px-1 rounded">
                  <span className="text-slate-300 shrink-0 select-none tabular-nums">
                    {new Date(linea.at).toLocaleTimeString('es-ES')}
                  </span>
                  <span className={`shrink-0 w-16 font-semibold ${COLOR_NIVEL[linea.level] || 'text-slate-400'}`}>
                    {linea.level}
                  </span>
                  <span className="text-slate-700 whitespace-pre-wrap break-all">{linea.message}</span>
                </div>
              ))}
              <div ref={finConsolaRef} />
            </>
          )}
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Historial                                                           */}
      {/* ------------------------------------------------------------------ */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
        <div className="px-5 py-3.5 bg-slate-50 border-b border-slate-200">
          <h3 className="font-semibold text-slate-800 text-sm">Historial de despliegues</h3>
        </div>

        {historial.length === 0 ? (
          <div className="p-10 text-center text-slate-500 text-sm">Todavía no hay despliegues registrados.</div>
        ) : (
          <div className="divide-y divide-slate-100">
            {historial.map((d) => {
              const f = fase(d.status);
              const desplegado = abierto === d.id;
              return (
                <div key={d.id}>
                  <div className="px-5 py-3.5 flex items-center gap-4 hover:bg-slate-50/60 transition-colors">
                    <button
                      onClick={() => setAbierto(desplegado ? null : d.id)}
                      className="text-slate-400 hover:text-slate-700 shrink-0"
                      title={desplegado ? 'Contraer' : 'Ver detalle'}
                    >
                      {desplegado ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                    </button>

                    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border shrink-0 ${f.tono}`}>
                      {d.status === 'activo'
                        ? <CheckCircle2 className="w-3.5 h-3.5" />
                        : d.status === 'fallido'
                          ? <XCircle className="w-3.5 h-3.5" />
                          : <span className={`w-2 h-2 rounded-full ${f.punto}`} />}
                      {f.etiqueta}
                    </span>

                    {d.kind === 'rollback' && (
                      <span className="text-xs text-slate-500 bg-slate-100 border border-slate-200 rounded-md px-2 py-0.5 shrink-0">
                        Reversión
                      </span>
                    )}

                    <div className="flex-1 min-w-0">
                      <Commit git={d.git} ramaPorDefecto={gitBranch} />
                    </div>

                    <span className="text-xs text-slate-400 shrink-0 hidden sm:block">
                      {d.trigger === 'webhook' ? 'Push de GitHub' : 'Manual'}
                    </span>
                    <span className="text-xs text-slate-500 shrink-0 tabular-nums w-20 text-right">{formatDuracion(d.durationMs)}</span>
                    <span className="text-xs text-slate-400 shrink-0 hidden md:block w-32 text-right">{formatFecha(d.startedAt)}</span>

                    <button
                      onClick={() => verLogsDe(d)}
                      className="text-xs font-medium text-slate-600 hover:text-slate-900 border border-slate-200 px-2.5 py-1 rounded-lg shrink-0 bg-white"
                    >
                      Ver registro
                    </button>
                  </div>

                  {desplegado && (
                    <div className="px-5 pb-4 pt-1 bg-slate-50/60 border-t border-slate-100 text-xs text-slate-600 grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2">
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
                          <div className="text-slate-700 truncate" title={d.hostnames.join(', ')}>{d.hostnames.join(', ')}</div>
                        </div>
                      )}
                      {d.error && (
                        <div className="md:col-span-2 bg-rose-50 border border-rose-200 rounded-lg p-3 text-rose-800">
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
    </div>
  );
};
