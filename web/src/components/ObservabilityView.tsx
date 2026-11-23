import React, { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  RefreshCw,
  ShieldAlert,
  Wrench,
  XCircle,
} from 'lucide-react';
import {
  api,
  type DoctorCheck,
  type ObservabilityHistoryPoint,
  type ObservabilitySnapshot,
  type SystemDoctorReport,
} from '../lib/api';
import { copyToClipboard } from '../lib/clipboard';

interface ObservabilityViewProps {
  onNotify: (msg: string, type?: 'success' | 'info' | 'error') => void;
}

function formatUptime(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatMs(val: number | null | undefined): string {
  if (val === null || val === undefined || !Number.isFinite(val)) return '—';
  return val < 10 ? `${val.toFixed(2)} ms` : `${val.toFixed(1)} ms`;
}

interface SparklineCardProps {
  title: string;
  value: string;
  unit?: string;
  detailLine: string;
  footerLine: string;
  points: number[];
  timestamps?: number[];
  accent?: 'ink' | 'amber';
}

const SparklineCard: React.FC<SparklineCardProps> = ({
  title,
  value,
  unit,
  detailLine,
  footerLine,
  points,
  timestamps = [],
  accent = 'ink',
}) => {
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
  const width = 260;
  const height = 56;
  const padY = 6;
  const values = points.length >= 2 ? points : [0, points[0] ?? 0];
  const minVal = Math.min(...values, 0);
  const maxVal = Math.max(...values, minVal + 1);
  const span = maxVal - minVal || 1;

  const coords = values.map((v, i) => {
    const x = (i / Math.max(1, values.length - 1)) * width;
    const y = height - padY - ((v - minVal) / span) * (height - padY * 2);
    return { x, y, v };
  });

  const linePath = coords.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
  const areaPath = `${linePath} L${width},${height} L0,${height} Z`;

  const activePoint = hoverIdx !== null && coords[hoverIdx] ? coords[hoverIdx] : null;
  const displayValue = activePoint
    ? (activePoint.v < 10 ? activePoint.v.toFixed(2) : activePoint.v.toFixed(1))
    : value;
  const hoverTime = hoverIdx !== null && timestamps[hoverIdx]
    ? new Date(timestamps[hoverIdx]).toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : null;

  const strokeColor = accent === 'amber' ? '#d97706' : '#18181b';
  const fillColor = accent === 'amber' ? 'rgb(217 119 6 / 0.08)' : 'rgb(24 24 27 / 0.05)';

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4 flex flex-col justify-between">
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-xs font-medium text-slate-500">{title}</span>
        <span className="text-[11px] text-slate-400 tabular-nums">
          {hoverTime ? hoverTime : `máx ${maxVal < 10 ? maxVal.toFixed(1) : Math.round(maxVal)}${unit ? ` ${unit}` : ''}`}
        </span>
      </div>
      <div className="mt-1 flex items-baseline gap-1.5">
        <span className="text-2xl font-semibold text-slate-900 tracking-tight tabular-nums">{displayValue}</span>
        {unit && <span className="text-xs font-medium text-slate-500">{unit}</span>}
      </div>
      <p className="text-[11px] text-slate-500 mt-0.5 truncate tabular-nums">{detailLine}</p>
      <div className="mt-3">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="w-full h-14 overflow-visible cursor-crosshair"
          role="img"
          aria-label={`Tendencia de ${title}`}
          onMouseLeave={() => setHoverIdx(null)}
          onMouseMove={(e) => {
            const rect = e.currentTarget.getBoundingClientRect();
            if (!rect.width) return;
            const ratio = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
            const idx = Math.round(ratio * (coords.length - 1));
            setHoverIdx(idx);
          }}
        >
          <path d={areaPath} fill={fillColor} />
          <path
            d={linePath}
            fill="none"
            stroke={strokeColor}
            strokeWidth="1.6"
            vectorEffect="non-scaling-stroke"
            strokeLinejoin="round"
            strokeLinecap="round"
          />
          {activePoint && (
            <>
              <line
                x1={activePoint.x}
                y1={0}
                x2={activePoint.x}
                y2={height}
                stroke="#cbd5e1"
                strokeWidth="1"
                strokeDasharray="2 2"
                vectorEffect="non-scaling-stroke"
              />
              <circle cx={activePoint.x} cy={activePoint.y} r="3.2" fill={strokeColor} stroke="#ffffff" strokeWidth="1.5" />
            </>
          )}
        </svg>
      </div>
      <p className="text-[11px] text-slate-400 mt-2 truncate tabular-nums">{footerLine}</p>
    </div>
  );
};

export const ObservabilityView: React.FC<ObservabilityViewProps> = ({ onNotify }) => {
  const [snapshot, setSnapshot] = useState<ObservabilitySnapshot | null>(null);
  const [doctor, setDoctor] = useState<SystemDoctorReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [doctorRunning, setDoctorRunning] = useState(false);
  const [fixingAction, setFixingAction] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [copiedProm, setCopiedProm] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadSnapshot = useCallback(async (fresh = false) => {
    try {
      const snap = await api.getObservabilitySnapshot(fresh);
      setSnapshot(snap);
      setError(null);
    } catch (e: any) {
      setError(e?.message || 'No se pudieron cargar las métricas');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  const loadDoctor = useCallback(async (notify = false) => {
    setDoctorRunning(true);
    try {
      const report = await api.getSystemDoctor();
      setDoctor(report);
      if (notify) {
        onNotify(
          report.overall === 'ok'
            ? `Diagnóstico completado: ${report.summary.ok} comprobaciones correctas.`
            : `Diagnóstico completado: ${report.summary.ok} ok, ${report.summary.warn} avisos, ${report.summary.fail} fallos.`,
          report.overall === 'fail' ? 'error' : 'info'
        );
      }
    } catch (e: any) {
      onNotify(e?.message || 'No se pudo ejecutar el diagnóstico del sistema', 'error');
    } finally {
      setDoctorRunning(false);
    }
  }, [onNotify]);

  useEffect(() => {
    let active = true;
    api.getObservabilitySnapshot(true)
      .then((snap) => {
        if (!active) return;
        setSnapshot(snap);
        setError(null);
      })
      .catch((e: any) => {
        if (active) setError(e?.message || 'No se pudieron cargar las métricas');
      })
      .finally(() => {
        if (active) {
          setLoading(false);
          setRefreshing(false);
        }
      });
    api.getSystemDoctor()
      .then((report) => {
        if (active) setDoctor(report);
      })
      .catch(() => {})
      .finally(() => {
        if (active) setDoctorRunning(false);
      });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = window.setInterval(() => {
      void loadSnapshot(false);
    }, 5000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, loadSnapshot]);

  const handleFix = async (check: DoctorCheck) => {
    if (!check.fixAction) return;
    setFixingAction(check.fixAction);
    try {
      const res = await api.runDoctorFix(check.fixAction);
      onNotify(res.message || 'Corrección aplicada correctamente', 'success');
      await Promise.all([loadDoctor(false), loadSnapshot(true)]);
    } catch (e: any) {
      onNotify(e?.message || 'No se pudo aplicar la corrección', 'error');
    } finally {
      setFixingAction(null);
    }
  };

  const handleCopyPrometheus = async () => {
    const origin = window.location.origin.replace(/^https?:\/\//, '');
    const scheme = window.location.protocol === 'https:' ? 'https' : 'http';
    const snippet = [
      'scrape_configs:',
      '  - job_name: culkibo',
      `    scheme: ${scheme}`,
      '    metrics_path: /metrics',
      '    scrape_interval: 15s',
      '    static_configs:',
      `      - targets: ['${origin}']`,
      '    # Si el panel requiere token remoto, añade:',
      '    # authorization:',
      '    #   credentials: "<TU_CULKIBO_TOKEN>"',
    ].join('\n');
    const ok = await copyToClipboard(snippet);
    if (ok) {
      setCopiedProm(true);
      onNotify('Configuración de Prometheus copiada al portapapeles', 'success');
      window.setTimeout(() => setCopiedProm(false), 2000);
    } else {
      onNotify('No se pudo copiar al portapapeles', 'error');
    }
  };

  const history: ObservabilityHistoryPoint[] = snapshot?.history || [];
  const timestamps = history.map((h) => h.ts);

  return (
    <div className="space-y-6">
      {/* Cabecera */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">Métricas y salud</h1>
          <p className="text-sm text-slate-500 mt-1">
            Telemetría real del plano de control, bucle de eventos, Caddy y diagnóstico con corrección automática.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setAutoRefresh((v) => !v)}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors cursor-pointer flex items-center gap-1.5 ${
              autoRefresh
                ? 'bg-slate-900 text-white border-slate-900'
                : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
            }`}
          >
            <span className={`w-1.5 h-1.5 rounded-full ${autoRefresh ? 'bg-emerald-400' : 'bg-slate-300'}`} />
            {autoRefresh ? 'Auto 5 s' : 'Pausado'}
          </button>
          <button
            type="button"
            onClick={handleCopyPrometheus}
            className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-200 bg-white text-slate-700 hover:bg-slate-50 transition-colors cursor-pointer flex items-center gap-1.5"
          >
            {copiedProm ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
            {copiedProm ? 'Copiado' : 'Copiar Prometheus'}
          </button>
          <button
            type="button"
            onClick={() => {
              setRefreshing(true);
              void loadSnapshot(true);
            }}
            disabled={refreshing}
            className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-200 bg-white text-slate-700 hover:bg-slate-50 transition-colors cursor-pointer flex items-center gap-1.5 disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Actualizar
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-800 rounded-xl px-4 py-3 text-sm flex items-center justify-between gap-3">
          <span>{error}</span>
          <button
            type="button"
            onClick={() => void loadSnapshot(true)}
            className="text-xs font-medium underline hover:no-underline cursor-pointer"
          >
            Reintentar
          </button>
        </div>
      )}

      {/* 4 tarjetas unificadas de métricas + sparklines interactivos (cero KPIs duplicados) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <SparklineCard
          title="Latencia HTTP (p95)"
          value={loading ? '—' : (snapshot?.http?.latencyMs?.p95 != null ? (snapshot.http.latencyMs.p95 < 10 ? snapshot.http.latencyMs.p95.toFixed(2) : snapshot.http.latencyMs.p95.toFixed(1)) : '0.00')}
          unit="ms"
          detailLine={`p50 ${formatMs(snapshot?.http?.latencyMs?.p50)} · p99 ${formatMs(snapshot?.http?.latencyMs?.p99)}`}
          footerLine={`En curso: ${snapshot?.http?.inFlight ?? 0} · 4xx: ${snapshot?.http?.status?.['4xx'] ?? 0} · 5xx: ${snapshot?.http?.status?.['5xx'] ?? 0}`}
          points={history.map((h) => h.p95Ms)}
          timestamps={timestamps}
          accent="amber"
        />
        <SparklineCard
          title="Tráfico del panel"
          value={loading ? '—' : (snapshot?.http?.rps?.rps10s ?? 0).toFixed(1)}
          unit="req/s"
          detailLine={`${snapshot?.http?.requestsTotal ?? 0} peticiones totales registradas`}
          footerLine={`1 s: ${(snapshot?.http?.rps?.rps1s ?? 0).toFixed(1)} · 60 s: ${(snapshot?.http?.rps?.rps60s ?? 0).toFixed(2)} req/s`}
          points={history.map((h) => h.rps)}
          timestamps={timestamps}
        />
        <SparklineCard
          title="Memoria RSS del proceso"
          value={loading ? '—' : String(snapshot?.process?.memoryMb ?? 0)}
          unit="MB"
          detailLine={`Heap ${snapshot?.process?.heapUsedMb ?? 0} MB · Activo ${formatUptime(snapshot?.process?.uptimeSeconds ?? snapshot?.uptimeSeconds ?? 0)}`}
          footerLine={
            snapshot?.process
              ? `Host libre: ${snapshot.process.hostMemoryFreeMb ?? Math.max(0, (snapshot.process.hostMemoryTotalMb || 0) - (snapshot.process.hostMemoryUsedMb || 0))} / ${snapshot.process.hostMemoryTotalMb ?? 0} MB`
              : 'Midiendo memoria del host'
          }
          points={history.map((h) => h.rssMb)}
          timestamps={timestamps}
        />
        <SparklineCard
          title="Bucle de eventos (p95)"
          value={loading ? '—' : (snapshot?.eventLoop?.p95Ms != null ? snapshot.eventLoop.p95Ms.toFixed(1) : '0.0')}
          unit="ms"
          detailLine={
            snapshot
              ? `${snapshot.bootMs != null ? `Arranque ${snapshot.bootMs} ms · ` : ''}${snapshot.process?.nodeVersion || 'Node.js'}`
              : 'Midiendo arranque'
          }
          footerLine={
            snapshot?.eventLoop?.utilizationRatio != null
              ? `Uso del bucle: ${(snapshot.eventLoop.utilizationRatio * 100).toFixed(1)}%`
              : 'Midiendo utilización'
          }
          points={history.map((h) => h.elLagMs)}
          timestamps={timestamps}
        />
      </div>

      {/* Diagnóstico del sistema (Doctor) */}
      <section className="bg-white border border-slate-200 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <Activity className="w-4 h-4 text-slate-700" />
            <div>
              <h2 className="text-sm font-semibold text-slate-900">Diagnóstico del sistema</h2>
              <p className="text-xs text-slate-500">
                Comprueba entorno Node.js, Docker, Caddy, disco, seguridad, dominios, copias y temporales.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2.5">
            {doctor && (
              <span
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border tabular-nums ${
                  doctor.overall === 'ok'
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : doctor.overall === 'warn'
                      ? 'bg-amber-50 text-amber-800 border-amber-200'
                      : 'bg-red-50 text-red-700 border-red-200'
                }`}
              >
                {doctor.overall === 'ok' && <CheckCircle2 className="w-3.5 h-3.5" />}
                {doctor.overall === 'warn' && <AlertTriangle className="w-3.5 h-3.5" />}
                {doctor.overall === 'fail' && <ShieldAlert className="w-3.5 h-3.5" />}
                {doctor.summary.ok}/{doctor.checks.length} correctas · {doctor.durationMs} ms
              </span>
            )}
            <button
              type="button"
              onClick={() => void loadDoctor(true)}
              disabled={doctorRunning}
              className="px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-900 text-white hover:bg-slate-800 transition-colors cursor-pointer disabled:opacity-50 flex items-center gap-1.5"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${doctorRunning ? 'animate-spin' : ''}`} />
              {doctorRunning ? 'Analizando…' : 'Ejecutar diagnóstico'}
            </button>
          </div>
        </div>

        <div className="divide-y divide-slate-200">
          {!doctor ? (
            <div className="p-6 text-center text-sm text-slate-500">Ejecutando comprobaciones reales del servidor…</div>
          ) : (
            doctor.checks.map((check) => (
              <div key={check.id} className="px-5 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-start gap-3 min-w-0">
                  <div className="mt-0.5 shrink-0">
                    {check.status === 'ok' && <CheckCircle2 className="w-4 h-4 text-emerald-600" />}
                    {check.status === 'warn' && <AlertTriangle className="w-4 h-4 text-amber-600" />}
                    {check.status === 'fail' && <XCircle className="w-4 h-4 text-red-600" />}
                  </div>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-medium text-slate-900">{check.name}</span>
                      <span className="text-xs text-slate-600 font-mono tabular-nums">{check.summary}</span>
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">{check.detail}</p>
                  </div>
                </div>
                {check.fixAction && check.fixLabel && (
                  <button
                    type="button"
                    onClick={() => void handleFix(check)}
                    disabled={fixingAction !== null}
                    className="shrink-0 self-start sm:self-center px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-300 bg-white text-slate-900 hover:bg-slate-50 transition-colors cursor-pointer disabled:opacity-50 flex items-center gap-1.5"
                  >
                    <Wrench className="w-3.5 h-3.5" />
                    {fixingAction === check.fixAction ? 'Aplicando…' : check.fixLabel}
                  </button>
                )}
              </div>
            ))
          )}
        </div>
      </section>

      {/* Tabla de rutas activas + Live Sync / Caddy */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <section className="lg:col-span-2 bg-white border border-slate-200 rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-200 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-900">Rutas más activas</h2>
            <span className="text-xs text-slate-500 font-mono">GET /metrics</span>
          </div>
          {!snapshot || !snapshot.http?.topRoutes?.length ? (
            <div className="p-6 text-sm text-slate-500 text-center">Sin tráfico registrado todavía.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 text-[11px] uppercase tracking-wider text-slate-500">
                    <th className="py-2.5 px-3 sm:px-5 font-medium">Ruta</th>
                    <th className="py-2.5 px-2 sm:px-4 font-medium text-right">Req</th>
                    <th className="py-2.5 px-2 sm:px-4 font-medium text-right">Media</th>
                    <th className="py-2.5 px-3 sm:px-5 font-medium text-right">Err</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 text-xs">
                  {snapshot.http.topRoutes.map((r) => (
                    <tr key={r.route} className="hover:bg-slate-50/70">
                      <td className="py-2.5 px-3 sm:px-5 font-mono text-slate-800 truncate max-w-[160px] sm:max-w-[260px]">{r.route}</td>
                      <td className="py-2.5 px-2 sm:px-4 text-right font-mono tabular-nums text-slate-700">{r.count}</td>
                      <td className="py-2.5 px-2 sm:px-4 text-right font-mono tabular-nums text-slate-700">{formatMs(r.avgMs)}</td>
                      <td className={`py-2.5 px-3 sm:px-5 text-right font-mono tabular-nums ${r.errors > 0 ? 'text-red-600 font-medium' : 'text-slate-400'}`}>
                        {r.errors}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="bg-white border border-slate-200 rounded-xl p-5 flex flex-col justify-between space-y-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-900">Plano de datos y tiempo real</h2>
            <p className="text-xs text-slate-500 mt-0.5">WebSocket, Live Sync y conmutación atómica Caddy.</p>
          </div>
          <dl className="space-y-2.5 text-xs">
            <div className="flex items-center justify-between py-1.5 border-b border-slate-100">
              <dt className="text-slate-500">Paneles conectados (WS)</dt>
              <dd className="font-mono font-medium text-slate-900 tabular-nums">{snapshot?.websocket?.telemetryClients ?? 0}</dd>
            </div>
            <div className="flex items-center justify-between py-1.5 border-b border-slate-100">
              <dt className="text-slate-500">Agentes Live Sync</dt>
              <dd className="font-mono font-medium text-slate-900 tabular-nums">{snapshot?.websocket?.syncClients ?? 0}</dd>
            </div>
            <div className="flex items-center justify-between py-1.5 border-b border-slate-100">
              <dt className="text-slate-500">Cambios aplicados / volumen</dt>
              <dd className="font-mono font-medium text-slate-900 tabular-nums">
                {snapshot?.liveSync?.framesApplied ?? 0} · {formatBytes(snapshot?.liveSync?.bytesSynced ?? 0)}
              </dd>
            </div>
            <div className="flex items-center justify-between py-1.5 border-b border-slate-100">
              <dt className="text-slate-500">Latencia Live Sync (p50 / p95)</dt>
              <dd className="font-mono font-medium text-slate-900 tabular-nums">
                {formatMs(snapshot?.liveSync?.applyLatencyMs?.p50)} / {formatMs(snapshot?.liveSync?.applyLatencyMs?.p95)}
              </dd>
            </div>
            <div className="flex items-center justify-between py-1.5">
              <dt className="text-slate-500">Caddy ({snapshot?.caddy?.managedRoutes ?? 0} rutas)</dt>
              <dd className="font-mono font-medium text-slate-900 tabular-nums">
                {snapshot?.caddy?.swapsTotal ?? 0} cambios ({formatMs(snapshot?.caddy?.swapLatencyMs?.p50)})
              </dd>
            </div>
          </dl>
        </section>
      </div>
    </div>
  );
};
