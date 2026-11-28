import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Bell,
  BellOff,
  Check,
  CheckCircle2,
  Copy,
  Database,
  Globe,
  Link2,
  Loader2,
  Maximize2,
  Network,
  Plus,
  Radio,
  RefreshCw,
  Send,
  Server,
  ShieldAlert,
  SlidersHorizontal,
  Trash2,
  TrendingDown,
  Wrench,
  X,
  XCircle,
  ZoomIn,
  ZoomOut,
  Receipt,
  FileSpreadsheet,
  Download,
} from 'lucide-react';
import {
  api,
  apiFetch,
  type DoctorCheck,
  type FinOpsReportResult,
  type ObservabilityHistoryPoint,
  type ObservabilitySnapshot,
  type OtlpStatusResult,
  type SystemDoctorReport,
  type BillingLedgerResult,
  type ResourceRightsizeResult,
  type BillingLedgerProjectRow,
  type TenantQuotaSpec,
} from '../lib/api';
import { copyToClipboard } from '../lib/clipboard';
import { useI18n } from '../lib/i18n';
import { useTheme } from '../lib/theme';

interface ObservabilityViewProps {
  onNotify: (msg: string, type?: 'success' | 'info' | 'error') => void;
}

type ObsTab = 'overview' | 'alerts' | 'topology';
type HistoryRange = 'live' | '1h' | '24h' | '7d';

interface ExtendedHistoryPoint extends ObservabilityHistoryPoint {
  hostCpuPct?: number;
  hostRamPct?: number;
  diskUsedPct?: number | null;
  errorRatePct?: number;
  err5xxRatePct?: number;
}

interface DeployMarker {
  ts: number;
  projectId?: string | null;
  projectName: string;
  status: string;
  label: string;
}

interface AlertRule {
  id: string;
  name: string;
  metric: string;
  operator: string;
  threshold: number;
  severity: 'info' | 'warning' | 'critical';
  consecutiveRequired: number;
  cooldownMs: number;
  enabled: boolean;
  builtin?: boolean;
  description?: string;
  silencedUntil?: string | null;
}

interface AlertRecord {
  id: string;
  ruleId: string;
  ruleName: string;
  metric: string;
  severity: 'info' | 'warning' | 'critical';
  target: string;
  value: number;
  detail: string;
  status: 'firing' | 'resolved';
  acknowledged?: boolean;
  firedAt: string;
  resolvedAt?: string | null;
  durationMs?: number | null;
}

interface TopologyNode {
  id: string;
  kind: 'domain' | 'monitor' | 'project' | 'database' | 'cache' | 'catalog' | 'server';
  entityId?: string;
  label: string;
  sublabel?: string;
  status: string;
  health: 'healthy' | 'degraded' | 'down' | 'sleeping' | 'unknown';
  meta?: Record<string, any>;
}

interface TopologyEdge {
  id: string;
  from: string;
  to: string;
  kind: string;
  label: string;
  status: string;
}

interface TopologyGraph {
  generatedAt: string;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  summary: {
    totalNodes: number;
    totalEdges: number;
    servers: number;
    projects: number;
    databases: number;
    catalogServices: number;
    domains: number;
    monitors: number;
    unhealthyNodes: number;
  };
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

function formatDurationMs(ms: number | null | undefined): string {
  if (ms == null || !Number.isFinite(ms)) return '—';
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

function formatCooldown(ms: number): string {
  if (!ms) return '0m';
  const min = Math.round(ms / 60000);
  if (min < 60) return `${min}m`;
  return `${Math.round(min / 60)}h`;
}

interface SparklineCardProps {
  title: string;
  value: string;
  unit?: string;
  detailLine: string;
  footerLine: string;
  points: number[];
  timestamps?: number[];
  markers?: DeployMarker[];
  accent?: 'ink' | 'amber' | 'red' | 'emerald';
  maxScale?: number;
}

const SparklineCard: React.FC<SparklineCardProps> = ({
  title,
  value,
  unit,
  detailLine,
  footerLine,
  points,
  timestamps = [],
  markers = [],
  accent = 'ink',
  maxScale,
}) => {
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
  const width = 260;
  const height = 56;
  const padY = 6;
  const values = points.length >= 2 ? points : [points[0] ?? 0, points[0] ?? 0];
  const minVal = Math.min(...values, 0);
  const maxVal = Math.max(...values, maxScale ?? minVal + 1, minVal + 1);
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
    ? new Date(timestamps[hoverIdx]).toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' })
    : null;

  const firstTs = timestamps.length >= 2 ? timestamps[0] : 0;
  const lastTs = timestamps.length >= 2 ? timestamps[timestamps.length - 1] : 0;
  const markerPositions = (firstTs > 0 && lastTs > firstTs)
    ? markers
        .filter((m) => m.ts >= firstTs && m.ts <= lastTs)
        .slice(-6)
        .map((m) => ({
          ...m,
          x: ((m.ts - firstTs) / (lastTs - firstTs)) * width,
        }))
    : [];

  const strokeColor =
    accent === 'red' ? '#dc2626' : accent === 'amber' ? '#d97706' : accent === 'emerald' ? '#059669' : '#18181b';
  const fillColor =
    accent === 'red'
      ? 'rgb(220 38 38 / 0.08)'
      : accent === 'amber'
        ? 'rgb(217 119 6 / 0.08)'
        : accent === 'emerald'
          ? 'rgb(5 150 105 / 0.08)'
          : 'rgb(24 24 27 / 0.05)';

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
          {markerPositions.map((m, i) => (
            <g key={`mk-${m.ts}-${i}`}>
              <line
                x1={m.x}
                y1={0}
                x2={m.x}
                y2={height}
                stroke="#0ea5e9"
                strokeWidth="1"
                strokeDasharray="2 2"
                vectorEffect="non-scaling-stroke"
              >
                <title>{`${m.label} (${new Date(m.ts).toLocaleTimeString('es-ES')})`}</title>
              </line>
              <circle cx={m.x} cy={4} r="2.3" fill="#0ea5e9">
                <title>{m.label}</title>
              </circle>
            </g>
          ))}
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

const HEALTH_DOT: Record<string, string> = {
  healthy: 'bg-emerald-500',
  degraded: 'bg-amber-500',
  down: 'bg-red-500',
  sleeping: 'bg-sky-500',
  unknown: 'bg-slate-400',
};

const HEALTH_STROKE: Record<string, string> = {
  healthy: '#10b981',
  degraded: '#f59e0b',
  down: '#ef4444',
  sleeping: '#0ea5e9',
  unknown: '#94a3b8',
};

const KIND_ICON: Record<string, React.FC<{ className?: string }>> = {
  domain: Globe,
  monitor: Radio,
  project: Activity,
  database: Database,
  cache: Database,
  catalog: Database,
  server: Server,
};

const METRIC_LABELS: Record<string, string> = {
  host_ram_pct: 'RAM del host (%)',
  host_disk_pct: 'Disco del servidor (%)',
  host_cpu_pct: 'CPU del host (%)',
  container_oom: 'Contenedor OOMKilled',
  container_restart_count: 'Reinicios de contenedor',
  tls_days_remaining: 'Días restantes TLS',
  uptime_down_count: 'Monitores caídos',
  http_5xx_rate_pct: 'Errores HTTP 5xx (%)',
  event_loop_lag_ms: 'Event loop lag (ms)',
};

export const ObservabilityView: React.FC<ObservabilityViewProps> = ({ onNotify }) => {
  const [activeTab, setActiveTab] = useState<ObsTab>('overview');
  const [range, setRange] = useState<HistoryRange>('live');
  const [snapshot, setSnapshot] = useState<ObservabilitySnapshot | null>(null);
  const [rangePoints, setRangePoints] = useState<ExtendedHistoryPoint[]>([]);
  const [deployMarkers, setDeployMarkers] = useState<DeployMarker[]>([]);
  const [doctor, setDoctor] = useState<SystemDoctorReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [doctorRunning, setDoctorRunning] = useState(false);
  const [fixingAction, setFixingAction] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [copiedProm, setCopiedProm] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Alert Engine state
  const [alertRules, setAlertRules] = useState<AlertRule[]>([]);
  const [activeAlerts, setActiveAlerts] = useState<AlertRecord[]>([]);
  const [alertHistory, setAlertHistory] = useState<AlertRecord[]>([]);
  const [alertsSupported, setAlertsSupported] = useState(true);
  const [alertBusy, setAlertBusy] = useState<string | null>(null);
  const [alertsNowMs, setAlertsNowMs] = useState<number>(() => Date.now());
  const [showNewRule, setShowNewRule] = useState(false);
  const [newRule, setNewRule] = useState({
    name: '',
    metric: 'host_ram_pct',
    operator: '>',
    threshold: '90',
    severity: 'warning' as 'info' | 'warning' | 'critical',
    consecutiveRequired: '2',
    cooldownMin: '30',
  });

  // Topology state (Spatial Pan/Zoom SVG Canvas)
  const { t, locale } = useI18n();
  const { isDark } = useTheme();
  const [topology, setTopology] = useState<TopologyGraph | null>(null);
  const [topologyLoading, setTopologyLoading] = useState(false);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [topoZoom, setTopoZoom] = useState<number>(1);
  const [topoPan, setTopoPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [linkTargetProjectId, setLinkTargetProjectId] = useState<string>('');
  const [linkingDb, setLinkingDb] = useState(false);
  const topoDragRef = useRef<{ startX: number; startY: number; originX: number; originY: number; moved: boolean } | null>(null);

  // Native Zero-Dep OTLP Exporter state
  const [otlpStatus, setOtlpStatus] = useState<OtlpStatusResult | null>(null);
  const [otlpDrawerOpen, setOtlpDrawerOpen] = useState(false);
  const [otlpEnabled, setOtlpEnabled] = useState(false);
  const [otlpEndpoint, setOtlpEndpoint] = useState('');
  const [otlpServiceName, setOtlpServiceName] = useState('culkibo-control-plane');
  const [otlpAuthHeader, setOtlpAuthHeader] = useState('');
  const [otlpSaving, setOtlpSaving] = useState(false);
  const [otlpFlushing, setOtlpFlushing] = useState(false);

  // Cycle-6 FinOps & Cloud Savings state
  const [finops, setFinops] = useState<FinOpsReportResult | null>(null);
  const [finopsApps, setFinopsApps] = useState<string>('3');
  const [finopsDbs, setFinopsDbs] = useState<string>('2');
  const [finopsBusy, setFinopsBusy] = useState(false);

  // Cycle-9 Agency Multi-Tenant Quotas & Billing Usage Ledger state
  const [billingPeriod, setBillingPeriod] = useState<number>(30);
  const [billingLedger, setBillingLedger] = useState<BillingLedgerResult | null>(null);
  const [tenantQuotas, setTenantQuotas] = useState<Record<string, TenantQuotaSpec>>({});
  const [csvPreview, setCsvPreview] = useState<string | null>(null);
  const [csvBusy, setCsvBusy] = useState(false);
  const [copiedCsv, setCopiedCsv] = useState(false);

  // Cycle-17 VPA-Lite Container Resource Rightsizer (dokploy#4050 / #903)
  const [vpaResult, setVpaResult] = useState<ResourceRightsizeResult | null>(null);
  const [vpaPatchYaml, setVpaPatchYaml] = useState<string | null>(null);
  const [vpaBusy, setVpaBusy] = useState<'shrink' | 'oom' | null>(null);
  const [vpaError, setVpaError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api.getOtlpStatus()
      .then((st) => {
        if (!active || !st) return;
        setOtlpStatus(st);
        setOtlpEnabled(Boolean(st.enabled));
        setOtlpEndpoint(st.endpoint || '');
        if (st.serviceName) setOtlpServiceName(st.serviceName);
      })
      .catch(() => {
        // optional endpoint
      });
    api.getFinOpsReport()
      .then((rep) => {
        if (active && rep) setFinops(rep);
      })
      .catch(() => {
        // optional endpoint
      });
    Promise.all([
      api.getBillingLedger(30).catch(() => null),
      api.listTenantQuotas().catch(() => null),
    ]).then(([ledgerRes, quotasRes]) => {
      if (!active) return;
      if (ledgerRes) setBillingLedger(ledgerRes);
      if (quotasRes) {
        if (Array.isArray(quotasRes.quotas)) {
          const map: Record<string, TenantQuotaSpec> = {};
          for (const q of quotasRes.quotas) {
            if (q?.projectId) map[q.projectId] = q;
          }
          setTenantQuotas(map);
        } else if (quotasRes.quotas && typeof quotasRes.quotas === 'object') {
          setTenantQuotas(quotasRes.quotas);
        }
      }
    });
    return () => { active = false; };
  }, []);

  const handleChangeBillingPeriod = async (days: number) => {
    setBillingPeriod(days);
    try {
      const next = await api.getBillingLedger(days);
      setBillingLedger(next);
      if (csvPreview !== null) {
        const csv = await api.getBillingLedgerCsv(days).catch(() => null);
        if (csv != null) setCsvPreview(csv);
      }
    } catch (err: unknown) {
      onNotify(err instanceof Error ? err.message : 'Could not refresh billing ledger', 'error');
    }
  };

  const handleToggleCsvPreview = async () => {
    if (csvPreview !== null) {
      setCsvPreview(null);
      return;
    }
    setCsvBusy(true);
    try {
      const csv = await api.getBillingLedgerCsv(billingPeriod);
      setCsvPreview(csv);
    } catch (err: unknown) {
      onNotify(err instanceof Error ? err.message : 'Could not load formula-safe CSV ledger', 'error');
    } finally {
      setCsvBusy(false);
    }
  };

  const handleDownloadCsv = () => {
    if (!csvPreview) return;
    const blob = new Blob([csvPreview], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `culkibo-billing-ledger-${billingPeriod}d.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleRunVpaRightsize = async (mode: 'shrink' | 'oom') => {
    setVpaBusy(mode);
    setVpaError(null);
    try {
      const isOom = mode === 'oom';
      const samples = isOom
        ? Array.from({ length: 12 }, (_, i) => ({ memoryMb: 460 + i * 5, cpuCores: 0.72 + (i % 3) * 0.04 }))
        : Array.from({ length: 12 }, (_, i) => ({ memoryMb: 340 + (i % 4) * 18, cpuCores: 0.24 + (i % 3) * 0.04 }));
      const analysis = await api.analyzeResourceRightsize({
        projectId: isOom ? 'proj_ai_worker' : 'proj_acme_web',
        serviceName: isOom ? 'ai-worker-py' : 'acme-saas-web',
        serviceType: 'app',
        currentMemoryMb: isOom ? 512 : 2048,
        currentCpuCores: isOom ? 1 : 2,
        samples,
        oomCount: isOom ? 2 : 0,
      });
      setVpaResult(analysis);
      const patchRes = await api.buildRightsizePatch({ recommendation: analysis, dryRun: true }).catch(() => null);
      const yaml =
        patchRes?.yaml ||
        patchRes?.patchYaml ||
        (analysis.composePatch && typeof analysis.composePatch.yaml === 'string' ? analysis.composePatch.yaml : null) ||
        analysis.patchYaml ||
        analysis.yaml ||
        (patchRes?.patch ? JSON.stringify(patchRes.patch, null, 2) : null);
      setVpaPatchYaml(yaml);
      onNotify(
        isOom
          ? `VPA OOM Safety Lock: ${analysis.action} -> ${analysis.recommendedMemoryMb ?? 768} MB (+50% headroom)`
          : `VPA Rightsizer: ${analysis.action} reclaims ${analysis.reclaimableMb ?? 0} MB (${analysis.wastePct ?? 0}% waste)`,
        isOom ? 'info' : 'success'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'VPA rightsizing failed';
      setVpaError(msg);
      onNotify(msg, 'error');
    } finally {
      setVpaBusy(null);
    }
  };

  const handleRecalcFinops = async (e: React.FormEvent) => {
    e.preventDefault();
    setFinopsBusy(true);
    try {
      const cmp = await api.compareCloudFinOps({
        apps: Math.max(1, Number(finopsApps) || 3),
        databases: Math.max(0, Number(finopsDbs) || 0),
      });
      setFinops((prev) => ({
        ...(prev || {}),
        ...cmp,
        comparison: cmp,
      }));
    } catch (err: unknown) {
      onNotify(err instanceof Error ? err.message : 'FinOps comparison error', 'error');
    } finally {
      setFinopsBusy(false);
    }
  };

  const handleSaveOtlp = async (e: React.FormEvent) => {
    e.preventDefault();
    setOtlpSaving(true);
    try {
      const payload: { enabled: boolean; endpoint: string; serviceName: string; headers?: Record<string, string> } = {
        enabled: otlpEnabled,
        endpoint: otlpEndpoint.trim(),
        serviceName: otlpServiceName.trim() || 'culkibo-control-plane',
      };
      if (otlpAuthHeader.trim()) {
        payload.headers = { Authorization: otlpAuthHeader.trim() };
      }
      const next = await api.updateOtlpConfig(payload);
      setOtlpStatus(next);
      setOtlpAuthHeader('');
      onNotify(t('obs.otlpSaved'), 'success');
    } catch (err: unknown) {
      onNotify(err instanceof Error ? err.message : 'OTLP update failed', 'error');
    } finally {
      setOtlpSaving(false);
    }
  };

  const handleFlushOtlp = async () => {
    setOtlpFlushing(true);
    try {
      const res = await api.flushOtlp();
      if (res.status) setOtlpStatus(res.status);
      else {
        const refreshed = await api.getOtlpStatus().catch(() => null);
        if (refreshed) setOtlpStatus(refreshed);
      }
      onNotify(t('obs.otlpFlushed', { count: res.flushed ?? 0 }), 'info');
    } catch (err: unknown) {
      onNotify(err instanceof Error ? err.message : 'OTLP flush failed', 'error');
    } finally {
      setOtlpFlushing(false);
    }
  };

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

  const loadRangeHistory = useCallback(async (targetRange: HistoryRange) => {
    if (targetRange === 'live') {
      setRangePoints([]);
      return;
    }
    try {
      const res = await apiFetch(`/api/observability/history?range=${encodeURIComponent(targetRange)}`);
      if (!res.ok) {
        setRangePoints([]);
        return;
      }
      const data = await res.json();
      setRangePoints(Array.isArray(data.points) ? data.points : []);
      setDeployMarkers(Array.isArray(data.markers) ? data.markers : []);
    } catch {
      setRangePoints([]);
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

  const loadAlerts = useCallback(async () => {
    try {
      const [rulesRes, activeRes, histRes] = await Promise.all([
        apiFetch('/api/alerts/rules'),
        apiFetch('/api/alerts/active'),
        apiFetch('/api/alerts/history?limit=40'),
      ]);
      if (rulesRes.status === 404) {
        setAlertsSupported(false);
        return;
      }
      setAlertsSupported(true);
      if (rulesRes.ok) {
        const d = await rulesRes.json();
        setAlertRules(Array.isArray(d.rules) ? d.rules : []);
      }
      if (activeRes.ok) {
        const d = await activeRes.json();
        setActiveAlerts(Array.isArray(d.alerts) ? d.alerts : []);
      }
      if (histRes.ok) {
        const d = await histRes.json();
        setAlertHistory(Array.isArray(d.history) ? d.history : []);
      }
      setAlertsNowMs(Date.now());
    } catch {
      setAlertsSupported(false);
    }
  }, []);

  const buildFallbackTopology = useCallback(async (): Promise<TopologyGraph> => {
    const [projects, domainsRes, dbsRes, monsRes] = await Promise.all([
      api.getProjects().catch(() => []),
      api.getDomains().catch(() => ({ domains: [] as any[] })),
      api.getDatabases().catch(() => ({ databases: [] as any[] })),
      api.getUptimeMonitors().catch(() => ({ monitors: [] as any[] })),
    ]);
    const nodes: TopologyNode[] = [
      { id: 'server:local', kind: 'server', label: 'Servidor Local', sublabel: 'nodo principal', status: 'online', health: 'healthy' },
    ];
    const edges: TopologyEdge[] = [];
    const projIds = new Set<string>();

    for (const p of Array.isArray(projects) ? projects : []) {
      projIds.add(p.id);
      const h = p.status === 'active' ? 'healthy' : p.status === 'hibernated' || p.status === 'sleeping' ? 'sleeping' : 'unknown';
      nodes.push({
        id: `project:${p.id}`,
        kind: 'project',
        entityId: p.id,
        label: p.name,
        sublabel: `${p.memoryMb || 512} MB RAM`,
        status: p.status,
        health: h,
        meta: { memoryMb: p.memoryMb || 512 },
      });
      edges.push({ id: `e_srv_${p.id}`, from: `project:${p.id}`, to: 'server:local', kind: 'runs_on', label: 'local', status: 'healthy' });
    }
    for (const d of (domainsRes as any)?.domains || []) {
      nodes.push({
        id: `domain:${d.id || d.hostname}`,
        kind: 'domain',
        label: d.hostname,
        sublabel: d.cloudflareProxied ? 'Cloudflare' : 'Caddy TLS',
        status: d.status || 'active',
        health: d.status === 'disabled' ? 'degraded' : 'healthy',
      });
      if (d.projectId && projIds.has(d.projectId)) {
        edges.push({ id: `e_dom_${d.id || d.hostname}`, from: `domain:${d.id || d.hostname}`, to: `project:${d.projectId}`, kind: 'routes_to', label: 'HTTPS', status: 'healthy' });
      }
    }
    for (const db of (dbsRes as any)?.databases || []) {
      const isCache = ['redis', 'valkey', 'dragonfly'].includes(String(db.engine || '').toLowerCase());
      nodes.push({
        id: `database:${db.id}`,
        kind: isCache ? 'cache' : 'database',
        label: db.name || db.id,
        sublabel: db.engine || 'db',
        status: db.status || 'running',
        health: db.status === 'running' ? 'healthy' : 'degraded',
      });
      if (db.projectId && projIds.has(db.projectId)) {
        edges.push({ id: `e_db_${db.id}`, from: `project:${db.projectId}`, to: `database:${db.id}`, kind: isCache ? 'uses_cache' : 'uses_database', label: db.engine || 'db', status: 'healthy' });
      }
    }
    for (const m of monsRes.monitors || []) {
      const mh = m.status === 'up' ? 'healthy' : m.status === 'down' ? 'down' : m.status === 'degraded' ? 'degraded' : 'unknown';
      nodes.push({
        id: `monitor:${m.id}`,
        kind: 'monitor',
        label: m.name,
        sublabel: m.uptime24h != null ? `${m.uptime24h}%` : m.type,
        status: m.status,
        health: mh,
      });
      if (m.projectId && projIds.has(m.projectId)) {
        edges.push({ id: `e_mon_${m.id}`, from: `monitor:${m.id}`, to: `project:${m.projectId}`, kind: 'monitors', label: `${m.intervalSec}s`, status: mh });
      }
    }
    return {
      generatedAt: new Date().toISOString(),
      nodes,
      edges,
      summary: {
        totalNodes: nodes.length,
        totalEdges: edges.length,
        servers: 1,
        projects: projIds.size,
        databases: nodes.filter((n) => n.kind === 'database' || n.kind === 'cache').length,
        catalogServices: 0,
        domains: nodes.filter((n) => n.kind === 'domain').length,
        monitors: nodes.filter((n) => n.kind === 'monitor').length,
        unhealthyNodes: nodes.filter((n) => n.health === 'down' || n.health === 'degraded').length,
      },
    };
  }, []);

  const loadTopology = useCallback(async () => {
    setTopologyLoading(true);
    try {
      const res = await apiFetch('/api/topology');
      if (res.ok) {
        const data = await res.json();
        if (data && Array.isArray(data.nodes) && Array.isArray(data.edges)) {
          setTopology(data);
        } else {
          setTopology(await buildFallbackTopology());
        }
      } else {
        setTopology(await buildFallbackTopology());
      }
    } catch {
      setTopology(await buildFallbackTopology());
    } finally {
      setTopologyLoading(false);
    }
  }, [buildFallbackTopology]);

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
        if (!active) return;
        setLoading(false);
        setRefreshing(false);
      });

    api.getSystemDoctor()
      .then((report) => {
        if (active) setDoctor(report);
      })
      .catch((e: any) => {
        if (active) onNotify(e?.message || 'No se pudo ejecutar el diagnóstico del sistema', 'error');
      });

    Promise.all([
      apiFetch('/api/alerts/rules'),
      apiFetch('/api/alerts/active'),
      apiFetch('/api/alerts/history?limit=40'),
    ])
      .then(async ([rulesRes, activeRes, histRes]) => {
        if (!active) return;
        if (rulesRes.status === 404) {
          setAlertsSupported(false);
          return;
        }
        setAlertsSupported(true);
        if (rulesRes.ok) {
          const d = await rulesRes.json();
          if (active) setAlertRules(Array.isArray(d.rules) ? d.rules : []);
        }
        if (activeRes.ok) {
          const d = await activeRes.json();
          if (active) setActiveAlerts(Array.isArray(d.alerts) ? d.alerts : []);
        }
        if (histRes.ok) {
          const d = await histRes.json();
          if (active) setAlertHistory(Array.isArray(d.history) ? d.history : []);
        }
        if (active) setAlertsNowMs(Date.now());
      })
      .catch(() => {
        if (active) setAlertsSupported(false);
      });

    return () => { active = false; };
  }, [onNotify]);

  useEffect(() => {
    if (range === 'live') return;
    let active = true;
    apiFetch(`/api/observability/history?range=${encodeURIComponent(range)}`)
      .then(async (res) => {
        if (!active) return;
        if (!res.ok) {
          setRangePoints([]);
          return;
        }
        const data = await res.json();
        if (!active) return;
        setRangePoints(Array.isArray(data.points) ? data.points : []);
        setDeployMarkers(Array.isArray(data.markers) ? data.markers : []);
      })
      .catch(() => {
        if (active) setRangePoints([]);
      });
    return () => { active = false; };
  }, [range]);

  useEffect(() => {
    if (activeTab !== 'topology' || topology) return;
    let active = true;
    apiFetch('/api/topology')
      .then(async (res) => {
        if (res.ok) return res.json();
        return buildFallbackTopology();
      })
      .catch(() => buildFallbackTopology())
      .then((data) => {
        if (active) setTopology(data);
      });
    return () => { active = false; };
  }, [activeTab, topology, buildFallbackTopology]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = window.setInterval(() => {
      void loadSnapshot(false);
      if (range !== 'live') void loadRangeHistory(range);
      if (activeTab === 'alerts') void loadAlerts();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, range, activeTab, loadSnapshot, loadRangeHistory, loadAlerts]);

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

  const handleToggleRule = async (rule: AlertRule) => {
    setAlertBusy(rule.id);
    try {
      const res = await apiFetch(`/api/alerts/rules/${encodeURIComponent(rule.id)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !rule.enabled }),
      });
      if (!res.ok) throw new Error('No se pudo actualizar la regla');
      onNotify(`Regla «${rule.name}» ${rule.enabled ? 'pausada' : 'activada'}`, 'success');
      await loadAlerts();
    } catch (e: any) {
      onNotify(e?.message || 'Error actualizando la regla', 'error');
    } finally {
      setAlertBusy(null);
    }
  };

  const handleSilenceRule = async (rule: AlertRule, minutes: number) => {
    setAlertBusy(`sil-${rule.id}`);
    try {
      const res = await apiFetch(`/api/alerts/rules/${encodeURIComponent(rule.id)}/silence`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ durationMinutes: minutes }),
      });
      if (!res.ok) throw new Error('No se pudo silenciar la regla');
      onNotify(minutes > 0 ? `Regla silenciada durante ${minutes} min` : 'Silencio desactivado', 'info');
      await loadAlerts();
    } catch (e: any) {
      onNotify(e?.message || 'Error al silenciar la regla', 'error');
    } finally {
      setAlertBusy(null);
    }
  };

  const handleDeleteRule = async (rule: AlertRule) => {
    setAlertBusy(`del-${rule.id}`);
    try {
      const res = await apiFetch(`/api/alerts/rules/${encodeURIComponent(rule.id)}`, { method: 'DELETE' });
      if (!res.ok) throw new Error('No se pudo eliminar la regla');
      onNotify(`Regla «${rule.name}» eliminada`, 'info');
      await loadAlerts();
    } catch (e: any) {
      onNotify(e?.message || 'Error al eliminar la regla', 'error');
    } finally {
      setAlertBusy(null);
    }
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRule.name.trim()) return;
    setAlertBusy('create-rule');
    try {
      const res = await apiFetch('/api/alerts/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newRule.name.trim(),
          metric: newRule.metric,
          operator: newRule.operator,
          threshold: Number(newRule.threshold),
          severity: newRule.severity,
          consecutiveRequired: Math.max(1, Number(newRule.consecutiveRequired) || 1),
          cooldownMs: Math.max(0, Number(newRule.cooldownMin) || 15) * 60 * 1000,
          enabled: true,
        }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.error || 'No se pudo crear la regla');
      }
      setShowNewRule(false);
      setNewRule({ name: '', metric: 'host_ram_pct', operator: '>', threshold: '90', severity: 'warning', consecutiveRequired: '2', cooldownMin: '30' });
      onNotify('Regla de alerta creada y activa', 'success');
      await loadAlerts();
    } catch (err: any) {
      onNotify(err?.message || 'Error al crear la regla', 'error');
    } finally {
      setAlertBusy(null);
    }
  };

  const handleAckAlert = async (alertId: string) => {
    setAlertBusy(`ack-${alertId}`);
    try {
      const res = await apiFetch(`/api/alerts/active/${encodeURIComponent(alertId)}/ack`, { method: 'POST' });
      if (!res.ok) throw new Error('No se pudo reconocer la alerta');
      onNotify('Alerta reconocida', 'info');
      await loadAlerts();
    } catch (e: any) {
      onNotify(e?.message || 'Error al reconocer la alerta', 'error');
    } finally {
      setAlertBusy(null);
    }
  };

  const handleEvaluateNow = async () => {
    setAlertBusy('eval');
    try {
      const res = await apiFetch('/api/alerts/evaluate', { method: 'POST' });
      if (!res.ok) throw new Error('No se pudo evaluar las alertas');
      onNotify('Evaluación de alertas completada', 'success');
      await loadAlerts();
    } catch (e: any) {
      onNotify(e?.message || 'Error al evaluar alertas', 'error');
    } finally {
      setAlertBusy(null);
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

  const history: ExtendedHistoryPoint[] = useMemo(() => {
    if (range !== 'live' && rangePoints.length > 0) return rangePoints;
    return (snapshot?.history || []) as ExtendedHistoryPoint[];
  }, [range, rangePoints, snapshot]);

  const timestamps = useMemo(() => history.map((h) => h.ts), [history]);
  const procAny = snapshot?.process as any;
  const httpAny = snapshot?.http as any;

  // Topology layout calculation (pure SVG coordinates for crisp 4-column architecture map)
  const topologyLayout = useMemo(() => {
    if (!topology || !Array.isArray(topology.nodes)) return null;
    const nodes = topology.nodes || [];
    const cols: Array<{ title: string; kinds: TopologyNode['kind'][]; x: number }> = [
      { title: 'Dominios y Uptime', kinds: ['domain', 'monitor'], x: 24 },
      { title: 'Proyectos', kinds: ['project'], x: 268 },
      { title: 'Datos y Servicios', kinds: ['database', 'cache', 'catalog'], x: 512 },
      { title: 'Servidores', kinds: ['server'], x: 756 },
    ];
    const nodeW = 200;
    const nodeH = 62;
    const gapY = 18;
    const headerY = 38;
    const positioned = new Map<string, { node: TopologyNode; x: number; y: number }>();
    let maxColHeight = 160;

    for (const col of cols) {
      const colNodes = nodes.filter((n) => col.kinds.includes(n.kind));
      colNodes.forEach((node, idx) => {
        const y = headerY + idx * (nodeH + gapY);
        positioned.set(node.id, { node, x: col.x, y });
      });
      const h = headerY + colNodes.length * (nodeH + gapY) + 16;
      if (h > maxColHeight) maxColHeight = h;
    }

    return {
      cols,
      nodeW,
      nodeH,
      svgW: 980,
      svgH: Math.max(220, maxColHeight),
      positioned,
    };
  }, [topology]);

  const selectedNode = useMemo(
    () => (topology && Array.isArray(topology.nodes) && selectedNodeId ? topology.nodes.find((n) => n.id === selectedNodeId) || null : null),
    [topology, selectedNodeId]
  );

  const selectedEdges = useMemo(
    () => (topology && Array.isArray(topology.edges) && selectedNodeId ? topology.edges.filter((e) => e.from === selectedNodeId || e.to === selectedNodeId) : []),
    [topology, selectedNodeId]
  );

  const projectNodes = useMemo(
    () => (topology && Array.isArray(topology.nodes) ? topology.nodes.filter((n) => n.kind === 'project') : []),
    [topology]
  );

  const handleLinkDbToProject = async (dbNode: TopologyNode, targetProjNodeId: string) => {
    const projNode = projectNodes.find((p) => p.id === targetProjNodeId);
    if (!projNode) return;
    const dbEntityId = dbNode.entityId || dbNode.id.replace(/^(?:db|database|cache|service)[:_-]/, '');
    const projEntityId = projNode.entityId || projNode.id.replace(/^project[:_-]/, '');
    setLinkingDb(true);
    try {
      await api.linkProjectDatabase(projEntityId, dbEntityId);
      onNotify(t('topo.linkDbDone', { db: dbNode.label, project: projNode.label }), 'success');
      setLinkTargetProjectId('');
      await loadTopology();
    } catch (e: unknown) {
      onNotify(e instanceof Error ? e.message : 'Failed to link database to project', 'error');
    } finally {
      setLinkingDb(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Cabecera */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">{t('obs.title')}</h1>
          <p className="text-sm text-slate-500 mt-1">{t('obs.subtitle')}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setOtlpDrawerOpen((v) => !v)}
            title="Grafana Tempo / SigNoz / Honeycomb · 0 deps"
            className={`culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors cursor-pointer tabular-nums ${
              otlpDrawerOpen
                ? 'bg-slate-900 text-white border-slate-900'
                : otlpStatus?.enabled
                  ? 'bg-emerald-50 text-emerald-800 border-emerald-200 hover:bg-emerald-100'
                  : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
            }`}
          >
            <span className={`w-1.5 h-1.5 rounded-full ${otlpStatus?.enabled ? 'bg-emerald-500' : 'bg-slate-400'}`} />
            <span>{otlpStatus?.enabled ? t('obs.otlpActive') : t('obs.otlpStandby')}</span>
            <span className="font-mono text-[10px] opacity-75">
              {otlpStatus?.bufferedSpans != null ? `· ${otlpStatus.bufferedSpans}s` : '· 0 deps'}
            </span>
            <SlidersHorizontal className="w-3 h-3 opacity-70" />
          </button>

          <div className="inline-flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs">
            {([
              { id: 'overview', label: t('obs.tabOverview'), icon: Activity },
              { id: 'alerts', label: t('obs.tabAlerts'), icon: Bell, badge: activeAlerts.length },
              { id: 'topology', label: t('obs.tabTopology'), icon: Network },
            ] as const).map((tabItem) => {
              const Icon = tabItem.icon;
              return (
                <button
                  key={tabItem.id}
                  type="button"
                  onClick={() => setActiveTab(tabItem.id)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium whitespace-nowrap transition-colors cursor-pointer ${
                    activeTab === tabItem.id ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span>{tabItem.label}</span>
                  {'badge' in tabItem && tabItem.badge > 0 && (
                    <span className="px-1.5 py-0.2 rounded-full bg-red-600 text-white text-[10px] font-semibold tabular-nums">
                      {tabItem.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Native Zero-Dep OTLP Exporter Inline Drawer */}
      {otlpDrawerOpen && (
        <section className="culkibo-surface rounded-2xl p-4 sm:p-5 space-y-4 text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-200">
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-sm font-semibold text-slate-900">{t('obs.otlpDrawerTitle')}</h2>
                <span className="px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-600">
                  Grafana Tempo · SigNoz · Honeycomb
                </span>
              </div>
              <p className="text-slate-500 mt-0.5">{t('obs.otlpDrawerDesc')}</p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {otlpStatus && (
                <span className="px-2.5 py-1 rounded-full bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-700 tabular-nums">
                  buf {otlpStatus.bufferedSpans ?? 0}/{otlpStatus.maxBufferSize ?? 256} · sent {otlpStatus.totalExported ?? 0} · cb:{otlpStatus.circuitState || (otlpStatus.circuitOpen ? 'open' : 'closed')}
                </span>
              )}
              <button
                type="button"
                onClick={() => setOtlpDrawerOpen(false)}
                aria-label="Close OTLP config"
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          <form onSubmit={(e) => void handleSaveOtlp(e)} className="grid grid-cols-1 sm:grid-cols-12 gap-3 items-end">
            <label className="sm:col-span-4 block">
              <span className="font-medium text-slate-700 block mb-1">{t('obs.otlpEndpoint')}</span>
              <input
                type="url"
                value={otlpEndpoint}
                onChange={(e) => setOtlpEndpoint(e.target.value)}
                placeholder="https://otlp.your-tempo.io:4318"
                className="w-full px-3 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
              />
            </label>
            <label className="sm:col-span-3 block">
              <span className="font-medium text-slate-700 block mb-1">{t('obs.otlpService')}</span>
              <input
                type="text"
                value={otlpServiceName}
                onChange={(e) => setOtlpServiceName(e.target.value)}
                placeholder="culkibo-control-plane"
                className="w-full px-3 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
              />
            </label>
            <label className="sm:col-span-3 block">
              <span className="font-medium text-slate-700 block mb-1">{t('obs.otlpAuth')}</span>
              <input
                type="password"
                value={otlpAuthHeader}
                onChange={(e) => setOtlpAuthHeader(e.target.value)}
                placeholder={otlpStatus?.hasAuthHeader ? '•••••••• (configured)' : 'Bearer …'}
                className="w-full px-3 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
              />
            </label>
            <div className="sm:col-span-2 flex items-center gap-2 pb-1.5">
              <label className="inline-flex items-center gap-2 cursor-pointer font-medium text-slate-700 select-none">
                <input
                  type="checkbox"
                  checked={otlpEnabled}
                  onChange={(e) => setOtlpEnabled(e.target.checked)}
                  className="rounded border-slate-300 accent-slate-900"
                />
                <span>{t('obs.otlpEnabled')}</span>
              </label>
            </div>
            <div className="sm:col-span-12 flex items-center justify-between gap-2 flex-wrap pt-1">
              <span className="text-[11px] font-mono text-slate-400">
                W3C traceparent · gzip JSON · lowercase hex IDs · 0 @opentelemetry/* deps
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={otlpFlushing}
                  onClick={() => void handleFlushOtlp()}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  {otlpFlushing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                  <span>{t('obs.otlpFlush')}</span>
                </button>
                <button
                  type="submit"
                  disabled={otlpSaving}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {otlpSaving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                  <span>{t('obs.otlpSave')}</span>
                </button>
              </div>
            </div>
          </form>
        </section>
      )}

      {/* TAB 1: METRICS + DOCTOR */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="inline-flex items-center gap-1 bg-white p-1 rounded-lg border border-slate-200 text-xs">
              {([
                { id: 'live', label: t('obs.rangeLive') },
                { id: '1h', label: '1h' },
                { id: '24h', label: '24h' },
                { id: '7d', label: '7d' },
              ] as const).map((r) => (
                <button
                  key={r.id}
                  type="button"
                  onClick={() => setRange(r.id)}
                  className={`px-2.5 py-1 rounded-md font-medium transition-colors cursor-pointer ${
                    range === r.id ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-50'
                  }`}
                >
                  {r.label}
                </button>
              ))}
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
                {autoRefresh ? t('obs.auto5s') : t('obs.paused')}
              </button>
              <button
                type="button"
                onClick={handleCopyPrometheus}
                className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-200 bg-white text-slate-700 hover:bg-slate-50 transition-colors cursor-pointer flex items-center gap-1.5"
              >
                {copiedProm ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedProm ? t('obs.copied') : t('obs.copyProm')}
              </button>
              <button
                type="button"
                onClick={() => {
                  setRefreshing(true);
                  void loadSnapshot(true);
                  if (range !== 'live') void loadRangeHistory(range);
                }}
                disabled={refreshing}
                className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-200 bg-white text-slate-700 hover:bg-slate-50 transition-colors cursor-pointer flex items-center gap-1.5 disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
                {t('obs.refresh')}
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
                {t('obs.retry')}
              </button>
            </div>
          )}

          {/* Fila 1: Recursos del host + tasa de error (persistidos 24h/7d) */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <SparklineCard
              title={t('obs.kpiCpu')}
              value={loading ? '—' : String(procAny?.hostCpuPercent ?? history[history.length - 1]?.hostCpuPct ?? 0)}
              unit="%"
              detailLine={`${snapshot?.process?.hostCpus ?? 1} vCPU · Load ${snapshot?.process?.loadAvg?.[0] ?? 0}`}
              footerLine={`Daemon: ${snapshot?.process?.cpuPercent ?? 0}% CPU`}
              points={history.map((h) => h.hostCpuPct ?? h.cpuPercent ?? 0)}
              timestamps={timestamps}
              markers={deployMarkers}
              accent={(procAny?.hostCpuPercent ?? 0) > 85 ? 'red' : 'ink'}
              maxScale={100}
            />
            <SparklineCard
              title={t('obs.kpiRam')}
              value={loading ? '—' : String(procAny?.hostMemoryUsedPct ?? history[history.length - 1]?.hostRamPct ?? 0)}
              unit="%"
              detailLine={
                snapshot?.process
                  ? `${snapshot.process.hostMemoryUsedMb} / ${snapshot.process.hostMemoryTotalMb} MB`
                  : 'MemAvailable'
              }
              footerLine={
                snapshot?.process
                  ? `Free: ${procAny?.hostMemoryAvailableMb ?? snapshot.process.hostMemoryFreeMb ?? 0} MB (${procAny?.hostMemorySource === 'proc_meminfo' ? 'MemAvailable' : 'OS'})`
                  : '—'
              }
              points={history.map((h) => h.hostRamPct ?? 0)}
              timestamps={timestamps}
              markers={deployMarkers}
              accent={(procAny?.hostMemoryUsedPct ?? 0) > 90 ? 'red' : (procAny?.hostMemoryUsedPct ?? 0) > 80 ? 'amber' : 'emerald'}
              maxScale={100}
            />
            <SparklineCard
              title={t('obs.kpiDisk')}
              value={loading ? '—' : (procAny?.diskUsedPct != null ? String(procAny.diskUsedPct) : '—')}
              unit={procAny?.diskUsedPct != null ? '%' : undefined}
              detailLine={
                procAny?.diskFreeGb != null
                  ? `Free: ${procAny.diskFreeGb} GB / ${procAny.diskTotalGb ?? '—'} GB`
                  : 'Local data volume'
              }
              footerLine="Auto-alert > 85%"
              points={history.map((h) => h.diskUsedPct ?? procAny?.diskUsedPct ?? 0)}
              timestamps={timestamps}
              accent={(procAny?.diskUsedPct ?? 0) > 85 ? 'amber' : 'ink'}
              maxScale={100}
            />
            <SparklineCard
              title={t('obs.kpiErrRate')}
              value={loading ? '—' : String(httpAny?.errorRatePct ?? 0)}
              unit="%"
              detailLine={`4xx: ${snapshot?.http?.status?.['4xx'] ?? 0} · 5xx: ${snapshot?.http?.status?.['5xx'] ?? 0}`}
              footerLine={`5xx: ${httpAny?.error5xxRatePct ?? 0}% / ${snapshot?.http?.requestsTotal ?? 0} req`}
              points={history.map((h) => h.errorRatePct ?? 0)}
              timestamps={timestamps}
              markers={deployMarkers}
              accent={(httpAny?.error5xxRatePct ?? 0) > 1 ? 'red' : 'ink'}
            />
          </div>

          {/* Fila 2: Plano de control (latencia, tráfico, RSS daemon, event loop) */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <SparklineCard
              title={t('obs.kpiLatency')}
              value={loading ? '—' : (snapshot?.http?.latencyMs?.p95 != null ? (snapshot.http.latencyMs.p95 < 10 ? snapshot.http.latencyMs.p95.toFixed(2) : snapshot.http.latencyMs.p95.toFixed(1)) : '0.00')}
              unit="ms"
              detailLine={`p50 ${formatMs(snapshot?.http?.latencyMs?.p50)} · p99 ${formatMs(snapshot?.http?.latencyMs?.p99)}`}
              footerLine={`In-flight: ${snapshot?.http?.inFlight ?? 0} · 2xx: ${snapshot?.http?.status?.['2xx'] ?? 0}`}
              points={history.map((h) => h.p95Ms)}
              timestamps={timestamps}
              markers={deployMarkers}
              accent="amber"
            />
            <SparklineCard
              title={t('obs.kpiTraffic')}
              value={loading ? '—' : (snapshot?.http?.rps?.rps10s ?? 0).toFixed(1)}
              unit="req/s"
              detailLine={`${snapshot?.http?.requestsTotal ?? 0} total requests`}
              footerLine={`1s: ${(snapshot?.http?.rps?.rps1s ?? 0).toFixed(1)} · 60s: ${(snapshot?.http?.rps?.rps60s ?? 0).toFixed(2)} req/s`}
              points={history.map((h) => h.rps)}
              timestamps={timestamps}
              markers={deployMarkers}
            />
            <SparklineCard
              title={t('obs.kpiRss')}
              value={loading ? '—' : String(snapshot?.process?.memoryMb ?? 0)}
              unit="MB"
              detailLine={`Heap ${snapshot?.process?.heapUsedMb ?? 0} MB · Up ${formatUptime(snapshot?.process?.uptimeSeconds ?? snapshot?.uptimeSeconds ?? 0)}`}
              footerLine="Target idle RSS ≤ 60 MB"
              points={history.map((h) => h.rssMb)}
              timestamps={timestamps}
              markers={deployMarkers}
            />
            <SparklineCard
              title={t('obs.kpiEventLoop')}
              value={loading ? '—' : (snapshot?.eventLoop?.p95Ms != null ? snapshot.eventLoop.p95Ms.toFixed(1) : '0.0')}
              unit="ms"
              detailLine={
                snapshot
                  ? `${snapshot.bootMs != null ? `Boot ${snapshot.bootMs} ms · ` : ''}${snapshot.process?.nodeVersion || 'Node.js'}`
                  : 'Measuring boot'
              }
              footerLine={
                snapshot?.eventLoop?.utilizationRatio != null
                  ? `Loop utilization: ${(snapshot.eventLoop.utilizationRatio * 100).toFixed(1)}%`
                  : 'Measuring'
              }
              points={history.map((h) => h.elLagMs)}
              timestamps={timestamps}
              markers={deployMarkers}
            />
          </div>

          {/* Diagnóstico del sistema (Doctor) */}
          <section className="bg-white border border-slate-200 rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <Activity className="w-4 h-4 text-slate-700" />
                <div>
                  <h2 className="text-sm font-semibold text-slate-900">{t('obs.doctorTitle')}</h2>
                  <p className="text-xs text-slate-500">{t('obs.doctorDesc')}</p>
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
                    {doctor.summary.ok}/{doctor.checks.length} OK · {doctor.durationMs} ms
                  </span>
                )}
                <button
                  type="button"
                  onClick={() => void loadDoctor(true)}
                  disabled={doctorRunning}
                  className="px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-900 text-white hover:bg-slate-800 transition-colors cursor-pointer disabled:opacity-50 flex items-center gap-1.5"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${doctorRunning ? 'animate-spin' : ''}`} />
                  {doctorRunning ? '…' : t('obs.doctorRun')}
                </button>
              </div>
            </div>

            <div className="divide-y divide-slate-200">
              {!doctor ? (
                <div className="p-6 text-center text-sm text-slate-500">…</div>
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

          {/* FinOps & Cloud Savings Calculator Card */}
          {(() => {
            const cmp = finops?.costComparison || finops?.comparison || finops?.cloudComparison || finops;
            const annualUsd = cmp?.annualSavingsUsd ?? null;
            const monthlySelfUsd = cmp?.monthlySelfHostedUsd ?? null;
            const monthlyCloudUsd = cmp?.monthlyCloudUsd ?? null;
            const pct = cmp?.savingsPct ?? null;
            const vpsRaw = cmp?.recommendedVps;
            const vpsLabel = typeof vpsRaw === 'string'
              ? vpsRaw
              : vpsRaw
                ? (vpsRaw.plan
                    ? `${vpsRaw.provider} ${vpsRaw.plan}`
                    : `${vpsRaw.provider} ${vpsRaw.name || 'VPS'}${vpsRaw.vcpus && vpsRaw.ramGb ? ` (${vpsRaw.vcpus} vCPU · ${vpsRaw.ramGb} GB)` : ''}`)
                : 'Hetzner CX32 (4 vCPU · 8 GB)';
            const recs = finops?.recommendations || [];
            const footnote = finops?.pricingFootnotes?.[0] || cmp?.pricingFootnotes?.[0] || cmp?.footnote || t('obs.finopsFootnote');
            return (
              <section className="culkibo-surface rounded-2xl overflow-hidden">
                <div className="px-5 py-4 border-b border-slate-200 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                  <div className="flex items-start gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-700 flex items-center justify-center shrink-0 mt-0.5">
                      <TrendingDown className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <h2 className="text-sm font-semibold text-slate-900">{t('obs.finopsTitle')}</h2>
                        {pct != null && (
                          <span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 text-[11px] font-mono font-semibold tabular-nums">
                            -{pct}% vs Cloud PaaS
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-slate-500 mt-0.5">{t('obs.finopsDesc')}</p>
                    </div>
                  </div>
                  <form onSubmit={(e) => void handleRecalcFinops(e)} className="flex items-center gap-2 text-xs flex-wrap shrink-0">
                    <label className="inline-flex items-center gap-1.5 text-slate-600">
                      <span>Apps</span>
                      <input
                        type="number"
                        min={1}
                        max={200}
                        value={finopsApps}
                        onChange={(e) => setFinopsApps(e.target.value)}
                        className="w-16 px-2 py-1 rounded-lg border border-slate-200 bg-white font-mono text-slate-900 tabular-nums"
                      />
                    </label>
                    <label className="inline-flex items-center gap-1.5 text-slate-600">
                      <span>DBs</span>
                      <input
                        type="number"
                        min={0}
                        max={50}
                        value={finopsDbs}
                        onChange={(e) => setFinopsDbs(e.target.value)}
                        className="w-16 px-2 py-1 rounded-lg border border-slate-200 bg-white font-mono text-slate-900 tabular-nums"
                      />
                    </label>
                    <button
                      type="submit"
                      disabled={finopsBusy}
                      className="culkibo-press px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                    >
                      {finopsBusy ? '…' : t('obs.finopsRecalc')}
                    </button>
                  </form>
                </div>

                <div className="grid grid-cols-2 lg:grid-cols-4 divide-y lg:divide-y-0 lg:divide-x divide-slate-200 tabular-nums">
                  <div className="p-4">
                    <div className="text-xs text-slate-500">{t('obs.finopsAnnual')}</div>
                    <div className="text-xl font-semibold text-emerald-700 mt-1">
                      {annualUsd != null ? `$${annualUsd.toLocaleString('en-US')}/yr` : '—'}
                    </div>
                  </div>
                  <div className="p-4">
                    <div className="text-xs text-slate-500">{t('obs.finopsSelfHosted')}</div>
                    <div className="text-xl font-semibold text-slate-900 mt-1">
                      {monthlySelfUsd != null ? `$${monthlySelfUsd}/mo` : '—'}
                    </div>
                  </div>
                  <div className="p-4">
                    <div className="text-xs text-slate-500">{t('obs.finopsCloud')}</div>
                    <div className="text-xl font-semibold text-slate-900 mt-1">
                      {monthlyCloudUsd != null ? `$${monthlyCloudUsd}/mo` : '—'}
                    </div>
                  </div>
                  <div className="p-4">
                    <div className="text-xs text-slate-500">{t('obs.finopsVps')}</div>
                    <div className="text-xs font-mono font-semibold text-slate-900 mt-1.5 truncate" title={vpsLabel}>
                      {vpsLabel}
                    </div>
                  </div>
                </div>

                {recs.length > 0 && (
                  <div className="px-5 py-3 bg-slate-50 border-t border-slate-200 space-y-1.5 text-xs">
                    {recs.slice(0, 3).map((rec, i) => {
                      const recText = rec.title || (rec.projectName ? `${rec.projectName}: ${rec.message || rec.type || ''}` : (rec.message || rec.type || 'Right-size workload'));
                      return (
                        <div key={rec.id || `${rec.projectId || 'rec'}-${i}`} className="flex items-center justify-between gap-2 flex-wrap">
                          <span className="font-medium text-slate-800">{recText}</span>
                          {rec.reclaimableRamMb != null && rec.reclaimableRamMb > 0 && (
                            <span className="px-2 py-0.5 rounded bg-white border border-slate-200 font-mono text-[11px] text-emerald-700 tabular-nums">
                              +{rec.reclaimableRamMb} MB RAM
                            </span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}

                <div className="px-5 py-2.5 bg-white border-t border-slate-100 text-[11px] text-slate-400">
                  {footnote}
                </div>
              </section>
            );
          })()}

          {/* Cycle-9: Agency Multi-Tenant Quotas & Billing Usage Ledger */}
          {(() => {
            const rawRows: BillingLedgerProjectRow[] = Array.isArray(billingLedger?.entries)
              ? billingLedger.entries
              : Array.isArray(billingLedger?.projects)
                ? billingLedger.projects
                : Array.isArray(billingLedger?.items)
                  ? billingLedger.items
                  : Array.isArray(billingLedger?.rows)
                    ? billingLedger.rows
                    : [];
            const totals = billingLedger?.totals || {
              cpuHours: rawRows.reduce((acc, r) => acc + (Number(r.cpuHours) || 0), 0),
              ramGbHours: rawRows.reduce((acc, r) => acc + (Number(r.ramGbHours) || 0), 0),
              storageGb: rawRows.reduce((acc, r) => acc + (Number(r.storageGb) || 0), 0),
              bandwidthGb: rawRows.reduce((acc, r) => acc + (Number(r.bandwidthGb) || 0), 0),
              estimatedCostUsd: rawRows.reduce((acc, r) => acc + (Number(r.estimatedCostUsd) || 0), 0),
            };
            return (
              <section className="culkibo-surface rounded-2xl overflow-hidden">
                <div className="px-5 py-4 border-b border-slate-200 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                  <div className="flex items-start gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0 mt-0.5">
                      <Receipt className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <h2 className="text-sm font-semibold text-slate-900">{t('obs.ledgerTitle')}</h2>
                        <span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
                          Tenant ACL · CSV-Safe
                        </span>
                      </div>
                      <p className="text-xs text-slate-500 mt-0.5">{t('obs.ledgerDesc')}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap shrink-0 text-xs">
                    <div className="inline-flex items-center gap-1 bg-slate-100 p-0.5 rounded-lg border border-slate-200">
                      {[7, 30].map((d) => (
                        <button
                          key={d}
                          type="button"
                          onClick={() => void handleChangeBillingPeriod(d)}
                          className={`px-2.5 py-1 rounded-md font-mono font-medium cursor-pointer ${
                            billingPeriod === d ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                          }`}
                        >
                          {d}d
                        </button>
                      ))}
                    </div>
                    <button
                      type="button"
                      disabled={csvBusy}
                      onClick={() => void handleToggleCsvPreview()}
                      className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                    >
                      {csvBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FileSpreadsheet className="w-3.5 h-3.5" />}
                      <span>{csvPreview !== null ? t('obs.ledgerHideCsv') : t('obs.ledgerPreviewCsv')}</span>
                    </button>
                  </div>
                </div>

                {/* Summary KPI Strip */}
                <div className="grid grid-cols-2 lg:grid-cols-4 divide-y lg:divide-y-0 lg:divide-x divide-slate-200 tabular-nums">
                  <div className="p-4">
                    <div className="text-xs text-slate-500">{t('obs.ledgerTotalBill')} ({billingPeriod}d)</div>
                    <div className="text-xl font-semibold text-slate-900 mt-1">
                      ${(totals.estimatedCostUsd ?? 0).toFixed(2)}
                    </div>
                  </div>
                  <div className="p-4">
                    <div className="text-xs text-slate-500">{t('obs.ledgerCpuHrs')}</div>
                    <div className="text-xl font-semibold text-slate-900 mt-1">
                      {(totals.cpuHours ?? 0).toFixed(1)} h
                    </div>
                  </div>
                  <div className="p-4">
                    <div className="text-xs text-slate-500">{t('obs.ledgerRamHrs')}</div>
                    <div className="text-xl font-semibold text-slate-900 mt-1">
                      {(totals.ramGbHours ?? 0).toFixed(1)} GB·h
                    </div>
                  </div>
                  <div className="p-4">
                    <div className="text-xs text-slate-500">{t('obs.ledgerStorageBw')}</div>
                    <div className="text-sm font-mono font-semibold text-slate-900 mt-1.5">
                      {(totals.storageGb ?? 0).toFixed(1)} GB · {(totals.bandwidthGb ?? 0).toFixed(1)} GB
                    </div>
                  </div>
                </div>

                {/* Per-Project Ledger & Quota Usage Table */}
                {rawRows.length === 0 ? (
                  <div className="p-5 text-center text-xs text-slate-500 border-t border-slate-200">
                    {t('obs.ledgerEmpty')}
                  </div>
                ) : (
                  <div className="overflow-x-auto border-t border-slate-200">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="bg-slate-50 border-b border-slate-200 text-[10px] uppercase tracking-wider text-slate-500">
                          <th className="py-2.5 px-4">{t('obs.ledgerColProject')}</th>
                          <th className="py-2.5 px-3 text-right">{t('obs.ledgerColCpu')}</th>
                          <th className="py-2.5 px-3 text-right">{t('obs.ledgerColRam')}</th>
                          <th className="py-2.5 px-3 text-right">{t('obs.ledgerColStorage')}</th>
                          <th className="py-2.5 px-3 text-right">{t('obs.ledgerColBw')}</th>
                          <th className="py-2.5 px-3">{t('obs.ledgerColQuota')}</th>
                          <th className="py-2.5 px-4 text-right">{t('obs.ledgerColEst')}</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 tabular-nums">
                        {rawRows.map((row) => {
                          const q = row.quota || tenantQuotas[row.projectId];
                          const derivedPct = row.quotaUtilizationPct != null
                            ? row.quotaUtilizationPct
                            : q?.storageGb
                              ? Math.min(100, Math.round(((Number(row.storageGb) || 0) / q.storageGb) * 100))
                              : q?.memoryMb && row.memoryMb
                                ? Math.min(100, Math.round((row.memoryMb / q.memoryMb) * 100))
                                : 42;
                          const clampedPct = Math.max(4, Math.min(100, derivedPct));
                          const barColor = clampedPct >= 90 ? 'bg-red-500' : clampedPct >= 75 ? 'bg-amber-500' : 'bg-emerald-500';
                          return (
                            <tr key={row.projectId}>
                              <td className="py-2.5 px-4 font-medium text-slate-900 whitespace-nowrap">
                                {row.projectName || row.name || row.projectId}
                              </td>
                              <td className="py-2.5 px-3 text-right font-mono text-slate-600 whitespace-nowrap">
                                {(Number(row.cpuHours) || 0).toFixed(1)}
                              </td>
                              <td className="py-2.5 px-3 text-right font-mono text-slate-600 whitespace-nowrap">
                                {(Number(row.ramGbHours) || 0).toFixed(1)}
                              </td>
                              <td className="py-2.5 px-3 text-right font-mono text-slate-600 whitespace-nowrap">
                                {(Number(row.storageGb) || 0).toFixed(1)} GB
                              </td>
                              <td className="py-2.5 px-3 text-right font-mono text-slate-600 whitespace-nowrap">
                                {(Number(row.bandwidthGb) || 0).toFixed(1)} GB
                              </td>
                              <td className="py-2.5 px-3 min-w-[130px]">
                                <div className="flex items-center gap-2">
                                  <div className="flex-1 h-1.5 rounded-full bg-slate-200 overflow-hidden">
                                    <div className={`h-full rounded-full ${barColor}`} style={{ width: `${clampedPct}%` }} />
                                  </div>
                                  <span className="font-mono text-[10px] text-slate-500 w-8 text-right">{clampedPct}%</span>
                                </div>
                              </td>
                              <td className="py-2.5 px-4 text-right font-mono font-semibold text-slate-900 whitespace-nowrap">
                                ${(Number(row.estimatedCostUsd) || 0).toFixed(2)}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}

                {csvPreview !== null && (
                  <div className="p-4 bg-slate-950 border-t border-slate-800 space-y-2.5">
                    <div className="flex items-center justify-between gap-2 flex-wrap text-[11px] font-mono">
                      <span className="text-emerald-300">Formula-Safe CSV (neutralizes = + - @ cells)</span>
                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={async () => {
                            const ok = await copyToClipboard(csvPreview);
                            if (ok) {
                              setCopiedCsv(true);
                              window.setTimeout(() => setCopiedCsv(false), 1800);
                            }
                          }}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-100 cursor-pointer"
                        >
                          {copiedCsv ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedCsv ? t('obs.copied') : 'Copy CSV'}</span>
                        </button>
                        <button
                          type="button"
                          onClick={handleDownloadCsv}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-100 cursor-pointer"
                        >
                          <Download className="w-3 h-3" />
                          <span>{t('obs.ledgerDownloadCsv')}</span>
                        </button>
                      </div>
                    </div>
                    <pre className="text-[11px] font-mono text-emerald-200 leading-relaxed overflow-x-auto max-h-52">
                      {csvPreview}
                    </pre>
                  </div>
                )}
              </section>
            );
          })()}

          {/* Cycle-17: VPA-Lite Container Resource Rightsizer (dokploy#4050 / #903) */}
          <section className="culkibo-surface rounded-2xl overflow-hidden text-xs">
            <div className="px-5 py-4 border-b border-slate-200 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
              <div className="flex items-start gap-2.5 min-w-0">
                <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0 mt-0.5">
                  <SlidersHorizontal className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('obs.vpaTitle')}</h2>
                    <span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
                      P95/P99 · ≥4 MiB / 0.001 CPU
                    </span>
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('obs.vpaDesc')}</p>
                </div>
              </div>
              <div className="flex items-center gap-1.5 flex-wrap shrink-0">
                <button
                  type="button"
                  disabled={vpaBusy !== null}
                  onClick={() => void handleRunVpaRightsize('shrink')}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {vpaBusy === 'shrink' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <TrendingDown className="w-3.5 h-3.5" />}
                  <span>{vpaBusy === 'shrink' ? t('obs.vpaWorking') : t('obs.vpaShrinkBtn')}</span>
                </button>
                <button
                  type="button"
                  disabled={vpaBusy !== null}
                  onClick={() => void handleRunVpaRightsize('oom')}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-amber-200 bg-amber-50 hover:bg-slate-100 text-amber-800 font-medium cursor-pointer disabled:opacity-50"
                >
                  {vpaBusy === 'oom' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                  <span>{vpaBusy === 'oom' ? t('obs.vpaWorking') : t('obs.vpaOomBtn')}</span>
                </button>
              </div>
            </div>

            {vpaError && (
              <div className="p-3 m-4 rounded-lg bg-red-50 border border-red-200 text-red-700">{vpaError}</div>
            )}

            {vpaResult && (() => {
              const isOomUpscale = vpaResult.action === 'UPSCALE_OOM' || (vpaResult.oomCount ?? 0) > 0;
              const p95Mem = vpaResult.p95?.memoryMb ?? vpaResult.p95MemoryMb;
              const p99Mem = vpaResult.p99?.memoryMb ?? vpaResult.p99MemoryMb;
              return (
                <div className="p-4 space-y-3 font-mono text-[11px] tabular-nums">
                  <div className={`p-3.5 rounded-xl border space-y-2 ${
                    isOomUpscale
                      ? 'bg-amber-50 border-amber-200 text-amber-800'
                      : 'bg-emerald-50 border-emerald-200 text-emerald-700'
                  }`}>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded-full bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                        {vpaResult.action}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                        {vpaResult.serviceName || 'app'}: {vpaResult.currentMemoryMb ?? 0} MB → {vpaResult.recommendedMemoryMb ?? 0} MB
                      </span>
                      {isOomUpscale ? (
                        <span className="px-2 py-0.5 rounded bg-red-50 border border-red-200 text-red-700 text-[10px] font-semibold">
                          OOM Safety Lock ({vpaResult.oomCount ?? 1} kills · +50% upscale, never shrinks)
                        </span>
                      ) : (
                        <>
                          <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                            reclaimable: {vpaResult.reclaimableMb ?? 0} MB
                          </span>
                          <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                            waste: {vpaResult.wastePct ?? 0}%
                          </span>
                        </>
                      )}
                      {p95Mem != null && (
                        <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px]">
                          P95 {p95Mem} MB{p99Mem != null ? ` / P99 ${p99Mem} MB` : ''}
                        </span>
                      )}
                    </div>
                  </div>
                  {vpaPatchYaml && (
                    <pre className="p-3 rounded-xl bg-slate-950 text-sky-300 border border-slate-800 text-[10px] leading-relaxed overflow-x-auto max-h-48">
                      {vpaPatchYaml}
                    </pre>
                  )}
                </div>
              );
            })()}
          </section>

          {/* Tabla de rutas activas + Live Sync / Caddy */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <section className="lg:col-span-2 bg-white border border-slate-200 rounded-xl overflow-hidden">
              <div className="px-5 py-3.5 border-b border-slate-200 flex items-center justify-between">
                <h2 className="text-sm font-semibold text-slate-900">{t('obs.topRoutes')}</h2>
                <span className="text-xs text-slate-500 font-mono">GET /metrics</span>
              </div>
              {!snapshot || !snapshot.http?.topRoutes?.length ? (
                <div className="p-6 text-sm text-slate-500 text-center">
                  {locale === 'es' ? 'Sin tráfico registrado todavía.' : 'No traffic recorded yet.'}
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-slate-200 text-[11px] uppercase tracking-wider text-slate-500">
                        <th className="py-2.5 px-3 sm:px-5 font-medium">{locale === 'es' ? 'Ruta' : 'Route'}</th>
                        <th className="py-2.5 px-2 sm:px-4 font-medium text-right">Req</th>
                        <th className="py-2.5 px-2 sm:px-4 font-medium text-right">{locale === 'es' ? 'Media' : 'Avg'}</th>
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
                <h2 className="text-sm font-semibold text-slate-900">{t('obs.dataPlaneTitle')}</h2>
                <p className="text-xs text-slate-500 mt-0.5">{t('obs.dataPlaneDesc')}</p>
              </div>
              <dl className="space-y-2.5 text-xs">
                <div className="flex items-center justify-between py-1.5 border-b border-slate-100">
                  <dt className="text-slate-500">{locale === 'es' ? 'Paneles conectados (WS)' : 'Connected dashboards (WS)'}</dt>
                  <dd className="font-mono font-medium text-slate-900 tabular-nums">{snapshot?.websocket?.telemetryClients ?? 0}</dd>
                </div>
                <div className="flex items-center justify-between py-1.5 border-b border-slate-100">
                  <dt className="text-slate-500">{locale === 'es' ? 'Agentes Live Sync' : 'Live Sync agents'}</dt>
                  <dd className="font-mono font-medium text-slate-900 tabular-nums">{snapshot?.websocket?.syncClients ?? 0}</dd>
                </div>
                <div className="flex items-center justify-between py-1.5 border-b border-slate-100">
                  <dt className="text-slate-500">{locale === 'es' ? 'Cambios aplicados / volumen' : 'Applied changes / volume'}</dt>
                  <dd className="font-mono font-medium text-slate-900 tabular-nums">
                    {snapshot?.liveSync?.framesApplied ?? 0} · {formatBytes(snapshot?.liveSync?.bytesSynced ?? 0)}
                  </dd>
                </div>
                <div className="flex items-center justify-between py-1.5 border-b border-slate-100">
                  <dt className="text-slate-500">{locale === 'es' ? 'Latencia Live Sync (p50 / p95)' : 'Live Sync latency (p50 / p95)'}</dt>
                  <dd className="font-mono font-medium text-slate-900 tabular-nums">
                    {formatMs(snapshot?.liveSync?.applyLatencyMs?.p50)} / {formatMs(snapshot?.liveSync?.applyLatencyMs?.p95)}
                  </dd>
                </div>
                <div className="flex items-center justify-between py-1.5">
                  <dt className="text-slate-500">
                    Caddy ({snapshot?.caddy?.managedRoutes ?? 0} {locale === 'es' ? 'rutas' : 'routes'})
                  </dt>
                  <dd className="font-mono font-medium text-slate-900 tabular-nums">
                    {snapshot?.caddy?.swapsTotal ?? 0} {locale === 'es' ? 'cambios' : 'swaps'} ({formatMs(snapshot?.caddy?.swapLatencyMs?.p50)})
                  </dd>
                </div>
              </dl>
            </section>
          </div>
        </div>
      )}

      {/* TAB 2: PROACTIVE ALERT RULES ENGINE */}
      {activeTab === 'alerts' && (
        <div className="space-y-4">
          {activeAlerts.length > 0 && (
            <section className="bg-red-50 border border-red-200 rounded-xl p-4 space-y-2.5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-red-800 text-xs font-semibold">
                  <ShieldAlert className="w-4 h-4" />
                  <span>{activeAlerts.length} alerta(s) activa(s) ahora mismo</span>
                </div>
              </div>
              <div className="space-y-2">
                {activeAlerts.map((al) => (
                  <div key={al.id} className="bg-white border border-red-200 rounded-lg px-3.5 py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                    <div className="min-w-0">
                      <div className="font-semibold text-slate-900">{al.ruleName} · <span className="font-mono text-red-700">{al.target}</span></div>
                      <div className="text-slate-600 mt-0.5">{al.detail}</div>
                    </div>
                    <button
                      type="button"
                      disabled={al.acknowledged || alertBusy === `ack-${al.id}`}
                      onClick={() => void handleAckAlert(al.id)}
                      className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer disabled:opacity-50 shrink-0"
                    >
                      {al.acknowledged ? 'Reconocida' : 'Reconocer'}
                    </button>
                  </div>
                ))}
              </div>
            </section>
          )}

          <section className="bg-white border border-slate-200 rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-slate-900">{t('obs.alertsTitle')}</h2>
                <p className="text-xs text-slate-500 mt-0.5">{t('obs.alertsDesc')}</p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={alertBusy === 'eval'}
                  onClick={() => void handleEvaluateNow()}
                  className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-200 bg-white text-slate-700 hover:bg-slate-50 cursor-pointer flex items-center gap-1.5"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${alertBusy === 'eval' ? 'animate-spin' : ''}`} />
                  {t('obs.alertsEval')}
                </button>
                <button
                  type="button"
                  onClick={() => setShowNewRule((v) => !v)}
                  className="px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-900 text-white hover:bg-slate-800 cursor-pointer flex items-center gap-1.5"
                >
                  <Plus className="w-3.5 h-3.5" />
                  {t('obs.alertsNew')}
                </button>
              </div>
            </div>

            {showNewRule && (
              <form onSubmit={handleCreateRule} className="p-4 bg-slate-50 border-b border-slate-200 grid grid-cols-1 sm:grid-cols-6 gap-2.5 text-xs items-end">
                <label className="sm:col-span-2 block">
                  <span className="text-slate-600 font-medium">Nombre</span>
                  <input
                    required
                    value={newRule.name}
                    onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                    placeholder="RAM crítica > 92%"
                    className="mt-1 w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-slate-900"
                  />
                </label>
                <label className="block">
                  <span className="text-slate-600 font-medium">Métrica</span>
                  <select
                    value={newRule.metric}
                    onChange={(e) => setNewRule({ ...newRule, metric: e.target.value })}
                    className="mt-1 w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-slate-900"
                  >
                    {Object.entries(METRIC_LABELS).map(([k, lbl]) => (
                      <option key={k} value={k}>{lbl}</option>
                    ))}
                  </select>
                </label>
                <div className="flex gap-1.5">
                  <label className="w-16 block">
                    <span className="text-slate-600 font-medium">Op</span>
                    <select
                      value={newRule.operator}
                      onChange={(e) => setNewRule({ ...newRule, operator: e.target.value })}
                      className="mt-1 w-full px-1.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                    >
                      <option value=">">&gt;</option>
                      <option value=">=">&gt;=</option>
                      <option value="<">&lt;</option>
                      <option value="<=">&lt;=</option>
                    </select>
                  </label>
                  <label className="flex-1 block">
                    <span className="text-slate-600 font-medium">Umbral</span>
                    <input
                      type="number"
                      step="any"
                      required
                      value={newRule.threshold}
                      onChange={(e) => setNewRule({ ...newRule, threshold: e.target.value })}
                      className="mt-1 w-full px-2 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                    />
                  </label>
                </div>
                <label className="block">
                  <span className="text-slate-600 font-medium">Muestras / Cool (m)</span>
                  <div className="mt-1 flex gap-1">
                    <input
                      type="number"
                      min={1}
                      max={10}
                      value={newRule.consecutiveRequired}
                      onChange={(e) => setNewRule({ ...newRule, consecutiveRequired: e.target.value })}
                      className="w-14 px-2 py-1.5 rounded-lg border border-slate-200 bg-white font-mono"
                      title="Muestras consecutivas"
                    />
                    <input
                      type="number"
                      min={0}
                      max={1440}
                      value={newRule.cooldownMin}
                      onChange={(e) => setNewRule({ ...newRule, cooldownMin: e.target.value })}
                      className="flex-1 px-2 py-1.5 rounded-lg border border-slate-200 bg-white font-mono"
                      title="Cooldown en minutos"
                    />
                  </div>
                </label>
                <button
                  type="submit"
                  disabled={alertBusy === 'create-rule'}
                  className="px-3 py-1.5 rounded-lg bg-slate-900 text-white font-medium hover:bg-slate-800 cursor-pointer disabled:opacity-50"
                >
                  Guardar
                </button>
              </form>
            )}

            {!alertsSupported ? (
              <div className="p-8 text-center text-xs text-slate-500">
                El endpoint <code className="font-mono">/api/alerts/rules</code> se activará en el reinicio del servidor.
              </div>
            ) : alertRules.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500">Sin reglas de alerta cargadas todavía.</div>
            ) : (
              <div className="divide-y divide-slate-100">
                {alertRules.map((r) => {
                  const silenced = Boolean(r.silencedUntil && Date.parse(r.silencedUntil) > alertsNowMs);
                  return (
                    <div key={r.id} className="px-5 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 text-xs">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-semibold text-slate-900">{r.name}</span>
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${
                            r.severity === 'critical'
                              ? 'bg-red-50 text-red-700 border-red-200'
                              : r.severity === 'warning'
                                ? 'bg-amber-50 text-amber-800 border-amber-200'
                                : 'bg-slate-100 text-slate-700 border-slate-200'
                          }`}>
                            {r.severity}
                          </span>
                          <span className="font-mono text-[11px] text-slate-600">
                            {METRIC_LABELS[r.metric] || r.metric} {r.operator} {r.threshold}
                          </span>
                          {silenced && (
                            <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 text-[10px]">Silenciada</span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-500 mt-0.5 tabular-nums">
                          Amortiguación: {r.consecutiveRequired} muestra(s) · Cooldown: {formatCooldown(r.cooldownMs)}
                          {r.description ? ` · ${r.description}` : ''}
                        </div>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <button
                          type="button"
                          onClick={() => void handleSilenceRule(r, silenced ? 0 : 60)}
                          disabled={alertBusy === `sil-${r.id}`}
                          className="p-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-600 cursor-pointer"
                          title={silenced ? 'Quitar silencio' : 'Silenciar 1 hora'}
                        >
                          <BellOff className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => void handleToggleRule(r)}
                          disabled={alertBusy === r.id}
                          className={`px-2.5 py-1.5 rounded-lg border font-medium cursor-pointer ${
                            r.enabled
                              ? 'bg-emerald-50 text-emerald-700 border-emerald-200 hover:bg-emerald-100'
                              : 'bg-white text-slate-500 border-slate-200 hover:bg-slate-50'
                          }`}
                        >
                          {r.enabled ? 'Activa' : 'Pausada'}
                        </button>
                        {!r.builtin && (
                          <button
                            type="button"
                            onClick={() => void handleDeleteRule(r)}
                            disabled={alertBusy === `del-${r.id}`}
                            aria-label={`Eliminar regla ${r.name}`}
                            className="p-1.5 rounded-lg border border-slate-200 bg-white hover:bg-red-50 text-slate-500 hover:text-red-700 cursor-pointer"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </section>

          {alertHistory.length > 0 && (
            <section className="bg-white border border-slate-200 rounded-xl overflow-hidden">
              <div className="px-5 py-3 border-b border-slate-200 text-xs font-semibold text-slate-900">
                Historial reciente de alertas ({alertHistory.length})
              </div>
              <div className="divide-y divide-slate-100 text-xs">
                {alertHistory.slice(0, 20).map((item) => (
                  <div key={item.id} className="px-5 py-2.5 flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <span className={`inline-block w-2 h-2 rounded-full mr-2 ${item.status === 'resolved' ? 'bg-emerald-500' : 'bg-red-500'}`} />
                      <span className="font-medium text-slate-900">{item.ruleName}</span>
                      <span className="text-slate-500 font-mono ml-2">{item.target}</span>
                    </div>
                    <div className="text-[11px] text-slate-500 font-mono tabular-nums shrink-0">
                      {item.status === 'resolved' ? `Resuelta (${formatDurationMs(item.durationMs)})` : 'Activa'} · {new Date(item.firedAt).toLocaleTimeString('es-ES')}
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>
      )}

      {/* TAB 3: RAILWAY-CLASS INTERACTIVE SPATIAL SVG TOPOLOGY CANVAS */}
      {activeTab === 'topology' && (
        <div className="space-y-4">
          <section className="culkibo-surface rounded-2xl overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-slate-900">{t('topo.title')}</h2>
                <p className="text-xs text-slate-500 mt-0.5">{t('topo.subtitle')}</p>
              </div>
              <div className="flex items-center gap-1.5 flex-wrap text-xs">
                {topology && (
                  <span className="px-2.5 py-1 rounded-full bg-slate-100 border border-slate-200 text-slate-700 font-mono tabular-nums">
                    {topology.summary.totalNodes} {t('topo.nodes')} · {topology.summary.totalEdges} {t('topo.edges')}
                  </span>
                )}
                <div className="inline-flex items-center bg-slate-100 border border-slate-200 rounded-lg p-0.5">
                  <button
                    type="button"
                    aria-label="Zoom out"
                    title="Zoom out"
                    onClick={() => setTopoZoom((z) => Math.max(0.6, Number((z - 0.15).toFixed(2))))}
                    className="p-1.5 rounded-md text-slate-600 hover:text-slate-900 hover:bg-white transition-colors cursor-pointer"
                  >
                    <ZoomOut className="w-3.5 h-3.5" />
                  </button>
                  <span className="px-2 font-mono text-[11px] text-slate-700 tabular-nums">
                    {Math.round(topoZoom * 100)}%
                  </span>
                  <button
                    type="button"
                    aria-label="Zoom in"
                    title="Zoom in"
                    onClick={() => setTopoZoom((z) => Math.min(1.8, Number((z + 0.15).toFixed(2))))}
                    className="p-1.5 rounded-md text-slate-600 hover:text-slate-900 hover:bg-white transition-colors cursor-pointer"
                  >
                    <ZoomIn className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    aria-label={t('topo.fit')}
                    title={t('topo.fit')}
                    onClick={() => {
                      setTopoZoom(1);
                      setTopoPan({ x: 0, y: 0 });
                    }}
                    className="p-1.5 rounded-md text-slate-600 hover:text-slate-900 hover:bg-white transition-colors cursor-pointer"
                  >
                    <Maximize2 className="w-3.5 h-3.5" />
                  </button>
                </div>
                <button
                  type="button"
                  onClick={() => void loadTopology()}
                  disabled={topologyLoading}
                  className="culkibo-press px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer flex items-center gap-1.5"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${topologyLoading ? 'animate-spin' : ''}`} />
                  <span>{t('topo.refresh')}</span>
                </button>
              </div>
            </div>

            {topologyLoading && !topology ? (
              <div className="p-12 text-center text-xs text-slate-500">{t('topo.building')}</div>
            ) : !topology || !topologyLayout || topology.nodes.length === 0 ? (
              <div className="p-12 text-center text-xs text-slate-500">{t('topo.empty')}</div>
            ) : (
              <div className="grid grid-cols-1 xl:grid-cols-[1fr_300px] divide-y xl:divide-y-0 xl:divide-x divide-slate-200">
                {/* Interactive Pan & Zoom Spatial SVG Canvas */}
                <div
                  className={`relative overflow-hidden select-none min-h-[380px] ${
                    isPanning ? 'cursor-grabbing' : 'cursor-grab'
                  }`}
                  style={{ backgroundColor: 'var(--topo-bg)' }}
                  onPointerDown={(e) => {
                    if ((e.target as HTMLElement).closest('[data-topo-node="true"]')) return;
                    topoDragRef.current = {
                      startX: e.clientX,
                      startY: e.clientY,
                      originX: topoPan.x,
                      originY: topoPan.y,
                      moved: false,
                    };
                    setIsPanning(true);
                  }}
                  onPointerMove={(e) => {
                    const drag = topoDragRef.current;
                    if (!drag) return;
                    const dx = e.clientX - drag.startX;
                    const dy = e.clientY - drag.startY;
                    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) drag.moved = true;
                    setTopoPan({ x: drag.originX + dx, y: drag.originY + dy });
                  }}
                  onPointerUp={() => {
                    topoDragRef.current = null;
                    setIsPanning(false);
                  }}
                  onPointerLeave={() => {
                    topoDragRef.current = null;
                    setIsPanning(false);
                  }}
                  onWheel={(e) => {
                    if (e.ctrlKey || e.metaKey) {
                      e.preventDefault();
                      const delta = e.deltaY > 0 ? -0.1 : 0.1;
                      setTopoZoom((z) => Math.min(1.8, Math.max(0.6, Number((z + delta).toFixed(2)))));
                    }
                  }}
                >
                  <svg
                    viewBox={`0 0 ${topologyLayout.svgW} ${Math.max(360, topologyLayout.svgH + 24)}`}
                    className="w-full h-[420px] xl:h-[460px] block"
                    role="img"
                    aria-label={t('topo.title')}
                  >
                    <defs>
                      <pattern id="topo-dots" width="22" height="22" patternUnits="userSpaceOnUse">
                        <circle cx="2" cy="2" r="1" fill="var(--topo-dot)" />
                      </pattern>
                      <marker
                        id="topo-arrow"
                        viewBox="0 0 10 10"
                        refX="8"
                        refY="5"
                        markerWidth="5.5"
                        markerHeight="5.5"
                        orient="auto-start-reverse"
                      >
                        <path d="M 0 1.5 L 9 5 L 0 8.5 z" fill="#71717a" />
                      </marker>
                      <marker
                        id="topo-arrow-healthy"
                        viewBox="0 0 10 10"
                        refX="8"
                        refY="5"
                        markerWidth="5.5"
                        markerHeight="5.5"
                        orient="auto-start-reverse"
                      >
                        <path d="M 0 1.5 L 9 5 L 0 8.5 z" fill="#10b981" />
                      </marker>
                    </defs>

                    <rect width="100%" height="100%" fill="url(#topo-dots)" />

                    <g transform={`translate(${topoPan.x}, ${topoPan.y}) scale(${topoZoom})`}>
                      {/* Column headers */}
                      {topologyLayout.cols.map((col, idx) => {
                        const colTitles = [t('topo.colEdge'), t('topo.colProjects'), t('topo.colData'), t('topo.colServers')];
                        return (
                          <text
                            key={col.title}
                            x={col.x}
                            y={22}
                            fill="var(--topo-col-label)"
                            className="text-[10.5px] font-semibold uppercase tracking-wider"
                          >
                            {colTitles[idx] || col.title}
                          </text>
                        );
                      })}

                      {/* Curved dependency edges + animated directional flow pulses */}
                      {topology.edges.map((edge) => {
                        const fromPos = topologyLayout.positioned.get(edge.from);
                        const toPos = topologyLayout.positioned.get(edge.to);
                        if (!fromPos || !toPos) return null;
                        const x1 = fromPos.x + topologyLayout.nodeW;
                        const y1 = fromPos.y + topologyLayout.nodeH / 2;
                        const x2 = toPos.x - 4;
                        const y2 = toPos.y + topologyLayout.nodeH / 2;
                        const dx = Math.max(48, Math.abs(x2 - x1) * 0.45);
                        const pathD = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
                        const midX = (x1 + x2) / 2;
                        const midY = (y1 + y2) / 2;
                        const isHighlighted = selectedNodeId === edge.from || selectedNodeId === edge.to;
                        const stroke = HEALTH_STROKE[edge.status] || '#71717a';
                        const isHealthy = edge.status === 'healthy';
                        return (
                          <g key={edge.id} opacity={selectedNodeId && !isHighlighted ? 0.18 : 0.95}>
                            <path
                              d={pathD}
                              fill="none"
                              stroke={stroke}
                              strokeOpacity={isHighlighted ? 0.9 : 0.42}
                              strokeWidth={isHighlighted ? 2.2 : 1.5}
                              markerEnd={isHealthy ? 'url(#topo-arrow-healthy)' : 'url(#topo-arrow)'}
                            />
                            {(isHealthy || isHighlighted) && (
                              <path
                                d={pathD}
                                fill="none"
                                stroke={stroke}
                                strokeWidth={isHighlighted ? 2.2 : 1.6}
                                strokeLinecap="round"
                                className="culkibo-flow-edge"
                              />
                            )}
                            {edge.label && (
                              <g transform={`translate(${midX}, ${midY - 8})`}>
                                <rect
                                  x={-26}
                                  y={-8}
                                  width={52}
                                  height={15}
                                  rx={4}
                                  fill="var(--topo-edge-label-bg)"
                                  stroke="var(--topo-node-stroke)"
                                  strokeWidth={0.75}
                                />
                                <text
                                  x={0}
                                  y={2.5}
                                  textAnchor="middle"
                                  fill="var(--topo-muted)"
                                  className="text-[8.5px] font-mono"
                                >
                                  {edge.label.slice(0, 10)}
                                </text>
                              </g>
                            )}
                          </g>
                        );
                      })}

                      {/* Interactive Spatial Nodes with type badge + live status */}
                      {Array.from(topologyLayout.positioned.values()).map(({ node, x, y }) => {
                        const isSelected = selectedNodeId === node.id;
                        const isConnected =
                          isSelected ||
                          !selectedNodeId ||
                          topology.edges.some(
                            (e) =>
                              (e.from === selectedNodeId && e.to === node.id) ||
                              (e.to === selectedNodeId && e.from === node.id)
                          );
                        const dotColor = HEALTH_STROKE[node.health] || '#71717a';
                        const kindAccent: Record<TopologyNode['kind'], string> = {
                          domain: '#10b981',
                          monitor: '#06b6d4',
                          project: '#f59e0b',
                          database: '#6366f1',
                          cache: '#ec4899',
                          catalog: '#8b5cf6',
                          server: '#64748b',
                        };
                        const accent = kindAccent[node.kind] || '#71717a';
                        return (
                          <g
                            key={node.id}
                            data-topo-node="true"
                            transform={`translate(${x}, ${y})`}
                            onClick={() => setSelectedNodeId((prev) => (prev === node.id ? null : node.id))}
                            className="cursor-pointer"
                            opacity={isConnected ? 1 : 0.28}
                          >
                            {isSelected && (
                              <rect
                                x={-3}
                                y={-3}
                                width={topologyLayout.nodeW + 6}
                                height={topologyLayout.nodeH + 6}
                                rx={14}
                                fill="none"
                                stroke={accent}
                                strokeOpacity={0.45}
                                strokeWidth={2}
                              />
                            )}
                            <rect
                              width={topologyLayout.nodeW}
                              height={topologyLayout.nodeH}
                              rx={11}
                              fill="var(--topo-node-bg)"
                              stroke={isSelected ? 'var(--topo-node-selected)' : 'var(--topo-node-stroke)'}
                              strokeWidth={isSelected ? 1.8 : 1}
                            />
                            {/* Left accent bar */}
                            <rect x={0.5} y={10} width={3} height={topologyLayout.nodeH - 20} rx={1.5} fill={accent} />
                            {/* Health dot */}
                            <circle cx={17} cy={22} r={4} fill={dotColor} />
                            {/* Node name */}
                            <text
                              x={27}
                              y={25}
                              fill="var(--topo-text)"
                              className="text-[11.5px] font-semibold"
                            >
                              {node.label.length > 18 ? `${node.label.slice(0, 17)}…` : node.label}
                            </text>
                            {/* Type badge pill */}
                            <rect
                              x={topologyLayout.nodeW - 56}
                              y={11}
                              width={48}
                              height={16}
                              rx={4}
                              fill="var(--topo-badge-bg)"
                            />
                            <text
                              x={topologyLayout.nodeW - 32}
                              y={22}
                              textAnchor="middle"
                              fill="var(--topo-muted)"
                              className="text-[8px] font-mono uppercase"
                            >
                              {node.kind.slice(0, 8)}
                            </text>
                            {/* Sublabel */}
                            <text
                              x={17}
                              y={46}
                              fill="var(--topo-muted)"
                              className="text-[9.5px] font-mono"
                            >
                              {(node.sublabel || node.status).slice(0, 27)}
                            </text>
                          </g>
                        );
                      })}
                    </g>
                  </svg>

                  {/* Bottom-left subtle canvas hint (high-contrast Obsidian Dark + Light safe) */}
                  <div
                    className={`pointer-events-none absolute bottom-3 left-3 px-2.5 py-1 rounded-lg border text-[10px] font-medium backdrop-blur-xs ${
                      isDark
                        ? 'bg-zinc-900/90 text-zinc-200 border-zinc-700'
                        : 'bg-white/90 text-slate-600 border-slate-200'
                    }`}
                    style={
                      isDark
                        ? { backgroundColor: 'rgba(24, 24, 27, 0.92)', color: '#e4e4e7', borderColor: '#3f3f46' }
                        : undefined
                    }
                  >
                    {t('topo.dragHint')}
                  </div>
                </div>

                {/* Railway-style Live Node Inspector Side Panel */}
                <aside className="p-4 bg-white flex flex-col justify-between gap-4 text-xs">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between gap-2 pb-2 border-b border-slate-100">
                      <span className="font-semibold text-slate-900">{t('topo.inspectorTitle')}</span>
                      {selectedNode && (
                        <button
                          type="button"
                          onClick={() => {
                            setSelectedNodeId(null);
                            setLinkTargetProjectId('');
                          }}
                          className="text-[11px] text-slate-400 hover:text-slate-700 cursor-pointer"
                        >
                          {t('topo.clear')}
                        </button>
                      )}
                    </div>

                    {selectedNode ? (
                      <div className="space-y-3">
                        <div className="flex items-start gap-2.5">
                          <span className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center shrink-0">
                            {(() => {
                              const Icon = KIND_ICON[selectedNode.kind] || Activity;
                              return <Icon className="w-4 h-4 text-slate-700" />;
                            })()}
                          </span>
                          <div className="min-w-0">
                            <div className="font-semibold text-slate-900 text-sm truncate">{selectedNode.label}</div>
                            <div className="flex items-center gap-1.5 mt-1 flex-wrap">
                              <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[10px] uppercase text-slate-600">
                                {selectedNode.kind}
                              </span>
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-slate-50 border border-slate-200 font-mono text-[10px] text-slate-700">
                                <span className={`w-1.5 h-1.5 rounded-full ${HEALTH_DOT[selectedNode.health] || HEALTH_DOT.unknown}`} />
                                {selectedNode.status}
                              </span>
                            </div>
                          </div>
                        </div>

                        {selectedNode.sublabel && (
                          <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 font-mono text-[11px] text-slate-600">
                            {selectedNode.sublabel}
                          </div>
                        )}

                        {/* Click-to-Link DB -> Project Env Injection */}
                        {(selectedNode.kind === 'database' || selectedNode.kind === 'cache') && (
                          <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
                            <div className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-900">
                              <Link2 className="w-3.5 h-3.5 text-indigo-600 shrink-0" />
                              <span>{t('topo.linkDbTitle')}</span>
                            </div>
                            <p className="text-[11px] text-slate-500 leading-snug">{t('topo.linkDbDesc')}</p>
                            {projectNodes.length === 0 ? (
                              <p className="text-[11px] text-slate-400 italic">{t('topo.linkDbNoProjects')}</p>
                            ) : (
                              <div className="space-y-2">
                                <select
                                  value={linkTargetProjectId}
                                  onChange={(e) => setLinkTargetProjectId(e.target.value)}
                                  className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-xs text-slate-900"
                                >
                                  <option value="">{t('topo.linkDbSelect')}</option>
                                  {projectNodes.map((proj) => (
                                    <option key={proj.id} value={proj.id}>
                                      {proj.label}
                                    </option>
                                  ))}
                                </select>
                                <button
                                  type="button"
                                  disabled={!linkTargetProjectId || linkingDb}
                                  onClick={() => void handleLinkDbToProject(selectedNode, linkTargetProjectId)}
                                  className="culkibo-press w-full inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-[11px] font-medium cursor-pointer disabled:opacity-50"
                                >
                                  {linkingDb ? (
                                    <Loader2 className="w-3 h-3 animate-spin" />
                                  ) : (
                                    <Link2 className="w-3 h-3" />
                                  )}
                                  <span>{linkingDb ? t('topo.linkDbLinking') : t('topo.linkDbBtn')}</span>
                                </button>
                              </div>
                            )}
                          </div>
                        )}

                        {(() => {
                          const inbound = selectedEdges.filter((e) => e.to === selectedNode.id);
                          const outbound = selectedEdges.filter((e) => e.from === selectedNode.id);
                          return (
                            <div className="space-y-2.5">
                              {inbound.length > 0 && (
                                <div className="space-y-1">
                                  <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                                    {t('topo.inbound')} ({inbound.length})
                                  </div>
                                  {inbound.map((e) => {
                                    const src = topology.nodes.find((n) => n.id === e.from);
                                    return (
                                      <button
                                        key={e.id}
                                        type="button"
                                        onClick={() => setSelectedNodeId(e.from)}
                                        className="w-full px-2.5 py-1.5 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200/80 flex items-center justify-between gap-2 text-left cursor-pointer"
                                      >
                                        <span className="inline-flex items-center gap-1.5 truncate text-slate-700">
                                          <ArrowLeft className="w-3 h-3 text-slate-400 shrink-0" />
                                          <span className="truncate">{src?.label || e.from}</span>
                                        </span>
                                        <span className="font-mono text-[10px] text-slate-400 shrink-0">{e.label || e.kind}</span>
                                      </button>
                                    );
                                  })}
                                </div>
                              )}
                              {outbound.length > 0 && (
                                <div className="space-y-1">
                                  <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                                    {t('topo.outbound')} ({outbound.length})
                                  </div>
                                  {outbound.map((e) => {
                                    const dst = topology.nodes.find((n) => n.id === e.to);
                                    return (
                                      <button
                                        key={e.id}
                                        type="button"
                                        onClick={() => setSelectedNodeId(e.to)}
                                        className="w-full px-2.5 py-1.5 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200/80 flex items-center justify-between gap-2 text-left cursor-pointer"
                                      >
                                        <span className="inline-flex items-center gap-1.5 truncate text-slate-700">
                                          <ArrowRight className="w-3 h-3 text-slate-400 shrink-0" />
                                          <span className="truncate">{dst?.label || e.to}</span>
                                        </span>
                                        <span className="font-mono text-[10px] text-slate-400 shrink-0">{e.label || e.kind}</span>
                                      </button>
                                    );
                                  })}
                                </div>
                              )}
                            </div>
                          );
                        })()}
                      </div>
                    ) : (
                      <div className="space-y-3">
                        <p className="text-slate-500 leading-relaxed">{t('topo.inspectorEmpty')}</p>
                        <div className="grid grid-cols-2 gap-2 tabular-nums">
                          <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                            <span className="text-[10px] text-slate-400 block">{t('topo.colProjects')}</span>
                            <span className="font-mono text-sm font-semibold text-slate-900">{topology.summary.projects}</span>
                          </div>
                          <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                            <span className="text-[10px] text-slate-400 block">{t('topo.legendDb')}</span>
                            <span className="font-mono text-sm font-semibold text-slate-900">{topology.summary.databases}</span>
                          </div>
                          <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                            <span className="text-[10px] text-slate-400 block">{t('topo.legendDomain')}</span>
                            <span className="font-mono text-sm font-semibold text-slate-900">{topology.summary.domains}</span>
                          </div>
                          <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                            <span className="text-[10px] text-slate-400 block">{t('topo.legendServer')}</span>
                            <span className="font-mono text-sm font-semibold text-slate-900">{topology.summary.servers}</span>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Color Legend */}
                  <div className="pt-3 border-t border-slate-100 flex flex-wrap gap-x-3 gap-y-1.5 text-[10px] text-slate-500">
                    <span className="inline-flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-emerald-500" />{t('topo.legendDomain')}</span>
                    <span className="inline-flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-amber-500" />{t('topo.legendProject')}</span>
                    <span className="inline-flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-indigo-500" />{t('topo.legendDb')}</span>
                    <span className="inline-flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-slate-500" />{t('topo.legendServer')}</span>
                  </div>
                </aside>
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
};
