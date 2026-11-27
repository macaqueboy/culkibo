import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Bell,
  BellOff,
  Check,
  CheckCircle2,
  Copy,
  Database,
  Globe,
  Network,
  Plus,
  Radio,
  RefreshCw,
  Server,
  ShieldAlert,
  Trash2,
  Wrench,
  XCircle,
} from 'lucide-react';
import {
  api,
  apiFetch,
  type DoctorCheck,
  type ObservabilityHistoryPoint,
  type ObservabilitySnapshot,
  type SystemDoctorReport,
} from '../lib/api';
import { copyToClipboard } from '../lib/clipboard';

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

  // Topology state
  const [topology, setTopology] = useState<TopologyGraph | null>(null);
  const [topologyLoading, setTopologyLoading] = useState(false);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

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
        setTopology(data);
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
    if (!topology) return null;
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
      const colNodes = topology.nodes.filter((n) => col.kinds.includes(n.kind));
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
    () => (topology && selectedNodeId ? topology.nodes.find((n) => n.id === selectedNodeId) || null : null),
    [topology, selectedNodeId]
  );

  const selectedEdges = useMemo(
    () => (topology && selectedNodeId ? topology.edges.filter((e) => e.from === selectedNodeId || e.to === selectedNodeId) : []),
    [topology, selectedNodeId]
  );

  return (
    <div className="space-y-6">
      {/* Cabecera */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">Métricas, Alertas y Topología</h1>
          <p className="text-sm text-slate-500 mt-1">
            Historial persistente 24h/7d, reglas proactivas con amortiguación, mapa de dependencias y Doctor 1-clic.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="inline-flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs">
            {([
              { id: 'overview', label: 'Métricas y Doctor', icon: Activity },
              { id: 'alerts', label: 'Alertas', icon: Bell, badge: activeAlerts.length },
              { id: 'topology', label: 'Topología', icon: Network },
            ] as const).map((t) => {
              const Icon = t.icon;
              return (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setActiveTab(t.id)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium whitespace-nowrap transition-colors cursor-pointer ${
                    activeTab === t.id ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span>{t.label}</span>
                  {'badge' in t && t.badge > 0 && (
                    <span className="px-1.5 py-0.2 rounded-full bg-red-600 text-white text-[10px] font-semibold tabular-nums">
                      {t.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* TAB 1: METRICS + DOCTOR */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="inline-flex items-center gap-1 bg-white p-1 rounded-lg border border-slate-200 text-xs">
              {([
                { id: 'live', label: '5m vivo' },
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
                  if (range !== 'live') void loadRangeHistory(range);
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

          {/* Fila 1: Recursos del host + tasa de error (persistidos 24h/7d) */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <SparklineCard
              title="CPU del servidor"
              value={loading ? '—' : String(procAny?.hostCpuPercent ?? history[history.length - 1]?.hostCpuPct ?? 0)}
              unit="%"
              detailLine={`${snapshot?.process?.hostCpus ?? 1} vCPU · Load ${snapshot?.process?.loadAvg?.[0] ?? 0}`}
              footerLine={`Proceso daemon: ${snapshot?.process?.cpuPercent ?? 0}% CPU`}
              points={history.map((h) => h.hostCpuPct ?? h.cpuPercent ?? 0)}
              timestamps={timestamps}
              markers={deployMarkers}
              accent={(procAny?.hostCpuPercent ?? 0) > 85 ? 'red' : 'ink'}
              maxScale={100}
            />
            <SparklineCard
              title="RAM real del host"
              value={loading ? '—' : String(procAny?.hostMemoryUsedPct ?? history[history.length - 1]?.hostRamPct ?? 0)}
              unit="%"
              detailLine={
                snapshot?.process
                  ? `Usada ${snapshot.process.hostMemoryUsedMb} / ${snapshot.process.hostMemoryTotalMb} MB`
                  : 'Midiendo MemAvailable'
              }
              footerLine={
                snapshot?.process
                  ? `Disponible: ${procAny?.hostMemoryAvailableMb ?? snapshot.process.hostMemoryFreeMb ?? 0} MB (${procAny?.hostMemorySource === 'proc_meminfo' ? 'MemAvailable' : 'SO'})`
                  : 'Sin lectura'
              }
              points={history.map((h) => h.hostRamPct ?? 0)}
              timestamps={timestamps}
              markers={deployMarkers}
              accent={(procAny?.hostMemoryUsedPct ?? 0) > 90 ? 'red' : (procAny?.hostMemoryUsedPct ?? 0) > 80 ? 'amber' : 'emerald'}
              maxScale={100}
            />
            <SparklineCard
              title="Disco del servidor"
              value={loading ? '—' : (procAny?.diskUsedPct != null ? String(procAny.diskUsedPct) : '—')}
              unit={procAny?.diskUsedPct != null ? '%' : undefined}
              detailLine={
                procAny?.diskFreeGb != null
                  ? `Libre: ${procAny.diskFreeGb} GB de ${procAny.diskTotalGb ?? '—'} GB`
                  : 'Volumen de datos local'
              }
              footerLine="Alerta automática si > 85% usado"
              points={history.map((h) => h.diskUsedPct ?? procAny?.diskUsedPct ?? 0)}
              timestamps={timestamps}
              accent={(procAny?.diskUsedPct ?? 0) > 85 ? 'amber' : 'ink'}
              maxScale={100}
            />
            <SparklineCard
              title="Tasa de errores HTTP"
              value={loading ? '—' : String(httpAny?.errorRatePct ?? 0)}
              unit="%"
              detailLine={`4xx: ${snapshot?.http?.status?.['4xx'] ?? 0} · 5xx: ${snapshot?.http?.status?.['5xx'] ?? 0}`}
              footerLine={`5xx: ${httpAny?.error5xxRatePct ?? 0}% sobre ${snapshot?.http?.requestsTotal ?? 0} req`}
              points={history.map((h) => h.errorRatePct ?? 0)}
              timestamps={timestamps}
              markers={deployMarkers}
              accent={(httpAny?.error5xxRatePct ?? 0) > 1 ? 'red' : 'ink'}
            />
          </div>

          {/* Fila 2: Plano de control (latencia, tráfico, RSS daemon, event loop) */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <SparklineCard
              title="Latencia HTTP (p95)"
              value={loading ? '—' : (snapshot?.http?.latencyMs?.p95 != null ? (snapshot.http.latencyMs.p95 < 10 ? snapshot.http.latencyMs.p95.toFixed(2) : snapshot.http.latencyMs.p95.toFixed(1)) : '0.00')}
              unit="ms"
              detailLine={`p50 ${formatMs(snapshot?.http?.latencyMs?.p50)} · p99 ${formatMs(snapshot?.http?.latencyMs?.p99)}`}
              footerLine={`En curso: ${snapshot?.http?.inFlight ?? 0} · 2xx: ${snapshot?.http?.status?.['2xx'] ?? 0}`}
              points={history.map((h) => h.p95Ms)}
              timestamps={timestamps}
              markers={deployMarkers}
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
              markers={deployMarkers}
            />
            <SparklineCard
              title="Memoria RSS del proceso"
              value={loading ? '—' : String(snapshot?.process?.memoryMb ?? 0)}
              unit="MB"
              detailLine={`Heap ${snapshot?.process?.heapUsedMb ?? 0} MB · Activo ${formatUptime(snapshot?.process?.uptimeSeconds ?? snapshot?.uptimeSeconds ?? 0)}`}
              footerLine="Objetivo plano de control ≤ 60 MB en reposo"
              points={history.map((h) => h.rssMb)}
              timestamps={timestamps}
              markers={deployMarkers}
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
              markers={deployMarkers}
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
                    Comprueba entorno Node.js, Docker, Caddy, disco, MemAvailable, seguridad, TLS, copias y alertas.
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
                <h2 className="text-sm font-semibold text-slate-900">Reglas de alerta proactivas</h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Umbrales con amortiguación anti-picos, enfriamiento y notificación automática de recuperación por Telegram/Discord/Slack/Webhook.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={alertBusy === 'eval'}
                  onClick={() => void handleEvaluateNow()}
                  className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-200 bg-white text-slate-700 hover:bg-slate-50 cursor-pointer flex items-center gap-1.5"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${alertBusy === 'eval' ? 'animate-spin' : ''}`} />
                  Evaluar
                </button>
                <button
                  type="button"
                  onClick={() => setShowNewRule((v) => !v)}
                  className="px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-900 text-white hover:bg-slate-800 cursor-pointer flex items-center gap-1.5"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Nueva regla
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

      {/* TAB 3: VISUAL SERVICE TOPOLOGY / DEPENDENCY MAP */}
      {activeTab === 'topology' && (
        <div className="space-y-4">
          <section className="bg-white border border-slate-200 rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-slate-900">Mapa visual de topología y dependencias</h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Flujo en vivo: Dominios/Monitores → Proyectos → Bases de datos / Redis / Catálogo → Servidores.
                </p>
              </div>
              <div className="flex items-center gap-2 text-xs">
                {topology && (
                  <span className="px-2.5 py-1 rounded-full bg-slate-100 border border-slate-200 text-slate-700 font-mono tabular-nums">
                    {topology.summary.totalNodes} nodos · {topology.summary.totalEdges} enlaces
                  </span>
                )}
                <button
                  type="button"
                  onClick={() => void loadTopology()}
                  disabled={topologyLoading}
                  className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer flex items-center gap-1.5"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${topologyLoading ? 'animate-spin' : ''}`} />
                  Actualizar mapa
                </button>
              </div>
            </div>

            {topologyLoading && !topology ? (
              <div className="p-10 text-center text-xs text-slate-500">Construyendo mapa de dependencias…</div>
            ) : !topology || !topologyLayout || topology.nodes.length === 0 ? (
              <div className="p-10 text-center text-xs text-slate-500">
                Crea tu primer proyecto o base de datos para visualizar su topología de red.
              </div>
            ) : (
              <div className="p-4 overflow-x-auto bg-slate-50/60">
                <svg
                  viewBox={`0 0 ${topologyLayout.svgW} ${topologyLayout.svgH}`}
                  className="w-full min-w-[780px] h-auto select-none"
                  role="img"
                  aria-label="Mapa de topología de servicios Culkibo"
                >
                  {/* Column headers */}
                  {topologyLayout.cols.map((col) => (
                    <text
                      key={col.title}
                      x={col.x}
                      y={20}
                      className="fill-slate-400 text-[11px] font-semibold uppercase tracking-wider"
                    >
                      {col.title}
                    </text>
                  ))}

                  {/* Curved dependency edges */}
                  {topology.edges.map((edge) => {
                    const fromPos = topologyLayout.positioned.get(edge.from);
                    const toPos = topologyLayout.positioned.get(edge.to);
                    if (!fromPos || !toPos) return null;
                    const x1 = fromPos.x + topologyLayout.nodeW;
                    const y1 = fromPos.y + topologyLayout.nodeH / 2;
                    const x2 = toPos.x;
                    const y2 = toPos.y + topologyLayout.nodeH / 2;
                    const midX = (x1 + x2) / 2;
                    const isHighlighted = selectedNodeId === edge.from || selectedNodeId === edge.to;
                    const stroke = HEALTH_STROKE[edge.status] || '#94a3b8';
                    return (
                      <g key={edge.id} opacity={selectedNodeId && !isHighlighted ? 0.22 : 0.9}>
                        <path
                          d={`M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`}
                          fill="none"
                          stroke={stroke}
                          strokeWidth={isHighlighted ? 2.2 : 1.4}
                        />
                        {edge.label && (
                          <text
                            x={midX}
                            y={(y1 + y2) / 2 - 4}
                            textAnchor="middle"
                            className="fill-slate-500 text-[9px] font-mono"
                          >
                            {edge.label}
                          </text>
                        )}
                      </g>
                    );
                  })}

                  {/* Interactive service nodes */}
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
                    const strokeColor = isSelected ? '#0f172a' : '#e2e8f0';
                    const dotColor = HEALTH_STROKE[node.health] || '#94a3b8';
                    return (
                      <g
                        key={node.id}
                        transform={`translate(${x}, ${y})`}
                        onClick={() => setSelectedNodeId((prev) => (prev === node.id ? null : node.id))}
                        className="cursor-pointer"
                        opacity={isConnected ? 1 : 0.35}
                      >
                        <rect
                          width={topologyLayout.nodeW}
                          height={topologyLayout.nodeH}
                          rx={10}
                          fill="#ffffff"
                          stroke={strokeColor}
                          strokeWidth={isSelected ? 2 : 1}
                        />
                        <circle cx={16} cy={22} r={4.5} fill={dotColor} />
                        <text x={28} y={25} className="fill-slate-900 text-[12px] font-semibold">
                          {node.label.length > 22 ? `${node.label.slice(0, 21)}…` : node.label}
                        </text>
                        <text x={28} y={44} className="fill-slate-500 text-[10px] font-mono">
                          {(node.sublabel || node.kind).slice(0, 26)}
                        </text>
                      </g>
                    );
                  })}
                </svg>
              </div>
            )}
          </section>

          {selectedNode && (
            <section className="bg-white border border-slate-200 rounded-xl p-4 text-xs space-y-2">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  {(() => {
                    const Icon = KIND_ICON[selectedNode.kind] || Activity;
                    return <Icon className="w-4 h-4 text-slate-700" />;
                  })()}
                  <span className="font-semibold text-slate-900 text-sm">{selectedNode.label}</span>
                  <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 font-mono text-[10px]`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${HEALTH_DOT[selectedNode.health] || HEALTH_DOT.unknown}`} />
                    {selectedNode.status}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedNodeId(null)}
                  className="text-slate-400 hover:text-slate-700 cursor-pointer"
                >
                  Cerrar
                </button>
              </div>
              {selectedEdges.length > 0 && (
                <div className="text-slate-600">
                  Conexiones ({selectedEdges.length}):{' '}
                  {selectedEdges.map((e) => `${e.from.split(':')[1]} → ${e.to.split(':')[1]} (${e.label || e.kind})`).join(' · ')}
                </div>
              )}
            </section>
          )}
        </div>
      )}
    </div>
  );
};
