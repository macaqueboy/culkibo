import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Activity,
  Plus,
  RefreshCw,
  Trash2,
  ExternalLink,
  Copy,
  Check,
  Loader2,
  AlertTriangle,
  Globe,
  Moon,
  Sun,
  TrendingDown,
  SlidersHorizontal,
  Radio,
  ShieldCheck,
  Pencil,
} from 'lucide-react';
import {
  api,
  apiFetch,
  type UptimeMonitor,
  type PublicStatusPage,
  type ResourceAdvisorReport,
  type SleepPolicy,
  type Project,
} from '../lib/api';
import { copyToClipboard } from '../lib/clipboard';
import { useI18n } from '../lib/i18n';
import { Modal } from './Modal';
import { HelpTip } from './HelpTip';

interface UptimeStatusViewProps {
  onNotify: (msg: string, type?: 'info' | 'success' | 'error') => void;
}

type UptimeTab = 'monitors' | 'pages' | 'advisor';

const MONITOR_STATUS_STYLE: Record<string, { label: string; dot: string; badge: string }> = {
  up: { label: 'Operativo', dot: 'bg-emerald-500', badge: 'bg-emerald-50 text-emerald-700 border-emerald-200' },
  degraded: { label: 'Degradado', dot: 'bg-amber-500', badge: 'bg-amber-50 text-amber-800 border-amber-200' },
  down: { label: 'Caído', dot: 'bg-red-500', badge: 'bg-red-50 text-red-700 border-red-200' },
  pending: { label: 'Pendiente', dot: 'bg-slate-400', badge: 'bg-slate-100 text-slate-600 border-slate-200' },
};

const ACCENT_PRESETS = ['#18181b', '#059669', '#2563eb', '#d97706', '#dc2626'];

function formatPct(val?: number | null): string {
  if (val == null || !Number.isFinite(val)) return '—';
  return `${val.toFixed(val === 100 ? 0 : 2)}%`;
}

function formatMs(val?: number | null): string {
  if (val == null || !Number.isFinite(val)) return '—';
  return `${Math.round(val)} ms`;
}

function formatEur(val?: number | null): string {
  if (val == null || !Number.isFinite(val)) return '—';
  return `${val.toFixed(val >= 100 ? 0 : 1)} €`;
}

export const UptimeStatusView: React.FC<UptimeStatusViewProps> = ({ onNotify }) => {
  const { t } = useI18n();
  const [tab, setTab] = useState<UptimeTab>('monitors');
  const [loading, setLoading] = useState(true);
  const [monitors, setMonitors] = useState<UptimeMonitor[]>([]);
  const [pages, setPages] = useState<PublicStatusPage[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [advisor, setAdvisor] = useState<ResourceAdvisorReport | null>(null);
  const [sleepPolicies, setSleepPolicies] = useState<Record<string, SleepPolicy>>({});

  const [vpsMonthlyEur, setVpsMonthlyEur] = useState<string>('12');
  const [advisorBusy, setAdvisorBusy] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Add/Edit Monitor modal
  const [monitorModalOpen, setMonitorModalOpen] = useState(false);
  const [editingMonitorId, setEditingMonitorId] = useState<string | null>(null);
  const [monForm, setMonForm] = useState({
    name: '',
    type: 'http' as 'http' | 'tcp' | 'managed_project',
    url: '',
    host: '',
    port: '443',
    projectId: '',
    healthPath: '/',
    intervalSec: '60',
    expectedStatus: '200',
    keyword: '',
    maxLatencyMs: '3000',
    public: true,
  });

  // Manual status page incident modal
  const [incidentSlug, setIncidentSlug] = useState<string | null>(null);
  const [incidentForm, setIncidentForm] = useState({
    title: '',
    severity: 'minor' as 'minor' | 'major' | 'critical' | 'maintenance',
    message: '',
  });

  // Status Page Builder modal
  const [pageModalOpen, setPageModalOpen] = useState(false);
  const [pageForm, setPageForm] = useState({
    slug: 'estado',
    title: 'Estado de los servicios',
    description: 'Disponibilidad en tiempo real e historial de incidentes.',
    accentColor: '#18181b',
    monitorIds: [] as string[],
  });

  // Sleep Policy modal
  const [sleepModalProject, setSleepModalProject] = useState<Project | null>(null);
  const [sleepForm, setSleepForm] = useState({
    enabled: true,
    idleMinutes: '15',
    mode: 'pause' as 'pause' | 'stop',
    excludeCrons: true,
  });

  const loadAll = useCallback(async (eurOverride?: number) => {
    try {
      const eur = eurOverride ?? (Number.parseFloat(vpsMonthlyEur) || 12);
      const [monRes, pageRes, projRes, advRes] = await Promise.all([
        api.getUptimeMonitors().catch(() => ({ monitors: [] })),
        api.getStatusPages().catch(() => ({ pages: [] })),
        api.getProjects().catch(() => []),
        api.getResourceAdvisor(eur).catch(() => null),
      ]);
      const projList = Array.isArray(projRes) ? projRes : [];
      setMonitors(monRes.monitors || []);
      setPages(pageRes.pages || []);
      setProjects(projList);
      setAdvisor(advRes);

      if (projList.length > 0) {
        // Prefer bulk GET /api/sleep to avoid N+1 requests; fallback to batched per-project reads for ALL projects
        let loadedBulk = false;
        try {
          const bulkRes = await apiFetch('/api/sleep');
          if (bulkRes.ok) {
            const bulkData = await bulkRes.json();
            const list: SleepPolicy[] = Array.isArray(bulkData)
              ? bulkData
              : Array.isArray(bulkData?.policies)
                ? bulkData.policies
                : [];
            const map: Record<string, SleepPolicy> = {};
            for (const pol of list) {
              if (pol && pol.projectId) map[pol.projectId] = pol;
            }
            setSleepPolicies(map);
            loadedBulk = true;
          }
        } catch {}

        if (!loadedBulk) {
          const map: Record<string, SleepPolicy> = {};
          const chunkSize = 10;
          for (let i = 0; i < projList.length; i += chunkSize) {
            const chunk = projList.slice(i, i + chunkSize);
            const entries = await Promise.all(
              chunk.map(async (p) => {
                const pol = await api.getSleepPolicy(p.id).catch(() => null);
                return pol ? ([p.id, pol] as const) : null;
              })
            );
            for (const entry of entries) {
              if (entry) map[entry[0]] = entry[1];
            }
          }
          setSleepPolicies(map);
        }
      }
    } finally {
      setLoading(false);
    }
  }, [vpsMonthlyEur]);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const copy = async (text: string, id: string, label = 'Copiado al portapapeles') => {
    const ok = await copyToClipboard(text);
    if (!ok) {
      onNotify('No se pudo copiar al portapapeles', 'error');
      return;
    }
    setCopiedKey(id);
    window.setTimeout(() => setCopiedKey(null), 1800);
    onNotify(label, 'success');
  };

  const openNewMonitor = () => {
    setEditingMonitorId(null);
    setMonForm({
      name: '',
      type: 'http',
      url: '',
      host: '',
      port: '443',
      projectId: projects[0]?.id || '',
      healthPath: '/',
      intervalSec: '60',
      expectedStatus: '200',
      keyword: '',
      maxLatencyMs: '3000',
      public: true,
    });
    setMonitorModalOpen(true);
  };

  const openEditMonitor = (mon: UptimeMonitor) => {
    const monAny = mon as any;
    const isManaged = Boolean(monAny.allowLocalProject || mon.type === 'managed_project');
    setEditingMonitorId(mon.id);
    setMonForm({
      name: mon.name || '',
      type: isManaged ? 'managed_project' : (mon.type === 'tcp' ? 'tcp' : 'http'),
      url: mon.url || '',
      host: mon.host || '',
      port: String(mon.port ?? 443),
      projectId: mon.projectId || projects[0]?.id || '',
      healthPath: monAny.healthPath || '/',
      intervalSec: String(mon.intervalSec || 60),
      expectedStatus: String(mon.expectedStatus ?? 200),
      keyword: mon.keyword || '',
      maxLatencyMs: mon.maxLatencyMs != null ? String(mon.maxLatencyMs) : '3000',
      public: mon.public !== false,
    });
    setMonitorModalOpen(true);
  };

  const handleCreateMonitor = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!monForm.name.trim()) return;
    setBusyId('create-monitor');
    try {
      const intervalSec = Math.max(30, Number.parseInt(monForm.intervalSec, 10) || 60);
      const expectedStatus = Number.parseInt(monForm.expectedStatus, 10) || 200;
      const maxLatencyMs = Number.parseInt(monForm.maxLatencyMs, 10) || undefined;
      const cleanHealthPath = (monForm.healthPath.trim() || '/').startsWith('/')
        ? (monForm.healthPath.trim() || '/')
        : `/${monForm.healthPath.trim()}`;
      const body = {
        name: monForm.name.trim(),
        type: monForm.type,
        ...(monForm.type === 'http' ? { url: monForm.url.trim(), expectedStatus, keyword: monForm.keyword.trim() || undefined } : {}),
        ...(monForm.type === 'tcp' ? { host: monForm.host.trim(), port: Number.parseInt(monForm.port, 10) || 443 } : {}),
        ...(monForm.type === 'managed_project'
          ? { projectId: monForm.projectId, allowLocalProject: true, healthPath: cleanHealthPath, expectedStatus }
          : {}),
        intervalSec,
        maxLatencyMs,
        public: monForm.public,
      };
      if (editingMonitorId) {
        const res = await apiFetch(`/api/uptime/monitors/${encodeURIComponent(editingMonitorId)}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        if (!res.ok) {
          const d = await res.json().catch(() => ({}));
          throw new Error(d.error || 'No se pudo actualizar el monitor');
        }
        onNotify('Monitor de disponibilidad actualizado', 'success');
      } else {
        const res = await apiFetch('/api/uptime/monitors', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        if (!res.ok) {
          const d = await res.json().catch(() => ({}));
          throw new Error(d.error || 'No se pudo crear el monitor');
        }
        onNotify('Monitor de disponibilidad creado y activo', 'success');
      }
      setMonitorModalOpen(false);
      setEditingMonitorId(null);
      await loadAll();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudo guardar el monitor', 'error');
    } finally {
      setBusyId(null);
    }
  };

  const handlePublishPageIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incidentSlug || !incidentForm.title.trim()) return;
    setBusyId(`inc-${incidentSlug}`);
    try {
      const res = await apiFetch(`/api/uptime/pages/${encodeURIComponent(incidentSlug)}/incidents`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: incidentForm.title.trim(),
          severity: incidentForm.severity,
          message: incidentForm.message.trim(),
        }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.error || 'No se pudo publicar el incidente en la página de estado');
      }
      setIncidentSlug(null);
      setIncidentForm({ title: '', severity: 'minor', message: '' });
      onNotify('Incidente publicado en la página pública de estado', 'success');
      await loadAll();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Error al publicar el incidente', 'error');
    } finally {
      setBusyId(null);
    }
  };

  const handleResolvePageIncident = async (slug: string, incidentId: string) => {
    setBusyId(`res-inc-${incidentId}`);
    try {
      const res = await apiFetch(`/api/uptime/pages/${encodeURIComponent(slug)}/incidents/${encodeURIComponent(incidentId)}/resolve`, {
        method: 'POST',
      });
      if (!res.ok) throw new Error('No se pudo resolver el incidente');
      onNotify('Incidente marcado como resuelto', 'success');
      await loadAll();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Error al resolver el incidente', 'error');
    } finally {
      setBusyId(null);
    }
  };

  const handleApplyRecommendation = async (rec: any) => {
    const action = rec?.action;
    const pid = rec?.projectId || action?.projectId;
    if (!pid) return;
    setBusyId(`rec-${rec.id || pid}`);
    try {
      if (action?.kind === 'enable_sleep' || rec.type === 'auto_sleep_candidate' || rec.category === 'auto_sleep') {
        await api.saveSleepPolicy(pid, {
          enabled: true,
          mode: action?.suggestedMode === 'pause' ? 'pause' : 'stop',
          idleMinutes: Number(action?.suggestedIdleMinutes) || 15,
          excludeCrons: true,
        });
        onNotify(`Auto-Sleep activado para ${rec.projectName || rec.target || pid}`, 'success');
      } else if (action?.kind === 'resize_memory' || rec.recommendedMemoryMb) {
        const nextMb = Number(action?.recommendedMemoryMb || rec.recommendedMemoryMb);
        if (!Number.isFinite(nextMb) || nextMb < 64) return;
        await api.updateProject(pid, { memoryMb: nextMb });
        onNotify(`Límite de RAM actualizado a ${nextMb} MB para ${rec.projectName || rec.target || pid}`, 'success');
      }
      await loadAll();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudo aplicar la recomendación', 'error');
    } finally {
      setBusyId(null);
    }
  };

  const handleCheckNow = async (mon: UptimeMonitor) => {
    setBusyId(`chk-${mon.id}`);
    try {
      const res = await api.runUptimeCheck(mon.id);
      const ok = res.check?.ok ?? res.monitor?.status === 'up';
      onNotify(
        `${mon.name}: ${ok ? 'Operativo' : 'Fallo detectado'}${res.check?.latencyMs != null ? ` (${Math.round(res.check.latencyMs)} ms)` : ''}`,
        ok ? 'success' : 'error'
      );
      await loadAll();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Error al ejecutar la comprobación', 'error');
    } finally {
      setBusyId(null);
    }
  };

  const handleDeleteMonitor = async (mon: UptimeMonitor) => {
    setBusyId(`del-mon-${mon.id}`);
    try {
      await api.deleteUptimeMonitor(mon.id);
      onNotify(`Monitor «${mon.name}» eliminado`, 'info');
      await loadAll();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudo eliminar el monitor', 'error');
    } finally {
      setBusyId(null);
    }
  };

  const openNewPage = () => {
    setPageForm({
      slug: pages.length === 0 ? 'estado' : `estado-${pages.length + 1}`,
      title: 'Estado de los servicios',
      description: 'Disponibilidad en tiempo real e historial de incidentes.',
      accentColor: '#18181b',
      monitorIds: monitors.filter((m) => m.public !== false).map((m) => m.id),
    });
    setPageModalOpen(true);
  };

  const openEditPage = (p: PublicStatusPage) => {
    setPageForm({
      slug: p.slug,
      title: p.title,
      description: p.description || '',
      accentColor: p.accentColor || '#18181b',
      monitorIds: p.monitorIds || [],
    });
    setPageModalOpen(true);
  };

  const handleSavePage = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanSlug = pageForm.slug.trim().toLowerCase().replace(/[^a-z0-9-]/g, '-');
    if (!cleanSlug || !pageForm.title.trim()) return;
    setBusyId('save-page');
    try {
      await api.saveStatusPage({
        slug: cleanSlug,
        title: pageForm.title.trim(),
        description: pageForm.description.trim(),
        accentColor: pageForm.accentColor,
        monitorIds: pageForm.monitorIds,
      });
      setPageModalOpen(false);
      onNotify(`Página pública /status/${cleanSlug} guardada`, 'success');
      await loadAll();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudo guardar la página de estado', 'error');
    } finally {
      setBusyId(null);
    }
  };

  const handleDeletePage = async (slug: string) => {
    setBusyId(`del-page-${slug}`);
    try {
      await api.deleteStatusPage(slug);
      onNotify(`Página /status/${slug} eliminada`, 'info');
      await loadAll();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudo eliminar la página de estado', 'error');
    } finally {
      setBusyId(null);
    }
  };

  const handleRecalculateAdvisor = async (e: React.FormEvent) => {
    e.preventDefault();
    const eur = Math.max(0, Number.parseFloat(vpsMonthlyEur) || 0);
    setAdvisorBusy(true);
    try {
      const report = await api.getResourceAdvisor(eur);
      setAdvisor(report);
      onNotify(`Ahorro recalculado con VPS de ${eur} €/mes`, 'success');
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudo recalcular el asesor', 'error');
    } finally {
      setAdvisorBusy(false);
    }
  };

  const openSleepModal = (proj: Project) => {
    const existing = sleepPolicies[proj.id];
    setSleepModalProject(proj);
    setSleepForm({
      enabled: existing ? Boolean(existing.enabled) : true,
      idleMinutes: String(existing?.idleMinutes ?? 15),
      mode: existing?.mode || 'pause',
      excludeCrons: existing?.excludeCrons !== false,
    });
  };

  const handleSaveSleepPolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!sleepModalProject) return;
    setBusyId(`sleep-pol-${sleepModalProject.id}`);
    try {
      const idleMinutes = Math.max(5, Number.parseInt(sleepForm.idleMinutes, 10) || 15);
      const saved = await api.saveSleepPolicy(sleepModalProject.id, {
        enabled: sleepForm.enabled,
        idleMinutes,
        mode: sleepForm.mode,
        excludeCrons: sleepForm.excludeCrons,
      });
      setSleepPolicies((prev) => ({ ...prev, [sleepModalProject.id]: saved }));
      onNotify(
        sleepForm.enabled
          ? `Auto-reposo activado para ${sleepModalProject.name} (${idleMinutes} min)`
          : `Auto-reposo desactivado para ${sleepModalProject.name}`,
        'success'
      );
      setSleepModalProject(null);
      await loadAll();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudo guardar la política de reposo', 'error');
    } finally {
      setBusyId(null);
    }
  };

  const handleSleepNow = async (proj: Project) => {
    setBusyId(`sleep-${proj.id}`);
    try {
      const res: any = await api.sleepProject(proj.id);
      if (res && (res.slept === false || res.blocked === true || res.sleeping === false)) {
        onNotify(
          res.reason || res.error || `No se pudo suspender ${proj.name} porque tiene operaciones activas`,
          'error'
        );
      } else {
        onNotify(`${proj.name} puesto en reposo (despertará automáticamente al recibir tráfico)`, 'success');
      }
      await loadAll();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudo suspender el proyecto', 'error');
    } finally {
      setBusyId(null);
    }
  };

  const handleWakeNow = async (proj: Project) => {
    setBusyId(`wake-${proj.id}`);
    try {
      const res: any = await api.wakeProject(proj.id);
      if (res && (res.woken === false || res.awake === false)) {
        onNotify(res.error || `No se pudo reactivar ${proj.name}`, 'error');
      } else {
        onNotify(`${proj.name} reactivado y en línea`, 'success');
      }
      await loadAll();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudo despertar el proyecto', 'error');
    } finally {
      setBusyId(null);
    }
  };

  const summary = useMemo(() => {
    const upCount = monitors.filter((m) => m.status === 'up').length;
    const incidents = monitors.filter((m) => Boolean(m.incidentOpen || m.activeIncidentId || m.status === 'down')).length;
    const uptimes = monitors.map((m) => m.uptime24h).filter((x): x is number => typeof x === 'number');
    const avgUptime = uptimes.length > 0 ? uptimes.reduce((a, b) => a + b, 0) / uptimes.length : null;
    const p95s = monitors.map((m) => m.p95LatencyMs).filter((x): x is number => typeof x === 'number');
    const avgP95 = p95s.length > 0 ? p95s.reduce((a, b) => a + b, 0) / p95s.length : null;
    return { upCount, incidents, avgUptime, avgP95 };
  }, [monitors]);

  if (loading) {
    return (
      <div className="flex items-center justify-center gap-2 py-16 text-xs text-slate-500">
        <Loader2 className="w-4 h-4 animate-spin" />
        <span>{t('uptime.loading')}</span>
      </div>
    );
  }

  const origin = window.location.origin;

  const localizedMonStatus = (status: string): string => {
    if (status === 'up') return t('uptime.statusUp');
    if (status === 'degraded') return t('uptime.statusDegraded');
    if (status === 'down') return t('uptime.statusDown');
    return t('uptime.statusPending');
  };

  return (
    <div className="space-y-5">
      {/* Cabecera */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">{t('uptime.title')}</h1>
            <HelpTip title="Built-in Synthetic Monitoring">
              <p>Checks services every 30–300s with SSRF guard, publishes <code className="font-mono">/status/:slug</code> without leaking internal URLs, and hibernates idle projects.</p>
            </HelpTip>
          </div>
          <p className="text-sm text-slate-500 mt-1 max-w-2xl">{t('uptime.subtitle')}</p>
        </div>

        <div className="flex items-center gap-2 flex-wrap shrink-0">
          <div className="inline-flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs overflow-x-auto no-scrollbar max-w-full">
            {([
              { id: 'monitors', label: `${t('uptime.tabMonitors')} (${monitors.length})`, icon: Radio },
              { id: 'pages', label: `${t('uptime.tabPages')} (${pages.length})`, icon: Globe },
              { id: 'advisor', label: t('uptime.tabAdvisor'), icon: TrendingDown },
            ] as const).map((tabItem) => {
              const Icon = tabItem.icon;
              return (
                <button
                  key={tabItem.id}
                  type="button"
                  onClick={() => setTab(tabItem.id)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium whitespace-nowrap transition-colors cursor-pointer ${
                    tab === tabItem.id ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span>{tabItem.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* TAB 1: MONITORS */}
      {tab === 'monitors' && (
        <div className="space-y-4">
          <div className="bg-white border border-slate-200 rounded-xl grid grid-cols-2 lg:grid-cols-4 divide-y lg:divide-y-0 lg:divide-x divide-slate-200">
            <div className="p-4">
              <div className="text-xs text-slate-500">{t('uptime.kpiOperational')}</div>
              <div className="text-xl font-semibold text-slate-900 mt-1 tabular-nums">
                {summary.upCount} <span className="text-sm font-normal text-slate-400">/ {monitors.length}</span>
              </div>
            </div>
            <div className="p-4">
              <div className="text-xs text-slate-500">{t('uptime.kpiAvailability')}</div>
              <div className="text-xl font-semibold text-emerald-700 mt-1 tabular-nums">
                {formatPct(summary.avgUptime)}
              </div>
            </div>
            <div className="p-4">
              <div className="text-xs text-slate-500">{t('uptime.kpiLatency')}</div>
              <div className="text-xl font-semibold text-slate-900 mt-1 tabular-nums">
                {formatMs(summary.avgP95)}
              </div>
            </div>
            <div className="p-4">
              <div className="text-xs text-slate-500">{t('uptime.kpiIncidents')}</div>
              <div className={`text-xl font-semibold mt-1 tabular-nums ${summary.incidents > 0 ? 'text-red-600' : 'text-slate-900'}`}>
                {summary.incidents}
              </div>
            </div>
          </div>

          <div className="flex items-center justify-between gap-2 flex-wrap">
            <span className="text-xs text-slate-500">{t('uptime.alertHint')}</span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => void loadAll()}
                aria-label="Refresh monitors"
                className="p-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-600 cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
              <button
                type="button"
                onClick={openNewMonitor}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>{t('uptime.addMonitor')}</span>
              </button>
            </div>
          </div>

          {monitors.length === 0 ? (
            <div className="bg-white border border-slate-200 rounded-xl p-10 text-center space-y-3">
              <Activity className="w-8 h-8 text-slate-300 mx-auto" />
              <div className="text-sm font-semibold text-slate-900">{t('uptime.emptyMonitorsTitle')}</div>
              <p className="text-xs text-slate-500 max-w-md mx-auto">{t('uptime.emptyMonitorsDesc')}</p>
              <button
                type="button"
                onClick={openNewMonitor}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 text-white text-xs font-medium cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" /> {t('uptime.createFirstMonitor')}
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              {monitors.map((mon) => {
                const st = MONITOR_STATUS_STYLE[mon.status] || MONITOR_STATUS_STYLE.pending;
                const historyBars = Array.isArray(mon.history30) && mon.history30.length > 0
                  ? mon.history30.slice(-30)
                  : null;
                const recentBars = !historyBars ? (mon.recentChecks || []).slice(-30) : [];
                const paddedCount = historyBars ? Math.max(0, 30 - historyBars.length) : Math.max(0, 30 - recentBars.length);
                return (
                  <article key={mon.id} className="bg-white border border-slate-200 rounded-xl p-4 space-y-3">
                    <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <h2 className="text-sm font-semibold text-slate-900 truncate">{mon.name}</h2>
                          <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[10px] uppercase text-slate-600">
                            {mon.type === 'managed_project' ? 'Proyecto' : mon.type}
                          </span>
                          <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium border ${st.badge}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${st.dot}`} />
                            {localizedMonStatus(mon.status)}
                          </span>
                        </div>
                        <div className="text-xs font-mono text-slate-500 truncate mt-0.5">
                          {mon.url || mon.target || (mon.host ? `${mon.host}:${mon.port}` : mon.projectId || '—')} · {mon.intervalSec}s
                        </div>
                      </div>

                      <div className="flex items-center gap-1.5 shrink-0">
                        <button
                          type="button"
                          disabled={busyId === `chk-${mon.id}`}
                          onClick={() => void handleCheckNow(mon)}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-700 cursor-pointer disabled:opacity-50"
                        >
                          <RefreshCw className={`w-3.5 h-3.5 ${busyId === `chk-${mon.id}` ? 'animate-spin' : ''}`} />
                          <span>{t('uptime.checkNow')}</span>
                        </button>
                        <button
                          type="button"
                          aria-label={`Editar monitor ${mon.name}`}
                          onClick={() => openEditMonitor(mon)}
                          className="p-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-600 cursor-pointer"
                        >
                          <Pencil className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          aria-label={`Eliminar monitor ${mon.name}`}
                          disabled={busyId === `del-mon-${mon.id}`}
                          onClick={() => void handleDeleteMonitor(mon)}
                          className="p-1.5 rounded-lg bg-white hover:bg-red-50 border border-slate-200 hover:border-red-200 text-slate-500 hover:text-red-700 cursor-pointer"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>

                    {/* Barras de 30 comprobaciones recientes */}
                    <div className="flex items-end gap-0.5 h-6" aria-label="Historial de comprobaciones">
                      {Array.from({ length: paddedCount }).map((_, idx) => (
                        <span key={`empty-${idx}`} className="flex-1 h-4 rounded-[2px] bg-slate-100" />
                      ))}
                      {historyBars
                        ? historyBars.map((bar, idx) => (
                            <span
                              key={`h-${idx}`}
                              title={
                                bar.status === 'nodata'
                                  ? 'Sin datos'
                                  : `${bar.status === 'up' ? 'Operativo' : bar.status === 'degraded' ? 'Degradado' : 'Caído'}${bar.uptimePct != null ? ` (${bar.uptimePct}%)` : ''}`
                              }
                              className={`flex-1 rounded-[2px] ${
                                bar.status === 'nodata'
                                  ? 'h-4 bg-slate-100'
                                  : bar.status === 'down'
                                    ? 'h-6 bg-red-500'
                                    : bar.status === 'degraded'
                                      ? 'h-6 bg-amber-400'
                                      : 'h-6 bg-emerald-500'
                              }`}
                            />
                          ))
                        : recentBars.map((pt, idx) => (
                            <span
                              key={`${pt.at}-${idx}`}
                              title={`${new Date(pt.at).toLocaleTimeString('es-ES')} · ${pt.ok ? 'OK' : 'Fallo'}${pt.latencyMs != null ? ` (${Math.round(pt.latencyMs)} ms)` : ''}`}
                              className={`flex-1 h-6 rounded-[2px] ${
                                pt.ok
                                  ? (pt.status === 'degraded' ? 'bg-amber-400' : 'bg-emerald-500')
                                  : 'bg-red-500'
                              }`}
                            />
                          ))}
                    </div>

                    {/* Métricas 24h / 7d / 30d + p50 / p95 */}
                    <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-2 border-t border-slate-100 text-xs tabular-nums">
                      <div>
                        <span className="text-slate-400 block text-[11px]">Uptime 24h</span>
                        <span className="font-mono font-semibold text-slate-900">{formatPct(mon.uptime24h)}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[11px]">Uptime 7d</span>
                        <span className="font-mono font-semibold text-slate-900">{formatPct(mon.uptime7d)}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[11px]">Uptime 30d</span>
                        <span className="font-mono font-semibold text-slate-900">{formatPct(mon.uptime30d)}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[11px]">Latencia p50</span>
                        <span className="font-mono font-semibold text-slate-900">{formatMs(mon.p50LatencyMs)}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[11px]">Latencia p95</span>
                        <span className="font-mono font-semibold text-slate-900">{formatMs(mon.p95LatencyMs)}</span>
                      </div>
                    </div>

                    {mon.lastError && (
                      <div className="text-[11px] text-red-700 bg-red-50 border border-red-100 rounded-lg px-2.5 py-1.5 break-words">
                        Último error: {mon.lastError}
                      </div>
                    )}
                  </article>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: PUBLIC STATUS PAGES */}
      {tab === 'pages' && (
        <div className="space-y-4">
          <div className="bg-white border border-slate-200 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
            <div className="flex items-start gap-2.5 min-w-0">
              <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
              <div>
                <div className="font-semibold text-slate-900">{t('uptime.pagesPrivacyTitle')}</div>
                <p className="text-slate-500 mt-0.5">
                  Accessible at <code className="font-mono">/status/:slug</code> without auth. Exposes display names, uptime bars, and incidents only — never internal URLs or IPs.
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={openNewPage}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer shrink-0 self-start sm:self-auto"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>{t('uptime.newPage')}</span>
            </button>
          </div>

          {pages.length === 0 ? (
            <div className="bg-white border border-slate-200 rounded-xl p-10 text-center space-y-3">
              <Globe className="w-8 h-8 text-slate-300 mx-auto" />
              <div className="text-sm font-semibold text-slate-900">{t('uptime.emptyPagesTitle')}</div>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                Publica una página de estado profesional en segundos con insignia SVG incrustable para tu web o README.
              </p>
              <button
                type="button"
                onClick={openNewPage}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 text-white text-xs font-medium cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" /> Crear página /status/estado
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {pages.map((p) => {
                const publicHref = p.publicUrl || `${origin}/status/${encodeURIComponent(p.slug)}`;
                const badgeHref = p.badgeUrl || `${origin}/status/${encodeURIComponent(p.slug)}/badge.svg`;
                const mdBadge = `[![Estado](${badgeHref})](${publicHref})`;
                return (
                  <article key={p.slug} className="bg-white border border-slate-200 rounded-xl p-4 flex flex-col gap-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span
                            className="w-2.5 h-2.5 rounded-full shrink-0"
                            style={{ backgroundColor: p.accentColor || '#18181b' }}
                          />
                          <h2 className="text-sm font-semibold text-slate-900 truncate">{p.title}</h2>
                        </div>
                        <code className="text-xs font-mono text-slate-500 block mt-0.5 truncate">/status/{p.slug}</code>
                      </div>
                      <span className="px-2 py-0.5 rounded-full bg-slate-100 border border-slate-200 text-[11px] font-medium text-slate-700 tabular-nums shrink-0">
                        {(p.monitorIds || []).length} monitores
                      </span>
                    </div>

                    {p.description && <p className="text-xs text-slate-600">{p.description}</p>}

                    {Array.isArray((p as any).incidents) && (p as any).incidents.filter((i: any) => i.status === 'open').length > 0 && (
                      <div className="space-y-1.5">
                        {(p as any).incidents
                          .filter((i: any) => i.status === 'open')
                          .map((inc: any) => (
                            <div key={inc.id} className="flex items-center justify-between gap-2 bg-amber-50 border border-amber-200 rounded-lg px-2.5 py-1.5 text-[11px]">
                              <span className="text-amber-900 font-medium truncate">{inc.title}</span>
                              <button
                                type="button"
                                disabled={busyId === `res-inc-${inc.id}`}
                                onClick={() => void handleResolvePageIncident(p.slug, inc.id)}
                                className="px-2 py-0.5 rounded bg-white border border-amber-300 text-amber-900 font-medium hover:bg-amber-100 cursor-pointer shrink-0"
                              >
                                Resolver
                              </button>
                            </div>
                          ))}
                      </div>
                    )}

                    <div className="flex flex-wrap items-center gap-1.5 pt-2 border-t border-slate-100 mt-auto">
                      <a
                        href={`/status/${encodeURIComponent(p.slug)}`}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                        <span>Abrir vista previa</span>
                      </a>
                      <button
                        type="button"
                        onClick={() => void copy(publicHref, `url-${p.slug}`, 'URL pública copiada')}
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs text-slate-700 cursor-pointer"
                      >
                        {copiedKey === `url-${p.slug}` ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>URL</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => void copy(mdBadge, `md-${p.slug}`, 'Insignia Markdown SVG copiada')}
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs text-slate-700 cursor-pointer"
                      >
                        {copiedKey === `md-${p.slug}` ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>Badge SVG</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setIncidentSlug(p.slug);
                          setIncidentForm({ title: '', severity: 'minor', message: '' });
                        }}
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-white hover:bg-amber-50 border border-slate-200 hover:border-amber-200 text-xs text-slate-700 hover:text-amber-900 cursor-pointer"
                      >
                        <AlertTriangle className="w-3.5 h-3.5" />
                        <span>Incidente</span>
                      </button>
                      <button
                        type="button"
                        aria-label={`Editar página ${p.slug}`}
                        onClick={() => openEditPage(p)}
                        className="p-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-600 cursor-pointer ml-auto"
                      >
                        <Pencil className="w-3.5 h-3.5" />
                      </button>
                      <button
                        type="button"
                        aria-label={`Eliminar página ${p.slug}`}
                        disabled={busyId === `del-page-${p.slug}`}
                        onClick={() => void handleDeletePage(p.slug)}
                        className="p-1.5 rounded-lg bg-white hover:bg-red-50 border border-slate-200 hover:border-red-200 text-slate-500 hover:text-red-700 cursor-pointer"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </article>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: COST ADVISOR & AUTO-SLEEP */}
      {tab === 'advisor' && (
        <div className="space-y-5">
          {/* Barra de configuración de coste VPS */}
          <form
            onSubmit={handleRecalculateAdvisor}
            className="bg-white border border-slate-200 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
          >
            <div>
              <div className="font-semibold text-slate-900">{t('uptime.advisorTitle')}</div>
              <p className="text-slate-500 mt-0.5">
                Compare your real monthly VPS cost against managed PaaS (Railway, Render, Fly) and detect idle containers or OOM risk.
              </p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <label className="inline-flex items-center gap-1.5 text-slate-600">
                <span>VPS:</span>
                <input
                  type="number"
                  min={0}
                  step="0.5"
                  value={vpsMonthlyEur}
                  onChange={(e) => setVpsMonthlyEur(e.target.value)}
                  className="w-20 px-2.5 py-1.5 rounded-lg border border-slate-200 font-mono text-slate-900 tabular-nums"
                />
                <span>€/mo</span>
              </label>
              <button
                type="submit"
                disabled={advisorBusy}
                className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                {advisorBusy ? '…' : t('uptime.advisorRecalc')}
              </button>
            </div>
          </form>

          {/* KPIs de ahorro */}
          {(() => {
            const monthlySavings = advisor?.costLedger?.monthlySavingsEur ?? advisor?.savingsLedger?.monthlySavingsEur ?? null;
            const annualSavings = advisor?.costLedger?.annualSavingsEur ?? advisor?.savingsLedger?.annualSavingsEur ?? null;
            const saasMonthly = advisor?.costLedger?.saasAverageMonthlyEur ?? advisor?.savingsLedger?.estimatedSaasMonthlyEur ?? null;
            const vpsEur = advisor?.costLedger?.vpsMonthlyEur ?? advisor?.vpsMonthlyEur ?? Number(vpsMonthlyEur);
            const freeRamMb = advisor?.host?.freeMemMb ?? advisor?.host?.freeRamMb ?? null;
            const totalRamMb = advisor?.host?.totalMemMb ?? advisor?.host?.totalRamMb ?? null;
            const freePct = advisor?.host?.freeMemPct ?? advisor?.host?.freePercent ?? null;
            const reclaimableRamMb = advisor?.summary?.reclaimableRamMb ?? advisor?.savingsLedger?.reclaimableRamMb ?? null;
            return (
              <div className="bg-white border border-slate-200 rounded-xl grid grid-cols-2 lg:grid-cols-4 divide-y lg:divide-y-0 lg:divide-x divide-slate-200">
                <div className="p-4">
                  <div className="text-xs text-slate-500">{t('uptime.advisorMonthlySavings')}</div>
                  <div className="text-xl font-semibold text-emerald-700 mt-1 tabular-nums">
                    {formatEur(monthlySavings)}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5 tabular-nums">
                    {annualSavings != null
                      ? `${formatEur(annualSavings)} / yr`
                      : 'Live'}
                  </div>
                </div>
                <div className="p-4">
                  <div className="text-xs text-slate-500">{t('uptime.advisorSaasEq')}</div>
                  <div className="text-xl font-semibold text-slate-900 mt-1 tabular-nums">
                    {formatEur(saasMonthly)}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5 tabular-nums">
                    vs {formatEur(vpsEur)} VPS
                  </div>
                </div>
                <div className="p-4">
                  <div className="text-xs text-slate-500">{t('uptime.advisorFreeRam')}</div>
                  <div className="text-xl font-semibold text-slate-900 mt-1 tabular-nums">
                    {freeRamMb != null ? `${Math.round(freeRamMb)} MB` : '—'}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5 tabular-nums">
                    {freePct != null && totalRamMb != null
                      ? `${Math.round(freePct)}% / ${Math.round(totalRamMb)} MB`
                      : '—'}
                  </div>
                </div>
                <div className="p-4">
                  <div className="text-xs text-slate-500">{t('uptime.advisorReclaimable')}</div>
                  <div className="text-xl font-semibold text-slate-900 mt-1 tabular-nums">
                    {reclaimableRamMb != null ? `${Math.round(reclaimableRamMb)} MB` : '0 MB'}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5">Scale-to-Zero</div>
                </div>
              </div>
            );
          })()}

          {/* Recomendaciones priorizadas */}
          {advisor && advisor.recommendations && advisor.recommendations.length > 0 && (
            <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
              <div className="px-5 py-3 bg-slate-50 border-b border-slate-200 text-xs font-semibold text-slate-800">
                Recomendaciones accionables ({advisor.recommendations.length})
              </div>
              <div className="divide-y divide-slate-100">
                {advisor.recommendations.map((rec, idx) => {
                  const recAny = rec as any;
                  const recSavings = rec.estimatedMonthlySavingsEur ?? rec.estimatedSavingsEur;
                  const canApply = Boolean(
                    (rec.projectId || recAny.action?.projectId) &&
                    (recAny.action?.kind === 'enable_sleep' ||
                      recAny.action?.kind === 'resize_memory' ||
                      recAny.type === 'auto_sleep_candidate' ||
                      recAny.recommendedMemoryMb)
                  );
                  const applyLabel =
                    rec.actionLabel ||
                    (recAny.action?.kind === 'enable_sleep' || recAny.type === 'auto_sleep_candidate'
                      ? 'Activar Auto-Sleep'
                      : recAny.recommendedMemoryMb
                        ? `Ajustar a ${recAny.recommendedMemoryMb} MB`
                        : 'Aplicar');
                  const isCrit = rec.severity === 'critical';
                  const isWarn = rec.severity === 'high' || rec.severity === 'warn' || rec.severity === 'medium';
                  return (
                    <div key={rec.id || `${rec.category || recAny.type}-${idx}`} className="px-5 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                      <div className="flex items-start gap-2.5 min-w-0">
                        <AlertTriangle
                          className={`w-4 h-4 shrink-0 mt-0.5 ${
                            isCrit ? 'text-red-600' : isWarn ? 'text-amber-600' : 'text-emerald-600'
                          }`}
                        />
                        <div className="min-w-0">
                          <div className="font-semibold text-slate-900">{rec.title}</div>
                          <p className="text-slate-500 mt-0.5 leading-relaxed">{rec.detail}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0 tabular-nums flex-wrap">
                        {rec.reclaimableRamMb ? (
                          <span className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-800 font-mono text-[11px]">
                            +{Math.round(rec.reclaimableRamMb)} MB RAM
                          </span>
                        ) : null}
                        {recSavings ? (
                          <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-700 font-mono text-[11px]">
                            {formatEur(recSavings)}/mes
                          </span>
                        ) : null}
                        {canApply && (
                          <button
                            type="button"
                            disabled={busyId === `rec-${rec.id || rec.projectId}`}
                            onClick={() => void handleApplyRecommendation(recAny)}
                            className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-[11px] font-medium cursor-pointer disabled:opacity-50"
                          >
                            {busyId === `rec-${rec.id || rec.projectId}` ? 'Aplicando…' : applyLabel}
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Controles de Auto-Sleep por proyecto (Scale-to-Zero) */}
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
            <div className="px-5 py-3.5 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-2">
              <div>
                <h2 className="text-xs font-semibold text-slate-900">Control Scale-to-Zero / Auto-Reposo por proyecto</h2>
                <p className="text-[11px] text-slate-500">
                  Pausa o detiene proyectos inactivos respetando crons, despliegues y Live Sync; Caddy los despierta en la primera petición HTTPS.
                </p>
              </div>
            </div>

            {projects.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500">
                No hay proyectos creados todavía para configurar auto-reposo.
              </div>
            ) : (
              <div className="divide-y divide-slate-100">
                {projects.map((proj) => {
                  const pol = sleepPolicies[proj.id];
                  const isSleeping = Boolean((pol?.sleeping ?? pol?.isSleeping) || proj.status === 'sleeping' || proj.status === 'hibernated');
                  return (
                    <div key={proj.id} className="px-5 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-semibold text-slate-900 truncate">{proj.name}</span>
                          <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium border ${
                            isSleeping
                              ? 'bg-amber-50 text-amber-800 border-amber-200'
                              : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          }`}>
                            {isSleeping ? <Moon className="w-3 h-3" /> : <Sun className="w-3 h-3" />}
                            {isSleeping ? 'En reposo' : 'Activo'}
                          </span>
                          {pol?.enabled && (
                            <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-600 text-[10px] font-mono tabular-nums">
                              Auto ({pol.mode === 'stop' ? 'detener' : 'pausar'} tras {pol.idleMinutes}m)
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-500 mt-0.5 tabular-nums">
                          Límite RAM: {proj.memoryMb || 512} MB{proj.domains?.[0] ? ` · ${proj.domains[0]}` : ''}
                        </div>
                      </div>

                      <div className="flex items-center gap-1.5 flex-wrap shrink-0">
                        <button
                          type="button"
                          onClick={() => openSleepModal(proj)}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 font-medium cursor-pointer"
                        >
                          <SlidersHorizontal className="w-3.5 h-3.5" />
                          <span>Política</span>
                        </button>
                        {isSleeping ? (
                          <button
                            type="button"
                            disabled={busyId === `wake-${proj.id}`}
                            onClick={() => void handleWakeNow(proj)}
                            className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                          >
                            {busyId === `wake-${proj.id}` ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Sun className="w-3.5 h-3.5" />}
                            <span>Despertar</span>
                          </button>
                        ) : (
                          <button
                            type="button"
                            disabled={busyId === `sleep-${proj.id}`}
                            onClick={() => void handleSleepNow(proj)}
                            className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-white hover:bg-amber-50 border border-slate-200 hover:border-amber-200 text-slate-700 hover:text-amber-900 font-medium cursor-pointer disabled:opacity-50"
                          >
                            {busyId === `sleep-${proj.id}` ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Moon className="w-3.5 h-3.5" />}
                            <span>Dormir ahora</span>
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Modal: Añadir / Editar Monitor */}
      <Modal
        open={monitorModalOpen}
        onClose={() => {
          setMonitorModalOpen(false);
          setEditingMonitorId(null);
        }}
        title={editingMonitorId ? 'Editar monitor de disponibilidad' : 'Nuevo monitor de disponibilidad'}
        subtitle="Las URLs externas se validan contra SSRF y DNS rebinding en cada sondeo."
        maxWidthClass="max-w-lg"
      >
        <form onSubmit={handleCreateMonitor} className="p-5 space-y-4 text-xs">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label className="block">
              <span className="font-medium text-slate-700">Nombre visible</span>
              <input
                required
                value={monForm.name}
                onChange={(e) => setMonForm({ ...monForm, name: e.target.value })}
                placeholder="API Producción"
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 text-slate-900"
              />
            </label>
            <label className="block">
              <span className="font-medium text-slate-700">Tipo de comprobación</span>
              <select
                value={monForm.type}
                onChange={(e) => setMonForm({ ...monForm, type: e.target.value as 'http' | 'tcp' | 'managed_project' })}
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 bg-white text-slate-900"
              >
                <option value="http">HTTP / HTTPS</option>
                <option value="managed_project">Proyecto gestionado por Culkibo</option>
                <option value="tcp">Puerto TCP</option>
              </select>
            </label>
          </div>

          {monForm.type === 'http' && (
            <label className="block">
              <span className="font-medium text-slate-700">URL pública a comprobar</span>
              <input
                type="url"
                required
                value={monForm.url}
                onChange={(e) => setMonForm({ ...monForm, url: e.target.value })}
                placeholder="https://api.midominio.com/health"
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900"
              />
            </label>
          )}

          {monForm.type === 'tcp' && (
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <label className="block sm:col-span-2">
                <span className="font-medium text-slate-700">Host público</span>
                <input
                  required
                  value={monForm.host}
                  onChange={(e) => setMonForm({ ...monForm, host: e.target.value })}
                  placeholder="mail.midominio.com"
                  className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900"
                />
              </label>
              <label className="block">
                <span className="font-medium text-slate-700">Puerto</span>
                <input
                  type="number"
                  min={1}
                  max={65535}
                  required
                  value={monForm.port}
                  onChange={(e) => setMonForm({ ...monForm, port: e.target.value })}
                  className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900 tabular-nums"
                />
              </label>
            </div>
          )}

          {monForm.type === 'managed_project' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <label className="block">
                <span className="font-medium text-slate-700">Proyecto Culkibo</span>
                <select
                  required
                  value={monForm.projectId}
                  onChange={(e) => setMonForm({ ...monForm, projectId: e.target.value })}
                  className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 bg-white text-slate-900"
                >
                  <option value="">Selecciona un proyecto…</option>
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>{p.name}</option>
                  ))}
                </select>
              </label>
              <label className="block">
                <span className="font-medium text-slate-700">Ruta de salud (healthPath)</span>
                <input
                  value={monForm.healthPath}
                  onChange={(e) => setMonForm({ ...monForm, healthPath: e.target.value })}
                  placeholder="/health"
                  className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900"
                />
              </label>
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <label className="block">
              <span className="font-medium text-slate-700">Intervalo (s)</span>
              <input
                type="number"
                min={30}
                max={3600}
                value={monForm.intervalSec}
                onChange={(e) => setMonForm({ ...monForm, intervalSec: e.target.value })}
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900 tabular-nums"
              />
            </label>
            {monForm.type !== 'tcp' && (
              <label className="block">
                <span className="font-medium text-slate-700">HTTP esperado</span>
                <input
                  type="number"
                  min={100}
                  max={599}
                  value={monForm.expectedStatus}
                  onChange={(e) => setMonForm({ ...monForm, expectedStatus: e.target.value })}
                  className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900 tabular-nums"
                />
              </label>
            )}
            <label className="block">
              <span className="font-medium text-slate-700">Latencia máx. (ms)</span>
              <input
                type="number"
                min={50}
                max={10000}
                value={monForm.maxLatencyMs}
                onChange={(e) => setMonForm({ ...monForm, maxLatencyMs: e.target.value })}
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900 tabular-nums"
              />
            </label>
          </div>

          {monForm.type === 'http' && (
            <label className="block">
              <span className="font-medium text-slate-700">Texto obligatorio en respuesta (opcional)</span>
              <input
                value={monForm.keyword}
                onChange={(e) => setMonForm({ ...monForm, keyword: e.target.value })}
                placeholder='"status":"ok"'
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900"
              />
            </label>
          )}

          <label className="inline-flex items-center gap-2 text-slate-700 cursor-pointer">
            <input
              type="checkbox"
              checked={monForm.public}
              onChange={(e) => setMonForm({ ...monForm, public: e.target.checked })}
              className="accent-slate-900"
            />
            <span>Permitir incluir este monitor en páginas públicas de estado</span>
          </label>

          <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
            <button type="button" onClick={() => setMonitorModalOpen(false)} className="px-3.5 py-2 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 cursor-pointer">
              Cancelar
            </button>
            <button
              type="submit"
              disabled={busyId === 'create-monitor'}
              className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              {busyId === 'create-monitor' ? 'Guardando…' : (editingMonitorId ? 'Guardar cambios' : 'Crear monitor')}
            </button>
          </div>
        </form>
      </Modal>

      {/* Modal: Constructor de Página Pública de Estado */}
      <Modal
        open={pageModalOpen}
        onClose={() => setPageModalOpen(false)}
        title="Constructor de página pública de estado"
        subtitle="Se servirá con caché en RAM, CSP estricta y sin exponer URLs ni IPs internas."
        maxWidthClass="max-w-lg"
      >
        <form onSubmit={handleSavePage} className="p-5 space-y-4 text-xs">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label className="block">
              <span className="font-medium text-slate-700">Slug público</span>
              <input
                required
                value={pageForm.slug}
                onChange={(e) => setPageForm({ ...pageForm, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '') })}
                placeholder="estado"
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900"
              />
              <span className="text-[11px] text-slate-400 font-mono block mt-1 truncate">
                {origin}/status/{pageForm.slug || 'estado'}
              </span>
            </label>
            <label className="block">
              <span className="font-medium text-slate-700">Título de la página</span>
              <input
                required
                value={pageForm.title}
                onChange={(e) => setPageForm({ ...pageForm, title: e.target.value })}
                placeholder="Estado de MiApp"
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 text-slate-900"
              />
            </label>
          </div>

          <label className="block">
            <span className="font-medium text-slate-700">Descripción breve</span>
            <input
              value={pageForm.description}
              onChange={(e) => setPageForm({ ...pageForm, description: e.target.value })}
              placeholder="Disponibilidad en vivo de nuestros servicios principales."
              className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 text-slate-900"
            />
          </label>

          <div className="space-y-1.5">
            <div className="font-medium text-slate-700">Color de acento</div>
            <div className="flex items-center gap-2">
              {ACCENT_PRESETS.map((hex) => (
                <button
                  key={hex}
                  type="button"
                  aria-label={`Color ${hex}`}
                  onClick={() => setPageForm({ ...pageForm, accentColor: hex })}
                  className={`w-6 h-6 rounded-full cursor-pointer border-2 ${
                    pageForm.accentColor === hex ? 'border-slate-900 scale-110' : 'border-white shadow-xs'
                  }`}
                  style={{ backgroundColor: hex }}
                />
              ))}
            </div>
          </div>

          <div className="space-y-1.5">
            <div className="font-medium text-slate-700">Monitores visibles ({pageForm.monitorIds.length})</div>
            {monitors.length === 0 ? (
              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-slate-500">
                Crea al menos un monitor en la pestaña Monitores para mostrarlo aquí.
              </div>
            ) : (
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5 max-h-40 overflow-y-auto">
                {monitors.map((m) => (
                  <label key={m.id} className="flex items-center gap-2 text-slate-700 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={pageForm.monitorIds.includes(m.id)}
                      onChange={() => {
                        setPageForm((prev) => ({
                          ...prev,
                          monitorIds: prev.monitorIds.includes(m.id)
                            ? prev.monitorIds.filter((id) => id !== m.id)
                            : [...prev.monitorIds, m.id],
                        }));
                      }}
                      className="accent-slate-900"
                    />
                    <span className="truncate font-medium">{m.name}</span>
                  </label>
                ))}
              </div>
            )}
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
            <button type="button" onClick={() => setPageModalOpen(false)} className="px-3.5 py-2 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 cursor-pointer">
              Cancelar
            </button>
            <button
              type="submit"
              disabled={busyId === 'save-page'}
              className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              {busyId === 'save-page' ? 'Guardando…' : 'Guardar página'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Modal: Configurar política Auto-Sleep */}
      <Modal
        open={Boolean(sleepModalProject)}
        onClose={() => setSleepModalProject(null)}
        title={`Auto-reposo de ${sleepModalProject?.name || ''}`}
        subtitle="Suspende el contenedor sin tráfico HTTP y reactívalo automáticamente al llegar la siguiente visita."
        maxWidthClass="max-w-md"
      >
        <form onSubmit={handleSaveSleepPolicy} className="p-5 space-y-4 text-xs">
          <label className="flex items-center justify-between p-3 rounded-xl bg-slate-50 border border-slate-200 cursor-pointer">
            <span className="font-medium text-slate-800">Activar Scale-to-Zero automático</span>
            <input
              type="checkbox"
              checked={sleepForm.enabled}
              onChange={(e) => setSleepForm({ ...sleepForm, enabled: e.target.checked })}
              className="accent-slate-900"
            />
          </label>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label className="block">
              <span className="font-medium text-slate-700">Inactividad (mín. 5 min)</span>
              <input
                type="number"
                min={5}
                max={1440}
                value={sleepForm.idleMinutes}
                onChange={(e) => setSleepForm({ ...sleepForm, idleMinutes: e.target.value })}
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900 tabular-nums"
              />
            </label>
            <label className="block">
              <span className="font-medium text-slate-700">Modo de suspensión</span>
              <select
                value={sleepForm.mode}
                onChange={(e) => setSleepForm({ ...sleepForm, mode: e.target.value as 'pause' | 'stop' })}
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 bg-white text-slate-900"
              >
                <option value="pause">Pausar (&lt;150 ms despertar)</option>
                <option value="stop">Detener (libera 100% RAM)</option>
              </select>
            </label>
          </div>

          <label className="inline-flex items-center gap-2 text-slate-700 cursor-pointer">
            <input
              type="checkbox"
              checked={sleepForm.excludeCrons}
              onChange={(e) => setSleepForm({ ...sleepForm, excludeCrons: e.target.checked })}
              className="accent-slate-900"
            />
            <span>No suspender mientras haya tareas Cron, Live Sync o despliegues activos</span>
          </label>

          <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
            <button type="button" onClick={() => setSleepModalProject(null)} className="px-3.5 py-2 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 cursor-pointer">
              Cancelar
            </button>
            <button
              type="submit"
              disabled={busyId !== null}
              className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              Guardar política
            </button>
          </div>
        </form>
      </Modal>
      {/* Modal: Publicar incidente manual en página de estado */}
      <Modal
        open={Boolean(incidentSlug)}
        onClose={() => setIncidentSlug(null)}
        title={`Publicar incidente en /status/${incidentSlug || ''}`}
        subtitle="Visible al público en la página de estado sin exponer detalles técnicos internos."
        maxWidthClass="max-w-md"
      >
        <form onSubmit={handlePublishPageIncident} className="p-5 space-y-4 text-xs">
          <label className="block">
            <span className="font-medium text-slate-700">Título del incidente</span>
            <input
              required
              value={incidentForm.title}
              onChange={(e) => setIncidentForm({ ...incidentForm, title: e.target.value })}
              placeholder="Mantenimiento programado de base de datos"
              className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 text-slate-900"
            />
          </label>
          <label className="block">
            <span className="font-medium text-slate-700">Severidad</span>
            <select
              value={incidentForm.severity}
              onChange={(e) => setIncidentForm({ ...incidentForm, severity: e.target.value as any })}
              className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 bg-white text-slate-900"
            >
              <option value="maintenance">Mantenimiento</option>
              <option value="minor">Menor (Degradado)</option>
              <option value="major">Mayor (Interrupción)</option>
              <option value="critical">Crítico</option>
            </select>
          </label>
          <label className="block">
            <span className="font-medium text-slate-700">Mensaje público</span>
            <textarea
              rows={3}
              value={incidentForm.message}
              onChange={(e) => setIncidentForm({ ...incidentForm, message: e.target.value })}
              placeholder="Estamos realizando tareas breves de actualización."
              className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 text-slate-900"
            />
          </label>
          <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
            <button type="button" onClick={() => setIncidentSlug(null)} className="px-3.5 py-2 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 cursor-pointer">
              Cancelar
            </button>
            <button
              type="submit"
              disabled={busyId !== null}
              className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              Publicar incidente
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
