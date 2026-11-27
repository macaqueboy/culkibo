import { useState, useEffect, useRef, useCallback, lazy, Suspense } from 'react';
import { Keyboard, X, CheckCircle2, AlertCircle, Info } from 'lucide-react';
import { Header, type AppView, type DaemonHeaderStats } from './components/Header';
import { ProjectList } from './components/ProjectList';
import { AuthGate } from './components/AuthGate';
import { ErrorBoundary } from './components/ErrorBoundary';
import { CommandPalette } from './components/CommandPalette';
import { ShortcutsModal } from './components/ShortcutsModal';
import { api, clearAuthToken, getAuthToken, setUnauthorizedHandler, type Project } from './lib/api';
import { deployStream } from './lib/deployStream';
import { liveEvents } from './lib/liveEvents';
import { setTelemetryCurrentView } from './lib/clientTelemetry';
import { useI18n } from './lib/i18n';
import './lib/theme';
import type { ImportSourceTab } from './components/UniversalImporter';

const ProjectDetail = lazy(() => import('./components/ProjectDetail').then((m) => ({ default: m.ProjectDetail })));
const FleetView = lazy(() => import('./components/FleetView').then((m) => ({ default: m.FleetView })));
const UptimeStatusView = lazy(() => import('./components/UptimeStatusView').then((m) => ({ default: m.UptimeStatusView })));
const ObservabilityView = lazy(() => import('./components/ObservabilityView').then((m) => ({ default: m.ObservabilityView })));
const UniversalImporter = lazy(() => import('./components/UniversalImporter').then((m) => ({ default: m.UniversalImporter })));
const DomainManager = lazy(() => import('./components/DomainManager').then((m) => ({ default: m.DomainManager })));
const ServiceCatalog = lazy(() => import('./components/ServiceCatalog').then((m) => ({ default: m.ServiceCatalog })));
const AiAgentHub = lazy(() => import('./components/AiAgentHub').then((m) => ({ default: m.AiAgentHub })));
const LiveLogs = lazy(() => import('./components/LiveLogs').then((m) => ({ default: m.LiveLogs })));
const SettingsView = lazy(() => import('./components/SettingsView').then((m) => ({ default: m.SettingsView })));

export type ToastKind = 'info' | 'success' | 'error';
type FaviconState = 'healthy' | 'deploying' | 'error';

const DEPLOYING_STATUSES = new Set([
  'pendiente',
  'en_cola',
  'sincronizando',
  'construyendo',
  'arrancando',
  'verificando',
  'promocionando',
  'drenando',
]);

function buildStatusFaviconHref(state: FaviconState): string {
  const dotColor = state === 'deploying' ? '#F59E0B' : state === 'error' ? '#F43F5E' : '#10B981';
  const svg = [
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">',
    '<rect width="32" height="32" rx="8" fill="#111113"/>',
    '<rect x="7.5" y="7" width="3.8" height="18" rx="1.2" fill="#FFFFFF"/>',
    '<path d="M13 15.1L19.6 7H23.4L16.4 15.6L13 15.1Z" fill="#F59E0B"/>',
    '<path d="M13 16.9L16.6 16.4L23.5 25H19.4L13 16.9Z" fill="#FFFFFF"/>',
    `<circle cx="25.5" cy="25.5" r="5.5" fill="#111113"/>`,
    `<circle cx="25.5" cy="25.5" r="4" fill="${dotColor}"/>`,
    '</svg>',
  ].join('');
  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}

const VALID_VIEWS: ReadonlySet<AppView> = new Set([
  'projects',
  'fleet',
  'uptime',
  'metrics',
  'import',
  'domains',
  'catalog',
  'ai',
  'global_logs',
  'settings',
]);

function parseHashRoute(): { view: AppView; projectId: string | null; subTab: string | null } {
  const raw = window.location.hash.replace(/^#\/?/, '').trim();
  if (!raw) return { view: 'projects', projectId: null, subTab: null };
  const parts = raw.split('/').filter(Boolean);
  if (parts[0] === 'projects' && parts[1]) {
    return {
      view: 'projects',
      projectId: decodeURIComponent(parts[1]),
      subTab: parts[2] ? decodeURIComponent(parts[2]) : null,
    };
  }
  const alias = parts[0] === 'logs' ? 'global_logs' : parts[0];
  if (VALID_VIEWS.has(alias as AppView)) {
    return {
      view: alias as AppView,
      projectId: null,
      subTab: parts[1] ? decodeURIComponent(parts[1]) : null,
    };
  }
  return { view: 'projects', projectId: null, subTab: null };
}

function toHash(view: AppView, projectId: string | null, subTab?: string | null): string {
  if (projectId) {
    return subTab
      ? `#/projects/${encodeURIComponent(projectId)}/${encodeURIComponent(subTab)}`
      : `#/projects/${encodeURIComponent(projectId)}`;
  }
  if (view === 'global_logs') return '#/logs';
  if (view === 'settings' && subTab) return `#/settings/${encodeURIComponent(subTab)}`;
  return `#/${view}`;
}

function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
  return target.isContentEditable || Boolean(target.closest('[contenteditable="true"]'));
}

const ViewFallback = () => (
  <div className="space-y-5 animate-pulse" aria-busy="true" aria-label="Loading view">
    <div className="flex items-center justify-between gap-4">
      <div className="space-y-2">
        <div className="h-6 w-40 rounded-lg bg-slate-200/80" />
        <div className="h-3.5 w-64 rounded bg-slate-200/60" />
      </div>
      <div className="h-9 w-32 rounded-lg bg-slate-200/70" />
    </div>
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-40 rounded-2xl bg-white border border-slate-200/80 p-4 space-y-3">
          <div className="h-4 w-28 rounded bg-slate-200/70" />
          <div className="h-3 w-full rounded bg-slate-100" />
          <div className="h-3 w-2/3 rounded bg-slate-100" />
        </div>
      ))}
    </div>
  </div>
);

export function App() {
  const { t, locale } = useI18n();
  const initialRoute = parseHashRoute();
  const [authChecked, setAuthChecked] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);
  const [sessionOffline, setSessionOffline] = useState(false);
  const [tokenSource, setTokenSource] = useState('data/auth.json');

  const [activeView, setActiveView] = useState<AppView>(initialRoute.view);
  const [activeProjectId, setActiveProjectId] = useState<string | null>(initialRoute.projectId);
  const [projectInitialTab, setProjectInitialTab] = useState<string | null>(initialRoute.projectId ? initialRoute.subTab : null);
  const [settingsInitialTab, setSettingsInitialTab] = useState<string | null>(initialRoute.view === 'settings' ? initialRoute.subTab : null);
  const [importInitialTab, setImportInitialTab] = useState<ImportSourceTab>('wordpress');
  const [importTabTrigger, setImportTabTrigger] = useState(0);
  const [domainWizardTrigger, setDomainWizardTrigger] = useState(0);
  const [domainWizardPreset, setDomainWizardPreset] = useState<{
    serviceId?: string;
    serviceName?: string;
    targetPort?: number;
    suggestedHostname?: string;
  } | null>(null);
  const [createProjectTrigger, setCreateProjectTrigger] = useState(0);
  const [catalogInitialTab, setCatalogInitialTab] = useState<'catalogo' | 'instalados'>('catalogo');
  const [catalogTabTrigger, setCatalogTabTrigger] = useState(0);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [checklistRestoreTick, setChecklistRestoreTick] = useState(0);

  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [daemonStats, setDaemonStats] = useState<DaemonHeaderStats | null>(null);
  const [deployStates, setDeployStates] = useState<Record<string, FaviconState>>({});
  const [toasts, setToasts] = useState<Array<{ id: number; msg: string; kind: ToastKind }>>([]);
  const [aiPulseLabel, setAiPulseLabel] = useState<string | null>(null);
  const [activeSyncCount, setActiveSyncCount] = useState<number>(0);

  const wsRef = useRef<WebSocket | null>(null);
  const toastIdRef = useRef(0);
  const toastTimersRef = useRef<Map<number, ReturnType<typeof setTimeout>>>(new Map());
  const aiPulseTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const syncClientsByProjectRef = useRef<Map<string, number>>(new Map());

  const faviconState: FaviconState = (() => {
    const vals = Object.values(deployStates);
    if (vals.includes('deploying')) return 'deploying';
    if (vals.includes('error') || sessionOffline) return 'error';
    return 'healthy';
  })();

  // Live Build-Status Tab Favicon (updates inline SVG status dot cleanly)
  useEffect(() => {
    if (typeof document === 'undefined') return;
    let link = document.querySelector<HTMLLinkElement>('link[rel="icon"]');
    if (!link) {
      link = document.createElement('link');
      link.rel = 'icon';
      link.type = 'image/svg+xml';
      document.head.appendChild(link);
    }
    link.href = buildStatusFaviconHref(faviconState);
  }, [faviconState]);

  const checkSession = useCallback(() => {
    setSessionOffline(false);
    api.getAuthSession()
      .then((s) => {
        setAuthenticated(Boolean(s.authenticated));
        setTokenSource(s.tokenSource || 'data/auth.json');
      })
      .catch(() => {
        setAuthenticated(false);
        setSessionOffline(true);
      })
      .finally(() => setAuthChecked(true));
  }, []);

  useEffect(() => {
    let active = true;
    api.getAuthSession()
      .then((s) => {
        if (!active) return;
        setSessionOffline(false);
        setAuthenticated(Boolean(s.authenticated));
        setTokenSource(s.tokenSource || 'data/auth.json');
      })
      .catch(() => {
        if (!active) return;
        setAuthenticated(false);
        setSessionOffline(true);
      })
      .finally(() => {
        if (active) setAuthChecked(true);
      });
    setUnauthorizedHandler(() => {
      setAuthenticated(false);
    });
    return () => {
      active = false;
      setUnauthorizedHandler(null);
    };
  }, []);

  // Telemetría ligera del daemon (RAM RSS + RTT real) sin polling agresivo
  useEffect(() => {
    if (!authenticated) return;
    let active = true;
    const sampleDaemon = () => {
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return;
      const t0 = typeof performance !== 'undefined' ? performance.now() : 0;
      api.getSystemStatus()
        .then((sys) => {
          if (!active || !sys) return;
          const latencyMs = typeof performance !== 'undefined' && t0 > 0
            ? Math.max(1, Math.round(performance.now() - t0))
            : null;
          setDaemonStats({
            memoryMb: typeof sys.memoryUsageMb === 'number' ? sys.memoryUsageMb : null,
            latencyMs,
            version: typeof sys.version === 'string' ? sys.version : null,
            nodeVersion: typeof sys.nodeVersion === 'string' ? sys.nodeVersion : null,
            uptimeSeconds: typeof sys.uptimeSeconds === 'number' ? sys.uptimeSeconds : null,
          });
        })
        .catch(() => {
          // silencioso
        });
    };

    sampleDaemon();
    const timer = window.setInterval(sampleDaemon, 30000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [authenticated]);

  // Sincroniza cambios de hash (atrás/adelante del navegador)
  useEffect(() => {
    const onHashChange = () => {
      const parsed = parseHashRoute();
      setActiveView(parsed.view);
      setActiveProjectId(parsed.projectId);
      if (parsed.projectId) setProjectInitialTab(parsed.subTab);
      if (parsed.view === 'settings') setSettingsInitialTab(parsed.subTab);
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  useEffect(() => {
    setTelemetryCurrentView(activeView);
  }, [activeView]);

  // Atajos globales: Cmd/Ctrl+K, ?, n, y acordes g+letra
  useEffect(() => {
    if (!authenticated) return;
    let gPrefix = false;
    let gTimer: ReturnType<typeof setTimeout> | null = null;
    const clearG = () => {
      gPrefix = false;
      if (gTimer) {
        clearTimeout(gTimer);
        gTimer = null;
      }
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setShortcutsOpen(false);
        setPaletteOpen((prev) => !prev);
        return;
      }
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (isEditableTarget(e.target)) return;
      if (paletteOpen) return;

      const key = e.key;
      if (key === '?') {
        e.preventDefault();
        setShortcutsOpen((v) => !v);
        clearG();
        return;
      }
      if (shortcutsOpen) return;

      if (gPrefix) {
        clearG();
        const lower = key.toLowerCase();
        const map: Record<string, AppView> = {
          p: 'projects',
          f: 'fleet',
          u: 'uptime',
          m: 'metrics',
          d: 'domains',
          c: 'catalog',
          i: 'import',
          a: 'ai',
          l: 'global_logs',
          s: 'settings',
        };
        if (map[lower]) {
          e.preventDefault();
          const targetView = map[lower];
          setActiveView(targetView);
          setActiveProjectId(null);
          const nextHash = toHash(targetView, null);
          if (window.location.hash !== nextHash) window.history.pushState(null, '', nextHash);
        }
        return;
      }

      if (key.toLowerCase() === 'g') {
        gPrefix = true;
        gTimer = setTimeout(clearG, 900);
        return;
      }

      if (key.toLowerCase() === 'n') {
        e.preventDefault();
        setActiveProjectId(null);
        setActiveView('projects');
        const nextHash = toHash('projects', null);
        if (window.location.hash !== nextHash) window.history.pushState(null, '', nextHash);
        setCreateProjectTrigger((c) => c + 1);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => {
      clearG();
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [authenticated, paletteOpen, shortcutsOpen]);

  const dismissToast = useCallback((id: number) => {
    const tTimer = toastTimersRef.current.get(id);
    if (tTimer) {
      clearTimeout(tTimer);
      toastTimersRef.current.delete(id);
    }
    setToasts((prev) => prev.filter((item) => item.id !== id));
  }, []);

  const showToast = useCallback((msg: string, kind: ToastKind = 'info') => {
    const id = ++toastIdRef.current;
    setToasts((prev) => [...prev.slice(-2), { id, msg, kind }]);
    const timer = setTimeout(() => {
      toastTimersRef.current.delete(id);
      setToasts((prev) => prev.filter((item) => item.id !== id));
    }, kind === 'error' ? 5500 : 3800);
    toastTimersRef.current.set(id, timer);
  }, []);

  const [projects, setProjects] = useState<Project[]>([]);
  const [projectsLoaded, setProjectsLoaded] = useState(false);

  const fetchProjects = useCallback(async () => {
    if (!authenticated) return;
    try {
      const data = await api.getProjects();
      setProjects(data);
    } catch (e: unknown) {
      console.error(e);
    } finally {
      setProjectsLoaded(true);
    }
  }, [authenticated]);

  useEffect(() => () => {
    for (const timer of toastTimersRef.current.values()) clearTimeout(timer);
    toastTimersRef.current.clear();
    if (aiPulseTimerRef.current) clearTimeout(aiPulseTimerRef.current);
  }, []);

  useEffect(() => {
    if (!authenticated) return;
    let active = true;
    api.getProjects()
      .then((data) => { if (active) setProjects(data); })
      .catch((e) => console.error(e))
      .finally(() => { if (active) setProjectsLoaded(true); });
    api.getSyncSummary()
      .then((summary) => {
        if (!active || !summary) return;
        const map = new Map<string, number>();
        let total = 0;
        if (Array.isArray(summary.sessions)) {
          for (const s of summary.sessions) {
            if (s.projectId && s.connectedClients > 0) {
              map.set(s.projectId, s.connectedClients);
              total += s.connectedClients;
            }
          }
        } else if (typeof summary.totalConnectedClients === 'number') {
          total = summary.totalConnectedClients;
        }
        syncClientsByProjectRef.current = map;
        setActiveSyncCount(total);
      })
      .catch(() => {});
    return () => { active = false; };
  }, [authenticated]);

  useEffect(() => {
    if (!authenticated) return;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.port === '5173' ? '127.0.0.1:3030' : window.location.host;
    const wsUrl = `${protocol}//${host}/ws`;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let reconnectAttempts = 0;
    let disposed = false;

    const connectWs = async () => {
      if (disposed) return;
      try {
        let protocols: string[] | undefined;
        const storedToken = getAuthToken();
        if (storedToken) {
          const { ticket } = await api.getWsTicket();
          if (!ticket) throw new Error('Could not issue WebSocket ticket');
          protocols = ['culkibo.v1', `culkibo-ticket.${ticket}`];
        } else {
          protocols = ['culkibo.v1'];
        }
        if (disposed) return;
        const ws = new WebSocket(wsUrl, protocols);
        wsRef.current = ws;

        ws.onopen = () => {
          setWsConnected(true);
          reconnectAttempts = 0;
        };

        ws.onmessage = (event) => {
          try {
            const parsed = JSON.parse(event.data);
            const { type, data } = parsed;

            if (type === 'log') {
              liveEvents.emitLog(data);
            } else if (type === 'deploy_log') {
              deployStream.emitLog(data);
            } else if (type === 'deploy_event') {
              deployStream.emitEvent(data);
              if (data?.projectId && typeof data?.status === 'string') {
                const nextFav: FaviconState = DEPLOYING_STATUSES.has(data.status)
                  ? 'deploying'
                  : data.status === 'fallido'
                    ? 'error'
                    : 'healthy';
                setDeployStates((prev) => ({ ...prev, [data.projectId]: nextFav }));
              }
            } else if (type === 'sync_applied') {
              liveEvents.emitSyncApplied(data);
            } else if (type === 'sync_rollback') {
              liveEvents.emitSyncRollback(data);
            } else if (type === 'sync_conflict') {
              liveEvents.emitSyncConflict(data);
              if (data?.path) {
                showToast(`Live Sync conflict detected in ${data.path}`, 'error');
              }
            } else if (type === 'sync_client') {
              liveEvents.emitSyncClient(data);
              if (data?.projectId) {
                const map = syncClientsByProjectRef.current;
                if (data.connectedClients > 0) map.set(data.projectId, data.connectedClients);
                else map.delete(data.projectId);
                let total = 0;
                for (const v of map.values()) total += v;
                setActiveSyncCount(total);
              }
            } else if (type === 'service_progress') {
              liveEvents.emitServiceProgress(data);
            } else if (type === 'service_installed') {
              liveEvents.emitServiceInstalled(data);
              if (data?.name) showToast(`${data.name} installed and running`, 'success');
            } else if (type === 'service_failed') {
              liveEvents.emitServiceFailed(data);
              if (data?.name) showToast(`Error installing ${data.name}`, 'error');
            } else if (type === 'traffic_change') {
              showToast(`Traffic updated: ${data.citadel}% Prod / ${data.forge}% Dev`);
            } else if (type === 'ssl_progress') {
              if (data?.stage === 'installed') {
                showToast(`SSL certificate ready for ${data.domain}`, 'success');
              }
            } else if (type === 'github_deploy') {
              showToast(`Push on ${data.branch} (${data.commit}) by ${data.author}: ${data.message}`, 'success');
              void fetchProjects();
            } else if (type === 'project_update' && data?.id) {
              setProjects((prev) => prev.map((p) => (p.id === data.id ? data : p)));
              liveEvents.emitProjectChange({ action: 'update', project: data });
            } else if (type === 'project_created' && data?.id) {
              setProjects((prev) => (prev.some((p) => p.id === data.id) ? prev : [data, ...prev]));
              liveEvents.emitProjectChange({ action: 'created', project: data });
            } else if (type === 'project_deleted') {
              const delId = typeof data === 'string' ? data : data?.id;
              if (delId) {
                setProjects((prev) => prev.filter((p) => p.id !== delId));
                liveEvents.emitProjectChange({ action: 'deleted', id: delId });
              }
            } else if (type === 'cron_run') {
              liveEvents.emitCronRun(data);
            } else if (type === 'preview_event') {
              liveEvents.emitPreviewEvent(data);
            } else if (type === 'mcp_call') {
              liveEvents.emitMcpCall(data);
              if (data?.toolName) {
                setAiPulseLabel(data.toolName);
                if (aiPulseTimerRef.current) clearTimeout(aiPulseTimerRef.current);
                aiPulseTimerRef.current = setTimeout(() => setAiPulseLabel(null), 6000);
                showToast(`AI Agent ran: ${data.toolName}`);
              }
            }
          } catch {
            // ignore malformed JSON frames
          }
        };

        ws.onclose = (ev) => {
          setWsConnected(false);
          if (disposed) return;
          if (ev.code === 4001) {
            clearAuthToken();
            setAuthenticated(false);
            showToast('Session closed: server access token rotated.', 'error');
            return;
          }
          const base = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
          const backoff = Math.round(base * (0.75 + Math.random() * 0.5));
          reconnectAttempts++;
          reconnectTimer = setTimeout(() => { void connectWs(); }, backoff);
        };

        ws.onerror = () => ws.close();
      } catch {
        if (disposed) return;
        const base = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
        const backoff = Math.round(base * (0.75 + Math.random() * 0.5));
        reconnectAttempts++;
        reconnectTimer = setTimeout(() => { void connectWs(); }, backoff);
      }
    };

    void connectWs();

    return () => {
      disposed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.onerror = null;
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [authenticated, fetchProjects, showToast]);

  const navigate = useCallback((rawView: AppView | 'logs', subTab?: string | null) => {
    const view: AppView = rawView === 'logs' ? 'global_logs' : rawView;
    setActiveView(view);
    setActiveProjectId(null);
    if (view === 'settings') setSettingsInitialTab(subTab || null);
    const nextHash = toHash(view, null, view === 'settings' ? subTab : null);
    if (window.location.hash !== nextHash) window.history.pushState(null, '', nextHash);
  }, []);

  const selectProject = useCallback((id: string | null, tab?: string | null) => {
    setActiveProjectId(id);
    setProjectInitialTab(tab || null);
    if (id) setActiveView('projects');
    const nextHash = toHash('projects', id, tab || null);
    if (window.location.hash !== nextHash) window.history.pushState(null, '', nextHash);
  }, []);

  const handleProjectTabChange = useCallback((tab: string) => {
    setProjectInitialTab(tab);
    if (!activeProjectId) return;
    const nextHash = toHash('projects', activeProjectId, tab);
    if (window.location.hash !== nextHash) window.history.replaceState(null, '', nextHash);
  }, [activeProjectId]);

  const handleSettingsTabChange = useCallback((tab: string) => {
    setSettingsInitialTab(tab);
    const nextHash = toHash('settings', null, tab);
    if (window.location.hash !== nextHash) window.history.replaceState(null, '', nextHash);
  }, []);

  const restoreQuickstartChecklist = useCallback(() => {
    try {
      window.localStorage.removeItem('culkibo_onboarding_dismissed_v1');
      window.localStorage.removeItem('culkibo_quickstart_dismissed');
    } catch {
      // ignore
    }
    setChecklistRestoreTick((c) => c + 1);
    navigate('projects');
    showToast(locale === 'es' ? 'Guía de primeros pasos restaurada' : 'Quick start checklist restored', 'info');
  }, [navigate, showToast, locale]);

  const openImport = useCallback((source: ImportSourceTab = 'wordpress') => {
    setActiveProjectId(null);
    setImportInitialTab(source);
    setImportTabTrigger((c) => c + 1);
    setActiveView('import');
    const nextHash = toHash('import', null);
    if (window.location.hash !== nextHash) window.history.pushState(null, '', nextHash);
  }, []);

  const openCatalog = useCallback((tab: 'catalogo' | 'instalados' = 'catalogo') => {
    setActiveProjectId(null);
    setCatalogInitialTab(tab);
    setCatalogTabTrigger((c) => c + 1);
    setActiveView('catalog');
    const nextHash = toHash('catalog', null);
    if (window.location.hash !== nextHash) window.history.pushState(null, '', nextHash);
  }, []);

  const openDomainWizardWithPreset = useCallback((preset?: {
    serviceId?: string;
    serviceName?: string;
    targetPort?: number;
    suggestedHostname?: string;
  }) => {
    setActiveProjectId(null);
    setDomainWizardPreset(preset || null);
    navigate('domains');
    setDomainWizardTrigger((c) => c + 1);
  }, [navigate]);

  const handleQuickAction = useCallback((action: 'new_project' | 'wordpress' | 'import' | 'domain') => {
    setActiveProjectId(null);
    if (action === 'new_project') {
      navigate('projects');
      setCreateProjectTrigger((c) => c + 1);
    } else if (action === 'wordpress') {
      openImport('wordpress');
    } else if (action === 'import') {
      openImport('coolify');
    } else if (action === 'domain') {
      openDomainWizardWithPreset();
    }
  }, [navigate, openImport, openDomainWizardWithPreset]);

  if (!authChecked) {
    return (
      <div className="min-h-screen bg-slate-50 text-slate-500 flex items-center justify-center text-sm">
        {t('app.checkingAuth')}
      </div>
    );
  }

  if (sessionOffline) {
    return (
      <div className="min-h-screen bg-slate-50 text-slate-900 flex items-center justify-center p-4">
        <div className="culkibo-surface w-full max-w-md rounded-2xl p-6 text-center space-y-4">
          <h1 className="text-base font-semibold text-slate-900">{t('app.offlineTitle')}</h1>
          <p className="text-xs text-slate-500 leading-relaxed">
            {t('app.offlineDesc')}
          </p>
          <button
            type="button"
            onClick={checkSession}
            className="culkibo-press px-4 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium transition-colors cursor-pointer"
          >
            {t('app.retry')}
          </button>
        </div>
      </div>
    );
  }

  if (!authenticated) {
    return <AuthGate tokenSource={tokenSource} onAuthenticated={() => setAuthenticated(true)} />;
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 selection:bg-slate-900 selection:text-white flex flex-col font-sans">
      {toasts.length > 0 && (
        <div
          aria-live="polite"
          className="fixed bottom-4 right-4 left-4 sm:left-auto sm:bottom-5 sm:right-5 z-50 flex flex-col gap-2 items-end pointer-events-none"
        >
          {toasts.map((item) => (
            <div
              key={item.id}
              role={item.kind === 'error' ? 'alert' : 'status'}
              className={`culkibo-toast-enter pointer-events-auto w-full sm:w-auto sm:max-w-sm flex items-center gap-2.5 pl-3.5 pr-2 py-2.5 rounded-xl bg-white border text-xs font-medium shadow-lg ${
                item.kind === 'error'
                  ? 'border-red-200 text-red-900'
                  : item.kind === 'success'
                    ? 'border-emerald-200 text-emerald-950'
                    : 'border-slate-200 text-slate-900'
              }`}
            >
              {item.kind === 'error' ? (
                <AlertCircle className="w-4 h-4 text-red-500 shrink-0" />
              ) : item.kind === 'success' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
              ) : (
                <Info className="w-4 h-4 text-slate-600 shrink-0" />
              )}
              <span className="leading-snug flex-1 min-w-0">{item.msg}</span>
              <button
                type="button"
                onClick={() => dismissToast(item.id)}
                aria-label={t('app.closeNotice')}
                className="inline-flex items-center justify-center w-8 h-8 text-slate-400 hover:text-slate-700 hover:bg-slate-100 rounded-lg transition-colors cursor-pointer shrink-0"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      )}

      <Header
        activeView={activeView}
        setActiveView={navigate}
        wsConnected={wsConnected}
        activeProjectId={activeProjectId}
        setActiveProjectId={(id) => selectProject(id)}
        projects={projects}
        onQuickAction={handleQuickAction}
        onOpenPalette={() => setPaletteOpen(true)}
        aiPulseLabel={aiPulseLabel}
        activeSyncCount={activeSyncCount}
        daemonStats={daemonStats}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-3.5 sm:px-6 lg:px-8 py-6 sm:py-7">
        <ErrorBoundary key={`${activeView}:${activeProjectId || ''}`}>
          <Suspense fallback={<ViewFallback />}>
            {activeView === 'projects' && !activeProjectId && (
              <ProjectList
                projects={projects}
                projectsLoading={!projectsLoaded}
                onRefreshProjects={fetchProjects}
                onSelectProject={(id, tab) => selectProject(id, tab)}
                onImportCoolify={() => openImport('coolify')}
                onOpenWordPress={() => openImport('wordpress')}
                onOpenCatalog={() => openCatalog('catalogo')}
                onOpenDomains={() => handleQuickAction('domain')}
                onOpenAi={() => navigate('ai')}
                onOpenSecurity={() => navigate('settings', 'security')}
                onNotify={showToast}
                externalCreateTrigger={createProjectTrigger}
                checklistRestoreTick={checklistRestoreTick}
              />
            )}

            {activeProjectId && (
              <ProjectDetail
                projectId={activeProjectId}
                initialTab={projectInitialTab}
                onTabChange={handleProjectTabChange}
                onBack={() => { selectProject(null); void fetchProjects(); }}
                onNotify={showToast}
                onProjectUpdate={fetchProjects}
                onOpenCatalog={() => openCatalog('catalogo')}
                onOpenBackupSettings={() => navigate('settings', 'backups')}
              />
            )}

            {activeView === 'fleet' && !activeProjectId && (
              <FleetView onNotify={showToast} />
            )}

            {activeView === 'uptime' && !activeProjectId && (
              <UptimeStatusView onNotify={showToast} />
            )}

            {activeView === 'metrics' && !activeProjectId && (
              <ObservabilityView onNotify={showToast} />
            )}

            {activeView === 'import' && !activeProjectId && (
              <UniversalImporter
                initialSource={importInitialTab}
                sourceTrigger={importTabTrigger}
                onComplete={(createdId) => {
                  void fetchProjects();
                  if (createdId) {
                    selectProject(createdId);
                  } else {
                    navigate('projects');
                  }
                }}
                onOpenCatalogInstalled={() => openCatalog('instalados')}
                onOpenDomains={(preset) => openDomainWizardWithPreset(preset)}
                onNotify={showToast}
              />
            )}

            {activeView === 'domains' && !activeProjectId && (
              <DomainManager
                onNotify={showToast}
                wizardTrigger={domainWizardTrigger}
                wizardPreset={domainWizardPreset}
                onClearWizardPreset={() => setDomainWizardPreset(null)}
              />
            )}

            {activeView === 'catalog' && !activeProjectId && (
              <ServiceCatalog
                onNotify={showToast}
                initialTab={catalogInitialTab}
                tabTrigger={catalogTabTrigger}
              />
            )}

            {activeView === 'ai' && !activeProjectId && (
              <AiAgentHub onNotify={showToast} />
            )}

            {activeView === 'global_logs' && !activeProjectId && (
              <div className="h-[75vh]">
                <LiveLogs />
              </div>
            )}

            {activeView === 'settings' && !activeProjectId && (
              <SettingsView
                onNotify={showToast}
                onOpenMetrics={() => navigate('metrics')}
                initialTab={settingsInitialTab}
                onTabChange={handleSettingsTabChange}
                onRestoreChecklist={restoreQuickstartChecklist}
              />
            )}
          </Suspense>
        </ErrorBoundary>
      </main>

      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        projects={projects}
        activeProjectId={activeProjectId}
        onNavigate={(v, subTab) => navigate(v as AppView, subTab)}
        onSelectProject={(id, tab) => selectProject(id, tab)}
        onQuickCreateProject={() => handleQuickAction('new_project')}
        onQuickConnectDomain={() => handleQuickAction('domain')}
        onQuickImport={(src) => openImport(src || 'wordpress')}
        onOpenShortcuts={() => setShortcutsOpen(true)}
        onRestoreChecklist={restoreQuickstartChecklist}
        onNotify={showToast}
      />

      <ShortcutsModal open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} />

      <footer className="border-t border-slate-200/90 py-4 bg-white mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-2">
          <div className="flex items-center gap-2 flex-wrap justify-center sm:justify-start">
            <span className="font-semibold text-slate-800">
              Culkibo v{daemonStats?.version || '1.1.0'}
            </span>
            <span className="text-slate-300">·</span>
            <span>Apache-2.0</span>
            <span className="text-slate-300">·</span>
            <span>Zero-Shell Engine</span>
          </div>
          <div className="flex items-center gap-3 text-slate-400 flex-wrap justify-center">
            <span>Caddy HTTP/3</span>
            <span>·</span>
            <span>Live Sync</span>
            <span>·</span>
            <span>MCP 2026-07-28</span>
            <span>·</span>
            <button
              type="button"
              onClick={() => setShortcutsOpen(true)}
              className="inline-flex items-center gap-1 text-slate-500 hover:text-slate-900 transition-colors cursor-pointer"
              title={t('app.shortcuts')}
            >
              <Keyboard className="w-3.5 h-3.5" />
              <span>{t('app.shortcuts')}</span>
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
