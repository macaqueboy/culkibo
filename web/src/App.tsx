import { useState, useEffect, useRef, useCallback, lazy, Suspense } from 'react';
import { X } from 'lucide-react';
import { Header, type AppView } from './components/Header';
import { ProjectList } from './components/ProjectList';
import { AuthGate } from './components/AuthGate';
import { ErrorBoundary } from './components/ErrorBoundary';
import { CommandPalette } from './components/CommandPalette';
import { api, getAuthToken, setUnauthorizedHandler, type Project } from './lib/api';
import { deployStream } from './lib/deployStream';
import { liveEvents } from './lib/liveEvents';
import type { ImportSourceTab } from './components/UniversalImporter';

const ProjectDetail = lazy(() => import('./components/ProjectDetail').then((m) => ({ default: m.ProjectDetail })));
const ObservabilityView = lazy(() => import('./components/ObservabilityView').then((m) => ({ default: m.ObservabilityView })));
const UniversalImporter = lazy(() => import('./components/UniversalImporter').then((m) => ({ default: m.UniversalImporter })));
const DomainManager = lazy(() => import('./components/DomainManager').then((m) => ({ default: m.DomainManager })));
const ServiceCatalog = lazy(() => import('./components/ServiceCatalog').then((m) => ({ default: m.ServiceCatalog })));
const AiAgentHub = lazy(() => import('./components/AiAgentHub').then((m) => ({ default: m.AiAgentHub })));
const LiveLogs = lazy(() => import('./components/LiveLogs').then((m) => ({ default: m.LiveLogs })));
const SettingsView = lazy(() => import('./components/SettingsView').then((m) => ({ default: m.SettingsView })));

export type ToastKind = 'info' | 'success' | 'error';

const VALID_VIEWS: ReadonlySet<AppView> = new Set([
  'projects',
  'metrics',
  'import',
  'domains',
  'catalog',
  'ai',
  'global_logs',
  'settings',
]);

function parseHashRoute(): { view: AppView; projectId: string | null } {
  const raw = window.location.hash.replace(/^#\/?/, '').trim();
  if (!raw) return { view: 'projects', projectId: null };
  const parts = raw.split('/').filter(Boolean);
  if (parts[0] === 'projects' && parts[1]) {
    return { view: 'projects', projectId: decodeURIComponent(parts[1]) };
  }
  const alias = parts[0] === 'logs' ? 'global_logs' : parts[0];
  if (VALID_VIEWS.has(alias as AppView)) {
    return { view: alias as AppView, projectId: null };
  }
  return { view: 'projects', projectId: null };
}

function toHash(view: AppView, projectId: string | null): string {
  if (projectId) return `#/projects/${encodeURIComponent(projectId)}`;
  if (view === 'global_logs') return '#/logs';
  return `#/${view}`;
}

const ViewFallback = () => (
  <div className="py-16 text-center text-sm text-slate-500">Cargando vista…</div>
);

export function App() {
  const initialRoute = parseHashRoute();
  const [authChecked, setAuthChecked] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);
  const [sessionOffline, setSessionOffline] = useState(false);
  const [tokenSource, setTokenSource] = useState('data/auth.json');

  const [activeView, setActiveView] = useState<AppView>(initialRoute.view);
  const [activeProjectId, setActiveProjectId] = useState<string | null>(initialRoute.projectId);
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

  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [toasts, setToasts] = useState<Array<{ id: number; msg: string; kind: ToastKind }>>([]);
  const [aiPulseLabel, setAiPulseLabel] = useState<string | null>(null);
  const [activeSyncCount, setActiveSyncCount] = useState<number>(0);

  const wsRef = useRef<WebSocket | null>(null);
  const toastIdRef = useRef(0);
  const toastTimersRef = useRef<Map<number, ReturnType<typeof setTimeout>>>(new Map());
  const aiPulseTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const syncClientsByProjectRef = useRef<Map<string, number>>(new Map());

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

  // Sincroniza cambios de hash (atrás/adelante del navegador)
  useEffect(() => {
    const onHashChange = () => {
      const parsed = parseHashRoute();
      setActiveView(parsed.view);
      setActiveProjectId(parsed.projectId);
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  // Atajo global Cmd+K / Ctrl+K para la paleta de comandos
  useEffect(() => {
    if (!authenticated) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [authenticated]);

  const dismissToast = useCallback((id: number) => {
    const t = toastTimersRef.current.get(id);
    if (t) {
      clearTimeout(t);
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
    } catch (e: any) {
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
      .catch((e) => console.error(e));
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
          try {
            const { ticket } = await api.getWsTicket();
            if (ticket) protocols = [`culkibo-ticket.${ticket}`];
          } catch {
            protocols = [`culkibo-token.${storedToken}`];
          }
        }
        if (disposed) return;
        const ws = protocols ? new WebSocket(wsUrl, protocols) : new WebSocket(wsUrl);
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
            } else if (type === 'sync_applied') {
              liveEvents.emitSyncApplied(data);
            } else if (type === 'sync_rollback') {
              liveEvents.emitSyncRollback(data);
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
              if (data?.name) showToast(`${data.name} instalado y en marcha`, 'success');
            } else if (type === 'service_failed') {
              liveEvents.emitServiceFailed(data);
              if (data?.name) showToast(`Error instalando ${data.name}`, 'error');
            } else if (type === 'traffic_change') {
              showToast(`Tráfico actualizado: ${data.citadel}% Prod / ${data.forge}% Dev`);
            } else if (type === 'ssl_progress') {
              if (data?.stage === 'installed') {
                showToast(`Certificado SSL listo para ${data.domain}`, 'success');
              }
            } else if (type === 'github_deploy') {
              showToast(`Push en ${data.branch} (${data.commit}) por ${data.author}: ${data.message}`, 'success');
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
            } else if (type === 'mcp_call') {
              liveEvents.emitMcpCall(data);
              if (data?.toolName) {
                setAiPulseLabel(data.toolName);
                if (aiPulseTimerRef.current) clearTimeout(aiPulseTimerRef.current);
                aiPulseTimerRef.current = setTimeout(() => setAiPulseLabel(null), 6000);
                showToast(`Agente IA ejecutó: ${data.toolName}`);
              }
            }
          } catch {
            // ignorar tramas JSON malformadas
          }
        };

        ws.onclose = () => {
          setWsConnected(false);
          if (disposed) return;
          const backoff = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
          reconnectAttempts++;
          reconnectTimer = setTimeout(() => { void connectWs(); }, backoff);
        };

        ws.onerror = () => ws.close();
      } catch {
        if (disposed) return;
        const backoff = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
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

  const navigate = useCallback((rawView: AppView | 'logs') => {
    const view: AppView = rawView === 'logs' ? 'global_logs' : rawView;
    setActiveView(view);
    setActiveProjectId(null);
    const nextHash = toHash(view, null);
    if (window.location.hash !== nextHash) window.history.pushState(null, '', nextHash);
  }, []);

  const selectProject = useCallback((id: string | null) => {
    setActiveProjectId(id);
    if (id) setActiveView('projects');
    const nextHash = toHash('projects', id);
    if (window.location.hash !== nextHash) window.history.pushState(null, '', nextHash);
  }, []);

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
        Comprobando acceso…
      </div>
    );
  }

  if (sessionOffline) {
    return (
      <div className="min-h-screen bg-slate-50 text-slate-900 flex items-center justify-center p-4">
        <div className="w-full max-w-md bg-white border border-slate-200 rounded-xl shadow-sm p-6 text-center space-y-4">
          <h1 className="text-base font-semibold text-slate-900">No se pudo conectar con Culkibo</h1>
          <p className="text-xs text-slate-500 leading-relaxed">
            El servidor del plano de control no responde en este momento. Comprueba que el servicio esté activo y vuelve a intentarlo.
          </p>
          <button
            type="button"
            onClick={checkSession}
            className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium transition-colors cursor-pointer"
          >
            Reintentar conexión
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
          className="fixed bottom-5 right-5 z-50 flex flex-col gap-2 items-end pointer-events-none"
        >
          {toasts.map((item) => (
            <div
              key={item.id}
              role="status"
              className={`culkibo-modal-enter pointer-events-auto max-w-sm flex items-center gap-2.5 px-3.5 py-2.5 rounded-lg bg-white border text-xs font-medium shadow-lg ${
                item.kind === 'error'
                  ? 'border-red-200 text-red-800'
                  : item.kind === 'success'
                    ? 'border-emerald-200 text-emerald-900'
                    : 'border-slate-200 text-slate-900'
              }`}
            >
              <span
                className={`w-2 h-2 rounded-full shrink-0 ${
                  item.kind === 'error' ? 'bg-red-500' : item.kind === 'success' ? 'bg-emerald-500' : 'bg-slate-900'
                }`}
              />
              <span className="leading-snug">{item.msg}</span>
              <button
                type="button"
                onClick={() => dismissToast(item.id)}
                aria-label="Cerrar aviso"
                className="ml-1 p-0.5 text-slate-400 hover:text-slate-700 rounded cursor-pointer shrink-0"
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
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-7">
        <ErrorBoundary key={`${activeView}:${activeProjectId || ''}`}>
          <Suspense fallback={<ViewFallback />}>
            {activeView === 'projects' && !activeProjectId && (
              <ProjectList
                projects={projects}
                projectsLoading={!projectsLoaded}
                onRefreshProjects={fetchProjects}
                onSelectProject={(id) => selectProject(id)}
                onImportCoolify={() => openImport('coolify')}
                onOpenWordPress={() => openImport('wordpress')}
                onOpenCatalog={() => openCatalog('catalogo')}
                onOpenDomains={() => handleQuickAction('domain')}
                onOpenAi={() => navigate('ai')}
                onNotify={showToast}
                externalCreateTrigger={createProjectTrigger}
              />
            )}

            {activeProjectId && (
              <ProjectDetail
                projectId={activeProjectId}
                onBack={() => { selectProject(null); void fetchProjects(); }}
                onNotify={showToast}
                onProjectUpdate={fetchProjects}
                onOpenCatalog={() => openCatalog('catalogo')}
              />
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
              <SettingsView onNotify={showToast} onOpenMetrics={() => navigate('metrics')} />
            )}
          </Suspense>
        </ErrorBoundary>
      </main>

      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        projects={projects}
        onNavigate={(v) => navigate(v as AppView)}
        onSelectProject={(id) => selectProject(id)}
        onQuickCreateProject={() => handleQuickAction('new_project')}
        onQuickConnectDomain={() => handleQuickAction('domain')}
        onQuickImport={(src) => openImport(src || 'wordpress')}
      />

      <footer className="border-t border-slate-200 py-4 bg-white mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-2">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-800">Culkibo v1.0.0</span>
            <span>·</span>
            <span>Apache-2.0</span>
          </div>
          <div className="flex items-center gap-3 text-slate-400">
            <span>Caddy</span>
            <span>·</span>
            <span>Live Sync</span>
            <span>·</span>
            <span>MCP 2026-07-28</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
