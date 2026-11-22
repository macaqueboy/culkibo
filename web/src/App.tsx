import { useState, useEffect, useRef, useCallback, lazy, Suspense } from 'react';
import { Header, type AppView } from './components/Header';
import { ProjectList } from './components/ProjectList';
import { AuthGate } from './components/AuthGate';
import { ErrorBoundary } from './components/ErrorBoundary';
import { api, getAuthToken, type Project } from './lib/api';
import { deployStream } from './lib/deployStream';
import { liveEvents } from './lib/liveEvents';
import type { ImportSourceTab } from './components/UniversalImporter';

const ProjectDetail = lazy(() => import('./components/ProjectDetail').then((m) => ({ default: m.ProjectDetail })));
const UniversalImporter = lazy(() => import('./components/UniversalImporter').then((m) => ({ default: m.UniversalImporter })));
const DomainManager = lazy(() => import('./components/DomainManager').then((m) => ({ default: m.DomainManager })));
const ServiceCatalog = lazy(() => import('./components/ServiceCatalog').then((m) => ({ default: m.ServiceCatalog })));
const AiAgentHub = lazy(() => import('./components/AiAgentHub').then((m) => ({ default: m.AiAgentHub })));
const LiveLogs = lazy(() => import('./components/LiveLogs').then((m) => ({ default: m.LiveLogs })));
const SettingsView = lazy(() => import('./components/SettingsView').then((m) => ({ default: m.SettingsView })));

type ToastKind = 'info' | 'success' | 'error';

const ViewFallback = () => (
  <div className="py-16 text-center text-sm text-slate-500">Cargando vista…</div>
);

export function App() {
  const [authChecked, setAuthChecked] = useState(false);
  const [authenticated, setAuthenticated] = useState(true);
  const [tokenSource, setTokenSource] = useState('data/auth.json');
  const [activeView, setActiveView] = useState<AppView>('projects');
  const [importInitialTab, setImportInitialTab] = useState<ImportSourceTab>('wordpress');
  const [domainWizardAutoOpen, setDomainWizardAutoOpen] = useState(false);
  const [createProjectTrigger, setCreateProjectTrigger] = useState(0);
  const [activeProjectId, setActiveProjectId] = useState<string | null>(null);

  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [toast, setToast] = useState<{ msg: string; kind: ToastKind } | null>(null);
  const [aiPulseLabel, setAiPulseLabel] = useState<string | null>(null);
  const [activeSyncCount, setActiveSyncCount] = useState<number>(0);

  const wsRef = useRef<WebSocket | null>(null);
  const toastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const aiPulseTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const syncClientsByProjectRef = useRef<Map<string, number>>(new Map());

  useEffect(() => {
    api.getAuthSession()
      .then((s) => {
        setAuthenticated(s.authenticated);
        setTokenSource(s.tokenSource || 'data/auth.json');
      })
      .catch(() => {
        setAuthenticated(true);
      })
      .finally(() => setAuthChecked(true));
  }, []);

  const showToast = useCallback((msg: string, kind: ToastKind = 'info') => {
    setToast({ msg, kind });
    if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    toastTimerRef.current = setTimeout(() => setToast(null), 3800);
  }, []);

  const [projects, setProjects] = useState<Project[]>([]);

  const fetchProjects = useCallback(async () => {
    if (!authenticated) return;
    try {
      const data = await api.getProjects();
      setProjects(data);
    } catch (e) {
      console.error(e);
    }
  }, [authenticated]);

  useEffect(() => () => {
    if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    if (aiPulseTimerRef.current) clearTimeout(aiPulseTimerRef.current);
  }, []);

  useEffect(() => {
    if (!authenticated) return;
    let active = true;
    api.getProjects()
      .then((data) => { if (active) setProjects(data); })
      .catch((e) => console.error(e));
    return () => { active = false; };
  }, [authenticated]);

  useEffect(() => {
    if (!authenticated) return;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.port === '5173' ? 'localhost:3030' : window.location.host;
    const wsUrl = `${protocol}//${host}/ws`;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let reconnectAttempts = 0;
    let disposed = false;

    const connectWs = () => {
      if (disposed) return;
      try {
        const storedToken = getAuthToken();
        const ws = storedToken
          ? new WebSocket(wsUrl, [`culkibo-token.${storedToken}`])
          : new WebSocket(wsUrl);
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
              // Sin useState en App: el bus entrega logs directo a LiveLogs con 0 re-renders globales.
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
          reconnectTimer = setTimeout(connectWs, backoff);
        };

        ws.onerror = () => ws.close();
      } catch {
        if (disposed) return;
        const backoff = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
        reconnectAttempts++;
        reconnectTimer = setTimeout(connectWs, backoff);
      }
    };

    connectWs();

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

  const navigate = (view: AppView) => {
    setDomainWizardAutoOpen(false);
    setActiveView(view);
    setActiveProjectId(null);
  };

  const handleQuickAction = (action: 'new_project' | 'wordpress' | 'import' | 'domain') => {
    setActiveProjectId(null);
    if (action === 'new_project') {
      setActiveView('projects');
      setCreateProjectTrigger((c) => c + 1);
    } else if (action === 'wordpress') {
      setImportInitialTab('wordpress');
      setActiveView('import');
    } else if (action === 'import') {
      setImportInitialTab('coolify');
      setActiveView('import');
    } else if (action === 'domain') {
      setDomainWizardAutoOpen(true);
      setActiveView('domains');
    }
  };

  const getBreadcrumb = () => {
    if (activeView === 'projects') return 'Tus Proyectos';
    if (activeView === 'import') return 'Importar y Migrar';
    if (activeView === 'domains') return 'Dominios y HTTPS';
    if (activeView === 'catalog') return 'Catálogo 1 clic';
    if (activeView === 'ai') return 'Agentes IA en directo';
    if (activeView === 'global_logs') return 'Actividad en vivo';
    if (activeView === 'settings') return 'Ajustes';
    return '';
  };

  if (!authChecked) {
    return (
      <div className="min-h-screen bg-slate-50 text-slate-500 flex items-center justify-center text-sm">
        Comprobando acceso…
      </div>
    );
  }

  if (!authenticated) {
    return <AuthGate tokenSource={tokenSource} onAuthenticated={() => setAuthenticated(true)} />;
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 selection:bg-blue-100 selection:text-blue-900 flex flex-col font-sans">
      {toast && (
        <div
          className={`fixed bottom-6 right-6 z-50 flex items-center gap-2.5 px-4 py-3 rounded-xl bg-white border text-xs font-medium shadow-xl ${
            toast.kind === 'error'
              ? 'border-rose-200 text-rose-800'
              : toast.kind === 'success'
                ? 'border-emerald-200 text-emerald-900'
                : 'border-slate-200 text-slate-900'
          }`}
        >
          <span
            className={`w-2 h-2 rounded-full ${
              toast.kind === 'error' ? 'bg-rose-500' : toast.kind === 'success' ? 'bg-emerald-500' : 'bg-blue-600'
            }`}
          />
          <span>{toast.msg}</span>
        </div>
      )}

      <Header
        activeView={activeView}
        setActiveView={navigate}
        wsConnected={wsConnected}
        breadcrumb={activeProjectId ? undefined : getBreadcrumb()}
        activeProjectId={activeProjectId}
        setActiveProjectId={setActiveProjectId}
        projects={projects}
        onQuickAction={handleQuickAction}
        aiPulseLabel={aiPulseLabel}
        activeSyncCount={activeSyncCount}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <ErrorBoundary>
          <Suspense fallback={<ViewFallback />}>
            {activeView === 'projects' && !activeProjectId && (
              <ProjectList
                projects={projects}
                onRefreshProjects={fetchProjects}
                onSelectProject={setActiveProjectId}
                onImportCoolify={() => { setImportInitialTab('coolify'); navigate('import'); }}
                onOpenWordPress={() => { setImportInitialTab('wordpress'); navigate('import'); }}
                onOpenCatalog={() => navigate('catalog')}
                onOpenDomains={() => navigate('domains')}
                onOpenAi={() => navigate('ai')}
                onNotify={(m) => showToast(m)}
                externalCreateTrigger={createProjectTrigger}
              />
            )}

            {activeProjectId && (
              <ProjectDetail
                projectId={activeProjectId}
                onBack={() => { setActiveProjectId(null); void fetchProjects(); }}
                onNotify={(m) => showToast(m)}
                onProjectUpdate={fetchProjects}
                onOpenCatalog={() => navigate('catalog')}
              />
            )}

            {activeView === 'import' && !activeProjectId && (
              <UniversalImporter
                initialSource={importInitialTab}
                onComplete={(createdId) => {
                  void fetchProjects();
                  if (createdId) {
                    setActiveView('projects');
                    setActiveProjectId(createdId);
                  } else {
                    navigate('projects');
                  }
                }}
                onOpenDomains={() => navigate('domains')}
                onNotify={(m) => showToast(m)}
              />
            )}

            {activeView === 'domains' && !activeProjectId && (
              <DomainManager
                onNotify={(m) => showToast(m)}
                autoOpenWizard={domainWizardAutoOpen}
              />
            )}

            {activeView === 'catalog' && !activeProjectId && (
              <ServiceCatalog onNotify={(m) => showToast(m)} />
            )}

            {activeView === 'ai' && !activeProjectId && (
              <AiAgentHub onNotify={(m) => showToast(m)} />
            )}

            {activeView === 'global_logs' && !activeProjectId && (
              <div className="h-[75vh] bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
                <LiveLogs />
              </div>
            )}

            {activeView === 'settings' && !activeProjectId && (
              <SettingsView onNotify={(m) => showToast(m)} />
            )}
          </Suspense>
        </ErrorBoundary>
      </main>

      <footer className="border-t border-slate-200 py-6 bg-white mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-3">
          <div className="flex items-center gap-2">
            <span className="font-bold text-slate-800">Culkibo v1.0.0</span>
            <span>·</span>
            <span>Orquestador cloud autohospedado · Apache-2.0</span>
          </div>
          <div className="flex items-center gap-4 text-slate-500">
            <span>Caddy zero-downtime</span>
            <span>Live Sync Binario &amp; Merkle</span>
            <span>MCP 2026-07-28</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
