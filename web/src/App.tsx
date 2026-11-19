import { useState, useEffect, useRef, useCallback } from 'react';
import { Header } from './components/Header';
import { ProjectList } from './components/ProjectList';
import { ProjectDetail } from './components/ProjectDetail';
import { CoolifyImport } from './components/CoolifyImport';
import { LiveLogs } from './components/LiveLogs';
import { SettingsView } from './components/SettingsView';
import { ServiceCatalog } from './components/ServiceCatalog';
import { AuthGate } from './components/AuthGate';
import { ErrorBoundary } from './components/ErrorBoundary';
import { api, getAuthToken, type LogEntry } from './lib/api';
import { deployStream } from './lib/deployStream';

export function App() {
  const [authChecked, setAuthChecked] = useState(false);
  const [authenticated, setAuthenticated] = useState(true);
  const [tokenSource, setTokenSource] = useState('data/auth.json');
  const [activeView, setActiveView] = useState<'projects' | 'catalog' | 'import' | 'global_logs' | 'settings'>('projects');
  const [activeProjectId, setActiveProjectId] = useState<string | null>(null);
  
  const [latestLog, setLatestLog] = useState<LogEntry | null>(null);
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const toastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

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

  // Each toast restarts its own timer. Previously a second toast inherited the
  // first one's countdown and vanished early.
  const showToast = (msg: string) => {
    setToastMessage(msg);
    if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    toastTimerRef.current = setTimeout(() => setToastMessage(null), 3500);
  };

  const [projects, setProjects] = useState<any[]>([]);

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
  }, []);

  useEffect(() => {
    if (!authenticated) return;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.port === '5173' ? 'localhost:3030' : window.location.host;
    const wsUrl = `${protocol}//${host}/ws`;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let reconnectAttempts = 0;
    // Closing the socket in the cleanup fires onclose asynchronously, which used
    // to schedule a fresh reconnect AFTER the cleanup already cleared the timer —
    // leaving an orphan socket reconnecting forever (doubled under StrictMode).
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
            if (parsed.type === 'log') {
              setLatestLog(parsed.data);
            } else if (parsed.type === 'deploy_log') {
              // Deliberately NOT state: a verbose build emits thousands of
              // lines per second, and each WebSocket message is its own
              // macrotask, so React 19's auto-batching would not merge them.
              // The panel buffers these in a ref and paints once per frame.
              deployStream.emitLog(parsed.data);
            } else if (parsed.type === 'deploy_event') {
              deployStream.emitEvent(parsed.data);
            } else if (parsed.type === 'traffic_change') {
              showToast(`Tráfico actualizado: ${parsed.data.citadel}% Prod / ${parsed.data.forge}% Dev`);
            } else if (parsed.type === 'ssl_progress') {
              if (parsed.data.stage === 'installed') {
                showToast(`¡SSL Wildcard emitido para ${parsed.data.domain}!`);
              }
            } else if (parsed.type === 'github_deploy') {
              showToast(`🚀 Push en ${parsed.data.branch} (${parsed.data.commit}) por ${parsed.data.author}: ${parsed.data.message}`);
              void fetchProjects();
            } else if (parsed.type === 'project_update' || parsed.type === 'project_created' || parsed.type === 'project_deleted') {
              void fetchProjects();
            } else if (parsed.type === 'mcp_call') {
              showToast(`Agente IA ejecutó: ${parsed.data.toolName}`);
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
  }, [authenticated, fetchProjects]);

  useEffect(() => {
    if (!authenticated) return;
    let active = true;
    api.getProjects()
      .then((data) => { if (active) setProjects(data); })
      .catch((e) => console.error(e));
    return () => { active = false; };
  }, [activeView, activeProjectId, authenticated]);

  const getBreadcrumb = () => {
    if (activeView === 'projects') return 'Mis Proyectos';
    if (activeView === 'catalog') return 'Catálogo de servicios';
    if (activeView === 'import') return 'Mis Proyectos > Importar de Coolify';
    if (activeView === 'global_logs') return 'Actividad Global';
    if (activeView === 'settings') return 'Configuración';
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
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 px-4 py-3 rounded-xl bg-white border border-slate-200 text-slate-900 font-medium text-xs shadow-xl animate-fade-in">
          <span className="w-2 h-2 rounded-full bg-blue-600 animate-ping" />
          <span>{toastMessage}</span>
        </div>
      )}

      <Header
        activeView={activeView}
        setActiveView={(v) => { setActiveView(v); setActiveProjectId(null); }}
        wsConnected={wsConnected}
        breadcrumb={activeProjectId ? undefined : getBreadcrumb()}
        activeProjectId={activeProjectId}
        setActiveProjectId={setActiveProjectId}
        projects={projects}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <ErrorBoundary>
        {activeView === 'projects' && !activeProjectId && (
          <ProjectList 
            projects={projects}
            onRefreshProjects={fetchProjects}
            onSelectProject={setActiveProjectId} 
            onImportCoolify={() => setActiveView('import')} 
            onNotify={showToast}
          />
        )}

        {activeProjectId && (
          <ProjectDetail 
            projectId={activeProjectId} 
            onBack={() => { setActiveProjectId(null); fetchProjects(); }} 
            onNotify={showToast} 
            onProjectUpdate={fetchProjects}
            incomingLog={latestLog}
          />
        )}

        {activeView === 'catalog' && !activeProjectId && (
          <ServiceCatalog onNotify={showToast} />
        )}

        {activeView === 'import' && (
          <CoolifyImport 
            onComplete={() => setActiveView('projects')} 
            onCancel={() => setActiveView('projects')} 
            onNotify={showToast} 
          />
        )}

        {activeView === 'global_logs' && (
          <div className="h-[75vh] bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
            <LiveLogs incomingLog={latestLog} />
          </div>
        )}

        {activeView === 'settings' && (
          <SettingsView />
        )}
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
            <span>Live Sync &amp; Merkle</span>
            <span>MCP 2026-07-28</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
