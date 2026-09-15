import { useState, useEffect, useRef } from 'react';
import { Header } from './components/Header';
import { ProjectList } from './components/ProjectList';
import { ProjectDetail } from './components/ProjectDetail';
import { CoolifyImport } from './components/CoolifyImport';
import { LiveLogs } from './components/LiveLogs';
import { SettingsView } from './components/SettingsView';
import { api, type LogEntry } from './lib/api';

export function App() {
  const [activeView, setActiveView] = useState<'projects' | 'import' | 'global_logs' | 'settings'>('projects');
  const [activeProjectId, setActiveProjectId] = useState<string | null>(null);
  
  const [latestLog, setLatestLog] = useState<LogEntry | null>(null);
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const toastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Each toast restarts its own timer. Previously a second toast inherited the
  // first one's countdown and vanished early.
  const showToast = (msg: string) => {
    setToastMessage(msg);
    if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    toastTimerRef.current = setTimeout(() => setToastMessage(null), 3500);
  };

  useEffect(() => () => {
    if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
  }, []);

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.port === '5173' ? 'localhost:3030' : window.location.host;
    const wsUrl = `${protocol}//${host}/ws`;
    let reconnectTimer: any = null;
    let reconnectAttempts = 0;
    // Closing the socket in the cleanup fires onclose asynchronously, which used
    // to schedule a fresh reconnect AFTER the cleanup already cleared the timer —
    // leaving an orphan socket reconnecting forever (doubled under StrictMode).
    let disposed = false;

    const connectWs = () => {
      if (disposed) return;
      try {
        const ws = new WebSocket(wsUrl);
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
            } else if (parsed.type === 'traffic_change') {
              showToast(`Tráfico actualizado: ${parsed.data.citadel}% Prod / ${parsed.data.forge}% Dev`);
            } else if (parsed.type === 'ssl_progress') {
              if (parsed.data.stage === 'installed') {
                showToast(`¡SSL Wildcard emitido para ${parsed.data.domain}!`);
              }
            } else if (parsed.type === 'github_deploy') {
              showToast(`🚀 Push en ${parsed.data.branch} (${parsed.data.commit}) por ${parsed.data.author}: ${parsed.data.message}`);
              fetchProjects();
            } else if (parsed.type === 'project_update' || parsed.type === 'project_created' || parsed.type === 'project_deleted') {
              fetchProjects();
            } else if (parsed.type === 'mcp_call') {
              showToast(`Agente IA ejecutó: ${parsed.data.toolName}`);
            }
          } catch (e) {}
        };

        ws.onclose = () => {
          setWsConnected(false);
          if (disposed) return;
          const backoff = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
          reconnectAttempts++;
          reconnectTimer = setTimeout(connectWs, backoff);
        };

        ws.onerror = () => ws.close();
      } catch (err) {
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
  }, []);

  const [projects, setProjects] = useState<any[]>([]);

  const fetchProjects = async () => {
    try {
      const data = await api.getProjects();
      setProjects(data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchProjects();
  }, [activeView, activeProjectId]);

  const getBreadcrumb = () => {
    if (activeView === 'projects') return 'Mis Proyectos';
    if (activeView === 'import') return 'Mis Proyectos > Importar de Coolify';
    if (activeView === 'global_logs') return 'Actividad Global';
    if (activeView === 'settings') return 'Configuración';
    return '';
  };

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
      </main>

      <footer className="border-t border-slate-200 py-6 bg-white mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-3">
          <div className="flex items-center gap-2">
            <span className="font-bold text-slate-800">Culkibo v1.0.0</span>
            <span>•</span>
            <span>Tu nube y servidor en tiempo real con IA</span>
          </div>
          <div className="flex items-center gap-4 text-slate-500">
            <span>Sincronización &lt;35ms</span>
            <span>Cloudflare Wildcard SSL</span>
            <span>Control nativo por MCP</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
