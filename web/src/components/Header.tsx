import React, { useState } from 'react';
import { Settings, RefreshCw, LayoutGrid, Activity, ChevronRight, Package } from 'lucide-react';
import { api } from '../lib/api';

interface HeaderProps {
  activeView: string;
  setActiveView: (view: any) => void;
  wsConnected: boolean;
  breadcrumb?: string;
  activeProjectId?: string | null;
  setActiveProjectId?: (id: string) => void;
  projects?: any[];
}

export const Header: React.FC<HeaderProps> = ({
  activeView,
  setActiveView,
  wsConnected,
  breadcrumb,
  activeProjectId,
  setActiveProjectId,
  projects = []
}) => {
  const [syncing, setSyncing] = useState(false);
  const [syncMessage, setSyncMessage] = useState<string | null>(null);

  const handleQuickSync = async () => {
    try {
      setSyncing(true);
      const res = await api.triggerHotSync('src/App.tsx');
      if (res.success) {
        setSyncMessage(`${res.syncDurationMs}ms`);
        setTimeout(() => setSyncMessage(null), 3000);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setSyncing(false);
    }
  };

  const navItems = [
    { id: 'projects', label: 'Proyectos', icon: LayoutGrid },
    { id: 'catalog', label: 'Catálogo', icon: Package },
    { id: 'global_logs', label: 'Actividad Global', icon: Activity },
    { id: 'settings', label: 'Configuración', icon: Settings }
  ];

  return (
    <header className="sticky top-0 z-50 bg-white border-b border-slate-200 shadow-[0_1px_3px_0_rgba(0,0,0,0.02)]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Brand */}
          <div className="flex items-center gap-3">
            <div className="flex-shrink-0 flex items-center justify-center cursor-pointer" onClick={() => setActiveView('projects')}>
              <svg width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                <rect width="32" height="32" rx="8" fill="#1E293B" />
                <path d="M9.5 16L14.5 11L22.5 19" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
                <path d="M14.5 21L19.5 16L22.5 19" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
                <circle cx="22.5" cy="19" r="2" fill="white" />
                <circle cx="14.5" cy="11" r="2" fill="white" />
                <circle cx="9.5" cy="16" r="2" fill="white" />
              </svg>
            </div>
            <div className="flex flex-col justify-center">
              <div className="flex items-baseline gap-2">
                <span className="font-semibold text-lg text-slate-900 tracking-tight leading-none cursor-pointer" onClick={() => setActiveView('projects')}>
                  Culkibo
                </span>
                {breadcrumb && (
                  <div className="hidden sm:flex items-center gap-2 text-sm text-slate-500 font-medium">
                    <ChevronRight className="w-4 h-4 text-slate-300" />
                    <span>{breadcrumb}</span>
                  </div>
                )}
                {activeProjectId && projects.length > 0 && (
                  <div className="hidden sm:flex items-center gap-2 text-sm text-slate-500 font-medium ml-2 border-l border-slate-200 pl-4">
                    <select
                      value={activeProjectId}
                      onChange={(e) => setActiveProjectId?.(e.target.value)}
                      className="bg-transparent font-semibold text-slate-900 focus:outline-none cursor-pointer"
                    >
                      {projects.map(p => (
                        <option key={p.id} value={p.id}>{p.name}</option>
                      ))}
                    </select>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Center Navigation Tabs - gap-2 instead of gap-1, padding px-4 py-2 */}
          <nav className="hidden md:flex items-center gap-2">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeView === item.id || (item.id === 'projects' && activeView === 'import');
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveView(item.id)}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                    isActive
                      ? 'bg-slate-100 text-slate-900 shadow-sm border border-slate-200'
                      : 'text-slate-500 hover:text-slate-900 hover:bg-slate-50 border border-transparent'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-slate-900' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Quick Actions & Status */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5">
              <span className="relative flex h-2.5 w-2.5">
                {wsConnected && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>}
                <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${wsConnected ? 'bg-emerald-500' : 'bg-red-500'}`}></span>
              </span>
              <span className="text-slate-600 font-medium text-xs hidden sm:inline">
                {wsConnected ? 'Conectado' : 'Desconectado'}
              </span>
            </div>

            <div className="h-4 w-px bg-slate-200 hidden sm:block"></div>

            {/* Quick Sync Button with Blue Background */}
            <button
              onClick={handleQuickSync}
              disabled={syncing}
              title="Sincronizar cambios inmediatamente con el servidor"
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold text-white bg-blue-600 hover:bg-blue-700 transition-colors shadow-sm disabled:opacity-50 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
              <span>{syncing ? 'Sincronizando...' : 'Sincronizar'}</span>
              {syncMessage && (
                <span className="ml-1 text-blue-100 font-medium">
                  {syncMessage}
                </span>
              )}
            </button>
          </div>
        </div>

        {/* Mobile Navigation Tabs */}
        <div className="flex md:hidden overflow-x-auto py-2 gap-2 border-t border-slate-100 scrollbar-hide">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeView === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveView(item.id)}
                className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-medium whitespace-nowrap border ${
                  isActive
                    ? 'bg-slate-100 text-slate-900 border-slate-200 shadow-sm'
                    : 'text-slate-500 hover:bg-slate-50 border-transparent'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-slate-900' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};
