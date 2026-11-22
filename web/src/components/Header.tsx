import React, { useState, useRef, useEffect } from 'react';
import {
  Settings,
  LayoutGrid,
  Activity,
  ChevronRight,
  Package,
  Globe,
  Bot,
  Download,
  Plus,
  ChevronDown,
  Rocket,
  FileCode2,
  Zap
} from 'lucide-react';

export type AppView = 'projects' | 'import' | 'domains' | 'catalog' | 'ai' | 'global_logs' | 'settings';

interface HeaderProps {
  activeView: AppView;
  setActiveView: (view: AppView) => void;
  wsConnected: boolean;
  breadcrumb?: string;
  activeProjectId?: string | null;
  setActiveProjectId?: (id: string) => void;
  projects?: any[];
  onQuickAction?: (action: 'new_project' | 'wordpress' | 'import' | 'domain') => void;
  aiPulseLabel?: string | null;
  activeSyncCount?: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeView,
  setActiveView,
  wsConnected,
  breadcrumb,
  activeProjectId,
  setActiveProjectId,
  projects = [],
  onQuickAction,
  aiPulseLabel,
  activeSyncCount = 0
}) => {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!menuOpen) return;
    const onDocClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMenuOpen(false);
    };
    document.addEventListener('mousedown', onDocClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDocClick);
      document.removeEventListener('keydown', onKey);
    };
  }, [menuOpen]);

  const navItems: Array<{ id: AppView; label: string; icon: React.ComponentType<{ className?: string }> }> = [
    { id: 'projects', label: 'Proyectos', icon: LayoutGrid },
    { id: 'import', label: 'Importar', icon: Download },
    { id: 'domains', label: 'Dominios', icon: Globe },
    { id: 'catalog', label: 'Catálogo', icon: Package },
    { id: 'ai', label: 'Agentes IA', icon: Bot }
  ];

  const triggerAction = (action: 'new_project' | 'wordpress' | 'import' | 'domain') => {
    setMenuOpen(false);
    if (onQuickAction) {
      onQuickAction(action);
      return;
    }
    if (action === 'domain') setActiveView('domains');
    else if (action === 'import' || action === 'wordpress') setActiveView('import');
    else setActiveView('projects');
  };

  return (
    <header className="sticky top-0 z-50 bg-white/95 backdrop-blur-sm border-b border-slate-200 shadow-[0_1px_2px_0_rgba(0,0,0,0.02)]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-3">
          {/* Logo & Brand */}
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              className="flex-shrink-0 flex items-center gap-2.5 cursor-pointer group"
              onClick={() => setActiveView('projects')}
            >
              <svg width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" className="shrink-0">
                <rect width="32" height="32" rx="8" fill="#18181B" />
                <path d="M9.5 16L14.5 11L22.5 19" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
                <path d="M14.5 21L19.5 16L22.5 19" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
                <circle cx="22.5" cy="19" r="2" fill="white" />
                <circle cx="14.5" cy="11" r="2" fill="white" />
                <circle cx="9.5" cy="16" r="2" fill="white" />
              </svg>
              <span className="font-semibold text-lg text-slate-900 tracking-tight leading-none">
                Culkibo
              </span>
            </button>

            {breadcrumb && !activeProjectId && (
              <div className="hidden xl:flex items-center gap-1.5 text-xs text-slate-400 font-medium truncate">
                <ChevronRight className="w-3.5 h-3.5 text-slate-300 shrink-0" />
                <span className="truncate">{breadcrumb}</span>
              </div>
            )}

            {activeProjectId && projects.length > 0 && (
              <div className="hidden sm:flex items-center gap-2 text-sm text-slate-500 font-medium ml-1 border-l border-slate-200 pl-3">
                <select
                  aria-label="Cambiar de proyecto"
                  value={activeProjectId}
                  onChange={(e) => setActiveProjectId?.(e.target.value)}
                  className="bg-transparent font-semibold text-slate-900 focus:outline-none cursor-pointer max-w-[180px] truncate"
                >
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>{p.name}</option>
                  ))}
                </select>
              </div>
            )}
          </div>

          {/* Center Primary Navigation */}
          <nav className="hidden md:flex items-center gap-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeView === item.id && !activeProjectId;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveView(item.id)}
                  className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-150 cursor-pointer whitespace-nowrap ${
                    isActive
                      ? 'bg-slate-100 text-slate-900 border border-slate-200 shadow-2xs'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50 border border-transparent'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-slate-900' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                  {item.id === 'ai' && aiPulseLabel && (
                    <span className="w-1.5 h-1.5 rounded-full bg-blue-600 animate-ping" title={aiPulseLabel} />
                  )}
                </button>
              );
            })}
          </nav>

          {/* Right Utilities & + Nuevo */}
          <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
            {/* Live status pill */}
            <button
              type="button"
              onClick={() => setActiveView(aiPulseLabel ? 'ai' : 'global_logs')}
              className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 text-xs font-medium text-slate-700 transition-colors cursor-pointer"
              title={aiPulseLabel ? `Última acción IA: ${aiPulseLabel}` : wsConnected ? 'Conexión en tiempo real activa' : 'Reconectando con el servidor'}
            >
              <span className="relative flex h-2 w-2">
                {wsConnected && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />}
                <span className={`relative inline-flex rounded-full h-2 w-2 ${wsConnected ? 'bg-emerald-500' : 'bg-rose-500'}`} />
              </span>
              {activeSyncCount > 0 ? (
                <span className="inline-flex items-center gap-1 text-blue-700 font-semibold">
                  <Zap className="w-3 h-3" />
                  Live ({activeSyncCount})
                </span>
              ) : aiPulseLabel ? (
                <span className="text-blue-700 font-semibold max-w-[110px] truncate">IA activa</span>
              ) : (
                <span>{wsConnected ? 'En línea' : 'Sin señal'}</span>
              )}
            </button>

            <button
              type="button"
              onClick={() => setActiveView('global_logs')}
              title="Actividad y registros en vivo"
              className={`p-2 rounded-lg border transition-colors cursor-pointer ${
                activeView === 'global_logs'
                  ? 'bg-slate-100 text-slate-900 border-slate-200'
                  : 'text-slate-500 hover:text-slate-900 hover:bg-slate-50 border-transparent'
              }`}
            >
              <Activity className="w-4 h-4" />
            </button>

            <button
              type="button"
              onClick={() => setActiveView('settings')}
              title="Ajustes del servidor y acceso remoto"
              className={`p-2 rounded-lg border transition-colors cursor-pointer ${
                activeView === 'settings'
                  ? 'bg-slate-100 text-slate-900 border-slate-200'
                  : 'text-slate-500 hover:text-slate-900 hover:bg-slate-50 border-transparent'
              }`}
            >
              <Settings className="w-4 h-4" />
            </button>

            {/* + Nuevo Dropdown */}
            <div className="relative" ref={menuRef}>
              <button
                type="button"
                onClick={() => setMenuOpen((prev) => !prev)}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 transition-colors shadow-sm cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Nuevo</span>
                <ChevronDown className={`w-3.5 h-3.5 text-slate-300 transition-transform ${menuOpen ? 'rotate-180' : ''}`} />
              </button>

              {menuOpen && (
                <div className="absolute right-0 mt-2 w-64 bg-white border border-slate-200 rounded-xl shadow-xl py-1.5 z-50">
                  <button
                    type="button"
                    onClick={() => triggerAction('new_project')}
                    className="w-full px-3.5 py-2.5 text-left hover:bg-slate-50 flex items-start gap-2.5 transition-colors cursor-pointer"
                  >
                    <Rocket className="w-4 h-4 text-slate-700 mt-0.5 shrink-0" />
                    <div>
                      <div className="text-xs font-semibold text-slate-900">Nuevo proyecto</div>
                      <div className="text-[11px] text-slate-500">GitHub, URL Git o plantilla rápida</div>
                    </div>
                  </button>
                  <button
                    type="button"
                    onClick={() => triggerAction('wordpress')}
                    className="w-full px-3.5 py-2.5 text-left hover:bg-slate-50 flex items-start gap-2.5 transition-colors cursor-pointer"
                  >
                    <Globe className="w-4 h-4 text-blue-600 mt-0.5 shrink-0" />
                    <div>
                      <div className="text-xs font-semibold text-slate-900">Migrar mi WordPress</div>
                      <div className="text-[11px] text-slate-500">Analiza tu web y pásala sin cortes</div>
                    </div>
                  </button>
                  <button
                    type="button"
                    onClick={() => triggerAction('import')}
                    className="w-full px-3.5 py-2.5 text-left hover:bg-slate-50 flex items-start gap-2.5 transition-colors cursor-pointer"
                  >
                    <FileCode2 className="w-4 h-4 text-indigo-600 mt-0.5 shrink-0" />
                    <div>
                      <div className="text-xs font-semibold text-slate-900">Importar desde otra plataforma</div>
                      <div className="text-[11px] text-slate-500">Coolify, Compose, Vercel, Netlify, Railway</div>
                    </div>
                  </button>
                  <div className="my-1 border-t border-slate-100" />
                  <button
                    type="button"
                    onClick={() => triggerAction('domain')}
                    className="w-full px-3.5 py-2.5 text-left hover:bg-slate-50 flex items-start gap-2.5 transition-colors cursor-pointer"
                  >
                    <Globe className="w-4 h-4 text-emerald-600 mt-0.5 shrink-0" />
                    <div>
                      <div className="text-xs font-semibold text-slate-900">Conectar dominio o Wildcard</div>
                      <div className="text-[11px] text-slate-500">Asistente en 3 pasos con HTTPS</div>
                    </div>
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Mobile Navigation Tabs */}
        <div className="flex md:hidden overflow-x-auto py-2 gap-1.5 border-t border-slate-100">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeView === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveView(item.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap border cursor-pointer ${
                  isActive
                    ? 'bg-slate-100 text-slate-900 border-slate-200 shadow-2xs'
                    : 'text-slate-600 hover:bg-slate-50 border-transparent'
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
