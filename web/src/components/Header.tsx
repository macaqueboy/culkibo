import React, { useState, useRef, useEffect } from 'react';
import {
  Settings,
  LayoutGrid,
  Gauge,
  Package,
  Globe,
  Bot,
  Download,
  Plus,
  ChevronDown,
  Rocket,
  FileCode2,
  Search,
  Zap,
  Check,
} from 'lucide-react';
import { CulkiboLogo } from './CulkiboLogo';

const IS_MAC = typeof navigator !== 'undefined' && /mac|iphone|ipad/i.test(navigator.platform || navigator.userAgent || '');

export type AppView =
  | 'projects'
  | 'metrics'
  | 'import'
  | 'domains'
  | 'catalog'
  | 'ai'
  | 'global_logs'
  | 'settings';

interface HeaderProps {
  activeView: AppView;
  setActiveView: (view: AppView) => void;
  wsConnected: boolean;
  activeProjectId?: string | null;
  setActiveProjectId?: (id: string) => void;
  projects?: any[];
  onQuickAction?: (action: 'new_project' | 'wordpress' | 'import' | 'domain') => void;
  onOpenPalette?: () => void;
  aiPulseLabel?: string | null;
  activeSyncCount?: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeView,
  setActiveView,
  wsConnected,
  activeProjectId,
  setActiveProjectId,
  projects = [],
  onQuickAction,
  onOpenPalette,
  aiPulseLabel,
  activeSyncCount = 0,
}) => {
  const [menuOpen, setMenuOpen] = useState(false);
  const [projMenuOpen, setProjMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const projMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!menuOpen && !projMenuOpen) return;
    const onDocClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
      if (projMenuRef.current && !projMenuRef.current.contains(e.target as Node)) {
        setProjMenuOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setMenuOpen(false);
        setProjMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', onDocClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDocClick);
      document.removeEventListener('keydown', onKey);
    };
  }, [menuOpen, projMenuOpen]);

  const currentProject = activeProjectId ? projects.find((p) => p.id === activeProjectId) : null;

  const navItems: Array<{ id: AppView; label: string; icon: React.ComponentType<{ className?: string }> }> = [
    { id: 'projects', label: 'Proyectos', icon: LayoutGrid },
    { id: 'metrics', label: 'Métricas', icon: Gauge },
    { id: 'domains', label: 'Dominios', icon: Globe },
    { id: 'catalog', label: 'Catálogo', icon: Package },
    { id: 'import', label: 'Importar', icon: Download },
    { id: 'ai', label: 'Agentes IA', icon: Bot },
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
    <header className="sticky top-0 z-40 bg-white/95 backdrop-blur-sm border-b border-slate-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-14 gap-3">
          {/* Marca + Selector de proyecto cuando estamos dentro de uno */}
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              className="shrink-0 flex items-center gap-2 cursor-pointer rounded-lg pr-1"
              onClick={() => setActiveView('projects')}
            >
              <CulkiboLogo size={26} />
              <span className="font-semibold text-[15px] text-slate-900 tracking-tight leading-none">
                Culkibo
              </span>
            </button>

            {activeProjectId && projects.length > 0 && (
              <div className="hidden sm:flex items-center relative border-l border-slate-200 pl-3" ref={projMenuRef}>
                <button
                  type="button"
                  onClick={() => setProjMenuOpen((v) => !v)}
                  aria-expanded={projMenuOpen}
                  aria-haspopup="listbox"
                  className="inline-flex items-center gap-1.5 px-2 py-1 rounded-lg text-sm font-medium text-slate-900 hover:bg-slate-100 transition-colors cursor-pointer max-w-[190px]"
                >
                  <span className="truncate">{currentProject?.name || 'Proyecto'}</span>
                  <ChevronDown className={`w-3.5 h-3.5 text-slate-400 shrink-0 transition-transform ${projMenuOpen ? 'rotate-180' : ''}`} />
                </button>
                {projMenuOpen && (
                  <div
                    role="listbox"
                    aria-label="Cambiar de proyecto"
                    className="culkibo-modal-enter absolute left-3 top-full mt-1.5 w-60 max-h-72 overflow-y-auto bg-white border border-slate-200 rounded-xl shadow-lg py-1.5 z-50"
                  >
                    {projects.map((p) => {
                      const selected = p.id === activeProjectId;
                      return (
                        <button
                          key={p.id}
                          type="button"
                          role="option"
                          aria-selected={selected}
                          onClick={() => {
                            setProjMenuOpen(false);
                            setActiveProjectId?.(p.id);
                          }}
                          className={`w-full px-3 py-2 text-left text-xs flex items-center justify-between gap-2 transition-colors cursor-pointer ${
                            selected ? 'bg-slate-100 text-slate-900 font-semibold' : 'text-slate-700 hover:bg-slate-50'
                          }`}
                        >
                          <span className="truncate">{p.name}</span>
                          {selected && <Check className="w-3.5 h-3.5 text-slate-900 shrink-0" />}
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Navegación principal */}
          <nav aria-label="Navegación principal" className="hidden lg:flex items-center gap-0.5">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeView === item.id && !activeProjectId;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveView(item.id)}
                  className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[13px] font-medium transition-colors cursor-pointer whitespace-nowrap ${
                    isActive
                      ? 'bg-slate-100 text-slate-900'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                  }`}
                >
                  <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-slate-900' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                  {item.id === 'ai' && aiPulseLabel && (
                    <span className="w-1.5 h-1.5 rounded-full bg-slate-900" title={aiPulseLabel} />
                  )}
                </button>
              );
            })}
          </nav>

          {/* Utilidades + Nuevo */}
          <div className="flex items-center gap-1.5 shrink-0">
            {onOpenPalette && (
              <button
                type="button"
                onClick={onOpenPalette}
                aria-label="Abrir búsqueda rápida"
                title={`Búsqueda rápida (${IS_MAC ? '⌘K' : 'Ctrl+K'})`}
                className="inline-flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 text-xs text-slate-500 transition-colors cursor-pointer"
              >
                <Search className="w-3.5 h-3.5 text-slate-400" />
                <kbd className="hidden sm:inline font-mono text-[10px] text-slate-400">{IS_MAC ? '⌘K' : 'Ctrl K'}</kbd>
              </button>
            )}

            <button
              type="button"
              onClick={() => setActiveView(aiPulseLabel ? 'ai' : 'global_logs')}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-medium transition-colors cursor-pointer ${
                activeView === 'global_logs' && !activeProjectId
                  ? 'bg-slate-100 border-slate-300 text-slate-900'
                  : 'bg-slate-50 hover:bg-slate-100 border-slate-200 text-slate-700'
              }`}
              title={aiPulseLabel ? `Última acción IA: ${aiPulseLabel}` : wsConnected ? 'En línea · abrir registros en vivo' : 'Reconectando con el servidor'}
            >
              <span className={`w-2 h-2 rounded-full shrink-0 ${wsConnected ? 'bg-emerald-500' : 'bg-red-500'}`} />
              {activeSyncCount > 0 ? (
                <span className="hidden sm:inline-flex items-center gap-1 text-slate-900 font-semibold tabular-nums">
                  <Zap className="w-3 h-3 text-amber-500" />
                  En vivo ({activeSyncCount})
                </span>
              ) : aiPulseLabel ? (
                <span className="hidden sm:inline text-slate-900 font-semibold max-w-[100px] truncate">IA activa</span>
              ) : (
                <span className="hidden sm:inline">{wsConnected ? 'Registros' : 'Reconectando…'}</span>
              )}
            </button>

            <button
              type="button"
              onClick={() => setActiveView('settings')}
              aria-label="Ajustes del servidor"
              title="Ajustes del servidor"
              className={`p-2 rounded-lg transition-colors cursor-pointer ${
                activeView === 'settings' && !activeProjectId
                  ? 'bg-slate-100 text-slate-900'
                  : 'text-slate-500 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              <Settings className="w-4 h-4" />
            </button>

            {/* Menú + Nuevo */}
            <div className="relative" ref={menuRef}>
              <button
                type="button"
                onClick={() => setMenuOpen((prev) => !prev)}
                aria-expanded={menuOpen}
                aria-haspopup="menu"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 transition-colors cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Nuevo</span>
                <ChevronDown className={`w-3.5 h-3.5 text-slate-300 transition-transform ${menuOpen ? 'rotate-180' : ''}`} />
              </button>

              {menuOpen && (
                <div
                  role="menu"
                  className="absolute right-0 mt-1.5 w-64 bg-white border border-slate-200 rounded-xl shadow-lg py-1.5 z-50"
                >
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => triggerAction('new_project')}
                    className="w-full px-3.5 py-2 text-left hover:bg-slate-50 flex items-start gap-2.5 transition-colors cursor-pointer"
                  >
                    <Rocket className="w-4 h-4 text-slate-600 mt-0.5 shrink-0" />
                    <div>
                      <div className="text-xs font-semibold text-slate-900">Nuevo proyecto</div>
                      <div className="text-[11px] text-slate-500">GitHub, URL Git o carpeta local</div>
                    </div>
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => triggerAction('wordpress')}
                    className="w-full px-3.5 py-2 text-left hover:bg-slate-50 flex items-start gap-2.5 transition-colors cursor-pointer"
                  >
                    <Globe className="w-4 h-4 text-slate-600 mt-0.5 shrink-0" />
                    <div>
                      <div className="text-xs font-semibold text-slate-900">Migrar WordPress</div>
                      <div className="text-[11px] text-slate-500">Analiza tu web y pásala sin cortes</div>
                    </div>
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => triggerAction('import')}
                    className="w-full px-3.5 py-2 text-left hover:bg-slate-50 flex items-start gap-2.5 transition-colors cursor-pointer"
                  >
                    <FileCode2 className="w-4 h-4 text-slate-600 mt-0.5 shrink-0" />
                    <div>
                      <div className="text-xs font-semibold text-slate-900">Importar proyecto</div>
                      <div className="text-[11px] text-slate-500">Coolify, Compose, Vercel, Netlify, Railway</div>
                    </div>
                  </button>
                  <div className="my-1 border-t border-slate-100" />
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => triggerAction('domain')}
                    className="w-full px-3.5 py-2 text-left hover:bg-slate-50 flex items-start gap-2.5 transition-colors cursor-pointer"
                  >
                    <Globe className="w-4 h-4 text-slate-600 mt-0.5 shrink-0" />
                    <div>
                      <div className="text-xs font-semibold text-slate-900">Conectar dominio</div>
                      <div className="text-[11px] text-slate-500">Asistente guiado con HTTPS automático</div>
                    </div>
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Navegación móvil/tablet */}
        <nav aria-label="Navegación móvil" className="flex lg:hidden overflow-x-auto no-scrollbar py-2 gap-1 border-t border-slate-100">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeView === item.id && !activeProjectId;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveView(item.id)}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap cursor-pointer ${
                  isActive
                    ? 'bg-slate-100 text-slate-900'
                    : 'text-slate-600 hover:bg-slate-50'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-slate-900' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
};
