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
  Terminal,
  Server,
  HeartPulse,
  Menu,
  X,
  Activity,
  Boxes,
  Sun,
  Moon,
} from 'lucide-react';
import { CulkiboLogo } from './CulkiboLogo';
import type { Project } from '../lib/api';
import { useI18n, type TranslationKey } from '../lib/i18n';
import { useTheme } from '../lib/theme';

const IS_MAC = typeof navigator !== 'undefined' && /mac|iphone|ipad/i.test(navigator.platform || navigator.userAgent || '');

export type AppView =
  | 'projects'
  | 'fleet'
  | 'uptime'
  | 'metrics'
  | 'import'
  | 'domains'
  | 'catalog'
  | 'ai'
  | 'global_logs'
  | 'settings';

export interface DaemonHeaderStats {
  memoryMb: number | null;
  latencyMs: number | null;
  version?: string | null;
  nodeVersion?: string | null;
  uptimeSeconds?: number | null;
}

interface HeaderProps {
  activeView: AppView;
  setActiveView: (view: AppView) => void;
  wsConnected: boolean;
  activeProjectId?: string | null;
  setActiveProjectId?: (id: string) => void;
  projects?: Project[];
  onQuickAction?: (action: 'new_project' | 'wordpress' | 'import' | 'domain') => void;
  onOpenPalette?: () => void;
  aiPulseLabel?: string | null;
  activeSyncCount?: number;
  daemonStats?: DaemonHeaderStats | null;
}

type NavEntry = {
  id: AppView;
  labelKey: TranslationKey;
  shortLabelKey?: TranslationKey;
  icon: React.ComponentType<{ className?: string }>;
  group: 'workspace' | 'infra' | 'system';
};

const NAV_ITEMS: NavEntry[] = [
  { id: 'projects', labelKey: 'nav.projects', icon: LayoutGrid, group: 'workspace' },
  { id: 'catalog', labelKey: 'nav.catalog', icon: Package, group: 'workspace' },
  { id: 'domains', labelKey: 'nav.domains', icon: Globe, group: 'workspace' },
  { id: 'ai', labelKey: 'nav.ai', shortLabelKey: 'nav.aiShort', icon: Bot, group: 'workspace' },
  { id: 'fleet', labelKey: 'nav.fleet', icon: Server, group: 'infra' },
  { id: 'metrics', labelKey: 'nav.metrics', icon: Gauge, group: 'infra' },
  { id: 'uptime', labelKey: 'nav.uptime', icon: HeartPulse, group: 'infra' },
  { id: 'import', labelKey: 'nav.import', icon: Download, group: 'infra' },
];

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
  daemonStats = null,
}) => {
  const { locale, toggleLocale, t } = useI18n();
  const { isDark, toggleTheme } = useTheme();
  const [menuOpen, setMenuOpen] = useState(false);
  const [projMenuOpen, setProjMenuOpen] = useState(false);
  const [mobileDrawerOpen, setMobileDrawerOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const projMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!menuOpen && !projMenuOpen && !mobileDrawerOpen) return;
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
        setMobileDrawerOpen(false);
      }
    };
    document.addEventListener('mousedown', onDocClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDocClick);
      document.removeEventListener('keydown', onKey);
    };
  }, [menuOpen, projMenuOpen, mobileDrawerOpen]);

  useEffect(() => {
    if (!mobileDrawerOpen) return;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = prevOverflow;
    };
  }, [mobileDrawerOpen]);

  const currentProject = activeProjectId ? projects.find((p) => p.id === activeProjectId) : null;

  const triggerAction = (action: 'new_project' | 'wordpress' | 'import' | 'domain' | 'catalog') => {
    setMenuOpen(false);
    setMobileDrawerOpen(false);
    if (action === 'catalog') {
      setActiveView('catalog');
      return;
    }
    if (onQuickAction) {
      onQuickAction(action);
      return;
    }
    if (action === 'domain') setActiveView('domains');
    else if (action === 'import' || action === 'wordpress') setActiveView('import');
    else setActiveView('projects');
  };

  const navigateFromDrawer = (view: AppView) => {
    setMobileDrawerOpen(false);
    setActiveView(view);
  };

  const hasRam = typeof daemonStats?.memoryMb === 'number' && Number.isFinite(daemonStats.memoryMb);
  const hasLatency = typeof daemonStats?.latencyMs === 'number' && Number.isFinite(daemonStats.latencyMs);
  const daemonTooltip = wsConnected
    ? [
        t('header.daemonOnline'),
        hasRam ? `RAM: ${Math.round(daemonStats!.memoryMb!)} MB` : null,
        hasLatency ? `RTT: ${Math.round(daemonStats!.latencyMs!)} ms` : null,
        daemonStats?.nodeVersion ? `Node ${daemonStats.nodeVersion}` : null,
        t('header.openLogsHint'),
      ]
        .filter(Boolean)
        .join(' · ')
    : t('header.reconnectingFull');

  return (
    <>
      <header className="sticky top-0 z-40 bg-white/92 backdrop-blur-md border-b border-slate-200/90">
        <div className="max-w-7xl mx-auto px-3 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-14 gap-2">
            {/* Left: Brand + Active project switcher */}
            <div className="flex items-center gap-2 min-w-0">
              <button
                type="button"
                className="culkibo-press shrink-0 inline-flex items-center gap-2 min-h-[44px] sm:min-h-[36px] px-1 rounded-lg cursor-pointer"
                onClick={() => setActiveView('projects')}
              >
                <CulkiboLogo size={26} />
                <span className="font-semibold text-[15px] text-slate-900 tracking-tight leading-none">
                  Culkibo
                </span>
              </button>

              {activeProjectId && projects.length > 0 && (
                <div className="hidden sm:flex items-center relative pl-0.5" ref={projMenuRef}>
                  <span aria-hidden="true" className="text-slate-300 text-sm select-none mr-1.5">/</span>
                  <button
                    type="button"
                    onClick={() => setProjMenuOpen((v) => !v)}
                    aria-expanded={projMenuOpen}
                    aria-haspopup="listbox"
                    className="culkibo-press inline-flex items-center gap-1.5 px-2 py-1.5 rounded-lg text-[13px] font-medium text-slate-900 hover:bg-slate-100 transition-colors cursor-pointer max-w-[155px]"
                  >
                    <span className="truncate">{currentProject?.name || t('projects.tableProject')}</span>
                    <ChevronDown
                      className={`w-3.5 h-3.5 text-slate-400 shrink-0 transition-transform duration-150 ${
                        projMenuOpen ? 'rotate-180' : ''
                      }`}
                    />
                  </button>
                  {projMenuOpen && (
                    <div
                      role="listbox"
                      aria-label={t('nav.projects')}
                      className="culkibo-modal-enter absolute left-2 top-full mt-1.5 w-60 max-h-72 overflow-y-auto bg-white border border-slate-200 rounded-xl shadow-lg p-1.5 z-50"
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
                            className={`w-full px-2.5 py-2 rounded-lg text-left text-xs flex items-center justify-between gap-2 transition-colors cursor-pointer ${
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

            {/* Center: 8 Desktop nav tabs — 100% unclipped at 1440px, 1280px & 1024px */}
            <nav
              aria-label="Primary navigation"
              className="hidden lg:flex items-center gap-0.5 min-w-0 shrink"
            >
              {NAV_ITEMS.map((item) => {
                const Icon = item.icon;
                const isActive = activeView === item.id && !activeProjectId;
                const label = t(item.labelKey);
                const shortLabel = item.shortLabelKey ? t(item.shortLabelKey) : null;
                return (
                  <button
                    key={item.id}
                    type="button"
                    aria-current={isActive ? 'page' : undefined}
                    onClick={() => setActiveView(item.id)}
                    className={`culkibo-press flex items-center gap-1 xl:gap-1.5 px-1.5 xl:px-2 py-1.5 rounded-lg text-xs xl:text-[12.5px] transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
                      isActive
                        ? 'bg-slate-100 text-slate-900 font-semibold'
                        : 'text-slate-600 font-medium hover:text-slate-900 hover:bg-slate-100/70'
                    }`}
                  >
                    <Icon
                      className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-slate-900' : 'text-slate-400'}`}
                    />
                    {shortLabel ? (
                      <>
                        <span className="2xl:hidden">{shortLabel}</span>
                        <span className="hidden 2xl:inline">{label}</span>
                      </>
                    ) : (
                      <span>{label}</span>
                    )}
                    {item.id === 'ai' && aiPulseLabel && (
                      <span
                        className="w-1.5 h-1.5 rounded-full bg-amber-500"
                        title={`AI Agent: ${aiPulseLabel}`}
                      />
                    )}
                  </button>
                );
              })}
            </nav>

            {/* Right: Cmd+K, EN/ES, Dark/Light, Daemon RAM pill, Settings, + New & Mobile Drawer */}
            <div className="flex items-center gap-1 shrink-0">
              {onOpenPalette && (
                <button
                  type="button"
                  onClick={onOpenPalette}
                  aria-label={t('header.searchAria')}
                  title={`${t('header.searchTitle')} (${IS_MAC ? '⌘K' : 'Ctrl+K'})`}
                  className="culkibo-press inline-flex items-center justify-center sm:justify-start gap-1.5 min-w-[44px] min-h-[44px] sm:min-w-0 sm:min-h-[32px] px-2 py-1 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200/90 text-xs text-slate-500 transition-colors cursor-pointer"
                >
                  <Search className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                  <kbd className="culkibo-kbd hidden sm:inline-flex items-center px-1.5 py-0.5 rounded bg-white border border-slate-200 text-[10px] font-medium text-slate-500 leading-none">
                    {IS_MAC ? '⌘K' : 'Ctrl K'}
                  </kbd>
                </button>
              )}

              {/* Instant EN / ES language toggle */}
              <button
                type="button"
                onClick={() => toggleLocale()}
                aria-label={t('header.langToggle')}
                title={t('header.langToggle')}
                className="culkibo-press hidden sm:inline-flex items-center justify-center min-w-[32px] h-8 px-1.5 rounded-lg border border-slate-200/90 bg-white hover:bg-slate-100 text-[11px] font-mono font-semibold text-slate-600 hover:text-slate-900 uppercase transition-colors cursor-pointer"
              >
                {locale}
              </button>

              {/* Instant Light / Dark theme toggle */}
              <button
                type="button"
                onClick={() => toggleTheme()}
                aria-label={isDark ? t('header.themeLight') : t('header.themeDark')}
                title={isDark ? t('header.themeLight') : t('header.themeDark')}
                className="culkibo-press hidden sm:inline-flex items-center justify-center w-8 h-8 rounded-lg border border-slate-200/90 bg-white hover:bg-slate-100 text-slate-500 hover:text-slate-900 transition-colors cursor-pointer"
              >
                {isDark ? <Sun className="w-3.5 h-3.5 text-amber-400" /> : <Moon className="w-3.5 h-3.5" />}
              </button>

              {/* Live daemon telemetry pill */}
              <button
                type="button"
                onClick={() => setActiveView('global_logs')}
                aria-current={activeView === 'global_logs' && !activeProjectId ? 'page' : undefined}
                aria-label={daemonTooltip}
                title={daemonTooltip}
                className={`culkibo-press hidden md:inline-flex items-center gap-1.5 h-8 px-2 rounded-lg border text-xs font-medium transition-colors cursor-pointer tabular-nums ${
                  activeView === 'global_logs' && !activeProjectId
                    ? 'bg-slate-100 border-slate-300 text-slate-900'
                    : 'bg-white hover:bg-slate-50 border-slate-200/90 text-slate-700'
                }`}
              >
                <span
                  className={`w-2 h-2 rounded-full shrink-0 ${
                    wsConnected ? 'bg-emerald-500 culkibo-dot-live' : 'bg-red-500'
                  }`}
                />
                {activeSyncCount > 0 ? (
                  <span className="inline-flex items-center gap-1 text-slate-900 font-semibold">
                    <Zap className="w-3 h-3 text-amber-500 shrink-0" />
                    <span>{activeSyncCount}</span>
                  </span>
                ) : !wsConnected ? (
                  <span className="hidden 2xl:inline text-red-700">{t('header.reconnecting')}</span>
                ) : hasRam ? (
                  <span className="hidden xl:inline-flex items-center gap-1 font-mono text-[11px] text-slate-600">
                    <span>{Math.round(daemonStats!.memoryMb!)} MB</span>
                    {hasLatency && (
                      <span className="hidden 2xl:inline text-emerald-700">· {Math.round(daemonStats!.latencyMs!)}ms</span>
                    )}
                  </span>
                ) : (
                  <span className="hidden 2xl:inline text-slate-600">{t('header.daemonOnlineShort')}</span>
                )}
              </button>

              <button
                type="button"
                onClick={() => setActiveView('settings')}
                aria-current={activeView === 'settings' && !activeProjectId ? 'page' : undefined}
                aria-label={t('nav.settings')}
                title={t('header.settingsTitle')}
                className={`culkibo-press hidden sm:inline-flex items-center justify-center w-8 h-8 rounded-lg transition-colors cursor-pointer ${
                  activeView === 'settings' && !activeProjectId
                    ? 'bg-slate-100 text-slate-900'
                    : 'text-slate-500 hover:text-slate-900 hover:bg-slate-100/70'
                }`}
              >
                <Settings className="w-4 h-4" />
              </button>

              {/* + New primary action */}
              <div className="relative" ref={menuRef}>
                <button
                  type="button"
                  onClick={() => setMenuOpen((prev) => !prev)}
                  aria-expanded={menuOpen}
                  aria-haspopup="menu"
                  className="culkibo-press inline-flex items-center gap-1 min-h-[44px] sm:min-h-[32px] px-2.5 sm:px-3 py-1 rounded-lg text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 shadow-xs cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5 shrink-0" />
                  <span>{t('header.new')}</span>
                  <ChevronDown
                    className={`w-3.5 h-3.5 text-slate-300 transition-transform duration-150 ${
                      menuOpen ? 'rotate-180' : ''
                    }`}
                  />
                </button>

                {menuOpen && (
                  <div
                    role="menu"
                    className="culkibo-modal-enter absolute right-0 mt-1.5 w-72 bg-white border border-slate-200 rounded-xl shadow-xl p-1.5 z-50"
                  >
                    <button
                      type="button"
                      role="menuitem"
                      onClick={() => triggerAction('new_project')}
                      className="w-full px-3 py-2.5 rounded-lg text-left hover:bg-slate-50 flex items-start gap-2.5 transition-colors cursor-pointer"
                    >
                      <Rocket className="w-4 h-4 text-slate-700 mt-0.5 shrink-0" />
                      <div className="min-w-0">
                        <div className="text-xs font-semibold text-slate-900">{t('header.newDeployGit')}</div>
                        <div className="text-[11px] text-slate-500">{t('header.newDeployGitDesc')}</div>
                      </div>
                    </button>
                    <button
                      type="button"
                      role="menuitem"
                      onClick={() => triggerAction('import')}
                      className="w-full px-3 py-2.5 rounded-lg text-left hover:bg-slate-50 flex items-start gap-2.5 transition-colors cursor-pointer"
                    >
                      <FileCode2 className="w-4 h-4 text-slate-700 mt-0.5 shrink-0" />
                      <div className="min-w-0">
                        <div className="text-xs font-semibold text-slate-900">{t('header.newImport')}</div>
                        <div className="text-[11px] text-slate-500">{t('header.newImportDesc')}</div>
                      </div>
                    </button>
                    <button
                      type="button"
                      role="menuitem"
                      onClick={() => triggerAction('catalog')}
                      className="w-full px-3 py-2.5 rounded-lg text-left hover:bg-slate-50 flex items-start gap-2.5 transition-colors cursor-pointer"
                    >
                      <Boxes className="w-4 h-4 text-slate-700 mt-0.5 shrink-0" />
                      <div className="min-w-0">
                        <div className="text-xs font-semibold text-slate-900">{t('header.newCatalog')}</div>
                        <div className="text-[11px] text-slate-500">{t('header.newCatalogDesc')}</div>
                      </div>
                    </button>
                    <div className="my-1 border-t border-slate-100" />
                    <button
                      type="button"
                      role="menuitem"
                      onClick={() => triggerAction('wordpress')}
                      className="w-full px-3 py-2.5 rounded-lg text-left hover:bg-slate-50 flex items-start gap-2.5 transition-colors cursor-pointer"
                    >
                      <Globe className="w-4 h-4 text-slate-700 mt-0.5 shrink-0" />
                      <div className="min-w-0">
                        <div className="text-xs font-semibold text-slate-900">{t('header.newWordpress')}</div>
                        <div className="text-[11px] text-slate-500">{t('header.newWordpressDesc')}</div>
                      </div>
                    </button>
                    <button
                      type="button"
                      role="menuitem"
                      onClick={() => triggerAction('domain')}
                      className="w-full px-3 py-2.5 rounded-lg text-left hover:bg-slate-50 flex items-start gap-2.5 transition-colors cursor-pointer"
                    >
                      <Globe className="w-4 h-4 text-slate-700 mt-0.5 shrink-0" />
                      <div className="min-w-0">
                        <div className="text-xs font-semibold text-slate-900">{t('header.newDomain')}</div>
                        <div className="text-[11px] text-slate-500">{t('header.newDomainDesc')}</div>
                      </div>
                    </button>
                  </div>
                )}
              </div>

              {/* Mobile drawer toggle (>=44x44px touch target) */}
              <button
                type="button"
                onClick={() => setMobileDrawerOpen(true)}
                aria-label="Open navigation menu"
                aria-expanded={mobileDrawerOpen}
                aria-controls="mobile-nav-drawer"
                className="culkibo-press lg:hidden inline-flex items-center justify-center w-11 h-11 rounded-lg text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
              >
                <Menu className="w-5 h-5" />
              </button>
            </div>
          </div>

          {/* Mobile compact breadcrumb inside a project */}
          {activeProjectId && currentProject && (
            <div className="flex sm:hidden items-center justify-between gap-2 py-1.5 border-t border-slate-100 text-xs">
              <button
                type="button"
                onClick={() => setActiveView('projects')}
                className="text-slate-500 hover:text-slate-900 font-medium cursor-pointer shrink-0"
              >
                {t('header.backProjects')}
              </button>
              <span className="font-semibold text-slate-900 truncate">{currentProject.name}</span>
            </div>
          )}
        </div>
      </header>

      {/* Mobile slide-over drawer (>=44px touch targets, 0px horizontal overflow) */}
      {mobileDrawerOpen && (
        <div
          className="fixed inset-0 z-50 lg:hidden flex justify-end bg-slate-950/40 backdrop-blur-[2px]"
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) setMobileDrawerOpen(false);
          }}
        >
          <div
            id="mobile-nav-drawer"
            role="dialog"
            aria-modal="true"
            aria-label="Navigation menu"
            className="culkibo-drawer-enter w-full max-w-[320px] h-full bg-white shadow-2xl border-l border-slate-200 flex flex-col overflow-hidden"
          >
            <div className="px-4 h-14 border-b border-slate-200 flex items-center justify-between shrink-0">
              <div className="flex items-center gap-2">
                <CulkiboLogo size={24} />
                <span className="font-semibold text-sm text-slate-900 tracking-tight">Culkibo</span>
              </div>
              <button
                type="button"
                onClick={() => setMobileDrawerOpen(false)}
                aria-label="Close menu"
                className="inline-flex items-center justify-center w-11 h-11 rounded-lg text-slate-500 hover:text-slate-900 hover:bg-slate-100 cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Live daemon telemetry + quick EN/ES & Theme controls */}
            <div className="px-4 py-3 bg-slate-50/80 border-b border-slate-200/80 space-y-2.5 text-xs">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                  <span
                    className={`w-2 h-2 rounded-full shrink-0 ${
                      wsConnected ? 'bg-emerald-500 culkibo-dot-live' : 'bg-red-500'
                    }`}
                  />
                  <span className="font-medium text-slate-800 truncate">
                    {wsConnected ? t('header.daemonOnline') : t('header.reconnecting')}
                  </span>
                </div>
                <span className="font-mono text-[11px] text-slate-500 tabular-nums shrink-0">
                  {hasRam ? `${Math.round(daemonStats!.memoryMb!)} MB` : '—'}
                  {hasLatency ? ` · ${Math.round(daemonStats!.latencyMs!)}ms` : ''}
                </span>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => toggleTheme()}
                  className="min-h-[44px] px-3 rounded-xl bg-white border border-slate-200 flex items-center justify-center gap-2 text-xs font-medium text-slate-700 cursor-pointer"
                >
                  {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-slate-500" />}
                  <span>{isDark ? t('settings.themeLight') : t('settings.themeDark')}</span>
                </button>
                <button
                  type="button"
                  onClick={() => toggleLocale()}
                  className="min-h-[44px] px-3 rounded-xl bg-white border border-slate-200 flex items-center justify-center gap-2 text-xs font-medium text-slate-700 font-mono uppercase cursor-pointer"
                >
                  <span>{locale === 'en' ? 'EN → ES' : 'ES → EN'}</span>
                </button>
              </div>
            </div>

            <nav aria-label="Mobile navigation" className="flex-1 overflow-y-auto px-3 py-3 space-y-4">
              {onOpenPalette && (
                <button
                  type="button"
                  onClick={() => {
                    setMobileDrawerOpen(false);
                    onOpenPalette();
                  }}
                  className="w-full min-h-[44px] px-3 rounded-xl bg-slate-100/90 hover:bg-slate-100 border border-slate-200/80 flex items-center justify-between text-xs text-slate-600 cursor-pointer"
                >
                  <span className="inline-flex items-center gap-2">
                    <Search className="w-4 h-4 text-slate-400" />
                    <span>{t('header.drawerSearch')}</span>
                  </span>
                  <kbd className="culkibo-kbd px-1.5 py-0.5 rounded bg-white border border-slate-200 text-[10px] text-slate-500">
                    {IS_MAC ? '⌘K' : 'Ctrl K'}
                  </kbd>
                </button>
              )}

              <div>
                <div className="px-2 pb-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                  {t('header.drawerWorkspace')}
                </div>
                <div className="space-y-0.5">
                  {NAV_ITEMS.filter((i) => i.group === 'workspace').map((item) => {
                    const Icon = item.icon;
                    const isActive = activeView === item.id && !activeProjectId;
                    return (
                      <button
                        key={item.id}
                        type="button"
                        aria-current={isActive ? 'page' : undefined}
                        onClick={() => navigateFromDrawer(item.id)}
                        className={`w-full min-h-[44px] px-3 rounded-xl flex items-center justify-between text-sm transition-colors cursor-pointer ${
                          isActive
                            ? 'bg-slate-900 text-white font-medium'
                            : 'text-slate-700 hover:bg-slate-100'
                        }`}
                      >
                        <span className="inline-flex items-center gap-2.5">
                          <Icon className={`w-4 h-4 ${isActive ? 'text-white' : 'text-slate-400'}`} />
                          <span>{t(item.labelKey)}</span>
                        </span>
                        {item.id === 'ai' && aiPulseLabel && (
                          <span className="w-2 h-2 rounded-full bg-amber-400" />
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>

              <div>
                <div className="px-2 pb-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                  {t('header.drawerInfra')}
                </div>
                <div className="space-y-0.5">
                  {NAV_ITEMS.filter((i) => i.group === 'infra').map((item) => {
                    const Icon = item.icon;
                    const isActive = activeView === item.id && !activeProjectId;
                    return (
                      <button
                        key={item.id}
                        type="button"
                        aria-current={isActive ? 'page' : undefined}
                        onClick={() => navigateFromDrawer(item.id)}
                        className={`w-full min-h-[44px] px-3 rounded-xl flex items-center gap-2.5 text-sm transition-colors cursor-pointer ${
                          isActive
                            ? 'bg-slate-900 text-white font-medium'
                            : 'text-slate-700 hover:bg-slate-100'
                        }`}
                      >
                        <Icon className={`w-4 h-4 ${isActive ? 'text-white' : 'text-slate-400'}`} />
                        <span>{t(item.labelKey)}</span>
                      </button>
                    );
                  })}
                </div>
              </div>

              <div>
                <div className="px-2 pb-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                  {t('header.drawerOps')}
                </div>
                <div className="space-y-0.5">
                  <button
                    type="button"
                    aria-current={activeView === 'global_logs' && !activeProjectId ? 'page' : undefined}
                    onClick={() => navigateFromDrawer('global_logs')}
                    className={`w-full min-h-[44px] px-3 rounded-xl flex items-center justify-between text-sm transition-colors cursor-pointer ${
                      activeView === 'global_logs' && !activeProjectId
                        ? 'bg-slate-900 text-white font-medium'
                        : 'text-slate-700 hover:bg-slate-100'
                    }`}
                  >
                    <span className="inline-flex items-center gap-2.5">
                      <Terminal className={`w-4 h-4 ${activeView === 'global_logs' ? 'text-white' : 'text-slate-400'}`} />
                      <span>{t('nav.logs')}</span>
                    </span>
                    {activeSyncCount > 0 && (
                      <span className="px-1.5 py-0.5 rounded-full bg-amber-100 text-amber-900 text-[11px] font-mono tabular-nums">
                        {activeSyncCount} sync
                      </span>
                    )}
                  </button>
                  <button
                    type="button"
                    aria-current={activeView === 'settings' && !activeProjectId ? 'page' : undefined}
                    onClick={() => navigateFromDrawer('settings')}
                    className={`w-full min-h-[44px] px-3 rounded-xl flex items-center gap-2.5 text-sm transition-colors cursor-pointer ${
                      activeView === 'settings' && !activeProjectId
                        ? 'bg-slate-900 text-white font-medium'
                        : 'text-slate-700 hover:bg-slate-100'
                    }`}
                  >
                    <Settings className={`w-4 h-4 ${activeView === 'settings' ? 'text-white' : 'text-slate-400'}`} />
                    <span>{t('header.drawerSettings')}</span>
                  </button>
                </div>
              </div>
            </nav>

            <div className="p-3 border-t border-slate-200 bg-slate-50/70 flex items-center justify-between text-[11px] text-slate-500 shrink-0">
              <span className="inline-flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-slate-400" />
                <span>Culkibo v{daemonStats?.version || '1.1.0'}</span>
              </span>
              <span>Zero-Shell · Apache-2.0</span>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
