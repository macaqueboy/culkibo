import React, { useState, useEffect, useMemo, useDeferredValue } from 'react';
import {
  Search,
  Plus,
  Download,
  Globe,
  ExternalLink,
  GitBranch,
  Zap,
  Lock,
  ArrowRight,
  LayoutGrid,
  List,
  X,
  Boxes,
  RefreshCw,
  Play,
  Square,
  Loader2,
  PauseCircle,
  Rocket,
  Terminal,
  Cpu,
  Database,
  Copy,
  Check,
  Bot,
  Sparkles,
} from 'lucide-react';
import { api, type Project } from '../lib/api';
import { copyToClipboard } from '../lib/clipboard';
import { useI18n, type Locale } from '../lib/i18n';
import { CreateProjectModal } from './CreateProjectModal';
import { OnboardingChecklist } from './OnboardingChecklist';

interface ProjectListProps {
  onSelectProject: (id: string, tab?: string | null) => void;
  onImportCoolify: () => void;
  onOpenWordPress?: () => void;
  onOpenCatalog?: () => void;
  onOpenDomains?: () => void;
  onOpenAi?: () => void;
  onOpenSecurity?: () => void;
  projects?: Project[];
  projectsLoading?: boolean;
  onRefreshProjects?: () => void;
  onNotify?: (msg: string, type?: 'info' | 'success' | 'error') => void;
  externalCreateTrigger?: number;
  checklistRestoreTick?: number;
}

function isProjectActuallyActive(p: Project): boolean {
  return Boolean(!p.maintenanceMode && ((p.lastDeployedAt && p.status === 'active') || p.localRunning));
}

interface ProjectMetadata {
  cleanGit: string | null;
  monogram: string;
  branch: string | null;
  totalDbs: number;
  ramLabel: string | null;
  cpuLabel: string | null;
  shortCommit: string | null;
  lastDeployShort: string | null;
  summaryTag: string;
}

function getProjectMetadata(p: Project, locale: Locale): ProjectMetadata {
  let rawGit = p.gitRepo || '';
  if (!rawGit && p.resources && Array.isArray(p.resources)) {
    const resWithGit = p.resources.find((r: { gitRepo?: string }) => Boolean(r?.gitRepo));
    if (resWithGit?.gitRepo) rawGit = resWithGit.gitRepo;
  }

  const cleanGit = rawGit
    ? rawGit
        .replace(/^git@[^:]+:/, '')
        .replace(/^https?:\/\/[^/]+\//, '')
        .replace(/\.git$/, '')
    : null;

  const words = (p.name || 'PR')
    .replace(/[^a-zA-Z0-9\s-]/g, ' ')
    .split(/[\s-]+/)
    .filter(Boolean);
  const monogram = words.length >= 2
    ? `${words[0][0]}${words[1][0]}`.toUpperCase()
    : (words[0] || 'PR').slice(0, 2).toUpperCase();

  const linkedDbs = Array.isArray(p.linkedDatabaseIds) ? p.linkedDatabaseIds.length : 0;
  const embeddedDbs = (p.resources || []).filter((r: { type?: string }) => r?.type === 'database').length;
  const totalDbs = linkedDbs + embeddedDbs;

  const ramLabel = typeof p.memoryMb === 'number' && p.memoryMb > 0
    ? p.memoryMb >= 1024
      ? `${(p.memoryMb / 1024).toFixed(p.memoryMb % 1024 === 0 ? 0 : 1)} GB`
      : `${p.memoryMb} MB`
    : null;
  const cpuLabel = p.cpus !== undefined && p.cpus !== null && String(p.cpus).trim() !== ''
    ? `${p.cpus} vCPU`
    : null;
  const shortCommit = p.lastCommit?.sha ? p.lastCommit.sha.slice(0, 7) : null;
  const dateLocale = locale === 'es' ? 'es-ES' : 'en-US';
  const lastDeployShort = p.lastDeployedAt
    ? new Date(p.lastDeployedAt).toLocaleDateString(dateLocale, { day: '2-digit', month: 'short' })
    : null;

  const parts: string[] = [];
  if (p.gitBranch) parts.push(p.gitBranch);
  if (ramLabel) parts.push(ramLabel);
  if (totalDbs > 0) parts.push(`${totalDbs} DB`);
  if (lastDeployShort) parts.push(lastDeployShort);
  const summaryTag = parts.join(' · ') || (locale === 'es' ? 'Sin desplegar todavía' : 'Not deployed yet');

  return {
    cleanGit,
    monogram,
    branch: p.gitBranch || null,
    totalDbs,
    ramLabel,
    cpuLabel,
    shortCommit,
    lastDeployShort,
    summaryTag,
  };
}

export const ProjectList: React.FC<ProjectListProps> = ({
  onSelectProject,
  onImportCoolify,
  onOpenWordPress,
  onOpenCatalog,
  onOpenDomains,
  onOpenAi,
  onOpenSecurity,
  projects: parentProjects,
  projectsLoading,
  onRefreshProjects,
  onNotify,
  externalCreateTrigger,
  checklistRestoreTick = 0,
}) => {
  const { t, locale } = useI18n();
  const [localProjects, setLocalProjects] = useState<Project[]>(() => (Array.isArray(parentProjects) ? parentProjects : []));
  const [loading, setLoading] = useState<boolean>(() => !Array.isArray(parentProjects));
  const [startingLocalId, setStartingLocalId] = useState<string | null>(null);
  const [stoppingLocalId, setStoppingLocalId] = useState<string | null>(null);
  const [deployingId, setDeployingId] = useState<string | null>(null);
  const [copiedDomainId, setCopiedDomainId] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const deferredSearch = useDeferredValue(search);
  const [filter, setFilter] = useState<'all' | 'active' | 'hibernated' | 'local'>('all');
  const [view, setView] = useState<'grid' | 'table'>('grid');
  const [sortBy, setSortBy] = useState<'recent' | 'name' | 'domains' | 'status'>('recent');
  const [showCreateModal, setShowCreateModal] = useState(false);

  const [prevCreateTrigger, setPrevCreateTrigger] = useState(externalCreateTrigger);
  if (externalCreateTrigger !== prevCreateTrigger) {
    setPrevCreateTrigger(externalCreateTrigger);
    if (externalCreateTrigger && externalCreateTrigger > 0) {
      setShowCreateModal(true);
    }
  }

  const [prevParentProjects, setPrevParentProjects] = useState(parentProjects);
  if (parentProjects !== prevParentProjects) {
    setPrevParentProjects(parentProjects);
    if (Array.isArray(parentProjects)) {
      setLocalProjects(parentProjects);
      setLoading(false);
    }
  }

  const fetchProjects = () => {
    if (onRefreshProjects) {
      onRefreshProjects();
      return;
    }
    setLoading(true);
    api.getProjects()
      .then((data) => {
        setLocalProjects(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error(err);
        setLoading(false);
      });
  };

  useEffect(() => {
    let active = true;
    if (!Array.isArray(parentProjects)) {
      api.getProjects()
        .then((data) => {
          if (!active) return;
          setLocalProjects(data);
          setLoading(false);
        })
        .catch((err) => {
          console.error(err);
          if (active) setLoading(false);
        });
    }

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === '/' && !e.metaKey && !e.ctrlKey && !e.altKey) {
        const tag = (e.target as HTMLElement | null)?.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
        e.preventDefault();
        document.getElementById('omnibar')?.focus();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      active = false;
      window.removeEventListener('keydown', handleKeyDown);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const previewHost = typeof window !== 'undefined' ? window.location.hostname : 'localhost';

  const getHonestStatus = (p: Project): {
    label: string;
    pillClass: string;
    dotClass: string;
    isLive?: boolean;
    isMaintenance?: boolean;
  } => {
    if (p.maintenanceMode) {
      return {
        label: t('projects.statusMaintenance'),
        pillClass: 'bg-amber-50 text-amber-800 border-amber-200',
        dotClass: 'bg-amber-500',
        isMaintenance: true,
      };
    }
    if (p.lastDeployedAt && p.status === 'active') {
      return {
        label: t('projects.statusLive'),
        pillClass: 'bg-emerald-50 text-emerald-700 border-emerald-200',
        dotClass: 'bg-emerald-500',
        isLive: true,
      };
    }
    if (p.localRunning) {
      return {
        label: p.localPort ? `${t('projects.statusLocal')} :${p.localPort}` : t('projects.statusLocal'),
        pillClass: 'bg-amber-50 text-amber-800 border-amber-200',
        dotClass: 'bg-amber-500',
      };
    }
    if (p.status === 'hibernated' || p.status === 'sleeping') {
      return {
        label: t('projects.statusHibernated'),
        pillClass: 'bg-slate-100 text-slate-600 border-slate-200',
        dotClass: 'bg-slate-400',
      };
    }
    if (p.status === 'stopped') {
      return {
        label: t('projects.statusStopped'),
        pillClass: 'bg-slate-100 text-slate-600 border-slate-200',
        dotClass: 'bg-slate-400',
      };
    }
    return {
      label: t('projects.statusReady'),
      pillClass: 'bg-slate-100 text-slate-600 border-slate-200',
      dotClass: 'bg-slate-400',
    };
  };

  const handleStartLocal = async (id: string) => {
    try {
      setStartingLocalId(id);
      const res = await api.startLocal(id);
      fetchProjects();
      const port = res?.localPort;
      onNotify?.(
        port ? `Started at http://${previewHost}:${port}` : 'Project started locally',
        'success'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error starting local preview';
      onNotify?.(msg, 'error');
      fetchProjects();
    } finally {
      setStartingLocalId(null);
    }
  };

  const handleStopLocal = async (id: string) => {
    try {
      setStoppingLocalId(id);
      await api.stopProject(id);
      fetchProjects();
      onNotify?.(locale === 'es' ? 'Proyecto detenido y puerto liberado' : 'Project stopped and port released', 'info');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error stopping project';
      onNotify?.(msg, 'error');
      fetchProjects();
    } finally {
      setStoppingLocalId(null);
    }
  };

  const handleQuickDeploy = async (p: Project) => {
    try {
      setDeployingId(p.id);
      await api.startDeploy(p.id);
      onNotify?.(
        locale === 'es' ? `Despliegue iniciado para ${p.name}` : `Deployment started for ${p.name}`,
        'success'
      );
      onSelectProject(p.id, 'deploy');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Could not start deployment';
      onNotify?.(msg, 'error');
    } finally {
      setDeployingId(null);
    }
  };

  const handleCopyDomain = async (id: string, domain: string) => {
    const ok = await copyToClipboard(`https://${domain}`);
    if (!ok) return;
    setCopiedDomainId(id);
    window.setTimeout(() => setCopiedDomainId(null), 1600);
    onNotify?.(`URL copied: https://${domain}`, 'success');
  };

  const projects = localProjects;

  const metadataMap = useMemo(() => {
    const map = new Map<string, ProjectMetadata>();
    for (const p of projects) {
      map.set(p.id, getProjectMetadata(p, locale));
    }
    return map;
  }, [projects, locale]);

  const stats = useMemo(() => {
    const total = projects.length;
    const active = projects.filter(isProjectActuallyActive).length;
    const inactive = total - active;
    const local = projects.filter((p) => p.localRunning).length;
    const totalDomains = projects.reduce((acc, p) => acc + (p.domains?.length || 0), 0);
    return { total, active, inactive, local, totalDomains };
  }, [projects]);

  const filtered = useMemo(() => {
    const q = deferredSearch.trim().toLowerCase();
    return projects
      .filter((p) => {
        if (filter === 'active' && !isProjectActuallyActive(p)) return false;
        if (filter === 'hibernated' && isProjectActuallyActive(p)) return false;
        if (filter === 'local' && !p.localRunning) return false;

        if (q) {
          const meta = metadataMap.get(p.id) || getProjectMetadata(p, locale);
          const matchName = (p.name || '').toLowerCase().includes(q);
          const matchDesc = (p.description || '').toLowerCase().includes(q);
          const matchDomain = p.domains?.some((d) => d.toLowerCase().includes(q));
          const matchGit = (p.gitRepo || '').toLowerCase().includes(q) || (meta.cleanGit || '').toLowerCase().includes(q);
          if (!matchName && !matchDesc && !matchDomain && !matchGit) return false;
        }
        return true;
      })
      .sort((a, b) => {
        if (sortBy === 'name') return a.name.localeCompare(b.name);
        if (sortBy === 'domains') return (b.domains?.length || 0) - (a.domains?.length || 0);
        if (sortBy === 'status') {
          const aAct = isProjectActuallyActive(a);
          const bAct = isProjectActuallyActive(b);
          if (aAct === bAct) return 0;
          return aAct ? -1 : 1;
        }
        return new Date(b.updatedAt || b.createdAt || 0).getTime() - new Date(a.updatedAt || a.createdAt || 0).getTime();
      });
  }, [projects, metadataMap, locale, filter, deferredSearch, sortBy]);

  const isLoading = loading || Boolean(projectsLoading);

  const summaryLine = locale === 'es'
    ? `${stats.total} ${stats.total === 1 ? 'proyecto' : 'proyectos'} · ${stats.active} ${stats.active === 1 ? 'activo' : 'activos'} · ${stats.totalDomains} ${stats.totalDomains === 1 ? 'dominio' : 'dominios'}${stats.local > 0 ? ` · ${stats.local} en local` : ''}`
    : `${stats.total} ${stats.total === 1 ? 'project' : 'projects'} · ${stats.active} active · ${stats.totalDomains} ${stats.totalDomains === 1 ? 'domain' : 'domains'}${stats.local > 0 ? ` · ${stats.local} local` : ''}`;

  return (
    <div className="space-y-5">
      {/* Page header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">{t('projects.title')}</h1>
          <p className="text-sm text-slate-500 mt-1 tabular-nums">
            {isLoading && projects.length === 0
              ? t('projects.loading')
              : stats.total === 0
                ? t('projects.emptySubtitle')
                : summaryLine}
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0 flex-wrap">
          <button
            type="button"
            onClick={onImportCoolify}
            className="culkibo-press inline-flex items-center gap-1.5 min-h-[44px] sm:min-h-[36px] px-3.5 py-2 rounded-lg text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-200 shadow-2xs cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-slate-500" />
            <span>{t('projects.importBtn')}</span>
          </button>

          <button
            type="button"
            onClick={() => setShowCreateModal(true)}
            className="culkibo-press inline-flex items-center gap-1.5 min-h-[44px] sm:min-h-[36px] px-3.5 py-2 rounded-lg text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 shadow-xs cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{t('projects.newBtn')}</span>
          </button>
        </div>
      </div>

      {/* Quick-start strip */}
      <OnboardingChecklist
        projectsCount={stats.total}
        domainsCount={stats.totalDomains}
        onCreateProject={() => setShowCreateModal(true)}
        onOpenWordPress={onOpenWordPress || onImportCoolify}
        onOpenImport={onImportCoolify}
        onOpenCatalog={onOpenCatalog || onImportCoolify}
        onOpenDomains={onOpenDomains || (() => {})}
        onOpenAi={onOpenAi || (() => {})}
        onOpenSecurity={onOpenSecurity}
        onNotify={onNotify}
        restoreTick={checklistRestoreTick}
      />

      {/* Search & filters */}
      {projects.length > 0 && (
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-2.5">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
            <input
              id="omnibar"
              type="text"
              placeholder={t('projects.searchPlaceholder')}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full min-h-[44px] sm:min-h-[36px] pl-9 pr-10 py-1.5 bg-white border border-slate-200 rounded-lg text-sm text-slate-900 placeholder:text-slate-400"
            />
            {search ? (
              <button
                type="button"
                onClick={() => setSearch('')}
                aria-label="Clear search"
                className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 text-slate-400 hover:text-slate-700 rounded cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            ) : (
              <kbd className="culkibo-kbd hidden sm:inline-flex items-center absolute right-2.5 top-1/2 -translate-y-1/2 px-1.5 py-0.5 text-[10px] font-medium text-slate-400 bg-slate-50 border border-slate-200 rounded">
                /
              </kbd>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2 justify-between lg:justify-end">
            <div className="flex items-center bg-slate-100 p-0.5 rounded-lg border border-slate-200/90 text-xs overflow-x-auto no-scrollbar max-w-full">
              {([
                { id: 'all', label: `${t('projects.filterAll')} (${stats.total})` },
                { id: 'active', label: `${t('projects.filterActive')} (${stats.active})` },
                { id: 'local', label: `${t('projects.filterLocal')} (${stats.local})` },
                { id: 'hibernated', label: `${t('projects.filterStopped')} (${stats.inactive})` },
              ] as const).map((pill) => (
                <button
                  key={pill.id}
                  type="button"
                  onClick={() => setFilter(pill.id)}
                  className={`px-2.5 py-1.5 sm:py-1 rounded-md font-medium transition-colors cursor-pointer whitespace-nowrap tabular-nums ${
                    filter === pill.id
                      ? 'bg-white text-slate-900 shadow-2xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {pill.label}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-2">
              <select
                aria-label="Sort projects"
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as 'recent' | 'name' | 'domains' | 'status')}
                className="bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-medium rounded-lg px-2.5 py-1.5 min-h-[36px] cursor-pointer"
              >
                <option value="recent">{t('projects.sortRecent')}</option>
                <option value="name">{t('projects.sortName')}</option>
                <option value="domains">{t('projects.sortDomains')}</option>
                <option value="status">{t('projects.sortStatus')}</option>
              </select>

              <div className="flex bg-slate-100 p-0.5 rounded-lg border border-slate-200/90">
                <button
                  type="button"
                  onClick={() => setView('grid')}
                  aria-label="Grid view"
                  title="Grid view"
                  className={`p-1.5 rounded-md transition-colors cursor-pointer ${
                    view === 'grid' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-400 hover:text-slate-700'
                  }`}
                >
                  <LayoutGrid className="w-3.5 h-3.5" />
                </button>
                <button
                  type="button"
                  onClick={() => setView('table')}
                  aria-label="Table view"
                  title="Table view"
                  className={`p-1.5 rounded-md transition-colors cursor-pointer ${
                    view === 'table' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-400 hover:text-slate-700'
                  }`}
                >
                  <List className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Project list */}
      {isLoading && projects.length === 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <div
              key={i}
              className="bg-white border border-slate-200 rounded-2xl p-5 h-[204px] animate-pulse space-y-4"
            >
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-slate-200/80" />
                <div className="space-y-2 flex-1">
                  <div className="h-3.5 w-28 rounded bg-slate-200/80" />
                  <div className="h-3 w-40 rounded bg-slate-100" />
                </div>
              </div>
              <div className="h-7 w-44 rounded-lg bg-slate-100" />
              <div className="h-3 w-36 rounded bg-slate-100" />
            </div>
          ))}
        </div>
      ) : filtered.length > 0 && view === 'grid' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 items-stretch">
          {filtered.map((p) => {
            const meta = metadataMap.get(p.id) || getProjectMetadata(p, locale);
            const isStartingThisLocal = startingLocalId === p.id;
            const isDeployingThis = deployingId === p.id;
            const statusMeta = getHonestStatus(p);

            return (
              <article
                key={p.id}
                className="culkibo-card group rounded-2xl p-4 flex flex-col justify-between gap-4 min-w-0"
              >
                <div className="space-y-3 min-w-0">
                  <div className="flex items-start justify-between gap-2.5">
                    <button
                      type="button"
                      onClick={() => onSelectProject(p.id)}
                      className="flex items-center gap-3 min-w-0 text-left cursor-pointer group/title"
                    >
                      <span
                        aria-hidden="true"
                        className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0 bg-slate-900 text-white text-xs font-semibold tracking-tight font-mono shadow-2xs"
                      >
                        {meta.monogram}
                      </span>
                      <span className="min-w-0">
                        <span className="block text-sm font-semibold text-slate-900 group-hover/title:underline tracking-tight truncate">
                          {p.name}
                        </span>
                        <span className="flex items-center gap-1 text-xs text-slate-500 font-mono mt-0.5 truncate">
                          {meta.cleanGit ? (
                            <>
                              <GitBranch className="w-3 h-3 text-slate-400 shrink-0" />
                              <span className="truncate max-w-[165px]" title={meta.cleanGit}>
                                {meta.cleanGit}
                              </span>
                            </>
                          ) : p.localPath ? (
                            <span className="truncate max-w-[165px]" title={p.localPath}>
                              {p.localPath}
                            </span>
                          ) : (
                            <span className="font-sans text-slate-400">{t('projects.localProject')}</span>
                          )}
                        </span>
                      </span>
                    </button>

                    <span
                      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium border shrink-0 tabular-nums ${statusMeta.pillClass}`}
                    >
                      {statusMeta.isMaintenance ? (
                        <PauseCircle className="w-3 h-3 text-amber-600" />
                      ) : (
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${statusMeta.dotClass} ${
                            statusMeta.isLive ? 'culkibo-dot-live' : ''
                          }`}
                        />
                      )}
                      {statusMeta.label}
                    </span>
                  </div>

                  {/* HTTPS domain pill + 1-click copy */}
                  <div className="min-h-[30px] flex items-center justify-between gap-2 min-w-0">
                    {p.domains && p.domains.length > 0 ? (
                      <div className="flex items-center gap-1 min-w-0 max-w-full">
                        <a
                          href={`https://${p.domains[0]}`}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono text-slate-700 bg-slate-50 hover:bg-slate-100 border border-slate-200/90 transition-colors max-w-[215px] truncate"
                          title={`https://${p.domains[0]}`}
                        >
                          <Lock className="w-3 h-3 text-emerald-600 shrink-0" />
                          <span className="truncate">{p.domains[0]}</span>
                          <ExternalLink className="w-2.5 h-2.5 text-slate-400 shrink-0" />
                        </a>
                        <button
                          type="button"
                          onClick={() => void handleCopyDomain(p.id, p.domains[0])}
                          aria-label={`Copy https://${p.domains[0]}`}
                          title="Copy HTTPS URL"
                          className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer shrink-0"
                        >
                          {copiedDomainId === p.id ? (
                            <Check className="w-3.5 h-3.5 text-emerald-600" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                        {p.domains.length > 1 && (
                          <span className="text-[11px] font-mono text-slate-400 tabular-nums shrink-0">
                            +{p.domains.length - 1}
                          </span>
                        )}
                      </div>
                    ) : p.localRunning && p.localPort ? (
                      <a
                        href={`http://${previewHost}:${p.localPort}`}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono text-amber-900 bg-amber-50 hover:bg-amber-100 border border-amber-200 transition-colors tabular-nums"
                      >
                        <Zap className="w-3 h-3 text-amber-600 shrink-0" />
                        <span>http://{previewHost}:{p.localPort}</span>
                        <ExternalLink className="w-2.5 h-2.5 text-amber-600/80 shrink-0" />
                      </a>
                    ) : (
                      <button
                        type="button"
                        onClick={() => onSelectProject(p.id, 'domains')}
                        className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-700 transition-colors cursor-pointer"
                      >
                        <Globe className="w-3.5 h-3.5 text-slate-300" />
                        <span>{t('projects.connectDomain')}</span>
                      </button>
                    )}
                  </div>

                  {/* Real telemetry chips */}
                  <div className="flex items-center gap-1.5 flex-wrap text-[11px] text-slate-500 tabular-nums">
                    {meta.branch && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-50 border border-slate-200/80 font-mono text-slate-600">
                        <GitBranch className="w-2.5 h-2.5 text-slate-400" />
                        {meta.branch}
                      </span>
                    )}
                    {(meta.ramLabel || meta.cpuLabel) && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-50 border border-slate-200/80 font-mono text-slate-600">
                        <Cpu className="w-2.5 h-2.5 text-slate-400" />
                        {[meta.ramLabel, meta.cpuLabel].filter(Boolean).join(' · ')}
                      </span>
                    )}
                    {meta.totalDbs > 0 && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-50 border border-slate-200/80 font-mono text-slate-600">
                        <Database className="w-2.5 h-2.5 text-slate-400" />
                        {meta.totalDbs} DB
                      </span>
                    )}
                    {meta.shortCommit && (
                      <span className="px-1.5 py-0.5 rounded-md bg-slate-50 border border-slate-200/80 font-mono text-slate-500">
                        #{meta.shortCommit}
                      </span>
                    )}
                    {meta.lastDeployShort ? (
                      <span className="text-slate-400 ml-auto">{meta.lastDeployShort}</span>
                    ) : (
                      !meta.branch && !meta.ramLabel && meta.totalDbs === 0 && (
                        <span className="text-slate-400">{t('projects.notDeployed')}</span>
                      )
                    )}
                  </div>
                </div>

                {/* 1-click footer */}
                <div className="pt-3 border-t border-slate-100 flex items-center justify-between gap-1.5">
                  <div className="flex items-center gap-1.5 min-w-0">
                    {p.localRunning ? (
                      <button
                        type="button"
                        onClick={() => void handleStopLocal(p.id)}
                        disabled={stoppingLocalId === p.id}
                        className="culkibo-press inline-flex items-center gap-1.5 min-h-[36px] px-2.5 py-1.5 text-xs font-medium text-red-700 bg-red-50 hover:bg-red-100 border border-red-200 rounded-lg cursor-pointer disabled:opacity-50"
                      >
                        <Square className="w-3 h-3 fill-red-600 text-red-600" />
                        <span>{stoppingLocalId === p.id ? t('projects.stopping') : t('projects.stop')}</span>
                      </button>
                    ) : (
                      <button
                        type="button"
                        onClick={() => void handleQuickDeploy(p)}
                        disabled={isDeployingThis}
                        title={t('projects.deploy')}
                        className="culkibo-press inline-flex items-center gap-1.5 min-h-[36px] px-2.5 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-lg cursor-pointer disabled:opacity-50"
                      >
                        {isDeployingThis ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <Rocket className="w-3.5 h-3.5" />
                        )}
                        <span>{isDeployingThis ? t('projects.deploying') : t('projects.deploy')}</span>
                      </button>
                    )}

                    {!p.localRunning && (
                      <button
                        type="button"
                        onClick={() => void handleStartLocal(p.id)}
                        disabled={isStartingThisLocal}
                        aria-label={`Start local preview for ${p.name}`}
                        title="Start local preview"
                        className="culkibo-press inline-flex items-center justify-center w-9 h-9 rounded-lg text-slate-600 bg-slate-50 hover:bg-slate-100 border border-slate-200/80 cursor-pointer disabled:opacity-50"
                      >
                        {isStartingThisLocal ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <Play className="w-3.5 h-3.5" />
                        )}
                      </button>
                    )}
                  </div>

                  <div className="flex items-center gap-0.5 shrink-0">
                    <button
                      type="button"
                      onClick={() => onSelectProject(p.id, 'deploy')}
                      aria-label={`Logs for ${p.name}`}
                      title="Logs & Deployments"
                      className="inline-flex items-center justify-center w-9 h-9 rounded-lg text-slate-500 hover:text-slate-900 hover:bg-slate-100 transition-colors cursor-pointer"
                    >
                      <Terminal className="w-3.5 h-3.5" />
                    </button>
                    <button
                      type="button"
                      onClick={() => onSelectProject(p.id, 'live')}
                      aria-label={`Live Sync for ${p.name}`}
                      title="Live Sync <10ms"
                      className="inline-flex items-center justify-center w-9 h-9 rounded-lg text-slate-500 hover:text-amber-600 hover:bg-amber-50 transition-colors cursor-pointer"
                    >
                      <Zap className="w-3.5 h-3.5" />
                    </button>
                    <button
                      type="button"
                      onClick={() => onSelectProject(p.id)}
                      className="inline-flex items-center gap-1 min-h-[36px] px-2.5 py-1.5 rounded-lg text-xs font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors cursor-pointer"
                    >
                      <span>{t('projects.open')}</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </article>
            );
          })}
        </div>
      ) : filtered.length > 0 ? (
        <div className="culkibo-surface rounded-2xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200">
              <thead className="bg-slate-50/80">
                <tr>
                  <th className="px-5 py-3 text-left text-xs font-medium text-slate-500">{t('projects.tableProject')}</th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-slate-500">{t('projects.tableStatus')}</th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-slate-500">{t('projects.tableRuntime')}</th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-slate-500">{t('projects.tableDomain')}</th>
                  <th className="px-5 py-3 text-right text-xs font-medium text-slate-500">{t('projects.tableActions')}</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-slate-100">
                {filtered.map((p) => {
                  const meta = metadataMap.get(p.id) || getProjectMetadata(p, locale);
                  const s = getHonestStatus(p);
                  return (
                    <tr
                      key={p.id}
                      tabIndex={0}
                      onClick={() => onSelectProject(p.id)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          onSelectProject(p.id);
                        }
                      }}
                      className="hover:bg-slate-50/90 focus:bg-slate-50 transition-colors cursor-pointer group outline-none"
                    >
                      <td className="px-5 py-3.5 whitespace-nowrap">
                        <div className="flex items-center gap-3">
                          <span className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 bg-slate-900 text-white text-[11px] font-semibold font-mono">
                            {meta.monogram}
                          </span>
                          <div className="min-w-0">
                            <div className="text-sm font-medium text-slate-900">{p.name}</div>
                            <div className="text-xs text-slate-400 truncate max-w-[220px] font-mono">
                              {meta.cleanGit || t('projects.localProject')}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="px-5 py-3.5 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium border tabular-nums ${s.pillClass}`}
                        >
                          <span className={`w-1.5 h-1.5 rounded-full ${s.dotClass} ${s.isLive ? 'culkibo-dot-live' : ''}`} />
                          {s.label}
                        </span>
                      </td>
                      <td className="px-5 py-3.5 whitespace-nowrap text-xs text-slate-600 tabular-nums font-mono">
                        {meta.summaryTag}
                      </td>
                      <td className="px-5 py-3.5 whitespace-nowrap">
                        {p.domains && p.domains.length > 0 ? (
                          <span className="font-mono text-xs text-slate-700 bg-slate-50 border border-slate-200 px-2 py-0.5 rounded-md inline-flex items-center gap-1">
                            <Lock className="w-2.5 h-2.5 text-emerald-600" />
                            {p.domains[0]}
                          </span>
                        ) : (
                          <span className="text-xs text-slate-400">{t('projects.noDomain')}</span>
                        )}
                      </td>
                      <td className="px-5 py-3.5 whitespace-nowrap text-right">
                        <div
                          className="inline-flex items-center gap-1"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <button
                            type="button"
                            onClick={() => void handleQuickDeploy(p)}
                            disabled={deployingId === p.id}
                            title={t('projects.deploy')}
                            className="p-1.5 rounded-lg text-slate-500 hover:text-slate-900 hover:bg-slate-100 cursor-pointer disabled:opacity-50"
                          >
                            {deployingId === p.id ? (
                              <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                              <Rocket className="w-3.5 h-3.5" />
                            )}
                          </button>
                          <button
                            type="button"
                            onClick={() => onSelectProject(p.id, 'live')}
                            title="Live Sync"
                            className="p-1.5 rounded-lg text-slate-500 hover:text-amber-600 hover:bg-amber-50 cursor-pointer"
                          >
                            <Zap className="w-3.5 h-3.5" />
                          </button>
                          <button
                            type="button"
                            onClick={() => onSelectProject(p.id)}
                            className="inline-flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-100 cursor-pointer"
                          >
                            <span>{t('projects.open')}</span>
                            <ArrowRight className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}

      {/* 3-Path Empty State Hero */}
      {!isLoading && filtered.length === 0 && (
        projects.length === 0 ? (
          <section className="culkibo-surface rounded-2xl p-6 sm:p-8 space-y-6">
            <div className="max-w-xl mx-auto text-center space-y-2">
              <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-100 border border-slate-200/80 text-[11px] font-medium text-slate-700">
                <Sparkles className="w-3 h-3 text-amber-500" />
                <span>{t('projects.heroPill')}</span>
              </div>
              <h2 className="text-xl sm:text-2xl font-semibold text-slate-900 tracking-tight">
                {t('projects.heroTitle')}
              </h2>
              <p className="text-sm text-slate-500 leading-relaxed">
                {t('projects.heroDesc')}
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <button
                type="button"
                onClick={onImportCoolify}
                className="culkibo-card culkibo-stagger-1 culkibo-press text-left rounded-2xl p-5 flex flex-col justify-between gap-4 cursor-pointer group"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="w-10 h-10 rounded-xl bg-amber-50 border border-amber-200/80 text-amber-700 flex items-center justify-center">
                      <Download className="w-5 h-5" />
                    </span>
                    <span className="px-2 py-0.5 rounded-full bg-amber-50 text-amber-800 border border-amber-200/80 text-[11px] font-medium">
                      1-Click
                    </span>
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-900">{t('projects.pathCoolifyTitle')}</h3>
                    <p className="text-xs text-slate-500 mt-1 leading-relaxed">{t('projects.pathCoolifyDesc')}</p>
                  </div>
                </div>
                <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-900 group-hover:translate-x-0.5 transition-transform">
                  <span>{t('projects.pathCoolifyCta')}</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </span>
              </button>

              <button
                type="button"
                onClick={() => setShowCreateModal(true)}
                className="culkibo-card culkibo-stagger-2 culkibo-press text-left rounded-2xl p-5 flex flex-col justify-between gap-4 cursor-pointer group border-slate-900/20"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="w-10 h-10 rounded-xl bg-slate-900 text-white flex items-center justify-center">
                      <GitBranch className="w-5 h-5" />
                    </span>
                    <span className="px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 border border-slate-200 text-[11px] font-medium">
                      Live Sync &lt;10ms
                    </span>
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-900">{t('projects.pathGitTitle')}</h3>
                    <p className="text-xs text-slate-500 mt-1 leading-relaxed">{t('projects.pathGitDesc')}</p>
                  </div>
                </div>
                <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-900 group-hover:translate-x-0.5 transition-transform">
                  <span>{t('projects.pathGitCta')}</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </span>
              </button>

              <button
                type="button"
                onClick={onOpenCatalog || onImportCoolify}
                className="culkibo-card culkibo-stagger-3 culkibo-press text-left rounded-2xl p-5 flex flex-col justify-between gap-4 cursor-pointer group"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="w-10 h-10 rounded-xl bg-emerald-50 border border-emerald-200/80 text-emerald-700 flex items-center justify-center">
                      <Boxes className="w-5 h-5" />
                    </span>
                    <span className="px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-800 border border-emerald-200/80 text-[11px] font-medium tabular-nums">
                      140+ Apps
                    </span>
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-900">{t('projects.pathCatalogTitle')}</h3>
                    <p className="text-xs text-slate-500 mt-1 leading-relaxed">{t('projects.pathCatalogDesc')}</p>
                  </div>
                </div>
                <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-900 group-hover:translate-x-0.5 transition-transform">
                  <span>{t('projects.pathCatalogCta')}</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </span>
              </button>
            </div>

            <div className="pt-2 border-t border-slate-100 flex flex-wrap items-center justify-center gap-x-5 gap-y-2 text-xs text-slate-500">
              <button
                type="button"
                onClick={onOpenWordPress || onImportCoolify}
                className="inline-flex items-center gap-1.5 hover:text-slate-900 transition-colors cursor-pointer"
              >
                <Globe className="w-3.5 h-3.5 text-slate-400" />
                <span>{t('projects.heroWpLink')}</span>
              </button>
              {onOpenAi && (
                <button
                  type="button"
                  onClick={onOpenAi}
                  className="inline-flex items-center gap-1.5 hover:text-slate-900 transition-colors cursor-pointer"
                >
                  <Bot className="w-3.5 h-3.5 text-slate-400" />
                  <span>{t('projects.heroAiLink')}</span>
                </button>
              )}
            </div>
          </section>
        ) : (
          <div className="culkibo-surface rounded-2xl p-10 text-center max-w-lg mx-auto space-y-3">
            <div className="w-10 h-10 rounded-xl bg-slate-100 text-slate-400 flex items-center justify-center mx-auto">
              <Search className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-semibold text-slate-900">
              {search.trim()
                ? t('projects.noMatchQuery', { query: search.trim() })
                : t('projects.noMatchFilter')}
            </h3>
            <button
              type="button"
              onClick={() => { setSearch(''); setFilter('all'); }}
              className="culkibo-press inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>{t('projects.resetFilters')}</span>
            </button>
          </div>
        )
      )}

      <CreateProjectModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        onNotify={onNotify}
        onSuccess={(createdId, initialTab) => {
          fetchProjects();
          if (createdId) onSelectProject(createdId, initialTab || null);
        }}
      />
    </div>
  );
};
