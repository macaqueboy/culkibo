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
} from 'lucide-react';
import { api, type Project } from '../lib/api';
import { CreateProjectModal } from './CreateProjectModal';
import { OnboardingChecklist } from './OnboardingChecklist';

interface ProjectListProps {
  onSelectProject: (id: string, tab?: string | null) => void;
  onImportCoolify: () => void;
  onOpenWordPress?: () => void;
  onOpenCatalog?: () => void;
  onOpenDomains?: () => void;
  onOpenAi?: () => void;
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

function getHonestStatus(p: Project): {
  label: string;
  pillClass: string;
  dotClass: string;
  isMaintenance?: boolean;
} {
  if (p.maintenanceMode) {
    return {
      label: 'Mantenimiento',
      pillClass: 'bg-amber-50 text-amber-800 border-amber-200',
      dotClass: 'bg-amber-500',
      isMaintenance: true,
    };
  }
  if (p.lastDeployedAt && p.status === 'active') {
    return {
      label: 'En producción',
      pillClass: 'bg-emerald-50 text-emerald-700 border-emerald-200',
      dotClass: 'bg-emerald-500',
    };
  }
  if (p.localRunning) {
    return {
      label: p.localPort ? `En local :${p.localPort}` : 'En local',
      pillClass: 'bg-amber-50 text-amber-800 border-amber-200',
      dotClass: 'bg-amber-500',
    };
  }
  if (p.status === 'hibernated') {
    return {
      label: 'Hibernado',
      pillClass: 'bg-slate-100 text-slate-600 border-slate-200',
      dotClass: 'bg-slate-400',
    };
  }
  if (p.status === 'stopped') {
    return {
      label: 'Detenido',
      pillClass: 'bg-slate-100 text-slate-600 border-slate-200',
      dotClass: 'bg-slate-400',
    };
  }
  return {
    label: 'Sin iniciar',
    pillClass: 'bg-slate-100 text-slate-600 border-slate-200',
    dotClass: 'bg-slate-400',
  };
}

interface ProjectMetadata {
  cleanGit: string | null;
  monogram: string;
  summaryTag: string;
}

function getProjectMetadata(p: Project): ProjectMetadata {
  let rawGit = p.gitRepo || '';
  if (!rawGit && p.resources && Array.isArray(p.resources)) {
    const resWithGit = p.resources.find((r: any) => r.gitRepo);
    if (resWithGit) rawGit = resWithGit.gitRepo;
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
  const embeddedDbs = (p.resources || []).filter((r: any) => r.type === 'database').length;
  const totalDbs = linkedDbs + embeddedDbs;

  const parts: string[] = [];
  if (p.gitBranch) parts.push(p.gitBranch);
  if (totalDbs > 0) parts.push(`${totalDbs} BD`);
  if (p.lastDeployedAt) {
    parts.push(`Desplegado ${new Date(p.lastDeployedAt).toLocaleDateString('es-ES', { day: '2-digit', month: 'short' })}`);
  }
  const summaryTag = parts.join(' · ') || 'Sin desplegar todavía';

  return { cleanGit, monogram, summaryTag };
}

export const ProjectList: React.FC<ProjectListProps> = ({
  onSelectProject,
  onImportCoolify,
  onOpenWordPress,
  onOpenCatalog,
  onOpenDomains,
  onOpenAi,
  projects: parentProjects,
  projectsLoading,
  onRefreshProjects,
  onNotify,
  externalCreateTrigger,
  checklistRestoreTick = 0,
}) => {
  const [localProjects, setLocalProjects] = useState<Project[]>(() => (Array.isArray(parentProjects) ? parentProjects : []));
  const [loading, setLoading] = useState<boolean>(() => !Array.isArray(parentProjects));
  const [startingLocalId, setStartingLocalId] = useState<string | null>(null);
  const [stoppingLocalId, setStoppingLocalId] = useState<string | null>(null);
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

  const handleStartLocal = async (id: string) => {
    try {
      setStartingLocalId(id);
      const res: any = await api.startLocal(id);
      fetchProjects();
      const port = res?.localPort || res?.port;
      onNotify?.(
        port ? `Iniciado en http://${previewHost}:${port}` : 'Proyecto iniciado en local',
        'success'
      );
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al iniciar en local', 'error');
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
      onNotify?.('Proyecto detenido y puerto liberado', 'info');
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al detener el proyecto', 'error');
      fetchProjects();
    } finally {
      setStoppingLocalId(null);
    }
  };

  const projects = localProjects;

  const metadataMap = useMemo(() => {
    const map = new Map<string, ProjectMetadata>();
    for (const p of projects) {
      map.set(p.id, getProjectMetadata(p));
    }
    return map;
  }, [projects]);

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
          const meta = metadataMap.get(p.id) || getProjectMetadata(p);
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
  }, [projects, metadataMap, filter, deferredSearch, sortBy]);

  const previewHost = typeof window !== 'undefined' ? window.location.hostname : 'localhost';
  const isLoading = loading || Boolean(projectsLoading);

  return (
    <div className="space-y-5">
      {/* Cabecera limpia sobre el lienzo */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">Proyectos</h1>
          <p className="text-sm text-slate-500 mt-1 tabular-nums">
            {isLoading && projects.length === 0
              ? 'Cargando espacio de trabajo…'
              : stats.total === 0
                ? 'Despliega aplicaciones, migra WordPress y publica con HTTPS automático.'
                : `${stats.total} ${stats.total === 1 ? 'proyecto' : 'proyectos'} · ${stats.active} ${stats.active === 1 ? 'activo' : 'activos'} · ${stats.totalDomains} ${stats.totalDomains === 1 ? 'dominio' : 'dominios'}${stats.local > 0 ? ` · ${stats.local} en local` : ''}`}
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0 flex-wrap">
          <button
            type="button"
            onClick={onImportCoolify}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-200 transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-slate-500" />
            <span>Importar o migrar</span>
          </button>

          <button
            type="button"
            onClick={() => setShowCreateModal(true)}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Nuevo proyecto</span>
          </button>
        </div>
      </div>

      {/* Rail compacto de puesta en marcha */}
      <OnboardingChecklist
        projectsCount={stats.total}
        domainsCount={stats.totalDomains}
        onCreateProject={() => setShowCreateModal(true)}
        onOpenWordPress={onOpenWordPress || onImportCoolify}
        onOpenImport={onImportCoolify}
        onOpenCatalog={onOpenCatalog || onImportCoolify}
        onOpenDomains={onOpenDomains || (() => {})}
        onOpenAi={onOpenAi || (() => {})}
        onNotify={onNotify}
        restoreTick={checklistRestoreTick}
      />

      {/* Barra de búsqueda y filtros directa sobre el lienzo (solo cuando hay proyectos) */}
      {projects.length > 0 && (
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-2.5">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
            <input
              id="omnibar"
              type="text"
              placeholder="Buscar proyecto, repositorio o dominio…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-10 py-1.5 bg-white border border-slate-200 rounded-lg text-sm text-slate-900 placeholder:text-slate-400"
            />
            {search ? (
              <button
                type="button"
                onClick={() => setSearch('')}
                aria-label="Limpiar búsqueda"
                className="absolute right-2.5 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-slate-700 rounded cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            ) : (
              <kbd className="hidden sm:inline-flex items-center absolute right-2.5 top-1/2 -translate-y-1/2 px-1.5 py-0.5 text-[10px] font-mono text-slate-400 bg-slate-50 border border-slate-200 rounded">
                /
              </kbd>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2 justify-between lg:justify-end">
            <div className="flex items-center bg-slate-100 p-0.5 rounded-lg border border-slate-200 text-xs overflow-x-auto">
              {([
                { id: 'all', label: `Todos (${stats.total})` },
                { id: 'active', label: `Activos (${stats.active})` },
                { id: 'local', label: `Local (${stats.local})` },
                { id: 'hibernated', label: `Detenidos (${stats.inactive})` },
              ] as const).map((pill) => (
                <button
                  key={pill.id}
                  type="button"
                  onClick={() => setFilter(pill.id)}
                  className={`px-2.5 py-1 rounded-md font-medium transition-colors cursor-pointer whitespace-nowrap tabular-nums ${
                    filter === pill.id
                      ? 'bg-white text-slate-900 shadow-2xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {pill.label}
                </button>
              ))}
            </div>

            <select
              aria-label="Ordenar proyectos"
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-medium rounded-lg px-2.5 py-1.5 cursor-pointer"
            >
              <option value="recent">Más recientes</option>
              <option value="name">Nombre (A–Z)</option>
              <option value="domains">Más dominios</option>
              <option value="status">Estado</option>
            </select>

            <div className="flex bg-slate-100 p-0.5 rounded-lg border border-slate-200">
              <button
                type="button"
                onClick={() => setView('grid')}
                aria-label="Vista en cuadrícula"
                title="Vista en cuadrícula"
                className={`p-1.5 rounded-md transition-colors cursor-pointer ${
                  view === 'grid' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-400 hover:text-slate-700'
                }`}
              >
                <LayoutGrid className="w-3.5 h-3.5" />
              </button>
              <button
                type="button"
                onClick={() => setView('table')}
                aria-label="Vista en tabla"
                title="Vista en tabla"
                className={`p-1.5 rounded-md transition-colors cursor-pointer ${
                  view === 'table' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-400 hover:text-slate-700'
                }`}
              >
                <List className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Listado */}
      {isLoading && projects.length === 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="bg-white border border-slate-200 rounded-xl p-5 h-[180px] animate-pulse" />
          ))}
        </div>
      ) : filtered.length > 0 && view === 'grid' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 items-stretch">
          {filtered.map((p) => {
            const meta = metadataMap.get(p.id) || getProjectMetadata(p);
            const isStartingThisLocal = startingLocalId === p.id;
            const statusMeta = getHonestStatus(p);

            return (
              <article
                key={p.id}
                className="group bg-white border border-slate-200 hover:border-slate-300 rounded-xl p-4 shadow-2xs hover:shadow-xs transition-all flex flex-col justify-between gap-4"
              >
                {/* Señal 1: Identidad + Estado */}
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-3">
                    <button
                      type="button"
                      onClick={() => onSelectProject(p.id)}
                      className="flex items-center gap-3 min-w-0 text-left cursor-pointer group/title"
                    >
                      <span
                        aria-hidden="true"
                        className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0 bg-slate-900 text-white text-xs font-semibold tracking-tight font-mono"
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
                              <span className="truncate max-w-[170px]" title={meta.cleanGit}>{meta.cleanGit}</span>
                            </>
                          ) : p.localPath ? (
                            <span className="truncate max-w-[170px]" title={p.localPath}>{p.localPath}</span>
                          ) : (
                            <span className="font-sans text-slate-400">Carpeta local / sin Git</span>
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
                        <span className={`w-1.5 h-1.5 rounded-full ${statusMeta.dotClass}`} />
                      )}
                      {statusMeta.label}
                    </span>
                  </div>

                  {/* Señal 2: Dominio conectado */}
                  <div className="min-h-[26px] flex items-center justify-between gap-2">
                    {p.domains && p.domains.length > 0 ? (
                      <div className="flex items-center gap-1.5 min-w-0">
                        <a
                          href={`https://${p.domains[0]}`}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-mono text-slate-700 bg-slate-50 hover:bg-slate-100 border border-slate-200 transition-colors max-w-[220px] truncate"
                          title={`Abrir https://${p.domains[0]}`}
                        >
                          <Lock className="w-3 h-3 text-emerald-600 shrink-0" />
                          <span className="truncate">{p.domains[0]}</span>
                          <ExternalLink className="w-2.5 h-2.5 text-slate-400 shrink-0" />
                        </a>
                        {p.domains.length > 1 && (
                          <span className="text-[11px] font-mono text-slate-500 tabular-nums">
                            +{p.domains.length - 1}
                          </span>
                        )}
                      </div>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-xs text-slate-400">
                        <Globe className="w-3.5 h-3.5 text-slate-300" />
                        {p.localRunning ? 'Solo vista previa local' : 'Sin dominio conectado'}
                      </span>
                    )}
                  </div>

                  {/* Señal 3: Resumen único de rama / BD / último deploy */}
                  <p className="text-xs text-slate-500 truncate tabular-nums">
                    {meta.summaryTag}
                  </p>
                </div>

                {/* Señal 4: Barra de acción limpia sin botones anidados */}
                <div className="pt-3 border-t border-slate-100 flex items-center justify-between gap-2">
                  {p.localRunning ? (
                    <div className="flex items-center gap-1.5 flex-wrap">
                      {p.localPort && (
                        <a
                          href={`http://${previewHost}:${p.localPort}`}
                          target="_blank"
                          rel="noreferrer"
                          title={`Abrir vista previa local en http://${previewHost}:${p.localPort}`}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-amber-900 bg-amber-50 hover:bg-amber-100 border border-amber-200 rounded-lg transition-colors font-mono tabular-nums"
                        >
                          <Zap className="w-3.5 h-3.5 text-amber-600 shrink-0" />
                          <span>Abrir :{p.localPort}</span>
                          <ExternalLink className="w-3 h-3 text-amber-600/80 shrink-0" />
                        </a>
                      )}
                      <button
                        type="button"
                        onClick={() => void handleStopLocal(p.id)}
                        disabled={stoppingLocalId === p.id}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-red-700 bg-red-50 hover:bg-red-100 border border-red-200 rounded-lg cursor-pointer disabled:opacity-50"
                      >
                        <Square className="w-3 h-3 fill-red-600 text-red-600" />
                        <span>{stoppingLocalId === p.id ? 'Parando…' : 'Detener'}</span>
                      </button>
                    </div>
                  ) : (
                    <button
                      type="button"
                      onClick={() => void handleStartLocal(p.id)}
                      disabled={isStartingThisLocal}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded-lg cursor-pointer disabled:opacity-50"
                    >
                      {isStartingThisLocal ? (
                        <Loader2 className="w-3.5 h-3.5 text-slate-600 animate-spin" />
                      ) : (
                        <Play className="w-3.5 h-3.5 text-slate-600" />
                      )}
                      <span>{isStartingThisLocal ? 'Iniciando…' : 'Iniciar local'}</span>
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={() => onSelectProject(p.id)}
                    className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors cursor-pointer"
                  >
                    <span>Gestionar</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      ) : filtered.length > 0 ? (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200">
              <thead className="bg-slate-50/80">
                <tr>
                  <th className="px-5 py-3 text-left text-xs font-medium text-slate-500">Proyecto</th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-slate-500">Estado</th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-slate-500">Resumen</th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-slate-500">Dominio</th>
                  <th className="px-5 py-3 text-right text-xs font-medium text-slate-500">Acción</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-slate-100">
                {filtered.map((p) => {
                  const meta = metadataMap.get(p.id) || getProjectMetadata(p);
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
                      className="hover:bg-slate-50 focus:bg-slate-50 transition-colors cursor-pointer group outline-none"
                    >
                      <td className="px-5 py-3.5 whitespace-nowrap">
                        <div className="flex items-center gap-3">
                          <span className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 bg-slate-900 text-white text-[11px] font-semibold font-mono">
                            {meta.monogram}
                          </span>
                          <div className="min-w-0">
                            <div className="text-sm font-medium text-slate-900">{p.name}</div>
                            <div className="text-xs text-slate-400 truncate max-w-[220px] font-mono">
                              {meta.cleanGit || 'Sin repositorio Git'}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="px-5 py-3.5 whitespace-nowrap">
                        {(() => {
                          const s = getHonestStatus(p);
                          return (
                            <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium border tabular-nums ${s.pillClass}`}>
                              <span className={`w-1.5 h-1.5 rounded-full ${s.dotClass}`} />
                              {s.label}
                            </span>
                          );
                        })()}
                      </td>
                      <td className="px-5 py-3.5 whitespace-nowrap text-xs text-slate-600 tabular-nums">
                        {meta.summaryTag}
                      </td>
                      <td className="px-5 py-3.5 whitespace-nowrap">
                        {p.domains && p.domains.length > 0 ? (
                          <span className="font-mono text-xs text-slate-700 bg-slate-50 border border-slate-200 px-2 py-0.5 rounded inline-flex items-center gap-1">
                            <Lock className="w-2.5 h-2.5 text-emerald-600" />
                            {p.domains[0]}
                          </span>
                        ) : (
                          <span className="text-xs text-slate-400">Sin dominio</span>
                        )}
                      </td>
                      <td className="px-5 py-3.5 whitespace-nowrap text-right">
                        <span className="inline-flex items-center gap-1 text-xs font-medium text-slate-500 group-hover:text-slate-900">
                          <span>Gestionar</span>
                          <ArrowRight className="w-3.5 h-3.5" />
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}

      {/* Estado vacío calmado y enfocado */}
      {!isLoading && filtered.length === 0 && (
        <div className="bg-white border border-slate-200 rounded-xl p-10 text-center max-w-xl mx-auto">
          {projects.length === 0 ? (
            <div className="space-y-4">
              <div className="w-11 h-11 rounded-xl bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center mx-auto">
                <Boxes className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-slate-900">Empieza con tu primer proyecto</h3>
                <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto leading-relaxed">
                  Conecta un repositorio Git, migra una web WordPress en minutos o importa stacks desde Coolify, Vercel, Railway o Docker Compose.
                </p>
              </div>
              <div className="flex flex-wrap items-center justify-center gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(true)}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Crear proyecto</span>
                </button>
                <button
                  type="button"
                  onClick={onOpenWordPress || onImportCoolify}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-200 cursor-pointer"
                >
                  <Globe className="w-3.5 h-3.5 text-slate-500" />
                  <span>Migrar WordPress</span>
                </button>
                <button
                  type="button"
                  onClick={onImportCoolify}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-200 cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5 text-slate-500" />
                  <span>Importar plataforma</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="w-10 h-10 rounded-lg bg-slate-100 text-slate-400 flex items-center justify-center mx-auto">
                <Search className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-semibold text-slate-900">
                {search.trim()
                  ? `No hay proyectos que coincidan con «${search.trim()}»`
                  : 'No hay proyectos en este filtro'}
              </h3>
              <button
                type="button"
                onClick={() => { setSearch(''); setFilter('all'); }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Restablecer filtros</span>
              </button>
            </div>
          )}
        </div>
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
