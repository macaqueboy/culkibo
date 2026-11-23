import React, { useState, useEffect, useMemo, useDeferredValue } from 'react';
import {
  Search,
  Plus,
  Download,
  Globe,
  ExternalLink,
  GitBranch,
  Layers,
  Database,
  Server,
  Zap,
  Radio,
  Lock,
  ArrowRight,
  LayoutGrid,
  List,
  ShoppingBag,
  Cpu,
  Wrench,
  X,
  Boxes,
  RefreshCw,
  Play,
  Square,
  Power,
  Loader2,
} from 'lucide-react';
import { api, type Project } from '../lib/api';
import { CreateProjectModal } from './CreateProjectModal';
import { OnboardingChecklist } from './OnboardingChecklist';

interface ProjectListProps {
  onSelectProject: (id: string) => void;
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
}

interface ProjectMetadata {
  cleanGit: string | null;
  appsCount: number;
  dbsCount: number;
  servicesCount: number;
  techTags: string[];
  dbType: string | null;
  IconComponent: React.ComponentType<{ className?: string }>;
}

function getProjectMetadata(p: Project): ProjectMetadata {
  const nameLower = (p.name || '').toLowerCase();
  const descLower = (p.description || '').toLowerCase();

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

  const allEnvVars: Record<string, string> = { ...(p.envVars || {}) };
  if (p.resources && Array.isArray(p.resources)) {
    for (const res of p.resources) {
      if (res.envVars && typeof res.envVars === 'object') {
        Object.assign(allEnvVars, res.envVars);
      }
    }
  }
  const envKeys = Object.keys(allEnvVars).join(' ');

  const apps = (p.resources || []).filter((r: any) => r.type === 'app');
  const appsCount = apps.length || (p.source !== 'coolify-import' ? 1 : 0);
  const dbs = (p.resources || []).filter((r: any) => r.type === 'database');
  const dbsCount = dbs.length;
  const services = (p.resources || []).filter((r: any) => r.type === 'service');
  const servicesCount = services.length;

  let dbType: string | null = null;
  if (dbsCount > 0) {
    const db = dbs[0];
    const dbName = (db.name || '').toLowerCase();
    const dbTypeProp = (db.databaseType || '').toLowerCase();
    const dbUrl = (allEnvVars.DATABASE_URL || allEnvVars.DATABASE_URL_ADMIN || '').toLowerCase();

    if (dbTypeProp.includes('postgres') || dbName.includes('postgres') || dbUrl.includes('postgres')) {
      dbType = 'PostgreSQL';
    } else if (dbTypeProp.includes('mysql') || dbName.includes('mysql') || dbUrl.includes('mysql')) {
      dbType = 'MySQL';
    } else if (dbTypeProp.includes('mariadb') || dbName.includes('mariadb')) {
      dbType = 'MariaDB';
    } else if (dbTypeProp.includes('redis') || dbName.includes('redis') || dbName.includes('valkey') || dbUrl.includes('redis')) {
      dbType = 'Valkey / Redis';
    } else if (dbTypeProp.includes('mongo') || dbName.includes('mongo') || dbUrl.includes('mongo')) {
      dbType = 'MongoDB';
    } else if (dbTypeProp.includes('sqlite') || dbName.includes('sqlite')) {
      dbType = 'SQLite';
    } else {
      dbType = 'Base de datos';
    }
  }

  const tags: string[] = [];
  const buildPacks = (p.resources || []).map((r: any) => r.buildConfig?.build_pack || '').filter(Boolean);

  if (envKeys.includes('NEXT_PUBLIC') || envKeys.includes('NEXT_') || descLower.includes('next')) {
    tags.push('Next.js');
  } else if (descLower.includes('vite') || descLower.includes('react')) {
    tags.push('React / Vite');
  } else if (descLower.includes('wordpress') || nameLower.includes('wordpress')) {
    tags.push('WordPress');
  }

  if (buildPacks.includes('nixpacks')) {
    tags.push('Nixpacks');
  } else if (buildPacks.includes('dockerfile') || p.source === 'coolify-import' || p.source === 'compose-import') {
    tags.push('Docker');
  }

  if (nameLower.includes('api') || descLower.includes('api') || descLower.includes('gateway')) {
    if (!tags.includes('API')) tags.unshift('API');
  }

  if (tags.length === 0) {
    if (appsCount > 0) tags.push('Aplicación web');
    else tags.push('Servicio');
  }

  const techTags = Array.from(new Set(tags)).slice(0, 3);

  let IconComponent: React.ComponentType<{ className?: string }> = Boxes;
  if (descLower.includes('tienda') || descLower.includes('commerce') || descLower.includes('shop')) {
    IconComponent = ShoppingBag;
  } else if (nameLower.includes('api') || descLower.includes('api') || descLower.includes('gateway')) {
    IconComponent = Cpu;
  } else if (nameLower.includes('tool') || descLower.includes('tool')) {
    IconComponent = Wrench;
  } else if (servicesCount > 0 || dbsCount > 0) {
    IconComponent = Database;
  }

  return {
    cleanGit,
    appsCount,
    dbsCount,
    servicesCount,
    techTags,
    dbType,
    IconComponent,
  };
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

  const handleStartLocal = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    try {
      setStartingLocalId(id);
      await api.startLocal(id);
      fetchProjects();
      onNotify?.('Proyecto iniciado en local', 'success');
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al iniciar en local', 'error');
      fetchProjects();
    } finally {
      setStartingLocalId(null);
    }
  };

  const handleStopLocal = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
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

  const handleActivate = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    try {
      await api.activateProject(id);
      fetchProjects();
      onNotify?.('Proyecto marcado como activo', 'success');
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al activar el proyecto', 'error');
      fetchProjects();
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
    const active = projects.filter((p) => p.status === 'active').length;
    const hibernated = projects.filter((p) => p.status === 'hibernated').length;
    const stopped = projects.filter((p) => p.status === 'stopped').length;
    const inactive = hibernated + stopped;
    const local = projects.filter((p) => p.localRunning).length;
    const configuredLocal = projects.filter((p) => p.localPort).length;
    const totalDomains = projects.reduce((acc, p) => acc + (p.domains?.length || 0), 0);
    return { total, active, hibernated, stopped, inactive, local, configuredLocal, totalDomains };
  }, [projects]);

  const filtered = useMemo(() => {
    const q = deferredSearch.trim().toLowerCase();
    return projects
      .filter((p) => {
        if (filter === 'active' && p.status !== 'active') return false;
        if (filter === 'hibernated' && p.status !== 'hibernated' && p.status !== 'stopped') return false;
        if (filter === 'local' && !p.localRunning) return false;

        if (q) {
          const meta = metadataMap.get(p.id) || getProjectMetadata(p);
          const matchName = (p.name || '').toLowerCase().includes(q);
          const matchDesc = (p.description || '').toLowerCase().includes(q);
          const matchDomain = p.domains?.some((d) => d.toLowerCase().includes(q));
          const matchGit = (p.gitRepo || '').toLowerCase().includes(q) || (meta.cleanGit || '').toLowerCase().includes(q);
          const matchTags = meta.techTags.some((t) => t.toLowerCase().includes(q));
          const matchDb = (meta.dbType || '').toLowerCase().includes(q);

          if (!matchName && !matchDesc && !matchDomain && !matchGit && !matchTags && !matchDb) {
            return false;
          }
        }
        return true;
      })
      .sort((a, b) => {
        if (sortBy === 'name') return a.name.localeCompare(b.name);
        if (sortBy === 'domains') return (b.domains?.length || 0) - (a.domains?.length || 0);
        if (sortBy === 'status') {
          if (a.status === b.status) return 0;
          return a.status === 'active' ? -1 : 1;
        }
        return new Date(b.updatedAt || b.createdAt || 0).getTime() - new Date(a.updatedAt || a.createdAt || 0).getTime();
      });
  }, [projects, metadataMap, filter, deferredSearch, sortBy]);

  const previewHost = typeof window !== 'undefined' ? window.location.hostname : 'localhost';
  const isLoading = loading || Boolean(projectsLoading);

  return (
    <div className="space-y-6">
      {/* 1. Cabecera y acciones principales */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-semibold text-slate-900 tracking-tight">Proyectos</h1>
            <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-slate-100 text-slate-600 border border-slate-200 tabular-nums">
              {isLoading && projects.length === 0 ? 'Cargando…' : `${stats.total} ${stats.total === 1 ? 'proyecto' : 'proyectos'}`}
            </span>
          </div>
          <p className="text-sm text-slate-500 mt-1">
            Despliega aplicaciones, migra sitios existentes y gestiona tus dominios HTTPS desde un único lugar.
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

      {/* Guía de primeros pasos */}
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
      />

      {/* 2. Tira de métricas monocroma compacta */}
      <div className="bg-white rounded-xl border border-slate-200 grid grid-cols-2 lg:grid-cols-4 divide-y lg:divide-y-0 lg:divide-x divide-slate-200">
        <div className="px-4 py-3.5">
          <div className="text-xs text-slate-500">Total proyectos</div>
          <div className="text-lg font-semibold text-slate-900 mt-1 tabular-nums">{stats.total}</div>
        </div>

        <div className="px-4 py-3.5">
          <div className="text-xs text-slate-500">Activos</div>
          <div className="text-lg font-semibold text-slate-900 mt-1 flex items-center gap-2 tabular-nums">
            <span>{stats.active}</span>
            {stats.active > 0 && <span className="w-2 h-2 rounded-full bg-emerald-500" />}
          </div>
        </div>

        <div className="px-4 py-3.5">
          <div className="text-xs text-slate-500">En ejecución local</div>
          <div className="text-lg font-semibold text-slate-900 mt-1 flex items-baseline gap-1 tabular-nums">
            <span>{stats.local}</span>
            <span className="text-xs font-normal text-slate-400">/ {stats.configuredLocal}</span>
          </div>
        </div>

        <button
          type="button"
          onClick={onOpenDomains}
          className="px-4 py-3.5 text-left hover:bg-slate-50/80 transition-colors cursor-pointer group"
        >
          <div className="text-xs text-slate-500 flex items-center justify-between">
            <span>Dominios vinculados</span>
            <span className="text-[11px] text-slate-400 group-hover:text-slate-700 transition-colors">Gestionar →</span>
          </div>
          <div className="text-lg font-semibold text-slate-900 mt-1 tabular-nums">{stats.totalDomains}</div>
        </button>
      </div>

      {/* 3. Barra de búsqueda, filtros y vista */}
      <div className="bg-white rounded-xl border border-slate-200 p-2.5 flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-2.5">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            id="omnibar"
            type="text"
            placeholder="Filtrar por nombre, repositorio, dominio o tecnología…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-10 py-1.5 bg-slate-50 hover:bg-white focus:bg-white border border-slate-200 rounded-lg text-sm text-slate-900 placeholder:text-slate-400 transition-colors"
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
            <kbd className="hidden sm:inline-flex items-center absolute right-2.5 top-1/2 -translate-y-1/2 px-1.5 py-0.5 text-[10px] font-mono text-slate-400 bg-white border border-slate-200 rounded">
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

      {/* 4. Listado */}
      {isLoading && projects.length === 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="bg-white border border-slate-200 rounded-xl p-5 h-[220px] animate-pulse" />
          ))}
        </div>
      ) : filtered.length > 0 && view === 'grid' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 items-stretch">
          {filtered.map((p) => {
            const meta = metadataMap.get(p.id) || getProjectMetadata(p);
            const { IconComponent } = meta;
            const forgePct = p.trafficSplit?.forge || 0;
            const citadelPct = p.trafficSplit?.citadel ?? 0;
            const hasTrafficSplit = forgePct > 0 && citadelPct > 0;
            const isStartingThisLocal = startingLocalId === p.id;

            return (
              <div
                key={p.id}
                role="button"
                tabIndex={0}
                onClick={() => onSelectProject(p.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onSelectProject(p.id);
                  }
                }}
                className="group relative bg-white border border-slate-200 hover:border-slate-300 rounded-xl p-4 shadow-2xs hover:shadow-xs transition-all cursor-pointer flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start justify-between gap-3 mb-3">
                    <div className="flex items-start gap-3 min-w-0">
                      <div className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0 bg-slate-100 border border-slate-200 text-slate-700">
                        <IconComponent className="w-4 h-4" />
                      </div>
                      <div className="min-w-0">
                        <h3 className="text-sm font-semibold text-slate-900 tracking-tight truncate">
                          {p.name}
                        </h3>
                        {meta.cleanGit ? (
                          <div className="flex items-center gap-1 text-xs text-slate-500 font-mono mt-0.5">
                            <GitBranch className="w-3 h-3 text-slate-400 shrink-0" />
                            <span className="truncate max-w-[170px]" title={meta.cleanGit}>{meta.cleanGit}</span>
                          </div>
                        ) : (
                          <div className="text-xs text-slate-400 mt-0.5">Sin repositorio Git</div>
                        )}
                      </div>
                    </div>

                    <div className="flex flex-col items-end gap-1 shrink-0">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium border ${
                          p.status === 'active'
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                            : p.status === 'hibernated'
                              ? 'bg-slate-100 text-slate-600 border-slate-200'
                              : 'bg-slate-100 text-slate-600 border-slate-200'
                        }`}
                      >
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          p.status === 'active' ? 'bg-emerald-500' : 'bg-slate-400'
                        }`} />
                        {p.status === 'active' ? 'Activo' : p.status === 'hibernated' ? 'Hibernado' : 'Detenido'}
                      </span>

                      {p.localRunning && p.localPort ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono font-medium bg-amber-50 text-amber-800 border border-amber-200 tabular-nums">
                          <Zap className="w-3 h-3 text-amber-600" />
                          <span>:{p.localPort}</span>
                        </span>
                      ) : null}
                    </div>
                  </div>

                  <p className="text-xs text-slate-500 line-clamp-2 leading-relaxed min-h-[34px] mb-3">
                    {p.description || 'Sin descripción configurada.'}
                  </p>

                  <div className="flex flex-wrap items-center gap-1.5 mb-3">
                    {meta.appsCount > 0 && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-medium bg-slate-100 text-slate-700 border border-slate-200 tabular-nums">
                        <Layers className="w-3 h-3 text-slate-500" />
                        {meta.appsCount} {meta.appsCount === 1 ? 'app' : 'apps'}
                      </span>
                    )}
                    {meta.dbsCount > 0 && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-medium bg-slate-100 text-slate-700 border border-slate-200">
                        <Database className="w-3 h-3 text-slate-500" />
                        {meta.dbType || 'Base de datos'}
                      </span>
                    )}
                    {meta.servicesCount > 0 && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-medium bg-slate-100 text-slate-700 border border-slate-200 tabular-nums">
                        <Server className="w-3 h-3 text-slate-500" />
                        {meta.servicesCount} {meta.servicesCount === 1 ? 'servicio' : 'servicios'}
                      </span>
                    )}
                    {meta.techTags.map((tag) => (
                      <span key={tag} className="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] text-slate-600 bg-slate-50 border border-slate-200">
                        {tag}
                      </span>
                    ))}
                  </div>

                  {hasTrafficSplit ? (
                    <div className="bg-slate-50 rounded-lg p-2.5 border border-slate-200/70 mb-3">
                      <div className="flex items-center justify-between text-[11px] mb-1.5 font-mono tabular-nums">
                        <span className="font-medium text-slate-700 font-sans flex items-center gap-1">
                          <Radio className="w-3 h-3 text-slate-500" />
                          Tráfico
                        </span>
                        <span className="text-slate-500">{citadelPct}% Prod · {forgePct}% Dev</span>
                      </div>
                      <div className="w-full h-1.5 bg-slate-200 rounded-full overflow-hidden flex">
                        <div className="bg-emerald-500 h-full" style={{ width: `${citadelPct}%` }} />
                        <div className="bg-amber-400 h-full" style={{ width: `${forgePct}%` }} />
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-center justify-between px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-200/70 mb-3 text-[11px]">
                      <span className="text-slate-500">Entorno</span>
                      {p.localRunning && p.localPort ? (
                        <span className="font-mono font-medium text-amber-800 tabular-nums">Local :{p.localPort}</span>
                      ) : p.lastDeployedAt ? (
                        <span className="font-medium text-emerald-700 tabular-nums">
                          Desplegado {new Date(p.lastDeployedAt).toLocaleDateString('es-ES')}
                        </span>
                      ) : (
                        <span className="text-slate-500">Sin desplegar</span>
                      )}
                    </div>
                  )}

                  {/* Dominios */}
                  <div className="min-h-[26px] flex items-center justify-between gap-2">
                    {p.domains && p.domains.length > 0 ? (
                      <div className="flex items-center justify-between w-full gap-2">
                        <a
                          href={`https://${p.domains[0]}`}
                          target="_blank"
                          rel="noreferrer"
                          onClick={(e) => e.stopPropagation()}
                          className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-mono text-slate-700 bg-slate-50 hover:bg-slate-100 border border-slate-200 transition-colors max-w-[220px] truncate"
                          title={`Abrir https://${p.domains[0]}`}
                        >
                          <Lock className="w-3 h-3 text-emerald-600 shrink-0" />
                          <span className="truncate">{p.domains[0]}</span>
                          <ExternalLink className="w-2.5 h-2.5 text-slate-400 shrink-0" />
                        </a>
                        {p.domains.length > 1 && (
                          <span className="text-[11px] font-mono text-slate-500 bg-slate-100 border border-slate-200 px-1.5 py-0.5 rounded tabular-nums">
                            +{p.domains.length - 1}
                          </span>
                        )}
                      </div>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-xs text-slate-400">
                        <Globe className="w-3.5 h-3.5 text-slate-300" />
                        Sin dominio público
                      </span>
                    )}
                  </div>
                </div>

                {/* Pie de tarjeta */}
                <div className="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    {p.localRunning ? (
                      <>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            window.open(`http://${previewHost}:${p.localPort}`, '_blank');
                          }}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-amber-800 bg-amber-50 hover:bg-amber-100 border border-amber-200 rounded-lg cursor-pointer tabular-nums"
                        >
                          <Zap className="w-3.5 h-3.5 text-amber-600" />
                          <span>Abrir :{p.localPort}</span>
                        </button>
                        <button
                          type="button"
                          onClick={(e) => handleStopLocal(e, p.id)}
                          disabled={stoppingLocalId === p.id}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-red-700 bg-red-50 hover:bg-red-100 border border-red-200 rounded-lg cursor-pointer disabled:opacity-50"
                        >
                          <Square className="w-3 h-3 fill-red-600 text-red-600" />
                          <span>{stoppingLocalId === p.id ? 'Parando…' : 'Detener'}</span>
                        </button>
                      </>
                    ) : (
                      <>
                        <button
                          type="button"
                          onClick={(e) => handleStartLocal(e, p.id)}
                          disabled={isStartingThisLocal}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200/80 border border-slate-200 rounded-lg cursor-pointer disabled:opacity-50"
                        >
                          {isStartingThisLocal ? (
                            <Loader2 className="w-3.5 h-3.5 text-slate-600 animate-spin" />
                          ) : (
                            <Play className="w-3.5 h-3.5 text-slate-600" />
                          )}
                          <span>{isStartingThisLocal ? 'Iniciando…' : 'Iniciar local'}</span>
                        </button>
                        {p.status !== 'active' && (
                          <button
                            type="button"
                            onClick={(e) => handleActivate(e, p.id)}
                            className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-emerald-700 bg-emerald-50 hover:bg-emerald-100 border border-emerald-200 rounded-lg cursor-pointer"
                          >
                            <Power className="w-3 h-3 text-emerald-600" />
                            <span>Activar</span>
                          </button>
                        )}
                      </>
                    )}
                  </div>

                  <div className="flex items-center gap-1 text-xs font-medium text-slate-500 group-hover:text-slate-900 transition-colors ml-auto">
                    <span>Abrir</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </div>
                </div>
              </div>
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
                  <th className="px-5 py-3 text-left text-xs font-medium text-slate-500">Componentes</th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-slate-500">Dominios</th>
                  <th className="px-5 py-3 text-right text-xs font-medium text-slate-500">Acción</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-slate-100">
                {filtered.map((p) => {
                  const meta = metadataMap.get(p.id) || getProjectMetadata(p);
                  const { IconComponent } = meta;
                  return (
                    <tr
                      key={p.id}
                      onClick={() => onSelectProject(p.id)}
                      className="hover:bg-slate-50 transition-colors cursor-pointer group"
                    >
                      <td className="px-5 py-3.5 whitespace-nowrap">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 bg-slate-100 border border-slate-200 text-slate-700">
                            <IconComponent className="w-4 h-4" />
                          </div>
                          <div className="min-w-0">
                            <div className="text-sm font-medium text-slate-900">{p.name}</div>
                            <div className="text-xs text-slate-400 truncate max-w-[220px] font-mono">
                              {meta.cleanGit || p.description || 'Sin descripción'}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="px-5 py-3.5 whitespace-nowrap">
                        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium border ${
                          p.status === 'active'
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                            : 'bg-slate-100 text-slate-600 border-slate-200'
                        }`}>
                          {p.status === 'active' ? 'Activo' : p.status === 'hibernated' ? 'Hibernado' : 'Detenido'}
                        </span>
                      </td>
                      <td className="px-5 py-3.5 whitespace-nowrap text-xs text-slate-600 tabular-nums">
                        {meta.appsCount} {meta.appsCount === 1 ? 'app' : 'apps'}
                        {meta.dbsCount > 0 ? ` · ${meta.dbType || 'BD'}` : ''}
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
                          <span>Abrir</span>
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

      {/* Estado vacío */}
      {!loading && filtered.length === 0 && (
        <div className="bg-white border border-slate-200 rounded-xl p-10 text-center max-w-xl mx-auto">
          {projects.length === 0 ? (
            <div className="space-y-4">
              <div className="w-12 h-12 rounded-xl bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center mx-auto">
                <Boxes className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-slate-900">Crea tu primer proyecto</h3>
                <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto leading-relaxed">
                  Conecta un repositorio Git, migra una web WordPress, importa desde Coolify o Docker Compose, o instala un servicio del catálogo.
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
        onSuccess={(createdId) => {
          fetchProjects();
          if (createdId) onSelectProject(createdId);
        }}
      />
    </div>
  );
};
