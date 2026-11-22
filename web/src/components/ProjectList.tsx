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
  CheckCircle2,
  X,
  Boxes,
  RefreshCw,
  Play,
  Square,
  Power
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
  onRefreshProjects?: () => void;
  onNotify?: (msg: string) => void;
  externalCreateTrigger?: number;
}

interface ProjectMetadata {
  cleanGit: string | null;
  appsCount: number;
  dbsCount: number;
  servicesCount: number;
  techTags: string[];
  dbType: string | null;
  iconBg: string;
  iconText: string;
  iconBorder: string;
  IconComponent: React.ComponentType<{ className?: string }>;
}

/**
 * Extrae metadatos visuales y técnicos reales desde los campos del proyecto
 * sin ningún nombre personal o de demostración incrustado.
 */
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
  let iconBg = 'bg-blue-50/80';
  let iconText = 'text-blue-600';
  let iconBorder = 'border-blue-100';

  if (descLower.includes('tienda') || descLower.includes('commerce') || descLower.includes('shop')) {
    IconComponent = ShoppingBag;
    iconBg = 'bg-emerald-50/80';
    iconText = 'text-emerald-600';
    iconBorder = 'border-emerald-100';
  } else if (nameLower.includes('api') || descLower.includes('api') || descLower.includes('gateway')) {
    IconComponent = Cpu;
    iconBg = 'bg-cyan-50/80';
    iconText = 'text-cyan-600';
    iconBorder = 'border-cyan-100';
  } else if (nameLower.includes('tool') || descLower.includes('tool')) {
    IconComponent = Wrench;
    iconBg = 'bg-purple-50/80';
    iconText = 'text-purple-600';
    iconBorder = 'border-purple-100';
  } else if (servicesCount > 0 || dbsCount > 0) {
    IconComponent = Database;
    iconBg = 'bg-indigo-50/80';
    iconText = 'text-indigo-600';
    iconBorder = 'border-indigo-100';
  }

  return {
    cleanGit,
    appsCount,
    dbsCount,
    servicesCount,
    techTags,
    dbType,
    iconBg,
    iconText,
    iconBorder,
    IconComponent
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
  onRefreshProjects,
  onNotify,
  externalCreateTrigger
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
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
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
      setLocalProjects((prev) => prev.map((p) => (p.id === id ? { ...p, status: 'active', localRunning: true } : p)));
      await api.startLocal(id);
      fetchProjects();
      onNotify?.('Proyecto iniciado en local');
    } catch (err) {
      console.error(err);
      onNotify?.('Error al iniciar en local');
      fetchProjects();
    } finally {
      setStartingLocalId(null);
    }
  };

  const handleStopLocal = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    try {
      setStoppingLocalId(id);
      setLocalProjects((prev) => prev.map((p) => (p.id === id ? { ...p, status: 'stopped', localRunning: false } : p)));
      await api.stopProject(id);
      fetchProjects();
      onNotify?.('Proyecto detenido y puerto liberado');
    } catch (err) {
      console.error(err);
      onNotify?.('Error al detener el proyecto');
      fetchProjects();
    } finally {
      setStoppingLocalId(null);
    }
  };

  const handleActivate = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    try {
      setLocalProjects((prev) => prev.map((p) => (p.id === id ? { ...p, status: 'active' } : p)));
      await api.activateProject(id);
      fetchProjects();
      onNotify?.('Proyecto marcado como activo');
    } catch (err) {
      console.error(err);
      onNotify?.('Error al activar el proyecto');
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

  return (
    <div className="space-y-6">
      {/* 1. Header & Primary Actions */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">Tus Proyectos</h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200/80 shadow-2xs tabular-nums">
              {stats.total} {stats.total === 1 ? 'proyecto' : 'proyectos'}
            </span>
          </div>
          <p className="text-sm text-slate-500 mt-1">
            Publica apps, migra desde WordPress u otras nubes, conecta tus dominios con HTTPS y controla todo desde tu agente IA.
          </p>
        </div>

        <div className="flex items-center gap-2.5 shrink-0 flex-wrap">
          <button
            type="button"
            onClick={onImportCoolify}
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold text-slate-700 bg-white hover:bg-slate-50 border border-slate-200/90 shadow-2xs hover:border-slate-300 transition-all duration-150 cursor-pointer"
          >
            <Download className="w-4 h-4 text-slate-500" />
            <span>Importar / Migrar</span>
          </button>

          <button
            type="button"
            onClick={() => setShowCreateModal(true)}
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold text-white bg-slate-900 hover:bg-slate-800 shadow-sm transition-all duration-150 cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Nuevo proyecto</span>
          </button>
        </div>
      </div>

      {/* Onboarding Checklist para principiantes */}
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

      {/* 2. Honest Cluster Metrics Ribbon */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        <div className="bg-white rounded-2xl border border-slate-200/80 p-3.5 sm:p-4 shadow-2xs flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-slate-100 border border-slate-200/60 flex items-center justify-center text-slate-700 shrink-0">
            <Layers className="w-5 h-5 text-slate-700" />
          </div>
          <div className="min-w-0">
            <div className="text-xs font-medium text-slate-500 leading-none mb-1.5">Total proyectos</div>
            <div className="text-xl sm:text-2xl font-extrabold text-slate-900 tracking-tight leading-none tabular-nums">
              {stats.total}
            </div>
          </div>
        </div>

        <div className="bg-white rounded-2xl border border-slate-200/80 p-3.5 sm:p-4 shadow-2xs flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-emerald-50 border border-emerald-200/70 text-emerald-600 flex items-center justify-center shrink-0">
            <CheckCircle2 className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <div className="text-xs font-medium text-slate-500 leading-none mb-1.5">Activos</div>
            <div className="text-xl sm:text-2xl font-extrabold text-slate-900 tracking-tight leading-none flex items-center gap-2 tabular-nums">
              <span>{stats.active}</span>
              {stats.active > 0 && (
                <span className="relative flex h-2.5 w-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="bg-white rounded-2xl border border-slate-200/80 p-3.5 sm:p-4 shadow-2xs flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-amber-50 border border-amber-200/70 text-amber-600 flex items-center justify-center shrink-0">
            <Zap className="w-5 h-5 fill-amber-500 text-amber-600" />
          </div>
          <div className="min-w-0">
            <div className="text-xs font-medium text-slate-500 leading-none mb-1.5">En ejecución local</div>
            <div className="text-xl sm:text-2xl font-extrabold text-slate-900 tracking-tight leading-none flex items-baseline gap-1 tabular-nums">
              <span>{stats.local}</span>
              <span className="text-xs font-normal text-slate-400">/ {stats.configuredLocal}</span>
            </div>
          </div>
        </div>

        <button
          type="button"
          onClick={onOpenDomains}
          className="bg-white rounded-2xl border border-slate-200/80 hover:border-slate-300 p-3.5 sm:p-4 shadow-2xs flex items-center gap-3.5 text-left transition-colors cursor-pointer"
        >
          <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-200/70 text-blue-600 flex items-center justify-center shrink-0">
            <Globe className="w-5 h-5 text-blue-600" />
          </div>
          <div className="min-w-0">
            <div className="text-xs font-medium text-slate-500 leading-none mb-1.5">Dominios vinculados</div>
            <div className="text-xl sm:text-2xl font-extrabold text-slate-900 tracking-tight leading-none flex items-center gap-1.5 tabular-nums">
              <span>{stats.totalDomains}</span>
              <span className="text-[11px] font-medium text-slate-500 bg-slate-100 px-1.5 py-0.5 rounded-md border border-slate-200">
                Gestionar →
              </span>
            </div>
          </div>
        </button>
      </div>

      {/* 3. Search, Filter & View Controls */}
      <div className="bg-white rounded-2xl border border-slate-200/90 shadow-2xs p-3 flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            id="omnibar"
            type="text"
            placeholder="Buscar por nombre, repositorio, dominio o tecnología… (⌘K)"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9.5 pr-14 py-2 bg-slate-50/70 hover:bg-slate-50 focus:bg-white border border-slate-200 rounded-xl text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none transition-all"
          />
          {search ? (
            <button
              type="button"
              onClick={() => setSearch('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-slate-600 rounded-md cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          ) : (
            <kbd className="hidden sm:inline-flex items-center absolute right-3 top-1/2 -translate-y-1/2 px-1.5 py-0.5 text-[10px] font-mono text-slate-400 bg-white border border-slate-200 rounded shadow-2xs">
              ⌘K
            </kbd>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 justify-between lg:justify-end">
          <div className="flex items-center bg-slate-100/90 p-1 rounded-xl border border-slate-200/70 text-xs overflow-x-auto">
            {([
              { id: 'all', label: `Todos (${stats.total})` },
              { id: 'active', label: `Activos (${stats.active})` },
              { id: 'local', label: `En local (${stats.local})` },
              { id: 'hibernated', label: `Detenidos (${stats.inactive})` }
            ] as const).map((pill) => (
              <button
                key={pill.id}
                type="button"
                onClick={() => setFilter(pill.id)}
                className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
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
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as any)}
            className="bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-semibold rounded-xl px-3 py-2 focus:outline-none cursor-pointer shadow-2xs"
          >
            <option value="recent">Más recientes</option>
            <option value="name">Nombre (A-Z)</option>
            <option value="domains">Más dominios</option>
            <option value="status">Estado (Activos)</option>
          </select>

          <div className="flex bg-slate-100/90 p-1 rounded-xl border border-slate-200/70">
            <button
              type="button"
              onClick={() => setView('grid')}
              title="Vista en cuadrícula"
              className={`p-1.5 rounded-lg transition-all cursor-pointer ${
                view === 'grid' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-400 hover:text-slate-700'
              }`}
            >
              <LayoutGrid className="w-4 h-4" />
            </button>
            <button
              type="button"
              onClick={() => setView('table')}
              title="Vista en tabla"
              className={`p-1.5 rounded-lg transition-all cursor-pointer ${
                view === 'table' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-400 hover:text-slate-700'
              }`}
            >
              <List className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* 4. Loading Skeleton */}
      {loading && projects.length === 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 items-stretch">
          {[1, 2, 3].map((i) => (
            <div key={i} className="bg-white border border-slate-200/90 rounded-2xl p-5 shadow-xs animate-pulse h-[240px]" />
          ))}
        </div>
      ) : filtered.length > 0 && view === 'grid' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 items-stretch">
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
                onClick={() => onSelectProject(p.id)}
                className="group relative bg-white border border-slate-200/80 hover:border-slate-300 rounded-2xl p-5 shadow-2xs hover:shadow-md hover:-translate-y-0.5 transition-all duration-200 ease-out cursor-pointer flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start justify-between gap-3 mb-3">
                    <div className="flex items-start gap-3 min-w-0">
                      <div className={`w-11 h-11 rounded-xl flex items-center justify-center shrink-0 border ${meta.iconBg} ${meta.iconBorder} ${meta.iconText} shadow-2xs`}>
                        <IconComponent className="w-5 h-5" />
                      </div>
                      <div className="min-w-0">
                        <h3 className="text-base font-bold text-slate-900 group-hover:text-blue-600 transition-colors tracking-tight truncate">
                          {p.name}
                        </h3>
                        {meta.cleanGit ? (
                          <div className="flex items-center gap-1.5 text-xs text-slate-500 font-mono mt-0.5">
                            <GitBranch className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                            <span className="truncate max-w-[170px]" title={meta.cleanGit}>{meta.cleanGit}</span>
                          </div>
                        ) : (
                          <div className="text-xs text-slate-400 mt-0.5">Proyecto sin repositorio Git</div>
                        )}
                      </div>
                    </div>

                    <div className="flex flex-col items-end gap-1.5 shrink-0">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold ${
                          p.status === 'active'
                            ? 'bg-emerald-50 text-emerald-700 border border-emerald-200/80'
                            : p.status === 'hibernated'
                              ? 'bg-sky-50 text-sky-700 border border-sky-200/80'
                              : 'bg-slate-100 text-slate-600 border border-slate-200'
                        }`}
                      >
                        <span className={`w-2 h-2 rounded-full ${
                          p.status === 'active' ? 'bg-emerald-500' : p.status === 'hibernated' ? 'bg-sky-400' : 'bg-slate-400'
                        }`} />
                        {p.status === 'active' ? 'Activo' : p.status === 'hibernated' ? 'Hibernado' : 'Detenido'}
                      </span>

                      {p.localRunning && p.localPort ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-amber-50 text-amber-700 border border-amber-200/80">
                          <Zap className="w-3 h-3 text-amber-600 fill-amber-500" />
                          <span>:{p.localPort}</span>
                        </span>
                      ) : null}
                    </div>
                  </div>

                  <p className="text-xs text-slate-600 line-clamp-2 leading-relaxed min-h-[34px] mb-3">
                    {p.description || 'Sin descripción configurada.'}
                  </p>

                  <div className="flex flex-wrap items-center gap-1.5 mb-3.5">
                    {meta.appsCount > 0 && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-slate-100 text-slate-700 border border-slate-200/70">
                        <Layers className="w-3 h-3 text-slate-500" />
                        {meta.appsCount} {meta.appsCount === 1 ? 'app' : 'apps'}
                      </span>
                    )}
                    {meta.dbsCount > 0 && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200/70">
                        <Database className="w-3 h-3 text-indigo-500" />
                        {meta.dbType || 'Base de datos'}
                      </span>
                    )}
                    {meta.servicesCount > 0 && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-slate-100 text-slate-700 border border-slate-200/70">
                        <Server className="w-3 h-3 text-slate-500" />
                        {meta.servicesCount} servicio{meta.servicesCount > 1 ? 's' : ''}
                      </span>
                    )}
                    {meta.techTags.map((tag) => (
                      <span key={tag} className="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-medium bg-slate-50 text-slate-600 border border-slate-200/80">
                        {tag}
                      </span>
                    ))}
                  </div>

                  {/* Estado honesto de ejecución / despliegue */}
                  {hasTrafficSplit ? (
                    <div className="bg-slate-50/90 rounded-xl p-2.5 border border-slate-100 mb-3.5">
                      <div className="flex items-center justify-between text-[11px] mb-1.5 font-mono">
                        <span className="font-semibold text-slate-700 font-sans flex items-center gap-1.5">
                          <Radio className="w-3 h-3 text-amber-500" />
                          Reparto de tráfico
                        </span>
                        <span className="text-slate-500 font-medium">{citadelPct}% Prod · {forgePct}% Dev</span>
                      </div>
                      <div className="w-full h-1.5 bg-slate-200 rounded-full overflow-hidden flex">
                        <div className="bg-emerald-500 h-full" style={{ width: `${citadelPct}%` }} />
                        <div className="bg-amber-400 h-full" style={{ width: `${forgePct}%` }} />
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-center justify-between px-3 py-2 rounded-xl bg-slate-50/80 border border-slate-100 mb-3.5 text-[11px]">
                      <span className="text-slate-500 font-medium">Entorno</span>
                      {p.localRunning && p.localPort ? (
                        <span className="font-mono font-semibold text-amber-700">Local activo en :{p.localPort}</span>
                      ) : p.lastDeployedAt ? (
                        <span className="font-medium text-emerald-700">
                          Desplegado {new Date(p.lastDeployedAt).toLocaleDateString('es-ES')}
                        </span>
                      ) : (
                        <span className="text-slate-500">Listo para desplegar</span>
                      )}
                    </div>
                  )}

                  {/* Domains */}
                  <div className="min-h-[28px] flex items-center justify-between gap-2">
                    {p.domains && p.domains.length > 0 ? (
                      <div className="flex items-center justify-between w-full gap-2">
                        <a
                          href={`https://${p.domains[0]}`}
                          target="_blank"
                          rel="noreferrer"
                          onClick={(e) => e.stopPropagation()}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono font-medium text-slate-700 bg-slate-50 hover:bg-slate-100 hover:text-blue-600 border border-slate-200/80 transition-all max-w-[220px] truncate"
                          title={`Abrir https://${p.domains[0]}`}
                        >
                          <Lock className="w-3 h-3 text-emerald-600 shrink-0" />
                          <span className="truncate">{p.domains[0]}</span>
                          <ExternalLink className="w-2.5 h-2.5 text-slate-400 shrink-0" />
                        </a>
                        {p.domains.length > 1 && (
                          <span className="text-[10px] font-mono font-semibold text-slate-600 bg-slate-100 border border-slate-200/80 px-1.5 py-0.5 rounded-md">
                            +{p.domains.length - 1}
                          </span>
                        )}
                      </div>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-[11px] text-slate-400">
                        <Globe className="w-3.5 h-3.5 text-slate-300" />
                        Sin dominio público todavía
                      </span>
                    )}
                  </div>
                </div>

                {/* Card Action Footer */}
                <div className="mt-4 pt-3.5 border-t border-slate-100 flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    {p.localRunning ? (
                      <>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            window.open(`http://localhost:${p.localPort}`, '_blank');
                          }}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-amber-800 bg-amber-50 hover:bg-amber-100 border border-amber-200/80 rounded-xl cursor-pointer"
                        >
                          <Zap className="w-3.5 h-3.5 fill-amber-500 text-amber-600" />
                          <span>Abrir :{p.localPort}</span>
                        </button>
                        <button
                          type="button"
                          onClick={(e) => handleStopLocal(e, p.id)}
                          disabled={stoppingLocalId === p.id}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-semibold text-rose-700 bg-rose-50 hover:bg-rose-100 border border-rose-200/80 rounded-xl cursor-pointer disabled:opacity-50"
                        >
                          <Square className="w-3 h-3 fill-rose-600 text-rose-600" />
                          <span>{stoppingLocalId === p.id ? 'Parando…' : 'Detener'}</span>
                        </button>
                      </>
                    ) : (
                      <>
                        <button
                          type="button"
                          onClick={(e) => handleStartLocal(e, p.id)}
                          disabled={isStartingThisLocal}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200/80 border border-slate-200 rounded-xl cursor-pointer disabled:opacity-50"
                        >
                          <Play className={`w-3.5 h-3.5 text-slate-600 ${isStartingThisLocal ? 'animate-spin' : ''}`} />
                          <span>{isStartingThisLocal ? 'Iniciando…' : 'Iniciar local'}</span>
                        </button>
                        {p.status !== 'active' && (
                          <button
                            type="button"
                            onClick={(e) => handleActivate(e, p.id)}
                            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-emerald-700 bg-emerald-50 hover:bg-emerald-100 border border-emerald-200/80 rounded-xl cursor-pointer"
                          >
                            <Power className="w-3 h-3 text-emerald-600" />
                            <span>Activar</span>
                          </button>
                        )}
                      </>
                    )}
                  </div>

                  <div className="flex items-center gap-1 text-xs font-semibold text-slate-700 group-hover:text-blue-600 transition-colors ml-auto">
                    <span>Abrir</span>
                    <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      ) : filtered.length > 0 ? (
        <div className="bg-white border border-slate-200/90 rounded-2xl shadow-2xs overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200">
              <thead className="bg-slate-50/80 border-b border-slate-200/70">
                <tr>
                  <th className="px-6 py-3.5 text-left text-xs font-semibold text-slate-500">Proyecto</th>
                  <th className="px-6 py-3.5 text-left text-xs font-semibold text-slate-500">Estado</th>
                  <th className="px-6 py-3.5 text-left text-xs font-semibold text-slate-500">Componentes</th>
                  <th className="px-6 py-3.5 text-left text-xs font-semibold text-slate-500">Dominios</th>
                  <th className="px-6 py-3.5 text-right text-xs font-semibold text-slate-500">Acciones</th>
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
                      className="hover:bg-slate-50/80 transition-colors cursor-pointer group"
                    >
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-3">
                          <div className={`w-9 h-9 rounded-xl flex items-center justify-center shrink-0 border ${meta.iconBg} ${meta.iconBorder} ${meta.iconText}`}>
                            <IconComponent className="w-4 h-4" />
                          </div>
                          <div className="min-w-0">
                            <div className="text-sm font-bold text-slate-900 group-hover:text-blue-600">{p.name}</div>
                            <div className="text-xs text-slate-400 truncate max-w-[220px] font-mono">
                              {meta.cleanGit || p.description || 'Sin descripción'}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${
                          p.status === 'active'
                            ? 'bg-emerald-50 text-emerald-700 border border-emerald-200/80'
                            : p.status === 'hibernated'
                              ? 'bg-sky-50 text-sky-700 border border-sky-200/80'
                              : 'bg-slate-100 text-slate-600 border border-slate-200'
                        }`}>
                          {p.status === 'active' ? 'Activo' : p.status === 'hibernated' ? 'Hibernado' : 'Detenido'}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-xs text-slate-600">
                        {meta.appsCount} app{meta.appsCount !== 1 ? 's' : ''}
                        {meta.dbsCount > 0 ? ` · ${meta.dbType || 'BD'}` : ''}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {p.domains && p.domains.length > 0 ? (
                          <span className="font-mono text-xs text-slate-700 bg-slate-50 border border-slate-200 px-2 py-0.5 rounded-md inline-flex items-center gap-1">
                            <Lock className="w-2.5 h-2.5 text-emerald-600" />
                            {p.domains[0]}
                          </span>
                        ) : (
                          <span className="text-xs text-slate-400">Sin dominio</span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right">
                        <span className="inline-flex items-center gap-1 text-xs font-semibold text-slate-700 group-hover:text-blue-600">
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

      {/* Empty State */}
      {!loading && filtered.length === 0 && (
        <div className="bg-white border border-slate-200 rounded-2xl p-10 text-center shadow-2xs max-w-2xl mx-auto">
          {projects.length === 0 ? (
            <div className="space-y-4">
              <div className="w-14 h-14 rounded-2xl bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center mx-auto">
                <Boxes className="w-7 h-7" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-900">Empieza con tu primer proyecto</h3>
                <p className="text-sm text-slate-500 mt-1 max-w-md mx-auto">
                  Puedes subir un repositorio Git, traer tu web de WordPress, importar desde Coolify/Compose o instalar una app en 1 clic.
                </p>
              </div>
              <div className="flex flex-wrap items-center justify-center gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(true)}
                  className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold text-white bg-slate-900 hover:bg-slate-800 shadow-sm cursor-pointer"
                >
                  <Plus className="w-4 h-4" />
                  <span>Crear proyecto</span>
                </button>
                <button
                  type="button"
                  onClick={onOpenWordPress || onImportCoolify}
                  className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold text-slate-700 bg-white hover:bg-slate-50 border border-slate-200 cursor-pointer"
                >
                  <Globe className="w-4 h-4 text-blue-600" />
                  <span>Migrar mi WordPress</span>
                </button>
                <button
                  type="button"
                  onClick={onImportCoolify}
                  className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold text-slate-700 bg-white hover:bg-slate-50 border border-slate-200 cursor-pointer"
                >
                  <Download className="w-4 h-4 text-slate-500" />
                  <span>Importar de otra plataforma</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="w-12 h-12 rounded-xl bg-slate-100 text-slate-400 flex items-center justify-center mx-auto">
                <Search className="w-6 h-6" />
              </div>
              <h3 className="text-base font-bold text-slate-900">
                No se encontraron proyectos para «{search}»
              </h3>
              <button
                type="button"
                onClick={() => { setSearch(''); setFilter('all'); }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg cursor-pointer"
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
