import React, { useState, useEffect, useMemo } from 'react';
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
  Sparkles,
  ShoppingBag,
  Gamepad2,
  Cpu,
  Wrench,
  CheckCircle2,
  X,
  Boxes,
  RefreshCw,
  Play,
  Square,
  ShieldCheck,
  Power
} from 'lucide-react';
import { api, type Project } from '../lib/api';
import { CreateProjectModal } from './CreateProjectModal';

interface ProjectListProps {
  onSelectProject: (id: string) => void;
  onImportCoolify: () => void;
  projects?: Project[];
  onRefreshProjects?: () => void;
  onNotify?: (msg: string) => void;
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
  accentBadge: string;
}

/**
 * Extract dynamic project metadata from resources, envVars and configuration.
 * Avoids rigid hardcoding, allowing any imported or newly created project to
 * inherit correct architectural metrics, clean Git repo identifiers and custom themes.
 */
function getProjectMetadata(p: Project): ProjectMetadata {
  const nameLower = (p.name || '').toLowerCase();
  const descLower = (p.description || '').toLowerCase();

  // 1. Resolve Git repository (root or from resources)
  let rawGit = p.gitRepo || '';
  if (!rawGit && p.resources && Array.isArray(p.resources)) {
    const resWithGit = p.resources.find((r: any) => r.gitRepo);
    if (resWithGit) rawGit = resWithGit.gitRepo;
  }

  const cleanGit = rawGit
    ? rawGit
        .replace(/^git@github\.com:/, '')
        .replace(/^https?:\/\/github\.com\//, '')
        .replace(/\.git$/, '')
    : null;

  // 2. Aggregate all environment variables across project and child resources
  const allEnvVars: Record<string, string> = { ...(p.envVars || {}) };
  if (p.resources && Array.isArray(p.resources)) {
    for (const res of p.resources) {
      if (res.envVars && typeof res.envVars === 'object') {
        Object.assign(allEnvVars, res.envVars);
      }
    }
  }
  const envKeys = Object.keys(allEnvVars).join(' ');

  // 3. Count architectural components
  const apps = (p.resources || []).filter((r: any) => r.type === 'app');
  const appsCount = apps.length || (p.source !== 'coolify-import' ? 1 : 0);
  const dbs = (p.resources || []).filter((r: any) => r.type === 'database');
  const dbsCount = dbs.length;
  const services = (p.resources || []).filter((r: any) => r.type === 'service');
  const servicesCount = services.length;

  // 4. Resolve Database type
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
    } else if (dbTypeProp.includes('redis') || dbName.includes('redis') || dbUrl.includes('redis')) {
      dbType = 'Redis';
    } else if (dbTypeProp.includes('mongo') || dbName.includes('mongo') || dbUrl.includes('mongo')) {
      dbType = 'MongoDB';
    } else if (dbTypeProp.includes('sqlite') || dbName.includes('sqlite')) {
      dbType = 'SQLite';
    } else {
      dbType = 'Base de datos';
    }
  } else if (servicesCount > 0 && (nameLower.includes('pocketbase') || descLower.includes('pocketbase'))) {
    dbType = 'SQLite';
  }

  // 5. Detect framework and technology stack tags
  const tags: string[] = [];
  const buildPacks = (p.resources || []).map((r: any) => r.buildConfig?.build_pack || '').filter(Boolean);

  if (envKeys.includes('NEXT_PUBLIC') || envKeys.includes('NEXT_') || descLower.includes('next')) {
    tags.push('Next.js');
  } else if (descLower.includes('vite') || descLower.includes('react')) {
    tags.push('React');
  }

  if (envKeys.includes('BETTER_AUTH') || envKeys.includes('AUTH_') || envKeys.includes('JWT')) {
    tags.push('Auth Ready');
  }

  if (envKeys.includes('GEMINI_API') || envKeys.includes('OPENAI_API') || descLower.includes('ia') || nameLower.includes('ia')) {
    tags.push('IA Native');
  }

  if (buildPacks.includes('nixpacks')) {
    tags.push('Nixpacks');
  } else if (buildPacks.includes('dockerfile') || p.source === 'coolify-import') {
    tags.push('Docker');
  }

  if (nameLower.includes('api') || descLower.includes('proxy') || descLower.includes('gateway')) {
    if (!tags.includes('API Gateway')) tags.unshift('API Gateway');
  }

  if (nameLower.includes('game') || descLower.includes('arcade') || nameLower.includes('flappy')) {
    if (!tags.includes('HTML5 Canvas')) tags.unshift('HTML5 Canvas');
  }

  if (nameLower.includes('tool') || descLower.includes('devtool') || descLower.includes('suite')) {
    if (!tags.includes('TypeScript')) tags.push('TypeScript');
  }

  if (servicesCount > 0 && (nameLower.includes('pocketbase') || descLower.includes('pocketbase'))) {
    tags.length = 0;
    tags.push('BaaS Engine', 'Go Runtime', 'Auth & Storage');
  }

  if (tags.length === 0) {
    if (appsCount > 0) tags.push('Web App', 'Docker');
    else tags.push('Microservicio');
  }

  const techTags = Array.from(new Set(tags)).slice(0, 3);

  // 6. Distinctive icon and harmonic palette per project archetype
  let IconComponent = Boxes;
  let iconBg = 'bg-blue-50/80';
  let iconText = 'text-blue-600';
  let iconBorder = 'border-blue-100';
  let accentBadge = 'bg-blue-50 text-blue-700 border-blue-200/80';

  if (nameLower.includes('caleki') || descLower.includes('reserva') || descLower.includes('belleza')) {
    IconComponent = Sparkles;
    iconBg = 'bg-indigo-50/80';
    iconText = 'text-indigo-600';
    iconBorder = 'border-indigo-100';
    accentBadge = 'bg-indigo-50 text-indigo-700 border-indigo-200/80';
  } else if (nameLower.includes('calma') || descLower.includes('suplemento') || descLower.includes('tienda') || descLower.includes('commerce')) {
    IconComponent = ShoppingBag;
    iconBg = 'bg-emerald-50/80';
    iconText = 'text-emerald-600';
    iconBorder = 'border-emerald-100';
    accentBadge = 'bg-emerald-50 text-emerald-700 border-emerald-200/80';
  } else if (nameLower.includes('flappy') || descLower.includes('game') || descLower.includes('arcade')) {
    IconComponent = Gamepad2;
    iconBg = 'bg-amber-50/80';
    iconText = 'text-amber-600';
    iconBorder = 'border-amber-100';
    accentBadge = 'bg-amber-50 text-amber-700 border-amber-200/80';
  } else if (nameLower.includes('galeia') || nameLower.includes('api') || descLower.includes('proxy')) {
    IconComponent = Cpu;
    iconBg = 'bg-cyan-50/80';
    iconText = 'text-cyan-600';
    iconBorder = 'border-cyan-100';
    accentBadge = 'bg-cyan-50 text-cyan-700 border-cyan-200/80';
  } else if (nameLower.includes('tool') || descLower.includes('tools')) {
    IconComponent = Wrench;
    iconBg = 'bg-purple-50/80';
    iconText = 'text-purple-600';
    iconBorder = 'border-purple-100';
    accentBadge = 'bg-purple-50 text-purple-700 border-purple-200/80';
  } else if (nameLower.includes('pocketbase') || servicesCount > 0 || dbsCount > 0) {
    IconComponent = Database;
    iconBg = 'bg-rose-50/80';
    iconText = 'text-rose-600';
    iconBorder = 'border-rose-100';
    accentBadge = 'bg-rose-50 text-rose-700 border-rose-200/80';
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
    IconComponent,
    accentBadge
  };
}

export const ProjectList: React.FC<ProjectListProps> = ({
  onSelectProject,
  onImportCoolify,
  projects: parentProjects,
  onRefreshProjects,
  onNotify
}) => {
  const [localProjects, setLocalProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [startingLocalId, setStartingLocalId] = useState<string | null>(null);
  const [stoppingLocalId, setStoppingLocalId] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<'all' | 'active' | 'hibernated' | 'local'>('all');
  const [view, setView] = useState<'grid' | 'table'>('grid');
  const [sortBy, setSortBy] = useState<'recent' | 'name' | 'domains' | 'status'>('recent');
  const [showCreateModal, setShowCreateModal] = useState(false);

  // Sync parentProjects into localProjects whenever the parent refetches
  // (derived during render to avoid cascading setState-in-effect renders).
  const [prevParentProjects, setPrevParentProjects] = useState(parentProjects);
  if (parentProjects !== prevParentProjects) {
    setPrevParentProjects(parentProjects);
    if (Array.isArray(parentProjects)) {
      setLocalProjects(parentProjects);
      if (parentProjects.length > 0) setLoading(false);
    }
  }

  const fetchProjects = () => {
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
    onRefreshProjects?.();
  };

  useEffect(() => {
    let active = true;
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
  }, []);

  const handleStartLocal = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    try {
      setStartingLocalId(id);
      setLocalProjects(prev => prev.map(p => p.id === id ? { ...p, status: 'active', localRunning: true } : p));
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
      setLocalProjects(prev => prev.map(p => p.id === id ? { ...p, status: 'stopped', localRunning: false } : p));
      await api.stopProject(id);
      fetchProjects();
      onNotify?.('Proyecto detenido: procesos finalizados y puerto liberado');
    } catch (err) {
      console.error(err);
      onNotify?.('Error al detener proyecto');
      fetchProjects();
    } finally {
      setStoppingLocalId(null);
    }
  };

  const handleActivate = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    try {
      setLocalProjects(prev => prev.map(p => p.id === id ? { ...p, status: 'active' } : p));
      await api.activateProject(id);
      fetchProjects();
      onNotify?.('Proyecto activado en producción');
    } catch (err) {
      console.error(err);
      onNotify?.('Error al activar proyecto');
      fetchProjects();
    }
  };

  const projects = localProjects;

  // Real-time cluster metrics calculation
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

  // Deep search matching name, git, description, domain, database and stack tags
  const filtered = useMemo(() => {
    return projects
      .filter((p) => {
        if (filter === 'active' && p.status !== 'active') return false;
        if (filter === 'hibernated' && p.status !== 'hibernated' && p.status !== 'stopped') return false;
        if (filter === 'local' && !p.localRunning) return false;

        if (search.trim()) {
          const q = search.toLowerCase();
          const meta = getProjectMetadata(p);
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
  }, [projects, filter, search, sortBy]);

  return (
    <div className="space-y-6">
      {/* 1. Header & Primary Cluster Actions */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">Mis Proyectos</h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200/80 shadow-2xs">
              {stats.total} {stats.total === 1 ? 'proyecto' : 'proyectos'}
            </span>
          </div>
          <p className="text-sm text-slate-500 mt-1">
            Orquestador autohospedado con control nativo por agentes de IA, gestión de dominios y ejecución local de proyectos.
          </p>
        </div>

        <div className="flex items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={onImportCoolify}
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold text-slate-700 bg-white hover:bg-slate-50 border border-slate-200/90 shadow-2xs hover:border-slate-300 transition-all duration-150 active:scale-[0.98] cursor-pointer"
          >
            <Download className="w-4 h-4 text-slate-500" />
            <span>Importar desde Coolify</span>
          </button>

          <button
            type="button"
            onClick={() => setShowCreateModal(true)}
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold text-white bg-slate-900 hover:bg-slate-800 shadow-sm hover:shadow transition-all duration-150 active:scale-[0.98] cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Nuevo Proyecto</span>
          </button>
        </div>
      </div>

      {/* 2. Responsive Cluster Metrics Ribbon (Clean, Non-Truncating) */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        {/* Total Projects */}
        <div className="bg-white rounded-2xl border border-slate-200/80 p-3.5 sm:p-4 shadow-2xs flex items-center gap-3.5 hover:border-slate-300 transition-colors">
          <div className="w-10 h-10 rounded-xl bg-slate-100 border border-slate-200/60 flex items-center justify-center text-slate-700 shrink-0">
            <Layers className="w-5 h-5 text-slate-700" />
          </div>
          <div className="min-w-0">
            <div className="text-xs font-medium text-slate-500 leading-none mb-1.5">Total Proyectos</div>
            <div className="text-xl sm:text-2xl font-extrabold text-slate-900 tracking-tight leading-none">
              {stats.total}
            </div>
          </div>
        </div>

        {/* Active Production */}
        <div className="bg-white rounded-2xl border border-slate-200/80 p-3.5 sm:p-4 shadow-2xs flex items-center gap-3.5 hover:border-slate-300 transition-colors">
          <div className="w-10 h-10 rounded-xl bg-emerald-50 border border-emerald-200/70 text-emerald-600 flex items-center justify-center shrink-0">
            <CheckCircle2 className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <div className="text-xs font-medium text-slate-500 leading-none mb-1.5">Producción Activa</div>
            <div className="text-xl sm:text-2xl font-extrabold text-slate-900 tracking-tight leading-none flex items-center gap-2">
              <span>{stats.active}</span>
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
              </span>
            </div>
          </div>
        </div>

        {/* Local Environments */}
        <div className="bg-white rounded-2xl border border-slate-200/80 p-3.5 sm:p-4 shadow-2xs flex items-center gap-3.5 hover:border-slate-300 transition-colors">
          <div className="w-10 h-10 rounded-xl bg-amber-50 border border-amber-200/70 text-amber-600 flex items-center justify-center shrink-0">
            <Zap className="w-5 h-5 fill-amber-500 text-amber-600" />
          </div>
          <div className="min-w-0">
            <div className="text-xs font-medium text-slate-500 leading-none mb-1.5">Entornos Locales</div>
            <div className="text-xl sm:text-2xl font-extrabold text-slate-900 tracking-tight leading-none flex items-baseline gap-1">
              <span>{stats.local}</span>
              <span className="text-xs font-normal text-slate-400">/ {stats.configuredLocal}</span>
            </div>
          </div>
        </div>

        {/* Cloudflare SSL Domains */}
        <div className="bg-white rounded-2xl border border-slate-200/80 p-3.5 sm:p-4 shadow-2xs flex items-center gap-3.5 hover:border-slate-300 transition-colors">
          <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-200/70 text-blue-600 flex items-center justify-center shrink-0">
            <Globe className="w-5 h-5 text-blue-600" />
          </div>
          <div className="min-w-0">
            <div className="text-xs font-medium text-slate-500 leading-none mb-1.5">Dominios SSL</div>
            <div className="text-xl sm:text-2xl font-extrabold text-slate-900 tracking-tight leading-none flex items-center gap-1.5">
              <span>{stats.totalDomains}</span>
              <span className="text-[11px] font-semibold text-emerald-700 bg-emerald-50 px-1.5 py-0.5 rounded-md border border-emerald-200/70">
                ✓ Wildcard
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* 3. Search, Filter & View Controls (Railway / Linear Polish) */}
      <div className="bg-white rounded-2xl border border-slate-200/90 shadow-2xs p-3 flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3">
        {/* Search Input */}
        <div className="relative flex-1">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            id="omnibar"
            type="text"
            placeholder="Buscar por nombre, repositorio, dominio o tecnología... (⌘K)"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9.5 pr-14 py-2 bg-slate-50/70 hover:bg-slate-50 focus:bg-white border border-slate-200 rounded-xl text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-400 transition-all"
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

        {/* Filter Badges & View Switcher */}
        <div className="flex flex-wrap items-center gap-2 justify-between lg:justify-end">
          {/* Status Filter Pills */}
          <div className="flex items-center bg-slate-100/90 p-1 rounded-xl border border-slate-200/70 text-xs overflow-x-auto">
            <button
              type="button"
              onClick={() => setFilter('all')}
              className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
                filter === 'all'
                  ? 'bg-white text-slate-900 shadow-2xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Todos ({stats.total})
            </button>
            <button
              type="button"
              onClick={() => setFilter('active')}
              className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
                filter === 'active'
                  ? 'bg-white text-emerald-700 shadow-2xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Activos ({stats.active})
            </button>
            <button
              type="button"
              onClick={() => setFilter('local')}
              className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
                filter === 'local'
                  ? 'bg-white text-blue-700 shadow-2xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              En Local ({stats.local})
            </button>
            <button
              type="button"
              onClick={() => setFilter('hibernated')}
              className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
                filter === 'hibernated'
                  ? 'bg-white text-slate-700 shadow-2xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Detenidos ({stats.inactive})
            </button>
          </div>

          {/* Sort Selector */}
          <div className="relative">
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="appearance-none bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-semibold rounded-xl pl-3 pr-8 py-2 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-400 cursor-pointer shadow-2xs transition-all"
            >
              <option value="recent">Más recientes</option>
              <option value="name">Nombre (A-Z)</option>
              <option value="domains">Más dominios</option>
              <option value="status">Estado (Activos)</option>
            </select>
            <div className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400">
              <svg className="w-3.5 h-3.5 fill-current" viewBox="0 0 20 20">
                <path d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" />
              </svg>
            </div>
          </div>

          {/* View Toggle */}
          <div className="flex bg-slate-100/90 p-1 rounded-xl border border-slate-200/70">
            <button
              type="button"
              onClick={() => setView('grid')}
              title="Vista en Cuadrícula"
              className={`p-1.5 rounded-lg transition-all cursor-pointer ${
                view === 'grid'
                  ? 'bg-white text-slate-900 shadow-2xs'
                  : 'text-slate-400 hover:text-slate-700'
              }`}
            >
              <LayoutGrid className="w-4 h-4" />
            </button>
            <button
              type="button"
              onClick={() => setView('table')}
              title="Vista en Tabla"
              className={`p-1.5 rounded-lg transition-all cursor-pointer ${
                view === 'table'
                  ? 'bg-white text-slate-900 shadow-2xs'
                  : 'text-slate-400 hover:text-slate-700'
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
          {[1, 2, 3, 4, 5, 6].map((i) => (
            <div
              key={i}
              className="bg-white border border-slate-200/90 rounded-2xl p-5 shadow-xs animate-pulse flex flex-col justify-between h-[280px]"
            >
              <div>
                <div className="flex items-start justify-between gap-3 mb-3">
                  <div className="flex items-start gap-3">
                    <div className="w-12 h-12 rounded-xl bg-slate-100" />
                    <div className="space-y-2 pt-1">
                      <div className="w-24 h-4 bg-slate-200 rounded" />
                      <div className="w-32 h-3 bg-slate-100 rounded" />
                    </div>
                  </div>
                  <div className="w-16 h-6 bg-slate-100 rounded-full" />
                </div>
                <div className="space-y-1.5 mt-4">
                  <div className="w-full h-3 bg-slate-100 rounded" />
                  <div className="w-3/4 h-3 bg-slate-100 rounded" />
                </div>
              </div>
              <div className="border-t border-slate-100 pt-3 flex justify-between">
                <div className="w-16 h-6 bg-slate-100 rounded" />
                <div className="w-20 h-4 bg-slate-100 rounded" />
              </div>
            </div>
          ))}
        </div>
      ) : view === 'grid' ? (
        /* 5. Projects Grid View (Ultra Premium Vercel / Railway Craftsmanship) */
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 items-stretch">
          {filtered.map((p) => {
            const meta = getProjectMetadata(p);
            const { IconComponent } = meta;
            const forgePct = p.trafficSplit?.forge || 0;
            const citadelPct = p.trafficSplit?.citadel ?? 100;
            const isStartingThisLocal = startingLocalId === p.id;

            return (
              <div
                key={p.id}
                onClick={() => onSelectProject(p.id)}
                className="group relative bg-white border border-slate-200/80 hover:border-slate-300 rounded-2xl p-5 shadow-2xs hover:shadow-[0_12px_24px_-4px_rgba(0,0,0,0.06),0_4px_8px_-2px_rgba(0,0,0,0.03)] hover:-translate-y-0.5 transition-all duration-200 ease-out cursor-pointer flex flex-col justify-between"
              >
                <div>
                  {/* Top Row: Identity & Status Badges */}
                  <div className="flex items-start justify-between gap-3 mb-3">
                    <div className="flex items-start gap-3 min-w-0">
                      {/* Stylized Distinctive App Icon */}
                      <div
                        className={`w-11 h-11 rounded-xl flex items-center justify-center shrink-0 border ${meta.iconBg} ${meta.iconBorder} ${meta.iconText} shadow-2xs group-hover:scale-105 transition-transform duration-200`}
                      >
                        <IconComponent className="w-5 h-5" />
                      </div>

                      <div className="min-w-0">
                        <h3 className="text-base font-bold text-slate-900 group-hover:text-blue-600 transition-colors tracking-tight truncate">
                          {p.name}
                        </h3>

                        {meta.cleanGit ? (
                          <div className="flex items-center gap-1.5 text-xs text-slate-500 font-mono mt-0.5">
                            <GitBranch className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                            <span className="truncate max-w-[170px]" title={meta.cleanGit}>
                              {meta.cleanGit}
                            </span>
                          </div>
                        ) : (
                          <div className="text-xs text-slate-400 mt-0.5">Servicio local</div>
                        )}
                      </div>
                    </div>

                    {/* Status & Local Pills */}
                    <div className="flex flex-col items-end gap-1.5 shrink-0">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold shadow-2xs ${
                          p.status === 'active'
                            ? 'bg-emerald-50 text-emerald-700 border border-emerald-200/80'
                            : p.status === 'hibernated'
                            ? 'bg-sky-50 text-sky-700 border border-sky-200/80'
                            : 'bg-slate-100 text-slate-600 border border-slate-200'
                        }`}
                      >
                        {p.status === 'active' ? (
                          <>
                            <span className="relative flex h-2 w-2">
                              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
                            </span>
                            Activo
                          </>
                        ) : p.status === 'hibernated' ? (
                          <>
                            <span className="w-2 h-2 rounded-full bg-sky-400" />
                            Hibernado
                          </>
                        ) : (
                          <>
                            <span className="w-2 h-2 rounded-full bg-slate-400" />
                            Detenido
                          </>
                        )}
                      </span>

                      {p.localRunning ? (
                        <span
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-amber-50 text-amber-700 border border-amber-200/80 shadow-2xs"
                          title={`Servicio en ejecución local en puerto ${p.localPort}`}
                        >
                          <Zap className="w-3 h-3 text-amber-600 fill-amber-500" />
                          <span>:{p.localPort}</span>
                        </span>
                      ) : p.localPort ? (
                        <span
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono text-slate-400 bg-slate-50 border border-slate-200"
                          title={`Puerto asignado (inactivo): ${p.localPort}`}
                        >
                          <span>:{p.localPort} (off)</span>
                        </span>
                      ) : null}
                    </div>
                  </div>

                  {/* Project Description */}
                  <p className="text-xs text-slate-600 line-clamp-2 leading-relaxed min-h-[34px] mb-3">
                    {p.description || 'Microservicio orquestado en tiempo real sin descripción previa.'}
                  </p>

                  {/* Architecture & Stack Badges */}
                  <div className="flex flex-wrap items-center gap-1.5 mb-3.5">
                    {meta.appsCount > 0 && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-slate-100 text-slate-700 border border-slate-200/70">
                        <Layers className="w-3 h-3 text-slate-500" />
                        {meta.appsCount} {meta.appsCount === 1 ? 'App' : 'Apps'}
                      </span>
                    )}

                    {meta.dbsCount > 0 && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200/70">
                        <Database className="w-3 h-3 text-indigo-500" />
                        {meta.dbType || 'Base de datos'}
                      </span>
                    )}

                    {meta.servicesCount > 0 && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-rose-50 text-rose-700 border border-rose-200/70">
                        <Server className="w-3 h-3 text-rose-500" />
                        BaaS / SQLite
                      </span>
                    )}

                    {meta.techTags.map((tag) => (
                      <span
                        key={tag}
                        className="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-medium bg-slate-50 text-slate-600 border border-slate-200/80"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>

                  {/* Ingress Edge Routing (Intelligent, Non-Cluttered Display) */}
                  {forgePct > 0 ? (
                    /* Active Traffic Split (Canary / Dev Hot-Sync) */
                    <div className="bg-slate-50/90 rounded-xl p-2.5 border border-slate-100 mb-3.5">
                      <div className="flex items-center justify-between text-[11px] mb-1.5 font-mono">
                        <span className="font-semibold text-slate-700 font-sans flex items-center gap-1.5">
                          <Radio className="w-3 h-3 text-amber-500 animate-pulse" />
                          Tráfico Split (Canary)
                        </span>
                        <span className="text-slate-500 font-medium">
                          {citadelPct}% Prod (:8080) · {forgePct}% Dev (:3001)
                        </span>
                      </div>
                      <div className="w-full h-1.5 bg-slate-200 rounded-full overflow-hidden flex">
                        <div className="bg-emerald-500 h-full transition-all duration-300" style={{ width: `${citadelPct}%` }} />
                        <div className="bg-amber-400 h-full transition-all duration-300" style={{ width: `${forgePct}%` }} />
                      </div>
                    </div>
                  ) : (
                    /* Clean In-Cluster Ingress Indicator */
                    <div className="flex items-center justify-between px-3 py-2 rounded-xl bg-slate-50/80 border border-slate-100 mb-3.5 text-xs font-mono">
                      <div className="flex items-center gap-1.5 text-slate-600 font-sans font-medium text-[11px]">
                        <Radio className="w-3.5 h-3.5 text-emerald-500" />
                        <span>Ingress Edge</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-[11px]">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                        <span className="font-semibold text-slate-800">Citadel</span>
                        <span className="text-slate-400 font-mono">:8080</span>
                        <span className="text-emerald-700 font-sans font-semibold bg-emerald-50 px-1.5 py-0.5 rounded text-[10px] border border-emerald-200/60">
                          100%
                        </span>
                      </div>
                    </div>
                  )}

                  {/* Domains Section */}
                  <div className="min-h-[28px] flex items-center justify-between gap-2">
                    {p.domains && p.domains.length > 0 ? (
                      <div className="flex items-center justify-between w-full gap-2">
                        <a
                          href={`https://${p.domains[0]}`}
                          target="_blank"
                          rel="noreferrer"
                          onClick={(e) => e.stopPropagation()}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono font-medium text-slate-700 bg-slate-50 hover:bg-slate-100/90 hover:text-blue-600 border border-slate-200/80 transition-all max-w-[210px] truncate group/domain"
                          title={`Abrir https://${p.domains[0]}`}
                        >
                          <Lock className="w-3 h-3 text-emerald-600 shrink-0" />
                          <span className="truncate">{p.domains[0]}</span>
                          <ExternalLink className="w-2.5 h-2.5 text-slate-400 group-hover/domain:text-blue-600 shrink-0" />
                        </a>

                        <div className="flex items-center gap-1.5 shrink-0">
                          {p.domains.length > 1 && (
                            <span
                              className="text-[10px] font-mono font-semibold text-slate-600 bg-slate-100 border border-slate-200/80 px-1.5 py-0.5 rounded-md"
                              title={p.domains.slice(1).join(', ')}
                            >
                              +{p.domains.length - 1}
                            </span>
                          )}
                          <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-700 bg-emerald-50/90 border border-emerald-200/70 px-2 py-0.5 rounded-full">
                            <ShieldCheck className="w-3 h-3 text-emerald-600" />
                            <span className="text-[10px] font-semibold">SSL</span>
                          </span>
                        </div>
                      </div>
                    ) : (
                      <div className="flex items-center justify-between w-full text-xs text-slate-400 py-0.5">
                        <span className="inline-flex items-center gap-1.5 text-[11px]">
                          <Globe className="w-3.5 h-3.5 text-slate-300" />
                          Red interna / Sin dominio público
                        </span>
                        <span className="text-[10px] font-mono bg-slate-100 text-slate-500 px-1.5 py-0.5 rounded">
                          Cluster IP
                        </span>
                      </div>
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
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-amber-800 bg-amber-50 hover:bg-amber-100 border border-amber-200/80 rounded-xl transition-all shadow-2xs hover:shadow-xs active:scale-[0.98] cursor-pointer"
                          title={`Abrir entorno local en http://localhost:${p.localPort}`}
                        >
                          <Zap className="w-3.5 h-3.5 fill-amber-500 text-amber-600" />
                          <span>Local :{p.localPort}</span>
                        </button>
                        <button
                          type="button"
                          onClick={(e) => handleStopLocal(e, p.id)}
                          disabled={stoppingLocalId === p.id}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-semibold text-rose-700 bg-rose-50 hover:bg-rose-100 border border-rose-200/80 rounded-xl transition-all active:scale-[0.98] cursor-pointer disabled:opacity-50"
                          title="Detener servidor y liberar puerto"
                        >
                          <Square className="w-3 h-3 fill-rose-600 text-rose-600" />
                          <span>{stoppingLocalId === p.id ? 'Parando...' : 'Detener'}</span>
                        </button>
                      </>
                    ) : p.status === 'active' ? (
                      <>
                        <button
                          type="button"
                          onClick={(e) => handleStartLocal(e, p.id)}
                          disabled={isStartingThisLocal}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200/80 border border-slate-200 rounded-xl transition-all active:scale-[0.98] cursor-pointer disabled:opacity-50"
                          title={p.localPort ? `Iniciar servidor local en puerto ${p.localPort}` : 'Iniciar servidor local'}
                        >
                          <Play className={`w-3.5 h-3.5 text-slate-600 ${isStartingThisLocal ? 'animate-spin' : ''}`} />
                          <span>{isStartingThisLocal ? 'Iniciando...' : 'Iniciar Local'}</span>
                        </button>
                        <button
                          type="button"
                          onClick={(e) => handleStopLocal(e, p.id)}
                          disabled={stoppingLocalId === p.id}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-semibold text-rose-700 bg-rose-50 hover:bg-rose-100 border border-rose-200/80 rounded-xl transition-all active:scale-[0.98] cursor-pointer disabled:opacity-50"
                          title="Detener proyecto y pasar a reposo"
                        >
                          <Square className="w-3 h-3 fill-rose-600 text-rose-600" />
                          <span>{stoppingLocalId === p.id ? 'Parando...' : 'Detener'}</span>
                        </button>
                      </>
                    ) : (
                      <>
                        <button
                          type="button"
                          onClick={(e) => handleStartLocal(e, p.id)}
                          disabled={isStartingThisLocal}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200/80 border border-slate-200 rounded-xl transition-all active:scale-[0.98] cursor-pointer disabled:opacity-50"
                          title={p.localPort ? `Iniciar servidor local en puerto ${p.localPort}` : 'Iniciar servidor local'}
                        >
                          <Play className={`w-3.5 h-3.5 text-slate-600 ${isStartingThisLocal ? 'animate-spin' : ''}`} />
                          <span>{isStartingThisLocal ? 'Iniciando...' : 'Iniciar Local'}</span>
                        </button>
                        <button
                          type="button"
                          onClick={(e) => handleActivate(e, p.id)}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-emerald-700 bg-emerald-50 hover:bg-emerald-100 border border-emerald-200/80 rounded-xl transition-all active:scale-[0.98] cursor-pointer"
                          title="Activar en producción"
                        >
                          <Power className="w-3 h-3 text-emerald-600" />
                          <span>Activar</span>
                        </button>
                      </>
                    )}

                    {p.domains && p.domains.length > 0 && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          window.open(`https://${p.domains[0]}`, '_blank');
                        }}
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-slate-600 hover:text-slate-900 bg-white hover:bg-slate-50 border border-slate-200 rounded-xl transition-all shadow-2xs active:scale-[0.98] cursor-pointer"
                        title={`Visitar https://${p.domains[0]}`}
                      >
                        <ExternalLink className="w-3 h-3 text-slate-400" />
                        <span>Visitar</span>
                      </button>
                    )}
                  </div>

                  <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-700 group-hover:text-blue-600 transition-colors ml-auto">
                    <span>Detalles</span>
                    <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        /* 6. Projects Table View (Sleek Linear / Supabase Aesthetics) */
        <div className="bg-white border border-slate-200/90 rounded-2xl shadow-2xs overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200">
              <thead className="bg-slate-50/80 border-b border-slate-200/70">
                <tr>
 <th className="px-6 py-3.5 text-left text-xs font-semibold text-slate-500">
                    Proyecto & Repositorio
                  </th>
 <th className="px-6 py-3.5 text-left text-xs font-semibold text-slate-500">
                    Estado
                  </th>
 <th className="px-6 py-3.5 text-left text-xs font-semibold text-slate-500">
                    Arquitectura
                  </th>
 <th className="px-6 py-3.5 text-left text-xs font-semibold text-slate-500">
                    Enrutamiento Ingress
                  </th>
 <th className="px-6 py-3.5 text-left text-xs font-semibold text-slate-500">
                    Dominios
                  </th>
 <th className="px-6 py-3.5 text-right text-xs font-semibold text-slate-500">
                    Acciones
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-slate-100">
                {filtered.map((p) => {
                  const meta = getProjectMetadata(p);
                  const { IconComponent } = meta;
                  const citadelPct = p.trafficSplit?.citadel ?? 100;
                  const forgePct = p.trafficSplit?.forge || 0;

                  return (
                    <tr
                      key={p.id}
                      onClick={() => onSelectProject(p.id)}
                      className="hover:bg-slate-50/80 transition-colors cursor-pointer group"
                    >
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-3">
                          <div
                            className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 border ${meta.iconBg} ${meta.iconBorder} ${meta.iconText} shadow-2xs`}
                          >
                            <IconComponent className="w-5 h-5" />
                          </div>
                          <div className="min-w-0">
                            <div className="text-sm font-bold text-slate-900 group-hover:text-blue-600 transition-colors">
                              {p.name}
                            </div>
                            {meta.cleanGit ? (
                              <div className="flex items-center gap-1 text-xs text-slate-500 font-mono">
                                <GitBranch className="w-3 h-3 text-slate-400" />
                                <span>{meta.cleanGit}</span>
                              </div>
                            ) : (
                              <div className="text-xs text-slate-400 truncate max-w-[200px]">
                                {p.description || 'Sin descripción'}
                              </div>
                            )}
                          </div>
                        </div>
                      </td>

                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <span
                            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold shadow-2xs ${
                              p.status === 'active'
                                ? 'bg-emerald-50 text-emerald-700 border border-emerald-200/80'
                                : p.status === 'hibernated'
                                ? 'bg-sky-50 text-sky-700 border border-sky-200/80'
                                : 'bg-slate-100 text-slate-600 border border-slate-200'
                            }`}
                          >
                            <span
                              className={`w-1.5 h-1.5 rounded-full ${
                                p.status === 'active'
                                  ? 'bg-emerald-500 animate-pulse'
                                  : p.status === 'hibernated'
                                  ? 'bg-sky-400'
                                  : 'bg-slate-400'
                              }`}
                            />
                            {p.status === 'active' ? 'Activo' : p.status === 'hibernated' ? 'Hibernado' : 'Detenido'}
                          </span>
                          {p.localRunning ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-amber-50 text-amber-700 border border-amber-200/70">
                              <Zap className="w-3 h-3 text-amber-600 fill-amber-500" />
                              :{p.localPort}
                            </span>
                          ) : p.localPort ? (
                            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-mono text-slate-400 bg-slate-50 border border-slate-200">
                              :{p.localPort} (off)
                            </span>
                          ) : null}
                        </div>
                      </td>

                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          {meta.appsCount > 0 && (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-slate-100 text-slate-700 border border-slate-200/70">
                              <Layers className="w-3 h-3 text-slate-400" />
                              {meta.appsCount}
                            </span>
                          )}
                          {meta.dbsCount > 0 && (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-indigo-50 text-indigo-700 border border-indigo-200/70">
                              <Database className="w-3 h-3 text-indigo-500" />
                              {meta.dbType || 'BD'}
                            </span>
                          )}
                          {meta.servicesCount > 0 && (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-rose-50 text-rose-700 border border-rose-200/70">
                              <Server className="w-3 h-3 text-rose-500" />
                              BaaS
                            </span>
                          )}
                        </div>
                      </td>

                      <td className="px-6 py-4 whitespace-nowrap">
                        {forgePct > 0 ? (
                          <div className="w-36">
                            <div className="flex items-center justify-between text-[11px] text-slate-600 mb-1 font-mono">
                              <span>{citadelPct}% Prod</span>
                              <span>{forgePct}% Dev</span>
                            </div>
                            <div className="w-full h-1.5 bg-slate-100 rounded-full overflow-hidden flex">
                              <div className="bg-emerald-500 h-full" style={{ width: `${citadelPct}%` }} />
                              <div className="bg-amber-400 h-full" style={{ width: `${forgePct}%` }} />
                            </div>
                          </div>
                        ) : (
                          <div className="flex items-center gap-1.5 text-xs font-mono text-slate-700">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                            <span>Citadel :8080 (100%)</span>
                          </div>
                        )}
                      </td>

                      <td className="px-6 py-4 whitespace-nowrap">
                        {p.domains && p.domains.length > 0 ? (
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono text-xs text-slate-700 bg-slate-50 border border-slate-200 px-2 py-0.5 rounded-md flex items-center gap-1">
                              <Lock className="w-2.5 h-2.5 text-emerald-600" />
                              {p.domains[0]}
                            </span>
                            {p.domains.length > 1 && (
                              <span className="text-[10px] font-mono text-slate-500 bg-slate-100 px-1 py-0.5 rounded">
                                +{p.domains.length - 1}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-xs text-slate-400">Sin dominio público</span>
                        )}
                      </td>

                      <td className="px-6 py-4 whitespace-nowrap text-right">
                        <div className="flex items-center justify-end gap-2">
                          {p.localRunning ? (
                            <>
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  window.open(`http://localhost:${p.localPort}`, '_blank');
                                }}
                                className="p-1.5 text-xs text-amber-700 hover:text-amber-800 hover:bg-amber-50 rounded-lg border border-amber-200/80 transition-colors cursor-pointer"
                                title={`Abrir http://localhost:${p.localPort}`}
                              >
                                <Zap className="w-3.5 h-3.5 fill-amber-500 text-amber-600" />
                              </button>
                              <button
                                type="button"
                                onClick={(e) => handleStopLocal(e, p.id)}
                                disabled={stoppingLocalId === p.id}
                                className="p-1.5 text-xs text-rose-700 hover:text-rose-800 hover:bg-rose-50 rounded-lg border border-rose-200 transition-colors cursor-pointer disabled:opacity-50"
                                title="Detener proyecto y liberar puerto"
                              >
                                <Square className="w-3.5 h-3.5 fill-rose-600 text-rose-600" />
                              </button>
                            </>
                          ) : p.status === 'active' ? (
                            <>
                              <button
                                type="button"
                                onClick={(e) => handleStartLocal(e, p.id)}
                                disabled={startingLocalId === p.id}
                                className="p-1.5 text-xs text-slate-600 hover:text-slate-900 hover:bg-slate-100 rounded-lg border border-slate-200 transition-colors cursor-pointer disabled:opacity-50"
                                title={p.localPort ? `Iniciar servidor local (: ${p.localPort})` : 'Iniciar en local'}
                              >
                                <Play className={`w-3.5 h-3.5 fill-slate-500 text-slate-500 ${startingLocalId === p.id ? 'animate-spin' : ''}`} />
                              </button>
                              <button
                                type="button"
                                onClick={(e) => handleStopLocal(e, p.id)}
                                disabled={stoppingLocalId === p.id}
                                className="p-1.5 text-xs text-rose-700 hover:text-rose-800 hover:bg-rose-50 rounded-lg border border-rose-200 transition-colors cursor-pointer disabled:opacity-50"
                                title="Detener proyecto"
                              >
                                <Square className="w-3.5 h-3.5 fill-rose-600 text-rose-600" />
                              </button>
                            </>
                          ) : (
                            <>
                              <button
                                type="button"
                                onClick={(e) => handleStartLocal(e, p.id)}
                                disabled={startingLocalId === p.id}
                                className="p-1.5 text-xs text-slate-600 hover:text-slate-900 hover:bg-slate-100 rounded-lg border border-slate-200 transition-colors cursor-pointer disabled:opacity-50"
                                title={p.localPort ? `Iniciar servidor local (: ${p.localPort})` : 'Iniciar en local'}
                              >
                                <Play className={`w-3.5 h-3.5 fill-slate-500 text-slate-500 ${startingLocalId === p.id ? 'animate-spin' : ''}`} />
                              </button>
                              <button
                                type="button"
                                onClick={(e) => handleActivate(e, p.id)}
                                className="p-1.5 text-xs text-emerald-700 hover:text-emerald-800 hover:bg-emerald-50 rounded-lg border border-emerald-200 transition-colors cursor-pointer"
                                title="Activar en producción"
                              >
                                <Power className="w-3.5 h-3.5 text-emerald-600" />
                              </button>
                            </>
                          )}
                          <span className="inline-flex items-center gap-1 text-xs font-semibold text-slate-700 group-hover:text-blue-600 transition-colors ml-1">
                            <span>Detalles</span>
                            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
                          </span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 7. Empty State: No projects found matching filter/search */}
      {filtered.length === 0 && (
        <div className="bg-white border border-slate-200 rounded-2xl p-12 text-center shadow-2xs max-w-xl mx-auto">
          {projects.length === 0 ? (
            /* Onboarding State when system has 0 projects */
            <div className="space-y-4">
              <div className="w-16 h-16 rounded-2xl bg-blue-50 border border-blue-100 text-blue-600 flex items-center justify-center mx-auto shadow-sm">
                <Boxes className="w-8 h-8" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-900">Comienza con tu primer proyecto</h3>
                <p className="text-sm text-slate-500 mt-1 max-w-md mx-auto">
                  Culkibo te permite orquestar tus proyectos y microservicios con control nativo por agentes de IA y gestión unificada de dominios.
                </p>
              </div>

              <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(true)}
                  className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold text-white bg-slate-900 hover:bg-slate-800 shadow-sm transition-all cursor-pointer"
                >
                  <Plus className="w-4 h-4" />
                  <span>Crear Nuevo Proyecto</span>
                </button>
                <button
                  type="button"
                  onClick={onImportCoolify}
                  className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold text-slate-700 bg-white hover:bg-slate-50 border border-slate-200 transition-all cursor-pointer"
                >
                  <Download className="w-4 h-4 text-slate-500" />
                  <span>Importar desde Coolify</span>
                </button>
              </div>
            </div>
          ) : (
            /* Search / Filter empty state */
            <div className="space-y-3">
              <div className="w-12 h-12 rounded-xl bg-slate-100 text-slate-400 flex items-center justify-center mx-auto">
                <Search className="w-6 h-6" />
              </div>
              <h3 className="text-base font-bold text-slate-900">
                No se encontraron proyectos para "{search}"
              </h3>
              <p className="text-xs text-slate-500">
                Prueba a ajustar los filtros o el término de búsqueda para ver los proyectos disponibles.
              </p>
              <div className="pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setSearch('');
                    setFilter('all');
                  }}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Restablecer filtros</span>
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 8. Modal para Crear Proyecto */}
      <CreateProjectModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        onSuccess={fetchProjects}
      />
    </div>
  );
};
