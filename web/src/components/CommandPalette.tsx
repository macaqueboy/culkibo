import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  Bot,
  Boxes,
  Database,
  FolderKanban,
  Globe,
  HardDrive,
  Keyboard,
  ListChecks,
  Plus,
  Rocket,
  Search,
  Settings,
  Terminal,
  Upload,
  Zap,
  Server,
  HeartPulse,
  Users,
  FileCode2,
  ShieldCheck,
  Radio,
  Sparkles,
  X,
  CornerDownLeft,
} from 'lucide-react';
import { api, type Project, type ServiceTemplate } from '../lib/api';

const IS_MAC = typeof navigator !== 'undefined' && /mac|iphone|ipad/i.test(navigator.platform || navigator.userAgent || '');

let cachedCatalogTemplates: ServiceTemplate[] | null = null;

export interface CommandItem {
  id: string;
  group: 'Proyecto actual' | 'Acciones rápidas' | 'Proyectos' | 'Catálogo (140+ apps)' | 'Navegación';
  label: string;
  hint?: string;
  badge?: string;
  shortcut?: string[];
  keywords?: string;
  statusDot?: string;
  icon: React.ReactNode;
  onSelect: () => void;
}

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  projects: Project[];
  activeProjectId?: string | null;
  onNavigate: (view: string, subTab?: string | null) => void;
  onSelectProject: (id: string, tab?: string | null) => void;
  onQuickCreateProject: () => void;
  onQuickConnectDomain: () => void;
  onQuickImport: (source?: 'wordpress' | 'compose' | 'git' | 'platform' | 'coolify') => void;
  onOpenShortcuts?: () => void;
  onRestoreChecklist?: () => void;
  onNotify?: (msg: string, kind?: 'info' | 'success' | 'error') => void;
}

function normalizeStr(s: string): string {
  return s
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '');
}

/**
 * Zero-dependency fuzzy scorer: prioritizes exact prefix, word-boundary hits,
 * contiguous substring matches, and ordered character subsequences (e.g. "clfy" -> "Coolify").
 */
function fuzzyMatchScore(rawQuery: string, rawTarget: string): number {
  const q = normalizeStr(rawQuery.trim());
  if (!q) return 1;
  const target = normalizeStr(rawTarget);
  if (!target) return 0;

  if (target === q) return 1000;
  if (target.startsWith(q)) return 850 - Math.min(200, target.length - q.length);

  const exactIdx = target.indexOf(q);
  if (exactIdx !== -1) {
    const atBoundary = exactIdx === 0 || /[\s\-_/.·]/.test(target[exactIdx - 1]);
    return (atBoundary ? 720 : 560) - Math.min(180, exactIdx);
  }

  let qi = 0;
  let score = 0;
  let consecutive = 0;
  for (let ti = 0; ti < target.length && qi < q.length; ti++) {
    if (target[ti] === q[qi]) {
      const atBoundary = ti === 0 || /[\s\-_/.·]/.test(target[ti - 1]);
      consecutive += 1;
      score += 18 + (atBoundary ? 24 : 0) + consecutive * 7;
      qi += 1;
    } else {
      consecutive = 0;
    }
  }
  return qi === q.length ? score : 0;
}

function scoreCommandItem(rawQuery: string, item: CommandItem): number {
  const tokens = normalizeStr(rawQuery.trim()).split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return 1;

  const label = item.label;
  const secondary = `${item.hint || ''} ${item.badge || ''} ${item.keywords || ''}`;
  let total = 0;
  for (const tok of tokens) {
    const labelScore = fuzzyMatchScore(tok, label) * 1.6;
    const secScore = fuzzyMatchScore(tok, secondary);
    const best = Math.max(labelScore, secScore);
    if (best <= 0) return 0;
    total += best;
  }
  return total;
}

const FEATURED_CATALOG_IDS = ['n8n', 'langfuse', 'dify', 'wordpress', 'authelia'];

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  open,
  onClose,
  projects,
  activeProjectId,
  onNavigate,
  onSelectProject,
  onQuickCreateProject,
  onQuickConnectDomain,
  onQuickImport,
  onOpenShortcuts,
  onRestoreChecklist,
  onNotify,
}) => {
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const [catalogTemplates, setCatalogTemplates] = useState<ServiceTemplate[]>(() => cachedCatalogTemplates || []);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    inputRef.current?.focus();
    const raf = window.requestAnimationFrame(() => inputRef.current?.focus());

    let alive = true;
    if (!cachedCatalogTemplates) {
      api.getCatalog()
        .then((res) => {
          const list = Array.isArray(res?.templates) ? res.templates : [];
          cachedCatalogTemplates = list;
          if (alive) setCatalogTemplates(list);
        })
        .catch(() => {
          // Catálogo opcional si el servidor está cargando
        });
    }

    return () => {
      alive = false;
      document.body.style.overflow = prevOverflow;
      window.cancelAnimationFrame(raf);
    };
  }, [open]);

  const baseItems = useMemo<CommandItem[]>(() => {
    const statusLabels: Record<string, string> = {
      active: 'En producción',
      running: 'En producción',
      stopped: 'Detenido',
      hibernated: 'Hibernado',
      sleeping: 'En reposo',
      building: 'Compilando',
      error: 'Error',
    };

    const projectItems: CommandItem[] = projects.map((p) => {
      const isLive = Boolean(!p.maintenanceMode && ((p.lastDeployedAt && p.status === 'active') || p.localRunning));
      return {
        id: `proj-${p.id}`,
        group: 'Proyectos',
        label: p.name,
        hint: p.domains?.[0] || p.gitRepo || statusLabels[p.status] || p.status,
        badge: p.memoryMb ? `${p.memoryMb} MB` : undefined,
        statusDot: p.maintenanceMode
          ? 'bg-amber-500'
          : isLive
            ? 'bg-emerald-500'
            : 'bg-slate-300',
        keywords: `${p.name} ${p.description || ''} ${(p.domains || []).join(' ')} ${p.gitBranch || ''}`,
        icon: <FolderKanban className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onSelectProject(p.id),
      };
    });

    const navItems: CommandItem[] = [
      {
        id: 'nav-projects',
        group: 'Navegación',
        label: 'Ir a Proyectos',
        hint: 'Panel principal de aplicaciones',
        shortcut: ['G', 'P'],
        keywords: 'proyectos apps inicio home dashboard',
        icon: <FolderKanban className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('projects'),
      },
      {
        id: 'nav-catalog',
        group: 'Navegación',
        label: 'Ir al Catálogo de servicios (140+ apps)',
        hint: 'WordPress, n8n, Langfuse, Dify, PostgreSQL…',
        shortcut: ['G', 'C'],
        keywords: 'catalogo servicios 140 apps templates plantillas',
        icon: <Boxes className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('catalog'),
      },
      {
        id: 'nav-domains',
        group: 'Navegación',
        label: 'Ir a Dominios, HTTPS y HTTP/3',
        hint: 'Caddy, Multi-DNS-01 wildcard y túneles CGNAT',
        shortcut: ['G', 'D'],
        keywords: 'dominios ssl https tls wildcard caddy dns http3 quic cloudflare',
        icon: <Globe className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('domains'),
      },
      {
        id: 'nav-ai',
        group: 'Navegación',
        label: 'Ir a Agentes de IA (MCP 2026)',
        hint: '109 herramientas, Playbooks y ahorro ~81% tokens',
        shortcut: ['G', 'A'],
        keywords: 'ia mcp claude code antigravity cursor windsurf codex agentes',
        icon: <Bot className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('ai'),
      },
      {
        id: 'nav-fleet',
        group: 'Navegación',
        label: 'Ir a Flota de servidores',
        hint: 'Nodos VPS SSH, TOFU y bóveda de llaves',
        shortcut: ['G', 'F'],
        keywords: 'flota fleet servidores vps ssh tofu llaves keys',
        icon: <Server className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('fleet'),
      },
      {
        id: 'nav-uptime',
        group: 'Navegación',
        label: 'Ir a Uptime, Estado y Ahorro',
        hint: 'Monitores, /status/:slug y auto-reposo',
        shortcut: ['G', 'U'],
        keywords: 'uptime monitores estado status page ahorro coste vps sleep reposo',
        icon: <HeartPulse className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('uptime'),
      },
      {
        id: 'nav-metrics',
        group: 'Navegación',
        label: 'Ir a Métricas y Doctor del sistema',
        hint: 'Latencia, RAM <60 MB, Prometheus y topología',
        shortcut: ['G', 'M'],
        keywords: 'metricas observabilidad doctor prometheus latencia ram cpu salud topologia',
        icon: <Activity className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('metrics'),
      },
      {
        id: 'nav-import',
        group: 'Navegación',
        label: 'Ir a Importar y migrar',
        hint: 'Coolify v4, WordPress, Compose, Vercel, Railway',
        shortcut: ['G', 'I'],
        keywords: 'importar migrar wordpress coolify vercel railway docker compose dokploy',
        icon: <Upload className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('import'),
      },
      {
        id: 'nav-logs',
        group: 'Navegación',
        label: 'Ir a Registros en directo',
        hint: 'Stream WebSocket en tiempo real',
        shortcut: ['G', 'L'],
        keywords: 'logs registros consola errores stream',
        icon: <Terminal className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('global_logs'),
      },
      {
        id: 'nav-settings',
        group: 'Navegación',
        label: 'Ir a Ajustes del servidor',
        hint: 'Seguridad 2FA, OIDC, GitOps, S3 y alertas',
        shortcut: ['G', 'S'],
        keywords: 'ajustes configuracion seguridad 2fa oidc token s3 notificaciones',
        icon: <Settings className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('settings'),
      },
    ];

    const currentProj = activeProjectId ? projects.find((p) => p.id === activeProjectId) : null;
    const contextItems: CommandItem[] = currentProj
      ? [
          {
            id: 'ctx-deploy',
            group: 'Proyecto actual',
            label: `${currentProj.name} · Despliegues, Cron y Previews`,
            hint: 'Producción, logs y rollback',
            keywords: 'deploy despliegue cron preview logs rollback contenedor',
            icon: <Rocket className="w-4 h-4 text-slate-700 shrink-0" />,
            onSelect: () => onSelectProject(currentProj.id, 'deploy'),
          },
          {
            id: 'ctx-live',
            group: 'Proyecto actual',
            label: `${currentProj.name} · En vivo (Live Sync <10ms)`,
            hint: 'Delta Merkle, historial por archivo y rollback',
            keywords: 'live sync forge merkle carpeta local hot reload',
            icon: <Zap className="w-4 h-4 text-amber-500 shrink-0" />,
            onSelect: () => onSelectProject(currentProj.id, 'live'),
          },
          {
            id: 'ctx-domains',
            group: 'Proyecto actual',
            label: `${currentProj.name} · Dominios HTTPS`,
            hint: 'Rutas Caddy y TLS automático',
            keywords: 'dominios ssl https url',
            icon: <Globe className="w-4 h-4 text-slate-700 shrink-0" />,
            onSelect: () => onSelectProject(currentProj.id, 'domains'),
          },
          {
            id: 'ctx-databases',
            group: 'Proyecto actual',
            label: `${currentProj.name} · Bases de datos y copias`,
            hint: 'PostgreSQL, MySQL, Redis, MongoDB',
            keywords: 'base de datos db postgres mysql redis mongo backup',
            icon: <Database className="w-4 h-4 text-slate-700 shrink-0" />,
            onSelect: () => onSelectProject(currentProj.id, 'databases'),
          },
          {
            id: 'ctx-settings',
            group: 'Proyecto actual',
            label: `${currentProj.name} · Configuración y Webhooks`,
            hint: 'GitHub, GitLab, Gitea, Bitbucket, Deploy Hook',
            keywords: 'configuracion webhook git hooks predeploy',
            icon: <Settings className="w-4 h-4 text-slate-700 shrink-0" />,
            onSelect: () => onSelectProject(currentProj.id, 'settings'),
          },
        ]
      : [];

    const quickItems: CommandItem[] = [
      {
        id: 'act-new-project',
        group: 'Acciones rápidas',
        label: 'Crear nuevo proyecto',
        hint: 'GitHub, URL Git o carpeta local',
        shortcut: ['N'],
        keywords: 'crear nuevo proyecto app deploy git carpeta local',
        icon: <Plus className="w-4 h-4 text-slate-700 shrink-0" />,
        onSelect: onQuickCreateProject,
      },
      {
        id: 'act-migrate-coolify',
        group: 'Acciones rápidas',
        label: 'Migrar desde Coolify',
        hint: 'Apps, BD, magic vars y traducción Traefik → Caddy',
        badge: '1-Clic',
        keywords: 'migrar migrate coolify v4 importar traefik caddy magic vars',
        icon: <Sparkles className="w-4 h-4 text-amber-500 shrink-0" />,
        onSelect: () => onQuickImport('coolify'),
      },
      {
        id: 'act-connect-mcp',
        group: 'Acciones rápidas',
        label: 'Conectar Claude Code / Antigravity MCP',
        hint: 'Streamable HTTP 2026 · 109 herramientas y perfiles',
        shortcut: ['G', 'A'],
        keywords: 'conectar connect claude code antigravity cursor windsurf codex mcp ia agent',
        icon: <Bot className="w-4 h-4 text-slate-700 shrink-0" />,
        onSelect: () => onNavigate('ai'),
      },
      {
        id: 'act-security-audit',
        group: 'Acciones rápidas',
        label: 'Ejecutar auditoría de seguridad y 2FA',
        hint: 'TOTP 2FA, OIDC SSO, cadena SHA-256 y Secret Scanner',
        badge: 'v1.1',
        keywords: 'security seguridad audit auditoria 2fa totp oidc sso secret scanner chain sha256 verificar',
        icon: <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0" />,
        onSelect: () => onNavigate('settings', 'security'),
      },
      {
        id: 'act-check-edge-http3',
        group: 'Acciones rápidas',
        label: 'Comprobar Edge Multi-DNS-01 y HTTP/3',
        hint: 'QUIC UDP :443 y 7 proveedores wildcard DNS-01',
        badge: 'Edge',
        keywords: 'edge http3 h3 quic multi dns01 wildcard cloudflare hetzner route53 caddy',
        icon: <Radio className="w-4 h-4 text-slate-700 shrink-0" />,
        onSelect: () => onNavigate('settings', 'system'),
      },
      {
        id: 'act-connect-domain',
        group: 'Acciones rápidas',
        label: 'Conectar un dominio HTTPS',
        hint: 'Proxy, DNS, Wildcard o Túnel CGNAT sin puertos',
        keywords: 'conectar dominio ssl wildcard tunel cloudflare cgnat',
        icon: <Globe className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: onQuickConnectDomain,
      },
      {
        id: 'act-wp',
        group: 'Acciones rápidas',
        label: 'Migrar una web WordPress',
        hint: 'Analiza y clona sin caídas',
        keywords: 'wordpress woocommerce migrar',
        icon: <Upload className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onQuickImport('wordpress'),
      },
      {
        id: 'act-compose',
        group: 'Acciones rápidas',
        label: 'Importar docker-compose.yml',
        hint: 'Detecta servicios, puertos y bases de datos',
        keywords: 'docker compose yaml importar',
        icon: <Upload className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onQuickImport('compose'),
      },
      {
        id: 'act-team-rbac',
        group: 'Acciones rápidas',
        label: 'Equipo, Roles (RBAC) y Tokens API',
        hint: 'Miembros, invitaciones y tokens con alcance',
        keywords: 'equipo rbac roles usuarios invitaciones tokens permisos acl',
        icon: <Users className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('settings', 'team'),
      },
      {
        id: 'act-gitops-vault',
        group: 'Acciones rápidas',
        label: 'GitOps (culkibo.yaml) y Vault cifrado',
        hint: 'Exportar, planificar, aplicar y secretos AES-256-GCM',
        keywords: 'gitops yaml vault secretos entornos promocion diff',
        icon: <FileCode2 className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('settings', 'gitops'),
      },
      {
        id: 'act-backups-dr',
        group: 'Acciones rápidas',
        label: 'Backups, S3 y recuperación (DR)',
        hint: 'Snapshot completo cifrado y bucket remoto',
        keywords: 'backup snapshot dr recuperacion s3 r2 restaurar',
        icon: <HardDrive className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('settings', 'backups'),
      },
      ...(onOpenShortcuts
        ? [
            {
              id: 'act-shortcuts',
              group: 'Acciones rápidas' as const,
              label: 'Ver atajos de teclado',
              hint: 'Navegación rápida sin ratón',
              shortcut: ['?'],
              keywords: 'atajos teclado ayuda shortcuts ?',
              icon: <Keyboard className="w-4 h-4 text-slate-500 shrink-0" />,
              onSelect: onOpenShortcuts,
            },
          ]
        : []),
      ...(onRestoreChecklist
        ? [
            {
              id: 'act-restore-checklist',
              group: 'Acciones rápidas' as const,
              label: 'Restaurar guía de primeros pasos',
              hint: 'Volver a mostrar la lista inicial en Proyectos',
              keywords: 'primeros pasos checklist guia tutorial onboarding ayuda',
              icon: <ListChecks className="w-4 h-4 text-slate-500 shrink-0" />,
              onSelect: onRestoreChecklist,
            },
          ]
        : []),
    ];

    return [...contextItems, ...quickItems, ...projectItems, ...navItems];
  }, [
    projects,
    activeProjectId,
    onNavigate,
    onSelectProject,
    onQuickCreateProject,
    onQuickConnectDomain,
    onQuickImport,
    onOpenShortcuts,
    onRestoreChecklist,
  ]);

  const catalogCommandItems = useMemo<CommandItem[]>(() => {
    return catalogTemplates.map((tpl) => {
      const ramLabel =
        tpl.totalMemoryMb >= 1024
          ? `${(tpl.totalMemoryMb / 1024).toFixed(tpl.totalMemoryMb % 1024 === 0 ? 0 : 1)} GB`
          : `${tpl.totalMemoryMb || tpl.memoryMb} MB`;
      return {
        id: `cat-${tpl.id}`,
        group: 'Catálogo (140+ apps)',
        label: tpl.name,
        hint: `${tpl.categoryLabel} · ${tpl.summary}`,
        badge: ramLabel,
        keywords: `${tpl.id} ${tpl.name} ${tpl.category} ${tpl.categoryLabel} ${(tpl.tags || []).join(' ')} ${tpl.summary}`,
        icon: <Boxes className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => {
          try {
            window.sessionStorage.setItem('culkibo_catalog_search_hint', tpl.name);
          } catch {
            // ignorar
          }
          onNavigate('catalog');
          onNotify?.(`Catálogo abierto · busca «${tpl.name}» para instalar en 1 clic`, 'info');
        },
      };
    });
  }, [catalogTemplates, onNavigate, onNotify]);

  const filtered = useMemo(() => {
    const q = query.trim();
    if (!q) {
      // Sin búsqueda: mostrar todos los baseItems + 5 apps destacadas del catálogo
      const featured: CommandItem[] = [];
      for (const fid of FEATURED_CATALOG_IDS) {
        const match = catalogCommandItems.find((c) => c.id === `cat-${fid}`);
        if (match) featured.push(match);
      }
      const catalogSlice = featured.length > 0 ? featured : catalogCommandItems.slice(0, 5);
      return [...baseItems, ...catalogSlice];
    }

    const scoredBase = baseItems
      .map((item) => ({ item, score: scoreCommandItem(q, item) }))
      .filter((x) => x.score > 0)
      .sort((a, b) => b.score - a.score)
      .map((x) => x.item);

    const scoredCatalog = catalogCommandItems
      .map((item) => ({ item, score: scoreCommandItem(q, item) }))
      .filter((x) => x.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 10)
      .map((x) => x.item);

    return [...scoredBase, ...scoredCatalog];
  }, [baseItems, catalogCommandItems, query]);

  const orderedGroups = useMemo(() => {
    const groupOrder: Array<CommandItem['group']> = [
      'Proyecto actual',
      'Acciones rápidas',
      'Proyectos',
      'Catálogo (140+ apps)',
      'Navegación',
    ];
    return groupOrder
      .map((name) => ({
        name,
        items: filtered.filter((i) => i.group === name),
      }))
      .filter((g) => g.items.length > 0);
  }, [filtered]);

  // Flat render order matching visual order so arrow keys always move line-by-line
  const flatItems = useMemo(
    () => orderedGroups.flatMap((g) => g.items),
    [orderedGroups]
  );

  const safeIndex = flatItems.length > 0 ? Math.min(activeIndex, flatItems.length - 1) : 0;

  useEffect(() => {
    if (!open || !listRef.current) return;
    const el = listRef.current.querySelector<HTMLElement>(`[data-cmd-idx="${safeIndex}"]`);
    el?.scrollIntoView({ block: 'nearest' });
  }, [open, safeIndex]);

  if (!open) return null;

  const runItem = (item: CommandItem) => {
    setQuery('');
    setActiveIndex(0);
    onClose();
    item.onSelect();
  };

  const handleClose = () => {
    setQuery('');
    setActiveIndex(0);
    onClose();
  };

  let runningIndex = 0;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[10vh] sm:pt-[12vh] px-3 sm:px-4 bg-slate-950/30 backdrop-blur-[2px]"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) handleClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Paleta de comandos"
        className="culkibo-modal-enter w-full max-w-2xl bg-white border border-slate-200 rounded-2xl shadow-2xl overflow-hidden"
      >
        <div className="flex items-center gap-2.5 px-4 py-3.5 border-b border-slate-200/90">
          <Search className="w-4 h-4 text-slate-400 shrink-0" />
          <input
            ref={inputRef}
            autoFocus
            type="text"
            role="combobox"
            aria-expanded="true"
            aria-controls="command-palette-listbox"
            aria-activedescendant={flatItems[safeIndex] ? `cmd-opt-${flatItems[safeIndex].id}` : undefined}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActiveIndex(0);
            }}
            onKeyDown={(e) => {
              if (e.key === 'Escape') {
                e.preventDefault();
                handleClose();
              } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (flatItems.length > 0) {
                  setActiveIndex((i) => (i + 1) % flatItems.length);
                }
              } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (flatItems.length > 0) {
                  setActiveIndex((i) => (i - 1 + flatItems.length) % flatItems.length);
                }
              } else if (e.key === 'Home') {
                e.preventDefault();
                setActiveIndex(0);
              } else if (e.key === 'End') {
                e.preventDefault();
                setActiveIndex(Math.max(0, flatItems.length - 1));
              } else if (e.key === 'Enter' && flatItems[safeIndex]) {
                e.preventDefault();
                runItem(flatItems[safeIndex]);
              }
            }}
            placeholder="Buscar proyectos, 140+ apps del catálogo, Coolify, MCP, 2FA…"
            className="w-full bg-transparent text-sm text-slate-900 placeholder:text-slate-400 border-0 !shadow-none !outline-none"
          />
          {query && (
            <button
              type="button"
              onClick={() => {
                setQuery('');
                setActiveIndex(0);
                inputRef.current?.focus();
              }}
              aria-label="Limpiar búsqueda"
              className="p-1 rounded-md text-slate-400 hover:text-slate-700 hover:bg-slate-100 cursor-pointer shrink-0"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
          <kbd className="culkibo-kbd hidden sm:inline-block px-1.5 py-0.5 text-[10px] font-medium text-slate-500 bg-slate-100 border border-slate-200 rounded">
            Esc
          </kbd>
        </div>

        <div
          id="command-palette-listbox"
          role="listbox"
          ref={listRef}
          className="max-h-[58vh] overflow-y-auto p-2 space-y-1.5"
        >
          {flatItems.length === 0 ? (
            <div className="px-4 py-10 text-center space-y-1.5">
              <div className="text-sm font-medium text-slate-700">
                Sin coincidencias para «{query}»
              </div>
              <p className="text-xs text-slate-400">
                Prueba con «coolify», «mcp», «2fa», «http3», «n8n», «langfuse» o el nombre de un proyecto.
              </p>
            </div>
          ) : (
            orderedGroups.map((group) => (
              <div key={group.name}>
                <div className="px-2.5 pt-1.5 pb-1 flex items-center justify-between text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  <span>{group.name}</span>
                  {group.name === 'Catálogo (140+ apps)' && catalogTemplates.length > 0 && (
                    <span className="font-mono text-[10px] font-normal normal-case text-slate-400 tabular-nums">
                      {catalogTemplates.length} apps indexadas
                    </span>
                  )}
                </div>
                <div className="space-y-0.5">
                  {group.items.map((item) => {
                    const idx = runningIndex++;
                    const isActive = idx === safeIndex;
                    return (
                      <button
                        key={item.id}
                        id={`cmd-opt-${item.id}`}
                        data-cmd-idx={idx}
                        type="button"
                        role="option"
                        aria-selected={isActive}
                        onMouseEnter={() => setActiveIndex(idx)}
                        onClick={() => runItem(item)}
                        className={`w-full px-3 py-2.5 rounded-xl flex items-center justify-between gap-3 text-left transition-colors cursor-pointer ${
                          isActive ? 'bg-slate-100 text-slate-950' : 'text-slate-700 hover:bg-slate-50'
                        }`}
                      >
                        <span className="flex items-center gap-2.5 min-w-0">
                          <span
                            className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 border ${
                              isActive
                                ? 'bg-white border-slate-200/90 shadow-2xs'
                                : 'bg-slate-50 border-slate-200/60'
                            }`}
                          >
                            {item.icon}
                          </span>
                          <span className="min-w-0">
                            <span className="flex items-center gap-1.5">
                              {item.statusDot && (
                                <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${item.statusDot}`} />
                              )}
                              <span className="text-[13px] font-medium truncate">{item.label}</span>
                            </span>
                            {item.hint && (
                              <span className="block text-[11px] text-slate-500 truncate max-w-[340px] sm:max-w-[400px]">
                                {item.hint}
                              </span>
                            )}
                          </span>
                        </span>

                        <span className="flex items-center gap-1.5 shrink-0">
                          {item.badge && (
                            <span className="px-1.5 py-0.5 rounded-md bg-white border border-slate-200 text-[10px] font-mono text-slate-600 tabular-nums">
                              {item.badge}
                            </span>
                          )}
                          {item.shortcut && item.shortcut.length > 0 && (
                            <span className="hidden sm:inline-flex items-center gap-0.5">
                              {item.shortcut.map((k) => (
                                <kbd
                                  key={k}
                                  className="culkibo-kbd px-1.5 py-0.5 rounded bg-white border border-slate-200 text-[10px] font-medium text-slate-500"
                                >
                                  {k}
                                </kbd>
                              ))}
                            </span>
                          )}
                          {isActive && (
                            <CornerDownLeft className="w-3.5 h-3.5 text-slate-400 hidden sm:block" />
                          )}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>
            ))
          )}
        </div>

        <div className="px-4 py-2.5 border-t border-slate-100 bg-slate-50/80 flex items-center justify-between gap-2 text-[11px] text-slate-500 tabular-nums">
          <div className="flex items-center gap-3">
            <span>↑↓ navegar</span>
            <span>↵ abrir</span>
            <span>{flatItems.length} {flatItems.length === 1 ? 'resultado' : 'resultados'}</span>
          </div>
          <span className="font-mono text-slate-400">{IS_MAC ? '⌘K' : 'Ctrl+K'}</span>
        </div>
      </div>
    </div>
  );
};
