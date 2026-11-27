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
  Moon,
  Sun,
  Languages,
} from 'lucide-react';
import { api, type Project, type ServiceTemplate } from '../lib/api';
import { useI18n } from '../lib/i18n';
import { useTheme } from '../lib/theme';

const IS_MAC = typeof navigator !== 'undefined' && /mac|iphone|ipad/i.test(navigator.platform || navigator.userAgent || '');

let cachedCatalogTemplates: ServiceTemplate[] | null = null;

type GroupId = 'current' | 'quick' | 'projects' | 'catalog' | 'nav';

export interface CommandItem {
  id: string;
  group: GroupId;
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
  const { locale, toggleLocale, t } = useI18n();
  const { isDark, toggleTheme } = useTheme();
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
          // optional if server loading
        });
    }

    return () => {
      alive = false;
      document.body.style.overflow = prevOverflow;
      window.cancelAnimationFrame(raf);
    };
  }, [open]);

  const baseItems = useMemo<CommandItem[]>(() => {
    const isEs = locale === 'es';
    const projectItems: CommandItem[] = projects.map((p) => {
      const isLive = Boolean(!p.maintenanceMode && ((p.lastDeployedAt && p.status === 'active') || p.localRunning));
      return {
        id: `proj-${p.id}`,
        group: 'projects',
        label: p.name,
        hint: p.domains?.[0] || p.gitRepo || p.status,
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
        group: 'nav',
        label: isEs ? 'Ir a Proyectos' : 'Go to Projects',
        hint: isEs ? 'Panel principal de aplicaciones' : 'Main applications workspace',
        shortcut: ['G', 'P'],
        keywords: 'projects proyectos apps inicio home dashboard',
        icon: <FolderKanban className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('projects'),
      },
      {
        id: 'nav-catalog',
        group: 'nav',
        label: isEs ? 'Ir al Catálogo (140+ apps)' : 'Go to 1-Click Catalog (140+ apps)',
        hint: 'WordPress, n8n, Langfuse, Dify, PostgreSQL…',
        shortcut: ['G', 'C'],
        keywords: 'catalog catalogo servicios 140 apps templates',
        icon: <Boxes className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('catalog'),
      },
      {
        id: 'nav-domains',
        group: 'nav',
        label: isEs ? 'Ir a Dominios, HTTPS y HTTP/3' : 'Go to Domains, HTTPS & HTTP/3',
        hint: 'Caddy v2.11, Geo-Routing (CF-IPCountry), Sticky A/B & EdgeTunnel',
        shortcut: ['G', 'D'],
        keywords: 'domains dominios ssl https tls wildcard caddy dns http3 quic cloudflare geo routing cf-ipcountry sticky ab experiment kill-switch',
        icon: <Globe className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('domains'),
      },
      {
        id: 'nav-ai',
        group: 'nav',
        label: isEs ? 'Ir a Agentes IA (MCP 2026)' : 'Go to AI Agents (MCP 2026)',
        hint: isEs ? '150 herramientas, Playbooks y ~89% menos tokens' : '150 tools, MCP Apps & ~89% fewer tokens',
        shortcut: ['G', 'A'],
        keywords: 'ai ia mcp claude code antigravity cursor windsurf codex agents 150 triage forensics oom image bloat pii mask oncall cron lease',
        icon: <Bot className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('ai'),
      },
      {
        id: 'nav-fleet',
        group: 'nav',
        label: isEs ? 'Ir a Flota de servidores' : 'Go to Server Fleet',
        hint: 'SSH VPS, WireGuard Mesh, Remote Builders, AI/GPU & Volume Migrator',
        shortcut: ['G', 'F'],
        keywords: 'fleet flota servidores vps ssh tofu keys wireguard mesh x25519 wg0 remote builder offload ollama vllm llamacpp gpu vram cdi volume migration numeric-owner uid 999',
        icon: <Server className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('fleet'),
      },
      {
        id: 'nav-uptime',
        group: 'nav',
        label: isEs ? 'Ir a Uptime y Auto-Reposo' : 'Go to Uptime & Scale-to-Zero',
        hint: 'Monitors, On-Call Escalation, Cron Fencing Leases, Synthetic Flows & TLS Sentinel',
        shortcut: ['G', 'U'],
        keywords: 'uptime monitors status page sleep cost savings cron timeline lease fencing heartbeat synthetic flow tls sni sentinel oncall escalation flapping dedup',
        icon: <HeartPulse className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('uptime'),
      },
      {
        id: 'nav-metrics',
        group: 'nav',
        label: isEs ? 'Ir a Métricas y Topología' : 'Go to Metrics & Spatial Topology',
        hint: 'RAM <60 MB, FinOps, Agency Ledger, Doctor & SVG Topology',
        shortcut: ['G', 'M'],
        keywords: 'metrics metricas observability doctor prometheus topology svg ram cpu finops agency billing ledger quotas csv',
        icon: <Activity className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('metrics'),
      },
      {
        id: 'nav-import',
        group: 'nav',
        label: isEs ? 'Ir a Importar y migrar' : 'Go to Import & Migrate',
        hint: 'Coolify v4, WordPress, Compose, Vercel, Railway',
        shortcut: ['G', 'I'],
        keywords: 'import importar migrate migrar wordpress coolify vercel railway compose dokploy',
        icon: <Upload className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('import'),
      },
      {
        id: 'nav-logs',
        group: 'nav',
        label: isEs ? 'Ir a Registros en directo' : 'Go to Live Logs',
        hint: 'Real-time WebSocket stream & Persistent .ndjson.gz Archive Search',
        shortcut: ['G', 'L'],
        keywords: 'logs registros console stream errors archive ndjson gz search redos',
        icon: <Terminal className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('global_logs'),
      },
      {
        id: 'nav-settings',
        group: 'nav',
        label: isEs ? 'Ir a Ajustes' : 'Go to Settings',
        hint: '2FA, OIDC, GitOps, S3, Theme & Language',
        shortcut: ['G', 'S'],
        keywords: 'settings ajustes security 2fa oidc token s3 dark theme language',
        icon: <Settings className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('settings'),
      },
    ];

    const currentProj = activeProjectId ? projects.find((p) => p.id === activeProjectId) : null;
    const contextItems: CommandItem[] = currentProj
      ? [
          {
            id: 'ctx-deploy',
            group: 'current',
            label: `${currentProj.name} · Deploy, SLO Canary, Autoscaler & Previews`,
            hint: isEs ? 'Producción, Canary 10→100%, KEDA Autoscaler y rollback' : 'Production, SLO Canary 10→100%, KEDA Autoscaler & rollback',
            keywords: 'deploy despliegue cron preview logs rollback slo canary burn rate auto-rollback autoscaler keda hysteresis circuit breaker 503',
            icon: <Rocket className="w-4 h-4 text-slate-700 shrink-0" />,
            onSelect: () => onSelectProject(currentProj.id, 'deploy'),
          },
          {
            id: 'ctx-live',
            group: 'current',
            label: `${currentProj.name} · Live Sync (<10ms)`,
            hint: 'Merkle delta, per-file time travel & rollback',
            keywords: 'live sync forge merkle hot reload',
            icon: <Zap className="w-4 h-4 text-amber-500 shrink-0" />,
            onSelect: () => onSelectProject(currentProj.id, 'live'),
          },
          {
            id: 'ctx-vars',
            group: 'current',
            label: `${currentProj.name} · Env Vars & Fast Restart`,
            hint: isEs ? 'Reinicia en ~1.5s sin reconstruir imagen' : 'Apply runtime env in ~1.5s, no rebuild',
            keywords: 'env vars variables secrets fast restart',
            icon: <Settings className="w-4 h-4 text-slate-700 shrink-0" />,
            onSelect: () => onSelectProject(currentProj.id, 'vars'),
          },
          {
            id: 'ctx-domains',
            group: 'current',
            label: `${currentProj.name} · HTTPS Domains`,
            hint: 'Caddy routes & automatic TLS',
            keywords: 'domains dominios ssl https url',
            icon: <Globe className="w-4 h-4 text-slate-700 shrink-0" />,
            onSelect: () => onSelectProject(currentProj.id, 'domains'),
          },
          {
            id: 'ctx-databases',
            group: 'current',
            label: `${currentProj.name} · Databases, Studio, SQL Linter, DR Drill & S3`,
            hint: 'PostgreSQL, Read-Only Studio, SQL DDL Linter, DR Fire-Drill & Garage/RustFS S3',
            keywords: 'database db postgres mysql redis valkey studio sql bloat lint linter migration concurrently backup dr drill fire-drill restore s3 garage rustfs seaweedfs sigv4 presign',
            icon: <Database className="w-4 h-4 text-slate-700 shrink-0" />,
            onSelect: () => onSelectProject(currentProj.id, 'databases'),
          },
        ]
      : [];

    const quickItems: CommandItem[] = [
      {
        id: 'act-new-project',
        group: 'quick',
        label: t('cmd.actNewProject'),
        hint: t('cmd.actNewProjectHint'),
        shortcut: ['N'],
        keywords: 'create crear new nuevo project proyecto deploy git',
        icon: <Plus className="w-4 h-4 text-slate-700 shrink-0" />,
        onSelect: onQuickCreateProject,
      },
      {
        id: 'act-migrate-coolify',
        group: 'quick',
        label: t('cmd.actCoolify'),
        hint: t('cmd.actCoolifyHint'),
        badge: '1-Click',
        keywords: 'migrate migrar coolify v4 import traefik caddy magic vars',
        icon: <Sparkles className="w-4 h-4 text-amber-500 shrink-0" />,
        onSelect: () => onQuickImport('coolify'),
      },
      {
        id: 'act-connect-mcp',
        group: 'quick',
        label: t('cmd.actMcp'),
        hint: t('cmd.actMcpHint'),
        shortcut: ['G', 'A'],
        keywords: 'connect conectar claude code antigravity cursor windsurf codex mcp ai agent',
        icon: <Bot className="w-4 h-4 text-slate-700 shrink-0" />,
        onSelect: () => onNavigate('ai'),
      },
      {
        id: 'act-security-audit',
        group: 'quick',
        label: t('cmd.actSecurity'),
        hint: t('cmd.actSecurityHint'),
        badge: 'v1.2',
        keywords: 'security seguridad audit auditoria 2fa totp oidc sso secret scanner chain sha256 passkey lease cve iac brand white-label webhooks dlq whsec admission policy cis pss soc2 iso27001 gdpr compliance ed25519 spdx license agpl sspl seccomp runc cve-2025-31133',
        icon: <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0" />,
        onSelect: () => onNavigate('settings', 'security'),
      },
      {
        id: 'act-check-edge-http3',
        group: 'quick',
        label: t('cmd.actEdge'),
        hint: t('cmd.actEdgeHint'),
        badge: 'Edge',
        keywords: 'edge http3 h3 quic multi dns01 wildcard cloudflare hetzner route53 caddy',
        icon: <Radio className="w-4 h-4 text-slate-700 shrink-0" />,
        onSelect: () => onNavigate('settings', 'system'),
      },
      {
        id: 'act-toggle-theme',
        group: 'quick',
        label: t('cmd.actTheme'),
        hint: t('cmd.actThemeHint'),
        badge: isDark ? 'Dark' : 'Light',
        keywords: 'theme tema dark oscuro light claro mode modo appearance',
        icon: isDark
          ? <Sun className="w-4 h-4 text-amber-400 shrink-0" />
          : <Moon className="w-4 h-4 text-slate-600 shrink-0" />,
        onSelect: () => {
          const next = toggleTheme();
          onNotify?.(
            next === 'dark'
              ? (isEs ? 'Modo oscuro activado' : 'Dark mode enabled')
              : (isEs ? 'Modo claro activado' : 'Light mode enabled'),
            'info'
          );
        },
      },
      {
        id: 'act-toggle-lang',
        group: 'quick',
        label: t('cmd.actLang'),
        hint: t('cmd.actLangHint'),
        badge: locale.toUpperCase(),
        keywords: 'language idioma english spanish ingles espanol i18n locale en es',
        icon: <Languages className="w-4 h-4 text-slate-600 shrink-0" />,
        onSelect: () => {
          const next = toggleLocale();
          onNotify?.(next === 'en' ? 'Language switched to English' : 'Idioma cambiado a Español', 'info');
        },
      },
      {
        id: 'act-connect-domain',
        group: 'quick',
        label: t('cmd.actDomain'),
        hint: t('cmd.actDomainHint'),
        keywords: 'connect conectar domain dominio ssl wildcard tunnel cloudflare cgnat',
        icon: <Globe className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: onQuickConnectDomain,
      },
      {
        id: 'act-wp',
        group: 'quick',
        label: isEs ? 'Migrar una web WordPress' : 'Migrate a WordPress site',
        hint: isEs ? 'Analiza y clona sin caídas' : 'Analyze and clone with zero downtime',
        keywords: 'wordpress woocommerce migrate migrar',
        icon: <Upload className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onQuickImport('wordpress'),
      },
      {
        id: 'act-compose',
        group: 'quick',
        label: isEs ? 'Importar docker-compose.yml' : 'Import docker-compose.yml',
        hint: isEs ? 'Detecta servicios, puertos y BD' : 'Auto-detects services, ports & databases',
        keywords: 'docker compose yaml import importar',
        icon: <Upload className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onQuickImport('compose'),
      },
      {
        id: 'act-team-rbac',
        group: 'quick',
        label: isEs ? 'Equipo, Roles (RBAC) y Tokens API' : 'Team, RBAC Roles & Scoped API Tokens',
        hint: isEs ? 'Miembros, invitaciones y permisos' : 'Members, invites & scoped tokens',
        keywords: 'team equipo rbac roles users tokens acl',
        icon: <Users className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('settings', 'team'),
      },
      {
        id: 'act-gitops-vault',
        group: 'quick',
        label: 'GitOps (culkibo.yaml) & Encrypted Vault',
        hint: 'Export, plan, apply & AES-256-GCM secrets',
        keywords: 'gitops yaml vault secrets entornos diff',
        icon: <FileCode2 className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('settings', 'gitops'),
      },
      {
        id: 'act-backups-dr',
        group: 'quick',
        label: isEs ? 'Backups, S3 y recuperación (DR)' : 'Backups, S3 & Disaster Recovery',
        hint: 'Encrypted full snapshot & S3/R2 bucket',
        keywords: 'backup snapshot dr recovery s3 r2 restore',
        icon: <HardDrive className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => onNavigate('settings', 'backups'),
      },
      ...(onOpenShortcuts
        ? [
            {
              id: 'act-shortcuts',
              group: 'quick' as const,
              label: isEs ? 'Ver atajos de teclado' : 'View keyboard shortcuts',
              hint: isEs ? 'Navegación rápida sin ratón' : 'Fast keyboard navigation',
              shortcut: ['?'],
              keywords: 'shortcuts atajos keyboard teclado help ?',
              icon: <Keyboard className="w-4 h-4 text-slate-500 shrink-0" />,
              onSelect: onOpenShortcuts,
            },
          ]
        : []),
      ...(onRestoreChecklist
        ? [
            {
              id: 'act-restore-checklist',
              group: 'quick' as const,
              label: isEs ? 'Restaurar guía de primeros pasos' : 'Restore quick start guide',
              hint: isEs ? 'Volver a mostrar la guía en Proyectos' : 'Show onboarding strip in Projects',
              keywords: 'checklist onboarding guide primeros pasos guia',
              icon: <ListChecks className="w-4 h-4 text-slate-500 shrink-0" />,
              onSelect: onRestoreChecklist,
            },
          ]
        : []),
    ];

    return [...contextItems, ...quickItems, ...projectItems, ...navItems];
  }, [
    locale,
    isDark,
    t,
    toggleTheme,
    toggleLocale,
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
  ]);

  const catalogCommandItems = useMemo<CommandItem[]>(() => {
    const isEs = locale === 'es';
    return catalogTemplates.map((tpl) => {
      const ramLabel =
        tpl.totalMemoryMb >= 1024
          ? `${(tpl.totalMemoryMb / 1024).toFixed(tpl.totalMemoryMb % 1024 === 0 ? 0 : 1)} GB`
          : `${tpl.totalMemoryMb || tpl.memoryMb} MB`;
      return {
        id: `cat-${tpl.id}`,
        group: 'catalog',
        label: tpl.name,
        hint: `${tpl.categoryLabel} · ${tpl.summary}`,
        badge: ramLabel,
        keywords: `${tpl.id} ${tpl.name} ${tpl.category} ${tpl.categoryLabel} ${(tpl.tags || []).join(' ')} ${tpl.summary}`,
        icon: <Boxes className="w-4 h-4 text-slate-500 shrink-0" />,
        onSelect: () => {
          try {
            window.sessionStorage.setItem('culkibo_catalog_search_hint', tpl.name);
          } catch {
            // ignore
          }
          onNavigate('catalog');
          onNotify?.(
            isEs
              ? `Catálogo abierto · busca «${tpl.name}» para instalar en 1 clic`
              : `Catalog opened · search “${tpl.name}” for 1-click install`,
            'info'
          );
        },
      };
    });
  }, [catalogTemplates, onNavigate, onNotify, locale]);

  const filtered = useMemo(() => {
    const q = query.trim();
    if (!q) {
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
    const groupOrder: Array<{ id: GroupId; label: string }> = [
      { id: 'current', label: t('cmd.groupCurrent') },
      { id: 'quick', label: t('cmd.groupQuick') },
      { id: 'projects', label: t('cmd.groupProjects') },
      { id: 'catalog', label: t('cmd.groupCatalog') },
      { id: 'nav', label: t('cmd.groupNav') },
    ];
    return groupOrder
      .map((g) => ({
        ...g,
        items: filtered.filter((i) => i.group === g.id),
      }))
      .filter((g) => g.items.length > 0);
  }, [filtered, t]);

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
      className="fixed inset-0 z-50 flex items-start justify-center pt-[10vh] sm:pt-[12vh] px-3 sm:px-4 bg-slate-950/35 backdrop-blur-[2px]"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) handleClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
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
            placeholder={t('cmd.placeholder')}
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
              aria-label="Clear search"
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
                {t('cmd.emptyTitle', { query })}
              </div>
              <p className="text-xs text-slate-400">{t('cmd.emptyHint')}</p>
            </div>
          ) : (
            orderedGroups.map((group) => (
              <div key={group.id}>
                <div className="px-2.5 pt-1.5 pb-1 flex items-center justify-between text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  <span>{group.label}</span>
                  {group.id === 'catalog' && catalogTemplates.length > 0 && (
                    <span className="font-mono text-[10px] font-normal normal-case text-slate-400 tabular-nums">
                      {t('cmd.indexedApps', { count: catalogTemplates.length })}
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
            <span>{t('cmd.footerNav')}</span>
            <span>{t('cmd.footerOpen')}</span>
            <span>
              {flatItems.length} {flatItems.length === 1 ? t('cmd.resultSingular') : t('cmd.resultPlural')}
            </span>
          </div>
          <span className="font-mono text-slate-400">{IS_MAC ? '⌘K' : 'Ctrl+K'}</span>
        </div>
      </div>
    </div>
  );
};
