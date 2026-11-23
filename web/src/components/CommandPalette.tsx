import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  Bot,
  Boxes,
  FolderKanban,
  Globe,
  Plus,
  Search,
  Settings,
  Terminal,
  Upload,
} from 'lucide-react';
import type { Project } from '../lib/api';

export interface CommandItem {
  id: string;
  group: 'Proyectos' | 'Navegación' | 'Acciones rápidas';
  label: string;
  hint?: string;
  keywords?: string;
  icon: React.ReactNode;
  onSelect: () => void;
}

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  projects: Project[];
  onNavigate: (view: string) => void;
  onSelectProject: (id: string) => void;
  onQuickCreateProject: () => void;
  onQuickConnectDomain: () => void;
  onQuickImport: (source?: 'wordpress' | 'compose' | 'git' | 'platform' | 'coolify') => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  open,
  onClose,
  projects,
  onNavigate,
  onSelectProject,
  onQuickCreateProject,
  onQuickConnectDomain,
  onQuickImport,
}) => {
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    inputRef.current?.focus();
    const raf = window.requestAnimationFrame(() => inputRef.current?.focus());
    return () => {
      document.body.style.overflow = prevOverflow;
      window.cancelAnimationFrame(raf);
    };
  }, [open]);

  const items = useMemo<CommandItem[]>(() => {
    const statusLabels: Record<string, string> = {
      active: 'Activo',
      running: 'Activo',
      stopped: 'Detenido',
      hibernated: 'En reposo',
      sleeping: 'En reposo',
      building: 'Compilando',
      error: 'Error',
    };
    const projectItems: CommandItem[] = projects.map((p) => ({
      id: `proj-${p.id}`,
      group: 'Proyectos',
      label: p.name,
      hint: p.domains?.[0] || p.gitRepo || statusLabels[p.status] || p.status,
      keywords: `${p.name} ${p.description || ''} ${(p.domains || []).join(' ')}`,
      icon: <FolderKanban className="w-4 h-4 text-slate-500" />,
      onSelect: () => onSelectProject(p.id),
    }));

    const navItems: CommandItem[] = [
      {
        id: 'nav-projects',
        group: 'Navegación',
        label: 'Ir a Proyectos',
        hint: 'Panel principal',
        keywords: 'proyectos apps inicio home',
        icon: <FolderKanban className="w-4 h-4 text-slate-500" />,
        onSelect: () => onNavigate('projects'),
      },
      {
        id: 'nav-metrics',
        group: 'Navegación',
        label: 'Ir a Métricas y salud',
        hint: 'Latencia, Prometheus y Doctor',
        keywords: 'metricas observabilidad doctor prometheus latencia ram cpu salud',
        icon: <Activity className="w-4 h-4 text-slate-500" />,
        onSelect: () => onNavigate('metrics'),
      },
      {
        id: 'nav-domains',
        group: 'Navegación',
        label: 'Ir a Dominios y HTTPS',
        hint: 'Caddy, Cloudflare y TLS',
        keywords: 'dominios ssl https tls wildcard caddy dns',
        icon: <Globe className="w-4 h-4 text-slate-500" />,
        onSelect: () => onNavigate('domains'),
      },
      {
        id: 'nav-catalog',
        group: 'Navegación',
        label: 'Ir al Catálogo de servicios',
        hint: 'WordPress, n8n, Postgres y más',
        keywords: 'catalogo servicios wordpress n8n ghost plausible',
        icon: <Boxes className="w-4 h-4 text-slate-500" />,
        onSelect: () => onNavigate('catalog'),
      },
      {
        id: 'nav-import',
        group: 'Navegación',
        label: 'Ir a Importar y migrar',
        hint: 'WordPress, Compose, Git, Vercel, Coolify',
        keywords: 'importar migrar wordpress coolify vercel railway docker compose',
        icon: <Upload className="w-4 h-4 text-slate-500" />,
        onSelect: () => onNavigate('import'),
      },
      {
        id: 'nav-ai',
        group: 'Navegación',
        label: 'Ir a Agentes de IA (MCP)',
        hint: 'Herramientas MCP 2026-07-28 y Live Sync',
        keywords: 'ia mcp claude cursor codex agentes herramientas',
        icon: <Bot className="w-4 h-4 text-slate-500" />,
        onSelect: () => onNavigate('ai'),
      },
      {
        id: 'nav-logs',
        group: 'Navegación',
        label: 'Ir a Registros en directo',
        hint: 'Stream WebSocket en vivo',
        keywords: 'logs registros consola errores',
        icon: <Terminal className="w-4 h-4 text-slate-500" />,
        onSelect: () => onNavigate('global_logs'),
      },
      {
        id: 'nav-settings',
        group: 'Navegación',
        label: 'Ir a Ajustes',
        hint: 'Seguridad, Cloudflare, S3 y alertas',
        keywords: 'ajustes configuracion token s3 notificaciones telegram discord',
        icon: <Settings className="w-4 h-4 text-slate-500" />,
        onSelect: () => onNavigate('settings'),
      },
    ];

    const quickItems: CommandItem[] = [
      {
        id: 'act-new-project',
        group: 'Acciones rápidas',
        label: 'Crear nuevo proyecto',
        hint: 'Desde GitHub, URL Git o vacío',
        keywords: 'crear nuevo proyecto app',
        icon: <Plus className="w-4 h-4 text-slate-500" />,
        onSelect: onQuickCreateProject,
      },
      {
        id: 'act-connect-domain',
        group: 'Acciones rápidas',
        label: 'Conectar un dominio HTTPS',
        hint: 'Asistente paso a paso',
        keywords: 'conectar dominio ssl wildcard',
        icon: <Globe className="w-4 h-4 text-slate-500" />,
        onSelect: onQuickConnectDomain,
      },
      {
        id: 'act-wp',
        group: 'Acciones rápidas',
        label: 'Migrar una web WordPress',
        hint: 'Analiza y clona sin caídas',
        keywords: 'wordpress woocommerce migrar',
        icon: <Upload className="w-4 h-4 text-slate-500" />,
        onSelect: () => onQuickImport('wordpress'),
      },
      {
        id: 'act-compose',
        group: 'Acciones rápidas',
        label: 'Importar docker-compose.yml',
        hint: 'Detecta servicios y bases de datos',
        keywords: 'docker compose yaml importar',
        icon: <Upload className="w-4 h-4 text-slate-500" />,
        onSelect: () => onQuickImport('compose'),
      },
    ];

    return [...quickItems, ...projectItems, ...navItems];
  }, [projects, onNavigate, onSelectProject, onQuickCreateProject, onQuickConnectDomain, onQuickImport]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter((item) => {
      const hay = `${item.label} ${item.hint || ''} ${item.keywords || ''}`.toLowerCase();
      return q.split(/\s+/).every((part) => hay.includes(part));
    });
  }, [items, query]);

  const safeIndex = Math.min(activeIndex, Math.max(0, filtered.length - 1));
  const listRef = useRef<HTMLDivElement>(null);

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

  const groups: Array<CommandItem['group']> = ['Acciones rápidas', 'Proyectos', 'Navegación'];

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[12vh] px-4 bg-slate-900/25 backdrop-blur-[2px]"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) handleClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Paleta de comandos"
        className="culkibo-modal-enter w-full max-w-xl bg-white border border-slate-200 rounded-xl shadow-xl overflow-hidden"
      >
        <div className="flex items-center gap-2.5 px-4 py-3 border-b border-slate-200">
          <Search className="w-4 h-4 text-slate-400 shrink-0" />
          <input
            ref={inputRef}
            autoFocus
            type="text"
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
                setActiveIndex((i) => Math.min(filtered.length - 1, i + 1));
              } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setActiveIndex((i) => Math.max(0, i - 1));
              } else if (e.key === 'Enter' && filtered[safeIndex]) {
                e.preventDefault();
                runItem(filtered[safeIndex]);
              }
            }}
            placeholder="Buscar proyectos, vistas o acciones…"
            className="w-full bg-transparent text-sm text-slate-900 placeholder:text-slate-400 border-0 !shadow-none !outline-none"
          />
          <kbd className="hidden sm:inline-block px-1.5 py-0.5 text-[10px] font-mono text-slate-400 bg-slate-100 border border-slate-200 rounded">
            Esc
          </kbd>
        </div>

        <div ref={listRef} className="max-h-[55vh] overflow-y-auto py-2">
          {filtered.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-slate-500">
              No hay resultados para «{query}».
            </div>
          ) : (
            groups.map((groupName) => {
              const groupItems = filtered.filter((i) => i.group === groupName);
              if (groupItems.length === 0) return null;
              return (
                <div key={groupName} className="mb-1">
                  <div className="px-4 py-1.5 text-[11px] font-medium text-slate-400 uppercase tracking-wider">
                    {groupName}
                  </div>
                  {groupItems.map((item) => {
                    const globalIdx = filtered.indexOf(item);
                    const isActive = globalIdx === safeIndex;
                    return (
                      <button
                        key={item.id}
                        data-cmd-idx={globalIdx}
                        type="button"
                        onMouseEnter={() => setActiveIndex(globalIdx)}
                        onClick={() => runItem(item)}
                        className={`w-full px-4 py-2 flex items-center justify-between gap-3 text-left transition-colors cursor-pointer ${
                          isActive ? 'bg-slate-100 text-slate-900' : 'text-slate-700 hover:bg-slate-50'
                        }`}
                      >
                        <span className="flex items-center gap-2.5 min-w-0">
                          {item.icon}
                          <span className="text-sm font-medium truncate">{item.label}</span>
                        </span>
                        {item.hint && (
                          <span className="text-xs text-slate-400 truncate max-w-[200px]">{item.hint}</span>
                        )}
                      </button>
                    );
                  })}
                </div>
              );
            })
          )}
        </div>

        <div className="px-4 py-2 border-t border-slate-100 bg-slate-50/70 flex items-center justify-between text-[11px] text-slate-400">
          <span>↑↓ navegar · Enter abrir</span>
          <span>⌘K / Ctrl+K</span>
        </div>
      </div>
    </div>
  );
};
