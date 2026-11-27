import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Settings,
  LayoutGrid,
  ScrollText,
  Globe,
  Variable,
  Play,
  Square,
  Moon,
  Trash2,
  ShieldAlert,
  Database,
  Server,
  Copy,
  Eye,
  EyeOff,
  Plus,
  Search,
  Upload,
  Save,
  CheckCircle2,
  Box,
  Cpu,
  Webhook,
  Check,
  RefreshCw,
  Zap,
  Power,
  Rocket,
  ArrowLeft,
  Activity,
  PauseCircle,
  MoreHorizontal,
  FolderOpen,
  KeyRound,
  Loader2,
  X,
} from 'lucide-react';
import { api, type Project } from '../lib/api';
import { liveEvents } from '../lib/liveEvents';
import { copyToClipboard } from '../lib/clipboard';
import { useI18n } from '../lib/i18n';
import { LiveLogs } from './LiveLogs';
import { DomainManager } from './DomainManager';
import { DatabasesPanel } from './DatabasesPanel';
import { DeploymentsPanel } from './DeploymentsPanel';
import { LiveForgePanel } from './LiveForgePanel';
import { Modal } from './Modal';
import { HelpTip } from './HelpTip';

type ProjectTabId = 'general' | 'live' | 'deployments' | 'logs' | 'domains' | 'databases' | 'storage' | 'vars' | 'config';

function normalizeProjectTab(raw?: string | null): ProjectTabId {
  if (!raw) return 'general';
  const map: Record<string, ProjectTabId> = {
    general: 'general',
    live: 'live',
    sync: 'live',
    deploy: 'deployments',
    deployments: 'deployments',
    logs: 'logs',
    domains: 'domains',
    databases: 'databases',
    db: 'databases',
    storage: 'storage',
    vars: 'vars',
    env: 'vars',
    config: 'config',
    settings: 'config',
  };
  return map[raw.toLowerCase()] || 'general';
}

interface ProjectDetailProps {
  projectId: string;
  initialTab?: string | null;
  onTabChange?: (tab: string) => void;
  onBack: () => void;
  onNotify: (msg: string, type?: 'info' | 'success' | 'error') => void;
  onProjectUpdate?: () => void;
  onOpenCatalog?: () => void;
  onOpenBackupSettings?: () => void;
  incomingLog?: any;
}

type EnvRow = { key: string; value: string; id: string };

function envObjectToRows(envVars?: Record<string, string>): EnvRow[] {
  return Object.entries(envVars || {}).map(([k, v], i) => ({
    key: k,
    value: String(v ?? ''),
    id: `row_${i}_${k}`,
  }));
}

function envRowsToText(rows: EnvRow[]): string {
  return rows
    .filter((r) => r.key.trim())
    .map((r) => `${r.key.trim()}=${r.value}`)
    .join('\n');
}

function parseRawEnv(raw: string): Record<string, string> {
  const out: Record<string, string> = {};
  const lines = raw.replace(/\r\n?/g, '\n').split('\n');
  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const match = trimmed.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!match) continue;
    const key = match[1];
    let val = match[2];
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    out[key] = val;
  }
  return out;
}

export const ProjectDetail: React.FC<ProjectDetailProps> = ({
  projectId,
  initialTab,
  onTabChange,
  onBack,
  onNotify,
  onProjectUpdate,
  onOpenCatalog,
  onOpenBackupSettings,
  incomingLog,
}) => {
  const { t, locale } = useI18n();
  const [envSavedPendingRestart, setEnvSavedPendingRestart] = useState(false);
  const [fastRestarting, setFastRestarting] = useState(false);
  const [lastFastRestart, setLastFastRestart] = useState<{ durationMs: number | null } | null>(null);
  const [project, setProject] = useState<Project | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [activeTab, setActiveTabState] = useState<ProjectTabId>(() => normalizeProjectTab(initialTab));
  const [loading, setLoading] = useState(false);
  const [simulatingWebhook, setSimulatingWebhook] = useState(false);
  const [webhookProvider, setWebhookProvider] = useState<'github' | 'gitlab' | 'gitea' | 'bitbucket' | 'deploy_hook'>('github');
  const [rotatingHook, setRotatingHook] = useState(false);
  const [moreMenuOpen, setMoreMenuOpen] = useState(false);
  const moreMenuRef = useRef<HTMLDivElement>(null);
  const [configDirty, setConfigDirty] = useState(false);

  const setActiveTab = useCallback((next: ProjectTabId) => {
    setActiveTabState(next);
    onTabChange?.(next);
  }, [onTabChange]);

  const [prevInitialTab, setPrevInitialTab] = useState(initialTab);
  if (initialTab !== prevInitialTab) {
    setPrevInitialTab(initialTab);
    if (initialTab) setActiveTabState(normalizeProjectTab(initialTab));
  }

  useEffect(() => {
    if (!moreMenuOpen) return;
    const onDown = (e: MouseEvent) => {
      if (moreMenuRef.current && !moreMenuRef.current.contains(e.target as Node)) setMoreMenuOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMoreMenuOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [moreMenuOpen]);

  const [copiedUrl, setCopiedUrl] = useState(false);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [showSecret, setShowSecret] = useState(false);

  const [envMode, setEnvMode] = useState<'table' | 'raw'>('table');
  const [envText, setEnvText] = useState('');
  const [envRows, setEnvRows] = useState<EnvRow[]>([]);
  const [showValues, setShowValues] = useState<Record<string, boolean>>({});
  const [searchVar, setSearchVar] = useState('');
  const envFileInputRef = useRef<HTMLInputElement>(null);

  const [showVolumeForm, setShowVolumeForm] = useState(false);
  const [volForm, setVolForm] = useState({ name: '', mount_path: '/data', host_path: '' });
  const [showMountForm, setShowMountForm] = useState(false);
  const [mountForm, setMountForm] = useState({ mount_path: '/etc/app/config.json', content: '', chmod: '644' });

  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [confirmDeleteName, setConfirmDeleteName] = useState('');
  const [deleting, setDeleting] = useState(false);

  const [prevProjectId, setPrevProjectId] = useState(projectId);
  const lastEnvJsonRef = useRef<string>('');
  const reqIdRef = useRef(0);
  const [togglingMaintenance, setTogglingMaintenance] = useState(false);

  if (prevProjectId !== projectId) {
    setPrevProjectId(projectId);
    setProject(null);
    setLoadError(null);
  }

  const syncEnvState = useCallback((envVars?: Record<string, string>) => {
    const rows = envObjectToRows(envVars);
    lastEnvJsonRef.current = JSON.stringify(envVars || {});
    setEnvRows(rows);
    setEnvText(envRowsToText(rows));
  }, []);

  const fetchProject = useCallback(async () => {
    const myReq = ++reqIdRef.current;
    try {
      setLoadError(null);
      const found = await api.getProject(projectId);
      if (myReq !== reqIdRef.current) return;
      if (found) {
        setProject(found);
        syncEnvState(found.envVars);
      }
    } catch (e: any) {
      if (myReq !== reqIdRef.current) return;
      setLoadError(e?.message || 'No se pudo cargar el proyecto');
    }
  }, [projectId, syncEnvState]);

  useEffect(() => {
    let active = true;
    const myReq = ++reqIdRef.current;
    api.getProject(projectId)
      .then((found) => {
        if (!active || myReq !== reqIdRef.current || !found) return;
        setProject(found);
        setLoadError(null);
        syncEnvState(found.envVars);
      })
      .catch((e: any) => {
        if (active && myReq === reqIdRef.current) setLoadError(e?.message || 'Proyecto no encontrado');
      });
    return () => { active = false; };
  }, [projectId, syncEnvState]);

  useEffect(() => {
    return liveEvents.onProjectChange((ev) => {
      const updated = ev.project;
      if (ev.action === 'update' && updated && updated.id === projectId) {
        setProject(updated);
        const nextEnv = JSON.stringify(updated.envVars || {});
        if (lastEnvJsonRef.current !== nextEnv) {
          syncEnvState(updated.envVars);
        }
      } else if (ev.action === 'deleted' && ev.id === projectId) {
        onBack();
      }
    });
  }, [projectId, onBack, syncEnvState]);

  const switchEnvMode = (nextMode: 'table' | 'raw') => {
    if (nextMode === envMode) return;
    if (nextMode === 'raw') {
      setEnvText(envRowsToText(envRows));
    } else {
      const parsed = parseRawEnv(envText);
      setEnvRows(envObjectToRows(parsed));
    }
    setEnvMode(nextMode);
  };

  const handleImportEnvFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const content = String(reader.result || '');
      setEnvText(content);
      setEnvRows(envObjectToRows(parseRawEnv(content)));
      setEnvMode('raw');
      onNotify(`Archivo ${file.name} cargado. Pulsa «Guardar variables» para aplicarlo.`, 'info');
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const handleAddVolume = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!project || !volForm.name.trim() || !volForm.mount_path.trim()) return;
    try {
      const nextVolumes = [
        ...(project.volumes || []),
        {
          name: volForm.name.trim(),
          mount_path: volForm.mount_path.trim(),
          host_path: volForm.host_path.trim() || undefined,
        },
      ];
      await api.updateProject(projectId, { volumes: nextVolumes });
      setVolForm({ name: '', mount_path: '/data', host_path: '' });
      setShowVolumeForm(false);
      onNotify('Volumen persistente guardado', 'success');
      void fetchProject();
    } catch (err: any) {
      onNotify(err?.message || 'Error al añadir volumen', 'error');
    }
  };

  const handleRemoveVolume = async (index: number) => {
    if (!project) return;
    const nextVolumes = (project.volumes || []).filter((_, i) => i !== index);
    try {
      await api.updateProject(projectId, { volumes: nextVolumes });
      onNotify('Volumen eliminado', 'info');
      void fetchProject();
    } catch (err: any) {
      onNotify(err?.message || 'Error al eliminar volumen', 'error');
    }
  };

  const handleAddFileMount = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!project || !mountForm.mount_path.trim()) return;
    try {
      const nextMounts = [
        ...(project.fileMounts || []),
        {
          mount_path: mountForm.mount_path.trim(),
          content: mountForm.content,
          chmod: mountForm.chmod.trim() || '644',
        },
      ];
      await api.updateProject(projectId, { fileMounts: nextMounts });
      setMountForm({ mount_path: '/etc/app/config.json', content: '', chmod: '644' });
      setShowMountForm(false);
      onNotify('Archivo montado guardado', 'success');
      void fetchProject();
    } catch (err: any) {
      onNotify(err?.message || 'Error al añadir archivo montado', 'error');
    }
  };

  const handleRemoveFileMount = async (index: number) => {
    if (!project) return;
    const nextMounts = (project.fileMounts || []).filter((_, i) => i !== index);
    try {
      await api.updateProject(projectId, { fileMounts: nextMounts });
      onNotify('Archivo montado eliminado', 'info');
      void fetchProject();
    } catch (err: any) {
      onNotify(err?.message || 'Error al eliminar archivo montado', 'error');
    }
  };

  const handleSimulatePush = async () => {
    if (!project) return;
    setSimulatingWebhook(true);
    try {
      const res = await api.testProjectWebhook(project.id);
      onNotify(res.message || 'Prueba de webhook ejecutada correctamente', 'success');
      void fetchProject();
    } catch (e: any) {
      onNotify(e?.message || 'Error al probar el webhook', 'error');
    } finally {
      setSimulatingWebhook(false);
    }
  };

  if (loadError) {
    return (
      <div className="bg-white border border-slate-200 rounded-xl p-8 max-w-lg mx-auto text-center space-y-4">
        <h2 className="text-base font-semibold text-slate-900">No se pudo cargar el proyecto</h2>
        <p className="text-xs text-slate-500">{loadError}</p>
        <div className="flex items-center justify-center gap-2">
          <button
            type="button"
            onClick={onBack}
            className="px-3.5 py-2 rounded-lg text-xs font-medium border border-slate-200 text-slate-700 hover:bg-slate-50 cursor-pointer"
          >
            Volver a proyectos
          </button>
          <button
            type="button"
            onClick={() => void fetchProject()}
            className="px-3.5 py-2 rounded-lg text-xs font-medium bg-slate-900 text-white hover:bg-slate-800 cursor-pointer"
          >
            Reintentar
          </button>
        </div>
      </div>
    );
  }

  if (!project) {
    return <div className="p-10 text-center text-xs text-slate-500">Cargando proyecto…</div>;
  }

  const previewHost = typeof window !== 'undefined' ? window.location.hostname : 'localhost';

  const handleStop = async () => {
    setLoading(true);
    try {
      await api.stopProject(projectId);
      await fetchProject();
      onNotify('Proyecto detenido y puerto liberado', 'info');
      onProjectUpdate?.();
    } catch (e: any) {
      onNotify(e?.message || 'Error al detener el proyecto', 'error');
      await fetchProject();
    } finally {
      setLoading(false);
    }
  };

  const handleHibernate = async () => {
    setLoading(true);
    try {
      await api.hibernateProject(projectId);
      await fetchProject();
      onNotify('Proyecto hibernado correctamente', 'info');
      onProjectUpdate?.();
    } catch (e: any) {
      onNotify(e?.message || 'Error al hibernar el proyecto', 'error');
      await fetchProject();
    } finally {
      setLoading(false);
    }
  };

  const handleStart = async () => {
    setLoading(true);
    try {
      await api.startLocal(projectId);
      await fetchProject();
      onNotify('Proyecto iniciado en local', 'success');
      onProjectUpdate?.();
    } catch (e: any) {
      onNotify(e?.message || 'Error al iniciar en local', 'error');
      await fetchProject();
    } finally {
      setLoading(false);
    }
  };

  const handleActivate = async () => {
    setLoading(true);
    try {
      await api.activateProject(projectId);
      await fetchProject();
      onNotify('Proyecto marcado como activo', 'success');
      onProjectUpdate?.();
    } catch (e: any) {
      onNotify(e?.message || 'Error al activar el proyecto', 'error');
      await fetchProject();
    } finally {
      setLoading(false);
    }
  };

  const handleSaveEnvRaw = async () => {
    const newVars = parseRawEnv(envText);
    try {
      await api.updateProject(projectId, { envVars: newVars });
      setEnvSavedPendingRestart(true);
      setLastFastRestart(null);
      onNotify(locale === 'es' ? 'Variables de entorno guardadas' : 'Environment variables saved', 'success');
      await fetchProject();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error saving env vars';
      onNotify(msg, 'error');
    }
  };

  const handleSaveEnvTable = async () => {
    const newVars: Record<string, string> = {};
    for (const r of envRows) {
      if (r.key.trim()) newVars[r.key.trim()] = r.value;
    }
    try {
      await api.updateProject(projectId, { envVars: newVars });
      setEnvSavedPendingRestart(true);
      setLastFastRestart(null);
      onNotify(locale === 'es' ? 'Variables de entorno guardadas' : 'Environment variables saved', 'success');
      await fetchProject();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error saving env vars';
      onNotify(msg, 'error');
    }
  };

  const handleFastRestart = async () => {
    setFastRestarting(true);
    try {
      const res = await api.fastRestartProject(projectId);
      const durationMs = typeof res.durationMs === 'number' ? res.durationMs : null;
      setEnvSavedPendingRestart(false);
      setLastFastRestart({ durationMs });
      const msLabel = durationMs !== null
        ? (durationMs >= 1000 ? `${(durationMs / 1000).toFixed(1)}s` : `${Math.round(durationMs)}ms`)
        : '~1.5s';
      onNotify(t('pd.fastRestartDone', { ms: msLabel }), 'success');
      await fetchProject();
      onProjectUpdate?.();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Fast restart unavailable';
      onNotify(msg, 'error');
    } finally {
      setFastRestarting(false);
    }
  };

  const handleDelete = async () => {
    if (confirmDeleteName.trim() !== project.name) return;
    setDeleting(true);
    try {
      await api.deleteProject(projectId);
      onNotify('Proyecto eliminado', 'info');
      onBack();
    } catch (e: any) {
      onNotify(e?.message || 'Error al eliminar el proyecto', 'error');
      setDeleting(false);
    }
  };

  const copyValue = async (text: string, message = 'Copiado al portapapeles') => {
    const ok = await copyToClipboard(text);
    onNotify(ok ? message : 'No se pudo copiar al portapapeles', ok ? 'success' : 'error');
  };

  const domainCount = (project.domains || []).length;
  const dbCount = (project.linkedDatabaseIds || []).length;
  const envCount = Object.keys(project.envVars || {}).length;

  const envIsDirty = (() => {
    const currentObj: Record<string, string> = {};
    if (envMode === 'table') {
      for (const r of envRows) {
        if (r.key.trim()) currentObj[r.key.trim()] = r.value;
      }
    } else {
      Object.assign(currentObj, parseRawEnv(envText));
    }
    return JSON.stringify(currentObj) !== JSON.stringify(project.envVars || {});
  })();

  const tabGroups: Array<{
    group: string;
    items: Array<{ id: ProjectTabId; label: string; icon: React.ComponentType<{ className?: string }>; count?: number }>;
  }> = [
    {
      group: 'Operación',
      items: [
        { id: 'general', label: 'General', icon: LayoutGrid },
        { id: 'deployments', label: 'Despliegues', icon: Rocket },
        { id: 'live', label: 'En vivo', icon: Zap },
        { id: 'logs', label: 'Registros', icon: ScrollText },
      ],
    },
    {
      group: 'Infraestructura',
      items: [
        { id: 'domains', label: 'Dominios', icon: Globe, count: domainCount },
        { id: 'databases', label: 'Bases de datos', icon: Database, count: dbCount },
        { id: 'storage', label: 'Almacenamiento', icon: Box },
      ],
    },
    {
      group: 'Ajustes',
      items: [
        { id: 'vars', label: 'Variables', icon: Variable, count: envCount },
        { id: 'config', label: 'Configuración', icon: Settings },
      ],
    },
  ];

  const handleToggleMaintenance = async () => {
    const nextEnabled = !project.maintenanceMode;
    setTogglingMaintenance(true);
    try {
      const res = await api.toggleMaintenance(project.id, nextEnabled);
      if (res.project) setProject(res.project);
      else await fetchProject();
      onNotify(
        nextEnabled
          ? 'Modo mantenimiento activado (<10 ms en Caddy): el tráfico público recibe 503.'
          : 'Modo mantenimiento desactivado: tráfico restaurado en Caddy.',
        nextEnabled ? 'info' : 'success'
      );
      onProjectUpdate?.();
    } catch (e: any) {
      onNotify(e?.message || 'No se pudo cambiar el modo mantenimiento', 'error');
    } finally {
      setTogglingMaintenance(false);
    }
  };

  const monogramWords = (project.name || 'PR').replace(/[^a-zA-Z0-9\s-]/g, ' ').split(/[\s-]+/).filter(Boolean);
  const monogram = monogramWords.length >= 2
    ? `${monogramWords[0][0]}${monogramWords[1][0]}`.toUpperCase()
    : (monogramWords[0] || 'PR').slice(0, 2).toUpperCase();

  return (
    <div className="space-y-5">
      {/* Cabecera limpia directamente sobre el lienzo */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-start gap-3 min-w-0">
          <button
            type="button"
            onClick={onBack}
            aria-label="Volver a proyectos"
            className="mt-1 p-2 rounded-lg border border-slate-200 bg-white text-slate-500 hover:text-slate-900 hover:bg-slate-50 transition-colors cursor-pointer shrink-0"
            title="Volver a proyectos"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <span
            aria-hidden="true"
            className="mt-0.5 w-10 h-10 rounded-lg bg-slate-900 text-white font-mono text-xs font-semibold flex items-center justify-center shrink-0"
          >
            {monogram}
          </span>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-2xl font-semibold text-slate-900 tracking-tight truncate">{project.name}</h1>
              <span
                className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium border ${
                  project.maintenanceMode
                    ? 'bg-amber-50 text-amber-800 border-amber-200'
                    : project.lastDeployedAt && project.status === 'active'
                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      : project.localRunning
                        ? 'bg-amber-50 text-amber-800 border-amber-200'
                        : 'bg-slate-100 text-slate-600 border-slate-200'
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${
                  project.maintenanceMode
                    ? 'bg-amber-500'
                    : project.lastDeployedAt && project.status === 'active'
                      ? 'bg-emerald-500'
                      : project.localRunning
                        ? 'bg-amber-500'
                        : 'bg-slate-400'
                }`} />
                {project.maintenanceMode
                  ? 'Mantenimiento (503)'
                  : project.lastDeployedAt && project.status === 'active'
                    ? 'En producción'
                    : project.localRunning
                      ? `En local${project.localPort ? ` :${project.localPort}` : ''}`
                      : project.status === 'hibernated'
                        ? 'Hibernado'
                        : project.status === 'stopped'
                          ? 'Detenido'
                          : 'Sin iniciar'}
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-1">
              {project.description || 'Sin descripción configurada.'}
              {project.lastDeployedAt && (
                <span className="ml-2 text-slate-400 tabular-nums">
                  · Último despliegue: {new Date(project.lastDeployedAt).toLocaleDateString('es-ES')}
                </span>
              )}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap shrink-0">
          {project.maintenanceMode && (
            <button
              type="button"
              onClick={() => void handleToggleMaintenance()}
              disabled={togglingMaintenance}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-amber-50 hover:bg-amber-100 text-amber-900 border border-amber-300 transition-colors cursor-pointer disabled:opacity-50"
            >
              <PauseCircle className="w-3.5 h-3.5 text-amber-600" />
              Salir de mantenimiento
            </button>
          )}

          {project.localRunning && project.localPort ? (
            <a
              href={`http://${previewHost}:${project.localPort}`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 bg-amber-50 hover:bg-amber-100 text-amber-800 px-3 py-2 rounded-lg text-xs font-medium border border-amber-200 tabular-nums"
            >
              <Globe className="w-3.5 h-3.5 text-amber-600" /> Abrir :{project.localPort}
            </a>
          ) : (
            <button
              type="button"
              onClick={handleStart}
              disabled={loading}
              className="inline-flex items-center gap-1.5 bg-slate-900 hover:bg-slate-800 text-white px-3.5 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5" /> Iniciar local
            </button>
          )}

          {project.localRunning ? (
            <button
              type="button"
              onClick={handleStop}
              disabled={loading}
              className="inline-flex items-center gap-1.5 bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 px-3 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer disabled:opacity-50"
            >
              <Square className="w-3 h-3 fill-red-600 text-red-600" /> Detener
            </button>
          ) : project.status !== 'active' ? (
            <button
              type="button"
              onClick={handleActivate}
              disabled={loading}
              className="inline-flex items-center gap-1.5 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 px-3 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer disabled:opacity-50"
            >
              <Power className="w-3.5 h-3.5 text-emerald-600" /> Activar
            </button>
          ) : null}

          {project.domains && project.domains.length > 0 && (
            <a
              href={`https://${project.domains[0]}`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 px-3 py-2 rounded-lg text-xs font-medium transition-colors"
            >
              <Globe className="w-3.5 h-3.5 text-slate-500" /> Ver web
            </a>
          )}

          {/* Menú Más: Mantenimiento, Hibernar, Detener */}
          <div className="relative" ref={moreMenuRef}>
            <button
              type="button"
              onClick={() => setMoreMenuOpen((v) => !v)}
              aria-expanded={moreMenuOpen}
              aria-haspopup="menu"
              aria-label="Más acciones del proyecto"
              className="inline-flex items-center gap-1.5 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 px-2.5 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer"
            >
              <MoreHorizontal className="w-4 h-4" />
            </button>
            {moreMenuOpen && (
              <div
                role="menu"
                className="culkibo-modal-enter absolute right-0 mt-1.5 w-56 bg-white border border-slate-200 rounded-xl shadow-lg py-1.5 z-40"
              >
                <button
                  type="button"
                  role="menuitem"
                  onClick={() => { setMoreMenuOpen(false); void handleToggleMaintenance(); }}
                  disabled={togglingMaintenance}
                  className="w-full px-3.5 py-2 text-left text-xs text-slate-700 hover:bg-slate-50 flex items-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  <PauseCircle className="w-3.5 h-3.5 text-amber-600 shrink-0" />
                  <span>{project.maintenanceMode ? 'Salir de mantenimiento' : 'Modo mantenimiento (503)'}</span>
                </button>
                {project.status === 'active' && (
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => { setMoreMenuOpen(false); void handleHibernate(); }}
                    disabled={loading}
                    className="w-full px-3.5 py-2 text-left text-xs text-slate-700 hover:bg-slate-50 flex items-center gap-2 cursor-pointer disabled:opacity-50"
                  >
                    <Moon className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                    <span>Hibernar proyecto</span>
                  </button>
                )}
                {(project.status === 'active' || project.localRunning) && (
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => { setMoreMenuOpen(false); void handleStop(); }}
                    disabled={loading}
                    className="w-full px-3.5 py-2 text-left text-xs text-red-700 hover:bg-red-50 flex items-center gap-2 cursor-pointer disabled:opacity-50"
                  >
                    <Square className="w-3 h-3 fill-red-600 text-red-600 shrink-0" />
                    <span>Detener procesos</span>
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Pestañas agrupadas en 3 bloques con separador sutil */}
      <div
        role="tablist"
        aria-label="Secciones del proyecto"
        className="flex items-center border-b border-slate-200 gap-1 px-1 overflow-x-auto no-scrollbar"
      >
        {tabGroups.map((group, gIdx) => (
          <React.Fragment key={group.group}>
            {gIdx > 0 && <span aria-hidden="true" className="h-4 w-px bg-slate-200 mx-2 mb-2.5 shrink-0" />}
            <div className="flex items-center gap-3.5 shrink-0">
              {group.items.map((t) => {
                const selected = activeTab === t.id;
                return (
                  <button
                    key={t.id}
                    type="button"
                    role="tab"
                    aria-selected={selected}
                    onClick={() => setActiveTab(t.id)}
                    className={`flex items-center gap-1.5 pb-3 text-xs font-medium border-b-2 transition-colors whitespace-nowrap cursor-pointer shrink-0 ${
                      selected
                        ? 'border-slate-900 text-slate-900'
                        : 'border-transparent text-slate-500 hover:text-slate-800'
                    }`}
                  >
                    <t.icon className={`w-3.5 h-3.5 ${selected ? 'text-slate-900' : 'text-slate-400'}`} />
                    <span>{t.label}</span>
                    {typeof t.count === 'number' && t.count > 0 && (
                      <span className="px-1.5 py-0.2 rounded-full bg-slate-100 text-slate-600 text-[10px] font-mono tabular-nums">
                        {t.count}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </React.Fragment>
        ))}
      </div>

      <div className="pt-1">
        {activeTab === 'live' && (
          <LiveForgePanel projectId={project.id} projectName={project.name} onNotify={onNotify} />
        )}

        {activeTab === 'general' && (
          <div className="space-y-5">
            {!project.localRunning && !project.lastDeployedAt && (
              <div className="bg-white rounded-xl border border-slate-200 p-4 space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <div>
                    <h2 className="text-sm font-semibold text-slate-900">¿Cómo quieres arrancar este proyecto?</h2>
                    <p className="text-xs text-slate-500 mt-0.5">Elige según estés probando en tu equipo o publicando en un servidor.</p>
                  </div>
                  <HelpTip title="Local vs Docker vs Live Sync" align="right">
                    <p><strong>Vista previa local:</strong> corre directo en tu ordenador sin Docker, ideal para probar rápido.</p>
                    <p><strong>Desplegar con Docker:</strong> crea un contenedor aislado con cero cortes y rollback automático.</p>
                    <p><strong>Live Sync:</strong> sincroniza tu editor en milisegundos sin hacer git push.</p>
                  </HelpTip>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
                  <button
                    type="button"
                    onClick={handleStart}
                    disabled={loading}
                    className="p-3 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-left transition-colors cursor-pointer disabled:opacity-50"
                  >
                    <div className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
                      <Play className="w-3.5 h-3.5 text-slate-700" /> Iniciar en local
                    </div>
                    <p className="text-[11px] text-slate-500 mt-1">Arranca rápido en localhost sin necesitar Docker.</p>
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveTab('deployments')}
                    className="p-3 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-left transition-colors cursor-pointer"
                  >
                    <div className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
                      <Rocket className="w-3.5 h-3.5 text-slate-700" /> Desplegar con Docker
                    </div>
                    <p className="text-[11px] text-slate-500 mt-1">Compila imagen, verifica salud y publica detrás de Caddy.</p>
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveTab('live')}
                    className="p-3 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-left transition-colors cursor-pointer"
                  >
                    <div className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
                      <FolderOpen className="w-3.5 h-3.5 text-slate-700" /> Conectar carpeta / Live Sync
                    </div>
                    <p className="text-[11px] text-slate-500 mt-1">Sincroniza cambios desde tu editor en menos de 10 ms.</p>
                  </button>
                </div>
              </div>
            )}

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            <div className="lg:col-span-2 space-y-5">
              <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
                <div className="px-5 py-3.5 border-b border-slate-200 flex justify-between items-center bg-slate-50/70 gap-2 flex-wrap">
                  <h2 className="font-semibold text-sm text-slate-900 flex items-center gap-2">
                    <Box className="w-4 h-4 text-slate-600" />
                    Recursos y entornos
                    <HelpTip title="Desarrollo y Producción">
                      <p><strong>Desarrollo (The Forge):</strong> vista previa local rápida o sincronizada en vivo mientras editas.</p>
                      <p><strong>Producción (The Citadel):</strong> contenedor Docker estable publicado por Caddy con HTTPS automático.</p>
                    </HelpTip>
                  </h2>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setActiveTab('databases')}
                      className="text-xs font-medium text-slate-700 hover:text-slate-900 bg-white border border-slate-200 px-2.5 py-1.5 rounded-lg flex items-center gap-1 cursor-pointer"
                    >
                      <Database className="w-3.5 h-3.5" /> Añadir BD
                    </button>
                    {onOpenCatalog && (
                      <button
                        type="button"
                        onClick={onOpenCatalog}
                        className="text-xs font-medium text-slate-700 hover:text-slate-900 bg-white border border-slate-200 px-2.5 py-1.5 rounded-lg flex items-center gap-1 cursor-pointer"
                      >
                        <Plus className="w-3.5 h-3.5" /> Catálogo
                      </button>
                    )}
                  </div>
                </div>
                <div className="p-5 space-y-3">
                  {project.resources && project.resources.length > 0 ? (
                    project.resources.map((res: any) => {
                      const isResActive = project.status === 'active' && (project.localRunning || res.status === 'running' || res.status === 'active');
                      return (
                        <div key={res.id} className="flex items-center justify-between p-3.5 rounded-xl border border-slate-200 bg-white gap-3 flex-wrap">
                          <div className="flex items-center gap-3 min-w-0">
                            <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-600 shrink-0">
                              {res.type === 'database' ? <Database className="w-4 h-4" /> : <Server className="w-4 h-4" />}
                            </div>
                            <div className="min-w-0">
                              <div className="text-sm font-medium text-slate-900 truncate">{res.name}</div>
                              <div className="text-xs text-slate-500">
                                {res.type} · <span className="font-mono">{res.image || 'proceso local'}</span>
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-3 text-xs">
                            {project.localRunning && res.localPort && (
                              <a
                                href={`http://${previewHost}:${res.localPort}`}
                                target="_blank"
                                rel="noreferrer"
                                className="inline-flex items-center gap-1 bg-slate-100 text-slate-700 hover:bg-slate-200 px-2.5 py-1 rounded-md font-mono"
                              >
                                <Globe className="w-3 h-3" /> :{res.localPort}
                              </a>
                            )}
                            <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full font-medium border ${
                              isResActive
                                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                : 'bg-slate-100 text-slate-600 border-slate-200'
                            }`}>
                              <span className={`w-1.5 h-1.5 rounded-full ${isResActive ? 'bg-emerald-500' : 'bg-slate-400'}`} />
                              {isResActive ? 'Activo' : 'Detenido'}
                            </span>
                            <span className="text-slate-400 font-mono tabular-nums">
                              {Array.isArray(res.ports) ? res.ports.join(', ') : (res.ports || res.port || '—')}
                            </span>
                          </div>
                        </div>
                      );
                    })
                  ) : (
                    <>
                      <div className="flex items-center justify-between p-3.5 rounded-xl border border-slate-200 bg-white gap-3">
                        <div className="flex items-center gap-3">
                          <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-600">
                            <Cpu className="w-4 h-4" />
                          </div>
                          <div>
                            <div className="text-sm font-medium text-slate-900">Entorno de desarrollo</div>
                            <div className="text-xs text-slate-500">Vista previa local y sincronización en vivo</div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3 text-xs">
                          <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full font-medium border ${
                            project.localRunning
                              ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                              : 'bg-slate-100 text-slate-600 border-slate-200'
                          }`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${project.localRunning ? 'bg-emerald-500' : 'bg-slate-400'}`} />
                            {project.localRunning ? 'En ejecución' : 'Detenido'}
                          </span>
                          <span className="text-slate-400 font-mono tabular-nums">:{project.localPort || project.forgePort}</span>
                        </div>
                      </div>

                      <div className="flex items-center justify-between p-3.5 rounded-xl border border-slate-200 bg-white gap-3">
                        <div className="flex items-center gap-3">
                          <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-600">
                            <Server className="w-4 h-4" />
                          </div>
                          <div>
                            <div className="text-sm font-medium text-slate-900">Entorno de producción</div>
                            <div className="text-xs text-slate-500">Contenedor Docker aislado detrás de Caddy</div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3 text-xs">
                          <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full font-medium border ${
                            project.lastDeployedAt && project.status === 'active'
                              ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                              : 'bg-slate-100 text-slate-600 border-slate-200'
                          }`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${project.lastDeployedAt && project.status === 'active' ? 'bg-emerald-500' : 'bg-slate-400'}`} />
                            {project.lastDeployedAt
                              ? (project.status === 'active' ? 'Desplegado' : 'Detenido')
                              : 'Sin desplegar'}
                          </span>
                          <span className="text-slate-400 font-mono tabular-nums">:{project.citadelPort}</span>
                        </div>
                      </div>
                    </>
                  )}
                </div>
              </div>
            </div>

            <div className="space-y-5">
              <div className="bg-white p-5 rounded-xl border border-slate-200 space-y-4">
                <h2 className="font-semibold text-sm text-slate-900 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-slate-600" /> Reparto de tráfico
                </h2>
                <div className="space-y-3 text-xs">
                  <div>
                    <div className="flex justify-between mb-1.5">
                      <span className="text-slate-600">Desarrollo</span>
                      <span className="font-mono font-semibold text-slate-900 tabular-nums">{project.trafficSplit?.forge || 0}%</span>
                    </div>
                    <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                      <div className="bg-slate-900 h-2 rounded-full" style={{ width: `${project.trafficSplit?.forge || 0}%` }} />
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between mb-1.5">
                      <span className="text-slate-600">Producción</span>
                      <span className="font-mono font-semibold text-slate-900 tabular-nums">{project.trafficSplit?.citadel || 0}%</span>
                    </div>
                    <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                      <div className="bg-emerald-500 h-2 rounded-full" style={{ width: `${project.trafficSplit?.citadel || 0}%` }} />
                    </div>
                  </div>
                </div>
                <div className="pt-3 border-t border-slate-100 space-y-2">
                  <button
                    type="button"
                    onClick={() => setActiveTab('deployments')}
                    className="w-full py-2 bg-slate-900 text-white rounded-lg text-xs font-medium hover:bg-slate-800 transition-colors cursor-pointer"
                  >
                    Publicar a producción →
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveTab('live')}
                    className="w-full py-2 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 rounded-lg text-xs font-medium transition-colors cursor-pointer"
                  >
                    Abrir sincronización en vivo
                  </button>
                </div>
              </div>

              <div className="bg-white p-5 rounded-xl border border-slate-200 space-y-3">
                <div className="flex items-center justify-between">
                  <h2 className="font-semibold text-sm text-slate-900 flex items-center gap-2">
                    <Globe className="w-4 h-4 text-slate-500" /> Dominios
                  </h2>
                  <button
                    type="button"
                    onClick={() => setActiveTab('domains')}
                    className="text-xs font-medium text-slate-600 hover:text-slate-900 cursor-pointer"
                  >
                    Gestionar →
                  </button>
                </div>
                {project.domains && project.domains.length > 0 ? (
                  <div className="space-y-2">
                    {project.domains.map((d: string) => (
                      <div key={d} className="flex items-center justify-between p-2.5 bg-slate-50 border border-slate-200 rounded-lg gap-2">
                        <span className="text-xs font-mono text-slate-700 truncate">{d}</span>
                        <div className="flex items-center gap-1 shrink-0">
                          <button
                            type="button"
                            aria-label={`Copiar ${d}`}
                            onClick={() => void copyValue(d)}
                            className="p-1 text-slate-400 hover:text-slate-700 rounded cursor-pointer"
                          >
                            <Copy className="w-3.5 h-3.5" />
                          </button>
                          <a
                            href={`https://${d}`}
                            target="_blank"
                            rel="noreferrer"
                            aria-label={`Abrir ${d}`}
                            className="p-1 text-slate-500 hover:text-slate-900 rounded"
                          >
                            <Globe className="w-3.5 h-3.5" />
                          </a>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-slate-500 p-4 bg-slate-50 border border-slate-200 rounded-lg text-center">
                    Sin dominios vinculados todavía.
                  </div>
                )}
              </div>
            </div>
          </div>
          </div>
        )}

        {activeTab === 'deployments' && (
          <DeploymentsPanel
            projectId={project.id}
            projectName={project.name}
            gitBranch={project.gitBranch || 'main'}
            onNotify={onNotify}
          />
        )}

        {activeTab === 'logs' && (
          <div className="h-[620px]">
            <LiveLogs incomingLog={incomingLog} projectId={project.id} />
          </div>
        )}

        {activeTab === 'domains' && (
          <DomainManager
            onNotify={onNotify}
            projectId={project.id}
            projectDomains={project.domains || []}
            onDomainAddedToProject={() => { void fetchProject(); }}
            onDomainRemovedFromProject={() => { void fetchProject(); }}
          />
        )}

        {activeTab === 'databases' && (
          <DatabasesPanel
            projectId={project.id}
            linkedDatabaseIds={project.linkedDatabaseIds || []}
            onProjectChanged={() => { void fetchProject(); }}
            onOpenDeployments={() => setActiveTab('deployments')}
            onOpenBackupSettings={onOpenBackupSettings}
            onNotify={onNotify}
          />
        )}

        {activeTab === 'vars' && (
          <div className="culkibo-surface rounded-2xl overflow-hidden">
            <div className="p-5 border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-50/70">
              <div>
                <h2 className="font-semibold text-slate-900 text-base flex items-center gap-2">
                  <Variable className="w-4 h-4 text-slate-600" /> {t('pd.envTitle')}
                  {envIsDirty && (
                    <span className="px-2 py-0.5 rounded-full bg-amber-50 border border-amber-200 text-amber-800 text-[11px] font-medium">
                      {t('pd.envDirty')}
                    </span>
                  )}
                </h2>
                <p className="text-xs text-slate-500 mt-0.5">{t('pd.envDesc')}</p>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                {project.lastDeployedAt && !envSavedPendingRestart && (
                  <button
                    type="button"
                    disabled={fastRestarting}
                    onClick={() => void handleFastRestart()}
                    className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-amber-200 bg-amber-50 hover:bg-amber-100 text-amber-900 text-xs font-medium cursor-pointer disabled:opacity-50"
                  >
                    {fastRestarting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5 text-amber-600" />}
                    <span>{fastRestarting ? t('pd.fastRestarting') : t('pd.fastRestartBtn')}</span>
                  </button>
                )}
                <div className="flex items-center bg-slate-200/70 p-0.5 rounded-lg">
                  <button
                    type="button"
                    onClick={() => switchEnvMode('table')}
                    className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                      envMode === 'table' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    Tabla visual
                  </button>
                  <button
                    type="button"
                    onClick={() => switchEnvMode('raw')}
                    className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                      envMode === 'raw' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    Archivo .env
                  </button>
                </div>
              </div>
            </div>

            {/* Runtime-Only Fast Restart Banner (curing dokploy#2547) */}
            {envSavedPendingRestart && (
              <div className="mx-5 mt-4 p-4 rounded-xl bg-amber-50/80 border border-amber-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                <div className="flex items-start gap-2.5 min-w-0">
                  <Zap className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                  <div className="min-w-0">
                    <div className="font-semibold text-amber-950">{t('pd.fastBannerTitle')}</div>
                    <p className="text-amber-800/90 mt-0.5 leading-relaxed">{t('pd.fastBannerDesc')}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0 flex-wrap">
                  <button
                    type="button"
                    disabled={fastRestarting}
                    onClick={() => void handleFastRestart()}
                    className="culkibo-press inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                  >
                    {fastRestarting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5 text-amber-400" />}
                    <span>{fastRestarting ? t('pd.fastRestarting') : t('pd.fastRestartBtn')}</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveTab('deployments')}
                    className="culkibo-press inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 font-medium cursor-pointer"
                  >
                    <Rocket className="w-3.5 h-3.5 text-slate-500" />
                    <span>{t('pd.fullDeployBtn')}</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setEnvSavedPendingRestart(false)}
                    aria-label="Dismiss banner"
                    className="p-1.5 rounded-lg text-amber-700/70 hover:text-amber-900 hover:bg-amber-100 cursor-pointer"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )}

            {lastFastRestart && !envSavedPendingRestart && (
              <div className="mx-5 mt-4 px-4 py-2.5 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-900 text-xs flex items-center justify-between gap-2">
                <span className="inline-flex items-center gap-2 font-medium tabular-nums">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  <span>
                    {t('pd.fastRestartDone', {
                      ms:
                        lastFastRestart.durationMs !== null
                          ? lastFastRestart.durationMs >= 1000
                            ? `${(lastFastRestart.durationMs / 1000).toFixed(1)}s`
                            : `${Math.round(lastFastRestart.durationMs)}ms`
                          : '~1.5s',
                    })}
                  </span>
                </span>
                <button
                  type="button"
                  onClick={() => setLastFastRestart(null)}
                  aria-label="Dismiss"
                  className="p-1 rounded text-emerald-700 hover:bg-emerald-100 cursor-pointer"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}

            <div className="p-5">
              {envMode === 'table' ? (
                <div className="space-y-4">
                  <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5">
                    <div className="relative flex-1">
                      <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                      <input
                        type="text"
                        placeholder="Filtrar por nombre de variable…"
                        value={searchVar}
                        onChange={(e) => setSearchVar(e.target.value)}
                        className="w-full pl-9 pr-3 py-2 border border-slate-200 rounded-lg text-sm"
                      />
                    </div>
                    <button
                      type="button"
                      onClick={() => setEnvRows([{ key: '', value: '', id: `new_${Date.now()}` }, ...envRows])}
                      className="inline-flex items-center justify-center gap-1.5 bg-slate-900 hover:bg-slate-800 text-white px-3.5 py-2 rounded-lg text-xs font-medium cursor-pointer"
                    >
                      <Plus className="w-3.5 h-3.5" /> Añadir variable
                    </button>
                  </div>

                  <div className="border border-slate-200 rounded-xl overflow-hidden">
                    <div className="grid grid-cols-[1fr_1.8fr_auto] gap-3 bg-slate-50 px-3 py-2.5 border-b border-slate-200 text-xs font-medium text-slate-500">
                      <div>Clave</div>
                      <div>Valor</div>
                      <div className="w-20 text-center">Acciones</div>
                    </div>
                    <div className="divide-y divide-slate-100 max-h-[460px] overflow-y-auto">
                      {envRows.filter((r) => !searchVar || r.key.toLowerCase().includes(searchVar.toLowerCase())).length === 0 && (
                        <div className="p-8 text-center text-slate-500 text-xs">No hay variables que coincidan.</div>
                      )}
                      {envRows
                        .filter((r) => !searchVar || r.key.toLowerCase().includes(searchVar.toLowerCase()))
                        .map((row) => (
                          <div key={row.id} className="grid grid-cols-[1fr_1.8fr_auto] gap-3 p-2.5 items-center hover:bg-slate-50/70 group">
                            <input
                              type="text"
                              value={row.key}
                              onChange={(e) => {
                                setEnvRows((prev) => prev.map((r) => (r.id === row.id ? { ...r, key: e.target.value } : r)));
                              }}
                              placeholder="API_KEY"
                              className="w-full px-2.5 py-1.5 border border-transparent hover:border-slate-200 rounded-lg text-xs font-mono bg-transparent focus:bg-white"
                            />
                            <div className="relative flex items-center">
                              <input
                                type={showValues[row.id] ? 'text' : 'password'}
                                value={row.value}
                                onChange={(e) => {
                                  setEnvRows((prev) => prev.map((r) => (r.id === row.id ? { ...r, value: e.target.value } : r)));
                                }}
                                placeholder="valor"
                                className="w-full pl-2.5 pr-9 py-1.5 border border-transparent hover:border-slate-200 rounded-lg text-xs font-mono bg-transparent focus:bg-white"
                              />
                              <button
                                type="button"
                                aria-label={showValues[row.id] ? 'Ocultar valor' : 'Mostrar valor'}
                                onClick={() => setShowValues((prev) => ({ ...prev, [row.id]: !prev[row.id] }))}
                                className="absolute right-2 p-1 text-slate-400 hover:text-slate-700 rounded cursor-pointer"
                              >
                                {showValues[row.id] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                              </button>
                            </div>
                            <div className="flex items-center justify-center gap-1 w-20 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 sm:group-focus-within:opacity-100 transition-opacity">
                              <button
                                type="button"
                                aria-label="Copiar valor"
                                onClick={() => void copyValue(row.value)}
                                className="p-1.5 text-slate-400 hover:text-slate-900 hover:bg-slate-100 rounded cursor-pointer"
                                title="Copiar valor"
                              >
                                <Copy className="w-3.5 h-3.5" />
                              </button>
                              <button
                                type="button"
                                aria-label="Eliminar variable"
                                onClick={() => setEnvRows((prev) => prev.filter((r) => r.id !== row.id))}
                                className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded cursor-pointer"
                                title="Eliminar"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </div>
                        ))}
                    </div>
                  </div>
                  <div className="flex justify-end pt-2">
                    <button
                      type="button"
                      onClick={() => void handleSaveEnvTable()}
                      className="inline-flex items-center gap-1.5 bg-slate-900 hover:bg-slate-800 text-white px-4 py-2 rounded-lg text-xs font-medium cursor-pointer"
                    >
                      <Save className="w-3.5 h-3.5" /> Guardar variables
                    </button>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex flex-wrap justify-between items-center gap-2 text-xs text-slate-500">
                    <p>
                      Pega líneas <code className="bg-slate-100 px-1 rounded text-slate-700 font-mono">CLAVE=valor</code>. Los comentarios con <code className="font-mono">#</code> se ignoran al guardar.
                    </p>
                    <div>
                      <input ref={envFileInputRef} type="file" accept=".env,.txt" onChange={handleImportEnvFile} className="hidden" />
                      <button
                        type="button"
                        onClick={() => envFileInputRef.current?.click()}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 text-xs font-medium cursor-pointer"
                      >
                        <Upload className="w-3.5 h-3.5" /> Importar archivo .env
                      </button>
                    </div>
                  </div>
                  <textarea
                    value={envText}
                    onChange={(e) => setEnvText(e.target.value)}
                    className="w-full h-[360px] p-3.5 bg-slate-50 text-slate-900 border border-slate-200 rounded-xl font-mono text-xs leading-relaxed resize-y"
                    placeholder={'PORT=3000\nDATABASE_URL=postgres://user:pass@host:5432/db'}
                    spellCheck={false}
                  />
                  <div className="flex justify-end">
                    <button
                      type="button"
                      onClick={() => void handleSaveEnvRaw()}
                      className="inline-flex items-center gap-1.5 bg-slate-900 hover:bg-slate-800 text-white px-4 py-2 rounded-lg text-xs font-medium cursor-pointer"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" /> Guardar variables
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'storage' && (
          <div className="space-y-5">
            <div className="bg-white p-5 rounded-xl border border-slate-200 space-y-4">
              <div className="flex justify-between items-center">
                <h2 className="font-semibold text-slate-900 flex items-center gap-2 text-base">
                  <Database className="w-4 h-4 text-slate-600" /> Volúmenes persistentes
                </h2>
                <button
                  type="button"
                  onClick={() => setShowVolumeForm((prev) => !prev)}
                  className="text-xs font-medium text-slate-700 hover:text-slate-900 bg-white border border-slate-200 px-3 py-1.5 rounded-lg flex items-center gap-1 cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" /> {showVolumeForm ? 'Cerrar' : 'Añadir volumen'}
                </button>
              </div>

              {showVolumeForm && (
                <form onSubmit={handleAddVolume} className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 grid grid-cols-1 sm:grid-cols-3 gap-2.5 text-xs">
                  <input required value={volForm.name} onChange={(e) => setVolForm({ ...volForm, name: e.target.value })} placeholder="Nombre (ej. uploads)" className="px-3 py-2 bg-white border border-slate-200 rounded-lg" />
                  <input required value={volForm.mount_path} onChange={(e) => setVolForm({ ...volForm, mount_path: e.target.value })} placeholder="Ruta contenedor (/data)" className="px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono" />
                  <div className="flex gap-2">
                    <input value={volForm.host_path} onChange={(e) => setVolForm({ ...volForm, host_path: e.target.value })} placeholder="Ruta host (opcional)" className="flex-1 px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono" />
                    <button type="submit" className="px-3 py-2 rounded-lg bg-slate-900 text-white font-medium cursor-pointer">Guardar</button>
                  </div>
                </form>
              )}

              <div className="border border-slate-200 rounded-xl overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-50 border-b border-slate-200 text-xs font-medium text-slate-500">
                      <th className="py-2.5 px-4">Nombre</th>
                      <th className="py-2.5 px-4">Ruta contenedor</th>
                      <th className="py-2.5 px-4">Ruta host</th>
                      <th className="py-2.5 px-4 w-12" />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 text-xs">
                    {(!project.volumes || project.volumes.length === 0) ? (
                      <tr><td colSpan={4} className="p-6 text-center text-slate-500">No hay volúmenes configurados.</td></tr>
                    ) : (
                      project.volumes.map((vol, i) => (
                        <tr key={i}>
                          <td className="py-2.5 px-4 font-medium text-slate-700">{vol.name || `Volumen ${i + 1}`}</td>
                          <td className="py-2.5 px-4 font-mono text-slate-500">{vol.mount_path || vol.mountPath || '/data'}</td>
                          <td className="py-2.5 px-4 font-mono text-slate-500">{vol.host_path || vol.hostPath || '—'}</td>
                          <td className="py-2.5 px-4 text-right">
                            <button type="button" aria-label="Eliminar volumen" onClick={() => void handleRemoveVolume(i)} className="p-1 text-slate-400 hover:text-red-600 cursor-pointer">
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="bg-white p-5 rounded-xl border border-slate-200 space-y-4">
              <div className="flex justify-between items-center">
                <h2 className="font-semibold text-slate-900 flex items-center gap-2 text-base">
                  <Box className="w-4 h-4 text-slate-600" /> Archivos montados
                </h2>
                <button
                  type="button"
                  onClick={() => setShowMountForm((prev) => !prev)}
                  className="text-xs font-medium text-slate-700 hover:text-slate-900 bg-white border border-slate-200 px-3 py-1.5 rounded-lg flex items-center gap-1 cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" /> {showMountForm ? 'Cerrar' : 'Montar archivo'}
                </button>
              </div>

              {showMountForm && (
                <form onSubmit={handleAddFileMount} className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-3 text-xs">
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                    <input required value={mountForm.mount_path} onChange={(e) => setMountForm({ ...mountForm, mount_path: e.target.value })} placeholder="Ruta de montaje (/etc/app/config.json)" className="sm:col-span-2 px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono" />
                    <input value={mountForm.chmod} onChange={(e) => setMountForm({ ...mountForm, chmod: e.target.value })} placeholder="Permisos (644)" className="px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono" />
                  </div>
                  <textarea value={mountForm.content} onChange={(e) => setMountForm({ ...mountForm, content: e.target.value })} rows={3} placeholder="Contenido del archivo (opcional)" className="w-full p-2.5 bg-white border border-slate-200 rounded-lg font-mono" />
                  <div className="flex justify-end">
                    <button type="submit" className="px-3.5 py-2 rounded-lg bg-slate-900 text-white font-medium cursor-pointer">Guardar archivo</button>
                  </div>
                </form>
              )}

              <div className="border border-slate-200 rounded-xl overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-50 border-b border-slate-200 text-xs font-medium text-slate-500">
                      <th className="py-2.5 px-4">Ruta de montaje</th>
                      <th className="py-2.5 px-4">Permisos</th>
                      <th className="py-2.5 px-4 w-12" />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 text-xs">
                    {(!project.fileMounts || project.fileMounts.length === 0) ? (
                      <tr><td colSpan={3} className="p-6 text-center text-slate-500">No hay archivos montados.</td></tr>
                    ) : (
                      project.fileMounts.map((fm, i) => (
                        <tr key={i}>
                          <td className="py-2.5 px-4 font-mono text-slate-700">{fm.mountPath || fm.mount_path || '/etc/config.json'}</td>
                          <td className="py-2.5 px-4 font-mono text-slate-500">chmod {fm.chmod || '644'}</td>
                          <td className="py-2.5 px-4 text-right">
                            <button type="button" aria-label="Eliminar archivo montado" onClick={() => void handleRemoveFileMount(i)} className="p-1 text-slate-400 hover:text-red-600 cursor-pointer">
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'config' && (
          <div className="space-y-5">
            <div className="bg-white p-5 rounded-xl border border-slate-200 space-y-4">
              <div className="flex items-center justify-between gap-2">
                <h2 className="font-semibold text-slate-900 flex items-center gap-2 text-base">
                  <Settings className="w-4 h-4 text-slate-600" /> Configuración del proyecto
                </h2>
                {configDirty && (
                  <span className="px-2 py-0.5 rounded-full bg-amber-50 border border-amber-200 text-amber-800 text-[11px] font-medium">
                    Cambios sin guardar
                  </span>
                )}
              </div>
              <form
                key={project.id}
                onChange={() => setConfigDirty(true)}
                onSubmit={async (e) => {
                  e.preventDefault();
                  const formData = new FormData(e.currentTarget);
                  const wp = (formData.get('watchPaths') as string) || '';
                  const memRaw = Number(formData.get('memoryMb'));
                  const cpuRaw = String(formData.get('cpus') || '').trim();
                  const localPathVal = String(formData.get('localPath') || '').trim();
                  const preDeployVal = String(formData.get('preDeployCommand') || '').trim();
                  const postDeployVal = String(formData.get('postDeployCommand') || '').trim();
                  const updates = {
                    name: formData.get('name'),
                    description: formData.get('description'),
                    gitRepo: formData.get('gitRepo'),
                    gitBranch: formData.get('gitBranch'),
                    localPath: localPathVal || null,
                    buildCommand: formData.get('buildCommand'),
                    startCommand: formData.get('startCommand'),
                    preDeployCommand: preDeployVal || null,
                    postDeployCommand: postDeployVal || null,
                    baseDirectory: formData.get('baseDirectory'),
                    watchPaths: wp.split(',').map((s) => s.trim()).filter(Boolean),
                    ...(Number.isFinite(memRaw) && memRaw >= 64 ? { memoryMb: memRaw } : {}),
                    ...(cpuRaw ? { cpus: cpuRaw } : {}),
                    autoRollback: formData.get('autoRollback') === 'on',
                  };
                  try {
                    await api.updateProject(projectId, updates);
                    setConfigDirty(false);
                    onNotify('Configuración guardada correctamente', 'success');
                    await fetchProject();
                    onProjectUpdate?.();
                  } catch (err: any) {
                    onNotify(err?.message || 'Error al guardar configuración', 'error');
                  }
                }}
                className="space-y-4"
              >
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="sm:col-span-2">
                    <label className="block text-xs font-medium text-slate-700 mb-1">Nombre</label>
                    <input name="name" defaultValue={project.name} required className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm" />
                  </div>
                  <div className="sm:col-span-2">
                    <label className="block text-xs font-medium text-slate-700 mb-1">Descripción</label>
                    <textarea name="description" defaultValue={project.description} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm" rows={2} />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">URL del repositorio Git</label>
                    <input name="gitRepo" defaultValue={project.gitRepo} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm font-mono" placeholder="https://github.com/usuario/repo" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">Rama</label>
                    <input name="gitBranch" defaultValue={project.gitBranch} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm font-mono" placeholder="main" />
                  </div>
                  <div className="sm:col-span-2">
                    <label className="block text-xs font-medium text-slate-700 mb-1">Carpeta local vinculada (opcional)</label>
                    <input name="localPath" defaultValue={project.localPath || ''} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm font-mono" placeholder="C:\proyectos\mi-app o /srv/mi-app" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">Directorio base</label>
                    <input name="baseDirectory" defaultValue={project.baseDirectory} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm font-mono" placeholder="/" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">Rutas vigiladas</label>
                    <input name="watchPaths" defaultValue={(project.watchPaths || []).join(', ')} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm font-mono" placeholder="src/**, public/**" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">Comando de compilación</label>
                    <input name="buildCommand" defaultValue={project.buildCommand} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm font-mono" placeholder="npm run build" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">Comando de inicio</label>
                    <input name="startCommand" defaultValue={project.startCommand} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm font-mono" placeholder="npm start" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">Hook pre-despliegue (migraciones)</label>
                    <input name="preDeployCommand" defaultValue={project.preDeployCommand || ''} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm font-mono" placeholder="npx prisma migrate deploy" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">Hook post-despliegue</label>
                    <input name="postDeployCommand" defaultValue={project.postDeployCommand || ''} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm font-mono" placeholder="npm run cache:warm" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">Límite de memoria (MB)</label>
                    <input name="memoryMb" type="number" min={64} max={65536} defaultValue={project.memoryMb || 512} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm font-mono tabular-nums" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">Límite de CPU (vCPU)</label>
                    <input name="cpus" defaultValue={String(project.cpus ?? '1')} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm font-mono tabular-nums" placeholder="1.0" />
                  </div>
                  <div className="sm:col-span-2 pt-1">
                    <label className="inline-flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
                      <input
                        type="checkbox"
                        name="autoRollback"
                        defaultChecked={Boolean(project.autoRollback)}
                        className="rounded border-slate-300 accent-slate-900"
                      />
                      <span>Reversión automática si el contenedor cae por OOM o entra en bucle de reinicios</span>
                    </label>
                  </div>
                </div>
                <div className="flex justify-end pt-3 border-t border-slate-100">
                  <button
                    type="submit"
                    className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-medium inline-flex items-center gap-1.5 cursor-pointer"
                  >
                    <Save className="w-3.5 h-3.5" /> Guardar configuración
                  </button>
                </div>
              </form>
            </div>

            {/* Webhooks Multi-Git y Deploy Hook CI/CD */}
            <div className="bg-white p-5 rounded-xl border border-slate-200 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 bg-slate-100 text-slate-700 rounded-lg border border-slate-200 flex items-center justify-center shrink-0">
                    <Webhook className="w-4 h-4" />
                  </div>
                  <div>
                    <h2 className="font-semibold text-slate-900 text-sm flex items-center gap-1.5">
                      <span>Webhooks Git y Deploy Hook CI/CD</span>
                      <HelpTip title="Webhooks y Deploy Hooks">
                        <p>Permiten desplegar automáticamente en cada <code className="font-mono">git push</code> desde GitHub, GitLab, Gitea o Bitbucket.</p>
                        <p>Con <strong>Deploy Hook</strong> puedes lanzar un despliegue desde GitHub Actions o cualquier script con un simple <code className="font-mono">curl -X POST</code>.</p>
                      </HelpTip>
                    </h2>
                    <p className="text-xs text-slate-500">
                      Firma HMAC verificada, filtrado por rama y rutas de monorepo.
                    </p>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={async () => {
                    const nextState = project.autoDeploy === false;
                    try {
                      await api.updateProject(projectId, { autoDeploy: nextState });
                      onNotify(`Despliegue automático ${nextState ? 'activado' : 'desactivado'}`, 'success');
                      await fetchProject();
                    } catch (err: any) {
                      onNotify(err?.message || 'Error al actualizar estado', 'error');
                    }
                  }}
                  className={`px-3 py-1.5 rounded-full text-xs font-medium inline-flex items-center gap-1.5 border cursor-pointer ${
                    project.autoDeploy !== false
                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      : 'bg-slate-100 text-slate-600 border-slate-200'
                  }`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${project.autoDeploy !== false ? 'bg-emerald-500' : 'bg-slate-400'}`} />
                  {project.autoDeploy !== false ? 'Activo' : 'Desactivado'}
                </button>
              </div>

              <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200 overflow-x-auto no-scrollbar text-xs">
                {([
                  { id: 'github', label: 'GitHub' },
                  { id: 'gitlab', label: 'GitLab' },
                  { id: 'gitea', label: 'Gitea / Forgejo' },
                  { id: 'bitbucket', label: 'Bitbucket' },
                  { id: 'deploy_hook', label: 'Deploy Hook (CI/CD)' },
                ] as const).map((prov) => (
                  <button
                    key={prov.id}
                    type="button"
                    onClick={() => setWebhookProvider(prov.id)}
                    className={`px-2.5 py-1.5 rounded-md font-medium whitespace-nowrap transition-colors cursor-pointer ${
                      webhookProvider === prov.id
                        ? 'bg-white text-slate-900 shadow-2xs'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    {prov.label}
                  </button>
                ))}
              </div>

              {webhookProvider === 'deploy_hook' ? (
                <div className="space-y-3.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-medium text-slate-700">Endpoint firmado para CI/CD</span>
                    <button
                      type="button"
                      disabled={rotatingHook}
                      onClick={async () => {
                        setRotatingHook(true);
                        try {
                          await api.rotateDeployHook(project.id);
                          onNotify('Token de Deploy Hook rotado correctamente', 'success');
                          await fetchProject();
                        } catch (err: any) {
                          onNotify(err?.message || 'No se pudo rotar el token', 'error');
                        } finally {
                          setRotatingHook(false);
                        }
                      }}
                      className="text-xs text-slate-600 hover:text-slate-900 font-medium inline-flex items-center gap-1 underline cursor-pointer disabled:opacity-50"
                    >
                      <KeyRound className="w-3 h-3" /> {rotatingHook ? 'Rotando…' : project.deployHookToken ? 'Rotar token' : 'Generar token'}
                    </button>
                  </div>
                  {project.deployHookToken ? (
                    <>
                      <div className="flex gap-2">
                        <input
                          type="text"
                          readOnly
                          value={`${window.location.origin}/api/webhooks/deploy/${project.id}?token=${project.deployHookToken}`}
                          className="flex-1 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs font-mono text-slate-700 select-all"
                        />
                        <button
                          type="button"
                          onClick={() => void copyValue(`${window.location.origin}/api/webhooks/deploy/${project.id}?token=${project.deployHookToken}`, 'Deploy Hook copiado')}
                          className="px-3 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium rounded-lg text-xs inline-flex items-center gap-1.5 cursor-pointer shrink-0"
                        >
                          <Copy className="w-3.5 h-3.5" /> Copiar
                        </button>
                      </div>
                      <div className="p-3 bg-slate-900 text-slate-100 rounded-lg text-[11px] font-mono overflow-x-auto flex items-center justify-between gap-2">
                        <code className="truncate">
                          {`curl -X POST "${window.location.origin}/api/webhooks/deploy/${project.id}" -H "X-Deploy-Token: ${project.deployHookToken}"`}
                        </code>
                        <button
                          type="button"
                          onClick={() => void copyValue(`curl -X POST "${window.location.origin}/api/webhooks/deploy/${project.id}" -H "X-Deploy-Token: ${project.deployHookToken}"`, 'Comando curl copiado')}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 shrink-0 cursor-pointer"
                        >
                          Copiar curl
                        </button>
                      </div>
                    </>
                  ) : (
                    <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-500">
                      Todavía no hay token de Deploy Hook generado para este proyecto. Pulsa «Generar token» arriba para activarlo.
                    </div>
                  )}
                </div>
              ) : (
              <div className="space-y-3.5">
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">Payload URL ({webhookProvider})</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      readOnly
                      value={`${window.location.origin}/api/webhooks/${webhookProvider}?projectId=${project.id}`}
                      className="flex-1 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs font-mono text-slate-700 select-all"
                    />
                    <button
                      type="button"
                      onClick={() => {
                        void copyValue(`${window.location.origin}/api/webhooks/${webhookProvider}?projectId=${project.id}`, 'URL del webhook copiada');
                        setCopiedUrl(true);
                        window.setTimeout(() => setCopiedUrl(false), 2000);
                      }}
                      className="px-3 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium rounded-lg text-xs inline-flex items-center gap-1.5 cursor-pointer shrink-0"
                    >
                      {copiedUrl ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      {copiedUrl ? 'Copiado' : 'Copiar'}
                    </button>
                  </div>
                  <p className="text-[11px] text-slate-500 mt-1">
                    {webhookProvider === 'github' && 'Configura Content-Type como application/json y pega el secreto HMAC abajo.'}
                    {webhookProvider === 'gitlab' && 'En GitLab → Settings → Webhooks, pega el secreto en el campo «Secret token» (X-Gitlab-Token).'}
                    {webhookProvider === 'gitea' && 'En Gitea/Forgejo → Webhooks, usa formato JSON y pega el secreto (X-Gitea-Signature).'}
                    {webhookProvider === 'bitbucket' && 'En Bitbucket → Webhooks, añade el secreto compartido (X-Hub-Signature).'}
                  </p>
                </div>

                <div>
                  <div className="flex justify-between items-center mb-1">
                    <label className="block text-xs font-medium text-slate-700">Secreto compartido / HMAC</label>
                    <button
                      type="button"
                      onClick={async () => {
                        const newSecret = Array.from(crypto.getRandomValues(new Uint8Array(16)))
                          .map((b) => b.toString(16).padStart(2, '0'))
                          .join('');
                        try {
                          await api.updateProject(projectId, { webhookSecret: newSecret });
                          onNotify('Secreto de webhook regenerado', 'success');
                          await fetchProject();
                        } catch (err: any) {
                          onNotify(err?.message || 'Error al regenerar secreto', 'error');
                        }
                      }}
                      className="text-xs text-slate-600 hover:text-slate-900 font-medium inline-flex items-center gap-1 underline cursor-pointer"
                    >
                      <RefreshCw className="w-3 h-3" /> Regenerar
                    </button>
                  </div>
                  <div className="flex gap-2">
                    <div className="relative flex-1">
                      <input
                        type={showSecret ? 'text' : 'password'}
                        readOnly
                        value={project.webhookSecret || ''}
                        placeholder="Genera un secreto para firmar las entregas"
                        className="w-full px-3 py-2 pr-9 bg-slate-50 border border-slate-200 rounded-lg text-xs font-mono text-slate-700"
                      />
                      <button
                        type="button"
                        aria-label={showSecret ? 'Ocultar secreto' : 'Mostrar secreto'}
                        onClick={() => setShowSecret(!showSecret)}
                        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-700 cursor-pointer"
                      >
                        {showSecret ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                    <button
                      type="button"
                      disabled={!project.webhookSecret}
                      onClick={() => {
                        if (!project.webhookSecret) return;
                        void copyValue(project.webhookSecret, 'Secreto copiado');
                        setCopiedSecret(true);
                        window.setTimeout(() => setCopiedSecret(false), 2000);
                      }}
                      className="px-3 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium rounded-lg text-xs inline-flex items-center gap-1.5 disabled:opacity-40 cursor-pointer shrink-0"
                    >
                      {copiedSecret ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      {copiedSecret ? 'Copiado' : 'Copiar'}
                    </button>
                  </div>
                </div>

                <div className="flex flex-col sm:flex-row sm:items-center justify-between p-3 bg-slate-50 rounded-lg border border-slate-200 gap-2 text-xs">
                  <span className="text-slate-600">
                    Rama vigilada: <strong className="font-mono text-slate-900">{project.gitBranch || 'main'}</strong>
                  </span>
                  <button
                    type="button"
                    onClick={() => void handleSimulatePush()}
                    disabled={simulatingWebhook}
                    className="px-3 py-1.5 bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 font-medium rounded-lg text-xs inline-flex items-center gap-1.5 disabled:opacity-50 cursor-pointer self-start sm:self-auto"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${simulatingWebhook ? 'animate-spin' : ''}`} />
                    {simulatingWebhook ? 'Probando…' : 'Probar webhook'}
                  </button>
                </div>

                {project.lastCommit && (
                  <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-lg text-xs space-y-1">
                    <div className="font-medium text-emerald-900 flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                      Última entrega procesada
                    </div>
                    <div className="text-slate-700">
                      <span className="font-mono bg-white px-1.5 py-0.5 rounded border border-emerald-200 text-emerald-800 mr-1.5">
                        {project.lastCommit.sha}
                      </span>
                      {project.lastCommit.message}
                    </div>
                    <div className="text-[11px] text-slate-500">
                      {project.lastCommit.author} · {new Date(project.lastCommit.timestamp).toLocaleString('es-ES')}
                    </div>
                  </div>
                )}

                {window.location.hostname === 'localhost' && (
                  <p className="text-[11px] text-slate-500 bg-slate-50 border border-slate-200 rounded-lg p-3 leading-relaxed">
                    En entornos locales, para recibir webhooks reales desde Git publica el panel mediante un dominio HTTPS o un túnel de Cloudflare en Ajustes.
                  </p>
                )}
              </div>
              )}
            </div>

            {/* Zona de peligro */}
            <div className="bg-white p-5 rounded-xl border border-red-200 space-y-3">
              <h2 className="font-semibold text-red-700 flex items-center gap-2 text-base">
                <ShieldAlert className="w-4 h-4" /> Zona de peligro
              </h2>
              <p className="text-xs text-slate-600 max-w-2xl leading-relaxed">
                Eliminar este proyecto detendrá todos sus contenedores, retirará sus rutas públicas y eliminará sus variables y volúmenes. Esta acción no se puede deshacer.
              </p>
              <button
                type="button"
                onClick={() => { setConfirmDeleteName(''); setShowDeleteDialog(true); }}
                className="px-4 py-2 bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 rounded-lg text-xs font-medium inline-flex items-center gap-1.5 cursor-pointer"
              >
                <Trash2 className="w-3.5 h-3.5" /> Eliminar proyecto
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Modal de borrado definitivo */}
      <Modal
        open={showDeleteDialog}
        onClose={() => !deleting && setShowDeleteDialog(false)}
        title={`Eliminar «${project.name}»`}
        subtitle="Esta acción es irreversible."
        maxWidthClass="max-w-lg"
        closeDisabled={deleting}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void handleDelete();
          }}
          className="p-5 space-y-4"
        >
          <ul className="text-xs text-slate-700 space-y-1.5 bg-slate-50 border border-slate-200 rounded-xl p-4 leading-relaxed">
            <li>· Se detienen y eliminan los contenedores de desarrollo y producción.</li>
            <li>· Se eliminan las <strong>{Object.keys(project.envVars || {}).length}</strong> variables de entorno.</li>
            <li>· Se borran los volúmenes persistentes configurados.</li>
            <li>
              · Se desvinculan <strong>{domainCount}</strong> {domainCount === 1 ? 'dominio' : 'dominios'} y se retiran sus rutas públicas
              {domainCount > 0 && <span className="text-slate-500"> ({(project.domains || []).join(', ')})</span>}.
            </li>
            <li>· Se descarta el historial de despliegues.</li>
          </ul>

          <label className="block text-xs">
            <span className="text-slate-600">
              Escribe <strong className="font-mono text-slate-900">{project.name}</strong> para confirmar:
            </span>
            <input
              autoFocus
              type="text"
              value={confirmDeleteName}
              onChange={(e) => setConfirmDeleteName(e.target.value)}
              placeholder={project.name}
              className="w-full border border-slate-200 rounded-lg px-3 py-2 mt-1.5 text-slate-900 font-mono text-sm"
            />
          </label>

          <div className="flex justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={() => setShowDeleteDialog(false)}
              disabled={deleting}
              className="text-xs font-medium text-slate-600 border border-slate-200 px-3.5 py-2 rounded-lg hover:bg-slate-50 cursor-pointer"
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={deleting || confirmDeleteName.trim() !== project.name}
              className="inline-flex items-center gap-1.5 text-xs font-medium bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
            >
              <Trash2 className="w-3.5 h-3.5" /> {deleting ? 'Eliminando…' : 'Eliminar proyecto'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
