import React, { useState, useEffect } from 'react';
import {
  CheckCircle2,
  Server,
  ExternalLink,
  Unlink,
  Key,
  AlertCircle,
  RefreshCw,
  Globe,
  Plug,
  Bell,
  Cpu,
  Cloud,
  Send,
  Trash2,
  Play,
  Loader2,
  Activity,
  HardDrive,
  Download,
  Upload,
  ShieldCheck,
  ListChecks,
  FileText,
  Eye,
  EyeOff,
} from 'lucide-react';
import {
  api,
  type GitHubStatus,
  type NotificationsConfig,
  type NotificationHistoryItem,
  type DbStorageConfig,
  type RemoteS3Object,
  type InstanceBackupItem,
  type AuditLogEvent,
  type TelemetryStatus,
  type TelemetryPreview,
} from '../lib/api';
import { RemoteAccessPanel } from './RemoteAccessPanel';
import { Modal } from './Modal';
import { HelpTip } from './HelpTip';

type SettingsTab = 'remote' | 'integrations' | 'backups' | 'notifications' | 'system';

function formatSafeDate(raw?: string | null): string {
  if (!raw) return '—';
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString('es-ES');
}

function normalizeSettingsTab(raw?: string | null): SettingsTab {
  if (!raw) return 'remote';
  const k = raw.toLowerCase();
  if (k === 'remote' || k === 'integrations' || k === 'backups' || k === 'notifications' || k === 'system') {
    return k;
  }
  return 'remote';
}

interface SettingsViewProps {
  onNotify?: (msg: string, type?: 'info' | 'success' | 'error') => void;
  onOpenMetrics?: () => void;
  initialTab?: string | null;
  onTabChange?: (tab: string) => void;
  onRestoreChecklist?: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  onNotify,
  onOpenMetrics,
  initialTab,
  onTabChange,
  onRestoreChecklist,
}) => {
  const [tab, setTabState] = useState<SettingsTab>(() => normalizeSettingsTab(initialTab));
  const setTab = (next: SettingsTab) => {
    setTabState(next);
    onTabChange?.(next);
  };
  const [prevInitialTab, setPrevInitialTab] = useState(initialTab);
  if (initialTab !== prevInitialTab) {
    setPrevInitialTab(initialTab);
    if (initialTab) setTabState(normalizeSettingsTab(initialTab));
  }
  const [sysStatus, setSysStatus] = useState<any>(null);
  const [dockerStatus, setDockerStatus] = useState<{ available: boolean; reason: string | null } | null>(null);
  const [caddyStatus, setCaddyStatus] = useState<{ available: boolean; adminUrl?: string; message?: string } | null>(null);
  const [pruning, setPruning] = useState(false);
  const [startingCaddy, setStartingCaddy] = useState(false);
  const [auditEvents, setAuditEvents] = useState<AuditLogEvent[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);

  // Telemetría anónima y diagnósticos
  const [telemetryStatus, setTelemetryStatus] = useState<TelemetryStatus | null>(null);
  const [telemetryBusy, setTelemetryBusy] = useState(false);
  const [telemetryPreview, setTelemetryPreview] = useState<TelemetryPreview | null>(null);
  const [telemetryPreviewLoading, setTelemetryPreviewLoading] = useState(false);
  const [showTelemetryPreview, setShowTelemetryPreview] = useState(false);

  // Backups & DR (S3 Remote Browser + Instance Snapshot Export/Import)
  const [s3Objects, setS3Objects] = useState<RemoteS3Object[]>([]);
  const [s3ObjectsLoading, setS3ObjectsLoading] = useState(false);
  const [instanceBackups, setInstanceBackups] = useState<InstanceBackupItem[]>([]);
  const [exportIncludeSecrets, setExportIncludeSecrets] = useState(false);
  const [exportPassphrase, setExportPassphrase] = useState('');
  const [exportUploadS3, setExportUploadS3] = useState(false);
  const [exportingSnapshot, setExportingSnapshot] = useState(false);
  const [importPassphrase, setImportPassphrase] = useState('');
  const [importMode, setImportMode] = useState<'merge' | 'overwrite'>('merge');
  const [importSnapshotObj, setImportSnapshotObj] = useState<any>(null);
  const [importFileName, setImportFileName] = useState<string>('');
  const [importDryRunResult, setImportDryRunResult] = useState<any>(null);
  const [importingSnapshot, setImportingSnapshot] = useState(false);
  const [notifHistory, setNotifHistory] = useState<NotificationHistoryItem[]>([]);

  // GitHub
  const [githubStatus, setGithubStatus] = useState<GitHubStatus | null>(null);
  const [ghToken, setGhToken] = useState('');
  const [ghBusy, setGhBusy] = useState(false);
  const [confirmDisconnectGh, setConfirmDisconnectGh] = useState(false);
  const [ghFeedback, setGhFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  // Cloudflare
  const [cfConfig, setCfConfig] = useState<any>(null);
  const [cfToken, setCfToken] = useState('');
  const [cfAccountId, setCfAccountId] = useState('');
  const [cfZones, setCfZones] = useState<any[]>([]);
  const [cfBusy, setCfBusy] = useState(false);
  const [cfFeedback, setCfFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  // S3 / R2
  const [s3Config, setS3Config] = useState<DbStorageConfig>({ configured: false });
  const [s3Form, setS3Form] = useState({ endpoint: '', region: 'auto', bucket: '', accessKeyId: '', secretAccessKey: '', prefix: 'culkibo/' });
  const [s3Busy, setS3Busy] = useState(false);
  const [confirmDisconnectS3, setConfirmDisconnectS3] = useState(false);

  // Notifications
  const [notif, setNotif] = useState<NotificationsConfig | null>(null);
  const [notifLoadFailed, setNotifLoadFailed] = useState(false);
  const [notifBusy, setNotifBusy] = useState(false);
  const [notifTesting, setNotifTesting] = useState(false);

  const loadAll = async () => {
    const [sys, gh, cf, ntf, doc, ing, s3, tel] = await Promise.all([
      api.getSystemStatus().catch(() => null),
      api.getGitHubStatus().catch(() => null),
      api.getCloudflareConfig().catch(() => null),
      api.getNotificationsConfig().catch(() => null),
      api.getDbDockerStatus().catch(() => null),
      api.getIngressStatus({ probe: false }).catch(() => null),
      api.getDbStorage().catch((): DbStorageConfig => ({ configured: false })),
      api.getTelemetryStatus().catch(() => null),
    ]);
    setSysStatus(sys);
    setGithubStatus(gh);
    setCfConfig(cf);
    setTelemetryStatus(tel);
    // P0-2: nunca copiar valores enmascarados (`...`/`••`) al input editable
    if (cf?.accountId && !String(cf.accountId).includes('...') && !String(cf.accountId).includes('••')) {
      setCfAccountId(cf.accountId);
    }
    setNotif(ntf);
    setNotifLoadFailed(!ntf);
    setDockerStatus(doc);
    setCaddyStatus(ing);
    setS3Config(s3);
    if (s3?.configured) {
      setS3Form((prev) => ({
        ...prev,
        endpoint: prev.endpoint || s3.endpoint || '',
        bucket: prev.bucket || s3.bucket || '',
        region: prev.region || s3.region || 'auto',
        prefix: prev.prefix || s3.prefix || 'culkibo/',
      }));
    }
    if (cf?.isConfigured) {
      api.getCloudflareZones().then((z) => setCfZones(z.zones || [])).catch(() => {});
    }
  };

  useEffect(() => {
    let active = true;
    Promise.all([
      api.getSystemStatus().catch(() => null),
      api.getGitHubStatus().catch(() => null),
      api.getCloudflareConfig().catch(() => null),
      api.getNotificationsConfig().catch(() => null),
      api.getDbDockerStatus().catch(() => null),
      api.getIngressStatus({ probe: false }).catch(() => null),
      api.getDbStorage().catch((): DbStorageConfig => ({ configured: false })),
    ]).then(([sys, gh, cf, ntf, doc, ing, s3]) => {
      if (!active) return;
      setSysStatus(sys);
      setGithubStatus(gh);
      setCfConfig(cf);
      if (cf?.accountId && !String(cf.accountId).includes('...') && !String(cf.accountId).includes('••')) {
        setCfAccountId(cf.accountId);
      }
      setNotif(ntf);
      setNotifLoadFailed(!ntf);
      setDockerStatus(doc);
      setCaddyStatus(ing);
      setS3Config(s3);
      if (s3?.configured) {
        setS3Form((prev) => ({
          ...prev,
          endpoint: s3.endpoint || '',
          bucket: s3.bucket || '',
          region: s3.region || 'auto',
          prefix: s3.prefix || 'culkibo/',
        }));
      }
      if (cf?.isConfigured) {
        api.getCloudflareZones().then((z) => { if (active) setCfZones(z.zones || []); }).catch(() => {});
      }
    });
    return () => { active = false; };
  }, []);

  const handleConnectGitHub = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ghToken.trim()) return;
    setGhBusy(true);
    setGhFeedback(null);
    try {
      await api.connectGitHub(ghToken.trim());
      setGhToken('');
      setGhFeedback({ type: 'ok', text: 'Cuenta de GitHub vinculada correctamente.' });
      void loadAll();
    } catch (err: any) {
      setGhFeedback({ type: 'err', text: err?.message || 'Error al conectar con GitHub' });
    } finally {
      setGhBusy(false);
    }
  };

  const handleDisconnectGitHub = async () => {
    setGhBusy(true);
    setConfirmDisconnectGh(false);
    try {
      await api.disconnectGitHub();
      setGhFeedback({ type: 'ok', text: 'Cuenta de GitHub desconectada.' });
      void loadAll();
    } catch (err: any) {
      setGhFeedback({ type: 'err', text: err?.message || 'Error al desconectar' });
    } finally {
      setGhBusy(false);
    }
  };

  const handleSaveCloudflare = async (e: React.FormEvent) => {
    e.preventDefault();
    setCfBusy(true);
    setCfFeedback(null);
    try {
      const cleanToken = cfToken.trim();
      const cleanAccount = cfAccountId.trim();
      if (cleanToken) {
        const verify = await api.verifyCloudflareToken(cleanToken);
        if (verify.error || verify.valid === false) {
          throw new Error(verify.message || verify.error || 'Token de Cloudflare inválido');
        }
      }
      const payload: { apiToken?: string; accountId?: string; useMock: boolean } = { useMock: false };
      if (cleanToken) payload.apiToken = cleanToken;
      if (cleanAccount && !cleanAccount.includes('...') && !cleanAccount.includes('••')) {
        payload.accountId = cleanAccount;
      }
      await api.saveCloudflareConfig(payload);
      setCfToken('');
      setCfFeedback({ type: 'ok', text: 'Cloudflare guardado y verificado.' });
      const zonesRes = await api.getCloudflareZones().catch(() => ({ zones: [] }));
      setCfZones(zonesRes.zones || []);
      void loadAll();
    } catch (err: any) {
      setCfFeedback({ type: 'err', text: err?.message || 'Error al guardar Cloudflare' });
    } finally {
      setCfBusy(false);
    }
  };

  const handleSaveS3 = async (e: React.FormEvent) => {
    e.preventDefault();
    setS3Busy(true);
    try {
      const payload: Record<string, unknown> = {
        endpoint: s3Form.endpoint.trim(),
        bucket: s3Form.bucket.trim(),
        region: s3Form.region.trim() || 'auto',
        prefix: s3Form.prefix.trim(),
      };
      if (s3Form.accessKeyId.trim()) payload.accessKeyId = s3Form.accessKeyId.trim();
      if (s3Form.secretAccessKey.trim()) payload.secretAccessKey = s3Form.secretAccessKey.trim();
      await api.setDbStorage(payload);
      setS3Form((prev) => ({ ...prev, accessKeyId: '', secretAccessKey: '' }));
      onNotify?.('Almacenamiento S3 / R2 guardado', 'success');
      void loadAll();
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al guardar S3 / R2', 'error');
    } finally {
      setS3Busy(false);
    }
  };

  const loadInstanceBackups = async () => {
    const res = await api.listInstanceBackups().catch(() => ({ backups: [] }));
    setInstanceBackups(res.backups || []);
  };

  const loadS3Objects = async () => {
    setS3ObjectsLoading(true);
    try {
      const res = await api.listRemoteS3Objects();
      setS3Objects(res.objects || []);
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudieron listar los objetos en S3', 'error');
    } finally {
      setS3ObjectsLoading(false);
    }
  };

  const loadAudit = async () => {
    setAuditLoading(true);
    try {
      const res = await api.getSystemAudit({ limit: 40 });
      setAuditEvents(res.events || []);
    } catch {
      // ignorar
    } finally {
      setAuditLoading(false);
    }
  };

  const loadNotifHistory = async () => {
    const res = await api.getNotificationsHistory(20).catch(() => ({ notifications: [] }));
    setNotifHistory(res.notifications || []);
  };

  useEffect(() => {
    let active = true;
    if (tab === 'backups') {
      api.listInstanceBackups()
        .then((res) => { if (active) setInstanceBackups(res.backups || []); })
        .catch(() => {});
    } else if (tab === 'system') {
      api.getSystemAudit({ limit: 40 })
        .then((res) => { if (active) setAuditEvents(res.events || []); })
        .catch(() => {});
      api.getTelemetryStatus()
        .then((res) => { if (active) setTelemetryStatus(res); })
        .catch(() => {});
    } else if (tab === 'notifications') {
      api.getNotificationsHistory(20)
        .then((res) => { if (active) setNotifHistory(res.notifications || []); })
        .catch(() => {});
    }
    return () => { active = false; };
  }, [tab]);

  const handleExportInstance = async (e: React.FormEvent) => {
    e.preventDefault();
    setExportingSnapshot(true);
    try {
      const res = await api.exportInstanceSnapshot({
        includeSecrets: exportIncludeSecrets,
        passphrase: exportPassphrase.trim() || '',
        uploadToS3: exportUploadS3 && s3Config.configured,
      });
      onNotify?.(
        res.fileName
          ? `Snapshot completo creado: ${res.fileName}`
          : 'Snapshot completo exportado correctamente',
        'success'
      );
      await loadInstanceBackups();
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al exportar snapshot', 'error');
    } finally {
      setExportingSnapshot(false);
    }
  };

  const handleDownloadSnapshot = async (fileName: string) => {
    try {
      const { blob } = await api.downloadInstanceSnapshotBlob(fileName);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo descargar el snapshot', 'error');
    }
  };

  const handleImportInstance = async (dryRun: boolean) => {
    if (!importSnapshotObj) return;
    setImportingSnapshot(true);
    try {
      const res = await api.importInstanceSnapshot({
        snapshot: importSnapshotObj,
        passphrase: importPassphrase.trim() || '',
        dryRun,
        mode: importMode,
      });
      setImportDryRunResult(res);
      if (!dryRun) {
        onNotify?.('Instancia Culkibo restaurada desde snapshot correctamente', 'success');
        void loadAll();
      } else {
        onNotify?.('Simulación (dry-run) completada. Revisa los cambios antes de aplicar.', 'info');
      }
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al procesar el snapshot', 'error');
    } finally {
      setImportingSnapshot(false);
    }
  };

  const handleTestS3 = async () => {
    setS3Busy(true);
    try {
      const r = await api.testDbStorage();
      onNotify?.(`Conexión correcta con el bucket ${r.bucket}`, 'success');
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo conectar con S3 / R2', 'error');
    } finally {
      setS3Busy(false);
    }
  };

  const handleDisconnectS3 = async () => {
    setConfirmDisconnectS3(false);
    setS3Busy(true);
    try {
      await api.setDbStorage(null);
      setS3Form({ endpoint: '', region: 'auto', bucket: '', accessKeyId: '', secretAccessKey: '', prefix: 'culkibo/' });
      onNotify?.('Almacenamiento S3 / R2 desconectado', 'info');
      void loadAll();
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo desconectar S3 / R2', 'error');
    } finally {
      setS3Busy(false);
    }
  };

  const handleSaveNotifications = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!notif) return;
    setNotifBusy(true);
    try {
      const updated = await api.saveNotificationsConfig(notif);
      setNotif(updated);
      onNotify?.('Preferencias de alertas guardadas', 'success');
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al guardar notificaciones', 'error');
    } finally {
      setNotifBusy(false);
    }
  };

  const handleTestNotifications = async () => {
    if (!notif) return;
    setNotifTesting(true);
    try {
      // Guardar primero cambios pendientes para no probar una configuración desactualizada
      const saved = await api.saveNotificationsConfig(notif);
      setNotif(saved);
      const res = await api.testNotifications();
      void loadNotifHistory();
      if (res.sent) {
        onNotify?.(`Alerta de prueba enviada a ${res.delivered} ${res.delivered === 1 ? 'canal' : 'canales'}`, 'success');
      } else {
        const failedDetails = Array.isArray(res.results)
          ? res.results
              .filter((r: any) => r && !r.ok)
              .map((r: any) => `${r.channel}: ${r.error || 'error'}`)
              .join(' · ')
          : '';
        const reason = res.reason === 'no_channels'
          ? 'Activa al menos un canal (Telegram, Discord, Slack o Webhook) antes de probar.'
          : res.reason === 'disabled'
            ? 'Activa el interruptor principal de alertas.'
            : failedDetails
              ? `Fallo al enviar alerta: ${failedDetails}`
              : (res.reason || 'No se pudo entregar la alerta a ningún canal.');
        onNotify?.(reason, failedDetails ? 'error' : 'info');
      }
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al enviar alerta de prueba', 'error');
    } finally {
      setNotifTesting(false);
    }
  };

  const handlePruneCache = async () => {
    setPruning(true);
    try {
      const res = await api.pruneBuildCache({ keepStorageGb: 5 });
      onNotify?.(res.ok ? 'Caché de Docker BuildKit podada correctamente' : (res.error || 'Poda completada'), 'success');
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al podar caché', 'error');
    } finally {
      setPruning(false);
    }
  };

  const handleStartCaddy = async () => {
    setStartingCaddy(true);
    try {
      const res = await api.startIngress();
      onNotify?.(res.message || 'Caddy activado', 'success');
      void loadAll();
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo iniciar Caddy', 'error');
    } finally {
      setStartingCaddy(false);
    }
  };

  const handleToggleTelemetry = async () => {
    if (!telemetryStatus || telemetryStatus.lockedByEnv) return;
    setTelemetryBusy(true);
    try {
      const next = await api.setTelemetryEnabled(!telemetryStatus.persistedEnabled);
      setTelemetryStatus(next);
      onNotify?.(
        next.enabled
          ? 'Telemetría anónima activada'
          : 'Telemetría anónima desactivada (cola local vaciada)',
        'success'
      );
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo actualizar la telemetría', 'error');
    } finally {
      setTelemetryBusy(false);
    }
  };

  const handleResetTelemetryId = async () => {
    setTelemetryBusy(true);
    try {
      const next = await api.resetTelemetryId();
      setTelemetryStatus(next);
      if (showTelemetryPreview) {
        const prev = await api.getTelemetryPreview().catch(() => null);
        if (prev) setTelemetryPreview(prev);
      }
      onNotify?.('Identificador anónimo rotado correctamente', 'success');
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo rotar el identificador', 'error');
    } finally {
      setTelemetryBusy(false);
    }
  };

  const handleToggleTelemetryPreview = async () => {
    if (showTelemetryPreview) {
      setShowTelemetryPreview(false);
      return;
    }
    setShowTelemetryPreview(true);
    setTelemetryPreviewLoading(true);
    try {
      const prev = await api.getTelemetryPreview();
      setTelemetryPreview(prev);
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo obtener la vista previa de telemetría', 'error');
    } finally {
      setTelemetryPreviewLoading(false);
    }
  };

  const hasCfToken = Boolean(cfConfig?.hasApiToken || cfConfig?.hasToken);

  return (
    <div className="space-y-5 max-w-5xl mx-auto">
      <div>
        <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">Ajustes</h1>
        <p className="text-sm text-slate-500 mt-1">
          Acceso remoto, integraciones externas, alertas y mantenimiento del servidor.
        </p>
      </div>

      {/* Pestañas */}
      <div className="flex flex-wrap gap-1 p-1 bg-slate-100 border border-slate-200 rounded-lg text-xs">
        {([
          { id: 'remote', label: 'Acceso remoto', icon: Globe },
          { id: 'integrations', label: 'Integraciones', icon: Plug },
          { id: 'backups', label: 'Backups y DR', icon: HardDrive },
          { id: 'notifications', label: 'Notificaciones', icon: Bell },
          { id: 'system', label: 'Sistema', icon: Cpu },
        ] as const).map((t) => {
          const Icon = t.icon;
          return (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-colors cursor-pointer ${
                tab === t.id ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{t.label}</span>
            </button>
          );
        })}
      </div>

      {tab === 'remote' && <RemoteAccessPanel onNotify={onNotify} />}

      {tab === 'integrations' && (
        <div className="space-y-5">
          {/* Cloudflare */}
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <Cloud className="w-4 h-4" />
                </div>
                <div>
                  <h2 className="text-sm font-semibold text-slate-900">Cloudflare (DNS automático, comodines y túneles)</h2>
                  <p className="text-xs text-slate-500">
                    Conecta tu API Token para crear registros A, emitir <code className="font-mono">*.tudominio.com</code> y gestionar túneles.
                  </p>
                </div>
              </div>
              <span className={`px-2 py-0.5 rounded-full text-[11px] font-medium border ${
                cfConfig?.isConfigured
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-slate-100 text-slate-600 border-slate-200'
              }`}>
                {cfConfig?.isConfigured ? 'Conectado' : 'Sin configurar'}
              </span>
            </div>

            {cfFeedback && (
              <div className={`p-3 rounded-lg text-xs border flex items-center gap-2 ${
                cfFeedback.type === 'ok'
                  ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                  : 'bg-red-50 border-red-200 text-red-700'
              }`}>
                {cfFeedback.type === 'ok' ? <CheckCircle2 className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
                <span>{cfFeedback.text}</span>
              </div>
            )}

            <form onSubmit={handleSaveCloudflare} className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div>
                <label className="block font-medium text-slate-700 mb-1">API Token (Zone DNS Edit + Tunnel Edit)</label>
                <input
                  type="password"
                  value={cfToken}
                  onChange={(e) => setCfToken(e.target.value)}
                  placeholder={hasCfToken ? '•••••••• (dejar vacío para conservar)' : 'Pega tu API Token de Cloudflare'}
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </div>
              <div>
                <label className="block font-medium text-slate-700 mb-1">Account ID (opcional, requerido para túneles)</label>
                <input
                  type="text"
                  value={cfAccountId}
                  onChange={(e) => setCfAccountId(e.target.value)}
                  placeholder={cfConfig?.accountId ? 'Guardado (dejar vacío para conservar)' : '32 caracteres hexadecimales'}
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </div>
              <div className="sm:col-span-2 flex justify-end">
                <button
                  type="submit"
                  disabled={cfBusy}
                  className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {cfBusy ? 'Verificando…' : 'Verificar y guardar'}
                </button>
              </div>
            </form>

            {cfZones.length > 0 && (
              <div className="pt-3 border-t border-slate-100">
                <div className="text-xs font-medium text-slate-700 mb-2 tabular-nums">Zonas detectadas ({cfZones.length}):</div>
                <div className="flex flex-wrap gap-1.5">
                  {cfZones.map((z) => (
                    <span key={z.id} className="px-2 py-0.5 rounded-md bg-slate-50 border border-slate-200 text-xs font-mono text-slate-700">
                      {z.name}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* GitHub */}
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <Key className="w-4 h-4" />
                </div>
                <div>
                  <h2 className="text-sm font-semibold text-slate-900">GitHub (repositorios privados y webhooks)</h2>
                  <p className="text-xs text-slate-500">Para repositorios públicos no necesitas token.</p>
                </div>
              </div>
              <span className={`px-2 py-0.5 rounded-full text-[11px] font-medium border ${
                githubStatus?.connected ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-slate-100 text-slate-600 border-slate-200'
              }`}>
                {githubStatus?.connected ? 'Conectado' : 'No conectado'}
              </span>
            </div>

            {ghFeedback && (
              <div className={`p-3 rounded-lg text-xs border ${
                ghFeedback.type === 'ok' ? 'bg-emerald-50 border-emerald-200 text-emerald-800' : 'bg-red-50 border-red-200 text-red-700'
              }`}>
                {ghFeedback.text}
              </div>
            )}

            {githubStatus?.connected && githubStatus.user ? (
              <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200 flex items-center justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-3">
                  <img src={githubStatus.user.avatar_url} alt={githubStatus.user.login} className="w-9 h-9 rounded-full border border-slate-200" />
                  <div>
                    <div className="text-xs font-semibold text-slate-900">{githubStatus.user.name || githubStatus.user.login}</div>
                    <a href={githubStatus.user.html_url} target="_blank" rel="noreferrer" className="text-xs text-slate-600 hover:underline inline-flex items-center gap-1">
                      @{githubStatus.user.login} <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                </div>
                {confirmDisconnectGh ? (
                  <div className="flex items-center gap-2">
                    <button type="button" onClick={() => void handleDisconnectGitHub()} className="px-3 py-1.5 rounded-lg bg-red-600 text-white text-xs font-medium cursor-pointer">
                      Sí, desconectar
                    </button>
                    <button type="button" onClick={() => setConfirmDisconnectGh(false)} className="px-3 py-1.5 rounded-lg bg-white border border-slate-200 text-xs text-slate-600 cursor-pointer">
                      Cancelar
                    </button>
                  </div>
                ) : (
                  <button
                    type="button"
                    onClick={() => setConfirmDisconnectGh(true)}
                    disabled={ghBusy}
                    className="px-3 py-1.5 rounded-lg bg-white hover:bg-red-50 text-red-700 border border-red-200 text-xs font-medium inline-flex items-center gap-1.5 cursor-pointer"
                  >
                    <Unlink className="w-3.5 h-3.5" /> Desconectar
                  </button>
                )}
              </div>
            ) : (
              <form onSubmit={handleConnectGitHub} className="flex flex-col sm:flex-row gap-2">
                <input
                  type="password"
                  value={ghToken}
                  onChange={(e) => setGhToken(e.target.value)}
                  placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                  className="flex-1 px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs font-mono"
                />
                <button
                  type="submit"
                  disabled={ghBusy || !ghToken.trim()}
                  className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50"
                >
                  {ghBusy ? 'Verificando…' : 'Conectar GitHub'}
                </button>
              </form>
            )}
          </div>

          {/* Enlace limpio a Backups y DR */}
          <div className="bg-white rounded-xl border border-slate-200 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
            <div>
              <div className="font-semibold text-slate-900">Almacenamiento S3 / Cloudflare R2 y Snapshots de instancia</div>
              <p className="text-slate-500 mt-0.5">
                {s3Config.configured ? `Conectado al bucket ${s3Config.bucket}` : 'Configura tu bucket S3/R2 y exporta copias completas cifradas en Backups y DR.'}
              </p>
            </div>
            <button
              type="button"
              onClick={() => setTab('backups')}
              className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer shrink-0"
            >
              Abrir Backups y DR
            </button>
          </div>
        </div>
      )}

      {tab === 'backups' && (
        <div className="space-y-5">
          {/* Almacenamiento S3 / R2 (soporta edición parcial sin reescribir claves) */}
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div>
                <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-1.5">
                  <span>Almacenamiento remoto S3 / Cloudflare R2</span>
                  <HelpTip title="Backups externos S3 / R2">
                    <p>Sube automáticamente cada copia de base de datos o snapshot completo fuera del servidor.</p>
                    <p>Si ya está configurado, puedes cambiar el bucket o prefijo dejando las claves vacías para conservarlas.</p>
                  </HelpTip>
                </h2>
                <p className="text-xs text-slate-500 mt-0.5">Compatible con Cloudflare R2, AWS S3, Backblaze B2 y MinIO.</p>
              </div>
              {s3Config.configured && (
                <div className="flex items-center gap-2 flex-wrap">
                  <button
                    type="button"
                    onClick={() => void handleTestS3()}
                    disabled={s3Busy}
                    className="px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-700 cursor-pointer"
                  >
                    Probar conexión
                  </button>
                  <button
                    type="button"
                    onClick={() => void loadS3Objects()}
                    disabled={s3ObjectsLoading}
                    className="px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-700 cursor-pointer"
                  >
                    {s3ObjectsLoading ? 'Cargando…' : 'Explorar bucket'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirmDisconnectS3(true)}
                    disabled={s3Busy}
                    className="px-3 py-1.5 rounded-lg bg-white hover:bg-red-50 border border-red-200 text-xs font-medium text-red-700 cursor-pointer"
                  >
                    Desconectar
                  </button>
                </div>
              )}
            </div>

            <form onSubmit={handleSaveS3} className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <label className="block">
                <span className="font-medium text-slate-700">Endpoint</span>
                <input
                  value={s3Form.endpoint}
                  onChange={(e) => setS3Form({ ...s3Form, endpoint: e.target.value })}
                  placeholder={s3Config.endpoint || 'https://<id>.r2.cloudflarestorage.com'}
                  required
                  className="mt-1 w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </label>
              <label className="block">
                <span className="font-medium text-slate-700">Bucket</span>
                <input
                  value={s3Form.bucket}
                  onChange={(e) => setS3Form({ ...s3Form, bucket: e.target.value })}
                  placeholder={s3Config.bucket || 'culkibo-backups'}
                  required
                  className="mt-1 w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </label>
              <label className="block">
                <span className="font-medium text-slate-700">Región</span>
                <input
                  value={s3Form.region}
                  onChange={(e) => setS3Form({ ...s3Form, region: e.target.value })}
                  placeholder="auto (R2) o eu-west-1"
                  required
                  className="mt-1 w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </label>
              <label className="block">
                <span className="font-medium text-slate-700">Prefijo</span>
                <input
                  value={s3Form.prefix}
                  onChange={(e) => setS3Form({ ...s3Form, prefix: e.target.value })}
                  placeholder="culkibo/"
                  className="mt-1 w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </label>
              <label className="block">
                <span className="font-medium text-slate-700">Access Key ID</span>
                <input
                  value={s3Form.accessKeyId}
                  onChange={(e) => setS3Form({ ...s3Form, accessKeyId: e.target.value })}
                  placeholder={s3Config.configured ? `${s3Config.accessKeyId || '••••'} (vacío para conservar)` : 'Access Key ID'}
                  required={!s3Config.configured}
                  className="mt-1 w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </label>
              <label className="block">
                <span className="font-medium text-slate-700">Secret Access Key</span>
                <input
                  type="password"
                  value={s3Form.secretAccessKey}
                  onChange={(e) => setS3Form({ ...s3Form, secretAccessKey: e.target.value })}
                  placeholder={s3Config.configured ? '•••••••• (vacío para conservar)' : 'Secret Access Key'}
                  required={!s3Config.configured}
                  className="mt-1 w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </label>
              <div className="sm:col-span-2 flex justify-end">
                <button type="submit" disabled={s3Busy} className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50">
                  Guardar S3 / R2
                </button>
              </div>
            </form>

            {s3Objects.length > 0 && (
              <div className="border border-slate-200 rounded-xl overflow-hidden text-xs">
                <div className="px-4 py-2 bg-slate-50 border-b border-slate-200 font-medium text-slate-700 tabular-nums">
                  Objetos remotos en bucket ({s3Objects.length})
                </div>
                <div className="divide-y divide-slate-100 max-h-48 overflow-y-auto">
                  {s3Objects.map((obj) => (
                    <div key={obj.key} className="px-4 py-2 flex items-center justify-between gap-2">
                      <span className="font-mono text-slate-700 truncate">{obj.key}</span>
                      <span className="text-slate-400 font-mono tabular-nums shrink-0">
                        {(obj.size / 1024).toFixed(1)} KB
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Snapshot completo de instancia (Disaster Recovery) */}
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-5 text-xs">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-slate-600" />
                <span>Snapshot completo de instancia Culkibo (DR)</span>
              </h2>
              <p className="text-slate-500 mt-0.5">
                Exporta o restaura en bloque todos tus proyectos, dominios, tareas cron, políticas TLS, notificaciones y metadatos con cifrado opcional AES-256-GCM.
              </p>
            </div>

            <form onSubmit={handleExportInstance} className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
              <div className="font-semibold text-slate-800">1. Exportar snapshot de este servidor</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="space-y-2">
                  <label className="flex items-center gap-2 text-slate-700 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={exportIncludeSecrets}
                      onChange={(e) => setExportIncludeSecrets(e.target.checked)}
                      className="rounded border-slate-300 accent-slate-900"
                    />
                    <span>Incluir variables de entorno y secretos (requiere contraseña de cifrado)</span>
                  </label>
                  {s3Config.configured && (
                    <label className="flex items-center gap-2 text-slate-700 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={exportUploadS3}
                        onChange={(e) => setExportUploadS3(e.target.checked)}
                        className="rounded border-slate-300 accent-slate-900"
                      />
                      <span>Subir copia también al bucket S3 / R2</span>
                    </label>
                  )}
                </div>
                <div>
                  <label className="block font-medium text-slate-700 mb-1">
                    Contraseña de cifrado AES-256-GCM {exportIncludeSecrets ? '(obligatoria)' : '(opcional)'}
                  </label>
                  <input
                    type="password"
                    value={exportPassphrase}
                    onChange={(e) => setExportPassphrase(e.target.value)}
                    required={exportIncludeSecrets}
                    placeholder="Frase segura para cifrar el archivo"
                    className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                  />
                </div>
              </div>
              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={exportingSnapshot}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {exportingSnapshot ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
                  <span>{exportingSnapshot ? 'Exportando…' : 'Crear snapshot ahora'}</span>
                </button>
              </div>
            </form>

            {instanceBackups.length > 0 && (
              <div className="border border-slate-200 rounded-xl overflow-hidden">
                <div className="px-4 py-2 bg-slate-50 border-b border-slate-200 font-medium text-slate-700">
                  Snapshots disponibles en disco ({instanceBackups.length})
                </div>
                <div className="divide-y divide-slate-100 max-h-44 overflow-y-auto">
                  {instanceBackups.map((bk) => (
                    <div key={bk.fileName} className="px-4 py-2.5 flex items-center justify-between gap-2">
                      <div className="min-w-0">
                        <span className="font-mono text-slate-800 truncate block">{bk.fileName}</span>
                        {bk.createdAt && <span className="text-[11px] text-slate-400">{new Date(bk.createdAt).toLocaleString('es-ES')}</span>}
                      </div>
                      <button
                        type="button"
                        onClick={() => void handleDownloadSnapshot(bk.fileName)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer shrink-0"
                      >
                        <Download className="w-3 h-3" /> Descargar
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Importar Snapshot */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
              <div className="font-semibold text-slate-800">2. Restaurar o migrar desde un archivo snapshot (.json)</div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 items-end">
                <div>
                  <label className="block font-medium text-slate-700 mb-1">Archivo snapshot</label>
                  <label className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 font-medium cursor-pointer">
                    <Upload className="w-3.5 h-3.5" />
                    <span className="truncate">{importFileName || 'Seleccionar archivo .json'}</span>
                    <input
                      type="file"
                      accept=".json"
                      className="hidden"
                      onChange={(e) => {
                        const f = e.target.files?.[0];
                        if (!f) return;
                        setImportFileName(f.name);
                        setImportDryRunResult(null);
                        f.text().then((txt) => {
                          try {
                            setImportSnapshotObj(JSON.parse(txt));
                          } catch {
                            onNotify?.('El archivo seleccionado no es un JSON válido', 'error');
                          }
                        });
                        e.target.value = '';
                      }}
                    />
                  </label>
                </div>
                <div>
                  <label className="block font-medium text-slate-700 mb-1">Modo de restauración</label>
                  <select
                    value={importMode}
                    onChange={(e) => setImportMode(e.target.value as 'merge' | 'overwrite')}
                    className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-slate-800"
                  >
                    <option value="merge">Combinar (añade sin borrar lo actual)</option>
                    <option value="overwrite">Sobrescribir (reemplaza configuración)</option>
                  </select>
                </div>
                <div>
                  <label className="block font-medium text-slate-700 mb-1">Contraseña (si está cifrado)</label>
                  <input
                    type="password"
                    value={importPassphrase}
                    onChange={(e) => setImportPassphrase(e.target.value)}
                    placeholder="Contraseña AES-256"
                    className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                  />
                </div>
              </div>

              {importDryRunResult && (
                <div className="p-3 rounded-lg bg-white border border-slate-200 text-[11px] font-mono text-slate-700 overflow-x-auto">
                  {JSON.stringify(importDryRunResult.summary || importDryRunResult.counts || importDryRunResult, null, 2)}
                </div>
              )}

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  disabled={!importSnapshotObj || importingSnapshot}
                  onClick={() => void handleImportInstance(true)}
                  className="px-3.5 py-2 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  Simular (Dry-Run)
                </button>
                <button
                  type="button"
                  disabled={!importSnapshotObj || importingSnapshot}
                  onClick={() => void handleImportInstance(false)}
                  className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {importingSnapshot ? 'Aplicando…' : 'Aplicar restauración'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {tab === 'notifications' && (
        !notif ? (
          <div className="bg-white rounded-xl border border-slate-200 p-8 text-center text-xs text-slate-500 space-y-3">
            {notifLoadFailed ? (
              <>
                <p>No se pudo cargar la configuración de notificaciones.</p>
                <button
                  type="button"
                  onClick={() => void loadAll()}
                  className="px-3.5 py-2 rounded-lg bg-slate-900 text-white font-medium cursor-pointer"
                >
                  Reintentar
                </button>
              </>
            ) : (
              <span>Cargando configuración de alertas…</span>
            )}
          </div>
        ) : (
          <form onSubmit={handleSaveNotifications} className="bg-white rounded-xl border border-slate-200 p-5 space-y-5 text-xs">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div>
                <h2 className="text-sm font-semibold text-slate-900">Alertas automáticas</h2>
                <p className="text-slate-500 mt-0.5">Recibe avisos en Telegram, Discord, Slack o mediante webhook HTTPS.</p>
              </div>
              <label className="inline-flex items-center gap-2 font-medium text-slate-800 cursor-pointer">
                <input
                  type="checkbox"
                  checked={notif.enabled}
                  onChange={(e) => setNotif({ ...notif, enabled: e.target.checked })}
                  className="rounded border-slate-300 accent-slate-900"
                />
                Activar alertas
              </label>
            </div>

            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
              <div className="font-medium text-slate-800">Eventos que disparan alerta:</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
                {([
                  ['service_down', 'Servicio caído'],
                  ['service_failed', 'Error instalando servicio'],
                  ['deploy_started', 'Despliegue iniciado'],
                  ['deploy_failed', 'Despliegue fallido'],
                  ['deploy_succeeded', 'Despliegue completado'],
                  ['rollback', 'Reversión automática / manual'],
                  ['production_unhealthy', 'Producción sin salud'],
                  ['ssl_issued', 'Certificado TLS emitido'],
                  ['tls_expiring', 'Certificado TLS próximo a caducar'],
                  ['backup_succeeded', 'Copia BD completada'],
                  ['backup_failed', 'Copia BD fallida'],
                  ['disk_warning', 'Alerta de espacio en disco'],
                  ['cron_failed', 'Tarea Cron fallida'],
                  ['project_stopped', 'Proyecto detenido'],
                ] as const).map(([key, label]) => (
                  <label key={key} className="inline-flex items-center gap-1.5 cursor-pointer text-slate-700">
                    <input
                      type="checkbox"
                      checked={Boolean(notif.events[key])}
                      onChange={(e) => setNotif({ ...notif, events: { ...notif.events, [key]: e.target.checked } })}
                      className="rounded border-slate-300 accent-slate-900"
                    />
                    <span>{label}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl border border-slate-200 space-y-2.5">
                <label className="flex items-center justify-between font-semibold text-slate-900">
                  <span>Telegram</span>
                  <input
                    type="checkbox"
                    checked={notif.channels.telegram.enabled}
                    onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, telegram: { ...notif.channels.telegram, enabled: e.target.checked } } })}
                    className="accent-slate-900"
                  />
                </label>
                <input
                  type="password"
                  value={notif.channels.telegram.botToken}
                  onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, telegram: { ...notif.channels.telegram, botToken: e.target.value } } })}
                  placeholder="Bot Token (123456:ABC...)"
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
                <input
                  type="text"
                  value={notif.channels.telegram.chatId}
                  onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, telegram: { ...notif.channels.telegram, chatId: e.target.value } } })}
                  placeholder="Chat ID (ej. -100123456789)"
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </div>

              <div className="p-4 rounded-xl border border-slate-200 space-y-2.5">
                <label className="flex items-center justify-between font-semibold text-slate-900">
                  <span>Discord</span>
                  <input
                    type="checkbox"
                    checked={notif.channels.discord.enabled}
                    onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, discord: { ...notif.channels.discord, enabled: e.target.checked } } })}
                    className="accent-slate-900"
                  />
                </label>
                <input
                  type="text"
                  value={notif.channels.discord.webhookUrl}
                  onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, discord: { ...notif.channels.discord, webhookUrl: e.target.value } } })}
                  placeholder="https://discord.com/api/webhooks/..."
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </div>

              <div className="p-4 rounded-xl border border-slate-200 space-y-2.5">
                <label className="flex items-center justify-between font-semibold text-slate-900">
                  <span>Slack</span>
                  <input
                    type="checkbox"
                    checked={notif.channels.slack.enabled}
                    onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, slack: { ...notif.channels.slack, enabled: e.target.checked } } })}
                    className="accent-slate-900"
                  />
                </label>
                <input
                  type="text"
                  value={notif.channels.slack.webhookUrl}
                  onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, slack: { ...notif.channels.slack, webhookUrl: e.target.value } } })}
                  placeholder="https://hooks.slack.com/services/..."
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </div>

              <div className="p-4 rounded-xl border border-slate-200 space-y-2.5">
                <label className="flex items-center justify-between font-semibold text-slate-900">
                  <span>Webhook HTTPS</span>
                  <input
                    type="checkbox"
                    checked={notif.channels.webhook.enabled}
                    onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, webhook: { ...notif.channels.webhook, enabled: e.target.checked } } })}
                    className="accent-slate-900"
                  />
                </label>
                <input
                  type="text"
                  value={notif.channels.webhook.url}
                  onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, webhook: { ...notif.channels.webhook, url: e.target.value } } })}
                  placeholder="https://tu-endpoint.com/webhook"
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
                <input
                  type="password"
                  value={notif.channels.webhook.secretHeader || ''}
                  onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, webhook: { ...notif.channels.webhook, secretHeader: e.target.value } } })}
                  placeholder={notif.channels.webhook.hasSecretHeader ? '•••••••• (firma HMAC-SHA256 activa)' : 'Secreto HMAC-SHA256 (opcional)'}
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </div>
            </div>

            {notifHistory.length > 0 && (
              <div className="border border-slate-200 rounded-xl overflow-hidden">
                <div className="px-4 py-2 bg-slate-50 border-b border-slate-200 font-medium text-slate-700">
                  Últimas alertas enviadas ({notifHistory.length})
                </div>
                <div className="divide-y divide-slate-100 max-h-44 overflow-y-auto">
                  {notifHistory.slice(0, 10).map((item) => (
                    <div key={item.id} className="px-4 py-2 flex items-center justify-between gap-2 text-[11px]">
                      <div className="min-w-0">
                        <span className="font-medium text-slate-800">{item.title}</span>
                        <span className="text-slate-400 ml-2 font-mono">{item.event}</span>
                      </div>
                      <span className="text-slate-400 shrink-0 tabular-nums">{formatSafeDate(item.timestamp || item.at)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100">
              <button
                type="button"
                onClick={() => void handleTestNotifications()}
                disabled={notifTesting}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-800 font-medium cursor-pointer disabled:opacity-50"
              >
                <Send className="w-3.5 h-3.5" />
                <span>{notifTesting ? 'Enviando…' : 'Guardar y enviar prueba'}</span>
              </button>
              <button
                type="submit"
                disabled={notifBusy}
                className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                {notifBusy ? 'Guardando…' : 'Guardar alertas'}
              </button>
            </div>
          </form>
        )
      )}

      {tab === 'system' && (
        <div className="space-y-5">
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <Server className="w-4 h-4" />
                </div>
                <div>
                  <h2 className="text-sm font-semibold text-slate-900">Servidor Culkibo v{sysStatus?.version || '1.0.0'}</h2>
                  <p className="text-xs text-slate-500">Métricas reales del proceso y dependencias del host.</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {onOpenMetrics && (
                  <button
                    type="button"
                    onClick={onOpenMetrics}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer"
                  >
                    <Activity className="w-3.5 h-3.5" />
                    <span>Abrir diagnóstico y métricas</span>
                  </button>
                )}
                <button
                  type="button"
                  aria-label="Actualizar estado del sistema"
                  onClick={() => void loadAll()}
                  className="p-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-600 cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {sysStatus && (
              <div className="bg-slate-50 border border-slate-200 rounded-xl grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-slate-200 text-xs">
                <div className="p-3.5">
                  <span className="text-slate-500 block">Node.js</span>
                  <span className="text-slate-900 font-semibold font-mono text-sm mt-0.5 block">{sysStatus.nodeVersion}</span>
                </div>
                <div className="p-3.5">
                  <span className="text-slate-500 block">Tiempo activo</span>
                  <span className="text-slate-900 font-semibold font-mono text-sm mt-0.5 block tabular-nums">
                    {Math.floor(sysStatus.uptimeSeconds / 60)} min
                  </span>
                </div>
                <div className="p-3.5">
                  <span className="text-slate-500 block">Memoria RSS</span>
                  <span className="text-slate-900 font-semibold font-mono text-sm mt-0.5 block tabular-nums">
                    {sysStatus.memoryUsageMb} MB
                  </span>
                </div>
                <div className="p-3.5">
                  <span className="text-slate-500 block">Heap JS</span>
                  <span className="text-slate-900 font-semibold font-mono text-sm mt-0.5 block tabular-nums">
                    {sysStatus.heapUsedMb} MB
                  </span>
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between gap-2">
                <div>
                  <div className="font-semibold text-slate-900">Motor Docker</div>
                  <div className="text-slate-500 mt-0.5">
                    {dockerStatus?.available ? 'Disponible para contenedores y bases de datos' : (dockerStatus?.reason || 'No detectado')}
                  </div>
                </div>
                <span className={`px-2 py-0.5 rounded-full font-medium border shrink-0 ${
                  dockerStatus?.available ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-amber-50 text-amber-800 border-amber-200'
                }`}>
                  {dockerStatus?.available ? 'Activo' : 'Inactivo'}
                </span>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between gap-2">
                <div>
                  <div className="font-semibold text-slate-900">Proxy Caddy (HTTPS)</div>
                  <div className="text-slate-500 mt-0.5 font-mono">{caddyStatus?.available ? caddyStatus.adminUrl : 'Detenido'}</div>
                </div>
                {caddyStatus?.available ? (
                  <span className="px-2 py-0.5 rounded-full font-medium bg-emerald-50 text-emerald-700 border border-emerald-200 shrink-0">Activo</span>
                ) : (
                  <button
                    type="button"
                    onClick={() => void handleStartCaddy()}
                    disabled={startingCaddy}
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-900 text-white font-medium cursor-pointer disabled:opacity-50 shrink-0"
                  >
                    {startingCaddy ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                    <span>Activar</span>
                  </button>
                )}
              </div>
            </div>
          </div>

          <div className="bg-white rounded-xl border border-slate-200 p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-900">Mantenimiento de disco (Docker BuildKit)</h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Elimina capas antiguas de compilación conservando 5 GB de caché reciente.
              </p>
            </div>
            <div className="flex items-center gap-2 flex-wrap shrink-0">
              {onRestoreChecklist && (
                <button
                  type="button"
                  onClick={onRestoreChecklist}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-700 cursor-pointer"
                >
                  <ListChecks className="w-3.5 h-3.5 text-slate-500" />
                  <span>Mostrar guía inicial</span>
                </button>
              )}
              <button
                type="button"
                onClick={() => void handlePruneCache()}
                disabled={pruning}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-800 cursor-pointer disabled:opacity-50"
              >
                {pruning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5 text-slate-500" />}
                <span>{pruning ? 'Podando…' : 'Podar caché BuildKit'}</span>
              </button>
            </div>
          </div>

          {/* Telemetría anónima y diagnósticos */}
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
              <div className="flex items-start gap-3">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
                  <ShieldCheck className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <h3 className="text-sm font-semibold text-slate-900">Telemetría y diagnósticos</h3>
                    <span className={`px-2 py-0.5 rounded-full text-[11px] font-medium border ${
                      telemetryStatus?.enabled
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : telemetryStatus?.lockedByEnv
                          ? 'bg-amber-50 text-amber-800 border-amber-200'
                          : 'bg-slate-100 text-slate-600 border-slate-200'
                    }`}>
                      {telemetryStatus?.enabled
                        ? 'Activa'
                        : telemetryStatus?.lockedByEnv
                          ? 'Controlada por entorno'
                          : 'Desactivada'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">
                    Envía informes anónimos de fallos, errores de la interfaz y métricas agregadas para corregir problemas rápidamente. Nunca incluye secretos, dominios ni datos de negocio.
                  </p>
                </div>
              </div>
              <button
                type="button"
                role="switch"
                aria-label="Activar o desactivar telemetría anónima"
                aria-checked={Boolean(telemetryStatus?.enabled)}
                disabled={!telemetryStatus || telemetryStatus.lockedByEnv || telemetryBusy}
                onClick={() => void handleToggleTelemetry()}
                className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${
                  telemetryStatus?.enabled ? 'bg-slate-900' : 'bg-slate-300'
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
                    telemetryStatus?.enabled ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>

            {telemetryStatus?.lockedByEnv && (
              <div className="px-3.5 py-2.5 rounded-lg bg-amber-50 border border-amber-200 text-xs text-amber-900">
                {telemetryStatus.reason}. Modifica las variables de entorno del proceso (<code className="font-mono">CULKIBO_TELEMETRY</code> / <code className="font-mono">DO_NOT_TRACK</code>) para cambiar este estado.
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
                <div className="font-semibold text-slate-800">Qué enviamos</div>
                <ul className="space-y-1 text-slate-600 list-disc list-inside text-[11px]">
                  <li>Versión de Culkibo, Node.js, sistema operativo y rangos de RAM/CPU</li>
                  <li>Errores fatales del servidor, 5xx en rutas canónicas y fallos de despliegue/copias</li>
                  <li>Errores capturados por la interfaz web (sin URLs ni texto de usuario)</li>
                  <li>Contadores agregados de uso de funciones para priorizar mejoras</li>
                </ul>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
                <div className="font-semibold text-slate-800">Qué NUNCA recopilamos</div>
                <ul className="space-y-1 text-slate-600 list-disc list-inside text-[11px]">
                  {(telemetryStatus?.neverCollected || [
                    'Nombres o URLs de repositorios, proyectos o dominios',
                    'Variables de entorno, contraseñas, tokens o certificados',
                    'Direcciones IP, correos electrónicos o rutas con nombre de usuario',
                    'Contenido de bases de datos, backups o logs de negocio',
                  ]).map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2 border-t border-slate-100 text-xs">
              <div className="text-slate-500 min-w-0">
                <span>ID anónimo: </span>
                <code className="font-mono text-[11px] text-slate-700 bg-slate-100 px-1.5 py-0.5 rounded break-all">
                  {telemetryStatus?.instanceId || '—'}
                </code>
              </div>
              <div className="flex items-center gap-2 flex-wrap shrink-0">
                <button
                  type="button"
                  onClick={() => void handleResetTelemetryId()}
                  disabled={telemetryBusy || !telemetryStatus}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 text-slate-500 ${telemetryBusy ? 'animate-spin' : ''}`} />
                  <span>Rotar ID</span>
                </button>
                <button
                  type="button"
                  onClick={() => void handleToggleTelemetryPreview()}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-800 font-medium cursor-pointer"
                >
                  {showTelemetryPreview ? <EyeOff className="w-3.5 h-3.5 text-slate-500" /> : <Eye className="w-3.5 h-3.5 text-slate-500" />}
                  <span>{showTelemetryPreview ? 'Ocultar payload' : 'Ver payload exacto'}</span>
                </button>
              </div>
            </div>

            {showTelemetryPreview && (
              <div className="rounded-xl border border-slate-200 bg-slate-950 text-slate-100 p-3.5 overflow-x-auto">
                {telemetryPreviewLoading ? (
                  <div className="text-xs text-slate-400 flex items-center gap-2">
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Generando sobre JSON saneado…</span>
                  </div>
                ) : (
                  <pre className="text-[11px] leading-relaxed font-mono whitespace-pre-wrap break-words max-h-64 overflow-y-auto">
                    {JSON.stringify(telemetryPreview, null, 2)}
                  </pre>
                )}
              </div>
            )}
          </div>

          {/* Registro de auditoría del servidor */}
          <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
            <div className="px-5 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-800">
                <FileText className="w-3.5 h-3.5 text-slate-500" />
                <span>Registro de auditoría de seguridad</span>
              </div>
              <button
                type="button"
                onClick={() => void loadAudit()}
                disabled={auditLoading}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md border border-slate-200 bg-white hover:bg-slate-100 text-[11px] font-medium text-slate-700 cursor-pointer"
              >
                <RefreshCw className={`w-3 h-3 ${auditLoading ? 'animate-spin' : ''}`} />
                <span>Actualizar</span>
              </button>
            </div>
            {auditEvents.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500">
                No hay eventos de auditoría registrados todavía.
              </div>
            ) : (
              <div className="divide-y divide-slate-100 max-h-64 overflow-y-auto text-xs">
                {auditEvents.map((ev, i) => (
                  <div key={ev.id || `${ev.timestamp || ev.at || 'ev'}-${i}`} className="px-5 py-2.5 flex items-center justify-between gap-3">
                    <div className="min-w-0 flex items-center gap-2 flex-wrap">
                      <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-700">
                        {ev.source}
                      </span>
                      <span className="font-medium text-slate-900">{ev.action}</span>
                      {ev.target && <span className="font-mono text-slate-500 truncate">{ev.target}</span>}
                    </div>
                    <span className="text-[11px] text-slate-400 tabular-nums shrink-0">
                      {formatSafeDate(ev.timestamp || ev.at)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      <Modal
        open={confirmDisconnectS3}
        onClose={() => setConfirmDisconnectS3(false)}
        title="Desconectar almacenamiento S3 / R2"
        subtitle="Las futuras copias se guardarán únicamente en disco local."
        maxWidthClass="max-w-md"
      >
        <div className="p-5 space-y-4">
          <p className="text-xs text-slate-600">
            Los archivos existentes en el bucket <code className="font-mono">{s3Config.bucket}</code> no se eliminarán.
          </p>
          <div className="flex justify-end gap-2">
            <button type="button" onClick={() => setConfirmDisconnectS3(false)} className="px-3.5 py-2 text-xs font-medium text-slate-600 border border-slate-200 rounded-lg hover:bg-slate-50 cursor-pointer">
              Cancelar
            </button>
            <button type="button" onClick={() => void handleDisconnectS3()} className="px-4 py-2 text-xs font-medium bg-red-600 hover:bg-red-700 text-white rounded-lg cursor-pointer">
              Desconectar
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
