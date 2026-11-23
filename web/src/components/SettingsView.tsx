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
} from 'lucide-react';
import { api, type GitHubStatus, type NotificationsConfig, type DbStorageConfig } from '../lib/api';
import { RemoteAccessPanel } from './RemoteAccessPanel';
import { Modal } from './Modal';

type SettingsTab = 'remote' | 'integrations' | 'notifications' | 'system';

interface SettingsViewProps {
  onNotify?: (msg: string, type?: 'info' | 'success' | 'error') => void;
  onOpenMetrics?: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ onNotify, onOpenMetrics }) => {
  const [tab, setTab] = useState<SettingsTab>('remote');
  const [sysStatus, setSysStatus] = useState<any>(null);
  const [dockerStatus, setDockerStatus] = useState<{ available: boolean; reason: string | null } | null>(null);
  const [caddyStatus, setCaddyStatus] = useState<{ available: boolean; adminUrl?: string; message?: string } | null>(null);
  const [pruning, setPruning] = useState(false);
  const [startingCaddy, setStartingCaddy] = useState(false);

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
    const [sys, gh, cf, ntf, doc, ing, s3] = await Promise.all([
      api.getSystemStatus().catch(() => null),
      api.getGitHubStatus().catch(() => null),
      api.getCloudflareConfig().catch(() => null),
      api.getNotificationsConfig().catch(() => null),
      api.getDbDockerStatus().catch(() => null),
      api.getIngressStatus({ probe: false }).catch(() => null),
      api.getDbStorage().catch((): DbStorageConfig => ({ configured: false })),
    ]);
    setSysStatus(sys);
    setGithubStatus(gh);
    setCfConfig(cf);
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
      await api.setDbStorage(s3Form);
      onNotify?.('Almacenamiento S3 / R2 guardado', 'success');
      void loadAll();
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al guardar S3 / R2', 'error');
    } finally {
      setS3Busy(false);
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
      if (res.sent) {
        onNotify?.(`Alerta de prueba enviada a ${res.delivered} ${res.delivered === 1 ? 'canal' : 'canales'}`, 'success');
      } else {
        const reason = res.reason === 'no_channels'
          ? 'Activa al menos un canal (Telegram, Discord, Slack o Webhook) antes de probar.'
          : res.reason === 'disabled'
            ? 'Activa el interruptor principal de alertas.'
            : (res.reason || 'No se pudo entregar la alerta a ningún canal.');
        onNotify?.(reason, 'info');
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

  const hasCfToken = Boolean(cfConfig?.hasApiToken || cfConfig?.hasToken);

  return (
    <div className="space-y-5 max-w-5xl mx-auto">
      <div>
        <h1 className="text-xl font-semibold text-slate-900 tracking-tight">Ajustes</h1>
        <p className="text-sm text-slate-500 mt-1">
          Acceso remoto, integraciones externas, alertas y mantenimiento del servidor.
        </p>
      </div>

      {/* Pestañas */}
      <div className="flex flex-wrap gap-1 p-1 bg-slate-100 border border-slate-200 rounded-lg text-xs">
        {([
          { id: 'remote', label: 'Acceso remoto', icon: Globe },
          { id: 'integrations', label: 'Integraciones', icon: Plug },
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

          {/* S3 / R2 */}
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div>
                <h2 className="text-sm font-semibold text-slate-900">Almacenamiento de copias S3 / Cloudflare R2</h2>
                <p className="text-xs text-slate-500 mt-0.5">Copias externas cifradas para bases de datos gestionadas.</p>
              </div>
              {s3Config.configured && (
                <div className="flex items-center gap-2">
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
                <span className="font-medium text-slate-700">Clave de acceso (Access Key ID)</span>
                <input
                  value={s3Form.accessKeyId}
                  onChange={(e) => setS3Form({ ...s3Form, accessKeyId: e.target.value })}
                  placeholder="Access Key ID"
                  required
                  className="mt-1 w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </label>
              <label className="block">
                <span className="font-medium text-slate-700">Clave secreta (Secret Access Key)</span>
                <input
                  type="password"
                  value={s3Form.secretAccessKey}
                  onChange={(e) => setS3Form({ ...s3Form, secretAccessKey: e.target.value })}
                  placeholder="Secret Access Key"
                  required
                  className="mt-1 w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                />
              </label>
              <div className="sm:col-span-2 flex justify-end">
                <button type="submit" disabled={s3Busy} className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50">
                  Guardar S3 / R2
                </button>
              </div>
            </form>
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

            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
              <div className="font-medium text-slate-800">Eventos que disparan alerta:</div>
              <div className="flex flex-wrap gap-4">
                {([
                  ['service_down', 'Servicio caído'],
                  ['deploy_failed', 'Despliegue fallido'],
                  ['deploy_succeeded', 'Despliegue completado'],
                  ['ssl_issued', 'Certificado TLS emitido'],
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
              </div>
            </div>

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
            <button
              type="button"
              onClick={() => void handlePruneCache()}
              disabled={pruning}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-800 cursor-pointer disabled:opacity-50 shrink-0"
            >
              {pruning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5 text-slate-500" />}
              <span>{pruning ? 'Podando…' : 'Podar caché BuildKit'}</span>
            </button>
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
