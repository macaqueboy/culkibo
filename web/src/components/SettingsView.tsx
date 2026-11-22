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
  Loader2
} from 'lucide-react';
import { api, type GitHubStatus, type NotificationsConfig, type DbStorageConfig } from '../lib/api';
import { RemoteAccessPanel } from './RemoteAccessPanel';

type SettingsTab = 'remote' | 'integrations' | 'notifications' | 'system';

export const SettingsView: React.FC<{ onNotify?: (msg: string) => void }> = ({ onNotify }) => {
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

  // Notifications
  const [notif, setNotif] = useState<NotificationsConfig | null>(null);
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
      api.getDbStorage().catch(() => ({ configured: false }))
    ]);
    setSysStatus(sys);
    setGithubStatus(gh);
    setCfConfig(cf);
    if (cf?.accountId) setCfAccountId(cf.accountId);
    setNotif(ntf);
    setDockerStatus(doc);
    setCaddyStatus(ing);
    setS3Config(s3);
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
      api.getDbStorage().catch(() => ({ configured: false }))
    ]).then(([sys, gh, cf, ntf, doc, ing, s3]) => {
      if (!active) return;
      setSysStatus(sys);
      setGithubStatus(gh);
      setCfConfig(cf);
      if (cf?.accountId) setCfAccountId(cf.accountId);
      setNotif(ntf);
      setDockerStatus(doc);
      setCaddyStatus(ing);
      setS3Config(s3);
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
      if (cfToken.trim()) {
        const verify = await api.verifyCloudflareToken(cfToken.trim());
        if (verify.error || verify.valid === false) {
          throw new Error(verify.error || 'Token de Cloudflare inválido');
        }
      }
      await api.saveCloudflareConfig({
        apiToken: cfToken.trim() || undefined,
        accountId: cfAccountId.trim() || undefined,
        useMock: false
      });
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
      onNotify?.('Almacenamiento S3 / R2 guardado');
      void loadAll();
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al guardar S3 / R2');
    } finally {
      setS3Busy(false);
    }
  };

  const handleTestS3 = async () => {
    setS3Busy(true);
    try {
      const r = await api.testDbStorage();
      onNotify?.(`Conexión correcta con el bucket ${r.bucket}`);
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo conectar con S3 / R2');
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
      onNotify?.('Preferencias de notificaciones guardadas');
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al guardar notificaciones');
    } finally {
      setNotifBusy(false);
    }
  };

  const handleTestNotifications = async () => {
    setNotifTesting(true);
    try {
      const res = await api.testNotifications();
      onNotify?.(res.sent
        ? `Alerta de prueba enviada a ${res.delivered} canal(es)`
        : `No se envió alerta (${res.reason || 'configura al menos un canal'})`);
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al enviar alerta de prueba');
    } finally {
      setNotifTesting(false);
    }
  };

  const handlePruneCache = async () => {
    setPruning(true);
    try {
      const res = await api.pruneBuildCache({ keepStorageGb: 5 });
      onNotify?.(res.ok ? 'Caché de Docker BuildKit podada correctamente' : (res.error || 'Poda completada'));
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al podar caché');
    } finally {
      setPruning(false);
    }
  };

  const handleStartCaddy = async () => {
    setStartingCaddy(true);
    try {
      const res = await api.startIngress();
      onNotify?.(res.message || 'Caddy activado');
      void loadAll();
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo iniciar Caddy');
    } finally {
      setStartingCaddy(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div>
        <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight">Ajustes del servidor</h1>
        <p className="text-sm text-slate-500 mt-1">
          Configura el acceso remoto, integra Cloudflare/GitHub/S3, activa alertas y controla la salud del servidor.
        </p>
      </div>

      {/* 4 Tabs */}
      <div className="flex flex-wrap gap-1.5 p-1 bg-slate-100 border border-slate-200 rounded-xl text-xs">
        {([
          { id: 'remote', label: 'Acceso remoto', icon: Globe },
          { id: 'integrations', label: 'Integraciones (GitHub, Cloudflare, S3)', icon: Plug },
          { id: 'notifications', label: 'Notificaciones', icon: Bell },
          { id: 'system', label: 'Sistema y mantenimiento', icon: Cpu }
        ] as const).map((t) => {
          const Icon = t.icon;
          return (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={`inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg font-semibold transition-colors cursor-pointer ${
                tab === t.id ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{t.label}</span>
            </button>
          );
        })}
      </div>

      {/* TAB 1: ACCESO REMOTO */}
      {tab === 'remote' && <RemoteAccessPanel onNotify={onNotify} />}

      {/* TAB 2: INTEGRACIONES */}
      {tab === 'integrations' && (
        <div className="space-y-6">
          {/* Cloudflare */}
          <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 space-y-4">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-orange-50 border border-orange-100 text-orange-600">
                  <Cloud className="w-5 h-5" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-slate-900">Cloudflare (DNS automático, Wildcards y Túneles)</h2>
                  <p className="text-xs text-slate-500">
                    Conecta tu API Token para crear registros A, activar Wildcard <code className="font-mono">*.tudominio.com</code> y gestionar túneles.
                  </p>
                </div>
              </div>
              <span className={`px-2.5 py-1 rounded-full text-xs font-semibold border ${
                cfConfig?.isConfigured
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-slate-100 text-slate-600 border-slate-200'
              }`}>
                {cfConfig?.isConfigured ? 'Conectado' : 'Sin configurar'}
              </span>
            </div>

            {cfFeedback && (
              <div className={`p-3 rounded-xl text-xs border flex items-center gap-2 ${
                cfFeedback.type === 'ok'
                  ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                  : 'bg-rose-50 border-rose-200 text-rose-700'
              }`}>
                {cfFeedback.type === 'ok' ? <CheckCircle2 className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
                <span>{cfFeedback.text}</span>
              </div>
            )}

            <form onSubmit={handleSaveCloudflare} className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div>
                <label className="block font-semibold text-slate-700 mb-1">API Token (Zone DNS Edit + Tunnel Edit)</label>
                <input
                  type="password"
                  value={cfToken}
                  onChange={(e) => setCfToken(e.target.value)}
                  placeholder={cfConfig?.hasApiToken ? '•••••••• (dejar vacío para conservar)' : 'Pega tu API Token de Cloudflare'}
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl font-mono"
                />
              </div>
              <div>
                <label className="block font-semibold text-slate-700 mb-1">Account ID (opcional, requerido para Túneles)</label>
                <input
                  type="text"
                  value={cfAccountId}
                  onChange={(e) => setCfAccountId(e.target.value)}
                  placeholder="32 caracteres hexadecimales"
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl font-mono"
                />
              </div>
              <div className="sm:col-span-2 flex justify-end">
                <button
                  type="submit"
                  disabled={cfBusy}
                  className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white font-semibold cursor-pointer disabled:opacity-50"
                >
                  {cfBusy ? 'Verificando…' : 'Verificar y guardar Cloudflare'}
                </button>
              </div>
            </form>

            {cfZones.length > 0 && (
              <div className="pt-3 border-t border-slate-100">
                <div className="text-xs font-semibold text-slate-700 mb-2">Zonas detectadas ({cfZones.length}):</div>
                <div className="flex flex-wrap gap-1.5">
                  {cfZones.map((z) => (
                    <span key={z.id} className="px-2.5 py-1 rounded-lg bg-slate-50 border border-slate-200 text-xs font-mono text-slate-700">
                      {z.name}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* GitHub */}
          <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 space-y-4">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-slate-900 text-white">
                  <Key className="w-5 h-5" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-slate-900">GitHub (Repositorios privados y auto-despliegue)</h2>
                  <p className="text-xs text-slate-500">Para repositorios públicos no necesitas token; conéctalo si quieres desplegar repos privados.</p>
                </div>
              </div>
              <span className={`px-2.5 py-1 rounded-full text-xs font-semibold border ${
                githubStatus?.connected ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-slate-100 text-slate-600 border-slate-200'
              }`}>
                {githubStatus?.connected ? 'Conectado' : 'No conectado'}
              </span>
            </div>

            {ghFeedback && (
              <div className={`p-3 rounded-xl text-xs border ${
                ghFeedback.type === 'ok' ? 'bg-emerald-50 border-emerald-200 text-emerald-800' : 'bg-rose-50 border-rose-200 text-rose-700'
              }`}>
                {ghFeedback.text}
              </div>
            )}

            {githubStatus?.connected && githubStatus.user ? (
              <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 flex items-center justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-3">
                  <img src={githubStatus.user.avatar_url} alt={githubStatus.user.login} className="w-10 h-10 rounded-full border border-slate-200" />
                  <div>
                    <div className="text-sm font-bold text-slate-900">{githubStatus.user.name || githubStatus.user.login}</div>
                    <a href={githubStatus.user.html_url} target="_blank" rel="noreferrer" className="text-xs text-blue-600 hover:underline inline-flex items-center gap-1">
                      @{githubStatus.user.login} <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                </div>
                {confirmDisconnectGh ? (
                  <div className="flex items-center gap-2">
                    <button type="button" onClick={handleDisconnectGitHub} className="px-3 py-1.5 rounded-lg bg-rose-600 text-white text-xs font-semibold cursor-pointer">
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
                    className="px-3 py-1.5 rounded-lg bg-white hover:bg-rose-50 text-rose-600 border border-rose-200 text-xs font-semibold inline-flex items-center gap-1.5 cursor-pointer"
                  >
                    <Unlink className="w-3.5 h-3.5" /> Desconectar
                  </button>
                )}
              </div>
            ) : (
              <form onSubmit={handleConnectGitHub} className="flex flex-col sm:flex-row gap-2.5">
                <input
                  type="password"
                  value={ghToken}
                  onChange={(e) => setGhToken(e.target.value)}
                  placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                  className="flex-1 px-3.5 py-2 bg-slate-50 border border-slate-300 rounded-xl text-xs font-mono"
                />
                <button
                  type="submit"
                  disabled={ghBusy || !ghToken.trim()}
                  className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold cursor-pointer disabled:opacity-50"
                >
                  {ghBusy ? 'Verificando…' : 'Conectar GitHub'}
                </button>
              </form>
            )}
          </div>

          {/* S3 / R2 */}
          <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold text-slate-900">Almacenamiento de copias S3 / Cloudflare R2</h2>
                <p className="text-xs text-slate-500">Guarda copias cifradas de tus bases de datos fuera del servidor.</p>
              </div>
              {s3Config.configured && (
                <button
                  type="button"
                  onClick={handleTestS3}
                  disabled={s3Busy}
                  className="px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-xs font-semibold text-slate-700 cursor-pointer"
                >
                  Probar conexión
                </button>
              )}
            </div>

            <form onSubmit={handleSaveS3} className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <input value={s3Form.endpoint} onChange={(e) => setS3Form({ ...s3Form, endpoint: e.target.value })} placeholder={s3Config.endpoint || 'Endpoint (https://<id>.r2.cloudflarestorage.com)'} required className="px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl font-mono" />
              <input value={s3Form.bucket} onChange={(e) => setS3Form({ ...s3Form, bucket: e.target.value })} placeholder={s3Config.bucket || 'Bucket (culkibo-backups)'} required className="px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl font-mono" />
              <input value={s3Form.accessKeyId} onChange={(e) => setS3Form({ ...s3Form, accessKeyId: e.target.value })} placeholder="Access Key ID" required className="px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl font-mono" />
              <input type="password" value={s3Form.secretAccessKey} onChange={(e) => setS3Form({ ...s3Form, secretAccessKey: e.target.value })} placeholder="Secret Access Key" required className="px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl font-mono" />
              <div className="sm:col-span-2 flex justify-end">
                <button type="submit" disabled={s3Busy} className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white font-semibold cursor-pointer disabled:opacity-50">
                  Guardar S3 / R2
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* TAB 3: NOTIFICACIONES */}
      {tab === 'notifications' && notif && (
        <form onSubmit={handleSaveNotifications} className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 space-y-5 text-xs">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div>
              <h2 className="text-base font-bold text-slate-900">Alertas automáticas (Telegram, Discord, Slack y Webhook)</h2>
              <p className="text-slate-500 mt-0.5">Entérate al instante si falla un despliegue o se detiene un servicio.</p>
            </div>
            <label className="inline-flex items-center gap-2 font-semibold text-slate-800 cursor-pointer">
              <input
                type="checkbox"
                checked={notif.enabled}
                onChange={(e) => setNotif({ ...notif, enabled: e.target.checked })}
                className="rounded border-slate-300"
              />
              Activar alertas
            </label>
          </div>

          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
            <div className="font-semibold text-slate-800">Avisarme cuando ocurra:</div>
            <div className="flex flex-wrap gap-4">
              {([
                ['service_down', 'Un servicio se cae'],
                ['deploy_failed', 'Falla un despliegue'],
                ['deploy_succeeded', 'Despliegue completado'],
                ['ssl_issued', 'Certificado SSL emitido'],
                ['project_stopped', 'Proyecto detenido']
              ] as const).map(([key, label]) => (
                <label key={key} className="inline-flex items-center gap-1.5 cursor-pointer text-slate-700">
                  <input
                    type="checkbox"
                    checked={Boolean(notif.events[key])}
                    onChange={(e) => setNotif({ ...notif, events: { ...notif.events, [key]: e.target.checked } })}
                    className="rounded border-slate-300"
                  />
                  <span>{label}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl border border-slate-200 space-y-2.5">
              <label className="flex items-center justify-between font-bold text-slate-900">
                <span>Telegram</span>
                <input
                  type="checkbox"
                  checked={notif.channels.telegram.enabled}
                  onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, telegram: { ...notif.channels.telegram, enabled: e.target.checked } } })}
                />
              </label>
              <input
                type="password"
                value={notif.channels.telegram.botToken}
                onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, telegram: { ...notif.channels.telegram, botToken: e.target.value } } })}
                placeholder="Bot Token (123456:ABC...)"
                className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg font-mono"
              />
              <input
                type="text"
                value={notif.channels.telegram.chatId}
                onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, telegram: { ...notif.channels.telegram, chatId: e.target.value } } })}
                placeholder="Chat ID (ej. -100123456789)"
                className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg font-mono"
              />
            </div>

            <div className="p-4 rounded-xl border border-slate-200 space-y-2.5">
              <label className="flex items-center justify-between font-bold text-slate-900">
                <span>Discord</span>
                <input
                  type="checkbox"
                  checked={notif.channels.discord.enabled}
                  onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, discord: { ...notif.channels.discord, enabled: e.target.checked } } })}
                />
              </label>
              <input
                type="text"
                value={notif.channels.discord.webhookUrl}
                onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, discord: { ...notif.channels.discord, webhookUrl: e.target.value } } })}
                placeholder="https://discord.com/api/webhooks/..."
                className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg font-mono"
              />
            </div>

            <div className="p-4 rounded-xl border border-slate-200 space-y-2.5">
              <label className="flex items-center justify-between font-bold text-slate-900">
                <span>Slack</span>
                <input
                  type="checkbox"
                  checked={notif.channels.slack.enabled}
                  onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, slack: { ...notif.channels.slack, enabled: e.target.checked } } })}
                />
              </label>
              <input
                type="text"
                value={notif.channels.slack.webhookUrl}
                onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, slack: { ...notif.channels.slack, webhookUrl: e.target.value } } })}
                placeholder="https://hooks.slack.com/services/..."
                className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg font-mono"
              />
            </div>

            <div className="p-4 rounded-xl border border-slate-200 space-y-2.5">
              <label className="flex items-center justify-between font-bold text-slate-900">
                <span>Webhook HTTPS genérico</span>
                <input
                  type="checkbox"
                  checked={notif.channels.webhook.enabled}
                  onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, webhook: { ...notif.channels.webhook, enabled: e.target.checked } } })}
                />
              </label>
              <input
                type="text"
                value={notif.channels.webhook.url}
                onChange={(e) => setNotif({ ...notif, channels: { ...notif.channels, webhook: { ...notif.channels.webhook, url: e.target.value } } })}
                placeholder="https://tu-endpoint.com/webhook"
                className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg font-mono"
              />
            </div>
          </div>

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100">
            <button
              type="button"
              onClick={handleTestNotifications}
              disabled={notifTesting}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-800 font-semibold cursor-pointer disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5" />
              <span>{notifTesting ? 'Enviando…' : 'Enviar alerta de prueba'}</span>
            </button>
            <button
              type="submit"
              disabled={notifBusy}
              className="px-5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white font-semibold cursor-pointer disabled:opacity-50"
            >
              {notifBusy ? 'Guardando…' : 'Guardar alertas'}
            </button>
          </div>
        </form>
      )}

      {/* TAB 4: SISTEMA */}
      {tab === 'system' && (
        <div className="space-y-6">
          <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 space-y-4">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-blue-50 border border-blue-100 text-blue-600">
                  <Server className="w-5 h-5" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-slate-900">Daemon Culkibo v{sysStatus?.version || '1.0.0'}</h2>
                  <p className="text-xs text-slate-500">Métricas reales del proceso y servicios detectados en este host.</p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => void loadAll()}
                className="p-2 rounded-xl bg-slate-100 hover:bg-slate-200 border border-slate-200 text-slate-600 cursor-pointer"
              >
                <RefreshCw className="w-4 h-4" />
              </button>
            </div>

            {sysStatus && (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200">
                  <span className="text-slate-500 block">Node.js</span>
                  <span className="text-slate-900 font-bold font-mono text-sm">{sysStatus.nodeVersion}</span>
                </div>
                <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200">
                  <span className="text-slate-500 block">Tiempo activo</span>
                  <span className="text-slate-900 font-bold font-mono text-sm">{Math.floor(sysStatus.uptimeSeconds / 60)} min</span>
                </div>
                <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200">
                  <span className="text-slate-500 block">Memoria RSS</span>
                  <span className="text-slate-900 font-bold font-mono text-sm">{sysStatus.memoryUsageMb} MB</span>
                </div>
                <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200">
                  <span className="text-slate-500 block">Heap JS</span>
                  <span className="text-slate-900 font-bold font-mono text-sm">{sysStatus.heapUsedMb} MB</span>
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs pt-2">
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between">
                <div>
                  <div className="font-semibold text-slate-900">Motor Docker</div>
                  <div className="text-slate-500 mt-0.5">{dockerStatus?.available ? 'Disponible para contenedores y bases de datos' : (dockerStatus?.reason || 'No detectado')}</div>
                </div>
                <span className={`px-2 py-0.5 rounded-full font-semibold border ${
                  dockerStatus?.available ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-amber-50 text-amber-800 border-amber-200'
                }`}>
                  {dockerStatus?.available ? 'Activo' : 'Inactivo'}
                </span>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between gap-2">
                <div>
                  <div className="font-semibold text-slate-900">Plano de datos Caddy (HTTPS)</div>
                  <div className="text-slate-500 mt-0.5">{caddyStatus?.available ? caddyStatus.adminUrl : 'Detenido en este equipo'}</div>
                </div>
                {caddyStatus?.available ? (
                  <span className="px-2 py-0.5 rounded-full font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">Activo</span>
                ) : (
                  <button
                    type="button"
                    onClick={handleStartCaddy}
                    disabled={startingCaddy}
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-900 text-white font-semibold cursor-pointer disabled:opacity-50"
                  >
                    {startingCaddy ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                    <span>Activar</span>
                  </button>
                )}
              </div>
            </div>
          </div>

          <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-bold text-slate-900">Mantenimiento de disco (Docker BuildKit)</h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Limpia capas antiguas de compilación manteniendo 5 GB de caché reciente para que tus builds sigan siendo ultrarrápidos.
              </p>
            </div>
            <button
              type="button"
              onClick={handlePruneCache}
              disabled={pruning}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-white hover:bg-slate-50 border border-slate-200 text-xs font-semibold text-slate-800 cursor-pointer disabled:opacity-50 shrink-0"
            >
              {pruning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5 text-slate-500" />}
              <span>{pruning ? 'Podando…' : 'Podar caché BuildKit'}</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
