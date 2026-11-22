import React, { useState, useEffect } from 'react';
import {
  Globe,
  Cloud,
  Copy,
  Check,
  Terminal,
  Plus,
  Loader2,
  ShieldCheck,
  LogOut,
  ExternalLink
} from 'lucide-react';
import { api, clearAuthToken, getAuthToken, type RemoteAccessInfo } from '../lib/api';

export const RemoteAccessPanel: React.FC<{ onNotify?: (msg: string) => void }> = ({ onNotify }) => {
  const [info, setInfo] = useState<RemoteAccessInfo | null>(null);
  const [panelDomainInput, setPanelDomainInput] = useState('');
  const [savingDomain, setSavingDomain] = useState(false);
  const [newTunnelName, setNewTunnelName] = useState('');
  const [creatingTunnel, setCreatingTunnel] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const loadInfo = async () => {
    try {
      const data = await api.getRemoteAccess();
      setInfo(data);
      setPanelDomainInput(data.panelDomain || '');
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    let active = true;
    api.getRemoteAccess()
      .then((data) => {
        if (!active) return;
        setInfo(data);
        setPanelDomainInput(data.panelDomain || '');
      })
      .catch((err) => console.error(err));
    return () => { active = false; };
  }, []);

  const copy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
    onNotify?.('Copiado al portapapeles');
  };

  const handleSavePanelDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingDomain(true);
    try {
      const res = await api.setPanelDomain(panelDomainInput.trim());
      onNotify?.(res.panelDomain
        ? `Panel configurado en https://${res.panelDomain} (Caddy HTTPS)`
        : 'Dominio propio del panel eliminado');
      await loadInfo();
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al configurar el dominio del panel');
    } finally {
      setSavingDomain(false);
    }
  };

  const handleCreateTunnel = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTunnelName.trim()) return;
    setCreatingTunnel(true);
    try {
      await api.createCloudflareTunnel(newTunnelName.trim());
      setNewTunnelName('');
      onNotify?.('Túnel de Cloudflare creado');
      await loadInfo();
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo crear el túnel');
    } finally {
      setCreatingTunnel(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Dominio HTTPS del propio panel */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 space-y-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-blue-50 border border-blue-100 text-blue-600">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900">Dominio HTTPS para entrar a Culkibo desde cualquier sitio</h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Ponle un dominio (por ejemplo <code className="font-mono">panel.tuempresa.com</code>) para entrar desde el móvil u otro ordenador con candado HTTPS automático.
              </p>
            </div>
          </div>
          {info?.serverIp && (
            <span className="px-2.5 py-1 rounded-lg bg-slate-100 border border-slate-200 text-xs font-mono text-slate-700 shrink-0">
              IP: {info.serverIp}
            </span>
          )}
        </div>

        <form onSubmit={handleSavePanelDomain} className="flex flex-col sm:flex-row gap-2.5">
          <input
            type="text"
            value={panelDomainInput}
            onChange={(e) => setPanelDomainInput(e.target.value)}
            placeholder="panel.midominio.com"
            className="flex-1 px-3.5 py-2.5 bg-slate-50 border border-slate-300 rounded-xl text-sm font-mono focus:bg-white focus:outline-none"
          />
          <button
            type="submit"
            disabled={savingDomain}
            className="px-5 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold inline-flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            {savingDomain ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
            <span>Guardar dominio HTTPS</span>
          </button>
        </form>

        {info?.panelDomain && (
          <div className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 text-xs text-emerald-900 flex items-center justify-between gap-2 flex-wrap">
            <span>
              Panel remoto configurado en <strong className="font-mono">https://{info.panelDomain}</strong>. Apunta un registro A hacia <strong className="font-mono">{info.serverIp || 'tu IP pública'}</strong>.
            </span>
            <a
              href={`https://${info.panelDomain}`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 font-semibold underline"
            >
              Abrir <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        )}
      </div>

      {/* Cloudflare Tunnels (sin abrir puertos) */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 space-y-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-orange-50 border border-orange-100 text-orange-600">
            <Cloud className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-900">Túneles de Cloudflare (sin abrir puertos en el router)</h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Ideal si alojas Culkibo en casa, en un mini-PC o detrás de un firewall corporativo.
            </p>
          </div>
        </div>

        <form onSubmit={handleCreateTunnel} className="flex flex-col sm:flex-row gap-2.5">
          <input
            type="text"
            value={newTunnelName}
            onChange={(e) => setNewTunnelName(e.target.value)}
            placeholder="Nombre del túnel (ej. servidor-oficina)"
            className="flex-1 px-3.5 py-2 bg-slate-50 border border-slate-300 rounded-xl text-xs"
          />
          <button
            type="submit"
            disabled={creatingTunnel || !newTunnelName.trim()}
            className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold cursor-pointer disabled:opacity-50"
          >
            {creatingTunnel ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
            <span>Crear túnel</span>
          </button>
        </form>

        {info && info.tunnels.length > 0 && (
          <div className="divide-y divide-slate-100 border border-slate-200 rounded-xl overflow-hidden text-xs">
            {info.tunnels.map((t) => (
              <div key={t.id} className="px-4 py-2.5 flex items-center justify-between bg-white">
                <div>
                  <span className="font-semibold text-slate-900">{t.name}</span>
                  <span className="ml-2 font-mono text-[11px] text-slate-400">{t.id}</span>
                </div>
                <span className="px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 font-medium">
                  {t.status || (info.tunnelsMock ? 'demo' : 'activo')}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Comandos CLI rápidos y sesión */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 space-y-4">
        <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
          <Terminal className="w-4 h-4 text-slate-600" />
          Comandos útiles para este servidor
        </h3>

        <div className="space-y-2.5 text-xs">
          {[
            { key: 'upd', label: 'Actualizar Culkibo a la última versión', cmd: info?.cliUpdateCommand || 'culkibo update' },
            { key: 'tok', label: 'Ver clave de acceso remoto en el servidor', cmd: `cat ${info?.auth?.tokenSource || 'data/auth.json'}` }
          ].map((item) => (
            <div key={item.key} className="p-3 bg-slate-50 border border-slate-200 rounded-xl flex items-center justify-between gap-2">
              <div className="min-w-0">
                <div className="text-slate-500 text-[11px]">{item.label}</div>
                <code className="font-mono text-slate-900 font-semibold">{item.cmd}</code>
              </div>
              <button
                type="button"
                onClick={() => copy(item.cmd, item.key)}
                className="p-1.5 rounded-lg bg-white border border-slate-200 text-slate-500 hover:text-slate-900 cursor-pointer shrink-0"
              >
                {copiedKey === item.key ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          ))}
        </div>

        {getAuthToken() && (
          <div className="pt-3 border-t border-slate-100 flex items-center justify-between gap-3">
            <span className="text-xs text-slate-600">Sesión remota autenticada con token en este navegador.</span>
            <button
              type="button"
              onClick={() => { clearAuthToken(); window.location.reload(); }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-rose-700 bg-rose-50 border border-rose-200 hover:bg-rose-100 cursor-pointer"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Cerrar sesión</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
