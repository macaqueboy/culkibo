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
  ExternalLink,
  KeyRound,
  AlertTriangle,
  Play,
  Trash2,
  Link2,
} from 'lucide-react';
import { api, clearAuthToken, getAuthToken, setAuthToken, type RemoteAccessInfo } from '../lib/api';
import { copyToClipboard } from '../lib/clipboard';
import { Modal } from './Modal';
import { HelpTip } from './HelpTip';

export const RemoteAccessPanel: React.FC<{ onNotify?: (msg: string, type?: 'info' | 'success' | 'error') => void }> = ({ onNotify }) => {
  const [info, setInfo] = useState<RemoteAccessInfo | null>(null);
  const [panelDomainInput, setPanelDomainInput] = useState('');
  const [savingDomain, setSavingDomain] = useState(false);
  const [startingCaddy, setStartingCaddy] = useState(false);
  const [newTunnelName, setNewTunnelName] = useState('');
  const [creatingTunnel, setCreatingTunnel] = useState(false);
  const [tunnelBusyId, setTunnelBusyId] = useState<string | null>(null);
  const [routeTunnelId, setRouteTunnelId] = useState<string | null>(null);
  const [routeHost, setRouteHost] = useState('');
  const [routeService, setRouteService] = useState('http://127.0.0.1:3030');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const [confirmRotate, setConfirmRotate] = useState(false);
  const [rotating, setRotating] = useState(false);
  const [rotatedToken, setRotatedToken] = useState<string | null>(null);

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

  const copy = async (text: string, key: string) => {
    const ok = await copyToClipboard(text);
    if (!ok) {
      onNotify?.('No se pudo copiar al portapapeles', 'error');
      return;
    }
    setCopiedKey(key);
    window.setTimeout(() => setCopiedKey(null), 1800);
    onNotify?.('Copiado al portapapeles', 'success');
  };

  const handleSavePanelDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingDomain(true);
    try {
      const res = await api.setPanelDomain(panelDomainInput.trim());
      if (!res.panelDomain) {
        onNotify?.('Dominio propio del panel eliminado', 'info');
      } else if (res.ingress?.applied) {
        onNotify?.(`Panel publicado en https://${res.panelDomain} con Caddy`, 'success');
      } else {
        onNotify?.(
          `Dominio ${res.panelDomain} guardado, pero Caddy no aplicó la ruta (${res.ingress?.message || res.ingress?.reason || 'Caddy detenido'}).`,
          'info'
        );
      }
      await loadInfo();
    } catch (err: any) {
      onNotify?.(err?.message || 'Error al configurar el dominio del panel', 'error');
    } finally {
      setSavingDomain(false);
    }
  };

  const handleCreateTunnel = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTunnelName.trim()) return;
    setCreatingTunnel(true);
    try {
      const res = await api.createCloudflareTunnel(newTunnelName.trim());
      if (res && res.success === false) {
        throw new Error(res.error || res.message || 'No se pudo crear el túnel');
      }
      setNewTunnelName('');
      onNotify?.('Túnel de Cloudflare creado', 'success');
      await loadInfo();
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo crear el túnel', 'error');
    } finally {
      setCreatingTunnel(false);
    }
  };

  const handleRotateToken = async () => {
    setRotating(true);
    try {
      const res = await api.rotateAuthToken();
      if (res.token) {
        if (getAuthToken()) setAuthToken(res.token);
        setRotatedToken(res.token);
        onNotify?.('Token de acceso rotado. Guárdalo en un lugar seguro.', 'success');
      }
      setConfirmRotate(false);
      await loadInfo();
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo rotar el token', 'error');
    } finally {
      setRotating(false);
    }
  };

  const handleStartCaddy = async () => {
    setStartingCaddy(true);
    try {
      const res = await api.startIngress();
      onNotify?.(res.message || 'Caddy activado correctamente', 'success');
      await loadInfo();
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo iniciar Caddy', 'error');
    } finally {
      setStartingCaddy(false);
    }
  };

  const handleStartConnector = async (tunnelId: string) => {
    setTunnelBusyId(tunnelId);
    try {
      const tokRes = await api.getCloudflareTunnelToken(tunnelId);
      if (!tokRes.token) throw new Error('Cloudflare no devolvió un token de conector');
      const started = await api.startCloudflareTunnelConnector({ tunnelToken: tokRes.token });
      onNotify?.(
        started.started
          ? `Conector cloudflared iniciado (${started.containerName || 'Docker'})`
          : (started.error || 'No se pudo arrancar cloudflared'),
        started.started ? 'success' : 'error'
      );
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo arrancar el conector cloudflared', 'error');
    } finally {
      setTunnelBusyId(null);
    }
  };

  const handleRouteTunnel = async (e: React.FormEvent, tunnelId: string) => {
    e.preventDefault();
    if (!routeHost.trim()) return;
    setTunnelBusyId(tunnelId);
    try {
      await api.routeCloudflareTunnel(tunnelId, {
        hostname: routeHost.trim(),
        serviceUrl: routeService.trim() || 'http://127.0.0.1:3030',
      });
      onNotify?.(`Dominio ${routeHost.trim()} enrutado por el túnel`, 'success');
      setRouteHost('');
      setRouteTunnelId(null);
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo conectar el dominio al túnel', 'error');
    } finally {
      setTunnelBusyId(null);
    }
  };

  const handleDeleteTunnel = async (tunnelId: string, name: string) => {
    setTunnelBusyId(tunnelId);
    try {
      await api.deleteCloudflareTunnel(tunnelId);
      onNotify?.(`Túnel «${name}» eliminado`, 'info');
      await loadInfo();
    } catch (err: any) {
      onNotify?.(err?.message || 'No se pudo eliminar el túnel', 'error');
    } finally {
      setTunnelBusyId(null);
    }
  };

  const tokenSource = info?.auth?.tokenSource || 'data/auth.json';
  const isEnvToken = tokenSource === 'env' || tokenSource === 'CULKIBO_TOKEN';
  const tokenCmd = isEnvToken
    ? 'echo "$CULKIBO_TOKEN"'
    : `cat ${tokenSource}`;

  return (
    <div className="space-y-5">
      {/* Dominio HTTPS del panel */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
              <Globe className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-900">Dominio HTTPS del panel</h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Publica este panel en un dominio propio (ej. <code className="font-mono">panel.tuempresa.com</code>) con HTTPS gestionado por Caddy.
              </p>
            </div>
          </div>
          {info?.serverIp && (
            <span className="px-2.5 py-1 rounded-lg bg-slate-100 border border-slate-200 text-xs font-mono text-slate-700 shrink-0 tabular-nums">
              IP: {info.serverIp}
            </span>
          )}
        </div>

        <form onSubmit={handleSavePanelDomain} className="flex flex-col sm:flex-row gap-2">
          <input
            type="text"
            value={panelDomainInput}
            onChange={(e) => setPanelDomainInput(e.target.value)}
            placeholder="panel.midominio.com"
            className="flex-1 px-3 py-2 bg-white border border-slate-200 rounded-lg text-sm font-mono"
          />
          <button
            type="submit"
            disabled={savingDomain}
            className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium inline-flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            {savingDomain ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
            <span>Guardar dominio</span>
          </button>
        </form>

        {info?.panelDomain && (
          <div className={`p-3.5 rounded-xl border text-xs flex items-center justify-between gap-2 flex-wrap ${
            info.caddy?.available
              ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
              : 'bg-amber-50 border-amber-200 text-amber-900'
          }`}>
            <span>
              Panel configurado en <strong className="font-mono">https://{info.panelDomain}</strong>
              {info.caddy?.available
                ? ` · Apunta un registro A hacia ${info.serverIp || 'la IP del servidor'}.`
                : ' · Caddy está detenido: actívalo en Dominios o Sistema para servir HTTPS.'}
            </span>
            <div className="flex items-center gap-2 shrink-0">
              {!info.caddy?.available && (
                <button
                  type="button"
                  onClick={() => void handleStartCaddy()}
                  disabled={startingCaddy}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50"
                >
                  {startingCaddy ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                  <span>Activar Caddy</span>
                </button>
              )}
              <a
                href={`https://${info.panelDomain}`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 font-medium underline"
              >
                Abrir <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>
        )}
      </div>

      {/* Cloudflare Tunnels — flujo guiado en 3 pasos */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
              <Cloud className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-1.5">
                <span>Túneles de Cloudflare (sin abrir puertos)</span>
                <HelpTip title="Túneles Zero-Trust">
                  <p>Permite publicar el panel o tus proyectos desde un ordenador en casa o detrás de NAT sin abrir los puertos 80/443 en el router.</p>
                  <p>Flujo: 1) Crea el túnel, 2) Conecta tu dominio y 3) Inicia el conector <code className="font-mono">cloudflared</code>.</p>
                </HelpTip>
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                1. Crea túnel → 2. Conecta dominio → 3. Arranca el conector Docker <code className="font-mono">cloudflared</code>.
              </p>
            </div>
          </div>
        </div>

        <form onSubmit={handleCreateTunnel} className="flex flex-col sm:flex-row gap-2">
          <input
            type="text"
            value={newTunnelName}
            onChange={(e) => setNewTunnelName(e.target.value)}
            placeholder="Nombre del túnel (ej. servidor-oficina)"
            className="flex-1 px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs"
          />
          <button
            type="submit"
            disabled={creatingTunnel || !newTunnelName.trim()}
            className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50"
          >
            {creatingTunnel ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
            <span>1. Crear túnel</span>
          </button>
        </form>

        {info && info.tunnels.length > 0 && !info.tunnelsMock && (
          <div className="divide-y divide-slate-100 border border-slate-200 rounded-xl overflow-hidden text-xs">
            {info.tunnels.map((t) => {
              const busy = tunnelBusyId === t.id;
              const isRouting = routeTunnelId === t.id;
              return (
                <div key={t.id} className="p-3.5 bg-white space-y-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="min-w-0">
                      <span className="font-medium text-slate-900">{t.name}</span>
                      <span className="ml-2 font-mono text-[11px] text-slate-400">{t.id}</span>
                      <span className="ml-2 px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 font-medium text-[10px]">
                        {t.status || 'activo'}
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5 flex-wrap shrink-0">
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => setRouteTunnelId(isRouting ? null : t.id)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer"
                      >
                        <Link2 className="w-3 h-3" /> 2. Conectar dominio
                      </button>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => void handleStartConnector(t.id)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                      >
                        {busy ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                        <span>3. Iniciar conector</span>
                      </button>
                      <button
                        type="button"
                        disabled={busy}
                        aria-label={`Eliminar túnel ${t.name}`}
                        onClick={() => void handleDeleteTunnel(t.id, t.name)}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 cursor-pointer"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  {isRouting && (
                    <form onSubmit={(e) => void handleRouteTunnel(e, t.id)} className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2 border-t border-slate-100">
                      <input
                        required
                        value={routeHost}
                        onChange={(e) => setRouteHost(e.target.value)}
                        placeholder="panel.midominio.com"
                        className="px-2.5 py-1.5 bg-slate-50 border border-slate-200 rounded-lg font-mono"
                      />
                      <input
                        required
                        value={routeService}
                        onChange={(e) => setRouteService(e.target.value)}
                        placeholder="http://127.0.0.1:3030"
                        className="px-2.5 py-1.5 bg-slate-50 border border-slate-200 rounded-lg font-mono"
                      />
                      <button
                        type="submit"
                        disabled={busy || !routeHost.trim()}
                        className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                      >
                        Guardar ruta DNS + túnel
                      </button>
                    </form>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Seguridad, token y comandos */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-slate-600" />
            Acceso y seguridad del servidor
          </h2>
          <button
            type="button"
            disabled={isEnvToken}
            title={isEnvToken ? 'La clave viene de la variable de entorno CULKIBO_TOKEN: cámbiala en tu .env o gestor de procesos.' : 'Genera una nueva clave de acceso'}
            onClick={() => setConfirmRotate(true)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-xs font-medium text-slate-700 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <KeyRound className="w-3.5 h-3.5" />
            <span>{isEnvToken ? 'Gestionado por CULKIBO_TOKEN' : 'Rotar clave de acceso'}</span>
          </button>
        </div>

        {rotatedToken && (
          <div className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 text-xs space-y-2">
            <div className="font-semibold text-emerald-900">Nueva clave de acceso generada (guárdala ahora):</div>
            <div className="flex items-center gap-2 bg-white border border-emerald-200 rounded-lg px-3 py-2">
              <code className="flex-1 font-mono text-slate-900 break-all">{rotatedToken}</code>
              <button
                type="button"
                aria-label="Copiar nueva clave"
                onClick={() => void copy(rotatedToken, 'rotated')}
                className="p-1 text-slate-500 hover:text-slate-900 cursor-pointer shrink-0"
              >
                {copiedKey === 'rotated' ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
          </div>
        )}

        <div className="space-y-2.5 text-xs">
          {[
            { key: 'upd', label: 'Actualizar Culkibo', cmd: info?.cliUpdateCommand || 'culkibo update' },
            { key: 'tok', label: 'Consultar clave de acceso en el servidor', cmd: tokenCmd },
          ].map((item) => (
            <div key={item.key} className="p-3 bg-slate-50 border border-slate-200 rounded-lg flex items-center justify-between gap-2">
              <div className="min-w-0">
                <div className="text-slate-500 text-[11px]">{item.label}</div>
                <code className="font-mono text-slate-900 font-medium">{item.cmd}</code>
              </div>
              <button
                type="button"
                aria-label={`Copiar comando: ${item.label}`}
                onClick={() => void copy(item.cmd, item.key)}
                className="p-1.5 rounded-lg bg-white border border-slate-200 text-slate-500 hover:text-slate-900 cursor-pointer shrink-0"
              >
                {copiedKey === item.key ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          ))}
        </div>

        {getAuthToken() && (
          <div className="pt-3 border-t border-slate-100 flex items-center justify-between gap-3">
            <span className="text-xs text-slate-600">Sesión remota autenticada en este navegador.</span>
            <button
              type="button"
              onClick={() => { clearAuthToken(); window.location.reload(); }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-red-700 bg-red-50 border border-red-200 hover:bg-red-100 cursor-pointer"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Cerrar sesión</span>
            </button>
          </div>
        )}
      </div>

      {/* Modal confirmar rotación de token */}
      <Modal
        open={confirmRotate}
        onClose={() => !rotating && setConfirmRotate(false)}
        title="Rotar clave de acceso del servidor"
        subtitle="La clave anterior dejará de funcionar inmediatamente en agentes remotos y otros navegadores."
        maxWidthClass="max-w-md"
        closeDisabled={rotating}
      >
        <div className="p-5 space-y-4">
          <div className="p-3.5 rounded-xl bg-amber-50 border border-amber-200 text-xs text-amber-900 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
            <span>
              Tendrás que actualizar la clave en tus clientes MCP remotos y en cualquier sesión de <code className="font-mono">culkibo sync</code>.
            </span>
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setConfirmRotate(false)}
              disabled={rotating}
              className="px-3.5 py-2 text-xs font-medium text-slate-600 border border-slate-200 rounded-lg hover:bg-slate-50 cursor-pointer"
            >
              Cancelar
            </button>
            <button
              type="button"
              onClick={() => void handleRotateToken()}
              disabled={rotating}
              className="px-4 py-2 text-xs font-medium bg-red-600 hover:bg-red-700 text-white rounded-lg cursor-pointer disabled:opacity-50"
            >
              {rotating ? 'Rotando…' : 'Sí, generar nueva clave'}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
