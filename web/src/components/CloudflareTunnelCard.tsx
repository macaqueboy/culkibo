import React, { useState, useEffect } from 'react';
import { Cloud, Key, CheckCircle2, AlertCircle, RefreshCw, Plus, Network, Terminal } from 'lucide-react';
import { api } from '../lib/api';

export const CloudflareTunnelCard: React.FC = () => {
  const [tokenInput, setTokenInput] = useState('');
  const [useMock, setUseMock] = useState(true);
  const [tokenStatus, setTokenStatus] = useState<any>(null);
  const [verifying, setVerifying] = useState(false);
  const [zones, setZones] = useState<any[]>([]);
  const [selectedZone, setSelectedZone] = useState<string>('');
  const [records, setRecords] = useState<any[]>([]);
  const [tunnels, setTunnels] = useState<any[]>([]);
  const [newTunnelName, setNewTunnelName] = useState('');
  const [showTunnelModal, setShowTunnelModal] = useState(false);
  const [tunnelError, setTunnelError] = useState<string | null>(null);

  const loadCloudflareData = async () => {
    try {
      const [cfgRes, zonesRes, tunnelsRes] = await Promise.all([
        api.getCloudflareConfig(),
        api.getCloudflareZones(),
        api.getCloudflareTunnels()
      ]);
      setUseMock(cfgRes.useMock ?? true);
      if (zonesRes.zones && zonesRes.zones.length > 0) {
        setZones(zonesRes.zones);
        const zoneId = zonesRes.zones[0].id;
        setSelectedZone(zoneId);
        const recRes = await api.getCloudflareRecords(zoneId);
        setRecords(recRes.records || []);
      }
      setTunnels(tunnelsRes.tunnels || []);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadCloudflareData();
  }, []);

  const handleVerifyToken = async () => {
    setVerifying(true);
    try {
      const res = await api.verifyCloudflareToken(tokenInput || undefined);
      setTokenStatus(res);
      if (res.valid) {
        await api.saveCloudflareConfig({ apiToken: tokenInput, useMock: false });
        loadCloudflareData();
      }
    } catch (e: any) {
      setTokenStatus({ valid: false, message: e.message });
    } finally {
      setVerifying(false);
    }
  };

  const handleSelectZone = async (zoneId: string) => {
    setSelectedZone(zoneId);
    try {
      const recRes = await api.getCloudflareRecords(zoneId);
      setRecords(recRes.records || []);
    } catch (e) {
      console.error(e);
    }
  };

  const handleCreateTunnel = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTunnelName.trim()) return;
    setTunnelError(null);
    try {
      await api.createCloudflareTunnel(newTunnelName.trim());
      setShowTunnelModal(false);
      setNewTunnelName('');
      loadCloudflareData();
    } catch (e: any) {
      setTunnelError(e.message || 'Error al crear túnel');
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Top Banner / Cloudflare Credentials */}
      <div className="bg-white rounded-2xl border border-slate-200/90 shadow-sm p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-orange-50 border border-orange-100 text-orange-600">
              <Cloud className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-xl font-bold text-slate-900 tracking-tight">
                Integración con Cloudflare & DNS
              </h3>
              <p className="text-sm text-slate-500">
                Permite emitir certificados Wildcard SSL (*.tudominio.com) y crear túneles seguros
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500 font-medium">Estado:</span>
            <span className="px-3 py-1 rounded-full text-xs font-semibold bg-orange-50 text-orange-700 border border-orange-200">
              {useMock ? 'MODO DEMO / SIMULADO' : 'CONECTADO A CLOUDFLARE EN VIVO'}
            </span>
          </div>
        </div>

        {/* API Token Input & Verification */}
        <div className="flex flex-col sm:flex-row gap-3 pt-2">
          <div className="relative flex-1">
            <Key className="w-4 h-4 text-slate-400 absolute left-3.5 top-3.5" />
            <input
              type="password"
              placeholder="Pega tu Token de API de Cloudflare (o escribe 'demo' para probar)"
              value={tokenInput}
              onChange={(e) => setTokenInput(e.target.value)}
              className="w-full pl-10 pr-3.5 py-2.5 bg-slate-50 border border-slate-300 rounded-xl text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500/20 focus:border-orange-500 font-mono"
            />
          </div>
          <button
            onClick={handleVerifyToken}
            disabled={verifying}
            className="px-5 py-2.5 rounded-xl bg-orange-500 hover:bg-orange-600 active:bg-orange-700 text-white font-semibold text-xs shadow-sm flex items-center justify-center gap-2 cursor-pointer transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${verifying ? 'animate-spin' : ''}`} />
            <span>{verifying ? 'Verificando...' : 'Verificar y Guardar Token'}</span>
          </button>
        </div>

        {tokenStatus && (
          <div
            className={`p-3.5 rounded-xl border text-xs flex items-center gap-2.5 ${
              tokenStatus.valid
                ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                : 'bg-rose-50 border-rose-200 text-rose-800'
            }`}
          >
            {tokenStatus.valid ? (
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600" />
            ) : (
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-600" />
            )}
            <span>{tokenStatus.message}</span>
          </div>
        )}
      </div>

      {/* Cloudflare Zero Trust Tunnels */}
      <div className="bg-white rounded-2xl border border-slate-200/90 shadow-sm p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Network className="w-5 h-5 text-orange-600" />
            <h3 className="text-base font-bold text-slate-900">
              Túneles Cloudflare (cloudflared)
            </h3>
          </div>
          <button
            onClick={() => setShowTunnelModal(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-orange-50 hover:bg-orange-100 text-orange-700 border border-orange-200 text-xs font-semibold cursor-pointer transition-colors"
          >
            <Plus className="w-4 h-4" />
            <span>Crear Nuevo Túnel</span>
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {tunnels.map((tun) => (
            <div
              key={tun.id}
              className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3"
            >
              <div className="flex items-start justify-between">
                <div>
                  <span className="font-bold text-sm text-slate-900 block">
                    {tun.name}
                  </span>
                  <span className="text-[11px] text-slate-500 font-mono">
                    ID: {tun.id}
                  </span>
                </div>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                  {tun.status.toUpperCase()}
                </span>
              </div>

              {/* Conexiones de Borde */}
              <div className="text-xs text-slate-600 space-y-1">
                <div className="text-slate-500">Puntos de presencia Cloudflare:</div>
                <div className="flex gap-2">
                  {tun.connections?.map((c: any) => (
                    <span
                      key={c.uuid}
                      className="px-2 py-0.5 rounded-lg bg-white text-slate-700 border border-slate-200 text-[11px] font-medium"
                    >
                      {c.colo_name} (Enrutador)
                    </span>
                  ))}
                </div>
              </div>

              {/* Rutas de Enrutamiento */}
              <div className="text-xs text-slate-600 pt-2 border-t border-slate-200">
                <div className="text-slate-500 mb-1 font-medium">Reglas de Enrutamiento:</div>
                {tun.routes?.map((r: any, idx: number) => (
                  <div key={idx} className="flex justify-between text-xs font-mono text-blue-700">
                    <span>{r.hostname}</span>
                    <span className="text-slate-500">&rarr; {r.service}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Cloudflare Zone & DNS Records Inspector */}
      <div className="bg-white rounded-2xl border border-slate-200/90 shadow-sm p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-slate-600" />
            <h3 className="text-base font-bold text-slate-900">
              Registros DNS en Cloudflare
            </h3>
          </div>

          {/* Zone Selector */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-600 font-semibold">Zona:</span>
            <select
              value={selectedZone}
              onChange={(e) => handleSelectZone(e.target.value)}
              className="px-3.5 py-1.5 bg-slate-50 border border-slate-300 rounded-xl text-xs font-semibold text-slate-800 focus:outline-none"
            >
              {zones.map((z) => (
                <option key={z.id} value={z.id}>
                  {z.name} ({z.plan?.name || 'Activo'})
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Records Table */}
        <div className="overflow-x-auto rounded-xl border border-slate-200">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
 <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-semibold text-slate-600">
                <th className="py-3 px-4">Tipo</th>
                <th className="py-3 px-4">Nombre</th>
                <th className="py-3 px-4">Destino / Contenido</th>
                <th className="py-3 px-4">Proxy Cloudflare</th>
                <th className="py-3 px-4">TTL</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {records.map((r) => (
                <tr key={r.id} className="hover:bg-slate-50/70">
                  <td className="py-2.5 px-4">
                    <span className="px-2 py-0.5 rounded-lg text-[11px] font-bold bg-slate-100 text-slate-800 border border-slate-200">
                      {r.type}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 font-mono font-semibold text-slate-900">{r.name}</td>
                  <td className="py-2.5 px-4 font-mono text-slate-600 truncate max-w-[280px]">{r.content}</td>
                  <td className="py-2.5 px-4">
                    {r.proxied ? (
                      <span className="text-orange-600 font-medium flex items-center gap-1">
                        <Cloud className="w-3.5 h-3.5 fill-orange-500/20" /> Protegido (Nube Naranja)
                      </span>
                    ) : (
                      <span className="text-slate-500">Solo DNS</span>
                    )}
                  </td>
                  <td className="py-2.5 px-4 text-slate-500">{r.ttl === 1 ? 'Automático' : `${r.ttl}s`}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* --- CREATE TUNNEL MODAL --- */}
      {showTunnelModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl p-6 shadow-xl space-y-4">
            <h3 className="text-lg font-bold text-slate-900 flex items-center gap-2">
              <Network className="w-5 h-5 text-orange-600" />
              Crear Túnel Zero Trust
            </h3>
            <p className="text-xs text-slate-600">
              Crea un túnel entrante seguro con Cloudflare para exponer tu web a internet sin abrir puertos en tu router.
            </p>

            <form onSubmit={handleCreateTunnel} className="space-y-4">
              {tunnelError && (
                <div className="p-3 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-700 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 shrink-0 text-rose-600" />
                  <span>{tunnelError}</span>
                </div>
              )}
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1.5">Nombre del Túnel</label>
                <input
                  type="text"
                  placeholder="ej. mi-app-tunel"
                  value={newTunnelName}
                  onChange={(e) => setNewTunnelName(e.target.value)}
                  className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-300 rounded-xl text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-orange-500/20 focus:border-orange-500"
                  required
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowTunnelModal(false)}
                  className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-600 hover:bg-slate-100 cursor-pointer"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-orange-500 hover:bg-orange-600 text-white font-semibold text-xs cursor-pointer shadow-sm"
                >
                  Crear Túnel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
