import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Server,
  Plus,
  RefreshCw,
  KeyRound,
  ShieldCheck,
  ShieldAlert,
  Cpu,
  HardDrive,
  MemoryStick,
  Copy,
  Check,
  Trash2,
  Pencil,
  Loader2,
  Search,
  AlertTriangle,
  Globe,
  Terminal,
  Box,
} from 'lucide-react';
import { api, type FleetServer, type FleetSshKey } from '../lib/api';
import { copyToClipboard } from '../lib/clipboard';
import { Modal } from './Modal';
import { HelpTip } from './HelpTip';

interface FleetViewProps {
  onNotify: (msg: string, type?: 'info' | 'success' | 'error') => void;
}

type FleetTab = 'nodes' | 'keys';
type StatusFilter = 'all' | 'online' | 'degraded' | 'offline';

const STATUS_META: Record<string, { label: string; dot: string; badge: string }> = {
  online: {
    label: 'En línea',
    dot: 'bg-emerald-500',
    badge: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  },
  degraded: {
    label: 'Degradado',
    dot: 'bg-amber-500',
    badge: 'bg-amber-50 text-amber-800 border-amber-200',
  },
  offline: {
    label: 'Sin conexión',
    dot: 'bg-red-500',
    badge: 'bg-red-50 text-red-700 border-red-200',
  },
  host_key_mismatch: {
    label: 'Huella cambiada',
    dot: 'bg-red-500',
    badge: 'bg-red-50 text-red-800 border-red-200',
  },
  unknown: {
    label: 'Sin sondear',
    dot: 'bg-slate-400',
    badge: 'bg-slate-100 text-slate-600 border-slate-200',
  },
};

function formatMb(mb?: number | null): string {
  if (mb == null || !Number.isFinite(mb)) return '—';
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`;
  return `${Math.round(mb)} MB`;
}

function formatGb(gb?: number | null): string {
  if (gb == null || !Number.isFinite(gb)) return '—';
  return `${gb.toFixed(gb >= 100 ? 0 : 1)} GB`;
}

function percentUsed(total?: number | null, available?: number | null): number | null {
  if (total == null || available == null || total <= 0) return null;
  const used = Math.max(0, total - available);
  return Math.min(100, Math.round((used / total) * 100));
}

function barColor(pct: number): string {
  if (pct >= 88) return 'bg-red-500';
  if (pct >= 72) return 'bg-amber-500';
  return 'bg-slate-900';
}

export const FleetView: React.FC<FleetViewProps> = ({ onNotify }) => {
  const [tab, setTab] = useState<FleetTab>('nodes');
  const [servers, setServers] = useState<FleetServer[]>([]);
  const [keys, setKeys] = useState<FleetSshKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');

  const [probingId, setProbingId] = useState<string | null>(null);
  const [probingAll, setProbingAll] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Add / Edit server modal
  const [serverModalOpen, setServerModalOpen] = useState(false);
  const [editingServer, setEditingServer] = useState<FleetServer | null>(null);
  const [serverSaving, setServerSaving] = useState(false);
  const [srvForm, setSrvForm] = useState({
    name: '',
    host: '',
    port: '22',
    user: 'root',
    keyId: '',
    dockerSocketPath: '/var/run/docker.sock',
    region: 'eu-west',
    tagsText: '',
    hostKeyPolicy: 'tofu' as 'tofu' | 'strict',
    expectedFingerprint: '',
  });

  // Delete server modal
  const [deleteTarget, setDeleteTarget] = useState<FleetServer | null>(null);
  const [deleteForce, setDeleteForce] = useState(false);
  const [deleting, setDeleting] = useState(false);

  // Re-pin host key modal
  const [repinTarget, setRepinTarget] = useState<FleetServer | null>(null);
  const [repinExpected, setRepinExpected] = useState('');
  const [repinning, setRepinning] = useState(false);

  // Add SSH key modal
  const [keyModalOpen, setKeyModalOpen] = useState(false);
  const [keyMode, setKeyMode] = useState<'generate' | 'import'>('generate');
  const [keyName, setKeyName] = useState('');
  const [keyPem, setKeyPem] = useState('');
  const [keySaving, setKeySaving] = useState(false);
  const [deleteKeyTarget, setDeleteKeyTarget] = useState<FleetSshKey | null>(null);

  const loadFleet = useCallback(async () => {
    try {
      const [srvRes, keyRes] = await Promise.all([
        api.getServers(),
        api.getFleetKeys().catch(() => ({ keys: [] })),
      ]);
      setServers(srvRes.servers || []);
      setKeys(keyRes.keys || []);
      setLoadError(null);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'No se pudo cargar la flota de servidores');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    Promise.all([
      api.getServers(),
      api.getFleetKeys().catch(() => ({ keys: [] })),
    ])
      .then(([srvRes, keyRes]) => {
        if (!active) return;
        setServers(srvRes.servers || []);
        setKeys(keyRes.keys || []);
        setLoadError(null);
      })
      .catch((err) => {
        if (!active) return;
        setLoadError(err instanceof Error ? err.message : 'No se pudo cargar la flota de servidores');
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => { active = false; };
  }, []);

  const copy = async (text: string, id: string, label = 'Copiado al portapapeles') => {
    const ok = await copyToClipboard(text);
    if (!ok) {
      onNotify('No se pudo copiar al portapapeles', 'error');
      return;
    }
    setCopiedKey(id);
    window.setTimeout(() => setCopiedKey(null), 1800);
    onNotify(label, 'success');
  };

  const openAddServer = () => {
    setEditingServer(null);
    setSrvForm({
      name: '',
      host: '',
      port: '22',
      user: 'root',
      keyId: keys[0]?.id || '',
      dockerSocketPath: '/var/run/docker.sock',
      region: 'eu-west',
      tagsText: '',
      hostKeyPolicy: 'tofu',
      expectedFingerprint: '',
    });
    setServerModalOpen(true);
  };

  const openEditServer = (srv: FleetServer) => {
    setEditingServer(srv);
    setSrvForm({
      name: srv.name,
      host: srv.host,
      port: String(srv.port || 22),
      user: srv.user || 'root',
      keyId: srv.keyId || '',
      dockerSocketPath: srv.dockerSocketPath || '/var/run/docker.sock',
      region: srv.region || 'default',
      tagsText: (srv.tags || []).join(', '),
      hostKeyPolicy: srv.hostKeyPolicy || 'tofu',
      expectedFingerprint: '',
    });
    setServerModalOpen(true);
  };

  const handleSaveServer = async (e: React.FormEvent) => {
    e.preventDefault();
    setServerSaving(true);
    try {
      const portNum = Math.max(1, Math.min(65535, Number.parseInt(srvForm.port, 10) || 22));
      const tags = srvForm.tagsText
        .split(',')
        .map((t) => t.trim().toLowerCase())
        .filter(Boolean);
      const basePayload = {
        name: srvForm.name.trim(),
        host: srvForm.host.trim(),
        port: portNum,
        user: srvForm.user.trim() || 'root',
        dockerSocketPath: srvForm.dockerSocketPath.trim() || '/var/run/docker.sock',
        region: srvForm.region.trim() || 'default',
        tags,
        hostKeyPolicy: srvForm.hostKeyPolicy,
      };
      if (editingServer) {
        const updatePayload = {
          ...basePayload,
          ...(srvForm.keyId && srvForm.keyId !== editingServer.keyId ? { keyId: srvForm.keyId } : {}),
        };
        await api.updateServer(editingServer.id, updatePayload);
        onNotify(`Servidor «${basePayload.name}» actualizado`, 'success');
      } else {
        const addPayload = {
          ...basePayload,
          ...(srvForm.keyId ? { keyId: srvForm.keyId } : { generateKey: true }),
          ...(srvForm.hostKeyPolicy === 'strict' && srvForm.expectedFingerprint.trim()
            ? { expectedFingerprint: srvForm.expectedFingerprint.trim() }
            : {}),
        };
        await api.addServer(addPayload);
        onNotify(`Servidor «${basePayload.name}» añadido a la flota`, 'success');
      }
      setServerModalOpen(false);
      await loadFleet();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudo guardar el servidor', 'error');
    } finally {
      setServerSaving(false);
    }
  };

  const handleProbe = async (srv: FleetServer) => {
    setProbingId(srv.id);
    try {
      const res = await api.probeServer(srv.id, true);
      const metrics = res.probe || res.resources;
      const nextStatus = res.server?.status || res.status || (metrics?.dockerReady ? 'online' : 'degraded');
      onNotify(
        `Sondeo completado en ${srv.name}: ${STATUS_META[nextStatus]?.label || nextStatus}`,
        nextStatus === 'online' ? 'success' : 'info'
      );
      await loadFleet();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : `Error al sondear ${srv.name}`, 'error');
    } finally {
      setProbingId(null);
    }
  };

  const handleProbeAll = async () => {
    if (servers.length === 0) return;
    setProbingAll(true);
    try {
      await Promise.allSettled(servers.map((s) => api.probeServer(s.id, true)));
      onNotify(`Sondeo de flota completado (${servers.length} nodos)`, 'success');
      await loadFleet();
    } finally {
      setProbingAll(false);
    }
  };

  const handleRepin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repinTarget) return;
    setRepinning(true);
    try {
      await api.repinServerHostKey(repinTarget.id, repinExpected.trim() || undefined);
      onNotify(`Huella SSH de ${repinTarget.name} fijada de nuevo`, 'success');
      setRepinTarget(null);
      setRepinExpected('');
      await loadFleet();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudo re-fijar la huella SSH', 'error');
    } finally {
      setRepinning(false);
    }
  };

  const handleDeleteServer = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await api.deleteServer(deleteTarget.id, deleteForce);
      onNotify(`Servidor «${deleteTarget.name}» eliminado de la flota`, 'info');
      setDeleteTarget(null);
      setDeleteForce(false);
      await loadFleet();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudo eliminar el servidor', 'error');
    } finally {
      setDeleting(false);
    }
  };

  const closeKeyModal = () => {
    setKeyModalOpen(false);
    setKeyName('');
    setKeyPem('');
  };

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!keyName.trim()) return;
    if (keyMode === 'import' && !keyPem.trim()) return;
    setKeySaving(true);
    try {
      await api.createFleetKey({
        name: keyName.trim(),
        mode: keyMode,
        ...(keyMode === 'import' ? { privateKeyPem: keyPem } : {}),
      });
      // Limpiar inmediatamente la clave privada de la memoria del componente
      setKeyPem('');
      setKeyName('');
      setKeyModalOpen(false);
      onNotify(
        keyMode === 'generate'
          ? 'Par de llaves Ed25519 generado y cifrado con AES-256-GCM'
          : 'Llave privada importada y cifrada en la bóveda',
        'success'
      );
      await loadFleet();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudo guardar la llave SSH', 'error');
    } finally {
      setKeySaving(false);
    }
  };

  const handleDeleteKey = async () => {
    if (!deleteKeyTarget) return;
    setKeySaving(true);
    try {
      await api.deleteFleetKey(deleteKeyTarget.id);
      onNotify(`Llave «${deleteKeyTarget.name}» eliminada`, 'info');
      setDeleteKeyTarget(null);
      await loadFleet();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'No se pudo eliminar la llave SSH', 'error');
    } finally {
      setKeySaving(false);
    }
  };

  const filteredServers = useMemo(() => {
    const q = search.trim().toLowerCase();
    return servers.filter((s) => {
      if (statusFilter === 'online' && s.status !== 'online') return false;
      if (statusFilter === 'degraded' && s.status !== 'degraded' && s.status !== 'host_key_mismatch') return false;
      if (statusFilter === 'offline' && s.status !== 'offline' && s.status !== 'unknown') return false;
      if (!q) return true;
      const hay = `${s.name} ${s.host} ${s.region || ''} ${(s.tags || []).join(' ')}`.toLowerCase();
      return hay.includes(q);
    });
  }, [servers, search, statusFilter]);

  const kpis = useMemo(() => {
    const online = servers.filter((s) => s.status === 'online').length;
    const totalCpus = servers.reduce((acc, s) => acc + ((s.probe || s.resources)?.cpus || 0), 0);
    const availRamMb = servers.reduce((acc, s) => acc + ((s.probe || s.resources)?.memoryAvailableMb || 0), 0);
    const totalRamMb = servers.reduce((acc, s) => acc + ((s.probe || s.resources)?.memoryTotalMb || 0), 0);
    return { online, totalCpus, availRamMb, totalRamMb };
  }, [servers]);

  if (loading) {
    return (
      <div className="flex items-center justify-center gap-2 py-16 text-xs text-slate-500">
        <Loader2 className="w-4 h-4 animate-spin" />
        <span>Cargando flota de servidores…</span>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Cabecera */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">Flota de servidores</h1>
            <HelpTip title="Orquestación multi-VPS por túnel SSH">
              <p>Culkibo se conecta a cada VPS mediante túneles SSH con huellas TOFU verificadas y llaves Ed25519 cifradas con AES-256-GCM.</p>
              <p>Nunca expone el socket de Docker ni el API interno de Caddy a Internet.</p>
            </HelpTip>
          </div>
          <p className="text-sm text-slate-500 mt-1 max-w-2xl">
            Orquesta este nodo local y VPS remotos con métricas en vivo, verificación de huella SSH (TOFU) y bóveda de llaves cifrada.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap shrink-0">
          <div className="inline-flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs">
            <button
              type="button"
              onClick={() => setTab('nodes')}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors cursor-pointer ${
                tab === 'nodes' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Nodos <span className="tabular-nums text-slate-400">({servers.length})</span>
            </button>
            <button
              type="button"
              onClick={() => setTab('keys')}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-colors cursor-pointer ${
                tab === 'keys' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <KeyRound className="w-3.5 h-3.5" />
              <span>Llaves SSH</span>
              <span className="tabular-nums text-slate-400">({keys.length})</span>
            </button>
          </div>

          {tab === 'nodes' ? (
            <>
              <button
                type="button"
                onClick={() => void handleProbeAll()}
                disabled={probingAll || servers.length === 0}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-700 cursor-pointer disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${probingAll ? 'animate-spin' : ''}`} />
                <span>Sondear todos</span>
              </button>
              <button
                type="button"
                onClick={openAddServer}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Añadir servidor</span>
              </button>
            </>
          ) : (
            <button
              type="button"
              onClick={() => setKeyModalOpen(true)}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Nueva llave SSH</span>
            </button>
          )}
        </div>
      </div>

      {loadError && (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex items-start gap-3 text-xs">
          <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold text-amber-900">No se pudo actualizar la flota</p>
            <p className="text-amber-800 mt-0.5">{loadError}</p>
          </div>
        </div>
      )}

      {/* KPIs */}
      <div className="bg-slate-200 border border-slate-200 rounded-xl overflow-hidden grid grid-cols-2 lg:grid-cols-4 gap-px">
        <div className="bg-white p-4">
          <div className="text-xs text-slate-500">Nodos en línea</div>
          <div className="text-xl font-semibold text-slate-900 mt-1 tabular-nums">
            {kpis.online} <span className="text-sm font-normal text-slate-400">/ {servers.length}</span>
          </div>
        </div>
        <div className="bg-white p-4">
          <div className="text-xs text-slate-500">Núcleos totales</div>
          <div className="text-xl font-semibold text-slate-900 mt-1 tabular-nums">
            {kpis.totalCpus > 0 ? `${kpis.totalCpus} vCPU` : '—'}
          </div>
        </div>
        <div className="bg-white p-4">
          <div className="text-xs text-slate-500">RAM disponible</div>
          <div className="text-xl font-semibold text-slate-900 mt-1 tabular-nums">
            {kpis.totalRamMb > 0 ? `${formatMb(kpis.availRamMb)} / ${formatMb(kpis.totalRamMb)}` : '—'}
          </div>
        </div>
        <div className="bg-white p-4">
          <div className="text-xs text-slate-500">Llaves en bóveda</div>
          <div className="text-xl font-semibold text-slate-900 mt-1 tabular-nums">
            {keys.length} <span className="text-xs font-normal text-slate-400">AES-256-GCM</span>
          </div>
        </div>
      </div>

      {tab === 'nodes' && (
        <>
          {/* Filtros */}
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1 min-w-0">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filtrar por nombre, host, región o etiqueta…"
                className="w-full pl-9 pr-3 py-2 rounded-lg border border-slate-200 bg-white text-xs text-slate-900 placeholder:text-slate-400"
              />
            </div>
            <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar shrink-0">
              {([
                { id: 'all', label: 'Todos' },
                { id: 'online', label: 'En línea' },
                { id: 'degraded', label: 'Alertas' },
                { id: 'offline', label: 'Sin conexión' },
              ] as const).map((f) => (
                <button
                  key={f.id}
                  type="button"
                  onClick={() => setStatusFilter(f.id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer whitespace-nowrap ${
                    statusFilter === f.id
                      ? 'bg-slate-900 text-white border-slate-900'
                      : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                  }`}
                >
                  {f.label}
                </button>
              ))}
            </div>
          </div>

          {filteredServers.length === 0 ? (
            <div className="bg-white border border-slate-200 rounded-xl p-10 text-center space-y-3">
              <Server className="w-8 h-8 text-slate-300 mx-auto" />
              <div className="text-sm font-semibold text-slate-900">
                {servers.length === 0 ? 'Aún no hay servidores registrados' : 'Ningún servidor coincide con el filtro'}
              </div>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                Registra un VPS remoto por SSH para desplegar proyectos y servicios distribuidos con Docker y Caddy gestionados automáticamente.
              </p>
              {servers.length === 0 && (
                <button
                  type="button"
                  onClick={openAddServer}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 text-white text-xs font-medium cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" /> Añadir primer servidor
                </button>
              )}
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {filteredServers.map((srv) => {
                const isLocal = Boolean(srv.isLocal || srv.id === 'local');
                const st = STATUS_META[srv.status] || STATUS_META.unknown;
                const metrics = srv.probe || srv.resources;
                const errMsg = srv.lastError || srv.statusReason || metrics?.error;
                const ramPct = percentUsed(metrics?.memoryTotalMb, metrics?.memoryAvailableMb);
                const diskPct = percentUsed(metrics?.diskTotalGb, metrics?.diskAvailableGb);
                const isMismatch = srv.status === 'host_key_mismatch';

                return (
                  <article
                    key={srv.id}
                    className={`bg-white border rounded-xl p-4 flex flex-col gap-3.5 transition-colors ${
                      isMismatch ? 'border-red-300' : 'border-slate-200 hover:border-slate-300'
                    }`}
                  >
                    {/* Top row */}
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <h2 className="text-sm font-semibold text-slate-900 truncate">{srv.name}</h2>
                          {isLocal && (
                            <span className="px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 text-[10px] font-medium text-slate-700">
                              Nodo local
                            </span>
                          )}
                          {srv.region && (
                            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-50 border border-slate-200 text-[10px] font-mono text-slate-500">
                              <Globe className="w-2.5 h-2.5" />
                              {srv.region}
                            </span>
                          )}
                        </div>
                        <div className="text-xs font-mono text-slate-500 mt-1 truncate">
                          {isLocal ? '127.0.0.1 (plano de control)' : `${srv.user}@${srv.host}:${srv.port || 22}`}
                        </div>
                      </div>

                      <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium border shrink-0 ${st.badge}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${st.dot}`} />
                        {st.label}
                      </span>
                    </div>

                    {/* Alerta de huella SSH modificada */}
                    {isMismatch && (
                      <div className="p-3 rounded-lg bg-red-50 border border-red-200 text-xs text-red-900 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-start gap-2 min-w-0">
                          <ShieldAlert className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
                          <span className="leading-snug">
                            La clave del host SSH cambió. Conexiones bloqueadas por seguridad hasta verificar y re-fijar.
                          </span>
                        </div>
                        <button
                          type="button"
                          onClick={() => {
                            setRepinTarget(srv);
                            setRepinExpected('');
                          }}
                          className="px-2.5 py-1.5 rounded-md bg-red-600 hover:bg-red-700 text-white font-medium text-[11px] shrink-0 cursor-pointer"
                        >
                          Re-fijar huella
                        </button>
                      </div>
                    )}

                    {/* Métricas hardware */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 bg-slate-50 border border-slate-200 rounded-xl p-3 text-xs tabular-nums">
                      <div className="space-y-1">
                        <div className="flex items-center justify-between text-slate-500">
                          <span className="inline-flex items-center gap-1"><Cpu className="w-3 h-3" /> CPU</span>
                          <span className="font-mono text-slate-900 font-medium">
                            {metrics?.cpus != null ? `${metrics.cpus}c` : '—'}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono">
                          Carga: {metrics?.load1m != null ? metrics.load1m.toFixed(2) : '—'}
                        </div>
                      </div>

                      <div className="space-y-1">
                        <div className="flex items-center justify-between text-slate-500">
                          <span className="inline-flex items-center gap-1"><MemoryStick className="w-3 h-3" /> RAM</span>
                          <span className="font-mono text-slate-900 font-medium">
                            {ramPct != null ? `${ramPct}%` : '—'}
                          </span>
                        </div>
                        <div className="h-1.5 rounded-full bg-slate-200 overflow-hidden">
                          <div
                            className={`h-full rounded-full ${ramPct != null ? barColor(ramPct) : 'bg-slate-300'}`}
                            style={{ width: `${ramPct ?? 0}%` }}
                          />
                        </div>
                        <div className="text-[10px] text-slate-400 font-mono">
                          Libre: {formatMb(metrics?.memoryAvailableMb)} / {formatMb(metrics?.memoryTotalMb)}
                        </div>
                      </div>

                      <div className="space-y-1">
                        <div className="flex items-center justify-between text-slate-500">
                          <span className="inline-flex items-center gap-1"><HardDrive className="w-3 h-3" /> Disco</span>
                          <span className="font-mono text-slate-900 font-medium">
                            {diskPct != null ? `${diskPct}%` : '—'}
                          </span>
                        </div>
                        <div className="h-1.5 rounded-full bg-slate-200 overflow-hidden">
                          <div
                            className={`h-full rounded-full ${diskPct != null ? barColor(diskPct) : 'bg-slate-300'}`}
                            style={{ width: `${diskPct ?? 0}%` }}
                          />
                        </div>
                        <div className="text-[10px] text-slate-400 font-mono">
                          Libre: {formatGb(metrics?.diskAvailableGb)} / {formatGb(metrics?.diskTotalGb)}
                        </div>
                      </div>
                    </div>

                    {/* Badges Docker / Caddy / Latencia / TOFU */}
                    <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md border font-mono ${
                        metrics?.dockerReady
                          ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                          : 'bg-slate-50 border-slate-200 text-slate-600'
                      }`}>
                        <Box className="w-3 h-3" />
                        Docker {metrics?.dockerVersion || (metrics?.dockerReady ? 'OK' : '—')}
                      </span>

                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md border font-mono ${
                        metrics?.caddyAvailable
                          ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                          : 'bg-slate-50 border-slate-200 text-slate-600'
                      }`}>
                        <Globe className="w-3 h-3" />
                        Caddy {metrics?.caddyAvailable ? 'OK' : '—'}
                      </span>

                      {metrics?.latencyMs != null && (
                        <span className="px-2 py-0.5 rounded-md bg-slate-50 border border-slate-200 text-slate-600 font-mono tabular-nums">
                          RTT {metrics.latencyMs} ms
                        </span>
                      )}

                      {!isLocal && (
                        <button
                          type="button"
                          onClick={() => srv.hostKeyFingerprint && void copy(srv.hostKeyFingerprint, `fp-${srv.id}`, 'Huella SSH copiada')}
                          disabled={!srv.hostKeyFingerprint}
                          title={srv.hostKeyFingerprint || 'Se fijará automáticamente en el primer sondeo (TOFU)'}
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-50 hover:bg-slate-100 border border-slate-200 text-slate-700 font-mono max-w-full cursor-pointer disabled:cursor-default"
                        >
                          <ShieldCheck className="w-3 h-3 text-slate-500 shrink-0" />
                          <span className="truncate max-w-[165px]">
                            {srv.hostKeyFingerprint ? srv.hostKeyFingerprint : `${(srv.hostKeyPolicy || 'tofu').toUpperCase()} pendiente`}
                          </span>
                          {srv.hostKeyFingerprint && (
                            copiedKey === `fp-${srv.id}`
                              ? <Check className="w-3 h-3 text-emerald-600 shrink-0" />
                              : <Copy className="w-3 h-3 text-slate-400 shrink-0" />
                          )}
                        </button>
                      )}
                    </div>

                    {srv.tags && srv.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {srv.tags.map((tag) => (
                          <span key={tag} className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 text-[10px] font-mono">
                            #{tag}
                          </span>
                        ))}
                      </div>
                    )}

                    {errMsg && (
                      <p className="text-[11px] text-red-700 bg-red-50 border border-red-100 rounded-lg px-2.5 py-1.5 break-words">
                        {errMsg}
                      </p>
                    )}

                    {/* Acciones */}
                    <div className="flex items-center justify-between gap-2 pt-2 border-t border-slate-100 mt-auto">
                      <span className="text-[11px] text-slate-400 tabular-nums">
                        {srv.projectsCount != null ? `${srv.projectsCount} ${srv.projectsCount === 1 ? 'proyecto' : 'proyectos'}` : (metrics?.os || 'Listo')}
                      </span>
                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => void handleProbe(srv)}
                          disabled={probingId === srv.id}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-700 cursor-pointer disabled:opacity-50"
                        >
                          <RefreshCw className={`w-3.5 h-3.5 ${probingId === srv.id ? 'animate-spin' : ''}`} />
                          <span>Sondear</span>
                        </button>
                        {!isLocal && (
                          <>
                            <button
                              type="button"
                              aria-label={`Editar ${srv.name}`}
                              onClick={() => openEditServer(srv)}
                              className="p-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-600 cursor-pointer"
                            >
                              <Pencil className="w-3.5 h-3.5" />
                            </button>
                            <button
                              type="button"
                              aria-label={`Eliminar ${srv.name}`}
                              onClick={() => {
                                setDeleteTarget(srv);
                                setDeleteForce(false);
                              }}
                              className="p-1.5 rounded-lg bg-white hover:bg-red-50 border border-slate-200 hover:border-red-200 text-slate-500 hover:text-red-700 cursor-pointer"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </>
                        )}
                      </div>
                    </div>
                  </article>
                );
              })}
            </div>
          )}
        </>
      )}

      {tab === 'keys' && (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 bg-slate-50 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-slate-900">Bóveda de llaves SSH (AES-256-GCM)</h2>
              <p className="text-xs text-slate-500">
                Las claves privadas se cifran en reposo con AAD y nunca se devuelven por API. Copia la clave pública a <code className="font-mono">~/.ssh/authorized_keys</code> del VPS.
              </p>
            </div>
          </div>

          {keys.length === 0 ? (
            <div className="p-10 text-center space-y-3">
              <KeyRound className="w-8 h-8 text-slate-300 mx-auto" />
              <div className="text-sm font-semibold text-slate-900">Sin llaves SSH en la bóveda</div>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                Genera un par Ed25519 en un clic o importa una clave privada OpenSSH existente para conectar tus servidores remotos.
              </p>
              <button
                type="button"
                onClick={() => setKeyModalOpen(true)}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 text-white text-xs font-medium cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" /> Crear llave Ed25519
              </button>
            </div>
          ) : (
            <div className="divide-y divide-slate-100">
              {keys.map((k) => {
                const safePubKey = String(k.publicKey || '').replace(/[\r\n]+/g, ' ').trim();
                const shellSafePubKey = safePubKey.replace(/'/g, "'\\''");
                const installCmd = `mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '${shellSafePubKey}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`;
                return (
                  <div key={k.id} className="p-4 sm:px-5 space-y-2.5">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-semibold text-slate-900">{k.name}</span>
                          <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-600">
                            {k.keyType || k.algorithm || 'ed25519'}
                          </span>
                        </div>
                        <div className="text-[11px] font-mono text-slate-500 mt-0.5 break-all">
                          {k.fingerprint}
                        </div>
                      </div>
                      <div className="flex items-center gap-1.5 flex-wrap shrink-0">
                        <button
                          type="button"
                          onClick={() => void copy(k.publicKey, `pub-${k.id}`, 'Clave pública copiada')}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-700 cursor-pointer"
                        >
                          {copiedKey === `pub-${k.id}` ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                          <span>Clave pública</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => void copy(installCmd, `cmd-${k.id}`, 'Comando authorized_keys copiado')}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-700 cursor-pointer"
                        >
                          {copiedKey === `cmd-${k.id}` ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Terminal className="w-3.5 h-3.5" />}
                          <span>Copiar comando</span>
                        </button>
                        <button
                          type="button"
                          aria-label={`Eliminar llave ${k.name}`}
                          onClick={() => setDeleteKeyTarget(k)}
                          className="p-1.5 rounded-lg bg-white hover:bg-red-50 border border-slate-200 hover:border-red-200 text-slate-500 hover:text-red-700 cursor-pointer"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                    <pre className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-[11px] font-mono text-slate-600 overflow-x-auto whitespace-nowrap">
                      {k.publicKey}
                    </pre>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Modal: Añadir / Editar servidor */}
      <Modal
        open={serverModalOpen}
        onClose={() => setServerModalOpen(false)}
        title={editingServer ? `Editar ${editingServer.name}` : 'Añadir servidor SSH a la flota'}
        subtitle="Culkibo abre túneles SSH cifrados bajo demanda. Se bloquean IPs de metadatos cloud y loopback por seguridad."
        maxWidthClass="max-w-xl"
      >
        <form onSubmit={handleSaveServer} className="p-5 space-y-4 text-xs">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label className="block">
              <span className="font-medium text-slate-700">Nombre visible</span>
              <input
                required
                value={srvForm.name}
                onChange={(e) => setSrvForm({ ...srvForm, name: e.target.value })}
                placeholder="VPS Producción EU"
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 text-slate-900"
              />
            </label>
            <label className="block">
              <span className="font-medium text-slate-700">Host o IP (pública, VPC o Tailscale)</span>
              <input
                required
                value={srvForm.host}
                onChange={(e) => setSrvForm({ ...srvForm, host: e.target.value })}
                placeholder="203.0.113.42 o vps-eu.ejemplo.com"
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900"
              />
            </label>
            <label className="block">
              <span className="font-medium text-slate-700">Usuario SSH</span>
              <input
                required
                value={srvForm.user}
                onChange={(e) => setSrvForm({ ...srvForm, user: e.target.value })}
                placeholder="root"
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900"
              />
            </label>
            <label className="block">
              <span className="font-medium text-slate-700">Puerto SSH</span>
              <input
                type="number"
                min={1}
                max={65535}
                value={srvForm.port}
                onChange={(e) => setSrvForm({ ...srvForm, port: e.target.value })}
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900 tabular-nums"
              />
            </label>
            <label className="block">
              <span className="font-medium text-slate-700">Llave SSH de la bóveda</span>
              <select
                value={srvForm.keyId}
                onChange={(e) => setSrvForm({ ...srvForm, keyId: e.target.value })}
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 bg-white text-slate-900"
              >
                <option value="">
                  {editingServer ? 'Conservar llave actual' : 'Generar llave Ed25519 automáticamente'}
                </option>
                {keys.map((k) => (
                  <option key={k.id} value={k.id}>
                    {k.name} ({k.fingerprint.slice(0, 18)}…)
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="font-medium text-slate-700">Región</span>
              <input
                value={srvForm.region}
                onChange={(e) => setSrvForm({ ...srvForm, region: e.target.value })}
                placeholder="eu-west"
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900"
              />
            </label>
            <label className="block">
              <span className="font-medium text-slate-700">Socket Docker remoto</span>
              <input
                value={srvForm.dockerSocketPath}
                onChange={(e) => setSrvForm({ ...srvForm, dockerSocketPath: e.target.value })}
                placeholder="/var/run/docker.sock"
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900"
              />
            </label>
            <label className="block">
              <span className="font-medium text-slate-700">Etiquetas (separadas por coma)</span>
              <input
                value={srvForm.tagsText}
                onChange={(e) => setSrvForm({ ...srvForm, tagsText: e.target.value })}
                placeholder="prod, hetzner, gpu"
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900"
              />
            </label>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
            <div className="font-medium text-slate-800">Política de huella de host SSH (anti-MITM)</div>
            <div className="flex flex-wrap gap-3">
              <label className="inline-flex items-center gap-1.5 cursor-pointer text-slate-700">
                <input
                  type="radio"
                  name="hostKeyPolicy"
                  checked={srvForm.hostKeyPolicy === 'tofu'}
                  onChange={() => setSrvForm({ ...srvForm, hostKeyPolicy: 'tofu' })}
                  className="accent-slate-900"
                />
                <span>TOFU (fijar en el primer contacto)</span>
              </label>
              <label className="inline-flex items-center gap-1.5 cursor-pointer text-slate-700">
                <input
                  type="radio"
                  name="hostKeyPolicy"
                  checked={srvForm.hostKeyPolicy === 'strict'}
                  onChange={() => setSrvForm({ ...srvForm, hostKeyPolicy: 'strict' })}
                  className="accent-slate-900"
                />
                <span>Estricta (exigir huella SHA256 exacta)</span>
              </label>
            </div>
            {srvForm.hostKeyPolicy === 'strict' && (
              <input
                value={srvForm.expectedFingerprint}
                onChange={(e) => setSrvForm({ ...srvForm, expectedFingerprint: e.target.value })}
                placeholder="SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                required={!editingServer}
                className="w-full px-3 py-2 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
              />
            )}
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
            <button
              type="button"
              onClick={() => setServerModalOpen(false)}
              className="px-3.5 py-2 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 cursor-pointer"
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={serverSaving}
              className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              {serverSaving ? 'Guardando…' : (editingServer ? 'Guardar cambios' : 'Registrar servidor')}
            </button>
          </div>
        </form>
      </Modal>

      {/* Modal: Re-fijar huella SSH */}
      <Modal
        open={Boolean(repinTarget)}
        onClose={() => setRepinTarget(null)}
        title={`Re-fijar huella SSH de ${repinTarget?.name || ''}`}
        subtitle="Hazlo únicamente si reinstalaste el VPS o rotaste las claves del host de forma intencionada."
        maxWidthClass="max-w-md"
      >
        <form onSubmit={handleRepin} className="p-5 space-y-4 text-xs">
          <label className="block">
            <span className="font-medium text-slate-700">Huella SHA256 esperada (opcional para verificar)</span>
            <input
              value={repinExpected}
              onChange={(e) => setRepinExpected(e.target.value)}
              placeholder="SHA256:..."
              className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900"
            />
          </label>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setRepinTarget(null)}
              className="px-3.5 py-2 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 cursor-pointer"
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={repinning}
              className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-700 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              {repinning ? 'Fijando…' : 'Confirmar nueva huella'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Modal: Eliminar servidor */}
      <Modal
        open={Boolean(deleteTarget)}
        onClose={() => setDeleteTarget(null)}
        title={`Eliminar ${deleteTarget?.name || ''}`}
        subtitle="Culkibo dejará de gestionar este nodo remoto. Los contenedores en el VPS no se destruirán."
        maxWidthClass="max-w-md"
      >
        <div className="p-5 space-y-4 text-xs">
          <label className="flex items-start gap-2.5 p-3 rounded-lg bg-slate-50 border border-slate-200 cursor-pointer">
            <input
              type="checkbox"
              checked={deleteForce}
              onChange={(e) => setDeleteForce(e.target.checked)}
              className="mt-0.5 accent-red-600"
            />
            <span className="text-slate-700">
              Forzar eliminación incluso si hay proyectos asignados a este servidor
            </span>
          </label>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setDeleteTarget(null)}
              className="px-3.5 py-2 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 cursor-pointer"
            >
              Cancelar
            </button>
            <button
              type="button"
              disabled={deleting}
              onClick={() => void handleDeleteServer()}
              className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-700 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              {deleting ? 'Eliminando…' : 'Eliminar servidor'}
            </button>
          </div>
        </div>
      </Modal>

      {/* Modal: Crear o importar llave SSH */}
      <Modal
        open={keyModalOpen}
        onClose={closeKeyModal}
        title="Nueva llave SSH en bóveda"
        subtitle="Se cifra inmediatamente con AES-256-GCM en el servidor; la clave privada nunca vuelve a mostrarse."
        maxWidthClass="max-w-lg"
      >
        <form onSubmit={handleCreateKey} className="p-5 space-y-4 text-xs">
          <div className="inline-flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200">
            <button
              type="button"
              onClick={() => setKeyMode('generate')}
              className={`px-3 py-1.5 rounded-md font-medium cursor-pointer ${
                keyMode === 'generate' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600'
              }`}
            >
              Generar Ed25519
            </button>
            <button
              type="button"
              onClick={() => setKeyMode('import')}
              className={`px-3 py-1.5 rounded-md font-medium cursor-pointer ${
                keyMode === 'import' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600'
              }`}
            >
              Importar clave privada
            </button>
          </div>

          <label className="block">
            <span className="font-medium text-slate-700">Nombre identificador</span>
            <input
              required
              value={keyName}
              onChange={(e) => setKeyName(e.target.value)}
              placeholder="prod-hetzner-2026"
              className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 text-slate-900"
            />
          </label>

          {keyMode === 'import' && (
            <label className="block">
              <span className="font-medium text-slate-700">Clave privada OpenSSH / PEM (sin contraseña)</span>
              <textarea
                required
                rows={6}
                value={keyPem}
                onChange={(e) => setKeyPem(e.target.value)}
                placeholder={'-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----'}
                spellCheck={false}
                className="mt-1 w-full p-3 rounded-lg border border-slate-200 font-mono text-[11px] text-slate-900"
              />
            </label>
          )}

          <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
            <button
              type="button"
              onClick={closeKeyModal}
              className="px-3.5 py-2 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 cursor-pointer"
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={keySaving}
              className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              {keySaving ? 'Procesando…' : (keyMode === 'generate' ? 'Generar llave' : 'Importar y cifrar')}
            </button>
          </div>
        </form>
      </Modal>

      {/* Modal: Eliminar llave SSH */}
      <Modal
        open={Boolean(deleteKeyTarget)}
        onClose={() => setDeleteKeyTarget(null)}
        title={`Eliminar llave «${deleteKeyTarget?.name || ''}»`}
        subtitle="Solo es posible si ningún servidor de la flota la utiliza actualmente."
        maxWidthClass="max-w-md"
      >
        <div className="p-5 space-y-4 text-xs">
          <p className="text-slate-600">
            La clave cifrada se eliminará permanentemente de la bóveda local de Culkibo.
          </p>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setDeleteKeyTarget(null)}
              className="px-3.5 py-2 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 cursor-pointer"
            >
              Cancelar
            </button>
            <button
              type="button"
              disabled={keySaving}
              onClick={() => void handleDeleteKey()}
              className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-700 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              Eliminar llave
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
