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
  Wrench,
  PauseCircle,
  Rocket,
  Network,
  RotateCw,
  X,
  Hammer,
  Sparkles,
  Lock,
  CheckCircle2,
  Play,
} from 'lucide-react';
import {
  api,
  type FleetServer,
  type FleetSshKey,
  type DirectPushPlanResult,
  type FleetMeshStatusResult,
  type FleetMeshPlanResult,
  type FleetMeshRotateResult,
  type RemoteBuilderNode,
  type RemoteBuildScheduleResult,
  type AiRuntimePreset,
  type AiVramEstimateResult,
  type AiWorkloadPlanResult,
  type VolumeMigrationRecord,
} from '../lib/api';
import { copyToClipboard } from '../lib/clipboard';
import { useI18n } from '../lib/i18n';
import { Modal } from './Modal';
import { HelpTip } from './HelpTip';

interface FleetViewProps {
  onNotify: (msg: string, type?: 'info' | 'success' | 'error') => void;
}

type MaintenanceState = 'active' | 'draining' | 'maintenance';
type FleetServerWithMaintenance = FleetServer & {
  maintenanceState?: MaintenanceState | string;
  maintenanceReason?: string | null;
  maintenanceSince?: string | null;
};

type FleetTab = 'nodes' | 'keys';
type StatusFilter = 'all' | 'online' | 'degraded' | 'maintenance' | 'offline';

const MAINTENANCE_META: Record<'draining' | 'maintenance', { label: string; badge: string; hint: string }> = {
  draining: {
    label: 'Drenando',
    badge: 'bg-amber-50 text-amber-800 border-amber-200',
    hint: 'Nuevos despliegues bloqueados; los contenedores existentes siguen atendiendo tráfico.',
  },
  maintenance: {
    label: 'Mantenimiento',
    badge: 'bg-slate-100 text-slate-700 border-slate-300',
    hint: 'Nodo en mantenimiento; nuevos despliegues y programación automática deshabilitados.',
  },
};

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
  const { t } = useI18n();
  const [tab, setTab] = useState<FleetTab>('nodes');
  const [servers, setServers] = useState<FleetServerWithMaintenance[]>([]);
  const [keys, setKeys] = useState<FleetSshKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');

  // DirectPush (Zero-Registry SSH) modal state
  const [directPushServer, setDirectPushServer] = useState<FleetServerWithMaintenance | null>(null);
  const [directPushImage, setDirectPushImage] = useState('my-app:latest');
  const [directPushPort, setDirectPushPort] = useState('5055');
  const [directPushPlan, setDirectPushPlan] = useState<DirectPushPlanResult | null>(null);
  const [directPushLoading, setDirectPushLoading] = useState(false);
  const [directPushError, setDirectPushError] = useState<string | null>(null);

  // WireGuard Fleet Mesh (10.88.0.0/24) state
  const [mesh, setMesh] = useState<FleetMeshStatusResult | null>(null);
  const [meshPlan, setMeshPlan] = useState<FleetMeshPlanResult | null>(null);
  const [meshRotate, setMeshRotate] = useState<FleetMeshRotateResult | null>(null);
  const [meshBusy, setMeshBusy] = useState<'plan' | 'rotate' | null>(null);
  const [meshError, setMeshError] = useState<string | null>(null);

  // Cycle-10 Remote Build-Node Offloader state
  const [builders, setBuilders] = useState<RemoteBuilderNode[]>([]);
  const [builderSchedule, setBuilderSchedule] = useState<RemoteBuildScheduleResult | null>(null);
  const [builderBusy, setBuilderBusy] = useState(false);
  const [builderError, setBuilderError] = useState<string | null>(null);

  // Cycle-10 Self-Hosted AI / GPU & Local LLM Workload Planner state
  const [aiPresets, setAiPresets] = useState<AiRuntimePreset[]>([]);
  const [aiRuntime, setAiRuntime] = useState<'ollama' | 'vllm' | 'llamacpp'>('ollama');
  const [aiParamsB, setAiParamsB] = useState<number>(14);
  const [aiQuant, setAiQuant] = useState<'Q4_K_M' | 'Q8_0' | 'FP16'>('Q4_K_M');
  const [aiVramGb, setAiVramGb] = useState<number>(24);
  const [aiGpuMode, setAiGpuMode] = useState<'cdi' | 'legacy' | 'cpu'>('cdi');
  const [aiVramEst, setAiVramEst] = useState<AiVramEstimateResult | null>(null);
  const [aiPlan, setAiPlan] = useState<AiWorkloadPlanResult | null>(null);
  const [aiBusy, setAiBusy] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  // Cycle-11: Stateful Volume Snapshot Cloner & Cross-VPS Migration Planner
  const [volMigrations, setVolMigrations] = useState<VolumeMigrationRecord[]>([]);
  const [volName, setVolName] = useState('acme_postgres_data');
  const [volMount, setVolMount] = useState('/var/lib/postgresql/data');
  const [volUidGid, setVolUidGid] = useState('999:999');
  const [volTargetHost, setVolTargetHost] = useState('198.51.100.42');
  const [volBusy, setVolBusy] = useState(false);
  const [volError, setVolError] = useState<string | null>(null);
  const [activeVolPlan, setActiveVolPlan] = useState<VolumeMigrationRecord | null>(null);

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
      const [srvRes, keyRes, meshRes, bldRes, aiRes] = await Promise.all([
        api.getServers(),
        api.getFleetKeys().catch(() => ({ keys: [] })),
        api.getFleetMesh().catch(() => null),
        api.listRemoteBuilders().catch(() => ({ builders: [] })),
        api.getAiPresets().catch(() => ({ presets: [] })),
      ]);
      setServers(Array.isArray(srvRes?.servers) ? srvRes.servers : []);
      setKeys(Array.isArray(keyRes?.keys) ? keyRes.keys : []);
      if (meshRes) setMesh(meshRes);
      setBuilders(Array.isArray(bldRes?.builders) ? bldRes.builders : []);
      setAiPresets(Array.isArray(aiRes?.presets) ? aiRes.presets : []);
      setLoadError(null);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Could not load server fleet');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    Promise.all([
      api.getServers(),
      api.getFleetKeys().catch(() => ({ keys: [] })),
      api.getFleetMesh().catch(() => null),
      api.listRemoteBuilders().catch(() => ({ builders: [] })),
      api.getAiPresets().catch(() => ({ presets: [] })),
      api.listVolumeMigrations().catch(() => ({ migrations: [] })),
    ])
      .then(([srvRes, keyRes, meshRes, bldRes, aiRes, volRes]) => {
        if (!active) return;
        const srvList = Array.isArray(srvRes?.servers) ? srvRes.servers : [];
        setServers(srvList);
        const firstRemote = srvList.find((x) => !x.isLocal && x.id !== 'local' && x.host);
        if (firstRemote?.host) setVolTargetHost(firstRemote.host);
        setKeys(Array.isArray(keyRes?.keys) ? keyRes.keys : []);
        if (meshRes) setMesh(meshRes);
        setBuilders(Array.isArray(bldRes?.builders) ? bldRes.builders : []);
        setAiPresets(Array.isArray(aiRes?.presets) ? aiRes.presets : []);
        const migList = Array.isArray(volRes?.migrations) ? volRes.migrations : [];
        setVolMigrations(migList);
        if (migList.length > 0) setActiveVolPlan(migList[0]);
        setLoadError(null);
      })
      .catch((err) => {
        if (!active) return;
        setLoadError(err instanceof Error ? err.message : 'Could not load server fleet');
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    api.estimateAiVram({
      paramsB: aiParamsB,
      quantization: aiQuant,
      contextLen: 8192,
      batchSize: 1,
      availableVramGb: aiVramGb,
    })
      .then((res) => {
        if (active && res) setAiVramEst(res);
      })
      .catch(() => {
        // optional
      });
    return () => { active = false; };
  }, [aiParamsB, aiQuant, aiVramGb]);

  const handleTestPreviewOffload = async () => {
    setBuilderBusy(true);
    setBuilderError(null);
    try {
      if (builders.length === 0) {
        await api.registerRemoteBuilder({
          name: 'builder-eu-01',
          host: '10.88.0.10',
          arch: 'linux/amd64',
          maxConcurrency: 4,
          allowPreviews: true,
          keepStorageGb: 20,
        }).catch(() => null);
      }
      const res = await api.scheduleRemoteBuild({
        arch: 'linux/amd64',
        isPreview: true,
      });
      setBuilderSchedule(res);
      const refreshed = await api.listRemoteBuilders().catch(() => null);
      if (refreshed && Array.isArray(refreshed.builders)) setBuilders(refreshed.builders);
      onNotify(`PR Preview offloaded to ${res.builderName || res.builderId} (SSH mux pinned)`, 'success');
    } catch (err: unknown) {
      setBuilderError(err instanceof Error ? err.message : 'Could not schedule remote build offload');
    } finally {
      setBuilderBusy(false);
    }
  };

  const handlePlanAiWorkload = async () => {
    setAiBusy(true);
    setAiError(null);
    try {
      const res = await api.planAiWorkload({
        runtime: aiRuntime,
        model: `${aiRuntime === 'vllm' ? 'Qwen/Qwen2.5' : 'qwen2.5'}:${aiParamsB}b-${aiQuant.toLowerCase()}`,
        paramsB: aiParamsB,
        quantization: aiQuant,
        contextLen: 8192,
        availableVramGb: aiVramGb,
        gpuMode: aiGpuMode,
        bindAddress: '127.0.0.1',
        authProxyEnabled: true,
      });
      setAiPlan(res);
      onNotify(`Secure ${aiRuntime} plan generated (127.0.0.1 + Bearer proxy + CVE-safe tag)`, 'success');
    } catch (err: unknown) {
      setAiPlan(null);
      setAiError(err instanceof Error ? err.message : 'AI/GPU guardrail rejected workload plan');
    } finally {
      setAiBusy(false);
    }
  };

  const handlePlanVolumeMigration = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setVolBusy(true);
    setVolError(null);
    try {
      const parts = volUidGid.split(':').map((n) => parseInt(n.trim(), 10));
      const uid = Number.isInteger(parts[0]) ? parts[0] : 999;
      const gid = Number.isInteger(parts[1]) ? parts[1] : uid;
      const res = await api.planVolumeMigration({
        volumeName: volName.trim(),
        mountPath: volMount.trim(),
        sourceHost: 'local',
        targetHost: volTargetHost.trim() || '198.51.100.42',
        uid,
        gid,
        containerName: 'culkibo-db-pg-main',
        estimatedMb: 512,
      });
      setActiveVolPlan(res);
      setVolMigrations((prev) => [res, ...prev.filter((m) => m.id !== res.id)].slice(0, 10));
      onNotify(`4-phase zero-shell migration planned for ${res.volumeName} (${uid}:${gid} preserved)`, 'success');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Volume migration guardrail blocked plan';
      setVolError(msg);
      onNotify(msg, 'error');
    } finally {
      setVolBusy(false);
    }
  };

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
      const mState = s.maintenanceState || 'active';
      if (statusFilter === 'online' && s.status !== 'online') return false;
      if (statusFilter === 'degraded' && s.status !== 'degraded' && s.status !== 'host_key_mismatch') return false;
      if (statusFilter === 'maintenance' && mState !== 'draining' && mState !== 'maintenance') return false;
      if (statusFilter === 'offline' && s.status !== 'offline' && s.status !== 'unknown') return false;
      if (!q) return true;
      const hay = `${s.name} ${s.host} ${s.region || ''} ${mState} ${(s.tags || []).join(' ')}`.toLowerCase();
      return hay.includes(q);
    });
  }, [servers, search, statusFilter]);

  const kpis = useMemo(() => {
    const online = servers.filter((s) => s.status === 'online').length;
    const cordoned = servers.filter((s) => s.maintenanceState === 'draining' || s.maintenanceState === 'maintenance').length;
    const totalCpus = servers.reduce((acc, s) => acc + ((s.probe || s.resources)?.cpus || 0), 0);
    const availRamMb = servers.reduce((acc, s) => acc + ((s.probe || s.resources)?.memoryAvailableMb || 0), 0);
    const totalRamMb = servers.reduce((acc, s) => acc + ((s.probe || s.resources)?.memoryTotalMb || 0), 0);
    return { online, cordoned, totalCpus, availRamMb, totalRamMb };
  }, [servers]);

  const openDirectPushModal = (srv: FleetServerWithMaintenance) => {
    setDirectPushServer(srv);
    setDirectPushImage('my-app:latest');
    setDirectPushPort('5055');
    setDirectPushPlan(null);
    setDirectPushError(null);
  };

  const handlePlanDirectPush = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!directPushServer || !directPushImage.trim()) return;
    setDirectPushLoading(true);
    setDirectPushError(null);
    try {
      const plan = await api.planDirectPush({
        image: directPushImage.trim(),
        serverId: directPushServer.id,
        sshHost: directPushServer.host || undefined,
        sshPort: directPushServer.port || 22,
        sshUser: directPushServer.user || 'root',
        localPort: Number(directPushPort) || 5055,
      });
      setDirectPushPlan(plan);
    } catch (err: unknown) {
      setDirectPushError(err instanceof Error ? err.message : 'DirectPush plan error');
    } finally {
      setDirectPushLoading(false);
    }
  };

  const handlePreviewMeshPlan = async () => {
    setMeshBusy('plan');
    setMeshError(null);
    try {
      const plan = await api.planFleetMesh({ dryRun: true, includeRedactedTemplate: true });
      setMeshPlan(plan);
    } catch (err: unknown) {
      setMeshError(err instanceof Error ? err.message : 'WireGuard mesh plan unavailable');
    } finally {
      setMeshBusy(null);
    }
  };

  const handleDryRunRotateKey = async (nodeId?: string) => {
    const targetId = nodeId || mesh?.peers?.[0]?.nodeId || servers[0]?.id || 'local';
    setMeshBusy('rotate');
    setMeshError(null);
    try {
      const res = await api.rotateFleetMeshKey({ nodeId: targetId, dryRun: true });
      setMeshRotate(res);
    } catch (err: unknown) {
      setMeshError(err instanceof Error ? err.message : 'WireGuard key rotation preview unavailable');
    } finally {
      setMeshBusy(null);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center gap-2 py-16 text-xs text-slate-500">
        <Loader2 className="w-4 h-4 animate-spin" />
        <span>{t('fleet.loading')}</span>
      </div>
    );
  }

  const localizedStatusLabel = (status: string): string => {
    if (status === 'online') return t('fleet.statusOnline');
    if (status === 'degraded') return t('fleet.statusDegraded');
    if (status === 'offline') return t('fleet.statusOffline');
    if (status === 'host_key_mismatch') return t('fleet.statusMismatch');
    return t('fleet.statusUnknown');
  };

  return (
    <div className="space-y-5">
      {/* Cabecera */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">{t('fleet.title')}</h1>
            <HelpTip title="Multi-VPS SSH & DirectPush">
              <p>Culkibo connects over SSH tunnels with TOFU host-key pinning and AES-256-GCM encrypted Ed25519 keys.</p>
              <p>Docker socket and Caddy admin API are never exposed to the public internet.</p>
            </HelpTip>
          </div>
          <p className="text-sm text-slate-500 mt-1 max-w-2xl">{t('fleet.subtitle')}</p>
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
              {t('fleet.tabNodes')} <span className="tabular-nums text-slate-400">({servers.length})</span>
            </button>
            <button
              type="button"
              onClick={() => setTab('keys')}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-colors cursor-pointer ${
                tab === 'keys' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <KeyRound className="w-3.5 h-3.5" />
              <span>{t('fleet.tabKeys')}</span>
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
                <span>{t('fleet.probeAll')}</span>
              </button>
              <button
                type="button"
                onClick={openAddServer}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>{t('fleet.addServer')}</span>
              </button>
            </>
          ) : (
            <button
              type="button"
              onClick={() => setKeyModalOpen(true)}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>{t('fleet.newKey')}</span>
            </button>
          )}
        </div>
      </div>

      {loadError && (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex items-start gap-3 text-xs">
          <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold text-amber-900">{loadError}</p>
          </div>
        </div>
      )}

      {/* KPIs */}
      <div className="bg-slate-200 border border-slate-200 rounded-xl overflow-hidden grid grid-cols-2 lg:grid-cols-4 gap-px">
        <div className="bg-white p-4">
          <div className="text-xs text-slate-500">{t('fleet.kpiOnline')}</div>
          <div className="text-xl font-semibold text-slate-900 mt-1 tabular-nums">
            {kpis.online} <span className="text-sm font-normal text-slate-400">/ {servers.length}</span>
          </div>
          {kpis.cordoned > 0 && (
            <div className="text-[11px] text-amber-700 mt-0.5 tabular-nums">
              {kpis.cordoned} {t('fleet.filterMaintenance').toLowerCase()}
            </div>
          )}
        </div>
        <div className="bg-white p-4">
          <div className="text-xs text-slate-500">{t('fleet.kpiCores')}</div>
          <div className="text-xl font-semibold text-slate-900 mt-1 tabular-nums">
            {kpis.totalCpus > 0 ? `${kpis.totalCpus} vCPU` : '—'}
          </div>
        </div>
        <div className="bg-white p-4">
          <div className="text-xs text-slate-500">{t('fleet.kpiRam')}</div>
          <div className="text-xl font-semibold text-slate-900 mt-1 tabular-nums">
            {kpis.totalRamMb > 0 ? `${formatMb(kpis.availRamMb)} / ${formatMb(kpis.totalRamMb)}` : '—'}
          </div>
        </div>
        <div className="bg-white p-4">
          <div className="text-xs text-slate-500">{t('fleet.kpiKeys')}</div>
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
                placeholder={t('fleet.searchPlaceholder')}
                className="w-full pl-9 pr-3 py-2 rounded-lg border border-slate-200 bg-white text-xs text-slate-900 placeholder:text-slate-400"
              />
            </div>
            <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar shrink-0">
              {([
                { id: 'all', label: t('fleet.filterAll') },
                { id: 'online', label: t('fleet.filterOnline') },
                { id: 'degraded', label: t('fleet.filterDegraded') },
                { id: 'maintenance', label: t('fleet.filterMaintenance') },
                { id: 'offline', label: t('fleet.filterOffline') },
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
                {servers.length === 0 ? t('fleet.emptyTitle') : t('fleet.emptyFiltered')}
              </div>
              <p className="text-xs text-slate-500 max-w-md mx-auto">{t('fleet.emptyDesc')}</p>
              {servers.length === 0 && (
                <button
                  type="button"
                  onClick={openAddServer}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 text-white text-xs font-medium cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" /> {t('fleet.addFirst')}
                </button>
              )}
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {filteredServers.map((srv) => {
                const isLocal = Boolean(srv.isLocal || srv.id === 'local');
                const st = STATUS_META[srv.status] || STATUS_META.unknown;
                const mState = srv.maintenanceState === 'draining' || srv.maintenanceState === 'maintenance'
                  ? srv.maintenanceState
                  : null;
                const mMeta = mState ? MAINTENANCE_META[mState] : null;
                const metrics = srv.probe || srv.resources;
                const errMsg = srv.lastError || srv.statusReason || metrics?.error;
                const ramPct = percentUsed(metrics?.memoryTotalMb, metrics?.memoryAvailableMb);
                const diskPct = percentUsed(metrics?.diskTotalGb, metrics?.diskAvailableGb);
                const isMismatch = srv.status === 'host_key_mismatch';

                return (
                  <article
                    key={srv.id}
                    className={`bg-white border rounded-xl p-4 flex flex-col gap-3.5 transition-colors ${
                      isMismatch
                        ? 'border-red-300'
                        : mState
                          ? 'border-amber-200 hover:border-amber-300'
                          : 'border-slate-200 hover:border-slate-300'
                    }`}
                  >
                    {/* Top row */}
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <h2 className="text-sm font-semibold text-slate-900 truncate">{srv.name}</h2>
                          {isLocal && (
                            <span className="px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 text-[10px] font-medium text-slate-700">
                              {t('fleet.localNode')}
                            </span>
                          )}
                          {srv.region && (
                            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-50 border border-slate-200 text-[10px] font-mono text-slate-500">
                              <Globe className="w-2.5 h-2.5" />
                              {srv.region}
                            </span>
                          )}
                          {mMeta && mState && (
                            <span
                              title={srv.maintenanceReason || mMeta.hint}
                              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-[10px] font-medium ${mMeta.badge}`}
                            >
                              {mState === 'draining' ? (
                                <PauseCircle className="w-3 h-3 shrink-0" />
                              ) : (
                                <Wrench className="w-3 h-3 shrink-0" />
                              )}
                              {mMeta.label}
                            </span>
                          )}
                        </div>
                        <div className="text-xs font-mono text-slate-500 mt-1 truncate">
                          {isLocal ? `127.0.0.1 (${t('fleet.controlPlane')})` : `${srv.user}@${srv.host}:${srv.port || 22}`}
                        </div>
                      </div>

                      <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium border shrink-0 ${st.badge}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${st.dot}`} />
                        {localizedStatusLabel(srv.status)}
                      </span>
                    </div>

                    {/* Aviso de drenaje / mantenimiento */}
                    {mMeta && mState && (
                      <div className="p-2.5 rounded-lg bg-amber-50 border border-amber-200 text-[11px] text-amber-900 flex items-start gap-2">
                        {mState === 'draining' ? (
                          <PauseCircle className="w-3.5 h-3.5 text-amber-600 shrink-0 mt-0.5" />
                        ) : (
                          <Wrench className="w-3.5 h-3.5 text-amber-600 shrink-0 mt-0.5" />
                        )}
                        <div className="min-w-0 leading-snug">
                          <span className="font-semibold">{mMeta.label}:</span>{' '}
                          <span>{srv.maintenanceReason || mMeta.hint}</span>
                        </div>
                      </div>
                    )}

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
                          {t('fleet.load')}: {metrics?.load1m != null ? metrics.load1m.toFixed(2) : '—'}
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
                          {t('fleet.free')}: {formatMb(metrics?.memoryAvailableMb)} / {formatMb(metrics?.memoryTotalMb)}
                        </div>
                      </div>

                      <div className="space-y-1">
                        <div className="flex items-center justify-between text-slate-500">
                          <span className="inline-flex items-center gap-1"><HardDrive className="w-3 h-3" /> {t('fleet.disk')}</span>
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
                          {t('fleet.free')}: {formatGb(metrics?.diskAvailableGb)} / {formatGb(metrics?.diskTotalGb)}
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
                            {srv.hostKeyFingerprint ? srv.hostKeyFingerprint : `${(srv.hostKeyPolicy || 'tofu').toUpperCase()} ${t('fleet.pending')}`}
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
                        {srv.projectsCount != null
                          ? `${srv.projectsCount} ${srv.projectsCount === 1 ? t('fleet.projectSingular') : t('fleet.projectPlural')}`
                          : (metrics?.os || t('fleet.ready'))}
                      </span>
                      <div className="flex items-center gap-1.5 flex-wrap justify-end">
                        <button
                          type="button"
                          onClick={() => openDirectPushModal(srv)}
                          className="culkibo-press inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer"
                        >
                          <Rocket className="w-3.5 h-3.5" />
                          <span>{t('fleet.directPushBtn')}</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => void handleProbe(srv)}
                          disabled={probingId === srv.id}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-700 cursor-pointer disabled:opacity-50"
                        >
                          <RefreshCw className={`w-3.5 h-3.5 ${probingId === srv.id ? 'animate-spin' : ''}`} />
                          <span>{t('fleet.probe')}</span>
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

          {/* Zero-Config WireGuard Fleet Mesh (10.88.0.0/24) Card */}
          <section className="culkibo-surface rounded-2xl overflow-hidden text-xs">
            <div className="px-5 py-4 border-b border-slate-200 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
              <div className="flex items-start gap-2.5 min-w-0">
                <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0 mt-0.5">
                  <Network className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('fleet.meshTitle')}</h2>
                    <span className="px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 font-mono text-[10px] font-semibold text-slate-700">
                      x25519 · AES-256-GCM
                    </span>
                    {mesh?.firewallGuard?.blocksPublicDbPorts !== false && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 text-[10px] font-semibold">
                        <ShieldCheck className="w-3 h-3" />
                        {t('fleet.meshUfwShield')}
                      </span>
                    )}
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('fleet.meshDesc')}</p>
                </div>
              </div>
              <div className="flex items-center gap-1.5 flex-wrap shrink-0">
                <button
                  type="button"
                  disabled={meshBusy !== null}
                  onClick={() => void handlePreviewMeshPlan()}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {meshBusy === 'plan' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Terminal className="w-3.5 h-3.5" />}
                  <span>{meshBusy === 'plan' ? t('fleet.meshPlanning') : t('fleet.meshPreview')}</span>
                </button>
                <button
                  type="button"
                  disabled={meshBusy !== null}
                  onClick={() => void handleDryRunRotateKey()}
                  className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
                >
                  {meshBusy === 'rotate' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RotateCw className="w-3.5 h-3.5" />}
                  <span>{meshBusy === 'rotate' ? t('fleet.meshRotating') : t('fleet.meshRotate')}</span>
                </button>
              </div>
            </div>

            {meshError && (
              <div className="mx-5 mt-3 p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{meshError}</div>
            )}

            {mesh && Array.isArray(mesh.peers) && mesh.peers.length > 0 ? (
              <div className="divide-y divide-slate-100">
                {mesh.peers.map((peer) => (
                  <div key={peer.nodeId} className="px-5 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-slate-900">{peer.name || peer.nodeId}</span>
                        <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[11px] font-semibold text-slate-800 tabular-nums">
                          {peer.meshIp}
                        </span>
                        <span className="font-mono text-[10px] text-slate-500">
                          {peer.endpoint || `:${peer.listenPort || 51820}`}
                        </span>
                      </div>
                      <div className="font-mono text-[11px] text-slate-500 mt-0.5 truncate" title={peer.publicKey}>
                        pub: {peer.publicKey ? `${peer.publicKey.slice(0, 22)}…` : '—'}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 text-[10px] font-medium">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                        {peer.status || 'ready'}
                      </span>
                      <button
                        type="button"
                        disabled={meshBusy !== null}
                        onClick={() => void handleDryRunRotateKey(peer.nodeId)}
                        className="px-2 py-1 rounded-md border border-slate-200 bg-white hover:bg-slate-50 text-[11px] text-slate-700 cursor-pointer disabled:opacity-50"
                      >
                        Rotate
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="px-5 py-4 text-slate-500">{t('fleet.meshEmpty')}</div>
            )}

            {meshPlan && (() => {
              const wgList = Array.isArray(meshPlan.wgConfigs) ? meshPlan.wgConfigs : null;
              const firstConfig =
                wgList?.[0]?.config ||
                wgList?.[0]?.wgConfig ||
                meshPlan.configs?.[0]?.wgConfig ||
                meshPlan.configs?.[0]?.config ||
                meshPlan.nodes?.[0]?.wgConfig ||
                meshPlan.nodes?.[0]?.config ||
                (meshPlan.wgConfigs && !Array.isArray(meshPlan.wgConfigs) ? Object.values(meshPlan.wgConfigs)[0] : null) ||
                '# wg0.conf ready (redacted private key)';
              const fp = meshPlan.firewallPlan;
              const fwRules = Array.isArray(meshPlan.firewallRules)
                ? meshPlan.firewallRules
                : Array.isArray(fp)
                  ? fp
                  : typeof fp === 'string'
                    ? fp.split('\n').filter(Boolean)
                    : fp && typeof fp === 'object'
                      ? [...(Array.isArray(fp.ufw) ? fp.ufw : []), ...(Array.isArray(fp.rules) ? fp.rules : [])]
                      : [];
              return (
                <div className="p-4 bg-slate-50 border-t border-slate-200 space-y-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-slate-900">wg0.conf Preview (0 plaintext private keys)</span>
                    <button type="button" onClick={() => setMeshPlan(null)} className="text-slate-400 hover:text-slate-700 cursor-pointer">
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                  <pre className="p-3 rounded-xl bg-slate-950 text-emerald-200 font-mono text-[11px] leading-relaxed overflow-x-auto max-h-48 border border-slate-800">
                    {firstConfig}
                  </pre>
                  {fwRules.length > 0 && (
                    <div className="font-mono text-[11px] text-slate-600 space-y-0.5">
                      {fwRules.slice(0, 4).map((r, i) => (
                        <div key={i} className="truncate">• {r}</div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })()}

            {meshRotate && (() => {
              const nextPub = meshRotate.newPublicKey || meshRotate.previewNewPublicKey || meshRotate.newFingerprint || meshRotate.previewNewFingerprint;
              const steps = Array.isArray(meshRotate.rolloutSteps) && meshRotate.rolloutSteps.length > 0
                ? meshRotate.rolloutSteps
                : Array.isArray(meshRotate.rolloutPlan)
                  ? meshRotate.rolloutPlan
                  : [];
              return (
                <div className="p-4 bg-slate-50 border-t border-slate-200 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-slate-900">
                      Dry-Run x25519 Key Rotation · {meshRotate.nodeId} (v{meshRotate.nextKeyVersion ?? meshRotate.keyVersion ?? 2})
                    </span>
                    <button type="button" onClick={() => setMeshRotate(null)} className="text-slate-400 hover:text-slate-700 cursor-pointer">
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                  {nextPub && (
                    <div className="font-mono text-[11px] text-emerald-700 truncate">
                      next pub: {nextPub}
                    </div>
                  )}
                  {steps.length > 0 && (
                    <ul className="list-disc list-inside text-[11px] text-slate-600 space-y-0.5">
                      {steps.map((step, idx) => <li key={idx}>{step}</li>)}
                    </ul>
                  )}
                </div>
              );
            })()}
          </section>

          {/* Cycle-10: Distributed Remote Build-Node Offloader */}
          <section className="culkibo-surface rounded-2xl overflow-hidden text-xs">
            <div className="px-5 py-4 border-b border-slate-200 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
              <div className="flex items-start gap-2.5 min-w-0">
                <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0 mt-0.5">
                  <Hammer className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('fleet.buildersTitle')}</h2>
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
                      <ShieldCheck className="w-3 h-3" />
                      {t('fleet.buildersMuxPinned')}
                    </span>
                    <span className="px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-600">
                      {t('fleet.buildersPreviewPill')}
                    </span>
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('fleet.buildersDesc')}</p>
                </div>
              </div>
              <button
                type="button"
                disabled={builderBusy}
                onClick={() => void handleTestPreviewOffload()}
                className="culkibo-press inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer shrink-0 disabled:opacity-50"
              >
                {builderBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                <span>{builderBusy ? t('fleet.buildersTesting') : t('fleet.buildersTestPreview')}</span>
              </button>
            </div>

            {builderError && (
              <div className="mx-5 mt-3 p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700">{builderError}</div>
            )}

            <div className="divide-y divide-slate-100">
              {(builders.length > 0
                ? builders
                : [
                    { id: 'bld_local_default', name: 'local-buildkit-node', host: '127.0.0.1', arch: 'linux/amd64', maxConcurrency: 2, activeBuilds: 0, allowPreviews: true, keepStorageGb: 20, sshMuxPinned: false },
                  ]
              ).map((b) => {
                const maxC = Math.max(1, b.maxConcurrency || 2);
                const act = Math.max(0, b.activeBuilds || 0);
                const pct = Math.min(100, Math.round((act / maxC) * 100));
                return (
                  <div key={b.id} className="px-5 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="min-w-0 space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-slate-900">{b.name}</span>
                        <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-700">
                          {b.arch}
                        </span>
                        {b.allowPreviews !== false && (
                          <span className="px-1.5 py-0.5 rounded bg-emerald-50 border border-emerald-200 font-mono text-[10px] text-emerald-700">
                            {t('fleet.buildersPreviewPill')}
                          </span>
                        )}
                        {(b.sshMuxPinned || act > 0) && (
                          <span className="px-1.5 py-0.5 rounded bg-amber-50 border border-amber-200 font-mono text-[10px] text-amber-800">
                            Mux Pinned ({act} active)
                          </span>
                        )}
                      </div>
                      <div className="font-mono text-[11px] text-slate-500">
                        {b.host} · cache keep {b.keepStorageGb ?? 20} GB
                      </div>
                    </div>
                    <div className="flex items-center gap-2.5 shrink-0 min-w-[150px] tabular-nums">
                      <div className="flex-1 h-1.5 rounded-full bg-slate-200 overflow-hidden">
                        <div className={`h-full rounded-full ${pct >= 90 ? 'bg-amber-500' : 'bg-emerald-500'}`} style={{ width: `${Math.max(8, pct)}%` }} />
                      </div>
                      <span className="font-mono text-[11px] text-slate-700 whitespace-nowrap">
                        {act} / {maxC} slots
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>

            {builderSchedule && (() => {
              const target = builderSchedule.directPushTarget;
              const targetLabel = typeof target === 'string'
                ? target
                : target && typeof target === 'object'
                  ? `${target.host || '127.0.0.1'}:${target.port ?? 22}${target.protocol ? ` (${target.protocol})` : ''}`
                  : '127.0.0.1:5055';
              return (
                <div className="px-5 py-3 bg-slate-50 border-t border-slate-200 flex flex-wrap items-center justify-between gap-2 font-mono text-[11px]">
                  <span className="text-emerald-700 inline-flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                    Leased {builderSchedule.leaseId || 'slot'} on {builderSchedule.builderName || builderSchedule.builderId} · DirectPush: {targetLabel}
                  </span>
                  <span className="text-slate-500">
                    canRecycleMux: {String(builderSchedule.canRecycleMux?.allowed ?? false)} ({builderSchedule.canRecycleMux?.reason || 'ACTIVE_BUILDS_IN_FLIGHT'})
                  </span>
                </div>
              );
            })()}
          </section>

          {/* Cycle-10: Self-Hosted AI / GPU & Local LLM Workload Planner */}
          <section className="culkibo-surface rounded-2xl p-5 space-y-4 text-xs">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
              <div className="flex items-start gap-2.5 min-w-0">
                <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0 mt-0.5">
                  <Sparkles className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('fleet.aiTitle')}</h2>
                    <span className="px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 font-mono text-[10px] font-semibold text-slate-700">
                      NVIDIA CDI
                    </span>
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
                      <Lock className="w-3 h-3" />
                      127.0.0.1 + Bearer Proxy
                    </span>
                    <span className="px-2 py-0.5 rounded-md bg-emerald-50 border border-emerald-200 font-mono text-[10px] text-emerald-700">
                      CVE-Safe Tags
                    </span>
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('fleet.aiDesc')}</p>
                </div>
              </div>
              <button
                type="button"
                disabled={aiBusy}
                onClick={() => void handlePlanAiWorkload()}
                className="culkibo-press inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer shrink-0 disabled:opacity-50"
              >
                {aiBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Cpu className="w-3.5 h-3.5" />}
                <span>{aiBusy ? t('fleet.aiGenerating') : t('fleet.aiGeneratePlan')}</span>
              </button>
            </div>

            {/* Interactive Runtime / Params / Quantization / VRAM / GPU Mode Selectors */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2.5">
              <label className="block">
                <span className="text-[11px] font-medium text-slate-600 block mb-1">Runtime</span>
                <select
                  value={aiRuntime}
                  onChange={(e) => setAiRuntime(e.target.value as 'ollama' | 'vllm' | 'llamacpp')}
                  className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                >
                  <option value="ollama">Ollama (0.17.4)</option>
                  <option value="vllm">vLLM (v0.21.2)</option>
                  <option value="llamacpp">llama.cpp CUDA</option>
                </select>
              </label>
              <label className="block">
                <span className="text-[11px] font-medium text-slate-600 block mb-1">Model Size</span>
                <select
                  value={aiParamsB}
                  onChange={(e) => setAiParamsB(Number(e.target.value))}
                  className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                >
                  {[7, 14, 32, 70].map((b) => (
                    <option key={b} value={b}>{b}B params</option>
                  ))}
                </select>
              </label>
              <label className="block">
                <span className="text-[11px] font-medium text-slate-600 block mb-1">Quantization</span>
                <select
                  value={aiQuant}
                  onChange={(e) => setAiQuant(e.target.value as 'Q4_K_M' | 'Q8_0' | 'FP16')}
                  className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                >
                  <option value="Q4_K_M">Q4_K_M</option>
                  <option value="Q8_0">Q8_0</option>
                  <option value="FP16">FP16</option>
                </select>
              </label>
              <label className="block">
                <span className="text-[11px] font-medium text-slate-600 block mb-1">GPU VRAM</span>
                <select
                  value={aiVramGb}
                  onChange={(e) => setAiVramGb(Number(e.target.value))}
                  className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                >
                  {[8, 16, 24, 48, 80].map((gb) => (
                    <option key={gb} value={gb}>{gb} GB VRAM</option>
                  ))}
                </select>
              </label>
              <label className="block col-span-2 sm:col-span-1">
                <span className="text-[11px] font-medium text-slate-600 block mb-1">GPU Passthrough</span>
                <select
                  value={aiGpuMode}
                  onChange={(e) => setAiGpuMode(e.target.value as 'cdi' | 'legacy' | 'cpu')}
                  className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                >
                  <option value="cdi">NVIDIA CDI</option>
                  <option value="legacy">Legacy --gpus all</option>
                  <option value="cpu">CPU Only</option>
                </select>
              </label>
            </div>

            {/* Live VRAM Pre-Flight Bar (weights + KV-cache + overhead) */}
            {aiVramEst && (() => {
              const reqGb = Number(aiVramEst.totalRequiredGb) || 0;
              const availGb = Math.max(1, Number(aiVramEst.availableVramGb ?? aiVramGb) || 24);
              const fits = aiVramEst.fits ?? (reqGb <= availGb);
              const barPct = Math.min(100, Math.round((reqGb / availGb) * 100));
              const activePreset = aiPresets.find((p) => p.id === aiRuntime);
              return (
                <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-2 tabular-nums">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`px-2 py-0.5 rounded-full font-mono text-[10px] font-semibold border ${
                        fits
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-red-50 text-red-700 border-red-200'
                      }`}>
                        {fits ? 'VRAM FITS' : 'VRAM OVERFLOW (BLOCKED)'}
                      </span>
                      <span className="font-mono font-semibold text-slate-900">
                        {reqGb.toFixed(1)} GB / {availGb} GB
                      </span>
                      <span className="font-mono text-[11px] text-slate-500">
                        weights {Number(aiVramEst.weightsGb).toFixed(1)} GB + KV-cache {Number(aiVramEst.kvCacheGb).toFixed(1)} GB + overhead {Number(aiVramEst.overheadGb).toFixed(1)} GB
                      </span>
                    </div>
                    {activePreset?.image && (
                      <span className="font-mono text-[10px] text-slate-500">{activePreset.image}</span>
                    )}
                  </div>
                  <div className="h-2 rounded-full bg-slate-200 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${fits ? (barPct > 85 ? 'bg-amber-500' : 'bg-emerald-500') : 'bg-red-600'}`}
                      style={{ width: `${Math.max(5, barPct)}%` }}
                    />
                  </div>
                </div>
              );
            })()}

            {aiError && (
              <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-800 font-mono text-[11px] flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 shrink-0" />
                <span>{aiError}</span>
              </div>
            )}

            {aiPlan && (() => {
              const vol = aiPlan.volumeMount;
              const volumeLabel = typeof vol === 'string'
                ? vol
                : vol && typeof vol === 'object'
                  ? `${vol.volumeName || 'culkibo_ai_cache'}:${vol.containerPath || '/models'}`
                  : 'persistent';
              const guard = aiPlan.caddyProxyGuard;
              const guardLabel = typeof guard === 'string'
                ? guard
                : guard && typeof guard === 'object'
                  ? `Caddy Bearer Auth Proxy -> ${guard.upstream || '127.0.0.1'} (${guard.rateLimitPerMinute ?? 60} req/m)`
                  : null;
              return (
                <div className="p-3.5 rounded-xl bg-slate-950 text-emerald-300 border border-slate-800 font-mono text-[11px] space-y-1.5 overflow-x-auto">
                  <div className="flex items-center justify-between gap-2 flex-wrap text-slate-400">
                    <span>Image: {aiPlan.image || aiPlan.imageTag || aiRuntime} · Cache: {volumeLabel}</span>
                    <span className="text-emerald-400">security.safe = {String(aiPlan.security?.safe ?? true)}</span>
                  </div>
                  {Array.isArray(aiPlan.dockerArgs) && aiPlan.dockerArgs.length > 0 && (
                    <div className="break-all">docker {aiPlan.dockerArgs.join(' ')}</div>
                  )}
                  {guardLabel && (
                    <div className="text-slate-300">{guardLabel}</div>
                  )}
                </div>
              );
            })()}
          </section>

          {/* Cycle-11: Stateful Volume Snapshot Cloner & Cross-VPS Migration Planner */}
          <section className="culkibo-surface rounded-2xl p-5 space-y-4 text-xs">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
              <div className="flex items-start gap-2.5 min-w-0">
                <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0 mt-0.5">
                  <HardDrive className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-sm font-semibold text-slate-900">{t('fleet.volTitle')}</h2>
                    <span className="px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 font-mono text-[10px] font-semibold text-slate-700">
                      tar --numeric-owner · SHA-256
                    </span>
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
                      <ShieldCheck className="w-3 h-3" />
                      CVE-2025-66213 Guard
                    </span>
                  </div>
                  <p className="text-slate-500 mt-0.5">{t('fleet.volDesc')}</p>
                </div>
              </div>
            </div>

            <form onSubmit={(e) => void handlePlanVolumeMigration(e)} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-12 gap-2.5 items-end">
              <label className="lg:col-span-3 block">
                <span className="text-[11px] font-medium text-slate-600 block mb-1">{t('fleet.volNameLabel')}</span>
                <input
                  type="text"
                  required
                  value={volName}
                  onChange={(e) => setVolName(e.target.value)}
                  placeholder="acme_postgres_data"
                  className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                />
              </label>
              <label className="lg:col-span-3 block">
                <span className="text-[11px] font-medium text-slate-600 block mb-1">{t('fleet.volMountLabel')}</span>
                <input
                  type="text"
                  required
                  value={volMount}
                  onChange={(e) => setVolMount(e.target.value)}
                  placeholder="/var/lib/postgresql/data"
                  className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                />
              </label>
              <label className="lg:col-span-2 block">
                <span className="text-[11px] font-medium text-slate-600 block mb-1">{t('fleet.volUidLabel')}</span>
                <input
                  type="text"
                  required
                  value={volUidGid}
                  onChange={(e) => setVolUidGid(e.target.value)}
                  placeholder="999:999"
                  className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900 tabular-nums"
                />
              </label>
              <label className="lg:col-span-2 block">
                <span className="text-[11px] font-medium text-slate-600 block mb-1">{t('fleet.volTargetLabel')}</span>
                <input
                  type="text"
                  required
                  value={volTargetHost}
                  onChange={(e) => setVolTargetHost(e.target.value)}
                  placeholder="198.51.100.42"
                  className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                />
              </label>
              <div className="lg:col-span-2">
                <button
                  type="submit"
                  disabled={volBusy}
                  className="culkibo-press w-full inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  {volBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                  <span>{volBusy ? t('fleet.volPlanning') : t('fleet.volPlanBtn')}</span>
                </button>
              </div>
            </form>

            {volError && (
              <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-800 font-mono text-[11px] flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 shrink-0" />
                <span>{volError}</span>
              </div>
            )}

            {activeVolPlan ? (() => {
              const phases = Array.isArray(activeVolPlan.plan?.phases)
                ? activeVolPlan.plan.phases
                : Array.isArray(activeVolPlan.phases)
                  ? activeVolPlan.phases
                  : [];
              return (
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2 p-3 rounded-xl bg-slate-50 border border-slate-200 font-mono text-[11px] tabular-nums">
                    <span className="font-semibold text-slate-900">
                      {activeVolPlan.volumeName} ({activeVolPlan.sourceHost} → {activeVolPlan.targetHost})
                    </span>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-700 text-[10px] font-semibold">
                        UID:GID {activeVolPlan.uid}:{activeVolPlan.gid}
                      </span>
                      <span className="text-slate-500 text-[10px]">
                        mount: {activeVolPlan.mountPath} · shell:false
                      </span>
                    </div>
                  </div>

                  {/* 4-Phase Zero-Shell Stepper */}
                  {phases.length > 0 && (
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
                      {phases.map((ph, idx) => {
                        const cmds = Array.isArray(ph.commands) ? ph.commands : [];
                        const firstCmd = cmds[0];
                        const cmdPreview = !firstCmd
                          ? (Array.isArray(ph.argv) ? ph.argv.join(' ') : '')
                          : Array.isArray(firstCmd)
                            ? firstCmd.join(' ')
                            : `${firstCmd.program} ${(Array.isArray(firstCmd.args) ? firstCmd.args : []).join(' ')}`;
                        return (
                          <div key={ph.id || idx} className="p-3 rounded-xl bg-white border border-slate-200 space-y-1.5">
                            <div className="flex items-center justify-between gap-1.5">
                              <span className="px-1.5 py-0.5 rounded bg-slate-900 text-white font-mono text-[10px] font-semibold tabular-nums">
                                Phase {ph.phase ?? idx + 1}
                              </span>
                              <span className="font-mono text-[10px] text-slate-400 truncate">{ph.id || ''}</span>
                            </div>
                            <div className="font-semibold text-slate-900 text-[11px] leading-snug">
                              {ph.title || ph.name || `Phase ${idx + 1}`}
                            </div>
                            {cmdPreview && (
                              <div className="p-1.5 rounded bg-slate-950 text-emerald-300 font-mono text-[10px] truncate" title={cmdPreview}>
                                {cmdPreview}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {volMigrations.length > 1 && (
                    <div className="text-[11px] font-mono text-slate-500">
                      {volMigrations.length} volume migration plans recorded (source volumes retained for instant rollback).
                    </div>
                  )}
                </div>
              );
            })() : (
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-slate-500 text-center">
                {t('fleet.volEmpty')}
              </div>
            )}
          </section>
        </>
      )}

      {tab === 'keys' && (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 bg-slate-50 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-slate-900">{t('fleet.vaultTitle')}</h2>
              <p className="text-xs text-slate-500">
                Private keys are encrypted at rest with AAD and never returned by API. Copy public key to <code className="font-mono">~/.ssh/authorized_keys</code>.
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

      {/* Modal: DirectPush (Zero-Registry SSH OCI v2 Layer-Delta) */}
      <Modal
        open={Boolean(directPushServer)}
        onClose={() => setDirectPushServer(null)}
        title={`${t('fleet.directPushTitle')}${directPushServer ? ` · ${directPushServer.name}` : ''}`}
        subtitle={t('fleet.directPushSubtitle')}
        maxWidthClass="max-w-2xl"
      >
        <div className="p-5 space-y-4 text-xs">
          <form onSubmit={(e) => void handlePlanDirectPush(e)} className="grid grid-cols-1 sm:grid-cols-12 gap-2.5 items-end">
            <label className="sm:col-span-6 block">
              <span className="font-medium text-slate-700 block mb-1">{t('fleet.directPushImage')}</span>
              <input
                type="text"
                required
                value={directPushImage}
                onChange={(e) => setDirectPushImage(e.target.value)}
                placeholder="my-app:latest"
                className="w-full px-3 py-2 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
              />
            </label>
            <label className="sm:col-span-3 block">
              <span className="font-medium text-slate-700 block mb-1">{t('fleet.directPushPort')}</span>
              <input
                type="number"
                min={1024}
                max={65535}
                value={directPushPort}
                onChange={(e) => setDirectPushPort(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-200 bg-white font-mono text-slate-900 tabular-nums"
              />
            </label>
            <div className="sm:col-span-3">
              <button
                type="submit"
                disabled={directPushLoading || !directPushImage.trim()}
                className="culkibo-press w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
              >
                {directPushLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Rocket className="w-3.5 h-3.5" />}
                <span>{directPushLoading ? t('fleet.directPushPlanning') : t('fleet.directPushGenerate')}</span>
              </button>
            </div>
          </form>

          {directPushError && (
            <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-700">{directPushError}</div>
          )}

          {directPushPlan && (
            <div className="space-y-3.5">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="px-2 py-0.5 rounded-md bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
                  {directPushPlan.protocol}
                </span>
                <span className="px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 text-slate-700 font-mono text-[10px]">
                  shell: false
                </span>
                <span className="px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 text-slate-700 font-mono text-[10px] tabular-nums">
                  127.0.0.1:{directPushPlan.tunnel.localPort} → {directPushPlan.tunnel.sshUser}@{directPushPlan.tunnel.sshHost}:{directPushPlan.tunnel.sshPort}
                </span>
              </div>

              <div className="p-3 rounded-xl bg-slate-950 text-slate-100 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold">
                    {t('fleet.directPushCliLabel')}
                  </span>
                  <button
                    type="button"
                    onClick={() =>
                      void copy(
                        `culkibo pussh ${directPushPlan.sourceImage} --server ${directPushPlan.serverId}`,
                        'dp-cli',
                        'culkibo pussh copied'
                      )
                    }
                    className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-medium cursor-pointer"
                  >
                    {copiedKey === 'dp-cli' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{t('fleet.directPushCopyCli')}</span>
                  </button>
                </div>
                <code className="block font-mono text-[11px] text-emerald-300 break-all">
                  culkibo pussh {directPushPlan.sourceImage} --server {directPushPlan.serverId}
                </code>
              </div>

              <div className="space-y-2">
                <div className="text-[11px] font-semibold text-slate-700">{t('fleet.directPushSteps')}</div>
                {directPushPlan.steps.map((st) => (
                  <div key={st.id} className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-medium text-slate-900">
                        {st.step}. {st.description}
                      </span>
                      <span className="px-1.5 py-0.5 rounded bg-white border border-slate-200 font-mono text-[10px] text-slate-500 shrink-0">
                        {st.skippedForLocal ? 'local skip' : 'argv'}
                      </span>
                    </div>
                    <code className="block font-mono text-[11px] text-slate-600 break-all">
                      {[st.bin, ...st.argv].join(' ')}
                    </code>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
};
