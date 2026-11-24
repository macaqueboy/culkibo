import React, { useState, useEffect, useCallback } from 'react';
import {
  Database,
  Plus,
  Play,
  Square,
  RefreshCw,
  Trash2,
  Eye,
  EyeOff,
  Copy,
  Check,
  ShieldAlert,
  Clock,
  CloudUpload,
  History,
  Lock,
  Globe,
  AlertTriangle,
  Server,
  Link2,
  Unlink,
  Rocket,
  Download,
  Upload,
  Stethoscope,
  Wrench,
  RotateCcw,
} from 'lucide-react';
import {
  api,
  type ManagedDatabase,
  type DbEngine,
  type DbBackup,
  type DbCredentials,
  type DbStorageConfig,
  type DbInspectResult,
} from '../lib/api';
import { copyToClipboard } from '../lib/clipboard';
import { Modal } from './Modal';
import { HelpTip } from './HelpTip';

interface Props {
  projectId: string;
  linkedDatabaseIds?: string[];
  onProjectChanged?: () => void;
  onOpenDeployments?: () => void;
  onOpenBackupSettings?: () => void;
  onNotify: (msg: string, type?: 'info' | 'success' | 'error') => void;
}

function getEnvVarKeyForEngine(engine: string): string {
  if (engine === 'valkey' || engine === 'redis') return 'REDIS_URL';
  if (engine === 'mongodb') return 'MONGODB_URI';
  return 'DATABASE_URL';
}

const HEALTH_STYLE: Record<string, { dot: string; label: string }> = {
  healthy: { dot: 'bg-emerald-500', label: 'Saludable' },
  starting: { dot: 'bg-amber-500 animate-pulse', label: 'Arrancando' },
  unhealthy: { dot: 'bg-red-500', label: 'Con fallos' },
  unknown: { dot: 'bg-slate-300', label: 'Desconocido' },
};

const CRON_PRESETS = [
  { value: '0 * * * *', label: 'Cada hora' },
  { value: '0 3 * * *', label: 'Cada día a las 03:00' },
  { value: '0 4 * * 0', label: 'Cada domingo a las 04:00' },
  { value: '0 5 1 * *', label: 'El día 1 de cada mes a las 05:00' },
];

function formatBytes(n: number): string {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('es-ES', { dateStyle: 'short', timeStyle: 'short' });
}

export const DatabasesPanel: React.FC<Props> = ({
  projectId,
  linkedDatabaseIds = [],
  onProjectChanged,
  onOpenDeployments,
  onOpenBackupSettings,
  onNotify,
}) => {
  const [databases, setDatabases] = useState<ManagedDatabase[]>([]);
  const [linkedIds, setLinkedIds] = useState<string[]>(linkedDatabaseIds);
  const [recentlyLinkedId, setRecentlyLinkedId] = useState<string | null>(null);
  const [engines, setEngines] = useState<DbEngine[]>([]);
  const [dockerOk, setDockerOk] = useState<boolean | null>(null);
  const [dockerReason, setDockerReason] = useState<string | null>(null);
  const [creating, setCreating] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [busyKeys, setBusyKeys] = useState<Set<string>>(() => new Set());
  const isBusy = (key: string) => busyKeys.has(key);

  const [creds, setCreds] = useState<Record<string, DbCredentials>>({});
  const [backups, setBackups] = useState<Record<string, DbBackup[]>>({});
  const [inspectResults, setInspectResults] = useState<Record<string, DbInspectResult>>({});
  const [undoRestore, setUndoRestore] = useState<{ dbId: string; dbName: string; safetyBackupId: string } | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  // Confirmaciones destructivas en Modal (P0-11)
  const [confirmRestore, setConfirmRestore] = useState<{ db: ManagedDatabase; backup: DbBackup } | null>(null);
  const [createSafetySnapshot, setCreateSafetySnapshot] = useState(true);
  const [confirmDelete, setConfirmDelete] = useState<{ db: ManagedDatabase; destroyData: boolean } | null>(null);

  const [storage, setStorage] = useState<DbStorageConfig>({ configured: false });
  const databasesRef = React.useRef<ManagedDatabase[]>([]);
  useEffect(() => {
    databasesRef.current = databases;
  }, [databases]);

  const load = useCallback(async () => {
    try {
      const [dbs, eng, status, store] = await Promise.all([
        api.getDatabases(projectId),
        api.getDbEngines(),
        api.getDbDockerStatus(),
        api.getDbStorage(),
      ]);
      setDatabases(dbs.databases);
      setEngines(eng.engines);
      setDockerOk(status.available);
      setDockerReason(status.reason);
      setStorage(store);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Error al cargar las bases de datos', 'error');
    }
  }, [projectId, onNotify]);

  useEffect(() => {
    let active = true;
    Promise.all([
      api.getDatabases(projectId),
      api.getDbEngines(),
      api.getDbDockerStatus(),
      api.getDbStorage(),
    ])
      .then(([dbs, eng, status, store]) => {
        if (!active) return;
        setDatabases(dbs.databases);
        setEngines(eng.engines);
        setDockerOk(status.available);
        setDockerReason(status.reason);
        setStorage(store);
      })
      .catch((err) => {
        if (!active) return;
        onNotify(err instanceof Error ? err.message : 'Error al cargar las bases de datos', 'error');
      });
    return () => { active = false; };
  }, [projectId, onNotify]);

  const needsHealthPoll = databases.some((d) => d.health === 'starting' || d.health === 'unknown');
  useEffect(() => {
    if (!needsHealthPoll) return;
    let disposed = false;
    const t = setInterval(async () => {
      const pending = databasesRef.current.filter((x) => x.health === 'starting' || x.health === 'unknown');
      for (const d of pending) {
        if (disposed) return;
        try { await api.refreshDatabaseHealth(d.id); } catch { /* silencio */ }
      }
      if (disposed) return;
      const dbs = await api.getDatabases(projectId).catch(() => null);
      if (!disposed && dbs) setDatabases(dbs.databases);
    }, 5000);
    return () => {
      disposed = true;
      clearInterval(t);
    };
  }, [needsHealthPoll, projectId]);

  const guard = async (key: string, fn: () => Promise<void>) => {
    setBusyKeys((prev) => {
      const next = new Set(prev);
      next.add(key);
      return next;
    });
    try {
      await fn();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Ha ocurrido un error', 'error');
    } finally {
      setBusyKeys((prev) => {
        const next = new Set(prev);
        next.delete(key);
        return next;
      });
    }
  };

  const handleCreate = async (engine: DbEngine) => {
    setCreating(engine.engine);
    try {
      const created = await api.createDatabase({ projectId, engine: engine.engine, name: engine.label });
      onNotify(`${engine.label} aprovisionado. Inyecta la cadena de conexión desde «Gestionar».`, 'success');
      await load();
      setExpanded(created.id);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Error al aprovisionar', 'error');
    } finally {
      setCreating(null);
    }
  };

  const copy = async (text: string, key: string) => {
    const ok = await copyToClipboard(text);
    if (!ok) return;
    setCopied(key);
    window.setTimeout(() => setCopied(null), 1800);
  };

  const toggleCredentials = (db: ManagedDatabase) => guard(`creds-${db.id}`, async () => {
    if (creds[db.id]) {
      const next = { ...creds };
      delete next[db.id];
      setCreds(next);
      return;
    }
    setCreds({ ...creds, [db.id]: await api.getDatabaseCredentials(db.id) });
  });

  const loadBackups = (db: ManagedDatabase) => guard(`bk-${db.id}`, async () => {
    setBackups({ ...backups, [db.id]: (await api.getDatabaseBackups(db.id)).backups });
  });

  const handleExpose = (db: ManagedDatabase, enabled: boolean) => guard(`exp-${db.id}`, async () => {
    const payload = enabled
      ? { enabled: true, ...(db.exposure.hostPort ? { hostPort: db.exposure.hostPort } : {}) }
      : { enabled: false };
    const res = await api.setDatabaseExposure(db.id, payload);
    if (res.warning) onNotify(res.warning, 'info');
    await load();
  });

  const [prevLinkedProp, setPrevLinkedProp] = useState(linkedDatabaseIds);
  if (linkedDatabaseIds !== prevLinkedProp) {
    setPrevLinkedProp(linkedDatabaseIds);
    setLinkedIds(linkedDatabaseIds);
  }

  const handleToggleLink = (db: ManagedDatabase) => guard(`lnk-${db.id}`, async () => {
    const isLinked = linkedIds.includes(db.id);
    if (isLinked) {
      const res = await api.unlinkProjectDatabase(projectId, db.id);
      setLinkedIds(res.project?.linkedDatabaseIds || linkedIds.filter((id) => id !== db.id));
      if (recentlyLinkedId === db.id) setRecentlyLinkedId(null);
      onNotify(`${db.name} desvinculada del proyecto`, 'info');
    } else {
      const res = await api.linkProjectDatabase(projectId, db.id);
      setLinkedIds(res.project?.linkedDatabaseIds || [...linkedIds, db.id]);
      setRecentlyLinkedId(db.id);
      onNotify(res.note || `${db.name} vinculada en red aislada. Redespliega para inyectar credenciales en runtime.`, 'success');
    }
    onProjectChanged?.();
  });

  const handleInjectEnv = (db: ManagedDatabase) => guard(`inj-${db.id}`, async () => {
    const c = creds[db.id] || await api.getDatabaseCredentials(db.id);
    if (!creds[db.id]) setCreds((prev) => ({ ...prev, [db.id]: c }));
    const project = await api.getProject(projectId);
    const key = getEnvVarKeyForEngine(db.engine);
    const nextEnv = { ...(project.envVars || {}), [key]: c.internalConnectionString };
    await api.updateProject(projectId, { envVars: nextEnv });
    onNotify(`Variable ${key} inyectada en el proyecto`, 'success');
  });

  const handleInspectDb = (db: ManagedDatabase) => guard(`ins-${db.id}`, async () => {
    const res = await api.inspectDatabase(db.id);
    setInspectResults((prev) => ({ ...prev, [db.id]: res }));
    setExpanded(db.id);
    onNotify(
      res.reachable
        ? `${db.name} responde en ${res.latencyMs ?? 0} ms${res.version ? ` (${res.version})` : ''}`
        : (res.error || `${db.name} no responde en este momento`),
      res.reachable ? 'success' : 'error'
    );
  });

  const handleRecoverDb = (db: ManagedDatabase) => guard(`rec-${db.id}`, async () => {
    await api.recoverDatabase(db.id);
    onNotify(`Contenedor de ${db.name} recreado conservando el volumen de datos`, 'success');
    await load();
  });

  const handleDownloadBackup = (db: ManagedDatabase, b: DbBackup) => guard(`dl-${b.id}`, async () => {
    const { blob, fileName } = await api.downloadDatabaseBackupBlob(db.id, b.id);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
  });

  const handleDeleteBackup = (db: ManagedDatabase, b: DbBackup) => guard(`delbk-${b.id}`, async () => {
    await api.deleteDatabaseBackup(db.id, b.id, false);
    onNotify('Copia local eliminada', 'info');
    await load();
    setBackups((prev) => ({ ...prev, [db.id]: (prev[db.id] || []).filter((x) => x.id !== b.id) }));
  });

  const handleUploadBackup = (db: ManagedDatabase, file: File) => guard(`up-${db.id}`, async () => {
    await api.uploadDatabaseBackup(db.id, file, { restore: false });
    onNotify(`Copia «${file.name}» subida y verificada. Ya puedes restaurarla abajo.`, 'success');
    await load();
    setBackups((prev) => ({ ...prev, [db.id]: [] }));
    const refreshed = await api.getDatabaseBackups(db.id);
    setBackups((prev) => ({ ...prev, [db.id]: refreshed.backups }));
  });

  return (
    <div className="space-y-5">
      {dockerOk === false && (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex items-start gap-3">
          <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
          <div className="text-xs">
            <p className="font-semibold text-amber-900">Docker no está disponible</p>
            <p className="text-amber-800 mt-0.5">
              {dockerReason || 'Las bases de datos gestionadas necesitan Docker en marcha.'}
            </p>
          </div>
        </div>
      )}

      {/* Aprovisionar */}
      <div className="bg-white p-5 rounded-xl border border-slate-200">
        <h3 className="font-semibold text-slate-900 flex items-center gap-2 text-base">
          <Database className="w-4 h-4 text-slate-600" /> Aprovisionar base de datos
        </h3>
        <p className="text-xs text-slate-500 mt-1 mb-4">
          Contraseña aleatoria cifrada, volumen persistente, red privada del proyecto, límites de recursos y sonda de salud.{' '}
          <strong className="text-slate-700 font-medium">Sin puertos expuestos por defecto.</strong>
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
          {engines.map((e) => (
            <button
              key={e.engine}
              type="button"
              disabled={dockerOk === false || creating !== null}
              onClick={() => void handleCreate(e)}
              className="text-left border border-slate-200 rounded-xl p-3.5 hover:border-slate-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed bg-white cursor-pointer"
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-sm text-slate-900">{e.label}</span>
                {creating === e.engine
                  ? <RefreshCw className="w-3.5 h-3.5 text-slate-500 animate-spin" />
                  : <Plus className="w-3.5 h-3.5 text-slate-400" />}
              </div>
              <div className="font-mono text-xs text-slate-500 mt-1 truncate">{e.image}</div>
              <div className="text-[11px] text-slate-400 mt-0.5">{e.licence}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Listado */}
      {databases.length === 0 && (
        <div className="bg-white p-8 rounded-xl border border-slate-200 text-center text-slate-500 text-xs">
          Este proyecto todavía no tiene bases de datos gestionadas.
        </div>
      )}

      {databases.map((db) => {
        const health = HEALTH_STYLE[db.health] || HEALTH_STYLE.unknown;
        const open = expanded === db.id;
        const isLinked = linkedIds.includes(db.id);
        return (
          <div key={db.id} className="bg-white rounded-xl border border-slate-200 overflow-hidden">
            <div className="p-5 flex flex-col md:flex-row md:items-center gap-4">
              <div className="flex items-center gap-3 flex-1 min-w-0">
                <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center shrink-0">
                  <Database className="w-4 h-4 text-slate-600" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-semibold text-sm text-slate-900 truncate">{db.name}</span>
                    <span className="text-[11px] bg-slate-100 text-slate-600 px-2 py-0.5 rounded">{db.engineLabel}</span>
                    {isLinked && (
                      <span className="inline-flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">
                        <Link2 className="w-3 h-3" /> Conectada al proyecto
                      </span>
                    )}
                  </div>
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500 mt-1 tabular-nums">
                    <span className="flex items-center gap-1.5">
                      <span className={`w-1.5 h-1.5 rounded-full ${health.dot}`} /> {health.label}
                    </span>
                    <span className="font-mono truncate max-w-[200px]">{db.containerName}</span>
                    <span>{db.memoryMb} MB · {db.cpus} vCPU</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2 flex-wrap shrink-0">
                {(db.status === 'missing' || db.health === 'unhealthy') && (
                  <button
                    type="button"
                    onClick={() => void handleRecoverDb(db)}
                    disabled={isBusy(`rec-${db.id}`)}
                    className="inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1.5 rounded-lg border border-amber-300 bg-amber-50 hover:bg-amber-100 text-amber-900 cursor-pointer disabled:opacity-50"
                  >
                    <Wrench className="w-3.5 h-3.5" />
                    <span>{isBusy(`rec-${db.id}`) ? 'Recreando…' : 'Recrear contenedor'}</span>
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => void handleInspectDb(db)}
                  disabled={isBusy(`ins-${db.id}`)}
                  title="Probar conexión, versión y tamaño real de la base de datos"
                  className="inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 cursor-pointer disabled:opacity-50"
                >
                  <Stethoscope className="w-3.5 h-3.5 text-slate-500" />
                  <span>{isBusy(`ins-${db.id}`) ? 'Probando…' : 'Inspeccionar'}</span>
                </button>
                <button
                  type="button"
                  onClick={() => void handleToggleLink(db)}
                  disabled={isBusy(`lnk-${db.id}`)}
                  className={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1.5 rounded-lg border cursor-pointer disabled:opacity-50 ${
                    isLinked
                      ? 'bg-white hover:bg-slate-50 text-slate-600 border-slate-200'
                      : 'bg-slate-900 hover:bg-slate-800 text-white border-slate-900'
                  }`}
                >
                  {isLinked ? <Unlink className="w-3.5 h-3.5" /> : <Link2 className="w-3.5 h-3.5" />}
                  <span>{isLinked ? 'Desvincular' : 'Enlazar al proyecto'}</span>
                </button>
                {db.exposure.enabled ? (
                  <span className={`text-xs px-2 py-1 rounded-md font-mono flex items-center gap-1 tabular-nums ${
                    db.exposure.bindAddress === '0.0.0.0'
                      ? 'bg-red-50 text-red-700 border border-red-200'
                      : 'bg-amber-50 text-amber-800 border border-amber-200'
                  }`}>
                    <Globe className="w-3 h-3" /> {db.exposure.bindAddress}:{db.exposure.hostPort}
                  </span>
                ) : (
                  <span className="text-xs px-2 py-1 rounded-md bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1">
                    <Lock className="w-3 h-3" /> Solo red privada
                  </span>
                )}
                <button
                  type="button"
                  onClick={() => void guard(`ctl-${db.id}`, async () => {
                    await api.controlDatabase(db.id, db.status === 'running' ? 'stop' : 'start');
                    await load();
                  })}
                  disabled={isBusy(`ctl-${db.id}`)}
                  aria-label={db.status === 'running' ? 'Detener base de datos' : 'Iniciar base de datos'}
                  className="p-2 rounded-lg border border-slate-200 hover:bg-slate-50 text-slate-600 disabled:opacity-50 cursor-pointer"
                  title={db.status === 'running' ? 'Detener' : 'Iniciar'}
                >
                  {db.status === 'running' ? <Square className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                </button>
                <button
                  type="button"
                  onClick={() => { setExpanded(open ? null : db.id); if (!open) void loadBackups(db); }}
                  className="text-xs font-medium text-slate-700 hover:text-slate-900 border border-slate-200 px-3 py-1.5 rounded-lg cursor-pointer"
                >
                  {open ? 'Cerrar' : 'Gestionar'}
                </button>
              </div>
            </div>

            {recentlyLinkedId === db.id && isLinked && (
              <div className="px-5 py-2.5 bg-emerald-50/70 border-t border-emerald-200 flex flex-wrap items-center justify-between gap-2 text-xs text-emerald-900">
                <span>
                  Red aislada y variable <code className="font-mono">{getEnvVarKeyForEngine(db.engine)}</code> preparadas en runtime (sin guardar contraseñas en disco).
                </span>
                {onOpenDeployments && (
                  <button
                    type="button"
                    onClick={onOpenDeployments}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-emerald-700 hover:bg-emerald-800 text-white font-medium cursor-pointer shrink-0"
                  >
                    <Rocket className="w-3 h-3" /> Redesplegar ahora
                  </button>
                )}
              </div>
            )}

            {undoRestore && undoRestore.dbId === db.id && (
              <div className="px-5 py-2.5 bg-amber-50 border-t border-amber-200 flex flex-wrap items-center justify-between gap-2 text-xs text-amber-900">
                <span>Restauración aplicada. Se creó un snapshot de seguridad previo por si necesitas volver atrás.</span>
                <button
                  type="button"
                  disabled={isBusy(`res-${db.id}`)}
                  onClick={() => void guard(`res-${db.id}`, async () => {
                    await api.restoreDatabase(db.id, { backupId: undoRestore.safetyBackupId, createSafetySnapshot: false });
                    setUndoRestore(null);
                    onNotify('Estado previo restaurado desde el snapshot de seguridad', 'success');
                    await load();
                  })}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-white border border-amber-300 text-amber-950 font-medium hover:bg-amber-100 cursor-pointer shrink-0"
                >
                  <RotateCcw className="w-3 h-3" /> Deshacer restauración
                </button>
              </div>
            )}

            {open && (
              <div className="border-t border-slate-200 bg-slate-50/60 p-5 space-y-5">
                {inspectResults[db.id] && (
                  <section className="bg-white border border-slate-200 rounded-xl p-4 space-y-2.5 text-xs">
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <span className="font-semibold text-slate-900 flex items-center gap-1.5">
                        <Stethoscope className="w-3.5 h-3.5 text-slate-500" />
                        Inspección en directo
                      </span>
                      <span className={`px-2 py-0.5 rounded-full text-[11px] font-medium border tabular-nums ${
                        inspectResults[db.id].reachable
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-red-50 text-red-700 border-red-200'
                      }`}>
                        {inspectResults[db.id].reachable ? `Conectada · ${inspectResults[db.id].latencyMs ?? 0} ms` : 'Sin respuesta'}
                      </span>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
                      <div>
                        <div className="text-slate-400">Versión</div>
                        <div className="font-mono text-slate-800 truncate">{inspectResults[db.id].version || '—'}</div>
                      </div>
                      <div>
                        <div className="text-slate-400">Tamaño BD</div>
                        <div className="font-mono text-slate-800 tabular-nums">{inspectResults[db.id].databaseSizeHuman || '—'}</div>
                      </div>
                      <div>
                        <div className="text-slate-400">Volumen en disco</div>
                        <div className="font-mono text-slate-800 tabular-nums">{inspectResults[db.id].volumeSizeHuman || '—'}</div>
                      </div>
                      <div>
                        <div className="text-slate-400">Tablas / Claves</div>
                        <div className="font-mono text-slate-800 tabular-nums">
                          {inspectResults[db.id].keyCount != null
                            ? `${inspectResults[db.id].keyCount} claves`
                            : inspectResults[db.id].topTables
                              ? `${inspectResults[db.id].topTables?.length} tablas`
                              : '—'}
                        </div>
                      </div>
                    </div>
                  </section>
                )}

                {/* Conexión */}
                <section>
                  <h4 className="font-semibold text-slate-800 text-xs mb-1.5 flex items-center gap-1.5">
                    <Server className="w-3.5 h-3.5 text-slate-500" /> Conexión interna
                    <HelpTip title="Enlazar vs Inyectar variable">
                      <p><strong>Enlazar al proyecto:</strong> conecta la red Docker e inyecta la URL automáticamente en cada despliegue sin guardar contraseñas en texto claro.</p>
                      <p><strong>Inyectar variable:</strong> copia la cadena directamente a la pestaña Variables si necesitas editarla o usarla en pruebas locales.</p>
                    </HelpTip>
                  </h4>
                  <p className="text-xs text-slate-500 mb-2">
                    Accesible por nombre de contenedor en la red <code className="font-mono">{db.networkName}</code>. La contraseña solo se descifra al pedirla.
                  </p>
                  <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                    <code className="flex-1 bg-white border border-slate-200 rounded-lg px-3 py-2 text-xs font-mono text-slate-700 overflow-x-auto whitespace-nowrap">
                      {creds[db.id] ? creds[db.id].internalConnectionString : db.connectionTemplate}
                    </code>
                    <div className="flex items-center gap-1.5 shrink-0">
                      <button
                        type="button"
                        onClick={() => void toggleCredentials(db)}
                        disabled={isBusy(`creds-${db.id}`)}
                        aria-label={creds[db.id] ? 'Ocultar credenciales' : 'Mostrar credenciales'}
                        className="p-2 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-600 disabled:opacity-50 cursor-pointer"
                        title={creds[db.id] ? 'Ocultar credenciales' : 'Mostrar credenciales'}
                      >
                        {creds[db.id] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                      {creds[db.id] && (
                        <button
                          type="button"
                          onClick={() => void copy(creds[db.id].internalConnectionString, `conn-${db.id}`)}
                          aria-label="Copiar cadena de conexión"
                          className="p-2 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-600 cursor-pointer"
                          title="Copiar"
                        >
                          {copied === `conn-${db.id}` ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => void handleInjectEnv(db)}
                        disabled={isBusy(`inj-${db.id}`)}
                        className="px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium shrink-0 cursor-pointer disabled:opacity-50"
                      >
                        {isBusy(`inj-${db.id}`) ? 'Inyectando…' : `Inyectar ${getEnvVarKeyForEngine(db.engine)}`}
                      </button>
                    </div>
                  </div>
                </section>

                {/* Exposición */}
                <section>
                  <h4 className="font-semibold text-slate-800 text-xs mb-1.5 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-slate-500" /> Acceso local desde el host
                  </h4>
                  <div className="bg-white border border-slate-200 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <p className="text-xs text-slate-600 leading-relaxed">
                      Culkibo publica solo en <code className="font-mono">127.0.0.1</code> para que las reglas de Docker no omitan el cortafuegos del servidor. Para acceso externo usa un túnel SSH.
                    </p>
                    <button
                      type="button"
                      onClick={() => void handleExpose(db, !db.exposure.enabled)}
                      disabled={isBusy(`exp-${db.id}`)}
                      className={`shrink-0 text-xs font-medium px-3 py-1.5 rounded-lg border disabled:opacity-50 cursor-pointer ${
                        db.exposure.enabled
                          ? 'border-slate-200 text-slate-700 bg-white hover:bg-slate-50'
                          : 'border-slate-900 bg-slate-900 text-white hover:bg-slate-800'
                      }`}
                    >
                      {db.exposure.enabled ? 'Dejar de publicar' : 'Publicar en 127.0.0.1'}
                    </button>
                  </div>
                </section>

                {/* Copias programadas */}
                <section>
                  <h4 className="font-semibold text-slate-800 text-xs mb-1.5 flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-slate-500" /> Copias programadas
                  </h4>
                  <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3">
                    <div className="flex flex-wrap items-center gap-2.5">
                      <select
                        aria-label="Frecuencia de copias"
                        value={db.schedule.cron}
                        onChange={(e) => void guard(`sch-${db.id}`, async () => {
                          await api.setDatabaseSchedule(db.id, { enabled: db.schedule.enabled, cron: e.target.value });
                          await load();
                        })}
                        className="text-xs border border-slate-200 rounded-lg px-2.5 py-1.5 bg-white text-slate-700"
                      >
                        {CRON_PRESETS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
                        {!CRON_PRESETS.some((p) => p.value === db.schedule.cron) && (
                          <option value={db.schedule.cron}>{db.schedule.cron}</option>
                        )}
                      </select>
                      <button
                        type="button"
                        onClick={() => void guard(`sch-${db.id}`, async () => {
                          await api.setDatabaseSchedule(db.id, { enabled: !db.schedule.enabled, cron: db.schedule.cron });
                          await load();
                        })}
                        disabled={isBusy(`sch-${db.id}`)}
                        className={`text-xs font-medium px-3 py-1.5 rounded-lg border disabled:opacity-50 cursor-pointer ${
                          db.schedule.enabled
                            ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
                            : 'border-slate-200 bg-white text-slate-600'
                        }`}
                      >
                        {db.schedule.enabled ? 'Programación activa' : 'Programación desactivada'}
                      </button>
                      <span className="text-xs text-slate-500 tabular-nums">
                        Próxima: <strong className="text-slate-700">{formatDate(db.schedule.nextRunAt)}</strong>
                        {' '}· Última: {formatDate(db.schedule.lastRunAt)}
                        {db.schedule.lastStatus === 'error' && <span className="text-red-600"> (falló)</span>}
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-slate-100">
                      <span className="text-xs text-slate-500">Conservar</span>
                      {([
                        { k: 'hourly' as const, label: 'horarias', max: 168 },
                        { k: 'daily' as const, label: 'diarias', max: 365 },
                        { k: 'weekly' as const, label: 'semanales', max: 260 },
                      ]).map(({ k, label, max }) => (
                        <label key={k} className="flex items-center gap-1.5 text-xs text-slate-600">
                          <input
                            type="number"
                            min={0}
                            max={max}
                            defaultValue={db.retention[k] ?? 0}
                            onBlur={(e) => {
                              const parsed = parseInt(e.target.value, 10) || 0;
                              if (parsed === (db.retention[k] ?? 0)) return;
                              void guard(`ret-${db.id}`, async () => {
                                await api.setDatabaseRetention(db.id, { ...db.retention, [k]: parsed });
                                await load();
                              });
                            }}
                            className="w-16 border border-slate-200 rounded-lg px-2 py-1 text-slate-700 font-mono tabular-nums"
                          />
                          {label}
                        </label>
                      ))}
                    </div>
                  </div>
                </section>

                {/* Historial de copias + Subir / Descargar / Eliminar */}
                <section>
                  <div className="flex items-center justify-between gap-2 flex-wrap mb-2">
                    <h4 className="font-semibold text-slate-800 text-xs flex items-center gap-1.5 tabular-nums">
                      <History className="w-3.5 h-3.5 text-slate-500" /> Copias ({db.backupsCount})
                    </h4>
                    <div className="flex items-center gap-2">
                      <label className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-200 px-3 py-1.5 rounded-lg cursor-pointer">
                        <Upload className="w-3.5 h-3.5 text-slate-500" />
                        <span>{isBusy(`up-${db.id}`) ? 'Subiendo…' : 'Subir copia (.sql/.gz)'}</span>
                        <input
                          type="file"
                          accept=".sql,.gz,.dump,.archive,.rdb,.bak,.zip"
                          disabled={isBusy(`up-${db.id}`)}
                          className="hidden"
                          onChange={(e) => {
                            const f = e.target.files?.[0];
                            if (f) void handleUploadBackup(db, f);
                            e.target.value = '';
                          }}
                        />
                      </label>
                      <button
                        type="button"
                        onClick={() => void guard(`run-${db.id}`, async () => {
                          await api.runDatabaseBackup(db.id);
                          onNotify('Copia de seguridad completada', 'success');
                          await load();
                          setBackups({ ...backups, [db.id]: (await api.getDatabaseBackups(db.id)).backups });
                        })}
                        disabled={isBusy(`run-${db.id}`)}
                        className="text-xs font-medium bg-slate-900 text-white px-3 py-1.5 rounded-lg hover:bg-slate-800 disabled:opacity-50 flex items-center gap-1.5 cursor-pointer"
                      >
                        {isBusy(`run-${db.id}`)
                          ? <><RefreshCw className="w-3.5 h-3.5 animate-spin" /> Copiando…</>
                          : <><CloudUpload className="w-3.5 h-3.5" /> Copiar ahora</>}
                      </button>
                    </div>
                  </div>
                  <div className="border border-slate-200 rounded-xl overflow-x-auto bg-white">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="bg-slate-50 border-b border-slate-200 text-[11px] font-medium text-slate-500">
                          <th className="py-2.5 px-3.5">Fecha</th>
                          <th className="py-2.5 px-3">Tamaño</th>
                          <th className="py-2.5 px-3">Origen</th>
                          <th className="py-2.5 px-3">Destino</th>
                          <th className="py-2.5 px-3.5 text-right">Acciones</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 text-xs">
                        {(backups[db.id] || []).length === 0 ? (
                          <tr>
                            <td colSpan={5} className="p-6 text-center text-slate-500">Todavía no hay copias.</td>
                          </tr>
                        ) : (
                          (backups[db.id] || []).map((b) => (
                            <tr key={b.id}>
                              <td className="py-2.5 px-3.5 text-slate-700 tabular-nums whitespace-nowrap">{formatDate(b.createdAt)}</td>
                              <td className="py-2.5 px-3 text-slate-500 font-mono tabular-nums whitespace-nowrap">{formatBytes(b.sizeBytes)}</td>
                              <td className="py-2.5 px-3 text-slate-500 whitespace-nowrap">
                                {b.trigger === 'scheduled'
                                  ? 'Programada'
                                  : b.trigger === 'catch-up'
                                    ? 'Recuperada'
                                    : b.trigger === 'pre-restore'
                                      ? 'Seguridad'
                                      : b.trigger === 'upload'
                                        ? 'Subida'
                                        : 'Manual'}
                              </td>
                              <td className="py-2.5 px-3 whitespace-nowrap">
                                {b.localAvailable && <span className="text-slate-600">Disco</span>}
                                {b.localAvailable && b.remoteAvailable && <span className="text-slate-300"> / </span>}
                                {b.remoteAvailable && <span className="text-emerald-700">Bucket</span>}
                              </td>
                              <td className="py-2.5 px-3.5 text-right whitespace-nowrap">
                                <div className="inline-flex items-center gap-1.5">
                                  {b.localAvailable && (
                                    <button
                                      type="button"
                                      onClick={() => void handleDownloadBackup(db, b)}
                                      disabled={isBusy(`dl-${b.id}`)}
                                      aria-label="Descargar copia"
                                      title="Descargar copia al navegador"
                                      className="p-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-600 cursor-pointer disabled:opacity-50"
                                    >
                                      <Download className="w-3.5 h-3.5" />
                                    </button>
                                  )}
                                  <button
                                    type="button"
                                    onClick={() => {
                                      setCreateSafetySnapshot(true);
                                      setConfirmRestore({ db, backup: b });
                                    }}
                                    disabled={isBusy(`res-${db.id}`)}
                                    className="text-xs font-medium text-slate-700 hover:text-slate-900 border border-slate-200 px-2.5 py-1 rounded-lg disabled:opacity-50 cursor-pointer"
                                  >
                                    Restaurar
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => void handleDeleteBackup(db, b)}
                                    disabled={isBusy(`delbk-${b.id}`)}
                                    aria-label="Eliminar copia local"
                                    title="Eliminar copia local"
                                    className="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 cursor-pointer disabled:opacity-50"
                                  >
                                    <Trash2 className="w-3.5 h-3.5" />
                                  </button>
                                </div>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </section>

                {/* Eliminar */}
                <section className="pt-3 border-t border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <p className="text-xs text-slate-500">
                    Puedes eliminar solo el contenedor conservando el volumen, o destruir también los datos y copias.
                  </p>
                  <div className="flex flex-wrap gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => setConfirmDelete({ db, destroyData: false })}
                      disabled={isBusy(`del-${db.id}`)}
                      className="text-xs font-medium text-slate-700 border border-slate-200 bg-white px-3 py-1.5 rounded-lg hover:bg-slate-50 disabled:opacity-50 cursor-pointer"
                    >
                      Eliminar contenedor
                    </button>
                    <button
                      type="button"
                      onClick={() => setConfirmDelete({ db, destroyData: true })}
                      disabled={isBusy(`del-${db.id}`)}
                      className="text-xs font-medium text-red-700 border border-red-200 bg-red-50 px-3 py-1.5 rounded-lg hover:bg-red-100 disabled:opacity-50 inline-flex items-center gap-1.5 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" /> Eliminar y borrar datos
                    </button>
                  </div>
                </section>
              </div>
            )}
          </div>
        );
      })}

      {/* Franja compacta de Almacenamiento S3 / R2 global (configuración unificada en Ajustes → Backups y DR) */}
      <div className="bg-white p-4 rounded-xl border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-600 shrink-0">
            <CloudUpload className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <div className="font-semibold text-slate-900">
              {storage.configured
                ? `Copias externas activas en S3 / R2 (${storage.bucket})`
                : 'Copias externas S3 / R2 sin configurar'}
            </div>
            <p className="text-slate-500 truncate mt-0.5">
              {storage.configured
                ? `${storage.endpoint} · Región ${storage.region || 'auto'}`
                : 'Ahora las copias se guardan en disco local. Configura un bucket S3/R2 global y snapshots completos en Ajustes.'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {storage.configured && (
            <button
              type="button"
              onClick={() => void guard('s3test', async () => {
                const r = await api.testDbStorage();
                onNotify(`Conexión correcta con ${r.bucket}`, 'success');
              })}
              disabled={isBusy('s3test')}
              className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
            >
              Probar S3
            </button>
          )}
          {onOpenBackupSettings && (
            <button
              type="button"
              onClick={onOpenBackupSettings}
              className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer"
            >
              {storage.configured ? 'Gestionar en Backups y DR' : 'Configurar S3 / Backups'}
            </button>
          )}
        </div>
      </div>

      {/* Modal: Confirmar restauración con snapshot previo automático */}
      <Modal
        open={Boolean(confirmRestore)}
        onClose={() => setConfirmRestore(null)}
        title="Restaurar copia de seguridad"
        subtitle="Esta operación sobrescribirá los datos actuales de la base de datos."
        maxWidthClass="max-w-md"
      >
        {confirmRestore && (
          <div className="p-5 space-y-4">
            <div className="p-3.5 rounded-xl bg-amber-50 border border-amber-200 text-xs text-amber-900 space-y-1">
              <div className="font-semibold">{confirmRestore.db.name} ({confirmRestore.db.engineLabel})</div>
              <div>
                Copia del <strong>{formatDate(confirmRestore.backup.createdAt)}</strong> ({formatBytes(confirmRestore.backup.sizeBytes)})
              </div>
              <div className="text-amber-800">
                Los cambios posteriores a esa fecha se sustituirán por el contenido de este volcado.
              </div>
            </div>
            <label className="flex items-start gap-2 text-xs text-slate-700 cursor-pointer">
              <input
                type="checkbox"
                checked={createSafetySnapshot}
                onChange={(e) => setCreateSafetySnapshot(e.target.checked)}
                className="mt-0.5 rounded border-slate-300 accent-slate-900"
              />
              <span>
                Crear copia de seguridad automática antes de restaurar (recomendado para poder deshacer en 1 clic).
              </span>
            </label>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmRestore(null)}
                className="px-3.5 py-2 text-xs font-medium text-slate-600 border border-slate-200 rounded-lg hover:bg-slate-50 cursor-pointer"
              >
                Cancelar
              </button>
              <button
                type="button"
                onClick={() => {
                  const target = confirmRestore;
                  const withSafety = createSafetySnapshot;
                  setConfirmRestore(null);
                  void guard(`res-${target.db.id}`, async () => {
                    const res = await api.restoreDatabase(target.db.id, {
                      backupId: target.backup.id,
                      createSafetySnapshot: withSafety,
                    });
                    if (res?.safetyBackupId) {
                      setUndoRestore({
                        dbId: target.db.id,
                        dbName: target.db.name,
                        safetyBackupId: res.safetyBackupId,
                      });
                    }
                    onNotify('Restauración completada correctamente', 'success');
                    await load();
                    const refreshed = await api.getDatabaseBackups(target.db.id).catch(() => null);
                    if (refreshed) setBackups((prev) => ({ ...prev, [target.db.id]: refreshed.backups }));
                  });
                }}
                className="px-4 py-2 text-xs font-medium bg-red-600 hover:bg-red-700 text-white rounded-lg cursor-pointer"
              >
                Sí, restaurar ahora
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* Modal: Confirmar eliminación */}
      <Modal
        open={Boolean(confirmDelete)}
        onClose={() => setConfirmDelete(null)}
        title={confirmDelete?.destroyData ? 'Eliminar base de datos y datos' : 'Eliminar contenedor de base de datos'}
        subtitle={
          confirmDelete?.destroyData
            ? 'Esta acción borrará permanentemente el contenedor, el volumen y las copias locales.'
            : 'Se eliminará el contenedor pero se conservará el volumen persistente en disco.'
        }
        maxWidthClass="max-w-md"
      >
        {confirmDelete && (
          <div className="p-5 space-y-4">
            <div className={`p-3.5 rounded-xl border text-xs ${confirmDelete.destroyData ? 'bg-red-50 border-red-200 text-red-900' : 'bg-slate-50 border-slate-200 text-slate-700'}`}>
              Base de datos: <strong>{confirmDelete.db.name}</strong> (<code className="font-mono">{confirmDelete.db.containerName}</code>)
            </div>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmDelete(null)}
                className="px-3.5 py-2 text-xs font-medium text-slate-600 border border-slate-200 rounded-lg hover:bg-slate-50 cursor-pointer"
              >
                Cancelar
              </button>
              <button
                type="button"
                onClick={() => {
                  const target = confirmDelete;
                  setConfirmDelete(null);
                  void guard(`del-${target.db.id}`, async () => {
                    await api.deleteDatabase(target.db.id, {
                      deleteVolume: target.destroyData,
                      deleteBackups: target.destroyData,
                    });
                    onNotify(
                      target.destroyData
                        ? 'Base de datos y datos eliminados'
                        : 'Contenedor eliminado; volumen conservado',
                      'info'
                    );
                    await load();
                  });
                }}
                className={`px-4 py-2 text-xs font-medium text-white rounded-lg cursor-pointer ${
                  confirmDelete.destroyData ? 'bg-red-600 hover:bg-red-700' : 'bg-slate-900 hover:bg-slate-800'
                }`}
              >
                {confirmDelete.destroyData ? 'Eliminar permanentemente' : 'Eliminar contenedor'}
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
