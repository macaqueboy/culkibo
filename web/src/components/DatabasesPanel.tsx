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
} from 'lucide-react';
import {
  api,
  type ManagedDatabase,
  type DbEngine,
  type DbBackup,
  type DbCredentials,
  type DbStorageConfig,
} from '../lib/api';
import { copyToClipboard } from '../lib/clipboard';
import { Modal } from './Modal';

interface Props {
  projectId: string;
  onNotify: (msg: string, type?: 'info' | 'success' | 'error') => void;
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

export const DatabasesPanel: React.FC<Props> = ({ projectId, onNotify }) => {
  const [databases, setDatabases] = useState<ManagedDatabase[]>([]);
  const [engines, setEngines] = useState<DbEngine[]>([]);
  const [dockerOk, setDockerOk] = useState<boolean | null>(null);
  const [dockerReason, setDockerReason] = useState<string | null>(null);
  const [creating, setCreating] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const [creds, setCreds] = useState<Record<string, DbCredentials>>({});
  const [backups, setBackups] = useState<Record<string, DbBackup[]>>({});
  const [copied, setCopied] = useState<string | null>(null);

  // Confirmaciones destructivas en Modal (P0-11)
  const [confirmRestore, setConfirmRestore] = useState<{ db: ManagedDatabase; backup: DbBackup } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<{ db: ManagedDatabase; destroyData: boolean } | null>(null);
  const [confirmDisconnectS3, setConfirmDisconnectS3] = useState(false);

  const [storage, setStorage] = useState<DbStorageConfig>({ configured: false });
  const [showStorageForm, setShowStorageForm] = useState(false);
  const [storageForm, setStorageForm] = useState({
    endpoint: '',
    region: 'auto',
    bucket: '',
    accessKeyId: '',
    secretAccessKey: '',
    prefix: 'culkibo/',
  });

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

  useEffect(() => {
    if (!databases.some((d) => d.health === 'starting' || d.health === 'unknown')) return;
    const t = setInterval(async () => {
      for (const d of databases.filter((x) => x.health === 'starting' || x.health === 'unknown')) {
        try { await api.refreshDatabaseHealth(d.id); } catch { /* silencio */ }
      }
      const dbs = await api.getDatabases(projectId).catch(() => null);
      if (dbs) setDatabases(dbs.databases);
    }, 5000);
    return () => clearInterval(t);
  }, [databases, projectId]);

  const guard = async (key: string, fn: () => Promise<void>) => {
    setBusy(key);
    try {
      await fn();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Ha ocurrido un error', 'error');
    } finally {
      setBusy(null);
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

  const handleInjectEnv = (db: ManagedDatabase) => guard(`inj-${db.id}`, async () => {
    const c = creds[db.id] || await api.getDatabaseCredentials(db.id);
    if (!creds[db.id]) setCreds((prev) => ({ ...prev, [db.id]: c }));
    const project = await api.getProject(projectId);
    const key = db.engine === 'valkey' || db.engine === 'redis' ? 'REDIS_URL' : 'DATABASE_URL';
    const nextEnv = { ...(project.envVars || {}), [key]: c.internalConnectionString };
    await api.updateProject(projectId, { envVars: nextEnv });
    onNotify(`Variable ${key} inyectada en el proyecto`, 'success');
  });

  const openStorageEditor = () => {
    if (!showStorageForm && storage.configured) {
      setStorageForm({
        endpoint: storage.endpoint || '',
        region: storage.region || 'auto',
        bucket: storage.bucket || '',
        prefix: storage.prefix || 'culkibo/',
        accessKeyId: '',
        secretAccessKey: '',
      });
    }
    setShowStorageForm((v) => !v);
  };

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
                  disabled={busy === `ctl-${db.id}`}
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

            {open && (
              <div className="border-t border-slate-200 bg-slate-50/60 p-5 space-y-5">
                {/* Conexión */}
                <section>
                  <h4 className="font-semibold text-slate-800 text-xs mb-1.5 flex items-center gap-1.5">
                    <Server className="w-3.5 h-3.5 text-slate-500" /> Conexión interna
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
                        disabled={busy === `creds-${db.id}`}
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
                        disabled={busy === `inj-${db.id}`}
                        className="px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium shrink-0 cursor-pointer disabled:opacity-50"
                      >
                        {busy === `inj-${db.id}` ? 'Inyectando…' : `Inyectar ${db.engine === 'valkey' || db.engine === 'redis' ? 'REDIS_URL' : 'DATABASE_URL'}`}
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
                      disabled={busy === `exp-${db.id}`}
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
                        disabled={busy === `sch-${db.id}`}
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
                      {(['daily', 'weekly'] as const).map((k) => (
                        <label key={k} className="flex items-center gap-1.5 text-xs text-slate-600">
                          <input
                            type="number"
                            min={0}
                            max={k === 'daily' ? 365 : 260}
                            defaultValue={db.retention[k]}
                            onBlur={(e) => {
                              const parsed = parseInt(e.target.value, 10) || 0;
                              if (parsed === db.retention[k]) return;
                              void guard(`ret-${db.id}`, async () => {
                                await api.setDatabaseRetention(db.id, { ...db.retention, [k]: parsed });
                                await load();
                              });
                            }}
                            className="w-16 border border-slate-200 rounded-lg px-2 py-1 text-slate-700 font-mono tabular-nums"
                          />
                          {k === 'daily' ? 'diarias' : 'semanales'}
                        </label>
                      ))}
                    </div>
                  </div>
                </section>

                {/* Historial de copias */}
                <section>
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="font-semibold text-slate-800 text-xs flex items-center gap-1.5 tabular-nums">
                      <History className="w-3.5 h-3.5 text-slate-500" /> Copias ({db.backupsCount})
                    </h4>
                    <button
                      type="button"
                      onClick={() => void guard(`run-${db.id}`, async () => {
                        await api.runDatabaseBackup(db.id);
                        onNotify('Copia de seguridad completada', 'success');
                        await load();
                        setBackups({ ...backups, [db.id]: (await api.getDatabaseBackups(db.id)).backups });
                      })}
                      disabled={busy === `run-${db.id}`}
                      className="text-xs font-medium bg-slate-900 text-white px-3 py-1.5 rounded-lg hover:bg-slate-800 disabled:opacity-50 flex items-center gap-1.5 cursor-pointer"
                    >
                      {busy === `run-${db.id}`
                        ? <><RefreshCw className="w-3.5 h-3.5 animate-spin" /> Copiando…</>
                        : <><CloudUpload className="w-3.5 h-3.5" /> Copiar ahora</>}
                    </button>
                  </div>
                  <div className="border border-slate-200 rounded-xl overflow-x-auto bg-white">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="bg-slate-50 border-b border-slate-200 text-[11px] font-medium text-slate-500">
                          <th className="py-2.5 px-3.5">Fecha</th>
                          <th className="py-2.5 px-3">Tamaño</th>
                          <th className="py-2.5 px-3">Origen</th>
                          <th className="py-2.5 px-3">Destino</th>
                          <th className="py-2.5 px-3.5 text-right">Acción</th>
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
                                {b.trigger === 'scheduled' ? 'Programada' : b.trigger === 'catch-up' ? 'Recuperada' : 'Manual'}
                              </td>
                              <td className="py-2.5 px-3 whitespace-nowrap">
                                {b.localAvailable && <span className="text-slate-600">Disco</span>}
                                {b.localAvailable && b.remoteAvailable && <span className="text-slate-300"> / </span>}
                                {b.remoteAvailable && <span className="text-emerald-700">Bucket</span>}
                              </td>
                              <td className="py-2.5 px-3.5 text-right">
                                <button
                                  type="button"
                                  onClick={() => setConfirmRestore({ db, backup: b })}
                                  disabled={busy === `res-${db.id}`}
                                  className="text-xs font-medium text-slate-700 hover:text-slate-900 border border-slate-200 px-2.5 py-1 rounded-lg disabled:opacity-50 cursor-pointer"
                                >
                                  Restaurar
                                </button>
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
                      disabled={busy === `del-${db.id}`}
                      className="text-xs font-medium text-slate-700 border border-slate-200 bg-white px-3 py-1.5 rounded-lg hover:bg-slate-50 disabled:opacity-50 cursor-pointer"
                    >
                      Eliminar contenedor
                    </button>
                    <button
                      type="button"
                      onClick={() => setConfirmDelete({ db, destroyData: true })}
                      disabled={busy === `del-${db.id}`}
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

      {/* Almacenamiento remoto S3 / R2 */}
      <div className="bg-white p-5 rounded-xl border border-slate-200">
        <div className="flex justify-between items-center mb-1">
          <h3 className="font-semibold text-slate-900 flex items-center gap-2 text-base">
            <CloudUpload className="w-4 h-4 text-slate-600" /> Copias externas (S3 / R2)
          </h3>
          <button
            type="button"
            onClick={openStorageEditor}
            className="text-xs font-medium text-slate-700 hover:text-slate-900 border border-slate-200 px-3 py-1.5 rounded-lg cursor-pointer"
          >
            {showStorageForm ? 'Cancelar' : storage.configured ? 'Cambiar' : 'Configurar'}
          </button>
        </div>
        <p className="text-xs text-slate-500 mb-4">
          Compatible con Cloudflare R2, MinIO, Backblaze B2 y AWS S3. La clave secreta se cifra en disco.
        </p>

        {storage.configured && !showStorageForm && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
            <div>
              <div className="text-slate-400">Endpoint</div>
              <div className="font-mono text-slate-700 truncate mt-0.5">{storage.endpoint}</div>
            </div>
            <div>
              <div className="text-slate-400">Bucket</div>
              <div className="text-slate-700 mt-0.5">{storage.bucket}</div>
            </div>
            <div>
              <div className="text-slate-400">Región</div>
              <div className="text-slate-700 mt-0.5">{storage.region}</div>
            </div>
            <div>
              <div className="text-slate-400">Clave de acceso</div>
              <div className="font-mono text-slate-700 mt-0.5">{storage.accessKeyId}</div>
            </div>
            <div className="col-span-2 md:col-span-4 flex gap-2 pt-1">
              <button
                type="button"
                onClick={() => void guard('s3test', async () => {
                  const r = await api.testDbStorage();
                  onNotify(`Conexión correcta con ${r.bucket}`, 'success');
                })}
                disabled={busy === 's3test'}
                className="text-xs font-medium bg-slate-900 text-white px-3 py-1.5 rounded-lg hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
              >
                Probar conexión
              </button>
              <button
                type="button"
                onClick={() => setConfirmDisconnectS3(true)}
                className="text-xs font-medium text-slate-600 border border-slate-200 px-3 py-1.5 rounded-lg hover:bg-slate-50 cursor-pointer"
              >
                Desconectar
              </button>
            </div>
          </div>
        )}

        {!storage.configured && !showStorageForm && (
          <div className="text-xs text-slate-500 bg-slate-50 border border-slate-200 rounded-lg p-3.5">
            Sin configurar. Las copias se guardan solo en el disco local de este servidor.
          </div>
        )}

        {showStorageForm && (
          <form
            className="grid grid-cols-1 md:grid-cols-2 gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              void guard('s3save', async () => {
                await api.setDbStorage(storageForm);
                onNotify('Almacenamiento remoto guardado', 'success');
                setShowStorageForm(false);
                await load();
              });
            }}
          >
            {([
              ['endpoint', 'Endpoint', 'https://<cuenta>.r2.cloudflarestorage.com'],
              ['bucket', 'Bucket', 'culkibo-copias'],
              ['region', 'Región', 'auto (R2) o eu-west-1'],
              ['prefix', 'Prefijo', 'culkibo/'],
              ['accessKeyId', 'Clave de acceso', ''],
              ['secretAccessKey', 'Clave secreta', ''],
            ] as const).map(([field, label, placeholder]) => (
              <label key={field} className="block">
                <span className="text-xs font-medium text-slate-600">{label}</span>
                <input
                  type={field === 'secretAccessKey' ? 'password' : 'text'}
                  required={field !== 'prefix'}
                  value={storageForm[field]}
                  placeholder={placeholder}
                  onChange={(e) => setStorageForm({ ...storageForm, [field]: e.target.value })}
                  className="w-full border border-slate-200 rounded-lg px-3 py-2 mt-1 text-slate-800 font-mono text-xs bg-white"
                />
              </label>
            ))}
            <div className="md:col-span-2 flex justify-end">
              <button
                type="submit"
                disabled={busy === 's3save'}
                className="text-xs font-medium bg-slate-900 text-white px-4 py-2 rounded-lg hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
              >
                Guardar configuración
              </button>
            </div>
          </form>
        )}
      </div>

      {/* Modal: Confirmar restauración */}
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
                Los cambios posteriores a esa fecha se perderán al restaurar el volcado.
              </div>
            </div>
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
                  setConfirmRestore(null);
                  void guard(`res-${target.db.id}`, async () => {
                    await api.restoreDatabase(target.db.id, { backupId: target.backup.id });
                    onNotify('Restauración completada', 'success');
                    await load();
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

      {/* Modal: Desconectar S3 */}
      <Modal
        open={confirmDisconnectS3}
        onClose={() => setConfirmDisconnectS3(false)}
        title="Desconectar almacenamiento S3 / R2"
        subtitle="Las futuras copias solo se guardarán localmente hasta que vuelvas a configurarlo."
        maxWidthClass="max-w-md"
      >
        <div className="p-5 space-y-4">
          <p className="text-xs text-slate-600">
            Los archivos que ya subiste al bucket <code className="font-mono">{storage.bucket}</code> no se borran.
          </p>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setConfirmDisconnectS3(false)}
              className="px-3.5 py-2 text-xs font-medium text-slate-600 border border-slate-200 rounded-lg hover:bg-slate-50 cursor-pointer"
            >
              Cancelar
            </button>
            <button
              type="button"
              onClick={() => {
                setConfirmDisconnectS3(false);
                void guard('s3clear', async () => {
                  await api.setDbStorage(null);
                  onNotify('Almacenamiento remoto desconectado', 'info');
                  await load();
                });
              }}
              className="px-4 py-2 text-xs font-medium bg-red-600 hover:bg-red-700 text-white rounded-lg cursor-pointer"
            >
              Desconectar
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
