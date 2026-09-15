import React, { useState, useEffect } from 'react';
import {
  Database, Plus, Play, Square, RefreshCw, Trash2, Eye, EyeOff, Copy, Check,
  ShieldAlert, Clock, CloudUpload, History, Lock, Globe, AlertTriangle, Server
} from 'lucide-react';
import { api, type ManagedDatabase, type DbEngine, type DbBackup, type DbCredentials, type DbStorageConfig } from '../lib/api';

interface Props {
  projectId: string;
  onNotify: (msg: string) => void;
}

const HEALTH_STYLE: Record<string, { dot: string; label: string }> = {
  healthy: { dot: 'bg-emerald-500', label: 'Saludable' },
  starting: { dot: 'bg-amber-500 animate-pulse', label: 'Arrancando' },
  unhealthy: { dot: 'bg-red-500', label: 'Con fallos' },
  unknown: { dot: 'bg-slate-300', label: 'Desconocido' }
};

const CRON_PRESETS = [
  { value: '0 * * * *', label: 'Cada hora' },
  { value: '0 3 * * *', label: 'Cada día a las 03:00' },
  { value: '0 4 * * 0', label: 'Cada domingo a las 04:00' },
  { value: '0 5 1 * *', label: 'El día 1 de cada mes a las 05:00' }
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
  const [storage, setStorage] = useState<DbStorageConfig>({ configured: false });
  const [showStorageForm, setShowStorageForm] = useState(false);
  const [storageForm, setStorageForm] = useState({
    endpoint: '', region: 'auto', bucket: '', accessKeyId: '', secretAccessKey: '', prefix: 'culkibo/'
  });

  const load = async () => {
    try {
      const [dbs, eng, status, store] = await Promise.all([
        api.getDatabases(projectId),
        api.getDbEngines(),
        api.getDbDockerStatus(),
        api.getDbStorage()
      ]);
      setDatabases(dbs.databases);
      setEngines(eng.engines);
      setDockerOk(status.available);
      setDockerReason(status.reason);
      setStorage(store);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Error al cargar las bases de datos');
    }
  };

  useEffect(() => { load(); }, [projectId]);

  // Mientras algo esté arrancando conviene refrescar: la sonda de salud tarda
  // decenas de segundos y el usuario no debería tener que recargar a mano.
  useEffect(() => {
    if (!databases.some((d) => d.health === 'starting' || d.health === 'unknown')) return;
    const t = setInterval(async () => {
      for (const d of databases.filter((x) => x.health === 'starting' || x.health === 'unknown')) {
        try { await api.refreshDatabaseHealth(d.id); } catch (e) { /* silencio */ }
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
      onNotify(err instanceof Error ? err.message : 'Ha ocurrido un error');
    } finally {
      setBusy(null);
    }
  };

  const handleCreate = async (engine: DbEngine) => {
    setCreating(engine.engine);
    try {
      const created = await api.createDatabase({ projectId, engine: engine.engine, name: engine.label });
      onNotify(`${engine.label} aprovisionado. Guarde la cadena de conexión desde «Credenciales».`);
      await load();
      setExpanded(created.id);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Error al aprovisionar');
    } finally {
      setCreating(null);
    }
  };

  const copy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 1800);
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
    const res = await api.setDatabaseExposure(db.id, { enabled, hostPort: db.port });
    if (res.warning) onNotify(res.warning);
    await load();
  });

  return (
    <div className="space-y-6">
      {dockerOk === false && (
        <div className="bg-amber-50 border border-amber-200 rounded-2xl p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="font-semibold text-amber-900">Docker no está disponible</p>
            <p className="text-amber-800">{dockerReason || 'Las bases de datos gestionadas necesitan un daemon de Docker activo.'}</p>
          </div>
        </div>
      )}

      {/* ---------------------------------------------------------------- */}
      {/* Aprovisionar                                                      */}
      {/* ---------------------------------------------------------------- */}
      <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
        <div className="flex justify-between items-center mb-1">
          <h3 className="font-bold text-slate-900 flex items-center gap-2 text-lg">
            <Database className="w-5 h-5" /> Aprovisionar base de datos
          </h3>
        </div>
        <p className="text-sm text-slate-500 mb-4">
          Un clic y listo: contraseña generada, volumen persistente, red privada del proyecto, límites de
          recursos y sonda de salud. <strong className="text-slate-700">Nunca se publica ningún puerto.</strong>
        </p>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          {engines.map((e) => (
            <button
              key={e.engine}
              disabled={dockerOk === false || creating !== null}
              onClick={() => handleCreate(e)}
              className="text-left border border-slate-200 rounded-xl p-4 hover:border-slate-900 hover:shadow-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed bg-white"
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-900">{e.label}</span>
                {creating === e.engine
                  ? <RefreshCw className="w-4 h-4 text-slate-400 animate-spin" />
                  : <Plus className="w-4 h-4 text-slate-400" />}
              </div>
              <div className="font-mono text-xs text-slate-500 mt-1">{e.image}</div>
              <div className="text-[11px] text-slate-400 mt-1">{e.licence}</div>
            </button>
          ))}
        </div>
      </div>

      {/* ---------------------------------------------------------------- */}
      {/* Listado                                                           */}
      {/* ---------------------------------------------------------------- */}
      {databases.length === 0 && (
        <div className="bg-white p-10 rounded-2xl border border-slate-200 shadow-sm text-center text-slate-500 text-sm">
          Este proyecto todavía no tiene bases de datos gestionadas.
        </div>
      )}

      {databases.map((db) => {
        const health = HEALTH_STYLE[db.health] || HEALTH_STYLE.unknown;
        const open = expanded === db.id;
        return (
          <div key={db.id} className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="p-6 flex flex-col md:flex-row md:items-center gap-4">
              <div className="flex items-center gap-3 flex-1 min-w-0">
                <div className="w-11 h-11 rounded-xl bg-slate-50 border border-slate-100 flex items-center justify-center shrink-0">
                  <Database className="w-5 h-5 text-slate-600" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-slate-900 truncate">{db.name}</span>
                    <span className="text-xs bg-slate-100 text-slate-600 px-2 py-0.5 rounded-md">{db.engineLabel}</span>
                  </div>
                  <div className="flex items-center gap-3 text-xs text-slate-500 mt-1">
                    <span className="flex items-center gap-1.5">
                      <span className={`w-2 h-2 rounded-full ${health.dot}`} /> {health.label}
                    </span>
                    <span className="font-mono truncate">{db.containerName}</span>
                    <span>{db.memoryMb} MB &bull; {db.cpus} vCPU</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {db.exposure.enabled ? (
                  <span className={`text-xs px-2 py-1 rounded-md flex items-center gap-1 ${
                    db.exposure.bindAddress === '0.0.0.0'
                      ? 'bg-red-50 text-red-700 border border-red-200'
                      : 'bg-amber-50 text-amber-700 border border-amber-200'}`}>
                    <Globe className="w-3 h-3" /> {db.exposure.bindAddress}:{db.exposure.hostPort}
                  </span>
                ) : (
                  <span className="text-xs px-2 py-1 rounded-md bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1">
                    <Lock className="w-3 h-3" /> Sólo red privada
                  </span>
                )}
                <button
                  onClick={() => guard(`ctl-${db.id}`, async () => {
                    await api.controlDatabase(db.id, db.status === 'running' ? 'stop' : 'start');
                    await load();
                  })}
                  disabled={busy === `ctl-${db.id}`}
                  className="p-2 rounded-lg border border-slate-200 hover:bg-slate-50 text-slate-600 disabled:opacity-50"
                  title={db.status === 'running' ? 'Detener' : 'Iniciar'}
                >
                  {db.status === 'running' ? <Square className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                </button>
                <button
                  onClick={() => { setExpanded(open ? null : db.id); if (!open) loadBackups(db); }}
                  className="text-sm font-medium text-slate-600 hover:text-slate-900 border border-slate-200 px-3 py-1.5 rounded-lg"
                >
                  {open ? 'Cerrar' : 'Gestionar'}
                </button>
              </div>
            </div>

            {open && (
              <div className="border-t border-slate-100 bg-slate-50/60 p-6 space-y-6">
                {/* ---- Conexión --------------------------------------- */}
                <section>
                  <h4 className="font-semibold text-slate-800 text-sm mb-2 flex items-center gap-2">
                    <Server className="w-4 h-4" /> Conexión
                  </h4>
                  <p className="text-xs text-slate-500 mb-2">
                    Las aplicaciones del proyecto llegan por el nombre del contenedor dentro de la red
                    <span className="font-mono"> {db.networkName}</span>. La contraseña no aparece en ningún
                    listado; hay que pedirla aquí.
                  </p>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 bg-white border border-slate-200 rounded-lg px-3 py-2 text-xs font-mono text-slate-700 overflow-x-auto whitespace-nowrap">
                      {creds[db.id] ? creds[db.id].internalConnectionString : db.connectionTemplate}
                    </code>
                    <button
                      onClick={() => toggleCredentials(db)}
                      disabled={busy === `creds-${db.id}`}
                      className="p-2 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-600 disabled:opacity-50"
                      title={creds[db.id] ? 'Ocultar credenciales' : 'Mostrar credenciales'}
                    >
                      {creds[db.id] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                    {creds[db.id] && (
                      <button
                        onClick={() => copy(creds[db.id].internalConnectionString, `conn-${db.id}`)}
                        className="p-2 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-600"
                        title="Copiar"
                      >
                        {copied === `conn-${db.id}` ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
                      </button>
                    )}
                  </div>
                </section>

                {/* ---- Exposición ------------------------------------- */}
                <section>
                  <h4 className="font-semibold text-slate-800 text-sm mb-2 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4" /> Acceso desde fuera
                  </h4>
                  <div className="bg-white border border-slate-200 rounded-xl p-4 flex items-start justify-between gap-4">
                    <p className="text-xs text-slate-600 leading-relaxed">
                      Publicar el puerto expone la base de datos en el host. Culkibo enlaza en
                      <span className="font-mono"> 127.0.0.1</span>, nunca en todas las interfaces:
                      las reglas que escribe Docker se evalúan <strong>antes</strong> que UFW, así que un
                      puerto abierto a 0.0.0.0 queda accesible aunque el cortafuegos diga lo contrario.
                      Para acceso remoto, use un túnel SSH.
                    </p>
                    <button
                      onClick={() => handleExpose(db, !db.exposure.enabled)}
                      disabled={busy === `exp-${db.id}`}
                      className={`shrink-0 text-sm font-medium px-3 py-1.5 rounded-lg border disabled:opacity-50 ${
                        db.exposure.enabled
                          ? 'border-slate-200 text-slate-700 bg-white hover:bg-slate-50'
                          : 'border-slate-900 bg-slate-900 text-white hover:bg-slate-800'}`}
                    >
                      {db.exposure.enabled ? 'Dejar de publicar' : `Publicar en 127.0.0.1:${db.port}`}
                    </button>
                  </div>
                </section>

                {/* ---- Copias programadas ----------------------------- */}
                <section>
                  <h4 className="font-semibold text-slate-800 text-sm mb-2 flex items-center gap-2">
                    <Clock className="w-4 h-4" /> Copias programadas
                  </h4>
                  <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3">
                    <div className="flex flex-wrap items-center gap-3">
                      <select
                        value={db.schedule.cron}
                        onChange={(e) => guard(`sch-${db.id}`, async () => {
                          await api.setDatabaseSchedule(db.id, { enabled: db.schedule.enabled, cron: e.target.value });
                          await load();
                        })}
                        className="text-sm border border-slate-200 rounded-lg px-3 py-1.5 bg-white text-slate-700"
                      >
                        {CRON_PRESETS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
                        {!CRON_PRESETS.some((p) => p.value === db.schedule.cron) && (
                          <option value={db.schedule.cron}>{db.schedule.cron}</option>
                        )}
                      </select>
                      <button
                        onClick={() => guard(`sch-${db.id}`, async () => {
                          await api.setDatabaseSchedule(db.id, { enabled: !db.schedule.enabled, cron: db.schedule.cron });
                          await load();
                        })}
                        disabled={busy === `sch-${db.id}`}
                        className={`text-sm font-medium px-3 py-1.5 rounded-lg border disabled:opacity-50 ${
                          db.schedule.enabled
                            ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
                            : 'border-slate-200 bg-white text-slate-600'}`}
                      >
                        {db.schedule.enabled ? 'Programación activa' : 'Programación desactivada'}
                      </button>
                      <span className="text-xs text-slate-500">
                        Próxima: <strong className="text-slate-700">{formatDate(db.schedule.nextRunAt)}</strong>
                        {' '}&bull; Última: {formatDate(db.schedule.lastRunAt)}
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
                            onBlur={(e) => guard(`ret-${db.id}`, async () => {
                              const next = { ...db.retention, [k]: parseInt(e.target.value, 10) || 0 };
                              await api.setDatabaseRetention(db.id, next);
                              await load();
                            })}
                            className="w-16 border border-slate-200 rounded-lg px-2 py-1 text-slate-700"
                          />
                          {k === 'daily' ? 'diarias' : 'semanales'}
                        </label>
                      ))}
                      <span className="text-xs text-slate-400">
                        El resto se poda automáticamente tras cada copia, en disco y en el bucket.
                      </span>
                    </div>
                  </div>
                </section>

                {/* ---- Historial -------------------------------------- */}
                <section>
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="font-semibold text-slate-800 text-sm flex items-center gap-2">
                      <History className="w-4 h-4" /> Copias ({db.backupsCount})
                    </h4>
                    <button
                      onClick={() => guard(`run-${db.id}`, async () => {
                        await api.runDatabaseBackup(db.id);
                        onNotify('Copia completada');
                        await load();
                        setBackups({ ...backups, [db.id]: (await api.getDatabaseBackups(db.id)).backups });
                      })}
                      disabled={busy === `run-${db.id}`}
                      className="text-sm font-medium bg-slate-900 text-white px-3 py-1.5 rounded-lg hover:bg-slate-800 disabled:opacity-50 flex items-center gap-1.5"
                    >
                      {busy === `run-${db.id}`
                        ? <><RefreshCw className="w-4 h-4 animate-spin" /> Copiando…</>
                        : <><CloudUpload className="w-4 h-4" /> Copiar ahora</>}
                    </button>
                  </div>
                  <div className="border border-slate-200 rounded-xl overflow-hidden bg-white">
                    <div className="grid grid-cols-[1.4fr_0.6fr_0.7fr_0.7fr_auto] gap-3 bg-slate-50 p-3 border-b border-slate-200 text-xs font-semibold text-slate-500">
                      <div>Fecha</div><div>Tamaño</div><div>Origen</div><div>Destino</div><div />
                    </div>
                    <div className="divide-y divide-slate-100">
                      {(backups[db.id] || []).length === 0 && (
                        <div className="p-6 text-center text-slate-500 text-sm">Todavía no hay copias.</div>
                      )}
                      {(backups[db.id] || []).map((b) => (
                        <div key={b.id} className="grid grid-cols-[1.4fr_0.6fr_0.7fr_0.7fr_auto] gap-3 p-3 items-center text-sm">
                          <div className="text-slate-700">{formatDate(b.createdAt)}</div>
                          <div className="text-slate-500">{formatBytes(b.sizeBytes)}</div>
                          <div className="text-slate-500 text-xs">
                            {b.trigger === 'scheduled' ? 'Programada' : b.trigger === 'catch-up' ? 'Recuperada' : 'Manual'}
                          </div>
                          <div className="text-xs">
                            {b.localAvailable && <span className="text-slate-500">Disco</span>}
                            {b.localAvailable && b.remoteAvailable && <span className="text-slate-300"> / </span>}
                            {b.remoteAvailable && <span className="text-emerald-600">Bucket</span>}
                          </div>
                          <button
                            onClick={() => guard(`res-${db.id}`, async () => {
                              await api.restoreDatabase(db.id, { backupId: b.id });
                              onNotify('Restauración completada');
                              await load();
                            })}
                            disabled={busy === `res-${db.id}`}
                            className="text-xs font-medium text-slate-600 hover:text-slate-900 border border-slate-200 px-2.5 py-1 rounded-lg disabled:opacity-50"
                          >
                            Restaurar
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                </section>

                {/* ---- Eliminar --------------------------------------- */}
                <section className="pt-2 border-t border-slate-200">
                  <div className="flex items-center justify-between gap-4">
                    <p className="text-xs text-slate-500">
                      Al eliminar se borra el contenedor. El volumen con los datos se conserva salvo que se
                      indique lo contrario.
                    </p>
                    <div className="flex gap-2 shrink-0">
                      <button
                        onClick={() => guard(`del-${db.id}`, async () => {
                          await api.deleteDatabase(db.id, { deleteVolume: false });
                          onNotify('Base de datos eliminada; el volumen se ha conservado');
                          await load();
                        })}
                        disabled={busy === `del-${db.id}`}
                        className="text-sm font-medium text-slate-700 border border-slate-200 px-3 py-1.5 rounded-lg hover:bg-white disabled:opacity-50"
                      >
                        Eliminar y conservar datos
                      </button>
                      <button
                        onClick={() => guard(`del-${db.id}`, async () => {
                          if (!window.confirm(
                            `Se borrará el volumen «${db.volumeName}» y TODOS sus datos de forma irreversible. ¿Continuar?`
                          )) return;
                          await api.deleteDatabase(db.id, { deleteVolume: true, deleteBackups: true });
                          onNotify('Base de datos y volumen eliminados');
                          await load();
                        })}
                        disabled={busy === `del-${db.id}`}
                        className="text-sm font-medium text-red-700 border border-red-200 bg-red-50 px-3 py-1.5 rounded-lg hover:bg-red-100 disabled:opacity-50 flex items-center gap-1.5"
                      >
                        <Trash2 className="w-4 h-4" /> Eliminar y borrar datos
                      </button>
                    </div>
                  </div>
                </section>
              </div>
            )}
          </div>
        );
      })}

      {/* ---------------------------------------------------------------- */}
      {/* Almacenamiento remoto                                             */}
      {/* ---------------------------------------------------------------- */}
      <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
        <div className="flex justify-between items-center mb-1">
          <h3 className="font-bold text-slate-900 flex items-center gap-2 text-lg">
            <CloudUpload className="w-5 h-5" /> Copias fuera del servidor (S3 / R2)
          </h3>
          <button
            onClick={() => setShowStorageForm(!showStorageForm)}
            className="text-sm font-medium text-slate-600 hover:text-slate-900 border border-slate-200 px-3 py-1.5 rounded-lg"
          >
            {showStorageForm ? 'Cancelar' : storage.configured ? 'Cambiar' : 'Configurar'}
          </button>
        </div>
        <p className="text-sm text-slate-500 mb-4">
          Compatible con Cloudflare R2, MinIO, Backblaze B2 y AWS S3. La clave secreta se guarda cifrada y
          no vuelve a mostrarse.
        </p>

        {storage.configured && !showStorageForm && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div><div className="text-xs text-slate-400">Endpoint</div><div className="font-mono text-xs text-slate-700 truncate">{storage.endpoint}</div></div>
            <div><div className="text-xs text-slate-400">Bucket</div><div className="text-slate-700">{storage.bucket}</div></div>
            <div><div className="text-xs text-slate-400">Región</div><div className="text-slate-700">{storage.region}</div></div>
            <div><div className="text-xs text-slate-400">Clave de acceso</div><div className="font-mono text-xs text-slate-700">{storage.accessKeyId}</div></div>
            <div className="col-span-2 md:col-span-4 flex gap-2 pt-2">
              <button
                onClick={() => guard('s3test', async () => {
                  const r = await api.testDbStorage();
                  onNotify(`Conexión correcta con ${r.bucket}`);
                })}
                disabled={busy === 's3test'}
                className="text-sm font-medium bg-slate-900 text-white px-3 py-1.5 rounded-lg hover:bg-slate-800 disabled:opacity-50"
              >
                Probar conexión
              </button>
              <button
                onClick={() => guard('s3clear', async () => {
                  await api.setDbStorage(null);
                  onNotify('Almacenamiento remoto desconectado');
                  await load();
                })}
                className="text-sm font-medium text-slate-600 border border-slate-200 px-3 py-1.5 rounded-lg hover:bg-slate-50"
              >
                Desconectar
              </button>
            </div>
          </div>
        )}

        {!storage.configured && !showStorageForm && (
          <div className="text-sm text-slate-500 bg-slate-50 border border-slate-200 rounded-xl p-4">
            Sin configurar. Las copias se guardan sólo en este servidor: si el disco falla, se pierden con él.
          </div>
        )}

        {showStorageForm && (
          <form
            className="grid grid-cols-1 md:grid-cols-2 gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              guard('s3save', async () => {
                await api.setDbStorage(storageForm);
                onNotify('Almacenamiento remoto guardado');
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
              ['secretAccessKey', 'Clave secreta', '']
            ] as const).map(([field, label, placeholder]) => (
              <label key={field} className="text-sm">
                <span className="text-xs text-slate-500">{label}</span>
                <input
                  type={field === 'secretAccessKey' ? 'password' : 'text'}
                  required={field !== 'prefix'}
                  value={storageForm[field]}
                  placeholder={placeholder}
                  onChange={(e) => setStorageForm({ ...storageForm, [field]: e.target.value })}
                  className="w-full border border-slate-200 rounded-lg px-3 py-2 mt-1 text-slate-700 font-mono text-xs"
                />
              </label>
            ))}
            <div className="md:col-span-2">
              <button
                type="submit"
                disabled={busy === 's3save'}
                className="text-sm font-medium bg-slate-900 text-white px-4 py-2 rounded-lg hover:bg-slate-800 disabled:opacity-50"
              >
                Guardar
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
