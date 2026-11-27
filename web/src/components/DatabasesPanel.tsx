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
  Terminal,
  ShieldCheck,
  HardDrive,
  KeyRound,
  ChevronDown,
  ChevronUp,
  Loader2,
  CheckCircle2,
  Flame,
} from 'lucide-react';
import {
  api,
  type ManagedDatabase,
  type DbEngine,
  type DbBackup,
  type DbCredentials,
  type DbStorageConfig,
  type DbInspectResult,
  type DbStudioSqlResult,
  type DbStudioRedisResult,
  type DbStudioBloatResult,
  type S3StoragePreset,
  type S3PresignResult,
  type DrDrillScorecard,
  type SqlMigrationLintResult,
  type PiiMaskResult,
} from '../lib/api';
import { copyToClipboard } from '../lib/clipboard';
import { Modal } from './Modal';
import { HelpTip } from './HelpTip';
import { useI18n } from '../lib/i18n';

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
  const { t } = useI18n();
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

  // Cycle-9 Read-Only Live DB Studio & Safe Redis Inspector
  const [studioOpen, setStudioOpen] = useState(true);
  const [studioTab, setStudioTab] = useState<'sql' | 'redis' | 'bloat'>('sql');
  const [studioDbId, setStudioDbId] = useState<string>('');
  const [sqlInput, setSqlInput] = useState('SELECT id, project, status, duration_ms, created_at FROM deployments ORDER BY created_at DESC LIMIT 20');
  const [sqlResult, setSqlResult] = useState<DbStudioSqlResult | null>(null);
  const [sqlError, setSqlError] = useState<string | null>(null);
  const [redisInput, setRedisInput] = useState('SCAN 0 COUNT 50');
  const [redisResult, setRedisResult] = useState<DbStudioRedisResult | null>(null);
  const [redisError, setRedisError] = useState<string | null>(null);
  const [bloatResult, setBloatResult] = useState<DbStudioBloatResult | null>(null);
  const [bloatError, setBloatError] = useState<string | null>(null);
  const [studioBusy, setStudioBusy] = useState<'sql' | 'redis' | 'bloat' | null>(null);

  // Cycle-9 Post-MinIO S3 Storage (Garage / RustFS / SeaweedFS) & Pure-Crypto SigV4 Presigner
  const [s3Presets, setS3Presets] = useState<S3StoragePreset[]>([]);
  const [activePresetId, setActivePresetId] = useState<string>('garage');
  const [presignForm, setPresignForm] = useState({
    endpoint: 'http://127.0.0.1:3900',
    region: 'garage',
    bucket: 'culkibo-backups',
    key: 'snapshots/acme-prod-2026.sql.gz',
    method: 'GET' as 'GET' | 'PUT' | 'HEAD' | 'DELETE',
    expiresIn: '900',
    accessKeyId: 'GK_demo_access_key',
    secretAccessKey: 'demo_secret_access_key_replace_me',
  });
  const [presignResult, setPresignResult] = useState<S3PresignResult | null>(null);
  const [presignError, setPresignError] = useState<string | null>(null);
  const [presignBusy, setPresignBusy] = useState(false);

  // Cycle-10 Automated DR Backup Fire-Drill Verifier
  const [drDrills, setDrDrills] = useState<DrDrillScorecard[]>([]);
  const [drBusy, setDrBusy] = useState<'valid' | 'corrupt' | null>(null);
  const [drError, setDrError] = useState<string | null>(null);

  // Cycle-12 Zero-Downtime SQL Migration Linter (10 DDL Rules)
  const [lintSqlText, setLintSqlText] = useState(
    "SET lock_timeout = '5s';\nSET statement_timeout = '30s';\nCREATE INDEX CONCURRENTLY idx_users_email ON users(email);"
  );
  const [lintResult, setLintResult] = useState<SqlMigrationLintResult | null>(null);
  const [lintBusy, setLintBusy] = useState(false);
  const [lintError, setLintError] = useState<string | null>(null);

  // Cycle-13 PR-Preview DB PII Masker (Post-Snaplet / Neosync)
  const [piiInput, setPiiInput] = useState(
    JSON.stringify(
      [
        { id: 101, full_name: 'Alice Martin', email: 'alice.martin@acme-corp.example', phone: '+1-415-555-0192', ssn: '123-45-6789', client_ip: '203.0.113.42' },
        { id: 102, full_name: 'Carlos Vega', email: 'carlos.vega@acme-corp.example', phone: '+1-415-555-0198', ssn: '987-65-4321', client_ip: '198.51.100.77' },
      ],
      null,
      2
    )
  );
  const [piiSeed, setPiiSeed] = useState('culkibo-pr-418-seed');
  const [piiResult, setPiiResult] = useState<PiiMaskResult | null>(null);
  const [piiBusy, setPiiBusy] = useState(false);
  const [piiError, setPiiError] = useState<string | null>(null);
  const [piiShowDdl, setPiiShowDdl] = useState(false);
  const [piiCopiedDdl, setPiiCopiedDdl] = useState(false);

  const databasesRef = React.useRef<ManagedDatabase[]>([]);
  useEffect(() => {
    databasesRef.current = databases;
  }, [databases]);

  const load = useCallback(async () => {
    try {
      const [dbs, eng, status, store, presetsRes, drillsRes] = await Promise.all([
        api.getDatabases(projectId),
        api.getDbEngines().catch(() => ({ engines: [] })),
        api.getDbDockerStatus().catch(() => ({ available: true, reason: null })),
        api.getDbStorage().catch((): DbStorageConfig => ({ configured: false })),
        api.getStoragePresets().catch(() => ({ presets: [] })),
        api.listDrDrills().catch(() => ({ drills: [] })),
      ]);
      const dbList = Array.isArray(dbs?.databases) ? dbs.databases : [];
      setDatabases(dbList);
      setEngines(Array.isArray(eng?.engines) ? eng.engines : []);
      setDockerOk(Boolean(status?.available));
      setDockerReason(status?.reason ?? null);
      setStorage(store || { configured: false });
      setS3Presets(Array.isArray(presetsRes?.presets) ? presetsRes.presets : []);
      setDrDrills(Array.isArray(drillsRes?.drills) ? drillsRes.drills : []);
      if (dbList.length > 0) {
        setStudioDbId((prev) => prev || dbList[0].id);
      }
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Error loading databases', 'error');
    }
  }, [projectId, onNotify]);

  useEffect(() => {
    let active = true;
    Promise.all([
      api.getDatabases(projectId),
      api.getDbEngines().catch(() => ({ engines: [] })),
      api.getDbDockerStatus().catch(() => ({ available: true, reason: null })),
      api.getDbStorage().catch((): DbStorageConfig => ({ configured: false })),
      api.getStoragePresets().catch(() => ({ presets: [] })),
      api.listDrDrills().catch(() => ({ drills: [] })),
    ])
      .then(([dbs, eng, status, store, presetsRes, drillsRes]) => {
        if (!active) return;
        const dbList = Array.isArray(dbs?.databases) ? dbs.databases : [];
        setDatabases(dbList);
        setEngines(Array.isArray(eng?.engines) ? eng.engines : []);
        setDockerOk(Boolean(status?.available));
        setDockerReason(status?.reason ?? null);
        setStorage(store || { configured: false });
        setS3Presets(Array.isArray(presetsRes?.presets) ? presetsRes.presets : []);
        setDrDrills(Array.isArray(drillsRes?.drills) ? drillsRes.drills : []);
        if (dbList.length > 0) {
          setStudioDbId((prev) => prev || dbList[0].id);
        }
      })
      .catch((err) => {
        if (!active) return;
        onNotify(err instanceof Error ? err.message : 'Error loading databases', 'error');
      });
    return () => { active = false; };
  }, [projectId, onNotify]);

  const handleRunDrDrill = async (mode: 'valid' | 'corrupt') => {
    const targetDb = studioDbId || databases[0]?.id || 'db_pg_main';
    setDrBusy(mode);
    setDrError(null);
    try {
      const payload = mode === 'corrupt'
        ? {
            engine: 'postgres',
            projectId,
            artifactBase64: 'H4sIAAAAAAAAAAMAAAAAAAAAAAA=',
            preserveAcl: true,
          }
        : {
            engine: 'postgres',
            projectId,
            sqlSample: '-- PostgreSQL database dump\nCREATE TABLE IF NOT EXISTS deployments (id text PRIMARY KEY, status text NOT NULL, created_at timestamptz DEFAULT now());\nINSERT INTO deployments (id, status) VALUES (\'dep_01\', \'active\');\nGRANT SELECT, INSERT ON TABLE deployments TO acme;\n',
            preserveAcl: true,
          };
      const drill = await api.runDatabaseDrDrill(targetDb, payload);
      setDrDrills((prev) => [drill, ...prev.filter((d) => d.id !== drill.id)].slice(0, 12));
      if (drill.verdict === 'PASS') {
        onNotify(`DR Fire-Drill PASS (${drill.rtoMs ?? 0} ms RTO, SHA-256 + ACL verified)`, 'success');
      } else {
        onNotify(`DR Fire-Drill BLOCKED (${drill.errors?.[0] || 'Corrupt or empty dump detected'})`, 'error');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'DR fire-drill verification failed';
      setDrError(msg);
      onNotify(msg, 'error');
    } finally {
      setDrBusy(null);
    }
  };

  const handleLintSqlMigration = async (overrideSql?: string) => {
    const sql = (overrideSql ?? lintSqlText).trim();
    if (!sql) return;
    if (overrideSql !== undefined) setLintSqlText(overrideSql);
    setLintBusy(true);
    setLintError(null);
    try {
      const res = await api.lintSqlMigration(sql);
      setLintResult(res);
      onNotify(
        res.safe
          ? `Zero-Downtime SQL Linter: SAFE (${res.score}/100)`
          : `SQL Linter BLOCKED (${Array.isArray(res.blockers) ? res.blockers.length : 1} lock/rewrite blocker(s))`,
        res.safe ? 'success' : 'error'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'SQL migration linter failed';
      setLintError(msg);
      onNotify(msg, 'error');
    } finally {
      setLintBusy(false);
    }
  };

  const handleMaskPreviewPii = async () => {
    const raw = piiInput.trim();
    if (!raw) return;
    setPiiBusy(true);
    setPiiError(null);
    try {
      let payload: { rows?: Array<Record<string, unknown>>; sqlDump?: string; seed: string; autoDetect: boolean };
      if (raw.startsWith('[') || raw.startsWith('{')) {
        const parsed = JSON.parse(raw);
        const rows = Array.isArray(parsed) ? parsed : [parsed];
        payload = { rows, seed: piiSeed.trim() || 'culkibo-preview-seed', autoDetect: true };
      } else {
        payload = { sqlDump: raw, seed: piiSeed.trim() || 'culkibo-preview-seed', autoDetect: true };
      }
      const res = await api.maskDatabasePii(payload);
      setPiiResult(res);
      onNotify(
        res.zeroPiiLeaked
          ? `PR-Preview PII Masked (${res.maskedCount} values · Zero PII Leaked)`
          : `PII Masker completed with ${res.maskedCount} replacements`,
        res.zeroPiiLeaked ? 'success' : 'info'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'PR-Preview PII masking failed';
      setPiiError(msg);
      onNotify(msg, 'error');
    } finally {
      setPiiBusy(false);
    }
  };

  const handleRunStudioSql = async (queryOverride?: string) => {
    const q = (queryOverride ?? sqlInput).trim();
    if (!q) return;
    if (queryOverride !== undefined) setSqlInput(queryOverride);
    const targetDb = studioDbId || databases[0]?.id || 'db_pg_main';
    setStudioBusy('sql');
    setSqlError(null);
    try {
      const res = await api.runDbStudioSql(targetDb, { query: q, engine: 'postgres', maxRows: 200 });
      setSqlResult(res);
    } catch (err: unknown) {
      setSqlResult(null);
      setSqlError(err instanceof Error ? err.message : 'Read-Only SQL gate rejected query');
    } finally {
      setStudioBusy(null);
    }
  };

  const handleRunStudioRedis = async (cmdOverride?: string) => {
    const raw = (cmdOverride ?? redisInput).trim();
    if (!raw) return;
    if (cmdOverride !== undefined) setRedisInput(cmdOverride);
    const targetDb = studioDbId || databases.find((d) => d.engine === 'valkey' || d.engine === 'redis')?.id || databases[0]?.id || 'db_valkey_cache';
    setStudioBusy('redis');
    setRedisError(null);
    try {
      const res = await api.runDbStudioRedis(targetDb, { argv: raw.split(/\s+/).filter(Boolean) });
      setRedisResult(res);
    } catch (err: unknown) {
      setRedisResult(null);
      setRedisError(err instanceof Error ? err.message : 'Safe Redis inspector rejected command');
    } finally {
      setStudioBusy(null);
    }
  };

  const handleRunStudioBloat = async () => {
    const targetDb = studioDbId || databases[0]?.id || 'db_pg_main';
    setStudioBusy('bloat');
    setBloatError(null);
    try {
      const res = await api.runDbStudioBloat(targetDb, {});
      setBloatResult(res);
    } catch (err: unknown) {
      setBloatResult(null);
      setBloatError(err instanceof Error ? err.message : 'Could not analyze Postgres table bloat');
    } finally {
      setStudioBusy(null);
    }
  };

  const handleSelectS3Preset = (preset: S3StoragePreset) => {
    setActivePresetId(preset.id);
    const bind = preset.bindAddress || '127.0.0.1';
    const port = preset.defaultPort || preset.s3Port || (preset.id === 'garage' ? 3900 : preset.id === 'seaweedfs' ? 8333 : 9000);
    setPresignForm((prev) => ({
      ...prev,
      endpoint: `http://${bind}:${port}`,
      region: preset.region || (preset.id === 'garage' ? 'garage' : 'us-east-1'),
    }));
  };

  const handleGeneratePresign = async (e: React.FormEvent) => {
    e.preventDefault();
    setPresignBusy(true);
    setPresignError(null);
    try {
      const res = await api.generateS3PresignedUrl({
        endpoint: presignForm.endpoint.trim(),
        region: presignForm.region.trim() || 'us-east-1',
        bucket: presignForm.bucket.trim(),
        key: presignForm.key.trim(),
        method: presignForm.method,
        expiresIn: Number(presignForm.expiresIn) || 900,
        accessKeyId: presignForm.accessKeyId.trim() || 'GK_demo_access_key',
        secretAccessKey: presignForm.secretAccessKey.trim() || 'demo_secret_access_key_replace_me',
      });
      setPresignResult(res);
      onNotify('AWS SigV4 presigned URL generated locally (0 deps)', 'success');
    } catch (err: unknown) {
      setPresignResult(null);
      setPresignError(err instanceof Error ? err.message : 'Could not generate SigV4 presigned URL');
    } finally {
      setPresignBusy(false);
    }
  };

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
            <p className="font-semibold text-amber-900">{t('db.dockerOffTitle')}</p>
            <p className="text-amber-800 mt-0.5">
              {dockerReason || t('db.dockerOffDesc')}
            </p>
          </div>
        </div>
      )}

      {/* Aprovisionar */}
      <div className="bg-white p-5 rounded-xl border border-slate-200">
        <h3 className="font-semibold text-slate-900 flex items-center gap-2 text-base">
          <Database className="w-4 h-4 text-slate-600" /> {t('db.provisionTitle')}
        </h3>
        <p className="text-xs text-slate-500 mt-1 mb-4">
          {t('db.provisionDesc')}{' '}
          <strong className="text-slate-700 font-medium">{t('db.provisionNoPorts')}</strong>
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
          {t('db.emptyList')}
        </div>
      )}

      {databases.map((db) => {
        const health = HEALTH_STYLE[db.health] || HEALTH_STYLE.unknown;
        const healthLabel =
          db.health === 'healthy'
            ? t('db.healthHealthy')
            : db.health === 'starting'
              ? t('db.healthStarting')
              : db.health === 'unhealthy'
                ? t('db.healthUnhealthy')
                : t('db.healthUnknown');
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
                        <Link2 className="w-3 h-3" /> {t('db.connectedProject')}
                      </span>
                    )}
                  </div>
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500 mt-1 tabular-nums">
                    <span className="flex items-center gap-1.5">
                      <span className={`w-1.5 h-1.5 rounded-full ${health.dot}`} /> {healthLabel}
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
                    <span>{isBusy(`rec-${db.id}`) ? t('db.recreating') : t('db.recreate')}</span>
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => void handleInspectDb(db)}
                  disabled={isBusy(`ins-${db.id}`)}
                  title={t('db.inspect')}
                  className="inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 cursor-pointer disabled:opacity-50"
                >
                  <Stethoscope className="w-3.5 h-3.5 text-slate-500" />
                  <span>{isBusy(`ins-${db.id}`) ? t('db.inspecting') : t('db.inspect')}</span>
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
                  <span>{isLinked ? t('db.unlink') : t('db.linkProject')}</span>
                </button>
                {db.exposure?.enabled ? (
                  <span className={`text-xs px-2 py-1 rounded-md font-mono flex items-center gap-1 tabular-nums ${
                    db.exposure?.bindAddress === '0.0.0.0'
                      ? 'bg-red-50 text-red-700 border border-red-200'
                      : 'bg-amber-50 text-amber-800 border border-amber-200'
                  }`}>
                    <Globe className="w-3 h-3" /> {db.exposure?.bindAddress}:{db.exposure?.hostPort}
                  </span>
                ) : (
                  <span className="text-xs px-2 py-1 rounded-md bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1">
                    <Lock className="w-3 h-3" /> {t('db.privateOnly')}
                  </span>
                )}
                <button
                  type="button"
                  onClick={() => void guard(`ctl-${db.id}`, async () => {
                    await api.controlDatabase(db.id, db.status === 'running' ? 'stop' : 'start');
                    await load();
                  })}
                  disabled={isBusy(`ctl-${db.id}`)}
                  aria-label={db.status === 'running' ? 'Stop database' : 'Start database'}
                  className="p-2 rounded-lg border border-slate-200 hover:bg-slate-50 text-slate-600 disabled:opacity-50 cursor-pointer"
                  title={db.status === 'running' ? 'Stop' : 'Start'}
                >
                  {db.status === 'running' ? <Square className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                </button>
                <button
                  type="button"
                  onClick={() => { setExpanded(open ? null : db.id); if (!open) void loadBackups(db); }}
                  className="text-xs font-medium text-slate-700 hover:text-slate-900 border border-slate-200 px-3 py-1.5 rounded-lg cursor-pointer"
                >
                  {open ? t('db.close') : t('db.manage')}
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

      {/* Cycle-9: Read-Only Live DB Studio & Safe Redis Inspector */}
      <section className="culkibo-surface rounded-2xl overflow-hidden text-xs">
        <div className="px-5 py-4 border-b border-slate-200 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex items-start gap-2.5 min-w-0">
            <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0 mt-0.5">
              <Terminal className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold text-slate-900">{t('db.studioTitle')}</h3>
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
                  <ShieldCheck className="w-3 h-3" />
                  {t('db.studioPill')}
                </span>
              </div>
              <p className="text-slate-500 mt-0.5">{t('db.studioDesc')}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0 flex-wrap">
            {databases.length > 0 && (
              <select
                aria-label="Target database"
                value={studioDbId || databases[0]?.id || ''}
                onChange={(e) => setStudioDbId(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-[11px] text-slate-800"
              >
                {databases.map((db) => (
                  <option key={db.id} value={db.id}>
                    {db.name} ({db.engine})
                  </option>
                ))}
              </select>
            )}
            <button
              type="button"
              onClick={() => setStudioOpen((v) => !v)}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer"
            >
              {studioOpen ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              <span>{studioOpen ? 'Hide' : 'Open Studio'}</span>
            </button>
          </div>
        </div>

        {studioOpen && (
          <div className="p-5 space-y-4">
            <div className="inline-flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200">
              {([
                { id: 'sql', label: t('db.studioTabSql') },
                { id: 'redis', label: t('db.studioTabRedis') },
                { id: 'bloat', label: t('db.studioTabBloat') },
              ] as const).map((tabItem) => (
                <button
                  key={tabItem.id}
                  type="button"
                  onClick={() => setStudioTab(tabItem.id)}
                  className={`px-3 py-1.5 rounded-md font-medium transition-colors cursor-pointer ${
                    studioTab === tabItem.id ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {tabItem.label}
                </button>
              ))}
            </div>

            {studioTab === 'sql' && (
              <div className="space-y-3">
                <textarea
                  rows={3}
                  value={sqlInput}
                  onChange={(e) => setSqlInput(e.target.value)}
                  spellCheck={false}
                  aria-label="Read-only SQL query"
                  className="w-full p-3 rounded-xl border border-slate-200 bg-slate-50 focus:bg-white font-mono text-[11px] leading-relaxed text-slate-900"
                />
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => void handleRunStudioSql('SELECT id, project, status, duration_ms, created_at FROM deployments ORDER BY created_at DESC LIMIT 20')}
                      className="px-2.5 py-1 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 font-mono text-[10px] text-slate-700 cursor-pointer"
                    >
                      SELECT deployments
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleRunStudioSql('EXPLAIN SELECT id, status FROM deployments WHERE status = \'active\'')}
                      className="px-2.5 py-1 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 font-mono text-[10px] text-slate-700 cursor-pointer"
                    >
                      EXPLAIN plan
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleRunStudioSql('DROP TABLE deployments;')}
                      className="px-2.5 py-1 rounded-lg border border-red-200 bg-red-50 hover:bg-red-100 font-mono text-[10px] text-red-700 cursor-pointer"
                    >
                      {t('db.studioTestBlock')}
                    </button>
                  </div>
                  <button
                    type="button"
                    disabled={studioBusy !== null || !sqlInput.trim()}
                    onClick={() => void handleRunStudioSql()}
                    className="culkibo-press inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                  >
                    {studioBusy === 'sql' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                    <span>{studioBusy === 'sql' ? t('db.studioRunning') : t('db.studioRunSql')}</span>
                  </button>
                </div>

                {sqlError && (
                  <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-800 flex items-start gap-2">
                    <ShieldAlert className="w-4 h-4 text-red-700 shrink-0 mt-0.5" />
                    <div className="space-y-0.5">
                      <div className="font-semibold">Write / Destructive SQL Blocked</div>
                      <div className="font-mono text-[11px]">{sqlError}</div>
                    </div>
                  </div>
                )}

                {sqlResult && (
                  <div className="space-y-2.5">
                    {sqlResult.wrappedSql && (
                      <div className="p-3 rounded-xl bg-slate-950 text-emerald-300 border border-slate-800 font-mono text-[11px] overflow-x-auto">
                        {sqlResult.wrappedSql}
                      </div>
                    )}
                    {Array.isArray(sqlResult.rows) && sqlResult.rows.length > 0 && (
                      <div className="border border-slate-200 rounded-xl overflow-x-auto bg-white">
                        <table className="w-full text-left border-collapse">
                          <thead>
                            <tr className="bg-slate-50 border-b border-slate-200 text-[10px] font-mono uppercase text-slate-500">
                              {(Array.isArray(sqlResult.columns) && sqlResult.columns.length > 0
                                ? sqlResult.columns
                                : Object.keys(sqlResult.rows[0] || {})
                              ).map((col) => (
                                <th key={col} className="py-2 px-3 whitespace-nowrap">{col}</th>
                              ))}
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-100 font-mono text-[11px] tabular-nums">
                            {sqlResult.rows.slice(0, 20).map((row, rIdx) => {
                              const cols = Array.isArray(sqlResult.columns) && sqlResult.columns.length > 0
                                ? sqlResult.columns
                                : Object.keys(row || {});
                              return (
                                <tr key={rIdx}>
                                  {cols.map((col) => (
                                    <td key={col} className="py-2 px-3 text-slate-700 whitespace-nowrap">
                                      {row[col] == null ? 'NULL' : String(row[col])}
                                    </td>
                                  ))}
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {studioTab === 'redis' && (
              <div className="space-y-3">
                <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                  <input
                    type="text"
                    value={redisInput}
                    onChange={(e) => setRedisInput(e.target.value)}
                    placeholder="SCAN 0 COUNT 50"
                    className="flex-1 px-3 py-2 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                  />
                  <button
                    type="button"
                    disabled={studioBusy !== null || !redisInput.trim()}
                    onClick={() => void handleRunStudioRedis()}
                    className="culkibo-press inline-flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50 shrink-0"
                  >
                    {studioBusy === 'redis' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                    <span>{studioBusy === 'redis' ? t('db.studioRunning') : t('db.studioRunRedis')}</span>
                  </button>
                </div>
                <div className="flex flex-wrap items-center gap-1.5">
                  {['SCAN 0 COUNT 50', 'INFO memory', 'DBSIZE'].map((preset) => (
                    <button
                      key={preset}
                      type="button"
                      onClick={() => void handleRunStudioRedis(preset)}
                      className="px-2.5 py-1 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 font-mono text-[10px] text-slate-700 cursor-pointer"
                    >
                      {preset}
                    </button>
                  ))}
                  <button
                    type="button"
                    onClick={() => void handleRunStudioRedis('FLUSHALL')}
                    className="px-2.5 py-1 rounded-lg border border-red-200 bg-red-50 hover:bg-red-100 font-mono text-[10px] text-red-700 cursor-pointer"
                  >
                    {t('db.studioTestFlush')}
                  </button>
                </div>

                {redisError && (
                  <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-800 flex items-start gap-2">
                    <ShieldAlert className="w-4 h-4 text-red-700 shrink-0 mt-0.5" />
                    <div className="font-mono text-[11px]">{redisError}</div>
                  </div>
                )}

                {redisResult && (
                  <div className="p-3 rounded-xl bg-slate-950 text-emerald-300 border border-slate-800 font-mono text-[11px] space-y-1.5 overflow-x-auto">
                    <div className="text-slate-400">
                      argv: {(Array.isArray(redisResult.normalizedArgv) ? redisResult.normalizedArgv.join(' ') : redisResult.command) || 'OK'}
                      {redisResult.clampedCount != null
                        ? ` (COUNT clamped <= 100: ${redisResult.clampedCount})`
                        : redisResult.countClamped
                          ? ` (COUNT clamped <= ${redisResult.maxScanCount ?? 100})`
                          : ''}
                    </div>
                    <pre className="whitespace-pre-wrap">
                      {redisResult.output || (redisResult.result != null ? JSON.stringify(redisResult.result, null, 2) : 'Read-only preview validated')}
                    </pre>
                  </div>
                )}
              </div>
            )}

            {studioTab === 'bloat' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <span className="text-slate-600">
                    Detects dead-tuple ratios (&ge;20% or &ge;10k dead tuples) and zero-scan unused indexes.
                  </span>
                  <button
                    type="button"
                    disabled={studioBusy !== null}
                    onClick={() => void handleRunStudioBloat()}
                    className="culkibo-press inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                  >
                    {studioBusy === 'bloat' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Stethoscope className="w-3.5 h-3.5" />}
                    <span>{studioBusy === 'bloat' ? t('db.studioRunning') : t('db.studioRunBloat')}</span>
                  </button>
                </div>

                {bloatError && (
                  <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-700">{bloatError}</div>
                )}

                {bloatResult && (
                  <div className="space-y-2.5">
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 tabular-nums">
                      <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                        <span className="text-[10px] uppercase text-slate-400 block font-semibold">Tables Checked</span>
                        <span className="font-mono text-sm font-semibold text-slate-900">{bloatResult.checkedTables ?? 0}</span>
                      </div>
                      <div className="p-2.5 rounded-xl bg-amber-50 border border-amber-200">
                        <span className="text-[10px] uppercase text-amber-700 block font-semibold">Bloated Tables</span>
                        <span className="font-mono text-sm font-semibold text-amber-800">
                          {Array.isArray(bloatResult.bloatedTables) ? bloatResult.bloatedTables.length : 0}
                        </span>
                      </div>
                      <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                        <span className="text-[10px] uppercase text-slate-400 block font-semibold">Recommendations</span>
                        <span className="font-mono text-sm font-semibold text-slate-900">
                          {Array.isArray(bloatResult.recommendations) ? bloatResult.recommendations.length : 0}
                        </span>
                      </div>
                    </div>
                    {Array.isArray(bloatResult.recommendations) && bloatResult.recommendations.length > 0 && (
                      <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1 text-[11px] text-slate-700">
                        {bloatResult.recommendations.map((rec, i) => (
                          <div key={i}>• {typeof rec === 'string' ? rec : (rec.message || rec.action || rec.table || 'Optimize table')}</div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </section>

      {/* Cycle-9: Post-MinIO S3 Storage (Garage · RustFS · SeaweedFS) & Pure-Crypto SigV4 Presigner */}
      <section className="culkibo-surface rounded-2xl p-5 space-y-4 text-xs">
        <div className="flex items-start gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0 mt-0.5">
            <HardDrive className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm font-semibold text-slate-900">{t('db.s3Title')}</h3>
              <span className="px-2 py-0.5 rounded-full bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-600">
                127.0.0.1 Private Bridge · AWS4-HMAC-SHA256
              </span>
            </div>
            <p className="text-slate-500 mt-0.5">{t('db.s3Desc')}</p>
          </div>
        </div>

        {/* 3 Pinned 2026 MinIO-Replacement Preset Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {(s3Presets.length > 0
            ? s3Presets
            : [
                { id: 'garage', name: 'Garage', label: 'Garage S3', image: 'dxflrs/garage:v1.0.1', licence: 'AGPL-3.0', bindAddress: '127.0.0.1', defaultPort: 3900, memoryMb: 40, region: 'garage', summary: 'Rust CRDT S3 (~40 MB RAM) built for multi-node WireGuard mesh.' },
                { id: 'rustfs', name: 'RustFS', label: 'RustFS', image: 'rustfs/rustfs:1.0.0-alpha.45', licence: 'Apache-2.0', bindAddress: '127.0.0.1', defaultPort: 9000, memoryMb: 96, region: 'us-east-1', summary: 'Apache-2.0 high-throughput MinIO drop-in with ILM & Object Lock.' },
                { id: 'seaweedfs', name: 'SeaweedFS', label: 'SeaweedFS', image: 'chrislusf/seaweedfs:3.85', licence: 'Apache-2.0', bindAddress: '127.0.0.1', defaultPort: 8333, memoryMb: 128, region: 'us-east-1', summary: 'Distributed Filer + S3 gateway for high-density blob workloads.' },
              ]
          ).map((preset) => {
            const isSelected = activePresetId === preset.id;
            return (
              <button
                key={preset.id}
                type="button"
                onClick={() => handleSelectS3Preset(preset)}
                className={`text-left p-3.5 rounded-xl border transition-colors cursor-pointer space-y-1.5 ${
                  isSelected
                    ? 'border-slate-900 bg-slate-50'
                    : 'border-slate-200 bg-white hover:border-slate-300'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-sm text-slate-900">{preset.label || preset.name || preset.id}</span>
                  <span className="px-1.5 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px]">
                    {preset.bindAddress || '127.0.0.1'}
                  </span>
                </div>
                <div className="font-mono text-[11px] text-slate-600 truncate">{preset.image}</div>
                <p className="text-[11px] text-slate-500 leading-relaxed">
                  {preset.summary || preset.description || 'Pinned private-bridge S3 preset.'}
                </p>
                <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 pt-1 tabular-nums">
                  <span>{preset.licence || preset.license || 'OSS'}</span>
                  <span>~{preset.memoryMb || preset.ramEstimateMb || 64} MB RAM</span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Pure-Crypto SigV4 Presigner Form */}
        <form onSubmit={(e) => void handleGeneratePresign(e)} className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            <label className="block">
              <span className="text-[11px] font-medium text-slate-600 block mb-1">S3 Endpoint</span>
              <input
                type="url"
                required
                value={presignForm.endpoint}
                onChange={(e) => setPresignForm((p) => ({ ...p, endpoint: e.target.value }))}
                className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
              />
            </label>
            <label className="block">
              <span className="text-[11px] font-medium text-slate-600 block mb-1">Bucket</span>
              <input
                type="text"
                required
                value={presignForm.bucket}
                onChange={(e) => setPresignForm((p) => ({ ...p, bucket: e.target.value }))}
                className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
              />
            </label>
            <label className="block">
              <span className="text-[11px] font-medium text-slate-600 block mb-1">Object Key</span>
              <input
                type="text"
                required
                value={presignForm.key}
                onChange={(e) => setPresignForm((p) => ({ ...p, key: e.target.value }))}
                className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
              />
            </label>
            <div className="grid grid-cols-2 gap-2">
              <label className="block">
                <span className="text-[11px] font-medium text-slate-600 block mb-1">Method</span>
                <select
                  value={presignForm.method}
                  onChange={(e) => setPresignForm((p) => ({ ...p, method: e.target.value as 'GET' | 'PUT' | 'HEAD' | 'DELETE' }))}
                  className="w-full px-2 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900"
                >
                  <option value="GET">GET</option>
                  <option value="PUT">PUT</option>
                  <option value="HEAD">HEAD</option>
                  <option value="DELETE">DELETE</option>
                </select>
              </label>
              <label className="block">
                <span className="text-[11px] font-medium text-slate-600 block mb-1">TTL (sec)</span>
                <input
                  type="number"
                  min={60}
                  max={604800}
                  value={presignForm.expiresIn}
                  onChange={(e) => setPresignForm((p) => ({ ...p, expiresIn: e.target.value }))}
                  className="w-full px-2 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900 tabular-nums"
                />
              </label>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-1">
            <span className="text-[11px] text-slate-500 font-mono">
              Region: {presignForm.region} · 60s–7d TTL cap · blocks ../ traversal
            </span>
            <button
              type="submit"
              disabled={presignBusy}
              className="culkibo-press inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              {presignBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <KeyRound className="w-3.5 h-3.5" />}
              <span>{presignBusy ? t('db.s3Presigning') : t('db.s3PresignBtn')}</span>
            </button>
          </div>
        </form>

        {presignError && (
          <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-700 font-mono text-[11px]">
            {presignError}
          </div>
        )}

        {presignResult && (
          <div className="p-3.5 rounded-xl bg-slate-950 text-emerald-300 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between gap-2 flex-wrap text-[10px] font-mono text-slate-400">
              <span>{presignResult.algorithm || 'AWS4-HMAC-SHA256'} · {presignResult.method} · TTL {presignResult.expiresIn}s</span>
              <button
                type="button"
                onClick={() => void copy(presignResult.url, 'sigv4_url')}
                className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-100 cursor-pointer"
              >
                {copied === 'sigv4_url' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copied === 'sigv4_url' ? 'Copied' : 'Copy URL'}</span>
              </button>
            </div>
            <div className="font-mono text-[11px] break-all leading-relaxed">{presignResult.url}</div>
          </div>
        )}
      </section>

      {/* Cycle-10: Automated DR Backup Restore Fire-Drill Verifier */}
      <section className="culkibo-surface rounded-2xl p-5 space-y-4 text-xs">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex items-start gap-2.5 min-w-0">
            <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0 mt-0.5">
              <Flame className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold text-slate-900">{t('db.drTitle')}</h3>
                <span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-mono text-[10px] font-semibold">
                  SHA-256 · gunzip · ACL Preserved
                </span>
              </div>
              <p className="text-slate-500 mt-0.5">{t('db.drDesc')}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap shrink-0">
            <button
              type="button"
              disabled={drBusy !== null}
              onClick={() => void handleRunDrDrill('corrupt')}
              className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-red-200 bg-red-50 hover:bg-red-100 text-red-700 font-medium cursor-pointer disabled:opacity-50"
            >
              {drBusy === 'corrupt' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
              <span>{t('db.drTestCorrupt')}</span>
            </button>
            <button
              type="button"
              disabled={drBusy !== null}
              onClick={() => void handleRunDrDrill('valid')}
              className="culkibo-press inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              {drBusy === 'valid' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
              <span>{drBusy === 'valid' ? t('db.drRunning') : t('db.drRun')}</span>
            </button>
          </div>
        </div>

        {drError && (
          <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-800 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 shrink-0" />
            <span>{drError}</span>
          </div>
        )}

        {drDrills.length === 0 ? (
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-slate-500 text-center">
            {t('db.drEmpty')}
          </div>
        ) : (
          <div className="divide-y divide-slate-100 border border-slate-200 rounded-xl overflow-hidden">
            {drDrills.slice(0, 5).map((d) => {
              const isPass = d.verdict === 'PASS';
              const errs = Array.isArray(d.errors) ? d.errors : [];
              const warns = Array.isArray(d.warnings) ? d.warnings : [];
              return (
                <div key={d.id} className="px-4 py-3 bg-white space-y-1.5">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full font-mono text-[10px] font-semibold border ${
                        isPass
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-red-50 text-red-700 border-red-200'
                      }`}>
                        {isPass ? <CheckCircle2 className="w-3 h-3" /> : <ShieldAlert className="w-3 h-3" />}
                        {d.verdict}
                      </span>
                      <span className="font-mono font-semibold text-slate-900">{d.databaseId}</span>
                      <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-600 tabular-nums">
                        RTO {d.rtoMs ?? 0} ms · RPO {d.rpoSec != null ? `${Math.round(d.rpoSec / 60)}m` : '0m'}
                      </span>
                      {d.bytesVerified != null && (
                        <span className="font-mono text-[10px] text-slate-500 tabular-nums">
                          {formatBytes(d.bytesVerified)}
                        </span>
                      )}
                      {(d.aclPreserved ?? d.preserveAcl) !== false && isPass && (
                        <span className="px-1.5 py-0.5 rounded bg-emerald-50 border border-emerald-200 font-mono text-[10px] text-emerald-700">
                          ACL OK
                        </span>
                      )}
                    </div>
                    {d.sha256 && (
                      <span className="font-mono text-[10px] text-slate-400 tabular-nums">
                        sha256:{String(d.sha256).slice(0, 12)}
                      </span>
                    )}
                  </div>
                  {errs.length > 0 && (
                    <div className="p-2 rounded-lg bg-red-50 border border-red-200 font-mono text-[11px] text-red-800">
                      {errs.join(' · ')}
                    </div>
                  )}
                  {warns.length > 0 && (
                    <div className="p-2 rounded-lg bg-amber-50 border border-amber-200 font-mono text-[11px] text-amber-800">
                      {warns.join(' · ')}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Cycle-12: Zero-Downtime SQL Migration Linter (10 DDL Rules) */}
      <section className="culkibo-surface rounded-2xl p-5 space-y-4 text-xs">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex items-start gap-2.5 min-w-0">
            <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0 mt-0.5">
              <Stethoscope className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold text-slate-900">{t('db.sqlLintTitle')}</h3>
                <span className="px-2 py-0.5 rounded-full bg-slate-100 border border-slate-200 font-mono text-[10px] font-semibold text-slate-700">
                  Squawk-Class · Pure JS · 0 Deps
                </span>
              </div>
              <p className="text-slate-500 mt-0.5">{t('db.sqlLintDesc')}</p>
            </div>
          </div>
          <div className="flex items-center gap-1.5 flex-wrap shrink-0">
            <button
              type="button"
              disabled={lintBusy}
              onClick={() => void handleLintSqlMigration('CREATE INDEX idx_orders_uid ON orders(user_id);\nALTER TABLE orders DROP COLUMN legacy_token;')}
              className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-red-200 bg-red-50 hover:bg-red-100 text-red-700 font-medium cursor-pointer disabled:opacity-50"
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>{t('db.sqlLintTestUnsafe')}</span>
            </button>
            <button
              type="button"
              disabled={lintBusy}
              onClick={() => void handleLintSqlMigration("SET lock_timeout = '5s';\nSET statement_timeout = '30s';\nCREATE INDEX CONCURRENTLY idx_orders_uid ON orders(user_id);")}
              className="culkibo-press inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-emerald-200 bg-emerald-50 hover:bg-emerald-100 text-emerald-700 font-medium cursor-pointer disabled:opacity-50"
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>{t('db.sqlLintTestSafe')}</span>
            </button>
            <button
              type="button"
              disabled={lintBusy || !lintSqlText.trim()}
              onClick={() => void handleLintSqlMigration()}
              className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              {lintBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
              <span>{lintBusy ? t('db.sqlLintRunning') : t('db.sqlLintRun')}</span>
            </button>
          </div>
        </div>

        <textarea
          rows={3}
          value={lintSqlText}
          onChange={(e) => setLintSqlText(e.target.value)}
          placeholder={t('db.sqlLintPlaceholder')}
          spellCheck={false}
          className="w-full p-3 rounded-xl border border-slate-200 bg-slate-50 focus:bg-white font-mono text-[11px] text-slate-900 leading-relaxed"
        />

        {lintError && (
          <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 shrink-0" />
            <span>{lintError}</span>
          </div>
        )}

        {lintResult && (() => {
          const blockers = Array.isArray(lintResult.blockers) ? lintResult.blockers : [];
          const hints = Array.isArray(lintResult.rewriteHints) ? lintResult.rewriteHints : [];
          return (
            <div className={`p-3.5 rounded-xl border space-y-2 ${
              lintResult.safe
                ? 'bg-emerald-50/70 border-emerald-200 text-emerald-950'
                : 'bg-red-50 border-red-200 text-red-900'
            }`}>
              <div className="flex items-center justify-between gap-2 flex-wrap font-mono tabular-nums">
                <span className="inline-flex items-center gap-1.5 font-semibold">
                  {lintResult.safe ? <CheckCircle2 className="w-4 h-4 text-emerald-600" /> : <ShieldAlert className="w-4 h-4 text-red-600" />}
                  <span>{lintResult.safe ? `${lintResult.score}/100 SAFE` : `BLOCKED · ${lintResult.score}/100`}</span>
                </span>
                <span className="text-[10px] opacity-80">
                  {lintResult.analyzedStatements ?? 0} stmt(s) · lock_timeout: {lintResult.hasLockTimeout ? 'OK' : 'MISSING'}
                </span>
              </div>
              {blockers.length > 0 && (
                <div className="space-y-1 font-mono text-[11px]">
                  {blockers.map((b, idx) => {
                    const txt = typeof b === 'string'
                      ? b
                      : `[${b.rule || b.ruleId || b.id || b.code || 'DDL'}] ${b.message || 'Unsafe DDL operation'}`;
                    return <div key={idx}>• {txt}</div>;
                  })}
                </div>
              )}
              {hints.length > 0 && (
                <div className="pt-1.5 border-t border-red-200/70 space-y-0.5 text-[11px]">
                  <span className="font-semibold">Zero-Downtime Rewrite Hints:</span>
                  {hints.slice(0, 4).map((h, idx) => (
                    <div key={idx} className="font-mono">→ {h}</div>
                  ))}
                </div>
              )}
            </div>
          );
        })()}
      </section>

      {/* Cycle-13: PR-Preview DB PII Masker (Post-Snaplet / Neosync) */}
      <section className="culkibo-surface rounded-2xl p-5 space-y-4 text-xs">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex items-start gap-2.5 min-w-0">
            <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0 mt-0.5">
              <Lock className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold text-slate-900">{t('db.piiTitle')}</h3>
                <span className="px-2 py-0.5 rounded-full bg-slate-100 border border-slate-200 font-mono text-[10px] font-semibold text-slate-700">
                  HMAC-SHA256 · FK-Safe · pg_anonymizer
                </span>
              </div>
              <p className="text-slate-500 mt-0.5">{t('db.piiDesc')}</p>
            </div>
          </div>
          <div className="flex items-center gap-1.5 flex-wrap shrink-0">
            <input
              type="text"
              value={piiSeed}
              onChange={(e) => setPiiSeed(e.target.value)}
              aria-label="Deterministic masking seed"
              placeholder="culkibo-preview-seed"
              className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-mono text-slate-900 w-44"
            />
            <button
              type="button"
              disabled={piiBusy || !piiInput.trim()}
              onClick={() => void handleMaskPreviewPii()}
              className="culkibo-press inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              {piiBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
              <span>{piiBusy ? t('db.piiMasking') : t('db.piiMaskBtn')}</span>
            </button>
          </div>
        </div>

        <textarea
          rows={4}
          value={piiInput}
          onChange={(e) => setPiiInput(e.target.value)}
          aria-label="Sample JSON rows or SQL dump to mask"
          spellCheck={false}
          className="w-full p-3 rounded-xl border border-slate-200 bg-slate-50 focus:bg-white font-mono text-[11px] text-slate-900 leading-relaxed"
        />

        {piiError && (
          <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-red-700 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 shrink-0" />
            <span>{piiError}</span>
          </div>
        )}

        {piiResult && (() => {
          const maskedFields = Array.isArray(piiResult.fieldsMasked) ? piiResult.fieldsMasked : [];
          const previewText = piiResult.maskedSql
            ? piiResult.maskedSql
            : JSON.stringify(piiResult.maskedRows || [], null, 2);
          return (
            <div className="space-y-2.5 tabular-nums">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full font-mono text-[10px] font-semibold border ${
                    piiResult.zeroPiiLeaked
                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      : 'bg-amber-50 text-amber-800 border-amber-200'
                  }`}>
                    <CheckCircle2 className="w-3 h-3" />
                    <span>{piiResult.zeroPiiLeaked ? t('db.piiZeroLeak') : 'Review Residual PII'}</span>
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-700">
                    maskedCount: {piiResult.maskedCount}
                  </span>
                  {maskedFields.slice(0, 6).map((f) => (
                    <span key={f} className="px-2 py-0.5 rounded bg-white border border-slate-200 font-mono text-[10px] text-slate-600">
                      {f}
                    </span>
                  ))}
                </div>
                {piiResult.pgAnonDdl && (
                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => setPiiShowDdl((v) => !v)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer"
                    >
                      {piiShowDdl ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                      <span>{t('db.piiToggleDdl')}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        void copyToClipboard(piiResult.pgAnonDdl || '');
                        setPiiCopiedDdl(true);
                        setTimeout(() => setPiiCopiedDdl(false), 1800);
                        onNotify('pg_anonymizer SECURITY LABEL DDL copied', 'success');
                      }}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer"
                    >
                      {piiCopiedDdl ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                      <span>{t('db.piiCopyDdl')}</span>
                    </button>
                  </div>
                )}
              </div>

              <pre className="p-3 rounded-xl bg-slate-950 text-emerald-300 font-mono text-[11px] leading-relaxed overflow-x-auto max-h-48 border border-slate-800">
                {previewText}
              </pre>

              {piiShowDdl && piiResult.pgAnonDdl && (
                <pre className="p-3 rounded-xl bg-slate-950 text-sky-300 font-mono text-[11px] leading-relaxed overflow-x-auto max-h-40 border border-slate-800">
                  {piiResult.pgAnonDdl}
                </pre>
              )}
            </div>
          );
        })()}
      </section>

      {/* Franja compacta de Almacenamiento S3 / R2 global (configuración unificada en Ajustes → Backups y DR) */}
      <div className="bg-white p-4 rounded-xl border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-8 h-8 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-600 shrink-0">
            <CloudUpload className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <div className="font-semibold text-slate-900">
              {storage.configured
                ? t('db.s3GlobalActive', { bucket: storage.bucket || 's3' })
                : t('db.s3GlobalUnconfigured')}
            </div>
            <p className="text-slate-500 truncate mt-0.5">
              {storage.configured
                ? t('db.s3GlobalActiveDesc', { endpoint: storage.endpoint || '', region: storage.region || 'auto' })
                : t('db.s3GlobalUnconfiguredDesc')}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {storage.configured && (
            <button
              type="button"
              onClick={() => void guard('s3test', async () => {
                const r = await api.testDbStorage();
                onNotify(`S3 connection verified (${r.bucket})`, 'success');
              })}
              disabled={isBusy('s3test')}
              className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer disabled:opacity-50"
            >
              {t('db.s3TestBtn')}
            </button>
          )}
          {onOpenBackupSettings && (
            <button
              type="button"
              onClick={onOpenBackupSettings}
              className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer"
            >
              {storage.configured ? t('db.s3ManageBtn') : t('db.s3ConfigureBtn')}
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
