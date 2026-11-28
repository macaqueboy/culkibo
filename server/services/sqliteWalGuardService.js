const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * SQLite WAL Checkpoint Starvation & Network-FS Corruption Guard (100% Zero-Dep).
 *
 * Protege despliegues single-VPS con SQLite en producción (Rails 8 Solid Queue/Cache,
 * PocketBase, Uptime Kuma, Litestream):
 *  - Bloquea montajes de red incompatibles con POSIX flock (`nfs`, `cifs`, `smb`, `efs` ->
 *    `SQLITE_NETWORK_FS_CORRUPTION`).
 *  - Verifica `journal_mode=WAL` (`SQLITE_NON_WAL_LOCK_RISK`), `busy_timeout >= 5000`
 *    (`SQLITE_BUSY_TIMEOUT_LOW`), `synchronous != OFF` (`SQLITE_SYNC_OFF_CORRUPTION`),
 *    `journal_size_limit` acotado (`SQLITE_UNBOUNDED_WAL`) y retención/crecimiento de `-wal`
 *    por lectores largos (`WAL_CHECKPOINT_STARVATION`).
 *  - Emite SQL de arranque `PRAGMA` endurecido + `PRAGMA wal_checkpoint(TRUNCATE)` (`dryRun: true`).
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/sqlite-wal-guard.json`.
 */

const MAX_AUDITS = 200;
const NETWORK_FILESYSTEMS = new Set([
  'nfs',
  'nfs3',
  'nfs4',
  'cifs',
  'smb',
  'smb2',
  'smb3',
  'efs',
  'glusterfs',
  'cephfs',
  'sshfs'
]);

/**
 * Resuelve dinámicamente la ruta a `sqlite-wal-guard.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'sqlite-wal-guard.json')
    : path.join(base, 'data', 'sqlite-wal-guard.json');
}

/**
 * Escritura atómica con permisos `0o600`.
 * @param {string} targetPath
 * @param {string} content
 */
function atomicWriteFileSync(targetPath, content) {
  const dir = path.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = `${targetPath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(tmpPath, content, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmpPath, targetPath);
    try { fs.chmodSync(targetPath, 0o600); } catch (e) {}
  } catch (err) {
    try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e) {}
    throw err;
  }
}

/**
 * Carga auditorías almacenadas desde disco (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, audits: any[] }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), audits: [] };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && Array.isArray(parsed.audits)) {
      return parsed;
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), audits: [] };
}

/**
 * Guarda auditorías de forma atómica (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, audits: any[] }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  if (store.audits.length > MAX_AUDITS) {
    store.audits = store.audits.slice(-MAX_AUDITS);
  }
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Renderiza SQL `PRAGMA` endurecido para arranque de SQLite WAL y checkpoint seguro.
 * `dryRun: true` por defecto.
 *
 * @param {{
 *   databaseName?: string,
 *   busyTimeoutMs?: number,
 *   journalSizeLimitMb?: number,
 *   cacheSizeKb?: number,
 *   synchronous?: string,
 *   foreignKeys?: boolean,
 *   dryRun?: boolean
 * }} [input]
 */
function renderHardenedSqlitePragmas(input = {}) {
  const opts = input || {};
  const dryRun = opts.dryRun !== undefined ? Boolean(opts.dryRun) : true;
  const databaseName = String(opts.databaseName || 'app.sqlite3').replace(/[\r\n]/g, '').trim() || 'app.sqlite3';
  const busyTimeoutMs = Math.max(5000, Math.floor(Number(opts.busyTimeoutMs) || 5000));
  const journalSizeLimitMb = Math.max(16, Math.floor(Number(opts.journalSizeLimitMb) || 64));
  const journalSizeLimitBytes = journalSizeLimitMb * 1024 * 1024;
  const cacheSizeKb = Math.max(8000, Math.floor(Number(opts.cacheSizeKb) || 64000));
  const syncRaw = String(opts.synchronous || 'NORMAL').trim().toUpperCase();
  const synchronous = syncRaw === 'FULL' ? 'FULL' : 'NORMAL';
  const foreignKeys = opts.foreignKeys !== undefined ? Boolean(opts.foreignKeys) : true;

  const pragmaSql = [
    `-- Hardened SQLite WAL Bootstrap (${databaseName})`,
    'PRAGMA journal_mode = WAL;',
    `PRAGMA synchronous = ${synchronous};`,
    `PRAGMA busy_timeout = ${busyTimeoutMs};`,
    `PRAGMA foreign_keys = ${foreignKeys ? 'ON' : 'OFF'};`,
    'PRAGMA temp_store = MEMORY;',
    `PRAGMA journal_size_limit = ${journalSizeLimitBytes};`,
    'PRAGMA wal_autocheckpoint = 1000;',
    `PRAGMA cache_size = -${cacheSizeKb};`,
    '-- Safe maintenance checkpoint (run after closing idle long-lived read transactions):',
    'PRAGMA wal_checkpoint(TRUNCATE);'
  ].join('\n');

  return {
    ok: true,
    dryRun,
    databaseName,
    busyTimeoutMs,
    journalSizeLimitMb,
    journalSizeLimitBytes,
    synchronous,
    foreignKeys,
    pragmaSql,
    renderedAt: new Date().toISOString()
  };
}

/**
 * Audita la salud de SQLite WAL, riesgo de corrupción en sistemas de archivos de red,
 * `busy_timeout`, durabilidad `synchronous` e inanición de checkpoints `-wal`.
 *
 * @param {{
 *   databaseName?: string,
 *   filesystemType?: string,
 *   journalMode?: string,
 *   synchronous?: string,
 *   busyTimeoutMs?: number,
 *   busy_timeout?: number,
 *   journalSizeLimitMb?: number | null,
 *   dbSizeMb?: number,
 *   walSizeMb?: number,
 *   blockedReaders?: number,
 *   foreignKeys?: boolean,
 *   persist?: boolean
 * }} [input]
 */
function auditSqliteWalHealth(input = {}) {
  const opts = input || {};
  const databaseName = String(opts.databaseName || 'app.sqlite3').replace(/[\r\n]/g, '').trim() || 'app.sqlite3';
  const filesystemType = String(opts.filesystemType || 'ext4').trim().toLowerCase() || 'ext4';
  const journalMode = String(opts.journalMode ?? 'wal').trim().toLowerCase() || 'wal';
  const synchronous = String(opts.synchronous ?? 'normal').trim().toLowerCase() || 'normal';
  const rawBusy = opts.busyTimeoutMs !== undefined ? opts.busyTimeoutMs : opts.busy_timeout;
  const busyTimeoutMs = rawBusy !== undefined ? Math.max(0, Number(rawBusy) || 0) : 5000;
  const hasExplicitJournalLimit = opts.journalSizeLimitMb !== undefined;
  const journalSizeLimitMb = hasExplicitJournalLimit
    ? (opts.journalSizeLimitMb === null ? -1 : Number(opts.journalSizeLimitMb))
    : 64;
  const dbSizeMb = Math.max(0, Number(opts.dbSizeMb) || 0);
  const walSizeMb = Math.max(0, Number(opts.walSizeMb) || 0);
  const blockedReaders = Math.max(0, Math.floor(Number(opts.blockedReaders) || 0));
  const foreignKeys = opts.foreignKeys !== undefined ? Boolean(opts.foreignKeys) : true;

  const walToDbRatio = dbSizeMb > 0
    ? Math.round((walSizeMb / dbSizeMb) * 100) / 100
    : (walSizeMb > 0 ? walSizeMb : 0);

  /** @type {Array<{ code: string, severity: 'critical' | 'high' | 'medium', message: string, fix: string }>} */
  const findings = [];

  // 1. Network filesystem corruption risk (NFS/CIFS/SMB/EFS)
  if (NETWORK_FILESYSTEMS.has(filesystemType)) {
    findings.push({
      code: 'SQLITE_NETWORK_FS_CORRUPTION',
      severity: 'critical',
      message: `SQLite database "${databaseName}" is mounted on network filesystem "${filesystemType}" — broken POSIX advisory locking & -shm coherence cause silent B-tree corruption.`,
      fix: 'Move SQLite storage to local NVMe/ext4/xfs block storage and replicate backups continuously with Litestream or atomic S3 snapshots.'
    });
  }

  // 2. Non-WAL journal mode causes reader/writer contention
  if (journalMode !== 'wal') {
    findings.push({
      code: 'SQLITE_NON_WAL_LOCK_RISK',
      severity: 'high',
      message: `Journal mode is "${journalMode}" instead of "wal" — concurrent readers and writers serialize behind exclusive database locks.`,
      fix: 'Enable `PRAGMA journal_mode = WAL;` at database startup.'
    });
  }

  // 3. Low or zero busy_timeout causes immediate SQLITE_BUSY errors
  if (busyTimeoutMs < 5000) {
    findings.push({
      code: 'SQLITE_BUSY_TIMEOUT_LOW',
      severity: 'high',
      message: `PRAGMA busy_timeout is ${busyTimeoutMs} ms (< 5000 ms) — short write bursts will immediately throw SQLITE_BUSY.`,
      fix: 'Set `PRAGMA busy_timeout = 5000;` (or higher) on every connection opened by the pool.'
    });
  }

  // 4. synchronous=OFF risks catastrophic corruption on host power loss/crash
  if (synchronous === 'off' || synchronous === '0') {
    findings.push({
      code: 'SQLITE_SYNC_OFF_CORRUPTION',
      severity: 'critical',
      message: 'PRAGMA synchronous is set to OFF — OS crashes or container host power loss can leave the database unrecoverably corrupt.',
      fix: 'Use `PRAGMA synchronous = NORMAL;` (safe & fast with WAL) or `FULL`.'
    });
  }

  // 5. Missing or unbounded journal_size_limit
  if (!Number.isFinite(journalSizeLimitMb) || journalSizeLimitMb <= 0) {
    findings.push({
      code: 'SQLITE_UNBOUNDED_WAL',
      severity: 'medium',
      message: `PRAGMA journal_size_limit is unbounded (${journalSizeLimitMb}) — post-checkpoint -wal files will not be truncated back to disk.`,
      fix: 'Set `PRAGMA journal_size_limit = 67108864;` (64 MB) to bound residual -wal disk usage.'
    });
  }

  // 6. WAL checkpoint starvation (bloated -wal or pinned long-lived readers)
  if ((dbSizeMb > 0 && walSizeMb > dbSizeMb * 2) || walSizeMb >= 256 || blockedReaders > 0) {
    findings.push({
      code: 'WAL_CHECKPOINT_STARVATION',
      severity: 'critical',
      message: `SQLite -wal growth/starvation detected (${walSizeMb} MB -wal vs ${dbSizeMb} MB db, ratio ${walToDbRatio}x, ${blockedReaders} pinned reader(s)) — checkpoint cannot reclaim WAL frames.`,
      fix: 'Terminate long-lived read transactions, cap connection idle lifetime, and run `PRAGMA wal_checkpoint(TRUNCATE);`.'
    });
  }

  const rendered = renderHardenedSqlitePragmas({
    databaseName,
    busyTimeoutMs: Math.max(5000, busyTimeoutMs),
    journalSizeLimitMb: journalSizeLimitMb > 0 ? journalSizeLimitMb : 64,
    foreignKeys,
    dryRun: true
  });

  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const safe = findings.length === 0;
  const blocked = criticalCount > 0 || findings.some((f) => f.severity === 'high');
  const status = criticalCount > 0 ? 'CRITICAL' : (findings.length > 0 ? 'WARNING' : 'HEALTHY');
  const auditedAt = new Date().toISOString();

  const result = {
    ok: true,
    id: `wal_${crypto.randomBytes(5).toString('hex')}`,
    databaseName,
    safe,
    blocked,
    status,
    filesystemType,
    journalMode,
    synchronous,
    busyTimeoutMs,
    journalSizeLimitMb,
    dbSizeMb,
    walSizeMb,
    walToDbRatio,
    blockedReaders,
    foreignKeys,
    findings,
    findingCodes: findings.map((f) => f.code),
    pragmaSql: rendered.pragmaSql,
    auditedAt
  };

  if (opts.persist !== false) {
    const store = loadStore();
    store.audits.push({
      id: result.id,
      databaseName,
      filesystemType,
      walSizeMb,
      dbSizeMb,
      blockedReaders,
      safe,
      status,
      findingCodes: result.findingCodes,
      auditedAt
    });
    saveStore(store);
  }

  return result;
}

/**
 * Lista auditorías SQLite WAL almacenadas (más recientes primero).
 * @param {string} [databaseName]
 */
function listSqliteWalAudits(databaseName) {
  const store = loadStore();
  const cleanName = databaseName ? String(databaseName).trim() : '';
  const items = cleanName
    ? store.audits.filter((a) => a.databaseName === cleanName)
    : store.audits;
  return [...items].reverse();
}

module.exports = {
  auditSqliteWalHealth,
  renderHardenedSqlitePragmas,
  listSqliteWalAudits
};
