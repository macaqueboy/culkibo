const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Container Disk-Pressure, `overlay2` Bloat & Inode Exhaustion Guard (100% Zero-Dep).
 *
 * Contramedida directa a `Dokploy/dokploy#4651`, `#2702` y `#2494`:
 *  - Vigila simultáneamente bloques (`df -h`) E inodos (`df -ih`), detectando
 *    `INODE_EXHAUSTION_CRITICAL` (>=85% inodos incluso con uso bajo de GB!).
 *  - Detecta `BLOCK_PRESSURE_CRITICAL` (>=85% bloques), `PG_WAL_SLOT_RUNAWAY`
 *    (slots de replicación inactivos o crecimiento desbocado de `pg_wal`),
 *    `UNROTATED_DOCKER_LOGS` y `OVERLAY2_BLOAT`.
 *  - Emite configuración `/etc/docker/daemon.json` (`max-size: 10m`, `max-file: 3`)
 *    y planes de remediación con `dryRun: true` por defecto y comandos `argv` sin shell.
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/disk-pressure-guard.json`.
 */

const MAX_STORED_REPORTS = 200;

/**
 * Resuelve dinámicamente la ruta a `disk-pressure-guard.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'disk-pressure-guard.json')
    : path.join(base, 'data', 'disk-pressure-guard.json');
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
 * Carga reportes almacenados desde disco (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, reports: any[] }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), reports: [] };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && Array.isArray(parsed.reports)) {
      return parsed;
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), reports: [] };
}

/**
 * Persiste reportes de forma atómica (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, reports: any[] }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  if (store.reports.length > MAX_STORED_REPORTS) {
    store.reports = store.reports.slice(-MAX_STORED_REPORTS);
  }
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Genera la configuración `/etc/docker/daemon.json` para rotación acotada de logs
 * de contenedores y prevención de llenado de disco (`max-size: 10m`, `max-file: 3`).
 *
 * @param {{
 *   maxSize?: string,
 *   maxFile?: string | number,
 *   logDriver?: string,
 *   storageDriver?: string
 * }} [options]
 */
function generateDaemonLogQuotaConfig(options = {}) {
  const opts = options || {};
  const maxSize = String(opts.maxSize || '10m').trim() || '10m';
  const maxFile = String(opts.maxFile ?? '3').trim() || '3';
  const logDriver = String(opts.logDriver || 'json-file').trim() || 'json-file';
  const storageDriver = String(opts.storageDriver || 'overlay2').trim() || 'overlay2';

  const config = {
    'log-driver': logDriver,
    'log-opts': {
      'max-size': maxSize,
      'max-file': maxFile
    },
    'storage-driver': storageDriver
  };

  return {
    ok: true,
    targetPath: '/etc/docker/daemon.json',
    maxSize,
    maxFile,
    config,
    jsonString: JSON.stringify(config, null, 2)
  };
}

/**
 * Evalúa telemetría dual de bloques (`df -h`), inodos (`df -ih`), `overlay2`,
 * logs JSON de Docker y segmentos `pg_wal` / slots inactivos de Postgres.
 *
 * @param {{
 *   nodeId?: string,
 *   blockUsedPct?: number,
 *   inodeUsedPct?: number,
 *   overlay2Gb?: number,
 *   containerLogGb?: number,
 *   pgWalGb?: number,
 *   inactiveReplicationSlots?: number,
 *   diskTotalGb?: number,
 *   persist?: boolean
 * }} [input]
 */
function evaluateDiskPressure(input = {}) {
  const opts = input || {};
  const nodeId = String(opts.nodeId || 'local').trim() || 'local';
  const blockUsedPct = Math.max(0, Math.min(100, Number(opts.blockUsedPct) || 0));
  const inodeUsedPct = Math.max(0, Math.min(100, Number(opts.inodeUsedPct) || 0));
  const overlay2Gb = Math.max(0, Number(opts.overlay2Gb) || 0);
  const containerLogGb = Math.max(0, Number(opts.containerLogGb) || 0);
  const pgWalGb = Math.max(0, Number(opts.pgWalGb) || 0);
  const inactiveReplicationSlots = Math.max(0, Math.floor(Number(opts.inactiveReplicationSlots) || 0));
  const diskTotalGb = Math.max(1, Number(opts.diskTotalGb) || 100);

  /** @type {Array<{ code: string, severity: 'critical' | 'high' | 'medium', message: string, fix: string }>} */
  const alerts = [];

  // 1. Inode exhaustion (df -ih) — fires CRITICAL even when blockUsedPct is low!
  if (inodeUsedPct >= 85) {
    alerts.push({
      code: 'INODE_EXHAUSTION_CRITICAL',
      severity: 'critical',
      message: `Filesystem inode usage is ${inodeUsedPct}% (>= 85%) on node "${nodeId}" despite ${blockUsedPct}% block usage — imminent ENOSPC risk.`,
      fix: 'Prune stopped containers, BuildKit cache mounts, and small temp/session files immediately.'
    });
  } else if (inodeUsedPct >= 75) {
    alerts.push({
      code: 'INODE_PRESSURE_WARNING',
      severity: 'medium',
      message: `Filesystem inode usage reached ${inodeUsedPct}% on node "${nodeId}".`,
      fix: 'Schedule BuildKit cache and dangling overlay2 layer cleanup before hitting 85%.'
    });
  }

  // 2. Block space exhaustion (df -h)
  if (blockUsedPct >= 85) {
    alerts.push({
      code: 'BLOCK_PRESSURE_CRITICAL',
      severity: 'critical',
      message: `Disk block usage is ${blockUsedPct}% (>= 85%) on node "${nodeId}" (${diskTotalGb} GB volume).`,
      fix: 'Reclaim dangling images/logs and expand root/data volume before database writes fail with ENOSPC.'
    });
  } else if (blockUsedPct >= 75) {
    alerts.push({
      code: 'BLOCK_PRESSURE_WARNING',
      severity: 'medium',
      message: `Disk block usage reached ${blockUsedPct}% on node "${nodeId}".`,
      fix: 'Run orphan PR-preview reaper and enforce Docker json-file log rotation.'
    });
  }

  // 3. Postgres pg_wal runaway / abandoned inactive replication slots
  const walThresholdGb = Math.max(5, Math.round(diskTotalGb * 0.15 * 10) / 10);
  if (inactiveReplicationSlots > 0 || pgWalGb >= walThresholdGb) {
    alerts.push({
      code: 'PG_WAL_SLOT_RUNAWAY',
      severity: 'critical',
      message: `Postgres pg_wal runaway risk on "${nodeId}": ${inactiveReplicationSlots} inactive replication slot(s) and ${pgWalGb} GB WAL retained.`,
      fix: 'Inspect pg_replication_slots, drop abandoned inactive slots via pg_drop_replication_slot(), and set max_slot_wal_keep_size.'
    });
  }

  // 4. Unrotated Docker json-file logs
  const logThresholdGb = Math.max(2, Math.round(diskTotalGb * 0.05 * 10) / 10);
  if (containerLogGb >= logThresholdGb) {
    alerts.push({
      code: 'UNROTATED_DOCKER_LOGS',
      severity: 'high',
      message: `Container JSON logs consume ${containerLogGb} GB on "${nodeId}" (exceeds ${logThresholdGb} GB quota).`,
      fix: 'Deploy /etc/docker/daemon.json with json-file max-size=10m, max-file=3 and reload Docker.'
    });
  }

  // 5. overlay2 layer bloat
  const overlayThresholdGb = Math.max(20, Math.round(diskTotalGb * 0.35 * 10) / 10);
  if (overlay2Gb >= overlayThresholdGb) {
    alerts.push({
      code: 'OVERLAY2_BLOAT',
      severity: 'high',
      message: `Docker overlay2 storage consumes ${overlay2Gb} GB (${Math.round((overlay2Gb / diskTotalGb) * 100)}% of ${diskTotalGb} GB disk).`,
      fix: 'Run BuildKit cache prune, reap closed PR previews, and apply container/volume storage quotas.'
    });
  }

  const criticalCount = alerts.filter((a) => a.severity === 'critical').length;
  const status = criticalCount > 0 ? 'CRITICAL' : (alerts.length > 0 ? 'WARNING' : 'HEALTHY');
  const safe = criticalCount === 0;
  const alertCodes = alerts.map((a) => a.code);
  const daemonLogQuota = generateDaemonLogQuotaConfig();
  const evaluatedAt = new Date().toISOString();

  const report = {
    ok: true,
    id: `disk_${crypto.randomBytes(5).toString('hex')}`,
    nodeId,
    status,
    safe,
    blockUsedPct,
    inodeUsedPct,
    overlay2Gb,
    containerLogGb,
    pgWalGb,
    inactiveReplicationSlots,
    diskTotalGb,
    alerts,
    alertCodes,
    daemonLogQuota,
    evaluatedAt
  };

  if (opts.persist !== false) {
    const store = loadStore();
    store.reports.push({
      id: report.id,
      nodeId,
      status,
      safe,
      blockUsedPct,
      inodeUsedPct,
      overlay2Gb,
      containerLogGb,
      pgWalGb,
      inactiveReplicationSlots,
      alertCodes,
      evaluatedAt
    });
    saveStore(store);
  }

  return report;
}

/**
 * Construye un plan de remediación de presión de disco (por defecto `dryRun: true`)
 * usando arreglos `argv` cero-shell y parches `/etc/docker/daemon.json`.
 *
 * @param {{ evaluation: ReturnType<typeof evaluateDiskPressure>, dryRun?: boolean }} input
 */
function planPressureRemediation(input) {
  const opts = input || /** @type {any} */ ({});
  const ev = opts.evaluation || evaluateDiskPressure({ persist: false });
  const dryRun = opts.dryRun !== undefined ? Boolean(opts.dryRun) : true;
  const codes = new Set(Array.isArray(ev.alertCodes) ? ev.alertCodes : []);
  const daemonLogQuota = ev.daemonLogQuota || generateDaemonLogQuotaConfig();

  /** @type {Array<{ order: number, code: string, action: string, argv: string[] | null, estimatedRecoveryGb: number }>} */
  const actions = [];

  if (codes.has('PG_WAL_SLOT_RUNAWAY')) {
    actions.push({
      order: actions.length + 1,
      code: 'PG_WAL_SLOT_RUNAWAY',
      action: 'Audit pg_replication_slots where active=false, drop abandoned slots, and enforce max_slot_wal_keep_size=4GB.',
      argv: ['psql', '-c', "SELECT slot_name, active, pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) FROM pg_replication_slots WHERE NOT active;"],
      estimatedRecoveryGb: Math.max(0, Math.round((Number(ev.pgWalGb) || 0) * 0.75 * 10) / 10)
    });
  }
  if (codes.has('UNROTATED_DOCKER_LOGS') || codes.has('BLOCK_PRESSURE_CRITICAL')) {
    actions.push({
      order: actions.length + 1,
      code: 'UNROTATED_DOCKER_LOGS',
      action: 'Apply /etc/docker/daemon.json json-file log rotation (max-size=10m, max-file=3) to cap future log growth.',
      argv: null,
      estimatedRecoveryGb: Math.max(0, Math.round((Number(ev.containerLogGb) || 0) * 0.8 * 10) / 10)
    });
  }
  if (codes.has('INODE_EXHAUSTION_CRITICAL') || codes.has('INODE_PRESSURE_WARNING') || codes.has('OVERLAY2_BLOAT')) {
    actions.push({
      order: actions.length + 1,
      code: codes.has('INODE_EXHAUSTION_CRITICAL') ? 'INODE_EXHAUSTION_CRITICAL' : 'OVERLAY2_BLOAT',
      action: 'Prune aged BuildKit build cache & dangling layers (>72h) while shielding active Compose sidecar images.',
      argv: ['docker', 'builder', 'prune', '--filter', 'until=72h', '--force'],
      estimatedRecoveryGb: Math.max(0, Math.round((Number(ev.overlay2Gb) || 0) * 0.35 * 10) / 10)
    });
  }
  if (codes.has('BLOCK_PRESSURE_CRITICAL') || codes.has('BLOCK_PRESSURE_WARNING')) {
    actions.push({
      order: actions.length + 1,
      code: 'BLOCK_PRESSURE_CRITICAL',
      action: 'Trigger Orphan PR-Preview Auto-Reaper (dry-run review) and enforce volume blkio/storage quotas.',
      argv: ['docker', 'system', 'df', '--format', '{{json .}}'],
      estimatedRecoveryGb: 2
    });
  }

  const totalEstimatedRecoveryGb = Math.round(
    actions.reduce((sum, a) => sum + a.estimatedRecoveryGb, 0) * 10
  ) / 10;

  return {
    ok: true,
    dryRun,
    nodeId: ev.nodeId || 'local',
    status: ev.status || 'HEALTHY',
    actionCount: actions.length,
    actions,
    totalEstimatedRecoveryGb,
    daemonLogQuota,
    plannedAt: new Date().toISOString()
  };
}

/**
 * Lista reportes históricos de presión de disco (más recientes primero).
 * @param {string} [nodeId]
 */
function listDiskPressureReports(nodeId) {
  const store = loadStore();
  const cleanId = nodeId ? String(nodeId).trim() : '';
  const items = cleanId
    ? store.reports.filter((r) => r.nodeId === cleanId)
    : store.reports;
  return [...items].reverse();
}

module.exports = {
  evaluateDiskPressure,
  generateDaemonLogQuotaConfig,
  planPressureRemediation,
  listDiskPressureReports
};
