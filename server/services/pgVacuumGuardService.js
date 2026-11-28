const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * PostgreSQL Autovacuum, 32-Bit XID Wraparound & Bloat Guard (100% Zero-Dep).
 *
 * Detecta tempranamente los modos de fallo más destructivos en Postgres:
 *  - `XID_WRAPAROUND_IMMINENT` (`age(datfrozenxid) >= 1.5B` hacia el bloqueo a 2B)
 *  - `XID_WRAPAROUND_WARNING` (`>= 1.0B`)
 *  - `IDLE_IN_TX_XMIN_PIN` (`idle in transaction >= 300s` anclando el horizonte `xmin`)
 *  - `MISSING_IDLE_TX_TIMEOUT` (`idle_in_transaction_session_timeout <= 0`)
 *  - `AUTOVACUUM_DISABLED_TABLE` (`autovacuum_enabled = false`)
 *  - `TABLE_BLOAT_HIGH` (`deadTuplePct >= 30%`)
 *  - `INACTIVE_REPLICATION_SLOT_PIN` (slots inactivos reteniendo `xmin`/`pg_wal`)
 *
 * Invariante crítica de recuperación: emite exclusivamente operaciones online
 * (`VACUUM (VERBOSE, FREEZE, ANALYZE)`, `pg_terminate_backend`, timeouts) —
 * JAMÁS emite bloqueos exclusivos destructivos (`usesVacuumFull: false`).
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/pg-vacuum-guard.json`.
 */

const MAX_AUDITS = 200;
const XID_WRAPAROUND_LIMIT = 2_000_000_000;
const XID_WARNING_THRESHOLD = 1_000_000_000;
const XID_CRITICAL_THRESHOLD = 1_500_000_000;

/**
 * Resuelve dinámicamente la ruta a `pg-vacuum-guard.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'pg-vacuum-guard.json')
    : path.join(base, 'data', 'pg-vacuum-guard.json');
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
 * Carga auditorías desde disco (sin mutar si no existe).
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
 * Sanitiza un identificador SQL simple (`schema.table` o `table`).
 * @param {string} raw
 */
function sanitizeSqlIdent(raw) {
  const clean = String(raw || '').replace(/[^a-zA-Z0-9_.]/g, '');
  return clean || 'public.app_table';
}

/**
 * Genera SQL online seguro para descongelar XIDs y restaurar autovacuum (JAMÁS bloquea tablas).
 *
 * @param {{
 *   databaseName?: string,
 *   autovacuumDisabledTables?: string[],
 *   idleInTxTimeoutMs?: number,
 *   dryRun?: boolean
 * }} [options]
 */
function renderHardenedVacuumSql(options = {}) {
  const opts = options || {};
  const dbName = sanitizeSqlIdent(opts.databaseName || 'app_prod');
  const tables = Array.isArray(opts.autovacuumDisabledTables)
    ? opts.autovacuumDisabledTables.map((t) => sanitizeSqlIdent(String(t))).filter(Boolean)
    : [];
  const timeoutSec = Math.max(15, Math.min(300, Math.round((Number(opts.idleInTxTimeoutMs) > 0 ? Number(opts.idleInTxTimeoutMs) : 60000) / 1000)));
  const dryRun = opts.dryRun !== undefined ? Boolean(opts.dryRun) : true;

  const lines = [
    `-- Culkibo Online PostgreSQL Wraparound & Autovacuum Recovery SQL (database: ${dbName})`,
    '-- Safe non-locking freeze pass (zero exclusive table rewrite).',
    'SET statement_timeout = 0;',
    "SET maintenance_work_mem = '512MB';",
    `ALTER DATABASE ${dbName} SET idle_in_transaction_session_timeout = '${timeoutSec}s';`,
    '',
    '-- 1. Terminate idle-in-transaction sessions pinning the xmin horizon (> 5m):',
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle in transaction' AND now() - state_change > interval '5 minutes';"
  ];

  if (tables.length > 0) {
    lines.push('', '-- 2. Re-enable autovacuum on disabled tables & run online freeze:');
    for (const tbl of tables) {
      lines.push(`ALTER TABLE ${tbl} SET (autovacuum_enabled = true);`);
      lines.push(`VACUUM (VERBOSE, FREEZE, ANALYZE) ${tbl};`);
    }
  } else {
    lines.push('', '-- 2. Run online database-wide freeze pass:');
    lines.push('VACUUM (VERBOSE, FREEZE, ANALYZE);');
  }

  lines.push(
    '',
    '-- 3. Verify remaining XID age after online vacuum:',
    'SELECT datname, age(datfrozenxid) AS xid_age FROM pg_database ORDER BY xid_age DESC;'
  );

  return {
    ok: true,
    dryRun,
    databaseName: dbName,
    usesVacuumFull: false,
    recoverySql: lines.join('\n')
  };
}

/**
 * Audita la salud de Autovacuum, edad XID 32-bit, sesiones `idle in transaction` y bloat.
 *
 * @param {{
 *   databaseName?: string,
 *   xidAge?: number,
 *   maxTableXidAge?: number,
 *   idleInTxSec?: number,
 *   deadTuplePct?: number,
 *   autovacuumDisabledTables?: string[],
 *   inactiveSlots?: number | string[],
 *   idleInTxTimeoutMs?: number,
 *   persist?: boolean
 * }} [input]
 */
function auditPgVacuumHealth(input = {}) {
  const opts = input || {};
  const databaseName = String(opts.databaseName || 'postgres').trim() || 'postgres';
  const xidAge = Math.max(0, Math.floor(Number(opts.xidAge) || 0));
  const maxTableXidAge = Math.max(0, Math.floor(Number(opts.maxTableXidAge) || 0));
  const effectiveXidAge = Math.max(xidAge, maxTableXidAge);
  const pctToLockout = Math.min(100, Math.round((effectiveXidAge / XID_WRAPAROUND_LIMIT) * 1000) / 10);
  const idleInTxSec = Math.max(0, Number(opts.idleInTxSec) || 0);
  const deadTuplePct = Math.max(0, Math.min(100, Number(opts.deadTuplePct) || 0));
  const autovacuumDisabledTables = Array.isArray(opts.autovacuumDisabledTables)
    ? opts.autovacuumDisabledTables.map((t) => String(t || '').trim()).filter(Boolean)
    : [];
  const inactiveSlotCount = Array.isArray(opts.inactiveSlots)
    ? opts.inactiveSlots.length
    : Math.max(0, Math.floor(Number(opts.inactiveSlots) || 0));
  const idleInTxTimeoutMs = opts.idleInTxTimeoutMs !== undefined ? Number(opts.idleInTxTimeoutMs) : 60000;

  /** @type {Array<{ code: string, severity: 'critical' | 'high' | 'medium', message: string, fix: string }>} */
  const findings = [];

  // 1. 32-bit XID wraparound thresholds
  if (effectiveXidAge >= XID_CRITICAL_THRESHOLD) {
    findings.push({
      code: 'XID_WRAPAROUND_IMMINENT',
      severity: 'critical',
      message: `Database "${databaseName}" XID age reached ${effectiveXidAge.toLocaleString('en-US')} (${pctToLockout}% of 2B write-lockout limit)!`,
      fix: 'Terminate xmin blockers and run online VACUUM (VERBOSE, FREEZE, ANALYZE) immediately.'
    });
  } else if (effectiveXidAge >= XID_WARNING_THRESHOLD) {
    findings.push({
      code: 'XID_WRAPAROUND_WARNING',
      severity: 'high',
      message: `Database "${databaseName}" XID age is ${effectiveXidAge.toLocaleString('en-US')} (${pctToLockout}% of 2B wraparound limit).`,
      fix: 'Raise autovacuum_freeze_max_age monitoring and tune autovacuum_vacuum_cost_limit.'
    });
  }

  // 2. Idle in transaction pinning xmin horizon
  if (idleInTxSec >= 300) {
    findings.push({
      code: 'IDLE_IN_TX_XMIN_PIN',
      severity: 'critical',
      message: `Session idle in transaction for ${idleInTxSec}s (>= 300s) is pinning global xmin and blocking autovacuum tuple cleanup.`,
      fix: 'Terminate stale idle-in-transaction backends with pg_terminate_backend() and enforce idle_in_transaction_session_timeout.'
    });
  }

  // 3. Missing idle_in_transaction_session_timeout
  if (!Number.isFinite(idleInTxTimeoutMs) || idleInTxTimeoutMs <= 0) {
    findings.push({
      code: 'MISSING_IDLE_TX_TIMEOUT',
      severity: 'high',
      message: 'idle_in_transaction_session_timeout is 0 (disabled), allowing leaked ORM transactions to pin xmin indefinitely.',
      fix: "Set idle_in_transaction_session_timeout = '60s' at database or role level."
    });
  }

  // 4. Forgotten autovacuum_enabled = false tables
  if (autovacuumDisabledTables.length > 0) {
    findings.push({
      code: 'AUTOVACUUM_DISABLED_TABLE',
      severity: 'critical',
      message: `Autovacuum is explicitly disabled on ${autovacuumDisabledTables.length} table(s): ${autovacuumDisabledTables.join(', ')}.`,
      fix: `Re-enable via ALTER TABLE <tbl> SET (autovacuum_enabled = true) and run online VACUUM VERBOSE.`
    });
  }

  // 5. High dead-tuple bloat
  if (deadTuplePct >= 30) {
    findings.push({
      code: 'TABLE_BLOAT_HIGH',
      severity: 'high',
      message: `Dead-tuple ratio reached ${deadTuplePct}% (>= 30%), degrading index scans and buffer cache hit ratio.`,
      fix: 'Lower autovacuum_vacuum_scale_factor (e.g. 0.05) on hot tables and run online VACUUM (VERBOSE, ANALYZE) or pg_repack.'
    });
  }

  // 6. Inactive replication slots pinning xmin/WAL
  if (inactiveSlotCount > 0) {
    findings.push({
      code: 'INACTIVE_REPLICATION_SLOT_PIN',
      severity: 'critical',
      message: `${inactiveSlotCount} inactive replication slot(s) are pinning catalog_xmin and retaining pg_wal.`,
      fix: 'Drop abandoned inactive slots via pg_drop_replication_slot() and set max_slot_wal_keep_size.'
    });
  }

  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const safe = findings.length === 0;
  const blocked = !safe;
  const status = criticalCount > 0 ? 'CRITICAL' : (findings.length > 0 ? 'WARNING' : 'HEALTHY');
  const rendered = renderHardenedVacuumSql({ databaseName, autovacuumDisabledTables, idleInTxTimeoutMs, dryRun: true });
  const auditedAt = new Date().toISOString();

  const result = {
    ok: true,
    id: `vac_${crypto.randomBytes(5).toString('hex')}`,
    databaseName,
    safe,
    blocked,
    status,
    xidAge,
    maxTableXidAge,
    effectiveXidAge,
    pctToLockout,
    idleInTxSec,
    deadTuplePct,
    autovacuumDisabledTables,
    inactiveSlotCount,
    findings,
    findingCodes: findings.map((f) => f.code),
    usesVacuumFull: false,
    recoverySql: rendered.recoverySql,
    auditedAt
  };

  if (opts.persist !== false) {
    const store = loadStore();
    store.audits.push({
      id: result.id,
      databaseName,
      safe,
      status,
      effectiveXidAge,
      pctToLockout,
      findingCodes: result.findingCodes,
      auditedAt
    });
    saveStore(store);
  }

  return result;
}

/**
 * Construye un plan ordenado de recuperación online de XID/Autovacuum (`dryRun: true` por defecto,
 * acepta tanto una auditoría previa como telemetría cruda; `usesVacuumFull: false` siempre).
 *
 * @param {any} input
 */
function planWraparoundRecovery(input = {}) {
  const opts = input || {};
  const dryRun = opts.dryRun !== undefined ? Boolean(opts.dryRun) : true;
  const audit = (opts.findings && Array.isArray(opts.findings) && opts.databaseName)
    ? opts
    : auditPgVacuumHealth({ ...opts, persist: false });

  const codes = new Set(Array.isArray(audit.findingCodes) ? audit.findingCodes : []);
  /** @type {Array<{ order: number, phase: string, action: string }>} */
  const steps = [];

  if (codes.has('IDLE_IN_TX_XMIN_PIN') || codes.has('MISSING_IDLE_TX_TIMEOUT')) {
    steps.push({
      order: steps.length + 1,
      phase: 'unpin-xmin',
      action: 'Terminate stale idle-in-transaction backends (>5m) and enforce idle_in_transaction_session_timeout = 60s.'
    });
  }
  if (codes.has('INACTIVE_REPLICATION_SLOT_PIN')) {
    steps.push({
      order: steps.length + 1,
      phase: 'drop-stale-slots',
      action: 'Audit pg_replication_slots where active = false and drop abandoned slots pinning catalog_xmin.'
    });
  }
  if (codes.has('AUTOVACUUM_DISABLED_TABLE')) {
    steps.push({
      order: steps.length + 1,
      phase: 'reenable-autovacuum',
      action: `Re-enable autovacuum_enabled = true on: ${(audit.autovacuumDisabledTables || []).join(', ')}.`
    });
  }
  steps.push({
    order: steps.length + 1,
    phase: 'online-vacuum-freeze',
    action: 'Execute non-locking VACUUM (VERBOSE, FREEZE, ANALYZE) with increased maintenance_work_mem (zero exclusive table rewrite).'
  });

  const sqlRes = renderHardenedVacuumSql({
    databaseName: audit.databaseName,
    autovacuumDisabledTables: audit.autovacuumDisabledTables,
    dryRun
  });

  return {
    ok: true,
    dryRun,
    databaseName: audit.databaseName,
    status: audit.status,
    usesVacuumFull: false,
    steps,
    recoverySql: sqlRes.recoverySql,
    findingCodes: audit.findingCodes,
    plannedAt: new Date().toISOString()
  };
}

/**
 * Lista auditorías de Autovacuum/XID almacenadas (más recientes primero).
 * @param {string} [databaseName]
 */
function listVacuumAudits(databaseName) {
  const store = loadStore();
  const cleanDb = databaseName ? String(databaseName).trim() : '';
  const items = cleanDb
    ? store.audits.filter((a) => a.databaseName === cleanDb)
    : store.audits;
  return [...items].reverse();
}

module.exports = {
  auditPgVacuumHealth,
  planWraparoundRecovery,
  renderHardenedVacuumSql,
  listVacuumAudits
};
