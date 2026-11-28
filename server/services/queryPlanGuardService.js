const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Database Query-Plan & Connection Pool Exhaustion Regression Guard (100% Zero-Dep).
 *
 * Inspirado en PgBouncer v1.25+, Prisma 7 connection-pool guardrails y pganalyze/pgMustard:
 *  - Recorre recursivamente árboles Postgres `EXPLAIN (ANALYZE, FORMAT JSON)` detectando:
 *      * `SEQ_SCAN_REGRESSION` (`Seq Scan` sobre tablas grandes o costes excesivos)
 *      * `ROW_ESTIMATE_SKEW` (desviación >10x entre `Plan Rows` y `Actual Rows` → `ANALYZE` obsoleto)
 *      * `DISK_SORT_SPILL` (`Sort Space Type: Disk`)
 *  - `detectNPlusOne`: normaliza trazas SQL parametrizadas para detectar `>= 20` consultas idénticas (`N_PLUS_ONE_DETECTED`).
 *  - `auditPoolBudget`: impone `replicas * poolSizePerReplica <= maxConnections - reservedSuperuser`
 *    (`POOL_OVERCOMMIT`) e `idleTimeoutSec > 0` (`MISSING_IDLE_TIMEOUT`, curando fugas de Prisma 7).
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/query-plan-guard.json`.
 */

const MAX_HISTORY_ENTRIES = 200;

/**
 * Resuelve dinámicamente la ruta a `query-plan-guard.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'query-plan-guard.json')
    : path.join(base, 'data', 'query-plan-guard.json');
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
 * Carga historial desde disco (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, history: any[] }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), history: [] };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && Array.isArray(parsed.history)) {
      return parsed;
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), history: [] };
}

/**
 * Guarda historial de forma atómica (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, history: any[] }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  if (store.history.length > MAX_HISTORY_ENTRIES) {
    store.history = store.history.slice(-MAX_HISTORY_ENTRIES);
  }
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Recorre recursivamente un árbol `EXPLAIN (ANALYZE, FORMAT JSON)` de PostgreSQL.
 *
 * @param {{
 *   planJson: any,
 *   sql?: string,
 *   tableRowThreshold?: number,
 *   costThreshold?: number
 * }} input
 */
function analyzeExplainPlan(input) {
  const opts = input || /** @type {any} */ ({});
  const tableRowThreshold = Math.max(1, Number(opts.tableRowThreshold ?? 10000) || 10000);
  const costThreshold = Math.max(1, Number(opts.costThreshold ?? 50000) || 50000);

  let parsed = opts.planJson;
  if (typeof parsed === 'string') {
    try {
      parsed = JSON.parse(parsed);
    } catch (e) {
      return {
        ok: false,
        safe: false,
        nodesAnalyzed: 0,
        totalCost: 0,
        findings: [{ code: 'INVALID_EXPLAIN_JSON', severity: 'high', relation: null, message: 'planJson is not valid JSON.' }],
        recommendations: ['Run EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) and pass the JSON output.']
      };
    }
  }

  /** @type {any[]} */
  const roots = [];
  if (Array.isArray(parsed)) {
    for (const item of parsed) {
      if (item && item.Plan) roots.push(item.Plan);
      else if (item && item['Node Type']) roots.push(item);
    }
  } else if (parsed && typeof parsed === 'object') {
    if (parsed.Plan) roots.push(parsed.Plan);
    else if (parsed['Node Type']) roots.push(parsed);
  }

  /** @type {Array<{ code: string, severity: 'critical' | 'high' | 'medium', nodeType: string, relation: string | null, message: string, fix: string }>} */
  const findings = [];
  /** @type {Set<string>} */
  const recommendations = new Set();
  let nodesAnalyzed = 0;
  let totalCost = 0;

  /**
   * @param {any} node
   * @param {number} depth
   */
  const walk = (node, depth) => {
    if (!node || typeof node !== 'object' || depth > 64) return;
    nodesAnalyzed++;

    const nodeType = String(node['Node Type'] || node.nodeType || 'Unknown');
    const relation = node['Relation Name'] || node.relationName || null;
    const planRows = Number(node['Plan Rows'] ?? node.planRows ?? 0) || 0;
    const hasActual = node['Actual Rows'] !== undefined || node.actualRows !== undefined;
    const actualRows = hasActual ? (Number(node['Actual Rows'] ?? node.actualRows ?? 0) || 0) : planRows;
    const nodeCost = Number(node['Total Cost'] ?? node.totalCost ?? 0) || 0;
    if (depth === 0) totalCost = Math.max(totalCost, nodeCost);

    // 1. SEQ_SCAN_REGRESSION
    if (nodeType.toLowerCase() === 'seq scan') {
      const effectiveRows = Math.max(actualRows, planRows);
      if (effectiveRows >= tableRowThreshold || nodeCost >= costThreshold) {
        const relLabel = relation || 'table';
        const fix = `Add a targeted B-tree/GIN index via CREATE INDEX CONCURRENTLY ON ${relLabel} (...) to eliminate full table Seq Scan.`;
        findings.push({
          code: 'SEQ_SCAN_REGRESSION',
          severity: 'critical',
          nodeType,
          relation,
          message: `Sequential scan on "${relLabel}" scanned ${effectiveRows} rows (cost=${nodeCost}, threshold=${tableRowThreshold}).`,
          fix
        });
        recommendations.add(fix);
      }
    }

    // 2. ROW_ESTIMATE_SKEW (>10x estimated vs actual row count difference)
    if (hasActual && Math.abs(actualRows - planRows) >= 100) {
      const ratio = Math.max(actualRows, 1) / Math.max(planRows, 1);
      const invRatio = Math.max(planRows, 1) / Math.max(actualRows, 1);
      const skew = Math.max(ratio, invRatio);
      if (skew > 10) {
        const relLabel = relation || nodeType;
        const fix = `Run ANALYZE ${relation || '<table_name>'}; (and consider CREATE STATISTICS for correlated columns) to refresh planner estimates.`;
        findings.push({
          code: 'ROW_ESTIMATE_SKEW',
          severity: 'high',
          nodeType,
          relation,
          message: `Planner row estimate skew of ${Math.round(skew * 10) / 10}x on "${relLabel}" (Plan Rows=${planRows}, Actual Rows=${actualRows}).`,
          fix
        });
        recommendations.add(fix);
      }
    }

    // 3. DISK_SORT_SPILL
    const sortSpaceType = String(node['Sort Space Type'] ?? node.sortSpaceType ?? '').toLowerCase();
    if (nodeType.toLowerCase() === 'sort' && sortSpaceType === 'disk') {
      const sortUsedKb = Number(node['Sort Space Used'] ?? node.sortSpaceUsed ?? 0) || 0;
      const fix = 'Add a composite index matching ORDER BY columns or increase per-session work_mem to keep sorts in memory.';
      findings.push({
        code: 'DISK_SORT_SPILL',
        severity: 'high',
        nodeType,
        relation,
        message: `Sort node spilled ${sortUsedKb} kB to disk (Sort Space Type = Disk).`,
        fix
      });
      recommendations.add(fix);
    }

    if (Array.isArray(node.Plans)) {
      for (const child of node.Plans) walk(child, depth + 1);
    }
  };

  for (const r of roots) walk(r, 0);

  return {
    ok: true,
    safe: findings.length === 0,
    sql: String(opts.sql || ''),
    nodesAnalyzed,
    totalCost,
    findings,
    recommendations: Array.from(recommendations)
  };
}

/**
 * Audita el presupuesto total de conexiones de pool (replicas × poolSize <= maxConnections - reservedSuperuser)
 * y valida `idleTimeoutSec > 0` (curing Prisma 7 / PgBouncer starvation).
 *
 * @param {{
 *   maxConnections?: number,
 *   reservedSuperuser?: number,
 *   replicas?: number,
 *   poolSizePerReplica?: number,
 *   pgbouncerMode?: 'transaction' | 'session' | 'statement' | 'none' | string,
 *   idleTimeoutSec?: number
 * }} [input]
 */
function auditPoolBudget(input = {}) {
  const opts = input || {};
  const maxConnections = Math.max(1, Math.floor(Number(opts.maxConnections ?? 100) || 100));
  const reservedSuperuser = Math.max(0, Math.floor(Number(opts.reservedSuperuser ?? 5)));
  const replicas = Math.max(1, Math.floor(Number(opts.replicas ?? 1) || 1));
  const poolSizePerReplica = Math.max(1, Math.floor(Number(opts.poolSizePerReplica ?? 10) || 10));
  const pgbouncerMode = String(opts.pgbouncerMode || 'transaction').trim().toLowerCase();
  const idleTimeoutSec = Number(opts.idleTimeoutSec ?? 30);

  const availableConnections = Math.max(0, maxConnections - reservedSuperuser);
  const requestedConnections = replicas * poolSizePerReplica;
  const utilizationPct = availableConnections > 0
    ? Math.round((requestedConnections / availableConnections) * 1000) / 10
    : 100;
  const recommendedPoolSizePerReplica = Math.max(1, Math.floor((availableConnections * 0.85) / replicas));

  /** @type {Array<{ code: string, severity: string, message: string, fix: string }>} */
  const blockers = [];
  /** @type {Array<{ code: string, severity: string, message: string }>} */
  const warnings = [];

  if (requestedConnections > availableConnections) {
    blockers.push({
      code: 'POOL_OVERCOMMIT',
      severity: 'critical',
      message: `${replicas} replicas × ${poolSizePerReplica} conns = ${requestedConnections} exceeds ${availableConnections} available DB slots (max=${maxConnections}, reserved=${reservedSuperuser}).`,
      fix: `Lower poolSizePerReplica to <= ${recommendedPoolSizePerReplica} or place PgBouncer in transaction pooling mode in front of Postgres.`
    });
  }

  if (!Number.isFinite(idleTimeoutSec) || idleTimeoutSec <= 0) {
    blockers.push({
      code: 'MISSING_IDLE_TIMEOUT',
      severity: 'high',
      message: `Pool idleTimeoutSec is ${idleTimeoutSec} — idle connections never recycle, risking Prisma 7 / serverless pool exhaustion.`,
      fix: 'Set idleTimeoutSec between 15 and 60 seconds (e.g. idleTimeoutMillis: 30000).'
    });
  }

  if (pgbouncerMode === 'transaction') {
    warnings.push({
      code: 'PGBOUNCER_TRANSACTION_MODE_NOTE',
      severity: 'info',
      message: 'PgBouncer transaction mode requires max_prepared_statements > 0 (PgBouncer >= 1.21) or pgbouncer=true on ORM URLs.'
    });
  } else if (pgbouncerMode === 'none' && requestedConnections > Math.floor(availableConnections * 0.7)) {
    warnings.push({
      code: 'HIGH_POOL_UTILIZATION',
      severity: 'medium',
      message: `Direct DB pool utilization is ${utilizationPct}% without PgBouncer multiplexing.`
    });
  }

  return {
    ok: true,
    safe: blockers.length === 0,
    maxConnections,
    reservedSuperuser,
    availableConnections,
    replicas,
    poolSizePerReplica,
    requestedConnections,
    utilizationPct,
    recommendedPoolSizePerReplica,
    pgbouncerMode,
    idleTimeoutSec,
    blockers,
    warnings
  };
}

/**
 * Normaliza una consulta SQL a una huella canónica para detectar patrones N+1.
 * @param {string} rawSql
 */
function fingerprintSql(rawSql) {
  return String(rawSql || '')
    .replace(/'(?:''|[^'])*'/g, '$S')
    .replace(/\$\d+/g, '$P')
    .replace(/\?/g, '$P')
    .replace(/\b\d+(?:\.\d+)?\b/g, '$N')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

/**
 * Detecta patrones N+1 (`>= threshold` ejecuciones repetidas de una misma consulta parametrizada).
 *
 * @param {Array<string | { sql?: string, query?: string, durationMs?: number }>} queryTrace
 * @param {{ threshold?: number }} [options]
 */
function detectNPlusOne(queryTrace, options = {}) {
  const list = Array.isArray(queryTrace) ? queryTrace : [];
  const threshold = Math.max(2, Math.floor(Number((options && options.threshold) ?? 20) || 20));

  /** @type {Map<string, { fingerprint: string, sampleSql: string, count: number, totalDurationMs: number }>} */
  const counts = new Map();

  for (const item of list) {
    const rawSql = typeof item === 'string'
      ? item
      : String((item && (item.sql || item.query)) || '');
    if (!rawSql.trim()) continue;
    const fp = fingerprintSql(rawSql);
    if (!fp) continue;
    const dur = (item && typeof item === 'object' && Number(item.durationMs) > 0) ? Number(item.durationMs) : 0;
    const cur = counts.get(fp);
    if (cur) {
      cur.count++;
      cur.totalDurationMs += dur;
    } else {
      counts.set(fp, { fingerprint: fp, sampleSql: rawSql.trim(), count: 1, totalDurationMs: dur });
    }
  }

  const offenders = Array.from(counts.values())
    .filter((entry) => entry.count >= threshold)
    .sort((a, b) => b.count - a.count)
    .map((entry) => ({
      code: 'N_PLUS_ONE_DETECTED',
      fingerprint: entry.fingerprint,
      sampleSql: entry.sampleSql,
      count: entry.count,
      totalDurationMs: Math.round(entry.totalDurationMs * 100) / 100,
      fix: 'Batch lookups using WHERE id = ANY($1) / DataLoader / JOIN instead of issuing per-row queries inside a loop.'
    }));

  return {
    ok: true,
    detected: offenders.length > 0,
    code: offenders.length > 0 ? 'N_PLUS_ONE_DETECTED' : 'CLEAN',
    threshold,
    totalQueries: list.length,
    offenders
  };
}

/**
 * Compuerta combinada pre-cutover: ejecuta EXPLAIN + Pool Budget + N+1 y persiste auditoría.
 *
 * @param {{
 *   projectId?: string,
 *   planJson?: any,
 *   sql?: string,
 *   poolConfig?: any,
 *   queryTrace?: any[],
 *   persist?: boolean
 * }} [input]
 */
function evaluateDbCutoverGate(input = {}) {
  const opts = input || {};
  const projectId = opts.projectId ? String(opts.projectId).trim() : null;

  const explainReport = opts.planJson !== undefined && opts.planJson !== null
    ? analyzeExplainPlan({ planJson: opts.planJson, sql: opts.sql })
    : null;
  const poolReport = opts.poolConfig && typeof opts.poolConfig === 'object'
    ? auditPoolBudget(opts.poolConfig)
    : null;
  const nPlusOneReport = Array.isArray(opts.queryTrace)
    ? detectNPlusOne(opts.queryTrace)
    : null;

  /** @type {Array<{ code: string, message: string }>} */
  const blockers = [];
  if (explainReport && !explainReport.safe) {
    for (const f of explainReport.findings) blockers.push({ code: f.code, message: f.message });
  }
  if (poolReport && !poolReport.safe) {
    for (const b of poolReport.blockers) blockers.push({ code: b.code, message: b.message });
  }
  if (nPlusOneReport && nPlusOneReport.detected) {
    for (const o of nPlusOneReport.offenders) {
      blockers.push({ code: 'N_PLUS_ONE_DETECTED', message: `Repeated query executed ${o.count} times: ${o.sampleSql.slice(0, 80)}` });
    }
  }

  const allowed = blockers.length === 0;
  const blockerCodes = Array.from(new Set(blockers.map((b) => b.code)));
  const evaluatedAt = new Date().toISOString();

  if (opts.persist !== false && projectId) {
    const store = loadStore();
    store.history.push({
      id: `qguard_${crypto.randomBytes(5).toString('hex')}`,
      projectId,
      allowed,
      blockerCodes,
      blockerCount: blockers.length,
      evaluatedAt
    });
    saveStore(store);
  }

  return {
    ok: true,
    projectId,
    allowed,
    blockerCodes,
    blockers,
    explainReport,
    poolReport,
    nPlusOneReport,
    evaluatedAt
  };
}

/**
 * Lista historial de evaluaciones del Query/Pool Guard (más recientes primero).
 * @param {string} [projectId]
 */
function listQueryGuardHistory(projectId) {
  const store = loadStore();
  const cleanId = projectId ? String(projectId).trim() : '';
  const items = cleanId
    ? store.history.filter((h) => h.projectId === cleanId)
    : store.history;
  return [...items].reverse();
}

module.exports = {
  analyzeExplainPlan,
  auditPoolBudget,
  detectNPlusOne,
  evaluateDbCutoverGate,
  listQueryGuardHistory
};
