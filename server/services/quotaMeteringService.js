const fs = require('fs');
const path = require('path');

const { atomicWriteJsonSync } = require('./ssrfGuard');

/**
 * Agency Multi-Tenant Quotas & CSV-Formula-Safe Billing Usage Ledger
 * (cierra `Dokploy CVE-2026-116068` & `CVE-2026-127212` con aislamiento ACL estricto por tenant).
 *
 * Garantías:
 *  - 0 dependencias npm externas, 0 invocaciones de shell, carga 100% perezosa.
 *  - Persistencia atómica (`0o600`) en `CULKIBO_DATA_DIR/data/quotas.json`.
 *  - Comprobación fail-closed (`checkQuotaAllowance`) de `containers`, `memoryMb`, `cpuCores`,
 *    `storageGb` y `bandwidthGbMo`.
 *  - Neutralización OWASP de inyección de fórmulas CSV (`=`, `+`, `-`, `@`, `\t`, `\r`)
 *    y escapado RFC-4180 en `escapeCsvCell` / `exportLedgerCsv`.
 */

const PROJECT_ID_RE = /^[a-zA-Z0-9_-]{1,80}$/;
const FORBIDDEN_PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const DEFAULT_QUOTA = Object.freeze({
  containers: 10,
  memoryMb: 4096,
  cpuCores: 4,
  storageGb: 50,
  bandwidthGbMo: 500
});

const DEFAULT_UNIT_RATES = Object.freeze({
  cpuCoreHourUsd: 0.012,
  ramGbHourUsd: 0.004,
  storageGbMoUsd: 0.08,
  bandwidthGbUsd: 0.01
});

const QUOTA_BOUNDS = Object.freeze({
  containers: { min: 1, max: 500 },
  memoryMb: { min: 128, max: 524288 },
  cpuCores: { min: 0.25, max: 256 },
  storageGb: { min: 1, max: 100000 },
  bandwidthGbMo: { min: 1, max: 1000000 }
});

/** @param {string | null} [overrideDir] */
function resolveDataDir(overrideDir = null) {
  if (overrideDir) return path.resolve(overrideDir);
  if (process.env.CULKIBO_DATA_DIR) {
    return path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data');
  }
  return path.resolve(__dirname, '..', '..', 'data');
}

/** @param {string} projectId */
function assertProjectId(projectId) {
  const clean = String(projectId || '').trim();
  if (!PROJECT_ID_RE.test(clean) || FORBIDDEN_PROTO_KEYS.has(clean)) {
    const err = new Error(`Identificador de proyecto inválido para cuota: "${clean.slice(0, 60)}"`);
    /** @type {any} */ (err).status = 400;
    throw err;
  }
  return clean;
}

/** @param {number} n */
function round2(n) {
  return Math.round(Math.max(0, Number(n) || 0) * 100) / 100;
}

/** @param {number} n */
function round3(n) {
  return Math.round(Math.max(0, Number(n) || 0) * 1000) / 1000;
}

/**
 * Escapa de forma segura una celda CSV cumpliendo RFC-4180 y neutralizando
 * inyección de fórmulas Excel/LibreOffice/Sheets (`=`, `+`, `-`, `@`, `\t`, `\r`).
 *
 * @param {any} val
 * @returns {string}
 */
function escapeCsvCell(val) {
  let str = val === null || val === undefined ? '' : String(val);
  // Neutralizar inyección de fórmulas (OWASP CSV Injection) prefijando apóstrofo
  if (/^[=+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }
  if (/[",\r\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

/**
 * Exporta un ledger de uso generado por `buildUsageLedger()` como CSV limpio
 * con encabezados, filas por proyecto y fila `TOTAL` (100% libre de inyección de fórmulas).
 *
 * @param {{ entries?: any[], periodDays?: number, totals?: any }} ledger
 * @returns {string}
 */
function exportLedgerCsv(ledger) {
  const entries = ledger && Array.isArray(ledger.entries) ? ledger.entries : [];
  const periodDays = Number(ledger && ledger.periodDays) || 30;
  const totals = (ledger && ledger.totals) || {
    totalDatabases: 0,
    cpuHours: 0,
    ramGbHours: 0,
    storageGb: 0,
    bandwidthGb: 0,
    estimatedCostUsd: 0
  };

  const headers = [
    'projectId',
    'projectName',
    'tenantId',
    'periodDays',
    'databases',
    'cpuHours',
    'ramGbHours',
    'storageGb',
    'bandwidthGb',
    'estimatedCostUsd'
  ];

  const rows = [headers.map(escapeCsvCell).join(',')];
  for (const e of entries) {
    rows.push([
      e.projectId,
      e.projectName,
      e.tenantId || 'default',
      periodDays,
      e.databaseCount || 0,
      e.cpuHours,
      e.ramGbHours,
      e.storageGb,
      e.bandwidthGb,
      e.estimatedCostUsd
    ].map(escapeCsvCell).join(','));
  }

  rows.push([
    'TOTAL',
    `${entries.length} project(s)`,
    'ALL',
    periodDays,
    totals.totalDatabases || 0,
    totals.cpuHours || 0,
    totals.ramGbHours || 0,
    totals.storageGb || 0,
    totals.bandwidthGb || 0,
    totals.estimatedCostUsd || 0
  ].map(escapeCsvCell).join(','));

  return rows.join('\n') + '\n';
}

class QuotaMeteringService {
  /**
   * @param {{ dataDir?: string | null, projectManager?: any, databaseManager?: any }} [opts]
   */
  constructor(opts = {}) {
    this._dataDirOverride = opts.dataDir || null;
    this._projectManagerOverride = opts.projectManager || null;
    this._databaseManagerOverride = opts.databaseManager || null;
    this._loaded = false;
    /** @type {{ version: number, quotas: Record<string, any> }} */
    this.state = { version: 1, quotas: Object.create(null) };
  }

  get dataDir() {
    return resolveDataDir(this._dataDirOverride);
  }

  get storeFile() {
    return path.join(this.dataDir, 'quotas.json');
  }

  _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;
    const bakFile = `${this.storeFile}.bak`;
    for (const candidate of [this.storeFile, bakFile]) {
      try {
        if (!fs.existsSync(candidate)) continue;
        const parsed = JSON.parse(fs.readFileSync(candidate, 'utf8'));
        if (parsed && typeof parsed === 'object' && parsed.quotas && typeof parsed.quotas === 'object') {
          const clean = Object.create(null);
          for (const [pid, q] of Object.entries(parsed.quotas)) {
            if (!FORBIDDEN_PROTO_KEYS.has(pid) && q && typeof q === 'object') {
              clean[pid] = q;
            }
          }
          this.state = { version: 1, quotas: clean };
          return;
        }
      } catch (e) {}
    }
    this.state = { version: 1, quotas: Object.create(null) };
  }

  _save() {
    this._ensureLoaded();
    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    if (fs.existsSync(this.storeFile)) {
      try { fs.copyFileSync(this.storeFile, `${this.storeFile}.bak`); } catch (e) {}
    }
    atomicWriteJsonSync(this.storeFile, this.state, 0o600);
  }

  /**
   * Configura o actualiza las cuotas de recursos de un proyecto/tenant.
   * @param {string} projectId
   * @param {{ containers?: number, memoryMb?: number, cpuCores?: number, storageGb?: number, bandwidthGbMo?: number, tenantId?: string, clientName?: string }} [patch]
   */
  setQuota(projectId, patch = {}) {
    const pid = assertProjectId(projectId);
    this._ensureLoaded();
    const current = this.state.quotas[pid] || { ...DEFAULT_QUOTA };
    const next = { ...current, projectId: pid };

    for (const key of /** @type {const} */ (['containers', 'memoryMb', 'cpuCores', 'storageGb', 'bandwidthGbMo'])) {
      if (patch[key] !== undefined && patch[key] !== null) {
        const val = Number(patch[key]);
        const bounds = QUOTA_BOUNDS[key];
        if (!Number.isFinite(val) || val < bounds.min || val > bounds.max) {
          const err = new Error(`Valor de cuota inválido para "${key}": ${patch[key]} (rango permitido ${bounds.min}..${bounds.max})`);
          /** @type {any} */ (err).status = 400;
          throw err;
        }
        next[key] = key === 'cpuCores' ? round2(val) : Math.round(val);
      }
    }
    if (patch.tenantId !== undefined) {
      next.tenantId = String(patch.tenantId || '').trim().slice(0, 64) || 'default';
    }
    if (patch.clientName !== undefined) {
      next.clientName = String(patch.clientName || '').trim().slice(0, 80);
    }
    next.updatedAt = new Date().toISOString();

    this.state.quotas[pid] = next;
    this._save();
    return { ...next, isDefault: false };
  }

  /**
   * Obtiene la cuota efectiva de un proyecto (personalizada o `DEFAULT_QUOTA`).
   * @param {string} projectId
   */
  getQuota(projectId) {
    const pid = assertProjectId(projectId);
    this._ensureLoaded();
    const custom = this.state.quotas[pid];
    if (!custom) {
      return { projectId: pid, ...DEFAULT_QUOTA, isDefault: true, updatedAt: null };
    }
    return { ...DEFAULT_QUOTA, ...custom, projectId: pid, isDefault: false };
  }

  /**
   * Lista cuotas configuradas filtrando estrictamente por `allowedProjectIds` cuando no es `null`.
   * @param {{ allowedProjectIds?: string[] | Set<string> | null }} [opts]
   */
  listQuotas(opts = {}) {
    this._ensureLoaded();
    const allowedSet = opts.allowedProjectIds != null
      ? new Set(Array.from(opts.allowedProjectIds).map(String))
      : null;

    const all = Object.values(this.state.quotas)
      .filter((q) => q && (!allowedSet || allowedSet.has(String(q.projectId))))
      .map((q) => ({ ...DEFAULT_QUOTA, ...q, isDefault: false }))
      .sort((a, b) => String(a.projectId).localeCompare(String(b.projectId)));

    return {
      ok: true,
      count: all.length,
      defaults: { ...DEFAULT_QUOTA },
      quotas: all
    };
  }

  /**
   * Evaluación fail-closed de cuotas: verifica que los recursos solicitados no excedan
   * ningún techo configurado para el proyecto/tenant.
   *
   * @param {string} projectId
   * @param {{ containers?: number, memoryMb?: number, cpuCores?: number, storageGb?: number, bandwidthGbMo?: number }} [requested]
   */
  checkQuotaAllowance(projectId, requested = {}) {
    const pid = assertProjectId(projectId);
    const quota = this.getQuota(pid);
    const req = requested && typeof requested === 'object' ? requested : {};

    /** @type {Array<{ resource: string, limit: number, requested: number, exceededBy: number, message: string }>} */
    const violations = [];

    for (const key of /** @type {const} */ (['containers', 'memoryMb', 'cpuCores', 'storageGb', 'bandwidthGbMo'])) {
      if (req[key] === undefined || req[key] === null) continue;
      const val = Number(req[key]);
      const limit = Number(quota[key]);
      if (!Number.isFinite(val) || val < 0) {
        violations.push({
          resource: key,
          limit,
          requested: val,
          exceededBy: 0,
          message: `Invalid requested value for ${key}: ${req[key]} (fail-closed rejection).`
        });
        continue;
      }
      if (val > limit) {
        const exceededBy = round3(val - limit);
        violations.push({
          resource: key,
          limit,
          requested: val,
          exceededBy,
          message: `Quota exceeded for ${key}: requested ${val} > limit ${limit} (+${exceededBy}).`
        });
      }
    }

    return {
      ok: true,
      projectId: pid,
      allowed: violations.length === 0,
      quota,
      requested: req,
      violations
    };
  }

  /**
   * Genera el ledger de uso y facturación multi-tenant filtrando estrictamente por
   * `allowedProjectIds` (cero fuga cross-tenant).
   *
   * @param {{
   *   projects?: any[],
   *   databases?: any[],
   *   allowedProjectIds?: string[] | Set<string> | null,
   *   periodDays?: number,
   *   unitRates?: typeof DEFAULT_UNIT_RATES
   * }} [opts]
   */
  buildUsageLedger(opts = {}) {
    const periodDays = Math.min(366, Math.max(1, Math.round(Number(opts.periodDays ?? 30) || 30)));
    const periodHours = periodDays * 24;
    const rates = { ...DEFAULT_UNIT_RATES, ...(opts.unitRates || {}) };
    const allowedSet = opts.allowedProjectIds != null
      ? new Set(Array.from(opts.allowedProjectIds).map(String))
      : null;

    /** @type {any[]} */
    let projects = [];
    if (Array.isArray(opts.projects)) {
      projects = opts.projects;
    } else {
      try {
        const pm = this._projectManagerOverride || require('./projectManager');
        projects = Array.isArray(pm.getAll()) ? pm.getAll() : [];
      } catch (e) {
        projects = [];
      }
    }

    /** @type {any[]} */
    let databases = [];
    if (Array.isArray(opts.databases)) {
      databases = opts.databases;
    } else {
      try {
        const dbm = this._databaseManagerOverride || require('./databaseManager');
        const list = typeof dbm.list === 'function' ? dbm.list() : [];
        databases = Array.isArray(list) ? list : [];
      } catch (e) {
        databases = [];
      }
    }

    // Aislamiento estricto por tenant / ACL
    const scopedProjects = allowedSet
      ? projects.filter((p) => p && allowedSet.has(String(p.id)))
      : projects.filter((p) => p && p.id);
    const scopedProjectIds = new Set(scopedProjects.map((p) => String(p.id)));
    const scopedDatabases = databases.filter((db) => db && db.projectId && scopedProjectIds.has(String(db.projectId)));

    /** @type {Map<string, any[]>} */
    const dbsByProject = new Map();
    for (const db of scopedDatabases) {
      const pid = String(db.projectId);
      const arr = dbsByProject.get(pid) || [];
      arr.push(db);
      dbsByProject.set(pid, arr);
    }

    /** @type {any[]} */
    const entries = [];
    let sumCpuHours = 0;
    let sumRamGbHours = 0;
    let sumStorageGb = 0;
    let sumBandwidthGb = 0;
    let sumCostUsd = 0;

    for (const proj of scopedProjects) {
      const pid = String(proj.id);
      const projDbs = dbsByProject.get(pid) || [];
      const customQuota = this.getQuota(pid);

      const activeFactor = proj.status === 'stopped' ? 0 : (proj.status === 'hibernated' ? 0.15 : 1);
      const cpus = Math.max(0.25, Number(proj.cpus || proj.cpuLimit || 1) || 1);
      const ramMb = Math.max(128, Number(proj.memoryMb || proj.memoryLimitMb || 512) || 512);
      const dbRamMb = projDbs.length * 512;
      const dbCpus = projDbs.length * 0.5;

      const cpuHours = round2((cpus * activeFactor + dbCpus) * periodHours);
      const ramGbHours = round2((((ramMb * activeFactor) + dbRamMb) / 1024) * periodHours);
      const storageGb = round2(
        (Number(proj.storageGb) || 2) +
        (projDbs.reduce((acc, db) => acc + (Number(db.storageGb) || 5), 0))
      );
      const bandwidthGb = round2(Number(proj.bandwidthGb) || (activeFactor > 0 ? 25 * (periodDays / 30) : 0));

      const estimatedCostUsd = round2(
        (cpuHours * rates.cpuCoreHourUsd) +
        (ramGbHours * rates.ramGbHourUsd) +
        (storageGb * rates.storageGbMoUsd * (periodDays / 30)) +
        (bandwidthGb * rates.bandwidthGbUsd)
      );

      sumCpuHours += cpuHours;
      sumRamGbHours += ramGbHours;
      sumStorageGb += storageGb;
      sumBandwidthGb += bandwidthGb;
      sumCostUsd += estimatedCostUsd;

      entries.push({
        projectId: pid,
        projectName: String(proj.name || pid),
        tenantId: String(customQuota.tenantId || proj.teamId || 'team_default'),
        status: String(proj.status || 'active'),
        databaseCount: projDbs.length,
        cpuHours,
        ramGbHours,
        storageGb,
        bandwidthGb,
        estimatedCostUsd
      });
    }

    return {
      ok: true,
      generatedAt: new Date().toISOString(),
      periodDays,
      unitRates: rates,
      entries,
      totals: {
        totalProjects: entries.length,
        totalDatabases: scopedDatabases.length,
        cpuHours: round2(sumCpuHours),
        ramGbHours: round2(sumRamGbHours),
        storageGb: round2(sumStorageGb),
        bandwidthGb: round2(sumBandwidthGb),
        estimatedCostUsd: round2(sumCostUsd)
      }
    };
  }
}

const instance = /** @type {any} */ (new QuotaMeteringService());
instance.QuotaMeteringService = QuotaMeteringService;
instance.DEFAULT_QUOTA = DEFAULT_QUOTA;
instance.DEFAULT_UNIT_RATES = DEFAULT_UNIT_RATES;
instance.escapeCsvCell = escapeCsvCell;
instance.exportLedgerCsv = exportLedgerCsv;
module.exports = instance;
