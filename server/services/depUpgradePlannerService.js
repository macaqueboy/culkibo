const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Security Patch & Transitive Dependency Upgrade Planner (100% Zero-Dep).
 *
 * Inspirado en `pnpm` v10.16/v11 `minimumReleaseAge`, Renovate `vulnerabilityAlerts`
 * y Dependabot `cooldown`:
 *  - Clasifica actualizaciones directas y transitivas en 4 carriles seguros:
 *      1. `FAST_TRACK_CVE` (advisory CVE activo — salta el cooldown inmediatamente!)
 *      2. `COOLDOWN_HOLD` (paquete rutinario más joven que `minReleaseAgeHours`, default 168h,
 *         o sin fecha de publicación — frena malware zero-day en npm!)
 *      3. `MAJOR_MANUAL_REVIEW` (cambio mayor SemVer aislado con snapshot de rollback)
 *      4. `SAFE_PATCH_MINOR` (parche/menor maduro listo para actualización atómica agrupada)
 *  - Genera configuración sincronizada `.npmrc` + `pnpm-workspace.yaml` con exclusiones CVE
 *    para prevenir `ERR_PNPM_MINIMUM_RELEASE_AGE_VIOLATION`.
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/dep-upgrade-plans.json`.
 */

const UPGRADE_LANES = Object.freeze([
  'FAST_TRACK_CVE',
  'COOLDOWN_HOLD',
  'SAFE_PATCH_MINOR',
  'MAJOR_MANUAL_REVIEW'
]);

const MAX_STORED_PLANS = 200;

/**
 * Resuelve dinámicamente la ruta a `dep-upgrade-plans.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'dep-upgrade-plans.json')
    : path.join(base, 'data', 'dep-upgrade-plans.json');
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
 * Carga planes almacenados desde disco (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, plans: any[] }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), plans: [] };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && Array.isArray(parsed.plans)) {
      return parsed;
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), plans: [] };
}

/**
 * Guarda planes de forma atómica (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, plans: any[] }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  if (store.plans.length > MAX_STORED_PLANS) {
    store.plans = store.plans.slice(-MAX_STORED_PLANS);
  }
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Parsea una versión SemVer básica (`^/~v?X.Y.Z`).
 * @param {string | null | undefined} raw
 */
function parseSemver(raw) {
  const m = String(raw || '').trim().match(/^[~^v=]*(\d+)\.(\d+)\.(\d+)/i);
  if (!m) return null;
  return {
    major: parseInt(m[1], 10),
    minor: parseInt(m[2], 10),
    patch: parseInt(m[3], 10)
  };
}

/**
 * Determina el tipo de salto SemVer entre dos versiones.
 * @param {string} currentVersion
 * @param {string} targetVersion
 * @returns {'major' | 'minor' | 'patch' | 'unknown'}
 */
function detectBumpType(currentVersion, targetVersion) {
  const cur = parseSemver(currentVersion);
  const tgt = parseSemver(targetVersion);
  if (!cur || !tgt) return 'unknown';
  if (tgt.major > cur.major) return 'major';
  if (tgt.minor > cur.minor) return 'minor';
  if (tgt.patch > cur.patch) return 'patch';
  return 'patch';
}

/**
 * Clasifica el riesgo y carril seguro de una actualización de dependencia individual.
 *
 * @param {{
 *   name: string,
 *   currentVersion?: string,
 *   targetVersion?: string,
 *   publishedAt?: string | number | null,
 *   ageHours?: number | null,
 *   transitive?: boolean,
 *   cveIds?: string[],
 *   hasActiveCve?: boolean,
 *   severity?: string
 * }} pkgUpdate
 * @param {{ advisories?: Array<{ package?: string, name?: string, cve?: string, id?: string, severity?: string }>, minReleaseAgeHours?: number, nowMs?: number }} [options]
 */
function classifyUpgradeRisk(pkgUpdate, options = {}) {
  const pkg = pkgUpdate || /** @type {any} */ ({});
  const opts = options || {};
  const name = String(pkg.name || 'unknown').trim();
  const currentVersion = String(pkg.currentVersion || '0.0.0').trim();
  const targetVersion = String(pkg.targetVersion || currentVersion).trim();
  const transitive = Boolean(pkg.transitive);
  const minReleaseAgeHours = Math.max(0, Number(opts.minReleaseAgeHours ?? 168));
  const nowMs = typeof opts.nowMs === 'number' && Number.isFinite(opts.nowMs) ? opts.nowMs : Date.now();
  const bumpType = detectBumpType(currentVersion, targetVersion);

  const advisories = Array.isArray(opts.advisories) ? opts.advisories : [];
  const matchingAdvisories = advisories.filter((a) => (
    a && String(a.package || a.name || '').trim().toLowerCase() === name.toLowerCase()
  ));

  const cveIds = Array.from(new Set([
    ...(Array.isArray(pkg.cveIds) ? pkg.cveIds.map(String) : []),
    ...matchingAdvisories.map((a) => String(a.cve || a.id || 'CVE-ADVISORY'))
  ].filter(Boolean)));

  const hasActiveCve = Boolean(pkg.hasActiveCve) || cveIds.length > 0;

  /** @type {number | null} */
  let releaseAgeHours = null;
  if (typeof pkg.ageHours === 'number' && Number.isFinite(pkg.ageHours) && pkg.ageHours >= 0) {
    releaseAgeHours = Math.round(pkg.ageHours * 100) / 100;
  } else if (pkg.publishedAt !== undefined && pkg.publishedAt !== null && String(pkg.publishedAt).trim() !== '') {
    const pubMs = typeof pkg.publishedAt === 'number' ? pkg.publishedAt : Date.parse(String(pkg.publishedAt));
    if (Number.isFinite(pubMs)) {
      releaseAgeHours = Math.max(0, Math.round(((nowMs - pubMs) / 3600000) * 100) / 100);
    }
  }

  // 1. Active CVE advisory ALWAYS fast-tracks (bypassing supply-chain cooldown!)
  if (hasActiveCve) {
    return {
      name,
      currentVersion,
      targetVersion,
      bumpType,
      transitive,
      lane: 'FAST_TRACK_CVE',
      releaseAgeHours,
      remainingCooldownHours: 0,
      cveIds,
      excludeFromCooldown: true,
      rollbackTag: `pre-cve-${name.replace(/[^a-z0-9_-]/gi, '-')}-${currentVersion}`,
      reason: `Active security advisory (${cveIds.join(', ') || 'CVE'}) bypasses ${minReleaseAgeHours}h release cooldown for immediate patching.`
    };
  }

  // 2. Cooldown hold if release is younger than minReleaseAgeHours or missing publish timestamp
  if (releaseAgeHours === null || releaseAgeHours < minReleaseAgeHours) {
    const remainingCooldownHours = releaseAgeHours === null
      ? minReleaseAgeHours
      : Math.max(1, Math.ceil(minReleaseAgeHours - releaseAgeHours));
    return {
      name,
      currentVersion,
      targetVersion,
      bumpType,
      transitive,
      lane: 'COOLDOWN_HOLD',
      releaseAgeHours,
      remainingCooldownHours,
      cveIds: [],
      excludeFromCooldown: false,
      rollbackTag: null,
      reason: releaseAgeHours === null
        ? 'Missing publish timestamp; held in cooldown to prevent unverified supply-chain package adoption.'
        : `Release age (${releaseAgeHours}h) is below minimum cooldown (${minReleaseAgeHours}h); hold ${remainingCooldownHours}h more.`
    };
  }

  // 3. Major version bumps isolated for manual review + rollback snapshot
  if (bumpType === 'major') {
    return {
      name,
      currentVersion,
      targetVersion,
      bumpType,
      transitive,
      lane: 'MAJOR_MANUAL_REVIEW',
      releaseAgeHours,
      remainingCooldownHours: 0,
      cveIds: [],
      excludeFromCooldown: false,
      rollbackTag: `pre-major-${name.replace(/[^a-z0-9_-]/gi, '-')}-${currentVersion}`,
      reason: `Breaking major bump (${currentVersion} -> ${targetVersion}) isolated from automated patch/minor batch.`
    };
  }

  // 4. Mature patch/minor upgrade ready for grouped atomic rollout
  return {
    name,
    currentVersion,
    targetVersion,
    bumpType,
    transitive,
    lane: 'SAFE_PATCH_MINOR',
    releaseAgeHours,
    remainingCooldownHours: 0,
    cveIds: [],
    excludeFromCooldown: false,
    rollbackTag: null,
    reason: `Aged ${bumpType} release (${releaseAgeHours}h >= ${minReleaseAgeHours}h) cleared for grouped upgrade.`
  };
}

/**
 * Genera configuración sincronizada `.npmrc` + `pnpm-workspace.yaml` para `minimumReleaseAge`
 * con exclusiones explícitas para paquetes CVE fast-track (evita `ERR_PNPM_MINIMUM_RELEASE_AGE_VIOLATION`).
 *
 * @param {{
 *   manager?: 'pnpm' | 'npm' | 'yarn' | string,
 *   minReleaseAgeMinutes?: number,
 *   exclude?: string[]
 * }} [input]
 */
function generatePackageManagerCooldown(input = {}) {
  const opts = input || {};
  const manager = String(opts.manager || 'pnpm').trim().toLowerCase() || 'pnpm';
  const minReleaseAgeMinutes = Math.max(0, Math.floor(Number(opts.minReleaseAgeMinutes ?? 10080)));
  const exclude = Array.from(new Set(
    (Array.isArray(opts.exclude) ? opts.exclude : []).map((x) => String(x || '').trim()).filter(Boolean)
  ));

  const npmrcLines = [
    `# Generated by Culkibo Dependency Cooldown Guard (${manager})`,
    `minimum-release-age=${minReleaseAgeMinutes}`
  ];
  for (const pkg of exclude) {
    npmrcLines.push(`minimum-release-age-exclude[]=${pkg}`);
  }

  const wsLines = [
    '# Synced pnpm-workspace.yaml cooldown settings (pnpm v10.16+ / v11)',
    `minimumReleaseAge: ${minReleaseAgeMinutes}`
  ];
  if (exclude.length > 0) {
    wsLines.push('minimumReleaseAgeExclude:');
    for (const pkg of exclude) {
      wsLines.push(`  - "${pkg}"`);
    }
  } else {
    wsLines.push('minimumReleaseAgeExclude: []');
  }

  const days = Math.max(1, Math.round(minReleaseAgeMinutes / 1440));
  const renovateConfig = {
    minimumReleaseAge: `${days} days`,
    vulnerabilityAlerts: {
      enabled: true,
      minimumReleaseAge: '0 days'
    }
  };

  return {
    ok: true,
    manager,
    minReleaseAgeMinutes,
    exclude,
    npmrc: npmrcLines.join('\n'),
    pnpmWorkspaceYaml: wsLines.join('\n'),
    renovateConfig
  };
}

/**
 * Planifica actualizaciones directas y transitivas de dependencias en los 4 carriles de seguridad.
 *
 * @param {{
 *   projectId?: string,
 *   dependencies?: any[],
 *   advisories?: any[],
 *   minReleaseAgeHours?: number,
 *   nowIso?: string | number,
 *   persist?: boolean
 * }} [input]
 */
function planDependencyUpgrades(input = {}) {
  const opts = input || {};
  const projectId = opts.projectId ? String(opts.projectId).trim() : null;
  const dependencies = Array.isArray(opts.dependencies) ? opts.dependencies : [];
  const advisories = Array.isArray(opts.advisories) ? opts.advisories : [];
  const minReleaseAgeHours = Math.max(0, Number(opts.minReleaseAgeHours ?? 168));
  const nowMs = opts.nowIso !== undefined
    ? (typeof opts.nowIso === 'number' ? opts.nowIso : (Date.parse(String(opts.nowIso)) || Date.now()))
    : Date.now();

  const items = dependencies.map((d) => classifyUpgradeRisk(d, { advisories, minReleaseAgeHours, nowMs }));

  /** @type {Record<string, typeof items>} */
  const lanes = {
    FAST_TRACK_CVE: [],
    COOLDOWN_HOLD: [],
    SAFE_PATCH_MINOR: [],
    MAJOR_MANUAL_REVIEW: []
  };
  for (const item of items) {
    if (lanes[item.lane]) lanes[item.lane].push(item);
  }

  const cveExcludes = lanes.FAST_TRACK_CVE.map((i) => i.name);
  const cooldownConfig = generatePackageManagerCooldown({
    manager: 'pnpm',
    minReleaseAgeMinutes: Math.round(minReleaseAgeHours * 60),
    exclude: cveExcludes
  });

  const counts = {
    FAST_TRACK_CVE: lanes.FAST_TRACK_CVE.length,
    COOLDOWN_HOLD: lanes.COOLDOWN_HOLD.length,
    SAFE_PATCH_MINOR: lanes.SAFE_PATCH_MINOR.length,
    MAJOR_MANUAL_REVIEW: lanes.MAJOR_MANUAL_REVIEW.length
  };
  const plannedAt = new Date(nowMs).toISOString();

  const planRecord = {
    id: `uplan_${crypto.randomBytes(5).toString('hex')}`,
    projectId,
    minReleaseAgeHours,
    totalDependencies: items.length,
    counts,
    lanes,
    items,
    cooldownConfig,
    plannedAt
  };

  if (opts.persist !== false && projectId) {
    const store = loadStore();
    store.plans.push(planRecord);
    saveStore(store);
  }

  return {
    ok: true,
    ...planRecord
  };
}

/**
 * Lista planes de actualización guardados (más recientes primero).
 * @param {string} [projectId]
 */
function listUpgradePlans(projectId) {
  const store = loadStore();
  const cleanId = projectId ? String(projectId).trim() : '';
  const items = cleanId
    ? store.plans.filter((p) => p.projectId === cleanId)
    : store.plans;
  return [...items].reverse();
}

module.exports = {
  UPGRADE_LANES,
  classifyUpgradeRisk,
  planDependencyUpgrades,
  generatePackageManagerCooldown,
  listUpgradePlans
};
