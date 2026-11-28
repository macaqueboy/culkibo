const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Reproducible Build & Build-Cache Poisoning Verifier (100% Zero-Dep Pure JS).
 *
 * Contramedidas directas ante CVEs 2026 de BuildKit/Docker:
 *  - `CVE-2026-33747`: bloquea frontends `#syntax=` no confiables o sin pin `@sha256:` (`UNPINNED_FRONTEND`).
 *  - `CVE-2026-93318`: planifica caches BuildKit aislados por proyecto+rama+hash de lockfile con
 *    `sharing=locked` y verificación de `DiffID` contra envenenamiento cross-PR.
 *  - `CVE-2026-93326`: valida fuentes Git contra esquemas inseguros y hosts no confiables (`UNTRUSTED_GIT_SOURCE`).
 *  - `CVE-2026-133630`: detecta copias de `.git`/`.git/config` o credenciales en URLs Git (`GIT_CONFIG_TOKEN_LEAK`).
 *  - Exige `SOURCE_DATE_EPOCH` entero (`MISSING_SOURCE_DATE_EPOCH`), prohíbe `curl|bash` / `npx` sin versión
 *    (`PIPE_TO_SHELL`) y valida cobertura `sha512-` en `package-lock.json` (`WEAK_LOCKFILE_HASH`).
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/reproducible-builds.json`.
 */

const TRUSTED_FRONTEND_REPOS = Object.freeze([
  'docker/dockerfile',
  'docker.io/docker/dockerfile'
]);

const SHA256_PIN_RE = /@sha256:[a-f0-9]{64}$/i;
const PIPE_TO_SHELL_RE = /\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:\/bin\/|\/usr\/bin\/)?(?:sh|bash|zsh|dash)\b/i;
const UNPINNED_NPX_RE = /\bnpx\s+(?:--yes\s+|-y\s+)?(?!@?[a-z0-9._/-]+@\d)(@?[a-z0-9._/-]+)/i;
const GIT_CRED_URL_RE = /\bhttps?:\/\/[^:\s'"`]+:[^@\s'"`]+@[^\s'"`]+/i;
const MAX_STORED_AUDITS = 200;

/**
 * Resuelve dinámicamente la ruta a `reproducible-builds.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'reproducible-builds.json')
    : path.join(base, 'data', 'reproducible-builds.json');
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
 * Persiste auditorías de forma atómica (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, audits: any[] }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  if (store.audits.length > MAX_STORED_AUDITS) {
    store.audits = store.audits.slice(-MAX_STORED_AUDITS);
  }
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Verifica que un `package-lock.json` (v1/v2/v3) cubra todas sus dependencias con hashes `sha512-`.
 *
 * @param {any} lockfileJson
 */
function verifyLockfileIntegrity(lockfileJson) {
  let obj = lockfileJson;
  if (typeof lockfileJson === 'string') {
    try {
      obj = JSON.parse(lockfileJson);
    } catch (e) {
      return {
        ok: true,
        valid: false,
        totalPackages: 0,
        sha512Count: 0,
        weakCount: 1,
        weakEntries: [{ package: 'package-lock.json', code: 'WEAK_LOCKFILE_HASH', reason: 'Invalid JSON lockfile.' }],
        lockfileHash: ''
      };
    }
  }

  if (!obj || typeof obj !== 'object') {
    return {
      ok: true,
      valid: false,
      totalPackages: 0,
      sha512Count: 0,
      weakCount: 1,
      weakEntries: [{ package: 'package-lock.json', code: 'WEAK_LOCKFILE_HASH', reason: 'Missing lockfile object.' }],
      lockfileHash: ''
    };
  }

  /** @type {Array<{ package: string, code: string, reason: string }>} */
  const weakEntries = [];
  let totalPackages = 0;
  let sha512Count = 0;

  /**
   * @param {string} name
   * @param {any} meta
   */
  const checkPkg = (name, meta) => {
    if (!meta || typeof meta !== 'object' || meta.link === true) return;
    totalPackages++;
    const integrity = typeof meta.integrity === 'string' ? meta.integrity.trim() : '';
    if (!integrity) {
      weakEntries.push({ package: name, code: 'WEAK_LOCKFILE_HASH', reason: `Package "${name}" is missing an integrity hash.` });
      return;
    }
    if (/^sha1-/i.test(integrity) || !/\bsha512-[A-Za-z0-9+/=]{32,}/i.test(integrity)) {
      weakEntries.push({ package: name, code: 'WEAK_LOCKFILE_HASH', reason: `Package "${name}" uses weak/non-SHA-512 integrity (${integrity.slice(0, 12)}...).` });
      return;
    }
    sha512Count++;
  };

  if (obj.packages && typeof obj.packages === 'object') {
    for (const [pkgPath, meta] of Object.entries(obj.packages)) {
      if (!pkgPath) continue; // skip root workspace entry ""
      checkPkg(pkgPath, meta);
    }
  } else if (obj.dependencies && typeof obj.dependencies === 'object') {
    /** @param {Record<string, any>} depMap */
    const walkDeps = (depMap) => {
      for (const [depName, meta] of Object.entries(depMap)) {
        checkPkg(depName, meta);
        if (meta && meta.dependencies && typeof meta.dependencies === 'object') {
          walkDeps(meta.dependencies);
        }
      }
    };
    walkDeps(obj.dependencies);
  }

  const lockfileHash = crypto.createHash('sha256').update(JSON.stringify(obj), 'utf8').digest('hex').slice(0, 16);

  return {
    ok: true,
    valid: weakEntries.length === 0,
    totalPackages,
    sha512Count,
    weakCount: weakEntries.length,
    weakEntries,
    lockfileHash
  };
}

/**
 * Audita reproducibilidad y resistencia a envenenamiento de caché en Dockerfiles, lockfiles y fuentes Git.
 *
 * @param {{
 *   projectId?: string,
 *   dockerfile?: string,
 *   lockfileJson?: any,
 *   buildArgs?: Record<string, any>,
 *   cachePolicy?: { allowedFrontends?: string[], allowedGitHosts?: string[], strictCacheIsolation?: boolean },
 *   gitSources?: string[],
 *   persist?: boolean
 * }} [input]
 */
function auditBuildReproducibility(input = {}) {
  const opts = input || {};
  const projectId = opts.projectId ? String(opts.projectId).trim() : null;
  const dockerfile = typeof opts.dockerfile === 'string' ? opts.dockerfile : '';
  const buildArgs = (opts.buildArgs && typeof opts.buildArgs === 'object') ? opts.buildArgs : {};
  const cachePolicy = (opts.cachePolicy && typeof opts.cachePolicy === 'object') ? opts.cachePolicy : {};
  const gitSources = Array.isArray(opts.gitSources) ? opts.gitSources.map(String) : [];
  const allowedFrontends = Array.isArray(cachePolicy.allowedFrontends) && cachePolicy.allowedFrontends.length > 0
    ? cachePolicy.allowedFrontends.map((f) => String(f).toLowerCase())
    : [...TRUSTED_FRONTEND_REPOS];
  const allowedGitHosts = Array.isArray(cachePolicy.allowedGitHosts)
    ? cachePolicy.allowedGitHosts.map((h) => String(h).toLowerCase())
    : [];

  /** @type {Array<{ code: string, severity: 'critical' | 'high' | 'medium', line: number | null, message: string, fix: string }>} */
  const findings = [];
  const lines = dockerfile.split(/\r?\n/);

  let hasSourceDateEpoch = false;
  if (buildArgs.SOURCE_DATE_EPOCH !== undefined && /^\d+$/.test(String(buildArgs.SOURCE_DATE_EPOCH).trim())) {
    hasSourceDateEpoch = true;
  }

  /** @type {Set<string>} */
  const stageAliases = new Set();

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].trim();
    const lineNum = i + 1;
    if (!raw) continue;

    // 1. #syntax= BuildKit frontend directive check (CVE-2026-33747)
    const syntaxMatch = raw.match(/^#\s*syntax\s*=\s*(\S+)/i);
    if (syntaxMatch) {
      const fe = syntaxMatch[1].trim();
      const feLower = fe.toLowerCase();
      const repoPart = feLower.split('@')[0].split(':')[0];
      const isTrustedRepo = allowedFrontends.includes(repoPart);
      const isDigestPinned = SHA256_PIN_RE.test(fe);
      if (!isTrustedRepo || !isDigestPinned) {
        findings.push({
          code: 'UNPINNED_FRONTEND',
          severity: 'critical',
          line: lineNum,
          message: `BuildKit #syntax=${fe} is untrusted or not pinned to @sha256:<64hex> (CVE-2026-33747).`,
          fix: 'Pin #syntax=docker/dockerfile:1.7@sha256:<verified-digest> from an official trusted frontend.'
        });
      }
      continue;
    }

    if (raw.startsWith('#')) continue;

    // 2. SOURCE_DATE_EPOCH detection in ENV/ARG
    const epochMatch = raw.match(/^(?:ENV|ARG)\s+SOURCE_DATE_EPOCH(?:\s*=\s*|\s+)(\d+)\b/i);
    if (epochMatch) {
      hasSourceDateEpoch = true;
    }

    // 3. Mutable :latest or untagged FROM base image
    const fromMatch = raw.match(/^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i);
    if (fromMatch) {
      const baseRef = fromMatch[1];
      if (fromMatch[2]) stageAliases.add(fromMatch[2].toLowerCase());
      const baseLower = baseRef.toLowerCase();
      const isSpecial = baseLower === 'scratch' || stageAliases.has(baseLower) || baseRef.startsWith('$');
      if (!isSpecial && (/:latest$/i.test(baseRef) || (!baseRef.includes(':') && !baseRef.includes('@')))) {
        findings.push({
          code: 'MUTABLE_BASE_IMAGE',
          severity: 'high',
          line: lineNum,
          message: `Base image "${baseRef}" uses a mutable :latest or untagged reference.`,
          fix: 'Pin FROM base images to an explicit version tag + @sha256:<digest>.'
        });
      }
    }

    // 4. PIPE_TO_SHELL (curl|bash, wget|sh, unpinned npx)
    if (PIPE_TO_SHELL_RE.test(raw) || UNPINNED_NPX_RE.test(raw)) {
      findings.push({
        code: 'PIPE_TO_SHELL',
        severity: 'critical',
        line: lineNum,
        message: `Unpinned remote execution (curl|sh, wget|bash, or unpinned npx) detected at line ${lineNum}.`,
        fix: 'Download version-pinned artifacts, verify SHA-256 checksums, or pin npx <pkg>@x.y.z.'
      });
    }

    // 5. GIT_CONFIG_TOKEN_LEAK (CVE-2026-133630)
    if (
      /\.git\/config\b/i.test(raw)
      || /^COPY\s+.*\.git(?:\s|$)/i.test(raw)
      || GIT_CRED_URL_RE.test(raw)
      || /git\s+config\b.*credential/i.test(raw)
    ) {
      findings.push({
        code: 'GIT_CONFIG_TOKEN_LEAK',
        severity: 'critical',
        line: lineNum,
        message: `Potential Git credential or .git/config leak into image layer at line ${lineNum} (CVE-2026-133630).`,
        fix: 'Add .git to .dockerignore and pass Git auth exclusively via BuildKit --mount=type=ssh or --mount=type=secret.'
      });
    }

    // 6. Unisolated shared cache mount check
    if (cachePolicy.strictCacheIsolation && /--mount=type=cache/i.test(raw)) {
      if (/sharing=shared/i.test(raw) || !/\bid=/i.test(raw)) {
        findings.push({
          code: 'UNISOLATED_BUILD_CACHE',
          severity: 'high',
          line: lineNum,
          message: `BuildKit cache mount at line ${lineNum} lacks scoped id= or uses sharing=shared (cross-PR poisoning risk, CVE-2026-93318).`,
          fix: 'Use --mount=type=cache,id=<project>-<branch>-<lockhash>,sharing=locked.'
        });
      }
    }
  }

  // 7. MISSING_SOURCE_DATE_EPOCH
  if (dockerfile.trim() && !hasSourceDateEpoch) {
    findings.push({
      code: 'MISSING_SOURCE_DATE_EPOCH',
      severity: 'medium',
      line: null,
      message: 'Build is missing integer SOURCE_DATE_EPOCH for deterministic archive/layer timestamps.',
      fix: 'Set ARG/ENV SOURCE_DATE_EPOCH=<unix-timestamp> or pass --build-arg SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct).'
    });
  }

  // 8. UNTRUSTED_GIT_SOURCE (CVE-2026-93326)
  for (const src of gitSources) {
    const s = src.trim();
    if (!s) continue;
    const isUnsafeScheme = /^(?:git|http|file):\/\//i.test(s);
    const hasEmbeddedCreds = GIT_CRED_URL_RE.test(s);
    const hasTraversal = s.includes('..');
    let hostBlocked = false;
    if (allowedGitHosts.length > 0 && /^https:\/\//i.test(s)) {
      try {
        const parsedUrl = new URL(s);
        hostBlocked = !allowedGitHosts.includes(parsedUrl.hostname.toLowerCase());
      } catch (e) {
        hostBlocked = true;
      }
    }
    if (isUnsafeScheme || hasEmbeddedCreds || hasTraversal || hostBlocked) {
      findings.push({
        code: 'UNTRUSTED_GIT_SOURCE',
        severity: 'critical',
        line: null,
        message: `Git build source fails CVE-2026-93326 URL/TLS policy (unsafe scheme, credentials, traversal, or unapproved host).`,
        fix: 'Use clean https:// URLs on approved Git hosts without embedded tokens or path traversal.'
      });
    }
  }

  // 9. Lockfile SHA-512 integrity check
  /** @type {ReturnType<typeof verifyLockfileIntegrity> | null} */
  let lockfileSummary = null;
  if (opts.lockfileJson !== null && opts.lockfileJson !== undefined) {
    const lfRes = verifyLockfileIntegrity(opts.lockfileJson);
    lockfileSummary = lfRes;
    if (!lfRes.valid) {
      findings.push({
        code: 'WEAK_LOCKFILE_HASH',
        severity: 'high',
        line: null,
        message: `Lockfile contains ${lfRes.weakCount} package(s) missing sha512- integrity hashes.`,
        fix: 'Regenerate package-lock.json with npm v9+ so every entry includes a sha512- SRI digest.'
      });
    }
  }

  const reproducible = findings.length === 0;
  /** @type {Record<string, number>} */
  const weights = { critical: 30, high: 20, medium: 12 };
  const penalty = findings.reduce((sum, f) => sum + (weights[f.severity] || 15), 0);
  const score = Math.max(0, 100 - penalty);
  const auditedAt = new Date().toISOString();

  const summaryRecord = {
    id: `repro_${crypto.randomBytes(5).toString('hex')}`,
    projectId,
    reproducible,
    score,
    findingCodes: findings.map((f) => f.code),
    lockfileHash: lockfileSummary ? lockfileSummary.lockfileHash : null,
    auditedAt
  };

  if (opts.persist !== false && projectId) {
    const store = loadStore();
    store.audits.push(summaryRecord);
    saveStore(store);
  }

  return {
    ok: true,
    projectId,
    reproducible,
    score,
    findings,
    lockfileSummary,
    auditedAt
  };
}

/**
 * Construye un plan de caché BuildKit aislado por proyecto+rama+hash de lockfile con
 * `sharing=locked`, `SOURCE_DATE_EPOCH` y verificación de `DiffID` (`CVE-2026-93318`).
 *
 * @param {{
 *   projectId?: string,
 *   branch?: string,
 *   lockfileHash?: string,
 *   sourceDateEpoch?: number | string
 * }} [input]
 */
function buildIsolatedCachePlan(input = {}) {
  const opts = input || {};
  const slug = (s, fallback) => String(s || fallback).toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32) || fallback;
  const projectSlug = slug(opts.projectId, 'default');
  const branchSlug = slug(opts.branch, 'main');
  const hashSlug = slug(opts.lockfileHash, 'default').slice(0, 16);
  const epochRaw = Number(opts.sourceDateEpoch ?? 1700000000);
  const sourceDateEpoch = Number.isFinite(epochRaw) && epochRaw >= 0 ? Math.floor(epochRaw) : 1700000000;

  const scopedCacheId = `culkibo-${projectSlug}-${branchSlug}-${hashSlug}`;
  const cacheMountFlag = `--mount=type=cache,id=${scopedCacheId},sharing=locked,target=/root/.npm`;

  const buildxArgv = [
    'docker', 'buildx', 'build',
    '--build-arg', `SOURCE_DATE_EPOCH=${sourceDateEpoch}`,
    '--output', 'type=oci,rewrite-timestamp=true',
    '--cache-from', `type=local,src=/var/lib/culkibo/cache/${scopedCacheId}`,
    '--cache-to', `type=local,dest=/var/lib/culkibo/cache/${scopedCacheId},mode=max`,
    '--provenance=mode=max',
    '--sbom=true',
    '.'
  ];

  return {
    ok: true,
    projectId: String(opts.projectId || 'default'),
    branch: String(opts.branch || 'main'),
    lockfileHash: hashSlug,
    sourceDateEpoch,
    scopedCacheId,
    sharing: 'locked',
    isolationScope: 'project+branch+lockfile',
    verifyDiffIds: true,
    cacheMountFlag,
    buildxArgv
  };
}

/**
 * Lista auditorías de reproducibilidad guardadas (más recientes primero).
 * @param {string} [projectId]
 */
function listBuildAudits(projectId) {
  const store = loadStore();
  const cleanId = projectId ? String(projectId).trim() : '';
  const items = cleanId
    ? store.audits.filter((a) => a.projectId === cleanId)
    : store.audits;
  return [...items].reverse();
}

module.exports = {
  TRUSTED_FRONTEND_REPOS,
  verifyLockfileIntegrity,
  auditBuildReproducibility,
  buildIsolatedCachePlan,
  listBuildAudits
};
