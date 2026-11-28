'use strict';

/**
 * Culkibo Supply-Chain Worm (`Shai-Hulud` / `CHAINDROP`), Typosquatting & `postinstall` Guard.
 *
 * Defends Node/npm supply chains against 2025–2026 self-propagating lifecycle worms
 * (`Shai-Hulud 1.0/2.0`, `CHAINDROP` Aug 2026 `keyv@6.0.0`), typosquats, and unscoped
 * dependency confusion in zero external npm dependencies:
 *  - Atomic `0o600` audit history in `CULKIBO_DATA_DIR/data/pkg-confusion-guard.json`.
 *  - Exact `levenshteinDistance(a, b)` detecting typosquats (distance 1..2 vs popular npm packages).
 *  - `scanInstallScriptRisk` catching Shai-Hulud/CHAINDROP IoCs (`setup.mjs`, `math_init.js`,
 *    `Math_Symbol.js`, `rm -rf ~`, remote pipe-to-shell, `.npmrc`/env/token exfiltration).
 *  - Flags `WORM_IOC_DETECTED`, `UNAPPROVED_LIFECYCLE_SCRIPT`, `NPM_SCRIPTS_ENABLED`,
 *    `DEPENDENCY_CONFUSION_RISK`, and `TYPOSQUAT_SUSPECTED`.
 *  - Generates hardened `.npmrc` (`ignore-scripts=true`) (`generateSafeNpmrc`, `dryRun: true` default).
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MAX_STORED_AUDITS = 500;

const POPULAR_PACKAGES = Object.freeze([
  'express',
  'lodash',
  'react',
  'react-dom',
  'next',
  'axios',
  'chalk',
  'commander',
  'dotenv',
  'eslint',
  'prettier',
  'typescript',
  'webpack',
  'vite',
  'prisma',
  'sequelize',
  'mongoose',
  'jsonwebtoken',
  'bcryptjs',
  'zod',
  'keyv',
  'ioredis',
  'mysql2',
  'stripe',
  'aws-sdk',
  'tailwindcss',
  'fastify',
  'socket.io',
  'uuid',
  'semver',
  'minimist',
  'yargs',
  'node-fetch',
  'undici',
  'pino',
  'winston',
  'bullmq'
]);

const POPULAR_SET = new Set(POPULAR_PACKAGES);

const WORM_IOC_PATTERNS = Object.freeze([
  Object.freeze({ id: 'CHAINDROP_SETUP_DROPPER', re: /\b(?:setup\.mjs|math_init\.js|Math_Symbol\.js|bundle_init\.mjs)\b/i }),
  Object.freeze({ id: 'WIPER_HOME_RM', re: /\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+(?:~\/?|\/?\$(?:HOME|\{HOME\})|\/(?:\s|$))/i }),
  Object.freeze({ id: 'PIPE_TO_SHELL_HOOK', re: /\b(?:curl|wget)\b[^\n]*\|\s*(?:sh|bash|node)\b/i }),
  Object.freeze({ id: 'TOKEN_EXFIL_HOOK', re: /(?:NPM_TOKEN|GITHUB_TOKEN|\.npmrc|~\/\.ssh|process\.env)[\s\S]{0,120}(?:curl|wget|fetch|http\.request|webhook|post)/i }),
  Object.freeze({ id: 'OBFUSCATED_BASE64_EVAL', re: /\beval\s*\(\s*Buffer\.from\([^)]*['"]base64['"]\)/i })
]);

/**
 * Atomically writes UTF-8 text to disk with `0o600` mode.
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
 * Computes exact Levenshtein edit distance between two strings (case-insensitive).
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function levenshteinDistance(a, b) {
  const s1 = String(a || '').toLowerCase();
  const s2 = String(b || '').toLowerCase();
  const m = s1.length;
  const n = s2.length;
  if (m === 0) return n;
  if (n === 0) return m;

  /** @type {number[]} */
  let prev = new Array(n + 1);
  /** @type {number[]} */
  let curr = new Array(n + 1);
  for (let j = 0; j <= n; j += 1) prev[j] = j;

  for (let i = 1; i <= m; i += 1) {
    curr[0] = i;
    const c1 = s1.charCodeAt(i - 1);
    for (let j = 1; j <= n; j += 1) {
      const cost = c1 === s2.charCodeAt(j - 1) ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,
        curr[j - 1] + 1,
        prev[j - 1] + cost
      );
    }
    const tmp = prev;
    prev = curr;
    curr = tmp;
  }
  return prev[n];
}

/**
 * Scans a package lifecycle script (`preinstall`/`install`/`postinstall`) for known
 * Shai-Hulud / CHAINDROP worm IoCs, home-dir wipers, remote droppers, and token exfiltration.
 *
 * @param {string} scriptBody
 */
function scanInstallScriptRisk(scriptBody) {
  const raw = typeof scriptBody === 'string' ? scriptBody.trim() : '';
  if (!raw) {
    return { ok: true, safe: true, blocked: false, wormIocDetected: false, code: 'CLEAN', matches: [], riskScore: 0 };
  }

  /** @type {string[]} */
  const matches = [];
  for (const rule of WORM_IOC_PATTERNS) {
    if (rule.re.test(raw)) matches.push(rule.id);
  }

  const wormIocDetected = matches.length > 0;
  return {
    ok: true,
    safe: !wormIocDetected,
    blocked: wormIocDetected,
    wormIocDetected,
    code: wormIocDetected ? 'WORM_IOC_DETECTED' : 'CLEAN',
    matches,
    riskScore: wormIocDetected ? Math.min(100, matches.length * 45 + 35) : 0
  };
}

/**
 * Generates a hardened `.npmrc` disabling automatic lifecycle scripts (`ignore-scripts=true`)
 * and pinning internal scopes to private registries (`dryRun: true` default).
 *
 * @param {string[] | { allowScripts?: string[], internalScopes?: string[], registryUrl?: string, dryRun?: boolean }} [input]
 */
function generateSafeNpmrc(input = {}) {
  const isArr = Array.isArray(input);
  const src = !isArr && input && typeof input === 'object' ? input : {};
  const allowScripts = isArr
    ? input.map((s) => String(s || '').trim()).filter(Boolean)
    : (Array.isArray(src.allowScripts) ? src.allowScripts.map((s) => String(s || '').trim()).filter(Boolean) : []);
  const internalScopes = Array.isArray(src.internalScopes)
    ? src.internalScopes.map((s) => String(s || '').trim()).filter(Boolean)
    : [];
  const registryUrl = typeof src.registryUrl === 'string' && /^https?:\/\//i.test(src.registryUrl.trim())
    ? src.registryUrl.trim()
    : 'https://registry.internal.local/';
  const dryRun = src.dryRun !== undefined ? Boolean(src.dryRun) : true;

  const lines = [
    '# Culkibo Supply-Chain Hardened .npmrc (Shai-Hulud / CHAINDROP Defense)',
    'ignore-scripts=true',
    'audit=true',
    'fund=false',
    'save-exact=true',
    'strict-ssl=true'
  ];

  for (const rawScope of internalScopes) {
    const scope = rawScope.startsWith('@') ? rawScope : `@${rawScope.replace(/[-_]+$/, '')}`;
    lines.push(`${scope}:registry=${registryUrl}`);
  }

  if (allowScripts.length > 0) {
    lines.push(`# Explicitly allowlisted native build packages (pnpm onlyBuiltDependencies / LavaMoat):`);
    lines.push(`# allow-scripts=${allowScripts.join(',')}`);
  }

  const npmrcContent = lines.join('\n') + '\n';
  return {
    ok: true,
    dryRun,
    allowScripts,
    internalScopes,
    npmrcContent
  };
}

/**
 * Finds the closest popular npm package if `pkgName` is a suspected Levenshtein 1..2 typosquat.
 * @param {string} pkgName
 */
function detectTyposquat(pkgName) {
  const clean = String(pkgName || '').trim().toLowerCase();
  if (!clean || clean.startsWith('@') || clean.length < 4 || POPULAR_SET.has(clean)) return null;

  /** @type {{ target: string, distance: number } | null} */
  let best = null;
  for (const pop of POPULAR_PACKAGES) {
    if (Math.abs(clean.length - pop.length) > 2) continue;
    const dist = levenshteinDistance(clean, pop);
    const maxDist = pop.length >= 5 ? 2 : 1;
    if (dist >= 1 && dist <= maxDist) {
      if (!best || dist < best.distance) {
        best = { target: pop, distance: dist };
      }
    }
  }
  return best;
}

class PkgConfusionGuardService {
  /**
   * @param {{ dataDir?: string | null }} [opts]
   */
  constructor(opts = {}) {
    /** @type {string | null} */
    this._explicitDataDir = opts && typeof opts.dataDir === 'string' && opts.dataDir.trim()
      ? path.resolve(opts.dataDir.trim())
      : null;
  }

  /** @returns {string} */
  resolveDataDir() {
    if (this._explicitDataDir) return this._explicitDataDir;
    if (process.env.CULKIBO_DATA_DIR) {
      return path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data');
    }
    return path.join(__dirname, '..', '..', 'data');
  }

  /** @returns {string} */
  getStoreFilePath() {
    return path.join(this.resolveDataDir(), 'pkg-confusion-guard.json');
  }

  /** @returns {any[]} */
  _loadAudits() {
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) return [];
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      return parsed && Array.isArray(parsed.audits) ? parsed.audits : [];
    } catch (e) {
      return [];
    }
  }

  /** @param {any[]} audits */
  _saveAudits(audits) {
    const trimmed = audits.slice(-MAX_STORED_AUDITS);
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({ schemaVersion: 1, updatedAt: new Date().toISOString(), audits: trimmed }, null, 2) + '\n'
    );
  }

  /**
   * Delegates to `levenshteinDistance`.
   * @param {string} a
   * @param {string} b
   */
  levenshteinDistance(a, b) {
    return levenshteinDistance(a, b);
  }

  /**
   * Delegates to `scanInstallScriptRisk`.
   * @param {string} scriptBody
   */
  scanInstallScriptRisk(scriptBody) {
    return scanInstallScriptRisk(scriptBody);
  }

  /**
   * Delegates to `generateSafeNpmrc`.
   * @param {any} [input]
   */
  generateSafeNpmrc(input) {
    return generateSafeNpmrc(input);
  }

  /**
   * Audits a package dependency graph for Shai-Hulud/CHAINDROP worm IoCs, unapproved lifecycle
   * scripts, missing `.npmrc` `ignore-scripts=true`, unscoped dependency confusion, and typosquats.
   *
   * @param {{
   *   projectId?: string,
   *   packages?: any[],
   *   internalScopes?: string[],
   *   allowLifecycleScripts?: string[],
   *   npmrcIgnoreScripts?: boolean,
   *   persist?: boolean
   * }} [input]
   */
  auditPackageSupplyChain(input = {}) {
    const src = input && typeof input === 'object' ? input : {};
    const projectId = String(src.projectId || 'default').trim().slice(0, 128) || 'default';
    const packages = Array.isArray(src.packages) ? src.packages : [];
    const internalScopes = Array.isArray(src.internalScopes)
      ? src.internalScopes.map((s) => String(s || '').trim().toLowerCase()).filter(Boolean)
      : [];
    const allowLifecycleScripts = Array.isArray(src.allowLifecycleScripts)
      ? src.allowLifecycleScripts.map((s) => String(s || '').trim().toLowerCase()).filter(Boolean)
      : [];
    const allowSet = new Set(allowLifecycleScripts);
    const npmrcIgnoreScripts = Boolean(src.npmrcIgnoreScripts);

    /** @type {Array<{ code: string, severity: 'critical' | 'high' | 'medium', packageName: string, detail?: any, message: string, remediation: string }>} */
    const findings = [];

    // 1. Check .npmrc ignore-scripts=true baseline
    if (!npmrcIgnoreScripts) {
      findings.push({
        code: 'NPM_SCRIPTS_ENABLED',
        severity: 'high',
        packageName: '.npmrc',
        message: 'Automatic npm lifecycle scripts are enabled (ignore-scripts=true missing from .npmrc).',
        remediation: 'Add ignore-scripts=true to .npmrc and explicitly allowlist required native bindings.'
      });
    }

    const internalPrefixes = internalScopes.map((s) => s.replace(/^@/, '').replace(/[-_]+$/, '')).filter(Boolean);

    for (const rawPkg of packages) {
      const pkg = typeof rawPkg === 'string' ? { name: rawPkg } : (rawPkg && typeof rawPkg === 'object' ? rawPkg : null);
      if (!pkg) continue;
      const pkgName = String(pkg.name || '').trim();
      if (!pkgName) continue;
      const lowerName = pkgName.toLowerCase();

      // 2. Lifecycle scripts inspection (preinstall / install / postinstall)
      const scriptsObj = pkg.scripts && typeof pkg.scripts === 'object' ? pkg.scripts : {};
      /** @type {Array<[string, string]>} */
      const hooks = [];
      for (const hookName of ['preinstall', 'install', 'postinstall']) {
        const body = typeof scriptsObj[hookName] === 'string'
          ? scriptsObj[hookName]
          : (typeof pkg[hookName] === 'string' ? pkg[hookName] : '');
        if (body && body.trim()) hooks.push([hookName, body.trim()]);
      }

      for (const [hookName, scriptBody] of hooks) {
        const risk = scanInstallScriptRisk(scriptBody);
        if (risk.wormIocDetected) {
          findings.push({
            code: 'WORM_IOC_DETECTED',
            severity: 'critical',
            packageName: pkgName,
            detail: { hook: hookName, matches: risk.matches },
            message: `Shai-Hulud/CHAINDROP worm IoC detected in ${pkgName} ${hookName} hook (${risk.matches.join(', ')}).`,
            remediation: `Quarantine ${pkgName} immediately, rotate CI/npm/GitHub tokens, and enforce ignore-scripts=true.`
          });
        }
        if (!allowSet.has(lowerName)) {
          findings.push({
            code: 'UNAPPROVED_LIFECYCLE_SCRIPT',
            severity: 'high',
            packageName: pkgName,
            detail: { hook: hookName },
            message: `Package "${pkgName}" executes unapproved ${hookName} lifecycle script.`,
            remediation: `Block ${hookName} via ignore-scripts=true or audit and add "${pkgName}" to allowLifecycleScripts.`
          });
        }
      }

      // 3. Unscoped private / internal dependency confusion guard
      const isUnscoped = !lowerName.startsWith('@');
      const matchesInternalPrefix = isUnscoped && internalPrefixes.some(
        (pref) => lowerName.startsWith(`${pref}-`) || lowerName.startsWith(`${pref}_`)
      );
      if (isUnscoped && (pkg.private === true || pkg.isInternal === true || matchesInternalPrefix)) {
        findings.push({
          code: 'DEPENDENCY_CONFUSION_RISK',
          severity: 'high',
          packageName: pkgName,
          message: `Unscoped internal/private package "${pkgName}" is vulnerable to public npm registry dependency confusion.`,
          remediation: 'Namespace internal packages under a reserved @org/ scope pinned to your private registry in .npmrc.'
        });
      }

      // 4. Levenshtein 1..2 typosquat check against popular npm packages
      const typo = detectTyposquat(pkgName);
      if (typo) {
        findings.push({
          code: 'TYPOSQUAT_SUSPECTED',
          severity: 'high',
          packageName: pkgName,
          detail: typo,
          message: `Package "${pkgName}" is edit distance ${typo.distance} from popular package "${typo.target}" (suspected typosquat).`,
          remediation: `Verify spelling — did you mean "${typo.target}"? Remove "${pkgName}" before installing.`
        });
      }
    }

    const blocked = findings.length > 0;
    const npmrc = generateSafeNpmrc({ allowScripts: allowLifecycleScripts, internalScopes, dryRun: true });
    const record = {
      ok: true,
      id: `pkg_${crypto.randomBytes(6).toString('hex')}`,
      projectId,
      safe: !blocked,
      blocked,
      status: blocked ? 'BLOCKED' : 'SAFE',
      packageCount: packages.length,
      findings,
      findingCodes: Array.from(new Set(findings.map((f) => f.code))),
      npmrcContent: npmrc.npmrcContent,
      auditedAt: new Date().toISOString()
    };

    if (src.persist !== false) {
      const audits = this._loadAudits();
      audits.push(record);
      this._saveAudits(audits);
    }

    return record;
  }

  /**
   * Lists persisted supply-chain audits (optionally filtered by `projectId`), newest first.
   * @param {string | null} [projectId]
   */
  listPkgGuardAudits(projectId) {
    const filterId = typeof projectId === 'string' && projectId.trim() ? projectId.trim() : null;
    return this._loadAudits()
      .filter((a) => (!filterId || a.projectId === filterId))
      .slice()
      .reverse();
  }
}

const defaultPkgConfusionGuardService = new PkgConfusionGuardService();

const exported = Object.assign(defaultPkgConfusionGuardService, {
  PkgConfusionGuardService,
  POPULAR_PACKAGES,
  levenshteinDistance: PkgConfusionGuardService.prototype.levenshteinDistance.bind(defaultPkgConfusionGuardService),
  scanInstallScriptRisk: PkgConfusionGuardService.prototype.scanInstallScriptRisk.bind(defaultPkgConfusionGuardService),
  auditPackageSupplyChain: PkgConfusionGuardService.prototype.auditPackageSupplyChain.bind(defaultPkgConfusionGuardService),
  generateSafeNpmrc: PkgConfusionGuardService.prototype.generateSafeNpmrc.bind(defaultPkgConfusionGuardService),
  listPkgGuardAudits: PkgConfusionGuardService.prototype.listPkgGuardAudits.bind(defaultPkgConfusionGuardService)
});

module.exports = exported;
