const fs = require('fs');
const path = require('path');

/**
 * CycloneDX 1.6 SPDX License Risk Auditor (Zero-Dep).
 *
 * Parsea expresiones SPDX compuestas con `AND` / `OR` y paréntesis (`OR` selecciona la
 * rama más permisiva; `AND` selecciona la más restrictiva), así como licencias custom
 * `LicenseRef-*`, clasificándolas en:
 *  - `permissive` (MIT, ISC, Apache-2.0, BSD-*, 0BSD, Unlicense, CC0-1.0, Zlib, BlueOak...)
 *  - `weak_copyleft` (LGPL-*, MPL-2.0, EPL-*, CDDL-*, EUPL-*, OFL-1.1...)
 *  - `strong_copyleft` (AGPL-*, GPL-*)
 *  - `source_available` (SSPL-*, BSL-*, BUSL-*, Elastic-2.0, LicenseRef-*, PROPRIETARY...)
 *  - `unknown`
 *
 * Soporta 3 políticas: `saas-strict`, `oss-permissive`, `audit-only`.
 */

const POLICIES = Object.freeze(['saas-strict', 'oss-permissive', 'audit-only']);

/** Orden de severidad (menor = más permisivo, mayor = más restrictivo/riesgoso). */
const CATEGORY_STRICTNESS = Object.freeze({
  permissive: 0,
  weak_copyleft: 1,
  strong_copyleft: 2,
  source_available: 3,
  unknown: 4
});

const PERMISSIVE_EXACT = new Set([
  'MIT', 'ISC', 'APACHE-2.0', 'APACHE-1.1', 'BSD-2-CLAUSE', 'BSD-3-CLAUSE',
  'BSD-2-CLAUSE-PATENT', 'BSD-3-CLAUSE-CLEAR', 'BSD-1-CLAUSE', 'BSD', '0BSD',
  'UNLICENSE', 'CC0-1.0', 'ZLIB', 'BLUEOAK-1.0.0', 'PYTHON-2.0', 'WTFPL',
  'CC-BY-4.0', 'CC-BY-3.0', 'ARTISTIC-2.0', 'POSTGRESQL', 'NCSA', 'JSON',
  'AFL-2.1', 'AFL-3.0', 'BSL-1.0', 'MIT-0', 'PUBLIC DOMAIN', 'PUBLIC-DOMAIN'
]);

/**
 * Clasifica un identificador SPDX simple (hoja) en una de las 5 categorías.
 * @param {string} rawLeaf
 * @returns {'permissive' | 'weak_copyleft' | 'strong_copyleft' | 'source_available' | 'unknown'}
 */
function classifySingleLicense(rawLeaf) {
  const clean = String(rawLeaf || '')
    .trim()
    .replace(/^\(+|\)+$/g, '')
    .replace(/\s+WITH\s+.+$/i, '')
    .trim();
  if (!clean) return 'unknown';

  const upper = clean.toUpperCase();
  if (upper === 'NONE' || upper === 'NOASSERTION' || upper === 'UNKNOWN') return 'unknown';

  // Source-available / non-OSI / proprietary / custom LicenseRef-*
  if (
    /^SSPL\b/i.test(upper)
    || /^BUSL\b/i.test(upper)
    || /^BSL-(?!1\.0$)/i.test(upper)
    || /^ELASTIC-2\.0/i.test(upper)
    || /^LICENSEREF-/i.test(upper)
    || /^PROPRIETARY/i.test(upper)
    || /^UNLICENSED$/i.test(upper)
    || /^COMMERCIAL/i.test(upper)
    || /^SEE LICENSE IN /i.test(upper)
    || /COMMONS-CLAUSE/i.test(upper)
  ) {
    return 'source_available';
  }

  // Strong copyleft (AGPL / GPL)
  if (/^A?GPL(?:[- ]|$)/i.test(upper) || /AFFERO/i.test(upper)) {
    return 'strong_copyleft';
  }

  // Weak copyleft (LGPL, MPL, EPL, CDDL, EUPL, OFL, CC-BY-SA)
  if (
    /^LGPL(?:[- ]|$)/i.test(upper)
    || /^MPL(?:[- ]|$)/i.test(upper)
    || /^EPL(?:[- ]|$)/i.test(upper)
    || /^CDDL(?:[- ]|$)/i.test(upper)
    || /^EUPL(?:[- ]|$)/i.test(upper)
    || /^CPL(?:[- ]|$)/i.test(upper)
    || /^OFL(?:[- ]|$)/i.test(upper)
    || /^CC-BY-SA/i.test(upper)
  ) {
    return 'weak_copyleft';
  }

  // Permissive exact + common prefixes
  if (PERMISSIVE_EXACT.has(upper) || /^(?:MIT|ISC|APACHE-2|BSD-[23]-CLAUSE|0BSD)/i.test(upper)) {
    return 'permissive';
  }

  return 'unknown';
}

/**
 * Divide una expresión por un operador lógico (`OR` / `AND`) respetando paréntesis.
 * @param {string} expr
 * @param {'OR' | 'AND'} op
 * @returns {string[]}
 */
function splitTopLevelOp(expr, op) {
  /** @type {string[]} */
  const parts = [];
  let depth = 0;
  let lastIdx = 0;
  const opToken = ` ${op} `;
  const upper = expr.toUpperCase();

  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i];
    if (ch === '(') depth++;
    else if (ch === ')') depth = Math.max(0, depth - 1);
    else if (depth === 0 && upper.startsWith(opToken, i)) {
      parts.push(expr.slice(lastIdx, i).trim());
      i += opToken.length - 1;
      lastIdx = i + 1;
    }
  }
  parts.push(expr.slice(lastIdx).trim());
  return parts.filter(Boolean);
}

/**
 * Quita paréntesis envolventes redundantes de una expresión SPDX `(MIT OR Apache-2.0)`.
 * @param {string} expr
 */
function stripOuterParens(expr) {
  let s = expr.trim();
  while (s.startsWith('(') && s.endsWith(')')) {
    let depth = 0;
    let wrapsEntire = true;
    for (let i = 0; i < s.length - 1; i++) {
      if (s[i] === '(') depth++;
      else if (s[i] === ')') {
        depth--;
        if (depth === 0) {
          wrapsEntire = false;
          break;
        }
      }
    }
    if (!wrapsEntire) break;
    s = s.slice(1, -1).trim();
  }
  return s;
}

/**
 * Evalúa recursivamente una expresión SPDX compuesta:
 *  - `OR` elige la categoría MÁS permisiva (menor `CATEGORY_STRICTNESS`)
 *  - `AND` elige la categoría MÁS restrictiva (mayor `CATEGORY_STRICTNESS`)
 *
 * @param {string} rawExpr
 * @returns {'permissive' | 'weak_copyleft' | 'strong_copyleft' | 'source_available' | 'unknown'}
 */
function evaluateSpdxCategory(rawExpr) {
  const s = stripOuterParens(String(rawExpr || '').replace(/\s+/g, ' ').trim());
  if (!s) return 'unknown';

  const orParts = splitTopLevelOp(s, 'OR');
  if (orParts.length > 1) {
    /** @type {'permissive' | 'weak_copyleft' | 'strong_copyleft' | 'source_available' | 'unknown'} */
    let best = 'unknown';
    for (const part of orParts) {
      const cat = evaluateSpdxCategory(part);
      if (CATEGORY_STRICTNESS[cat] < CATEGORY_STRICTNESS[best]) {
        best = cat;
      }
    }
    return best;
  }

  const andParts = splitTopLevelOp(s, 'AND');
  if (andParts.length > 1) {
    /** @type {'permissive' | 'weak_copyleft' | 'strong_copyleft' | 'source_available' | 'unknown'} */
    let strictest = 'permissive';
    for (const part of andParts) {
      const cat = evaluateSpdxCategory(part);
      if (CATEGORY_STRICTNESS[cat] > CATEGORY_STRICTNESS[strictest]) {
        strictest = cat;
      }
    }
    return strictest;
  }

  return classifySingleLicense(s);
}

/**
 * Clasifica una expresión SPDX simple o compuesta y devuelve su categoría y nivel de riesgo.
 * @param {string | null | undefined} expr
 */
function classifySpdxLicense(expr) {
  const normalized = String(expr || '').replace(/\s+/g, ' ').trim() || 'UNKNOWN';
  const category = evaluateSpdxCategory(normalized);
  return {
    expression: normalized,
    category,
    strictness: CATEGORY_STRICTNESS[category]
  };
}

/**
 * Extrae componentes `{ name, version, licenseExpr, purl }` desde un SBOM CycloneDX 1.6 JSON.
 * @param {any} sbom
 */
function extractComponentsFromSbom(sbom) {
  const obj = typeof sbom === 'string' ? JSON.parse(sbom) : sbom;
  const comps = obj && Array.isArray(obj.components) ? obj.components : [];
  return comps.map((c) => {
    /** @type {string[]} */
    const licList = [];
    if (Array.isArray(c.licenses)) {
      for (const entry of c.licenses) {
        if (!entry || typeof entry !== 'object') continue;
        if (typeof entry.expression === 'string' && entry.expression.trim()) {
          licList.push(entry.expression.trim());
        } else if (entry.license && typeof entry.license === 'object') {
          const idOrName = entry.license.id || entry.license.name || '';
          if (String(idOrName).trim()) licList.push(String(idOrName).trim());
        }
      }
    }
    const licenseExpr = licList.length > 1
      ? licList.join(' AND ')
      : (licList[0] || 'UNKNOWN');
    return {
      name: String(c.name || 'unknown'),
      version: String(c.version || ''),
      purl: c.purl ? String(c.purl) : null,
      licenseExpr
    };
  });
}

/**
 * Fallback local: extrae componentes y licencias desde `package-lock.json` o `package.json`.
 * @param {string} projectDir
 */
function extractComponentsFromProjectDir(projectDir) {
  const baseDir = path.resolve(projectDir);
  const lockPath = path.join(baseDir, 'package-lock.json');
  /** @type {Array<{ name: string, version: string, purl: string | null, licenseExpr: string }>} */
  const out = [];

  if (fs.existsSync(lockPath)) {
    try {
      const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
      if (lock && lock.packages && typeof lock.packages === 'object') {
        for (const [pkgPath, meta] of Object.entries(lock.packages)) {
          if (!pkgPath || !meta || typeof meta !== 'object') continue;
          const name = meta.name || pkgPath.replace(/^.*node_modules\//, '');
          const version = String(meta.version || '');
          let licenseExpr = typeof meta.license === 'string' ? meta.license : '';
          if (!licenseExpr) {
            // Intentar leer license del package.json instalado en node_modules si existe
            try {
              const modPkgPath = path.join(baseDir, pkgPath, 'package.json');
              if (fs.existsSync(modPkgPath)) {
                const modPkg = JSON.parse(fs.readFileSync(modPkgPath, 'utf8'));
                if (typeof modPkg.license === 'string') licenseExpr = modPkg.license;
                else if (modPkg.license && typeof modPkg.license.type === 'string') licenseExpr = modPkg.license.type;
              }
            } catch (e) {}
          }
          out.push({
            name: String(name),
            version,
            purl: version ? `pkg:npm/${name}@${version}` : null,
            licenseExpr: licenseExpr || 'UNKNOWN'
          });
        }
        if (out.length > 0) return out;
      }
    } catch (e) {}
  }

  const pkgPath = path.join(baseDir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      const deps = Object.entries(pkg.dependencies || {});
      for (const [depName, depVer] of deps) {
        let licenseExpr = 'UNKNOWN';
        try {
          const modPkgPath = path.join(baseDir, 'node_modules', depName, 'package.json');
          if (fs.existsSync(modPkgPath)) {
            const modPkg = JSON.parse(fs.readFileSync(modPkgPath, 'utf8'));
            if (typeof modPkg.license === 'string') licenseExpr = modPkg.license;
            else if (modPkg.license && typeof modPkg.license.type === 'string') licenseExpr = modPkg.license.type;
          }
        } catch (e) {}
        out.push({
          name: depName,
          version: String(depVer || ''),
          purl: `pkg:npm/${depName}`,
          licenseExpr
        });
      }
      if (out.length === 0) {
        out.push({
          name: String(pkg.name || 'root'),
          version: String(pkg.version || '0.0.0'),
          purl: null,
          licenseExpr: typeof pkg.license === 'string' ? pkg.license : 'UNKNOWN'
        });
      }
    } catch (e) {}
  }

  return out;
}

/**
 * Audita las licencias SPDX de un SBOM CycloneDX 1.6 o de un directorio de proyecto
 * bajo la política especificada (`saas-strict`, `oss-permissive`, `audit-only`).
 *
 * @param {{
 *   sbom?: any,
 *   projectDir?: string,
 *   policy?: 'saas-strict' | 'oss-permissive' | 'audit-only' | string
 * }} [opts]
 */
function auditLicenses(opts = {}) {
  const rawPolicy = String((opts && opts.policy) || 'saas-strict').trim().toLowerCase();
  if (!POLICIES.includes(rawPolicy)) {
    const err = new Error(`Política de licencias desconocida: "${rawPolicy}" (usa ${POLICIES.join(', ')})`);
    /** @type {any} */ (err).status = 400;
    throw err;
  }
  const policy = /** @type {'saas-strict' | 'oss-permissive' | 'audit-only'} */ (rawPolicy);

  const components = opts && opts.sbom
    ? extractComponentsFromSbom(opts.sbom)
    : extractComponentsFromProjectDir((opts && opts.projectDir) || path.resolve(__dirname, '..', '..'));

  const countsByCategory = {
    permissive: 0,
    weak_copyleft: 0,
    strong_copyleft: 0,
    source_available: 0,
    unknown: 0
  };

  /** @type {Array<{ name: string, version: string, license: string, category: string, reason: string }>} */
  const violations = [];
  /** @type {Array<{ name: string, version: string, license: string, category: string, reason: string }>} */
  const warnings = [];

  for (const comp of components) {
    const classified = classifySpdxLicense(comp.licenseExpr);
    countsByCategory[classified.category]++;

    const item = {
      name: comp.name,
      version: comp.version,
      license: classified.expression,
      category: classified.category,
      reason: ''
    };

    if (policy === 'saas-strict') {
      if (classified.category === 'strong_copyleft' || classified.category === 'source_available' || classified.category === 'unknown') {
        item.reason = `Policy "saas-strict" blocks ${classified.category} license "${classified.expression}".`;
        violations.push(item);
      } else if (classified.category === 'weak_copyleft') {
        item.reason = `Weak copyleft license "${classified.expression}" requires dynamic-linking/notice review.`;
        warnings.push(item);
      }
    } else if (policy === 'oss-permissive') {
      if (classified.category === 'strong_copyleft' || classified.category === 'source_available') {
        item.reason = `Policy "oss-permissive" blocks ${classified.category} license "${classified.expression}".`;
        violations.push(item);
      } else if (classified.category === 'weak_copyleft' || classified.category === 'unknown') {
        item.reason = `Review ${classified.category} license "${classified.expression}".`;
        warnings.push(item);
      }
    } else {
      // audit-only: warn only, always compliant
      if (classified.category !== 'permissive') {
        item.reason = `Audit notice: ${classified.category} license "${classified.expression}".`;
        warnings.push(item);
      }
    }
  }

  const totalComponents = components.length;
  const compliant = violations.length === 0;
  const score = totalComponents === 0
    ? 100
    : Math.max(0, Math.min(100, Math.round(100 - ((violations.length / totalComponents) * 80) - ((warnings.length / totalComponents) * 15))));

  return {
    ok: true,
    compliant,
    policy,
    score,
    totalComponents,
    countsByCategory,
    violations,
    warnings,
    auditedAt: new Date().toISOString()
  };
}

module.exports = {
  POLICIES,
  classifySpdxLicense,
  auditLicenses
};
