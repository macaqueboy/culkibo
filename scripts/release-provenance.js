#!/usr/bin/env node
'use strict';

/**
 * Culkibo Release Provenance, CycloneDX 1.6 SBOM & SHA-256 Checksum Generator.
 *
 * Garantías:
 *  - Cero dependencias npm externas (únicamente `fs`, `path`, `crypto`).
 *  - Cero ejecución de shell (`child_process` no importado).
 *  - Determinista: listas ordenadas lexicográficamente en formato POSIX.
 *  - Nunca muta `data/*.json` ni archivos fuente; escribe solo en `--out-dir` (default `dist-release/`).
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DEFAULT_ROOT_DIR = path.resolve(__dirname, '..');

/** @param {string} filePath */
function readJsonSafe(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (e) {
    return null;
  }
}

/** @param {Buffer | string} content */
function sha256Hex(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Convierte un nombre de paquete npm (con o sin `@scope/`) + versión a Package URL (PURL) RFC-compliant.
 * @param {string} name
 * @param {string} version
 * @returns {string}
 */
function buildNpmPurl(name, version) {
  const cleanName = String(name || '').trim();
  const cleanVer = String(version || '0.0.0').replace(/^[~^>=<\s]+/, '').trim() || '0.0.0';
  if (cleanName.startsWith('@')) {
    const slash = cleanName.indexOf('/');
    if (slash > 1) {
      const scope = encodeURIComponent(cleanName.slice(0, slash));
      const pkg = encodeURIComponent(cleanName.slice(slash + 1));
      return `pkg:npm/${scope}/${pkg}@${encodeURIComponent(cleanVer)}`;
    }
  }
  return `pkg:npm/${encodeURIComponent(cleanName)}@${encodeURIComponent(cleanVer)}`;
}

/**
 * Convierte un SRI `sha512-...` o `sha256-...` de `package-lock.json` al formato `hashes` de CycloneDX 1.6.
 * @param {string | undefined | null} integrity
 * @returns {Array<{ alg: string, content: string }>}
 */
function parseIntegrityToCdxHashes(integrity) {
  if (typeof integrity !== 'string' || !integrity.includes('-')) return [];
  const dashIdx = integrity.indexOf('-');
  const algRaw = integrity.slice(0, dashIdx).toLowerCase();
  const b64 = integrity.slice(dashIdx + 1).trim();
  /** @type {Record<string, string>} */
  const algMap = { sha512: 'SHA-512', sha384: 'SHA-384', sha256: 'SHA-256', sha1: 'SHA-1' };
  const cdxAlg = algMap[algRaw];
  if (!cdxAlg || !b64) return [];
  try {
    const hex = Buffer.from(b64, 'base64').toString('hex');
    if (!hex) return [];
    return [{ alg: cdxAlg, content: hex }];
  } catch (e) {
    return [];
  }
}

/**
 * Extrae metadatos de licencia CycloneDX 1.6 cuando está disponible en lockfile o manifest.
 * @param {any} rawLicense
 */
function formatCdxLicenses(rawLicense) {
  if (!rawLicense) return undefined;
  if (typeof rawLicense === 'string' && rawLicense.trim()) {
    return [{ license: { id: rawLicense.trim() } }];
  }
  return undefined;
}

/**
 * Genera un SBOM CycloneDX 1.6 válido (JSON) inspeccionando `package.json`, `package-lock.json`,
 * `web/package.json` y `telemetry-collector/package.json`.
 *
 * @param {{ rootDir?: string, timestamp?: string, serialNumber?: string }} [opts]
 */
function generateCycloneDxSbom(opts = {}) {
  const rootDir = path.resolve(opts.rootDir || DEFAULT_ROOT_DIR);
  const rootPkg = readJsonSafe(path.join(rootDir, 'package.json')) || { name: 'culkibo', version: '1.2.0', dependencies: {} };
  const rootLock = readJsonSafe(path.join(rootDir, 'package-lock.json'));
  const webPkg = readJsonSafe(path.join(rootDir, 'web', 'package.json')) || { name: 'web', version: '0.0.0', dependencies: {} };
  const collectorPkg = readJsonSafe(path.join(rootDir, 'telemetry-collector', 'package.json')) || {
    name: 'culkibo-telemetry-collector',
    version: '1.0.0',
    dependencies: {}
  };

  const rootVersion = String(rootPkg.version || '1.2.0');
  const rootName = String(rootPkg.name || 'culkibo');
  const rootDeps = rootPkg.dependencies && typeof rootPkg.dependencies === 'object' ? rootPkg.dependencies : {};
  const webDeps = webPkg.dependencies && typeof webPkg.dependencies === 'object' ? webPkg.dependencies : {};
  const collectorDeps = collectorPkg.dependencies && typeof collectorPkg.dependencies === 'object' ? collectorPkg.dependencies : {};

  /** @type {Map<string, any>} */
  const componentMap = new Map();
  /** @type {Map<string, Set<string>>} */
  const depGraph = new Map();

  const rootBomRef = buildNpmPurl(rootName, rootVersion);
  const webBomRef = buildNpmPurl('culkibo-web', rootVersion);
  const collectorBomRef = buildNpmPurl(String(collectorPkg.name || 'culkibo-telemetry-collector'), String(collectorPkg.version || '1.0.0'));

  depGraph.set(rootBomRef, new Set([webBomRef, collectorBomRef]));
  depGraph.set(webBomRef, new Set());
  depGraph.set(collectorBomRef, new Set());

  // Sub-componentes internos del workspace (web + telemetry-collector)
  componentMap.set(webBomRef, {
    type: 'application',
    'bom-ref': webBomRef,
    name: 'culkibo-web',
    version: rootVersion,
    purl: webBomRef,
    scope: 'required',
    properties: [
      { name: 'culkibo:workspace', value: 'web' },
      { name: 'culkibo:runtime_dependencies', value: String(Object.keys(webDeps).length) }
    ]
  });

  componentMap.set(collectorBomRef, {
    type: 'application',
    'bom-ref': collectorBomRef,
    name: String(collectorPkg.name || 'culkibo-telemetry-collector'),
    version: String(collectorPkg.version || '1.0.0'),
    purl: collectorBomRef,
    scope: 'optional',
    properties: [
      { name: 'culkibo:workspace', value: 'telemetry-collector' },
      { name: 'culkibo:runtime_dependencies', value: String(Object.keys(collectorDeps).length) }
    ]
  });

  /** @type {Map<string, string>} */
  const resolvedRootVersions = new Map();

  // Resolver dependencias del lockfile raíz (solo dependencias runtime — excluir dev:true)
  if (rootLock && rootLock.packages && typeof rootLock.packages === 'object') {
    for (const [pkgPath, meta] of Object.entries(rootLock.packages)) {
      if (!pkgPath || pkgPath === '' || !meta || typeof meta !== 'object') continue;
      if (meta.dev === true) continue;
      const idx = pkgPath.lastIndexOf('node_modules/');
      if (idx === -1) continue;
      const pkgName = meta.name || pkgPath.slice(idx + 'node_modules/'.length);
      const pkgVersion = String(meta.version || '').trim();
      if (!pkgName || !pkgVersion) continue;
      const purl = buildNpmPurl(pkgName, pkgVersion);
      if (pkgPath === `node_modules/${pkgName}`) {
        resolvedRootVersions.set(pkgName, purl);
      }
      if (!componentMap.has(purl)) {
        const hashes = parseIntegrityToCdxHashes(meta.integrity);
        const licenses = formatCdxLicenses(meta.license);
        componentMap.set(purl, {
          type: 'library',
          'bom-ref': purl,
          name: pkgName,
          version: pkgVersion,
          purl,
          scope: meta.optional ? 'optional' : 'required',
          ...(licenses ? { licenses } : {}),
          ...(hashes.length > 0 ? { hashes } : {}),
          properties: [
            { name: 'culkibo:workspace', value: 'root' },
            { name: 'culkibo:direct', value: Object.prototype.hasOwnProperty.call(rootDeps, pkgName) ? 'true' : 'false' }
          ]
        });
      }
    }
  }

  // Asegurar que todas las dependencias directas raíz estén presentes (incluso sin lockfile)
  for (const [depName, depRange] of Object.entries(rootDeps).sort(([a], [b]) => a.localeCompare(b))) {
    const existingPurl = resolvedRootVersions.get(depName);
    if (existingPurl) {
      depGraph.get(rootBomRef)?.add(existingPurl);
      continue;
    }
    const cleanVer = String(depRange || '0.0.0').replace(/^[~^>=<\s]+/, '') || '0.0.0';
    const purl = buildNpmPurl(depName, cleanVer);
    depGraph.get(rootBomRef)?.add(purl);
    if (!componentMap.has(purl)) {
      componentMap.set(purl, {
        type: 'library',
        'bom-ref': purl,
        name: depName,
        version: cleanVer,
        purl,
        scope: 'required',
        properties: [
          { name: 'culkibo:workspace', value: 'root' },
          { name: 'culkibo:direct', value: 'true' }
        ]
      });
    }
  }

  // Dependencias directas de frontend (`web/package.json`)
  for (const [depName, depRange] of Object.entries(webDeps).sort(([a], [b]) => a.localeCompare(b))) {
    const cleanVer = String(depRange || '0.0.0').replace(/^[~^>=<\s]+/, '') || '0.0.0';
    const purl = buildNpmPurl(depName, cleanVer);
    depGraph.get(webBomRef)?.add(purl);
    if (!componentMap.has(purl)) {
      componentMap.set(purl, {
        type: 'library',
        'bom-ref': purl,
        name: depName,
        version: cleanVer,
        purl,
        scope: 'required',
        properties: [
          { name: 'culkibo:workspace', value: 'web' },
          { name: 'culkibo:direct', value: 'true' }
        ]
      });
    }
  }

  // Dependencias directas de `telemetry-collector/package.json` (esperado: 0)
  for (const [depName, depRange] of Object.entries(collectorDeps).sort(([a], [b]) => a.localeCompare(b))) {
    const cleanVer = String(depRange || '0.0.0').replace(/^[~^>=<\s]+/, '') || '0.0.0';
    const purl = buildNpmPurl(depName, cleanVer);
    depGraph.get(collectorBomRef)?.add(purl);
    if (!componentMap.has(purl)) {
      componentMap.set(purl, {
        type: 'library',
        'bom-ref': purl,
        name: depName,
        version: cleanVer,
        purl,
        scope: 'required',
        properties: [
          { name: 'culkibo:workspace', value: 'telemetry-collector' },
          { name: 'culkibo:direct', value: 'true' }
        ]
      });
    }
  }

  const components = Array.from(componentMap.values()).sort((a, b) =>
    String(a['bom-ref']).localeCompare(String(b['bom-ref']))
  );

  const dependencies = Array.from(depGraph.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([ref, deps]) => ({
      ref,
      dependsOn: Array.from(deps).sort()
    }));

  const sbom = {
    $schema: 'http://cyclonedx.org/schema/bom-1.6.schema.json',
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: opts.serialNumber || `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: opts.timestamp || new Date().toISOString(),
      tools: {
        components: [
          {
            type: 'application',
            name: 'culkibo-release-provenance',
            version: rootVersion
          }
        ]
      },
      component: {
        type: 'application',
        'bom-ref': rootBomRef,
        name: rootName,
        version: rootVersion,
        description: String(rootPkg.description || ''),
        licenses: [{ license: { id: String(rootPkg.license || 'Apache-2.0') } }],
        purl: rootBomRef,
        properties: [
          { name: 'culkibo:root_runtime_dependencies', value: String(Object.keys(rootDeps).length) },
          { name: 'culkibo:collector_runtime_dependencies', value: String(Object.keys(collectorDeps).length) },
          { name: 'culkibo:web_runtime_dependencies', value: String(Object.keys(webDeps).length) },
          { name: 'culkibo:shell_execution_policy', value: 'shell:false' }
        ]
      }
    },
    components,
    dependencies
  };

  return sbom;
}

/**
 * Recolecta la lista determinista de archivos clave del servidor, CLI y recolector para `CHECKSUMS.sha256`.
 * @param {string} rootDir
 * @returns {string[]}
 */
function collectReleaseFiles(rootDir) {
  /** @type {string[]} */
  const relPaths = [];
  const fixedFiles = [
    'package.json',
    'bin/culkibo.js',
    'server/index.js',
    'telemetry-collector/package.json',
    'telemetry-collector/server.js',
    'scripts/release-provenance.js'
  ];
  for (const rel of fixedFiles) {
    if (fs.existsSync(path.join(rootDir, rel))) relPaths.push(rel);
  }

  const dirs = [
    'server/middleware',
    'server/models',
    'server/routes',
    'server/services'
  ];
  for (const dirRel of dirs) {
    const absDir = path.join(rootDir, dirRel);
    if (!fs.existsSync(absDir)) continue;
    for (const entry of fs.readdirSync(absDir, { withFileTypes: true })) {
      if (entry.isFile() && entry.name.endsWith('.js')) {
        relPaths.push(`${dirRel}/${entry.name}`);
      }
    }
  }
  return Array.from(new Set(relPaths)).sort();
}

/**
 * Genera el manifiesto determinista `CHECKSUMS.sha256` sobre los archivos clave del plano de control y CLI.
 * @param {{ rootDir?: string, files?: string[] }} [opts]
 */
function generateChecksums(opts = {}) {
  const rootDir = path.resolve(opts.rootDir || DEFAULT_ROOT_DIR);
  const relList = Array.isArray(opts.files) && opts.files.length > 0
    ? Array.from(new Set(opts.files.map((f) => String(f).replace(/\\/g, '/')))).sort()
    : collectReleaseFiles(rootDir);

  /** @type {Array<{ path: string, sha256: string, bytes: number }>} */
  const entries = [];
  /** @type {string[]} */
  const lines = [];

  for (const rel of relList) {
    if (!rel || rel.startsWith('/') || rel.includes('..') || /^[A-Za-z]:/.test(rel)) {
      throw new Error(`Ruta relativa insegura rechazada en checksums: "${rel}"`);
    }
    const abs = path.resolve(rootDir, rel);
    const relativeBack = path.relative(rootDir, abs);
    if (relativeBack.startsWith('..') || path.isAbsolute(relativeBack)) {
      throw new Error(`Ruta fuera de rootDir rechazada en checksums: "${rel}"`);
    }
    const buf = fs.readFileSync(abs);
    const digest = sha256Hex(buf);
    entries.push({ path: rel, sha256: digest, bytes: buf.length });
    lines.push(`${digest}  ${rel}`);
  }

  const text = lines.join('\n') + (lines.length > 0 ? '\n' : '');
  return {
    algorithm: 'sha256',
    count: entries.length,
    files: entries,
    text
  };
}

/**
 * Verifica un archivo o texto `CHECKSUMS.sha256` contra el directorio raíz (detección de manipulación/corrupción).
 * @param {string} checksumsTextOrPath
 * @param {{ rootDir?: string }} [opts]
 */
function verifyChecksums(checksumsTextOrPath, opts = {}) {
  const rootDir = path.resolve(opts.rootDir || DEFAULT_ROOT_DIR);
  const rawText = (typeof checksumsTextOrPath === 'string' && !checksumsTextOrPath.includes('\n') && fs.existsSync(checksumsTextOrPath))
    ? fs.readFileSync(checksumsTextOrPath, 'utf8')
    : String(checksumsTextOrPath || '');

  /** @type {string[]} */
  const missing = [];
  /** @type {Array<{ path: string, expected: string, actual: string }>} */
  const mismatched = [];
  /** @type {string[]} */
  const malformed = [];
  let checked = 0;

  for (const rawLine of rawText.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const m = line.match(/^([a-f0-9]{64})\s+\*?(.+)$/i);
    if (!m) {
      malformed.push(line.slice(0, 80));
      continue;
    }
    const expected = m[1].toLowerCase();
    const rel = m[2].trim().replace(/\\/g, '/');
    if (!rel || rel.startsWith('/') || rel.includes('..') || /^[A-Za-z]:/.test(rel)) {
      malformed.push(rel.slice(0, 80));
      continue;
    }
    const abs = path.resolve(rootDir, rel);
    const back = path.relative(rootDir, abs);
    if (back.startsWith('..') || path.isAbsolute(back)) {
      malformed.push(rel.slice(0, 80));
      continue;
    }
    if (!fs.existsSync(abs)) {
      missing.push(rel);
      continue;
    }
    checked++;
    const actual = sha256Hex(fs.readFileSync(abs));
    if (actual !== expected) {
      mismatched.push({ path: rel, expected, actual });
    }
  }

  const valid = checked > 0 && missing.length === 0 && mismatched.length === 0 && malformed.length === 0;
  return { valid, checked, missing, mismatched, malformed };
}

/**
 * Escritura atómica local sin dependencias externas (temp + rename).
 * @param {string} targetPath
 * @param {string} content
 */
function atomicWriteTextSync(targetPath, content) {
  const dir = path.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = `${targetPath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, content, { encoding: 'utf8', mode: 0o644 });
  fs.renameSync(tmp, targetPath);
}

/**
 * Genera y escribe `sbom.cdx.json`, `CHECKSUMS.sha256` y `provenance.json` en `outDir`.
 * @param {{ rootDir?: string, outDir?: string, timestamp?: string, files?: string[] }} [opts]
 */
function writeReleaseProvenance(opts = {}) {
  const rootDir = path.resolve(opts.rootDir || DEFAULT_ROOT_DIR);
  const outDir = path.resolve(opts.outDir || path.join(rootDir, 'dist-release'));
  const timestamp = opts.timestamp || new Date().toISOString();

  const sbom = generateCycloneDxSbom({ rootDir, timestamp });
  const checksums = generateChecksums({ rootDir, files: opts.files });

  const sbomJson = JSON.stringify(sbom, null, 2) + '\n';
  const sbomSha256 = sha256Hex(sbomJson);
  const checksumsSha256 = sha256Hex(checksums.text);

  const rootPkg = readJsonSafe(path.join(rootDir, 'package.json')) || {};
  const webPkg = readJsonSafe(path.join(rootDir, 'web', 'package.json')) || {};
  const collectorPkg = readJsonSafe(path.join(rootDir, 'telemetry-collector', 'package.json')) || {};

  const counts = {
    rootDeps: Object.keys(rootPkg.dependencies || {}).length,
    webDeps: Object.keys(webPkg.dependencies || {}).length,
    collectorDeps: Object.keys(collectorPkg.dependencies || {}).length,
    sbomComponents: sbom.components.length,
    checksumFiles: checksums.count
  };

  const provenance = {
    schema: 'culkibo-release-provenance/v1',
    name: sbom.metadata.component.name,
    version: sbom.metadata.component.version,
    license: String(rootPkg.license || 'Apache-2.0'),
    generatedAt: timestamp,
    runtime: {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch
    },
    invariants: {
      rootRuntimeDeps: counts.rootDeps,
      collectorRuntimeDeps: counts.collectorDeps,
      webRuntimeDeps: counts.webDeps,
      shellExecutionPolicy: 'shell:false'
    },
    artifacts: {
      sbom: { file: 'sbom.cdx.json', format: 'CycloneDX', specVersion: '1.6', sha256: sbomSha256 },
      checksums: { file: 'CHECKSUMS.sha256', algorithm: 'sha256', filesCount: counts.checksumFiles, sha256: checksumsSha256 }
    }
  };

  const sbomPath = path.join(outDir, 'sbom.cdx.json');
  const checksumsPath = path.join(outDir, 'CHECKSUMS.sha256');
  const provenancePath = path.join(outDir, 'provenance.json');

  atomicWriteTextSync(sbomPath, sbomJson);
  atomicWriteTextSync(checksumsPath, checksums.text);
  atomicWriteTextSync(provenancePath, JSON.stringify(provenance, null, 2) + '\n');

  return {
    ok: true,
    version: provenance.version,
    outDir,
    files: {
      sbom: sbomPath,
      checksums: checksumsPath,
      provenance: provenancePath
    },
    counts,
    hashes: {
      sbomSha256,
      checksumsSha256
    },
    sbom,
    provenance
  };
}

/** @param {string[]} argv */
function parseCliArgs(argv) {
  /** @type {{ outDir?: string, json: boolean, stdoutSbom: boolean, verify?: string }} */
  const out = { json: false, stdoutSbom: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') out.json = true;
    else if (a === '--stdout-sbom') out.stdoutSbom = true;
    else if (a === '--out-dir' && argv[i + 1]) { out.outDir = argv[++i]; }
    else if (a.startsWith('--out-dir=')) { out.outDir = a.slice('--out-dir='.length); }
    else if (a === '--verify' && argv[i + 1]) { out.verify = argv[++i]; }
    else if (a.startsWith('--verify=')) { out.verify = a.slice('--verify='.length); }
  }
  return out;
}

if (require.main === module) {
  const args = parseCliArgs(process.argv.slice(2));
  if (args.verify) {
    const res = verifyChecksums(args.verify);
    if (args.json) console.log(JSON.stringify(res, null, 2));
    else console.log(res.valid ? `OK: ${res.checked} files verified.` : `FAILED: missing=${res.missing.length} mismatched=${res.mismatched.length} malformed=${res.malformed.length}`);
    process.exit(res.valid ? 0 : 1);
  }
  if (args.stdoutSbom) {
    console.log(JSON.stringify(generateCycloneDxSbom(), null, 2));
    process.exit(0);
  }
  const result = writeReleaseProvenance({ outDir: args.outDir });
  if (args.json) {
    console.log(JSON.stringify({
      ok: result.ok,
      version: result.version,
      outDir: result.outDir,
      files: result.files,
      counts: result.counts,
      hashes: result.hashes
    }, null, 2));
  } else {
    console.log(`Culkibo v${result.version} release provenance generated in ${result.outDir}`);
    console.log(`  - sbom.cdx.json   (${result.counts.sbomComponents} components, ROOT_DEPS=${result.counts.rootDeps}, COLLECTOR_DEPS=${result.counts.collectorDeps})`);
    console.log(`  - CHECKSUMS.sha256 (${result.counts.checksumFiles} files, sha256:${result.hashes.checksumsSha256.slice(0, 16)}...)`);
    console.log(`  - provenance.json`);
  }
}

module.exports = {
  generateCycloneDxSbom,
  generateChecksums,
  verifyChecksums,
  writeReleaseProvenance,
  buildNpmPurl,
  parseIntegrityToCdxHashes
};
