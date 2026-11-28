const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Archive ("Zip Slip") / Symlink Traversal & Zip-Bomb Firewall (100% Zero-Dep).
 *
 * Contramedida directa a `CVE-2026-23745` y `CVE-2026-23950` (`node-tar <=7.5.2` escapes
 * de symlink/hardlink y colisiones Unicode/mayúsculas), `CVE-2025-66626` (Argo Workflows
 * Zip-Slip RCE) y `CVE-2025-62725` (Docker Compose OCI traversal):
 *  - Normalización canónica POSIX de rutas y detección de `..` / rutas absolutas (`ZIP_SLIP_PATH_TRAVERSAL`).
 *  - Validación dual de ruta + `linkname` en symlinks/hardlinks (`SYMLINK_ESCAPE_BLOCKED`, `HARDLINK_ESCAPE_BLOCKED`).
 *  - Normalización Unicode NFC + case-folding detectando colisiones (`UNICODE_PATH_COLLISION`).
 *  - Bloqueo de bombas de descompresión `uncompressed/compressed > maxRatio` (`ZIP_BOMB_DETECTED`).
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/archive-slip-guard.json`.
 */

const MAX_AUDITS = 200;

/**
 * Resuelve dinámicamente la ruta a `archive-slip-guard.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'archive-slip-guard.json')
    : path.join(base, 'data', 'archive-slip-guard.json');
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
 * Normaliza un directorio raíz en formato POSIX canónico (`/srv/extract`).
 * @param {string} rawRoot
 */
function normalizeRootPosix(rawRoot) {
  const replaced = String(rawRoot || '/srv/extract').replace(/\\/g, '/').trim() || '/srv/extract';
  const resolved = path.posix.resolve('/', replaced);
  return resolved.endsWith('/') && resolved.length > 1 ? resolved.slice(0, -1) : resolved;
}

/**
 * Valida y normaliza una ruta de entrada de archivo contra `targetRoot`, bloqueando
 * rutas absolutas, bytes nulos, unidades Windows y traversal `..` fuera de `targetRoot`.
 *
 * @param {string} targetRoot
 * @param {string} entryPath
 */
function normalizeSafeEntryPath(targetRoot, entryPath) {
  const root = normalizeRootPosix(targetRoot);
  const raw = String(entryPath || '');

  if (!raw || raw.includes('\0')) {
    return { safe: false, code: 'ZIP_SLIP_PATH_TRAVERSAL', normalizedRelative: '', resolvedPath: null, canonicalKey: '' };
  }

  const posixEntry = raw.replace(/\\/g, '/');
  // Reject absolute paths, Windows drive letters, and UNC prefixes
  if (posixEntry.startsWith('/') || /^[a-zA-Z]:/.test(posixEntry)) {
    return { safe: false, code: 'ZIP_SLIP_PATH_TRAVERSAL', normalizedRelative: posixEntry, resolvedPath: null, canonicalKey: '' };
  }

  const resolved = path.posix.resolve(root, posixEntry);
  const rootPrefix = root === '/' ? '/' : `${root}/`;
  const staysInside = resolved === root || resolved.startsWith(rootPrefix);

  if (!staysInside) {
    return { safe: false, code: 'ZIP_SLIP_PATH_TRAVERSAL', normalizedRelative: posixEntry, resolvedPath: null, canonicalKey: '' };
  }

  const normalizedRelative = path.posix.relative(root, resolved);
  // Also reject explicit `..` traversal segments even if partially cancelled inside the archive
  if (posixEntry.split('/').some((seg) => seg === '..')) {
    return { safe: false, code: 'ZIP_SLIP_PATH_TRAVERSAL', normalizedRelative, resolvedPath: null, canonicalKey: '' };
  }

  const canonicalKey = normalizedRelative.normalize('NFC').toLowerCase();
  return {
    safe: true,
    code: 'SAFE_PATH',
    normalizedRelative,
    resolvedPath: resolved,
    canonicalKey
  };
}

/**
 * Inspecciona un manifiesto de archivo (`.tar`/`.tar.gz`/`.zip`/capas OCI) ANTES de extraerlo.
 *
 * @param {{
 *   targetRoot?: string,
 *   entries?: Array<{ path?: string, name?: string, type?: string, linkname?: string, target?: string, compressedBytes?: number, uncompressedBytes?: number, size?: number }>,
 *   maxRatio?: number,
 *   maxTotalUncompressedBytes?: number,
 *   allowSymlinks?: boolean,
 *   persist?: boolean
 * }} [input]
 */
function inspectArchiveManifest(input = {}) {
  const opts = input || {};
  const targetRoot = normalizeRootPosix(opts.targetRoot || '/srv/extract');
  const rootPrefix = targetRoot === '/' ? '/' : `${targetRoot}/`;
  const entries = Array.isArray(opts.entries) ? opts.entries : [];
  const maxRatio = Math.max(1, Number(opts.maxRatio ?? 100) || 100);
  const maxTotalUncompressedBytes = Math.max(1024, Number(opts.maxTotalUncompressedBytes ?? (512 * 1024 * 1024)) || (512 * 1024 * 1024));
  const allowSymlinks = Boolean(opts.allowSymlinks);

  /** @type {Array<{ code: string, severity: 'critical' | 'high', entry: string, message: string, fix: string }>} */
  const findings = [];
  /** @type {Map<string, string>} */
  const seenCanonical = new Map();

  let totalCompressedBytes = 0;
  let totalUncompressedBytes = 0;
  let flaggedBomb = false;

  for (const entry of entries) {
    if (!entry || typeof entry !== 'object') continue;
    const rawPath = String(entry.path || entry.name || '').trim();
    const type = String(entry.type || 'file').trim().toLowerCase();
    const linkname = entry.linkname !== undefined ? String(entry.linkname) : (entry.target !== undefined ? String(entry.target) : '');
    const comp = Math.max(0, Number(entry.compressedBytes) || 0);
    const uncomp = Math.max(0, Number(entry.uncompressedBytes ?? entry.size ?? 0) || 0);

    totalCompressedBytes += comp;
    totalUncompressedBytes += uncomp;

    // 1. Entry path canonical Zip-Slip check
    const pathCheck = normalizeSafeEntryPath(targetRoot, rawPath);
    if (!pathCheck.safe) {
      findings.push({
        code: 'ZIP_SLIP_PATH_TRAVERSAL',
        severity: 'critical',
        entry: rawPath,
        message: `Archive entry "${rawPath}" attempts path traversal outside extraction root "${targetRoot}".`,
        fix: 'Reject the archive and strip any absolute or `..` path entries before extraction.'
      });
    } else if (pathCheck.canonicalKey) {
      // 2. Unicode NFC & case-insensitive collision check (CVE-2026-23950)
      const prev = seenCanonical.get(pathCheck.canonicalKey);
      if (prev && prev !== rawPath) {
        findings.push({
          code: 'UNICODE_PATH_COLLISION',
          severity: 'critical',
          entry: rawPath,
          message: `Archive contains Unicode/case-colliding paths "${prev}" and "${rawPath}" (CVE-2026-23950 race risk on case-insensitive filesystems).`,
          fix: 'Reject archives containing duplicate case-folded or NFC-equivalent entry paths.'
        });
      } else {
        seenCanonical.set(pathCheck.canonicalKey, rawPath);
      }
    }

    // 3. Symlink & hardlink target escape check (CVE-2026-23745)
    const isSymlink = type === 'symlink' || type === 'symboliclink';
    const isHardlink = type === 'hardlink' || type === 'link';
    if (isSymlink || isHardlink || linkname) {
      const linkPosix = linkname.replace(/\\/g, '/').trim();
      const entryDir = pathCheck.resolvedPath ? path.posix.dirname(pathCheck.resolvedPath) : targetRoot;
      const isAbsLink = linkPosix.startsWith('/') || /^[a-zA-Z]:/.test(linkPosix);
      const resolvedLink = isAbsLink
        ? path.posix.resolve('/', linkPosix)
        : path.posix.resolve(entryDir, linkPosix || '.');
      const linkInside = !isAbsLink && (resolvedLink === targetRoot || resolvedLink.startsWith(rootPrefix));

      if (!linkInside || (!allowSymlinks && isSymlink && linkPosix.includes('..'))) {
        const code = isHardlink ? 'HARDLINK_ESCAPE_BLOCKED' : 'SYMLINK_ESCAPE_BLOCKED';
        findings.push({
          code,
          severity: 'critical',
          entry: rawPath,
          message: `Archive ${isHardlink ? 'hardlink' : 'symlink'} "${rawPath}" -> "${linkname}" escapes extraction root "${targetRoot}" (CVE-2026-23745).`,
          fix: 'Reject archives containing absolute or root-escaping symlinks/hardlinks.'
        });
      }
    }

    // 4. Per-entry Zip-Bomb compression ratio check
    if (comp > 0 && (uncomp / comp) > maxRatio) {
      const ratio = Math.round((uncomp / comp) * 10) / 10;
      flaggedBomb = true;
      findings.push({
        code: 'ZIP_BOMB_DETECTED',
        severity: 'critical',
        entry: rawPath,
        message: `Archive entry "${rawPath}" decompression ratio ${ratio}:1 exceeds maxRatio ${maxRatio}:1 (${uncomp} B uncompressed / ${comp} B compressed).`,
        fix: 'Abort extraction before allocating disk/RAM and reject high-ratio compressed payloads.'
      });
    }
  }

  // 5. Aggregate uncompressed size / overall ratio Zip-Bomb check
  const overallRatio = totalCompressedBytes > 0
    ? Math.round((totalUncompressedBytes / totalCompressedBytes) * 10) / 10
    : 1;
  if (!flaggedBomb && (totalUncompressedBytes > maxTotalUncompressedBytes || (totalCompressedBytes > 0 && overallRatio > maxRatio))) {
    findings.push({
      code: 'ZIP_BOMB_DETECTED',
      severity: 'critical',
      entry: '<archive>',
      message: `Aggregate archive payload (${totalUncompressedBytes} B, ratio ${overallRatio}:1) exceeds safe extraction budget.`,
      fix: 'Enforce strict streaming uncompressed byte caps during extraction.'
    });
  }

  const safe = findings.length === 0;
  const blocked = !safe;
  const status = safe ? 'SAFE' : 'BLOCKED';
  const findingCodes = Array.from(new Set(findings.map((f) => f.code)));
  const inspectedAt = new Date().toISOString();

  const result = {
    ok: true,
    id: `arch_${crypto.randomBytes(5).toString('hex')}`,
    targetRoot,
    safe,
    blocked,
    status,
    entriesInspected: entries.length,
    totalCompressedBytes,
    totalUncompressedBytes,
    compressionRatio: overallRatio,
    findings,
    findingCodes,
    inspectedAt
  };

  if (opts.persist !== false) {
    const store = loadStore();
    store.audits.push({
      id: result.id,
      targetRoot,
      safe,
      status,
      entriesInspected: result.entriesInspected,
      compressionRatio: overallRatio,
      findingCodes,
      inspectedAt
    });
    saveStore(store);
  }

  return result;
}

/**
 * Lista auditorías de archivos almacenadas (más recientes primero).
 */
function listArchiveAudits() {
  const store = loadStore();
  return [...store.audits].reverse();
}

module.exports = {
  normalizeSafeEntryPath,
  inspectArchiveManifest,
  listArchiveAudits
};
