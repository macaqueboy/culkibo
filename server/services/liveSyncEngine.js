const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { EventEmitter } = require('events');

/**
 * Motor de sincronización en vivo (The Forge): guarda un fichero en local y
 * aparece servido en el destino en milisegundos, sin commit, sin build y sin
 * simulaciones.
 *
 * Propiedades reales implementadas aquí:
 *  1. Commit frames atómicos: un agente de IA edita 15 ficheros en ráfaga y
 *     llegan como una única transacción numerada (`seq`), evitando estados
 *     intermedios rotos.
 *  2. Deduplicación por SHA-256: un fichero cuyo contenido ya coincide con el
 *     disco no vuelve a escribirse ni provoca recargas innecesarias.
 *  3. Historial de parches en memoria: cada commit frame guarda los bytes
 *     anteriores exactos para revertir (`rollback`) en <10 ms sin reconstruir.
 *  4. Clasificación honesta Camino B vs Camino C: nunca disfraza un cambio de
 *     dependencias o Dockerfile de hot-reload; lo declara como `path_c_restart`.
 *  5. Integridad por árbol de Merkle: `computeMerkleTree()` y `verifySync()`
 *     hacen imposible la divergencia silenciosa entre máquina local y servidor.
 *  6. Seguridad estricta de rutas: bloquea traversal (`..`), rutas absolutas,
 *     bytes nulos, escritura en `.git/` y escapes por symlink.
 */

const IGNORED_DIRS = new Set([
  '.git',
  'node_modules',
  '.next',
  '.nuxt',
  '.turbo',
  '.svelte-kit',
  '.output',
  '.astro',
  '.cache',
  '.culkibo',
  'dist',
  'build',
  'coverage',
  '__pycache__',
  '.venv',
  'venv',
  'target',
  'vendor'
]);

const IGNORED_FILES = new Set(['.DS_Store', 'Thumbs.db']);

const MAX_FILES_PER_FRAME = 500;
const MAX_FILE_BYTES = 10 * 1024 * 1024; // 10 MiB por fichero en un frame
const MAX_CHUNKED_FILE_BYTES = 100 * 1024 * 1024; // 100 MiB máximo para carga troceada con SHA-256
const MAX_CHUNK_BYTES = 4 * 1024 * 1024; // 4 MiB máximo por trozo
const MAX_ACTIVE_CHUNK_UPLOADS = 16;
const CHUNK_UPLOAD_TTL_MS = 5 * 60 * 1000;
const MAX_PATCH_HISTORY = 25;
const MAX_LATENCY_SAMPLES = 200;

const FRAME_MAGIC_RAW = 0x01;
const FRAME_MAGIC_BROTLI = 0x02;
const FRAME_MAGIC_GZIP = 0x03;
const MAX_DECOMPRESSED_FRAME_BYTES = 16 * 1024 * 1024 + 512 * 1024; // 16.5 MiB anti-zip-bomb
const MAX_FRAME_META_BYTES = 2 * 1024 * 1024; // 2 MiB cabecera JSON máxima

const MAX_PER_FILE_HISTORY = 30;
const MAX_TRACKED_FILES_HISTORY = 250;
const MAX_FILE_SNAPSHOT_BYTES = 1024 * 1024; // 1 MiB snapshot por revisión
const MAX_FILE_HISTORY_BYTES = 24 * 1024 * 1024; // 24 MiB tope por sesión
const SNAPSHOT_COMPRESS_THRESHOLD = 4096;
const MAX_FILE_TOUCH_ENTRIES = 2000;
const MAX_RECENT_CONFLICTS = 50;
const DEFAULT_CONFLICT_WINDOW_MS = 15000;
const MAX_LCS_DIFF_LINES = 400;

/** @type {typeof import('zlib') | null} */
let _zlib = null;
function getZlib() {
  if (!_zlib) _zlib = require('zlib');
  return _zlib;
}

/**
 * Decodifica un payload binario comprimido o crudo con defensa nativa anti-zip-bomb
 * (`maxOutputLength` en C++ de Node `zlib`).
 *
 * - `0x01`: payload crudo (verifica `buf.length <= maxOutBytes`).
 * - `0x02`: Brotli (`zlib.brotliDecompressSync` con `{ maxOutputLength }`).
 * - `0x03`: Gzip (`zlib.gunzipSync` con `{ maxOutputLength }`).
 *
 * @param {number} codecByte
 * @param {Buffer} buf
 * @param {number} [maxOutBytes]
 * @returns {Buffer}
 */
function decodeCompressedPayload(codecByte, buf, maxOutBytes = MAX_DECOMPRESSED_FRAME_BYTES) {
  if (!Buffer.isBuffer(buf)) {
    const err = new Error('El payload binario debe ser un Buffer');
    /** @type {any} */ (err).code = 'BAD_FRAME';
    throw err;
  }
  const limit = (typeof maxOutBytes === 'number' && Number.isFinite(maxOutBytes) && maxOutBytes > 0)
    ? Math.min(Math.floor(maxOutBytes), MAX_DECOMPRESSED_FRAME_BYTES)
    : MAX_DECOMPRESSED_FRAME_BYTES;

  if (codecByte === FRAME_MAGIC_RAW) {
    if (buf.length > limit) {
      const err = new Error(`Trama binaria excede el límite máximo permitido (${limit} bytes)`);
      /** @type {any} */ (err).code = 'FRAME_TOO_LARGE';
      throw err;
    }
    return buf;
  }

  if (codecByte === FRAME_MAGIC_BROTLI || codecByte === FRAME_MAGIC_GZIP) {
    const z = getZlib();
    try {
      const out = codecByte === FRAME_MAGIC_BROTLI
        ? z.brotliDecompressSync(buf, { maxOutputLength: limit })
        : z.gunzipSync(buf, { maxOutputLength: limit });
      if (out.length > limit) {
        const err = new Error(`Trama comprimida excede el límite máximo descomprimido (${limit} bytes)`);
        /** @type {any} */ (err).code = 'FRAME_TOO_LARGE';
        throw err;
      }
      return out;
    } catch (e) {
      if (e && (e.code === 'ERR_BUFFER_TOO_LARGE' || e.code === 'FRAME_TOO_LARGE')) {
        const err = new Error(`Trama comprimida rechazada por límite anti-zip-bomb (${limit} bytes)`);
        /** @type {any} */ (err).code = 'FRAME_TOO_LARGE';
        throw err;
      }
      const err = new Error(`Error descomprimiendo trama binaria (${codecByte === FRAME_MAGIC_BROTLI ? 'br' : 'gzip'}): ${e && e.message ? e.message : String(e)}`);
      /** @type {any} */ (err).code = 'BAD_FRAME';
      throw err;
    }
  }

  const err = new Error(`Códec binario no soportado: 0x${Number(codecByte).toString(16)}`);
  /** @type {any} */ (err).code = 'UNSUPPORTED_CODEC';
  throw err;
}

/**
 * Decodifica una trama binaria completa de Commit Frame (`/ws/sync`):
 * - `0x01`: `[1B 0x01][4B uint32BE metaLen][JSON meta][buffers]`
 * - `0x02`: `[1B 0x02][4B uint32BE rawLen][brotli([4B metaLen][JSON meta][buffers])]`
 * - `0x03`: `[1B 0x03][4B uint32BE rawLen][gzip([4B metaLen][JSON meta][buffers])]`
 *
 * Protecciones:
 * - `rawLen <= 16.5 MiB`, `metaLen <= 2 MiB`, `decompressed.length === rawLen`,
 *   y `maxOutputLength` nativo en `zlib` (anti-zip-bomb).
 * - Desacopla slices respaldados por un slab ArrayBuffer >2x el fichero.
 *
 * @param {Buffer} buf
 * @param {number} [maxOutBytes]
 */
function decodeBinarySyncFrame(buf, maxOutBytes = MAX_DECOMPRESSED_FRAME_BYTES) {
  if (!Buffer.isBuffer(buf) || buf.length < 5) {
    const err = new Error('Trama binaria de sincronización inválida');
    /** @type {any} */ (err).code = 'BAD_FRAME';
    throw err;
  }
  const limit = (typeof maxOutBytes === 'number' && Number.isFinite(maxOutBytes) && maxOutBytes > 0)
    ? Math.min(Math.floor(maxOutBytes), MAX_DECOMPRESSED_FRAME_BYTES)
    : MAX_DECOMPRESSED_FRAME_BYTES;

  const magic = buf[0];
  const wireBytes = buf.length;
  /** @type {Buffer} */
  let bodyBuf;
  /** @type {'none' | 'br' | 'gzip'} */
  let codec = 'none';

  if (magic === FRAME_MAGIC_RAW) {
    bodyBuf = decodeCompressedPayload(FRAME_MAGIC_RAW, buf.subarray(1), limit);
    codec = 'none';
  } else if (magic === FRAME_MAGIC_BROTLI || magic === FRAME_MAGIC_GZIP) {
    codec = magic === FRAME_MAGIC_BROTLI ? 'br' : 'gzip';
    const declaredRawLen = buf.readUInt32BE(1);
    if (declaredRawLen > limit) {
      const err = new Error(`Trama comprimida declara ${declaredRawLen} bytes (> límite ${limit})`);
      /** @type {any} */ (err).code = 'FRAME_TOO_LARGE';
      throw err;
    }
    if (declaredRawLen < 5) {
      const err = new Error('Longitud declarada de trama comprimida inválida');
      /** @type {any} */ (err).code = 'BAD_FRAME';
      throw err;
    }
    const decompressed = decodeCompressedPayload(magic, buf.subarray(5), Math.min(limit, declaredRawLen));
    if (decompressed.length !== declaredRawLen) {
      const err = new Error(`Tamaño descomprimido (${decompressed.length}) no coincide con rawLen (${declaredRawLen})`);
      /** @type {any} */ (err).code = 'BAD_FRAME';
      throw err;
    }
    bodyBuf = decompressed;
  } else {
    const err = new Error(`Trama binaria de sincronización inválida (magic 0x${magic.toString(16)})`);
    /** @type {any} */ (err).code = 'BAD_FRAME';
    throw err;
  }

  if (bodyBuf.length < 4) {
    const err = new Error('Cabecera de trama binaria truncada');
    /** @type {any} */ (err).code = 'BAD_FRAME';
    throw err;
  }
  const metaLen = bodyBuf.readUInt32BE(0);
  if (metaLen > MAX_FRAME_META_BYTES) {
    const err = new Error(`Cabecera JSON de trama binaria excede el límite (${MAX_FRAME_META_BYTES} bytes)`);
    /** @type {any} */ (err).code = 'FRAME_TOO_LARGE';
    throw err;
  }
  const headerEnd = 4 + metaLen;
  if (headerEnd > bodyBuf.length) {
    const err = new Error('Cabecera de trama binaria truncada');
    /** @type {any} */ (err).code = 'BAD_FRAME';
    throw err;
  }

  let meta;
  try {
    meta = JSON.parse(bodyBuf.subarray(4, headerEnd).toString('utf8'));
  } catch (e) {
    const err = new Error('JSON de cabecera en trama binaria inválido');
    /** @type {any} */ (err).code = 'BAD_FRAME';
    throw err;
  }
  if (!meta || typeof meta !== 'object') {
    const err = new Error('Metadatos de trama binaria inválidos');
    /** @type {any} */ (err).code = 'BAD_FRAME';
    throw err;
  }

  let offset = headerEnd;
  const rawFiles = Array.isArray(meta.files) ? meta.files : [];
  const files = rawFiles.map((f) => {
    if (f.op === 'delete') {
      return {
        path: f.path,
        op: 'delete',
        ...(f.baseSha256 ? { baseSha256: String(f.baseSha256) } : {})
      };
    }
    const byteLen = Number(f.byteLength || 0);
    if (!Number.isInteger(byteLen) || byteLen < 0 || offset + byteLen > bodyBuf.length) {
      const err = new Error(`Longitud binaria inválida para ${f.path}`);
      /** @type {any} */ (err).code = 'BAD_FRAME';
      throw err;
    }
    const rawSlice = bodyBuf.subarray(offset, offset + byteLen);
    // Desacoplar del slab ArrayBuffer del frame WS si el slab padre supera 2x el fichero
    const contentBuf = (byteLen > 0 && rawSlice.buffer.byteLength > byteLen * 2)
      ? Buffer.from(rawSlice)
      : rawSlice;
    offset += byteLen;
    return {
      path: f.path,
      op: 'upsert',
      buffer: contentBuf,
      sha256: f.sha256,
      ...(f.baseSha256 ? { baseSha256: String(f.baseSha256) } : {})
    };
  });

  const rawBytes = magic === FRAME_MAGIC_RAW ? wireBytes : (1 + bodyBuf.length);
  const savedBytes = Math.max(0, rawBytes - wireBytes);

  return {
    ...meta,
    type: 'frame',
    files,
    _wireStats: {
      codec,
      wireBytes,
      rawBytes,
      savedBytes,
      compressed: codec !== 'none'
    }
  };
}

/**
 * Compacta en memoria un snapshot de revisión de fichero (gzip nivel 1 si >4 KiB).
 * @param {Buffer | null} buf
 * @returns {{ data: Buffer | null, encoding: 'raw' | 'gzip' | 'none', storedBytes: number, restorable: boolean }}
 */
function packSnapshot(buf) {
  if (buf === null) {
    return { data: null, encoding: 'none', storedBytes: 0, restorable: true };
  }
  if (buf.length > MAX_FILE_SNAPSHOT_BYTES) {
    return { data: null, encoding: 'none', storedBytes: 0, restorable: false };
  }
  if (buf.length > SNAPSHOT_COMPRESS_THRESHOLD) {
    try {
      const gz = getZlib().gzipSync(buf, { level: 1 });
      if (gz.length < buf.length) {
        return { data: gz, encoding: 'gzip', storedBytes: gz.length, restorable: true };
      }
    } catch (e) {}
  }
  const safeBuf = (buf.length > 0 && buf.buffer.byteLength > buf.length * 2) ? Buffer.from(buf) : buf;
  return { data: safeBuf, encoding: 'raw', storedBytes: safeBuf.length, restorable: true };
}

/**
 * Restaura los bytes exactos de un snapshot en memoria.
 * @param {{ data: Buffer | null, encoding: 'raw' | 'gzip' | 'none', restorable: boolean } | null | undefined} snap
 * @returns {Buffer | null}
 */
function unpackSnapshot(snap) {
  if (!snap || !snap.restorable) {
    const err = new Error('El snapshot de esta revisión excedía el límite en memoria y no es restaurable');
    /** @type {any} */ (err).code = 'SNAPSHOT_NOT_RESTORABLE';
    throw err;
  }
  if (snap.data === null || snap.encoding === 'none') return null;
  if (snap.encoding === 'gzip') {
    return getZlib().gunzipSync(snap.data, { maxOutputLength: MAX_FILE_SNAPSHOT_BYTES + 1024 });
  }
  return snap.data;
}

/**
 * Diff unificado por líneas sin dependencias externas usando LCS para ficheros <= 400 líneas
 * (con recorte previo de prefijo/sufijo común y fallback indexado O(N) para ficheros mayores).
 *
 * @param {string[]} beforeLines
 * @param {string[]} afterLines
 * @returns {string}
 */
function computeUnifiedLineDiff(beforeLines, afterLines) {
  const aLen = beforeLines.length;
  const bLen = afterLines.length;
  if (aLen === 0 && bLen === 0) return '';

  // Recorte O(N) de prefijo y sufijo idénticos
  let prefix = 0;
  const minLen = Math.min(aLen, bLen);
  while (prefix < minLen && beforeLines[prefix] === afterLines[prefix]) prefix++;

  let suffix = 0;
  while (
    suffix < (minLen - prefix) &&
    beforeLines[aLen - 1 - suffix] === afterLines[bLen - 1 - suffix]
  ) {
    suffix++;
  }

  const midA = beforeLines.slice(prefix, aLen - suffix);
  const midB = afterLines.slice(prefix, bLen - suffix);

  if (midA.length === 0 && midB.length === 0) {
    return beforeLines.slice(0, 20).map((l) => `  ${l}`).join('\n');
  }

  // Fallback rápido O(N) si la ventana cambiada supera 400 líneas
  if (aLen > MAX_LCS_DIFF_LINES || bLen > MAX_LCS_DIFF_LINES || midA.length > MAX_LCS_DIFF_LINES || midB.length > MAX_LCS_DIFF_LINES) {
    /** @type {string[]} */
    const out = [];
    const ctxStart = Math.max(0, prefix - 3);
    for (let i = ctxStart; i < prefix; i++) out.push(`  ${beforeLines[i]}`);
    const maxMid = Math.min(200, Math.max(midA.length, midB.length));
    for (let i = 0; i < maxMid; i++) {
      const b = midA[i];
      const a = midB[i];
      if (b === a) {
        if (b !== undefined) out.push(`  ${b}`);
      } else {
        if (b !== undefined) out.push(`- ${b}`);
        if (a !== undefined) out.push(`+ ${a}`);
      }
    }
    const sufCtx = Math.min(3, suffix);
    for (let i = 0; i < sufCtx; i++) out.push(`  ${beforeLines[aLen - suffix + i]}`);
    return out.join('\n');
  }

  // LCS DP compacto con Uint16Array plano sobre la ventana central
  const m = midA.length;
  const n = midB.length;
  const cols = n + 1;
  const dp = new Uint16Array((m + 1) * cols);

  for (let i = m - 1; i >= 0; i--) {
    const rowOff = i * cols;
    const nextRowOff = (i + 1) * cols;
    const lineA = midA[i];
    for (let j = n - 1; j >= 0; j--) {
      if (lineA === midB[j]) {
        dp[rowOff + j] = dp[nextRowOff + j + 1] + 1;
      } else {
        const down = dp[nextRowOff + j];
        const right = dp[rowOff + j + 1];
        dp[rowOff + j] = down >= right ? down : right;
      }
    }
  }

  /** @type {Array<{ op: ' ' | '-' | '+', line: string, oldLine: number, newLine: number }>} */
  const ops = [];
  let i = 0;
  let j = 0;
  let oldLn = prefix + 1;
  let newLn = prefix + 1;
  while (i < m && j < n) {
    if (midA[i] === midB[j]) {
      ops.push({ op: ' ', line: midA[i], oldLine: oldLn++, newLine: newLn++ });
      i++;
      j++;
    } else if (dp[(i + 1) * cols + j] >= dp[i * cols + j + 1]) {
      ops.push({ op: '-', line: midA[i], oldLine: oldLn++, newLine: newLn });
      i++;
    } else {
      ops.push({ op: '+', line: midB[j], oldLine: oldLn, newLine: newLn++ });
      j++;
    }
  }
  while (i < m) ops.push({ op: '-', line: midA[i++], oldLine: oldLn++, newLine: newLn });
  while (j < n) ops.push({ op: '+', line: midB[j++], oldLine: oldLn, newLine: newLn++ });

  // Construir secuencia completa de líneas con contexto (3 líneas antes/después de cambios)
  /** @type {Array<{ op: ' ' | '-' | '+', line: string, oldLine: number, newLine: number }>} */
  const allOps = [];
  const leadStart = Math.max(0, prefix - 3);
  for (let k = leadStart; k < prefix; k++) {
    allOps.push({ op: ' ', line: beforeLines[k], oldLine: k + 1, newLine: k + 1 });
  }
  for (const op of ops) allOps.push(op);
  const trailCount = Math.min(3, suffix);
  for (let k = 0; k < trailCount; k++) {
    const oldIdx = aLen - suffix + k;
    const newIdx = bLen - suffix + k;
    allOps.push({ op: ' ', line: beforeLines[oldIdx], oldLine: oldIdx + 1, newLine: newIdx + 1 });
  }

  // Agrupar en hunks unificados con contexto de 3 líneas
  const CONTEXT = 3;
  /** @type {number[]} */
  const changeIndices = [];
  for (let idx = 0; idx < allOps.length; idx++) {
    if (allOps[idx].op !== ' ') changeIndices.push(idx);
  }
  if (changeIndices.length === 0) return '';

  /** @type {Array<[number, number]>} */
  const ranges = [];
  let rStart = Math.max(0, changeIndices[0] - CONTEXT);
  let rEnd = Math.min(allOps.length - 1, changeIndices[0] + CONTEXT);
  for (let c = 1; c < changeIndices.length; c++) {
    const nextStart = Math.max(0, changeIndices[c] - CONTEXT);
    const nextEnd = Math.min(allOps.length - 1, changeIndices[c] + CONTEXT);
    if (nextStart <= rEnd + 1) {
      rEnd = nextEnd;
    } else {
      ranges.push([rStart, rEnd]);
      rStart = nextStart;
      rEnd = nextEnd;
    }
  }
  ranges.push([rStart, rEnd]);

  /** @type {string[]} */
  const out = [];
  const MAX_OUT_LINES = 400;
  for (const [rs, re] of ranges) {
    if (out.length >= MAX_OUT_LINES) break;
    const first = allOps[rs];
    let oldCount = 0;
    let newCount = 0;
    for (let idx = rs; idx <= re; idx++) {
      if (allOps[idx].op !== '+') oldCount++;
      if (allOps[idx].op !== '-') newCount++;
    }
    out.push(`@@ -${first.oldLine},${oldCount} +${first.newLine},${newCount} @@`);
    for (let idx = rs; idx <= re && out.length < MAX_OUT_LINES; idx++) {
      const item = allOps[idx];
      out.push(`${item.op === ' ' ? '  ' : `${item.op} `}${item.line}`);
    }
  }
  return out.join('\n');
}

/** Ficheros cuya modificación exige reiniciar proceso/rebuild (Camino C). */
const PATH_C_PATTERNS = [
  /(^|\/)package\.json$/i,
  /(^|\/)package-lock\.json$/i,
  /(^|\/)pnpm-lock\.yaml$/i,
  /(^|\/)yarn\.lock$/i,
  /(^|\/)bun\.lockb?$/i,
  /(^|\/)dockerfile$/i,
  /(^|\/)docker-compose[^/]*\.ya?ml$/i,
  /(^|\/)requirements\.txt$/i,
  /(^|\/)pyproject\.toml$/i,
  /(^|\/)go\.(mod|sum)$/i,
  /(^|\/)\.env(\..+)?$/i,
  /(^|\/)(vite|next|nuxt|astro|webpack|tsconfig)\.config\.[^/]+$/i,
  /(^|\/)tsconfig(\.[^/]+)?\.json$/i
];

/**
 * @param {Buffer | string} content
 * @returns {string}
 */
function sha256(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * @param {number[]} values
 * @param {number} p
 * @returns {number | null}
 */
function percentile(values, p) {
  if (!values || values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return Number(sorted[Math.max(0, idx)].toFixed(2));
}

/**
 * Normaliza y valida una ruta relativa dentro de `baseDir`.
 * Lanza error con `code = 'PATH_TRAVERSAL_BLOCKED'` si intenta escapar
 * (incluyendo escapes por enlace simbólico en directorios ancestros o en el fichero hoja).
 *
 * @param {string} baseDir
 * @param {string} relPath
 * @param {{ realBase?: string | null, verifiedDirs?: Set<string> }} [ctx]
 * @returns {{ rel: string, abs: string, stat: import('fs').Stats | null }}
 */
function resolveSafeFilePath(baseDir, relPath, ctx = {}) {
  if (typeof relPath !== 'string' || !relPath.trim()) {
    const err = new Error('Ruta de fichero vacía');
    /** @type {any} */ (err).code = 'INVALID_PATH';
    throw err;
  }
  if (relPath.includes('\0')) {
    const err = new Error('Byte nulo detectado en la ruta');
    /** @type {any} */ (err).code = 'PATH_TRAVERSAL_BLOCKED';
    throw err;
  }
  const slashNorm = relPath.replace(/\\/g, '/').replace(/^\/+/, '');
  if (relPath.startsWith('/') || relPath.startsWith('\\') || /^[A-Za-z]:/.test(relPath)) {
    const err = new Error(`Ruta absoluta rechazada: ${relPath}`);
    /** @type {any} */ (err).code = 'PATH_TRAVERSAL_BLOCKED';
    throw err;
  }

  const segments = slashNorm.split('/').filter(Boolean);
  if (segments.length === 0) {
    const err = new Error(`Ruta inválida: ${relPath}`);
    /** @type {any} */ (err).code = 'INVALID_PATH';
    throw err;
  }
  for (const seg of segments) {
    if (seg === '..' || seg === '.') {
      const err = new Error(`Intento de path traversal bloqueado: ${relPath}`);
      /** @type {any} */ (err).code = 'PATH_TRAVERSAL_BLOCKED';
      throw err;
    }
  }
  if (segments[0] === '.git') {
    const err = new Error('No se permite sobrescribir metadatos de .git vía sincronización en vivo');
    /** @type {any} */ (err).code = 'PATH_TRAVERSAL_BLOCKED';
    throw err;
  }

  const cleanRel = segments.join('/');
  const resolvedBase = path.resolve(baseDir);
  const resolvedTarget = path.resolve(resolvedBase, cleanRel);
  const relativeBack = path.relative(resolvedBase, resolvedTarget);
  if (!relativeBack || relativeBack.startsWith('..') || path.isAbsolute(relativeBack)) {
    const err = new Error(`Ruta fuera del espacio del proyecto: ${relPath}`);
    /** @type {any} */ (err).code = 'PATH_TRAVERSAL_BLOCKED';
    throw err;
  }

  // Comprueba que ningún ancestro existente sea un symlink hacia fuera (cacheado por frame).
  const targetDir = path.dirname(resolvedTarget);
  const verifiedDirs = ctx.verifiedDirs;
  if (!verifiedDirs || !verifiedDirs.has(targetDir)) {
    const realBase = ctx.realBase !== undefined
      ? ctx.realBase
      : (fs.existsSync(resolvedBase) ? fs.realpathSync(resolvedBase) : null);
    if (realBase) {
      let checkDir = targetDir;
      while (checkDir.length >= resolvedBase.length) {
        if (fs.existsSync(checkDir)) {
          const realCheck = fs.realpathSync(checkDir);
          const relReal = path.relative(realBase, realCheck);
          if (relReal.startsWith('..') || path.isAbsolute(relReal)) {
            const err = new Error(`Escape por enlace simbólico bloqueado: ${relPath}`);
            /** @type {any} */ (err).code = 'PATH_TRAVERSAL_BLOCKED';
            throw err;
          }
          if (verifiedDirs) verifiedDirs.add(targetDir);
          break;
        }
        const parent = path.dirname(checkDir);
        if (parent === checkDir) break;
        checkDir = parent;
      }
    }
  }

  // Comprueba también el propio fichero hoja (impide leer o sobrescribir symlinks externos)
  // y devuelve su `lstat` para reutilizar `mtimeMs`/`size` sin syscalls extra.
  /** @type {import('fs').Stats | null} */
  let leafStat = null;
  try {
    const st = fs.lstatSync(resolvedTarget);
    if (st.isSymbolicLink()) {
      const err = new Error(`Enlace simbólico de destino bloqueado: ${relPath}`);
      /** @type {any} */ (err).code = 'PATH_TRAVERSAL_BLOCKED';
      throw err;
    }
    leafStat = st;
  } catch (e) {
    if (e && e.code !== 'ENOENT') throw e;
  }

  return { rel: cleanRel, abs: resolvedTarget, stat: leafStat };
}

/**
 * Clasifica un conjunto de rutas modificadas entre Camino B (hot-apply) y
 * Camino C (requiere reinicio/reconstrucción).
 *
 * @param {string[]} relPaths
 * @returns {{ path: 'path_b_hot' | 'path_c_restart', reason: string, triggerFiles: string[] }}
 */
function classifyChanges(relPaths) {
  const triggerFiles = relPaths.filter((p) => PATH_C_PATTERNS.some((re) => re.test(p)));
  if (triggerFiles.length > 0) {
    return {
      path: 'path_c_restart',
      reason: `Cambios de configuración o dependencias (${triggerFiles.slice(0, 3).join(', ')}): requiere reinicio limpio`,
      triggerFiles
    };
  }
  return {
    path: 'path_b_hot',
    reason: 'Cambios en código o activos hoja: aplicados en vivo sin reiniciar',
    triggerFiles: []
  };
}

let tempSeq = 0;

/**
 * Escritura atómica en disco (POSIX y Windows NTFS): escribe primero en un temporal
 * en el mismo directorio, cierra el descriptor y realiza `renameSync` con reintentos
 * cortos ante bloqueos transitorios del AV en Windows. Jamás trunca el archivo destino
 * in-place para evitar lecturas corruptas a mitad de escritura.
 *
 * @param {string} absPath
 * @param {Buffer} buffer
 * @param {Set<string> | null} [ensuredDirs]
 * @returns {{ mtimeMs: number, size: number } | null}
 */
function writeFileAtomic(absPath, buffer, ensuredDirs = null) {
  const dir = path.dirname(absPath);
  if (!ensuredDirs || !ensuredDirs.has(dir)) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    if (ensuredDirs) ensuredDirs.add(dir);
  }
  const tempPath = `${absPath}.culkibo-sync-${process.pid}-${++tempSeq}.tmp`;
  /** @type {{ mtimeMs: number, size: number } | null} */
  let tempStat = null;
  let fd = -1;
  try {
    fd = fs.openSync(tempPath, 'w');
    if (buffer.length > 0) fs.writeSync(fd, buffer, 0, buffer.length, 0);
    const st = fs.fstatSync(fd);
    tempStat = { mtimeMs: st.mtimeMs, size: st.size };
  } catch (err) {
    if (fd !== -1) {
      try { fs.closeSync(fd); } catch (e) {}
      fd = -1;
    }
    try { fs.unlinkSync(tempPath); } catch (e) {}
    throw err;
  } finally {
    if (fd !== -1) {
      try { fs.closeSync(fd); } catch (e) {}
    }
  }
  let renamed = false;
  const maxAttempts = process.platform === 'win32' ? 5 : 3;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      fs.renameSync(tempPath, absPath);
      renamed = true;
      break;
    } catch (err) {
      if (attempt < maxAttempts && err && (err.code === 'EPERM' || err.code === 'EBUSY' || err.code === 'EACCES')) {
        try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 15 * attempt); } catch (e) {}
        continue;
      }
      break;
    }
  }
  if (renamed && tempStat) {
    return tempStat;
  }
  if (!renamed) {
    try {
      const st = fs.lstatSync(absPath);
      if (st.isSymbolicLink()) {
        try { fs.unlinkSync(tempPath); } catch (e) {}
        throw new Error(`Rechazado escribir sobre enlace simbólico: ${absPath}`);
      }
    } catch (e) {
      if (e && e.code !== 'ENOENT') throw e;
    }
    fs.copyFileSync(tempPath, absPath);
    try { fs.unlinkSync(tempPath); } catch (e) {}
  }
  try {
    const st = fs.statSync(absPath);
    return { mtimeMs: st.mtimeMs, size: st.size };
  } catch (e) {
    return null;
  }
}

/** Calcula SHA-256 de un fichero grande en streaming síncrono con búfer fijo de 256 KiB (0 picos RAM). */
function sha256FileSync(absPath) {
  const hasher = crypto.createHash('sha256');
  const buf = Buffer.allocUnsafe(256 * 1024);
  const fd = fs.openSync(absPath, 'r');
  try {
    let bytesRead = 0;
    while ((bytesRead = fs.readSync(fd, buf, 0, buf.length, null)) > 0) {
      hasher.update(bytesRead === buf.length ? buf : buf.subarray(0, bytesRead));
    }
  } finally {
    fs.closeSync(fd);
  }
  return hasher.digest('hex');
}

/** Caché por (absPath -> { mtimeMs, size, hash }) para árboles Merkle ultrarrápidos. */
/** @type {Map<string, { mtimeMs: number, size: number, hash: string }>} */
const merkleFileCache = new Map();
const MAX_MERKLE_CACHE_ENTRIES = 25000;
const MAX_MERKLE_FILES = 20000;
const MAX_MERKLE_DEPTH = 20;

/**
 * Calcula el árbol determinista de hashes (Merkle plano ordenado por ruta) de
 * un directorio. Sirve para demostrar cero divergencia silenciosa.
 *
 * @param {string} baseDir
 * @returns {{ rootDigest: string, fileCount: number, totalBytes: number, files: Record<string, string> }}
 */
function computeMerkleTree(baseDir) {
  /** @type {Record<string, string>} */
  const files = Object.create(null);
  let totalBytes = 0;
  let scannedFiles = 0;

  if (!fs.existsSync(baseDir)) {
    return { rootDigest: sha256(''), fileCount: 0, totalBytes: 0, files };
  }

  /** @param {string} dir @param {string} prefix @param {number} depth */
  const walk = (dir, prefix, depth) => {
    if (depth > MAX_MERKLE_DEPTH || scannedFiles >= MAX_MERKLE_FILES) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      return;
    }

    for (const entry of entries) {
      if (scannedFiles >= MAX_MERKLE_FILES) break;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(entry.name)) continue;
        walk(path.join(dir, entry.name), prefix ? `${prefix}/${entry.name}` : entry.name, depth + 1);
      } else if (entry.isFile()) {
        if (IGNORED_FILES.has(entry.name) || entry.name.includes('.culkibo-sync-')) continue;
        const abs = path.join(dir, entry.name);
        const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
        try {
          const st = fs.statSync(abs);
          if (st.size > MAX_CHUNKED_FILE_BYTES) continue;
          scannedFiles++;
          totalBytes += st.size;
          const cached = merkleFileCache.get(abs);
          if (cached && cached.mtimeMs === st.mtimeMs && cached.size === st.size) {
            // Refresca posición LRU en O(1)
            merkleFileCache.delete(abs);
            merkleFileCache.set(abs, cached);
            files[rel] = cached.hash;
          } else {
            const h = st.size > MAX_FILE_BYTES ? sha256FileSync(abs) : sha256(fs.readFileSync(abs));
            files[rel] = h;
            if (merkleFileCache.size >= MAX_MERKLE_CACHE_ENTRIES) {
              const oldest = merkleFileCache.keys().next().value;
              if (oldest !== undefined) merkleFileCache.delete(oldest);
            }
            merkleFileCache.set(abs, { mtimeMs: st.mtimeMs, size: st.size, hash: h });
          }
        } catch (e) {}
      }
    }
  };

  walk(baseDir, '', 0);

  const sortedKeys = Object.keys(files).sort();
  const rootHasher = crypto.createHash('sha256');
  for (const k of sortedKeys) {
    rootHasher.update(`${k}\0${files[k]}\n`);
  }

  return {
    rootDigest: rootHasher.digest('hex'),
    fileCount: sortedKeys.length,
    totalBytes,
    files
  };
}

/**
 * Compara dos mapas de archivos `{ relPath: sha256 }` y devuelve la divergencia
 * exacta (protegido contra colisiones con Object.prototype).
 *
 * @param {Record<string, string>} clientFiles
 * @param {Record<string, string>} serverFiles
 */
function diffMerkleTrees(clientFiles, serverFiles) {
  /** @type {string[]} */
  const missingOnServer = [];
  /** @type {string[]} */
  const staleOnServer = [];
  /** @type {string[]} */
  const extraOnServer = [];

  const cMap = clientFiles || {};
  const sMap = serverFiles || {};

  for (const [rel, hash] of Object.entries(cMap)) {
    if (!Object.prototype.hasOwnProperty.call(sMap, rel)) {
      missingOnServer.push(rel);
    } else if (sMap[rel] !== hash) {
      staleOnServer.push(rel);
    }
  }
  for (const rel of Object.keys(sMap)) {
    if (!Object.prototype.hasOwnProperty.call(cMap, rel)) {
      extraOnServer.push(rel);
    }
  }

  return {
    inSync: missingOnServer.length === 0 && staleOnServer.length === 0 && extraOnServer.length === 0,
    missingOnServer,
    staleOnServer,
    extraOnServer,
    divergentCount: missingOnServer.length + staleOnServer.length + extraOnServer.length
  };
}

/** Calcula p50/p95/p99 en un solo ordenamiento. */
function computePercentiles(samples) {
  if (!samples || samples.length === 0) {
    return { samples: 0, p50: null, p95: null, p99: null };
  }
  const sorted = [...samples].sort((a, b) => a - b);
  const pick = (p) => {
    const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
    return Number(sorted[Math.max(0, idx)].toFixed(2));
  };
  return {
    samples: sorted.length,
    p50: pick(50),
    p95: pick(95),
    p99: pick(99)
  };
}

const MAX_PATCH_HISTORY_BYTES = 32 * 1024 * 1024; // 32 MiB por sesión
const MAX_RECENT_FRAMES = 25;
const MAX_SESSION_CACHE_BYTES = 16 * 1024 * 1024;
const MAX_SESSION_CACHE_ENTRIES = 500;
const ROOT_BASE_DIR = process.env.CULKIBO_DATA_DIR
  ? path.resolve(process.env.CULKIBO_DATA_DIR)
  : path.resolve(__dirname, '..', '..');

/**
 * @param {any} session
 * @param {string} abs
 * @param {Buffer} buf
 * @param {{ mtimeMs: number, size: number } | null} postStat
 */
function putSessionFileCache(session, abs, buf, postStat) {
  const cache = session && session.fileCache;
  if (!cache) return;
  const prevCached = cache.get(abs);
  if (prevCached) {
    session.fileCacheBytes = Math.max(0, (session.fileCacheBytes || 0) - prevCached.buf.length);
  }
  if (!postStat || buf.length > 512 * 1024) {
    cache.delete(abs);
    return;
  }
  while (
    cache.size > 0 &&
    (cache.size >= MAX_SESSION_CACHE_ENTRIES || (session.fileCacheBytes || 0) + buf.length > MAX_SESSION_CACHE_BYTES)
  ) {
    const oldestKey = cache.keys().next().value;
    if (oldestKey === undefined) break;
    const oldestVal = cache.get(oldestKey);
    cache.delete(oldestKey);
    if (oldestVal) {
      session.fileCacheBytes = Math.max(0, (session.fileCacheBytes || 0) - oldestVal.buf.length);
    }
  }
  const safeBuf = (buf.length > 0 && buf.buffer.byteLength > buf.length * 2) ? Buffer.from(buf) : buf;
  cache.delete(abs);
  cache.set(abs, { buf: safeBuf, mtimeMs: postStat.mtimeMs, size: postStat.size });
  session.fileCacheBytes = (session.fileCacheBytes || 0) + safeBuf.length;
}

/**
 * @param {any} session
 * @param {string} abs
 */
function deleteSessionFileCache(session, abs) {
  const cache = session && session.fileCache;
  if (!cache) return;
  const prevCached = cache.get(abs);
  if (prevCached) {
    session.fileCacheBytes = Math.max(0, (session.fileCacheBytes || 0) - prevCached.buf.length);
    cache.delete(abs);
  }
}

/**
 * @param {string} abs
 * @param {{ mtimeMs: number, size: number } | null} postStat
 * @param {string | null} hash
 */
function putMerkleCache(abs, postStat, hash) {
  if (!postStat || !hash) {
    merkleFileCache.delete(abs);
    return;
  }
  if (merkleFileCache.size >= MAX_MERKLE_CACHE_ENTRIES) {
    const oldestMerkle = merkleFileCache.keys().next().value;
    if (oldestMerkle !== undefined) merkleFileCache.delete(oldestMerkle);
  }
  merkleFileCache.delete(abs);
  merkleFileCache.set(abs, { mtimeMs: postStat.mtimeMs, size: postStat.size, hash });
}

/**
 * Registra una revisión en el historial time-travel por fichero de la sesión (acotado en RAM).
 * @param {any} session
 * @param {string} rel
 * @param {{
 *   seq: number,
 *   appliedAt: string,
 *   action: 'created' | 'modified' | 'deleted' | 'rolled_back',
 *   clientId: string | null,
 *   clientName: string | null,
 *   prevExisted: boolean,
 *   prevBuffer: Buffer | null,
 *   prevHash: string | null,
 *   existed: boolean,
 *   newBuffer: Buffer | null,
 *   newHash: string | null,
 *   restoredFromSeq?: number
 * }} info
 */
function recordFileRevision(session, rel, info) {
  /** @type {Map<string, any[]>} */
  const historyMap = session.fileHistory;
  let list = historyMap.get(rel);
  if (!list) {
    list = [];
    const baseSnap = info.prevExisted ? packSnapshot(info.prevBuffer) : { data: null, encoding: 'none', storedBytes: 0, restorable: true };
    const baseRev = {
      seq: 0,
      appliedAt: info.appliedAt,
      action: 'initial',
      clientId: null,
      clientName: 'baseline',
      existed: Boolean(info.prevExisted),
      byteLength: info.prevExisted && info.prevBuffer ? info.prevBuffer.length : 0,
      sha256: info.prevExisted ? (info.prevHash || (info.prevBuffer ? sha256(info.prevBuffer) : null)) : null,
      snapshot: baseSnap
    };
    list.push(baseRev);
    session.fileHistoryBytes = (session.fileHistoryBytes || 0) + baseSnap.storedBytes;
  }

  const newSnap = info.existed ? packSnapshot(info.newBuffer) : { data: null, encoding: 'none', storedBytes: 0, restorable: true };
  /** @type {any} */
  const rev = {
    seq: info.seq,
    appliedAt: info.appliedAt,
    action: info.action,
    clientId: info.clientId || null,
    clientName: info.clientName || null,
    existed: Boolean(info.existed),
    byteLength: info.existed && info.newBuffer ? info.newBuffer.length : 0,
    sha256: info.existed ? (info.newHash || (info.newBuffer ? sha256(info.newBuffer) : null)) : null,
    snapshot: newSnap
  };
  if (info.restoredFromSeq !== undefined) {
    rev.restoredFromSeq = info.restoredFromSeq;
  }

  list.unshift(rev);
  session.fileHistoryBytes = (session.fileHistoryBytes || 0) + newSnap.storedBytes;

  while (list.length > MAX_PER_FILE_HISTORY) {
    const dropped = list.pop();
    if (dropped && dropped.snapshot) {
      session.fileHistoryBytes = Math.max(0, (session.fileHistoryBytes || 0) - (dropped.snapshot.storedBytes || 0));
    }
  }

  // Refrescar LRU en O(1)
  historyMap.delete(rel);
  historyMap.set(rel, list);

  while (historyMap.size > MAX_TRACKED_FILES_HISTORY) {
    const oldestRel = historyMap.keys().next().value;
    if (oldestRel === undefined || oldestRel === rel) break;
    const evictedList = historyMap.get(oldestRel) || [];
    for (const item of evictedList) {
      if (item && item.snapshot) {
        session.fileHistoryBytes = Math.max(0, (session.fileHistoryBytes || 0) - (item.snapshot.storedBytes || 0));
      }
    }
    historyMap.delete(oldestRel);
  }

  while ((session.fileHistoryBytes || 0) > MAX_FILE_HISTORY_BYTES && historyMap.size > 0) {
    const oldestRel = historyMap.keys().next().value;
    if (oldestRel === undefined) break;
    if (oldestRel === rel) {
      if (list.length <= 1) break;
      const dropped = list.pop();
      if (dropped && dropped.snapshot) {
        session.fileHistoryBytes = Math.max(0, (session.fileHistoryBytes || 0) - (dropped.snapshot.storedBytes || 0));
      }
    } else {
      const evictedList = historyMap.get(oldestRel) || [];
      for (const item of evictedList) {
        if (item && item.snapshot) {
          session.fileHistoryBytes = Math.max(0, (session.fileHistoryBytes || 0) - (item.snapshot.storedBytes || 0));
        }
      }
      historyMap.delete(oldestRel);
    }
  }
}

/**
 * Registra el último toque de cliente en un fichero (LRU acotado).
 * @param {any} session
 * @param {string} rel
 * @param {{ clientId: string | null, clientName: string | null, seq: number, atMs: number, at: string, sha256: string | null, op: 'upsert' | 'delete' | 'rollback' }} touch
 */
function recordFileTouch(session, rel, touch) {
  /** @type {Map<string, any>} */
  const map = session.fileTouchMap;
  if (!map) return;
  if (map.size >= MAX_FILE_TOUCH_ENTRIES && !map.has(rel)) {
    const oldest = map.keys().next().value;
    if (oldest !== undefined) map.delete(oldest);
  }
  map.delete(rel);
  map.set(rel, touch);
}

class LiveSyncEngine extends EventEmitter {
  /**
   * @param {number} codecByte
   * @param {Buffer} buf
   * @param {number} [maxOutBytes]
   */
  static decodeCompressedPayload(codecByte, buf, maxOutBytes = MAX_DECOMPRESSED_FRAME_BYTES) {
    return decodeCompressedPayload(codecByte, buf, maxOutBytes);
  }

  /**
   * @param {Buffer} buf
   * @param {number} [maxOutBytes]
   */
  static decodeBinarySyncFrame(buf, maxOutBytes = MAX_DECOMPRESSED_FRAME_BYTES) {
    return decodeBinarySyncFrame(buf, maxOutBytes);
  }

  constructor() {
    super();
    /** @type {Map<string, any>} */
    this.sessions = new Map();
    /** @type {Map<string, string>} */
    this.targetOverrides = new Map();
  }

  /**
   * Directorio objetivo en disco para un proyecto.
   *
   * @param {string} projectId
   * @param {string | null} [explicitDir]
   * @returns {string}
   */
  resolveTargetDir(projectId, explicitDir = null) {
    if (explicitDir) return path.resolve(explicitDir);
    if (this.targetOverrides.has(projectId)) {
      return /** @type {string} */ (this.targetOverrides.get(projectId));
    }
    const cleanId = String(projectId || '').trim();
    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(cleanId)) {
      const err = new Error(`Identificador de proyecto inválido para Live Sync: ${projectId}`);
      /** @type {any} */ (err).code = 'INVALID_PROJECT_ID';
      throw err;
    }
    // Respetar `project.localPath` si está configurado en ProjectManager y existe como directorio real
    try {
      const pm = require('./projectManager');
      const project = pm && typeof pm.getById === 'function' ? pm.getById(cleanId) : null;
      const lp = typeof project?.localPath === 'string' ? project.localPath.trim() : '';
      if (lp && !lp.includes('\0')) {
        const resolved = path.resolve(lp);
        if (resolved !== path.parse(resolved).root && fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) {
          return resolved;
        }
      }
    } catch (e) {}
    return path.join(ROOT_BASE_DIR, 'projects', cleanId);
  }

  /** Registra un directorio objetivo explícito (usado por proyectos locales y tests). */
  setTargetDir(projectId, dir) {
    this.targetOverrides.set(projectId, path.resolve(dir));
  }

  /** @param {string} projectId */
  getOrCreateSession(projectId) {
    let s = this.sessions.get(projectId);
    if (!s) {
      s = {
        projectId,
        lastSeq: 0,
        connectedClients: 0,
        clients: /** @type {Map<string, { id: string, clientName: string, sourceDir: string | null, pid: number | null, connectedAt: string, lastFrameAt: string | null, framesSent: number, lastClientSeq: number }>} */ (new Map()),
        clientSeqMap: /** @type {Map<string, number>} */ (new Map()),
        framesApplied: 0,
        filesWritten: 0,
        filesDeleted: 0,
        dedupSkipped: 0,
        bytesSynced: 0,
        rollbacksCount: 0,
        driftDetected: false,
        lastPath: null,
        lastReason: null,
        lastAppliedAt: null,
        lastApplyMs: null,
        latencySamples: /** @type {number[]} */ ([]),
        patchHistory: /** @type {any[]} */ ([]),
        patchHistoryBytes: 0,
        recentFrames: /** @type {any[]} */ ([]),
        fileCache: /** @type {Map<string, { buf: Buffer, mtimeMs: number, size: number }>} */ (new Map()),
        fileCacheBytes: 0,
        fileHistory: /** @type {Map<string, any[]>} */ (new Map()),
        fileHistoryBytes: 0,
        fileTouchMap: /** @type {Map<string, any>} */ (new Map()),
        recentConflicts: /** @type {any[]} */ ([]),
        conflictsCount: 0,
        wireStats: {
          rawBytes: 0,
          wireBytes: 0,
          savedBytes: 0,
          savedPct: 0,
          compressedFrames: 0,
          rawFrames: 0,
          lastCodec: /** @type {string | null} */ (null),
          lastSavedPct: 0
        },
        lastActiveMs: Date.now(),
        cachedRealBaseKey: /** @type {string | null} */ (null),
        cachedRealBase: /** @type {string | null} */ (null),
        verifiedDirs: /** @type {Set<string>} */ (new Set()),
        chunkUploads: /** @type {Map<string, any>} */ (new Map())
      };
      this.sessions.set(projectId, s);
    }
    s.lastActiveMs = Date.now();
    return s;
  }

  /** Limpia temporales de cargas troceadas caducadas o huérfanas. */
  _cleanupChunkUploads(session, onlyExpired = true) {
    if (!session || !session.chunkUploads || session.chunkUploads.size === 0) return;
    const now = Date.now();
    for (const [uid, up] of Array.from(session.chunkUploads.entries())) {
      if (onlyExpired && (now - up.updatedAtMs) < CHUNK_UPLOAD_TTL_MS) continue;
      session.chunkUploads.delete(uid);
      try { if (up.tempPath && fs.existsSync(up.tempPath)) fs.unlinkSync(up.tempPath); } catch (e) {}
    }
  }

  /** Libera buffers en RAM y elimina sesiones abandonadas desconectadas tras `maxIdleMs`. */
  evictIdleSessions(maxIdleMs = 15 * 60 * 1000) {
    const now = Date.now();
    let evicted = 0;
    for (const [pid, s] of Array.from(this.sessions.entries())) {
      if (s.connectedClients > 0) continue;
      const idleFor = now - (s.lastActiveMs || 0);
      if (idleFor < maxIdleMs) continue;
      if (s.fileCache && s.fileCache.size > 0) {
        s.fileCache.clear();
        s.fileCacheBytes = 0;
        evicted++;
      }
      if (s.patchHistory && s.patchHistory.length > 0) {
        s.patchHistory = [];
        s.patchHistoryBytes = 0;
      }
      if (s.fileHistory && s.fileHistory.size > 0) {
        s.fileHistory.clear();
        s.fileHistoryBytes = 0;
      }
      if (s.fileTouchMap && s.fileTouchMap.size > 0) {
        s.fileTouchMap.clear();
      }
      if (s.clientSeqMap && s.clientSeqMap.size > 0) {
        s.clientSeqMap.clear();
      }
      if (s.verifiedDirs) s.verifiedDirs.clear();
      this._cleanupChunkUploads(s, false);
      if (idleFor >= maxIdleMs * 4) {
        this.sessions.delete(pid);
        evicted++;
      }
    }
    return evicted;
  }

  /** @param {string} projectId @param {{ id?: string, clientName?: string | null, sourceDir?: string | null, pid?: number | null }} [meta] */
  registerClient(projectId, meta = {}) {
    const s = this.getOrCreateSession(projectId);
    s.connectedClients++;
    if (meta && meta.id) {
      s.clients.set(meta.id, {
        id: meta.id,
        clientName: String(meta.clientName || 'cli').slice(0, 80),
        sourceDir: meta.sourceDir ? String(meta.sourceDir).slice(0, 300) : null,
        pid: typeof meta.pid === 'number' ? meta.pid : null,
        connectedAt: new Date().toISOString(),
        lastFrameAt: null,
        framesSent: 0,
        lastClientSeq: 0
      });
    }
    this.emit('sync_client', { projectId, connectedClients: s.connectedClients, clients: Array.from(s.clients.values()) });
    return s;
  }

  /** @param {string} projectId @param {string | null} [clientId] */
  unregisterClient(projectId, clientId = null) {
    const s = this.sessions.get(projectId);
    if (!s) return;
    if (clientId && s.clients) s.clients.delete(clientId);
    if (clientId && s.clientSeqMap) s.clientSeqMap.delete(clientId);
    s.connectedClients = Math.max(0, s.connectedClients - 1);
    this.emit('sync_client', { projectId, connectedClients: s.connectedClients, clients: Array.from((s.clients || new Map()).values()) });
  }

  /** Emite los eventos `sync_applied` y `sync_conflict` (permite diferirlos tras `frame_ack` en /ws/sync). */
  emitApplied(result) {
    this.emit('sync_applied', result);
    if (result && Array.isArray(result.conflicts) && result.conflicts.length > 0) {
      for (const conflict of result.conflicts) {
        this.emit('sync_conflict', conflict);
      }
    }
  }

  /**
   * Aplica un Commit Frame atómico sobre el directorio vivo del proyecto.
   *
   * @param {string} projectId
   * @param {{
   *   seq?: number,
   *   clientId?: string | null,
   *   clientName?: string | null,
   *   _wireStats?: { codec?: string, wireBytes?: number, rawBytes?: number, savedBytes?: number, compressed?: boolean },
   *   files?: Array<{ path: string, op?: 'upsert' | 'delete', content?: string, buffer?: Buffer, encoding?: 'utf8' | 'base64', sha256?: string, baseSha256?: string }>,
   *   clientSentAtMs?: number
   * }} frame
   * @param {{
   *   targetDir?: string,
   *   deferEmit?: boolean,
   *   clientId?: string | null,
   *   clientName?: string | null,
   *   conflictWindowMs?: number,
   *   conflictPolicy?: 'warn' | 'reject',
   *   wireStats?: { codec?: string, wireBytes?: number, rawBytes?: number, savedBytes?: number, compressed?: boolean } | null
   * }} [options]
   */
  applyCommitFrame(projectId, frame, options = {}) {
    const startedNs = process.hrtime.bigint();
    const session = this.getOrCreateSession(projectId);
    const baseDir = this.resolveTargetDir(projectId, options.targetDir || null);

    if (!frame || !Array.isArray(frame.files) || frame.files.length === 0) {
      throw new Error('El commit frame debe incluir al menos un fichero en `files`');
    }
    if (frame.files.length > MAX_FILES_PER_FRAME) {
      throw new Error(`El commit frame supera el máximo permitido (${MAX_FILES_PER_FRAME} ficheros)`);
    }

    const incomingClientId = options.clientId || frame.clientId || null;
    const registeredClient = incomingClientId && session.clients ? session.clients.get(incomingClientId) : null;
    const incomingClientName = options.clientName || frame.clientName || (registeredClient && registeredClient.clientName) || (incomingClientId ? String(incomingClientId) : null);
    const conflictWindowMs = typeof options.conflictWindowMs === 'number' && Number.isFinite(options.conflictWindowMs) && options.conflictWindowMs >= 0
      ? options.conflictWindowMs
      : DEFAULT_CONFLICT_WINDOW_MS;
    const conflictPolicy = options.conflictPolicy === 'reject' ? 'reject' : 'warn';

    // Reutilizar realBase y verifiedDirs en la sesión para el mismo baseDir (evita realpathSync en cada frame)
    const resolvedBase = path.resolve(baseDir);
    if (session.cachedRealBaseKey !== resolvedBase) {
      session.cachedRealBaseKey = resolvedBase;
      try { session.cachedRealBase = fs.realpathSync(baseDir); } catch (e) { session.cachedRealBase = null; }
      session.verifiedDirs = new Set();
      if (session.cachedRealBase) session.verifiedDirs.add(resolvedBase);
    } else if (!session.cachedRealBase && fs.existsSync(baseDir)) {
      try {
        session.cachedRealBase = fs.realpathSync(baseDir);
        session.verifiedDirs.add(resolvedBase);
      } catch (e) {}
    }
    if (session.verifiedDirs.size > 500) {
      session.verifiedDirs.clear();
      if (session.cachedRealBase) session.verifiedDirs.add(resolvedBase);
    }
    const realBase = session.cachedRealBase;
    const pathCtx = { realBase, verifiedDirs: session.verifiedDirs };

    /** @type {Map<string, { rel: string, abs: string, op: 'upsert' | 'delete', buffer: Buffer | null, hash: string | null, baseSha256: string | null, stat: import('fs').Stats | null }>} */
    const preparedByRel = new Map();
    for (const item of frame.files) {
      const { rel, abs, stat } = resolveSafeFilePath(baseDir, item.path, pathCtx);
      const op = item.op === 'delete' ? 'delete' : 'upsert';
      const baseSha256 = typeof item.baseSha256 === 'string' && item.baseSha256.trim()
        ? item.baseSha256.trim()
        : null;
      if (op === 'upsert') {
        const buffer = Buffer.isBuffer(item.buffer)
          ? item.buffer
          : Buffer.from(String(item.content ?? ''), item.encoding === 'base64' ? 'base64' : 'utf8');
        if (buffer.length > MAX_FILE_BYTES) {
          throw new Error(`El fichero ${rel} supera el límite de ${MAX_FILE_BYTES} bytes`);
        }
        /** @type {string | null} */
        let verifiedHash = null;
        if (item.sha256) {
          const computedHash = sha256(buffer);
          if (item.sha256 !== computedHash) {
            throw new Error(`Checksum SHA-256 inválido para ${rel}`);
          }
          verifiedHash = computedHash;
        }
        preparedByRel.set(rel, { rel, abs, op, buffer, hash: verifiedHash, baseSha256, stat });
      } else {
        preparedByRel.set(rel, { rel, abs, op, buffer: null, hash: null, baseSha256, stat });
      }
    }
    // Deduplicación last-write-wins y ordenación segura para renombres sólo de mayúsculas/minúsculas
    // (en NTFS/APFS un delete `App.tsx` DEBE ejecutarse ANTES del upsert `app.tsx` para no borrar el nuevo fichero).
    const prepared = Array.from(preparedByRel.values());
    const upsertLower = new Set(prepared.filter((p) => p.op === 'upsert').map((p) => p.rel.toLowerCase()));
    const hasCaseCollision = prepared.some((p) => p.op === 'delete' && upsertLower.has(p.rel.toLowerCase()));
    if (hasCaseCollision) {
      const deleteLower = new Set(prepared.filter((p) => p.op === 'delete').map((p) => p.rel.toLowerCase()));
      prepared.sort((a, b) => {
        if (a.op === b.op) return 0;
        return a.op === 'delete' ? -1 : 1;
      });
      // En sistemas insensibles a mayúsculas (NTFS/APFS), invalidar el `stat` previo del upsert
      // tras borrar la capitalización anterior para garantizar que el fichero se recree con el nuevo nombre.
      for (const p of prepared) {
        if (p.op === 'upsert' && deleteLower.has(p.rel.toLowerCase())) {
          p.stat = null;
        }
      }
    }

    const prevLastSeq = session.lastSeq;
    let reconcileRequired = false;
    const hasExplicitSeq = typeof frame.seq === 'number' && Number.isInteger(frame.seq) && frame.seq > 0;
    const seq = hasExplicitSeq ? /** @type {number} */ (frame.seq) : session.lastSeq + 1;

    // Detección de huecos compatible: por clientId cuando hay múltiples clientes activos; global `session.lastSeq` en modo individual/anónimo
    const multiClientMode = Boolean(
      incomingClientId &&
      (session.connectedClients > 1 || (session.clientSeqMap && (session.clientSeqMap.size > 1 || (session.clientSeqMap.size === 1 && !session.clientSeqMap.has(incomingClientId)))))
    );
    if (multiClientMode && incomingClientId) {
      const prevClientSeq = (registeredClient && registeredClient.lastClientSeq) || session.clientSeqMap.get(incomingClientId) || 0;
      if (hasExplicitSeq && prevClientSeq > 0 && seq > prevClientSeq + 1) {
        reconcileRequired = true;
        session.driftDetected = true;
      }
    } else if (session.lastSeq > 0 && seq > session.lastSeq + 1) {
      reconcileRequired = true;
      session.driftDetected = true;
    }

    // Secuencia única en el historial del servidor (evita colisión cuando dos clientes envían el mismo `frame.seq`)
    const historySeq = seq > session.lastSeq ? seq : session.lastSeq + 1;

    const ensuredDirs = new Set();
    if (!realBase && !fs.existsSync(baseDir)) {
      fs.mkdirSync(baseDir, { recursive: true });
    }
    ensuredDirs.add(baseDir);

    const nowMs = Date.now();
    const appliedAt = new Date(nowMs).toISOString();

    /** @type {Array<{ rel: string, abs: string, op: 'upsert' | 'delete', existed: boolean, prevBuffer: Buffer | null, prevHash: string | null }>} */
    const undoEntries = [];
    /** @type {Array<{ rel: string, info: any }>} */
    const pendingFileRevisions = [];
    /** @type {Array<{ rel: string, touch: any }>} */
    const pendingTouches = [];
    /** @type {any[]} */
    const frameConflicts = [];
    /** @type {string[]} */
    const rejectedFiles = [];
    let undoBytes = 0;
    let written = 0;
    let deleted = 0;
    let dedupSkipped = 0;
    let bytesWritten = 0;
    /** @type {string[]} */
    const changedPaths = [];
    const cache = session.fileCache;

    try {
      for (const entry of prepared) {
        let existed = Boolean(entry.stat);
        /** @type {Buffer | null} */
        let prevBuffer = null;
        if (entry.stat && entry.stat.isFile()) {
          const cached = cache.get(entry.abs);
          if (cached && cached.mtimeMs === entry.stat.mtimeMs && cached.size === entry.stat.size) {
            prevBuffer = cached.buf;
          } else {
            try {
              prevBuffer = fs.readFileSync(entry.abs);
            } catch (e) {
              if (!e || (e.code !== 'ENOENT' && e.code !== 'EISDIR')) throw e;
              existed = false;
            }
          }
        }

        if (entry.op === 'upsert' && entry.buffer !== null) {
          if (prevBuffer && prevBuffer.length === entry.buffer.length && prevBuffer.equals(entry.buffer)) {
            dedupSkipped++;
            continue;
          }

          const lastTouch = session.fileTouchMap ? session.fileTouchMap.get(entry.rel) || null : null;
          const needHashes = Boolean(entry.baseSha256 || (incomingClientId && lastTouch) || entry.hash);
          const newHash = entry.hash || (needHashes ? sha256(entry.buffer) : null);
          const prevHash = (existed && prevBuffer !== null && (entry.baseSha256 || (incomingClientId && lastTouch)))
            ? sha256(prevBuffer)
            : null;

          // Detector optimista de conflictos de 2 capas (CAS baseSha256 + ventana concurrente)
          /** @type {'stale_base_hash' | 'concurrent_window' | null} */
          let conflictReason = null;
          if (
            entry.baseSha256 &&
            prevHash !== null &&
            prevHash !== entry.baseSha256 &&
            prevHash !== newHash &&
            (!incomingClientId || !lastTouch || !lastTouch.clientId || lastTouch.clientId !== incomingClientId)
          ) {
            conflictReason = 'stale_base_hash';
          } else if (
            incomingClientId &&
            lastTouch &&
            lastTouch.clientId &&
            lastTouch.clientId !== incomingClientId &&
            (nowMs - lastTouch.atMs) <= conflictWindowMs &&
            newHash !== lastTouch.sha256
          ) {
            conflictReason = 'concurrent_window';
          }

          if (conflictReason) {
            const conflict = {
              id: `conf_${historySeq}_${nowMs.toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
              projectId,
              path: entry.rel,
              seq: historySeq,
              previousSeq: lastTouch ? lastTouch.seq : 0,
              reason: conflictReason,
              deltaMs: lastTouch ? Math.max(0, nowMs - lastTouch.atMs) : null,
              incoming: {
                clientId: incomingClientId,
                clientName: incomingClientName,
                sha256: newHash || sha256(entry.buffer),
                baseSha256: entry.baseSha256,
                op: 'upsert'
              },
              previous: lastTouch ? {
                clientId: lastTouch.clientId,
                clientName: lastTouch.clientName,
                sha256: lastTouch.sha256,
                at: lastTouch.at
              } : {
                clientId: null,
                clientName: 'disk',
                sha256: prevHash,
                at: appliedAt
              },
              detectedAt: appliedAt,
              policy: conflictPolicy,
              rejected: conflictPolicy === 'reject',
              resolved: false,
              resolvedAt: null
            };
            frameConflicts.push(conflict);
            if (conflictPolicy === 'reject') {
              rejectedFiles.push(entry.rel);
              continue;
            }
          }

          undoEntries.push({ rel: entry.rel, abs: entry.abs, op: 'upsert', existed, prevBuffer, prevHash });
          if (prevBuffer) undoBytes += prevBuffer.length;
          const postStat = writeFileAtomic(entry.abs, entry.buffer, ensuredDirs);
          if (postStat) {
            putSessionFileCache(session, entry.abs, entry.buffer, postStat);
            putMerkleCache(entry.abs, postStat, newHash);
          } else {
            deleteSessionFileCache(session, entry.abs);
            merkleFileCache.delete(entry.abs);
          }
          written++;
          bytesWritten += entry.buffer.length;
          changedPaths.push(entry.rel);

          const finalHash = newHash || (entry.buffer.length <= MAX_FILE_SNAPSHOT_BYTES ? sha256(entry.buffer) : null);
          pendingFileRevisions.push({
            rel: entry.rel,
            info: {
              seq: historySeq,
              appliedAt,
              action: existed ? 'modified' : 'created',
              clientId: incomingClientId,
              clientName: incomingClientName,
              prevExisted: existed,
              prevBuffer,
              prevHash,
              existed: true,
              newBuffer: entry.buffer,
              newHash: finalHash
            }
          });
          pendingTouches.push({
            rel: entry.rel,
            touch: {
              clientId: incomingClientId,
              clientName: incomingClientName,
              seq: historySeq,
              atMs: nowMs,
              at: appliedAt,
              sha256: finalHash,
              op: 'upsert'
            }
          });
        } else if (entry.op === 'delete') {
          if (!existed) {
            dedupSkipped++;
            continue;
          }

          const lastTouch = session.fileTouchMap ? session.fileTouchMap.get(entry.rel) || null : null;
          const prevHash = (prevBuffer !== null && (entry.baseSha256 || (incomingClientId && lastTouch)))
            ? sha256(prevBuffer)
            : null;

          /** @type {'stale_base_hash' | 'concurrent_window' | null} */
          let conflictReason = null;
          if (
            entry.baseSha256 &&
            prevHash !== null &&
            prevHash !== entry.baseSha256 &&
            (!incomingClientId || !lastTouch || !lastTouch.clientId || lastTouch.clientId !== incomingClientId)
          ) {
            conflictReason = 'stale_base_hash';
          } else if (
            incomingClientId &&
            lastTouch &&
            lastTouch.clientId &&
            lastTouch.clientId !== incomingClientId &&
            (nowMs - lastTouch.atMs) <= conflictWindowMs
          ) {
            conflictReason = 'concurrent_window';
          }

          if (conflictReason) {
            const conflict = {
              id: `conf_${historySeq}_${nowMs.toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
              projectId,
              path: entry.rel,
              seq: historySeq,
              previousSeq: lastTouch ? lastTouch.seq : 0,
              reason: conflictReason,
              deltaMs: lastTouch ? Math.max(0, nowMs - lastTouch.atMs) : null,
              incoming: {
                clientId: incomingClientId,
                clientName: incomingClientName,
                sha256: null,
                baseSha256: entry.baseSha256,
                op: 'delete'
              },
              previous: lastTouch ? {
                clientId: lastTouch.clientId,
                clientName: lastTouch.clientName,
                sha256: lastTouch.sha256,
                at: lastTouch.at
              } : {
                clientId: null,
                clientName: 'disk',
                sha256: prevHash,
                at: appliedAt
              },
              detectedAt: appliedAt,
              policy: conflictPolicy,
              rejected: conflictPolicy === 'reject',
              resolved: false,
              resolvedAt: null
            };
            frameConflicts.push(conflict);
            if (conflictPolicy === 'reject') {
              rejectedFiles.push(entry.rel);
              continue;
            }
          }

          undoEntries.push({ rel: entry.rel, abs: entry.abs, op: 'delete', existed: true, prevBuffer, prevHash });
          if (prevBuffer) undoBytes += prevBuffer.length;
          if (entry.stat && entry.stat.isDirectory()) {
            fs.rmSync(entry.abs, { recursive: true, force: true });
          } else {
            fs.unlinkSync(entry.abs);
          }
          deleteSessionFileCache(session, entry.abs);
          merkleFileCache.delete(entry.abs);
          deleted++;
          changedPaths.push(entry.rel);

          pendingFileRevisions.push({
            rel: entry.rel,
            info: {
              seq: historySeq,
              appliedAt,
              action: 'deleted',
              clientId: incomingClientId,
              clientName: incomingClientName,
              prevExisted: true,
              prevBuffer,
              prevHash,
              existed: false,
              newBuffer: null,
              newHash: null
            }
          });
          pendingTouches.push({
            rel: entry.rel,
            touch: {
              clientId: incomingClientId,
              clientName: incomingClientName,
              seq: historySeq,
              atMs: nowMs,
              at: appliedAt,
              sha256: null,
              op: 'delete'
            }
          });
        }
      }
    } catch (writeErr) {
      // Atomicidad real: si falla a mitad de trama, revertir lo escrito y restaurar lastSeq (P1-16)
      for (let i = undoEntries.length - 1; i >= 0; i--) {
        const u = undoEntries[i];
        try {
          if (u.existed && u.prevBuffer !== null) {
            writeFileAtomic(u.abs, u.prevBuffer, ensuredDirs);
          } else if (fs.existsSync(u.abs)) {
            fs.unlinkSync(u.abs);
          }
          deleteSessionFileCache(session, u.abs);
          merkleFileCache.delete(u.abs);
        } catch (e) {}
      }
      session.lastSeq = prevLastSeq;
      throw writeErr;
    }

    if (historySeq > session.lastSeq) session.lastSeq = historySeq;
    if (incomingClientId) {
      session.clientSeqMap.set(incomingClientId, seq);
      if (registeredClient) {
        registeredClient.lastFrameAt = appliedAt;
        registeredClient.framesSent = (registeredClient.framesSent || 0) + 1;
        registeredClient.lastClientSeq = seq;
      }
    }

    // Confirmar historial por fichero, toques y conflictos tras éxito atómico en disco
    for (const item of pendingFileRevisions) {
      recordFileRevision(session, item.rel, item.info);
    }
    for (const item of pendingTouches) {
      recordFileTouch(session, item.rel, item.touch);
    }
    if (frameConflicts.length > 0) {
      session.conflictsCount = (session.conflictsCount || 0) + frameConflicts.length;
      for (const c of frameConflicts) {
        session.recentConflicts.unshift(c);
      }
      while (session.recentConflicts.length > MAX_RECENT_CONFLICTS) {
        session.recentConflicts.pop();
      }
    }

    // Telemetría de compresión en cable
    const wireStats = options.wireStats || frame._wireStats || null;
    if (wireStats && typeof wireStats.wireBytes === 'number' && wireStats.wireBytes >= 0) {
      const wireB = wireStats.wireBytes;
      const rawB = typeof wireStats.rawBytes === 'number' && wireStats.rawBytes >= wireB ? wireStats.rawBytes : wireB;
      const savedB = Math.max(0, rawB - wireB);
      session.wireStats.rawBytes += rawB;
      session.wireStats.wireBytes += wireB;
      session.wireStats.savedBytes += savedB;
      session.wireStats.savedPct = session.wireStats.rawBytes > 0
        ? Number(((session.wireStats.savedBytes / session.wireStats.rawBytes) * 100).toFixed(1))
        : 0;
      const codec = wireStats.codec || 'none';
      if (codec !== 'none') session.wireStats.compressedFrames++;
      else session.wireStats.rawFrames++;
      session.wireStats.lastCodec = codec;
      session.wireStats.lastSavedPct = rawB > 0 ? Number(((savedB / rawB) * 100).toFixed(1)) : 0;
    }

    const classification = classifyChanges(changedPaths.length > 0 ? changedPaths : prepared.map(p => p.rel));

    if (undoEntries.length > 0) {
      const afterByRel = new Map();
      let afterBytes = 0;
      for (const p of prepared) {
        if (p.op === 'upsert' && p.buffer && p.buffer.length <= 64 * 1024 && !p.buffer.includes(0) && !rejectedFiles.includes(p.rel)) {
          afterByRel.set(p.rel, p.buffer);
          afterBytes += p.buffer.length;
        }
      }
      const patch = {
        patchId: `patch_${historySeq}_${Date.now()}`,
        seq: historySeq,
        clientSeq: seq,
        clientId: incomingClientId,
        clientName: incomingClientName,
        appliedAt,
        files: changedPaths,
        classification: classification.path,
        byteSize: undoBytes + afterBytes,
        undoEntries,
        afterByRel
      };
      session.patchHistory.unshift(patch);
      session.patchHistoryBytes = (session.patchHistoryBytes || 0) + patch.byteSize;
      while (
        session.patchHistory.length > MAX_PATCH_HISTORY ||
        (session.patchHistory.length > 1 && session.patchHistoryBytes > MAX_PATCH_HISTORY_BYTES)
      ) {
        const evicted = session.patchHistory.pop();
        if (evicted) session.patchHistoryBytes = Math.max(0, session.patchHistoryBytes - (evicted.byteSize || 0));
      }
    }

    const applyMs = Number((Number(process.hrtime.bigint() - startedNs) / 1e6).toFixed(2));
    session.framesApplied++;
    session.filesWritten += written;
    session.filesDeleted += deleted;
    session.dedupSkipped += dedupSkipped;
    session.bytesSynced += bytesWritten;
    session.lastPath = classification.path;
    session.lastReason = classification.reason;
    session.lastAppliedAt = appliedAt;
    session.lastApplyMs = applyMs;
    session.latencySamples.push(applyMs);
    if (session.latencySamples.length > MAX_LATENCY_SAMPLES) {
      session.latencySamples.shift();
    }

    session.recentFrames.unshift({
      seq: historySeq,
      at: appliedAt,
      appliedAt,
      clientId: incomingClientId,
      clientName: incomingClientName,
      written,
      deleted,
      dedupSkipped,
      bytesWritten,
      applyMs,
      mode: classification.path,
      files: changedPaths.slice(0, 10),
      totalFiles: changedPaths.length,
      conflictsCount: frameConflicts.length,
      codec: wireStats ? (wireStats.codec || 'none') : null
    });
    if (session.recentFrames.length > MAX_RECENT_FRAMES) {
      session.recentFrames.pop();
    }

    const result = {
      applied: true,
      projectId,
      seq,
      serverSeq: historySeq,
      clientId: incomingClientId,
      clientName: incomingClientName,
      written,
      deleted,
      dedupSkipped,
      bytesWritten,
      changedFiles: changedPaths,
      rejectedFiles,
      conflicts: frameConflicts,
      mode: classification.path,
      reason: classification.reason,
      triggerFiles: classification.triggerFiles,
      applyMs,
      reconcileRequired,
      historyDepth: session.patchHistory.length,
      wireStats: wireStats ? {
        codec: wireStats.codec || 'none',
        wireBytes: wireStats.wireBytes || 0,
        rawBytes: wireStats.rawBytes || 0,
        savedBytes: wireStats.savedBytes || 0
      } : null
    };

    if (!options.deferEmit) {
      this.emitApplied(result);
    }
    return result;
  }

  /**
   * Revierte los últimos `steps` commit frames directamente desde el historial
   * de parches en memoria: <10 ms sin reconstruir nada.
   * Repuebla `fileCache` y `merkleFileCache` para evitar lecturas frías posteriores.
   *
   * @param {string} projectId
   * @param {number} [steps]
   */
  rollback(projectId, steps = 1) {
    const startedNs = process.hrtime.bigint();
    const session = this.getOrCreateSession(projectId);
    const count = Math.max(1, Math.min(Number(steps) || 1, session.patchHistory.length));
    if (session.patchHistory.length === 0) {
      throw new Error('No hay historial de parches de sincronización en vivo para revertir');
    }

    /** @type {string[]} */
    const restoredFiles = [];
    /** @type {string[]} */
    const revertedPatchIds = [];
    const ensuredDirs = new Set();
    const nowMs = Date.now();
    const nowIso = new Date(nowMs).toISOString();

    for (let i = 0; i < count; i++) {
      const patch = session.patchHistory.shift();
      if (!patch) break;
      session.patchHistoryBytes = Math.max(0, (session.patchHistoryBytes || 0) - (patch.byteSize || 0));
      revertedPatchIds.push(patch.patchId);
      for (const entry of patch.undoEntries) {
        if (entry.existed && entry.prevBuffer !== null) {
          const postStat = writeFileAtomic(entry.abs, entry.prevBuffer, ensuredDirs);
          const restoredHash = entry.prevHash || (entry.prevBuffer.length <= 512 * 1024 ? sha256(entry.prevBuffer) : null);
          if (postStat) {
            putSessionFileCache(session, entry.abs, entry.prevBuffer, postStat);
            putMerkleCache(entry.abs, postStat, restoredHash);
          } else {
            deleteSessionFileCache(session, entry.abs);
            merkleFileCache.delete(entry.abs);
          }
          recordFileTouch(session, entry.rel, {
            clientId: null,
            clientName: 'rollback',
            seq: session.lastSeq,
            atMs: nowMs,
            at: nowIso,
            sha256: restoredHash,
            op: 'rollback'
          });
        } else {
          if (fs.existsSync(entry.abs)) {
            fs.unlinkSync(entry.abs);
          }
          deleteSessionFileCache(session, entry.abs);
          merkleFileCache.delete(entry.abs);
          if (session.fileTouchMap) session.fileTouchMap.delete(entry.rel);
        }
        restoredFiles.push(entry.rel);
      }
    }

    const durationMs = Number((Number(process.hrtime.bigint() - startedNs) / 1e6).toFixed(2));
    session.rollbacksCount++;

    const result = {
      reverted: true,
      projectId,
      revertedPatchIds,
      restoredFiles: Array.from(new Set(restoredFiles)),
      durationMs,
      remainingHistory: session.patchHistory.length
    };
    this.emit('sync_rollback', result);
    return result;
  }

  /**
   * Devuelve el historial time-travel de un único fichero (validando estrictamente la ruta).
   *
   * @param {string} projectId
   * @param {string} filePath
   * @param {{ targetDir?: string | null, limit?: number, includeDiff?: boolean }} [options]
   */
  getFileHistory(projectId, filePath, options = {}) {
    const session = this.getOrCreateSession(projectId);
    const baseDir = this.resolveTargetDir(projectId, options.targetDir || null);
    // Re-verificación completa sin caché de directorios (anti-traversal y anti-symlink hoja)
    const { rel, abs, stat } = resolveSafeFilePath(baseDir, filePath);

    const existsOnDisk = Boolean(stat && stat.isFile());
    /** @type {string | null} */
    let currentSha256 = null;
    if (existsOnDisk && stat) {
      const cached = session.fileCache.get(abs);
      if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
        currentSha256 = sha256(cached.buf);
      } else {
        const merkleHit = merkleFileCache.get(abs);
        if (merkleHit && merkleHit.mtimeMs === stat.mtimeMs && merkleHit.size === stat.size) {
          currentSha256 = merkleHit.hash;
        } else {
          try {
            currentSha256 = sha256(fs.readFileSync(abs));
          } catch (e) {}
        }
      }
    }

    const allRevs = (session.fileHistory && session.fileHistory.get(rel)) || [];
    const maxItems = (typeof options.limit === 'number' && Number.isFinite(options.limit) && options.limit > 0)
      ? Math.min(allRevs.length, Math.floor(options.limit))
      : allRevs.length;
    const includeDiff = Boolean(options.includeDiff);

    const revisions = [];
    for (let idx = 0; idx < maxItems; idx++) {
      const r = allRevs[idx];
      /** @type {any} */
      const item = {
        seq: r.seq,
        appliedAt: r.appliedAt,
        action: r.action,
        clientId: r.clientId || null,
        clientName: r.clientName || null,
        existed: Boolean(r.existed),
        byteLength: r.byteLength,
        sha256: r.sha256 || null,
        restorable: Boolean(r.snapshot && r.snapshot.restorable),
        ...(r.restoredFromSeq !== undefined ? { restoredFromSeq: r.restoredFromSeq } : {})
      };
      if (includeDiff && r.snapshot && r.snapshot.restorable) {
        try {
          const afterBuf = r.existed ? unpackSnapshot(r.snapshot) : null;
          const prevRev = allRevs[idx + 1];
          const beforeBuf = prevRev && prevRev.existed && prevRev.snapshot && prevRev.snapshot.restorable
            ? unpackSnapshot(prevRev.snapshot)
            : null;
          const isBin = (afterBuf && afterBuf.includes(0)) || (beforeBuf && beforeBuf.includes(0));
          if (!isBin) {
            const bLines = beforeBuf ? beforeBuf.toString('utf8').slice(0, 16384).split(/\r?\n/) : [];
            const aLines = afterBuf ? afterBuf.toString('utf8').slice(0, 16384).split(/\r?\n/) : [];
            item.diff = computeUnifiedLineDiff(bLines, aLines);
          }
        } catch (e) {}
      }
      revisions.push(item);
    }

    return {
      projectId,
      path: rel,
      filePath: rel,
      existsOnDisk,
      currentSha256,
      revisionCount: allRevs.length,
      revisions,
      versions: revisions
    };
  }

  /**
   * Rollback quirúrgico (time-travel) de un único fichero a una revisión concreta (`seq`).
   * - Valida la ruta con `resolveSafeFilePath` (re-check de ancestros y `lstatSync` anti-symlink).
   * - Repuebla `fileCache` y `merkleFileCache`.
   * - Registra un nuevo frame deshacible en `patchHistory` y una nueva revisión en `fileHistory`.
   *
   * @param {string} projectId
   * @param {string} filePath
   * @param {number} seq
   * @param {{ mode?: 'to' | 'before', targetDir?: string | null, clientId?: string | null, clientName?: string | null, actor?: string | null }} [options]
   */
  rollbackFile(projectId, filePath, seq, options = {}) {
    const startedNs = process.hrtime.bigint();
    const session = this.getOrCreateSession(projectId);
    const baseDir = this.resolveTargetDir(projectId, options.targetDir || null);
    // Re-verificación estricta en disco (bloquea traversal, rutas absolutas, .git y symlinks)
    const { rel, abs, stat } = resolveSafeFilePath(baseDir, filePath);

    const targetSeq = Number(seq);
    if (!Number.isInteger(targetSeq) || targetSeq < 0) {
      const err = new Error(`Número de secuencia inválido para rollbackFile: ${seq}`);
      /** @type {any} */ (err).code = 'INVALID_SEQ';
      throw err;
    }

    const mode = options.mode === 'before' ? 'before' : 'to';
    const revs = (session.fileHistory && session.fileHistory.get(rel)) || [];
    const idx = revs.findIndex((r) => Number(r.seq) === targetSeq);
    if (idx === -1) {
      const err = new Error(`Revisión #${targetSeq} no encontrada en el historial de ${rel}`);
      /** @type {any} */ (err).code = 'REVISION_NOT_FOUND';
      throw err;
    }

    const chosenRev = mode === 'before' ? revs[idx + 1] : revs[idx];
    if (!chosenRev) {
      const err = new Error(`No existe una revisión anterior a #${targetSeq} en el historial de ${rel}`);
      /** @type {any} */ (err).code = 'REVISION_NOT_FOUND';
      throw err;
    }

    /** @type {Buffer | null} */
    let targetBuf = null;
    if (chosenRev.existed) {
      targetBuf = unpackSnapshot(chosenRev.snapshot);
      if (targetBuf === null) {
        const err = new Error(`Snapshot de revisión #${chosenRev.seq} no disponible para ${rel}`);
        /** @type {any} */ (err).code = 'SNAPSHOT_NOT_RESTORABLE';
        throw err;
      }
    }

    // Capturar estado actual en disco para que este rollback quirúrgico sea deshacible vía `rollback(id, 1)`
    let prevExisted = Boolean(stat && stat.isFile());
    /** @type {Buffer | null} */
    let prevBuffer = null;
    if (prevExisted && stat) {
      const cached = session.fileCache.get(abs);
      if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
        prevBuffer = cached.buf;
      } else {
        try {
          prevBuffer = fs.readFileSync(abs);
        } catch (e) {
          if (!e || (e.code !== 'ENOENT' && e.code !== 'EISDIR')) throw e;
          prevExisted = false;
        }
      }
    }
    const prevHash = prevExisted && prevBuffer !== null ? sha256(prevBuffer) : null;

    const ensuredDirs = new Set();
    /** @type {'restored' | 'deleted'} */
    let actionPerformed = 'restored';
    /** @type {string | null} */
    let newSha = null;

    if (chosenRev.existed && targetBuf !== null) {
      const postStat = writeFileAtomic(abs, targetBuf, ensuredDirs);
      newSha = chosenRev.sha256 || sha256(targetBuf);
      if (postStat) {
        putSessionFileCache(session, abs, targetBuf, postStat);
        putMerkleCache(abs, postStat, newSha);
      } else {
        deleteSessionFileCache(session, abs);
        merkleFileCache.delete(abs);
      }
      actionPerformed = 'restored';
    } else {
      if (stat) {
        if (stat.isDirectory()) fs.rmSync(abs, { recursive: true, force: true });
        else fs.unlinkSync(abs);
      }
      deleteSessionFileCache(session, abs);
      merkleFileCache.delete(abs);
      actionPerformed = 'deleted';
      newSha = null;
    }

    const nowMs = Date.now();
    const appliedAt = new Date(nowMs).toISOString();
    const newSeq = (session.lastSeq || 0) + 1;
    session.lastSeq = newSeq;

    const actorId = options.clientId || null;
    const actorName = options.clientName || options.actor || 'time-travel';

    // Registrar nuevo frame deshacible en patchHistory
    const undoEntry = {
      rel,
      abs,
      op: /** @type {'upsert' | 'delete'} */ (chosenRev.existed ? 'upsert' : 'delete'),
      existed: prevExisted,
      prevBuffer,
      prevHash
    };
    const afterByRel = new Map();
    let afterBytes = 0;
    if (targetBuf !== null && targetBuf.length <= 64 * 1024 && !targetBuf.includes(0)) {
      afterByRel.set(rel, targetBuf);
      afterBytes = targetBuf.length;
    }
    const patch = {
      patchId: `patch_rbfile_${newSeq}_${nowMs}`,
      seq: newSeq,
      clientId: actorId,
      clientName: actorName,
      appliedAt,
      files: [rel],
      classification: classifyChanges([rel]).path,
      byteSize: (prevBuffer ? prevBuffer.length : 0) + afterBytes,
      undoEntries: [undoEntry],
      afterByRel,
      rollbackOf: { filePath: rel, targetSeq: chosenRev.seq, requestedSeq: targetSeq, mode }
    };
    session.patchHistory.unshift(patch);
    session.patchHistoryBytes = (session.patchHistoryBytes || 0) + patch.byteSize;
    while (
      session.patchHistory.length > MAX_PATCH_HISTORY ||
      (session.patchHistory.length > 1 && session.patchHistoryBytes > MAX_PATCH_HISTORY_BYTES)
    ) {
      const evicted = session.patchHistory.pop();
      if (evicted) session.patchHistoryBytes = Math.max(0, session.patchHistoryBytes - (evicted.byteSize || 0));
    }

    // Registrar nueva revisión en fileHistory y actualizar fileTouchMap
    recordFileRevision(session, rel, {
      seq: newSeq,
      appliedAt,
      action: 'rolled_back',
      clientId: actorId,
      clientName: actorName,
      prevExisted,
      prevBuffer,
      prevHash,
      existed: Boolean(chosenRev.existed),
      newBuffer: targetBuf,
      newHash: newSha,
      restoredFromSeq: chosenRev.seq
    });

    recordFileTouch(session, rel, {
      clientId: actorId,
      clientName: actorName,
      seq: newSeq,
      atMs: nowMs,
      at: appliedAt,
      sha256: newSha,
      op: 'rollback'
    });

    const durationMs = Number((Number(process.hrtime.bigint() - startedNs) / 1e6).toFixed(2));
    session.rollbacksCount++;

    session.recentFrames.unshift({
      seq: newSeq,
      at: appliedAt,
      appliedAt,
      clientId: actorId,
      clientName: actorName,
      written: chosenRev.existed ? 1 : 0,
      deleted: chosenRev.existed ? 0 : 1,
      dedupSkipped: 0,
      bytesWritten: targetBuf ? targetBuf.length : 0,
      applyMs: durationMs,
      mode: patch.classification,
      files: [rel],
      totalFiles: 1,
      rollbackOf: chosenRev.seq
    });
    if (session.recentFrames.length > MAX_RECENT_FRAMES) {
      session.recentFrames.pop();
    }

    const result = {
      reverted: true,
      scope: 'file',
      projectId,
      filePath: rel,
      targetSeq: chosenRev.seq,
      requestedSeq: targetSeq,
      mode,
      seq: newSeq,
      restoredFiles: [rel],
      action: actionPerformed,
      sha256: newSha,
      durationMs,
      remainingHistory: session.patchHistory.length
    };
    this.emit('sync_rollback', result);
    return result;
  }

  /**
   * Marca un conflicto multi-cliente reciente como resuelto/descartado.
   *
   * @param {string} projectId
   * @param {string} conflictId
   */
  resolveConflict(projectId, conflictId) {
    const session = this.getOrCreateSession(projectId);
    const cleanId = String(conflictId || '').trim();
    const conflict = (session.recentConflicts || []).find((c) => c.id === cleanId);
    if (!conflict) {
      const err = new Error(`Conflicto de sincronización no encontrado: ${cleanId}`);
      /** @type {any} */ (err).code = 'CONFLICT_NOT_FOUND';
      throw err;
    }
    conflict.resolved = true;
    conflict.resolvedAt = new Date().toISOString();
    this.emit('sync_conflict_resolved', { projectId, conflictId: cleanId, conflict });
    return { resolved: true, projectId, conflict };
  }

  /**
   * Devuelve una vista compacta del diff unificado (LCS <=400 líneas) de un Commit Frame concreto.
   * @param {string} projectId
   * @param {number} seq
   */
  getFrameDiff(projectId, seq) {
    const session = this.getOrCreateSession(projectId);
    const numSeq = Number(seq);
    const patch = (session.patchHistory || []).find((p) => Number(p.seq) === numSeq);
    if (!patch) return null;

    const files = (patch.undoEntries || []).map((u) => {
      const beforeBuf = u.prevBuffer;
      const afterBuf = patch.afterByRel ? patch.afterByRel.get(u.rel) : null;
      const isBinary = (beforeBuf && beforeBuf.includes(0)) || (afterBuf && afterBuf.includes(0));
      if (isBinary) {
        return {
          path: u.rel,
          binary: true,
          existedBefore: Boolean(u.existed),
          beforeBytes: beforeBuf ? beforeBuf.length : 0,
          afterBytes: afterBuf ? afterBuf.length : 0
        };
      }
      const beforeText = beforeBuf ? beforeBuf.toString('utf8').slice(0, 32768) : '';
      const afterText = afterBuf ? afterBuf.toString('utf8').slice(0, 32768) : '';
      const isDeleted = u.op === 'delete' || (u.existed && !afterBuf && !fs.existsSync(u.abs));
      const status = !u.existed ? 'added' : (isDeleted ? 'deleted' : 'modified');
      const beforeLines = beforeText ? beforeText.split(/\r?\n/) : [];
      const afterLines = afterText ? afterText.split(/\r?\n/) : [];
      const diff = computeUnifiedLineDiff(beforeLines, afterLines);
      return {
        path: u.rel,
        status,
        action: status,
        binary: false,
        before: beforeText,
        after: afterText,
        diff,
        truncated: (beforeBuf && beforeBuf.length > 32768) || (afterBuf && afterBuf.length > 32768)
      };
    });

    return {
      projectId,
      seq: patch.seq,
      patchId: patch.patchId,
      appliedAt: patch.appliedAt,
      clientId: patch.clientId || null,
      clientName: patch.clientName || null,
      mode: patch.classification,
      files
    };
  }

  /**
   * Verifica la integridad del árbol de archivos del servidor contra un digest
   * o mapa de hashes del cliente.
   *
   * @param {string} projectId
   * @param {{ clientDigest?: string | null, clientFiles?: Record<string, string> | null, targetDir?: string | null }} [opts]
   */
  verifySync(projectId, opts = {}) {
    const startedNs = process.hrtime.bigint();
    const session = this.getOrCreateSession(projectId);
    const baseDir = this.resolveTargetDir(projectId, opts.targetDir || null);
    const tree = computeMerkleTree(baseDir);

    /** @type {any} */
    let comparison = null;
    let verifiedAgainstClient = false;
    if (opts.clientFiles && typeof opts.clientFiles === 'object') {
      comparison = diffMerkleTrees(opts.clientFiles, tree.files);
      session.driftDetected = !comparison.inSync;
      verifiedAgainstClient = true;
    } else if (opts.clientDigest) {
      const inSync = opts.clientDigest === tree.rootDigest;
      comparison = {
        inSync,
        divergentCount: inSync ? 0 : null,
        missingOnServer: /** @type {string[]} */ ([]),
        staleOnServer: /** @type {string[]} */ ([]),
        extraOnServer: /** @type {string[]} */ ([])
      };
      session.driftDetected = !inSync;
      verifiedAgainstClient = true;
    } else {
      session.driftDetected = false;
    }

    const inSyncVal = comparison
      ? comparison.inSync
      : (session.connectedClients > 0 ? !session.driftDetected : null);

    return {
      projectId,
      targetDir: baseDir,
      serverDigest: tree.rootDigest,
      fileCount: tree.fileCount,
      totalBytes: tree.totalBytes,
      inSync: inSyncVal,
      verifiedAgainstClient,
      message: verifiedAgainstClient
        ? (inSyncVal ? 'Árbol Merkle idéntico entre cliente y servidor.' : 'Se detectaron diferencias respecto al cliente.')
        : (session.connectedClients === 0
          ? 'Árbol local verificado en disco (sin cliente Live Sync conectado para comparar).'
          : 'Árbol local verificado en disco.'),
      comparison,
      verifyMs: Number((Number(process.hrtime.bigint() - startedNs) / 1e6).toFixed(2)),
      lastSeq: session.lastSeq,
      connectedClients: session.connectedClients
    };
  }

  /**
   * Estado completo + percentiles reales de latencia, conflictos y estadísticas de compresión.
   *
   * @param {string} projectId
   */
  getStatus(projectId) {
    const s = this.getOrCreateSession(projectId);
    const ws = s.wireStats || {
      rawBytes: 0,
      wireBytes: 0,
      savedBytes: 0,
      savedPct: 0,
      compressedFrames: 0,
      rawFrames: 0,
      lastCodec: null,
      lastSavedPct: 0
    };
    return {
      projectId,
      targetDir: this.resolveTargetDir(projectId),
      connectedClients: s.connectedClients,
      clients: Array.from((s.clients || new Map()).values()),
      lastSeq: s.lastSeq,
      framesApplied: s.framesApplied,
      filesWritten: s.filesWritten,
      filesDeleted: s.filesDeleted,
      dedupSkipped: s.dedupSkipped,
      bytesSynced: s.bytesSynced,
      rollbacksCount: s.rollbacksCount,
      driftDetected: s.driftDetected,
      lastPath: s.lastPath,
      lastReason: s.lastReason,
      lastAppliedAt: s.lastAppliedAt,
      lastApplyMs: s.lastApplyMs,
      historyDepth: s.patchHistory.length,
      recentFrames: s.recentFrames || [],
      conflictsCount: s.conflictsCount || 0,
      recentConflicts: s.recentConflicts || [],
      wireStats: {
        rawBytes: ws.rawBytes,
        wireBytes: ws.wireBytes,
        savedBytes: ws.savedBytes,
        savedPct: ws.savedPct,
        compressedFrames: ws.compressedFrames,
        rawFrames: ws.rawFrames,
        lastCodec: ws.lastCodec,
        lastSavedPct: ws.lastSavedPct
      },
      wireBytesReceived: ws.wireBytes,
      rawBytesReceived: ws.rawBytes,
      compressionSavedBytes: ws.savedBytes,
      compressionRatio: ws.savedPct,
      lastCompression: ws.lastCodec,
      latencyMs: computePercentiles(s.latencySamples)
    };
  }

  /** Resumen global de todas las sesiones activas de sincronización en vivo. */
  getGlobalSummary() {
    const active = [];
    let totalFrames = 0;
    let totalClients = 0;
    let totalRawBytes = 0;
    let totalWireBytes = 0;
    let totalSavedBytes = 0;
    let totalCompressedFrames = 0;
    let totalConflicts = 0;
    /** @type {number[]} */
    const allSamples = [];

    for (const s of this.sessions.values()) {
      totalFrames += s.framesApplied;
      totalClients += s.connectedClients;
      totalConflicts += s.conflictsCount || 0;
      if (s.wireStats) {
        totalRawBytes += s.wireStats.rawBytes || 0;
        totalWireBytes += s.wireStats.wireBytes || 0;
        totalSavedBytes += s.wireStats.savedBytes || 0;
        totalCompressedFrames += s.wireStats.compressedFrames || 0;
      }
      allSamples.push(...s.latencySamples);
      if (s.framesApplied > 0 || s.connectedClients > 0) {
        active.push(this.getStatus(s.projectId));
      }
    }

    const savedPct = totalRawBytes > 0 ? Number(((totalSavedBytes / totalRawBytes) * 100).toFixed(1)) : 0;

    return {
      activeSessions: active.length,
      connectedClients: totalClients,
      totalFramesApplied: totalFrames,
      totalConflicts,
      wireStats: {
        rawBytes: totalRawBytes,
        wireBytes: totalWireBytes,
        savedBytes: totalSavedBytes,
        savedPct,
        compressedFrames: totalCompressedFrames
      },
      latencyMs: computePercentiles(allSamples),
      sessions: active
    };
  }

  // =========================================================================
  // CHUNKED UPLOAD (>10 MiB hasta 100 MiB) CON VERIFICACIÓN SHA-256 ATÓMICA
  // =========================================================================

  /**
   * Inicia una carga troceada para ficheros grandes (>10 MiB, hasta 100 MiB) sin
   * mantener el fichero entero en memoria ni sobrepasar el límite de frame WS.
   *
   * @param {string} projectId
   * @param {{ path: string, totalBytes: number, sha256: string, baseSha256?: string | null, clientId?: string | null, clientName?: string | null }} meta
   * @param {{ targetDir?: string | null }} [options]
   */
  startChunkedUpload(projectId, meta, options = {}) {
    const session = this.getOrCreateSession(projectId);
    this._cleanupChunkUploads(session, true);
    if (session.chunkUploads.size >= MAX_ACTIVE_CHUNK_UPLOADS) {
      const err = new Error(`Demasiadas cargas troceadas simultáneas (máximo ${MAX_ACTIVE_CHUNK_UPLOADS})`);
      /** @type {any} */ (err).code = 'TOO_MANY_UPLOADS';
      throw err;
    }

    const baseDir = this.resolveTargetDir(projectId, options.targetDir || null);
    const { rel, abs } = resolveSafeFilePath(baseDir, meta && meta.path);

    const totalBytes = Number(meta && meta.totalBytes);
    if (!Number.isInteger(totalBytes) || totalBytes < 0 || totalBytes > MAX_CHUNKED_FILE_BYTES) {
      const err = new Error(`totalBytes inválido para carga troceada (0..${MAX_CHUNKED_FILE_BYTES}): ${meta && meta.totalBytes}`);
      /** @type {any} */ (err).code = 'FILE_TOO_LARGE';
      throw err;
    }
    const expectedSha256 = String((meta && meta.sha256) || '').trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(expectedSha256)) {
      const err = new Error('startChunkedUpload requiere un sha256 hexadecimal válido de 64 caracteres');
      /** @type {any} */ (err).code = 'INVALID_SHA256';
      throw err;
    }

    const dir = path.dirname(abs);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const uploadId = `chk_${Date.now().toString(36)}_${crypto.randomBytes(6).toString('hex')}`;
    const tempPath = `${abs}.culkibo-sync-chunk-${uploadId}.tmp`;
    fs.writeFileSync(tempPath, Buffer.alloc(0));

    const nowMs = Date.now();
    session.chunkUploads.set(uploadId, {
      uploadId,
      rel,
      abs,
      baseDir,
      tempPath,
      totalBytes,
      expectedSha256,
      baseSha256: meta && meta.baseSha256 ? String(meta.baseSha256) : null,
      clientId: meta && meta.clientId ? String(meta.clientId) : null,
      clientName: meta && meta.clientName ? String(meta.clientName) : null,
      receivedBytes: 0,
      nextIndex: 0,
      hasher: crypto.createHash('sha256'),
      startedAtMs: nowMs,
      updatedAtMs: nowMs
    });

    return {
      ok: true,
      uploadId,
      path: rel,
      totalBytes,
      maxChunkBytes: MAX_CHUNK_BYTES
    };
  }

  /**
   * Añade un trozo secuencial (`index === nextIndex`) a una carga troceada activa.
   *
   * @param {string} projectId
   * @param {{ uploadId: string, index: number, data: Buffer | string, encoding?: 'base64' | 'utf8' }} part
   */
  appendChunk(projectId, part) {
    const session = this.getOrCreateSession(projectId);
    const uploadId = String((part && part.uploadId) || '');
    const upload = session.chunkUploads.get(uploadId);
    if (!upload) {
      const err = new Error(`Carga troceada no encontrada o expirada: ${uploadId}`);
      /** @type {any} */ (err).code = 'UPLOAD_NOT_FOUND';
      throw err;
    }
    const index = Number(part && part.index);
    if (!Number.isInteger(index) || index !== upload.nextIndex) {
      const err = new Error(`Índice de trozo fuera de orden: esperado ${upload.nextIndex}, recibido ${index}`);
      /** @type {any} */ (err).code = 'OUT_OF_ORDER_CHUNK';
      throw err;
    }
    const buf = Buffer.isBuffer(part.data)
      ? part.data
      : Buffer.from(String(part.data || ''), part.encoding === 'utf8' ? 'utf8' : 'base64');
    if (buf.length > MAX_CHUNK_BYTES) {
      const err = new Error(`Trozo supera el máximo permitido (${MAX_CHUNK_BYTES} bytes)`);
      /** @type {any} */ (err).code = 'CHUNK_TOO_LARGE';
      throw err;
    }
    if (upload.receivedBytes + buf.length > upload.totalBytes) {
      const err = new Error(`Los bytes recibidos superan totalBytes (${upload.totalBytes})`);
      /** @type {any} */ (err).code = 'CHUNK_OVERFLOW';
      throw err;
    }

    if (buf.length > 0) {
      fs.appendFileSync(upload.tempPath, buf);
      upload.hasher.update(buf);
      upload.receivedBytes += buf.length;
    }
    upload.nextIndex++;
    upload.updatedAtMs = Date.now();

    return {
      ok: true,
      uploadId,
      index,
      receivedBytes: upload.receivedBytes,
      totalBytes: upload.totalBytes
    };
  }

  /**
   * Verifica tamaño y SHA-256 final y promueve atómicamente el fichero troceado a su ruta destino.
   *
   * @param {string} projectId
   * @param {{ uploadId: string }} req
   * @param {{ targetDir?: string | null, deferEmit?: boolean }} [options]
   */
  commitChunkedUpload(projectId, req, options = {}) {
    const startedNs = process.hrtime.bigint();
    const session = this.getOrCreateSession(projectId);
    const uploadId = String((req && req.uploadId) || '');
    const upload = session.chunkUploads.get(uploadId);
    if (!upload) {
      const err = new Error(`Carga troceada no encontrada o expirada: ${uploadId}`);
      /** @type {any} */ (err).code = 'UPLOAD_NOT_FOUND';
      throw err;
    }

    const cleanupTemp = () => {
      session.chunkUploads.delete(uploadId);
      try { if (upload.tempPath && fs.existsSync(upload.tempPath)) fs.unlinkSync(upload.tempPath); } catch (e) {}
    };

    if (upload.receivedBytes !== upload.totalBytes) {
      cleanupTemp();
      const err = new Error(`Carga troceada incompleta: recibidos ${upload.receivedBytes} de ${upload.totalBytes} bytes`);
      /** @type {any} */ (err).code = 'INCOMPLETE_UPLOAD';
      throw err;
    }

    const actualSha = upload.hasher.digest('hex');
    if (actualSha !== upload.expectedSha256) {
      cleanupTemp();
      const err = new Error(`Checksum SHA-256 inválido en carga troceada para ${upload.rel}`);
      /** @type {any} */ (err).code = 'CHECKSUM_MISMATCH';
      throw err;
    }

    // Re-verificación anti-TOCTOU/symlink antes de mover el temporal al destino final
    const baseDir = this.resolveTargetDir(projectId, options.targetDir || upload.baseDir || null);
    let safe;
    try {
      safe = resolveSafeFilePath(baseDir, upload.rel);
    } catch (e) {
      cleanupTemp();
      throw e;
    }

    let renamed = false;
    const maxAttempts = process.platform === 'win32' ? 5 : 3;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        fs.renameSync(upload.tempPath, safe.abs);
        renamed = true;
        break;
      } catch (err) {
        if (attempt < maxAttempts && err && (err.code === 'EPERM' || err.code === 'EBUSY' || err.code === 'EACCES')) {
          try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 15 * attempt); } catch (e) {}
          continue;
        }
        break;
      }
    }
    if (!renamed) {
      try {
        fs.copyFileSync(upload.tempPath, safe.abs);
      } finally {
        try { if (fs.existsSync(upload.tempPath)) fs.unlinkSync(upload.tempPath); } catch (e) {}
      }
    }
    session.chunkUploads.delete(uploadId);

    /** @type {{ mtimeMs: number, size: number } | null} */
    let postStat = null;
    try {
      const st = fs.statSync(safe.abs);
      postStat = { mtimeMs: st.mtimeMs, size: st.size };
    } catch (e) {}
    deleteSessionFileCache(session, safe.abs);
    putMerkleCache(safe.abs, postStat, actualSha);

    const nowMs = Date.now();
    const appliedAt = new Date(nowMs).toISOString();
    const seq = ++session.lastSeq;
    const classification = classifyChanges([upload.rel]);
    const applyMs = Number((Number(process.hrtime.bigint() - startedNs) / 1e6).toFixed(2));

    session.framesApplied++;
    session.filesWritten++;
    session.bytesSynced += upload.totalBytes;
    session.lastPath = classification.path;
    session.lastReason = classification.reason;
    session.lastAppliedAt = appliedAt;
    session.lastApplyMs = applyMs;
    recordFileTouch(session, upload.rel, {
      clientId: upload.clientId,
      clientName: upload.clientName,
      seq,
      atMs: nowMs,
      at: appliedAt,
      sha256: actualSha,
      op: 'upsert'
    });
    session.recentFrames.unshift({
      seq,
      at: appliedAt,
      appliedAt,
      clientId: upload.clientId,
      clientName: upload.clientName,
      written: 1,
      deleted: 0,
      dedupSkipped: 0,
      bytesWritten: upload.totalBytes,
      applyMs,
      mode: classification.path,
      files: [upload.rel],
      totalFiles: 1,
      chunked: true
    });
    if (session.recentFrames.length > MAX_RECENT_FRAMES) session.recentFrames.pop();

    const result = {
      applied: true,
      chunked: true,
      projectId,
      uploadId,
      seq,
      serverSeq: seq,
      path: upload.rel,
      written: 1,
      deleted: 0,
      dedupSkipped: 0,
      bytesWritten: upload.totalBytes,
      sha256: actualSha,
      changedFiles: [upload.rel],
      conflicts: [],
      mode: classification.path,
      reason: classification.reason,
      triggerFiles: classification.triggerFiles,
      applyMs
    };
    if (!options.deferEmit) {
      this.emitApplied(result);
    }
    return result;
  }

  /** Aborta una carga troceada y elimina su fichero temporal. */
  abortChunkedUpload(projectId, { uploadId }) {
    const session = this.getOrCreateSession(projectId);
    const uid = String(uploadId || '');
    const upload = session.chunkUploads.get(uid);
    if (!upload) return { aborted: false, uploadId: uid };
    session.chunkUploads.delete(uid);
    try { if (upload.tempPath && fs.existsSync(upload.tempPath)) fs.unlinkSync(upload.tempPath); } catch (e) {}
    return { aborted: true, uploadId: uid };
  }

  /**
   * Despachador unificado de mensajes WS de carga troceada (`chunk_start`, `chunk_part`, `chunk_commit`, `chunk_abort`)
   * para conectar con `/ws/sync` en `server/index.js`.
   *
   * @param {string} projectId
   * @param {any} msg
   * @param {{ targetDir?: string | null, clientId?: string | null, clientName?: string | null, deferEmit?: boolean }} [options]
   */
  handleChunkMessage(projectId, msg, options = {}) {
    const type = String(msg && msg.type || '');
    if (type === 'chunk_start') {
      const res = this.startChunkedUpload(projectId, {
        path: msg.path,
        totalBytes: msg.totalBytes,
        sha256: msg.sha256,
        baseSha256: msg.baseSha256 || null,
        clientId: options.clientId || null,
        clientName: options.clientName || null
      }, { targetDir: options.targetDir || null });
      return { type: 'chunk_ack', op: 'start', reqId: msg.reqId || null, ...res };
    }
    if (type === 'chunk_part') {
      const res = this.appendChunk(projectId, {
        uploadId: msg.uploadId,
        index: msg.index,
        data: msg.data,
        encoding: msg.encoding || 'base64'
      });
      return { type: 'chunk_ack', op: 'part', reqId: msg.reqId || null, ...res };
    }
    if (type === 'chunk_commit') {
      const res = this.commitChunkedUpload(projectId, { uploadId: msg.uploadId }, {
        targetDir: options.targetDir || null,
        deferEmit: options.deferEmit
      });
      return { type: 'chunk_ack', op: 'commit', reqId: msg.reqId || null, ...res };
    }
    if (type === 'chunk_abort') {
      const res = this.abortChunkedUpload(projectId, { uploadId: msg.uploadId });
      return { type: 'chunk_ack', op: 'abort', reqId: msg.reqId || null, ...res };
    }
    const err = new Error(`Mensaje de carga troceada no soportado: ${type}`);
    /** @type {any} */ (err).code = 'UNKNOWN_CHUNK_OP';
    throw err;
  }

  /** Limpia el estado en memoria de una sesión (usado por pruebas). */
  resetSession(projectId) {
    const s = this.sessions.get(projectId);
    if (s) this._cleanupChunkUploads(s, false);
    this.sessions.delete(projectId);
    this.targetOverrides.delete(projectId);
  }
}

const liveSyncEngineInstance = Object.assign(new LiveSyncEngine(), {
  LiveSyncEngine,
  resolveSafeFilePath,
  classifyChanges,
  computeMerkleTree,
  diffMerkleTrees,
  sha256,
  sha256FileSync,
  writeFileAtomic,
  decodeCompressedPayload,
  decodeBinarySyncFrame,
  FRAME_MAGIC_RAW,
  FRAME_MAGIC_BROTLI,
  FRAME_MAGIC_GZIP,
  MAX_FILE_BYTES,
  MAX_CHUNKED_FILE_BYTES,
  MAX_CHUNK_BYTES,
  MAX_DECOMPRESSED_FRAME_BYTES,
  MAX_FRAME_META_BYTES
});
module.exports = liveSyncEngineInstance;
