const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

/**
 * Culkibo Portable Stack Bundle Archiver (`.zip` & `.ckb.gz`) — Zero External Dependencies.
 *
 * Permite exportar e importar un stack completo de Culkibo (proyectos, `culkibo.yaml`,
 * dominios/Caddy edge, bases de datos, crons, configuración MCP para agentes de IA y
 * sobre cifrado AES-256-GCM del Vault) como un único archivo portátil `.zip` o `.ckb.gz`.
 *
 * Garantías de seguridad:
 *  - Cero dependencias npm externas (únicamente `zlib`, `crypto`, `fs`, `path`).
 *  - Cero construcción o ejecución de shell.
 *  - Escritor y lector PKZIP 2.0 en JS puro con verificación CRC32 IEEE 802.3 estricta.
 *  - Protección anti-path-traversal (`..`, rutas absolutas, unidades Windows, NUL, symlinks).
 *  - Protección anti-zip-bomb (límites de entradas, tamaño por archivo, tamaño total,
 *    ratio de compresión y `maxOutputLength` nativo en `zlib`).
 *  - Coherencia estricta entre Local File Header y Central Directory (anti-polyglot).
 *  - Cifrado de secretos del Vault con AES-256-GCM + scrypt (N=16384, r=8, p=1) y AAD;
 *    sin contraseña jamás se escriben secretos en claro (modo redactado por defecto).
 */

const BUNDLE_FORMAT_VERSION = 1;
const CULKIBO_VERSION = '1.1.0';

// PKZIP signatures
const SIG_LOCAL_FILE_HEADER = 0x04034b50;
const SIG_CENTRAL_DIR_HEADER = 0x02014b50;
const SIG_END_OF_CENTRAL_DIR = 0x06054b50;

const ZIP_METHOD_STORE = 0;
const ZIP_METHOD_DEFLATE = 8;
const ZIP_FLAG_UTF8 = 0x0800;
const ZIP_FLAG_ENCRYPTED = 0x0001;
const ZIP_FLAG_DATA_DESCRIPTOR = 0x0008;

// Default security limits (anti-zip-bomb / DoS)
const DEFAULT_MAX_ARCHIVE_BYTES = 25 * 1024 * 1024;          // 25 MB compressed input
const DEFAULT_MAX_ENTRIES = 200;                             // max files in archive
const DEFAULT_MAX_SINGLE_FILE_BYTES = 10 * 1024 * 1024;      // 10 MB per extracted file
const DEFAULT_MAX_TOTAL_UNCOMPRESSED_BYTES = 50 * 1024 * 1024; // 50 MB total uncompressed
const DEFAULT_MAX_COMPRESSION_RATIO = 100;                   // max 100:1 expansion ratio
const RATIO_CHECK_MIN_BYTES = 64 * 1024;                     // enforce ratio check above 64 KB

const SAFE_ENTRY_PATH_RE = /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/;
const SENSITIVE_KEY_RE = /(secret|token|pass(word|wd|phrase)?|apikey|api_key|private|auth|cred(ential)?|jwt|cookie|session|cert|pem|dsn|database_url|db_url|redis_url|mongo_url|smtp|webhook|stripe|openai|anthropic|gemini|aws_|s3_|r2_|encryption|signing|master)/i;
const FORBIDDEN_PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// ============================================================================
// PURE-JS IEEE 802.3 CRC32
// ============================================================================

const CRC32_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let k = 0; k < 8; k++) {
    c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
  }
  CRC32_TABLE[i] = c >>> 0;
}

/**
 * Calcula CRC32 IEEE 802.3 sin signo (compatible con PKZIP).
 * @param {Buffer | Uint8Array} buf
 * @returns {number}
 */
function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = CRC32_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Calcula SHA-256 hexadecimal de un Buffer o cadena UTF-8.
 * @param {Buffer | string} input
 * @returns {string}
 */
function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

// ============================================================================
// PATH VALIDATION (ANTI-TRAVERSAL / ANTI-SYMLINK)
// ============================================================================

/**
 * Valida y normaliza una ruta relativa dentro del archivo ZIP.
 * Rechaza traversal (`..`), rutas absolutas, unidades Windows, backslashes, NUL y control chars.
 * @param {string} rawName
 * @returns {string}
 */
function validateArchiveEntryPath(rawName) {
  if (typeof rawName !== 'string' || rawName.length === 0) {
    throw new Error('Ruta de archivo vacía en el bundle');
  }
  if (rawName.length > 240) {
    throw new Error(`Ruta demasiado larga en el bundle: "${rawName.slice(0, 60)}"`);
  }
  if (/[\x00-\x1f\x7f]/.test(rawName)) {
    throw new Error('Caracteres de control o byte nulo rechazados en ruta del bundle');
  }
  if (rawName.includes('\\')) {
    throw new Error(`Separador "\\" no permitido en ruta del bundle (posible traversal): "${rawName.slice(0, 80)}"`);
  }
  if (rawName.startsWith('/') || /^[A-Za-z]:/.test(rawName)) {
    throw new Error(`Ruta absoluta rechazada en el bundle: "${rawName.slice(0, 80)}"`);
  }
  const clean = rawName.replace(/\/+$/, '');
  if (!clean) {
    throw new Error('Ruta raíz vacía rechazada en el bundle');
  }
  const segments = clean.split('/');
  for (const seg of segments) {
    if (!seg || seg === '.' || seg === '..') {
      throw new Error(`Path traversal rechazado en el bundle: "${rawName.slice(0, 80)}"`);
    }
    if (FORBIDDEN_PROTO_KEYS.has(seg)) {
      throw new Error(`Segmento reservado rechazado en el bundle: "${seg}"`);
    }
  }
  if (!SAFE_ENTRY_PATH_RE.test(clean)) {
    throw new Error(`Caracteres no permitidos en ruta del bundle: "${rawName.slice(0, 80)}"`);
  }
  return clean;
}

/**
 * Convierte un Date a par `(dosTime, dosDate)` para cabeceras PKZIP.
 * @param {Date} date
 * @returns {{ dosTime: number, dosDate: number }}
 */
function toDosDateTime(date) {
  const year = Math.max(1980, Math.min(2107, date.getUTCFullYear()));
  const month = date.getUTCMonth() + 1;
  const day = date.getUTCDate();
  const hours = date.getUTCHours();
  const minutes = date.getUTCMinutes();
  const seconds = Math.floor(date.getUTCSeconds() / 2);
  const dosTime = ((hours & 0x1f) << 11) | ((minutes & 0x3f) << 5) | (seconds & 0x1f);
  const dosDate = (((year - 1980) & 0x7f) << 9) | ((month & 0x0f) << 5) | (day & 0x1f);
  return { dosTime, dosDate };
}

// ============================================================================
// PURE-JS PKZIP 2.0 WRITER & HARDENED READER
// ============================================================================

/**
 * Crea un archivo `.zip` estándar (PKZIP 2.0, DEFLATE/STORE, CRC32, UTF-8) en memoria.
 *
 * @param {Record<string, Buffer | string> | Array<{ name: string, data: Buffer | string, compress?: boolean }>} entriesInput
 * @param {{ timestamp?: Date, level?: number, comment?: string }} [opts]
 * @returns {Buffer}
 */
function createZipBuffer(entriesInput, opts = {}) {
  /** @type {Array<{ name: string, data: Buffer, compress: boolean }>} */
  const normalizedEntries = [];
  const seenNames = new Set();

  if (Array.isArray(entriesInput)) {
    for (const item of entriesInput) {
      if (!item || typeof item !== 'object') continue;
      const safeName = validateArchiveEntryPath(String(item.name || ''));
      if (seenNames.has(safeName)) {
        throw new Error(`Entrada duplicada en el archivo ZIP: "${safeName}"`);
      }
      seenNames.add(safeName);
      const buf = Buffer.isBuffer(item.data) ? item.data : Buffer.from(String(item.data ?? ''), 'utf8');
      normalizedEntries.push({ name: safeName, data: buf, compress: item.compress !== false });
    }
  } else if (entriesInput && typeof entriesInput === 'object') {
    for (const key of Object.keys(entriesInput).sort()) {
      const safeName = validateArchiveEntryPath(key);
      if (seenNames.has(safeName)) {
        throw new Error(`Entrada duplicada en el archivo ZIP: "${safeName}"`);
      }
      seenNames.add(safeName);
      const val = entriesInput[key];
      const buf = Buffer.isBuffer(val) ? val : Buffer.from(String(val ?? ''), 'utf8');
      normalizedEntries.push({ name: safeName, data: buf, compress: true });
    }
  } else {
    throw new Error('entriesInput debe ser un mapa o lista de archivos');
  }

  if (normalizedEntries.length > DEFAULT_MAX_ENTRIES) {
    throw new Error(`Demasiadas entradas para el archivo ZIP (máx. ${DEFAULT_MAX_ENTRIES})`);
  }

  const level = Math.min(9, Math.max(0, Number.isFinite(Number(opts.level)) ? Number(opts.level) : 6));
  const { dosTime, dosDate } = toDosDateTime(opts.timestamp instanceof Date ? opts.timestamp : new Date());
  const commentBuf = Buffer.from(String(opts.comment || 'Culkibo Portable Stack Bundle v1').slice(0, 255), 'utf8');

  /** @type {Buffer[]} */
  const localParts = [];
  /** @type {Buffer[]} */
  const centralParts = [];
  let offset = 0;

  for (const entry of normalizedEntries) {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    const rawBuf = entry.data;
    const checksum = crc32(rawBuf);

    let method = ZIP_METHOD_STORE;
    let payloadBuf = rawBuf;

    if (entry.compress && level > 0 && rawBuf.length > 0) {
      const deflated = zlib.deflateRawSync(rawBuf, { level });
      if (deflated.length < rawBuf.length) {
        method = ZIP_METHOD_DEFLATE;
        payloadBuf = deflated;
      }
    }

    // Local File Header (30 bytes + filename)
    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(SIG_LOCAL_FILE_HEADER, 0);
    lfh.writeUInt16LE(20, 4);                // version needed to extract (2.0)
    lfh.writeUInt16LE(ZIP_FLAG_UTF8, 6);     // general purpose bit flag (UTF-8)
    lfh.writeUInt16LE(method, 8);            // compression method
    lfh.writeUInt16LE(dosTime, 10);
    lfh.writeUInt16LE(dosDate, 12);
    lfh.writeUInt32LE(checksum, 14);
    lfh.writeUInt32LE(payloadBuf.length >>> 0, 18);
    lfh.writeUInt32LE(rawBuf.length >>> 0, 22);
    lfh.writeUInt16LE(nameBuf.length, 26);
    lfh.writeUInt16LE(0, 28);                // extra field length

    localParts.push(lfh, nameBuf, payloadBuf);

    // Central Directory File Header (46 bytes + filename)
    const cdh = Buffer.alloc(46);
    cdh.writeUInt32LE(SIG_CENTRAL_DIR_HEADER, 0);
    cdh.writeUInt16LE((3 << 8) | 20, 4);     // version made by (Unix, 2.0)
    cdh.writeUInt16LE(20, 6);                // version needed
    cdh.writeUInt16LE(ZIP_FLAG_UTF8, 8);     // UTF-8 flag
    cdh.writeUInt16LE(method, 10);
    cdh.writeUInt16LE(dosTime, 12);
    cdh.writeUInt16LE(dosDate, 14);
    cdh.writeUInt32LE(checksum, 16);
    cdh.writeUInt32LE(payloadBuf.length >>> 0, 20);
    cdh.writeUInt32LE(rawBuf.length >>> 0, 24);
    cdh.writeUInt16LE(nameBuf.length, 28);
    cdh.writeUInt16LE(0, 30);                // extra length
    cdh.writeUInt16LE(0, 32);                // file comment length
    cdh.writeUInt16LE(0, 34);                // disk number start
    cdh.writeUInt16LE(0, 36);                // internal file attributes
    cdh.writeUInt32LE((0o100644 << 16) >>> 0, 38); // regular file 0644
    cdh.writeUInt32LE(offset >>> 0, 42);     // relative offset of local header

    centralParts.push(cdh, nameBuf);
    offset += 30 + nameBuf.length + payloadBuf.length;
  }

  const centralDirBuf = Buffer.concat(centralParts);

  // End of Central Directory Record (22 bytes + comment)
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(SIG_END_OF_CENTRAL_DIR, 0);
  eocd.writeUInt16LE(0, 4);                  // disk number
  eocd.writeUInt16LE(0, 6);                  // start disk
  eocd.writeUInt16LE(normalizedEntries.length, 8);
  eocd.writeUInt16LE(normalizedEntries.length, 10);
  eocd.writeUInt32LE(centralDirBuf.length >>> 0, 12);
  eocd.writeUInt32LE(offset >>> 0, 16);
  eocd.writeUInt16LE(commentBuf.length, 20);

  return Buffer.concat([...localParts, centralDirBuf, eocd, commentBuf]);
}

/**
 * Lee y verifica un buffer `.zip` con defensas completas contra zip-bomb,
 * path-traversal, symlinks, corrupción CRC32 y ataques polyglot LFH/CDH.
 *
 * @param {Buffer} zipBuf
 * @param {{
 *   maxArchiveBytes?: number,
 *   maxEntries?: number,
 *   maxSingleFileBytes?: number,
 *   maxTotalUncompressedBytes?: number,
 *   maxCompressionRatio?: number
 * }} [opts]
 * @returns {{ files: Record<string, Buffer>, entries: Array<{ name: string, method: number, compressedSize: number, uncompressedSize: number, crc32: number }>, comment: string }}
 */
function parseZipBuffer(zipBuf, opts = {}) {
  if (!Buffer.isBuffer(zipBuf)) {
    throw new Error('Se esperaba un Buffer válido para parsear el archivo ZIP');
  }
  const maxArchiveBytes = opts.maxArchiveBytes || DEFAULT_MAX_ARCHIVE_BYTES;
  const maxEntries = opts.maxEntries || DEFAULT_MAX_ENTRIES;
  const maxSingleFileBytes = opts.maxSingleFileBytes || DEFAULT_MAX_SINGLE_FILE_BYTES;
  const maxTotalBytes = opts.maxTotalUncompressedBytes || DEFAULT_MAX_TOTAL_UNCOMPRESSED_BYTES;
  const maxRatio = opts.maxCompressionRatio || DEFAULT_MAX_COMPRESSION_RATIO;

  if (zipBuf.length < 22) {
    throw new Error('Archivo ZIP truncado o inválido (menor de 22 bytes)');
  }
  if (zipBuf.length > maxArchiveBytes) {
    throw new Error(`El archivo ZIP supera el tamaño máximo permitido (${Math.round(maxArchiveBytes / (1024 * 1024))} MB)`);
  }

  // Locate EOCD scanning backwards (max 65535 comment + 22 fixed bytes)
  const minEocdPos = Math.max(0, zipBuf.length - 22 - 65535);
  let eocdOffset = -1;
  for (let pos = zipBuf.length - 22; pos >= minEocdPos; pos--) {
    if (zipBuf.readUInt32LE(pos) === SIG_END_OF_CENTRAL_DIR) {
      const commentLen = zipBuf.readUInt16LE(pos + 20);
      if (pos + 22 + commentLen === zipBuf.length) {
        eocdOffset = pos;
        break;
      }
    }
  }
  if (eocdOffset === -1) {
    throw new Error('Archivo ZIP inválido: no se encontró End of Central Directory (EOCD)');
  }

  const diskNum = zipBuf.readUInt16LE(eocdOffset + 4);
  const cdStartDisk = zipBuf.readUInt16LE(eocdOffset + 6);
  const entriesOnDisk = zipBuf.readUInt16LE(eocdOffset + 8);
  const totalEntries = zipBuf.readUInt16LE(eocdOffset + 10);
  const cdSize = zipBuf.readUInt32LE(eocdOffset + 12);
  const cdOffset = zipBuf.readUInt32LE(eocdOffset + 16);
  const commentLen = zipBuf.readUInt16LE(eocdOffset + 20);
  const comment = zipBuf.subarray(eocdOffset + 22, eocdOffset + 22 + commentLen).toString('utf8');

  if (diskNum !== 0 || cdStartDisk !== 0 || entriesOnDisk !== totalEntries) {
    throw new Error('Archivos ZIP multi-disco no están soportados');
  }
  if (totalEntries === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    throw new Error('ZIP64 excede los límites de tamaño seguros permitidos para bundles');
  }
  if (totalEntries > maxEntries) {
    throw new Error(`Zip-bomb bloqueado: demasiadas entradas en el ZIP (${totalEntries} > ${maxEntries})`);
  }
  if (cdOffset + cdSize > eocdOffset) {
    throw new Error('Cabecera Central Directory corrupta o fuera de rango');
  }

  /** @type {Record<string, Buffer>} */
  const files = Object.create(null);
  /** @type {Array<{ name: string, method: number, compressedSize: number, uncompressedSize: number, crc32: number }>} */
  const entries = [];
  let totalUncompressed = 0;
  let cursor = cdOffset;
  const cdEnd = cdOffset + cdSize;

  for (let i = 0; i < totalEntries; i++) {
    if (cursor + 46 > cdEnd) {
      throw new Error('Entrada Central Directory truncada');
    }
    if (zipBuf.readUInt32LE(cursor) !== SIG_CENTRAL_DIR_HEADER) {
      throw new Error('Firma Central Directory inválida');
    }

    const versionMadeBy = zipBuf.readUInt16LE(cursor + 4);
    const flags = zipBuf.readUInt16LE(cursor + 8);
    const method = zipBuf.readUInt16LE(cursor + 10);
    const expectedCrc = zipBuf.readUInt32LE(cursor + 16);
    const compSize = zipBuf.readUInt32LE(cursor + 20);
    const uncompSize = zipBuf.readUInt32LE(cursor + 24);
    const nameLen = zipBuf.readUInt16LE(cursor + 28);
    const extraLen = zipBuf.readUInt16LE(cursor + 30);
    const entryCommentLen = zipBuf.readUInt16LE(cursor + 32);
    const extAttrs = zipBuf.readUInt32LE(cursor + 38);
    const lfhOffset = zipBuf.readUInt32LE(cursor + 42);

    const recordEnd = cursor + 46 + nameLen + extraLen + entryCommentLen;
    if (recordEnd > cdEnd) {
      throw new Error('Metadatos de entrada ZIP truncados');
    }

    if ((flags & ZIP_FLAG_ENCRYPTED) !== 0) {
      throw new Error('El cifrado PKZIP clásico no está permitido; usa el sobre AES-256-GCM de Culkibo');
    }

    const rawName = zipBuf.subarray(cursor + 46, cursor + 46 + nameLen).toString('utf8');
    cursor = recordEnd;

    // Bloquear enlaces simbólicos Unix (S_IFLNK = 0o120000)
    const creatorOs = (versionMadeBy >>> 8) & 0xff;
    const unixMode = (extAttrs >>> 16) & 0o170000;
    if (creatorOs === 3 && unixMode === 0o120000) {
      throw new Error(`Enlace simbólico rechazado en archivo ZIP: "${rawName.slice(0, 80)}"`);
    }

    // Saltar directorios explícitos pero validando su ruta contra traversal
    if (rawName.endsWith('/')) {
      validateArchiveEntryPath(rawName);
      continue;
    }

    const safeName = validateArchiveEntryPath(rawName);
    if (Object.prototype.hasOwnProperty.call(files, safeName)) {
      throw new Error(`Archivo duplicado en ZIP rechazado: "${safeName}"`);
    }

    if (method !== ZIP_METHOD_STORE && method !== ZIP_METHOD_DEFLATE) {
      throw new Error(`Método de compresión ZIP no soportado (${method}) en "${safeName}"`);
    }

    // Comprobar límites anti-zip-bomb declarados ANTES de descomprimir
    if (uncompSize > maxSingleFileBytes) {
      throw new Error(`Zip-bomb bloqueado: "${safeName}" declara ${uncompSize} bytes (máx. ${maxSingleFileBytes})`);
    }
    if (totalUncompressed + uncompSize > maxTotalBytes) {
      throw new Error(`Zip-bomb bloqueado: tamaño descomprimido acumulado supera ${maxTotalBytes} bytes`);
    }
    if (uncompSize >= RATIO_CHECK_MIN_BYTES && compSize > 0 && (uncompSize / compSize) > maxRatio) {
      throw new Error(`Zip-bomb bloqueado: ratio de compresión anómalo (${Math.round(uncompSize / compSize)}:1 > ${maxRatio}:1) en "${safeName}"`);
    }

    // Validar Local File Header (coherencia LFH vs CDH anti-polyglot)
    if (lfhOffset + 30 > cdOffset) {
      throw new Error(`Local File Header fuera de rango para "${safeName}"`);
    }
    if (zipBuf.readUInt32LE(lfhOffset) !== SIG_LOCAL_FILE_HEADER) {
      throw new Error(`Firma Local File Header inválida para "${safeName}"`);
    }
    const lfhFlags = zipBuf.readUInt16LE(lfhOffset + 6);
    const lfhMethod = zipBuf.readUInt16LE(lfhOffset + 8);
    const lfhCrc = zipBuf.readUInt32LE(lfhOffset + 14);
    const lfhCompSize = zipBuf.readUInt32LE(lfhOffset + 18);
    const lfhUncompSize = zipBuf.readUInt32LE(lfhOffset + 22);
    const lfhNameLen = zipBuf.readUInt16LE(lfhOffset + 26);
    const lfhExtraLen = zipBuf.readUInt16LE(lfhOffset + 28);

    const dataStart = lfhOffset + 30 + lfhNameLen + lfhExtraLen;
    if (dataStart > cdOffset) {
      throw new Error(`Cabecera LFH truncada para "${safeName}"`);
    }
    const lfhName = zipBuf.subarray(lfhOffset + 30, lfhOffset + 30 + lfhNameLen).toString('utf8');
    if (lfhName !== rawName) {
      throw new Error(`Discrepancia LFH/CDH de nombre detectada (posible ZIP polyglot): "${safeName}"`);
    }
    if (lfhMethod !== method) {
      throw new Error(`Discrepancia LFH/CDH de método en "${safeName}"`);
    }
    if ((lfhFlags & ZIP_FLAG_DATA_DESCRIPTOR) === 0) {
      if (lfhCompSize !== compSize || lfhUncompSize !== uncompSize || lfhCrc !== expectedCrc) {
        throw new Error(`Discrepancia LFH/CDH de tamaño o CRC32 en "${safeName}"`);
      }
    }

    const dataEnd = dataStart + compSize;
    if (dataEnd > cdOffset) {
      throw new Error(`Datos comprimidos fuera de rango para "${safeName}"`);
    }

    const compressedSlice = zipBuf.subarray(dataStart, dataEnd);
    /** @type {Buffer} */
    let extracted;
    if (method === ZIP_METHOD_STORE) {
      if (compressedSlice.length !== uncompSize) {
        throw new Error(`Tamaño inconsistente en entrada STORE "${safeName}"`);
      }
      extracted = Buffer.from(compressedSlice);
    } else {
      const remainingBudget = Math.min(maxSingleFileBytes, maxTotalBytes - totalUncompressed);
      try {
        extracted = zlib.inflateRawSync(compressedSlice, { maxOutputLength: remainingBudget });
      } catch (err) {
        const msg = String(err && err.message || '');
        if (/maxOutputLength|length|buffer/i.test(msg)) {
          throw new Error(`Zip-bomb bloqueado al descomprimir "${safeName}" (excedió límite de memoria de ${remainingBudget} bytes)`);
        }
        throw new Error(`Error descomprimiendo "${safeName}": ${msg}`);
      }
      if (extracted.length > maxSingleFileBytes) {
        throw new Error(`Zip-bomb bloqueado: "${safeName}" expandió a ${extracted.length} bytes`);
      }
      if (extracted.length >= RATIO_CHECK_MIN_BYTES && compressedSlice.length > 0 && (extracted.length / compressedSlice.length) > maxRatio) {
        throw new Error(`Zip-bomb bloqueado: expansión real ${Math.round(extracted.length / compressedSlice.length)}:1 supera el límite (${maxRatio}:1) en "${safeName}"`);
      }
      if (extracted.length !== uncompSize) {
        throw new Error(`Tamaño real descomprimido no coincide con la cabecera en "${safeName}" (${extracted.length} != ${uncompSize})`);
      }
    }

    const actualCrc = crc32(extracted);
    if (actualCrc !== expectedCrc) {
      throw new Error(`Error de integridad CRC32 en "${safeName}" (esperado 0x${expectedCrc.toString(16)}, obtenido 0x${actualCrc.toString(16)})`);
    }

    totalUncompressed += extracted.length;
    if (totalUncompressed > maxTotalBytes) {
      throw new Error(`Zip-bomb bloqueado: tamaño total descomprimido excede ${maxTotalBytes} bytes`);
    }

    files[safeName] = extracted;
    entries.push({
      name: safeName,
      method,
      compressedSize: compSize,
      uncompressedSize: extracted.length,
      crc32: actualCrc
    });
  }

  return { files, entries, comment };
}

// ============================================================================
// GZIP BUNDLE FORMAT (.ckb.gz)
// ============================================================================

/**
 * Serializa un objeto de bundle en formato `.ckb.gz`.
 * @param {Record<string, any>} bundlePayload
 * @returns {Buffer}
 */
function createCkbGzBuffer(bundlePayload) {
  const json = JSON.stringify({
    format: 'culkibo-bundle/v1',
    ...bundlePayload
  });
  return zlib.gzipSync(Buffer.from(json, 'utf8'), { level: 6 });
}

/**
 * Lee un buffer `.ckb.gz` con límite anti-gzip-bomb (`maxOutputLength`).
 * @param {Buffer} gzBuf
 * @param {{ maxArchiveBytes?: number, maxTotalUncompressedBytes?: number, maxCompressionRatio?: number }} [opts]
 * @returns {Record<string, any>}
 */
function parseCkbGzBuffer(gzBuf, opts = {}) {
  if (!Buffer.isBuffer(gzBuf)) {
    throw new Error('Se esperaba un Buffer válido para .ckb.gz');
  }
  const maxArchiveBytes = opts.maxArchiveBytes || DEFAULT_MAX_ARCHIVE_BYTES;
  const maxTotalBytes = opts.maxTotalUncompressedBytes || DEFAULT_MAX_TOTAL_UNCOMPRESSED_BYTES;
  const maxRatio = opts.maxCompressionRatio || DEFAULT_MAX_COMPRESSION_RATIO;

  if (gzBuf.length < 18 || gzBuf[0] !== 0x1f || gzBuf[1] !== 0x8b) {
    throw new Error('Archivo .ckb.gz inválido (firma GZIP ausente)');
  }
  if (gzBuf.length > maxArchiveBytes) {
    throw new Error(`El archivo .ckb.gz supera el tamaño máximo (${Math.round(maxArchiveBytes / (1024 * 1024))} MB)`);
  }

  /** @type {Buffer} */
  let raw;
  try {
    raw = zlib.gunzipSync(gzBuf, { maxOutputLength: maxTotalBytes });
  } catch (err) {
    const msg = String(err && err.message || '');
    if (/maxOutputLength|length|buffer/i.test(msg)) {
      throw new Error(`Gzip-bomb bloqueado: el contenido descomprimido supera ${maxTotalBytes} bytes`);
    }
    throw new Error(`Error descomprimiendo .ckb.gz: ${msg}`);
  }

  if (raw.length >= RATIO_CHECK_MIN_BYTES && (raw.length / gzBuf.length) > maxRatio) {
    throw new Error(`Gzip-bomb bloqueado: ratio de expansión ${Math.round(raw.length / gzBuf.length)}:1 supera el límite (${maxRatio}:1)`);
  }

  const parsed = JSON.parse(raw.toString('utf8'));
  if (!parsed || typeof parsed !== 'object' || parsed.format !== 'culkibo-bundle/v1') {
    throw new Error('Formato .ckb.gz no reconocido (se esperaba culkibo-bundle/v1)');
  }
  return parsed;
}

// ============================================================================
// ENCRYPTED VAULT ENVELOPE (AES-256-GCM + SCRYPT + AAD)
// ============================================================================

/**
 * Cifra un mapa de secretos en un sobre portátil AES-256-GCM + scrypt con AAD.
 * @param {Record<string, string>} secretsMap
 * @param {string} passphrase
 * @param {string} bundleId
 */
function encryptVaultEnvelope(secretsMap, passphrase, bundleId) {
  const pwd = String(passphrase || '');
  if (pwd.length < 8) {
    throw new Error('La contraseña del Vault portátil debe tener al menos 8 caracteres');
  }
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const aad = `culkibo-bundle-vault:v1:${bundleId}`;
  const key = crypto.scryptSync(pwd, salt, 32, { N: 16384, r: 8, p: 1 });
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const plain = Buffer.from(JSON.stringify({ secrets: secretsMap }), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();

  /** @type {Record<string, string>} */
  const fingerprints = {};
  for (const [k, v] of Object.entries(secretsMap)) {
    fingerprints[k] = `sha256:${sha256Hex(`${bundleId}:${k}:${v}`).slice(0, 16)}`;
  }

  return {
    version: 1,
    encrypted: true,
    kdf: 'scrypt',
    kdfParams: { N: 16384, r: 8, p: 1 },
    cipher: 'aes-256-gcm',
    bundleId,
    keyCount: Object.keys(secretsMap).length,
    keys: Object.keys(secretsMap).sort(),
    fingerprints,
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64')
  };
}

/**
 * Descifra un sobre portátil `vault.enc.json` validando AAD y AuthTag AES-256-GCM.
 * @param {Record<string, any>} envelope
 * @param {string} passphrase
 * @returns {Record<string, string>}
 */
function decryptVaultEnvelope(envelope, passphrase) {
  const pwd = String(passphrase || '');
  if (!pwd) {
    throw new Error('Este bundle contiene un Vault cifrado; proporciona la contraseña (passphrase)');
  }
  if (!envelope || envelope.encrypted !== true || envelope.cipher !== 'aes-256-gcm') {
    throw new Error('Sobre vault.enc.json inválido o formato no soportado');
  }
  const bundleId = String(envelope.bundleId || '');
  const salt = Buffer.from(String(envelope.salt || ''), 'base64');
  const iv = Buffer.from(String(envelope.iv || ''), 'base64');
  const tag = Buffer.from(String(envelope.tag || ''), 'base64');
  const ciphertext = Buffer.from(String(envelope.ciphertext || ''), 'base64');
  if (!bundleId || salt.length < 16 || iv.length !== 12 || tag.length !== 16) {
    throw new Error('Metadatos criptográficos inválidos en vault.enc.json');
  }
  try {
    const key = crypto.scryptSync(pwd, salt, 32, { N: 16384, r: 8, p: 1 });
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
    decipher.setAAD(Buffer.from(`culkibo-bundle-vault:v1:${bundleId}`, 'utf8'));
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    const parsed = JSON.parse(plain);
    if (!parsed || typeof parsed.secrets !== 'object' || Array.isArray(parsed.secrets)) {
      throw new Error('Payload de secretos inválido');
    }
    /** @type {Record<string, string>} */
    const out = {};
    for (const [k, v] of Object.entries(parsed.secrets)) {
      if (!FORBIDDEN_PROTO_KEYS.has(k)) out[k] = String(v ?? '');
    }
    return out;
  } catch (err) {
    throw new Error('Contraseña incorrecta o vault.enc.json manipulado/corrupto');
  }
}

// ============================================================================
// SAFE YAML + MCP AGENT CONFIG + SANITIZATION HELPERS
// ============================================================================

/**
 * Determina si una variable de entorno debe tratarse como secreto.
 * @param {string} key
 * @param {string} val
 */
function isSecretEnvPair(key, val) {
  const v = String(val ?? '');
  if (/^\$\{vault\.[A-Za-z_][A-Za-z0-9_]{0,127}\}$/.test(v.trim())) return false;
  if (SENSITIVE_KEY_RE.test(key)) return true;
  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(v)) return true;
  if (/(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp):\/\/[^:\s/@]+:[^@\s/]+@/i.test(v)) return true;
  if (/\b(?:gh[pousr]_[A-Za-z0-9_]{12,}|sk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{12,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/.test(v)) return true;
  return false;
}

/**
 * Serializador YAML determinista y seguro para `culkibo.yaml` v1 dentro del bundle.
 * @param {any} val
 * @param {number} indent
 * @returns {string}
 */
function serializeYaml(val, indent = 0) {
  const pad = ' '.repeat(indent);
  if (val === null || val === undefined) return 'null';
  if (typeof val === 'boolean' || typeof val === 'number') return String(val);
  if (typeof val === 'string') {
    if (val === '' || /[:#\[\]{}&*!|>'"%@`\r\n\t]/.test(val) || /^\s|\s$/.test(val) || /^(true|false|null|~|-?\d+(\.\d+)?)$/i.test(val)) {
      return JSON.stringify(val);
    }
    return val;
  }
  if (Array.isArray(val)) {
    if (val.length === 0) return '[]';
    return val.map((item) => {
      if (item !== null && typeof item === 'object' && !Array.isArray(item)) {
        const entries = Object.entries(item).filter(([, v]) => v !== undefined);
        if (entries.length === 0) return `${pad}- {}`;
        const [firstK, firstV] = entries[0];
        const firstLine = (firstV !== null && typeof firstV === 'object' && (!Array.isArray(firstV) || firstV.length > 0))
          ? `${pad}- ${firstK}:\n${serializeYaml(firstV, indent + 4)}`
          : `${pad}- ${firstK}: ${serializeYaml(firstV, indent + 4)}`;
        const rest = entries.slice(1).map(([k, v]) => {
          if (v !== null && typeof v === 'object' && (!Array.isArray(v) || v.length > 0)) {
            return `${pad}  ${k}:\n${serializeYaml(v, indent + 4)}`;
          }
          return `${pad}  ${k}: ${serializeYaml(v, indent + 4)}`;
        });
        return [firstLine, ...rest].join('\n');
      }
      return `${pad}- ${serializeYaml(item, indent + 2)}`;
    }).join('\n');
  }
  const entries = Object.entries(val).filter(([, v]) => v !== undefined);
  if (entries.length === 0) return '{}';
  return entries.map(([k, v]) => {
    const safeKey = /^[A-Za-z0-9_.-]+$/.test(k) ? k : JSON.stringify(k);
    if (v !== null && typeof v === 'object' && (!Array.isArray(v) || v.length > 0)) {
      return `${pad}${safeKey}:\n${serializeYaml(v, indent + 2)}`;
    }
    return `${pad}${safeKey}: ${serializeYaml(v, indent + 2)}`;
  }).join('\n');
}

/**
 * Construye una configuración MCP drop-in lista para agentes de IA (nunca incluye tokens reales).
 * @param {string} stackName
 * @param {string} [panelUrl]
 */
function buildAgentMcpConfig(stackName, panelUrl = 'http://localhost:3030') {
  const cleanUrl = String(panelUrl || 'http://localhost:3030').replace(/\/+$/, '');
  const mcpEndpoint = `${cleanUrl}/mcp?profile=core`;
  return {
    schemaVersion: 1,
    stackName,
    profile: 'core',
    tokenPlaceholder: '${CULKIBO_TOKEN}',
    note: 'Never commit real API tokens. Set CULKIBO_TOKEN in your local shell or secret manager.',
    clients: {
      claudeCode: {
        file: '.mcp.json',
        config: {
          mcpServers: {
            culkibo: {
              type: 'http',
              url: mcpEndpoint,
              headers: { Authorization: 'Bearer ${CULKIBO_TOKEN}' }
            }
          }
        }
      },
      cursor: {
        file: '.cursor/mcp.json',
        config: {
          mcpServers: {
            culkibo: {
              url: mcpEndpoint,
              headers: { Authorization: 'Bearer ${CULKIBO_TOKEN}' }
            }
          }
        }
      },
      antigravity: {
        file: 'mcp_config.json',
        config: {
          mcpServers: {
            culkibo: {
              serverUrl: mcpEndpoint,
              headers: { Authorization: 'Bearer ${CULKIBO_TOKEN}' }
            }
          }
        }
      },
      stdioCli: {
        command: 'culkibo',
        args: ['mcp'],
        env: {
          CULKIBO_MCP_PROFILE: 'core',
          CULKIBO_API_URL: cleanUrl,
          CULKIBO_TOKEN: '${CULKIBO_TOKEN}'
        }
      }
    }
  };
}

/**
 * Sanitiza proyectos separando secretos hacia el Vault y reemplazando valores
 * sensibles por `${vault.KEY}` para que `projects.json` y `culkibo.yaml` sean 100% seguros.
 *
 * @param {any[]} rawProjects
 * @param {Record<string, string>} secretCollector
 */
function sanitizeProjectsForBundle(rawProjects, secretCollector) {
  /** @type {Set<string>} */
  const vaultRefs = new Set();
  const sanitized = (Array.isArray(rawProjects) ? rawProjects : []).map((proj) => {
    const slug = String(proj.id || proj.name || 'app')
      .toUpperCase()
      .replace(/[^A-Z0-9]+/g, '_')
      .replace(/^_+|_+$/g, '')
      .slice(0, 32) || 'APP';

    /** @type {Record<string, string>} */
    const cleanEnv = {};
    const rawEnv = proj.envVars && typeof proj.envVars === 'object' ? proj.envVars : {};
    for (const [k, v] of Object.entries(rawEnv)) {
      if (FORBIDDEN_PROTO_KEYS.has(k)) continue;
      const valStr = String(v ?? '');
      const vaultMatches = valStr.matchAll(/\$\{vault\.([A-Za-z_][A-Za-z0-9_]{0,127})\}/g);
      let hasExplicitRef = false;
      for (const m of vaultMatches) {
        vaultRefs.add(m[1]);
        hasExplicitRef = true;
      }
      if (!hasExplicitRef && isSecretEnvPair(k, valStr) && valStr.length > 0) {
        const vaultKey = `${slug}_${k}`.replace(/[^A-Za-z0-9_]/g, '_').slice(0, 120);
        vaultRefs.add(vaultKey);
        secretCollector[vaultKey] = valStr;
        cleanEnv[k] = `\${vault.${vaultKey}}`;
      } else {
        cleanEnv[k] = valStr;
      }
    }

    const resources = Array.isArray(proj.resources)
      ? proj.resources.map((r) => {
          const copy = { ...r };
          if (copy.credentials && typeof copy.credentials === 'object') {
            const dbSlug = String(copy.name || copy.id || 'DB').toUpperCase().replace(/[^A-Z0-9]+/g, '_').slice(0, 32);
            if (copy.credentials.password) {
              const vk = `${dbSlug}_PASSWORD`;
              vaultRefs.add(vk);
              secretCollector[vk] = String(copy.credentials.password);
            }
            if (copy.credentials.rootPassword) {
              const vk = `${dbSlug}_ROOT_PASSWORD`;
              vaultRefs.add(vk);
              secretCollector[vk] = String(copy.credentials.rootPassword);
            }
            copy.credentials = {
              user: copy.credentials.user || '',
              dbName: copy.credentials.dbName || '',
              passwordRef: copy.credentials.password ? `\${vault.${dbSlug}_PASSWORD}` : '',
              rootPasswordRef: copy.credentials.rootPassword ? `\${vault.${dbSlug}_ROOT_PASSWORD}` : ''
            };
          }
          if (copy.envVars && typeof copy.envVars === 'object') {
            /** @type {Record<string, string>} */
            const resCleanEnv = {};
            for (const [rk, rv] of Object.entries(copy.envVars)) {
              const rvStr = String(rv ?? '');
              if (isSecretEnvPair(rk, rvStr) && rvStr.length > 0) {
                const vk = `${slug}_${rk}`.replace(/[^A-Za-z0-9_]/g, '_').slice(0, 120);
                vaultRefs.add(vk);
                if (!secretCollector[vk]) secretCollector[vk] = rvStr;
                resCleanEnv[rk] = `\${vault.${vk}}`;
              } else {
                resCleanEnv[rk] = rvStr;
              }
            }
            copy.envVars = resCleanEnv;
          }
          return copy;
        })
      : [];

    return {
      id: proj.id,
      name: proj.name,
      description: proj.description || '',
      icon: proj.icon || '🚀',
      source: proj.source || 'culkibo-bundle',
      gitRepo: proj.gitRepo || '',
      gitBranch: proj.gitBranch || 'main',
      buildCommand: proj.buildCommand || '',
      startCommand: proj.startCommand || '',
      baseDirectory: proj.baseDirectory || '/',
      containerPort: proj.containerPort || proj.citadelPort || 3000,
      healthPath: proj.healthPath || '/',
      memoryMb: proj.memoryMb || proj.memoryLimitMb || null,
      cpus: proj.cpus || proj.cpuLimit || null,
      preDeployCommand: proj.preDeployCommand || '',
      postDeployCommand: proj.postDeployCommand || '',
      domains: Array.isArray(proj.domains) ? [...proj.domains] : [],
      envVars: cleanEnv,
      volumes: Array.isArray(proj.volumes) ? proj.volumes : [],
      fileMounts: Array.isArray(proj.fileMounts)
        ? proj.fileMounts.map((fm) => ({ mount_path: fm.mount_path || fm.path || '', fs_path: fm.fs_path || null, redacted: true }))
        : [],
      smokeTests: Array.isArray(proj.smokeTests) ? proj.smokeTests : [],
      resources
    };
  });

  return { sanitizedProjects: sanitized, vaultRefs: Array.from(vaultRefs).sort() };
}

/**
 * Sanitiza dominios ocultando hashes bcrypt o credenciales en el bundle.
 * @param {any[]} rawDomains
 */
function sanitizeDomainsForBundle(rawDomains) {
  return (Array.isArray(rawDomains) ? rawDomains : []).map((d) => {
    /** @type {Record<string, any>} */
    const out = {
      hostname: d.hostname,
      projectId: d.projectId || null,
      targetPod: d.targetPod || 'citadel',
      targetPort: Number(d.targetPort) || 3000,
      routingMode: d.routingMode || 'direct_dns',
      cloudflareProxied: Boolean(d.cloudflareProxied),
      canonicalRedirect: d.canonicalRedirect || 'none',
      securityHeaders: d.securityHeaders !== false,
      ...(d.hstsPreload !== undefined ? { hstsPreload: Boolean(d.hstsPreload) } : {}),
      ...(d.hstsMaxAge != null ? { hstsMaxAge: Number(d.hstsMaxAge) } : {}),
      ...(d.framePolicy ? { framePolicy: d.framePolicy } : {}),
      ...(d.csp ? { csp: d.csp } : {}),
      ...(d.permissionsPolicy ? { permissionsPolicy: d.permissionsPolicy } : {}),
      ...(d.customHeaders ? { customHeaders: d.customHeaders } : {}),
      ...(d.cors && d.cors.enabled ? { cors: d.cors } : {}),
      ...(d.forwardAuth && d.forwardAuth.enabled ? { forwardAuth: d.forwardAuth } : {}),
      ...(Array.isArray(d.pathRoutes) && d.pathRoutes.length > 0 ? { pathRoutes: d.pathRoutes } : {}),
      ...(Array.isArray(d.pathRedirects) && d.pathRedirects.length > 0 ? { pathRedirects: d.pathRedirects } : {}),
      ...(Array.isArray(d.ipAllowlist) && d.ipAllowlist.length > 0 ? { ipAllowlist: d.ipAllowlist } : {}),
      ...(d.rateLimit && d.rateLimit.enabled ? { rateLimit: d.rateLimit } : {}),
      ...(d.maxBodySizeMb ? { maxBodySizeMb: d.maxBodySizeMb } : {}),
      ...(d.protocol && d.protocol !== 'http' ? { protocol: d.protocol } : {}),
      ...(d.migrationSource ? { migrationSource: d.migrationSource } : {})
    };
    if (d.basicAuth && d.basicAuth.enabled) {
      out.basicAuth = {
        enabled: true,
        realm: d.basicAuth.realm || 'Acceso protegido',
        usernames: Array.isArray(d.basicAuth.accounts)
          ? d.basicAuth.accounts.map((a) => a.username)
          : (Array.isArray(d.basicAuth.usernames) ? d.basicAuth.usernames : [])
      };
    }
    return out;
  });
}

// ============================================================================
// HIGH-LEVEL BUNDLE EXPORT / INSPECT / IMPORT API
// ============================================================================

class BundleArchiver {
  /**
   * Exporta un stack completo de Culkibo en un archivo portátil `.zip` (por defecto) o `.ckb.gz`.
   * Acepta datos explícitos (para tests o snapshots offline de Coolify) o lee los gestores activos.
   *
   * @param {{
   *   stackName?: string,
   *   format?: 'zip' | 'ckb.gz',
   *   source?: string,
   *   passphrase?: string | null,
   *   panelUrl?: string,
   *   projectIds?: string[] | null,
   *   projects?: any[],
   *   domains?: any[],
   *   databases?: any[],
   *   crons?: any[],
   *   vaultSecrets?: Record<string, string>,
   *   migrationReport?: any,
   *   timestamp?: Date
   * }} [opts]
   */
  exportStackBundle(opts = {}) {
    const format = opts.format === 'ckb.gz' ? 'ckb.gz' : 'zip';
    const stackName = String(opts.stackName || 'culkibo-stack')
      .replace(/[^a-zA-Z0-9._ -]/g, '')
      .trim()
      .slice(0, 64) || 'culkibo-stack';
    const slug = stackName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'culkibo-stack';
    const createdAt = (opts.timestamp instanceof Date ? opts.timestamp : new Date()).toISOString();
    const bundleId = `ckb_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`;

    // Resolver fuentes (datos explícitos o carga perezosa de gestores en vivo)
    /** @type {any[]} */
    let rawProjects = [];
    if (Array.isArray(opts.projects)) {
      rawProjects = opts.projects;
    } else {
      const pm = require('./projectManager');
      const all = Array.isArray(pm.getAll()) ? pm.getAll() : [];
      rawProjects = Array.isArray(opts.projectIds) && opts.projectIds.length > 0
        ? all.filter((p) => opts.projectIds && opts.projectIds.includes(p.id))
        : all;
    }
    const projectIdSet = new Set(rawProjects.map((p) => p.id).filter(Boolean));

    /** @type {any[]} */
    let rawDomains = [];
    if (Array.isArray(opts.domains)) {
      rawDomains = opts.domains;
    } else {
      const dm = require('./domainManager');
      const allDoms = Array.isArray(dm.listDomains()) ? dm.listDomains() : [];
      rawDomains = Array.isArray(opts.projectIds) && opts.projectIds.length > 0
        ? allDoms.filter((d) => d.projectId && projectIdSet.has(d.projectId))
        : allDoms;
    }

    /** @type {any[]} */
    let rawCrons = [];
    if (Array.isArray(opts.crons)) {
      rawCrons = opts.crons;
    } else {
      try {
        const cm = require('./cronManager');
        const allCrons = Array.isArray(cm.list()) ? cm.list() : [];
        rawCrons = Array.isArray(opts.projectIds) && opts.projectIds.length > 0
          ? allCrons.filter((c) => c.projectId && projectIdSet.has(c.projectId))
          : allCrons;
      } catch (e) {
        rawCrons = [];
      }
    }

    const rawDatabases = Array.isArray(opts.databases) ? opts.databases : [];

    /** @type {Record<string, string>} */
    const secretCollector = {};
    if (opts.vaultSecrets && typeof opts.vaultSecrets === 'object') {
      for (const [k, v] of Object.entries(opts.vaultSecrets)) {
        if (!FORBIDDEN_PROTO_KEYS.has(k) && v !== undefined && v !== null) {
          secretCollector[k] = String(v);
        }
      }
    }

    const { sanitizedProjects, vaultRefs } = sanitizeProjectsForBundle(rawProjects, secretCollector);
    const sanitizedDomains = sanitizeDomainsForBundle(rawDomains);
    const sanitizedDatabases = rawDatabases.map((db) => ({
      id: db.id || db.uuid || undefined,
      name: db.name,
      engine: db.engine || db.database_type || 'postgres',
      image: db.image || undefined,
      projectId: db.projectId || null,
      dbName: db.dbName || undefined,
      username: db.username || undefined,
      port: db.port || undefined,
      volumes: Array.isArray(db.volumes) ? db.volumes : [],
      generateSecret: true
    }));
    const sanitizedCrons = (rawCrons || []).map((c) => ({
      name: c.name,
      projectId: c.projectId || null,
      schedule: c.schedule,
      mode: c.mode === 'http' ? 'http' : 'exec',
      ...(c.mode === 'http'
        ? { httpPath: c.httpPath || '/', httpMethod: c.httpMethod || 'POST' }
        : { command: c.command || '', ...(c.workdir ? { workdir: c.workdir } : {}) }),
      enabled: c.enabled !== false
    }));

    const allVaultKeys = Array.from(new Set([...vaultRefs, ...Object.keys(secretCollector)])).sort();

    // Generar culkibo.yaml v1 declarativo y 100% libre de secretos
    /** @type {Record<string, any>} */
    const yamlManifestObj = {
      version: 1,
      name: stackName,
      ...(allVaultKeys.length > 0 ? { vaultRefs: allVaultKeys } : {}),
      projects: sanitizedProjects.map((p) => ({
        id: p.id,
        name: p.name,
        ...(p.description ? { description: p.description } : {}),
        ...(p.gitRepo ? { gitRepo: p.gitRepo } : {}),
        gitBranch: p.gitBranch || 'main',
        ...(p.buildCommand ? { buildCommand: p.buildCommand } : {}),
        ...(p.startCommand ? { startCommand: p.startCommand } : {}),
        baseDirectory: p.baseDirectory || '/',
        containerPort: Number(p.containerPort) || 3000,
        healthPath: p.healthPath || '/',
        ...(p.memoryMb ? { memoryMb: p.memoryMb } : {}),
        ...(p.cpus ? { cpus: p.cpus } : {}),
        ...(p.domains.length > 0 ? { domains: p.domains } : {}),
        ...(Object.keys(p.envVars).length > 0 ? { env: p.envVars } : {})
      })),
      ...(sanitizedDatabases.length > 0 ? { databases: sanitizedDatabases } : {}),
      ...(sanitizedDomains.length > 0 ? {
        domains: sanitizedDomains.map((d) => ({
          hostname: d.hostname,
          projectId: d.projectId,
          targetPort: d.targetPort,
          routingMode: d.routingMode,
          cloudflareProxied: d.cloudflareProxied,
          canonicalRedirect: d.canonicalRedirect,
          securityHeaders: d.securityHeaders
        }))
      } : {}),
      ...(sanitizedCrons.length > 0 ? { crons: sanitizedCrons } : {})
    };
    const culkiboYaml = `# Culkibo Portable Stack Manifest (culkibo.yaml v1)\n# Bundle: ${bundleId}\n${serializeYaml(yamlManifestObj, 0)}\n`;

    const mcpConfig = buildAgentMcpConfig(stackName, opts.panelUrl);

    const hasPassphrase = typeof opts.passphrase === 'string' && opts.passphrase.length > 0;
    const vaultMode = hasPassphrase ? 'encrypted' : 'redacted';
    const vaultFileName = hasPassphrase ? 'vault.enc.json' : 'vault.redacted.json';
    const vaultFileObj = hasPassphrase
      ? encryptVaultEnvelope(secretCollector, String(opts.passphrase), bundleId)
      : {
          version: 1,
          encrypted: false,
          mode: 'redacted',
          bundleId,
          note: 'Secrets were intentionally omitted because no passphrase was supplied. Populate these keys in Culkibo Vault before deploying.',
          requiredKeys: allVaultKeys.map((k) => ({
            key: k,
            hasCapturedValue: Object.prototype.hasOwnProperty.call(secretCollector, k),
            fingerprint: Object.prototype.hasOwnProperty.call(secretCollector, k)
              ? `sha256:${sha256Hex(`${bundleId}:${k}:${secretCollector[k]}`).slice(0, 16)}`
              : null
          }))
        };

    const readmeRestore = [
      `# Culkibo Portable Stack Bundle — ${stackName}`,
      '',
      `- **Bundle ID**: \`${bundleId}\``,
      `- **Created**: ${createdAt}`,
      `- **Source**: ${opts.source || 'culkibo'}`,
      `- **Vault Mode**: ${vaultMode === 'encrypted' ? 'AES-256-GCM encrypted (`vault.enc.json`)' : 'Redacted (`vault.redacted.json` — zero plaintext secrets)'}`,
      '',
      '## Contents',
      '- `manifest.json` — Bundle metadata & resource counts',
      '- `culkibo.yaml` — Declarative GitOps v1 stack manifest',
      '- `projects.json` — Sanitized projects & resources',
      '- `domains.json` — Domains & Caddy edge policies (CORS, HSTS, ForwardAuth, PathRoutes)',
      '- `databases.json` — Database topologies (without plaintext credentials)',
      '- `crons.json` — Scheduled tasks',
      '- `mcp-agent-config.json` — Drop-in AI Agent MCP config (Antigravity, Claude Code, Cursor)',
      `- \`${vaultFileName}\` — Vault secrets (${vaultMode})`,
      '- `checksums.json` — SHA-256 integrity manifest for every file',
      '',
      '## Restore in 1 Click',
      '1. Upload this `.zip` in Culkibo → **Importar → Coolify / Bundle Portátil**.',
      vaultMode === 'encrypted'
        ? '2. Enter your Vault passphrase to decrypt and seed secrets directly into Culkibo AES-256-GCM Vault.'
        : '2. Populate the keys listed in `vault.redacted.json` in Culkibo Vault before deploying.',
      '3. Verify endpoints and complete zero-downtime DNS cutover.'
    ].join('\n');

    /** @type {Record<string, string>} */
    const payloadFiles = {
      'culkibo.yaml': culkiboYaml,
      'projects.json': JSON.stringify(sanitizedProjects, null, 2),
      'domains.json': JSON.stringify(sanitizedDomains, null, 2),
      'databases.json': JSON.stringify(sanitizedDatabases, null, 2),
      'crons.json': JSON.stringify(sanitizedCrons, null, 2),
      'mcp-agent-config.json': JSON.stringify(mcpConfig, null, 2),
      [vaultFileName]: JSON.stringify(vaultFileObj, null, 2),
      'README-RESTORE.md': readmeRestore
    };

    if (opts.migrationReport) {
      payloadFiles['migration-report.json'] = JSON.stringify(opts.migrationReport, null, 2);
    }

    /** @type {Record<string, string>} */
    const checksums = {};
    for (const [fname, content] of Object.entries(payloadFiles).sort(([a], [b]) => a.localeCompare(b))) {
      checksums[fname] = sha256Hex(content);
    }

    const manifest = {
      format: 'culkibo-bundle/v1',
      version: BUNDLE_FORMAT_VERSION,
      culkiboVersion: CULKIBO_VERSION,
      bundleId,
      stackName,
      source: opts.source || 'culkibo',
      createdAt,
      vaultMode,
      vaultFile: vaultFileName,
      vaultRefs: allVaultKeys,
      counts: {
        projects: sanitizedProjects.length,
        domains: sanitizedDomains.length,
        databases: sanitizedDatabases.length,
        crons: sanitizedCrons.length,
        vaultKeys: allVaultKeys.length
      },
      files: Object.keys(payloadFiles).sort()
    };

    const allFiles = {
      'manifest.json': JSON.stringify(manifest, null, 2),
      'checksums.json': JSON.stringify({ algorithm: 'sha256', files: checksums }, null, 2),
      ...payloadFiles
    };

    const buffer = format === 'ckb.gz'
      ? createCkbGzBuffer({ manifest, checksums: { algorithm: 'sha256', files: checksums }, files: payloadFiles })
      : createZipBuffer(allFiles, {
          timestamp: opts.timestamp instanceof Date ? opts.timestamp : new Date(),
          comment: `Culkibo Portable Stack Bundle v1 (${bundleId})`
        });

    const filename = `${slug}-${bundleId}.${format}`;
    return {
      ok: true,
      format,
      bundleId,
      filename,
      buffer,
      byteLength: buffer.length,
      sha256: sha256Hex(buffer),
      manifest,
      stats: {
        fileCount: Object.keys(allFiles).length,
        vaultMode,
        ...manifest.counts
      }
    };
  }

  /**
   * Inspecciona y verifica la integridad completa de un bundle `.zip` o `.ckb.gz`
   * sin mutar ningún estado del servidor.
   *
   * @param {Buffer} buffer
   * @param {{ passphrase?: string | null, maxArchiveBytes?: number, maxEntries?: number, maxSingleFileBytes?: number, maxTotalUncompressedBytes?: number, maxCompressionRatio?: number }} [opts]
   */
  inspectStackBundle(buffer, opts = {}) {
    if (!Buffer.isBuffer(buffer) || buffer.length < 4) {
      throw new Error('Buffer de bundle inválido o demasiado pequeño');
    }

    const isZip = buffer[0] === 0x50 && buffer[1] === 0x4b;
    const isGzip = buffer[0] === 0x1f && buffer[1] === 0x8b;
    if (!isZip && !isGzip) {
      throw new Error('Formato de bundle no reconocido (se esperaba .zip o .ckb.gz)');
    }

    /** @type {'zip' | 'ckb.gz'} */
    const format = isZip ? 'zip' : 'ckb.gz';
    /** @type {Record<string, string>} */
    const textFiles = Object.create(null);
    /** @type {any} */
    let manifest;
    /** @type {any} */
    let checksumsDoc;
    /** @type {any[]} */
    let archiveEntries = [];

    if (isZip) {
      const parsed = parseZipBuffer(buffer, opts);
      archiveEntries = parsed.entries;
      for (const [name, buf] of Object.entries(parsed.files)) {
        textFiles[name] = buf.toString('utf8');
      }
      if (!textFiles['manifest.json']) {
        throw new Error('Bundle ZIP inválido: falta manifest.json');
      }
      manifest = JSON.parse(textFiles['manifest.json']);
      checksumsDoc = textFiles['checksums.json'] ? JSON.parse(textFiles['checksums.json']) : null;
    } else {
      const parsed = parseCkbGzBuffer(buffer, opts);
      manifest = parsed.manifest;
      checksumsDoc = parsed.checksums || null;
      if (parsed.files && typeof parsed.files === 'object') {
        for (const [k, v] of Object.entries(parsed.files)) {
          const safe = validateArchiveEntryPath(k);
          textFiles[safe] = String(v ?? '');
        }
      }
    }

    if (!manifest || manifest.format !== 'culkibo-bundle/v1' || manifest.version !== BUNDLE_FORMAT_VERSION) {
      throw new Error('Manifiesto de bundle incompatible o versión desconocida');
    }

    // Verificar checksums SHA-256 de cada archivo declarado
    /** @type {string[]} */
    const warnings = [];
    let checksumsVerified = false;
    if (checksumsDoc && checksumsDoc.files && typeof checksumsDoc.files === 'object') {
      for (const [fname, expectedHash] of Object.entries(checksumsDoc.files)) {
        const safe = validateArchiveEntryPath(fname);
        if (!Object.prototype.hasOwnProperty.call(textFiles, safe)) {
          throw new Error(`Fallo de integridad en bundle: falta el archivo "${safe}" listado en checksums.json`);
        }
        const actualHash = sha256Hex(textFiles[safe]);
        if (actualHash !== expectedHash) {
          throw new Error(`Fallo de integridad SHA-256 en "${safe}" (archivo manipulado o corrupto)`);
        }
      }
      checksumsVerified = true;
    } else {
      warnings.push('El bundle no incluye checksums.json; se omitió verificación SHA-256 adicional.');
    }

    const projects = textFiles['projects.json'] ? JSON.parse(textFiles['projects.json']) : [];
    const domains = textFiles['domains.json'] ? JSON.parse(textFiles['domains.json']) : [];
    const databases = textFiles['databases.json'] ? JSON.parse(textFiles['databases.json']) : [];
    const crons = textFiles['crons.json'] ? JSON.parse(textFiles['crons.json']) : [];
    const mcpConfig = textFiles['mcp-agent-config.json'] ? JSON.parse(textFiles['mcp-agent-config.json']) : null;
    const culkiboYaml = textFiles['culkibo.yaml'] || '';

    let vaultSummary = {
      mode: manifest.vaultMode || 'redacted',
      encrypted: manifest.vaultMode === 'encrypted',
      unlocked: false,
      keyCount: Array.isArray(manifest.vaultRefs) ? manifest.vaultRefs.length : 0,
      keys: Array.isArray(manifest.vaultRefs) ? [...manifest.vaultRefs] : []
    };

    /** @type {Record<string, string> | null} */
    let decryptedVault = null;
    if (textFiles['vault.enc.json']) {
      const envObj = JSON.parse(textFiles['vault.enc.json']);
      vaultSummary.encrypted = true;
      vaultSummary.mode = 'encrypted';
      vaultSummary.keys = Array.isArray(envObj.keys) ? envObj.keys : vaultSummary.keys;
      vaultSummary.keyCount = vaultSummary.keys.length;
      if (opts.passphrase) {
        decryptedVault = decryptVaultEnvelope(envObj, opts.passphrase);
        vaultSummary.unlocked = true;
      } else {
        warnings.push('El bundle tiene un Vault cifrado (vault.enc.json). Proporciona la passphrase al importar para restaurar los secretos.');
      }
    } else if (textFiles['vault.redacted.json']) {
      const redObj = JSON.parse(textFiles['vault.redacted.json']);
      const reqKeys = Array.isArray(redObj.requiredKeys) ? redObj.requiredKeys.map((k) => k.key) : [];
      vaultSummary.keys = reqKeys.length > 0 ? reqKeys : vaultSummary.keys;
      vaultSummary.keyCount = vaultSummary.keys.length;
      if (vaultSummary.keyCount > 0) {
        warnings.push(`Bundle redactado sin secretos en claro: recuerda cargar ${vaultSummary.keyCount} clave(s) en el Vault antes de desplegar.`);
      }
    }

    return {
      ok: true,
      format,
      sha256: sha256Hex(buffer),
      byteLength: buffer.length,
      checksumsVerified,
      manifest,
      culkiboYaml,
      projects: Array.isArray(projects) ? projects : [],
      domains: Array.isArray(domains) ? domains : [],
      databases: Array.isArray(databases) ? databases : [],
      crons: Array.isArray(crons) ? crons : [],
      mcpConfig,
      vaultSummary,
      entries: archiveEntries,
      warnings,
      // Solo interno: nunca serializar valores secretos en logs públicos
      _decryptedVaultCount: decryptedVault ? Object.keys(decryptedVault).length : 0
    };
  }

  /**
   * Importa un bundle portátil `.zip` o `.ckb.gz` a Culkibo.
   * Por seguridad admite `dryRun: true` para planificar antes de aplicar cambios.
   *
   * @param {Buffer} buffer
   * @param {{
   *   passphrase?: string | null,
   *   dryRun?: boolean,
   *   selectedProjectIds?: string[] | null,
   *   projectManager?: any,
   *   domainManager?: any,
   *   cronManager?: any,
   *   environmentManager?: any
   * }} [opts]
   */
  async importStackBundle(buffer, opts = {}) {
    const inspected = this.inspectStackBundle(buffer, { passphrase: opts.passphrase });
    const dryRun = Boolean(opts.dryRun);

    const selectedIds = Array.isArray(opts.selectedProjectIds) ? new Set(opts.selectedProjectIds) : null;
    const projectsToImport = selectedIds
      ? inspected.projects.filter((p) => selectedIds.has(p.id) || selectedIds.has(p.name))
      : inspected.projects;
    const importedProjectIdSet = new Set(projectsToImport.map((p) => p.id).filter(Boolean));
    const domainsToImport = selectedIds
      ? inspected.domains.filter((d) => !d.projectId || importedProjectIdSet.has(d.projectId))
      : inspected.domains;
    const cronsToImport = selectedIds
      ? inspected.crons.filter((c) => !c.projectId || importedProjectIdSet.has(c.projectId))
      : inspected.crons;

    if (dryRun) {
      return {
        ok: true,
        dryRun: true,
        bundleId: inspected.manifest.bundleId,
        stackName: inspected.manifest.stackName,
        format: inspected.format,
        checksumsVerified: inspected.checksumsVerified,
        wouldImport: {
          projects: projectsToImport.length,
          domains: domainsToImport.length,
          databases: inspected.databases.length,
          crons: cronsToImport.length,
          vaultSecrets: inspected._decryptedVaultCount
        },
        vaultSummary: inspected.vaultSummary,
        warnings: inspected.warnings
      };
    }

    const pm = opts.projectManager || require('./projectManager');
    const dm = opts.domainManager || require('./domainManager');
    const cm = opts.cronManager || (() => {
      try { return require('./cronManager'); } catch (e) { return null; }
    })();
    const em = opts.environmentManager || (() => {
      try { return require('./environmentManager'); } catch (e) { return null; }
    })();

    const result = {
      ok: true,
      dryRun: false,
      bundleId: inspected.manifest.bundleId,
      stackName: inspected.manifest.stackName,
      format: inspected.format,
      importedProjects: 0,
      importedDomains: 0,
      importedCrons: 0,
      importedVaultSecrets: 0,
      databasesCataloged: inspected.databases.length,
      createdProjectIds: /** @type {string[]} */ ([]),
      warnings: [...inspected.warnings],
      errors: /** @type {string[]} */ ([])
    };

    // 1. Restaurar secretos del Vault si el sobre está descifrado
    if (inspected.vaultSummary.encrypted && opts.passphrase && em && typeof em.setVaultSecret === 'function') {
      const parsedZip = inspected.format === 'zip' ? parseZipBuffer(buffer) : null;
      const rawVaultStr = parsedZip
        ? (parsedZip.files['vault.enc.json'] ? parsedZip.files['vault.enc.json'].toString('utf8') : null)
        : (parseCkbGzBuffer(buffer).files || {})['vault.enc.json'];
      if (rawVaultStr) {
        const secrets = decryptVaultEnvelope(JSON.parse(rawVaultStr), opts.passphrase);
        for (const [k, v] of Object.entries(secrets)) {
          try {
            em.setVaultSecret(k, v, { description: `Restaurado de bundle ${inspected.manifest.bundleId}`, actor: 'bundle-import' });
            result.importedVaultSecrets++;
          } catch (err) {
            result.errors.push(`Vault ${k}: ${err.message}`);
          }
        }
      }
    }

    // 2. Crear proyectos
    /** @type {Map<string, string>} */
    const projectIdMap = new Map();
    for (const proj of projectsToImport) {
      try {
        const created = pm.create({
          ...proj,
          source: proj.source || 'culkibo-bundle'
        });
        const realId = (created && created.id) || proj.id;
        if (proj.id && realId) projectIdMap.set(proj.id, realId);
        if (realId) result.createdProjectIds.push(realId);
        result.importedProjects++;
      } catch (err) {
        result.errors.push(`Proyecto ${proj.name || proj.id}: ${err.message}`);
      }
    }

    // 3. Registrar dominios con sus políticas Edge
    for (const dom of domainsToImport) {
      try {
        const mappedProjectId = dom.projectId && projectIdMap.has(dom.projectId)
          ? projectIdMap.get(dom.projectId)
          : (dom.projectId || null);
        const domainPayload = {
          ...dom,
          projectId: mappedProjectId,
          sslStatus: 'pending_migration',
          sslProvider: 'lets_encrypt',
          migrationSource: dom.migrationSource || 'culkibo-bundle'
        };
        // No pasar basicAuth sin passwordHash válido (en bundles sanitizados solo hay nombres de usuario)
        if (domainPayload.basicAuth && !Array.isArray(domainPayload.basicAuth.accounts)) {
          delete domainPayload.basicAuth;
          result.warnings.push(`Dominio ${dom.hostname}: Basic Auth requiere reconfigurar contraseñas por seguridad.`);
        }
        await dm.addDomain(domainPayload);
        result.importedDomains++;
      } catch (err) {
        result.errors.push(`Dominio ${dom.hostname}: ${err.message}`);
      }
    }

    // 4. Registrar crons
    if (cm && typeof cm.create === 'function') {
      for (const cron of cronsToImport) {
        const targetPid = (cron.projectId && projectIdMap.get(cron.projectId)) || cron.projectId || result.createdProjectIds[0];
        if (!targetPid) continue;
        try {
          cm.create(targetPid, cron);
          result.importedCrons++;
        } catch (err) {
          result.warnings.push(`Cron "${cron.name}": ${err.message}`);
        }
      }
    }

    if (typeof pm.flushToDisk === 'function') {
      try { await pm.flushToDisk(); } catch (e) {}
    }

    return result;
  }

  /**
   * Escribe un bundle generado directamente a disco (utilidad CLI / backup).
   * @param {string} targetPath
   * @param {ReturnType<BundleArchiver['exportStackBundle']>} bundle
   */
  writeBundleToFile(targetPath, bundle) {
    const resolved = path.resolve(targetPath);
    fs.mkdirSync(path.dirname(resolved), { recursive: true });
    fs.writeFileSync(resolved, bundle.buffer, { mode: 0o600 });
    return { path: resolved, byteLength: bundle.byteLength, sha256: bundle.sha256 };
  }
}

const instance = /** @type {any} */ (new BundleArchiver());
instance.BundleArchiver = BundleArchiver;
instance.crc32 = crc32;
instance.createZipBuffer = createZipBuffer;
instance.parseZipBuffer = parseZipBuffer;
instance.createCkbGzBuffer = createCkbGzBuffer;
instance.parseCkbGzBuffer = parseCkbGzBuffer;
instance.encryptVaultEnvelope = encryptVaultEnvelope;
instance.decryptVaultEnvelope = decryptVaultEnvelope;
instance.validateArchiveEntryPath = validateArchiveEntryPath;
instance.buildAgentMcpConfig = buildAgentMcpConfig;

module.exports = instance;
