const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { atomicWriteJsonSync, loadJsonWithBackupSync, assertContainedPath } = require('./ssrfGuard');

/**
 * Culkibo SnapStream — Replicación incremental cifrada de SQLite WAL a disco / S3 (estilo Litestream).
 *
 * Garantías de diseño y seguridad:
 *  - Cero dependencias npm externas (`crypto`, `zlib`, `fs`, `path` + `s3Uploader.js` nativo).
 *  - Cero llamadas de shell (`shell: false` / 0 subprocesos).
 *  - Seguimiento SHA-256 delta del fichero SQLite principal y de su journal `-wal`:
 *      * Generación 1 o cambio en el fichero principal → `snapshot` completo (DB + WAL actual).
 *      * Crecimiento/modificación exclusiva del `-wal` → `wal_delta` incremental (solo bytes nuevos).
 *      * Sin cambios en DB ni `-wal` → omitido (`skipped: true`, 0 bytes escritos).
 *  - Compresión nativa con `zlib.brotliCompressSync` + cifrado autenticado AES-256-GCM en sobre
 *    binario **`CKS1`** con AAD contextual (`cks1:<dbId>:<generationId>:<kind>`) que impide
 *    trasplante de frames entre bases de datos o generaciones y detecta cualquier manipulación de 1 bit.
 *  - Restauración Point-in-Time (`restorePointInTime`) reconstruye desde el snapshot base y
 *    reproduce secuencialmente todos los `wal_delta` verificando SHA-256 final y escribiendo atómicamente.
 */

const MAGIC_HEADER = Buffer.from('CKS1', 'ascii'); // 0x43 0x4b 0x53 0x31
const ENVELOPE_VERSION = 1;
const FLAG_BROTLI_AESGCM = 0x01;
const DB_ID_RE = /^[a-zA-Z0-9_-]{1,80}$/;
const MAX_RESTORE_BYTES = 256 * 1024 * 1024; // 256 MiB protección contra bomba de descompresión

/** Carga perezosa de `S3Client` solo cuando se especifica `s3Config`. */
function getS3ClientClass() {
  return require('./s3Uploader').S3Client;
}

/** @param {string | null} [overrideDir] */
function resolveDataDir(overrideDir = null) {
  if (overrideDir) return path.resolve(overrideDir);
  if (process.env.CULKIBO_DATA_DIR) {
    return path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data');
  }
  return path.resolve(__dirname, '..', '..', 'data');
}

/** @param {string} dbId */
function assertSafeDbId(dbId) {
  const clean = String(dbId || '').trim();
  if (!DB_ID_RE.test(clean)) {
    throw new Error(`dbId inválido para SnapStream (permitido [a-zA-Z0-9_-]{1,80}): "${clean.slice(0, 40)}"`);
  }
  return clean;
}

/** @param {Buffer | string} data */
function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Deriva una clave AES-256 de 32 bytes desde `encryptionKey` (Buffer de 32 bytes o passphrase string)
 * y la sal aleatoria de 16 bytes del sobre `CKS1` usando HKDF-SHA256.
 * @param {Buffer | string} encryptionKey
 * @param {Buffer} salt
 * @returns {Buffer}
 */
function deriveFrameKey(encryptionKey, salt) {
  if (!encryptionKey) {
    throw new Error('SnapStream exige encryptionKey (Buffer de 32 bytes o frase de >= 8 caracteres)');
  }
  /** @type {Buffer} */
  let ikm;
  if (Buffer.isBuffer(encryptionKey)) {
    if (encryptionKey.length < 16) {
      throw new Error('encryptionKey Buffer debe tener al menos 16 bytes (recomendado 32)');
    }
    ikm = encryptionKey;
  } else {
    const str = String(encryptionKey);
    if (str.length < 8) {
      throw new Error('encryptionKey debe tener al menos 8 caracteres');
    }
    ikm = Buffer.from(str, 'utf8');
  }
  return Buffer.from(crypto.hkdfSync('sha256', ikm, salt, Buffer.from('culkibo-snapstream-cks1', 'utf8'), 32));
}

/**
 * Comprime con Brotli y cifra un payload en sobre binario `CKS1` (AES-256-GCM + AAD).
 * Formato binario:
 *   [0..3]   'CKS1'
 *   [4]      version (1)
 *   [5]      flags (0x01 = brotli + aes-256-gcm)
 *   [6..21]  salt (16B)
 *   [22..33] iv (12B)
 *   [34..49] authTag (16B)
 *   [50..51] aadLen (UInt16BE)
 *   [52..52+aadLen) aad UTF-8
 *   [52+aadLen..]   ciphertext
 *
 * @param {Buffer} plainPayload
 * @param {Buffer | string} encryptionKey
 * @param {string} aadStr
 * @returns {{ envelope: Buffer, compressedBytes: number, rawBytes: number }}
 */
function encryptEnvelope(plainPayload, encryptionKey, aadStr) {
  const compressed = zlib.brotliCompressSync(plainPayload, {
    params: {
      [zlib.constants.BROTLI_PARAM_QUALITY]: 4
    }
  });
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const aadBuf = Buffer.from(String(aadStr), 'utf8');
  if (aadBuf.length > 65535) throw new Error('AAD demasiado largo para sobre CKS1');

  const key = deriveFrameKey(encryptionKey, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  cipher.setAAD(aadBuf);
  const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const header = Buffer.allocUnsafe(52);
  MAGIC_HEADER.copy(header, 0);
  header[4] = ENVELOPE_VERSION;
  header[5] = FLAG_BROTLI_AESGCM;
  salt.copy(header, 6);
  iv.copy(header, 22);
  authTag.copy(header, 34);
  header.writeUInt16BE(aadBuf.length, 50);

  return {
    envelope: Buffer.concat([header, aadBuf, ciphertext]),
    compressedBytes: compressed.length,
    rawBytes: plainPayload.length
  };
}

/**
 * Verifica y descifra un sobre binario `CKS1`, validando firma mágica, AAD esperada,
 * etiqueta AES-256-GCM y descompresión Brotli acotada.
 *
 * @param {Buffer} envelope
 * @param {Buffer | string} encryptionKey
 * @param {string} expectedAad
 * @returns {Buffer}
 */
function decryptEnvelope(envelope, encryptionKey, expectedAad) {
  if (!Buffer.isBuffer(envelope) || envelope.length < 52) {
    throw new Error('Sobre CKS1 truncado o inválido');
  }
  if (!envelope.subarray(0, 4).equals(MAGIC_HEADER)) {
    throw new Error('Firma mágica CKS1 inválida (archivo corrupto o formato desconocido)');
  }
  const version = envelope[4];
  const flags = envelope[5];
  if (version !== ENVELOPE_VERSION || flags !== FLAG_BROTLI_AESGCM) {
    throw new Error(`Versión o flags de sobre CKS1 no soportados (v=${version}, flags=${flags})`);
  }

  const salt = envelope.subarray(6, 22);
  const iv = envelope.subarray(22, 34);
  const authTag = envelope.subarray(34, 50);
  const aadLen = envelope.readUInt16BE(50);
  if (52 + aadLen > envelope.length) {
    throw new Error('Longitud de AAD fuera de rango en sobre CKS1');
  }
  const aadBuf = envelope.subarray(52, 52 + aadLen);
  const aadText = aadBuf.toString('utf8');
  if (expectedAad && aadText !== expectedAad) {
    throw new Error(`AAD de sobre CKS1 no coincide (posible trasplante de frame: esperado "${expectedAad}", recibido "${aadText}")`);
  }

  const ciphertext = envelope.subarray(52 + aadLen);
  const key = deriveFrameKey(encryptionKey, salt);

  /** @type {Buffer} */
  let compressed;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
    decipher.setAAD(aadBuf);
    decipher.setAuthTag(authTag);
    compressed = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    throw new Error('Fallo de autenticación AES-256-GCM en sobre CKS1: clave incorrecta o frame manipulado');
  }

  try {
    return zlib.brotliDecompressSync(compressed, { maxOutputLength: MAX_RESTORE_BYTES });
  } catch (err) {
    throw new Error(`Error descomprimiendo frame CKS1 Brotli: ${err.message}`);
  }
}

/**
 * Empaqueta el contenido binario de una generación (`main` + `wal`) en un buffer compacto
 * sin overhead base64:
 *   [0..3] mainLen (UInt32BE)
 *   [4..7] walLen  (UInt32BE)
 *   [8..11] walOffset (UInt32BE, para wal_delta incremental)
 *   [12..12+mainLen) mainBytes
 *   [12+mainLen..)   walBytes
 *
 * @param {Buffer} mainBytes
 * @param {Buffer} walBytes
 * @param {number} [walOffset]
 * @returns {Buffer}
 */
function packFramePayload(mainBytes, walBytes, walOffset = 0) {
  const hdr = Buffer.allocUnsafe(12);
  hdr.writeUInt32BE(mainBytes.length >>> 0, 0);
  hdr.writeUInt32BE(walBytes.length >>> 0, 4);
  hdr.writeUInt32BE(walOffset >>> 0, 8);
  return Buffer.concat([hdr, mainBytes, walBytes]);
}

/**
 * Desempaqueta un payload de frame binario `packFramePayload`.
 * @param {Buffer} buf
 * @returns {{ mainBytes: Buffer, walBytes: Buffer, walOffset: number }}
 */
function unpackFramePayload(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) {
    throw new Error('Payload interno de frame SnapStream corrupto');
  }
  const mainLen = buf.readUInt32BE(0);
  const walLen = buf.readUInt32BE(4);
  const walOffset = buf.readUInt32BE(8);
  if (12 + mainLen + walLen !== buf.length) {
    throw new Error('Longitudes internas de payload SnapStream inconsistentes');
  }
  return {
    mainBytes: buf.subarray(12, 12 + mainLen),
    walBytes: buf.subarray(12 + mainLen, 12 + mainLen + walLen),
    walOffset
  };
}

class SqliteStreamBackup {
  /** @param {{ dataDir?: string | null }} [opts] */
  constructor(opts = {}) {
    this._dataDirOverride = opts.dataDir || null;
    /** @type {Map<string, { lastCapturedAt: string | null, lastError: string | null, lastGenerationId: string | null }>} */
    this._runtimeState = new Map();
  }

  /**
   * Resuelve el directorio de generaciones para `dbId`.
   * @param {string} dbId
   * @param {string | null} [destDir]
   */
  _resolveDbDir(dbId, destDir = null) {
    const safeId = assertSafeDbId(dbId);
    const root = destDir ? path.resolve(destDir) : path.join(resolveDataDir(this._dataDirOverride), 'snapstream');
    return assertContainedPath(root, safeId);
  }

  /** @param {string} dbDir */
  _loadIndex(dbDir) {
    const idxFile = path.join(dbDir, 'index.json');
    const loaded = loadJsonWithBackupSync(idxFile, {
      validate: (p) => Boolean(p && typeof p === 'object' && Array.isArray(p.generations))
    });
    if (loaded.ok && loaded.data) {
      return loaded.data;
    }
    return { version: 1, generations: [] };
  }

  /** @param {string} dbDir @param {any} idxData */
  _saveIndex(dbDir, idxData) {
    fs.mkdirSync(dbDir, { recursive: true, mode: 0o700 });
    atomicWriteJsonSync(path.join(dbDir, 'index.json'), idxData, { mode: 0o600, backup: true });
  }

  /**
   * Captura una generación incremental (snapshot o wal_delta) de una base de datos SQLite,
   * la comprime con Brotli, la cifra en sobre `CKS1` AES-256-GCM con AAD y opcionalmente la
   * sube a S3/R2 usando `s3Uploader.js`.
   *
   * @param {string} dbId
   * @param {string} dbPath
   * @param {{
   *   encryptionKey: Buffer | string,
   *   destDir?: string | null,
   *   s3Config?: Record<string, any> | null,
   *   s3Client?: any,
   *   label?: string | null,
   *   forceFull?: boolean
   * }} opts
   */
  async captureGeneration(dbId, dbPath, opts) {
    const safeId = assertSafeDbId(dbId);
    if (!opts || !opts.encryptionKey) {
      throw new Error('captureGeneration requiere encryptionKey');
    }
    const resolvedDbPath = path.resolve(String(dbPath || ''));
    if (!fs.existsSync(resolvedDbPath)) {
      throw new Error(`Archivo SQLite no encontrado: ${resolvedDbPath}`);
    }

    const dbDir = this._resolveDbDir(safeId, opts.destDir || null);
    const index = this._loadIndex(dbDir);
    const prevGen = index.generations.length > 0 ? index.generations[index.generations.length - 1] : null;

    const mainBuf = fs.readFileSync(resolvedDbPath);
    const walPath = `${resolvedDbPath}-wal`;
    const walBuf = fs.existsSync(walPath) ? fs.readFileSync(walPath) : Buffer.alloc(0);

    const dbSha256 = sha256Hex(mainBuf);
    const walSha256 = sha256Hex(walBuf);

    // Detección de delta sin cambios
    if (
      prevGen
      && !opts.forceFull
      && prevGen.dbSha256 === dbSha256
      && prevGen.walSha256 === walSha256
      && prevGen.walBytes === walBuf.length
    ) {
      return {
        captured: false,
        skipped: true,
        reason: 'no_changes',
        dbId: safeId,
        latestGeneration: prevGen,
        dbSha256,
        walSha256
      };
    }

    const sequence = prevGen ? (Number(prevGen.sequence) || 0) + 1 : 1;
    const generationId = `gen_${String(sequence).padStart(6, '0')}_${crypto.randomBytes(4).toString('hex')}`;

    // Decidir si emitir wal_delta incremental o snapshot completo
    let kind = /** @type {'snapshot' | 'wal_delta'} */ ('snapshot');
    let baseGenerationId = generationId;
    let walOffset = 0;
    let payloadMain = mainBuf;
    let payloadWal = walBuf;

    const canDeltaWal = Boolean(
      prevGen
      && !opts.forceFull
      && prevGen.dbSha256 === dbSha256
      && walBuf.length >= (Number(prevGen.walBytes) || 0)
      && prevGen.baseGenerationId
      && prevGen.walSha256 === sha256Hex(walBuf.subarray(0, Number(prevGen.walBytes) || 0))
    );

    if (canDeltaWal && prevGen) {
      kind = 'wal_delta';
      baseGenerationId = prevGen.baseGenerationId;
      walOffset = Number(prevGen.walBytes) || 0;
      payloadMain = Buffer.alloc(0);
      payloadWal = walBuf.subarray(walOffset);
    }

    const packed = packFramePayload(payloadMain, payloadWal, walOffset);
    const aad = `cks1:${safeId}:${generationId}:${kind}`;
    const { envelope, compressedBytes, rawBytes } = encryptEnvelope(packed, opts.encryptionKey, aad);

    fs.mkdirSync(dbDir, { recursive: true, mode: 0o700 });
    const fileName = `${generationId}.cks1`;
    const filePath = assertContainedPath(dbDir, fileName);
    const tmpPath = `${filePath}.tmp`;
    fs.writeFileSync(tmpPath, envelope, { mode: 0o600 });
    fs.renameSync(tmpPath, filePath);

    /** @type {string | null} */
    let s3Key = null;
    if (opts.s3Client || opts.s3Config) {
      const s3 = opts.s3Client || new (getS3ClientClass())(opts.s3Config || undefined);
      const prefix = String((opts.s3Config && opts.s3Config.prefix) || 'snapstream').replace(/^\/+|\/+$/g, '');
      s3Key = `${prefix}/${safeId}/${fileName}`;
      await s3.putObject(s3Key, envelope, 'application/octet-stream', {
        checksumSha256: true,
        metadata: {
          db_id: safeId,
          generation_id: generationId,
          kind,
          sequence: String(sequence),
          db_sha256: dbSha256
        }
      });
    }

    const now = new Date().toISOString();
    const record = {
      generationId,
      sequence,
      kind,
      baseGenerationId,
      fileName,
      envelopeMagic: 'CKS1',
      aad,
      label: opts.label ? String(opts.label).slice(0, 80) : null,
      dbSha256,
      walSha256,
      dbBytes: mainBuf.length,
      walBytes: walBuf.length,
      walDeltaOffset: walOffset,
      walDeltaBytes: payloadWal.length,
      rawBytes,
      compressedBytes,
      encryptedBytes: envelope.length,
      envelopeSha256: sha256Hex(envelope),
      s3Key,
      createdAt: now
    };

    index.generations.push(record);
    this._saveIndex(dbDir, index);
    this._runtimeState.set(safeId, { lastCapturedAt: now, lastError: null, lastGenerationId: generationId });

    return {
      captured: true,
      skipped: false,
      dbId: safeId,
      filePath,
      ...record
    };
  }

  /**
   * Lista todas las generaciones registradas para una base de datos SQLite.
   * @param {string} dbId
   * @param {{ destDir?: string | null }} [opts]
   */
  listGenerations(dbId, opts = {}) {
    const dbDir = this._resolveDbDir(dbId, opts.destDir || null);
    const index = this._loadIndex(dbDir);
    return index.generations.map((g) => ({ ...g }));
  }

  /**
   * Restaura una base de datos SQLite a un punto en el tiempo exacto (generación por ID,
   * número de secuencia, timestamp ISO o la última disponible), descifrando y verificando
   * cada sobre `CKS1` AES-256-GCM y reproduciendo los `wal_delta` desde el snapshot base.
   *
   * @param {string} dbId
   * @param {string} targetPath
   * @param {{
   *   generation?: string | number | null,
   *   encryptionKey: Buffer | string,
   *   destDir?: string | null
   * }} opts
   */
  restorePointInTime(dbId, targetPath, opts) {
    const safeId = assertSafeDbId(dbId);
    if (!opts || !opts.encryptionKey) {
      throw new Error('restorePointInTime requiere encryptionKey');
    }
    const dbDir = this._resolveDbDir(safeId, opts.destDir || null);
    const index = this._loadIndex(dbDir);
    const gens = index.generations;
    if (!Array.isArray(gens) || gens.length === 0) {
      throw new Error(`No existen generaciones SnapStream para "${safeId}"`);
    }

    // Seleccionar generación objetivo
    /** @type {any} */
    let targetGen = null;
    if (opts.generation === undefined || opts.generation === null || opts.generation === '') {
      targetGen = gens[gens.length - 1];
    } else if (typeof opts.generation === 'number') {
      targetGen = gens.find((g) => g.sequence === opts.generation) || null;
    } else {
      const genQuery = String(opts.generation).trim();
      targetGen = gens.find((g) => g.generationId === genQuery || String(g.sequence) === genQuery) || null;
      if (!targetGen) {
        const targetTs = Date.parse(genQuery);
        if (!Number.isNaN(targetTs)) {
          const candidates = gens.filter((g) => Date.parse(g.createdAt) <= targetTs);
          targetGen = candidates.length > 0 ? candidates[candidates.length - 1] : null;
        }
      }
    }
    if (!targetGen) {
      throw new Error(`Generación "${String(opts.generation)}" no encontrada para "${safeId}"`);
    }

    // Construir cadena de reproducción: [snapshot base, ...wal_deltas hasta targetGen]
    const baseIdx = gens.findIndex((g) => g.generationId === targetGen.baseGenerationId);
    const targetIdx = gens.findIndex((g) => g.generationId === targetGen.generationId);
    if (baseIdx === -1 || targetIdx === -1 || baseIdx > targetIdx) {
      throw new Error(`Cadena de generaciones inconsistente para "${targetGen.generationId}"`);
    }

    /** @type {any[]} */
    const chain = [];
    for (let i = baseIdx; i <= targetIdx; i++) {
      const g = gens[i];
      if (i === baseIdx || (g.baseGenerationId === targetGen.baseGenerationId && g.kind === 'wal_delta')) {
        chain.push(g);
      }
    }

    /** @type {Buffer} */
    let restoredMain = Buffer.alloc(0);
    /** @type {Buffer[]} */
    const walParts = [];
    let currentWalLen = 0;

    for (const g of chain) {
      const frameFile = assertContainedPath(dbDir, String(g.fileName));
      if (!fs.existsSync(frameFile)) {
        throw new Error(`Frame SnapStream faltante en disco: ${g.fileName}`);
      }
      const envBuf = fs.readFileSync(frameFile);
      const expectedAad = `cks1:${safeId}:${g.generationId}:${g.kind}`;
      const plainPayload = decryptEnvelope(envBuf, opts.encryptionKey, expectedAad);
      const { mainBytes, walBytes, walOffset } = unpackFramePayload(plainPayload);

      if (g.kind === 'snapshot') {
        restoredMain = Buffer.from(mainBytes);
        walParts.length = 0;
        if (walBytes.length > 0) walParts.push(Buffer.from(walBytes));
        currentWalLen = walBytes.length;
      } else {
        if (walOffset !== currentWalLen) {
          throw new Error(`Desfase de offset WAL en generación "${g.generationId}" (${walOffset} != ${currentWalLen})`);
        }
        if (walBytes.length > 0) {
          walParts.push(Buffer.from(walBytes));
          currentWalLen += walBytes.length;
        }
      }
    }

    const restoredWal = walParts.length === 0
      ? Buffer.alloc(0)
      : (walParts.length === 1 ? walParts[0] : Buffer.concat(walParts));

    // Verificación final SHA-256 contra la generación solicitada
    const actualDbSha = sha256Hex(restoredMain);
    const actualWalSha = sha256Hex(restoredWal);
    if (actualDbSha !== targetGen.dbSha256) {
      throw new Error(`Verificación SHA-256 fallida al restaurar DB principal (${actualDbSha} != ${targetGen.dbSha256})`);
    }
    if (actualWalSha !== targetGen.walSha256) {
      throw new Error(`Verificación SHA-256 fallida al restaurar SQLite WAL (${actualWalSha} != ${targetGen.walSha256})`);
    }

    const resolvedTarget = path.resolve(String(targetPath || ''));
    fs.mkdirSync(path.dirname(resolvedTarget), { recursive: true });
    const mainTmp = `${resolvedTarget}.cks1restore.tmp`;
    fs.writeFileSync(mainTmp, restoredMain, { mode: 0o600 });
    fs.renameSync(mainTmp, resolvedTarget);

    const walTargetPath = `${resolvedTarget}-wal`;
    let walRestored = false;
    if (restoredWal.length > 0) {
      const walTmp = `${walTargetPath}.cks1restore.tmp`;
      fs.writeFileSync(walTmp, restoredWal, { mode: 0o600 });
      fs.renameSync(walTmp, walTargetPath);
      walRestored = true;
    } else if (fs.existsSync(walTargetPath)) {
      try { fs.unlinkSync(walTargetPath); } catch (e) {}
    }

    return {
      restored: true,
      dbId: safeId,
      generationId: targetGen.generationId,
      sequence: targetGen.sequence,
      kind: targetGen.kind,
      targetPath: resolvedTarget,
      walRestored,
      walPath: walRestored ? walTargetPath : null,
      dbBytes: restoredMain.length,
      walBytes: restoredWal.length,
      dbSha256: actualDbSha,
      walSha256: actualWalSha,
      framesReplayed: chain.length
    };
  }

  /**
   * Devuelve el estado de SnapStream para una BD concreta (o resumen global).
   * @param {string | null} [dbId]
   * @param {{ destDir?: string | null }} [opts]
   */
  getStatus(dbId = null, opts = {}) {
    if (!dbId) {
      const root = opts.destDir ? path.resolve(opts.destDir) : path.join(resolveDataDir(this._dataDirOverride), 'snapstream');
      /** @type {string[]} */
      let ids = [];
      if (fs.existsSync(root)) {
        ids = fs.readdirSync(root, { withFileTypes: true })
          .filter((d) => d.isDirectory() && DB_ID_RE.test(d.name))
          .map((d) => d.name);
      }
      const databases = ids.map((id) => this.getStatus(id, opts));
      return {
        enabled: true,
        format: 'CKS1',
        compression: 'brotli',
        cipher: 'aes-256-gcm',
        trackedDatabases: databases.length,
        databases
      };
    }

    const safeId = assertSafeDbId(dbId);
    const gens = this.listGenerations(safeId, opts);
    const latest = gens.length > 0 ? gens[gens.length - 1] : null;
    let totalRaw = 0;
    let totalEncrypted = 0;
    let snapshotCount = 0;
    let walDeltaCount = 0;
    for (const g of gens) {
      totalRaw += Number(g.rawBytes) || 0;
      totalEncrypted += Number(g.encryptedBytes) || 0;
      if (g.kind === 'wal_delta') walDeltaCount++;
      else snapshotCount++;
    }
    const rt = this._runtimeState.get(safeId) || null;
    return {
      dbId: safeId,
      format: 'CKS1',
      compression: 'brotli',
      cipher: 'aes-256-gcm',
      generationCount: gens.length,
      snapshotCount,
      walDeltaCount,
      totalRawBytes: totalRaw,
      totalEncryptedBytes: totalEncrypted,
      compressionRatio: totalEncrypted > 0 ? Number((totalRaw / totalEncrypted).toFixed(2)) : 1,
      latestGeneration: latest,
      lastCapturedAt: (latest && latest.createdAt) || (rt && rt.lastCapturedAt) || null,
      lastError: (rt && rt.lastError) || null
    };
  }
}

const instance = /** @type {any} */ (new SqliteStreamBackup());
instance.SqliteStreamBackup = SqliteStreamBackup;
instance.MAGIC_HEADER = MAGIC_HEADER;
instance.encryptEnvelope = encryptEnvelope;
instance.decryptEnvelope = decryptEnvelope;
instance.packFramePayload = packFramePayload;
instance.unpackFramePayload = unpackFramePayload;

module.exports = instance;
