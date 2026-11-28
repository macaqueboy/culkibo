const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Backup Envelope Key-Rotation & S3 WORM Object-Lock Verifier (100% Zero-Dep).
 *
 * Contramedida directa a `coollabsio/coolify#12211`/`#4774` (`mc pipe` sin `Content-MD5`
 * rechazado por S3 Object Lock) y `restic/restic#5411`/`#3491` (borrado de `locks/` fallando
 * en buckets WORM):
 *  - Audita políticas S3 Object Lock (`MISSING_CONTENT_MD5_WORM`, `WORM_LOCK_PREFIX_CONFLICT`,
 *    `APP_KEY_ESCROW_MISSING`, `INSUFFICIENT_WORM_RETENTION`).
 *  - Cifrado de sobre AES-256-GCM puro con `node:crypto` (`wrapBackupKey`, `rotateBackupKek`,
 *    `verifyEnvelopeUnwrap`): rota KEK `v1 → v2` con **`reuploadBytes: 0`** sin re-subir
 *    archivos multi-GB.
 *  - **CERO persistencia de material de claves (DEK/KEK)** en disco ni en auditorías!
 *
 * Persistencia atómica `0o600` (solo metadatos) en `CULKIBO_DATA_DIR/data/worm-backup-crypto.json`.
 */

const MAX_AUDITS = 200;

/**
 * Resuelve dinámicamente la ruta a `worm-backup-crypto.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'worm-backup-crypto.json')
    : path.join(base, 'data', 'worm-backup-crypto.json');
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
 * Carga auditorías metadatos desde disco (sin mutar si no existe).
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
 * Guarda auditorías metadatos de forma atómica (`0o600`).
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
 * Convierte una clave hex de 64 chars (32 bytes) en `Buffer` AES-256 (o deriva 32 bytes deterministas).
 * @param {string} keyHex
 * @returns {Buffer}
 */
function toAes256KeyBuffer(keyHex) {
  const s = String(keyHex || '').trim();
  if (!s) {
    const err = /** @type {any} */ (new Error('A non-empty 256-bit key is required.'));
    err.status = 400;
    err.code = 'MISSING_CRYPTO_KEY';
    throw err;
  }
  if (/^[a-f0-9]{64}$/i.test(s)) {
    return Buffer.from(s, 'hex');
  }
  return crypto.createHash('sha256').update(s, 'utf8').digest();
}

/**
 * Audita la configuración S3 WORM Object Lock, `Content-MD5`, prefijo `locks/` y escrow de `APP_KEY`.
 *
 * @param {{
 *   bucket?: string,
 *   objectLockMode?: 'COMPLIANCE' | 'GOVERNANCE' | 'NONE' | string,
 *   retentionDays?: number,
 *   streamingPipeNoMd5?: boolean,
 *   resticLocksInWormPrefix?: boolean,
 *   keyEscrowVerified?: boolean,
 *   persist?: boolean
 * }} [input]
 */
function auditWormBackupPolicy(input = {}) {
  const opts = input || {};
  const bucket = String(opts.bucket || 's3://culkibo-backups').trim() || 's3://culkibo-backups';
  const objectLockMode = String(opts.objectLockMode || 'NONE').trim().toUpperCase();
  const retentionDays = Math.max(0, Math.floor(Number(opts.retentionDays) || 0));
  const streamingPipeNoMd5 = Boolean(opts.streamingPipeNoMd5);
  const resticLocksInWormPrefix = Boolean(opts.resticLocksInWormPrefix);
  const keyEscrowVerified = Boolean(opts.keyEscrowVerified);

  /** @type {Array<{ code: string, severity: 'critical' | 'high', message: string, fix: string }>} */
  const findings = [];

  // 1. Streaming pipe missing Content-MD5 rejected on S3 Object Lock (Coolify#12211/#4774)
  if (streamingPipeNoMd5) {
    findings.push({
      code: 'MISSING_CONTENT_MD5_WORM',
      severity: 'critical',
      message: 'Streaming backup pipe omits Content-MD5 / x-amz-checksum-sha256 — S3 Object Lock buckets reject uploads with HTTP 400 MissingContentMD5 (Coolify#12211).',
      fix: 'Buffer archive chunks locally or compute SHA-256/Content-MD5 before PutObject when uploading to Object Lock buckets.'
    });
  }

  // 2. Restic locks/ prefix inside WORM bucket (Restic#5411/#3491)
  if (resticLocksInWormPrefix) {
    findings.push({
      code: 'WORM_LOCK_PREFIX_CONFLICT',
      severity: 'critical',
      message: 'Restic/Kopia mutable `locks/` prefix resides under WORM Object Lock retention — lock deletion will fail and deadlock prune/check jobs (Restic#5411).',
      fix: 'Place `data/` and `snapshots/` under WORM prefix while keeping mutable `locks/` on a separate non-WORM prefix or bucket.'
    });
  }

  // 3. APP_KEY / KEK offline escrow verification
  if (!keyEscrowVerified) {
    findings.push({
      code: 'APP_KEY_ESCROW_MISSING',
      severity: 'critical',
      message: 'Master APP_KEY / KEK escrow is unverified — losing the Culkibo host renders all encrypted backups permanently unrecoverable.',
      fix: 'Escrow the encrypted KEK recovery kit offline (HSM / Shamir / hardware password manager) and verify an unwrap drill.'
    });
  }

  // 4. Object Lock mode & minimum retention period
  if ((objectLockMode !== 'COMPLIANCE' && objectLockMode !== 'GOVERNANCE') || retentionDays < 7) {
    findings.push({
      code: 'INSUFFICIENT_WORM_RETENTION',
      severity: 'high',
      message: `Bucket "${bucket}" has objectLockMode=${objectLockMode} and retentionDays=${retentionDays} (requires COMPLIANCE or GOVERNANCE with >= 7 days).`,
      fix: 'Enable S3 Object Lock in COMPLIANCE or GOVERNANCE mode with retentionDays >= 7 (30d recommended for ransomware immunity).'
    });
  }

  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const safe = findings.length === 0;
  const blocked = !safe;
  const status = criticalCount > 0 ? 'CRITICAL' : (findings.length > 0 ? 'WARNING' : 'COMPLIANT');
  const auditedAt = new Date().toISOString();

  const record = {
    ok: true,
    id: `worm_${crypto.randomBytes(5).toString('hex')}`,
    type: 'policy_audit',
    bucket,
    objectLockMode,
    retentionDays,
    safe,
    blocked,
    status,
    findings,
    findingCodes: findings.map((f) => f.code),
    auditedAt
  };

  if (opts.persist !== false) {
    const store = loadStore();
    store.audits.push({
      id: record.id,
      type: record.type,
      bucket,
      objectLockMode,
      retentionDays,
      safe,
      status,
      findingCodes: record.findingCodes,
      auditedAt
    });
    saveStore(store);
  }

  return record;
}

/**
 * Envuelve una clave de datos (DEK) bajo una KEK usando AES-256-GCM con AAD versionado.
 * Nunca incluye la KEK ni la DEK en claro en el sobre devuelto.
 *
 * @param {{ dekHex: string, kekHex: string, kekVersion?: number, keyId?: string }} input
 */
function wrapBackupKey(input) {
  const opts = input || /** @type {any} */ ({});
  const dekBuf = toAes256KeyBuffer(opts.dekHex);
  const kekBuf = toAes256KeyBuffer(opts.kekHex);
  const kekVersion = Math.max(1, Math.floor(Number(opts.kekVersion ?? 1) || 1));
  const keyId = String(opts.keyId || `kek-v${kekVersion}`).trim();
  const aad = `culkibo-worm-kek-v${kekVersion}`;

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', kekBuf, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(dekBuf), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const dekSha256 = crypto.createHash('sha256').update(dekBuf).digest('hex');

  const envelope = {
    algorithm: 'aes-256-gcm',
    kekVersion,
    keyId,
    aad,
    ivHex: iv.toString('hex'),
    ciphertextHex: ciphertext.toString('hex'),
    authTagHex: authTag.toString('hex'),
    dekSha256,
    wrappedAt: new Date().toISOString()
  };

  return {
    ok: true,
    envelope
  };
}

/**
 * Desenvuelve y verifica la integridad autenticada AES-256-GCM de un sobre DEK/KEK.
 *
 * @param {{ envelope: any, kekHex: string }} input
 */
function verifyEnvelopeUnwrap(input) {
  const opts = input || /** @type {any} */ ({});
  const env = (opts.envelope && typeof opts.envelope === 'object') ? opts.envelope : null;
  if (!env || !env.ivHex || !env.ciphertextHex || !env.authTagHex) {
    return {
      ok: true,
      valid: false,
      code: 'INVALID_ENVELOPE',
      dekHex: null
    };
  }

  let kekBuf;
  try {
    kekBuf = toAes256KeyBuffer(opts.kekHex);
  } catch (e) {
    return { ok: true, valid: false, code: 'MISSING_CRYPTO_KEY', dekHex: null };
  }

  try {
    const iv = Buffer.from(String(env.ivHex), 'hex');
    const ciphertext = Buffer.from(String(env.ciphertextHex), 'hex');
    const authTag = Buffer.from(String(env.authTagHex), 'hex');
    const aad = String(env.aad || `culkibo-worm-kek-v${env.kekVersion || 1}`);

    const decipher = crypto.createDecipheriv('aes-256-gcm', kekBuf, iv);
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(authTag);
    const dekBuf = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const actualSha = crypto.createHash('sha256').update(dekBuf).digest('hex');

    if (env.dekSha256 && actualSha !== env.dekSha256) {
      return { ok: true, valid: false, code: 'DEK_DIGEST_MISMATCH', dekHex: null };
    }

    return {
      ok: true,
      valid: true,
      code: 'UNWRAPPED_VERIFIED',
      kekVersion: env.kekVersion || 1,
      dekHex: dekBuf.toString('hex'),
      dekSha256: actualSha
    };
  } catch (e) {
    return {
      ok: true,
      valid: false,
      code: 'KEK_AUTH_TAG_MISMATCH',
      dekHex: null
    };
  }
}

/**
 * Rota la KEK de un sobre (`v1 → v2`) re-envolviendo la misma DEK con `reuploadBytes: 0`
 * (sin re-subir backups multi-GB, `dryRun: true` por defecto; nunca guarda claves en disco!).
 *
 * @param {{
 *   envelope: any,
 *   oldKekHex: string,
 *   newKekHex: string,
 *   newKekVersion?: number,
 *   dryRun?: boolean
 * }} input
 */
function rotateBackupKek(input) {
  const opts = input || /** @type {any} */ ({});
  const dryRun = opts.dryRun !== undefined ? Boolean(opts.dryRun) : true;
  const oldEnv = opts.envelope;
  const unwrapped = verifyEnvelopeUnwrap({ envelope: oldEnv, kekHex: opts.oldKekHex });

  if (!unwrapped.valid || !unwrapped.dekHex) {
    return {
      ok: false,
      blocked: true,
      code: 'OLD_KEK_INVALID',
      status: 400,
      reuploadBytes: 0,
      message: 'Failed to unwrap existing backup envelope with oldKekHex.'
    };
  }

  const prevVer = Number(oldEnv && oldEnv.kekVersion) || 1;
  const nextVer = Math.max(prevVer + 1, Math.floor(Number(opts.newKekVersion) || (prevVer + 1)));
  const rewrapped = wrapBackupKey({
    dekHex: unwrapped.dekHex,
    kekHex: opts.newKekHex,
    kekVersion: nextVer,
    keyId: `kek-v${nextVer}`
  });
  const rotatedAt = new Date().toISOString();

  if (!dryRun) {
    const store = loadStore();
    store.audits.push({
      id: `rot_${crypto.randomBytes(5).toString('hex')}`,
      type: 'kek_rotation',
      previousKekVersion: prevVer,
      newKekVersion: nextVer,
      dekSha256: rewrapped.envelope.dekSha256,
      reuploadBytes: 0,
      rotatedAt
    });
    saveStore(store);
  }

  return {
    ok: true,
    dryRun,
    persisted: !dryRun,
    previousKekVersion: prevVer,
    newKekVersion: nextVer,
    reuploadBytes: 0,
    envelope: rewrapped.envelope,
    rotatedAt
  };
}

/**
 * Lista auditorías WORM y rotaciones KEK registradas (metadatos únicamente, más recientes primero).
 */
function listWormAudits() {
  const store = loadStore();
  return [...store.audits].reverse();
}

module.exports = {
  auditWormBackupPolicy,
  wrapBackupKey,
  rotateBackupKek,
  verifyEnvelopeUnwrap,
  listWormAudits
};
