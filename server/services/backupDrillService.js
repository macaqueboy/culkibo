const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');
const zlib = require('zlib');

const { atomicWriteJsonSync } = require('./ssrfGuard');

/**
 * Automated DR Backup Restore Fire-Drill Verifier
 * (cures `dokploy#1382`, `coolify#6506`, `coolify#12244`, `dokploy#6035`).
 *
 * Garantías:
 *  - 0 dependencias npm externas (`crypto`, `fs`, `path`, `perf_hooks`, `zlib`).
 *  - 0 invocaciones de shell (`shell: false`).
 *  - Detecta volcados silenciosamente vacíos (`0 B`, `<= 64 B`, o archivos `.gz` vacíos de 20 bytes).
 *  - Verifica SHA-256 opcional en tiempo constante, descifrado AES-256-GCM, descompresión
 *    gzip segura (con cota anti-gzip-bomb), estructura DDL SQL, preservación de ACL/GRANT
 *    (`coolify#12244`), incompatibilidad de downgrade de versión mayor, y restaura cross-target
 *    autorizada dentro de la misma organización (`dokploy#6035`, bloqueando cross-org con `403`).
 */

const MIN_VALID_BACKUP_BYTES = 65;
const MAX_GUNZIP_BYTES = 64 * 1024 * 1024;
const MAX_DRILL_HISTORY = 100;
const SAFE_IDENT_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/;

/** @param {string | null} [overrideDir] */
function resolveDataDir(overrideDir = null) {
  if (overrideDir) return path.resolve(overrideDir);
  if (process.env.CULKIBO_DATA_DIR) {
    return path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data');
  }
  return path.resolve(__dirname, '..', '..', 'data');
}

/** @param {string} val @param {string} label */
function assertSafeId(val, label) {
  const clean = String(val || '').trim();
  if (!clean || !SAFE_IDENT_RE.test(clean) || clean.includes('..')) {
    const err = new Error(`Identificador inválido para ${label}: "${clean.slice(0, 60)}"`);
    /** @type {any} */ (err).status = 400;
    throw err;
  }
  return clean;
}

/**
 * Verifica la estructura DDL/DML y la preservación de privilegios (`GRANT`/`OWNER`)
 * en el contenido SQL descomprimido de un backup.
 *
 * @param {string} sqlText
 * @param {{ engine?: string, preserveAcl?: boolean }} [opts]
 */
function verifySqlDumpContent(sqlText, opts = {}) {
  const text = String(sqlText || '');
  const engine = String(opts.engine || 'postgres').toLowerCase();
  const preserveAcl = opts.preserveAcl !== false;

  /** @type {string[]} */
  const markers = [];
  /** @type {string[]} */
  const warnings = [];
  /** @type {string[]} */
  const errors = [];

  if (text.trim().length < 24) {
    errors.push('EMPTY_OR_TRUNCATED_DUMP: Decompressed SQL content is empty or truncated (<24 chars).');
    return {
      validSql: false,
      markers,
      tableCount: 0,
      hasGrantOrAcl: false,
      aclStripped: false,
      warnings,
      errors
    };
  }

  /** @type {Array<[string, RegExp]>} */
  const markerChecks = [
    ['PostgreSQL database dump', /PostgreSQL database dump/i],
    ['MySQL/MariaDB dump', /(?:MySQL|MariaDB)\s+dump/i],
    ['CREATE TABLE', /\bCREATE\s+TABLE\b/i],
    ['CREATE SCHEMA', /\bCREATE\s+SCHEMA\b/i],
    ['INSERT INTO', /\bINSERT\s+INTO\b/i],
    ['COPY', /\bCOPY\s+[\w."]+\s*\(/i],
    ['BEGIN TRANSACTION', /\bBEGIN\s+TRANSACTION\b/i]
  ];

  for (const [label, re] of markerChecks) {
    if (re.test(text)) markers.push(label);
  }

  const tableMatches = text.match(/\bCREATE\s+TABLE\b/gi);
  const tableCount = tableMatches ? tableMatches.length : 0;

  if (markers.length === 0) {
    errors.push('INVALID_SQL_STRUCTURE: Backup payload does not contain recognizable SQL DDL/DML markers.');
  }

  const hasExplicitNoAcl = /--no-acl|--no-privileges/i.test(text);
  const hasGrantOrAcl = /\b(?:GRANT|REVOKE)\s+/i.test(text) || /\bALTER\s+\w+\s+[^\n;]*\bOWNER\s+TO\b/i.test(text);
  const aclStripped = hasExplicitNoAcl || (preserveAcl && (engine === 'postgres' || engine === 'postgresql') && !hasGrantOrAcl);

  if (preserveAcl && aclStripped) {
    warnings.push(
      hasExplicitNoAcl
        ? 'ACL_STRIPPED_WARNING: Dump explicitly contains --no-acl/--no-privileges while preserveAcl=true (coolify#12244 risk for Supabase/RLS roles).'
        : 'ACL_STRIPPED_WARNING: No GRANT/OWNER statements detected in PostgreSQL dump while preserveAcl=true (verify Supabase/RLS role ACLs).'
    );
  }

  return {
    validSql: errors.length === 0,
    markers,
    tableCount,
    hasGrantOrAcl,
    aclStripped,
    warnings,
    errors
  };
}

/**
 * Planifica una restauración cross-target (p. ej. prod → staging/dev, curando `dokploy#6035`)
 * dentro de la misma organización con bloqueo estricto cross-org (`403 CROSS_ORG_RESTORE_FORBIDDEN`)
 * y preservación de ACLs por defecto (`coolify#12244`).
 *
 * @param {{
 *   sourceDatabaseId: string,
 *   targetDatabaseId: string,
 *   sourceOrgId: string,
 *   targetOrgId: string,
 *   engine?: string,
 *   preserveAcl?: boolean,
 *   sourceContainer?: string,
 *   targetContainer?: string,
 *   dbUser?: string,
 *   dbName?: string
 * }} opts
 */
function planCrossTargetRestore(opts) {
  const sourceDatabaseId = assertSafeId(opts && opts.sourceDatabaseId, 'sourceDatabaseId');
  const targetDatabaseId = assertSafeId(opts && opts.targetDatabaseId, 'targetDatabaseId');
  const sourceOrgId = assertSafeId(opts && opts.sourceOrgId, 'sourceOrgId');
  const targetOrgId = assertSafeId(opts && opts.targetOrgId, 'targetOrgId');

  if (sourceOrgId !== targetOrgId) {
    const err = new Error(
      `Cross-organization database restore forbidden (${sourceOrgId} -> ${targetOrgId})`
    );
    /** @type {any} */ (err).status = 403;
    /** @type {any} */ (err).code = 'CROSS_ORG_RESTORE_FORBIDDEN';
    throw err;
  }

  const engine = String((opts && opts.engine) || 'postgres').trim().toLowerCase();
  const preserveAcl = opts && opts.preserveAcl !== undefined ? Boolean(opts.preserveAcl) : true;
  const sourceContainer = assertSafeId((opts && opts.sourceContainer) || `culkibo_db_${sourceDatabaseId}`, 'sourceContainer');
  const targetContainer = assertSafeId((opts && opts.targetContainer) || `culkibo_db_${targetDatabaseId}`, 'targetContainer');
  const dbUser = assertSafeId((opts && opts.dbUser) || (engine.includes('mysql') || engine.includes('maria') ? 'root' : 'postgres'), 'dbUser');
  const dbName = assertSafeId((opts && opts.dbName) || 'app', 'dbName');

  /** @type {string[]} */
  let dumpArgs;
  /** @type {string[]} */
  let restoreArgs;

  if (engine === 'mysql' || engine === 'mariadb') {
    const dumpBin = engine === 'mariadb' ? 'mariadb-dump' : 'mysqldump';
    const restoreBin = engine === 'mariadb' ? 'mariadb' : 'mysql';
    dumpArgs = ['exec', '-i', sourceContainer, dumpBin, '-u', dbUser, '--single-transaction', '--routines', '--triggers', dbName];
    restoreArgs = ['exec', '-i', targetContainer, restoreBin, '-u', dbUser, dbName];
  } else {
    dumpArgs = ['exec', '-i', sourceContainer, 'pg_dump', '-U', dbUser, '-d', dbName, '-F', 'c'];
    restoreArgs = ['exec', '-i', targetContainer, 'pg_restore', '-U', dbUser, '-d', dbName, '--clean', '--if-exists'];
    // Incluir --no-acl ÚNICAMENTE cuando preserveAcl === false (cura coolify#12244)
    if (!preserveAcl) {
      dumpArgs.push('--no-acl', '--no-owner');
      restoreArgs.push('--no-acl', '--no-owner');
    }
  }

  return {
    ok: true,
    allowed: true,
    crossTargetAuthorized: true,
    orgId: sourceOrgId,
    sourceDatabaseId,
    targetDatabaseId,
    engine,
    preserveAcl,
    zeroShell: true,
    dumpCommand: { program: 'docker', args: dumpArgs },
    restoreCommand: { program: 'docker', args: restoreArgs },
    warnings: preserveAcl
      ? []
      : ['preserveAcl=false: GRANT/OWNER ACL statements will be omitted on restore.']
  };
}

class BackupDrillService {
  /**
   * @param {{ dataDir?: string | null }} [opts]
   */
  constructor(opts = {}) {
    this._dataDirOverride = opts.dataDir || null;
    this._loaded = false;
    /** @type {{ version: number, drills: any[] }} */
    this.state = { version: 1, drills: [] };
  }

  get dataDir() {
    return resolveDataDir(this._dataDirOverride);
  }

  get storeFile() {
    return path.join(this.dataDir, 'dr-drills.json');
  }

  _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;
    const bakFile = `${this.storeFile}.bak`;
    for (const candidate of [this.storeFile, bakFile]) {
      try {
        if (!fs.existsSync(candidate)) continue;
        const parsed = JSON.parse(fs.readFileSync(candidate, 'utf8'));
        if (parsed && typeof parsed === 'object' && Array.isArray(parsed.drills)) {
          this.state = { version: 1, drills: parsed.drills };
          return;
        }
      } catch (e) {}
    }
    this.state = { version: 1, drills: [] };
  }

  _save() {
    this._ensureLoaded();
    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    if (fs.existsSync(this.storeFile)) {
      try { fs.copyFileSync(this.storeFile, `${this.storeFile}.bak`); } catch (e) {}
    }
    atomicWriteJsonSync(this.storeFile, this.state, 0o600);
  }

  /**
   * Ejecuta un simulacro automatizado de restauración DR verificando tamaño, SHA-256,
   * descifrado AES-256-GCM opcional, descompresión gzip, estructura DDL SQL, ACLs y
   * compatibilidad de versión mayor; persiste el Scorecard atómicamente.
   *
   * @param {{
   *   databaseId: string,
   *   projectId?: string,
   *   engine?: string,
   *   artifactBuffer?: Buffer | Uint8Array | string,
   *   artifactBase64?: string,
   *   sqlSample?: string,
   *   artifactPath?: string,
   *   expectedSha256?: string | null,
   *   encryptedKeyHex?: string | null,
   *   ivHex?: string | null,
   *   authTagHex?: string | null,
   *   preserveAcl?: boolean,
   *   sourceMajorVersion?: number | null,
   *   targetMajorVersion?: number | null,
   *   createdAt?: string | number | null,
   *   onAlert?: (scorecard: any) => any
   * }} opts
   */
  async runFireDrill(opts) {
    const t0 = performance.now();
    const databaseId = assertSafeId((opts && opts.databaseId) || 'db_default', 'databaseId');
    const projectId = opts && opts.projectId ? String(opts.projectId).trim().slice(0, 80) : '';
    const engine = String((opts && opts.engine) || 'postgres').trim().toLowerCase();
    const preserveAcl = opts && opts.preserveAcl !== undefined ? Boolean(opts.preserveAcl) : true;

    /** @type {Array<{ check: string, ok: boolean, code?: string, detail: string }>} */
    const checks = [];
    /** @type {string[]} */
    const warnings = [];
    /** @type {string[]} */
    const errors = [];

    // 1. Cargar bytes del artefacto
    /** @type {Buffer} */
    let rawBuf = Buffer.alloc(0);
    if (opts && opts.artifactBuffer != null) {
      rawBuf = Buffer.isBuffer(opts.artifactBuffer)
        ? opts.artifactBuffer
        : (typeof opts.artifactBuffer === 'string'
            ? Buffer.from(opts.artifactBuffer, 'utf8')
            : Buffer.from(opts.artifactBuffer));
    } else if (opts && typeof opts.artifactBase64 === 'string') {
      rawBuf = Buffer.from(opts.artifactBase64, 'base64');
    } else if (opts && typeof opts.sqlSample === 'string') {
      rawBuf = Buffer.from(opts.sqlSample, 'utf8');
    } else if (opts && opts.artifactPath) {
      const abs = path.resolve(String(opts.artifactPath));
      if (!fs.existsSync(abs)) {
        errors.push(`ARTIFACT_NOT_FOUND: Backup file not found at ${abs}`);
      } else {
        rawBuf = fs.readFileSync(abs);
      }
    } else {
      errors.push('EMPTY_OR_TRUNCATED_DUMP: No backup artifactBuffer, artifactPath, or sqlSample provided.');
    }

    const bytesVerified = rawBuf.length;
    const sha256 = crypto.createHash('sha256').update(rawBuf).digest('hex');

    // 2. Comprobación de tamaño mínimo (atrapa 0 B, <= 64 B y gzip vacíos de 20 B — dokploy#1382, coolify#6506)
    if (errors.length === 0) {
      if (rawBuf.length === 0 || rawBuf.length < MIN_VALID_BACKUP_BYTES) {
        checks.push({
          check: 'min_size',
          ok: false,
          code: 'EMPTY_OR_TRUNCATED_DUMP',
          detail: `Artifact is ${rawBuf.length} B (< ${MIN_VALID_BACKUP_BYTES} B minimum valid dump threshold).`
        });
        errors.push(`EMPTY_OR_TRUNCATED_DUMP: Backup payload is too small (${rawBuf.length} bytes).`);
      } else {
        checks.push({
          check: 'min_size',
          ok: true,
          detail: `Artifact size ${rawBuf.length} B meets minimum threshold.`
        });
      }
    }

    // 3. Verificación SHA-256 en tiempo constante
    if (opts && opts.expectedSha256) {
      const expected = String(opts.expectedSha256).trim().toLowerCase();
      const match = expected.length === 64
        && /^[a-f0-9]{64}$/.test(expected)
        && crypto.timingSafeEqual(Buffer.from(sha256, 'hex'), Buffer.from(expected, 'hex'));
      if (!match) {
        checks.push({
          check: 'sha256',
          ok: false,
          code: 'CHECKSUM_MISMATCH',
          detail: `SHA-256 mismatch: actual ${sha256.slice(0, 16)} != expected ${expected.slice(0, 16)}.`
        });
        errors.push('CHECKSUM_MISMATCH: Backup artifact SHA-256 does not match expected digest.');
      } else {
        checks.push({ check: 'sha256', ok: true, detail: 'SHA-256 checksum verified.' });
      }
    }

    // 4. Descifrado AES-256-GCM opcional
    let workingBuf = rawBuf;
    if (errors.length === 0 && opts && opts.encryptedKeyHex) {
      try {
        const key = Buffer.from(String(opts.encryptedKeyHex).trim(), 'hex');
        if (key.length !== 32) throw new Error('Encryption key must be 32 bytes (64 hex chars)');
        let iv;
        let tag;
        let ct;
        if (opts.ivHex && opts.authTagHex) {
          iv = Buffer.from(String(opts.ivHex).trim(), 'hex');
          tag = Buffer.from(String(opts.authTagHex).trim(), 'hex');
          ct = workingBuf;
        } else {
          if (workingBuf.length < 29) throw new Error('Encrypted payload too short for iv+tag');
          iv = workingBuf.subarray(0, 12);
          tag = workingBuf.subarray(12, 28);
          ct = workingBuf.subarray(28);
        }
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        workingBuf = Buffer.concat([decipher.update(ct), decipher.final()]);
        checks.push({ check: 'aes_256_gcm_decrypt', ok: true, detail: `Decrypted ${workingBuf.length} B payload cleanly.` });
      } catch (decErr) {
        checks.push({ check: 'aes_256_gcm_decrypt', ok: false, code: 'DECRYPT_FAILED', detail: decErr.message });
        errors.push(`DECRYPT_FAILED: AES-256-GCM decryption failed (${decErr.message}).`);
      }
    }

    // 5. Auto-detección y descompresión gzip segura (0x1f 0x8b)
    let uncompressedBytes = workingBuf.length;
    if (errors.length === 0 && workingBuf.length >= 2 && workingBuf[0] === 0x1f && workingBuf[1] === 0x8b) {
      try {
        workingBuf = zlib.gunzipSync(workingBuf, { maxOutputLength: MAX_GUNZIP_BYTES });
        uncompressedBytes = workingBuf.length;
        if (uncompressedBytes < MIN_VALID_BACKUP_BYTES) {
          checks.push({
            check: 'gunzip',
            ok: false,
            code: 'EMPTY_OR_TRUNCATED_DUMP',
            detail: `Gzip stream decompressed to only ${uncompressedBytes} B.`
          });
          errors.push(`EMPTY_OR_TRUNCATED_DUMP: Decompressed gzip payload is empty/truncated (${uncompressedBytes} B).`);
        } else {
          checks.push({ check: 'gunzip', ok: true, detail: `Decompressed gzip stream cleanly (${uncompressedBytes} B).` });
        }
      } catch (gzErr) {
        checks.push({ check: 'gunzip', ok: false, code: 'CORRUPT_GZIP', detail: gzErr.message });
        errors.push(`CORRUPT_GZIP: Gzip decompression failed (${gzErr.message}).`);
      }
    }

    // 6. Verificación de contenido SQL / SQLite
    if (errors.length === 0) {
      const isSqliteHeader = engine === 'sqlite'
        && workingBuf.length >= 100
        && workingBuf.subarray(0, 16).toString('utf8') === 'SQLite format 3\0';
      if (isSqliteHeader) {
        checks.push({ check: 'sqlite_header', ok: true, detail: 'Valid SQLite format 3 binary header verified.' });
      } else {
        const sqlCheck = verifySqlDumpContent(workingBuf.toString('utf8'), { engine, preserveAcl });
        warnings.push(...sqlCheck.warnings);
        errors.push(...sqlCheck.errors);
        checks.push({
          check: 'sql_ddl_structure',
          ok: sqlCheck.validSql,
          code: sqlCheck.validSql ? undefined : 'INVALID_SQL_STRUCTURE',
          detail: sqlCheck.validSql
            ? `Verified SQL markers [${sqlCheck.markers.join(', ')}] (${sqlCheck.tableCount} CREATE TABLE).`
            : sqlCheck.errors.join('; ')
        });
      }
    }

    // 7. Compatibilidad de versión mayor (flag downgrade)
    if (opts && opts.sourceMajorVersion != null && opts.targetMajorVersion != null) {
      const srcMaj = Number(opts.sourceMajorVersion);
      const tgtMaj = Number(opts.targetMajorVersion);
      if (Number.isFinite(srcMaj) && Number.isFinite(tgtMaj) && tgtMaj < srcMaj) {
        warnings.push(`MAJOR_VERSION_MISMATCH: Target major version (${tgtMaj}) is lower than source (${srcMaj}); pg_restore/dump downgrade may fail.`);
        checks.push({
          check: 'major_version',
          ok: false,
          code: 'MAJOR_VERSION_MISMATCH',
          detail: `Downgrade detected: v${srcMaj} -> v${tgtMaj}.`
        });
      } else {
        checks.push({ check: 'major_version', ok: true, detail: `Compatible major versions (v${srcMaj} -> v${tgtMaj}).` });
      }
    }

    const rtoMs = Number((performance.now() - t0).toFixed(3));
    const createdMs = opts && opts.createdAt ? Date.parse(String(opts.createdAt)) : NaN;
    const rpoSec = Number.isFinite(createdMs) ? Math.max(0, Math.round((Date.now() - createdMs) / 1000)) : 0;
    const verdict = errors.length === 0 ? 'PASS' : 'FAIL';

    const scorecard = {
      id: `drill_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`,
      databaseId,
      projectId,
      engine,
      verdict,
      rtoMs,
      rpoSec,
      bytesVerified,
      uncompressedBytes,
      sha256,
      preserveAcl,
      checks,
      warnings,
      errors,
      executedAt: new Date().toISOString()
    };

    this._ensureLoaded();
    this.state.drills.unshift(scorecard);
    if (this.state.drills.length > MAX_DRILL_HISTORY) {
      this.state.drills = this.state.drills.slice(0, MAX_DRILL_HISTORY);
    }
    this._save();

    if (verdict === 'FAIL' && opts && typeof opts.onAlert === 'function') {
      try {
        await opts.onAlert(scorecard);
      } catch (e) {}
    }

    return { ok: true, ...scorecard };
  }

  /**
   * Lista el historial de DR Drill Scorecards (filtrable por `databaseId` y/o `allowedProjectIds`).
   * @param {string | { databaseId?: string | null, allowedProjectIds?: string[] | Set<string> | null } | null} [databaseIdOrOpts]
   */
  listDrills(databaseIdOrOpts = null) {
    this._ensureLoaded();
    /** @type {string | null} */
    let databaseId = null;
    /** @type {Set<string> | null} */
    let allowedSet = null;

    if (typeof databaseIdOrOpts === 'string' && databaseIdOrOpts.trim()) {
      databaseId = databaseIdOrOpts.trim();
    } else if (databaseIdOrOpts && typeof databaseIdOrOpts === 'object') {
      if (databaseIdOrOpts.databaseId) databaseId = String(databaseIdOrOpts.databaseId).trim();
      if (databaseIdOrOpts.allowedProjectIds != null) {
        allowedSet = new Set(Array.from(databaseIdOrOpts.allowedProjectIds).map(String));
      }
    }

    const filtered = this.state.drills.filter((d) => {
      if (!d) return false;
      if (databaseId && d.databaseId !== databaseId) return false;
      if (allowedSet && d.projectId && !allowedSet.has(String(d.projectId))) return false;
      return true;
    });

    return {
      ok: true,
      count: filtered.length,
      drills: filtered
    };
  }

  /** @param {any} opts */
  planCrossTargetRestore(opts) {
    return planCrossTargetRestore(opts);
  }
}

const instance = /** @type {any} */ (new BackupDrillService());
instance.BackupDrillService = BackupDrillService;
instance.MIN_VALID_BACKUP_BYTES = MIN_VALID_BACKUP_BYTES;
instance.verifySqlDumpContent = verifySqlDumpContent;
instance.planCrossTargetRestore = planCrossTargetRestore;
module.exports = instance;
