const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Registro de auditoría del plano de control a prueba de manipulaciones (cero dependencias externas).
 *
 * Combina:
 * - Anillo en memoria acotado (250 entradas) para consultas instantáneas en UI/API.
 * - Archivo JSONL append-only `data/audit.jsonl` con permisos `0o600` y rotación
 *   automática al superar 5 MB (conserva `.1`) con registro ancla encadenado.
 * - Cadena criptográfica SHA-256 (`seq` + `prevHash` + `entryHash`) verificable
 *   mediante `verifyIntegrity()` (prueba matemática de cero manipulación o borrado).
 * - Metadatos de actor (`userId`, `email`, `role`, `teamId`, `tokenId`, `kind`) y
 *   redacción automática de secretos para no filtrar jamás tokens ni contraseñas.
 */

const MAX_RING_ENTRIES = 250;
const MAX_FILE_BYTES = 5 * 1024 * 1024;
const GENESIS_HASH = '0'.repeat(64);
const SENSITIVE_KEY_RE = /(token|secret|password|passwd|apikey|api_key|privatekey|private_key|authorization|cookie|passphrase|credential)/i;

/**
 * Serialización JSON canónica y determinista (ordena claves recursivamente, omite `undefined`).
 * @param {any} value
 * @returns {string}
 */
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((v) => (v === undefined ? 'null' : canonicalJson(v))).join(',') + ']';
  }
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return '{' + keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',') + '}';
}

/**
 * Calcula el hash SHA-256 de una entrada encadenada a `prevHash`.
 * @param {string} prevHash
 * @param {Record<string, any>} entryWithoutHash
 * @returns {string}
 */
function computeEntryHash(prevHash, entryWithoutHash) {
  return crypto
    .createHash('sha256')
    .update(`${String(prevHash || GENESIS_HASH)}\n${canonicalJson(entryWithoutHash)}`, 'utf8')
    .digest('hex');
}

/** Redacta secretos incrustados dentro de cadenas libres (Bearer, PATs, AWS, Stripe, GCP, JWT, URLs con credenciales, PEM). */
function redactInlineSecrets(str) {
  let s = str;
  s = s.replace(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, '[REDACTED_PEM]');
  s = s.replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, '$1[REDACTED]');
  s = s.replace(/\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g, '[REDACTED]');
  s = s.replace(/\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,99}\b/g, '[REDACTED]');
  s = s.replace(/\bwhsec_[0-9A-Za-z]{16,128}\b/g, '[REDACTED]');
  s = s.replace(/\bAIza[0-9A-Za-z_-]{35}\b/g, '[REDACTED]');
  s = s.replace(/\bnpm_[A-Za-z0-9]{20,}\b/g, '[REDACTED]');
  s = s.replace(/\b(gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|glpat-[A-Za-z0-9_-]{12,}|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{12,}|ckh_[a-f0-9]{16,}|ck[stihpm]_[A-Za-z0-9._-]{12,})\b/g, '[REDACTED]');
  s = s.replace(/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{12,}\b/g, '[REDACTED_JWT]');
  s = s.replace(/((?:https?|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?):\/\/[^:\s/@]+:)([^@\s/]+)(@)/gi, '$1[REDACTED]$3');
  s = s.replace(/([?&](?:token|key|secret|password|passwd|api_key|apikey|access_token)=)[^&\s]+/gi, '$1[REDACTED]');
  return s;
}

/** @param {any} value @param {number} [depth] */
function sanitizeDetail(value, depth = 0) {
  if (value == null) return value;
  if (depth > 3) return '[truncated]';
  if (typeof value === 'string') {
    const clean = redactInlineSecrets(value);
    return clean.length > 300 ? `${clean.slice(0, 300)}...` : clean;
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) {
    return value.slice(0, 20).map((item) => sanitizeDetail(item, depth + 1));
  }
  if (typeof value === 'object') {
    /** @type {Record<string, any>} */
    const out = {};
    for (const [k, v] of Object.entries(value).slice(0, 24)) {
      if (SENSITIVE_KEY_RE.test(k)) {
        out[k] = '[REDACTED]';
      } else {
        out[k] = sanitizeDetail(v, depth + 1);
      }
    }
    return out;
  }
  return String(value).slice(0, 120);
}

/**
 * Extrae metadatos seguros del actor (sin tokens ni secretos).
 * @param {any} rawActor
 * @returns {{ userId: string | null, email: string | null, role: string | null, teamId: string | null, tokenId: string | null, kind: string | null } | null}
 */
function sanitizeActor(rawActor) {
  if (!rawActor) return null;
  if (typeof rawActor === 'string') {
    const clean = redactInlineSecrets(rawActor).slice(0, 120);
    return { userId: null, email: clean.includes('@') ? clean : null, role: null, teamId: null, tokenId: null, kind: clean };
  }
  if (typeof rawActor !== 'object') return null;
  const src = rawActor.principal && typeof rawActor.principal === 'object' ? rawActor.principal : rawActor;
  return {
    userId: src.userId ? String(src.userId).slice(0, 64) : null,
    email: src.email ? String(src.email).slice(0, 120) : null,
    role: src.role ? String(src.role).slice(0, 32) : null,
    teamId: src.teamId ? String(src.teamId).slice(0, 64) : null,
    tokenId: src.tokenId ? String(src.tokenId).slice(0, 64) : null,
    kind: src.kind ? String(src.kind).slice(0, 32) : null
  };
}

class AuditLogger {
  /**
   * @param {{ dataDir?: string, maxFileBytes?: number, maxRingEntries?: number, disableDisk?: boolean }} [options]
   */
  constructor(options = {}) {
    this._explicitDataDir = options.dataDir ? path.resolve(options.dataDir) : null;
    this.maxFileBytes = Math.max(512, Number(options.maxFileBytes) || MAX_FILE_BYTES);
    this.maxRingEntries = Math.max(10, Number(options.maxRingEntries) || MAX_RING_ENTRIES);
    this._disableDiskOverride = typeof options.disableDisk === 'boolean' ? options.disableDisk : null;

    /** @type {Array<Record<string, any>>} */
    this.ring = [];
    /** @type {string[]} */
    this._pendingLines = [];
    /** @type {ReturnType<typeof setTimeout> | null} */
    this._flushTimer = null;
    this._loaded = false;
    this._lastSeq = 0;
    this._lastHash = GENESIS_HASH;
  }

  _getPaths() {
    const dataDir = this._explicitDataDir || (
      process.env.CULKIBO_DATA_DIR
        ? path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data')
        : path.resolve(__dirname, '..', '..', 'data')
    );
    return {
      dataDir,
      auditFile: path.join(dataDir, 'audit.jsonl'),
      rotatedFile: path.join(dataDir, 'audit.jsonl.1')
    };
  }

  _isDiskDisabled() {
    if (this._disableDiskOverride !== null) return this._disableDiskOverride;
    if (this._explicitDataDir) return false;
    return process.env.CULKIBO_DISABLE_AUDIT_DISK === '1';
  }

  _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;
    try {
      const { auditFile } = this._getPaths();
      if (!fs.existsSync(auditFile)) return;
      const raw = fs.readFileSync(auditFile, 'utf8');
      const lines = raw.split(/\r?\n/).filter(Boolean);
      const tail = lines.slice(-this.maxRingEntries);
      for (const line of tail) {
        try {
          const parsed = JSON.parse(line);
          if (parsed && typeof parsed === 'object') {
            this.ring.push(parsed);
          }
        } catch (e) {}
      }
      // Restaurar cabeza de la cadena (seq + entryHash) desde el último registro válido en disco
      for (let i = lines.length - 1; i >= 0; i--) {
        try {
          const parsed = JSON.parse(lines[i]);
          if (parsed && typeof parsed === 'object') {
            if (typeof parsed.seq === 'number' && Number.isInteger(parsed.seq) && parsed.seq > 0) {
              this._lastSeq = parsed.seq;
            }
            if (typeof parsed.entryHash === 'string' && /^[a-f0-9]{64}$/.test(parsed.entryHash)) {
              this._lastHash = parsed.entryHash;
            }
            break;
          }
        } catch (e) {}
      }
    } catch (e) {}
  }

  /**
   * Construye, encadena con SHA-256 (`prevHash` -> `entryHash`) y añade un registro al anillo.
   * @param {Record<string, any>} baseFields
   */
  _chainEntry(baseFields) {
    const seq = this._lastSeq + 1;
    const prevHash = this._lastHash;
    /** @type {Record<string, any>} */
    const unsigned = {
      id: `aud_${Date.now().toString(36)}_${crypto.randomBytes(3).toString('hex')}`,
      seq,
      timestamp: new Date().toISOString(),
      ...baseFields,
      prevHash
    };
    // Limpiar campos undefined antes de hashear para mantener paridad exacta tras JSON.parse
    for (const k of Object.keys(unsigned)) {
      if (unsigned[k] === undefined) delete unsigned[k];
    }
    const entryHash = computeEntryHash(prevHash, unsigned);
    const record = { ...unsigned, entryHash };
    this._lastSeq = seq;
    this._lastHash = entryHash;

    this.ring.push(record);
    if (this.ring.length > this.maxRingEntries) {
      this.ring.shift();
    }
    return record;
  }

  /**
   * Registra un evento de auditoría encadenado criptográficamente con SHA-256.
   * @param {{
   *   source?: 'http' | 'ws' | 'mcp' | 'system' | 'auth',
   *   action: string,
   *   method?: string | null,
   *   path?: string | null,
   *   resourceId?: string | null,
   *   ip?: string | null,
   *   authMethod?: string | null,
   *   actor?: any,
   *   principal?: any,
   *   status?: number | string | null,
   *   durationMs?: number | null,
   *   detail?: any
   * }} entry
   */
  record(entry) {
    this._ensureLoaded();
    const actor = sanitizeActor(entry.actor !== undefined ? entry.actor : entry.principal);
    const record = this._chainEntry({
      source: entry.source || 'http',
      action: String(entry.action || 'unknown').slice(0, 120),
      method: entry.method || null,
      path: entry.path ? String(entry.path).slice(0, 200) : null,
      resourceId: entry.resourceId ? String(entry.resourceId).slice(0, 120) : null,
      ip: entry.ip ? String(entry.ip).slice(0, 80) : null,
      authMethod: entry.authMethod || null,
      actor,
      status: entry.status ?? null,
      durationMs: entry.durationMs != null ? Number(Number(entry.durationMs).toFixed(1)) : null,
      detail: entry.detail !== undefined ? sanitizeDetail(entry.detail) : undefined
    });

    if (!this._isDiskDisabled()) {
      this._pendingLines.push(JSON.stringify(record));
      this._scheduleFlush();
    }
    return record;
  }

  _scheduleFlush() {
    if (this._flushTimer) return;
    this._flushTimer = setTimeout(() => {
      this._flushTimer = null;
      this.flushSync();
    }, 400);
    if (this._flushTimer.unref) this._flushTimer.unref();
  }

  flushSync() {
    if (this._flushTimer) {
      clearTimeout(this._flushTimer);
      this._flushTimer = null;
    }
    if (this._pendingLines.length === 0) return;
    const payload = this._pendingLines.join('\n') + '\n';
    this._pendingLines = [];
    const { dataDir, auditFile, rotatedFile } = this._getPaths();
    try {
      fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
      fs.appendFileSync(auditFile, payload, { encoding: 'utf8', mode: 0o600 });
      if (process.platform !== 'win32') {
        try { fs.chmodSync(auditFile, 0o600); } catch (e) {}
      }
      // Rotar DESPUÉS de persistir el lote y emitir un registro ancla encadenado en el nuevo archivo
      try {
        const st = fs.statSync(auditFile);
        if (st.size >= this.maxFileBytes) {
          const anchorSeq = this._lastSeq;
          const anchorHash = this._lastHash;
          try { fs.unlinkSync(rotatedFile); } catch (e) {}
          fs.renameSync(auditFile, rotatedFile);
          const anchorRecord = this._chainEntry({
            source: 'system',
            action: 'audit.log_rotated',
            method: null,
            path: null,
            resourceId: null,
            ip: null,
            authMethod: 'system',
            actor: null,
            status: 200,
            durationMs: null,
            detail: {
              rotatedTo: path.basename(rotatedFile),
              anchorSeq,
              anchorHash
            }
          });
          fs.appendFileSync(auditFile, `${JSON.stringify(anchorRecord)}\n`, { encoding: 'utf8', mode: 0o600 });
          if (process.platform !== 'win32') {
            try { fs.chmodSync(auditFile, 0o600); } catch (e) {}
          }
        }
      } catch (e) {}
    } catch (e) {
      // No romper el plano de control por un fallo de disco en auditoría
    }
  }

  /**
   * Verifica criptográficamente la cadena SHA-256 completa (`audit.jsonl.1` + `audit.jsonl`,
   * o el anillo en memoria si el disco está deshabilitado). Detecta cualquier edición de un
   * solo byte, borrado de líneas, inserción, reordenación o falsificación de hash.
   *
   * @param {{ includeRotated?: boolean }} [opts]
   * @returns {{
   *   valid: boolean,
   *   checkedCount: number,
   *   filesChecked: string[],
   *   anchored: boolean,
   *   firstSeq: number | null,
   *   lastSeq: number | null,
   *   headHash: string | null,
   *   brokenAtSeq: number | null,
   *   brokenAtLine: number | null,
   *   brokenFile: string | null,
   *   reason: string | null
   * }}
   */
  verifyIntegrity(opts = {}) {
    this._ensureLoaded();
    const includeRotated = opts.includeRotated !== false;
    if (!this._isDiskDisabled()) {
      this.flushSync();
    }

    /** @type {Array<{ file: string, lineNo: number, raw: string | null, parsed?: Record<string, any> }>} */
    const entries = [];
    /** @type {string[]} */
    const filesChecked = [];

    if (this._isDiskDisabled()) {
      filesChecked.push('memory:ring');
      for (let i = 0; i < this.ring.length; i++) {
        entries.push({ file: 'memory:ring', lineNo: i + 1, raw: null, parsed: this.ring[i] });
      }
    } else {
      const { auditFile, rotatedFile } = this._getPaths();
      if (includeRotated && fs.existsSync(rotatedFile)) {
        filesChecked.push(path.basename(rotatedFile));
        const lines = fs.readFileSync(rotatedFile, 'utf8').split(/\r?\n/);
        for (let i = 0; i < lines.length; i++) {
          if (!lines[i].trim()) continue;
          entries.push({ file: path.basename(rotatedFile), lineNo: i + 1, raw: lines[i] });
        }
      }
      if (fs.existsSync(auditFile)) {
        filesChecked.push(path.basename(auditFile));
        const lines = fs.readFileSync(auditFile, 'utf8').split(/\r?\n/);
        for (let i = 0; i < lines.length; i++) {
          if (!lines[i].trim()) continue;
          entries.push({ file: path.basename(auditFile), lineNo: i + 1, raw: lines[i] });
        }
      }
    }

    if (entries.length === 0) {
      return {
        valid: true,
        checkedCount: 0,
        filesChecked,
        anchored: false,
        firstSeq: null,
        lastSeq: null,
        headHash: GENESIS_HASH,
        brokenAtSeq: null,
        brokenAtLine: null,
        brokenFile: null,
        reason: null
      };
    }

    let expectedPrevHash = GENESIS_HASH;
    /** @type {number | null} */
    let expectedSeq = 1;
    let anchored = false;
    /** @type {number | null} */
    let firstSeq = null;
    /** @type {number | null} */
    let lastSeq = null;
    /** @type {string | null} */
    let headHash = null;

    for (let idx = 0; idx < entries.length; idx++) {
      const item = entries[idx];
      /** @type {any} */
      let rec = item.parsed;
      if (!rec) {
        try {
          rec = JSON.parse(/** @type {string} */ (item.raw));
        } catch (e) {
          return {
            valid: false,
            checkedCount: idx,
            filesChecked,
            anchored,
            firstSeq,
            lastSeq,
            headHash,
            brokenAtSeq: expectedSeq,
            brokenAtLine: item.lineNo,
            brokenFile: item.file,
            reason: 'CORRUPT_JSON_LINE'
          };
        }
      }

      if (!rec || typeof rec !== 'object' || typeof rec.seq !== 'number' || typeof rec.prevHash !== 'string' || typeof rec.entryHash !== 'string') {
        return {
          valid: false,
          checkedCount: idx,
          filesChecked,
          anchored,
          firstSeq,
          lastSeq,
          headHash,
          brokenAtSeq: typeof rec?.seq === 'number' ? rec.seq : expectedSeq,
          brokenAtLine: item.lineNo,
          brokenFile: item.file,
          reason: 'MISSING_CHAIN_FIELDS'
        };
      }

      // Aceptar un ancla de rotación legítimo en la línea 1 cuando `.1` ya no existe o se excluye
      if (idx === 0) {
        if (rec.seq > 1 && rec.action === 'audit.log_rotated' && rec.detail && rec.detail.anchorHash === rec.prevHash && rec.detail.anchorSeq === rec.seq - 1) {
          expectedPrevHash = rec.prevHash;
          expectedSeq = rec.seq;
          anchored = true;
        } else if (item.file === 'memory:ring' && rec.seq > 1) {
          expectedPrevHash = rec.prevHash;
          expectedSeq = rec.seq;
          anchored = true;
        }
        firstSeq = rec.seq;
      }

      if (rec.seq !== expectedSeq) {
        return {
          valid: false,
          checkedCount: idx,
          filesChecked,
          anchored,
          firstSeq,
          lastSeq,
          headHash,
          brokenAtSeq: rec.seq,
          brokenAtLine: item.lineNo,
          brokenFile: item.file,
          reason: `SEQ_DISCONTINUITY (expected ${expectedSeq}, got ${rec.seq})`
        };
      }

      if (rec.prevHash !== expectedPrevHash) {
        return {
          valid: false,
          checkedCount: idx,
          filesChecked,
          anchored,
          firstSeq,
          lastSeq,
          headHash,
          brokenAtSeq: rec.seq,
          brokenAtLine: item.lineNo,
          brokenFile: item.file,
          reason: 'PREV_HASH_MISMATCH'
        };
      }

      const { entryHash, ...unsigned } = rec;
      const recomputed = computeEntryHash(rec.prevHash, unsigned);
      if (recomputed !== entryHash) {
        return {
          valid: false,
          checkedCount: idx,
          filesChecked,
          anchored,
          firstSeq,
          lastSeq,
          headHash,
          brokenAtSeq: rec.seq,
          brokenAtLine: item.lineNo,
          brokenFile: item.file,
          reason: 'ENTRY_HASH_TAMPERED'
        };
      }

      expectedPrevHash = entryHash;
      expectedSeq = rec.seq + 1;
      lastSeq = rec.seq;
      headHash = entryHash;
    }

    return {
      valid: true,
      checkedCount: entries.length,
      filesChecked,
      anchored,
      firstSeq,
      lastSeq,
      headHash,
      brokenAtSeq: null,
      brokenAtLine: null,
      brokenFile: null,
      reason: null
    };
  }

  /**
   * Consulta eventos recientes (más nuevos primero).
   * @param {{ limit?: number, source?: string, action?: string, actor?: string, teamId?: string, since?: string }} [filters]
   */
  query({ limit = 50, source = '', action = '', actor = '', teamId = '', since = '' } = {}) {
    this._ensureLoaded();
    const safeLimit = Math.min(this.maxRingEntries, Math.max(1, Number(limit) || 50));
    const srcFilter = String(source || '').trim().toLowerCase();
    const actFilter = String(action || '').trim().toLowerCase();
    const actorFilter = String(actor || '').trim().toLowerCase();
    const teamFilter = String(teamId || '').trim();
    const sinceMs = since ? Date.parse(String(since)) : NaN;
    /** @type {Array<Record<string, any>>} */
    const out = [];
    for (let i = this.ring.length - 1; i >= 0 && out.length < safeLimit; i--) {
      const item = this.ring[i];
      if (srcFilter && String(item.source || '').toLowerCase() !== srcFilter) continue;
      if (actFilter && !String(item.action || '').toLowerCase().includes(actFilter)) continue;
      if (teamFilter && (!item.actor || item.actor.teamId !== teamFilter)) continue;
      if (actorFilter) {
        const hay = `${item.actor?.email || ''} ${item.actor?.userId || ''} ${item.actor?.kind || ''}`.toLowerCase();
        if (!hay.includes(actorFilter)) continue;
      }
      if (Number.isFinite(sinceMs) && Date.parse(String(item.timestamp || '')) < sinceMs) continue;
      out.push(item);
    }
    return out;
  }

  resetForTests() {
    this.ring = [];
    this._pendingLines = [];
    this._loaded = false;
    this._lastSeq = 0;
    this._lastHash = GENESIS_HASH;
    if (this._flushTimer) {
      clearTimeout(this._flushTimer);
      this._flushTimer = null;
    }
  }
}

const defaultInstance = new AuditLogger();

module.exports = Object.assign(defaultInstance, {
  AuditLogger,
  GENESIS_HASH,
  canonicalJson,
  computeEntryHash,
  redactInlineSecrets,
  sanitizeDetail,
  sanitizeActor
});
