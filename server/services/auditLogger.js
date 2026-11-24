const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Registro de auditoría del plano de control (cero dependencias externas).
 *
 * Combina:
 * - Anillo en memoria acotado (250 entradas) para consultas instantáneas en UI/API.
 * - Archivo JSONL append-only `data/audit.jsonl` con permisos `0o600` y rotación
 *   automática al superar 5 MB (conserva `.1`).
 * - Redacción automática de secretos para no filtrar jamás tokens ni contraseñas.
 */

const DATA_DIR = process.env.CULKIBO_DATA_DIR
  ? path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data')
  : path.resolve(__dirname, '..', '..', 'data');
const AUDIT_FILE = path.join(DATA_DIR, 'audit.jsonl');
const AUDIT_FILE_ROTATED = path.join(DATA_DIR, 'audit.jsonl.1');
const MAX_RING_ENTRIES = 250;
const MAX_FILE_BYTES = 5 * 1024 * 1024;
const SENSITIVE_KEY_RE = /(token|secret|password|passwd|apikey|api_key|privatekey|private_key|authorization|cookie|passphrase|credential)/i;

/** @param {any} value @param {number} [depth] */
function sanitizeDetail(value, depth = 0) {
  if (value == null) return value;
  if (depth > 3) return '[truncated]';
  if (typeof value === 'string') {
    return value.length > 300 ? `${value.slice(0, 300)}...` : value;
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

class AuditLogger {
  constructor() {
    /** @type {Array<Record<string, any>>} */
    this.ring = [];
    /** @type {string[]} */
    this._pendingLines = [];
    /** @type {ReturnType<typeof setTimeout> | null} */
    this._flushTimer = null;
    this._loaded = false;
  }

  _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;
    try {
      if (!fs.existsSync(AUDIT_FILE)) return;
      const raw = fs.readFileSync(AUDIT_FILE, 'utf8');
      const lines = raw.split(/\r?\n/).filter(Boolean);
      const tail = lines.slice(-MAX_RING_ENTRIES);
      for (const line of tail) {
        try {
          const parsed = JSON.parse(line);
          if (parsed && typeof parsed === 'object') this.ring.push(parsed);
        } catch (e) {}
      }
    } catch (e) {}
  }

  /**
   * Registra un evento de auditoría.
   * @param {{
   *   source?: 'http' | 'ws' | 'mcp' | 'system' | 'auth',
   *   action: string,
   *   method?: string | null,
   *   path?: string | null,
   *   resourceId?: string | null,
   *   ip?: string | null,
   *   authMethod?: string | null,
   *   status?: number | string | null,
   *   durationMs?: number | null,
   *   detail?: any
   * }} entry
   */
  record(entry) {
    this._ensureLoaded();
    const record = {
      id: `aud_${Date.now().toString(36)}_${crypto.randomBytes(3).toString('hex')}`,
      timestamp: new Date().toISOString(),
      source: entry.source || 'http',
      action: String(entry.action || 'unknown').slice(0, 120),
      method: entry.method || null,
      path: entry.path ? String(entry.path).slice(0, 200) : null,
      resourceId: entry.resourceId ? String(entry.resourceId).slice(0, 120) : null,
      ip: entry.ip ? String(entry.ip).slice(0, 80) : null,
      authMethod: entry.authMethod || null,
      status: entry.status ?? null,
      durationMs: entry.durationMs != null ? Number(Number(entry.durationMs).toFixed(1)) : null,
      detail: entry.detail !== undefined ? sanitizeDetail(entry.detail) : undefined
    };

    this.ring.push(record);
    if (this.ring.length > MAX_RING_ENTRIES) {
      this.ring.shift();
    }

    if (process.env.CULKIBO_DISABLE_AUDIT_DISK !== '1') {
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
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
      try {
        const st = fs.statSync(AUDIT_FILE);
        if (st.size >= MAX_FILE_BYTES) {
          try { fs.unlinkSync(AUDIT_FILE_ROTATED); } catch (e) {}
          fs.renameSync(AUDIT_FILE, AUDIT_FILE_ROTATED);
        }
      } catch (e) {}
      fs.appendFileSync(AUDIT_FILE, payload, { encoding: 'utf8', mode: 0o600 });
      if (process.platform !== 'win32') {
        try { fs.chmodSync(AUDIT_FILE, 0o600); } catch (e) {}
      }
    } catch (e) {
      // No romper el plano de control por un fallo de disco en auditoría
    }
  }

  /**
   * Consulta eventos recientes (más nuevos primero).
   * @param {{ limit?: number, source?: string, action?: string }} [filters]
   */
  query({ limit = 50, source = '', action = '' } = {}) {
    this._ensureLoaded();
    const safeLimit = Math.min(MAX_RING_ENTRIES, Math.max(1, Number(limit) || 50));
    const srcFilter = String(source || '').trim().toLowerCase();
    const actFilter = String(action || '').trim().toLowerCase();
    /** @type {Array<Record<string, any>>} */
    const out = [];
    for (let i = this.ring.length - 1; i >= 0 && out.length < safeLimit; i--) {
      const item = this.ring[i];
      if (srcFilter && String(item.source || '').toLowerCase() !== srcFilter) continue;
      if (actFilter && !String(item.action || '').toLowerCase().includes(actFilter)) continue;
      out.push(item);
    }
    return out;
  }

  resetForTests() {
    this.ring = [];
    this._pendingLines = [];
    if (this._flushTimer) {
      clearTimeout(this._flushTimer);
      this._flushTimer = null;
    }
  }
}

module.exports = new AuditLogger();
