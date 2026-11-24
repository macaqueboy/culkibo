'use strict';

const crypto = require('crypto');

const ALLOWED_EVENT_TYPES = new Set([
  'instance_heartbeat',
  'server_crash',
  'api_error_5xx',
  'operation_failure',
  'client_error',
  'feature_usage',
]);

const ISSUE_EVENT_TYPES = new Set([
  'server_crash',
  'api_error_5xx',
  'operation_failure',
  'client_error',
]);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const VERSION_RE = /^[0-9a-zA-Z._+-]{1,32}$/;

/**
 * Saneado de segunda capa (defensa en profundidad en el servidor colector)
 * para garantizar que ni siquiera clientes antiguos o modificados persistan PII o secretos.
 * @param {unknown} input
 * @param {number} [maxLen]
 */
function scrubString(input, maxLen = 400) {
  if (input === null || input === undefined) return '';
  let s = String(input);
  s = s.replace(/-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/g, '<pem>');
  s = s.replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g, '<jwt>');
  s = s.replace(/\b(?:ghp|gho|ghu|ghs|ghr|github_pat|glpat|sk|pk|xoxb|xoxp|AKIA|ASIA)[A-Za-z0-9_-]{10,}\b/g, '<secret>');
  s = s.replace(/\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{8,}/gi, '$1 <redacted>');
  s = s.replace(/\b([a-z][a-z0-9+.-]{1,15}:\/\/)([^/\s:@]+):([^/\s@]+)@([^\s/'"]+)/gi, '$1<user>:<pass>@<host>');
  s = s.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '<email>');
  s = s.replace(/(?:[A-Za-z]:\\Users\\[^\\/\s'"]+|\/(?:Users|home)\/[^/\s'"]+)/g, '<home>');
  s = s.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '<ip>');
  if (s.length > maxLen) s = `${s.slice(0, maxLen)}…`;
  return s;
}

/** @param {unknown} value @param {number} [depth] */
function scrubValue(value, depth = 0) {
  if (depth > 5 || value === null || value === undefined) return value ?? null;
  if (typeof value === 'boolean' || typeof value === 'number') {
    return typeof value === 'number' && !Number.isFinite(value) ? null : value;
  }
  if (typeof value === 'string') return scrubString(value, 350);
  if (Array.isArray(value)) {
    return value.slice(0, 20).map((item) => scrubValue(item, depth + 1));
  }
  if (typeof value === 'object') {
    /** @type {Record<string, any>} */
    const out = {};
    const entries = Object.entries(value).slice(0, 40);
    for (const [k, v] of entries) {
      if (/pass(word|phrase)?|secret|token|cookie|authorization|apikey|api_key|privatekey/i.test(k)) {
        out[k] = '<redacted>';
      } else {
        out[k.slice(0, 64)] = scrubValue(v, depth + 1);
      }
    }
    return out;
  }
  return null;
}

/** @param {string} type @param {Record<string, any>} data */
function buildFallbackFingerprint(type, data) {
  const parts = [
    type,
    data.kind || data.operation || data.source || data.method || '',
    data.stage || data.view || data.route || '',
    data.errorName || data.errorCode || data.status || '',
    String(data.message || '').slice(0, 120),
  ];
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 20);
}

/** @param {string} type @param {Record<string, any>} data */
function buildIssueTitle(type, data) {
  if (type === 'server_crash') {
    return `[Crash:${data.kind || 'error'}] ${data.errorName || 'Error'}: ${String(data.message || '').slice(0, 120)}`;
  }
  if (type === 'api_error_5xx') {
    return `[HTTP ${data.status || 500}] ${data.method || 'GET'} ${data.route || '/api'} — ${String(data.message || '').slice(0, 90)}`;
  }
  if (type === 'operation_failure') {
    return `[Op:${data.operation || 'unknown'}/${data.stage || 'run'}${data.kind ? `:${data.kind}` : ''}] ${String(data.message || '').slice(0, 110)}`;
  }
  if (type === 'client_error') {
    return `[UI:${data.view || 'unknown'}] ${data.errorName || 'Error'}: ${String(data.message || '').slice(0, 110)}`;
  }
  return `[${type}] ${String(data.message || '').slice(0, 120)}`;
}

/**
 * Valida y sanea un sobre JSON Schema v1 entrante.
 * @param {any} body
 */
function validateEnvelope(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, error: 'El cuerpo debe ser un objeto JSON' };
  }
  if (body.schemaVersion !== 1) {
    return { ok: false, error: 'schemaVersion no soportado (se esperaba 1)' };
  }
  const instanceId = typeof body.instanceId === 'string' ? body.instanceId.trim() : '';
  if (!UUID_RE.test(instanceId)) {
    return { ok: false, error: 'instanceId debe ser un UUID válido' };
  }
  const appVersion = typeof body.appVersion === 'string' && VERSION_RE.test(body.appVersion.trim())
    ? body.appVersion.trim()
    : 'unknown';

  if (!Array.isArray(body.events) || body.events.length === 0) {
    return { ok: false, error: 'events debe ser un array no vacío' };
  }
  if (body.events.length > 50) {
    return { ok: false, error: 'Máximo 50 eventos por lote' };
  }

  const nowIso = new Date().toISOString();
  const normalizedEvents = [];
  for (const raw of body.events) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
    const type = typeof raw.type === 'string' ? raw.type.trim() : '';
    if (!ALLOWED_EVENT_TYPES.has(type)) continue;

    const eventId = typeof raw.id === 'string' && raw.id.length <= 64 ? raw.id : crypto.randomUUID();
    const rawTs = typeof raw.ts === 'string' && !Number.isNaN(Date.parse(raw.ts)) ? new Date(raw.ts).toISOString() : nowIso;
    const occRaw = Number(raw.occurrences);
    const occurrences = Number.isInteger(occRaw) && occRaw >= 1 ? Math.min(10000, occRaw) : 1;
    const data = scrubValue(raw.data && typeof raw.data === 'object' ? raw.data : {}) || {};

    let fingerprint = null;
    if (ISSUE_EVENT_TYPES.has(type)) {
      const candidate = typeof raw.fingerprint === 'string' ? raw.fingerprint.trim().replace(/[^a-f0-9_-]/gi, '').slice(0, 32) : '';
      fingerprint = candidate.length >= 8 ? candidate : buildFallbackFingerprint(type, data);
    }

    normalizedEvents.push({
      eventId,
      type,
      ts: rawTs,
      occurrences,
      fingerprint,
      title: ISSUE_EVENT_TYPES.has(type) ? buildIssueTitle(type, data) : type,
      data,
    });
  }

  if (normalizedEvents.length === 0) {
    return { ok: false, error: 'Ningún evento válido en el lote' };
  }

  return {
    ok: true,
    envelope: {
      schemaVersion: 1,
      instanceId,
      appVersion,
      receivedAt: nowIso,
      events: normalizedEvents,
    },
  };
}

module.exports = {
  ALLOWED_EVENT_TYPES,
  ISSUE_EVENT_TYPES,
  scrubString,
  scrubValue,
  validateEnvelope,
  buildIssueTitle,
};
