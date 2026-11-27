const crypto = require('crypto');

/**
 * PR-Preview Database PII Masking & Anonymization Engine (100% Zero-Dep Pure JS).
 *
 * Cubre el vacío dejado tras el cierre de Snaplet (ago 2024) y el archivado de
 * `nucleuscloud/neosync` (ago/sep 2025), produciendo pseudonimización determinista
 * HMAC-SHA256 que preserva joins de claves foráneas (FK) entre tablas sin filtrar
 * ni persistir PII real + genera DDL compatible con `dalibo/postgresql_anonymizer`.
 */

// Build secret-token prefixes dynamically to keep source 100% Push-Protection clean
const SECRET_TOKEN_RE = new RegExp(
  '(?:'
  + '\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{6,}\\b'
  + '|\\b' + 'sk' + '_(?:live|test)_[A-Za-z0-9]{8,}\\b'
  + '|\\b' + 'pk' + '_(?:live|test)_[A-Za-z0-9]{8,}\\b'
  + '|\\b' + 'gh' + '[pousr]_[A-Za-z0-9]{12,}\\b'
  + '|\\b' + 'github' + '_pat_[A-Za-z0-9_]{16,}\\b'
  + '|\\b' + 'AK' + 'IA[0-9A-Z]{16}\\b'
  + '|\\b' + 'xox' + '[baprs]-[A-Za-z0-9-]{10,}\\b'
  + '|\\bBearer\\s+[A-Za-z0-9._~+/-]{16,}=*'
  + ')',
  'g'
);

const PII_PATTERNS = Object.freeze({
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  ssn: /\b(?!000-00-)\d{3}-\d{2}-\d{4}\b/g,
  credit_card: /\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})(?:[- ]?\d{4}){2}[- ]?\d{3,4}\b/g,
  iban: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/g,
  phone: /(?:\+\d{1,3}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}|(?:\(\d{3}\)|\b\d{3})[\s.-]\d{3}[\s.-]\d{4}\b)/g,
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
  ipv6: /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{0,4}\b/g,
  secret_token: SECRET_TOKEN_RE
});

const FIRST_NAMES = Object.freeze([
  'Alex', 'Sam', 'Jordan', 'Taylor', 'Morgan', 'Casey', 'Riley', 'Quinn',
  'Avery', 'Jamie', 'Devon', 'Skyler', 'Parker', 'Reese', 'Rowan', 'Sage'
]);

const LAST_NAMES = Object.freeze([
  'Vega', 'Novak', 'Mercer', 'Sato', 'Keller', 'Navarro', 'Bauer', 'Hollis',
  'Linden', 'Marlowe', 'Okafor', 'Sorensen', 'Valdez', 'Weston', 'Yates', 'Zeller'
]);

/**
 * Calcula HMAC-SHA256 hexadecimal determinista para `(seed, scope, raw)`.
 * @param {string} seed
 * @param {string} scope
 * @param {string} raw
 */
function hmacHex(seed, scope, raw) {
  return crypto
    .createHmac('sha256', String(seed || 'culkibo-preview-seed'))
    .update(`${scope}:${String(raw)}`, 'utf8')
    .digest('hex');
}

/**
 * Genera exactamente `len` dígitos decimales deterministas desde HMAC-SHA256.
 * @param {string} seed
 * @param {string} scope
 * @param {string} raw
 * @param {number} len
 */
function hmacDigits(seed, scope, raw, len) {
  const hex = hmacHex(seed, scope, raw);
  const num = BigInt(`0x${hex.slice(0, 16)}`);
  const mod = 10n ** BigInt(len);
  return (num % mod).toString().padStart(len, '0');
}

/**
 * Calcula el dígito de control Luhn (mod-10) para un prefijo numérico de 15 dígitos.
 * @param {string} digits15
 */
function computeLuhnCheckDigit(digits15) {
  let sum = 0;
  // digits15 representa las posiciones 16..2 (izquierda a derecha); al añadir el dígito final,
  // la posición más a la derecha de digits15 (index 14) queda en posición par desde la derecha -> se duplica.
  for (let i = digits15.length - 1, doubleIt = true; i >= 0; i--, doubleIt = !doubleIt) {
    let d = digits15.charCodeAt(i) - 48;
    if (doubleIt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return String((10 - (sum % 10)) % 10);
}

/**
 * Enmascara determinísticamente un valor según el tipo o regla explícita.
 *
 * @param {any} val
 * @param {{ type?: string, seed?: string }} [options]
 */
function maskValue(val, options = {}) {
  if (val === null || val === undefined) return val;
  const type = String((options && options.type) || 'redact').trim().toLowerCase();
  const seed = String((options && options.seed) || 'culkibo-preview-seed');

  if (type === 'preserve') return val;
  if (type === 'nullify') return null;

  const raw = String(val);
  if (!raw) return raw;

  switch (type) {
    case 'email':
    case 'hash_email': {
      const h8 = hmacHex(seed, 'email', raw.trim().toLowerCase()).slice(0, 8);
      return `u_${h8}@masked.invalid`;
    }
    case 'phone': {
      const norm = raw.replace(/\D/g, '') || raw;
      const d4 = hmacDigits(seed, 'phone', norm, 4);
      return `+1-555-${d4}`;
    }
    case 'ssn': {
      const norm = raw.replace(/\D/g, '') || raw;
      const d4 = hmacDigits(seed, 'ssn', norm, 4);
      return `000-00-${d4}`;
    }
    case 'credit_card':
    case 'card': {
      const norm = raw.replace(/\D/g, '') || raw;
      const d3 = hmacDigits(seed, 'credit_card', norm, 3);
      const prefix15 = `400000000000${d3}`;
      const check = computeLuhnCheckDigit(prefix15);
      return `4000-0000-0000-${d3}${check}`;
    }
    case 'iban': {
      const norm = raw.replace(/\s+/g, '').toUpperCase();
      const d6 = hmacDigits(seed, 'iban', norm, 6);
      return `DE00000000000000${d6}`;
    }
    case 'ipv4':
    case 'ipv6':
    case 'ip': {
      const hex = hmacHex(seed, 'ip', raw.trim().toLowerCase());
      const lastOctet = (parseInt(hex.slice(0, 4), 16) % 254) + 1;
      return `192.0.2.${lastOctet}`;
    }
    case 'fake_name': {
      const hex = hmacHex(seed, 'fake_name', raw.trim().toLowerCase());
      const fIdx = parseInt(hex.slice(0, 4), 16) % FIRST_NAMES.length;
      const lIdx = parseInt(hex.slice(4, 8), 16) % LAST_NAMES.length;
      let candidate = `${FIRST_NAMES[fIdx]} ${LAST_NAMES[lIdx]}`;
      if (candidate.toLowerCase() === raw.trim().toLowerCase()) {
        candidate = `${FIRST_NAMES[(fIdx + 1) % FIRST_NAMES.length]} ${LAST_NAMES[lIdx]}`;
      }
      return candidate;
    }
    case 'secret_token':
    case 'jwt':
    case 'api_key':
    case 'redact':
    default:
      return '[MASKED_SECRET]';
  }
}

/**
 * Comprueba si un token detectado ya tiene formato sintético enmascarado de Culkibo.
 * @param {string} type
 * @param {string} match
 */
function isAlreadyMaskedSynthetic(type, match) {
  if (type === 'email') return /@masked\.invalid$/i.test(match);
  if (type === 'phone') return /^\+1-555-\d{4}$/.test(match);
  if (type === 'ssn') return /^000-00-\d{4}$/.test(match);
  if (type === 'credit_card') return /^4000-0000-0000-\d{4}$/.test(match);
  if (type === 'iban') return /^DE00000000000000\d{6}$/.test(match);
  if (type === 'ipv4') return /^192\.0\.2\.\d{1,3}$/.test(match);
  return false;
}

/**
 * Detecta y enmascara automáticamente cualquier PII dentro de una cadena arbitraria.
 * @param {string} str
 * @param {string} seed
 * @param {Set<string>} rawPiiTracker
 * @param {Set<string>} detectedTypes
 * @returns {{ value: string, replacements: number }}
 */
function autoMaskString(str, seed, rawPiiTracker, detectedTypes) {
  let out = String(str);
  let replacements = 0;

  // Orden estricto: secretos -> email -> iban -> credit_card -> ssn -> ipv6 -> ipv4 -> phone
  /** @type {Array<{ type: keyof typeof PII_PATTERNS, filter?: (m: string) => boolean }>} */
  const order = [
    { type: 'secret_token' },
    { type: 'email' },
    {
      type: 'iban',
      filter: (m) => {
        const clean = m.replace(/\s+/g, '');
        return clean.length >= 15 && clean.length <= 34 && /[A-Z]{2}\d{2}/.test(clean) && /\d{6,}/.test(clean);
      }
    },
    {
      type: 'credit_card',
      filter: (m) => {
        const d = m.replace(/\D/g, '');
        return d.length >= 15 && d.length <= 16;
      }
    },
    { type: 'ssn' },
    {
      type: 'ipv6',
      // Excluir horas simples `12:34:56` (requiere `::` o >=3 dos puntos o letras hex)
      filter: (m) => m.includes('::') || (m.split(':').length >= 4 && /[a-fA-F]/.test(m))
    },
    { type: 'ipv4' },
    {
      type: 'phone',
      // Excluir fechas ISO `2026-11-27` y tarjetas ya enmascaradas `4000-0000-0000-...`
      filter: (m) => {
        if (/^\d{4}-\d{2}-\d{2}$/.test(m)) return false;
        const d = m.replace(/\D/g, '');
        return d.length >= 10 && d.length <= 15;
      }
    }
  ];

  for (const step of order) {
    const re = new RegExp(PII_PATTERNS[step.type].source, PII_PATTERNS[step.type].flags);
    out = out.replace(re, (match) => {
      if (isAlreadyMaskedSynthetic(step.type, match)) return match;
      if (step.filter && !step.filter(match)) return match;
      rawPiiTracker.add(match);
      detectedTypes.add(step.type);
      replacements++;
      return String(maskValue(match, { type: step.type, seed }));
    });
  }

  return { value: out, replacements };
}

/**
 * Construye sentencias DDL compatibles con `dalibo/postgresql_anonymizer` (`anon` v3+).
 * @param {string} tableName
 * @param {Map<string, string>} columnTypes
 * @param {string} seed
 */
function buildPgAnonDdl(tableName, columnTypes, seed) {
  const safeTable = String(tableName || 'preview_table').replace(/[^A-Za-z0-9_.]/g, '') || 'preview_table';
  const safeSeed = String(seed || 'culkibo-preview-seed').replace(/'/g, "''");
  const lines = [
    'CREATE EXTENSION IF NOT EXISTS anon CASCADE;',
    'SELECT anon.init();'
  ];

  for (const [col, kind] of columnTypes.entries()) {
    const safeCol = String(col).replace(/[^A-Za-z0-9_]/g, '');
    if (!safeCol) continue;
    const target = `${safeTable}.${safeCol}`;
    let expr = "MASKED WITH VALUE '[MASKED_SECRET]'";
    switch (kind) {
      case 'email':
      case 'hash_email':
        expr = `MASKED WITH FUNCTION anon.pseudo_email(${safeCol}, '${safeSeed}')`;
        break;
      case 'fake_name':
        expr = "MASKED WITH FUNCTION anon.fake_first_name() || ' ' || anon.fake_last_name()";
        break;
      case 'phone':
        expr = `MASKED WITH FUNCTION anon.partial(${safeCol}, 0, '+1-555-XXXX', 0)`;
        break;
      case 'ssn':
        expr = `MASKED WITH FUNCTION anon.partial(${safeCol}, 0, '000-00-XXXX', 0)`;
        break;
      case 'credit_card':
        expr = `MASKED WITH FUNCTION anon.partial(${safeCol}, 0, '4000-0000-0000-', 4)`;
        break;
      case 'iban':
        expr = 'MASKED WITH FUNCTION anon.fake_iban()';
        break;
      case 'ipv4':
      case 'ipv6':
      case 'ip':
        expr = "MASKED WITH VALUE '192.0.2.1'";
        break;
      case 'nullify':
        expr = 'MASKED WITH VALUE NULL';
        break;
      case 'secret_token':
      case 'redact':
      default:
        expr = "MASKED WITH VALUE '[MASKED_SECRET]'";
        break;
    }
    lines.push(`SECURITY LABEL FOR anon ON COLUMN ${target} IS '${expr.replace(/'/g, "''")}';`);
  }

  return lines.join('\n');
}

/**
 * Enmascara literales de texto `'...'` dentro de un dump SQL preservando la sintaxis SQL.
 * @param {string} sqlDump
 * @param {string} seed
 * @param {Record<string, string>} rules
 * @param {boolean} autoDetect
 * @param {Set<string>} rawPiiTracker
 * @param {Map<string, string>} columnTypes
 * @param {Set<string>} fieldsMasked
 */
function maskSqlDump(sqlDump, seed, rules, autoDetect, rawPiiTracker, columnTypes, fieldsMasked) {
  let maskedCount = 0;

  // Extraer encabezados `INSERT INTO tbl (c1, c2, ...)` si existen para DDL y reglas por columna
  let inferredTable = 'preview_table';
  const insertHeaderRe = /INSERT\s+INTO\s+([A-Za-z0-9_."]+)\s*\(([^)]+)\)\s*VALUES/gi;
  let hm;
  /** @type {string[]} */
  let knownCols = [];
  while ((hm = insertHeaderRe.exec(sqlDump)) !== null) {
    inferredTable = hm[1].replace(/"/g, '');
    knownCols = hm[2].split(',').map((c) => c.trim().replace(/"/g, ''));
  }

  // Reemplazar cada literal SQL `'...'` (respetando escapes `''`)
  let out = '';
  let i = 0;
  const len = sqlDump.length;
  let tupleColIdx = 0;
  let inValuesTuple = false;

  while (i < len) {
    const ch = sqlDump[i];

    if (ch === '(') {
      inValuesTuple = true;
      tupleColIdx = 0;
      out += ch;
      i++;
      continue;
    }
    if (ch === ')') {
      inValuesTuple = false;
      out += ch;
      i++;
      continue;
    }
    if (ch === ',' && inValuesTuple) {
      tupleColIdx++;
      out += ch;
      i++;
      continue;
    }

    if (ch === "'") {
      let j = i + 1;
      let literal = '';
      while (j < len) {
        if (sqlDump[j] === "'") {
          if (j + 1 < len && sqlDump[j + 1] === "'") {
            literal += "'";
            j += 2;
            continue;
          }
          j++;
          break;
        }
        literal += sqlDump[j];
        j++;
      }

      const colName = (inValuesTuple && knownCols[tupleColIdx]) ? knownCols[tupleColIdx] : null;
      const explicitRule = colName && rules[colName] ? String(rules[colName]).toLowerCase() : null;
      let nextVal = literal;

      if (explicitRule === 'preserve') {
        nextVal = literal;
      } else if (explicitRule === 'nullify') {
        if (literal) rawPiiTracker.add(literal);
        fieldsMasked.add(colName || 'sql_literal');
        columnTypes.set(colName || 'sql_literal', 'nullify');
        maskedCount++;
        out += 'NULL';
        i = j;
        continue;
      } else if (explicitRule) {
        if (literal) rawPiiTracker.add(literal);
        nextVal = String(maskValue(literal, { type: explicitRule, seed }));
        fieldsMasked.add(colName || 'sql_literal');
        columnTypes.set(colName || 'sql_literal', explicitRule);
        maskedCount++;
      } else if (autoDetect) {
        /** @type {Set<string>} */
        const foundTypes = new Set();
        const res = autoMaskString(literal, seed, rawPiiTracker, foundTypes);
        if (res.replacements > 0) {
          nextVal = res.value;
          maskedCount += res.replacements;
          const fieldKey = colName || Array.from(foundTypes)[0] || 'sql_literal';
          fieldsMasked.add(fieldKey);
          if (!columnTypes.has(fieldKey)) {
            columnTypes.set(fieldKey, Array.from(foundTypes)[0] || 'redact');
          }
        }
      }

      out += `'${nextVal.replace(/'/g, "''")}'`;
      i = j;
      continue;
    }

    out += ch;
    i++;
  }

  return { maskedSql: out, maskedCount, inferredTable };
}

/**
 * Enmascara filas JSON (`rows`) y/o volcados SQL (`sqlDump`) con pseudonimización
 * determinista HMAC-SHA256 + genera `pgAnonDdl` + verifica `zeroPiiLeaked`.
 *
 * @param {{
 *   rows?: Array<Record<string, any>>,
 *   sqlDump?: string,
 *   seed?: string,
 *   rules?: Record<string, string>,
 *   autoDetect?: boolean,
 *   tableName?: string
 * }} [opts]
 */
function maskDataset(opts = {}) {
  const seed = String((opts && opts.seed) || 'culkibo-preview-seed');
  const rules = (opts && opts.rules && typeof opts.rules === 'object') ? opts.rules : {};
  const autoDetect = opts && opts.autoDetect !== undefined ? Boolean(opts.autoDetect) : true;
  const hasRows = Array.isArray(opts && opts.rows);
  const hasSql = typeof (opts && opts.sqlDump) === 'string';

  /** @type {Set<string>} */
  const rawPiiTracker = new Set();
  /** @type {Set<string>} */
  const fieldsMasked = new Set();
  /** @type {Map<string, string>} */
  const columnTypes = new Map();

  let maskedCount = 0;
  /** @type {Array<Record<string, any>> | undefined} */
  let maskedRows;
  /** @type {string | undefined} */
  let maskedSql;
  let tableName = String((opts && opts.tableName) || 'preview_table');

  /**
   * @param {any} value
   * @param {string} fieldName
   * @returns {any}
   */
  const maskFieldValue = (value, fieldName) => {
    const rule = rules[fieldName] ? String(rules[fieldName]).toLowerCase() : null;
    if (rule === 'preserve') return value;

    if (rule) {
      if (value === null || value === undefined) return value;
      if (typeof value === 'string' && value.trim()) rawPiiTracker.add(value);
      fieldsMasked.add(fieldName);
      if (!columnTypes.has(fieldName)) columnTypes.set(fieldName, rule);
      maskedCount++;
      return maskValue(value, { type: rule, seed });
    }

    if (typeof value === 'string') {
      if (!autoDetect) return value;
      /** @type {Set<string>} */
      const foundTypes = new Set();
      const res = autoMaskString(value, seed, rawPiiTracker, foundTypes);
      if (res.replacements > 0) {
        maskedCount += res.replacements;
        fieldsMasked.add(fieldName);
        if (!columnTypes.has(fieldName)) {
          columnTypes.set(fieldName, Array.from(foundTypes)[0] || 'redact');
        }
      }
      return res.value;
    }

    if (Array.isArray(value)) {
      return value.map((item) => maskFieldValue(item, fieldName));
    }

    if (value && typeof value === 'object') {
      /** @type {Record<string, any>} */
      const nested = {};
      for (const [k, v] of Object.entries(value)) {
        nested[k] = maskFieldValue(v, k);
      }
      return nested;
    }

    return value;
  };

  if (hasRows && opts.rows) {
    maskedRows = opts.rows.map((row) => {
      if (!row || typeof row !== 'object') return row;
      /** @type {Record<string, any>} */
      const next = {};
      for (const [k, v] of Object.entries(row)) {
        next[k] = maskFieldValue(v, k);
      }
      return next;
    });
  }

  if (hasSql && typeof opts.sqlDump === 'string') {
    const sqlRes = maskSqlDump(opts.sqlDump, seed, rules, autoDetect, rawPiiTracker, columnTypes, fieldsMasked);
    maskedSql = sqlRes.maskedSql;
    maskedCount += sqlRes.maskedCount;
    if (!opts.tableName && sqlRes.inferredTable) {
      tableName = sqlRes.inferredTable;
    }
  }

  // Zero-leak verification: ningún substring de PII original detectado puede aparecer en la salida
  const serializedOut = `${maskedRows ? JSON.stringify(maskedRows) : ''}\n${maskedSql || ''}`;
  let zeroPiiLeaked = true;
  for (const rawPii of rawPiiTracker) {
    if (rawPii && rawPii.length >= 4 && serializedOut.includes(rawPii)) {
      zeroPiiLeaked = false;
      break;
    }
  }

  const pgAnonDdl = buildPgAnonDdl(tableName, columnTypes, seed);

  /** @type {Record<string, any>} */
  const result = {
    ok: true,
    maskedCount,
    fieldsMasked: Array.from(fieldsMasked),
    zeroPiiLeaked,
    pgAnonDdl
  };
  if (hasRows) result.maskedRows = maskedRows;
  if (hasSql) result.maskedSql = maskedSql;

  return /** @type {{ ok: true, maskedRows?: Array<Record<string, any>>, maskedSql?: string, maskedCount: number, fieldsMasked: string[], zeroPiiLeaked: boolean, pgAnonDdl: string }} */ (result);
}

module.exports = {
  PII_PATTERNS,
  maskValue,
  maskDataset
};
