/**
 * Parser compartido de expresiones Cron de 5 campos (cero dependencias).
 *
 * Compartido entre `databaseManager.js` (copias programadas) y `cronManager.js`
 * (tareas programadas por proyecto).
 *
 * Formato: `minuto hora día-del-mes mes día-de-la-semana`
 * Alias admitidos: `@hourly`, `@daily`, `@midnight`, `@weekly`, `@monthly`.
 */

const CRON_ALIASES = Object.freeze({
  '@hourly': '0 * * * *',
  '@daily': '0 0 * * *',
  '@midnight': '0 0 * * *',
  '@weekly': '0 0 * * 0',
  '@monthly': '0 0 1 * *'
});

/** Número máximo posible de días por mes (incluyendo 29 de febrero en año bisiesto). */
const MAX_DAYS_BY_MONTH = Object.freeze({
  1: 31,
  2: 29,
  3: 31,
  4: 30,
  5: 31,
  6: 30,
  7: 31,
  8: 31,
  9: 30,
  10: 31,
  11: 30,
  12: 31
});

/** Horizonte máximo de búsqueda (8 años cubre saltos de año bisiesto incluso cruzando un siglo no bisiesto). */
const MAX_HORIZON_MS = 8 * 366 * 24 * 60 * 60 * 1000;
const MAX_LOOP_ITERATIONS = 50000;

/**
 * @param {string} expr
 * @param {number} min
 * @param {number} max
 * @returns {{ set: Set<number>, isWildcard: boolean }}
 */
function parseCronField(expr, min, max) {
  const clean = String(expr || '').trim();
  if (!clean) throw new Error('Campo cron vacío');
  if (clean === '*') {
    const all = new Set();
    for (let i = min; i <= max; i++) all.add(i);
    return { set: all, isWildcard: true };
  }

  /** @type {Set<number>} */
  const set = new Set();
  for (const rawPart of clean.split(',')) {
    const part = rawPart.trim();
    if (!part) throw new Error(`Expresión cron inválida: ${expr}`);
    const slashParts = part.split('/');
    if (slashParts.length > 2) throw new Error(`Expresión cron inválida: ${part}`);
    const [rangePart, stepPart] = slashParts;
    if (!rangePart) throw new Error(`Expresión cron inválida: ${part}`);
    if (stepPart !== undefined && !/^\d+$/.test(stepPart)) {
      throw new Error(`Paso cron inválido: ${part}`);
    }
    const step = stepPart !== undefined ? Number(stepPart) : 1;
    if (!Number.isInteger(step) || step < 1 || step > max - min + 1) {
      throw new Error(`Paso cron inválido: ${part}`);
    }

    let start = min;
    let end = max;
    if (rangePart !== '*') {
      if (rangePart.includes('-')) {
        const bounds = rangePart.split('-');
        if (bounds.length !== 2 || !/^\d+$/.test(bounds[0]) || !/^\d+$/.test(bounds[1])) {
          throw new Error(`Rango cron inválido: ${part}`);
        }
        const a = Number(bounds[0]);
        const b = Number(bounds[1]);
        if (!Number.isInteger(a) || !Number.isInteger(b) || a > b) {
          throw new Error(`Rango cron inválido: ${part}`);
        }
        start = a;
        end = b;
      } else {
        if (!/^\d+$/.test(rangePart)) throw new Error(`Valor cron inválido: ${part}`);
        const n = Number(rangePart);
        if (!Number.isInteger(n)) throw new Error(`Valor cron inválido: ${part}`);
        start = n;
        end = stepPart !== undefined ? max : n;
      }
    }

    if (start < min || end > max) {
      // Permitir 7 como domingo en día de la semana (0-7)
      if (!(max === 7 && start >= 0 && end <= 7)) {
        throw new Error(`Valor fuera de rango (${min}-${max}): ${part}`);
      }
    }

    for (let v = start; v <= end; v += step) {
      set.add(max === 7 && v === 7 ? 0 : v);
    }
  }

  if (set.size === 0) throw new Error(`Campo cron sin valores válidos: ${expr}`);
  return { set, isWildcard: false };
}

/**
 * Parsea una expresión cron de 5 campos (o alias `@daily`, etc.).
 * @param {string} raw
 */
function parseCron(raw) {
  const trimmed = String(raw || '').trim();
  if (!trimmed) throw new Error('La expresión cron es obligatoria');
  const lower = trimmed.toLowerCase();
  const normalized = CRON_ALIASES[lower] || trimmed;
  const parts = normalized.split(/\s+/);
  if (parts.length !== 5) {
    throw new Error('La expresión cron debe tener exactamente 5 campos (minuto hora día mes día-semana)');
  }
  const minute = parseCronField(parts[0], 0, 59);
  const hour = parseCronField(parts[1], 0, 23);
  const dom = parseCronField(parts[2], 1, 31);
  const month = parseCronField(parts[3], 1, 12);
  const dow = parseCronField(parts[4], 0, 7);
  return {
    expression: normalized,
    minute: minute.set,
    hour: hour.set,
    dom: dom.set,
    domWildcard: dom.isWildcard,
    month: month.set,
    dow: dow.set,
    dowWildcard: dow.isWildcard
  };
}

/**
 * Comprueba en O(1) si la combinación `(mes, día-del-mes)` es imposible cuando
 * el día de la semana es `*` (semántica AND estricta, p. ej. `0 0 30 2 *` o `0 0 31 4 *`).
 * Cuando ambos `dom` y `dow` son restringidos, cron usa semántica OR y el día de la semana
 * puede coincidir igualmente.
 * @param {{ month: Set<number>, dom: Set<number>, dowWildcard: boolean }} parsed
 * @returns {boolean}
 */
function hasPossibleCalendarDay(parsed) {
  if (!parsed.dowWildcard) return true;
  for (const mon of parsed.month) {
    const maxDay = MAX_DAYS_BY_MONTH[/** @type {keyof typeof MAX_DAYS_BY_MONTH} */ (mon)] || 31;
    for (const day of parsed.dom) {
      if (day <= maxDay) return true;
    }
  }
  return false;
}

/**
 * Calcula la siguiente ejecución a partir de `fromDate` (estrictamente posterior).
 * Acotado tanto por horizonte temporal (`MAX_HORIZON_MS`) como por iteraciones
 * máximas para eliminar cualquier riesgo de DoS síncrono en fechas imposibles.
 * @param {string} expression
 * @param {Date} [fromDate]
 * @returns {Date}
 */
function nextCronRun(expression, fromDate = new Date()) {
  const parsed = parseCron(expression);
  if (!(fromDate instanceof Date) || !Number.isFinite(fromDate.getTime())) {
    throw new Error('Fecha base inválida para cálculo de cron');
  }
  if (!hasPossibleCalendarDay(parsed)) {
    throw new Error(`No se encontró una próxima ejecución válida para cron "${expression}"`);
  }

  const baseMs = fromDate.getTime();
  const maxTimeMs = baseMs + MAX_HORIZON_MS;
  const cursor = new Date(baseMs);
  cursor.setSeconds(0, 0);
  cursor.setMinutes(cursor.getMinutes() + 1);

  for (let i = 0; i < MAX_LOOP_ITERATIONS && cursor.getTime() <= maxTimeMs; i++) {
    const mon = cursor.getMonth() + 1;
    if (!parsed.month.has(mon)) {
      cursor.setMonth(cursor.getMonth() + 1, 1);
      cursor.setHours(0, 0, 0, 0);
      continue;
    }

    const domMatch = parsed.dom.has(cursor.getDate());
    const dowMatch = parsed.dow.has(cursor.getDay());
    const dayOk = (!parsed.domWildcard && !parsed.dowWildcard)
      ? (domMatch || dowMatch)
      : (domMatch && dowMatch);
    if (!dayOk) {
      cursor.setDate(cursor.getDate() + 1);
      cursor.setHours(0, 0, 0, 0);
      continue;
    }

    if (!parsed.hour.has(cursor.getHours())) {
      cursor.setHours(cursor.getHours() + 1, 0, 0, 0);
      continue;
    }

    if (!parsed.minute.has(cursor.getMinutes())) {
      cursor.setMinutes(cursor.getMinutes() + 1, 0, 0);
      continue;
    }

    return cursor;
  }

  throw new Error(`No se encontró una próxima ejecución válida para cron "${expression}"`);
}

/**
 * Devuelve si la expresión cron ejecuta con frecuencia subdiaria (más de una vez al día).
 * @param {string} expression
 */
function isSubDailyCron(expression) {
  try {
    const p = parseCron(expression);
    return (p.hour.size * p.minute.size) > 1;
  } catch (e) {
    return false;
  }
}

module.exports = {
  CRON_ALIASES,
  parseCron,
  nextCronRun,
  isSubDailyCron
};
