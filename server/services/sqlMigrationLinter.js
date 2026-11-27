/**
 * Zero-Downtime SQL Migration Linter (Squawk / Strong Migrations — 100% Zero-Dep Pure JS).
 *
 * Analiza migraciones DDL con un tokenizador SQL real en una sola pasada que elimina
 * comentarios (`--`, `/* ... *\/` anidados), literales `'...'` y bloques `$$...$$`
 * antes de dividir sentencias por `;` — cero falsos positivos por comentarios o strings.
 *
 * Detecta 10 patrones críticos de bloqueo / pérdida de datos (9 blockers + 1 warning):
 *  1. `CREATE_INDEX_NOT_CONCURRENT` (blocker)
 *  2. `DROP_INDEX_NOT_CONCURRENT` (blocker)
 *  3. `MISSING_LOCK_TIMEOUT` (blocker)
 *  4. `UNSAFE_ADD_CONSTRAINT` (blocker — FOREIGN KEY / CHECK sin NOT VALID)
 *  5. `DESTRUCTIVE_DROP_COLUMN_OR_TABLE` (blocker)
 *  6. `ALTER_COLUMN_TYPE_REWRITE` (blocker)
 *  7. `SET_NOT_NULL_WITHOUT_CHECK` (blocker)
 *  8. `VOLATILE_ADD_COLUMN_DEFAULT` (blocker)
 *  9. `UNSAFE_RENAME_OBJECT` (blocker)
 * 10. `MISSING_STATEMENT_TIMEOUT` (warning — mantiene `safe: true` si 0 blockers)
 */

const RULES = Object.freeze([
  Object.freeze({
    id: 'CREATE_INDEX_NOT_CONCURRENT',
    severity: 'blocker',
    title: 'CREATE INDEX without CONCURRENTLY acquires SHARE lock blocking writes',
    rewriteHint: 'Use CREATE INDEX CONCURRENTLY (or CREATE UNIQUE INDEX CONCURRENTLY) outside an explicit BEGIN/COMMIT block.'
  }),
  Object.freeze({
    id: 'DROP_INDEX_NOT_CONCURRENT',
    severity: 'blocker',
    title: 'DROP INDEX without CONCURRENTLY acquires ACCESS EXCLUSIVE lock',
    rewriteHint: 'Use DROP INDEX CONCURRENTLY IF EXISTS <index_name>.'
  }),
  Object.freeze({
    id: 'MISSING_LOCK_TIMEOUT',
    severity: 'blocker',
    title: 'DDL migration missing SET lock_timeout can queue-block all production traffic',
    rewriteHint: "Prepend SET lock_timeout = '5s'; before running DDL statements."
  }),
  Object.freeze({
    id: 'UNSAFE_ADD_CONSTRAINT',
    severity: 'blocker',
    title: 'ADD CONSTRAINT (FOREIGN KEY / CHECK) without NOT VALID scans entire table under lock',
    rewriteHint: 'Add NOT VALID first (ADD CONSTRAINT ... CHECK/FOREIGN KEY ... NOT VALID), then run ALTER TABLE ... VALIDATE CONSTRAINT ... in a separate step.'
  }),
  Object.freeze({
    id: 'DESTRUCTIVE_DROP_COLUMN_OR_TABLE',
    severity: 'blocker',
    title: 'DROP COLUMN / DROP TABLE breaks live old-version replicas during rolling deploy',
    rewriteHint: 'Use expand-contract: stop referencing the column/table in app code, deploy, then drop in a follow-up migration.'
  }),
  Object.freeze({
    id: 'ALTER_COLUMN_TYPE_REWRITE',
    severity: 'blocker',
    title: 'ALTER COLUMN TYPE rewrites the table under ACCESS EXCLUSIVE lock',
    rewriteHint: 'Use expand-contract: add a new nullable column, backfill in batches, dual-write, then swap.'
  }),
  Object.freeze({
    id: 'SET_NOT_NULL_WITHOUT_CHECK',
    severity: 'blocker',
    title: 'SET NOT NULL without a validated CHECK constraint locks the table for a full scan',
    rewriteHint: 'Add CHECK (col IS NOT NULL) NOT VALID, run VALIDATE CONSTRAINT, then SET NOT NULL (PostgreSQL 12+ skips the scan).'
  }),
  Object.freeze({
    id: 'VOLATILE_ADD_COLUMN_DEFAULT',
    severity: 'blocker',
    title: 'ADD COLUMN with volatile DEFAULT (now/random/gen_random_uuid) rewrites every existing row',
    rewriteHint: 'Add the column nullable without a volatile default, backfill existing rows in batches, then ALTER COLUMN SET DEFAULT.'
  }),
  Object.freeze({
    id: 'UNSAFE_RENAME_OBJECT',
    severity: 'blocker',
    title: 'RENAME COLUMN / RENAME TO breaks running application replicas immediately',
    rewriteHint: 'Use expand-contract: create the new column or view alias, migrate readers/writers, then retire the old name.'
  }),
  Object.freeze({
    id: 'MISSING_STATEMENT_TIMEOUT',
    severity: 'warning',
    title: 'DDL migration missing SET statement_timeout can hold long-running locks indefinitely',
    rewriteHint: "Add SET statement_timeout = '30s'; alongside lock_timeout to cap runaway migrations."
  })
]);

const RULE_BY_ID = Object.freeze(
  Object.fromEntries(RULES.map((r) => [r.id, r]))
);

const DDL_STMT_RE = /^\s*(?:ALTER\s+TABLE|CREATE\s+(?:UNIQUE\s+)?INDEX|DROP\s+INDEX|CREATE\s+TABLE|DROP\s+TABLE|TRUNCATE|REINDEX|CLUSTER|VACUUM)\b/i;
const VOLATILE_DEFAULT_RE = /\bDEFAULT\b[^,;)]*\b(?:now\s*\(\s*\)|random\s*\(\s*\)|gen_random_uuid\s*\(\s*\)|uuid_generate_v[14]\s*\(\s*\)|clock_timestamp\s*\(\s*\)|current_timestamp\b|timeofday\s*\(\s*\))/i;

/**
 * Tokenizador SQL puro en una pasada: elimina comentarios `--` y `/* ... *\/` anidados,
 * neutraliza literales `'...'` y `$tag$...$tag$` en `''`, y divide sentencias por `;`.
 *
 * @param {string} rawSql
 * @returns {string[]}
 */
function tokenizeAndSplitSql(rawSql) {
  const src = String(rawSql || '');
  const len = src.length;
  /** @type {string[]} */
  const statements = [];
  let current = '';
  let i = 0;

  while (i < len) {
    const ch = src[i];
    const next = i + 1 < len ? src[i + 1] : '';

    // 1. Line comment (-- ...)
    if (ch === '-' && next === '-') {
      i += 2;
      while (i < len && src[i] !== '\n') i++;
      current += ' ';
      continue;
    }

    // 2. Block comment (/* ... */ with PostgreSQL nesting support)
    if (ch === '/' && next === '*') {
      let depth = 1;
      i += 2;
      while (i < len && depth > 0) {
        if (src[i] === '/' && i + 1 < len && src[i + 1] === '*') {
          depth++;
          i += 2;
        } else if (src[i] === '*' && i + 1 < len && src[i + 1] === '/') {
          depth--;
          i += 2;
        } else {
          i++;
        }
      }
      current += ' ';
      continue;
    }

    // 3. Single-quoted string literal ('...' with '' escape)
    if (ch === "'") {
      i++;
      while (i < len) {
        if (src[i] === "'") {
          if (i + 1 < len && src[i + 1] === "'") {
            i += 2;
            continue;
          }
          i++;
          break;
        }
        i++;
      }
      current += "''";
      continue;
    }

    // 4. Dollar-quoted string literal ($$...$$ or $tag$...$tag$)
    if (ch === '$') {
      const rest = src.slice(i);
      const tagMatch = rest.match(/^\$([A-Za-z_][A-Za-z0-9_]*)?\$/);
      if (tagMatch) {
        const delim = tagMatch[0];
        const endIdx = src.indexOf(delim, i + delim.length);
        if (endIdx >= 0) {
          i = endIdx + delim.length;
          current += "''";
          continue;
        }
      }
    }

    // 5. Double-quoted identifier ("...")
    if (ch === '"') {
      current += ch;
      i++;
      while (i < len) {
        current += src[i];
        if (src[i] === '"') {
          if (i + 1 < len && src[i + 1] === '"') {
            current += '"';
            i += 2;
            continue;
          }
          i++;
          break;
        }
        i++;
      }
      continue;
    }

    // 6. Statement delimiter
    if (ch === ';') {
      const trimmed = current.replace(/\s+/g, ' ').trim();
      if (trimmed) statements.push(trimmed);
      current = '';
      i++;
      continue;
    }

    current += ch;
    i++;
  }

  const tail = current.replace(/\s+/g, ' ').trim();
  if (tail) statements.push(tail);
  return statements;
}

/**
 * Analiza una migración SQL DDL con las 10 reglas zero-downtime.
 *
 * @param {string} sql
 * @param {{ requireStatementTimeout?: boolean }} [options]
 */
function lintSqlMigration(sql, options = {}) {
  if (typeof sql !== 'string') {
    const err = new Error('lintSqlMigration requiere una cadena SQL válida');
    /** @type {any} */ (err).status = 400;
    throw err;
  }

  const statements = tokenizeAndSplitSql(sql);
  /** @type {Array<{ rule: string, severity: 'blocker', statementIndex: number, message: string, rewriteHint: string }>} */
  const blockers = [];
  /** @type {Array<{ rule: string, severity: 'warning', statementIndex: number, message: string, rewriteHint: string }>} */
  const warnings = [];
  /** @type {Set<string>} */
  const hintSet = new Set();

  let hasLockTimeout = false;
  let hasStatementTimeout = false;
  let hasDdl = false;
  let hasValidatedCheck = false;
  let missingLockTimeoutReported = false;

  const pushFinding = (ruleId, statementIndex, customMessage = null) => {
    const rule = RULE_BY_ID[ruleId];
    if (!rule) return;
    hintSet.add(rule.rewriteHint);
    const entry = {
      rule: rule.id,
      severity: rule.severity,
      statementIndex,
      message: customMessage || rule.title,
      rewriteHint: rule.rewriteHint
    };
    if (rule.severity === 'blocker') {
      blockers.push(/** @type {any} */ (entry));
    } else {
      warnings.push(/** @type {any} */ (entry));
    }
  };

  for (let idx = 0; idx < statements.length; idx++) {
    const stmt = statements[idx];
    const stmtNum = idx + 1;

    if (/^SET\s+(?:LOCAL\s+|SESSION\s+)?lock_timeout\b/i.test(stmt)) {
      hasLockTimeout = true;
      continue;
    }
    if (/^SET\s+(?:LOCAL\s+|SESSION\s+)?statement_timeout\b/i.test(stmt)) {
      hasStatementTimeout = true;
      continue;
    }

    if (/\bVALIDATE\s+CONSTRAINT\b/i.test(stmt)) {
      hasValidatedCheck = true;
    }

    const isDdl = DDL_STMT_RE.test(stmt);
    if (isDdl) {
      hasDdl = true;
      if (!hasLockTimeout && !missingLockTimeoutReported) {
        missingLockTimeoutReported = true;
        pushFinding('MISSING_LOCK_TIMEOUT', stmtNum);
      }
    }

    // 1. CREATE INDEX without CONCURRENTLY
    if (/^CREATE\s+(?:UNIQUE\s+)?INDEX\b/i.test(stmt) && !/\bCONCURRENTLY\b/i.test(stmt)) {
      pushFinding('CREATE_INDEX_NOT_CONCURRENT', stmtNum);
    }

    // 2. DROP INDEX without CONCURRENTLY
    if (/^DROP\s+INDEX\b/i.test(stmt) && !/\bCONCURRENTLY\b/i.test(stmt)) {
      pushFinding('DROP_INDEX_NOT_CONCURRENT', stmtNum);
    }

    // 3. DESTRUCTIVE DROP TABLE / DROP COLUMN (ignora DROP CONSTRAINT / DROP DEFAULT / DROP NOT NULL)
    if (/^DROP\s+TABLE\b/i.test(stmt) || (/^ALTER\s+TABLE\b/i.test(stmt) && /\bDROP\s+(?:COLUMN\s+)?(?:IF\s+EXISTS\s+)?(?!CONSTRAINT\b|DEFAULT\b|NOT\s+NULL\b|IDENTITY\b|EXPRESSION\b)/i.test(stmt))) {
      pushFinding('DESTRUCTIVE_DROP_COLUMN_OR_TABLE', stmtNum);
    }

    if (/^ALTER\s+TABLE\b/i.test(stmt)) {
      // 4. UNSAFE ADD CONSTRAINT (FOREIGN KEY or CHECK without NOT VALID)
      if (/\bADD\s+(?:CONSTRAINT\s+[\w."]+\s+)?(?:FOREIGN\s+KEY|CHECK)\b/i.test(stmt) && !/\bNOT\s+VALID\b/i.test(stmt)) {
        pushFinding('UNSAFE_ADD_CONSTRAINT', stmtNum);
      }

      // 5. ALTER COLUMN TYPE rewrite
      if (/\bALTER\s+(?:COLUMN\s+)?[\w."]+\s+(?:SET\s+DATA\s+)?TYPE\b/i.test(stmt)) {
        pushFinding('ALTER_COLUMN_TYPE_REWRITE', stmtNum);
      }

      // 6. SET NOT NULL without prior validated CHECK constraint
      if (/\bALTER\s+(?:COLUMN\s+)?[\w."]+\s+SET\s+NOT\s+NULL\b/i.test(stmt) && !hasValidatedCheck) {
        pushFinding('SET_NOT_NULL_WITHOUT_CHECK', stmtNum);
      }

      // 7. VOLATILE ADD COLUMN DEFAULT
      if (/\bADD\s+(?:COLUMN\s+)?(?!CONSTRAINT\b)/i.test(stmt) && VOLATILE_DEFAULT_RE.test(stmt)) {
        pushFinding('VOLATILE_ADD_COLUMN_DEFAULT', stmtNum);
      }

      // 8. UNSAFE RENAME COLUMN / RENAME TO
      if (/\bRENAME\s+(?:COLUMN\b|TO\b)/i.test(stmt)) {
        pushFinding('UNSAFE_RENAME_OBJECT', stmtNum);
      }
    }
  }

  // 10. Warning: MISSING_STATEMENT_TIMEOUT (keeps safe: true when 0 blockers!)
  if (hasDdl && !hasStatementTimeout && options.requireStatementTimeout !== false) {
    pushFinding('MISSING_STATEMENT_TIMEOUT', 1);
  }

  const penalty = (blockers.length * 18) + (warnings.length * 5);
  const score = Math.max(0, Math.min(100, 100 - penalty));

  return {
    ok: true,
    safe: blockers.length === 0,
    score,
    blockers,
    warnings,
    rewriteHints: Array.from(hintSet),
    analyzedStatements: statements.length,
    hasLockTimeout,
    hasStatementTimeout
  };
}

module.exports = {
  RULES,
  lintSqlMigration,
  tokenizeAndSplitSql
};
