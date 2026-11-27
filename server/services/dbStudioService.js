/**
 * Zero-Dep Read-Only Live DB Studio & Safe Redis/Valkey Inspector (cura `Dokploy CVE-2026-24841`).
 *
 * Garantías estrictas de solo lectura y seguridad:
 *  - 0 dependencias npm externas, 0 invocaciones de shell, 0 sidecars (sin Adminer/pgAdmin).
 *  - Escáner léxico SQL real en una sola pasada: elimina comentarios `--` y `/* ... *\/`
 *    anidados respetando literales de cadena `'...'`, rechaza metacomandos `psql` (`\!`,
 *    `\copy`, `\i`, `\o`, `\gexec`), rechaza bloques `$tag$...$tag$`, rechaza sentencias
 *    apiladas (`;`), rechaza TODAS las palabras clave mutantes/DDL/DML/archivos (incluso
 *    dentro de CTEs `WITH`), impone `LIMIT <= 200`, y envuelve la ejecución en
 *    `BEGIN TRANSACTION READ ONLY; SET LOCAL statement_timeout = '5000ms'; ...; ROLLBACK;`.
 *  - Inspector Redis/Valkey con lista blanca estricta (`SCAN`, `TYPE`, `TTL`, `PTTL`, `DBSIZE`,
 *    `INFO`, `STRLEN`, `LLEN`, `HLEN`, `SCARD`, `ZCARD`, `GET`), bloqueo explícito de
 *    `KEYS *`/`FLUSHALL`/`CONFIG`/`EVAL`/`SET`/`DEL` y `SCAN COUNT <= 100`.
 */

const MAX_ROW_LIMIT = 200;
const STATEMENT_TIMEOUT_MS = 5000;
const MAX_SQL_BYTES = 16 * 1024;
const MAX_REDIS_SCAN_COUNT = 100;
const DEFAULT_REDIS_SCAN_COUNT = 50;

const ALLOWED_SQL_LEADING = new Set(['SELECT', 'EXPLAIN', 'SHOW', 'WITH']);

const FORBIDDEN_SQL_KEYWORDS = new Set([
  'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'TRUNCATE', 'CREATE',
  'GRANT', 'REVOKE', 'COPY', 'CALL', 'DO', 'SET', 'RESET', 'VACUUM',
  'ANALYZE', 'CLUSTER', 'REINDEX', 'ATTACH', 'DETACH', 'PRAGMA',
  'MERGE', 'REPLACE', 'EXEC', 'EXECUTE', 'LOAD', 'LOCK', 'LISTEN',
  'NOTIFY', 'PREPARE', 'DEALLOCATE',
  'PG_TERMINATE_BACKEND', 'PG_CANCEL_BACKEND', 'PG_RELOAD_CONF', 'PG_ROTATE_LOGFILE',
  'PG_READ_FILE', 'PG_READ_BINARY_FILE', 'PG_LS_DIR', 'PG_STAT_FILE',
  'LO_IMPORT', 'LO_EXPORT', 'LO_UNLINK', 'DBLINK', 'DBLINK_EXEC'
]);

const ALLOWED_REDIS_COMMANDS = new Set([
  'SCAN', 'TYPE', 'TTL', 'PTTL', 'DBSIZE', 'INFO',
  'STRLEN', 'LLEN', 'HLEN', 'SCARD', 'ZCARD', 'GET'
]);

const DENIED_REDIS_COMMANDS = new Set([
  'KEYS', 'FLUSHALL', 'FLUSHDB', 'CONFIG', 'EVAL', 'EVALSHA', 'EVAL_RO', 'EVALSHA_RO',
  'SCRIPT', 'DEBUG', 'SHUTDOWN', 'MODULE', 'SLAVEOF', 'REPLICAOF', 'SAVE', 'BGSAVE',
  'SET', 'MSET', 'DEL', 'UNLINK', 'RENAME', 'RENAMENX', 'MIGRATE', 'CLIENT', 'ACL',
  'MONITOR', 'RESTORE', 'FUNCTION', 'FCALL'
]);

/**
 * Crea un error HTTP tipado de validación/rechazo.
 * @param {string} message
 * @param {number} status
 * @param {string} code
 */
function makeStudioError(message, status, code) {
  const err = new Error(message);
  /** @type {any} */ (err).status = status;
  /** @type {any} */ (err).code = code;
  return err;
}

/**
 * Escáner léxico SQL: elimina comentarios `--` y `/* ... *\/` (incluyendo anidados)
 * respetando literales entre comillas simples `'...'`, rechaza metacomandos psql y
 * bloques dollar-quoted `$tag$`, y devuelve:
 *  - `cleanedSql`: SQL ejecutable sin comentarios (conservando literales de cadena)
 *  - `codeOnly`: misma estructura con literales sustituidos por `''` para análisis seguro de tokens
 *
 * @param {string} rawSql
 */
function lexAndStripSql(rawSql) {
  let cleanedSql = '';
  let codeOnly = '';
  const len = rawSql.length;
  let i = 0;

  while (i < len) {
    const ch = rawSql[i];
    const next = i + 1 < len ? rawSql[i + 1] : '';

    // 1. Literal de cadena con comillas simples ('...' con escape '')
    if (ch === "'") {
      let lit = "'";
      i++;
      let closed = false;
      while (i < len) {
        const c = rawSql[i];
        lit += c;
        if (c === "'") {
          if (i + 1 < len && rawSql[i + 1] === "'") {
            lit += "'";
            i += 2;
            continue;
          }
          closed = true;
          i++;
          break;
        }
        i++;
      }
      if (!closed) {
        throw makeStudioError('Literal SQL sin cerrar (comilla simple desbalanceada)', 400, 'SQL_UNTERMINATED_STRING');
      }
      cleanedSql += lit;
      codeOnly += "''";
      continue;
    }

    // 2. Identificador entre comillas dobles ("...")
    if (ch === '"') {
      let ident = '"';
      i++;
      let closed = false;
      while (i < len) {
        const c = rawSql[i];
        ident += c;
        if (c === '"') {
          if (i + 1 < len && rawSql[i + 1] === '"') {
            ident += '"';
            i += 2;
            continue;
          }
          closed = true;
          i++;
          break;
        }
        i++;
      }
      if (!closed) {
        throw makeStudioError('Identificador SQL sin cerrar (comilla doble desbalanceada)', 400, 'SQL_UNTERMINATED_IDENT');
      }
      cleanedSql += ident;
      codeOnly += ident;
      continue;
    }

    // 3. Comentario de línea (-- ...)
    if (ch === '-' && next === '-') {
      i += 2;
      while (i < len && rawSql[i] !== '\n') i++;
      cleanedSql += ' ';
      codeOnly += ' ';
      continue;
    }

    // 4. Comentario de bloque (/* ... */ con soporte de anidamiento PostgreSQL)
    if (ch === '/' && next === '*') {
      let depth = 1;
      i += 2;
      while (i < len && depth > 0) {
        if (rawSql[i] === '/' && i + 1 < len && rawSql[i + 1] === '*') {
          depth++;
          i += 2;
        } else if (rawSql[i] === '*' && i + 1 < len && rawSql[i + 1] === '/') {
          depth--;
          i += 2;
        } else {
          i++;
        }
      }
      if (depth > 0) {
        throw makeStudioError('Comentario de bloque SQL sin cerrar', 400, 'SQL_UNTERMINATED_COMMENT');
      }
      cleanedSql += ' ';
      codeOnly += ' ';
      continue;
    }

    // 5. Rechazar metacomandos de psql (\!, \copy, \i, \o, \gexec, etc.) fuera de literales
    if (ch === '\\') {
      throw makeStudioError('Metacomandos psql con barra invertida (\\!, \\copy, \\i, \\gexec) estrictamente prohibidos', 403, 'SQL_PSQL_METACOMMAND_BLOCKED');
    }

    // 6. Rechazar dollar-quoting ($tag$ / $$) que permite bloques DO / funciones PL/pgSQL
    if (ch === '$' && (next === '$' || /[A-Za-z_]/.test(next))) {
      throw makeStudioError('Bloques dollar-quoted ($tag$ / $$) no permitidos en DB Studio de solo lectura', 403, 'SQL_DOLLAR_QUOTE_BLOCKED');
    }

    cleanedSql += ch;
    codeOnly += ch;
    i++;
  }

  return { cleanedSql: cleanedSql.trim(), codeOnly: codeOnly.trim() };
}

/**
 * Valida estrictamente una consulta SQL de solo lectura y genera un bloque envuelto
 * en `BEGIN TRANSACTION READ ONLY; SET LOCAL statement_timeout = '5000ms'; ...; ROLLBACK;`.
 *
 * @param {string} sql
 * @param {{ maxRows?: number }} [opts]
 */
function validateReadOnlySql(sql, opts = {}) {
  if (typeof sql !== 'string' || !sql.trim()) {
    throw makeStudioError('Consulta SQL vacía o inválida', 400, 'SQL_EMPTY');
  }
  if (sql.includes('\0')) {
    throw makeStudioError('Bytes nulos no permitidos en consulta SQL', 400, 'SQL_NULL_BYTE');
  }
  if (Buffer.byteLength(sql, 'utf8') > MAX_SQL_BYTES) {
    throw makeStudioError(`Consulta SQL supera el límite de ${MAX_SQL_BYTES} bytes`, 400, 'SQL_TOO_LARGE');
  }

  const { cleanedSql, codeOnly } = lexAndStripSql(sql);
  if (!cleanedSql || !codeOnly) {
    throw makeStudioError('Consulta SQL vacía tras eliminar comentarios', 400, 'SQL_EMPTY');
  }

  // Eliminar un único punto y coma final opcional y rechazar cualquier `;` restante (sentencias apiladas)
  const trimmedClean = cleanedSql.replace(/;\s*$/, '').trim();
  const trimmedCode = codeOnly.replace(/;\s*$/, '').trim();
  if (trimmedCode.includes(';')) {
    throw makeStudioError('Sentencias SQL apiladas (;) estrictamente prohibidas en modo solo lectura', 403, 'SQL_STACKED_STATEMENT_BLOCKED');
  }

  // Extraer tokens de palabras clave sobre codeOnly (sin comentarios ni literales)
  const wordMatches = trimmedCode.match(/\b[A-Za-z_][A-Za-z0-9_]*\b/g) || [];
  if (wordMatches.length === 0) {
    throw makeStudioError('No se detectó ninguna sentencia SQL válida', 400, 'SQL_INVALID');
  }

  const upperTokens = wordMatches.map((w) => w.toUpperCase());
  const leadingKeyword = upperTokens[0];
  if (!ALLOWED_SQL_LEADING.has(leadingKeyword)) {
    throw makeStudioError(
      `Sentencia "${leadingKeyword}" rechazada: solo se permiten SELECT, EXPLAIN, SHOW y WITH en modo solo lectura`,
      403,
      'SQL_MUTATION_BLOCKED'
    );
  }

  // Comprobar todas las palabras clave prohibidas en cualquier posición (incluyendo CTEs WITH)
  for (let idx = 0; idx < upperTokens.length; idx++) {
    const tok = upperTokens[idx];
    if (FORBIDDEN_SQL_KEYWORDS.has(tok)) {
      // Permitir opción ANALYZE exclusivamente en encabezado de `EXPLAIN [ANALYZE]` sobre consultas de lectura pura
      // (cualquier palabra mutante dentro de la consulta será rechazada en este mismo bucle!)
      if (tok === 'ANALYZE' && leadingKeyword === 'EXPLAIN' && idx <= 5) {
        continue;
      }
      throw makeStudioError(
        `Palabra clave o función prohibida "${tok}" detectada en consulta de solo lectura`,
        403,
        'SQL_MUTATION_BLOCKED'
      );
    }
  }

  // Bloquear `SELECT ... INTO <nueva_tabla>` que crea tablas implícitamente
  if (/\bSELECT\b[\s\S]*\bINTO\b/i.test(trimmedCode)) {
    throw makeStudioError('SELECT ... INTO prohibido en modo solo lectura', 403, 'SQL_MUTATION_BLOCKED');
  }

  // En EXPLAIN: verificar que la sentencia explicada también sea estrictamente de solo lectura (SELECT/WITH/SHOW)
  if (leadingKeyword === 'EXPLAIN') {
    const explainBody = trimmedCode
      .replace(/^EXPLAIN\b/i, '')
      .replace(/^\s*\([^)]*\)/, '')
      .replace(/^\s*(?:ANALYZE|VERBOSE|COSTS|SETTINGS|BUFFERS|WAL|TIMING|SUMMARY|MEMORY)\b/gi, '')
      .trim();
    const bodyMatch = explainBody.match(/^([A-Za-z_]+)/);
    const bodyVerb = bodyMatch ? bodyMatch[1].toUpperCase() : '';
    if (!['SELECT', 'WITH', 'SHOW'].includes(bodyVerb)) {
      throw makeStudioError(
        `EXPLAIN solo puede analizar consultas SELECT/WITH/SHOW (recibido: "${bodyVerb || 'desconocido'}")`,
        403,
        'SQL_MUTATION_BLOCKED'
      );
    }
  }

  const rowCap = Math.min(MAX_ROW_LIMIT, Math.max(1, Math.round(Number(opts.maxRows) || MAX_ROW_LIMIT)));
  let finalSql = trimmedClean;
  let limitClamped = false;

  if (leadingKeyword === 'SELECT' || leadingKeyword === 'WITH') {
    const limitRe = /\bLIMIT\s+(\d+)(\s+OFFSET\s+\d+)?\s*$/i;
    const limitAllRe = /\bLIMIT\s+ALL(\s+OFFSET\s+\d+)?\s*$/i;
    const limMatch = finalSql.match(limitRe);
    if (limMatch) {
      const requestedLimit = Number(limMatch[1]);
      if (requestedLimit > rowCap) {
        finalSql = finalSql.replace(limitRe, `LIMIT ${rowCap}${limMatch[2] || ''}`);
        limitClamped = true;
      }
    } else if (limitAllRe.test(finalSql)) {
      finalSql = finalSql.replace(limitAllRe, `LIMIT ${rowCap}$1`);
      limitClamped = true;
    } else {
      finalSql = `${finalSql} LIMIT ${rowCap}`;
      limitClamped = true;
    }
  }

  const wrappedSql = `BEGIN TRANSACTION READ ONLY; SET LOCAL statement_timeout = '${STATEMENT_TIMEOUT_MS}ms'; ${finalSql}; ROLLBACK;`;

  return {
    ok: true,
    readOnlyEnforced: true,
    leadingKeyword,
    sanitizedSql: finalSql,
    wrappedSql,
    rowCap,
    statementTimeoutMs: STATEMENT_TIMEOUT_MS,
    limitClamped
  };
}

/**
 * Valida un comando Redis/Valkey exclusivamente de inspección segura (lista blanca estricta,
 * `SCAN COUNT <= 100`, bloqueo total de `KEYS *`, `FLUSHALL`, `EVAL`, `CONFIG`, `SET`, `DEL`).
 *
 * @param {string | string[]} argv
 */
function validateSafeRedisCommand(argv) {
  /** @type {string[]} */
  let tokens = [];
  if (Array.isArray(argv)) {
    tokens = argv.map((t) => String(t ?? '').trim()).filter(Boolean);
  } else if (typeof argv === 'string') {
    if (/[\r\n\0]/.test(argv)) {
      throw makeStudioError('Caracteres de control no permitidos en comando Redis', 400, 'REDIS_INVALID_INPUT');
    }
    tokens = argv.trim().split(/\s+/).filter(Boolean);
  } else {
    throw makeStudioError('Comando Redis inválido (se requiere string o string[])', 400, 'REDIS_INVALID_INPUT');
  }

  if (tokens.length === 0) {
    throw makeStudioError('Comando Redis vacío', 400, 'REDIS_EMPTY');
  }
  if (tokens.length > 16) {
    throw makeStudioError('Demasiados argumentos en comando Redis de inspección (máximo 16)', 400, 'REDIS_TOO_MANY_ARGS');
  }
  for (const tok of tokens) {
    if (/[\r\n\0;|&`$]/.test(tok)) {
      throw makeStudioError('Metacaracteres prohibidos en argumentos Redis', 400, 'REDIS_INVALID_ARG');
    }
  }

  const cmd = tokens[0].toUpperCase();
  if (DENIED_REDIS_COMMANDS.has(cmd)) {
    throw makeStudioError(
      `Comando Redis "${cmd}" bloqueado por política de solo lectura / anti-bloqueo (O(N) o mutante)`,
      403,
      'REDIS_COMMAND_BLOCKED'
    );
  }
  if (!ALLOWED_REDIS_COMMANDS.has(cmd)) {
    throw makeStudioError(
      `Comando Redis "${cmd}" no está en la lista blanca de inspección segura (${Array.from(ALLOWED_REDIS_COMMANDS).join(', ')})`,
      403,
      'REDIS_COMMAND_NOT_ALLOWED'
    );
  }

  const normalizedArgv = [cmd, ...tokens.slice(1)];
  let countClamped = false;

  if (cmd === 'SCAN') {
    if (normalizedArgv.length === 1) {
      normalizedArgv.push('0');
    }
    if (!/^\d+$/.test(normalizedArgv[1])) {
      throw makeStudioError(`Cursor SCAN inválido: "${normalizedArgv[1]}" (debe ser entero >= 0)`, 400, 'REDIS_INVALID_CURSOR');
    }
    let foundCountIdx = -1;
    for (let i = 2; i < normalizedArgv.length - 1; i++) {
      if (normalizedArgv[i].toUpperCase() === 'COUNT') {
        foundCountIdx = i + 1;
        break;
      }
    }
    if (foundCountIdx >= 0) {
      const requestedCount = Number(normalizedArgv[foundCountIdx]);
      if (!Number.isInteger(requestedCount) || requestedCount < 1) {
        normalizedArgv[foundCountIdx] = String(DEFAULT_REDIS_SCAN_COUNT);
        countClamped = true;
      } else if (requestedCount > MAX_REDIS_SCAN_COUNT) {
        normalizedArgv[foundCountIdx] = String(MAX_REDIS_SCAN_COUNT);
        countClamped = true;
      }
    } else {
      normalizedArgv.push('COUNT', String(DEFAULT_REDIS_SCAN_COUNT));
      countClamped = true;
    }
  }

  return {
    ok: true,
    readOnlyEnforced: true,
    command: cmd,
    normalizedArgv,
    maxScanCount: MAX_REDIS_SCAN_COUNT,
    countClamped
  };
}

/**
 * Analiza estadísticas de tablas e índices de PostgreSQL (`pg_stat_user_tables` /
 * `pg_stat_user_indexes`) detectando bloat por tuplas muertas e índices sin uso.
 *
 * @param {any[]} [tableStats]
 */
function analyzePostgresBloat(tableStats = []) {
  const list = Array.isArray(tableStats) ? tableStats : [];
  /** @type {any[]} */
  const bloatedTables = [];
  /** @type {any[]} */
  const unusedIndexes = [];
  /** @type {string[]} */
  const recommendations = [];

  for (const row of list) {
    if (!row || typeof row !== 'object') continue;
    const schema = String(row.schema || row.schemaname || 'public');
    const table = String(row.table || row.tableName || row.relname || 'unknown');
    const liveTuples = Math.max(0, Number(row.liveTuples ?? row.n_live_tup ?? 0) || 0);
    const deadTuples = Math.max(0, Number(row.deadTuples ?? row.n_dead_tup ?? 0) || 0);
    const totalTuples = liveTuples + deadTuples;
    const deadTupleRatio = totalTuples > 0 ? Number((deadTuples / totalTuples).toFixed(4)) : 0;
    const sizeBytes = Math.max(0, Number(row.sizeBytes ?? row.tableSizeBytes ?? 0) || 0);

    if (deadTupleRatio >= 0.2 || deadTuples >= 10000) {
      const severity = (deadTupleRatio >= 0.4 || deadTuples >= 100000) ? 'high' : 'medium';
      bloatedTables.push({
        schema,
        table,
        liveTuples,
        deadTuples,
        deadTupleRatio,
        sizeBytes,
        severity
      });
      recommendations.push(
        `Table ${schema}.${table} has ${(deadTupleRatio * 100).toFixed(1)}% dead tuples (${deadTuples}). Schedule VACUUM (ANALYZE) ${schema}.${table} during a maintenance window.`
      );
    }

    const idxList = Array.isArray(row.indexes) ? row.indexes : [];
    for (const idx of idxList) {
      if (!idx || typeof idx !== 'object') continue;
      const idxScan = Number(idx.idx_scan ?? idx.idxScan ?? 0) || 0;
      const idxSize = Number(idx.sizeBytes ?? idx.size_bytes ?? 0) || 0;
      const idxName = String(idx.name || idx.indexrelname || 'unknown_idx');
      if (idxScan === 0 && idxSize > 65536) {
        unusedIndexes.push({
          schema,
          table,
          indexName: idxName,
          idxScan,
          sizeBytes: idxSize
        });
        recommendations.push(
          `Index ${schema}.${idxName} on ${table} has 0 scans (${Math.round(idxSize / 1024)} KiB). Consider DROP INDEX CONCURRENTLY if not enforcing uniqueness.`
        );
      }
    }
  }

  return {
    ok: true,
    checkedTables: list.length,
    bloatedTables,
    unusedIndexes,
    recommendations
  };
}

/**
 * Resume un plan JSON de PostgreSQL `EXPLAIN (FORMAT JSON)` extrayendo coste total,
 * tiempo de ejecución, nodos `Seq Scan` vs `Index Scan` y alertas accionables.
 *
 * @param {any} planJson
 */
function summarizeExplainPlan(planJson) {
  let parsed = planJson;
  if (typeof planJson === 'string') {
    try {
      parsed = JSON.parse(planJson);
    } catch (e) {
      throw makeStudioError('EXPLAIN JSON inválido', 400, 'EXPLAIN_INVALID_JSON');
    }
  }
  const rootEntry = Array.isArray(parsed) ? parsed[0] : parsed;
  const rootPlan = rootEntry && rootEntry.Plan ? rootEntry.Plan : rootEntry;
  if (!rootPlan || typeof rootPlan !== 'object') {
    throw makeStudioError('Estructura EXPLAIN Plan ausente', 400, 'EXPLAIN_EMPTY');
  }

  /** @type {Array<{ relation: string, cost: number, rows: number, filter: string | null }>} */
  const seqScanNodes = [];
  /** @type {Array<{ nodeType: string, relation: string, indexName: string | null, cost: number, rows: number }>} */
  const indexScanNodes = [];
  /** @type {string[]} */
  const warnings = [];

  /** @param {any} node */
  const walk = (node) => {
    if (!node || typeof node !== 'object') return;
    const nodeType = String(node['Node Type'] || '');
    const relation = String(node['Relation Name'] || node['Alias'] || 'unknown');
    const cost = Number(node['Total Cost'] || 0);
    const rows = Number(node['Actual Rows'] ?? node['Plan Rows'] ?? 0);

    if (nodeType === 'Seq Scan') {
      seqScanNodes.push({
        relation,
        cost,
        rows,
        filter: node.Filter ? String(node.Filter) : null
      });
      if (cost >= 1000 || rows >= 5000) {
        warnings.push(`Sequential scan on "${relation}" (cost=${cost}, rows=${rows}) — consider adding an index on filter columns.`);
      }
    } else if (/Index/i.test(nodeType)) {
      indexScanNodes.push({
        nodeType,
        relation,
        indexName: node['Index Name'] ? String(node['Index Name']) : null,
        cost,
        rows
      });
    }

    if (Array.isArray(node.Plans)) {
      for (const child of node.Plans) walk(child);
    }
  };
  walk(rootPlan);

  const totalCost = Number(rootPlan['Total Cost'] || 0);
  const executionTimeMs = rootEntry && rootEntry['Execution Time'] != null
    ? Number(rootEntry['Execution Time'])
    : (rootPlan['Actual Total Time'] != null ? Number(rootPlan['Actual Total Time']) : null);
  const planningTimeMs = rootEntry && rootEntry['Planning Time'] != null
    ? Number(rootEntry['Planning Time'])
    : null;

  if (totalCost >= 10000) {
    warnings.push(`High estimated query cost (${totalCost}). Review joins and index coverage.`);
  }
  if (executionTimeMs != null && executionTimeMs >= 1000) {
    warnings.push(`Slow query execution (${executionTimeMs} ms >= 1000 ms).`);
  }

  return {
    ok: true,
    totalCost,
    planningTimeMs,
    executionTimeMs,
    seqScanNodes,
    indexScanNodes,
    warnings
  };
}

class DbStudioService {
  /**
   * Valida y ejecuta (o previsualiza en modo dry-run si no hay driver conectado)
   * una consulta SQL estrictamente de solo lectura.
   *
   * @param {{
   *   databaseId?: string,
   *   engine?: string,
   *   query: string,
   *   maxRows?: number,
   *   executor?: (ctx: { databaseId: string, engine: string, wrappedSql: string, sanitizedSql: string, timeoutMs: number, rowCap: number }) => Promise<any>
   * }} opts
   */
  async runReadOnlyQuery(opts) {
    const databaseId = String((opts && opts.databaseId) || 'default').trim();
    const engine = String((opts && opts.engine) || 'postgres').trim().toLowerCase();
    const validated = validateReadOnlySql(opts && opts.query, { maxRows: opts && opts.maxRows });

    if (opts && typeof opts.executor === 'function') {
      const result = await opts.executor({
        databaseId,
        engine,
        wrappedSql: validated.wrappedSql,
        sanitizedSql: validated.sanitizedSql,
        timeoutMs: validated.statementTimeoutMs,
        rowCap: validated.rowCap
      });
      return {
        ...validated,
        dryRunPreview: false,
        databaseId,
        engine,
        result
      };
    }

    return {
      ...validated,
      dryRunPreview: true,
      databaseId,
      engine
    };
  }

  /**
   * Valida y ejecuta (o previsualiza) un comando Redis/Valkey estrictamente de inspección.
   *
   * @param {{
   *   databaseId?: string,
   *   argv: string | string[],
   *   executor?: (ctx: { databaseId: string, argv: string[] }) => Promise<any>
   * }} opts
   */
  async runSafeRedisInspect(opts) {
    const databaseId = String((opts && opts.databaseId) || 'default').trim();
    const validated = validateSafeRedisCommand(opts && opts.argv);

    if (opts && typeof opts.executor === 'function') {
      const result = await opts.executor({
        databaseId,
        argv: validated.normalizedArgv
      });
      return {
        ...validated,
        dryRunPreview: false,
        databaseId,
        result
      };
    }

    return {
      ...validated,
      dryRunPreview: true,
      databaseId
    };
  }

  /** @param {any[]} tableStats */
  analyzePostgresBloat(tableStats) {
    return analyzePostgresBloat(tableStats);
  }

  /** @param {any} planJson */
  summarizeExplainPlan(planJson) {
    return summarizeExplainPlan(planJson);
  }
}

const instance = /** @type {any} */ (new DbStudioService());
instance.DbStudioService = DbStudioService;
instance.validateReadOnlySql = validateReadOnlySql;
instance.validateSafeRedisCommand = validateSafeRedisCommand;
instance.analyzePostgresBloat = analyzePostgresBloat;
instance.summarizeExplainPlan = summarizeExplainPlan;
instance.MAX_ROW_LIMIT = MAX_ROW_LIMIT;
instance.STATEMENT_TIMEOUT_MS = STATEMENT_TIMEOUT_MS;
module.exports = instance;
