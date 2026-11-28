const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Event-Bus / Queue Schema Evolution & Poison-Pill DLQ Circuit-Breaker Gate (Zero-Dep).
 *
 * Contramedida directa a Apache Kafka KIP-1034 / `UnresolvedUnionException`, cambios
 * incompatibles BullMQ v5→v6 y tormentas DLX en RabbitMQ Quorum:
 *  - `checkEventSchemaEvolution`: valida evolución `BACKWARD`/`FORWARD`/`FULL` para
 *    JSON Schema y Avro (`REQUIRED_FIELD_ADDED_NO_DEFAULT`, `FIELD_REMOVED`, `UNION_TYPE_NARROWED`).
 *  - `evaluatePoisonPillCircuit`: impone passthrough de bytes opacos en DLQ (bloqueando
 *    `DLQ_SCHEMA_DEADLOCK` cuando `dlqRawPassthrough === false`) y dispara el disyuntor
 *    de cuarentena cuando `consecutivePoisonCount >= poisonThreshold` (default 5).
 *  - `quarantinePoisonMessage`: cuarentena segura de bytes opacos (`dryRun: true` por defecto).
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/queue-schema-dlq.json`.
 */

const MAX_QUARANTINE_ITEMS = 200;

/**
 * Resuelve dinámicamente la ruta a `queue-schema-dlq.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'queue-schema-dlq.json')
    : path.join(base, 'data', 'queue-schema-dlq.json');
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
 * Carga cuarentena DLQ desde disco (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, quarantine: any[] }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), quarantine: [] };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && Array.isArray(parsed.quarantine)) {
      return parsed;
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), quarantine: [] };
}

/**
 * Guarda cuarentena DLQ atómicamente (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, quarantine: any[] }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  if (store.quarantine.length > MAX_QUARANTINE_ITEMS) {
    store.quarantine = store.quarantine.slice(-MAX_QUARANTINE_ITEMS);
  }
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Normaliza un tipo JSON-Schema o Avro a un conjunto de ramas de unión.
 * @param {any} rawType
 * @returns {Set<string>}
 */
function normalizeUnionTypes(rawType) {
  /** @type {Set<string>} */
  const out = new Set();
  if (typeof rawType === 'string' && rawType.trim()) {
    out.add(rawType.trim().toLowerCase());
  } else if (Array.isArray(rawType)) {
    for (const branch of rawType) {
      if (typeof branch === 'string') out.add(branch.trim().toLowerCase());
      else if (branch && typeof branch === 'object' && branch.type) {
        out.add(String(branch.name || branch.type).trim().toLowerCase());
      }
    }
  } else if (rawType && typeof rawType === 'object' && rawType.type) {
    out.add(String(rawType.name || rawType.type).trim().toLowerCase());
  }
  return out;
}

/**
 * Verifica compatibilidad de evolución de esquema (`BACKWARD`, `FORWARD`, `FULL`)
 * para eventos en JSON Schema o Apache Avro.
 *
 * @param {{
 *   format?: 'jsonschema' | 'json-schema' | 'avro' | string,
 *   baseSchema: any,
 *   nextSchema: any,
 *   compatibilityMode?: 'BACKWARD' | 'FORWARD' | 'FULL' | string
 * }} input
 */
function checkEventSchemaEvolution(input) {
  const opts = input || /** @type {any} */ ({});
  const format = String(opts.format || 'jsonschema').trim().toLowerCase();
  const compatibilityMode = String(opts.compatibilityMode || 'BACKWARD').trim().toUpperCase();
  const base = typeof opts.baseSchema === 'string' ? JSON.parse(opts.baseSchema) : (opts.baseSchema || {});
  const next = typeof opts.nextSchema === 'string' ? JSON.parse(opts.nextSchema) : (opts.nextSchema || {});

  /** @type {Array<{ code: string, field: string, message: string, fix: string }>} */
  const breakingChanges = [];

  if (format === 'avro') {
    const baseFields = Array.isArray(base.fields) ? base.fields : [];
    const nextFields = Array.isArray(next.fields) ? next.fields : [];
    /** @type {Map<string, any>} */
    const baseMap = new Map(baseFields.map((f) => [String(f.name), f]));
    /** @type {Map<string, any>} */
    const nextMap = new Map(nextFields.map((f) => [String(f.name), f]));

    // 1. New fields added without default break BACKWARD & FULL
    if (compatibilityMode === 'BACKWARD' || compatibilityMode === 'FULL') {
      for (const [name, nf] of nextMap.entries()) {
        if (!baseMap.has(name) && !Object.prototype.hasOwnProperty.call(nf, 'default')) {
          breakingChanges.push({
            code: 'REQUIRED_FIELD_ADDED_NO_DEFAULT',
            field: name,
            message: `Avro field "${name}" added without a default value breaks ${compatibilityMode} deserialization of in-flight events.`,
            fix: `Add an explicit "default" value (e.g. null with ["null", "..."] union) to Avro field "${name}".`
          });
        }
      }
    }

    // 2. Removed fields & narrowed union types
    for (const [name, bf] of baseMap.entries()) {
      const nf = nextMap.get(name);
      if (!nf) {
        if (compatibilityMode === 'FULL' || compatibilityMode === 'FORWARD' || !Object.prototype.hasOwnProperty.call(bf, 'default')) {
          breakingChanges.push({
            code: 'FIELD_REMOVED',
            field: name,
            message: `Avro field "${name}" was removed (breaks ${compatibilityMode} consumers/producers).`,
            fix: `Retain "${name}" with a default or perform a two-phase expand-contract migration.`
          });
        }
        continue;
      }

      const baseUnion = normalizeUnionTypes(bf.type);
      const nextUnion = normalizeUnionTypes(nf.type);
      for (const branch of baseUnion) {
        if (!nextUnion.has(branch)) {
          breakingChanges.push({
            code: 'UNION_TYPE_NARROWED',
            field: name,
            message: `Avro union for "${name}" dropped branch "${branch}" (UnresolvedUnionException risk).`,
            fix: `Keep "${branch}" in union [${Array.from(baseUnion).join(', ')}] until all historical events drain.`
          });
        }
      }
    }
  } else {
    // JSON Schema event evolution
    const baseProps = (base.properties && typeof base.properties === 'object') ? base.properties : {};
    const nextProps = (next.properties && typeof next.properties === 'object') ? next.properties : {};
    const baseReq = new Set(Array.isArray(base.required) ? base.required.map(String) : []);
    const nextReq = new Set(Array.isArray(next.required) ? next.required.map(String) : []);

    // 1. Newly required field without default breaks BACKWARD & FULL
    if (compatibilityMode === 'BACKWARD' || compatibilityMode === 'FULL') {
      for (const reqField of nextReq) {
        if (!baseReq.has(reqField)) {
          const propDef = nextProps[reqField] || {};
          const hasDefault = Object.prototype.hasOwnProperty.call(propDef, 'default');
          if (!hasDefault) {
            breakingChanges.push({
              code: 'REQUIRED_FIELD_ADDED_NO_DEFAULT',
              field: reqField,
              message: `Required event field "${reqField}" added without a default breaks ${compatibilityMode} compatibility for existing queued payloads.`,
              fix: `Make "${reqField}" optional or provide a schema "default" before deploying consumers.`
            });
          }
        }
      }
    }

    // 2. Removed fields & union type narrowing
    for (const [propName, baseDef] of Object.entries(baseProps)) {
      if (!Object.prototype.hasOwnProperty.call(nextProps, propName)) {
        breakingChanges.push({
          code: 'FIELD_REMOVED',
          field: propName,
          message: `Event field "${propName}" removed from schema.`,
          fix: `Deprecate "${propName}" instead of deleting it while older producers/consumers remain active.`
        });
        continue;
      }

      const nextDef = nextProps[propName] || {};
      const baseUnion = normalizeUnionTypes(baseDef && baseDef.type);
      const nextUnion = normalizeUnionTypes(nextDef && nextDef.type);
      if (baseUnion.size > 0 && nextUnion.size > 0) {
        for (const branch of baseUnion) {
          if (!nextUnion.has(branch)) {
            breakingChanges.push({
              code: 'UNION_TYPE_NARROWED',
              field: propName,
              message: `Field "${propName}" narrowed type from [${Array.from(baseUnion).join('|')}] to [${Array.from(nextUnion).join('|')}].`,
              fix: `Preserve "${branch}" in "${propName}.type" union during rolling consumer deployment.`
            });
          }
        }
      }
    }
  }

  const compatible = breakingChanges.length === 0;

  return {
    ok: true,
    format,
    compatibilityMode,
    compatible,
    breakingCount: breakingChanges.length,
    breakingChanges,
    summary: compatible
      ? `Event schema evolution is ${compatibilityMode}-compatible (0 breaking changes).`
      : `Blocked: ${breakingChanges.length} ${compatibilityMode}-incompatible event schema change(s) detected.`
  };
}

/**
 * Evalúa el disyuntor de mensajes poison-pill y verifica passthrough crudo en DLQ (Kafka KIP-1034).
 *
 * @param {{
 *   queueName?: string,
 *   totalDelivered?: number,
 *   failedCount?: number,
 *   consecutivePoisonCount?: number,
 *   dlqRawPassthrough?: boolean,
 *   maxRetries?: number,
 *   poisonThreshold?: number
 * }} [input]
 */
function evaluatePoisonPillCircuit(input = {}) {
  const opts = input || {};
  const queueName = String(opts.queueName || 'default').trim() || 'default';
  const totalDelivered = Math.max(0, Math.floor(Number(opts.totalDelivered) || 0));
  const failedCount = Math.max(0, Math.floor(Number(opts.failedCount) || 0));
  const consecutivePoisonCount = Math.max(0, Math.floor(Number(opts.consecutivePoisonCount) || 0));
  const dlqRawPassthrough = opts.dlqRawPassthrough !== undefined ? Boolean(opts.dlqRawPassthrough) : true;
  const maxRetries = Math.max(1, Math.floor(Number(opts.maxRetries ?? 5) || 5));
  const poisonThreshold = Math.max(1, Math.floor(Number(opts.poisonThreshold ?? 5) || 5));

  const failureRatePct = totalDelivered > 0
    ? Math.round((failedCount / totalDelivered) * 1000) / 10
    : 0;

  /** @type {Array<{ code: string, severity: 'critical' | 'high', message: string, fix: string }>} */
  const findings = [];
  let circuitOpen = false;
  let action = 'ALLOW_CONSUME';

  // 1. DLQ schema deadlock guard (KIP-1034)
  if (!dlqRawPassthrough) {
    findings.push({
      code: 'DLQ_SCHEMA_DEADLOCK',
      severity: 'critical',
      message: `Queue "${queueName}" has dlqRawPassthrough=false — DLQ re-validates broken payloads against strict schema and will crash-loop/drop poison messages.`,
      fix: 'Configure DLQ topic/queue as raw opaque byte passthrough (KIP-1034) with error headers only.'
    });
    action = 'FIX_DLQ_PASSTHROUGH';
  }

  // 2. Consecutive poison-pill circuit breaker
  if (consecutivePoisonCount >= poisonThreshold) {
    circuitOpen = true;
    action = 'TRIP_QUARANTINE_BREAKER';
    findings.push({
      code: 'POISON_PILL_CIRCUIT_OPEN',
      severity: 'critical',
      message: `Queue "${queueName}" hit ${consecutivePoisonCount} consecutive poison-pill failures (threshold=${poisonThreshold}) — tripping quarantine circuit breaker.`,
      fix: 'Route failing message IDs to raw-byte quarantine, pause poisoned consumer group, and inspect schema diff.'
    });
  }

  // 3. Elevated queue failure rate warning
  if (totalDelivered >= 10 && failureRatePct >= 25) {
    findings.push({
      code: 'HIGH_QUEUE_FAILURE_RATE',
      severity: 'high',
      message: `Queue "${queueName}" failure rate is ${failureRatePct}% (${failedCount}/${totalDelivered}).`,
      fix: 'Verify consumer schema compatibility and downstream dependency health before raising concurrency.'
    });
  }

  return {
    ok: true,
    queueName,
    healthy: findings.length === 0,
    circuitOpen,
    action,
    dlqRawPassthrough,
    totalDelivered,
    failedCount,
    failureRatePct,
    consecutivePoisonCount,
    poisonThreshold,
    maxRetries,
    findings,
    findingCodes: findings.map((f) => f.code)
  };
}

/**
 * Envía un mensaje poison-pill a cuarentena como bytes opacos Base64 sin re-parsearlo (`dryRun: true` por defecto).
 *
 * @param {{
 *   queueName?: string,
 *   messageId: string,
 *   rawPayloadBase64?: string,
 *   errorCode?: string,
 *   attemptCount?: number,
 *   dryRun?: boolean
 * }} input
 */
function quarantinePoisonMessage(input) {
  const opts = input || /** @type {any} */ ({});
  const queueName = String(opts.queueName || 'default').trim() || 'default';
  const messageId = String(opts.messageId || `msg_${crypto.randomBytes(5).toString('hex')}`).trim();
  const rawPayloadBase64 = String(opts.rawPayloadBase64 || '');
  const errorCode = String(opts.errorCode || 'DESERIALIZATION_ERROR').trim();
  const attemptCount = Math.max(1, Math.floor(Number(opts.attemptCount) || 1));
  const dryRun = opts.dryRun !== undefined ? Boolean(opts.dryRun) : true;

  const rawBuf = Buffer.from(rawPayloadBase64, 'base64');
  const payloadSha256 = crypto.createHash('sha256').update(rawBuf).digest('hex');

  const record = {
    id: `dlq_${crypto.randomBytes(5).toString('hex')}`,
    queueName,
    messageId,
    errorCode,
    attemptCount,
    rawPassthrough: true,
    payloadByteLength: rawBuf.length,
    payloadSha256,
    rawPayloadPreviewBase64: rawPayloadBase64.slice(0, 256),
    quarantinedAt: new Date().toISOString()
  };

  if (!dryRun) {
    const store = loadStore();
    store.quarantine.push(record);
    saveStore(store);
  }

  return {
    ok: true,
    dryRun,
    persisted: !dryRun,
    record
  };
}

/**
 * Lista mensajes en cuarentena DLQ (opcionalmente filtrados por `queueName`, más recientes primero).
 * @param {string} [queueName]
 */
function listDlqQuarantine(queueName) {
  const store = loadStore();
  const cleanName = queueName ? String(queueName).trim() : '';
  const items = cleanName
    ? store.quarantine.filter((q) => q.queueName === cleanName)
    : store.quarantine;
  return [...items].reverse();
}

module.exports = {
  checkEventSchemaEvolution,
  evaluatePoisonPillCircuit,
  quarantinePoisonMessage,
  listDlqQuarantine
};
