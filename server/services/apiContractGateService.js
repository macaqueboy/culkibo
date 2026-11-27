const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Zero-Dep API Contract & Schema Drift Gate (Post-Optic Jan 2026 + oasdiff + graphql-inspector).
 *
 * Detecta cambios incompatibles (breaking changes) antes del despliegue en:
 *  - OpenAPI 3.0 / 3.1 (`PATH_REMOVED`, `METHOD_REMOVED`, `REQUIRED_PARAM_ADDED`,
 *    `REQUIRED_PROP_ADDED`, `RESPONSE_FIELD_REMOVED`, `TYPE_NARROWED`,
 *    `ENUM_VALUE_REMOVED`, `AUTH_REMOVED`)
 *  - JSON Schema (`REQUIRED_PROP_ADDED`, `RESPONSE_FIELD_REMOVED`, `TYPE_NARROWED`, `ENUM_VALUE_REMOVED`)
 *  - GraphQL SDL con lexer/parser puro (`FIELD_REMOVED`, `ARG_MADE_NON_NULL_WITHOUT_DEFAULT`,
 *    `ENUM_VALUE_REMOVED`, `TYPE_KIND_CHANGED`, `TYPE_NARROWED`)
 *
 * Impone `MISSING-VERSION-BUMP`: bloquea despliegues con breaking changes salvo que se
 * incremente la versión mayor SemVer (ej. `1.4.0 → 2.0.0`) o exista `overrideReason`.
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/api-contracts.json`.
 */

const HTTP_METHODS = Object.freeze(['get', 'post', 'put', 'patch', 'delete', 'options', 'head']);
const MAX_HISTORY_ENTRIES = 250;

/**
 * Resuelve dinámicamente la ruta a `api-contracts.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'api-contracts.json')
    : path.join(base, 'data', 'api-contracts.json');
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
 * Carga el store desde disco (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, baselines: Record<string, any>, history: any[] }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), baselines: {}, history: [] };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && typeof parsed === 'object') {
      return {
        schemaVersion: 1,
        updatedAt: parsed.updatedAt || new Date().toISOString(),
        baselines: parsed.baselines && typeof parsed.baselines === 'object' ? parsed.baselines : {},
        history: Array.isArray(parsed.history) ? parsed.history : []
      };
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), baselines: {}, history: [] };
}

/**
 * Guarda el store atómicamente (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, baselines: Record<string, any>, history: any[] }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  if (store.history.length > MAX_HISTORY_ENTRIES) {
    store.history = store.history.slice(-MAX_HISTORY_ENTRIES);
  }
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Parsea una versión SemVer (`v?X.Y.Z`).
 * @param {string | null | undefined} raw
 */
function parseSemver(raw) {
  const m = String(raw || '').trim().match(/^v?(\d+)\.(\d+)\.(\d+)/i);
  if (!m) return null;
  return {
    major: parseInt(m[1], 10),
    minor: parseInt(m[2], 10),
    patch: parseInt(m[3], 10)
  };
}

/**
 * Comprueba si hubo incremento de versión mayor (`major`).
 * @param {string} baseVersion
 * @param {string} revisionVersion
 */
function isMajorBump(baseVersion, revisionVersion) {
  const b = parseSemver(baseVersion);
  const r = parseSemver(revisionVersion);
  if (!b || !r) return false;
  return r.major > b.major;
}

/**
 * Resuelve `$ref` interno (`#/components/schemas/...` o `#/$defs/...`).
 * @param {any} rootDoc
 * @param {any} schema
 * @param {Set<string>} [seenRefs]
 */
function resolveLocalSchema(rootDoc, schema, seenRefs = new Set()) {
  if (!schema || typeof schema !== 'object') return schema;
  if (typeof schema.$ref === 'string' && schema.$ref.startsWith('#/')) {
    if (seenRefs.has(schema.$ref)) return {};
    seenRefs.add(schema.$ref);
    const parts = schema.$ref.slice(2).split('/').map((s) => s.replace(/~1/g, '/').replace(/~0/g, '~'));
    let cur = rootDoc;
    for (const part of parts) {
      if (cur && typeof cur === 'object' && Object.prototype.hasOwnProperty.call(cur, part)) {
        cur = cur[part];
      } else {
        return {};
      }
    }
    return resolveLocalSchema(rootDoc, cur, seenRefs);
  }
  return schema;
}

/**
 * Normaliza `schema.type` a un conjunto de tipos primitivos (soporta OpenAPI 3.1 `type: ['string','null']`).
 * @param {any} schema
 * @returns {Set<string>}
 */
function extractTypeSet(schema) {
  /** @type {Set<string>} */
  const out = new Set();
  if (!schema || typeof schema !== 'object') return out;
  if (typeof schema.type === 'string') out.add(schema.type.toLowerCase());
  else if (Array.isArray(schema.type)) {
    for (const t of schema.type) if (typeof t === 'string') out.add(t.toLowerCase());
  }
  if (schema.nullable === true) out.add('null');
  return out;
}

/**
 * Comparador recursivo cycle-safe para JSON Schema / sub-esquemas OpenAPI.
 * @param {any} baseRoot
 * @param {any} revRoot
 * @param {any} rawBase
 * @param {any} rawRev
 * @param {string} pointer
 * @param {'request' | 'response' | 'schema'} context
 * @param {Array<{ code: string, severity: 'breaking' | 'non_breaking', location: string, message: string }>} changes
 * @param {Set<string>} visited
 */
function diffJsonSchemas(baseRoot, revRoot, rawBase, rawRev, pointer, context, changes, visited = new Set()) {
  const base = resolveLocalSchema(baseRoot, rawBase);
  const rev = resolveLocalSchema(revRoot, rawRev);
  if (!base || !rev || typeof base !== 'object' || typeof rev !== 'object') return;

  const cycleKey = `${pointer}:${base.$ref || ''}:${rev.$ref || ''}:${visited.size > 40 ? 'cap' : ''}`;
  if (visited.has(cycleKey) || visited.size > 200) return;
  visited.add(cycleKey);

  // 1. Type narrowing check
  const baseTypes = extractTypeSet(base);
  const revTypes = extractTypeSet(rev);
  if (baseTypes.size > 0 && revTypes.size > 0) {
    for (const t of baseTypes) {
      if (!revTypes.has(t)) {
        // Widening integer -> number in requests is safe; narrowing number -> integer or changing types is breaking
        const safeWiden = context === 'request' && t === 'integer' && revTypes.has('number');
        if (!safeWiden) {
          changes.push({
            code: 'TYPE_NARROWED',
            severity: 'breaking',
            location: pointer,
            message: `Type at "${pointer}" narrowed/changed from [${Array.from(baseTypes).join('|')}] to [${Array.from(revTypes).join('|')}].`
          });
          break;
        }
      }
    }
  }

  // 2. Enum value removals
  if (Array.isArray(base.enum) && Array.isArray(rev.enum)) {
    const revSet = new Set(rev.enum.map((v) => JSON.stringify(v)));
    for (const val of base.enum) {
      if (!revSet.has(JSON.stringify(val))) {
        changes.push({
          code: 'ENUM_VALUE_REMOVED',
          severity: 'breaking',
          location: pointer,
          message: `Enum value ${JSON.stringify(val)} removed at "${pointer}".`
        });
      }
    }
  }

  // 3. Required property additions (breaking on request / schema input)
  const baseReq = new Set(Array.isArray(base.required) ? base.required.map(String) : []);
  const revReq = new Set(Array.isArray(rev.required) ? rev.required.map(String) : []);
  if (context === 'request' || context === 'schema') {
    for (const reqProp of revReq) {
      if (!baseReq.has(reqProp)) {
        changes.push({
          code: 'REQUIRED_PROP_ADDED',
          severity: 'breaking',
          location: `${pointer}.${reqProp}`,
          message: `Required property "${reqProp}" added at "${pointer}".`
        });
      }
    }
  }

  // 4. Property removals & recursive property comparison
  const baseProps = (base.properties && typeof base.properties === 'object') ? base.properties : {};
  const revProps = (rev.properties && typeof rev.properties === 'object') ? rev.properties : {};

  for (const [propName, basePropSchema] of Object.entries(baseProps)) {
    if (!Object.prototype.hasOwnProperty.call(revProps, propName)) {
      if (context === 'response' || context === 'schema') {
        changes.push({
          code: 'RESPONSE_FIELD_REMOVED',
          severity: 'breaking',
          location: `${pointer}.${propName}`,
          message: `Field "${propName}" removed from "${pointer}".`
        });
      }
    } else {
      diffJsonSchemas(baseRoot, revRoot, basePropSchema, revProps[propName], `${pointer}.${propName}`, context, changes, visited);
    }
  }

  // 5. Array items recursion
  if (base.items && rev.items) {
    diffJsonSchemas(baseRoot, revRoot, base.items, rev.items, `${pointer}[]`, context, changes, visited);
  }
}

/**
 * Compara dos especificaciones OpenAPI 3.0 / 3.1.
 * @param {any} baseDoc
 * @param {any} revDoc
 * @param {Array<{ code: string, severity: 'breaking' | 'non_breaking', location: string, message: string }>} changes
 */
function diffOpenApiSpecs(baseDoc, revDoc, changes) {
  const basePaths = (baseDoc && baseDoc.paths && typeof baseDoc.paths === 'object') ? baseDoc.paths : {};
  const revPaths = (revDoc && revDoc.paths && typeof revDoc.paths === 'object') ? revDoc.paths : {};
  const baseGlobalSec = Array.isArray(baseDoc && baseDoc.security) ? baseDoc.security : [];
  const revGlobalSec = Array.isArray(revDoc && revDoc.security) ? revDoc.security : [];

  for (const [pathKey, basePathObj] of Object.entries(basePaths)) {
    if (!basePathObj || typeof basePathObj !== 'object') continue;
    const revPathObj = revPaths[pathKey];
    if (!revPathObj || typeof revPathObj !== 'object') {
      changes.push({
        code: 'PATH_REMOVED',
        severity: 'breaking',
        location: pathKey,
        message: `OpenAPI path "${pathKey}" was removed.`
      });
      continue;
    }

    for (const method of HTTP_METHODS) {
      const baseOp = basePathObj[method];
      if (!baseOp || typeof baseOp !== 'object') continue;
      const opLoc = `${method.toUpperCase()} ${pathKey}`;
      const revOp = revPathObj[method];
      if (!revOp || typeof revOp !== 'object') {
        changes.push({
          code: 'METHOD_REMOVED',
          severity: 'breaking',
          location: opLoc,
          message: `HTTP method ${opLoc} was removed.`
        });
        continue;
      }

      // 1. AUTH_REMOVED check (effective operation or global security)
      const baseEffSec = Array.isArray(baseOp.security) ? baseOp.security : baseGlobalSec;
      const revEffSec = Array.isArray(revOp.security) ? revOp.security : revGlobalSec;
      if (baseEffSec.length > 0 && revEffSec.length === 0) {
        changes.push({
          code: 'AUTH_REMOVED',
          severity: 'breaking',
          location: opLoc,
          message: `Authentication/security requirement removed from ${opLoc}.`
        });
      }

      // 2. REQUIRED_PARAM_ADDED check
      const baseParams = [
        ...(Array.isArray(basePathObj.parameters) ? basePathObj.parameters : []),
        ...(Array.isArray(baseOp.parameters) ? baseOp.parameters : [])
      ];
      const revParams = [
        ...(Array.isArray(revPathObj.parameters) ? revPathObj.parameters : []),
        ...(Array.isArray(revOp.parameters) ? revOp.parameters : [])
      ];
      /** @type {Map<string, any>} */
      const baseParamMap = new Map();
      for (const p of baseParams) {
        if (p && p.name) baseParamMap.set(`${p.in || 'query'}:${p.name}`, p);
      }
      for (const p of revParams) {
        if (!p || !p.name) continue;
        const key = `${p.in || 'query'}:${p.name}`;
        const prev = baseParamMap.get(key);
        if (p.required === true && (!prev || prev.required !== true)) {
          changes.push({
            code: 'REQUIRED_PARAM_ADDED',
            severity: 'breaking',
            location: `${opLoc} param:${p.name}`,
            message: `Required parameter "${p.name}" (in=${p.in || 'query'}) added to ${opLoc}.`
          });
        }
      }

      // 3. Request body schema diff
      const baseReqContent = baseOp.requestBody && baseOp.requestBody.content ? baseOp.requestBody.content : {};
      const revReqContent = revOp.requestBody && revOp.requestBody.content ? revOp.requestBody.content : {};
      if (revOp.requestBody && revOp.requestBody.required === true && (!baseOp.requestBody || baseOp.requestBody.required !== true)) {
        changes.push({
          code: 'REQUIRED_PROP_ADDED',
          severity: 'breaking',
          location: `${opLoc} requestBody`,
          message: `Request body became required on ${opLoc}.`
        });
      }
      for (const [mime, baseMedia] of Object.entries(baseReqContent)) {
        const revMedia = revReqContent[mime];
        if (baseMedia && baseMedia.schema && revMedia && revMedia.schema) {
          diffJsonSchemas(baseDoc, revDoc, baseMedia.schema, revMedia.schema, `${opLoc} req[${mime}]`, 'request', changes);
        }
      }

      // 4. Response schema diff (2xx responses)
      const baseResps = baseOp.responses && typeof baseOp.responses === 'object' ? baseOp.responses : {};
      const revResps = revOp.responses && typeof revOp.responses === 'object' ? revOp.responses : {};
      for (const [statusCode, baseResp] of Object.entries(baseResps)) {
        if (!/^2\d\d$/.test(statusCode)) continue;
        const revResp = revResps[statusCode];
        if (!revResp || typeof revResp !== 'object') continue;
        const baseContent = baseResp && baseResp.content ? baseResp.content : {};
        const revContent = revResp && revResp.content ? revResp.content : {};
        for (const [mime, baseMedia] of Object.entries(baseContent)) {
          const revMedia = revContent[mime];
          if (baseMedia && baseMedia.schema && revMedia && revMedia.schema) {
            diffJsonSchemas(baseDoc, revDoc, baseMedia.schema, revMedia.schema, `${opLoc} res[${statusCode}][${mime}]`, 'response', changes);
          }
        }
      }
    }
  }
}

/**
 * Lexer/parser GraphQL SDL cero-dependencias para extraer `type`, `interface`, `input` y `enum`.
 * @param {string} sdl
 */
function parseGraphQlSdl(sdl) {
  const cleaned = String(sdl || '')
    .replace(/"""[\s\S]*?"""/g, ' ')
    .replace(/#[^\n]*/g, ' ');

  /** @type {Map<string, { kind: string, fields: Map<string, { type: string, args: Map<string, { type: string, hasDefault: boolean }> }>, values: Set<string> }>} */
  const defs = new Map();

  const blockRe = /\b(type|interface|input|enum)\s+([A-Za-z_][A-Za-z0-9_]*)[^{]*\{([\s\S]*?)\}/g;
  let m;
  while ((m = blockRe.exec(cleaned)) !== null) {
    const kind = m[1];
    const name = m[2];
    const body = m[3];

    /** @type {Map<string, { type: string, args: Map<string, { type: string, hasDefault: boolean }> }>} */
    const fields = new Map();
    /** @type {Set<string>} */
    const values = new Set();

    if (kind === 'enum') {
      const tokens = body.split(/[\s,]+/).map((t) => t.trim()).filter((t) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(t));
      for (const tok of tokens) values.add(tok);
    } else {
      const fieldRe = /([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(([^)]*)\))?\s*:\s*([A-Za-z0-9_[\]!]+)/g;
      let fm;
      while ((fm = fieldRe.exec(body)) !== null) {
        const fieldName = fm[1];
        const argsRaw = fm[2] || '';
        const fieldType = fm[3].trim();
        /** @type {Map<string, { type: string, hasDefault: boolean }>} */
        const args = new Map();

        if (argsRaw.trim()) {
          const argParts = argsRaw.split(',');
          for (const ap of argParts) {
            const am = ap.trim().match(/^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z0-9_[\]!]+)(?:\s*=\s*(.+))?$/);
            if (am) {
              args.set(am[1], { type: am[2].trim(), hasDefault: am[3] !== undefined && am[3].trim().length > 0 });
            }
          }
        }
        fields.set(fieldName, { type: fieldType, args });
      }
    }

    defs.set(name, { kind, fields, values });
  }

  return defs;
}

/**
 * Compara dos esquemas GraphQL SDL.
 * @param {string} baseSdl
 * @param {string} revSdl
 * @param {Array<{ code: string, severity: 'breaking' | 'non_breaking', location: string, message: string }>} changes
 */
function diffGraphQlSdl(baseSdl, revSdl, changes) {
  const baseDefs = parseGraphQlSdl(baseSdl);
  const revDefs = parseGraphQlSdl(revSdl);

  for (const [typeName, baseDef] of baseDefs.entries()) {
    const revDef = revDefs.get(typeName);
    if (!revDef) {
      changes.push({
        code: 'TYPE_KIND_CHANGED',
        severity: 'breaking',
        location: typeName,
        message: `GraphQL ${baseDef.kind} "${typeName}" was removed.`
      });
      continue;
    }

    if (baseDef.kind !== revDef.kind) {
      changes.push({
        code: 'TYPE_KIND_CHANGED',
        severity: 'breaking',
        location: typeName,
        message: `GraphQL "${typeName}" changed kind from ${baseDef.kind} to ${revDef.kind}.`
      });
      continue;
    }

    if (baseDef.kind === 'enum') {
      for (const val of baseDef.values) {
        if (!revDef.values.has(val)) {
          changes.push({
            code: 'ENUM_VALUE_REMOVED',
            severity: 'breaking',
            location: `${typeName}.${val}`,
            message: `GraphQL enum value "${typeName}.${val}" was removed.`
          });
        }
      }
      continue;
    }

    for (const [fieldName, baseField] of baseDef.fields.entries()) {
      const revField = revDef.fields.get(fieldName);
      if (!revField) {
        changes.push({
          code: 'FIELD_REMOVED',
          severity: 'breaking',
          location: `${typeName}.${fieldName}`,
          message: `GraphQL field "${typeName}.${fieldName}" was removed.`
        });
        continue;
      }

      if (baseField.type !== revField.type) {
        changes.push({
          code: 'TYPE_NARROWED',
          severity: 'breaking',
          location: `${typeName}.${fieldName}`,
          message: `GraphQL field "${typeName}.${fieldName}" changed type from ${baseField.type} to ${revField.type}.`
        });
      }

      // Check newly added or tightened non-null args without default
      for (const [argName, revArg] of revField.args.entries()) {
        const baseArg = baseField.args.get(argName);
        const isNonNull = revArg.type.endsWith('!');
        const wasNonNull = baseArg ? baseArg.type.endsWith('!') : false;
        if (isNonNull && !revArg.hasDefault && (!baseArg || !wasNonNull)) {
          changes.push({
            code: 'ARG_MADE_NON_NULL_WITHOUT_DEFAULT',
            severity: 'breaking',
            location: `${typeName}.${fieldName}(${argName})`,
            message: `GraphQL argument "${argName}: ${revArg.type}" on ${typeName}.${fieldName} is non-null without a default value.`
          });
        }
      }
    }
  }
}

/**
 * Compara dos contratos API (OpenAPI 3.x, JSON Schema o GraphQL SDL) y evalúa
 * la compuerta SemVer (`MISSING-VERSION-BUMP`).
 *
 * @param {{
 *   format?: 'openapi' | 'jsonschema' | 'json-schema' | 'graphql' | string,
 *   baseSpec: any,
 *   revisionSpec: any,
 *   policy?: { baseVersion?: string, revisionVersion?: string, overrideReason?: string, requireMajorBumpOnBreaking?: boolean }
 * }} input
 */
function diffContracts(input) {
  const opts = input || /** @type {any} */ ({});
  const format = String(opts.format || 'openapi').trim().toLowerCase();
  const policy = (opts.policy && typeof opts.policy === 'object') ? opts.policy : {};
  const overrideReason = String(policy.overrideReason || '').trim();

  /** @type {Array<{ code: string, severity: 'breaking' | 'non_breaking', location: string, message: string }>} */
  const changes = [];
  let baseVersion = String(policy.baseVersion || '1.0.0');
  let revisionVersion = String(policy.revisionVersion || baseVersion);

  if (format === 'graphql') {
    diffGraphQlSdl(String(opts.baseSpec || ''), String(opts.revisionSpec || ''), changes);
  } else {
    const baseObj = typeof opts.baseSpec === 'string' ? JSON.parse(opts.baseSpec) : (opts.baseSpec || {});
    const revObj = typeof opts.revisionSpec === 'string' ? JSON.parse(opts.revisionSpec) : (opts.revisionSpec || {});

    if (baseObj && baseObj.info && baseObj.info.version) baseVersion = String(baseObj.info.version);
    if (revObj && revObj.info && revObj.info.version) revisionVersion = String(revObj.info.version);

    if (format === 'jsonschema' || format === 'json-schema') {
      diffJsonSchemas(baseObj, revObj, baseObj, revObj, '$', 'schema', changes);
    } else {
      diffOpenApiSpecs(baseObj, revObj, changes);
    }
  }

  const breakingChanges = changes.filter((c) => c.severity === 'breaking');
  const nonBreakingChanges = changes.filter((c) => c.severity !== 'breaking');
  const majorBumped = isMajorBump(baseVersion, revisionVersion);
  const requireMajor = policy.requireMajorBumpOnBreaking !== false;

  let allowed = true;
  let code = 'SAFE';
  const classification = breakingChanges.length > 0 ? 'BREAKING' : 'NON_BREAKING';

  if (breakingChanges.length > 0) {
    if (majorBumped) {
      allowed = true;
      code = 'MAJOR_VERSION_BUMP_ALLOWED';
    } else if (overrideReason) {
      allowed = true;
      code = 'OVERRIDDEN_WITH_REASON';
    } else if (requireMajor) {
      allowed = false;
      code = 'MISSING-VERSION-BUMP';
    }
  }

  return {
    ok: true,
    format,
    allowed,
    code,
    classification,
    baseVersion,
    revisionVersion,
    majorBumped,
    breakingCount: breakingChanges.length,
    breakingChanges,
    nonBreakingChanges,
    summary: breakingChanges.length === 0
      ? `No breaking contract drift detected (${baseVersion} -> ${revisionVersion}).`
      : allowed
        ? `${breakingChanges.length} breaking change(s) permitted via ${code} (${baseVersion} -> ${revisionVersion}).`
        : `Blocked (${code}): ${breakingChanges.length} breaking contract change(s) without major SemVer bump (${baseVersion} -> ${revisionVersion}).`
  };
}

/**
 * Guarda la especificación baseline de un proyecto para compuertas futuras.
 *
 * @param {{ projectId: string, format?: string, version?: string, spec: any }} input
 */
function saveBaseline(input) {
  const opts = input || /** @type {any} */ ({});
  const projectId = String(opts.projectId || '').trim();
  if (!projectId) {
    const err = /** @type {any} */ (new Error('projectId is required to save contract baseline.'));
    err.status = 400;
    err.code = 'PROJECT_ID_REQUIRED';
    throw err;
  }
  const format = String(opts.format || 'openapi').trim().toLowerCase();
  const parsedSpec = (format !== 'graphql' && typeof opts.spec === 'string')
    ? JSON.parse(opts.spec)
    : opts.spec;
  const inferredVersion = (parsedSpec && typeof parsedSpec === 'object' && parsedSpec.info && parsedSpec.info.version)
    ? String(parsedSpec.info.version)
    : '1.0.0';
  const version = String(opts.version || inferredVersion);
  const nowIso = new Date().toISOString();

  const store = loadStore();
  const key = `${projectId}:${format}`;
  const baseline = { projectId, format, version, spec: parsedSpec, savedAt: nowIso };
  store.baselines[key] = baseline;
  store.history.push({
    id: `chg_${crypto.randomBytes(5).toString('hex')}`,
    type: 'baseline_saved',
    projectId,
    format,
    version,
    allowed: true,
    code: 'BASELINE_SAVED',
    breakingCount: 0,
    timestamp: nowIso
  });
  saveStore(store);

  return {
    ok: true,
    projectId,
    format,
    version,
    baseline
  };
}

/**
 * Evalúa una nueva revisión contra el baseline guardado del proyecto.
 *
 * @param {{ projectId: string, format?: string, revisionSpec: any, overrideReason?: string }} input
 */
function evaluateDeployGate(input) {
  const opts = input || /** @type {any} */ ({});
  const projectId = String(opts.projectId || '').trim();
  const format = String(opts.format || 'openapi').trim().toLowerCase();
  const overrideReason = String(opts.overrideReason || '').trim();

  const store = loadStore();
  const baseline = store.baselines[`${projectId}:${format}`];
  if (!baseline) {
    return {
      ok: true,
      projectId,
      format,
      allowed: true,
      code: 'NO_BASELINE_REGISTERED',
      classification: 'NON_BREAKING',
      breakingCount: 0,
      breakingChanges: [],
      nonBreakingChanges: [],
      summary: `No contract baseline registered for ${projectId} (${format}).`
    };
  }

  const diff = diffContracts({
    format,
    baseSpec: baseline.spec,
    revisionSpec: opts.revisionSpec,
    policy: { baseVersion: baseline.version, overrideReason }
  });

  store.history.push({
    id: `gate_${crypto.randomBytes(5).toString('hex')}`,
    type: 'deploy_gate',
    projectId,
    format,
    baseVersion: diff.baseVersion,
    revisionVersion: diff.revisionVersion,
    allowed: diff.allowed,
    code: diff.code,
    breakingCount: diff.breakingCount,
    overrideReason: overrideReason || null,
    timestamp: new Date().toISOString()
  });
  saveStore(store);

  return {
    ...diff,
    projectId,
    overrideReason: overrideReason || null
  };
}

/**
 * Lista el historial de baselines y evaluaciones de compuerta (más recientes primero).
 * @param {string} [projectId]
 */
function listContractHistory(projectId) {
  const store = loadStore();
  const cleanId = projectId ? String(projectId).trim() : '';
  const items = cleanId
    ? store.history.filter((h) => h.projectId === cleanId)
    : store.history;
  return [...items].reverse();
}

module.exports = {
  diffContracts,
  saveBaseline,
  evaluateDeployGate,
  listContractHistory
};
