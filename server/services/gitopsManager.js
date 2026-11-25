const fs = require('fs');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const EventEmitter = require('events');
const { atomicWriteJsonSync, loadJsonWithBackupSync, isMetadataIp, isPrivateIp } = require('./ssrfGuard');
const { parseCron } = require('./cronParser');
const { parseSafeCommandArgv } = require('./safeCommand');

/**
 * Motor Declarativo GitOps (`culkibo.yaml` v1) — Cero Dependencias Externas.
 *
 * Capacidades y garantías de seguridad:
 *  - Parser YAML seguro y acotado (sin `js-yaml` ni eval):
 *      * Máximo 256 KB, máximo 2000 líneas, máximo 2000 nodos, profundidad máxima 12.
 *      * Rechaza explícitamente anclas (`&`), alias (`*`) y claves de fusión (`<<`)
 *        -> inmune a ataques Billion Laughs / expansión exponencial (YAML bombs).
 *      * Rechaza etiquetas personalizadas/peligrosas (`!`, `!!js/function`, `!!python/...`).
 *      * Construye mapas con `Object.create(null)` y rechaza `__proto__`, `constructor`, `prototype`.
 *  - Serializador YAML determinista y canónico (`exportStack`) que JAMÁS escribe secretos
 *    en claro: sustituye automáticamente toda variable/secreto por `${vault.KEY}` y emite
 *    `generateSecret: true` para bases de datos (100% seguro para Git).
 *  - Validación estricta por esquema (rechaza montajes privilegiados `docker.sock`, variables
 *    de secuestro del host, etiquetas `:latest`, traversal en rutas, dominios o crons inválidos).
 *  - `planApply` (dry-run puro), `applyStack` (reconciliación idempotente con bloqueo de borrado
 *    de BDs salvo `prune && confirmDestructive`), `detectDrift` y puente `convertExternalToCulkiboYaml`.
 */

const MAX_YAML_BYTES = 256 * 1024;
const MAX_YAML_LINES = 2000;
const MAX_YAML_DEPTH = 12;
const MAX_YAML_NODES = 2000;

const FORBIDDEN_PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const ALLOWED_TOP_SECTIONS = new Set([
  'version', 'name', 'vaultRefs', 'projects', 'databases', 'domains', 'crons', 'monitors'
]);
const ALLOWED_DB_ENGINES = new Set(['postgres', 'mysql', 'mariadb', 'valkey', 'redis', 'mongodb']);
const FLOATING_TAG_RE = /:(?:latest|stable|main|master|edge|nightly|release|dev|canary|lts|community)$/i;

const PROJECT_ID_RE = /^[a-zA-Z0-9_-]{1,80}$/;
const ENV_SLUG_RE = /^[a-z0-9][a-z0-9-]{0,22}[a-z0-9]$/;
const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const SERVER_ID_RE = /^[a-z0-9_-]{1,64}$/;
const STACK_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const DB_IDENT_RE = /^[a-z][a-z0-9_]{0,62}$/;
const VAULT_REF_RE = /\$\{vault\.([A-Za-z_][A-Za-z0-9_]{0,127})\}/g;
const FULL_VAULT_REF_RE = /^\$\{vault\.([A-Za-z_][A-Za-z0-9_]{0,127})\}$/;

const DANGEROUS_HOST_ENV_KEYS = new Set([
  'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH',
  'DOCKER_HOST', 'DOCKER_CONFIG', 'DOCKER_CONTEXT', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY',
  'BUILDKIT_HOST', 'NODE_OPTIONS', 'BASH_ENV', 'IFS',
  'GIT_SSH_COMMAND', 'GIT_ASKPASS', 'GIT_EXEC_PATH', 'COMSPEC', 'PATHEXT'
]);

const SECRET_ENV_KEY_RE = /(secret|token|pass(word|wd|phrase)?|key|auth|cred(ential)?|jwt|cookie|session|private|cert|pem|dsn|database_url|db_url|redis_url|mongo_url|smtp|webhook|stripe|openai|anthropic|gemini|aws_|s3_|r2_|cloudflare|github|gitlab|slack|discord|twilio|sendgrid|resend|sentry|encryption|signing|salt|hash|pepper|master|admin)/i;

const SAFE_CONFIG_KEY_ALLOWLIST = new Set([
  'NODE_ENV', 'PORT', 'HOST', 'HOSTNAME', 'TZ', 'LOG_LEVEL', 'DEBUG',
  'APP_ENV', 'APP_NAME', 'APP_URL', 'PUBLIC_URL', 'BASE_URL', 'SITE_URL',
  'CORS_ORIGIN', 'WORKERS', 'CONCURRENCY', 'TIMEOUT_MS', 'LANG', 'LC_ALL'
]);

const SENSITIVE_MOUNT_HOST_RE = /^\/(?:var\/run\/docker\.sock|etc|root|proc|sys|dev|boot|var\/lib\/docker)(?:\/|$)/i;
const SCP_GIT_URL_RE = /^git@([a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?):([a-zA-Z0-9._][a-zA-Z0-9._/-]{0,255})$/;
const BLOCKED_METADATA_HOSTS = new Set(['localhost', 'metadata', 'metadata.google.internal', 'metadata.goog', 'instance-data']);

/**
 * Valida que un host o IP literal no apunte a metadatos cloud, loopback ni rangos privados (anti-SSRF).
 * @param {string} rawHost
 * @param {string} ctx
 */
function assertSafePublicHost(rawHost, ctx) {
  const host = String(rawHost || '').trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  if (!host) {
    throw new Error(`${ctx}: host vacío`);
  }
  if (BLOCKED_METADATA_HOSTS.has(host) || host.endsWith('.localhost') || host.endsWith('.internal')) {
    throw new Error(`${ctx}: host local o de metadatos bloqueado por SSRF ("${host}")`);
  }
  if (isMetadataIp(host)) {
    throw new Error(`${ctx}: IP de metadatos cloud bloqueada por SSRF ("${host}")`);
  }
  if (net.isIP(host) && isPrivateIp(host)) {
    throw new Error(`${ctx}: IP privada/loopback bloqueada por SSRF ("${host}")`);
  }
  return host;
}

/**
 * Valida `gitRepo` en `culkibo.yaml`: únicamente `https://`, `http://` o `git@host:ruta`.
 * Rechaza `ext::`, `file://`, opciones con guion inicial (`--upload-pack=...`),
 * credenciales embebidas, espacios/caracteres de control y hosts privados/metadatos.
 * @param {any} raw
 * @param {string} ctx
 * @returns {string}
 */
function validateGitRepoUrl(raw, ctx) {
  if (raw === undefined || raw === null) return '';
  const str = String(raw).trim();
  if (!str) return '';
  if (str.length > 512 || /[\s\r\n\0]/.test(str)) {
    throw new Error(`${ctx}: gitRepo inválido (longitud o caracteres de control no permitidos)`);
  }
  if (str.startsWith('-')) {
    throw new Error(`${ctx}: gitRepo no puede empezar por "-" (protección contra inyección de opciones git)`);
  }
  if (/^(?:ext::|file:|ssh:\/\/|git:\/\/|fd::)/i.test(str)) {
    throw new Error(`${ctx}: esquema de gitRepo no permitido (usa https://, http:// o git@host:org/repo)`);
  }

  const scpMatch = str.match(SCP_GIT_URL_RE);
  if (scpMatch) {
    const [, host, repoPath] = scpMatch;
    if (repoPath.includes('..') || repoPath.startsWith('-')) {
      throw new Error(`${ctx}: ruta gitRepo SCP inválida`);
    }
    assertSafePublicHost(host, ctx);
    return str;
  }

  if (!/^https?:\/\//i.test(str)) {
    throw new Error(`${ctx}: gitRepo debe usar https://, http:// o git@host:org/repo`);
  }
  let parsed;
  try {
    parsed = new URL(str);
  } catch (e) {
    throw new Error(`${ctx}: gitRepo malformado`);
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error(`${ctx}: protocolo de gitRepo no permitido (${parsed.protocol})`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${ctx}: no se permiten credenciales embebidas en gitRepo`);
  }
  assertSafePublicHost(parsed.hostname, ctx);
  return str;
}

/**
 * @param {string | null} [overrideDir]
 * @returns {string}
 */
function resolveDataDir(overrideDir = null) {
  if (overrideDir) return path.resolve(overrideDir);
  if (process.env.CULKIBO_DATA_DIR) {
    return path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data');
  }
  return path.resolve(__dirname, '..', '..', 'data');
}

/**
 * Clasifica si un par `(key, value)` debe sustituirse por `${vault.KEY}` al exportar YAML.
 * @param {string} key
 * @param {string} value
 * @param {boolean} [explicitSecret]
 * @returns {boolean}
 */
function shouldRedactEnvForGit(key, value, explicitSecret = false) {
  const k = String(key || '').trim();
  const v = String(value == null ? '' : value);
  if (FULL_VAULT_REF_RE.test(v.trim())) return false; // Ya es una referencia ${vault.KEY}
  if (explicitSecret) return true;
  if (SECRET_ENV_KEY_RE.test(k)) return true;
  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(v)) return true;
  if (/(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp):\/\/[^:\s/@]+:[^@\s/]+@/i.test(v)) return true;
  if (/\b(?:gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,}|glpat-[A-Za-z0-9_-]{10,}|sk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{12,}|xox[baprs]-[A-Za-z0-9-]{10,}|ck[stihp]_[A-Za-z0-9_-]{10,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/.test(v)) {
    return true;
  }
  if (/^Bearer\s+\S{8,}/i.test(v.trim())) return true;
  if (SAFE_CONFIG_KEY_ALLOWLIST.has(k.toUpperCase())) return false;
  // Valores largos de alta entropía sin espacios que parecen secretos/claves
  if (v.length >= 24 && !/\s/.test(v) && !/^https?:\/\/[^@]+$/i.test(v) && /[a-z]/.test(v) && /[A-Z0-9]/.test(v)) {
    return true;
  }
  return false;
}

/**
 * Extrae claves `${vault.KEY}` de una cadena.
 * @param {string} str
 * @returns {string[]}
 */
function extractVaultRefs(str) {
  /** @type {string[]} */
  const out = [];
  VAULT_REF_RE.lastIndex = 0;
  let m;
  while ((m = VAULT_REF_RE.exec(String(str || ''))) !== null) {
    out.push(m[1]);
  }
  return out;
}

// ===========================================================================
// ZERO-DEP BOMB-PROOF YAML PARSER
// ===========================================================================

/**
 * Elimina comentarios `# ...` fuera de comillas respetando escapes en comillas dobles.
 * @param {string} line
 * @returns {string}
 */
function stripCommentOutsideQuotes(line) {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inDouble) {
      if (ch === '\\') { i++; continue; }
      if (ch === '"') inDouble = false;
    } else if (inSingle) {
      if (ch === "'" && line[i + 1] === "'") { i++; continue; }
      if (ch === "'") inSingle = false;
    } else {
      if (ch === '"') inDouble = true;
      else if (ch === "'") inSingle = true;
      else if (ch === '#' && (i === 0 || /\s/.test(line[i - 1]))) {
        return line.slice(0, i).trimEnd();
      }
    }
  }
  return line.trimEnd();
}

/**
 * Busca el separador `:` de un par clave-valor fuera de comillas y colecciones inline.
 * Requiere que `:` esté al final de línea o seguido de espacio/tab.
 * @param {string} str
 * @returns {number}
 */
function findMappingColon(str) {
  let inSingle = false;
  let inDouble = false;
  let flowDepth = 0;
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (inDouble) {
      if (ch === '\\') { i++; continue; }
      if (ch === '"') inDouble = false;
    } else if (inSingle) {
      if (ch === "'" && str[i + 1] === "'") { i++; continue; }
      if (ch === "'") inSingle = false;
    } else {
      if (ch === '"') inDouble = true;
      else if (ch === "'") inSingle = true;
      else if (ch === '[' || ch === '{') flowDepth++;
      else if (ch === ']' || ch === '}') flowDepth = Math.max(0, flowDepth - 1);
      else if (ch === ':' && flowDepth === 0) {
        const next = str[i + 1];
        if (next === undefined || next === ' ' || next === '\t') {
          return i;
        }
      }
    }
  }
  return -1;
}

/**
 * Verifica que un token sin comillas no contenga anclas (`&`), alias (`*`) ni etiquetas (`!`).
 * @param {string} raw
 * @param {number} lineNo
 */
function assertNoForbiddenYamlSyntax(raw, lineNo) {
  const s = raw.trim();
  if (!s) return;
  if (s[0] === '"' || s[0] === "'") return;

  if (s[0] === '!') {
    throw new Error(`Línea ${lineNo}: etiqueta YAML peligrosa/personalizada no permitida ("${s.slice(0, 32)}")`);
  }
  if (s[0] === '&') {
    throw new Error(`Línea ${lineNo}: ancla YAML (&) bloqueada por protección contra YAML bombs`);
  }
  if (s[0] === '*') {
    throw new Error(`Línea ${lineNo}: alias YAML (*) bloqueado por protección contra YAML bombs`);
  }
  // Comprobar también tokens intermedios fuera de comillas (p. ej. `!!str foo`, `&a [1]`)
  if (/(?:^|\s)![A-Za-z0-9_!<>\/.-]*/.test(s)) {
    throw new Error(`Línea ${lineNo}: etiqueta YAML (!) no permitida`);
  }
  if (/(?:^|\s)&[A-Za-z0-9_-]+/.test(s)) {
    throw new Error(`Línea ${lineNo}: ancla YAML (&) bloqueada por protección contra YAML bombs`);
  }
  if (/(?:^|\s)\*[A-Za-z0-9_-]+/.test(s)) {
    throw new Error(`Línea ${lineNo}: alias YAML (*) bloqueado por protección contra YAML bombs`);
  }
}

/**
 * Decodifica una cadena entre comillas dobles YAML/JSON.
 * @param {string} raw
 * @param {number} lineNo
 * @returns {string}
 */
function parseDoubleQuoted(raw, lineNo) {
  if (!raw.startsWith('"') || !raw.endsWith('"') || raw.length < 2) {
    throw new Error(`Línea ${lineNo}: cadena con comillas dobles sin cerrar`);
  }
  // Verificar que ninguna comilla doble sin escapar cierre la cadena antes del final
  let out = '';
  for (let i = 1; i < raw.length - 1; i++) {
    const ch = raw[i];
    if (ch === '"') {
      throw new Error(`Línea ${lineNo}: comilla doble sin escapar o contenido tras cierre de cadena`);
    }
    if (ch === '\\') {
      if (i + 1 >= raw.length - 1) {
        throw new Error(`Línea ${lineNo}: secuencia de escape incompleta al final de cadena`);
      }
      const nxt = raw[++i];
      if (nxt === 'n') out += '\n';
      else if (nxt === 'r') out += '\r';
      else if (nxt === 't') out += '\t';
      else if (nxt === 'b') out += '\b';
      else if (nxt === 'f') out += '\f';
      else if (nxt === '"' || nxt === '\\' || nxt === '/') out += nxt;
      else if (nxt === 'u') {
        const hex = raw.slice(i + 1, i + 5);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
          throw new Error(`Línea ${lineNo}: escape unicode inválido \\u${hex}`);
        }
        out += String.fromCharCode(parseInt(hex, 16));
        i += 4;
      } else {
        throw new Error(`Línea ${lineNo}: escape YAML no soportado \\${nxt}`);
      }
    } else {
      out += ch;
    }
  }
  return out;
}

/**
 * Decodifica una cadena entre comillas simples YAML (`''` -> `'`).
 * @param {string} raw
 * @param {number} lineNo
 * @returns {string}
 */
function parseSingleQuoted(raw, lineNo) {
  if (!raw.startsWith("'") || !raw.endsWith("'") || raw.length < 2) {
    throw new Error(`Línea ${lineNo}: cadena con comillas simples sin cerrar`);
  }
  let out = '';
  for (let i = 1; i < raw.length - 1; i++) {
    const ch = raw[i];
    if (ch === "'") {
      if (i + 1 < raw.length - 1 && raw[i + 1] === "'") {
        out += "'";
        i++;
      } else {
        throw new Error(`Línea ${lineNo}: comilla simple sin escapar o contenido tras cierre de cadena`);
      }
    } else {
      out += ch;
    }
  }
  return out;
}

/**
 * Parsea un escalar YAML validando contra etiquetas/anclas/alias.
 * @param {string} raw
 * @param {number} lineNo
 * @returns {any}
 */
function parseScalar(raw, lineNo) {
  const s = raw.trim();
  if (!s) return null;
  if (s.startsWith('"')) return parseDoubleQuoted(s, lineNo);
  if (s.startsWith("'")) return parseSingleQuoted(s, lineNo);

  assertNoForbiddenYamlSyntax(s, lineNo);

  if (s === 'null' || s === '~') return null;
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/.test(s)) {
    const n = Number(s);
    if (Number.isFinite(n)) return n;
  }
  return s;
}

/**
 * Valida y decodifica una clave de mapa YAML (rechaza `<<` y claves de prototype pollution).
 * @param {string} rawKey
 * @param {number} lineNo
 * @returns {string}
 */
function parseMappingKey(rawKey, lineNo) {
  const trimmed = rawKey.trim();
  if (!trimmed) throw new Error(`Línea ${lineNo}: clave YAML vacía`);
  let key;
  if (trimmed.startsWith('"')) {
    key = parseDoubleQuoted(trimmed, lineNo);
  } else if (trimmed.startsWith("'")) {
    key = parseSingleQuoted(trimmed, lineNo);
  } else {
    assertNoForbiddenYamlSyntax(trimmed, lineNo);
    key = trimmed;
  }
  if (!key || typeof key !== 'string') {
    throw new Error(`Línea ${lineNo}: clave YAML inválida`);
  }
  if (key === '<<') {
    throw new Error(`Línea ${lineNo}: clave de fusión YAML (<<) bloqueada por protección contra YAML bombs`);
  }
  if (FORBIDDEN_PROTO_KEYS.has(key)) {
    throw new Error(`Línea ${lineNo}: clave YAML prohibida ("${key}")`);
  }
  return key;
}

/**
 * Parser de colecciones inline YAML (`[...]` y `{...}`) con control estricto de profundidad y nodos.
 * @param {string} input
 * @param {number} depth
 * @param {number} lineNo
 * @param {{ nodes: number, maxDepth: number, maxNodes: number }} limits
 */
function parseFlowCollection(input, depth, lineNo, limits) {
  let pos = 0;
  const len = input.length;

  const skipWs = () => {
    while (pos < len && (input[pos] === ' ' || input[pos] === '\t')) pos++;
  };

  const bumpNode = () => {
    limits.nodes++;
    if (limits.nodes > limits.maxNodes) {
      throw new Error(`YAML supera el límite máximo de nodos (${limits.maxNodes})`);
    }
  };

  const checkDepth = (d) => {
    if (d > limits.maxDepth) {
      throw new Error(`YAML supera la profundidad máxima permitida (${limits.maxDepth})`);
    }
  };

  /** @param {number} d @returns {any} */
  const parseNode = (d) => {
    checkDepth(d);
    skipWs();
    if (pos >= len) return null;
    const ch = input[pos];
    if (ch === '[') return parseArr(d + 1);
    if (ch === '{') return parseObj(d + 1);
    if (ch === '"') return readDoubleString();
    if (ch === "'") return readSingleString();
    return readPlainScalar();
  };

  const readDoubleString = () => {
    const start = pos++;
    while (pos < len) {
      if (input[pos] === '\\') { pos += 2; continue; }
      if (input[pos] === '"') {
        pos++;
        return parseDoubleQuoted(input.slice(start, pos), lineNo);
      }
      pos++;
    }
    throw new Error(`Línea ${lineNo}: cadena entre comillas dobles sin cerrar en colección inline`);
  };

  const readSingleString = () => {
    const start = pos++;
    while (pos < len) {
      if (input[pos] === "'" && input[pos + 1] === "'") { pos += 2; continue; }
      if (input[pos] === "'") {
        pos++;
        return parseSingleQuoted(input.slice(start, pos), lineNo);
      }
      pos++;
    }
    throw new Error(`Línea ${lineNo}: cadena entre comillas simples sin cerrar en colección inline`);
  };

  const readPlainScalar = (stopAtColon = false) => {
    const start = pos;
    while (pos < len) {
      const ch = input[pos];
      if (ch === ',' || ch === ']' || ch === '}') break;
      if (stopAtColon && ch === ':' && (pos + 1 >= len || /\s/.test(input[pos + 1]) || input[pos + 1] === ',' || input[pos + 1] === '}')) {
        break;
      }
      pos++;
    }
    const token = input.slice(start, pos).trim();
    if (stopAtColon) return token;
    return parseScalar(token, lineNo);
  };

  /** @param {number} d */
  const parseArr = (d) => {
    checkDepth(d);
    pos++; // skip '['
    /** @type {any[]} */
    const arr = [];
    skipWs();
    if (pos < len && input[pos] === ']') {
      pos++;
      return arr;
    }
    while (pos < len) {
      bumpNode();
      arr.push(parseNode(d));
      skipWs();
      if (pos < len && input[pos] === ',') {
        pos++;
        skipWs();
        if (pos < len && input[pos] === ']') { pos++; return arr; }
        continue;
      }
      if (pos < len && input[pos] === ']') {
        pos++;
        return arr;
      }
      throw new Error(`Línea ${lineNo}: se esperaba "," o "]" en array YAML inline`);
    }
    throw new Error(`Línea ${lineNo}: array YAML inline sin cerrar`);
  };

  /** @param {number} d */
  const parseObj = (d) => {
    checkDepth(d);
    pos++; // skip '{'
    const obj = Object.create(null);
    skipWs();
    if (pos < len && input[pos] === '}') {
      pos++;
      return obj;
    }
    while (pos < len) {
      bumpNode();
      skipWs();
      let rawKey;
      if (input[pos] === '"') rawKey = JSON.stringify(readDoubleString());
      else if (input[pos] === "'") rawKey = `'${readSingleString().replace(/'/g, "''")}'`;
      else rawKey = readPlainScalar(true);

      const key = parseMappingKey(String(rawKey || ''), lineNo);
      skipWs();
      if (pos >= len || input[pos] !== ':') {
        throw new Error(`Línea ${lineNo}: se esperaba ":" tras clave "${key}" en mapa inline`);
      }
      pos++; // skip ':'
      const val = parseNode(d);
      obj[key] = val;
      skipWs();
      if (pos < len && input[pos] === ',') {
        pos++;
        skipWs();
        if (pos < len && input[pos] === '}') { pos++; return obj; }
        continue;
      }
      if (pos < len && input[pos] === '}') {
        pos++;
        return obj;
      }
      throw new Error(`Línea ${lineNo}: se esperaba "," o "}" en mapa YAML inline`);
    }
    throw new Error(`Línea ${lineNo}: mapa YAML inline sin cerrar`);
  };

  const result = parseNode(depth);
  skipWs();
  if (pos < len) {
    throw new Error(`Línea ${lineNo}: contenido inesperado al final de colección YAML inline`);
  }
  return result;
}

/**
 * Parsea un documento YAML v1 seguro y acotado (protegido contra YAML bombs y prototype pollution).
 * @param {string} yamlText
 * @param {{ maxBytes?: number, maxLines?: number, maxDepth?: number, maxNodes?: number }} [opts]
 * @returns {any}
 */
function parseSafeYaml(yamlText, opts = {}) {
  const maxBytes = opts.maxBytes || MAX_YAML_BYTES;
  const maxLines = opts.maxLines || MAX_YAML_LINES;
  const maxDepth = opts.maxDepth || MAX_YAML_DEPTH;
  const maxNodes = opts.maxNodes || MAX_YAML_NODES;

  if (typeof yamlText !== 'string' || !yamlText.trim()) {
    throw new Error('El manifiesto YAML está vacío');
  }
  const cleanText = yamlText.charCodeAt(0) === 0xfeff ? yamlText.slice(1) : yamlText;
  if (cleanText.includes('\0')) {
    throw new Error('Byte nulo no permitido en YAML');
  }
  if (Buffer.byteLength(cleanText, 'utf8') > maxBytes) {
    throw new Error(`El manifiesto YAML supera el límite máximo de ${Math.round(maxBytes / 1024)} KB`);
  }

  const rawLines = cleanText.split(/\r?\n/);
  if (rawLines.length > maxLines) {
    throw new Error(`El manifiesto YAML supera el límite máximo de ${maxLines} líneas`);
  }

  /** @type {Array<{ indent: number, text: string, lineNo: number }>} */
  const entries = [];
  let sawDocStart = false;
  let sawContent = false;

  for (let i = 0; i < rawLines.length; i++) {
    const rawLine = rawLines[i];
    const lineNo = i + 1;
    const leadMatch = rawLine.match(/^([ \t]*)/);
    if (leadMatch && leadMatch[1].includes('\t')) {
      throw new Error(`Línea ${lineNo}: no se permiten tabulaciones en la indentación YAML`);
    }
    const stripped = stripCommentOutsideQuotes(rawLine);
    const trimmed = stripped.trim();
    if (!trimmed) continue;

    if (trimmed === '---') {
      if (sawContent || sawDocStart) {
        throw new Error(`Línea ${lineNo}: los streams multi-documento YAML ("---") no están permitidos`);
      }
      sawDocStart = true;
      continue;
    }
    if (trimmed === '...') {
      break;
    }

    sawContent = true;
    const indent = stripped.search(/\S/);
    entries.push({ indent, text: trimmed, lineNo });
  }

  if (entries.length === 0) {
    throw new Error('El manifiesto YAML no contiene datos');
  }

  const limits = { nodes: 0, maxDepth, maxNodes };
  let idx = 0;

  const isSeqItem = (text) => text === '-' || text.startsWith('- ');

  const bumpNode = () => {
    limits.nodes++;
    if (limits.nodes > limits.maxNodes) {
      throw new Error(`YAML supera el límite máximo de nodos (${limits.maxNodes})`);
    }
  };

  const checkDepth = (d) => {
    if (d > limits.maxDepth) {
      throw new Error(`YAML supera la profundidad máxima permitida (${limits.maxDepth})`);
    }
  };

  /**
   * Lee un escalar de bloque (`|`, `|-`, `>`, `>-`) usando las líneas crudas originales.
   * @param {number} parentIndent
   * @param {string} indicator
   * @param {number} startLineNo
   */
  const consumeBlockScalar = (parentIndent, indicator, startLineNo) => {
    const folded = indicator.startsWith('>');
    const stripTrailing = indicator.endsWith('-');
    /** @type {string[]} */
    const blockLines = [];
    let blockIndent = -1;

    // Avanzar sobre las entradas que pertenecen al bloque escalar (indent > parentIndent)
    let endRawIdx = startLineNo; // 0-based index of next raw line after header
    for (let r = startLineNo; r < rawLines.length; r++) {
      const rl = rawLines[r];
      if (!rl.trim()) {
        blockLines.push('');
        endRawIdx = r + 1;
        continue;
      }
      const ind = rl.search(/\S/);
      if (ind <= parentIndent) break;
      if (blockIndent === -1) blockIndent = ind;
      blockLines.push(rl.slice(Math.min(blockIndent, ind)));
      endRawIdx = r + 1;
    }

    // Sincronizar `idx` saltando las `entries` que quedaron dentro de este bloque escalar
    while (idx < entries.length && entries[idx].lineNo <= endRawIdx) {
      idx++;
    }

    while (blockLines.length > 0 && blockLines[blockLines.length - 1] === '') {
      blockLines.pop();
    }
    const joined = folded ? blockLines.join(' ').trim() : blockLines.join('\n');
    return stripTrailing ? joined : (joined ? `${joined}\n` : '');
  };

  /** @param {string} rawVal @param {number} depth @param {number} lineNo */
  const parseValue = (rawVal, depth, lineNo) => {
    const s = rawVal.trim();
    if (s.startsWith('[') || s.startsWith('{')) {
      return parseFlowCollection(s, depth, lineNo, limits);
    }
    return parseScalar(s, lineNo);
  };

  /** @param {number} minIndent @param {number} depth @returns {any} */
  const parseBlock = (minIndent, depth) => {
    checkDepth(depth);
    if (idx >= entries.length) return null;
    const cur = entries[idx];
    if (cur.indent < minIndent) return null;
    if (isSeqItem(cur.text)) {
      return parseSequence(cur.indent, depth);
    }
    return parseMapping(cur.indent, depth);
  };

  /** @param {number} seqIndent @param {number} depth @returns {any[]} */
  const parseSequence = (seqIndent, depth) => {
    checkDepth(depth);
    /** @type {any[]} */
    const arr = [];

    while (idx < entries.length) {
      const cur = entries[idx];
      if (cur.indent !== seqIndent || !isSeqItem(cur.text)) break;
      bumpNode();

      const afterDash = cur.text.length > 1 ? cur.text.slice(2) : '';
      const rest = afterDash.trimStart();
      const lineNo = cur.lineNo;
      idx++;

      if (!rest) {
        if (idx < entries.length && entries[idx].indent > seqIndent) {
          arr.push(parseBlock(entries[idx].indent, depth + 1));
        } else {
          arr.push(null);
        }
        continue;
      }

      if (rest === '|' || rest === '|-' || rest === '>' || rest === '>-') {
        arr.push(consumeBlockScalar(seqIndent, rest, lineNo));
        continue;
      }

      // Secuencia anidada inline (`- - item`)
      if (isSeqItem(rest)) {
        throw new Error(`Línea ${lineNo}: sintaxis compacta "- -" no soportada; usa indentación en bloque`);
      }

      // Objeto inline como elemento de lista (`- key: val`)
      const colonIdx = !rest.startsWith('{') && !rest.startsWith('[') ? findMappingColon(rest) : -1;
      if (colonIdx > 0) {
        checkDepth(depth + 1);
        const obj = Object.create(null);
        const key = parseMappingKey(rest.slice(0, colonIdx), lineNo);
        const valRaw = rest.slice(colonIdx + 1).trim();
        const itemKeyIndent = seqIndent + 2;

        if (!valRaw) {
          if (idx < entries.length && entries[idx].indent > itemKeyIndent) {
            obj[key] = parseBlock(entries[idx].indent, depth + 2);
          } else if (idx < entries.length && entries[idx].indent === itemKeyIndent && isSeqItem(entries[idx].text)) {
            obj[key] = parseSequence(entries[idx].indent, depth + 2);
          } else {
            obj[key] = null;
          }
        } else if (valRaw === '|' || valRaw === '|-' || valRaw === '>' || valRaw === '>-') {
          obj[key] = consumeBlockScalar(itemKeyIndent, valRaw, lineNo);
        } else {
          obj[key] = parseValue(valRaw, depth + 2, lineNo);
        }

        // Continuar leyendo el resto de propiedades del mismo objeto
        if (idx < entries.length && entries[idx].indent > seqIndent && !isSeqItem(entries[idx].text)) {
          const contIndent = entries[idx].indent;
          const restMap = parseMapping(contIndent, depth + 1);
          for (const [rk, rv] of Object.entries(restMap)) {
            obj[rk] = rv;
          }
        }
        arr.push(obj);
        continue;
      }

      arr.push(parseValue(rest, depth + 1, lineNo));
    }

    return arr;
  };

  /** @param {number} mapIndent @param {number} depth @returns {Record<string, any>} */
  const parseMapping = (mapIndent, depth) => {
    checkDepth(depth);
    const obj = Object.create(null);

    while (idx < entries.length) {
      const cur = entries[idx];
      if (cur.indent !== mapIndent) break;
      if (isSeqItem(cur.text)) break;

      const colonIdx = findMappingColon(cur.text);
      if (colonIdx <= 0) {
        throw new Error(`Línea ${cur.lineNo}: se esperaba "clave: valor" en bloque YAML`);
      }

      bumpNode();
      const key = parseMappingKey(cur.text.slice(0, colonIdx), cur.lineNo);
      const valRaw = cur.text.slice(colonIdx + 1).trim();
      const lineNo = cur.lineNo;
      idx++;

      if (!valRaw) {
        if (idx < entries.length && entries[idx].indent > mapIndent) {
          obj[key] = parseBlock(entries[idx].indent, depth + 1);
        } else if (idx < entries.length && entries[idx].indent === mapIndent && isSeqItem(entries[idx].text)) {
          obj[key] = parseSequence(entries[idx].indent, depth + 1);
        } else {
          obj[key] = null;
        }
      } else if (valRaw === '|' || valRaw === '|-' || valRaw === '>' || valRaw === '>-') {
        obj[key] = consumeBlockScalar(mapIndent, valRaw, lineNo);
      } else {
        obj[key] = parseValue(valRaw, depth + 1, lineNo);
      }
    }

    return obj;
  };

  const root = parseBlock(entries[0].indent, 1);
  if (idx < entries.length) {
    throw new Error(`Línea ${entries[idx].lineNo}: indentación YAML inconsistente o contenido sobrante`);
  }
  return root;
}

// ===========================================================================
// DETERMINISTIC SAFE YAML SERIALIZER
// ===========================================================================

const YAML_NEEDS_QUOTE_RE = /(?:^[\s\-?:,\[\]{}#&*!|>'"%@`]|[\s]$|:\s|\s#|[\r\n\t"'\\`${}\[\],&*!|>%@`]|^(?:true|false|yes|no|on|off|null|~)$|^-?(?:0|[1-9]\d*)(?:\.\d+)?$)/i;

/** @param {string} str */
function formatYamlString(str) {
  if (str === '' || YAML_NEEDS_QUOTE_RE.test(str)) {
    return JSON.stringify(str);
  }
  return str;
}

/** @param {string} key */
function formatYamlKey(key) {
  if (/^[A-Za-z_][A-Za-z0-9_-]*$/.test(key) && !/^(?:true|false|yes|no|on|off|null)$/i.test(key)) {
    return key;
  }
  return JSON.stringify(key);
}

/**
 * Serializa un valor JS a YAML determinista y canónico (indentación de 2 espacios).
 * @param {any} value
 * @param {number} [indent]
 * @returns {string}
 */
function serializeSafeYaml(value, indent = 0) {
  const pad = ' '.repeat(indent);

  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : 'null';
  if (typeof value === 'string') return formatYamlString(value);

  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    /** @type {string[]} */
    const lines = [];
    for (const item of value) {
      if (item === null || typeof item !== 'object') {
        lines.push(`${pad}- ${serializeSafeYaml(item, indent + 2)}`);
      } else if (Array.isArray(item)) {
        if (item.length === 0) {
          lines.push(`${pad}- []`);
        } else {
          lines.push(`${pad}-`);
          lines.push(serializeSafeYaml(item, indent + 2));
        }
      } else {
        const entries = Object.entries(item).filter(([, v]) => v !== undefined);
        if (entries.length === 0) {
          lines.push(`${pad}- {}`);
        } else {
          entries.forEach(([k, v], i) => {
            const prefix = i === 0 ? `${pad}- ` : `${pad}  `;
            const kFmt = formatYamlKey(k);
            if (v === null || typeof v !== 'object') {
              lines.push(`${prefix}${kFmt}: ${serializeSafeYaml(v, indent + 4)}`);
            } else if (Array.isArray(v) && v.length === 0) {
              lines.push(`${prefix}${kFmt}: []`);
            } else if (!Array.isArray(v) && Object.keys(v).filter((x) => v[x] !== undefined).length === 0) {
              lines.push(`${prefix}${kFmt}: {}`);
            } else {
              lines.push(`${prefix}${kFmt}:`);
              lines.push(serializeSafeYaml(v, indent + 4));
            }
          });
        }
      }
    }
    return lines.join('\n');
  }

  if (typeof value === 'object') {
    const entries = Object.entries(value).filter(([k, v]) => v !== undefined && !FORBIDDEN_PROTO_KEYS.has(k));
    if (entries.length === 0) return '{}';
    /** @type {string[]} */
    const lines = [];
    for (const [k, v] of entries) {
      const kFmt = formatYamlKey(k);
      if (v === null || typeof v !== 'object') {
        lines.push(`${pad}${kFmt}: ${serializeSafeYaml(v, indent + 2)}`);
      } else if (Array.isArray(v) && v.length === 0) {
        lines.push(`${pad}${kFmt}: []`);
      } else if (!Array.isArray(v) && Object.keys(v).filter((x) => v[x] !== undefined).length === 0) {
        lines.push(`${pad}${kFmt}: {}`);
      } else {
        lines.push(`${pad}${kFmt}:`);
        lines.push(serializeSafeYaml(v, indent + 2));
      }
    }
    return lines.join('\n');
  }

  return JSON.stringify(String(value));
}

/**
 * Calcula un hash SHA-256 determinista del manifiesto canónico.
 * @param {any} doc
 * @returns {string}
 */
function hashManifest(doc) {
  const canonical = serializeSafeYaml(doc, 0) + '\n';
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Normaliza un slug de stack seguro.
 * @param {string | undefined | null} raw
 * @returns {string}
 */
function normalizeStackId(raw) {
  const slug = String(raw || 'culkibo-stack')
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^[^a-z0-9]+/, '')
    .replace(/-+$/, '')
    .slice(0, 64);
  return STACK_ID_RE.test(slug) ? slug : 'culkibo-stack';
}

// ===========================================================================
// GITOPS MANAGER
// ===========================================================================

class GitOpsManager extends EventEmitter {
  /**
   * @param {{
   *   dataDir?: string | null,
   *   projectManager?: any,
   *   domainManager?: any,
   *   cronManager?: any,
   *   databaseManager?: any,
   *   environmentManager?: any,
   *   uptimeMonitor?: any,
   *   ingressManager?: any,
   *   universalImporter?: any,
   *   auditLogger?: any
   * }} [opts]
   */
  constructor(opts = {}) {
    super();
    this._dataDirOverride = opts.dataDir || null;
    this._deps = {
      projectManager: opts.projectManager || null,
      domainManager: opts.domainManager || null,
      cronManager: opts.cronManager || null,
      databaseManager: opts.databaseManager || null,
      environmentManager: opts.environmentManager || null,
      uptimeMonitor: opts.uptimeMonitor || null,
      ingressManager: opts.ingressManager || null,
      universalImporter: opts.universalImporter || null,
      auditLogger: opts.auditLogger || null
    };
    this._loaded = false;
    this._corruptReadOnly = false;
    /** @type {{ version: number, stacks: Record<string, any> }} */
    this.state = {
      version: 1,
      stacks: Object.create(null)
    };
  }

  get dataDir() {
    return resolveDataDir(this._dataDirOverride);
  }

  get storeFile() {
    return path.join(this.dataDir, 'gitops.json');
  }

  _getProjectManager() {
    if (!this._deps.projectManager) this._deps.projectManager = require('./projectManager');
    return this._deps.projectManager;
  }

  _getDomainManager() {
    if (!this._deps.domainManager) this._deps.domainManager = require('./domainManager');
    return this._deps.domainManager;
  }

  _getCronManager() {
    if (!this._deps.cronManager) this._deps.cronManager = require('./cronManager');
    return this._deps.cronManager;
  }

  _getDatabaseManager() {
    if (!this._deps.databaseManager) {
      try { this._deps.databaseManager = require('./databaseManager'); } catch (e) {}
    }
    return this._deps.databaseManager;
  }

  _getEnvironmentManager() {
    if (!this._deps.environmentManager) this._deps.environmentManager = require('./environmentManager');
    return this._deps.environmentManager;
  }

  _getUptimeMonitor() {
    if (!this._deps.uptimeMonitor) {
      try { this._deps.uptimeMonitor = require('./uptimeMonitor'); } catch (e) {}
    }
    return this._deps.uptimeMonitor;
  }

  _getIngressManager() {
    if (!this._deps.ingressManager) {
      try { this._deps.ingressManager = require('./ingressManager'); } catch (e) {}
    }
    return this._deps.ingressManager;
  }

  _getUniversalImporter() {
    if (!this._deps.universalImporter) this._deps.universalImporter = require('./universalImporter');
    return this._deps.universalImporter;
  }

  _getAuditLogger() {
    if (!this._deps.auditLogger) {
      try { this._deps.auditLogger = require('./auditLogger'); } catch (e) {}
    }
    return this._deps.auditLogger;
  }

  /**
   * @param {string} action
   * @param {string | null} resourceId
   * @param {Record<string, any>} detail
   */
  _audit(action, resourceId, detail) {
    try {
      const al = this._getAuditLogger();
      if (al && typeof al.record === 'function') {
        al.record({ source: 'system', action, resourceId, status: 'ok', detail });
      }
    } catch (e) {}
  }

  _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;

    const loaded = loadJsonWithBackupSync(this.storeFile, {
      validate: (parsed) => Boolean(parsed && typeof parsed === 'object' && !Array.isArray(parsed))
    });
    if (loaded.ok && loaded.data) {
      const stacks = Object.create(null);
      if (loaded.data.stacks && typeof loaded.data.stacks === 'object') {
        for (const [sid, sObj] of Object.entries(loaded.data.stacks)) {
          if (!FORBIDDEN_PROTO_KEYS.has(sid) && sObj && typeof sObj === 'object') {
            stacks[sid] = sObj;
          }
        }
      }
      this.state = { version: 1, stacks };
      this._corruptReadOnly = false;
      return;
    }
    if (loaded.corrupt) {
      this._corruptReadOnly = true;
      console.error(`[GitOpsManager] ${this.storeFile} corrupto (cuarentena: ${loaded.quarantinePath}). Guardado bloqueado.`);
    }
  }

  _save() {
    this._ensureLoaded();
    if (this._corruptReadOnly) {
      throw new Error('gitops.json estaba corrupto al cargar; repáralo antes de guardar cambios');
    }
    atomicWriteJsonSync(this.storeFile, this.state, { mode: 0o600, backup: true });
  }

  /** @param {string} raw */
  _validateHostname(raw) {
    const dm = this._getDomainManager();
    if (dm && typeof dm.normalizeAndValidateHostname === 'function') {
      return dm.normalizeAndValidateHostname(raw);
    }
    const clean = String(raw || '').trim().toLowerCase().replace(/\.+$/, '');
    if (clean === 'localhost') return 'localhost';
    if (!clean || clean.length > 253 || !/^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/.test(clean)) {
      throw new Error(`Invalid domain format: ${raw}`);
    }
    return clean;
  }

  // =========================================================================
  // 1. DETERMINISTIC SECRET-FREE EXPORT (`culkibo.yaml` v1)
  // =========================================================================

  /**
   * Exporta el stack actual como un manifiesto `culkibo.yaml` v1 determinista y
   * libre de secretos (sustituye TODOS los secretos por `${vault.KEY}`).
   *
   * @param {{
   *   projectIds?: string[] | null,
   *   name?: string,
   *   includeEnvironments?: boolean,
   *   includeDatabases?: boolean,
   *   includeDomains?: boolean,
   *   includeCrons?: boolean,
   *   includeMonitors?: boolean,
   *   redactAllEnv?: boolean,
   *   schemaUrl?: string | null
   * }} [opts]
   */
  exportStack(opts = {}) {
    const pm = this._getProjectManager();
    const dm = this._getDomainManager();
    const cm = this._getCronManager();
    const dbm = this._getDatabaseManager();
    const em = this._getEnvironmentManager();
    const um = this._getUptimeMonitor();

    const stackName = String(opts.name || 'culkibo-stack').replace(/[\x00-\x1f\x7f<>]/g, '').trim().slice(0, 80) || 'culkibo-stack';
    const filterIds = Array.isArray(opts.projectIds)
      ? new Set(opts.projectIds.map((x) => String(x)))
      : null;

    const allProjects = (pm && typeof pm.getAll === 'function' ? pm.getAll() : [])
      .filter((p) => p && (!filterIds || filterIds.has(p.id)))
      .sort((a, b) => String(a.id).localeCompare(String(b.id)));

    const includedProjectIds = new Set(allProjects.map((p) => p.id));
    /** @type {Set<string>} */
    const vaultRefs = new Set();

    /**
     * Sanea un mapa de variables reemplazando secretos por `${vault.KEY}`.
     * @param {Record<string, any>} rawEnv
     * @param {Record<string, { secret?: boolean }> | null} [metaMap]
     */
    const sanitizeEnvMap = (rawEnv, metaMap = null) => {
      /** @type {Record<string, string>} */
      const out = {};
      const keys = Object.keys(rawEnv || {}).sort();
      for (const k of keys) {
        if (FORBIDDEN_PROTO_KEYS.has(k) || !ENV_KEY_RE.test(k)) continue;
        if (DANGEROUS_HOST_ENV_KEYS.has(k.toUpperCase())) continue;
        const valStr = rawEnv[k] == null ? '' : String(rawEnv[k]);
        const refs = extractVaultRefs(valStr);
        if (refs.length > 0) {
          for (const r of refs) vaultRefs.add(r);
          out[k] = valStr;
          continue;
        }
        const explicitSecret = Boolean(metaMap && metaMap[k] && metaMap[k].secret);
        const existsInVault = Boolean(em && typeof em.hasVaultSecret === 'function' && em.hasVaultSecret(k));
        if (opts.redactAllEnv || existsInVault || shouldRedactEnvForGit(k, valStr, explicitSecret)) {
          vaultRefs.add(k);
          out[k] = `\${vault.${k}}`;
        } else {
          out[k] = valStr;
        }
      }
      return out;
    };

    const projects = allProjects.map((p) => {
      /** @type {Record<string, any>} */
      const projDoc = {
        id: p.id,
        name: p.name
      };
      if (p.description) projDoc.description = p.description;
      if (p.gitRepo) projDoc.gitRepo = p.gitRepo;
      projDoc.gitBranch = p.gitBranch || 'main';
      if (p.buildCommand) projDoc.buildCommand = p.buildCommand;
      if (p.startCommand) projDoc.startCommand = p.startCommand;
      if (p.baseDirectory && p.baseDirectory !== '/') projDoc.baseDirectory = p.baseDirectory;
      if (p.containerPort) projDoc.containerPort = Number(p.containerPort);
      if (p.healthPath && p.healthPath !== '/') projDoc.healthPath = p.healthPath;
      if (p.memoryMb) projDoc.memoryMb = Number(p.memoryMb);
      if (p.cpus) projDoc.cpus = Number(p.cpus);
      projDoc.serverId = p.serverId || 'local';
      projDoc.autoDeploy = p.autoDeploy !== false;
      if (p.maintenanceMode) projDoc.maintenanceMode = true;

      const projDomains = Array.isArray(p.domains) ? [...p.domains].sort() : [];
      if (projDomains.length > 0) projDoc.domains = projDomains;

      const sanitizedEnv = sanitizeEnvMap(p.envVars || {});
      if (Object.keys(sanitizedEnv).length > 0) projDoc.env = sanitizedEnv;

      if (opts.includeEnvironments !== false && em && typeof em.listEnvironments === 'function') {
        const envs = em.listEnvironments(p.id);
        if (envs.length > 0) {
          /** @type {Record<string, any>} */
          const envSection = {};
          for (const e of envs) {
            const inspected = typeof em._inspectEnvironmentForExport === 'function'
              ? em._inspectEnvironmentForExport(p.id, e.name)
              : null;
            /** @type {Record<string, string>} */
            const rawVals = {};
            /** @type {Record<string, { secret: boolean }>} */
            const meta = {};
            if (inspected && inspected.envVars) {
              for (const [k, item] of Object.entries(inspected.envVars)) {
                rawVals[k] = item.value;
                meta[k] = { secret: Boolean(item.secret) };
              }
            }
            const cleanEnvVars = sanitizeEnvMap(rawVals, meta);
            /** @type {Record<string, any>} */
            const eDoc = {
              branch: e.branch,
              serverId: e.serverId || 'local'
            };
            if (e.protected) eDoc.protected = true;
            if (e.requireApproval) eDoc.requireApproval = true;
            if (Array.isArray(e.domains) && e.domains.length > 0) {
              eDoc.domains = [...e.domains].sort();
            }
            if (Object.keys(cleanEnvVars).length > 0) {
              eDoc.env = cleanEnvVars;
            }
            envSection[e.name] = eDoc;
          }
          projDoc.environments = envSection;
        }
      }

      return projDoc;
    });

    /** @type {any[]} */
    const databases = [];
    if (opts.includeDatabases !== false && dbm && typeof dbm.list === 'function') {
      const dbList = dbm.list();
      for (const db of dbList) {
        if (!db) continue;
        if (filterIds && db.projectId && !includedProjectIds.has(db.projectId)) continue;
        if (filterIds && !db.projectId) continue;
        databases.push({
          id: db.id,
          name: db.name || db.dbName || db.id,
          engine: db.engine,
          ...(db.image ? { image: db.image } : {}),
          ...(db.projectId ? { projectId: db.projectId } : {}),
          ...(db.dbName ? { dbName: db.dbName } : {}),
          ...(db.username ? { username: db.username } : {}),
          generateSecret: true
        });
      }
      databases.sort((a, b) => String(a.id).localeCompare(String(b.id)));
    }

    /** @type {any[]} */
    const domains = [];
    if (opts.includeDomains !== false && dm && typeof dm.listDomains === 'function') {
      const domList = dm.listDomains();
      for (const d of domList) {
        if (!d || !d.hostname) continue;
        if (filterIds) {
          if (!d.projectId || !includedProjectIds.has(d.projectId)) continue;
        } else if (!d.projectId) {
          // Omitir dominios semilla globales sin proyecto asociado para no contaminar stacks
          continue;
        }
        domains.push({
          hostname: d.hostname,
          projectId: d.projectId,
          targetPort: Number(d.targetPort) || 3000,
          routingMode: d.routingMode || 'direct_dns',
          cloudflareProxied: Boolean(d.cloudflareProxied),
          canonicalRedirect: d.canonicalRedirect || 'none',
          securityHeaders: d.securityHeaders !== false
        });
      }
      domains.sort((a, b) => String(a.hostname).localeCompare(String(b.hostname)));
    }

    /** @type {any[]} */
    const crons = [];
    if (opts.includeCrons !== false && cm && typeof cm.list === 'function') {
      const cronList = cm.list();
      for (const j of cronList) {
        if (!j) continue;
        if (filterIds && !includedProjectIds.has(j.projectId)) continue;
        /** @type {Record<string, any>} */
        const cDoc = {
          name: j.name,
          projectId: j.projectId,
          schedule: j.schedule,
          mode: j.mode || 'exec',
          enabled: j.enabled !== false
        };
        if (cDoc.mode === 'exec') {
          cDoc.command = j.command;
          if (j.workdir) cDoc.workdir = j.workdir;
        } else {
          cDoc.httpPath = j.httpPath || '/';
          cDoc.httpMethod = j.httpMethod || 'POST';
        }
        crons.push(cDoc);
      }
      crons.sort((a, b) => `${a.projectId}:${a.name}`.localeCompare(`${b.projectId}:${b.name}`));
    }

    /** @type {any[]} */
    const monitors = [];
    if (opts.includeMonitors !== false && um && typeof um.listMonitors === 'function') {
      const monList = um.listMonitors();
      for (const m of monList) {
        if (!m) continue;
        if (filterIds && m.projectId && !includedProjectIds.has(m.projectId)) continue;
        if (filterIds && !m.projectId) continue;
        monitors.push({
          name: m.name,
          ...(m.projectId ? { projectId: m.projectId } : {}),
          type: m.type || 'http',
          ...(m.url ? { url: m.url } : {}),
          intervalSec: Number(m.intervalSec) || 60,
          expectedStatus: Number(m.expectedStatus) || 200,
          enabled: m.enabled !== false,
          public: Boolean(m.public)
        });
      }
      monitors.sort((a, b) => `${a.projectId || ''}:${a.name}`.localeCompare(`${b.projectId || ''}:${b.name}`));
    }

    /** @type {Record<string, any>} */
    const manifest = {
      version: 1,
      name: stackName
    };
    const sortedVaultRefs = Array.from(vaultRefs).sort();
    if (sortedVaultRefs.length > 0) manifest.vaultRefs = sortedVaultRefs;
    manifest.projects = projects;
    if (databases.length > 0) manifest.databases = databases;
    if (domains.length > 0) manifest.domains = domains;
    if (crons.length > 0) manifest.crons = crons;
    if (monitors.length > 0) manifest.monitors = monitors;

    const schemaHeader = opts.schemaUrl && /^[^\r\n\0]+$/.test(String(opts.schemaUrl))
      ? `# yaml-language-server: $schema=${String(opts.schemaUrl).trim()}\n`
      : '';
    const yaml = schemaHeader + serializeSafeYaml(manifest, 0) + '\n';
    const manifestHash = hashManifest(manifest);

    return {
      ok: true,
      name: stackName,
      version: 1,
      manifestHash,
      vaultRefs: sortedVaultRefs,
      counts: {
        projects: projects.length,
        databases: databases.length,
        domains: domains.length,
        crons: crons.length,
        monitors: monitors.length
      },
      manifest,
      yaml
    };
  }

  /**
   * Devuelve el JSON Schema (Draft 2020-12) oficial de `culkibo.yaml` v1 para
   * autocompletado y validación en tiempo real en VS Code / JetBrains / SchemaStore.
   */
  getJsonSchema() {
    return {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      $id: 'https://culkibo.dev/schema/culkibo.yaml.json',
      title: 'Culkibo Declarative GitOps Manifest (culkibo.yaml v1)',
      type: 'object',
      additionalProperties: false,
      required: ['version', 'projects'],
      properties: {
        version: { type: 'integer', const: 1, description: 'Schema version (must be 1).' },
        name: { type: 'string', minLength: 1, maxLength: 80, description: 'Logical GitOps stack name.' },
        vaultRefs: {
          type: 'array',
          uniqueItems: true,
          items: { type: 'string', pattern: '^[A-Za-z_][A-Za-z0-9_]{0,127}$' },
          description: 'List of secret keys referenced via ${vault.KEY}.'
        },
        projects: {
          type: 'array',
          items: {
            type: 'object',
            required: ['name'],
            properties: {
              id: { type: 'string', pattern: '^[a-zA-Z0-9_-]{1,80}$' },
              name: { type: 'string', minLength: 1, maxLength: 120 },
              description: { type: 'string', maxLength: 300 },
              gitRepo: { type: 'string', maxLength: 512 },
              gitBranch: { type: 'string', default: 'main' },
              buildCommand: { type: 'string' },
              startCommand: { type: 'string' },
              baseDirectory: { type: 'string', default: '/' },
              containerPort: { type: 'integer', minimum: 1, maximum: 65535 },
              healthPath: { type: 'string', pattern: '^/[A-Za-z0-9._~\\-/]*$', default: '/' },
              memoryMb: { type: 'integer', minimum: 64, maximum: 65536 },
              cpus: { type: 'number', exclusiveMinimum: 0, maximum: 64 },
              serverId: { type: 'string', pattern: '^[a-z0-9_-]{1,64}$', default: 'local' },
              autoDeploy: { type: 'boolean', default: true },
              maintenanceMode: { type: 'boolean', default: false },
              domains: { type: 'array', items: { type: 'string' } },
              env: {
                type: 'object',
                additionalProperties: { type: ['string', 'number', 'boolean'] }
              },
              environments: {
                type: 'object',
                additionalProperties: {
                  type: 'object',
                  properties: {
                    branch: { type: 'string' },
                    serverId: { type: 'string', pattern: '^[a-z0-9_-]{1,64}$' },
                    protected: { type: 'boolean' },
                    requireApproval: { type: 'boolean' },
                    domains: { type: 'array', items: { type: 'string' } },
                    env: { type: 'object', additionalProperties: { type: ['string', 'number', 'boolean'] } }
                  }
                }
              }
            }
          }
        },
        databases: {
          type: 'array',
          items: {
            type: 'object',
            required: ['engine'],
            properties: {
              id: { type: 'string' },
              name: { type: 'string', maxLength: 63 },
              engine: { type: 'string', enum: Array.from(ALLOWED_DB_ENGINES) },
              image: { type: 'string', description: 'Pinned container image tag (no :latest).' },
              projectId: { type: 'string' },
              dbName: { type: 'string', pattern: '^[a-z][a-z0-9_]{0,62}$' },
              username: { type: 'string', pattern: '^[a-z][a-z0-9_]{0,62}$' },
              generateSecret: { type: 'boolean', default: true }
            }
          }
        },
        domains: {
          type: 'array',
          items: {
            type: 'object',
            required: ['hostname'],
            properties: {
              hostname: { type: 'string', maxLength: 253 },
              projectId: { type: ['string', 'null'] },
              targetPort: { type: 'integer', minimum: 1, maximum: 65535, default: 3000 },
              routingMode: { type: 'string', enum: ['direct_dns', 'cloudflare_proxy', 'cloudflare_tunnel'], default: 'direct_dns' },
              cloudflareProxied: { type: 'boolean', default: false },
              canonicalRedirect: { type: 'string', enum: ['none', 'www_to_apex', 'apex_to_www'], default: 'none' },
              securityHeaders: { type: 'boolean', default: true }
            }
          }
        },
        crons: {
          type: 'array',
          items: {
            type: 'object',
            required: ['name', 'schedule'],
            properties: {
              name: { type: 'string', minLength: 1, maxLength: 80 },
              projectId: { type: ['string', 'null'] },
              schedule: { type: 'string' },
              mode: { type: 'string', enum: ['exec', 'http'], default: 'exec' },
              command: { type: 'string' },
              workdir: { type: 'string' },
              httpPath: { type: 'string', pattern: '^/' },
              httpMethod: { type: 'string', enum: ['GET', 'POST'], default: 'POST' },
              enabled: { type: 'boolean', default: true }
            }
          }
        },
        monitors: {
          type: 'array',
          items: {
            type: 'object',
            required: ['name'],
            properties: {
              name: { type: 'string', minLength: 1, maxLength: 80 },
              projectId: { type: ['string', 'null'] },
              type: { type: 'string', enum: ['http', 'tcp', 'managed_project'], default: 'http' },
              url: { type: 'string', format: 'uri' },
              host: { type: 'string' },
              intervalSec: { type: 'integer', minimum: 30, default: 60 },
              expectedStatus: { type: 'integer', minimum: 100, maximum: 599, default: 200 },
              enabled: { type: 'boolean', default: true },
              public: { type: 'boolean', default: false }
            }
          }
        }
      }
    };
  }

  // =========================================================================
  // 2. STRICT MANIFEST VALIDATION
  // =========================================================================

  /**
   * Valida y normaliza un manifiesto `culkibo.yaml` v1 parseado.
   * @param {any} doc
   */
  validateManifest(doc) {
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
      throw new Error('El manifiesto culkibo.yaml debe ser un objeto YAML');
    }
    if (doc.version !== 1) {
      throw new Error(`Versión de manifiesto no soportada: ${String(doc.version)} (se requiere version: 1)`);
    }

    /** @type {string[]} */
    const warnings = [];
    for (const k of Object.keys(doc)) {
      if (!ALLOWED_TOP_SECTIONS.has(k)) {
        warnings.push(`Sección desconocida ignorada en culkibo.yaml: "${k}"`);
      }
    }

    const name = String(doc.name || 'culkibo-stack').replace(/[\x00-\x1f\x7f<>]/g, '').trim().slice(0, 80) || 'culkibo-stack';
    const em = this._getEnvironmentManager();
    /** @type {Set<string>} */
    const referencedVaultKeys = new Set();

    /** @param {Record<string, any>} rawEnv @param {string} ctx */
    const validateEnvMap = (rawEnv, ctx) => {
      /** @type {Record<string, string>} */
      const clean = {};
      if (!rawEnv) return clean;
      if (typeof rawEnv !== 'object' || Array.isArray(rawEnv)) {
        throw new Error(`${ctx}: env debe ser un mapa clave-valor`);
      }
      for (const [k, v] of Object.entries(rawEnv)) {
        if (FORBIDDEN_PROTO_KEYS.has(k) || !ENV_KEY_RE.test(k)) {
          throw new Error(`${ctx}: nombre de variable inválido "${k}"`);
        }
        if (DANGEROUS_HOST_ENV_KEYS.has(k.toUpperCase())) {
          throw new Error(`${ctx}: variable bloqueada por seguridad del host "${k}"`);
        }
        const valStr = v == null ? '' : String(v);
        if (valStr.includes('\0')) {
          throw new Error(`${ctx}: byte nulo en variable "${k}"`);
        }
        for (const ref of extractVaultRefs(valStr)) {
          referencedVaultKeys.add(ref);
        }
        clean[k] = valStr;
      }
      return clean;
    };

    // Validar proyectos
    const rawProjects = doc.projects === undefined || doc.projects === null ? [] : doc.projects;
    if (!Array.isArray(rawProjects)) {
      throw new Error('projects debe ser una lista YAML');
    }
    /** @type {any[]} */
    const projects = [];
    const seenProjectKeys = new Set();

    for (let i = 0; i < rawProjects.length; i++) {
      const p = rawProjects[i];
      if (!p || typeof p !== 'object' || Array.isArray(p)) {
        throw new Error(`projects[${i}] debe ser un objeto`);
      }
      const pName = String(p.name || '').replace(/[\x00-\x1f\x7f<>]/g, '').trim().slice(0, 120);
      if (!pName) throw new Error(`projects[${i}].name es obligatorio`);

      /** @type {string | null} */
      let pId = null;
      if (p.id !== undefined && p.id !== null && String(p.id).trim() !== '') {
        pId = String(p.id).trim();
        if (!PROJECT_ID_RE.test(pId) || FORBIDDEN_PROTO_KEYS.has(pId)) {
          throw new Error(`projects[${i}].id inválido: ${pId.slice(0, 40)}`);
        }
      }
      const uniqueKey = pId || pName.toLowerCase();
      if (seenProjectKeys.has(uniqueKey)) {
        throw new Error(`Proyecto duplicado en culkibo.yaml: "${uniqueKey}"`);
      }
      seenProjectKeys.add(uniqueKey);

      const baseDirectory = p.baseDirectory !== undefined ? String(p.baseDirectory).trim() || '/' : '/';
      if (baseDirectory.includes('\0') || baseDirectory.split(/[\\/]+/).includes('..')) {
        throw new Error(`projects[${i}].baseDirectory inválido (path traversal)`);
      }
      for (const cmdField of ['buildCommand', 'startCommand']) {
        if (p[cmdField] !== undefined && p[cmdField] !== null) {
          const cv = String(p[cmdField]);
          if (/[;\0\r\n]/.test(cv)) {
            throw new Error(`projects[${i}].${cmdField} contiene caracteres prohibidos`);
          }
        }
      }

      // Bloquear montajes privilegiados (docker.sock, /etc, /root, /proc, /sys)
      for (const mountField of ['volumes', 'fileMounts']) {
        if (Array.isArray(p[mountField])) {
          for (const m of p[mountField]) {
            const mStr = typeof m === 'string' ? m : String(m && (m.hostPath || m.source || m.path) || '');
            const hostSide = mStr.split(':')[0] || '';
            if (mStr.includes('docker.sock') || hostSide === '/' || SENSITIVE_MOUNT_HOST_RE.test(hostSide)) {
              throw new Error(`projects[${i}].${mountField}: montaje privilegiado bloqueado por seguridad ("${mStr.slice(0, 60)}")`);
            }
          }
        }
      }

      const serverId = p.serverId !== undefined && p.serverId !== null ? String(p.serverId).trim() : 'local';
      if (!SERVER_ID_RE.test(serverId)) {
        throw new Error(`projects[${i}].serverId inválido: ${serverId}`);
      }

      /** @type {number | null} */
      let containerPort = null;
      if (p.containerPort !== undefined && p.containerPort !== null) {
        const port = Number(p.containerPort);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
          throw new Error(`projects[${i}].containerPort inválido: ${p.containerPort}`);
        }
        containerPort = port;
      }

      /** @type {number | null} */
      let memoryMb = null;
      if (p.memoryMb !== undefined && p.memoryMb !== null) {
        const mem = Number(p.memoryMb);
        if (!Number.isFinite(mem) || mem < 64 || mem > 65536) {
          throw new Error(`projects[${i}].memoryMb fuera de rango (64-65536): ${p.memoryMb}`);
        }
        memoryMb = Math.round(mem);
      }

      /** @type {number | null} */
      let cpus = null;
      if (p.cpus !== undefined && p.cpus !== null) {
        const c = Number(p.cpus);
        if (!Number.isFinite(c) || c <= 0 || c > 64) {
          throw new Error(`projects[${i}].cpus fuera de rango (0.1-64): ${p.cpus}`);
        }
        cpus = c;
      }

      const healthPath = p.healthPath !== undefined && p.healthPath !== null ? String(p.healthPath).trim() || '/' : '/';
      if (!/^\/[A-Za-z0-9._~\-/]*$/.test(healthPath) || healthPath.includes('..')) {
        throw new Error(`projects[${i}].healthPath inválido: ${healthPath}`);
      }

      const projDomains = Array.isArray(p.domains)
        ? Array.from(new Set(p.domains.map((d) => this._validateHostname(String(d))))).sort()
        : [];

      const env = validateEnvMap(p.env, `projects[${i}]`);

      /** @type {Record<string, any>} */
      const environments = {};
      if (p.environments !== undefined && p.environments !== null) {
        if (typeof p.environments !== 'object' || Array.isArray(p.environments)) {
          throw new Error(`projects[${i}].environments debe ser un mapa de entornos`);
        }
        for (const [envSlug, eSpec] of Object.entries(p.environments)) {
          if (!ENV_SLUG_RE.test(envSlug) || FORBIDDEN_PROTO_KEYS.has(envSlug)) {
            throw new Error(`projects[${i}].environments: nombre de entorno inválido "${envSlug}"`);
          }
          if (!eSpec || typeof eSpec !== 'object' || Array.isArray(eSpec)) {
            throw new Error(`projects[${i}].environments.${envSlug} debe ser un objeto`);
          }
          const eServerId = eSpec.serverId !== undefined ? String(eSpec.serverId).trim() : serverId;
          if (!SERVER_ID_RE.test(eServerId)) {
            throw new Error(`projects[${i}].environments.${envSlug}.serverId inválido`);
          }
          const eDomains = Array.isArray(eSpec.domains)
            ? Array.from(new Set(eSpec.domains.map((d) => this._validateHostname(String(d))))).sort()
            : [];
          const eEnv = validateEnvMap(eSpec.env || eSpec.envVars, `projects[${i}].environments.${envSlug}`);
          environments[envSlug] = {
            branch: String(eSpec.branch || p.gitBranch || 'main').trim(),
            serverId: eServerId,
            protected: eSpec.protected !== undefined ? Boolean(eSpec.protected) : envSlug === 'production',
            requireApproval: Boolean(eSpec.requireApproval),
            domains: eDomains,
            env: eEnv
          };
        }
      }

      const gitRepo = validateGitRepoUrl(p.gitRepo, `projects[${i}].gitRepo`);

      projects.push({
        ...(pId ? { id: pId } : {}),
        name: pName,
        description: p.description !== undefined ? String(p.description).slice(0, 300) : '',
        gitRepo,
        gitBranch: String(p.gitBranch || 'main').trim(),
        buildCommand: p.buildCommand !== undefined ? String(p.buildCommand) : '',
        startCommand: p.startCommand !== undefined ? String(p.startCommand) : '',
        baseDirectory,
        containerPort,
        healthPath,
        memoryMb,
        cpus,
        serverId,
        autoDeploy: p.autoDeploy !== undefined ? Boolean(p.autoDeploy) : true,
        maintenanceMode: Boolean(p.maintenanceMode),
        domains: projDomains,
        env,
        environments
      });
    }

    // Validar bases de datos
    const rawDatabases = doc.databases === undefined || doc.databases === null ? [] : doc.databases;
    if (!Array.isArray(rawDatabases)) throw new Error('databases debe ser una lista YAML');
    /** @type {any[]} */
    const databases = [];
    for (let i = 0; i < rawDatabases.length; i++) {
      const db = rawDatabases[i];
      if (!db || typeof db !== 'object' || Array.isArray(db)) {
        throw new Error(`databases[${i}] debe ser un objeto`);
      }
      const engine = String(db.engine || '').trim().toLowerCase();
      if (!ALLOWED_DB_ENGINES.has(engine)) {
        throw new Error(`databases[${i}].engine no soportado: "${engine}"`);
      }
      if (db.image !== undefined && db.image !== null && String(db.image).trim() !== '') {
        const img = String(db.image).trim();
        if (FLOATING_TAG_RE.test(img) || !img.includes(':') || /[;\0\r\n\s]/.test(img)) {
          throw new Error(`databases[${i}].image inválida o con etiqueta flotante no permitida: "${img}"`);
        }
      }
      if (db.dbName !== undefined && db.dbName !== null && !DB_IDENT_RE.test(String(db.dbName))) {
        throw new Error(`databases[${i}].dbName inválido: "${db.dbName}"`);
      }
      if (db.username !== undefined && db.username !== null && !DB_IDENT_RE.test(String(db.username))) {
        throw new Error(`databases[${i}].username inválido: "${db.username}"`);
      }
      databases.push({
        ...(db.id ? { id: String(db.id).trim() } : {}),
        name: String(db.name || db.dbName || `${engine}_${i + 1}`).trim().slice(0, 63),
        engine,
        ...(db.image ? { image: String(db.image).trim() } : {}),
        ...(db.projectId ? { projectId: String(db.projectId).trim() } : {}),
        ...(db.dbName ? { dbName: String(db.dbName).trim() } : {}),
        ...(db.username ? { username: String(db.username).trim() } : {}),
        generateSecret: db.generateSecret !== false
      });
    }

    // Validar dominios
    const rawDomains = doc.domains === undefined || doc.domains === null ? [] : doc.domains;
    if (!Array.isArray(rawDomains)) throw new Error('domains debe ser una lista YAML');
    /** @type {any[]} */
    const domains = [];
    const seenHosts = new Set();
    for (let i = 0; i < rawDomains.length; i++) {
      const d = rawDomains[i];
      if (!d || typeof d !== 'object' || Array.isArray(d)) {
        throw new Error(`domains[${i}] debe ser un objeto`);
      }
      const hostname = this._validateHostname(String(d.hostname || ''));
      if (seenHosts.has(hostname)) {
        throw new Error(`Dominio duplicado en culkibo.yaml: "${hostname}"`);
      }
      seenHosts.add(hostname);
      const targetPort = Number(d.targetPort || 3000);
      if (!Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) {
        throw new Error(`domains[${i}].targetPort inválido: ${d.targetPort}`);
      }
      domains.push({
        hostname,
        projectId: d.projectId ? String(d.projectId).trim() : null,
        targetPort,
        routingMode: String(d.routingMode || 'direct_dns'),
        cloudflareProxied: Boolean(d.cloudflareProxied),
        canonicalRedirect: String(d.canonicalRedirect || 'none'),
        securityHeaders: d.securityHeaders !== false
      });
    }

    // Validar crons
    const rawCrons = doc.crons === undefined || doc.crons === null ? [] : doc.crons;
    if (!Array.isArray(rawCrons)) throw new Error('crons debe ser una lista YAML');
    /** @type {any[]} */
    const crons = [];
    for (let i = 0; i < rawCrons.length; i++) {
      const c = rawCrons[i];
      if (!c || typeof c !== 'object' || Array.isArray(c)) {
        throw new Error(`crons[${i}] debe ser un objeto`);
      }
      const cName = String(c.name || '').trim().slice(0, 80);
      if (!cName) throw new Error(`crons[${i}].name es obligatorio`);
      const parsedCron = parseCron(String(c.schedule || ''));
      const mode = c.mode === 'http' ? 'http' : 'exec';
      if (mode === 'exec') {
        parseSafeCommandArgv(c.command);
      } else {
        const hp = String(c.httpPath || '/').trim();
        if (!hp.startsWith('/') || /[\r\n\0\s]/.test(hp)) {
          throw new Error(`crons[${i}].httpPath inválido: ${hp}`);
        }
      }
      crons.push({
        name: cName,
        projectId: c.projectId ? String(c.projectId).trim() : null,
        schedule: parsedCron.expression,
        mode,
        ...(mode === 'exec'
          ? { command: String(c.command).trim(), ...(c.workdir ? { workdir: String(c.workdir).trim() } : {}) }
          : { httpPath: String(c.httpPath || '/').trim(), httpMethod: String(c.httpMethod || 'POST').toUpperCase() === 'GET' ? 'GET' : 'POST' }),
        enabled: c.enabled !== false
      });
    }

    // Validar monitores uptime
    const rawMonitors = doc.monitors === undefined || doc.monitors === null ? [] : doc.monitors;
    if (!Array.isArray(rawMonitors)) throw new Error('monitors debe ser una lista YAML');
    /** @type {any[]} */
    const monitors = [];
    for (let i = 0; i < rawMonitors.length; i++) {
      const m = rawMonitors[i];
      if (!m || typeof m !== 'object' || Array.isArray(m)) {
        throw new Error(`monitors[${i}] debe ser un objeto`);
      }
      const mName = String(m.name || '').trim().slice(0, 80);
      if (!mName) throw new Error(`monitors[${i}].name es obligatorio`);
      const type = String(m.type || 'http').toLowerCase();
      if (!['http', 'tcp', 'managed_project'].includes(type)) {
        throw new Error(`monitors[${i}].type inválido: ${type}`);
      }
      if (type === 'http' && m.url) {
        let parsedUrl;
        try { parsedUrl = new URL(String(m.url)); } catch (e) {
          throw new Error(`monitors[${i}].url inválida: ${m.url}`);
        }
        if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
          throw new Error(`monitors[${i}].url protocolo no permitido: ${parsedUrl.protocol}`);
        }
        if (parsedUrl.username || parsedUrl.password) {
          throw new Error(`monitors[${i}].url no puede contener credenciales incrustadas`);
        }
        assertSafePublicHost(parsedUrl.hostname, `monitors[${i}].url`);
      } else if (type === 'tcp' && m.host) {
        assertSafePublicHost(String(m.host), `monitors[${i}].host`);
      }
      const intervalSec = Math.max(30, Number(m.intervalSec) || 60);
      monitors.push({
        name: mName,
        ...(m.projectId ? { projectId: String(m.projectId).trim() } : {}),
        type,
        ...(m.url ? { url: String(m.url).trim() } : {}),
        intervalSec,
        expectedStatus: Number(m.expectedStatus) || 200,
        enabled: m.enabled !== false,
        public: Boolean(m.public)
      });
    }

    // Añadir vaultRefs declarados explícitamente al chequeo
    if (Array.isArray(doc.vaultRefs)) {
      for (const r of doc.vaultRefs) {
        if (typeof r === 'string' && ENV_KEY_RE.test(r)) referencedVaultKeys.add(r);
      }
    }

    // Comprobar qué secretos `${vault.KEY}` faltan en el Vault (nunca exponer valores!)
    /** @type {string[]} */
    const missingVaultRefs = [];
    for (const refKey of Array.from(referencedVaultKeys).sort()) {
      if (em && typeof em.hasVaultSecret === 'function' && !em.hasVaultSecret(refKey)) {
        missingVaultRefs.push(refKey);
        warnings.push(`Falta el secreto "${refKey}" en el Vault (\${vault.${refKey}})`);
      }
    }

    const normalized = {
      version: 1,
      name,
      ...(referencedVaultKeys.size > 0 ? { vaultRefs: Array.from(referencedVaultKeys).sort() } : {}),
      projects,
      ...(databases.length > 0 ? { databases } : {}),
      ...(domains.length > 0 ? { domains } : {}),
      ...(crons.length > 0 ? { crons } : {}),
      ...(monitors.length > 0 ? { monitors } : {})
    };

    return {
      manifest: normalized,
      warnings,
      referencedVaultKeys: Array.from(referencedVaultKeys).sort(),
      missingVaultRefs
    };
  }

  // =========================================================================
  // 3. DRY-RUN PLAN & DIFF (`planApply`)
  // =========================================================================

  /**
   * Calcula un plan de reconciliación puro (cero mutaciones en servicios o disco).
   *
   * @param {string} yamlText
   * @param {{ prune?: boolean, confirmDestructive?: boolean, stackId?: string | null }} [opts]
   */
  planApply(yamlText, opts = {}) {
    this._ensureLoaded();
    const prune = Boolean(opts.prune);
    const confirmDestructive = Boolean(opts.confirmDestructive);

    const parsed = parseSafeYaml(yamlText);
    const { manifest, warnings, referencedVaultKeys, missingVaultRefs } = this.validateManifest(parsed);
    const stackId = normalizeStackId(opts.stackId || manifest.name);
    const manifestHash = hashManifest(manifest);

    const pm = this._getProjectManager();
    const dm = this._getDomainManager();
    const cm = this._getCronManager();
    const dbm = this._getDatabaseManager();
    const em = this._getEnvironmentManager();
    const um = this._getUptimeMonitor();

    const prevStack = this.state.stacks[stackId] || null;
    const prevManaged = (prevStack && prevStack.managedResources) || {
      projectIds: [],
      domainHostnames: [],
      cronKeys: [],
      databaseIds: [],
      envKeys: [],
      monitorKeys: []
    };

    /** @type {any[]} */
    const create = [];
    /** @type {any[]} */
    const update = [];
    /** @type {any[]} */
    const del = [];
    /** @type {any[]} */
    const unchanged = [];
    const planWarnings = [...warnings];

    const liveProjects = pm && typeof pm.getAll === 'function' ? pm.getAll() : [];
    /** @type {Map<string, any>} */
    const liveProjById = new Map(liveProjects.map((p) => [p.id, p]));
    /** @type {Map<string, any>} */
    const liveProjByName = new Map(liveProjects.map((p) => [String(p.name || '').toLowerCase(), p]));

    /** @type {Map<string, string>} manifestProjectRef -> liveProjectId */
    const resolvedProjectIds = new Map();
    const desiredProjectIds = new Set();
    const desiredEnvKeys = new Set();

    // --- 1. Projects + per-project Environments ---
    for (const p of manifest.projects) {
      const existing = (p.id && liveProjById.get(p.id)) || liveProjByName.get(p.name.toLowerCase()) || null;
      const effectiveId = existing ? existing.id : (p.id || `new:${p.name}`);
      if (p.id) resolvedProjectIds.set(p.id, effectiveId);
      resolvedProjectIds.set(p.name, effectiveId);
      if (existing) desiredProjectIds.add(existing.id);

      if (!existing) {
        create.push({
          kind: 'project',
          key: p.id || p.name,
          name: p.name,
          details: { gitBranch: p.gitBranch, serverId: p.serverId, containerPort: p.containerPort }
        });
      } else {
        /** @type {Array<{ field: string, from: any, to: any }>} */
        const changes = [];
        const compareFields = [
          ['name', existing.name, p.name],
          ['description', existing.description || '', p.description || ''],
          ['gitRepo', existing.gitRepo || '', p.gitRepo || ''],
          ['gitBranch', existing.gitBranch || 'main', p.gitBranch || 'main'],
          ['buildCommand', existing.buildCommand || '', p.buildCommand || ''],
          ['startCommand', existing.startCommand || '', p.startCommand || ''],
          ['baseDirectory', existing.baseDirectory || '/', p.baseDirectory || '/'],
          ['healthPath', existing.healthPath || '/', p.healthPath || '/'],
          ['containerPort', existing.containerPort || null, p.containerPort || null],
          ['memoryMb', existing.memoryMb || null, p.memoryMb || null],
          ['cpus', existing.cpus || null, p.cpus || null],
          ['serverId', existing.serverId || 'local', p.serverId || 'local'],
          ['autoDeploy', existing.autoDeploy !== false, p.autoDeploy !== false],
          ['maintenanceMode', Boolean(existing.maintenanceMode), Boolean(p.maintenanceMode)]
        ];
        for (const [field, fromVal, toVal] of compareFields) {
          if (fromVal !== toVal) {
            changes.push({ field: String(field), from: fromVal, to: toVal });
          }
        }
        const curDomains = Array.isArray(existing.domains) ? [...existing.domains].sort() : [];
        const desiredDomains = Array.isArray(p.domains) ? [...p.domains].sort() : [];
        if (JSON.stringify(curDomains) !== JSON.stringify(desiredDomains)) {
          changes.push({ field: 'domains', from: curDomains, to: desiredDomains });
        }
        // Comparar claves env (nunca mostrar valores de secretos!)
        const curEnv = existing.envVars || {};
        const desiredEnv = p.env || {};
        for (const [ek, ev] of Object.entries(desiredEnv)) {
          const curVal = curEnv[ek];
          if (curVal === undefined) {
            changes.push({ field: `env.${ek}`, from: '(ausente)', to: FULL_VAULT_REF_RE.test(ev) ? ev : '[set]' });
          } else if (curVal !== ev && !FULL_VAULT_REF_RE.test(ev)) {
            changes.push({ field: `env.${ek}`, from: '[changed]', to: '[updated]' });
          }
        }
        if (changes.length > 0) {
          update.push({ kind: 'project', key: existing.id, id: existing.id, name: p.name, changes });
        } else {
          unchanged.push({ kind: 'project', key: existing.id, id: existing.id, name: p.name });
        }
      }

      // Environments de este proyecto
      for (const [envSlug, eSpec] of Object.entries(p.environments || {})) {
        const envKey = `${effectiveId}:${envSlug}`;
        desiredEnvKeys.add(envKey);
        const liveEnv = existing && em && typeof em.getEnvironment === 'function'
          ? em.getEnvironment(existing.id, envSlug)
          : null;
        if (!liveEnv) {
          create.push({
            kind: 'environment',
            key: envKey,
            projectId: effectiveId,
            name: `${p.name}/${envSlug}`,
            details: { branch: eSpec.branch, serverId: eSpec.serverId, envVarCount: Object.keys(eSpec.env || {}).length }
          });
        } else {
          /** @type {Array<{ field: string, from: any, to: any }>} */
          const eChanges = [];
          if (liveEnv.branch !== eSpec.branch) eChanges.push({ field: 'branch', from: liveEnv.branch, to: eSpec.branch });
          if ((liveEnv.serverId || 'local') !== eSpec.serverId) eChanges.push({ field: 'serverId', from: liveEnv.serverId, to: eSpec.serverId });
          if (Boolean(liveEnv.protected) !== Boolean(eSpec.protected)) eChanges.push({ field: 'protected', from: Boolean(liveEnv.protected), to: Boolean(eSpec.protected) });
          if (Boolean(liveEnv.requireApproval) !== Boolean(eSpec.requireApproval)) eChanges.push({ field: 'requireApproval', from: Boolean(liveEnv.requireApproval), to: Boolean(eSpec.requireApproval) });
          if (JSON.stringify([...(liveEnv.domains || [])].sort()) !== JSON.stringify([...(eSpec.domains || [])].sort())) {
            eChanges.push({ field: 'domains', from: liveEnv.domains || [], to: eSpec.domains || [] });
          }
          const inspected = typeof em._inspectEnvironmentForExport === 'function'
            ? em._inspectEnvironmentForExport(existing.id, envSlug)
            : null;
          const liveEnvVars = (inspected && inspected.envVars) || {};
          for (const [ek, ev] of Object.entries(eSpec.env || {})) {
            if (!liveEnvVars[ek]) {
              eChanges.push({ field: `env.${ek}`, from: '(ausente)', to: FULL_VAULT_REF_RE.test(ev) ? ev : '[set]' });
            } else if (liveEnvVars[ek].value !== ev && !FULL_VAULT_REF_RE.test(ev)) {
              eChanges.push({ field: `env.${ek}`, from: '[changed]', to: '[updated]' });
            }
          }
          if (eChanges.length > 0) {
            update.push({ kind: 'environment', key: envKey, id: envKey, projectId: existing.id, envName: envSlug, name: `${p.name}/${envSlug}`, changes: eChanges });
          } else {
            unchanged.push({ kind: 'environment', key: envKey, id: envKey, name: `${p.name}/${envSlug}` });
          }
        }
      }
    }

    // --- 2. Domains ---
    const desiredHostnames = new Set();
    for (const d of manifest.domains || []) {
      desiredHostnames.add(d.hostname);
      const liveDom = dm && typeof dm.getByHostname === 'function' ? dm.getByHostname(d.hostname) : null;
      const targetProjectId = d.projectId ? (resolvedProjectIds.get(d.projectId) || d.projectId) : null;
      if (!liveDom) {
        create.push({
          kind: 'domain',
          key: d.hostname,
          name: d.hostname,
          projectId: targetProjectId,
          details: { targetPort: d.targetPort, routingMode: d.routingMode }
        });
      } else {
        /** @type {Array<{ field: string, from: any, to: any }>} */
        const dChanges = [];
        if (targetProjectId && liveDom.projectId !== targetProjectId) {
          dChanges.push({ field: 'projectId', from: liveDom.projectId, to: targetProjectId });
        }
        if (Number(liveDom.targetPort) !== Number(d.targetPort)) {
          dChanges.push({ field: 'targetPort', from: liveDom.targetPort, to: d.targetPort });
        }
        if ((liveDom.routingMode || 'direct_dns') !== d.routingMode) {
          dChanges.push({ field: 'routingMode', from: liveDom.routingMode, to: d.routingMode });
        }
        if (Boolean(liveDom.cloudflareProxied) !== Boolean(d.cloudflareProxied)) {
          dChanges.push({ field: 'cloudflareProxied', from: Boolean(liveDom.cloudflareProxied), to: Boolean(d.cloudflareProxied) });
        }
        if (dChanges.length > 0) {
          update.push({ kind: 'domain', key: d.hostname, id: liveDom.id, name: d.hostname, changes: dChanges });
        } else {
          unchanged.push({ kind: 'domain', key: d.hostname, id: liveDom.id, name: d.hostname });
        }
      }
    }

    // --- 3. Crons ---
    const liveCrons = cm && typeof cm.list === 'function' ? cm.list() : [];
    const desiredCronKeys = new Set();
    for (const c of manifest.crons || []) {
      const pid = c.projectId ? (resolvedProjectIds.get(c.projectId) || c.projectId) : null;
      const cKey = `${pid || ''}:${c.name}`;
      desiredCronKeys.add(cKey);
      const existingCron = liveCrons.find((j) => j.projectId === pid && j.name === c.name) || null;
      if (!existingCron) {
        create.push({
          kind: 'cron',
          key: cKey,
          projectId: pid,
          name: c.name,
          details: { schedule: c.schedule, mode: c.mode }
        });
      } else {
        /** @type {Array<{ field: string, from: any, to: any }>} */
        const cChanges = [];
        if (existingCron.schedule !== c.schedule) cChanges.push({ field: 'schedule', from: existingCron.schedule, to: c.schedule });
        if (existingCron.mode !== c.mode) cChanges.push({ field: 'mode', from: existingCron.mode, to: c.mode });
        if (Boolean(existingCron.enabled) !== Boolean(c.enabled)) cChanges.push({ field: 'enabled', from: Boolean(existingCron.enabled), to: Boolean(c.enabled) });
        if (c.mode === 'exec' && existingCron.command !== c.command) {
          cChanges.push({ field: 'command', from: existingCron.command, to: c.command });
        }
        if (c.mode === 'http' && (existingCron.httpPath !== c.httpPath || existingCron.httpMethod !== c.httpMethod)) {
          cChanges.push({ field: 'http', from: `${existingCron.httpMethod} ${existingCron.httpPath}`, to: `${c.httpMethod} ${c.httpPath}` });
        }
        if (cChanges.length > 0) {
          update.push({ kind: 'cron', key: cKey, id: existingCron.id, projectId: pid, name: c.name, changes: cChanges });
        } else {
          unchanged.push({ kind: 'cron', key: cKey, id: existingCron.id, name: c.name });
        }
      }
    }

    // --- 4. Databases ---
    const liveDbs = dbm && typeof dbm.list === 'function' ? dbm.list() : [];
    const desiredDbIds = new Set();
    for (const db of manifest.databases || []) {
      const pid = db.projectId ? (resolvedProjectIds.get(db.projectId) || db.projectId) : null;
      const existingDb = liveDbs.find((x) =>
        (db.id && x.id === db.id) || (x.engine === db.engine && x.name === db.name && (!pid || x.projectId === pid))
      ) || null;
      if (!existingDb) {
        create.push({
          kind: 'database',
          key: db.id || `${db.engine}:${db.name}`,
          name: db.name,
          projectId: pid,
          details: { engine: db.engine, image: db.image || null, generateSecret: true }
        });
      } else {
        desiredDbIds.add(existingDb.id);
        unchanged.push({ kind: 'database', key: existingDb.id, id: existingDb.id, name: existingDb.name || existingDb.id });
      }
    }

    // --- 5. Uptime Monitors ---
    const liveMonitors = um && typeof um.listMonitors === 'function' ? um.listMonitors() : [];
    const desiredMonitorKeys = new Set();
    for (const m of manifest.monitors || []) {
      const pid = m.projectId ? (resolvedProjectIds.get(m.projectId) || m.projectId) : null;
      const mKey = `${pid || ''}:${m.name}`;
      desiredMonitorKeys.add(mKey);
      const existingMon = liveMonitors.find((x) => x.name === m.name && (!pid || x.projectId === pid)) || null;
      if (!existingMon) {
        create.push({ kind: 'monitor', key: mKey, projectId: pid, name: m.name, details: { type: m.type, intervalSec: m.intervalSec } });
      } else {
        unchanged.push({ kind: 'monitor', key: mKey, id: existingMon.id, name: m.name });
      }
    }

    // --- 6. Prune calculation (ONLY if prune === true) ---
    if (prune) {
      const scopeProjectIds = new Set([...prevManaged.projectIds, ...desiredProjectIds]);

      // Dominios huérfanos pertenecientes a proyectos del stack o previamente gestionados
      const allLiveDomains = dm && typeof dm.listDomains === 'function' ? dm.listDomains() : [];
      for (const d of allLiveDomains) {
        if (!d || !d.hostname) continue;
        const inScope = prevManaged.domainHostnames.includes(d.hostname) || (d.projectId && scopeProjectIds.has(d.projectId));
        if (inScope && !desiredHostnames.has(d.hostname)) {
          del.push({ kind: 'domain', key: d.hostname, id: d.id, name: d.hostname, destructive: false, blocked: false });
        }
      }

      // Crons huérfanos en proyectos del stack
      for (const j of liveCrons) {
        const cKey = `${j.projectId}:${j.name}`;
        const inScope = prevManaged.cronKeys.includes(cKey) || scopeProjectIds.has(j.projectId);
        if (inScope && !desiredCronKeys.has(cKey)) {
          del.push({ kind: 'cron', key: cKey, id: j.id, projectId: j.projectId, name: j.name, destructive: false, blocked: false });
        }
      }

      // Entornos huérfanos en proyectos del stack
      if (em && typeof em.listEnvironments === 'function') {
        for (const pid of scopeProjectIds) {
          for (const env of em.listEnvironments(pid)) {
            const envKey = `${pid}:${env.name}`;
            if (!desiredEnvKeys.has(envKey)) {
              del.push({
                kind: 'environment',
                key: envKey,
                id: envKey,
                projectId: pid,
                envName: env.name,
                name: `${pid}/${env.name}`,
                destructive: Boolean(env.protected),
                blocked: Boolean(env.protected && !confirmDestructive)
              });
              if (env.protected && !confirmDestructive) {
                planWarnings.push(`Eliminación del entorno protegido "${envKey}" bloqueada sin confirmDestructive: true`);
              }
            }
          }
        }
      }

      // Proyectos gestionados anteriormente que ya no están en el manifiesto
      for (const pid of prevManaged.projectIds) {
        if (!desiredProjectIds.has(pid) && liveProjById.has(pid)) {
          const lp = liveProjById.get(pid);
          del.push({ kind: 'project', key: pid, id: pid, name: lp.name, destructive: true, blocked: false });
        }
      }

      // Bases de datos: JAMÁS eliminar salvo `prune && confirmDestructive`!
      for (const db of liveDbs) {
        const inScope = prevManaged.databaseIds.includes(db.id) || (db.projectId && scopeProjectIds.has(db.projectId));
        if (inScope && !desiredDbIds.has(db.id)) {
          const blocked = !confirmDestructive;
          del.push({
            kind: 'database',
            key: db.id,
            id: db.id,
            name: db.name || db.id,
            destructive: true,
            blocked
          });
          if (blocked) {
            planWarnings.push(`Eliminación de base de datos "${db.name || db.id}" bloqueada: requiere prune: true y confirmDestructive: true`);
          }
        }
      }
    }

    const actionableDeletes = del.filter((d) => !d.blocked);
    const hasChanges = create.length > 0 || update.length > 0 || actionableDeletes.length > 0;

    return {
      ok: true,
      valid: true,
      dryRun: true,
      stackId,
      stackName: manifest.name,
      manifestHash,
      vaultRefs: referencedVaultKeys,
      missingVaultRefs,
      create,
      update,
      delete: del,
      unchanged,
      warnings: planWarnings,
      summary: {
        create: create.length,
        update: update.length,
        delete: del.length,
        blockedDeletes: del.filter((d) => d.blocked).length,
        unchanged: unchanged.length,
        warnings: planWarnings.length,
        hasChanges
      },
      manifest
    };
  }

  // =========================================================================
  // 4. IDEMPOTENT RECONCILIATION (`applyStack`)
  // =========================================================================

  /**
   * Reconcilia de forma idempotente el estado vivo contra un manifiesto `culkibo.yaml`.
   * Nunca borra bases de datos salvo `prune === true && confirmDestructive === true`.
   *
   * @param {string} yamlText
   * @param {{
   *   dryRun?: boolean,
   *   prune?: boolean,
   *   confirmDestructive?: boolean,
   *   actor?: string,
   *   stackId?: string | null
   * }} [opts]
   */
  async applyStack(yamlText, opts = {}) {
    this._ensureLoaded();
    const dryRun = Boolean(opts.dryRun);
    const prune = Boolean(opts.prune);
    const confirmDestructive = Boolean(opts.confirmDestructive);
    const actor = String(opts.actor || 'system').slice(0, 80);

    const plan = this.planApply(yamlText, { prune, confirmDestructive, stackId: opts.stackId });
    if (dryRun) {
      return {
        ...plan,
        dryRun: true,
        applied: false
      };
    }

    const pm = this._getProjectManager();
    const dm = this._getDomainManager();
    const cm = this._getCronManager();
    const dbm = this._getDatabaseManager();
    const em = this._getEnvironmentManager();
    const um = this._getUptimeMonitor();
    const im = this._getIngressManager();

    const manifest = plan.manifest;
    const stackId = plan.stackId;
    const appliedWarnings = [...plan.warnings];
    const appliedCounts = { created: 0, updated: 0, deleted: 0, skipped: 0 };

    /** @type {Map<string, string>} */
    const resolvedProjectIds = new Map();
    /** @type {string[]} */
    const managedProjectIds = [];
    /** @type {string[]} */
    const managedDomainHostnames = [];
    /** @type {string[]} */
    const managedCronKeys = [];
    /** @type {string[]} */
    const managedDatabaseIds = [];
    /** @type {string[]} */
    const managedEnvKeys = [];
    /** @type {string[]} */
    const managedMonitorKeys = [];

    // 1. Reconciliar Proyectos y sus Entornos
    const liveProjects = pm.getAll();
    for (const p of manifest.projects) {
      const existing = (p.id && pm.getById(p.id))
        || liveProjects.find((x) => String(x.name || '').toLowerCase() === p.name.toLowerCase())
        || null;

      let liveProj = existing;
      if (!existing) {
        const createPayload = {
          ...(p.id ? { id: p.id } : {}),
          name: p.name,
          description: p.description,
          gitRepo: p.gitRepo,
          gitBranch: p.gitBranch,
          buildCommand: p.buildCommand,
          startCommand: p.startCommand,
          baseDirectory: p.baseDirectory,
          containerPort: p.containerPort,
          healthPath: p.healthPath,
          memoryMb: p.memoryMb,
          cpus: p.cpus,
          serverId: p.serverId,
          autoDeploy: p.autoDeploy,
          maintenanceMode: p.maintenanceMode,
          domains: p.domains,
          envVars: p.env,
          source: 'gitops'
        };
        liveProj = pm.create(createPayload);
        appliedCounts.created++;
      } else {
        const projPlanUpdate = plan.update.find((u) => u.kind === 'project' && u.id === existing.id);
        if (projPlanUpdate) {
          // Conservar envVars existentes cuando el manifiesto referencia ${vault.KEY} sin sobrescribir valores locales no declarados
          const mergedEnv = { ...(existing.envVars || {}) };
          for (const [ek, ev] of Object.entries(p.env || {})) {
            if (!FULL_VAULT_REF_RE.test(ev) || mergedEnv[ek] === undefined) {
              mergedEnv[ek] = ev;
            }
          }
          liveProj = pm.update(existing.id, {
            name: p.name,
            description: p.description,
            gitRepo: p.gitRepo,
            gitBranch: p.gitBranch,
            buildCommand: p.buildCommand,
            startCommand: p.startCommand,
            baseDirectory: p.baseDirectory,
            containerPort: p.containerPort,
            healthPath: p.healthPath,
            memoryMb: p.memoryMb,
            cpus: p.cpus,
            serverId: p.serverId,
            autoDeploy: p.autoDeploy,
            maintenanceMode: p.maintenanceMode,
            domains: p.domains,
            envVars: mergedEnv
          });
          appliedCounts.updated++;
        }
      }

      if (p.id) resolvedProjectIds.set(p.id, liveProj.id);
      resolvedProjectIds.set(p.name, liveProj.id);
      managedProjectIds.push(liveProj.id);

      // Reconciliar entornos aislados del proyecto
      for (const [envSlug, eSpec] of Object.entries(p.environments || {})) {
        const envKey = `${liveProj.id}:${envSlug}`;
        managedEnvKeys.push(envKey);
        const existingEnv = em.getEnvironment(liveProj.id, envSlug);
        const envNeedsUpdate = !existingEnv || plan.update.some((u) => u.kind === 'environment' && u.key === envKey);
        if (envNeedsUpdate) {
          /** @type {Record<string, string>} */
          const envVarsToUpsert = {};
          const existingEnvKeys = new Set(
            existingEnv && Array.isArray(existingEnv.envKeys) ? existingEnv.envKeys : []
          );
          for (const [ek, ev] of Object.entries(eSpec.env || {})) {
            // No sobrescribir un secreto cifrado vivo con el marcador literal `${vault.KEY}`
            if (existingEnv && FULL_VAULT_REF_RE.test(ev) && existingEnvKeys.has(ek)) {
              continue;
            }
            envVarsToUpsert[ek] = ev;
          }
          em.upsertEnvironment(liveProj.id, envSlug, {
            branch: eSpec.branch,
            serverId: eSpec.serverId,
            protected: eSpec.protected,
            requireApproval: eSpec.requireApproval,
            domains: eSpec.domains,
            ...(Object.keys(envVarsToUpsert).length > 0 ? { envVars: envVarsToUpsert } : {}),
            actor
          });
          if (!existingEnv) appliedCounts.created++;
          else appliedCounts.updated++;
        }
      }
    }

    // 2. Reconciliar Dominios
    for (const d of manifest.domains || []) {
      const targetProjectId = d.projectId ? (resolvedProjectIds.get(d.projectId) || d.projectId) : null;
      managedDomainHostnames.push(d.hostname);
      const existingDom = dm.getByHostname(d.hostname);
      if (!existingDom) {
        await dm.addDomain({
          hostname: d.hostname,
          projectId: targetProjectId,
          targetPort: d.targetPort,
          routingMode: d.routingMode,
          cloudflareProxied: d.cloudflareProxied,
          canonicalRedirect: d.canonicalRedirect,
          securityHeaders: d.securityHeaders
        });
        appliedCounts.created++;
      } else {
        const domUpdate = plan.update.find((u) => u.kind === 'domain' && u.id === existingDom.id);
        if (domUpdate) {
          await dm.updateDomain(existingDom.id, {
            projectId: targetProjectId,
            targetPort: d.targetPort,
            routingMode: d.routingMode,
            cloudflareProxied: d.cloudflareProxied,
            canonicalRedirect: d.canonicalRedirect,
            securityHeaders: d.securityHeaders
          });
          appliedCounts.updated++;
        }
      }
    }

    // 3. Reconciliar Crons
    const liveCrons = cm.list();
    for (const c of manifest.crons || []) {
      const pid = c.projectId ? (resolvedProjectIds.get(c.projectId) || c.projectId) : null;
      if (!pid) {
        appliedWarnings.push(`Cron "${c.name}" omitido: falta projectId`);
        appliedCounts.skipped++;
        continue;
      }
      const cKey = `${pid}:${c.name}`;
      managedCronKeys.push(cKey);
      const existingCron = liveCrons.find((j) => j.projectId === pid && j.name === c.name) || null;
      if (!existingCron) {
        cm.create(pid, {
          name: c.name,
          schedule: c.schedule,
          mode: c.mode,
          command: c.command,
          workdir: c.workdir,
          httpPath: c.httpPath,
          httpMethod: c.httpMethod,
          enabled: c.enabled
        });
        appliedCounts.created++;
      } else {
        const cronUpdate = plan.update.find((u) => u.kind === 'cron' && u.id === existingCron.id);
        if (cronUpdate) {
          cm.update(existingCron.id, {
            schedule: c.schedule,
            mode: c.mode,
            command: c.command,
            workdir: c.workdir,
            httpPath: c.httpPath,
            httpMethod: c.httpMethod,
            enabled: c.enabled
          });
          appliedCounts.updated++;
        }
      }
    }

    // 4. Reconciliar Bases de Datos (best-effort si Docker / provision está disponible)
    const liveDbs = dbm && typeof dbm.list === 'function' ? dbm.list() : [];
    for (const db of manifest.databases || []) {
      const pid = db.projectId ? (resolvedProjectIds.get(db.projectId) || db.projectId) : null;
      const existingDb = liveDbs.find((x) =>
        (db.id && x.id === db.id) || (x.engine === db.engine && x.name === db.name && (!pid || x.projectId === pid))
      ) || null;
      if (existingDb) {
        managedDatabaseIds.push(existingDb.id);
      } else if (dbm && typeof dbm.provision === 'function') {
        try {
          const created = await dbm.provision({
            projectId: pid,
            engine: db.engine,
            name: db.name,
            dbName: db.dbName,
            username: db.username,
            image: db.image
          });
          if (created && created.id) managedDatabaseIds.push(created.id);
          appliedCounts.created++;
        } catch (err) {
          /** @type {any} */
          const e = err;
          appliedWarnings.push(`Base de datos "${db.name}" (${db.engine}) no aprovisionada: ${e.message || e}`);
          appliedCounts.skipped++;
        }
      }
    }

    // 5. Reconciliar Monitores Uptime (si uptimeMonitor está disponible)
    if (um && typeof um.listMonitors === 'function' && typeof um.createMonitor === 'function') {
      const liveMons = um.listMonitors();
      for (const m of manifest.monitors || []) {
        const pid = m.projectId ? (resolvedProjectIds.get(m.projectId) || m.projectId) : null;
        const mKey = `${pid || ''}:${m.name}`;
        managedMonitorKeys.push(mKey);
        const existingMon = liveMons.find((x) => x.name === m.name && (!pid || x.projectId === pid)) || null;
        if (!existingMon) {
          try {
            await um.createMonitor({ ...m, projectId: pid });
            appliedCounts.created++;
          } catch (err) {
            /** @type {any} */
            const e = err;
            appliedWarnings.push(`Monitor "${m.name}" omitido: ${e.message || e}`);
            appliedCounts.skipped++;
          }
        }
      }
    }

    // 6. Prune de recursos eliminados del manifiesto
    if (prune) {
      for (const item of plan.delete) {
        if (item.blocked) {
          appliedCounts.skipped++;
          continue;
        }
        if (item.kind === 'domain') {
          await dm.deleteDomain(item.id);
          appliedCounts.deleted++;
        } else if (item.kind === 'cron') {
          cm.remove(item.id);
          appliedCounts.deleted++;
        } else if (item.kind === 'environment') {
          em.deleteEnvironment(item.projectId, item.envName, { force: confirmDestructive, actor });
          appliedCounts.deleted++;
        } else if (item.kind === 'project') {
          pm.delete(item.id);
          appliedCounts.deleted++;
        } else if (item.kind === 'database') {
          // Doble cinturón de seguridad: NUNCA borrar BD sin prune && confirmDestructive
          if (!prune || !confirmDestructive) {
            appliedCounts.skipped++;
            continue;
          }
          if (dbm && typeof dbm.delete === 'function') {
            await dbm.delete(item.id);
            appliedCounts.deleted++;
          } else if (dbm && typeof dbm.remove === 'function') {
            await dbm.remove(item.id);
            appliedCounts.deleted++;
          }
        }
      }
    }

    // Reconciliar Ingress (best-effort sin bloquear si Caddy está apagado)
    if (im && typeof im.reconcile === 'function') {
      try { await im.reconcile(); } catch (e) {}
    }

    const now = new Date().toISOString();
    const canonicalYaml = serializeSafeYaml(manifest, 0) + '\n';
    const liveExport = this.exportStack({ projectIds: managedProjectIds, name: manifest.name });

    const prevRecord = this.state.stacks[stackId] || null;
    const history = Array.isArray(prevRecord && prevRecord.history) ? [...prevRecord.history] : [];
    history.push({
      manifestHash: plan.manifestHash,
      appliedAt: now,
      actor,
      prune,
      counts: { ...appliedCounts }
    });

    this.state.stacks[stackId] = {
      id: stackId,
      name: manifest.name,
      manifestHash: plan.manifestHash,
      postApplyExportHash: liveExport.manifestHash,
      canonicalYaml,
      managedResources: {
        projectIds: Array.from(new Set(managedProjectIds)).sort(),
        domainHostnames: Array.from(new Set(managedDomainHostnames)).sort(),
        cronKeys: Array.from(new Set(managedCronKeys)).sort(),
        databaseIds: Array.from(new Set(managedDatabaseIds)).sort(),
        envKeys: Array.from(new Set(managedEnvKeys)).sort(),
        monitorKeys: Array.from(new Set(managedMonitorKeys)).sort()
      },
      lastAppliedAt: now,
      lastAppliedBy: actor,
      appliedCounts,
      history: history.slice(-30)
    };
    this._save();

    this._audit('gitops.stack_applied', stackId, {
      stackId,
      manifestHash: plan.manifestHash,
      prune,
      confirmDestructive,
      appliedCounts,
      actor
    });

    const result = {
      ok: true,
      dryRun: false,
      applied: true,
      stackId,
      stackName: manifest.name,
      manifestHash: plan.manifestHash,
      appliedCounts,
      plan: {
        create: plan.create,
        update: plan.update,
        delete: plan.delete,
        unchanged: plan.unchanged,
        summary: plan.summary
      },
      warnings: appliedWarnings,
      managedResources: this.state.stacks[stackId].managedResources,
      appliedAt: now
    };
    this.emit('stack_applied', result);
    return result;
  }

  // =========================================================================
  // 5. DRIFT DETECTION & STACK REGISTRY
  // =========================================================================

  /** Lista todos los stacks GitOps rastreados en `data/gitops.json`. */
  listStacks() {
    this._ensureLoaded();
    return Object.values(this.state.stacks)
      .sort((a, b) => String(b.lastAppliedAt || '').localeCompare(String(a.lastAppliedAt || '')))
      .map((s) => ({
        id: s.id,
        name: s.name,
        manifestHash: s.manifestHash,
        lastAppliedAt: s.lastAppliedAt,
        lastAppliedBy: s.lastAppliedBy,
        managedResources: s.managedResources,
        appliedCounts: s.appliedCounts
      }));
  }

  /**
   * Detecta divergencias entre el último manifiesto aplicado (`data/gitops.json`)
   * y el estado vivo actual de Culkibo.
   *
   * @param {string | null} [stackId]
   */
  detectDrift(stackId = null) {
    this._ensureLoaded();
    const stackIds = Object.keys(this.state.stacks);
    if (stackIds.length === 0) {
      return {
        ok: true,
        drifted: false,
        hasDrift: false,
        stackId: null,
        stackName: null,
        expectedHash: null,
        liveHash: null,
        differences: { create: [], update: [], delete: [] },
        summary: { create: 0, update: 0, delete: 0, hasChanges: false },
        checkedAt: new Date().toISOString()
      };
    }

    const targetId = stackId
      ? normalizeStackId(stackId)
      : this.listStacks()[0].id;
    const stack = this.state.stacks[targetId];
    if (!stack) {
      throw new Error(`Stack GitOps "${targetId}" no encontrado`);
    }

    const diffPlan = this.planApply(stack.canonicalYaml, { prune: true, stackId: targetId });
    const liveExport = this.exportStack({
      projectIds: (stack.managedResources && stack.managedResources.projectIds) || [],
      name: stack.name
    });

    const hashChanged = Boolean(stack.postApplyExportHash && liveExport.manifestHash !== stack.postApplyExportHash);
    const hasDiffItems = diffPlan.create.length > 0 || diffPlan.update.length > 0 || diffPlan.delete.length > 0;
    const drifted = hasDiffItems || hashChanged;

    return {
      ok: true,
      drifted,
      hasDrift: drifted,
      stackId: stack.id,
      stackName: stack.name,
      expectedHash: stack.manifestHash,
      expectedExportHash: stack.postApplyExportHash || null,
      liveHash: liveExport.manifestHash,
      lastAppliedAt: stack.lastAppliedAt,
      differences: {
        create: diffPlan.create,
        update: diffPlan.update,
        delete: diffPlan.delete
      },
      warnings: diffPlan.warnings,
      summary: {
        create: diffPlan.create.length,
        update: diffPlan.update.length,
        delete: diffPlan.delete.length,
        hasChanges: drifted
      },
      checkedAt: new Date().toISOString()
    };
  }

  // =========================================================================
  // 5b. WEBHOOK-TRIGGERED GITOPS AUTO-PLAN / NON-DESTRUCTIVE RECONCILE
  // =========================================================================

  /**
   * Lee de forma segura un archivo `culkibo.yaml` contenido dentro de `repoDir`
   * (bloquea path traversal, symlinks externos y archivos >256 KB).
   * @param {string} repoDir
   * @param {string} [manifestPath]
   * @returns {{ found: boolean, absPath: string | null, yamlText: string | null }}
   */
  readRepoManifestSafe(repoDir, manifestPath = 'culkibo.yaml') {
    const cleanRel = String(manifestPath || 'culkibo.yaml').trim().replace(/\\/g, '/').replace(/^\/+/, '');
    if (!cleanRel || cleanRel.includes('\0') || cleanRel.split('/').includes('..') || /^[A-Za-z]:/.test(cleanRel)) {
      throw new Error(`Ruta de manifiesto GitOps inválida: "${manifestPath}"`);
    }
    const base = path.resolve(String(repoDir || ''));
    if (!base || !fs.existsSync(base)) {
      return { found: false, absPath: null, yamlText: null };
    }
    const realBase = fs.realpathSync(base);
    const candidate = path.resolve(realBase, cleanRel);
    const relCheck = path.relative(realBase, candidate);
    if (!relCheck || relCheck.startsWith('..') || path.isAbsolute(relCheck)) {
      throw new Error(`Escape de directorio bloqueado en manifiesto GitOps: "${manifestPath}"`);
    }
    if (!fs.existsSync(candidate)) {
      return { found: false, absPath: null, yamlText: null };
    }
    const lstat = fs.lstatSync(candidate);
    if (lstat.isSymbolicLink() || !lstat.isFile()) {
      throw new Error(`El manifiesto GitOps "${cleanRel}" no puede ser un enlace simbólico ni directorio`);
    }
    const realCandidate = fs.realpathSync(candidate);
    const relReal = path.relative(realBase, realCandidate);
    if (!relReal || relReal.startsWith('..') || path.isAbsolute(relReal)) {
      throw new Error(`Escape por symlink bloqueado en manifiesto GitOps: "${manifestPath}"`);
    }
    if (lstat.size > MAX_YAML_BYTES) {
      throw new Error(`El manifiesto GitOps "${cleanRel}" supera el límite de ${Math.round(MAX_YAML_BYTES / 1024)} KB`);
    }
    return {
      found: true,
      absPath: realCandidate,
      yamlText: fs.readFileSync(realCandidate, 'utf8')
    };
  }

  /**
   * Reconciliación GitOps disparada por webhook Git (opt-in por proyecto).
   * - `project.gitopsAutoSync === 'plan'`: ejecuta `planApply` puro (0 mutaciones).
   * - `project.gitopsAutoSync === 'apply'`: ejecuta `applyStack` con `prune: false` y
   *   `confirmDestructive: false` FIJOS (un push Git JAMÁS borra BDs ni entornos protegidos).
   * - Cualquier otro valor (`'off'`, ausente): fail-closed (no hace nada).
   *
   * @param {{
   *   project: any,
   *   yamlText?: string | null,
   *   repoDir?: string | null,
   *   manifestPath?: string | null,
   *   provider?: string,
   *   commitSha?: string | null,
   *   branch?: string | null,
   *   actor?: string | null
   * }} opts
   */
  async reconcileWebhookManifest(opts) {
    const project = opts && opts.project;
    if (!project || typeof project !== 'object') {
      throw new Error('Se requiere un proyecto válido para reconciliación GitOps por webhook');
    }
    const mode = String(project.gitopsAutoSync || 'off').trim().toLowerCase();
    if (mode !== 'plan' && mode !== 'apply') {
      return {
        ok: true,
        mode: 'off',
        skipped: true,
        applied: false,
        reason: 'gitopsAutoSync deshabilitado para este proyecto'
      };
    }

    const manifestPath = String(opts.manifestPath || project.gitopsManifestPath || 'culkibo.yaml').trim() || 'culkibo.yaml';
    let rawYaml = typeof opts.yamlText === 'string' && opts.yamlText.trim() ? opts.yamlText : null;
    if (!rawYaml) {
      if (!opts.repoDir) {
        return {
          ok: true,
          mode,
          skipped: true,
          applied: false,
          reason: `No se proporcionó directorio local ni contenido de ${manifestPath}`
        };
      }
      const loaded = this.readRepoManifestSafe(opts.repoDir, manifestPath);
      if (!loaded.found || !loaded.yamlText) {
        return {
          ok: true,
          mode,
          skipped: true,
          applied: false,
          reason: `Manifiesto ${manifestPath} no encontrado en el repositorio`
        };
      }
      rawYaml = loaded.yamlText;
    }

    const stackId = normalizeStackId(project.gitopsStackId || project.id || project.name);
    const provider = String(opts.provider || 'git');
    const actor = String(opts.actor || `webhook:${provider}`).slice(0, 80);

    if (mode === 'plan') {
      const plan = this.planApply(rawYaml, { prune: false, confirmDestructive: false, stackId });
      this._audit('gitops.webhook_plan', stackId, {
        projectId: project.id,
        provider,
        branch: opts.branch || null,
        commitSha: opts.commitSha || null,
        manifestPath,
        manifestHash: plan.manifestHash,
        summary: plan.summary
      });
      const payload = {
        ok: true,
        mode: 'plan',
        applied: false,
        prune: false,
        stackId,
        manifestPath,
        manifestHash: plan.manifestHash,
        summary: plan.summary,
        warnings: plan.warnings,
        plan
      };
      this.emit('webhook_plan', payload);
      return payload;
    }

    // Modo 'apply': SIEMPRE no destructivo (prune: false, confirmDestructive: false)
    /** @type {any} */
    const result = await this.applyStack(rawYaml, {
      dryRun: false,
      prune: false,
      confirmDestructive: false,
      stackId,
      actor
    });
    this._audit('gitops.webhook_applied', stackId, {
      projectId: project.id,
      provider,
      branch: opts.branch || null,
      commitSha: opts.commitSha || null,
      manifestPath,
      manifestHash: result.manifestHash,
      appliedCounts: result.appliedCounts
    });
    const payload = {
      ok: true,
      mode: 'apply',
      applied: true,
      prune: false,
      stackId,
      manifestPath,
      manifestHash: result.manifestHash,
      appliedCounts: result.appliedCounts,
      warnings: result.warnings,
      result
    };
    this.emit('webhook_applied', payload);
    return payload;
  }

  // =========================================================================
  // 6. EXTERNAL IMPORTER BRIDGE (`convertExternalToCulkiboYaml`)
  // =========================================================================

  /**
   * Convierte configuraciones externas (`docker-compose`, `render`, `railway`, `vercel`,
   * `netlify`, `fly`, `heroku`, `procfile`, `dokploy`, `env`, `auto`) a un manifiesto
   * `culkibo.yaml` v1 seguro y libre de secretos usando `universalImporter`.
   *
   * @param {string} platform
   * @param {string} rawText
   * @param {{ name?: string, envText?: string, procfileText?: string, profiles?: string[], includeProfiled?: boolean }} [opts]
   */
  convertExternalToCulkiboYaml(platform, rawText, opts = {}) {
    const importer = this._getUniversalImporter();
    const plat = String(platform || 'auto').trim().toLowerCase();
    const text = String(rawText || '');
    if (!text.trim()) {
      throw new Error('El contenido de configuración externa está vacío');
    }

    /** @type {Set<string>} */
    const vaultRefs = new Set();
    /** @type {string[]} */
    const warnings = [];
    /** @type {any[]} */
    const projects = [];
    /** @type {any[]} */
    const databases = [];
    /** @type {any[]} */
    const domains = [];
    /** @type {any[]} */
    const crons = [];

    /** @param {Record<string, any>} rawEnv */
    const sanitizeImportedEnv = (rawEnv) => {
      /** @type {Record<string, string>} */
      const clean = {};
      for (const k of Object.keys(rawEnv || {}).sort()) {
        if (FORBIDDEN_PROTO_KEYS.has(k) || !ENV_KEY_RE.test(k)) continue;
        if (DANGEROUS_HOST_ENV_KEYS.has(k.toUpperCase())) {
          warnings.push(`Variable bloqueada por seguridad omitida al convertir: ${k}`);
          continue;
        }
        const v = rawEnv[k] == null ? '' : String(rawEnv[k]);
        const refs = extractVaultRefs(v);
        if (refs.length > 0) {
          for (const r of refs) vaultRefs.add(r);
          clean[k] = v;
        } else if (shouldRedactEnvForGit(k, v, false)) {
          vaultRefs.add(k);
          clean[k] = `\${vault.${k}}`;
        } else {
          clean[k] = v;
        }
      }
      return clean;
    };

    let detectedPlatform = plat;
    const looksLikeRender = /^\s*services\s*:/m.test(text) && (
      /buildCommand\s*:/m.test(text) ||
      /startCommand\s*:/m.test(text) ||
      /^\s*-?\s*type\s*:\s*(?:web|worker|cron|pserv|static)\b/m.test(text)
    );

    if (plat === 'docker-compose' || plat === 'compose' || (plat === 'auto' && /^\s*services\s*:/m.test(text) && !looksLikeRender)) {
      detectedPlatform = 'docker-compose';
      const parsed = importer.parseDockerCompose(text);
      const activeProfiles = new Set((Array.isArray(opts.profiles) ? opts.profiles : []).map((p) => String(p).trim()).filter(Boolean));
      const includeProfiled = Boolean(opts.includeProfiled);

      for (const svc of parsed.services || []) {
        if (!includeProfiled && Array.isArray(svc.profiles) && svc.profiles.length > 0 && !svc.profiles.some((p) => activeProfiles.has(p))) {
          warnings.push(`Servicio Compose "${svc.name}" omitido por perfil (${svc.profiles.join(', ')})`);
          continue;
        }
        if (Array.isArray(svc.warnings)) warnings.push(...svc.warnings);
        if (svc.kind === 'database' && svc.dbEngine && ALLOWED_DB_ENGINES.has(svc.dbEngine)) {
          databases.push({
            name: String(svc.name || svc.dbEngine).toLowerCase().replace(/[^a-z0-9_]/g, '_').slice(0, 48) || svc.dbEngine,
            engine: svc.dbEngine,
            generateSecret: true
          });
        } else {
          const mergedEnv = { ...(svc.envVars || {}) };
          // Mapear secretos Compose v3 a referencias ${vault.SECRET_NAME}
          for (const sec of Array.isArray(svc.secrets) ? svc.secrets : []) {
            const rawSecName = typeof sec === 'string' ? sec : sec?.source;
            if (!rawSecName) continue;
            const envKey = String(rawSecName).toUpperCase().replace(/[^A-Z0-9_]/g, '_').replace(/^([^A-Z_])/, 'SECRET_$1').slice(0, 120);
            if (ENV_KEY_RE.test(envKey) && !DANGEROUS_HOST_ENV_KEYS.has(envKey)) {
              vaultRefs.add(envKey);
              mergedEnv[envKey] = `\${vault.${envKey}}`;
            }
          }
          const cleanEnv = sanitizeImportedEnv(mergedEnv);
          /** @type {Record<string, any>} */
          const proj = {
            name: String(svc.name || 'app').slice(0, 80),
            gitBranch: 'main',
            serverId: 'local',
            autoDeploy: true
          };
          if (svc.containerPort) proj.containerPort = Number(svc.containerPort);
          if (svc.healthPath && svc.healthPath !== '/') proj.healthPath = svc.healthPath;
          if (svc.resources && svc.resources.memoryMb) proj.memoryMb = Number(svc.resources.memoryMb);
          if (svc.resources && svc.resources.cpus) proj.cpus = Number(svc.resources.cpus);
          if (Object.keys(cleanEnv).length > 0) proj.env = cleanEnv;
          projects.push(proj);
        }
      }
    } else if (plat === 'env' || plat === '.env') {
      detectedPlatform = 'env';
      const parsed = importer.parseEnvText(text);
      const cleanEnv = sanitizeImportedEnv(parsed.envVars || {});
      projects.push({
        name: opts.name || 'imported-app',
        gitBranch: 'main',
        serverId: 'local',
        autoDeploy: true,
        ...(Object.keys(cleanEnv).length > 0 ? { env: cleanEnv } : {})
      });
      for (const rec of parsed.recommendedDatabases || []) {
        if (ALLOWED_DB_ENGINES.has(rec.engine)) {
          databases.push({ name: `${rec.engine}_main`, engine: rec.engine, generateSecret: true });
        }
      }
    } else {
      const parsed = importer.parsePlatformConfig({
        platform: plat,
        configText: text,
        envText: opts.envText || '',
        procfileText: opts.procfileText || ''
      });
      detectedPlatform = parsed.platform || plat;
      if (Array.isArray(parsed.notes)) warnings.push(...parsed.notes);

      // Multi-service Render Blueprints
      if (detectedPlatform === 'render' && Array.isArray(parsed.services) && parsed.services.length > 0) {
        /** @type {string | null} */
        let primaryProjId = null;
        for (let idx = 0; idx < parsed.services.length; idx++) {
          const svc = parsed.services[idx];
          const mergedSvcEnv = idx === 0
            ? { ...(parsed.envVars || {}), ...(svc.envVars || {}) }
            : (svc.envVars || {});
          const cleanEnv = sanitizeImportedEnv(mergedSvcEnv);
          const sName = svc.name || 'render-service';
          const sId = `proj_${normalizeStackId(sName).replace(/-/g, '_')}`;
          if (!primaryProjId) primaryProjId = sId;
          /** @type {Record<string, any>} */
          const proj = {
            id: sId,
            name: sName,
            gitBranch: svc.gitBranch || 'main',
            serverId: 'local',
            autoDeploy: true
          };
          if (svc.gitRepo) proj.gitRepo = svc.gitRepo;
          if (svc.buildCommand) proj.buildCommand = svc.buildCommand;
          if (svc.startCommand) proj.startCommand = svc.startCommand;
          if (svc.baseDirectory && svc.baseDirectory !== '/') proj.baseDirectory = svc.baseDirectory;
          if (svc.port) proj.containerPort = Number(svc.port);
          if (svc.healthPath && svc.healthPath !== '/') proj.healthPath = svc.healthPath;
          if (Object.keys(cleanEnv).length > 0) proj.env = cleanEnv;
          projects.push(proj);
        }
        const seenDbEngines = new Set();
        for (const db of Array.isArray(parsed.databases) ? parsed.databases : []) {
          if (ALLOWED_DB_ENGINES.has(db.engine)) {
            seenDbEngines.add(db.engine);
            const dbNameClean = db.dbName && DB_IDENT_RE.test(db.dbName) ? db.dbName : undefined;
            const userClean = db.username && DB_IDENT_RE.test(db.username) ? db.username : undefined;
            databases.push({
              name: String(db.name || 'render_pg').slice(0, 63),
              engine: db.engine,
              ...(db.image ? { image: db.image } : {}),
              ...(primaryProjId ? { projectId: primaryProjId } : {}),
              ...(dbNameClean ? { dbName: dbNameClean } : {}),
              ...(userClean ? { username: userClean } : {}),
              generateSecret: true
            });
          }
        }
        for (const rec of parsed.recommendedDatabases || []) {
          if (ALLOWED_DB_ENGINES.has(rec.engine) && !seenDbEngines.has(rec.engine)) {
            seenDbEngines.add(rec.engine);
            databases.push({ name: `${rec.engine}_main`, engine: rec.engine, ...(primaryProjId ? { projectId: primaryProjId } : {}), generateSecret: true });
          }
        }
        for (const cr of Array.isArray(parsed.crons) ? parsed.crons : []) {
          try {
            parseCron(cr.schedule);
            parseSafeCommandArgv(cr.command);
            crons.push({
              name: String(cr.name).slice(0, 80),
              ...(primaryProjId ? { projectId: primaryProjId } : {}),
              schedule: cr.schedule,
              mode: 'exec',
              command: cr.command,
              enabled: true
            });
          } catch (e) {
            warnings.push(`Cron Render "${cr.name}" omitido por validación: ${e.message}`);
          }
        }
      } else {
        const cleanEnv = sanitizeImportedEnv(parsed.envVars || {});
        const projName = opts.name || parsed.name || `${detectedPlatform}-app`;
        const projId = `proj_${normalizeStackId(projName).replace(/-/g, '_')}`;
        /** @type {Record<string, any>} */
        const proj = {
          id: projId,
          name: projName,
          gitBranch: parsed.gitBranch || 'main',
          serverId: 'local',
          autoDeploy: true
        };
        if (parsed.description) proj.description = String(parsed.description).slice(0, 300);
        if (parsed.gitRepo) proj.gitRepo = parsed.gitRepo;
        if (parsed.buildCommand) proj.buildCommand = parsed.buildCommand;
        if (parsed.startCommand) proj.startCommand = parsed.startCommand;
        if (parsed.baseDirectory && parsed.baseDirectory !== '/') proj.baseDirectory = parsed.baseDirectory;
        if (parsed.port) proj.containerPort = Number(parsed.port);
        if (parsed.healthPath && parsed.healthPath !== '/') proj.healthPath = parsed.healthPath;
        if (parsed.memoryMb) proj.memoryMb = Number(parsed.memoryMb);
        if (parsed.cpus) proj.cpus = Number(parsed.cpus);
        if (Object.keys(cleanEnv).length > 0) proj.env = cleanEnv;
        projects.push(proj);

        // Workers adicionales (p. ej. Heroku Procfile `worker:`)
        if (Array.isArray(parsed.workers)) {
          for (const w of parsed.workers) {
            if (!w || !w.name || !w.command) continue;
            const wName = `${projName}-${w.name}`.slice(0, 80);
            const wId = `proj_${normalizeStackId(wName).replace(/-/g, '_')}`;
            projects.push({
              id: wId,
              name: wName,
              gitBranch: parsed.gitBranch || 'main',
              ...(parsed.gitRepo ? { gitRepo: parsed.gitRepo } : {}),
              startCommand: w.command,
              serverId: 'local',
              autoDeploy: true,
              ...(Object.keys(cleanEnv).length > 0 ? { env: cleanEnv } : {})
            });
          }
        }

        for (const rawHost of parsed.domains || []) {
          try {
            const host = this._validateHostname(String(rawHost));
            domains.push({
              hostname: host,
              projectId: projId,
              targetPort: Number(parsed.port) || 3000,
              routingMode: 'direct_dns',
              cloudflareProxied: false,
              canonicalRedirect: 'none',
              securityHeaders: true
            });
          } catch (e) {}
        }

        for (const rec of parsed.recommendedDatabases || []) {
          if (ALLOWED_DB_ENGINES.has(rec.engine)) {
            databases.push({ name: `${rec.engine}_main`, engine: rec.engine, projectId: projId, generateSecret: true });
          }
        }
      }
    }

    const sortedVaultRefs = Array.from(vaultRefs).sort();
    const stackName = opts.name || `${detectedPlatform}-stack`;
    /** @type {Record<string, any>} */
    const manifest = {
      version: 1,
      name: stackName,
      ...(sortedVaultRefs.length > 0 ? { vaultRefs: sortedVaultRefs } : {}),
      projects,
      ...(databases.length > 0 ? { databases } : {}),
      ...(domains.length > 0 ? { domains } : {}),
      ...(crons.length > 0 ? { crons } : {})
    };

    const yaml = serializeSafeYaml(manifest, 0) + '\n';
    // Auto-verificar que el YAML generado pasa nuestro propio parser y validador estricto
    this.validateManifest(parseSafeYaml(yaml));

    return {
      ok: true,
      platform: detectedPlatform,
      manifestHash: hashManifest(manifest),
      vaultRefs: sortedVaultRefs,
      warnings,
      manifest,
      yaml
    };
  }
}

const instance = Object.assign(new GitOpsManager(), {
  GitOpsManager,
  parseSafeYaml,
  serializeSafeYaml,
  hashManifest,
  shouldRedactEnvForGit,
  MAX_YAML_BYTES,
  MAX_YAML_LINES,
  MAX_YAML_DEPTH,
  MAX_YAML_NODES
});

module.exports = instance;
