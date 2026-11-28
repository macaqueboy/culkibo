const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Build-`ARG` / `ENV` Secret Surface & `/run/secrets/` Migrator (100% Zero-Dep).
 *
 * Contramedida directa a `Dokploy/dokploy#3347` (BuildKit `SecretsUsedInArgOrEnv` filtrando
 * `AUTH_SECRET`/`JWT_SECRET` en `ARG`/`ENV` y `docker history`) y `coollabsio/coolify#10822`
 * (exposición simultánea build+runtime por defecto):
 *  - Escanea Dockerfiles y claves de Compose **exclusivamente por nombre de clave** —
 *    JAMÁS persiste ni devuelve valores crudos de secretos.
 *  - Detecta `BUILDKIT_SECRET_IN_ARG_OR_ENV`, `COMPOSE_SECRET_IN_PLAIN_ENV` y
 *    `BUILD_RUNTIME_SECRET_OVERLAP`.
 *  - Emite migraciones sin fugas con BuildKit `RUN --mount=type=secret,id=<id>` y
 *    Compose `secrets:` (`mode: 0400`, `/run/secrets/<id>`), con `dryRun: true` por defecto.
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/env-secret-surface.json`.
 */

const MAX_AUDITS = 200;

const SENSITIVE_KEY_RE = /(?:^|_)(?:SECRET|KEY|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIAL|CREDENTIALS|PRIVATE|AUTH|SIGNING|HMAC|ENCRYPTION|MASTER|DSN|WEBHOOK|CERT)(?:$|_)|^(?:DATABASE_URL|REDIS_URL|MONGO_URI|MONGODB_URI|SMTP_URL|POSTGRES_URL|MYSQL_URL|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|STRIPE_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|GH_TOKEN|GITHUB_TOKEN|NPM_TOKEN|JWT_SECRET|NEXTAUTH_SECRET|AUTH_SECRET|SESSION_SECRET|COOKIE_SECRET)$/i;

const NON_SECRET_KEY_RE = /^(?:NODE_ENV|APP_ENV|PORT|HOST|HOSTNAME|TZ|LOG_LEVEL|DEBUG|PUBLIC_URL|NEXT_PUBLIC_.*|VITE_.*|PUBLIC_KEY|SSH_PUBLIC_KEY|.*_PUBLIC_KEY|.*_FILE|.*_EXPIRES_IN|.*_TTL|.*_MIN_LENGTH|.*_PROVIDER|.*_REGION|.*_ENABLED|.*_MODE|.*_FORMAT|.*_ISSUER|.*_AUDIENCE)$/i;

/**
 * Resuelve dinámicamente la ruta a `env-secret-surface.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'env-secret-surface.json')
    : path.join(base, 'data', 'env-secret-surface.json');
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
 * Carga auditorías almacenadas desde disco (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, audits: any[] }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), audits: [] };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && Array.isArray(parsed.audits)) {
      return parsed;
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), audits: [] };
}

/**
 * Guarda auditorías de forma atómica (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, audits: any[] }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  if (store.audits.length > MAX_AUDITS) {
    store.audits = store.audits.slice(-MAX_AUDITS);
  }
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Extrae ÚNICAMENTE el nombre de clave (nunca el valor después de `=` o `:`).
 * @param {unknown} raw
 * @returns {string}
 */
function extractKeyNameOnly(raw) {
  const s = String(raw || '').trim();
  if (!s) return '';
  const withoutListPrefix = s.replace(/^-\s*/, '').trim();
  const keyOnly = withoutListPrefix.split(/[=:\s]/)[0].replace(/^["']|["']$/g, '').trim();
  if (!/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(keyOnly)) return '';
  return keyOnly;
}

/**
 * Normaliza un array de nombres de clave descartando cualquier valor crudo.
 * @param {unknown} list
 * @returns {string[]}
 */
function sanitizeKeyList(list) {
  if (!Array.isArray(list)) return [];
  /** @type {string[]} */
  const out = [];
  const seen = new Set();
  for (const item of list) {
    const k = extractKeyNameOnly(item);
    if (k && !seen.has(k)) {
      seen.add(k);
      out.push(k);
    }
  }
  return out;
}

/**
 * Determina si un nombre de clave corresponde a un secreto/credencial sensible.
 * @param {string} keyName
 * @returns {boolean}
 */
function isSensitiveKeyName(keyName) {
  if (!keyName) return false;
  if (NON_SECRET_KEY_RE.test(keyName)) return false;
  return SENSITIVE_KEY_RE.test(keyName);
}

/**
 * Convierte un nombre de variable (ej. `JWT_SECRET`) en un ID BuildKit/Compose seguro (`jwt_secret`).
 * @param {string} keyName
 * @returns {string}
 */
function toSecretId(keyName) {
  const cleaned = extractKeyNameOnly(keyName)
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return cleaned || 'app_secret';
}

/**
 * Extrae nombres de claves `ARG` y `ENV` de un Dockerfile (ignorando por completo los valores).
 * @param {string} dockerfile
 * @returns {{ argKeys: string[], envKeys: string[] }}
 */
function parseDockerfileKeysOnly(dockerfile) {
  const raw = String(dockerfile || '');
  if (!raw.trim()) return { argKeys: [], envKeys: [] };

  // Join backslash line continuations safely
  const logicalLines = [];
  let buf = '';
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!buf && (!trimmed || trimmed.startsWith('#'))) continue;
    if (trimmed.endsWith('\\')) {
      buf += trimmed.slice(0, -1) + ' ';
    } else {
      buf += trimmed;
      logicalLines.push(buf.trim());
      buf = '';
    }
  }
  if (buf.trim()) logicalLines.push(buf.trim());

  const argSet = new Set();
  const envSet = new Set();

  for (const stmt of logicalLines) {
    const argMatch = /^ARG\s+(.+)$/i.exec(stmt);
    if (argMatch) {
      // ARG supports one or more NAME[=default] tokens
      const tokens = argMatch[1].match(/[A-Za-z_][A-Za-z0-9_]*(?:=(?:"[^"]*"|'[^']*'|\S*))?/g) || [];
      for (const tok of tokens) {
        const key = extractKeyNameOnly(tok);
        if (key) argSet.add(key);
      }
      continue;
    }

    const envMatch = /^ENV\s+(.+)$/i.exec(stmt);
    if (envMatch) {
      const rest = envMatch[1].trim();
      if (rest.includes('=')) {
        // Modern syntax: ENV KEY=val KEY2="val 2"
        const pairs = rest.match(/[A-Za-z_][A-Za-z0-9_]*=(?:"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|\S*)/g) || [];
        for (const pair of pairs) {
          const key = extractKeyNameOnly(pair);
          if (key) envSet.add(key);
        }
      } else {
        // Legacy syntax: ENV KEY value (only first token is key name)
        const key = extractKeyNameOnly(rest);
        if (key) envSet.add(key);
      }
    }
  }

  return {
    argKeys: Array.from(argSet),
    envKeys: Array.from(envSet)
  };
}

/**
 * Genera fragmentos de migración zero-leak para Dockerfile (`RUN --mount=type=secret,id=<id>`)
 * y Docker Compose (`secrets:` con `mode: 0400` y `<KEY>_FILE=/run/secrets/<id>`).
 * `dryRun: true` por defecto; jamás incluye valores crudos de secretos.
 *
 * @param {{ secretNames?: string[], dryRun?: boolean }} [input]
 */
function renderSecretMountMigration(input = {}) {
  const opts = input || {};
  const dryRun = opts.dryRun !== undefined ? Boolean(opts.dryRun) : true;
  const cleanedNames = sanitizeKeyList(opts.secretNames);
  const secretNames = cleanedNames.length > 0 ? cleanedNames : ['JWT_SECRET', 'DATABASE_URL'];

  const pairs = secretNames.map((name) => ({
    envName: name.toUpperCase(),
    secretId: toSecretId(name)
  }));

  const mountLines = pairs.map((p, idx) =>
    idx === 0
      ? `RUN --mount=type=secret,id=${p.secretId},target=/run/secrets/${p.secretId},required=true \\`
      : `  --mount=type=secret,id=${p.secretId},target=/run/secrets/${p.secretId},required=true \\`
  );

  const dockerfileSnippet = [
    '# syntax=docker/dockerfile:1.7',
    '# Zero-Leak BuildKit Secret Mounts (replaces ARG/ENV — never persisted in docker history)',
    ...mountLines,
    '  sh -c \'set -eu; ' +
      pairs.map((p) => `${p.envName}="$(cat /run/secrets/${p.secretId})"`).join('; ') +
      '; export ' + pairs.map((p) => p.envName).join(' ') + '; npm run build\''
  ].join('\n');

  const composeEnvLines = pairs
    .map((p) => `      ${p.envName}_FILE: /run/secrets/${p.secretId}`)
    .join('\n');
  const composeServiceSecretLines = pairs
    .map((p) => [
      `      - source: ${p.secretId}`,
      `        target: /run/secrets/${p.secretId}`,
      '        mode: 0400'
    ].join('\n'))
    .join('\n');
  const composeTopSecretLines = pairs
    .map((p) => [
      `  ${p.secretId}:`,
      `    file: ./secrets/${p.secretId}.txt`
    ].join('\n'))
    .join('\n');

  const composeSnippet = [
    '# Zero-Leak Docker Compose tmpfs Secrets (mode 0400 — never plain environment values)',
    'services:',
    '  app:',
    '    environment:',
    composeEnvLines,
    '    secrets:',
    composeServiceSecretLines,
    'secrets:',
    composeTopSecretLines
  ].join('\n');

  return {
    ok: true,
    dryRun,
    secretNames: pairs.map((p) => p.envName),
    secretIds: pairs.map((p) => p.secretId),
    dockerfileSnippet,
    composeSnippet,
    zeroRawSecretsStored: true,
    renderedAt: new Date().toISOString()
  };
}

/**
 * Audita la superficie de secretos en Dockerfile `ARG`/`ENV` y variables de Compose
 * (solo nombres de claves — jamás almacena ni hace eco de valores crudos).
 *
 * @param {{
 *   projectId?: string,
 *   dockerfile?: string,
 *   composeEnvKeys?: string[],
 *   composeSecretKeys?: string[],
 *   buildTimeEnvKeys?: string[],
 *   persist?: boolean
 * }} [input]
 */
function auditEnvSecretSurface(input = {}) {
  const opts = input || {};
  const projectId = opts.projectId ? String(opts.projectId).trim() : null;
  const parsedDf = parseDockerfileKeysOnly(opts.dockerfile || '');

  const composeEnvKeys = sanitizeKeyList(opts.composeEnvKeys);
  const composeSecretKeys = sanitizeKeyList(opts.composeSecretKeys);
  const buildTimeEnvKeys = sanitizeKeyList(opts.buildTimeEnvKeys);

  const composeSecretIdSet = new Set(composeSecretKeys.map((k) => toSecretId(k)));
  const composeSecretUpperSet = new Set(composeSecretKeys.map((k) => k.toUpperCase()));

  const dockerfileArgSecrets = parsedDf.argKeys.filter((k) => isSensitiveKeyName(k));
  const dockerfileEnvSecrets = parsedDf.envKeys.filter((k) => isSensitiveKeyName(k));
  const dockerfileSecretKeys = Array.from(new Set([...dockerfileArgSecrets, ...dockerfileEnvSecrets]));

  const composePlainSecretKeys = composeEnvKeys.filter((k) => {
    if (!isSensitiveKeyName(k)) return false;
    return !composeSecretUpperSet.has(k.toUpperCase()) && !composeSecretIdSet.has(toSecretId(k));
  });

  // Build+Runtime overlap detection (Coolify#10822)
  const buildKeyUpperSet = new Set([
    ...dockerfileSecretKeys.map((k) => k.toUpperCase()),
    ...buildTimeEnvKeys.filter((k) => isSensitiveKeyName(k)).map((k) => k.toUpperCase())
  ]);
  const buildRuntimeOverlapKeys = composeEnvKeys.filter(
    (k) => isSensitiveKeyName(k) && buildKeyUpperSet.has(k.toUpperCase())
  );

  /** @type {Array<{ code: string, severity: 'critical' | 'high', keys: string[], message: string, fix: string }>} */
  const findings = [];

  if (dockerfileSecretKeys.length > 0) {
    findings.push({
      code: 'BUILDKIT_SECRET_IN_ARG_OR_ENV',
      severity: 'critical',
      keys: dockerfileSecretKeys,
      message: `Sensitive key(s) declared in Dockerfile ARG/ENV (${dockerfileSecretKeys.join(', ')}) — plaintext values leak permanently into OCI image config & docker history (Dokploy#3347).`,
      fix: 'Remove sensitive ARG/ENV lines and pass secrets ephemerally with `RUN --mount=type=secret,id=<id>`.'
    });
  }

  if (composePlainSecretKeys.length > 0) {
    findings.push({
      code: 'COMPOSE_SECRET_IN_PLAIN_ENV',
      severity: 'high',
      keys: composePlainSecretKeys,
      message: `Sensitive key(s) exposed via plain Compose environment (${composePlainSecretKeys.join(', ')}) instead of /run/secrets/ tmpfs mounts.`,
      fix: 'Migrate credentials to Compose `secrets:` (mode 0400) and pass `<KEY>_FILE=/run/secrets/<id>`.'
    });
  }

  if (buildRuntimeOverlapKeys.length > 0) {
    findings.push({
      code: 'BUILD_RUNTIME_SECRET_OVERLAP',
      severity: 'high',
      keys: buildRuntimeOverlapKeys,
      message: `Sensitive key(s) scoped to both build-time and runtime environments (${buildRuntimeOverlapKeys.join(', ')}) — runtime credentials should never be available inside build stages (Coolify#10822).`,
      fix: 'Restrict runtime credentials to runtime-only `/run/secrets/` mounts and disable default build+runtime inheritance.'
    });
  }

  const allFlaggedSecretNames = Array.from(
    new Set([...dockerfileSecretKeys, ...composePlainSecretKeys, ...buildRuntimeOverlapKeys])
  );
  const migration = renderSecretMountMigration({
    secretNames: allFlaggedSecretNames,
    dryRun: true
  });

  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const safe = findings.length === 0;
  const blocked = !safe;
  const status = criticalCount > 0 ? 'CRITICAL' : (findings.length > 0 ? 'WARNING' : 'HEALTHY');
  const auditedAt = new Date().toISOString();

  const result = {
    ok: true,
    id: `envsurf_${crypto.randomBytes(5).toString('hex')}`,
    projectId,
    safe,
    blocked,
    status,
    dockerfileSecretKeys,
    composePlainSecretKeys,
    buildRuntimeOverlapKeys,
    composeSecretKeys,
    zeroRawSecretsStored: true,
    findings,
    findingCodes: findings.map((f) => f.code),
    dockerfileSnippet: migration.dockerfileSnippet,
    composeSnippet: migration.composeSnippet,
    auditedAt
  };

  if (opts.persist !== false) {
    const store = loadStore();
    store.audits.push({
      id: result.id,
      projectId,
      safe,
      status,
      dockerfileSecretKeys,
      composePlainSecretKeys,
      buildRuntimeOverlapKeys,
      findingCodes: result.findingCodes,
      zeroRawSecretsStored: true,
      auditedAt
    });
    saveStore(store);
  }

  return result;
}

/**
 * Lista auditorías de superficie de secretos (solo nombres de claves, más recientes primero).
 * @param {string} [projectId]
 */
function listEnvSurfaceAudits(projectId) {
  const store = loadStore();
  const cleanId = projectId ? String(projectId).trim() : '';
  const items = cleanId
    ? store.audits.filter((a) => a.projectId === cleanId)
    : store.audits;
  return [...items].reverse();
}

module.exports = {
  auditEnvSecretSurface,
  renderSecretMountMigration,
  listEnvSurfaceAudits
};
