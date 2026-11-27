const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Immutable Digest Multi-Environment GitOps Promotion Pipeline (Zero-Dep).
 *
 * Inspirado en Kargo Freight, cura `dokploy#2097` y `argo-cd#5290`:
 *  - Exige digests inmutables `@sha256:<64hex>` rechazando `:latest` y tags mutables (`MUTABLE_TAG_FORBIDDEN`).
 *  - Verifica paridad de claves de entorno (solo nombres de claves, CERO valores secretos!) bloqueando
 *    claves faltantes en el destino (`MISSING_TARGET_ENV_KEYS`).
 *  - Impone control dual (`DUAL_CONTROL_VIOLATION` si `approver === requester` con `requireDualControl: true`).
 *  - Exige aprobación previa para despliegues a `prod` (`APPROVAL_REQUIRED`).
 *  - Mantiene manifiesto de rollback determinista al `previousDigest`.
 *  - Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/digest-promotions.json`.
 */

const IMMUTABLE_DIGEST_RE = /^([a-z0-9._/-]+(?::[a-z0-9._-]+)?)@(sha256:[a-f0-9]{64})$/i;

/**
 * @typedef {object} DigestPromotionRecord
 * @property {string} id
 * @property {string} projectId
 * @property {string} imageRef
 * @property {string} digest
 * @property {string | null} previousDigest
 * @property {string} fromEnv
 * @property {string} toEnv
 * @property {string[]} sourceEnvKeys
 * @property {string[]} targetEnvKeys
 * @property {boolean} envParityOk
 * @property {string} requester
 * @property {boolean} requireDualControl
 * @property {'pending_approval' | 'approved' | 'promoted' | 'rolled_back'} status
 * @property {Array<{ approver: string, comment: string, approvedAt: string }>} approvals
 * @property {string} createdAt
 * @property {string} updatedAt
 * @property {string | null} executedAt
 * @property {string | null} rolledBackAt
 * @property {string | null} rolledBackBy
 */

/**
 * Resuelve dinámicamente la ruta a `digest-promotions.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'digest-promotions.json')
    : path.join(base, 'data', 'digest-promotions.json');
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
 * @returns {{ schemaVersion: number, updatedAt: string, promotions: DigestPromotionRecord[] }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), promotions: [] };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && Array.isArray(parsed.promotions)) {
      return parsed;
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), promotions: [] };
}

/**
 * Persiste el store atómicamente (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, promotions: DigestPromotionRecord[] }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Valida que una referencia de imagen OCI esté fijada a un digest inmutable `@sha256:<64hex>`.
 * Rechaza `:latest` y cualquier tag mutable con `MUTABLE_TAG_FORBIDDEN`.
 *
 * @param {string} imageRef
 */
function validateImmutableDigest(imageRef) {
  const raw = String(imageRef || '').trim();
  const m = raw.match(IMMUTABLE_DIGEST_RE);
  if (!m) {
    return {
      ok: true,
      valid: false,
      code: 'MUTABLE_TAG_FORBIDDEN',
      imageRef: raw,
      repository: null,
      digest: null,
      message: `Image "${raw || '(empty)'}" is not pinned to an immutable @sha256:<64hex> digest; mutable tags like :latest are forbidden for promotions.`
    };
  }
  return {
    ok: true,
    valid: true,
    code: 'IMMUTABLE_DIGEST_VALID',
    imageRef: raw,
    repository: m[1],
    digest: m[2].toLowerCase(),
    message: 'Image reference is pinned to a valid immutable SHA-256 OCI digest.'
  };
}

/**
 * Sanitiza nombres de claves de variables de entorno (NUNCA valores).
 * @param {any} keys
 * @returns {string[]}
 */
function normalizeEnvKeys(keys) {
  if (!Array.isArray(keys)) return [];
  return Array.from(
    new Set(
      keys
        .map((k) => String(k || '').split('=')[0].trim())
        .filter(Boolean)
    )
  );
}

/**
 * Crea una solicitud de promoción inmutable entre entornos (`dev → staging → prod`),
 * bloqueando tags mutables (`MUTABLE_TAG_FORBIDDEN`) y claves faltantes en destino (`MISSING_TARGET_ENV_KEYS`).
 *
 * @param {{
 *   projectId: string,
 *   imageRef: string,
 *   fromEnv?: string,
 *   toEnv?: string,
 *   sourceEnvKeys?: string[],
 *   targetEnvKeys?: string[],
 *   requester: string,
 *   requireDualControl?: boolean,
 *   previousDigest?: string | null
 * }} input
 */
function createPromotion(input) {
  const opts = input || /** @type {any} */ ({});
  const projectId = String(opts.projectId || '').trim();
  const requester = String(opts.requester || '').trim();
  const fromEnv = String(opts.fromEnv || 'staging').trim().toLowerCase() || 'staging';
  const toEnv = String(opts.toEnv || 'prod').trim().toLowerCase() || 'prod';
  const requireDualControl = opts.requireDualControl !== undefined ? Boolean(opts.requireDualControl) : true;

  if (!projectId) {
    return { ok: false, blocked: true, code: 'PROJECT_ID_REQUIRED', status: 400, message: 'projectId is required.', promotion: null };
  }
  if (!requester) {
    return { ok: false, blocked: true, code: 'REQUESTER_REQUIRED', status: 400, message: 'requester is required.', promotion: null };
  }

  const check = validateImmutableDigest(opts.imageRef);
  if (!check.valid || !check.digest) {
    return {
      ok: false,
      blocked: true,
      code: 'MUTABLE_TAG_FORBIDDEN',
      status: 400,
      message: check.message,
      promotion: null
    };
  }

  let previousDigest = opts.previousDigest ? String(opts.previousDigest).trim() : null;
  if (previousDigest) {
    const prevCheck = validateImmutableDigest(previousDigest);
    if (!prevCheck.valid && !/^sha256:[a-f0-9]{64}$/i.test(previousDigest)) {
      return {
        ok: false,
        blocked: true,
        code: 'MUTABLE_TAG_FORBIDDEN',
        status: 400,
        message: `previousDigest "${previousDigest}" must be an immutable @sha256 or sha256:<64hex> reference.`,
        promotion: null
      };
    }
  }

  const sourceEnvKeys = normalizeEnvKeys(opts.sourceEnvKeys);
  const targetEnvKeys = normalizeEnvKeys(opts.targetEnvKeys);
  const targetSet = new Set(targetEnvKeys);
  const missingKeys = sourceEnvKeys.filter((k) => !targetSet.has(k));

  if (missingKeys.length > 0) {
    return {
      ok: false,
      blocked: true,
      code: 'MISSING_TARGET_ENV_KEYS',
      status: 400,
      missingKeys,
      message: `Target environment "${toEnv}" is missing required env key(s) present in "${fromEnv}": ${missingKeys.join(', ')}.`,
      promotion: null
    };
  }

  const nowIso = new Date().toISOString();
  /** @type {DigestPromotionRecord} */
  const promotion = {
    id: `promo_${crypto.randomBytes(6).toString('hex')}`,
    projectId,
    imageRef: check.imageRef,
    digest: check.digest,
    previousDigest,
    fromEnv,
    toEnv,
    sourceEnvKeys,
    targetEnvKeys,
    envParityOk: true,
    requester,
    requireDualControl,
    status: 'pending_approval',
    approvals: [],
    createdAt: nowIso,
    updatedAt: nowIso,
    executedAt: null,
    rolledBackAt: null,
    rolledBackBy: null
  };

  const store = loadStore();
  store.promotions.push(promotion);
  saveStore(store);

  return {
    ok: true,
    blocked: false,
    code: 'PROMOTION_CREATED',
    promotion
  };
}

/**
 * Aprueba una promoción pendiente aplicando control dual (`DUAL_CONTROL_VIOLATION` si `approver === requester`).
 *
 * @param {string} promoId
 * @param {{ approver: string, comment?: string }} input
 */
function approvePromotion(promoId, input) {
  const cleanId = String(promoId || '').trim();
  const approver = String((input && input.approver) || '').trim();
  const comment = String((input && input.comment) || '').trim();

  if (!approver) {
    return { ok: false, blocked: true, code: 'APPROVER_REQUIRED', status: 400, message: 'approver is required.', promotion: null };
  }

  const store = loadStore();
  const promo = store.promotions.find((p) => p.id === cleanId);
  if (!promo) {
    return { ok: false, blocked: true, code: 'PROMOTION_NOT_FOUND', status: 404, message: `Promotion "${cleanId}" not found.`, promotion: null };
  }

  if (promo.requireDualControl && approver.toLowerCase() === promo.requester.toLowerCase()) {
    return {
      ok: false,
      blocked: true,
      code: 'DUAL_CONTROL_VIOLATION',
      status: 403,
      message: `Dual-control policy forbids self-approval: requester "${promo.requester}" cannot approve their own promotion.`,
      promotion: promo
    };
  }

  const nowIso = new Date().toISOString();
  promo.approvals.push({ approver, comment, approvedAt: nowIso });
  promo.status = 'approved';
  promo.updatedAt = nowIso;
  saveStore(store);

  return {
    ok: true,
    blocked: false,
    code: 'PROMOTION_APPROVED',
    promotion: promo
  };
}

/**
 * Ejecuta (o simula en `dryRun: true`) una promoción inmutable. Exige `status === 'approved'`
 * para promociones a `prod`/`production` (`APPROVAL_REQUIRED`).
 *
 * @param {string} promoId
 * @param {{ dryRun?: boolean }} [options]
 */
function executePromotion(promoId, options = {}) {
  const cleanId = String(promoId || '').trim();
  const dryRun = options && options.dryRun !== undefined ? Boolean(options.dryRun) : true;

  const store = loadStore();
  const promo = store.promotions.find((p) => p.id === cleanId);
  if (!promo) {
    return { ok: false, blocked: true, code: 'PROMOTION_NOT_FOUND', status: 404, message: `Promotion "${cleanId}" not found.`, promotion: null };
  }

  const isProdTarget = promo.toEnv === 'prod' || promo.toEnv === 'production';
  if (isProdTarget && promo.status !== 'approved' && promo.status !== 'promoted') {
    return {
      ok: false,
      blocked: true,
      code: 'APPROVAL_REQUIRED',
      status: 409,
      message: `Promotion "${cleanId}" targeting "${promo.toEnv}" requires explicit approval before execution (current status: "${promo.status}").`,
      promotion: promo
    };
  }

  const promotionManifest = {
    promoId: promo.id,
    projectId: promo.projectId,
    fromEnv: promo.fromEnv,
    toEnv: promo.toEnv,
    imageRef: promo.imageRef,
    digest: promo.digest,
    previousDigest: promo.previousDigest,
    steps: [
      'verify-immutable-sha256-digest',
      'verify-target-env-key-parity',
      'switch-target-workload-to-digest',
      'verify-post-promotion-healthcheck'
    ]
  };

  const rollbackManifest = {
    promoId: promo.id,
    targetEnv: promo.toEnv,
    restoreDigest: promo.previousDigest,
    available: Boolean(promo.previousDigest)
  };

  if (!dryRun) {
    const nowIso = new Date().toISOString();
    promo.status = 'promoted';
    promo.executedAt = nowIso;
    promo.updatedAt = nowIso;
    saveStore(store);
  }

  return {
    ok: true,
    blocked: false,
    code: dryRun ? 'PROMOTION_DRY_RUN_READY' : 'PROMOTION_EXECUTED',
    dryRun,
    promotion: promo,
    promotionManifest,
    rollbackManifest
  };
}

/**
 * Revierte una promoción al `previousDigest` inmutable registrado.
 *
 * @param {string} promoId
 * @param {{ actor?: string, dryRun?: boolean }} [options]
 */
function rollbackPromotion(promoId, options = {}) {
  const cleanId = String(promoId || '').trim();
  const actor = String((options && options.actor) || 'admin').trim() || 'admin';
  const dryRun = options && options.dryRun !== undefined ? Boolean(options.dryRun) : true;

  const store = loadStore();
  const promo = store.promotions.find((p) => p.id === cleanId);
  if (!promo) {
    return { ok: false, blocked: true, code: 'PROMOTION_NOT_FOUND', status: 404, message: `Promotion "${cleanId}" not found.`, promotion: null };
  }

  if (!promo.previousDigest) {
    return {
      ok: false,
      blocked: true,
      code: 'NO_PREVIOUS_DIGEST',
      status: 400,
      message: `Promotion "${cleanId}" has no recorded previousDigest for rollback.`,
      promotion: promo
    };
  }

  if (!dryRun) {
    const nowIso = new Date().toISOString();
    promo.status = 'rolled_back';
    promo.rolledBackAt = nowIso;
    promo.rolledBackBy = actor;
    promo.updatedAt = nowIso;
    saveStore(store);
  }

  return {
    ok: true,
    blocked: false,
    code: dryRun ? 'ROLLBACK_DRY_RUN_READY' : 'PROMOTION_ROLLED_BACK',
    dryRun,
    restoredDigest: promo.previousDigest,
    actor,
    promotion: promo
  };
}

/**
 * Lista promociones registradas (opcionalmente filtradas por `projectId`, más recientes primero).
 * @param {string} [projectId]
 * @returns {DigestPromotionRecord[]}
 */
function listPromotions(projectId) {
  const store = loadStore();
  const cleanId = projectId ? String(projectId).trim() : '';
  const list = cleanId
    ? store.promotions.filter((p) => p.projectId === cleanId)
    : store.promotions;
  return [...list].reverse();
}

module.exports = {
  validateImmutableDigest,
  createPromotion,
  approvePromotion,
  executePromotion,
  rollbackPromotion,
  listPromotions
};
