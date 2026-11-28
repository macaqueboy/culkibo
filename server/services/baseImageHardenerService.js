const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * EOL Base-Image, CNCF `copa` Thin-Patch & Distroless/Wolfi Hardener (100% Zero-Dep).
 *
 * Audita Dockerfiles y resúmenes de CVEs de OS:
 *  - Detecta bases EOL (`node:16`/`18`, `python:3.8`/`3.9`, `debian:buster`/`bullseye`,
 *    `alpine:3.18`, `ubuntu:20.04` → `EOL_BASE_IMAGE`).
 *  - Detecta `USER root` / ausencia de usuario non-root (`ROOT_USER_FINAL_STAGE`).
 *  - Detecta etiquetas mutables sin `@sha256:` (`UNPINNED_BASE_TAG`).
 *  - Detecta `readOnlyRootfs: false` (`WRITABLE_ROOTFS_RISK`).
 *  - Emite reemplazos Wolfi/Distroless (UID `65532`) y planes `copa patch` cero-shell (`dryRun: true`).
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/base-image-hardener.json`.
 */

const MAX_AUDITS = 200;
const DIGEST_PIN_RE = /@sha256:[a-f0-9]{64}$/i;

const EOL_BASE_CATALOG = Object.freeze([
  Object.freeze({ family: 'node', pattern: /^node:(?:14|16|18)(?:[.-]|$)/i, eolDate: '2025-04-30', replacement: 'cgr.dev/chainguard/node:latest@sha256:' + 'a'.repeat(64) }),
  Object.freeze({ family: 'python', pattern: /^python:(?:3\.7|3\.8|3\.9)(?:[.-]|$)/i, eolDate: '2025-10-31', replacement: 'cgr.dev/chainguard/python:latest@sha256:' + 'b'.repeat(64) }),
  Object.freeze({ family: 'debian', pattern: /^debian:(?:buster|bullseye|10|11)(?:[.-]|$)/i, eolDate: '2026-08-31', replacement: 'gcr.io/distroless/base-debian12:nonroot@sha256:' + 'c'.repeat(64) }),
  Object.freeze({ family: 'alpine', pattern: /^alpine:(?:3\.15|3\.16|3\.17|3\.18)(?:[.-]|$)/i, eolDate: '2025-05-09', replacement: 'cgr.dev/chainguard/wolfi-base:latest@sha256:' + 'd'.repeat(64) }),
  Object.freeze({ family: 'ubuntu', pattern: /^ubuntu:(?:18\.04|20\.04|bionic|focal)(?:[.-]|$)/i, eolDate: '2025-05-31', replacement: 'cgr.dev/chainguard/wolfi-base:latest@sha256:' + 'e'.repeat(64) })
]);

/**
 * Resuelve dinámicamente la ruta a `base-image-hardener.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'base-image-hardener.json')
    : path.join(base, 'data', 'base-image-hardener.json');
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
 * Carga auditorías desde disco (sin mutar si no existe).
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
 * Comprueba si una imagen base está en el catálogo EOL.
 * @param {string} imageRef
 */
function matchEolBase(imageRef) {
  const clean = String(imageRef || '')
    .trim()
    .replace(/^docker\.io\/(?:library\/)?/i, '')
    .split('@')[0];
  for (const entry of EOL_BASE_CATALOG) {
    if (entry.pattern.test(clean)) return entry;
  }
  return null;
}

/**
 * Sugiere la imagen Distroless/Wolfi recomendada según el base image original.
 * @param {string} imageRef
 */
function suggestHardenedBase(imageRef) {
  const lower = String(imageRef || '').toLowerCase();
  if (lower.includes('python')) return 'gcr.io/distroless/python3-debian12:nonroot';
  if (lower.includes('golang') || lower.includes('go:')) return 'gcr.io/distroless/static-debian12:nonroot';
  if (lower.includes('node')) return 'cgr.dev/chainguard/node:latest';
  return 'cgr.dev/chainguard/wolfi-base:latest';
}

/**
 * Audita un Dockerfile para bases EOL, `USER root`, etiquetas sin digest `@sha256:` y rootfs escribible.
 *
 * @param {{
 *   projectId?: string,
 *   dockerfile?: string,
 *   trivySummary?: { criticalOsCves?: number, highOsCves?: number, osCves?: any[] } | null,
 *   readOnlyRootfs?: boolean,
 *   persist?: boolean
 * }} [input]
 */
function auditDockerfileHardening(input = {}) {
  const opts = input || {};
  const projectId = opts.projectId ? String(opts.projectId).trim() : null;
  const dockerfile = typeof opts.dockerfile === 'string' ? opts.dockerfile : '';
  const readOnlyRootfs = opts.readOnlyRootfs !== undefined ? Boolean(opts.readOnlyRootfs) : true;
  const lines = dockerfile.split(/\r?\n/);

  /** @type {Array<{ fromLine: number, baseImage: string, alias: string | null, user: string | null }>} */
  const stages = [];
  /** @type {Set<string>} */
  const stageAliases = new Set();

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].trim();
    if (!raw || raw.startsWith('#')) continue;
    const fromMatch = raw.match(/^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i);
    if (fromMatch) {
      const baseImage = fromMatch[1];
      const alias = fromMatch[2] || null;
      if (alias) stageAliases.add(alias.toLowerCase());
      stages.push({ fromLine: i + 1, baseImage, alias, user: null });
      continue;
    }
    const userMatch = raw.match(/^USER\s+(\S+)/i);
    if (userMatch && stages.length > 0) {
      stages[stages.length - 1].user = userMatch[1];
    }
  }

  /** @type {Array<{ code: string, severity: 'critical' | 'high' | 'medium', line: number | null, message: string, fix: string }>} */
  const findings = [];
  /** @type {string} */
  let recommendedBase = 'cgr.dev/chainguard/wolfi-base:latest';

  for (const st of stages) {
    const baseLower = st.baseImage.toLowerCase();
    if (baseLower === 'scratch' || stageAliases.has(baseLower)) continue;

    // 1. EOL_BASE_IMAGE
    const eol = matchEolBase(st.baseImage);
    if (eol) {
      recommendedBase = eol.replacement;
      findings.push({
        code: 'EOL_BASE_IMAGE',
        severity: 'critical',
        line: st.fromLine,
        message: `Base image "${st.baseImage}" reached End-of-Life (${eol.eolDate}) and no longer receives upstream security patches.`,
        fix: `Migrate to digest-pinned ${eol.replacement} or apply CNCF copa thin OS patching immediately.`
      });
    }

    // 2. UNPINNED_BASE_TAG
    if (!DIGEST_PIN_RE.test(st.baseImage)) {
      findings.push({
        code: 'UNPINNED_BASE_TAG',
        severity: 'high',
        line: st.fromLine,
        message: `Base image "${st.baseImage}" is not pinned to an immutable @sha256:<64hex> digest.`,
        fix: 'Pin every FROM reference to @sha256:<64hex> to guarantee reproducible, tamper-proof builds.'
      });
    }
  }

  const finalStage = stages.length > 0 ? stages[stages.length - 1] : null;
  const finalBaseImage = finalStage ? finalStage.baseImage : '';
  if (finalStage && !matchEolBase(finalBaseImage)) {
    recommendedBase = suggestHardenedBase(finalBaseImage);
  }

  // 3. ROOT_USER_FINAL_STAGE
  if (finalStage) {
    const u = String(finalStage.user || '').trim().toLowerCase();
    const isExplicitRoot = u === 'root' || u === '0' || u.startsWith('0:') || u.startsWith('root:');
    const baseImplicitNonRoot = /:nonroot(?:@|$)/i.test(finalStage.baseImage)
      || finalStage.baseImage.toLowerCase().startsWith('cgr.dev/chainguard/')
      || finalStage.baseImage.toLowerCase() === 'scratch';
    if (isExplicitRoot || (!u && !baseImplicitNonRoot)) {
      findings.push({
        code: 'ROOT_USER_FINAL_STAGE',
        severity: 'critical',
        line: finalStage.fromLine,
        message: `Final runtime stage (${finalStage.baseImage}) runs as root (USER ${finalStage.user || 'root (default)'}).`,
        fix: 'Add `USER 65532` (nonroot) or switch to a `:nonroot` Distroless/Wolfi runtime base.'
      });
    }
  }

  // 4. WRITABLE_ROOTFS_RISK
  if (!readOnlyRootfs) {
    findings.push({
      code: 'WRITABLE_ROOTFS_RISK',
      severity: 'medium',
      line: null,
      message: 'Container root filesystem is writable (`readOnlyRootfs: false`), permitting runtime dropper persistence.',
      fix: 'Enable `read_only: true` in Compose/Docker run and mount ephemeral `/tmp` as `tmpfs: /tmp:noexec,nosuid`.'
    });
  }

  // Optional Trivy summary check
  let osCveCount = 0;
  if (opts.trivySummary && typeof opts.trivySummary === 'object') {
    osCveCount = (Number(opts.trivySummary.criticalOsCves) || 0)
      + (Number(opts.trivySummary.highOsCves) || 0)
      + (Array.isArray(opts.trivySummary.osCves) ? opts.trivySummary.osCves.length : 0);
  }

  const recommendedDockerfile = [
    `# Hardened Multi-Stage Distroless/Wolfi Dockerfile (read_only: true, UID 65532)`,
    `FROM ${recommendedBase}`,
    'WORKDIR /app',
    'COPY --chown=65532:65532 dist/ ./dist/',
    'USER 65532:65532',
    'EXPOSE 3000',
    'ENTRYPOINT ["node", "dist/server.js"]'
  ].join('\n');

  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const safe = findings.length === 0;
  const blocked = !safe;
  const status = criticalCount > 0 ? 'CRITICAL' : (findings.length > 0 ? 'WARNING' : 'HARDENED');
  const auditedAt = new Date().toISOString();

  const result = {
    ok: true,
    id: `hard_${crypto.randomBytes(5).toString('hex')}`,
    projectId,
    safe,
    blocked,
    status,
    finalBaseImage,
    osCveCount,
    findings,
    findingCodes: findings.map((f) => f.code),
    recommendedBase,
    recommendedDockerfile,
    auditedAt
  };

  if (opts.persist !== false && projectId) {
    const store = loadStore();
    store.audits.push({
      id: result.id,
      projectId,
      safe,
      status,
      finalBaseImage,
      findingCodes: result.findingCodes,
      osCveCount,
      auditedAt
    });
    saveStore(store);
  }

  return result;
}

/**
 * Planifica un parche fino de capas OS con CNCF `project-copacetic/copa` sin rebuild completo
 * (devolviendo `copaCommandArgv` 100% `shell: false`, `dryRun: true` por defecto).
 *
 * @param {{
 *   imageRef: string,
 *   osCves?: any[],
 *   reportPath?: string,
 *   patchedTag?: string,
 *   dryRun?: boolean
 * }} input
 */
function planCopaThinPatch(input) {
  const opts = input || /** @type {any} */ ({});
  const imageRef = String(opts.imageRef || 'app:latest').trim() || 'app:latest';
  const osCves = Array.isArray(opts.osCves) ? opts.osCves : [];
  const reportPath = String(opts.reportPath || 'trivy-os-report.json').trim() || 'trivy-os-report.json';
  const dryRun = opts.dryRun !== undefined ? Boolean(opts.dryRun) : true;

  const baseName = imageRef.split('@')[0].split(':')[0];
  const patchedTag = String(opts.patchedTag || `${baseName}:copa-patched`).trim();

  const copaCommandArgv = [
    'copa', 'patch',
    '-i', imageRef,
    '-r', reportPath,
    '-t', patchedTag,
    '--timeout', '5m'
  ];

  return {
    ok: true,
    dryRun,
    imageRef,
    patchedTag,
    osCveCount: osCves.length,
    patchableCves: osCves.map((c) => (typeof c === 'string' ? c : String((c && (c.id || c.cve)) || 'CVE'))),
    fullRebuildRequired: false,
    copaCommandArgv,
    plannedAt: new Date().toISOString()
  };
}

/**
 * Lista auditorías de endurecimiento almacenadas (más recientes primero).
 * @param {string} [projectId]
 */
function listHardeningAudits(projectId) {
  const store = loadStore();
  const cleanId = projectId ? String(projectId).trim() : '';
  const items = cleanId
    ? store.audits.filter((a) => a.projectId === cleanId)
    : store.audits;
  return [...items].reverse();
}

module.exports = {
  EOL_BASE_CATALOG,
  auditDockerfileHardening,
  planCopaThinPatch,
  listHardeningAudits
};
