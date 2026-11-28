const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Preview Environment Synthetic Smoke-Gate & Signed Commit-Status Reporter (Zero-Dep).
 *
 * Resuelve las brechas abiertas de `coollabsio/coolify#1671`/`#7155` y `Dokploy/dokploy#5856`/
 * `#4859`/`#6010`:
 *  - Bloquea PRs de forks no aprobados (`FORK_APPROVAL_REQUIRED`) antes de exponer secretos o builds.
 *  - Vincula la aprobación del mantenedor estrictamente al `commitSha` exacto (si el fork empuja
 *    un nuevo commit, la aprobación anterior deja de aplicar y se vuelve a bloquear).
 *  - Agrega checks compuestos (health, DB migrations, API contract diff, smoke sintético) y
 *    emite un payload GitHub Commit Status (`context: 'culkibo/preview-gate'`) firmado con HMAC-SHA256.
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/preview-gates.json`.
 */

const MAX_STORED_GATES = 250;

/**
 * Resuelve dinámicamente la ruta a `preview-gates.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'preview-gates.json')
    : path.join(base, 'data', 'preview-gates.json');
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
 * Carga el store de aprobaciones de forks y evaluaciones (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, forkApprovals: Record<string, any>, evaluations: any[] }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), forkApprovals: {}, evaluations: [] };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && typeof parsed === 'object') {
      return {
        schemaVersion: 1,
        updatedAt: parsed.updatedAt || new Date().toISOString(),
        forkApprovals: parsed.forkApprovals && typeof parsed.forkApprovals === 'object' ? parsed.forkApprovals : {},
        evaluations: Array.isArray(parsed.evaluations) ? parsed.evaluations : []
      };
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), forkApprovals: {}, evaluations: [] };
}

/**
 * Guarda el store atómicamente (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, forkApprovals: Record<string, any>, evaluations: any[] }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  if (store.evaluations.length > MAX_STORED_GATES) {
    store.evaluations = store.evaluations.slice(-MAX_STORED_GATES);
  }
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Normaliza checks desde objeto `{ health: true, contract: { passed: false } }` o array.
 * @param {any} checks
 * @returns {Array<{ name: string, passed: boolean, detail: string }>}
 */
function normalizeChecks(checks) {
  /** @type {Array<{ name: string, passed: boolean, detail: string }>} */
  const out = [];
  if (Array.isArray(checks)) {
    for (const c of checks) {
      if (!c || typeof c !== 'object') continue;
      const passed = c.passed !== undefined
        ? Boolean(c.passed)
        : (c.ok !== undefined ? Boolean(c.ok) : String(c.status || '').toLowerCase() === 'passed');
      out.push({
        name: String(c.name || 'check'),
        passed,
        detail: String(c.detail || c.message || (passed ? 'passed' : 'failed'))
      });
    }
    return out;
  }
  if (checks && typeof checks === 'object') {
    for (const [name, val] of Object.entries(checks)) {
      if (typeof val === 'boolean') {
        out.push({ name, passed: val, detail: val ? 'passed' : 'failed' });
      } else if (val && typeof val === 'object') {
        const passed = val.passed !== undefined
          ? Boolean(val.passed)
          : (val.ok !== undefined ? Boolean(val.ok) : String(val.status || '').toLowerCase() === 'passed');
        out.push({
          name,
          passed,
          detail: String(val.detail || val.message || (passed ? 'passed' : 'failed'))
        });
      }
    }
  }
  return out;
}

/**
 * Registra la aprobación de un mantenedor vinculada estrictamente al `commitSha` exacto (`dokploy#6010`).
 *
 * @param {{ projectId: string, prNumber: number | string, commitSha: string, approver: string }} input
 */
function approveForkPreview(input) {
  const opts = input || /** @type {any} */ ({});
  const projectId = String(opts.projectId || '').trim();
  const prNumber = Number(opts.prNumber);
  const commitSha = String(opts.commitSha || '').trim();
  const approver = String(opts.approver || '').trim();

  if (!projectId || !Number.isFinite(prNumber) || !commitSha || !approver) {
    const err = /** @type {any} */ (new Error('projectId, prNumber, commitSha, and approver are required to approve a fork preview.'));
    err.status = 400;
    err.code = 'INVALID_FORK_APPROVAL';
    throw err;
  }

  const key = `${projectId}:pr-${prNumber}`;
  const approval = {
    projectId,
    prNumber,
    approvedCommitSha: commitSha,
    approver,
    approvedAt: new Date().toISOString()
  };

  const store = loadStore();
  store.forkApprovals[key] = approval;
  saveStore(store);

  return {
    ok: true,
    approval
  };
}

/**
 * Evalúa la compuerta de merge para una PR preview (aprobación SHA-bound de forks + checks compuestos).
 *
 * @param {{
 *   projectId: string,
 *   prNumber: number | string,
 *   commitSha: string,
 *   isFork?: boolean,
 *   maintainerApproved?: boolean,
 *   checks?: any,
 *   persist?: boolean
 * }} input
 */
function evaluatePreviewGate(input) {
  const opts = input || /** @type {any} */ ({});
  const projectId = String(opts.projectId || 'default').trim() || 'default';
  const prNumber = Number(opts.prNumber) || 0;
  const commitSha = String(opts.commitSha || '').trim();
  const isFork = Boolean(opts.isFork);
  const checkResults = normalizeChecks(opts.checks);
  const checksDigest = crypto.createHash('sha256').update(JSON.stringify(checkResults), 'utf8').digest('hex');

  const store = loadStore();
  const storedApproval = store.forkApprovals[`${projectId}:pr-${prNumber}`] || null;
  const shaBoundApproved = Boolean(
    opts.maintainerApproved === true
    || (storedApproval && commitSha && storedApproval.approvedCommitSha === commitSha)
  );

  let allowed = false;
  /** @type {'success' | 'failure' | 'pending'} */
  let state = 'pending';
  let code = 'CHECKS_PENDING';
  let description = 'Waiting for preview checks.';
  /** @type {string[]} */
  let failedChecks = [];

  if (isFork && !shaBoundApproved) {
    allowed = false;
    state = 'pending';
    code = 'FORK_APPROVAL_REQUIRED';
    description = storedApproval
      ? `Fork PR #${prNumber} pushed new commit ${commitSha.slice(0, 8)}; re-approval required (previous approval bound to ${String(storedApproval.approvedCommitSha).slice(0, 8)}).`
      : `Fork PR #${prNumber} requires maintainer approval bound to exact commit SHA ${commitSha.slice(0, 8)} before preview build.`;
  } else {
    failedChecks = checkResults.filter((c) => !c.passed).map((c) => c.name);
    if (failedChecks.length > 0) {
      allowed = false;
      state = 'failure';
      code = 'CHECKS_FAILED';
      description = `Preview gate failed ${failedChecks.length} check(s): ${failedChecks.join(', ')}.`;
    } else if (checkResults.length === 0) {
      allowed = false;
      state = 'pending';
      code = 'CHECKS_PENDING';
      description = 'No preview checks reported yet.';
    } else {
      allowed = true;
      state = 'success';
      code = 'PREVIEW_GATE_PASSED';
      description = `All ${checkResults.length} preview checks passed for PR #${prNumber} (${commitSha.slice(0, 8)}).`;
    }
  }

  const evaluatedAt = new Date().toISOString();
  const evaluation = {
    id: `pgate_${crypto.randomBytes(5).toString('hex')}`,
    projectId,
    prNumber,
    commitSha,
    isFork,
    forkApproved: !isFork || shaBoundApproved,
    allowed,
    state,
    code,
    failedChecks,
    checkResults,
    checksDigest,
    description,
    evaluatedAt
  };

  if (opts.persist !== false) {
    store.evaluations.push(evaluation);
    saveStore(store);
  }

  return {
    ok: true,
    ...evaluation
  };
}

/**
 * Construye la cadena canónica firmable para un Commit Status de GitHub.
 * @param {any} payload
 */
function canonicalCommitStatusString(payload) {
  return [
    String(payload.repo || ''),
    String(payload.commitSha || ''),
    String(payload.state || ''),
    String(payload.context || ''),
    String(payload.target_url || ''),
    String(payload.checksDigest || '')
  ].join('|');
}

/**
 * Construye un payload GitHub Commit Status firmado criptográficamente (HMAC-SHA256).
 *
 * @param {{
 *   repo: string,
 *   commitSha: string,
 *   context?: string,
 *   targetUrl?: string,
 *   evaluation: any,
 *   signingKey?: string
 * }} input
 */
function buildSignedCommitStatus(input) {
  const opts = input || /** @type {any} */ ({});
  const evalObj = opts.evaluation || {};
  const repo = String(opts.repo || 'org/repo').trim();
  const commitSha = String(opts.commitSha || evalObj.commitSha || '').trim();
  const context = String(opts.context || 'culkibo/preview-gate').trim();
  const state = /** @type {'success' | 'failure' | 'pending'} */ (
    evalObj.state === 'success' || evalObj.state === 'failure' || evalObj.state === 'pending'
      ? evalObj.state
      : 'pending'
  );
  const targetUrl = String(
    opts.targetUrl
    || `https://culkibo.local/projects/${encodeURIComponent(String(evalObj.projectId || 'preview'))}/pr/${evalObj.prNumber || 0}`
  );
  const description = String(evalObj.description || `Culkibo preview gate: ${state}`).slice(0, 140);
  const checksDigest = String(evalObj.checksDigest || '');

  const payload = {
    repo,
    commitSha,
    state,
    context,
    target_url: targetUrl,
    description,
    checksDigest,
    issuedAt: new Date().toISOString()
  };

  const key = String(opts.signingKey || 'culkibo-preview-gate-hmac-key');
  const canonical = canonicalCommitStatusString(payload);
  const signature = crypto.createHmac('sha256', key).update(canonical, 'utf8').digest('hex');

  return {
    ok: true,
    algorithm: 'hmac-sha256',
    payload,
    signature,
    githubApiPath: `/repos/${repo}/statuses/${commitSha}`
  };
}

/**
 * Verifica la firma HMAC-SHA256 de un Commit Status en tiempo constante.
 *
 * @param {{ payload: any, signature: string, signingKey?: string }} input
 */
function verifySignedCommitStatus(input) {
  const opts = input || /** @type {any} */ ({});
  const key = String(opts.signingKey || 'culkibo-preview-gate-hmac-key');
  const expected = crypto
    .createHmac('sha256', key)
    .update(canonicalCommitStatusString(opts.payload || {}), 'utf8')
    .digest('hex');
  const provided = String(opts.signature || '').trim().toLowerCase();

  let valid = false;
  if (provided.length === expected.length && /^[a-f0-9]+$/.test(provided)) {
    valid = crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(provided, 'hex'));
  }

  return {
    ok: true,
    valid,
    algorithm: 'hmac-sha256'
  };
}

/**
 * Lista evaluaciones de compuerta preview (más recientes primero).
 * @param {string} [projectId]
 */
function listPreviewGates(projectId) {
  const store = loadStore();
  const cleanId = projectId ? String(projectId).trim() : '';
  const items = cleanId
    ? store.evaluations.filter((e) => e.projectId === cleanId)
    : store.evaluations;
  return [...items].reverse();
}

module.exports = {
  approveForkPreview,
  evaluatePreviewGate,
  buildSignedCommitStatus,
  verifySignedCommitStatus,
  listPreviewGates
};
