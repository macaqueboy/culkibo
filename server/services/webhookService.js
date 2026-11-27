const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const projectManager = require('./projectManager');
const githubService = require('./githubService');
const deployManager = require('./deployManager');
const containerOrchestrator = require('./containerOrchestrator');

/** @type {any} */
let _previewManager = null;
function getPreviewManager() {
  if (!_previewManager) _previewManager = require('./previewManager');
  return _previewManager;
}

/** @type {any} */
let _gitopsManager = null;
function getGitOpsManager() {
  if (!_gitopsManager) _gitopsManager = require('./gitopsManager');
  return _gitopsManager;
}

const ROOT_BASE_DIR = process.env.CULKIBO_DATA_DIR
  ? path.resolve(process.env.CULKIBO_DATA_DIR)
  : path.resolve(__dirname, '..', '..');

/** Comprueba si el push tocó el archivo `culkibo.yaml` (o `project.gitopsManifestPath`) configurado. */
function didChangeGitOpsManifest(project, changedFiles) {
  const mode = String(project?.gitopsAutoSync || 'off').trim().toLowerCase();
  if (mode !== 'plan' && mode !== 'apply') return false;
  if (!Array.isArray(changedFiles) || changedFiles.length === 0) return false;
  const manifestPath = String(project?.gitopsManifestPath || 'culkibo.yaml')
    .trim()
    .replace(/\\/g, '/')
    .replace(/^\/+/, '');
  if (!manifestPath) return false;
  return changedFiles.some((f) => String(f || '').replace(/\\/g, '/').replace(/^\/+/, '') === manifestPath);
}

/** Resuelve el directorio de trabajo local de un proyecto para leer `culkibo.yaml`. */
function resolveProjectRepoDir(project) {
  if (project && typeof project.localPath === 'string' && project.localPath.trim()) {
    const p = path.resolve(project.localPath.trim());
    if (fs.existsSync(p)) return p;
  }
  const cleanId = String(project?.id || '').trim();
  if (cleanId && /^[a-zA-Z0-9_-]{1,80}$/.test(cleanId)) {
    const candidate = path.join(ROOT_BASE_DIR, 'projects', cleanId);
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

/**
 * Motor unificado de webhooks multi-Git (GitHub, GitLab, Gitea/Forgejo, Bitbucket)
 * y Deploy Hook genérico CI/CD.
 *
 * Reglas de seguridad:
 *  - Verificación en tiempo constante (`crypto.timingSafeEqual`) por proyecto:
 *    en un monorepo con varios proyectos compartiendo repo, un proyecto con secreto
 *    válido jamás autoriza a un hermano con secreto distinto.
 *  - Respeta `watchPaths` (si el proyecto declara rutas vigiladas, ignora pushes sin
 *    archivos coincidentes).
 *  - Conecta `pull_request` / Merge Request con `previewManager` (puerta anti-forks).
 */

function timingSafeStrEqual(a, b) {
  const ba = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  if (ba.length === 0 || ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/** Verifica una firma HMAC-SHA256 (acepta con o sin prefijo `sha256=`, insensible a mayúsculas). */
function verifyHmacSha256(rawBuffer, secret, providedSignature) {
  if (!secret || !providedSignature) return false;
  const clean = String(providedSignature).trim().replace(/^sha256=/i, '').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(clean)) return false;
  const expected = crypto.createHmac('sha256', String(secret)).update(rawBuffer).digest('hex');
  return timingSafeStrEqual(expected, clean);
}

/** Extrae el slug canónico `owner/repo` (o `group/sub/repo`) desde cualquier URL Git (incl. `ssh://git@host:2222/org/repo.git`). */
function normalizeRepoSlug(raw) {
  const s = String(raw || '').trim().toLowerCase();
  if (!s) return '';
  return s
    .replace(/^(?:https?|ssh|git):\/\/(?:[^@/\s]+@)?[^/\s]+\//, '')
    .replace(/^git@[^:\s]+:/, '')
    .replace(/\.git$/, '')
    .replace(/^\/+|\/+$/g, '');
}

const SKIP_CI_RE = /\[(skip ci|ci skip|skip cd|cd skip|no ci|culkibo skip)\]/i;
const WEBHOOK_MAX_REPLAY_AGE_SEC = 300;

/**
 * Redacta secretos, tokens de deploy hook y cabeceras de autorización de mensajes/errores de webhook
 * sin filtrar jamás prefijos ni fragmentos de tokens (cura dokploy#4898).
 *
 * @param {any} input
 * @param {string[]} [extraSecrets]
 * @returns {string}
 */
function redactWebhookSecrets(input, extraSecrets = []) {
  let out = String(input == null ? '' : input);
  if (!out) return '';
  for (const raw of extraSecrets) {
    if (typeof raw === 'string' && raw.length >= 6) {
      out = out.split(raw).join('[REDACTED]');
    }
  }
  out = out
    .replace(/\b(?:ckh|cks|ckt|ckp|whsec|ghp|gho|ghu|ghs|ghr|glpat|sk_live|sk_test|pk_live|xox[baprs])_[A-Za-z0-9._-]{4,}\b/gi, '[REDACTED]')
    .replace(/\b(?:glpat|github_pat|npm)-[A-Za-z0-9._-]{6,}\b/gi, '[REDACTED]')
    .replace(/(Authorization\s*:\s*Bearer\s+)[^\s'",;]+/gi, '$1[REDACTED]')
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, '$1[REDACTED]')
    .replace(/((?:token|secret|password|x-gitlab-token|x-deploy-token)\s*[:=]\s*)['"]?[^\s'",;&}]+['"]?/gi, '$1[REDACTED]');
  return out;
}

/**
 * Valida la ventana opcional de marca temporal anti-replay (`<= 300 s`) en webhooks.
 * - Si no viene cabecera ni campo `timestamp`, devuelve `{ valid: true, skipped: true }`
 *   para mantener compatibilidad total con proveedores que no firman timestamps.
 * - Si viene `x-webhook-timestamp` / `x-gitlab-event-timestamp` / `x-culkibo-timestamp` /
 *   `body.timestamp`, rechaza cualquier entrega con desfase superior a `maxAgeSec` (por defecto 300 s)
 *   con código `401 WEBHOOK_REPLAY_EXPIRED`.
 *
 * @param {any} reqOrHeaders
 * @param {{ maxAgeSec?: number, nowMs?: number, body?: any }} [opts]
 */
function validateWebhookTimestamp(reqOrHeaders, opts = {}) {
  const headers = reqOrHeaders && reqOrHeaders.headers ? reqOrHeaders.headers : (reqOrHeaders || {});
  const body = opts.body !== undefined ? opts.body : (reqOrHeaders && reqOrHeaders.body ? reqOrHeaders.body : null);
  const rawTs = headers['x-webhook-timestamp']
    ?? headers['x-gitlab-event-timestamp']
    ?? headers['x-culkibo-timestamp']
    ?? headers['x-timestamp']
    ?? (body && typeof body === 'object' ? body.timestamp : undefined);

  if (rawTs === undefined || rawTs === null || String(rawTs).trim() === '') {
    return { valid: true, skipped: true, status: 200, code: null, error: null, ageSec: 0 };
  }

  const maxAgeSec = Number.isFinite(Number(opts.maxAgeSec)) && Number(opts.maxAgeSec) > 0
    ? Number(opts.maxAgeSec)
    : WEBHOOK_MAX_REPLAY_AGE_SEC;
  const nowMs = opts.nowMs != null && Number.isFinite(Number(opts.nowMs)) ? Number(opts.nowMs) : Date.now();

  let tsMs = NaN;
  const str = String(rawTs).trim();
  if (/^\d+(?:\.\d+)?$/.test(str)) {
    const num = Number(str);
    // Unix segundos (<= 1e11) vs milisegundos (> 1e11)
    tsMs = num < 1e11 ? Math.round(num * 1000) : Math.round(num);
  } else {
    tsMs = Date.parse(str);
  }

  if (!Number.isFinite(tsMs) || tsMs <= 0) {
    return {
      valid: false,
      skipped: false,
      status: 401,
      code: 'WEBHOOK_REPLAY_EXPIRED',
      error: 'Marca temporal de webhook inválida o malformada',
      ageSec: null
    };
  }

  const driftMs = Math.abs(nowMs - tsMs);
  const ageSec = Math.round(driftMs / 1000);
  if (driftMs > maxAgeSec * 1000) {
    return {
      valid: false,
      skipped: false,
      status: 401,
      code: 'WEBHOOK_REPLAY_EXPIRED',
      error: `Webhook expirado o fuera de ventana anti-replay (${ageSec}s > ${maxAgeSec}s)`,
      ageSec
    };
  }

  return {
    valid: true,
    skipped: false,
    status: 200,
    code: null,
    error: null,
    timestampMs: tsMs,
    ageSec
  };
}

/** Convierte un patrón glob sencillo (`*`, `**`) a RegExp sin dependencias ni ReDoS. */
function compileWatchGlob(pattern) {
  let out = '^';
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === '*') {
      if (pattern[i + 1] === '*') {
        if (pattern[i + 2] === '/') {
          out += '(?:.*/)?';
          i += 2;
        } else {
          out += '.*';
          i += 1;
        }
      } else {
        out += '[^/]*';
      }
    } else if (/[.+?^${}()|[\]\\]/.test(ch)) {
      out += `\\${ch}`;
    } else {
      out += ch;
    }
  }
  out += '$';
  return new RegExp(out);
}

/** Comprueba si una lista de ficheros tocados en el push intersecta `project.watchPaths`. */
function matchesWatchPaths(watchPaths, changedFiles) {
  if (!Array.isArray(watchPaths) || watchPaths.length === 0) return true;
  if (!Array.isArray(changedFiles) || changedFiles.length === 0) return true;
  const normalizedWatch = watchPaths
    .map((p) => String(p || '').trim().replace(/^\/+|\/+$/g, ''))
    .filter(Boolean);
  if (normalizedWatch.length === 0) return true;
  const compiled = normalizedWatch.map((w) => ({
    raw: w,
    re: w.includes('*') ? compileWatchGlob(w) : null
  }));
  return changedFiles.some((f) => {
    const cleanFile = String(f || '').replace(/^\/+/, '');
    return compiled.some(({ raw, re }) => {
      if (re) return re.test(cleanFile);
      return cleanFile === raw || cleanFile.startsWith(`${raw}/`);
    });
  });
}

/**
 * Busca proyectos que coincidan por `projectId` explícito o por slug de repositorio exacto.
 * @param {{ queryProjectId?: string | null, repoUrls?: Array<string | null | undefined> }} [opts]
 */
function resolveMatchingProjects({ queryProjectId = null, repoUrls = [] } = {}) {
  if (queryProjectId) {
    const p = projectManager.getById(String(queryProjectId));
    return p ? [p] : [];
  }
  const slugs = new Set(repoUrls.map(normalizeRepoSlug).filter(Boolean));
  if (slugs.size === 0) return [];
  return projectManager.getAll().filter((p) => {
    const pSlug = normalizeRepoSlug(p.gitRepo);
    return pSlug && slugs.has(pSlug);
  });
}

/**
 * Despacha un push ya autenticado para uno o varios proyectos del mismo repo.
 */
async function dispatchPush({
  provider,
  projects,
  branch,
  commitSha,
  commitMsg,
  author,
  deliveryId = null,
  changedFiles = [],
  manifestYaml = null,
  gitopsManager = null,
  awaitSync = false,
  failOnDeployError = false
}) {
  const shortSha = String(commitSha || `c_${Date.now().toString(36)}`).slice(0, 7);
  const now = new Date().toISOString();
  const label = provider.charAt(0).toUpperCase() + provider.slice(1);

  if (commitMsg && SKIP_CI_RE.test(String(commitMsg))) {
    return {
      status: 200,
      body: {
        success: true,
        deployed: false,
        skipped: true,
        reason: 'Commit marcado con [skip ci] / [ci skip]'
      }
    };
  }

  const branchProjects = projects.filter((p) => (p.gitBranch || 'main') === branch);
  if (branchProjects.length === 0) {
    const first = projects[0];
    const configuredBranch = first.gitBranch || 'main';
    containerOrchestrator.addLog('INFO', 'citadel', `[${label}:Webhook] Push ignorado en rama '${branch}'. El proyecto '${first.name}' escucha '${configuredBranch}'.`, new Date(), first.id);
    return {
      status: 200,
      body: {
        success: true,
        deployed: false,
        reason: `Rama '${branch}' no coincide con la rama configurada '${configuredBranch}'`
      }
    };
  }

  const eligibleProjects = branchProjects.filter((p) => p.autoDeploy !== false || didChangeGitOpsManifest(p, changedFiles));
  if (eligibleProjects.length === 0) {
    containerOrchestrator.addLog('INFO', 'citadel', `[${label}:Webhook] Push recibido pero el auto-despliegue está deshabilitado para '${branchProjects[0].name}'.`, new Date(), branchProjects[0].id);
    return {
      status: 200,
      body: {
        success: true,
        deployed: false,
        reason: 'Auto-despliegue deshabilitado para este proyecto'
      }
    };
  }

  const pathEligible = eligibleProjects.filter((p) => matchesWatchPaths(p.watchPaths, changedFiles) || didChangeGitOpsManifest(p, changedFiles));
  if (pathEligible.length === 0) {
    containerOrchestrator.addLog('INFO', 'citadel', `[${label}:Webhook] Push ignorado (${shortSha}): ningún archivo coincide con watchPaths.`, new Date(), eligibleProjects[0].id);
    return {
      status: 200,
      body: {
        success: true,
        deployed: false,
        reason: 'Sin cambios en las rutas vigiladas (watchPaths)'
      }
    };
  }

  const dockerProbe = await deployManager.detectDocker({ force: true });
  /** @type {any[]} */
  const dispatched = [];
  let allDuplicates = true;
  /** @type {string | null} */
  let lastDupReason = null;

  for (const target of pathEligible) {
    const claim = githubService.claimDelivery(target.id, { deliveryId, commitSha });
    if (!claim.fresh) {
      lastDupReason = claim.reason;
      containerOrchestrator.addLog('INFO', 'citadel', `[${label}:Webhook] ${claim.reason} (${shortSha}); no se relanza el despliegue.`, new Date(), target.id);
      continue;
    }
    allDuplicates = false;

    // GitOps auto-plan / non-destructive reconcile cuando el push modifica `culkibo.yaml` (opt-in por proyecto)
    /** @type {any} */
    let gitopsResult = null;
    if (didChangeGitOpsManifest(target, changedFiles)) {
      try {
        const gm = gitopsManager || getGitOpsManager();
        const repoDir = resolveProjectRepoDir(target);
        gitopsResult = await gm.reconcileWebhookManifest({
          project: target,
          yamlText: typeof manifestYaml === 'string' ? manifestYaml : null,
          repoDir,
          manifestPath: target.gitopsManifestPath || 'culkibo.yaml',
          provider,
          commitSha,
          branch,
          actor: `webhook:${provider}`
        });
        containerOrchestrator.addLog(
          'INFO',
          'citadel',
          `[${label}:GitOps] ${gitopsResult.mode === 'apply' ? 'Reconciliado' : 'Plan calculado'} para ${target.name} (${shortSha}) · prune=false`,
          new Date(),
          target.id
        );
      } catch (gitopsErr) {
        gitopsResult = { ok: false, error: gitopsErr.message || String(gitopsErr) };
        containerOrchestrator.addLog('WARN', 'citadel', `[${label}:GitOps] Error procesando culkibo.yaml para ${target.name}: ${gitopsResult.error}`, new Date(), target.id);
      }
    }

    const repoName = target.gitRepo || target.name;
    containerOrchestrator.addLog('INFO', 'citadel', `[${label}:Webhook] Push recibido en ${repoName} (${branch}) por ${author}: "${String(commitMsg || '').trim()}" (${shortSha})`, new Date(), target.id);

    /** @type {{ dispatched: boolean, queued: boolean, failed?: boolean, blocked?: boolean, code?: string | null, reason: string | null }} */
    let pipeline = { dispatched: false, queued: false, failed: false, blocked: false, code: null, reason: null };
    const projectSecrets = [target.webhookSecret, target.deployHookToken].filter(Boolean);
    if (target.autoDeploy === false) {
      pipeline.reason = 'autoDeploy deshabilitado (solo GitOps ejecutado)';
    } else if (!target.gitRepo) {
      pipeline.reason = 'El proyecto no tiene repositorio configurado';
    } else if (!dockerProbe.available) {
      pipeline.reason = redactWebhookSecrets(dockerProbe.reason, projectSecrets);
    } else {
      containerOrchestrator.addLog('INFO', 'citadel', `[Citadel:Deploy] Iniciando despliegue automatizado para ${target.name}...`, new Date(), target.id);
      try {
        const started = deployManager.enqueue(target, {
          commit: /^[0-9a-f]{7,40}$/i.test(String(commitSha || '')) ? String(commitSha) : null,
          version: `${provider.slice(0, 2)}-${shortSha}`,
          trigger: 'webhook'
        });
        if (started && started.blocked) {
          pipeline = {
            dispatched: false,
            queued: false,
            failed: true,
            blocked: true,
            code: started.code || 'DEPLOY_FROZEN',
            reason: redactWebhookSecrets(started.reason || 'Despliegue bloqueado por ventana de congelación', projectSecrets)
          };
        } else if (awaitSync && started && started.promise) {
          try {
            const depResult = await started.promise;
            const depFailed = !depResult || depResult.status === 'fallido' || depResult.ok === false;
            pipeline = {
              dispatched: !depFailed,
              queued: false,
              failed: depFailed,
              blocked: false,
              code: depFailed ? 'DEPLOY_FAILED' : null,
              reason: depFailed ? redactWebhookSecrets(depResult?.error || 'El despliegue síncrono falló', projectSecrets) : null
            };
          } catch (syncErr) {
            /** @type {any} */
            const se = syncErr;
            pipeline = {
              dispatched: false,
              queued: false,
              failed: true,
              blocked: false,
              code: (se && se.code) || 'DEPLOY_FAILED',
              reason: redactWebhookSecrets((se && se.message) || String(syncErr), projectSecrets)
            };
          }
        } else {
          pipeline = { dispatched: Boolean(started.started), queued: Boolean(started.queued), failed: false, blocked: false, code: null, reason: null };
        }
      } catch (err) {
        /** @type {any} */
        const e = err;
        pipeline = {
          dispatched: false,
          queued: false,
          failed: true,
          blocked: false,
          code: (e && e.code) || 'DEPLOY_FAILED',
          reason: redactWebhookSecrets((e && e.message) || String(err), projectSecrets)
        };
      }
    }

    if (pipeline.reason && target.autoDeploy !== false) {
      containerOrchestrator.addLog('WARN', 'citadel', `[Citadel:Deploy] No se lanza la construcción de imagen: ${redactWebhookSecrets(pipeline.reason, projectSecrets)}.`, new Date(), target.id);
    } else if (pipeline.queued) {
      containerOrchestrator.addLog('INFO', 'citadel', `[Citadel:Deploy] Ya hay un despliegue en curso; ${shortSha} queda en cola y se construirá al terminar.`, new Date(), target.id);
    }

    const lastCommit = {
      sha: shortSha,
      message: String(commitMsg || 'Push automático').trim(),
      author: String(author || label),
      timestamp: now
    };
    if (projectManager.getById(target.id)) {
      projectManager.update(target.id, { lastDeployedAt: now, lastCommit });
    }

    containerOrchestrator.emit('github_deploy', {
      provider,
      projectId: target.id,
      projectName: target.name,
      branch,
      commit: shortSha,
      author: lastCommit.author,
      message: lastCommit.message,
      timestamp: now,
      ...(gitopsResult ? { gitops: gitopsResult } : {})
    });

    containerOrchestrator.addLog(
      pipeline.failed ? 'ERROR' : 'SUCCESS',
      'citadel',
      pipeline.failed
        ? `[${label}:Webhook] Despliegue fallido para ${target.name} (${shortSha}): ${redactWebhookSecrets(pipeline.reason || 'error desconocido', projectSecrets)}`
        : (pipeline.dispatched || pipeline.queued
          ? `[${label}:Webhook] Despliegue en curso para ${target.name} (${shortSha}); sigue el progreso en la pestaña Despliegues.`
          : `[${label}:Webhook] Push procesado para ${target.name} (${shortSha})`),
      new Date(),
      target.id
    );

    dispatched.push({
      projectId: target.id,
      pipeline: pipeline.failed ? 'failed' : (pipeline.dispatched ? 'building' : pipeline.queued ? 'queued' : 'registro'),
      pipelineReason: pipeline.reason,
      ...(pipeline.code ? { code: pipeline.code } : {}),
      ...(gitopsResult ? { gitops: gitopsResult } : {})
    });
  }

  if (allDuplicates) {
    return {
      status: 200,
      body: {
        success: true,
        deployed: false,
        duplicate: true,
        projectId: pathEligible[0].id,
        commit: shortSha,
        reason: lastDupReason || 'Entrega duplicada'
      }
    };
  }

  const primary = dispatched[0];
  const anyFailed = dispatched.some((d) => d.pipeline === 'failed');
  if (anyFailed && (awaitSync || failOnDeployError)) {
    const failedEntry = dispatched.find((d) => d.pipeline === 'failed') || primary;
    const isFrozen = failedEntry && failedEntry.code === 'DEPLOY_FROZEN';
    return {
      status: isFrozen ? 423 : 502,
      body: {
        success: false,
        deployed: false,
        code: (failedEntry && failedEntry.code) || 'DEPLOY_FAILED',
        error: redactWebhookSecrets((failedEntry && failedEntry.pipelineReason) || 'El despliegue disparado por webhook falló'),
        provider,
        projectId: primary.projectId,
        matchedProjects: dispatched.length,
        dispatched,
        branch,
        commit: shortSha
      }
    };
  }

  return {
    status: 200,
    body: {
      success: true,
      deployed: true,
      provider,
      projectId: primary.projectId,
      matchedProjects: dispatched.length,
      dispatched,
      branch,
      commit: shortSha,
      author: String(author || label),
      message: String(commitMsg || '').trim()
    }
  };
}

/**
 * Despacha eventos de Pull Request / Merge Request hacia Preview Deployments.
 * - Deduplicación por `githubService.claimDelivery` (evita builds dobles en reintentos).
 * - Ejecución asíncrona no bloqueante por defecto (responde HTTP 202 al instante para
 *   no agotar el timeout de 10 s de GitHub/GitLab webhooks).
 */
async function dispatchPullRequest({
  provider,
  projects,
  action,
  prNumber,
  branch,
  commitSha = null,
  isFork = false,
  deliveryId = null,
  awaitCompletion = false,
  previewManager: previewMgrOverride = null
}) {
  const pm = previewMgrOverride || getPreviewManager();
  /** @type {any[]} */
  const results = [];
  let queuedCount = 0;

  for (const project of projects) {
    const cfg = project.previewDeployments || {};
    if (!cfg.enabled) {
      results.push({ projectId: project.id, action: 'skipped', reason: 'previews_disabled' });
      continue;
    }

    const isDestroy = action === 'closed' || action === 'merged';
    const isDeploy = action === 'opened' || action === 'synchronize' || action === 'reopened' || action === 'update';
    if (!isDestroy && !isDeploy) {
      results.push({ projectId: project.id, action: 'ignored', reason: `action_${action}` });
      continue;
    }

    if (isDeploy && isFork && !cfg.allowForks) {
      containerOrchestrator.addLog('WARN', 'citadel', `[${provider}:Preview] PR #${prNumber} desde fork bloqueada por seguridad (allowForks=false).`, new Date(), project.id);
      results.push({ projectId: project.id, action: 'blocked', reason: 'fork_pr_blocked' });
      continue;
    }

    // Deduplicación fail-safe por entrega PR (deliveryId explícito o tupla PR+acción+SHA)
    const effectiveDeliveryId = deliveryId
      ? `pr:${String(deliveryId).slice(0, 80)}`
      : `pr:${prNumber ?? branch}:${action}:${commitSha ? String(commitSha).slice(0, 16) : 'head'}`;
    const claim = githubService.claimDelivery(project.id, { deliveryId: effectiveDeliveryId });
    if (!claim.fresh) {
      containerOrchestrator.addLog('INFO', 'citadel', `[${provider}:Preview] ${claim.reason} (PR #${prNumber}); entrega ignorada.`, new Date(), project.id);
      results.push({ projectId: project.id, action: 'duplicate_skipped', duplicate: true, reason: claim.reason });
      continue;
    }

    if (isDestroy) {
      if (awaitCompletion) {
        try {
          const res = await pm.destroyPreview(project.id, { prNumber, branch });
          results.push({ projectId: project.id, action: 'destroyed', ...res });
        } catch (e) {
          results.push({ projectId: project.id, action: 'destroy_skipped', reason: e.message });
        }
      } else {
        queuedCount++;
        Promise.resolve()
          .then(() => pm.destroyPreview(project.id, { prNumber, branch }))
          .catch((e) => {
            containerOrchestrator.addLog('WARN', 'citadel', `[${provider}:Preview] Error destruyendo preview PR #${prNumber}: ${e && e.message ? e.message : String(e)}`, new Date(), project.id);
          });
        results.push({ projectId: project.id, action: 'destroy_queued', async: true, prNumber, branch });
      }
    } else if (isDeploy) {
      if (awaitCompletion) {
        try {
          const res = await pm.deployPreview(project, { prNumber, branch, commit: commitSha, isFork });
          results.push({ projectId: project.id, action: 'preview_deployed', preview: res });
        } catch (e) {
          results.push({
            projectId: project.id,
            action: 'preview_error',
            error: redactWebhookSecrets(e && e.message ? e.message : String(e), [project.webhookSecret, project.deployHookToken].filter(Boolean))
          });
        }
      } else {
        queuedCount++;
        Promise.resolve()
          .then(() => pm.deployPreview(project, { prNumber, branch, commit: commitSha, isFork }))
          .catch((e) => {
            containerOrchestrator.addLog('WARN', 'citadel', `[${provider}:Preview] Error desplegando preview PR #${prNumber}: ${redactWebhookSecrets(e && e.message ? e.message : String(e), [project.webhookSecret, project.deployHookToken].filter(Boolean))}`, new Date(), project.id);
          });
        results.push({ projectId: project.id, action: 'preview_queued', async: true, prNumber, branch });
      }
    }
  }

  const allPreviewErrored = Boolean(awaitCompletion && results.length > 0 && results.every((r) => r.action === 'preview_error'));
  if (allPreviewErrored) {
    return {
      status: 502,
      body: {
        success: false,
        code: 'PREVIEW_DEPLOY_FAILED',
        error: results[0].error || 'El despliegue de vista previa falló',
        provider,
        event: 'pull_request',
        prNumber,
        branch,
        queued: 0,
        results
      }
    };
  }

  return {
    status: queuedCount > 0 ? 202 : 200,
    body: {
      success: true,
      provider,
      event: 'pull_request',
      prNumber,
      branch,
      queued: queuedCount,
      results
    }
  };
}

/**
 * GitLab Webhook (`POST /api/webhooks/gitlab`) — autenticado con `X-Gitlab-Token`.
 */
async function handleGitLabWebhook(req) {
  const token = String(req.headers['x-gitlab-token'] || '');
  const event = String(req.headers['x-gitlab-event'] || '');
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const queryProjectId = req.query?.projectId || null;

  const matched = resolveMatchingProjects({
    queryProjectId,
    repoUrls: [
      body?.project?.git_http_url,
      body?.project?.http_url,
      body?.project?.git_ssh_url,
      body?.project?.path_with_namespace
    ]
  });

  if (matched.length === 0) {
    return { status: 404, body: { error: 'No se encontró un proyecto asociado a este repositorio de GitLab' } };
  }

  // Filtrar estrictamente sólo los proyectos cuyo webhookSecret coincida con X-Gitlab-Token
  const authorized = matched.filter((p) => p.webhookSecret && timingSafeStrEqual(p.webhookSecret, token));
  if (authorized.length === 0) {
    return { status: 401, body: { error: 'X-Gitlab-Token ausente o inválido para los proyectos coincidentes' } };
  }

  const tsCheck = validateWebhookTimestamp(req);
  if (!tsCheck.valid) {
    return { status: 401, body: { success: false, code: tsCheck.code, error: tsCheck.error } };
  }

  if (event === 'Merge Request Hook' || body.object_kind === 'merge_request') {
    const attrs = body.object_attributes || {};
    const actionMap = { merge: 'merged', close: 'closed', open: 'opened', reopen: 'reopened', update: 'update' };
    const mrAction = actionMap[String(attrs.action || '').toLowerCase()] || null;
    if (!mrAction) {
      return { status: 200, body: { success: true, ignored: true, reason: `Acción MR '${attrs.action || ''}' ignorada` } };
    }
    // Fail-closed: si falta source_project_id o target_project_id, tratar como fork
    const isFork = !attrs.source_project_id || !attrs.target_project_id || attrs.source_project_id !== attrs.target_project_id;
    return dispatchPullRequest({
      provider: 'gitlab',
      projects: authorized,
      action: mrAction,
      prNumber: attrs.iid || attrs.id,
      branch: attrs.source_branch || '',
      commitSha: attrs.last_commit?.id || null,
      isFork,
      deliveryId: req.headers['x-gitlab-event-uuid'] || null
    });
  }

  if (event === 'Push Hook' || body.object_kind === 'push') {
    if (body.after === '0000000000000000000000000000000000000000') {
      return { status: 200, body: { success: true, deployed: false, reason: 'Eliminación de rama ignorada' } };
    }
    const ref = String(body.ref || '');
    const branch = ref.replace(/^refs\/heads\//, '');
    const commits = Array.isArray(body.commits) ? body.commits : [];
    const lastCommit = commits[commits.length - 1] || {};
    const changedFiles = commits.flatMap((c) => [...(c.added || []), ...(c.modified || []), ...(c.removed || [])]);
    return dispatchPush({
      provider: 'gitlab',
      projects: authorized,
      branch,
      commitSha: body.checkout_sha || body.after || lastCommit.id,
      commitMsg: lastCommit.message || 'Push desde GitLab',
      author: body.user_name || lastCommit.author?.name || 'GitLab',
      deliveryId: req.headers['x-gitlab-event-uuid'] || null,
      changedFiles
    });
  }

  return { status: 200, body: { success: true, ignored: true, event } };
}

/**
 * Gitea / Forgejo Webhook (`POST /api/webhooks/gitea`) — autenticado con HMAC SHA-256.
 */
async function handleGiteaWebhook(req) {
  const sig = String(req.headers['x-gitea-signature'] || req.headers['x-forgejo-signature'] || req.headers['x-hub-signature-256'] || '');
  const event = String(req.headers['x-gitea-event'] || req.headers['x-forgejo-event'] || req.headers['x-github-event'] || 'push');
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const rawBody = req.rawBody || Buffer.from(JSON.stringify(body));
  const queryProjectId = req.query?.projectId || null;

  const matched = resolveMatchingProjects({
    queryProjectId,
    repoUrls: [body?.repository?.clone_url, body?.repository?.html_url, body?.repository?.full_name]
  });
  if (matched.length === 0) {
    return { status: 404, body: { error: 'No se encontró un proyecto asociado a este repositorio de Gitea/Forgejo' } };
  }

  const authorized = matched.filter((p) => p.webhookSecret && verifyHmacSha256(rawBody, p.webhookSecret, sig));
  if (authorized.length === 0) {
    return { status: 401, body: { error: 'Firma HMAC de Gitea/Forgejo ausente o inválida' } };
  }

  const tsCheck = validateWebhookTimestamp(req);
  if (!tsCheck.valid) {
    return { status: 401, body: { success: false, code: tsCheck.code, error: tsCheck.error } };
  }

  if (event === 'pull_request' && body.pull_request) {
    const pr = body.pull_request;
    const headFull = String(pr.head?.repo?.full_name || '').trim().toLowerCase();
    const baseFull = String(pr.base?.repo?.full_name || '').trim().toLowerCase();
    const isFork = !headFull || !baseFull || headFull !== baseFull;
    return dispatchPullRequest({
      provider: 'gitea',
      projects: authorized,
      action: body.action || 'opened',
      prNumber: pr.number,
      branch: pr.head?.ref || '',
      commitSha: pr.head?.sha || null,
      isFork,
      deliveryId: req.headers['x-gitea-delivery'] || null
    });
  }

  if (event === 'push') {
    const ref = String(body.ref || '');
    const branch = ref.replace(/^refs\/heads\//, '');
    const commits = Array.isArray(body.commits) ? body.commits : [];
    const head = body.head_commit || commits[commits.length - 1] || {};
    const changedFiles = commits.flatMap((c) => [...(c.added || []), ...(c.modified || []), ...(c.removed || [])]);
    return dispatchPush({
      provider: 'gitea',
      projects: authorized,
      branch,
      commitSha: body.after || head.id,
      commitMsg: head.message || 'Push desde Gitea',
      author: body.pusher?.full_name || body.pusher?.username || 'Gitea',
      deliveryId: req.headers['x-gitea-delivery'] || null,
      changedFiles
    });
  }

  return { status: 200, body: { success: true, ignored: true, event } };
}

/**
 * Bitbucket Cloud Webhook (`POST /api/webhooks/bitbucket`) — autenticado con `X-Hub-Signature`.
 */
async function handleBitbucketWebhook(req) {
  const sig = String(req.headers['x-hub-signature'] || req.headers['x-hub-signature-256'] || '');
  const event = String(req.headers['x-event-key'] || 'repo:push');
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const rawBody = req.rawBody || Buffer.from(JSON.stringify(body));
  const queryProjectId = req.query?.projectId || null;

  const matched = resolveMatchingProjects({
    queryProjectId,
    repoUrls: [body?.repository?.links?.html?.href, body?.repository?.full_name]
  });
  if (matched.length === 0) {
    return { status: 404, body: { error: 'No se encontró un proyecto asociado a este repositorio de Bitbucket' } };
  }

  const authorized = matched.filter((p) => p.webhookSecret && verifyHmacSha256(rawBody, p.webhookSecret, sig));
  if (authorized.length === 0) {
    return { status: 401, body: { error: 'Firma HMAC de Bitbucket ausente o inválida' } };
  }

  const tsCheck = validateWebhookTimestamp(req);
  if (!tsCheck.valid) {
    return { status: 401, body: { success: false, code: tsCheck.code, error: tsCheck.error } };
  }

  if (event === 'repo:push') {
    const allChanges = Array.isArray(body?.push?.changes) ? body.push.changes : [];
    const branchChanges = allChanges.filter((c) => c && c.new && c.new.type === 'branch');
    if (branchChanges.length === 0) {
      return { status: 200, body: { success: true, deployed: false, reason: 'Evento Bitbucket sin cambio de rama ignorado' } };
    }
    const author = body?.actor?.display_name || body?.actor?.nickname || 'Bitbucket';
    /** @type {any} */
    let lastResult = null;
    for (const change of branchChanges) {
      const branch = change.new.name;
      const commitSha = change.new.target?.hash || '';
      const commitMsg = change.new.target?.message || 'Push desde Bitbucket';
      const deliveryId = req.headers['x-request-uuid'] ? `${req.headers['x-request-uuid']}:${branch}` : null;
      const res = await dispatchPush({
        provider: 'bitbucket',
        projects: authorized,
        branch,
        commitSha,
        commitMsg,
        author,
        deliveryId: /** @type {any} */ (deliveryId)
      });
      if (res.body && res.body.deployed) return res;
      lastResult = res;
    }
    return lastResult || { status: 200, body: { success: true, deployed: false, reason: 'Sin ramas coincidentes' } };
  }

  if (event.startsWith('pullrequest:') && body.pullrequest) {
    const pr = body.pullrequest;
    const bbActions = {
      'pullrequest:created': 'opened',
      'pullrequest:updated': 'update',
      'pullrequest:fulfilled': 'merged',
      'pullrequest:rejected': 'closed'
    };
    const act = bbActions[event] || null;
    if (!act) {
      return { status: 200, body: { success: true, ignored: true, event } };
    }
    const srcRepo = String(pr.source?.repository?.full_name || '').trim().toLowerCase();
    const dstRepo = String(pr.destination?.repository?.full_name || '').trim().toLowerCase();
    const isFork = !srcRepo || !dstRepo || srcRepo !== dstRepo;
    return dispatchPullRequest({
      provider: 'bitbucket',
      projects: authorized,
      action: act,
      prNumber: pr.id,
      branch: pr.source?.branch?.name || '',
      commitSha: pr.source?.commit?.hash || null,
      isFork,
      deliveryId: req.headers['x-request-uuid'] || null
    });
  }

  return { status: 200, body: { success: true, ignored: true, event } };
}

/**
 * Deploy Hook genérico CI/CD (`POST /api/webhooks/deploy/:projectId`).
 * Permite disparar un despliegue desde GitHub Actions, GitLab CI, cron externo o curl
 * usando exclusivamente el `deployHookToken` propio del proyecto.
 */
async function handleDeployHook(req) {
  const project = projectManager.getById(req.params.projectId);
  if (!project) return { status: 404, body: { error: 'Proyecto no encontrado' } };
  if (!project.deployHookToken) {
    return { status: 403, body: { error: 'El Deploy Hook no está habilitado en este proyecto. Genera un token en Configuración.' } };
  }

  const authHeader = String(req.headers.authorization || '');
  const bearer = authHeader.toLowerCase().startsWith('bearer ') ? authHeader.slice(7).trim() : '';
  const provided = bearer || String(req.headers['x-deploy-token'] || req.query?.token || '');
  if (!timingSafeStrEqual(project.deployHookToken, provided)) {
    return { status: 401, body: { error: 'Token de Deploy Hook inválido' } };
  }

  const tsCheck = validateWebhookTimestamp(req);
  if (!tsCheck.valid) {
    return { status: 401, body: { success: false, code: tsCheck.code, error: tsCheck.error } };
  }

  const projectSecrets = [project.deployHookToken, project.webhookSecret].filter(Boolean);
  const dockerProbe = await deployManager.detectDocker({ force: true });
  if (!dockerProbe.available) {
    return {
      status: 503,
      body: {
        success: false,
        deployed: false,
        code: 'DOCKER_UNAVAILABLE',
        error: redactWebhookSecrets(`Docker no está disponible: ${dockerProbe.reason}`, projectSecrets)
      }
    };
  }

  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const commit = body.commit && /^[0-9a-f]{7,40}$/i.test(String(body.commit)) ? String(body.commit) : null;
  const version = body.version ? String(body.version).slice(0, 48) : (commit ? `hook-${commit.slice(0, 7)}` : null);
  const awaitSync = Boolean(body.sync || body.wait || req.query?.sync === '1' || req.query?.sync === 'true');

  /** @type {any} */
  let queued;
  try {
    queued = deployManager.enqueue(project, { commit, version, trigger: 'deploy_hook' });
  } catch (err) {
    /** @type {any} */
    const e = err;
    const safeErr = redactWebhookSecrets((e && e.message) || String(err), projectSecrets);
    containerOrchestrator.addLog('ERROR', 'citadel', `[DeployHook] Error lanzando despliegue para ${project.name}: ${safeErr}`, new Date(), project.id);
    const errStatus = (e && Number.isInteger(e.status) && e.status >= 400 && e.status < 600) ? e.status : 500;
    return {
      status: errStatus,
      body: {
        success: false,
        deployed: false,
        code: (e && e.code) || 'DEPLOY_FAILED',
        projectId: project.id,
        error: safeErr
      }
    };
  }

  if (queued && queued.blocked) {
    const safeReason = redactWebhookSecrets(queued.reason || 'Despliegue bloqueado por ventana de congelación', projectSecrets);
    return {
      status: 423,
      body: {
        success: false,
        deployed: false,
        blocked: true,
        code: queued.code || 'DEPLOY_FROZEN',
        projectId: project.id,
        error: safeReason,
        window: queued.window || null
      }
    };
  }

  if (awaitSync && queued && queued.promise) {
    try {
      const depResult = await queued.promise;
      if (!depResult || depResult.status === 'fallido' || depResult.ok === false) {
        const safeErr = redactWebhookSecrets(depResult?.error || 'El despliegue síncrono falló', projectSecrets);
        containerOrchestrator.addLog('ERROR', 'citadel', `[DeployHook] Despliegue síncrono fallido para ${project.name}: ${safeErr}`, new Date(), project.id);
        return {
          status: 502,
          body: {
            success: false,
            deployed: false,
            code: 'DEPLOY_FAILED',
            projectId: project.id,
            trigger: 'deploy_hook',
            error: safeErr
          }
        };
      }
      containerOrchestrator.addLog('INFO', 'citadel', `[DeployHook] Despliegue síncrono completado para ${project.name}`, new Date(), project.id);
      return {
        status: 200,
        body: {
          success: true,
          deployed: true,
          projectId: project.id,
          trigger: 'deploy_hook',
          deploymentId: depResult.id || depResult.deploymentId || null,
          status: depResult.status || 'activo'
        }
      };
    } catch (syncErr) {
      /** @type {any} */
      const se = syncErr;
      const safeErr = redactWebhookSecrets((se && se.message) || String(syncErr), projectSecrets);
      containerOrchestrator.addLog('ERROR', 'citadel', `[DeployHook] Excepción en despliegue síncrono para ${project.name}: ${safeErr}`, new Date(), project.id);
      return {
        status: 502,
        body: {
          success: false,
          deployed: false,
          code: (se && se.code) || 'DEPLOY_FAILED',
          projectId: project.id,
          trigger: 'deploy_hook',
          error: safeErr
        }
      };
    }
  }

  containerOrchestrator.addLog('INFO', 'citadel', `[DeployHook] Despliegue disparado por webhook CI/CD para ${project.name}`, new Date(), project.id);
  const { promise: _ignoredPromise, ...safeQueued } = queued || {};

  return {
    status: 202,
    body: {
      success: true,
      projectId: project.id,
      trigger: 'deploy_hook',
      ...safeQueued
    }
  };
}

/** Genera o rota el `deployHookToken` de un proyecto. */
async function rotateDeployHookToken(projectId) {
  const project = projectManager.getById(projectId);
  if (!project) throw new Error('Proyecto no encontrado');
  const token = `ckh_${crypto.randomBytes(24).toString('hex')}`;
  projectManager.update(project.id, { deployHookToken: token });
  await projectManager.flushToDisk();
  return {
    success: true,
    projectId: project.id,
    deployHookToken: token,
    urlPath: `/api/webhooks/deploy/${project.id}`
  };
}

module.exports = {
  WEBHOOK_MAX_REPLAY_AGE_SEC,
  timingSafeStrEqual,
  verifyHmacSha256,
  validateWebhookTimestamp,
  redactWebhookSecrets,
  normalizeRepoSlug,
  matchesWatchPaths,
  didChangeGitOpsManifest,
  resolveMatchingProjects,
  dispatchPush,
  dispatchPullRequest,
  handleGitLabWebhook,
  handleGiteaWebhook,
  handleBitbucketWebhook,
  handleDeployHook,
  rotateDeployHookToken
};
