const crypto = require('crypto');
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

/** Extrae el slug canónico `owner/repo` (o `group/sub/repo`) desde cualquier URL Git. */
function normalizeRepoSlug(raw) {
  const s = String(raw || '').trim().toLowerCase();
  if (!s) return '';
  return s
    .replace(/^https?:\/\/(?:[^@/\s]+@)?[^/\s]+\//, '')
    .replace(/^git@[^:\s]+:/, '')
    .replace(/\.git$/, '')
    .replace(/^\/+|\/+$/g, '');
}

/** Comprueba si una lista de ficheros tocados en el push intersecta `project.watchPaths`. */
function matchesWatchPaths(watchPaths, changedFiles) {
  if (!Array.isArray(watchPaths) || watchPaths.length === 0) return true;
  if (!Array.isArray(changedFiles) || changedFiles.length === 0) return true;
  const normalizedWatch = watchPaths
    .map((p) => String(p || '').trim().replace(/^\/+|\/+$/g, ''))
    .filter(Boolean);
  if (normalizedWatch.length === 0) return true;
  return changedFiles.some((f) => {
    const cleanFile = String(f || '').replace(/^\/+/, '');
    return normalizedWatch.some((w) => {
      if (w.endsWith('/*')) {
        const prefix = w.slice(0, -1);
        return cleanFile.startsWith(prefix);
      }
      return cleanFile === w || cleanFile.startsWith(`${w}/`);
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
async function dispatchPush({ provider, projects, branch, commitSha, commitMsg, author, deliveryId = null, changedFiles = [] }) {
  const shortSha = String(commitSha || `c_${Date.now().toString(36)}`).slice(0, 7);
  const now = new Date().toISOString();
  const label = provider.charAt(0).toUpperCase() + provider.slice(1);

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

  const eligibleProjects = branchProjects.filter((p) => p.autoDeploy !== false);
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

  const pathEligible = eligibleProjects.filter((p) => matchesWatchPaths(p.watchPaths, changedFiles));
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

    const repoName = target.gitRepo || target.name;
    containerOrchestrator.addLog('INFO', 'citadel', `[${label}:Webhook] Push recibido en ${repoName} (${branch}) por ${author}: "${String(commitMsg || '').trim()}" (${shortSha})`, new Date(), target.id);
    containerOrchestrator.addLog('INFO', 'citadel', `[Citadel:Deploy] Iniciando despliegue automatizado para ${target.name}...`, new Date(), target.id);

    /** @type {{ dispatched: boolean, queued: boolean, reason: string | null }} */
    let pipeline = { dispatched: false, queued: false, reason: null };
    if (!target.gitRepo) {
      pipeline.reason = 'El proyecto no tiene repositorio configurado';
    } else if (!dockerProbe.available) {
      pipeline.reason = dockerProbe.reason;
    } else {
      try {
        const started = deployManager.enqueue(target, {
          commit: /^[0-9a-f]{7,40}$/i.test(String(commitSha || '')) ? String(commitSha) : null,
          version: `${provider.slice(0, 2)}-${shortSha}`,
          trigger: 'webhook'
        });
        pipeline = { dispatched: started.started, queued: started.queued, reason: null };
      } catch (err) {
        pipeline.reason = err.message;
      }
    }

    if (pipeline.reason) {
      containerOrchestrator.addLog('WARN', 'citadel', `[Citadel:Deploy] No se lanza la construcción de imagen: ${pipeline.reason}.`, new Date(), target.id);
    } else if (pipeline.queued) {
      containerOrchestrator.addLog('INFO', 'citadel', `[Citadel:Deploy] Ya hay un despliegue en curso; ${shortSha} queda en cola y se construirá al terminar.`, new Date(), target.id);
    }

    const lastCommit = {
      sha: shortSha,
      message: String(commitMsg || 'Push automático').trim(),
      author: String(author || label),
      timestamp: now
    };
    projectManager.update(target.id, { lastDeployedAt: now, lastCommit });

    containerOrchestrator.emit('github_deploy', {
      provider,
      projectId: target.id,
      projectName: target.name,
      branch,
      commit: shortSha,
      author: lastCommit.author,
      message: lastCommit.message,
      timestamp: now
    });

    containerOrchestrator.addLog(
      'SUCCESS',
      'citadel',
      pipeline.dispatched || pipeline.queued
        ? `[${label}:Webhook] Despliegue en curso para ${target.name} (${shortSha}); sigue el progreso en la pestaña Despliegues.`
        : `[${label}:Webhook] Despliegue completado para ${target.name} (${shortSha})`,
      new Date(),
      target.id
    );

    dispatched.push({
      projectId: target.id,
      pipeline: pipeline.dispatched ? 'building' : pipeline.queued ? 'queued' : 'registro',
      pipelineReason: pipeline.reason
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

/** Despacha eventos de Pull Request / Merge Request hacia Preview Deployments. */
async function dispatchPullRequest({ provider, projects, action, prNumber, branch, commitSha, isFork = false }) {
  const pm = getPreviewManager();
  const results = [];
  for (const project of projects) {
    const cfg = project.previewDeployments || {};
    if (!cfg.enabled) {
      results.push({ projectId: project.id, action: 'skipped', reason: 'previews_disabled' });
      continue;
    }
    if (action === 'closed' || action === 'merged') {
      try {
        const res = await pm.destroyPreview(project.id, { prNumber, branch });
        results.push({ projectId: project.id, action: 'destroyed', ...res });
      } catch (e) {
        results.push({ projectId: project.id, action: 'destroy_skipped', reason: e.message });
      }
    } else if (action === 'opened' || action === 'synchronize' || action === 'reopened' || action === 'update') {
      if (isFork && !cfg.allowForks) {
        containerOrchestrator.addLog('WARN', 'citadel', `[${provider}:Preview] PR #${prNumber} desde fork bloqueada por seguridad (allowForks=false).`, new Date(), project.id);
        results.push({ projectId: project.id, action: 'blocked', reason: 'fork_pr_blocked' });
        continue;
      }
      try {
        const res = await pm.deployPreview(project, { prNumber, branch, commit: commitSha, isFork });
        results.push({ projectId: project.id, action: 'preview_deployed', preview: res });
      } catch (e) {
        results.push({ projectId: project.id, action: 'preview_error', error: e.message });
      }
    }
  }
  return { status: 200, body: { success: true, provider, event: 'pull_request', prNumber, branch, results } };
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

  if (event === 'Merge Request Hook' || body.object_kind === 'merge_request') {
    const attrs = body.object_attributes || {};
    const mrAction = attrs.action === 'merge' ? 'merged' : attrs.action === 'close' ? 'closed' : (attrs.action === 'open' ? 'opened' : (attrs.action === 'reopen' ? 'reopened' : 'update'));
    const isFork = Boolean(attrs.source_project_id && attrs.target_project_id && attrs.source_project_id !== attrs.target_project_id);
    return dispatchPullRequest({
      provider: 'gitlab',
      projects: authorized,
      action: mrAction,
      prNumber: attrs.iid || attrs.id,
      branch: attrs.source_branch || '',
      commitSha: attrs.last_commit?.id || null,
      isFork
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

  if (event === 'pull_request' && body.pull_request) {
    const pr = body.pull_request;
    const isFork = Boolean(pr.head?.repo?.full_name && pr.base?.repo?.full_name && pr.head.repo.full_name !== pr.base.repo.full_name);
    return dispatchPullRequest({
      provider: 'gitea',
      projects: authorized,
      action: body.action || 'opened',
      prNumber: pr.number,
      branch: pr.head?.ref || '',
      commitSha: pr.head?.sha || null,
      isFork
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

  if (event === 'repo:push') {
    const change = Array.isArray(body?.push?.changes) ? body.push.changes[0] : null;
    if (!change || !change.new || change.new.type !== 'branch') {
      return { status: 200, body: { success: true, deployed: false, reason: 'Evento Bitbucket sin cambio de rama ignorado' } };
    }
    const branch = change.new.name;
    const commitSha = change.new.target?.hash || '';
    const commitMsg = change.new.target?.message || 'Push desde Bitbucket';
    const author = body?.actor?.display_name || body?.actor?.nickname || 'Bitbucket';
    return dispatchPush({
      provider: 'bitbucket',
      projects: authorized,
      branch,
      commitSha,
      commitMsg,
      author,
      deliveryId: req.headers['x-request-uuid'] || null
    });
  }

  if (event.startsWith('pullrequest:') && body.pullrequest) {
    const pr = body.pullrequest;
    const act = event === 'pullrequest:fulfilled' ? 'merged' : (event === 'pullrequest:rejected' ? 'closed' : 'opened');
    const isFork = Boolean(pr.source?.repository?.full_name && pr.destination?.repository?.full_name && pr.source.repository.full_name !== pr.destination.repository.full_name);
    return dispatchPullRequest({
      provider: 'bitbucket',
      projects: authorized,
      action: act,
      prNumber: pr.id,
      branch: pr.source?.branch?.name || '',
      commitSha: pr.source?.commit?.hash || null,
      isFork
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

  const dockerProbe = await deployManager.detectDocker({ force: true });
  if (!dockerProbe.available) {
    return { status: 503, body: { error: `Docker no está disponible: ${dockerProbe.reason}` } };
  }

  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const commit = body.commit && /^[0-9a-f]{7,40}$/i.test(String(body.commit)) ? String(body.commit) : null;
  const version = body.version ? String(body.version).slice(0, 48) : (commit ? `hook-${commit.slice(0, 7)}` : null);
  const queued = deployManager.enqueue(project, { commit, version, trigger: 'deploy_hook' });
  containerOrchestrator.addLog('INFO', 'citadel', `[DeployHook] Despliegue disparado por webhook CI/CD para ${project.name}`, new Date(), project.id);

  return {
    status: 202,
    body: {
      success: true,
      projectId: project.id,
      trigger: 'deploy_hook',
      ...queued
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
  timingSafeStrEqual,
  verifyHmacSha256,
  normalizeRepoSlug,
  matchesWatchPaths,
  resolveMatchingProjects,
  dispatchPush,
  dispatchPullRequest,
  handleGitLabWebhook,
  handleGiteaWebhook,
  handleBitbucketWebhook,
  handleDeployHook,
  rotateDeployHookToken
};
