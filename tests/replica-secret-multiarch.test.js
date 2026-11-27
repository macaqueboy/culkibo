const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  saveTopology,
  getTopology,
  evaluateReadWriteSplit,
  planReplicaPromotion
} = require('../server/services/replicaFailoverService');
const {
  computeShannonEntropy,
  SECRET_RULES,
  scanPreDeployPayload
} = require('../server/services/preDeploySecretGate');
const {
  SUPPORTED_PLATFORMS,
  verifyManifestCompatibility,
  planBuildMatrix
} = require('../server/services/multiArchPlannerService');

/**
 * Suite Cycle #14: Blue/Green DB Read-Replica Split-Brain Fencing, Pre-Deploy
 * Shannon-Entropy Secret Gate & Multi-Arch (amd64/arm64) OCI Manifest Planner.
 *
 * Runs strictly inside an isolated `os.tmpdir()` `CULKIBO_DATA_DIR` — ZERO mutations to live `data/`.
 */
async function runTests() {
  console.log('--- Iniciando Tests de Replica Failover, Secret Gate y Multi-Arch OCI Planner ---');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c14-'));
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
    // 1. BLUE/GREEN DB READ-REPLICA PROMOTION & SPLIT-BRAIN FENCING
    // =========================================================================
    await runCase('1. replicaFailoverService blocks lagging/unfenced promotion, filters lagging reads & promotes safely', async () => {
      const dbId = 'pg-prod-1';
      const saved = saveTopology(dbId, {
        primary: { id: 'pg-primary-a', host: '10.0.1.10', port: 5432, timeline: 4, fenced: false, healthy: true },
        replicas: [
          { id: 'pg-rep-fast', host: '10.0.1.11', port: 5432, timeline: 4, lagBytes: 4096, lagMs: 45, healthy: true },
          { id: 'pg-rep-lagging', host: '10.0.1.12', port: 5432, timeline: 4, lagBytes: 50 * 1024 * 1024, lagMs: 3200, healthy: true }
        ]
      });
      assert.strictEqual(saved.ok, true);
      assert.ok(getTopology(dbId));

      // Read/Write split excludes lagging replica while keeping synced replica
      const split = evaluateReadWriteSplit(dbId, { maxReadLagMs: 500 });
      assert.strictEqual(split.ok, true);
      assert.strictEqual(split.fallbackToPrimary, false);
      assert.strictEqual(split.writeTarget.id, 'pg-primary-a');
      assert.strictEqual(split.readTargets.length, 1);
      assert.strictEqual(split.readTargets[0].id, 'pg-rep-fast');
      assert.strictEqual(split.excludedLagging.length, 1);
      assert.strictEqual(split.excludedLagging[0].id, 'pg-rep-lagging');

      // Promoting lagging standby with unfenced primary -> blocks BOTH REPLICA_LAG_TOO_HIGH & OLD_PRIMARY_NOT_FENCED
      const blockedBoth = planReplicaPromotion(dbId, {
        targetReplicaId: 'pg-rep-lagging',
        maxAcceptableLagBytes: 1048576,
        requireOldPrimaryFenced: true,
        dryRun: true
      });
      assert.strictEqual(blockedBoth.allowed, false);
      const blockerCodes = new Set(blockedBoth.blockers.map((b) => b.code));
      assert.ok(blockerCodes.has('REPLICA_LAG_TOO_HIGH'), 'Expected REPLICA_LAG_TOO_HIGH blocker');
      assert.ok(blockerCodes.has('OLD_PRIMARY_NOT_FENCED'), 'Expected OLD_PRIMARY_NOT_FENCED blocker');
      assert.strictEqual(blockedBoth.steps.length, 0);

      // Fence old primary -> promoting fast replica succeeds with ordered drain->fence->promote->re-route steps!
      saveTopology(dbId, {
        primary: { id: 'pg-primary-a', host: '10.0.1.10', port: 5432, timeline: 4, fenced: true, healthy: false },
        replicas: [
          { id: 'pg-rep-fast', host: '10.0.1.11', port: 5432, timeline: 4, lagBytes: 2048, lagMs: 25, healthy: true }
        ]
      });

      const dryPlan = planReplicaPromotion(dbId, { targetReplicaId: 'pg-rep-fast', dryRun: true });
      assert.strictEqual(dryPlan.allowed, true);
      assert.strictEqual(dryPlan.blockers.length, 0);
      assert.strictEqual(dryPlan.timelineNext, 5);
      assert.deepStrictEqual(dryPlan.steps.map((s) => s.phase), ['drain', 'fence', 'promote', 're-route']);
      // dryRun must NOT mutate persisted primary
      assert.strictEqual(getTopology(dbId).primary.id, 'pg-primary-a');

      // Live commit (dryRun: false) transitions topology atomically
      const committed = planReplicaPromotion(dbId, { targetReplicaId: 'pg-rep-fast', dryRun: false });
      assert.strictEqual(committed.allowed, true);
      assert.strictEqual(committed.dryRun, false);
      const after = getTopology(dbId);
      assert.strictEqual(after.primary.id, 'pg-rep-fast');
      assert.strictEqual(after.primary.timeline, 5);

      // All-unhealthy/lagging replicas trigger fallbackToPrimary: true
      const fallbackSplit = evaluateReadWriteSplit(dbId, { maxReadLagMs: 500 });
      assert.strictEqual(fallbackSplit.fallbackToPrimary, true);
      assert.strictEqual(fallbackSplit.readTargets[0].id, 'pg-rep-fast');
    });

    // =========================================================================
    // 2. PRE-DEPLOY SHANNON-ENTROPY & PATTERN SECRET GATE (12 RULES)
    // =========================================================================
    await runCase('2. preDeploySecretGate blocks dynamic secrets with 0 raw echoes & allows benign UUID/SHA/pragma', async () => {
      assert.strictEqual(SECRET_RULES.length, 12);
      assert.strictEqual(computeShannonEntropy(''), 0);
      assert.strictEqual(computeShannonEntropy('aaaaaaaaaa'), 0);
      assert.ok(computeShannonEntropy('aB3$xY9!kL2@pQ7#mN5&zR8*vW1') >= 4.2);

      // Construct synthetic test secrets dynamically (ZERO GH013 literals!)
      const dynStripe = ['sk', 'live', 'AbCdEfGhIjKlMnOpQrSt'].join('_');
      const dynGithub = ['ghp', 'XyZ1234567890AbCdEfGhIj'].join('_');
      const dynPemHeader = '-----BEGIN ' + 'PRIVATE KEY-----';
      const dynHighEnt = 'K9mP4xQ8zR2wL7vN5cB1tF6yH3jD0sA9uE';

      const diffText = [
        'diff --git a/.env b/.env',
        '--- a/.env',
        '+++ b/.env',
        '@@ -1,2 +1,7 @@',
        `+PAYMENT_KEY=${dynStripe}`,
        `+REPO_TOKEN=${dynGithub}`,
        `+${dynPemHeader}`,
        `+CUSTOM_MASTER_SEED=${dynHighEnt}`,
        '+BENIGN_UUID=550e8400-e29b-41d4-a716-446655440000',
        '+BENIGN_SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        `+ALLOWED_FIXTURE=${dynStripe} # culkibo:allow-secret`
      ].join('\n');

      const res = scanPreDeployPayload({ diffText, mode: 'enforce' });
      assert.strictEqual(res.ok, true);
      assert.strictEqual(res.allowed, false);
      assert.strictEqual(res.blockedCount, 4);
      const foundRules = new Set(res.findings.map((f) => f.ruleId));
      assert.ok(foundRules.has('STRIPE_PAYMENT_KEY'));
      assert.ok(foundRules.has('GITHUB_TOKEN'));
      assert.ok(foundRules.has('PEM_PRIVATE_KEY'));
      assert.ok(foundRules.has('HIGH_ENTROPY_ASSIGNMENT'));

      // ZERO raw secret echoes in serialized output!
      const serialized = JSON.stringify(res);
      assert.ok(!serialized.includes(dynStripe), 'Raw Stripe test secret echoed!');
      assert.ok(!serialized.includes(dynGithub), 'Raw GitHub test secret echoed!');
      assert.ok(!serialized.includes(dynPemHeader), 'Raw PEM header echoed!');
      assert.ok(!serialized.includes(dynHighEnt), 'Raw high-entropy secret echoed!');
      for (const f of res.findings) {
        assert.strictEqual(f.fingerprintSha256.length, 64);
        assert.ok(f.redactedPreview.includes('REDACTED'));
      }

      // warn mode allows while reporting findings
      const warnRes = scanPreDeployPayload({ diffText, mode: 'warn' });
      assert.strictEqual(warnRes.allowed, true);
      assert.strictEqual(warnRes.blockedCount, 4);

      // Benign-only payload passes cleanly with 0 findings
      const benign = scanPreDeployPayload({
        envMap: {
          REQUEST_ID: '550e8400-e29b-41d4-a716-446655440000',
          BUILD_COMMIT_SHA: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          API_KEY: 'changeme_example_key'
        },
        mode: 'enforce'
      });
      assert.strictEqual(benign.allowed, true);
      assert.strictEqual(benign.blockedCount, 0);
    });

    // =========================================================================
    // 3. MULTI-ARCH (AMD64/ARM64) OCI MANIFEST & MATRIX PLANNER
    // =========================================================================
    await runCase('3. multiArchPlannerService catches EXEC_FORMAT_MISMATCH, warns strict OCI & routes native builders ahead of QEMU', async () => {
      assert.deepStrictEqual(SUPPORTED_PLATFORMS, ['linux/amd64', 'linux/arm64']);

      // Apple Silicon arm64-only image on x86_64 host -> EXEC_FORMAT_MISMATCH
      const mismatch = verifyManifestCompatibility({
        imageArch: 'aarch64',
        hostArch: 'x86_64',
        strictOciRegistry: true,
        includeAttestations: true
      });
      assert.strictEqual(mismatch.ok, true);
      assert.strictEqual(mismatch.compatible, false);
      assert.strictEqual(mismatch.code, 'EXEC_FORMAT_MISMATCH');
      assert.ok(mismatch.warnings.some((w) => w.includes('attestation')));

      // Multi-arch OCI index passes cleanly on both x86_64 and arm64
      const okMulti = verifyManifestCompatibility({
        manifestPlatforms: ['linux/amd64', 'linux/arm64'],
        hostArch: 'x86_64',
        strictOciRegistry: false
      });
      assert.strictEqual(okMulti.compatible, true);
      assert.strictEqual(okMulti.code, 'COMPATIBLE');

      // Native fleet routing ahead of QEMU
      const nativePlan = planBuildMatrix({
        targetPlatforms: ['linux/x86_64', 'linux/aarch64'],
        builders: [
          { name: 'hetzner-x86', arch: 'x86_64', online: true },
          { name: 'hetzner-cax-arm', arch: 'aarch64', online: true }
        ],
        imageTag: 'ghcr.io/culkibo/api:v1.2.0'
      });
      assert.strictEqual(nativePlan.ok, true);
      assert.strictEqual(nativePlan.usesQemu, false);
      assert.strictEqual(nativePlan.qemuWarning, null);
      assert.strictEqual(nativePlan.assignments.find((a) => a.arch === 'amd64').builder, 'hetzner-x86');
      assert.strictEqual(nativePlan.assignments.find((a) => a.arch === 'arm64').builder, 'hetzner-cax-arm');
      assert.ok(Array.isArray(nativePlan.buildxArgv) && nativePlan.buildxArgv[0] === 'docker');
      assert.ok(Array.isArray(nativePlan.manifestCreateArgv) && nativePlan.manifestCreateArgv[0] === 'docker');

      // Missing arm64 builder falls back to QEMU with explicit warning
      const qemuPlan = planBuildMatrix({
        targetPlatforms: ['linux/amd64', 'linux/arm64'],
        builders: [{ name: 'only-x86', arch: 'amd64', online: true }]
      });
      assert.strictEqual(qemuPlan.usesQemu, true);
      assert.ok(qemuPlan.qemuWarning && qemuPlan.qemuWarning.includes('linux/arm64'));
    });

    console.log(`\n✅ Replica Failover, Pre-Deploy Secret Gate & Multi-Arch OCI Suite: ${passed}/3 tests PASSED!`);
  } finally {
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ Replica/Secret/Multi-Arch test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
