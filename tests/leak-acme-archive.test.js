const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  computeLinearSlope,
  analyzeRuntimeLeakTelemetry,
  buildProactiveDrainPlan,
  listLeakAnalyses
} = require('../server/services/runtimeLeakGuardService');
const {
  auditAcmeRateBudget,
  evaluateAriRenewalWindow,
  auditTlsCipherPolicy,
  listAcmeBudgetAudits
} = require('../server/services/acmeTlsBudgetService');
const {
  normalizeSafeEntryPath,
  inspectArchiveManifest,
  listArchiveAudits
} = require('../server/services/archiveSlipGuardService');

/**
 * Suite Cycle #22: Container Heap-Slope/FD/Event-Loop Leak Guard, ACME Rate-Limit
 * & RFC 9773 ARI / TLS Cipher Guard (Coolify#6800, Dokploy#2238), and Archive
 * Zip-Slip / Symlink / Unicode / Zip-Bomb Firewall (CVE-2026-23745/23950).
 *
 * Runs strictly inside an isolated `os.tmpdir()` `CULKIBO_DATA_DIR` — ZERO mutations to live `data/`.
 */
async function runTests() {
  console.log('--- Iniciando Tests de Runtime Leak Guard, ACME/TLS Budget y Archive Zip-Slip Guard ---');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c22-'));
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
    // 1. CONTAINER HEAP-SLOPE, FD-LEAK & EVENT-LOOP LAG GUARD
    // =========================================================================
    await runCase('1. runtimeLeakGuardService computes OLS slope/hoursToOom, flags EMFILE/lag & recommends --max-old-space-size=798', async () => {
      assert.strictEqual(computeLinearSlope([200, 320, 440, 560, 680]), 120);
      assert.strictEqual(computeLinearSlope([100]), 0);

      const bad = analyzeRuntimeLeakTelemetry({
        projectId: 'proj-api',
        containerLimitMb: 1024,
        configuredMaxOldSpaceMb: 2048,
        heapSamplesMb: [200, 320, 440, 560, 680],
        rssSamplesMb: [240, 410, 580, 750, 920],
        openFds: 950,
        fdLimit: 1024,
        eventLoopLagP99Ms: 180
      });
      assert.strictEqual(bad.safe, false);
      assert.strictEqual(bad.status, 'CRITICAL');
      assert.strictEqual(bad.recommendedMaxOldSpaceMb, 798);
      assert.ok(bad.nodeOptions.includes('--max-old-space-size=798'));
      assert.ok(bad.hoursToOom !== null && bad.hoursToOom > 0);
      assert.ok(bad.findingCodes.includes('HEAP_LEAK_SLOPE_HIGH'));
      assert.ok(bad.findingCodes.includes('V8_HEAP_EXCEEDS_CGROUP'));
      assert.ok(bad.findingCodes.includes('FD_EXHAUSTION_EMFILE_RISK'));
      assert.ok(bad.findingCodes.includes('EVENT_LOOP_LAG_CRITICAL'));

      const drainPlan = buildProactiveDrainPlan(bad);
      assert.strictEqual(drainPlan.dryRun, true);
      assert.strictEqual(drainPlan.heapSnapshotSignal, 'SIGUSR2');
      assert.strictEqual(drainPlan.steps.length, 4);
      assert.strictEqual(listLeakAnalyses('proj-api').length, 1);

      const healthy = analyzeRuntimeLeakTelemetry({
        projectId: 'proj-api',
        containerLimitMb: 1024,
        configuredMaxOldSpaceMb: 798,
        heapSamplesMb: [210, 212, 208, 211, 209],
        openFds: 120,
        fdLimit: 1024,
        eventLoopLagP99Ms: 8
      });
      assert.strictEqual(healthy.safe, true);
      assert.strictEqual(healthy.hoursToOom, null);
    });

    // =========================================================================
    // 2. ACME RATE-LIMIT BUDGET, RFC 9773 ARI & TLS CIPHER GUARD
    // =========================================================================
    await runCase('2. acmeTlsBudgetService catches Coolify#6800/Dokploy#2238, computes jittered ARI window & blocks weak TLS/ciphers', async () => {
      const badBudget = auditAcmeRateBudget({
        domain: 'app.acme.io',
        certsIssued7d: 44,
        failedAuthz1h: 5,
        staleDomainsInStore: ['old.example.com'],
        ariSupported: false,
        hasPersistentCertVolume: false
      });
      assert.strictEqual(badBudget.blocked, true);
      assert.ok(badBudget.findingCodes.includes('ACME_WEEKLY_QUOTA_NEAR'));
      assert.ok(badBudget.findingCodes.includes('ACME_AUTHZ_LOCKOUT_RISK'));
      assert.ok(badBudget.findingCodes.includes('STALE_ACME_DOMAINS_DETECTED'));
      assert.ok(badBudget.findingCodes.includes('EPHEMERAL_CERT_STORAGE'));
      assert.ok(badBudget.findingCodes.includes('ARI_REPLACES_MISSING'));
      assert.strictEqual(typeof badBudget.caddyTlsBlock, 'string');
      assert.strictEqual(listAcmeBudgetAudits().length, 1);

      // RFC 9773 ARI suggestedWindow jitter
      const ari = evaluateAriRenewalWindow({
        certId: 'cert-abc-123',
        suggestedStartIso: '2026-12-01T00:00:00Z',
        suggestedEndIso: '2026-12-03T00:00:00Z',
        nowIso: '2026-12-02T23:59:59Z',
        replacesCertId: 'cert-prev-001'
      });
      assert.strictEqual(ari.rateLimitWaiverEligible, true);
      const chosenMs = Date.parse(ari.chosenRenewalIso);
      assert.ok(chosenMs >= Date.parse('2026-12-01T00:00:00Z') && chosenMs <= Date.parse('2026-12-03T00:00:00Z'));

      // Weak TLS 1.1 & RC4 cipher rejection
      const badTls = auditTlsCipherPolicy({
        minTlsVersion: '1.1',
        ciphers: ['TLS_RSA_WITH_RC4_128_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384']
      });
      assert.strictEqual(badTls.blocked, true);
      assert.ok(badTls.findingCodes.includes('WEAK_TLS_VERSION'));
      assert.ok(badTls.findingCodes.includes('WEAK_CIPHER_SUITE'));

      const goodTls = auditTlsCipherPolicy({
        minTlsVersion: '1.3',
        ciphers: ['TLS_AES_256_GCM_SHA384']
      });
      assert.strictEqual(goodTls.safe, true);
    });

    // =========================================================================
    // 3. ARCHIVE ZIP-SLIP, SYMLINK TRAVERSAL, UNICODE COLLISION & ZIP-BOMB GUARD
    // =========================================================================
    await runCase('3. archiveSlipGuardService blocks Zip-Slip, symlink escape, Unicode collision & 500:1 bomb while passing clean archives', async () => {
      assert.strictEqual(normalizeSafeEntryPath('/srv/app', '../../etc/passwd').safe, false);
      assert.strictEqual(normalizeSafeEntryPath('/srv/app', 'src/index.js').safe, true);

      const hostile = inspectArchiveManifest({
        targetRoot: '/srv/extract',
        entries: [
          { path: '../../etc/cron.d/pwn', type: 'file', compressedBytes: 100, uncompressedBytes: 120 },
          { path: 'links/escape', type: 'symlink', linkname: '/etc/passwd' },
          { path: 'links/hard', type: 'hardlink', linkname: '../../etc/shadow' },
          { path: 'App/config.json', type: 'file', compressedBytes: 50, uncompressedBytes: 80 },
          { path: 'app/config.json', type: 'file', compressedBytes: 50, uncompressedBytes: 80 },
          { path: 'bomb.bin', type: 'file', compressedBytes: 1000, uncompressedBytes: 500_000 }
        ]
      });

      assert.strictEqual(hostile.safe, false);
      assert.strictEqual(hostile.blocked, true);
      assert.ok(hostile.findingCodes.includes('ZIP_SLIP_PATH_TRAVERSAL'));
      assert.ok(hostile.findingCodes.includes('SYMLINK_ESCAPE_BLOCKED'));
      assert.ok(hostile.findingCodes.includes('HARDLINK_ESCAPE_BLOCKED'));
      assert.ok(hostile.findingCodes.includes('UNICODE_PATH_COLLISION'));
      assert.ok(hostile.findingCodes.includes('ZIP_BOMB_DETECTED'));

      const clean = inspectArchiveManifest({
        targetRoot: '/srv/extract',
        entries: [
          { path: 'package.json', type: 'file', compressedBytes: 400, uncompressedBytes: 1200 },
          { path: 'dist/server.js', type: 'file', compressedBytes: 12000, uncompressedBytes: 48000 }
        ]
      });
      assert.strictEqual(clean.safe, true);
      assert.strictEqual(clean.blocked, false);
      assert.strictEqual(listArchiveAudits().length, 2);
    });

    console.log(`\n✅ Runtime Leak Guard, ACME/TLS Budget & Archive Zip-Slip Suite: ${passed}/3 tests PASSED!`);
  } finally {
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ Leak/ACME/Archive test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
