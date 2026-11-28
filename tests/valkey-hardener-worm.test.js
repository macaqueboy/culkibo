const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  auditValkeyConfig,
  renderHardenedValkeyConfig,
  listValkeyAudits
} = require('../server/services/valkeyGuardService');
const {
  EOL_BASE_CATALOG,
  auditDockerfileHardening,
  planCopaThinPatch,
  listHardeningAudits
} = require('../server/services/baseImageHardenerService');
const {
  auditWormBackupPolicy,
  wrapBackupKey,
  rotateBackupKek,
  verifyEnvelopeUnwrap,
  listWormAudits
} = require('../server/services/wormBackupCryptoService');

/**
 * Suite Cycle #20: Valkey/Redis Guard, EOL Base-Image & CNCF `copa` Hardener,
 * and S3 WORM Object-Lock + Pure-Node AES-256-GCM Envelope KEK Rotation.
 *
 * Runs strictly inside an isolated `os.tmpdir()` `CULKIBO_DATA_DIR` — ZERO mutations to live `data/`.
 */
async function runTests() {
  console.log('--- Iniciando Tests de Valkey Guard, Base-Image Hardener y WORM Backup Crypto ---');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c20-'));
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
    // 1. VALKEY / REDIS PERSISTENCE, EVICTION & HOT-KEY GUARD
    // =========================================================================
    await runCase('1. valkeyGuardService catches BGSAVE fork OOM, THP, queue eviction & emits hardened valkey.conf', async () => {
      const badQueue = auditValkeyConfig({
        projectId: 'proj-queue',
        workload: 'queue',
        hostRamMb: 1024,
        maxmemoryMb: 900,
        evictionPolicy: 'allkeys-lru',
        overcommitMemory: 0,
        thpEnabled: 'always',
        topKeyTrafficPct: 35
      });
      assert.strictEqual(badQueue.ok, true);
      assert.strictEqual(badQueue.safe, false);
      assert.strictEqual(badQueue.blocked, true);
      assert.ok(badQueue.findingCodes.includes('BGSAVE_FORK_OOM_RISK'));
      assert.ok(badQueue.findingCodes.includes('THP_COW_AMPLIFICATION'));
      assert.ok(badQueue.findingCodes.includes('INSUFFICIENT_FORK_HEADROOM'));
      assert.ok(badQueue.findingCodes.includes('QUEUE_SILENT_JOB_EVICTION'));
      assert.ok(badQueue.findingCodes.includes('HOT_KEY_SKEW'));
      assert.strictEqual(typeof badQueue.valkeyConf, 'string');
      assert.strictEqual(typeof badQueue.sysctlSnippet, 'string');

      const goodQueue = auditValkeyConfig({
        projectId: 'proj-queue',
        workload: 'queue',
        hostRamMb: 2048,
        maxmemoryMb: 1200,
        evictionPolicy: 'noeviction',
        overcommitMemory: 1,
        thpEnabled: 'never',
        appendonly: true,
        topKeyTrafficPct: 5
      });
      assert.strictEqual(goodQueue.safe, true);
      assert.strictEqual(goodQueue.status, 'HEALTHY');

      const rendered = renderHardenedValkeyConfig({ workload: 'cache', hostRamMb: 2048 });
      assert.strictEqual(rendered.dryRun, true);
      assert.ok(rendered.valkeyConf.includes('maxmemory-policy allkeys-lfu'));
      assert.strictEqual(listValkeyAudits('proj-queue').length, 2);
    });

    // =========================================================================
    // 2. EOL BASE-IMAGE, CNCF COPA & DISTROLESS ADVISOR
    // =========================================================================
    await runCase('2. baseImageHardenerService flags EOL/root/unpinned bases, approves Chainguard UID 65532 & plans copa', async () => {
      assert.ok(EOL_BASE_CATALOG.length >= 5);

      const badDocker = [
        'FROM node:18',
        'WORKDIR /app',
        'COPY . .',
        'USER root',
        'CMD ["node", "server.js"]'
      ].join('\n');

      const badRes = auditDockerfileHardening({
        projectId: 'proj-api',
        dockerfile: badDocker,
        readOnlyRootfs: false,
        trivySummary: { criticalOsCves: 2, highOsCves: 5 }
      });
      assert.strictEqual(badRes.safe, false);
      assert.ok(badRes.findingCodes.includes('EOL_BASE_IMAGE'));
      assert.ok(badRes.findingCodes.includes('UNPINNED_BASE_TAG'));
      assert.ok(badRes.findingCodes.includes('ROOT_USER_FINAL_STAGE'));
      assert.ok(badRes.findingCodes.includes('WRITABLE_ROOTFS_RISK'));
      assert.strictEqual(typeof badRes.recommendedDockerfile, 'string');

      const digest = 'a'.repeat(64);
      const hardenedDocker = [
        `FROM cgr.dev/chainguard/node@sha256:${digest}`,
        'WORKDIR /app',
        'COPY --chown=65532:65532 dist/ ./dist/',
        'USER 65532',
        'ENTRYPOINT ["node", "dist/server.js"]'
      ].join('\n');

      const goodRes = auditDockerfileHardening({
        projectId: 'proj-api',
        dockerfile: hardenedDocker,
        readOnlyRootfs: true
      });
      assert.strictEqual(goodRes.safe, true);
      assert.strictEqual(goodRes.status, 'HARDENED');

      const copaPlan = planCopaThinPatch({
        imageRef: `ghcr.io/culkibo/api@sha256:${digest}`,
        osCves: ['CVE-2026-11111', 'CVE-2026-22222']
      });
      assert.strictEqual(copaPlan.dryRun, true);
      assert.strictEqual(copaPlan.fullRebuildRequired, false);
      assert.ok(Array.isArray(copaPlan.copaCommandArgv) && copaPlan.copaCommandArgv[0] === 'copa');
      assert.strictEqual(listHardeningAudits('proj-api').length, 2);
    });

    // =========================================================================
    // 3. S3 WORM OBJECT-LOCK & AES-256-GCM ENVELOPE KEK ROTATION
    // =========================================================================
    await runCase('3. wormBackupCryptoService flags Coolify#12211/Restic#5411 & rotates AES-256-GCM KEK v1->v2 with 0 B re-upload', async () => {
      const badWorm = auditWormBackupPolicy({
        bucket: 's3://prod-worm-backups',
        objectLockMode: 'NONE',
        retentionDays: 3,
        streamingPipeNoMd5: true,
        resticLocksInWormPrefix: true,
        keyEscrowVerified: false
      });
      assert.strictEqual(badWorm.safe, false);
      assert.ok(badWorm.findingCodes.includes('MISSING_CONTENT_MD5_WORM'));
      assert.ok(badWorm.findingCodes.includes('WORM_LOCK_PREFIX_CONFLICT'));
      assert.ok(badWorm.findingCodes.includes('APP_KEY_ESCROW_MISSING'));
      assert.ok(badWorm.findingCodes.includes('INSUFFICIENT_WORM_RETENTION'));

      // Ephemeral 256-bit DEK, old KEK, new KEK
      const dekHex = crypto.randomBytes(32).toString('hex');
      const oldKekHex = crypto.randomBytes(32).toString('hex');
      const newKekHex = crypto.randomBytes(32).toString('hex');

      const wrappedV1 = wrapBackupKey({ dekHex, kekHex: oldKekHex, kekVersion: 1 });
      assert.strictEqual(wrappedV1.ok, true);
      assert.strictEqual(wrappedV1.envelope.kekVersion, 1);

      const unwrapV1 = verifyEnvelopeUnwrap({ envelope: wrappedV1.envelope, kekHex: oldKekHex });
      assert.strictEqual(unwrapV1.valid, true);
      assert.strictEqual(unwrapV1.dekHex, dekHex);

      // Rotate KEK v1 -> v2 (dryRun: true default, then live commit)
      const dryRot = rotateBackupKek({
        envelope: wrappedV1.envelope,
        oldKekHex,
        newKekHex,
        newKekVersion: 2
      });
      assert.strictEqual(dryRot.dryRun, true);
      assert.strictEqual(dryRot.reuploadBytes, 0);
      assert.strictEqual(dryRot.newKekVersion, 2);

      const liveRot = rotateBackupKek({
        envelope: wrappedV1.envelope,
        oldKekHex,
        newKekHex,
        newKekVersion: 2,
        dryRun: false
      });
      assert.strictEqual(liveRot.ok, true);
      assert.strictEqual(liveRot.persisted, true);
      assert.strictEqual(liveRot.reuploadBytes, 0);

      // New KEK unwraps IDENTICAL DEK; old KEK MUST fail!
      const unwrapWithNew = verifyEnvelopeUnwrap({ envelope: liveRot.envelope, kekHex: newKekHex });
      assert.strictEqual(unwrapWithNew.valid, true);
      assert.strictEqual(unwrapWithNew.dekHex, dekHex);

      const unwrapWithOld = verifyEnvelopeUnwrap({ envelope: liveRot.envelope, kekHex: oldKekHex });
      assert.strictEqual(unwrapWithOld.valid, false);
      assert.strictEqual(unwrapWithOld.code, 'KEK_AUTH_TAG_MISMATCH');

      // ZERO raw DEK/KEK material persisted on disk!
      const diskContent = fs.readFileSync(path.join(tmpDir, 'data', 'worm-backup-crypto.json'), 'utf8');
      assert.ok(!diskContent.includes(dekHex), 'Raw DEK leaked to disk!');
      assert.ok(!diskContent.includes(oldKekHex), 'Raw old KEK leaked to disk!');
      assert.ok(!diskContent.includes(newKekHex), 'Raw new KEK leaked to disk!');
      assert.strictEqual(listWormAudits().length, 2);
    });

    console.log(`\n✅ Valkey Guard, Base-Image Hardener & WORM Backup Crypto Suite: ${passed}/3 tests PASSED!`);
  } finally {
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ Valkey/Hardener/WORM test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
