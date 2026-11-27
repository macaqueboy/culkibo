const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');

const {
  BackupDrillService,
  MIN_VALID_BACKUP_BYTES,
  verifySqlDumpContent,
  planCrossTargetRestore
} = require('../server/services/backupDrillService');
const {
  AiWorkloadService,
  AI_RUNTIME_PRESETS,
  QUANTIZATION_BYTES_PER_PARAM,
  estimateVram,
  auditAiImageSecurity,
  buildAiWorkloadSpec
} = require('../server/services/aiWorkloadService');
const {
  RemoteBuilderService,
  buildPruneArgs
} = require('../server/services/remoteBuilderService');

/**
 * Suite Cycle #10: Automated DR Backup Fire-Drill Verifier, Self-Hosted AI/GPU
 * Local LLM Orchestrator (Ollama/vLLM/llama.cpp), and Distributed Remote
 * Build-Node Offloader with SSH Mux Ref-Count Pinning.
 *
 * Runs 100% isolated inside `os.tmpdir()` — ZERO mutations to live `data/`.
 */
async function runTests() {
  console.log('--- Iniciando Tests de DR Fire-Drill, AI/GPU LLM Orchestrator y Remote Builder Offloader ---');

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-dr-ai-bld-'));
  const dataDir = path.join(tmpRoot, 'data');
  fs.mkdirSync(dataDir, { recursive: true });

  const dr = new BackupDrillService({ dataDir });
  const ai = new AiWorkloadService();
  const builderSvc = new RemoteBuilderService({ dataDir });

  let passed = 0;
  const runCase = async (name, fn) => {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  };

  try {
    // =========================================================================
    // 1. DR BACKUP FIRE-DRILL VERIFIER (dokploy#1382, coolify#6506/#12244, dokploy#6035)
    // =========================================================================
    await runCase('1. BackupDrillService rejects 0B/20B-gzip/bad-SHA256, verifies valid gzip SQL & flags --no-acl', async () => {
      assert.strictEqual(MIN_VALID_BACKUP_BYTES, 65);

      let alertsFired = 0;
      const onAlert = () => { alertsFired++; };

      // 1a. 0-byte empty dump -> FAIL + alert
      const zeroRes = await dr.runFireDrill({
        databaseId: 'db_pg_main',
        projectId: 'proj_saas',
        artifactBuffer: Buffer.alloc(0),
        onAlert
      });
      assert.strictEqual(zeroRes.verdict, 'FAIL');
      assert.ok(zeroRes.errors.some((e) => e.includes('EMPTY_OR_TRUNCATED_DUMP')));
      assert.strictEqual(alertsFired, 1);

      // 1b. Silent 20-byte empty gzip archive (dokploy#1382 / coolify#6506) -> FAIL + alert
      const emptyGz = zlib.gzipSync(Buffer.alloc(0));
      assert.strictEqual(emptyGz.length, 20);
      const gzEmptyRes = await dr.runFireDrill({
        databaseId: 'db_pg_main',
        projectId: 'proj_saas',
        artifactBuffer: emptyGz,
        onAlert
      });
      assert.strictEqual(gzEmptyRes.verdict, 'FAIL');
      assert.ok(gzEmptyRes.errors.some((e) => e.includes('EMPTY_OR_TRUNCATED_DUMP')));
      assert.strictEqual(alertsFired, 2);

      // 1c. Valid gzipped PostgreSQL SQL dump with GRANT ACL + SHA-256 verification -> PASS
      const validSql = [
        '-- PostgreSQL database dump',
        'CREATE SCHEMA public;',
        'CREATE TABLE public.users (id serial PRIMARY KEY, email text NOT NULL);',
        "INSERT INTO public.users (email) VALUES ('ops@culkibo.dev');",
        'GRANT SELECT, INSERT ON TABLE public.users TO app_user;'
      ].join('\n');
      const validGz = zlib.gzipSync(Buffer.from(validSql, 'utf8'));
      const validSha = crypto.createHash('sha256').update(validGz).digest('hex');

      const passRes = await dr.runFireDrill({
        databaseId: 'db_pg_main',
        projectId: 'proj_saas',
        engine: 'postgres',
        artifactBuffer: validGz,
        expectedSha256: validSha,
        preserveAcl: true,
        sourceMajorVersion: 17,
        targetMajorVersion: 17,
        createdAt: new Date(Date.now() - 120000).toISOString()
      });
      assert.strictEqual(passRes.verdict, 'PASS');
      assert.strictEqual(passRes.errors.length, 0);
      assert.strictEqual(passRes.warnings.length, 0);
      assert.strictEqual(passRes.sha256, validSha);
      assert.ok(passRes.uncompressedBytes > 100);
      assert.ok(passRes.rpoSec >= 100);

      // 1d. Corrupt SHA-256 -> FAIL
      const badShaRes = await dr.runFireDrill({
        databaseId: 'db_pg_main',
        artifactBuffer: validGz,
        expectedSha256: '0'.repeat(64)
      });
      assert.strictEqual(badShaRes.verdict, 'FAIL');
      assert.ok(badShaRes.errors.some((e) => e.includes('CHECKSUM_MISMATCH')));

      // 1e. --no-acl stripped dump warns cleanly when preserveAcl=true (coolify#12244)
      const noAclCheck = verifySqlDumpContent(
        '-- PostgreSQL database dump (--no-acl)\nCREATE TABLE t (id int);\nINSERT INTO t VALUES (1);',
        { engine: 'postgres', preserveAcl: true }
      );
      assert.strictEqual(noAclCheck.validSql, true);
      assert.strictEqual(noAclCheck.aclStripped, true);
      assert.ok(noAclCheck.warnings.some((w) => w.includes('ACL_STRIPPED_WARNING')));

      // 1f. Scorecard persistence
      const drReloaded = new BackupDrillService({ dataDir });
      assert.strictEqual(drReloaded.listDrills('db_pg_main').count, 4);

      // 1g. Same-org cross-target restore allowed (dokploy#6035) vs cross-org 403 forbidden
      const sameOrg = planCrossTargetRestore({
        sourceDatabaseId: 'db_prod',
        targetDatabaseId: 'db_staging',
        sourceOrgId: 'org_acme',
        targetOrgId: 'org_acme',
        engine: 'postgres',
        preserveAcl: true
      });
      assert.strictEqual(sameOrg.allowed, true);
      assert.ok(!sameOrg.restoreCommand.args.includes('--no-acl'), 'preserveAcl=true must NOT pass --no-acl');

      const noAclRestore = planCrossTargetRestore({
        sourceDatabaseId: 'db_prod',
        targetDatabaseId: 'db_dev',
        sourceOrgId: 'org_acme',
        targetOrgId: 'org_acme',
        preserveAcl: false
      });
      assert.ok(noAclRestore.restoreCommand.args.includes('--no-acl'), 'preserveAcl=false should include --no-acl');

      assert.throws(
        () => planCrossTargetRestore({
          sourceDatabaseId: 'db_prod',
          targetDatabaseId: 'db_other',
          sourceOrgId: 'org_acme',
          targetOrgId: 'org_evil'
        }),
        (err) => err && err.status === 403 && err.code === 'CROSS_ORG_RESTORE_FORBIDDEN'
      );
    });

    // =========================================================================
    // 2. SELF-HOSTED AI / GPU LLM ORCHESTRATOR (dokploy#1621, CVE-2025-63389, CVE-2026-*)
    // =========================================================================
    await runCase('2. AiWorkloadService enforces VRAM pre-flight, CDI/legacy GPU flags & 2026 CVE guards', async () => {
      assert.strictEqual(ai.getPresets().presets.length, 3);
      assert.ok(AI_RUNTIME_PRESETS.ollama.image.includes('0.17.4'));
      assert.ok(AI_RUNTIME_PRESETS.vllm.image.includes('0.21.2'));
      assert.ok(QUANTIZATION_BYTES_PER_PARAM.Q4_K_M > 0.5);

      // 2a. VRAM estimation & overflow fail-closed
      const vram8b = estimateVram({ paramsB: 8, quantization: 'Q4_K_M', contextLen: 8192, availableVramGb: 16 });
      assert.strictEqual(vram8b.fits, true);
      assert.ok(vram8b.totalRequiredGb < 12);

      assert.throws(
        () => buildAiWorkloadSpec({ runtime: 'ollama', model: 'llama3.1:70b', paramsB: 70, quantization: 'FP16', availableVramGb: 24 }),
        (err) => err && err.status === 400 && err.code === 'VRAM_INSUFFICIENT'
      );

      // 2b. Unauthenticated 0.0.0.0 exposure blocked (CVE-2025-63389)
      assert.throws(
        () => buildAiWorkloadSpec({ runtime: 'ollama', bindAddress: '0.0.0.0', authProxyEnabled: false }),
        (err) => err && err.status === 400 && err.code === 'PUBLIC_AI_ENDPOINT_BLOCKED'
      );

      // 2c. Vulnerable ollama <0.17.1 & vllm <0.21.1 CVE detection vs safe pinned versions
      const badOllama = auditAiImageSecurity({ runtime: 'ollama', imageTag: 'ollama/ollama:0.16.0' });
      assert.strictEqual(badOllama.safe, false);
      assert.ok(badOllama.cves.some((c) => c.id === 'CVE-2026-7482'));

      const badVllm = auditAiImageSecurity({ runtime: 'vllm', imageTag: 'vllm/vllm-openai:v0.19.0' });
      assert.strictEqual(badVllm.safe, false);
      assert.ok(badVllm.cves.some((c) => c.id === 'CVE-2026-22778'));
      assert.ok(badVllm.cves.some((c) => c.id === 'CVE-2026-137477'));

      const safeVllm = auditAiImageSecurity({ runtime: 'vllm', imageTag: AI_RUNTIME_PRESETS.vllm.image });
      assert.strictEqual(safeVllm.safe, true);

      // 2d. NVIDIA CDI (--device nvidia.com/gpu=all) vs legacy toolkit (--gpus all, dokploy#1621)
      const cdiSpec = buildAiWorkloadSpec({ runtime: 'ollama', gpuMode: 'cdi', availableVramGb: 16 });
      assert.strictEqual(cdiSpec.ok, true);
      assert.ok(cdiSpec.dockerArgs.includes('--device') && cdiSpec.dockerArgs.includes('nvidia.com/gpu=all'));
      assert.ok(cdiSpec.dockerArgs.includes('127.0.0.1:11434:11434'));

      const legacySpec = buildAiWorkloadSpec({ runtime: 'vllm', gpuMode: 'legacy', availableVramGb: 24 });
      assert.strictEqual(legacySpec.ok, true);
      assert.ok(legacySpec.dockerArgs.includes('--gpus') && legacySpec.dockerArgs.includes('all'));
      assert.strictEqual(legacySpec.volumeMount.containerPath, '/root/.cache/huggingface');
    });

    // =========================================================================
    // 3. REMOTE BUILD-NODE OFFLOADER & SSH MUX PINNING (coolify#11372, dokploy#3226/#3450)
    // =========================================================================
    await runCase('3. RemoteBuilderService pins SSH mux during active builds, isolates queues & offloads previews', async () => {
      builderSvc.registerBuilder({
        id: 'bld-prod-only',
        name: 'Prod Heavy Builder',
        host: '198.51.100.51',
        arch: 'linux/amd64',
        maxConcurrency: 1,
        allowPreviews: false,
        keepStorageGb: 25
      });
      builderSvc.registerBuilder({
        id: 'bld-preview-arm',
        name: 'Preview Fleet Builder',
        host: '198.51.100.52',
        arch: 'linux/amd64',
        maxConcurrency: 2,
        allowPreviews: true,
        keepStorageGb: 15
      });

      // Idle mux can be recycled
      assert.strictEqual(builderSvc.canRecycleMux('bld-prod-only').allowed, true);

      // Acquire slot on bld-prod-only -> SSH mux MUST be pinned (cannot recycle while activeBuilds > 0!)
      const lease1 = builderSvc.acquireBuildSlot({ builderId: 'bld-prod-only', projectId: 'proj_a' });
      assert.strictEqual(lease1.leased, true);
      assert.strictEqual(lease1.sshMuxPinned, true);
      assert.strictEqual(lease1.activeBuilds, 1);

      const muxCheckBusy = builderSvc.canRecycleMux('bld-prod-only');
      assert.strictEqual(muxCheckBusy.allowed, false);
      assert.strictEqual(muxCheckBusy.reason, 'ACTIVE_BUILDS_IN_FLIGHT');

      // Second build on full bld-prod-only queues on bld-prod-only WITHOUT stalling bld-preview-arm (dokploy#3226)!
      const queuedOnProd = builderSvc.acquireBuildSlot({ builderId: 'bld-prod-only', projectId: 'proj_b' });
      assert.strictEqual(queuedOnProd.leased, false);
      assert.strictEqual(queuedOnProd.queued, true);
      assert.strictEqual(queuedOnProd.queuePosition, 1);

      // PR preview build automatically routes to allowPreviews=true builder (dokploy#3450)
      const prevLease = builderSvc.acquireBuildSlot({ arch: 'linux/amd64', isPreview: true, projectId: 'proj_pr_99' });
      assert.strictEqual(prevLease.leased, true);
      assert.strictEqual(prevLease.builderId, 'bld-preview-arm');
      assert.strictEqual(prevLease.sshMuxPinned, true);

      // Release bld-prod-only -> mux becomes recyclable cleanly
      const rel1 = builderSvc.releaseBuildSlot(lease1.leaseId);
      assert.strictEqual(rel1.released, true);
      assert.strictEqual(rel1.activeBuilds, 0);
      assert.strictEqual(builderSvc.canRecycleMux('bld-prod-only').allowed, true);
      // bld-preview-arm is still busy independently!
      assert.strictEqual(builderSvc.canRecycleMux('bld-preview-arm').allowed, false);

      builderSvc.releaseBuildSlot(prevLease.leaseId);
      assert.strictEqual(builderSvc.canRecycleMux('bld-preview-arm').allowed, true);

      // Zero-shell buildx prune argv
      assert.deepStrictEqual(buildPruneArgs({ keepStorageGb: 20 }), ['buildx', 'prune', '--force', '--keep-storage', '20GB']);

      // Reload from disk verifies persistence
      const reloaded = new RemoteBuilderService({ dataDir });
      assert.strictEqual(reloaded.listBuilders().count, 2);
    });

    console.log(`\n✅ DR Fire-Drill, AI/GPU Orchestrator & Remote Builder Suite: ${passed}/3 tests PASSED!`);
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ DR/AI/Builder test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
