const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  ComplianceBundleService,
  FRAMEWORKS,
  verifyComplianceBundle,
  renderComplianceMarkdown
} = require('../server/services/complianceBundleService');
const {
  VolumeMigrationService,
  SAFE_VOLUME_NAME_RE,
  SAFE_HOST_RE,
  validateVolumeMigrationRequest,
  buildFourPhaseArgvPlan
} = require('../server/services/volumeMigrationService');

/**
 * Suite Cycle #11: Ed25519-Signed SOC 2 / ISO 27001 / GDPR Compliance Evidence Bundle
 * (`dokploy#2642`/`#4360`) + 4-Phase Zero-Shell Stateful Volume Migration Planner
 * (`CVE-2025-66213`, Dokploy `999:999`, Kamal `Errno::EACCES`).
 *
 * Runs 100% isolated inside `os.tmpdir()` — ZERO mutations to live `data/`.
 */
async function runTests() {
  console.log('--- Iniciando Tests de Compliance Bundle (Ed25519) y Volume Migration Planner (4 fases) ---');

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-comp-vol-'));
  const dataDir = path.join(tmpRoot, 'data');
  fs.mkdirSync(dataDir, { recursive: true });

  const compliance = new ComplianceBundleService({ dataDir });
  const volMig = new VolumeMigrationService({ dataDir });

  let passed = 0;
  const runCase = async (name, fn) => {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  };

  try {
    // =========================================================================
    // 1. ED25519-SIGNED COMPLIANCE BUNDLE + 1-BYTE TAMPER DETECTION + 0 LEAKS
    // =========================================================================
    await runCase('1. ComplianceBundleService generates Ed25519 SOC2/ISO27001/GDPR bundle, detects 1-byte tamper & leaks 0 secrets', async () => {
      assert.deepStrictEqual(FRAMEWORKS, ['all', 'soc2', 'iso27001', 'gdpr']);

      const CANARY_SECRET = 'CANARY_DOKPLOY_4360_PLAINTEXT_SECRET_999';
      const bundle = compliance.generateBundle({
        framework: 'all',
        actor: 'auditor-pablo',
        snapshot: {
          accessControl: { rbacEnabled: true, userCount: 5, mfaEnabledUsers: 4, passkeyCount: 2 },
          encryption: { aes256GcmEnabled: true, fileMode0600Enforced: true, vaultSecretCount: 14, rawSecretCanary: CANARY_SECRET },
          audit: { chainValid: true, entryCount: 420 },
          supplyChain: { sbomCycloneDx16: true, slsaEd25519Enabled: true, criticalCves: 0, highCves: 0, staleSecretsCount: 0 },
          governance: { admissionPreset: 'soc2-strict', zeroShellEnforced: true },
          disasterRecovery: { totalDrills: 4, passedDrills: 4, latestRtoMs: 12.4, latestRpoSec: 60 }
        }
      });

      assert.strictEqual(bundle.ok, true);
      assert.strictEqual(bundle.algorithm, 'Ed25519');
      assert.strictEqual(bundle.payload.controls.length, 6);
      assert.strictEqual(bundle.overallScore, 100);
      assert.strictEqual(bundle.payloadSha256.length, 64);
      assert.ok(bundle.publicKeyPem.includes('BEGIN PUBLIC KEY'));
      assert.ok(bundle.markdownReport.includes('SOC2-CC6.1'));
      assert.ok(bundle.markdownReport.includes('ISO27001-A.8.24'));
      assert.ok(bundle.markdownReport.includes('GDPR-Art32'));
      assert.strictEqual(typeof renderComplianceMarkdown(bundle), 'string');

      // Cryptographic signature verifies validly
      const verOk = verifyComplianceBundle(bundle);
      assert.strictEqual(verOk.valid, true);
      assert.strictEqual(verOk.reason, 'SIGNATURE_VERIFIED');

      // 1-byte tamper in payload MUST fail verification immediately!
      const tampered = JSON.parse(JSON.stringify(bundle));
      tampered.payload.overallScore = 99;
      const verTampered = verifyComplianceBundle(tampered);
      assert.strictEqual(verTampered.valid, false);

      // Even if attacker recomputes payloadSha256, Ed25519 signature MUST fail!
      tampered.payloadSha256 = verTampered.payloadSha256;
      const verSigFail = verifyComplianceBundle(tampered);
      assert.strictEqual(verSigFail.valid, false);
      assert.strictEqual(verSigFail.reason, 'INVALID_ED25519_SIGNATURE');

      // ZERO canary secret OR Ed25519 private key in bundle JSON, Markdown, or persisted latest file!
      const serialized = JSON.stringify(bundle);
      const diskBundle = fs.readFileSync(path.join(dataDir, 'compliance-bundle-latest.json'), 'utf8');
      assert.ok(!serialized.includes(CANARY_SECRET), 'Canary secret must NEVER leak into compliance bundle');
      assert.ok(!serialized.includes('PRIVATE KEY'), 'Ed25519 private key must NEVER appear in bundle');
      assert.ok(!diskBundle.includes(CANARY_SECRET));
      assert.ok(!diskBundle.includes('PRIVATE KEY'));

      // Framework filtering (gdpr subset) + getLatestBundle persistence
      const gdprBundle = compliance.generateBundle({ framework: 'gdpr', actor: 'dpo' });
      assert.strictEqual(gdprBundle.payload.controls.length, 3);
      assert.strictEqual(verifyComplianceBundle(gdprBundle).valid, true);
      assert.strictEqual(compliance.getLatestBundle().bundleId, gdprBundle.bundleId);
    });

    // =========================================================================
    // 2. VOLUME MIGRATION: CVE-2025-66213 INJECTION, TRAVERSAL & CROSS-ORG 403
    // =========================================================================
    await runCase('2. VolumeMigrationService blocks CVE-2025-66213 volume injection, mount traversal & cross-org 403', async () => {
      assert.ok(SAFE_VOLUME_NAME_RE.test('pg_prod_data-1'));
      assert.ok(SAFE_HOST_RE.test('198.51.100.77'));

      const maliciousVols = [
        'vol;rm -rf /',
        'vol$(id)',
        'vol`whoami`',
        'vol|cat /etc/passwd',
        'vol&&echo pwn',
        '../escape_vol',
        'vol/sub'
      ];
      for (const badVol of maliciousVols) {
        assert.throws(
          () => validateVolumeMigrationRequest({
            projectId: 'proj_pg',
            volumeName: badVol,
            mountPath: '/var/lib/postgresql/data',
            targetHost: '198.51.100.77'
          }),
          (err) => err && err.status === 400 && err.code === 'UNSAFE_VOLUME_NAME',
          `Must reject malicious volume name: ${badVol}`
        );
      }

      // Mount traversal & host-root rejections
      for (const badMount of ['/../etc/passwd', '/app/../../etc', '/', '/etc/nginx', '/proc/self', '/var/run/docker.sock']) {
        assert.throws(
          () => validateVolumeMigrationRequest({
            projectId: 'proj_pg',
            volumeName: 'pg_data',
            mountPath: badMount,
            targetHost: '198.51.100.77'
          }),
          (err) => err && err.status === 400,
          `Must reject unsafe mountPath: ${badMount}`
        );
      }

      // Cross-org 403 block
      assert.throws(
        () => validateVolumeMigrationRequest({
          projectId: 'proj_pg',
          volumeName: 'pg_data',
          mountPath: '/var/lib/postgresql/data',
          targetHost: '198.51.100.77',
          sourceOrgId: 'org_alpha',
          targetOrgId: 'org_beta'
        }),
        (err) => err && err.status === 403 && err.code === 'CROSS_TENANT_FORBIDDEN'
      );
    });

    // =========================================================================
    // 3. 4-PHASE ZERO-SHELL --NUMERIC-OWNER (999:999 & 1000:1000) + ACL LISTING
    // =========================================================================
    await runCase('3. VolumeMigrationService generates 4-phase zero-shell --numeric-owner plans & persists with ACL', async () => {
      // Postgres 999:999 stateful volume migration plan
      const pgPlan = volMig.planMigration({
        projectId: 'proj_pg_prod',
        volumeName: 'pg_main_data',
        mountPath: '/var/lib/postgresql/data',
        sourceHost: 'local',
        targetHost: '198.51.100.88',
        uid: 999,
        gid: 999,
        containerName: 'culkibo_db_pg_main',
        estimatedMb: 1024
      });

      assert.strictEqual(pgPlan.ok, true);
      assert.strictEqual(pgPlan.zeroShell, true);
      assert.strictEqual(pgPlan.numericOwnerPreserved, true);
      assert.strictEqual(pgPlan.uidGid, '999:999');
      assert.strictEqual(pgPlan.retainSourceVolume, true);
      assert.strictEqual(pgPlan.phases.length, 4);
      assert.deepStrictEqual(pgPlan.phases.map((p) => p.id), [
        'pre_sync',
        'quiesce_snapshot',
        'ssh_stream_transfer',
        'verify_and_cutover'
      ]);

      const phase2 = pgPlan.phases[1];
      assert.strictEqual(phase2.commands[0].args[0], 'pause');
      assert.ok(phase2.commands[1].args.includes('--numeric-owner'));
      assert.strictEqual(phase2.commands[2].program, 'sha256sum');
      assert.strictEqual(phase2.commands[3].args[0], 'unpause');

      const phase3 = pgPlan.phases[2];
      assert.ok(phase3.commands[0].args.includes('BatchMode=yes'));
      assert.ok(phase3.commands[0].args.includes('StrictHostKeyChecking=yes'));

      const phase4 = pgPlan.phases[3];
      assert.ok(phase4.commands[0].args.includes('sha256sum'));
      assert.ok(phase4.commands[1].args.includes('--numeric-owner'));
      assert.ok(phase4.commands[2].args.includes('%u:%g'));

      // App 1000:1000 stateful volume migration plan + pure buildFourPhaseArgvPlan helper check
      const appPlan = volMig.planMigration({
        projectId: 'proj_uploads',
        volumeName: 'uploads_vol',
        mountPath: '/app/uploads',
        targetHost: '203.0.113.44',
        uid: 1000,
        gid: 1000
      });
      assert.strictEqual(appPlan.uidGid, '1000:1000');
      assert.strictEqual(typeof buildFourPhaseArgvPlan, 'function');

      // Reload & verify project ACL isolation in listMigrations
      const reloaded = new VolumeMigrationService({ dataDir });
      assert.strictEqual(reloaded.listMigrations().count, 2);
      const scoped = reloaded.listMigrations({ projectIds: ['proj_pg_prod'] });
      assert.strictEqual(scoped.count, 1);
      assert.strictEqual(scoped.migrations[0].id, pgPlan.id);
      assert.strictEqual(reloaded.getMigration(pgPlan.id).uidGid, '999:999');
    });

    console.log(`\n✅ Compliance Bundle (Ed25519) & Volume Migration Suite: ${passed}/3 tests PASSED!`);
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ Compliance & Volumes test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
