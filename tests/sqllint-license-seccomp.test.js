const assert = require('assert');
const path = require('path');

const { RULES, lintSqlMigration } = require('../server/services/sqlMigrationLinter');
const { POLICIES, classifySpdxLicense, auditLicenses } = require('../server/services/licenseAuditorService');
const {
  SUPPORTED_STACKS,
  BLOCKED_SYSCALLS,
  generateSeccompProfile,
  validateSeccompSpec,
  auditRuncVersion
} = require('../server/services/seccompProfileService');

/**
 * Suite Cycle #12: Zero-Downtime SQL DDL Linter (10 rules), CycloneDX 1.6 SPDX
 * License Risk Auditor, and Runtime-Tailored Seccomp / `runc` CVE Guard.
 *
 * Pure in-memory & read-only — ZERO mutations to live `data/`.
 */
async function runTests() {
  console.log('--- Iniciando Tests de SQL DDL Linter, SPDX License Auditor y Seccomp/runc CVE Guard ---');

  let passed = 0;
  const runCase = async (name, fn) => {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  };

  // =========================================================================
  // 1. ZERO-DOWNTIME SQL DDL LINTER (10 RULES + COMMENT/STRING IMMUNITY)
  // =========================================================================
  await runCase('1. sqlMigrationLinter catches all 9 blockers + warning while ignoring comments/strings', async () => {
    assert.strictEqual(RULES.length, 10);

    // Safe zero-downtime migration (missing statement_timeout is ONLY a warning, safe MUST remain true!)
    const safeRes = lintSqlMigration("SET lock_timeout = '5s'; CREATE INDEX CONCURRENTLY idx_users_email ON users(email);");
    assert.strictEqual(safeRes.safe, true);
    assert.strictEqual(safeRes.blockers.length, 0);
    assert.strictEqual(safeRes.hasLockTimeout, true);
    assert.strictEqual(safeRes.hasStatementTimeout, false);
    assert.strictEqual(safeRes.warnings.length, 1);
    assert.strictEqual(safeRes.warnings[0].rule, 'MISSING_STATEMENT_TIMEOUT');

    // Fully hardened migration (lock_timeout + statement_timeout + CONCURRENTLY + DROP DEFAULT + dollar-quotes + nested comments) -> 100/100
    const perfect = lintSqlMigration([
      "SET lock_timeout = '5s';",
      "SET statement_timeout = '30s';",
      '-- DROP TABLE users; (must be ignored inside line comment)',
      '/* outer /* DROP TABLE nested; */ ALTER TABLE users DROP COLUMN email; */',
      "SELECT 'CREATE INDEX idx_fake ON t(a);' AS note;",
      'SELECT $$DROP TABLE fake_dollar; ALTER TABLE users DROP COLUMN x;$$ AS body;',
      'ALTER TABLE users ALTER COLUMN legacy_flag DROP DEFAULT;',
      'CREATE INDEX CONCURRENTLY idx_orders_created ON orders(created_at);'
    ].join('\n'));
    assert.strictEqual(perfect.safe, true);
    assert.strictEqual(perfect.score, 100);
    assert.strictEqual(perfect.blockers.length, 0);
    assert.strictEqual(perfect.warnings.length, 0);

    // Unsafe multi-violation migration triggering all 9 blocker rules!
    const unsafeSql = [
      'CREATE INDEX idx_bad ON users(email);',
      'DROP INDEX idx_old;',
      'ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id);',
      'ALTER TABLE users DROP COLUMN legacy_bio;',
      'ALTER TABLE users ALTER COLUMN age TYPE bigint;',
      'ALTER TABLE users ALTER COLUMN phone SET NOT NULL;',
      'ALTER TABLE users ADD COLUMN created_ts timestamptz DEFAULT now();',
      'ALTER TABLE users RENAME COLUMN name TO full_name;'
    ].join('\n');

    const badRes = lintSqlMigration(unsafeSql);
    assert.strictEqual(badRes.safe, false);
    const blockerIds = new Set(badRes.blockers.map((b) => b.rule));
    for (const expectedRule of [
      'MISSING_LOCK_TIMEOUT',
      'CREATE_INDEX_NOT_CONCURRENT',
      'DROP_INDEX_NOT_CONCURRENT',
      'UNSAFE_ADD_CONSTRAINT',
      'DESTRUCTIVE_DROP_COLUMN_OR_TABLE',
      'ALTER_COLUMN_TYPE_REWRITE',
      'SET_NOT_NULL_WITHOUT_CHECK',
      'VOLATILE_ADD_COLUMN_DEFAULT',
      'UNSAFE_RENAME_OBJECT'
    ]) {
      assert.ok(blockerIds.has(expectedRule), `Missing expected blocker rule: ${expectedRule}`);
    }
    assert.ok(badRes.rewriteHints.length >= 8);
  });

  // =========================================================================
  // 2. CYCLONEDX 1.6 SPDX LICENSE RISK AUDITOR
  // =========================================================================
  await runCase('2. licenseAuditorService parses compound SPDX (OR/AND/LicenseRef) & enforces policies', async () => {
    assert.deepStrictEqual(POLICIES, ['saas-strict', 'oss-permissive', 'audit-only']);

    // Compound SPDX semantics: OR picks most permissive, AND picks strictest
    assert.strictEqual(classifySpdxLicense('MIT').category, 'permissive');
    assert.strictEqual(classifySpdxLicense('(MIT OR GPL-3.0-only)').category, 'permissive');
    assert.strictEqual(classifySpdxLicense('(Apache-2.0 AND AGPL-3.0-only)').category, 'strong_copyleft');
    assert.strictEqual(classifySpdxLicense('(MIT AND SSPL-1.0)').category, 'source_available');
    assert.strictEqual(classifySpdxLicense('BUSL-1.1').category, 'source_available');
    assert.strictEqual(classifySpdxLicense('BSL-1.1').category, 'source_available');
    assert.strictEqual(classifySpdxLicense('BSL-1.0').category, 'permissive');
    assert.strictEqual(classifySpdxLicense('LicenseRef-Custom-Enterprise').category, 'source_available');
    assert.strictEqual(classifySpdxLicense('MPL-2.0').category, 'weak_copyleft');
    assert.strictEqual(classifySpdxLicense('NOASSERTION').category, 'unknown');

    const syntheticSbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      components: [
        { name: 'ws', version: '8.18.0', licenses: [{ license: { id: 'MIT' } }] },
        { name: 'dual-lib', version: '1.0.0', licenses: [{ expression: '(MIT OR GPL-3.0-only)' }] },
        { name: 'mpl-pkg', version: '2.0.0', licenses: [{ license: { id: 'MPL-2.0' } }] },
        { name: 'agpl-pkg', version: '3.0.0', licenses: [{ license: { id: 'AGPL-3.0-only' } }] },
        { name: 'sspl-db', version: '1.0.0', licenses: [{ license: { id: 'SSPL-1.0' } }] },
        { name: 'mystery-pkg', version: '0.1.0', licenses: [] }
      ]
    };

    const strict = auditLicenses({ sbom: syntheticSbom, policy: 'saas-strict' });
    assert.strictEqual(strict.compliant, false);
    assert.strictEqual(strict.totalComponents, 6);
    assert.strictEqual(strict.countsByCategory.permissive, 2);
    assert.strictEqual(strict.countsByCategory.weak_copyleft, 1);
    assert.strictEqual(strict.countsByCategory.strong_copyleft, 1);
    assert.strictEqual(strict.countsByCategory.source_available, 1);
    assert.strictEqual(strict.countsByCategory.unknown, 1);
    assert.strictEqual(strict.violations.length, 3); // AGPL + SSPL + unknown

    const oss = auditLicenses({ sbom: syntheticSbom, policy: 'oss-permissive' });
    assert.strictEqual(oss.compliant, false);
    assert.strictEqual(oss.violations.length, 2); // AGPL + SSPL only (unknown is warning)

    const auditOnly = auditLicenses({ sbom: syntheticSbom, policy: 'audit-only' });
    assert.strictEqual(auditOnly.compliant, true);
    assert.strictEqual(auditOnly.violations.length, 0);
    assert.strictEqual(auditOnly.warnings.length, 4);

    // Fallback scan against Culkibo repo root cleanly reads package-lock.json
    const repoAudit = auditLicenses({ projectDir: path.resolve(__dirname, '..'), policy: 'audit-only' });
    assert.strictEqual(repoAudit.compliant, true);
    assert.ok(repoAudit.totalComponents > 0);
  });

  // =========================================================================
  // 3. RUNTIME-TAILORED SECCOMP GENERATOR & RUNC CVE GUARD
  // =========================================================================
  await runCase('3. seccompProfileService blocks unconfined, emits zero-overlap OCI profiles & flags runc CVEs', async () => {
    assert.deepStrictEqual(SUPPORTED_STACKS, ['node', 'python', 'go', 'rust', 'static-caddy']);
    for (const mustBlock of ['io_uring_setup', 'io_uring_enter', 'ptrace', 'mount', 'bpf', 'unshare', 'keyctl']) {
      assert.ok(BLOCKED_SYSCALLS.includes(mustBlock), `BLOCKED_SYSCALLS missing ${mustBlock}`);
    }

    // Reject unconfined cleanly with SECCOMP_UNCONFINED_FORBIDDEN
    assert.throws(
      () => generateSeccompProfile('unconfined'),
      (err) => err && err.code === 'SECCOMP_UNCONFINED_FORBIDDEN' && err.status === 400
    );
    assert.throws(
      () => generateSeccompProfile('node', { mode: 'unconfined' }),
      (err) => err && err.code === 'SECCOMP_UNCONFINED_FORBIDDEN'
    );
    assert.throws(
      () => generateSeccompProfile({ stack: 'node', mode: 'unconfined' }),
      (err) => err && err.code === 'SECCOMP_UNCONFINED_FORBIDDEN'
    );

    // Even if extraAllowed requests a blocked syscall, zero-overlap invariant strips it
    const stripped = generateSeccompProfile('node', { extraAllowed: ['ptrace', 'io_uring_setup'] });
    const strippedAllow = stripped.profile.syscalls.find((r) => r.action === 'SCMP_ACT_ALLOW');
    assert.ok(strippedAllow && !strippedAllow.names.includes('ptrace') && !strippedAllow.names.includes('io_uring_setup'));

    // Generate & validate every supported stack profile (zero overlap between allow & block!)
    const blockedSet = new Set(BLOCKED_SYSCALLS);
    for (const stack of SUPPORTED_STACKS) {
      const gen = generateSeccompProfile(stack);
      assert.strictEqual(gen.ok, true);
      assert.strictEqual(gen.profile.defaultAction, 'SCMP_ACT_ERRNO');
      assert.strictEqual(gen.sha256.length, 64);
      const allowRule = gen.profile.syscalls.find((r) => r.action === 'SCMP_ACT_ALLOW');
      assert.ok(allowRule && allowRule.names.length > 40);
      for (const s of allowRule.names) {
        assert.ok(!blockedSet.has(s), `Overlap detected in stack ${stack}: ${s}`);
      }
      const val = validateSeccompSpec(gen.profile);
      assert.strictEqual(val.safe, true, `Generated profile for ${stack} failed validation: ${val.violations.join(', ')}`);
    }

    // validateSeccompSpec catches unconfined, SCMP_ACT_ALLOW default, and allowed ptrace/io_uring
    assert.strictEqual(validateSeccompSpec('unconfined').safe, false);
    assert.strictEqual(validateSeccompSpec({ defaultAction: 'SCMP_ACT_ALLOW', syscalls: [] }).safe, false);
    const badAllow = validateSeccompSpec({
      defaultAction: 'SCMP_ACT_ERRNO',
      syscalls: [{ action: 'SCMP_ACT_ALLOW', names: ['read', 'io_uring_setup', 'ptrace'] }]
    });
    assert.strictEqual(badAllow.safe, false);
    assert.ok(badAllow.violations.some((v) => v.includes('io_uring_setup')));
    assert.ok(badAllow.violations.some((v) => v.includes('ptrace')));

    // auditRuncVersion: CVE-2025-31133 / CVE-2025-52565 / CVE-2025-52881 matrix
    for (const vuln of ['runc version 1.2.7\ncommit: abc', '1.3.2', '1.4.0-rc.2', '1.1.12']) {
      const r = auditRuncVersion(vuln);
      assert.strictEqual(r.status, 'CRITICAL', `Expected CRITICAL for ${vuln}`);
      assert.strictEqual(r.vulnerable, true);
      assert.deepStrictEqual(r.cves, ['CVE-2025-31133', 'CVE-2025-52565', 'CVE-2025-52881']);
    }
    for (const safe of ['runc version 1.2.8', '1.3.3', '1.4.0-rc.3', '1.4.0']) {
      const r = auditRuncVersion(safe);
      assert.strictEqual(r.status, 'PASS', `Expected PASS for ${safe}`);
      assert.strictEqual(r.vulnerable, false);
      assert.strictEqual(r.cves.length, 0);
    }
    const unk = auditRuncVersion('not-a-version');
    assert.strictEqual(unk.status, 'UNKNOWN');
    assert.strictEqual(unk.vulnerable, false);
  });

  console.log(`\n✅ SQL DDL Linter, SPDX License Auditor & Seccomp/runc Guard Suite: ${passed}/3 tests PASSED!`);
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ SQL Linter / License / Seccomp test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
