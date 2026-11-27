const assert = require('assert');

const { RULES: IMAGE_RULES, auditDockerfileAndLayers } = require('../server/services/imageBloatAuditor');
const { PII_PATTERNS, maskValue, maskDataset } = require('../server/services/piiMaskerService');
const { FAILURE_CLASSES, computeBackoffSec, classifyContainerFailure } = require('../server/services/oomForensicsService');

/**
 * Helper Luhn validator for synthetic masked credit cards (`4000-0000-0000-XXXX`).
 * @param {string} cardStr
 */
function isValidLuhn(cardStr) {
  const digits = String(cardStr || '').replace(/\D/g, '');
  if (digits.length < 13) return false;
  let sum = 0;
  for (let i = digits.length - 1, dbl = false; i >= 0; i--, dbl = !dbl) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

/**
 * Suite Cycle #13: Image Bloat/Secret Auditor, Deterministic PII Masker & OOM Forensics Classifier.
 * Pure in-memory — ZERO mutations to live `data/`.
 */
async function runTests() {
  console.log('--- Iniciando Tests de Image Bloat Auditor, PII Masker y OOM Forensics ---');

  let passed = 0;
  const runCase = async (name, fn) => {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  };

  // =========================================================================
  // 1. IMAGE LAYER BLOAT & SECRET-IN-LAYER AUDITOR (8 RULES)
  // =========================================================================
  await runCase('1. imageBloatAuditor catches all 8 bloat/secret rules, redacts leaks & scores clean multi-stage >= 90', async () => {
    assert.strictEqual(IMAGE_RULES.length, 8);

    // Build synthetic tokens dynamically to stay 100% Push-Protection clean
    const fakeStripe = ['sk', 'live', '99887766554433221100'].join('_');
    const fakeGithub = ['ghp', 'AaBbCcDdEeFf0011223344'].join('_');

    const leakyDockerfile = [
      'FROM node:22',
      'WORKDIR /app',
      `ENV API_KEY=${fakeStripe}`,
      `ARG GITHUB_TOKEN=${fakeGithub}`,
      'COPY .npmrc /root/.npmrc',
      'ADD config.json /app/config.json',
      'COPY . .',
      'RUN apt-get update && apt-get install -y curl',
      'RUN npm install',
      'RUN rm -rf /tmp/build-artifacts',
      'CMD ["node", "server.js"]'
    ].join('\n');

    const bad = auditDockerfileAndLayers({
      dockerfile: leakyDockerfile,
      historyLayers: [
        { createdBy: 'COPY . /app', sizeBytes: 120 * 1024 * 1024 },
        { createdBy: 'RUN rm -rf /app/tmp', sizeBytes: 1024 }
      ],
      stack: 'node'
    });

    assert.strictEqual(bad.ok, true);
    assert.ok(bad.efficiencyScore < 50, `Expected leaky score < 50, got ${bad.efficiencyScore}`);
    assert.ok(bad.estimatedSavingsMb > 100, `Expected estimatedSavingsMb > 100, got ${bad.estimatedSavingsMb}`);
    assert.ok(bad.wastedBytes > 0);
    assert.ok(bad.secretLeaks.length >= 3, `Expected >= 3 secret leaks, got ${bad.secretLeaks.length}`);

    // CRITICAL: raw secrets MUST be redacted everywhere in the output!
    const serialized = JSON.stringify(bad);
    assert.ok(!serialized.includes(fakeStripe), 'Raw Stripe token leaked in auditor output!');
    assert.ok(!serialized.includes(fakeGithub), 'Raw GitHub token leaked in auditor output!');

    const ruleIds = new Set(bad.findings.map((f) => f.rule));
    for (const expected of [
      'SECRET_IN_ENV_OR_ARG',
      'CROSS_LAYER_DELETE_WASTE',
      'UNDELETED_PACKAGE_CACHE',
      'MISSING_MULTI_STAGE',
      'COPY_ALL_BEFORE_LOCKFILE',
      'ADD_INSTEAD_OF_COPY',
      'HEAVY_BASE_IMAGE',
      'MISSING_NON_ROOT_USER'
    ]) {
      assert.ok(ruleIds.has(expected), `Missing expected rule: ${expected}`);
    }
    assert.ok(bad.multiStageTemplate.includes('FROM gcr.io/distroless/nodejs22-debian12:nonroot'));

    // Clean multi-stage distroless non-root Dockerfile MUST score >= 90 with 0 secretLeaks
    const cleanDockerfile = [
      'FROM node:22-alpine AS builder',
      'WORKDIR /app',
      'COPY package.json package-lock.json ./',
      'RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci',
      'COPY . .',
      'RUN npm run build',
      'FROM gcr.io/distroless/nodejs22-debian12:nonroot',
      'WORKDIR /app',
      'COPY --from=builder /app/dist ./dist',
      'CMD ["dist/index.js"]'
    ].join('\n');

    const good = auditDockerfileAndLayers({ dockerfile: cleanDockerfile, stack: 'node' });
    assert.strictEqual(good.ok, true);
    assert.strictEqual(good.secretLeaks.length, 0);
    assert.ok(good.efficiencyScore >= 90, `Expected clean score >= 90, got ${good.efficiencyScore}`);
  });

  // =========================================================================
  // 2. DETERMINISTIC PR-PREVIEW PII MASKER + PG_ANONYMIZER DDL
  // =========================================================================
  await runCase('2. piiMaskerService masks all PII deterministically (FK-safe, Luhn-valid, zero leaks, pg_anonymizer DDL)', async () => {
    assert.ok(PII_PATTERNS.email instanceof RegExp);
    const seed = 'pr-42-seed';

    // Format + determinism checks
    const em1 = maskValue('alice@acme.io', { type: 'email', seed });
    const em2 = maskValue('ALICE@ACME.IO', { type: 'email', seed });
    assert.strictEqual(em1, em2, 'Email pseudonymization must preserve FK join determinism');
    assert.match(em1, /^u_[0-9a-f]{8}@masked\.invalid$/);

    const ph = maskValue('+34 612 345 678', { type: 'phone', seed });
    assert.match(ph, /^\+1-555-\d{4}$/);

    const ssn = maskValue('123-45-6789', { type: 'ssn', seed });
    assert.match(ssn, /^000-00-\d{4}$/);

    const cc = maskValue('4532-0151-1283-0366', { type: 'credit_card', seed });
    assert.match(cc, /^4000-0000-0000-\d{4}$/);
    assert.strictEqual(isValidLuhn(cc), true, `Synthetic card must be Luhn-valid: ${cc}`);

    const iban = maskValue('ES9121000418450200051332', { type: 'iban', seed });
    assert.match(iban, /^DE00000000000000\d{6}$/);

    const ip = maskValue('203.0.113.45', { type: 'ipv4', seed });
    assert.match(ip, /^192\.0\.2\.(?:[1-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-4])$/);

    // Dynamic test secrets (Push-Protection clean)
    const fakeJwt = ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiJ1c2VyXzEifQ', 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV'].join('.');
    const fakeApiKey = ['sk', 'live', 'abcde1234567890'].join('_');
    assert.strictEqual(maskValue(fakeJwt, { type: 'secret_token', seed }), '[MASKED_SECRET]');

    // Cross-table FK join determinism + explicit column rules + zero PII leak check
    const users = [
      {
        id: 101,
        full_name: 'Maria Garcia',
        email: 'maria@example.com',
        phone: '+1 (415) 890-1234',
        ssn: '987-65-4321',
        card: '4242-4242-4242-4242',
        iban: 'ES9121000418450200051332',
        last_ip: '8.8.4.4',
        api_token: fakeApiKey,
        session_jwt: fakeJwt,
        secret_note: 'keep-null',
        plan: 'pro'
      }
    ];
    const orders = [
      { order_id: 5001, customer_email: 'maria@example.com', amount: 49.99 }
    ];

    const maskedUsers = maskDataset({
      rows: users,
      seed,
      tableName: 'public.users',
      rules: {
        full_name: 'fake_name',
        secret_note: 'nullify',
        plan: 'preserve'
      }
    });
    const maskedOrders = maskDataset({ rows: orders, seed, tableName: 'public.orders' });

    assert.strictEqual(maskedUsers.ok, true);
    assert.strictEqual(maskedUsers.zeroPiiLeaked, true);
    assert.ok(maskedUsers.maskedCount >= 9);
    assert.strictEqual(maskedUsers.maskedRows[0].id, 101);
    assert.strictEqual(maskedUsers.maskedRows[0].plan, 'pro');
    assert.strictEqual(maskedUsers.maskedRows[0].secret_note, null);
    assert.notStrictEqual(maskedUsers.maskedRows[0].full_name, 'Maria Garcia');
    assert.strictEqual(maskedUsers.maskedRows[0].api_token, '[MASKED_SECRET]');
    assert.strictEqual(maskedUsers.maskedRows[0].session_jwt, '[MASKED_SECRET]');
    // FK Join determinism across two independent tables!
    assert.strictEqual(
      maskedUsers.maskedRows[0].email,
      maskedOrders.maskedRows[0].customer_email,
      'Same email across users & orders must hash to identical pseudonym under same seed'
    );
    // pg_anonymizer SECURITY LABEL DDL
    assert.ok(maskedUsers.pgAnonDdl.includes('SECURITY LABEL FOR anon ON COLUMN public.users.email'));
    assert.ok(maskedUsers.pgAnonDdl.includes('CREATE EXTENSION IF NOT EXISTS anon'));

    // SQL dump masking with zero leaks
    const sqlDump = `INSERT INTO customers (id, email, phone, token) VALUES (1, 'maria@example.com', '+1-415-890-1234', '${fakeApiKey}');`;
    const maskedSqlRes = maskDataset({ sqlDump, seed });
    assert.strictEqual(maskedSqlRes.zeroPiiLeaked, true);
    assert.ok(!maskedSqlRes.maskedSql.includes('maria@example.com'));
    assert.ok(!maskedSqlRes.maskedSql.includes(fakeApiKey));
    assert.ok(maskedSqlRes.maskedSql.includes(maskedUsers.maskedRows[0].email));
    assert.ok(maskedSqlRes.pgAnonDdl.includes('SECURITY LABEL FOR anon ON COLUMN customers.email'));
  });

  // =========================================================================
  // 3. CONTAINER OOM-KILL FORENSICS & CRASH-LOOP CLASSIFIER (8 CLASSES)
  // =========================================================================
  await runCase('3. oomForensicsService classifies all 8 failure modes & computes capped backoff', async () => {
    assert.strictEqual(FAILURE_CLASSES.length, 8);

    // Exponential capped backoff
    assert.strictEqual(computeBackoffSec(0), 0);
    assert.strictEqual(computeBackoffSec(1), 5);
    assert.strictEqual(computeBackoffSec(2), 10);
    assert.strictEqual(computeBackoffSec(3), 20);
    assert.strictEqual(computeBackoffSec(10), 300);

    // 1. STALE_HISTORICAL_TASK_IGNORED (Portainer false rollback guard!)
    const stale = classifyContainerFailure({
      containerName: 'api-old',
      exitCode: 137,
      oomKilled: true,
      cgroupOomKills: 2,
      historicalOnly: true
    });
    assert.strictEqual(stale.classification, 'STALE_HISTORICAL_TASK_IGNORED');
    assert.strictEqual(stale.ignoreForRollback, true);
    assert.strictEqual(stale.severity, 'info');

    // 2. CGROUP_OOM_KILL (137 + oomKilled -> 1.5x RAM bump)
    const oom = classifyContainerFailure({
      containerName: 'api-web',
      exitCode: 137,
      oomKilled: true,
      memoryLimitMb: 512,
      memoryPeakMb: 510,
      restartCount: 3
    });
    assert.strictEqual(oom.classification, 'CGROUP_OOM_KILL');
    assert.strictEqual(oom.severity, 'critical');
    assert.strictEqual(oom.ignoreForRollback, false);
    assert.strictEqual(oom.recommendedMemoryMb, 768);
    assert.strictEqual(oom.backoffSec, 20);

    // 3. FORCED_SIGKILL_TIMEOUT (137 + !oomKilled + cgroupOomKills === 0)
    const sigkill = classifyContainerFailure({
      containerName: 'worker-1',
      exitCode: 137,
      oomKilled: false,
      cgroupOomKills: 0,
      memoryLimitMb: 512
    });
    assert.strictEqual(sigkill.classification, 'FORCED_SIGKILL_TIMEOUT');
    assert.strictEqual(sigkill.severity, 'high');
    assert.strictEqual(sigkill.recommendedMemoryMb, null);

    // 4. SEGFAULT_ARCH_OR_NATIVE (139)
    const segfault = classifyContainerFailure({ exitCode: 139 });
    assert.strictEqual(segfault.classification, 'SEGFAULT_ARCH_OR_NATIVE');
    assert.strictEqual(segfault.severity, 'critical');

    // 5. ABORT_HEAP_OR_ASSERT (134)
    const abort = classifyContainerFailure({ exitCode: 134 });
    assert.strictEqual(abort.classification, 'ABORT_HEAP_OR_ASSERT');
    assert.strictEqual(abort.severity, 'high');

    // 6. GRACEFUL_SIGTERM_EXITED (143)
    const sigterm = classifyContainerFailure({ exitCode: 143 });
    assert.strictEqual(sigterm.classification, 'GRACEFUL_SIGTERM_EXITED');
    assert.strictEqual(sigterm.severity, 'info');
    assert.strictEqual(sigterm.ignoreForRollback, true);

    // 7. EXEC_OR_ENTRYPOINT_MISSING (126 & 127)
    assert.strictEqual(classifyContainerFailure({ exitCode: 126 }).classification, 'EXEC_OR_ENTRYPOINT_MISSING');
    assert.strictEqual(classifyContainerFailure({ exitCode: 127 }).classification, 'EXEC_OR_ENTRYPOINT_MISSING');

    // 8. HEALTHCHECK_CRASH_LOOP (unhealthy while app logs listening)
    const hc = classifyContainerFailure({
      containerName: 'web-1',
      exitCode: 143,
      healthStatus: 'unhealthy',
      recentLogs: 'Server listening on http://127.0.0.1:3000',
      restartCount: 4
    });
    assert.strictEqual(hc.classification, 'HEALTHCHECK_CRASH_LOOP');
    assert.strictEqual(hc.severity, 'high');
    assert.strictEqual(hc.backoffSec, 40);
  });

  console.log(`\n✅ Image Bloat Auditor, PII Masker & OOM Forensics Suite: ${passed}/3 tests PASSED!`);
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ Image/PII/OOM test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
