const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  evaluateDiskPressure,
  generateDaemonLogQuotaConfig,
  planPressureRemediation,
  listDiskPressureReports
} = require('../server/services/diskPressureGuardService');
const {
  CREDENTIAL_KINDS,
  registerCredentialMetadata,
  auditCredentialExpiries,
  checkSshAndJwtHygiene,
  listTrackedCredentials
} = require('../server/services/credentialExpiryWatchdogService');
const {
  checkEventSchemaEvolution,
  evaluatePoisonPillCircuit,
  quarantinePoisonMessage,
  listDlqQuarantine
} = require('../server/services/queueSchemaDlqService');

/**
 * Suite Cycle #19: Container Disk-Pressure & Inode Guard (Dokploy#4651/#2702),
 * Metadata-Only Credential Expiry Watchdog (Coolify#4702, Dokploy#2913/#5618),
 * and Event-Bus Schema Evolution / Poison-Pill DLQ Gate (Kafka KIP-1034 / BullMQ v6).
 *
 * Runs strictly inside an isolated `os.tmpdir()` `CULKIBO_DATA_DIR` — ZERO mutations to live `data/`.
 */
async function runTests() {
  console.log('--- Iniciando Tests de Disk Pressure Guard, Credential Watchdog y Queue Schema/DLQ Gate ---');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c19-'));
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
    // 1. CONTAINER DISK-PRESSURE, OVERLAY2 BLOAT & INODE EXHAUSTION GUARD
    // =========================================================================
    await runCase('1. diskPressureGuardService catches inode starvation at low GB, pg_wal runaway & emits daemon.json', async () => {
      // Low block usage (35%) but critical 96% inodes + 2 inactive replication slots + unrotated logs
      const evalRes = evaluateDiskPressure({
        nodeId: 'vps-eu-1',
        blockUsedPct: 35,
        inodeUsedPct: 96,
        overlay2Gb: 42,
        containerLogGb: 8.5,
        pgWalGb: 18,
        inactiveReplicationSlots: 2,
        diskTotalGb: 100
      });

      assert.strictEqual(evalRes.ok, true);
      assert.strictEqual(evalRes.status, 'CRITICAL');
      assert.strictEqual(evalRes.safe, false);
      assert.ok(evalRes.alertCodes.includes('INODE_EXHAUSTION_CRITICAL'));
      assert.ok(evalRes.alertCodes.includes('PG_WAL_SLOT_RUNAWAY'));
      assert.ok(evalRes.alertCodes.includes('UNROTATED_DOCKER_LOGS'));
      assert.ok(evalRes.alertCodes.includes('OVERLAY2_BLOAT'));

      const daemonCfg = generateDaemonLogQuotaConfig();
      assert.strictEqual(daemonCfg.config['log-opts']['max-size'], '10m');
      assert.strictEqual(daemonCfg.config['log-opts']['max-file'], '3');

      const plan = planPressureRemediation({ evaluation: evalRes });
      assert.strictEqual(plan.dryRun, true);
      assert.ok(plan.actionCount >= 3);
      assert.ok(plan.totalEstimatedRecoveryGb > 0);
      assert.strictEqual(listDiskPressureReports('vps-eu-1').length, 1);

      // Healthy node passes cleanly
      const healthy = evaluateDiskPressure({
        nodeId: 'vps-eu-2',
        blockUsedPct: 40,
        inodeUsedPct: 22,
        overlay2Gb: 8,
        containerLogGb: 0.4,
        pgWalGb: 1,
        inactiveReplicationSlots: 0,
        diskTotalGb: 100
      });
      assert.strictEqual(healthy.status, 'HEALTHY');
      assert.strictEqual(healthy.safe, true);
    });

    // =========================================================================
    // 2. METADATA-ONLY CREDENTIAL EXPIRY & SSH/JWT HYGIENE WATCHDOG
    // =========================================================================
    await runCase('2. credentialExpiryWatchdogService audits expiries/hygiene & persists ZERO raw secrets', async () => {
      assert.ok(CREDENTIAL_KINDS.includes('github_app'));
      const nowMs = Date.parse('2026-11-28T03:00:00Z');
      const dayMs = 86400000;
      const dynSecret = ['ghp', 'ShouldNeverBePersisted1234'].join('_');

      // dryRun default MUST NOT persist!
      const dryReg = registerCredentialMetadata({
        id: 'cred-dry',
        projectId: 'proj-sec',
        kind: 's3_iam',
        label: 'Nightly S3 Key',
        expiresAtIso: new Date(nowMs - 2 * dayMs).toISOString(),
        secret: dynSecret // must be stripped!
      });
      assert.strictEqual(dryReg.dryRun, true);
      assert.strictEqual(dryReg.persisted, false);
      assert.ok(dryReg.strippedSecretFields.includes('secret'));
      assert.ok(!JSON.stringify(dryReg).includes(dynSecret));
      assert.strictEqual(listTrackedCredentials('proj-sec').length, 0);

      // Live registration (dryRun: false) persists metadata only (0 raw secrets on disk!)
      registerCredentialMetadata({
        id: 's3-expired',
        projectId: 'proj-sec',
        kind: 's3_iam',
        label: 'S3 Backup Cert',
        expiresAtIso: new Date(nowMs - 1 * dayMs).toISOString(),
        token: dynSecret,
        dryRun: false
      });
      registerCredentialMetadata({
        id: 'oauth-crit',
        projectId: 'proj-sec',
        kind: 'oauth',
        label: 'Google OAuth Secret',
        expiresAtIso: new Date(nowMs + 5 * dayMs).toISOString(),
        dryRun: false
      });
      registerCredentialMetadata({
        id: 'acme-ok',
        projectId: 'proj-sec',
        kind: 'acme_cert',
        label: 'Wildcard TLS',
        expiresAtIso: new Date(nowMs + 75 * dayMs).toISOString(),
        dryRun: false
      });

      const storeRaw = fs.readFileSync(path.join(tmpDir, 'data', 'credential-watchdog.json'), 'utf8');
      assert.ok(!storeRaw.includes(dynSecret), 'Raw secret leaked into credential-watchdog.json!');

      const audit = auditCredentialExpiries({ projectId: 'proj-sec', nowIso: new Date(nowMs).toISOString() });
      assert.strictEqual(audit.ok, true);
      assert.strictEqual(audit.healthy, false);
      assert.strictEqual(audit.counts.EXPIRED, 1);
      assert.strictEqual(audit.counts.CRITICAL, 1);
      assert.strictEqual(audit.counts.HEALTHY, 1);

      // SSH / NTP JWT / STS / Log hygiene checks (Coolify#4702, Dokploy#2913/#5618)
      const badHygiene = checkSshAndJwtHygiene({
        clockSkewSec: 90,
        sshKeyMode: '0777',
        usesTempStsToken: true,
        logsContainInstallToken: true
      });
      assert.strictEqual(badHygiene.safe, false);
      assert.ok(badHygiene.findingCodes.includes('CLOCK_SKEW_JWT_FAILURE'));
      assert.ok(badHygiene.findingCodes.includes('INSECURE_SSH_KEY_MODE'));
      assert.ok(badHygiene.findingCodes.includes('EPHEMERAL_BACKUP_CREDENTIAL'));
      assert.ok(badHygiene.findingCodes.includes('BUILD_LOG_INSTALL_TOKEN_LEAK'));

      const okHygiene = checkSshAndJwtHygiene({ clockSkewSec: 2, sshKeyMode: '0600' });
      assert.strictEqual(okHygiene.safe, true);
    });

    // =========================================================================
    // 3. EVENT-BUS / QUEUE SCHEMA EVOLUTION & POISON-PILL DLQ GATE
    // =========================================================================
    await runCase('3. queueSchemaDlqService blocks breaking schema evolution, detects DLQ_SCHEMA_DEADLOCK & quarantines poison pills', async () => {
      const baseSchema = {
        type: 'object',
        required: ['orderId'],
        properties: {
          orderId: { type: 'string' },
          totalCents: { type: ['integer', 'null'] }
        }
      };

      // Adding required field without default + narrowing union -> incompatible!
      const badNext = {
        type: 'object',
        required: ['orderId', 'tenantId'],
        properties: {
          orderId: { type: 'string' },
          totalCents: { type: 'integer' },
          tenantId: { type: 'string' }
        }
      };
      const badEvo = checkEventSchemaEvolution({
        format: 'jsonschema',
        baseSchema,
        nextSchema: badNext,
        compatibilityMode: 'BACKWARD'
      });
      assert.strictEqual(badEvo.compatible, false);
      const evoCodes = new Set(badEvo.breakingChanges.map((c) => c.code));
      assert.ok(evoCodes.has('REQUIRED_FIELD_ADDED_NO_DEFAULT'));
      assert.ok(evoCodes.has('UNION_TYPE_NARROWED'));

      // Adding optional or defaulted field passes BACKWARD compatibility!
      const goodNext = {
        type: 'object',
        required: ['orderId', 'currency'],
        properties: {
          orderId: { type: 'string' },
          totalCents: { type: ['integer', 'null'] },
          currency: { type: 'string', default: 'USD' },
          promoCode: { type: 'string' }
        }
      };
      const goodEvo = checkEventSchemaEvolution({
        format: 'jsonschema',
        baseSchema,
        nextSchema: goodNext,
        compatibilityMode: 'BACKWARD'
      });
      assert.strictEqual(goodEvo.compatible, true);

      // Poison-pill circuit breaker + KIP-1034 DLQ raw passthrough guard
      const tripped = evaluatePoisonPillCircuit({
        queueName: 'orders.created',
        totalDelivered: 20,
        failedCount: 6,
        consecutivePoisonCount: 5,
        dlqRawPassthrough: false
      });
      assert.strictEqual(tripped.healthy, false);
      assert.strictEqual(tripped.circuitOpen, true);
      assert.ok(tripped.findingCodes.includes('DLQ_SCHEMA_DEADLOCK'));
      assert.ok(tripped.findingCodes.includes('POISON_PILL_CIRCUIT_OPEN'));

      // Quarantine defaults dryRun: true, then persists opaque raw bytes when dryRun: false
      const rawBroken = Buffer.from('{not valid json!!!', 'utf8').toString('base64');
      const dryQ = quarantinePoisonMessage({
        queueName: 'orders.created',
        messageId: 'msg-901',
        rawPayloadBase64: rawBroken,
        errorCode: 'UNRESOLVED_UNION_EXCEPTION'
      });
      assert.strictEqual(dryQ.dryRun, true);
      assert.strictEqual(dryQ.persisted, false);
      assert.strictEqual(listDlqQuarantine('orders.created').length, 0);

      const liveQ = quarantinePoisonMessage({
        queueName: 'orders.created',
        messageId: 'msg-901',
        rawPayloadBase64: rawBroken,
        errorCode: 'UNRESOLVED_UNION_EXCEPTION',
        dryRun: false
      });
      assert.strictEqual(liveQ.dryRun, false);
      assert.strictEqual(liveQ.persisted, true);
      assert.strictEqual(listDlqQuarantine('orders.created').length, 1);
    });

    console.log(`\n✅ Disk Pressure Guard, Credential Watchdog & Queue Schema/DLQ Suite: ${passed}/3 tests PASSED!`);
  } finally {
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ Disk/Creds/QueueDLQ test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
