'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const logPiiScrubberService = require('../server/services/logPiiScrubberService');
const gracefulDrainService = require('../server/services/gracefulDrainService');

const {
  LogPiiScrubberService,
  SCRUB_RULES_ORDERED,
  isValidLuhn,
  scrubPayload,
  scrubStreamChunk,
  upsertScrubPolicy,
  getRedactionLedger
} = logPiiScrubberService;

const {
  GracefulDrainService,
  DRAIN_PHASES,
  auditShutdownReadiness,
  planOrderedDrain,
  advanceDrainState,
  listDrainPlans
} = gracefulDrainService;

/**
 * Verifies deterministic ordered PII scrubbing (OTel#49858/#36633/#37591/#50770),
 * Luhn PCI verification, deep span.events[] + numeric SSN traversal, chained pass
 * redaction.* ledger preservation, and NDJSON chunk scrubbing.
 * @param {string} tmpRoot
 */
function testLogPiiScrubber(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'pii-data');
  const svc = new LogPiiScrubberService({ dataDir });

  // 1. Strict deterministic rule order
  assert.deepStrictEqual(
    SCRUB_RULES_ORDERED.map((r) => r.id),
    ['JWT', 'API_TOKEN', 'PCI_PAN', 'IBAN', 'SSN', 'EMAIL', 'PHONE']
  );

  // 2. Luhn check accuracy: valid test Visa PAN vs invalid 16-digit order ID
  const validPan = '4532-0151-1283-0366';
  const invalidOrderId = '1234567890123456';
  assert.strictEqual(svc.isValidLuhn(validPan), true);
  assert.strictEqual(svc.isValidLuhn(invalidOrderId), false);

  // Dynamically construct fake token so GH013 secret scanning never trips
  const dynamicApiToken = ['sk', 'live', '99887766554433221100'].join('_');
  const dynamicJwt = [
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
    'eyJzdWIiOiJ1c2VyXzQyIn0',
    'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV'
  ].join('.');

  const otlpSpan = {
    traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
    attributes: {
      orderId: invalidOrderId,
      numericOrderId: 1234567890123456,
      userEmail: 'alice.smith@example.com',
      ssn: 123456789,
      apiKey: dynamicApiToken,
      auth: dynamicJwt,
      iban: 'DE89370400440532013000',
      phone: '+1-415-555-0199'
    },
    span: {
      events: [
        {
          name: 'checkout.submit',
          attributes: {
            note: `Charged card ${validPan} for bob@company.org`,
            numericPan: 4532015112830366
          }
        }
      ]
    }
  };

  // 3. Deterministic across 10 consecutive runs
  const firstRun = svc.scrubPayload(otlpSpan, { projectId: 'proj_obs', persist: true });
  assert.strictEqual(firstRun.ok, true);
  assert.ok(firstRun.redactedCount >= 8, `Expected >= 8 redactions, got ${firstRun.redactedCount}`);
  assert.ok(firstRun.redactedBytes > 0);
  assert.strictEqual(firstRun.scrubbed.attributes.orderId, invalidOrderId, 'Luhn-invalid order ID must NOT be redacted');
  assert.strictEqual(firstRun.scrubbed.attributes.numericOrderId, 1234567890123456);
  assert.strictEqual(firstRun.scrubbed.attributes.userEmail, '[REDACTED:EMAIL]');
  assert.strictEqual(firstRun.scrubbed.attributes.ssn, '[REDACTED:SSN]');
  assert.strictEqual(firstRun.scrubbed.attributes.apiKey, '[REDACTED:API_TOKEN]');
  assert.strictEqual(firstRun.scrubbed.attributes.auth, '[REDACTED:JWT]');
  assert.strictEqual(firstRun.scrubbed.attributes.iban, '[REDACTED:IBAN]');
  assert.strictEqual(firstRun.scrubbed.attributes.phone, '[REDACTED:PHONE]');
  assert.ok(firstRun.scrubbed.span.events[0].attributes.note.includes('[REDACTED:PCI_PAN]'));
  assert.ok(firstRun.scrubbed.span.events[0].attributes.note.includes('[REDACTED:EMAIL]'));
  assert.strictEqual(firstRun.scrubbed.span.events[0].attributes.numericPan, '[REDACTED:PCI_PAN]');

  const serializedFirst = JSON.stringify(firstRun.scrubbed);
  assert.ok(!serializedFirst.includes('alice.smith@example.com'));
  assert.ok(!serializedFirst.includes(validPan));
  assert.ok(!serializedFirst.includes(dynamicApiToken));

  for (let i = 0; i < 9; i += 1) {
    const repeat = svc.scrubPayload(otlpSpan);
    assert.strictEqual(JSON.stringify(repeat.scrubbed), serializedFirst, `Run #${i + 2} must be byte-identical`);
    assert.strictEqual(repeat.sha256Post, firstRun.sha256Post);
  }

  // 4. Chained 2nd pass preserves redaction.* ledger keys verbatim (otel-contrib#50770)
  const payloadWithLedger = {
    ...firstRun.scrubbed,
    'redaction.count': firstRun.redactedCount,
    redaction: {
      count: firstRun.redactedCount,
      bytes: firstRun.redactedBytes,
      categories: firstRun.categoryCounts
    }
  };
  const secondPass = svc.scrubPayload(payloadWithLedger);
  assert.strictEqual(secondPass.redactedCount, 0);
  assert.strictEqual(secondPass.scrubbed['redaction.count'], firstRun.redactedCount);
  assert.strictEqual(secondPass.scrubbed.redaction.count, firstRun.redactedCount);
  assert.strictEqual(secondPass.scrubbed.redaction.bytes, firstRun.redactedBytes);

  // 5. NDJSON chunk scrubbing & zero raw PII in ledger file on disk
  const chunk = [
    JSON.stringify({ msg: 'User carol@example.com logged in', card: validPan }),
    'plain log line phone 415-555-0123'
  ].join('\n');
  const chunkRes = svc.scrubStreamChunk(chunk, { projectId: 'proj_obs', persist: true });
  assert.strictEqual(chunkRes.linesProcessed, 2);
  assert.strictEqual(chunkRes.redactedCount, 3);
  assert.ok(!chunkRes.scrubbedChunk.includes('carol@example.com'));

  const ledgerFile = path.join(dataDir, 'pii-redaction-ledger.json');
  assert.ok(fs.existsSync(ledgerFile));
  const rawLedgerDisk = fs.readFileSync(ledgerFile, 'utf8');
  assert.ok(!rawLedgerDisk.includes('alice.smith@example.com'), 'Ledger file must NEVER contain raw PII');
  assert.ok(!rawLedgerDisk.includes(validPan), 'Ledger file must NEVER contain raw PAN');

  const ledger = svc.getRedactionLedger('proj_obs');
  assert.strictEqual(ledger.count, 2);
  assert.ok(ledger.totalRedactedCount >= 11);
}

/**
 * Verifies PID-1 shell-form CMD audit, LB drain race, stop grace check,
 * and strict 4-phase drain state machine refusing EMIT_SIGTERM until inFlight === 0 && lbDrained.
 * @param {string} tmpRoot
 */
function testGracefulDrainService(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'drain-data');
  const svc = new GracefulDrainService({ dataDir });

  assert.deepStrictEqual(Array.from(DRAIN_PHASES), [
    'FLIP_READINESS_503',
    'WAIT_LB_DRAIN',
    'DRAIN_INFLIGHT_JOBS',
    'EMIT_SIGTERM',
    'COMPLETED'
  ]);

  // 1. Shell-form CMD + lbDrainDelaySec: 0 + tight stopGracePeriodSec -> fails with all 3 codes
  const badAudit = svc.auditShutdownReadiness({
    dockerfile: 'FROM node:22-alpine\nWORKDIR /app\nCMD npm start\n',
    stopGracePeriodSec: 10,
    lbDrainDelaySec: 0,
    healthCheckIntervalSec: 5,
    activeQueueDepth: 20
  });
  assert.strictEqual(badAudit.ready, false);
  assert.ok(badAudit.codes.includes('PID1_SHELL_WRAPPER'));
  assert.ok(badAudit.codes.includes('LB_DRAIN_RACE'));
  assert.ok(badAudit.codes.includes('INSUFFICIENT_STOP_GRACE'));

  // 2. Clean exec-form CMD + sufficient LB drain + stop grace -> ready: true (100/100)
  const goodAudit = svc.auditShutdownReadiness({
    dockerfile: 'FROM node:22-alpine\nWORKDIR /app\nCMD ["node", "server/index.js"]\n',
    stopGracePeriodSec: 60,
    lbDrainDelaySec: 12,
    healthCheckIntervalSec: 5,
    activeQueueDepth: 10
  });
  assert.strictEqual(goodAudit.ready, true);
  assert.strictEqual(goodAudit.score, 100);
  assert.strictEqual(goodAudit.findings.length, 0);

  // 3. Ordered 4-phase drain state machine refuses EMIT_SIGTERM while inFlightJobs > 0 or !lbDrained
  const planned = svc.planOrderedDrain({
    projectId: 'proj_payments',
    serviceName: 'webhook-worker',
    inFlightHttp: 4,
    inFlightJobs: 3,
    lbDrainDelaySec: 10,
    maxDrainSec: 60,
    dryRun: true
  });
  assert.strictEqual(planned.ok, true);
  assert.strictEqual(planned.currentPhase, 'FLIP_READINESS_503');
  assert.strictEqual(planned.sigtermEmitted, false);

  const blockedJobs = svc.advanceDrainState(planned.drainId, {
    inFlightHttp: 0,
    inFlightJobs: 3,
    lbDrained: true,
    readinessFlipped: true
  });
  assert.strictEqual(blockedJobs.blocked, true);
  assert.strictEqual(blockedJobs.code, 'INFLIGHT_WORK_REMAINING');
  assert.strictEqual(blockedJobs.sigtermEmitted, false);

  const blockedLb = svc.advanceDrainState(planned.drainId, {
    inFlightHttp: 0,
    inFlightJobs: 0,
    lbDrained: false,
    readinessFlipped: true
  });
  assert.strictEqual(blockedLb.blocked, true);
  assert.strictEqual(blockedLb.code, 'INFLIGHT_WORK_REMAINING');
  assert.strictEqual(blockedLb.sigtermEmitted, false);

  const completed = svc.advanceDrainState(planned.drainId, {
    inFlightHttp: 0,
    inFlightJobs: 0,
    lbDrained: true,
    readinessFlipped: true
  });
  assert.strictEqual(completed.blocked, false);
  assert.strictEqual(completed.code, 'SIGTERM_EMITTED');
  assert.strictEqual(completed.currentPhase, 'COMPLETED');
  assert.strictEqual(completed.sigtermEmitted, true);

  assert.strictEqual(svc.listDrainPlans('proj_payments').length, 1);
  assert.ok(fs.existsSync(path.join(dataDir, 'graceful-drains.json')));
}

/**
 * Verifies BOTH singleton (`svc.fn`) AND destructured (`fn`) exports with dynamic `CULKIBO_DATA_DIR`.
 * @param {string} tmpRoot
 */
function testSingletonAndDestructuredExports(tmpRoot) {
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = path.join(tmpRoot, 'singleton-env');

  try {
    // LogPiiScrubberService singleton + destructured
    assert.strictEqual(isValidLuhn('4532015112830366'), true);
    assert.strictEqual(upsertScrubPolicy({ complianceProfiles: ['gdpr', 'pci'] }).ok, true);
    const s1 = scrubPayload({ email: 'test@example.com' }, { projectId: 'sp', persist: true });
    assert.strictEqual(s1.scrubbed.email, '[REDACTED:EMAIL]');
    assert.strictEqual(scrubStreamChunk('hello dev@example.com').redactedCount, 1);
    assert.strictEqual(getRedactionLedger('sp').count, 1);
    assert.strictEqual(logPiiScrubberService.getRedactionLedger('sp').count, 1);

    // GracefulDrainService singleton + destructured
    assert.strictEqual(auditShutdownReadiness({ dockerfile: 'CMD npm start', lbDrainDelaySec: 0 }).ready, false);
    const pl = planOrderedDrain({ projectId: 'sp', serviceName: 'api', inFlightJobs: 2 });
    assert.strictEqual(advanceDrainState(pl.drainId, { inFlightJobs: 2, lbDrained: true }).blocked, true);
    assert.strictEqual(gracefulDrainService.advanceDrainState(pl.drainId, { inFlightJobs: 0, lbDrained: true }).sigtermEmitted, true);
    assert.strictEqual(listDrainPlans('sp').length, 1);
  } finally {
    if (prevDataDir === undefined) {
      delete process.env.CULKIBO_DATA_DIR;
    } else {
      process.env.CULKIBO_DATA_DIR = prevDataDir;
    }
  }
}

async function runAllTests() {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c18-pii-drain-'));
  try {
    testLogPiiScrubber(tmpRoot);
    testGracefulDrainService(tmpRoot);
    testSingletonAndDestructuredExports(tmpRoot);
    console.log('✅ pii-scrubber-and-drain.test.js PASSED (deterministic OTLP PII scrub, Luhn PCI, chained ledger, PID-1/LB audit, 4-phase drain, singleton+destructured)');
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runAllTests().catch((err) => {
    console.error('❌ pii-scrubber-and-drain.test.js FAILED:', err);
    process.exit(1);
  });
}

module.exports = runAllTests;
