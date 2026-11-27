'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const cronLeaseService = require('../server/services/cronLeaseService');
const oncallEscalationService = require('../server/services/oncallEscalationService');

const {
  CronLeaseService,
  acquireCronLease,
  renewCronLease,
  completeCronLease,
  listCronLeases
} = cronLeaseService;

const {
  OnCallEscalationService,
  savePolicy,
  listPolicies,
  resolveCurrentOnCall,
  ingestAlert,
  acknowledgeIncident,
  evaluateEscalations,
  listIncidents
} = oncallEscalationService;

/**
 * Verifies distributed cron fencing-token leases, double-fire slot guard,
 * TTL expiry reclamation, and stale fencing-token / holder rejection.
 * @param {string} tmpRoot
 */
function testCronLeaseService(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'cron-data');
  const svc = new CronLeaseService({ dataDir });
  const t0 = Date.UTC(2026, 10, 27, 0, 0, 0);
  const slotA = '2026-11-27T00:00:00Z';
  const slotB = '2026-11-27T01:00:00Z';

  // 1. First acquire succeeds with fencingToken === 1
  const acq1 = svc.acquireCronLease({
    jobId: 'billing-daily',
    scheduleSlotIso: slotA,
    holderId: 'replica-1',
    ttlSec: 300,
    nowMs: t0
  });
  assert.strictEqual(acq1.ok, true);
  assert.strictEqual(acq1.acquired, true);
  assert.strictEqual(acq1.fencingToken, 1);
  assert.ok(acq1.leaseId && acq1.lease && acq1.lease.status === 'active');

  // Verify persisted store exists in isolated dir
  assert.ok(fs.existsSync(path.join(dataDir, 'cron-leases.json')));

  // 2. Concurrent active lease on same jobId is rejected (ALREADY_RUNNING)
  const dupConcurrent = svc.acquireCronLease({
    jobId: 'billing-daily',
    scheduleSlotIso: slotA,
    holderId: 'replica-2',
    ttlSec: 300,
    nowMs: t0 + 5000
  });
  assert.strictEqual(dupConcurrent.acquired, false);
  assert.strictEqual(dupConcurrent.reason, 'ALREADY_RUNNING');
  assert.ok(dupConcurrent.activeLease);
  assert.strictEqual(dupConcurrent.activeLease.leaseId, acq1.leaseId);

  // 3. Renew rejects wrong holder, accepts right holder
  const badRenew = svc.renewCronLease(acq1.leaseId, {
    holderId: 'replica-2',
    extendSec: 300,
    nowMs: t0 + 60000
  });
  assert.strictEqual(badRenew.ok, false);
  assert.strictEqual(badRenew.reason, 'HOLDER_MISMATCH');

  const goodRenew = svc.renewCronLease(acq1.leaseId, {
    holderId: 'replica-1',
    extendSec: 300,
    nowMs: t0 + 60000
  });
  assert.strictEqual(goodRenew.ok, true);
  assert.strictEqual(goodRenew.lease.expiresAtMs, t0 + 60000 + 300000);

  // 4. Complete rejects stale fencingToken, wrong holder, unknown leaseId
  const badToken = svc.completeCronLease(acq1.leaseId, {
    holderId: 'replica-1',
    fencingToken: 99,
    status: 'succeeded',
    nowMs: t0 + 70000
  });
  assert.strictEqual(badToken.ok, false);
  assert.strictEqual(badToken.reason, 'STALE_FENCING_TOKEN');

  const badHolder = svc.completeCronLease(acq1.leaseId, {
    holderId: 'replica-2',
    fencingToken: 1,
    status: 'succeeded',
    nowMs: t0 + 70000
  });
  assert.strictEqual(badHolder.ok, false);
  assert.strictEqual(badHolder.reason, 'HOLDER_MISMATCH');

  const unknownLease = svc.completeCronLease('cl_nonexistent', {
    holderId: 'replica-1',
    fencingToken: 1,
    status: 'succeeded',
    nowMs: t0 + 70000
  });
  assert.strictEqual(unknownLease.ok, false);
  assert.strictEqual(unknownLease.reason, 'LEASE_NOT_FOUND');

  // 5. Valid completion succeeds
  const done1 = svc.completeCronLease(acq1.leaseId, {
    holderId: 'replica-1',
    fencingToken: 1,
    status: 'succeeded',
    nowMs: t0 + 80000
  });
  assert.strictEqual(done1.ok, true);
  assert.strictEqual(done1.status, 'succeeded');

  // 6. Repeat execution of the SAME scheduleSlotIso (even formatted with .000Z!) is rejected (ALREADY_EXECUTED_SLOT)
  const repeatSlot = svc.acquireCronLease({
    jobId: 'billing-daily',
    scheduleSlotIso: '2026-11-27T00:00:00.000Z',
    holderId: 'replica-2',
    ttlSec: 300,
    nowMs: t0 + 180000
  });
  assert.strictEqual(repeatSlot.acquired, false);
  assert.strictEqual(repeatSlot.reason, 'ALREADY_EXECUTED_SLOT');
  assert.ok(repeatSlot.completedLease);
  assert.strictEqual(repeatSlot.completedLease.leaseId, acq1.leaseId);

  // 7. Next slot acquires fencingToken === 2, then expires and is auto-reclaimed with fencingToken === 3
  const acq2 = svc.acquireCronLease({
    jobId: 'billing-daily',
    scheduleSlotIso: slotB,
    holderId: 'replica-stale',
    ttlSec: 60,
    nowMs: t0 + 3600000
  });
  assert.strictEqual(acq2.acquired, true);
  assert.strictEqual(acq2.fencingToken, 2);

  // Advance past TTL -> replica-3 reclaims expired lease with fencingToken === 3
  const acq3 = svc.acquireCronLease({
    jobId: 'billing-daily',
    scheduleSlotIso: slotB,
    holderId: 'replica-3',
    ttlSec: 300,
    nowMs: t0 + 3600000 + 61000
  });
  assert.strictEqual(acq3.acquired, true);
  assert.strictEqual(acq3.reclaimed, true);
  assert.strictEqual(acq3.fencingToken, 3);
  assert.strictEqual(acq3.lease.reclaimedFromLeaseId, acq2.leaseId);

  // Zombie replica-stale tries to complete its superseded lease with token 2 -> STALE_FENCING_TOKEN!
  const zombieComplete = svc.completeCronLease(acq2.leaseId, {
    holderId: 'replica-stale',
    fencingToken: 2,
    status: 'succeeded',
    nowMs: t0 + 3600000 + 65000
  });
  assert.strictEqual(zombieComplete.ok, false);
  assert.strictEqual(zombieComplete.reason, 'STALE_FENCING_TOKEN');

  // Replica-3 completes with token 3 -> succeeds!
  const done3 = svc.completeCronLease(acq3.leaseId, {
    holderId: 'replica-3',
    fencingToken: 3,
    status: 'succeeded',
    nowMs: t0 + 3600000 + 70000
  });
  assert.strictEqual(done3.ok, true);

  // 8. Failed slot CAN be retried with incremented fencingToken === 4
  const slotC = '2026-11-27T02:00:00Z';
  const acqFail = svc.acquireCronLease({
    jobId: 'billing-daily',
    scheduleSlotIso: slotC,
    holderId: 'replica-1',
    ttlSec: 120,
    nowMs: t0 + 7200000
  });
  assert.strictEqual(acqFail.fencingToken, 4);
  const failedRes = svc.completeCronLease(acqFail.leaseId, {
    holderId: 'replica-1',
    fencingToken: 4,
    status: 'failed',
    nowMs: t0 + 7205000
  });
  assert.strictEqual(failedRes.ok, true);
  assert.strictEqual(failedRes.status, 'failed');

  const retrySlotC = svc.acquireCronLease({
    jobId: 'billing-daily',
    scheduleSlotIso: slotC,
    holderId: 'replica-2',
    ttlSec: 120,
    nowMs: t0 + 7210000
  });
  assert.strictEqual(retrySlotC.acquired, true);
  assert.strictEqual(retrySlotC.fencingToken, 5);

  const leases = svc.listCronLeases('billing-daily', t0 + 7215000);
  assert.strictEqual(leases.length, 5);
  assert.strictEqual(leases[0].fencingToken, 5);
}

/**
 * Verifies incident fingerprint dedup, flapping suppression, deterministic on-call shift rotation,
 * Tier 1 -> Tier 2 -> Tier 3 ack-timeout escalation, and immediate escalation freeze on ack.
 * @param {string} tmpRoot
 */
function testOnCallEscalationService(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'oncall-data');
  const svc = new OnCallEscalationService({ dataDir });
  const t0 = Date.UTC(2026, 10, 27, 8, 0, 0);

  // 1. Save policy with 3 tiers & deterministic rotation
  const policy = svc.savePolicy({
    id: 'pol-core-sre',
    name: 'Core SRE Escalation',
    shiftDurationHours: 24,
    rotationStartMs: t0,
    ackTimeoutSec: 300,
    flappingWindowSec: 600,
    flappingThreshold: 3,
    tiers: [
      { tier: 1, responders: ['alice', 'bob'] },
      { tier: 2, responders: ['charlie'] },
      { tier: 3, responders: ['vp-eng'] }
    ]
  });
  assert.strictEqual(policy.id, 'pol-core-sre');
  assert.strictEqual(svc.listPolicies().length, 1);
  assert.ok(fs.existsSync(path.join(dataDir, 'oncall-policies.json')));

  // 2. Deterministic shift rotation across days
  const shift0 = svc.resolveCurrentOnCall(policy.id, t0);
  const shift1 = svc.resolveCurrentOnCall(policy.id, t0 + 24 * 3600000);
  const shift2 = svc.resolveCurrentOnCall(policy.id, t0 + 48 * 3600000);
  assert.strictEqual(shift0.responder, 'alice');
  assert.strictEqual(shift1.responder, 'bob');
  assert.strictEqual(shift2.responder, 'alice');

  // 3. Fingerprint deduplication: 3 firing alerts collapse into 1 incident with occurrences === 3
  const a1 = svc.ingestAlert({
    policyId: policy.id,
    fingerprint: 'db-primary-down',
    projectId: 'proj_payments',
    severity: 'critical',
    title: 'Primary Postgres unreachable',
    state: 'firing',
    nowMs: t0
  });
  assert.strictEqual(a1.created, true);
  assert.strictEqual(a1.deduplicated, false);
  assert.strictEqual(a1.suppressed, false);
  assert.strictEqual(a1.paged, true);
  assert.ok(a1.incident);
  assert.strictEqual(a1.incident.occurrences, 1);
  assert.strictEqual(a1.incident.assignedResponder, 'alice');

  const a2 = svc.ingestAlert({
    policyId: policy.id,
    fingerprint: 'db-primary-down',
    projectId: 'proj_payments',
    severity: 'critical',
    title: 'Primary Postgres unreachable',
    state: 'firing',
    nowMs: t0 + 15000
  });
  assert.strictEqual(a2.created, false);
  assert.strictEqual(a2.deduplicated, true);
  assert.strictEqual(a2.suppressed, true);
  assert.strictEqual(a2.paged, false);
  assert.strictEqual(a2.incident.id, a1.incident.id);
  assert.strictEqual(a2.incident.occurrences, 2);

  const a3 = svc.ingestAlert({
    policyId: policy.id,
    fingerprint: 'db-primary-down',
    projectId: 'proj_payments',
    severity: 'critical',
    title: 'Primary Postgres unreachable',
    state: 'firing',
    nowMs: t0 + 30000
  });
  assert.strictEqual(a3.deduplicated, true);
  assert.strictEqual(a3.suppressed, true);
  assert.strictEqual(a3.incident.occurrences, 3);
  assert.strictEqual(svc.listIncidents({ activeOnly: true }).length, 1);

  // 4. Tier 1 -> Tier 2 -> Tier 3 escalation on ackTimeoutSec (300s)
  const evalEarly = svc.evaluateEscalations(t0 + 299000);
  assert.strictEqual(evalEarly.escalatedCount, 0);

  const evalTier2 = svc.evaluateEscalations(t0 + 300000);
  assert.strictEqual(evalTier2.escalatedCount, 1);
  assert.strictEqual(evalTier2.escalated[0].fromTier, 1);
  assert.strictEqual(evalTier2.escalated[0].toTier, 2);
  assert.strictEqual(evalTier2.escalated[0].assignedResponder, 'charlie');

  // Acknowledge at Tier 2 -> freezes escalation immediately (NEVER escalates to Tier 3!)
  const acked = svc.acknowledgeIncident(a1.incident.id, {
    actor: 'charlie',
    nowMs: t0 + 320000
  });
  assert.strictEqual(acked.status, 'acknowledged');
  assert.strictEqual(acked.acknowledgedBy, 'charlie');
  assert.strictEqual(acked.acknowledgedAtMs, t0 + 320000);

  const evalAfterAck = svc.evaluateEscalations(t0 + 1200000);
  assert.strictEqual(evalAfterAck.escalatedCount, 0);

  // Unacknowledged incident escalates all the way Tier 1 -> Tier 2 -> Tier 3 and stops at maxTier
  const unack = svc.ingestAlert({
    policyId: policy.id,
    fingerprint: 'redis-oom',
    severity: 'critical',
    title: 'Redis OOM',
    state: 'firing',
    nowMs: t0 + 1300000
  });
  assert.ok(unack.incident);
  const esc2 = svc.evaluateEscalations(t0 + 1600000);
  assert.strictEqual(esc2.escalatedCount, 1);
  assert.strictEqual(esc2.escalated[0].toTier, 2);

  const esc3 = svc.evaluateEscalations(t0 + 1900000);
  assert.strictEqual(esc3.escalatedCount, 1);
  assert.strictEqual(esc3.escalated[0].toTier, 3);
  assert.strictEqual(esc3.escalated[0].assignedResponder, 'vp-eng');

  // Already at max tier -> no further escalation
  const escMax = svc.evaluateEscalations(t0 + 2500000);
  assert.strictEqual(escMax.escalatedCount, 0);

  // 5. Flapping damper: >= 3 firing <-> resolved transitions within flappingWindowSec triggers FLAPPING_SUPPRESSED
  const f0 = svc.ingestAlert({
    policyId: policy.id,
    fingerprint: 'edge-health-flaky',
    severity: 'warning',
    title: 'Edge probe flapping',
    state: 'firing',
    nowMs: t0 + 3000000
  });
  assert.strictEqual(f0.flapping, false);
  const f1 = svc.ingestAlert({
    policyId: policy.id,
    fingerprint: 'edge-health-flaky',
    state: 'resolved',
    nowMs: t0 + 3010000
  });
  assert.strictEqual(f1.flapping, false);
  assert.strictEqual(f1.incident.status, 'resolved');

  const f2 = svc.ingestAlert({
    policyId: policy.id,
    fingerprint: 'edge-health-flaky',
    state: 'firing',
    nowMs: t0 + 3020000
  });
  assert.strictEqual(f2.flapping, false);
  assert.strictEqual(f2.incident.status, 'open');

  const f3 = svc.ingestAlert({
    policyId: policy.id,
    fingerprint: 'edge-health-flaky',
    state: 'resolved',
    nowMs: t0 + 3030000
  });
  assert.strictEqual(f3.flapping, true);
  assert.strictEqual(f3.suppressed, true);
  assert.strictEqual(f3.reason, 'FLAPPING_SUPPRESSED');
  assert.strictEqual(f3.incident.status, 'flapping_suppressed');

  // Subsequent firing inside window stays suppressed and NEVER escalates
  const f4 = svc.ingestAlert({
    policyId: policy.id,
    fingerprint: 'edge-health-flaky',
    state: 'firing',
    nowMs: t0 + 3040000
  });
  assert.strictEqual(f4.flapping, true);
  assert.strictEqual(f4.suppressed, true);
  assert.strictEqual(f4.paged, false);
  assert.strictEqual(f4.reason, 'FLAPPING_SUPPRESSED');

  // Resolve unack incident so only flapping_suppressed + acknowledged remain, verify flapping NEVER escalates
  svc.ingestAlert({
    policyId: policy.id,
    fingerprint: 'redis-oom',
    state: 'resolved',
    nowMs: t0 + 3050000
  });
  const evalFlap = svc.evaluateEscalations(t0 + 4000000);
  assert.strictEqual(evalFlap.escalatedCount, 0);
}

/**
 * Verifies BOTH default singleton calls (`svc.fn(...)`) AND destructured exports (`fn(...)`)
 * with dynamic `CULKIBO_DATA_DIR` isolation (catching Cycle-12 `#305` recursion bugs).
 * @param {string} tmpRoot
 */
function testSingletonAndDestructuredExports(tmpRoot) {
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = path.join(tmpRoot, 'singleton-env');

  try {
    const t0 = Date.UTC(2026, 10, 27, 12, 0, 0);

    // CronLeaseService: singleton method call + destructured function call
    const sAcq = cronLeaseService.acquireCronLease({
      jobId: 'singleton-cron',
      scheduleSlotIso: '2026-11-27T12:00:00Z',
      holderId: 'h1',
      ttlSec: 120,
      nowMs: t0
    });
    assert.strictEqual(sAcq.acquired, true);
    assert.strictEqual(sAcq.fencingToken, 1);

    const dRenew = renewCronLease(sAcq.leaseId, { holderId: 'h1', extendSec: 180, nowMs: t0 + 10000 });
    assert.strictEqual(dRenew.ok, true);

    const dComplete = completeCronLease(sAcq.leaseId, {
      holderId: 'h1',
      fencingToken: 1,
      status: 'succeeded',
      nowMs: t0 + 20000
    });
    assert.strictEqual(dComplete.ok, true);

    const sDup = acquireCronLease({
      jobId: 'singleton-cron',
      scheduleSlotIso: '2026-11-27T12:00:00Z',
      holderId: 'h2',
      nowMs: t0 + 30000
    });
    assert.strictEqual(sDup.acquired, false);
    assert.strictEqual(sDup.reason, 'ALREADY_EXECUTED_SLOT');

    assert.strictEqual(cronLeaseService.listCronLeases('singleton-cron', t0 + 30000).length, 1);
    assert.strictEqual(listCronLeases('singleton-cron', t0 + 30000).length, 1);

    // OnCallEscalationService: singleton method call + destructured function call
    const pol = oncallEscalationService.savePolicy({
      id: 'singleton-pol',
      name: 'Singleton OnCall',
      shiftDurationHours: 12,
      rotationStartMs: t0,
      ackTimeoutSec: 60,
      tiers: [
        { tier: 1, responders: ['sre-a', 'sre-b'] },
        { tier: 2, responders: ['lead-c'] }
      ]
    });
    assert.strictEqual(listPolicies().length, 1);
    assert.strictEqual(resolveCurrentOnCall(pol.id, t0).responder, 'sre-a');
    assert.strictEqual(oncallEscalationService.resolveCurrentOnCall(pol.id, t0 + 12 * 3600000).responder, 'sre-b');

    const incRes = ingestAlert({
      policyId: pol.id,
      fingerprint: 'singleton-fp',
      title: 'Singleton Alert',
      state: 'firing',
      nowMs: t0
    });
    assert.strictEqual(incRes.created, true);
    assert.strictEqual(oncallEscalationService.listIncidents({ activeOnly: true }).length, 1);
    assert.strictEqual(listIncidents({ activeOnly: true }).length, 1);

    const escRes = evaluateEscalations(t0 + 61000);
    assert.strictEqual(escRes.escalatedCount, 1);

    const ackRes = acknowledgeIncident(incRes.incident.id, { actor: 'lead-c', nowMs: t0 + 62000 });
    assert.strictEqual(ackRes.status, 'acknowledged');
    assert.strictEqual(oncallEscalationService.evaluateEscalations(t0 + 300000).escalatedCount, 0);
  } finally {
    if (prevDataDir === undefined) {
      delete process.env.CULKIBO_DATA_DIR;
    } else {
      process.env.CULKIBO_DATA_DIR = prevDataDir;
    }
  }
}

async function runAllTests() {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c13-cron-oncall-'));
  try {
    testCronLeaseService(tmpRoot);
    testOnCallEscalationService(tmpRoot);
    testSingletonAndDestructuredExports(tmpRoot);
    console.log('✅ cron-lease-and-oncall.test.js PASSED (cron leases, fencing tokens, dedup, flapping, escalation, singleton+destructured)');
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runAllTests().catch((err) => {
    console.error('❌ cron-lease-and-oncall.test.js FAILED:', err);
    process.exit(1);
  });
}

module.exports = runAllTests;
