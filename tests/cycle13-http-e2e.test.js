const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

async function testCycle13HttpE2E() {
  console.log('\n🚀 Testing Cycle #13 150-MCP Milestone Live Isolated HTTP E2E (Image Bloat, Cron Leases, PII Masker, OOM Forensics, On-Call Escalation)...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c13-http-'));
  const rootDir = path.resolve(__dirname, '..');
  const runnerPath = path.join(tmpDir, 'cycle13-http-runner.js');

  fs.writeFileSync(runnerPath, `
const assert = require('assert');
const http = require('http');
const path = require('path');

const TMP_DIR = ${JSON.stringify(tmpDir)};
const ROOT_DIR = ${JSON.stringify(rootDir)};
process.env.NODE_ENV = 'test';
process.env.CULKIBO_DATA_DIR = TMP_DIR;
process.env.CULKIBO_DISABLE_AUDIT_DISK = '1';

const express = require(path.join(ROOT_DIR, 'node_modules', 'express'));
const auth = require(path.join(ROOT_DIR, 'server/middleware/auth'));
const projectManager = require(path.join(ROOT_DIR, 'server/services/projectManager'));
const teamManager = require(path.join(ROOT_DIR, 'server/services/teamManager'));
const apiRouter = require(path.join(ROOT_DIR, 'server/routes/api'));

function reqJson(port, method, pth, { token, body } = {}) {
  return new Promise((resolve, reject) => {
    const raw = body !== undefined ? JSON.stringify(body) : null;
    const headers = { host: 'panel.example.test' };
    if (token) headers.authorization = 'Bearer ' + token;
    if (raw !== null) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = Buffer.byteLength(raw);
    }
    const r = http.request({ hostname: '127.0.0.1', port, method, path: pth, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch (e) {}
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    r.on('error', reject);
    if (raw !== null) r.write(raw);
    r.end();
  });
}

(async () => {
  const app = express();
  app.use(express.json({ limit: '2mb' }));
  app.use('/api', auth.authMiddleware, apiRouter);
  const srv = await new Promise((res) => { const s = app.listen(0, '127.0.0.1', () => res(s)); });
  const port = srv.address().port;
  const master = auth.resolveToken();

  try {
    const projA = projectManager.create({
      id: 'proj_c13_a',
      name: 'Cycle13 Milestone App',
      domains: ['c13.example.test']
    });

    // Build synthetic token dynamically (GH013 Push Protection safe)
    const fakeStripeKey = ['sk', 'live', 'c13AuditSynthetic99887766'].join('_');

    // 1. Container Image Bloat & Secret-in-Layer Auditor
    const leakyDf = [
      'FROM node:22',
      'WORKDIR /app',
      'ENV API_KEY=' + fakeStripeKey,
      'COPY . .',
      'RUN apt-get update && apt-get install -y curl',
      'RUN npm install',
      'RUN rm -rf /app/tmp-artifacts',
      'CMD ["node", "index.js"]'
    ].join('\\n');

    const imgBad = await reqJson(port, 'POST', '/api/build/image-audit', {
      token: master,
      body: { dockerfile: leakyDf, stack: 'node' }
    });
    assert.strictEqual(imgBad.status, 200, 'POST /api/build/image-audit failed: ' + imgBad.text);
    assert.ok(imgBad.json.secretLeaks.length >= 1, 'Leaky Dockerfile MUST flag secretLeaks');
    assert.ok(!imgBad.text.includes(fakeStripeKey), 'Response MUST redact matched raw secret token');
    const badImgRules = imgBad.json.findings.map((f) => f.rule);
    assert.ok(badImgRules.includes('SECRET_IN_ENV_OR_ARG'));
    assert.ok(badImgRules.includes('CROSS_LAYER_DELETE_WASTE'));
    assert.ok(badImgRules.includes('MISSING_MULTI_STAGE'));

    const slimDf = [
      'FROM node:22-alpine AS builder',
      'WORKDIR /app',
      'COPY package.json package-lock.json ./',
      'RUN npm ci',
      'COPY . .',
      'RUN npm run build',
      'FROM gcr.io/distroless/nodejs22-debian12:nonroot',
      'WORKDIR /app',
      'COPY --from=builder /app/dist ./dist',
      'CMD ["dist/index.js"]'
    ].join('\\n');
    const imgGood = await reqJson(port, 'POST', '/api/build/image-audit', {
      token: master,
      body: { dockerfile: slimDf, stack: 'node' }
    });
    assert.strictEqual(imgGood.status, 200);
    assert.strictEqual(imgGood.json.secretLeaks.length, 0);
    assert.ok(imgGood.json.efficiencyScore >= 90, 'Slim multi-stage distroless MUST score >= 90');

    // 2. Distributed Cron Fencing-Token Lease Guard (concurrency + slot idempotency + stale fencing token)
    const baseMs = Date.UTC(2026, 10, 27, 0, 0, 0);
    const slotIso = '2026-11-27T00:00:00Z';
    const acq1 = await reqJson(port, 'POST', '/api/crons/job_daily_billing/lease/acquire', {
      token: master,
      body: { scheduleSlotIso: slotIso, holderId: 'worker-eu-1', ttlSec: 300, nowMs: baseMs }
    });
    assert.strictEqual(acq1.status, 201, 'First cron lease acquire failed: ' + acq1.text);
    assert.strictEqual(acq1.json.acquired, true);
    assert.strictEqual(acq1.json.fencingToken, 1);

    const acqOverlap = await reqJson(port, 'POST', '/api/crons/job_daily_billing/lease/acquire', {
      token: master,
      body: { scheduleSlotIso: slotIso, holderId: 'worker-eu-2', ttlSec: 300, nowMs: baseMs + 5000 }
    });
    assert.strictEqual(acqOverlap.status, 200);
    assert.strictEqual(acqOverlap.json.acquired, false);
    assert.strictEqual(acqOverlap.json.reason, 'ALREADY_RUNNING');

    const compStale = await reqJson(port, 'POST', '/api/crons/job_daily_billing/lease/complete', {
      token: master,
      body: { leaseId: acq1.json.leaseId, holderId: 'worker-eu-1', fencingToken: 99, status: 'succeeded', nowMs: baseMs + 10000 }
    });
    assert.strictEqual(compStale.status, 200);
    assert.strictEqual(compStale.json.ok, false);
    assert.strictEqual(compStale.json.reason, 'STALE_FENCING_TOKEN');

    const compOk = await reqJson(port, 'POST', '/api/crons/job_daily_billing/lease/complete', {
      token: master,
      body: { leaseId: acq1.json.leaseId, holderId: 'worker-eu-1', fencingToken: 1, status: 'succeeded', nowMs: baseMs + 12000 }
    });
    assert.strictEqual(compOk.status, 200);
    assert.strictEqual(compOk.json.ok, true);

    const acqRepeatSlot = await reqJson(port, 'POST', '/api/crons/job_daily_billing/lease/acquire', {
      token: master,
      body: { scheduleSlotIso: slotIso, holderId: 'worker-eu-2', ttlSec: 300, nowMs: baseMs + 60000 }
    });
    assert.strictEqual(acqRepeatSlot.status, 200);
    assert.strictEqual(acqRepeatSlot.json.acquired, false);
    assert.strictEqual(acqRepeatSlot.json.reason, 'ALREADY_EXECUTED_SLOT');

    const leaseList = await reqJson(port, 'GET', '/api/crons/job_daily_billing/leases', { token: master });
    assert.strictEqual(leaseList.status, 200);
    assert.ok(Array.isArray(leaseList.json.leases) && leaseList.json.leases.length >= 1);

    // 3. PR-Preview DB PII Masker (Zero PII Leaked + FK determinism + pg_anonymizer DDL)
    const rawEmail = 'ceo.private@acme-corp.example';
    const rawPhone = '+1-415-867-5309';
    const rawCard = '4532-1111-2222-3333';
    const rawIban = 'DE89370400440532013000';
    const rawIp = '203.0.113.42';
    const piiRes1 = await reqJson(port, 'POST', '/api/databases/pii-mask', {
      token: master,
      body: {
        seed: 'pr-42-seed',
        rows: [
          {
            id: 1,
            email: rawEmail,
            phone: rawPhone,
            card: rawCard,
            iban: rawIban,
            ip: rawIp,
            api_token: fakeStripeKey
          }
        ],
        sqlDump: "INSERT INTO customers (email, phone) VALUES ('" + rawEmail + "', '" + rawPhone + "');"
      }
    });
    assert.strictEqual(piiRes1.status, 200, 'POST /api/databases/pii-mask failed: ' + piiRes1.text);
    assert.strictEqual(piiRes1.json.zeroPiiLeaked, true);
    assert.ok(piiRes1.json.maskedCount >= 6);
    assert.ok(piiRes1.json.pgAnonDdl.includes('SECURITY LABEL FOR anon ON COLUMN'));
    for (const rawSecret of [rawEmail, rawPhone, rawCard, rawIban, rawIp, fakeStripeKey]) {
      assert.ok(!piiRes1.text.includes(rawSecret), 'Raw PII/secret leaked in HTTP response: ' + rawSecret);
    }

    const piiRes2 = await reqJson(port, 'POST', '/api/databases/pii-mask', {
      token: master,
      body: { seed: 'pr-42-seed', rows: [{ customer_email: rawEmail }] }
    });
    assert.strictEqual(piiRes2.status, 200);
    assert.strictEqual(piiRes2.json.maskedRows[0].customer_email, piiRes1.json.maskedRows[0].email, 'Same seed MUST yield deterministic FK-preserving masked email');

    // 4. Container OOM Forensics & Crash-Loop Classifier
    const oomRes = await reqJson(port, 'POST', '/api/projects/proj_c13_a/forensics/classify', {
      token: master,
      body: { exitCode: 137, oomKilled: true, memoryLimitMb: 512, memoryPeakMb: 510, restartCount: 3 }
    });
    assert.strictEqual(oomRes.status, 200, 'POST forensics/classify failed: ' + oomRes.text);
    assert.strictEqual(oomRes.json.classification, 'CGROUP_OOM_KILL');
    assert.strictEqual(oomRes.json.recommendedMemoryMb, 768);
    assert.strictEqual(oomRes.json.ignoreForRollback, false);

    const sigkillRes = await reqJson(port, 'POST', '/api/projects/proj_c13_a/forensics/classify', {
      token: master,
      body: { exitCode: 137, oomKilled: false, cgroupOomKills: 0 }
    });
    assert.strictEqual(sigkillRes.status, 200);
    assert.strictEqual(sigkillRes.json.classification, 'FORCED_SIGKILL_TIMEOUT');
    assert.strictEqual(sigkillRes.json.recommendedMemoryMb, null);

    const staleRes = await reqJson(port, 'POST', '/api/projects/proj_c13_a/forensics/classify', {
      token: master,
      body: { exitCode: 137, oomKilled: true, historicalOnly: true }
    });
    assert.strictEqual(staleRes.status, 200);
    assert.strictEqual(staleRes.json.classification, 'STALE_HISTORICAL_TASK_IGNORED');
    assert.strictEqual(staleRes.json.ignoreForRollback, true);

    // 5. On-Call Escalation Router (Policies, 3x Dedup, Escalation, Ack Freeze & Flapping Damper)
    const ocStart = Date.UTC(2026, 10, 27, 8, 0, 0);
    const polSave = await reqJson(port, 'POST', '/api/oncall/policies', {
      token: master,
      body: {
        id: 'pol_primary_c13',
        name: 'Primary SRE Rotation',
        shiftDurationHours: 24,
        rotationStartMs: ocStart,
        ackTimeoutSec: 300,
        flappingWindowSec: 600,
        flappingThreshold: 3,
        tiers: [
          { tier: 1, responders: ['alice', 'bob'] },
          { tier: 2, responders: ['charlie'] },
          { tier: 3, responders: ['vp-eng'] }
        ]
      }
    });
    assert.strictEqual(polSave.status, 201, 'POST /api/oncall/policies failed: ' + polSave.text);

    const polList = await reqJson(port, 'GET', '/api/oncall/policies?nowMs=' + ocStart, { token: master });
    assert.strictEqual(polList.status, 200);
    assert.strictEqual(polList.json.policies[0].currentOnCall.responder, 'alice');

    const ing1 = await reqJson(port, 'POST', '/api/oncall/ingest', {
      token: master,
      body: { policyId: 'pol_primary_c13', projectId: projA.id, fingerprint: 'db-down-prod', severity: 'critical', title: 'Primary DB down', state: 'firing', nowMs: ocStart }
    });
    assert.strictEqual(ing1.status, 200);
    assert.strictEqual(ing1.json.created, true);
    const incId = ing1.json.incident.id;

    const ing2 = await reqJson(port, 'POST', '/api/oncall/ingest', {
      token: master,
      body: { policyId: 'pol_primary_c13', projectId: projA.id, fingerprint: 'db-down-prod', severity: 'critical', title: 'Primary DB down', state: 'firing', nowMs: ocStart + 10000 }
    });
    const ing3 = await reqJson(port, 'POST', '/api/oncall/ingest', {
      token: master,
      body: { policyId: 'pol_primary_c13', projectId: projA.id, fingerprint: 'db-down-prod', severity: 'critical', title: 'Primary DB down', state: 'firing', nowMs: ocStart + 20000 }
    });
    assert.strictEqual(ing2.json.deduplicated, true);
    assert.strictEqual(ing3.json.incident.occurrences, 3);

    const evalEsc = await reqJson(port, 'POST', '/api/oncall/evaluate', {
      token: master,
      body: { nowMs: ocStart + 310000 }
    });
    assert.strictEqual(evalEsc.status, 200);
    assert.strictEqual(evalEsc.json.escalatedCount, 1);
    assert.strictEqual(evalEsc.json.escalated[0].toTier, 2);
    assert.strictEqual(evalEsc.json.escalated[0].assignedResponder, 'charlie');

    const ackRes = await reqJson(port, 'POST', '/api/oncall/incidents/' + encodeURIComponent(incId) + '/ack', {
      token: master,
      body: { actor: 'charlie', nowMs: ocStart + 320000 }
    });
    assert.strictEqual(ackRes.status, 200);
    assert.strictEqual(ackRes.json.acknowledged, true);

    const evalAfterAck = await reqJson(port, 'POST', '/api/oncall/evaluate', {
      token: master,
      body: { nowMs: ocStart + 900000 }
    });
    assert.strictEqual(evalAfterAck.status, 200);
    assert.strictEqual(evalAfterAck.json.escalatedCount, 0, 'Acknowledged incident MUST NOT escalate further');

    // Flapping suppression test
    await reqJson(port, 'POST', '/api/oncall/ingest', { token: master, body: { policyId: 'pol_primary_c13', fingerprint: 'flap-api', state: 'firing', nowMs: ocStart } });
    await reqJson(port, 'POST', '/api/oncall/ingest', { token: master, body: { policyId: 'pol_primary_c13', fingerprint: 'flap-api', state: 'resolved', nowMs: ocStart + 10000 } });
    await reqJson(port, 'POST', '/api/oncall/ingest', { token: master, body: { policyId: 'pol_primary_c13', fingerprint: 'flap-api', state: 'firing', nowMs: ocStart + 20000 } });
    const flapTrip = await reqJson(port, 'POST', '/api/oncall/ingest', { token: master, body: { policyId: 'pol_primary_c13', fingerprint: 'flap-api', state: 'resolved', nowMs: ocStart + 30000 } });
    assert.strictEqual(flapTrip.status, 200);
    assert.strictEqual(flapTrip.json.flapping, true);
    assert.strictEqual(flapTrip.json.reason, 'FLAPPING_SUPPRESSED');

    const incList = await reqJson(port, 'GET', '/api/oncall/incidents', { token: master });
    assert.strictEqual(incList.status, 200);
    assert.ok(Array.isArray(incList.json.incidents) && incList.json.incidents.length >= 2);

    // 6. Strict RBAC & Multi-Tenant 403 Enforcement
    const bootOwner = teamManager.bootstrapOwner({ email: 'c13-owner@example.test', password: 'OwnerPassword!2026' });
    const ownerPrincipal = teamManager.verifySessionToken(bootOwner.sessionToken).principal;
    const invViewer = teamManager.createInvite(ownerPrincipal, { email: 'c13-viewer@example.test', role: 'viewer' });
    const accViewer = teamManager.acceptInvite({ token: invViewer.inviteToken, email: 'c13-viewer@example.test', password: 'ViewerPassword!2026', name: 'ViewerA' });

    const viewerGetPolicies = await reqJson(port, 'GET', '/api/oncall/policies', { token: accViewer.sessionToken });
    assert.strictEqual(viewerGetPolicies.status, 200);

    const viewerPostPolicy = await reqJson(port, 'POST', '/api/oncall/policies', {
      token: accViewer.sessionToken,
      body: { name: 'Blocked Policy', tiers: [{ tier: 1, responders: ['x'] }] }
    });
    assert.strictEqual(viewerPostPolicy.status, 403, 'Viewer MUST get 403 on POST /api/oncall/policies');

    const teamB = teamManager.createTeam(ownerPrincipal, { name: 'Tenant B C13' });
    const invDevB = teamManager.createInvite(ownerPrincipal, { email: 'c13-devb@example.test', role: 'developer', teamId: teamB.id });
    const accDevB = teamManager.acceptInvite({ token: invDevB.inviteToken, email: 'c13-devb@example.test', password: 'DevBPassword!2026', name: 'DevB' });

    const foreignForensics = await reqJson(port, 'POST', '/api/projects/proj_c13_a/forensics/classify', {
      token: accDevB.sessionToken,
      body: { exitCode: 137, oomKilled: true }
    });
    assert.strictEqual(foreignForensics.status, 403, 'Foreign tenant developer MUST get 403 on /projects/:id/forensics/classify');

    const devPostPolicy = await reqJson(port, 'POST', '/api/oncall/policies', {
      token: accDevB.sessionToken,
      body: { name: 'Blocked Dev Policy', tiers: [{ tier: 1, responders: ['x'] }] }
    });
    assert.strictEqual(devPostPolicy.status, 403, 'Developer MUST get 403 on POST /api/oncall/policies');

    console.log('CYCLE13_HTTP_E2E_OK');
  } finally {
    await new Promise((r) => srv.close(r));
  }
})().catch((err) => { console.error(err); process.exit(1); });
`, 'utf8');

  try {
    const out = execFileSync(process.execPath, [runnerPath], {
      cwd: rootDir,
      encoding: 'utf8',
      timeout: 30000
    });
    assert.ok(out.includes('CYCLE13_HTTP_E2E_OK'), `Cycle-13 HTTP E2E check failed:\n${out}`);
    console.log('  ✓ Image Bloat & Secret Auditor (leaky ENV redaction + cross-layer rm vs slim >=90) verified over live HTTP');
    console.log('  ✓ Distributed Cron Leases (fencingToken++, ALREADY_RUNNING, STALE_FENCING_TOKEN, ALREADY_EXECUTED_SLOT) verified over live HTTP');
    console.log('  ✓ PR-Preview PII Masker (zeroPiiLeaked, deterministic FK join, pg_anonymizer DDL, 0 raw PII in response) verified over live HTTP');
    console.log('  ✓ OOM Forensics Classifier (CGROUP_OOM_KILL 1.5x, FORCED_SIGKILL_TIMEOUT, STALE_HISTORICAL_TASK_IGNORED) verified over live HTTP');
    console.log('  ✓ On-Call Escalation Router (3x dedup, Tier 1->2 escalation, ack freeze, flapping damper) verified over live HTTP');
    console.log('  ✓ Strict RBAC & Multi-Tenant 403 Isolation (viewer/dev 403 on /oncall/policies; Tenant B 403 on foreign /forensics/classify) verified');
    console.log('✅ Cycle #13 Live Isolated HTTP E2E Suite PASSED!\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  testCycle13HttpE2E()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ Cycle #13 HTTP E2E Suite failed:', err);
      process.exit(1);
    });
}

module.exports = testCycle13HttpE2E;
