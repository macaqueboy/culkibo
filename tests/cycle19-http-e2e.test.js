const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

async function testCycle19HttpE2E() {
  console.log('\n🚀 Testing Cycle #19 180-MCP & 80-Suites Milestone Live Isolated HTTP E2E (Webhook Firewall, Disk/Inode Guard, Multi-Region Shift, Credential Watchdog, Queue Schema/DLQ)...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c19-http-'));
  const rootDir = path.resolve(__dirname, '..');
  const runnerPath = path.join(tmpDir, 'cycle19-http-runner.js');

  fs.writeFileSync(runnerPath, `
const assert = require('assert');
const crypto = require('crypto');
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
    projectManager.create({
      id: 'proj_c19_a',
      name: 'Cycle19 Milestone Stack',
      domains: ['c19.example.test']
    });

    // 1. Inbound Webhook Signature Replay & Clock-Skew Firewall (/api/webhooks/firewall/* — CVE-2026-41351 / CVE-2025-61926)
    const nowSec = 1764290000;
    const rawBody = '{"id":"evt_1","type":"invoice.paid"}';
    const dynSecret = ['wh-c19', 'ephemeral', 'signing', 'key', '9911'].join('-');

    const whNoSec = await reqJson(port, 'POST', '/api/webhooks/firewall/verify', {
      token: master,
      body: { provider: 'svix', rawBody, headers: {}, secret: '', nowSec, routeId: 'billing' }
    });
    assert.strictEqual(whNoSec.status, 200, 'POST /webhooks/firewall/verify failed: ' + whNoSec.text);
    assert.strictEqual(whNoSec.json.verified, false);
    assert.strictEqual(whNoSec.json.code, 'WEBHOOK_SECRET_UNCONFIGURED');

    const msgId = 'msg_c19_replay_1';
    const svixDigest = crypto.createHmac('sha256', Buffer.from(dynSecret, 'utf8'))
      .update(msgId + '.' + nowSec + '.' + rawBody)
      .digest();
    const b64Sig = svixDigest.toString('base64');
    const b64UrlSig = b64Sig.replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');

    const whSkew = await reqJson(port, 'POST', '/api/webhooks/firewall/verify', {
      token: master,
      body: {
        provider: 'svix',
        rawBody,
        secret: dynSecret,
        nowSec,
        routeId: 'billing',
        headers: { 'svix-id': 'msg_old', 'svix-timestamp': String(nowSec - 500), 'svix-signature': 'v1,' + b64Sig }
      }
    });
    assert.strictEqual(whSkew.json.verified, false);
    assert.strictEqual(whSkew.json.code, 'CLOCK_SKEW_EXCEEDED');

    const whPass = await reqJson(port, 'POST', '/api/webhooks/firewall/verify', {
      token: master,
      body: {
        provider: 'svix',
        rawBody,
        secret: dynSecret,
        nowSec,
        routeId: 'billing',
        headers: { 'svix-id': msgId, 'svix-timestamp': String(nowSec), 'svix-signature': 'v1,' + b64Sig }
      }
    });
    assert.strictEqual(whPass.json.verified, true);

    // CVE-2026-41351 replay via Base64URL re-encoding of identical Svix signature
    const whReplay = await reqJson(port, 'POST', '/api/webhooks/firewall/verify', {
      token: master,
      body: {
        provider: 'svix',
        rawBody,
        secret: dynSecret,
        nowSec: nowSec + 5,
        routeId: 'billing',
        headers: { 'svix-id': msgId, 'svix-timestamp': String(nowSec), 'svix-signature': 'v1,' + b64UrlSig }
      }
    });
    assert.strictEqual(whReplay.json.verified, false);
    assert.strictEqual(whReplay.json.code, 'WEBHOOK_REPLAY_DETECTED');

    const whPolDry = await reqJson(port, 'POST', '/api/webhooks/firewall/policy', {
      token: master,
      body: { routeId: 'billing', provider: 'svix', maxSkewSec: 180 }
    });
    assert.strictEqual(whPolDry.status, 200);
    assert.strictEqual(whPolDry.json.dryRun, true, 'POST /webhooks/firewall/policy MUST default to dryRun: true');

    const whStats = await reqJson(port, 'GET', '/api/webhooks/firewall/stats?routeId=billing', { token: master });
    assert.strictEqual(whStats.status, 200);
    assert.ok(whStats.json.replayEntryCount >= 1);

    // 2. Dual Block+Inode & pg_wal Disk-Pressure Guard (/api/nodes/disk-pressure/* — Dokploy#4651)
    const dpEval = await reqJson(port, 'POST', '/api/nodes/disk-pressure/evaluate', {
      token: master,
      body: { nodeId: 'vps-eu-1', blockUsedPct: 35, inodeUsedPct: 96, overlay2Gb: 25, containerLogGb: 6, pgWalGb: 18, inactiveReplicationSlots: 2, diskTotalGb: 100 }
    });
    assert.strictEqual(dpEval.status, 200, 'POST /nodes/disk-pressure/evaluate failed: ' + dpEval.text);
    assert.strictEqual(dpEval.json.status, 'CRITICAL');
    assert.ok(dpEval.json.alertCodes.includes('INODE_EXHAUSTION_CRITICAL'));
    assert.ok(dpEval.json.alertCodes.includes('PG_WAL_SLOT_RUNAWAY'));
    assert.strictEqual(dpEval.json.daemonLogQuota.config['log-opts']['max-size'], '10m');
    assert.strictEqual(dpEval.json.daemonLogQuota.config['log-opts']['max-file'], '3');

    const dpRem = await reqJson(port, 'POST', '/api/nodes/disk-pressure/remediate', {
      token: master,
      body: { evaluation: dpEval.json }
    });
    assert.strictEqual(dpRem.status, 200);
    assert.strictEqual(dpRem.json.dryRun, true, 'POST /nodes/disk-pressure/remediate MUST default to dryRun: true');
    assert.ok(dpRem.json.actionCount >= 2);

    const dpRep = await reqJson(port, 'GET', '/api/nodes/disk-pressure/reports?nodeId=vps-eu-1', { token: master });
    assert.strictEqual(dpRep.status, 200);
    assert.ok(dpRep.json.count >= 1);

    // 3. Multi-Region Health-Gated Blue/Green Traffic Shift (/api/edge/traffic-shift/* — Caddy#7544/#6393)
    const tsBad = await reqJson(port, 'POST', '/api/edge/traffic-shift/evaluate', {
      token: master,
      body: {
        projectId: 'proj_c19_a',
        targetGreenWeightPct: 50,
        regions: [
          { id: 'eu-west', role: 'blue', healthyEndpoints: 2, errorRatePct: 0.1, probeStatus: 200 },
          { id: 'us-east', role: 'green', healthyEndpoints: 0, errorRatePct: 0, probeStatus: 302, healthPort: 8081 }
        ]
      }
    });
    assert.strictEqual(tsBad.status, 200, 'POST /edge/traffic-shift/evaluate failed: ' + tsBad.text);
    assert.strictEqual(tsBad.json.allowed, false);
    assert.strictEqual(tsBad.json.code, 'UNHEALTHY_TARGET_REGION');

    const tsPlan = await reqJson(port, 'POST', '/api/edge/traffic-shift/plan', {
      token: master,
      body: {
        projectId: 'proj_c19_a',
        currentBlueWeightPct: 100,
        stepPct: 25,
        stickyMaxAgeSec: 900,
        failDurationSec: 30,
        regions: [
          { id: 'eu-west', role: 'blue', healthyEndpoints: 2, errorRatePct: 0.1, probeStatus: 200 },
          { id: 'us-east', role: 'green', healthyEndpoints: 2, errorRatePct: 0.1, probeStatus: 200 }
        ]
      }
    });
    assert.strictEqual(tsPlan.status, 200);
    assert.strictEqual(tsPlan.json.dryRun, true, 'POST /edge/traffic-shift/plan MUST default to dryRun: true');
    assert.strictEqual(tsPlan.json.allowed, true);
    assert.strictEqual(tsPlan.json.stickyCookiePolicy.maxAgeSec, 900);
    assert.ok(tsPlan.json.caddyBlock.caddyfile.includes('lb_policy cookie'));
    assert.ok(tsPlan.json.caddyBlock.caddyfile.includes('health_uri'));
    assert.ok(tsPlan.json.caddyBlock.caddyfile.includes('lb_try_duration'));

    const tsHist = await reqJson(port, 'GET', '/api/edge/traffic-shift/history?projectId=proj_c19_a', { token: master });
    assert.strictEqual(tsHist.status, 200);
    assert.strictEqual(tsHist.json.count, 0, 'dryRun: true shift plan MUST NOT persist');

    // 4. Unified Credential Expiry & SSH/JWT Watchdog (/api/security/credentials/* — metadata ONLY!)
    const nowIso = '2026-11-28T03:00:00Z';
    const rawSecretAttempt = ['never', 'persist', 'this', 'secret', '999'].join('_');
    const credDry = await reqJson(port, 'POST', '/api/security/credentials/register', {
      token: master,
      body: { id: 'cred_s3_1', projectId: 'proj_c19_a', kind: 's3_iam', label: 'Backup S3', expiresAtIso: '2026-11-20T00:00:00Z', secret: rawSecretAttempt }
    });
    assert.strictEqual(credDry.status, 200);
    assert.strictEqual(credDry.json.dryRun, true, 'POST /security/credentials/register MUST default to dryRun: true');
    assert.ok(!credDry.text.includes(rawSecretAttempt), 'Watchdog MUST NEVER echo or persist raw secrets');
    assert.ok(credDry.json.strippedSecretFields.includes('secret'));

    await reqJson(port, 'POST', '/api/security/credentials/register', {
      token: master,
      body: { id: 'cred_s3_1', projectId: 'proj_c19_a', kind: 's3_iam', label: 'Backup S3', expiresAtIso: '2026-11-20T00:00:00Z', dryRun: false }
    });
    await reqJson(port, 'POST', '/api/security/credentials/register', {
      token: master,
      body: { id: 'cred_oauth_1', projectId: 'proj_c19_a', kind: 'oauth', label: 'GitHub OAuth', expiresAtIso: '2026-12-02T00:00:00Z', dryRun: false }
    });

    const credAudit = await reqJson(port, 'POST', '/api/security/credentials/audit', {
      token: master,
      body: { projectId: 'proj_c19_a', nowIso, clockSkewSec: 90, sshKeyMode: '0777', usesTempStsToken: true, logsContainInstallToken: true }
    });
    assert.strictEqual(credAudit.status, 200);
    assert.strictEqual(credAudit.json.counts.EXPIRED, 1);
    assert.strictEqual(credAudit.json.counts.CRITICAL, 1);
    assert.ok(credAudit.json.hygiene.findingCodes.includes('CLOCK_SKEW_JWT_FAILURE'));
    assert.ok(credAudit.json.hygiene.findingCodes.includes('INSECURE_SSH_KEY_MODE'));
    assert.ok(credAudit.json.hygiene.findingCodes.includes('EPHEMERAL_BACKUP_CREDENTIAL'));
    assert.ok(credAudit.json.hygiene.findingCodes.includes('BUILD_LOG_INSTALL_TOKEN_LEAK'));

    const credWatch = await reqJson(port, 'GET', '/api/security/credentials/watchdog?projectId=proj_c19_a', { token: master });
    assert.strictEqual(credWatch.status, 200);
    assert.strictEqual(credWatch.json.count, 2);

    // 5. Event-Bus / Queue Schema Evolution & Poison-Pill DLQ Gate (/api/queues/* — Kafka KIP-1034 / BullMQ v6)
    const schFail = await reqJson(port, 'POST', '/api/queues/schema/check', {
      token: master,
      body: {
        format: 'jsonschema',
        compatibilityMode: 'BACKWARD',
        baseSchema: { type: 'object', properties: { orderId: { type: 'string' } }, required: ['orderId'] },
        nextSchema: { type: 'object', properties: { orderId: { type: 'string' }, tenantId: { type: 'string' } }, required: ['orderId', 'tenantId'] }
      }
    });
    assert.strictEqual(schFail.status, 200);
    assert.strictEqual(schFail.json.compatible, false);
    assert.ok(schFail.json.breakingChanges.some((b) => b.code === 'REQUIRED_FIELD_ADDED_NO_DEFAULT'));

    const dlqEval = await reqJson(port, 'POST', '/api/queues/dlq/evaluate', {
      token: master,
      body: { queueName: 'orders.v1', totalDelivered: 100, failedCount: 30, consecutivePoisonCount: 6, dlqRawPassthrough: false }
    });
    assert.strictEqual(dlqEval.status, 200);
    assert.strictEqual(dlqEval.json.circuitOpen, true);
    assert.ok(dlqEval.json.findingCodes.includes('DLQ_SCHEMA_DEADLOCK'));
    assert.ok(dlqEval.json.findingCodes.includes('POISON_PILL_CIRCUIT_OPEN'));

    const dlqQuarDry = await reqJson(port, 'POST', '/api/queues/dlq/quarantine', {
      token: master,
      body: { queueName: 'orders.v1', messageId: 'm_bad_1', rawPayloadBase64: Buffer.from('{broken').toString('base64'), errorCode: 'INVALID_JSON' }
    });
    assert.strictEqual(dlqQuarDry.status, 200);
    assert.strictEqual(dlqQuarDry.json.dryRun, true, 'POST /queues/dlq/quarantine MUST default to dryRun: true');

    await reqJson(port, 'POST', '/api/queues/dlq/quarantine', {
      token: master,
      body: { queueName: 'orders.v1', messageId: 'm_bad_1', rawPayloadBase64: Buffer.from('{broken').toString('base64'), dryRun: false }
    });
    const dlqList = await reqJson(port, 'GET', '/api/queues/dlq/list?queueName=orders.v1', { token: master });
    assert.strictEqual(dlqList.status, 200);
    assert.strictEqual(dlqList.json.count, 1);

    // 6. Strict RBAC & Multi-Tenant 403 Enforcement
    const bootOwner = teamManager.bootstrapOwner({ email: 'c19-owner@example.test', password: 'OwnerPassword!2026' });
    const ownerPrincipal = teamManager.verifySessionToken(bootOwner.sessionToken).principal;
    const invViewer = teamManager.createInvite(ownerPrincipal, { email: 'c19-viewer@example.test', role: 'viewer' });
    const accViewer = teamManager.acceptInvite({ token: invViewer.inviteToken, email: 'c19-viewer@example.test', password: 'ViewerPassword!2026', name: 'ViewerC19' });

    const viewerWatchdog = await reqJson(port, 'GET', '/api/security/credentials/watchdog?projectId=proj_c19_a', { token: accViewer.sessionToken });
    assert.strictEqual(viewerWatchdog.status, 200, 'Viewer MUST be allowed on metadata-only GET /security/credentials/watchdog');

    const viewerCredReg = await reqJson(port, 'POST', '/api/security/credentials/register', { token: accViewer.sessionToken, body: { expiresAtIso: nowIso } });
    assert.strictEqual(viewerCredReg.status, 403, 'Viewer MUST get 403 on POST /security/credentials/register');

    const viewerWhPol = await reqJson(port, 'POST', '/api/webhooks/firewall/policy', { token: accViewer.sessionToken, body: { routeId: 'r1' } });
    assert.strictEqual(viewerWhPol.status, 403, 'Viewer MUST get 403 on POST /webhooks/firewall/policy');

    const viewerDiskRem = await reqJson(port, 'POST', '/api/nodes/disk-pressure/remediate', { token: accViewer.sessionToken, body: {} });
    assert.strictEqual(viewerDiskRem.status, 403, 'Viewer MUST get 403 on POST /nodes/disk-pressure/remediate');

    const viewerShiftPlan = await reqJson(port, 'POST', '/api/edge/traffic-shift/plan', { token: accViewer.sessionToken, body: { projectId: 'proj_c19_a' } });
    assert.strictEqual(viewerShiftPlan.status, 403, 'Viewer MUST get 403 on POST /edge/traffic-shift/plan');

    const viewerDlqQuar = await reqJson(port, 'POST', '/api/queues/dlq/quarantine', { token: accViewer.sessionToken, body: { messageId: 'm1' } });
    assert.strictEqual(viewerDlqQuar.status, 403, 'Viewer MUST get 403 on POST /queues/dlq/quarantine');

    const teamB = teamManager.createTeam(ownerPrincipal, { name: 'Tenant B C19' });
    const invDevB = teamManager.createInvite(ownerPrincipal, { email: 'c19-devb@example.test', role: 'developer', teamId: teamB.id });
    const accDevB = teamManager.acceptInvite({ token: invDevB.inviteToken, email: 'c19-devb@example.test', password: 'DevBPassword!2026', name: 'DevBC19' });

    const foreignShift = await reqJson(port, 'POST', '/api/edge/traffic-shift/evaluate', {
      token: accDevB.sessionToken,
      body: { projectId: 'proj_c19_a', targetGreenWeightPct: 25, regions: [] }
    });
    assert.strictEqual(foreignShift.status, 403, 'Foreign Tenant B MUST get 403 on /edge/traffic-shift/evaluate for proj_c19_a');

    console.log('CYCLE19_HTTP_E2E_OK');
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
    assert.ok(out.includes('CYCLE19_HTTP_E2E_OK'), `Cycle-19 HTTP E2E check failed:\n${out}`);
    console.log('  ✓ Inbound Webhook Firewall (CVE-2025-61926 fail-closed, CLOCK_SKEW_EXCEEDED, CVE-2026-41351 Base64URL replay block) verified over live HTTP');
    console.log('  ✓ Dual Block+Inode & pg_wal Disk-Pressure Guard (low-GB 96% INODE_EXHAUSTION_CRITICAL, PG_WAL_SLOT_RUNAWAY, daemon.json, dryRun) verified over live HTTP');
    console.log('  ✓ Multi-Region Blue/Green Traffic Shift (Caddy#7544 UNHEALTHY_TARGET_REGION, sticky Max-Age, Caddy lb_policy cookie, dryRun) verified over live HTTP');
    console.log('  ✓ Unified Credential Expiry Watchdog (0 raw secrets stored, EXPIRED/CRITICAL, NTP/SSH/STS/log hygiene) verified over live HTTP');
    console.log('  ✓ Event-Bus Schema Evolution & Poison-Pill DLQ Gate (REQUIRED_FIELD_ADDED_NO_DEFAULT, DLQ_SCHEMA_DEADLOCK, quarantine dryRun) verified over live HTTP');
    console.log('  ✓ Strict RBAC & Multi-Tenant 403 Isolation (viewer watchdog 200 / admin 403 + Tenant B 403) verified over live HTTP');
    console.log('✅ Cycle #19 Live Isolated HTTP E2E Suite PASSED!\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  testCycle19HttpE2E()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ Cycle #19 HTTP E2E Suite failed:', err);
      process.exit(1);
    });
}

module.exports = testCycle19HttpE2E;
