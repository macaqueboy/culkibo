const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

async function testCycle14HttpE2E() {
  console.log('\n🚀 Testing Cycle #14 Resilience, Fencing & Secret-Gate Live Isolated HTTP E2E (Egress/nftables, DB Replicas, Secret Gate, Multi-Arch, Chaos GameDay)...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c14-http-'));
  const rootDir = path.resolve(__dirname, '..');
  const runnerPath = path.join(tmpDir, 'cycle14-http-runner.js');

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
      id: 'proj_c14_a',
      name: 'Cycle14 Resilience App',
      domains: ['c14.example.test']
    });

    // 1. Container Egress & Firewall (DOCKER-USER / nftables) Drift Auditor
    const egGet = await reqJson(port, 'GET', '/api/projects/proj_c14_a/egress-policy', { token: master });
    assert.strictEqual(egGet.status, 200, 'GET egress-policy failed: ' + egGet.text);
    assert.strictEqual(egGet.json.blockMetadata, true);
    assert.ok(egGet.json.preserveAdminPorts.includes(22) && egGet.json.preserveAdminPorts.includes(443));

    const egPut = await reqJson(port, 'PUT', '/api/projects/proj_c14_a/egress-policy', {
      token: master,
      body: { mode: 'allowlist', allowedCidrs: ['1.1.1.1/32'], blockMetadata: true, blockPrivateLan: true }
    });
    assert.strictEqual(egPut.status, 200, 'PUT egress-policy failed: ' + egPut.text);
    assert.deepStrictEqual(egPut.json.allowedCidrs, ['1.1.1.1/32']);

    const egAudit = await reqJson(port, 'POST', '/api/projects/proj_c14_a/egress-audit', {
      token: master,
      body: {
        backend: 'nftables',
        observedSockets: ['169.254.169.254:80', '10.0.0.15:5432', '1.1.1.1:443'],
        firewallRules: []
      }
    });
    assert.strictEqual(egAudit.status, 200, 'POST egress-audit failed: ' + egAudit.text);
    assert.strictEqual(egAudit.json.compliant, false);
    assert.strictEqual(egAudit.json.antiLockoutSafe, true);
    assert.ok(egAudit.json.missingChains.includes('DOCKER-USER'));
    const egRules = egAudit.json.violations.map((v) => v.ruleId);
    assert.ok(egRules.includes('CLOUD_METADATA_EGRESS'));
    assert.ok(egRules.includes('UNAUTHORIZED_PRIVATE_LAN_EGRESS'));

    // 2. Blue/Green DB Read-Replica Failover & Split-Brain Fencing
    const repPut1 = await reqJson(port, 'PUT', '/api/databases/db_c14_pg/replicas', {
      token: master,
      body: {
        primary: { id: 'pg-primary-1', host: '10.88.0.10', port: 5432, timeline: 1, fenced: false },
        replicas: [
          { id: 'pg-rep-lag', host: '10.88.0.11', port: 5432, lagBytes: 5242880, lagMs: 2400, healthy: true },
          { id: 'pg-rep-sync', host: '10.88.0.12', port: 5432, lagBytes: 2048, lagMs: 35, healthy: true }
        ]
      }
    });
    assert.strictEqual(repPut1.status, 200, 'PUT replicas failed: ' + repPut1.text);

    const repGet = await reqJson(port, 'GET', '/api/databases/db_c14_pg/replicas', { token: master });
    assert.strictEqual(repGet.status, 200);
    assert.ok(repGet.json.readWriteSplit, 'GET replicas must include readWriteSplit');
    assert.strictEqual(repGet.json.readWriteSplit.readTargets.length, 1);
    assert.strictEqual(repGet.json.readWriteSplit.readTargets[0].id, 'pg-rep-sync');
    assert.strictEqual(repGet.json.readWriteSplit.excludedLagging.length, 1);

    const promBlocked = await reqJson(port, 'POST', '/api/databases/db_c14_pg/replicas/promote', {
      token: master,
      body: { targetReplicaId: 'pg-rep-lag', dryRun: true }
    });
    assert.strictEqual(promBlocked.status, 200);
    assert.strictEqual(promBlocked.json.allowed, false);
    const blockerCodes = promBlocked.json.blockers.map((b) => b.code);
    assert.ok(blockerCodes.includes('REPLICA_LAG_TOO_HIGH'));
    assert.ok(blockerCodes.includes('OLD_PRIMARY_NOT_FENCED'));

    await reqJson(port, 'PUT', '/api/databases/db_c14_pg/replicas', {
      token: master,
      body: {
        primary: { id: 'pg-primary-1', host: '10.88.0.10', port: 5432, timeline: 1, fenced: true },
        replicas: [
          { id: 'pg-rep-sync', host: '10.88.0.12', port: 5432, lagBytes: 2048, lagMs: 35, healthy: true }
        ]
      }
    });
    const promOk = await reqJson(port, 'POST', '/api/databases/db_c14_pg/replicas/promote', {
      token: master,
      body: { targetReplicaId: 'pg-rep-sync' }
    });
    assert.strictEqual(promOk.status, 200);
    assert.strictEqual(promOk.json.allowed, true);
    assert.strictEqual(promOk.json.dryRun, true);
    assert.strictEqual(promOk.json.steps.length, 4);
    assert.strictEqual(promOk.json.timelineNext, 2);

    // 3. Pre-Deploy Shannon-Entropy & Pattern Secret Gate (0 raw echoes!)
    const dynStripe = ['sk', 'live', 'c14E2eSecretToken99887766aB'].join('_');
    const dynPem = '-----BEGIN ' + 'PRIVATE KEY-----';
    const secBlocked = await reqJson(port, 'POST', '/api/security/predeploy-secret-scan', {
      token: master,
      body: {
        mode: 'enforce',
        diffText: [
          'diff --git a/.env b/.env',
          '@@ -1,0 +1,2 @@',
          '+STRIPE_SECRET=' + dynStripe,
          '+KEY_HEADER=' + dynPem
        ].join('\\n')
      }
    });
    assert.strictEqual(secBlocked.status, 200, 'POST predeploy-secret-scan failed: ' + secBlocked.text);
    assert.strictEqual(secBlocked.json.allowed, false);
    assert.ok(secBlocked.json.blockedCount >= 2);
    assert.ok(!secBlocked.text.includes(dynStripe), 'Raw secret token MUST NEVER be echoed in response');
    assert.ok(!secBlocked.text.includes(dynPem), 'Raw PEM header MUST NEVER be echoed in response');

    const secBenign = await reqJson(port, 'POST', '/api/security/predeploy-secret-scan', {
      token: master,
      body: {
        mode: 'enforce',
        files: [
          {
            path: 'config.env',
            content: [
              'TENANT_UUID=550e8400-e29b-41d4-a716-446655440000',
              'COMMIT_SHA=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
              'CUSTOM_TOKEN=' + dynStripe + ' # culkibo:allow-secret'
            ].join('\\n')
          }
        ]
      }
    });
    assert.strictEqual(secBenign.status, 200);
    assert.strictEqual(secBenign.json.allowed, true);
    assert.strictEqual(secBenign.json.blockedCount, 0);

    // 4. Multi-Arch (amd64 / arm64) OCI Manifest & Matrix Planner
    const maMismatch = await reqJson(port, 'POST', '/api/build/multiarch/verify', {
      token: master,
      body: { imageArch: 'arm64', hostArch: 'x86_64', strictOciRegistry: true, includeAttestations: true }
    });
    assert.strictEqual(maMismatch.status, 200);
    assert.strictEqual(maMismatch.json.compatible, false);
    assert.strictEqual(maMismatch.json.code, 'EXEC_FORMAT_MISMATCH');

    const maPlan = await reqJson(port, 'POST', '/api/build/multiarch/plan', {
      token: master,
      body: {
        imageTag: 'ghcr.io/culkibo/app:1.2.0',
        targetPlatforms: ['linux/amd64', 'linux/arm64'],
        builders: [
          { name: 'vps-x86', arch: 'x86_64', online: true },
          { name: 'vps-arm', arch: 'aarch64', online: true }
        ]
      }
    });
    assert.strictEqual(maPlan.status, 200);
    assert.strictEqual(maPlan.json.usesQemu, false);
    assert.ok(maPlan.json.assignments.every((a) => a.strategy === 'native'));
    assert.ok(Array.isArray(maPlan.json.buildxArgv) && maPlan.json.buildxArgv.includes('docker'));

    // 5. Chaos Fault-Injection GameDay Simulator (Prod Lock 400 + Auto-Abort + Healthy >=85)
    const chaosProdBlock = await reqJson(port, 'POST', '/api/projects/proj_c14_a/chaos/simulate', {
      token: master,
      body: { environment: 'production', faultType: 'latency_jitter', explicitProdConfirm: false }
    });
    assert.strictEqual(chaosProdBlock.status, 400, 'Unconfirmed prod chaos MUST return HTTP 400');
    assert.strictEqual(chaosProdBlock.json.blocked, true);
    assert.strictEqual(chaosProdBlock.json.code, 'PROD_CHAOS_CONFIRM_REQUIRED');

    const chaosAbort = await reqJson(port, 'POST', '/api/projects/proj_c14_a/chaos/simulate', {
      token: master,
      body: { environment: 'staging', faultType: 'http_5xx', faultRatePct: 30, maxErrorAbortPct: 15 }
    });
    assert.strictEqual(chaosAbort.status, 200);
    assert.strictEqual(chaosAbort.json.status, 'AUTO_ABORTED');
    assert.strictEqual(chaosAbort.json.aborted, true);

    const chaosHealthy = await reqJson(port, 'POST', '/api/projects/proj_c14_a/chaos/simulate', {
      token: master,
      body: { environment: 'staging', faultType: 'latency_jitter', latencyMs: 60, jitterMs: 10, faultRatePct: 5, recoverySec: 10 }
    });
    assert.strictEqual(chaosHealthy.status, 200);
    assert.strictEqual(chaosHealthy.json.status, 'COMPLETED');
    assert.ok(chaosHealthy.json.resilienceScore >= 85);

    const chaosList = await reqJson(port, 'GET', '/api/projects/proj_c14_a/chaos/gamedays', { token: master });
    assert.strictEqual(chaosList.status, 200);
    assert.ok(Array.isArray(chaosList.json.gamedays) && chaosList.json.gamedays.length >= 2);

    // 6. Strict RBAC & Multi-Tenant 403 Enforcement
    const bootOwner = teamManager.bootstrapOwner({ email: 'c14-owner@example.test', password: 'OwnerPassword!2026' });
    const ownerPrincipal = teamManager.verifySessionToken(bootOwner.sessionToken).principal;
    const invViewer = teamManager.createInvite(ownerPrincipal, { email: 'c14-viewer@example.test', role: 'viewer' });
    const accViewer = teamManager.acceptInvite({ token: invViewer.inviteToken, email: 'c14-viewer@example.test', password: 'ViewerPassword!2026', name: 'ViewerA' });

    const viewerGetEg = await reqJson(port, 'GET', '/api/projects/proj_c14_a/egress-policy', { token: accViewer.sessionToken });
    assert.strictEqual(viewerGetEg.status, 200);
    const viewerPutEg = await reqJson(port, 'PUT', '/api/projects/proj_c14_a/egress-policy', {
      token: accViewer.sessionToken,
      body: { mode: 'permissive' }
    });
    assert.strictEqual(viewerPutEg.status, 403, 'Viewer MUST get 403 on PUT /egress-policy');

    const viewerPromote = await reqJson(port, 'POST', '/api/databases/db_c14_pg/replicas/promote', {
      token: accViewer.sessionToken,
      body: { targetReplicaId: 'pg-rep-sync' }
    });
    assert.strictEqual(viewerPromote.status, 403, 'Viewer MUST get 403 on POST /replicas/promote');

    const teamB = teamManager.createTeam(ownerPrincipal, { name: 'Tenant B C14' });
    const invDevB = teamManager.createInvite(ownerPrincipal, { email: 'c14-devb@example.test', role: 'developer', teamId: teamB.id });
    const accDevB = teamManager.acceptInvite({ token: invDevB.inviteToken, email: 'c14-devb@example.test', password: 'DevBPassword!2026', name: 'DevB' });

    const foreignEgress = await reqJson(port, 'POST', '/api/projects/proj_c14_a/egress-audit', {
      token: accDevB.sessionToken,
      body: { observedSockets: [] }
    });
    assert.strictEqual(foreignEgress.status, 403, 'Foreign tenant MUST get 403 on /projects/:id/egress-audit');

    const foreignChaos = await reqJson(port, 'POST', '/api/projects/proj_c14_a/chaos/simulate', {
      token: accDevB.sessionToken,
      body: { environment: 'staging', faultType: 'latency_jitter' }
    });
    assert.strictEqual(foreignChaos.status, 403, 'Foreign tenant MUST get 403 on /projects/:id/chaos/simulate');

    console.log('CYCLE14_HTTP_E2E_OK');
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
    assert.ok(out.includes('CYCLE14_HTTP_E2E_OK'), `Cycle-14 HTTP E2E check failed:\n${out}`);
    console.log('  ✓ Container Egress/nftables Drift Auditor (metadata/LAN flags, missing DOCKER-USER, antiLockoutSafe SSH/80/443) verified over live HTTP');
    console.log('  ✓ Blue/Green DB Read-Replica Failover (lag filter, REPLICA_LAG_TOO_HIGH + OLD_PRIMARY_NOT_FENCED blocks, 4-step dry-run) verified over live HTTP');
    console.log('  ✓ Pre-Deploy Shannon-Entropy Secret Gate (0 raw echoes vs benign UUID/SHA/pragma pass) verified over live HTTP');
    console.log('  ✓ Multi-Arch OCI Manifest & Matrix Planner (EXEC_FORMAT_MISMATCH + native fleet routing ahead of QEMU) verified over live HTTP');
    console.log('  ✓ Chaos GameDay Simulator (400 PROD_CHAOS_CONFIRM_REQUIRED, AUTO_ABORTED, healthy >=85 scorecard) verified over live HTTP');
    console.log('  ✓ Strict RBAC & Multi-Tenant 403 Isolation (viewer/dev blocks + Tenant B 403 on egress & chaos) verified over live HTTP');
    console.log('✅ Cycle #14 Live Isolated HTTP E2E Suite PASSED!\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  testCycle14HttpE2E()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ Cycle #14 HTTP E2E Suite failed:', err);
      process.exit(1);
    });
}

module.exports = testCycle14HttpE2E;
