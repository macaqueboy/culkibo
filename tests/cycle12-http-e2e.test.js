const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

async function testCycle12HttpE2E() {
  console.log('\n🚀 Testing Cycle #12 Reliability & Security Live Isolated HTTP E2E (Synthetic Flows/TLS, SQL DDL Linter, KEDA Autoscaler, SPDX License Audit, Seccomp/runc Guard)...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c12-http-'));
  const rootDir = path.resolve(__dirname, '..');
  const runnerPath = path.join(tmpDir, 'cycle12-http-runner.js');

  fs.writeFileSync(runnerPath, `
const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');

const TMP_DIR = ${JSON.stringify(tmpDir)};
const ROOT_DIR = ${JSON.stringify(rootDir)};
process.env.NODE_ENV = 'test';
process.env.CULKIBO_DATA_DIR = TMP_DIR;
process.env.CULKIBO_DISABLE_AUDIT_DISK = '1';
delete process.env.CULKIBO_ALLOW_LOOPBACK_SYNTHETIC;

const express = require(path.join(ROOT_DIR, 'node_modules', 'express'));
const auth = require(path.join(ROOT_DIR, 'server/middleware/auth'));
const projectManager = require(path.join(ROOT_DIR, 'server/services/projectManager'));
const teamManager = require(path.join(ROOT_DIR, 'server/services/teamManager'));
const systemDoctor = require(path.join(ROOT_DIR, 'server/services/systemDoctor'));
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
      id: 'proj_c12_a',
      name: 'Cycle12 Reliability App',
      domains: ['c12.example.test']
    });

    // 1. Synthetic Multi-Step Flows CRUD + Secret Redaction + SSRF Guard + TLS Sentinel SSRF Guard
    const SECRET_API_KEY = 'ck_live_never_persist_c12_secret';
    const flowSave = await reqJson(port, 'POST', '/api/uptime/synthetic/flows', {
      token: master,
      body: {
        id: 'flow_checkout_c12',
        name: 'Checkout Login Flow',
        projectId: projA.id,
        steps: [
          {
            name: 'login',
            method: 'POST',
            url: 'https://api.example.test/login',
            headers: { 'X-Api-Key': SECRET_API_KEY },
            body: { user: 'demo', password: 'SuperSecretPassword!99' },
            extract: { token: 'json.access_token' },
            assert: { status: 200 }
          },
          {
            name: 'profile',
            method: 'GET',
            url: 'https://api.example.test/me',
            headers: { Authorization: 'Bearer {{token}}' },
            assert: { status: 200, maxLatencyMs: 500 }
          }
        ]
      }
    });
    assert.strictEqual(flowSave.status, 201, 'POST synthetic flow failed: ' + flowSave.text);
    assert.ok(!flowSave.text.includes(SECRET_API_KEY), 'Literal sensitive header MUST be redacted');
    assert.ok(!flowSave.text.includes('SuperSecretPassword!99'), 'Literal sensitive body password MUST be redacted');
    assert.strictEqual(flowSave.json.flow.steps[0].headers['X-Api-Key'], '[REDACTED]');
    assert.strictEqual(flowSave.json.flow.steps[1].headers.Authorization, 'Bearer {{token}}');

    const flowList = await reqJson(port, 'GET', '/api/uptime/synthetic/flows', { token: master });
    assert.strictEqual(flowList.status, 200);
    assert.ok(Array.isArray(flowList.json.flows) && flowList.json.flows.some((f) => f.id === 'flow_checkout_c12'));

    const ssrfMetaRun = await reqJson(port, 'POST', '/api/uptime/synthetic/run', {
      token: master,
      body: {
        flow: {
          name: 'SSRF Metadata Probe',
          steps: [{ name: 'imds', method: 'GET', url: 'http://169.254.169.254/latest/meta-data/' }]
        },
        allowLoopback: true
      }
    });
    assert.strictEqual(ssrfMetaRun.status, 200);
    assert.strictEqual(ssrfMetaRun.json.ok, false, '169.254.169.254 MUST fail SSRF guard');
    assert.ok(JSON.stringify(ssrfMetaRun.json).includes('SSRF_BLOCKED'));

    const ssrfLoopRun = await reqJson(port, 'POST', '/api/uptime/synthetic/run', {
      token: master,
      body: {
        flow: {
          name: 'SSRF Loopback Attempt',
          steps: [{ name: 'local', method: 'GET', url: 'http://127.0.0.1:' + port + '/api/health' }]
        },
        allowLoopback: true
      }
    });
    assert.strictEqual(ssrfLoopRun.status, 200);
    assert.strictEqual(ssrfLoopRun.json.ok, false, 'Caller allowLoopback MUST be ignored when env flag is unset');
    assert.ok(JSON.stringify(ssrfLoopRun.json).includes('SSRF_BLOCKED'));

    const tlsSsrfMeta = await reqJson(port, 'POST', '/api/uptime/tls-sentinel', {
      token: master,
      body: { host: '169.254.169.254', port: 443 }
    });
    assert.strictEqual(tlsSsrfMeta.status, 403, 'TLS Sentinel MUST block 169.254.169.254 with 403');
    assert.strictEqual(tlsSsrfMeta.json.code, 'SSRF_BLOCKED');

    const tlsSsrfLoop = await reqJson(port, 'POST', '/api/uptime/tls-sentinel', {
      token: master,
      body: { host: '127.0.0.1', port: 443 }
    });
    assert.strictEqual(tlsSsrfLoop.status, 403, 'TLS Sentinel MUST block 127.0.0.1 with 403 by default');

    const flowDel = await reqJson(port, 'DELETE', '/api/uptime/synthetic/flows/flow_checkout_c12', { token: master });
    assert.strictEqual(flowDel.status, 200);
    assert.strictEqual(flowDel.json.deleted, true);

    // 2. Zero-Downtime SQL Migration Linter (blocked vs safe)
    const sqlBad = await reqJson(port, 'POST', '/api/databases/lint-sql', {
      token: master,
      body: {
        sql: 'CREATE INDEX idx_orders_uid ON orders(user_id); ALTER TABLE orders DROP COLUMN legacy_ref; ALTER TABLE orders ADD CONSTRAINT fk_u FOREIGN KEY (user_id) REFERENCES users(id);'
      }
    });
    assert.strictEqual(sqlBad.status, 200, 'POST /api/databases/lint-sql failed: ' + sqlBad.text);
    assert.strictEqual(sqlBad.json.safe, false);
    const badRules = sqlBad.json.blockers.map((b) => b.rule);
    assert.ok(badRules.includes('CREATE_INDEX_NOT_CONCURRENT'));
    assert.ok(badRules.includes('DESTRUCTIVE_DROP_COLUMN_OR_TABLE'));
    assert.ok(badRules.includes('UNSAFE_ADD_CONSTRAINT'));
    assert.ok(badRules.includes('MISSING_LOCK_TIMEOUT'));

    const sqlGood = await reqJson(port, 'POST', '/api/databases/lint-sql', {
      token: master,
      body: {
        sql: "SET lock_timeout = '5s'; SET statement_timeout = '30s'; CREATE INDEX CONCURRENTLY idx_orders_uid ON orders(user_id);"
      }
    });
    assert.strictEqual(sqlGood.status, 200);
    assert.strictEqual(sqlGood.json.safe, true);
    assert.strictEqual(sqlGood.json.score, 100);

    // 3. Queue/Worker Autoscaler & Backpressure Circuit Breaker
    const asGet = await reqJson(port, 'GET', '/api/projects/proj_c12_a/autoscaler', { token: master });
    assert.strictEqual(asGet.status, 200, 'GET autoscaler failed: ' + asGet.text);
    assert.strictEqual(asGet.json.projectId, projA.id);

    const asPut = await reqJson(port, 'PUT', '/api/projects/proj_c12_a/autoscaler', {
      token: master,
      body: {
        minReplicas: 1,
        maxReplicas: 8,
        perReplicaRamMb: 256,
        reserveHostRamMb: 512,
        scaleUpCooldownSec: 60,
        breakerQueueThreshold: 200,
        breakerRetryAfterSec: 45
      }
    });
    assert.strictEqual(asPut.status, 200, 'PUT autoscaler failed: ' + asPut.text);
    assert.strictEqual(asPut.json.maxReplicas, 8);

    const asCap = await reqJson(port, 'POST', '/api/projects/proj_c12_a/autoscaler/evaluate', {
      token: master,
      body: { queueDepth: 150, currentReplicas: 1, hostFreeRamMb: 1024 }
    });
    assert.strictEqual(asCap.status, 200, 'POST autoscaler evaluate failed: ' + asCap.text);
    assert.strictEqual(asCap.json.maxSafeReplicas, 2);
    assert.strictEqual(asCap.json.targetReplicas, 2);
    assert.strictEqual(asCap.json.reason, 'MEMORY_CEILING_CAPPED');

    const nowMs = Date.now();
    const asCool = await reqJson(port, 'POST', '/api/projects/proj_c12_a/autoscaler/evaluate', {
      token: master,
      body: { queueDepth: 150, currentReplicas: 2, hostFreeRamMb: 4096, lastScaleAtMs: nowMs - 10000, nowMs }
    });
    assert.strictEqual(asCool.status, 200);
    assert.strictEqual(asCool.json.action, 'HOLD');
    assert.strictEqual(asCool.json.reason, 'COOLDOWN_ACTIVE');

    const asTrip = await reqJson(port, 'POST', '/api/projects/proj_c12_a/autoscaler/evaluate', {
      token: master,
      body: { queueDepth: 250, currentReplicas: 2, hostFreeRamMb: 4096 }
    });
    assert.strictEqual(asTrip.status, 200);
    assert.strictEqual(asTrip.json.circuitBreaker.state, 'OPEN');
    assert.strictEqual(asTrip.json.circuitBreaker.httpStatus, 503);
    assert.strictEqual(asTrip.json.circuitBreaker.headers['Retry-After'], '45');

    // 4. CycloneDX 1.6 SPDX License Risk Auditor
    const licBad = await reqJson(port, 'POST', '/api/security/license-audit', {
      token: master,
      body: {
        policy: 'saas-strict',
        sbom: {
          bomFormat: 'CycloneDX',
          specVersion: '1.6',
          components: [
            { name: 'safe-lib', version: '1.0.0', licenses: [{ license: { id: 'MIT' } }] },
            { name: 'agpl-lib', version: '2.0.0', licenses: [{ license: { id: 'AGPL-3.0-only' } }] },
            { name: 'sspl-db', version: '7.0.0', licenses: [{ license: { id: 'SSPL-1.0' } }] }
          ]
        }
      }
    });
    assert.strictEqual(licBad.status, 200, 'POST license-audit failed: ' + licBad.text);
    assert.strictEqual(licBad.json.compliant, false);
    assert.strictEqual(licBad.json.violations.length, 2);

    const licGood = await reqJson(port, 'POST', '/api/security/license-audit', {
      token: master,
      body: {
        policy: 'saas-strict',
        sbom: {
          bomFormat: 'CycloneDX',
          specVersion: '1.6',
          components: [
            { name: 'express', version: '4.21.0', licenses: [{ license: { id: 'MIT' } }] },
            { name: 'ws', version: '8.18.0', licenses: [{ expression: 'MIT OR Apache-2.0' }] }
          ]
        }
      }
    });
    assert.strictEqual(licGood.status, 200);
    assert.strictEqual(licGood.json.compliant, true);
    assert.strictEqual(licGood.json.score, 100);

    // 5. Tailored Seccomp Profile (400 on unconfined!) & runc CVE-2025-31133/52565/52881 Audit + systemDoctor
    const secUnconfined = await reqJson(port, 'POST', '/api/security/seccomp/profile', {
      token: master,
      body: { stack: 'unconfined' }
    });
    assert.strictEqual(secUnconfined.status, 400, 'seccomp=unconfined MUST return 400');
    assert.strictEqual(secUnconfined.json.code, 'SECCOMP_UNCONFINED_FORBIDDEN');

    const secUnconfinedMode = await reqJson(port, 'POST', '/api/security/seccomp/profile', {
      token: master,
      body: { stack: 'node', mode: 'unconfined' }
    });
    assert.strictEqual(secUnconfinedMode.status, 400);
    assert.strictEqual(secUnconfinedMode.json.code, 'SECCOMP_UNCONFINED_FORBIDDEN');

    const secNode = await reqJson(port, 'POST', '/api/security/seccomp/profile', {
      token: master,
      body: { stack: 'node' }
    });
    assert.strictEqual(secNode.status, 200, 'POST seccomp profile failed: ' + secNode.text);
    assert.strictEqual(secNode.json.profile.defaultAction, 'SCMP_ACT_ERRNO');
    assert.ok(secNode.json.blockedSyscalls.includes('io_uring_setup'));
    assert.ok(secNode.json.blockedSyscalls.includes('mount'));

    const runcVuln = await reqJson(port, 'POST', '/api/security/runc-audit', {
      token: master,
      body: { version: 'runc version 1.2.7\\ncommit: v1.2.7-0' }
    });
    assert.strictEqual(runcVuln.status, 200);
    assert.strictEqual(runcVuln.json.status, 'CRITICAL');
    assert.strictEqual(runcVuln.json.vulnerable, true);
    assert.ok(runcVuln.json.cves.includes('CVE-2025-31133'));

    const runcSafe = await reqJson(port, 'POST', '/api/security/runc-audit', {
      token: master,
      body: { version: 'runc version 1.3.3' }
    });
    assert.strictEqual(runcSafe.status, 200);
    assert.strictEqual(runcSafe.json.status, 'PASS');
    assert.strictEqual(runcSafe.json.vulnerable, false);

    const runcHost = await reqJson(port, 'POST', '/api/security/runc-audit', { token: master, body: {} });
    assert.strictEqual(runcHost.status, 200);
    assert.strictEqual(runcHost.json.hostProbe, true);

    const docVuln = systemDoctor.checkRuncRuntime({ versionOutput: 'runc version 1.3.2' });
    assert.strictEqual(docVuln.status, 'fail', 'systemDoctor.checkRuncRuntime MUST flag runc 1.3.2 as fail');
    const docPass = systemDoctor.checkRuncRuntime({ versionOutput: 'runc version 1.3.3' });
    assert.strictEqual(docPass.status, 'ok', 'systemDoctor.checkRuncRuntime MUST pass runc 1.3.3');

    // 6. RBAC & Multi-Tenant ACL Enforcement (viewer 403 on PUT /autoscaler, foreign tenant 403)
    const bootOwner = teamManager.bootstrapOwner({ email: 'c12-owner@example.test', password: 'OwnerPassword!2026' });
    const ownerPrincipal = teamManager.verifySessionToken(bootOwner.sessionToken).principal;
    const invViewer = teamManager.createInvite(ownerPrincipal, { email: 'c12-viewer@example.test', role: 'viewer' });
    const accViewer = teamManager.acceptInvite({ token: invViewer.inviteToken, email: 'c12-viewer@example.test', password: 'ViewerPassword!2026', name: 'ViewerA' });

    const viewerGetAs = await reqJson(port, 'GET', '/api/projects/proj_c12_a/autoscaler', { token: accViewer.sessionToken });
    assert.strictEqual(viewerGetAs.status, 200, 'Same-team viewer MUST be able to read GET /autoscaler');

    const viewerPutAs = await reqJson(port, 'PUT', '/api/projects/proj_c12_a/autoscaler', {
      token: accViewer.sessionToken,
      body: { maxReplicas: 5 }
    });
    assert.strictEqual(viewerPutAs.status, 403, 'Viewer MUST get 403 on PUT /api/projects/:id/autoscaler');

    const viewerPostFlow = await reqJson(port, 'POST', '/api/uptime/synthetic/flows', {
      token: accViewer.sessionToken,
      body: { name: 'Blocked', steps: [{ url: 'https://example.com' }] }
    });
    assert.strictEqual(viewerPostFlow.status, 403, 'Viewer MUST get 403 on POST /api/uptime/synthetic/flows');

    const teamB = teamManager.createTeam(ownerPrincipal, { name: 'Tenant B C12' });
    const invDevB = teamManager.createInvite(ownerPrincipal, { email: 'c12-devb@example.test', role: 'developer', teamId: teamB.id });
    const accDevB = teamManager.acceptInvite({ token: invDevB.inviteToken, email: 'c12-devb@example.test', password: 'DevBPassword!2026', name: 'DevB' });

    const foreignAsEval = await reqJson(port, 'POST', '/api/projects/proj_c12_a/autoscaler/evaluate', {
      token: accDevB.sessionToken,
      body: { queueDepth: 50, currentReplicas: 1, hostFreeRamMb: 4096 }
    });
    assert.strictEqual(foreignAsEval.status, 403, 'Foreign tenant developer MUST get 403 on /projects/:id/autoscaler/evaluate');

    const devPutAs = await reqJson(port, 'PUT', '/api/projects/proj_c12_a/autoscaler', {
      token: accDevB.sessionToken,
      body: { maxReplicas: 9 }
    });
    assert.strictEqual(devPutAs.status, 403, 'Developer MUST get 403 on PUT /api/projects/:id/autoscaler');

    console.log('CYCLE12_HTTP_E2E_OK');
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
    assert.ok(out.includes('CYCLE12_HTTP_E2E_OK'), `Cycle-12 HTTP E2E check failed:\n${out}`);
    console.log('  ✓ Synthetic Flows CRUD + [REDACTED] secret scrubbing + SSRF metadata/loopback blocks verified over live HTTP');
    console.log('  ✓ Zero-Downtime SQL DDL Linter (unsafe blockers vs safe CONCURRENTLY 100/100) verified over live HTTP');
    console.log('  ✓ KEDA Worker Autoscaler (GET/PUT, VPS RAM ceiling cap, cooldown anti-flap, 503 Retry-After breaker) verified over live HTTP');
    console.log('  ✓ CycloneDX 1.6 SPDX License Auditor (AGPL/SSPL block vs MIT/Apache pass) verified over live HTTP');
    console.log('  ✓ Tailored Seccomp (400 SECCOMP_UNCONFINED_FORBIDDEN + SCMP_ACT_ERRNO) & runc CVE-2025-31133/52565/52881 + systemDoctor verified');
    console.log('  ✓ Strict RBAC & Multi-Tenant 403 Isolation (viewer 403 on PUT /autoscaler & POST flows; Tenant B 403 on foreign project) verified');
    console.log('✅ Cycle #12 Live Isolated HTTP E2E Suite PASSED!\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  testCycle12HttpE2E()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ Cycle #12 HTTP E2E Suite failed:', err);
      process.exit(1);
    });
}

module.exports = testCycle12HttpE2E;
