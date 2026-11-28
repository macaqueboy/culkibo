const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

async function testCycle18HttpE2E() {
  console.log('\n🚀 Testing Cycle #18 175-MCP Milestone Live Isolated HTTP E2E (Query/Pool Guard, Network Micro-Seg, Dep Upgrades, Streaming PII Scrubber, 4-Phase Graceful Drain)...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c18-http-'));
  const rootDir = path.resolve(__dirname, '..');
  const runnerPath = path.join(tmpDir, 'cycle18-http-runner.js');

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
    projectManager.create({
      id: 'proj_c18_a',
      name: 'Cycle18 Database & Edge App',
      domains: ['c18.example.test']
    });

    // 1. DB Query-Plan & Pool Exhaustion Regression Guard (/api/db/query-guard/*)
    const badExplain = [{
      Plan: {
        'Node Type': 'Sort',
        'Sort Space Type': 'Disk',
        'Sort Space Used': 24576,
        'Total Cost': 92000,
        'Plan Rows': 500,
        'Actual Rows': 85000,
        Plans: [{
          'Node Type': 'Seq Scan',
          'Relation Name': 'orders',
          'Plan Rows': 500,
          'Actual Rows': 85000,
          'Total Cost': 78000
        }]
      }
    }];
    const nPlusOneTrace = Array.from({ length: 25 }, (_, i) => 'SELECT * FROM users WHERE id = ' + (i + 1));

    const qGate = await reqJson(port, 'POST', '/api/db/query-guard/analyze', {
      token: master,
      body: {
        projectId: 'proj_c18_a',
        planJson: badExplain,
        poolConfig: { maxConnections: 100, reservedSuperuser: 5, replicas: 8, poolSizePerReplica: 20, idleTimeoutSec: 0 },
        queryTrace: nPlusOneTrace
      }
    });
    assert.strictEqual(qGate.status, 200, 'POST /db/query-guard/analyze failed: ' + qGate.text);
    assert.strictEqual(qGate.json.allowed, false);
    assert.ok(qGate.json.blockerCodes.includes('SEQ_SCAN_REGRESSION'));
    assert.ok(qGate.json.blockerCodes.includes('ROW_ESTIMATE_SKEW'));
    assert.ok(qGate.json.blockerCodes.includes('DISK_SORT_SPILL'));
    assert.ok(qGate.json.blockerCodes.includes('POOL_OVERCOMMIT'));
    assert.ok(qGate.json.blockerCodes.includes('MISSING_IDLE_TIMEOUT'));
    assert.ok(qGate.json.blockerCodes.includes('N_PLUS_ONE_DETECTED'));

    const poolOk = await reqJson(port, 'POST', '/api/db/query-guard/pool-audit', {
      token: master,
      body: { maxConnections: 100, reservedSuperuser: 5, replicas: 4, poolSizePerReplica: 15, idleTimeoutSec: 30 }
    });
    assert.strictEqual(poolOk.status, 200);
    assert.strictEqual(poolOk.json.safe, true);

    const qHist = await reqJson(port, 'GET', '/api/db/query-guard/history?projectId=proj_c18_a', { token: master });
    assert.strictEqual(qHist.status, 200);
    assert.ok(qHist.json.count >= 1);

    // 2. Container Network Micro-Segmentation Compiler (/api/security/netseg/* — dokploy#2798)
    const nsAudit = await reqJson(port, 'POST', '/api/security/netseg/audit', {
      token: master,
      body: {
        sharedNetworkName: 'dokploy-network',
        services: [
          { name: 'web', tier: 'frontend', networks: ['dokploy-network'] },
          { name: 'api', tier: 'api', networks: ['dokploy-network'] },
          { name: 'postgres', tier: 'database', networks: ['dokploy-network'] }
        ],
        networks: { 'dokploy-network': { internal: false } }
      }
    });
    assert.strictEqual(nsAudit.status, 200, 'POST /security/netseg/audit failed: ' + nsAudit.text);
    assert.strictEqual(nsAudit.json.safe, false);
    assert.ok(nsAudit.json.violations.some((v) => v.code === 'LATERAL_DB_EXPOSURE'));

    const nsCompile = await reqJson(port, 'POST', '/api/security/netseg/compile', {
      token: master,
      body: {
        projectId: 'proj_c18_a',
        services: [{ name: 'web', tier: 'frontend' }, { name: 'api', tier: 'api' }, { name: 'postgres', tier: 'database' }],
        allowedEdges: [{ from: 'api', to: 'postgres' }]
      }
    });
    assert.strictEqual(nsCompile.status, 200);
    assert.strictEqual(nsCompile.json.dryRun, true, 'POST /security/netseg/compile MUST default to dryRun: true');
    assert.strictEqual(nsCompile.json.frontendToDbIsolated, true);
    assert.strictEqual(nsCompile.json.networks.data_postgres.internal, true);
    assert.ok(nsCompile.json.networks.data_postgres.members.includes('api'));
    assert.ok(!nsCompile.json.networks.data_postgres.members.includes('web'));

    const nsPols = await reqJson(port, 'GET', '/api/security/netseg/policies?projectId=proj_c18_a', { token: master });
    assert.strictEqual(nsPols.status, 200);
    assert.strictEqual(nsPols.json.count, 0, 'dryRun: true compile MUST NOT persist');

    // 3. Security Patch & Dependency Cooldown Planner (/api/supply-chain/upgrades/*)
    const upPlan = await reqJson(port, 'POST', '/api/supply-chain/upgrades/plan', {
      token: master,
      body: {
        projectId: 'proj_c18_a',
        minReleaseAgeHours: 168,
        dependencies: [
          { name: 'undici', currentVersion: '6.19.0', targetVersion: '6.19.8', ageHours: 2, cveIds: ['CVE-2026-99999'] },
          { name: 'fresh-lib', currentVersion: '1.2.0', targetVersion: '1.3.0', ageHours: 6 },
          { name: 'zod', currentVersion: '3.22.0', targetVersion: '3.23.8', ageHours: 400 },
          { name: 'express', currentVersion: '4.21.0', targetVersion: '5.0.1', ageHours: 720 }
        ]
      }
    });
    assert.strictEqual(upPlan.status, 200, 'POST /supply-chain/upgrades/plan failed: ' + upPlan.text);
    assert.strictEqual(upPlan.json.counts.FAST_TRACK_CVE, 1);
    assert.strictEqual(upPlan.json.counts.COOLDOWN_HOLD, 1);
    assert.strictEqual(upPlan.json.counts.SAFE_PATCH_MINOR, 1);
    assert.strictEqual(upPlan.json.counts.MAJOR_MANUAL_REVIEW, 1);

    const upCd = await reqJson(port, 'POST', '/api/supply-chain/upgrades/cooldown', {
      token: master,
      body: { manager: 'pnpm', minReleaseAgeMinutes: 10080, exclude: ['undici'] }
    });
    assert.strictEqual(upCd.status, 200);
    assert.strictEqual(upCd.json.dryRun, true);
    assert.ok(upCd.json.npmrc.includes('minimum-release-age=10080'));
    assert.ok(upCd.json.pnpmWorkspaceYaml.includes('undici'));

    const upList = await reqJson(port, 'GET', '/api/supply-chain/upgrades/plans?projectId=proj_c18_a', { token: master });
    assert.strictEqual(upList.status, 200);
    assert.ok(upList.json.count >= 1);

    // 4. Streaming Log PII Redaction & Compliance Scrubber (/api/observability/pii-scrub/* — otel-contrib#49858/#50770)
    const testCard = ['4242', '4242', '4242', '4242'].join('-');
    const orderIdNonLuhn = '4242424242424243';
    const otlpSpan = {
      spanId: 'sp_01',
      orderId: orderIdNonLuhn,
      ssn: 123456789,
      'redaction.count': 7,
      events: [{ name: 'checkout', attributes: { email: 'alice@example.test', card: testCard } }]
    };

    const scrub1 = await reqJson(port, 'POST', '/api/observability/pii-scrub/test', {
      token: master,
      body: { projectId: 'proj_c18_a', payload: otlpSpan, persist: true }
    });
    assert.strictEqual(scrub1.status, 200, 'POST /observability/pii-scrub/test failed: ' + scrub1.text);
    assert.strictEqual(scrub1.json.scrubbed.orderId, orderIdNonLuhn, 'Luhn-invalid 16-digit orderId MUST NOT be redacted');
    assert.strictEqual(scrub1.json.scrubbed.ssn, '[REDACTED:SSN]');
    assert.strictEqual(scrub1.json.scrubbed.events[0].attributes.email, '[REDACTED:EMAIL]');
    assert.strictEqual(scrub1.json.scrubbed.events[0].attributes.card, '[REDACTED:PCI_PAN]');
    assert.strictEqual(scrub1.json.scrubbed['redaction.count'], 7, 'redaction.* ledger key MUST be preserved');

    const scrub2 = await reqJson(port, 'POST', '/api/observability/pii-scrub/test', {
      token: master,
      body: { projectId: 'proj_c18_a', payload: scrub1.json.scrubbed }
    });
    assert.strictEqual(scrub2.status, 200);
    assert.strictEqual(scrub2.json.scrubbed['redaction.count'], 7, 'Chained 2nd pass MUST preserve redaction.count');

    const scrubPolDry = await reqJson(port, 'POST', '/api/observability/pii-scrub/policy', {
      token: master,
      body: { complianceProfiles: ['gdpr', 'pci'] }
    });
    assert.strictEqual(scrubPolDry.status, 200);
    assert.strictEqual(scrubPolDry.json.dryRun, true);

    const ledgerGet = await reqJson(port, 'GET', '/api/observability/pii-scrub/ledger?projectId=proj_c18_a', { token: master });
    assert.strictEqual(ledgerGet.status, 200);
    assert.ok(ledgerGet.json.count >= 1);

    // 5. 4-Phase Graceful Shutdown & Zero-Drop Drain (/api/deploys/drain/* — coolify#8627)
    const drainAudit = await reqJson(port, 'POST', '/api/deploys/drain/audit', {
      token: master,
      body: { dockerfile: 'FROM node:22-alpine\\nCMD npm start', lbDrainDelaySec: 0, healthCheckIntervalSec: 5, stopGracePeriodSec: 10, activeQueueDepth: 8 }
    });
    assert.strictEqual(drainAudit.status, 200, 'POST /deploys/drain/audit failed: ' + drainAudit.text);
    assert.strictEqual(drainAudit.json.ready, false);
    assert.ok(drainAudit.json.codes.includes('PID1_SHELL_WRAPPER'));
    assert.ok(drainAudit.json.codes.includes('LB_DRAIN_RACE'));

    const drainPlan = await reqJson(port, 'POST', '/api/deploys/drain/plan', {
      token: master,
      body: { projectId: 'proj_c18_a', serviceName: 'webhooks', inFlightHttp: 4, inFlightJobs: 3, lbDrainDelaySec: 10 }
    });
    assert.strictEqual(drainPlan.status, 200);
    assert.strictEqual(drainPlan.json.dryRun, true, 'POST /deploys/drain/plan MUST default to dryRun: true');
    const drainId = drainPlan.json.drainId;

    const advBlocked = await reqJson(port, 'POST', '/api/deploys/drain/' + drainId + '/advance', {
      token: master,
      body: { readinessFlipped: true, lbDrained: true, inFlightHttp: 0, inFlightJobs: 2 }
    });
    assert.strictEqual(advBlocked.status, 200);
    assert.strictEqual(advBlocked.json.blocked, true);
    assert.strictEqual(advBlocked.json.code, 'INFLIGHT_WORK_REMAINING');
    assert.strictEqual(advBlocked.json.sigtermEmitted, false);

    const advDone = await reqJson(port, 'POST', '/api/deploys/drain/' + drainId + '/advance', {
      token: master,
      body: { readinessFlipped: true, lbDrained: true, inFlightHttp: 0, inFlightJobs: 0 }
    });
    assert.strictEqual(advDone.status, 200);
    assert.strictEqual(advDone.json.blocked, false);
    assert.strictEqual(advDone.json.sigtermEmitted, true);
    assert.strictEqual(advDone.json.currentPhase, 'COMPLETED');

    const drainPlansGet = await reqJson(port, 'GET', '/api/deploys/drain/plans?projectId=proj_c18_a', { token: master });
    assert.strictEqual(drainPlansGet.status, 200);
    assert.ok(drainPlansGet.json.count >= 1);

    // 6. Strict RBAC & Multi-Tenant 403 Enforcement
    const bootOwner = teamManager.bootstrapOwner({ email: 'c18-owner@example.test', password: 'OwnerPassword!2026' });
    const ownerPrincipal = teamManager.verifySessionToken(bootOwner.sessionToken).principal;
    const invViewer = teamManager.createInvite(ownerPrincipal, { email: 'c18-viewer@example.test', role: 'viewer' });
    const accViewer = teamManager.acceptInvite({ token: invViewer.inviteToken, email: 'c18-viewer@example.test', password: 'ViewerPassword!2026', name: 'ViewerC18' });

    const viewerCompile = await reqJson(port, 'POST', '/api/security/netseg/compile', { token: accViewer.sessionToken, body: { projectId: 'proj_c18_a' } });
    assert.strictEqual(viewerCompile.status, 403, 'Viewer MUST get 403 on POST /security/netseg/compile');

    const viewerCooldown = await reqJson(port, 'POST', '/api/supply-chain/upgrades/cooldown', { token: accViewer.sessionToken, body: {} });
    assert.strictEqual(viewerCooldown.status, 403, 'Viewer MUST get 403 on POST /supply-chain/upgrades/cooldown');

    const viewerScrubPol = await reqJson(port, 'POST', '/api/observability/pii-scrub/policy', { token: accViewer.sessionToken, body: {} });
    assert.strictEqual(viewerScrubPol.status, 403, 'Viewer MUST get 403 on POST /observability/pii-scrub/policy');

    const viewerDrainPlan = await reqJson(port, 'POST', '/api/deploys/drain/plan', { token: accViewer.sessionToken, body: { projectId: 'proj_c18_a' } });
    assert.strictEqual(viewerDrainPlan.status, 403, 'Viewer MUST get 403 on POST /deploys/drain/plan');

    const teamB = teamManager.createTeam(ownerPrincipal, { name: 'Tenant B C18' });
    const invDevB = teamManager.createInvite(ownerPrincipal, { email: 'c18-devb@example.test', role: 'developer', teamId: teamB.id });
    const accDevB = teamManager.acceptInvite({ token: invDevB.inviteToken, email: 'c18-devb@example.test', password: 'DevBPassword!2026', name: 'DevBC18' });

    const foreignQueryGuard = await reqJson(port, 'POST', '/api/db/query-guard/analyze', {
      token: accDevB.sessionToken,
      body: { projectId: 'proj_c18_a', planJson: badExplain }
    });
    assert.strictEqual(foreignQueryGuard.status, 403, 'Foreign Tenant B MUST get 403 on /db/query-guard/analyze for proj_c18_a');

    console.log('CYCLE18_HTTP_E2E_OK');
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
    assert.ok(out.includes('CYCLE18_HTTP_E2E_OK'), `Cycle-18 HTTP E2E check failed:\n${out}`);
    console.log('  ✓ DB Query-Plan & Pool Guard (SEQ_SCAN_REGRESSION, ROW_ESTIMATE_SKEW, DISK_SORT_SPILL, POOL_OVERCOMMIT, N_PLUS_ONE) verified over live HTTP');
    console.log('  ✓ Network Micro-Segmentation Compiler (dokploy#2798 LATERAL_DB_EXPOSURE + internal: true data_postgres dryRun default) verified over live HTTP');
    console.log('  ✓ Dep Upgrade Planner (FAST_TRACK_CVE vs COOLDOWN_HOLD vs SAFE_PATCH_MINOR vs MAJOR + synced .npmrc) verified over live HTTP');
    console.log('  ✓ Streaming Log PII Scrubber (otel-contrib#49858/#50770 nested span.events[], Luhn-invalid orderId kept, 2nd-pass redaction.count kept) verified over live HTTP');
    console.log('  ✓ 4-Phase Graceful Drain (coolify#8627 PID1_SHELL_WRAPPER + LB_DRAIN_RACE + EMIT_SIGTERM blocked while inFlightJobs>0) verified over live HTTP');
    console.log('  ✓ Strict RBAC & Multi-Tenant 403 Isolation (viewer admin blocks + Tenant B 403 on foreign project) verified over live HTTP');
    console.log('✅ Cycle #18 Live Isolated HTTP E2E Suite PASSED!\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  testCycle18HttpE2E()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ Cycle #18 HTTP E2E Suite failed:', err);
      process.exit(1);
    });
}

module.exports = testCycle18HttpE2E;
