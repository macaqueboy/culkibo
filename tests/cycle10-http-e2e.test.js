const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

async function testCycle10HttpE2E() {
  console.log('\n🚀 Testing Cycle #10 Milestone Live Isolated HTTP E2E (DR Drills, SLO Canary, AI/GPU, Remote Builders, Compressed Log Archive)...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c10-http-'));
  const rootDir = path.resolve(__dirname, '..');
  const runnerPath = path.join(tmpDir, 'cycle10-http-runner.js');

  fs.writeFileSync(runnerPath, `
const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const path = require('path');
const zlib = require('zlib');

const TMP_DIR = ${JSON.stringify(tmpDir)};
const ROOT_DIR = ${JSON.stringify(rootDir)};
process.env.NODE_ENV = 'test';
process.env.CULKIBO_DATA_DIR = TMP_DIR;
process.env.CULKIBO_DISABLE_AUDIT_DISK = '1';

const express = require(path.join(ROOT_DIR, 'node_modules', 'express'));
const auth = require(path.join(ROOT_DIR, 'server/middleware/auth'));
const projectManager = require(path.join(ROOT_DIR, 'server/services/projectManager'));
const databaseManager = require(path.join(ROOT_DIR, 'server/services/databaseManager'));
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
    const proj = projectManager.create({
      id: 'proj_c10_1',
      name: 'Cycle10 E2E App',
      domains: ['c10.example.test']
    });
    databaseManager.dataFile = path.join(TMP_DIR, 'databases.json');
    databaseManager.state = {
      databases: [{
        id: 'db_c10_1',
        projectId: proj.id,
        engine: 'postgres',
        name: 'PrimaryPG',
        username: 'app',
        dbName: 'app',
        port: 5432,
        containerName: 'culkibo_pg_c10',
        volumeName: 'culkibo_pg_c10_vol',
        networkName: 'culkibo-net-proj_c10_1',
        status: 'running',
        health: 'healthy',
        exposure: { enabled: false, bindAddress: '127.0.0.1', hostPort: null },
        schedule: { enabled: false, cron: null },
        retention: { keepLast: 7 },
        backups: [],
        restoreHistory: [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      }],
      s3: null
    };

    // 1. DR Backup Fire-Drill API (20B empty gzip FAIL vs valid gzipped SQL PASS + cross-org 403)
    const emptyGz = zlib.gzipSync(Buffer.alloc(0));
    const drillFail = await reqJson(port, 'POST', '/api/databases/db_c10_1/dr-drill', {
      token: master,
      body: { engine: 'postgres', artifactBase64: emptyGz.toString('base64'), preserveAcl: true }
    });
    assert.strictEqual(drillFail.status, 200, 'DR drill empty gzip HTTP failed: ' + drillFail.text);
    assert.strictEqual(drillFail.json.verdict, 'FAIL', '20B empty gzip MUST FAIL DR fire-drill');

    const validSql = [
      '-- PostgreSQL database dump',
      'CREATE TABLE orders (id SERIAL PRIMARY KEY, total NUMERIC NOT NULL);',
      'GRANT ALL PRIVILEGES ON TABLE orders TO app;',
      'INSERT INTO orders (total) VALUES (49.99), (99.00);'
    ].join('\\n');
    const validGz = zlib.gzipSync(Buffer.from(validSql, 'utf8'));
    const expectedSha = crypto.createHash('sha256').update(validGz).digest('hex');
    const drillPass = await reqJson(port, 'POST', '/api/databases/db_c10_1/dr-drill', {
      token: master,
      body: { engine: 'postgres', artifactBase64: validGz.toString('base64'), expectedSha256: expectedSha, preserveAcl: true }
    });
    assert.strictEqual(drillPass.status, 200, 'DR drill valid SQL HTTP failed: ' + drillPass.text);
    assert.strictEqual(drillPass.json.verdict, 'PASS', 'Valid gzipped SQL must PASS DR drill: ' + drillPass.text);

    const drillsList = await reqJson(port, 'GET', '/api/dr/drills', { token: master });
    assert.strictEqual(drillsList.status, 200);
    assert.ok(Array.isArray(drillsList.json.drills) && drillsList.json.drills.length >= 2);

    const sameOrgRestore = await reqJson(port, 'POST', '/api/databases/cross-restore/plan', {
      token: master,
      body: { sourceDatabaseId: 'db_c10_1', targetDatabaseId: 'db_c10_staging', sourceOrgId: 'org_acme', targetOrgId: 'org_acme', engine: 'postgres', preserveAcl: true }
    });
    assert.strictEqual(sameOrgRestore.status, 200, 'Same-org cross-target restore plan should succeed: ' + sameOrgRestore.text);

    const crossOrgRestore = await reqJson(port, 'POST', '/api/databases/cross-restore/plan', {
      token: master,
      body: { sourceDatabaseId: 'db_c10_1', targetDatabaseId: 'db_other', sourceOrgId: 'org_acme', targetOrgId: 'org_evil', engine: 'postgres' }
    });
    assert.strictEqual(crossOrgRestore.status, 403, 'Cross-org restore plan MUST be rejected with 403');

    // 2. SLO Error-Budget Canary Auto-Rollback API (10% -> 25% + burn-rate breach -> instant ROLLED_BACK 100/0)
    const canaryStart = await reqJson(port, 'POST', '/api/projects/proj_c10_1/slo-canary/start', {
      token: master,
      body: {
        hostname: 'c10.example.test',
        stableUpstream: '127.0.0.1:4100',
        canaryUpstream: '127.0.0.1:4101',
        steps: [10, 25, 50, 100],
        sloTarget: 0.999,
        maxBurnRate: 14.4
      }
    });
    assert.strictEqual(canaryStart.status, 201, 'SLO canary start failed: ' + canaryStart.text);
    const rObj = canaryStart.json.rollout || canaryStart.json;
    const rolloutId = rObj.id;
    assert.ok(rolloutId, 'Canary rolloutId expected');
    assert.strictEqual(rObj.canaryWeight, 10);

    const canaryList = await reqJson(port, 'GET', '/api/projects/proj_c10_1/slo-canary', { token: master });
    assert.strictEqual(canaryList.status, 200);
    assert.ok(Array.isArray(canaryList.json.rollouts) && canaryList.json.rollouts.length >= 1);

    const evalHealthy = await reqJson(port, 'POST', '/api/projects/proj_c10_1/slo-canary/' + encodeURIComponent(rolloutId) + '/evaluate', {
      token: master,
      body: { totalRequests: 1000, error5xxCount: 0, baselineP95Ms: 40, canaryP95Ms: 42 }
    });
    assert.strictEqual(evalHealthy.status, 200, 'SLO canary healthy eval failed: ' + evalHealthy.text);
    const evalHealthyRollout = evalHealthy.json.rollout || evalHealthy.json;
    assert.strictEqual(evalHealthyRollout.canaryWeight, 25, 'Healthy canary must advance 10% -> 25%');

    const evalBreach = await reqJson(port, 'POST', '/api/projects/proj_c10_1/slo-canary/' + encodeURIComponent(rolloutId) + '/evaluate', {
      token: master,
      body: { totalRequests: 1000, error5xxCount: 40, baselineP95Ms: 40, canaryP95Ms: 45 }
    });
    assert.strictEqual(evalBreach.status, 200, 'SLO canary breach eval failed: ' + evalBreach.text);
    const evalBreachRollout = evalBreach.json.rollout || evalBreach.json;
    assert.strictEqual(evalBreachRollout.status, 'ROLLED_BACK', 'Burn-rate breach must trigger instant ROLLED_BACK');
    assert.strictEqual(evalBreachRollout.canaryWeight, 0, 'ROLLED_BACK must restore Caddy weights to 100/0');

    const canaryStart2 = await reqJson(port, 'POST', '/api/projects/proj_c10_1/slo-canary/start', {
      token: master,
      body: { hostname: 'c10.example.test', stableUpstream: '127.0.0.1:4100', canaryUpstream: '127.0.0.1:4102' }
    });
    assert.strictEqual(canaryStart2.status, 201);
    const rid2 = (canaryStart2.json.rollout || canaryStart2.json).id;
    const abortRes = await reqJson(port, 'POST', '/api/projects/proj_c10_1/slo-canary/' + encodeURIComponent(rid2) + '/abort', {
      token: master,
      body: { reason: 'operator_check' }
    });
    assert.strictEqual(abortRes.status, 200);
    assert.strictEqual((abortRes.json.rollout || abortRes.json).canaryWeight, 0);

    // 3. Self-Hosted AI / GPU & LLM Orchestrator API
    const aiPresets = await reqJson(port, 'GET', '/api/ai/presets', { token: master });
    assert.strictEqual(aiPresets.status, 200, 'GET /api/ai/presets failed: ' + aiPresets.text);
    assert.ok(Array.isArray(aiPresets.json.presets) && aiPresets.json.presets.length >= 3);

    const vramEst = await reqJson(port, 'POST', '/api/ai/vram-estimate', {
      token: master,
      body: { paramsB: 70, quantization: 'FP16', contextLen: 8192, availableVramGb: 24 }
    });
    assert.strictEqual(vramEst.status, 200, 'POST /api/ai/vram-estimate failed: ' + vramEst.text);
    assert.strictEqual(vramEst.json.fits, false);

    const aiOverflow = await reqJson(port, 'POST', '/api/ai/plan', {
      token: master,
      body: { runtime: 'ollama', model: 'llama3.3:70b', paramsB: 70, quantization: 'FP16', availableVramGb: 16 }
    });
    assert.strictEqual(aiOverflow.status, 400, 'VRAM overflow MUST fail closed with 400');

    const aiPublicExpose = await reqJson(port, 'POST', '/api/ai/plan', {
      token: master,
      body: { runtime: 'ollama', model: 'llama3.2:8b', paramsB: 8, quantization: 'Q4_K_M', availableVramGb: 16, bindAddress: '0.0.0.0', authProxyEnabled: false }
    });
    assert.strictEqual(aiPublicExpose.status, 400, 'Unauthenticated 0.0.0.0:11434 MUST fail closed with 400 (CVE-2025-63389)');

    const aiOk = await reqJson(port, 'POST', '/api/ai/plan', {
      token: master,
      body: { runtime: 'ollama', model: 'llama3.2:8b', paramsB: 8, quantization: 'Q4_K_M', availableVramGb: 16, gpuMode: 'cdi', bindAddress: '127.0.0.1', authProxyEnabled: true }
    });
    assert.strictEqual(aiOk.status, 200, 'Valid CDI AI workload plan failed: ' + aiOk.text);
    assert.ok(Array.isArray(aiOk.json.dockerArgs) && aiOk.json.dockerArgs.includes('nvidia.com/gpu=all'));

    // 4. Distributed Remote Build-Node Offloader API (mux pinning + PR preview offload)
    const bldReg = await reqJson(port, 'POST', '/api/fleet/builders', {
      token: master,
      body: { id: 'bld_eu_1', name: 'EU Builder 1', host: '10.88.0.11', arch: 'linux/amd64', maxConcurrency: 2, allowPreviews: true }
    });
    assert.strictEqual(bldReg.status, 201, 'POST /api/fleet/builders failed: ' + bldReg.text);
    const bldList = await reqJson(port, 'GET', '/api/fleet/builders', { token: master });
    assert.strictEqual(bldList.status, 200);
    assert.ok(Array.isArray(bldList.json.builders) && bldList.json.builders.length >= 1);

    const bldSched = await reqJson(port, 'POST', '/api/fleet/builders/schedule', {
      token: master,
      body: { builderId: 'bld_eu_1', projectId: 'proj_c10_1', arch: 'linux/amd64', isPreview: true }
    });
    assert.strictEqual(bldSched.status, 200, 'POST /api/fleet/builders/schedule failed: ' + bldSched.text);
    assert.strictEqual(bldSched.json.leased, true);
    assert.strictEqual(bldSched.json.sshMuxPinned, true);

    const muxBlocked = await reqJson(port, 'POST', '/api/fleet/builders/schedule', {
      token: master,
      body: { action: 'can_recycle_mux', builderId: 'bld_eu_1' }
    });
    assert.strictEqual(muxBlocked.status, 200);
    assert.strictEqual(muxBlocked.json.allowed, false, 'SSH mux recycle MUST be blocked while activeBuilds > 0 (coolify#11372)');

    const relSlot = await reqJson(port, 'POST', '/api/fleet/builders/schedule', {
      token: master,
      body: { action: 'release', leaseId: bldSched.json.leaseId }
    });
    assert.strictEqual(relSlot.status, 200);

    const muxAllowed = await reqJson(port, 'POST', '/api/fleet/builders/schedule', {
      token: master,
      body: { action: 'can_recycle_mux', builderId: 'bld_eu_1' }
    });
    assert.strictEqual(muxAllowed.status, 200);
    assert.strictEqual(muxAllowed.json.allowed, true);

    // 5. Compressed .ndjson.gz Log Archive & ReDoS-Safe Search + Cross-Tenant 403
    const logApp = await reqJson(port, 'POST', '/api/projects/proj_c10_1/logs/archive/append', {
      token: master,
      body: {
        entries: [
          { ts: new Date().toISOString(), level: 'info', releaseId: 'rel_10', stream: 'stdout', message: 'Booted HTTP worker' },
          { ts: new Date().toISOString(), level: 'error', releaseId: 'rel_10', stream: 'stderr', message: 'Upstream pool timeout after 5000ms' }
        ]
      }
    });
    assert.strictEqual(logApp.status, 201, 'POST log archive append failed: ' + logApp.text);
    assert.strictEqual(logApp.json.appended, 2);

    const logStats = await reqJson(port, 'GET', '/api/projects/proj_c10_1/logs/archive/stats', { token: master });
    assert.strictEqual(logStats.status, 200, 'GET log archive stats failed: ' + logStats.text);
    assert.ok(logStats.json.totalBytes > 0);

    const logSearch = await reqJson(port, 'POST', '/api/projects/proj_c10_1/logs/archive/search', {
      token: master,
      body: { level: 'error', query: 'timeout' }
    });
    assert.strictEqual(logSearch.status, 200, 'POST log archive search failed: ' + logSearch.text);
    assert.strictEqual(logSearch.json.totalMatches, 1);

    const logRedos = await reqJson(port, 'POST', '/api/projects/proj_c10_1/logs/archive/search', {
      token: master,
      body: { regex: '(a+)+$' }
    });
    assert.strictEqual(logRedos.status, 400, 'ReDoS regex MUST return 400');
    assert.strictEqual(logRedos.json.code, 'UNSAFE_REGEX');

    // Cross-tenant 403 check on log archive search
    const bootOwner = teamManager.bootstrapOwner({ email: 'c10-owner@example.test', password: 'OwnerPassword!2026' });
    const ownerPrincipal = teamManager.verifySessionToken(bootOwner.sessionToken).principal;
    const teamB = teamManager.createTeam(ownerPrincipal, { name: 'Tenant B C10' });
    const invB = teamManager.createInvite(ownerPrincipal, { email: 'c10-tenantb@example.test', role: 'developer', teamId: teamB.id });
    const accB = teamManager.acceptInvite({ token: invB.inviteToken, email: 'c10-tenantb@example.test', password: 'TenantBPassword!2026', name: 'TenantB' });
    const foreignLogSearch = await reqJson(port, 'POST', '/api/projects/proj_c10_1/logs/archive/search', {
      token: accB.sessionToken,
      body: { query: 'timeout' }
    });
    assert.strictEqual(foreignLogSearch.status, 403, 'Foreign tenant log archive search MUST return 403');

    console.log('CYCLE10_HTTP_E2E_OK');
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
    assert.ok(out.includes('CYCLE10_HTTP_E2E_OK'), `Cycle-10 HTTP E2E check failed:\n${out}`);
    console.log('  ✓ DR Fire-Drill (20B empty gzip FAIL, valid SQL PASS, cross-org 403) verified over live HTTP');
    console.log('  ✓ SLO Canary (10%→25% advance, burn-rate breach instant ROLLED_BACK 100/0, manual abort) verified over live HTTP');
    console.log('  ✓ AI/GPU Orchestrator (VRAM overflow 400, 0.0.0.0:11434 block 400, CDI nvidia.com/gpu=all) verified over live HTTP');
    console.log('  ✓ Remote Build-Node Offloader (PR preview offload + SSH mux ref-count pinning) verified over live HTTP');
    console.log('  ✓ Compressed .ndjson.gz Log Archive (append/stats/search + ReDoS 400 UNSAFE_REGEX + cross-tenant 403) verified over live HTTP');
    console.log('✅ Cycle #10 Live Isolated HTTP E2E Suite PASSED!\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  testCycle10HttpE2E()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ Cycle #10 HTTP E2E Suite failed:', err);
      process.exit(1);
    });
}

module.exports = testCycle10HttpE2E;
