const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

async function testCycle11HttpE2E() {
  console.log('\n🚀 Testing Cycle #11 Enterprise Governance & Multi-Region Edge Live Isolated HTTP E2E (Admission Gate, Ed25519 Compliance Bundle, Stateful Volume Migration, Edge Geo/A-B + Kill-Switch)...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c11-http-'));
  const rootDir = path.resolve(__dirname, '..');
  const runnerPath = path.join(tmpDir, 'cycle11-http-runner.js');

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
    const CANARY_SECRET = 'sk_live_c11_canary_never_leak_999';
    const projA = projectManager.create({
      id: 'proj_c11_a',
      name: 'Cycle11 Governance App',
      domains: ['c11.example.test'],
      envVars: { STRIPE_SECRET_KEY: CANARY_SECRET }
    });

    // 1. Policy-as-Code Admission Gate (GET / PUT / POST evaluate 422 ADMISSION_DENIED vs 200 ALLOW)
    const polGet = await reqJson(port, 'GET', '/api/security/admission-policy', { token: master });
    assert.strictEqual(polGet.status, 200, 'GET admission-policy failed: ' + polGet.text);
    assert.strictEqual(polGet.json.preset, 'baseline');
    assert.strictEqual(polGet.json.catalog.length, 10);

    const polPut = await reqJson(port, 'PUT', '/api/security/admission-policy', {
      token: master,
      body: { preset: 'restricted' }
    });
    assert.strictEqual(polPut.status, 200, 'PUT admission-policy failed: ' + polPut.text);
    assert.strictEqual(polPut.json.preset, 'restricted');

    const badRootEval = await reqJson(port, 'POST', '/api/security/admission-policy/evaluate', {
      token: master,
      body: {
        enforceStatus: true,
        spec: {
          image: 'nginx:latest',
          privileged: true,
          volumes: ['- /:/host:rw', '/var/run/docker.sock:/var/run/docker.sock'],
          capAdd: ['SYS_ADMIN'],
          user: '0',
          bindAddress: '0.0.0.0',
          port: 5432
        }
      }
    });
    assert.strictEqual(badRootEval.status, 422, 'Enforced violation MUST return HTTP 422: ' + badRootEval.text);
    assert.strictEqual(badRootEval.json.code, 'ADMISSION_DENIED');
    assert.strictEqual(badRootEval.json.allowed, false);
    assert.ok(badRootEval.json.enforcedViolations.some((v) => v.id === 'no_host_root_mount'));
    assert.ok(badRootEval.json.enforcedViolations.some((v) => v.id === 'no_public_db_or_panel_bind'));

    const goodEval = await reqJson(port, 'POST', '/api/security/admission-policy/evaluate', {
      token: master,
      body: {
        enforceStatus: true,
        spec: {
          image: 'ghcr.io/culkibo/app:1.4.2',
          privileged: false,
          user: '1000:1000',
          memoryLimitMb: 512,
          cpuLimit: 1,
          healthcheckPath: '/healthz',
          bindAddress: '127.0.0.1',
          port: 3000,
          attestationVerified: true
        }
      }
    });
    assert.strictEqual(goodEval.status, 200, 'Hardened spec MUST pass with HTTP 200: ' + goodEval.text);
    assert.strictEqual(goodEval.json.allowed, true);
    assert.strictEqual(goodEval.json.score, 100);

    // 2. Ed25519-Signed Compliance Evidence Bundle (POST / GET latest / POST verify + 1-byte tamper + 0 secret leaks)
    const cmpBefore = await reqJson(port, 'GET', '/api/compliance/bundle/latest', { token: master });
    assert.strictEqual(cmpBefore.status, 200);
    assert.strictEqual(cmpBefore.json.found, false);

    const cmpGen = await reqJson(port, 'POST', '/api/compliance/bundle', {
      token: master,
      body: { framework: 'all' }
    });
    assert.strictEqual(cmpGen.status, 201, 'POST /api/compliance/bundle failed: ' + cmpGen.text);
    assert.strictEqual(cmpGen.json.algorithm, 'Ed25519');
    assert.ok(cmpGen.json.signatureB64 && cmpGen.json.publicKeyPem && cmpGen.json.payloadSha256);
    assert.ok(typeof cmpGen.json.markdownReport === 'string' && cmpGen.json.markdownReport.includes('SOC2-CC6.1'));
    assert.ok(!cmpGen.text.includes(CANARY_SECRET), 'Compliance bundle MUST NEVER leak plaintext secrets!');
    assert.ok(!cmpGen.text.includes('BEGIN PRIVATE KEY'), 'Compliance bundle MUST NEVER leak Ed25519 private key!');

    const cmpLatest = await reqJson(port, 'GET', '/api/compliance/bundle/latest', { token: master });
    assert.strictEqual(cmpLatest.status, 200);
    assert.strictEqual(cmpLatest.json.found, true);
    assert.strictEqual(cmpLatest.json.bundleId, cmpGen.json.bundleId);

    const cmpVerOk = await reqJson(port, 'POST', '/api/compliance/bundle/verify', {
      token: master,
      body: { bundle: cmpGen.json }
    });
    assert.strictEqual(cmpVerOk.status, 200);
    assert.strictEqual(cmpVerOk.json.valid, true);

    const tampered = JSON.parse(JSON.stringify(cmpGen.json));
    tampered.payload.overallScore = (tampered.payload.overallScore || 90) - 1;
    const cmpVerBad = await reqJson(port, 'POST', '/api/compliance/bundle/verify', {
      token: master,
      body: { bundle: tampered }
    });
    assert.strictEqual(cmpVerBad.status, 200);
    assert.strictEqual(cmpVerBad.json.valid, false, '1-byte tampered compliance bundle MUST fail verify!');

    // 3. Stateful Volume Snapshot Cloner & Cross-VPS Migration Planner (CVE-2025-66213, traversal, cross-org 403)
    const volOk = await reqJson(port, 'POST', '/api/volumes/migrations/plan', {
      token: master,
      body: {
        projectId: projA.id,
        volumeName: 'culkibo_pg_main_data',
        mountPath: '/var/lib/postgresql/data',
        sourceHost: 'vps-eu-1',
        targetHost: 'vps-eu-2',
        uid: 999,
        gid: 999,
        containerName: 'culkibo_pg_main',
        sourceOrgId: 'org_alpha',
        targetOrgId: 'org_alpha'
      }
    });
    assert.strictEqual(volOk.status, 201, 'POST volume migration plan failed: ' + volOk.text);
    assert.strictEqual(volOk.json.zeroShell, true);
    assert.strictEqual(volOk.json.uidGid, '999:999');
    assert.strictEqual(volOk.json.phases.length, 4);
    assert.ok(volOk.text.includes('--numeric-owner'), 'Volume migration plan must preserve --numeric-owner');

    const volInject = await reqJson(port, 'POST', '/api/volumes/migrations/plan', {
      token: master,
      body: {
        projectId: projA.id,
        volumeName: 'pgdata;id',
        mountPath: '/var/lib/postgresql/data',
        targetHost: 'vps-eu-2'
      }
    });
    assert.strictEqual(volInject.status, 400, 'CVE-2025-66213 shell metachar volumeName MUST return 400');

    const volTrav = await reqJson(port, 'POST', '/api/volumes/migrations/plan', {
      token: master,
      body: {
        projectId: projA.id,
        volumeName: 'safe_vol',
        mountPath: '/data/../etc/passwd',
        targetHost: 'vps-eu-2'
      }
    });
    assert.strictEqual(volTrav.status, 400, 'Path traversal mountPath MUST return 400');

    const volCrossOrg = await reqJson(port, 'POST', '/api/volumes/migrations/plan', {
      token: master,
      body: {
        projectId: projA.id,
        volumeName: 'safe_vol',
        mountPath: '/var/lib/postgresql/data',
        targetHost: 'vps-eu-2',
        sourceOrgId: 'org_alpha',
        targetOrgId: 'org_evil'
      }
    });
    assert.strictEqual(volCrossOrg.status, 403, 'Cross-org volume migration MUST return 403');

    const volList = await reqJson(port, 'GET', '/api/volumes/migrations', { token: master });
    assert.strictEqual(volList.status, 200);
    assert.ok(Array.isArray(volList.json.migrations) && volList.json.migrations.length >= 1);

    // 4. Multi-Region Edge Geo-Routing & Sticky A/B Experiments + 1-Click Kill-Switch
    const badCountry = await reqJson(port, 'POST', '/api/edge/experiments', {
      token: master,
      body: {
        projectId: projA.id,
        hostname: 'geo.example.test',
        headerName: 'CF-IPCountry',
        regions: [{ countries: ['ZZZ'], upstream: '10.0.1.10:3000' }],
        defaultUpstream: '10.0.2.10:3000'
      }
    });
    assert.strictEqual(badCountry.status, 400, 'Invalid ISO country code MUST return 400');

    const badWeights = await reqJson(port, 'POST', '/api/edge/experiments', {
      token: master,
      body: {
        projectId: projA.id,
        hostname: 'ab.example.test',
        stickyMode: 'cookie',
        variants: [
          { name: 'control', upstream: '127.0.0.1:4100', weight: 50 },
          { name: 'treatment', upstream: '127.0.0.1:4101', weight: 40 }
        ]
      }
    });
    assert.strictEqual(badWeights.status, 400, 'Weights summing to != 100 MUST return 400');

    const abCreate = await reqJson(port, 'POST', '/api/edge/experiments', {
      token: master,
      body: {
        id: 'exp_checkout_v2',
        projectId: projA.id,
        name: 'Checkout V2 Sticky Split',
        hostname: 'ab.example.test',
        stickyMode: 'cookie',
        variants: [
          { name: 'control', upstream: '127.0.0.1:4100', weight: 50 },
          { name: 'treatment', upstream: '127.0.0.1:4101', weight: 50 }
        ]
      }
    });
    assert.strictEqual(abCreate.status, 201, 'Valid A/B experiment creation failed: ' + abCreate.text);
    assert.strictEqual(abCreate.json.experiment.compiledCaddy.route.handle[0].load_balancing.selection_policy.policy, 'cookie');

    const expList = await reqJson(port, 'GET', '/api/edge/experiments', { token: master });
    assert.strictEqual(expList.status, 200);
    assert.ok(Array.isArray(expList.json.experiments) && expList.json.experiments.length >= 1);

    const ksRes = await reqJson(port, 'POST', '/api/edge/experiments/exp_checkout_v2/kill-switch', {
      token: master,
      body: { reason: 'checkout_error_spike' }
    });
    assert.strictEqual(ksRes.status, 200, 'Kill-switch failed: ' + ksRes.text);
    assert.strictEqual(ksRes.json.killed, true);
    assert.strictEqual(ksRes.json.controlUpstream, '127.0.0.1:4100');
    assert.strictEqual(ksRes.json.experiment.compiledCaddy.route.handle[0].upstreams.length, 1);

    // 5. Multi-Tenant Cross-Tenant 403 Enforcement (Tenant B developer blocked on Tenant A resources & admin-only routes)
    const bootOwner = teamManager.bootstrapOwner({ email: 'c11-owner@example.test', password: 'OwnerPassword!2026' });
    const ownerPrincipal = teamManager.verifySessionToken(bootOwner.sessionToken).principal;
    const teamB = teamManager.createTeam(ownerPrincipal, { name: 'Tenant B C11' });
    const invB = teamManager.createInvite(ownerPrincipal, { email: 'c11-devb@example.test', role: 'developer', teamId: teamB.id });
    const accB = teamManager.acceptInvite({ token: invB.inviteToken, email: 'c11-devb@example.test', password: 'TenantBPassword!2026', name: 'DevB' });

    const devPutPolicy = await reqJson(port, 'PUT', '/api/security/admission-policy', {
      token: accB.sessionToken,
      body: { preset: 'baseline' }
    });
    assert.strictEqual(devPutPolicy.status, 403, 'Non-admin developer MUST get 403 on PUT /api/security/admission-policy');

    const devGenCompliance = await reqJson(port, 'POST', '/api/compliance/bundle', {
      token: accB.sessionToken,
      body: { framework: 'soc2' }
    });
    assert.strictEqual(devGenCompliance.status, 403, 'Non-admin developer MUST get 403 on POST /api/compliance/bundle');

    const foreignVolPlan = await reqJson(port, 'POST', '/api/volumes/migrations/plan', {
      token: accB.sessionToken,
      body: {
        projectId: projA.id,
        volumeName: 'culkibo_pg_main_data',
        mountPath: '/var/lib/postgresql/data',
        targetHost: 'vps-eu-2'
      }
    });
    assert.strictEqual(foreignVolPlan.status, 403, 'Tenant B MUST get 403 on foreign project volume migration plan');

    const foreignVolList = await reqJson(port, 'GET', '/api/volumes/migrations', { token: accB.sessionToken });
    assert.strictEqual(foreignVolList.status, 200);
    assert.strictEqual(foreignVolList.json.migrations.length, 0, 'Tenant B MUST NOT see Tenant A volume migrations');

    const foreignExpCreate = await reqJson(port, 'POST', '/api/edge/experiments', {
      token: accB.sessionToken,
      body: {
        projectId: projA.id,
        hostname: 'hijack.example.test',
        stickyMode: 'cookie',
        variants: [
          { name: 'a', upstream: '127.0.0.1:4100', weight: 50 },
          { name: 'b', upstream: '127.0.0.1:4101', weight: 50 }
        ]
      }
    });
    assert.strictEqual(foreignExpCreate.status, 403, 'Tenant B MUST get 403 on foreign project edge experiment');

    const foreignExpKill = await reqJson(port, 'POST', '/api/edge/experiments/exp_checkout_v2/kill-switch', {
      token: accB.sessionToken,
      body: { reason: 'unauthorized' }
    });
    assert.strictEqual(foreignExpKill.status, 403, 'Tenant B MUST get 403 triggering kill-switch on Tenant A experiment');

    const foreignExpList = await reqJson(port, 'GET', '/api/edge/experiments', { token: accB.sessionToken });
    assert.strictEqual(foreignExpList.status, 200);
    assert.strictEqual(foreignExpList.json.experiments.length, 0, 'Tenant B MUST NOT see Tenant A edge experiments');

    console.log('CYCLE11_HTTP_E2E_OK');
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
    assert.ok(out.includes('CYCLE11_HTTP_E2E_OK'), `Cycle-11 HTTP E2E check failed:\n${out}`);
    console.log('  ✓ Policy-as-Code Admission Gate (GET/PUT restricted, - /:/host:rw -> 422 ADMISSION_DENIED, hardened -> 200) verified over live HTTP');
    console.log('  ✓ Ed25519 Compliance Evidence Bundle (POST/GET latest/verify + 1-byte tamper detect + 0 canary secrets) verified over live HTTP');
    console.log('  ✓ Stateful Volume Migration Planner (--numeric-owner 999:999 201, CVE-2025-66213 400, ../ traversal 400, cross-org 403) verified over live HTTP');
    console.log('  ✓ Multi-Region Edge Geo/A-B Experiments (invalid country 400, weight sum != 100 400, cookie split 201, 1-click kill-switch 200) verified over live HTTP');
    console.log('  ✓ Strict Cross-Tenant 403 Isolation (Tenant B blocked on policy PUT, compliance POST, foreign volume & foreign edge experiments) verified over live HTTP');
    console.log('✅ Cycle #11 Live Isolated HTTP E2E Suite PASSED!\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  testCycle11HttpE2E()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ Cycle #11 HTTP E2E Suite failed:', err);
      process.exit(1);
    });
}

module.exports = testCycle11HttpE2E;
