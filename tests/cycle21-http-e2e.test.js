const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

async function testCycle21HttpE2E() {
  console.log('\n🚀 Testing Cycle #21 190-MCP & 86-Suites Milestone Live Isolated HTTP E2E (CORS/CSP/SRI, Postgres XID/Vacuum, Monorepo DAG, Email Auth/SMTP, Shai-Hulud/CHAINDROP Guard)...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c21-http-'));
  const rootDir = path.resolve(__dirname, '..');
  const runnerPath = path.join(tmpDir, 'cycle21-http-runner.js');

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
      id: 'proj_c21_a',
      name: 'Cycle21 Milestone Stack',
      domains: ['c21.example.test']
    });

    // 1. Browser Security Headers, Strict CSP/SRI & CORS Firewall (/api/edge/cors-csp/*)
    const corsBad = await reqJson(port, 'POST', '/api/edge/cors-csp/audit', {
      token: master,
      body: {
        projectId: 'proj_c21_a',
        allowedOrigins: ['*'],
        allowCredentials: true,
        reflectOrigin: true,
        sameSiteCookie: 'None',
        probeOrigin: 'https://evil.example',
        headers: { 'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'" },
        externalScripts: [{ src: 'https://cdn.example.net/widget.js' }]
      }
    });
    assert.strictEqual(corsBad.status, 200, 'POST /edge/cors-csp/audit failed: ' + corsBad.text);
    assert.strictEqual(corsBad.json.safe, false);
    assert.strictEqual(corsBad.json.blocked, true);
    assert.ok(corsBad.json.cors && corsBad.json.securityHeaders);
    assert.ok(corsBad.json.findingCodes.includes('CORS_WILDCARD_CREDENTIALS'));
    assert.ok(corsBad.json.findingCodes.includes('CORS_REFLECTED_ORIGIN_CREDENTIALS'));
    assert.ok(corsBad.json.findingCodes.includes('CSP_UNSAFE_DIRECTIVE'));
    assert.ok(corsBad.json.findingCodes.includes('MISSING_SRI_HASH'));
    assert.strictEqual(typeof corsBad.json.caddyfile, 'string');

    const corsPolDry = await reqJson(port, 'POST', '/api/edge/cors-csp/policy', {
      token: master,
      body: { projectId: 'proj_c21_a', allowedOrigins: ['https://c21.example.test'], allowCredentials: true }
    });
    assert.strictEqual(corsPolDry.status, 200);
    assert.strictEqual(corsPolDry.json.dryRun, true, 'POST /edge/cors-csp/policy MUST default to dryRun: true');

    const corsPolSave = await reqJson(port, 'POST', '/api/edge/cors-csp/policy', {
      token: master,
      body: { projectId: 'proj_c21_a', allowedOrigins: ['https://c21.example.test'], allowCredentials: true, dryRun: false }
    });
    assert.strictEqual(corsPolSave.status, 200);
    assert.strictEqual(corsPolSave.json.dryRun, false);
    assert.strictEqual(corsPolSave.json.ok, true);

    const corsPolList = await reqJson(port, 'GET', '/api/edge/cors-csp/policies?projectId=proj_c21_a', { token: master });
    assert.strictEqual(corsPolList.status, 200);
    assert.strictEqual(corsPolList.json.count, 1);

    // 2. PostgreSQL Autovacuum, 32-Bit XID Wraparound & Bloat Guard (/api/db/vacuum-guard/*)
    const vacBad = await reqJson(port, 'POST', '/api/db/vacuum-guard/audit', {
      token: master,
      body: {
        projectId: 'proj_c21_a',
        databaseName: 'c21_prod',
        xidAge: 1650000000,
        idleInTxSec: 900,
        deadTuplePct: 45,
        autovacuumDisabledTables: ['audit_events'],
        inactiveSlots: 1,
        idleInTxTimeoutMs: 0
      }
    });
    assert.strictEqual(vacBad.status, 200, 'POST /db/vacuum-guard/audit failed: ' + vacBad.text);
    assert.strictEqual(vacBad.json.safe, false);
    assert.strictEqual(vacBad.json.usesVacuumFull, false);
    assert.ok(vacBad.json.findingCodes.includes('XID_WRAPAROUND_IMMINENT'));
    assert.ok(vacBad.json.findingCodes.includes('IDLE_IN_TX_XMIN_PIN'));
    assert.ok(vacBad.json.findingCodes.includes('AUTOVACUUM_DISABLED_TABLE'));
    assert.ok(vacBad.json.findingCodes.includes('TABLE_BLOAT_HIGH'));
    assert.ok(vacBad.json.findingCodes.includes('INACTIVE_REPLICATION_SLOT_PIN'));

    const vacRecDry = await reqJson(port, 'POST', '/api/db/vacuum-guard/recover-plan', {
      token: master,
      body: { projectId: 'proj_c21_a', databaseName: 'c21_prod', xidAge: 1650000000, autovacuumDisabledTables: ['audit_events'] }
    });
    assert.strictEqual(vacRecDry.status, 200);
    assert.strictEqual(vacRecDry.json.dryRun, true, 'POST /db/vacuum-guard/recover-plan MUST default to dryRun: true');
    assert.strictEqual(vacRecDry.json.usesVacuumFull, false);
    assert.ok(vacRecDry.json.recoverySql.includes('VACUUM (VERBOSE, FREEZE, ANALYZE)'));
    assert.ok(!/VACUUM\\s+FULL/i.test(vacRecDry.json.recoverySql));

    const vacAudits = await reqJson(port, 'GET', '/api/db/vacuum-guard/audits?databaseName=c21_prod', { token: master });
    assert.strictEqual(vacAudits.status, 200);
    assert.strictEqual(vacAudits.json.count, 1);

    // 3. Monorepo Affected-Graph Selective Builder & Rollout Planner (/api/builds/monorepo/*)
    const ws = [
      { name: 'packages/ui', dir: 'packages/ui', deps: [] },
      { name: 'apps/web', dir: 'apps/web', deps: ['packages/ui'] },
      { name: 'apps/billing', dir: 'apps/billing', deps: [] }
    ];
    const monoAff = await reqJson(port, 'POST', '/api/builds/monorepo/affected', {
      token: master,
      body: { projectId: 'proj_c21_a', workspaces: ws, changedFiles: ['packages/ui/btn.tsx'] }
    });
    assert.strictEqual(monoAff.status, 200, 'POST /builds/monorepo/affected failed: ' + monoAff.text);
    assert.strictEqual(monoAff.json.hasCycle, false);
    assert.deepStrictEqual(monoAff.json.affectedNames, ['apps/web', 'packages/ui']);
    assert.deepStrictEqual(monoAff.json.skippedServices, ['apps/billing']);
    assert.deepStrictEqual(monoAff.json.deployWaves, [['packages/ui'], ['apps/web']]);

    const monoCyc = await reqJson(port, 'POST', '/api/builds/monorepo/affected', {
      token: master,
      body: {
        projectId: 'proj_c21_a',
        workspaces: [
          { name: 'svc-a', dir: 'a', deps: ['svc-b'] },
          { name: 'svc-b', dir: 'b', deps: ['svc-a'] }
        ],
        changedFiles: ['a/index.ts']
      }
    });
    assert.strictEqual(monoCyc.status, 200);
    assert.strictEqual(monoCyc.json.hasCycle, true);
    assert.strictEqual(monoCyc.json.code, 'WORKSPACE_CYCLE_DETECTED');

    const monoPlanDry = await reqJson(port, 'POST', '/api/builds/monorepo/plan', {
      token: master,
      body: { projectId: 'proj_c21_a', workspaces: ws, changedFiles: ['packages/ui/btn.tsx'] }
    });
    assert.strictEqual(monoPlanDry.status, 200);
    assert.strictEqual(monoPlanDry.json.dryRun, true, 'POST /builds/monorepo/plan MUST default to dryRun: true');

    const monoPlanLive = await reqJson(port, 'POST', '/api/builds/monorepo/plan', {
      token: master,
      body: { projectId: 'proj_c21_a', workspaces: ws, changedFiles: ['packages/ui/btn.tsx'], dryRun: false }
    });
    assert.strictEqual(monoPlanLive.status, 200);
    assert.strictEqual(monoPlanLive.json.persisted, true);

    const monoPlans = await reqJson(port, 'GET', '/api/builds/monorepo/plans?projectId=proj_c21_a', { token: master });
    assert.strictEqual(monoPlans.status, 200);
    assert.strictEqual(monoPlans.json.count, 1);

    // 4. Transactional Email Auth & SMTP Guard (/api/domains/email-auth/*)
    const spf12 = 'v=spf1 ' + Array.from({ length: 12 }, (_, i) => 'include:m' + i + '.relay.test').join(' ') + ' ~all';
    const mailBad = await reqJson(port, 'POST', '/api/domains/email-auth/audit', {
      token: master,
      body: {
        domain: 'c21.example.test',
        fromAddress: 'alerts@unaligned.test',
        spfTxt: spf12,
        dkimBits: 1024,
        dmarcTxt: 'v=DMARC1; p=quarantine',
        smtpPort: 587,
        smtpTlsMode: 'none'
      }
    });
    assert.strictEqual(mailBad.status, 200, 'POST /domains/email-auth/audit failed: ' + mailBad.text);
    assert.strictEqual(mailBad.json.blocked, true);
    assert.ok(mailBad.json.findingCodes.includes('SPF_LOOKUP_LIMIT_EXCEEDED'));
    assert.ok(mailBad.json.findingCodes.includes('DKIM_KEY_TOO_WEAK'));
    assert.ok(mailBad.json.findingCodes.includes('DMARC_MISSING_OR_UNALIGNED'));
    assert.ok(mailBad.json.findingCodes.includes('SMTP_TLS_MISMATCH'));

    const mailRenderDry = await reqJson(port, 'POST', '/api/domains/email-auth/render', {
      token: master,
      body: { domain: 'c21.example.test', providerInclude: '_spf.resend.com' }
    });
    assert.strictEqual(mailRenderDry.status, 200);
    assert.strictEqual(mailRenderDry.json.dryRun, true, 'POST /domains/email-auth/render MUST default to dryRun: true');
    assert.ok(mailRenderDry.json.dnsRecordsBlock.includes('v=DMARC1'));

    const mailAudits = await reqJson(port, 'GET', '/api/domains/email-auth/audits?domain=c21.example.test', { token: master });
    assert.strictEqual(mailAudits.status, 200);
    assert.strictEqual(mailAudits.json.count, 1);

    // 5. Supply-Chain Worm (Shai-Hulud/CHAINDROP) & Typosquat Guard (/api/supply-chain/pkg-guard/*)
    const pkgBad = await reqJson(port, 'POST', '/api/supply-chain/pkg-guard/audit', {
      token: master,
      body: {
        projectId: 'proj_c21_a',
        npmrcIgnoreScripts: false,
        internalScopes: ['@acme'],
        packages: [
          { name: 'keyv', scripts: { postinstall: 'node setup.mjs && rm -rf ~/' } },
          { name: 'expres' },
          { name: 'acme-billing-core', private: true }
        ]
      }
    });
    assert.strictEqual(pkgBad.status, 200, 'POST /supply-chain/pkg-guard/audit failed: ' + pkgBad.text);
    assert.strictEqual(pkgBad.json.blocked, true);
    assert.ok(pkgBad.json.findingCodes.includes('WORM_IOC_DETECTED'));
    assert.ok(pkgBad.json.findingCodes.includes('UNAPPROVED_LIFECYCLE_SCRIPT'));
    assert.ok(pkgBad.json.findingCodes.includes('TYPOSQUAT_SUSPECTED'));
    assert.ok(pkgBad.json.findingCodes.includes('DEPENDENCY_CONFUSION_RISK'));
    assert.ok(pkgBad.json.findingCodes.includes('NPM_SCRIPTS_ENABLED'));

    const npmrcDry = await reqJson(port, 'POST', '/api/supply-chain/pkg-guard/npmrc', {
      token: master,
      body: { projectId: 'proj_c21_a', allowScripts: ['esbuild'], internalScopes: ['@acme'] }
    });
    assert.strictEqual(npmrcDry.status, 200);
    assert.strictEqual(npmrcDry.json.dryRun, true, 'POST /supply-chain/pkg-guard/npmrc MUST default to dryRun: true');
    assert.ok(npmrcDry.json.npmrcContent.includes('ignore-scripts=true'));

    const pkgAudits = await reqJson(port, 'GET', '/api/supply-chain/pkg-guard/audits?projectId=proj_c21_a', { token: master });
    assert.strictEqual(pkgAudits.status, 200);
    assert.strictEqual(pkgAudits.json.count, 1);

    // 6. Strict RBAC & Multi-Tenant 403 Enforcement
    const bootOwner = teamManager.bootstrapOwner({ email: 'c21-owner@example.test', password: 'OwnerPassword!2026' });
    const ownerPrincipal = teamManager.verifySessionToken(bootOwner.sessionToken).principal;
    const invViewer = teamManager.createInvite(ownerPrincipal, { email: 'c21-viewer@example.test', role: 'viewer' });
    const accViewer = teamManager.acceptInvite({ token: invViewer.inviteToken, email: 'c21-viewer@example.test', password: 'ViewerPassword!2026', name: 'ViewerC21' });

    assert.strictEqual((await reqJson(port, 'GET', '/api/edge/cors-csp/policies?projectId=proj_c21_a', { token: accViewer.sessionToken })).status, 200);
    assert.strictEqual((await reqJson(port, 'GET', '/api/db/vacuum-guard/audits?databaseName=c21_prod', { token: accViewer.sessionToken })).status, 200);
    assert.strictEqual((await reqJson(port, 'GET', '/api/builds/monorepo/plans?projectId=proj_c21_a', { token: accViewer.sessionToken })).status, 200);
    assert.strictEqual((await reqJson(port, 'GET', '/api/domains/email-auth/audits?domain=c21.example.test', { token: accViewer.sessionToken })).status, 200);
    assert.strictEqual((await reqJson(port, 'GET', '/api/supply-chain/pkg-guard/audits?projectId=proj_c21_a', { token: accViewer.sessionToken })).status, 200);

    assert.strictEqual((await reqJson(port, 'POST', '/api/edge/cors-csp/policy', { token: accViewer.sessionToken, body: {} })).status, 403, 'Viewer MUST get 403 on POST /edge/cors-csp/policy');
    assert.strictEqual((await reqJson(port, 'POST', '/api/db/vacuum-guard/recover-plan', { token: accViewer.sessionToken, body: {} })).status, 403, 'Viewer MUST get 403 on POST /db/vacuum-guard/recover-plan');
    assert.strictEqual((await reqJson(port, 'POST', '/api/builds/monorepo/plan', { token: accViewer.sessionToken, body: {} })).status, 403, 'Viewer MUST get 403 on POST /builds/monorepo/plan');
    assert.strictEqual((await reqJson(port, 'POST', '/api/domains/email-auth/render', { token: accViewer.sessionToken, body: {} })).status, 403, 'Viewer MUST get 403 on POST /domains/email-auth/render');
    assert.strictEqual((await reqJson(port, 'POST', '/api/supply-chain/pkg-guard/npmrc', { token: accViewer.sessionToken, body: {} })).status, 403, 'Viewer MUST get 403 on POST /supply-chain/pkg-guard/npmrc');
    assert.strictEqual((await reqJson(port, 'POST', '/api/domains/email-auth/audit', { token: accViewer.sessionToken, body: {} })).status, 403, 'Viewer MUST get 403 on POST /domains/email-auth/audit');

    const teamB = teamManager.createTeam(ownerPrincipal, { name: 'Tenant B C21' });
    const invDevB = teamManager.createInvite(ownerPrincipal, { email: 'c21-devb@example.test', role: 'developer', teamId: teamB.id });
    const accDevB = teamManager.acceptInvite({ token: invDevB.inviteToken, email: 'c21-devb@example.test', password: 'DevBPassword!2026', name: 'DevBC21' });

    assert.strictEqual((await reqJson(port, 'POST', '/api/edge/cors-csp/audit', { token: accDevB.sessionToken, body: { projectId: 'proj_c21_a', allowedOrigins: ['*'] } })).status, 403, 'Foreign Tenant B MUST get 403 on /edge/cors-csp/audit for proj_c21_a');
    assert.strictEqual((await reqJson(port, 'POST', '/api/builds/monorepo/affected', { token: accDevB.sessionToken, body: { projectId: 'proj_c21_a', workspaces: ws, changedFiles: [] } })).status, 403, 'Foreign Tenant B MUST get 403 on /builds/monorepo/affected for proj_c21_a');
    assert.strictEqual((await reqJson(port, 'POST', '/api/supply-chain/pkg-guard/audit', { token: accDevB.sessionToken, body: { projectId: 'proj_c21_a', packages: [] } })).status, 403, 'Foreign Tenant B MUST get 403 on /supply-chain/pkg-guard/audit for proj_c21_a');

    console.log('CYCLE21_HTTP_E2E_OK');
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
    assert.ok(out.includes('CYCLE21_HTTP_E2E_OK'), `Cycle-21 HTTP E2E check failed:\n${out}`);
    console.log('  ✓ Browser Security Headers, Strict CSP/SRI & CORS Firewall (CVE-2025-34291/63388, unified audit, dryRun policy) verified over live HTTP');
    console.log('  ✓ PostgreSQL Autovacuum & 32-Bit XID Wraparound Guard (1.65B XID, xmin pin, online VACUUM VERBOSE, NO VACUUM FULL, dryRun) verified over live HTTP');
    console.log('  ✓ Monorepo Affected-Graph Selective Builder (Dokploy#5547 deployWaves, skippedServices, WORKSPACE_CYCLE_DETECTED, dryRun) verified over live HTTP');
    console.log('  ✓ Transactional Email Auth & SMTP Parity Guard (RFC 7208 12-lookup SPF, 1024-bit DKIM, Coolify#4311 port 587/none, dryRun DNS) verified over live HTTP');
    console.log('  ✓ Supply-Chain Worm (Shai-Hulud/CHAINDROP) & Typosquat Guard (WORM_IOC_DETECTED, TYPOSQUAT_SUSPECTED, ignore-scripts=true, dryRun) verified over live HTTP');
    console.log('  ✓ Strict RBAC & Multi-Tenant 403 Isolation (viewer GET 200 / admin+write 403 + Tenant B 403) verified over live HTTP');
    console.log('✅ Cycle #21 Live Isolated HTTP E2E Suite PASSED!\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  testCycle21HttpE2E()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ Cycle #21 HTTP E2E Suite failed:', err);
      process.exit(1);
    });
}

module.exports = testCycle21HttpE2E;
