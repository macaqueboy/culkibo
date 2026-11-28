const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

async function testCycle22HttpE2E() {
  console.log('\n🚀 Testing Cycle #22 195-MCP & 89-Suites Milestone Live Isolated HTTP E2E (JWT/OIDC Firewall, Runtime Leak Guard, GraphQL Shield, ACME ARI/TLS Budget, Archive Zip-Slip)...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c22-http-'));
  const rootDir = path.resolve(__dirname, '..');
  const runnerPath = path.join(tmpDir, 'cycle22-http-runner.js');

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
      id: 'proj_c22_a',
      name: 'Cycle22 Milestone Stack',
      domains: ['c22.example.test']
    });

    const b64u = (obj) => Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
    const mkJwt = (h, p, sig) => [b64u(h), b64u(p), sig === undefined ? 'c2ln' : sig].join('.');
    const nowSec = 1764300000;

    // 1. JWT Algorithm-Confusion & OIDC Claim Firewall (/api/security/jwt-firewall/*)
    const rawBadJwt = mkJwt(
      { alg: 'HS256', jku: 'https://evil.example/jwks.json', kid: '../../etc/passwd' },
      { iss: 'https://idp.example', aud: 'culkibo', exp: nowSec + 300 },
      'c2lnbmF0dXJlLW5ldmVyLXN0b3JlZA'
    );
    const jwtBad = await reqJson(port, 'POST', '/api/security/jwt-firewall/inspect', {
      token: master,
      body: { token: rawBadJwt, expectedAlgorithms: ['RS256'], expectedIssuer: 'https://idp.example', expectedAudience: 'culkibo', nowSec }
    });
    assert.strictEqual(jwtBad.status, 200, 'POST /security/jwt-firewall/inspect failed: ' + jwtBad.text);
    assert.strictEqual(jwtBad.json.blocked, true);
    assert.ok(jwtBad.json.findingCodes.includes('JWT_ALG_CONFUSION_BLOCKED'));
    assert.ok(jwtBad.json.findingCodes.includes('JWT_JKU_SSRF_BLOCKED'));
    assert.ok(jwtBad.json.findingCodes.includes('JWT_KID_INJECTION'));
    assert.ok(!jwtBad.text.includes(rawBadJwt), 'Response MUST NEVER echo raw JWT string');

    const jwtCfgDry = await reqJson(port, 'POST', '/api/security/jwt-firewall/audit-config', {
      token: master,
      body: { pinnedAlgorithms: ['RS256', 'HS256'], allowAlgNone: true, allowJkuHeader: true }
    });
    assert.strictEqual(jwtCfgDry.status, 200);
    assert.strictEqual(jwtCfgDry.json.dryRun, true, 'POST /security/jwt-firewall/audit-config MUST default to dryRun: true');
    assert.ok(jwtCfgDry.json.findingCodes.includes('JWT_ALG_NONE_FORBIDDEN'));

    const jwtAudits = await reqJson(port, 'GET', '/api/security/jwt-firewall/audits', { token: master });
    assert.strictEqual(jwtAudits.status, 200);
    assert.strictEqual(jwtAudits.json.count, 1);
    const jwtDisk = fs.readFileSync(path.join(TMP_DIR, 'data', 'jwt-oidc-firewall.json'), 'utf8');
    assert.ok(!jwtDisk.includes(rawBadJwt), 'Raw JWT MUST NEVER be persisted to disk');

    // 2. Container Heap-Slope, FD-Leak & Event-Loop Lag Guard (/api/observability/leak-guard/*)
    const leakBad = await reqJson(port, 'POST', '/api/observability/leak-guard/analyze', {
      token: master,
      body: {
        projectId: 'proj_c22_a',
        containerLimitMb: 1024,
        heapSamplesMb: [200, 320, 440, 560, 680],
        openFds: 950,
        fdLimit: 1024,
        eventLoopLagP99Ms: 180
      }
    });
    assert.strictEqual(leakBad.status, 200, 'POST /observability/leak-guard/analyze failed: ' + leakBad.text);
    assert.strictEqual(leakBad.json.safe, false);
    assert.ok(leakBad.json.findingCodes.includes('HEAP_LEAK_SLOPE_HIGH'));
    assert.ok(leakBad.json.findingCodes.includes('FD_EXHAUSTION_EMFILE_RISK'));
    assert.ok(leakBad.json.findingCodes.includes('EVENT_LOOP_LAG_CRITICAL'));
    assert.strictEqual(leakBad.json.recommendedMaxOldSpaceMb, 798);
    assert.ok(leakBad.json.hoursToOom > 0);

    const drainDry = await reqJson(port, 'POST', '/api/observability/leak-guard/drain-plan', {
      token: master,
      body: { projectId: 'proj_c22_a', containerLimitMb: 1024, heapSamplesMb: [200, 320, 440, 560, 680] }
    });
    assert.strictEqual(drainDry.status, 200);
    assert.strictEqual(drainDry.json.dryRun, true, 'POST /observability/leak-guard/drain-plan MUST default to dryRun: true');
    assert.strictEqual(drainDry.json.heapSnapshotSignal, 'SIGUSR2');

    const leakHist = await reqJson(port, 'GET', '/api/observability/leak-guard/history?projectId=proj_c22_a', { token: master });
    assert.strictEqual(leakHist.status, 200);
    assert.strictEqual(leakHist.json.count, 1);

    // 3. GraphQL Depth, Fragment-Spread Alias & Introspection Shield (/api/edge/graphql-shield/*)
    const gqlBad = await reqJson(port, 'POST', '/api/edge/graphql-shield/inspect', {
      token: master,
      body: {
        projectId: 'proj_c22_a',
        env: 'production',
        maxAliases: 15,
        maxFragmentExpansions: 8,
        query: 'query Q { __schema { types { name } } ...F1 ...F1 ...F1 ...F1 } fragment F1 on Query { ...F2 ...F2 ...F2 ...F2 } fragment F2 on Query { a1:u a2:u a3:u }'
      }
    });
    assert.strictEqual(gqlBad.status, 200, 'POST /edge/graphql-shield/inspect failed: ' + gqlBad.text);
    assert.strictEqual(gqlBad.json.blocked, true);
    assert.ok(gqlBad.json.findingCodes.includes('GRAPHQL_ALIAS_AMPLIFICATION'));
    assert.ok(gqlBad.json.findingCodes.includes('GRAPHQL_FRAGMENT_FANOUT_DOS'));
    assert.ok(gqlBad.json.findingCodes.includes('GRAPHQL_INTROSPECTION_BLOCKED'));

    const gqlPolDry = await reqJson(port, 'POST', '/api/edge/graphql-shield/policy', {
      token: master,
      body: { projectId: 'proj_c22_a', maxDepth: 6, maxAliases: 12 }
    });
    assert.strictEqual(gqlPolDry.status, 200);
    assert.strictEqual(gqlPolDry.json.dryRun, true, 'POST /edge/graphql-shield/policy MUST default to dryRun: true');

    const gqlPolSave = await reqJson(port, 'POST', '/api/edge/graphql-shield/policy', {
      token: master,
      body: { projectId: 'proj_c22_a', maxDepth: 6, maxAliases: 12, dryRun: false }
    });
    assert.strictEqual(gqlPolSave.status, 200);
    assert.strictEqual(gqlPolSave.json.dryRun, false);

    const gqlPolList = await reqJson(port, 'GET', '/api/edge/graphql-shield/policies?projectId=proj_c22_a', { token: master });
    assert.strictEqual(gqlPolList.status, 200);
    assert.strictEqual(gqlPolList.json.count, 1);

    // 4. ACME Rate-Limit Budget, RFC 9773 ARI & TLS Cipher Guard (/api/domains/acme-budget/*)
    const acmeBad = await reqJson(port, 'POST', '/api/domains/acme-budget/audit', {
      token: master,
      body: {
        domain: 'c22.example.test',
        failedAuthz1h: 5,
        staleDomainsInStore: ['stale.c22.test'],
        hasPersistentCertVolume: false,
        minTlsVersion: '1.1',
        ciphers: ['TLS_RSA_WITH_RC4_128_SHA']
      }
    });
    assert.strictEqual(acmeBad.status, 200, 'POST /domains/acme-budget/audit failed: ' + acmeBad.text);
    assert.strictEqual(acmeBad.json.blocked, true);
    assert.ok(acmeBad.json.budget && acmeBad.json.tls);
    assert.ok(acmeBad.json.findingCodes.includes('ACME_AUTHZ_LOCKOUT_RISK'));
    assert.ok(acmeBad.json.findingCodes.includes('STALE_ACME_DOMAINS_DETECTED'));
    assert.ok(acmeBad.json.findingCodes.includes('EPHEMERAL_CERT_STORAGE'));
    assert.ok(acmeBad.json.findingCodes.includes('WEAK_TLS_VERSION'));
    assert.ok(acmeBad.json.findingCodes.includes('WEAK_CIPHER_SUITE'));
    assert.strictEqual(typeof acmeBad.json.caddyTlsBlock, 'string');

    const ariRes = await reqJson(port, 'POST', '/api/domains/acme-budget/ari-window', {
      token: master,
      body: { certId: 'cert_c22', replacesCertId: 'cert_prev_c22', suggestedStartIso: '2026-12-01T00:00:00Z', suggestedEndIso: '2026-12-03T00:00:00Z' }
    });
    assert.strictEqual(ariRes.status, 200);
    assert.strictEqual(ariRes.json.rateLimitWaiverEligible, true);

    const acmeAudits = await reqJson(port, 'GET', '/api/domains/acme-budget/audits', { token: master });
    assert.strictEqual(acmeAudits.status, 200);
    assert.strictEqual(acmeAudits.json.count, 1);

    // 5. Archive Zip-Slip / Symlink Traversal & Zip-Bomb Firewall (/api/security/archive-guard/*)
    const archBad = await reqJson(port, 'POST', '/api/security/archive-guard/inspect', {
      token: master,
      body: {
        projectId: 'proj_c22_a',
        targetRoot: '/srv/deploy',
        entries: [
          { path: '../../etc/cron.d/pwn', type: 'file', compressedBytes: 100, uncompressedBytes: 100 },
          { path: 'link-etc', type: 'symlink', linkname: '/etc/passwd' },
          { path: 'App/main.js', type: 'file', compressedBytes: 100, uncompressedBytes: 100 },
          { path: 'app/main.js', type: 'file', compressedBytes: 100, uncompressedBytes: 100 },
          { path: 'bomb.bin', type: 'file', compressedBytes: 1000, uncompressedBytes: 500000 }
        ]
      }
    });
    assert.strictEqual(archBad.status, 200, 'POST /security/archive-guard/inspect failed: ' + archBad.text);
    assert.strictEqual(archBad.json.blocked, true);
    assert.ok(archBad.json.findingCodes.includes('ZIP_SLIP_PATH_TRAVERSAL'));
    assert.ok(archBad.json.findingCodes.includes('SYMLINK_ESCAPE_BLOCKED'));
    assert.ok(archBad.json.findingCodes.includes('UNICODE_PATH_COLLISION'));
    assert.ok(archBad.json.findingCodes.includes('ZIP_BOMB_DETECTED'));

    const archAudits = await reqJson(port, 'GET', '/api/security/archive-guard/audits', { token: master });
    assert.strictEqual(archAudits.status, 200);
    assert.strictEqual(archAudits.json.count, 1);

    // 6. Strict RBAC & Multi-Tenant 403 Enforcement
    const bootOwner = teamManager.bootstrapOwner({ email: 'c22-owner@example.test', password: 'OwnerPassword!2026' });
    const ownerPrincipal = teamManager.verifySessionToken(bootOwner.sessionToken).principal;
    const invViewer = teamManager.createInvite(ownerPrincipal, { email: 'c22-viewer@example.test', role: 'viewer' });
    const accViewer = teamManager.acceptInvite({ token: invViewer.inviteToken, email: 'c22-viewer@example.test', password: 'ViewerPassword!2026', name: 'ViewerC22' });

    assert.strictEqual((await reqJson(port, 'GET', '/api/security/jwt-firewall/audits', { token: accViewer.sessionToken })).status, 200);
    assert.strictEqual((await reqJson(port, 'GET', '/api/observability/leak-guard/history?projectId=proj_c22_a', { token: accViewer.sessionToken })).status, 200);
    assert.strictEqual((await reqJson(port, 'GET', '/api/edge/graphql-shield/policies?projectId=proj_c22_a', { token: accViewer.sessionToken })).status, 200);
    assert.strictEqual((await reqJson(port, 'GET', '/api/domains/acme-budget/audits', { token: accViewer.sessionToken })).status, 200);
    assert.strictEqual((await reqJson(port, 'GET', '/api/security/archive-guard/audits', { token: accViewer.sessionToken })).status, 200);

    assert.strictEqual((await reqJson(port, 'POST', '/api/security/jwt-firewall/audit-config', { token: accViewer.sessionToken, body: {} })).status, 403, 'Viewer MUST get 403 on POST /security/jwt-firewall/audit-config');
    assert.strictEqual((await reqJson(port, 'POST', '/api/observability/leak-guard/drain-plan', { token: accViewer.sessionToken, body: {} })).status, 403, 'Viewer MUST get 403 on POST /observability/leak-guard/drain-plan');
    assert.strictEqual((await reqJson(port, 'POST', '/api/edge/graphql-shield/policy', { token: accViewer.sessionToken, body: {} })).status, 403, 'Viewer MUST get 403 on POST /edge/graphql-shield/policy');
    assert.strictEqual((await reqJson(port, 'POST', '/api/domains/acme-budget/audit', { token: accViewer.sessionToken, body: {} })).status, 403, 'Viewer MUST get 403 on POST /domains/acme-budget/audit');
    assert.strictEqual((await reqJson(port, 'POST', '/api/security/archive-guard/inspect', { token: accViewer.sessionToken, body: {} })).status, 403, 'Viewer MUST get 403 on POST /security/archive-guard/inspect');

    const teamB = teamManager.createTeam(ownerPrincipal, { name: 'Tenant B C22' });
    const invDevB = teamManager.createInvite(ownerPrincipal, { email: 'c22-devb@example.test', role: 'developer', teamId: teamB.id });
    const accDevB = teamManager.acceptInvite({ token: invDevB.inviteToken, email: 'c22-devb@example.test', password: 'DevBPassword!2026', name: 'DevBC22' });

    assert.strictEqual((await reqJson(port, 'POST', '/api/observability/leak-guard/analyze', { token: accDevB.sessionToken, body: { projectId: 'proj_c22_a', containerLimitMb: 1024 } })).status, 403, 'Foreign Tenant B MUST get 403 on /observability/leak-guard/analyze for proj_c22_a');
    assert.strictEqual((await reqJson(port, 'POST', '/api/edge/graphql-shield/inspect', { token: accDevB.sessionToken, body: { projectId: 'proj_c22_a', query: '{ ok }' } })).status, 403, 'Foreign Tenant B MUST get 403 on /edge/graphql-shield/inspect for proj_c22_a');
    assert.strictEqual((await reqJson(port, 'POST', '/api/security/archive-guard/inspect', { token: accDevB.sessionToken, body: { projectId: 'proj_c22_a', entries: [] } })).status, 403, 'Foreign Tenant B MUST get 403 on /security/archive-guard/inspect for proj_c22_a');

    console.log('CYCLE22_HTTP_E2E_OK');
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
    assert.ok(out.includes('CYCLE22_HTTP_E2E_OK'), `Cycle-22 HTTP E2E check failed:\n${out}`);
    console.log('  ✓ JWT Algorithm-Confusion & OIDC Firewall (CVE-2026-29000/33322, 0 raw tokens stored/echoed, dryRun audit-config) verified over live HTTP');
    console.log('  ✓ Container Heap-Slope, FD-Leak & Event-Loop Lag Guard (OLS slope, hoursToOom, --max-old-space-size=798, SIGUSR2 drain dryRun) verified over live HTTP');
    console.log('  ✓ GraphQL Depth, Fragment-Spread Alias & Introspection Shield (CVE-2026-47707/35441, policy dryRun) verified over live HTTP');
    console.log('  ✓ ACME Rate-Limit Budget, RFC 9773 ARI & TLS Cipher Guard (Coolify#6800, Dokploy#2238, unified budget+TLS + caddyTlsBlock) verified over live HTTP');
    console.log('  ✓ Archive Zip-Slip / Symlink Traversal & Zip-Bomb Firewall (CVE-2026-23745/23950, 500:1 bomb) verified over live HTTP');
    console.log('  ✓ Strict RBAC & Multi-Tenant 403 Isolation (viewer GET 200 / admin+write 403 + Tenant B 403) verified over live HTTP');
    console.log('✅ Cycle #22 Live Isolated HTTP E2E Suite PASSED!\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  testCycle22HttpE2E()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ Cycle #22 HTTP E2E Suite failed:', err);
      process.exit(1);
    });
}

module.exports = testCycle22HttpE2E;
