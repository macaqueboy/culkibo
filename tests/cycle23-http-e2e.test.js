const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

async function testCycle23HttpE2E() {
  console.log('\n🚀 Testing Historic Cycle #23 200-MCP & 92-Suites Milestone Live Isolated HTTP E2E (React2Shell/SSR Edge, Registry Mirror, Go 1.25 CSRF/PKCE, SQLite WAL/NFS, Build-ARG /run/secrets/)...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c23-http-'));
  const rootDir = path.resolve(__dirname, '..');
  const runnerPath = path.join(tmpDir, 'cycle23-http-runner.js');

  fs.writeFileSync(runnerPath, `
const assert = require('assert');
const crypto = require('crypto');
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
      id: 'proj_c23_a',
      name: 'Cycle23 Historic 200-MCP Stack',
      domains: ['c23.example.test']
    });

    // 1. Next.js / React2Shell SSR Edge Guard (/api/edge/ssr-guard/*)
    const ssrBad = await reqJson(port, 'POST', '/api/edge/ssr-guard/evaluate', {
      token: master,
      body: {
        projectId: 'proj_c23_a',
        framework: 'nextjs',
        nextVersion: '15.2.1',
        reactVersion: '19.1.0',
        requestHeaders: { 'x-middleware-subrequest': 'middleware' },
        responseHeaders: { Vary: 'Accept-Encoding' }
      }
    });
    assert.strictEqual(ssrBad.status, 200, 'POST /edge/ssr-guard/evaluate failed: ' + ssrBad.text);
    assert.strictEqual(ssrBad.json.blocked, true);
    assert.ok(ssrBad.json.findingCodes.includes('SSR_INTERNAL_HEADER_SPOOF'));
    assert.ok(ssrBad.json.findingCodes.includes('REACT2SHELL_VULNERABLE_VERSION'));
    assert.ok(ssrBad.json.findingCodes.includes('NEXTJS_MIDDLEWARE_CVE_VERSION'));
    assert.ok(ssrBad.json.findingCodes.includes('RSC_VARY_HEADER_MISSING'));
    assert.strictEqual(typeof ssrBad.json.caddyBlock, 'string');

    const ssrRenderDry = await reqJson(port, 'POST', '/api/edge/ssr-guard/render', {
      token: master,
      body: { projectId: 'proj_c23_a', upstream: '127.0.0.1:3000' }
    });
    assert.strictEqual(ssrRenderDry.status, 200);
    assert.strictEqual(ssrRenderDry.json.dryRun, true, 'POST /edge/ssr-guard/render MUST default to dryRun: true');
    assert.ok(ssrRenderDry.json.caddyBlock.includes('header_up -x-middleware-subrequest'));

    const ssrAudits = await reqJson(port, 'GET', '/api/edge/ssr-guard/audits', { token: master });
    assert.strictEqual(ssrAudits.status, 200);
    assert.strictEqual(ssrAudits.json.count, 1);

    // 2. Container Registry Pull-Limit & Pull-Through Mirror Guard (/api/builds/registry-mirror/*)
    const regBad = await reqJson(port, 'POST', '/api/builds/registry-mirror/audit', {
      token: master,
      body: {
        nodeId: 'vps_c23_1',
        registry: 'docker.io',
        authenticated: false,
        pullsPerHour: 12,
        archCount: 2,
        sharedNatIp: true,
        mirrors: [],
        plaintextConfigAuth: true
      }
    });
    assert.strictEqual(regBad.status, 200, 'POST /builds/registry-mirror/audit failed: ' + regBad.text);
    assert.strictEqual(regBad.json.blocked, true);
    assert.ok(regBad.json.findingCodes.includes('ANONYMOUS_HUB_RATE_LIMIT_RISK'));
    assert.ok(regBad.json.findingCodes.includes('SHARED_NAT_QUOTA_EXHAUSTION'));
    assert.ok(regBad.json.findingCodes.includes('MISSING_REGISTRY_MIRROR'));
    assert.ok(regBad.json.findingCodes.includes('PLAINTEXT_DOCKER_CONFIG_AUTH'));

    const regCfgDry = await reqJson(port, 'POST', '/api/builds/registry-mirror/config', {
      token: master,
      body: { mirrorUrls: ['http://127.0.0.1:5000'], maxConcurrentDownloads: 3 }
    });
    assert.strictEqual(regCfgDry.status, 200);
    assert.strictEqual(regCfgDry.json.dryRun, true, 'POST /builds/registry-mirror/config MUST default to dryRun: true');
    assert.ok(regCfgDry.json.daemonJsonText.includes('registry-mirrors'));

    const regAudits = await reqJson(port, 'GET', '/api/builds/registry-mirror/audits?nodeId=vps_c23_1', { token: master });
    assert.strictEqual(regAudits.status, 200);
    assert.strictEqual(regAudits.json.count, 1);

    // 3. Session Cookie, Go 1.25 Fetch-Metadata CSRF & OAuth 2.1 PKCE Guard (/api/security/session-csrf/*)
    const rawCookieSecret = ['ephem', 'cookie', 'val', 'never', 'stored', 'c23'].join('_');
    const csrfEval = await reqJson(port, 'POST', '/api/security/session-csrf/evaluate', {
      token: master,
      body: {
        projectId: 'proj_c23_a',
        method: 'POST',
        secFetchSite: 'cross-site',
        setCookieHeader: '__Host-sid=' + rawCookieSecret + '; Path=/app'
      }
    });
    assert.strictEqual(csrfEval.status, 200, 'POST /security/session-csrf/evaluate failed: ' + csrfEval.text);
    assert.strictEqual(csrfEval.json.blocked, true);
    assert.ok(csrfEval.json.csrf && csrfEval.json.cookie);
    assert.ok(csrfEval.json.findingCodes.includes('CSRF_CROSS_ORIGIN_BLOCKED'));
    assert.ok(csrfEval.json.findingCodes.includes('COOKIE_HOST_PREFIX_INVALID'));
    assert.ok(!csrfEval.text.includes(rawCookieSecret), 'Response MUST NEVER echo raw cookie value');

    const verifier = crypto.randomBytes(36).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier, 'utf8').digest('base64url');
    const pkceBad = await reqJson(port, 'POST', '/api/security/session-csrf/pkce', {
      token: master,
      body: { method: 'plain', codeChallenge: challenge, codeVerifier: verifier, state: '1234' }
    });
    assert.strictEqual(pkceBad.status, 200);
    assert.strictEqual(pkceBad.json.blocked, true);
    assert.ok(pkceBad.json.findingCodes.includes('PKCE_PLAIN_FORBIDDEN'));
    assert.ok(pkceBad.json.findingCodes.includes('OAUTH_STATE_WEAK'));
    assert.ok(!pkceBad.text.includes(verifier), 'Response MUST NEVER echo raw PKCE verifier');

    const pkceGood = await reqJson(port, 'POST', '/api/security/session-csrf/pkce', {
      token: master,
      body: { method: 'S256', persistedMethod: 'S256', codeChallenge: challenge, codeVerifier: verifier, state: crypto.randomBytes(16).toString('hex') }
    });
    assert.strictEqual(pkceGood.status, 200);
    assert.strictEqual(pkceGood.json.verified, true);

    const csrfAudits = await reqJson(port, 'GET', '/api/security/session-csrf/audits', { token: master });
    assert.strictEqual(csrfAudits.status, 200);
    assert.ok(csrfAudits.json.count >= 3);
    const csrfDisk = fs.readFileSync(path.join(TMP_DIR, 'data', 'session-csrf-guard.json'), 'utf8');
    assert.ok(!csrfDisk.includes(rawCookieSecret) && !csrfDisk.includes(verifier), 'Raw cookie/PKCE verifier MUST NEVER be persisted on disk');

    // 4. SQLite WAL Checkpoint Starvation & Network-FS Corruption Guard (/api/db/sqlite-wal/*)
    const walBad = await reqJson(port, 'POST', '/api/db/sqlite-wal/audit', {
      token: master,
      body: {
        projectId: 'proj_c23_a',
        databaseName: 'pocketbase.db',
        filesystemType: 'nfs',
        journalMode: 'delete',
        synchronous: 'off',
        busyTimeoutMs: 0,
        journalSizeLimitMb: 0,
        dbSizeMb: 80,
        walSizeMb: 512,
        blockedReaders: 2
      }
    });
    assert.strictEqual(walBad.status, 200, 'POST /db/sqlite-wal/audit failed: ' + walBad.text);
    assert.strictEqual(walBad.json.blocked, true);
    assert.ok(walBad.json.findingCodes.includes('SQLITE_NETWORK_FS_CORRUPTION'));
    assert.ok(walBad.json.findingCodes.includes('SQLITE_NON_WAL_LOCK_RISK'));
    assert.ok(walBad.json.findingCodes.includes('SQLITE_BUSY_TIMEOUT_LOW'));
    assert.ok(walBad.json.findingCodes.includes('SQLITE_SYNC_OFF_CORRUPTION'));
    assert.ok(walBad.json.findingCodes.includes('WAL_CHECKPOINT_STARVATION'));

    const pragmasDry = await reqJson(port, 'POST', '/api/db/sqlite-wal/pragmas', {
      token: master,
      body: { projectId: 'proj_c23_a', databaseName: 'pocketbase.db', busyTimeoutMs: 5000 }
    });
    assert.strictEqual(pragmasDry.status, 200);
    assert.strictEqual(pragmasDry.json.dryRun, true, 'POST /db/sqlite-wal/pragmas MUST default to dryRun: true');
    assert.ok(pragmasDry.json.pragmaSql.includes('PRAGMA journal_mode = WAL;'));

    const walAudits = await reqJson(port, 'GET', '/api/db/sqlite-wal/audits?databaseName=pocketbase.db', { token: master });
    assert.strictEqual(walAudits.status, 200);
    assert.strictEqual(walAudits.json.count, 1);

    // 5. Build-ARG / ENV Secret Surface & /run/secrets/ Migrator (/api/security/env-surface/*)
    const rawBuildSecretVal = ['never', 'echoed', 'raw', 'secret', 'c23'].join('_');
    const envBad = await reqJson(port, 'POST', '/api/security/env-surface/audit', {
      token: master,
      body: {
        projectId: 'proj_c23_a',
        dockerfile: 'FROM node:22-alpine\\nARG JWT_SECRET=' + rawBuildSecretVal + '\\nENV DATABASE_URL=' + rawBuildSecretVal + '\\nRUN npm run build',
        composeEnvKeys: ['JWT_SECRET', 'STRIPE_SECRET'],
        buildTimeEnvKeys: ['JWT_SECRET']
      }
    });
    assert.strictEqual(envBad.status, 200, 'POST /security/env-surface/audit failed: ' + envBad.text);
    assert.strictEqual(envBad.json.blocked, true);
    assert.strictEqual(envBad.json.zeroRawSecretsStored, true);
    assert.ok(envBad.json.findingCodes.includes('BUILDKIT_SECRET_IN_ARG_OR_ENV'));
    assert.ok(envBad.json.findingCodes.includes('COMPOSE_SECRET_IN_PLAIN_ENV'));
    assert.ok(envBad.json.findingCodes.includes('BUILD_RUNTIME_SECRET_OVERLAP'));
    assert.ok(!envBad.text.includes(rawBuildSecretVal), 'Response MUST NEVER echo raw build secret values');

    const migDry = await reqJson(port, 'POST', '/api/security/env-surface/migrate', {
      token: master,
      body: { projectId: 'proj_c23_a', secretNames: ['JWT_SECRET', 'DATABASE_URL'] }
    });
    assert.strictEqual(migDry.status, 200);
    assert.strictEqual(migDry.json.dryRun, true, 'POST /security/env-surface/migrate MUST default to dryRun: true');
    assert.ok(migDry.json.dockerfileSnippet.includes('RUN --mount=type=secret,id=jwt_secret'));
    assert.ok(migDry.json.composeSnippet.includes('mode: 0400'));

    const envAudits = await reqJson(port, 'GET', '/api/security/env-surface/audits?projectId=proj_c23_a', { token: master });
    assert.strictEqual(envAudits.status, 200);
    assert.strictEqual(envAudits.json.count, 1);
    const envDisk = fs.readFileSync(path.join(TMP_DIR, 'data', 'env-secret-surface.json'), 'utf8');
    assert.ok(!envDisk.includes(rawBuildSecretVal), 'Raw secret values MUST NEVER be persisted to disk');

    // 6. Strict RBAC & Multi-Tenant 403 Enforcement
    const bootOwner = teamManager.bootstrapOwner({ email: 'c23-owner@example.test', password: 'OwnerPassword!2026' });
    const ownerPrincipal = teamManager.verifySessionToken(bootOwner.sessionToken).principal;
    const invViewer = teamManager.createInvite(ownerPrincipal, { email: 'c23-viewer@example.test', role: 'viewer' });
    const accViewer = teamManager.acceptInvite({ token: invViewer.inviteToken, email: 'c23-viewer@example.test', password: 'ViewerPassword!2026', name: 'ViewerC23' });

    assert.strictEqual((await reqJson(port, 'GET', '/api/edge/ssr-guard/audits', { token: accViewer.sessionToken })).status, 200);
    assert.strictEqual((await reqJson(port, 'GET', '/api/builds/registry-mirror/audits', { token: accViewer.sessionToken })).status, 200);
    assert.strictEqual((await reqJson(port, 'GET', '/api/security/session-csrf/audits', { token: accViewer.sessionToken })).status, 200);
    assert.strictEqual((await reqJson(port, 'GET', '/api/db/sqlite-wal/audits', { token: accViewer.sessionToken })).status, 200);
    assert.strictEqual((await reqJson(port, 'GET', '/api/security/env-surface/audits?projectId=proj_c23_a', { token: accViewer.sessionToken })).status, 200);

    assert.strictEqual((await reqJson(port, 'POST', '/api/edge/ssr-guard/render', { token: accViewer.sessionToken, body: {} })).status, 403, 'Viewer MUST get 403 on POST /edge/ssr-guard/render');
    assert.strictEqual((await reqJson(port, 'POST', '/api/builds/registry-mirror/config', { token: accViewer.sessionToken, body: {} })).status, 403, 'Viewer MUST get 403 on POST /builds/registry-mirror/config');
    assert.strictEqual((await reqJson(port, 'POST', '/api/db/sqlite-wal/pragmas', { token: accViewer.sessionToken, body: {} })).status, 403, 'Viewer MUST get 403 on POST /db/sqlite-wal/pragmas');
    assert.strictEqual((await reqJson(port, 'POST', '/api/security/env-surface/migrate', { token: accViewer.sessionToken, body: {} })).status, 403, 'Viewer MUST get 403 on POST /security/env-surface/migrate');
    assert.strictEqual((await reqJson(port, 'POST', '/api/security/session-csrf/evaluate', { token: accViewer.sessionToken, body: {} })).status, 403, 'Viewer MUST get 403 on POST /security/session-csrf/evaluate');

    const teamB = teamManager.createTeam(ownerPrincipal, { name: 'Tenant B C23' });
    const invDevB = teamManager.createInvite(ownerPrincipal, { email: 'c23-devb@example.test', role: 'developer', teamId: teamB.id });
    const accDevB = teamManager.acceptInvite({ token: invDevB.inviteToken, email: 'c23-devb@example.test', password: 'DevBPassword!2026', name: 'DevBC23' });

    assert.strictEqual((await reqJson(port, 'POST', '/api/edge/ssr-guard/evaluate', { token: accDevB.sessionToken, body: { projectId: 'proj_c23_a' } })).status, 403, 'Foreign Tenant B MUST get 403 on /edge/ssr-guard/evaluate for proj_c23_a');
    assert.strictEqual((await reqJson(port, 'POST', '/api/db/sqlite-wal/audit', { token: accDevB.sessionToken, body: { projectId: 'proj_c23_a' } })).status, 403, 'Foreign Tenant B MUST get 403 on /db/sqlite-wal/audit for proj_c23_a');
    assert.strictEqual((await reqJson(port, 'POST', '/api/security/env-surface/audit', { token: accDevB.sessionToken, body: { projectId: 'proj_c23_a' } })).status, 403, 'Foreign Tenant B MUST get 403 on /security/env-surface/audit for proj_c23_a');

    console.log('CYCLE23_HTTP_E2E_OK');
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
    assert.ok(out.includes('CYCLE23_HTTP_E2E_OK'), `Cycle-23 HTTP E2E check failed:\n${out}`);
    console.log('  ✓ Next.js / React2Shell SSR Edge Guard (CVE-2025-29927/55182/49005, dryRun caddyBlock) verified over live HTTP');
    console.log('  ✓ Container Registry Pull-Limit & Mirror Guard (Docker Hub 429, registry:3 daemon.json dryRun) verified over live HTTP');
    console.log('  ✓ Session Cookie, Go 1.25 Fetch-Metadata CSRF & OAuth 2.1 PKCE Guard (CVE-2026-26247, 0 raw secrets stored/echoed) verified over live HTTP');
    console.log('  ✓ SQLite WAL Checkpoint Starvation & Network-FS Corruption Guard (NFS/WAL/busy_timeout, dryRun PRAGMAs) verified over live HTTP');
    console.log('  ✓ Build-ARG / ENV Secret Surface & /run/secrets/ Migrator (Dokploy#3347/Coolify#10822, 0 raw secrets stored/echoed, dryRun) verified over live HTTP');
    console.log('  ✓ Strict RBAC & Multi-Tenant 403 Isolation (viewer GET 200 / admin+write 403 + Tenant B 403) verified over live HTTP');
    console.log('✅ Historic Cycle #23 Live Isolated HTTP E2E Suite PASSED!\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  testCycle23HttpE2E()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ Cycle #23 HTTP E2E Suite failed:', err);
      process.exit(1);
    });
}

module.exports = testCycle23HttpE2E;
