const assert = require('assert');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { performance } = require('perf_hooks');
const { execFileSync } = require('child_process');

const { parseCron, nextCronRun } = require('../server/services/cronParser');
const Project = require('../server/models/Project');
const {
  EditionService,
  CORE_OSS_FEATURES,
  COMMERCIAL_FEATURE_CATALOG,
  generateLicenseKeyPair,
  mintLicense,
  verifyLicenseKey
} = require('../server/services/editionService');

/**
 * Isolated HTTP runner executed in a clean Node subprocess with `CULKIBO_DATA_DIR`
 * pointing to `os.tmpdir()` and `projectManager.dataPath` redirected before any write,
 * guaranteeing ZERO mutations to live `data/*.json`.
 */
function runIsolatedHttpBolaAndWave2Suite() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-edition-bola-http-'));
  const scriptPath = path.join(tmpDir, 'http-bola-runner.js');
  const rootDir = path.resolve(__dirname, '..');

  const runnerSource = `
const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');

const TMP_DIR = ${JSON.stringify(tmpDir)};
const ROOT_DIR = ${JSON.stringify(rootDir)};
const express = require(path.join(ROOT_DIR, 'node_modules', 'express'));

process.env.NODE_ENV = 'test';
process.env.CULKIBO_DATA_DIR = TMP_DIR;
process.env.CULKIBO_DISABLE_AUDIT_DISK = '1';

const auth = require(path.join(ROOT_DIR, 'server/middleware/auth'));
const { TeamManager, DEFAULT_TEAM_ID } = require(path.join(ROOT_DIR, 'server/services/teamManager'));
const projectManager = require(path.join(ROOT_DIR, 'server/services/projectManager'));
const domainManager = require(path.join(ROOT_DIR, 'server/services/domainManager'));
const databaseManager = require(path.join(ROOT_DIR, 'server/services/databaseManager'));
const deployManager = require(path.join(ROOT_DIR, 'server/services/deployManager'));
const ingressManager = require(path.join(ROOT_DIR, 'server/services/ingressManager'));
const auditLogger = require(path.join(ROOT_DIR, 'server/services/auditLogger'));
const containerOrchestrator = require(path.join(ROOT_DIR, 'server/services/containerOrchestrator'));
const editionService = require(path.join(ROOT_DIR, 'server/services/editionService'));
const { generateLicenseKeyPair, mintLicense } = editionService;

// Isolate every singleton store to TMP_DIR so live data/*.json is NEVER touched
projectManager.dataPath = path.join(TMP_DIR, 'projects.json');
projectManager.projects.clear();
projectManager.invalidateCache();
domainManager.domainsFile = path.join(TMP_DIR, 'domains.json');
domainManager.domains = [];
domainManager.invalidateCache && domainManager.invalidateCache();
databaseManager.dataFile = path.join(TMP_DIR, 'databases.json');
databaseManager.state = { databases: [], s3: null };
ingressManager.configFile = path.join(TMP_DIR, 'ingress.json');
ingressManager.wildcardPolicies = [];
auditLogger._explicitDataDir = TMP_DIR;
auditLogger.ring = [];

const keypair = generateLicenseKeyPair();
editionService._explicitDataDir = TMP_DIR;
editionService._trustedPublicKeys = [keypair.publicKeyPem];
editionService._stored = null;
editionService._loadedPath = null;

// Setup isolated multi-tenant TeamManager
const tm = new TeamManager({ dataDir: TMP_DIR, bcryptCost: 4 });
auth._setTeamManagerForTest(tm);

// Also inject same TeamManager instance into api.js lazy cache via require.cache
const tmModulePath = require.resolve(path.join(ROOT_DIR, 'server/services/teamManager'));
const origTmExports = require.cache[tmModulePath].exports;
require.cache[tmModulePath].exports = Object.assign(tm, {
  TeamManager: origTmExports.TeamManager,
  DEFAULT_TEAM_ID: origTmExports.DEFAULT_TEAM_ID
});

const apiRouter = require(path.join(ROOT_DIR, 'server/routes/api'));

function httpJson(port, method, reqPath, { token, cookie, body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body !== undefined ? JSON.stringify(body) : null;
    const reqHeaders = {
      host: 'panel.example.test',
      ...headers
    };
    if (token) reqHeaders.authorization = 'Bearer ' + token;
    if (cookie) reqHeaders.cookie = cookie;
    if (payload !== null) {
      reqHeaders['content-type'] = 'application/json';
      reqHeaders['content-length'] = Buffer.byteLength(payload);
    }
    const req = http.request({ hostname: '127.0.0.1', port, method, path: reqPath, headers: reqHeaders }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch (e) {}
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.on('error', reject);
    if (payload !== null) req.write(payload);
    req.end();
  });
}

(async () => {
  const app = express();
  app.use(express.json());
  app.use('/api', auth.authMiddleware, apiRouter);

  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const port = server.address().port;

  try {
    // 1. Bootstrap owner + create Team Alpha users (dev, viewer) & Team Bravo admin
    const ownerBoot = tm.bootstrapOwner({
      email: 'owner@alpha.test',
      name: 'Alpha Owner',
      password: 'AlphaOwnerPassword!2026',
      teamName: 'Team Alpha'
    });
    const ownerPrincipal = tm.verifySessionToken(ownerBoot.sessionToken).principal;
    const devInv = tm.createInvite(ownerPrincipal, { email: 'dev@alpha.test', role: 'developer' });
    const devAcc = tm.acceptInvite({ token: devInv.inviteToken, email: 'dev@alpha.test', password: 'AlphaDevPassword!2026' });
    const viewerInv = tm.createInvite(ownerPrincipal, { email: 'viewer@alpha.test', role: 'viewer' });
    const viewerAcc = tm.acceptInvite({ token: viewerInv.inviteToken, email: 'viewer@alpha.test', password: 'AlphaViewerPassword!2026' });

    const teamB = tm.createTeam(ownerPrincipal, { name: 'Team Bravo', slug: 'bravo' });
    const bravoInv = tm.createInvite(ownerPrincipal, { teamId: teamB.id, email: 'admin@bravo.test', role: 'admin' });
    const bravoAcc = tm.acceptInvite({ token: bravoInv.inviteToken, email: 'admin@bravo.test', password: 'BravoAdminPassword!2026' });

    // Create Team Alpha project (with buildSecrets, preview buildSecrets & leaked Stripe key for scanner check) + Team Bravo project
    const projA = projectManager.create({
      id: 'proj_alpha_sec',
      name: 'Alpha App',
      teamId: DEFAULT_TEAM_ID,
      envVars: { STRIPE_SECRET_KEY: 'sk_live_' + 'AbCdEfGhIjKlMnOpQrStUvWx12' },
      buildSecrets: { NPM_TOKEN: 'npm_super_secret_build_token_999' },
      previewDeployments: {
        enabled: true,
        baseDomain: 'prev.alpha.test',
        envVars: { PREVIEW_DB_TOKEN: 'preview_env_secret_123' },
        buildSecrets: { PREV_BUILD_KEY: 'prev_build_secret_456' },
        healthTimeoutMs: 42000
      }
    });
    const projB = projectManager.create({
      id: 'proj_bravo_sec',
      name: 'Bravo App',
      teamId: teamB.id
    });

    // Attach domain & database to projA
    const domA = {
      id: 'dom_alpha_1',
      hostname: 'app.alpha.test',
      projectId: projA.id,
      targetPod: 'citadel',
      targetPort: 3001,
      status: 'active',
      cloudflareProxied: false,
      sslStatus: 'pending_ssl',
      routingMode: 'direct',
      createdAt: new Date().toISOString()
    };
    domainManager.domains.push(domA);

    const dbA = {
      id: 'db_alpha_1',
      projectId: projA.id,
      engine: 'postgres',
      name: 'AlphaPG',
      username: 'alpha',
      dbName: 'alpha',
      port: 5432,
      containerName: 'culkibo_db_alpha_test',
      volumeName: 'culkibo_vol_alpha_test',
      networkName: 'culkibo_net_alpha_test',
      status: 'stopped',
      health: 'unknown',
      exposure: { enabled: false, bindAddress: '127.0.0.1', hostPort: null },
      schedule: { enabled: false, cron: null, nextRunAt: null, lastRunAt: null, lastStatus: null },
      retention: { keepLast: 7 },
      backups: [],
      restoreHistory: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    databaseManager.state.databases.push(dbA);
    containerOrchestrator.addLog('INFO', 'citadel', 'Alpha confidential startup log', new Date(), projA.id);
    containerOrchestrator.addLog('INFO', 'citadel', 'Bravo startup log', new Date(), projB.id);

    // 2. Cross-team BOLA/IDOR regression checks: Bravo Admin MUST get 404 on ALL projA/domA/dbA endpoints!
    const crossTeamProbes = [
      ['POST', '/api/projects/proj_alpha_sec/activate'],
      ['POST', '/api/projects/proj_alpha_sec/hibernate'],
      ['POST', '/api/projects/proj_alpha_sec/stop'],
      ['GET', '/api/projects/proj_alpha_sec/deploy/strategy'],
      ['POST', '/api/projects/proj_alpha_sec/deploy'],
      ['POST', '/api/projects/proj_alpha_sec/deploy/cancel'],
      ['GET', '/api/projects/proj_alpha_sec/deployments'],
      ['GET', '/api/projects/proj_alpha_sec/deploy/status'],
      ['POST', '/api/projects/proj_alpha_sec/rollback'],
      ['GET', '/api/projects/proj_alpha_sec/runtime/logs'],
      ['GET', '/api/projects/proj_alpha_sec/runtime/stats'],
      ['GET', '/api/projects/proj_alpha_sec/crons'],
      ['POST', '/api/projects/proj_alpha_sec/crons', { name: 'evil', schedule: '* * * * *', command: 'id' }],
      ['GET', '/api/projects/proj_alpha_sec/previews'],
      ['GET', '/api/projects/proj_alpha_sec/sync/status'],
      ['POST', '/api/projects/proj_alpha_sec/sync/verify'],
      ['POST', '/api/projects/proj_alpha_sec/webhook/test'],
      ['POST', '/api/projects/proj_alpha_sec/deploy-hook/rotate'],
      ['POST', '/api/projects/proj_alpha_sec/databases/db_alpha_1/link'],
      ['DELETE', '/api/projects/proj_bravo_sec/domains/dom_alpha_1'], // cross-project domain deletion!
      ['DELETE', '/api/domains/dom_alpha_1'],
      ['PATCH', '/api/domains/dom_alpha_1', { securityHeaders: false }],
      ['GET', '/api/databases/db_alpha_1'],
      ['GET', '/api/databases/db_alpha_1/credentials'],
      ['GET', '/api/logs?projectId=proj_alpha_sec']
    ];
    for (const [m, pth, body] of crossTeamProbes) {
      const r = await httpJson(port, m, pth, { token: bravoAcc.sessionToken, body });
      assert.strictEqual(r.status, 404, 'BOLA cross-team leak on ' + m + ' ' + pth + ': expected 404, got ' + r.status + ' body=' + r.text);
    }

    // Fail-closed RBAC blocks Bravo admin on instance-admin backup export (403) AND handler-level assertProjectAccess blocks scoped owner token (404)
    const bravoBackupExp = await httpJson(port, 'POST', '/api/backup/export/proj_alpha_sec', { token: bravoAcc.sessionToken });
    assert.strictEqual(bravoBackupExp.status, 403, 'Expected 403 for Bravo admin on POST /api/backup/export/proj_alpha_sec, got ' + bravoBackupExp.status);

    const scopedOwnerTok = tm.createApiToken(ownerPrincipal, {
      name: 'Scoped Bravo Only Token',
      scopes: ['*'],
      projectIds: [projB.id]
    });
    const scopedBackupExp = await httpJson(port, 'POST', '/api/backup/export/proj_alpha_sec', { token: scopedOwnerTok.token });
    assert.strictEqual(scopedBackupExp.status, 404, 'Scoped token must get 404 on POST /api/backup/export/proj_alpha_sec, got ' + scopedBackupExp.status);
    const scopedBundleExp = await httpJson(port, 'POST', '/api/bundles/export', {
      token: scopedOwnerTok.token,
      body: { stackName: 'CrossScope', projectIds: [projA.id] }
    });
    assert.strictEqual(scopedBundleExp.status, 404, 'Scoped token must get 404 on POST /api/bundles/export for forbidden projectId, got ' + scopedBundleExp.status);

    // Bravo GET /api/domains & GET /api/databases MUST NOT return Alpha's domain or DB
    const bravoDoms = await httpJson(port, 'GET', '/api/domains', { token: bravoAcc.sessionToken });
    assert.strictEqual(bravoDoms.status, 200);
    assert.strictEqual(bravoDoms.json.domains.some((d) => d.id === 'dom_alpha_1'), false, 'Bravo must not see Alpha domains');

    const bravoDbs = await httpJson(port, 'GET', '/api/databases', { token: bravoAcc.sessionToken });
    assert.strictEqual(bravoDbs.status, 200);
    assert.strictEqual(bravoDbs.json.databases.some((d) => d.id === 'db_alpha_1'), false, 'Bravo must not see Alpha databases');

    // 3. Unprivileged Viewer serialization NEVER leaks buildSecrets or previewDeployments.buildSecrets
    const viewerProj = await httpJson(port, 'GET', '/api/projects/proj_alpha_sec', { token: viewerAcc.sessionToken });
    assert.strictEqual(viewerProj.status, 200);
    assert.strictEqual(viewerProj.json.buildSecrets.NPM_TOKEN, '[REDACTED]');
    assert.strictEqual(viewerProj.json.previewDeployments.buildSecrets.PREV_BUILD_KEY, '[REDACTED]');
    assert.strictEqual(viewerProj.json.previewDeployments.envVars.PREVIEW_DB_TOKEN, '[REDACTED]');
    assert.ok(!viewerProj.text.includes('npm_super_secret_build_token_999'), 'Raw buildSecret leaked to viewer!');
    assert.ok(!viewerProj.text.includes('prev_build_secret_456'), 'Raw preview buildSecret leaked to viewer!');

    const viewerPrev = await httpJson(port, 'GET', '/api/projects/proj_alpha_sec/previews', { token: viewerAcc.sessionToken });
    assert.strictEqual(viewerPrev.status, 200);
    assert.strictEqual(viewerPrev.json.config.buildSecrets.PREV_BUILD_KEY, '[REDACTED]');
    assert.ok(!viewerPrev.text.includes('prev_build_secret_456'), 'Raw preview buildSecret leaked on /previews!');

    // 4. Developer localPath owner-only check + Deploy freeze (423) + freeze override RBAC (403) + secretScanner block (422)
    const devLocalPath = await httpJson(port, 'POST', '/api/projects', {
      token: devAcc.sessionToken,
      body: { name: 'LocalPath Attempt', localPath: TMP_DIR }
    });
    assert.strictEqual(devLocalPath.status, 403);
    assert.strictEqual(devLocalPath.json.code, 'LOCAL_PATH_OWNER_REQUIRED');

    // Add active all-day freeze window on projA
    projectManager.update(projA.id, {
      freezeWindows: [{ days: [0, 1, 2, 3, 4, 5, 6], startHour: 0, endHour: 24, tz: 'UTC', reason: 'Black Friday freeze' }]
    });
    const frozenRes = await httpJson(port, 'POST', '/api/projects/proj_alpha_sec/deploy', {
      token: devAcc.sessionToken,
      body: {}
    });
    assert.strictEqual(frozenRes.status, 423, 'Frozen deploy must return 423 DEPLOY_FROZEN, got ' + frozenRes.status);
    assert.strictEqual(frozenRes.json.code, 'DEPLOY_FROZEN');

    const devOverride = await httpJson(port, 'POST', '/api/projects/proj_alpha_sec/deploy', {
      token: devAcc.sessionToken,
      body: { overrideFreeze: true }
    });
    assert.strictEqual(devOverride.status, 403, 'Developer must not override freeze window');
    assert.strictEqual(devOverride.json.code, 'FREEZE_OVERRIDE_FORBIDDEN');

    // Owner overriding freeze with secretScanMode:'block' hits pre-deploy secretScanner (422)
    const secretBlocked = await httpJson(port, 'POST', '/api/projects/proj_alpha_sec/deploy', {
      token: ownerBoot.sessionToken,
      body: { overrideFreeze: true, secretScanMode: 'block' }
    });
    assert.strictEqual(secretBlocked.status, 422, 'Pre-deploy secretScanner block mode must return 422');
    assert.strictEqual(secretBlocked.json.code, 'SECRET_LEAK_DETECTED');

    // 5. HttpOnly; SameSite=Strict Cookies on /auth/login & /auth/verify + Bearer compatibility
    const loginRes = await httpJson(port, 'POST', '/api/auth/login', {
      body: { email: 'owner@alpha.test', password: 'AlphaOwnerPassword!2026' }
    });
    assert.strictEqual(loginRes.status, 200);
    assert.ok(loginRes.json.sessionToken && loginRes.json.sessionToken.startsWith('cks_'));
    const loginCookies = [].concat(loginRes.headers['set-cookie'] || []);
    assert.ok(loginCookies.some((c) => c.includes('HttpOnly') && c.includes('SameSite=Strict') && c.includes('culkibo_session=cks_')),
      'POST /auth/login must emit HttpOnly; SameSite=Strict session cookie');

    const masterToken = auth.resolveToken();
    const verifyRes = await httpJson(port, 'POST', '/api/auth/verify', {
      body: { token: masterToken }
    });
    assert.strictEqual(verifyRes.status, 200);
    assert.strictEqual(verifyRes.json.valid, true);
    const verifyCookies = [].concat(verifyRes.headers['set-cookie'] || []);
    assert.ok(verifyCookies.some((c) => c.includes('HttpOnly') && c.includes('SameSite=Strict')),
      'POST /auth/verify must emit HttpOnly; SameSite=Strict cookie');
    assert.ok(!verifyCookies.some((c) => c.includes(masterToken)),
      'POST /auth/verify must never place raw master token in cookie');

    // 6. Actor metadata in auditLogger + hash-chain verify endpoint
    const updRes = await httpJson(port, 'PUT', '/api/projects/proj_alpha_sec', {
      token: ownerBoot.sessionToken,
      body: { description: 'Audited description update' }
    });
    assert.strictEqual(updRes.status, 200);
    const recentAudit = auditLogger.query({ limit: 5 });
    const putAudit = recentAudit.find((e) => e.method === 'PUT' && e.path === '/projects/proj_alpha_sec');
    assert.ok(putAudit, 'PUT /projects/:id mutation must be recorded in auditLogger');
    assert.strictEqual(putAudit.actor && putAudit.actor.email, 'owner@alpha.test');
    assert.strictEqual(putAudit.actor && putAudit.actor.role, 'owner');
    assert.strictEqual(putAudit.authMethod, 'session');

    const auditVerify = await httpJson(port, 'GET', '/api/system/audit/verify', { token: ownerBoot.sessionToken });
    assert.strictEqual(auditVerify.status, 200);
    assert.strictEqual(auditVerify.json.valid, true);

    // 7. Edition API + Offline Ed25519 activation + Tamper rejection
    const edInit = await httpJson(port, 'GET', '/api/system/edition?includeCatalog=1', { token: ownerBoot.sessionToken });
    assert.strictEqual(edInit.status, 200);
    assert.strictEqual(edInit.json.edition, 'community');
    assert.strictEqual(edInit.json.coreFeatures.unlimited_projects, true);
    assert.strictEqual(edInit.json.commercialFeatures.enterprise_scim_saml, false);

    const entKey = mintLicense({
      licenseId: 'lic_ent_http_01',
      edition: 'enterprise',
      holder: { org: 'Acme Corp', email: 'ops@acme.test' },
      expiresAt: new Date(Date.now() + 90 * 86400000).toISOString(),
      seats: 50
    }, keypair.privateKeyPem);

    const edAct = await httpJson(port, 'POST', '/api/system/edition/activate', {
      token: ownerBoot.sessionToken,
      body: { licenseKey: entKey }
    });
    assert.strictEqual(edAct.status, 200, 'Valid Ed25519 license activation failed: ' + edAct.text);
    assert.strictEqual(edAct.json.edition, 'enterprise');
    assert.strictEqual(edAct.json.commercialActive, true);
    assert.strictEqual(edAct.json.commercialFeatures.enterprise_scim_saml, true);
    assert.strictEqual(edAct.json.commercialFeatures.sla_support_export, true);

    const badAct = await httpJson(port, 'POST', '/api/system/edition/activate', {
      token: ownerBoot.sessionToken,
      body: { licenseKey: entKey.slice(0, -4) + 'AAAA' }
    });
    assert.strictEqual(badAct.status, 400);
    assert.strictEqual(badAct.json.code, 'INVALID_LICENSE_SIGNATURE');

    // 8. Wave-2 Endpoints: MCP ?profile=, Logs export, Topology, Catalog drift, Cloudflare tunnels, Secret scanner, Wildcard DNS-01
    const mcpCore = await httpJson(port, 'GET', '/api/mcp/tools?profile=core', { token: masterToken });
    assert.strictEqual(mcpCore.status, 200);
    assert.strictEqual(mcpCore.headers['x-culkibo-mcp-profile'], 'core');
    assert.ok(Array.isArray(mcpCore.json.tools) && mcpCore.json.tools.length <= 25, 'core profile must return compact tool subset');

    const mcpBad = await httpJson(port, 'GET', '/api/mcp/tools?profile=bogus_profile', { token: masterToken });
    assert.strictEqual(mcpBad.status, 400);

    const mcpCfg = await httpJson(port, 'GET', '/api/mcp/config?profile=core', { token: masterToken });
    assert.strictEqual(mcpCfg.status, 200);
    assert.ok(mcpCfg.text.includes('profile=core'));

    const logsExp = await httpJson(port, 'GET', '/api/observability/logs/export?format=ndjson', { token: ownerBoot.sessionToken });
    assert.strictEqual(logsExp.status, 200);
    assert.ok(String(logsExp.headers['content-disposition'] || '').includes('attachment'));
    assert.ok(logsExp.text.includes('Alpha confidential startup log'));
    assert.ok(!logsExp.text.includes('Bravo startup log'), 'Scoped log export must never leak cross-team logs');

    const topo = await httpJson(port, 'GET', '/api/observability/topology', { token: ownerBoot.sessionToken });
    assert.strictEqual(topo.status, 200);
    assert.ok(Array.isArray(topo.json.nodes) && Array.isArray(topo.json.edges));

    const drift = await httpJson(port, 'GET', '/api/catalog/drift', { token: masterToken });
    assert.strictEqual(drift.status, 200);

    const cfCfg = await httpJson(port, 'POST', '/api/cloudflare/tunnels/config', {
      token: masterToken,
      body: { enabled: false, mode: 'per_hostname' }
    });
    assert.strictEqual(cfCfg.status, 200);
    const cfStatus = await httpJson(port, 'GET', '/api/cloudflare/tunnels/status', { token: masterToken });
    assert.strictEqual(cfStatus.status, 200);

    const wildRes = await httpJson(port, 'POST', '/api/ingress/wildcard-dns01', {
      token: masterToken,
      body: { domain: 'multi.example.test', provider: 'hetzner', credentialsEnv: { auth_api_token: 'HETZNER_DNS_TOKEN' } }
    });
    assert.strictEqual(wildRes.status, 200, 'Multi-provider wildcard-dns01 failed: ' + wildRes.text);
    assert.strictEqual(wildRes.json.policy.provider, 'hetzner');
    assert.strictEqual(wildRes.json.policy.tokenEnv, 'HETZNER_DNS_TOKEN');

    const syntheticAwsKey = 'AKIA' + '9X8W7V6U5T4S3R2Q';
    const scanRes = await httpJson(port, 'POST', '/api/security/scan-secrets', {
      token: devAcc.sessionToken,
      body: { envVars: { AWS_ACCESS_KEY_ID: syntheticAwsKey }, mode: 'warn' }
    });
    assert.strictEqual(scanRes.status, 200);
    assert.strictEqual(scanRes.json.clean, false);
    assert.ok(!scanRes.text.includes(syntheticAwsKey), 'Secret scanner must mask secret values');

    // 9. Coolify Plan/Verify + Portable Stack Bundle Export/Inspect/Import (#114 / #115) + Cross-team BOLA rejection
    const coolifyPlan = await httpJson(port, 'POST', '/api/import/coolify/plan', {
      token: ownerBoot.sessionToken,
      body: {
        snapshot: {
          apps: [{
            uuid: 'cf-app-1',
            name: 'Billing API',
            fqdn: 'https://billing.example.test',
            ports_exposes: '4000',
            health_check_path: '/healthz',
            environment_variables: [
              { key: 'APP_URL', value: '\${SERVICE_URL_BILLING}' },
              { key: 'JWT_SECRET', value: '\${SERVICE_PASSWORD_64_JWT}' }
            ]
          }],
          databases: [{ uuid: 'cf-db-1', name: 'MainPG', database_type: 'postgresql', postgres_db: 'billing' }],
          services: []
        }
      }
    });
    assert.strictEqual(coolifyPlan.status, 200, 'POST /api/import/coolify/plan failed: ' + coolifyPlan.text);
    assert.ok(coolifyPlan.json.parityScore >= 90, 'Expected high parity score');
    assert.strictEqual(coolifyPlan.json.summary.apps, 1);
    assert.strictEqual(coolifyPlan.json.summary.databases, 1);

    const coolifyVerify = await httpJson(port, 'POST', '/api/import/coolify/verify', {
      token: ownerBoot.sessionToken,
      body: {
        dryRun: true,
        targetIp: '203.0.113.10',
        targets: [{ name: 'Billing', hostname: 'billing.example.test', sourceUrl: 'https://billing.example.test/healthz', targetUrl: 'http://203.0.113.10:4000/healthz', healthPath: '/healthz' }]
      }
    });
    assert.strictEqual(coolifyVerify.status, 200, 'POST /api/import/coolify/verify failed: ' + coolifyVerify.text);
    assert.strictEqual(coolifyVerify.json.dryRun, true);
    assert.strictEqual(coolifyVerify.json.summary.total, 1);

    // Bundle export -> inspect -> dryRun import (with encrypted Vault passphrase)
    const expRes = await httpJson(port, 'POST', '/api/bundles/export', {
      token: ownerBoot.sessionToken,
      body: { stackName: 'Alpha Prod', format: 'zip', passphrase: 'BundleVaultPassphrase!2026', projectIds: [projA.id] }
    });
    assert.strictEqual(expRes.status, 200, 'POST /api/bundles/export failed: ' + expRes.text);
    assert.strictEqual(expRes.json.format, 'zip');
    assert.ok(expRes.json.bundleBase64 && expRes.json.sha256);
    assert.strictEqual(expRes.json.manifest.vaultMode, 'encrypted');
    assert.strictEqual(expRes.json.manifest.counts.projects, 1);

    // Cross-team BOLA: Bravo admin cannot export Alpha's project via /api/bundles/export (403 RBAC or 404 BOLA)
    const bravoBundleExp = await httpJson(port, 'POST', '/api/bundles/export', {
      token: bravoAcc.sessionToken,
      body: { stackName: 'Steal Alpha', projectIds: [projA.id] }
    });
    assert.ok(bravoBundleExp.status === 403 || bravoBundleExp.status === 404,
      'Bravo must not export Alpha bundle, got ' + bravoBundleExp.status);

    // Inspect exported bundle with valid passphrase & reject wrong passphrase
    const inspOk = await httpJson(port, 'POST', '/api/bundles/inspect', {
      token: ownerBoot.sessionToken,
      body: { bundleBase64: expRes.json.bundleBase64, passphrase: 'BundleVaultPassphrase!2026' }
    });
    assert.strictEqual(inspOk.status, 200, 'POST /api/bundles/inspect failed: ' + inspOk.text);
    assert.strictEqual(inspOk.json.checksumsVerified, true);
    assert.strictEqual(inspOk.json.vaultSummary.unlocked, true);

    const inspBadPass = await httpJson(port, 'POST', '/api/bundles/inspect', {
      token: ownerBoot.sessionToken,
      body: { bundleBase64: expRes.json.bundleBase64, passphrase: 'WrongPassphrase!999' }
    });
    assert.strictEqual(inspBadPass.status, 400, 'Wrong vault passphrase must return 400');

    // Dry-run import
    const impDry = await httpJson(port, 'POST', '/api/bundles/import', {
      token: ownerBoot.sessionToken,
      body: { bundleBase64: expRes.json.bundleBase64, passphrase: 'BundleVaultPassphrase!2026', dryRun: true }
    });
    assert.strictEqual(impDry.status, 200, 'POST /api/bundles/import dryRun failed: ' + impDry.text);
    assert.strictEqual(impDry.json.dryRun, true);
    assert.strictEqual(impDry.json.wouldImport.projects, 1);

    console.log('HTTP_BOLA_WAVE2_OK');
  } finally {
    await new Promise((r) => server.close(r));
  }
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
`;

  fs.writeFileSync(scriptPath, runnerSource, 'utf8');
  try {
    const out = execFileSync(process.execPath, [scriptPath], {
      cwd: rootDir,
      encoding: 'utf8',
      timeout: 30000
    });
    assert.ok(out.includes('HTTP_BOLA_WAVE2_OK'), `Isolated HTTP BOLA/Wave-2 suite failed:\n${out}`);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testEditionAndBola() {
  console.log('🔐 Testing CronParser Anti-DoS, Project Secrets, Ed25519 Edition Verifier & BOLA/Wave-2 HTTP Closure...');

  // -------------------------------------------------------------------------
  // 1. CronParser Anti-DoS: impossible dates MUST terminate in < 5 ms
  // -------------------------------------------------------------------------
  {
    const impossible = ['0 0 30 2 *', '0 0 31 2 *', '0 0 31 4 *', '0 0 31 6,9,11 *'];
    const base = new Date('2026-01-01T00:00:00Z');
    // Warm up JIT once
    try { nextCronRun('0 0 30 2 *', base); } catch (e) {}

    let worstMs = 0;
    for (const expr of impossible) {
      const t0 = performance.now();
      assert.throws(
        () => nextCronRun(expr, base),
        /próxima ejecución válida|No se encontró/i,
        `Cron imposible "${expr}" debe lanzar error limpio`
      );
      const elapsed = performance.now() - t0;
      worstMs = Math.max(worstMs, elapsed);
      assert.ok(elapsed < 5, `Cron DoS regression on "${expr}": took ${elapsed.toFixed(2)}ms (>= 5ms)`);
    }

    // Leap day 2028-02-29 resolves cleanly in < 5ms
    const tLeap0 = performance.now();
    const leap = nextCronRun('0 0 29 2 *', new Date('2027-01-01T00:00:00Z'));
    const tLeap = performance.now() - tLeap0;
    assert.strictEqual(leap.getMonth(), 1);
    assert.strictEqual(leap.getDate(), 29);
    assert.strictEqual(leap.getFullYear(), 2028);
    assert.ok(tLeap < 5, `Leap day took ${tLeap.toFixed(2)}ms`);

    // Century boundary leap day 2096 -> 2104 (2100 is NOT leap) resolves cleanly in < 5ms
    const tCent0 = performance.now();
    const centLeap = nextCronRun('0 0 29 2 *', new Date('2096-03-01T00:00:00Z'));
    const tCent = performance.now() - tCent0;
    assert.strictEqual(centLeap.getFullYear(), 2104);
    assert.strictEqual(centLeap.getMonth(), 1);
    assert.strictEqual(centLeap.getDate(), 29);
    assert.ok(tCent < 5, `Century leap day took ${tCent.toFixed(2)}ms`);

    // OR semantics: Feb 30 OR Monday in February MUST still match first Monday in Feb!
    const orRun = nextCronRun('0 0 30 2 1', new Date('2026-01-31T23:59:00Z'));
    assert.strictEqual(orRun.getMonth(), 1);
    assert.strictEqual(orRun.getDay(), 1);
    assert.ok(parseCron('@daily').minute.has(0));

    console.log(`  ✓ 1. CronParser anti-DoS verified: impossible dates max ${worstMs.toFixed(3)}ms (<5ms), leap/century/OR semantics OK`);
  }

  // -------------------------------------------------------------------------
  // 2. Project.js persistence (buildSecrets, health*, previewDeployments.*) & redaction
  // -------------------------------------------------------------------------
  {
    const raw = {
      id: 'proj_secrets_persist_1',
      name: 'Secret Persist App',
      envVars: { API_KEY: 'live_api_key_999' },
      buildArgs: { NODE_ENV: 'production' },
      buildSecrets: {
        NPM_TOKEN: 'npm_secret_value_12345',
        GH_PACKAGES_TOKEN: 'ghp_secret_value_67890',
        'BAD-KEY': 'must_be_dropped',
        __proto__: 'must_be_dropped'
      },
      healthStartPeriodSec: 45,
      healthRetries: 5,
      healthyThreshold: 3,
      previewDeployments: {
        enabled: true,
        baseDomain: 'previews.example.com',
        maxPreviews: 8,
        allowForks: false,
        ttlHours: 72,
        memoryMb: 512,
        envVars: { PREVIEW_MODE: 'true', PREVIEW_TOKEN: 'prev_env_secret_111' },
        buildSecrets: { PREVIEW_NPM_TOKEN: 'prev_build_secret_222' },
        healthTimeoutMs: 45000
      }
    };

    const p1 = new Project(raw);
    assert.deepStrictEqual(p1.buildSecrets, {
      NPM_TOKEN: 'npm_secret_value_12345',
      GH_PACKAGES_TOKEN: 'ghp_secret_value_67890'
    });
    assert.strictEqual(p1.healthStartPeriodSec, 45);
    assert.strictEqual(p1.healthRetries, 5);
    assert.strictEqual(p1.healthyThreshold, 3);
    assert.deepStrictEqual(p1.previewDeployments.envVars, { PREVIEW_MODE: 'true', PREVIEW_TOKEN: 'prev_env_secret_111' });
    assert.deepStrictEqual(p1.previewDeployments.buildSecrets, { PREVIEW_NPM_TOKEN: 'prev_build_secret_222' });
    assert.strictEqual(p1.previewDeployments.healthTimeoutMs, 45000);

    // Round-trip persistence check (projects.json simulation)
    const pReloaded = new Project(JSON.parse(JSON.stringify(p1)));
    assert.deepStrictEqual(pReloaded.buildSecrets, p1.buildSecrets);
    assert.strictEqual(pReloaded.healthStartPeriodSec, 45);
    assert.strictEqual(pReloaded.healthRetries, 5);
    assert.strictEqual(pReloaded.healthyThreshold, 3);
    assert.deepStrictEqual(pReloaded.previewDeployments, p1.previewDeployments);

    // Bounds clamping
    const pClamped = new Project({
      name: 'Clamped',
      healthStartPeriodSec: 9999,
      healthRetries: 99,
      healthyThreshold: 99,
      previewDeployments: { enabled: true, healthTimeoutMs: 10 }
    });
    assert.strictEqual(pClamped.healthStartPeriodSec, 300);
    assert.strictEqual(pClamped.healthRetries, 10);
    assert.strictEqual(pClamped.healthyThreshold, 5);
    assert.strictEqual(pClamped.previewDeployments.healthTimeoutMs, 5000);

    // Unprivileged serialization NEVER leaks buildSecrets or previewDeployments.buildSecrets
    const safe = p1.toSafeJSON();
    const safeText = JSON.stringify(safe);
    assert.strictEqual(safe._secretsRedacted, true);
    assert.strictEqual(safe.buildSecrets.NPM_TOKEN, '[REDACTED]');
    assert.strictEqual(safe.previewDeployments.buildSecrets.PREVIEW_NPM_TOKEN, '[REDACTED]');
    assert.strictEqual(safe.previewDeployments.envVars.PREVIEW_TOKEN, '[REDACTED]');
    assert.strictEqual(safe.envVars.API_KEY, '[REDACTED]');
    assert.ok(!safeText.includes('npm_secret_value_12345'));
    assert.ok(!safeText.includes('prev_build_secret_222'));
    assert.ok(!safeText.includes('prev_env_secret_111'));
    // Original instance remains unmutated
    assert.strictEqual(p1.buildSecrets.NPM_TOKEN, 'npm_secret_value_12345');

    console.log('  ✓ 2. Project.js buildSecrets, healthcheck bounds, previewDeployments.* persistence & unprivileged redaction verified');
  }

  // -------------------------------------------------------------------------
  // 3. EditionService: Ethical Open-Core & Offline Ed25519 License Verifier
  // -------------------------------------------------------------------------
  {
    const tmpEdDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-edition-test-'));
    try {
      const kp1 = generateLicenseKeyPair();
      const kpUntrusted = generateLicenseKeyPair();
      const svc = new EditionService({
        dataDir: tmpEdDir,
        trustedPublicKeys: [kp1.publicKeyPem],
        instanceId: 'inst_prod_001'
      });

      // Default Community Edition: 100% OSS core unlocked, zero disk writes on read
      const comm = svc.getStatus({ includeCatalog: true });
      assert.strictEqual(comm.edition, 'community');
      assert.strictEqual(comm.commercialActive, false);
      assert.strictEqual(fs.existsSync(path.join(tmpEdDir, 'edition.json')), false, 'Reading default edition must not write disk');
      for (const feat of Object.keys(CORE_OSS_FEATURES)) {
        assert.strictEqual(svc.hasFeature(feat), true, `Community OSS MUST never gate core feature ${feat}`);
      }
      for (const pack of Object.keys(COMMERCIAL_FEATURE_CATALOG)) {
        assert.strictEqual(svc.hasFeature(pack), false, `Commercial pack ${pack} must be false without license`);
      }

      // Mint & activate Pro license
      const now = Date.now();
      const proKey = mintLicense({
        licenseId: 'lic_pro_2026_01',
        edition: 'pro',
        holder: { org: 'Indie Studio', email: 'founder@indie.dev' },
        issuedAt: new Date(now - 60000).toISOString(),
        expiresAt: new Date(now + 30 * 86400000).toISOString(),
        maxNodes: 10,
        seats: 15,
        instanceId: 'inst_prod_001'
      }, kp1.privateKeyPem);

      const proRes = svc.activateLicense(proKey, { nowMs: now });
      assert.strictEqual(proRes.activated, true);
      assert.strictEqual(proRes.edition, 'pro');
      assert.strictEqual(proRes.commercialActive, true);
      assert.strictEqual(svc.hasFeature('managed_multi_region_relay', { nowMs: now }), true);
      assert.strictEqual(svc.hasFeature('custom_branding', { nowMs: now }), true);
      assert.strictEqual(svc.hasFeature('enterprise_scim_saml', { nowMs: now }), false);
      assert.strictEqual(svc.hasFeature('unlimited_projects', { nowMs: now }), true);
      assert.ok(fs.existsSync(path.join(tmpEdDir, 'edition.json')));

      // Reload from disk offline
      const svcReloaded = new EditionService({
        dataDir: tmpEdDir,
        trustedPublicKeys: [kp1.publicKeyPem],
        instanceId: 'inst_prod_001'
      });
      const reloadedStatus = svcReloaded.getStatus({ nowMs: now });
      assert.strictEqual(reloadedStatus.edition, 'pro');
      assert.strictEqual(reloadedStatus.license.licenseId, 'lic_pro_2026_01');
      assert.strictEqual(reloadedStatus.license.verifiedOffline, true);

      // Expired evaluation gracefully reverts to Community OSS without breaking core features
      const afterExpiry = svcReloaded.getStatus({ nowMs: now + 31 * 86400000 });
      assert.strictEqual(afterExpiry.edition, 'community');
      assert.strictEqual(afterExpiry.commercialActive, false);
      assert.strictEqual(afterExpiry.verification.code, 'LICENSE_EXPIRED');
      assert.strictEqual(afterExpiry.coreFeatures.unlimited_projects, true);

      // Tamper proofs: payload bit-flip, signature bit-flip, wrong keypair, expired activation, notBefore, instanceId mismatch
      const parts = proKey.split('.');
      const tamperedPayload = parts[1].slice(0, -2) + (parts[1].endsWith('AA') ? 'BB' : 'AA');
      assert.strictEqual(
        verifyLicenseKey(`${parts[0]}.${tamperedPayload}.${parts[2]}`, { publicKeys: [kp1.publicKeyPem], nowMs: now }).code,
        'INVALID_LICENSE_SIGNATURE'
      );
      const tamperedSig = parts[2].slice(0, -2) + (parts[2].endsWith('AA') ? 'BB' : 'AA');
      assert.strictEqual(
        verifyLicenseKey(`${parts[0]}.${parts[1]}.${tamperedSig}`, { publicKeys: [kp1.publicKeyPem], nowMs: now }).code,
        'INVALID_LICENSE_SIGNATURE'
      );
      const forgedKey = mintLicense({
        licenseId: 'lic_forged_01',
        edition: 'enterprise',
        holder: { org: 'Attacker' },
        expiresAt: new Date(now + 86400000).toISOString()
      }, kpUntrusted.privateKeyPem);
      assert.throws(
        () => svc.activateLicense(forgedKey, { nowMs: now }),
        (err) => err && err.code === 'INVALID_LICENSE_SIGNATURE'
      );

      // Expired license activation rejected (HTTP 422)
      assert.throws(
        () => svc.activateLicense(proKey, { nowMs: now + 35 * 86400000 }),
        (err) => err && err.status === 422 && err.code === 'LICENSE_EXPIRED'
      );

      // Not-yet-valid license rejected (HTTP 422)
      const futureKey = mintLicense({
        licenseId: 'lic_future_01',
        edition: 'cloud',
        holder: { org: 'Future Corp' },
        issuedAt: new Date(now).toISOString(),
        notBefore: new Date(now + 10 * 86400000).toISOString(),
        expiresAt: new Date(now + 40 * 86400000).toISOString()
      }, kp1.privateKeyPem);
      assert.throws(
        () => svc.activateLicense(futureKey, { nowMs: now }),
        (err) => err && err.status === 422 && err.code === 'LICENSE_NOT_YET_VALID'
      );

      // Instance ID mismatch rejected
      const otherInstKey = mintLicense({
        licenseId: 'lic_other_inst',
        edition: 'enterprise',
        holder: { org: 'Other' },
        instanceId: 'inst_other_999',
        expiresAt: new Date(now + 86400000).toISOString()
      }, kp1.privateKeyPem);
      assert.throws(
        () => svc.activateLicense(otherInstKey, { nowMs: now }),
        (err) => err && err.code === 'LICENSE_INSTANCE_MISMATCH'
      );

      // Deactivate cleanly reverts to Community
      const deact = svc.deactivateLicense();
      assert.strictEqual(deact.deactivated, true);
      assert.strictEqual(deact.edition, 'community');
      assert.strictEqual(svc.hasFeature('managed_multi_region_relay'), false);
      assert.strictEqual(svc.hasFeature('unlimited_projects'), true);

      // CULKIBO_DATA_DIR isolation check
      const prevEnv = process.env.CULKIBO_DATA_DIR;
      try {
        process.env.CULKIBO_DATA_DIR = tmpEdDir;
        const envSvc = new EditionService();
        assert.strictEqual(path.resolve(envSvc._getFilePath()), path.resolve(path.join(tmpEdDir, 'edition.json')));
      } finally {
        if (prevEnv === undefined) delete process.env.CULKIBO_DATA_DIR;
        else process.env.CULKIBO_DATA_DIR = prevEnv;
      }

      console.log('  ✓ 3. EditionService Ed25519 mint/verify/tamper/expiry/nbf/instanceId & Ethical Open-Core verified');
    } finally {
      fs.rmSync(tmpEdDir, { recursive: true, force: true });
    }
  }

  // -------------------------------------------------------------------------
  // 4. Real Express HTTP BOLA/IDOR Closure, Audit Actor, HttpOnly Cookies & Wave-2 Routes
  // -------------------------------------------------------------------------
  runIsolatedHttpBolaAndWave2Suite();
  console.log('  ✓ 4. Real Express HTTP BOLA/IDOR (26 cross-team probes), HttpOnly cookies, audit actor, freeze/scanner & Wave-2 routes verified');

  console.log('✅ All Edition, CronParser Anti-DoS, Project Secrets & BOLA/IDOR tests passed!\n');
}

module.exports = testEditionAndBola;

if (require.main === module) {
  testEditionAndBola().catch((err) => {
    console.error('❌ Edition & BOLA test failure:', err);
    process.exit(1);
  });
}
