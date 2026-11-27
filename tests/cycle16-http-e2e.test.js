const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

async function testCycle16HttpE2E() {
  console.log('\n🚀 Testing Cycle #16 165-MCP Milestone Live Isolated HTTP E2E (API Contract Gate, OCI/SLSA Rekor, WS/SSE Flood & 101 Guard, DNS Cutover, Orphan PR-Preview Reaper)...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c16-http-'));
  const rootDir = path.resolve(__dirname, '..');
  const runnerPath = path.join(tmpDir, 'cycle16-http-runner.js');

  fs.writeFileSync(runnerPath, `
const assert = require('assert');
const crypto = require('crypto');
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
const { computeDssePae } = require(path.join(ROOT_DIR, 'server/services/ociSignatureVerifier'));
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
      id: 'proj_c16_a',
      name: 'Cycle16 Sovereign API',
      domains: ['c16.example.test']
    });

    // 1. API Contract & Schema Drift Gate (/api/contracts/*)
    const baseOpenApi = {
      openapi: '3.1.0',
      info: { title: 'Billing API', version: '1.4.0' },
      security: [{ bearerAuth: [] }],
      paths: {
        '/v1/users/{id}': {
          get: { responses: { '200': { description: 'ok' } } },
          delete: { responses: { '204': { description: 'deleted' } } }
        }
      }
    };
    const breakingMinorOpenApi = {
      openapi: '3.1.0',
      info: { title: 'Billing API', version: '1.5.0' },
      security: [],
      paths: {
        '/v1/users/{id}': {
          get: {
            parameters: [{ name: 'tenantId', in: 'header', required: true }],
            responses: { '200': { description: 'ok' } }
          }
        }
      }
    };
    const breakingMajorOpenApi = {
      ...breakingMinorOpenApi,
      info: { title: 'Billing API', version: '2.0.0' }
    };

    const cBase = await reqJson(port, 'POST', '/api/contracts/baseline', {
      token: master,
      body: { projectId: 'proj_c16_a', format: 'openapi', version: '1.4.0', spec: baseOpenApi }
    });
    assert.strictEqual(cBase.status, 201, 'POST /contracts/baseline failed: ' + cBase.text);
    assert.strictEqual(cBase.json.ok, true);

    const cDiffBlocked = await reqJson(port, 'POST', '/api/contracts/diff', {
      token: master,
      body: { format: 'openapi', baseSpec: baseOpenApi, revisionSpec: breakingMinorOpenApi }
    });
    assert.strictEqual(cDiffBlocked.status, 200);
    assert.strictEqual(cDiffBlocked.json.allowed, false);
    assert.strictEqual(cDiffBlocked.json.code, 'MISSING-VERSION-BUMP');
    const diffCodes = cDiffBlocked.json.breakingChanges.map((c) => c.code);
    assert.ok(diffCodes.includes('METHOD_REMOVED'));
    assert.ok(diffCodes.includes('REQUIRED_PARAM_ADDED'));
    assert.ok(diffCodes.includes('AUTH_REMOVED'));

    const cGateBlocked = await reqJson(port, 'POST', '/api/contracts/gate', {
      token: master,
      body: { projectId: 'proj_c16_a', format: 'openapi', revisionSpec: breakingMinorOpenApi }
    });
    assert.strictEqual(cGateBlocked.status, 200);
    assert.strictEqual(cGateBlocked.json.allowed, false);
    assert.strictEqual(cGateBlocked.json.code, 'MISSING-VERSION-BUMP');

    const cGateMajor = await reqJson(port, 'POST', '/api/contracts/gate', {
      token: master,
      body: { projectId: 'proj_c16_a', format: 'openapi', revisionSpec: breakingMajorOpenApi }
    });
    assert.strictEqual(cGateMajor.status, 200);
    assert.strictEqual(cGateMajor.json.allowed, true);
    assert.strictEqual(cGateMajor.json.code, 'MAJOR_VERSION_BUMP_ALLOWED');

    const cHist = await reqJson(port, 'GET', '/api/contracts/history?projectId=proj_c16_a', { token: master });
    assert.strictEqual(cHist.status, 200);
    assert.ok(cHist.json.count >= 3);

    // 2. Pure-Node OCI Artifact Signature & SLSA Rekor Verifier (/api/supply-chain/* — CVE-2026-22703)
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const rootPut = await reqJson(port, 'PUT', '/api/supply-chain/trust-roots', {
      token: master,
      body: {
        id: 'github-oidc-ed25519',
        name: 'GitHub Actions SLSA Root',
        algorithm: 'ed25519',
        publicKeyPem: pubPem,
        allowedBuilders: ['https://github.com/actions/runner']
      }
    });
    assert.strictEqual(rootPut.status, 200, 'PUT /supply-chain/trust-roots failed: ' + rootPut.text);
    assert.strictEqual(rootPut.json.ok, true);

    const policiesGet = await reqJson(port, 'GET', '/api/supply-chain/oci-policies', { token: master });
    assert.strictEqual(policiesGet.status, 200);
    assert.strictEqual(policiesGet.json.count, 1);

    const digestHexA = 'a'.repeat(64);
    const digestHexB = 'b'.repeat(64);
    const imageRefA = 'ghcr.io/culkibo/api@sha256:' + digestHexA;
    const payloadType = 'application/vnd.in-toto+json';
    const statement = {
      _type: 'https://in-toto.io/Statement/v1',
      subject: [{ name: 'ghcr.io/culkibo/api', digest: { sha256: digestHexA } }],
      predicateType: 'https://slsa.dev/provenance/v1',
      predicate: { runDetails: { builder: { id: 'https://github.com/actions/runner' } } }
    };
    const payloadBuf = Buffer.from(JSON.stringify(statement), 'utf8');
    const pae = computeDssePae(payloadType, payloadBuf);
    const sigB64 = crypto.sign(null, pae, privateKey).toString('base64');

    const tamperedBundle = {
      dsseEnvelope: { payloadType, payload: payloadBuf.toString('base64'), signatures: [{ sig: sigB64 }] },
      verificationMaterial: {
        tlogEntries: [{
          canonicalizedBody: JSON.stringify({ spec: { artifactDigest: 'sha256:' + digestHexB } }),
          signedTimestamp: '2026-11-28T00:00:00Z'
        }]
      }
    };
    const ociTampered = await reqJson(port, 'POST', '/api/supply-chain/oci-verify', {
      token: master,
      body: { imageRef: imageRefA, trustRootId: 'github-oidc-ed25519', bundle: tamperedBundle }
    });
    assert.strictEqual(ociTampered.status, 200);
    assert.strictEqual(ociTampered.json.verified, false);
    assert.strictEqual(ociTampered.json.code, 'REKOR_DIGEST_MISMATCH');

    const boundBundle = {
      dsseEnvelope: { payloadType, payload: payloadBuf.toString('base64'), signatures: [{ sig: sigB64 }] },
      verificationMaterial: {
        tlogEntries: [{
          canonicalizedBody: JSON.stringify({ spec: { artifactDigest: 'sha256:' + digestHexA } }),
          signedTimestamp: '2026-11-28T00:00:00Z'
        }]
      }
    };
    const ociBound = await reqJson(port, 'POST', '/api/supply-chain/oci-verify', {
      token: master,
      body: {
        imageRef: imageRefA,
        trustRootId: 'github-oidc-ed25519',
        bundle: boundBundle,
        referrersStatus: 404,
        tlsVerify: true
      }
    });
    assert.strictEqual(ociBound.status, 200);
    assert.strictEqual(ociBound.json.verified, true);
    assert.strictEqual(ociBound.json.rekorVersion, 'v2');
    assert.strictEqual(ociBound.json.referrerStrategy.strategy, 'tag_fallback');
    assert.strictEqual(ociBound.json.referrerStrategy.fallbackTag, 'sha256-' + digestHexA + '.att');
    assert.strictEqual(ociBound.json.referrerStrategy.tlsVerify, true);

    // 3. Edge WS/SSE Flood & 101 Hop-by-Hop Guard (/api/edge/stream-guard* — CVE-2026-55458)
    const sgPol = await reqJson(port, 'POST', '/api/edge/stream-guard/policy', {
      token: master,
      body: { projectId: 'proj_c16_a', maxPerIp: 10, maxPerProject: 200, heartbeatIntervalSec: 25, streamCloseDelaySec: 30 }
    });
    assert.strictEqual(sgPol.status, 200, 'POST /edge/stream-guard/policy failed: ' + sgPol.text);
    assert.ok(sgPol.json.caddyBlock.caddyfile.includes('stream_close_delay 30s'));
    assert.ok(sgPol.json.caddyBlock.caddyfile.includes('flush_interval -1'));

    const sgEval = await reqJson(port, 'POST', '/api/edge/stream-guard/evaluate', {
      token: master,
      body: {
        projectId: 'proj_c16_a',
        clientIp: '203.0.113.42',
        protocol: 'ws',
        activePerIp: 10,
        upgradeHeaders: {
          Connection: 'Upgrade, Keep-Alive, X-Internal-Hop',
          Upgrade: 'websocket',
          'Sec-WebSocket-Accept': 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=',
          'Proxy-Authenticate': 'Basic realm="internal"',
          'Alt-Svc': 'h3=":443"',
          'Keep-Alive': 'timeout=5',
          'X-Internal-Hop': 'secret-hop'
        }
      }
    });
    assert.strictEqual(sgEval.status, 200, 'POST /edge/stream-guard/evaluate failed: ' + sgEval.text);
    assert.strictEqual(sgEval.json.allowed, false);
    assert.strictEqual(sgEval.json.httpStatus, 429);
    assert.strictEqual(sgEval.json.wsCloseCode, 1013);
    assert.ok(sgEval.json.scrubbedHeaders && sgEval.json.scrubbedHeaders.headers.Upgrade === 'websocket');
    assert.ok(sgEval.json.scrubbedHeaders.headers['Sec-WebSocket-Accept']);
    assert.strictEqual(sgEval.json.scrubbedHeaders.headers['Proxy-Authenticate'], undefined);
    assert.strictEqual(sgEval.json.scrubbedHeaders.headers['Alt-Svc'], undefined);
    assert.strictEqual(sgEval.json.scrubbedHeaders.headers['X-Internal-Hop'], undefined);

    const sgGet = await reqJson(port, 'GET', '/api/edge/stream-guard', { token: master });
    assert.strictEqual(sgGet.status, 200);
    assert.ok(sgGet.json.policyCount >= 1);

    // 4. Zero-Downtime DNS Cutover & Cloudflare Proxy Verifier (/api/domains/cutover/* — coolify#6271)
    const dnsConflict = await reqJson(port, 'POST', '/api/domains/cutover/preflight', {
      token: master,
      body: {
        domain: 'app.c16.example.test',
        targetIpv4: '198.51.100.10',
        challengeMode: 'http-01',
        recordsSnapshot: { a: ['104.21.10.5'], soaSerials: [2026112801, 2026112801] }
      }
    });
    assert.strictEqual(dnsConflict.status, 200, 'POST /domains/cutover/preflight failed: ' + dnsConflict.text);
    assert.strictEqual(dnsConflict.json.ready, false);
    assert.strictEqual(dnsConflict.json.isProxied, true);
    assert.strictEqual(dnsConflict.json.code, 'CLOUDFLARE_PROXY_ACME_CONFLICT');

    const dnsPlan = await reqJson(port, 'POST', '/api/domains/cutover/plan', {
      token: master,
      body: {
        domain: 'app.c16.example.test',
        currentTtlSec: 3600,
        targetTtlSec: 60,
        targetIp: '198.51.100.10',
        acmeMode: 'dns-01',
        nameserverSerials: [2026112801, 2026112801]
      }
    });
    assert.strictEqual(dnsPlan.status, 200);
    assert.strictEqual(dnsPlan.json.ready, true);
    assert.ok(dnsPlan.json.minPreCutoverWaitSec >= 3600);
    assert.strictEqual(dnsPlan.json.phases.length, 5);

    const dnsStatus = await reqJson(port, 'GET', '/api/domains/cutover/status/app.c16.example.test', { token: master });
    assert.strictEqual(dnsStatus.status, 200);
    assert.strictEqual(dnsStatus.json.found, true);

    // 5. Orphaned PR-Preview Auto-Reaper (/api/cleanup/orphans/* — dryRun: true protecting sidecars & DB)
    const dockerSnapshot = {
      containers: [
        { id: 'ctr_pr42', name: 'myapp-pr-42-web', labels: { 'culkibo.managed': 'true', 'culkibo.project': 'myapp', 'culkibo.preview.pr': '42' }, sizeBytes: 52428800 },
        { id: 'ctr_ghost', name: 'preview-shop-a9f2', labels: { 'culkibo.managed': 'true' }, sizeBytes: 10485760 },
        { id: 'ctr_sidecar', name: 'myapp-backup-runner', labels: { 'com.docker.compose.project': 'myapp' }, sizeBytes: 20971520 }
      ],
      volumes: [
        { name: 'app-pr-42-pgdata', labels: { 'culkibo.project': 'myapp', 'culkibo.preview.pr': '42' }, sizeBytes: 104857600 },
        { name: 'prod-pgdata', labels: { 'culkibo.project': 'myapp' }, sizeBytes: 536870912 }
      ],
      images: [
        { id: 'img_sidecar', tag: 'myapp-backup-runner:local', labels: { 'com.docker.compose.project': 'myapp' }, sidecar: true, sizeBytes: 41943040 }
      ]
    };
    const scanRes = await reqJson(port, 'POST', '/api/cleanup/orphans/scan', {
      token: master,
      body: { dockerSnapshot, activeProjects: ['myapp'], activePreviews: [] }
    });
    assert.strictEqual(scanRes.status, 200, 'POST /cleanup/orphans/scan failed: ' + scanRes.text);
    const orphanNames = scanRes.json.orphans.map((o) => o.name);
    const protectedNames = scanRes.json.protected.map((p) => p.name);
    assert.ok(orphanNames.includes('myapp-pr-42-web'));
    assert.ok(orphanNames.includes('preview-shop-a9f2'));
    assert.ok(orphanNames.includes('app-pr-42-pgdata'));
    assert.ok(protectedNames.includes('myapp-backup-runner'));
    assert.ok(protectedNames.includes('prod-pgdata'));
    assert.ok(protectedNames.includes('myapp-backup-runner:local'));

    const reapRes = await reqJson(port, 'POST', '/api/cleanup/orphans/reap', {
      token: master,
      body: { dockerSnapshot, activeProjects: ['myapp'], activePreviews: [] }
    });
    assert.strictEqual(reapRes.status, 200, 'POST /cleanup/orphans/reap failed: ' + reapRes.text);
    assert.strictEqual(reapRes.json.dryRun, true, 'POST /cleanup/orphans/reap MUST default to dryRun: true');
    assert.strictEqual(reapRes.json.executedCount, 0);
    assert.strictEqual(reapRes.json.plannedCount, 3);
    assert.ok(reapRes.json.estimatedReclaimableBytes > 0);

    const polGet = await reqJson(port, 'GET', '/api/cleanup/orphans/policy', { token: master });
    assert.strictEqual(polGet.status, 200);
    assert.strictEqual(polGet.json.policy.dryRunDefault, true);

    // 6. Strict RBAC & Multi-Tenant 403 Enforcement
    const bootOwner = teamManager.bootstrapOwner({ email: 'c16-owner@example.test', password: 'OwnerPassword!2026' });
    const ownerPrincipal = teamManager.verifySessionToken(bootOwner.sessionToken).principal;
    const invViewer = teamManager.createInvite(ownerPrincipal, { email: 'c16-viewer@example.test', role: 'viewer' });
    const accViewer = teamManager.acceptInvite({ token: invViewer.inviteToken, email: 'c16-viewer@example.test', password: 'ViewerPassword!2026', name: 'ViewerC16' });

    const viewerScan = await reqJson(port, 'POST', '/api/cleanup/orphans/scan', {
      token: accViewer.sessionToken,
      body: { dockerSnapshot: {}, activeProjects: [] }
    });
    assert.strictEqual(viewerScan.status, 200, 'Viewer MUST be allowed on POST /cleanup/orphans/scan');

    const viewerReap = await reqJson(port, 'POST', '/api/cleanup/orphans/reap', {
      token: accViewer.sessionToken,
      body: { dockerSnapshot: {} }
    });
    assert.strictEqual(viewerReap.status, 403, 'Viewer MUST get 403 on POST /cleanup/orphans/reap');

    const viewerTrustRoot = await reqJson(port, 'PUT', '/api/supply-chain/trust-roots', {
      token: accViewer.sessionToken,
      body: { id: 'rogue', publicKeyPem: pubPem }
    });
    assert.strictEqual(viewerTrustRoot.status, 403, 'Viewer MUST get 403 on PUT /supply-chain/trust-roots');

    const viewerDnsPlan = await reqJson(port, 'POST', '/api/domains/cutover/plan', {
      token: accViewer.sessionToken,
      body: { domain: 'app.c16.example.test' }
    });
    assert.strictEqual(viewerDnsPlan.status, 403, 'Viewer MUST get 403 on POST /domains/cutover/plan');

    const viewerBaseline = await reqJson(port, 'POST', '/api/contracts/baseline', {
      token: accViewer.sessionToken,
      body: { projectId: 'proj_c16_a', spec: baseOpenApi }
    });
    assert.strictEqual(viewerBaseline.status, 403, 'Viewer MUST get 403 on POST /contracts/baseline');

    const teamB = teamManager.createTeam(ownerPrincipal, { name: 'Tenant B C16' });
    const invDevB = teamManager.createInvite(ownerPrincipal, { email: 'c16-devb@example.test', role: 'developer', teamId: teamB.id });
    const accDevB = teamManager.acceptInvite({ token: invDevB.inviteToken, email: 'c16-devb@example.test', password: 'DevBPassword!2026', name: 'DevBC16' });

    const foreignGate = await reqJson(port, 'POST', '/api/contracts/gate', {
      token: accDevB.sessionToken,
      body: { projectId: 'proj_c16_a', format: 'openapi', revisionSpec: baseOpenApi }
    });
    assert.strictEqual(foreignGate.status, 403, 'Foreign tenant MUST get 403 on /contracts/gate for proj_c16_a');

    const devStreamPolicy = await reqJson(port, 'POST', '/api/edge/stream-guard/policy', {
      token: accDevB.sessionToken,
      body: { projectId: 'proj_c16_a', maxPerIp: 5 }
    });
    assert.strictEqual(devStreamPolicy.status, 403, 'Developer MUST get 403 on admin-only POST /edge/stream-guard/policy');

    console.log('CYCLE16_HTTP_E2E_OK');
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
    assert.ok(out.includes('CYCLE16_HTTP_E2E_OK'), `Cycle-16 HTTP E2E check failed:\n${out}`);
    console.log('  ✓ Post-Optic API Contract Gate (MISSING-VERSION-BUMP 1.4->1.5 block, 2.0.0 major allow, baseline & history) verified over live HTTP');
    console.log('  ✓ Pure-Node OCI/SLSA Rekor Verifier (CVE-2026-22703 REKOR_DIGEST_MISMATCH, Rekor v2 pass, GHCR 404 tlsVerify fallback) verified over live HTTP');
    console.log('  ✓ Edge WS/SSE Flood & 101 Guard (CVE-2026-55458 hop-by-hop scrub, 429/1013 flood block, Caddy stream_close_delay) verified over live HTTP');
    console.log('  ✓ Zero-Downtime DNS Cutover (coolify#6271 CLOUDFLARE_PROXY_ACME_CONFLICT, 5-phase TTL >=3600s plan, status) verified over live HTTP');
    console.log('  ✓ Orphan PR-Preview Auto-Reaper (dryRun: true default, ghost PR/volume flags, Compose sidecar & DB volume protection) verified over live HTTP');
    console.log('  ✓ Strict RBAC & Multi-Tenant 403 Isolation (viewer/dev admin-route blocks + Tenant B 403 on foreign project) verified over live HTTP');
    console.log('✅ Cycle #16 Live Isolated HTTP E2E Suite PASSED!\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  testCycle16HttpE2E()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ Cycle #16 HTTP E2E Suite failed:', err);
      process.exit(1);
    });
}

module.exports = testCycle16HttpE2E;
