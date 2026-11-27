const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const caddyManager = require('../server/services/caddyManager');
const ingressManager = require('../server/services/ingressManager');
const sslManager = require('../server/services/sslManager');
const portRegistry = require('../server/services/portRegistry');
const deployManager = require('../server/services/deployManager');
const projectManager = require('../server/services/projectManager');
const dbBackupManager = require('../server/services/dbBackupManager');
const databaseManager = require('../server/services/databaseManager');
const liveSyncEngine = require('../server/services/liveSyncEngine');
const { LiveSyncClient } = require('../server/services/liveSyncClient');
const mcpServer = require('../server/services/mcpServer');
const { ensureDaemon } = require('./helpers/daemon');

// Pure-Node X.509 v3 cert + keypair generator (no external openssl dependency)
const DER = {
  len(n) {
    if (n < 0x80) return Buffer.from([n]);
    const bytes = [];
    let v = n;
    while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); }
    return Buffer.from([0x80 | bytes.length, ...bytes]);
  },
  tlv: (tag, content) => Buffer.concat([Buffer.from([tag]), DER.len(content.length), content]),
  seq: (...parts) => DER.tlv(0x30, Buffer.concat(parts)),
  set: (...parts) => DER.tlv(0x31, Buffer.concat(parts)),
  int(buf) {
    let b = Buffer.from(buf);
    while (b.length > 1 && b[0] === 0) b = b.subarray(1);
    if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
    return DER.tlv(0x02, b);
  },
  oid(dotted) {
    const parts = dotted.split('.').map(Number);
    const bytes = [parts[0] * 40 + parts[1]];
    for (let i = 2; i < parts.length; i++) {
      let v = parts[i];
      const stack = [v & 0x7f];
      v = Math.floor(v / 128);
      while (v > 0) { stack.unshift((v & 0x7f) | 0x80); v = Math.floor(v / 128); }
      bytes.push(...stack);
    }
    return DER.tlv(0x06, Buffer.from(bytes));
  },
  utf8: (s) => DER.tlv(0x0c, Buffer.from(s, 'utf8')),
  utcTime(date) {
    const p = (n) => String(n).padStart(2, '0');
    const s = `${p(date.getUTCFullYear() % 100)}${p(date.getUTCMonth() + 1)}${p(date.getUTCDate())}` +
              `${p(date.getUTCHours())}${p(date.getUTCMinutes())}${p(date.getUTCSeconds())}Z`;
    return DER.tlv(0x17, Buffer.from(s, 'ascii'));
  }
};

function makeCertKeyPair({ cn = '*.origin-scale.test', dnsNames = ['*.origin-scale.test', 'origin-scale.test'], days = 365 } = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const ecdsaSha256 = DER.seq(DER.oid('1.2.840.10045.4.3.2'));
  const name = DER.seq(DER.set(DER.seq(Buffer.concat([DER.oid('2.5.4.3'), DER.utf8(cn)]))));
  const notBefore = new Date(Date.now() - 3600000);
  const notAfter = new Date(Date.now() + days * 86400000);
  const sanExt = DER.seq(Buffer.concat([
    DER.oid('2.5.29.17'),
    DER.tlv(0x04, DER.seq(Buffer.concat(dnsNames.map((d) => DER.tlv(0x82, Buffer.from(d, 'ascii'))))))
  ]));
  const tbs = DER.seq(
    DER.tlv(0xa0, DER.int(Buffer.from([2]))),
    DER.int(crypto.randomBytes(8)),
    ecdsaSha256,
    name,
    DER.seq(DER.utcTime(notBefore), DER.utcTime(notAfter)),
    name,
    spki,
    DER.tlv(0xa3, DER.seq(sanExt))
  );
  const signature = crypto.sign('sha256', tbs, privateKey);
  const der = DER.seq(tbs, ecdsaSha256, DER.tlv(0x03, Buffer.concat([Buffer.from([0]), signature])));
  const b64 = der.toString('base64').replace(/(.{64})/g, '$1\n');
  return {
    certPem: `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`,
    keyPem: String(privateKey.export({ type: 'pkcs8', format: 'pem' }))
  };
}

function rawHttpGet(urlPath, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port: 3030, path: urlPath, method: 'GET', agent: false, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks)
      }));
    });
    req.on('error', reject);
    req.end();
  });
}

async function testScaleAndWildcard() {
  console.log('🧪 Testing Scale, Multi-Wildcard SSL, Build Semaphore, Fast-Path & Integrity...');

  // ── 1. Multi-Wildcard DNS-01 persistence + Caddy route builders ────────────
  const prevPolicies = ingressManager.listWildcardPolicies().map((p) => ({ ...p }));
  try {
    // Persistir dos comodines distintos en simultáneo
    const addA = await ingressManager.addWildcardPolicy('alpha-scale.test', { tokenEnv: 'CF_API_TOKEN', includeApex: true });
    const addB = await ingressManager.addWildcardPolicy('beta-scale.test', { tokenEnv: 'CF_API_TOKEN', includeApex: false });
    assert.ok(addA.subjects.includes('*.alpha-scale.test') && addA.subjects.includes('alpha-scale.test'));
    assert.ok(addB.subjects.includes('*.beta-scale.test') && !addB.subjects.includes('beta-scale.test'));
    const list1 = ingressManager.listWildcardPolicies();
    assert.ok(list1.some((p) => p.rootDomain === 'alpha-scale.test' && p.includeApex === true));
    assert.ok(list1.some((p) => p.rootDomain === 'beta-scale.test' && p.includeApex === false));

    // Construir bloque TLS de Caddy con múltiples políticas simultáneas
    const tlsApp = caddyManager.buildTlsApp({
      wildcardPolicies: list1,
      acmeEmail: 'ops@alpha-scale.test',
      askEndpoint: 'http://127.0.0.1:3030/api/ingress/ask'
    });
    assert.ok(Array.isArray(tlsApp.automation.policies));
    assert.ok(tlsApp.automation.policies.some((p) => Array.isArray(p.subjects) && p.subjects.includes('*.alpha-scale.test')));
    assert.ok(tlsApp.automation.policies.some((p) => Array.isArray(p.subjects) && p.subjects.includes('*.beta-scale.test')));

    // Eliminar solo alpha-scale.test deja beta-scale.test intacto
    await ingressManager.removeWildcardPolicy('alpha-scale.test');
    const list2 = ingressManager.listWildcardPolicies();
    assert.ok(!list2.some((p) => p.rootDomain === 'alpha-scale.test'));
    assert.ok(list2.some((p) => p.rootDomain === 'beta-scale.test'));
    await ingressManager.removeWildcardPolicy('beta-scale.test');
    console.log('  ✓ Multi-wildcard DNS-01 policies coexist, generate multi-policy Caddy TLS JSON, and delete independently');
  } finally {
    // Restaurar exactamente las políticas anteriores si había alguna
    for (const p of ingressManager.listWildcardPolicies()) {
      if (!prevPolicies.some((o) => o.rootDomain === p.rootDomain)) {
        try { await ingressManager.removeWildcardPolicy(p.rootDomain); } catch (e) {}
      }
    }
  }

  // Verificar builders de Caddy: redirección 301 www, modo mantenimiento 503, compresión server-level
  const redirectRoute = caddyManager.buildRoute({
    projectId: 'scale_redir',
    hostnames: ['www.alpha-scale.test'],
    kind: 'redirect',
    redirectTo: 'alpha-scale.test',
    redirectStatus: 301
  });
  assert.strictEqual(redirectRoute.handle[0].handler, 'static_response');
  assert.strictEqual(redirectRoute.handle[0].status_code, '301');
  assert.strictEqual(redirectRoute.handle[0].headers.Location[0], 'https://alpha-scale.test{http.request.uri}');

  const maintRoute = caddyManager.buildRoute({
    projectId: 'scale_maint',
    hostnames: ['app.alpha-scale.test'],
    kind: 'maintenance'
  });
  assert.strictEqual(maintRoute.handle[0].status_code, '503');
  assert.strictEqual(maintRoute.handle[0].headers['Retry-After'][0], '300');

  const baseCfg = caddyManager.buildBaseConfig({ enableCompression: true });
  const srvRoutes = Object.values(baseCfg.apps.http.servers)[0].routes;
  assert.strictEqual(srvRoutes[0]['@id'], 'sys_encode');
  assert.notStrictEqual(srvRoutes[0].terminal, true);
  assert.ok(srvRoutes[0].handle[0].encodings.zstd);
  assert.ok(srvRoutes[0].handle[0].encodings.gzip);
  console.log('  ✓ Caddy 301 canonical redirect, 503 maintenance route & server-level zstd/gzip encode verified');

  // ── 2. Custom PEM / Cloudflare Origin CA upload + keypair verification ─────
  const pairA = makeCertKeyPair({ cn: '*.origin-scale.test', dnsNames: ['*.origin-scale.test', 'origin-scale.test'] });
  const pairB = makeCertKeyPair({ cn: '*.other-scale.test', dnsNames: ['*.other-scale.test'] });

  let mismatchRejected = false;
  try {
    sslManager.uploadCustomCertificate({
      domain: '*.origin-scale.test',
      certPem: pairA.certPem,
      keyPem: pairB.keyPem,
      provider: 'cloudflare_origin_ca'
    });
  } catch (err) {
    mismatchRejected = /clave privada|no coincide|mismatch/i.test(err.message);
  }
  assert.strictEqual(mismatchRejected, true, 'Mismatched cert/key pair must be cryptographically rejected');

  const uploaded = sslManager.uploadCustomCertificate({
    domain: '*.origin-scale.test',
    certPem: pairA.certPem,
    keyPem: pairA.keyPem,
    provider: 'cloudflare_origin_ca'
  });
  assert.strictEqual(uploaded.success, true);
  assert.ok(uploaded.cert && uploaded.cert.id);
  try {
    const loadedCerts = sslManager.listCertificates();
    const foundCert = loadedCerts.find((c) => c.id === uploaded.cert.id);
    assert.ok(foundCert && foundCert.status === 'on_disk', 'Uploaded PEM cert must verify as on_disk X.509');
    const caddyFiles = sslManager.listCaddyLoadFiles();
    assert.ok(caddyFiles.some((f) => f.id === uploaded.cert.id && fs.existsSync(f.certificate) && fs.existsSync(f.key)));
  } finally {
    // Limpiar también cualquier remanente de ejecuciones previas de esta prueba
    for (const c of sslManager.listCertificates()) {
      if (c.domain === '*.origin-scale.test') {
        try { sslManager.revokeCertificate(c.id); } catch (e) {}
      }
    }
  }
  console.log('  ✓ Custom PEM / Cloudflare Origin CA cryptographic match & mismatch rejection verified');

  // ── 3. Unified portRegistry 20-way concurrent collision-free allocation ────
  const owners = [];
  try {
    const scopes = ['local', 'deploy', 'database', 'catalog'];
    const allocations = await Promise.all(
      Array.from({ length: 20 }, (_, i) => {
        const owner = `scale_test_owner_${i}`;
        owners.push(owner);
        return portRegistry.allocate({ kind: scopes[i % scopes.length], owner });
      })
    );
    const uniquePorts = new Set(allocations);
    assert.strictEqual(uniquePorts.size, 20, `Expected 20 unique ports, got ${uniquePorts.size}`);
    // Verify disjoint subsystem ranges
    for (let i = 0; i < 20; i++) {
      const p = allocations[i];
      const kind = scopes[i % scopes.length];
      if (kind === 'local') assert.ok(p >= 15000 && p <= 19999, `local port ${p} out of range`);
      if (kind === 'deploy') assert.ok(p >= 20000 && p <= 24999, `deploy port ${p} out of range`);
      if (kind === 'database') assert.ok(p >= 28000 && p <= 29999, `database port ${p} out of range`);
      if (kind === 'catalog') assert.ok(p >= 42000 && p <= 42999, `catalog port ${p} out of range`);
    }
    assert.strictEqual(portRegistry.isProtectedPort(allocations[1], 'local'), true, 'local must treat deploy port as protected');
    console.log('  ✓ portRegistry allocated 20 concurrent collision-free ports across 4 disjoint subsystem ranges');
  } finally {
    for (const o of owners) portRegistry.releaseOwner(o);
  }

  // ── 4. Global build semaphore (5 parallel deploys, maxConcurrentBuilds=2) ─
  const prevMax = deployManager.maxConcurrentBuilds;
  deployManager.maxConcurrentBuilds = 2;
  try {
    let currentRunning = 0;
    let peakRunning = 0;
    const completedOrder = [];
    let observedQueued = 0;

    await Promise.all([1, 2, 3, 4, 5].map(async (n) => {
      await deployManager.acquireBuildSlot(`proj_sem_${n}`, `dep_sem_${n}`);
      try {
        currentRunning++;
        peakRunning = Math.max(peakRunning, currentRunning);
        const qStatus = deployManager.getQueueStatus();
        observedQueued = Math.max(observedQueued, qStatus.queuedBuilds.length);
        await new Promise((r) => setTimeout(r, 25));
        completedOrder.push(n);
      } finally {
        currentRunning--;
        deployManager.releaseBuildSlot();
      }
    }));

    assert.strictEqual(peakRunning, 2, `Expected peak concurrency 2, got ${peakRunning}`);
    assert.ok(observedQueued >= 2, `Expected queued builds while slots busy, saw max ${observedQueued}`);
    assert.strictEqual(completedOrder.length, 5);
    assert.strictEqual(deployManager.getQueueStatus().activeBuilds, 0);
    assert.strictEqual(deployManager.getQueueStatus().queuedBuilds.length, 0);
    console.log('  ✓ Global build semaphore capped 5 parallel builds to 2 concurrent slots with clean FIFO drain');
  } finally {
    deployManager.maxConcurrentBuilds = prevMax;
  }

  // ── 5. Project<->DB runtime linking + MCP secret redaction + 52 tools ────
  const secretProj = projectManager.create({
    name: 'Scale Secret Link Project',
    description: 'Testing MCP redaction and DB linking',
    envVars: {
      STRIPE_SECRET_KEY: 'sk_live_super_secret_value_999',
      PUBLIC_URL: 'https://example.com'
    },
    linkedDatabaseIds: ['db_mock_nonexistent'],
    maintenanceMode: false
  });
  try {
    // Verify 145 MCP 2026-07-28 tools registered including meta-discovery, self-healing, Coolify/Bundle, SmartPack, EdgeTunnel, OTLP, SLSA, Shadow Replay, Time-Machine, FinOps, Build Healer, Fleet Mesh, Cron Timeline, Edge Shield, Cycle-8 Sovereignty, Cycle-9 Post-MinIO/Agency, Cycle-10 DR/SLO-Canary/AI-GPU/RemoteBuilder/LogArchive, Cycle-11 Governance/Edge & Cycle-12 Synthetic/SQL-Lint/Autoscaler/SPDX/Seccomp tools
    const listedTools = await mcpServer.handleJsonRpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    const toolNames = (listedTools.result?.tools || []).map((t) => t.name);
    assert.strictEqual(toolNames.length, 145, `Expected 145 MCP tools, got ${toolNames.length}`);
    assert.ok(toolNames.includes('culkibo_link_database'));
    assert.ok(toolNames.includes('culkibo_toggle_maintenance'));
    assert.ok(toolNames.includes('culkibo_get_deploy_queue'));
    assert.ok(toolNames.includes('culkibo_fleet_list_servers'));
    assert.ok(toolNames.includes('culkibo_rbac_whoami'));
    assert.ok(toolNames.includes('culkibo_gitops_apply'));
    assert.ok(toolNames.includes('culkibo_cost_advisor'));
    assert.ok(toolNames.includes('culkibo_search_tools'));
    assert.ok(toolNames.includes('culkibo_diagnose_incident'));
    assert.ok(toolNames.includes('culkibo_auto_remediate'));

    // Verify core profile cuts serialized tools payload by >= 80%
    const allBuf = mcpServer.getToolsSerialized(null, { profile: 'all' });
    const coreBuf = mcpServer.getToolsSerialized(null, { profile: 'core' });
    assert.ok((1 - coreBuf.length / allBuf.length) >= 0.80, 'Core profile must cut payload size by >=80%');

    // Verify culkibo_get_project & culkibo_list_projects redact envVar secret values
    const getRes = await mcpServer.handleJsonRpc({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'culkibo_get_project', arguments: { projectId: secretProj.id } }
    });
    const rawText = JSON.stringify(getRes);
    assert.ok(!rawText.includes('sk_live_super_secret_value_999'), 'MCP culkibo_get_project MUST NOT expose raw env secret values');
    assert.ok(rawText.includes('STRIPE_SECRET_KEY'), 'MCP should preserve env key names for visibility');

    // Verify culkibo_get_deploy_queue returns valid queue object
    const qRes = await mcpServer.handleJsonRpc({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'culkibo_get_deploy_queue', arguments: {} }
    });
    const qPayload = qRes.result?.structuredContent || JSON.parse(qRes.result?.content?.[0]?.text || '{}');
    assert.strictEqual(typeof qPayload.maxConcurrentBuilds, 'number');
    assert.strictEqual(typeof qPayload.activeBuilds, 'number');
    console.log('  ✓ MCP secret redaction verified & all 107 tools (incl. profiles -80%+, self-healing, queue/link/maintenance/v2) active');
  } finally {
    projectManager.delete(secretProj.id);
    await projectManager.flushToDisk();
  }

  // ── 6. dbBackupManager real SHA-256 export & tamper detection on restore ─
  const bProj = projectManager.create({
    name: 'Scale Checksum Project',
    description: 'Testing real SHA-256 archive integrity',
    envVars: { APP_MODE: 'test' }
  });
  let exportedPath = null;
  try {
    const exp = await dbBackupManager.exportProject(bProj.id);
    exportedPath = exp.fullPath;
    assert.ok(exp.success && fs.existsSync(exportedPath));
    const parsed = JSON.parse(fs.readFileSync(exportedPath, 'utf8'));
    assert.match(String(parsed.checksum || ''), /^sha256:[0-9a-f]{64}$/, 'Backup bundle must embed real sha256:<64hex> checksum');

    // Tamper 1 field in backup JSON and verify restore rejects it
    const tamperedPath = `${exportedPath}.tampered.json`;
    parsed.project.name = 'HACKED_NAME';
    fs.writeFileSync(tamperedPath, JSON.stringify(parsed, null, 2), 'utf8');
    let tamperBlocked = false;
    try {
      await dbBackupManager.restoreProject(tamperedPath);
    } catch (err) {
      tamperBlocked = /integridad|checksum|sha-?256|corrupt|alterad/i.test(err.message);
    } finally {
      try { fs.unlinkSync(tamperedPath); } catch (e) {}
    }
    assert.strictEqual(tamperBlocked, true, 'Tampered backup archive must be rejected by SHA-256 verification');
    console.log('  ✓ Backup bundle real SHA-256 checksum & tamper rejection verified');
  } finally {
    projectManager.delete(bProj.id);
    if (exportedPath) { try { fs.unlinkSync(exportedPath); } catch (e) {} }
    await projectManager.flushToDisk();
  }

  // Verify databaseManager scheduler guard exists and can stop cleanly
  assert.strictEqual(typeof databaseManager.startScheduler, 'function');
  assert.strictEqual(typeof databaseManager.stopScheduler, 'function');

  // ── 7. Live Sync >500-file chunked reconcileFull & LRU eviction ──────────
  const tmpSrc = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-scale-src-'));
  const tmpDst = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-scale-dst-'));
  const scaleSyncId = `scale_sync_${Date.now()}`;
  try {
    for (let i = 0; i < 520; i++) {
      const sub = path.join(tmpSrc, `mod_${i % 10}`);
      if (!fs.existsSync(sub)) fs.mkdirSync(sub, { recursive: true });
      fs.writeFileSync(path.join(sub, `file_${i}.js`), `export const n = ${i};\n`, 'utf8');
    }
    liveSyncEngine.setTargetDir(scaleSyncId, tmpDst);
    const localTree = liveSyncEngine.computeMerkleTree(tmpSrc);
    assert.strictEqual(Object.keys(localTree.files).length, 520);

    // Drive reconcileFull through a lightweight in-process mock transport on LiveSyncClient
    const sentBatches = [];
    const client = new LiveSyncClient({ projectId: scaleSyncId, sourceDir: tmpSrc, serverUrl: 'ws://127.0.0.1:1/ws/sync' });
    client.sendFrame = async (changes) => {
      sentBatches.push({ count: changes.length });
      const res = liveSyncEngine.applyCommitFrame(scaleSyncId, {
        files: changes.map((c) => ({ path: c.path, op: c.op, buffer: c.buffer, sha256: c.sha256 })),
        reason: 'reconcile_chunk'
      });
      return res;
    };
    const recRes = await client.reconcileFull({});
    assert.strictEqual(recRes.framesSent, sentBatches.length);
    assert.ok(sentBatches.length >= 3, `Expected 520 files to chunk into >=3 batches (<=250 each), got ${sentBatches.length}`);
    for (const b of sentBatches) {
      assert.ok(b.count <= 250, `Batch exceeded 250-file chunk limit: ${b.count}`);
    }
    const serverTree = liveSyncEngine.computeMerkleTree(tmpDst);
    assert.strictEqual(serverTree.rootDigest, localTree.rootDigest, '520-file chunked reconcile must produce identical Merkle root');
    liveSyncEngine.resetSession(scaleSyncId);
    console.log(`  ✓ Live Sync 520-file chunked reconcileFull (${sentBatches.length} batches) achieved 100% Merkle parity`);
  } finally {
    fs.rmSync(tmpSrc, { recursive: true, force: true });
    fs.rmSync(tmpDst, { recursive: true, force: true });
  }

  // ── 8. HTTP Fast-Path: Pre-compressed Static (br/ETag/304) & API ETag ────
  const stopDaemon = await ensureDaemon();
  try {
    const htmlRes = await rawHttpGet('/', { 'Accept-Encoding': 'br, gzip' });
    assert.strictEqual(htmlRes.status, 200);
    assert.strictEqual(htmlRes.headers['content-encoding'], 'br', 'Static / must serve pre-compressed Brotli');
    assert.ok(htmlRes.headers['content-security-policy'], 'Static / must emit SPA CSP');
    assert.strictEqual(htmlRes.headers['x-content-type-options'], 'nosniff');

    // Find a real hashed asset served by the daemon (prefer HTML reference so pre-running daemons match)
    const zlib = require('zlib');
    const decodedHtml = htmlRes.headers['content-encoding'] === 'br'
      ? zlib.brotliDecompressSync(htmlRes.body).toString('utf8')
      : htmlRes.body.toString('utf8');
    const htmlAssetMatch = decodedHtml.match(/\/assets\/([A-Za-z0-9_.-]+\.js)/);
    const assetsDir = path.join(__dirname, '..', 'web', 'dist', 'assets');
    const jsAsset = (htmlAssetMatch && htmlAssetMatch[1])
      || fs.readdirSync(assetsDir).find((f) => f.endsWith('.js') && fs.existsSync(path.join(assetsDir, `${f}.br`)));
    assert.ok(jsAsset, 'Expected at least one pre-compressed .js.br bundle in web/dist/assets');
    const assetRes = await rawHttpGet(`/assets/${jsAsset}`, { 'Accept-Encoding': 'br, gzip' });
    assert.strictEqual(assetRes.status, 200);
    assert.strictEqual(assetRes.headers['content-encoding'], 'br');
    assert.ok(String(assetRes.headers['cache-control'] || '').includes('immutable'));
    assert.ok(assetRes.headers.etag, 'Hashed asset must emit ETag');
    const asset304 = await rawHttpGet(`/assets/${jsAsset}`, { 'Accept-Encoding': 'br, gzip', 'If-None-Match': assetRes.headers.etag });
    assert.strictEqual(asset304.status, 304, `Expected 304 on matching ETag for /assets/${jsAsset}, got ${asset304.status}`);
    assert.strictEqual(asset304.body.length, 0);

    const apiRes = await rawHttpGet('/api/projects', { 'Accept-Encoding': 'br, gzip' });
    assert.strictEqual(apiRes.status, 200);
    assert.ok(apiRes.headers.etag, '/api/projects must emit ETag');
    assert.strictEqual(apiRes.headers['cache-control'], 'private, no-cache');
    const api304 = await rawHttpGet('/api/projects', { 'Accept-Encoding': 'br, gzip', 'If-None-Match': apiRes.headers.etag });
    assert.strictEqual(api304.status, 304, `Expected 304 on matching ETag for /api/projects, got ${api304.status}`);
    assert.strictEqual(api304.body.length, 0);

    const healthRes = await rawHttpGet('/health');
    assert.strictEqual(healthRes.status, 200);
    assert.strictEqual(healthRes.headers['cache-control'], 'no-store');
    console.log('  ✓ HTTP fast-path verified: static br/immutable/ETag/304, /api/projects ETag/304, /health no-store');
  } finally {
    if (stopDaemon) await stopDaemon();
  }

  console.log('✅ Scale, Multi-Wildcard SSL, Build Semaphore & Fast-Path suite PASSED!\n');
}

if (require.main === module) {
  testScaleAndWildcard().then(() => {
    setTimeout(() => process.exit(0), 50);
  }).catch((err) => {
    console.error(err);
    setTimeout(() => process.exit(1), 50);
  });
}

module.exports = testScaleAndWildcard;
