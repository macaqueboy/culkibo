const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  FleetMeshService,
  MESH_CIDR,
  generateWireGuardKeyPair,
  renderWgConfig,
  renderFirewallPlan,
  decryptPrivateKey
} = require('../server/services/fleetMeshService');
const { BuildHealerService, FAILURE_PATTERNS } = require('../server/services/buildHealerService');
const { ProjectManager } = require('../server/services/projectManager');

/**
 * Suite Cycle #7: Zero-Config Fleet WireGuard Mesh (`x25519` + AES-256-GCM)
 * and 20-Pattern Deterministic Build & Runtime Auto-Healer.
 *
 * Runs 100% isolated inside `os.tmpdir()` — ZERO mutations to live `data/`.
 */
async function runTests() {
  console.log('--- Iniciando Tests de WireGuard Fleet Mesh (x25519) y Build Auto-Healer (20 patrones) ---');

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mesh-healer-'));
  const dataDir = path.join(tmpRoot, 'data');
  fs.mkdirSync(dataDir, { recursive: true });

  const pm = new ProjectManager({ dataPath: path.join(dataDir, 'projects.json'), seedDefaults: false });
  const mesh = new FleetMeshService({ dataDir });
  const healer = new BuildHealerService({ projectManager: pm });

  let passed = 0;
  const runCase = async (name, fn) => {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  };

  try {
    // =========================================================================
    // 1. REAL X25519 WIREGUARD KEYPAIR GENERATION
    // =========================================================================
    await runCase('1. generateWireGuardKeyPair() emits real 32-byte x25519 44-char base64 keys', async () => {
      assert.strictEqual(MESH_CIDR, '10.88.0.0/24');
      const kp1 = generateWireGuardKeyPair();
      const kp2 = generateWireGuardKeyPair();

      assert.strictEqual(kp1.algorithm, 'x25519');
      assert.strictEqual(kp1.privateKey.length, 44);
      assert.strictEqual(kp1.publicKey.length, 44);
      assert.ok(kp1.privateKey.endsWith('='));
      assert.ok(kp1.publicKey.endsWith('='));
      assert.strictEqual(Buffer.from(kp1.privateKey, 'base64').length, 32);
      assert.strictEqual(Buffer.from(kp1.publicKey, 'base64').length, 32);
      assert.notStrictEqual(kp1.privateKey, kp1.publicKey);
      assert.notStrictEqual(kp1.publicKey, kp2.publicKey);
      assert.ok(kp1.fingerprint.startsWith('wg:'));
    });

    // =========================================================================
    // 2. DETERMINISTIC 10.88.0.X ALLOCATION & AES-256-GCM AT-REST ENCRYPTION
    // =========================================================================
    await runCase('2. FleetMeshService assigns deterministic 10.88.0.x IPs & encrypts all private keys AES-256-GCM', async () => {
      const fleet = [
        { id: 'local', name: 'Local Server (Primary)', host: '127.0.0.1', isLocal: true, status: 'online' },
        { id: 'worker-eu-1', name: 'EU Worker 1', host: '198.51.100.11', status: 'online' },
        { id: 'worker-us-2', name: 'US Worker 2', host: '203.0.113.22', status: 'online' }
      ];

      const status = mesh.getStatus(fleet);
      assert.strictEqual(status.ok, true);
      assert.strictEqual(status.cidr, '10.88.0.0/24');
      assert.strictEqual(status.interfaceName, 'wg0');
      assert.strictEqual(status.peerCount, 3);
      assert.strictEqual(status.firewallGuard.blocksPublicDbPorts, true);

      const pLocal = status.peers.find((p) => p.nodeId === 'local');
      const pEu = status.peers.find((p) => p.nodeId === 'worker-eu-1');
      const pUs = status.peers.find((p) => p.nodeId === 'worker-us-2');
      assert.strictEqual(pLocal.meshIp, '10.88.0.1');
      assert.strictEqual(pLocal.role, 'control-plane');
      assert.strictEqual(pEu.meshIp, '10.88.0.2');
      assert.strictEqual(pEu.endpoint, '198.51.100.11:51820');
      assert.strictEqual(pUs.meshIp, '10.88.0.3');

      // Verify ZERO plaintext private keys in API JSON and AES-256-GCM ciphertext on disk!
      const statusJson = JSON.stringify(status);
      assert.ok(!statusJson.includes('encryptedPrivateKey'), 'API status must not leak encryptedPrivateKey blob');
      assert.ok(!statusJson.includes('privateKey":'), 'API status must never include plaintext privateKey');
      for (const peer of status.peers) {
        assert.strictEqual(peer.privateKeyEncrypted, true);
        assert.strictEqual(peer.publicKey.length, 44);
      }

      const rawDisk = JSON.parse(fs.readFileSync(path.join(dataDir, 'fleet-mesh.json'), 'utf8'));
      const rawDiskStr = fs.readFileSync(path.join(dataDir, 'fleet-mesh.json'), 'utf8');
      const masterKey = Buffer.from(fs.readFileSync(path.join(dataDir, '.fleet-mesh.key'), 'utf8').trim(), 'hex');
      assert.strictEqual(masterKey.length, 32);

      for (const nodeId of ['local', 'worker-eu-1', 'worker-us-2']) {
        const enc = rawDisk.peers[nodeId].encryptedPrivateKey;
        assert.ok(typeof enc === 'string' && enc.startsWith('v1:'), `Expected AES-256-GCM v1 blob for ${nodeId}`);
        const decrypted = decryptPrivateKey(enc, masterKey, nodeId);
        assert.strictEqual(decrypted.length, 44);
        assert.strictEqual(Buffer.from(decrypted, 'base64').length, 32);
        assert.ok(!rawDiskStr.includes(decrypted), `Plaintext private key leaked in fleet-mesh.json for ${nodeId}`);
        assert.ok(!statusJson.includes(decrypted), `Plaintext private key leaked in getStatus() for ${nodeId}`);
        // Wrong AAD must fail GCM auth tag verification!
        assert.throws(() => decryptPrivateKey(enc, masterKey, 'wrong-node-id'));
      }

      // Reload from disk in fresh instance: deterministic IPs & public keys MUST persist
      const meshReloaded = new FleetMeshService({ dataDir });
      const status2 = meshReloaded.getStatus(fleet);
      assert.strictEqual(status2.peers.find((p) => p.nodeId === 'worker-eu-1').meshIp, '10.88.0.2');
      assert.strictEqual(status2.peers.find((p) => p.nodeId === 'worker-eu-1').publicKey, pEu.publicKey);
    });

    // =========================================================================
    // 3. WG0.CONF + UFW/NFTABLES FIREWALL PLAN & TOPOLOGY DIFF + KEY ROTATION
    // =========================================================================
    await runCase('3. planMesh() renders redacted wg0.conf + UFW/nftables guard & rotatePeerKey() respects dryRun', async () => {
      const expandedFleet = [
        { id: 'local', name: 'Local Server (Primary)', host: '127.0.0.1', isLocal: true, status: 'online' },
        { id: 'worker-eu-1', name: 'EU Worker 1 (Upgraded)', host: '198.51.100.11', status: 'online' },
        { id: 'worker-ap-3', name: 'AP Worker 3', host: '198.51.100.33', status: 'online' }
      ];

      const plan = mesh.planMesh(expandedFleet, { dryRun: true });
      assert.strictEqual(plan.ok, true);
      assert.strictEqual(plan.dryRun, true);
      assert.deepStrictEqual(plan.diff.added, ['worker-ap-3']);
      assert.deepStrictEqual(plan.diff.updated, ['worker-eu-1']);
      assert.deepStrictEqual(plan.diff.removed, ['worker-us-2']);
      assert.strictEqual(plan.wgConfigs.length, 3);

      const euCfg = plan.wgConfigs.find((c) => c.nodeId === 'worker-eu-1').config;
      assert.ok(euCfg.includes('[Interface]'));
      assert.ok(euCfg.includes('Address = 10.88.0.2/24'));
      assert.ok(euCfg.includes('ListenPort = 51820'));
      assert.ok(euCfg.includes('PrivateKey = [REDACT_ON_API]'));
      assert.ok(euCfg.includes('AllowedIPs = 10.88.0.1/32'));
      assert.ok(euCfg.includes('Endpoint = 198.51.100.33:51820'));

      // Firewall plan cures kamal#1856 (allows 51820/udp + mesh DB ports, denies public 0.0.0.0 DB ports)
      assert.strictEqual(plan.firewallPlan.blocksPublicDbPorts, true);
      assert.ok(plan.firewallPlan.ufwRules.some((r) => r.includes('allow 51820/udp')));
      assert.ok(plan.firewallPlan.ufwRules.some((r) => r.includes('on wg0 from 10.88.0.0/24') && r.includes('5432')));
      assert.ok(plan.firewallPlan.ufwRules.some((r) => r.includes('deny 5432/tcp')));
      assert.ok(plan.firewallPlan.nftablesSnippet.includes('iifname "wg0" ip saddr 10.88.0.0/24'));

      // Pure helper smoke check
      const directCfg = renderWgConfig({ nodeId: 'a', name: 'A', meshIp: '10.88.0.1', publicKey: 'k1' }, []);
      assert.ok(directCfg.includes('PrivateKey = [REDACT_ON_API]'));
      assert.strictEqual(renderFirewallPlan().listenPort, 51820);

      // Dry-run key rotation MUST NOT mutate stored key
      const beforeKey = mesh.getStatus().peers.find((p) => p.nodeId === 'worker-eu-1').publicKey;
      const dryRot = mesh.rotatePeerKey('worker-eu-1', { dryRun: true });
      assert.strictEqual(dryRot.ok, true);
      assert.strictEqual(dryRot.dryRun, true);
      assert.strictEqual(dryRot.rotated, false);
      assert.strictEqual(dryRot.oldPublicKey, beforeKey);
      assert.notStrictEqual(dryRot.previewNewPublicKey, beforeKey);
      assert.strictEqual(mesh.getStatus().peers.find((p) => p.nodeId === 'worker-eu-1').publicKey, beforeKey);

      // Apply key rotation (`dryRun: false`) updates public key + increments keyVersion + keeps private key encrypted!
      const realRot = mesh.rotatePeerKey('worker-eu-1', { dryRun: false });
      assert.strictEqual(realRot.ok, true);
      assert.strictEqual(realRot.dryRun, false);
      assert.strictEqual(realRot.rotated, true);
      assert.strictEqual(realRot.keyVersion, 2);
      assert.strictEqual(realRot.oldPublicKey, beforeKey);
      assert.notStrictEqual(realRot.newPublicKey, beforeKey);
      assert.strictEqual(mesh.getStatus().peers.find((p) => p.nodeId === 'worker-eu-1').publicKey, realRot.newPublicKey);
      assert.ok(!JSON.stringify(realRot).includes('privateKey":'));
    });

    // =========================================================================
    // 4. BUILD AUTO-HEALER: ALL 20 DETERMINISTIC FAILURE PATTERNS
    // =========================================================================
    await runCase('4. BuildHealerService accurately diagnoses all 20 production failure patterns (0 LLM)', async () => {
      assert.strictEqual(FAILURE_PATTERNS.length, 20);
      assert.strictEqual(new Set(FAILURE_PATTERNS.map((p) => p.code)).size, 20);

      const samples = [
        ['NODE_HEAP_OOM', 'FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory'],
        ['CONTAINER_BIND_LOCALHOST', 'Server started and listening on http://127.0.0.1:3000'],
        ['DOCKER_LOG_OPT_DRIVER_MISMATCH', "docker: Error response from daemon: unknown log opt 'max-size' for journald log driver."],
        ['NPM_CI_LOCKFILE_DRIFT', 'npm error `npm ci` can only install packages when your package.json and package-lock.json or npm-shrinkwrap.json are in sync.'],
        ['NEXTJS_MISSING_STANDALONE', "Error: Cannot find module './server.js' in /app"],
        ['NATIVE_BUILD_TOOLCHAIN_MISSING', 'gyp ERR! stack Error: not found: python3'],
        ['PORT_EADDRINUSE', 'Error: listen EADDRINUSE: address already in use :::3000'],
        ['POSTGRES_PG_WAL_BLOAT', 'PANIC: could not write to file "pg_wal/xlogtemp.123": No space left on device'],
        ['POSTGRES_MAX_CONNECTIONS', 'FATAL:  sorry, too many clients already'],
        ['ALPINE_MUSL_BINARY_MISMATCH', 'Error relocating /app/node_modules/sharp/lib.node: fcntl64: symbol not found'],
        ['DOCKER_HUB_RATE_LIMIT', 'ERROR: toomanyrequests: You have reached your pull rate limit. You may increase the limit by authenticating'],
        ['PYTHON_PEP668_EXTERNALLY_MANAGED', 'error: externally-managed-environment (PEP 668)'],
        ['MISSING_PACKAGE_JSON', "npm error ENOENT: no such file or directory, open '/app/package.json'"],
        ['OOM_KILLED_EXIT_137', 'The command "/bin/sh -c npm run build" exited with code 137 (OOMKilled)'],
        ['TLS_CERT_VERIFY_FAILED', 'FetchError: request failed, reason: UNABLE_TO_VERIFY_LEAF_SIGNATURE'],
        ['RUST_LINKER_OOM', 'error: could not compile `api` (bin "api") (signal: 9, SIGKILL: kill)'],
        ['GO_CGO_DYNAMIC_LINK', 'exec /app/server: no such file or directory'],
        ['DISK_SPACE_EXHAUSTED', 'failed to register layer: write /usr/lib/node: no space left on device'],
        ['HEALTHCHECK_PORT_MISMATCH', 'healthcheck failed on port 8080: connect ECONNREFUSED 127.0.0.1:8080'],
        ['ENV_MISSING_REQUIRED_VAR', 'Error: DATABASE_URL is not defined in process.env']
      ];

      for (const [expectedCode, sampleLog] of samples) {
        const res = healer.diagnoseLogs(sampleLog);
        assert.strictEqual(res.ok, true);
        assert.strictEqual(res.matched, true, `Pattern ${expectedCode} failed to match sample log`);
        assert.strictEqual(res.primary.code, expectedCode, `Expected ${expectedCode}, got ${res.primary.code}`);
        assert.ok(res.primary.confidence >= 0.9);
        assert.ok(res.primary.patchPreview.length > 10);
        assert.ok(res.analyzedMs < 50);
      }

      // Healthy logs return matched: false cleanly
      const clean = healer.diagnoseLogs('✓ Build succeeded in 1.2s\nListening on 0.0.0.0:3000\nHTTP 200 /health');
      assert.strictEqual(clean.matched, false);
      assert.strictEqual(clean.totalMatches, 0);
      assert.strictEqual(clean.primary, null);
    });

    // =========================================================================
    // 5. APPLY HEALING PLAN: DRY-RUN VS SAFE NON-DESTRUCTIVE APPLY
    // =========================================================================
    await runCase('5. applyHealingPlan() previews safely on dryRun=true and patches project metadata on dryRun=false', async () => {
      const proj = pm.create({
        id: 'proj_oom_next',
        name: 'NextJS Storefront',
        memoryMb: 512,
        envVars: { NODE_ENV: 'production' }
      });

      const oomLog = 'Creating an optimized production build...\nFATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory';

      // Dry-run MUST NOT mutate ProjectManager!
      const dryPlan = await healer.applyHealingPlan(proj.id, { logs: oomLog, dryRun: true });
      assert.strictEqual(dryPlan.ok, true);
      assert.strictEqual(dryPlan.dryRun, true);
      assert.strictEqual(dryPlan.applied, false);
      assert.strictEqual(dryPlan.patchPlan.code, 'NODE_HEAP_OOM');
      assert.strictEqual(dryPlan.patchPlan.envAdditions.NODE_OPTIONS, '--max-old-space-size=1536');
      assert.strictEqual(dryPlan.patchPlan.memoryLimitMb, 2048);
      assert.strictEqual(pm.getById(proj.id).memoryMb, 512, 'dryRun must NOT mutate memoryMb');
      assert.strictEqual(pm.getById(proj.id).envVars.NODE_OPTIONS, undefined, 'dryRun must NOT mutate envVars');

      // Apply (`dryRun: false`) merges safe envVars + bumps memoryMb while preserving NODE_ENV!
      const applied = await healer.applyHealingPlan(proj.id, { logs: oomLog, dryRun: false });
      assert.strictEqual(applied.ok, true);
      assert.strictEqual(applied.dryRun, false);
      assert.strictEqual(applied.applied, true);
      assert.ok(applied.appliedFields.includes('envVars'));
      assert.ok(applied.appliedFields.includes('memoryMb'));
      const updatedProj = pm.getById(proj.id);
      assert.strictEqual(updatedProj.memoryMb, 2048);
      assert.strictEqual(updatedProj.envVars.NODE_ENV, 'production');
      assert.strictEqual(updatedProj.envVars.NODE_OPTIONS, '--max-old-space-size=1536');

      // Explicit pattern code lookup (`DOCKER_LOG_OPT_DRIVER_MISMATCH`)
      const logDriverPlan = await healer.applyHealingPlan(proj.id, {
        code: 'DOCKER_LOG_OPT_DRIVER_MISMATCH',
        dryRun: true
      });
      assert.strictEqual(logDriverPlan.patchPlan.logDriver, 'json-file');
    });

    console.log(`\n✅ WireGuard Fleet Mesh & 20-Pattern Build Auto-Healer Suite: ${passed}/5 tests PASSED!`);
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ Mesh & Healer test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
