const assert = require('assert');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

const fleetSingleton = require('../server/services/serverFleetManager');
const { ServerFleetManager, LOCAL_SERVER_ID, PROBE_CMD, helpers } = fleetSingleton;

/**
 * Generates a realistic RFC 4253 `ssh-ed25519` public key line (pure Node, no external binaries).
 * @param {string} [comment]
 */
function makeFakeEd25519PubKey(comment = 'test@culkibo') {
  const typeBuf = Buffer.from('ssh-ed25519', 'ascii');
  const keyBytes = crypto.randomBytes(32);
  const typeLen = Buffer.alloc(4);
  typeLen.writeUInt32BE(typeBuf.length, 0);
  const keyLen = Buffer.alloc(4);
  keyLen.writeUInt32BE(keyBytes.length, 0);
  const blob = Buffer.concat([typeLen, typeBuf, keyLen, keyBytes]);
  const b64 = blob.toString('base64');
  const line = `ssh-ed25519 ${b64} ${comment}`;
  const fp = helpers.computeSshFingerprint(line).fingerprint;
  return { line, b64, keyType: 'ssh-ed25519', fingerprint: fp };
}

/**
 * Generates a synthetic OpenSSH private key block for deterministic tests.
 * @param {string} [tag]
 */
function makeFakePrivatePem(tag = 'TEST') {
  const body = crypto.randomBytes(96).toString('base64');
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${tag}_${body}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

/**
 * Creates an isolated temp workspace for a test block.
 */
function createTempDir(prefix = 'culkibo-fleet-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function rmDirSafe(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) {}
}

/**
 * Creates a fake SSH tunnel child process that actually binds a local TCP or Unix socket
 * matching the `-L` argument passed to `ssh`, so real endpoint polling is exercised.
 */
function createFakeTunnelSpawner(opts = {}) {
  const spawns = [];
  const spawnFn = (bin, args, spawnOpts) => {
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.killed = false;
    child.pid = 50000 + spawns.length;
    child.exitCode = null;

    let server = null;
    const record = { bin, args: [...args], spawnOpts, child, server: null };
    spawns.push(record);

    child.kill = (sig = 'SIGTERM') => {
      if (child.killed) return true;
      child.killed = true;
      const finish = () => {
        child.exitCode = 0;
        child.emit('exit', 0, sig);
        child.emit('close', 0, sig);
      };
      if (server) {
        try { server.close(() => finish()); } catch (e) { finish(); }
      } else {
        setImmediate(finish);
      }
      return true;
    };

    if (opts.failWithHostKeyMismatch) {
      setTimeout(() => {
        child.stderr.emit('data', Buffer.from('@@@@@@@@@@@@@@@@@@@@\nREMOTE HOST IDENTIFICATION HAS CHANGED!\nHost key verification failed.\n'));
        child.exitCode = 255;
        child.emit('exit', 255, null);
      }, 15);
      return child;
    }

    // Parse -L spec: either `127.0.0.1:<localPort>:<remote>` or `<localSock>:<remote>`
    const lIdx = args.indexOf('-L');
    const lSpec = lIdx !== -1 ? args[lIdx + 1] : '';
    const tcpMatch = /^127\.0\.0\.1:(\d+):/.exec(lSpec);

    const delayMs = opts.connectDelayMs ?? 15;
    setTimeout(() => {
      if (child.killed) return;
      if (tcpMatch) {
        const port = parseInt(tcpMatch[1], 10);
        server = net.createServer((sock) => sock.end());
        server.unref();
        record.server = server;
        server.listen(port, '127.0.0.1');
      } else if (lSpec) {
        // POSIX unix socket path before the first colon (skipping Windows drive letters)
        const colonIdx = lSpec.indexOf(':');
        const sockPath = colonIdx > 0 ? lSpec.slice(0, colonIdx) : '';
        if (sockPath && process.platform !== 'win32') {
          server = net.createServer((sock) => sock.end());
          server.unref();
          record.server = server;
          server.listen(sockPath);
        }
      }
    }, delayMs);

    return child;
  };

  return { spawns, spawnFn };
}

async function testFleet() {
  console.log('🧪 Testing Multi-Server Fleet SSH Orchestration (serverFleetManager.js)...');

  // Verify singleton does NOT start any timers on require()
  assert.strictEqual(fleetSingleton._monitorRunning, false, 'Singleton must not start background monitor on require()');
  assert.strictEqual(fleetSingleton._monitorTimer, null, 'Singleton must have no timer armed on require()');

  // -------------------------------------------------------------------------
  // 1. AES-256-GCM Crypto, AAD Binding, Tamper Rejection & Anti-Key-Loss Guard
  // -------------------------------------------------------------------------
  {
    const masterKey = crypto.randomBytes(32);
    const pem = makeFakePrivatePem('VAULT');
    const enc = helpers.encryptPrivateKey(pem, 'fk_key1', masterKey);
    assert.ok(enc.startsWith('v1:'), 'Ciphertext must use v1: prefix');
    assert.strictEqual(helpers.decryptPrivateKey(enc, 'fk_key1', masterKey), pem, 'Roundtrip decrypt must match');

    // Wrong keyId (AAD mismatch / ciphertext swap between keys) must throw
    assert.throws(
      () => helpers.decryptPrivateKey(enc, 'fk_key2', masterKey),
      (err) => err && err.code === 'CRYPTO_DECRYPT_FAILED',
      'AAD mismatch (different keyId) must fail decryption'
    );

    // Tampered ciphertext byte must throw
    const parts = enc.split(':');
    const ctBuf = Buffer.from(parts[3], 'base64');
    ctBuf[0] ^= 0xff;
    const tamperedCt = `${parts[0]}:${parts[1]}:${parts[2]}:${ctBuf.toString('base64')}`;
    assert.throws(
      () => helpers.decryptPrivateKey(tamperedCt, 'fk_key1', masterKey),
      (err) => err && err.code === 'CRYPTO_DECRYPT_FAILED',
      'Tampered ciphertext must fail authentication tag'
    );

    // Tampered authTag must throw
    const tagBuf = Buffer.from(parts[2], 'base64');
    tagBuf[0] ^= 0x01;
    const tamperedTag = `${parts[0]}:${parts[1]}:${tagBuf.toString('base64')}:${parts[3]}`;
    assert.throws(
      () => helpers.decryptPrivateKey(tamperedTag, 'fk_key1', masterKey),
      (err) => err && err.code === 'CRYPTO_DECRYPT_FAILED',
      'Tampered authTag must fail'
    );

    // Plaintext fallback MUST NOT exist for private keys
    assert.throws(
      () => helpers.decryptPrivateKey(pem, 'fk_key1', masterKey),
      (err) => err && err.code === 'CRYPTO_DECRYPT_FAILED',
      'Plaintext blobs must be rejected (no legacy plaintext fallback)'
    );

    // Anti-key-loss guard: deleting .fleet.key while fleet-keys.json has "v1: must throw FLEET_KEY_MISSING
    const dir = createTempDir();
    try {
      const pub = makeFakeEd25519PubKey();
      const fakeExec = async (bin, args) => {
        if (bin === 'ssh-keygen' && args.includes('-t')) {
          const fIdx = args.indexOf('-f');
          const outPath = args[fIdx + 1];
          fs.writeFileSync(outPath, makeFakePrivatePem('ANTILOSS'), { mode: 0o600 });
          fs.writeFileSync(`${outPath}.pub`, `${pub.line}\n`, { mode: 0o600 });
          return { stdout: '', stderr: '' };
        }
        throw new Error(`Unexpected execFile: ${bin}`);
      };

      const mgr1 = new ServerFleetManager({ dataDir: dir, _execFile: fakeExec, autoMonitor: false });
      const k1 = await mgr1.generateKeyPair({ name: 'prod-key', teamId: 'team_alpha' });
      assert.ok(fs.existsSync(path.join(dir, '.fleet.key')), '.fleet.key must be created');
      assert.strictEqual(k1.fingerprint, pub.fingerprint);
      assert.strictEqual(k1.privateKeyEnc, undefined, 'Sanitized key must never expose privateKeyEnc');
      assert.ok(!JSON.stringify(k1).includes('PRIVATE KEY'), 'Sanitized key must never contain private PEM');

      // Delete .fleet.key while encrypted fleet-keys.json exists
      fs.unlinkSync(path.join(dir, '.fleet.key'));
      const mgr2 = new ServerFleetManager({ dataDir: dir, _execFile: fakeExec, autoMonitor: false });
      await assert.rejects(
        () => mgr2.withEphemeralKey(k1.id, async () => {}),
        (err) => err && err.code === 'FLEET_KEY_MISSING',
        'Missing .fleet.key with encrypted fleet-keys.json must trigger anti-key-loss guard'
      );
      assert.strictEqual(fs.existsSync(path.join(dir, '.fleet.key')), false, 'Anti-key-loss guard must NOT regenerate .fleet.key');

      // Corrupt .fleet.key must throw FLEET_KEY_CORRUPT and never regenerate
      fs.writeFileSync(path.join(dir, '.fleet.key'), 'not-valid-hex', 'utf8');
      const mgr3 = new ServerFleetManager({ dataDir: dir, _execFile: fakeExec, autoMonitor: false });
      await assert.rejects(
        () => mgr3.withEphemeralKey(k1.id, async () => {}),
        (err) => err && err.code === 'FLEET_KEY_CORRUPT',
        'Corrupt .fleet.key must throw FLEET_KEY_CORRUPT'
      );
    } finally {
      rmDirSafe(dir);
    }
    console.log('  ✓ AES-256-GCM AAD binding, tamper rejection & anti-key-loss guard');
  }

  // -------------------------------------------------------------------------
  // 2. Ephemeral Key Materialization, Zero-Wipe & Startup .fleet-tmp Sweep
  // -------------------------------------------------------------------------
  {
    const dir = createTempDir();
    try {
      const tmpDir = path.join(dir, '.fleet-tmp');
      fs.mkdirSync(tmpDir, { recursive: true, mode: 0o700 });
      const orphanFile = path.join(tmpDir, 'k_deadbeef00001111');
      fs.writeFileSync(orphanFile, 'SENSITIVE_LEFTOVER_KEY', 'utf8');

      // Constructor must sweep stale files in .fleet-tmp immediately on boot
      const pub = makeFakeEd25519PubKey();
      const secretPem = makeFakePrivatePem('EPHEMERAL_SECRET');
      const fakeExec = async (bin, args) => {
        if (bin === 'ssh-keygen' && args.includes('-y')) {
          return { stdout: `${pub.line}\n`, stderr: '' };
        }
        throw new Error(`Unexpected execFile: ${bin}`);
      };

      const mgr = new ServerFleetManager({ dataDir: dir, _execFile: fakeExec, autoMonitor: false });
      assert.strictEqual(fs.existsSync(orphanFile), false, 'Startup sweep must wipe and unlink orphaned files in .fleet-tmp');

      const imported = await mgr.importKey({ name: 'imported-ed25519', privateKeyPem: secretPem });
      assert.strictEqual(imported.fingerprint, pub.fingerprint);

      let seenKeyPath = '';
      await assert.rejects(
        () => mgr.withEphemeralKey(imported.id, async (keyFile) => {
          seenKeyPath = keyFile;
          assert.ok(fs.existsSync(keyFile), 'Ephemeral key must exist inside callback');
          assert.ok(fs.readFileSync(keyFile, 'utf8').includes('EPHEMERAL_SECRET'));
          throw new Error('simulated failure');
        }),
        /simulated failure/
      );
      assert.ok(seenKeyPath && !fs.existsSync(seenKeyPath), 'Ephemeral key must be wiped & unlinked even when callback throws');
      assert.strictEqual(fs.readdirSync(tmpDir).length, 0, '.fleet-tmp must be empty after withEphemeralKey');
    } finally {
      rmDirSafe(dir);
    }
    console.log('  ✓ Ephemeral 0o600 key materialization, zero-wipe & startup .fleet-tmp sweep');
  }

  // -------------------------------------------------------------------------
  // 3. SSRF, Metadata, Loopback, Dash-Host & Metacharacter Rejection + DNS Pinning
  // -------------------------------------------------------------------------
  {
    const blockedHosts = [
      // Cloud metadata IPs & names
      '169.254.169.254',
      '169.254.0.1',
      'fd00:ec2::254',
      'fd00:0ec2::254',
      '100.100.100.200',
      '::ffff:169.254.169.254',
      '::ffff:a9fe:a9fe',
      '0:0:0:0:0:ffff:169.254.169.254',
      '64:ff9b::a9fe:a9fe',
      '2002:a9fe:a9fe::1',
      'metadata.google.internal',
      'metadata.goog',
      'instance-data',
      // Loopback & unspecified (all notations)
      '127.0.0.1',
      '127.42.1.9',
      '0.0.0.0',
      '0.1.2.3',
      '::1',
      '::',
      '::0001',
      '0::1',
      '0:0:0:0:0:0:0:1',
      '::ffff:127.0.0.1',
      '0:0:0:0:0:ffff:127.0.0.1',
      'localhost',
      'api.localhost',
      'fe80::1',
      '2001:0::1',
      '224.0.0.1',
      '255.255.255.255'
    ];

    for (const h of blockedHosts) {
      await assert.rejects(
        () => helpers.assertSafeFleetHost(h, { resolveHost: async () => ['203.0.113.1'] }),
        (err) => err && (err.code === 'SSRF_BLOCKED' || err.code === 'INVALID_HOST'),
        `Expected blocked host to be rejected: ${h}`
      );
    }

    // Dash-prefixed, metacharacters & obfuscated numeric IPs
    const invalidSyntaxHosts = [
      '-oProxyCommand=id',
      '-Jevil.com',
      'host;id',
      'host|whoami',
      'host$(id)',
      'host`id`',
      'host\nid',
      'host name',
      'root@10.0.0.5',
      '2130706433',
      '0x7f000001',
      '0177.0.0.1',
      '10.0.0.5:22'
    ];
    for (const bad of invalidSyntaxHosts) {
      assert.throws(
        () => helpers.validateHostSyntax(bad),
        (err) => err && err.code === 'INVALID_HOST',
        `Expected malformed/injected host to be rejected: ${bad}`
      );
    }

    // DNS rebinding / hostname resolving to metadata or loopback must be blocked
    await assert.rejects(
      () => helpers.assertSafeFleetHost('rebind.example.com', { resolveHost: async () => ['169.254.169.254'] }),
      (err) => err && err.code === 'SSRF_BLOCKED'
    );
    await assert.rejects(
      () => helpers.assertSafeFleetHost('mixed.example.com', { resolveHost: async () => ['10.0.0.9', '127.0.0.1'] }),
      (err) => err && err.code === 'SSRF_BLOCKED'
    );

    // Allowed RFC1918, Tailscale CGNAT, WireGuard/Tailscale IPv6 ULA, and public hosts
    const allowedHosts = [
      '10.0.1.50',
      '172.16.20.5',
      '192.168.1.200',
      '100.64.10.20',       // Tailscale CGNAT (not 100.100.100.200)
      'fd7a:115c:a1e0::42', // Tailscale ULA IPv6 (not fd00:ec2::/32)
      '203.0.113.10',
      '2a01:4f8:c010::1'
    ];
    for (const okHost of allowedHosts) {
      const res = await helpers.assertSafeFleetHost(okHost);
      assert.strictEqual(res.pinnedIp, okHost.toLowerCase(), `Expected allowed host: ${okHost}`);
    }

    // Hostname resolves to pinned IP
    const resolved = await helpers.assertSafeFleetHost('vps-eu1.internal', { resolveHost: async () => ['10.20.30.40'] });
    assert.strictEqual(resolved.host, 'vps-eu1.internal');
    assert.strictEqual(resolved.pinnedIp, '10.20.30.40');

    // User, socket, port, serverId validators
    assert.throws(() => helpers.validateSshUser('-root'), (e) => e.code === 'INVALID_USER');
    assert.throws(() => helpers.validateSshUser('root;id'), (e) => e.code === 'INVALID_USER');
    assert.throws(() => helpers.validateDockerSocketPath('var/run/docker.sock'), (e) => e.code === 'INVALID_DOCKER_SOCKET');
    assert.throws(() => helpers.validateDockerSocketPath('/var/run/../etc/passwd'), (e) => e.code === 'INVALID_DOCKER_SOCKET');
    assert.throws(() => helpers.validateDockerSocketPath('/var/run/docker.sock;id'), (e) => e.code === 'INVALID_DOCKER_SOCKET');
    assert.throws(() => helpers.validatePort(0), (e) => e.code === 'INVALID_PORT');
    assert.throws(() => helpers.validatePort(65536), (e) => e.code === 'INVALID_PORT');
    assert.throws(() => helpers.validateServerId('local'), (e) => e.code === 'RESERVED_SERVER_ID');

    console.log('  ✓ SSRF/metadata/loopback/IPv6-canonical/dash-host/metachar validation & RFC1918/Tailscale allow');
  }

  // -------------------------------------------------------------------------
  // 4. Hardened OpenSSH Argv Builder (Non-Tunnel vs Tunnel ClearAllForwardings + Win32/POSIX NullDev)
  // -------------------------------------------------------------------------
  {
    const srv = { host: 'vps1.internal', port: 2222, user: 'deploy' };
    const execArgs = helpers.buildBaseSshArgs(srv, {
      keyFile: '/tmp/k_1234',
      knownHostsFile: '/tmp/kh_srv1',
      pinnedIp: '10.0.1.9',
      platform: 'linux',
      clearAllForwardings: true
    });
    assert.strictEqual(execArgs[0], '-F');
    assert.strictEqual(execArgs[1], '/dev/null');
    assert.ok(execArgs.includes('IdentitiesOnly=yes'));
    assert.ok(execArgs.includes('ForwardAgent=no'));
    assert.ok(execArgs.includes('PermitLocalCommand=no'));
    assert.ok(execArgs.includes('StrictHostKeyChecking=yes'));
    assert.ok(execArgs.includes('GlobalKnownHostsFile=/dev/null'));
    assert.ok(execArgs.includes('HostKeyAlias=vps1.internal'));
    assert.ok(execArgs.includes('ServerAliveInterval=15'));
    assert.ok(execArgs.includes('ServerAliveCountMax=3'));
    assert.ok(execArgs.includes('ClearAllForwardings=yes'), 'Non-tunnel SSH must set ClearAllForwardings=yes');
    assert.strictEqual(execArgs[execArgs.length - 2], '--');
    assert.strictEqual(execArgs[execArgs.length - 1], 'deploy@10.0.1.9', 'Must connect to pinnedIp after --');

    const winArgs = helpers.buildBaseSshArgs(srv, {
      keyFile: 'C:\\tmp\\k_1234',
      knownHostsFile: 'C:\\tmp\\kh_srv1',
      pinnedIp: '10.0.1.9',
      platform: 'win32',
      clearAllForwardings: true
    });
    assert.strictEqual(winArgs[0], '-F');
    assert.strictEqual(winArgs[1], 'NUL', 'Windows OpenSSH must use NUL for -F');
    assert.ok(winArgs.includes('GlobalKnownHostsFile=NUL'), 'Windows OpenSSH must use NUL for GlobalKnownHostsFile');

    const tunnelArgs = helpers.buildBaseSshArgs(srv, {
      keyFile: '/tmp/k_1234',
      knownHostsFile: '/tmp/kh_srv1',
      pinnedIp: '10.0.1.9',
      platform: 'linux',
      clearAllForwardings: false,
      extraArgs: ['-N', '-L', '127.0.0.1:41234:/var/run/docker.sock']
    });
    assert.ok(!tunnelArgs.includes('ClearAllForwardings=yes'), 'Tunnel SSH with -L MUST omit ClearAllForwardings=yes');
    assert.ok(tunnelArgs.includes('-L'));
    assert.strictEqual(tunnelArgs[tunnelArgs.length - 2], '--');
    assert.strictEqual(tunnelArgs[tunnelArgs.length - 1], 'deploy@10.0.1.9');
    console.log('  ✓ Hardened OpenSSH argv (-F /dev/null vs NUL, HostKeyAlias, -- user@pinnedIp, ClearAllForwardings rule)');
  }

  // -------------------------------------------------------------------------
  // 5. TOFU, Strict Host-Key Pinning, HOST_KEY_MISMATCH Lockdown & repinHostKey
  // -------------------------------------------------------------------------
  {
    const dir = createTempDir();
    try {
      const hostKeyA = makeFakeEd25519PubKey('host-A');
      const hostKeyB = makeFakeEd25519PubKey('host-B');
      const clientPub = makeFakeEd25519PubKey('client');
      let currentHostKey = hostKeyA;
      let sshCallCount = 0;
      let keyscanCalls = [];
      let simulateSshHostMismatch = false;

      const fakeExec = async (bin, args) => {
        if (bin === 'ssh-keygen' && args.includes('-y')) {
          return { stdout: `${clientPub.line}\n`, stderr: '' };
        }
        if (bin === 'ssh-keyscan') {
          keyscanCalls.push([...args]);
          // Include a weak ssh-dss line + valid ed25519 line to verify algorithm selection
          return {
            stdout: [
              `# 10.50.0.10:2222 SSH-2.0-OpenSSH_9.6`,
              `[10.50.0.10]:2222 ssh-dss AAAAB3NzaC1kc3MAAACBAAAAAAAAAAAAAAAAAAAAAAAAAA`,
              `[10.50.0.10]:2222 ${currentHostKey.keyType} ${currentHostKey.b64}`
            ].join('\n') + '\n',
            stderr: ''
          };
        }
        if (bin === 'ssh') {
          sshCallCount++;
          if (simulateSshHostMismatch) {
            const err = new Error('Host key verification failed');
            err.stderr = 'REMOTE HOST IDENTIFICATION HAS CHANGED!\nHost key verification failed.\n';
            throw err;
          }
          return {
            stdout: [
              'OS=Linux',
              'ARCH=x86_64',
              'CPUS=4',
              'LOAD=0.35',
              'MEM_KB=8192000 6144000',
              'DISK_KB=104857600 83886080',
              'DOCKER=27.3.1',
              'DOCKER_SOCK=rw',
              'CADDY=v2.8.4'
            ].join('\n') + '\n',
            stderr: ''
          };
        }
        throw new Error(`Unexpected execFile: ${bin}`);
      };

      const mgr = new ServerFleetManager({
        dataDir: dir,
        _execFile: fakeExec,
        _resolveHost: async () => ['10.50.0.10'],
        autoMonitor: false
      });

      const key = await mgr.importKey({ name: 'k-main', privateKeyPem: makeFakePrivatePem('MAIN'), teamId: 'team_ops' });

      // Strict policy without expectedFingerprint must reject
      await assert.rejects(
        () => mgr.addServer({ name: 'strict-bad', host: 'vps-strict.internal', keyId: key.id, teamId: 'team_ops', hostKeyPolicy: 'strict' }),
        (err) => err && err.code === 'EXPECTED_FINGERPRINT_REQUIRED'
      );

      // Strict policy with mismatched fingerprint + pinOnAdd must reject WITHOUT saving or calling ssh
      const beforeSsh = sshCallCount;
      await assert.rejects(
        () => mgr.addServer({
          id: 'srv-strict-fail',
          name: 'strict-fail',
          host: 'vps-strict.internal',
          port: 2222,
          keyId: key.id,
          teamId: 'team_ops',
          hostKeyPolicy: 'strict',
          expectedFingerprint: hostKeyB.fingerprint,
          pinOnAdd: true
        }),
        (err) => err && err.code === 'HOST_KEY_MISMATCH'
      );
      assert.strictEqual(mgr.getServer('srv-strict-fail'), null, 'Mismatched strict server must not be saved');
      assert.strictEqual(sshCallCount, beforeSsh, 'SSH credentials must NEVER be sent on strict mismatch');

      // DSA-only keyscan must fail
      assert.throws(
        () => helpers.parseBestKeyscanOutput('10.0.0.1 ssh-dss AAAAB3NzaC1kc3MAAACBAAAAAAAAAAAAAAAAAAAAAAAAAA'),
        (err) => err && err.code === 'KEYSCAN_NO_VALID_KEY'
      );

      // TOFU registration + first probe pins hostKeyA and uses pinnedIp + HostKeyAlias
      const srv = await mgr.addServer({
        id: 'eu-node-1',
        name: 'EU Worker 1',
        host: 'eu1.internal',
        port: 2222,
        user: 'ubuntu',
        keyId: key.id,
        region: 'eu-west',
        tags: ['prod', 'docker'],
        teamId: 'team_ops'
      });
      assert.strictEqual(srv.status, 'pending');
      assert.strictEqual(srv.teamId, 'team_ops');
      assert.strictEqual(srv.hostKeyLine, undefined, 'sanitizeServer must strip hostKeyLine');

      const probe1 = await mgr.probeServer('eu-node-1');
      assert.strictEqual(probe1.ok, true);
      assert.strictEqual(probe1.status, 'online');
      assert.strictEqual(probe1.server.hostKeyFingerprint, hostKeyA.fingerprint);
      assert.strictEqual(probe1.resources.dockerVersion, '27.3.1');
      assert.strictEqual(probe1.resources.caddyAvailable, true);

      // Verify ssh-keyscan targeted pinnedIp after `--`
      const lastScan = keyscanCalls[keyscanCalls.length - 1];
      assert.strictEqual(lastScan[lastScan.length - 2], '--');
      assert.strictEqual(lastScan[lastScan.length - 1], '10.50.0.10');

      // Verify per-server known_hosts file uses HostKeyAlias (eu1.internal), NOT raw pinnedIp
      const khPath = path.join(dir, '.fleet-known-hosts', 'eu-node-1');
      assert.ok(fs.existsSync(khPath), 'Per-server known_hosts file must be written');
      const khText = fs.readFileSync(khPath, 'utf8');
      assert.ok(khText.includes(`eu1.internal ssh-ed25519 ${hostKeyA.b64}`));
      assert.ok(khText.includes(`[eu1.internal]:2222 ssh-ed25519 ${hostKeyA.b64}`));

      // Simulate MITM: remote host key changes during SSH -> HOST_KEY_MISMATCH lockdown
      simulateSshHostMismatch = true;
      await assert.rejects(
        () => mgr.probeServer('eu-node-1', { force: true }),
        (err) => err && err.code === 'HOST_KEY_MISMATCH'
      );
      const locked = mgr.getServer('eu-node-1');
      assert.strictEqual(locked.status, 'host_key_mismatch', 'Server must lock down into host_key_mismatch');

      // Subsequent probe while locked MUST fail closed WITHOUT invoking ssh
      const countWhileLocked = sshCallCount;
      await assert.rejects(
        () => mgr.probeServer('eu-node-1', { force: true }),
        (err) => err && err.code === 'HOST_KEY_MISMATCH'
      );
      assert.strictEqual(sshCallCount, countWhileLocked, 'Locked server must NEVER invoke ssh before repinHostKey');

      // Explicit repinHostKey with wrong expectedFingerprint must reject & stay locked
      currentHostKey = hostKeyB;
      await assert.rejects(
        () => mgr.repinHostKey('eu-node-1', { expectedFingerprint: hostKeyA.fingerprint }),
        (err) => err && err.code === 'HOST_KEY_MISMATCH'
      );
      assert.strictEqual(mgr.getServer('eu-node-1').status, 'host_key_mismatch');

      // Explicit repinHostKey with matching new fingerprint clears lockdown and restores probe
      const repin = await mgr.repinHostKey('eu-node-1', { expectedFingerprint: hostKeyB.fingerprint });
      assert.strictEqual(repin.previousFingerprint, hostKeyA.fingerprint);
      assert.strictEqual(repin.fingerprint, hostKeyB.fingerprint);

      simulateSshHostMismatch = false;
      const probe2 = await mgr.probeServer('eu-node-1', { force: true });
      assert.strictEqual(probe2.ok, true);
      assert.strictEqual(probe2.status, 'online');
      assert.strictEqual(probe2.server.hostKeyFingerprint, hostKeyB.fingerprint);
    } finally {
      rmDirSafe(dir);
    }
    console.log('  ✓ TOFU pinning, strict mismatch rejection, HOST_KEY_MISMATCH lockdown & repinHostKey');
  }

  // -------------------------------------------------------------------------
  // 6. Ref-Counted Tunnel Leases, Coalescing, Graceful Drain, Idle Cleanup & Port/Caddy Tunnels
  // -------------------------------------------------------------------------
  {
    const dir = createTempDir();
    try {
      const hostKey = makeFakeEd25519PubKey('tun-host');
      const clientPub = makeFakeEd25519PubKey('tun-client');
      const dockerPsCalls = [];

      const fakeExec = async (bin, args, opts) => {
        if (bin === 'ssh-keygen' && args.includes('-y')) {
          return { stdout: `${clientPub.line}\n`, stderr: '' };
        }
        if (bin === 'ssh-keyscan') {
          return { stdout: `10.90.0.5 ${hostKey.keyType} ${hostKey.b64}\n`, stderr: '' };
        }
        if (bin === 'docker' && args[0] === 'ps') {
          dockerPsCalls.push({ args: [...args], dockerHost: opts && opts.env ? opts.env.DOCKER_HOST : null });
          return {
            stdout: [
              '127.0.0.1:30000->3000/tcp, 0.0.0.0:30001-30003->3001-3003/tcp',
              '[::]:30004->8080/tcp'
            ].join('\n') + '\n',
            stderr: ''
          };
        }
        throw new Error(`Unexpected execFile: ${bin}`);
      };

      const { spawns, spawnFn } = createFakeTunnelSpawner({ connectDelayMs: 25 });
      const prevDockerHostEnv = process.env.DOCKER_HOST;

      const mgr = new ServerFleetManager({
        dataDir: dir,
        _execFile: fakeExec,
        _spawn: spawnFn,
        _resolveHost: async () => ['10.90.0.5'],
        tunnelIdleMs: 120,
        platform: 'win32', // Uses real local loopback TCP ports cross-platform in tests
        autoMonitor: false
      });

      const key1 = await mgr.importKey({ name: 'key-1', privateKeyPem: makeFakePrivatePem('KEY1') });
      const key2 = await mgr.importKey({ name: 'key-2', privateKeyPem: makeFakePrivatePem('KEY2') });
      await mgr.addServer({ id: 'tun-node', name: 'Tunnel Node', host: 'tun.internal', keyId: key1.id });

      // Coalesce 2 concurrent tunnel acquisitions into ONE ssh spawn
      const [lease1, lease2] = await Promise.all([
        mgr.acquireDockerTunnel('tun-node'),
        mgr.acquireDockerTunnel('tun-node')
      ]);
      assert.strictEqual(spawns.length, 1, 'Concurrent acquires must coalesce onto a single ssh tunnel process');
      assert.strictEqual(lease1.tunnelId, lease2.tunnelId);
      assert.ok(lease1.dockerHost && lease1.dockerHost.startsWith('tcp://127.0.0.1:'));
      assert.strictEqual(process.env.DOCKER_HOST, prevDockerHostEnv, 'process.env.DOCKER_HOST must NEVER be mutated');

      // Ephemeral key MUST already be wiped right after tunnel handshake!
      assert.strictEqual(fs.readdirSync(path.join(dir, '.fleet-tmp')).length, 0, 'Ephemeral key must be zero-wiped right after tunnel handshake');

      // Verify tunnel ssh args omit ClearAllForwardings=yes, use NUL on win32, HostKeyAlias + pinnedIp, and ignore stdout
      assert.ok(!spawns[0].args.includes('ClearAllForwardings=yes'));
      assert.ok(spawns[0].args.includes('NUL'));
      assert.ok(spawns[0].args.includes('HostKeyAlias=tun.internal'));
      assert.deepStrictEqual(spawns[0].spawnOpts.stdio, ['ignore', 'ignore', 'pipe'], 'Tunnel spawn must ignore stdout to prevent buffer stall');
      assert.strictEqual(spawns[0].args[spawns[0].args.length - 2], '--');
      assert.strictEqual(spawns[0].args[spawns[0].args.length - 1], 'root@10.90.0.5');

      assert.strictEqual(mgr.getTunnelState('tun-node').refCount, 2);

      // Release lease1 -> refCount=1; wait well past tunnelIdleMs -> tunnel MUST stay alive!
      await lease1.release();
      // Idempotent double release must NOT decrement twice!
      await lease1.release();
      assert.strictEqual(mgr.getTunnelState('tun-node').refCount, 1);
      await new Promise((r) => setTimeout(r, 200));
      assert.strictEqual(spawns[0].child.killed, false, 'Tunnel MUST NEVER be killed while refCount > 0');

      // Remote port allocation uses lease.dockerHost without mutating process.env.DOCKER_HOST
      const p1 = await mgr.allocateRemotePort('tun-node', lease2);
      const p2 = await mgr.allocateRemotePort('tun-node', lease2);
      assert.strictEqual(p1, 30005, 'Must skip occupied ports 30000..30004');
      assert.strictEqual(p2, 30006, 'Consecutive allocations must not collide');
      assert.strictEqual(dockerPsCalls[0].dockerHost, lease2.dockerHost);
      assert.strictEqual(process.env.DOCKER_HOST, prevDockerHostEnv);

      // Graceful drain on key rotation: old tunnel stays alive for lease2 while new caller gets fresh tunnel!
      await mgr.updateServer('tun-node', { keyId: key2.id });
      assert.strictEqual(spawns[0].child.killed, false, 'Key rotation must NOT kill in-flight tunnel (graceful drain)');
      const lease3 = await mgr.acquireDockerTunnel('tun-node');
      assert.strictEqual(spawns.length, 2, 'New lease after key rotation must open a fresh tunnel');
      assert.notStrictEqual(lease3.tunnelId, lease2.tunnelId);

      // Releasing last lease on draining tunnel #1 closes tunnel #1 IMMEDIATELY without killing tunnel #2
      await lease2.release();
      assert.strictEqual(spawns[0].child.killed, true, 'Draining tunnel must close immediately once its refCount reaches 0');
      assert.strictEqual(spawns[1].child.killed, false, 'Fresh tunnel #2 must stay open while lease3 is active');

      // Releasing lease3 drops refCount=0 -> idle timer tears down tunnel #2 after tunnelIdleMs
      await lease3.release();
      assert.strictEqual(spawns[1].child.killed, false, 'Idle tunnel stays warm until idle timeout');
      await new Promise((r) => setTimeout(r, 220));
      assert.strictEqual(spawns[1].child.killed, true, 'Idle tunnel must close automatically once idle timer expires');

      // withPortTunnel & withCaddyTunnel tear down in finally
      const beforePortSpawns = spawns.length;
      const caddySeen = await mgr.withCaddyTunnel('tun-node', async (adminUrl, meta) => {
        assert.ok(adminUrl.startsWith('http://127.0.0.1:'));
        assert.strictEqual(meta.isLocal, false);
        assert.strictEqual(fs.readdirSync(path.join(dir, '.fleet-tmp')).length, 0);
        return adminUrl;
      });
      assert.ok(caddySeen);
      assert.strictEqual(spawns.length, beforePortSpawns + 1);
      assert.strictEqual(spawns[beforePortSpawns].child.killed, true, 'Short-lived Caddy tunnel must close in finally');
      const lIdx = spawns[beforePortSpawns].args.indexOf('-L');
      assert.ok(spawns[beforePortSpawns].args[lIdx + 1].endsWith(':127.0.0.1:2019'), 'Caddy tunnel must forward remote 127.0.0.1:2019');

      // Virtual 'local' pass-through spawns zero ssh processes
      const beforeLocalSpawns = spawns.length;
      await mgr.withDockerTunnel(LOCAL_SERVER_ID, async (lease) => {
        assert.strictEqual(lease.isLocal, true);
        assert.strictEqual(lease.dockerHost, null);
      });
      await mgr.withCaddyTunnel(LOCAL_SERVER_ID, async (adminUrl, meta) => {
        assert.strictEqual(adminUrl, 'http://127.0.0.1:2019');
        assert.strictEqual(meta.isLocal, true);
      });
      assert.strictEqual(spawns.length, beforeLocalSpawns, 'Local server tunnels must never spawn ssh');

      // POSIX Unix socket path length guard (<90B)
      const posixMgr = new ServerFleetManager({
        dataDir: dir,
        _execFile: fakeExec,
        _spawn: spawnFn,
        _resolveHost: async () => ['10.90.0.5'],
        _waitForEndpoint: async () => {},
        platform: 'linux',
        tmpSocketBaseDir: path.join(os.tmpdir(), 'ck-f-t'),
        autoMonitor: false
      });
      const posixLease = await posixMgr.acquireDockerTunnel('tun-node');
      assert.ok(posixLease.dockerHost && posixLease.dockerHost.startsWith('unix://'));
      const sockPath = posixLease.dockerHost.slice('unix://'.length);
      assert.ok(Buffer.byteLength(sockPath, 'utf8') < 104, `POSIX socket path must stay under sun_path limit: ${sockPath}`);
      await posixLease.release();
      await posixMgr.shutdown();
      await mgr.shutdown();
    } finally {
      rmDirSafe(dir);
    }
    console.log('  ✓ Ref-counted tunnel leases, coalescing, graceful drain, idle teardown, Caddy/Port tunnels & allocateRemotePort');
  }

  // -------------------------------------------------------------------------
  // 7. Static POSIX Probe Parser, Coalescing, Cache & Lazy Background Monitor
  // -------------------------------------------------------------------------
  {
    assert.ok(typeof PROBE_CMD === 'string' && PROBE_CMD.includes('DOCKER_SOCK='), 'PROBE_CMD must be a static POSIX string');

    // Healthy node with noisy MOTD banner
    const okParsed = helpers.parseProbeOutput([
      'Welcome to Ubuntu 24.04.1 LTS',
      'OS=Linux',
      'ARCH=aarch64',
      'CPUS=8',
      'LOAD=1.42',
      'MEM_KB=16384000 12288000',
      'DISK_KB=209715200 157286400',
      'DOCKER=27.4.0',
      'DOCKER_SOCK=rw',
      'CADDY=v2.9.0'
    ].join('\n'), 42, 'ubuntu');
    assert.strictEqual(okParsed.status, 'online');
    assert.strictEqual(okParsed.resources.cpus, 8);
    assert.strictEqual(okParsed.resources.load1m, 1.42);
    assert.strictEqual(okParsed.resources.memoryTotalMb, 16000);
    assert.strictEqual(okParsed.resources.memoryAvailableMb, 12000);
    assert.strictEqual(okParsed.resources.diskTotalGb, 200);
    assert.strictEqual(okParsed.resources.diskAvailableGb, 150);
    assert.strictEqual(okParsed.resources.dockerReady, true);
    assert.strictEqual(okParsed.resources.caddyAvailable, true);
    assert.strictEqual(okParsed.resources.latencyMs, 42);

    // Non-root user without docker group permissions -> degraded + actionable usermod fix
    const roParsed = helpers.parseProbeOutput([
      'OS=Linux',
      'ARCH=x86_64',
      'CPUS=2',
      'LOAD=0.10',
      'MEM_KB=4096000 2048000',
      'DISK_KB=52428800 26214400',
      'DOCKER=none',
      'DOCKER_SOCK=ro',
      'CADDY=none'
    ].join('\n'), 18, 'deploy');
    assert.strictEqual(roParsed.status, 'degraded');
    assert.strictEqual(roParsed.resources.dockerReady, false);
    assert.ok(roParsed.statusFix && roParsed.statusFix.includes('usermod -aG docker deploy'), 'Must give actionable usermod fix');

    // Missing docker daemon -> degraded + install guidance
    const missingParsed = helpers.parseProbeOutput('OS=Linux\nDOCKER=none\nDOCKER_SOCK=missing\nCADDY=none\n', 10, 'root');
    assert.strictEqual(missingParsed.status, 'degraded');
    assert.strictEqual(missingParsed.resources.dockerReady, false);
    assert.ok(missingParsed.statusFix && missingParsed.statusFix.includes('Docker'));

    // Probe caching, coalescing, and lazy monitor lifecycle (0 servers = no timer, >=1 = active, delete last = stopped)
    const dir = createTempDir();
    try {
      const hostKey = makeFakeEd25519PubKey('probe-host');
      const clientPub = makeFakeEd25519PubKey('probe-client');
      let sshProbeCalls = 0;

      const fakeExec = async (bin, args) => {
        if (bin === 'ssh-keygen' && args.includes('-y')) return { stdout: `${clientPub.line}\n`, stderr: '' };
        if (bin === 'ssh-keyscan') return { stdout: `10.10.0.10 ${hostKey.keyType} ${hostKey.b64}\n`, stderr: '' };
        if (bin === 'ssh') {
          sshProbeCalls++;
          await new Promise((r) => setTimeout(r, 20));
          return {
            stdout: 'OS=Linux\nARCH=x86_64\nCPUS=2\nLOAD=0.25\nMEM_KB=2048000 1024000\nDISK_KB=20971520 10485760\nDOCKER=27.0.0\nDOCKER_SOCK=rw\nCADDY=v2.8.4\n',
            stderr: ''
          };
        }
        throw new Error(`Unexpected execFile: ${bin}`);
      };

      const mgr = new ServerFleetManager({
        dataDir: dir,
        _execFile: fakeExec,
        _resolveHost: async () => ['10.10.0.10'],
        autoMonitor: true,
        monitorIntervalMs: 60000
      });

      assert.strictEqual(mgr.startMonitor(), false, 'Monitor must NOT start when 0 remote servers exist');
      assert.strictEqual(mgr.getFleetSummary().monitorActive, false);

      const k = await mgr.importKey({ name: 'pk', privateKeyPem: makeFakePrivatePem('PK') });
      await mgr.addServer({ id: 'mon-1', name: 'Mon Node', host: 'mon1.internal', keyId: k.id });
      assert.strictEqual(mgr.getFleetSummary().monitorActive, true, 'Monitor starts lazily once >=1 remote server exists');

      // Concurrent probe calls coalesce
      const [r1, r2] = await Promise.all([mgr.probeServer('mon-1'), mgr.probeServer('mon-1')]);
      assert.strictEqual(sshProbeCalls, 1, 'Concurrent probes must coalesce into 1 SSH call');
      assert.strictEqual(r1.ok, true);
      assert.strictEqual(r2.ok, true);

      // Cached within TTL
      const r3 = await mgr.probeServer('mon-1');
      assert.strictEqual(r3.cached, true);
      assert.strictEqual(sshProbeCalls, 1);

      // Force bypasses TTL
      const r4 = await mgr.probeServer('mon-1', { force: true });
      assert.strictEqual(r4.cached, false);
      assert.strictEqual(sshProbeCalls, 2);

      // Deleting last remote server stops monitor automatically
      await mgr.deleteServer('mon-1');
      assert.strictEqual(mgr.getFleetSummary().monitorActive, false, 'Monitor must stop automatically when 0 remote servers remain');
      await mgr.shutdown();
    } finally {
      rmDirSafe(dir);
    }
    console.log('  ✓ Static POSIX probe parser, coalescing, TTL cache & lazy background monitor lifecycle');
  }

  // -------------------------------------------------------------------------
  // 8. Key & Server CRUD, Virtual 'local' Node, Protection Guards & Summaries
  // -------------------------------------------------------------------------
  {
    const dir = createTempDir();
    try {
      const clientPub = makeFakeEd25519PubKey('crud-client');
      const fakeExec = async (bin, args) => {
        if (bin === 'ssh-keygen' && args.includes('-y')) {
          return { stdout: `${clientPub.line}\n`, stderr: '' };
        }
        throw new Error(`Unexpected execFile: ${bin}`);
      };

      const mgr = new ServerFleetManager({
        dataDir: dir,
        _execFile: fakeExec,
        _resolveHost: async () => ['10.88.0.1'],
        autoMonitor: false
      });

      // Virtual 'local' server is always present in listServers() & getServer('local')
      const initialList = mgr.listServers();
      assert.strictEqual(initialList.length, 1);
      assert.strictEqual(initialList[0].id, 'local');
      assert.strictEqual(initialList[0].isLocal, true);
      assert.strictEqual(initialList[0].status, 'online');
      assert.strictEqual(mgr.getServer('local').isLocal, true);
      assert.strictEqual(mgr.getDoctorSummary().ok, true);

      // Passphrase-protected key rejected cleanly
      await assert.rejects(
        () => mgr.importKey({
          name: 'enc-key',
          privateKeyPem: '-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----'
        }),
        (err) => err && err.code === 'PASSPHRASE_UNSUPPORTED'
      );

      // Create key + server + filters + cross-team key hijack prevention (Dokploy GHSA-pfvx-m77f-6qr6)
      const k = await mgr.importKey({ name: 'crud-key', privateKeyPem: makeFakePrivatePem('CRUD'), teamId: 'team_a' });
      const kTeamB = await mgr.importKey({ name: 'team-b-key', privateKeyPem: makeFakePrivatePem('TEAM_B'), teamId: 'team_b' });

      await assert.rejects(
        () => mgr.addServer({
          id: 'cross-team-hijack',
          name: 'Cross Team Hijack',
          host: '10.88.0.2',
          keyId: k.id,
          teamId: 'team_b'
        }),
        (e) => e && e.code === 'KEY_TEAM_MISMATCH' && e.statusCode === 403,
        'addServer must block attaching a key belonging to another team'
      );

      const s = await mgr.addServer({
        id: 'us-east-1',
        name: 'US Worker',
        host: '10.88.0.1',
        keyId: k.id,
        region: 'us-east',
        tags: ['gpu', 'prod'],
        teamId: 'team_a'
      });
      assert.strictEqual(s.id, 'us-east-1');
      assert.strictEqual(s.teamId, 'team_a');
      assert.strictEqual(s.publicKey, clientPub.line);

      await assert.rejects(
        () => mgr.updateServer('us-east-1', { keyId: kTeamB.id }),
        (e) => e && e.code === 'KEY_TEAM_MISMATCH' && e.statusCode === 403,
        'updateServer must block rotating to a key belonging to another team'
      );
      mgr.deleteKey(kTeamB.id);

      // Filters
      assert.strictEqual(mgr.listServers({ includeLocal: false }).length, 1);
      assert.strictEqual(mgr.listServers({ tag: 'gpu', includeLocal: false }).length, 1);
      assert.strictEqual(mgr.listServers({ region: 'eu-west', includeLocal: false }).length, 0);
      assert.strictEqual(mgr.listServers({ teamId: 'team_b', includeLocal: false }).length, 0);

      // Local server immutable
      await assert.rejects(() => mgr.updateServer('local', { name: 'hacked' }), (e) => e.code === 'LOCAL_SERVER_IMMUTABLE');
      await assert.rejects(() => mgr.deleteServer('local'), (e) => e.code === 'LOCAL_SERVER_IMMUTABLE');

      // Delete key in use must fail with KEY_IN_USE (409)
      assert.throws(() => mgr.deleteKey(k.id), (e) => e.code === 'KEY_IN_USE' && e.statusCode === 409);

      // Delete server with assigned projects must fail unless force: true
      await assert.rejects(
        () => mgr.deleteServer('us-east-1', { assignedProjectIds: ['proj-1'] }),
        (e) => e.code === 'SERVER_HAS_PROJECTS' && e.statusCode === 409
      );

      // Force delete server -> then key deletion succeeds
      const delSrv = await mgr.deleteServer('us-east-1', { assignedProjectIds: ['proj-1'], force: true });
      assert.strictEqual(delSrv.deleted, true);
      const delKey = mgr.deleteKey(k.id);
      assert.strictEqual(delKey.deleted, true);
      assert.strictEqual(mgr.listKeys().length, 0);

      // Persistence across reload (new instance reads servers.json & fleet-keys.json)
      const kPersist = await mgr.importKey({ name: 'persist-key', privateKeyPem: makeFakePrivatePem('PERSIST') });
      await mgr.addServer({ id: 'srv-persist', name: 'Persistent Node', host: '192.168.50.10', keyId: kPersist.id });
      const mgrReloaded = new ServerFleetManager({ dataDir: dir, _execFile: fakeExec, autoMonitor: false });
      assert.strictEqual(mgrReloaded.listKeys().length, 1);
      assert.strictEqual(mgrReloaded.getServer('srv-persist').host, '192.168.50.10');
      await mgr.shutdown();
      await mgrReloaded.shutdown();
    } finally {
      rmDirSafe(dir);
    }
    console.log('  ✓ Key & Server CRUD, virtual local node, in-use/project guards & atomic persistence');
  }

  // -------------------------------------------------------------------------
  // 9. Red-Team Defenses: DNS-Rebinding TOCTOU, Tunnel MITM Lockdown, Active-Tunnel Delete Guard & Redaction
  // -------------------------------------------------------------------------
  {
    const dir = createTempDir();
    try {
      const hostKey = makeFakeEd25519PubKey('rt-host');
      const clientPub = makeFakeEd25519PubKey('rt-client');
      let dnsAnswer = ['10.77.0.5'];
      let sshExecCount = 0;

      const fakeExec = async (bin, args) => {
        if (bin === 'ssh-keygen' && args.includes('-y')) return { stdout: `${clientPub.line}\n`, stderr: '' };
        if (bin === 'ssh-keyscan') return { stdout: `10.77.0.5 ${hostKey.keyType} ${hostKey.b64}\n`, stderr: '' };
        if (bin === 'ssh') {
          sshExecCount++;
          const err = new Error('Connection refused');
          err.stderr = 'ssh: connect to host 10.77.0.5: Connection refused -----BEGIN OPENSSH PRIVATE KEY-----\nSECRET\n-----END OPENSSH PRIVATE KEY-----';
          throw err;
        }
        throw new Error(`Unexpected execFile: ${bin}`);
      };

      // A. DNS-rebinding TOCTOU at probe/tunnel connect time
      const mgr = new ServerFleetManager({
        dataDir: dir,
        _execFile: fakeExec,
        _resolveHost: async () => dnsAnswer,
        autoMonitor: false
      });
      const key = await mgr.importKey({ name: 'rt-key', privateKeyPem: makeFakePrivatePem('RT') });
      await mgr.addServer({ id: 'rebind-srv', name: 'Rebind Target', host: 'rebind.internal', keyId: key.id });
      await mgr.pinHostKey('rebind-srv');

      // Flip DNS answer to AWS metadata IP after registration -> probe & tunnel MUST reject SSRF_BLOCKED
      dnsAnswer = ['169.254.169.254'];
      const beforeSsh = sshExecCount;
      await assert.rejects(() => mgr.probeServer('rebind-srv', { force: true }), (e) => e && e.code === 'SSRF_BLOCKED');
      await assert.rejects(() => mgr.acquireDockerTunnel('rebind-srv'), (e) => e && e.code === 'SSRF_BLOCKED');
      assert.strictEqual(sshExecCount, beforeSsh, 'DNS rebinding must block before invoking ssh');

      // B. Offline probe records redacted error (no PEM leak) & exponential backoff
      dnsAnswer = ['10.77.0.5'];
      const off1 = await mgr.probeServer('rebind-srv', { force: true });
      assert.strictEqual(off1.ok, false);
      assert.strictEqual(off1.status, 'offline');
      assert.strictEqual(off1.server.consecutiveFailures, 1);
      assert.ok(!String(off1.error || '').includes('SECRET'), 'Error output must redact private key material');
      assert.ok(String(off1.error || '').includes('[REDACTED_PRIVATE_KEY]'));

      // C. Tunnel MITM (HOST_KEY_MISMATCH on ssh stderr) locks server down & wipes ephemeral key
      const mitmSpawner = createFakeTunnelSpawner({ failWithHostKeyMismatch: true });
      const mitmMgr = new ServerFleetManager({
        dataDir: dir,
        _execFile: fakeExec,
        _spawn: mitmSpawner.spawnFn,
        _resolveHost: async () => ['10.77.0.5'],
        platform: 'win32',
        autoMonitor: false
      });
      await assert.rejects(
        () => mitmMgr.acquireDockerTunnel('rebind-srv'),
        (e) => e && e.code === 'HOST_KEY_MISMATCH'
      );
      assert.strictEqual(mitmMgr.getServer('rebind-srv').status, 'host_key_mismatch');
      assert.strictEqual(fs.readdirSync(path.join(dir, '.fleet-tmp')).length, 0, 'Ephemeral key must be wiped on tunnel MITM failure');
      const spawnsAfterMitm = mitmSpawner.spawns.length;
      await assert.rejects(
        () => mitmMgr.acquireDockerTunnel('rebind-srv'),
        (e) => e && e.code === 'HOST_KEY_MISMATCH'
      );
      assert.strictEqual(mitmSpawner.spawns.length, spawnsAfterMitm, 'Locked server must not spawn ssh again');

      // D. deleteServer blocked while tunnel lease is active unless force: true
      await mitmMgr.repinHostKey('rebind-srv');
      const okSpawner = createFakeTunnelSpawner({ connectDelayMs: 10 });
      const busyMgr = new ServerFleetManager({
        dataDir: dir,
        _execFile: fakeExec,
        _spawn: okSpawner.spawnFn,
        _resolveHost: async () => ['10.77.0.5'],
        platform: 'win32',
        autoMonitor: false
      });
      const activeLease = await busyMgr.acquireDockerTunnel('rebind-srv');
      await assert.rejects(
        () => busyMgr.deleteServer('rebind-srv'),
        (e) => e && e.code === 'SERVER_TUNNEL_BUSY' && e.statusCode === 409
      );
      await activeLease.release();
      await busyMgr.deleteServer('rebind-srv');
      assert.strictEqual(busyMgr.getServer('rebind-srv'), null);

      await mgr.shutdown();
      await mitmMgr.shutdown();
      await busyMgr.shutdown();
    } finally {
      rmDirSafe(dir);
    }
    console.log('  ✓ Red-team checks: DNS-rebinding TOCTOU, tunnel MITM lockdown, PEM redaction & active-tunnel delete guard');
  }

  console.log('✅ All Multi-Server Fleet SSH tests passed!\n');
}

module.exports = testFleet;

if (require.main === module) {
  testFleet().catch((err) => {
    console.error('❌ Fleet test failure:', err);
    process.exit(1);
  });
}
