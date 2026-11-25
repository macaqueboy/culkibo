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

  // -------------------------------------------------------------------------
  // 10. Stale POSIX Socket Sweep on Boot & Active-Socket Preservation
  // -------------------------------------------------------------------------
  {
    const dir = createTempDir();
    const sockDir = path.join(dir, 'ck-socks');
    try {
      fs.mkdirSync(sockDir, { recursive: true, mode: 0o700 });
      const stale1 = path.join(sockDir, 'ck-0123456789.sock');
      const stale2 = path.join(sockDir, 'ck-abcdef0123.sock');
      const unrelated = path.join(sockDir, 'keep-me.txt');
      fs.writeFileSync(stale1, 'orphan1');
      fs.writeFileSync(stale2, 'orphan2');
      fs.writeFileSync(unrelated, 'do-not-delete');

      const hostKey = makeFakeEd25519PubKey('sock-host');
      const clientPub = makeFakeEd25519PubKey('sock-client');
      const fakeExec = async (bin, args) => {
        if (bin === 'ssh-keygen' && args.includes('-y')) return { stdout: `${clientPub.line}\n`, stderr: '' };
        if (bin === 'ssh-keyscan') return { stdout: `10.91.0.1 ${hostKey.keyType} ${hostKey.b64}\n`, stderr: '' };
        throw new Error(`Unexpected execFile: ${bin}`);
      };
      const spawner = createFakeTunnelSpawner({ connectDelayMs: 10 });

      // Boot constructor sweeps orphaned ck-<10hex>.sock files automatically without touching unrelated files
      const mgr = new ServerFleetManager({
        dataDir: dir,
        tmpSocketBaseDir: sockDir,
        platform: 'linux',
        _execFile: fakeExec,
        _spawn: spawner.spawnFn,
        _waitForEndpoint: async () => {},
        _resolveHost: async () => ['10.91.0.1'],
        autoMonitor: false
      });
      assert.strictEqual(fs.existsSync(stale1), false, 'Boot sweep must remove orphaned ck-*.sock #1');
      assert.strictEqual(fs.existsSync(stale2), false, 'Boot sweep must remove orphaned ck-*.sock #2');
      assert.strictEqual(fs.existsSync(unrelated), true, 'Boot sweep must ignore non-socket files');

      // Active tunnel socket must be preserved during runtime sweepStaleSockets()
      const key = await mgr.importKey({ name: 'sk', privateKeyPem: makeFakePrivatePem('SK') });
      await mgr.addServer({ id: 'sock-node', name: 'Sock Node', host: '10.91.0.1', keyId: key.id });
      const lease = await mgr.acquireDockerTunnel('sock-node');
      const activeSockPath = lease.dockerHost.slice('unix://'.length);
      fs.writeFileSync(activeSockPath, 'active-placeholder');
      const lateOrphan = path.join(sockDir, 'ck-9999999999.sock');
      fs.writeFileSync(lateOrphan, 'late-orphan');

      const removed = mgr.sweepStaleSockets();
      assert.strictEqual(removed, 1, 'Runtime sweep must remove only the orphan socket');
      assert.strictEqual(fs.existsSync(lateOrphan), false);
      assert.strictEqual(fs.existsSync(activeSockPath), true, 'Active tunnel socket must never be deleted by sweepStaleSockets');

      await lease.release();
      await mgr.shutdown();
    } finally {
      rmDirSafe(dir);
    }
    console.log('  ✓ Stale POSIX socket sweep on boot & active-socket preservation');
  }

  // -------------------------------------------------------------------------
  // 11. Mid-Flight Tunnel Drop, Liveness Reap & withResilientDockerTunnel Auto-Reconnect
  // -------------------------------------------------------------------------
  {
    const dir = createTempDir();
    try {
      const hostKey = makeFakeEd25519PubKey('rec-host');
      const clientPub = makeFakeEd25519PubKey('rec-client');
      const fakeExec = async (bin, args) => {
        if (bin === 'ssh-keygen' && args.includes('-y')) return { stdout: `${clientPub.line}\n`, stderr: '' };
        if (bin === 'ssh-keyscan') return { stdout: `10.92.0.5 ${hostKey.keyType} ${hostKey.b64}\n`, stderr: '' };
        throw new Error(`Unexpected execFile: ${bin}`);
      };

      const spawner = createFakeTunnelSpawner({ connectDelayMs: 10 });
      let probeAlive = true;
      const staleEvents = [];
      const reconnectEvents = [];

      const mgr = new ServerFleetManager({
        dataDir: dir,
        _execFile: fakeExec,
        _spawn: spawner.spawnFn,
        _probeEndpoint: async () => probeAlive,
        _resolveHost: async () => ['10.92.0.5'],
        platform: 'win32',
        autoMonitor: false
      });
      mgr.on('tunnel:stale_reaped', (ev) => staleEvents.push(ev));
      mgr.on('tunnel:reconnecting', (ev) => reconnectEvents.push(ev));

      const key = await mgr.importKey({ name: 'rec-k', privateKeyPem: makeFakePrivatePem('REC') });
      await mgr.addServer({ id: 'rec-node', name: 'Reconnect Node', host: '10.92.0.5', keyId: key.id });

      // A. Unexpected mid-flight ssh exit(255) clears cache and next acquire transparently reconnects
      const l1 = await mgr.acquireDockerTunnel('rec-node');
      assert.strictEqual(spawner.spawns.length, 1);
      assert.strictEqual(l1.isAlive(), true);
      spawner.spawns[0].child.exitCode = 255;
      spawner.spawns[0].child.emit('exit', 255, null);
      assert.strictEqual(l1.isAlive(), false, 'Lease must report isAlive()=false after ssh exit');
      await l1.release();

      const l2 = await mgr.acquireDockerTunnel('rec-node');
      assert.strictEqual(spawner.spawns.length, 2, 'Next acquire after drop must spawn fresh tunnel');
      assert.notStrictEqual(l2.tunnelId, l1.tunnelId);
      await l2.release();

      // B. Zombie half-open socket (alive in JS, unreachable on probe) reaped & replaced
      probeAlive = false;
      const l3 = await mgr.acquireDockerTunnel('rec-node');
      assert.strictEqual(staleEvents.length, 1, 'Stale zombie tunnel must emit tunnel:stale_reaped');
      assert.strictEqual(spawner.spawns.length, 3, 'Must spawn replacement tunnel after reaping zombie');
      assert.strictEqual(spawner.spawns[1].child.killed, true, 'Reaped zombie child must be killed');
      probeAlive = true;
      await l3.release();

      // C. withResilientDockerTunnel recovers from transient mid-flight drop with backoff
      let calls = 0;
      const seenTunnelIds = [];
      const res = await mgr.withResilientDockerTunnel('rec-node', async (lease, meta) => {
        calls++;
        seenTunnelIds.push(lease.tunnelId);
        if (calls === 1) {
          const err = new Error('Cannot connect to the Docker daemon at tcp://127.0.0.1:44444');
          err.code = 'ECONNRESET';
          throw err;
        }
        return { ok: true, attempt: meta.attempt, reconnected: meta.reconnected };
      }, { maxRetries: 2, baseDelayMs: 15, maxDelayMs: 40 });
      assert.strictEqual(res.ok, true);
      assert.strictEqual(res.attempt, 1);
      assert.strictEqual(res.reconnected, true);
      assert.strictEqual(reconnectEvents.length, 1);
      assert.notStrictEqual(seenTunnelIds[0], seenTunnelIds[1], 'Reconnect must use a brand-new tunnel');

      // D. Fatal security error MUST NOT retry
      let fatalCalls = 0;
      await assert.rejects(
        () => mgr.withResilientDockerTunnel('rec-node', async () => {
          fatalCalls++;
          const err = new Error('MITM detected');
          err.code = 'HOST_KEY_MISMATCH';
          throw err;
        }, { maxRetries: 3, baseDelayMs: 10 }),
        (e) => e && e.code === 'HOST_KEY_MISMATCH'
      );
      assert.strictEqual(fatalCalls, 1, 'HOST_KEY_MISMATCH must never be retried');

      await mgr.shutdown();
    } finally {
      rmDirSafe(dir);
    }
    console.log('  ✓ Mid-flight tunnel drop recovery, zombie liveness reap & withResilientDockerTunnel backoff');
  }

  // -------------------------------------------------------------------------
  // 12. Concurrency Races: Coalesced AbortSignal Isolation, Drain-Epoch & Atomic updateServer Rollback
  // -------------------------------------------------------------------------
  {
    const dir = createTempDir();
    try {
      const hostKey = makeFakeEd25519PubKey('race-host');
      const clientPub = makeFakeEd25519PubKey('race-client');
      const fakeExec = async (bin, args) => {
        if (bin === 'ssh-keygen' && args.includes('-y')) return { stdout: `${clientPub.line}\n`, stderr: '' };
        if (bin === 'ssh-keyscan') return { stdout: `10.93.0.10 ${hostKey.keyType} ${hostKey.b64}\n`, stderr: '' };
        throw new Error(`Unexpected execFile: ${bin}`);
      };

      const spawner = createFakeTunnelSpawner({ connectDelayMs: 90 });
      const mgr = new ServerFleetManager({
        dataDir: dir,
        _execFile: fakeExec,
        _spawn: spawner.spawnFn,
        _resolveHost: async () => ['10.93.0.10'],
        platform: 'win32',
        autoMonitor: false
      });

      const k1 = await mgr.importKey({ name: 'rk1', privateKeyPem: makeFakePrivatePem('RK1') });
      const k2 = await mgr.importKey({ name: 'rk2', privateKeyPem: makeFakePrivatePem('RK2') });
      await mgr.addServer({ id: 'race-node', name: 'Race Node', host: 'race.internal', port: 2222, keyId: k1.id });
      await mgr.pinHostKey('race-node');

      // A. Caller A aborts while Caller B coalesces on same connect -> A gets ABORTED, B SUCCEEDS!
      const ctrlA = new AbortController();
      const ctrlB = new AbortController();
      const pA = mgr.acquireDockerTunnel('race-node', { signal: ctrlA.signal });
      const pB = mgr.acquireDockerTunnel('race-node', { signal: ctrlB.signal });
      setTimeout(() => ctrlA.abort(), 20);

      await assert.rejects(() => pA, (e) => e && e.code === 'ABORTED');
      const leaseB = await pB;
      assert.strictEqual(spawner.spawns.length, 1, 'Sibling waiter must share the single SSH handshake');
      assert.strictEqual(mgr.getTunnelState('race-node').refCount, 1, 'Aborted caller must not inflate refCount');
      await leaseB.release();
      mgr.drainServerTunnels('race-node');

      // B. When ALL waiters abort, underlying SSH handshake IS cancelled & ephemeral key wiped
      const ctrlC = new AbortController();
      const ctrlD = new AbortController();
      const pC = mgr.acquireDockerTunnel('race-node', { signal: ctrlC.signal });
      const pD = mgr.acquireDockerTunnel('race-node', { signal: ctrlD.signal });
      setTimeout(() => { ctrlC.abort(); ctrlD.abort(); }, 20);
      await assert.rejects(() => pC, (e) => e && e.code === 'ABORTED');
      await assert.rejects(() => pD, (e) => e && e.code === 'ABORTED');
      await new Promise((r) => setTimeout(r, 40));
      assert.strictEqual(spawner.spawns[spawner.spawns.length - 1].child.killed, true, 'Orphaned connect must kill ssh when all waiters abort');
      assert.strictEqual(fs.readdirSync(path.join(dir, '.fleet-tmp')).length, 0);

      // C. Concurrent updateServer() key/user rotation mid-handshake triggers drain epoch & re-fetches freshServer
      const spawnsBeforeEpoch = spawner.spawns.length;
      const slowAcquire = mgr.acquireDockerTunnel('race-node');
      setTimeout(() => { mgr.updateServer('race-node', { keyId: k2.id, user: 'ubuntu' }).catch(() => {}); }, 20);
      const epochLease = await slowAcquire;
      assert.strictEqual(epochLease.isAlive(), true, 'In-flight handshake crossing rotation must deliver a live fresh lease');
      assert.strictEqual(spawner.spawns.length, spawnsBeforeEpoch + 2, 'Must discard stale pre-rotation tunnel and open fresh tunnel');
      assert.strictEqual(spawner.spawns[spawnsBeforeEpoch].child.killed, true, 'Stale pre-rotation tunnel must be closed immediately');
      assert.strictEqual(
        spawner.spawns[spawnsBeforeEpoch + 1].args[spawner.spawns[spawnsBeforeEpoch + 1].args.length - 1],
        'ubuntu@10.93.0.10',
        'Re-opened tunnel must use fresh rotated user/keyId, never stale pre-update server reference'
      );
      const nextKeyLease = await mgr.acquireDockerTunnel('race-node');
      assert.strictEqual(nextKeyLease.tunnelId, epochLease.tunnelId, 'Subsequent caller must coalesce onto the fresh post-rotation tunnel');
      await epochLease.release();
      await nextKeyLease.release();

      // D. Atomic updateServer() rollback: invalid late field must leave earlier fields UNCHANGED
      const before = mgr.getServer('race-node');
      const khPath = path.join(dir, '.fleet-known-hosts', 'race-node');
      const khBefore = fs.readFileSync(khPath, 'utf8');
      await assert.rejects(
        () => mgr.updateServer('race-node', {
          name: 'CORRUPTED_PARTIAL_NAME',
          host: 'other.internal',
          port: 2299,
          region: 'ap-south',
          hostKeyPolicy: 'strict' // missing expectedFingerprint after endpoint change -> must throw!
        }),
        (e) => e && e.code === 'EXPECTED_FINGERPRINT_REQUIRED'
      );
      const after = mgr.getServer('race-node');
      assert.strictEqual(after.name, before.name, 'Atomic rollback must preserve original name');
      assert.strictEqual(after.host, before.host, 'Atomic rollback must preserve original host');
      assert.strictEqual(after.port, before.port, 'Atomic rollback must preserve original port');
      assert.strictEqual(after.region, before.region, 'Atomic rollback must preserve original region');
      assert.strictEqual(after.hostKeyPolicy, before.hostKeyPolicy, 'Atomic rollback must preserve hostKeyPolicy');
      assert.strictEqual(after.hostKeyFingerprint, before.hostKeyFingerprint, 'Atomic rollback must preserve pinned fingerprint');
      assert.strictEqual(fs.readFileSync(khPath, 'utf8'), khBefore, 'Atomic rollback must not delete known_hosts');

      await mgr.shutdown();
    } finally {
      rmDirSafe(dir);
    }
    console.log('  ✓ Concurrency races: coalesced AbortSignal isolation, drain-epoch & atomic updateServer rollback');
  }

  // -------------------------------------------------------------------------
  // 13. Node Maintenance / Drain Mode & Persistence
  // -------------------------------------------------------------------------
  {
    const dir = createTempDir();
    try {
      const clientPub = makeFakeEd25519PubKey('maint-client');
      const fakeExec = async (bin, args) => {
        if (bin === 'ssh-keygen' && args.includes('-y')) return { stdout: `${clientPub.line}\n`, stderr: '' };
        throw new Error(`Unexpected execFile: ${bin}`);
      };
      const mgr = new ServerFleetManager({ dataDir: dir, _execFile: fakeExec, _resolveHost: async () => ['10.94.0.1'], autoMonitor: false });
      const key = await mgr.importKey({ name: 'mk', privateKeyPem: makeFakePrivatePem('MK') });
      await mgr.addServer({ id: 'maint-1', name: 'Maint Node', host: '10.94.0.1', keyId: key.id });
      assert.strictEqual(mgr.getServer('maint-1').maintenanceState, 'active');

      // Local immutable & invalid states rejected
      assert.throws(() => mgr.setServerMaintenance('local', 'maintenance'), (e) => e && e.code === 'LOCAL_SERVER_IMMUTABLE');
      assert.throws(() => mgr.setServerMaintenance('maint-1', 'paused'), (e) => e && e.code === 'INVALID_MAINTENANCE_STATE');
      assert.throws(() => mgr.setServerMaintenance('maint-1', { state: 'draining', reason: 'bad\0byte' }), (e) => e && e.code === 'INVALID_MAINTENANCE_REASON');

      const events = [];
      mgr.on('server:maintenance', (ev) => events.push(ev));

      const draining = mgr.setServerMaintenance('maint-1', { state: 'draining', reason: 'Kernel security patching' });
      assert.strictEqual(draining.maintenanceState, 'draining');
      assert.strictEqual(draining.maintenanceReason, 'Kernel security patching');
      assert.ok(draining.maintenanceSince);
      assert.strictEqual(mgr.isServerSchedulable('maint-1').schedulable, false);
      assert.strictEqual(mgr.isServerSchedulable('maint-1').code, 'SERVER_IN_MAINTENANCE');
      assert.strictEqual(mgr.getFleetSummary().drainingCount, 1);

      const maint = mgr.setServerMaintenance('maint-1', 'maintenance');
      assert.strictEqual(maint.maintenanceState, 'maintenance');
      assert.strictEqual(maint.maintenanceReason, 'Kernel security patching');
      assert.strictEqual(mgr.getFleetSummary().maintenanceCount, 1);

      // Persists across reload
      const reloaded = new ServerFleetManager({ dataDir: dir, _execFile: fakeExec, autoMonitor: false });
      assert.strictEqual(reloaded.getServer('maint-1').maintenanceState, 'maintenance');
      assert.strictEqual(reloaded.getServer('maint-1').maintenanceReason, 'Kernel security patching');

      const active = reloaded.setServerMaintenance('maint-1', 'active');
      assert.strictEqual(active.maintenanceState, 'active');
      assert.strictEqual(active.maintenanceReason, null);
      assert.strictEqual(active.maintenanceSince, null);
      assert.strictEqual(events.length, 2);

      await mgr.shutdown();
      await reloaded.shutdown();
    } finally {
      rmDirSafe(dir);
    }
    console.log('  ✓ Node maintenance/draining state transitions, schedulability guard & persistence');
  }

  // -------------------------------------------------------------------------
  // 14. Smart Placement Scheduler (selectBestServer)
  // -------------------------------------------------------------------------
  {
    const dir = createTempDir();
    try {
      const clientPub = makeFakeEd25519PubKey('sched-client');
      const fakeExec = async (bin, args) => {
        if (bin === 'ssh-keygen' && args.includes('-y')) return { stdout: `${clientPub.line}\n`, stderr: '' };
        throw new Error(`Unexpected execFile: ${bin}`);
      };
      const mgr = new ServerFleetManager({ dataDir: dir, _execFile: fakeExec, autoMonitor: false });
      const key = await mgr.importKey({ name: 'sk', privateKeyPem: makeFakePrivatePem('SCHED') });

      await mgr.addServer({ id: 'eu-heavy', name: 'EU Heavy', host: '10.95.0.1', keyId: key.id, region: 'eu-west', tags: ['prod', 'ssd'] });
      await mgr.addServer({ id: 'eu-prime', name: 'EU Prime', host: '10.95.0.2', keyId: key.id, region: 'eu-west', tags: ['prod', 'ssd'] });
      await mgr.addServer({ id: 'eu-drain', name: 'EU Draining', host: '10.95.0.3', keyId: key.id, region: 'eu-west', tags: ['prod', 'ssd'] });
      await mgr.addServer({ id: 'us-gpu', name: 'US GPU', host: '10.95.0.4', keyId: key.id, region: 'us-east', tags: ['prod', 'gpu'] });

      // Seed deterministic probe telemetry directly on loaded records
      Object.assign(mgr._servers.get('eu-heavy'), {
        status: 'online',
        resources: { cpus: 4, load1m: 3.6, memoryTotalMb: 4096, memoryAvailableMb: 1024, diskTotalGb: 100, diskAvailableGb: 40, dockerReady: true, caddyAvailable: true, latencyMs: 35 }
      });
      Object.assign(mgr._servers.get('eu-prime'), {
        status: 'online',
        resources: { cpus: 8, load1m: 0.4, memoryTotalMb: 16384, memoryAvailableMb: 12288, diskTotalGb: 200, diskAvailableGb: 160, dockerReady: true, caddyAvailable: true, latencyMs: 65 }
      });
      Object.assign(mgr._servers.get('eu-drain'), {
        status: 'online',
        maintenanceState: 'draining',
        resources: { cpus: 16, load1m: 0.1, memoryTotalMb: 32768, memoryAvailableMb: 30000, diskTotalGb: 500, diskAvailableGb: 450, dockerReady: true, caddyAvailable: true, latencyMs: 5 }
      });
      Object.assign(mgr._servers.get('us-gpu'), {
        status: 'online',
        resources: { cpus: 8, load1m: 0.2, memoryTotalMb: 16384, memoryAvailableMb: 10000, diskTotalGb: 200, diskAvailableGb: 150, dockerReady: true, caddyAvailable: false, latencyMs: 4 }
      });

      // Picks eu-prime in eu-west and disqualifies eu-drain (even though eu-drain has 30GB free!)
      const p1 = mgr.selectBestServer({ region: 'eu-west', includeLocal: false });
      assert.strictEqual(p1.serverId, 'eu-prime');
      const drainRej = p1.rejected.find((r) => r.serverId === 'eu-drain');
      assert.ok(drainRej && drainRej.reasons.includes('maintenance_state:draining'));

      // Required tags & Caddy requirement
      const pGpu = mgr.selectBestServer({ tags: ['gpu'], includeLocal: false });
      assert.strictEqual(pGpu.serverId, 'us-gpu');
      const pGpuCaddy = mgr.selectBestServer({ tags: ['gpu'], requireCaddy: true, includeLocal: false });
      assert.strictEqual(pGpuCaddy.selected, null);
      assert.ok(pGpuCaddy.rejected.find((r) => r.serverId === 'us-gpu').reasons.includes('caddy_unavailable'));

      // RAM floor & anti-affinity exclusion
      const pRam = mgr.selectBestServer({ region: 'eu-west', minFreeRamMb: 8192, includeLocal: false });
      assert.strictEqual(pRam.serverId, 'eu-prime');
      assert.ok(pRam.rejected.find((r) => r.serverId === 'eu-heavy').reasons.some((x) => x.startsWith('insufficient_ram')));

      const pExclude = mgr.selectBestServer({ region: 'eu-west', excludeServerIds: ['eu-prime'], includeLocal: false });
      assert.strictEqual(pExclude.serverId, 'eu-heavy');

      // Lowest-latency strategy prefers us-gpu (4ms)
      const pLat = mgr.selectBestServer({ strategy: 'lowest-latency', includeLocal: false });
      assert.strictEqual(pLat.serverId, 'us-gpu');

      // Invalid strategy throws cleanly
      assert.throws(() => mgr.selectBestServer({ strategy: 'random' }), (e) => e && e.code === 'INVALID_PLACEMENT_STRATEGY');

      await mgr.shutdown();
    } finally {
      rmDirSafe(dir);
    }
    console.log('  ✓ Smart placement scheduler (RAM/load/disk/latency/region/tags/drain exclusion/strategies)');
  }

  // -------------------------------------------------------------------------
  // 15. Hardened 1-Command VPS Bootstrap Script Generator
  // -------------------------------------------------------------------------
  {
    const dir = createTempDir();
    try {
      const clientPub = makeFakeEd25519PubKey('boot-client');
      const fakeExec = async (bin, args) => {
        if (bin === 'ssh-keygen' && args.includes('-y')) return { stdout: `${clientPub.line}\n`, stderr: '' };
        throw new Error(`Unexpected execFile: ${bin}`);
      };
      const mgr = new ServerFleetManager({ dataDir: dir, _execFile: fakeExec, autoMonitor: false });
      const key = await mgr.importKey({ name: 'bk', privateKeyPem: makeFakePrivatePem('BOOT_SECRET') });
      await mgr.addServer({ id: 'vps-boot', name: 'Hetzner EU', host: '203.0.113.50', port: 2222, user: 'deploy', caddyAdminPort: 2019, keyId: key.id });

      const boot = mgr.generateBootstrapScript('vps-boot', {
        controlPlaneIp: '198.51.100.20/32',
        disableRootSsh: true
      });
      assert.strictEqual(boot.serverId, 'vps-boot');
      assert.strictEqual(boot.deployUser, 'deploy');
      assert.strictEqual(boot.sshPort, 2222);
      assert.strictEqual(boot.caddyAdminPort, 2019);
      assert.strictEqual(boot.keyFingerprint, clientPub.fingerprint);
      assert.ok(/^[a-f0-9]{64}$/.test(boot.sha256), 'Bootstrap script must include SHA-256 integrity hash');
      assert.ok(boot.script.includes('set -euo pipefail'));
      assert.ok(boot.script.includes('usermod -aG docker'));
      assert.ok(boot.script.includes('admin 127.0.0.1:2019'), 'Caddy admin must bind strictly to loopback');
      assert.ok(!boot.script.includes('0.0.0.0:2019'), 'Caddy admin must never expose 0.0.0.0');
      assert.ok(boot.script.includes('ufw allow from 198.51.100.20/32 to any port "2222" proto tcp'), 'UFW must allowlist control plane IP to prevent LIMIT lockouts');
      assert.ok(boot.script.includes('ufw allow 443/udp'), 'UFW must allow HTTP/3 QUIC');
      assert.ok(boot.script.includes('PasswordAuthentication no'));
      assert.ok(boot.script.includes('PermitRootLogin no'));
      assert.ok(boot.script.includes('if sshd -t; then'), 'Must validate sshd config before reload');
      assert.ok(boot.script.includes(clientPub.b64), 'Must embed vault public key');
      assert.ok(!boot.script.includes('BOOT_SECRET') && !boot.script.includes('PRIVATE KEY'), 'Must NEVER embed private key material');
      assert.ok(boot.oneLiner.startsWith("cat <<'CULKIBO_BOOTSTRAP_EOF' | sudo bash\n"));

      // Adversarial inputs rejected
      assert.throws(() => mgr.generateBootstrapScript('local'), (e) => e && e.code === 'LOCAL_SERVER_IMMUTABLE');
      assert.throws(() => mgr.generateBootstrapScript('vps-boot', { deployUser: 'deploy;id' }), (e) => e && e.code === 'INVALID_USER');
      assert.throws(() => mgr.generateBootstrapScript('vps-boot', { controlPlaneIp: '127.0.0.1' }), (e) => e && e.code === 'INVALID_CONTROL_PLANE_IP');
      assert.throws(() => mgr.generateBootstrapScript('vps-boot', { controlPlaneIp: '169.254.169.254' }), (e) => e && e.code === 'INVALID_CONTROL_PLANE_IP');
      assert.throws(() => mgr.generateBootstrapScript('vps-boot', { controlPlaneIp: '10.0.0.1;rm -rf /' }), (e) => e && e.code === 'INVALID_CONTROL_PLANE_IP');
      assert.throws(() => mgr.generateBootstrapScript('vps-boot', { sshPort: 70000 }), (e) => e && e.code === 'INVALID_PORT');

      await mgr.shutdown();
    } finally {
      rmDirSafe(dir);
    }
    console.log('  ✓ Auditable 1-command hardened VPS bootstrap script generator & injection guards');
  }

  // -------------------------------------------------------------------------
  // 16. Tunneled Remote Container Ops (Logs, Stats, Exec — Snapshot, Streaming & Adversarial)
  // -------------------------------------------------------------------------
  {
    const dir = createTempDir();
    try {
      const hostKey = makeFakeEd25519PubKey('ops-host');
      const clientPub = makeFakeEd25519PubKey('ops-client');
      const dockerExecCalls = [];
      let failFirstLogs = true;

      const fakeExec = async (bin, args, opts) => {
        if (bin === 'ssh-keygen' && args.includes('-y')) return { stdout: `${clientPub.line}\n`, stderr: '' };
        if (bin === 'ssh-keyscan') return { stdout: `10.96.0.10 ${hostKey.keyType} ${hostKey.b64}\n`, stderr: '' };
        if (bin === 'docker') {
          dockerExecCalls.push({ args: [...args], dockerHost: opts && opts.env ? opts.env.DOCKER_HOST : null });
          if (args[0] === 'logs') {
            if (failFirstLogs) {
              failFirstLogs = false;
              const e = new Error('Cannot connect to the Docker daemon');
              e.code = 'ECONNRESET';
              throw e;
            }
            return {
              stdout: 'server ready\n-----BEGIN OPENSSH PRIVATE KEY-----\nLEAK\n-----END OPENSSH PRIVATE KEY-----\n',
              stderr: 'warn line'
            };
          }
          if (args[0] === 'stats') {
            return {
              stdout: JSON.stringify({ ID: 'abc123', Name: 'web-prod', CPUPerc: '12.50%', MemUsage: '128MiB / 2GiB', MemPerc: '6.25%', NetIO: '1MB / 2MB', BlockIO: '0B / 0B', PIDs: '14' }) + '\n',
              stderr: ''
            };
          }
          if (args[0] === 'exec') {
            if (args.includes('fail-cmd')) {
              const e = new Error('exit 42');
              e.code = 42;
              e.stdout = 'partial';
              e.stderr = 'command failed';
              throw e;
            }
            return { stdout: 'v22.14.0\n', stderr: '' };
          }
        }
        throw new Error(`Unexpected execFile: ${bin}`);
      };

      const tunnelSpawner = createFakeTunnelSpawner({ connectDelayMs: 10 });
      const dockerSpawns = [];
      const compositeSpawn = (bin, args, spawnOpts) => {
        if (bin === 'ssh') return tunnelSpawner.spawnFn(bin, args, spawnOpts);
        if (bin === 'docker') {
          const child = new EventEmitter();
          child.stdout = new EventEmitter();
          child.stderr = new EventEmitter();
          child.killed = false;
          child.kill = () => {
            if (child.killed) return true;
            child.killed = true;
            setImmediate(() => { child.emit('exit', 0, 'SIGTERM'); child.emit('close', 0, 'SIGTERM'); });
            return true;
          };
          dockerSpawns.push({ args: [...args], dockerHost: spawnOpts && spawnOpts.env ? spawnOpts.env.DOCKER_HOST : null, child });
          return child;
        }
        throw new Error(`Unexpected spawn: ${bin}`);
      };

      const prevDockerHost = process.env.DOCKER_HOST;
      const mgr = new ServerFleetManager({
        dataDir: dir,
        _execFile: fakeExec,
        _spawn: compositeSpawn,
        _resolveHost: async () => ['10.96.0.10'],
        platform: 'win32',
        autoMonitor: false
      });

      const key = await mgr.importKey({ name: 'ops-k', privateKeyPem: makeFakePrivatePem('OPS') });
      await mgr.addServer({ id: 'ops-node', name: 'Ops Node', host: '10.96.0.10', keyId: key.id });

      // A. Snapshot logs auto-reconnects on ECONNRESET & redacts secrets without mutating process.env.DOCKER_HOST
      const logs = await mgr.remoteContainerLogs('ops-node', 'web_prod_1', { tail: 50, since: '10m', timestamps: true });
      assert.strictEqual(logs.reconnected, true, 'remoteContainerLogs must auto-reconnect on transient drop');
      assert.ok(logs.output.includes('server ready') && logs.output.includes('[REDACTED_PRIVATE_KEY]'));
      assert.ok(!logs.output.includes('LEAK'));
      assert.strictEqual(process.env.DOCKER_HOST, prevDockerHost);
      assert.ok(dockerExecCalls[0].dockerHost.startsWith('tcp://127.0.0.1:'));

      // B. Streaming logs holds tunnel lease until stop()
      const chunks = [];
      const logStream = await mgr.remoteContainerLogs('ops-node', 'web_prod_1', {
        follow: true,
        tail: 20,
        onChunk: (ev) => chunks.push(ev)
      });
      assert.strictEqual(mgr.getTunnelState('ops-node').refCount, 1, 'Streaming logs must hold tunnel lease');
      dockerSpawns[0].child.stdout.emit('data', Buffer.from('live line 1\n'));
      assert.strictEqual(chunks.length, 1);
      assert.strictEqual(chunks[0].chunk, 'live line 1\n');
      await logStream.stop();
      await logStream.done;
      assert.strictEqual(mgr.getTunnelState('ops-node').refCount, 0, 'Stopping stream must release tunnel lease');

      // C. Snapshot & streaming stats
      const st = await mgr.remoteContainerStats('ops-node', 'web_prod_1');
      assert.strictEqual(st.stats.name, 'web-prod');
      assert.strictEqual(st.stats.cpuPercent, 12.5);
      assert.strictEqual(st.stats.pids, 14);

      const statSamples = [];
      const statStream = await mgr.remoteContainerStats('ops-node', 'web_prod_1', {
        follow: true,
        onStats: (s) => statSamples.push(s)
      });
      dockerSpawns[1].child.stdout.emit('data', Buffer.from(JSON.stringify({ ID: 'abc123', Name: 'web-prod', CPUPerc: '4.0%', MemPerc: '5.0%', PIDs: '10' }) + '\n'));
      assert.strictEqual(statSamples.length, 1);
      assert.strictEqual(statSamples[0].containers[0].cpuPercent, 4);
      await statStream.stop();
      await statStream.done;

      // D. remoteContainerExec strict argv + non-zero exit (must NOT retry app exit code)
      const exOk = await mgr.remoteContainerExec('ops-node', 'web_prod_1', ['node', '-v'], {
        workdir: '/app',
        user: 'node',
        env: { NODE_ENV: 'production' }
      });
      assert.strictEqual(exOk.ok, true);
      assert.strictEqual(exOk.exitCode, 0);
      assert.strictEqual(exOk.stdout.trim(), 'v22.14.0');
      const lastExecCall = dockerExecCalls[dockerExecCalls.length - 1];
      assert.deepStrictEqual(lastExecCall.args, ['exec', '-w', '/app', '-u', 'node', '-e', 'NODE_ENV=production', 'web_prod_1', 'node', '-v']);

      const beforeFailCalls = dockerExecCalls.length;
      const exFail = await mgr.remoteContainerExec('ops-node', 'web_prod_1', ['fail-cmd']);
      assert.strictEqual(exFail.ok, false);
      assert.strictEqual(exFail.exitCode, 42);
      assert.strictEqual(dockerExecCalls.length, beforeFailCalls + 1, 'Non-zero app exit code must not trigger tunnel retry');

      // E. Adversarial injections rejected cleanly
      await assert.rejects(() => mgr.remoteContainerLogs('ops-node', '--privileged'), (e) => e && e.code === 'INVALID_DOCKER_REF');
      await assert.rejects(() => mgr.remoteContainerLogs('ops-node', 'web_prod_1', { since: '10m;id' }), (e) => e && e.code === 'INVALID_INPUT');
      await assert.rejects(() => mgr.remoteContainerExec('ops-node', 'web_prod_1', 'sh -c id'), (e) => e && e.code === 'INVALID_EXEC_COMMAND');
      await assert.rejects(() => mgr.remoteContainerExec('ops-node', 'web_prod_1', []), (e) => e && e.code === 'INVALID_EXEC_COMMAND');
      await assert.rejects(() => mgr.remoteContainerExec('ops-node', 'web_prod_1', ['ls', 'a\0b']), (e) => e && e.code === 'INVALID_EXEC_COMMAND');
      await assert.rejects(() => mgr.remoteContainerExec('ops-node', 'web_prod_1', ['id'], { workdir: '/app/../etc' }), (e) => e && e.code === 'INVALID_INPUT');
      await assert.rejects(() => mgr.remoteContainerExec('ops-node', 'web_prod_1', ['id'], { user: '-root' }), (e) => e && e.code === 'INVALID_INPUT');
      await assert.rejects(() => mgr.remoteContainerExec('ops-node', 'web_prod_1', ['id'], { env: { 'BAD;KEY': '1' } }), (e) => e && e.code === 'INVALID_INPUT');

      await mgr.shutdown();
    } finally {
      rmDirSafe(dir);
    }
    console.log('  ✓ Tunneled remote container logs/stats/exec (snapshot, streaming, reconnect & adversarial rejection)');
  }

  // -------------------------------------------------------------------------
  // 17. Remote Caddy Sync (syncRemoteCaddy) & Tunneled Host/Origin Anti-403 Verification
  // -------------------------------------------------------------------------
  {
    const dir = createTempDir();
    try {
      const hostKey = makeFakeEd25519PubKey('cad-host');
      const clientPub = makeFakeEd25519PubKey('cad-client');
      const fakeExec = async (bin, args) => {
        if (bin === 'ssh-keygen' && args.includes('-y')) return { stdout: `${clientPub.line}\n`, stderr: '' };
        if (bin === 'ssh-keyscan') return { stdout: `10.97.0.5 ${hostKey.keyType} ${hostKey.b64}\n`, stderr: '' };
        throw new Error(`Unexpected execFile: ${bin}`);
      };
      const spawner = createFakeTunnelSpawner({ connectDelayMs: 10 });

      const caddyCalls = [];
      const mockCaddy = {
        routeId: (pid) => `culkibo_${pid}`,
        detect: async (opts) => { caddyCalls.push({ op: 'detect', opts }); return { available: true }; },
        getWithEtag: async (reqPath, opts) => {
          caddyCalls.push({ op: 'getWithEtag', reqPath, opts });
          return { found: false, value: null, etag: null };
        },
        buildBaseConfig: (tls) => ({
          admin: { listen: '127.0.0.1:2099' },
          apps: { http: { servers: { culkibo: { listen: [':80', ':443'], routes: [] } } }, tls }
        }),
        adminRequest: async (method, reqPath, opts) => {
          caddyCalls.push({ op: 'adminRequest', method, reqPath, opts });
          return { ok: true, status: 200, text: '' };
        },
        write: async (method, reqPath, body, opts) => {
          caddyCalls.push({ op: 'write', method, reqPath, opts });
          return { ok: true };
        },
        reconcileTls: async (opts) => {
          caddyCalls.push({ op: 'reconcileTls', opts });
          return { ok: true };
        },
        upsertRoute: async (spec, opts) => {
          caddyCalls.push({ op: 'upsertRoute', spec, opts });
          return { created: true, unchanged: false, id: `culkibo_${spec.projectId}` };
        },
        removeRoute: async (pid, opts) => {
          caddyCalls.push({ op: 'removeRoute', pid, opts });
          return { removed: true };
        },
        listRoutes: async (opts) => {
          caddyCalls.push({ op: 'listRoutes', opts });
          return [
            { '@id': 'culkibo_app1' },
            { '@id': 'culkibo_stale_orphan' },
            { '@id': 'foreign_user_route' }
          ];
        }
      };

      const mgr = new ServerFleetManager({
        dataDir: dir,
        _execFile: fakeExec,
        _spawn: spawner.spawnFn,
        _caddyManager: mockCaddy,
        _resolveHost: async () => ['10.97.0.5'],
        platform: 'win32',
        autoMonitor: false
      });

      const key = await mgr.importKey({ name: 'ck', privateKeyPem: makeFakePrivatePem('CAD') });
      await mgr.addServer({ id: 'caddy-node', name: 'Caddy Worker', host: '10.97.0.5', caddyAdminPort: 2099, keyId: key.id });

      const syncRes = await mgr.syncRemoteCaddy('caddy-node', {
        routes: [
          { projectId: 'app1', hostnames: ['app1.example.com'], upstream: '127.0.0.1:30001' },
          { projectId: 'app2', hostnames: ['app2.example.com'], upstream: '127.0.0.1:30002' }
        ],
        removeProjectIds: ['old-app'],
        pruneStale: true,
        tls: { acmeEmail: 'ops@example.com' }
      });

      assert.strictEqual(syncRes.ok, true);
      assert.strictEqual(syncRes.bootstrapped, true, 'Fresh worker node must bootstrap base Caddy config');
      assert.strictEqual(syncRes.tlsSynced, true);
      assert.strictEqual(syncRes.syncedCount, 2);
      assert.deepStrictEqual(syncRes.removed, ['old-app', 'stale_orphan'], 'Must remove explicit + stale managed routes while preserving foreign routes');
      assert.strictEqual(syncRes.hostHeader, '127.0.0.1:2099');
      assert.strictEqual(spawner.spawns.length, 1, 'Entire sync must share ONE single SSH Caddy tunnel');
      assert.strictEqual(spawner.spawns[0].child.killed, true, 'Caddy tunnel must close after sync');

      // Every Caddy call must forward canonical Host/Origin 127.0.0.1:2099 (prevents remote Caddy HTTP 403!)
      const upsertCalls = caddyCalls.filter((c) => c.op === 'upsertRoute');
      assert.strictEqual(upsertCalls.length, 2);
      for (const c of upsertCalls) {
        assert.strictEqual(c.opts.hostHeader, '127.0.0.1:2099');
        assert.strictEqual(c.opts.originHeader, 'http://127.0.0.1:2099');
        assert.strictEqual(c.opts.remoteAdminPort, 2099);
        assert.ok(c.opts.adminUrl.startsWith('http://127.0.0.1:'));
      }
      const loadCall = caddyCalls.find((c) => c.op === 'adminRequest' && c.reqPath === '/load');
      assert.ok(loadCall && loadCall.opts.headers.Host === '127.0.0.1:2099');

      await mgr.shutdown();
    } finally {
      rmDirSafe(dir);
    }
    console.log('  ✓ Remote Caddy sync (single tunnel, base bootstrap, TLS, stale prune & Host/Origin anti-403)');
  }

  // -------------------------------------------------------------------------
  // 18. Adversarial Edge Cases: Invalid Hostnames, Malformed Probe, PortTunnel Errors & Monitor Backoff
  // -------------------------------------------------------------------------
  {
    // A. Additional invalid hostnames & empty DNS resolution
    const extraBadHosts = [
      'vps.example.com.',
      '.leading.dot',
      'double..dot.com',
      'my_vps.internal',
      'bücher.de',
      'fe80::1%eth0',
      '[10.0.0.1]',
      `${'a'.repeat(64)}.example.com`
    ];
    for (const bad of extraBadHosts) {
      assert.throws(
        () => helpers.validateHostSyntax(bad),
        (e) => e && e.code === 'INVALID_HOST',
        `Expected invalid hostname to reject: ${bad}`
      );
    }
    await assert.rejects(
      () => helpers.assertSafeFleetHost('empty.example.com', { resolveHost: async () => [] }),
      (e) => e && e.code === 'DNS_RESOLUTION_FAILED'
    );

    // B. Malformed & adversarial parseProbeOutput edge cases (CRLF, garbage MEM_KB, avail>total clamp, negative load)
    const badProbe = helpers.parseProbeOutput(
      'OS=Linux\r\nARCH=x86_64\r\nCPUS=0\r\nLOAD=-5.4\r\nMEM_KB=abc def\r\nDISK_KB=bad data\r\nDOCKER=none\r\nDOCKER_SOCK=rw\r\nCADDY=none\r\n',
      -10,
      'ops'
    );
    assert.strictEqual(badProbe.status, 'degraded');
    assert.strictEqual(badProbe.resources.cpus, 1);
    assert.strictEqual(badProbe.resources.load1m, 0);
    assert.strictEqual(badProbe.resources.memoryTotalMb, 0);
    assert.strictEqual(badProbe.resources.latencyMs, 0);

    const clampedProbe = helpers.parseProbeOutput('MEM_KB=2048000 9999999\nDISK_KB=10485760 99999999\nDOCKER=27.0.0\n', 12, 'root');
    assert.strictEqual(clampedProbe.resources.memoryAvailableMb, clampedProbe.resources.memoryTotalMb, 'Available RAM must clamp <= total');
    assert.strictEqual(clampedProbe.resources.diskAvailableGb, clampedProbe.resources.diskTotalGb, 'Available disk must clamp <= total');

    // C. withPortTunnel error/timeout/MITM paths + _runMonitorTick exponential backoff (60s -> 120s -> 300s)
    const dir = createTempDir();
    try {
      const hostKey = makeFakeEd25519PubKey('edge-host');
      const clientPub = makeFakeEd25519PubKey('edge-client');
      let sshProbeCalls = 0;

      const fakeExec = async (bin, args) => {
        if (bin === 'ssh-keygen' && args.includes('-y')) return { stdout: `${clientPub.line}\n`, stderr: '' };
        if (bin === 'ssh-keyscan') return { stdout: `10.98.0.5 ${hostKey.keyType} ${hostKey.b64}\n`, stderr: '' };
        if (bin === 'ssh') {
          sshProbeCalls++;
          const err = new Error('Connection timed out');
          err.stderr = 'ssh: connect to host 10.98.0.5 port 22: Connection timed out';
          throw err;
        }
        throw new Error(`Unexpected execFile: ${bin}`);
      };

      const slowSpawner = createFakeTunnelSpawner({ connectDelayMs: 500 });
      const mgr = new ServerFleetManager({
        dataDir: dir,
        _execFile: fakeExec,
        _spawn: slowSpawner.spawnFn,
        _resolveHost: async () => ['10.98.0.5'],
        platform: 'win32',
        autoMonitor: false
      });
      const key = await mgr.importKey({ name: 'ek', privateKeyPem: makeFakePrivatePem('EDGE') });
      await mgr.addServer({ id: 'edge-node', name: 'Edge Node', host: '10.98.0.5', keyId: key.id });
      await mgr.pinHostKey('edge-node');

      // withPortTunnel timeout -> TUNNEL_TIMEOUT (504), kills child, wipes ephemeral key
      await assert.rejects(
        () => mgr.withPortTunnel('edge-node', 3000, async () => 'never', { connectTimeoutMs: 60 }),
        (e) => e && e.code === 'TUNNEL_TIMEOUT' && e.statusCode === 504
      );
      assert.strictEqual(slowSpawner.spawns[0].child.killed, true, 'Timed-out port tunnel child must be killed');
      assert.strictEqual(fs.readdirSync(path.join(dir, '.fleet-tmp')).length, 0, 'Ephemeral key must be wiped on timeout');

      // withPortTunnel callback throw -> still tears down tunnel child
      const okSpawner = createFakeTunnelSpawner({ connectDelayMs: 10 });
      mgr._spawn = okSpawner.spawnFn;
      await assert.rejects(
        () => mgr.withPortTunnel('edge-node', 3000, async () => { throw new Error('callback boom'); }),
        /callback boom/
      );
      assert.strictEqual(okSpawner.spawns[0].child.killed, true, 'Port tunnel child must close when callback throws');

      // _runMonitorTick exponential backoff: 1st fail >=60s, 2nd fail >=120s, 3rd fail >=300s, and skips before dueAt
      mgr._monitorRunning = true;
      const before1 = Date.now();
      await mgr._runMonitorTick();
      assert.strictEqual(sshProbeCalls, 1);
      const next1 = mgr._nextProbeAt.get('edge-node') - before1;
      assert.ok(next1 >= 55000 && next1 <= 65000, `1st failure backoff should be ~60s (got ${next1}ms)`);

      // Calling tick immediately before dueAt must skip probe
      await mgr._runMonitorTick();
      assert.strictEqual(sshProbeCalls, 1, 'Monitor tick must skip server before backoff expires');

      // Simulate backoff elapsed -> 2nd failure => 120s
      mgr._nextProbeAt.set('edge-node', 0);
      const before2 = Date.now();
      await mgr._runMonitorTick();
      const next2 = mgr._nextProbeAt.get('edge-node') - before2;
      assert.ok(next2 >= 115000 && next2 <= 125000, `2nd failure backoff should be ~120s (got ${next2}ms)`);

      // 3rd failure => 300s
      mgr._nextProbeAt.set('edge-node', 0);
      const before3 = Date.now();
      await mgr._runMonitorTick();
      const next3 = mgr._nextProbeAt.get('edge-node') - before3;
      assert.ok(next3 >= 295000 && next3 <= 305000, `3rd failure backoff should be ~300s (got ${next3}ms)`);

      // Locked host_key_mismatch server must be skipped completely by _runMonitorTick
      mgr._servers.get('edge-node').status = 'host_key_mismatch';
      mgr._nextProbeAt.set('edge-node', 0);
      await mgr._runMonitorTick();
      assert.strictEqual(sshProbeCalls, 3, 'Monitor tick must never probe a host_key_mismatch server');

      await mgr.shutdown();
    } finally {
      rmDirSafe(dir);
    }
    console.log('  ✓ Edge cases: invalid hostnames, malformed probe clamping, port-tunnel timeout/throw & monitor backoff');
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
