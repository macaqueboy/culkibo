'use strict';

const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const { WebSocket, WebSocketServer } = require('ws');

const containerTerminalService = require('../server/services/containerTerminalService');
const edgeShieldService = require('../server/services/edgeShieldService');
const caddyManager = require('../server/services/caddyManager');

const {
  ContainerTerminalService,
  ALLOWED_SHELLS,
  MAX_SESSIONS_PER_USER,
  IDLE_TIMEOUT_MS
} = containerTerminalService;

const {
  EdgeShieldService,
  DEFAULT_BLOCKED_PATHS,
  DEFAULT_AI_SCRAPER_UAS,
  verifyPowSolution
} = edgeShieldService;

/**
 * Starts a real loopback mock Docker Engine HTTP + raw `Upgrade: tcp` hijack server
 * implementing:
 *  - `POST /containers/:id/exec`
 *  - `POST /exec/:id/start` (`Connection: Upgrade`, `Upgrade: tcp`)
 *  - `POST /exec/:id/resize?h=<rows>&w=<cols>`
 */
async function startMockDockerEngine() {
  /** @type {Array<{ execId: string, container: string, cmd: string[] }>} */
  const createdExecs = [];
  /** @type {Array<{ execId: string, cols: number, rows: number }>} */
  const resizeEvents = [];
  /** @type {Set<import('net').Socket>} */
  const openSockets = new Set();
  let seq = 0;

  const srv = http.createServer((req, res) => {
    const urlStr = req.url || '';
    /** @type {Buffer[]} */
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const bodyStr = Buffer.concat(chunks).toString('utf8');

      // POST /containers/:id/exec
      const createMatch = /^\/containers\/([^/]+)\/exec$/.exec(urlStr);
      if (req.method === 'POST' && createMatch) {
        const container = decodeURIComponent(createMatch[1]);
        let parsed = {};
        try { parsed = JSON.parse(bodyStr || '{}'); } catch (e) {}
        const execId = `exec_${++seq}_${crypto.randomBytes(4).toString('hex')}`;
        createdExecs.push({
          execId,
          container,
          cmd: Array.isArray(/** @type {any} */ (parsed).Cmd) ? /** @type {any} */ (parsed).Cmd : []
        });
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ Id: execId }));
        return;
      }

      // POST /exec/:id/resize?h=..&w=..
      const resizeMatch = /^\/exec\/([^/]+)\/resize(?:\?(.*))?$/.exec(urlStr);
      if (req.method === 'POST' && resizeMatch) {
        const execId = decodeURIComponent(resizeMatch[1]);
        const qs = new URLSearchParams(resizeMatch[2] || '');
        resizeEvents.push({
          execId,
          rows: Number(qs.get('h') || 0),
          cols: Number(qs.get('w') || 0)
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{}');
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: 'Not found' }));
    });
  });

  srv.on('upgrade', (req, socket) => {
    const startMatch = /^\/exec\/([^/]+)\/start$/.exec(req.url || '');
    if (!startMatch) {
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
      socket.destroy();
      return;
    }
    const execId = decodeURIComponent(startMatch[1]);
    openSockets.add(socket);
    socket.on('close', () => openSockets.delete(socket));

    socket.write(
      'HTTP/1.1 101 UPGRADED\r\n' +
      'Content-Type: application/vnd.docker.raw-stream\r\n' +
      'Connection: Upgrade\r\n' +
      'Upgrade: tcp\r\n\r\n'
    );
    // Send initial shell prompt banner
    socket.write(`# culkibo-pty-ready:${execId}\n`);

    // Echo stdin back prefixed with `out:` (ignoring the initial JSON start body if present)
    socket.on('data', (buf) => {
      const txt = buf.toString('utf8');
      if (txt.includes('"Detach":false') && txt.includes('"Tty":true')) return;
      socket.write(`out:${txt}`);
    });
  });

  await new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve(undefined)));
  const addr = /** @type {import('net').AddressInfo} */ (srv.address());
  return {
    port: addr.port,
    transport: { host: '127.0.0.1', port: addr.port },
    createdExecs,
    resizeEvents,
    stop: () => new Promise((resolve) => {
      for (const s of openSockets) {
        try { s.destroy(); } catch (e) {}
      }
      if (typeof srv.closeAllConnections === 'function') srv.closeAllConnections();
      srv.close(() => resolve(undefined));
    })
  };
}

/**
 * Solves a SHA-256 PoW challenge deterministically in Node (for E2E test verification).
 * @param {string} salt
 * @param {number} difficulty
 */
function solvePow(salt, difficulty) {
  const prefix = '0'.repeat(difficulty);
  for (let nonce = 0; nonce < 5_000_000; nonce++) {
    const h = crypto.createHash('sha256').update(`${salt}:${nonce}`, 'utf8').digest('hex');
    if (h.startsWith(prefix)) return { nonce: String(nonce), hash: h };
  }
  throw new Error('Failed to find PoW solution within iteration budget');
}

async function testContainerTerminal() {
  assert.deepStrictEqual(ALLOWED_SHELLS, ['/bin/sh', '/bin/bash', '/bin/ash']);
  assert.strictEqual(MAX_SESSIONS_PER_USER, 4);
  assert.strictEqual(IDLE_TIMEOUT_MS, 15 * 60 * 1000);

  /** @type {Array<{ action: string, meta: any }>} */
  const auditEvents = [];
  const svc = new ContainerTerminalService({
    auditFn: (action, meta) => auditEvents.push({ action, meta })
  });

  // 1. Disallowed shell & invalid containerName rejections
  assert.throws(
    () => svc.issueTicket({ projectId: 'p1', containerName: 'app_1', userId: 'u1', shell: '/bin/zsh' }),
    (/** @type {any} */ err) => err && err.code === 'INVALID_SHELL',
    'Disallowed shell must be rejected'
  );
  assert.throws(
    () => svc.issueTicket({ projectId: 'p1', containerName: 'app;rm -rf /', userId: 'u1', shell: '/bin/sh' }),
    (/** @type {any} */ err) => err && err.code === 'INVALID_CONTAINER_NAME',
    'Shell metacharacters in containerName must be rejected'
  );

  // 2. Single-use ticket consumption & replay rejection
  const t1 = svc.issueTicket({ projectId: 'p1', containerName: 'web-prod-1', userId: 'u1', username: 'alice', shell: '/bin/bash', cols: 100, rows: 30 });
  assert.ok(t1.wsPath.startsWith('/ws/terminal?ticket='));
  const c1 = svc.consumeTicket(t1.ticket);
  assert.strictEqual(c1.valid, true);
  assert.strictEqual(c1.sessionSpec?.containerName, 'web-prod-1');
  const replay = svc.consumeTicket(t1.ticket);
  assert.strictEqual(replay.valid, false);
  assert.strictEqual(replay.reason, 'TICKET_ALREADY_USED', 'Replayed ticket MUST be rejected');
  const tampered = svc.consumeTicket(t1.ticket + 'x');
  assert.strictEqual(tampered.valid, false);
  assert.strictEqual(tampered.reason, 'INVALID_SIGNATURE', 'Tampered ticket MUST be rejected');

  // 3. Real mock Docker TCP hijack + live WebSocket terminal I/O + resize + max-4 sessions cap
  const dockerMock = await startMockDockerEngine();
  const wsHttpServer = http.createServer();
  const wss = new WebSocketServer({ noServer: true });

  wsHttpServer.on('upgrade', (req, socket, head) => {
    wss.handleUpgrade(req, socket, head, (ws) => {
      svc.attachWebSocket(ws, req, { transport: dockerMock.transport });
    });
  });

  await new Promise((resolve) => wsHttpServer.listen(0, '127.0.0.1', () => resolve(undefined)));
  const wsPort = /** @type {import('net').AddressInfo} */ (wsHttpServer.address()).port;

  /** @type {WebSocket[]} */
  const openedClients = [];
  try {
    // Helper to connect a WS client and wait for ready message
    const connectClient = (/** @type {string} */ wsPath) => new Promise((resolve, reject) => {
      const client = new WebSocket(`ws://127.0.0.1:${wsPort}${wsPath}`);
      openedClients.push(client);
      /** @type {Array<string>} */
      const messages = [];
      let readyMsg = null;

      const timer = setTimeout(() => reject(new Error('WS terminal connect timeout')), 5000);
      client.on('message', (raw) => {
        const str = raw.toString('utf8');
        messages.push(str);
        if (!readyMsg && str.startsWith('{')) {
          try {
            const parsed = JSON.parse(str);
            if (parsed.type === 'ready') {
              readyMsg = parsed;
              clearTimeout(timer);
              resolve({ client, readyMsg, messages });
            } else if (parsed.type === 'error') {
              clearTimeout(timer);
              resolve({ client, errorMsg: parsed, messages });
            }
          } catch (e) {}
        }
      });
      client.on('error', (err) => { clearTimeout(timer); reject(err); });
    });

    const ticketA = svc.issueTicket({ projectId: 'proj-term', containerName: 'api-green', userId: 'user-42', username: 'pablo', shell: '/bin/sh', cols: 120, rows: 32 });
    const connA = /** @type {any} */ (await connectClient(ticketA.wsPath));
    assert.ok(connA.readyMsg && connA.readyMsg.type === 'ready', 'Terminal WS must emit ready event');
    assert.strictEqual(connA.readyMsg.containerName, 'api-green');

    // Send bidirectional command and wait for echoed output
    const echoPromise = new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('Terminal I/O echo timeout')), 4000);
      connA.client.on('message', (/** @type {Buffer} */ raw) => {
        const s = raw.toString('utf8');
        if (s.includes('out:echo hello-culkibo')) {
          clearTimeout(t);
          resolve(s);
        }
      });
    });
    connA.client.send('echo hello-culkibo\n');
    const echoed = await echoPromise;
    assert.ok(String(echoed).includes('out:echo hello-culkibo'), 'Must pipe stdin -> Docker TCP hijack -> WS stdout');

    // Send JSON resize control frame and verify Docker Engine resize API call
    const resizedPromise = new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('Resize ack timeout')), 4000);
      connA.client.on('message', (/** @type {Buffer} */ raw) => {
        const s = raw.toString('utf8');
        if (s.startsWith('{') && s.includes('"type":"resized"')) {
          clearTimeout(t);
          resolve(JSON.parse(s));
        }
      });
    });
    connA.client.send(JSON.stringify({ type: 'resize', cols: 160, rows: 48 }));
    const resizedAck = /** @type {any} */ (await resizedPromise);
    assert.strictEqual(resizedAck.ok, true);
    assert.strictEqual(resizedAck.cols, 160);
    assert.strictEqual(resizedAck.rows, 48);
    assert.ok(
      dockerMock.resizeEvents.some((ev) => ev.cols === 160 && ev.rows === 48),
      'Docker Engine /exec/:id/resize must receive updated cols=160 & rows=48'
    );

    // Open 3 more sessions (total 4 for user-42), then confirm 5th ticket is blocked (MAX_SESSIONS_EXCEEDED)
    for (let i = 0; i < 3; i++) {
      const tk = svc.issueTicket({ projectId: 'proj-term', containerName: `api-green-${i}`, userId: 'user-42', shell: '/bin/sh' });
      const c = /** @type {any} */ (await connectClient(tk.wsPath));
      assert.strictEqual(c.readyMsg?.type, 'ready');
    }
    assert.strictEqual(svc.listSessions('proj-term').length, 4, 'Must track all 4 active sessions');
    assert.throws(
      () => svc.issueTicket({ projectId: 'proj-term', containerName: 'api-green-5', userId: 'user-42', shell: '/bin/sh' }),
      (/** @type {any} */ err) => err && err.code === 'MAX_SESSIONS_EXCEEDED' && err.status === 429,
      '5th concurrent session for same user MUST be rejected with 429 MAX_SESSIONS_EXCEEDED'
    );

    // Close one session and verify audit log records metadata ONLY (zero keystrokes)
    const firstSessionId = connA.readyMsg.sessionId;
    const closedRes = svc.closeSession(firstSessionId, 'test_cleanup');
    assert.strictEqual(closedRes.closed, true);
    assert.strictEqual(svc.listSessions('proj-term').length, 3);

    const serializedAudit = JSON.stringify(auditEvents);
    assert.ok(serializedAudit.includes('terminal.session.opened'));
    assert.ok(serializedAudit.includes('terminal.session.closed'));
    assert.ok(!serializedAudit.includes('echo hello-culkibo'), 'Audit log MUST NEVER store raw keystrokes');
  } finally {
    svc.closeAll('test_done');
    for (const c of openedClients) {
      try { c.terminate(); } catch (e) {}
    }
    wss.close();
    await new Promise((resolve) => wsHttpServer.close(() => resolve(undefined)));
    await dockerMock.stop();
  }

  console.log('  ✓ 1. Container Web Terminal: HMAC single-use tickets, replay/shell/max-4 guards, Docker TCP hijack bidirectional I/O, resize & audit metadata verified');
}

async function testEdgeShieldAndCaddy() {
  assert.ok(DEFAULT_BLOCKED_PATHS.includes('/.env'));
  assert.ok(DEFAULT_BLOCKED_PATHS.includes('/wp-config.php'));
  assert.ok(DEFAULT_AI_SCRAPER_UAS.includes('Bytespider'));
  assert.ok(DEFAULT_AI_SCRAPER_UAS.includes('GPTBot'));

  const shield = new EdgeShieldService({ hmacSecret: 'test-shield-secret-key-2026' });

  // 1. Issue & solve live SHA-256 PoW challenge (difficulty 3 -> instant <5ms in Node, tests full crypto path)
  const ipA = '203.0.113.10';
  const uaA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/537.36 Chrome/134.0';
  const ch = shield.issueChallenge({ ip: ipA, userAgent: uaA, domain: 'shop.example.com', difficulty: 3 });
  assert.strictEqual(ch.algorithm, 'sha256');
  assert.strictEqual(ch.difficulty, 3);
  assert.strictEqual(ch.domain, 'shop.example.com');

  const solved = solvePow(ch.salt, ch.difficulty);
  assert.strictEqual(verifyPowSolution(ch.salt, solved.nonce, ch.difficulty).valid, true);
  assert.strictEqual(verifyPowSolution(ch.salt, 'definitely-wrong-nonce-zzz', 4).valid, false);

  // Wrong IP binding must fail BEFORE consuming or minting clearance
  const wrongIpVerify = shield.verifySolution({
    challengeId: ch.challengeId,
    salt: ch.salt,
    nonce: solved.nonce,
    ip: '198.51.100.77',
    userAgent: uaA,
    domain: 'shop.example.com'
  });
  assert.strictEqual(wrongIpVerify.valid, false);
  assert.strictEqual(wrongIpVerify.reason, 'CLIENT_BINDING_MISMATCH');

  // Correct IP + UA + valid PoW -> mints signed `ckb_shield` cookie
  const okRes = shield.verifySolution({
    challengeId: ch.challengeId,
    salt: ch.salt,
    nonce: solved.nonce,
    ip: ipA,
    userAgent: uaA,
    domain: 'shop.example.com'
  });
  assert.strictEqual(okRes.valid, true);
  assert.ok(okRes.cookie && okRes.cookie.includes('.'));
  assert.ok(okRes.cookieHeader && okRes.cookieHeader.startsWith('ckb_shield='));

  // Replay of same challengeId MUST fail
  const replayRes = shield.verifySolution({
    challengeId: ch.challengeId,
    salt: ch.salt,
    nonce: solved.nonce,
    ip: ipA,
    userAgent: uaA,
    domain: 'shop.example.com'
  });
  assert.strictEqual(replayRes.valid, false);
  assert.strictEqual(replayRes.reason, 'CHALLENGE_REPLAYED');

  // Verify clearance cookie: happy path + Cookie header form + cross-IP/tamper rejections
  const ckOk = shield.verifyClearanceCookie(okRes.cookie, { ip: ipA, userAgent: uaA, domain: 'shop.example.com' });
  assert.strictEqual(ckOk.valid, true);
  const ckHeaderOk = shield.verifyClearanceCookie(`foo=bar; ckb_shield=${okRes.cookie}; baz=1`, { ip: ipA, userAgent: uaA });
  assert.strictEqual(ckHeaderOk.valid, true);

  const ckWrongIp = shield.verifyClearanceCookie(okRes.cookie, { ip: '198.51.100.99', userAgent: uaA });
  assert.strictEqual(ckWrongIp.valid, false);
  assert.strictEqual(ckWrongIp.reason, 'CLIENT_BINDING_MISMATCH');

  const ckTampered = shield.verifyClearanceCookie(okRes.cookie.slice(0, -2) + 'AA', { ip: ipA, userAgent: uaA });
  assert.strictEqual(ckTampered.valid, false);
  assert.strictEqual(ckTampered.reason, 'INVALID_SIGNATURE');

  // Render challenge HTML (WebCrypto SHA-256 + open-redirect protection)
  const html = shield.renderChallengeHtml(ch, '//evil.example.com/phish');
  assert.ok(html.includes('crypto.subtle.digest'), 'Challenge HTML must use native WebCrypto SHA-256');
  assert.ok(html.includes('/api/edge-shield/verify'));
  assert.ok(!html.includes('//evil.example.com'), 'Unsafe returnUrl must be sanitized to "/"');

  // 2. Caddy v2.11 native JSON compilation (zero extra plugins) + caddyManager.buildRoute integration
  const route = caddyManager.buildRoute({
    projectId: 'proj-shield',
    hostnames: ['shield.example.com'],
    upstreams: ['127.0.0.1:4100'],
    edgeShield: {
      enabled: true,
      powChallenge: true,
      difficulty: 4
    }
  });
  assert.strictEqual(route.handle[0].handler, 'subroute');
  const subroutes = route.handle[0].routes;
  assert.ok(subroutes.length >= 5, 'Must prepend path, SQLi/XSS, AI-scraper UA, PoW redirect before upstream');
  const serializedRoute = JSON.stringify(subroutes);
  assert.ok(serializedRoute.includes('/.env'), 'Must block /.env scanner probes');
  assert.ok(serializedRoute.includes('Bytespider'), 'Must block AI scrapers');
  assert.ok(serializedRoute.includes('ck_shield_sqli_xss'), 'Must include SQLi/XSS matcher');
  assert.ok(serializedRoute.includes('ckb_shield='), 'Must include PoW clearance cookie check');
  assert.ok(serializedRoute.includes('/api/edge-shield/challenge'), 'Must redirect unverified browsers to PoW challenge');
  // Upstream reverse_proxy must remain intact as the final fallback route
  const lastSub = subroutes[subroutes.length - 1];
  assert.strictEqual(lastSub.handle[0].handler, 'reverse_proxy');

  // Backwards compatibility: when edgeShield is unset, route has direct reverse_proxy (no subroute wrapper)
  const plainRoute = caddyManager.buildRoute({
    projectId: 'proj-plain',
    hostnames: ['plain.example.com'],
    upstreams: ['127.0.0.1:4100']
  });
  assert.strictEqual(plainRoute.handle[0].handler, 'reverse_proxy', 'Disabled/unset edgeShield must preserve exact prior Caddy JSON');

  const st = shield.getStatus([
    { domain: 'a.com', edgeShield: { enabled: true, powChallenge: true } },
    { domain: 'b.com', edgeShield: { enabled: true, powChallenge: false } },
    { domain: 'c.com' }
  ]);
  assert.strictEqual(st.enabledCount, 2);
  assert.strictEqual(st.powEnabledCount, 1);
  assert.strictEqual(st.zeroCaddyPlugins, true);

  console.log('  ✓ 2. Edge Bot-Shield & Hashcash PoW: live SHA-256 solve, ckb_shield HMAC/IP-UA binding, tamper/replay rejection, WebCrypto HTML & native Caddy v2.11 JSON verified');
}

async function runTerminalAndShieldTests() {
  console.log('\n🛡️  Testing Zero-Dep Container Web Terminal & Caddy Edge Bot-Shield (Hashcash PoW)...\n');
  await testContainerTerminal();
  await testEdgeShieldAndCaddy();
  console.log('\n✅ All Container Web Terminal & Edge Bot-Shield tests PASSED!\n');
}

module.exports = runTerminalAndShieldTests;

if (require.main === module) {
  runTerminalAndShieldTests().catch((err) => {
    console.error('❌ Terminal & Edge Shield test FAILED:', err);
    process.exit(1);
  });
}
