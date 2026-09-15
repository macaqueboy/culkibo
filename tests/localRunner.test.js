const assert = require('assert');
const path = require('path');
const fs = require('fs');
const http = require('http');
const localRunner = require('../server/services/localRunner');

async function testLocalRunner() {
  console.log('🧪 Testing Local Runner Engine (Processes, Static, Git, Ports)...');

  // ----------------------------------------------------
  // 1. Test Git URL Normalization
  // ----------------------------------------------------
  console.log('  1. Testing normalizeGitUrl...');
  
  // Test short slug: owner/repo
  const slugUrl = localRunner.normalizeGitUrl('macaqueboy/toolsuite');
  assert.ok(slugUrl, 'Slug must return a valid URL');
  assert.ok(slugUrl.includes('github.com/macaqueboy/toolsuite.git'), 'Slug must resolve to github.com repository');
  
  // The PAT must NEVER appear in the clone URL. A token embedded in the URL
  // leaks into `ps` output, into the cloned repo's .git/config, and into git's
  // own error messages. Authentication goes through GIT_ASKPASS instead, so the
  // secret only ever lives in the child process's environment.
  //
  // Hermetic: plant a throwaway token so this path is exercised on every
  // machine, not only on one that happens to have GitHub connected.
  const ghPath = path.join(process.cwd(), 'data', 'github.json');
  const hadGhFile = fs.existsSync(ghPath);
  const originalGh = hadGhFile ? fs.readFileSync(ghPath, 'utf8') : null;
  const probeToken = 'ghp_TESTTOKEN_localRunner_do_not_use_0123456789';

  try {
    fs.mkdirSync(path.dirname(ghPath), { recursive: true });
    fs.writeFileSync(ghPath, JSON.stringify({ token: probeToken, connected: true }, null, 2), 'utf8');

    const authedUrl = localRunner.normalizeGitUrl('macaqueboy/toolsuite');
    assert.ok(!authedUrl.includes(probeToken), 'La URL de clonado NO debe contener el token');
    assert.ok(authedUrl.includes('x-access-token@github.com'), 'La URL debe llevar el usuario de credencial, no el secreto');

    const auth = localRunner.gitAuthEnv();
    const helperPath = auth.env.GIT_ASKPASS;
    try {
      assert.strictEqual(auth.env.CULKIBO_GIT_TOKEN, probeToken, 'El token debe viajar por el entorno del hijo');
      assert.ok(helperPath && fs.existsSync(helperPath), 'Debe existir el helper askpass');
      assert.strictEqual(auth.env.GIT_TERMINAL_PROMPT, '0', 'git nunca debe abrir un prompt interactivo');
      assert.ok(!fs.readFileSync(helperPath, 'utf8').includes(probeToken), 'El helper no debe contener el secreto en disco');
    } finally {
      auth.cleanup();
    }
    assert.ok(!fs.existsSync(helperPath), 'cleanup() debe borrar el helper temporal');

    // Secrets must never survive into a log line or the UI.
    const leaky = `fatal: could not read from https://x-access-token:${probeToken}@github.com/a/b.git`;
    const redacted = localRunner.redactSecrets(leaky);
    assert.ok(!redacted.includes(probeToken), 'redactSecrets debe eliminar el token de los mensajes');
    console.log('  ✓ El PAT no aparece en la URL, viaja por GIT_ASKPASS y se redacta en los errores');
  } finally {
    if (hadGhFile) fs.writeFileSync(ghPath, originalGh, 'utf8');
    else if (fs.existsSync(ghPath)) fs.unlinkSync(ghPath);
  }

  // Test SSH URL
  const sshUrl = localRunner.normalizeGitUrl('git@github.com:macaqueboy/caleki.git');
  assert.ok(sshUrl.includes('github.com/macaqueboy/caleki.git'), 'SSH URL must convert to HTTPS format');

  // Test Standard HTTPS URL
  const httpsUrl = localRunner.normalizeGitUrl('https://github.com/macaqueboy/toolsuite');
  assert.ok(httpsUrl.includes('github.com/macaqueboy/toolsuite.git'), 'HTTPS URL must be normalized with .git');

  // Test null / undefined
  assert.strictEqual(localRunner.normalizeGitUrl(null), null);
  assert.strictEqual(localRunner.normalizeGitUrl(''), null);
  console.log('  ✓ Git URL normalization & token injection passed');

  // ----------------------------------------------------
  // 2. Test Port Allocation & Zombie Process Cleanup
  // ----------------------------------------------------
  console.log('  2. Testing port allocation and zombie cleanup...');
  const basePort = 8400 + Math.floor(Math.random() * 500);
  const allocatedPort = await localRunner.getAvailablePort(basePort);
  assert.ok(allocatedPort >= basePort, 'Allocated port must be >= basePort');

  // Test collision avoidance: Occupy the port, ensure next port is found
  const dummyServer = http.createServer((req, res) => res.end('occupied'));
  await new Promise(r => dummyServer.listen(allocatedPort, '0.0.0.0', r));
  
  // Without killing dummyServer directly, call getAvailablePort on allocatedPort + 1
  const nextPort = await localRunner.getAvailablePort(allocatedPort + 1);
  assert.notStrictEqual(nextPort, allocatedPort, 'Must not allocate the occupied port');
  
  await new Promise(r => dummyServer.close(r));
  console.log(`  ✓ Port allocation and collision avoidance passed (ports: ${allocatedPort}, ${nextPort})`);

  // ----------------------------------------------------
  // 3. Test Static Web Server Hosting
  // ----------------------------------------------------
  console.log('  3. Testing static web hosting mode...');
  const testDir = path.join(process.cwd(), 'projects', 'test_static_app');
  if (!fs.existsSync(testDir)) fs.mkdirSync(testDir, { recursive: true });
  const testHtml = '<!DOCTYPE html><html><body><h1>Culkibo Test Static OK</h1></body></html>';
  fs.writeFileSync(path.join(testDir, 'index.html'), testHtml, 'utf8');

  const testProject = {
    id: 'test_static_app',
    name: 'Test Static App',
    localPort: allocatedPort
  };

  const staticResult = await localRunner.startStaticProject(testProject, testDir, allocatedPort);
  assert.strictEqual(staticResult.success, true);
  assert.strictEqual(localRunner.isRunning('test_static_app'), true);

  // Fetch static server
  const staticRes = await fetch(`http://localhost:${allocatedPort}/`);
  const staticText = await staticRes.text();
  assert.strictEqual(staticRes.status, 200);
  assert.ok(staticText.includes('Culkibo Test Static OK'), 'Static server must serve index.html');

  // Clean up static runner
  await localRunner.stop('test_static_app');
  assert.strictEqual(localRunner.isRunning('test_static_app'), false);
  try { fs.rmSync(testDir, { recursive: true, force: true }); } catch(e) {}
  console.log('  ✓ Static web hosting and graceful shutdown passed');

  // ----------------------------------------------------
  // 4. Test Fallback Sandbox Server
  // ----------------------------------------------------
  console.log('  4. Testing fallback sandbox server...');
  const fallbackProject = {
    id: 'test_fallback_app',
    name: 'Fallback Sandbox',
    icon: '📦'
  };
  const fbPort = allocatedPort + 2;
  const fbResult = await localRunner.startFallbackServer(fallbackProject, testDir, fbPort);
  assert.strictEqual(fbResult.success, true);
  assert.strictEqual(localRunner.isRunning('test_fallback_app'), true);

  const fbRes = await fetch(`http://localhost:${fbPort}/`);
  const fbText = await fbRes.text();
  assert.strictEqual(fbRes.status, 200);
  assert.ok(fbText.includes('Fallback Sandbox'), 'Fallback server must display project title');
  assert.ok(fbText.includes('Culkibo v1.0.0 Local Runner'), 'Fallback server must identify Culkibo');

  await localRunner.stop('test_fallback_app');
  assert.strictEqual(localRunner.isRunning('test_fallback_app'), false);
  console.log('  ✓ Fallback sandbox server and stop passed');

  // ----------------------------------------------------
  // 4b. Regressions: path traversal, id collisions, Unicode names
  // ----------------------------------------------------
  console.log('  4b. Testing hardening regressions (traversal, ids, nombres Unicode)...');

  const travPort = allocatedPort + 3;
  const travProject = { id: 'test_traversal_app', name: 'Traversal Probe', icon: '🛡️' };
  await localRunner.startStaticProject(travProject, testDir, travPort);

  // A raw request target with `..` must never escape the served root.
  const rawTraversal = await new Promise((resolve, reject) => {
    const req = require('http').request(
      { host: '127.0.0.1', port: travPort, method: 'GET', path: '/../../../package.json' },
      (r) => {
        let body = '';
        r.on('data', (c) => { body += c; });
        r.on('end', () => resolve({ status: r.statusCode, body }));
      }
    );
    req.on('error', reject);
    req.end();
  });
  assert.ok(
    !rawTraversal.body.includes('"culkibo"') || rawTraversal.status === 403,
    'Static server must not serve files outside its root via path traversal'
  );

  const encodedTraversal = await fetch(`http://127.0.0.1:${travPort}/%2e%2e%2f%2e%2e%2fpackage.json`);
  const encodedBody = await encodedTraversal.text();
  assert.ok(
    !encodedBody.includes('"culkibo"'),
    'Static server must not serve files outside its root via encoded traversal'
  );
  await localRunner.stop('test_traversal_app');
  console.log('  ✓ Static server path traversal blocked (raw and percent-encoded)');

  // Project ids created in the same millisecond must not collide.
  const Project = require('../server/models/Project');
  const ids = new Set();
  for (let i = 0; i < 500; i++) ids.add(new Project({ name: `Bulk ${i}` }).id);
  assert.strictEqual(ids.size, 500, 'Project ids must be unique even within one millisecond');
  console.log('  ✓ Project id uniqueness under bulk creation passed (500/500 únicos)');

  // Spanish names must survive sanitisation; markup must not.
  const projectManager = require('../server/services/projectManager');
  const payload = { name: 'Aplicación Núcleo ñandú 🚀 <script>alert(1)</script>' };
  projectManager.validateProjectData(payload);
  assert.ok(payload.name.includes('Aplicación'), 'Accents must be preserved');
  assert.ok(payload.name.includes('Núcleo'), 'Accents must be preserved');
  assert.ok(payload.name.includes('ñandú'), 'ñ must be preserved');
  assert.ok(payload.name.includes('🚀'), 'Emoji must be preserved');
  assert.ok(!payload.name.includes('<'), 'Angle brackets must be stripped');
  assert.ok(!payload.name.includes('>'), 'Angle brackets must be stripped');
  console.log(`  ✓ Unicode-safe name sanitisation passed ("${payload.name}")`);

  // ----------------------------------------------------
  // 5. Test Real Running Projects (ToolSuite / Calma)
  // ----------------------------------------------------
  console.log('  5. Testing real application live execution (ToolSuite on :7325)...');
  try {
    const liveRes = await fetch('http://localhost:7325/', { signal: AbortSignal.timeout(5000) });
    if (liveRes.status === 200) {
      const liveText = await liveRes.text();
      assert.ok(liveText.length > 500, 'Live application must serve complete page');
      console.log(`  ✓ ToolSuite is actively running and serving real Next.js application (${liveText.length} bytes, HTTP 200)`);
    }
  } catch(e) {
    console.log(`  ℹ Note: ToolSuite check info: ${e.message}`);
  }

  console.log('✅ All Local Runner tests passed!\n');
}

module.exports = testLocalRunner;

if (require.main === module) {
  testLocalRunner().then(() => process.exit(0)).catch(err => {
    console.error(err);
    process.exit(1);
  });
}
