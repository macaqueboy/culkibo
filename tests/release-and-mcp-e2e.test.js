const assert = require('assert');
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  generateCycloneDxSbom,
  generateChecksums,
  verifyChecksums,
  writeReleaseProvenance
} = require('../scripts/release-provenance');

const ROOT_DIR = path.resolve(__dirname, '..');

/**
 * Spawns `bin/culkibo.js mcp --profile core` as an actual external child process
 * speaking newline-delimited JSON-RPC over stdin/stdout (identical to Claude Code,
 * Antigravity, Cursor, and Codex CLI).
 */
async function runRealStdioMcpE2E(dataDir) {
  return new Promise((resolve, reject) => {
    const cliPath = path.join(ROOT_DIR, 'bin', 'culkibo.js');
    const child = spawn(process.execPath, [cliPath, 'mcp', '--profile', 'core'], {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        NODE_ENV: 'test',
        CULKIBO_DATA_DIR: dataDir,
        CULKIBO_DISABLE_AUDIT_DISK: '1',
        CULKIBO_API_URL: ''
      },
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
      windowsHide: true
    });

    /** @type {Map<number, { resolve: (msg: any) => void, reject: (err: Error) => void, timer: NodeJS.Timeout }>} */
    const pending = new Map();
    let stdoutBuf = '';
    let stderrBuf = '';

    child.stderr.on('data', (chunk) => {
      stderrBuf += chunk.toString('utf8');
    });

    child.stdout.on('data', (chunk) => {
      stdoutBuf += chunk.toString('utf8');
      const lines = stdoutBuf.split(/\r?\n/);
      stdoutBuf = lines.pop() || '';
      for (const raw of lines) {
        const trimmed = raw.trim();
        if (!trimmed) continue;
        try {
          const msg = JSON.parse(trimmed);
          if (msg && typeof msg.id === 'number' && pending.has(msg.id)) {
            const p = pending.get(msg.id);
            pending.delete(msg.id);
            if (p) {
              clearTimeout(p.timer);
              p.resolve(msg);
            }
          }
        } catch (e) {
          // Ignore any unexpected non-JSON line
        }
      }
    });

    const sendRpc = (id, method, params = {}) => new Promise((res, rej) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        rej(new Error(`MCP stdio timeout waiting for id=${id} (${method}). stderr=${stderrBuf}`));
      }, 15000);
      pending.set(id, { resolve: res, reject: rej, timer });
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });

    const sendNotification = (method, params = {}) => {
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
    };

    const exitPromise = new Promise((resExit) => {
      child.on('close', (code, signal) => resExit({ code, signal }));
    });

    (async () => {
      try {
        // 1. Handshake: initialize -> notifications/initialized + MCP 2026-07-28 server/discover
        const initRes = await sendRpc(1, 'initialize', {
          protocolVersion: '2026-07-28',
          capabilities: {},
          clientInfo: { name: 'culkibo-external-e2e', version: '1.2.0' }
        });
        assert.ok(initRes.result, `initialize failed: ${JSON.stringify(initRes)}`);
        assert.ok(
          initRes.result.protocolVersion === '2024-11-05' || initRes.result.protocolVersion === '2026-07-28',
          `Unexpected MCP protocolVersion: ${initRes.result.protocolVersion}`
        );
        assert.ok(
          initRes.result.capabilities &&
          initRes.result.capabilities.extensions &&
          initRes.result.capabilities.extensions['io.modelcontextprotocol/ui'],
          'MCP initialize must advertise io.modelcontextprotocol/ui MCP Apps extension'
        );
        sendNotification('notifications/initialized', {});

        const discoverRes = await sendRpc(10, 'server/discover', {});
        assert.ok(discoverRes.result, `server/discover failed: ${JSON.stringify(discoverRes)}`);
        assert.ok(
          Array.isArray(discoverRes.result.supportedVersions) && discoverRes.result.supportedVersions.includes('2026-07-28'),
          `Expected 2026-07-28 in server/discover supportedVersions: ${JSON.stringify(discoverRes.result)}`
        );

        // 2. tools/list -> core profile returns compact 17-tool subset (-80%+ savings)
        const toolsRes = await sendRpc(2, 'tools/list', {});
        const tools = (toolsRes.result && toolsRes.result.tools) || [];
        assert.strictEqual(tools.length, 17, `Expected 17 core MCP tools over stdio, got ${tools.length}`);

        // 3. prompts/list -> 13 prompts (8 native playbooks + 5 legacy)
        const promptsRes = await sendRpc(3, 'prompts/list', {});
        const prompts = (promptsRes.result && promptsRes.result.prompts) || [];
        assert.strictEqual(prompts.length, 13, `Expected 13 MCP prompts over stdio, got ${prompts.length}`);

        // 4. resources/list -> 10 resources including all 3 ui://culkibo/* MCP Apps
        const resourcesRes = await sendRpc(4, 'resources/list', {});
        const resources = (resourcesRes.result && resourcesRes.result.resources) || [];
        assert.strictEqual(resources.length, 10, `Expected 10 MCP resources over stdio, got ${resources.length}`);
        const uris = resources.map((r) => r.uri);
        assert.ok(uris.includes('ui://culkibo/topology'));
        assert.ok(uris.includes('ui://culkibo/incident-remediator'));
        assert.ok(uris.includes('ui://culkibo/coolify-migration-diff'));

        // 5. resources/read -> ui://culkibo/topology (text/html;profile=mcp-app + strict CSP + 0 external URLs)
        const topoRead = await sendRpc(5, 'resources/read', { uri: 'ui://culkibo/topology' });
        const content = topoRead.result && Array.isArray(topoRead.result.contents) ? topoRead.result.contents[0] : null;
        assert.ok(content, `resources/read returned no content: ${JSON.stringify(topoRead)}`);
        assert.strictEqual(content.mimeType, 'text/html;profile=mcp-app');
        assert.ok(content._meta && content._meta.ui && content._meta.ui.csp, 'MCP App must carry strict _meta.ui.csp');
        assert.ok(String(content.text || '').includes("default-src 'none'"), 'MCP App HTML must declare default-src none CSP');
        assert.ok(!/https?:\/\//i.test(String(content.text || '')), 'MCP App HTML must contain 0 external URLs');

        // 6. tools/call -> culkibo_smartpack_plan (works via direct call even under core profile)
        const spCall = await sendRpc(6, 'tools/call', {
          name: 'culkibo_smartpack_plan',
          arguments: {}
        });
        assert.ok(spCall.result && spCall.result.isError !== true, `culkibo_smartpack_plan failed: ${JSON.stringify(spCall)}`);
        const spPayload = spCall.result.structuredContent || JSON.parse((spCall.result.content && spCall.result.content[0] && spCall.result.content[0].text) || '{}');
        assert.ok(spPayload.plan && spPayload.plan.schemaVersion === 'culkibo.smartpack/v1', `Expected culkibo.smartpack/v1 schema: ${JSON.stringify(spPayload).slice(0, 300)}`);
        assert.ok(typeof spPayload.stack === 'string' && spPayload.stack.length > 0, 'Expected detected stack in SmartPack MCP tool result');

        // 7. Clean EOF exit code 0
        child.stdin.end();
        const { code, signal } = await exitPromise;
        assert.strictEqual(code, 0, `Expected clean exit 0 from culkibo mcp stdio, got code=${code} signal=${signal} stderr=${stderrBuf}`);
        resolve({
          toolsCount: tools.length,
          promptsCount: prompts.length,
          resourcesCount: resources.length,
          topologyBytes: Buffer.byteLength(String(content.text || ''), 'utf8')
        });
      } catch (err) {
        try { child.kill('SIGTERM'); } catch (e) {}
        reject(err);
      }
    })();
  });
}

/**
 * Isolated subprocess test verifying:
 *  - Clean fresh CULKIBO_DATA_DIR boots with 0 hardcoded Spanish starter projects/domains
 *  - GET /api/system/sbom returns valid CycloneDX 1.6 JSON (`application/vnd.cyclonedx+json`)
 *  - POST /api/import/coolify/stream-plan returns zero-shell streaming plan + SHA-256 verification
 */
function runFreshStoreAndApiSmokeSuite() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-fresh-store-c3-'));
  const runnerPath = path.join(tmpDir, 'fresh-runner.js');
  fs.writeFileSync(runnerPath, `
const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');

const TMP_DIR = ${JSON.stringify(tmpDir)};
const ROOT_DIR = ${JSON.stringify(ROOT_DIR)};
process.env.NODE_ENV = 'test';
process.env.CULKIBO_DATA_DIR = TMP_DIR;
process.env.CULKIBO_DISABLE_AUDIT_DISK = '1';

const express = require(path.join(ROOT_DIR, 'node_modules', 'express'));
const auth = require(path.join(ROOT_DIR, 'server/middleware/auth'));
const projectManager = require(path.join(ROOT_DIR, 'server/services/projectManager'));
const domainManager = require(path.join(ROOT_DIR, 'server/services/domainManager'));
const apiRouter = require(path.join(ROOT_DIR, 'server/routes/api'));

// 1. Fresh isolated CULKIBO_DATA_DIR MUST boot with 0 hardcoded Spanish/demo starter records
assert.strictEqual(projectManager.getAll().length, 0, 'Fresh CULKIBO_DATA_DIR must start with 0 starter projects');
assert.strictEqual(domainManager.listDomains().length, 0, 'Fresh CULKIBO_DATA_DIR must start with 0 starter domains');
assert.strictEqual(fs.existsSync(path.join(TMP_DIR, 'projects.json')), false, 'Empty fresh boot must not write demo projects.json');
assert.strictEqual(fs.existsSync(path.join(TMP_DIR, 'domains.json')), false, 'Empty fresh boot must not write demo domains.json');

function reqHttp(port, method, reqPath, { token, body } = {}) {
  return new Promise((resolve, reject) => {
    const raw = body !== undefined ? JSON.stringify(body) : null;
    const headers = { host: 'panel.example.test' };
    if (token) headers.authorization = 'Bearer ' + token;
    if (raw !== null) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = Buffer.byteLength(raw);
    }
    const req = http.request({ hostname: '127.0.0.1', port, method, path: reqPath, headers }, (res) => {
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
    if (raw !== null) req.write(raw);
    req.end();
  });
}

(async () => {
  const app = express();
  app.use(express.json());
  app.use('/api', auth.authMiddleware, apiRouter);
  const srv = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  const port = srv.address().port;
  const token = auth.resolveToken();
  try {
    // 2. GET /api/system/sbom -> CycloneDX 1.6 JSON
    const sbomRes = await reqHttp(port, 'GET', '/api/system/sbom', { token });
    assert.strictEqual(sbomRes.status, 200, 'GET /api/system/sbom failed: ' + sbomRes.text);
    assert.ok(String(sbomRes.headers['content-type'] || '').includes('application/vnd.cyclonedx+json'));
    assert.strictEqual(sbomRes.json.bomFormat, 'CycloneDX');
    assert.strictEqual(sbomRes.json.specVersion, '1.6');
    assert.strictEqual(sbomRes.json.metadata.component.version, '1.2.0');

    // 3. POST /api/import/coolify/stream-plan -> zero-shell stream pipelines + SHA-256 verify
    const streamRes = await reqHttp(port, 'POST', '/api/import/coolify/stream-plan', {
      token,
      body: {
        snapshot: {
          apps: [{ uuid: 'app-1', name: 'Web', local_persistent_volumes: [{ name: 'uploads_vol', mount_path: '/app/uploads' }] }],
          databases: [{ uuid: 'db-1', name: 'PrimaryPG', database_type: 'postgresql', postgres_user: 'app', postgres_db: 'appdb' }],
          services: []
        },
        options: { sourceHost: '198.51.100.10', sourceUser: 'root' }
      }
    });
    assert.strictEqual(streamRes.status, 200, 'POST /api/import/coolify/stream-plan failed: ' + streamRes.text);
    assert.strictEqual(streamRes.json.ok, true);
    assert.strictEqual(streamRes.json.zeroShell, true);
    assert.strictEqual(streamRes.json.databaseStreams.length, 1);
    assert.strictEqual(streamRes.json.volumeStreams.length, 1);

    // Unsafe flag injection rejected with 400
    const badStream = await reqHttp(port, 'POST', '/api/import/coolify/stream-plan', {
      token,
      body: { snapshot: { databases: [] }, options: { sourceHost: '-oProxyCommand=evil' } }
    });
    assert.strictEqual(badStream.status, 400);

    console.log('FRESH_STORE_AND_C3_API_OK');
  } finally {
    await new Promise((r) => srv.close(r));
  }
})().catch((err) => { console.error(err); process.exit(1); });
`, 'utf8');

  try {
    const out = execFileSync(process.execPath, [runnerPath], { cwd: ROOT_DIR, encoding: 'utf8', timeout: 30000 });
    assert.ok(out.includes('FRESH_STORE_AND_C3_API_OK'), `Fresh store & C3 API test failed:\n${out}`);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testReleaseAndMcpE2E() {
  console.log('📦 Testing External MCP Client Stdio E2E, CycloneDX 1.6 SBOM Provenance & Fresh-Store Boot...');

  // 1. Real external child process speaking MCP 2026-07-28 JSON-RPC over stdio
  const mcpTmp = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mcp-stdio-e2e-'));
  try {
    const mcpStats = await runRealStdioMcpE2E(mcpTmp);
    console.log(
      `  ✓ 1. Real external MCP stdio E2E passed (core=${mcpStats.toolsCount} tools, ${mcpStats.promptsCount} prompts, ${mcpStats.resourcesCount} resources incl. 3 MCP Apps, topology=${mcpStats.topologyBytes}B, clean exit 0)`
    );
  } finally {
    fs.rmSync(mcpTmp, { recursive: true, force: true });
  }

  // 2. CycloneDX 1.6 SBOM, SHA-256 Checksums, CLI & Tamper Detection
  const outTmp = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-sbom-out-'));
  const tamperTmp = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-sbom-tamper-'));
  try {
    const sbom = generateCycloneDxSbom({ rootDir: ROOT_DIR });
    assert.strictEqual(sbom.bomFormat, 'CycloneDX');
    assert.strictEqual(sbom.specVersion, '1.6');
    assert.ok(/^urn:uuid:[0-9a-f-]{36}$/i.test(sbom.serialNumber));
    assert.strictEqual(sbom.metadata.component.name, 'culkibo');
    assert.strictEqual(sbom.metadata.component.version, '1.2.0');
    const rootDepsProp = sbom.metadata.component.properties.find((p) => p.name === 'culkibo:root_runtime_dependencies');
    const colDepsProp = sbom.metadata.component.properties.find((p) => p.name === 'culkibo:collector_runtime_dependencies');
    assert.strictEqual(rootDepsProp && rootDepsProp.value, '6', 'ROOT_DEPS invariant must be 6 in SBOM');
    assert.strictEqual(colDepsProp && colDepsProp.value, '0', 'COLLECTOR_DEPS invariant must be 0 in SBOM');
    assert.ok(sbom.components.length >= 6);
    for (const comp of sbom.components) {
      assert.ok(String(comp.purl || '').startsWith('pkg:npm/'), `Invalid PURL in SBOM: ${comp.purl}`);
    }

    const written = writeReleaseProvenance({ rootDir: ROOT_DIR, outDir: outTmp });
    assert.strictEqual(written.ok, true);
    assert.strictEqual(written.counts.rootDeps, 6);
    assert.strictEqual(written.counts.collectorDeps, 0);
    assert.ok(fs.existsSync(written.files.sbom));
    assert.ok(fs.existsSync(written.files.checksums));
    assert.ok(fs.existsSync(written.files.provenance));

    const verified = verifyChecksums(written.files.checksums, { rootDir: ROOT_DIR });
    assert.strictEqual(verified.valid, true, `Checksums verification failed: ${JSON.stringify(verified)}`);
    assert.strictEqual(verified.checked, written.counts.checksumFiles);

    // Tamper detection on isolated copy
    fs.writeFileSync(path.join(tamperTmp, 'core.js'), 'module.exports = { safe: true };\n', 'utf8');
    const cs = generateChecksums({ rootDir: tamperTmp, files: ['core.js'] });
    assert.strictEqual(verifyChecksums(cs.text, { rootDir: tamperTmp }).valid, true);
    fs.writeFileSync(path.join(tamperTmp, 'core.js'), 'module.exports = { safe: false };\n', 'utf8');
    const tampered = verifyChecksums(cs.text, { rootDir: tamperTmp });
    assert.strictEqual(tampered.valid, false, 'Modified file MUST fail SHA-256 checksum verification');
    assert.strictEqual(tampered.mismatched.length, 1);

    // CLI invocation check (`node scripts/release-provenance.js --out-dir <dir> --json`)
    const cliOutDir = path.join(outTmp, 'cli-run');
    const cliOut = execFileSync(
      process.execPath,
      [path.join(ROOT_DIR, 'scripts', 'release-provenance.js'), '--out-dir', cliOutDir, '--json'],
      { cwd: ROOT_DIR, encoding: 'utf8', timeout: 15000 }
    );
    const cliJson = JSON.parse(cliOut);
    assert.strictEqual(cliJson.ok, true);
    assert.strictEqual(cliJson.version, '1.2.0');
    assert.strictEqual(cliJson.counts.rootDeps, 6);

    console.log(
      `  ✓ 2. CycloneDX 1.6 SBOM (${written.counts.sbomComponents} components, ROOT_DEPS=6, COLLECTOR_DEPS=0), SHA-256 (${written.counts.checksumFiles} files) & tamper rejection verified`
    );
  } finally {
    fs.rmSync(outTmp, { recursive: true, force: true });
    fs.rmSync(tamperTmp, { recursive: true, force: true });
  }

  // 3. Fresh CULKIBO_DATA_DIR zero-starter-records + GET /api/system/sbom + POST /api/import/coolify/stream-plan
  runFreshStoreAndApiSmokeSuite();
  console.log('  ✓ 3. Fresh CULKIBO_DATA_DIR zero-starter boot, GET /api/system/sbom & POST /api/import/coolify/stream-plan verified');

  console.log('✅ All Release Provenance, CycloneDX 1.6 SBOM & External MCP Stdio E2E tests passed!\n');
}

module.exports = testReleaseAndMcpE2E;

if (require.main === module) {
  testReleaseAndMcpE2E().catch((err) => {
    console.error('❌ Release & MCP E2E test failure:', err);
    process.exit(1);
  });
}
