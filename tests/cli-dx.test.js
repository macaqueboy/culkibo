const assert = require('assert');
const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const CLI_PATH = path.resolve(__dirname, '..', 'bin', 'culkibo.js');

/**
 * Ejecuta el CLI `bin/culkibo.js` como subproceso aislado asíncrono (sin shell y sin
 * bloquear el event loop para que el mock HTTP local responda al instante).
 * @param {string[]} args
 * @param {{ cwd?: string, env?: Record<string, string>, input?: string }} [opts]
 * @returns {Promise<{ status: number | null, stdout: string, stderr: string }>}
 */
function runCli(args, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_PATH, ...args], {
      cwd: opts.cwd || process.cwd(),
      env: { ...process.env, ...(opts.env || {}) },
      shell: false,
      windowsHide: true
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (e) {}
      reject(new Error(`Timeout ejecutando CLI: ${args.join(' ')}`));
    }, 15000);
    if (timer.unref) timer.unref();
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (err) => { clearTimeout(timer); reject(err); });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ status: code, stdout, stderr });
    });
    if (opts.input !== undefined) {
      child.stdin.write(opts.input);
    }
    child.stdin.end();
  });
}

async function testCliDx() {
  console.log('🧪 Testing Culkibo CLI DX (init, up, logs, env, exec, releases, rollback, backup, doctor --json, CULKIBO_API_URL)...');

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-cli-dx-'));
  const dataRoot = path.join(tmpRoot, 'data-root');
  const appDir = path.join(tmpRoot, 'my-next-app');
  fs.mkdirSync(dataRoot, { recursive: true });
  fs.mkdirSync(appDir, { recursive: true });

  const isolatedEnv = {
    CULKIBO_DATA_DIR: dataRoot,
    CULKIBO_API_URL: '',
    CULKIBO_TOKEN: '',
    NODE_ENV: 'test'
  };

  /** @type {http.Server | null} */
  let mockServer = null;

  try {
    // 1. culkibo init: autodetecta Next.js + .env (sin filtrar secretos en culkibo.yaml) + .culkiboignore
    fs.writeFileSync(path.join(appDir, 'package.json'), JSON.stringify({
      name: '@acme/shop-web',
      scripts: { build: 'next build', start: 'next start' },
      dependencies: { next: '15.0.0', react: '19.0.0' }
    }, null, 2), 'utf8');
    fs.writeFileSync(path.join(appDir, 'pnpm-lock.yaml'), 'lockfileVersion: 9.0\n', 'utf8');
    fs.writeFileSync(
      path.join(appDir, '.env'),
      'NODE_ENV=production\nSTRIPE_SECRET_KEY=sk_live_never_commit_me_999999\nDATABASE_URL=postgres://app:topsecret@db:5432/shop\n',
      'utf8'
    );

    const initRes = await runCli(['init', appDir, '--json'], { env: isolatedEnv });
    assert.strictEqual(initRes.status, 0, `culkibo init falló: ${initRes.stderr} ${initRes.stdout}`);
    const initJson = JSON.parse(initRes.stdout);
    assert.strictEqual(initJson.ok, true);
    assert.strictEqual(initJson.framework, 'Next.js');
    assert.strictEqual(initJson.containerPort, 3000);
    assert.ok(initJson.vaultRefs.includes('STRIPE_SECRET_KEY'));
    assert.ok(initJson.vaultRefs.includes('DATABASE_URL'));
    assert.ok(initJson.databases.includes('postgres'));

    const yamlPath = path.join(appDir, 'culkibo.yaml');
    const ignorePath = path.join(appDir, '.culkiboignore');
    assert.strictEqual(fs.existsSync(yamlPath), true);
    assert.strictEqual(fs.existsSync(ignorePath), true);
    const yamlContent = fs.readFileSync(yamlPath, 'utf8');
    assert.ok(yamlContent.startsWith('# yaml-language-server: $schema='), 'Debe incluir cabecera $schema para IDE');
    assert.ok(!yamlContent.includes('sk_live_never_commit_me_999999'), 'culkibo init JAMÁS debe escribir secretos en claro');
    assert.ok(!yamlContent.includes('topsecret'), 'culkibo init JAMÁS debe escribir contraseñas DB en claro');
    assert.ok(yamlContent.includes('${vault.STRIPE_SECRET_KEY}'));

    // Re-ejecutar init sin --force debe fallar limpiamente con JSON
    const initDup = await runCli(['init', appDir, '--json'], { env: isolatedEnv });
    assert.strictEqual(initDup.status, 1);
    assert.strictEqual(JSON.parse(initDup.stdout).ok, false);
    console.log('  ✓ culkibo init: autodetectó Next.js/pnpm/Postgres, generó culkibo.yaml sin secretos y .culkiboignore');

    // 2. culkibo gitops schema + culkibo up --dry-run (0 escrituras en disco)
    const schemaRes = await runCli(['gitops', 'schema'], { env: isolatedEnv });
    assert.strictEqual(schemaRes.status, 0, schemaRes.stderr);
    const schemaObj = JSON.parse(schemaRes.stdout);
    assert.strictEqual(schemaObj.$schema, 'https://json-schema.org/draft/2020-12/schema');
    assert.ok(schemaObj.properties && schemaObj.properties.projects && schemaObj.properties.databases);

    const upDry = await runCli(['up', appDir, '--dry-run', '--json'], { env: isolatedEnv });
    assert.strictEqual(upDry.status, 0, upDry.stderr);
    const upDryJson = JSON.parse(upDry.stdout);
    assert.strictEqual(upDryJson.ok, true);
    assert.strictEqual(upDryJson.dryRun, true);
    assert.ok(upDryJson.plan.create.some((c) => c.kind === 'project'));
    console.log('  ✓ culkibo gitops schema + culkibo up --dry-run --json verificados');

    // 3. Vault local cifrado AES-256-GCM vía CLI (`env set --stdin --vault`, `env list --vault`, `env unset --vault`,
    //    `env set --env staging`, `env pull --env staging`) en CULKIBO_DATA_DIR aislado (0 mutaciones en live data/)
    const pid = initJson.projectId;
    const stdinRes = await runCli(['env', 'set', pid, '--stdin', 'STDIN_TOKEN', '--vault', '--json'], {
      env: isolatedEnv,
      input: 'tok_from_stdin_secret_888\n'
    });
    assert.strictEqual(stdinRes.status, 0, stdinRes.stderr);
    const stdinJson = JSON.parse(stdinRes.stdout);
    assert.strictEqual(stdinJson.vault, true);
    assert.ok(stdinJson.secrets[0].fingerprint.startsWith('sha256:'));
    assert.ok(!stdinRes.stdout.includes('tok_from_stdin_secret_888'), 'env set --vault jamás imprime valor en claro');

    const vaultList = await runCli(['env', 'list', pid, '--vault', '--json'], { env: isolatedEnv });
    assert.strictEqual(vaultList.status, 0, vaultList.stderr);
    const vaultJson = JSON.parse(vaultList.stdout);
    assert.strictEqual(vaultJson.secrets.length, 1);
    assert.strictEqual(vaultJson.secrets[0].key, 'STDIN_TOKEN');
    assert.ok(!vaultList.stdout.includes('tok_from_stdin_secret_888'));

    const envSetStage = await runCli(['env', 'set', pid, 'PUBLIC_MODE=edge', 'API_SECRET=super_secret_val_42', '--env', 'staging', '--json'], { env: isolatedEnv });
    assert.strictEqual(envSetStage.status, 0, envSetStage.stderr);

    const pulledSafe = path.join(tmpRoot, 'pulled-safe.env');
    const pullRes = await runCli(['env', 'pull', pid, '--env', 'staging', '-f', pulledSafe, '--json'], { env: isolatedEnv });
    assert.strictEqual(pullRes.status, 0, pullRes.stderr);
    const pulledText = fs.readFileSync(pulledSafe, 'utf8');
    assert.ok(pulledText.includes('PUBLIC_MODE=edge'));
    assert.ok(pulledText.includes('API_SECRET=${vault.API_SECRET}'), 'env pull sin --reveal debe redactar secretos');
    assert.ok(!pulledText.includes('super_secret_val_42'));

    const envUnsetStage = await runCli(['env', 'unset', pid, 'PUBLIC_MODE', '--env', 'staging', '--json'], { env: isolatedEnv });
    assert.strictEqual(envUnsetStage.status, 0, envUnsetStage.stderr);
    const envListStage = JSON.parse((await runCli(['env', 'list', pid, '--env', 'staging', '--json'], { env: isolatedEnv })).stdout);
    assert.strictEqual(envListStage.keys.includes('PUBLIC_MODE'), false);
    assert.strictEqual(envListStage.keys.includes('API_SECRET'), true);
    console.log('  ✓ culkibo env local (--stdin --vault, --env staging set/list/pull redactado/unset) en CULKIBO_DATA_DIR aislado');

    // 4. Modo daemon/remoto CULKIBO_API_URL + --json (status, doctor exitCode=1 on fail, up, env push/list/unset,
    //    logs, exec, releases, rollback --release, backup --db)
    /** @type {Record<string, any>} */
    const remoteProjects = {
      p_rem: { id: 'p_rem', name: 'Remote App', envVars: { NODE_ENV: 'production', DB_PASS: 'remote_secret_pwd' } }
    };
    /** @type {Array<{ method: string, url: string, auth: string | undefined, body: any }>} */
    const receivedReqs = [];
    mockServer = http.createServer((req, res) => {
      let bodyStr = '';
      req.on('data', (c) => { bodyStr += c; });
      req.on('end', () => {
        let parsedBody = null;
        try { parsedBody = bodyStr ? JSON.parse(bodyStr) : null; } catch (e) {}
        receivedReqs.push({ method: req.method || '', url: req.url || '', auth: req.headers.authorization, body: parsedBody });

        if (req.url === '/api/health') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'healthy', uptime: 123 }));
          return;
        }
        if (req.url === '/api/system/doctor') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            checks: [{ name: 'Docker', status: 'fail', summary: 'Offline', detail: 'Start daemon' }],
            summary: { ok: 5, warn: 0, fail: 1 },
            durationMs: 12
          }));
          return;
        }
        if (req.url === '/api/gitops/apply' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            ok: true,
            stackId: 'shop-web-stack',
            stackName: 'shop-web-stack',
            appliedCounts: { created: 1, updated: 0, deleted: 0, skipped: 0 },
            managedResources: { projectIds: ['p_rem'] }
          }));
          return;
        }
        if (req.url === '/api/projects/p_rem' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(remoteProjects.p_rem));
          return;
        }
        if (req.url === '/api/projects/p_rem' && req.method === 'PUT') {
          remoteProjects.p_rem = { ...remoteProjects.p_rem, ...(parsedBody || {}) };
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(remoteProjects.p_rem));
          return;
        }
        if (req.url === '/api/projects/p_rem/deploy' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'en_cola', message: 'Despliegue lanzado' }));
          return;
        }
        if (req.url && req.url.startsWith('/api/projects/p_rem/runtime/logs')) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, lines: ['[info] server ready on :3000', '[info] GET /health 200'] }));
          return;
        }
        if (req.url === '/api/projects/p_rem/runtime/exec') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, exitCode: 0, stdout: 'v22.0.0\n', stderr: '' }));
          return;
        }
        if (req.url && req.url.startsWith('/api/projects/p_rem/deployments')) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ deployments: [{ id: 'dep_001', status: 'activo', version: 'v1.2.3', durationMs: 4200 }] }));
          return;
        }
        if (req.url === '/api/projects/p_rem/rollback') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ id: 'rb_001', deploymentId: parsedBody?.deploymentId || 'prev', status: 'activo' }));
          return;
        }
        if (req.url === '/api/databases/db_pg_1/backups' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ id: 'bkp_42', fileName: 'pg-2026.sql.gz.enc', encrypted: true }));
          return;
        }
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found' }));
      });
    });

    await new Promise((resolve) => mockServer.listen(0, '127.0.0.1', resolve));
    const addr = /** @type {import('net').AddressInfo} */ (mockServer.address());
    const remoteEnv = {
      ...isolatedEnv,
      CULKIBO_API_URL: `http://127.0.0.1:${addr.port}`,
      CULKIBO_TOKEN: 'ck_test_bearer_token'
    };

    const stRes = await runCli(['--json', 'status'], { env: remoteEnv });
    assert.strictEqual(stRes.status, 0, stRes.stderr + stRes.stdout);
    assert.strictEqual(JSON.parse(stRes.stdout).ok, true);

    // doctor --json DEBE salir con código 1 cuando summary.fail > 0
    const docRes = await runCli(['doctor', '--json'], { env: remoteEnv });
    assert.strictEqual(docRes.status, 1, 'culkibo doctor debe devolver exitCode 1 cuando hay fallos');
    const docJson = JSON.parse(docRes.stdout);
    assert.strictEqual(docJson.ok, false);
    assert.strictEqual(docJson.summary.fail, 1);

    // culkibo up en modo remoto (apply + deploy en 1 comando)
    const upRemote = await runCli(['up', appDir, '--json'], { env: remoteEnv });
    assert.strictEqual(upRemote.status, 0, upRemote.stderr + upRemote.stdout);
    const upRemoteJson = JSON.parse(upRemote.stdout);
    assert.strictEqual(upRemoteJson.ok, true);
    assert.strictEqual(upRemoteJson.projectId, 'p_rem');
    assert.strictEqual(upRemoteJson.deployment.status, 'en_cola');

    // env push + env list (redactado) + env unset en modo remoto
    const pushFile = path.join(tmpRoot, 'push.env');
    fs.writeFileSync(pushFile, 'FEATURE_A=enabled\nLOG_LEVEL=info\n', 'utf8');
    const pushRes = await runCli(['env', 'push', 'p_rem', '-f', pushFile, '--json'], { env: remoteEnv });
    assert.strictEqual(pushRes.status, 0, pushRes.stderr);
    assert.strictEqual(JSON.parse(pushRes.stdout).pushedCount, 2);

    const listRedacted = await runCli(['env', 'list', 'p_rem', '--json'], { env: remoteEnv });
    assert.strictEqual(listRedacted.status, 0, listRedacted.stderr);
    const listObj = JSON.parse(listRedacted.stdout);
    assert.strictEqual(listObj.env.FEATURE_A, 'enabled');
    assert.strictEqual(listObj.env.DB_PASS, '[REDACTED]', 'env list debe redactar secretos por defecto');

    const unsetRes = await runCli(['env', 'unset', 'p_rem', 'FEATURE_A', '--json'], { env: remoteEnv });
    assert.strictEqual(unsetRes.status, 0, unsetRes.stderr);
    assert.strictEqual(remoteProjects.p_rem.envVars.FEATURE_A, undefined);

    const logsRes = await runCli(['logs', 'p_rem', '-n', '50', '--json'], { env: remoteEnv });
    assert.strictEqual(logsRes.status, 0, logsRes.stderr);
    assert.strictEqual(JSON.parse(logsRes.stdout).lines.length, 2);

    const execRes = await runCli(['exec', 'p_rem', '--json', '--', 'node', '-v'], { env: remoteEnv });
    assert.strictEqual(execRes.status, 0, execRes.stderr);
    const execReq = receivedReqs.find((r) => r.url === '/api/projects/p_rem/runtime/exec');
    assert.ok(execReq && execReq.auth === 'Bearer ck_test_bearer_token');
    assert.strictEqual(execReq.body.command, 'node -v');

    const relRes = await runCli(['releases', 'p_rem', '--json'], { env: remoteEnv });
    assert.strictEqual(relRes.status, 0, relRes.stderr);
    assert.strictEqual(JSON.parse(relRes.stdout).releases[0].id, 'dep_001');

    const rbRes = await runCli(['rollback', 'p_rem', '--release', 'dep_001', '--json'], { env: remoteEnv });
    assert.strictEqual(rbRes.status, 0, rbRes.stderr);
    assert.strictEqual(JSON.parse(rbRes.stdout).deploymentId, 'dep_001');

    const bkpRes = await runCli(['backup', '--db', 'db_pg_1', '--json'], { env: remoteEnv });
    assert.strictEqual(bkpRes.status, 0, bkpRes.stderr);
    assert.strictEqual(JSON.parse(bkpRes.stdout).backup.id, 'bkp_42');
    console.log('  ✓ Modo daemon/remoto CULKIBO_API_URL + --json (status, doctor exit=1, up, env push/list/unset, logs, exec, releases, rollback --release, backup --db) verificado');

    // 5. Confirmar exportación de helpers puros de bin/culkibo.js sin efectos secundarios
    const cliMod = require('../bin/culkibo');
    assert.strictEqual(typeof cliMod.detectLocalStack, 'function');
    assert.strictEqual(typeof cliMod.generateStarterManifest, 'function');
    assert.strictEqual(typeof cliMod.parseEnvAssignments, 'function');
    assert.strictEqual(typeof cliMod.writeAgentKitFiles, 'function');
    assert.deepStrictEqual(cliMod.parseEnvAssignments(['A=1', 'B=hello=world']), { A: '1', B: 'hello=world' });

    // 6. culkibo agent-init [target]: drop-in configs con ?profile=core y ${CULKIBO_TOKEN} (0 secretos en claro)
    const agentWorkspace = path.join(tmpRoot, 'agent-ws');
    fs.mkdirSync(agentWorkspace, { recursive: true });
    // Pre-poblar .cursor/mcp.json con otro servidor para verificar merge no destructivo
    fs.mkdirSync(path.join(agentWorkspace, '.cursor'), { recursive: true });
    fs.writeFileSync(
      path.join(agentWorkspace, '.cursor', 'mcp.json'),
      JSON.stringify({ mcpServers: { existingTool: { url: 'http://127.0.0.1:9999/mcp' } } }, null, 2),
      'utf8'
    );

    const envWithSecretToken = {
      ...isolatedEnv,
      CULKIBO_TOKEN: 'ck_real_master_secret_must_never_leak_777'
    };

    // 6a. --dry-run no escribe archivos
    const kitDry = await runCli(['agent-init', 'all', '-d', agentWorkspace, '--url', 'https://paas.acme.dev', '--dry-run', '--json'], { env: envWithSecretToken });
    assert.strictEqual(kitDry.status, 0, kitDry.stderr + kitDry.stdout);
    const kitDryJson = JSON.parse(kitDry.stdout);
    assert.strictEqual(kitDryJson.ok, true);
    assert.strictEqual(kitDryJson.dryRun, true);
    assert.strictEqual(kitDryJson.profile, 'core');
    assert.strictEqual(kitDryJson.containsPlaintextSecrets, false);
    assert.ok(kitDryJson.tokenSavings.savedPct >= 80, `Se esperaba ahorro >=80%, llegó ${kitDryJson.tokenSavings.savedPct}%`);
    assert.strictEqual(fs.existsSync(path.join(agentWorkspace, '.mcp.json')), false, '--dry-run no debe escribir archivos');

    // 6b. Escritura real para todos los agentes (antigravity, claude-code, cursor, windsurf, codex, vscode)
    const kitWrite = await runCli(['agent-init', 'all', '-d', agentWorkspace, '--url', 'https://paas.acme.dev', '--json'], { env: envWithSecretToken });
    assert.strictEqual(kitWrite.status, 0, kitWrite.stderr + kitWrite.stdout);
    const kitWriteJson = JSON.parse(kitWrite.stdout);
    assert.strictEqual(kitWriteJson.ok, true);
    assert.ok(!kitWrite.stdout.includes('ck_real_master_secret_must_never_leak_777'), 'agent-init JAMÁS debe imprimir CULKIBO_TOKEN real');

    const expectedAgentFiles = [
      '.antigravity/mcp.json',
      '.mcp.json',
      'CLAUDE.md',
      '.cursor/mcp.json',
      '.windsurf/mcp_config.json',
      '.codex/config.toml',
      '.vscode/mcp.json'
    ];
    for (const rel of expectedAgentFiles) {
      const full = path.join(agentWorkspace, rel);
      assert.strictEqual(fs.existsSync(full), true, `agent-init debe crear ${rel}`);
      const content = fs.readFileSync(full, 'utf8');
      assert.ok(!content.includes('ck_real_master_secret_must_never_leak_777'), `${rel} JAMÁS puede contener el token real`);
      assert.ok(content.includes('profile=core'), `${rel} debe usar ?profile=core por defecto`);
    }
    const mergedCursor = JSON.parse(fs.readFileSync(path.join(agentWorkspace, '.cursor', 'mcp.json'), 'utf8'));
    assert.ok(mergedCursor.mcpServers.existingTool, 'agent-init debe preservar servidores MCP existentes al fusionar JSON');
    assert.strictEqual(mergedCursor.mcpServers.culkibo.headers.Authorization, 'Bearer ${CULKIBO_TOKEN}');
    const codexToml = fs.readFileSync(path.join(agentWorkspace, '.codex', 'config.toml'), 'utf8');
    assert.ok(codexToml.includes('bearer_token_env_var = "CULKIBO_TOKEN"'));
    const claudeMd = fs.readFileSync(path.join(agentWorkspace, 'CLAUDE.md'), 'utf8');
    assert.ok(claudeMd.includes('culkibo_ship_and_verify') && claudeMd.includes('deploy_safely'));

    // Re-ejecutar sin --force omite entradas existentes sin sobrescribir
    const kitSkip = await runCli(['agent-init', 'cursor', '-d', agentWorkspace, '--url', 'https://paas.acme.dev', '--json'], { env: envWithSecretToken });
    assert.strictEqual(kitSkip.status, 0, kitSkip.stderr);
    const kitSkipJson = JSON.parse(kitSkip.stdout);
    assert.ok(kitSkipJson.skipped.includes('.cursor/mcp.json'));
    console.log(`  ✓ culkibo agent-init verificado (6 agentes, merge seguro, -${kitWriteJson.tokenSavings.savedPct}% tokens, 0 secretos en claro)`);

    // 7. CULKIBO_MCP_PROFILE sobre puente stdio local y remoto HTTP
    const stdioLocalInput = [
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
      JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
      JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'prompts/list', params: {} }),
      JSON.stringify({
        jsonrpc: '2.0',
        id: 4,
        method: 'tools/list',
        params: { _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} } }
      })
    ].join('\n') + '\n';

    const stdioLocalCore = await runCli(['mcp'], {
      env: { ...isolatedEnv, CULKIBO_MCP_PROFILE: 'core' },
      input: stdioLocalInput
    });
    assert.strictEqual(stdioLocalCore.status, 0, `culkibo mcp local falló: ${stdioLocalCore.stderr}`);
    const localResponses = stdioLocalCore.stdout.trim().split(/\r?\n/).map((l) => JSON.parse(l));
    assert.strictEqual(localResponses.length, 4);
    assert.strictEqual(localResponses[0].result.capabilities.prompts.listChanged, false);
    const coreStdioTools = localResponses[1].result.tools;
    assert.ok(coreStdioTools.length > 0 && coreStdioTools.length <= 20, `CULKIBO_MCP_PROFILE=core debe filtrar tools/list (devolvió ${coreStdioTools.length})`);
    assert.ok(coreStdioTools.some((t) => t.name === 'culkibo_ship_and_verify'));
    assert.ok(coreStdioTools.some((t) => t.name === 'culkibo_search_tools'));
    assert.ok(localResponses[2].result.prompts.some((p) => p.name === 'deploy_safely'));
    assert.strictEqual(localResponses[3].result.profile, 'core');
    assert.strictEqual(localResponses[3].result.tools.length, coreStdioTools.length);

    // Puente stdio remoto hacia HTTP mock verificando ?profile=core y legacy profile forwarding
    /** @type {Array<{ url: string, body: any }>} */
    const mcpBridgeReqs = [];
    const mcpMockServer = http.createServer((req, res) => {
      let bodyStr = '';
      req.on('data', (c) => { bodyStr += c; });
      req.on('end', () => {
        const parsed = bodyStr ? JSON.parse(bodyStr) : {};
        mcpBridgeReqs.push({ url: req.url || '', body: parsed });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: parsed.id, result: { tools: [{ name: 'culkibo_search_tools' }], profile: 'core' } }));
      });
    });
    await new Promise((resolve) => mcpMockServer.listen(0, '127.0.0.1', resolve));
    try {
      const mcpMockAddr = /** @type {import('net').AddressInfo} */ (mcpMockServer.address());
      const remoteStdioInput = [
        JSON.stringify({
          jsonrpc: '2.0',
          id: 10,
          method: 'tools/list',
          params: { _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} } }
        }),
        JSON.stringify({ jsonrpc: '2.0', id: 11, method: 'tools/list', params: {} })
      ].join('\n') + '\n';
      const stdioRemoteCore = await runCli(['mcp'], {
        env: {
          ...isolatedEnv,
          CULKIBO_API_URL: `http://127.0.0.1:${mcpMockAddr.port}`,
          CULKIBO_TOKEN: 'ck_bridge_tok',
          CULKIBO_MCP_PROFILE: 'core'
        },
        input: remoteStdioInput
      });
      assert.strictEqual(stdioRemoteCore.status, 0, stdioRemoteCore.stderr);
      assert.ok(mcpBridgeReqs.some((r) => r.url === '/api/mcp?profile=core'), 'Puente stdio moderno debe añadir ?profile=core a /api/mcp');
      assert.ok(mcpBridgeReqs.some((r) => r.url === '/api/mcp/message' && r.body?.params?.profile === 'core'), 'Puente stdio legacy debe reenviar params.profile=core');
    } finally {
      await new Promise((r) => mcpMockServer.close(() => r(undefined)));
    }
    console.log('  ✓ CULKIBO_MCP_PROFILE=core verificado en puente stdio local (2024-11-05 y 2026-07-28) y remoto HTTP');

    console.log('✅ All CLI DX tests passed!\n');
  } finally {
    if (mockServer) await new Promise((r) => mockServer.close(() => r(undefined)));
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

module.exports = testCliDx;

if (require.main === module) {
  testCliDx().then(() => process.exit(0)).catch((err) => {
    console.error('❌ CLI DX test failure:', err);
    process.exit(1);
  });
}
