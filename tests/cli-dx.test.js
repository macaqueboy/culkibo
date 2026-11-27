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

    // 8. Pioneer Cycle-2 CLI: smartpack, pussh --dry-run, tunnel-agent --dry-run
    const spCli = await runCli(['smartpack', appDir, '--json'], { env: isolatedEnv });
    assert.strictEqual(spCli.status, 0, `culkibo smartpack falló: ${spCli.stderr} ${spCli.stdout}`);
    const spJson = JSON.parse(spCli.stdout);
    assert.strictEqual(spJson.ok, true);
    assert.strictEqual(spJson.stack, 'nextjs');
    assert.ok(Array.isArray(spJson.dockerignore) && spJson.dockerignore.includes('.git') && spJson.dockerignore.includes('node_modules'));
    assert.ok(typeof spJson.dockerfile === 'string' && spJson.dockerfile.includes('FROM '));
    assert.ok(spJson.resourceLimits && typeof spJson.deterministicHash === 'string');

    const pusshCli = await runCli(['pussh', 'acme/shop-web:v1.2', '--server', 'srv_eu', '--port', '5055', '--dry-run', '--json'], { env: isolatedEnv });
    assert.strictEqual(pusshCli.status, 0, `culkibo pussh --dry-run falló: ${pusshCli.stderr} ${pusshCli.stdout}`);
    const pusshJson = JSON.parse(pusshCli.stdout);
    assert.strictEqual(pusshJson.ok, true);
    assert.strictEqual(pusshJson.dryRun, true);
    assert.strictEqual(pusshJson.plan.schemaVersion, 'culkibo.directpush/v1');
    assert.strictEqual(pusshJson.plan.shell, false);
    assert.strictEqual(pusshJson.plan.targetImageRef, '127.0.0.1:5055/acme/shop-web:v1.2');
    assert.strictEqual(pusshJson.plan.steps.length, 3);

    const tunCli = await runCli([
      'tunnel-agent',
      '--url', 'wss://paas.acme.dev/ws/tunnel',
      '--tunnel-id', 'tun_demo_1',
      '--token', 'cket_never_print_secret_tunnel_token_999',
      '--target', '127.0.0.1:3000',
      '--dry-run',
      '--json'
    ], { env: isolatedEnv });
    assert.strictEqual(tunCli.status, 0, `culkibo tunnel-agent --dry-run falló: ${tunCli.stderr} ${tunCli.stdout}`);
    assert.ok(!tunCli.stdout.includes('cket_never_print_secret_tunnel_token_999'), 'tunnel-agent JAMÁS puede imprimir el token en claro');
    const tunJson = JSON.parse(tunCli.stdout);
    assert.strictEqual(tunJson.ok, true);
    assert.strictEqual(tunJson.dryRun, true);
    assert.strictEqual(tunJson.token, '[REDACTED]');
    assert.strictEqual(tunJson.targetHost, '127.0.0.1');
    assert.strictEqual(tunJson.targetPort, 3000);
    console.log('  ✓ Pioneer CLI Cycle-2 verificado (culkibo smartpack, culkibo pussh --dry-run, culkibo tunnel-agent --dry-run)');

    // 9. Pioneer Cycle-4 CLI: `culkibo verify --json` (self-check, CHECKSUMS.sha256 + tamper, SLSA v1.1 DSSE + tamper) y `culkibo demo --json`
    const verifySelf = await runCli(['verify', '--json'], { env: isolatedEnv });
    assert.strictEqual(verifySelf.status, 0, `culkibo verify --json falló: ${verifySelf.stderr} ${verifySelf.stdout}`);
    const verifySelfJson = JSON.parse(verifySelf.stdout);
    assert.strictEqual(verifySelfJson.ok, true);
    assert.strictEqual(verifySelfJson.valid, true);
    assert.ok(verifySelfJson.checked > 0);
    assert.strictEqual(verifySelfJson.sbom?.specVersion, '1.6');

    // CHECKSUMS.sha256 verification (pass + tampered fail)
    const releaseProvenance = require('../scripts/release-provenance');
    const tmpProvDir = path.join(tmpRoot, 'prov-out');
    const provOut = releaseProvenance.writeReleaseProvenance({ outDir: tmpProvDir });
    const verifyChecksumsOk = await runCli(['verify', provOut.files.checksums, '--json'], { env: isolatedEnv });
    assert.strictEqual(verifyChecksumsOk.status, 0, `culkibo verify CHECKSUMS.sha256 falló: ${verifyChecksumsOk.stderr}`);
    const verifyCsOkJson = JSON.parse(verifyChecksumsOk.stdout);
    assert.strictEqual(verifyCsOkJson.ok, true);
    assert.strictEqual(verifyCsOkJson.valid, true);
    assert.strictEqual(verifyCsOkJson.mode, 'checksums');
    assert.ok(verifyCsOkJson.checked > 0);

    const tamperedCsPath = path.join(tmpProvDir, 'CHECKSUMS.tampered.sha256');
    const origCsText = fs.readFileSync(provOut.files.checksums, 'utf8');
    fs.writeFileSync(tamperedCsPath, origCsText.replace(/^[a-f0-9]{64}/m, '0'.repeat(64)), 'utf8');
    const verifyCsBad = await runCli(['verify', tamperedCsPath, '--json'], { env: isolatedEnv });
    assert.strictEqual(verifyCsBad.status, 1, 'CHECKSUMS.sha256 manipulado debe salir con código 1');
    const verifyCsBadJson = JSON.parse(verifyCsBad.stdout);
    assert.strictEqual(verifyCsBadJson.valid, false);
    assert.ok(Array.isArray(verifyCsBadJson.mismatched) && verifyCsBadJson.mismatched.length >= 1);

    // SLSA v1.1 Ed25519 DSSE verification (pass + tampered signature fail)
    const { SupplyChainAttestor } = require('../server/services/supplyChainAttestor');
    const attestDataDir = path.join(tmpRoot, 'data');
    const attestor = new SupplyChainAttestor({ dataDir: attestDataDir });
    const signedAtt = attestor.attestRelease({
      projectId: 'cli-verify-proj',
      revision: 'rev-1',
      commitSha: '1234567890abcdef1234567890abcdef12345678'
    });
    const pubKeyPath = path.join(tmpRoot, 'attest.pub.pem');
    fs.writeFileSync(pubKeyPath, signedAtt.publicKeyPem, 'utf8');
    const verifyDsseOk = await runCli(['verify', signedAtt.storedPath, '--public-key', pubKeyPath, '--json'], { env: isolatedEnv });
    assert.strictEqual(verifyDsseOk.status, 0, `culkibo verify DSSE falló: ${verifyDsseOk.stderr} ${verifyDsseOk.stdout}`);
    const verifyDsseOkJson = JSON.parse(verifyDsseOk.stdout);
    assert.strictEqual(verifyDsseOkJson.ok, true);
    assert.strictEqual(verifyDsseOkJson.valid, true);
    assert.strictEqual(verifyDsseOkJson.mode, 'slsa-dsse');
    assert.strictEqual(verifyDsseOkJson.algorithm, 'Ed25519');
    assert.strictEqual(verifyDsseOkJson.slsaVersion, '1.1');

    const badDssePath = path.join(tmpRoot, 'tampered.dsse.json');
    const badEnv = JSON.parse(JSON.stringify(signedAtt.envelope));
    badEnv.signatures[0].sig = Buffer.alloc(64, 7).toString('base64');
    fs.writeFileSync(badDssePath, JSON.stringify(badEnv, null, 2), 'utf8');
    const verifyDsseBad = await runCli(['verify', badDssePath, '--public-key', pubKeyPath, '--json'], { env: isolatedEnv });
    assert.strictEqual(verifyDsseBad.status, 1, 'Sobre DSSE manipulado debe salir con código 1');
    const verifyDsseBadJson = JSON.parse(verifyDsseBad.stdout);
    assert.strictEqual(verifyDsseBadJson.valid, false);
    assert.strictEqual(verifyDsseBadJson.reason, 'INVALID_SIGNATURE');

    // culkibo demo --json (<200 ms sandbox metadata + custom port)
    const demoCli = await runCli(['demo', '--no-open', '--json'], { env: isolatedEnv });
    assert.strictEqual(demoCli.status, 0, `culkibo demo --json falló: ${demoCli.stderr} ${demoCli.stdout}`);
    const demoJson = JSON.parse(demoCli.stdout);
    assert.strictEqual(demoJson.ok, true);
    assert.strictEqual(demoJson.mode, 'demo');
    assert.strictEqual(demoJson.demo, true);
    assert.strictEqual(demoJson.env.CULKIBO_DEMO, '1');
    assert.strictEqual(demoJson.url, 'http://127.0.0.1:3030/?demo=1&lang=en&theme=dark');
    assert.ok(typeof demoJson.bootMs === 'number' && demoJson.bootMs < 200, `bootMs debe ser <200ms (actual: ${demoJson.bootMs}ms)`);
    assert.strictEqual(demoJson.datasets.mcpTools, 145);

    const demoCustomPort = await runCli(['demo', '--port', '4044', '--no-open', '--json'], { env: isolatedEnv });
    assert.strictEqual(demoCustomPort.status, 0, demoCustomPort.stderr);
    assert.strictEqual(JSON.parse(demoCustomPort.stdout).url, 'http://127.0.0.1:4044/?demo=1&lang=en&theme=dark');
    console.log(`  ✓ Pioneer CLI Cycle-4 verificado (culkibo verify SHA-256/SLSA-DSSE + tamper detect, culkibo demo --json en ${demoJson.bootMs} ms)`);

    // 10. Pioneer Cycle-6 CLI: `culkibo finops --json` y `culkibo timemachine <list|create|diff|restore> --json`
    const finopsCli = await runCli(['finops', '--apps', '5', '--dbs', '2', '--json'], { env: isolatedEnv });
    assert.strictEqual(finopsCli.status, 0, `culkibo finops --json falló: ${finopsCli.stderr} ${finopsCli.stdout}`);
    const finopsJson = JSON.parse(finopsCli.stdout);
    assert.strictEqual(finopsJson.ok, true);
    assert.strictEqual(finopsJson.inputs.apps, 5);
    assert.strictEqual(finopsJson.inputs.databases, 2);
    assert.ok(finopsJson.comparison && finopsJson.comparison.annualSavingsUsd > 0);
    assert.ok(finopsJson.comparison.savingsPct > 0);
    assert.ok(finopsJson.analysis && finopsJson.analysis.ok === true);

    // Prepare isolated project in dataRoot/projects.json (matching CULKIBO_DATA_DIR) for CLI timemachine subcommands
    const tmProjectId = 'proj_cli_tm_1';
    const projectsJsonPath = path.join(dataRoot, 'projects.json');
    const existingProjects = fs.existsSync(projectsJsonPath) ? JSON.parse(fs.readFileSync(projectsJsonPath, 'utf8')) : [];
    const nextProjects = Array.isArray(existingProjects) ? existingProjects : [];
    if (!nextProjects.some((p) => p && p.id === tmProjectId)) {
      nextProjects.push({
        id: tmProjectId,
        name: 'CLI TimeMachine App',
        description: 'v1 baseline',
        memoryMb: 512,
        envVars: { MODE: 'prod' },
        resources: []
      });
      fs.writeFileSync(projectsJsonPath, JSON.stringify(nextProjects, null, 2), 'utf8');
    }

    const tmListEmpty = await runCli(['timemachine', 'list', tmProjectId, '--json'], { env: isolatedEnv });
    assert.strictEqual(tmListEmpty.status, 0, `culkibo timemachine list falló: ${tmListEmpty.stderr} ${tmListEmpty.stdout}`);
    const tmListEmptyJson = JSON.parse(tmListEmpty.stdout);
    assert.strictEqual(tmListEmptyJson.ok, true);
    assert.strictEqual(tmListEmptyJson.action, 'list');
    assert.strictEqual(tmListEmptyJson.count, 0);

    const tmCreate = await runCli(['timemachine', 'create', tmProjectId, '--label', 'cli-cp-1', '--json'], { env: isolatedEnv });
    assert.strictEqual(tmCreate.status, 0, `culkibo timemachine create falló: ${tmCreate.stderr} ${tmCreate.stdout}`);
    const tmCreateJson = JSON.parse(tmCreate.stdout);
    assert.strictEqual(tmCreateJson.ok, true);
    assert.ok(tmCreateJson.checkpoint && tmCreateJson.checkpoint.id.startsWith('tm_'));

    const tmListOne = await runCli(['timemachine', 'list', tmProjectId, '--json'], { env: isolatedEnv });
    assert.strictEqual(tmListOne.status, 0, tmListOne.stderr);
    assert.strictEqual(JSON.parse(tmListOne.stdout).count, 1);

    const tmRestoreDry = await runCli(['timemachine', 'restore', tmProjectId, '--id', tmCreateJson.checkpoint.id, '--json'], { env: isolatedEnv });
    assert.strictEqual(tmRestoreDry.status, 0, `culkibo timemachine restore dry-run falló: ${tmRestoreDry.stderr} ${tmRestoreDry.stdout}`);
    const tmRestoreDryJson = JSON.parse(tmRestoreDry.stdout);
    assert.strictEqual(tmRestoreDryJson.ok, true);
    assert.strictEqual(tmRestoreDryJson.dryRun, true);
    assert.strictEqual(tmRestoreDryJson.restored, false);
    console.log(`  ✓ Pioneer CLI Cycle-6 verificado (culkibo finops $${finopsJson.comparison.annualSavingsUsd}/yr, culkibo timemachine list/create/dryRun-restore)`);

    // 11. Pioneer Cycle-7 CLI: `culkibo heal --text "..." --json`, `culkibo mesh status|plan|rotate --json`
    const healCli = await runCli([
      'heal',
      '--text', 'FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory',
      '--json'
    ], { env: isolatedEnv });
    assert.strictEqual(healCli.status, 0, `culkibo heal falló: ${healCli.stderr} ${healCli.stdout}`);
    const healJson = JSON.parse(healCli.stdout);
    assert.strictEqual(healJson.ok, true);
    assert.strictEqual(healJson.matched, true);
    assert.strictEqual(healJson.diagnosis.primary.code, 'NODE_HEAP_OOM');
    assert.ok(typeof healJson.diagnosis.primary.patchPreview === 'string' && healJson.diagnosis.primary.patchPreview.length > 0);

    // File-based offline log diagnosis
    const sampleLogFile = path.join(tmpRoot, 'fail-build.log');
    fs.writeFileSync(sampleLogFile, "docker: Error response from daemon: failed to initialize logging driver: unknown log opt 'max-size' for syslog log driver.\n", 'utf8');
    const healFileCli = await runCli(['heal', sampleLogFile, '--json'], { env: isolatedEnv });
    assert.strictEqual(healFileCli.status, 0, healFileCli.stderr);
    const healFileJson = JSON.parse(healFileCli.stdout);
    assert.strictEqual(healFileJson.matched, true);
    assert.strictEqual(healFileJson.diagnosis.primary.code, 'DOCKER_LOG_OPT_DRIVER_MISMATCH');

    const meshStatusCli = await runCli(['mesh', 'status', '--json'], { env: isolatedEnv });
    assert.strictEqual(meshStatusCli.status, 0, `culkibo mesh status falló: ${meshStatusCli.stderr} ${meshStatusCli.stdout}`);
    const meshStatusJson = JSON.parse(meshStatusCli.stdout);
    assert.strictEqual(meshStatusJson.ok, true);
    assert.strictEqual(meshStatusJson.cidr, '10.88.0.0/24');
    assert.ok(Array.isArray(meshStatusJson.peers) && meshStatusJson.peers.length >= 1);
    assert.ok(!meshStatusCli.stdout.includes('encryptedPrivateKey'), 'culkibo mesh status jamás debe filtrar claves privadas');

    const meshPlanCli = await runCli(['mesh', 'plan', '--json'], { env: isolatedEnv });
    assert.strictEqual(meshPlanCli.status, 0, `culkibo mesh plan falló: ${meshPlanCli.stderr} ${meshPlanCli.stdout}`);
    const meshPlanJson = JSON.parse(meshPlanCli.stdout);
    assert.strictEqual(meshPlanJson.ok, true);
    assert.strictEqual(meshPlanJson.dryRun, true);
    assert.ok(Array.isArray(meshPlanJson.wgConfigs) && meshPlanJson.wgConfigs.length >= 1);
    assert.ok(meshPlanJson.wgConfigs[0].config.includes('[REDACT_ON_API]'));

    const meshRotateDryCli = await runCli(['mesh', 'rotate', '--node', meshStatusJson.peers[0].nodeId, '--json'], { env: isolatedEnv });
    assert.strictEqual(meshRotateDryCli.status, 0, `culkibo mesh rotate dry-run falló: ${meshRotateDryCli.stderr} ${meshRotateDryCli.stdout}`);
    const meshRotJson = JSON.parse(meshRotateDryCli.stdout);
    assert.strictEqual(meshRotJson.ok, true);
    assert.strictEqual(meshRotJson.dryRun, true);
    assert.strictEqual(meshRotJson.rotated, false);
    console.log('  ✓ Pioneer CLI Cycle-7 verificado (culkibo heal --text/file NODE_HEAP_OOM & kamal#1709, culkibo mesh status/plan/dryRun-rotate)');

    // 12. Pioneer Cycle-8 CLI: `culkibo export-iac --json` (--out atomic write + 0 secrets) y `culkibo cve-scan --json`
    const iacOutDir = path.join(tmpRoot, 'iac-bundle');
    const iacCli = await runCli(['export-iac', '--format', 'all', '--out', iacOutDir, '--json'], { env: isolatedEnv });
    assert.strictEqual(iacCli.status, 0, `culkibo export-iac falló: ${iacCli.stderr} ${iacCli.stdout}`);
    const iacJson = JSON.parse(iacCli.stdout);
    assert.strictEqual(iacJson.ok, true);
    assert.strictEqual(iacJson.format, 'all');
    assert.ok(iacJson.files && typeof iacJson.files['main.tf'] === 'string' && typeof iacJson.files['docker-compose.yml'] === 'string');
    assert.ok(fs.existsSync(path.join(iacOutDir, 'main.tf')));
    assert.ok(fs.existsSync(path.join(iacOutDir, 'variables.tf')));
    assert.ok(fs.existsSync(path.join(iacOutDir, 'docker-compose.yml')));
    assert.ok(fs.existsSync(path.join(iacOutDir, '.env.example')));

    const cveCli = await runCli(['cve-scan', '--json'], { env: isolatedEnv });
    assert.strictEqual(cveCli.status, 0, `culkibo cve-scan falló: ${cveCli.stderr} ${cveCli.stdout}`);
    const cveJson = JSON.parse(cveCli.stdout);
    assert.strictEqual(cveJson.ok, true);
    assert.ok(typeof cveJson.scannedComponents === 'number' && cveJson.scannedComponents > 0);
    assert.ok(cveJson.severityCounts && typeof cveJson.vulnerableCount === 'number');
    console.log(`  ✓ Pioneer CLI Cycle-8 verificado (culkibo export-iac ${iacJson.writtenFiles.length} archivos, culkibo cve-scan ${cveJson.scannedComponents} componentes)`);

    // 13. Pioneer Cycle-9 CLI: `culkibo ledger [--days 30] [--csv|--json]` y `culkibo s3-presets [--json]`
    const ledgerJsonCli = await runCli(['ledger', '--days', '30', '--json'], { env: isolatedEnv });
    assert.strictEqual(ledgerJsonCli.status, 0, `culkibo ledger --json falló: ${ledgerJsonCli.stderr} ${ledgerJsonCli.stdout}`);
    const ledgerJson = JSON.parse(ledgerJsonCli.stdout);
    assert.strictEqual(ledgerJson.ok, true);
    assert.strictEqual(ledgerJson.periodDays, 30);
    assert.ok(Array.isArray(ledgerJson.entries) && ledgerJson.entries.length >= 1);
    assert.ok(ledgerJson.totals && typeof ledgerJson.totals.estimatedCostUsd === 'number');

    // Inject a formula-bearing project name in isolated dataRoot/projects.json to verify CSV formula neutralization via CLI
    const curProjectsForCsv = JSON.parse(fs.readFileSync(projectsJsonPath, 'utf8'));
    curProjectsForCsv.push({
      id: 'proj_cli_csv_formula',
      name: '=SUM(1,1)',
      memoryMb: 256,
      cpus: 0.5,
      resources: []
    });
    fs.writeFileSync(projectsJsonPath, JSON.stringify(curProjectsForCsv, null, 2), 'utf8');

    const ledgerCsvCli = await runCli(['ledger', '--days', '30', '--csv'], { env: isolatedEnv });
    assert.strictEqual(ledgerCsvCli.status, 0, `culkibo ledger --csv falló: ${ledgerCsvCli.stderr} ${ledgerCsvCli.stdout}`);
    assert.ok(ledgerCsvCli.stdout.includes('projectId') && ledgerCsvCli.stdout.includes('TOTAL'));
    assert.ok(ledgerCsvCli.stdout.includes("'=SUM(1,1)"), 'culkibo ledger --csv debe neutralizar fórmulas =/+/-/@');

    const s3PresetsCli = await runCli(['s3-presets', '--json'], { env: isolatedEnv });
    assert.strictEqual(s3PresetsCli.status, 0, `culkibo s3-presets --json falló: ${s3PresetsCli.stderr} ${s3PresetsCli.stdout}`);
    const s3PresetsJson = JSON.parse(s3PresetsCli.stdout);
    assert.strictEqual(s3PresetsJson.ok, true);
    assert.strictEqual(s3PresetsJson.count, 3);
    assert.deepStrictEqual(s3PresetsJson.presets.map((p) => p.id).sort(), ['garage', 'rustfs', 'seaweedfs']);
    assert.ok(s3PresetsJson.presets.every((p) => p.bindAddress === '127.0.0.1'));
    console.log(`  ✓ Pioneer CLI Cycle-9 verificado (culkibo ledger --json/--csv formula-safe, culkibo s3-presets 3 engines Post-MinIO, culkibo demo 130 tools)`);

    // 14. Pioneer Cycle-10 CLI: `culkibo dr-drill <backupFile> [--engine] [--sha256] [--json]` y `culkibo ai-vram [--params --quant --ctx --vram --runtime --json]`
    const zlib = require('zlib');
    const crypto = require('crypto');
    const validSqlDump = '-- PostgreSQL database dump\nCREATE TABLE invoices (id SERIAL PRIMARY KEY, amount NUMERIC);\nINSERT INTO invoices (amount) VALUES (42.00);\nGRANT SELECT ON invoices TO readonly;\n';
    const validGzPath = path.join(tmpRoot, 'prod-backup.sql.gz');
    const validGzBuf = zlib.gzipSync(Buffer.from(validSqlDump, 'utf8'));
    fs.writeFileSync(validGzPath, validGzBuf);
    const validSha = crypto.createHash('sha256').update(validGzBuf).digest('hex');

    const drillPassCli = await runCli(['dr-drill', validGzPath, '--engine', 'postgres', '--sha256', validSha, '--json'], { env: isolatedEnv });
    assert.strictEqual(drillPassCli.status, 0, `culkibo dr-drill PASS falló: ${drillPassCli.stderr} ${drillPassCli.stdout}`);
    const drillPassJson = JSON.parse(drillPassCli.stdout);
    assert.strictEqual(drillPassJson.ok, true);
    assert.strictEqual(drillPassJson.verdict, 'PASS');
    assert.strictEqual(drillPassJson.sha256, validSha);

    // Empty 20-byte gzip -> MUST fail with verdict FAIL & non-zero exit code!
    const emptyGzPath = path.join(tmpRoot, 'empty-20b.sql.gz');
    fs.writeFileSync(emptyGzPath, zlib.gzipSync(Buffer.alloc(0)));
    const drillFailCli = await runCli(['dr-drill', emptyGzPath, '--json'], { env: isolatedEnv });
    assert.strictEqual(drillFailCli.status, 1, 'culkibo dr-drill debe retornar exit=1 en backup vacío 20B');
    const drillFailJson = JSON.parse(drillFailCli.stdout);
    assert.strictEqual(drillFailJson.ok, false);
    assert.strictEqual(drillFailJson.verdict, 'FAIL');

    // culkibo ai-vram --json (fits + overflow check)
    const vramFitCli = await runCli(['ai-vram', '--params', '8', '--quant', 'Q4_K_M', '--ctx', '8192', '--vram', '16', '--runtime', 'ollama', '--json'], { env: isolatedEnv });
    assert.strictEqual(vramFitCli.status, 0, `culkibo ai-vram falló: ${vramFitCli.stderr} ${vramFitCli.stdout}`);
    const vramFitJson = JSON.parse(vramFitCli.stdout);
    assert.strictEqual(vramFitJson.ok, true);
    assert.strictEqual(vramFitJson.runtime, 'ollama');
    assert.strictEqual(vramFitJson.fits, true);
    assert.ok(vramFitJson.totalRequiredGb > 0 && vramFitJson.totalRequiredGb < 16);

    const vramOverflowCli = await runCli(['ai-vram', '--params', '70', '--quant', 'FP16', '--vram', '24', '--runtime', 'vllm', '--json'], { env: isolatedEnv });
    assert.strictEqual(vramOverflowCli.status, 0, vramOverflowCli.stderr);
    const vramOverflowJson = JSON.parse(vramOverflowCli.stdout);
    assert.strictEqual(vramOverflowJson.fits, false);
    console.log(`  ✓ Pioneer CLI Cycle-10 verificado (culkibo dr-drill PASS/20B-FAIL, culkibo ai-vram ${vramFitJson.totalRequiredGb}GB fits/overflow, culkibo demo 135 tools)`);

    // 15. Pioneer Cycle-11 CLI: `culkibo compliance-bundle` (Ed25519 sign + verify + tamper) & `culkibo admission-check` (DENY exit 1 vs ALLOW exit 0)
    const bundleOutPath = path.join(tmpRoot, 'compliance-bundle.json');
    const compGenCli = await runCli(['compliance-bundle', '--framework', 'all', '--out', bundleOutPath, '--json'], { env: isolatedEnv });
    assert.strictEqual(compGenCli.status, 0, `culkibo compliance-bundle falló: ${compGenCli.stderr} ${compGenCli.stdout}`);
    const compGenJson = JSON.parse(compGenCli.stdout);
    assert.strictEqual(compGenJson.ok, true);
    assert.strictEqual(compGenJson.algorithm, 'Ed25519');
    assert.ok(fs.existsSync(bundleOutPath));
    assert.ok(!compGenCli.stdout.includes('PRIVATE KEY'), 'compliance-bundle CLI jamás debe exponer claves privadas');

    const compVerOkCli = await runCli(['compliance-bundle', '--verify', bundleOutPath, '--json'], { env: isolatedEnv });
    assert.strictEqual(compVerOkCli.status, 0, `culkibo compliance-bundle --verify falló: ${compVerOkCli.stderr}`);
    assert.strictEqual(JSON.parse(compVerOkCli.stdout).valid, true);

    const tamperedBundle = JSON.parse(fs.readFileSync(bundleOutPath, 'utf8'));
    tamperedBundle.payload.overallScore = tamperedBundle.payload.overallScore === 100 ? 99 : 100;
    const tamperedPath = path.join(tmpRoot, 'compliance-tampered.json');
    fs.writeFileSync(tamperedPath, JSON.stringify(tamperedBundle), 'utf8');
    const compVerBadCli = await runCli(['compliance-bundle', '--verify', tamperedPath, '--json'], { env: isolatedEnv });
    assert.strictEqual(compVerBadCli.status, 1, 'compliance-bundle --verify debe retornar exit=1 en bundle alterado');
    assert.strictEqual(JSON.parse(compVerBadCli.stdout).valid, false);

    // culkibo admission-check: privileged + /:/host:rw -> DENY exit 1; hardened soc2-strict -> ALLOW exit 0
    const admDenyCli = await runCli(['admission-check', '--preset', 'baseline', '--privileged', '--mount', '/:/host:rw', '--port-bind', '0.0.0.0:5432', '--json'], { env: isolatedEnv });
    assert.strictEqual(admDenyCli.status, 1, 'culkibo admission-check debe retornar exit=1 en DENY');
    const admDenyJson = JSON.parse(admDenyCli.stdout);
    assert.strictEqual(admDenyJson.ok, false);
    assert.strictEqual(admDenyJson.decision, 'DENY');
    assert.ok(admDenyJson.enforcedViolations.length >= 3);

    const admAllowCli = await runCli(['admission-check', '--preset', 'soc2-strict', '--image', 'ghcr.io/acme/api:v2.4.1', '--uid', '1000', '--memory', '512', '--cpu', '1', '--healthcheck', '/health', '--attested', '--json'], { env: isolatedEnv });
    assert.strictEqual(admAllowCli.status, 0, `culkibo admission-check ALLOW falló: ${admAllowCli.stderr} ${admAllowCli.stdout}`);
    const admAllowJson = JSON.parse(admAllowCli.stdout);
    assert.strictEqual(admAllowJson.ok, true);
    assert.strictEqual(admAllowJson.decision, 'ALLOW');
    assert.strictEqual(admAllowJson.score, 100);
    console.log(`  ✓ Pioneer CLI Cycle-11 verificado (culkibo compliance-bundle Ed25519 sign/verify/tamper, culkibo admission-check DENY=1/ALLOW=0)`);

    // 16. Pioneer Cycle-12 CLI: `culkibo lint-sql [sqlFile]` (unsafe exit 1 vs safe exit 0) & `culkibo audit-licenses` (MIT compliant exit 0 vs AGPL/SSPL exit 1)
    const unsafeSqlCli = await runCli([
      'lint-sql',
      '--sql', 'CREATE INDEX idx_users_email ON users(email); DROP TABLE legacy_sessions;',
      '--json'
    ], { env: isolatedEnv });
    assert.strictEqual(unsafeSqlCli.status, 1, 'culkibo lint-sql debe salir con código 1 ante DDL bloqueante');
    const unsafeSqlJson = JSON.parse(unsafeSqlCli.stdout);
    assert.strictEqual(unsafeSqlJson.ok, false);
    assert.strictEqual(unsafeSqlJson.safe, false);
    assert.ok(Array.isArray(unsafeSqlJson.blockers) && unsafeSqlJson.blockers.length >= 3);

    const safeSqlPath = path.join(tmpRoot, 'safe-migration.sql');
    fs.writeFileSync(
      safeSqlPath,
      "SET lock_timeout = '5s';\nSET statement_timeout = '30s';\nCREATE INDEX CONCURRENTLY idx_users_email ON users(email);\n",
      'utf8'
    );
    const safeSqlCli = await runCli(['lint-sql', safeSqlPath, '--json'], { env: isolatedEnv });
    assert.strictEqual(safeSqlCli.status, 0, `culkibo lint-sql seguro falló: ${safeSqlCli.stderr} ${safeSqlCli.stdout}`);
    const safeSqlJson = JSON.parse(safeSqlCli.stdout);
    assert.strictEqual(safeSqlJson.ok, true);
    assert.strictEqual(safeSqlJson.safe, true);
    assert.strictEqual(safeSqlJson.blockers.length, 0);
    assert.strictEqual(safeSqlJson.score, 100);

    // culkibo audit-licenses: isolated MIT-only dir -> exit 0; AGPL+SSPL dir -> exit 1 under saas-strict, exit 0 under audit-only
    const mitProjDir = path.join(tmpRoot, 'lic-mit-app');
    fs.mkdirSync(mitProjDir, { recursive: true });
    fs.writeFileSync(path.join(mitProjDir, 'package.json'), JSON.stringify({ name: 'mit-app', version: '1.0.0', license: 'MIT' }, null, 2), 'utf8');
    fs.writeFileSync(path.join(mitProjDir, 'package-lock.json'), JSON.stringify({
      name: 'mit-app',
      lockfileVersion: 3,
      packages: {
        '': { name: 'mit-app', version: '1.0.0', license: 'MIT' },
        'node_modules/fast-json': { version: '1.2.3', license: 'MIT' },
        'node_modules/safe-http': { version: '2.0.0', license: 'Apache-2.0' }
      }
    }, null, 2), 'utf8');

    const licPassCli = await runCli(['audit-licenses', '--policy', 'saas-strict', '--dir', mitProjDir, '--json'], { env: isolatedEnv });
    assert.strictEqual(licPassCli.status, 0, `culkibo audit-licenses MIT falló: ${licPassCli.stderr} ${licPassCli.stdout}`);
    const licPassJson = JSON.parse(licPassCli.stdout);
    assert.strictEqual(licPassJson.ok, true);
    assert.strictEqual(licPassJson.compliant, true);
    assert.strictEqual(licPassJson.violations.length, 0);

    const agplProjDir = path.join(tmpRoot, 'lic-agpl-app');
    fs.mkdirSync(agplProjDir, { recursive: true });
    fs.writeFileSync(path.join(agplProjDir, 'package.json'), JSON.stringify({ name: 'agpl-app', version: '1.0.0', license: 'MIT' }, null, 2), 'utf8');
    fs.writeFileSync(path.join(agplProjDir, 'package-lock.json'), JSON.stringify({
      name: 'agpl-app',
      lockfileVersion: 3,
      packages: {
        '': { name: 'agpl-app', version: '1.0.0', license: 'MIT' },
        'node_modules/copyleft-pdf': { version: '3.0.0', license: 'AGPL-3.0-only' },
        'node_modules/source-avail-db': { version: '1.0.0', license: 'SSPL-1.0' }
      }
    }, null, 2), 'utf8');

    const licFailCli = await runCli(['audit-licenses', '--policy', 'saas-strict', '--dir', agplProjDir, '--json'], { env: isolatedEnv });
    assert.strictEqual(licFailCli.status, 1, 'culkibo audit-licenses debe salir con código 1 ante AGPL/SSPL bajo saas-strict');
    const licFailJson = JSON.parse(licFailCli.stdout);
    assert.strictEqual(licFailJson.ok, false);
    assert.strictEqual(licFailJson.compliant, false);
    assert.strictEqual(licFailJson.violations.length, 2);

    const licWarnCli = await runCli(['audit-licenses', '--policy', 'audit-only', '--dir', agplProjDir, '--json'], { env: isolatedEnv });
    assert.strictEqual(licWarnCli.status, 0, `culkibo audit-licenses audit-only falló: ${licWarnCli.stderr}`);
    const licWarnJson = JSON.parse(licWarnCli.stdout);
    assert.strictEqual(licWarnJson.compliant, true);
    assert.ok(licWarnJson.warnings.length >= 2);
    console.log(`  ✓ Pioneer CLI Cycle-12 verificado (culkibo lint-sql unsafe=1/safe=0, culkibo audit-licenses MIT=0/AGPL+SSPL=1/audit-only=0, culkibo demo 145 tools)`);

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
