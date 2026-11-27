const assert = require('assert');
const mcpServer = require('../server/services/mcpServer');

async function testMcp() {
  console.log('🧪 Testing Model Context Protocol (MCP) Server...');

  // 1. JSON-RPC Initialize
  const initRes = await mcpServer.handleJsonRpc({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {}
  });
  assert.strictEqual(initRes.jsonrpc, '2.0');
  assert.strictEqual(initRes.id, 1);
  assert.strictEqual(initRes.result.serverInfo.name, 'culkibo-mcp-orchestrator');
  assert.strictEqual(initRes.result.capabilities.prompts.listChanged, false, 'initialize debe anunciar prompts: { listChanged: false }');
  console.log('  ✓ MCP JSON-RPC initialize handshake passed (incl. prompts capability)');

  // 2. tools/list
  const toolsRes = await mcpServer.handleJsonRpc({
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/list',
    params: {}
  });
  assert.strictEqual(toolsRes.jsonrpc, '2.0');
  assert.ok(Array.isArray(toolsRes.result.tools));
  assert.ok(toolsRes.result.tools.some(t => t.name === 'culkibo_list_pods'));
  assert.ok(toolsRes.result.tools.some(t => t.name === 'culkibo_hot_sync'));
  assert.ok(toolsRes.result.tools.some(t => t.name === 'culkibo_issue_wildcard_ssl'));
  assert.ok(toolsRes.result.tools.some(t => t.name === 'culkibo_analyze_wordpress'));
  assert.ok(toolsRes.result.tools.some(t => t.name === 'culkibo_import_compose'));
  assert.ok(toolsRes.result.tools.some(t => t.name === 'culkibo_get_remote_access'));
  assert.ok(toolsRes.result.tools.some(t => t.name === 'culkibo_get_observability'));
  assert.ok(toolsRes.result.tools.some(t => t.name === 'culkibo_system_doctor'));
  assert.ok(toolsRes.result.tools.some(t => t.name === 'culkibo_link_database'));
  assert.ok(toolsRes.result.tools.some(t => t.name === 'culkibo_toggle_maintenance'));
  assert.ok(toolsRes.result.tools.some(t => t.name === 'culkibo_get_deploy_queue'));
  assert.ok(toolsRes.result.tools.length >= 52, `Se esperaban >=52 herramientas MCP, hay ${toolsRes.result.tools.length}`);
  console.log(`  ✓ MCP tools/list passed (${toolsRes.result.tools.length} AI tools exposed)`);

  // 3. tools/call: culkibo_list_pods
  const callPodsRes = await mcpServer.handleJsonRpc({
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: {
      name: 'culkibo_list_pods',
      arguments: {}
    }
  });
  assert.strictEqual(callPodsRes.jsonrpc, '2.0');
  assert.ok(callPodsRes.result.content);
  assert.ok(callPodsRes.result.content[0].text.includes('The Forge'));
  console.log('  ✓ MCP tools/call (culkibo_list_pods) executed successfully');

  // 4. tools/call: culkibo_hot_sync
  const callSyncRes = await mcpServer.handleJsonRpc({
    jsonrpc: '2.0',
    id: 4,
    method: 'tools/call',
    params: {
      name: 'culkibo_hot_sync',
      arguments: { changedFile: 'src/api/auth.py', diffSize: '8 lines' }
    }
  });
    assert.strictEqual(callSyncRes.jsonrpc, '2.0');
    assert.ok(callSyncRes.result.content[0].text.includes('syncDurationMs'));
    console.log('  ✓ MCP tools/call (culkibo_hot_sync) executed successfully');

  // 5. tools/call: culkibo_inspect_ingress
  const callIngressRes = await mcpServer.handleJsonRpc({
    jsonrpc: '2.0',
    id: 5,
    method: 'tools/call',
    params: {
      name: 'culkibo_inspect_ingress',
      arguments: { hostname: 'preview.culkibo.dev' }
    }
  });
  assert.strictEqual(callIngressRes.jsonrpc, '2.0');
  assert.ok(callIngressRes.result.content[0].text.includes('*.culkibo.dev'));
  console.log('  ✓ MCP tools/call (culkibo_inspect_ingress) executed successfully');

  // 6. tools/call: culkibo_manage_watcher
  const callWatcherRes = await mcpServer.handleJsonRpc({
    jsonrpc: '2.0',
    id: 6,
    method: 'tools/call',
    params: {
      name: 'culkibo_manage_watcher',
      arguments: { action: 'status' }
    }
  });
  assert.strictEqual(callWatcherRes.jsonrpc, '2.0');
  assert.ok(callWatcherRes.result.content[0].text.includes('isWatching'));
  console.log('  ✓ MCP tools/call (culkibo_manage_watcher) executed successfully');

  // 7. tools/call: culkibo_docker_status
  const callDockerStatus = await mcpServer.handleJsonRpc({
    jsonrpc: '2.0',
    id: 7,
    method: 'tools/call',
    params: {
      name: 'culkibo_docker_status',
      arguments: {}
    }
  });
  assert.strictEqual(callDockerStatus.jsonrpc, '2.0');
  assert.ok(callDockerStatus.result.content[0].text.includes('mode'));
  console.log('  ✓ MCP tools/call (culkibo_docker_status) executed successfully');

  // 8. tools/call: culkibo_docker_containers
  const callDockerContainers = await mcpServer.handleJsonRpc({
    jsonrpc: '2.0',
    id: 8,
    method: 'tools/call',
    params: {
      name: 'culkibo_docker_containers',
      arguments: {}
    }
  });
  assert.strictEqual(callDockerContainers.jsonrpc, '2.0');
  assert.ok(callDockerContainers.result.content[0].text.includes('containers'));
  console.log('  ✓ MCP tools/call (culkibo_docker_containers) executed successfully');

  // 9. Audit Log verification
  const audit = mcpServer.getAuditLog(10);
  assert.ok(audit.length >= 6);
  assert.strictEqual(audit[0].toolName, 'culkibo_docker_containers');
  console.log('  ✓ MCP audit trail verified');

  // 10. Anotaciones de herramienta (2026-07-28)
  await testToolAnnotations();

  // 11. Transporte Streamable HTTP (2026-07-28)
  await testStreamableHttpTransport();

  // 12. MCP 2.0/2.1/2026: 109 herramientas, 7 recursos, 13 prompts (8 playbooks), dryRun universal, RBAC y anti-IDOR
  await testMcpV2Capabilities();

  // 13. MCP 2.1: perfiles (-80% contexto), meta-discovery, validación estricta, 4 handlers reparados, 5 anti-IDOR, self-healing ops
  await testMcpV21Superpowers();

  // 14. MCP 2026 Pioneer: 8 playbooks interactivos, culkibo_ship_and_verify (secret scan + confirmToken + smoke + auto-rollback) y culkibo_export_agent_kit
  await testMcp2026PioneerUpgrades();

  // 15. MCP 2026 Cycle-2: World-First PaaS MCP Apps (ui://culkibo/*), culkibo_smartpack_plan y culkibo_edge_tunnel (111 tools)
  await testMcp2026Cycle2AppsAndTools();

  // 16. MCP 2026 Cycle-4: Official Async Tasks (tasks/list|get|result|cancel + RBAC), elicitation/create, SLSA & OTLP (113 tools)
  await testMcp2026Cycle4TasksElicitationAndTools();

  // 17. MCP 2026 Cycle-6: Shadow Traffic Replay, Whole-Stack Time-Machine & FinOps Savings (116 tools)
  await testMcp2026Cycle6ShadowTimeMachineFinOps();

  // 18. MCP 2026 Cycle-7: Build Auto-Healer, WireGuard Fleet Mesh, Cron Timeline & Edge Bot-Shield (120 tools)
  await testMcp2026Cycle7HealerMeshTimelineShield();

  // 19. MCP 2026 Cycle-8: Autonomous Triage, SBOM CVE Scan, Config Drift + PgBouncer, OpenTofu IaC & Secret Leases (125 tools)
  await testMcp2026Cycle8TriageCveDriftIacLease();

  console.log('✅ All MCP tests passed!\n');
}

/**
 * Las anotaciones son lo que un cliente usa para decidir si pide confirmación
 * a la persona usuaria. Una herramienta que muta marcada como `readOnlyHint`
 * hace que se ejecute sin preguntar, así que eso se fija aquí.
 */
async function testToolAnnotations() {
  const tools = mcpServer.getToolsDefinition();
  assert.strictEqual(tools.length, 125, 'El catálogo MCP 2026 debe tener exactamente 125 herramientas anotadas');
  const uniqueNames = new Set(tools.map(t => t.name));
  assert.strictEqual(uniqueNames.size, 125, 'No puede haber nombres de herramientas duplicados');

  for (const tool of tools) {
    assert.ok(tool.title, `${tool.name} debe declarar title`);
    assert.ok(tool.annotations, `${tool.name} debe declarar annotations`);
    assert.strictEqual(typeof tool.annotations.readOnlyHint, 'boolean', `${tool.name}.readOnlyHint`);
    assert.strictEqual(typeof tool.annotations.openWorldHint, 'boolean', `${tool.name}.openWorldHint`);
    assert.ok(mcpServer.TOOL_POLICIES[tool.name], `${tool.name} debe tener política RBAC en TOOL_POLICIES`);
    if (tool.annotations.readOnlyHint) {
      // `destructiveHint` e `idempotentHint` solo significan algo cuando la
      // herramienta muta; declararlos en una de solo lectura es ruido.
      assert.strictEqual(tool.annotations.destructiveHint, undefined, `${tool.name} es de solo lectura y no debe declarar destructiveHint`);
    } else {
      assert.strictEqual(typeof tool.annotations.destructiveHint, 'boolean', `${tool.name}.destructiveHint`);
      assert.strictEqual(typeof tool.annotations.idempotentHint, 'boolean', `${tool.name}.idempotentHint`);
    }
  }

  const roCount = tools.filter(t => t.annotations.readOnlyHint).length;
  const mutCount = tools.filter(t => !t.annotations.readOnlyHint).length;
  const destCount = tools.filter(t => t.annotations.destructiveHint === true).length;
  const dryRunCount = tools.filter(t => Boolean(t.inputSchema?.properties?.dryRun)).length;
  const outputSchemaCount = tools.filter(t => Boolean(t.outputSchema)).length;
  assert.strictEqual(roCount, 57, `Se esperaban 57 herramientas RO, hay ${roCount}`);
  assert.strictEqual(mutCount, 68, `Se esperaban 68 herramientas mutadoras, hay ${mutCount}`);
  assert.strictEqual(destCount, 38, `Se esperaban 38 herramientas destructivas, hay ${destCount}`);
  assert.strictEqual(dryRunCount, 41, `Se esperaban 41 herramientas con dryRun, hay ${dryRunCount}`);
  assert.ok(outputSchemaCount >= 78, `Se esperaban >=78 herramientas con outputSchema, hay ${outputSchemaCount}`);

  const byName = Object.fromEntries(tools.map(t => [t.name, t]));
  const mustMutate = [
    'culkibo_create_project', 'culkibo_add_resource', 'culkibo_set_project_env',
    'culkibo_deploy_project', 'culkibo_hot_sync', 'culkibo_switch_traffic',
    'culkibo_manage_domain', 'culkibo_manage_watcher',
    'culkibo_create_sslip_domain', 'culkibo_export_backup', 'culkibo_restore_backup',
    'culkibo_github_connect', 'culkibo_github_disconnect', 'culkibo_create_project_from_github',
    'culkibo_import_compose'
  ];
  for (const name of mustMutate) {
    assert.strictEqual(byName[name].annotations.readOnlyHint, false, `${name} muta estado y no puede anotarse como readOnly`);
  }

  const mustBeDestructive = [
    'culkibo_switch_traffic', 'culkibo_manage_domain', 'culkibo_restore_backup',
    'culkibo_github_disconnect', 'culkibo_deploy_project'
  ];
  for (const name of mustBeDestructive) {
    assert.strictEqual(byName[name].annotations.destructiveHint, true, `${name} destruye o reemplaza estado vivo`);
  }

  const mustBeReadOnly = [
    'culkibo_list_projects', 'culkibo_get_project', 'culkibo_list_pods',
    'culkibo_inspect_ingress', 'culkibo_get_logs', 'culkibo_docker_status',
    'culkibo_docker_containers', 'culkibo_github_status', 'culkibo_github_list_repos',
    'culkibo_github_get_branches', 'culkibo_github_auto_detect',
    // No emite nada: devuelve siempre el error de «no implementado». Estaba en
    // `mustMutate` porque fabricaba un PEM y lo guardaba en disco como si fuera
    // un certificado real.
    'culkibo_issue_wildcard_ssl',
    'culkibo_analyze_wordpress', 'culkibo_get_remote_access'
  ];
  for (const name of mustBeReadOnly) {
    assert.strictEqual(byName[name].annotations.readOnlyHint, true, `${name} no muta nada`);
  }

  // Las que hablan con un tercero tienen que declararlo: de ahí depende la
  // clasificación de sus fallos como reintentables.
  assert.strictEqual(byName.culkibo_github_list_repos.annotations.openWorldHint, true);
  assert.strictEqual(byName.culkibo_list_pods.annotations.openWorldHint, false);

  // `culkibo_issue_wildcard_ssl` ya no emite nada: devuelve siempre un error
  // explicativo. Sus anotaciones tienen que decirlo, o un agente creerá que
  // invocarla cambia algo — que es justo lo que hacía cuando fabricaba un PEM.
  assert.strictEqual(byName.culkibo_issue_wildcard_ssl.annotations.readOnlyHint, true,
    'La emisión de comodín no está implementada: no muta nada');
  assert.strictEqual(byName.culkibo_issue_wildcard_ssl.annotations.openWorldHint, false,
    'No habla con ninguna CA: ya no hay llamada ACME que pueda fallar de forma reintentable');
  assert.ok(/NOT IMPLEMENTED/.test(byName.culkibo_issue_wildcard_ssl.description),
    'La descripción debe advertir al agente de que la herramienta no emite nada');

  assert.ok(byName.culkibo_list_pods.outputSchema, 'culkibo_list_pods debe declarar outputSchema');
  console.log(`  ✓ Anotaciones verificadas en las ${tools.length} herramientas (${tools.filter(t => t.annotations.readOnlyHint).length} de solo lectura, ${tools.filter(t => t.annotations.destructiveHint).length} destructivas)`);
}

/**
 * Transporte Streamable HTTP de la revisión 2026-07-28.
 *
 * Se monta el router real sobre un puerto efímero en vez de hablar con el
 * daemon de turno: así la suite no depende de que haya uno levantado ni del
 * puerto 3030, y prueba el cableado de rutas de verdad.
 */
async function testStreamableHttpTransport() {
  const express = require('express');
  const { authMiddleware } = require('../server/middleware/auth');
  const apiRouter = require('../server/routes/api');

  const app = express();
  app.use(express.json({ limit: '10mb' }));
  app.use(authMiddleware);
  app.use('/api', apiRouter);

  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });

  const V = mcpServer.protocol.PROTOCOL_VERSION;
  const base = `http://127.0.0.1:${server.address().port}`;
  const endpoint = `${base}/api/mcp`;

  const meta = () => ({
    'io.modelcontextprotocol/protocolVersion': V,
    'io.modelcontextprotocol/clientCapabilities': {},
    'io.modelcontextprotocol/clientInfo': { name: 'culkibo-test-client', version: '1.0.0' }
  });

  const post = (headers, body) => fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      ...headers
    },
    body: JSON.stringify(body)
  });

  try {
    assert.strictEqual(V, '2026-07-28', 'La revisión declarada debe ser la vigente');

    // 1. server/discover — obligatorio en esta revisión.
    const discoverRes = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'server/discover' },
      { jsonrpc: '2.0', id: 'disc-1', method: 'server/discover', params: { _meta: meta() } }
    );
    assert.strictEqual(discoverRes.status, 200);
    const discover = await discoverRes.json();
    assert.strictEqual(discover.id, 'disc-1');
    assert.strictEqual(discover.result.resultType, 'complete');
    assert.deepStrictEqual(discover.result.supportedVersions, [V]);
    assert.ok(discover.result.capabilities.tools, 'discover debe anunciar la capacidad tools');
    assert.strictEqual(
      discover.result._meta['io.modelcontextprotocol/serverInfo'].name,
      'culkibo-mcp-orchestrator'
    );
    assert.ok(discover.result.instructions.length > 0, 'discover debe traer instrucciones para el agente');
    console.log('  ✓ server/discover responde versiones, capacidades e identidad');

    // 2. Cabecera y cuerpo discrepan en la versión -> 400 con -32020.
    const mismatchRes = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'tools/list' },
      {
        jsonrpc: '2.0',
        id: 'mm-1',
        method: 'tools/list',
        params: { _meta: { ...meta(), 'io.modelcontextprotocol/protocolVersion': '2025-11-25' } }
      }
    );
    assert.strictEqual(mismatchRes.status, 400, 'Un desacuerdo cabecera/cuerpo debe ser 400');
    const mismatch = await mismatchRes.json();
    assert.strictEqual(mismatch.error.code, -32020, 'Debe ser HeaderMismatch');
    assert.strictEqual(mismatch.id, 'mm-1');
    assert.strictEqual(mismatch.error.data.header.value, V);
    assert.strictEqual(mismatch.error.data.body.value, '2025-11-25');
    console.log('  ✓ HeaderMismatch (-32020) al discrepar MCP-Protocol-Version y _meta');

    // 3. Mcp-Method ausente y Mcp-Name discrepante -> también -32020.
    const noMethodHeader = await post(
      { 'MCP-Protocol-Version': V },
      { jsonrpc: '2.0', id: 'mm-2', method: 'tools/list', params: { _meta: meta() } }
    );
    assert.strictEqual(noMethodHeader.status, 400);
    assert.strictEqual((await noMethodHeader.json()).error.code, -32020);

    const badName = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'tools/call', 'Mcp-Name': 'culkibo_list_projects' },
      {
        jsonrpc: '2.0',
        id: 'mm-3',
        method: 'tools/call',
        params: { name: 'culkibo_list_pods', arguments: {}, _meta: meta() }
      }
    );
    assert.strictEqual(badName.status, 400);
    const badNameBody = await badName.json();
    assert.strictEqual(badNameBody.error.code, -32020);
    assert.strictEqual(badNameBody.error.data.body.value, 'culkibo_list_pods');
    console.log('  ✓ HeaderMismatch (-32020) por Mcp-Method ausente y por Mcp-Name discrepante');

    // 4. Mcp-Name en el sentinela Base64 de la especificación.
    const encodedName = `=?base64?${Buffer.from('culkibo_list_pods', 'utf8').toString('base64')}?=`;
    const sentinelRes = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'tools/call', 'Mcp-Name': encodedName },
      {
        jsonrpc: '2.0',
        id: 'b64-1',
        method: 'tools/call',
        params: { name: 'culkibo_list_pods', arguments: {}, _meta: meta() }
      }
    );
    assert.strictEqual(sentinelRes.status, 200, 'El sentinela Base64 debe decodificarse antes de comparar');
    console.log('  ✓ Mcp-Name codificado en Base64 se decodifica antes de comparar');

    // 5. Versión no soportada -> -32022 listando las que sí.
    const oldVersionRes = await post(
      { 'MCP-Protocol-Version': '2025-06-18', 'Mcp-Method': 'tools/list' },
      {
        jsonrpc: '2.0',
        id: 'ver-1',
        method: 'tools/list',
        params: { _meta: { ...meta(), 'io.modelcontextprotocol/protocolVersion': '2025-06-18' } }
      }
    );
    assert.strictEqual(oldVersionRes.status, 400);
    const oldVersion = await oldVersionRes.json();
    assert.strictEqual(oldVersion.error.code, -32022);
    assert.deepStrictEqual(oldVersion.error.data.supported, [V]);
    assert.strictEqual(oldVersion.error.data.requested, '2025-06-18');
    console.log('  ✓ UnsupportedProtocolVersion (-32022) enumera las versiones soportadas');

    // 6. `_meta` obligatorio ausente -> -32602 diciendo qué falta.
    const noMetaRes = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'tools/list' },
      { jsonrpc: '2.0', id: 'meta-1', method: 'tools/list', params: {} }
    );
    assert.strictEqual(noMetaRes.status, 400);
    const noMeta = await noMetaRes.json();
    assert.strictEqual(noMeta.error.code, -32602);
    assert.ok(noMeta.error.data.missing.includes('io.modelcontextprotocol/protocolVersion'));
    assert.ok(noMeta.error.data.missing.includes('io.modelcontextprotocol/clientCapabilities'));
    console.log('  ✓ _meta obligatorio ausente -> -32602 con la lista de campos que faltan');

    // 7. tools/list sobre el transporte nuevo + perfiles ?profile= y params.query.
    assert.strictEqual(discover.result.capabilities.tools.filtering, true, 'discover debe anunciar capabilities.tools.filtering');
    const listRes = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'tools/list' },
      { jsonrpc: '2.0', id: 'list-1', method: 'tools/list', params: { _meta: meta() } }
    );
    const list = await listRes.json();
    assert.strictEqual(list.result.resultType, 'complete');
    assert.strictEqual(list.result.tools.length, 125);

    // 7b. ?profile=core reduce el tamaño/tokens de tools/list en >=80% y mantiene callable herramientas descubiertas.
    const coreListRes = await fetch(`${endpoint}?profile=core`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        'MCP-Protocol-Version': V,
        'Mcp-Method': 'tools/list'
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 'list-core', method: 'tools/list', params: { _meta: meta() } })
    });
    assert.strictEqual(coreListRes.status, 200);
    assert.strictEqual(coreListRes.headers.get('x-culkibo-mcp-profile'), 'core');
    const coreList = await coreListRes.json();
    assert.strictEqual(coreList.result.profile, 'core');
    assert.ok(coreList.result.tools.some((t) => t.name === 'culkibo_search_tools'));
    assert.ok(coreList.result.tools.some((t) => t.name === 'culkibo_diagnose_incident'));
    assert.ok(coreList.result.tools.some((t) => t.name === 'culkibo_auto_remediate'));
    const fullBytes = Buffer.byteLength(JSON.stringify(list.result.tools), 'utf8');
    const coreBytes = Buffer.byteLength(JSON.stringify(coreList.result.tools), 'utf8');
    const savedRatio = 1 - (coreBytes / fullBytes);
    assert.ok(savedRatio >= 0.80, `?profile=core debe recortar >=80% de tokens/bytes (logró ${(savedRatio * 100).toFixed(1)}%)`);

    // Invocar una herramienta fuera de ?profile=core tras descubrirla sigue funcionando
    const crossProfileCall = await fetch(`${endpoint}?profile=core`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'MCP-Protocol-Version': V,
        'Mcp-Method': 'tools/call',
        'Mcp-Name': 'culkibo_list_pods'
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 'call-xp', method: 'tools/call', params: { name: 'culkibo_list_pods', arguments: {}, _meta: meta() } })
    });
    assert.strictEqual(crossProfileCall.status, 200);
    assert.strictEqual((await crossProfileCall.json()).result.isError, false);

    // Perfil inválido en query string -> 400 + -32602
    const badProfileRes = await fetch(`${endpoint}?profile=nonexistent`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'MCP-Protocol-Version': V,
        'Mcp-Method': 'tools/list'
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 'bad-prof', method: 'tools/list', params: { _meta: meta() } })
    });
    assert.strictEqual(badProfileRes.status, 400);
    assert.strictEqual((await badProfileRes.json()).error.code, -32602);

    // params.query en tools/list
    const queryListRes = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'tools/list' },
      { jsonrpc: '2.0', id: 'list-q', method: 'tools/list', params: { query: 'oom memory', limit: 5, _meta: meta() } }
    );
    const queryList = await queryListRes.json();
    assert.ok(queryList.result.tools.length >= 1 && queryList.result.tools.length <= 5);
    console.log(`  ✓ tools/list Streamable HTTP (${list.result.tools.length} tools; ?profile=core -> ${coreList.result.tools.length} tools, -${(savedRatio * 100).toFixed(1)}% bytes, params.query ok)`);

    // 8. tools/call con salida estructurada.
    const callRes = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'tools/call', 'Mcp-Name': 'culkibo_list_pods' },
      {
        jsonrpc: '2.0',
        id: 'call-1',
        method: 'tools/call',
        params: { name: 'culkibo_list_pods', arguments: {}, _meta: meta() }
      }
    );
    const call = await callRes.json();
    assert.strictEqual(call.result.resultType, 'complete');
    assert.strictEqual(call.result.isError, false);
    assert.ok(call.result.structuredContent.pods, 'tools/call debe traer structuredContent');
    console.log('  ✓ tools/call devuelve content y structuredContent');

    // 9. Error de herramienta: accionable, no un volcado de texto.
    const failRes = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'tools/call', 'Mcp-Name': 'culkibo_get_project' },
      {
        jsonrpc: '2.0',
        id: 'call-2',
        method: 'tools/call',
        params: { name: 'culkibo_get_project', arguments: { projectId: 'no_existe_seguro' }, _meta: meta() }
      }
    );
    const fail = await failRes.json();
    assert.strictEqual(failRes.status, 200, 'Un fallo de herramienta no es un error de protocolo');
    assert.strictEqual(fail.result.isError, true);
    const failEnvelope = JSON.parse(fail.result.content[0].text);
    assert.strictEqual(failEnvelope.code, 'PROJECT_NOT_FOUND');
    assert.strictEqual(failEnvelope.retryable, false);
    assert.ok(failEnvelope.remediation.includes('culkibo_list_projects'));
    assert.strictEqual(failEnvelope.details.projectId, 'no_existe_seguro');

    // Un argumento obligatorio ausente se corrige solo si se dice cuál.
    const missingArgRes = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'tools/call', 'Mcp-Name': 'culkibo_get_project' },
      {
        jsonrpc: '2.0',
        id: 'call-3',
        method: 'tools/call',
        params: { name: 'culkibo_get_project', arguments: {}, _meta: meta() }
      }
    );
    const missingArg = JSON.parse((await missingArgRes.json()).result.content[0].text);
    assert.strictEqual(missingArg.code, 'MISSING_ARGUMENT');
    assert.strictEqual(missingArg.retryable, true);
    assert.deepStrictEqual(missingArg.details.missing, ['projectId']);
    console.log('  ✓ Errores de herramienta estructurados (code, retryable, remediation, details)');

    // 10. Notificación -> 202 sin cuerpo.
    const notifRes = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'notifications/progress' },
      { jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: 'x', progress: 1 } }
    );
    assert.strictEqual(notifRes.status, 202);
    assert.strictEqual((await notifRes.text()).length, 0, 'Una notificación se contesta sin cuerpo');
    console.log('  ✓ Notificación aceptada con 202 y sin cuerpo');

    // 11. GET y DELETE ya no existen en esta revisión.
    const getRes = await fetch(endpoint);
    assert.strictEqual(getRes.status, 405);
    assert.strictEqual(getRes.headers.get('allow'), 'POST');
    const deleteRes = await fetch(endpoint, { method: 'DELETE' });
    assert.strictEqual(deleteRes.status, 405);
    console.log('  ✓ GET y DELETE sobre el endpoint MCP responden 405 con Allow: POST');

    // 12. resources/list, resources/read, prompts/list, prompts/get + método desconocido -> 404 con -32601.
    const resListHttp = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'resources/list' },
      { jsonrpc: '2.0', id: 'res-1', method: 'resources/list', params: { _meta: meta() } }
    );
    assert.strictEqual(resListHttp.status, 200);
    const resList = await resListHttp.json();
    assert.ok(resList.result.resources.some((r) => r.uri === 'culkibo://projects'));

    const resReadHttp = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'resources/read', 'Mcp-Name': 'culkibo://pods' },
      { jsonrpc: '2.0', id: 'res-2', method: 'resources/read', params: { uri: 'culkibo://pods', _meta: meta() } }
    );
    assert.strictEqual(resReadHttp.status, 200);
    const resRead = await resReadHttp.json();
    assert.ok(resRead.result.contents[0].text.includes('The Forge'));

    const promptsListHttp = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'prompts/list' },
      { jsonrpc: '2.0', id: 'prm-1', method: 'prompts/list', params: { _meta: meta() } }
    );
    assert.strictEqual(promptsListHttp.status, 200);
    const promptsList = await promptsListHttp.json();
    assert.ok(promptsList.result.prompts.some((p) => p.name === 'debug-failed-deploy'));

    const promptGetHttp = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'prompts/get', 'Mcp-Name': 'audit-security-tls' },
      { jsonrpc: '2.0', id: 'prm-2', method: 'prompts/get', params: { name: 'audit-security-tls', arguments: {}, _meta: meta() } }
    );
    assert.strictEqual(promptGetHttp.status, 200);
    const promptGet = await promptGetHttp.json();
    assert.ok(promptGet.result.messages[0].content.text.includes('culkibo_system_doctor'));

    const unknownRes = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'sampling/createMessage' },
      { jsonrpc: '2.0', id: 'unk-1', method: 'sampling/createMessage', params: { _meta: meta() } }
    );
    assert.strictEqual(unknownRes.status, 404);
    const unknown = await unknownRes.json();
    assert.strictEqual(unknown.error.code, -32601);
    assert.ok(unknown.error.data.supported.includes('server/discover'));
    console.log('  ✓ resources/*, prompts/* y método no implementado (404 -32601) verificados');

    // 13. Respuesta SSE cuando el cliente pide progreso.
    const streamRes = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'tools/call', 'Mcp-Name': 'culkibo_list_pods' },
      {
        jsonrpc: '2.0',
        id: 'sse-1',
        method: 'tools/call',
        params: {
          name: 'culkibo_list_pods',
          arguments: {},
          _meta: { ...meta(), progressToken: 'tok-1' }
        }
      }
    );
    assert.strictEqual(streamRes.status, 200);
    assert.ok(streamRes.headers.get('content-type').includes('text/event-stream'));
    assert.strictEqual(streamRes.headers.get('cache-control'), 'private, no-cache, no-transform');
    assert.strictEqual(streamRes.headers.get('x-accel-buffering'), 'no', 'El stream debe pedir a los proxies que no lo acumulen');
    const streamBody = await streamRes.text();
    assert.ok(streamBody.startsWith(':'), 'El stream debe abrir con un comentario keep-alive');
    const finalEvent = streamBody.split('\n').find(line => line.startsWith('data: '));
    const finalEnvelope = JSON.parse(finalEvent.slice('data: '.length));
    assert.strictEqual(finalEnvelope.id, 'sse-1');
    assert.strictEqual(finalEnvelope.result.resultType, 'complete');
    console.log('  ✓ Respuesta SSE con keep-alive, X-Accel-Buffering y respuesta final en el stream');

    // 14. Mcp-Session-Id y Last-Event-ID ya no existen: se ignoran sin eco.
    const ignoredHeadersRes = await post(
      {
        'MCP-Protocol-Version': V,
        'Mcp-Method': 'tools/list',
        'Mcp-Session-Id': 'sesion-de-otra-era',
        'Last-Event-ID': '42'
      },
      { jsonrpc: '2.0', id: 'ign-1', method: 'tools/list', params: { _meta: meta() } }
    );
    assert.strictEqual(ignoredHeadersRes.status, 200);
    assert.strictEqual(ignoredHeadersRes.headers.get('mcp-session-id'), null, 'No se acuñan ni se devuelven sesiones');
    console.log('  ✓ Mcp-Session-Id y Last-Event-ID se ignoran sin devolver eco');

    // 15. El transporte antiguo sigue vivo, pero marcado como deprecado.
    const legacyRes = await fetch(`${base}/api/mcp/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 'legacy-1', method: 'initialize', params: {} })
    });
    assert.strictEqual(legacyRes.status, 200, 'La era antigua no puede romperse');
    assert.strictEqual(legacyRes.headers.get('deprecation'), 'true');
    assert.ok(legacyRes.headers.get('link').includes('/api/mcp'), 'Debe apuntar al sucesor');
    const legacy = await legacyRes.json();
    assert.strictEqual(legacy.result.protocolVersion, '2024-11-05');
    console.log('  ✓ Transporte 2024-11-05 sigue funcionando y se anuncia como deprecado');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

async function testMcpV2Capabilities() {
  const express = require('express');
  const projectManager = require('../server/services/projectManager');
  const mcpStreamableHttp = require('../server/services/mcpStreamableHttp');
  const V = mcpServer.protocol.PROTOCOL_VERSION;

  // 1. 10 Recursos (7 culkibo://* + 3 ui://culkibo/* MCP Apps) y 13 Prompts
  const resources = mcpServer.listResources();
  assert.strictEqual(resources.length, 10, `Se esperaban 10 recursos MCP (7 JSON + 3 MCP Apps), hay ${resources.length}`);
  for (const uri of ['culkibo://projects', 'culkibo://pods', 'culkibo://doctor', 'culkibo://domains', 'culkibo://fleet', 'culkibo://uptime', 'culkibo://environments', 'ui://culkibo/topology', 'ui://culkibo/incident-remediator', 'ui://culkibo/coolify-migration-diff']) {
    assert.ok(resources.some(r => r.uri === uri), `Falta recurso ${uri}`);
  }
  const fleetRes = await mcpServer.readResource('culkibo://fleet');
  assert.ok(fleetRes.contents[0].text.includes('"servers"'));
  assert.ok(!fleetRes.contents[0].text.includes('privateKey'));
  const uptimeRes = await mcpServer.readResource('culkibo://uptime');
  assert.ok(uptimeRes.contents[0].text.includes('"monitors"'));
  const envRes = await mcpServer.readResource('culkibo://environments');
  assert.ok(envRes.contents[0].text.includes('"projects"'));

  const prompts = mcpServer.listPrompts();
  assert.strictEqual(prompts.length, 13, `Se esperaban 13 prompts MCP (8 playbooks + 5 heredados), hay ${prompts.length}`);
  for (const name of [
    'deploy_safely', 'migrate_from_coolify', 'debug_production_crash', 'zero_downtime_db_upgrade',
    'security_audit_stack', 'setup_wildcard_tls_and_tunnel', 'optimize_ram_and_costs', 'disaster_recovery_drill',
    'debug-failed-deploy', 'zero-downtime-release', 'audit-security-tls', 'culkibo_multi_server_rollout', 'culkibo_incident_triage'
  ]) {
    assert.ok(prompts.some(p => p.name === name), `Falta prompt ${name}`);
  }
  const rolloutPrompt = mcpServer.getPrompt('culkibo_multi_server_rollout', { projectId: 'proj_demo', targetServers: 'srv_eu' });
  assert.ok(rolloutPrompt.messages[0].content.text.includes('culkibo_canary_rollout'));
  const triagePrompt = mcpServer.getPrompt('culkibo_incident_triage', { projectId: 'proj_demo', hostname: 'app.demo.test' });
  assert.ok(triagePrompt.messages[0].content.text.includes('culkibo_diagnose_incident'));
  assert.ok(triagePrompt.messages[0].content.text.includes('culkibo_auto_remediate'));
  console.log('  ✓ MCP 2.0/2026: 7 recursos y 13 prompts (8 playbooks + 5 heredados) verificados');

  // 2. Bugfixes y redacción ampliada
  const catTool = mcpServer.getToolByName('culkibo_list_catalog_templates');
  assert.ok(catTool && !/14 plantillas/i.test(catTool.description), 'La descripción del catálogo no debe hardcodear "14 plantillas"');

  const missingDom = await mcpServer.executeTool('culkibo_set_domain_basic_auth', { domainId: 'no_existe_seguro', enabled: false });
  assert.strictEqual(missingDom.isError, true);
  const missingDomErr = JSON.parse(missingDom.content[0].text);
  assert.ok(missingDomErr.remediation.includes('culkibo_manage_domain'), 'Debe referenciar culkibo_manage_domain y no culkibo_list_domains');
  assert.ok(!missingDomErr.remediation.includes('culkibo_list_domains'));

  const redacted = mcpServer.redactForAudit({
    privateKey: 'raw-key',
    sshKey: 'ssh-ed25519 ...',
    inviteToken: 'cki_12345678_secretvalue',
    tokenHash: 'abcdef',
    signingSecret: 'whsec_123',
    masterKey: 'mk_123',
    note: 'token is ckp_12345678_supersecretvalue'
  });
  assert.strictEqual(redacted.privateKey, '***');
  assert.strictEqual(redacted.sshKey, '***');
  assert.strictEqual(redacted.inviteToken, '***');
  assert.strictEqual(redacted.tokenHash, '***');
  assert.strictEqual(redacted.signingSecret, '***');
  assert.strictEqual(redacted.masterKey, '***');
  assert.strictEqual(redacted.note, '***');
  console.log('  ✓ Redacción ampliada (privateKey/sshKey/inviteToken/ck*_) y bugfixes verificados');

  // 3. Universal dryRun: true (cero mutaciones) + RBAC + Anti-IDOR
  const projA = projectManager.create({ name: 'MCP2 Project A', description: 'RBAC A', maintenanceMode: false });
  const projB = projectManager.create({ name: 'MCP2 Project B', description: 'RBAC B', maintenanceMode: false });
  try {
    // 3a. dryRun: true en culkibo_toggle_maintenance NO muta el proyecto
    const dryMaint = await mcpServer.executeTool('culkibo_toggle_maintenance', {
      projectId: projA.id,
      enabled: true,
      dryRun: true
    });
    assert.strictEqual(dryMaint.isError, false);
    assert.strictEqual(dryMaint.structuredContent.dryRun, true);
    assert.strictEqual(dryMaint.structuredContent.wouldExecute, true);
    assert.ok(Array.isArray(dryMaint.structuredContent.effects) && dryMaint.structuredContent.effects.length > 0);
    assert.strictEqual(projectManager.getById(projA.id).maintenanceMode, false, 'dryRun: true NUNCA puede mutar estado');

    // Auditar que dryRun se registró con dryRun: true
    const latestAudit = mcpServer.getAuditLog(1)[0];
    assert.strictEqual(latestAudit.toolName, 'culkibo_toggle_maintenance');
    assert.strictEqual(latestAudit.dryRun, true);

    // 3b. dryRun: true en culkibo_fleet_remove_server('local') reporta bloqueador
    const dryLocalRemove = await mcpServer.executeTool('culkibo_fleet_remove_server', { serverId: 'local', dryRun: true });
    assert.strictEqual(dryLocalRemove.isError, false);
    assert.strictEqual(dryLocalRemove.structuredContent.wouldExecute, false);
    assert.ok(dryLocalRemove.structuredContent.blockers.includes('CANNOT_REMOVE_LOCAL_SERVER'));

    // 3c. RBAC Viewer: solo RO, excluye culkibo_database_credentials y culkibo_rbac_list_tokens
    const viewerAuth = {
      ok: true,
      method: 'api_token',
      principal: { userId: 'usr_viewer_1', role: 'viewer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
    };
    const viewerTools = mcpServer.getToolsForPrincipal(viewerAuth);
    assert.ok(viewerTools.length > 0 && viewerTools.length < 125);
    assert.ok(viewerTools.every(t => t.annotations.readOnlyHint === true), 'viewer solo puede ver herramientas readOnly');
    assert.ok(!viewerTools.some(t => t.name === 'culkibo_database_credentials'), 'viewer NO puede ver culkibo_database_credentials');
    assert.ok(!viewerTools.some(t => t.name === 'culkibo_rbac_list_tokens'), 'viewer NO puede ver culkibo_rbac_list_tokens');

    // Serialized tools cache isolation
    const pubBuf = mcpServer.getToolsSerialized();
    const privBuf = mcpServer.getToolsSerialized(viewerAuth);
    assert.strictEqual(JSON.parse(pubBuf.toString('utf8')).count, 125);
    assert.strictEqual(JSON.parse(privBuf.toString('utf8')).cacheScope, 'private');
    assert.strictEqual(JSON.parse(privBuf.toString('utf8')).count, viewerTools.length);

    // Viewer llamando herramienta mutadora incluso con dryRun: true -> FORBIDDEN (RBAC ANTES de dryRun)
    const viewerDryMut = await mcpServer.executeTool('culkibo_toggle_maintenance', {
      projectId: projA.id,
      enabled: true,
      dryRun: true
    }, { auth: viewerAuth });
    assert.strictEqual(viewerDryMut.isError, true);
    assert.strictEqual(JSON.parse(viewerDryMut.content[0].text).code, 'FORBIDDEN');

    // 3d. Developer con ACL [projA.id] -> puede ver projA, FORBIDDEN en projB (anti-IDOR incluso en dryRun)
    const devAuth = {
      ok: true,
      method: 'session',
      principal: { userId: 'usr_dev_1', role: 'developer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
    };
    const devList = await mcpServer.executeTool('culkibo_list_projects', {}, { auth: devAuth });
    assert.strictEqual(devList.isError, false);
    const devProjIds = devList.structuredContent.projects.map(p => p.id);
    assert.ok(devProjIds.includes(projA.id));
    assert.ok(!devProjIds.includes(projB.id), 'culkibo_list_projects debe filtrar proyectos fuera del ACL');

    const idorRead = await mcpServer.executeTool('culkibo_get_project', { projectId: projB.id }, { auth: devAuth });
    assert.strictEqual(idorRead.isError, true);
    assert.strictEqual(JSON.parse(idorRead.content[0].text).code, 'FORBIDDEN');

    const idorDryRun = await mcpServer.executeTool('culkibo_toggle_maintenance', {
      projectId: projB.id,
      enabled: true,
      dryRun: true
    }, { auth: devAuth });
    assert.strictEqual(idorDryRun.isError, true);
    assert.strictEqual(JSON.parse(idorDryRun.content[0].text).code, 'FORBIDDEN');

    // Recurso culkibo://projects filtrado por ACL
    const scopedRes = await mcpServer.readResource('culkibo://projects', { auth: devAuth });
    const scopedProjects = JSON.parse(scopedRes.contents[0].text).projects;
    assert.ok(scopedProjects.some(p => p.id === projA.id));
    assert.ok(!scopedProjects.some(p => p.id === projB.id));

    // 3e. Anti-escalada: admin NO puede invitar owner ni exportar secretos de instancia sin redactar
    const adminAuth = {
      ok: true,
      method: 'session',
      principal: { userId: 'usr_admin_1', role: 'admin', teamId: 'team_default', projectIds: null, scopes: ['*'] }
    };
    const escInvite = await mcpServer.executeTool('culkibo_team_invite_member', {
      email: 'evil@example.com',
      role: 'owner'
    }, { auth: adminAuth });
    assert.strictEqual(escInvite.isError, true);
    assert.strictEqual(JSON.parse(escInvite.content[0].text).code, 'FORBIDDEN');

    const escSnap = await mcpServer.executeTool('culkibo_export_instance_snapshot', {
      includeSecrets: true
    }, { auth: adminAuth });
    assert.strictEqual(escSnap.isError, true);
    assert.strictEqual(JSON.parse(escSnap.content[0].text).code, 'FORBIDDEN');

    // 3f. culkibo_rbac_whoami + ejecución real de herramientas v2 RO + aislamiento cross-team
    const whoamiSuper = await mcpServer.executeTool('culkibo_rbac_whoami', {});
    assert.strictEqual(whoamiSuper.isError, false);
    assert.strictEqual(whoamiSuper.structuredContent.isSuperAdmin, true);
    assert.strictEqual(whoamiSuper.structuredContent.allowedToolsCount, 125);

    const whoamiViewer = await mcpServer.executeTool('culkibo_rbac_whoami', {}, { auth: viewerAuth });
    assert.strictEqual(whoamiViewer.isError, false);
    assert.strictEqual(whoamiViewer.structuredContent.role, 'viewer');
    assert.strictEqual(whoamiViewer.structuredContent.allowedToolsCount, viewerTools.length);

    // Cross-team teamId bloqueado con FORBIDDEN antes de dryRun
    const crossTeamRes = await mcpServer.executeTool('culkibo_team_update_member', {
      action: 'remove',
      memberId: 'usr_other',
      teamId: 'team_foreign',
      dryRun: true
    }, { auth: adminAuth });
    assert.strictEqual(crossTeamRes.isError, true);
    assert.strictEqual(JSON.parse(crossTeamRes.content[0].text).code, 'FORBIDDEN');

    // Smoke end-to-end sobre herramientas RO v2 (lazy-loaded)
    const fleetList = await mcpServer.executeTool('culkibo_fleet_list_servers', {});
    assert.strictEqual(fleetList.isError, false);
    assert.ok(Array.isArray(fleetList.structuredContent.servers));

    const advisorRes = await mcpServer.executeTool('culkibo_cost_advisor', { monthlyServerCostEur: 20 });
    assert.strictEqual(advisorRes.isError, false);
    assert.strictEqual(typeof advisorRes.structuredContent.reclaimableRamMb, 'number');

    const freezeList = await mcpServer.executeTool('culkibo_deploy_freeze', { action: 'list', projectId: projA.id });
    assert.strictEqual(freezeList.isError, false);
    assert.strictEqual(freezeList.structuredContent.scope, projA.id);

    const syncConf = await mcpServer.executeTool('culkibo_sync_conflicts', { projectId: projA.id });
    assert.strictEqual(syncConf.isError, false);
    assert.ok(Array.isArray(syncConf.structuredContent.conflicts));

    const envList = await mcpServer.executeTool('culkibo_env_list', { projectId: projA.id });
    assert.strictEqual(envList.isError, false);
    assert.ok(Array.isArray(envList.structuredContent.environments));

    // 3g. Streamable HTTP forward de req.auth + Cache-Control: private, no-store
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      req.auth = viewerAuth;
      next();
    });
    app.post('/api/mcp', mcpStreamableHttp.handlePost);
    const srv = await new Promise((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    try {
      const httpListRes = await fetch(`http://127.0.0.1:${srv.address().port}/api/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'MCP-Protocol-Version': V,
          'Mcp-Method': 'tools/list'
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 'rbac-http-1',
          method: 'tools/list',
          params: {
            _meta: {
              'io.modelcontextprotocol/protocolVersion': V,
              'io.modelcontextprotocol/clientCapabilities': {}
            }
          }
        })
      });
      assert.strictEqual(httpListRes.status, 200);
      assert.strictEqual(httpListRes.headers.get('cache-control'), 'private, no-store');
      const body = await httpListRes.json();
      assert.strictEqual(body.result.cacheScope, 'private');
      assert.strictEqual(body.result.ttlMs, 0);
      assert.strictEqual(body.result.tools.length, viewerTools.length);
    } finally {
      await new Promise((resolve) => srv.close(resolve));
    }

    // 3h. Cross-Project Cron IDOR bloqueado (projectId: projA + cronId de projB -> FORBIDDEN)
    const cronManager = require('../server/services/cronManager');
    const cronB = cronManager.create(projB.id, {
      name: 'Foreign Cron B',
      schedule: '0 * * * *',
      mode: 'http',
      httpPath: '/health',
      enabled: true
    });
    try {
      const cronIdor = await mcpServer.executeTool('culkibo_manage_crons', {
        projectId: projA.id,
        action: 'toggle',
        cronId: cronB.id,
        enabled: false
      }, { auth: devAuth });
      assert.strictEqual(cronIdor.isError, true);
      assert.strictEqual(JSON.parse(cronIdor.content[0].text).code, 'FORBIDDEN');
      const cronBStillEnabled = cronManager.list(projB.id).find(c => c.id === cronB.id);
      assert.strictEqual(cronBStillEnabled.enabled, true, 'El cron de projB no puede ser alterado por projA');
    } finally {
      try { cronManager.remove(cronB.id); } catch (e) {}
    }

    // 3i. Token acotado a projectIds: [projA] NO puede escapar a mutaciones globales
    const scopedAdminAuth = {
      ok: true,
      method: 'api_token',
      principal: { userId: 'usr_scoped_adm', role: 'admin', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
    };
    const scopedAdminTools = mcpServer.getToolsForPrincipal(scopedAdminAuth);
    assert.ok(!scopedAdminTools.some(t => t.name === 'culkibo_gitops_apply'), 'Token por proyecto no debe ver culkibo_gitops_apply');
    assert.ok(!scopedAdminTools.some(t => t.name === 'culkibo_fleet_remove_server'), 'Token por proyecto no debe ver culkibo_fleet_remove_server');

    for (const [toolName, toolArgs] of [
      ['culkibo_gitops_apply', { yamlText: 'version: 1\nprojects: []', dryRun: true }],
      ['culkibo_fleet_remove_server', { serverId: 'srv_any', dryRun: true }],
      ['culkibo_deploy_freeze', { action: 'set', windows: [], dryRun: true }],
      ['culkibo_status_page_manage', { action: 'configure', slug: 'escape-test', title: 'Escape' }]
    ]) {
      const esc = await mcpServer.executeTool(toolName, toolArgs, { auth: scopedAdminAuth });
      assert.strictEqual(esc.isError, true, `${toolName} debe bloquearse para token acotado a projectIds`);
      assert.strictEqual(JSON.parse(esc.content[0].text).code, 'FORBIDDEN');
    }

    // 3j. Eliminado comodín `mcp:write`: un token con solo ['mcp:write'] NO puede invocar escrituras destructivas
    const mcpWriteOnlyAuth = {
      ok: true,
      method: 'api_token',
      principal: { userId: 'usr_mw', role: 'admin', teamId: 'team_default', projectIds: null, scopes: ['mcp:write'] }
    };
    const mwTools = mcpServer.getToolsForPrincipal(mcpWriteOnlyAuth);
    assert.strictEqual(mwTools.length, 0, 'scopes: ["mcp:write"] no debe conceder acceso masivo a herramientas de escritura');
    const mwCall = await mcpServer.executeTool('culkibo_gitops_apply', { yamlText: 'version: 1', dryRun: true }, { auth: mcpWriteOnlyAuth });
    assert.strictEqual(mwCall.isError, true);
    assert.strictEqual(JSON.parse(mwCall.content[0].text).code, 'FORBIDDEN');

    // 3k. Overrides per-project ACL (`none` y degradación a `viewer`) integrados con teamManager
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    const teamSingleton = require('../server/services/teamManager');
    const { TeamManager } = teamSingleton;
    const tmpRbacDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mcp-acl-'));
    const origMulti = teamSingleton.isMultiUserEnabled;
    const origResolve = teamSingleton.resolveProjectRole;
    try {
      const tmpTm = new TeamManager({ dataDir: tmpRbacDir });
      const boot = tmpTm.bootstrapOwner({ email: 'owner@mcp-test.local', name: 'Owner', password: 'StrongPassword123!' });
      const ownerActor = tmpTm.verifyCredential(boot.sessionToken);
      const inv = tmpTm.createInvite(ownerActor, { email: 'dev@mcp-test.local', role: 'developer', teamId: 'team_default' });
      const accepted = tmpTm.acceptInvite({ token: inv.inviteToken, email: 'dev@mcp-test.local', name: 'Dev', password: 'DevPassword123!' });
      const devUserId = accepted.user.id;
      // Degradar a 'viewer' en projA y denegar con 'none' en projB (revoca sesión previa!)
      tmpTm.setProjectAcl(ownerActor, projA.id, { userId: devUserId, role: 'viewer', teamId: 'team_default' });
      tmpTm.setProjectAcl(ownerActor, projB.id, { userId: devUserId, role: 'none', teamId: 'team_default' });

      teamSingleton.isMultiUserEnabled = () => true;
      teamSingleton.resolveProjectRole = (p, proj) => tmpTm.resolveProjectRole(p, proj);

      // Sesión revocada ({ ok: false }) debe fallar cerrado (FORBIDDEN, 0 herramientas)
      const revokedAuth = tmpTm.verifyCredential(accepted.sessionToken);
      assert.strictEqual(revokedAuth.ok, false);
      assert.strictEqual(mcpServer.getToolsForPrincipal(revokedAuth).length, 0);
      const revokedCall = await mcpServer.executeTool('culkibo_get_project', { projectId: projA.id }, { auth: revokedAuth });
      assert.strictEqual(revokedCall.isError, true);
      assert.strictEqual(JSON.parse(revokedCall.content[0].text).code, 'FORBIDDEN');

      // Nueva sesión tras login aplica per-project ACL (`none` y degradación a `viewer`)
      const freshLogin = tmpTm.login({ email: 'dev@mcp-test.local', password: 'DevPassword123!' });
      const aclDevAuth = tmpTm.verifyCredential(freshLogin.sessionToken);
      assert.strictEqual(aclDevAuth.ok, true);

      // 'none' en projB -> denegado en lectura y ocultado en listado
      const deniedB = await mcpServer.executeTool('culkibo_get_project', { projectId: projB.id }, { auth: aclDevAuth });
      assert.strictEqual(deniedB.isError, true);
      assert.strictEqual(JSON.parse(deniedB.content[0].text).code, 'FORBIDDEN');
      const listAcl = await mcpServer.executeTool('culkibo_list_projects', {}, { auth: aclDevAuth });
      const listedIds = listAcl.structuredContent.projects.map(p => p.id);
      assert.ok(listedIds.includes(projA.id), 'projA (viewer) debe ser visible');
      assert.ok(!listedIds.includes(projB.id), 'projB (none) debe quedar oculto');

      // 'viewer' en projA -> lectura permitida, escritura/deploy bloqueada con FORBIDDEN incluso con dryRun: true
      const readA = await mcpServer.executeTool('culkibo_get_project', { projectId: projA.id }, { auth: aclDevAuth });
      assert.strictEqual(readA.isError, false);
      const mutA = await mcpServer.executeTool('culkibo_toggle_maintenance', { projectId: projA.id, enabled: true, dryRun: true }, { auth: aclDevAuth });
      assert.strictEqual(mutA.isError, true);
      assert.strictEqual(JSON.parse(mutA.content[0].text).code, 'FORBIDDEN');
      const deployA = await mcpServer.executeTool('culkibo_deploy_production', { projectId: projA.id, dryRun: true }, { auth: aclDevAuth });
      assert.strictEqual(deployA.isError, true);
      assert.strictEqual(JSON.parse(deployA.content[0].text).code, 'FORBIDDEN');
    } finally {
      teamSingleton.isMultiUserEnabled = origMulti;
      teamSingleton.resolveProjectRole = origResolve;
      fs.rmSync(tmpRbacDir, { recursive: true, force: true });
    }

    console.log('  ✓ MCP 2.0: dryRun universal (0 mutaciones), RBAC, per-project ACL, anti-IDOR (cron/global/team) y forwarding req.auth verificados');
  } finally {
    projectManager.delete(projA.id);
    projectManager.delete(projB.id);
    await projectManager.flushToDisk();
  }
}

/**
 * MCP 2.1: auditoría automatizada de los 107 handlers, meta-discovery, validación
 * estricta de rangos/patrones/items, 4 handlers corregidos, 5 fugas RBAC/IDOR cerradas
 * y ciclo completo de autocuración (culkibo_diagnose_incident + culkibo_auto_remediate).
 */
async function testMcpV21Superpowers() {
  const fs = require('fs');
  const path = require('path');
  const projectManager = require('../server/services/projectManager');
  const deployManager = require('../server/services/deployManager');
  const dockerManager = require('../server/services/dockerManager');
  const systemDoctor = require('../server/services/systemDoctor');
  const sleepAdvisor = require('../server/services/sleepAdvisor');
  const uptimeMonitor = require('../server/services/uptimeMonitor');
  const gitopsManager = require('../server/services/gitopsManager');
  const ingressManager = require('../server/services/ingressManager');

  // 1. Auditoría automatizada de cableado sobre LAS 107 HERRAMIENTAS (0 stubs rotos, 0 métodos inexistentes, 0 errores sin remediation)
  const src = fs.readFileSync(path.join(__dirname, '..', 'server', 'services', 'mcpServer.js'), 'utf8');
  const tools = mcpServer.getToolsDefinition();
  const switchBlock = src.slice(src.indexOf('switch (toolName)'), src.indexOf('// MCP Resources & Prompts'));
  const caseNames = new Set();
  let match;
  const caseRe = /case\s+'(culkibo_[a-z0-9_]+)'\s*:/g;
  while ((match = caseRe.exec(switchBlock))) caseNames.add(match[1]);
  assert.strictEqual(caseNames.size, 125, `Todos los 125 tools deben tener handler en switch (hay ${caseNames.size})`);
  for (const t of tools) {
    assert.ok(caseNames.has(t.name), `Falta case para ${t.name}`);
  }

  const svcMap = {
    containerOrchestrator: require('../server/services/containerOrchestrator'),
    domainManager: require('../server/services/domainManager'),
    sslManager: require('../server/services/sslManager'),
    cloudflareService: require('../server/services/cloudflareService'),
    projectManager,
    dockerManager,
    dbBackupManager: require('../server/services/dbBackupManager'),
    githubService: require('../server/services/githubService'),
    ingressManager,
    caddyManager: require('../server/services/caddyManager'),
    deployManager,
    databaseManager: require('../server/services/databaseManager'),
    catalogManager: require('../server/services/catalogManager'),
    liveSyncEngine: require('../server/services/liveSyncEngine'),
    coolifyMigrator: require('../server/services/coolifyMigrator'),
    wordpressMigrator: require('../server/services/wordpressMigrator'),
    universalImporter: require('../server/services/universalImporter'),
    metricsCollector: require('../server/services/metricsCollector'),
    systemDoctor,
    notificationService: require('../server/services/notificationService'),
    cronManager: require('../server/services/cronManager'),
    previewManager: require('../server/services/previewManager'),
    webhookService: require('../server/services/webhookService'),
    fleet: require('../server/services/serverFleetManager'),
    fleetSvc: require('../server/services/serverFleetManager'),
    tm: require('../server/services/teamManager'),
    em: require('../server/services/environmentManager'),
    um: uptimeMonitor,
    gm: gitopsManager,
    sa: sleepAdvisor,
    dm: deployManager,
    sp: require('../server/services/smartPackBuilder'),
    et: require('../server/services/edgeTunnelService'),
    sca: require('../server/services/supplyChainAttestor'),
    otlp: require('../server/services/otlpExporter'),
    sr: require('../server/services/shadowReplayService'),
    tms: require('../server/services/timeMachineService'),
    finops: require('../server/services/finopsOptimizer'),
    bh: require('../server/services/buildHealerService'),
    fm: require('../server/services/fleetMeshService'),
    es: require('../server/services/edgeShieldService'),
    cveSvc: require('../server/services/cveDriftService'),
    dd: require('../server/services/driftDetectorService'),
    iac: require('../server/services/iacExporter'),
    sls: require('../server/services/secretLeaseService')
  };
  const missingCalls = [];
  const callRe = /\b([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)\s*\(/g;
  while ((match = callRe.exec(switchBlock))) {
    const [, obj, fn] = match;
    if (svcMap[obj] && typeof svcMap[obj][fn] !== 'function') {
      missingCalls.push(`${obj}.${fn}()`);
    }
  }
  assert.deepStrictEqual(missingCalls, [], `Handlers MCP llaman a métodos inexistentes: ${missingCalls.join(', ')}`);
  assert.ok(!/throw new Error\(/.test(switchBlock), 'No debe haber throw new Error() sin tipar en handlers MCP');

  // Los 7 tools con acciones destructivas ahora son destructiveHint: true y soportan dryRun
  for (const name of [
    'culkibo_manage_watcher', 'culkibo_link_database', 'culkibo_manage_wildcard_dns01',
    'culkibo_manage_webhook', 'culkibo_manage_crons', 'culkibo_manage_previews', 'culkibo_status_page_manage'
  ]) {
    const t = mcpServer.getToolByName(name);
    assert.strictEqual(t.annotations.destructiveHint, true, `${name} debe tener destructiveHint: true`);
    assert.strictEqual(mcpServer.supportsDryRun(name), true, `${name} debe soportar dryRun`);
  }
  // Verificar que los 5 perfiles devuelven subconjuntos válidos
  for (const prof of ['core', 'deploy', 'ops', 'security', 'all']) {
    const subset = mcpServer.getToolsForPrincipal(null, { profile: prof });
    assert.ok(subset.length > 0, `El perfil ${prof} debe devolver herramientas`);
  }
  console.log('  ✓ Auditoría automatizada de 125 herramientas: 0 métodos inexistentes, 0 raw errors, 7 destructiveHints y 5 perfiles verificados');

  // 2. culkibo_search_tools (meta-discovery + aislamiento RBAC)
  const searchSuper = await mcpServer.executeTool('culkibo_search_tools', { query: 'postgres backup', limit: 5 });
  assert.strictEqual(searchSuper.isError, false);
  assert.ok(searchSuper.structuredContent.matchedCount >= 1);
  assert.ok(searchSuper.structuredContent.tools.some((t) => t.name.includes('database') && Boolean(t.inputSchema)));

  const viewerAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_v21_viewer', role: 'viewer', teamId: 'team_default', projectIds: null, scopes: ['*'] }
  };
  const searchViewer = await mcpServer.executeTool('culkibo_search_tools', { query: 'delete database revoke token', limit: 15 }, { auth: viewerAuth });
  assert.strictEqual(searchViewer.isError, false);
  assert.ok(searchViewer.structuredContent.tools.every((t) => t.annotations.readOnlyHint === true), 'culkibo_search_tools NUNCA debe revelar herramientas de escritura a un viewer');
  console.log('  ✓ culkibo_search_tools (meta-discovery ES/EN + filtro RBAC estricto) verificado');

  // 3. Validación estricta de rangos (minimum/maximum), pattern y array items
  const badPct = await mcpServer.executeTool('culkibo_switch_traffic', { citadelPercent: 150 });
  assert.strictEqual(badPct.isError, true);
  const badPctEnv = JSON.parse(badPct.content[0].text);
  assert.strictEqual(badPctEnv.code, 'INVALID_ARGUMENT');
  assert.ok(badPctEnv.remediation && badPctEnv.remediation.length > 5);

  const badLines = await mcpServer.executeTool('culkibo_get_container_logs', { projectId: 'any', lines: 5 });
  assert.strictEqual(badLines.isError, true);
  assert.strictEqual(JSON.parse(badLines.content[0].text).code, 'INVALID_ARGUMENT');

  const badSlug = await mcpServer.executeTool('culkibo_status_page_manage', { action: 'configure', slug: 'INVALID SLUG!' });
  assert.strictEqual(badSlug.isError, true);
  assert.strictEqual(JSON.parse(badSlug.content[0].text).code, 'INVALID_ARGUMENT');

  const badItems = await mcpServer.executeTool('culkibo_canary_rollout', { projectId: 'any', action: 'start', steps: [10, 250] });
  assert.strictEqual(badItems.isError, true);
  assert.strictEqual(JSON.parse(badItems.content[0].text).code, 'INVALID_ARGUMENT');
  console.log('  ✓ Validación estricta de minimum/maximum, pattern y array items con remediation verificada');

  // Crear dos proyectos temporales aislados para pruebas de handlers, RBAC/IDOR y autocuración
  const projA = projectManager.create({ name: 'MCP21 Project A', description: 'Owned A', maintenanceMode: false, teamId: 'team_default' });
  const projB = projectManager.create({ name: 'MCP21 Project B', description: 'Foreign B', maintenanceMode: false, teamId: 'team_default' });

  try {
    // 4. Verificación de los 4 handlers reparados (mocks en memoria restaurados en finally)
    const origStopProd = deployManager.stopProduction;
    const origStartProd = deployManager.startProduction;
    const origApplyFix = systemDoctor.applyFix;
    const origGetCanary = deployManager.getCanaryState;
    const origSwitchCanary = deployManager.switchCanaryRoute;
    const origPromoteCanary = deployManager.promoteCanary;
    const calledOps = [];
    try {
      deployManager.stopProduction = async (pid) => { calledOps.push(`stop:${pid}`); return { stopped: true, projectId: pid }; };
      deployManager.startProduction = async (pid) => { calledOps.push(`start:${pid}`); return { started: true, projectId: pid }; };
      systemDoctor.applyFix = async (act) => { calledOps.push(`doctor:${act}`); return { ok: true, action: act, message: 'ok' }; };
      deployManager.getCanaryState = (pid) => ({
        projectId: pid, deploymentId: 'dep_can_1', stableDial: '127.0.0.1:20001', canaryDial: '127.0.0.1:20002',
        weight: 10, stepIndex: 0, steps: [10, 50, 100]
      });
      deployManager.switchCanaryRoute = async (_dep, _hosts, opts) => {
        calledOps.push(`canary_weight:${opts.canaryWeight}`);
        return { ok: true, weights: [100 - opts.canaryWeight, opts.canaryWeight] };
      };
      deployManager.promoteCanary = (pid) => { calledOps.push(`canary_promote:${pid}`); return { ok: true, action: 'promote' }; };

      const restartRes = await mcpServer.executeTool('culkibo_manage_production_service', { projectId: projA.id, action: 'restart' });
      assert.strictEqual(restartRes.isError, false);
      assert.strictEqual(restartRes.structuredContent.restarted, true);
      assert.ok(calledOps.includes(`stop:${projA.id}`) && calledOps.includes(`start:${projA.id}`));

      const docFixAlias = await mcpServer.executeTool('culkibo_system_doctor_fix', { action: 'prune_build_cache' });
      assert.strictEqual(docFixAlias.isError, false);
      assert.ok(calledOps.includes('doctor:prune_buildkit'), 'prune_build_cache debe mapearse a prune_buildkit');

      const canaryAdv = await mcpServer.executeTool('culkibo_canary_rollout', { projectId: projA.id, action: 'advance' });
      assert.strictEqual(canaryAdv.isError, false);
      assert.strictEqual(canaryAdv.structuredContent.nextWeight, 50);
      assert.ok(calledOps.includes('canary_weight:50'));

      // Verificar propiedades reparadas en inputSchema de manage_domain y manage_crons
      assert.ok(mcpServer.getToolByName('culkibo_manage_domain').inputSchema.properties.targetPort);
      assert.ok(mcpServer.getToolByName('culkibo_manage_domain').inputSchema.properties.projectId);
      assert.ok(mcpServer.getToolByName('culkibo_manage_crons').inputSchema.properties.mode);
      assert.ok(mcpServer.getToolByName('culkibo_manage_crons').inputSchema.properties.httpPath);
      assert.ok(mcpServer.getToolByName('culkibo_manage_crons').inputSchema.properties.httpMethod);
    } finally {
      deployManager.stopProduction = origStopProd;
      deployManager.startProduction = origStartProd;
      systemDoctor.applyFix = origApplyFix;
      deployManager.getCanaryState = origGetCanary;
      deployManager.switchCanaryRoute = origSwitchCanary;
      deployManager.promoteCanary = origPromoteCanary;
    }
    console.log('  ✓ 4 handlers reparados verificados (stopProduction/startProduction, prune_buildkit, canary advance, schemas domain/crons)');

    // 5. Regresiones de las 5 fugas RBAC / IDOR cerradas
    const scopedDevA = {
      ok: true,
      method: 'api_token',
      principal: { userId: 'usr_dev_a', role: 'developer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
    };
    const teamViewer = {
      ok: true,
      method: 'session',
      principal: { userId: 'usr_tv', role: 'viewer', teamId: 'team_other', projectIds: null, scopes: ['*'] }
    };

    const origListContainers = dockerManager.listContainers;
    const origGetCandidates = sleepAdvisor.getSleepCandidates;
    const origAnalyzeRes = sleepAdvisor.analyzeResources;
    const origListMons = uptimeMonitor.listMonitors;
    const origListPages = uptimeMonitor.listStatusPages;
    let observedAnalyzeProjectIds = null;
    try {
      // 5a. docker_containers: sin projectId en el contenedor, team_other no ve nada y scopedDevA solo ve su contenedor
      dockerManager.listContainers = async () => [
        { id: 'c_a', names: [`culkibo_${projA.id}_live`], image: 'app:a', state: 'running' },
        { id: 'c_b', names: [`culkibo_${projB.id}_live`], image: 'app:b', state: 'running' },
        { id: 'c_sys', names: ['unrelated_host_container'], image: 'sys:1', state: 'running' }
      ];
      const devContainers = await mcpServer.executeTool('culkibo_docker_containers', {}, { auth: scopedDevA });
      assert.strictEqual(devContainers.isError, false);
      assert.deepStrictEqual(devContainers.structuredContent.containers.map((c) => c.id), ['c_a']);
      const otherTeamContainers = await mcpServer.executeTool('culkibo_docker_containers', {}, { auth: teamViewer });
      assert.strictEqual(otherTeamContainers.isError, false);
      assert.strictEqual(otherTeamContainers.structuredContent.containers.length, 0, 'team_other no debe ver contenedores de otro equipo ni sin propietario');

      // 5b. sleep_status: candidates filtrado por projectIds
      sleepAdvisor.getSleepCandidates = (opts) => [
        { projectId: projA.id, idleMinutes: 30 },
        { projectId: projB.id, idleMinutes: 45 }
      ].filter((c) => !Array.isArray(opts?.projectIds) || opts.projectIds.includes(c.projectId));
      const sleepScoped = await mcpServer.executeTool('culkibo_sleep_status', {}, { auth: scopedDevA });
      assert.strictEqual(sleepScoped.isError, false);
      assert.deepStrictEqual(sleepScoped.structuredContent.candidates.map((c) => c.projectId), [projA.id]);

      // 5c. cost_advisor: pasa projectIds al advisor
      sleepAdvisor.analyzeResources = async (opts) => {
        observedAnalyzeProjectIds = opts?.projectIds || null;
        return { summary: { freeMemPct: 45 }, recommendations: [], reclaimableRamMb: 0, estimatedMonthlySavingsEur: 0 };
      };
      const advScoped = await mcpServer.executeTool('culkibo_cost_advisor', {}, { auth: scopedDevA });
      assert.strictEqual(advScoped.isError, false);
      assert.deepStrictEqual(observedAnalyzeProjectIds, [projA.id]);

      // 5d. uptime_list_monitors y culkibo://uptime: statusPages filtradas por monitores permitidos
      uptimeMonitor.listMonitors = () => [
        { id: 'mon_a', projectId: projA.id, name: 'Mon A', status: 'up' },
        { id: 'mon_b', projectId: projB.id, name: 'Mon B', status: 'down' }
      ];
      uptimeMonitor.listStatusPages = () => [
        { slug: 'page-a', title: 'Page A', monitorIds: ['mon_a'] },
        { slug: 'page-b', title: 'Page B', monitorIds: ['mon_b'] },
        { slug: 'page-mix', title: 'Page Mix', monitorIds: ['mon_a', 'mon_b'] }
      ];
      const upScoped = await mcpServer.executeTool('culkibo_uptime_list_monitors', {}, { auth: scopedDevA });
      assert.strictEqual(upScoped.isError, false);
      assert.deepStrictEqual(upScoped.structuredContent.statusPages.map((p) => p.slug), ['page-a']);
      const upResScoped = await mcpServer.readResource('culkibo://uptime', { auth: scopedDevA });
      const upResParsed = JSON.parse(upResScoped.contents[0].text);
      assert.deepStrictEqual(upResParsed.statusPages.map((p) => p.slug), ['page-a']);

      // 5e. gitops_plan con prune: true no filtra projB a scopedDevA
      const gitopsPlan = await mcpServer.executeTool('culkibo_gitops_plan', {
        yamlText: 'version: 1\nname: scoped-check\nprojects: []\n',
        prune: true
      }, { auth: scopedDevA });
      assert.strictEqual(gitopsPlan.isError, false);
      const delSerialized = JSON.stringify(gitopsPlan.structuredContent.delete || []);
      assert.ok(!delSerialized.includes(projB.id) && !delSerialized.includes(projB.name), 'gitops_plan prune NO debe revelar proyectos ajenos');
    } finally {
      dockerManager.listContainers = origListContainers;
      sleepAdvisor.getSleepCandidates = origGetCandidates;
      sleepAdvisor.analyzeResources = origAnalyzeRes;
      uptimeMonitor.listMonitors = origListMons;
      uptimeMonitor.listStatusPages = origListPages;
    }
    console.log('  ✓ 5 fugas RBAC/IDOR cerradas verificadas (docker_containers, sleep_status, cost_advisor, uptime/statusPages, gitops_plan)');

    // 6. Autocuración Autónoma: culkibo_diagnose_incident + culkibo_auto_remediate (dryRun + confirmToken + replay + expiry)
    const origStatus = deployManager.status;
    const origRuntimeStats = deployManager.getRuntimeStats;
    const origRuntimeLogs = deployManager.getRuntimeLogs;
    const origListDeps = deployManager.listDeployments;
    const origRunDoctor = systemDoctor.runDoctor;
    const origUmList = uptimeMonitor.listMonitors;
    const origUmInc = uptimeMonitor.listIncidents;
    const origReconcile = ingressManager.reconcile;
    try {
      deployManager.status = async () => ({
        current: { id: 'dep_bad', containerName: `culkibo_${projA.id}_live`, status: 'error' },
        previous: { id: 'dep_good', containerName: `culkibo_${projA.id}_prev`, status: 'activo' }
      });
      deployManager.getRuntimeStats = async () => ({
        ok: true, running: false, status: 'exited', oomKilled: true, restartCount: 4, health: 'unhealthy', containerName: `culkibo_${projA.id}_live`
      });
      deployManager.getRuntimeLogs = async () => ({
        lines: ['INFO starting server', 'FATAL JavaScript heap out of memory (ENOMEM)', 'ERROR ECONNREFUSED 127.0.0.1:5432']
      });
      deployManager.listDeployments = () => [{ id: 'dep_bad', status: 'error', stage: 'healthcheck', commit: 'abc12345', error: 'OOM killed', logLines: [] }];
      systemDoctor.runDoctor = async () => ({ summary: { ok: 6, warn: 1, fail: 0 }, checks: [{ name: 'BuildKit', status: 'warn', summary: 'cache high', fixAction: 'prune_buildkit' }] });
      uptimeMonitor.listMonitors = () => [{ id: 'mon_a1', projectId: projA.id, name: 'API Health', status: 'down' }];
      uptimeMonitor.listIncidents = () => [{ id: 'inc_1', projectId: projA.id, status: 'open' }];
      ingressManager.reconcile = async () => ({ ok: true, reconciled: true });

      const diag = await mcpServer.executeTool('culkibo_diagnose_incident', { projectId: projA.id }, { auth: scopedDevA });
      assert.strictEqual(diag.isError, false);
      const d = diag.structuredContent;
      assert.strictEqual(d.severity, 'critical');
      const causeCodes = d.rootCauses.map((r) => r.code);
      assert.ok(causeCodes.includes('CONTAINER_OOM_KILLED'), 'Debe detectar CONTAINER_OOM_KILLED');
      assert.ok(causeCodes.includes('CONTAINER_CRASH_LOOP'), 'Debe detectar CONTAINER_CRASH_LOOP');
      assert.ok(causeCodes.includes('RECENT_DEPLOY_FAILED'), 'Debe detectar RECENT_DEPLOY_FAILED');
      assert.ok(causeCodes.includes('UPTIME_MONITOR_DOWN'), 'Debe detectar UPTIME_MONITOR_DOWN');
      assert.ok(d.remediationPlan.some((p) => p.tool === 'culkibo_auto_remediate' && p.action === 'rollback_release' && p.args.dryRun === true));

      // 6a. Ejecutar culkibo_auto_remediate SIN confirmToken -> CONFIRMATION_REQUIRED (0 mutaciones)
      const noTok = await mcpServer.executeTool('culkibo_auto_remediate', {
        action: 'toggle_maintenance',
        projectId: projA.id,
        maintenanceEnabled: true
      }, { auth: scopedDevA });
      assert.strictEqual(noTok.isError, true);
      assert.strictEqual(JSON.parse(noTok.content[0].text).code, 'CONFIRMATION_REQUIRED');
      assert.strictEqual(projectManager.getById(projA.id).maintenanceMode, false);

      // 6b. Acción global (doctor_fix) bloqueada con FORBIDDEN para developer / token por proyecto
      const globalBlocked = await mcpServer.executeTool('culkibo_auto_remediate', {
        action: 'doctor_fix',
        doctorFixAction: 'clean_tmp',
        dryRun: true
      }, { auth: scopedDevA });
      assert.strictEqual(globalBlocked.isError, true);
      assert.strictEqual(JSON.parse(globalBlocked.content[0].text).code, 'FORBIDDEN');

      // 6c. Fase 1 dryRun: true emite confirmToken HMAC-SHA256 y lo redacta de la auditoría
      const dryRem = await mcpServer.executeTool('culkibo_auto_remediate', {
        action: 'toggle_maintenance',
        projectId: projA.id,
        maintenanceEnabled: true,
        dryRun: true
      }, { auth: scopedDevA });
      assert.strictEqual(dryRem.isError, false);
      assert.strictEqual(dryRem.structuredContent.dryRun, true);
      assert.strictEqual(dryRem.structuredContent.wouldExecute, true);
      const token = dryRem.structuredContent.confirmToken;
      assert.ok(typeof token === 'string' && token.startsWith('ckr_'), 'Debe emitir confirmToken ckr_...');
      assert.strictEqual(projectManager.getById(projA.id).maintenanceMode, false, 'dryRun NUNCA muta estado');
      const auditLatest = mcpServer.getAuditLog(1)[0];
      assert.ok(!JSON.stringify(auditLatest).includes(token), 'confirmToken NUNCA debe quedar en claro en auditLog');

      // 6d. Robo de token por otro principal -> CONFIRM_TOKEN_MISMATCH
      const otherDevA = {
        ok: true,
        method: 'api_token',
        principal: { userId: 'usr_dev_other', role: 'developer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
      };
      const stolenTok = await mcpServer.executeTool('culkibo_auto_remediate', {
        action: 'toggle_maintenance',
        projectId: projA.id,
        maintenanceEnabled: true,
        confirmToken: token
      }, { auth: otherDevA });
      assert.strictEqual(stolenTok.isError, true);
      assert.strictEqual(JSON.parse(stolenTok.content[0].text).code, 'CONFIRM_TOKEN_MISMATCH');

      // 6e. Alteración de parámetros -> CONFIRM_TOKEN_MISMATCH
      const tamperedParams = await mcpServer.executeTool('culkibo_auto_remediate', {
        action: 'toggle_maintenance',
        projectId: projA.id,
        maintenanceEnabled: false,
        confirmToken: token
      }, { auth: scopedDevA });
      assert.strictEqual(tamperedParams.isError, true);
      assert.strictEqual(JSON.parse(tamperedParams.content[0].text).code, 'CONFIRM_TOKEN_MISMATCH');

      // 6f. Token caducado -> CONFIRM_TOKEN_EXPIRED
      const expiredMint = mcpServer.mintRemediationToken(
        mcpServer.normalizePrincipal(scopedDevA),
        { action: 'toggle_maintenance', projectId: projA.id, maintenanceEnabled: true },
        10
      );
      await new Promise((r) => setTimeout(r, 25));
      const expRes = await mcpServer.executeTool('culkibo_auto_remediate', {
        action: 'toggle_maintenance',
        projectId: projA.id,
        maintenanceEnabled: true,
        confirmToken: expiredMint.confirmToken
      }, { auth: scopedDevA });
      assert.strictEqual(expRes.isError, true);
      const expCode = JSON.parse(expRes.content[0].text).code;
      assert.ok(expCode === 'CONFIRM_TOKEN_EXPIRED' || expCode === 'CONFIRM_TOKEN_INVALID');

      // 6g. Ejecución legítima con confirmToken válido -> aplica y devuelve postVerification
      const execRem = await mcpServer.executeTool('culkibo_auto_remediate', {
        action: 'toggle_maintenance',
        projectId: projA.id,
        maintenanceEnabled: true,
        confirmToken: token
      }, { auth: scopedDevA });
      assert.strictEqual(execRem.isError, false);
      assert.strictEqual(execRem.structuredContent.executed, true);
      assert.ok(execRem.structuredContent.postVerification);
      assert.strictEqual(projectManager.getById(projA.id).maintenanceMode, true);

      // 6h. Replay con el mismo token ya consumido -> CONFIRM_TOKEN_REPLAYED
      const replayRes = await mcpServer.executeTool('culkibo_auto_remediate', {
        action: 'toggle_maintenance',
        projectId: projA.id,
        maintenanceEnabled: true,
        confirmToken: token
      }, { auth: scopedDevA });
      assert.strictEqual(replayRes.isError, true);
      assert.strictEqual(JSON.parse(replayRes.content[0].text).code, 'CONFIRM_TOKEN_REPLAYED');
    } finally {
      deployManager.status = origStatus;
      deployManager.getRuntimeStats = origRuntimeStats;
      deployManager.getRuntimeLogs = origRuntimeLogs;
      deployManager.listDeployments = origListDeps;
      systemDoctor.runDoctor = origRunDoctor;
      uptimeMonitor.listMonitors = origUmList;
      uptimeMonitor.listIncidents = origUmInc;
      ingressManager.reconcile = origReconcile;
    }
    console.log('  ✓ Autocuración autónoma verificada (diagnose_incident + auto_remediate dryRun/confirmToken/mismatch/expiry/exec/replay)');
  } finally {
    projectManager.delete(projA.id);
    projectManager.delete(projB.id);
    await projectManager.flushToDisk();
  }
}

/**
 * MCP 2026 Pioneer:
 *  - 8 playbooks interactivos (prompts/list + prompts/get + sanitización + fail-closed RBAC)
 *  - culkibo_ship_and_verify (pre-flight secret scan, confirmToken HMAC-SHA256, smoke check, auto-rollback, anti-IDOR)
 *  - culkibo_export_agent_kit (6 agentes drop-in, ?profile=core, ${CULKIBO_TOKEN} sin fugas de secretos)
 *  - X-Culkibo-Mcp-Profile header fallback en Streamable HTTP
 */
async function testMcp2026PioneerUpgrades() {
  const express = require('express');
  const projectManager = require('../server/services/projectManager');
  const deployManager = require('../server/services/deployManager');
  const mcpStreamableHttp = require('../server/services/mcpStreamableHttp');
  const V = mcpServer.protocol.PROTOCOL_VERSION;

  // 1. Verificar los 8 battle-tested playbooks vía handleModernRpc y handleJsonRpc + redacción de secretos en args
  const expectedPlaybooks = [
    ['deploy_safely', { projectId: 'proj_ship_1', targetEnv: 'production' }, 'culkibo_ship_and_verify'],
    ['migrate_from_coolify', { coolifyUrl: 'https://coolify.acme.dev' }, 'SERVICE_FQDN_'],
    ['debug_production_crash', { projectId: 'proj_crash_1', hostname: 'api.acme.dev' }, 'culkibo_diagnose_incident'],
    ['zero_downtime_db_upgrade', { databaseId: 'db_pg_main', targetVersion: 'postgres:17' }, 'culkibo_database_backup'],
    ['security_audit_stack', { scope: 'instance' }, '/api/audit/verify'],
    ['setup_wildcard_tls_and_tunnel', { rootDomain: 'acme.dev', mode: 'dns01' }, 'culkibo_manage_wildcard_dns01'],
    ['optimize_ram_and_costs', { monthlyServerCostEur: '25' }, 'culkibo_cost_advisor'],
    ['disaster_recovery_drill', { databaseId: 'db_pg_main', projectId: 'proj_dr_1' }, 'AES-256-GCM']
  ];

  const listModern = await mcpServer.handleModernRpc({
    jsonrpc: '2.0',
    id: 'pb-list-1',
    method: 'prompts/list',
    params: { _meta: { 'io.modelcontextprotocol/protocolVersion': V, 'io.modelcontextprotocol/clientCapabilities': {} } }
  });
  assert.strictEqual(listModern.result.prompts.length, 13);

  for (const [pbName, pbArgs, expectedNeedle] of expectedPlaybooks) {
    assert.ok(listModern.result.prompts.some((p) => p.name === pbName), `prompts/list debe incluir ${pbName}`);
    const got = await mcpServer.handleModernRpc({
      jsonrpc: '2.0',
      id: `pb-get-${pbName}`,
      method: 'prompts/get',
      params: {
        name: pbName,
        arguments: pbArgs,
        _meta: { 'io.modelcontextprotocol/protocolVersion': V, 'io.modelcontextprotocol/clientCapabilities': {} }
      }
    });
    assert.ok(got.result && Array.isArray(got.result.messages) && got.result.messages.length >= 1, `prompts/get falló para ${pbName}`);
    const text = got.result.messages[0].content.text;
    assert.ok(text.includes(expectedNeedle), `Playbook ${pbName} debe mencionar '${expectedNeedle}'`);
  }

  // Redacción de secretos si alguien pasa un secreto en los args de un prompt
  const secretArgPrompt = mcpServer.getPrompt('deploy_safely', { projectId: 'sk_live_never_echo_secret_12345678' });
  assert.ok(!secretArgPrompt.messages[0].content.text.includes('sk_live_never_echo_secret_12345678'), 'prompts/get NUNCA debe reflejar secretos');
  assert.ok(secretArgPrompt.messages[0].content.text.includes('[REDACTED]'));

  // Credencial revocada ({ ok: false }) falla cerrado en prompts/list y prompts/get
  const deniedAuth = { ok: false };
  assert.strictEqual(mcpServer.listPrompts(deniedAuth).length, 0);
  assert.throws(() => mcpServer.getPrompt('deploy_safely', {}, { auth: deniedAuth }), /Acceso denegado/);
  console.log('  ✓ MCP 2026: 8 playbooks interactivos verificados (prompts/list, prompts/get, redacción y RBAC fail-closed)');

  // 2. culkibo_export_agent_kit (6 agentes drop-in, ?profile=core, cero secretos en claro)
  const prevEnvToken = process.env.CULKIBO_TOKEN;
  process.env.CULKIBO_TOKEN = 'ck_master_super_secret_never_embed_999';
  try {
    const viewerAuth = {
      ok: true,
      method: 'api_token',
      principal: { userId: 'usr_kit_viewer', role: 'viewer', teamId: 'team_default', projectIds: null, scopes: ['*'] }
    };
    const kitRes = await mcpServer.executeTool('culkibo_export_agent_kit', {
      target: 'all',
      serverUrl: 'https://panel.acme.dev'
    }, { auth: viewerAuth });
    assert.strictEqual(kitRes.isError, false);
    const kit = kitRes.structuredContent;
    assert.strictEqual(kit.profile, 'core', 'culkibo_export_agent_kit debe usar profile=core por defecto');
    assert.strictEqual(kit.endpoint, 'https://panel.acme.dev/api/mcp?profile=core');
    assert.strictEqual(kit.tokenPlaceholder, '${CULKIBO_TOKEN}');
    assert.strictEqual(kit.containsPlaintextSecrets, false);
    assert.ok(kit.tokenSavings.savedPct >= 80, `El perfil core debe ahorrar >=80% (logró ${kit.tokenSavings.savedPct}%)`);
    for (const targetKey of ['antigravity', 'claude-code', 'cursor', 'windsurf', 'codex', 'vscode']) {
      assert.ok(kit.kits[targetKey], `Falta kit para ${targetKey}`);
      assert.ok(Array.isArray(kit.kits[targetKey].files) && kit.kits[targetKey].files.length >= 1);
    }
    assert.ok(kit.kits['claude-code'].files.some((f) => f.path === '.mcp.json'));
    assert.ok(kit.kits['claude-code'].files.some((f) => f.path === 'CLAUDE.md'));
    assert.ok(kit.kits.cursor.files.some((f) => f.path === '.cursor/mcp.json'));
    assert.ok(kit.kits.codex.files.some((f) => f.path === '.codex/config.toml' && f.content.includes('bearer_token_env_var = "CULKIBO_TOKEN"')));
    const serializedKit = JSON.stringify(kit);
    assert.ok(!serializedKit.includes('ck_master_super_secret_never_embed_999'), 'Agent kit JAMÁS puede incrustar CULKIBO_TOKEN real');
    assert.ok(serializedKit.includes('${CULKIBO_TOKEN}'), 'Agent kit debe usar placeholder ${CULKIBO_TOKEN}');
    console.log(`  ✓ culkibo_export_agent_kit verificado (6 agentes, ?profile=core -${kit.tokenSavings.savedPct}%, 0 secretos en claro)`);
  } finally {
    if (prevEnvToken === undefined) delete process.env.CULKIBO_TOKEN;
    else process.env.CULKIBO_TOKEN = prevEnvToken;
  }

  // 3. culkibo_ship_and_verify (pre-flight secret scan + 2-phase confirmToken + smoke verify + auto-rollback + RBAC)
  const leakyProj = projectManager.create({
    name: 'Ship Leaky App',
    description: 'Has hardcoded secret',
    envVars: {
      NODE_ENV: 'production',
      STRIPE_SECRET_KEY: 'sk_live_hardcoded_leak_1234567890abcdef'
    },
    teamId: 'team_default'
  });
  const cleanProj = projectManager.create({
    name: 'Ship Clean App',
    description: 'Vault-clean app',
    envVars: {
      NODE_ENV: 'production',
      STRIPE_SECRET_KEY: '${vault.STRIPE_SECRET_KEY}'
    },
    smokeTests: { enabled: true, failPolicy: 'rollback', checks: [{ path: '/health', expectedStatus: 200 }] },
    teamId: 'team_default'
  });

  const devScopedClean = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_ship_dev', role: 'developer', teamId: 'team_default', projectIds: [cleanProj.id], scopes: ['*'] }
  };

  const origDeploy = deployManager.deploy;
  const origStatus = deployManager.status;
  const origSmoke = deployManager.runSmokeTests;
  const origRollback = deployManager.rollback;
  const origStats = deployManager.getRuntimeStats;
  try {
    // 3a. Anti-IDOR: developer acotado a cleanProj NO puede usar ship_and_verify sobre leakyProj ni con dryRun
    const idorShip = await mcpServer.executeTool('culkibo_ship_and_verify', {
      projectId: leakyProj.id,
      dryRun: true
    }, { auth: devScopedClean });
    assert.strictEqual(idorShip.isError, true);
    assert.strictEqual(JSON.parse(idorShip.content[0].text).code, 'FORBIDDEN');

    // 3b. Developer NO puede degradar secretScanMode a 'warn'
    const warnBlocked = await mcpServer.executeTool('culkibo_ship_and_verify', {
      projectId: cleanProj.id,
      secretScanMode: 'warn',
      dryRun: true
    }, { auth: devScopedClean });
    assert.strictEqual(warnBlocked.isError, true);
    assert.strictEqual(JSON.parse(warnBlocked.content[0].text).code, 'FORBIDDEN');

    // 3c. Proyecto con secreto hardcoded -> dryRun: true bloquea con SECRET_LEAK_DETECTED y NO emite confirmToken ni filtra el secreto
    deployManager.status = async () => ({ current: { id: 'dep_prev_1', hostPort: 20101 }, previous: null });
    const dryLeaky = await mcpServer.executeTool('culkibo_ship_and_verify', {
      projectId: leakyProj.id,
      dryRun: true
    });
    assert.strictEqual(dryLeaky.isError, false);
    assert.strictEqual(dryLeaky.structuredContent.wouldExecute, false);
    assert.strictEqual(dryLeaky.structuredContent.secretScan.blocked, true);
    assert.ok(dryLeaky.structuredContent.blockers.includes('SECRET_LEAK_DETECTED'));
    assert.strictEqual(dryLeaky.structuredContent.confirmToken, undefined, 'No debe emitir confirmToken cuando hay fugas bloqueantes');
    assert.ok(!JSON.stringify(dryLeaky).includes('sk_live_hardcoded_leak_1234567890abcdef'), 'El reporte de secret scan jamás expone el secreto en claro');

    // 3d. dryRun: false sin confirmToken -> CONFIRMATION_REQUIRED
    const noShipTok = await mcpServer.executeTool('culkibo_ship_and_verify', {
      projectId: cleanProj.id,
      dryRun: false
    }, { auth: devScopedClean });
    assert.strictEqual(noShipTok.isError, true);
    assert.strictEqual(JSON.parse(noShipTok.content[0].text).code, 'CONFIRMATION_REQUIRED');

    // 3e. Proyecto limpio -> Fase 1 dryRun: true emite confirmToken ckr_ (redactado del auditLog)
    const dryClean = await mcpServer.executeTool('culkibo_ship_and_verify', {
      projectId: cleanProj.id,
      dryRun: true
    }, { auth: devScopedClean });
    assert.strictEqual(dryClean.isError, false);
    assert.strictEqual(dryClean.structuredContent.wouldExecute, true);
    assert.strictEqual(dryClean.structuredContent.secretScan.clean, true);
    assert.strictEqual(dryClean.structuredContent.rollbackReadiness.canRollback, true);
    const shipToken = dryClean.structuredContent.confirmToken;
    assert.ok(typeof shipToken === 'string' && shipToken.startsWith('ckr_'));
    const latestShipAudit = mcpServer.getAuditLog(1)[0];
    assert.ok(!JSON.stringify(latestShipAudit).includes(shipToken), 'confirmToken de ship_and_verify jamás debe aparecer en auditLog');

    // 3f. Cross-tool confusion: el token de ship_and_verify NO funciona en culkibo_auto_remediate
    const crossTool = await mcpServer.executeTool('culkibo_auto_remediate', {
      action: 'restart_service',
      projectId: cleanProj.id,
      confirmToken: shipToken
    }, { auth: devScopedClean });
    assert.strictEqual(crossTool.isError, true);
    assert.strictEqual(JSON.parse(crossTool.content[0].text).code, 'CONFIRM_TOKEN_MISMATCH');

    // 3g. Fase 2 exitosa: deploy + smoke tests OK + metricsSnapshot
    let rollbackCalls = 0;
    deployManager.deploy = async (proj) => ({ id: 'dep_ship_ok', projectId: proj.id, status: 'activo', hostPort: 20102 });
    deployManager.runSmokeTests = async () => ({ passed: true, ok: true, results: [{ path: '/health', status: 200, ok: true, latencyMs: 11 }] });
    deployManager.rollback = async (pid) => { rollbackCalls++; return { id: 'dep_prev_1', projectId: pid, status: 'activo' }; };
    deployManager.getRuntimeStats = async () => ({ ok: true, running: true, status: 'running', health: 'healthy' });

    const shippedOk = await mcpServer.executeTool('culkibo_ship_and_verify', {
      projectId: cleanProj.id,
      dryRun: false,
      confirmToken: shipToken
    }, { auth: devScopedClean });
    assert.strictEqual(shippedOk.isError, false);
    assert.strictEqual(shippedOk.structuredContent.phase, 'shipped_verified');
    assert.strictEqual(shippedOk.structuredContent.verified, true);
    assert.strictEqual(shippedOk.structuredContent.rollbackExecuted, false);
    assert.strictEqual(shippedOk.structuredContent.smokeVerification.passed, true);
    assert.ok(shippedOk.structuredContent.metricsSnapshot);
    assert.strictEqual(rollbackCalls, 0);

    // Replay del mismo token -> CONFIRM_TOKEN_REPLAYED
    const replayShip = await mcpServer.executeTool('culkibo_ship_and_verify', {
      projectId: cleanProj.id,
      dryRun: false,
      confirmToken: shipToken
    }, { auth: devScopedClean });
    assert.strictEqual(replayShip.isError, true);
    assert.strictEqual(JSON.parse(replayShip.content[0].text).code, 'CONFIRM_TOKEN_REPLAYED');

    // 3h. Auto-rollback cuando fallan los smoke checks post-despliegue
    const dryClean2 = await mcpServer.executeTool('culkibo_ship_and_verify', {
      projectId: cleanProj.id,
      dryRun: true
    }, { auth: devScopedClean });
    const shipToken2 = dryClean2.structuredContent.confirmToken;
    deployManager.runSmokeTests = async () => ({ passed: false, ok: false, results: [{ path: '/health', status: 503, ok: false }] });

    const shippedRb = await mcpServer.executeTool('culkibo_ship_and_verify', {
      projectId: cleanProj.id,
      dryRun: false,
      confirmToken: shipToken2
    }, { auth: devScopedClean });
    assert.strictEqual(shippedRb.isError, false);
    assert.strictEqual(shippedRb.structuredContent.phase, 'shipped_rolled_back');
    assert.strictEqual(shippedRb.structuredContent.verified, false);
    assert.strictEqual(shippedRb.structuredContent.rollbackExecuted, true);
    assert.strictEqual(rollbackCalls, 1);
    console.log('  ✓ culkibo_ship_and_verify verificado (secret scan block, confirmToken HMAC/replay/cross-tool, smoke verify, auto-rollback, anti-IDOR)');
  } finally {
    deployManager.deploy = origDeploy;
    deployManager.status = origStatus;
    deployManager.runSmokeTests = origSmoke;
    deployManager.rollback = origRollback;
    deployManager.getRuntimeStats = origStats;
    projectManager.delete(leakyProj.id);
    projectManager.delete(cleanProj.id);
    await projectManager.flushToDisk();
  }

  // 4. X-Culkibo-Mcp-Profile header fallback en Streamable HTTP
  const app = express();
  app.use(express.json());
  app.post('/api/mcp', mcpStreamableHttp.handlePost);
  const srv = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  try {
    const hdrRes = await fetch(`http://127.0.0.1:${srv.address().port}/api/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'MCP-Protocol-Version': V,
        'Mcp-Method': 'tools/list',
        'X-Culkibo-Mcp-Profile': 'core'
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 'hdr-prof-1',
        method: 'tools/list',
        params: { _meta: { 'io.modelcontextprotocol/protocolVersion': V, 'io.modelcontextprotocol/clientCapabilities': {} } }
      })
    });
    assert.strictEqual(hdrRes.status, 200);
    assert.strictEqual(hdrRes.headers.get('x-culkibo-mcp-profile'), 'core');
    assert.ok(String(hdrRes.headers.get('vary') || '').includes('X-Culkibo-Mcp-Profile'));
    const hdrBody = await hdrRes.json();
    assert.strictEqual(hdrBody.result.profile, 'core');
    assert.ok(hdrBody.result.tools.some((t) => t.name === 'culkibo_ship_and_verify'));
    console.log('  ✓ Streamable HTTP X-Culkibo-Mcp-Profile header fallback y Vary verificados');
  } finally {
    await new Promise((resolve) => srv.close(resolve));
  }
}

/**
 * MCP 2026 Cycle-2:
 *  - World-First PaaS MCP Apps (`ui://culkibo/*`, ext-apps 2026-01-26, MIME, strict CSP, 0 external URLs, XSS escaping, postMessage bridge, RBAC)
 *  - `_meta.ui.resourceUri` linkage on tools & tool results
 *  - `culkibo_smartpack_plan` (RO, outputSchema, path-boundary guard, real SmartPack plan)
 *  - `culkibo_edge_tunnel` (admin RBAC, dryRun preview, create/list/status/revoke, cket_ redaction in auditLog)
 */
async function testMcp2026Cycle2AppsAndTools() {
  const express = require('express');
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const projectManager = require('../server/services/projectManager');
  const mcpStreamableHttp = require('../server/services/mcpStreamableHttp');
  const mcpAppsRenderer = require('../server/services/mcpAppsRenderer');
  const V = mcpServer.protocol.PROTOCOL_VERSION;

  // 1. Capabilities extension advertised in discover & initialize
  const discover = mcpServer.getDiscoverResult();
  assert.ok(discover.capabilities.extensions && discover.capabilities.extensions['io.modelcontextprotocol/ui']);
  assert.ok(discover.capabilities.extensions['io.modelcontextprotocol/ui'].mimeTypes.includes('text/html;profile=mcp-app'));

  const initRes = await mcpServer.handleJsonRpc({ jsonrpc: '2.0', id: 'ext-init', method: 'initialize', params: {} });
  assert.ok(initRes.result.capabilities.extensions['io.modelcontextprotocol/ui'].mimeTypes.includes('text/html;profile=mcp-app'));

  // 2. _meta.ui attached to key tools
  for (const [toolName, expectedUri] of [
    ['culkibo_list_projects', 'ui://culkibo/topology'],
    ['culkibo_list_pods', 'ui://culkibo/topology'],
    ['culkibo_diagnose_incident', 'ui://culkibo/incident-remediator'],
    ['culkibo_migrate_coolify', 'ui://culkibo/coolify-migration-diff']
  ]) {
    const spec = mcpServer.getToolByName(toolName);
    assert.strictEqual(spec?._meta?.ui?.resourceUri, expectedUri, `${toolName} debe declarar _meta.ui.resourceUri=${expectedUri}`);
  }
  const podsExec = await mcpServer.executeTool('culkibo_list_pods', {});
  assert.strictEqual(podsExec._meta?.ui?.resourceUri, 'ui://culkibo/topology');

  // 3. 3 MCP Apps resources (`ui://culkibo/*`): MIME, strict CSP, 0 external URLs, XSS escaping, postMessage bridge, RBAC
  const resources = mcpServer.listResources();
  const uiResources = resources.filter((r) => r.uri.startsWith('ui://culkibo/'));
  assert.strictEqual(uiResources.length, 3);
  for (const r of uiResources) {
    assert.strictEqual(r.mimeType, 'text/html;profile=mcp-app');
    assert.ok(String(r._meta?.ui?.csp?.policy || '').includes("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"));
    assert.deepStrictEqual(r._meta?.ui?.csp?.connectDomains, []);
    assert.deepStrictEqual(r._meta?.ui?.csp?.resourceDomains, []);
  }

  // XSS + secret-redaction check via temporary project with hostile HTML/script name & secret value
  const xssProj = projectManager.create({
    name: '</script><img src=x onerror=alert(1)> EvilApp',
    description: 'sk_live_never_render_into_mcp_app_999999',
    teamId: 'team_default'
  });

  const app = express();
  app.use(express.json());
  app.post('/api/mcp', mcpStreamableHttp.handlePost);
  const srv = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  try {
    for (const uri of ['ui://culkibo/topology', 'ui://culkibo/incident-remediator', 'ui://culkibo/coolify-migration-diff']) {
      const httpRead = await fetch(`http://127.0.0.1:${srv.address().port}/api/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'MCP-Protocol-Version': V,
          'Mcp-Method': 'resources/read',
          'Mcp-Name': uri
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: `app-${uri}`,
          method: 'resources/read',
          params: {
            uri,
            _meta: { 'io.modelcontextprotocol/protocolVersion': V, 'io.modelcontextprotocol/clientCapabilities': {} }
          }
        })
      });
      assert.strictEqual(httpRead.status, 200, `resources/read HTTP falló para ${uri}`);
      const payload = await httpRead.json();
      const item = payload.result.contents[0];
      assert.strictEqual(item.mimeType, 'text/html;profile=mcp-app');
      assert.ok(item._meta?.ui?.csp?.policy.includes("default-src 'none'"));
      const html = item.text;
      assert.ok(html.includes('Content-Security-Policy'));
      assert.ok(html.includes("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"));
      assert.ok(html.includes('window.parent.postMessage'), `${uri} debe incluir puente postMessage JSON-RPC`);
      assert.ok(!/<script[^>]+src=/i.test(html) && !/<link[^>]+href=/i.test(html), `${uri} no puede cargar scripts ni hojas externas`);
      assert.ok(!html.includes('</script><img'), `${uri} debe escapar cualquier intento de cierre de </script> (XSS)`);
      assert.ok(!html.includes('sk_live_never_render_into_mcp_app_999999'), `${uri} jamás puede incrustar secretos en claro`);
    }

    // Unit-level XSS escaping verification on mcpAppsRenderer.safeJsonForScript
    const escaped = mcpAppsRenderer.safeJsonForScript({ evil: '</script><script>alert(1)</script>', secret: 'cket_abc1234567890' });
    assert.ok(!escaped.includes('</script>'));
    assert.ok(escaped.includes('\\u003c/script\\u003e'));
    assert.ok(!escaped.includes('cket_abc1234567890'));

    // RBAC on ui://culkibo/* (revoked -> 0 & FORBIDDEN; narrow token without migrations:read blocked on coolify-migration-diff)
    assert.strictEqual(mcpServer.listResources({ ok: false }).length, 0);
    await assert.rejects(() => mcpServer.readResource('ui://culkibo/topology', { auth: { ok: false } }), /Acceso denegado/);
    const narrowAuth = {
      ok: true,
      method: 'api_token',
      principal: { userId: 'usr_narrow', role: 'viewer', teamId: 'team_default', projectIds: null, scopes: ['projects:read'] }
    };
    const narrowList = mcpServer.listResources(narrowAuth);
    assert.ok(narrowList.some((r) => r.uri === 'ui://culkibo/topology'));
    assert.ok(!narrowList.some((r) => r.uri === 'ui://culkibo/coolify-migration-diff'));
    await assert.rejects(() => mcpServer.readResource('ui://culkibo/coolify-migration-diff', { auth: narrowAuth }), /Acceso denegado/);
    console.log('  ✓ MCP Apps (ui://culkibo/*): 3 apps HTML verificadas (MIME, CSP estricta, 0 URLs externas, anti-XSS, postMessage, RBAC)');
  } finally {
    await new Promise((resolve) => srv.close(resolve));
    projectManager.delete(xssProj.id);
    await projectManager.flushToDisk();
  }

  // 4. culkibo_smartpack_plan (RO, outputSchema, path-boundary security)
  const spRes = await mcpServer.executeTool('culkibo_smartpack_plan', {
    directory: path.join(__dirname, '..', 'web'),
    includeDockerfile: true
  });
  assert.strictEqual(spRes.isError, false);
  const sp = spRes.structuredContent;
  assert.ok(typeof sp.stack === 'string' && sp.stack.length > 0);
  assert.ok(sp.plan && typeof sp.plan.deterministicHash === 'string');
  assert.ok(Array.isArray(sp.dockerignore) && sp.dockerignore.includes('.git'));
  assert.ok(typeof sp.dockerfile === 'string' && sp.dockerfile.includes('FROM '));

  // Path traversal outside workspace blocked with FORBIDDEN_PATH
  const spTraversal = await mcpServer.executeTool('culkibo_smartpack_plan', { directory: path.resolve(os.tmpdir(), '..') });
  assert.strictEqual(spTraversal.isError, true);
  assert.strictEqual(JSON.parse(spTraversal.content[0].text).code, 'FORBIDDEN_PATH');
  console.log(`  ✓ culkibo_smartpack_plan verificado (stack=${sp.stack}, ${sp.dockerignore.length} ignore patterns, path guard OK)`);

  // 5. culkibo_edge_tunnel (admin RBAC, dryRun, isolated create/list/status/revoke, cket_ redaction in auditLog)
  const devAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_et_dev', role: 'developer', teamId: 'team_default', projectIds: null, scopes: ['*'] }
  };
  const devBlocked = await mcpServer.executeTool('culkibo_edge_tunnel', { action: 'list' }, { auth: devAuth });
  assert.strictEqual(devBlocked.isError, true);
  assert.strictEqual(JSON.parse(devBlocked.content[0].text).code, 'FORBIDDEN');

  const tmpEtDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mcp-et-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = tmpEtDir;
  try {
    const etDry = await mcpServer.executeTool('culkibo_edge_tunnel', {
      action: 'create',
      name: 'mcp-dry-tun',
      targetPort: 3000,
      dryRun: true
    });
    assert.strictEqual(etDry.isError, false);
    assert.strictEqual(etDry.structuredContent.dryRun, true);
    assert.strictEqual(etDry.structuredContent.wouldExecute, true);

    const etCreated = await mcpServer.executeTool('culkibo_edge_tunnel', {
      action: 'create',
      name: 'mcp-live-tun',
      targetHost: '127.0.0.1',
      targetPort: 3456,
      hostname: 'app.tunnel.test'
    });
    assert.strictEqual(etCreated.isError, false);
    const createdTun = etCreated.structuredContent.tunnel;
    assert.ok(createdTun && createdTun.id && typeof createdTun.token === 'string' && createdTun.token.startsWith('cket_'));
    const latestAudit = mcpServer.getAuditLog(1)[0];
    assert.ok(!JSON.stringify(latestAudit).includes(createdTun.token), 'Token cket_ jamás puede filtrarse al auditLog MCP');

    const etList = await mcpServer.executeTool('culkibo_edge_tunnel', { action: 'list' });
    assert.strictEqual(etList.isError, false);
    assert.ok(etList.structuredContent.tunnels.some((t) => t.id === createdTun.id));

    const etRevoke = await mcpServer.executeTool('culkibo_edge_tunnel', { action: 'revoke', tunnelId: createdTun.id });
    assert.strictEqual(etRevoke.isError, false);
    assert.strictEqual(etRevoke.structuredContent.revoked, true);
    console.log('  ✓ culkibo_edge_tunnel verificado (RBAC admin, dryRun, create/list/revoke aislado, cket_ redactado)');
  } finally {
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpEtDir, { recursive: true, force: true }); } catch (e) {}
  }
}

/**
 * MCP 2026 Cycle-4: Official Async Tasks (`io.modelcontextprotocol/tasks`),
 * `elicitation/create` remediation schemas, `culkibo_verify_attestation`,
 * `culkibo_otlp_status`, and `-80%+` `?profile=core` at 113 tools.
 */
async function testMcp2026Cycle4TasksElicitationAndTools() {
  const express = require('express');
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const projectManager = require('../server/services/projectManager');
  const mcpStreamableHttp = require('../server/services/mcpStreamableHttp');
  const supplyChainAttestor = require('../server/services/supplyChainAttestor');
  const otlpExporter = require('../server/services/otlpExporter');
  const V = mcpServer.protocol.PROTOCOL_VERSION;
  const meta = () => ({
    'io.modelcontextprotocol/protocolVersion': V,
    'io.modelcontextprotocol/clientCapabilities': {}
  });

  // 1. Capabilities advertisement: `tasks` in both `server/discover` and `initialize`
  const discover = mcpServer.getDiscoverResult();
  assert.deepStrictEqual(discover.capabilities.tasks, {
    list: {},
    cancel: {},
    requests: { tools: { call: {} } }
  }, 'server/discover debe anunciar capabilities.tasks completo');
  assert.ok(!discover.capabilities.sampling, 'No debe anunciar Sampling SEP-2577 deprecado');

  const initRes = await mcpServer.handleJsonRpc({ jsonrpc: '2.0', id: 'c4-init', method: 'initialize', params: {} });
  assert.deepStrictEqual(initRes.result.capabilities.tasks, {
    list: {},
    cancel: {},
    requests: { tools: { call: {} } }
  }, 'initialize debe anunciar capabilities.tasks completo');

  // 2. Async Tasks full lifecycle over Streamable HTTP POST /api/mcp
  const app = express();
  app.use(express.json());
  app.post('/api/mcp', mcpStreamableHttp.handlePost);
  const srv = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const endpoint = `http://127.0.0.1:${srv.address().port}/api/mcp`;
  const postMcp = (method, params, extraHeaders = {}) => fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'MCP-Protocol-Version': V,
      'Mcp-Method': method,
      ...extraHeaders
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: `req-${method}-${Math.random().toString(36).slice(2, 6)}`, method, params: { ...params, _meta: meta() } })
  });

  try {
    // 2a. Enqueue tool call with params.task -> immediate `{ task: { taskId, status: 'working', ... } }`
    const createRes = await postMcp(
      'tools/call',
      { name: 'culkibo_list_pods', arguments: {}, task: { ttl: 60000 } },
      { 'Mcp-Name': 'culkibo_list_pods' }
    );
    assert.strictEqual(createRes.status, 200);
    assert.ok(String(createRes.headers.get('cache-control') || '').includes('no-store'), 'Las tareas MCP nunca deben cachearse públicamente');
    const createdPayload = await createRes.json();
    const task = createdPayload.result.task;
    assert.ok(task && typeof task.taskId === 'string' && task.taskId.startsWith('tsk_'));
    assert.strictEqual(task.status, 'working');
    assert.strictEqual(task.ttl, 60000);
    assert.strictEqual(task.pollInterval, 1000);
    assert.ok(typeof task.createdAt === 'string');

    // 2b. tasks/list includes created task
    const listHttp = await postMcp('tasks/list', {});
    assert.strictEqual(listHttp.status, 200);
    const listPayload = await listHttp.json();
    assert.ok(Array.isArray(listPayload.result.tasks) && listPayload.result.tasks.some((t) => t.taskId === task.taskId));

    // 2c. tasks/result waits for completion and returns CallToolResult with related-task metadata
    const resultHttp = await postMcp('tasks/result', { taskId: task.taskId });
    assert.strictEqual(resultHttp.status, 200);
    const resultPayload = await resultHttp.json();
    assert.strictEqual(resultPayload.result.isError, false);
    assert.strictEqual(resultPayload.result._meta['io.modelcontextprotocol/related-task'].taskId, task.taskId);
    assert.ok(resultPayload.result.content[0].text.includes('The Forge'));

    // 2d. tasks/get now shows status === 'completed'
    const getHttp = await postMcp('tasks/get', { taskId: task.taskId });
    assert.strictEqual(getHttp.status, 200);
    const getPayload = await getHttp.json();
    assert.strictEqual(getPayload.result.status, 'completed');

    // 2e. tasks/cancel on a working task -> transitions to 'cancelled', tasks/result fails with TASK_CANCELLED
    const toCancel = await mcpServer.handleModernRpc({
      jsonrpc: '2.0',
      id: 'c4-cancel-create',
      method: 'tools/call',
      params: { name: 'culkibo_list_pods', arguments: {}, task: { ttl: 60000 }, _meta: meta() }
    });
    const cancelTaskId = toCancel.result.task.taskId;
    assert.strictEqual(toCancel.result.task.status, 'working');
    const cancelled = await mcpServer.handleModernRpc({
      jsonrpc: '2.0',
      id: 'c4-cancel-do',
      method: 'tasks/cancel',
      params: { taskId: cancelTaskId, _meta: meta() }
    });
    assert.strictEqual(cancelled.result.status, 'cancelled');
    const cancelledResult = await mcpServer.handleModernRpc({
      jsonrpc: '2.0',
      id: 'c4-cancel-res',
      method: 'tasks/result',
      params: { taskId: cancelTaskId, _meta: meta() }
    });
    assert.ok(cancelledResult.error && cancelledResult.error.data.code === 'TASK_CANCELLED');
    // Cancelling already-terminal task returns JSON-RPC -32602
    const cancelAgain = await mcpServer.handleModernRpc({
      jsonrpc: '2.0',
      id: 'c4-cancel-again',
      method: 'tasks/cancel',
      params: { taskId: cancelTaskId, _meta: meta() }
    });
    assert.ok(cancelAgain.error && cancelAgain.error.code === -32602);
  } finally {
    await new Promise((resolve) => srv.close(resolve));
  }

  // 2f. Cross-tenant RBAC isolation on Async Tasks (zero snooping across principals/teams!)
  const authAlpha = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_task_alpha', role: 'viewer', teamId: 'team_alpha', projectIds: null, scopes: ['*'] }
  };
  const authBeta = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_task_beta', role: 'viewer', teamId: 'team_beta', projectIds: null, scopes: ['*'] }
  };
  const alphaCreate = await mcpServer.handleModernRpc({
    jsonrpc: '2.0',
    id: 'c4-alpha-create',
    method: 'tools/call',
    params: { name: 'culkibo_list_pods', arguments: {}, task: { ttl: 60000 }, _meta: meta() }
  }, { auth: authAlpha });
  const alphaTaskId = alphaCreate.result.task.taskId;

  const betaList = await mcpServer.handleModernRpc({
    jsonrpc: '2.0',
    id: 'c4-beta-list',
    method: 'tasks/list',
    params: { _meta: meta() }
  }, { auth: authBeta });
  assert.ok(!betaList.result.tasks.some((t) => t.taskId === alphaTaskId), 'Principal Beta JAMÁS puede ver tareas de Principal Alpha');

  for (const forbiddenMethod of ['tasks/get', 'tasks/result', 'tasks/cancel']) {
    const attempt = await mcpServer.handleModernRpc({
      jsonrpc: '2.0',
      id: `c4-beta-${forbiddenMethod}`,
      method: forbiddenMethod,
      params: { taskId: alphaTaskId, _meta: meta() }
    }, { auth: authBeta });
    assert.ok(attempt.error && attempt.error.data.code === 'TASK_NOT_FOUND', `Beta debe recibir TASK_NOT_FOUND en ${forbiddenMethod}`);
  }
  // Fail-closed for revoked auth `{ ok: false }`
  const revokedCreate = await mcpServer.handleModernRpc({
    jsonrpc: '2.0',
    id: 'c4-revoked',
    method: 'tasks/list',
    params: { _meta: meta() }
  }, { auth: { ok: false } });
  assert.ok(revokedCreate.error && revokedCreate.error.data.code === 'FORBIDDEN');
  // Wait for alpha task to finish cleanly
  const alphaDone = await mcpServer.handleModernRpc({
    jsonrpc: '2.0',
    id: 'c4-alpha-res',
    method: 'tasks/result',
    params: { taskId: alphaTaskId, _meta: meta() }
  }, { auth: authAlpha });
  assert.strictEqual(alphaDone.result.isError, false);

  // Short TTL eviction test
  const shortTtl = await mcpServer.handleModernRpc({
    jsonrpc: '2.0',
    id: 'c4-short-ttl',
    method: 'tools/call',
    params: { name: 'culkibo_list_pods', arguments: {}, task: { ttl: 100 }, _meta: meta() }
  });
  await new Promise((r) => setTimeout(r, 140));
  const afterExpiry = await mcpServer.handleModernRpc({
    jsonrpc: '2.0',
    id: 'c4-expired-get',
    method: 'tasks/get',
    params: { taskId: shortTtl.result.task.taskId, _meta: meta() }
  });
  assert.ok(afterExpiry.error && afterExpiry.error.data.code === 'TASK_NOT_FOUND');
  console.log('  ✓ MCP 2026-07-28 Async Tasks verificados (capabilities, tasks/list|get|result|cancel, TTL eviction y aislamiento cross-tenant RBAC)');

  // 3. MCP elicitation/create helper + _meta['io.modelcontextprotocol/elicitation'] on CONFIRMATION_REQUIRED / MISSING_SECRET / DEPLOY_FROZEN
  const builtElicit = mcpServer.buildElicitationRequest({
    message: 'Confirm release deployment',
    action: 'ship_and_verify',
    projectId: 'proj_demo',
    requestedSchema: {
      type: 'object',
      properties: { confirm: { type: 'boolean' } },
      required: ['confirm']
    }
  });
  assert.strictEqual(builtElicit.method, 'elicitation/create');
  assert.strictEqual(builtElicit.params.mode, 'form');
  assert.strictEqual(builtElicit.params._meta.action, 'ship_and_verify');
  assert.strictEqual(builtElicit.params._meta.projectId, 'proj_demo');

  const tmpProj = projectManager.create({
    name: 'Cycle4 Elicitation Test App',
    teamId: 'team_default'
  });
  try {
    // 3a. CONFIRMATION_REQUIRED attaches _meta['io.modelcontextprotocol/elicitation']
    const noConfirm = await mcpServer.executeTool('culkibo_ship_and_verify', { projectId: tmpProj.id });
    assert.strictEqual(noConfirm.isError, true);
    assert.strictEqual(JSON.parse(noConfirm.content[0].text).code, 'CONFIRMATION_REQUIRED');
    const confirmElicit = noConfirm._meta['io.modelcontextprotocol/elicitation'];
    assert.ok(confirmElicit && confirmElicit.method === 'elicitation/create');
    assert.ok(confirmElicit.params.requestedSchema.required.includes('confirmToken'));

    // 3b. SECRET_LEAK_DETECTED (TOCTOU guard on Phase 2) attaches elicitation metadata
    const dryClean = await mcpServer.executeTool('culkibo_ship_and_verify', { projectId: tmpProj.id, dryRun: true });
    assert.strictEqual(dryClean.isError, false);
    assert.ok(typeof dryClean.structuredContent.confirmToken === 'string' && dryClean.structuredContent.confirmToken.startsWith('ckr_'));
    projectManager.update(tmpProj.id, { envVars: { STRIPE_KEY: ['sk', 'live', '0123456789abcdef0123456789abcdef'].join('_') } });
    const leakedShip = await mcpServer.executeTool('culkibo_ship_and_verify', {
      projectId: tmpProj.id,
      dryRun: false,
      confirmToken: dryClean.structuredContent.confirmToken
    });
    assert.strictEqual(leakedShip.isError, true);
    assert.strictEqual(JSON.parse(leakedShip.content[0].text).code, 'SECRET_LEAK_DETECTED');
    assert.strictEqual(leakedShip._meta['io.modelcontextprotocol/elicitation']?.method, 'elicitation/create');

    // 3c. MISSING_SECRET & DEPLOY_FROZEN / DEPLOY_FREEZE_ACTIVE schema builders
    const missingSecretElicit = mcpServer._buildErrorElicitation('culkibo_set_project_env', { projectId: tmpProj.id }, {
      code: 'MISSING_SECRET',
      message: 'Missing DATABASE_URL',
      details: { secretKey: 'DATABASE_URL' }
    }, null);
    assert.strictEqual(missingSecretElicit.method, 'elicitation/create');
    assert.ok(missingSecretElicit.params.requestedSchema.properties.storeInVault);
    assert.strictEqual(missingSecretElicit.params.requestedSchema.properties.secretKey.default, 'DATABASE_URL');

    const frozenElicit = mcpServer._buildErrorElicitation('culkibo_ship_and_verify', { projectId: tmpProj.id }, {
      code: 'DEPLOY_FROZEN',
      message: 'Deploy freeze active'
    }, null);
    assert.strictEqual(frozenElicit.method, 'elicitation/create');
    assert.ok(frozenElicit.params.requestedSchema.properties.overrideFreeze);
    assert.ok(frozenElicit.params.requestedSchema.required.includes('reason'));
  } finally {
    projectManager.delete(tmpProj.id);
    await projectManager.flushToDisk();
  }
  console.log('  ✓ MCP elicitation/create verificado (CONFIRMATION_REQUIRED, SECRET_LEAK_DETECTED, MISSING_SECRET y DEPLOY_FROZEN)');

  // 4. culkibo_verify_attestation (RO, isolated CULKIBO_DATA_DIR, Ed25519 DSSE verify + tamper reject + anti-IDOR)
  const tmpDataRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mcp-slsa-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = tmpDataRoot;
  const attProj = projectManager.create({ name: 'SLSA Attest Project', teamId: 'team_default' });
  try {
    const pubKeyRes = await mcpServer.executeTool('culkibo_verify_attestation', { action: 'public_key' });
    assert.strictEqual(pubKeyRes.isError, false);
    assert.ok(pubKeyRes.structuredContent.publicKeyPem.includes('BEGIN PUBLIC KEY'));

    const attested = supplyChainAttestor.attestRelease({
      projectId: attProj.id,
      revision: 'rev-c4-1',
      commitSha: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
      sbomSummary: { bomFormat: 'CycloneDX', specVersion: '1.6', componentCount: 93, rootDependencies: 6 }
    });
    assert.strictEqual(attested.ok, true);

    const verifiedStored = await mcpServer.executeTool('culkibo_verify_attestation', {
      action: 'verify',
      projectId: attProj.id,
      revision: 'rev-c4-1'
    });
    assert.strictEqual(verifiedStored.isError, false);
    assert.strictEqual(verifiedStored.structuredContent.valid, true);
    assert.strictEqual(verifiedStored.structuredContent.verification.algorithm, 'Ed25519');
    assert.strictEqual(verifiedStored.structuredContent.verification.slsaVersion, '1.1');

    // Tampered DSSE envelope must fail cryptographic verification cleanly
    const tamperedEnv = JSON.parse(JSON.stringify(attested.envelope));
    const decodedPayload = JSON.parse(Buffer.from(tamperedEnv.payload, 'base64').toString('utf8'));
    decodedPayload.subject[0].name = 'culkibo://evil-tampered';
    tamperedEnv.payload = Buffer.from(JSON.stringify(decodedPayload), 'utf8').toString('base64');
    const tamperedRes = await mcpServer.executeTool('culkibo_verify_attestation', {
      action: 'verify',
      envelope: tamperedEnv
    });
    assert.strictEqual(tamperedRes.isError, false);
    assert.strictEqual(tamperedRes.structuredContent.valid, false);
    assert.strictEqual(tamperedRes.structuredContent.verification.reason, 'INVALID_SIGNATURE');

    // Anti-IDOR RBAC check: viewer scoped to different project blocked
    const otherViewer = {
      ok: true,
      method: 'api_token',
      principal: { userId: 'usr_slsa_other', role: 'viewer', teamId: 'team_default', projectIds: ['proj_unrelated'], scopes: ['*'] }
    };
    const idorAtt = await mcpServer.executeTool('culkibo_verify_attestation', {
      action: 'verify',
      projectId: attProj.id,
      revision: 'rev-c4-1'
    }, { auth: otherViewer });
    assert.strictEqual(idorAtt.isError, true);
    assert.strictEqual(JSON.parse(idorAtt.content[0].text).code, 'FORBIDDEN');
    console.log('  ✓ culkibo_verify_attestation verificado (SLSA v1.1 Ed25519 DSSE pass, tamper INVALID_SIGNATURE y anti-IDOR)');
  } finally {
    projectManager.delete(attProj.id);
    await projectManager.flushToDisk();
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpDataRoot, { recursive: true, force: true }); } catch (e) {}
  }

  // 5. culkibo_otlp_status (admin RBAC, header redaction, SSRF metadata rejection, clean restore)
  const devAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_otlp_dev', role: 'developer', teamId: 'team_default', projectIds: null, scopes: ['*'] }
  };
  const otlpDevBlocked = await mcpServer.executeTool('culkibo_otlp_status', { action: 'status' }, { auth: devAuth });
  assert.strictEqual(otlpDevBlocked.isError, true);
  assert.strictEqual(JSON.parse(otlpDevBlocked.content[0].text).code, 'FORBIDDEN');

  try {
    const otlpStatus = await mcpServer.executeTool('culkibo_otlp_status', { action: 'status' });
    assert.strictEqual(otlpStatus.isError, false);
    assert.strictEqual(otlpStatus.structuredContent.status.protocol, 'otlp/http-json');
    assert.strictEqual(otlpStatus.structuredContent.status.contentEncoding, 'gzip');

    const otlpCfg = await mcpServer.executeTool('culkibo_otlp_status', {
      action: 'configure',
      endpoint: 'https://tempo.example.com:4318',
      headers: { Authorization: 'Bearer sk_live_otlp_secret_never_leak_999' },
      serviceName: 'culkibo-test-plane',
      enabled: false
    });
    assert.strictEqual(otlpCfg.isError, false);
    assert.strictEqual(otlpCfg.structuredContent.configured, true);
    assert.ok(!JSON.stringify(otlpCfg.structuredContent).includes('sk_live_otlp_secret_never_leak_999'), 'Authorization debe redactarse en status OTLP');
    assert.ok(!JSON.stringify(mcpServer.getAuditLog(1)[0]).includes('sk_live_otlp_secret_never_leak_999'), 'Authorization debe redactarse en auditLog MCP');

    // Cloud metadata SSRF rejected cleanly
    const otlpSsrf = await mcpServer.executeTool('culkibo_otlp_status', {
      action: 'configure',
      endpoint: 'http://169.254.169.254/latest/meta-data'
    });
    assert.strictEqual(otlpSsrf.isError, true);
    assert.strictEqual(JSON.parse(otlpSsrf.content[0].text).code, 'INVALID_ARGUMENT');
    console.log('  ✓ culkibo_otlp_status verificado (RBAC admin, redacción Authorization y bloqueo SSRF metadatos cloud)');
  } finally {
    otlpExporter.configure({ endpoint: null, headers: {}, enabled: false, serviceName: 'culkibo-control-plane', allowLoopback: false });
  }

  // 6. ?profile=core maintains -80%+ serialized token savings at 125 tools
  const fullBytes = Buffer.byteLength(JSON.stringify(mcpServer.getToolsForPrincipal(null, { profile: 'all' })), 'utf8');
  const coreTools = mcpServer.getToolsForPrincipal(null, { profile: 'core' });
  const coreBytes = Buffer.byteLength(JSON.stringify(coreTools), 'utf8');
  const savedPct = Math.round((1 - coreBytes / fullBytes) * 1000) / 10;
  assert.strictEqual(mcpServer.getToolsDefinition().length, 125);
  assert.ok(savedPct >= 80, `?profile=core debe ahorrar >=80% tokens sobre 125 tools (actual: ${savedPct}%)`);
  console.log(`  ✓ ?profile=core sobre 125 tools: ${coreTools.length}/125 herramientas (-${savedPct}% bytes/tokens)`);
}

/**
 * MCP 2026 Cycle-6: Shadow Traffic Replay (`culkibo_shadow_replay`),
 * Whole-Stack Time-Machine (`culkibo_time_machine`), FinOps Cloud Savings (`culkibo_finops_report`),
 * and `-82%+` `?profile=core` over 116 tools.
 */
async function testMcp2026Cycle6ShadowTimeMachineFinOps() {
  const fs = require('fs');
  const http = require('http');
  const os = require('os');
  const path = require('path');
  const projectManager = require('../server/services/projectManager');
  const timeMachineService = require('../server/services/timeMachineService');

  const tmpDataRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mcp-c6-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = tmpDataRoot;
  const resetTmCache = () => {
    timeMachineService._loaded = false;
    timeMachineService._masterKey = null;
    timeMachineService._hmacKey = null;
    timeMachineService.state = { version: 1, projects: Object.create(null) };
  };
  resetTmCache();

  const projC6 = projectManager.create({
    name: 'Cycle6 Pioneer App',
    description: 'Initial v1 description',
    teamId: 'team_default',
    memoryMb: 1024,
    envVars: { API_MODE: 'v1', SECRET_TOKEN: 'sk_live_c6_never_leak_999999' }
  });
  const projOther = projectManager.create({
    name: 'Cycle6 Foreign App',
    teamId: 'team_default',
    memoryMb: 512
  });

  // 1. culkibo_shadow_replay: PROMOTE vs BLOCK_CUTOVER, secret redaction, SSRF block & RBAC
  let candidateMode = 'healthy';
  const baseSrv = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, id: 1, version: 'v1', items: [{ sku: 'a' }] }));
  });
  const candSrv = http.createServer((req, res) => {
    if (candidateMode === 'broken') {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'boom' }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, id: 2, version: 'v2', items: [{ sku: 'b' }] }));
  });
  await Promise.all([
    new Promise((r) => baseSrv.listen(0, '127.0.0.1', () => r(undefined))),
    new Promise((r) => candSrv.listen(0, '127.0.0.1', () => r(undefined)))
  ]);

  try {
    const baseUrl = `http://127.0.0.1:${baseSrv.address().port}`;
    const candUrl = `http://127.0.0.1:${candSrv.address().port}`;

    // Viewer blocked (write tool) + scoped developer anti-IDOR blocked on foreign project
    const viewerAuth = {
      ok: true,
      method: 'api_token',
      principal: { userId: 'usr_c6_viewer', role: 'viewer', teamId: 'team_default', projectIds: [projC6.id], scopes: ['*'] }
    };
    const scopedDevAuth = {
      ok: true,
      method: 'api_token',
      principal: { userId: 'usr_c6_dev', role: 'developer', teamId: 'team_default', projectIds: [projC6.id], scopes: ['*'] }
    };

    const viewerShadow = await mcpServer.executeTool('culkibo_shadow_replay', {
      projectId: projC6.id,
      baselineUrl: baseUrl,
      candidateUrl: candUrl,
      requests: [{ method: 'GET', path: '/health' }],
      allowLoopback: true
    }, { auth: viewerAuth });
    assert.strictEqual(viewerShadow.isError, true);
    assert.strictEqual(JSON.parse(viewerShadow.content[0].text).code, 'FORBIDDEN');

    const idorShadow = await mcpServer.executeTool('culkibo_shadow_replay', {
      projectId: projOther.id,
      baselineUrl: baseUrl,
      candidateUrl: candUrl,
      requests: [{ method: 'GET', path: '/health' }],
      allowLoopback: true
    }, { auth: scopedDevAuth });
    assert.strictEqual(idorShadow.isError, true);
    assert.strictEqual(JSON.parse(idorShadow.content[0].text).code, 'FORBIDDEN');

    // Cloud-metadata SSRF blocked
    const ssrfShadow = await mcpServer.executeTool('culkibo_shadow_replay', {
      projectId: projC6.id,
      baselineUrl: 'http://169.254.169.254/latest/meta-data',
      candidateUrl: candUrl,
      requests: [{ method: 'GET', path: '/' }],
      allowLoopback: true
    });
    assert.strictEqual(ssrfShadow.isError, true);
    assert.strictEqual(JSON.parse(ssrfShadow.content[0].text).code, 'INVALID_ARGUMENT');

    // Pass scenario -> PROMOTE + Authorization redacted
    const passReplay = await mcpServer.executeTool('culkibo_shadow_replay', {
      projectId: projC6.id,
      baselineUrl: baseUrl,
      candidateUrl: candUrl,
      requests: [{ method: 'GET', path: '/api/items', headers: { Authorization: 'Bearer sk_live_shadow_never_store_999' } }],
      allowLoopback: true
    }, { auth: scopedDevAuth });
    assert.strictEqual(passReplay.isError, false);
    assert.strictEqual(passReplay.structuredContent.pass, true);
    assert.strictEqual(passReplay.structuredContent.verdict, 'PROMOTE');
    assert.ok(!JSON.stringify(passReplay.structuredContent).includes('sk_live_shadow_never_store_999'), 'Authorization jamás puede almacenarse en shadow replay');
    assert.ok(!JSON.stringify(mcpServer.getAuditLog(1)[0]).includes('sk_live_shadow_never_store_999'), 'Authorization jamás puede filtrarse al auditLog MCP');

    // Regression scenario -> BLOCK_CUTOVER
    candidateMode = 'broken';
    const failReplay = await mcpServer.executeTool('culkibo_shadow_replay', {
      projectId: projC6.id,
      baselineUrl: baseUrl,
      candidateUrl: candUrl,
      requests: [{ method: 'GET', path: '/api/items' }],
      allowLoopback: true
    });
    assert.strictEqual(failReplay.isError, false);
    assert.strictEqual(failReplay.structuredContent.pass, false);
    assert.strictEqual(failReplay.structuredContent.verdict, 'BLOCK_CUTOVER');
    assert.ok(failReplay.structuredContent.blockers.some((b) => b.code === 'REGRESSION_5XX'));

    const histReplay = await mcpServer.executeTool('culkibo_shadow_replay', { action: 'history', projectId: projC6.id });
    assert.strictEqual(histReplay.isError, false);
    assert.ok(histReplay.structuredContent.count >= 2);
    console.log('  ✓ culkibo_shadow_replay verificado (PROMOTE, BLOCK_CUTOVER 5xx, redacción Authorization, SSRF block y anti-IDOR)');

    // 2. culkibo_time_machine: create -> mutate -> diff -> default dryRun restore (0 mutations) -> dryRun:false restore + safety checkpoint + RBAC
    const idorTm = await mcpServer.executeTool('culkibo_time_machine', {
      action: 'list',
      projectId: projOther.id
    }, { auth: scopedDevAuth });
    assert.strictEqual(idorTm.isError, true);
    assert.strictEqual(JSON.parse(idorTm.content[0].text).code, 'FORBIDDEN');

    const cp1Res = await mcpServer.executeTool('culkibo_time_machine', {
      action: 'create',
      projectId: projC6.id,
      label: 'pre-upgrade-v1'
    }, { auth: scopedDevAuth });
    assert.strictEqual(cp1Res.isError, false);
    const cp1Id = cp1Res.structuredContent.checkpoint.id;
    assert.ok(typeof cp1Id === 'string' && cp1Id.startsWith('tm_'));
    assert.ok(!JSON.stringify(cp1Res.structuredContent).includes('sk_live_c6_never_leak_999999'), 'Time-Machine jamás puede devolver secretos en claro');

    // Mutate project state
    projectManager.update(projC6.id, {
      description: 'Broken v2 mutation',
      memoryMb: 2048,
      envVars: { API_MODE: 'v2-broken', EXTRA_FLAG: '1' }
    });

    const cp2Res = await mcpServer.executeTool('culkibo_time_machine', {
      action: 'create',
      projectId: projC6.id,
      label: 'post-upgrade-v2'
    }, { auth: scopedDevAuth });
    assert.strictEqual(cp2Res.isError, false);
    const cp2Id = cp2Res.structuredContent.checkpoint.id;

    const listTm = await mcpServer.executeTool('culkibo_time_machine', { action: 'list', projectId: projC6.id });
    assert.strictEqual(listTm.isError, false);
    assert.strictEqual(listTm.structuredContent.count, 2);

    const diffTm = await mcpServer.executeTool('culkibo_time_machine', {
      action: 'diff',
      projectId: projC6.id,
      fromId: cp1Id,
      toId: cp2Id
    });
    assert.strictEqual(diffTm.isError, false);
    assert.ok(diffTm.structuredContent.diff.hasChanges === true);
    assert.ok(diffTm.structuredContent.diff.env.added.includes('EXTRA_FLAG'));

    // Restore omitting dryRun -> defaults to dryRun: true (0 mutations!)
    const defaultDryRestore = await mcpServer.executeTool('culkibo_time_machine', {
      action: 'restore',
      projectId: projC6.id,
      checkpointId: cp1Id
    });
    assert.strictEqual(defaultDryRestore.isError, false);
    assert.strictEqual(defaultDryRestore.structuredContent.dryRun, true);
    assert.strictEqual(defaultDryRestore.structuredContent.restored, false);
    assert.strictEqual(projectManager.getById(projC6.id).description, 'Broken v2 mutation', 'restore sin dryRun:false NUNCA debe mutar estado');

    // Restore with explicit dryRun: true -> previewToolPlan (0 mutations!)
    const explicitDryRestore = await mcpServer.executeTool('culkibo_time_machine', {
      action: 'restore',
      projectId: projC6.id,
      checkpointId: cp1Id,
      dryRun: true
    });
    assert.strictEqual(explicitDryRestore.isError, false);
    assert.strictEqual(explicitDryRestore.structuredContent.dryRun, true);
    assert.strictEqual(explicitDryRestore.structuredContent.wouldExecute, true);
    assert.strictEqual(projectManager.getById(projC6.id).description, 'Broken v2 mutation');

    // Real restore with dryRun: false -> restores v1 + creates safety checkpoint!
    const realRestore = await mcpServer.executeTool('culkibo_time_machine', {
      action: 'restore',
      projectId: projC6.id,
      checkpointId: cp1Id,
      dryRun: false
    });
    assert.strictEqual(realRestore.isError, false);
    assert.strictEqual(realRestore.structuredContent.dryRun, false);
    assert.strictEqual(realRestore.structuredContent.restored, true);
    assert.ok(typeof realRestore.structuredContent.safetyCheckpointId === 'string' && realRestore.structuredContent.safetyCheckpointId.startsWith('tm_'));
    assert.strictEqual(projectManager.getById(projC6.id).description, 'Initial v1 description');
    assert.strictEqual(projectManager.getById(projC6.id).envVars.API_MODE, 'v1');
    console.log('  ✓ culkibo_time_machine verificado (create/list/diff, default dryRun=true, atomic restore + safety checkpoint y anti-IDOR)');

    // 3. culkibo_finops_report (RO, RBAC-scoped projects + compareCloudCosts)
    const finopsViewer = await mcpServer.executeTool('culkibo_finops_report', {
      apps: 6,
      databases: 2
    }, { auth: viewerAuth });
    assert.strictEqual(finopsViewer.isError, false);
    assert.strictEqual(finopsViewer.structuredContent.scopedProjectsCount, 1, 'culkibo_finops_report debe respetar ACL de proyectos del viewer');
    assert.ok(finopsViewer.structuredContent.comparison.annualSavingsUsd > 0);
    assert.ok(finopsViewer.structuredContent.comparison.savingsPct > 0);
    assert.ok(finopsViewer.structuredContent.analysis && Array.isArray(finopsViewer.structuredContent.analysis.recommendations));
    console.log(`  ✓ culkibo_finops_report verificado (RO RBAC scopedProjects=1, ahorro anual $${finopsViewer.structuredContent.comparison.annualSavingsUsd}/yr = ${finopsViewer.structuredContent.comparison.savingsPct}%)`);

    // 4. Verify ?profile=core achieves >=82% token savings at 125 tools
    const allBytes = Buffer.byteLength(JSON.stringify(mcpServer.getToolsForPrincipal(null, { profile: 'all' })), 'utf8');
    const coreSubset = mcpServer.getToolsForPrincipal(null, { profile: 'core' });
    const coreBytes = Buffer.byteLength(JSON.stringify(coreSubset), 'utf8');
    const pctSaved = Math.round((1 - coreBytes / allBytes) * 1000) / 10;
    assert.strictEqual(mcpServer.getToolsDefinition().length, 125);
    assert.strictEqual(coreSubset.length, 17);
    assert.ok(pctSaved >= 83, `?profile=core debe ahorrar >=83% tokens en 125 tools (actual: ${pctSaved}%)`);
    console.log(`  ✓ ?profile=core sobre 125 tools: ${coreSubset.length}/125 herramientas (-${pctSaved}% bytes/tokens)`);
  } finally {
    await Promise.all([
      new Promise((r) => baseSrv.close(() => r(undefined))),
      new Promise((r) => candSrv.close(() => r(undefined)))
    ]);
    projectManager.delete(projC6.id);
    projectManager.delete(projOther.id);
    await projectManager.flushToDisk();
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    resetTmCache();
    try { fs.rmSync(tmpDataRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

/**
 * MCP 2026 Cycle-7: Build Auto-Healer (`culkibo_heal_build_failure`),
 * WireGuard Fleet Mesh (`culkibo_fleet_mesh`), Cron 24h Heatmap + Heartbeats (`culkibo_cron_timeline`),
 * Edge Bot-Shield + Hashcash PoW (`culkibo_edge_shield`), and `-83%+` `?profile=core` over 120 tools.
 */
async function testMcp2026Cycle7HealerMeshTimelineShield() {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const projectManager = require('../server/services/projectManager');
  const cronManager = require('../server/services/cronManager');
  const fleetMeshService = require('../server/services/fleetMeshService');

  const tmpDataRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mcp-c7-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = tmpDataRoot;

  const resetC7Caches = () => {
    fleetMeshService._loaded = false;
    fleetMeshService._masterKey = null;
    fleetMeshService.state = {
      version: 1,
      cidr: '10.88.0.0/24',
      interfaceName: 'wg0',
      listenPort: 51820,
      peers: Object.create(null)
    };
    if ('_heartbeatsLoaded' in cronManager) cronManager._heartbeatsLoaded = false;
    if ('_heartbeatsPath' in cronManager) cronManager._heartbeatsPath = null;
    if (Array.isArray(cronManager.heartbeats)) cronManager.heartbeats = [];
  };
  resetC7Caches();

  const projAllowed = projectManager.create({
    name: 'Cycle7 Allowed App',
    teamId: 'team_default',
    memoryMb: 512,
    envVars: { NODE_ENV: 'production' }
  });
  const projForeign = projectManager.create({
    name: 'Cycle7 Foreign App',
    teamId: 'team_default',
    memoryMb: 512
  });

  const viewerAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c7_viewer', role: 'viewer', teamId: 'team_default', projectIds: [projAllowed.id], scopes: ['*'] }
  };
  const scopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c7_dev', role: 'developer', teamId: 'team_default', projectIds: [projAllowed.id], scopes: ['*'] }
  };
  const unscopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c7_unscoped_dev', role: 'developer', teamId: 'team_default', projectIds: null, scopes: ['*'] }
  };

  /** @type {string[]} */
  const createdHbIds = [];
  /** @type {string[]} */
  const createdCronIds = [];

  try {
    // 1. culkibo_heal_build_failure (20-pattern diagnose + dryRun default + apply dryRun:false + anti-IDOR)
    const oomLogs = 'FATAL ERROR: Ineffective mark-compacts near heap limit Allocation failed - JavaScript heap out of memory\nExit code 137';

    // Viewer blocked + scoped dev blocked on foreign project (anti-IDOR)
    const healViewer = await mcpServer.executeTool('culkibo_heal_build_failure', {
      projectId: projAllowed.id,
      logs: oomLogs
    }, { auth: viewerAuth });
    assert.strictEqual(healViewer.isError, true);
    assert.strictEqual(JSON.parse(healViewer.content[0].text).code, 'FORBIDDEN');

    const healIdor = await mcpServer.executeTool('culkibo_heal_build_failure', {
      projectId: projForeign.id,
      logs: oomLogs
    }, { auth: scopedDevAuth });
    assert.strictEqual(healIdor.isError, true);
    assert.strictEqual(JSON.parse(healIdor.content[0].text).code, 'FORBIDDEN');

    // apply: true WITHOUT dryRun: false MUST default to dryRun: true (0 mutations!)
    const healDefaultDry = await mcpServer.executeTool('culkibo_heal_build_failure', {
      projectId: projAllowed.id,
      logs: oomLogs,
      apply: true
    }, { auth: scopedDevAuth });
    assert.strictEqual(healDefaultDry.isError, false);
    assert.strictEqual(healDefaultDry.structuredContent.matched, true);
    assert.strictEqual(healDefaultDry.structuredContent.dryRun, true);
    assert.strictEqual(healDefaultDry.structuredContent.applied, false);
    assert.strictEqual(healDefaultDry.structuredContent.diagnosis.primary.code, 'NODE_HEAP_OOM');
    assert.strictEqual(projectManager.getById(projAllowed.id).memoryMb, 512, 'apply sin dryRun:false no debe mutar el proyecto');

    // previewToolPlan via explicit dryRun: true
    const healPreview = await mcpServer.executeTool('culkibo_heal_build_failure', {
      projectId: projAllowed.id,
      logs: oomLogs,
      apply: true,
      dryRun: true
    }, { auth: scopedDevAuth });
    assert.strictEqual(healPreview.isError, false);
    assert.strictEqual(healPreview.structuredContent.dryRun, true);
    assert.strictEqual(healPreview.structuredContent.wouldExecute, true);

    // Explicit apply: true + dryRun: false applies safe patch (raises memoryMb / injects NODE_OPTIONS)
    const healApplied = await mcpServer.executeTool('culkibo_heal_build_failure', {
      projectId: projAllowed.id,
      logs: oomLogs,
      apply: true,
      dryRun: false
    }, { auth: scopedDevAuth });
    assert.strictEqual(healApplied.isError, false);
    assert.strictEqual(healApplied.structuredContent.dryRun, false);
    assert.strictEqual(healApplied.structuredContent.applied, true);
    assert.ok(projectManager.getById(projAllowed.id).memoryMb > 512, 'applyHealingPlan debe incrementar memoryMb en NODE_HEAP_OOM');
    console.log('  ✓ culkibo_heal_build_failure verificado (NODE_HEAP_OOM, default dryRun=true, dryRun=false apply y anti-IDOR)');

    // 2. culkibo_fleet_mesh (admin RBAC, status/plan/rotate dryRun default, 0 private key leaks)
    const meshDevBlocked = await mcpServer.executeTool('culkibo_fleet_mesh', { action: 'status' }, { auth: unscopedDevAuth });
    assert.strictEqual(meshDevBlocked.isError, true);
    assert.strictEqual(JSON.parse(meshDevBlocked.content[0].text).code, 'FORBIDDEN');

    const meshStatus = await mcpServer.executeTool('culkibo_fleet_mesh', { action: 'status' });
    assert.strictEqual(meshStatus.isError, false);
    assert.strictEqual(meshStatus.structuredContent.cidr, '10.88.0.0/24');
    assert.strictEqual(meshStatus.structuredContent.interfaceName, 'wg0');
    assert.ok(meshStatus.structuredContent.peerCount >= 1);
    const firstPeer = meshStatus.structuredContent.peers[0];
    assert.ok(typeof firstPeer.publicKey === 'string' && firstPeer.publicKey.length === 44);
    assert.ok(!('privateKey' in firstPeer) && !('encryptedPrivateKey' in firstPeer), 'Jamás exponer claves privadas WireGuard');

    const meshPlan = await mcpServer.executeTool('culkibo_fleet_mesh', { action: 'plan' });
    assert.strictEqual(meshPlan.isError, false);
    assert.strictEqual(meshPlan.structuredContent.dryRun, true);
    assert.ok(meshPlan.structuredContent.plan && Array.isArray(meshPlan.structuredContent.plan.wgConfigs));
    assert.ok(meshPlan.structuredContent.plan.wgConfigs[0].config.includes('[REDACT_ON_API]'));

    // Rotate omitting dryRun -> defaults to dryRun: true (keyVersion unchanged!)
    const meshRotDry = await mcpServer.executeTool('culkibo_fleet_mesh', { action: 'rotate', nodeId: firstPeer.nodeId });
    assert.strictEqual(meshRotDry.isError, false);
    assert.strictEqual(meshRotDry.structuredContent.dryRun, true);
    assert.strictEqual(meshRotDry.structuredContent.rotation.rotated, false);

    // Rotate with dryRun: false -> rotates keypair & audit log redacts result
    const meshRotReal = await mcpServer.executeTool('culkibo_fleet_mesh', { action: 'rotate', nodeId: firstPeer.nodeId, dryRun: false });
    assert.strictEqual(meshRotReal.isError, false);
    assert.strictEqual(meshRotReal.structuredContent.dryRun, false);
    assert.strictEqual(meshRotReal.structuredContent.rotation.rotated, true);
    assert.notStrictEqual(meshRotReal.structuredContent.rotation.newPublicKey, firstPeer.publicKey);
    assert.strictEqual(mcpServer.getAuditLog(1)[0].resultSummary, '[resultado sensible ocultado en auditoría]');
    console.log('  ✓ culkibo_fleet_mesh verificado (RBAC admin, x25519 44-char pubkey, 0 private keys, dryRun default y rotate real)');

    // 3. culkibo_cron_timeline (RO viewer allowed, ACL-filtered crons & heartbeats, raw token redacted!)
    const c1 = cronManager.create(projAllowed.id, { name: 'Allowed Backup', schedule: '0 * * * *', mode: 'http', httpPath: '/health' });
    const c2 = cronManager.create(projForeign.id, { name: 'Foreign Secret Job', schedule: '0 * * * *', mode: 'http', httpPath: '/health' });
    if (c1?.id) createdCronIds.push(c1.id);
    if (c2?.id) createdCronIds.push(c2.id);

    const hbAllowed = cronManager.createHeartbeat({ name: 'Allowed Heartbeat', projectId: projAllowed.id, periodSec: 3600, graceSec: 300 });
    const hbForeign = cronManager.createHeartbeat({ name: 'Foreign Heartbeat', projectId: projForeign.id, periodSec: 3600, graceSec: 300 });
    createdHbIds.push(hbAllowed.id, hbForeign.id);

    const timelineViewer = await mcpServer.executeTool('culkibo_cron_timeline', { hours: 24, includeHeartbeats: true }, { auth: viewerAuth });
    assert.strictEqual(timelineViewer.isError, false);
    assert.strictEqual(timelineViewer.structuredContent.hours, 24);
    assert.strictEqual(timelineViewer.structuredContent.slots.length, 24);
    const serializedTimeline = JSON.stringify(timelineViewer.structuredContent);
    assert.ok(serializedTimeline.includes('Allowed Heartbeat'), 'Debe incluir heartbeats del proyecto autorizado');
    assert.ok(!serializedTimeline.includes('Foreign Heartbeat'), 'JAMÁS debe filtrar heartbeats de otros proyectos');
    assert.ok(!serializedTimeline.includes('Foreign Secret Job'), 'JAMÁS debe filtrar crons de otros proyectos');
    assert.ok(!serializedTimeline.includes(hbAllowed.token), 'JAMÁS debe exponer el token raw de check-in del heartbeat por culkibo_cron_timeline');
    console.log('  ✓ culkibo_cron_timeline verificado (RO viewer, 24h heatmap, ACL estricto por proyecto y redacción de token heartbeat)');

    // 4. culkibo_edge_shield (developer/admin RBAC, status, compile native Caddy v2.11 subroutes + PoW challenge)
    const shieldViewer = await mcpServer.executeTool('culkibo_edge_shield', { action: 'status' }, { auth: viewerAuth });
    assert.strictEqual(shieldViewer.isError, true);
    assert.strictEqual(JSON.parse(shieldViewer.content[0].text).code, 'FORBIDDEN');

    const shieldStatus = await mcpServer.executeTool('culkibo_edge_shield', { action: 'status' }, { auth: unscopedDevAuth });
    assert.strictEqual(shieldStatus.isError, false);
    assert.strictEqual(shieldStatus.structuredContent.status.zeroCaddyPlugins, true);

    const shieldCompile = await mcpServer.executeTool('culkibo_edge_shield', {
      action: 'compile',
      domain: 'api.acme.dev',
      powChallenge: true,
      difficulty: 4
    }, { auth: unscopedDevAuth });
    assert.strictEqual(shieldCompile.isError, false);
    assert.ok(Array.isArray(shieldCompile.structuredContent.routes) && shieldCompile.structuredContent.routes.length >= 4);

    const shieldChal = await mcpServer.executeTool('culkibo_edge_shield', {
      action: 'challenge',
      domain: 'api.acme.dev',
      difficulty: 3
    }, { auth: unscopedDevAuth });
    assert.strictEqual(shieldChal.isError, false);
    assert.strictEqual(shieldChal.structuredContent.challenge.algorithm, 'sha256');
    assert.strictEqual(shieldChal.structuredContent.challenge.difficulty, 3);
    console.log('  ✓ culkibo_edge_shield verificado (RBAC developer/admin, status, compile Caddy v2.11 + PoW y challenge SHA-256)');

    // 5. Final Cycle-7 assertion: exact 125 tools & ?profile=core 17/125 >83% reduction
    const allTools = mcpServer.getToolsForPrincipal(null, { profile: 'all' });
    const coreTools = mcpServer.getToolsForPrincipal(null, { profile: 'core' });
    const savedPct = Math.round((1 - Buffer.byteLength(JSON.stringify(coreTools), 'utf8') / Buffer.byteLength(JSON.stringify(allTools), 'utf8')) * 1000) / 10;
    assert.strictEqual(allTools.length, 125);
    assert.strictEqual(coreTools.length, 17);
    assert.ok(savedPct > 83, `?profile=core debe superar 83% de ahorro en 125 tools (actual: ${savedPct}%)`);
    console.log(`  ✓ Catálogo Cycle-7 verificado: 125 tools exactas, ?profile=core 17/125 (-${savedPct}% tokens/bytes)`);
  } finally {
    for (const cid of createdCronIds) {
      try { if (typeof cronManager.remove === 'function') cronManager.remove(cid); else if (typeof cronManager.delete === 'function') cronManager.delete(cid); } catch (e) {}
    }
    for (const hid of createdHbIds) {
      try { cronManager.deleteHeartbeat(hid); } catch (e) {}
    }
    projectManager.delete(projAllowed.id);
    projectManager.delete(projForeign.id);
    await projectManager.flushToDisk();
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    resetC7Caches();
    try { fs.rmSync(tmpDataRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

/**
 * MCP 2026 Cycle-8: Autonomous Triage (`culkibo_triage_playbook`), SBOM CVE Drift (`culkibo_cve_scan`),
 * Config Drift + PgBouncer (`culkibo_drift_check`), Zero-Lock-In IaC Export (`culkibo_export_iac`),
 * Ephemeral Secret Leases & Break-Glass (`culkibo_secret_lease`), and `-84%+` `?profile=core` at 125 tools.
 */
async function testMcp2026Cycle8TriageCveDriftIacLease() {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const projectManager = require('../server/services/projectManager');
  const secretLeaseService = require('../server/services/secretLeaseService');

  const tmpDataRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mcp-c8-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = tmpDataRoot;

  const projA = projectManager.create({
    name: 'Cycle8 Alpha API',
    teamId: 'team_default',
    memoryMb: 512,
    containerPort: 3000,
    imageTag: 'acme/alpha:v1',
    envVars: { DATABASE_URL: 'postgres://u:CANARY_C8_SECRET_9991@127.0.0.1:5432/app', PUBLIC_ENV: 'prod' }
  });
  const projB = projectManager.create({
    name: 'Cycle8 Foreign Beta',
    teamId: 'team_default',
    memoryMb: 512,
    envVars: { FOREIGN_SECRET: 'CANARY_FOREIGN_SECRET_8822' }
  });

  const viewerAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c8_viewer', role: 'viewer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const scopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c8_dev', role: 'developer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };

  try {
    // 1. culkibo_triage_playbook (RO viewer/dev/admin, strict project ACL, chains incident + healer + drift + offline CVE)
    const triageIdor = await mcpServer.executeTool('culkibo_triage_playbook', {
      projectId: projB.id
    }, { auth: viewerAuth });
    assert.strictEqual(triageIdor.isError, true);
    assert.strictEqual(JSON.parse(triageIdor.content[0].text).code, 'FORBIDDEN');

    const driftedInspect = {
      Config: {
        Image: 'acme/alpha:v2-manual-hotfix',
        Env: ['DATABASE_URL=redacted', 'UNDECLARED_DEBUG=1'],
        StopTimeout: 10
      },
      HostConfig: {
        Memory: 256 * 1024 * 1024,
        PortBindings: { '3000/tcp': [{ HostIp: '0.0.0.0', HostPort: '3000' }] },
        LogConfig: { Type: 'syslog' }
      }
    };
    const triageOk = await mcpServer.executeTool('culkibo_triage_playbook', {
      projectId: projA.id,
      logs: 'FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory',
      actualInspect: driftedInspect,
      includeCveScan: true
    }, { auth: viewerAuth });
    assert.strictEqual(triageOk.isError, false);
    assert.strictEqual(triageOk.structuredContent.projectId, projA.id);
    assert.strictEqual(triageOk.structuredContent.healer.primary.code, 'NODE_HEAP_OOM');
    assert.strictEqual(triageOk.structuredContent.drift.drifted, true);
    assert.ok(triageOk.structuredContent.cve && triageOk.structuredContent.cve.ok === true);
    assert.ok(triageOk.structuredContent.rootCauses.length >= 2);
    assert.ok(triageOk.structuredContent.remediationSteps.length >= 2);
    assert.ok(!JSON.stringify(triageOk.structuredContent).includes('CANARY_C8_SECRET_9991'));
    console.log('  ✓ culkibo_triage_playbook verificado (incidente + NODE_HEAP_OOM + drift + SBOM CVE offline + anti-IDOR)');

    // 2. culkibo_cve_scan (RO viewer allowed, offline-safe default)
    const cveRes = await mcpServer.executeTool('culkibo_cve_scan', { allowNetwork: false }, { auth: viewerAuth });
    assert.strictEqual(cveRes.isError, false);
    assert.strictEqual(cveRes.structuredContent.ok, true);
    assert.ok(cveRes.structuredContent.scannedComponents > 0);
    console.log(`  ✓ culkibo_cve_scan verificado (${cveRes.structuredContent.scannedComponents} componentes SBOM, mode=${cveRes.structuredContent.mode})`);

    // 3. culkibo_drift_check (RO dev/admin, viewer blocked, anti-IDOR + PgBouncer preset)
    const driftViewerBlocked = await mcpServer.executeTool('culkibo_drift_check', { projectId: projA.id }, { auth: viewerAuth });
    assert.strictEqual(driftViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(driftViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const driftIdor = await mcpServer.executeTool('culkibo_drift_check', { projectId: projB.id }, { auth: scopedDevAuth });
    assert.strictEqual(driftIdor.isError, true);
    assert.strictEqual(JSON.parse(driftIdor.content[0].text).code, 'FORBIDDEN');

    const driftOk = await mcpServer.executeTool('culkibo_drift_check', {
      projectId: projA.id,
      actualInspect: driftedInspect,
      pgbouncerPreset: { name: 'pg-pool-main', databaseName: 'app', maxPreparedStatements: 200 }
    }, { auth: scopedDevAuth });
    assert.strictEqual(driftOk.isError, false);
    assert.strictEqual(driftOk.structuredContent.drift.drifted, true);
    assert.strictEqual(driftOk.structuredContent.drift.severity, 'critical');
    assert.strictEqual(driftOk.structuredContent.pgbouncerPreset.maxPreparedStatements, 200);
    assert.ok(driftOk.structuredContent.pgbouncerPreset.pgbouncerIni.includes('pool_mode = transaction'));
    assert.ok(!JSON.stringify(driftOk.structuredContent).includes('CANARY_C8_SECRET_9991'));
    console.log('  ✓ culkibo_drift_check verificado (kamal#1790 drift critical + PgBouncer preset + RBAC/anti-IDOR)');

    // 4. culkibo_export_iac (RO dev/admin, project ACL enforced, 0 plaintext canary secrets, audit redacted)
    const iacViewerBlocked = await mcpServer.executeTool('culkibo_export_iac', {}, { auth: viewerAuth });
    assert.strictEqual(iacViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(iacViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const iacIdor = await mcpServer.executeTool('culkibo_export_iac', { projectIds: [projB.id] }, { auth: scopedDevAuth });
    assert.strictEqual(iacIdor.isError, true);
    assert.strictEqual(JSON.parse(iacIdor.content[0].text).code, 'FORBIDDEN');

    const iacOk = await mcpServer.executeTool('culkibo_export_iac', { format: 'all' }, { auth: scopedDevAuth });
    assert.strictEqual(iacOk.isError, false);
    assert.strictEqual(iacOk.structuredContent.stats.projects, 1, 'culkibo_export_iac debe exportar solo proyectos del ACL del llamante');
    assert.ok(typeof iacOk.structuredContent.files['main.tf'] === 'string' && iacOk.structuredContent.files['main.tf'].includes('docker_container'));
    assert.ok(typeof iacOk.structuredContent.files['docker-compose.yml'] === 'string');
    assert.ok(typeof iacOk.structuredContent.files['.env.example'] === 'string');
    const serializedIac = JSON.stringify(iacOk.structuredContent);
    assert.ok(!serializedIac.includes('CANARY_C8_SECRET_9991'), 'IaC JAMÁS puede exportar secretos en claro');
    assert.ok(!serializedIac.includes('CANARY_FOREIGN_SECRET_8822'), 'IaC JAMÁS puede exportar proyectos ajenos');
    assert.strictEqual(mcpServer.getAuditLog(1)[0].resultSummary, '[resultado sensible ocultado en auditoría]');
    console.log('  ✓ culkibo_export_iac verificado (OpenTofu/Compose/.env.example, ACL estricto, 0 secretos en claro)');

    // 5. culkibo_secret_lease (admin RBAC, dryRun default on issue/revoke/break_glass, audit redaction, isolated CULKIBO_DATA_DIR)
    const leaseDevBlocked = await mcpServer.executeTool('culkibo_secret_lease', { action: 'list' }, { auth: scopedDevAuth });
    assert.strictEqual(leaseDevBlocked.isError, true);
    assert.strictEqual(JSON.parse(leaseDevBlocked.content[0].text).code, 'FORBIDDEN');

    // issue omitting dryRun -> safe dryRun: true (0 leases created!)
    const leaseDryIssue = await mcpServer.executeTool('culkibo_secret_lease', {
      action: 'issue',
      projectId: projA.id,
      secretKey: 'DATABASE_URL',
      ttlSec: 600
    });
    assert.strictEqual(leaseDryIssue.isError, false);
    assert.strictEqual(leaseDryIssue.structuredContent.dryRun, true);
    assert.strictEqual(leaseDryIssue.structuredContent.issued, false);

    // issue with dryRun: false -> returns one-time ckl_ token, redacted in auditLog!
    const leaseLiveIssue = await mcpServer.executeTool('culkibo_secret_lease', {
      action: 'issue',
      projectId: projA.id,
      secretKey: 'DATABASE_URL',
      ttlSec: 600,
      dryRun: false
    });
    assert.strictEqual(leaseLiveIssue.isError, false);
    assert.strictEqual(leaseLiveIssue.structuredContent.dryRun, false);
    assert.ok(typeof leaseLiveIssue.structuredContent.token === 'string' && leaseLiveIssue.structuredContent.token.startsWith('ckl_'));
    const leaseId = leaseLiveIssue.structuredContent.lease.id;
    assert.ok(!JSON.stringify(mcpServer.getAuditLog(1)[0]).includes(leaseLiveIssue.structuredContent.token), 'Token ckl_ jamás puede filtrarse al auditLog');

    // validateLease works before revoke and fails closed after revoke(dryRun: false)
    assert.strictEqual(secretLeaseService.validateLease(leaseLiveIssue.structuredContent.token).valid, true);
    const leaseRevDry = await mcpServer.executeTool('culkibo_secret_lease', { action: 'revoke', leaseId });
    assert.strictEqual(leaseRevDry.structuredContent.dryRun, true);
    assert.strictEqual(leaseRevDry.structuredContent.revoked, false);
    const leaseRevLive = await mcpServer.executeTool('culkibo_secret_lease', { action: 'revoke', leaseId, dryRun: false });
    assert.strictEqual(leaseRevLive.structuredContent.revoked, true);
    assert.strictEqual(secretLeaseService.validateLease(leaseLiveIssue.structuredContent.token).valid, false);

    // break_glass dryRun default + audit_rotation
    const bgDry = await mcpServer.executeTool('culkibo_secret_lease', {
      action: 'break_glass',
      reason: 'INC-808 emergency database failover drill',
      ttlSec: 3600
    });
    assert.strictEqual(bgDry.isError, false);
    assert.strictEqual(bgDry.structuredContent.dryRun, true);
    assert.ok(bgDry.structuredContent.wouldIssueBreakGlass.ttlSec <= 900, 'break_glass TTL debe acotarse a <=900s (15 min)');

    const rotAudit = await mcpServer.executeTool('culkibo_secret_lease', { action: 'audit_rotation', maxAgeDays: 90 });
    assert.strictEqual(rotAudit.isError, false);
    assert.ok(rotAudit.structuredContent.audit && typeof rotAudit.structuredContent.audit.totalKeys === 'number');
    console.log('  ✓ culkibo_secret_lease verificado (RBAC admin, dryRun default, ckl_ redactado, revoke fail-closed, break_glass <=15m)');

    // 6. Final Cycle-8 assertion: exact 125 tools & ?profile=core 17/125 >=84% reduction
    const all125 = mcpServer.getToolsForPrincipal(null, { profile: 'all' });
    const core17 = mcpServer.getToolsForPrincipal(null, { profile: 'core' });
    const saved125Pct = Math.round((1 - Buffer.byteLength(JSON.stringify(core17), 'utf8') / Buffer.byteLength(JSON.stringify(all125), 'utf8')) * 1000) / 10;
    assert.strictEqual(all125.length, 125);
    assert.strictEqual(core17.length, 17);
    assert.ok(saved125Pct >= 84, `?profile=core debe ahorrar >=84% tokens en 125 tools (actual: ${saved125Pct}%)`);
    console.log(`  ✓ Catálogo Cycle-8 verificado: 125 tools exactas, ?profile=core 17/125 (-${saved125Pct}% tokens/bytes)`);
  } finally {
    projectManager.delete(projA.id);
    projectManager.delete(projB.id);
    await projectManager.flushToDisk();
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpDataRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

module.exports = testMcp;

if (require.main === module) {
  testMcp()
    .then(() => {
      setTimeout(() => process.exit(0), 50);
    })
    .catch(err => {
      console.error('❌ MCP test failure:', err);
      process.exit(1);
    });
}
