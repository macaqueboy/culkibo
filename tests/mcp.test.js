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
  console.log('  ✓ MCP JSON-RPC initialize handshake passed');

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

  // 12. MCP 2.0: 104 herramientas, 7 recursos, 5 prompts, dryRun universal, RBAC y anti-IDOR
  await testMcpV2Capabilities();

  console.log('✅ All MCP tests passed!\n');
}

/**
 * Las anotaciones son lo que un cliente usa para decidir si pide confirmación
 * a la persona usuaria. Una herramienta que muta marcada como `readOnlyHint`
 * hace que se ejecute sin preguntar, así que eso se fija aquí.
 */
async function testToolAnnotations() {
  const tools = mcpServer.getToolsDefinition();
  assert.strictEqual(tools.length, 104, 'El catálogo MCP 2.0 debe tener exactamente 104 herramientas anotadas');
  const uniqueNames = new Set(tools.map(t => t.name));
  assert.strictEqual(uniqueNames.size, 104, 'No puede haber nombres de herramientas duplicados');

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
  assert.strictEqual(roCount, 46, `Se esperaban 46 herramientas RO, hay ${roCount}`);
  assert.strictEqual(mutCount, 58, `Se esperaban 58 herramientas mutadoras, hay ${mutCount}`);
  assert.strictEqual(destCount, 25, `Se esperaban 25 herramientas destructivas, hay ${destCount}`);
  assert.strictEqual(dryRunCount, 27, `Se esperaban 27 herramientas con dryRun, hay ${dryRunCount}`);

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

    // 7. tools/list sobre el transporte nuevo.
    const listRes = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'tools/list' },
      { jsonrpc: '2.0', id: 'list-1', method: 'tools/list', params: { _meta: meta() } }
    );
    const list = await listRes.json();
    assert.strictEqual(list.result.resultType, 'complete');
    assert.strictEqual(list.result.tools.length, 104);
    console.log(`  ✓ tools/list sobre Streamable HTTP (${list.result.tools.length} herramientas)`);

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

  // 1. 7 Recursos y 5 Prompts
  const resources = mcpServer.listResources();
  assert.strictEqual(resources.length, 7, `Se esperaban 7 recursos MCP, hay ${resources.length}`);
  for (const uri of ['culkibo://projects', 'culkibo://pods', 'culkibo://doctor', 'culkibo://domains', 'culkibo://fleet', 'culkibo://uptime', 'culkibo://environments']) {
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
  assert.strictEqual(prompts.length, 5, `Se esperaban 5 prompts MCP, hay ${prompts.length}`);
  for (const name of ['debug-failed-deploy', 'zero-downtime-release', 'audit-security-tls', 'culkibo_multi_server_rollout', 'culkibo_incident_triage']) {
    assert.ok(prompts.some(p => p.name === name), `Falta prompt ${name}`);
  }
  const rolloutPrompt = mcpServer.getPrompt('culkibo_multi_server_rollout', { projectId: 'proj_demo', targetServers: 'srv_eu' });
  assert.ok(rolloutPrompt.messages[0].content.text.includes('culkibo_canary_rollout'));
  const triagePrompt = mcpServer.getPrompt('culkibo_incident_triage', { projectId: 'proj_demo', hostname: 'app.demo.test' });
  assert.ok(triagePrompt.messages[0].content.text.includes('culkibo_cost_advisor'));
  console.log('  ✓ MCP 2.0: 7 recursos y 5 prompts verificados');

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
    assert.ok(viewerTools.length > 0 && viewerTools.length < 104);
    assert.ok(viewerTools.every(t => t.annotations.readOnlyHint === true), 'viewer solo puede ver herramientas readOnly');
    assert.ok(!viewerTools.some(t => t.name === 'culkibo_database_credentials'), 'viewer NO puede ver culkibo_database_credentials');
    assert.ok(!viewerTools.some(t => t.name === 'culkibo_rbac_list_tokens'), 'viewer NO puede ver culkibo_rbac_list_tokens');

    // Serialized tools cache isolation
    const pubBuf = mcpServer.getToolsSerialized();
    const privBuf = mcpServer.getToolsSerialized(viewerAuth);
    assert.strictEqual(JSON.parse(pubBuf.toString('utf8')).count, 104);
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
    assert.strictEqual(whoamiSuper.structuredContent.allowedToolsCount, 104);

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
