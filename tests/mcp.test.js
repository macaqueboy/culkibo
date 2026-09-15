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

  console.log('✅ All MCP tests passed!\n');
}

/**
 * Las anotaciones son lo que un cliente usa para decidir si pide confirmación
 * a la persona usuaria. Una herramienta que muta marcada como `readOnlyHint`
 * hace que se ejecute sin preguntar, así que eso se fija aquí.
 */
async function testToolAnnotations() {
  const tools = mcpServer.getToolsDefinition();
  assert.strictEqual(tools.length, 26, 'El catálogo debe seguir teniendo 26 herramientas');

  for (const tool of tools) {
    assert.ok(tool.title, `${tool.name} debe declarar title`);
    assert.ok(tool.annotations, `${tool.name} debe declarar annotations`);
    assert.strictEqual(typeof tool.annotations.readOnlyHint, 'boolean', `${tool.name}.readOnlyHint`);
    assert.strictEqual(typeof tool.annotations.openWorldHint, 'boolean', `${tool.name}.openWorldHint`);
    if (tool.annotations.readOnlyHint) {
      // `destructiveHint` e `idempotentHint` solo significan algo cuando la
      // herramienta muta; declararlos en una de solo lectura es ruido.
      assert.strictEqual(tool.annotations.destructiveHint, undefined, `${tool.name} es de solo lectura y no debe declarar destructiveHint`);
    } else {
      assert.strictEqual(typeof tool.annotations.destructiveHint, 'boolean', `${tool.name}.destructiveHint`);
      assert.strictEqual(typeof tool.annotations.idempotentHint, 'boolean', `${tool.name}.idempotentHint`);
    }
  }

  const byName = Object.fromEntries(tools.map(t => [t.name, t]));
  const mustMutate = [
    'culkibo_create_project', 'culkibo_add_resource', 'culkibo_set_project_env',
    'culkibo_deploy_project', 'culkibo_hot_sync', 'culkibo_switch_traffic',
    'culkibo_manage_domain', 'culkibo_manage_watcher', 'culkibo_issue_wildcard_ssl',
    'culkibo_create_sslip_domain', 'culkibo_export_backup', 'culkibo_restore_backup',
    'culkibo_github_connect', 'culkibo_github_disconnect', 'culkibo_create_project_from_github'
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
    'culkibo_github_get_branches', 'culkibo_github_auto_detect'
  ];
  for (const name of mustBeReadOnly) {
    assert.strictEqual(byName[name].annotations.readOnlyHint, true, `${name} no muta nada`);
  }

  // Las que hablan con un tercero tienen que declararlo: de ahí depende la
  // clasificación de sus fallos como reintentables.
  assert.strictEqual(byName.culkibo_github_list_repos.annotations.openWorldHint, true);
  assert.strictEqual(byName.culkibo_issue_wildcard_ssl.annotations.openWorldHint, true);
  assert.strictEqual(byName.culkibo_list_pods.annotations.openWorldHint, false);

  assert.ok(byName.culkibo_list_pods.outputSchema, 'culkibo_list_pods debe declarar outputSchema');
  console.log(`  ✓ Anotaciones verificadas en las 26 herramientas (${tools.filter(t => t.annotations.readOnlyHint).length} de solo lectura, ${tools.filter(t => t.annotations.destructiveHint).length} destructivas)`);
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
  const apiRouter = require('../server/routes/api');

  const app = express();
  app.use(express.json({ limit: '10mb' }));
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
    assert.strictEqual(list.result.tools.length, 26);
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

    // 12. Método desconocido -> 404 con -32601, que es lo que distingue a un
    //     servidor moderno de un 404 de servidor legado.
    const unknownRes = await post(
      { 'MCP-Protocol-Version': V, 'Mcp-Method': 'resources/list' },
      { jsonrpc: '2.0', id: 'unk-1', method: 'resources/list', params: { _meta: meta() } }
    );
    assert.strictEqual(unknownRes.status, 404);
    const unknown = await unknownRes.json();
    assert.strictEqual(unknown.error.code, -32601);
    assert.ok(unknown.error.data.supported.includes('server/discover'));
    console.log('  ✓ Método no implementado -> 404 con -32601 y la lista de métodos');

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
