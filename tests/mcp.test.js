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

  console.log('✅ All MCP tests passed!\n');
}

module.exports = testMcp;

if (require.main === module) {
  testMcp().catch(err => {
    console.error('❌ MCP test failure:', err);
    process.exit(1);
  });
}
