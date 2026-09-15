const assert = require('assert');
const http = require('http');
const { app, server } = require('../server/index');
const containerOrchestrator = require('../server/services/containerOrchestrator');

async function testLiveServer() {
  console.log('🧪 Testing Live Server & Ingress Reverse Router...');

  await new Promise((resolve) => {
    server.listen(3031, () => {
      resolve();
    });
  });

  try {
    // 1. Fetch system status
    const statusRes = await fetch('http://localhost:3031/api/system/status');
    const statusData = await statusRes.json();
    assert.strictEqual(statusData.version, '1.0.0');
    assert.strictEqual(statusData.name, 'Culkibo');
    console.log('  ✓ API /api/system/status responding with v1.0.0');

    // 2. Fetch root / (Dashboard HTML on direct access)
    const indexRes = await fetch('http://localhost:3031/');
    const htmlText = await indexRes.text();
    assert.ok(htmlText.includes('Culkibo'), 'Must serve built Vite index.html');
    assert.ok(htmlText.includes('assets/index-'), 'Must reference built bundle assets');
    console.log('  ✓ Web Dashboard HTML served from web/dist for management origin');

    // 3. Test Ingress reverse-proxy routing with x-forwarded-host: culkibo.dev
    const ingressRes = await fetch('http://localhost:3031/', {
      headers: {
        'x-forwarded-host': 'culkibo.dev',
        'Accept': 'application/json'
      }
    });
    const ingressData = await ingressRes.json();
    assert.strictEqual(ingressData.domain, 'culkibo.dev');
    assert.ok(ingressData.routedPod === 'forge' || ingressData.routedPod === 'citadel');
    assert.strictEqual(ingressRes.headers.get('x-culkibo-ingress'), '1');
    console.log(`  ✓ Edge Ingress reverse router routed culkibo.dev -> Pod [${ingressData.routedPod}]`);

    // 4. Test Wildcard Ingress routing with x-forwarded-host: preview.culkibo.dev
    const wildcardRes = await fetch('http://localhost:3031/', {
      headers: {
        'x-forwarded-host': 'preview.culkibo.dev',
        'Accept': 'application/json'
      }
    });
    const wildcardData = await wildcardRes.json();
    assert.strictEqual(wildcardData.domain, 'preview.culkibo.dev');
    assert.strictEqual(wildcardRes.headers.get('x-culkibo-ingress'), '1');
    console.log(`  ✓ Wildcard Ingress router routed preview.culkibo.dev -> Pod [${wildcardData.routedPod}]`);

    // 5. Fetch domains API & test PATCH update
    const domRes = await fetch('http://localhost:3031/api/domains');
    const domData = await domRes.json();
    assert.ok(domData.domains.length >= 2);
    const testDomId = domData.domains[0].id;

    // Toggle proxy via API
    const toggleRes = await fetch(`http://localhost:3031/api/domains/${testDomId}/toggle-proxy`, {
      method: 'POST'
    });
    const toggleData = await toggleRes.json();
    assert.strictEqual(toggleData.id, testDomId);
    console.log(`  ✓ API /api/domains/:id/toggle-proxy executed successfully (proxied: ${toggleData.cloudflareProxied})`);

    // 6. Fetch MCP tools API
    const mcpRes = await fetch('http://localhost:3031/api/mcp/tools');
    const mcpData = await mcpRes.json();
    assert.ok(mcpData.tools.length >= 7);
    console.log(`  ✓ API /api/mcp/tools responding (${mcpData.tools.length} AI tools)`);

    // 7. Live GitHub API endpoints
    const ghStatusRes = await fetch('http://localhost:3031/api/github/status');
    const ghStatusData = await ghStatusRes.json();
    assert.ok('connected' in ghStatusData);
    console.log('  ✓ API /api/github/status responding');

    const ghConnectRes = await fetch('http://localhost:3031/api/github/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'ghp_mock_live_test_token' })
    });
    const ghConnectData = await ghConnectRes.json();
    assert.strictEqual(ghConnectData.success, true);
    assert.strictEqual(ghConnectData.user.login, 'pablo-developer');
    console.log('  ✓ API /api/github/connect executed successfully');

    const ghReposRes = await fetch('http://localhost:3031/api/github/repos');
    const ghReposData = await ghReposRes.json();
    assert.ok(Array.isArray(ghReposData.repos));
    assert.ok(ghReposData.repos.length >= 3);
    console.log(`  ✓ API /api/github/repos responding with ${ghReposData.repos.length} repositories`);

    const ghDetectRes = await fetch('http://localhost:3031/api/github/auto-detect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ owner: 'pablo-developer', repo: 'culkibo-frontend', branch: 'main' })
    });
    const ghDetectData = await ghDetectRes.json();
    assert.strictEqual(ghDetectData.detected, true);
    assert.strictEqual(ghDetectData.framework, 'React (Vite)');
    console.log('  ✓ API /api/github/auto-detect responding with detected stack');

    console.log('✅ Live Server, Ingress Router, Static Dashboard & GitHub APIs verified successfully!\n');
  } finally {
    await containerOrchestrator.stop();
    await new Promise((resolve) => server.close(resolve));
  }
}


testLiveServer()
  .then(() => {
    setTimeout(() => process.exit(0), 50);
  })
  .catch(err => {
    console.error('❌ Live server test failed:', err);
    process.exit(1);
  });
