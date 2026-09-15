const assert = require('assert');
const domainManager = require('../server/services/domainManager');

async function testDomain() {
  console.log('🧪 Testing Domain Manager & Routing Engine...');

  // 1. List Domains
  const domains = domainManager.listDomains();
  assert.ok(Array.isArray(domains));
  assert.ok(domains.length >= 2, 'Initial domains must exist');
  console.log(`  ✓ Domain listing passed (${domains.length} domains)`);

  // 2. Add Domain
  const uniqueName = `test-${Date.now()}.culkibo.dev`;
  const added = await domainManager.addDomain({
    hostname: uniqueName,
    targetPod: 'forge',
    targetPort: 3001,
    cloudflareProxied: true
  });
  assert.strictEqual(added.hostname, uniqueName);
  assert.strictEqual(added.targetPod, 'forge');
  console.log(`  ✓ Add domain passed (${uniqueName})`);

  // 3. Duplicate domain prevention
  await assert.rejects(async () => {
    await domainManager.addDomain({ hostname: uniqueName });
  }, /already configured/);
  console.log('  ✓ Duplicate prevention rejected properly');

  // 4. Resolve Route (Exact vs Wildcard + Port Stripping + Case Insensitivity)
  const exactRoute = domainManager.resolveRoute('CULKIBO.DEV:3030');
  assert.ok(exactRoute);
  assert.strictEqual(exactRoute.hostname, 'culkibo.dev');

  const wildcardRoute = domainManager.resolveRoute('SubDomain.Culkibo.Dev:443');
  assert.ok(wildcardRoute);
  assert.strictEqual(wildcardRoute.isWildcard, true);
  console.log('  ✓ Route resolution (exact + wildcard + port normalization) passed');

  // 4b. Regression: a wildcard route must respect the label boundary.
  // `*.culkibo.dev` previously matched `evilculkibo.dev` via a bare endsWith(),
  // letting an unrelated host hijack another tenant's ingress rule.
  const hijackAttempt = domainManager.resolveRoute('evilculkibo.dev');
  assert.strictEqual(hijackAttempt, null, 'evilculkibo.dev must NOT match *.culkibo.dev');
  const hijackAttempt2 = domainManager.resolveRoute('notculkibo.dev:443');
  assert.strictEqual(hijackAttempt2, null, 'notculkibo.dev must NOT match *.culkibo.dev');
  const legitSub = domainManager.resolveRoute('app.culkibo.dev');
  assert.ok(legitSub && legitSub.isWildcard, 'app.culkibo.dev must still match the wildcard');
  console.log('  ✓ Wildcard label-boundary enforcement passed (no cross-domain hijack)');

  // 5. Toggle Proxy
  const toggled = await domainManager.toggleProxy(added.id);
  assert.strictEqual(toggled.cloudflareProxied, false);
  const toggledBack = await domainManager.toggleProxy(added.id);
  assert.strictEqual(toggledBack.cloudflareProxied, true);
  console.log('  ✓ Toggle Cloudflare proxy passed');

  // 6. Update Domain target pod
  const updated = await domainManager.updateDomain(added.id, { targetPod: 'citadel', targetPort: 8080 });
  assert.strictEqual(updated.targetPod, 'citadel');
  assert.strictEqual(updated.targetPort, 8080);
  console.log('  ✓ Update domain routing pod passed');

  // 7. Delete Domain
  const deleted = await domainManager.deleteDomain(added.id);
  assert.strictEqual(deleted.id, added.id);
  console.log('  ✓ Delete domain passed');

  // 6. Verify DNS format check
  const dnsRes = await domainManager.verifyDns('culkibo.dev');
  assert.ok(dnsRes.hostname);
  assert.ok(typeof dnsRes.lookupDurationMs === 'number');
  console.log('  ✓ DNS verification engine check passed');

  console.log('✅ All Domain tests passed!\n');
}

module.exports = testDomain;

if (require.main === module) {
  testDomain().catch(err => {
    console.error('❌ Domain test failure:', err);
    process.exit(1);
  });
}
