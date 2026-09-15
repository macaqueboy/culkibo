const assert = require('assert');
const cloudflareService = require('../server/services/cloudflareService');

async function testCloudflare() {
  console.log('🧪 Testing Cloudflare Service...');

  // 1. Verify Token (Demo/Simulated mode)
  const tokenRes = await cloudflareService.verifyToken('demo_token');
  assert.strictEqual(tokenRes.valid, true, 'Token should be valid in demo mode');
  assert.strictEqual(tokenRes.status, 'active');
  console.log('  ✓ Token verification passed');

  // 2. List Zones
  const zonesRes = await cloudflareService.listZones();
  assert.strictEqual(zonesRes.success, true);
  assert.ok(zonesRes.zones.length >= 2, 'Should list at least 2 mock zones');
  const culkiboZone = zonesRes.zones.find(z => z.name === 'culkibo.dev');
  assert.ok(culkiboZone, 'culkibo.dev zone must exist');
  console.log(`  ✓ Zone listing passed (${zonesRes.zones.length} zones found)`);

  // 3. List DNS Records
  const dnsRes = await cloudflareService.listDnsRecords(culkiboZone.id);
  assert.strictEqual(dnsRes.success, true);
  assert.ok(dnsRes.records.length >= 2);
  console.log(`  ✓ DNS records list passed (${dnsRes.records.length} records)`);

  // 4. Create DNS Record
  const newRec = await cloudflareService.createDnsRecord(culkiboZone.id, {
    type: 'A',
    name: 'test-api.culkibo.dev',
    content: '142.250.180.206',
    proxied: true
  });
  assert.strictEqual(newRec.success, true);
  assert.strictEqual(newRec.record.name, 'test-api.culkibo.dev');
  assert.strictEqual(newRec.record.proxied, true);
  console.log('  ✓ DNS record creation passed');

  // 5. ACME DNS-01 TXT record creation
  const acmeRec = await cloudflareService.createAcmeTxtRecord(culkiboZone.id, 'culkibo.dev', 'test-token-acme-12345');
  assert.strictEqual(acmeRec.success, true);
  assert.strictEqual(acmeRec.record.type, 'TXT');
  assert.strictEqual(acmeRec.record.name, '_acme-challenge.culkibo.dev');
  console.log('  ✓ ACME DNS-01 TXT record injection passed');

  // 6. List Tunnels
  const tunRes = await cloudflareService.listTunnels();
  assert.strictEqual(tunRes.success, true);
  assert.ok(tunRes.tunnels.length >= 1, 'Should find at least 1 Cloudflare tunnel');
  console.log('  ✓ Cloudflare Tunnels check passed');

  console.log('✅ All Cloudflare tests passed!\n');
}

module.exports = testCloudflare;

if (require.main === module) {
  testCloudflare().catch(err => {
    console.error('❌ Cloudflare test failure:', err);
    process.exit(1);
  });
}
