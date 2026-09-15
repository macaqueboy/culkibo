const assert = require('assert');
const sslManager = require('../server/services/sslManager');

async function testSsl() {
  console.log('🧪 Testing SSL Manager & Wildcard ACME Engine...');

  // 1. List certificates & expiry calculation
  const certs = sslManager.listCertificates();
  assert.ok(Array.isArray(certs), 'Should return an array of certificates');
  assert.ok(certs.length >= 2, 'Should have initial seed certificates');
  const firstCert = certs[0];
  assert.ok(typeof firstCert.daysRemaining === 'number', 'Must calculate days remaining');
  assert.ok(firstCert.daysRemaining > 0, 'Days remaining should be positive');
  console.log(`  ✓ Cert listing & days calculation passed (${certs.length} certs)`);

  // 2. Wildcard domain matching
  const matched = sslManager.getCertificateByDomain('api.culkibo.dev');
  assert.ok(matched, 'Wildcard *.culkibo.dev should match api.culkibo.dev');
  assert.strictEqual(matched.rootDomain, 'culkibo.dev');
  console.log('  ✓ Wildcard domain matching passed');

  // 3. Issue On-Demand TLS for sslip.io
  const sslipRes = await sslManager.issueOnDemandSslip({ ip: '192.168.1.100', service: 'nip.io' });
  assert.strictEqual(sslipRes.success, true);
  assert.strictEqual(sslipRes.cert.rootDomain, '192-168-1-100.nip.io');
  assert.strictEqual(sslipRes.cert.type, 'ondemand_tls');
  console.log('  ✓ Zero-Config On-Demand TLS generation passed');

  // 4. Issue Wildcard certificate with ACME DNS-01 stages
  const progressStages = [];
  const wildcardRes = await sslManager.issueWildcardCertificate({
    domain: '*.cloud-test.dev',
    zoneId: 'cf_zone_mock_1',
    provider: 'lets_encrypt',
    onProgress: (p) => progressStages.push(p.stage)
  });

  assert.strictEqual(wildcardRes.success, true);
  assert.strictEqual(wildcardRes.cert.domain, '*.cloud-test.dev');
  assert.ok(progressStages.includes('generating_keys'));
  assert.ok(progressStages.includes('configuring_dns'));
  assert.ok(progressStages.includes('installed'));
  console.log(`  ✓ ACME DNS-01 Wildcard issuance passed through stages: ${progressStages.join(' -> ')}`);

  console.log('✅ All SSL tests passed!\n');
}

module.exports = testSsl;

if (require.main === module) {
  testSsl().catch(err => {
    console.error('❌ SSL test failure:', err);
    process.exit(1);
  });
}
