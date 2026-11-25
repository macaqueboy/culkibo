const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const { SslManager } = require('../server/services/sslManager');
const { DomainManager } = require('../server/services/domainManager');
const { IngressManager } = require('../server/services/ingressManager');

// ── Generador DER X.509 v3 puro en Node (0 dependencias externas / sin openssl) ──
const DER = {
  len(n) {
    if (n < 0x80) return Buffer.from([n]);
    const bytes = [];
    let v = n;
    while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); }
    return Buffer.from([0x80 | bytes.length, ...bytes]);
  },
  tlv(tag, content) {
    return Buffer.concat([Buffer.from([tag]), DER.len(content.length), content]);
  },
  seq: (...parts) => DER.tlv(0x30, Buffer.concat(parts)),
  set: (...parts) => DER.tlv(0x31, Buffer.concat(parts)),
  int(buf) {
    let b = Buffer.from(buf);
    while (b.length > 1 && b[0] === 0) b = b.subarray(1);
    if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
    return DER.tlv(0x02, b);
  },
  oid(dotted) {
    const parts = dotted.split('.').map(Number);
    const bytes = [parts[0] * 40 + parts[1]];
    for (let i = 2; i < parts.length; i++) {
      let v = parts[i];
      const stack = [v & 0x7f];
      v = Math.floor(v / 128);
      while (v > 0) { stack.unshift((v & 0x7f) | 0x80); v = Math.floor(v / 128); }
      bytes.push(...stack);
    }
    return DER.tlv(0x06, Buffer.from(bytes));
  },
  utf8: (s) => DER.tlv(0x0c, Buffer.from(s, 'utf8')),
  utcTime(date) {
    const p = (n) => String(n).padStart(2, '0');
    const s = `${p(date.getUTCFullYear() % 100)}${p(date.getUTCMonth() + 1)}${p(date.getUTCDate())}` +
              `${p(date.getUTCHours())}${p(date.getUTCMinutes())}${p(date.getUTCSeconds())}Z`;
    return DER.tlv(0x17, Buffer.from(s, 'ascii'));
  }
};

function makeRealCertKeyPair({
  cn = 'prueba-real.dev',
  dnsNames = ['prueba-real.dev'],
  ipBytes = [],
  uris = [],
  notBeforeOffsetDays = -1,
  days = 30
} = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = publicKey.export({ type: 'spki', format: 'der' });

  const ecdsaSha256 = DER.seq(DER.oid('1.2.840.10045.4.3.2'));
  const name = DER.seq(DER.set(DER.seq(Buffer.concat([DER.oid('2.5.4.3'), DER.utf8(cn)]))));
  const notBefore = new Date(Date.now() + notBeforeOffsetDays * 86400000);
  const notAfter = new Date(Date.now() + days * 86400000);

  const sanItems = [
    ...dnsNames.map((d) => DER.tlv(0x82, Buffer.from(d, 'ascii'))),
    ...uris.map((u) => DER.tlv(0x86, Buffer.from(u, 'ascii'))),
    ...ipBytes.map((octets) => DER.tlv(0x87, Buffer.from(octets)))
  ];
  const sanExt = DER.seq(Buffer.concat([
    DER.oid('2.5.29.17'),
    DER.tlv(0x04, DER.seq(Buffer.concat(sanItems)))
  ]));

  const tbs = DER.seq(
    DER.tlv(0xa0, DER.int(Buffer.from([2]))),
    DER.int(crypto.randomBytes(8)),
    ecdsaSha256,
    name,
    DER.seq(DER.utcTime(notBefore), DER.utcTime(notAfter)),
    name,
    spki,
    DER.tlv(0xa3, DER.seq(sanExt))
  );

  const signature = crypto.sign('sha256', tbs, privateKey);
  const der = DER.seq(tbs, ecdsaSha256, DER.tlv(0x03, Buffer.concat([Buffer.from([0]), signature])));
  const b64 = (der.toString('base64').match(/.{1,64}/g) || []).join('\n');
  return {
    certPem: `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`,
    keyPem: String(privateKey.export({ type: 'pkcs8', format: 'pem' }))
  };
}

async function testSsl() {
  console.log('🧪 Testing SSL Manager (aislado en tmpdir + X.509 adversarial + alertas dedup/untrusted)...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-ssl-test-'));
  const certsDir = path.join(tmpDir, 'certs');
  try {
    const sslMgr = new SslManager({ certsDir });

    // 1. Un PEM fabricado nunca se publica ni sobrevive al recargar el registro
    const fakeDir = path.join(certsDir, 'prueba-falsa.dev');
    fs.mkdirSync(fakeDir, { recursive: true });
    const fakeCertPath = path.join(fakeDir, 'fullchain.pem');
    const fakeKeyPath = path.join(fakeDir, 'privkey.pem');
    fs.writeFileSync(
      fakeCertPath,
      `-----BEGIN CERTIFICATE-----\nMIICrDCCAZSgAwIBAgIU${crypto.randomBytes(32).toString('base64')}\n-----END CERTIFICATE-----`,
      'utf8'
    );
    fs.writeFileSync(fakeKeyPath, 'no-es-una-clave', 'utf8');

    sslMgr.registry.unshift({
      id: 'cert_falso_de_prueba',
      domain: '*.prueba-falsa.dev',
      rootDomain: 'prueba-falsa.dev',
      type: 'wildcard_dns01',
      provider: 'lets_encrypt',
      issuer: "Let's Encrypt Authority R3",
      sans: ['*.prueba-falsa.dev', 'prueba-falsa.dev'],
      status: 'active',
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000 * 90).toISOString(),
      fingerprint: 'AA:BB:CC',
      keyType: 'ECDSA (P-256)',
      certPath: fakeCertPath,
      keyPath: fakeKeyPath
    });

    assert.ok(!sslMgr.listCertificates().some((c) => c.id === 'cert_falso_de_prueba'));
    assert.ok(!sslMgr.getCertificateByDomain('api.prueba-falsa.dev'));

    // Recarga limpia del registro en disco: borra el PEM fabricado de disco
    fs.writeFileSync(path.join(certsDir, 'registry.json'), JSON.stringify([
      { id: 'cert_residuo', domain: '*.prueba-falsa.dev', rootDomain: 'prueba-falsa.dev', certPath: fakeCertPath, keyPath: fakeKeyPath }
    ], null, 2), 'utf8');
    const reloaded = new SslManager({ certsDir });
    assert.strictEqual(reloaded.listCertificates().length, 0);
    assert.ok(!fs.existsSync(fakeCertPath), 'El PEM fabricado debe borrarse del disco');
    assert.ok(!fs.existsSync(fakeKeyPath), 'La clave huérfana también debe borrarse');
    console.log('  ✓ Purga de PEMs fabricados en memoria y en disco verificada (aislada)');

    // 2. Parseo positivo estricto de X.509 real (sin omisión silenciosa) + filtrado de SANs no-DNS
    const mixedSanPair = makeRealCertKeyPair({
      cn: '*.cert-real.test',
      dnsNames: ['*.cert-real.test', 'cert-real.test'],
      ipBytes: [[192, 0, 2, 10]],
      uris: ['https://spiffe.example/id'],
      days: 60
    });
    const parsedDirect = new crypto.X509Certificate(mixedSanPair.certPem);
    assert.ok(parsedDirect.fingerprint256, 'El X.509 generado debe parsear siempre en Node');

    // 3. uploadCustomCertificate: validaciones adversariales
    // 3a. Clave privada no coincidente -> rechazada
    const otherPair = makeRealCertKeyPair({ cn: 'other.test', dnsNames: ['other.test'], days: 60 });
    assert.throws(
      () => reloaded.uploadCustomCertificate({ domain: '*.cert-real.test', certPem: mixedSanPair.certPem, keyPem: otherPair.keyPem }),
      /clave privada no coincide/i
    );

    // 3b. Certificado caducado -> rechazado
    const expiredPair = makeRealCertKeyPair({ cn: 'expired.test', dnsNames: ['expired.test'], notBeforeOffsetDays: -30, days: -2 });
    assert.throws(
      () => reloaded.uploadCustomCertificate({ domain: 'expired.test', certPem: expiredPair.certPem, keyPem: expiredPair.keyPem }),
      /caducado/i
    );

    // 3c. Certificado futuro (todavía no válido) -> rechazado
    const futurePair = makeRealCertKeyPair({ cn: 'future.test', dnsNames: ['future.test'], notBeforeOffsetDays: 10, days: 90 });
    assert.throws(
      () => reloaded.uploadCustomCertificate({ domain: 'future.test', certPem: futurePair.certPem, keyPem: futurePair.keyPem }),
      /todavía no es válido/i
    );

    // 3d. Dominio explícito no cubierto por SANs -> rechazado
    assert.throws(
      () => reloaded.uploadCustomCertificate({ domain: 'evil.other.test', certPem: mixedSanPair.certPem, keyPem: mixedSanPair.keyPem }),
      /no cubre el dominio/i
    );

    // 3e. Cadena invertida [intermedio, hoja] -> reordenada automáticamente con la hoja primero y SANs no-DNS filtrados
    const reversedChainPem = `${otherPair.certPem}\n${mixedSanPair.certPem}`;
    const uploaded = reloaded.uploadCustomCertificate({
      domain: '*.cert-real.test',
      certPem: reversedChainPem,
      keyPem: mixedSanPair.keyPem,
      provider: 'cloudflare_origin_ca'
    });
    assert.strictEqual(uploaded.success, true);
    assert.strictEqual(uploaded.cert.status, 'on_disk');
    assert.strictEqual(uploaded.cert.verified, true);
    assert.strictEqual(uploaded.cert.type, 'custom_wildcard');
    assert.deepStrictEqual(uploaded.cert.sans, ['*.cert-real.test', 'cert-real.test'], 'SANs no-DNS (IP/URI) deben filtrarse');

    // Verificar que fullchain.pem en disco tiene la hoja como primer bloque
    const savedBlocks = fs.readFileSync(uploaded.cert.certPath, 'utf8')
      .match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
    assert.strictEqual(savedBlocks.length, 2);
    assert.strictEqual(
      new crypto.X509Certificate(savedBlocks[0]).fingerprint256,
      parsedDirect.fingerprint256,
      'La hoja que coincide con la clave privada debe guardarse primero en fullchain.pem'
    );

    // Verificar listCaddyLoadFiles con containerMountPrefix
    const mounted = reloaded.listCaddyLoadFiles({ containerMountPrefix: '/etc/culkibo-certs' });
    assert.strictEqual(mounted.length, 1);
    assert.ok(mounted[0].certificate.startsWith('/etc/culkibo-certs/custom_cert-real.test_'));

    // 3f. RFC 6125 single-label wildcard matching en matchCertificate
    assert.ok(reloaded.getCertificateByDomain('api.cert-real.test'), 'api.cert-real.test debe coincidir con *.cert-real.test');
    assert.strictEqual(
      reloaded.getCertificateByDomain('a.b.cert-real.test'),
      undefined,
      'RFC 6125: subdominio multinivel a.b.cert-real.test NO debe coincidir con *.cert-real.test'
    );
    console.log('  ✓ uploadCustomCertificate adversarial (mismatch, expired, future, SAN mismatch, cadena invertida, RFC 6125)');

    // 4. Registro de host bajo demanda (sslip/nip.io): 0 PEMs escritos y campos null
    const beforeFiles = new Set(fs.readdirSync(certsDir));
    const sslipRes = await reloaded.issueOnDemandSslip({ ip: '192.168.1.100', service: 'nip.io' });
    assert.strictEqual(sslipRes.success, true);
    assert.strictEqual(sslipRes.cert.status, 'delegated');
    assert.strictEqual(sslipRes.cert.expiresAt, null);
    assert.strictEqual(sslipRes.cert.certPath, null);
    const createdFiles = fs.readdirSync(certsDir).filter((f) => !beforeFiles.has(f) && f !== 'registry.json' && !f.endsWith('.bak'));
    assert.deepStrictEqual(createdFiles, []);
    await assert.rejects(() => reloaded.issueOnDemandSslip({ ip: 'not-an-ip' }), /inválida/i);
    await assert.rejects(() => reloaded.issueOnDemandSslip({ ip: '1.2.3.4', service: 'evil.io' }), /no soportado/i);
    console.log('  ✓ On-demand sslip/nip.io sin PEMs inventados y validación estricta');

    // 5. issueWildcardCertificate honesto + lista de 7 proveedores DNS-01 soportados en Caddy
    const progress = [];
    const wcRes = await reloaded.issueWildcardCertificate({
      domain: '*.cloud-test.dev',
      zoneId: 'cf_zone_1',
      onProgress: (p) => progress.push(p.stage)
    });
    assert.strictEqual(wcRes.success, false);
    assert.strictEqual(wcRes.implemented, false);
    assert.strictEqual(wcRes.code, 'WILDCARD_ACME_NO_IMPLEMENTADO');
    assert.deepStrictEqual(progress, ['no_implementado']);
    assert.ok(Array.isArray(wcRes.supportedDnsProviders) && wcRes.supportedDnsProviders.includes('hetzner'));
    assert.ok(wcRes.supportedDnsProviders.includes('porkbun') && wcRes.supportedDnsProviders.includes('route53'));
    console.log('  ✓ issueWildcardCertificate honesto y actualizado con 7 proveedores DNS-01');

    // 6. checkCertificateExpiry: deduplicación on_disk+live y alertas de certificado no confiable/mismatched
    const expiringPair = makeRealCertKeyPair({ cn: 'soon.cert.test', dnsNames: ['soon.cert.test'], days: 5 });
    reloaded.uploadCustomCertificate({ domain: 'soon.cert.test', certPem: expiringPair.certPem, keyPem: expiringPair.keyPem });

    const isoDm = new DomainManager({ dataDir: tmpDir, seedDefaults: false, sslManager: reloaded });
    await isoDm.addDomain({ hostname: 'soon.cert.test', targetPod: 'citadel', targetPort: 8080 });
    await isoDm.addDomain({ hostname: 'broken-san.cert.test', targetPod: 'citadel', targetPort: 8080 });

    /** @type {any[]} */
    const sentAlerts = [];
    const mockNotifier = {
      async notify(payload) { sentAlerts.push(payload); }
    };
    const mockCaddy = {
      isContainerized: false,
      async detect() { return { available: true, adminUrl: 'http://127.0.0.1:2019', version: 'activo', reason: null }; }
    };
    const isoIm = new IngressManager({
      dataDir: tmpDir,
      caddyManager: mockCaddy,
      domainManager: isoDm,
      sslManager: reloaded,
      notificationService: mockNotifier
    });
    // Simular probeTls en vivo: soon.cert.test (también on_disk -> debe deduplicarse!) y broken-san.cert.test (no confiable)
    isoIm.probeTls = async (host) => {
      if (host === 'soon.cert.test') {
        return {
          hostname: host,
          reachable: true,
          expired: false,
          daysRemaining: 5,
          notAfter: new Date(Date.now() + 5 * 86400000).toISOString(),
          issuer: 'Test CA',
          trusted: true,
          trustError: null
        };
      }
      return {
        hostname: host,
        reachable: true,
        expired: false,
        daysRemaining: 60,
        notAfter: new Date(Date.now() + 60 * 86400000).toISOString(),
        issuer: 'Wrong Cert CA',
        trusted: false,
        trustError: 'El certificado servido pertenece a otro dominio.'
      };
    };

    const audit1 = await isoIm.checkCertificateExpiry({ warnDays: 14, probeLive: true });
    assert.strictEqual(audit1.expiring.filter((e) => e.hostname === 'soon.cert.test').length, 1, 'Debe deduplicar soon.cert.test entre on_disk y live');
    assert.strictEqual(audit1.untrusted.length, 1, 'Debe detectar broken-san.cert.test como certificado no confiable');
    assert.strictEqual(audit1.untrusted[0].hostname, 'broken-san.cert.test');
    assert.strictEqual(sentAlerts.length, 2, 'Debe emitir exactamente 1 alerta de expiración + 1 alerta de untrusted');

    // Segunda ejecución inmediata: deduplicación 24h impide spam
    await isoIm.checkCertificateExpiry({ warnDays: 14, probeLive: true });
    assert.strictEqual(sentAlerts.length, 2, 'Cooldown 24h debe evitar alertas duplicadas');
    console.log('  ✓ checkCertificateExpiry deduplica on_disk+live y alerta sobre certs untrusted/SAN-mismatch');

    console.log('✅ All SSL tests passed!\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

module.exports = testSsl;

if (require.main === module) {
  testSsl().catch((err) => {
    console.error('❌ SSL test failure:', err);
    process.exit(1);
  });
}
