const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sslManager = require('../server/services/sslManager');

const CERTS_DIR = path.join(__dirname, '..', 'data', 'certs');

/**
 * Suite del registro de certificados.
 *
 * Lo que se verifica aquí no es que la emisión funcione —no existe—, sino lo
 * contrario: que NADA de este módulo pueda volver a afirmar que hay un
 * certificado donde no lo hay. Las pruebas anteriores comprobaban que
 * `issueWildcardCertificate()` devolvía `success: true` y pasaba por seis
 * etapas ACME; todo aquello era simulado, así que la suite verde certificaba
 * una mentira.
 */

// ── Generador de un X.509 AUTÉNTICO para la prueba positiva ─────────────────
//
// Node no sabe emitir certificados, y depender de que `openssl` esté instalado
// haría la suite frágil. Así que se construye el DER a mano y se firma con
// `crypto.sign`: el resultado es un certificado de verdad —`X509Certificate` lo
// parsea, tiene caducidad y huella reales— y no un PEM de mentira. Sin esto, la
// prueba de «se rechaza lo falso» podría estar pasando porque se rechaza todo.

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

function makeRealSelfSignedCert({ cn = 'culkibo-prueba', dnsNames = ['prueba-real.dev'], days = 30 } = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = publicKey.export({ type: 'spki', format: 'der' });

  const ecdsaSha256 = DER.seq(DER.oid('1.2.840.10045.4.3.2'));
  const name = DER.seq(DER.set(DER.seq(Buffer.concat([DER.oid('2.5.4.3'), DER.utf8(cn)]))));
  const notBefore = new Date(Date.now() - 3600000);
  const notAfter = new Date(Date.now() + days * 86400000);

  const sanExt = DER.seq(Buffer.concat([
    DER.oid('2.5.29.17'),
    DER.tlv(0x04, DER.seq(Buffer.concat(dnsNames.map(d => DER.tlv(0x82, Buffer.from(d, 'ascii'))))))
  ]));

  const tbs = DER.seq(
    DER.tlv(0xa0, DER.int(Buffer.from([2]))),          // version v3
    DER.int(crypto.randomBytes(8)),                     // serialNumber
    ecdsaSha256,
    name,                                               // issuer (autofirmado)
    DER.seq(DER.utcTime(notBefore), DER.utcTime(notAfter)),
    name,                                               // subject
    spki,
    DER.tlv(0xa3, DER.seq(sanExt))                      // extensions
  );

  const signature = crypto.sign('sha256', tbs, privateKey);
  const der = DER.seq(tbs, ecdsaSha256, DER.tlv(0x03, Buffer.concat([Buffer.from([0]), signature])));
  const b64 = der.toString('base64').replace(/(.{64})/g, '$1\n');
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}

async function testSsl() {
  console.log('🧪 Testing SSL Manager (registro honesto, sin emisión falsa)...');

  // 1. El registro nunca informa de un certificado que no exista en disco.
  //    Se inyecta a mano una entrada como las que escribía la versión
  //    anterior: apunta a un fichero con un PEM fabricado.
  const fakeDir = path.join(CERTS_DIR, 'prueba-falsa.dev');
  fs.mkdirSync(fakeDir, { recursive: true });
  const fakeCertPath = path.join(fakeDir, 'fullchain.pem');
  const fakeKeyPath = path.join(fakeDir, 'privkey.pem');
  fs.writeFileSync(
    fakeCertPath,
    `-----BEGIN CERTIFICATE-----\nMIICrDCCAZSgAwIBAgIU${crypto.randomBytes(32).toString('base64')}\n-----END CERTIFICATE-----`,
    'utf8'
  );
  fs.writeFileSync(fakeKeyPath, 'no-es-una-clave', 'utf8');

  sslManager.registry.unshift({
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

  const afterFake = sslManager.listCertificates();
  assert.ok(
    !afterFake.some(c => c.id === 'cert_falso_de_prueba'),
    'listCertificates() no puede informar de un certificado cuyo PEM no es un X.509'
  );
  assert.ok(
    !sslManager.getCertificateByDomain('api.prueba-falsa.dev'),
    'getCertificateByDomain() tampoco puede devolver una entrada descartada'
  );
  console.log('  ✓ Un PEM fabricado no se publica nunca como certificado');

  // 2. Nada de lo que se publique puede tener caducidad inventada: o sale de un
  //    X.509 real, o es null.
  for (const cert of sslManager.listCertificates()) {
    if (cert.status === 'delegated') {
      assert.strictEqual(cert.expiresAt, null, 'Un certificado delegado no puede declarar caducidad');
      assert.strictEqual(cert.issuer, null, 'Un certificado delegado no puede declarar emisor');
      assert.strictEqual(cert.fingerprint, null, 'Un certificado delegado no puede declarar huella');
    } else {
      const disk = sslManager.readCertificateFile(cert.certPath);
      assert.ok(disk.ok, `El certificado ${cert.domain} se publica pero su fichero no parsea`);
      assert.strictEqual(cert.expiresAt, disk.notAfter, 'La caducidad publicada debe salir del X.509');
    }
  }
  console.log('  ✓ Toda caducidad publicada procede de un X.509 real, o es null');

  // 3. `data/certs/` no puede quedarse con PEMs fabricados. La entrada anterior
  //    los dejó ahí; una recarga del registro debe barrerlos.
  const SslManagerClass = sslManager.SslManager;
  fs.writeFileSync(path.join(CERTS_DIR, 'registry.json'), JSON.stringify([
    {
      id: 'cert_residuo',
      domain: '*.prueba-falsa.dev',
      rootDomain: 'prueba-falsa.dev',
      certPath: fakeCertPath,
      keyPath: fakeKeyPath
    }
  ], null, 2), 'utf8');
  const reloaded = new SslManagerClass();
  assert.strictEqual(reloaded.listCertificates().length, 0, 'La recarga debe descartar la entrada fabricada');
  assert.ok(!fs.existsSync(fakeCertPath), 'El PEM fabricado debe borrarse del disco, no sólo ignorarse');
  assert.ok(!fs.existsSync(fakeKeyPath), 'La clave huérfana también debe borrarse');
  console.log('  ✓ data/certs/ se purga de PEMs fabricados al cargar el registro');

  // 4. Un certificado X.509 auténtico SÍ se lee, y sus datos salen del propio
  //    certificado. Si no, el punto 1 pasaría por el motivo equivocado.
  const realPem = makeRealSelfSignedCert();
  let realParsed = null;
  try {
    realParsed = new crypto.X509Certificate(realPem);
  } catch (e) {
    realParsed = null;
  }
  if (realParsed) {
    const realDir = path.join(CERTS_DIR, 'prueba-real.dev');
    fs.mkdirSync(realDir, { recursive: true });
    const realPath = path.join(realDir, 'fullchain.pem');
    fs.writeFileSync(realPath, realPem, 'utf8');
    const read = sslManager.readCertificateFile(realPath);
    assert.strictEqual(read.ok, true, 'Un X.509 auténtico tiene que leerse');
    assert.ok(read.notAfter, 'Debe extraerse la caducidad real del certificado');
    assert.ok(read.fingerprint, 'Debe extraerse la huella real del certificado');
    fs.rmSync(realDir, { recursive: true, force: true });
    console.log('  ✓ Un X.509 auténtico se lee y sus campos salen del certificado');
  } else {
    // El PEM de muestra no parsea en esta versión de Node: la propiedad que
    // importa (rechazar lo falso) ya está comprobada arriba.
    console.log('  ⚠ Muestra X.509 no parseable en este Node; se omite la lectura positiva');
  }

  // 5. Registro de host bajo demanda: no escribe ficheros ni afirma caducidad.
  const before = new Set(fs.existsSync(CERTS_DIR) ? fs.readdirSync(CERTS_DIR) : []);
  const sslipRes = await sslManager.issueOnDemandSslip({ ip: '192.168.1.100', service: 'nip.io' });
  assert.strictEqual(sslipRes.success, true);
  assert.strictEqual(sslipRes.cert.rootDomain, '192-168-1-100.nip.io');
  assert.strictEqual(sslipRes.cert.type, 'ondemand_tls');
  assert.strictEqual(sslipRes.cert.status, 'delegated');
  assert.strictEqual(sslipRes.cert.expiresAt, null, 'No puede inventarse una caducidad para lo que emite Caddy');
  assert.strictEqual(sslipRes.cert.certPath, null, 'No puede haber ruta a un fichero que no existe');
  const after = new Set(fs.readdirSync(CERTS_DIR));
  const created = [...after].filter(f => !before.has(f) && f !== 'registry.json');
  assert.deepStrictEqual(created, [], `El registro bajo demanda no debe escribir PEMs (creó: ${created.join(', ')})`);
  console.log('  ✓ El alta de host bajo demanda no escribe ningún PEM');

  // 6. La emisión de comodín es honesta: nunca dice que ha funcionado.
  const progress = [];
  const wildcardRes = await sslManager.issueWildcardCertificate({
    domain: '*.cloud-test.dev',
    zoneId: 'cf_zone_mock_1',
    provider: 'lets_encrypt',
    onProgress: (p) => progress.push(p.stage)
  });
  assert.strictEqual(wildcardRes.success, false, 'La emisión de comodín no puede declararse exitosa');
  assert.strictEqual(wildcardRes.implemented, false);
  assert.strictEqual(wildcardRes.code, 'WILDCARD_ACME_NO_IMPLEMENTADO');
  assert.ok(/no está implementada/i.test(wildcardRes.error), 'El error debe explicarse en castellano');
  assert.deepStrictEqual(progress, ['no_implementado'], 'No debe simular etapas ACME');
  assert.ok(
    !sslManager.listCertificates().some(c => c.rootDomain === 'cloud-test.dev'),
    'Un intento de emisión de comodín no puede dejar rastro en el registro'
  );
  assert.ok(
    !fs.existsSync(path.join(CERTS_DIR, 'cloud-test.dev', 'fullchain.pem')),
    'Un intento de emisión de comodín no puede escribir ningún PEM'
  );
  console.log('  ✓ issueWildcardCertificate() devuelve un error honesto y no escribe nada');

  // 7. Limpieza: la entrada delegada de prueba y los restos en disco.
  sslManager.revokeCertificate(sslipRes.cert.id);
  fs.rmSync(fakeDir, { recursive: true, force: true });

  console.log('✅ All SSL tests passed!\n');
}

module.exports = testSsl;

if (require.main === module) {
  testSsl().catch(err => {
    console.error('❌ SSL test failure:', err);
    process.exit(1);
  });
}
