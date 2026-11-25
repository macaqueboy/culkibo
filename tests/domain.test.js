const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const {
  DomainManager,
  normalizeAndValidateHostname,
  detectIdnHomograph,
  sanitizeCustomHeaders
} = require('../server/services/domainManager');
const { SslManager } = require('../server/services/sslManager');
const { IngressManager } = require('../server/services/ingressManager');

const DER = {
  len(n) {
    if (n < 0x80) return Buffer.from([n]);
    const bytes = [];
    let v = n;
    while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); }
    return Buffer.from([0x80 | bytes.length, ...bytes]);
  },
  tlv: (tag, content) => Buffer.concat([Buffer.from([tag]), DER.len(content.length), content]),
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

function makeWildcardCertPair(root) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const ecdsaSha256 = DER.seq(DER.oid('1.2.840.10045.4.3.2'));
  const name = DER.seq(DER.set(DER.seq(Buffer.concat([DER.oid('2.5.4.3'), DER.utf8(`*.${root}`)]))));
  const notBefore = new Date(Date.now() - 3600000);
  const notAfter = new Date(Date.now() + 90 * 86400000);
  const sanExt = DER.seq(Buffer.concat([
    DER.oid('2.5.29.17'),
    DER.tlv(0x04, DER.seq(Buffer.concat([`*.${root}`, root].map((d) => DER.tlv(0x82, Buffer.from(d, 'ascii'))))))
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

async function testDomain() {
  console.log('🧪 Testing Domain Manager (aislado en tmpdir + IDN homographs + Header Injection + Edge Schemas)...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-domain-test-'));
  try {
    const sslMgr = new SslManager({ certsDir: path.join(tmpDir, 'certs') });
    const dm = new DomainManager({ dataDir: tmpDir, seedDefaults: true, sslManager: sslMgr });

    // 1. List Domains (semillas aisladas)
    const domains = dm.listDomains();
    assert.ok(Array.isArray(domains));
    assert.ok(domains.length >= 2, 'Initial domains must exist');
    console.log(`  ✓ Domain listing passed (${domains.length} isolated domains)`);

    // 2. Add Domain + Duplicate prevention
    const uniqueName = `test-${Date.now()}.culkibo.dev`;
    const added = await dm.addDomain({
      hostname: uniqueName,
      targetPod: 'forge',
      targetPort: 3001,
      cloudflareProxied: true
    });
    assert.strictEqual(added.hostname, uniqueName);
    assert.strictEqual(added.targetPod, 'forge');

    await assert.rejects(
      () => dm.addDomain({ hostname: uniqueName }),
      /already configured/
    );
    console.log('  ✓ Add domain & duplicate prevention passed');

    // 3. Route Resolution: Exact vs Wildcard + Port Stripping + Label Boundary + Multi-Label RFC 6125
    const exactRoute = dm.resolveRoute('CULKIBO.DEV:3030');
    assert.ok(exactRoute && exactRoute.hostname === 'culkibo.dev');

    const wildcardRoute = dm.resolveRoute('SubDomain.Culkibo.Dev:443');
    assert.ok(wildcardRoute && wildcardRoute.isWildcard === true);

    assert.strictEqual(dm.resolveRoute('evilculkibo.dev'), null, 'evilculkibo.dev must NOT match *.culkibo.dev');
    assert.strictEqual(dm.resolveRoute('notculkibo.dev:443'), null, 'notculkibo.dev must NOT match *.culkibo.dev');
    assert.strictEqual(dm.resolveRoute('a.b.culkibo.dev'), null, 'RFC 6125: multi-level a.b.culkibo.dev must NOT match *.culkibo.dev');

    // Añadir wildcard más específico `*.b.culkibo.dev` y comprobar precedencia de sufijo más largo
    const nestedWild = await dm.addDomain({ hostname: '*.b.culkibo.dev', targetPod: 'citadel', targetPort: 8080 });
    const matchedNested = dm.resolveRoute('a.b.culkibo.dev');
    assert.ok(matchedNested && matchedNested.hostname === '*.b.culkibo.dev', 'a.b.culkibo.dev debe resolver al comodín específico *.b.culkibo.dev');
    await dm.deleteDomain(nestedWild.id);
    console.log('  ✓ Exact, wildcard, label-boundary & RFC 6125 multi-level wildcard overlap passed');

    // 4. Adversarial IDN Homograph Guard
    // Mixto Latin + Cirílico (`а` = U+0430)
    assert.strictEqual(detectIdnHomograph('p\u0430ypal.com').suspicious, true);
    assert.throws(() => normalizeAndValidateHostname('p\u0430ypal.com'), /homograph/i);
    // Punycode pre-codificado del mismo homógrafo (`xn--pypal-4ve.com`)
    assert.throws(() => normalizeAndValidateHostname('xn--pypal-4ve.com'), /homograph/i);
    // Mixto Latin + Griego (`ο` = U+03BF)
    assert.throws(() => normalizeAndValidateHostname('g\u03bfogle.com'), /homograph/i);
    // Caracteres invisibles / BiDi override
    assert.throws(() => normalizeAndValidateHostname('app\u200B.example.com'), /homograph/i);
    assert.throws(() => normalizeAndValidateHostname('app\u202E.example.com'), /homograph/i);
    // Etiqueta puramente cirílica confusable bajo TLD ASCII `.com` (`аеорс.com`)
    assert.throws(() => normalizeAndValidateHostname('\u0430\u0435\u043e\u0440\u0441.com'), /homograph/i);
    // IDN legítimo de un solo alfabeto (Latin con tilde) DEBE aceptarse y normalizarse a punycode
    assert.strictEqual(normalizeAndValidateHostname('Café.Example.Test.'), 'xn--caf-dma.example.test');
    console.log('  ✓ Guardia anti-homógrafos IDN (Cirílico/Griego mixto, Punycode, BiDi, confusable TLD) verificada');

    // 5. Header Injection bloqueado en BOTH `addDomain()` AND `updateDomain()`
    assert.throws(() => sanitizeCustomHeaders({ response: { 'X-Test': 'ok\r\nSet-Cookie: pwn=1' } }), /CRLF/i);
    assert.throws(() => sanitizeCustomHeaders({ response: { 'Host': 'evil.com' } }), /hop-by-hop|reservada/i);
    assert.throws(() => sanitizeCustomHeaders({ request: { 'Transfer-Encoding': 'chunked' } }), /hop-by-hop|reservada/i);

    await assert.rejects(
      () => dm.addDomain({
        hostname: 'inject-add.example.test',
        customHeaders: { response: { 'X-Evil': 'a\r\nX-Injected: 1' } }
      }),
      /CRLF/i,
      'addDomain() NO puede saltarse el saneamiento CRLF de customHeaders'
    );
    await assert.rejects(
      () => dm.addDomain({
        hostname: 'inject-host.example.test',
        customHeaders: { request: { Host: 'spoofed.internal' } }
      }),
      /hop-by-hop|reservada/i
    );
    await assert.rejects(
      () => dm.updateDomain(added.id, {
        customHeaders: { response: { 'X-Bad\r\nKey': 'val' } }
      }),
      /CRLF/i
    );
    console.log('  ✓ Bloqueo de inyección de cabeceras CRLF/Host/hop-by-hop en addDomain() y updateDomain()');

    // 6. Nuevos esquemas Edge (ForwardAuth, CORS, HSTS Preload, PathRoutes, PathRedirects, gRPC, Tunnel)
    await assert.rejects(
      () => dm.addDomain({
        hostname: 'cors-bad.example.test',
        cors: { enabled: true, allowedOrigins: ['*'], allowCredentials: true }
      }),
      /allowCredentials/i
    );
    await assert.rejects(
      () => dm.addDomain({
        hostname: 'fa-ssrf.example.test',
        forwardAuth: { enabled: true, upstream: '169.254.169.254:80', uri: '/latest' }
      }),
      /SSRF|metadatos/i
    );
    await assert.rejects(
      () => dm.addDomain({
        hostname: 'redos-bad.example.test',
        pathRedirects: [{ pattern: '^(a+)+$', target: '/ok', status: 301, isRegex: true }]
      }),
      /ReDoS|rechazado/i
    );

    const edgeDom = await dm.addDomain({
      hostname: 'edge-full.example.test',
      targetPod: 'citadel',
      targetPort: 8080,
      hstsPreload: true,
      permissionsPolicy: 'geolocation=()',
      protocol: 'grpc',
      streaming: true,
      flushInterval: -1,
      streamCloseDelayMs: 12000,
      forwardAuth: { enabled: true, upstream: 'authelia:9091', uri: '/api/verify', copyHeaders: ['Remote-User'] },
      cors: { enabled: true, allowedOrigins: ['https://ui.example.test'], allowCredentials: true },
      pathRoutes: [{ path: '/v1/*', upstreams: ['127.0.0.1:50051'], stripPrefix: '/v1', protocol: 'grpc' }],
      pathRedirects: [{ pattern: '^/legacy/(.*)$', target: '/v2/$1', status: 308, isRegex: true }],
      customHeaders: { response: { 'X-Edge-Mode': 'pro' } }
    });
    assert.strictEqual(edgeDom.hstsPreload, true);
    assert.strictEqual(edgeDom.protocol, 'grpc');
    assert.strictEqual(edgeDom.forwardAuth.upstream, 'authelia:9091');
    assert.strictEqual(edgeDom.cors.allowCredentials, true);
    assert.strictEqual(edgeDom.pathRoutes.length, 1);
    assert.strictEqual(edgeDom.pathRedirects.length, 1);

    // Verificar propagación completa en IngressManager.buildDesiredState()
    const im = new IngressManager({ dataDir: tmpDir, domainManager: dm, sslManager: sslMgr });
    const desired = im.buildDesiredState();
    const edgeSpec = desired.specs.find((s) => s.hostnames.includes('edge-full.example.test'));
    assert.ok(edgeSpec);
    assert.strictEqual(edgeSpec.hstsPreload, true);
    assert.strictEqual(edgeSpec.protocol, 'grpc');
    assert.strictEqual(edgeSpec.forwardAuth.enabled, true);
    assert.strictEqual(edgeSpec.cors.enabled, true);
    assert.strictEqual(edgeSpec.pathRoutes.length, 1);
    assert.strictEqual(edgeSpec.pathRedirects.length, 1);
    console.log('  ✓ Validación, persistencia y propagación de esquemas Edge en IngressManager verificadas');

    // 7. certClaim.verified & isWildcard precisos para certificado PEM comodín en disco
    const pair = makeWildcardCertPair('cert-claim.test');
    sslMgr.uploadCustomCertificate({
      domain: '*.cert-claim.test',
      certPem: pair.certPem,
      keyPem: pair.keyPem,
      provider: 'cloudflare_origin_ca'
    });
    await dm.addDomain({ hostname: 'api.cert-claim.test', targetPod: 'citadel', targetPort: 8080 });
    const listed = dm.listDomains();
    const claimed = listed.find((d) => d.hostname === 'api.cert-claim.test');
    assert.ok(claimed && claimed.certClaim);
    assert.strictEqual(claimed.certClaim.verified, true, 'Certificado X.509 on_disk debe reportar verified: true');
    assert.strictEqual(claimed.certClaim.isWildcard, true, 'Certificado custom_wildcard debe reportar isWildcard: true');
    console.log('  ✓ certClaim.verified y isWildcard reportan con exactitud certificados X.509 on_disk');

    // 8. Toggle Proxy, Update & Delete
    const toggled = await dm.toggleProxy(added.id);
    assert.strictEqual(toggled.cloudflareProxied, false);
    const updated = await dm.updateDomain(added.id, { targetPod: 'citadel', targetPort: 8080 });
    assert.strictEqual(updated.targetPod, 'citadel');
    assert.strictEqual(updated.targetPort, 8080);
    const deleted = await dm.deleteDomain(added.id);
    assert.strictEqual(deleted.id, added.id);
    console.log('  ✓ Toggle proxy, update y delete pasaron sin tocar data/domains.json real');

    console.log('✅ All Domain tests passed!\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

module.exports = testDomain;

if (require.main === module) {
  testDomain().catch((err) => {
    console.error('❌ Domain test failure:', err);
    process.exit(1);
  });
}
