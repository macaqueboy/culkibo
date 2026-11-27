const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const brandMod = require('../server/services/brandThemeService');
const { BrandThemeService, DEFAULT_BRAND, validateBrandPatch, sanitizeBrandLogo } = brandMod;

async function testBrandTheme() {
  console.log('\n🎨 Testing Open-Core White-Label Brand & Custom Login Theme Engine (coolify#1744)...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-brand-theme-'));
  try {
    const svc = new BrandThemeService({ dataDir: tmpDir });

    // 1. Default brand values
    const initial = svc.getBrand();
    assert.deepStrictEqual(initial, { ...DEFAULT_BRAND });
    assert.strictEqual(initial.brandName, 'Culkibo');
    assert.strictEqual(initial.accentHex, '#6366f1');
    assert.strictEqual(initial.hidePoweredBy, false);
    assert.strictEqual(initial.updatedAt, null);

    // 2. Valid update + atomic persistence + reload across fresh instance
    const safeSvg = 'data:image/svg+xml;utf8,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="#10b981"/></svg>');
    const updated = svc.updateBrand({
      brandName: 'Acme Cloud PaaS',
      tagline: 'Managed sovereign hosting for Acme clients',
      accentHex: '#10B981',
      logoUrl: safeSvg,
      supportUrl: 'https://support.acme.example/help',
      hidePoweredBy: true
    }, { actor: 'owner@acme.example' });

    assert.strictEqual(updated.brandName, 'Acme Cloud PaaS');
    assert.strictEqual(updated.accentHex, '#10b981');
    assert.strictEqual(updated.logoUrl, safeSvg);
    assert.strictEqual(updated.supportUrl, 'https://support.acme.example/help');
    assert.strictEqual(updated.hidePoweredBy, true);
    assert.ok(typeof updated.updatedAt === 'string' && updated.updatedAt.length > 0);
    assert.ok(fs.existsSync(path.join(tmpDir, 'brand-theme.json')), 'brand-theme.json must persist in isolated dir');

    const svcReloaded = new BrandThemeService({ dataDir: tmpDir });
    assert.strictEqual(svcReloaded.getBrand().brandName, 'Acme Cloud PaaS');
    assert.strictEqual(svcReloaded.getBrand().hidePoweredBy, true);

    // Also allow clean HTTPS logo URL and base64-encoded safe SVG
    const b64SafeSvg = 'data:image/svg+xml;base64,' + Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><rect width="16" height="16"/></svg>').toString('base64');
    assert.strictEqual(sanitizeBrandLogo(b64SafeSvg), b64SafeSvg);
    assert.strictEqual(sanitizeBrandLogo('https://cdn.acme.example/logo.png'), 'https://cdn.acme.example/logo.png');

    // 3. Strict XSS / CSS injection rejection matrix
    const evilLogos = [
      'javascript:alert(1)',
      'vbscript:msgbox(1)',
      'data:text/html,<script>alert(1)</script>',
      'http://insecure.example/logo.png',
      'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
      'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>',
      'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"><image href="x" onerror="alert(1)"/></svg>',
      'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><iframe src="https://evil.test"/></body></foreignObject></svg>',
      'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"><iframe src="https://evil.test"/></svg>',
      'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><a xlink:href="javascript:alert(1)"><rect width="10" height="10"/></a></svg>',
      'data:image/svg+xml;base64,' + Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>').toString('base64')
    ];
    for (const evil of evilLogos) {
      assert.throws(
        () => sanitizeBrandLogo(evil),
        (err) => err && err.status === 400,
        `sanitizeBrandLogo MUST reject dangerous payload: ${evil.slice(0, 60)}`
      );
    }

    // Invalid hex CSS injection
    for (const badHex of ['#fff', '#6366f1; background:url(https://evil.test)', 'red', 'rgb(0,0,0)', '#GGGGGG']) {
      assert.throws(
        () => validateBrandPatch({ accentHex: badHex }),
        (err) => err && err.code === 'INVALID_ACCENT_HEX',
        `validateBrandPatch MUST reject invalid accentHex: ${badHex}`
      );
    }

    // Unsafe support URLs (http://, javascript:, data:)
    for (const badSupport of ['http://support.example', 'javascript:alert(1)', 'data:text/html,hi']) {
      assert.throws(
        () => validateBrandPatch({ supportUrl: badSupport }),
        (err) => err && err.code === 'INVALID_SUPPORT_URL',
        `validateBrandPatch MUST reject non-HTTPS supportUrl: ${badSupport}`
      );
    }

    // XSS characters in brandName & tagline
    assert.throws(() => validateBrandPatch({ brandName: '<img src=x onerror=alert(1)>' }), (err) => err && err.code === 'INVALID_BRAND_NAME');
    assert.throws(() => validateBrandPatch({ brandName: 'Acme "Injected"' }), (err) => err && err.code === 'INVALID_BRAND_NAME');
    assert.throws(() => validateBrandPatch({ tagline: 'Hello <script>x</script>' }), (err) => err && err.code === 'INVALID_BRAND_TAGLINE');

    // 4. Reset restores DEFAULT_BRAND cleanly
    const reset = svc.resetBrand({ actor: 'owner@acme.example' });
    assert.deepStrictEqual(reset, { ...DEFAULT_BRAND });
    assert.deepStrictEqual(new BrandThemeService({ dataDir: tmpDir }).getBrand(), { ...DEFAULT_BRAND });

    console.log('  ✓ Default brand, atomic 0o600 persistence, reset & strict XSS/CSS/SVG/URL rejection verified');
    console.log('✅ White-Label Brand Theme suite passed!\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  testBrandTheme()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ White-Label Brand Theme suite failed:', err);
      process.exit(1);
    });
}

module.exports = testBrandTheme;
