'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const edgeCorsCspService = require('../server/services/edgeCorsCspService');
const pkgConfusionGuardService = require('../server/services/pkgConfusionGuardService');

const {
  EdgeCorsCspService,
  auditCorsPolicy,
  auditSecurityHeaders,
  renderHardenedCaddyHeadersBlock,
  upsertCorsCspPolicy,
  listCorsCspPolicies
} = edgeCorsCspService;

const {
  PkgConfusionGuardService,
  levenshteinDistance,
  auditPackageSupplyChain,
  scanInstallScriptRisk,
  generateSafeNpmrc,
  listPkgGuardAudits
} = pkgConfusionGuardService;

/**
 * Verifies CVE-2025-34291/63388 CORS wildcard/reflected credentials blocks, regex suffix traps,
 * CSP unsafe directives, external CDN SRI hashes, HSTS/COOP/COEP, and plain string caddyfile.
 * @param {string} tmpRoot
 */
function testEdgeCorsCspService(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'cors-csp-data');
  const svc = new EdgeCorsCspService({ dataDir });

  // 1. CVE-2025-34291: wildcard * + reflected origin + credentials + SameSite=None -> BLOCKED
  const badCors = svc.auditCorsPolicy({
    allowedOrigins: ['*', 'example.com'],
    allowCredentials: true,
    reflectOrigin: true,
    sameSiteCookie: 'None',
    probeOrigin: 'https://evil-example.com'
  });
  assert.strictEqual(badCors.safe, false);
  assert.strictEqual(badCors.blocked, true);
  assert.ok(badCors.findingCodes.includes('CORS_WILDCARD_CREDENTIALS'));
  assert.ok(badCors.findingCodes.includes('CORS_REFLECTED_ORIGIN_CREDENTIALS'));
  assert.ok(badCors.findingCodes.includes('CORS_REGEX_SUFFIX_TRAP'));
  assert.ok(badCors.findingCodes.includes('CORS_SAMESITE_NONE_UNBOUND'));
  assert.strictEqual(typeof badCors.caddyfile, 'string');

  // Clean exact-origin CORS passes
  const goodCors = svc.auditCorsPolicy({
    allowedOrigins: ['https://app.culkibo.dev'],
    allowCredentials: true,
    reflectOrigin: false,
    sameSiteCookie: 'Lax',
    probeOrigin: 'https://app.culkibo.dev'
  });
  assert.strictEqual(goodCors.safe, true);
  assert.strictEqual(goodCors.probeAllowedExact, true);

  // 2. Security headers & external CDN script SRI check
  const badHdrs = svc.auditSecurityHeaders({
    headers: {
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'"
    },
    externalScripts: [
      { src: 'https://cdn.example.com/analytics.js' }
    ]
  });
  assert.strictEqual(badHdrs.safe, false);
  assert.ok(badHdrs.findingCodes.includes('CSP_UNSAFE_DIRECTIVE'));
  assert.ok(badHdrs.findingCodes.includes('MISSING_SRI_HASH'));
  assert.ok(badHdrs.findingCodes.includes('MISSING_HSTS'));
  assert.ok(badHdrs.findingCodes.includes('MISSING_COOP_COEP'));

  const goodHdrs = svc.auditSecurityHeaders({
    headers: {
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'strict-dynamic'; object-src 'none'",
      'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp'
    },
    externalScripts: [
      {
        src: 'https://cdn.example.com/lib.min.js',
        integrity: 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC'
      }
    ]
  });
  assert.strictEqual(goodHdrs.safe, true);

  // 3. Policy upsert defaults dryRun: true
  const dryPol = svc.upsertCorsCspPolicy('proj_web', { allowedOrigins: ['https://app.culkibo.dev'], allowCredentials: true });
  assert.strictEqual(dryPol.dryRun, true);
  assert.strictEqual(svc.listCorsCspPolicies().length, 0);

  const livePol = svc.upsertCorsCspPolicy('proj_web', {
    allowedOrigins: ['https://app.culkibo.dev'],
    allowCredentials: true,
    dryRun: false
  });
  assert.strictEqual(livePol.dryRun, false);
  assert.strictEqual(svc.listCorsCspPolicies().length, 1);
  assert.ok(fs.existsSync(path.join(dataDir, 'edge-cors-csp.json')));
}

/**
 * Verifies Shai-Hulud / CHAINDROP lifecycle IoCs, Levenshtein typosquats, unscoped dependency
 * confusion, ignore-scripts=true enforcement, and .npmrc generator.
 * @param {string} tmpRoot
 */
function testPkgConfusionGuardService(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'pkg-guard-data');
  const svc = new PkgConfusionGuardService({ dataDir });

  // 1. Exact Levenshtein distance
  assert.strictEqual(svc.levenshteinDistance('expres', 'express'), 1);
  assert.strictEqual(svc.levenshteinDistance('lodahs', 'lodash'), 2);
  assert.strictEqual(svc.levenshteinDistance('express', 'express'), 0);

  // 2. CHAINDROP / Shai-Hulud worm IoC + typosquat + unscoped private + ignore-scripts=false -> BLOCKED
  const hostile = svc.auditPackageSupplyChain({
    projectId: 'proj_api',
    internalScopes: ['@acme'],
    npmrcIgnoreScripts: false,
    packages: [
      { name: 'keyv', version: '6.0.0', postinstall: 'node setup.mjs && rm -rf ~/' },
      { name: 'expres', version: '4.19.0' },
      { name: 'acme-billing-sdk', version: '1.0.0', private: true }
    ]
  });
  assert.strictEqual(hostile.safe, false);
  assert.strictEqual(hostile.blocked, true);
  assert.ok(hostile.findingCodes.includes('WORM_IOC_DETECTED'));
  assert.ok(hostile.findingCodes.includes('UNAPPROVED_LIFECYCLE_SCRIPT'));
  assert.ok(hostile.findingCodes.includes('TYPOSQUAT_SUSPECTED'));
  assert.ok(hostile.findingCodes.includes('DEPENDENCY_CONFUSION_RISK'));
  assert.ok(hostile.findingCodes.includes('NPM_SCRIPTS_ENABLED'));
  assert.strictEqual(typeof hostile.npmrcContent, 'string');
  assert.ok(hostile.npmrcContent.includes('ignore-scripts=true'));

  // 3. Clean allowlisted build with ignore-scripts=true passes
  const clean = svc.auditPackageSupplyChain({
    projectId: 'proj_api',
    internalScopes: ['@acme'],
    allowLifecycleScripts: ['esbuild'],
    npmrcIgnoreScripts: true,
    packages: [
      { name: 'express', version: '4.21.2' },
      { name: '@acme/billing-sdk', version: '1.0.0', private: true },
      { name: 'esbuild', version: '0.24.0', postinstall: 'node install.js' }
    ]
  });
  assert.strictEqual(clean.safe, true);
  assert.strictEqual(clean.blocked, false);
  assert.strictEqual(clean.findings.length, 0);

  // 4. Direct script scanner & generateSafeNpmrc dryRun default
  assert.strictEqual(svc.scanInstallScriptRisk('node math_init.js').code, 'WORM_IOC_DETECTED');
  const npmrc = svc.generateSafeNpmrc({ allowScripts: ['esbuild'], internalScopes: ['@acme'] });
  assert.strictEqual(npmrc.dryRun, true);
  assert.ok(npmrc.npmrcContent.includes('ignore-scripts=true'));
  assert.ok(npmrc.npmrcContent.includes('@acme:registry='));

  assert.strictEqual(svc.listPkgGuardAudits('proj_api').length, 2);
  assert.ok(fs.existsSync(path.join(dataDir, 'pkg-confusion-guard.json')));
}

/**
 * Verifies BOTH singleton (`svc.fn`) AND destructured (`fn`) exports with dynamic `CULKIBO_DATA_DIR`.
 * @param {string} tmpRoot
 */
function testSingletonAndDestructuredExports(tmpRoot) {
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = path.join(tmpRoot, 'singleton-env');

  try {
    // EdgeCorsCspService singleton + destructured
    assert.strictEqual(auditCorsPolicy({ allowedOrigins: ['*'], allowCredentials: true }).blocked, true);
    assert.strictEqual(auditSecurityHeaders({ headers: {} }).blocked, true);
    assert.strictEqual(typeof renderHardenedCaddyHeadersBlock().caddyfile, 'string');
    assert.strictEqual(upsertCorsCspPolicy('sp', { allowedOrigins: ['https://a.dev'], dryRun: false }).ok, true);
    assert.strictEqual(listCorsCspPolicies().length, 1);
    assert.strictEqual(edgeCorsCspService.listCorsCspPolicies().length, 1);

    // PkgConfusionGuardService singleton + destructured
    assert.strictEqual(levenshteinDistance('lodahs', 'lodash'), 2);
    assert.strictEqual(scanInstallScriptRisk('node setup.mjs').wormIocDetected, true);
    assert.strictEqual(generateSafeNpmrc(['esbuild']).dryRun, true);
    assert.strictEqual(
      auditPackageSupplyChain({ projectId: 'sp', npmrcIgnoreScripts: true, packages: [{ name: 'express' }] }).safe,
      true
    );
    assert.strictEqual(listPkgGuardAudits('sp').length, 1);
    assert.strictEqual(pkgConfusionGuardService.listPkgGuardAudits('sp').length, 1);
  } finally {
    if (prevDataDir === undefined) {
      delete process.env.CULKIBO_DATA_DIR;
    } else {
      process.env.CULKIBO_DATA_DIR = prevDataDir;
    }
  }
}

async function runAllTests() {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c21-cors-pkg-'));
  try {
    testEdgeCorsCspService(tmpRoot);
    testPkgConfusionGuardService(tmpRoot);
    testSingletonAndDestructuredExports(tmpRoot);
    console.log('✅ cors-csp-and-pkg-guard.test.js PASSED (CVE-2025-34291 CORS/CSP/SRI, Shai-Hulud/CHAINDROP IoCs, typosquats, .npmrc, singleton+destructured)');
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runAllTests().catch((err) => {
    console.error('❌ cors-csp-and-pkg-guard.test.js FAILED:', err);
    process.exit(1);
  });
}

module.exports = runAllTests;
