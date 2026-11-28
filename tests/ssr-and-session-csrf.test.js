'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ssrEdgeGuardService = require('../server/services/ssrEdgeGuardService');
const sessionCsrfGuardService = require('../server/services/sessionCsrfGuardService');

const {
  SsrEdgeGuardService,
  INTERNAL_SSR_HEADERS,
  evaluateSsrEdgeSecurity,
  renderHardenedSsrCaddyBlock,
  listSsrEdgeAudits
} = ssrEdgeGuardService;

const {
  SessionCsrfGuardService,
  evaluateCrossOriginRequest,
  auditSessionCookie,
  verifyOAuthPkceFlow,
  listSessionCsrfAudits
} = sessionCsrfGuardService;

/**
 * Verifies CVE-2025-29927 middleware header spoof, CVE-2025-55182 React2Shell CVSS 10.0,
 * CVE-2025-49005 omitted Vary: RSC, patched safe pass, and plain string caddyBlock.
 * @param {string} tmpRoot
 */
function testSsrEdgeGuard(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'ssr-data');
  const svc = new SsrEdgeGuardService({ dataDir });

  assert.ok(INTERNAL_SSR_HEADERS.includes('x-middleware-subrequest'));

  // 1. Vulnerable Next.js + React2Shell + spoofed header + omitted Vary: RSC -> BLOCKED
  const vuln = svc.evaluateSsrEdgeSecurity({
    framework: 'nextjs',
    nextVersion: '15.2.0',
    reactVersion: '19.1.0',
    requestHeaders: {
      'x-middleware-subrequest': 'middleware:middleware:middleware',
      Host: 'app.culkibo.dev'
    },
    responseHeaders: {
      'Content-Type': 'text/html'
    }
  });
  assert.strictEqual(vuln.safe, false);
  assert.strictEqual(vuln.blocked, true);
  assert.ok(vuln.findingCodes.includes('SSR_INTERNAL_HEADER_SPOOF'));
  assert.ok(vuln.findingCodes.includes('REACT2SHELL_VULNERABLE_VERSION'));
  assert.ok(vuln.findingCodes.includes('NEXTJS_MIDDLEWARE_CVE_VERSION'));
  assert.ok(vuln.findingCodes.includes('RSC_VARY_HEADER_MISSING'));
  assert.strictEqual(typeof vuln.caddyBlock, 'string');
  assert.ok(vuln.caddyBlock.includes('-x-middleware-subrequest'));

  // 2. Patched Next.js 15.3.3 + React 19.2.1 + clean headers + complete Vary -> SAFE
  const clean = svc.evaluateSsrEdgeSecurity({
    framework: 'nextjs',
    nextVersion: '15.3.3',
    reactVersion: '19.2.1',
    requestHeaders: { Host: 'app.culkibo.dev' },
    responseHeaders: { Vary: 'RSC, Next-Router-State-Tree, Next-Router-Prefetch' }
  });
  assert.strictEqual(clean.safe, true);
  assert.strictEqual(clean.blocked, false);
  assert.strictEqual(clean.findings.length, 0);

  // 3. renderHardenedSsrCaddyBlock defaults dryRun: true
  const rendered = svc.renderHardenedSsrCaddyBlock({ upstream: '127.0.0.1:3000' });
  assert.strictEqual(rendered.dryRun, true);
  assert.strictEqual(typeof rendered.caddyBlock, 'string');
  assert.ok(rendered.caddyBlock.includes('Next-Router-State-Tree'));

  assert.strictEqual(svc.listSsrEdgeAudits().length, 2);
  assert.ok(fs.existsSync(path.join(dataDir, 'ssr-edge-guard.json')));
}

/**
 * Verifies Go 1.25 CrossOriginProtection (Sec-Fetch-Site + Origin fallback),
 * RFC 6265bis __Host- cookie audit, OAuth 2.1 PKCE S256 (CVE-2026-26247), and zero raw secrets on disk.
 * @param {string} tmpRoot
 */
function testSessionCsrfGuard(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'csrf-data');
  const svc = new SessionCsrfGuardService({ dataDir });

  // 1. Go 1.25 CrossOriginProtection: cross-site POST blocked 403, GET allowed, Origin mismatch blocked
  const crossPost = svc.evaluateCrossOriginRequest({
    method: 'POST',
    secFetchSite: 'cross-site',
    origin: 'https://evil.example',
    host: 'app.culkibo.dev'
  });
  assert.strictEqual(crossPost.blocked, true);
  assert.strictEqual(crossPost.httpStatus, 403);
  assert.ok(crossPost.findingCodes.includes('CSRF_CROSS_ORIGIN_BLOCKED'));

  const originMismatch = svc.evaluateCrossOriginRequest({
    method: 'DELETE',
    origin: 'https://evil.example',
    host: 'app.culkibo.dev'
  });
  assert.strictEqual(originMismatch.blocked, true);
  assert.ok(originMismatch.findingCodes.includes('CSRF_ORIGIN_MISMATCH'));

  const safeGet = svc.evaluateCrossOriginRequest({
    method: 'GET',
    secFetchSite: 'cross-site',
    origin: 'https://external.example',
    host: 'app.culkibo.dev'
  });
  assert.strictEqual(safeGet.allowed, true);
  assert.strictEqual(safeGet.httpStatus, 200);

  const sameOriginPost = svc.evaluateCrossOriginRequest({
    method: 'POST',
    secFetchSite: 'same-origin',
    origin: 'https://app.culkibo.dev',
    host: 'app.culkibo.dev'
  });
  assert.strictEqual(sameOriginPost.allowed, true);

  // 2. Session cookie audit: __Host- without Secure / wrong Path=/app -> COOKIE_HOST_PREFIX_INVALID
  const rawCookieSecret = 'ULTRA_SECRET_SESSION_VALUE_DO_NOT_PERSIST_9911';
  const badCookie = svc.auditSessionCookie(`__Host-sid=${rawCookieSecret}; Path=/app`, { persist: true });
  assert.strictEqual(badCookie.blocked, true);
  assert.ok(badCookie.findingCodes.includes('COOKIE_HOST_PREFIX_INVALID'));
  assert.ok(badCookie.findingCodes.includes('COOKIE_MISSING_HTTPONLY'));
  assert.ok(badCookie.findingCodes.includes('COOKIE_MISSING_SECURE'));
  assert.ok(badCookie.findingCodes.includes('COOKIE_MISSING_SAMESITE'));

  const goodCookie = svc.auditSessionCookie(`__Host-sid=${rawCookieSecret}; Path=/; Secure; HttpOnly; SameSite=Lax`);
  assert.strictEqual(goodCookie.safe, true);

  // 3. OAuth 2.1 PKCE S256 (CVE-2026-26247)
  const plainPkce = svc.verifyOAuthPkceFlow({ method: 'plain', state: '1234' });
  assert.strictEqual(plainPkce.blocked, true);
  assert.ok(plainPkce.findingCodes.includes('PKCE_PLAIN_FORBIDDEN'));
  assert.ok(plainPkce.findingCodes.includes('OAUTH_STATE_WEAK'));

  const verifier = 'culkibo_pkce_verifier_secret_0123456789abcdef_XYZ987';
  const challenge = crypto.createHash('sha256').update(verifier, 'utf8').digest('base64url');
  const strongState = crypto.randomBytes(16).toString('hex');

  const okPkce = svc.verifyOAuthPkceFlow({
    method: 'S256',
    persistedMethod: 'S256',
    codeChallenge: challenge,
    codeVerifier: verifier,
    state: strongState
  });
  assert.strictEqual(okPkce.safe, true);
  assert.strictEqual(okPkce.pkceMatched, true);

  const badVerifier = svc.verifyOAuthPkceFlow({
    method: 'S256',
    persistedMethod: 'S256',
    codeChallenge: challenge,
    codeVerifier: 'wrong_verifier_value_0123456789abcdef_XYZ987654321',
    state: strongState
  });
  assert.strictEqual(badVerifier.blocked, true);
  assert.ok(badVerifier.findingCodes.includes('PKCE_VERIFIER_MISMATCH'));

  // Confirm ZERO raw cookie values or PKCE verifiers persisted on disk!
  const disk = fs.readFileSync(path.join(dataDir, 'session-csrf-guard.json'), 'utf8');
  assert.ok(!disk.includes(rawCookieSecret), 'Raw cookie value must NEVER be persisted');
  assert.ok(!disk.includes(verifier), 'Raw PKCE codeVerifier must NEVER be persisted');
  assert.ok(!disk.includes(strongState), 'Raw OAuth state must NEVER be persisted');
  assert.ok(svc.listSessionCsrfAudits().length >= 5);
}

/**
 * Verifies BOTH singleton (`svc.fn`) AND destructured (`fn`) exports with dynamic `CULKIBO_DATA_DIR`.
 * @param {string} tmpRoot
 */
function testSingletonAndDestructuredExports(tmpRoot) {
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = path.join(tmpRoot, 'singleton-env');

  try {
    assert.strictEqual(evaluateSsrEdgeSecurity({ reactVersion: '19.1.0' }).blocked, true);
    assert.strictEqual(typeof renderHardenedSsrCaddyBlock().caddyBlock, 'string');
    assert.strictEqual(listSsrEdgeAudits().length, 1);
    assert.strictEqual(ssrEdgeGuardService.listSsrEdgeAudits().length, 1);

    assert.strictEqual(evaluateCrossOriginRequest({ method: 'POST', secFetchSite: 'cross-site' }).blocked, true);
    assert.strictEqual(auditSessionCookie('__Host-s=x; Path=/; Secure; HttpOnly; SameSite=Lax').safe, true);
    assert.strictEqual(verifyOAuthPkceFlow({ method: 'plain' }).blocked, true);
    assert.strictEqual(listSessionCsrfAudits().length, 2);
    assert.strictEqual(sessionCsrfGuardService.listSessionCsrfAudits().length, 2);
  } finally {
    if (prevDataDir === undefined) {
      delete process.env.CULKIBO_DATA_DIR;
    } else {
      process.env.CULKIBO_DATA_DIR = prevDataDir;
    }
  }
}

async function runAllTests() {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c23-ssr-csrf-'));
  try {
    testSsrEdgeGuard(tmpRoot);
    testSessionCsrfGuard(tmpRoot);
    testSingletonAndDestructuredExports(tmpRoot);
    console.log('✅ ssr-and-session-csrf.test.js PASSED (CVE-2025-29927/55182/49005 SSR guard, Go 1.25 CSRF, PKCE S256, __Host- cookie, singleton+destructured)');
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runAllTests().catch((err) => {
    console.error('❌ ssr-and-session-csrf.test.js FAILED:', err);
    process.exit(1);
  });
}

module.exports = runAllTests;
