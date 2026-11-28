'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const jwtOidcFirewallService = require('../server/services/jwtOidcFirewallService');
const graphqlDosShieldService = require('../server/services/graphqlDosShieldService');

const {
  JwtOidcFirewallService,
  inspectJwtHeaderAndClaims,
  auditOidcVerifierConfig,
  listJwtFirewallAudits
} = jwtOidcFirewallService;

const {
  GraphqlDosShieldService,
  inspectGraphqlQuery,
  upsertGraphqlShieldPolicy,
  listGraphqlShieldPolicies
} = graphqlDosShieldService;

/** Encodes a plain object into a Base64URL JWT segment. */
function b64u(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Verifies CVE-2026-29000 (JWE PlainJWT), CVE-2026-33322 (HS256 confusion), CVE-2026-22817,
 * jku SSRF, kid injection, OIDC claim checks, and ZERO raw token persistence.
 * @param {string} tmpRoot
 */
function testJwtOidcFirewall(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'jwt-data');
  const svc = new JwtOidcFirewallService({ dataDir });
  const nowSec = 1764310000;

  // 1. alg: none (mixed case "nOnE") -> JWT_ALG_NONE_FORBIDDEN
  const algNoneToken = `${b64u({ alg: 'nOnE', typ: 'JWT' })}.${b64u({ sub: 'admin', exp: nowSec + 3600 })}.`;
  const noneRes = svc.inspectJwtHeaderAndClaims({ token: algNoneToken, expectedAlgorithms: ['RS256'], nowSec });
  assert.strictEqual(noneRes.safe, false);
  assert.strictEqual(noneRes.blocked, true);
  assert.ok(noneRes.findingCodes.includes('JWT_ALG_NONE_FORBIDDEN'));

  // 2. CVE-2026-33322 (HS256 under RS256 pin) + jku SSRF + kid traversal + missing JWK alg + wrong iss
  const hostileToken = `${b64u({
    alg: 'HS256',
    jku: 'https://evil.example/jwks.json',
    kid: '../../etc/passwd'
  })}.${b64u({
    iss: 'https://attacker.example',
    aud: 'wrong-aud',
    exp: nowSec + 3600
  })}.fakesignature123`;
  const hostileRes = svc.inspectJwtHeaderAndClaims({
    token: hostileToken,
    expectedAlgorithms: ['RS256'],
    expectedIssuer: 'https://auth.culkibo.dev',
    expectedAudience: 'culkibo-api',
    jwkHasExplicitAlg: false,
    nowSec
  });
  assert.strictEqual(hostileRes.blocked, true);
  assert.ok(hostileRes.findingCodes.includes('JWT_ALG_CONFUSION_BLOCKED'));
  assert.ok(hostileRes.findingCodes.includes('JWT_JKU_SSRF_BLOCKED'));
  assert.ok(hostileRes.findingCodes.includes('JWT_KID_INJECTION'));
  assert.ok(hostileRes.findingCodes.includes('JWK_MISSING_EXPLICIT_ALG'));
  assert.ok(hostileRes.findingCodes.includes('JWT_CLAIMS_MISMATCH'));

  // 3. CVE-2026-29000 (CVSS 10.0): JWE-wrapped PlainJWT inner token -> JWE_PLAIN_INNER_FORBIDDEN
  const jweHeader = b64u({ alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'JWT' });
  const jweToken = `${jweHeader}.encKey.iv123.ciphertext.tag123`;
  const jweRes = svc.inspectJwtHeaderAndClaims({
    token: jweToken,
    innerToken: algNoneToken,
    nowSec
  });
  assert.strictEqual(jweRes.blocked, true);
  assert.ok(jweRes.findingCodes.includes('JWE_PLAIN_INNER_FORBIDDEN'));

  // 4. Valid RS256 token with matching iss/aud/exp passes
  const validToken = `${b64u({ alg: 'RS256', kid: 'key-2026-01', typ: 'JWT' })}.${b64u({
    iss: 'https://auth.culkibo.dev',
    aud: 'culkibo-api',
    sub: 'user_42',
    exp: nowSec + 3600
  })}.validSigBytesHere`;
  const okRes = svc.inspectJwtHeaderAndClaims({
    token: validToken,
    expectedAlgorithms: ['RS256'],
    expectedIssuer: 'https://auth.culkibo.dev',
    expectedAudience: 'culkibo-api',
    nowSec
  });
  assert.strictEqual(okRes.safe, true);
  assert.strictEqual(okRes.blocked, false);

  // Confirm ZERO raw token strings persisted on disk!
  const disk = fs.readFileSync(path.join(dataDir, 'jwt-oidc-firewall.json'), 'utf8');
  assert.ok(!disk.includes(hostileToken), 'Raw hostile JWT must NEVER be persisted');
  assert.ok(!disk.includes(validToken), 'Raw valid JWT must NEVER be persisted');

  // 5. OIDC verifier config audit (dryRun: true default)
  const cfgAudit = svc.auditOidcVerifierConfig({
    pinnedAlgorithms: ['HS256', 'RS256'],
    allowAlgNone: true,
    allowJkuHeader: true,
    sanitizeKid: false,
    validateIssAud: false
  });
  assert.strictEqual(cfgAudit.dryRun, true);
  assert.strictEqual(cfgAudit.blocked, true);
  assert.ok(cfgAudit.findingCodes.includes('JWT_ALG_NONE_FORBIDDEN'));
  assert.ok(cfgAudit.findingCodes.includes('JWT_ALG_CONFUSION_BLOCKED'));
  assert.strictEqual(svc.listJwtFirewallAudits().length, 4);
}

/**
 * Verifies CVE-2026-47707 fragment-spread alias expansion, CVE-2025-32031 fan-out DoS,
 * depth & batching limits, prod __schema introspection blocking, and bounded query pass.
 * @param {string} tmpRoot
 */
function testGraphqlDosShield(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'gql-data');
  const svc = new GraphqlDosShieldService({ dataDir });

  // 1. CVE-2026-47707 & CVE-2025-32031: Fragment-amplified query expanding 32 aliases via F1 -> F2
  const fragBomb = `
    query Amplify {
      ...F1
      ...F1
    }
    fragment F1 on Query {
      ...F2
      ...F2
      ...F2
      ...F2
    }
    fragment F2 on Query {
      a1: user { id }
      a2: user { id }
      a3: user { id }
      a4: user { id }
    }
  `;
  const ampRes = svc.inspectGraphqlQuery({ query: fragBomb, maxAliases: 15, maxFragmentExpansions: 8 });
  assert.strictEqual(ampRes.safe, false);
  assert.strictEqual(ampRes.blocked, true);
  assert.strictEqual(ampRes.metrics.expandedAliases, 32);
  assert.strictEqual(ampRes.metrics.fragmentExpansions, 10);
  assert.ok(ampRes.findingCodes.includes('GRAPHQL_ALIAS_AMPLIFICATION'));
  assert.ok(ampRes.findingCodes.includes('GRAPHQL_FRAGMENT_FANOUT_DOS'));

  // 2. Cyclic fragment spread terminates immediately & blocks
  const cyclic = `query { ...A } fragment A on Query { ...B } fragment B on Query { ...A }`;
  const cycRes = svc.inspectGraphqlQuery({ query: cyclic });
  assert.strictEqual(cycRes.blocked, true);
  assert.ok(cycRes.findingCodes.includes('GRAPHQL_FRAGMENT_FANOUT_DOS'));

  // 3. Prod __schema introspection & batch size > 10 & depth > 7
  const intro = svc.inspectGraphqlQuery({
    query: '{ __schema { types { name } } }',
    env: 'production',
    batchSize: 25
  });
  assert.strictEqual(intro.blocked, true);
  assert.ok(intro.findingCodes.includes('GRAPHQL_INTROSPECTION_BLOCKED'));
  assert.ok(intro.findingCodes.includes('GRAPHQL_BATCH_LIMIT_EXCEEDED'));

  const deep = svc.inspectGraphqlQuery({
    query: '{ a { b { c { d { e { f { g { h { id } } } } } } } } }',
    maxDepth: 5
  });
  assert.strictEqual(deep.blocked, true);
  assert.ok(deep.findingCodes.includes('GRAPHQL_DEPTH_EXCEEDED'));

  // 4. Clean bounded query passes
  const clean = svc.inspectGraphqlQuery({
    query: 'query GetUser { user(id: "42") { id email profile { avatar } } }',
    env: 'production'
  });
  assert.strictEqual(clean.safe, true);
  assert.strictEqual(clean.metrics.maxObservedDepth, 3);
  assert.strictEqual(clean.metrics.expandedAliases, 0);

  // 5. Policy upsert defaults dryRun: true
  const dryPol = svc.upsertGraphqlShieldPolicy('proj_gql', { maxDepth: 5, maxAliases: 10 });
  assert.strictEqual(dryPol.dryRun, true);
  assert.strictEqual(svc.listGraphqlShieldPolicies().length, 0);

  const livePol = svc.upsertGraphqlShieldPolicy('proj_gql', { maxDepth: 5, maxAliases: 10, dryRun: false });
  assert.strictEqual(livePol.dryRun, false);
  assert.strictEqual(svc.listGraphqlShieldPolicies().length, 1);
  assert.ok(fs.existsSync(path.join(dataDir, 'graphql-dos-shield.json')));
}

/**
 * Verifies BOTH singleton (`svc.fn`) AND destructured (`fn`) exports with dynamic `CULKIBO_DATA_DIR`.
 * @param {string} tmpRoot
 */
function testSingletonAndDestructuredExports(tmpRoot) {
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = path.join(tmpRoot, 'singleton-env');

  try {
    const t = `${b64u({ alg: 'none' })}.${b64u({ sub: '1' })}.`;
    assert.strictEqual(inspectJwtHeaderAndClaims({ token: t }).blocked, true);
    assert.strictEqual(auditOidcVerifierConfig({ pinnedAlgorithms: ['RS256'], dryRun: false }).safe, true);
    assert.strictEqual(listJwtFirewallAudits().length, 2);
    assert.strictEqual(jwtOidcFirewallService.listJwtFirewallAudits().length, 2);

    assert.strictEqual(inspectGraphqlQuery({ query: '{ __schema { types { name } } }' }).blocked, true);
    assert.strictEqual(upsertGraphqlShieldPolicy('sp', { maxDepth: 6, dryRun: false }).ok, true);
    assert.strictEqual(listGraphqlShieldPolicies().length, 1);
    assert.strictEqual(graphqlDosShieldService.listGraphqlShieldPolicies().length, 1);
  } finally {
    if (prevDataDir === undefined) {
      delete process.env.CULKIBO_DATA_DIR;
    } else {
      process.env.CULKIBO_DATA_DIR = prevDataDir;
    }
  }
}

async function runAllTests() {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c22-jwt-gql-'));
  try {
    testJwtOidcFirewall(tmpRoot);
    testGraphqlDosShield(tmpRoot);
    testSingletonAndDestructuredExports(tmpRoot);
    console.log('✅ jwt-and-graphql-shield.test.js PASSED (CVE-2026-29000/33322 JWT/OIDC, CVE-2026-47707/35441 GraphQL AST, singleton+destructured)');
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runAllTests().catch((err) => {
    console.error('❌ jwt-and-graphql-shield.test.js FAILED:', err);
    process.exit(1);
  });
}

module.exports = runAllTests;
