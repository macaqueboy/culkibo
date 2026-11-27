const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  diffContracts,
  saveBaseline,
  evaluateDeployGate,
  listContractHistory
} = require('../server/services/apiContractGateService');
const {
  computeDssePae,
  verifyOciBundle,
  resolveReferrerStrategy,
  upsertTrustRoot,
  listTrustRoots
} = require('../server/services/ociSignatureVerifier');
const {
  DEFAULT_REAPER_POLICY,
  scanOrphans,
  planReap,
  executeReap,
  upsertReaperPolicy,
  getReaperPolicy
} = require('../server/services/orphanReaperService');

/**
 * Suite Cycle #16: API Contract & Schema Drift Gate, Pure-Node OCI/SLSA Rekor
 * Verifier (CVE-2026-22703 / cosign#4640), and Docker-29-Immune Orphan PR Reaper.
 *
 * Runs strictly inside an isolated `os.tmpdir()` `CULKIBO_DATA_DIR` — ZERO mutations to live `data/`.
 */
async function runTests() {
  console.log('--- Iniciando Tests de API Contract Gate, OCI/SLSA Verifier y Orphan PR Reaper ---');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c16-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = tmpDir;

  let passed = 0;
  const runCase = async (name, fn) => {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  };

  try {
    // =========================================================================
    // 1. API CONTRACT & SCHEMA DRIFT GATE (OPENAPI 3.1 + GRAPHQL + SEMVER)
    // =========================================================================
    await runCase('1. apiContractGateService blocks breaking OpenAPI/GraphQL changes without major bump & allows 2.0.0', async () => {
      const baseOpenApi = {
        openapi: '3.1.0',
        info: { title: 'Users API', version: '1.4.0' },
        security: [{ bearerAuth: [] }],
        paths: {
          '/v1/users': {
            get: {
              security: [{ bearerAuth: [] }],
              parameters: [{ name: 'page', in: 'query', required: false }],
              responses: {
                '200': {
                  content: {
                    'application/json': {
                      schema: {
                        type: 'object',
                        properties: {
                          id: { type: 'string' },
                          email: { type: 'string' },
                          role: { type: 'string', enum: ['admin', 'member', 'viewer'] }
                        }
                      }
                    }
                  }
                }
              }
            }
          },
          '/v1/users/{id}': {
            delete: { security: [{ bearerAuth: [] }], responses: { '204': {} } }
          }
        }
      };

      const breakingMinor = {
        openapi: '3.1.0',
        info: { title: 'Users API', version: '1.5.0' },
        paths: {
          '/v1/users': {
            get: {
              security: [], // AUTH_REMOVED!
              parameters: [
                { name: 'page', in: 'query', required: false },
                { name: 'tenantId', in: 'header', required: true } // REQUIRED_PARAM_ADDED!
              ],
              responses: {
                '200': {
                  content: {
                    'application/json': {
                      schema: {
                        type: 'object',
                        properties: {
                          id: { type: 'integer' }, // TYPE_NARROWED!
                          // email removed -> RESPONSE_FIELD_REMOVED!
                          role: { type: 'string', enum: ['admin', 'member'] } // ENUM_VALUE_REMOVED!
                        }
                      }
                    }
                  }
                }
              }
            }
          }
          // /v1/users/{id} removed -> PATH_REMOVED!
        }
      };

      // Minor bump 1.4.0 -> 1.5.0 MUST fail with MISSING-VERSION-BUMP
      const blocked = diffContracts({ format: 'openapi', baseSpec: baseOpenApi, revisionSpec: breakingMinor });
      assert.strictEqual(blocked.allowed, false);
      assert.strictEqual(blocked.code, 'MISSING-VERSION-BUMP');
      const codes = new Set(blocked.breakingChanges.map((c) => c.code));
      for (const expected of ['PATH_REMOVED', 'AUTH_REMOVED', 'REQUIRED_PARAM_ADDED', 'RESPONSE_FIELD_REMOVED', 'TYPE_NARROWED', 'ENUM_VALUE_REMOVED']) {
        assert.ok(codes.has(expected), `Missing breaking rule: ${expected}`);
      }

      // Major bump 1.4.0 -> 2.0.0 passes!
      const breakingMajor = { ...breakingMinor, info: { title: 'Users API', version: '2.0.0' } };
      const allowedMajor = diffContracts({ format: 'openapi', baseSpec: baseOpenApi, revisionSpec: breakingMajor });
      assert.strictEqual(allowedMajor.allowed, true);
      assert.strictEqual(allowedMajor.code, 'MAJOR_VERSION_BUMP_ALLOWED');

      // Baseline + deploy gate + history persistence
      saveBaseline({ projectId: 'proj-users', format: 'openapi', version: '1.4.0', spec: baseOpenApi });
      const gateFail = evaluateDeployGate({ projectId: 'proj-users', format: 'openapi', revisionSpec: breakingMinor });
      assert.strictEqual(gateFail.allowed, false);
      assert.strictEqual(gateFail.code, 'MISSING-VERSION-BUMP');
      const gateOverride = evaluateDeployGate({
        projectId: 'proj-users',
        format: 'openapi',
        revisionSpec: breakingMinor,
        overrideReason: 'Emergency security sunset signed by SRE lead'
      });
      assert.strictEqual(gateOverride.allowed, true);
      assert.strictEqual(gateOverride.code, 'OVERRIDDEN_WITH_REASON');
      assert.ok(listContractHistory('proj-users').length >= 3);

      // GraphQL SDL breaking detection
      const baseGql = `
        enum Role { ADMIN MEMBER VIEWER }
        type User { id: ID! email: String! }
        type Query { users(limit: Int): [User!]! }
      `;
      const revGql = `
        enum Role { ADMIN MEMBER }
        type User { id: ID! }
        type Query { users(limit: Int!): [User!]! }
      `;
      const gqlDiff = diffContracts({ format: 'graphql', baseSpec: baseGql, revisionSpec: revGql });
      assert.strictEqual(gqlDiff.classification, 'BREAKING');
      assert.strictEqual(gqlDiff.allowed, false);
      const gqlCodes = new Set(gqlDiff.breakingChanges.map((c) => c.code));
      assert.ok(gqlCodes.has('FIELD_REMOVED'));
      assert.ok(gqlCodes.has('ARG_MADE_NON_NULL_WITHOUT_DEFAULT'));
      assert.ok(gqlCodes.has('ENUM_VALUE_REMOVED'));
    });

    // =========================================================================
    // 2. PURE-NODE OCI SIGNATURE & SLSA REKOR VERIFIER (CVE-2026-22703)
    // =========================================================================
    await runCase('2. ociSignatureVerifier verifies Ed25519 DSSE/SLSA+Rekor v2, blocks CVE-2026-22703 tampering & preserves tlsVerify', async () => {
      // Ephemeral Ed25519 keypair (never committed to disk as hardcoded PEM!)
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      const publicKeyPem = String(publicKey.export({ type: 'spki', format: 'pem' }));

      const rootRes = upsertTrustRoot({
        id: 'github-oidc-root',
        name: 'GitHub Actions SLSA Root',
        algorithm: 'ed25519',
        publicKeyPem,
        allowedBuilders: ['https://github.com/actions/runner']
      });
      assert.strictEqual(rootRes.ok, true);
      assert.strictEqual(listTrustRoots().length, 1);

      const digestA = 'a'.repeat(64);
      const digestB = 'b'.repeat(64);
      const imageRef = `ghcr.io/culkibo/api@sha256:${digestA}`;

      // Mutable tag MUST fail immediately
      const mutRes = verifyOciBundle({ imageRef: 'ghcr.io/culkibo/api:latest', bundle: {}, trustRootId: 'github-oidc-root' });
      assert.strictEqual(mutRes.verified, false);
      assert.strictEqual(mutRes.code, 'MUTABLE_TAG_FORBIDDEN');

      // Construct real signed DSSE SLSA v1.1 statement
      const payloadType = 'application/vnd.in-toto+json';
      const statement = {
        _type: 'https://in-toto.io/Statement/v1',
        subject: [{ name: 'ghcr.io/culkibo/api', digest: { sha256: digestA } }],
        predicateType: 'https://slsa.dev/provenance/v1',
        predicate: {
          runDetails: { builder: { id: 'https://github.com/actions/runner' } }
        }
      };
      const payloadBuf = Buffer.from(JSON.stringify(statement), 'utf8');
      const pae = computeDssePae(payloadType, payloadBuf);
      const sigB64 = crypto.sign(null, pae, privateKey).toString('base64');

      // 1. Valid Rekor v2 bound bundle -> VERIFIED
      const boundRekorBody = Buffer.from(JSON.stringify({
        spec: {
          data: { hash: { algorithm: 'sha256', value: digestA } },
          publicKeyFingerprint: rootRes.trustRoot.fingerprintSha256,
          signature: { content: sigB64 }
        }
      }), 'utf8').toString('base64');

      const validBundle = {
        mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.3',
        dsseEnvelope: { payloadType, payload: payloadBuf.toString('base64'), signatures: [{ sig: sigB64 }] },
        verificationMaterial: {
          tlogEntries: [{
            canonicalizedBody: boundRekorBody,
            signedTimestamp: '2026-11-28T00:00:00Z'
          }]
        }
      };

      const okRes = verifyOciBundle({ imageRef, bundle: validBundle, trustRootId: 'github-oidc-root', requireRekor: true });
      assert.strictEqual(okRes.verified, true);
      assert.strictEqual(okRes.code, 'VERIFIED');
      assert.strictEqual(okRes.rekorVersion, 'v2');

      // 2. CVE-2026-22703 Attack: valid DSSE signature + Rekor entry bound to UNRELATED digestB -> REKOR_DIGEST_MISMATCH!
      const tamperedRekorBody = Buffer.from(JSON.stringify({
        spec: {
          data: { hash: { algorithm: 'sha256', value: digestB } },
          publicKeyFingerprint: rootRes.trustRoot.fingerprintSha256,
          signature: { content: sigB64 }
        }
      }), 'utf8').toString('base64');

      const tamperedBundle = {
        ...validBundle,
        verificationMaterial: {
          tlogEntries: [{ canonicalizedBody: tamperedRekorBody, signedTimestamp: '2026-11-28T00:00:00Z' }]
        }
      };

      const attackBlocked = verifyOciBundle({ imageRef, bundle: tamperedBundle, trustRootId: 'github-oidc-root', requireRekor: true });
      assert.strictEqual(attackBlocked.verified, false);
      assert.strictEqual(attackBlocked.code, 'REKOR_DIGEST_MISMATCH');

      // 3. GHCR OCI 1.1 Referrers 404 fallback preserves tlsVerify: true
      const fallback = resolveReferrerStrategy({ referrersStatus: 404, digest: `sha256:${digestA}`, tlsVerify: true });
      assert.strictEqual(fallback.ok, true);
      assert.strictEqual(fallback.strategy, 'tag_fallback');
      assert.strictEqual(fallback.fallbackTag, `sha256-${digestA}.att`);
      assert.strictEqual(fallback.tlsVerify, true);
    });

    // =========================================================================
    // 3. DOCKER-29-IMMUNE ORPHANED PR-PREVIEW AUTO-REAPER
    // =========================================================================
    await runCase('3. orphanReaperService reaps closed-PR containers/volumes while shielding Compose sidecars & DB volumes', async () => {
      assert.strictEqual(DEFAULT_REAPER_POLICY.dryRunDefault, true);
      upsertReaperPolicy({ danglingImageMaxAgeHours: 48 });
      assert.strictEqual(getReaperPolicy().policy.danglingImageMaxAgeHours, 48);

      const scan = scanOrphans({
        activeProjects: ['myapp', 'billing'],
        activePreviews: [{ project: 'myapp', pr: 99 }],
        dockerSnapshot: {
          containers: [
            { id: 'c-closed-pr', name: 'myapp-pr-42', labels: { 'culkibo.managed': 'true', 'culkibo.project': 'myapp', 'culkibo.preview.pr': '42' }, sizeBytes: 150_000_000 },
            { id: 'c-ghost-parent', name: 'preview-shop-a9f2', labels: { 'culkibo.managed': 'true' }, sizeBytes: 90_000_000 },
            { id: 'c-active-pr', name: 'myapp-pr-99', labels: { 'culkibo.managed': 'true', 'culkibo.project': 'myapp', 'culkibo.preview.pr': '99' }, sizeBytes: 120_000_000 },
            { id: 'c-sidecar', name: 'myapp-backup-runner', labels: { 'com.docker.compose.project': 'myapp' }, sizeBytes: 60_000_000 }
          ],
          volumes: [
            { name: 'app-pr-42-pgdata', labels: { 'culkibo.project': 'myapp', 'culkibo.preview.pr': '42' }, sizeBytes: 500_000_000 },
            { name: 'prod-pgdata', labels: { 'culkibo.project': 'myapp', 'culkibo.protect': 'true' }, sizeBytes: 8_000_000_000 }
          ],
          images: [
            { id: 'img-sidecar', tag: 'myapp-backup-runner:local', labels: { 'com.docker.compose.project': 'myapp' }, inUseBySidecar: true, sizeBytes: 200_000_000 },
            { id: 'img-dangling', tag: '<none>:<none>', dangling: true, ageHours: 96, sizeBytes: 300_000_000 }
          ]
        }
      });

      const orphanNames = new Set(scan.orphans.map((o) => o.name));
      assert.ok(orphanNames.has('myapp-pr-42'), 'Closed PR container must be flagged orphan');
      assert.ok(orphanNames.has('preview-shop-a9f2'), 'Deleted-parent preview must be flagged orphan');
      assert.ok(orphanNames.has('app-pr-42-pgdata'), 'Leaked -pr-42 volume must be flagged orphan (coolify#11441)');
      assert.ok(orphanNames.has('<none>:<none>'), 'Aged dangling image must be flagged orphan');

      const protectedNames = new Set(scan.protected.map((p) => p.name));
      assert.ok(protectedNames.has('myapp-pr-99'), 'Active PR-99 container must be protected');
      assert.ok(protectedNames.has('myapp-backup-runner'), 'Active Compose sidecar must be protected');
      assert.ok(protectedNames.has('myapp-backup-runner:local'), 'Active Compose sidecar image must be protected (dokploy#3973)');
      assert.ok(protectedNames.has('prod-pgdata'), 'Production DB volume must be protected');

      // Plan & default dryRun: true execution
      const plan = planReap({ scanResult: scan, maxReapPerRun: 10 });
      assert.strictEqual(plan.actions.length, 4);
      // Order: containers before volumes before images
      assert.strictEqual(plan.actions[0].resourceType, 'container');
      assert.strictEqual(plan.actions[plan.actions.length - 1].resourceType, 'image');

      const dryExec = executeReap({ plan });
      assert.strictEqual(dryExec.dryRun, true);
      assert.strictEqual(dryExec.executedCount, 0);
      assert.ok(dryExec.estimatedReclaimableBytes > 1_000_000_000);

      // Live execution via injectable zero-shell argv executor
      /** @type {string[][]} */
      const executedArgvs = [];
      const liveExec = executeReap({
        plan,
        dryRun: false,
        executor: (argv) => executedArgvs.push(argv)
      });
      assert.strictEqual(liveExec.dryRun, false);
      assert.strictEqual(liveExec.executedCount, 4);
      assert.strictEqual(executedArgvs.length, 4);
      assert.ok(executedArgvs.every((argv) => Array.isArray(argv) && argv[0] === 'docker'));
    });

    console.log(`\n✅ API Contract Gate, OCI/SLSA Verifier & Orphan PR Reaper Suite: ${passed}/3 tests PASSED!`);
  } finally {
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ Contract/OCI/Orphan test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
