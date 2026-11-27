'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const admissionPolicyService = require('../server/services/admissionPolicyService');
const edgeExperimentService = require('../server/services/edgeExperimentService');
const caddyManager = require('../server/services/caddyManager');

const {
  AdmissionPolicyService,
  ADMISSION_RULES,
  POLICY_PRESETS,
  evaluateSpec
} = admissionPolicyService;

const {
  EdgeExperimentService,
  ISO_COUNTRY_CODES,
  compileGeoRoutes,
  compileAbExperimentRoute
} = edgeExperimentService;

async function testAdmissionPolicyService(tmpRoot) {
  assert.strictEqual(ADMISSION_RULES.length, 10);
  assert.ok(POLICY_PRESETS.baseline && POLICY_PRESETS.restricted && POLICY_PRESETS['soc2-strict']);

  const svc = new AdmissionPolicyService({ dataDir: path.join(tmpRoot, 'admission-data') });

  // 1. Adversarial deployment spec violating ALL critical CIS/PSS + Coolify + Dokploy rules
  const toxicSpec = {
    image: 'myapp:latest',
    privileged: true,
    user: '0:0',
    mounts: ['- /:/host:rw', '/var/run/docker.sock:/var/run/docker.sock'],
    capAdd: ['SYS_ADMIN', 'NET_ADMIN'],
    ports: ['0.0.0.0:5432:5432', '0.0.0.0:3000:3000']
  };

  // Baseline enforces 5 critical rules & audits the other 5
  const baseRes = svc.evaluateDeployment(toxicSpec, { preset: 'baseline' });
  assert.strictEqual(baseRes.allowed, false);
  assert.strictEqual(baseRes.decision, 'DENY');
  const baseEnforcedIds = baseRes.enforcedViolations.map((v) => v.id);
  assert.ok(baseEnforcedIds.includes('no_privileged'));
  assert.ok(baseEnforcedIds.includes('no_docker_sock_mount'));
  assert.ok(baseEnforcedIds.includes('no_host_root_mount'), 'Must block Coolify - /:/host:rw mount');
  assert.ok(baseEnforcedIds.includes('no_dangerous_caps'));
  assert.ok(baseEnforcedIds.includes('no_public_db_or_panel_bind'), 'Must block dokploy#2661 0.0.0.0:5432/3000');
  assert.strictEqual(baseRes.enforcedViolations.length, 5);
  assert.strictEqual(baseRes.auditWarnings.length, 5);
  assert.strictEqual(baseRes.score, 0);

  // Restricted enforces 9 rules (incl. :latest, UID 0, resource caps, healthcheck) and audits SLSA attestation
  const restRes = evaluateSpec(toxicSpec, { preset: 'restricted' });
  assert.strictEqual(restRes.allowed, false);
  assert.strictEqual(restRes.enforcedViolations.length, 9);
  assert.strictEqual(restRes.auditWarnings.length, 1);
  assert.strictEqual(restRes.auditWarnings[0].id, 'require_signed_attestation');

  // SOC2-Strict enforces ALL 10 rules
  const soc2Res = evaluateSpec(toxicSpec, { preset: 'soc2-strict' });
  assert.strictEqual(soc2Res.allowed, false);
  assert.strictEqual(soc2Res.enforcedViolations.length, 10);
  assert.strictEqual(soc2Res.auditWarnings.length, 0);

  // 2. Hardened production spec passes ALL 10 rules under soc2-strict (score 100, ALLOW)
  const hardenedSpec = {
    image: 'ghcr.io/acme/api:v2.4.1',
    privileged: false,
    user: '1000:1000',
    mounts: ['/srv/app-data:/data:rw'],
    capAdd: [],
    ports: ['127.0.0.1:5432:5432'],
    memoryLimitMb: 512,
    cpuLimit: 1.5,
    healthcheckPath: '/healthz',
    attestationVerified: true
  };
  const passSoc2 = svc.evaluateDeployment(hardenedSpec, { preset: 'soc2-strict' });
  assert.strictEqual(passSoc2.allowed, true);
  assert.strictEqual(passSoc2.decision, 'ALLOW');
  assert.strictEqual(passSoc2.score, 100);
  assert.strictEqual(passSoc2.passedRules.length, 10);

  // 3. Policy persistence & preset switching
  const applied = svc.applyPreset('restricted');
  assert.strictEqual(applied.preset, 'restricted');
  const reloaded = new AdmissionPolicyService({ dataDir: path.join(tmpRoot, 'admission-data') });
  assert.strictEqual(reloaded.getPolicy().preset, 'restricted');
  assert.throws(
    () => svc.applyPreset('nonexistent-preset'),
    (/** @type {any} */ err) => err && err.code === 'INVALID_PRESET'
  );

  console.log('  ✓ 1. Policy-as-Code Admission Engine: all 10 CIS/PSS rules across baseline/restricted/soc2-strict, Coolify -/:/host:rw, docker.sock, dokploy#2661 & persistence verified');
}

async function testEdgeExperimentAndCaddy(tmpRoot) {
  assert.ok(ISO_COUNTRY_CODES.has('DE') && ISO_COUNTRY_CODES.has('US') && !ISO_COUNTRY_CODES.has('ZZZ'));

  const svc = new EdgeExperimentService({ dataDir: path.join(tmpRoot, 'experiments-data') });

  // 1. Geo-IP validation & native Caddy v2.11 subroute compilation
  assert.throws(
    () => compileGeoRoutes({
      hostname: 'app.culkibo.dev',
      headerName: 'CF-IPCountry',
      regions: [{ countries: ['DE', 'ZZZ'], upstream: '10.88.0.2:3000' }],
      defaultUpstream: '10.88.0.1:3000'
    }),
    (/** @type {any} */ err) => err && err.code === 'INVALID_COUNTRY_CODE',
    'Invalid ISO country code ZZZ must be rejected'
  );
  assert.throws(
    () => compileGeoRoutes({
      hostname: 'app.culkibo.dev',
      headerName: 'X-Evil-Header',
      regions: [{ countries: ['DE'], upstream: '10.88.0.2:3000' }],
      defaultUpstream: '10.88.0.1:3000'
    }),
    (/** @type {any} */ err) => err && err.code === 'INVALID_GEO_HEADER'
  );

  const geoSubroutes = compileGeoRoutes({
    hostname: 'app.culkibo.dev',
    headerName: 'CF-IPCountry',
    regions: [
      { countries: ['de', 'fr', 'es'], upstream: '10.88.0.2:3000' },
      { countries: ['jp', 'sg'], upstream: '10.88.0.3:3000' }
    ],
    defaultUpstream: '10.88.0.1:3000'
  });
  assert.strictEqual(geoSubroutes.length, 3);
  assert.deepStrictEqual(geoSubroutes[0].match[0].header['CF-IPCountry'], ['DE', 'FR', 'ES']);
  assert.strictEqual(geoSubroutes[0].handle[0].upstreams[0].dial, '10.88.0.2:3000');
  assert.strictEqual(geoSubroutes[2].handle[0].upstreams[0].dial, '10.88.0.1:3000');

  // 2. Sticky Cookie & Header A/B Experiment validation, weight-sum != 100 rejection & kill-switch
  assert.throws(
    () => compileAbExperimentRoute({
      id: 'checkout_v2',
      hostname: 'shop.culkibo.dev',
      stickyMode: 'cookie',
      variants: [
        { name: 'control', upstream: '127.0.0.1:4001', weight: 60 },
        { name: 'treatment', upstream: '127.0.0.1:4002', weight: 30 } // sums to 90 != 100!
      ]
    }),
    (/** @type {any} */ err) => err && err.code === 'INVALID_WEIGHT_SUM',
    'Variant weights not summing to 100 MUST be rejected'
  );

  const created = svc.upsertExperiment({
    id: 'checkout_v2',
    projectId: 'proj_shop',
    hostname: 'shop.culkibo.dev',
    stickyMode: 'cookie',
    variants: [
      { name: 'control', upstream: '127.0.0.1:4001', weight: 80 },
      { name: 'treatment', upstream: '127.0.0.1:4002', weight: 20 }
    ]
  });
  assert.strictEqual(created.ok, true);
  const abPolicy = created.experiment.compiledCaddy.route.handle[0].load_balancing.selection_policy;
  assert.strictEqual(abPolicy.policy, 'cookie');
  assert.strictEqual(abPolicy.name, 'ckb_ab_checkout_v2');
  assert.deepStrictEqual(abPolicy.fallback, { policy: 'weighted_round_robin', weights: [80, 20] });

  // Header sticky mode compilation
  const headerRoute = compileAbExperimentRoute({
    id: 'pricing_test',
    hostname: 'shop.culkibo.dev',
    stickyMode: 'header',
    headerField: 'X-AB-Group',
    variants: [
      { name: 'control', upstream: '127.0.0.1:4001', weight: 50 },
      { name: 'treatment', upstream: '127.0.0.1:4002', weight: 50 }
    ]
  });
  assert.strictEqual(headerRoute.handle[0].load_balancing.selection_policy.policy, 'header');
  assert.strictEqual(headerRoute.handle[0].load_balancing.selection_policy.field, 'X-AB-Group');

  // 1-Click Kill-Switch reverts 100% to control upstream with zero split!
  const killed = svc.triggerKillSwitch('checkout_v2', { reason: 'conversion_drop' });
  assert.strictEqual(killed.killed, true);
  assert.strictEqual(killed.controlUpstream, '127.0.0.1:4001');
  const killedProxy = killed.experiment.compiledCaddy.route.handle[0];
  assert.deepStrictEqual(killedProxy.upstreams, [{ dial: '127.0.0.1:4001' }]);
  assert.strictEqual(killedProxy.load_balancing, undefined, 'Killed experiment must have zero traffic split');

  // 3. CaddyManager integration: geoRouting, edgeExperiment & exact backwards compatibility when unset
  const caddyGeo = caddyManager.buildRoute({
    projectId: 'proj_geo',
    hostnames: ['geo.culkibo.dev'],
    upstreams: ['10.88.0.1:3000'],
    geoRouting: {
      enabled: true,
      headerName: 'CF-IPCountry',
      regions: [{ countries: ['DE', 'FR'], upstream: '10.88.0.2:3000' }]
    }
  });
  assert.strictEqual(caddyGeo.handle[0].handler, 'subroute');
  assert.deepStrictEqual(caddyGeo.handle[0].routes[0].match[0].header['CF-IPCountry'], ['DE', 'FR']);

  const caddyAb = caddyManager.buildRoute({
    projectId: 'proj_ab',
    hostnames: ['ab.culkibo.dev'],
    upstreams: ['127.0.0.1:4001'],
    edgeExperiment: {
      enabled: true,
      id: 'hero_cta',
      stickyMode: 'cookie',
      variants: [
        { name: 'control', upstream: '127.0.0.1:4001', weight: 70 },
        { name: 'treatment', upstream: '127.0.0.1:4002', weight: 30 }
      ]
    }
  });
  assert.strictEqual(caddyAb.handle[0].handler, 'reverse_proxy');
  assert.strictEqual(caddyAb.handle[0].load_balancing.selection_policy.policy, 'cookie');
  assert.strictEqual(caddyAb.handle[0].load_balancing.selection_policy.name, 'ckb_ab_hero_cta');

  const caddyPlain = caddyManager.buildRoute({
    projectId: 'proj_plain',
    hostnames: ['plain.culkibo.dev'],
    upstreams: ['127.0.0.1:4001']
  });
  assert.strictEqual(caddyPlain.handle[0].handler, 'reverse_proxy');
  assert.strictEqual(caddyPlain.handle[0].load_balancing, undefined);

  console.log('  ✓ 2. Caddy v2.11 Geo-Routing & Sticky A/B Compiler: ISO-3166 country validation, 100% weight check, cookie/header policies, 1-click kill-switch & caddyManager integration verified');
}

async function runAdmissionAndExperimentsTests() {
  console.log('\n⚖️  Testing Policy-as-Code Admission Engine & Caddy Geo-Routing / Sticky A/B Experiments...\n');
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-cycle11-adm-exp-'));
  try {
    await testAdmissionPolicyService(tmpRoot);
    await testEdgeExperimentAndCaddy(tmpRoot);
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
  console.log('\n✅ All Policy-as-Code Admission & Edge Experiment tests PASSED!\n');
}

module.exports = runAdmissionAndExperimentsTests;

if (require.main === module) {
  runAdmissionAndExperimentsTests().catch((err) => {
    console.error('❌ Admission & Experiments test FAILED:', err);
    process.exit(1);
  });
}
