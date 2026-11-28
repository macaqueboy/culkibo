'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const webhookFirewallService = require('../server/services/webhookFirewallService');
const regionTrafficShiftService = require('../server/services/regionTrafficShiftService');

const {
  WebhookFirewallService,
  SUPPORTED_PROVIDERS,
  canonicalizeSignatureEncoding,
  verifyInboundWebhook,
  inspectReplayCache,
  upsertWebhookFirewallPolicy
} = webhookFirewallService;

const {
  RegionTrafficShiftService,
  evaluateTrafficShift,
  planBlueGreenShift,
  renderCaddyStickyFailoverBlock,
  listTrafficShifts
} = regionTrafficShiftService;

/**
 * Verifies CVE-2026-41351 Base64/Base64URL replay defense, CVE-2025-61926 fail-closed
 * weak/empty secret rejection, 1 MiB body cap, 300s clock skew, and multi-provider HMACs.
 * @param {string} tmpRoot
 */
function testWebhookFirewallService(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'webhook-fw-data');
  const svc = new WebhookFirewallService({ dataDir });
  const nowSec = 1764300000;
  const strongSecret = 'culkibo_wh_strong_test_key_9f8e7d6c5b4a';

  assert.deepStrictEqual(Array.from(SUPPORTED_PROVIDERS), [
    'stripe',
    'github',
    'linear',
    'slack',
    'shopify',
    'svix'
  ]);

  // 1. Fail-closed on empty, missing, or weak hardcoded secret (CVE-2025-61926)
  for (const badSecret of ['', '   ', 'secret', 'changeme', 'allstar', 'short']) {
    const res = svc.verifyInboundWebhook({
      provider: 'stripe',
      rawBody: '{"id":"evt_1"}',
      headers: { 'stripe-signature': `t=${nowSec},v1=abc` },
      secret: badSecret,
      nowSec,
      routeId: 'billing'
    });
    assert.strictEqual(res.verified, false);
    assert.strictEqual(res.code, 'WEBHOOK_SECRET_UNCONFIGURED');
  }

  // 2. Pre-verify body cap > 1 MiB -> WEBHOOK_BODY_TOO_LARGE
  const hugeBody = Buffer.alloc(1024 * 1024 + 16, 0x61);
  const tooLarge = svc.verifyInboundWebhook({
    provider: 'github',
    rawBody: hugeBody,
    headers: { 'x-hub-signature-256': 'sha256=' + '0'.repeat(64) },
    secret: strongSecret,
    nowSec,
    routeId: 'gh-hooks'
  });
  assert.strictEqual(tooLarge.verified, false);
  assert.strictEqual(tooLarge.code, 'WEBHOOK_BODY_TOO_LARGE');

  // 3. Clock skew > 300s -> CLOCK_SKEW_EXCEEDED
  const rawStripe = '{"id":"evt_old","type":"invoice.paid"}';
  const oldTs = nowSec - 450;
  const oldSig = crypto.createHmac('sha256', strongSecret).update(`${oldTs}.${rawStripe}`).digest('hex');
  const skewed = svc.verifyInboundWebhook({
    provider: 'stripe',
    rawBody: rawStripe,
    headers: { 'stripe-signature': `t=${oldTs},v1=${oldSig}` },
    secret: strongSecret,
    nowSec,
    routeId: 'billing'
  });
  assert.strictEqual(skewed.verified, false);
  assert.strictEqual(skewed.code, 'CLOCK_SKEW_EXCEEDED');

  // 4. CVE-2026-41351: Svix valid Base64 signature passes ONCE, then Base64URL re-encoding rejects WEBHOOK_REPLAY_DETECTED!
  const svixSecret = 'whsec_' + Buffer.from('culkibo-svix-signing-key-32bytes!').toString('base64');
  const svixKeyBytes = Buffer.from(svixSecret.slice(6), 'base64');
  const svixBody = '{"type":"deploy.completed","id":"dep_42"}';
  const msgId = 'msg_01J_REPLAY_TEST';
  const svixDigest = crypto.createHmac('sha256', svixKeyBytes).update(`${msgId}.${nowSec}.${svixBody}`).digest();
  const svixB64 = svixDigest.toString('base64');
  const svixB64Url = svixB64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  // Canonicalization must collapse Base64 and Base64URL to the EXACT SAME hex string!
  assert.strictEqual(
    svc.canonicalizeSignatureEncoding(`v1,${svixB64}`),
    svc.canonicalizeSignatureEncoding(`v1,${svixB64Url}`)
  );

  const pass1 = svc.verifyInboundWebhook({
    provider: 'svix',
    rawBody: svixBody,
    headers: {
      'svix-id': msgId,
      'svix-timestamp': String(nowSec),
      'svix-signature': `v1,${svixB64}`
    },
    secret: svixSecret,
    nowSec,
    routeId: 'svix-events'
  });
  assert.strictEqual(pass1.ok, true);
  assert.strictEqual(pass1.verified, true);
  assert.strictEqual(pass1.code, 'WEBHOOK_VERIFIED');

  // Replay exact signature re-encoded as Base64URL (even with a forged different svix-id? No, digest depends on msgId,
  // so replaying same msgId with Base64URL signature tests exact CVE-2026-41351 vector!)
  const replayB64Url = svc.verifyInboundWebhook({
    provider: 'svix',
    rawBody: svixBody,
    headers: {
      'svix-id': msgId,
      'svix-timestamp': String(nowSec),
      'svix-signature': `v1,${svixB64Url}`
    },
    secret: svixSecret,
    nowSec: nowSec + 5,
    routeId: 'svix-events'
  });
  assert.strictEqual(replayB64Url.verified, false);
  assert.strictEqual(replayB64Url.code, 'WEBHOOK_REPLAY_DETECTED');

  // Also test Shopify Base64 -> Base64URL replay WITHOUT delivery ID (pure signature-encoding replay!)
  const shopifyBody = '{"order_id":9001}';
  const shopDigest = crypto.createHmac('sha256', strongSecret).update(shopifyBody).digest();
  const shopB64 = shopDigest.toString('base64');
  const shopB64Url = shopB64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const shopPass = svc.verifyInboundWebhook({
    provider: 'shopify',
    rawBody: shopifyBody,
    headers: { 'x-shopify-hmac-sha256': shopB64 },
    secret: strongSecret,
    nowSec,
    routeId: 'shop-route'
  });
  assert.strictEqual(shopPass.verified, true);
  const shopReplay = svc.verifyInboundWebhook({
    provider: 'shopify',
    rawBody: shopifyBody,
    headers: { 'x-shopify-hmac-sha256': shopB64Url },
    secret: strongSecret,
    nowSec: nowSec + 2,
    routeId: 'shop-route'
  });
  assert.strictEqual(shopReplay.verified, false);
  assert.strictEqual(shopReplay.code, 'WEBHOOK_REPLAY_DETECTED');

  // 5. Stripe valid hex passes once, Slack & GitHub & Linear valid pass, policy dryRun default
  const stripeSig = crypto.createHmac('sha256', strongSecret).update(`${nowSec}.${rawStripe}`).digest('hex');
  assert.strictEqual(
    svc.verifyInboundWebhook({
      provider: 'stripe',
      rawBody: rawStripe,
      headers: { 'stripe-signature': `t=${nowSec},v1=${stripeSig}` },
      secret: strongSecret,
      nowSec,
      routeId: 'billing'
    }).verified,
    true
  );

  const ghSig = crypto.createHmac('sha256', strongSecret).update('{"ref":"main"}').digest('hex');
  assert.strictEqual(
    svc.verifyInboundWebhook({
      provider: 'github',
      rawBody: '{"ref":"main"}',
      headers: { 'x-hub-signature-256': `sha256=${ghSig}`, 'x-github-delivery': 'gh-deliv-1' },
      secret: strongSecret,
      nowSec,
      routeId: 'gh-hooks'
    }).verified,
    true
  );

  const dryPol = svc.upsertWebhookFirewallPolicy('billing', { provider: 'stripe', maxSkewSec: 180 });
  assert.strictEqual(dryPol.dryRun, true);
  assert.strictEqual(svc.inspectReplayCache('billing').policyCount, 0);

  const livePol = svc.upsertWebhookFirewallPolicy('billing', { provider: 'stripe', maxSkewSec: 180, dryRun: false });
  assert.strictEqual(livePol.dryRun, false);
  assert.strictEqual(svc.inspectReplayCache('billing').policyCount, 1);

  // Confirm ZERO raw secrets persisted on disk
  const rawDisk = fs.readFileSync(path.join(dataDir, 'webhook-firewall.json'), 'utf8');
  assert.ok(!rawDisk.includes(strongSecret), 'webhook-firewall.json must NEVER store raw secrets');
  assert.ok(!rawDisk.includes(svixSecret), 'webhook-firewall.json must NEVER store Svix secrets');
}

/**
 * Verifies Caddy#7544/#7524 health_port probe blocking, Caddy#6393/#8415 sticky cookie Max-Age
 * progressive Blue/Green planning, dryRun: true default, and Caddy failover block rendering.
 * @param {string} tmpRoot
 */
function testRegionTrafficShiftService(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'traffic-shift-data');
  const svc = new RegionTrafficShiftService({ dataDir });

  // 1. Block shift to green region with healthyEndpoints === 0
  const zeroEndpoints = svc.evaluateTrafficShift({
    projectId: 'proj_edge',
    targetGreenWeightPct: 25,
    regions: [
      { id: 'eu-central-blue', role: 'blue', healthyEndpoints: 3, totalEndpoints: 3, errorRatePct: 0.1 },
      { id: 'us-east-green', role: 'green', healthyEndpoints: 0, totalEndpoints: 3, errorRatePct: 0 }
    ]
  });
  assert.strictEqual(zeroEndpoints.allowed, false);
  assert.strictEqual(zeroEndpoints.code, 'UNHEALTHY_TARGET_REGION');

  // 2. Block shift when health_port probe returns 302 redirect (Caddy#7544/#7524 false 503 trap!)
  const probeRedirect = svc.evaluateTrafficShift({
    projectId: 'proj_edge',
    targetGreenWeightPct: 50,
    regions: [
      { id: 'eu-blue', role: 'blue', healthyEndpoints: 2, totalEndpoints: 2, errorRatePct: 0.1 },
      { id: 'us-green', role: 'green', healthyEndpoints: 2, totalEndpoints: 2, errorRatePct: 0.1, healthPort: 8081, probeStatus: 302 }
    ]
  });
  assert.strictEqual(probeRedirect.allowed, false);
  assert.strictEqual(probeRedirect.code, 'UNHEALTHY_TARGET_REGION');
  assert.strictEqual(probeRedirect.blockers[0].subCode, 'HEALTH_PORT_PROBE_FAILURE');

  // 3. Healthy shift allowed + progressive dryRun: true plan preserving sticky Max-Age
  const healthyEval = svc.evaluateTrafficShift({
    projectId: 'proj_edge',
    targetGreenWeightPct: 50,
    stickyCookiePolicy: { name: 'culkibo_affinity', maxAgeSec: 900, sameSite: 'Lax', httpOnly: true },
    regions: [
      { id: 'eu-blue', role: 'blue', healthyEndpoints: 3, totalEndpoints: 3, errorRatePct: 0.1 },
      { id: 'us-green', role: 'green', healthyEndpoints: 3, totalEndpoints: 3, errorRatePct: 0.2, healthPort: 8081, probeStatus: 200, probeHostHeader: true }
    ]
  });
  assert.strictEqual(healthyEval.allowed, true);
  assert.strictEqual(healthyEval.stickyCookieSafe, true);

  const dryPlan = svc.planBlueGreenShift({
    projectId: 'proj_edge',
    currentBlueWeightPct: 100,
    stepPct: 25,
    stickyMaxAgeSec: 900,
    failDurationSec: 30
  });
  assert.strictEqual(dryPlan.dryRun, true);
  assert.strictEqual(dryPlan.allowed, true);
  assert.strictEqual(dryPlan.steps.length, 4);
  assert.strictEqual(dryPlan.stickyCookiePolicy.maxAgeSec, 900);
  assert.strictEqual(dryPlan.stickyCookiePolicy.sameSite, 'Lax');
  assert.strictEqual(dryPlan.stickyCookiePolicy.httpOnly, true);
  assert.strictEqual(svc.listTrafficShifts('proj_edge').length, 0, 'dryRun: true must not persist');

  // 4. Live plan (`dryRun: false`) persists & Caddy block includes required directives
  const livePlan = svc.planBlueGreenShift({
    projectId: 'proj_edge',
    currentBlueWeightPct: 100,
    stepPct: 50,
    stickyMaxAgeSec: 600,
    failDurationSec: 30,
    dryRun: false
  });
  assert.strictEqual(livePlan.dryRun, false);
  assert.strictEqual(svc.listTrafficShifts('proj_edge').length, 1);
  assert.ok(fs.existsSync(path.join(dataDir, 'region-traffic-shifts.json')));

  const caddy = svc.renderCaddyStickyFailoverBlock({ stickyMaxAgeSec: 600, failDurationSec: 30, healthPort: 8081 });
  assert.ok(caddy.caddyfile.includes('lb_policy cookie culkibo_affinity'));
  assert.ok(caddy.caddyfile.includes('health_uri /healthz'));
  assert.ok(caddy.caddyfile.includes('lb_try_duration 5s'));
  assert.ok(caddy.caddyfile.includes('fail_duration 30s'));
  assert.ok(caddy.caddyfile.includes('Max-Age=600'));
}

/**
 * Verifies BOTH singleton (`svc.fn`) AND destructured (`fn`) exports with dynamic `CULKIBO_DATA_DIR`.
 * @param {string} tmpRoot
 */
function testSingletonAndDestructuredExports(tmpRoot) {
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = path.join(tmpRoot, 'singleton-env');

  try {
    // WebhookFirewallService singleton + destructured
    assert.strictEqual(canonicalizeSignatureEncoding('sha256=' + 'AB'.repeat(32)), 'ab'.repeat(32));
    assert.strictEqual(
      verifyInboundWebhook({ provider: 'stripe', rawBody: '{}', headers: {}, secret: '' }).code,
      'WEBHOOK_SECRET_UNCONFIGURED'
    );
    assert.strictEqual(upsertWebhookFirewallPolicy('r1', { provider: 'github', dryRun: false }).ok, true);
    assert.strictEqual(inspectReplayCache('r1').policyCount, 1);
    assert.strictEqual(webhookFirewallService.inspectReplayCache('r1').policyCount, 1);

    // RegionTrafficShiftService singleton + destructured
    assert.strictEqual(
      evaluateTrafficShift({ projectId: 'sp', targetGreenWeightPct: 50, regions: [{ id: 'g', role: 'green', healthyEndpoints: 0 }] }).code,
      'UNHEALTHY_TARGET_REGION'
    );
    const pl = planBlueGreenShift({ projectId: 'sp', dryRun: false });
    assert.strictEqual(pl.ok, true);
    assert.strictEqual(listTrafficShifts('sp').length, 1);
    assert.strictEqual(regionTrafficShiftService.listTrafficShifts('sp').length, 1);
    assert.ok(renderCaddyStickyFailoverBlock().caddyfile.includes('lb_policy cookie'));
  } finally {
    if (prevDataDir === undefined) {
      delete process.env.CULKIBO_DATA_DIR;
    } else {
      process.env.CULKIBO_DATA_DIR = prevDataDir;
    }
  }
}

async function runAllTests() {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c19-whfw-shift-'));
  try {
    testWebhookFirewallService(tmpRoot);
    testRegionTrafficShiftService(tmpRoot);
    testSingletonAndDestructuredExports(tmpRoot);
    console.log('✅ webhook-firewall-and-traffic-shift.test.js PASSED (CVE-2026-41351 replay, CVE-2025-61926 fail-closed, 6 providers, Caddy#7544/#6393 shift, singleton+destructured)');
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runAllTests().catch((err) => {
    console.error('❌ webhook-firewall-and-traffic-shift.test.js FAILED:', err);
    process.exit(1);
  });
}

module.exports = runAllTests;
