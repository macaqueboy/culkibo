const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { UptimeMonitor, buildGeoFailoverPlan } = require('../server/services/uptimeMonitor');
const { checkAllCaaRecords, getAcmeProfileSpec } = require('../server/services/ingressManager');
const { CaddyManager } = require('../server/services/caddyManager');

async function testUptimeMaintenanceCaa() {
  console.log('\n🧪 Testing Maintenance Windows (#7704/#8193), Incident Timeline, Multi-CAA (#6519), 6-Day shortlived ACME & Geo-Failover...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-maint-caa-'));
  const storeFile = path.join(tmpDir, 'uptime.json');
  const maintenanceFile = path.join(tmpDir, 'maintenance-incidents.json');

  try {
    const um = new UptimeMonitor({
      storeFile,
      maintenanceFile,
      autoStart: false
    });

    // -----------------------------------------------------------------------
    // 1. uptime-kuma#7704: Same-day recurring maintenance window fires on day 0
    // -----------------------------------------------------------------------
    const day0Start = Date.UTC(2026, 6, 10, 14, 0, 0); // 2026-07-10T14:00:00Z
    const sameDayWin = um.createMaintenanceWindow({
      title: 'Daily Hotfix Window',
      targetIds: ['mon_api_1'],
      kind: 'recurring',
      startAt: new Date(day0Start).toISOString(),
      durationMin: 60,
      intervalDays: 1
    });
    assert.ok(sameDayWin.id.startsWith('mw_'), 'Maintenance window should have mw_ id');
    assert.ok(fs.existsSync(maintenanceFile), 'maintenance-incidents.json must persist atomically inside isolated dir');

    // Before start -> false
    assert.strictEqual(um.isInMaintenance('mon_api_1', day0Start - 1000), false);
    // Day 0 same-day occurrence (k = 0) -> MUST be active (cures uptime-kuma#7704!)
    assert.strictEqual(um.isInMaintenance('mon_api_1', day0Start), true, 'Day 0 same-day window must fire at exact start');
    assert.strictEqual(um.isInMaintenance('mon_api_1', day0Start + 30 * 60 * 1000), true, 'Day 0 same-day window must be active mid-window');
    // After durationMin -> false
    assert.strictEqual(um.isInMaintenance('mon_api_1', day0Start + 60 * 60 * 1000), false, 'Window must end cleanly after durationMin');
    // Unrelated target -> false
    assert.strictEqual(um.isInMaintenance('mon_other', day0Start + 15 * 60 * 1000), false, 'Non-matching target must not be muted');
    // Day 1 next occurrence (k = 1) -> active again
    assert.strictEqual(um.isInMaintenance('mon_api_1', day0Start + 24 * 60 * 60 * 1000 + 10 * 60 * 1000), true);
    console.log('  ✓ uptime-kuma#7704: same-day recurring window fires dynamically on day 0 (k=0) and day 1 (k=1)');

    // -----------------------------------------------------------------------
    // 2. uptime-kuma#8193: Multi-day interval (>=2d) advances dynamically every cycle
    // -----------------------------------------------------------------------
    const multiStart = Date.UTC(2026, 6, 1, 3, 0, 0);
    const multiWin = um.createMaintenanceWindow({
      title: '3-Day DB Vacuum',
      targetIds: ['*'],
      kind: 'recurring',
      startAt: new Date(multiStart).toISOString(),
      durationMin: 45,
      intervalDays: 3
    });
    const DAY_MS = 24 * 60 * 60 * 1000;
    assert.strictEqual(um.isInMaintenance('mon_any', multiStart + 15 * 60 * 1000), true, 'Cycle k=0 active');
    assert.strictEqual(um.isInMaintenance('mon_any', multiStart + 1 * DAY_MS + 15 * 60 * 1000), false, 'Day +1 inactive');
    assert.strictEqual(um.isInMaintenance('mon_any', multiStart + 2 * DAY_MS + 15 * 60 * 1000), false, 'Day +2 inactive');
    assert.strictEqual(um.isInMaintenance('mon_any', multiStart + 3 * DAY_MS + 15 * 60 * 1000), true, 'Cycle k=1 (Day +3) active (cures #8193!)');
    assert.strictEqual(um.isInMaintenance('mon_any', multiStart + 6 * DAY_MS + 44 * 60 * 1000), true, 'Cycle k=2 (Day +6) active');
    assert.strictEqual(um.isInMaintenance('mon_any', multiStart + 6 * DAY_MS + 45 * 60 * 1000), false, 'Cycle k=2 ends after 45m');

    // Persistence reload check across fresh instance
    const umReloaded = new UptimeMonitor({ storeFile, maintenanceFile, autoStart: false });
    const reloadedList = umReloaded.listMaintenanceWindows({ nowMs: multiStart + 3 * DAY_MS + 10 * 60 * 1000 });
    assert.strictEqual(reloadedList.length, 2);
    assert.strictEqual(reloadedList.find((w) => w.id === multiWin.id).active, true);
    const delRes = umReloaded.deleteMaintenanceWindow(multiWin.id);
    assert.strictEqual(delRes.deleted, true);
    assert.strictEqual(umReloaded.listMaintenanceWindows().length, 1);
    console.log('  ✓ uptime-kuma#8193: multi-day interval (>=2d) progresses dynamically & persists atomically');

    // -----------------------------------------------------------------------
    // 3. Public Incident Timeline: investigating -> identified -> monitoring -> resolved
    // -----------------------------------------------------------------------
    const inc = um.createIncident({
      title: 'Elevated EU-West API Latency',
      severity: 'major',
      status: 'investigating',
      affectedIds: ['mon_api_1'],
      message: 'Investigating increased p95 response times on EU edge.'
    });
    assert.ok(inc.id.startsWith('tinc_'));
    assert.strictEqual(inc.status, 'investigating');
    assert.strictEqual(inc.resolvedAt, null);
    assert.strictEqual(inc.updates.length, 1);

    const incId = um.updateIncident(inc.id, {
      status: 'identified',
      message: 'Root cause isolated to upstream connection pool saturation.'
    });
    assert.strictEqual(incId.status, 'identified');
    assert.strictEqual(incId.updates.length, 2);

    const incMon = um.updateIncident(inc.id, {
      status: 'monitoring',
      message: 'PgBouncer transaction pool deployed; observing recovery.'
    });
    assert.strictEqual(incMon.status, 'monitoring');
    assert.strictEqual(incMon.updates.length, 3);
    assert.strictEqual(um.listIncidents({ activeOnly: true }).some((i) => i.id === inc.id), true);

    const incRes = um.updateIncident(inc.id, {
      status: 'resolved',
      message: 'Latency fully normalized for 15 minutes.'
    });
    assert.strictEqual(incRes.status, 'resolved');
    assert.ok(incRes.resolvedAt, 'resolvedAt must be populated upon resolution');
    assert.strictEqual(incRes.updates.length, 4);
    assert.strictEqual(um.listIncidents({ activeOnly: true }).some((i) => i.id === inc.id), false, 'Resolved incident excluded when activeOnly=true');
    assert.strictEqual(um.listIncidents({ activeOnly: false }).some((i) => i.id === inc.id), true);
    console.log('  ✓ Incident Timeline: investigating → identified → monitoring → resolved + activeOnly filter');

    // -----------------------------------------------------------------------
    // 4. uptime-kuma#6519: Multi-CAA Pre-Flight checks EVERY record (not just [0])
    // -----------------------------------------------------------------------
    const multiCaaOk = await checkAllCaaRecords('app.example.test', {
      expectedCa: 'letsencrypt.org',
      resolveCaaImpl: async () => [
        { critical: 0, issue: 'digicert.com' },
        { critical: 0, issue: 'letsencrypt.org; validationmethods=http-01' },
        { critical: 0, iodef: 'mailto:sec@example.test' }
      ]
    });
    assert.strictEqual(multiCaaOk.allowed, true, 'Must PASS when record [1] authorizes letsencrypt.org (cures #6519!)');
    assert.strictEqual(multiCaaOk.recordsCount, 3);
    assert.strictEqual(multiCaaOk.matchingRecords.length, 1);
    assert.strictEqual(multiCaaOk.blockingRecords.length, 1);

    const multiCaaBlocked = await checkAllCaaRecords('strict.example.test', {
      expectedCa: 'letsencrypt.org',
      resolveCaaImpl: async () => [
        { critical: 0, issue: 'digicert.com' },
        { critical: 0, issue: 'sectigo.com' }
      ]
    });
    assert.strictEqual(multiCaaBlocked.allowed, false, 'Must FAIL when no CAA record authorizes letsencrypt.org');
    assert.strictEqual(multiCaaBlocked.matchingRecords.length, 0);
    assert.strictEqual(multiCaaBlocked.blockingRecords.length, 2);

    const noCaaAllowed = await checkAllCaaRecords('open.example.test', {
      expectedCa: 'letsencrypt.org',
      resolveCaaImpl: async () => {
        const err = new Error('queryCaa ENODATA');
        /** @type {any} */ (err).code = 'ENODATA';
        throw err;
      }
    });
    assert.strictEqual(noCaaAllowed.allowed, true, 'ENODATA (no CAA published) must allow issuance per RFC 8659');
    assert.strictEqual(noCaaAllowed.recordsCount, 0);
    console.log('  ✓ uptime-kuma#6519: Multi-CAA pre-flight inspects all records ([1] passes, non-matching blocks, ENODATA allows)');

    // -----------------------------------------------------------------------
    // 5. caddy#7670: Let's Encrypt 6-day (160h) shortlived ACME profile & ECH QUIC
    // -----------------------------------------------------------------------
    const shortSpec = getAcmeProfileSpec('shortlived', { echEnabled: true });
    assert.strictEqual(shortSpec.profile, 'shortlived');
    assert.strictEqual(shortSpec.validityHours, 160);
    assert.strictEqual(shortSpec.validityDays, 6);
    assert.strictEqual(shortSpec.caddyIssuerProfile, 'shortlived');
    assert.strictEqual(shortSpec.echQuicCheck.enabled, true);
    assert.strictEqual(shortSpec.echQuicCheck.requiresHttp3Udp443, true);

    const cm = new CaddyManager();
    const defaultTls = cm.buildTlsApp({ askEndpoint: 'http://127.0.0.1:3030/api/ingress/ask' });
    const defaultAcme = defaultTls.automation.policies[0].issuers.find((i) => i.module === 'acme');
    assert.strictEqual(defaultAcme.profile, undefined, 'Default TLS config must omit profile for backwards compatibility');

    const shortTls = cm.buildTlsApp({
      askEndpoint: 'http://127.0.0.1:3030/api/ingress/ask',
      acmeProfile: 'shortlived',
      wildcardPolicies: [{ rootDomain: 'edge.example.test', provider: 'cloudflare', tokenEnv: 'CF_API_TOKEN', acmeProfile: 'shortlived' }]
    });
    const wcAcme = shortTls.automation.policies[0].issuers[0];
    const catchAllAcme = shortTls.automation.policies[1].issuers.find((i) => i.module === 'acme');
    assert.strictEqual(wcAcme.profile, 'shortlived', 'Wildcard ACME issuer must emit profile: shortlived');
    assert.strictEqual(catchAllAcme.profile, 'shortlived', 'On-demand ACME issuer must emit profile: shortlived');
    console.log('  ✓ caddy#7670: 6-day (160h) shortlived ACME spec + Caddy issuer profile emitted cleanly');

    // -----------------------------------------------------------------------
    // 6. Active-Passive Cloudflare DNS Geo-Failover Plan
    // -----------------------------------------------------------------------
    const plan = buildGeoFailoverPlan({
      domain: 'api.example.test',
      primaryIp: '203.0.113.10',
      secondaryIp: '198.51.100.20',
      consecutiveFailures: 3,
      ttlSec: 60
    });
    assert.strictEqual(plan.ok, true);
    assert.strictEqual(plan.provider, 'cloudflare');
    assert.strictEqual(plan.recordType, 'A');
    assert.strictEqual(plan.ttlSec, 60);
    assert.strictEqual(plan.trigger.consecutiveFailures, 3);
    assert.strictEqual(plan.primary.ip, '203.0.113.10');
    assert.strictEqual(plan.secondary.ip, '198.51.100.20');
    assert.strictEqual(plan.steps.length, 4);
    assert.strictEqual(plan.steps[1].action, 'dns_update');
    assert.strictEqual(plan.steps[1].to, '198.51.100.20');
    assert.strictEqual(plan.rollback.to, '203.0.113.10');

    // Rejects invalid / identical / metadata IPs
    assert.throws(
      () => buildGeoFailoverPlan({ domain: 'api.example.test', primaryIp: '203.0.113.10', secondaryIp: '203.0.113.10' }),
      /iguales/i
    );
    assert.throws(
      () => buildGeoFailoverPlan({ domain: 'api.example.test', primaryIp: '169.254.169.254', secondaryIp: '198.51.100.20' }),
      /metadatos/i
    );
    console.log('  ✓ Geo-Failover Plan: Active-Passive Cloudflare DNS cutover + rollback + IP safety validation');

    console.log('✅ Uptime Maintenance, Incident Timeline, Multi-CAA & 6-Day ACME suite passed!\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  testUptimeMaintenanceCaa()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ Uptime Maintenance / CAA suite failed:', err);
      process.exit(1);
    });
}

module.exports = testUptimeMaintenanceCaa;
