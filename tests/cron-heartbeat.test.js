'use strict';

const assert = require('assert');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const { CronManager } = require('../server/services/cronManager');

async function testCronHeartbeat() {
  console.log('\n🧪 Testing Cron 24h Visual Collision Heatmap & Dead-Man\'s-Switch Heartbeats...');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-cron-hb-'));
  const cronsFile = path.join(tmpDir, 'crons.json');
  const hbFile = path.join(tmpDir, 'heartbeats.json');

  try {
    const cm = new CronManager(cronsFile, { heartbeatsFile: hbFile });
    // Prevent real background interval timer during unit tests
    cm.startScheduler = () => {};

    // -----------------------------------------------------------------------
    // 1. 24h Timeline Projection & 5-Minute Heavy-IO Collision Detection
    // -----------------------------------------------------------------------
    cm.create('proj_alpha', {
      name: 'Nightly Analytics Rollup',
      schedule: '0 3 * * *',
      mode: 'exec',
      command: 'node scripts/rollup.js'
    });
    cm.create('proj_beta', {
      name: 'Search Index Rebuild',
      schedule: '2 3 * * *',
      mode: 'exec',
      command: 'node scripts/reindex.js'
    });
    cm.create('proj_gamma', {
      name: 'Midday Health Ping',
      schedule: '30 12 * * *',
      mode: 'http',
      httpPath: '/health'
    });

    const baseNowMs = new Date(2026, 5, 1, 0, 0, 0, 0).getTime(); // Local midnight so 03:00 -> slot 3, 12:30 -> slot 12 in any timezone
    const timeline = cm.getTimeline({
      hours: 24,
      nowMs: baseNowMs,
      databases: [
        {
          id: 'db_pg_main',
          projectId: 'proj_alpha',
          name: 'Main Postgres',
          schedule: { enabled: true, cron: '3 3 * * *' }
        }
      ]
    });

    assert.strictEqual(timeline.hours, 24);
    assert.strictEqual(timeline.slots.length, 24);
    assert.strictEqual(timeline.jobCount, 4, 'Must combine 3 project crons + 1 DB backup schedule');
    assert.strictEqual(timeline.totalScheduledRuns, 4);
    assert.strictEqual(timeline.slots[3].count, 3, '03:00..03:03 jobs must bucket into hour slot 3');
    assert.strictEqual(timeline.slots[12].count, 1, '12:30 job must bucket into hour slot 12');
    assert.ok(timeline.collisionWarnings.length >= 1, 'Must detect >=2 jobs overlapping within same 5-min window');
    assert.strictEqual(timeline.collisionWarnings[0].count, 3);
    assert.strictEqual(timeline.collisionWarnings[0].severity, 'high');

    // Scoped projectIds filter isolates timeline strictly
    const scopedTl = cm.getTimeline({
      hours: 24,
      nowMs: baseNowMs,
      projectIds: ['proj_gamma'],
      includeDatabases: false
    });
    assert.strictEqual(scopedTl.jobCount, 1);
    assert.strictEqual(scopedTl.collisionWarnings.length, 0);
    console.log('  ✓ 1. Cron 24h timeline buckets hourly slots, merges DB backup schedules & detects 5-min IO collisions');

    // -----------------------------------------------------------------------
    // 2. Dead-Man's-Switch Heartbeats: create -> start -> ok -> missed -> auto-resolve -> fail
    // -----------------------------------------------------------------------
    const hb = cm.createHeartbeat({
      name: 'Nightly Offsite Backup',
      projectId: 'proj_alpha',
      periodSec: 3600,
      graceSec: 300
    });
    assert.ok(hb.id.startsWith('hb_'));
    assert.strictEqual(hb.token.length, 48, '24-byte hex token must be 48 hex chars');
    assert.strictEqual(hb.pingUrl, `/api/heartbeat/${hb.token}`);
    assert.strictEqual(hb.status, 'new');
    assert.strictEqual(hb.lastPingAt, null);
    assert.ok(fs.existsSync(hbFile), 'heartbeats.json must persist inside isolated tmpDir');

    // Unknown token rejected with 404 (constant-time lookup)
    const badPing = cm.recordPing('0'.repeat(48));
    assert.strictEqual(badPing.ok, false);
    assert.strictEqual(badPing.status, 404);

    // State: start -> ok computes lastDurationMs & sets status 'up'
    const t0 = 1780000000000;
    const startRes = cm.recordPing(hb.token, { state: 'start', message: 'starting dump', nowMs: t0 });
    assert.strictEqual(startRes.ok, true);
    assert.strictEqual(startRes.heartbeat.status, 'running');

    const okRes = cm.recordPing(hb.token, { state: 'ok', message: 'dump uploaded 120MB', nowMs: t0 + 4250 });
    assert.strictEqual(okRes.ok, true);
    assert.strictEqual(okRes.heartbeat.status, 'up');
    assert.strictEqual(okRes.heartbeat.lastDurationMs, 4250);
    assert.strictEqual(okRes.heartbeat.lastMessage, 'dump uploaded 120MB');

    // Within period + grace -> NOT missed
    const onTime = cm.checkMissedHeartbeats(t0 + 4250 + (3600 + 299) * 1000);
    assert.strictEqual(onTime.missed.length, 0);

    // Past period + grace -> marked 'missed' & fires alert ONCE (deduplicated)
    /** @type {any[]} */
    const firedAlerts = [];
    const missed1 = cm.checkMissedHeartbeats(t0 + 4250 + (3600 + 305) * 1000, {
      onAlert: (inc) => firedAlerts.push(inc)
    });
    assert.strictEqual(missed1.missed.length, 1);
    assert.strictEqual(missed1.missed[0].deduplicated, false);
    assert.strictEqual(firedAlerts.length, 1);
    assert.strictEqual(cm.getHeartbeatById(hb.id).status, 'missed');

    const missed2 = cm.checkMissedHeartbeats(t0 + 4250 + (3600 + 600) * 1000, {
      onAlert: (inc) => firedAlerts.push(inc)
    });
    assert.strictEqual(missed2.missed.length, 1);
    assert.strictEqual(missed2.missed[0].deduplicated, true);
    assert.strictEqual(firedAlerts.length, 1, 'Missed alert must be deduplicated until recovery');

    // Subsequent ok ping auto-resolves active missed alert
    const recovered = cm.recordPing(hb.token, { state: 'ok', message: 'recovered', nowMs: t0 + 4250 + 4300 * 1000 });
    assert.strictEqual(recovered.ok, true);
    assert.strictEqual(recovered.autoResolved, true);
    assert.strictEqual(recovered.heartbeat.status, 'up');
    assert.strictEqual(recovered.heartbeat.alertActive, false);

    // Explicit fail state sets status 'down' and alertActive true
    const failed = cm.recordPing(hb.token, { state: 'fail', message: 'pg_dump exit 2', nowMs: t0 + 4250 + 4400 * 1000 });
    assert.strictEqual(failed.ok, true);
    assert.strictEqual(failed.heartbeat.status, 'down');
    assert.strictEqual(failed.heartbeat.alertActive, true);

    // Persistence reload check
    const cmReload = new CronManager(cronsFile, { heartbeatsFile: hbFile });
    assert.strictEqual(cmReload.listHeartbeats().length, 1);
    assert.strictEqual(cmReload.listHeartbeats()[0].status, 'down');
    console.log('  ✓ 2. Dead-Man\'s-Switch Heartbeats: create, start/ok duration, missed dedupe, auto-resolve, fail & atomic reload verified');

    // -----------------------------------------------------------------------
    // 3. Live Unauthenticated HTTP `/api/heartbeat/:token[/:state]` check-in
    // -----------------------------------------------------------------------
    const express = require('express');
    const app = express();
    app.use(express.json());
    const handler = (req, res) => {
      const state = req.params.state ? String(req.params.state) : 'ok';
      const msg = (req.body && req.body.message) || (req.query && req.query.msg) || '';
      const r = cm.recordPing(req.params.token, { state, message: String(msg) });
      res.status(r.status || 200).json(r);
    };
    app.get('/api/heartbeat/:token', handler);
    app.post('/api/heartbeat/:token', handler);
    app.get('/api/heartbeat/:token/:state', handler);
    app.post('/api/heartbeat/:token/:state', handler);

    const srv = await new Promise((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const port = srv.address().port;
    const reqJson = (method, pth, body) => new Promise((resolve, reject) => {
      const raw = body !== undefined ? JSON.stringify(body) : null;
      const headers = raw ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(raw) } : {};
      const r = http.request({ hostname: '127.0.0.1', port, method, path: pth, headers }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
      });
      r.on('error', reject);
      if (raw) r.write(raw);
      r.end();
    });

    try {
      const rStart = await reqJson('POST', `/api/heartbeat/${hb.token}/start`, { message: 'http start' });
      assert.strictEqual(rStart.status, 200);
      assert.strictEqual(rStart.json.heartbeat.status, 'running');

      const rOk = await reqJson('GET', `/api/heartbeat/${hb.token}?msg=http_done`);
      assert.strictEqual(rOk.status, 200);
      assert.strictEqual(rOk.json.heartbeat.status, 'up');
      assert.strictEqual(rOk.json.autoResolved, true);

      const rBad = await reqJson('GET', `/api/heartbeat/${'f'.repeat(48)}`);
      assert.strictEqual(rBad.status, 404);
    } finally {
      await new Promise((r) => srv.close(r));
    }

    assert.strictEqual(cm.deleteHeartbeat(hb.id).deleted, true);
    assert.strictEqual(cm.listHeartbeats().length, 0);
    console.log('  ✓ 3. Live HTTP /api/heartbeat/:token[/:state] check-in & deleteHeartbeat verified');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  console.log('✅ Cron 24h Heatmap & Dead-Man\'s-Switch Heartbeats suite PASSED!\n');
}

module.exports = testCronHeartbeat;

if (require.main === module) {
  testCronHeartbeat()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ Cron/Heartbeat test failure:', err);
      process.exit(1);
    });
}
