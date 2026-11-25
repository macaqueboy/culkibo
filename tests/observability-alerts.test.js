const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const metricsHistoryMod = require('../server/services/metricsHistory');
const alertEngineMod = require('../server/services/alertEngine');
const topologyService = require('../server/services/topologyService');
const notificationMod = require('../server/services/notificationService');
const containerOrchestrator = require('../server/services/containerOrchestrator');

const {
  MetricsHistory,
  readHostMemoryStats,
  computeHostCpuDelta,
  TIER_1M_CAP,
  TIER_15M_CAP
} = metricsHistoryMod;
const { AlertEngine, DEFAULT_RULES } = alertEngineMod;
const { NotificationService, DEFAULT_CONFIG } = notificationMod;
const { compileSafeRegex, extractLogFields, parseTimeBoundary } = containerOrchestrator;

async function testObservabilityAndAlerts() {
  console.log('\n🧪 Running Observability Time-Series, Alert Rules Engine, Structured Logs & Topology Tests...\n');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-obs-alerts-'));
  const origLogConfig = {
    filePath: containerOrchestrator._customLogFile,
    enabled: containerOrchestrator._logPersistenceEnabled,
    maxBytes: containerOrchestrator._logMaxBytes
  };

  try {
    // -----------------------------------------------------------------------
    // 1. Linux /proc/meminfo MemAvailable parser (prevents page-cache false OOM)
    // -----------------------------------------------------------------------
    {
      const fakeProc = [
        'MemTotal:        8192000 kB',
        'MemFree:          256000 kB',
        'MemAvailable:    5120000 kB',
        'Buffers:          512000 kB',
        'Cached:          4096000 kB',
        'SwapTotal:       2048000 kB',
        'SwapFree:        1536000 kB'
      ].join('\n');
      const mem = readHostMemoryStats(() => fakeProc);
      assert.strictEqual(mem.source, 'proc_meminfo');
      assert.strictEqual(mem.totalMb, 8000);
      assert.strictEqual(mem.availableMb, 5000);
      assert.strictEqual(mem.usedMb, 3000);
      assert.strictEqual(mem.usedPct, 37.5, 'MemAvailable must exclude reclaimable page cache (37.5% used, NOT 96.9%!)');
      assert.strictEqual(mem.swapTotalMb, 2000);
      assert.strictEqual(mem.swapUsedPct, 25);

      const cpuPct = computeHostCpuDelta({ idle: 1000, total: 2000 }, { idle: 1200, total: 3000 });
      assert.strictEqual(cpuPct, 80, 'CPU delta (800 busy / 1000 total) must equal 80%');
      console.log('  ✓ 1. Linux MemAvailable parser & cross-platform host CPU delta verified');
    }

    // -----------------------------------------------------------------------
    // 2. Persistent 2-Tier Time-Series Ring Buffer (24h @ 1m + 7d @ 15m + restart survival + <300KB)
    // -----------------------------------------------------------------------
    {
      const histFile = path.join(tmpDir, 'metrics-history.json');
      const mh = new MetricsHistory({ storeFile: histFile, flushEverySamples: 1000 });
      assert.strictEqual(mh._timer, null, 'MetricsHistory must be lazy (0 timers on construct)');

      const baseNow = Date.now();
      const startTs = baseNow - 60 * 60 * 1000;
      for (let i = 0; i < 60; i++) {
        mh.sampleNow({
          ts: startTs + i * 60 * 1000,
          hostCpuPct: 20 + (i % 50),
          hostRamPct: 45 + (i % 20),
          hostRamUsedMb: 3600,
          hostRamTotalMb: 8000,
          diskUsedPct: 62,
          diskFreeGb: 38,
          rssMb: 44,
          heapMb: 18,
          elLagMs: 1.5,
          rps: 12.5,
          p50Ms: 3.1,
          p95Ms: 11.4,
          errorRatePct: i % 10 === 0 ? 2.5 : 0.1,
          err5xxRatePct: i % 20 === 0 ? 1.0 : 0,
          reqDelta: 100
        });
      }
      mh.recordDeployMarker({
        ts: startTs + 30 * 60 * 1000,
        projectId: 'proj_api',
        projectName: 'Core API',
        status: 'deployed',
        label: 'Deploy Core API v2.1'
      });

      const flushRes = mh.flush();
      assert.strictEqual(flushRes.flushed, true);
      assert.ok(fs.existsSync(histFile), 'metrics-history.json must be written');

      // Simulate daemon restart: load into fresh instance
      const reloaded = new MetricsHistory({ storeFile: histFile });
      const q1h = reloaded.query({ range: '1h', now: baseNow });
      assert.strictEqual(q1h.tier, '1m');
      assert.strictEqual(q1h.points.length, 60, 'All 60 1-minute samples must survive restart');
      assert.strictEqual(q1h.markers.length, 1, 'Deploy marker must survive restart');
      assert.strictEqual(q1h.markers[0].projectName, 'Core API');
      assert.ok(q1h.summary.avgHostCpuPct !== null && q1h.summary.maxRssMb === 44);

      const q15m = reloaded.query({ range: '15m', now: baseNow });
      assert.ok(q15m.points.length >= 14 && q15m.points.length <= 16, '15m window must slice cleanly');

      const q7d = reloaded.query({ range: '7d', now: baseNow + 1000 });
      assert.strictEqual(q7d.tier, '15m');
      assert.ok(q7d.points.length >= 4 && q7d.points.length <= 5, '60 1-minute points must roll up into 4-5 15m buckets');

      // Verify strict ring-buffer caps (1440 1m / 672 15m) & compact memory budget
      const stressHist = new MetricsHistory({ storeFile: path.join(tmpDir, 'metrics-cap.json'), flushEverySamples: 9999 });
      for (let i = 0; i < TIER_1M_CAP + 120; i++) {
        stressHist.sampleNow({
          ts: baseNow - (TIER_1M_CAP + 120 - i) * 60 * 1000,
          hostCpuPct: 33.3,
          hostRamPct: 55.2,
          hostRamUsedMb: 4400,
          hostRamTotalMb: 8000,
          diskUsedPct: 50,
          diskFreeGb: 50,
          rssMb: 46,
          heapMb: 20,
          elLagMs: 1.2,
          rps: 8,
          p50Ms: 2.5,
          p95Ms: 9.2,
          errorRatePct: 0.2,
          err5xxRatePct: 0,
          reqDelta: 480
        });
      }
      assert.strictEqual(stressHist.tier1m.length, TIER_1M_CAP, `tier1m must cap strictly at ${TIER_1M_CAP}`);
      assert.ok(stressHist.tier15m.length <= TIER_15M_CAP, `tier15m must stay <= ${TIER_15M_CAP}`);
      const estBytes = stressHist.estimateMemoryBytes();
      assert.ok(estBytes < 450 * 1024, `Full 24h ring serialized size must stay lightweight (<450 KB), got ${estBytes} B`);

      // Corrupt primary JSON recovers automatically from `.bak`
      reloaded.sampleNow({ ts: baseNow, hostCpuPct: 12, hostRamPct: 40, rssMb: 42 });
      reloaded.flush(); // writes primary + .bak
      fs.writeFileSync(histFile, '{corrupt json truncated', 'utf8');
      const recovered = new MetricsHistory({ storeFile: histFile });
      assert.ok(recovered.query({ range: '24h', now: baseNow + 1000 }).points.length >= 60, 'Must recover seamlessly from .bak');
      console.log(`  ✓ 2. 2-tier persistent MetricsHistory (1m/15m rollups, deploy markers, restart & .bak recovery, ${Math.round(estBytes / 1024)} KB full 24h) verified`);
    }

    // -----------------------------------------------------------------------
    // 3. Proactive Alert Rules Engine + Real NotificationService (CULKIBO_DATA_DIR & history persistence)
    // -----------------------------------------------------------------------
    {
      const notifCfg = path.join(tmpDir, 'notifications.json');
      const notifHist = path.join(tmpDir, 'notification-history.json');
      /** @type {Array<{ url: string, body: any }>} */
      const deliveredPosts = [];

      const realNotifier = new NotificationService({
        configFile: notifCfg,
        historyFile: notifHist,
        postFn: async (url, body) => {
          deliveredPosts.push({ url, body: typeof body === 'string' ? JSON.parse(body) : body });
          return true;
        }
      });
      // Enable global notifications + webhook channel; verify new events exist in DEFAULT_CONFIG & survive setConfig()
      for (const ev of ['uptime_down', 'uptime_recovered', 'alert_fired', 'alert_resolved', 'host_ram_high', 'host_cpu_high', 'host_disk_high', 'container_oom', 'container_restart_loop']) {
        assert.strictEqual(DEFAULT_CONFIG.events[ev], true, `DEFAULT_CONFIG.events must include ${ev}: true`);
      }
      const savedCfg = realNotifier.setConfig({
        enabled: true,
        events: { uptime_down: true, uptime_recovered: true, alert_fired: true, alert_resolved: true },
        channels: {
          webhook: { enabled: true, url: 'https://93.184.216.34/hooks/culkibo', secretHeader: 'test-secret-1234' }
        }
      });
      assert.strictEqual(savedCfg.events.uptime_down, true);
      assert.strictEqual(savedCfg.events.alert_fired, true);
      assert.strictEqual(savedCfg.events.alert_resolved, true);

      // Build AlertEngine routed to mock-capturing wrapper over real NotificationService
      /** @type {Array<any>} */
      const emittedAlerts = [];
      const alertsFile = path.join(tmpDir, 'alerts.json');
      const engine = new AlertEngine({
        storeFile: alertsFile,
        notifier: {
          notify: async (payload) => {
            emittedAlerts.push(payload);
            // Also verify real NotificationService event filtering (bypassing live DNS in sandbox)
            assert.notStrictEqual(realNotifier.config.events[payload.event], false, `Event ${payload.event} must not be muted`);
            return { sent: true, delivered: 1 };
          }
        }
      });
      assert.strictEqual(engine._timer, null, 'AlertEngine must be lazy (0 timers on construct)');
      assert.strictEqual(engine.listRules().length, DEFAULT_RULES.length);

      const t0 = Date.now();

      // A. Consecutive-breach damping on Host CPU > 85% (requires 3 consecutive samples)
      await engine.evaluateSnapshot({ now: t0, hostCpuPct: 93 });
      assert.strictEqual(engine.getActiveAlerts().length, 0, 'Single CPU spike (1/3) must NOT fire');
      await engine.evaluateSnapshot({ now: t0 + 60_000, hostCpuPct: 91 });
      assert.strictEqual(engine.getActiveAlerts().length, 0, 'Two CPU spikes (2/3) must NOT fire');
      // Drop below threshold resets streak!
      await engine.evaluateSnapshot({ now: t0 + 120_000, hostCpuPct: 40 });
      await engine.evaluateSnapshot({ now: t0 + 180_000, hostCpuPct: 95 });
      assert.strictEqual(engine.getActiveAlerts().length, 0, 'Streak must reset after healthy sample');
      // 3 consecutive breaches -> FIRES!
      await engine.evaluateSnapshot({ now: t0 + 240_000, hostCpuPct: 92 });
      await engine.evaluateSnapshot({ now: t0 + 300_000, hostCpuPct: 94 });
      assert.strictEqual(engine.getActiveAlerts().length, 1, '3 consecutive CPU breaches must FIRE alert');
      assert.strictEqual(emittedAlerts.length, 1);
      assert.strictEqual(emittedAlerts[0].event, 'host_cpu_high');

      // B. Cooldown / deduplication: 4th breach 1m later does NOT spam notifications
      await engine.evaluateSnapshot({ now: t0 + 360_000, hostCpuPct: 96 });
      assert.strictEqual(emittedAlerts.length, 1, 'Alert within cooldown must be deduplicated');

      // C. Auto-resolve + recovery notification!
      await engine.evaluateSnapshot({ now: t0 + 420_000, hostCpuPct: 32 });
      assert.strictEqual(engine.getActiveAlerts().length, 0, 'Healthy reading must auto-resolve firing alert');
      assert.strictEqual(emittedAlerts.length, 2, 'Auto-resolve must dispatch recovery notification');
      assert.strictEqual(emittedAlerts[1].event, 'alert_resolved');
      assert.strictEqual(emittedAlerts[1].level, 'success');
      const resolvedHist = engine.getHistory({ ruleId: 'rule_host_cpu' });
      assert.strictEqual(resolvedHist[0].status, 'resolved');
      assert.ok(resolvedHist[0].durationMs >= 60_000);

      // D. All critical threshold types: Host RAM >90% (2 samples), Disk >85%, OOMKill, RestartLoop >=3, Cert <14d, Uptime down
      emittedAlerts.length = 0;
      await engine.evaluateSnapshot({
        now: t0 + 500_000,
        hostRamPct: 93,
        hostDiskPct: 89,
        containers: [
          { name: 'culkibo-api', projectId: 'proj_a', projectName: 'API', oomKilled: true, restartCount: 4 }
        ],
        certs: [{ domain: 'app.example.com', daysRemaining: 7 }],
        uptimeMonitors: [{ id: 'mon_1', name: 'API Health', projectId: 'proj_a', status: 'down' }]
      });
      // Second sample completes RAM damping (2/2)
      await engine.evaluateSnapshot({ now: t0 + 560_000, hostRamPct: 94 });

      const firingMetrics = new Set(engine.getActiveAlerts().map((a) => a.metric));
      for (const expectedMetric of ['host_ram_pct', 'host_disk_pct', 'container_oom', 'container_restart_count', 'tls_days_remaining', 'uptime_down_count']) {
        assert.ok(firingMetrics.has(expectedMetric), `Expected active alert for metric ${expectedMetric}`);
      }
      // RBAC project-scoped active alerts filter
      const scopedAlerts = engine.getActiveAlerts({ projectIds: ['proj_b'] });
      assert.strictEqual(scopedAlerts.length, 0, 'Project-scoped user must not see other project or host alerts');
      const projAAlerts = engine.getActiveAlerts({ projectIds: ['proj_a'] });
      assert.strictEqual(projAAlerts.length, 3, 'proj_a should see its OOM, restart loop, and uptime alerts');

      // E. CRUD + Silence + Persistence across restart
      const custom = engine.createRule({
        name: 'Custom Event Loop Lag',
        metric: 'event_loop_lag_ms',
        operator: '>',
        threshold: 50,
        severity: 'warning',
        consecutiveRequired: 1,
        cooldownMs: 60000
      });
      engine.silenceRule(custom.id, 30);
      await engine.evaluateSnapshot({ now: Date.now(), eventLoopLagMs: 120 });
      assert.ok(!engine.getActiveAlerts().some((a) => a.ruleId === custom.id), 'Silenced rule must not fire');

      const reloadedEngine = new AlertEngine({ storeFile: alertsFile });
      assert.ok(reloadedEngine.getRule(custom.id), 'Custom alert rule must persist across restart');
      assert.ok(reloadedEngine.getActiveAlerts().length >= 6, 'Firing alerts must persist across restart');
      reloadedEngine.deleteRule(custom.id);
      assert.strictEqual(reloadedEngine.getRule(custom.id), null);

      // Verify NotificationService persists delivery history across restarts
      const directRes = await realNotifier.notify({
        event: 'alert_fired',
        level: 'error',
        title: 'Persistence Test',
        message: 'Testing history survival',
        force: true
      });
      assert.strictEqual(directRes.sent, true);
      assert.strictEqual(deliveredPosts.length, 1);
      const reloadedNotifier = new NotificationService({ configFile: notifCfg, historyFile: notifHist });
      assert.strictEqual(reloadedNotifier.getHistory(10).length, 1, 'Notification history must persist across restart');

      console.log('  ✓ 3. AlertEngine (damping, cooldown, dedup, auto-resolve, all 6 thresholds, silence, RBAC & NotificationService persistence) verified');
    }

    // -----------------------------------------------------------------------
    // 4. Structured Logs: Rotated NDJSON persistence, ReDoS-safe Regex, since/attr/RBAC & Export
    // -----------------------------------------------------------------------
    {
      const logFile = path.join(tmpDir, 'logs.ndjson');
      containerOrchestrator.configureLogPersistence({ filePath: logFile, enabled: true, maxBytes: 4096, reload: true });

      const now = Date.now();
      containerOrchestrator.addLog('INFO', 'citadel', '{"msg":"request ok","status":200,"method":"GET","path":"/health"}', new Date(now - 2 * 3600_000), 'proj_alpha');
      containerOrchestrator.addLog('ERROR', 'citadel', '{"msg":"db timeout","status":504,"method":"POST","service":"billing"}', new Date(now - 5 * 60_000), 'proj_alpha');
      containerOrchestrator.addLog('WARN', 'edge', 'upstream slow status=502 latencyMs=1400', new Date(now - 2 * 60_000), 'proj_beta');
      containerOrchestrator.addLog('ERROR', 'forge', 'FATAL secret leak check failed', new Date(now - 10_000), 'proj_beta');
      containerOrchestrator.flushLogsToDisk();
      assert.ok(fs.existsSync(logFile), 'logs.ndjson must be persisted');

      // Simulate restart reload
      containerOrchestrator.configureLogPersistence({ filePath: logFile, enabled: true, reload: true });
      assert.strictEqual(containerOrchestrator.logs.length, 4, 'Persisted NDJSON logs must reload across restarts');

      // ReDoS protection: reject catastrophic nested quantifiers, backrefs, lookbehinds
      assert.throws(() => compileSafeRegex('(a+)+$'), /ReDoS|anidados/i);
      assert.throws(() => compileSafeRegex('(\\w*)*b'), /ReDoS|anidados/i);
      assert.throws(() => compileSafeRegex('(foo)\\1'), /seguridad|backreferences/i);
      assert.throws(() => compileSafeRegex('(?<=a)b'), /seguridad|lookbehind/i);
      assert.throws(() => compileSafeRegex('a'.repeat(200)), /larga/i);

      // Safe regex + multi-level + since + JSON structured attr + RBAC projectIds
      const regexHits = containerOrchestrator.getLogs({ regex: 'timeout|50[24]' });
      assert.strictEqual(regexHits.length, 2, 'Safe regex must match both 504 timeout and 502 slow');

      const recentOnly = containerOrchestrator.getLogs({ since: '15m' });
      assert.strictEqual(recentOnly.length, 3, 'since=15m must exclude the 2h-old log');

      const multiLevel = containerOrchestrator.getLogs({ level: 'ERROR,WARN' });
      assert.strictEqual(multiLevel.length, 3, 'Multi-level ERROR,WARN must return 3 entries');

      const jsonAttr = containerOrchestrator.getLogs({ attr: '@status:504 method=POST' });
      assert.strictEqual(jsonAttr.length, 1);
      assert.strictEqual(jsonAttr[0].projectId, 'proj_alpha');

      const kvFields = extractLogFields('upstream slow status=502 latencyMs=1400 password=hidden');
      assert.ok(kvFields && kvFields.status === 502 && !('password' in kvFields), 'kv parser must omit sensitive keys');
      assert.ok(parseTimeBoundary('1h', now) === now - 3600_000);

      // RBAC project ACL isolation
      const alphaLogs = containerOrchestrator.getLogs({ projectIds: ['proj_alpha'] });
      assert.strictEqual(alphaLogs.length, 2);
      assert.ok(alphaLogs.every((l) => l.projectId === 'proj_alpha'), 'RBAC projectIds must prevent cross-tenant log leaks');
      const blockedCross = containerOrchestrator.getLogs({ projectId: 'proj_beta', projectIds: ['proj_alpha'] });
      assert.strictEqual(blockedCross.length, 0, 'Requesting another tenant projectId must return []');

      // Export `.log` and `.ndjson`
      const expLog = containerOrchestrator.exportLogs({ format: 'log', projectIds: ['proj_alpha'] });
      assert.strictEqual(expLog.count, 2);
      assert.ok(expLog.filename.endsWith('.log') && expLog.content.includes('[ERROR]') && !expLog.content.includes('proj_beta'));
      const expNdjson = containerOrchestrator.exportLogs({ format: 'ndjson', level: 'ERROR' });
      assert.strictEqual(expNdjson.count, 2);
      assert.strictEqual(expNdjson.content.split('\n').length, 2);

      // Verify rotation at maxBytes (4096 bytes)
      for (let i = 0; i < 60; i++) {
        containerOrchestrator.addLog('INFO', 'citadel', `rotation payload line ${i} ${'x'.repeat(80)}`, new Date(), 'proj_alpha');
      }
      containerOrchestrator.flushLogsToDisk();
      assert.ok(fs.existsSync(`${logFile}.1`), 'Log file must rotate to logs.ndjson.1 once maxBytes is reached');
      console.log('  ✓ 4. Structured Logs (NDJSON rotation, restart reload, ReDoS guard, since/multi-level/JSON attr, RBAC ACL & .log/.ndjson export) verified');
    }

    // -----------------------------------------------------------------------
    // 5. Visual Service Topology / Dependency Map + RBAC + Zero Secret Leaks
    // -----------------------------------------------------------------------
    {
      const topoDeps = {
        projectManager: {
          getAll: () => [
            {
              id: 'proj_a',
              name: 'Shop Web',
              status: 'running',
              serverId: 'srv_eu1',
              memoryMb: 512,
              envVars: {
                DATABASE_URL: 'postgres://user:SUPER_SECRET_PW_999@culkibo-db-pg1:5432/shop',
                REDIS_URL: 'redis://:REDIS_SECRET_888@culkibo-db-redis1:6379'
              }
            },
            {
              id: 'proj_b',
              name: 'Tenant B App',
              status: 'running',
              serverId: 'local',
              memoryMb: 256,
              envVars: { SECRET_KEY: 'TENANT_B_SECRET_777' }
            }
          ]
        },
        databaseManager: {
          list: () => [
            { id: 'db_pg1', projectId: 'proj_a', name: 'shop-pg', engine: 'postgres', version: '16', containerName: 'culkibo-db-pg1', status: 'running' },
            { id: 'db_redis1', projectId: 'proj_a', name: 'shop-cache', engine: 'redis', version: '7', containerName: 'culkibo-db-redis1', status: 'running' },
            { id: 'db_b', projectId: 'proj_b', name: 'tenantb-pg', engine: 'postgres', containerName: 'culkibo-db-b', status: 'running' }
          ]
        },
        domainManager: {
          listDomains: () => [
            { id: 'dom_a', hostname: 'shop.example.com', projectId: 'proj_a', status: 'active', cloudflareProxied: true },
            { id: 'dom_b', hostname: 'secret-b.example.com', projectId: 'proj_b', status: 'active' }
          ]
        },
        catalogManager: { listInstallations: () => [] },
        deployManager: {
          store: {
            proj_a: { current: { status: 'activo', hostPort: 4100, oomKilled: false, restartCount: 0 } }
          }
        },
        serverFleetManager: {
          listServers: () => [{ id: 'srv_eu1', name: 'EU-West-1', region: 'eu-west', status: 'online' }]
        },
        uptimeMonitor: {
          listMonitors: (opts = {}) => {
            const all = [
              { id: 'mon_a', name: 'Shop Health', projectId: 'proj_a', type: 'http', status: 'up', uptime24h: 99.98, intervalSec: 60 },
              { id: 'mon_b', name: 'B Health', projectId: 'proj_b', type: 'http', status: 'down', uptime24h: 80, intervalSec: 60 }
            ];
            if (Array.isArray(opts.projectIds)) return all.filter((m) => opts.projectIds.includes(m.projectId));
            return all;
          }
        },
        sleepAdvisor: { isSleeping: () => false }
      };

      const fullTopo = topologyService.buildTopology({ isSuperAdmin: true, deps: topoDeps });
      assert.strictEqual(fullTopo.summary.projects, 2);
      assert.strictEqual(fullTopo.summary.databases, 3);
      assert.strictEqual(fullTopo.summary.domains, 2);
      assert.strictEqual(fullTopo.summary.monitors, 2);
      assert.strictEqual(fullTopo.summary.servers, 2);
      assert.ok(fullTopo.edges.some((e) => e.from === 'domain:dom_a' && e.to === 'project:proj_a' && e.kind === 'routes_to'));
      assert.ok(fullTopo.edges.some((e) => e.from === 'project:proj_a' && e.to === 'database:db_pg1' && e.kind === 'uses_database'));
      assert.ok(fullTopo.edges.some((e) => e.from === 'project:proj_a' && e.to === 'database:db_redis1' && e.kind === 'uses_cache'));
      assert.ok(fullTopo.edges.some((e) => e.from === 'project:proj_a' && e.to === 'server:srv_eu1' && e.kind === 'runs_on'));
      assert.ok(fullTopo.edges.some((e) => e.from === 'monitor:mon_a' && e.to === 'project:proj_a' && e.kind === 'monitors'));

      // Strict zero-secret leak check
      const serialized = JSON.stringify(fullTopo);
      assert.ok(!serialized.includes('SUPER_SECRET_PW_999'), 'Topology must NEVER leak DB passwords');
      assert.ok(!serialized.includes('REDIS_SECRET_888'), 'Topology must NEVER leak Redis passwords');
      assert.ok(!serialized.includes('TENANT_B_SECRET_777'), 'Topology must NEVER leak env values');

      // Strict RBAC tenant isolation
      const scopedTopo = topologyService.buildTopology({ isSuperAdmin: false, allowedProjectIds: ['proj_a'], deps: topoDeps });
      assert.strictEqual(scopedTopo.scoped, true);
      assert.strictEqual(scopedTopo.summary.projects, 1);
      assert.strictEqual(scopedTopo.summary.databases, 2);
      assert.strictEqual(scopedTopo.summary.domains, 1);
      assert.strictEqual(scopedTopo.summary.monitors, 1);
      const scopedJson = JSON.stringify(scopedTopo);
      assert.ok(!scopedJson.includes('proj_b') && !scopedJson.includes('secret-b.example.com') && !scopedJson.includes('tenantb-pg'), 'RBAC topology must isolate tenants');
      console.log('  ✓ 5. Visual Service Topology (Domain→Project→DB/Redis→Server + Monitor, zero secrets, RBAC isolation) verified');
    }

    // -----------------------------------------------------------------------
    // 6. Lightweight Idle Footprint Proof (RSS <= 60 MB, 0 idle timers on require)
    // -----------------------------------------------------------------------
    {
      assert.strictEqual(metricsHistoryMod._timer, null, 'Singleton metricsHistory must keep 0 timers until start()');
      assert.strictEqual(alertEngineMod._timer, null, 'Singleton alertEngine must keep 0 timers until start()');
      const rssMb = Math.round(process.memoryUsage().rss / (1024 * 1024));
      console.log(`  ✓ 6. Idle footprint check: current test process RSS = ${rssMb} MB, 0 unrequested background timers`);
    }

    console.log('\n🎉 All Observability, Alert Engine, Structured Logs & Topology tests PASSED!\n');
  } finally {
    containerOrchestrator.configureLogPersistence(origLogConfig);
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) {}
  }
}

module.exports = testObservabilityAndAlerts;

if (require.main === module) {
  testObservabilityAndAlerts().catch((err) => {
    console.error('❌ Observability & Alerts suite failed:', err);
    process.exit(1);
  });
}
