const assert = require('assert');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');

const uptimeModule = require('../server/services/uptimeMonitor');
const sleepModule = require('../server/services/sleepAdvisor');
const notificationModule = require('../server/services/notificationService');

const { UptimeMonitor, PUBLIC_STATUS_CSP } = uptimeModule;
const { NotificationService } = notificationModule;
const {
  SleepAdvisor,
  renderWakingHtml,
  parseDockerBytes,
  getHostAvailableMemBytes,
  resolveWakeClientIp,
  WAKING_PAGE_CSP
} = sleepModule;

async function testUptimeSleep() {
  console.log('🧪 Testing Synthetic Uptime Monitors, Public Status Pages, Smart Auto-Sleep & VPS Cost Advisor...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-uptime-sleep-'));
  const uptimeFile = path.join(tmpDir, 'uptime.json');
  const sleepFile = path.join(tmpDir, 'sleep-policies.json');

  /** @type {http.Server | null} */
  let localHttpServer = null;
  /** @type {net.Server | null} */
  let localTcpServer = null;
  /** @type {any} */
  let uptime = null;
  /** @type {any} */
  let advisor = null;

  try {
    // -----------------------------------------------------------------------
    // 0. Spin up real local HTTP & TCP test servers on ephemeral loopback ports
    // -----------------------------------------------------------------------
    let httpMode = 'ok'; // 'ok' | 'slow' | 'bad_keyword' | 'fail_500'
    localHttpServer = http.createServer((req, res) => {
      if (httpMode === 'fail_500') {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('INTERNAL_DB_FAILURE_10_0_0_99');
        return;
      }
      if (httpMode === 'bad_keyword') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('maintenance placeholder');
        return;
      }
      if (httpMode === 'slow') {
        setTimeout(() => {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('status:HEALTHY_OK');
        }, 80);
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('status:HEALTHY_OK');
    });

    await new Promise((resolve) => localHttpServer.listen(0, '127.0.0.1', resolve));
    const httpAddr = /** @type {net.AddressInfo} */ (localHttpServer.address());
    const verifiedHttpPort = httpAddr.port;

    localTcpServer = net.createServer((sock) => sock.end());
    await new Promise((resolve) => localTcpServer.listen(0, '127.0.0.1', resolve));
    const tcpAddr = /** @type {net.AddressInfo} */ (localTcpServer.address());
    const verifiedTcpPort = tcpAddr.port;

    const projectPorts = {
      proj_api: verifiedHttpPort,
      proj_tcp: verifiedTcpPort
    };
    /** @type {Array<any>} */
    const notifications = [];

    uptime = new UptimeMonitor({
      storeFile: uptimeFile,
      autoStart: true,
      resolveProjectPort: (pid) => projectPorts[pid] || null,
      notifier: {
        notify: async (payload) => {
          notifications.push(payload);
          return { sent: true };
        }
      }
    });

    // Lazy scheduler: 0 timers before any monitor is created
    assert.strictEqual(uptime._timer, null, 'Scheduler must not start before monitors exist');

    // -----------------------------------------------------------------------
    // 1. Strict SSRF Protection on createMonitor, updateMonitor, and probe-time
    // -----------------------------------------------------------------------
    const blockedUrls = [
      'http://169.254.169.254/latest/meta-data/',
      'http://metadata.google.internal/computeMetadata/v1/',
      'http://[fd00:ec2::254]/latest/meta-data/',
      'http://100.100.100.200/latest/meta-data/',
      'http://127.0.0.1:3030/api/projects',
      'http://localhost:8080/health',
      'http://10.0.0.1/admin',
      'http://172.16.0.5/internal',
      'http://192.168.1.10/metrics',
      'http://[::ffff:169.254.169.254]/',
      'http://[::1]:3030/',
      'https://admin:secret@1.1.1.1/',
      'file:///etc/passwd'
    ];

    for (const badUrl of blockedUrls) {
      await assert.rejects(
        () => uptime.createMonitor({ name: 'Bad', type: 'http', url: badUrl }),
        (err) => err instanceof Error && err.message.length > 0,
        `Expected SSRF rejection for ${badUrl}`
      );
    }

    // TCP SSRF blocks private & metadata targets
    for (const badTcp of [
      { host: '169.254.169.254', port: 80 },
      { host: '10.0.0.5', port: 5432 },
      { host: '127.0.0.1', port: 22 },
      { host: 'metadata.google.internal', port: 80 }
    ]) {
      await assert.rejects(
        () => uptime.createMonitor({ name: 'BadTCP', type: 'tcp', ...badTcp }),
        /bloqueado|SSRF|metadatos|privada/i,
        `Expected TCP SSRF rejection for ${badTcp.host}:${badTcp.port}`
      );
    }

    // allowLocalProject MUST reject unverified project, wrong port, or metadata/RFC1918 host
    await assert.rejects(
      () => uptime.createMonitor({ name: 'NoProj', type: 'http', allowLocalProject: true, url: `http://127.0.0.1:${verifiedHttpPort}/` }),
      /projectId/i
    );
    await assert.rejects(
      () => uptime.createMonitor({ name: 'UnknownProj', type: 'http', allowLocalProject: true, projectId: 'proj_unknown', url: `http://127.0.0.1:${verifiedHttpPort}/` }),
      /puerto desplegado verificado|SSRF/i
    );
    await assert.rejects(
      () => uptime.createMonitor({ name: 'WrongPort', type: 'http', allowLocalProject: true, projectId: 'proj_api', url: `http://127.0.0.1:${verifiedHttpPort + 1}/health` }),
      /no coincide|SSRF/i
    );
    await assert.rejects(
      () => uptime.createMonitor({ name: 'MetaBypass', type: 'http', allowLocalProject: true, projectId: 'proj_api', url: 'http://169.254.169.254/latest/meta-data/' }),
      /loopback|SSRF/i
    );

    // Reject interval < 30s
    await assert.rejects(
      () => uptime.createMonitor({
        name: 'TooFast',
        type: 'http',
        allowLocalProject: true,
        projectId: 'proj_api',
        healthPath: '/health',
        intervalSec: 5
      }),
      /intervalSec/i
    );
    console.log('  ✓ Strict SSRF protection blocks metadata, RFC1918, loopback, TCP & allowLocalProject bypasses');

    // -----------------------------------------------------------------------
    // 2. HTTP Check + Keyword + Max Latency + Incident Transitions + Notifications
    // -----------------------------------------------------------------------
    const apiMon = await uptime.createMonitor({
      name: 'API Core Internal',
      publicName: 'API Pública',
      type: 'http',
      allowLocalProject: true,
      projectId: 'proj_api',
      url: `http://127.0.0.1:${verifiedHttpPort}/internal-health-secret`,
      expectedStatus: 200,
      keyword: 'HEALTHY_OK',
      maxLatencyMs: 50,
      intervalSec: 30,
      retries: 2,
      enabled: true,
      public: true
    });

    assert.ok(apiMon.id.startsWith('mon_'));
    assert.ok(uptime._timer !== null, 'Lazy scheduler must start once >= 1 monitor is enabled');

    // Update SSRF guard: switching existing monitor to metadata IP MUST fail
    await assert.rejects(
      () => uptime.updateMonitor(apiMon.id, { allowLocalProject: false, url: 'http://169.254.169.254/' }),
      /SSRF|metadatos|bloqueado/i
    );

    // Check #1: Healthy fast response -> up
    const r1 = await uptime.runCheck(apiMon.id);
    assert.strictEqual(r1.status, 'up');
    assert.strictEqual(r1.check.statusCode, 200);
    assert.strictEqual(r1.incidentTransition, null);

    // Check #2: Slow response (> maxLatencyMs: 50) -> degraded
    httpMode = 'slow';
    const r2 = await uptime.runCheck(apiMon.id);
    assert.strictEqual(r2.status, 'degraded');
    assert.strictEqual(r2.check.ok, true);
    assert.strictEqual(notifications.length, 0, 'Degraded latency should not open down incident');

    // Check #3: Keyword mismatch (1st failure < retries: 2) -> degraded, NO incident yet
    httpMode = 'bad_keyword';
    const r3 = await uptime.runCheck(apiMon.id);
    assert.strictEqual(r3.check.status, 'down');
    assert.strictEqual(r3.status, 'degraded', 'First failure below retries threshold must not false-alarm');
    assert.strictEqual(r3.incidentTransition, null);
    assert.strictEqual(notifications.length, 0);

    // Check #4: HTTP 500 (2nd consecutive failure === retries: 2) -> DOWN + opens incident + notifies!
    httpMode = 'fail_500';
    const r4 = await uptime.runCheck(apiMon.id);
    assert.strictEqual(r4.status, 'down');
    assert.strictEqual(r4.incidentTransition, 'opened');
    assert.ok(r4.incident && r4.incident.status === 'open');
    assert.strictEqual(notifications.length, 1);
    assert.strictEqual(notifications[0].event, 'uptime_down');
    assert.strictEqual(notifications[0].level, 'error');

    // Check #5: Recovery -> UP + resolves incident + notifies uptime_recovered!
    httpMode = 'ok';
    const r5 = await uptime.runCheck(apiMon.id);
    assert.strictEqual(r5.status, 'up');
    assert.strictEqual(r5.incidentTransition, 'resolved');
    assert.ok(r5.incident && r5.incident.status === 'resolved' && r5.incident.resolvedAt);
    assert.strictEqual(notifications.length, 2);
    assert.strictEqual(notifications[1].event, 'uptime_recovered');
    assert.strictEqual(notifications[1].level, 'success');

    // Uptime % & latency stats verification (5 checks: 3 available [up/degraded/up], 2 down => 60%)
    const refreshed = uptime.getMonitor(apiMon.id);
    assert.strictEqual(refreshed.uptime24h, 60);
    assert.strictEqual(refreshed.uptime7d, 60);
    assert.strictEqual(refreshed.uptime30d, 60);
    assert.ok(typeof refreshed.p50LatencyMs === 'number');
    assert.ok(typeof refreshed.p95LatencyMs === 'number');
    assert.strictEqual(refreshed.history30.length, 30);

    // TCP monitor against verified local project port
    const tcpMon = await uptime.createMonitor({
      name: 'TCP Local Socket',
      publicName: 'Base de Datos',
      type: 'tcp',
      allowLocalProject: true,
      projectId: 'proj_tcp',
      intervalSec: 30,
      enabled: true,
      public: true
    });
    const rTcp = await uptime.runCheck(tcpMon.id);
    assert.strictEqual(rTcp.status, 'up', 'Local TCP probe should succeed');

    // External TCP monitor pins resolved IP (never passes raw hostname to net.connect)
    let probedHostIp = null;
    let rebindNow = false;
    const extUptime = new UptimeMonitor({
      storeFile: path.join(tmpDir, 'uptime-ext.json'),
      autoStart: false,
      assertSafeUrl: async (rawUrl) => {
        if (rebindNow) {
          throw new Error('Destino bloqueado (IP de metadatos cloud): 169.254.169.254');
        }
        return { url: new URL(rawUrl), addresses: ['93.184.216.34'] };
      },
      tcpProbe: async ({ pinnedIp }) => {
        probedHostIp = pinnedIp;
        return { ok: true, latencyMs: 12, error: null };
      }
    });
    const extTcp = await extUptime.createMonitor({
      name: 'External TLS',
      type: 'tcp',
      host: 'example.com',
      port: 443,
      intervalSec: 60
    });
    const extRes1 = await extUptime.runCheck(extTcp.id);
    assert.strictEqual(extRes1.status, 'up');
    assert.strictEqual(probedHostIp, '93.184.216.34', 'TCP probe MUST connect to pinnedIp, never raw hostname');

    // Probe-time DNS rebinding protection
    probedHostIp = null;
    rebindNow = true;
    const extRes2 = await extUptime.runCheck(extTcp.id);
    assert.strictEqual(extRes2.check.status, 'down');
    assert.strictEqual(probedHostIp, null, 'DNS rebinding to metadata IP must abort BEFORE socket connect');
    extUptime.stop();

    // Ring buffer bounded at 288 checks
    const rawMon = uptime.monitors.get(apiMon.id);
    for (let i = 0; i < 310; i++) {
      rawMon.checks.push({ ts: Date.now() - (310 - i) * 1000, status: 'up', ok: true, statusCode: 200, latencyMs: 10 + (i % 20), error: null });
    }
    await uptime.runCheck(apiMon.id);
    assert.strictEqual(uptime.monitors.get(apiMon.id).checks.length, 288, 'Ring buffer must cap strictly at 288 checks');
    console.log('  ✓ HTTP/TCP checks, keyword, latency degraded, retries->incident->recovery notifications, pinned TCP & 288 ring buffer verified');

    // -----------------------------------------------------------------------
    // 3. Public Status Pages — Zero-Leak HTML & JSON + XSS Escape + CSP
    // -----------------------------------------------------------------------
    assert.throws(() => uptime.saveStatusPage({ slug: '../evil', title: 'Bad' }), /Slug inválido/i);
    assert.throws(() => uptime.saveStatusPage({ slug: 'UPPER_CASE', title: 'Bad' }), /Slug inválido/i);

    // Put apiMon back into an active open incident with a sensitive internal error to prove zero leak!
    httpMode = 'fail_500';
    await uptime.runCheck(apiMon.id);
    await uptime.runCheck(apiMon.id);
    assert.strictEqual(uptime.getMonitor(apiMon.id).status, 'down');

    const page = uptime.saveStatusPage({
      slug: 'acme-prod',
      title: 'Acme <script>alert("xss")</script> Status',
      description: 'Estado público en tiempo real <b>test</b>',
      monitorIds: [apiMon.id, tcpMon.id],
      accentColor: '#0f172a',
      published: true
    });
    assert.strictEqual(page.slug, 'acme-prod');
    assert.strictEqual(uptime.listStatusPages().length, 1);

    const pubData = uptime.getPublicStatusData('acme-prod');
    assert.ok(pubData);
    assert.strictEqual(pubData.overallStatus, 'outage');
    assert.strictEqual(pubData.services.length, 2);
    assert.strictEqual(pubData.services[0].displayName, 'API Pública');
    assert.strictEqual(pubData.services[0].status, 'down');
    assert.strictEqual(pubData.services[0].history30.length, 30);

    // Strict zero-leak check on BOTH public JSON and rendered HTML
    const pubJsonStr = JSON.stringify(pubData);
    const pubResp = uptime.renderPublicStatusResponse('acme-prod');
    assert.ok(pubResp);
    assert.strictEqual(pubResp.headers['Content-Security-Policy'], PUBLIC_STATUS_CSP);
    const pubHtml = uptime.renderPublicStatusHtml('acme-prod');
    assert.strictEqual(pubHtml, pubResp.html);

    const forbiddenLeaks = [
      `127.0.0.1`,
      String(verifiedHttpPort),
      String(verifiedTcpPort),
      'internal-health-secret',
      'proj_api',
      'proj_tcp',
      apiMon.id,
      tcpMon.id,
      'HEALTHY_OK',
      'INTERNAL_DB_FAILURE_10_0_0_99',
      'Código HTTP inesperado',
      '<script>alert("xss")</script>'
    ];
    for (const secret of forbiddenLeaks) {
      assert.ok(!pubJsonStr.includes(secret), `Public status JSON leaked forbidden field: ${secret}`);
      assert.ok(!pubHtml.includes(secret), `Public status HTML leaked forbidden field: ${secret}`);
    }
    assert.ok(pubHtml.includes('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'), 'XSS payload must be HTML-escaped');
    assert.ok(pubHtml.includes('API Pública'), 'Public display name must appear in HTML');
    assert.ok((pubHtml.match(/class="bar"/g) || []).length === 60, '2 monitors x 30 bars = 60 bars');

    const badgeSvg = uptime.renderBadgeSvg('acme-prod');
    assert.ok(badgeSvg && badgeSvg.startsWith('<svg') && badgeSvg.includes('caído'));

    // Toggling monitor public: false MUST immediately remove it from public status pages even if listed in monitorIds
    await uptime.updateMonitor(tcpMon.id, { public: false });
    const afterPrivate = uptime.getPublicStatusData('acme-prod');
    assert.strictEqual(afterPrivate.services.length, 1, 'Private monitor must not appear on public status page even when in monitorIds');
    await uptime.updateMonitor(tcpMon.id, { public: true });

    // Manual incident publish/resolve + page delete
    const manualInc = uptime.publishStatusIncident('acme-prod', { title: 'Mantenimiento DNS', severity: 'maintenance', message: 'Ventana breve' });
    assert.strictEqual(manualInc.status, 'open');
    const resolvedManual = uptime.resolveStatusIncident('acme-prod', manualInc.id);
    assert.strictEqual(resolvedManual.status, 'resolved');

    // Persistence + backup check
    assert.ok(fs.existsSync(uptimeFile), 'uptime.json must be persisted');
    assert.ok(fs.existsSync(`${uptimeFile}.bak`), 'uptime.json.bak must be written on updates');

    const reloaded = new UptimeMonitor({ storeFile: uptimeFile, autoStart: false });
    assert.strictEqual(reloaded.listMonitors().length, 2);
    assert.strictEqual(reloaded.listStatusPages().length, 1);

    uptime.deleteStatusPage('acme-prod');
    assert.strictEqual(uptime.getPublicStatusData('acme-prod'), null);
    uptime.deleteMonitor(apiMon.id);
    uptime.deleteMonitor(tcpMon.id);
    assert.strictEqual(uptime._timer, null, 'Scheduler must stop cleanly when 0 monitors remain enabled');
    uptime.stop();
    console.log('  ✓ Public Status Pages zero-leak JSON/HTML, XSS escaping, CSP, 30-bar sparkline, SVG badge & persistence verified');

    // -----------------------------------------------------------------------
    // 4. SleepAdvisor — Policy Validation, Active-Op Protection, State-Synced Sleep
    // -----------------------------------------------------------------------
    const dockerCalls = [];
    let wakeDelayMs = 0;
    let sleepDelayMs = 0;
    let dockerStatsError = null;
    let mockStatsNdjson = '';

    const mockDeployStore = {
      proj_web: { current: { containerName: 'culkibo-proj-web', hostPort: 4101, status: 'activo', projectName: 'Web App' } },
      proj_oom: { current: { containerName: 'culkibo-proj-oom', hostPort: 4102, status: 'activo', projectName: 'Heavy Worker', oomKilled: false } },
      proj_idle: { current: { containerName: 'culkibo-proj-idle', hostPort: 4103, status: 'activo', projectName: 'Staging Preview' } },
      proj_busy: { current: { containerName: 'culkibo-proj-busy', hostPort: 4104, status: 'activo', projectName: 'Core API' } }
    };
    const mockDeployLocks = new Map();
    const mockLiveSessions = new Map();
    const mockCronRunning = new Set();
    const mockCronJobs = [{ id: 'cron_1', projectId: 'proj_web', name: 'Nightly sync' }];
    const mockProjects = new Map([
      ['proj_web', { id: 'proj_web', name: 'Web App', status: 'running', memoryMb: 512, cpus: 0.5 }],
      ['proj_oom', { id: 'proj_oom', name: 'Heavy Worker', status: 'running', memoryMb: 512, cpus: 1 }],
      ['proj_idle', { id: 'proj_idle', name: 'Staging Preview', status: 'running', memoryMb: 1024, cpus: 0.5 }],
      ['proj_busy', { id: 'proj_busy', name: 'Core API', status: 'running', memoryMb: 512, cpus: 1 }]
    ]);
    let reconcileCount = 0;

    advisor = new SleepAdvisor({
      storeFile: sleepFile,
      autoStart: true,
      wakeRateLimitMax: 3,
      wakeRateWindowMs: 60000,
      execFile: (bin, args, opts, cb) => {
        assert.strictEqual(bin, 'docker', 'SleepAdvisor must ONLY invoke docker binary');
        assert.strictEqual(opts.shell, false, 'SleepAdvisor must ALWAYS pass shell: false');
        dockerCalls.push({ bin, args: [...args], shell: opts.shell });

        if (args[0] === 'stats') {
          if (dockerStatsError) {
            cb(new Error(dockerStatsError), '', dockerStatsError);
            return;
          }
          cb(null, mockStatsNdjson, '');
          return;
        }
        if ((args[0] === 'pause' || args[0] === 'stop') && sleepDelayMs > 0) {
          setTimeout(() => cb(null, args[args.length - 1], ''), sleepDelayMs);
          return;
        }
        if ((args[0] === 'unpause' || args[0] === 'start') && wakeDelayMs > 0) {
          setTimeout(() => cb(null, args[args.length - 1], ''), wakeDelayMs);
          return;
        }
        cb(null, args[args.length - 1] || '', '');
      },
      healthCheck: async () => ({ healthy: true }),
      deps: {
        deployManager: {
          store: mockDeployStore,
          locks: mockDeployLocks,
          saveStore: () => {}
        },
        projectManager: {
          getAll: () => Array.from(mockProjects.values()),
          getById: (id) => mockProjects.get(id) || null,
          hibernate: (id) => {
            const p = mockProjects.get(id);
            if (p) p.status = 'hibernated';
          },
          update: (id, patch) => {
            const p = mockProjects.get(id);
            if (p) Object.assign(p, patch);
          }
        },
        cronManager: {
          jobs: mockCronJobs,
          runningJobs: mockCronRunning
        },
        liveSyncEngine: {
          sessions: mockLiveSessions
        },
        databaseManager: { list: () => [] },
        catalogManager: { list: () => [] },
        previewManager: { list: () => [] },
        ingressManager: {
          reconcile: async () => { reconcileCount++; }
        }
      }
    });

    assert.strictEqual(advisor._timer, null, 'SleepAdvisor must not start timer when 0 policies are enabled');

    // Policy validation
    assert.throws(() => advisor.setPolicy('proj_web', { enabled: true, mode: 'kill', idleMinutes: 10 }), /Modo.*inválido/i);
    assert.throws(() => advisor.setPolicy('proj_web', { enabled: true, mode: 'pause', idleMinutes: 4 }), /al menos 5/i);
    assert.throws(() => advisor.setPolicy('../bad', { enabled: true, mode: 'pause', idleMinutes: 10 }), /projectId inválido/i);

    const pol = advisor.setPolicy('proj_web', {
      enabled: true,
      mode: 'pause',
      idleMinutes: 10,
      excludeCrons: true
    });
    assert.strictEqual(pol.enabled, true);
    assert.strictEqual(pol.mode, 'pause');
    assert.strictEqual(pol.idleMinutes, 10);
    assert.ok(advisor._timer !== null, 'Lazy timer starts once >= 1 policy is enabled');
    assert.strictEqual(advisor.listPolicies().length, 1);

    // Active-operation protection: deploy lock, liveSync client, running cron
    mockDeployLocks.set('proj_web', Promise.resolve());
    let sleepRes = await advisor.sleepProject('proj_web');
    assert.strictEqual(sleepRes.slept, false);
    assert.strictEqual(sleepRes.blocked, true);
    assert.ok(sleepRes.blockers.includes('active_deploy'));
    mockDeployLocks.clear();

    mockLiveSessions.set('proj_web', { connectedClients: 2 });
    sleepRes = await advisor.sleepProject('proj_web');
    assert.strictEqual(sleepRes.slept, false);
    assert.strictEqual(sleepRes.blocked, true);
    assert.ok(sleepRes.blockers.includes('active_livesync'));
    mockLiveSessions.clear();

    mockCronRunning.add('cron_1');
    sleepRes = await advisor.sleepProject('proj_web');
    assert.strictEqual(sleepRes.slept, false);
    assert.strictEqual(sleepRes.blocked, true);
    assert.ok(sleepRes.blockers.includes('active_cron'));
    mockCronRunning.clear();

    assert.strictEqual(dockerCalls.length, 0, 'Docker must NOT be invoked while active ops block sleep');

    // Sleep succeeds once blockers clear
    sleepRes = await advisor.sleepProject('proj_web');
    assert.strictEqual(sleepRes.slept, true);
    assert.strictEqual(sleepRes.mode, 'pause');
    assert.strictEqual(advisor.isSleeping('proj_web'), true);
    assert.strictEqual(mockDeployStore.proj_web.current.status, 'sleeping');
    assert.strictEqual(mockProjects.get('proj_web').status, 'hibernated');
    assert.deepStrictEqual(dockerCalls[0].args, ['pause', 'culkibo-proj-web']);
    assert.ok(reconcileCount >= 1, 'Ingress must reconcile on sleep');
    console.log('  ✓ Sleep policy validation, active cron/LiveSync/deploy protection & state-synced pause verified');

    // -----------------------------------------------------------------------
    // 5. Single-Flight Wake Coalescing + Per-IP Rate Limiting + Wake Secret + HTML
    // -----------------------------------------------------------------------
    dockerCalls.length = 0;
    wakeDelayMs = 60;

    // Fire 10 concurrent wake calls -> MUST coalesce into STRICTLY 1 docker unpause call!
    const concurrentWakes = await Promise.all(
      Array.from({ length: 10 }, () => advisor.wakeProject('proj_web'))
    );
    assert.strictEqual(concurrentWakes.length, 10);
    assert.ok(concurrentWakes.every((w) => w.woken === true && w.hostPort === 4101));
    assert.strictEqual(
      dockerCalls.filter((c) => c.args[0] === 'unpause').length,
      1,
      '10 concurrent wakes MUST coalesce into strictly 1 docker unpause invocation'
    );
    const nonCoalesced = concurrentWakes.filter((w) => w.coalesced === false).length;
    const coalesced = concurrentWakes.filter((w) => w.coalesced === true).length;
    assert.strictEqual(nonCoalesced, 1);
    assert.strictEqual(coalesced, 9);
    assert.strictEqual(advisor.isSleeping('proj_web'), false);
    assert.strictEqual(mockDeployStore.proj_web.current.status, 'activo');
    assert.strictEqual(mockProjects.get('proj_web').status, 'running');

    // Stop mode roundtrip (`docker stop --time 10` -> `docker start`)
    dockerCalls.length = 0;
    wakeDelayMs = 0;
    advisor.setPolicy('proj_web', { enabled: true, mode: 'stop', idleMinutes: 15 });
    const stopSleep = await advisor.sleepProject('proj_web');
    assert.strictEqual(stopSleep.slept, true);
    assert.deepStrictEqual(dockerCalls[0].args, ['stop', '--time', '10', 'culkibo-proj-web']);
    const startWake = await advisor.wakeProject('proj_web');
    assert.strictEqual(startWake.woken, true);
    assert.deepStrictEqual(dockerCalls[1].args, ['start', 'culkibo-proj-web']);

    // Per-IP rate limiting (limit configured to 3)
    const rl1 = await advisor.wakeProject('proj_web', { clientIp: '198.51.100.7' });
    const rl2 = await advisor.wakeProject('proj_web', { clientIp: '198.51.100.7' });
    const rl3 = await advisor.wakeProject('proj_web', { clientIp: '198.51.100.7' });
    const rl4 = await advisor.wakeProject('proj_web', { clientIp: '198.51.100.7' });
    const rlOther = await advisor.wakeProject('proj_web', { clientIp: '198.51.100.8' });
    assert.strictEqual(rl1.rateLimited, false);
    assert.strictEqual(rl2.rateLimited, false);
    assert.strictEqual(rl3.rateLimited, false);
    assert.strictEqual(rl4.rateLimited, true);
    assert.strictEqual(rl4.woken, false);
    assert.ok(rl4.retryAfterSec >= 1);
    assert.strictEqual(rlOther.rateLimited, false);

    // Wake request secret & proxy peer verification
    const secret = advisor.getWakeSecret();
    assert.ok(secret.length === 64);
    assert.strictEqual(
      advisor.verifyWakeRequest({ socket: { remoteAddress: '203.0.113.9' }, headers: { 'x-culkibo-wake-secret': secret } }).ok,
      false,
      'Public peer must be rejected even with secret'
    );
    assert.strictEqual(
      advisor.verifyWakeRequest({ socket: { remoteAddress: '127.0.0.1' }, headers: { 'x-culkibo-wake-secret': 'wrong' } }).ok,
      false,
      'Wrong wake secret must be rejected'
    );
    assert.strictEqual(
      advisor.verifyWakeRequest({ socket: { remoteAddress: '127.0.0.1' }, headers: { 'x-culkibo-wake-secret': secret } }).ok,
      true,
      'Loopback peer with valid wake secret must be accepted'
    );

    // Branded waking HTML helper (XSS safe + strict CSP + refresh)
    const wakingHtml = renderWakingHtml('Demo <img src=x onerror=alert(1)>');
    assert.ok(wakingHtml.includes(WAKING_PAGE_CSP));
    assert.ok(wakingHtml.includes('http-equiv="refresh"'));
    assert.ok(wakingHtml.includes('Waking service'));
    assert.ok(!wakingHtml.includes('<img src=x'));
    assert.ok(wakingHtml.includes('&lt;img src=x onerror=alert(1)&gt;'));

    // Security regressions from audit (#33):
    // A. Anti-spoof X-Forwarded-For uses rightmost hop (Caddy-appended client IP)
    assert.strictEqual(
      resolveWakeClientIp({ socket: { remoteAddress: '127.0.0.1' }, headers: { 'x-forwarded-for': '1.2.3.4, 5.6.7.8, 198.51.100.42' } }),
      '198.51.100.42',
      'resolveWakeClientIp MUST pick rightmost X-Forwarded-For hop'
    );

    // B. Chunked body rejected with 503 Retry-After: 2 in handleWakeRequest (blocks 1 MiB bypass)
    const chunkedResp = { statusCode: 0, headers: {}, body: '' };
    await advisor.handleWakeRequest(
      {
        method: 'POST',
        socket: { remoteAddress: '127.0.0.1' },
        headers: {
          'x-culkibo-wake-secret': secret,
          'transfer-encoding': 'chunked'
        }
      },
      {
        writeHead: (code, hdrs) => { chunkedResp.statusCode = code; chunkedResp.headers = hdrs; },
        end: (b) => { chunkedResp.body = String(b || ''); }
      },
      'proj_web'
    );
    assert.strictEqual(chunkedResp.statusCode, 503, 'Chunked POST body during wake must be rejected with 503');
    assert.strictEqual(chunkedResp.headers['Retry-After'], '2');
    assert.strictEqual(advisor._heldGlobal, 0, 'Rejected request must not leak held slot');

    // C. sleepProject / wakeProject race serialization: wake waits for in-flight stop then starts!
    dockerCalls.length = 0;
    sleepDelayMs = 60;
    wakeDelayMs = 10;
    const sleepPromise = advisor.sleepProject('proj_web', { mode: 'stop' });
    const wakeDuringSleep = advisor.wakeProject('proj_web');
    const [raceSleep, raceWake] = await Promise.all([sleepPromise, wakeDuringSleep]);
    sleepDelayMs = 0;
    wakeDelayMs = 0;
    assert.strictEqual(raceSleep.slept, true);
    assert.strictEqual(raceWake.woken, true);
    assert.strictEqual(raceWake.alreadyAwake, false, 'Wake during in-flight sleep MUST NOT falsely short-circuit alreadyAwake');
    assert.strictEqual(advisor.isSleeping('proj_web'), false, 'Container must end AWAKE after sleep+wake race');
    assert.deepStrictEqual(dockerCalls.map((c) => c.args[0]), ['stop', 'start']);

    // D. checkIdleProjects bails cleanly when Docker stats fails (never sleeps active projects blind!)
    dockerCalls.length = 0;
    dockerStatsError = 'Cannot connect to Docker daemon';
    advisor.policies.get('proj_web').lastActivityAt = Date.now() - 60 * 60 * 1000;
    const failedSweep = await advisor.checkIdleProjects();
    dockerStatsError = null;
    assert.strictEqual(failedSweep.slept.length, 0, 'Must never sleep projects when docker stats is unavailable');
    assert.strictEqual(advisor.isSleeping('proj_web'), false);

    // E. Linux /proc/meminfo MemAvailable parser avoids false-positive host OOM alerts
    const parsedAvail = getHostAvailableMemBytes(() => 'MemTotal:       4096000 kB\nMemFree:         102400 kB\nMemAvailable:   2560000 kB\n');
    assert.strictEqual(parsedAvail, 2560000 * 1024);

    console.log('  ✓ Single-flight 10->1 wake coalescing, sleep/wake race serialization, anti-spoof XFF, chunked cap, docker-down guard & Linux MemAvailable verified');

    // -----------------------------------------------------------------------
    // 6. VPS Cost & RAM Advisor (`analyzeResources`, `getSleepCandidates`, `getDoctorSummary`)
    // -----------------------------------------------------------------------
    assert.strictEqual(parseDockerBytes('512MiB'), 512 * 1024 * 1024);
    assert.strictEqual(parseDockerBytes('1.5GB'), 1500000000);
    assert.strictEqual(parseDockerBytes('0B'), 0);

    mockStatsNdjson = [
      JSON.stringify({
        ID: 'aaa111',
        Name: 'culkibo-proj-oom',
        CPUPerc: '35.20%',
        MemUsage: '465MiB / 512MiB',
        MemPerc: '90.82%',
        NetIO: '12MB / 8MB',
        PIDs: '24'
      }),
      JSON.stringify({
        ID: 'bbb222',
        Name: 'culkibo-proj-idle',
        CPUPerc: '0.15%',
        MemUsage: '160MiB / 1024MiB',
        MemPerc: '15.63%',
        NetIO: '240B / 120B',
        PIDs: '8'
      }),
      JSON.stringify({
        ID: 'ccc333',
        Name: 'culkibo-proj-busy',
        CPUPerc: '18.50%',
        MemUsage: '300MiB / 512MiB',
        MemPerc: '58.59%',
        NetIO: '48MB / 32MB',
        PIDs: '31'
      })
    ].join('\n');

    const analysis = await advisor.analyzeResources({ vpsMonthlyEur: 12 });
    assert.strictEqual(analysis.dockerAvailable, true);
    assert.strictEqual(analysis.containers.length, 3);
    assert.ok(analysis.host.totalMemMb > 0 && analysis.host.daemonRssMb > 0);

    // OOM risk detected for proj_oom (90.8%)
    const oomRec = analysis.oomRisks.find((r) => r.projectId === 'proj_oom');
    assert.ok(oomRec, 'Advisor must detect OOM risk for container > 85% memory');
    assert.ok(oomRec.recommendedMemoryMb > 512);

    // Idle candidate detected for proj_idle (NOT for busy proj_busy)
    const idleRec = analysis.idleCandidates.find((r) => r.projectId === 'proj_idle');
    assert.ok(idleRec, 'Advisor must detect idle auto-sleep candidate');
    assert.strictEqual(idleRec.reclaimableRamMb, 160);
    assert.ok(!analysis.idleCandidates.some((r) => r.projectId === 'proj_busy'), 'Busy API must NOT be flagged as idle');

    // Oversized memoryMb cap detected for proj_idle (160/1024 = 15.6% < 20%)
    const oversizedRec = analysis.oversizedCaps.find((r) => r.projectId === 'proj_idle');
    assert.ok(oversizedRec, 'Advisor must detect oversized memoryMb cap (< 20% usage)');
    assert.ok(oversizedRec.recommendedMemoryMb < 1024);

    // SaaS-vs-VPS cost ledger
    assert.strictEqual(analysis.costLedger.vpsMonthlyEur, 12);
    assert.ok(analysis.costLedger.providers.railwayEur > 0);
    assert.ok(analysis.costLedger.providers.renderEur > 0);
    assert.ok(analysis.costLedger.providers.flyEur > 0);
    assert.ok(analysis.costLedger.saasAverageMonthlyEur > 12);
    assert.ok(analysis.costLedger.monthlySavingsEur > 0);
    assert.strictEqual(
      analysis.costLedger.annualSavingsEur,
      Number((analysis.costLedger.monthlySavingsEur * 12).toFixed(2))
    );

    // Synchronous sleep candidates helper
    const candidates = advisor.getSleepCandidates();
    assert.ok(candidates.some((c) => c.projectId === 'proj_idle'));

    // SystemDoctor check #10 summary
    const doctorSummary = await advisor.getDoctorSummary({ vpsMonthlyEur: 12 });
    assert.strictEqual(doctorSummary.id, 'cost_ram_advisor');
    assert.ok(['ok', 'warn', 'fail'].includes(doctorSummary.status));
    assert.ok(doctorSummary.metrics.oomRiskCount >= 1);
    assert.ok(doctorSummary.metrics.idleCandidatesCount >= 1);
    assert.ok(doctorSummary.metrics.monthlySavingsEur > 0);

    // Disable policy -> scheduler stops cleanly
    advisor.setPolicy('proj_web', { enabled: false });
    assert.strictEqual(advisor._timer, null, 'Scheduler must stop when all policies are disabled');

    // -----------------------------------------------------------------------
    // 7. Deep Integration: Real NotificationService wiring, cron schedule sleep/wake,
    //    handleWakeRequest browser 800ms HTML hold + real HTTP proxy forwarding
    // -----------------------------------------------------------------------
    {
      // A. Real NotificationService receives uptime_down & uptime_recovered without stripping config keys
      const sentNotifBodies = [];
      const realNotif = new NotificationService({
        configFile: path.join(tmpDir, 'notif-uptime.json'),
        historyFile: path.join(tmpDir, 'notif-uptime-hist.json'),
        postFn: async (_url, body) => {
          sentNotifBodies.push(typeof body === 'string' ? JSON.parse(body) : body);
          return true;
        }
      });
      realNotif.setConfig({
        enabled: true,
        events: { uptime_down: true, uptime_recovered: true },
        channels: { webhook: { enabled: true, url: 'https://93.184.216.34/uptime-hook' } }
      });
      const wiredUptime = new UptimeMonitor({
        storeFile: path.join(tmpDir, 'uptime-wired.json'),
        autoStart: false,
        resolveProjectPort: () => verifiedHttpPort,
        notifier: realNotif
      });
      try {
        const wMon = await wiredUptime.createMonitor({
          name: 'Wired API',
          type: 'http',
          allowLocalProject: true,
          projectId: 'proj_api',
          healthPath: '/health',
          retries: 1,
          intervalSec: 30,
          public: true
        });
        httpMode = 'fail_500';
        await wiredUptime.runCheck(wMon.id);
        assert.strictEqual(wiredUptime.getMonitor(wMon.id).incidentOpen, true, 'incidentOpen boolean must mirror activeIncidentId');
        httpMode = 'ok';
        await wiredUptime.runCheck(wMon.id);
        assert.strictEqual(wiredUptime.getMonitor(wMon.id).incidentOpen, false);
        assert.strictEqual(sentNotifBodies.length, 2, 'Real NotificationService must deliver both uptime_down and uptime_recovered');

        // listPageIncidents check
        wiredUptime.saveStatusPage({ slug: 'wired-page', title: 'Wired Status', monitorIds: [wMon.id] });
        const pi = wiredUptime.publishStatusIncident('wired-page', { title: 'Test Inc', severity: 'minor' });
        assert.strictEqual(wiredUptime.listPageIncidents('wired-page').length, 1);
        wiredUptime.resolveStatusIncident('wired-page', pi.id);
      } finally {
        wiredUptime.stop();
      }

      // B. SleepAdvisor cron schedule evaluation (sleepCron -> sleep, wakeCron -> wake)
      dockerCalls.length = 0;
      const schedDate = new Date(2026, 4, 15, 2, 30, 0); // 02:30 local
      advisor.setPolicy('proj_web', {
        enabled: true,
        mode: 'stop',
        idleMinutes: 60,
        schedule: { sleepCron: '30 2 * * *', wakeCron: '0 8 * * *' }
      });
      const schedSleep = await advisor.checkIdleProjects({ now: schedDate.getTime() });
      assert.ok(schedSleep.slept.includes('proj_web'), 'sleepCron matching 02:30 must sleep proj_web');
      assert.strictEqual(advisor.isSleeping('proj_web'), true);

      const wakeDate = new Date(2026, 4, 15, 8, 0, 0); // 08:00 local
      const schedWake = await advisor.checkIdleProjects({ now: wakeDate.getTime() });
      assert.ok(schedWake.woken.includes('proj_web'), 'wakeCron matching 08:00 must wake proj_web');
      assert.strictEqual(advisor.isSleeping('proj_web'), false);

      // C. handleWakeRequest real HTTP proxy forwarding (strips secret header, forwards wake-path & host)
      let proxiedHeaders = null;
      let proxiedUrl = null;
      const wakeTargetServer = http.createServer((req, res) => {
        proxiedHeaders = req.headers;
        proxiedUrl = req.url;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ proxied: true }));
      });
      await new Promise((resolve) => wakeTargetServer.listen(0, '127.0.0.1', resolve));
      const wakeTargetPort = /** @type {net.AddressInfo} */ (wakeTargetServer.address()).port;
      mockDeployStore.proj_web.current.hostPort = wakeTargetPort;

      try {
        await advisor.sleepProject('proj_web', { mode: 'pause' });
        const proxyServer = http.createServer((req, res) => {
          advisor.handleWakeRequest(req, res, 'proj_web');
        });
        await new Promise((resolve) => proxyServer.listen(0, '127.0.0.1', resolve));
        const proxyPort = /** @type {net.AddressInfo} */ (proxyServer.address()).port;

        try {
          const proxyResp = await new Promise((resolve, reject) => {
            const r = http.request({
              hostname: '127.0.0.1',
              port: proxyPort,
              path: '/_culkibo/wake/proj_web',
              method: 'GET',
              headers: {
                'Accept': 'application/json',
                'X-Culkibo-Wake-Secret': secret,
                'X-Culkibo-Wake-Host': 'app.example.com',
                'X-Culkibo-Wake-Path': '/api/v1/orders?page=2'
              }
            }, (res) => {
              let data = '';
              res.on('data', (c) => { data += c; });
              res.on('end', () => resolve({ status: res.statusCode, body: data }));
            });
            r.on('error', reject);
            r.end();
          });
          assert.strictEqual(proxyResp.status, 200);
          assert.ok(proxyResp.body.includes('"proxied":true'));
          assert.strictEqual(proxiedUrl, '/api/v1/orders?page=2', 'handleWakeRequest must forward X-Culkibo-Wake-Path');
          assert.strictEqual(proxiedHeaders.host, 'app.example.com', 'handleWakeRequest must restore X-Culkibo-Wake-Host');
          assert.strictEqual(proxiedHeaders['x-culkibo-wake-secret'], undefined, 'Wake secret MUST be stripped before forwarding to app container');

          // Browser slow-wake (>800ms) returns branded waking HTML with 503 + CSP
          await advisor.sleepProject('proj_web', { mode: 'pause' });
          wakeDelayMs = 1100;
          const htmlResp = await new Promise((resolve, reject) => {
            const r = http.request({
              hostname: '127.0.0.1',
              port: proxyPort,
              path: '/_culkibo/wake/proj_web',
              method: 'GET',
              headers: {
                'Accept': 'text/html',
                'X-Culkibo-Wake-Secret': secret
              }
            }, (res) => {
              let data = '';
              res.on('data', (c) => { data += c; });
              res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
            });
            r.on('error', reject);
            r.end();
          });
          wakeDelayMs = 0;
          assert.strictEqual(htmlResp.status, 503, 'Slow browser wake (>800ms) must return 503 branded HTML');
          assert.strictEqual(htmlResp.headers['content-security-policy'], WAKING_PAGE_CSP);
          assert.ok(htmlResp.body.includes('Waking service'), 'Branded waking HTML must be served');
        } finally {
          await new Promise((resolve) => proxyServer.close(resolve));
        }
      } finally {
        await new Promise((resolve) => wakeTargetServer.close(resolve));
      }

      advisor.setPolicy('proj_web', { enabled: false });
      console.log('  ✓ Real NotificationService uptime delivery, cron schedule sleep/wake & live HTTP handleWakeRequest proxy/HTML hold verified');
    }

    advisor.stop();

    console.log('  ✓ VPS Cost & RAM Advisor (OOM risk, idle auto-sleep, oversized cap, SaaS-vs-VPS ledger & Doctor summary) verified');
    console.log('✅ All Uptime Monitor, Status Pages, Smart Sleep & Cost Advisor tests passed!\n');
  } finally {
    if (uptime) uptime.stop();
    if (advisor) advisor.stop();
    if (localHttpServer) {
      await new Promise((resolve) => localHttpServer.close(resolve));
    }
    if (localTcpServer) {
      await new Promise((resolve) => localTcpServer.close(resolve));
    }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) {}
  }
}

module.exports = testUptimeSleep;

if (require.main === module) {
  testUptimeSleep().catch((err) => {
    console.error('❌ Uptime/Sleep test failure:', err);
    process.exit(1);
  });
}
