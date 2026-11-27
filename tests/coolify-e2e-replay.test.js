const assert = require('assert');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const coolifyMigrator = require('../server/services/coolifyMigrator');
const bundleArchiver = require('../server/services/bundleArchiver');
const { ProjectManager } = require('../server/services/projectManager');
const DomainManagerMod = require('../server/services/domainManager');
const { CronManager } = require('../server/services/cronManager');
const { EnvironmentManager } = require('../server/services/environmentManager');

/**
 * Full Mock-Coolify v4 Production Estate End-to-End Replay Test.
 *
 * Spins up a real in-process HTTP server emulating Coolify v4 REST API endpoints
 * serving a complex production estate (2 apps incl. Next.js Git + Docker Compose with
 * mem_limit/cpus + Base64 & plain Traefik labels + Magic Vars + Scheduled Tasks,
 * 3 DBs: PostgreSQL, Redis, ClickHouse, and named persistent volumes), then executes:
 *   planMigration() -> migrateFromCoolify() -> buildVolumeAndDbStreamPlan()
 *   -> verifyMigratedStack() -> exportMigrationBundle(.zip AES-256-GCM)
 *   -> bundleArchiver.importStackBundle() into a SECOND fresh isolated store!
 *
 * Runs 100% isolated inside os.tmpdir() — ZERO mutations to live data/.
 */
async function runTests() {
  console.log('--- Iniciando Coolify v4 Production Estate E2E Replay Test ---');

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-coolify-e2e-'));
  const storeADir = path.join(tmpRoot, 'store-a');
  const storeBDir = path.join(tmpRoot, 'store-b');
  fs.mkdirSync(path.join(storeADir, 'data'), { recursive: true });
  fs.mkdirSync(path.join(storeBDir, 'data'), { recursive: true });

  const VALID_TOKEN = '1|coolify_e2e_read_all_token_2026';
  const BCRYPT_HASH = '$2b$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ01234';

  // Production Estate Fixtures served by real Mock Coolify v4 HTTP API
  const projectsFixture = [
    { uuid: 'proj-saas-core', name: 'SaaS Production Estate', description: 'Main Coolify v4 production stack' }
  ];

  const base64TraefikLabels = Buffer.from(
    [
      'traefik.enable=true',
      'traefik.http.routers.web.rule=Host(`app.estate.dev`) && PathPrefix(`/api`)',
      'traefik.http.routers.web.middlewares=strip-api,cors-web,hsts-web,authelia-web,basic-web',
      'traefik.http.routers.web.service=web-svc',
      'traefik.http.services.web-svc.loadbalancer.server.port=3005',
      'traefik.http.middlewares.strip-api.stripprefix.prefixes=/api',
      'traefik.http.middlewares.cors-web.headers.accesscontrolalloworiginlist=https://app.estate.dev',
      'traefik.http.middlewares.cors-web.headers.accesscontrolallowmethods=GET,POST,OPTIONS',
      'traefik.http.middlewares.hsts-web.headers.stsseconds=31536000',
      'traefik.http.middlewares.hsts-web.headers.stspreload=true',
      'traefik.http.middlewares.authelia-web.forwardauth.address=http://authelia:9091/api/verify',
      `traefik.http.middlewares.basic-web.basicauth.users=ops:${BCRYPT_HASH.replace(/\$/g, '$$')}`
    ].join('\n'),
    'utf8'
  ).toString('base64');

  const appsFixture = [
    {
      uuid: 'app-nextjs',
      name: 'NextJS Web',
      description: 'Next.js App Router production frontend',
      fqdn: 'https://app.estate.dev',
      build_pack: 'nixpacks',
      git_repository: 'https://github.com/estate/nextjs-web',
      git_branch: 'main',
      build_command: 'npm run build',
      start_command: 'npm start',
      ports_exposes: '3000',
      limits_memory: '1g',
      limits_cpus: '2',
      health_check_enabled: true,
      health_check_path: '/api/health',
      health_check_method: 'GET',
      status: 'running:healthy',
      project_id: 'proj-saas-core',
      custom_labels: base64TraefikLabels
    },
    {
      uuid: 'app-compose-worker',
      name: 'Compose API Worker',
      description: 'Docker Compose multi-service backend with plain Traefik labels',
      fqdn: 'https://worker.estate.dev',
      build_pack: 'dockercompose',
      ports_exposes: '8080',
      limits_memory: '512m',
      limits_cpus: '1',
      health_check_enabled: true,
      health_check_path: '/healthz',
      status: 'running:healthy',
      project_id: 'proj-saas-core',
      docker_compose: [
        'services:',
        '  worker:',
        '    image: ghcr.io/estate/worker:1.4.0',
        '    mem_limit: 512m',
        '    cpus: 1.0',
        '    labels:',
        '      - "traefik.http.services.worker.loadbalancer.server.port=8088"',
        '      - "traefik.http.middlewares.worker-hdr.headers.stspreload=true"',
        '      - "traefik.http.middlewares.worker-hdr.headers.stsseconds=63072000"',
        '    environment:',
        '      - WORKER_PUBLIC_URL=${SERVICE_URL_WORKER}',
        '      - WORKER_SIGNING_KEY=${SERVICE_PASSWORD_64_WORKER}'
      ].join('\n')
    }
  ];

  const appEnvsMap = {
    'app-nextjs': [
      { key: 'NODE_ENV', value: 'production', is_preview: false },
      { key: 'NEXT_PUBLIC_HOST', value: '${SERVICE_FQDN_WEB}', is_preview: false },
      { key: 'NEXTAUTH_URL', value: '${COOLIFY_URL}', is_preview: false },
      { key: 'NEXTAUTH_SECRET', value: '${SERVICE_PASSWORD_64_NEXTAUTH}', is_preview: false },
      { key: 'STRIPE_SECRET_KEY', value: 'sk_live_estateSecretKey_NEVER_LEAK_999', is_preview: false },
      { key: 'PREVIEW_ONLY_FLAG', value: '1', is_preview: true }
    ],
    'app-compose-worker': [
      { key: 'APP_BRANCH', value: '${COOLIFY_BRANCH}', is_preview: false },
      { key: 'APP_CONTAINER', value: '${COOLIFY_CONTAINER_NAME}', is_preview: false },
      { key: 'WORKER_API_KEY', value: '${SERVICE_BASE64_64_WORKERKEY}', is_preview: false }
    ]
  };

  const appStoragesMap = {
    'app-nextjs': {
      persistent_storages: [{ name: 'nextjs_media_uploads', mount_path: '/app/public/uploads' }],
      file_storages: [{ fs_path: '/data/next.config.override.js', mount_path: '/app/override.js', content: 'module.exports={};' }]
    },
    'app-compose-worker': {
      persistent_storages: [{ name: 'worker_spool_vol', mount_path: '/var/spool/worker' }],
      file_storages: []
    }
  };

  const appTasksMap = {
    'app-nextjs': [
      { name: 'Session GC', frequency: 'daily', command: 'node scripts/gc-sessions.js', enabled: true }
    ],
    'app-compose-worker': [
      { name: 'Digest Rollup', frequency: 'hourly', command: 'node scripts/rollup.js', enabled: true }
    ]
  };

  const dbsFixture = [
    {
      uuid: 'db-pg-main',
      name: 'EstatePostgres',
      database_type: 'standalone-postgresql',
      image: 'postgres:17-alpine',
      postgres_user: 'estate_admin',
      postgres_password: 'SUPER_SECRET_PG_PASS_E2E',
      postgres_db: 'estate_prod',
      status: 'running:healthy',
      project_id: 'proj-saas-core'
    },
    {
      uuid: 'db-redis-cache',
      name: 'EstateRedis',
      database_type: 'standalone-redis',
      image: 'redis:7.4-alpine',
      redis_password: 'SUPER_SECRET_REDIS_PASS_E2E',
      status: 'running:healthy',
      project_id: 'proj-saas-core'
    },
    {
      uuid: 'db-clickhouse-events',
      name: 'EstateClickHouse',
      database_type: 'standalone-clickhouse',
      image: 'clickhouse/clickhouse-server:24.8-alpine',
      clickhouse_admin_user: 'ch_admin',
      clickhouse_admin_password: 'SUPER_SECRET_CH_PASS_E2E',
      status: 'running:healthy',
      project_id: 'proj-saas-core'
    }
  ];

  const dbStoragesMap = {
    'db-pg-main': { persistent_storages: [{ name: 'pg_estate_data', mount_path: '/var/lib/postgresql/data' }], file_storages: [] },
    'db-redis-cache': { persistent_storages: [{ name: 'redis_estate_data', mount_path: '/data' }], file_storages: [] },
    'db-clickhouse-events': { persistent_storages: [{ name: 'ch_estate_data', mount_path: '/var/lib/clickhouse' }], file_storages: [] }
  };

  // Start real Mock Coolify v4 HTTP API server + simulated source/target smoke target server
  const mockCoolifyServer = http.createServer((req, res) => {
    const auth = req.headers.authorization || '';
    if (auth !== `Bearer ${VALID_TOKEN}`) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ message: 'Unauthenticated.' }));
      return;
    }

    const urlPath = (req.url || '').split('?')[0];
    const sendJson = (obj) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(obj));
    };

    if (urlPath === '/api/v1/projects') return sendJson(projectsFixture);
    if (urlPath === '/api/v1/applications') return sendJson(appsFixture.map((a) => ({ uuid: a.uuid, name: a.name })));
    if (urlPath === '/api/v1/databases') return sendJson(dbsFixture.map((d) => ({ uuid: d.uuid, name: d.name })));
    if (urlPath === '/api/v1/services') return sendJson([]);

    const appMatch = urlPath.match(/^\/api\/v1\/applications\/([^/]+)(?:\/(envs|storages|scheduled-tasks))?$/);
    if (appMatch) {
      const id = decodeURIComponent(appMatch[1]);
      const sub = appMatch[2];
      const found = appsFixture.find((a) => a.uuid === id);
      if (!found) { res.writeHead(404); res.end('{}'); return; }
      if (!sub) return sendJson(found);
      if (sub === 'envs') return sendJson(appEnvsMap[id] || []);
      if (sub === 'storages') return sendJson(appStoragesMap[id] || { persistent_storages: [], file_storages: [] });
      if (sub === 'scheduled-tasks') return sendJson(appTasksMap[id] || []);
    }

    const dbMatch = urlPath.match(/^\/api\/v1\/databases\/([^/]+)(?:\/(envs|storages))?$/);
    if (dbMatch) {
      const id = decodeURIComponent(dbMatch[1]);
      const sub = dbMatch[2];
      const found = dbsFixture.find((d) => d.uuid === id);
      if (!found) { res.writeHead(404); res.end('{}'); return; }
      if (!sub) return sendJson(found);
      if (sub === 'envs') return sendJson([]);
      if (sub === 'storages') return sendJson(dbStoragesMap[id] || { persistent_storages: [], file_storages: [] });
    }

    res.writeHead(404);
    res.end('[]');
  });

  // Mock target HTTP endpoint server for real live verifyMigratedStack() check
  const mockTargetServer = http.createServer((req, res) => {
    res.writeHead(200, {
      'content-type': 'application/json',
      'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
      'access-control-allow-origin': 'https://app.estate.dev'
    });
    res.end(JSON.stringify({ ok: true, host: req.headers.host || '', path: req.url || '/' }));
  });

  // Mock localRunner.prepareProject so background git clones are never launched
  const localRunner = require('../server/services/localRunner');
  const ingressManager = require('../server/services/ingressManager');
  const realPrepare = localRunner.prepareProject;
  const realReconcile = ingressManager.reconcile;
  localRunner.prepareProject = async () => {};
  ingressManager.reconcile = async () => {};

  await new Promise((resolve) => mockCoolifyServer.listen(0, '127.0.0.1', resolve));
  await new Promise((resolve) => mockTargetServer.listen(0, '127.0.0.1', resolve));
  const coolifyPort = /** @type {any} */ (mockCoolifyServer.address()).port;
  const targetPort = /** @type {any} */ (mockTargetServer.address()).port;
  const mockCoolifyUrl = `http://127.0.0.1:${coolifyPort}`;

  const DomainManagerClass = DomainManagerMod.DomainManager || DomainManagerMod.constructor;

  // Create isolated Store A (primary migration target) & Store B (portable .zip bundle restore target)
  const pmA = new ProjectManager({ dataPath: path.join(storeADir, 'data', 'projects.json'), seedDefaults: false });
  const dmA = new DomainManagerClass({ dataDir: path.join(storeADir, 'data'), seedDefaults: false });
  const cmA = new CronManager(path.join(storeADir, 'data', 'crons.json'));

  const pmB = new ProjectManager({ dataPath: path.join(storeBDir, 'data', 'projects.json'), seedDefaults: false });
  const dmB = new DomainManagerClass({ dataDir: path.join(storeBDir, 'data'), seedDefaults: false });
  const cmB = new CronManager(path.join(storeBDir, 'data', 'crons.json'));
  const emB = new EnvironmentManager({ dataDir: path.join(storeBDir, 'data') });

  try {
    // 1. Live HTTP Auth Failure Check (401 rejection)
    await assert.rejects(
      () => coolifyMigrator.planMigration(mockCoolifyUrl, 'wrong_token', { allowLoopback: true }),
      /401|rechazado/i
    );
    console.log('  ✓ 1. Mock Coolify v4 HTTP API rejects invalid bearer token (401)');

    // 2. Live HTTP planMigration() against Mock Coolify v4 Estate
    const plan = await coolifyMigrator.planMigration(mockCoolifyUrl, VALID_TOKEN, { allowLoopback: true });
    assert.strictEqual(plan.summary.apps, 2);
    assert.strictEqual(plan.summary.databases, 3);
    assert.strictEqual(plan.summary.domains, 2);
    assert.strictEqual(plan.summary.cronsMapped, 2);
    assert.ok(plan.summary.magicVarsTranslated >= 6);
    assert.ok(plan.summary.traefikRulesTranslated >= 6);
    assert.ok(plan.parityScore >= 90, `Expected parityScore >= 90, got ${plan.parityScore}`);

    // Zero plaintext secret leakage guarantee in dry-run plan!
    const planStr = JSON.stringify(plan);
    for (const secret of [
      'sk_live_estateSecretKey_NEVER_LEAK_999',
      'SUPER_SECRET_PG_PASS_E2E',
      'SUPER_SECRET_REDIS_PASS_E2E',
      'SUPER_SECRET_CH_PASS_E2E',
      BCRYPT_HASH
    ]) {
      assert.ok(!planStr.includes(secret), `Secret leaked in planMigration output: ${secret}`);
    }
    console.log(`  ✓ 2. planMigration() live HTTP replay PASS (parity=${plan.parityScore}%, 0 leaked secrets)`);

    // 3. Live migrateFromCoolify() into Isolated Store A
    const migRes = await coolifyMigrator.migrateFromCoolify(mockCoolifyUrl, VALID_TOKEN, {
      allowLoopback: true,
      projectManager: pmA,
      domainManager: dmA,
      cronManager: cmA
    });
    assert.strictEqual(migRes.importedApps, 2);
    assert.strictEqual(migRes.importedDbs, 3);
    assert.strictEqual(migRes.importedCrons, 2);
    assert.strictEqual(migRes.domainsLinked, 2);
    assert.ok(migRes.traefikRulesApplied >= 6);
    assert.strictEqual(migRes.errors.length, 0);

    // Assert persisted Store A parity (Project, Domains w/ Traefik→Caddy Edge, Crons)
    const savedProjectsA = pmA.getAll();
    assert.strictEqual(savedProjectsA.length, 1);
    const estateProj = savedProjectsA[0];
    assert.strictEqual(estateProj.name, 'SaaS Production Estate');
    assert.strictEqual(estateProj.resources.length, 5); // 2 apps + 3 DBs
    assert.strictEqual(estateProj.memoryMb, 1024);
    assert.strictEqual(estateProj.cpus, 2);
    assert.strictEqual(estateProj.envVars.NEXTAUTH_SECRET, '${vault.SERVICE_PASSWORD_64_NEXTAUTH}');
    assert.strictEqual(estateProj.envVars.NEXTAUTH_URL, 'https://app.estate.dev');

    const domWeb = dmA.getByHostname('app.estate.dev');
    assert.ok(domWeb, 'app.estate.dev must be registered in isolated DomainManager');
    assert.strictEqual(domWeb.targetPort, 3005);
    assert.strictEqual(domWeb.hstsPreload, true);
    assert.strictEqual(domWeb.cors.enabled, true);
    assert.strictEqual(domWeb.forwardAuth.upstream, 'authelia:9091');
    assert.strictEqual(domWeb.pathRoutes[0].stripPrefix, '/api');
    assert.strictEqual(domWeb.basicAuth.enabled, true);

    const domWorker = dmA.getByHostname('worker.estate.dev');
    assert.ok(domWorker, 'worker.estate.dev must be registered');
    assert.strictEqual(domWorker.targetPort, 8088);
    assert.strictEqual(domWorker.hstsPreload, true);

    const cronsA = cmA.list(estateProj.id);
    assert.strictEqual(cronsA.length, 2);
    console.log('  ✓ 3. migrateFromCoolify() persisted 100% resource/Traefik→Caddy/cron parity into isolated Store A');

    // 4. Live buildVolumeAndDbStreamPlan() on fetched snapshot
    const fetchedSnapshot = {
      apps: await coolifyMigrator.fetchApplications(mockCoolifyUrl, VALID_TOKEN, { allowLoopback: true }),
      databases: await coolifyMigrator.fetchDatabases(mockCoolifyUrl, VALID_TOKEN, { allowLoopback: true }),
      services: [],
      projects: projectsFixture
    };
    const streamPlan = coolifyMigrator.buildVolumeAndDbStreamPlan(fetchedSnapshot, {
      sourceHost: '198.51.100.77',
      sourceUser: 'coolify-ops',
      sourcePort: 22
    });
    assert.strictEqual(streamPlan.zeroShell, true);
    assert.strictEqual(streamPlan.summary.databases, 3);
    assert.strictEqual(streamPlan.summary.volumes, 5); // 2 app vols + 3 DB vols
    const streamStr = JSON.stringify(streamPlan);
    assert.ok(!streamStr.includes('SUPER_SECRET_PG_PASS_E2E'));
    assert.ok(!streamStr.includes('SUPER_SECRET_CH_PASS_E2E'));
    console.log('  ✓ 4. buildVolumeAndDbStreamPlan() generated zero-shell arg arrays for 3 DBs + 5 named volumes (0 secrets in argv)');

    // 5. Live verifyMigratedStack() against in-process loopback HTTP server
    const verifyRes = await coolifyMigrator.verifyMigratedStack(
      [
        {
          name: 'NextJS Web',
          hostname: 'app.estate.dev',
          sourceUrl: `http://127.0.0.1:${targetPort}/api/health`,
          targetUrl: `http://127.0.0.1:${targetPort}/api/health`,
          healthPath: '/api/health',
          expectedStatus: 200,
          expectedHeaders: ['strict-transport-security', 'access-control-allow-origin']
        },
        {
          name: 'Compose API Worker',
          hostname: 'worker.estate.dev',
          sourceUrl: `http://127.0.0.1:${targetPort}/healthz`,
          targetUrl: `http://127.0.0.1:${targetPort}/healthz`,
          healthPath: '/healthz',
          expectedStatus: 200,
          expectedHeaders: ['strict-transport-security']
        }
      ],
      { allowLoopback: true }
    );
    assert.strictEqual(verifyRes.cutoverReady, true);
    assert.strictEqual(verifyRes.parityPercent, 100);
    assert.strictEqual(verifyRes.summary.passed, 2);
    console.log('  ✓ 5. verifyMigratedStack() live loopback HTTP parity check PASS (100% cutoverReady)');

    // 6. Export Portable .zip Bundle (AES-256-GCM Vault) → Import into Fresh Isolated Store B!
    const VAULT_PASSPHRASE = 'estate-e2e-portable-vault-2026';
    const bundle = coolifyMigrator.exportMigrationBundle(fetchedSnapshot, {
      stackName: 'Estate Portable ZIP',
      format: 'zip',
      passphrase: VAULT_PASSPHRASE
    });
    assert.strictEqual(bundle.ok, true);
    assert.strictEqual(bundle.format, 'zip');

    // Confirm zero plaintext secrets in cleartext ZIP files (culkibo.yaml, projects.json, domains.json)
    const rawEntries = bundleArchiver.parseZipBuffer(bundle.buffer).files;
    for (const fname of ['culkibo.yaml', 'projects.json', 'domains.json', 'databases.json', 'crons.json', 'mcp-agent-config.json']) {
      const txt = rawEntries[fname].toString('utf8');
      assert.ok(!txt.includes('sk_live_estateSecretKey_NEVER_LEAK_999'), `Plaintext Stripe key leaked in ${fname}`);
      assert.ok(!txt.includes('SUPER_SECRET_PG_PASS_E2E'), `Plaintext PG password leaked in ${fname}`);
      assert.ok(!txt.includes(BCRYPT_HASH), `Bcrypt hash leaked in ${fname}`);
    }

    // Restore portable .zip into completely separate Store B
    const importB = await bundleArchiver.importStackBundle(bundle.buffer, {
      passphrase: VAULT_PASSPHRASE,
      projectManager: pmB,
      domainManager: dmB,
      cronManager: cmB,
      environmentManager: emB
    });
    assert.strictEqual(importB.ok, true);
    assert.strictEqual(importB.errors.length, 0);
    assert.strictEqual(importB.importedProjects, 2);
    assert.strictEqual(importB.importedDomains, 2);
    assert.strictEqual(importB.importedCrons, 2);
    assert.ok(importB.importedVaultSecrets >= 4, `Expected >= 4 restored AES-256-GCM vault secrets, got ${importB.importedVaultSecrets}`);

    // Verify Store B actually persisted projects, domains (with Caddy Edge rules!), crons, and encrypted vault secrets
    assert.strictEqual(pmB.getAll().length, 2);
    assert.ok(dmB.getByHostname('app.estate.dev'));
    assert.strictEqual(dmB.getByHostname('app.estate.dev').hstsPreload, true);
    assert.strictEqual(dmB.getByHostname('app.estate.dev').cors.enabled, true);
    assert.strictEqual(dmB.getByHostname('worker.estate.dev').targetPort, 8088);
    assert.strictEqual(cmB.list().length, 2);
    assert.ok(emB.listVaultSecrets().length >= 4);
    console.log('  ✓ 6. exportMigrationBundle(.zip AES-256-GCM) → importStackBundle() into fresh Store B PASS (100% parity, 0 leaks)');

    console.log('\n✅ Coolify v4 Production Estate E2E Replay Test: 6/6 stages PASSED!');
  } finally {
    localRunner.prepareProject = realPrepare;
    ingressManager.reconcile = realReconcile;
    try { cmA.stopScheduler(); } catch (e) {}
    try { cmB.stopScheduler(); } catch (e) {}
    await new Promise((r) => mockCoolifyServer.close(r));
    await new Promise((r) => mockTargetServer.close(r));
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ Coolify E2E Replay Test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
