const assert = require('assert');
const zlib = require('zlib');
const migrator = require('../server/services/coolifyMigrator');
const bundleArchiver = require('../server/services/bundleArchiver');

async function runTests() {
  console.log('--- Iniciando Tests de Coolify Migrator v4 + Bundle Archiver ---');
  let passed = 0;
  let failed = 0;

  // Mock domainManager, projectManager, ingressManager and cronManager so tests NEVER mutate live data/*.json
  const projectManager = require('../server/services/projectManager');
  const domainManager = require('../server/services/domainManager');
  const ingressManager = require('../server/services/ingressManager');
  const cronManager = require('../server/services/cronManager');
  const localRunner = require('../server/services/localRunner');

  const realCreate = projectManager.create;
  const realFlush = projectManager.flushToDisk;
  const realAddDomain = domainManager.addDomain;
  const realReconcile = ingressManager.reconcile;
  const realCronCreate = cronManager.create;
  const realPrepareProject = localRunner.prepareProject;
  const originalFetch = migrator.fetchFromApi;

  const restoreSingletons = () => {
    projectManager.create = realCreate;
    projectManager.flushToDisk = realFlush;
    domainManager.addDomain = realAddDomain;
    ingressManager.reconcile = realReconcile;
    cronManager.create = realCronCreate;
    localRunner.prepareProject = realPrepareProject;
    migrator.fetchFromApi = originalFetch;
  };

  const runCase = async (name, fn) => {
    try {
      await fn();
      console.log(`  ✓ ${name}`);
      passed++;
    } catch (e) {
      console.error(`  ✗ ${name} falló:`, e);
      failed++;
    }
  };

  try {
    projectManager.create = () => {};
    projectManager.flushToDisk = async () => {};
    domainManager.addDomain = async () => {};
    ingressManager.reconcile = async () => {};
    cronManager.create = () => {};
    localRunner.prepareProject = async () => {};

    // =========================================================================
    // BASELINE TESTS 1-5 (Original Contract Compatibility)
    // =========================================================================
    const appFixture = {
      uuid: 'app-1',
      name: 'AuraCV API',
      fqdn: 'https://api.tryauracv.com',
      git_repository: 'macaqueboy/AuraCV',
      git_full_url: 'git@github.com:macaqueboy/AuraCV.git',
      status: 'running',
      project_id: 'proj-1',
      install_command: 'npm install',
      build_command: 'npm run build',
      start_command: 'npm start',
      limits_memory: '512m',
      health_check_path: '/health',
      environment_variables: [{ key: 'NODE_ENV', value: 'production' }],
      local_persistent_volumes: [{ name: 'data', mount_path: '/data' }],
      local_file_volumes: [{ fs_path: '/tmp/test', mount_path: '/test' }]
    };

    const dbFixture = {
      uuid: 'db-1',
      name: 'GaleiaDB',
      database_type: 'postgresql',
      postgres_user: 'root',
      postgres_password: 'pwd',
      postgres_db: 'galeia',
      status: 'running',
      project_id: 'proj-1',
      volumes: [{ name: 'db-data', mount_path: '/var/lib/postgresql/data' }],
      environment_variables: [{ key: 'PG_PASS', value: 'pwd' }]
    };

    const svcFixture = {
      uuid: 'svc-1',
      name: 'Redis Cache',
      docker_compose: 'version: "3"\nservices:\n  redis:\n    image: redis',
      status: 'running',
      project_id: 'proj-2',
      environment_variables: []
    };

    const projFixture = [
      { uuid: 'proj-1', name: 'Aura Project' },
      { uuid: 'proj-2', name: 'Other Project' }
    ];

    migrator.fetchFromApi = async (url, token, endpoint) => {
      if (endpoint === '/api/v1/applications') return [{ uuid: 'app-1' }];
      if (endpoint === '/api/v1/applications/app-1') return appFixture;
      if (endpoint === '/api/v1/applications/app-1/envs') return appFixture.environment_variables;
      if (endpoint === '/api/v1/applications/app-1/storages') return { persistent_storages: [{ name: 'data', mount_path: '/data' }], file_storages: [{ fs_path: '/tmp/test', mount_path: '/test' }] };
      if (endpoint === '/api/v1/applications/app-1/scheduled-tasks') return [];

      if (endpoint === '/api/v1/databases') return [{ uuid: 'db-1' }];
      if (endpoint === '/api/v1/databases/db-1') return dbFixture;
      if (endpoint === '/api/v1/databases/db-1/envs') return dbFixture.environment_variables;
      if (endpoint === '/api/v1/databases/db-1/storages') return { persistent_storages: [{ name: 'db-data', mount_path: '/var/lib/postgresql/data' }], file_storages: [] };

      if (endpoint === '/api/v1/services') return [{ uuid: 'svc-1' }];
      if (endpoint === '/api/v1/services/svc-1') return svcFixture;
      if (endpoint === '/api/v1/services/svc-1/envs') return svcFixture.environment_variables;
      if (endpoint === '/api/v1/services/svc-1/storages') return { persistent_storages: [], file_storages: [] };
      if (endpoint === '/api/v1/services/svc-1/scheduled-tasks') return [];

      if (endpoint === '/api/v1/projects') return projFixture;
      return [];
    };

    await runCase('Test 1: App fetch & mapping', async () => {
      const apps = await migrator.fetchApplications('url', 'tok');
      assert.strictEqual(apps.length, 1);
      assert.strictEqual(apps[0].build_command, 'npm run build');
      assert.strictEqual(apps[0].local_persistent_volumes.length, 1);
      assert.strictEqual(apps[0].environment_variables.length, 1);
    });

    await runCase('Test 2: PostgreSQL DB fetch & mapping', async () => {
      const dbs = await migrator.fetchDatabases('url', 'tok');
      assert.strictEqual(dbs.length, 1);
      assert.strictEqual(dbs[0].postgres_db, 'galeia');
      assert.strictEqual(dbs[0].volumes.length, 1);
    });

    await runCase('Test 3: Compose service fetch', async () => {
      const svcs = await migrator.fetchServices('url', 'tok');
      assert.strictEqual(svcs.length, 1);
      assert.ok(svcs[0].docker_compose.includes('redis'));
    });

    await runCase('Test 4: Grouping by Project + Preview Plan', async () => {
      const createdProjects = {};
      projectManager.create = (projData) => {
        createdProjects[projData.id] = projData;
        return { ...projData };
      };
      const preview = await migrator.previewMigration('url', 'tok');
      assert.ok(preview.plan);
      assert.strictEqual(preview.plan.parityScore, 100);

      const res = await migrator.migrate('url', 'tok', ['app-1'], ['db-1'], ['svc-1']);
      assert.strictEqual(res.importedApps, 1);
      assert.strictEqual(res.importedDbs, 1);
      assert.strictEqual(res.importedServices, 1);
      const p1 = createdProjects['proj-1'];
      assert.ok(p1);
      assert.strictEqual(p1.name, 'Aura Project');
      assert.strictEqual(p1.resources.length, 2);
      assert.strictEqual(p1.memoryMb, 512);
      assert.strictEqual(p1.smokeTests.length, 1);
      const p2 = createdProjects['proj-2'];
      assert.ok(p2);
      assert.strictEqual(p2.name, 'Other Project');
      assert.strictEqual(p2.resources.length, 1);
    });

    await runCase('Test 5: API error propagation', async () => {
      const savedMock = migrator.fetchFromApi;
      migrator.fetchFromApi = async (url, token, endpoint) => {
        if (endpoint === '/api/v1/applications') throw new Error('No se pudo conectar a la API de Coolify. Verifica URL y Token.');
        return [];
      };
      try {
        await migrator.fetchApplications('url', 'tok');
        assert.fail('Should have thrown');
      } catch (e) {
        assert.ok(e.message.includes('No se pudo conectar'));
      } finally {
        migrator.fetchFromApi = savedMock;
      }
    });

    // =========================================================================
    // TEST 6: COOLIFY v4 MAGIC VARIABLES RESOLUTION & SECRET REDACTION
    // =========================================================================
    await runCase('Test 6: Coolify v4 Magic Vars resolution & dry-run redaction', async () => {
      const envInput = {
        PUBLIC_HOST: '${SERVICE_FQDN_WEB}',
        API_URL: '${SERVICE_URL_API_8080}/v1',
        DB_USER: '${SERVICE_USER_POSTGRES}',
        DB_PASSWORD: '${SERVICE_PASSWORD_POSTGRES}',
        JWT_SECRET: '${SERVICE_PASSWORD_64_JWT}',
        APP_KEY: 'base64:${SERVICE_BASE64_APPKEY}',
        ENC_KEY: '${SERVICE_BASE64_64_ENC}',
        SITE_FQDN: '${COOLIFY_FQDN}',
        SITE_URL: '${COOLIFY_URL}',
        DEPLOY_BRANCH: '${COOLIFY_BRANCH}',
        CONTAINER_ID: '${COOLIFY_CONTAINER_NAME}',
        STRIPE_SECRET_KEY: ['sk', 'live', 'superSecretTokenValue9999'].join('_')
      };

      const tr = migrator.translateMagicVariables(envInput, {
        resourceName: 'SaaS Portal',
        fqdn: 'https://app.pablo.dev,https://api.pablo.dev',
        gitBranch: 'production',
        serviceHostMap: {
          WEB: { host: 'app.pablo.dev', url: 'https://app.pablo.dev' },
          API: { host: 'api.pablo.dev', url: 'https://api.pablo.dev' }
        },
        dockerCompose: 'services:\n  web:\n    environment:\n      - SECRET=${SERVICE_PASSWORD_64_COMPOSE}'
      });

      assert.strictEqual(tr.translatedEnv.PUBLIC_HOST, 'app.pablo.dev');
      assert.strictEqual(tr.translatedEnv.API_URL, 'https://api.pablo.dev/v1');
      assert.strictEqual(tr.translatedEnv.DB_USER, '${vault.SERVICE_USER_POSTGRES}');
      assert.strictEqual(tr.translatedEnv.DB_PASSWORD, '${vault.SERVICE_PASSWORD_POSTGRES}');
      assert.strictEqual(tr.translatedEnv.JWT_SECRET, '${vault.SERVICE_PASSWORD_64_JWT}');
      assert.strictEqual(tr.translatedEnv.APP_KEY, 'base64:${vault.SERVICE_BASE64_APPKEY}');
      assert.strictEqual(tr.translatedEnv.ENC_KEY, '${vault.SERVICE_BASE64_64_ENC}');
      assert.strictEqual(tr.translatedEnv.SITE_FQDN, 'app.pablo.dev,api.pablo.dev');
      assert.strictEqual(tr.translatedEnv.SITE_URL, 'https://app.pablo.dev');
      assert.strictEqual(tr.translatedEnv.DEPLOY_BRANCH, 'production');
      assert.strictEqual(tr.translatedEnv.CONTAINER_ID, 'culkibo-saas-portal');
      assert.ok(tr.translatedCompose.includes('${vault.SERVICE_PASSWORD_64_COMPOSE}'));

      // Dry-run redaction guarantee: plaintext secret MUST NEVER appear in redactedPreviewEnv
      assert.ok(!tr.redactedPreviewEnv.STRIPE_SECRET_KEY.includes(['sk', 'live', 'superSecretTokenValue9999'].join('_')));
      assert.ok(tr.redactedPreviewEnv.STRIPE_SECRET_KEY.startsWith('[REDACTED:sha256:'));
      assert.ok(tr.vaultRefs.includes('SERVICE_PASSWORD_64_JWT'));
      assert.ok(tr.vaultRefs.includes('SERVICE_PASSWORD_64_COMPOSE'));
      assert.ok(tr.secretWarnings.length >= 1);
    });

    // =========================================================================
    // TEST 7: TRAEFIK LABELS (PLAIN + BASE64 + COMPOSE) → CADDY EDGE TRANSLATOR
    // =========================================================================
    await runCase('Test 7: Traefik labels (plain + Base64) → Culkibo Caddy Edge', async () => {
      const bcryptSample = '$2b$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ01234';
      const labelsPlain = [
        'traefik.enable=true',
        'traefik.http.routers.api.rule=Host(`edge.pablo.dev`) && PathPrefix(`/api/v2`)',
        'traefik.http.routers.api.middlewares=strip-api,cors-hdr,hsts-hdr,authelia,basic-adm,redir-old,ip-safe,rl-api',
        'traefik.http.routers.api.service=api-svc',
        'traefik.http.services.api-svc.loadbalancer.server.port=8085',
        'traefik.http.middlewares.strip-api.stripprefix.prefixes=/api/v2',
        'traefik.http.middlewares.cors-hdr.headers.accesscontrolalloworiginlist=https://pablo.dev,https://admin.pablo.dev',
        'traefik.http.middlewares.cors-hdr.headers.accesscontrolallowmethods=GET,POST,OPTIONS',
        'traefik.http.middlewares.cors-hdr.headers.accesscontrolallowcredentials=true',
        'traefik.http.middlewares.hsts-hdr.headers.stsseconds=63072000',
        'traefik.http.middlewares.hsts-hdr.headers.stspreload=true',
        'traefik.http.middlewares.hsts-hdr.headers.framedeny=true',
        'traefik.http.middlewares.hsts-hdr.headers.customresponseheaders.X-Powered-By=Culkibo',
        'traefik.http.middlewares.authelia.forwardauth.address=http://authelia:9091/api/verify',
        'traefik.http.middlewares.authelia.forwardauth.authresponseheaders=Remote-User,Remote-Email',
        `traefik.http.middlewares.basic-adm.basicauth.users=admin:${bcryptSample.replace(/\$/g, '$$')}`,
        'traefik.http.middlewares.basic-adm.basicauth.realm=Admin Zone',
        'traefik.http.middlewares.redir-old.redirectregex.regex=^/legacy/(.*)$',
        'traefik.http.middlewares.redir-old.redirectregex.replacement=/v2/${1}',
        'traefik.http.middlewares.redir-old.redirectregex.permanent=true',
        'traefik.http.middlewares.ip-safe.ipallowlist.sourcerange=10.0.0.0/8,192.168.1.5',
        'traefik.http.middlewares.rl-api.ratelimit.average=120',
        'traefik.http.middlewares.rl-api.ratelimit.period=1m'
      ].join('\n');

      // Base64 encode (just like Coolify v4 API returns `custom_labels`!)
      const b64Labels = Buffer.from(labelsPlain, 'utf8').toString('base64');
      const parsed = migrator.parseTraefikLabels(b64Labels);

      assert.strictEqual(parsed.targetPort, 8085);
      assert.deepStrictEqual(parsed.hosts, ['edge.pablo.dev']);
      assert.strictEqual(parsed.edgeConfig.pathRoutes.length, 1);
      assert.strictEqual(parsed.edgeConfig.pathRoutes[0].path, '/api/v2');
      assert.strictEqual(parsed.edgeConfig.pathRoutes[0].stripPrefix, '/api/v2');
      assert.strictEqual(parsed.edgeConfig.pathRoutes[0].upstreams[0], '127.0.0.1:8085');
      assert.strictEqual(parsed.edgeConfig.cors.enabled, true);
      assert.deepStrictEqual(parsed.edgeConfig.cors.allowedOrigins, ['https://pablo.dev', 'https://admin.pablo.dev']);
      assert.strictEqual(parsed.edgeConfig.cors.allowCredentials, true);
      assert.strictEqual(parsed.edgeConfig.hstsPreload, true);
      assert.strictEqual(parsed.edgeConfig.hstsMaxAge, 63072000);
      assert.strictEqual(parsed.edgeConfig.framePolicy, 'DENY');
      assert.strictEqual(parsed.edgeConfig.customHeaders.response['X-Powered-By'], 'Culkibo');
      assert.strictEqual(parsed.edgeConfig.forwardAuth.upstream, 'authelia:9091');
      assert.strictEqual(parsed.edgeConfig.forwardAuth.uri, '/api/verify');
      assert.strictEqual(parsed.edgeConfig.basicAuth.accounts[0].username, 'admin');
      assert.strictEqual(parsed.edgeConfig.basicAuth.accounts[0].passwordHash, bcryptSample);
      // Preview edge config must NOT expose passwordHash
      assert.strictEqual(parsed.previewEdgeConfig.basicAuth.accounts, undefined);
      assert.deepStrictEqual(parsed.previewEdgeConfig.basicAuth.usernames, ['admin']);
      assert.strictEqual(parsed.edgeConfig.pathRedirects[0].status, 301);
      assert.strictEqual(parsed.edgeConfig.rateLimit.requests, 120);
      assert.strictEqual(parsed.edgeConfig.rateLimit.windowSeconds, 60);

      // Verify translated edgeConfig passes real DomainManager validation!
      const validated = domainManager._validateEdgeFields(parsed.edgeConfig);
      assert.strictEqual(validated.hstsPreload, true);
      assert.strictEqual(validated.cors.enabled, true);
      assert.strictEqual(validated.forwardAuth.enabled, true);
      assert.strictEqual(validated.pathRoutes.length, 1);
    });

    // =========================================================================
    // TEST 8: ADVERSARIAL TRAEFIK SECURITY GUARDS (SSRF, ReDoS, CORS *, APR1)
    // =========================================================================
    await runCase('Test 8: Adversarial Traefik labels blocked (SSRF IMDS, ReDoS, CORS *, APR1)', async () => {
      const evilLabels = [
        'traefik.http.middlewares.evil-fa.forwardauth.address=http://169.254.169.254/latest/meta-data/',
        'traefik.http.middlewares.evil-redos.redirectregex.regex=^(a+)+$',
        'traefik.http.middlewares.evil-redos.redirectregex.replacement=/boom',
        'traefik.http.middlewares.evil-cors.headers.accesscontrolalloworiginlist=*',
        'traefik.http.middlewares.evil-cors.headers.accesscontrolallowcredentials=true',
        'traefik.http.middlewares.legacy-ba.basicauth.users=olduser:$$apr1$$hash1234567890',
        'traefik.http.middlewares.evil-hdr.headers.customresponseheaders.Host=evil.com',
        'traefik.http.middlewares.unknown-plug.plugin.mywaf.enabled=true'
      ].join('\n');

      const parsed = migrator.parseTraefikLabels(evilLabels);
      assert.strictEqual(parsed.edgeConfig.forwardAuth, undefined, 'SSRF IMDS forwardAuth must be blocked');
      assert.strictEqual(parsed.edgeConfig.pathRedirects, undefined, 'ReDoS regex must be blocked');
      assert.strictEqual(parsed.edgeConfig.cors.allowCredentials, false, 'CORS * + credentials must be stripped');
      assert.strictEqual(parsed.edgeConfig.basicAuth, undefined, 'Legacy APR1 hash must not be blindly passed to Caddy');
      assert.strictEqual(parsed.edgeConfig.customHeaders, undefined, 'Hop-by-hop Host header must be rejected');
      assert.ok(parsed.unsupportedLabels.length >= 1, 'Unknown plugin label must be reported');
      assert.ok(parsed.warnings.length >= 4, 'Must record clear security warnings');
    });

    // =========================================================================
    // TEST 9: FULL RESOURCE PARITY (8 DB ENGINES, COMPOSE, CRONS, HEALTHCHECKS)
    // =========================================================================
    await runCase('Test 9: Full Coolify v4 Stack Plan & Migration (Dragonfly, ClickHouse, Crons, Compose)', async () => {
      const snapshot = {
        projects: [{ uuid: 'p-prod', name: 'Production Stack' }],
        sharedEnvs: [{ key: 'TZ', value: 'Europe/Madrid' }],
        apps: [
          {
            uuid: 'app-web',
            name: 'NextJS Frontend',
            fqdn: 'https://pablo.dev',
            build_pack: 'nixpacks',
            git_repository: 'pablo/web',
            git_branch: 'main',
            ports_exposes: '3000',
            limits_memory: '1g',
            limits_cpus: '2',
            health_check_enabled: true,
            health_check_path: '/api/health',
            status: 'running:healthy',
            project_id: 'p-prod',
            custom_labels: 'traefik.http.middlewares.h.headers.stspreload=true\ntraefik.http.middlewares.h.headers.stsseconds=31536000',
            environment_variables: [
              { key: 'NEXTAUTH_URL', value: '${COOLIFY_URL}' },
              { key: 'NEXTAUTH_SECRET', value: '${SERVICE_PASSWORD_64_AUTH}' },
              { key: 'PREVIEW_FLAG', value: 'true', is_preview: true }
            ],
            scheduled_tasks: [
              { name: 'Cleanup sessions', frequency: 'daily', command: 'node scripts/cleanup.js', enabled: true },
              { name: 'Shell pipe task', frequency: 'hourly', command: 'node a.js | grep err && echo ok', enabled: true }
            ]
          }
        ],
        databases: [
          { uuid: 'db-pg', name: 'MainPG', database_type: 'standalone-postgresql', image: 'pgvector/pgvector:0.8.0-pg17', postgres_user: 'app', postgres_password: 'secretPgPassword123', postgres_db: 'appdb', is_public: true, project_id: 'p-prod' },
          { uuid: 'db-df', name: 'FastCache', database_type: 'standalone-dragonfly', dragonfly_password: 'dfSecretPassword', project_id: 'p-prod' },
          { uuid: 'db-kdb', name: 'KeyCache', database_type: 'standalone-keydb', keydb_password: 'kdbSecretPassword', project_id: 'p-prod' },
          { uuid: 'db-ch', name: 'AnalyticsCH', database_type: 'standalone-clickhouse', clickhouse_admin_user: 'admin', clickhouse_admin_password: 'chSecretPassword', project_id: 'p-prod' },
          { uuid: 'db-my', name: 'LegacyMySQL', database_type: 'standalone-mysql', mysql_user: 'u', mysql_password: 'p', mysql_database: 'shop', project_id: 'p-prod' },
          { uuid: 'db-ma', name: 'MariaMain', database_type: 'standalone-mariadb', project_id: 'p-prod' },
          { uuid: 'db-mo', name: 'DocStore', database_type: 'standalone-mongodb', project_id: 'p-prod' }
        ],
        services: [
          {
            uuid: 'svc-plausible',
            name: 'Plausible Stack',
            project_id: 'p-prod',
            status: 'running',
            applications: [{ name: 'plausible', fqdn: 'https://stats.pablo.dev' }],
            docker_compose: [
              'services:',
              '  plausible:',
              '    image: ghcr.io/plausible/community-edition:v2.1',
              '    labels:',
              '      - "traefik.http.services.plausible.loadbalancer.server.port=8000"',
              '    environment:',
              '      - BASE_URL=${SERVICE_URL_PLAUSIBLE}',
              '      - SECRET_KEY_BASE=${SERVICE_BASE64_64_PLAUSIBLE}'
            ].join('\n'),
            environment_variables: []
          }
        ]
      };

      const plan = migrator.buildMigrationPlan(snapshot);
      assert.ok(plan.parityScore >= 85 && plan.parityScore <= 100);
      assert.strictEqual(plan.summary.apps, 1);
      assert.strictEqual(plan.summary.databases, 7);
      assert.strictEqual(plan.summary.services, 1);
      assert.strictEqual(plan.summary.cronsMapped, 2);
      assert.ok(plan.summary.magicVarsTranslated >= 4);
      assert.ok(plan.summary.traefikRulesTranslated >= 1);
      assert.strictEqual(plan.databases.find((d) => d.id === 'db-pg').culkiboEngine, 'pgvector');
      assert.strictEqual(plan.databases.find((d) => d.id === 'db-df').culkiboEngine, 'valkey');
      assert.strictEqual(plan.databases.find((d) => d.id === 'db-kdb').culkiboEngine, 'valkey');
      assert.strictEqual(plan.databases.find((d) => d.id === 'db-ch').culkiboEngine, 'clickhouse');
      assert.strictEqual(plan.crons.filter((c) => c.valid).length, 1);
      assert.strictEqual(plan.crons.filter((c) => !c.valid).length, 1);
      assert.ok(plan.dnsCutoverChecklist.length >= 4);
      assert.strictEqual(plan.rollbackPlan.sourceUntouched, true);
      // Verify no plaintext DB passwords leaked into plan JSON
      const serializedPlan = JSON.stringify(plan);
      assert.ok(!serializedPlan.includes('secretPgPassword123'));
      assert.ok(!serializedPlan.includes('chSecretPassword'));

      // Execute migration with isolated mocks (0 disk writes!)
      const createdDomains = [];
      const createdCrons = [];
      const createdProjects = [];
      const res = await migrator.migrateFromSnapshot(snapshot, {
        projectManager: {
          create: (p) => { createdProjects.push(p); return { ...p }; },
          flushToDisk: async () => {}
        },
        domainManager: {
          addDomain: async (d) => { createdDomains.push(d); }
        },
        cronManager: {
          create: (pid, c) => { createdCrons.push({ pid, ...c }); }
        }
      });

      assert.strictEqual(res.importedApps, 1);
      assert.strictEqual(res.importedDbs, 7);
      assert.strictEqual(res.importedServices, 1);
      assert.strictEqual(res.importedCrons, 1); // Only the valid argv cron registered
      assert.strictEqual(res.domainsLinked, 2);
      assert.strictEqual(createdDomains.find((d) => d.hostname === 'pablo.dev').hstsPreload, true);
      assert.strictEqual(createdDomains.find((d) => d.hostname === 'stats.pablo.dev').targetPort, 8000);
      assert.strictEqual(createdProjects[0].envVars.TZ, 'Europe/Madrid');
      assert.strictEqual(createdProjects[0].envVars.NEXTAUTH_URL, 'https://pablo.dev');
      assert.strictEqual(createdProjects[0].envVars.NEXTAUTH_SECRET, '${vault.SERVICE_PASSWORD_64_AUTH}');
    });

    // =========================================================================
    // TEST 10: POST-MIGRATION PARITY VERIFIER (`verifyMigratedStack`)
    // =========================================================================
    await runCase('Test 10: verifyMigratedStack (dry-run plan + live parity check)', async () => {
      const targets = [
        { name: 'Web', hostname: 'pablo.dev', sourceUrl: 'https://pablo.dev/health', targetUrl: 'http://203.0.113.10:3000/health', healthPath: '/health', expectedStatus: 200 },
        { name: 'API', hostname: 'api.pablo.dev', sourceUrl: 'https://api.pablo.dev/status', targetUrl: 'http://203.0.113.10:8080/status', healthPath: '/status', expectedStatus: 200 }
      ];

      const dryPlan = await migrator.verifyMigratedStack(targets, { dryRun: true, targetIp: '203.0.113.10' });
      assert.strictEqual(dryPlan.dryRun, true);
      assert.strictEqual(dryPlan.checks.length, 2);
      assert.ok(dryPlan.checks[0].preDnsCurlCommand.includes('--resolve pablo.dev:443:203.0.113.10'));

      // Passing live probe
      const okRes = await migrator.verifyMigratedStack(targets, {
        probeFn: async () => ({
          ok: true,
          status: 200,
          latencyMs: 35,
          headers: { 'strict-transport-security': 'max-age=31536000', 'access-control-allow-origin': 'https://pablo.dev' }
        })
      });
      assert.strictEqual(okRes.cutoverReady, true);
      assert.strictEqual(okRes.parityPercent, 100);
      assert.strictEqual(okRes.summary.passed, 2);

      // Failing status mismatch probe
      const failRes = await migrator.verifyMigratedStack(targets, {
        probeFn: async (u) => u.startsWith('https://')
          ? { ok: true, status: 200, latencyMs: 40, headers: { 'strict-transport-security': 'max-age=31536000' } }
          : { ok: false, status: 502, latencyMs: 120, headers: {} }
      });
      assert.strictEqual(failRes.cutoverReady, false);
      assert.strictEqual(failRes.summary.failed, 2);
    });

    // =========================================================================
    // TEST 11: BUNDLE ARCHIVER — ZIP & .CKB.GZ ROUNDTRIP + AES-256-GCM VAULT
    // =========================================================================
    await runCase('Test 11: bundleArchiver .zip & .ckb.gz roundtrip + encrypted Vault', async () => {
      const bundleOpts = {
        stackName: 'Pablo SaaS Stack',
        passphrase: 'correct-horse-battery-staple',
        projects: [
          {
            id: 'proj_saas',
            name: 'Pablo SaaS',
            gitRepo: 'https://github.com/pablo/saas',
            gitBranch: 'main',
            containerPort: 3000,
            domains: ['saas.pablo.dev'],
            envVars: { NODE_ENV: 'production', STRIPE_SECRET_KEY: 'sk_live_verySensitive123456' }
          }
        ],
        domains: [
          { hostname: 'saas.pablo.dev', projectId: 'proj_saas', targetPort: 3000, hstsPreload: true }
        ],
        databases: [
          { id: 'db_1', name: 'saas-pg', engine: 'postgres', projectId: 'proj_saas', dbName: 'saas', username: 'saas' }
        ],
        crons: [
          { name: 'Nightly sync', projectId: 'proj_saas', schedule: '0 2 * * *', mode: 'exec', command: 'node sync.js' }
        ],
        vaultSecrets: {
          EXTRA_API_KEY: 'super-secret-value-xyz'
        }
      };

      // A. ZIP format with encrypted Vault
      const zipBundle = bundleArchiver.exportStackBundle({ ...bundleOpts, format: 'zip' });
      assert.strictEqual(zipBundle.format, 'zip');
      assert.strictEqual(zipBundle.buffer[0], 0x50);
      assert.strictEqual(zipBundle.buffer[1], 0x4b);

      // Verify raw ZIP entries contain ZERO plaintext secrets in culkibo.yaml / projects.json!
      const rawParsed = bundleArchiver.parseZipBuffer(zipBundle.buffer);
      assert.ok(!rawParsed.files['culkibo.yaml'].toString('utf8').includes('sk_live_verySensitive123456'));
      assert.ok(!rawParsed.files['projects.json'].toString('utf8').includes('sk_live_verySensitive123456'));
      assert.ok(rawParsed.files['culkibo.yaml'].toString('utf8').includes('${vault.PROJ_SAAS_STRIPE_SECRET_KEY}'));
      assert.ok(rawParsed.files['mcp-agent-config.json'].toString('utf8').includes('${CULKIBO_TOKEN}'));
      assert.ok(rawParsed.files['vault.enc.json']);

      // Inspect with wrong passphrase -> MUST fail
      assert.throws(
        () => bundleArchiver.inspectStackBundle(zipBundle.buffer, { passphrase: 'wrong-password-123' }),
        /Contraseña incorrecta|manipulado/i
      );

      // Inspect with correct passphrase -> passes checksums + unlocks vault
      const inspected = bundleArchiver.inspectStackBundle(zipBundle.buffer, { passphrase: bundleOpts.passphrase });
      assert.strictEqual(inspected.ok, true);
      assert.strictEqual(inspected.checksumsVerified, true);
      assert.strictEqual(inspected.vaultSummary.unlocked, true);
      assert.strictEqual(inspected.projects.length, 1);
      assert.strictEqual(inspected.domains[0].hstsPreload, true);
      assert.strictEqual(inspected.crons.length, 1);

      // Import into mock managers (zero live disk writes!)
      const restoredVault = {};
      const restoredProjects = [];
      const restoredDomains = [];
      const restoredCrons = [];
      const importRes = await bundleArchiver.importStackBundle(zipBundle.buffer, {
        passphrase: bundleOpts.passphrase,
        projectManager: { create: (p) => { restoredProjects.push(p); return { ...p }; }, flushToDisk: async () => {} },
        domainManager: { addDomain: async (d) => { restoredDomains.push(d); } },
        cronManager: { create: (pid, c) => { restoredCrons.push({ pid, ...c }); } },
        environmentManager: { setVaultSecret: (k, v) => { restoredVault[k] = v; } }
      });
      assert.strictEqual(importRes.importedProjects, 1);
      assert.strictEqual(importRes.importedDomains, 1);
      assert.strictEqual(importRes.importedCrons, 1);
      assert.strictEqual(restoredVault.PROJ_SAAS_STRIPE_SECRET_KEY, 'sk_live_verySensitive123456');
      assert.strictEqual(restoredVault.EXTRA_API_KEY, 'super-secret-value-xyz');

      // B. .ckb.gz format roundtrip + Redacted mode (no passphrase -> 0 secrets stored)
      const gzBundle = bundleArchiver.exportStackBundle({ ...bundleOpts, passphrase: null, format: 'ckb.gz' });
      assert.strictEqual(gzBundle.format, 'ckb.gz');
      assert.strictEqual(gzBundle.buffer[0], 0x1f);
      assert.strictEqual(gzBundle.buffer[1], 0x8b);
      const gzInspected = bundleArchiver.inspectStackBundle(gzBundle.buffer);
      assert.strictEqual(gzInspected.checksumsVerified, true);
      assert.strictEqual(gzInspected.vaultSummary.mode, 'redacted');
      assert.strictEqual(gzInspected.vaultSummary.encrypted, false);
      assert.ok(!zlib.gunzipSync(gzBundle.buffer).toString('utf8').includes('sk_live_verySensitive123456'));
    });

    // =========================================================================
    // TEST 12: ADVERSARIAL ZIP SECURITY (TRAVERSAL, SYMLINK, ZIP-BOMB, CRC32, TAMPER)
    // =========================================================================
    await runCase('Test 12: Adversarial ZIP attacks rejected (traversal, symlink, zip-bomb, CRC32, LFH/CDH polyglot)', async () => {
      // Helper to craft raw ZIP with arbitrary malicious name/attrs/payload
      const craftMaliciousZip = ({ name, rawData, compress = true, unixMode = 0o100644, corruptCrc = false, lfhNameOverride = null }) => {
        const nameBuf = Buffer.from(name, 'utf8');
        const lfhNameBuf = Buffer.from(lfhNameOverride || name, 'utf8');
        const crc = (bundleArchiver.crc32(rawData) ^ (corruptCrc ? 0x00ff00ff : 0)) >>> 0;
        const payload = compress ? zlib.deflateRawSync(rawData, { level: 9 }) : rawData;
        const method = compress ? 8 : 0;

        const lfh = Buffer.alloc(30);
        lfh.writeUInt32LE(0x04034b50, 0);
        lfh.writeUInt16LE(20, 4);
        lfh.writeUInt16LE(0x0800, 6);
        lfh.writeUInt16LE(method, 8);
        lfh.writeUInt32LE(crc, 14);
        lfh.writeUInt32LE(payload.length >>> 0, 18);
        lfh.writeUInt32LE(rawData.length >>> 0, 22);
        lfh.writeUInt16LE(lfhNameBuf.length, 26);

        const cdOffset = 30 + lfhNameBuf.length + payload.length;
        const cdh = Buffer.alloc(46);
        cdh.writeUInt32LE(0x02014b50, 0);
        cdh.writeUInt16LE((3 << 8) | 20, 4); // Unix
        cdh.writeUInt16LE(20, 6);
        cdh.writeUInt16LE(0x0800, 8);
        cdh.writeUInt16LE(method, 10);
        cdh.writeUInt32LE(crc, 16);
        cdh.writeUInt32LE(payload.length >>> 0, 20);
        cdh.writeUInt32LE(rawData.length >>> 0, 24);
        cdh.writeUInt16LE(nameBuf.length, 28);
        cdh.writeUInt32LE((unixMode << 16) >>> 0, 38);
        cdh.writeUInt32LE(0, 42);

        const cdSize = 46 + nameBuf.length;
        const eocd = Buffer.alloc(22);
        eocd.writeUInt32LE(0x06054b50, 0);
        eocd.writeUInt16LE(1, 8);
        eocd.writeUInt16LE(1, 10);
        eocd.writeUInt32LE(cdSize >>> 0, 12);
        eocd.writeUInt32LE(cdOffset >>> 0, 16);

        return Buffer.concat([lfh, lfhNameBuf, payload, cdh, nameBuf, eocd]);
      };

      // 1. Path traversal: ../../etc/passwd, absolute /etc/shadow, Windows C:\evil.txt
      for (const badPath of ['../../etc/passwd', '/etc/shadow', 'C:\\Windows\\win.ini', 'safe/../../escape.json', 'null\x00byte.txt']) {
        const z = craftMaliciousZip({ name: badPath, rawData: Buffer.from('evil'), compress: false });
        assert.throws(() => bundleArchiver.parseZipBuffer(z), /traversal|absoluta|rechazada|Separador|control/i, `Must reject ${badPath}`);
      }

      // 2. Unix Symlink entry (S_IFLNK = 0o120777)
      const symZip = craftMaliciousZip({ name: 'link.txt', rawData: Buffer.from('/etc/passwd'), compress: false, unixMode: 0o120777 });
      assert.throws(() => bundleArchiver.parseZipBuffer(symZip), /simbólico/i);

      // 3. Zip-bomb (2 MB of zeros compresses to ~2 KB => ~1000:1 ratio, exceeding maxCompressionRatio 100:1!)
      const bombZip = craftMaliciousZip({ name: 'bomb.txt', rawData: Buffer.alloc(2 * 1024 * 1024, 0), compress: true });
      assert.throws(() => bundleArchiver.parseZipBuffer(bombZip), /Zip-bomb/i);

      // 4. CRC32 corruption detection
      const crcZip = craftMaliciousZip({ name: 'ok.json', rawData: Buffer.from('{"a":1}'), compress: true, corruptCrc: true });
      assert.throws(() => bundleArchiver.parseZipBuffer(crcZip), /CRC32/i);

      // 5. LFH vs CDH filename mismatch (polyglot attack)
      const polyZip = craftMaliciousZip({ name: 'manifest.json', lfhNameOverride: 'evil.json', rawData: Buffer.from('{}'), compress: false });
      assert.throws(() => bundleArchiver.parseZipBuffer(polyZip), /Discrepancia LFH\/CDH/i);

      // 6. Gzip-bomb in .ckb.gz
      const gzBomb = zlib.gzipSync(Buffer.alloc(3 * 1024 * 1024, 0x41), { level: 9 });
      assert.throws(() => bundleArchiver.parseCkbGzBuffer(gzBomb), /Gzip-bomb/i);

      // 7. Checksum tampering inside bundle
      const validBundle = bundleArchiver.exportStackBundle({
        stackName: 'Tamper Test',
        projects: [{ id: 'p1', name: 'App1' }],
        domains: [],
        databases: [],
        crons: []
      });
      const filesMap = bundleArchiver.parseZipBuffer(validBundle.buffer).files;
      filesMap['projects.json'] = Buffer.from('[{"id":"p1","name":"HACKED"}]', 'utf8');
      const tamperedZip = bundleArchiver.createZipBuffer(filesMap);
      assert.throws(() => bundleArchiver.inspectStackBundle(tamperedZip), /SHA-256|integridad/i);
    });

    // =========================================================================
    // TEST 13: COOLIFY MIGRATION → PORTABLE BUNDLE EXPORT ROUNDTRIP
    // =========================================================================
    await runCase('Test 13: coolifyMigrator.exportMigrationBundle() end-to-end roundtrip', async () => {
      const b = migrator.exportMigrationBundle(
        {
          apps: [appFixture],
          databases: [dbFixture],
          services: [svcFixture],
          projects: projFixture
        },
        { stackName: 'Coolify Export Test', passphrase: 'bundle-password-2026' }
      );
      assert.strictEqual(b.ok, true);
      assert.strictEqual(b.format, 'zip');
      const check = bundleArchiver.inspectStackBundle(b.buffer, { passphrase: 'bundle-password-2026' });
      assert.strictEqual(check.checksumsVerified, true);
      assert.strictEqual(check.vaultSummary.unlocked, true);
      assert.ok(check.culkiboYaml.includes('version: 1'));
      assert.strictEqual(check.databases[0].engine, 'postgres');
    });

    console.log(`\nResultados: ${passed} pasados, ${failed} fallados`);
    if (failed > 0) throw new Error(`${failed} tests failed in Coolify Migrator`);
  } finally {
    restoreSingletons();
  }
}

if (require.main === module) {
  runTests().catch(() => process.exit(1));
}

module.exports = runTests;
