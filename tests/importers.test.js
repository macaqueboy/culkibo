const assert = require('assert');
const http = require('http');

const wordpressMigrator = require('../server/services/wordpressMigrator');
const universalImporter = require('../server/services/universalImporter');
const projectManager = require('../server/services/projectManager');

async function testImporters() {
  console.log('📦 Testing WordPress Migrator & Universal Importer...');

  // 1. WordPress live analyzer against local mock HTTP WordPress server
  const mockWpServer = http.createServer((req, res) => {
    if (req.url === '/wp-json') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        name: 'Tienda Ejemplo WP',
        description: 'Demo WooCommerce',
        home: 'http://127.0.0.1',
        namespaces: ['wp/v2', 'wc/v3', 'yoast/v1']
      }));
      return;
    }
    if (req.url === '/wp-json/wp/v2/types') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ post: {}, page: {}, product: {} }));
      return;
    }
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      Link: '<http://127.0.0.1/wp-json/>; rel="https://api.w.org/"'
    });
    res.end(`
      <!doctype html>
      <html>
        <head>
          <title>Tienda Ejemplo WP</title>
          <meta name="generator" content="WordPress 6.7.2" />
          <link rel="stylesheet" href="/wp-content/themes/astra/style.css" />
          <script src="/wp-content/plugins/elementor/assets/js/app.js"></script>
          <script src="/wp-content/plugins/woocommerce/assets/js/wc.js"></script>
        </head>
        <body><h1>Hola WordPress</h1></body>
      </html>
    `);
  });

  await new Promise((resolve) => mockWpServer.listen(0, '127.0.0.1', resolve));
  const wpAddr = /** @type {import('net').AddressInfo} */ (mockWpServer.address());
  const wpUrl = `http://127.0.0.1:${wpAddr.port}`;

  try {
    // SSRF block when allowPrivate is false (default)
    await assert.rejects(
      () => wordpressMigrator.analyzeSite(wpUrl),
      /SSRF|privad|bloquead/i,
      'analyzeSite debe bloquear IPs privadas por defecto'
    );
    await assert.rejects(
      () => wordpressMigrator.analyzeSite('http://169.254.169.254/latest/meta-data/'),
      /SSRF|metadatos|privad|bloquead/i
    );

    // Live analysis with allowPrivate: true for local test harness
    const analysis = await wordpressMigrator.analyzeSite(wpUrl, { allowPrivate: true });
    assert.strictEqual(analysis.isWordPress, true);
    assert.strictEqual(analysis.wpVersion, '6.7.2');
    assert.strictEqual(analysis.theme, 'astra');
    assert.strictEqual(analysis.hasWooCommerce, true);
    assert.strictEqual(analysis.restApiAvailable, true);
    assert.ok(analysis.plugins.includes('elementor'));
    assert.ok(analysis.plugins.includes('woocommerce'));
    assert.ok(analysis.plugins.includes('wordpress-seo'));
    assert.strictEqual(analysis.estimatedRamMb, 1536);
    assert.ok(analysis.migrationPlan.length >= 4);
    console.log('  ✓ WordPress analyzeSite detectó versión 6.7.2, tema astra, WooCommerce y plugins (+ SSRF bloqueado)');
  } finally {
    await new Promise((resolve) => mockWpServer.close(resolve));
  }

  // 2. WordPress SQL domain rewriting + PHP serialization protection
  const plainSql = `
    CREATE TABLE \`mywp_options\` (option_name VARCHAR(64), option_value TEXT);
    INSERT INTO \`mywp_options\` VALUES ('siteurl', 'https://viejo.com');
  `;
  const prepPlain = wordpressMigrator.helpers.prepareSqlForDomain(plainSql, 'viejo.com', 'https://nuevo.com');
  assert.strictEqual(prepPlain.tablePrefix, 'mywp_');
  assert.strictEqual(prepPlain.urlsUpdated, true);
  assert.strictEqual(prepPlain.directReplaced, true);
  assert.strictEqual(prepPlain.serializedWarning, false);
  assert.ok(prepPlain.sql.includes("UPDATE `mywp_options` SET option_value = 'https://nuevo.com'"));

  const serializedSql = `
    CREATE TABLE \`wp_options\` (option_name VARCHAR(64), option_value TEXT);
    INSERT INTO \`wp_options\` VALUES ('widget_text', 'a:1:{s:3:"url";s:17:"https://viejo.com";}');
  `;
  const prepSer = wordpressMigrator.helpers.prepareSqlForDomain(serializedSql, 'viejo.com', 'https://nuevo.com');
  assert.strictEqual(prepSer.directReplaced, false, 'No debe corromper cadenas PHP serializadas con reemplazo ciego');
  assert.strictEqual(prepSer.serializedWarning, true);
  assert.ok(prepSer.sql.includes("UPDATE `wp_options` SET option_value = 'https://nuevo.com'"));
  console.log('  ✓ WordPress prepareSqlForDomain actualiza siteurl/home y protege datos PHP serializados');

  // 3. Docker Compose parser & importer
  const composeYaml = `
services:
  api:
    image: node:22-alpine
    ports:
      - "3000:3000"
    environment:
      NODE_ENV: production
      PORT: "3000"
    volumes:
      - api_data:/app/data
  db:
    image: postgres:latest
    ports:
      - "5432:5432"
`;
  const parsedCompose = universalImporter.parseDockerCompose(composeYaml);
  assert.strictEqual(parsedCompose.servicesCount, 2);
  assert.strictEqual(parsedCompose.appsCount, 1);
  assert.strictEqual(parsedCompose.databasesCount, 1);
  const dbSvc = parsedCompose.services.find((s) => s.name === 'db');
  assert.strictEqual(dbSvc.dbEngine, 'postgres');
  assert.ok(dbSvc.warnings.some((w) => w.includes(':latest')));

  const importedCompose = await universalImporter.importDockerCompose({
    yamlText: composeYaml,
    projectName: 'Compose Test Temp'
  });
  try {
    assert.strictEqual(importedCompose.success, true);
    assert.strictEqual(importedCompose.importedServices, 2);
    assert.strictEqual(importedCompose.project.source, 'compose-import');
  } finally {
    projectManager.delete(importedCompose.project.id);
    await projectManager.flushToDisk();
  }
  console.log('  ✓ Docker Compose parser e importador verificados (apps, BDs, env, volúmenes y avisos :latest)');

  // 4. Platform configs (Vercel, Netlify, Railway, Render, Dokploy + .env DB detection)
  const vercelRes = universalImporter.parsePlatformConfig({
    platform: 'auto',
    configText: JSON.stringify({ framework: 'nextjs', buildCommand: 'pnpm build', outputDirectory: '.next' }),
    envText: 'DATABASE_URL=postgres://u:p@host:5432/app\nREDIS_URL=redis://cache:6379'
  });
  assert.strictEqual(vercelRes.platform, 'vercel');
  assert.strictEqual(vercelRes.buildCommand, 'pnpm build');
  assert.strictEqual(vercelRes.recommendedDatabases.length, 2);

  const netlifyRes = universalImporter.parsePlatformConfig({
    platform: 'auto',
    configText: '[build]\ncommand = "npm run build"\npublish = "dist"\n[build.environment]\nNODE_VERSION = "22"\n'
  });
  assert.strictEqual(netlifyRes.platform, 'netlify');
  assert.strictEqual(netlifyRes.outputDirectory, 'dist');
  assert.strictEqual(netlifyRes.envVars.NODE_VERSION, '22');

  const railwayRes = universalImporter.parsePlatformConfig({
    platform: 'railway',
    configText: JSON.stringify({ build: { buildCommand: 'npm ci && npm run build' }, deploy: { startCommand: 'node server.js', healthcheckPath: '/health' } })
  });
  assert.strictEqual(railwayRes.healthPath, '/health');
  assert.strictEqual(railwayRes.startCommand, 'node server.js');

  const renderRes = universalImporter.parsePlatformConfig({
    platform: 'auto',
    configText: 'services:\n  - type: web\n    name: mi-api\n    buildCommand: pip install -r requirements.txt\n    startCommand: uvicorn main:app\n    healthCheckPath: /healthz\n'
  });
  assert.strictEqual(renderRes.platform, 'render');
  assert.strictEqual(renderRes.name, 'mi-api');
  assert.strictEqual(renderRes.healthPath, '/healthz');

  const dokployRes = universalImporter.parsePlatformConfig({
    platform: 'dokploy',
    configText: JSON.stringify({ name: 'AppDok', repository: 'https://github.com/org/repo', branch: 'main', env: 'PORT=4000', domains: [{ host: 'app.example.com' }] })
  });
  assert.strictEqual(dokployRes.name, 'AppDok');
  assert.deepStrictEqual(dokployRes.domains, ['app.example.com']);
  console.log('  ✓ Parseadores de Vercel, Netlify, Railway, Render, Dokploy y detección de BDs en .env verificados');

  // 4b. Fly.io (`fly.toml`), Heroku (`Procfile` + `app.json`), Multi-service `render.yaml` y Compose v3 (`profiles`/`secrets`/`configs`/`env_file`/`healthcheck`/`deploy.resources.limits`)
  const flyToml = [
    'app = "billing-edge"',
    'primary_region = "mad"',
    '',
    '[build]',
    '  dockerfile = "Dockerfile.prod"',
    '',
    '[env]',
    '  NODE_ENV = "production"',
    '  LOG_LEVEL = "info"',
    '',
    '[http_service]',
    '  internal_port = 8080',
    '  force_https = true',
    '',
    '[[http_service.checks]]',
    '  path = "/healthz"',
    '  interval = "15s"',
    '',
    '[mounts]',
    '  source = "billing_data"',
    '  destination = "/app/data"',
    '',
    '[processes]',
    '  app = "node dist/server.js"',
    '  worker = "node dist/worker.js"',
    '',
    '[[vm]]',
    '  memory = "1gb"',
    '  cpus = 2'
  ].join('\n');
  const flyRes = universalImporter.parsePlatformConfig({ platform: 'auto', configText: flyToml });
  assert.strictEqual(flyRes.platform, 'fly');
  assert.strictEqual(flyRes.name, 'billing-edge');
  assert.strictEqual(flyRes.region, 'mad');
  assert.strictEqual(flyRes.port, 8080);
  assert.strictEqual(flyRes.healthPath, '/healthz');
  assert.strictEqual(flyRes.memoryMb, 1024);
  assert.strictEqual(flyRes.cpus, 2);
  assert.strictEqual(flyRes.startCommand, 'node dist/server.js');
  assert.strictEqual(flyRes.volumes[0].mount_path, '/app/data');
  assert.strictEqual(flyRes.envVars.LOG_LEVEL, 'info');

  const herokuAppJson = JSON.stringify({
    name: 'crm-heroku',
    description: 'CRM SaaS',
    repository: 'https://github.com/acme/crm',
    scripts: { postdeploy: 'npm run db:seed' },
    buildpacks: [{ url: 'heroku/nodejs' }],
    addons: ['heroku-postgresql:essential-0', { plan: 'heroku-redis:mini' }],
    env: {
      SECRET_KEY_BASE: { description: 'Session signing secret', generator: 'secret' },
      APP_MODE: { value: 'saas' }
    }
  });
  const procfileText = 'release: npm run migrate\nweb: node server.js\nworker: node worker.js\n';
  const herokuRes = universalImporter.parsePlatformConfig({ platform: 'auto', configText: herokuAppJson, procfileText });
  assert.strictEqual(herokuRes.platform, 'heroku');
  assert.strictEqual(herokuRes.name, 'crm-heroku');
  assert.strictEqual(herokuRes.startCommand, 'node server.js');
  assert.strictEqual(herokuRes.preDeployCommand, 'npm run migrate');
  assert.strictEqual(herokuRes.postDeployCommand, 'npm run db:seed');
  assert.strictEqual(herokuRes.workers.length, 1);
  assert.strictEqual(herokuRes.workers[0].name, 'worker');
  assert.strictEqual(herokuRes.envVars.SECRET_KEY_BASE, '${vault.SECRET_KEY_BASE}');
  assert.ok(herokuRes.generatedSecrets.includes('SECRET_KEY_BASE'));
  assert.ok(herokuRes.recommendedDatabases.some((d) => d.engine === 'postgres'));
  assert.ok(herokuRes.recommendedDatabases.some((d) => d.engine === 'valkey'));

  const procOnly = universalImporter.parsePlatformConfig({ platform: 'auto', configText: 'web: gunicorn app:app\nworker: celery -A app worker\n' });
  assert.strictEqual(procOnly.platform, 'procfile');
  assert.strictEqual(procOnly.startCommand, 'gunicorn app:app');

  const multiRenderYaml = [
    'previews:',
    '  generation: automatic',
    'services:',
    '  - type: web',
    '    name: render-web',
    '    buildCommand: npm ci && npm run build',
    '    startCommand: npm start',
    '    healthCheckPath: /api/health',
    '    envVars:',
    '      - key: PORT',
    '        value: "4000"',
    '      - key: STRIPE_KEY',
    '        sync: false',
    '      - key: SESSION_SECRET',
    '        generateValue: true',
    '  - type: worker',
    '    name: render-worker',
    '    startCommand: node worker.js',
    '  - type: cron',
    '    name: nightly-report',
    '    schedule: "0 2 * * *"',
    '    startCommand: node scripts/report.js',
    'databases:',
    '  - name: render-pg',
    '    databaseName: app_prod',
    '    user: app_user',
    '    postgresMajorVersion: 16'
  ].join('\n');
  const multiRenderRes = universalImporter.parsePlatformConfig({ platform: 'auto', configText: multiRenderYaml });
  assert.strictEqual(multiRenderRes.platform, 'render');
  assert.strictEqual(multiRenderRes.services.length, 2, 'Debe parsear web + worker');
  assert.strictEqual(multiRenderRes.crons.length, 1, 'Debe parsear cron');
  assert.strictEqual(multiRenderRes.databases.length, 1, 'Debe parsear databases:');
  assert.strictEqual(multiRenderRes.databases[0].image, 'postgres:16-alpine');
  assert.strictEqual(multiRenderRes.envVars.STRIPE_KEY, '${vault.STRIPE_KEY}');
  assert.ok(multiRenderRes.secretEnvKeys.includes('STRIPE_KEY'));
  assert.ok(multiRenderRes.generatedSecrets.includes('SESSION_SECRET'));
  assert.strictEqual(multiRenderRes.previews.generation, 'automatic');

  const composeV3Yaml = [
    'services:',
    '  web:',
    '    image: node:22-alpine',
    '    ports:',
    '      - "3000:3000"',
    '    env_file:',
    '      - .env.prod',
    '    secrets:',
    '      - db_password',
    '      - source: jwt_signing_key',
    '        target: /run/secrets/jwt',
    '    configs:',
    '      - app_cfg',
    '    healthcheck:',
    '      test: ["CMD", "curl", "-f", "http://localhost:3000/ready"]',
    '      interval: 15s',
    '      timeout: 5s',
    '      retries: 3',
    '    deploy:',
    '      resources:',
    '        limits:',
    '          memory: 768M',
    '          cpus: "1.5"',
    '  debug-ui:',
    '    image: adminer:4.8.1',
    '    profiles:',
    '      - debug',
    '    ports:',
    '      - "8080:8080"',
    'secrets:',
    '  db_password:',
    '    file: ./secrets/db_password.txt',
    '  jwt_signing_key:',
    '    external: true',
    'configs:',
    '  app_cfg:',
    '    file: ./config/app.json'
  ].join('\n');
  const parsedV3 = universalImporter.parseDockerCompose(composeV3Yaml);
  assert.deepStrictEqual(parsedV3.profilesDetected, ['debug']);
  assert.ok(parsedV3.secrets.db_password && parsedV3.secrets.db_password.file === './secrets/db_password.txt');
  assert.ok(parsedV3.configs.app_cfg && parsedV3.configs.app_cfg.file === './config/app.json');
  const webSvc = parsedV3.services.find((s) => s.name === 'web');
  assert.strictEqual(webSvc.healthPath, '/ready');
  assert.strictEqual(webSvc.healthcheck.retries, 3);
  assert.strictEqual(webSvc.resources.memoryMb, 768);
  assert.strictEqual(webSvc.resources.cpus, 1.5);
  assert.strictEqual(webSvc.secrets.length, 2);
  assert.strictEqual(webSvc.configs.length, 1);
  assert.deepStrictEqual(webSvc.envFile, ['.env.prod']);
  const debugSvc = parsedV3.services.find((s) => s.name === 'debug-ui');
  assert.deepStrictEqual(debugSvc.profiles, ['debug']);
  assert.strictEqual(debugSvc.profileGated, true);

  // importDockerCompose debe omitir debug-ui por defecto y respetar profiles: ['debug'] cuando se activa
  const impDefault = await universalImporter.importDockerCompose({ yamlText: composeV3Yaml, projectName: 'ComposeV3 Default' });
  try {
    assert.strictEqual(impDefault.importedServices, 1, 'Servicio con profile debug debe omitirse por defecto');
    assert.deepStrictEqual(impDefault.skippedProfileServices, ['debug-ui']);
    assert.strictEqual(impDefault.project.healthPath, '/ready');
    assert.strictEqual(impDefault.project.memoryMb, 768);
  } finally {
    projectManager.delete(impDefault.project.id);
    await projectManager.flushToDisk();
  }
  const impDebug = await universalImporter.importDockerCompose({ yamlText: composeV3Yaml, projectName: 'ComposeV3 Debug', profiles: ['debug'] });
  try {
    assert.strictEqual(impDebug.importedServices, 2, 'Con profiles:["debug"] debe importar ambos servicios');
    assert.deepStrictEqual(impDebug.skippedProfileServices, []);
  } finally {
    projectManager.delete(impDebug.project.id);
    await projectManager.flushToDisk();
  }
  console.log('  ✓ Fly.io (fly.toml), Heroku (Procfile/app.json), Render multi-servicio y Compose v3 (profiles/secrets/configs/env_file/healthcheck/limits) verificados');

  // 5. Git URL inspector SSRF + protocol checks
  await assert.rejects(() => universalImporter.inspectGitUrl('file:///etc/passwd'), /protocolo|http|esquema|SSRF|bloquead/i);
  await assert.rejects(() => universalImporter.inspectGitUrl('http://127.0.0.1:3030/repo.git'), /SSRF|privad|bloquead/i);
  console.log('  ✓ inspectGitUrl bloquea file:// e IPs privadas');

  console.log('✅ WordPress Migrator & Universal Importer PASSED!\n');
}

module.exports = testImporters;

if (require.main === module) {
  testImporters()
    .then(() => { setTimeout(() => process.exit(0), 50); })
    .catch((err) => {
      console.error('❌ Importers test failure:', err);
      process.exit(1);
    });
}
