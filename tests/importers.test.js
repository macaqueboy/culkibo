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
