const assert = require('assert');
const migrator = require('../server/services/coolifyMigrator');

async function runTests() {
  console.log('--- Iniciando Tests de Coolify Migrator ---');
  let passed = 0;
  let failed = 0;

  // Mock domainManager and projectManager to not write files or fail.
  //
  // Both are singletons shared with the live daemon. This suite used to
  // overwrite `projectManager.create` and never restore it, so every later
  // suite — and the daemon itself, when it runs in this process — got a
  // `create()` that silently returned undefined. That surfaced as an opaque
  // "Cannot read properties of undefined (reading 'gitRepo')" three suites
  // later. Save the originals and always put them back.
  const projectManager = require('../server/services/projectManager');
  const domainManager = require('../server/services/domainManager');

  const realCreate = projectManager.create;
  const realAddDomain = domainManager.addDomain;
  const restoreSingletons = () => {
    projectManager.create = realCreate;
    domainManager.addDomain = realAddDomain;
  };

  try {
  projectManager.create = () => {};
  domainManager.addDomain = async () => {};

  // Override fetchFromApi for mocking
  const originalFetch = migrator.fetchFromApi.bind(migrator);
  
  // Fixtures
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
      if (endpoint === '/api/v1/applications') return [ { uuid: 'app-1' } ];
      if (endpoint === '/api/v1/applications/app-1') return appFixture;
      if (endpoint === '/api/v1/applications/app-1/envs') return appFixture.environment_variables;
      if (endpoint === '/api/v1/applications/app-1/storages') return { persistent_storages: [{ name: 'data', mount_path: '/data' }], file_storages: [{ fs_path: '/tmp/test', mount_path: '/test' }] };
      
      if (endpoint === '/api/v1/databases') return [ { uuid: 'db-1' } ];
      if (endpoint === '/api/v1/databases/db-1') return dbFixture;
      if (endpoint === '/api/v1/databases/db-1/envs') return dbFixture.environment_variables;
      if (endpoint === '/api/v1/databases/db-1/storages') return { persistent_storages: [{ name: 'db-data', mount_path: '/var/lib/postgresql/data' }], file_storages: [] };
      
      if (endpoint === '/api/v1/services') return [ { uuid: 'svc-1' } ];
      if (endpoint === '/api/v1/services/svc-1') return svcFixture;
      if (endpoint === '/api/v1/services/svc-1/envs') return svcFixture.environment_variables;
      if (endpoint === '/api/v1/services/svc-1/storages') return { persistent_storages: [], file_storages: [] };
      
      if (endpoint === '/api/v1/projects') return projFixture;
      
      return [];
  };

  try {
      // Test 1: Mapeo correcto de una app con todos los campos
      console.log('Test 1: App');
      const apps = await migrator.fetchApplications('url', 'tok');
      assert.strictEqual(apps.length, 1);
      assert.strictEqual(apps[0].build_command, 'npm run build');
      assert.strictEqual(apps[0].local_persistent_volumes.length, 1);
      assert.strictEqual(apps[0].environment_variables.length, 1);
      passed++;
  } catch (e) { console.error('Test 1 falló', e); failed++; }

  try {
      // Test 2: Mapeo correcto de una DB PostgreSQL con credenciales y volúmenes
      console.log('Test 2: DB');
      const dbs = await migrator.fetchDatabases('url', 'tok');
      assert.strictEqual(dbs.length, 1);
      assert.strictEqual(dbs[0].postgres_db, 'galeia');
      assert.strictEqual(dbs[0].volumes.length, 1);
      passed++;
  } catch (e) { console.error('Test 2 falló', e); failed++; }

  try {
      // Test 3: Mapeo correcto de un servicio Docker Compose
      console.log('Test 3: Service');
      const svcs = await migrator.fetchServices('url', 'tok');
      assert.strictEqual(svcs.length, 1);
      assert.ok(svcs[0].docker_compose.includes('redis'));
      passed++;
  } catch (e) { console.error('Test 3 falló', e); failed++; }

  try {
      // Test 4: Agrupación correcta por proyecto (mismo project_id)
      console.log('Test 4: Grouping by Project');
      let createdProjects = {};
      projectManager.create = (projData) => {
          createdProjects[projData.id] = projData;
      };
      const res = await migrator.migrate('url', 'tok', ['app-1'], ['db-1'], ['svc-1']);
      assert.strictEqual(res.importedApps, 1);
      assert.strictEqual(res.importedDbs, 1);
      assert.strictEqual(res.importedServices, 1);
      
      // Aura Project (proj-1) should have app-1 and db-1
      const p1 = createdProjects['proj-1'];
      assert.ok(p1);
      assert.strictEqual(p1.name, 'Aura Project');
      assert.strictEqual(p1.resources.length, 2);
      
      // Other Project (proj-2) should have svc-1
      const p2 = createdProjects['proj-2'];
      assert.ok(p2);
      assert.strictEqual(p2.name, 'Other Project');
      assert.strictEqual(p2.resources.length, 1);
      passed++;
  } catch (e) { console.error('Test 4 falló', e); failed++; }

  try {
      // Test 5: Manejo de errores (API caída, datos faltantes)
      console.log('Test 5: Error handling');
      migrator.fetchFromApi = async (url, token, endpoint) => {
          if (endpoint === '/api/v1/applications') throw new Error('No se pudo conectar a la API de Coolify. Verifica URL y Token.');
          return [];
      };
      try {
          await migrator.fetchApplications('url', 'tok');
          assert.fail('Should have thrown');
      } catch (e) {
          assert.ok(e.message.includes('No se pudo conectar'));
      }
      passed++;
  } catch (e) { console.error('Test 5 falló', e); failed++; }

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
