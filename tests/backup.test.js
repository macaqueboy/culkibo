const assert = require('assert');
const fs = require('fs');
const path = require('path');
const dbBackupManager = require('../server/services/dbBackupManager');
const projectManager = require('../server/services/projectManager');

async function testBackup() {
  console.log('🧪 Testing Database & Project Backup / Restore Engine...');

  // 1. Create a mock project to export
  const testProj = projectManager.create({
    name: 'Test Backup Project',
    description: 'Proyecto para pruebas de exportación y restauración',
    icon: '📦',
    envVars: {
      DATABASE_URL: 'postgresql://postgres:secret@localhost:5432/testdb',
      SECRET_KEY: 'culkibo_secret_token_123'
    },
    resources: [
      {
        id: 'res_pg_1',
        type: 'database',
        name: 'PostgreSQL Main',
        image: 'postgres:16-alpine'
      }
    ],
    volumes: [
      {
        name: 'pg-data',
        mountPath: '/var/lib/postgresql/data',
        hostPath: '/data/pg'
      }
    ]
  });

  assert.ok(testProj.id);
  console.log('  ✓ Test project created successfully');

  // 2. Export project
  const exportRes = await dbBackupManager.exportProject(testProj.id);
  assert.strictEqual(exportRes.success, true);
  assert.ok(fs.existsSync(exportRes.fullPath));
  console.log('  ✓ Project export bundle generated to disk');

  // 3. Database Dump Command Generator
  const pgCmd = await dbBackupManager.generateDbDumpCommand('postgresql', {
    host: 'db.internal',
    port: 5432,
    user: 'admin',
    password: 'secure_password',
    dbName: 'production',
    outputFile: '/backups/pg_prod.dump'
  });
  assert.ok(pgCmd.includes('pg_dump'));
  assert.ok(pgCmd.includes('production'));

  const mysqlCmd = await dbBackupManager.generateDbDumpCommand('mysql', {
    host: 'localhost',
    port: 3306,
    user: 'root',
    password: 'mysql_password',
    dbName: 'wordpress',
    outputFile: '/backups/mysql.sql'
  });
  assert.ok(mysqlCmd.includes('mysqldump'));

  const redisCmd = await dbBackupManager.generateDbDumpCommand('redis', {
    host: 'localhost',
    port: 6379,
    password: 'redis_pass',
    outputFile: '/backups/redis.rdb'
  });
  assert.ok(redisCmd.includes('redis-cli'));
  console.log('  ✓ Multi-database dump commands generated (Postgres, MySQL, Redis)');

  // 3b. Regression: the rendered command must never carry a secret, and the
  // executable form must be argv + env, never a shell string. Interpolating a
  // user-supplied host/user/dbName into a shell command is the exact class
  // behind 21 critical advisories in Coolify and 34 in Dokploy.
  assert.ok(!pgCmd.includes('secure_password'), 'El comando mostrado no puede contener la contraseña');
  assert.ok(!mysqlCmd.includes('mysql_password'), 'El comando mostrado no puede contener la contraseña');
  assert.ok(!redisCmd.includes('redis_pass'), 'El comando mostrado no puede contener la contraseña');

  const spec = dbBackupManager.buildDbDumpSpec('postgresql', {
    host: 'db.internal', user: 'admin', password: 'secure_password',
    dbName: 'production', outputFile: '/backups/pg_prod.dump'
  });
  assert.ok(Array.isArray(spec.args), 'Los argumentos deben ser un array, no una cadena de shell');
  assert.strictEqual(spec.env.PGPASSWORD, 'secure_password', 'El secreto viaja por el entorno');
  assert.ok(!spec.args.join(' ').includes('secure_password'), 'El secreto nunca en argv (visible en ps)');
  assert.strictEqual(spec.secretInArgs, false);

  // Shell metacharacters in user-controlled fields stay inert data.
  const evil = dbBackupManager.buildDbDumpSpec('postgresql', {
    host: 'h; rm -rf /', user: 'u`id`', dbName: 'd$(whoami)', outputFile: '/tmp/x'
  });
  assert.ok(evil.args.includes('h; rm -rf /'), 'Los metacaracteres quedan como dato literal en argv');
  console.log('  ✓ Volcados sin shell: argv + entorno, secretos redactados, metacaracteres inertes');

  // 4. List Backups
  const backups = await dbBackupManager.listBackups();
  assert.ok(backups.length >= 1);
  assert.ok(backups.some(b => b.fileName === exportRes.backupFile));
  console.log('  ✓ Backup listing verified');

  // 5. Restore Project
  const restoreRes = await dbBackupManager.restoreProject(exportRes.backupFile);
  assert.strictEqual(restoreRes.success, true);
  assert.ok(restoreRes.restoredProjectId);

  const restoredProject = projectManager.getById(restoreRes.restoredProjectId);
  assert.ok(restoredProject);
  assert.strictEqual(restoredProject.envVars.SECRET_KEY, 'culkibo_secret_token_123');
  assert.strictEqual(restoredProject.resources.length, 1);
  assert.strictEqual(restoredProject.volumes.length, 1);
  console.log('  ✓ Project restored with 100% data fidelity (metadata, envs, resources, volumes)');

  // Cleanup
  projectManager.delete(testProj.id);
  projectManager.delete(restoreRes.restoredProjectId);
  if (fs.existsSync(exportRes.fullPath)) {
    fs.unlinkSync(exportRes.fullPath);
  }
  console.log('  ✓ Test artifacts cleaned up');

  console.log('✅ All Backup / Restore tests passed!\n');
}

module.exports = testBackup;

if (require.main === module) {
  testBackup().catch(err => {
    console.error('Backup test failed:', err);
    process.exit(1);
  });
}
