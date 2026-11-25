const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const dbBackupManagerModule = require('../server/services/dbBackupManager');
const { DbBackupManager, assertSafeCliArg, assertSafePort } = dbBackupManagerModule;
const projectManager = require('../server/services/projectManager');

async function testBackup() {
  console.log('🧪 Testing Database & Project Backup / Restore Engine (Full Hardened Suite)...');

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-backup-test-'));
  const isolatedBackup = new DbBackupManager({ dataDir: tmpRoot });

  // Aislar projectManager en tmpRoot sin tocar nunca data/projects.json en disco
  const origDataPath = projectManager.dataPath;
  const origProjects = new Map(projectManager.projects);
  projectManager.dataPath = path.join(tmpRoot, 'projects.json');
  projectManager.projects = new Map();

  try {
    // =========================================================================
    // 1. Cobertura completa de los 12 motores en buildDbDumpSpec + redacción
    // =========================================================================
    const pgSpec = isolatedBackup.buildDbDumpSpec('postgresql', {
      host: 'db.internal', port: 5432, user: 'admin', password: 'secure_password',
      dbName: 'production', outputFile: '/backups/pg_prod.dump'
    });
    assert.strictEqual(pgSpec.program, 'pg_dump');
    assert.ok(Array.isArray(pgSpec.args), 'Los argumentos deben ser un array, no una cadena de shell');
    assert.ok(pgSpec.args.includes('--no-owner'), 'pg_dump debe incluir --no-owner');
    assert.ok(pgSpec.args.includes('--no-privileges'), 'pg_dump debe incluir --no-privileges');
    assert.ok(pgSpec.args.includes('--lock-wait-timeout=60000'), 'pg_dump debe incluir --lock-wait-timeout=60000');
    assert.strictEqual(pgSpec.env.PGPASSWORD, 'secure_password', 'El secreto viaja por el entorno');
    assert.ok(!pgSpec.args.join(' ').includes('secure_password'), 'El secreto nunca en argv');
    assert.strictEqual(pgSpec.secretInArgs, false);

    // pgvector y timescaledb usan pg_dump con los mismos flags seguros
    for (const pgVariant of ['pgvector', 'timescaledb']) {
      const s = isolatedBackup.buildDbDumpSpec(pgVariant, {
        host: '127.0.0.1', user: 'u', password: 'pw_' + pgVariant, dbName: 'ai_db', outputFile: '/tmp/a.dump'
      });
      assert.strictEqual(s.program, 'pg_dump');
      assert.ok(s.args.includes('--no-owner') && s.args.includes('--no-privileges'));
      assert.strictEqual(s.secretInArgs, false);
    }

    // MySQL incluye --single-transaction y --set-gtid-purged=OFF
    const mysqlSpec = isolatedBackup.buildDbDumpSpec('mysql', {
      host: 'localhost', port: 3306, user: 'root', password: 'mysql_password',
      dbName: 'wordpress', outputFile: '/backups/mysql.sql'
    });
    assert.strictEqual(mysqlSpec.program, 'mysqldump');
    assert.ok(mysqlSpec.args.includes('--single-transaction'));
    assert.ok(mysqlSpec.args.includes('--set-gtid-purged=OFF'));
    assert.strictEqual(mysqlSpec.env.MYSQL_PWD, 'mysql_password');
    assert.strictEqual(mysqlSpec.secretInArgs, false);

    // Regresión MariaDB 12: debe emitir `mariadb-dump` (NO `mysqldump`, eliminado en MariaDB 12) y SIN --set-gtid-purged
    const mariaSpec = isolatedBackup.buildDbDumpSpec('mariadb', {
      host: 'localhost', port: 3306, user: 'root', password: 'maria_password',
      dbName: 'shop', outputFile: '/backups/maria.sql'
    });
    assert.strictEqual(mariaSpec.program, 'mariadb-dump', 'MariaDB 12 debe usar mariadb-dump');
    assert.ok(mariaSpec.args.includes('--single-transaction'));
    assert.ok(!mariaSpec.args.some((a) => a.includes('gtid-purged')), 'mariadb-dump no soporta --set-gtid-purged');
    assert.strictEqual(mariaSpec.env.MYSQL_PWD, 'maria_password');

    // Valkey, Redis y Dragonfly
    const valkeySpec = isolatedBackup.buildDbDumpSpec('valkey', {
      host: 'localhost', port: 6379, password: 'vk_secret', outputFile: '/backups/valkey.rdb'
    });
    assert.strictEqual(valkeySpec.program, 'valkey-cli');
    assert.strictEqual(valkeySpec.env.VALKEYCLI_AUTH, 'vk_secret');
    assert.strictEqual(valkeySpec.env.REDISCLI_AUTH, 'vk_secret');

    const dragonflySpec = isolatedBackup.buildDbDumpSpec('dragonfly', {
      host: 'localhost', port: 6379, password: 'df_secret', outputFile: '/backups/df.rdb'
    });
    assert.strictEqual(dragonflySpec.program, 'redis-cli');
    assert.strictEqual(dragonflySpec.env.REDISCLI_AUTH, 'df_secret');

    // MongoDB: secretInArgs=true pero generateDbDumpCommand redacta --password=********
    const mongoSpec = isolatedBackup.buildDbDumpSpec('mongodb', {
      host: 'mongo.internal', port: 27017, user: 'admin', password: 'mongo_super_secret',
      dbName: 'app', outputFile: '/backups/mongo.archive.gz'
    });
    assert.strictEqual(mongoSpec.program, 'mongodump');
    assert.strictEqual(mongoSpec.secretInArgs, true);
    const mongoCmd = isolatedBackup.generateDbDumpCommand('mongodb', {
      host: 'mongo.internal', port: 27017, user: 'admin', password: 'mongo_super_secret',
      dbName: 'app', outputFile: '/backups/mongo.archive.gz'
    });
    assert.ok(!mongoCmd.includes('mongo_super_secret'), 'generateDbDumpCommand debe ocultar la contraseña de MongoDB');
    assert.ok(mongoCmd.includes('--password=********'));

    // ClickHouse, Qdrant, Meilisearch
    const chSpec = isolatedBackup.buildDbDumpSpec('clickhouse', {
      host: '127.0.0.1', port: 9000, user: 'ch', password: 'ch_secret',
      dbName: 'analytics', outputFile: '/tmp/ch_backup.zip'
    });
    assert.strictEqual(chSpec.program, 'clickhouse-client');
    assert.strictEqual(chSpec.env.CLICKHOUSE_PASSWORD, 'ch_secret');
    assert.ok(!chSpec.args.join(' ').includes('ch_secret'));

    const qdrantSpec = isolatedBackup.buildDbDumpSpec('qdrant', {
      host: '127.0.0.1', port: 6333, password: 'qd_secret', outputFile: '/tmp/q.snapshot'
    });
    assert.strictEqual(qdrantSpec.program, 'curl');
    assert.strictEqual(qdrantSpec.env.QDRANT_API_KEY, 'qd_secret');
    assert.ok(!qdrantSpec.args.join(' ').includes('qd_secret'));

    const meiliSpec = isolatedBackup.buildDbDumpSpec('meilisearch', {
      host: '127.0.0.1', port: 7700, password: 'ms_secret', outputFile: '/tmp/m.dump'
    });
    assert.strictEqual(meiliSpec.program, 'curl');
    assert.strictEqual(meiliSpec.env.MEILI_MASTER_KEY, 'ms_secret');
    assert.ok(!meiliSpec.args.join(' ').includes('ms_secret'));

    // generateDbDumpCommand jamás filtra secretos en ningún motor
    for (const [eng, pw] of [
      ['postgresql', 'pg_secret_99'],
      ['mysql', 'my_secret_99'],
      ['mariadb', 'ma_secret_99'],
      ['redis', 'rd_secret_99'],
      ['valkey', 'vk_secret_99'],
      ['dragonfly', 'df_secret_99'],
      ['clickhouse', 'ch_secret_99'],
      ['qdrant', 'qd_secret_99'],
      ['meilisearch', 'ms_secret_99']
    ]) {
      const cmd = isolatedBackup.generateDbDumpCommand(eng, {
        host: '127.0.0.1', user: 'u', password: pw, dbName: 'app', outputFile: '/tmp/out.dump'
      });
      assert.ok(!cmd.includes(pw), `generateDbDumpCommand(${eng}) filtró la contraseña`);
    }
    assert.throws(() => isolatedBackup.buildDbDumpSpec('oracle', { outputFile: '/tmp/x' }), /no soportado/i);
    console.log('  ✓ 12 motores verificados en buildDbDumpSpec (incl. mariadb-dump, pg_dump --no-owner/--no-privileges, 0 secretos en comandos)');

    // =========================================================================
    // 2. Defensa contra inyección de flags CLI (-o, --eval), caracteres de control y puertos inválidos
    // =========================================================================
    for (const bad of ['-o', '--eval=pwn', '--post-exec', 'abc\0def', 'abc\ndef', 'abc\rdef']) {
      assert.throws(() => assertSafeCliArg(bad, 'host'), /inválido/i, `Debe rechazar ${JSON.stringify(bad)}`);
    }
    assert.throws(() => isolatedBackup.buildDbDumpSpec('postgresql', { host: '--file=/etc/passwd', outputFile: '/tmp/a' }), /inválido/i);
    assert.throws(() => isolatedBackup.buildDbDumpSpec('postgresql', { dbName: '-d', outputFile: '/tmp/a' }), /inválido/i);
    assert.throws(() => isolatedBackup.buildDbDumpSpec('postgresql', { outputFile: '--eval=x' }), /inválido/i);
    for (const badPort of ['-p', '0', '70000', '5432;id', 'abc']) {
      assert.throws(() => assertSafePort(badPort, 5432), /inválido|rango/i, `Puerto inválido: ${badPort}`);
    }
    assert.throws(() => isolatedBackup.buildDbDumpSpec('clickhouse', { dbName: 'app; DROP TABLE x', outputFile: '/tmp/a.zip' }), /inválido/i);
    assert.throws(() => isolatedBackup.buildDbDumpSpec('clickhouse', { dbName: 'app', outputFile: "/tmp/a';--" }), /inválido/i);
    assert.throws(() => isolatedBackup.buildDbDumpSpec('qdrant', { host: 'evil@host/x', outputFile: '/tmp/a' }), /inválido/i);

    // Metacaracteres de shell quedan inertes en argv
    const evil = isolatedBackup.buildDbDumpSpec('postgresql', {
      host: 'h; rm -rf /', user: 'u`id`', dbName: 'd$(whoami)', outputFile: '/tmp/x'
    });
    assert.ok(evil.args.includes('h; rm -rf /'), 'Los metacaracteres quedan como dato literal en argv');
    console.log('  ✓ Defensa CLI: inyección de flags (-/--), control chars, puertos inválidos y SQL/URL injection bloqueados');

    // =========================================================================
    // 3. Exportación de proyecto con y sin secretos + restauración y colisión de ID
    // =========================================================================
    const testProj = projectManager.create({
      name: 'Test Backup Project',
      description: 'Proyecto para pruebas de exportación y restauración',
      icon: '📦',
      envVars: {
        DATABASE_URL: 'postgresql://postgres:secret@localhost:5432/testdb',
        SECRET_KEY: 'culkibo_secret_token_123'
      },
      webhookSecret: 'whsec_live_123456',
      deployHookToken: 'dhk_live_abcdef',
      fileMounts: [{ path: '/app/secret.pem', content: 'PRIVATE_KEY_BODY' }],
      resources: [
        {
          id: 'res_pg_1',
          type: 'database',
          name: 'PostgreSQL Main',
          image: 'postgres:18-alpine',
          credentials: { password: 'db_res_secret' }
        }
      ],
      volumes: [
        { name: 'pg-data', mountPath: '/var/lib/postgresql', hostPath: '/data/pg' }
      ]
    });

    // 3a. Export con secretos
    const exportFull = await isolatedBackup.exportProject(testProj.id, { includeSecrets: true });
    assert.strictEqual(exportFull.success, true);
    assert.strictEqual(exportFull.secretsRedacted, false);
    assert.match(exportFull.checksum, /^sha256:[a-f0-9]{64}$/);
    assert.ok(fs.existsSync(exportFull.fullPath));

    // 3b. Export con redacción de secretos (includeSecrets: false)
    const exportRedacted = await isolatedBackup.exportProject(testProj.id, { includeSecrets: false });
    assert.strictEqual(exportRedacted.secretsRedacted, true);
    const redactedText = fs.readFileSync(exportRedacted.fullPath, 'utf8');
    for (const secret of ['culkibo_secret_token_123', 'whsec_live_123456', 'dhk_live_abcdef', 'PRIVATE_KEY_BODY', 'db_res_secret']) {
      assert.ok(!redactedText.includes(secret), `exportProject(includeSecrets:false) filtró secreto: ${secret}`);
    }
    const redactedParsed = JSON.parse(redactedText);
    assert.deepStrictEqual(redactedParsed.project.redactedEnvKeys.sort(), ['DATABASE_URL', 'SECRET_KEY']);

    // 3c. Listado y restauración con colisión de ID -> renombra (Restaurado)
    const listed = await isolatedBackup.listBackups();
    assert.ok(listed.some((b) => b.fileName === exportFull.backupFile && b.kind === 'project'));

    const restoreRes = await isolatedBackup.restoreProject(exportFull.backupFile);
    assert.strictEqual(restoreRes.success, true);
    assert.notStrictEqual(restoreRes.restoredProjectId, testProj.id, 'Al existir el ID debe generar uno nuevo');
    const restoredProject = projectManager.getById(restoreRes.restoredProjectId);
    assert.ok(restoredProject);
    assert.ok(restoredProject.name.includes('(Restaurado)'));
    assert.strictEqual(restoredProject.envVars.SECRET_KEY, 'culkibo_secret_token_123');
    assert.strictEqual(restoredProject.resources.length, 1);
    assert.strictEqual(restoredProject.volumes.length, 1);
    console.log('  ✓ Exportación/restauración: fidelidad 100%, redacción total de secretos y manejo de colisión de ID');

    // =========================================================================
    // 4. Seguridad de restoreProject & resolveDownloadPath (traversal, symlink, tamaño, BOM, tamper, unsigned)
    // =========================================================================
    await assert.rejects(() => isolatedBackup.restoreProject('../../package.json'), /fuera|permitid|inválid/i);
    await assert.rejects(() => isolatedBackup.restoreProject('bad\0name.json'), /inválid/i);
    await assert.rejects(() => isolatedBackup.restoreProject('no_existe_123.json'), /no encontrado/i);

    // Externo sin allowExternalPath -> rechazado
    const externalBundle = path.join(tmpRoot, 'outside.json');
    fs.copyFileSync(exportFull.fullPath, externalBundle);
    await assert.rejects(() => isolatedBackup.restoreProject(externalBundle), /fuera del directorio permitido/i);

    // Symlink escape (si el OS permite crear symlinks en este entorno)
    const symlinkPath = path.join(isolatedBackup.backupsDir, 'escape_link.json');
    let symlinkCreated = false;
    try {
      fs.symlinkSync(externalBundle, symlinkPath);
      symlinkCreated = true;
    } catch (e) {}
    if (symlinkCreated) {
      await assert.rejects(() => isolatedBackup.restoreProject('escape_link.json'), /symlink|fuera/i);
      assert.throws(() => isolatedBackup.resolveDownloadPath('escape_link.json'), /symlink|fuera/i);
      fs.unlinkSync(symlinkPath);
    }

    // Archivo > 10 MB rechazado antes de JSON.parse (anti-OOM)
    const hugePath = path.join(isolatedBackup.backupsDir, 'huge_backup.json');
    fs.writeFileSync(hugePath, Buffer.alloc(10 * 1024 * 1024 + 64, 0x20));
    await assert.rejects(() => isolatedBackup.restoreProject('huge_backup.json'), /tamaño máximo/i);
    assert.throws(() => isolatedBackup.resolveDownloadPath('huge_backup.json'), /grande|inválido/i);
    fs.unlinkSync(hugePath);

    // Archivo alterado (1 byte modificado) -> rechazado por SHA-256
    const tamperedName = 'tampered_proj.json';
    const tamperedObj = JSON.parse(fs.readFileSync(exportFull.fullPath, 'utf8'));
    tamperedObj.project.name = 'HACKED';
    fs.writeFileSync(path.join(isolatedBackup.backupsDir, tamperedName), JSON.stringify(tamperedObj));
    await assert.rejects(() => isolatedBackup.restoreProject(tamperedName), /checksum SHA-256.*no coincide/i);

    // Sin checksum -> rechazado por defecto, permitido con allowUnsigned: true + soporte UTF-8 BOM
    const unsignedName = 'unsigned_bom.json';
    const { checksum: _drop, ...unsignedBody } = JSON.parse(fs.readFileSync(exportFull.fullPath, 'utf8'));
    fs.writeFileSync(path.join(isolatedBackup.backupsDir, unsignedName), `\uFEFF${JSON.stringify(unsignedBody)}`, 'utf8');
    await assert.rejects(() => isolatedBackup.restoreProject(unsignedName), /allowUnsigned|checksum/i);
    const unsignedRestored = await isolatedBackup.restoreProject(unsignedName, { allowUnsigned: true });
    assert.strictEqual(unsignedRestored.success, true);

    // resolveDownloadPath rechaza extensiones no .json
    assert.throws(() => isolatedBackup.resolveDownloadPath('secret.env'), /inválido/i);
    assert.strictEqual(isolatedBackup.resolveDownloadPath(exportFull.backupFile), fs.realpathSync(exportFull.fullPath));
    console.log(`  ✓ Seguridad restore/download: traversal, tamaño >10MB, tamper SHA-256, unsigned, BOM${symlinkCreated ? ' y symlink escape' : ''} verificados`);

    // =========================================================================
    // 5. Full-Instance Snapshot v2: cifrado AES-256-GCM + dryRun:false (merge & overwrite preservando secretos vivos)
    // =========================================================================
    await assert.rejects(
      () => isolatedBackup.exportInstanceSnapshot({ includeSecrets: true, passphrase: 'short', persist: false }),
      /al menos 8 caracteres/i
    );

    const encExport = await isolatedBackup.exportInstanceSnapshot({
      includeSecrets: true,
      passphrase: 'correct-horse-battery-staple',
      persist: true
    });
    assert.strictEqual(encExport.encrypted, true);
    assert.strictEqual(encExport.snapshot.data.cipher, 'aes-256-gcm');
    assert.ok(!JSON.stringify(encExport.snapshot.data).includes('culkibo_secret_token_123'));

    // Passphrase incorrecta rechazada
    await assert.rejects(
      () => isolatedBackup.importInstanceSnapshot({ snapshot: encExport.snapshot, passphrase: 'wrong-passphrase', dryRun: true }),
      /incorrecta|corrupto/i
    );

    // Snapshot redactado + dryRun: false en modo merge y overwrite (preservando secretos vivos del proyecto existente!)
    const redactedInst = await isolatedBackup.exportInstanceSnapshot({
      includeSecrets: false,
      persist: true
    });
    assert.strictEqual(redactedInst.secretsRedacted, true);

    // Modificar el snapshot para añadir un proyecto nuevo y actualizar descripción del existente (sin secretos!)
    const snapCopy = JSON.parse(JSON.stringify(redactedInst.snapshot));
    const targetInSnap = snapCopy.data.projects.find((p) => p.id === testProj.id);
    assert.ok(targetInSnap);
    targetInSnap.description = 'Descripción actualizada desde snapshot redactado';
    snapCopy.data.projects.push({
      id: 'proj_imported_new_1',
      name: 'Proyecto Nuevo Importado',
      description: 'Creado en importInstanceSnapshot(dryRun:false)',
      envVars: { PUBLIC_FLAG: '1' }
    });
    const { checksum: _oldCs, ...reBody } = snapCopy;
    snapCopy.checksum = `sha256:${crypto.createHash('sha256').update(JSON.stringify(reBody)).digest('hex')}`;

    // 5a. dryRun: true no muta nada
    const dryPlan = await isolatedBackup.importInstanceSnapshot({ snapshot: snapCopy, mode: 'merge', dryRun: true });
    assert.strictEqual(dryPlan.applied, false);
    assert.ok(dryPlan.plan.projectsToAdd.some((p) => p.id === 'proj_imported_new_1'));
    assert.ok(!projectManager.getById('proj_imported_new_1'), 'dryRun:true no puede crear el proyecto');

    // 5b. dryRun: false mode='merge': añade el nuevo, salta el existente, crea safety backup automático
    const mergeRes = await isolatedBackup.importInstanceSnapshot({ snapshot: snapCopy, mode: 'merge', dryRun: false });
    assert.strictEqual(mergeRes.applied, true);
    assert.strictEqual(mergeRes.result.addedProjects, 1);
    assert.strictEqual(mergeRes.result.updatedProjects, 0);
    assert.ok(mergeRes.preImportSafetyFile, 'Debe crearse copia de seguridad previa automática');
    assert.ok(fs.existsSync(path.join(isolatedBackup.backupsDir, mergeRes.preImportSafetyFile)));
    assert.ok(projectManager.getById('proj_imported_new_1'));

    // 5c. dryRun: false mode='replace' (alias de overwrite) con snapshot REDACTADO:
    //     actualiza description PERO JAMÁS borra envVars/webhookSecret/deployHookToken vivos!
    const overwriteRes = await isolatedBackup.importInstanceSnapshot({ snapshot: snapCopy, mode: 'replace', dryRun: false });
    assert.strictEqual(overwriteRes.applied, true);
    assert.strictEqual(overwriteRes.plan.mode, 'overwrite');
    assert.ok(overwriteRes.result.updatedProjects >= 1);
    const afterOverwrite = projectManager.getById(testProj.id);
    assert.strictEqual(afterOverwrite.description, 'Descripción actualizada desde snapshot redactado');
    assert.strictEqual(afterOverwrite.envVars.SECRET_KEY, 'culkibo_secret_token_123', 'Overwrite redactado jamás borra envVars vivas');
    assert.strictEqual(afterOverwrite.webhookSecret, 'whsec_live_123456', 'Overwrite redactado jamás borra webhookSecret vivo');
    assert.strictEqual(afterOverwrite.deployHookToken, 'dhk_live_abcdef', 'Overwrite redactado jamás borra deployHookToken vivo');
    console.log('  ✓ Instance Snapshot v2: cifrado GCM, dryRun, merge, overwrite/replace preservando secretos vivos y safety backup');

    console.log('✅ All Backup / Restore tests passed!\n');
  } finally {
    projectManager.dataPath = origDataPath;
    projectManager.projects = origProjects;
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

module.exports = testBackup;

if (require.main === module) {
  testBackup().catch((err) => {
    console.error('Backup test failed:', err);
    process.exit(1);
  });
}
