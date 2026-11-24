const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const databaseManager = require('../server/services/databaseManager');
const { ENGINES, encryptSecret, decryptSecret, generatePassword } = require('../server/services/databaseManager');
const s3 = require('../server/services/s3Uploader');
const { S3Client, signRequest, deriveSigningKey, rfc3986, canonicalQueryString } = s3;

/**
 * Bases de datos gestionadas.
 *
 * La mayor parte de la suite NO necesita Docker: la criptografía, la firma
 * SigV4, el planificador, la retención y —sobre todo— la garantía de que
 * ningún secreto acaba en argv se comprueban de forma determinista con el
 * daemon apagado. Sólo el tramo final, que crea un contenedor de verdad, se
 * salta cuando Docker no responde, igual que hace tests/caddy.test.js con Caddy.
 */
async function testDatabases() {
  console.log('🧪 Probando bases de datos gestionadas (aprovisionamiento, copias, S3, retención)...');

  // ==========================================================================
  // 1. Catálogo de motores
  // ==========================================================================
  const engines = databaseManager.listEngines();
  assert.ok(engines.length >= 5, 'Deben ofrecerse al menos cinco motores');

  const byKey = Object.fromEntries(engines.map((e) => [e.engine, e]));
  for (const key of ['postgres', 'mysql', 'mariadb', 'redis', 'valkey', 'mongodb']) {
    assert.ok(byKey[key], `Falta el motor ${key}`);
    // Una etiqueta flotante convierte un reinicio rutinario en una migración de
    // major no planificada. Toda imagen va fijada.
    assert.ok(/:/.test(byKey[key].image), `${key} debe fijar una etiqueta de imagen`);
    assert.ok(!/:latest$/.test(byKey[key].image), `${key} no puede usar :latest`);
    assert.ok(byKey[key].licence, `${key} debe declarar su licencia`);
  }

  // Ninguna de las imágenes oficiales trae HEALTHCHECK: si no lo inyectamos,
  // Docker informa "Up" de un motor que todavía no acepta conexiones.
  for (const [key, engine] of Object.entries(ENGINES)) {
    const probe = engine.health({ username: 'culkibo', dbName: 'app' });
    assert.ok(typeof probe === 'string' && probe.length > 3, `${key} debe definir una sonda de salud`);
  }

  // Regresión de PostgreSQL 18: PGDATA se movió y montar el volumen donde lo
  // esperaba la 17 da un contenedor que arranca y pierde los datos al reiniciar.
  assert.strictEqual(ENGINES.postgres.dataDirFor('postgres:18-alpine'), '/var/lib/postgresql');
  assert.strictEqual(ENGINES.postgres.dataDirFor('postgres:17-alpine'), '/var/lib/postgresql/data');
  console.log('  ✓ Catálogo: 6 motores con imagen fijada, licencia declarada y sonda de salud propia');

  // ==========================================================================
  // 2. Contraseñas y cifrado en reposo
  // ==========================================================================
  const passwords = new Set();
  for (let i = 0; i < 200; i++) passwords.add(generatePassword());
  assert.strictEqual(passwords.size, 200, 'Cada contraseña generada debe ser distinta');

  const sample = generatePassword();
  assert.strictEqual(sample.length, 32, '24 bytes en base64url son 32 caracteres');
  // base64url: sin +, / ni =, para que la cadena de conexión no requiera escapes.
  assert.ok(/^[A-Za-z0-9_-]{32}$/.test(sample), 'La contraseña debe usar el alfabeto base64url');

  const key = crypto.randomBytes(32);
  const blob = encryptSecret(sample, key);
  assert.ok(!blob.includes(sample), 'El texto cifrado no puede contener el secreto');
  assert.strictEqual(decryptSecret(blob, key), sample, 'Ida y vuelta del cifrado');
  assert.notStrictEqual(encryptSecret(sample, key), encryptSecret(sample, key), 'Cada cifrado usa un IV nuevo');

  // AES-GCM debe detectar manipulación, no devolver basura silenciosamente.
  const parts = blob.split(':');
  const tampered = [parts[0], parts[1], parts[2], Buffer.from('otracosa').toString('base64')].join(':');
  assert.throws(() => decryptSecret(tampered, key), 'Un texto cifrado alterado debe fallar la autenticación');
  console.log('  ✓ Contraseñas de 192 bits en base64url, cifradas con AES-256-GCM y autenticadas');

  // ==========================================================================
  // 3. Validación de identificadores (lista blanca, no saneado)
  // ==========================================================================
  const evilNames = [
    'app; rm -rf /', 'app`id`', 'app$(whoami)', 'app|nc 1.2.3.4 1', '../../etc',
    'app\nmalo', 'APP', '1app', 'app-guion', "app'", 'a'.repeat(64)
  ];
  for (const evil of evilNames) {
    await assert.rejects(
      databaseManager.provision({ projectId: 'proj_test', engine: 'postgres', dbName: evil }),
      /inválido/i,
      `Debe rechazarse el nombre de base de datos: ${JSON.stringify(evil)}`
    );
    await assert.rejects(
      databaseManager.provision({ projectId: 'proj_test', engine: 'postgres', username: evil }),
      /inválido/i,
      `Debe rechazarse el usuario: ${JSON.stringify(evil)}`
    );
  }
  await assert.rejects(
    databaseManager.provision({ projectId: 'proj$(id)', engine: 'postgres' }),
    /inválido/i,
    'Debe rechazarse un projectId con metacaracteres'
  );
  await assert.rejects(
    databaseManager.provision({ projectId: 'proj_test', engine: 'oracle' }),
    /no soportado/i
  );
  await assert.rejects(
    databaseManager.provision({ projectId: 'proj_test', engine: 'postgres', image: 'postgres:18; rm -rf /' }),
    /inválida/i
  );
  console.log(`  ✓ Identificadores: ${evilNames.length * 2 + 3} intentos de inyección rechazados por lista blanca`);

  // ==========================================================================
  // 4. SigV4: vectores publicados por AWS
  // ==========================================================================
  // Los dos ejemplos de la página de S3 usan la ortografía de 2013 de la clave
  // de ejemplo (con barra, no con más). Con la otra no reproducen las firmas
  // publicadas, así que este detalle es parte del vector.
  const S3_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
  const EMPTY_SHA = crypto.createHash('sha256').update('').digest('hex');

  const getObject = signRequest({
    method: 'GET',
    canonicalUri: '/test.txt',
    headers: { host: 'examplebucket.s3.amazonaws.com', range: 'bytes=0-9' },
    payloadHash: EMPTY_SHA,
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: S3_SECRET,
    region: 'us-east-1',
    service: 's3',
    date: new Date('2013-05-24T00:00:00Z')
  });
  assert.strictEqual(
    getObject.signature,
    'f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41',
    'Vector AWS «Example: GET Object»'
  );
  assert.strictEqual(getObject.signedHeaders, 'host;range;x-amz-content-sha256;x-amz-date');

  const putObject = signRequest({
    method: 'PUT',
    canonicalUri: '/test%24file.text',
    headers: {
      host: 'examplebucket.s3.amazonaws.com',
      date: 'Fri, 24 May 2013 00:00:00 GMT',
      'x-amz-storage-class': 'REDUCED_REDUNDANCY'
    },
    payloadHash: crypto.createHash('sha256').update('Welcome to Amazon S3.').digest('hex'),
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: S3_SECRET,
    region: 'us-east-1',
    service: 's3',
    date: new Date('2013-05-24T00:00:00Z')
  });
  assert.strictEqual(
    putObject.signature,
    '98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd',
    'Vector AWS «Example: PUT Object»'
  );

  assert.strictEqual(
    deriveSigningKey('wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', '20150830', 'us-east-1', 'iam').toString('hex'),
    'c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9',
    'Vector AWS de derivación de la clave de firma'
  );

  // encodeURIComponent deja !'()* sin codificar y SigV4 exige codificarlos.
  assert.strictEqual(rfc3986("a!b'c(d)e*f"), 'a%21b%27c%28d%29e%2Af');
  assert.strictEqual(rfc3986('espacio aquí'), 'espacio%20aqu%C3%AD');
  assert.strictEqual(rfc3986('-_.~'), '-_.~', 'Los caracteres no reservados no se tocan');
  // Ordenación por nombre y valor vacío firmado igualmente.
  assert.strictEqual(canonicalQueryString({ uploadId: 'x', partNumber: '2' }), 'partNumber=2&uploadId=x');
  assert.strictEqual(canonicalQueryString({ uploads: '' }), 'uploads=');
  console.log('  ✓ SigV4: 3 vectores oficiales de AWS reproducidos byte a byte (GET, PUT, clave de firma)');

  // ==========================================================================
  // 5. Cliente S3: direccionamiento y configuración
  // ==========================================================================
  const r2 = new S3Client({
    endpoint: 'https://abc123.r2.cloudflarestorage.com',
    region: 'auto',
    bucket: 'culkibo-backups',
    accessKeyId: 'AKIAEXAMPLE0000',
    secretAccessKey: 'supersecreto'
  });
  assert.strictEqual(r2.forcePathStyle, true, 'Un endpoint que no es AWS usa path-style');
  assert.strictEqual(
    r2.resolve('culkibo/proj/db/dump.sql.gz').canonicalUri,
    '/culkibo-backups/culkibo/proj/db/dump.sql.gz',
    'En path-style el bucket va en la ruta y las barras de la clave no se codifican'
  );

  const aws = new S3Client({
    endpoint: 'https://s3.eu-west-1.amazonaws.com',
    region: 'eu-west-1',
    bucket: 'mi-bucket',
    accessKeyId: 'AKIAEXAMPLE0000',
    secretAccessKey: 'supersecreto'
  });
  assert.strictEqual(aws.forcePathStyle, false, 'AWS usa virtual-host por defecto');
  assert.strictEqual(aws.resolve('a/b.txt').host, 'mi-bucket.s3.eu-west-1.amazonaws.com');

  // Una clave con espacios y caracteres reservados debe firmar y pedir la
  // MISMA cadena: codificar dos veces es el fallo clásico.
  const tricky = r2.resolve("copias/informe final (v2)+definitivo.sql.gz");
  assert.ok(tricky.canonicalUri.includes('%20'), 'El espacio se codifica como %20, nunca como +');
  assert.ok(tricky.canonicalUri.includes('%28') && tricky.canonicalUri.includes('%29'));
  assert.ok(tricky.url.endsWith(tricky.canonicalUri), 'La URL pedida y la ruta firmada deben coincidir');

  assert.ok(!JSON.stringify(r2.describe()).includes('supersecreto'), 'describe() no puede filtrar la clave');
  assert.strictEqual(r2.describe().secretAccessKey, '********');
  assert.strictEqual(r2.describe().accessKeyId, 'AKIA****0000');

  assert.throws(() => new S3Client({ endpoint: 'https://x', bucket: 'b' }), /incompleta/);
  assert.throws(() => new S3Client({ endpoint: 'no-es-una-url', bucket: 'bucket-ok', accessKeyId: 'a', secretAccessKey: 'b' }), /inválido/);
  assert.throws(() => new S3Client({ endpoint: 'https://x.com', bucket: 'MAYUSCULAS', accessKeyId: 'a', secretAccessKey: 'b' }), /bucket inválido/);
  assert.ok(r2.partSizeBytes >= s3.MIN_PART_SIZE, 'El tamaño de parte nunca baja del mínimo de 5 MiB de S3');
  console.log('  ✓ Cliente S3: path-style/virtual-host, codificación de clave sin doble escape, secretos redactados');

  // ==========================================================================
  // 6. Multipart: cuerpo XML de Complete
  // ==========================================================================
  // Los ETag viajan con sus comillas y las partes en orden ascendente; sin eso
  // S3 responde InvalidPart o InvalidPartOrder.
  let completeBody = null;
  const fakeR2 = new S3Client({
    endpoint: 'https://abc.r2.cloudflarestorage.com', region: 'auto', bucket: 'copias',
    accessKeyId: 'AKIAEXAMPLE0000', secretAccessKey: 's'
  });
  fakeR2.request = async (method, key, opts) => {
    completeBody = opts.body.toString('utf8');
    return { status: 200, text: async () => '<CompleteMultipartUploadResult><ETag>"final-1"</ETag></CompleteMultipartUploadResult>' };
  };
  await fakeR2.completeMultipartUpload('k', 'upload-1', [
    { partNumber: 2, etag: '"0c78aef83f66abc1fa1e8477f296d394"' },
    { partNumber: 1, etag: '"a54357aff0632cce46d942af68356b38"' }
  ]);
  assert.ok(completeBody.includes('<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'));
  assert.ok(
    completeBody.indexOf('<PartNumber>1</PartNumber>') < completeBody.indexOf('<PartNumber>2</PartNumber>'),
    'Las partes deben ir en orden ascendente'
  );
  assert.ok(completeBody.includes('<ETag>"a54357aff0632cce46d942af68356b38"</ETag>'), 'El ETag conserva sus comillas');

  // Un 200 OK puede llevar un <Error> dentro: darlo por bueno es corrupción
  // silenciosa. Es el fallo más caro de una implementación casera.
  fakeR2.request = async () => ({ status: 200, text: async () => '<Error><Code>InternalError</Code><Message>vaya</Message></Error>' });
  await assert.rejects(
    fakeR2.completeMultipartUpload('k', 'u', [{ partNumber: 1, etag: '"x"' }]),
    /InternalError/,
    'Un <Error> dentro de un 200 OK debe tratarse como fallo'
  );
  console.log('  ✓ Multipart: XML válido, ETag entrecomillados, orden ascendente y 200-con-Error detectado');

  // ==========================================================================
  // 7. Planificador cron
  // ==========================================================================
  const from = new Date('2026-09-15T10:07:30');
  const cases = [
    ['0 3 * * *', '2026-09-16T03:00:00'],
    ['*/15 * * * *', '2026-09-15T10:15:00'],
    ['0 0 1 * *', '2026-10-01T00:00:00'],
    ['30 2 * * 1', '2026-09-21T02:30:00'],
    ['0 1,13 * * *', '2026-09-15T13:00:00'],
    ['@hourly', '2026-09-15T11:00:00'],
    ['@weekly', '2026-09-20T04:00:00']
  ];
  for (const [expr, expected] of cases) {
    const next = databaseManager.nextCronRun(expr, from);
    assert.ok(next, `«${expr}» debe tener próxima ejecución`);
    const iso = new Date(next.getTime() - next.getTimezoneOffset() * 60000).toISOString().slice(0, 19);
    assert.strictEqual(iso, expected, `«${expr}» debería disparar en ${expected} y da ${iso}`);
    assert.ok(next > from, 'La próxima ejecución es estrictamente posterior');
  }
  // Domingo se escribe 0 o 7 y debe significar lo mismo.
  assert.strictEqual(
    databaseManager.nextCronRun('0 4 * * 7', from).getTime(),
    databaseManager.nextCronRun('0 4 * * 0', from).getTime()
  );
  for (const bad of ['', 'diario', '* * *', '99 * * * *', '* 25 * * *', '0 0 32 * *', '*/0 * * * *', '0 0 * * 9']) {
    assert.throws(() => databaseManager.parseCron(bad), `Debe rechazarse «${bad}»`);
  }
  console.log(`  ✓ Cron: ${cases.length} horarios calculados al minuto exacto y 8 expresiones inválidas rechazadas`);

  // ==========================================================================
  // 8. Retención abuelo-padre-hijo
  // ==========================================================================
  const now = new Date('2026-09-15T04:00:00Z');
  const history = [];
  for (let i = 0; i < 60; i++) {
    history.push({ id: `b${i}`, createdAt: new Date(now.getTime() - i * 24 * 3600 * 1000).toISOString() });
  }
  const plan = databaseManager.planRetention(history, { daily: 7, weekly: 4 });
  assert.ok(plan.keep.includes('b0'), 'La copia más reciente siempre se conserva');
  assert.strictEqual(plan.keep.length + plan.prune.length, history.length, 'Toda copia se conserva o se poda');
  assert.strictEqual(new Set(plan.keep).size, plan.keep.length, 'Sin duplicados en el plan');
  assert.ok(plan.keep.length >= 7 && plan.keep.length <= 11, `Se esperaban ~9 supervivientes, hay ${plan.keep.length}`);
  for (const id of plan.keep) assert.ok(plan.reasons[id], `Cada copia conservada debe decir por qué: ${id}`);

  // Varias copias el mismo día: sólo sobrevive la más reciente de ese día.
  const sameDay = [
    { id: 'm1', createdAt: '2026-09-15T01:00:00Z' },
    { id: 'm2', createdAt: '2026-09-15T02:00:00Z' },
    { id: 'm3', createdAt: '2026-09-15T03:00:00Z' }
  ];
  const dayPlan = databaseManager.planRetention(sameDay, { daily: 7, weekly: 0 });
  assert.deepStrictEqual(dayPlan.keep, ['m3'], 'De un mismo día sobrevive la última');
  assert.deepStrictEqual(dayPlan.prune.sort(), ['m1', 'm2']);

  // Una política vacía no puede dejar a nadie sin ninguna copia.
  const zeroPlan = databaseManager.planRetention(history, { daily: 0, weekly: 0 });
  assert.deepStrictEqual(zeroPlan.keep, ['b0'], 'Incluso con retención 0 sobrevive la última copia');
  assert.deepStrictEqual(databaseManager.planRetention([], { daily: 7, weekly: 4 }).keep, []);
  console.log('  ✓ Retención: 7 diarias + 4 semanales sobre 60 copias, sin huérfanas y sin quedarse a cero');

  // ==========================================================================
  // 9. Invariante central: ningún secreto en argv
  // ==========================================================================
  // Se ejecuta `provision()` de verdad interceptando la capa de Docker, para
  // comprobar sobre la línea de comandos REAL que la contraseña no aparece y
  // que viaja por un --env-file con permisos restringidos.
  const originalDocker = databaseManager.docker.bind(databaseManager);
  const originalAvailable = databaseManager.isDockerAvailable.bind(databaseManager);
  const invocations = [];
  let capturedEnvFile = null;

  databaseManager.isDockerAvailable = async () => true;
  databaseManager.docker = async (args) => {
    invocations.push(args);
    const i = args.indexOf('--env-file');
    if (i !== -1) {
      const file = args[i + 1];
      capturedEnvFile = { path: file, content: fs.readFileSync(file, 'utf8'), mode: fs.statSync(file).mode & 0o777 };
    }
    if (args[0] === 'network' && args[1] === 'inspect') throw new Error('no existe');
    return { stdout: 'c0ffee1234567890\n', stderr: '' };
  };

  let created = null;
  try {
    created = await databaseManager.provision({
      projectId: 'proj_test_db',
      engine: 'postgres',
      name: 'Pruebas',
      dbName: 'tienda',
      username: 'tendero'
    });

    const record = databaseManager.state.databases.find((d) => d.id === created.id);
    const clearPassword = databaseManager.decryptPassword(record);
    assert.ok(clearPassword && clearPassword.length === 32);

    // (a) La contraseña no aparece en NINGÚN argumento de NINGUNA llamada.
    for (const args of invocations) {
      for (const arg of args) {
        assert.ok(
          !String(arg).includes(clearPassword),
          `Secreto filtrado en argv de docker: ${String(arg).slice(0, 60)}`
        );
      }
    }
    // (b) Tampoco con la forma `-e CLAVE=valor`.
    const runArgs = invocations.find((a) => a[0] === 'run');
    assert.ok(runArgs, 'Debe haberse ejecutado un docker run');
    assert.ok(!runArgs.some((a) => /^-e$/.test(a)), 'No se usa -e: el secreto iría en la línea de comandos');
    assert.ok(runArgs.includes('--env-file'), 'El secreto entra por --env-file');

    // (c) El fichero temporal sí lo contenía, con permisos de sólo propietario,
    //     y se ha borrado al terminar.
    assert.ok(capturedEnvFile, 'Debe haberse escrito un fichero de entorno');
    assert.ok(capturedEnvFile.content.includes(`POSTGRES_PASSWORD=${clearPassword}`));
    assert.ok(capturedEnvFile.content.includes(`PGPASSWORD=${clearPassword}`), 'Se inyecta la variable que lee pg_dump');
    if (process.platform !== 'win32') {
      assert.strictEqual(capturedEnvFile.mode, 0o600, 'El fichero de entorno debe ser 0600');
    }
    assert.ok(!fs.existsSync(capturedEnvFile.path), 'El fichero temporal se borra siempre');

    // (d) Endurecimiento del contenedor.
    for (const flag of ['--restart', '--memory', '--memory-swap', '--cpus', '--pids-limit',
                        '--security-opt', '--health-cmd', '--network', '-v']) {
      assert.ok(runArgs.includes(flag), `Falta ${flag} en docker run`);
    }
    assert.strictEqual(runArgs[runArgs.indexOf('--restart') + 1], 'unless-stopped');
    assert.strictEqual(runArgs[runArgs.indexOf('--memory-swap') + 1], runArgs[runArgs.indexOf('--memory') + 1],
      'memory-swap debe igualar a memory o el límite de memoria no limita nada');
    assert.strictEqual(runArgs[runArgs.indexOf('--security-opt') + 1], 'no-new-privileges');
    assert.ok(runArgs.includes(`${record.volumeName}:/var/lib/postgresql`), 'Volumen en el PGDATA de PostgreSQL 18');

    // (e) NUNCA se publica un puerto al crear.
    assert.ok(!runArgs.includes('-p') && !runArgs.includes('--publish'),
      'Una base de datos recién creada no puede estar publicada en el host');
    assert.strictEqual(created.exposure.enabled, false);

    // (f) Red propia del proyecto, no una red plana compartida (fallo de Dokploy).
    assert.strictEqual(record.networkName, 'culkibo_net_proj_test_db');
    assert.ok(invocations.some((a) => a[0] === 'network' && a[1] === 'create'));
    console.log('  ✓ Aprovisionamiento: secreto sólo en --env-file 0600 y efímero, 0 apariciones en argv');
    console.log('  ✓ Contenedor: límites, sonda, no-new-privileges, red por proyecto y CERO puertos publicados');

    // ------------------------------------------------------------------------
    // 10. Redacción en todas las salidas
    // ------------------------------------------------------------------------
    const listed = databaseManager.list({ projectId: 'proj_test_db' });
    assert.ok(!JSON.stringify(listed).includes(clearPassword), 'El listado no puede devolver la contraseña');
    assert.ok(!JSON.stringify(databaseManager.get(created.id)).includes(clearPassword));
    assert.ok(listed[0].connectionTemplate.includes('********'), 'La plantilla lleva la contraseña oculta');
    assert.ok(!Object.prototype.hasOwnProperty.call(listed[0], 'passwordEnc'));
    assert.strictEqual(listed[0].hasPassword, true);

    // El fichero en disco tampoco la guarda en claro.
    const onDisk = fs.readFileSync(path.join(__dirname, '..', 'data', 'databases.json'), 'utf8');
    assert.ok(!onDisk.includes(clearPassword), 'databases.json no puede contener la contraseña en claro');

    // El endpoint explícito sí, y sólo ese.
    const creds = databaseManager.getCredentials(created.id);
    assert.strictEqual(creds.password, clearPassword);
    assert.strictEqual(creds.internalConnectionString,
      `postgresql://tendero:${clearPassword}@${record.containerName}:5432/tienda`);
    assert.strictEqual(creds.hostConnectionString, null, 'Sin exposición no hay cadena de host');

    // Un mensaje de error nunca arrastra el secreto a un log.
    assert.ok(!databaseManager.redactMessage(`fallo con ${clearPassword} dentro`, clearPassword).includes(clearPassword));
    console.log('  ✓ Redacción: ausente del listado, del detalle y del disco; presente sólo en /credentials');

    // ------------------------------------------------------------------------
    // 11. Exposición: opt-in con aviso
    // ------------------------------------------------------------------------
    await assert.rejects(
      databaseManager.setExposure(created.id, { enabled: true, bindAddress: '0.0.0.0', hostPort: 5432 }),
      /acknowledgeRisk/,
      'Enlazar en 0.0.0.0 exige confirmación explícita'
    );
    await assert.rejects(
      databaseManager.setExposure(created.id, { enabled: true, bindAddress: 'todas' }),
      /inválida/
    );

    // Obtener un puerto efímero realmente libre (evita rangos excluidos de Hyper-V/WSL2 en Windows)
    const testExposurePort = await new Promise((resolve, reject) => {
      const net = require('net');
      const s = net.createServer();
      s.once('error', reject);
      s.listen(0, '127.0.0.1', () => {
        const addr = s.address();
        const p = typeof addr === 'object' && addr ? addr.port : 55432;
        s.close(() => resolve(p));
      });
    });

    const local = await databaseManager.setExposure(created.id, { enabled: true, hostPort: testExposurePort });
    assert.strictEqual(local.exposure.bindAddress, '127.0.0.1', 'Por defecto sólo local');
    assert.ok(/127\.0\.0\.1/.test(local.warning));
    const reRun = invocations.filter((a) => a[0] === 'run').pop();
    assert.ok(reRun.includes(`127.0.0.1:${testExposurePort}:5432`), 'El mapeo debe fijar la interfaz de escucha');

    const open = await databaseManager.setExposure(created.id, {
      enabled: true, bindAddress: '0.0.0.0', hostPort: testExposurePort, acknowledgeRisk: true
    });
    assert.ok(/UFW/.test(open.warning), 'El aviso debe explicar que Docker se salta UFW');
    assert.ok(!JSON.stringify(open).includes(clearPassword));

    await databaseManager.setExposure(created.id, { enabled: false });
    assert.strictEqual(databaseManager.get(created.id).exposure.enabled, false);
    console.log('  ✓ Exposición: 127.0.0.1 por defecto, 0.0.0.0 sólo con confirmación y aviso sobre UFW');

    // ------------------------------------------------------------------------
    // 12. Planificación y disparo
    // ------------------------------------------------------------------------
    assert.throws(() => databaseManager.setSchedule(created.id, { enabled: true, cron: 'todos los martes' }));
    const scheduled = databaseManager.setSchedule(created.id, { enabled: true, cron: '0 3 * * *' });
    assert.strictEqual(scheduled.schedule.enabled, true);
    assert.ok(new Date(scheduled.schedule.nextRunAt) > new Date(), 'nextRunAt se persiste hacia el futuro');

    // El estado persistido es lo que permite recuperar una ventana perdida
    // mientras el daemon estaba parado; node-cron, en memoria, la perdería.
    const rec = databaseManager.state.databases.find((d) => d.id === created.id);
    rec.schedule.nextRunAt = new Date(Date.now() - 60000).toISOString();

    const fired = [];
    const originalRunBackup = databaseManager.runBackup.bind(databaseManager);
    databaseManager.runBackup = async (id, o) => { fired.push({ id, ...o }); return { success: true }; };
    const tick1 = await databaseManager.tick();
    assert.deepStrictEqual(tick1.fired, [created.id], 'Una ventana vencida dispara la copia');
    assert.strictEqual(fired[0].trigger, 'scheduled');
    assert.ok(new Date(rec.schedule.nextRunAt) > new Date(), 'nextRunAt se recalcula ANTES de ejecutar');

    // Un segundo tick inmediato no puede volver a disparar.
    const tick2 = await databaseManager.tick();
    assert.deepStrictEqual(tick2.fired, [], 'Sin ventana vencida no se dispara nada');

    databaseManager.setSchedule(created.id, { enabled: false });
    assert.strictEqual(databaseManager.get(created.id).schedule.nextRunAt, null);
    assert.deepStrictEqual((await databaseManager.tick()).fired, [], 'Una programación desactivada no dispara');
    databaseManager.runBackup = originalRunBackup;

    // El temporizador jamás puede mantener vivo el proceso.
    const timer = databaseManager.startScheduler({ intervalMs: 60000, catchUp: false });
    assert.ok(timer, 'startScheduler devuelve el temporizador');
    assert.strictEqual(databaseManager.startScheduler({ catchUp: false }), timer, 'Arrancarlo dos veces no duplica');
    databaseManager.stopScheduler();
    assert.strictEqual(databaseManager.schedulerTimer, null);
    console.log('  ✓ Planificador: nextRunAt persistido, recálculo previo al volcado, sin disparos dobles y unref()');

    // ------------------------------------------------------------------------
    // 13. Retención aplicada y configuración de S3
    // ------------------------------------------------------------------------
    assert.throws(() => databaseManager.setRetention(created.id, { daily: 0, weekly: 0 }), /no puede ser 0/);
    assert.deepStrictEqual(databaseManager.setRetention(created.id, { daily: 3, weekly: 2 }).retention,
      { daily: 3, weekly: 2 });

    const dir = databaseManager.backupDir(created.id);
    rec.backups = [];
    for (let i = 0; i < 10; i++) {
      const fileName = `fake_${i}.sql.gz`;
      fs.writeFileSync(path.join(dir, fileName), `contenido ${i}`);
      rec.backups.push({
        id: `bk${i}`, fileName, sizeBytes: 12,
        createdAt: new Date(Date.now() - i * 24 * 3600 * 1000).toISOString(),
        trigger: 'test', remote: null
      });
    }
    const applied = await databaseManager.applyRetention(created.id);
    assert.ok(applied.pruned > 0, 'Debe podarse algo con 10 copias y política 3+2');
    assert.strictEqual(applied.kept, rec.backups.length);
    for (const b of rec.backups) {
      assert.ok(fs.existsSync(path.join(dir, b.fileName)), 'Las copias conservadas siguen en disco');
    }
    assert.strictEqual(fs.readdirSync(dir).length, applied.kept, 'Las podadas se borran del disco');

    // Configuración del bucket: validada al guardar, nunca devuelta en claro.
    assert.throws(() => databaseManager.setS3Config({ endpoint: 'https://x.com', bucket: 'b' }), /incompleta/);
    const cfg = databaseManager.setS3Config({
      endpoint: 'https://cuenta.r2.cloudflarestorage.com',
      region: 'auto',
      bucket: 'culkibo-copias',
      accessKeyId: 'AKIAEXAMPLE0000',
      secretAccessKey: 'clave-ultra-secreta',
      prefix: 'culkibo/'
    });
    assert.strictEqual(cfg.configured, true);
    assert.strictEqual(cfg.secretAccessKey, '********');
    assert.ok(!JSON.stringify(cfg).includes('clave-ultra-secreta'));
    assert.ok(!fs.readFileSync(path.join(__dirname, '..', 'data', 'databases.json'), 'utf8').includes('clave-ultra-secreta'),
      'La clave secreta de S3 tampoco se guarda en claro');
    assert.strictEqual(databaseManager.s3ClientFor().secretAccessKey, 'clave-ultra-secreta',
      'El cliente sí la recupera descifrada');
    databaseManager.setS3Config(null);
    assert.strictEqual(databaseManager.getS3Config().configured, false);
    console.log('  ✓ Retención aplicada a disco y configuración S3/R2 validada, cifrada y redactada');
  } finally {
    databaseManager.docker = originalDocker;
    databaseManager.isDockerAvailable = originalAvailable;
    if (created) {
      try { await databaseManager.remove(created.id, { deleteVolume: false, deleteBackups: true }); } catch (e) {}
    }
    databaseManager.state.databases = databaseManager.state.databases.filter((d) => d.projectId !== 'proj_test_db');
    databaseManager.state.s3 = null;
    databaseManager.save();
  }

  // ==========================================================================
  // 14. Camino real contra Docker
  // ==========================================================================
  const dockerUp = await databaseManager.isDockerAvailable(true);
  if (!dockerUp) {
    console.log('  ⏭  Ciclo completo omitido: el daemon de Docker no responde.');
    console.log('     Para ejecutarlo: arranca Docker y repite. Todo lo anterior ya se ha verificado.\n');
    console.log('✅ Bases de datos gestionadas verificadas (sin Docker)\n');
    return;
  }

  // Por defecto sólo Valkey: 21 MB, arranca en segundos y recorre el camino
  // entero, incluido el arranque con `--requirepass` leído del entorno. Los
  // seis motores están verificados y se ejecutan con
  // CULKIBO_TEST_ENGINES=postgres,mysql,mariadb,redis,valkey,mongodb
  const requested = (process.env.CULKIBO_TEST_ENGINES || 'valkey')
    .split(',').map((s) => s.trim()).filter(Boolean);

  for (const engineKey of requested) {
    if (!ENGINES[engineKey]) {
      console.log(`  ⚠  Motor desconocido en CULKIBO_TEST_ENGINES: ${engineKey}`);
      continue;
    }
    await runLiveCycle(engineKey);
  }

  console.log('✅ Bases de datos gestionadas verificadas contra Docker real\n');
}

/**
 * Sondas por motor para el ciclo real. Cada una escribe, lee y estropea un
 * dato conocido usando SÓLO argv: ni una cadena de shell construida con datos.
 * Donde hace falta contraseña se usa el mismo envoltorio estático que usa el
 * servicio, leyendo la variable que ya está dentro del contenedor.
 */
const LIVE_PROBES = {
  postgres: {
    provision: { dbName: 'tienda', username: 'tendero' },
    sql: (c, q) => ['exec', c, 'psql', '-U', 'tendero', '-d', 'tienda', '-tAc', q]
  },
  mysql: {
    provision: { dbName: 'tienda', username: 'tendero' },
    sql: (c, q) => ['exec', c, 'sh', '-c', 'MYSQL_PWD="$CULKIBO_MYSQL_PWD" exec "$@"', 'p',
                    'mysql', '-u', 'root', '-N', '-B', 'tienda', '-e', q]
  },
  mariadb: {
    provision: { dbName: 'tienda', username: 'tendero' },
    sql: (c, q) => ['exec', c, 'sh', '-c', 'MYSQL_PWD="$CULKIBO_MYSQL_PWD" exec "$@"', 'p',
                    'mariadb', '-u', 'root', '-N', '-B', 'tienda', '-e', q]
  },
  mongodb: {
    provision: { dbName: 'tienda', username: 'tendero' },
    js: (c, code) => ['exec', c, 'sh', '-c',
      'exec mongosh --quiet -u "$MONGO_INITDB_ROOT_USERNAME" -p "$MONGO_INITDB_ROOT_PASSWORD" ' +
      '--authenticationDatabase admin tienda --eval "$1"', 'p', code]
  },
  redis: { provision: {}, cli: 'redis-cli', authVars: ['REDISCLI_AUTH'] },
  valkey: { provision: {}, cli: 'valkey-cli', authVars: ['VALKEYCLI_AUTH', 'REDISCLI_AUTH'] }
};

async function runLiveCycle(engineKey) {
  const engine = ENGINES[engineKey];
  const probe = LIVE_PROBES[engineKey];
  const projectId = `proj_live_${engineKey}`;

  try {
    await databaseManager.docker(['image', 'inspect', engine.image], { timeout: 15000 });
  } catch (e) {
    console.log(`  ℹ  Descargando ${engine.image}...`);
    try {
      await databaseManager.docker(['pull', engine.image], { timeout: 600000 });
    } catch (pullErr) {
      console.log(`  ⏭  ${engine.label} omitido: no se pudo descargar ${engine.image}.`);
      return;
    }
  }

  let live = null;
  try {
    live = await databaseManager.provision({
      projectId,
      engine: engineKey,
      name: `${engine.label} de pruebas`,
      memoryMb: 512,
      cpus: 1,
      ...probe.provision
    });
    assert.ok(live.id);
    assert.strictEqual(live.exposure.enabled, false);
    const c = live.containerName;

    // El contenedor llega a sano: la sonda que inyectamos tiene que pasar,
    // porque ninguna de estas imágenes trae HEALTHCHECK propia.
    let health = 'unknown';
    for (let i = 0; i < 120 && health !== 'healthy'; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      health = (await databaseManager.refreshHealth(live.id)).health;
      if (health === 'unhealthy') break;
    }
    assert.strictEqual(health, 'healthy', `${engine.label}: la sonda debe llegar a healthy (leído: ${health})`);

    // El puerto NO está publicado: nadie lo alcanza desde el host.
    const { stdout: ports } = await databaseManager.docker(['port', c]);
    assert.strictEqual(ports.trim(), '', `${engine.label}: una base recién creada no expone ningún puerto`);

    const creds = databaseManager.getCredentials(live.id);

    // La contraseña está activa de verdad.
    if (probe.cli) {
      // Hay que vaciar TODAS las variables de autenticación: valkey-cli mira
      // VALKEYCLI_AUTH antes que REDISCLI_AUTH, y limpiar sólo una dejaría al
      // cliente autenticado y a la prueba pasando sin probar nada. Además el
      // código de salida es 0 incluso con NOAUTH: hay que mirar la salida.
      const clear = probe.authVars.flatMap((v) => ['--env', `${v}=`]);
      const { stdout, stderr } = await databaseManager.docker(
        ['exec', ...clear, c, probe.cli, '--no-auth-warning', 'set', 'culkibo:intruso', 'v'],
        { timeout: 15000 }
      ).catch(() => ({ stdout: 'NOAUTH', stderr: '' }));
      assert.ok(/NOAUTH|WRONGPASS|denied/i.test(`${stdout}${stderr}`),
        `${engine.label}: sin credenciales el motor debe rechazar la escritura`);
    }

    // ---- Dato conocido -> copia -> estropear -> restaurar -> el dato vuelve --
    const read = async () => {
      if (probe.cli) return (await databaseManager.docker(['exec', c, probe.cli, 'get', 'culkibo:prueba'])).stdout.trim();
      if (probe.js) return (await databaseManager.docker(probe.js(c, 'db.pedidos.findOne({_id:1}).nota'))).stdout.trim();
      return (await databaseManager.docker(probe.sql(c, 'SELECT nota FROM pedidos'))).stdout.trim();
    };
    const write = async (value) => {
      if (probe.cli) return databaseManager.docker(['exec', c, probe.cli, 'set', 'culkibo:prueba', value]);
      if (probe.js) {
        return databaseManager.docker(probe.js(c,
          `db.pedidos.replaceOne({_id:1},{_id:1,nota:"${value}"},{upsert:true})`));
      }
      await databaseManager.docker(probe.sql(c, 'CREATE TABLE IF NOT EXISTS pedidos (id int, nota text)'));
      await databaseManager.docker(probe.sql(c, 'DELETE FROM pedidos'));
      return databaseManager.docker(probe.sql(c, `INSERT INTO pedidos VALUES (1, '${value}')`));
    };

    await write('valor-original');
    assert.strictEqual(await read(), 'valor-original');

    const backup = await databaseManager.runBackup(live.id, { trigger: 'manual' });
    assert.strictEqual(backup.success, true);
    assert.ok(backup.backup.sizeBytes > 0, 'La copia debe tener contenido');
    assert.ok(/^[0-9a-f]{64}$/.test(backup.backup.sha256), 'Se registra el sha256 de la copia');
    const backupPath = path.join(databaseManager.backupDir(live.id), backup.backup.fileName);
    assert.ok(fs.existsSync(backupPath));
    assert.ok(!fs.readFileSync(backupPath).includes(Buffer.from(creds.password)),
      'La copia no puede llevar dentro la contraseña');

    await write('valor-corrupto');
    assert.strictEqual(await read(), 'valor-corrupto');

    await databaseManager.restore(live.id, { backupId: backup.backup.id });

    let restored = '';
    for (let i = 0; i < 30 && restored !== 'valor-original'; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      try { restored = await read(); } catch (e) {}
    }
    assert.strictEqual(restored, 'valor-original', `${engine.label}: la restauración debe devolver el dato original`);

    // Una copia alterada no se restaura.
    fs.appendFileSync(backupPath, 'basura');
    await assert.rejects(
      databaseManager.restore(live.id, { backupId: backup.backup.id }),
      /sha256|corrupto/i,
      'Una copia que no cuadra con su sha256 no debe restaurarse'
    );

    console.log(`  ✓ ${engine.label} (${engine.image}): creado sano, sin puertos, con clave activa, ` +
                `copia de ${backup.backup.sizeBytes} B, restauración verificada e integridad comprobada`);
  } finally {
    if (live) {
      try { await databaseManager.remove(live.id, { deleteVolume: true, deleteBackups: true }); } catch (e) {}
    }
    databaseManager.state.databases = databaseManager.state.databases.filter((d) => d.projectId !== projectId);
    databaseManager.save();
    try { await databaseManager.docker(['network', 'rm', `culkibo_net_${projectId}`], { timeout: 20000 }); } catch (e) {}
  }
}

module.exports = testDatabases;

if (require.main === module) {
  testDatabases().catch((err) => {
    console.error('❌ Fallo en las pruebas de bases de datos:', err);
    process.exit(1);
  });
}
