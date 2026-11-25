const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');

const databaseManagerMod = require('../server/services/databaseManager');
const {
  DatabaseManager,
  ENGINES,
  PGBOUNCER_IMAGE,
  computeTuningConfig,
  loadOrCreateKey,
  encryptSecret,
  decryptSecret,
  generatePassword,
  computeKeyId,
  deriveBackupKeyFromPassphrase,
  encryptBackupFile,
  decryptBackupFile,
  hasCkb1Magic,
  inspectCkb1Header
} = databaseManagerMod;
const notificationService = require('../server/services/notificationService');
const s3 = require('../server/services/s3Uploader');
const {
  S3Client,
  signRequest,
  deriveSigningKey,
  rfc3986,
  canonicalQueryString,
  sha256Base64,
  buildLifecycleXml
} = s3;

/**
 * Crea un flujo Web ReadableStream a partir de trozos Buffer para simular S3 GET sin red real.
 */
function makeWebStream(chunks) {
  let idx = 0;
  return {
    getReader() {
      return {
        async read() {
          if (idx >= chunks.length) return { done: true, value: undefined };
          return { done: false, value: chunks[idx++] };
        },
        async cancel() {}
      };
    },
    async cancel() {}
  };
}

/**
 * Suite completa de Bases de Datos Gestionadas, Backups Cifrados AEAD y DR.
 *
 * Aislada 100% en os.tmpdir() — JAMÁS muta data/databases.json ni data/.databases.key.
 */
async function testDatabases() {
  console.log('🧪 Probando bases de datos gestionadas, AEAD CKB1, S3, tuning, PgBouncer, drills y clonado...');

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-db-test-'));
  const dm = new DatabaseManager({ dataDir: tmpRoot, registerPortProvider: false });

  // Capturar notificaciones reales sin hacer peticiones HTTP salientes
  const origNotify = notificationService.notify.bind(notificationService);
  /** @type {any[]} */
  const sentNotifications = [];
  notificationService.notify = async (payload) => {
    sentNotifications.push(payload);
    return { sent: true };
  };

  try {
    // =========================================================================
    // 1. Catálogo de 12 motores fijados (0 :latest) + PG18 dataDir + --no-privileges
    // =========================================================================
    const engines = dm.listEngines();
    assert.strictEqual(engines.length, 12, `Deben ofrecerse exactamente 12 motores (hay ${engines.length})`);

    const expectedEngines = [
      'postgres', 'pgvector', 'timescaledb', 'mysql', 'mariadb',
      'valkey', 'redis', 'dragonfly', 'mongodb', 'clickhouse', 'qdrant', 'meilisearch'
    ];
    const byKey = Object.fromEntries(engines.map((e) => [e.engine, e]));
    for (const key of expectedEngines) {
      assert.ok(byKey[key], `Falta el motor ${key}`);
      assert.ok(/:/.test(byKey[key].image), `${key} debe fijar una etiqueta de imagen`);
      assert.ok(!/:latest$/.test(byKey[key].image), `${key} no puede usar :latest`);
      assert.ok(byKey[key].licence, `${key} debe declarar su licencia`);
    }

    for (const [key, engine] of Object.entries(ENGINES)) {
      const probe = engine.health({ username: 'culkibo', dbName: 'app' });
      assert.ok(typeof probe === 'string' && probe.length > 3, `${key} debe definir una sonda de salud`);
    }

    // Regresión PG18 vs PG17 en postgres, pgvector y timescaledb
    assert.strictEqual(ENGINES.postgres.dataDirFor('postgres:18-alpine'), '/var/lib/postgresql');
    assert.strictEqual(ENGINES.postgres.dataDirFor('postgres:17-alpine'), '/var/lib/postgresql/data');
    assert.strictEqual(ENGINES.pgvector.dataDirFor('pgvector/pgvector:0.8.0-pg17'), '/var/lib/postgresql/data');
    assert.strictEqual(ENGINES.pgvector.dataDirFor('pgvector/pgvector:0.8.0-pg18'), '/var/lib/postgresql');
    assert.strictEqual(ENGINES.timescaledb.dataDirFor('timescale/timescaledb:2.19.3-pg17'), '/var/lib/postgresql/data');

    // Regresión Coolify-Docs #294: pg_restore debe incluir --no-owner Y --no-privileges
    for (const pgKey of ['postgres', 'pgvector', 'timescaledb']) {
      const rSpec = ENGINES[pgKey].restore({ username: 'u', dbName: 'd', inFile: '/tmp/a.dump' });
      assert.ok(rSpec.args.includes('--no-owner'), `${pgKey} restore debe incluir --no-owner`);
      assert.ok(rSpec.args.includes('--no-privileges'), `${pgKey} restore debe incluir --no-privileges`);
    }
    console.log('  ✓ Catálogo: 12 motores fijados (0 :latest), licencias, sondas, PG18 PGDATA y pg_restore --no-privileges');

    // =========================================================================
    // 2. Contraseñas, AES-256-GCM en reposo y guardas anti-corrupción (.key / .bak)
    // =========================================================================
    const passwords = new Set();
    for (let i = 0; i < 200; i++) passwords.add(generatePassword());
    assert.strictEqual(passwords.size, 200);
    const sample = generatePassword();
    assert.strictEqual(sample.length, 32);
    assert.ok(/^[A-Za-z0-9_-]{32}$/.test(sample));

    const key = crypto.randomBytes(32);
    const blob = encryptSecret(sample, key);
    assert.ok(!blob.includes(sample));
    assert.strictEqual(decryptSecret(blob, key), sample);
    assert.notStrictEqual(encryptSecret(sample, key), encryptSecret(sample, key));

    const parts = blob.split(':');
    const tampered = [parts[0], parts[1], parts[2], Buffer.from('otracosa').toString('base64')].join(':');
    assert.throws(() => decryptSecret(tampered, key));

    // Guardas anti-pérdida de clave y recuperación .bak
    const keyGuardDir = path.join(tmpRoot, 'key-guard');
    fs.mkdirSync(keyGuardDir, { recursive: true });
    const badKeyPath = path.join(keyGuardDir, '.bad.key');
    fs.writeFileSync(badKeyPath, 'deadbeef', 'utf8');
    assert.throws(() => loadOrCreateKey(badKeyPath, path.join(keyGuardDir, 'd.json')), /corrupta/i);

    const orphanData = path.join(keyGuardDir, 'orphan.json');
    fs.writeFileSync(orphanData, JSON.stringify({ databases: [{ passwordEnc: 'v1:abc:def:ghi' }] }));
    assert.throws(() => loadOrCreateKey(path.join(keyGuardDir, 'missing.key'), orphanData), /Falta el archivo de clave/i);

    // Recuperación automática desde .bak y bloqueo de escritura si ambos corruptos
    const bakTestDir = path.join(tmpRoot, 'bak-recovery');
    const bakDataDir = path.join(bakTestDir, 'data');
    fs.mkdirSync(bakDataDir, { recursive: true });
    fs.writeFileSync(path.join(bakDataDir, 'databases.json'), '{corrupt json', 'utf8');
    fs.writeFileSync(path.join(bakDataDir, 'databases.json.bak'), JSON.stringify({
      version: 1, s3: null, databases: [{ id: 'db_recovered', projectId: 'p1', engine: 'postgres', name: 'RecoverMe' }]
    }));
    const recoveredMgr = new DatabaseManager({ dataDir: bakTestDir, registerPortProvider: false });
    assert.strictEqual(recoveredMgr.state.databases.length, 1);
    assert.strictEqual(recoveredMgr.state.databases[0].id, 'db_recovered');

    const totalCorruptDir = path.join(tmpRoot, 'total-corrupt');
    fs.mkdirSync(path.join(totalCorruptDir, 'data'), { recursive: true });
    fs.writeFileSync(path.join(totalCorruptDir, 'data', 'databases.json'), '{broken', 'utf8');
    const brokenMgr = new DatabaseManager({ dataDir: totalCorruptDir, registerPortProvider: false });
    assert.strictEqual(brokenMgr._corruptedOnLoad, true);
    assert.throws(() => brokenMgr.save({ strict: true }), /corrupto/i);
    console.log('  ✓ Criptografía en reposo + guardas anti-pérdida de clave y recuperación .bak verificadas');

    // =========================================================================
    // 3. Validación estricta de identificadores (lista blanca)
    // =========================================================================
    const evilNames = [
      'app; rm -rf /', 'app`id`', 'app$(whoami)', 'app|nc 1.2.3.4 1', '../../etc',
      'app\nmalo', 'APP', '1app', 'app-guion', "app'", 'a'.repeat(64)
    ];
    for (const evil of evilNames) {
      await assert.rejects(dm.provision({ projectId: 'proj_test', engine: 'postgres', dbName: evil }), /inválido/i);
      await assert.rejects(dm.provision({ projectId: 'proj_test', engine: 'postgres', username: evil }), /inválido/i);
    }
    await assert.rejects(dm.provision({ projectId: 'proj$(id)', engine: 'postgres' }), /inválido/i);
    await assert.rejects(dm.provision({ projectId: 'proj_test', engine: 'oracle' }), /no soportado/i);
    await assert.rejects(dm.provision({ projectId: 'proj_test', engine: 'postgres', image: 'postgres:18; rm -rf /' }), /inválida/i);
    console.log(`  ✓ Identificadores: ${evilNames.length * 2 + 3} intentos de inyección rechazados`);

    // =========================================================================
    // 4. SigV4 vectores AWS + S3 Checksums (x-amz-checksum-sha256), Metadata, Multipart, Download & Lifecycle XML
    // =========================================================================
    const S3_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    const EMPTY_SHA = crypto.createHash('sha256').update('').digest('hex');

    const getObject = signRequest({
      method: 'GET', canonicalUri: '/test.txt',
      headers: { host: 'examplebucket.s3.amazonaws.com', range: 'bytes=0-9' },
      payloadHash: EMPTY_SHA, accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: S3_SECRET,
      region: 'us-east-1', service: 's3', date: new Date('2013-05-24T00:00:00Z')
    });
    assert.strictEqual(getObject.signature, 'f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41');
    assert.strictEqual(getObject.signedHeaders, 'host;range;x-amz-content-sha256;x-amz-date');

    const putObjectVec = signRequest({
      method: 'PUT', canonicalUri: '/test%24file.text',
      headers: { host: 'examplebucket.s3.amazonaws.com', date: 'Fri, 24 May 2013 00:00:00 GMT', 'x-amz-storage-class': 'REDUCED_REDUNDANCY' },
      payloadHash: crypto.createHash('sha256').update('Welcome to Amazon S3.').digest('hex'),
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: S3_SECRET,
      region: 'us-east-1', service: 's3', date: new Date('2013-05-24T00:00:00Z')
    });
    assert.strictEqual(putObjectVec.signature, '98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd');
    assert.strictEqual(
      deriveSigningKey('wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', '20150830', 'us-east-1', 'iam').toString('hex'),
      'c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9'
    );
    assert.strictEqual(rfc3986("a!b'c(d)e*f"), 'a%21b%27c%28d%29e%2Af');
    assert.strictEqual(canonicalQueryString({ uploadId: 'x', partNumber: '2' }), 'partNumber=2&uploadId=x');

    const r2 = new S3Client({
      endpoint: 'https://abc123.r2.cloudflarestorage.com', region: 'auto', bucket: 'culkibo-backups',
      accessKeyId: 'AKIAEXAMPLE0000', secretAccessKey: 'supersecreto'
    });
    assert.strictEqual(r2.forcePathStyle, true);
    assert.strictEqual(r2.resolve('culkibo/proj/db/dump.sql.gz').canonicalUri, '/culkibo-backups/culkibo/proj/db/dump.sql.gz');
    const aws = new S3Client({
      endpoint: 'https://s3.eu-west-1.amazonaws.com', region: 'eu-west-1', bucket: 'mi-bucket',
      accessKeyId: 'AKIAEXAMPLE0000', secretAccessKey: 'supersecreto'
    });
    assert.strictEqual(aws.forcePathStyle, false);
    assert.strictEqual(aws.resolve('a/b.txt').host, 'mi-bucket.s3.eu-west-1.amazonaws.com');
    assert.ok(!JSON.stringify(r2.describe()).includes('supersecreto'));

    // putObject envía Content-MD5 + x-amz-checksum-sha256 + x-amz-meta-*
    let capturedPutOpts = null;
    r2.request = async (method, keyArg, opts) => {
      capturedPutOpts = { method, keyArg, opts };
      return {
        status: 200,
        headers: { get: (h) => (h.toLowerCase() === 'etag' ? '"etag-1"' : null) },
        text: async () => ''
      };
    };
    const putPayload = Buffer.from('hello-s3-checksum', 'utf8');
    const putRes = await r2.putObject('k/test.ckb1', putPayload, 'application/octet-stream', {
      metadata: { 'culkibo-encrypted': 'true', 'culkibo-engine': 'postgres' }
    });
    assert.strictEqual(capturedPutOpts.opts.headers['x-amz-checksum-sha256'], sha256Base64(putPayload));
    assert.strictEqual(capturedPutOpts.opts.headers['content-md5'], crypto.createHash('md5').update(putPayload).digest('base64'));
    assert.strictEqual(capturedPutOpts.opts.headers['x-amz-meta-culkibo-encrypted'], 'true');
    assert.strictEqual(putRes.checksumSha256, sha256Base64(putPayload));
    await assert.rejects(() => r2.putObject('k', 'x', 'text/plain', { metadata: { 'bad key!': 'v' } }), /Clave de metadato S3 inválida/i);

    // Multipart upload con x-amz-checksum-sha256 por parte + CompleteMultipartUpload XML + Abort en fallo
    const mpClient = new S3Client({
      endpoint: 'https://abc.r2.cloudflarestorage.com', region: 'auto', bucket: 'copias',
      accessKeyId: 'AKIAEXAMPLE0000', secretAccessKey: 's'
    });
    // Forzar umbral pequeño para probar multipart en disco sin escribir >10 MiB
    mpClient.partSizeBytes = 1024;
    const mpFile = path.join(tmpRoot, 'mp_payload.bin');
    fs.writeFileSync(mpFile, crypto.randomBytes(2500)); // 3 partes: 1024 + 1024 + 452
    /** @type {any[]} */
    const mpReqs = [];
    mpClient.request = async (method, keyArg, opts) => {
      mpReqs.push({ method, keyArg, opts });
      if (method === 'POST' && opts.query?.uploads === '') {
        return { status: 200, text: async () => '<InitiateMultipartUploadResult><UploadId>up-99</UploadId></InitiateMultipartUploadResult>' };
      }
      if (method === 'PUT' && opts.query?.partNumber) {
        return {
          status: 200,
          headers: { get: (h) => (h.toLowerCase() === 'etag' ? `"part-${opts.query.partNumber}"` : null) }
        };
      }
      if (method === 'POST' && opts.query?.uploadId === 'up-99') {
        return { status: 200, text: async () => '<CompleteMultipartUploadResult><ETag>"mp-final"</ETag></CompleteMultipartUploadResult>' };
      }
      return { status: 204, text: async () => '' };
    };
    const mpOut = await mpClient.uploadFile('db/mp.ckb1', mpFile, { metadata: { 'culkibo-encrypted': 'true' } });
    assert.strictEqual(mpOut.multipart, true);
    assert.strictEqual(mpOut.parts, 3);
    assert.ok(mpOut.checksumSha256 && mpOut.checksumSha256.endsWith('-3'), 'Debe devolver SHA-256 compuesto AWS (-3)');
    const initReq = mpReqs[0];
    assert.strictEqual(initReq.opts.headers['x-amz-checksum-algorithm'], 'SHA256');
    assert.strictEqual(initReq.opts.headers['x-amz-meta-culkibo-encrypted'], 'true');
    const completeXml = mpReqs[mpReqs.length - 1].opts.body.toString('utf8');
    assert.ok(completeXml.includes('<ChecksumSHA256>'), 'CompleteMultipartUpload debe incluir <ChecksumSHA256> por parte');

    // Fallo a mitad de multipart debe ejecutar AbortMultipartUpload
    let aborted = false;
    mpClient.request = async (method, _k, opts) => {
      if (method === 'POST' && opts.query?.uploads === '') {
        return { status: 200, text: async () => '<InitiateMultipartUploadResult><UploadId>up-fail</UploadId></InitiateMultipartUploadResult>' };
      }
      if (method === 'PUT' && opts.query?.partNumber === '2') throw new Error('Simulated part 2 failure');
      if (method === 'PUT') return { status: 200, headers: { get: () => '"e1"' } };
      if (method === 'DELETE' && opts.query?.uploadId === 'up-fail') { aborted = true; return { status: 204 }; }
      return { status: 200, text: async () => '' };
    };
    await assert.rejects(() => mpClient.uploadFile('db/fail.bin', mpFile), /part 2 failure/i);
    assert.strictEqual(aborted, true, 'Un fallo en UploadPart debe abortar la subida multipart');

    // Complete 200 OK con <Error> detectado
    mpClient.request = async () => ({ status: 200, text: async () => '<Error><Code>InternalError</Code><Message>vaya</Message></Error>' });
    await assert.rejects(mpClient.completeMultipartUpload('k', 'u', [{ partNumber: 1, etag: '"x"' }]), /InternalError/);

    // downloadFile: verifica SHA-256 + rechaza truncamiento y checksum erróneo sin dejar .tmp
    const dlData = Buffer.from('contenido-descarga-verificada-123456', 'utf8');
    const dlHex = crypto.createHash('sha256').update(dlData).digest('hex');
    const dlB64 = sha256Base64(dlData);
    const dlDest = path.join(tmpRoot, 'dl_ok.bin');
    mpClient.request = async () => ({
      status: 200,
      headers: {
        get: (h) => ({ 'content-length': String(dlData.length), 'x-amz-checksum-sha256': dlB64 }[h.toLowerCase()] || null)
      },
      body: makeWebStream([dlData.subarray(0, 10), dlData.subarray(10)])
    });
    const dlOk = await mpClient.downloadFile('k', dlDest, { expectedSha256Hex: dlHex });
    assert.strictEqual(dlOk.sha256, dlHex);
    assert.deepStrictEqual(fs.readFileSync(dlDest), dlData);

    // Descarga truncada -> rechazada
    const dlTrunc = path.join(tmpRoot, 'dl_trunc.bin');
    mpClient.request = async () => ({
      status: 200,
      headers: { get: (h) => (h.toLowerCase() === 'content-length' ? '999' : null) },
      body: makeWebStream([Buffer.from('short')])
    });
    await assert.rejects(() => mpClient.downloadFile('k', dlTrunc), /truncada/i);
    assert.ok(!fs.existsSync(dlTrunc));

    // x-amz-checksum-sha256 no coincide -> rechazada
    const dlBadCs = path.join(tmpRoot, 'dl_badcs.bin');
    mpClient.request = async () => ({
      status: 200,
      headers: { get: (h) => ({ 'content-length': String(dlData.length), 'x-amz-checksum-sha256': sha256Base64('other') }[h.toLowerCase()] || null) },
      body: makeWebStream([dlData])
    });
    await assert.rejects(() => mpClient.downloadFile('k', dlBadCs), /x-amz-checksum-sha256/i);

    // listObjectsV2: unescape XML + orden inverso cronológico
    mpClient.request = async () => ({
      status: 200,
      text: async () =>
        '<ListBucketResult><IsTruncated>false</IsTruncated>' +
        '<Contents><Key>a&amp;old.gz</Key><Size>10</Size><LastModified>2026-01-01T00:00:00Z</LastModified><ETag>&quot;1&quot;</ETag></Contents>' +
        '<Contents><Key>b_new.gz</Key><Size>20</Size><LastModified>2026-09-01T00:00:00Z</LastModified><ETag>&quot;2&quot;</ETag></Contents>' +
        '</ListBucketResult>'
    });
    const listRes = await mpClient.listObjectsV2('culkibo/');
    assert.strictEqual(listRes.objects[0].key, 'b_new.gz', 'Debe ordenar del más reciente al más antiguo');
    assert.strictEqual(listRes.objects[1].key, 'a&old.gz', 'Debe decodificar entidades XML');

    // buildLifecycleXml + putBucketLifecycle
    const lcXml = buildLifecycleXml([
      {
        id: 'culkibo-db-retention',
        prefix: 'culkibo/',
        expirationDays: 90,
        abortIncompleteMultipartUploadDays: 3,
        transitions: [{ days: 30, storageClass: 'GLACIER' }]
      }
    ]);
    assert.ok(lcXml.includes('<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'));
    assert.ok(lcXml.includes('<Expiration><Days>90</Days></Expiration>'));
    assert.ok(lcXml.includes('<DaysAfterInitiation>3</DaysAfterInitiation>'));
    assert.ok(lcXml.includes('<StorageClass>GLACIER</StorageClass>'));
    assert.throws(() => buildLifecycleXml([]), /entre 1 y 100/i);
    assert.throws(() => buildLifecycleXml([{ id: 'r1', expirationDays: 0 }]), /inválido/i);
    assert.throws(() => buildLifecycleXml([{ id: 'r1', transitions: [{ days: 10, storageClass: 'INVALID' }] }]), /no permitido/i);
    let capturedLc = null;
    mpClient.request = async (method, _k, opts) => { capturedLc = { method, opts }; return { status: 200 }; };
    const lcOut = await mpClient.putBucketLifecycle([{ id: 'abort-mp', abortIncompleteMultipartUploadDays: 7 }]);
    assert.strictEqual(lcOut.applied, true);
    assert.strictEqual(capturedLc.opts.query.lifecycle, '');
    assert.ok(capturedLc.opts.headers['content-md5'] && capturedLc.opts.headers['x-amz-checksum-sha256']);
    console.log('  ✓ SigV4 + S3: x-amz-checksum-sha256, x-amz-meta-*, multipart+abort, download verify y lifecycle XML');

    // =========================================================================
    // 5. Cifrado Streaming AES-256-GCM por Bloques (CKB1) + 6 ataques de manipulación + Rotación de Key-ID
    // =========================================================================
    const encDir = path.join(tmpRoot, 'ckb1');
    fs.mkdirSync(encDir, { recursive: true });
    const plainSrc = path.join(encDir, 'sample.sql.gz');
    const rawSampleData = crypto.randomBytes(4096 * 12 + 333); // >12 bloques de 4 KiB
    fs.writeFileSync(plainSrc, rawSampleData);

    const keyA = crypto.randomBytes(32);
    const keyB = crypto.randomBytes(32);
    const encFile = path.join(encDir, 'sample.sql.gz.ckb1');
    const encMeta = await encryptBackupFile(plainSrc, encFile, keyA, { chunkSize: 4096 });
    assert.strictEqual(encMeta.format, 'CKB1');
    assert.strictEqual(encMeta.chunks, 13);
    assert.strictEqual(encMeta.keyId, computeKeyId(keyA));
    assert.strictEqual(hasCkb1Magic(encFile), true);
    assert.strictEqual(inspectCkb1Header(encFile).keyId, computeKeyId(keyA));
    assert.ok(!fs.readFileSync(encFile).includes(rawSampleData.subarray(0, 64)), 'El texto plano no aparece en el cifrado');

    // Descifrado legítimo byte a byte
    const decOk = path.join(encDir, 'dec_ok.bin');
    const decMeta = await decryptBackupFile(encFile, decOk, keyA);
    assert.strictEqual(decMeta.chunks, 13);
    assert.deepStrictEqual(fs.readFileSync(decOk), rawSampleData);

    // Ataque 1: Clave equivocada -> falla y NO deja fichero de salida
    const decWrong = path.join(encDir, 'dec_wrong.bin');
    await assert.rejects(() => decryptBackupFile(encFile, decWrong, keyB), /no encontrada/i);
    assert.ok(!fs.existsSync(decWrong));

    // Ataque 2: Bit-flip en ciphertext -> falla authTag GCM y borra destino
    const flippedCt = path.join(encDir, 'tamper_ct.ckb1');
    const ctBytes = Buffer.from(fs.readFileSync(encFile));
    ctBytes[32 + 5 + 20] ^= 0x01;
    fs.writeFileSync(flippedCt, ctBytes);
    const decFlip = path.join(encDir, 'dec_flip.bin');
    await assert.rejects(() => decryptBackupFile(flippedCt, decFlip, keyA), /autenticación AES-256-GCM/i);
    assert.ok(!fs.existsSync(decFlip));

    // Ataque 3: Bit-flip en authTag -> falla GCM
    const flippedTag = path.join(encDir, 'tamper_tag.ckb1');
    const tagBytes = Buffer.from(fs.readFileSync(encFile));
    tagBytes[32 + 5 + 4096 + 3] ^= 0x80;
    fs.writeFileSync(flippedTag, tagBytes);
    await assert.rejects(() => decryptBackupFile(flippedTag, path.join(encDir, 'd3.bin'), keyA), /autenticación AES-256-GCM/i);

    // Ataque 4: Reordenamiento de bloques (intercambiar chunk 0 y chunk 1) -> bloqueado por AAD chunkIndex!
    const swappedFile = path.join(encDir, 'tamper_swap.ckb1');
    const origBuf = fs.readFileSync(encFile);
    const frameLen = 5 + 4096 + 16;
    const swapped = Buffer.concat([
      origBuf.subarray(0, 32),
      origBuf.subarray(32 + frameLen, 32 + frameLen * 2),
      origBuf.subarray(32, 32 + frameLen),
      origBuf.subarray(32 + frameLen * 2)
    ]);
    fs.writeFileSync(swappedFile, swapped);
    await assert.rejects(() => decryptBackupFile(swappedFile, path.join(encDir, 'd4.bin'), keyA), /autenticación AES-256-GCM/i);

    // Ataque 5: Truncamiento (quitar último bloque final) -> bloqueado!
    const truncFile = path.join(encDir, 'tamper_trunc.ckb1');
    fs.writeFileSync(truncFile, origBuf.subarray(0, 32 + frameLen * 2));
    await assert.rejects(() => decryptBackupFile(truncFile, path.join(encDir, 'd5.bin'), keyA), /bloque final/i);

    // Ataque 6: Basura añadida tras el bloque final -> bloqueado!
    const trailingFile = path.join(encDir, 'tamper_trail.ckb1');
    fs.writeFileSync(trailingFile, Buffer.concat([origBuf, Buffer.from('EXTRA')]));
    await assert.rejects(() => decryptBackupFile(trailingFile, path.join(encDir, 'd6.bin'), keyA), /sobrantes/i);

    // Derivación por passphrase + rotación de claves en anillo
    assert.throws(() => deriveBackupKeyFromPassphrase('too-short'), /12 caracteres/i);
    const cfgEnc1 = dm.setBackupEncryption({ enabled: true, passphrase: 'mi-clave-maestra-ultra-segura-1' });
    assert.strictEqual(cfgEnc1.enabled, true);
    assert.strictEqual(cfgEnc1.keyCount, 1);
    const keyId1 = cfgEnc1.activeKeyId;
    const encWith1 = path.join(encDir, 'rot1.ckb1');
    await encryptBackupFile(plainSrc, encWith1, dm._getActiveBackupKey().key, { chunkSize: 4096 });

    const rot = dm.rotateBackupEncryptionKey({ passphrase: 'mi-nueva-clave-rotada-segura-2' });
    assert.strictEqual(rot.previousKeyId, keyId1);
    assert.notStrictEqual(rot.activeKeyId, keyId1);
    assert.strictEqual(rot.keyCount, 2);
    const encWith2 = path.join(encDir, 'rot2.ckb1');
    await encryptBackupFile(plainSrc, encWith2, dm._getActiveBackupKey().key, { chunkSize: 4096 });

    // El anillo descifra TANTO la copia antigua (keyId1 retirada) COMO la nueva (keyId2 activa)
    const ring = dm._getBackupKeyRing();
    await decryptBackupFile(encWith1, path.join(encDir, 'rot1.out'), ring);
    await decryptBackupFile(encWith2, path.join(encDir, 'rot2.out'), ring);
    assert.deepStrictEqual(fs.readFileSync(path.join(encDir, 'rot1.out')), rawSampleData);
    assert.deepStrictEqual(fs.readFileSync(path.join(encDir, 'rot2.out')), rawSampleData);
    assert.ok(!fs.readFileSync(dm.dataFile, 'utf8').includes(dm._getActiveBackupKey().key.toString('hex')));
    dm.setBackupEncryption({ enabled: false });
    console.log('  ✓ CKB1 AEAD streaming: 13 bloques, 6 ataques (wrong-key/bit-flip/tag/reorder/truncate/trailing) + rotación Key-ID');

    // =========================================================================
    // 6. Presets de Tuning por RAM/CPU + PgBouncer Pooler
    // =========================================================================
    const pgOltp = computeTuningConfig('postgres', { memoryMb: 2048, cpus: 2, preset: 'oltp' });
    assert.strictEqual(pgOltp.params.sharedBuffersMb, 512);
    assert.ok(pgOltp.commandArgs.includes('shared_buffers=512MB'));
    assert.ok(pgOltp.commandArgs.includes('wal_compression=on'));

    const pgAna = computeTuningConfig('pgvector', { memoryMb: 4096, cpus: 4, preset: 'analytics' });
    assert.ok(pgAna.params.workMemMb > pgOltp.params.workMemMb);

    const myLow = computeTuningConfig('mysql', { memoryMb: 1024, preset: 'low-memory' });
    assert.ok(myLow.commandArgs.some((a) => a.startsWith('--innodb-buffer-pool-size=')));

    const vkCache = computeTuningConfig('valkey', { memoryMb: 1024, preset: 'cache' });
    assert.strictEqual(vkCache.params.evictionPolicy, 'allkeys-lru');
    assert.ok(vkCache.params.maxMemoryMb < 1024, 'Valkey deja margen anti-OOM para BGSAVE');

    const dfCache = computeTuningConfig('dragonfly', { memoryMb: 1024, cpus: 4, preset: 'cache' });
    assert.ok(dfCache.commandArgs.includes('--cache_mode=true'));
    assert.ok(dfCache.commandArgs.includes('--proactor_threads=4'));

    const mongoT = computeTuningConfig('mongodb', { memoryMb: 2048, preset: 'oltp' });
    assert.ok(mongoT.commandArgs.includes('--wiredTigerCacheSizeGB'));

    const meiliT = computeTuningConfig('meilisearch', { memoryMb: 1024, cpus: 2, preset: 'oltp' });
    assert.ok(meiliT.env.MEILI_MAX_INDEXING_MEMORY);

    assert.throws(() => computeTuningConfig('postgres', { preset: 'turbo-magic' }), /Preset de tuning inválido/i);
    console.log('  ✓ Tuning RAM/CPU: presets oltp/analytics/low-memory/cache verificados en todos los motores');

    // =========================================================================
    // 7. Planificador cron + Retención GFS (horaria/diaria/semanal/pinned/pre-restore/S3-pending-delete)
    // =========================================================================
    const from = new Date('2026-09-15T10:07:30');
    const cronCases = [
      ['0 3 * * *', '2026-09-16T03:00:00'],
      ['*/15 * * * *', '2026-09-15T10:15:00'],
      ['0 0 1 * *', '2026-10-01T00:00:00'],
      ['30 2 * * 1', '2026-09-21T02:30:00'],
      ['0 1,13 * * *', '2026-09-15T13:00:00'],
      ['@hourly', '2026-09-15T11:00:00'],
      ['@weekly', '2026-09-20T04:00:00']
    ];
    for (const [expr, expected] of cronCases) {
      const next = dm.nextCronRun(expr, from);
      assert.ok(next);
      const iso = new Date(next.getTime() - next.getTimezoneOffset() * 60000).toISOString().slice(0, 19);
      assert.strictEqual(iso, expected);
    }
    assert.strictEqual(dm.nextCronRun('0 4 * * 7', from).getTime(), dm.nextCronRun('0 4 * * 0', from).getTime());
    for (const bad of ['', 'diario', '* * *', '99 * * * *', '* 25 * * *', '0 0 32 * *', '*/0 * * * *', '0 0 * * 9']) {
      assert.throws(() => dm.parseCron(bad));
    }

    const now = new Date('2026-09-15T04:00:00Z');
    const history = [];
    for (let i = 0; i < 60; i++) {
      history.push({ id: `b${i}`, createdAt: new Date(now.getTime() - i * 24 * 3600 * 1000).toISOString() });
    }
    const gfsPlan = dm.planRetention(history, { daily: 7, weekly: 4 });
    assert.ok(gfsPlan.keep.includes('b0'));
    assert.strictEqual(gfsPlan.keep.length + gfsPlan.prune.length, history.length);
    assert.deepStrictEqual(dm.planRetention(history, { daily: 0, weekly: 0 }).keep, ['b0']);
    // Pinned y top-3 pre-restore siempre protegidos
    const protectedSet = [
      { id: 'newest', createdAt: '2026-09-15T04:00:00Z' },
      { id: 'pin1', createdAt: '2025-01-01T00:00:00Z', pinned: true },
      { id: 'pre1', createdAt: '2025-02-04T00:00:00Z', trigger: 'pre-restore' },
      { id: 'pre2', createdAt: '2025-02-03T00:00:00Z', trigger: 'pre-restore' },
      { id: 'pre3', createdAt: '2025-02-02T00:00:00Z', trigger: 'pre-restore' },
      { id: 'pre4', createdAt: '2025-02-01T00:00:00Z', trigger: 'pre-restore' }
    ];
    const protPlan = dm.planRetention(protectedSet, { daily: 1, weekly: 0 });
    assert.ok(protPlan.keep.includes('pin1') && protPlan.keep.includes('pre1') && protPlan.keep.includes('pre3'));
    assert.ok(protPlan.prune.includes('pre4'), 'Sólo las 3 instantáneas pre-restore más recientes se protegen automáticamente');
    console.log('  ✓ Cron + Retención GFS: horarios exactos, pinned y protección top-3 pre-restore');

    // =========================================================================
    // 8. Seguridad SQL, sanitizador MySQL y bomba Gzip (offline determinista)
    // =========================================================================
    const secDir = path.join(tmpRoot, 'sql-sec');
    fs.mkdirSync(secDir, { recursive: true });
    for (const [fam, badSql] of [
      ['postgresql', 'SELECT 1;\n\\! rm -rf /\n'],
      ['postgresql', 'SELECT 1 \\gexec\n'],
      ['postgresql', 'SELECT 1;\n\\o | id\n'],
      ['postgresql', "COPY t FROM PROGRAM 'id';\n"],
      ['mysql', 'SELECT 1;\nsystem id;\n'],
      ['mysql', 'source /etc/passwd;\n'],
      ['mariadb', '\\! whoami\n']
    ]) {
      const f = path.join(secDir, `bad_${crypto.randomBytes(3).toString('hex')}.sql`);
      fs.writeFileSync(f, badSql, 'utf8');
      await assert.rejects(() => dm.assertSafeSqlFile(f, fam), /rechazado por seguridad/i, `Debe bloquear ${fam}: ${badSql}`);
    }

    // sanitizeMysqlSqlFile elimina BOM, USE, CREATE DATABASE y GTID_PURGED
    const dirtyMysql = path.join(secDir, 'dirty_mysql.sql');
    const cleanMysql = path.join(secDir, 'clean_mysql.sql');
    fs.writeFileSync(dirtyMysql,
      '\uFEFFCREATE DATABASE `other`;\nUSE `other`;\nSET @@GLOBAL.GTID_PURGED="uuid:1-5";\nCREATE TABLE users (id INT);\nINSERT INTO users VALUES (1);\n',
      'utf8'
    );
    await dm.sanitizeMysqlSqlFile(dirtyMysql, cleanMysql);
    const cleaned = fs.readFileSync(cleanMysql, 'utf8');
    assert.ok(!cleaned.includes('USE `other`'));
    assert.ok(!cleaned.includes('CREATE DATABASE'));
    assert.ok(!cleaned.includes('GTID_PURGED'));
    assert.ok(cleaned.includes('CREATE TABLE users (id INT);'));

    // gunzipFile: protección anti-bomba gzip (maxBytes)
    const bombGz = path.join(secDir, 'bomb.gz');
    fs.writeFileSync(bombGz, zlib.gzipSync(Buffer.alloc(200 * 1024, 0x41)));
    const bombOut = path.join(secDir, 'bomb.out');
    await assert.rejects(() => dm.gunzipFile(bombGz, bombOut, 32 * 1024), /límite seguro/i);
    assert.ok(!fs.existsSync(bombOut), 'Tras abortar bomba gzip no debe quedar archivo parcial');
    console.log('  ✓ Seguridad SQL/Gzip: 7 payloads meta-comandos bloqueados, sanitizador MySQL/GTID y anti-bomba gzip');

    // =========================================================================
    // 9. Ciclo Mock-Docker Completo: 12 motores, 0 secretos en argv, PgBouncer,
    //    runBackup cifrado CKB1 -> S3, verifyBackup, runRestoreDrill, restore,
    //    cloneDatabase, 409 lock, watchdog SLA y notificaciones!
    // =========================================================================
    const invocations = [];
    const capturedEnvFiles = new Map();
    const mockContainerFiles = new Map(); // `${container}:${path}` -> Buffer
    let failNextDockerCpOnRedis = false;

    dm.isDockerAvailable = async () => true;
    dm.docker = async (args, opts = {}) => {
      invocations.push({ args, opts });

      const envIdx = args.indexOf('--env-file');
      if (envIdx !== -1) {
        const ef = args[envIdx + 1];
        capturedEnvFiles.set(args[args.indexOf('--name') + 1], {
          path: ef,
          content: fs.readFileSync(ef, 'utf8'),
          mode: fs.statSync(ef).mode & 0o777
        });
      }

      if (args[0] === 'network' && args[1] === 'inspect') throw new Error('not found');

      // Simular volcados dentro del contenedor
      if (args[0] === 'exec') {
        const container = args[1] === '-i' ? args[2] : args[1];
        const joined = args.join(' ');
        // pg_dump
        const fIdx = args.indexOf('-f');
        if (args.includes('pg_dump') && fIdx !== -1) {
          mockContainerFiles.set(`${container}:${args[fIdx + 1]}`, Buffer.concat([Buffer.from('PGDMP'), Buffer.from('mock-pg-custom-dump-payload')]));
          return { stdout: '', stderr: '' };
        }
        // mysqldump / mariadb-dump
        const rfArg = args.find((a) => String(a).startsWith('--result-file='));
        if (rfArg) {
          const outFile = rfArg.slice('--result-file='.length);
          mockContainerFiles.set(`${container}:${outFile}`, Buffer.from('CREATE TABLE t (id INT);\nINSERT INTO t VALUES (42);\n', 'utf8'));
          return { stdout: '', stderr: '' };
        }
        // redis-cli / valkey-cli --rdb
        const rdbIdx = args.indexOf('--rdb');
        if (rdbIdx !== -1) {
          mockContainerFiles.set(`${container}:${args[rdbIdx + 1]}`, Buffer.from('REDIS0011mock-rdb-data', 'ascii'));
          return { stdout: '', stderr: '' };
        }
        // mongodump --archive=...
        const archArg = args.find((a) => String(a).startsWith('--archive='));
        if (args.includes('mongodump') && archArg) {
          mockContainerFiles.set(`${container}:${archArg.slice('--archive='.length)}`, zlib.gzipSync(Buffer.from('mock-mongo-archive')));
          return { stdout: '', stderr: '' };
        }
        // clickhouse-client BACKUP DATABASE ... TO File('...')
        const chQIdx = args.indexOf('--query');
        if (args.includes('clickhouse-client') && chQIdx !== -1) {
          const m = /TO File\('([^']+)'\)/.exec(args[chQIdx + 1] || '');
          if (m) {
            mockContainerFiles.set(`${container}:${m[1]}`, Buffer.from('PK\x03\x04mock-clickhouse-zip'));
            return { stdout: '', stderr: '' };
          }
        }
        // curl -o <file> (Qdrant / Meilisearch)
        const oIdx = args.indexOf('-o');
        if (args.includes('curl') && oIdx !== -1) {
          mockContainerFiles.set(`${container}:${args[oIdx + 1]}`, Buffer.from('{"status":"ok","snapshot":"v1"}'));
          return { stdout: '', stderr: '' };
        }
        // Sondas de drill (conteo de tablas/claves)
        if (joined.includes('information_schema.tables')) return { stdout: '7\n', stderr: '' };
        if (args.includes('DBSIZE')) return { stdout: '(integer) 12\n', stderr: '' };
        return { stdout: 'ok\n', stderr: '' };
      }

      // Simular docker cp (host -> container y container -> host)
      if (args[0] === 'cp') {
        const [, src, dst] = args;
        if (failNextDockerCpOnRedis && dst.endsWith('dump.rdb')) {
          failNextDockerCpOnRedis = false;
          throw new Error('Simulated docker cp failure on dump.rdb');
        }
        if (src.includes(':') && !path.isAbsolute(src)) {
          const buf = mockContainerFiles.get(src);
          if (!buf) throw new Error(`Mock file not found in container: ${src}`);
          fs.writeFileSync(dst, buf);
        } else if (dst.includes(':')) {
          mockContainerFiles.set(dst, fs.readFileSync(src));
        }
        return { stdout: '', stderr: '' };
      }

      return { stdout: 'c0ffee1234567890\n', stderr: '' };
    };

    // 9a. Aprovisionar TODOS los 12 motores -> 0 secretos en argv, 0 puertos, --env-file 0600 efímero
    /** @type {Record<string, any>} */
    const provisioned = {};
    for (const engineKey of expectedEngines) {
      const prevLen = invocations.length;
      const created = await dm.provision({
        projectId: 'proj_all12',
        engine: engineKey,
        name: `Test ${engineKey}`,
        dbName: ENGINES[engineKey].noDatabaseName ? undefined : 'tienda',
        username: 'tendero',
        memoryMb: 1024,
        cpus: 2
      });
      provisioned[engineKey] = created;
      const rec = dm.mustGet(created.id);
      const pw = dm.decryptPassword(rec);
      const newInvocs = invocations.slice(prevLen);
      for (const inv of newInvocs) {
        for (const arg of inv.args) {
          assert.ok(!String(arg).includes(pw), `Secreto de ${engineKey} filtrado en argv!`);
        }
      }
      const runCall = newInvocs.find((i) => i.args[0] === 'run');
      assert.ok(runCall, `${engineKey}: falta docker run`);
      assert.ok(!runCall.args.includes('-e'), `${engineKey}: nunca -e`);
      assert.ok(!runCall.args.includes('-p') && !runCall.args.includes('--publish'), `${engineKey}: nunca expuesto al crear`);
      assert.ok(runCall.args.includes('--security-opt') && runCall.args.includes('no-new-privileges'));
      const ef = capturedEnvFiles.get(rec.containerName);
      assert.ok(ef && ef.content.includes(pw) && !fs.existsSync(ef.path), `${engineKey}: --env-file efímero faltante o no borrado`);
    }
    // Verificar redacción en listado y disco
    const pgRec = dm.mustGet(provisioned.postgres.id);
    const pgPw = dm.decryptPassword(pgRec);
    assert.ok(!JSON.stringify(dm.list({ projectId: 'proj_all12' })).includes(pgPw));
    assert.ok(!fs.readFileSync(dm.dataFile, 'utf8').includes(pgPw));
    assert.strictEqual(dm.getCredentials(pgRec.id).password, pgPw);
    console.log('  ✓ Aprovisionamiento 12/12 motores: 0 secretos en argv, --env-file 0600 efímero, tuning aplicado y 0 puertos');

    // 9b. setTuning + PgBouncer pooler
    const tuned = await dm.setTuning(pgRec.id, { preset: 'analytics', memoryMb: 2048, cpus: 4 });
    assert.strictEqual(tuned.tuning.preset, 'analytics');
    assert.strictEqual(tuned.memoryMb, 2048);

    const pooled = await dm.configurePooler(pgRec.id, { enabled: true, poolMode: 'transaction', maxClientConn: 400, defaultPoolSize: 25 });
    assert.strictEqual(pooled.pooler.enabled, true);
    assert.strictEqual(pooled.pooler.port, 6432);
    assert.strictEqual(pooled.pooler.image, PGBOUNCER_IMAGE);
    assert.ok(pooled.pooledConnectionTemplate.includes('6432') && pooled.pooledConnectionTemplate.includes('********'));
    const pooledCreds = dm.getCredentials(pgRec.id);
    assert.ok(pooledCreds.pooledConnectionString.includes(`:${pgPw}@culkibo_pooler_${pgRec.id}:6432/tienda`));
    // Verificar que el docker run de PgBouncer no filtró la contraseña en argv
    const poolerRun = invocations.find((i) => i.args[0] === 'run' && i.args.includes(PGBOUNCER_IMAGE));
    assert.ok(poolerRun && !poolerRun.args.join(' ').includes(pgPw));
    // Motor no-PG rechaza PgBouncer
    await assert.rejects(() => dm.configurePooler(provisioned.valkey.id, { enabled: true }), /no soporta pooler/i);
    console.log('  ✓ setTuning + PgBouncer co-localizado: puerto 6432, transaction pooling, 0 secretos en argv');

    // 9c. Exposición opt-in con aviso UFW
    await assert.rejects(dm.setExposure(pgRec.id, { enabled: true, bindAddress: '0.0.0.0', hostPort: 5432 }), /acknowledgeRisk/);
    await assert.rejects(dm.setExposure(pgRec.id, { enabled: true, bindAddress: 'todas' }), /inválida/);
    const testPort = await new Promise((resolve, reject) => {
      const net = require('net');
      const s = net.createServer();
      s.once('error', reject);
      s.listen(0, '127.0.0.1', () => {
        const addr = s.address();
        const p = typeof addr === 'object' && addr ? addr.port : 55432;
        s.close(() => resolve(p));
      });
    });
    const expLocal = await dm.setExposure(pgRec.id, { enabled: true, hostPort: testPort });
    assert.strictEqual(expLocal.exposure.bindAddress, '127.0.0.1');
    const expOpen = await dm.setExposure(pgRec.id, { enabled: true, bindAddress: '0.0.0.0', hostPort: testPort, acknowledgeRisk: true });
    assert.ok(/UFW/.test(expOpen.warning));
    await dm.setExposure(pgRec.id, { enabled: false });

    // 9d. S3 anti-exfiltración (Dokploy GHSA-7f32-g5xc-mqr7) + runBackup cifrado CKB1 -> S3 mock + todos los motores
    dm.setS3Config({
      endpoint: 'https://cuenta.r2.cloudflarestorage.com', region: 'auto', bucket: 'culkibo-copias',
      accessKeyId: 'AKIAEXAMPLE0000', secretAccessKey: 'clave-ultra-secreta', prefix: 'culkibo/'
    });
    assert.throws(
      () => dm.setS3Config({ endpoint: 'https://evil.attacker.com', bucket: 'culkibo-copias', accessKeyId: 'AKIA****0000', secretAccessKey: '********' }),
      /volver a introducir Access Key y Secret Key/i
    );
    // Cambiar sólo el prefijo con credenciales enmascaradas sí está permitido
    const updatedPrefix = dm.setS3Config({ prefix: 'prod-backups/' });
    assert.strictEqual(updatedPrefix.prefix, 'prod-backups/');

    // Mock S3 en memoria para probar subida cifrada CKB1, HEAD en verifyBackup y descarga en restore
    /** @type {Map<string, { buf: Buffer, metadata: Record<string, string>, checksumSha256: string }>} */
    const s3Store = new Map();
    let forceNextS3Failure = false;
    const origS3ClientFor = dm.s3ClientFor.bind(dm);
    dm.s3ClientFor = () => {
      if (!dm.state.s3) return null;
      return {
        accessKeyId: dm.state.s3.accessKeyId,
        secretAccessKey: 'clave-ultra-secreta',
        async uploadFile(keyArg, filePath, opts = {}) {
          if (forceNextS3Failure) {
            forceNextS3Failure = false;
            throw new Error('S3 503 with secret clave-ultra-secreta');
          }
          const buf = fs.readFileSync(filePath);
          const cs = sha256Base64(buf);
          s3Store.set(keyArg, { buf, metadata: opts.metadata || {}, checksumSha256: cs });
          return { key: keyArg, etag: '"mock-etag"', multipart: false, checksumSha256: cs };
        },
        async headObject(keyArg) {
          const obj = s3Store.get(keyArg);
          if (!obj) return null;
          return { key: keyArg, sizeBytes: obj.buf.length, etag: '"mock-etag"', checksumSha256: obj.checksumSha256, metadata: obj.metadata };
        },
        async downloadFile(keyArg, destPath, opts = {}) {
          const obj = s3Store.get(keyArg);
          if (!obj) throw new Error('NoSuchKey');
          const hex = crypto.createHash('sha256').update(obj.buf).digest('hex');
          if (opts.expectedSha256Hex && hex !== opts.expectedSha256Hex) throw new Error('SHA mismatch');
          fs.writeFileSync(destPath, obj.buf);
          return { key: keyArg, destPath, sizeBytes: obj.buf.length, sha256: hex };
        },
        async deleteObject(keyArg) {
          if (forceNextS3Failure) {
            forceNextS3Failure = false;
            throw new Error('S3 delete denied');
          }
          s3Store.delete(keyArg);
          return { key: keyArg, deleted: true };
        }
      };
    };

    // Activar cifrado CKB1 y ejecutar runBackup en PostgreSQL
    dm.setBackupEncryption({ enabled: true });
    const pgBackup = await dm.runBackup(pgRec.id, { trigger: 'manual' });
    assert.strictEqual(pgBackup.success, true);
    assert.strictEqual(pgBackup.backup.encrypted, true);
    assert.ok(pgBackup.backup.fileName.endsWith('.dump.gz.ckb1'));
    assert.ok(pgBackup.remote && s3Store.has(pgBackup.remote));
    const s3UploadedObj = s3Store.get(pgBackup.remote);
    assert.strictEqual(s3UploadedObj.metadata['culkibo-encrypted'], 'true');
    assert.strictEqual(s3UploadedObj.metadata['culkibo-key-id'], pgBackup.backup.encryption.keyId);
    assert.ok(s3UploadedObj.buf.subarray(0, 4).toString('ascii') === 'CKB1', 'S3 debe almacenar sólo ciphertext CKB1');
    assert.ok(!s3UploadedObj.buf.includes(Buffer.from('PGDMP')), 'El texto plano PGDMP jamás puede llegar a S3');

    // runBackup en MySQL (sin duplicar --set-gtid-purged=OFF), MariaDB (mariadb-dump), MongoDB, ClickHouse, Qdrant, Meilisearch, Valkey
    for (const eng of ['mysql', 'mariadb', 'mongodb', 'clickhouse', 'qdrant', 'meilisearch', 'valkey', 'dragonfly']) {
      const r = dm.mustGet(provisioned[eng].id);
      const pw = dm.decryptPassword(r);
      const before = invocations.length;
      const bRes = await dm.runBackup(r.id, { trigger: 'manual', skipS3: true });
      assert.strictEqual(bRes.success, true, `runBackup(${eng}) falló`);
      const execCall = invocations.slice(before).find((i) => i.args[0] === 'exec' && !i.args.includes('rm'));
      assert.ok(execCall, `runBackup(${eng}) debe ejecutar docker exec`);
      assert.ok(!execCall.args.join(' ').includes(pw), `runBackup(${eng}) filtró contraseña en argv!`);
      if (eng === 'mysql') {
        const gtidCount = execCall.args.filter((a) => a === '--set-gtid-purged=OFF').length;
        assert.strictEqual(gtidCount, 1, 'MySQL no debe duplicar --set-gtid-purged=OFF');
      }
      if (eng === 'mariadb') {
        assert.ok(execCall.args.includes('mariadb-dump'), 'MariaDB debe usar mariadb-dump');
      }
    }

    // Fallo de S3 -> conserva copia local, redacta secreto S3 y dispara notificación backup_failed
    sentNotifications.length = 0;
    forceNextS3Failure = true;
    const s3FailBk = await dm.runBackup(pgRec.id, { trigger: 'scheduled' });
    assert.strictEqual(s3FailBk.success, true);
    assert.ok(s3FailBk.remoteError && !s3FailBk.remoteError.includes('clave-ultra-secreta'));
    assert.strictEqual(pgRec.schedule.lastStatus, 'local-only');
    assert.ok(sentNotifications.some((n) => n.event === 'backup_failed' && n.level === 'warning'));

    // Conflicto 409 cuando _activeOps está ocupado
    dm._activeOps.set(pgRec.id, { kind: 'restore', startedAt: Date.now() });
    await assert.rejects(
      () => dm.runBackup(pgRec.id),
      (err) => err && err.status === 409 && /en curso/i.test(err.message)
    );
    dm._activeOps.delete(pgRec.id);
    console.log('  ✓ runBackup cifrado CKB1->S3, 0 secretos en argv en 9 motores, S3 fallback + notificación y bloqueo 409');

    // 9e. verifyBackup() (éxito + detección de manipulación local y remota S3)
    const verOk = await dm.verifyBackup(pgRec.id, pgBackup.backup.id, { checkRemote: true });
    assert.strictEqual(verOk.ok, true);
    assert.strictEqual(verOk.checks.sha256, true);
    assert.strictEqual(verOk.checks.aead.ok, true);
    assert.strictEqual(verOk.checks.gzip, true);
    assert.strictEqual(verOk.checks.format, 'pg-custom-PGDMP');
    assert.strictEqual(verOk.checks.remoteHead.ok, true);
    assert.ok(dm.listVerificationHistory(pgRec.id).length >= 1);

    // Simular corrupción de 1 byte en S3 (desajuste de tamaño HEAD) -> verifyBackup devuelve ok:false y notifica!
    sentNotifications.length = 0;
    const origRemoteBuf = s3Store.get(pgBackup.remote).buf;
    s3Store.get(pgBackup.remote).buf = Buffer.concat([origRemoteBuf, Buffer.from('X')]);
    const verBadS3 = await dm.verifyBackup(pgRec.id, pgBackup.backup.id, { checkRemote: true });
    assert.strictEqual(verBadS3.ok, false);
    assert.match(verBadS3.error, /Tamaño remoto S3/i);
    assert.ok(sentNotifications.some((n) => n.event === 'backup_failed' && /Verificación/i.test(n.title)));
    s3Store.get(pgBackup.remote).buf = origRemoteBuf;

    // 9f. runRestoreDrill(): contenedor efímero --network none, consulta real, limpieza obligatoria + audit log
    const beforeDrill = invocations.length;
    const drillRes = await dm.runRestoreDrill(pgRec.id, { backupId: pgBackup.backup.id });
    assert.strictEqual(drillRes.ok, true);
    assert.strictEqual(drillRes.objectCount, 7);
    const drillCalls = invocations.slice(beforeDrill);
    const drillRun = drillCalls.find((c) => c.args[0] === 'run' && c.args.includes('culkibo.role=restore-drill'));
    assert.ok(drillRun, 'El simulacro debe crear un contenedor efímero etiquetado restore-drill');
    assert.ok(drillRun.args.includes('--network') && drillRun.args[drillRun.args.indexOf('--network') + 1] === 'none');
    assert.ok(!drillRun.args.includes('-p'));
    const drillRm = drillCalls.find((c) => c.args[0] === 'rm' && c.args.includes('-f'));
    assert.ok(drillRm, 'El simulacro debe destruir siempre el contenedor efímero al terminar');
    assert.ok(dm.listRestoreHistory(pgRec.id).some((h) => h.kind === 'drill' && h.status === 'ok'));
    console.log('  ✓ verifyBackup (SHA-256+AEAD+gzip+PGDMP+S3 HEAD) y runRestoreDrill (--network none + cleanup + audit)');

    // 9g. restore() cifrado CKB1: éxito + rechazo pre-restore ante manipulación AEAD + historial persistido
    const restOk = await dm.restore(pgRec.id, { backupId: pgBackup.backup.id, createSafetySnapshot: false });
    assert.strictEqual(restOk.success, true);
    assert.ok(dm.listRestoreHistory(pgRec.id).some((h) => h.kind === 'restore' && h.status === 'ok'));

    // Si alteramos un byte del .ckb1 Y actualizamos su sha256 (simulando ataque con hash recalculado),
    // la autenticación AEAD CKB1 debe detener restore() ANTES de tocar el contenedor!
    const bkFilePath = path.join(dm.backupDir(pgRec.id), pgBackup.backup.fileName);
    const savedBkBytes = fs.readFileSync(bkFilePath);
    const forgedBytes = Buffer.from(savedBkBytes);
    forgedBytes[forgedBytes.length - 3] ^= 0xff; // bit-flip en authTag
    fs.writeFileSync(bkFilePath, forgedBytes);
    const origSha = pgBackup.backup.sha256;
    pgBackup.backup.sha256 = crypto.createHash('sha256').update(forgedBytes).digest('hex');

    const beforeTamperRestore = invocations.length;
    await assert.rejects(
      () => dm.restore(pgRec.id, { backupId: pgBackup.backup.id, createSafetySnapshot: true }),
      /autenticación AES-256-GCM/i
    );
    const callsDuringBadRestore = invocations.slice(beforeTamperRestore);
    assert.strictEqual(callsDuringBadRestore.length, 0, 'Un fallo AEAD debe abortar ANTES de ejecutar cualquier comando Docker');
    // Restaurar fichero y hash válidos
    fs.writeFileSync(bkFilePath, savedBkBytes);
    pgBackup.backup.sha256 = origSha;

    // Redis restore: si falla `docker cp`, debe reiniciar el contenedor para no dejarlo detenido
    const valkeyRec = dm.mustGet(provisioned.valkey.id);
    const vkBackupId = valkeyRec.backups[0].id;
    failNextDockerCpOnRedis = true;
    const beforeVkFail = invocations.length;
    await assert.rejects(() => dm.restore(valkeyRec.id, { backupId: vkBackupId, createSafetySnapshot: false }), /Simulated docker cp/i);
    const vkRecoveryStart = invocations.slice(beforeVkFail).find((c) => c.args[0] === 'start' && c.args[1] === valkeyRec.containerName);
    assert.ok(vkRecoveryStart, 'Si falla docker cp en Redis/Valkey, restore() debe arrancar de nuevo el contenedor');

    // 9h. cloneDatabase(): clonar BD cifrada a nueva instancia aislada + rollback limpio en fallo
    const cloned = await dm.cloneDatabase(pgRec.id, {
      name: 'Postgres Staging Branch',
      backupId: pgBackup.backup.id,
      branchLabel: 'pr-42'
    });
    assert.ok(cloned.id && cloned.id !== pgRec.id);
    assert.strictEqual(cloned.clonedFrom.sourceDatabaseId, pgRec.id);
    assert.strictEqual(cloned.clonedFrom.branchLabel, 'pr-42');
    assert.notStrictEqual(dm.getCredentials(cloned.id).password, pgPw, 'El clon genera su propia contraseña única');
    console.log('  ✓ restore() AEAD pre-flight (0 comandos Docker si falla authTag), Redis recovery y cloneDatabase()');

    // 9i. applyRetention: protección horaria automática para crons sub-diarios + fallo S3 -> remotePendingDelete
    dm.setSchedule(pgRec.id, { enabled: true, cron: '*/30 * * * *' });
    dm.setRetention(pgRec.id, { daily: 1, weekly: 0 });
    const dir = dm.backupDir(pgRec.id);
    pgRec.backups = [];
    for (let i = 0; i < 4; i++) {
      const fn = `ret_${i}.dump.gz`;
      fs.writeFileSync(path.join(dir, fn), `data ${i}`);
      pgRec.backups.push({
        id: `rbk${i}`, fileName: fn, sizeBytes: 6,
        createdAt: new Date(Date.now() - i * 48 * 3600 * 1000).toISOString(),
        trigger: 'scheduled',
        remote: { key: `k/${fn}` }
      });
    }
    const subDailyRes = await dm.applyRetention(pgRec.id);
    assert.strictEqual(subDailyRes.pruned, 0, 'Con cron sub-diario, la ventana automática de 24 horarias protege las 4 copias');

    // Al pasar a cron diario, las 3 copias antiguas se podan y un fallo de deleteObject S3 marca remotePendingDelete
    dm.setSchedule(pgRec.id, { enabled: true, cron: '0 3 * * *' });
    forceNextS3Failure = true;
    await dm.applyRetention(pgRec.id);
    assert.ok(pgRec.backups.some((b) => b.remotePendingDelete === true && b.localDeleted === true), 'Si falla deleteObject S3 debe marcarse remotePendingDelete');

    // 9j. Watchdog SLA checkBackupHealth() (detecta copias silenciosamente atascadas — Coolify #10636)
    pgRec.schedule.enabled = true;
    pgRec.schedule.cron = '0 * * * *'; // cada hora
    pgRec.schedule.lastRunAt = new Date(Date.now() - 5 * 3600 * 1000).toISOString(); // 5 horas sin correr (> 2x)
    pgRec.schedule.lastStatus = 'error';
    sentNotifications.length = 0;
    const healthReport = dm.checkBackupHealth({ notify: true });
    assert.strictEqual(healthReport.healthy, false);
    assert.ok(healthReport.alerts.some((a) => a.code === 'BACKUP_STALE'));
    assert.ok(healthReport.alerts.some((a) => a.code === 'LAST_BACKUP_ERROR'));
    assert.ok(sentNotifications.some((n) => /Alerta SLA/i.test(n.title)));

    // 9k. Planificador tick() + auto-desactivación de cron inválido + startScheduler catch-up
    const vkSched = dm.mustGet(provisioned.valkey.id);
    vkSched.schedule = { enabled: true, cron: 'invalid cron expr', nextRunAt: null, lastRunAt: null, lastStatus: null };
    sentNotifications.length = 0;
    await dm.tick();
    assert.strictEqual(vkSched.schedule.enabled, false);
    assert.strictEqual(vkSched.schedule.lastStatus, 'horario-invalido');
    assert.ok(sentNotifications.some((n) => /desactivado/i.test(n.title)));

    // startScheduler unref & idempotente
    const timer = dm.startScheduler({ intervalMs: 60000, catchUp: false });
    assert.strictEqual(dm.startScheduler({ catchUp: false }), timer);
    dm.stopScheduler();
    assert.strictEqual(dm.schedulerTimer, null);

    // Limpieza con remove() también detiene PgBouncer
    const beforeRemove = invocations.length;
    await dm.remove(pgRec.id, { deleteVolume: true, deleteBackups: true });
    assert.ok(invocations.slice(beforeRemove).some((i) => i.args.includes(`culkibo_pooler_${pgRec.id}`)), 'remove() debe eliminar el pooler PgBouncer');

    dm.s3ClientFor = origS3ClientFor;
    console.log('  ✓ Retención S3-pending-delete, Watchdog SLA (Coolify #10636), cron guard y limpieza completa');
    console.log('✅ Bases de datos gestionadas + AEAD CKB1 + DR verificadas 100% determinísticamente\n');
  } finally {
    notificationService.notify = origNotify;
    dm.stopScheduler();
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

module.exports = testDatabases;

if (require.main === module) {
  testDatabases().catch((err) => {
    console.error('❌ Fallo en las pruebas de bases de datos:', err);
    process.exit(1);
  });
}
