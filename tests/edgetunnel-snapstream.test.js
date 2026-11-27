const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { WebSocketServer } = require('ws');

const { EdgeTunnelService, EdgeTunnelClient } = require('../server/services/edgeTunnelService');
const { SqliteStreamBackup } = require('../server/services/sqliteStreamBackup');
const { PreviewManager } = require('../server/services/previewManager');
const coolifyMigrator = require('../server/services/coolifyMigrator');

async function runTests() {
  console.log('--- Iniciando Tests de EdgeTunnel + SnapStream + Preview DB Branching + Coolify Streamer ---');
  let passed = 0;
  let failed = 0;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-cycle2-'));
  const dataDir = path.join(tmpRoot, 'data');
  fs.mkdirSync(dataDir, { recursive: true });

  const runCase = async (name, fn) => {
    try {
      await fn();
      console.log(`  ✓ ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✗ ${name} falló:`, err);
      failed++;
    }
  };

  try {
    // =========================================================================
    // 1. EDGETUNNEL: LIVE LOOPBACK WS FORWARDING + TOKEN VERIFY + SSRF + MUX
    // =========================================================================
    await runCase('Test 1: EdgeTunnel live loopback WS HTTP forward (GET/POST + headers + body)', async () => {
      // Spin up local HTTP backend behind simulated CGNAT
      const backend = http.createServer((req, res) => {
        /** @type {Buffer[]} */
        const chunks = [];
        req.on('data', (c) => chunks.push(c));
        req.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');
          if (req.url === '/echo') {
            res.writeHead(201, {
              'content-type': 'application/json',
              'x-backend-echo': String(req.headers['x-client-tag'] || 'none')
            });
            res.end(JSON.stringify({ method: req.method, path: req.url, body }));
            return;
          }
          res.writeHead(200, { 'content-type': 'text/plain' });
          res.end(`hello:${req.url}`);
        });
      });

      await new Promise((resolve) => backend.listen(0, '127.0.0.1', resolve));
      const backendPort = /** @type {any} */ (backend.address()).port;

      const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
      await new Promise((resolve) => wss.once('listening', resolve));
      const wsPort = /** @type {any} */ (wss.address()).port;

      const svc = new EdgeTunnelService({ dataDir });
      svc.attachWebSocketServer(wss);

      const created = svc.createTunnel({
        name: 'home-nas',
        targetHost: '127.0.0.1',
        targetPort: backendPort,
        hostname: 'nas.pablo.dev'
      });
      assert.ok(created.id.startsWith('tun_'));
      assert.ok(created.token && created.token.startsWith('cket_'));
      assert.strictEqual(svc.verifyToken(created.id, created.token), true);
      assert.strictEqual(svc.verifyToken(created.id, 'cket_wrong_token_value'), false);

      // listTunnels MUST never leak raw token
      const listed = svc.listTunnels();
      assert.strictEqual(listed.length, 1);
      assert.strictEqual(listed[0].token, undefined);
      assert.strictEqual(listed[0].tokenHmac, undefined);

      const client = new EdgeTunnelClient({
        serverUrl: `ws://127.0.0.1:${wsPort}`,
        tunnelId: created.id,
        token: created.token,
        targetHost: '127.0.0.1',
        targetPort: backendPort
      });

      try {
        await client.connect();
        // Wait a tick for server connection registration
        await new Promise((r) => setTimeout(r, 30));

        const getRes = await svc.forwardHttp(created.id, { method: 'GET', path: '/health' });
        assert.strictEqual(getRes.status, 200);
        assert.strictEqual(getRes.bodyText, 'hello:/health');

        const postRes = await svc.forwardHttp(created.id, {
          method: 'POST',
          path: '/echo',
          headers: { 'x-client-tag': 'sovereign-cgnat', 'content-type': 'text/plain' },
          body: 'payload-zero-cloudflare'
        });
        assert.strictEqual(postRes.status, 201);
        assert.strictEqual(postRes.headers['x-backend-echo'], 'sovereign-cgnat');
        const parsed = JSON.parse(postRes.bodyText);
        assert.strictEqual(parsed.method, 'POST');
        assert.strictEqual(parsed.body, 'payload-zero-cloudflare');

        const status = svc.getStatus();
        assert.strictEqual(status.connectedTunnels, 1);
        assert.strictEqual(status.totalRequestsForwarded, 2);
      } finally {
        client.close();
        svc.closeAll();
        await new Promise((r) => wss.close(r));
        await new Promise((r) => backend.close(r));
      }
    });

    await runCase('Test 2: EdgeTunnel concurrent multiplexing (8 parallel streams over 1 WS) + invalid/revoked token + SSRF block', async () => {
      const backend = http.createServer((req, res) => {
        const idx = Number(new URL(req.url || '/', 'http://127.0.0.1').searchParams.get('id') || '0');
        // Stagger responses in reverse order so out-of-order stream completion tests real multiplexing!
        setTimeout(() => {
          res.writeHead(200, { 'x-stream-idx': String(idx) });
          res.end(`mux-reply-${idx}`);
        }, (9 - idx) * 8);
      });
      await new Promise((resolve) => backend.listen(0, '127.0.0.1', resolve));
      const backendPort = /** @type {any} */ (backend.address()).port;

      const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
      await new Promise((resolve) => wss.once('listening', resolve));
      const wsPort = /** @type {any} */ (wss.address()).port;

      const svc = new EdgeTunnelService({ dataDir });
      svc.attachWebSocketServer(wss);

      // SSRF block: cloud metadata targets MUST be rejected
      assert.throws(
        () => svc.createTunnel({ name: 'imds', targetHost: '169.254.169.254', targetPort: 80 }),
        /SSRF|metadatos/i
      );
      assert.throws(
        () => svc.createTunnel({ name: 'gcp-meta', targetHost: 'metadata.google.internal', targetPort: 80 }),
        /SSRF|metadatos/i
      );

      const tun = svc.createTunnel({ name: 'mux-app', targetHost: '127.0.0.1', targetPort: backendPort });

      // Invalid token MUST be rejected by WS server
      const badClient = new EdgeTunnelClient({
        serverUrl: `ws://127.0.0.1:${wsPort}`,
        tunnelId: tun.id,
        token: 'cket_forged_invalid_token',
        targetHost: '127.0.0.1',
        targetPort: backendPort
      });
      const badClosed = new Promise((resolve) => badClient.once('close', resolve));
      await badClient.connect().catch(() => {});
      const closeInfo = /** @type {any} */ (await badClosed);
      assert.strictEqual(closeInfo.code, 4401);
      assert.ok(svc.getStatus().rejectedAuthCount >= 1);

      // Valid client + 8 concurrent multiplexed streams
      const goodClient = new EdgeTunnelClient({
        serverUrl: `ws://127.0.0.1:${wsPort}`,
        tunnelId: tun.id,
        token: tun.token,
        targetHost: '127.0.0.1',
        targetPort: backendPort
      });
      try {
        await goodClient.connect();
        await new Promise((r) => setTimeout(r, 30));

        const responses = await Promise.all(
          Array.from({ length: 8 }, (_, i) =>
            svc.forwardHttp(tun.id, { method: 'GET', path: `/work?id=${i + 1}` })
          )
        );
        for (let i = 0; i < 8; i++) {
          assert.strictEqual(responses[i].status, 200);
          assert.strictEqual(responses[i].headers['x-stream-idx'], String(i + 1));
          assert.strictEqual(responses[i].bodyText, `mux-reply-${i + 1}`);
        }

        // Revoke tunnel -> disconnects client & blocks subsequent verifyToken / forwardHttp
        const rev = svc.revokeTunnel(tun.id);
        assert.strictEqual(rev.revoked, true);
        assert.strictEqual(svc.verifyToken(tun.id, tun.token), false);
        await assert.rejects(
          () => svc.forwardHttp(tun.id, { method: 'GET', path: '/' }),
          /revocado|no encontrado/i
        );
      } finally {
        goodClient.close();
        svc.closeAll();
        await new Promise((r) => wss.close(r));
        await new Promise((r) => backend.close(r));
      }
    });

    // =========================================================================
    // 2. SNAPSTREAM: SQLITE WAL DELTA + BROTLI + AES-256-GCM CKS1 + PITR
    // =========================================================================
    await runCase('Test 3: SnapStream WAL generation capture, S3 upload, skip no-op & PITR restore', async () => {
      const snap = new SqliteStreamBackup({ dataDir });
      const destDir = path.join(tmpRoot, 'snapstream-store');
      const dbPath = path.join(tmpRoot, 'app.sqlite');
      const walPath = `${dbPath}-wal`;
      const encKey = crypto.randomBytes(32);

      /** @type {Array<{ key: string, bytes: number, meta: any }>} */
      const uploadedS3 = [];
      const mockS3 = {
        putObject: async (key, buf, _ct, opts) => {
          uploadedS3.push({ key, bytes: buf.length, meta: opts && opts.metadata });
          return { key, etag: '"mock"', size: buf.length };
        }
      };

      // Gen 1: initial SQLite main + initial WAL frame
      const mainV1 = Buffer.concat([Buffer.from('SQLite format 3\0'), crypto.randomBytes(4096)]);
      const walV1 = Buffer.concat([Buffer.from('WAL-HEADER-V1'), crypto.randomBytes(1024)]);
      fs.writeFileSync(dbPath, mainV1);
      fs.writeFileSync(walPath, walV1);

      const g1 = await snap.captureGeneration('db_orders', dbPath, {
        encryptionKey: encKey,
        destDir,
        s3Client: mockS3,
        label: 'initial'
      });
      assert.strictEqual(g1.captured, true);
      assert.strictEqual(g1.kind, 'snapshot');
      assert.strictEqual(g1.sequence, 1);
      assert.strictEqual(g1.envelopeMagic, 'CKS1');
      assert.strictEqual(uploadedS3.length, 1);

      // No changes -> skipped cleanly
      const noop = await snap.captureGeneration('db_orders', dbPath, { encryptionKey: encKey, destDir });
      assert.strictEqual(noop.captured, false);
      assert.strictEqual(noop.skipped, true);

      // Gen 2: append WAL frames only -> incremental wal_delta!
      const walDeltaChunk = Buffer.concat([Buffer.from('WAL-TX-2'), crypto.randomBytes(2048)]);
      const walV2 = Buffer.concat([walV1, walDeltaChunk]);
      fs.writeFileSync(walPath, walV2);

      const g2 = await snap.captureGeneration('db_orders', dbPath, {
        encryptionKey: encKey,
        destDir,
        s3Client: mockS3
      });
      assert.strictEqual(g2.captured, true);
      assert.strictEqual(g2.kind, 'wal_delta');
      assert.strictEqual(g2.sequence, 2);
      assert.strictEqual(g2.baseGenerationId, g1.generationId);
      assert.strictEqual(g2.walDeltaBytes, walDeltaChunk.length);
      assert.strictEqual(uploadedS3.length, 2);

      // Gen 3: checkpoint mutates main DB -> new snapshot
      const mainV3 = Buffer.concat([Buffer.from('SQLite format 3\0'), crypto.randomBytes(6144)]);
      fs.writeFileSync(dbPath, mainV3);
      fs.unlinkSync(walPath);

      const g3 = await snap.captureGeneration('db_orders', dbPath, { encryptionKey: encKey, destDir });
      assert.strictEqual(g3.captured, true);
      assert.strictEqual(g3.kind, 'snapshot');
      assert.strictEqual(g3.sequence, 3);

      const gens = snap.listGenerations('db_orders', { destDir });
      assert.strictEqual(gens.length, 3);
      const st = snap.getStatus('db_orders', { destDir });
      assert.strictEqual(st.generationCount, 3);
      assert.strictEqual(st.snapshotCount, 2);
      assert.strictEqual(st.walDeltaCount, 1);

      // PITR restore to Gen 2 (snapshot Gen 1 + wal_delta Gen 2 replayed!)
      const restoreV2Path = path.join(tmpRoot, 'restore-v2', 'orders.sqlite');
      const r2 = snap.restorePointInTime('db_orders', restoreV2Path, {
        generation: g2.generationId,
        encryptionKey: encKey,
        destDir
      });
      assert.strictEqual(r2.restored, true);
      assert.strictEqual(r2.framesReplayed, 2);
      assert.strictEqual(r2.walRestored, true);
      assert.ok(fs.readFileSync(restoreV2Path).equals(mainV1));
      assert.ok(fs.readFileSync(`${restoreV2Path}-wal`).equals(walV2));

      // PITR restore to latest (Gen 3)
      const restoreV3Path = path.join(tmpRoot, 'restore-v3', 'orders.sqlite');
      const r3 = snap.restorePointInTime('db_orders', restoreV3Path, {
        encryptionKey: encKey,
        destDir
      });
      assert.strictEqual(r3.sequence, 3);
      assert.strictEqual(r3.walRestored, false);
      assert.ok(fs.readFileSync(restoreV3Path).equals(mainV3));
    });

    await runCase('Test 4: SnapStream rejects wrong encryptionKey and tampered CKS1 frames', async () => {
      const snap = new SqliteStreamBackup({ dataDir });
      const destDir = path.join(tmpRoot, 'snapstream-tamper');
      const dbPath = path.join(tmpRoot, 'secret.sqlite');
      fs.writeFileSync(dbPath, Buffer.from('SQLite format 3\0sensitive-table-data-123456789'));

      const g1 = await snap.captureGeneration('db_sec', dbPath, {
        encryptionKey: 'correct-master-key-2026',
        destDir
      });

      // Wrong key MUST fail AES-GCM auth
      assert.throws(
        () => snap.restorePointInTime('db_sec', path.join(tmpRoot, 'out1.sqlite'), {
          generation: g1.generationId,
          encryptionKey: 'wrong-master-key-9999',
          destDir
        }),
        /AES-256-GCM|clave incorrecta|manipulado/i
      );

      // Flip 1 byte in ciphertext of .cks1 file -> MUST fail AES-GCM auth
      const raw = fs.readFileSync(g1.filePath);
      raw[raw.length - 1] ^= 0xff;
      fs.writeFileSync(g1.filePath, raw);

      assert.throws(
        () => snap.restorePointInTime('db_sec', path.join(tmpRoot, 'out2.sqlite'), {
          generation: g1.generationId,
          encryptionKey: 'correct-master-key-2026',
          destDir
        }),
        /AES-256-GCM|manipulado/i
      );
    });

    // =========================================================================
    // 3. PREVIEW DB BRANCHING (POSTGRES + SQLITE CoW + IDEMPOTENT TEARDOWN)
    // =========================================================================
    await runCase('Test 5: Preview DB Branching (Postgres parameterized plan, SQLite CoW clone & idempotent teardown)', async () => {
      const pm = new PreviewManager({
        dataDir,
        workDir: path.join(tmpRoot, 'previews-work')
      });

      const proj = {
        id: 'proj_billing',
        name: 'Billing API',
        previewDeployments: { enabled: true, baseDomain: 'previews.pablo.dev', branchDatabase: true }
      };

      // A. PostgreSQL parameterized plan (zero shell, strict identifier validation)
      const pgPlan = pm.planPreviewDbBranch(proj, 42, {
        engine: 'postgres',
        sourceDb: 'billing_prod',
        username: 'billing_user',
        containerName: 'culkibo-pg-billing'
      });
      assert.strictEqual(pgPlan.zeroShell, true);
      assert.strictEqual(pgPlan.engine, 'postgres');
      assert.strictEqual(pgPlan.branchDbName, 'culkibo_prev_proj_billing_pr42');
      assert.ok(pgPlan.createArgv.includes('CREATE DATABASE :"branch_db" WITH TEMPLATE :"template_db" OWNER :"db_owner";'));
      assert.ok(pgPlan.teardownArgv.includes('DROP DATABASE IF EXISTS :"branch_db" WITH (FORCE);'));

      // SQL injection in sourceDb or username MUST be rejected
      assert.throws(
        () => pm.planPreviewDbBranch(proj, 42, { engine: 'postgres', sourceDb: 'prod; DROP TABLE users;--' }),
        /inválido/i
      );

      // Teardown Postgres branch using mock executor + verify idempotency on second call
      /** @type {string[][]} */
      const executedArgvs = [];
      const td1 = await pm.teardownPreviewDbBranch(pgPlan.previewId, {
        executor: async (argv) => { executedArgvs.push(argv); return { code: 0 }; }
      });
      assert.strictEqual(td1.destroyed, true);
      assert.strictEqual(td1.alreadyCleaned, false);
      assert.strictEqual(executedArgvs.length, 1);

      const td2 = await pm.teardownPreviewDbBranch(pgPlan.previewId, {
        executor: async (argv) => { executedArgvs.push(argv); return { code: 0 }; }
      });
      assert.strictEqual(td2.alreadyCleaned, true);
      assert.strictEqual(executedArgvs.length, 1, 'Second teardown must be idempotent no-op');

      // B. SQLite CoW branch execute + verify file clone + automatic cleanup on destroyPreview (coolify#12458)
      const srcSqlite = path.join(tmpRoot, 'main-app.sqlite');
      fs.writeFileSync(srcSqlite, Buffer.from('SQLite format 3\0branch-content-check'));
      fs.writeFileSync(`${srcSqlite}-wal`, Buffer.from('WAL-DATA'));

      const sqPlan = pm.planPreviewDbBranch(proj, 99, {
        engine: 'sqlite',
        sourcePath: srcSqlite,
        execute: true
      });
      assert.strictEqual(sqPlan.provisioned, true);
      assert.strictEqual(fs.existsSync(sqPlan.branchPath), true);
      assert.strictEqual(fs.existsSync(`${sqPlan.branchPath}-wal`), true);
      assert.ok(fs.readFileSync(sqPlan.branchPath).equals(fs.readFileSync(srcSqlite)));

      // Seed preview record and trigger destroyPreview with mocked deployManager/ingressManager
      pm._ensureLoaded();
      pm.store[proj.id] = {
        'pr-99': {
          key: 'pr-99',
          projectId: proj.id,
          containerName: null,
          imageTag: null,
          dbBranch: sqPlan
        }
      };
      pm._getDeployManager = () => ({ runDocker: async () => ({ code: 0 }) });
      pm._getIngressManager = () => ({ previewRoutes: new Map(), reconcile: async () => {} });

      const destroyRes = await pm.destroyPreview(proj.id, 'pr-99');
      assert.strictEqual(destroyRes.removed, true);
      assert.strictEqual(fs.existsSync(sqPlan.branchPath), false, 'Branched SQLite file must be deleted on PR close');
      assert.strictEqual(fs.existsSync(`${sqPlan.branchPath}-wal`), false, 'Branched SQLite WAL must be deleted on PR close');
    });

    // =========================================================================
    // 4. COOLIFY LIVE VOLUME & SQL DATA STREAMER (`buildVolumeAndDbStreamPlan`)
    // =========================================================================
    await runCase('Test 6: Coolify buildVolumeAndDbStreamPlan (zero-shell arg arrays, SHA-256 checks & injection blocks)', async () => {
      const snapshot = {
        apps: [
          {
            uuid: 'app-media',
            name: 'MediaMate',
            local_persistent_volumes: [
              { name: 'mediamate_uploads', mount_path: '/app/uploads' }
            ]
          }
        ],
        databases: [
          { uuid: 'db-pg1', name: 'MainPG', database_type: 'postgresql', postgres_user: 'pgadmin', postgres_password: 'TOP_SECRET_PG_PASSWORD', postgres_db: 'prod_db', volumes: [{ name: 'pg_vol_data', mount_path: '/var/lib/postgresql/data' }] },
          { uuid: 'db-my1', name: 'ShopMySQL', database_type: 'mysql', mysql_user: 'shop', mysql_password: 'TOP_SECRET_MYSQL_PASSWORD', mysql_database: 'shopdb' },
          { uuid: 'db-mo1', name: 'DocsMongo', database_type: 'mongodb', mongo_initdb_root_username: 'root', mongo_initdb_root_password: 'TOP_SECRET_MONGO_PASSWORD' },
          { uuid: 'db-rd1', name: 'FastRedis', database_type: 'dragonfly', dragonfly_password: 'TOP_SECRET_REDIS_PASSWORD' }
        ],
        services: [
          { uuid: 'svc-1', name: 'Worker', volumes: [{ name: 'worker_cache', mount_path: '/cache' }] }
        ]
      };

      const plan = coolifyMigrator.buildVolumeAndDbStreamPlan(snapshot, {
        sourceHost: '198.51.100.25',
        sourceUser: 'deploy',
        sourcePort: 2222
      });

      assert.strictEqual(plan.ok, true);
      assert.strictEqual(plan.zeroShell, true);
      assert.strictEqual(plan.summary.databases, 4);
      assert.strictEqual(plan.summary.volumes, 3);

      // Every stream command uses strict program + args[] arrays and NEVER leaks passwords!
      const serialized = JSON.stringify(plan);
      assert.ok(!serialized.includes('TOP_SECRET_PG_PASSWORD'));
      assert.ok(!serialized.includes('TOP_SECRET_MYSQL_PASSWORD'));
      assert.ok(!serialized.includes('TOP_SECRET_MONGO_PASSWORD'));
      assert.ok(!serialized.includes('TOP_SECRET_REDIS_PASSWORD'));

      const pgStream = plan.databaseStreams.find((d) => d.id === 'db-pg1');
      assert.strictEqual(pgStream.sourceDump.program, 'docker');
      assert.ok(Array.isArray(pgStream.sourceDump.args));
      assert.ok(pgStream.sourceDump.args.includes('pg_dump'));
      assert.strictEqual(pgStream.sshSourceDump.program, 'ssh');
      assert.ok(pgStream.sshSourceDump.args.includes('deploy@198.51.100.25'));
      assert.strictEqual(pgStream.verification.streamChecksumAlgorithm, 'sha256');

      const volStream = plan.volumeStreams.find((v) => v.volumeName === 'mediamate_uploads');
      assert.ok(volStream);
      assert.strictEqual(volStream.sourceArchive.program, 'docker');
      assert.ok(volStream.sourceArchive.args.includes('tar'));
      assert.strictEqual(volStream.verification.algorithm, 'sha256');

      // Shell/flag injection in sourceHost or volume name MUST be rejected
      assert.throws(
        () => coolifyMigrator.buildVolumeAndDbStreamPlan(snapshot, { sourceHost: 'evil.com; rm -rf /' }),
        /inseguro/i
      );
      assert.throws(
        () => coolifyMigrator.buildVolumeAndDbStreamPlan({
          apps: [{ uuid: 'a1', name: 'Bad', volumes: [{ name: '-oProxyCommand=evil' }] }]
        }),
        /inseguro/i
      );
    });

    console.log(`\nResultados: ${passed} pasados, ${failed} fallados`);
    if (failed > 0) throw new Error(`${failed} tests failed in edgetunnel-snapstream suite`);
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = runTests;
