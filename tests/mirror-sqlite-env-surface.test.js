const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

/**
 * Suite aislada para Cycle #23 (Historic 200-MCP Milestone):
 *  - registryMirrorGuardService.js (Docker Hub 429, NAT compartido, registry:3 mirror, config auth)
 *  - sqliteWalGuardService.js (NFS/EFS corruption, non-WAL, busy_timeout, synchronous=OFF, WAL starvation)
 *  - envSecretSurfaceService.js (Dokploy#3347 BuildKit ARG/ENV, Coolify#10822 overlap, zero raw secret storage)
 */
async function run() {
  console.log('--- Iniciando Tests de Registry Mirror Guard, SQLite WAL Guard y Env Secret Surface ---');
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mirror-sqlite-env-'));
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = tmpRoot;

  try {
    const mirrorSvc = require('../server/services/registryMirrorGuardService');
    const sqliteSvc = require('../server/services/sqliteWalGuardService');
    const envSvc = require('../server/services/envSecretSurfaceService');

    // 1. Registry Mirror Guard
    const anonAudit = mirrorSvc.auditRegistryPullBudget({
      nodeId: 'vps-eu-01',
      registry: 'docker.io',
      authenticated: false,
      pullsPerHour: 12,
      archCount: 2,
      sharedNatIp: true,
      mirrors: [],
      plaintextConfigAuth: true
    });
    assert.strictEqual(anonAudit.ok, true);
    assert.strictEqual(anonAudit.safe, false);
    assert.strictEqual(anonAudit.blocked, true);
    assert.strictEqual(anonAudit.effectivePullsPerHour, 24);
    assert.ok(anonAudit.findingCodes.includes('ANONYMOUS_HUB_RATE_LIMIT_RISK'));
    assert.ok(anonAudit.findingCodes.includes('SHARED_NAT_QUOTA_EXHAUSTION'));
    assert.ok(anonAudit.findingCodes.includes('MISSING_REGISTRY_MIRROR'));
    assert.ok(anonAudit.findingCodes.includes('PLAINTEXT_DOCKER_CONFIG_AUTH'));
    assert.strictEqual(typeof anonAudit.daemonJsonText, 'string');
    assert.ok(anonAudit.daemonJsonText.includes('registry-mirrors'));

    const cleanMirrorAudit = mirrorSvc.auditRegistryPullBudget({
      nodeId: 'vps-eu-02',
      registry: 'docker.io',
      authenticated: true,
      pullsPerHour: 15,
      archCount: 2,
      sharedNatIp: false,
      mirrors: ['http://127.0.0.1:5000', 'https://mirror.gcr.io'],
      plaintextConfigAuth: false
    });
    assert.strictEqual(cleanMirrorAudit.safe, true);
    assert.strictEqual(cleanMirrorAudit.blocked, false);
    assert.strictEqual(cleanMirrorAudit.findingCodes.length, 0);

    const renderedDaemon = mirrorSvc.renderDaemonMirrorConfig({
      mirrorUrls: ['http://127.0.0.1:5000'],
      maxConcurrentDownloads: 4,
      nodeId: 'vps-eu-02'
    });
    assert.strictEqual(renderedDaemon.dryRun, true);
    assert.deepStrictEqual(renderedDaemon.daemonConfig['registry-mirrors'], ['http://127.0.0.1:5000']);
    assert.strictEqual(renderedDaemon.daemonConfig['max-concurrent-downloads'], 4);
    assert.strictEqual(typeof renderedDaemon.daemonJsonText, 'string');
    assert.ok(mirrorSvc.listRegistryMirrorAudits().length >= 2);
    assert.strictEqual(mirrorSvc.listRegistryMirrorAudits('vps-eu-01').length, 1);
    console.log('  ✓ 1. registryMirrorGuardService detects Hub 429/NAT/plaintext auth, passes mirrored nodes & renders daemon.json');

    // 2. SQLite WAL Checkpoint Starvation & Network-FS Guard
    const badWal = sqliteSvc.auditSqliteWalHealth({
      databaseName: 'solid_queue.sqlite3',
      filesystemType: 'nfs',
      journalMode: 'delete',
      synchronous: 'off',
      busyTimeoutMs: 0,
      journalSizeLimitMb: 0,
      dbSizeMb: 80,
      walSizeMb: 512,
      blockedReaders: 2
    });
    assert.strictEqual(badWal.ok, true);
    assert.strictEqual(badWal.safe, false);
    assert.strictEqual(badWal.blocked, true);
    assert.ok(badWal.findingCodes.includes('SQLITE_NETWORK_FS_CORRUPTION'));
    assert.ok(badWal.findingCodes.includes('SQLITE_NON_WAL_LOCK_RISK'));
    assert.ok(badWal.findingCodes.includes('SQLITE_BUSY_TIMEOUT_LOW'));
    assert.ok(badWal.findingCodes.includes('SQLITE_SYNC_OFF_CORRUPTION'));
    assert.ok(badWal.findingCodes.includes('SQLITE_UNBOUNDED_WAL'));
    assert.ok(badWal.findingCodes.includes('WAL_CHECKPOINT_STARVATION'));
    assert.strictEqual(typeof badWal.pragmaSql, 'string');
    assert.ok(badWal.pragmaSql.includes('PRAGMA journal_mode = WAL;'));
    assert.ok(badWal.pragmaSql.includes('PRAGMA wal_checkpoint(TRUNCATE);'));

    const healthyWal = sqliteSvc.auditSqliteWalHealth({
      databaseName: 'pocketbase.db',
      filesystemType: 'ext4',
      journalMode: 'wal',
      synchronous: 'normal',
      busyTimeoutMs: 5000,
      journalSizeLimitMb: 64,
      dbSizeMb: 120,
      walSizeMb: 18,
      blockedReaders: 0
    });
    assert.strictEqual(healthyWal.safe, true);
    assert.strictEqual(healthyWal.blocked, false);
    assert.strictEqual(healthyWal.findingCodes.length, 0);

    const pragmas = sqliteSvc.renderHardenedSqlitePragmas({
      databaseName: 'pocketbase.db',
      busyTimeoutMs: 8000,
      journalSizeLimitMb: 64
    });
    assert.strictEqual(pragmas.dryRun, true);
    assert.ok(pragmas.pragmaSql.includes('PRAGMA busy_timeout = 8000;'));
    assert.ok(sqliteSvc.listSqliteWalAudits().length >= 2);
    console.log('  ✓ 2. sqliteWalGuardService blocks NFS/non-WAL/low timeout/sync-OFF/starvation & emits hardened PRAGMAs');

    // 3. Build-ARG / ENV Secret Surface & /run/secrets/ Migrator (ZERO raw secret echoes/persistence)
    const syntheticValue = ['sup3r', 's3cr3t', 'val', '999'].join('_');
    const leakyDockerfile = [
      'FROM node:22-alpine',
      `ARG JWT_SECRET=${syntheticValue}`,
      `ENV DATABASE_URL=postgres://admin:${syntheticValue}@db.internal:5432/prod NODE_ENV=production`,
      'ENV NEXT_PUBLIC_APP_URL=https://app.example.com',
      'RUN npm run build'
    ].join('\n');

    const envAudit = envSvc.auditEnvSecretSurface({
      projectId: 'proj-saas',
      dockerfile: leakyDockerfile,
      composeEnvKeys: ['JWT_SECRET', `STRIPE_API_KEY=${syntheticValue}`, 'PORT', 'DATABASE_URL_FILE'],
      composeSecretKeys: [],
      buildTimeEnvKeys: ['JWT_SECRET', 'NODE_ENV']
    });
    assert.strictEqual(envAudit.ok, true);
    assert.strictEqual(envAudit.safe, false);
    assert.strictEqual(envAudit.blocked, true);
    assert.strictEqual(envAudit.zeroRawSecretsStored, true);
    assert.ok(envAudit.findingCodes.includes('BUILDKIT_SECRET_IN_ARG_OR_ENV'));
    assert.ok(envAudit.findingCodes.includes('COMPOSE_SECRET_IN_PLAIN_ENV'));
    assert.ok(envAudit.findingCodes.includes('BUILD_RUNTIME_SECRET_OVERLAP'));
    assert.ok(envAudit.dockerfileSecretKeys.includes('JWT_SECRET'));
    assert.ok(envAudit.dockerfileSecretKeys.includes('DATABASE_URL'));
    assert.ok(!envAudit.dockerfileSecretKeys.includes('NODE_ENV'));
    assert.ok(!envAudit.dockerfileSecretKeys.includes('NEXT_PUBLIC_APP_URL'));
    assert.ok(envAudit.dockerfileSnippet.includes('RUN --mount=type=secret,id=jwt_secret'));
    assert.ok(envAudit.composeSnippet.includes('mode: 0400') && envAudit.composeSnippet.includes('/run/secrets/jwt_secret'));

    // Assert ZERO raw secret values appear in response OR persisted store on disk!
    assert.strictEqual(JSON.stringify(envAudit).includes(syntheticValue), false, 'Response must NEVER echo raw secret values');
    const persistedJson = fs.readFileSync(path.join(tmpRoot, 'data', 'env-secret-surface.json'), 'utf8');
    assert.strictEqual(persistedJson.includes(syntheticValue), false, 'Disk store must NEVER persist raw secret values');

    const cleanEnvAudit = envSvc.auditEnvSecretSurface({
      projectId: 'proj-clean',
      dockerfile: 'FROM node:22-alpine\nENV NODE_ENV=production PORT=3000\nRUN --mount=type=secret,id=jwt_secret npm run build\n',
      composeEnvKeys: ['NODE_ENV', 'PORT', 'JWT_SECRET_FILE'],
      composeSecretKeys: ['jwt_secret'],
      buildTimeEnvKeys: ['NODE_ENV']
    });
    assert.strictEqual(cleanEnvAudit.safe, true);
    assert.strictEqual(cleanEnvAudit.blocked, false);

    const mig = envSvc.renderSecretMountMigration({ secretNames: ['JWT_SECRET', 'DATABASE_URL'] });
    assert.strictEqual(mig.dryRun, true);
    assert.strictEqual(typeof mig.dockerfileSnippet, 'string');
    assert.strictEqual(typeof mig.composeSnippet, 'string');
    assert.ok(mig.dockerfileSnippet.includes('RUN --mount=type=secret,id=jwt_secret'));
    assert.ok(mig.composeSnippet.includes('mode: 0400'));
    assert.strictEqual(envSvc.listEnvSurfaceAudits('proj-saas').length, 1);
    console.log('  ✓ 3. envSecretSurfaceService flags Dokploy#3347/Coolify#10822, emits --mount=type=secret & stores 0 raw secrets');

    console.log('\n✅ Registry Mirror, SQLite WAL & Env Secret Surface Suite: 3/3 tests PASSED!');
  } finally {
    if (prevDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
    else process.env.CULKIBO_DATA_DIR = prevDataDir;
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  run().catch((err) => {
    console.error('❌ mirror-sqlite-env-surface.test.js failed:', err);
    process.exit(1);
  });
}

module.exports = run;
