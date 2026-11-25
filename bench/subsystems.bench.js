/**
 * Banco de pruebas de subsistemas críticos de Culkibo (0 dependencias nuevas,
 * 100% aislado en `os.tmpdir()` — nunca toca `data/*.json`).
 *
 * Mide 6 métricas críticas previamente sin medir:
 *  1. RBAC auth & revocation latency (`verifySessionToken`, `verifyApiToken`, `authorizeHttpRoute`, instant logout)
 *  2. Live Sync 2.0 Brotli (0x02) compression ratio + 100-file burst throughput
 *  3. YAML parser anti-DoS timing (`parseSafeYaml` valid + 10 hostile vectors, `parseDockerCompose` >512KB)
 *  4. Concurrent persistence throughput (Atomic JSON Group Commit + native `node:sqlite` WAL)
 *  5. Backup SHA-256 integrity + AES-256-GCM encryption/decryption throughput (MB/s + scrypt KDF ms)
 *  6. 500-request authenticated HTTP P50/P95/P99 over real Express + `authMiddleware` + `requireRouteRbac`
 */

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const express = require('express');

const auth = require('../server/middleware/auth');
const { TeamManager } = require('../server/services/teamManager');
const liveSyncEngine = require('../server/services/liveSyncEngine');
const { LiveSyncEngine, decodeBinarySyncFrame, sha256 } = liveSyncEngine;
const { LiveSyncClient } = require('../server/services/liveSyncClient');
const { parseSafeYaml } = require('../server/services/gitopsManager');
const { parseDockerCompose } = require('../server/services/universalImporter');
const projectManager = require('../server/services/projectManager');
const Project = require('../server/models/Project');
const dbBackupManager = require('../server/services/dbBackupManager');
const { TelemetryStorage } = require('../telemetry-collector/lib/storage');

function percentile(sorted, p) {
  if (!sorted.length) return null;
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return Number(sorted[Math.max(0, idx)].toFixed(3));
}

function createIsolatedProjectManager(tmpFile) {
  const pm = Object.create(Object.getPrototypeOf(projectManager));
  require('events').EventEmitter.call(pm);
  pm.dataPath = tmpFile;
  pm.projects = new Map();
  pm.savingPromise = null;
  pm.pendingSave = false;
  pm._lastBackupAt = 0;
  pm._inFlightFlush = null;
  pm._queuedFlush = null;
  pm._batchingFlush = null;
  pm._serializedAll = null;
  pm._version = 1;
  pm._projectJsonCache = new Map();
  pm.saveDebounceTimer = null;
  pm.flushChain = Promise.resolve();
  pm.ensureDataDir();
  return pm;
}

/**
 * @param {{ silent?: boolean, httpRequests?: number, httpWorkers?: number }} [opts]
 */
async function run({ silent = false, httpRequests = 500, httpWorkers = 25 } = {}) {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-bench-subsystems-'));

  try {
    // =========================================================================
    // 1. RBAC Auth, Token Verification & Instant Revocation Latency
    // =========================================================================
    const tmDir = path.join(tmpRoot, 'rbac');
    const tm = new TeamManager({ dataDir: tmDir, bcryptCost: 4 });
    const boot = tm.bootstrapOwner({ email: 'bench-owner@culkibo.local', password: 'BenchOwnerPassword!2026' });
    const ownerP = tm.verifySessionToken(boot.sessionToken).principal;
    const devInv = tm.createInvite(ownerP, { email: 'bench-dev@culkibo.local', role: 'developer' });
    const devAcc = tm.acceptInvite({ token: devInv.inviteToken, email: 'bench-dev@culkibo.local', password: 'BenchDevPassword!2026' });
    const devP = tm.verifySessionToken(devAcc.sessionToken).principal;
    const apiTok = tm.createApiToken(devP, {
      name: 'Bench CI Token',
      scopes: ['projects:read', 'projects:write', 'deployments:write'],
      projectIds: ['proj_bench_1']
    });

    // Warmup
    for (let i = 0; i < 20; i++) {
      tm.verifySessionToken(devAcc.sessionToken);
      tm.verifyApiToken(apiTok.token);
      tm.authorizeHttpRoute(devP, 'GET', '/api/projects');
    }

    const sessSamples = [];
    const sessT0 = process.hrtime.bigint();
    for (let i = 0; i < 500; i++) {
      const s = process.hrtime.bigint();
      const r = tm.verifySessionToken(devAcc.sessionToken);
      if (!r.ok) throw new Error('verifySessionToken benchmark unexpectedly failed');
      sessSamples.push(Number(process.hrtime.bigint() - s) / 1e6);
    }
    const sessTotalMs = Number(process.hrtime.bigint() - sessT0) / 1e6;
    sessSamples.sort((a, b) => a - b);

    const apiSamples = [];
    const apiT0 = process.hrtime.bigint();
    for (let i = 0; i < 500; i++) {
      const s = process.hrtime.bigint();
      const r = tm.verifyApiToken(apiTok.token);
      if (!r.ok) throw new Error('verifyApiToken benchmark unexpectedly failed');
      apiSamples.push(Number(process.hrtime.bigint() - s) / 1e6);
    }
    const apiTotalMs = Number(process.hrtime.bigint() - apiT0) / 1e6;
    apiSamples.sort((a, b) => a - b);

    const routeSamples = [];
    const routesToCheck = [
      ['GET', '/api/projects'],
      ['POST', '/api/projects/proj_bench_1/deploy'],
      ['DELETE', '/api/projects/proj_bench_1/'],
      ['GET', '/api/databases/db1/CREDENTIALS']
    ];
    const routeT0 = process.hrtime.bigint();
    for (let i = 0; i < 1000; i++) {
      const [m, p] = routesToCheck[i % routesToCheck.length];
      const s = process.hrtime.bigint();
      tm.authorizeHttpRoute(devP, m, p);
      routeSamples.push(Number(process.hrtime.bigint() - s) / 1e6);
    }
    const routeTotalMs = Number(process.hrtime.bigint() - routeT0) / 1e6;
    routeSamples.sort((a, b) => a - b);

    // Instant session revocation latency
    const revSess = tm.login({ email: 'bench-dev@culkibo.local', password: 'BenchDevPassword!2026' });
    const revT0 = process.hrtime.bigint();
    tm.logoutSession(devAcc.user.id, revSess.sessionId);
    const revCheck = tm.verifySessionToken(revSess.sessionToken);
    const revocationMs = Number((Number(process.hrtime.bigint() - revT0) / 1e6).toFixed(3));
    if (revCheck.ok) throw new Error('Instant revocation failed in benchmark');

    const rbacBench = {
      sessionVerify500: {
        p50Ms: percentile(sessSamples, 50),
        p95Ms: percentile(sessSamples, 95),
        p99Ms: percentile(sessSamples, 99),
        opsPerSec: Math.round((500 / sessTotalMs) * 1000)
      },
      apiTokenVerify500: {
        p50Ms: percentile(apiSamples, 50),
        p95Ms: percentile(apiSamples, 95),
        p99Ms: percentile(apiSamples, 99),
        opsPerSec: Math.round((500 / apiTotalMs) * 1000)
      },
      routeAuthorize1000: {
        p50Ms: percentile(routeSamples, 50),
        p95Ms: percentile(routeSamples, 95),
        p99Ms: percentile(routeSamples, 99),
        opsPerSec: Math.round((1000 / routeTotalMs) * 1000)
      },
      instantRevocationMs: revocationMs
    };

    // =========================================================================
    // 2. Live Sync 2.0 Brotli Compression Ratio + 100-File Burst Throughput
    // =========================================================================
    const syncSrc = path.join(tmpRoot, 'sync-src');
    const syncDst = path.join(tmpRoot, 'sync-dst');
    fs.mkdirSync(syncSrc, { recursive: true });
    fs.mkdirSync(syncDst, { recursive: true });

    const burstFiles = [];
    let rawBytes = 0;
    for (let i = 0; i < 100; i++) {
      const content = [
        `import { useEffect, useState } from 'react';`,
        `export function ServiceCard${i}({ id, region }: { id: string; region: string }) {`,
        `  const [ready, setReady] = useState(true);`,
        ...Array.from({ length: 20 }, (_, j) =>
          `  const metric_${j} = \`svc-${i}-probe-${j}-\${id}-\${region}\`;`
        ),
        `  useEffect(() => { setReady(Boolean(id)); }, [id]);`,
        `  return <section className="rounded-lg border p-4">{id}:{region}:{String(ready)}</section>;`,
        `}\n`
      ].join('\n');
      const buf = Buffer.from(content, 'utf8');
      rawBytes += buf.length;
      burstFiles.push({ path: `src/cards/ServiceCard${i}.tsx`, op: 'upsert', buffer: buf, sha256: sha256(buf) });
    }

    const syncClient = new LiveSyncClient({ projectId: 'bench_sub_sync', sourceDir: syncSrc, targetDir: syncDst, autoWatch: false });
    syncClient.supportedCodecs = ['br', 'gzip'];
    syncClient.compression = 'auto';

    const syncEng = new LiveSyncEngine();
    syncEng.setTargetDir('bench_sub_sync', syncDst);

    const tEnc = process.hrtime.bigint();
    const wireFrame = syncClient.encodeBinaryFrame(1, burstFiles);
    const encMs = Number(process.hrtime.bigint() - tEnc) / 1e6;

    const tDec = process.hrtime.bigint();
    const decoded = decodeBinarySyncFrame(wireFrame);
    const decMs = Number(process.hrtime.bigint() - tDec) / 1e6;

    const tApp = process.hrtime.bigint();
    const appRes = syncEng.applyCommitFrame('bench_sub_sync', { seq: 1, files: decoded.files, _wireStats: decoded._wireStats });
    const appMs = Number(process.hrtime.bigint() - tApp) / 1e6;
    const totalSyncMs = encMs + decMs + appMs;

    const liveSyncBurstBench = {
      files: burstFiles.length,
      written: appRes.written,
      codec: decoded._wireStats.codec,
      rawBytes,
      wireBytes: wireFrame.length,
      savedPct: Number((((rawBytes - wireFrame.length) / rawBytes) * 100).toFixed(1)),
      compressionRatio: Number((rawBytes / wireFrame.length).toFixed(2)),
      encodeMs: Number(encMs.toFixed(2)),
      decodeMs: Number(decMs.toFixed(2)),
      applyMs: Number(appMs.toFixed(2)),
      totalMs: Number(totalSyncMs.toFixed(2)),
      filesPerSec: Math.round((burstFiles.length / totalSyncMs) * 1000),
      rawMbPerSec: Number(((rawBytes / (1024 * 1024)) / (totalSyncMs / 1000)).toFixed(2))
    };

    // =========================================================================
    // 3. YAML Parser Anti-DoS Timing (`parseSafeYaml` + `parseDockerCompose`)
    // =========================================================================
    const validManifest = [
      'version: 1',
      'name: bench-prod-stack',
      'vaultRefs:',
      '  - STRIPE_KEY',
      '  - DB_PASS',
      'projects:',
      ...Array.from({ length: 10 }, (_, i) => [
        `  - id: proj_${i}`,
        `    name: Service ${i}`,
        `    gitRepo: https://github.com/culkibo/svc-${i}.git`,
        `    gitBranch: main`,
        `    containerPort: ${3000 + i}`,
        `    env:`,
        `      NODE_ENV: production`,
        `      STRIPE_KEY: "\${vault.STRIPE_KEY}"`
      ].join('\n'))
    ].join('\n') + '\n';

    const validYamlSamples = [];
    for (let i = 0; i < 200; i++) {
      const s = process.hrtime.bigint();
      parseSafeYaml(validManifest);
      validYamlSamples.push(Number(process.hrtime.bigint() - s) / 1e6);
    }
    validYamlSamples.sort((a, b) => a - b);

    const hostileYamls = [
      ['billionLaughs', 'version: 1\na: &a [1,1,1,1]\nb: &b [*a,*a,*a,*a]\nc: [*b,*b,*b,*b]\n'],
      ['mergeKey', 'version: 1\n<<: base\n'],
      ['dangerousTag', 'version: 1\nx: !!js/function "()=>1"\n'],
      ['protoPollution', 'version: 1\n__proto__:\n  polluted: true\n'],
      ['oversize256Kb', 'version: 1\nbig: ' + 'X'.repeat(270 * 1024)],
      ['lines2050', Array.from({ length: 2050 }, (_, i) => `k${i}: v`).join('\n')],
      ['deepBlock18', Array.from({ length: 18 }, (_, i) => `${'  '.repeat(i)}d${i}:`).join('\n') + '\n' + '  '.repeat(18) + 'v: 1\n'],
      ['deepFlow20', 'version: 1\nx: ' + '['.repeat(20) + '1' + ']'.repeat(20) + '\n'],
      ['nodeBomb2100', 'version: 1\nx: [' + Array.from({ length: 2100 }, () => '1').join(',') + ']\n']
    ];
    /** @type {Record<string, number>} */
    const hostileTimings = {};
    let maxHostileMs = 0;
    for (const [label, payload] of hostileYamls) {
      const s = process.hrtime.bigint();
      let rejected = false;
      try { parseSafeYaml(payload); } catch (e) { rejected = true; }
      const ms = Number((Number(process.hrtime.bigint() - s) / 1e6).toFixed(3));
      if (!rejected) throw new Error(`YAML anti-DoS failed to reject ${label}`);
      hostileTimings[label] = ms;
      maxHostileMs = Math.max(maxHostileMs, ms);
    }
    const tComp = process.hrtime.bigint();
    let compRejected = false;
    try { parseDockerCompose('services:\n  a:\n    image: ' + 'x'.repeat(530 * 1024)); } catch (e) { compRejected = true; }
    const composeOversizeMs = Number((Number(process.hrtime.bigint() - tComp) / 1e6).toFixed(3));
    if (!compRejected) throw new Error('parseDockerCompose failed to reject >512 KB payload');

    const yamlAntiDosBench = {
      validParse200: {
        p50Ms: percentile(validYamlSamples, 50),
        p95Ms: percentile(validYamlSamples, 95)
      },
      hostileVectorsRejected: hostileYamls.length + 1,
      maxHostileRejectMs: Number(Math.max(maxHostileMs, composeOversizeMs).toFixed(3)),
      composeOversizeRejectMs: composeOversizeMs,
      byVectorMs: hostileTimings
    };

    // =========================================================================
    // 4. Persistence Throughput Under Concurrent Writes (Atomic JSON + SQLite WAL)
    // =========================================================================
    const pmDir = path.join(tmpRoot, 'pm-persist');
    fs.mkdirSync(pmDir, { recursive: true });
    const pmFile = path.join(pmDir, 'projects.json');
    const isoPm = createIsolatedProjectManager(pmFile);
    const jsonWrites = 100;
    const tJson0 = process.hrtime.bigint();
    await Promise.all(
      Array.from({ length: jsonWrites }, (_, i) => {
        const proj = new Project({ id: `bench_p_${i}`, name: `Bench Project ${i}`, description: 'Atomic Group Commit write' });
        isoPm.projects.set(proj.id, proj);
        return isoPm.flushToDisk(proj.id);
      })
    );
    const jsonTotalMs = Number(process.hrtime.bigint() - tJson0) / 1e6;
    const diskCount = JSON.parse(fs.readFileSync(pmFile, 'utf8')).length;
    if (diskCount !== jsonWrites) throw new Error(`Expected ${jsonWrites} projects persisted, found ${diskCount}`);

    // Native `node:sqlite` WAL throughput (TelemetryStorage)
    const sqlDir = path.join(tmpRoot, 'sqlite-wal');
    const storage = new TelemetryStorage({
      dbPath: path.join(sqlDir, 'bench.sqlite'),
      archiveDir: path.join(sqlDir, 'archive')
    });
    const envelopesCount = 200;
    const eventsPerEnvelope = 3;
    const sqlSamples = [];
    const nowIso = new Date().toISOString();
    const tSql0 = process.hrtime.bigint();
    for (let i = 0; i < envelopesCount; i++) {
      const s = process.hrtime.bigint();
      storage.ingestEnvelope({
        instanceId: `inst-bench-${i % 20}`,
        appVersion: '1.0.0',
        receivedAt: nowIso,
        events: [
          { eventId: `ev_${i}_1`, type: 'api_5xx', ts: nowIso, fingerprint: `fp_${i % 15}`, title: 'HTTP 500', occurrences: 1, data: { route: '/api/deploy', status: 500 } },
          { eventId: `ev_${i}_2`, type: 'operation_failure', ts: nowIso, fingerprint: `op_${i % 10}`, title: 'build fail', occurrences: 1, data: { operation: 'deploy', stage: 'build' } },
          { eventId: `ev_${i}_3`, type: 'feature_usage', ts: nowIso, fingerprint: null, title: 'deploy:node', occurrences: 1, data: { feature: 'deploy:node', ok: true } }
        ]
      });
      sqlSamples.push(Number(process.hrtime.bigint() - s) / 1e6);
    }
    const sqlTotalMs = Number(process.hrtime.bigint() - tSql0) / 1e6;
    sqlSamples.sort((a, b) => a - b);
    storage.close();

    const persistenceBench = {
      atomicJsonConcurrent: {
        concurrentWrites: jsonWrites,
        persistedCount: diskCount,
        totalMs: Number(jsonTotalMs.toFixed(2)),
        writesPerSec: Math.round((jsonWrites / jsonTotalMs) * 1000)
      },
      sqliteWal: {
        envelopes: envelopesCount,
        events: envelopesCount * eventsPerEnvelope,
        totalMs: Number(sqlTotalMs.toFixed(2)),
        envelopesPerSec: Math.round((envelopesCount / sqlTotalMs) * 1000),
        eventsPerSec: Math.round(((envelopesCount * eventsPerEnvelope) / sqlTotalMs) * 1000),
        p50Ms: percentile(sqlSamples, 50),
        p95Ms: percentile(sqlSamples, 95)
      }
    };

    // =========================================================================
    // 5. Backup SHA-256 + AES-256-GCM Encryption / Decryption Throughput
    // =========================================================================
    const payloadSizeMb = 4;
    const payloadBuf = crypto.randomBytes(payloadSizeMb * 1024 * 1024);
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);

    const tSha = process.hrtime.bigint();
    const digest = crypto.createHash('sha256').update(payloadBuf).digest('hex');
    const shaMs = Number(process.hrtime.bigint() - tSha) / 1e6;

    const tEncGcm = process.hrtime.bigint();
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
    const ct = Buffer.concat([cipher.update(payloadBuf), cipher.final()]);
    const tag = cipher.getAuthTag();
    const encGcmMs = Number(process.hrtime.bigint() - tEncGcm) / 1e6;

    const tDecGcm = process.hrtime.bigint();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    const decGcmMs = Number(process.hrtime.bigint() - tDecGcm) / 1e6;
    if (pt.length !== payloadBuf.length || !digest) throw new Error('AES-256-GCM roundtrip mismatch');

    // Measure scrypt KDF (N=16384, r=8, p=1) separately for full transparency
    const tKdf = process.hrtime.bigint();
    crypto.scryptSync('BenchBackupPassphrase!2026', crypto.randomBytes(16), 32, { N: 16384, r: 8, p: 1 });
    const scryptKdfMs = Number((Number(process.hrtime.bigint() - tKdf) / 1e6).toFixed(2));

    // Real end-to-end dbBackupManager snapshot export + encrypted dryRun import
    const tSnap0 = process.hrtime.bigint();
    const snap = await dbBackupManager.exportInstanceSnapshot({
      includeSecrets: true,
      passphrase: 'BenchBackupPassphrase!2026',
      persist: false
    });
    const snapExportMs = Number((Number(process.hrtime.bigint() - tSnap0) / 1e6).toFixed(2));
    const tSnapImp0 = process.hrtime.bigint();
    const snapImp = await dbBackupManager.importInstanceSnapshot({
      snapshot: snap.snapshot,
      passphrase: 'BenchBackupPassphrase!2026',
      dryRun: true
    });
    const snapImportMs = Number((Number(process.hrtime.bigint() - tSnapImp0) / 1e6).toFixed(2));
    if (!snapImp.success) throw new Error('Encrypted snapshot dryRun import failed');

    const backupCryptoBench = {
      payloadMb: payloadSizeMb,
      sha256Ms: Number(shaMs.toFixed(2)),
      sha256MbPerSec: Number((payloadSizeMb / (shaMs / 1000)).toFixed(1)),
      aes256GcmEncryptMs: Number(encGcmMs.toFixed(2)),
      aes256GcmEncryptMbPerSec: Number((payloadSizeMb / (encGcmMs / 1000)).toFixed(1)),
      aes256GcmDecryptMs: Number(decGcmMs.toFixed(2)),
      aes256GcmDecryptMbPerSec: Number((payloadSizeMb / (decGcmMs / 1000)).toFixed(1)),
      scryptKdfN16384Ms: scryptKdfMs,
      instanceSnapshotExportMs: snapExportMs,
      instanceSnapshotDryImportMs: snapImportMs
    };

    // =========================================================================
    // 6. 500-Request Authenticated HTTP P50 / P95 / P99 (Real Express + RBAC)
    // =========================================================================
    const app = express();
    app.use((req, _res, next) => {
      Object.defineProperty(req.socket, 'remoteAddress', { value: '203.0.113.99', configurable: true });
      next();
    });
    app.use('/api', auth.authMiddleware, auth.requireRouteRbac({ teamManager: tm }));
    app.get('/api/projects', (_req, res) => res.json({ ok: true, count: 10 }));
    app.post('/api/projects/:id/deploy', (_req, res) => res.json({ ok: true, queued: true }));
    app.delete('/api/projects/:id', (_req, res) => res.json({ deleted: true }));

    auth._setTeamManagerForTest(tm);
    const srv = await new Promise((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const httpPort = /** @type {import('net').AddressInfo} */ (srv.address()).port;
    const agent = new http.Agent({ keepAlive: true, maxSockets: httpWorkers });

    const reqMatrix = [
      { method: 'GET', path: '/api/projects', token: devAcc.sessionToken, expect: 200 },
      { method: 'GET', path: '/api/projects', token: apiTok.token, expect: 200 },
      { method: 'POST', path: '/api/projects/proj_bench_1/deploy', token: devAcc.sessionToken, expect: 200 },
      { method: 'DELETE', path: '/api/projects/proj_bench_1', token: devAcc.sessionToken, expect: 403 }
    ];

    const doAuthedReq = (spec) => new Promise((resolve) => {
      const s = process.hrtime.bigint();
      const req = http.request({
        host: '127.0.0.1',
        port: httpPort,
        path: spec.path,
        method: spec.method,
        agent,
        headers: {
          Host: 'panel.example.com',
          Authorization: `Bearer ${spec.token}`
        }
      }, (res) => {
        res.on('data', () => {});
        res.on('end', () => {
          resolve({
            ok: res.statusCode === spec.expect,
            status: res.statusCode,
            ms: Number(process.hrtime.bigint() - s) / 1e6
          });
        });
      });
      req.on('error', () => resolve({ ok: false, status: 0, ms: Number(process.hrtime.bigint() - s) / 1e6 }));
      req.end();
    });

    let authedHttpBench;
    try {
      // Warmup
      for (const spec of reqMatrix) await doAuthedReq(spec);

      const lat = [];
      let failures = 0;
      let cursor = 0;
      const tHttp0 = process.hrtime.bigint();
      await Promise.all(Array.from({ length: Math.min(httpWorkers, httpRequests) }, async () => {
        while (true) {
          const i = cursor++;
          if (i >= httpRequests) break;
          const r = await doAuthedReq(reqMatrix[i % reqMatrix.length]);
          if (!r.ok) failures++;
          else lat.push(r.ms);
        }
      }));
      const httpTotalMs = Number(process.hrtime.bigint() - tHttp0) / 1e6;
      lat.sort((a, b) => a - b);

      authedHttpBench = {
        requests: httpRequests,
        workers: httpWorkers,
        failures,
        totalMs: Number(httpTotalMs.toFixed(1)),
        rps: Math.round((httpRequests / httpTotalMs) * 1000),
        p50Ms: percentile(lat, 50),
        p95Ms: percentile(lat, 95),
        p99Ms: percentile(lat, 99),
        maxMs: percentile(lat, 100)
      };
    } finally {
      agent.destroy();
      auth._setTeamManagerForTest(null);
      auth.resetAuthRateLimit();
      await new Promise((r) => srv.close(() => r(undefined)));
    }

    const summary = {
      rbacAuth: rbacBench,
      liveSyncBurst100: liveSyncBurstBench,
      yamlAntiDos: yamlAntiDosBench,
      persistence: persistenceBench,
      backupCrypto: backupCryptoBench,
      authedHttp500: authedHttpBench
    };

    if (!silent) {
      console.log('\n════════════════════════════════════════════════════════════');
      console.log('  Culkibo · Banco de pruebas: Subsistemas críticos (6 métricas)');
      console.log('════════════════════════════════════════════════════════════\n');
      console.log(`  1. RBAC Auth & Revocación`);
      console.log(`       cks_ session verify (500x)    p50 ${rbacBench.sessionVerify500.p50Ms}ms · p95 ${rbacBench.sessionVerify500.p95Ms}ms · ${rbacBench.sessionVerify500.opsPerSec} ops/s`);
      console.log(`       ckp_ API token verify (500x)  p50 ${rbacBench.apiTokenVerify500.p50Ms}ms · p95 ${rbacBench.apiTokenVerify500.p95Ms}ms · ${rbacBench.apiTokenVerify500.opsPerSec} ops/s`);
      console.log(`       route RBAC check (1000x)      p50 ${rbacBench.routeAuthorize1000.p50Ms}ms · p95 ${rbacBench.routeAuthorize1000.p95Ms}ms · ${rbacBench.routeAuthorize1000.opsPerSec} ops/s`);
      console.log(`       revocación inmediata          ${rbacBench.instantRevocationMs} ms`);
      console.log(`  2. Live Sync 2.0 (100 ficheros TSX, ${(rawBytes / 1024).toFixed(1)} KB -> ${liveSyncBurstBench.wireBytes} B ${liveSyncBurstBench.codec})`);
      console.log(`       ahorro Brotli                 ${liveSyncBurstBench.savedPct}% (${liveSyncBurstBench.compressionRatio}x) · ${liveSyncBurstBench.totalMs}ms total (${liveSyncBurstBench.filesPerSec} files/s · ${liveSyncBurstBench.rawMbPerSec} MB/s)`);
      console.log(`  3. Parser YAML Anti-DoS`);
      console.log(`       manifiesto válido (200x)      p50 ${yamlAntiDosBench.validParse200.p50Ms}ms · p95 ${yamlAntiDosBench.validParse200.p95Ms}ms`);
      console.log(`       ${yamlAntiDosBench.hostileVectorsRejected} vectores hostiles          max ${yamlAntiDosBench.maxHostileRejectMs} ms (0 cuelgues)`);
      console.log(`  4. Persistencia concurrente`);
      console.log(`       Atomic JSON (100 writes)      ${persistenceBench.atomicJsonConcurrent.totalMs}ms (${persistenceBench.atomicJsonConcurrent.writesPerSec} writes/s, 100/100 íntegros)`);
      console.log(`       SQLite WAL (200 env / 600 ev) ${persistenceBench.sqliteWal.totalMs}ms (${persistenceBench.sqliteWal.eventsPerSec} events/s, p95 ${persistenceBench.sqliteWal.p95Ms}ms)`);
      console.log(`  5. Criptografía de copias (${payloadSizeMb} MiB payload)`);
      console.log(`       SHA-256                       ${backupCryptoBench.sha256MbPerSec} MB/s (${backupCryptoBench.sha256Ms}ms)`);
      console.log(`       AES-256-GCM enc / dec         ${backupCryptoBench.aes256GcmEncryptMbPerSec} MB/s / ${backupCryptoBench.aes256GcmDecryptMbPerSec} MB/s · scrypt KDF ${backupCryptoBench.scryptKdfN16384Ms}ms`);
      console.log(`       Snapshot DR export / dryRun   ${backupCryptoBench.instanceSnapshotExportMs}ms / ${backupCryptoBench.instanceSnapshotDryImportMs}ms`);
      console.log(`  6. HTTP autenticado RBAC (${httpRequests} req, ${httpWorkers} workers)`);
      console.log(`       latencia                      p50 ${authedHttpBench.p50Ms}ms · p95 ${authedHttpBench.p95Ms}ms · p99 ${authedHttpBench.p99Ms}ms · ${authedHttpBench.rps} req/s · ${authedHttpBench.failures} fallos\n`);
    }

    return summary;
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  const asJson = process.argv.includes('--json');
  run({ silent: asJson }).then((res) => {
    if (asJson) process.stdout.write(JSON.stringify(res, null, 2) + '\n');
    process.exit(0);
  }).catch((err) => {
    console.error('❌ Fallo en bench/subsystems.bench.js:', err);
    process.exit(1);
  });
}

module.exports = run;
