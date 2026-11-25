const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const express = require('express');

const projectManager = require('../server/services/projectManager');
const Project = require('../server/models/Project');
const { UptimeMonitor } = require('../server/services/uptimeMonitor');
const { PreviewManager } = require('../server/services/previewManager');
const { CronManager } = require('../server/services/cronManager');
const { TeamManager, DEFAULT_TEAM_ID } = require('../server/services/teamManager');
const { EnvironmentManager } = require('../server/services/environmentManager');
const { parseSafeYaml } = require('../server/services/gitopsManager');
const { parseDockerCompose } = require('../server/services/universalImporter');
const { parseCron, nextCronRun } = require('../server/services/cronParser');
const liveSyncEngine = require('../server/services/liveSyncEngine');
const {
  LiveSyncEngine,
  resolveSafeFilePath,
  decodeCompressedPayload,
  decodeBinarySyncFrame
} = liveSyncEngine;
const localRunner = require('../server/services/localRunner');
const dbBackupManager = require('../server/services/dbBackupManager');
const ssrfGuard = require('../server/services/ssrfGuard');
const auth = require('../server/middleware/auth');
const { TelemetryService } = require('../server/services/telemetryService');
const { TelemetryStorage } = require('../telemetry-collector/lib/storage');

/**
 * Crea una instancia completamente aislada de ProjectManager apuntando a `tmpFile`
 * sin tocar jamás el `data/projects.json` real del workspace.
 * @param {string} tmpFile
 */
function createIsolatedProjectManager(tmpFile) {
  const pm = Object.create(Object.getPrototypeOf(projectManager));
  // Inicializar EventEmitter
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
 * Suite #30: Pruebas Adversariales, Fuzzing, Crash-Recovery (.bak) y Concurrencia.
 *
 * 100% hermética: todo se ejecuta dentro de `os.tmpdir()` sin tocar `data/*.json`.
 * 0 dependencias externas, compatible con Windows (junctions + `..\\`) y Linux.
 */
async function testAdversarialFuzz() {
  console.log('\n🛡️  Running Adversarial, Fuzzing, Crash-Recovery & Concurrency Suite...');
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-adv-fuzz-'));

  try {
    // =========================================================================
    // 1. Corrupt & Truncated JSON Crash-Recovery (.bak) + Stale .tmp Cleanup
    // =========================================================================
    {
      // 1a. ProjectManager: truncated JSON, non-array JSON, empty file -> recovers from .bak + cleans stale .tmp
      const pmDir = path.join(tmpRoot, 'pm-recovery');
      fs.mkdirSync(pmDir, { recursive: true });
      const pmFile = path.join(pmDir, 'projects.json');
      const pmBak = `${pmFile}.bak`;

      const pGood = [
        new Project({ id: 'proj_rec_1', name: 'Recovered Alpha', localRunning: true }),
        new Project({ id: 'proj_rec_2', name: 'Recovered Beta', localRunning: true })
      ];
      fs.writeFileSync(pmBak, JSON.stringify(pGood, null, 2), 'utf8');

      // Plant stale .tmp files left by interrupted atomic flushes
      const staleTmps = [
        path.join(pmDir, 'projects.json.111_abc.tmp'),
        path.join(pmDir, 'projects.json.222_def.tmp'),
        path.join(pmDir, 'projects.json.333_ghi.tmp')
      ];
      for (const f of staleTmps) fs.writeFileSync(f, '{"partial":', 'utf8');

      for (const corruptPayload of ['[{"id":"proj_bad","name":"Trunc', '{}', '', '   \n\t  ', 'null']) {
        fs.writeFileSync(pmFile, corruptPayload, 'utf8');
        const pm = createIsolatedProjectManager(pmFile);
        pm.loadProjects();
        assert.strictEqual(pm.getAll().length, 2, `ProjectManager must recover 2 projects from .bak on corrupt input ${JSON.stringify(corruptPayload)}`);
        assert.strictEqual(pm.getById('proj_rec_1').name, 'Recovered Alpha');
        assert.strictEqual(pm.getById('proj_rec_1').localRunning, false, 'Boot sanitation must clear stale localRunning');
      }
      for (const f of staleTmps) {
        assert.strictEqual(fs.existsSync(f), false, `Stale temp file ${path.basename(f)} must be cleaned on boot`);
      }

      // 1b. UptimeMonitor: corrupt uptime.json -> recovers cleanly from uptime.json.bak
      const upFile = path.join(tmpRoot, 'uptime-recovery', 'uptime.json');
      fs.mkdirSync(path.dirname(upFile), { recursive: true });
      const u1 = new UptimeMonitor({
        storeFile: upFile,
        autoStart: false,
        assertSafeUrl: async (u) => ({ url: new URL(u), addresses: ['93.184.216.34'] })
      });
      await u1.createMonitor({ name: 'Mon Alpha', type: 'http', url: 'https://example.com/health', intervalSec: 60 });
      await u1.createMonitor({ name: 'Mon Beta', type: 'http', url: 'https://example.com/status', intervalSec: 60 });
      u1.saveStatusPage({ slug: 'rec-status', title: 'Recovery Status', monitorIds: u1.listMonitors().map((m) => m.id), published: true });
      u1.stop();
      assert.ok(fs.existsSync(`${upFile}.bak`), 'uptime.json.bak must exist before corrupting primary');
      fs.writeFileSync(upFile, '{"monitors":[{"id":"truncated', 'utf8');
      const u2 = new UptimeMonitor({ storeFile: upFile, autoStart: false });
      assert.ok(u2.listMonitors().length >= 2, 'UptimeMonitor must recover monitors from .bak after primary corruption');
      u2.stop();

      // 1c. PreviewManager: corrupt previews.json -> recovers from previews.json.bak
      const prevFile = path.join(tmpRoot, 'prev-recovery', 'previews.json');
      fs.mkdirSync(path.dirname(prevFile), { recursive: true });
      const pm1 = new PreviewManager(prevFile);
      pm1._ensureLoaded();
      pm1.store = { proj_1: { 'pr-10': { key: 'pr-10', projectId: 'proj_1', hostname: 'pr-10.example.test', status: 'active' } } };
      pm1.save();
      pm1.store.proj_1['pr-11'] = { key: 'pr-11', projectId: 'proj_1', hostname: 'pr-11.example.test', status: 'active' };
      pm1.save(); // Second save copies previous valid JSON to .bak
      assert.ok(fs.existsSync(`${prevFile}.bak`), 'previews.json.bak must exist');
      fs.writeFileSync(prevFile, '{corrupt json!!!', 'utf8');
      const pm2 = new PreviewManager(prevFile);
      assert.ok(pm2.get('proj_1', 'pr-10'), 'PreviewManager must recover from previews.json.bak');

      // 1d. CronManager: corrupt crons.json -> recovers from .bak or stays safe without crash
      const cronFile = path.join(tmpRoot, 'cron-recovery', 'crons.json');
      fs.mkdirSync(path.dirname(cronFile), { recursive: true });
      const cm1 = new CronManager(cronFile);
      cm1.create('proj_c', { name: 'Job 1', schedule: '0 * * * *', mode: 'http', httpPath: '/ok' });
      cm1.create('proj_c', { name: 'Job 2', schedule: '30 * * * *', mode: 'http', httpPath: '/ok2' });
      fs.writeFileSync(cronFile, '[{"id":"broken', 'utf8');
      const cm2 = new CronManager(cronFile);
      assert.ok(Array.isArray(cm2.list('proj_c')), 'CronManager must not crash on corrupt crons.json');

      // 1e. TeamManager: corrupt teams.json recovers from .bak; BOTH corrupt fails CLOSED (RBAC_STORE_CORRUPT)
      const tmDir = path.join(tmpRoot, 'tm-recovery');
      fs.mkdirSync(tmDir, { recursive: true });
      const tm1 = new TeamManager({ dataDir: tmDir, bcryptCost: 4 });
      const boot = tm1.bootstrapOwner({ email: 'owner@rec.local', password: 'StrongPassword!2026' });
      const ownerP = tm1.verifySessionToken(boot.sessionToken).principal;
      tm1.createInvite(ownerP, { email: 'u2@rec.local', role: 'viewer' }); // ensures .bak written with valid owner
      const teamsPath = path.join(tmDir, 'teams.json');
      const teamsBak = `${teamsPath}.bak`;
      assert.ok(fs.existsSync(teamsBak), 'teams.json.bak must exist after second write');
      fs.writeFileSync(teamsPath, '{"users":[broken', 'utf8');
      const tm2 = new TeamManager({ dataDir: tmDir, bcryptCost: 4 });
      assert.strictEqual(tm2.isMultiUserEnabled(), true, 'TeamManager must recover valid state from teams.json.bak');
      assert.strictEqual(tm2.verifySessionToken(boot.sessionToken).ok, true, 'Owner session must still verify after .bak recovery');

      // Corrupt BOTH primary and .bak -> MUST fail closed, never revert to unauthenticated mode
      fs.writeFileSync(teamsPath, 'CORRUPT_PRIMARY', 'utf8');
      fs.writeFileSync(teamsBak, 'CORRUPT_BACKUP', 'utf8');
      const tm3 = new TeamManager({ dataDir: tmDir, bcryptCost: 4 });
      assert.throws(
        () => tm3.verifySessionToken(boot.sessionToken),
        (err) => err && err.code === 'RBAC_STORE_CORRUPT',
        'Dual-corrupt teams.json + .bak must fail closed with RBAC_STORE_CORRUPT'
      );

      // 1f. TelemetryStorage SQLite WAL close/reopen durability
      const sqlDir = path.join(tmpRoot, 'sqlite-durability');
      const dbPath = path.join(sqlDir, 'telemetry.sqlite');
      const archiveDir = path.join(sqlDir, 'archive');
      const st1 = new TelemetryStorage({ dbPath, archiveDir });
      const iid = crypto.randomUUID();
      st1.ingestEnvelope({
        instanceId: iid,
        appVersion: '1.0.0',
        receivedAt: new Date().toISOString(),
        events: [{
          eventId: crypto.randomUUID(),
          type: 'server_crash',
          ts: new Date().toISOString(),
          fingerprint: 'fp_durability_01',
          title: 'Error: durability probe',
          occurrences: 1,
          data: { kind: 'uncaughtException', errorName: 'Error', message: 'durability probe', stack: [] }
        }]
      });
      st1.close();
      const st2 = new TelemetryStorage({ dbPath, archiveDir });
      const sum = st2.getSummary();
      assert.strictEqual(sum.kpis.openCrashes, 1, 'SQLite WAL must preserve committed rows across close/reopen');
      st2.close();

      console.log('  ✓ 1. Crash-recovery (.bak + stale .tmp + fail-closed RBAC + SQLite WAL) verified across 6 stores');
    }

    // =========================================================================
    // 2. Real Symlink / Junction Escape Attacks (Live Sync + LocalRunner Static)
    // =========================================================================
    {
      const symRoot = path.join(tmpRoot, 'symlink-escape');
      const outsideDir = path.join(symRoot, 'outside-secret');
      const targetDir = path.join(symRoot, 'project-root');
      fs.mkdirSync(outsideDir, { recursive: true });
      fs.mkdirSync(targetDir, { recursive: true });

      const secretOutsideFile = path.join(outsideDir, 'secret.txt');
      fs.writeFileSync(secretOutsideFile, 'CULKIBO_SYMLINK_CANARY_999', 'utf8');
      fs.writeFileSync(path.join(targetDir, 'index.html'), '<h1>SAFE_INDEX</h1>', 'utf8');

      // Directory link (`junction` works unprivileged on Windows; `dir` on POSIX)
      const dirEscapeLink = path.join(targetDir, 'escape-dir');
      fs.symlinkSync(outsideDir, dirEscapeLink, process.platform === 'win32' ? 'junction' : 'dir');

      // 2a. LiveSyncEngine resolveSafeFilePath & applyCommitFrame MUST block directory symlink escape
      assert.throws(
        () => resolveSafeFilePath(targetDir, 'escape-dir/pwned.txt'),
        (err) => err && err.code === 'PATH_TRAVERSAL_BLOCKED',
        'resolveSafeFilePath must block writes through directory symlink/junction'
      );

      const isolatedSync = new LiveSyncEngine();
      isolatedSync.setTargetDir('adv_symlink_proj', targetDir);
      assert.throws(
        () => isolatedSync.applyCommitFrame('adv_symlink_proj', {
          seq: 1,
          files: [{ path: 'escape-dir/pwned.txt', op: 'upsert', content: 'HACKED_OUTSIDE' }]
        }),
        (err) => err && err.code === 'PATH_TRAVERSAL_BLOCKED',
        'applyCommitFrame must reject symlink directory escape'
      );
      assert.strictEqual(fs.existsSync(path.join(outsideDir, 'pwned.txt')), false, 'Outside directory must remain untouched');

      // 2b. Leaf file symlink check (when OS grants file symlink privilege)
      let leafTested = false;
      const leafLink = path.join(targetDir, 'leaf-escape.txt');
      try {
        fs.symlinkSync(secretOutsideFile, leafLink, 'file');
        leafTested = true;
      } catch (e) {
        // Unprivileged Windows without Developer Mode may reject file symlinks with EPERM; junction test above already proves realpath enforcement
      }
      if (leafTested) {
        assert.throws(
          () => resolveSafeFilePath(targetDir, 'leaf-escape.txt'),
          (err) => err && err.code === 'PATH_TRAVERSAL_BLOCKED',
          'resolveSafeFilePath must reject leaf file symlink'
        );
      }

      // 2c. LocalRunner static HTTP server MUST block GET through symlink/junction with 403
      const symPort = await localRunner.getAvailablePort(18700);
      await localRunner.startStaticProject({ id: 'adv_symlink_static', name: 'Symlink Test' }, targetDir, symPort);
      try {
        const res = await fetch(`http://127.0.0.1:${symPort}/escape-dir/secret.txt`);
        const body = await res.text();
        assert.strictEqual(res.status, 403, `Static server must return 403 on symlink escape, got ${res.status}`);
        assert.ok(!body.includes('CULKIBO_SYMLINK_CANARY_999'), 'Static server must never leak symlinked outside file');
      } finally {
        await localRunner.stop('adv_symlink_static');
      }

      console.log(`  ✓ 2. Real symlink/junction escapes blocked in Live Sync & LocalRunner static (HTTP 403${leafTested ? ' + leaf file symlink' : ''})`);
    }

    // =========================================================================
    // 3. Live Sync 2.0 Binary WS Frame Fuzzer (25+ Hostile / Truncated Frames)
    // =========================================================================
    {
      const t0 = performance.now();
      const allowedCodes = new Set(['BAD_FRAME', 'FRAME_TOO_LARGE', 'UNSUPPORTED_CODEC']);

      const assertFrameRejected = (buf, label, maxOut = undefined) => {
        let threw = false;
        try {
          decodeBinarySyncFrame(buf, maxOut);
        } catch (err) {
          threw = true;
          assert.ok(err && allowedCodes.has(err.code), `${label}: unexpected error code ${err && err.code} (${err && err.message})`);
        }
        assert.strictEqual(threw, true, `${label}: hostile frame MUST be rejected`);
      };

      // Non-buffers & truncated headers
      for (const bad of [null, undefined, 'string', {}, Buffer.alloc(0), Buffer.from([0x01]), Buffer.from([0x01, 0, 0, 1])]) {
        assertFrameRejected(bad, `non-buf/short ${String(bad)}`);
      }
      // Invalid magic opcodes
      for (const op of [0x00, 0x04, 0x7f, 0xfe, 0xff]) {
        assertFrameRejected(Buffer.from([op, 0, 0, 0, 2, 0x7b, 0x7d]), `bad-magic-0x${op.toString(16)}`);
      }
      // Raw frame metaLen overflow / >2 MiB / truncated / invalid JSON / non-object JSON
      const mkRaw = (metaLen, tailBuf) => {
        const b = Buffer.alloc(5 + tailBuf.length);
        b[0] = 0x01;
        b.writeUInt32BE(metaLen >>> 0, 1);
        tailBuf.copy(b, 5);
        return b;
      };
      assertFrameRejected(mkRaw(0xffffffff, Buffer.from('{}')), 'metaLen-uint32-max');
      assertFrameRejected(mkRaw(3 * 1024 * 1024, Buffer.from('{}')), 'metaLen-gt-2mb');
      assertFrameRejected(mkRaw(100, Buffer.from('{"seq":1}')), 'metaLen-truncated');
      assertFrameRejected(mkRaw(4, Buffer.from('{bad')), 'meta-invalid-json');
      assertFrameRejected(mkRaw(4, Buffer.from('null')), 'meta-json-null');
      assertFrameRejected(mkRaw(3, Buffer.from('123')), 'meta-json-number');

      // Out-of-bounds / negative / fractional / non-numeric file byteLength
      for (const bl of [999999, -5, 1.5, 'not-a-number']) {
        const m = Buffer.from(JSON.stringify({ seq: 1, files: [{ path: 'a.js', op: 'upsert', byteLength: bl }] }));
        assertFrameRejected(mkRaw(m.length, m), `bad-byteLength-${bl}`);
      }

      // Compressed (0x02 Brotli & 0x03 Gzip) corrupt streams, bogus rawLen, rawLen mismatch, zip-bomb
      const validInner = Buffer.concat([Buffer.from([0, 0, 0, 2]), Buffer.from('{}')]);
      const validBr = zlib.brotliCompressSync(validInner);
      const validGz = zlib.gzipSync(validInner);
      const mkComp = (magic, rawLen, payload) => {
        const h = Buffer.alloc(5);
        h[0] = magic;
        h.writeUInt32BE(rawLen >>> 0, 1);
        return Buffer.concat([h, payload]);
      };
      for (const magic of [0x02, 0x03]) {
        assertFrameRejected(mkComp(magic, 0, Buffer.from('junk')), `comp-${magic}-rawLen-0`);
        assertFrameRejected(mkComp(magic, 4, Buffer.from('junk')), `comp-${magic}-rawLen-4`);
        assertFrameRejected(mkComp(magic, 64 * 1024 * 1024, Buffer.from('junk')), `comp-${magic}-rawLen-64mb`);
        assertFrameRejected(mkComp(magic, 100, Buffer.from('not-valid-compressed-stream-xyz')), `comp-${magic}-corrupt-stream`);
      }
      // Declared rawLen mismatch (actual is 6 bytes, header lies 50 bytes)
      assertFrameRejected(mkComp(0x02, 50, validBr), 'br-rawLen-mismatch');
      assertFrameRejected(mkComp(0x03, 50, validGz), 'gz-rawLen-mismatch');

      // 4 MiB Brotli & Gzip zip-bombs capped at 64 KiB
      const bomb = Buffer.alloc(4 * 1024 * 1024, 0x5a);
      const bombBr = zlib.brotliCompressSync(bomb);
      const bombGz = zlib.gzipSync(bomb);
      assert.throws(
        () => decodeCompressedPayload(0x02, bombBr, 64 * 1024),
        (e) => e && e.code === 'FRAME_TOO_LARGE'
      );
      assert.throws(
        () => decodeCompressedPayload(0x03, bombGz, 64 * 1024),
        (e) => e && e.code === 'FRAME_TOO_LARGE'
      );
      assert.throws(
        () => decodeCompressedPayload(0x99, Buffer.from('x'), 1024),
        (e) => e && e.code === 'UNSUPPORTED_CODEC'
      );

      const fuzzMs = Number((performance.now() - t0).toFixed(1));
      assert.ok(fuzzMs < 2000, `Binary frame fuzzing took too long: ${fuzzMs}ms`);
      console.log(`  ✓ 3. Live Sync 2.0 binary WS fuzzer (29 hostile frames + 4 MiB br/gz zip-bombs rejected in ${fuzzMs}ms)`);
    }

    // =========================================================================
    // 4. YAML & Docker Compose Anti-DoS + Prototype Pollution Fuzzer
    // =========================================================================
    {
      const yamlVectors = [
        ['billion-laughs', 'version: 1\na: &a [1,1,1,1]\nb: &b [*a,*a,*a,*a]\nc: [*b,*b,*b,*b]\n'],
        ['merge-key', 'version: 1\n<<: base\n'],
        ['tag-js-fn', 'version: 1\nx: !!js/function "()=>1"\n'],
        ['tag-include', 'version: 1\nx: !include /etc/passwd\n'],
        ['proto-block', 'version: 1\n__proto__:\n  polluted: true\n'],
        ['constructor-block', 'version: 1\nconstructor:\n  prototype:\n    polluted: true\n'],
        ['proto-inline', 'version: 1\nmeta: { __proto__: { polluted: true } }\n'],
        ['oversize-256kb', 'version: 1\nbig: ' + 'A'.repeat(270 * 1024)],
        ['lines-gt-2000', Array.from({ length: 2050 }, (_, i) => `k${i}: v`).join('\n')],
        ['deep-block', Array.from({ length: 18 }, (_, i) => `${'  '.repeat(i)}d${i}:`).join('\n') + '\n' + '  '.repeat(18) + 'v: 1\n'],
        ['deep-flow', 'version: 1\nx: ' + '['.repeat(20) + '1' + ']'.repeat(20) + '\n'],
        ['node-bomb', 'version: 1\nx: [' + Array.from({ length: 2100 }, () => '1').join(',') + ']\n'],
        ['tab-indent', 'version: 1\n\tbad: 1\n'],
        ['multi-doc', '---\nversion: 1\n---\nversion: 2\n']
      ];
      for (const [name, payload] of yamlVectors) {
        const s = performance.now();
        assert.throws(() => parseSafeYaml(payload), `parseSafeYaml must reject ${name}`);
        const dt = performance.now() - s;
        assert.ok(dt < 100, `parseSafeYaml(${name}) took ${dt.toFixed(1)}ms (>100ms anti-DoS budget)`);
      }

      // Universal Importer Docker Compose DoS + Prototype Pollution + ReDoS
      assert.throws(() => parseDockerCompose(''), /Pega|vací|compose/i);
      assert.throws(() => parseDockerCompose('services:\n  a:\n    image: ' + 'x'.repeat(530 * 1024)), /512 KB/i);

      const hostileCompose = [
        'x-common: &evil',
        '  environment: { __proto__: polluted, constructor: hacked, SAFE_KEY: ok }',
        'services:',
        '  web:',
        '    <<: *evil',
        '    image: node:22-alpine',
        '    environment:',
        '      - __proto__=polluted',
        '      - constructor=hacked',
        '      - APP_OK=1',
        '    ports:',
        `      - "\${PORT:-3000}:3000"`
      ].join('\n');
      const parsedCompose = parseDockerCompose(hostileCompose);
      assert.strictEqual(parsedCompose.services.length, 1);
      assert.strictEqual(/** @type {any} */ ({}).polluted, undefined, 'Object.prototype must NEVER be polluted by Compose YAML');

      // ReDoS check on expandComposeDefaults via many nested/repeated variable expressions
      const redosCompose = `services:\n  api:\n    image: node:22-alpine\n    ports:\n      - "${'${A:-1}'.repeat(300)}"\n`;
      const tRedos = performance.now();
      parseDockerCompose(redosCompose);
      assert.ok(performance.now() - tRedos < 100, 'Compose variable expansion must not exhibit catastrophic backtracking');

      console.log(`  ✓ 4. YAML & Compose anti-DoS + prototype pollution fuzzer (${yamlVectors.length} YAML + 4 Compose hostile payloads <100ms)`);
    }

    // =========================================================================
    // 5. CronParser Impossible Dates & Adversarial Syntax Fuzzing
    // =========================================================================
    {
      const impossibleDates = [
        '0 0 30 2 *', // Feb 30
        '0 0 31 2 *', // Feb 31
        '0 0 31 4 *'  // Apr 31
      ];
      let maxImpossibleMs = 0;
      for (const expr of impossibleDates) {
        const s = performance.now();
        assert.throws(
          () => nextCronRun(expr, new Date('2026-01-01T00:00:00Z')),
          /próxima ejecución válida|No se encontró/i,
          `Impossible cron ${expr} must fail cleanly without hanging`
        );
        const dt = performance.now() - s;
        maxImpossibleMs = Math.max(maxImpossibleMs, dt);
        assert.ok(dt < 5000, `Impossible cron ${expr} hung event loop for ${dt.toFixed(1)}ms (>5000ms)`);
      }

      // Leap day 2028-02-29 resolves cleanly when within 2-year horizon
      const leap = nextCronRun('0 0 29 2 *', new Date('2027-01-01T00:00:00Z'));
      assert.strictEqual(leap.getMonth(), 1); // February (0-indexed)
      assert.strictEqual(leap.getDate(), 29);

      const badCrons = [
        '', '   ', '*/0 * * * *', '*/-1 * * * *', '1-5-9 * * * *', '1/2/3 * * * *',
        '60 * * * *', '59-0 * * * *', '0 24 * * *', '0 0 0 * *', '0 0 * 13 *',
        '0 0 * * 8', '0 0 * *', '0 0 * * * *', 'a b c d e'
      ];
      for (const bad of badCrons) {
        assert.throws(() => parseCron(bad), `parseCron must reject "${bad}"`);
      }
      console.log(`  ✓ 5. CronParser fuzzing: ${impossibleDates.length} impossible dates terminated (max ${maxImpossibleMs.toFixed(0)}ms) + leap-day + ${badCrons.length} invalid expressions rejected`);
    }

    // =========================================================================
    // 6. Windows `..\\` Path Traversal & Backup AES-256-GCM Tamper Fuzzing
    // =========================================================================
    {
      const winVectors = [
        '..\\..\\package.json',
        '..\\../package.json',
        'sub\\..\\..\\..\\package.json',
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        '../../etc/passwd'
      ];
      for (const v of winVectors) {
        await assert.rejects(
          () => dbBackupManager.restoreProject(v),
          /fuera|backup|permitid|ruta|inválid|traversal|null|nulo/i,
          `restoreProject must reject traversal vector: ${v}`
        );
        assert.throws(
          () => ssrfGuard.assertContainedPath(tmpRoot, v),
          /fuera|traversal|ruta|absoluta|nulo|inválid/i,
          `assertContainedPath must reject: ${v}`
        );
      }
      // Null-byte injection in backup filename must be rejected by restoreProject
      await assert.rejects(
        () => dbBackupManager.restoreProject('backup.json\0.txt'),
        /null|nulo|inválid|fuera|backup|ruta|ERR_INVALID/i,
        'restoreProject must reject null-byte filename'
      );

      // Corrupt JSON backup file inside an isolated backupsDir
      const isoBackupDir = path.join(tmpRoot, 'backups-iso');
      fs.mkdirSync(isoBackupDir, { recursive: true });
      const corruptBackupFile = path.join(isoBackupDir, 'corrupt_backup.json');
      fs.writeFileSync(corruptBackupFile, '{"project":{"name":"broken', 'utf8');
      const origBackupsDir = dbBackupManager.backupsDir;
      dbBackupManager.backupsDir = isoBackupDir;
      try {
        await assert.rejects(
          () => dbBackupManager.restoreProject('corrupt_backup.json'),
          /JSON|Unexpected|corrupt|inválid|SyntaxError/i,
          'restoreProject must reject corrupt/truncated backup JSON'
        );
        await assert.rejects(
          () => dbBackupManager.restoreProject('does_not_exist_999.json'),
          /no encontrado|not found|ENOENT|existe/i
        );
      } finally {
        dbBackupManager.backupsDir = origBackupsDir;
      }

      // CLI argument flag injection in buildDbDumpSpec
      for (const badOpts of [
        { host: '-oProxyCommand=id' },
        { user: '--eval=evil' },
        { dbName: 'app\n--drop' },
        { outputFile: '-f/tmp/x' }
      ]) {
        assert.throws(() => dbBackupManager.buildDbDumpSpec('postgresql', badOpts), /guion|control|inválido/i);
      }

      // AES-256-GCM snapshot bit-flip tamper (authTag flip, ciphertext flip, 11-byte IV, wrong passphrase)
      const encSnap = await dbBackupManager.exportInstanceSnapshot({
        includeSecrets: true,
        passphrase: 'StrongDRPassphrase!2026',
        persist: false
      });
      const cloneSnap = () => JSON.parse(JSON.stringify(encSnap.snapshot));

      const tagFlip = cloneSnap();
      const tBuf = Buffer.from(tagFlip.data.tag, 'base64');
      tBuf[0] ^= 0xff;
      tagFlip.data.tag = tBuf.toString('base64');
      await assert.rejects(
        () => dbBackupManager.importInstanceSnapshot({ snapshot: tagFlip, passphrase: 'StrongDRPassphrase!2026', dryRun: true, allowUnsigned: true }),
        /Checksum|contraseña|corrupto|descifrar|inválid/i
      );

      const ctFlip = cloneSnap();
      const cBuf = Buffer.from(ctFlip.data.ciphertext, 'base64');
      cBuf[0] ^= 0x01;
      ctFlip.data.ciphertext = cBuf.toString('base64');
      await assert.rejects(
        () => dbBackupManager.importInstanceSnapshot({ snapshot: ctFlip, passphrase: 'StrongDRPassphrase!2026', dryRun: true, allowUnsigned: true }),
        /Checksum|contraseña|corrupto|descifrar|inválid/i
      );

      const shortIv = cloneSnap();
      shortIv.data.iv = crypto.randomBytes(11).toString('base64');
      await assert.rejects(
        () => dbBackupManager.importInstanceSnapshot({ snapshot: shortIv, passphrase: 'StrongDRPassphrase!2026', dryRun: true, allowUnsigned: true }),
        /Checksum|contraseña|corrupto|iv|12|inválid/i
      );

      console.log('  ✓ 6. Windows ..\\ traversal, corrupt backup JSON, CLI flag injection & AES-256-GCM bit-flips blocked');
    }

    // =========================================================================
    // 7. Concurrency & Race-Condition Torture Suite
    // =========================================================================
    {
      // 7a. TeamManager.acceptInvite 10-way parallel double-spend race
      const raceTmDir = path.join(tmpRoot, 'race-tm');
      const raceTm = new TeamManager({ dataDir: raceTmDir, bcryptCost: 4 });
      const boot = raceTm.bootstrapOwner({ email: 'owner@race.local', password: 'OwnerPassword!2026' });
      const ownerP = raceTm.verifySessionToken(boot.sessionToken).principal;
      const inv = raceTm.createInvite(ownerP, { email: 'racer@race.local', role: 'developer' });

      const inviteRaces = await Promise.allSettled(
        Array.from({ length: 10 }, (_, i) => Promise.resolve().then(() =>
          raceTm.acceptInvite({
            token: inv.inviteToken,
            email: 'racer@race.local',
            name: `Racer ${i}`,
            password: 'RacerPassword!2026'
          })
        ))
      );
      const inviteWins = inviteRaces.filter((r) => r.status === 'fulfilled');
      const inviteLosses = inviteRaces.filter((r) => r.status === 'rejected');
      assert.strictEqual(inviteWins.length, 1, `Expected strictly 1 invite acceptance, got ${inviteWins.length}`);
      assert.strictEqual(inviteLosses.length, 9);
      assert.ok(inviteLosses.every((r) => r.reason && r.reason.code === 'INVITE_ALREADY_USED'));

      // 7b. EnvironmentManager.promoteEnvironment 10-way parallel approval double-spend race
      const raceEnvDir = path.join(tmpRoot, 'race-env');
      const raceEnv = new EnvironmentManager({ dataDir: raceEnvDir });
      raceEnv.upsertEnvironment('proj_race', 'staging', {
        branch: 'staging',
        lastRelease: { imageTag: 'img:v2', commit: '222' },
        envVars: { KEY: 'v2' }
      });
      raceEnv.upsertEnvironment('proj_race', 'production', {
        branch: 'main',
        requireApproval: true,
        lastRelease: { imageTag: 'img:v1', commit: '111' },
        envVars: { KEY: 'v1' }
      });
      const reqAppr = raceEnv.createApprovalRequest({
        projectId: 'proj_race',
        fromEnv: 'staging',
        toEnv: 'production',
        requestedBy: 'dev-a'
      });
      const appr = raceEnv.approveRequest(reqAppr.id, { actor: 'admin-b' });

      const promoRaces = await Promise.allSettled(
        Array.from({ length: 10 }, () => Promise.resolve().then(() =>
          raceEnv.promoteEnvironment('proj_race', {
            fromEnv: 'staging',
            toEnv: 'production',
            includeEnvVars: true,
            approvalId: appr.id,
            actor: 'dev-a'
          })
        ))
      );
      const promoWins = promoRaces.filter((r) => r.status === 'fulfilled');
      assert.strictEqual(promoWins.length, 1, `Expected strictly 1 promotion for single-use approval, got ${promoWins.length}`);
      assert.strictEqual(promoRaces.filter((r) => r.status === 'rejected').length, 9);

      // 7c. ProjectManager.flushToDisk 50-way concurrent burst (isolated tmpDir)
      const racePmDir = path.join(tmpRoot, 'race-pm');
      fs.mkdirSync(racePmDir, { recursive: true });
      const racePmFile = path.join(racePmDir, 'projects.json');
      const racePm = createIsolatedProjectManager(racePmFile);
      await Promise.all(
        Array.from({ length: 50 }, (_, i) => {
          const p = new Project({ id: `proj_burst_${i}`, name: `Burst Project ${i}` });
          racePm.projects.set(p.id, p);
          return racePm.flushToDisk(p.id);
        })
      );
      const persisted = JSON.parse(fs.readFileSync(racePmFile, 'utf8'));
      assert.strictEqual(persisted.length, 50, 'All 50 concurrent writes must survive atomic Group Commit flush');
      const leftoverTmps = fs.readdirSync(racePmDir).filter((f) => f.endsWith('.tmp'));
      assert.strictEqual(leftoverTmps.length, 0, `No .tmp leftovers allowed after flush storm, found: ${leftoverTmps.join(', ')}`);

      // 7d. LiveSyncEngine 2-client interleaved 20-frame storm
      const stormDir = path.join(tmpRoot, 'race-sync');
      fs.mkdirSync(stormDir, { recursive: true });
      const stormEngine = new LiveSyncEngine();
      stormEngine.setTargetDir('proj_storm', stormDir);
      stormEngine.registerClient('proj_storm', { id: 'c_alice', clientName: 'Alice' });
      stormEngine.registerClient('proj_storm', { id: 'c_bob', clientName: 'Bob' });
      const stormResults = await Promise.all(
        Array.from({ length: 20 }, (_, i) => Promise.resolve().then(() => {
          const isAlice = i % 2 === 0;
          return stormEngine.applyCommitFrame('proj_storm', {
            seq: Math.floor(i / 2) + 1,
            files: [
              { path: 'shared.ts', op: 'upsert', content: `export const turn = ${i};\n` },
              { path: `client_${isAlice ? 'a' : 'b'}_${i}.ts`, op: 'upsert', content: `export const id = ${i};\n` }
            ]
          }, { clientId: isAlice ? 'c_alice' : 'c_bob', clientName: isAlice ? 'Alice' : 'Bob' });
        }))
      );
      assert.strictEqual(stormResults.length, 20);
      assert.ok(stormEngine.getStatus('proj_storm').recentConflicts.length >= 1, 'Multi-client storm on shared.ts must record conflicts');

      // 7e. UptimeMonitor 10-way concurrent runCheck on real local HTTP server
      const pingSrv = http.createServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('OK');
      });
      await new Promise((r) => pingSrv.listen(0, '127.0.0.1', () => r(undefined)));
      const pingPort = /** @type {import('net').AddressInfo} */ (pingSrv.address()).port;
      const raceUp = new UptimeMonitor({
        storeFile: path.join(tmpRoot, 'race-uptime', 'uptime.json'),
        autoStart: false,
        resolveProjectPort: () => pingPort
      });
      try {
        const mon = await raceUp.createMonitor({
          name: 'Concurrent Probe',
          type: 'http',
          allowLocalProject: true,
          projectId: 'proj_ping',
          url: `http://127.0.0.1:${pingPort}/`,
          intervalSec: 30
        });
        const checks = await Promise.all(Array.from({ length: 10 }, () => raceUp.runCheck(mon.id)));
        assert.strictEqual(checks.length, 10);
        assert.ok(checks.every((c) => c.status === 'up'));
        assert.ok(raceUp.monitors.get(mon.id).checks.length <= 288);
      } finally {
        raceUp.stop();
        await new Promise((r) => pingSrv.close(() => r(undefined)));
      }

      // 7f. TelemetryService 5-way concurrent flush() race -> strictly 1 transport send (no duplicates)
      const prevAllow = process.env.CULKIBO_TELEMETRY_ALLOW_IN_TEST;
      process.env.CULKIBO_TELEMETRY_ALLOW_IN_TEST = '1';
      try {
        let sends = 0;
        const raceTel = new TelemetryService({
          storePath: path.join(tmpRoot, 'race-tel', 'tel.json'),
          transport: async () => {
            sends++;
            await new Promise((r) => setTimeout(r, 30));
            return { ok: true, status: 202 };
          }
        });
        raceTel.captureCrash('uncaughtException', new Error('Single crash race test'));
        const flushes = await Promise.all(Array.from({ length: 5 }, () => raceTel.flush({ force: true })));
        assert.strictEqual(sends, 1, `Concurrent flush() must only send 1 HTTP batch, sent ${sends}`);
        assert.strictEqual(flushes.filter((f) => f.skipped === 'in_flight').length, 4);
      } finally {
        if (prevAllow === undefined) delete process.env.CULKIBO_TELEMETRY_ALLOW_IN_TEST;
        else process.env.CULKIBO_TELEMETRY_ALLOW_IN_TEST = prevAllow;
      }

      console.log('  ✓ 7. Concurrency races verified (10x acceptInvite, 10x promoteEnvironment, 50x flushToDisk, 20x LiveSync, 10x Uptime, 5x Telemetry)');
    }

    // =========================================================================
    // 8. Real Express HTTP RBAC Middleware Guard (Malformed Tokens + Non-Bypass)
    // =========================================================================
    {
      const httpTmDir = path.join(tmpRoot, 'express-rbac');
      const httpTm = new TeamManager({ dataDir: httpTmDir, bcryptCost: 4 });
      const boot = httpTm.bootstrapOwner({ email: 'owner@http.local', password: 'OwnerPassword!2026' });
      const ownerP = httpTm.verifySessionToken(boot.sessionToken).principal;
      const devInv = httpTm.createInvite(ownerP, { email: 'dev@http.local', role: 'developer' });
      const devAcc = httpTm.acceptInvite({ token: devInv.inviteToken, email: 'dev@http.local', password: 'DevPassword!2026' });
      const viewInv = httpTm.createInvite(ownerP, { email: 'viewer@http.local', role: 'viewer' });
      const viewAcc = httpTm.acceptInvite({ token: viewInv.inviteToken, email: 'viewer@http.local', password: 'ViewPassword!2026' });

      // Malformed / hostile token fuzzing against verifySessionToken & verifyApiToken
      const badTokens = [
        '', 'cks_', 'cks_a.b.c.d', 'cks_bad.sig', 'cks_' + 'A'.repeat(4096),
        'ckp_', 'ckp_12345678', 'ckp_12345678_\0null', 'Bearer invalid', null, undefined, 12345
      ];
      for (const bt of badTokens) {
        assert.strictEqual(httpTm.verifySessionToken(/** @type {any} */ (bt)).ok, false);
        assert.strictEqual(httpTm.verifyApiToken(/** @type {any} */ (bt)).ok, false);
      }

      const prevTm = auth._setTeamManagerForTest ? true : false;
      if (prevTm) auth._setTeamManagerForTest(httpTm);
      const app = express();
      app.use((req, _res, next) => {
        // Simular peer remoto real para que loopback bypass no aplique
        Object.defineProperty(req.socket, 'remoteAddress', { value: '203.0.113.77', configurable: true });
        next();
      });
      app.use('/api', auth.authMiddleware, auth.requireRouteRbac({ teamManager: httpTm }));
      app.all('/api/*', (_req, res) => res.status(200).json({ reachedHandler: true }));

      const srv = await new Promise((r) => {
        const s = app.listen(0, '127.0.0.1', () => r(s));
      });
      const port = /** @type {import('net').AddressInfo} */ (srv.address()).port;

      const sendRaw = (method, reqPath, token) => new Promise((resolve, reject) => {
        const req = http.request({
          host: '127.0.0.1',
          port,
          method,
          path: reqPath,
          headers: {
            Host: 'panel.example.com',
            ...(token ? { Authorization: `Bearer ${token}` } : {})
          }
        }, (res) => {
          let body = '';
          res.on('data', (c) => { body += c; });
          res.on('end', () => resolve({ status: res.statusCode, body }));
        });
        req.on('error', reject);
        req.end();
      });

      try {
        // Unauthenticated remote request -> 401
        const unauth = await sendRaw('GET', '/api/projects', null);
        assert.strictEqual(unauth.status, 401);

        // Canonical RBAC enforcement over real Express socket
        const devDelete = await sendRaw('DELETE', '/api/projects/proj_alpha', devAcc.sessionToken);
        assert.strictEqual(devDelete.status, 403, 'Developer must be blocked on DELETE /api/projects/:id');
        const devRotate = await sendRaw('POST', '/api/auth/rotate', devAcc.sessionToken);
        assert.strictEqual(devRotate.status, 403, 'Developer must be blocked on POST /api/auth/rotate');
        const viewerCreds = await sendRaw('GET', '/api/databases/db1/credentials', viewAcc.sessionToken);
        assert.strictEqual(viewerCreds.status, 403, 'Viewer must be blocked on GET /api/databases/:id/credentials');
        const viewerAudit = await sendRaw('GET', '/api/audit', viewAcc.sessionToken);
        assert.strictEqual(viewerAudit.status, 403, 'Viewer must be blocked on GET /api/audit');

        // Path-normalization bypass probes (trailing slash, uppercase, double slash, percent-encoding, dot-segments, malformed %XX, null byte, /api/system/audit)
        // Verifies canonicalization against Express's default case-insensitive, non-strict router!
        const bypassProbes = [
          ['DELETE', '/api/projects/proj_alpha/', devAcc.sessionToken, 'trailing-slash DELETE project'],
          ['DELETE', '/api/projects//proj_alpha', devAcc.sessionToken, 'double-slash DELETE project'],
          ['POST', '/api/projects/proj_alpha/ACL', devAcc.sessionToken, 'uppercase ACL mutation'],
          ['POST', '/api/projects/proj_alpha/FREEZE-WINDOWS', devAcc.sessionToken, 'uppercase freeze-windows'],
          ['POST', '/api/AUTH/ROTATE', devAcc.sessionToken, 'uppercase auth/rotate'],
          ['POST', '/api/auth/%72otate', devAcc.sessionToken, 'percent-encoded auth/rotate'],
          ['POST', '/api/auth/%2572otate', devAcc.sessionToken, 'double-encoded auth/rotate'],
          ['POST', '/api/projects/../auth/rotate', devAcc.sessionToken, 'dot-segment traversal to auth/rotate'],
          ['GET', '/api/databases/db1/CREDENTIALS', viewAcc.sessionToken, 'uppercase DB credentials'],
          ['GET', '/api/databases/db1/%63redentials', viewAcc.sessionToken, 'percent-encoded DB credentials'],
          ['GET', '/api/projects/proj_alpha/SECRETS', viewAcc.sessionToken, 'uppercase project secrets'],
          ['GET', '/api/AUDIT', viewAcc.sessionToken, 'uppercase audit log'],
          ['GET', '/api/system/audit', viewAcc.sessionToken, 'viewer /api/system/audit gate'],
          ['GET', '/api/system/health-summary', viewAcc.sessionToken, 'viewer /api/system/health-summary gate'],
          ['GET', '/api/projects/%ZZinvalid', devAcc.sessionToken, 'malformed percent encoding'],
          ['GET', '/api/projects/%00null', devAcc.sessionToken, 'null-byte path injection']
        ];
        for (const [m, p, tok, label] of bypassProbes) {
          const r = await sendRaw(m, p, tok);
          assert.ok(
            r.status === 400 || r.status === 403 || r.status === 404,
            `RBAC path-normalization bypass detected on ${label} (${m} ${p}): got HTTP ${r.status}`
          );
        }

        // Legit owner passes
        const ownerOk = await sendRaw('POST', '/api/auth/rotate', boot.sessionToken);
        assert.strictEqual(ownerOk.status, 200);
      } finally {
        if (prevTm) auth._setTeamManagerForTest(null);
        auth.resetAuthRateLimit();
        await new Promise((r) => srv.close(() => r(undefined)));
      }
      console.log('  ✓ 8. Real Express HTTP RBAC token fuzzing & path-normalization anti-bypass verified');
    }

    console.log('✅ Adversarial, Fuzzing, Crash-Recovery & Concurrency Suite PASSED!\n');
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

module.exports = testAdversarialFuzz;

if (require.main === module) {
  testAdversarialFuzz()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ Adversarial/Fuzz test failure:', err);
      process.exit(1);
    });
}
