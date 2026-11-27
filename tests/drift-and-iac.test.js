const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  DriftDetectorService,
  computeEnvKeySetHash,
  buildPgBouncerPreset,
  diffContainerConfig
} = require('../server/services/driftDetectorService');
const {
  IaCExporter,
  renderTerraformMain,
  renderTerraformVariables,
  renderTerraformOutputs,
  renderPortableCompose,
  renderEnvExample
} = require('../server/services/iacExporter');
const { ProjectManager } = require('../server/services/projectManager');

/**
 * Suite Cycle #8: Live Container/DB Config Drift Detector (`kamal#1790`),
 * Managed PgBouncer Smart Pool Preset (`max_prepared_statements = 200`),
 * and Zero Lock-In OpenTofu/Terraform + Compose IaC Exporter.
 *
 * Runs 100% isolated inside `os.tmpdir()` — ZERO mutations to live `data/`.
 */
async function runTests() {
  console.log('--- Iniciando Tests de Drift Detector, PgBouncer Smart Pool Preset y IaC Exporter ---');

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-drift-iac-'));
  const dataDir = path.join(tmpRoot, 'data');
  fs.mkdirSync(dataDir, { recursive: true });

  const pm = new ProjectManager({ dataPath: path.join(dataDir, 'projects.json'), seedDefaults: false });
  const drift = new DriftDetectorService({ projectManager: pm });
  const exporter = new IaCExporter({ projectManager: pm });

  let passed = 0;
  const runCase = async (name, fn) => {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  };

  try {
    // =========================================================================
    // 1. ENV KEY-SET HASH NEVER HASHES OR LEAKS VALUES
    // =========================================================================
    await runCase('1. computeEnvKeySetHash() hashes sorted key names ONLY (0 secret values)', async () => {
      const h1 = computeEnvKeySetHash({ B_KEY: 'SECRET_AAA', A_KEY: 'SECRET_BBB' });
      const h2 = computeEnvKeySetHash(['A_KEY=DIFFERENT_VAL_1', 'B_KEY=DIFFERENT_VAL_2']);
      const h3 = computeEnvKeySetHash(['B_KEY', 'A_KEY']);
      assert.strictEqual(h1.length, 64);
      assert.strictEqual(h1, h2);
      assert.strictEqual(h2, h3);

      const hDiff = computeEnvKeySetHash(['A_KEY', 'B_KEY', 'C_KEY']);
      assert.notStrictEqual(h1, hDiff);
    });

    // =========================================================================
    // 2. CLEAN NO-DRIFT VS MULTI-FIELD CRITICAL DRIFT + RECONCILE PLAN
    // =========================================================================
    await runCase('2. diffContainerConfig() distinguishes clean match vs critical multi-field drift with 0 secret leakage', async () => {
      const declared = {
        image: 'ghcr.io/acme/api:1.4.0',
        imageDigest: 'sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff',
        memoryLimitMb: 1024,
        cpuLimit: 2,
        port: 3000,
        bindAddress: '127.0.0.1',
        envKeys: ['NODE_ENV', 'DATABASE_URL', 'STRIPE_KEY'],
        logDriver: 'json-file',
        stopGracePeriodSec: 30
      };

      const cleanInspect = {
        Image: 'sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff',
        RepoDigests: ['ghcr.io/acme/api@sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff'],
        Config: {
          Image: 'ghcr.io/acme/api:1.4.0',
          StopTimeout: 30,
          Env: [
            'PATH=/usr/local/bin:/usr/bin',
            'NODE_ENV=production',
            'DATABASE_URL=postgres://u:CANARY_DRIFT_SECRET_5512@pg:5432/app',
            'STRIPE_KEY=sk_live_CANARY_DRIFT_SECRET_8821'
          ]
        },
        HostConfig: {
          Memory: 1024 * 1024 * 1024,
          NanoCpus: 2 * 1e9,
          LogConfig: { Type: 'json-file' },
          PortBindings: {
            '3000/tcp': [{ HostIp: '127.0.0.1', HostPort: '3000' }]
          }
        }
      };

      const noDrift = diffContainerConfig(declared, cleanInspect);
      assert.strictEqual(noDrift.ok, true);
      assert.strictEqual(noDrift.drifted, false);
      assert.strictEqual(noDrift.severity, 'none');
      assert.strictEqual(noDrift.diffs.length, 0);
      assert.strictEqual(noDrift.reconcilePlan.actionCount, 0);

      // Multi-field drift: mutated digest + 0.0.0.0 exposure (CRITICAL) + halved RAM + env key-set drift + logDriver + stopTimeout
      const driftedInspect = {
        Image: 'sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
        RepoDigests: ['ghcr.io/acme/api@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'],
        Config: {
          Image: 'ghcr.io/acme/api:1.4.0-hotfix',
          StopTimeout: 10,
          Env: [
            'NODE_ENV=production',
            'DATABASE_URL=postgres://u:CANARY_DRIFT_SECRET_5512@pg:5432/app',
            'ROGUE_DEBUG_KEY=CANARY_ROGUE_VAL_4420'
          ]
        },
        HostConfig: {
          Memory: 512 * 1024 * 1024,
          NanoCpus: 1 * 1e9,
          LogConfig: { Type: 'syslog' },
          PortBindings: {
            '3000/tcp': [{ HostIp: '0.0.0.0', HostPort: '3000' }]
          }
        }
      };

      const res = diffContainerConfig(declared, driftedInspect);
      assert.strictEqual(res.ok, true);
      assert.strictEqual(res.drifted, true);
      assert.strictEqual(res.severity, 'critical');
      assert.ok(res.diffs.some((d) => d.field === 'imageDigest' && d.severity === 'critical'));
      assert.ok(res.diffs.some((d) => d.field === 'bindAddress' && d.severity === 'critical'));
      assert.ok(res.diffs.some((d) => d.field === 'memoryLimitMb' && d.severity === 'high'));
      assert.ok(res.diffs.some((d) => d.field === 'cpuLimit' && d.severity === 'high'));
      assert.ok(res.diffs.some((d) => d.field === 'envKeys' && d.severity === 'high'));
      assert.ok(res.diffs.some((d) => d.field === 'logDriver' && d.severity === 'medium'));
      assert.ok(res.diffs.some((d) => d.field === 'stopGracePeriodSec' && d.severity === 'medium'));
      assert.strictEqual(res.reconcilePlan.dryRunDefault, true);
      assert.ok(res.reconcilePlan.actionCount >= 7);
      assert.strictEqual(res.reconcilePlan.requiresContainerRecreate, true);

      // ZERO plaintext env values leaked anywhere in drift report!
      const serialized = JSON.stringify(res);
      assert.ok(!serialized.includes('CANARY_DRIFT_SECRET_5512'));
      assert.ok(!serialized.includes('CANARY_ROGUE_VAL_4420'));

      // checkProjectDrift integration with isolated ProjectManager
      const proj = pm.create({
        id: 'proj_drift_demo',
        name: 'Drift Demo API',
        containerPort: 3000,
        memoryMb: 1024,
        cpus: 2,
        envVars: { NODE_ENV: 'production', DATABASE_URL: 'postgres://u:CANARY_DRIFT_SECRET_5512@pg:5432/app' }
      });
      const projCheck = await drift.checkProjectDrift(proj.id, { actualInspect: driftedInspect });
      assert.strictEqual(projCheck.ok, true);
      assert.strictEqual(projCheck.projectId, proj.id);
      assert.strictEqual(projCheck.drifted, true);
      assert.strictEqual(projCheck.severity, 'critical');
      assert.strictEqual(projCheck.runtimeOffline, false);
    });

    // =========================================================================
    // 3. MANAGED PGBOUNCER SMART POOL PRESET (PRISMA / DRIZZLE SAFE)
    // =========================================================================
    await runCase('3. buildPgBouncerPreset() generates Prisma/Drizzle-safe config & rejects injection', async () => {
      const preset = buildPgBouncerPreset({
        name: 'saas-main-pg',
        databaseName: 'saas_prod',
        upstreamHost: 'culkibo-pg-prod',
        upstreamPort: 5432,
        listenPort: 6432,
        poolMode: 'transaction',
        maxPreparedStatements: 200,
        defaultPoolSize: 25,
        maxClientConn: 200,
        reservePoolSize: 5
      });

      assert.strictEqual(preset.ok, true);
      assert.strictEqual(preset.preset, 'pgbouncer-smart-pool');
      assert.strictEqual(preset.poolMode, 'transaction');
      assert.strictEqual(preset.maxPreparedStatements, 200);
      assert.ok(preset.pgbouncerIni.includes('pool_mode = transaction'));
      assert.ok(preset.pgbouncerIni.includes('max_prepared_statements = 200'));
      assert.ok(preset.pgbouncerIni.includes('listen_addr = 127.0.0.1'));
      assert.ok(preset.pgbouncerIni.includes('auth_type = scram-sha-256'));
      assert.ok(preset.ormHints.prisma.includes('?pgbouncer=true'));
      assert.ok(preset.ormHints.drizzle.includes('max_prepared_statements=200'));
      assert.strictEqual(preset.dockerSpec.bindAddress, '127.0.0.1');

      // Shell/INI injection attempts MUST throw
      assert.throws(() => buildPgBouncerPreset({ name: 'bad;rm -rf /' }), /inválido|inseguro/i);
      assert.throws(() => buildPgBouncerPreset({ name: 'ok', databaseName: 'app\nadmin_users=evil' }), /inválido/i);
      assert.throws(() => buildPgBouncerPreset({ name: 'ok', upstreamHost: 'db;whoami' }), /inválido/i);
      assert.throws(() => buildPgBouncerPreset({ name: 'ok', poolMode: /** @type {any} */ ('invalid') }), /poolMode/i);
    });

    // =========================================================================
    // 4. ZERO LOCK-IN OPENTOFU/TERRAFORM & COMPOSE IAC EXPORTER (0 CANARY LEAKS)
    // =========================================================================
    await runCase('4. IaCExporter emits valid OpenTofu HCL + Compose + .env.example with ZERO canary secret leaks', async () => {
      const CANARY_APP_SECRET = 'CANARY_SECRET_VALUE_9981';
      const CANARY_DB_PASS = 'CANARY_DB_PASS_7742';
      const CANARY_WG_PRIV = 'CANARY_WG_PRIVATE_KEY_8833=';

      const snapshot = {
        projects: [
          {
            id: 'acme-api',
            name: 'Acme API',
            imageTag: 'ghcr.io/acme/api:2.1.0',
            containerPort: 8080,
            memoryMb: 1024,
            stopGracePeriodSec: 45,
            envVars: {
              NODE_ENV: 'production',
              STRIPE_SECRET_KEY: CANARY_APP_SECRET,
              CUSTOM_NON_OBVIOUS_CONFIG: CANARY_APP_SECRET
            }
          }
        ],
        databases: [
          {
            id: 'pg-main',
            name: 'Acme Postgres',
            engine: 'postgres',
            dbName: 'acme_prod',
            username: 'acme_user',
            password: CANARY_DB_PASS,
            port: 5432
          }
        ],
        domains: [
          {
            hostname: 'api.acme.dev',
            projectId: 'acme-api',
            cloudflareProxied: true
          }
        ],
        crons: [
          { id: 'c1', projectId: 'acme-api', name: 'Cleanup', schedule: '0 3 * * *', command: 'node cleanup.js' }
        ],
        meshPeers: [
          { nodeId: 'local', meshIp: '10.88.0.1', publicKey: 'PUB_KEY_LOCAL', privateKey: CANARY_WG_PRIV, privateKeyEncrypted: true },
          { nodeId: 'worker-eu-1', meshIp: '10.88.0.2', publicKey: 'PUB_KEY_EU', encryptedPrivateKey: 'v1:xxx', privateKeyEncrypted: true }
        ]
      };

      const exported = exporter.exportEstate({ format: 'all', snapshot });
      assert.strictEqual(exported.ok, true);
      assert.strictEqual(exported.format, 'all');
      assert.deepStrictEqual(Object.keys(exported.files).sort(), [
        '.env.example',
        'docker-compose.yml',
        'main.tf',
        'outputs.tf',
        'variables.tf'
      ]);
      assert.strictEqual(exported.stats.projects, 1);
      assert.strictEqual(exported.stats.databases, 1);
      assert.strictEqual(exported.stats.domains, 1);
      assert.strictEqual(exported.stats.crons, 1);
      assert.strictEqual(exported.stats.meshPeers, 2);
      assert.ok(exported.secretsRedactedCount >= 5);

      // Structural HCL & Compose assertions
      assert.ok(exported.files['main.tf'].includes('kreuzwerker/docker'));
      assert.ok(exported.files['main.tf'].includes('resource "docker_network" "net_acme_api"'));
      assert.ok(exported.files['main.tf'].includes('resource "docker_container" "app_acme_api"'));
      assert.ok(exported.files['main.tf'].includes('resource "docker_container" "db_pg_main"'));
      assert.ok(exported.files['main.tf'].includes('stop_timeout = 45'));
      assert.ok(exported.files['main.tf'].includes('"max-size" = "10m"'));
      assert.ok(exported.files['main.tf'].includes('var.acme_api_stripe_secret_key'));
      assert.ok(exported.files['main.tf'].includes('var.db_pg_main_password'));
      assert.ok(exported.files['main.tf'].includes('resource "cloudflare_record" "dns_api_acme_dev"'));

      assert.ok(exported.files['variables.tf'].includes('variable "acme_api_stripe_secret_key"'));
      assert.ok(exported.files['variables.tf'].includes('sensitive   = true'));
      assert.ok(!/^\s*default\s*=/m.test(exported.files['variables.tf']), 'Sensitive variables must never have default = values');

      assert.ok(exported.files['outputs.tf'].includes('"local" = "10.88.0.1"'));
      assert.ok(exported.files['outputs.tf'].includes('"api.acme.dev"'));

      assert.ok(exported.files['docker-compose.yml'].includes('stop_grace_period: 45s'));
      assert.ok(exported.files['docker-compose.yml'].includes('max-size: "10m"'));
      assert.ok(exported.files['docker-compose.yml'].includes('${ACME_API_STRIPE_SECRET_KEY}'));
      assert.ok(exported.files['docker-compose.yml'].includes('${DB_PG_MAIN_PASSWORD}'));
      assert.ok(exported.files['docker-compose.yml'].includes('127.0.0.1:5432:5432'));

      assert.ok(exported.files['.env.example'].includes('ACME_API_STRIPE_SECRET_KEY='));
      assert.ok(exported.files['.env.example'].includes('DB_PG_MAIN_PASSWORD='));

      // STRICT SECURITY INVARIANT: synthetic canary secrets MUST NEVER appear in ANY exported file!
      for (const [fname, content] of Object.entries(exported.files)) {
        assert.ok(!content.includes(CANARY_APP_SECRET), `Canary app secret leaked in ${fname}!`);
        assert.ok(!content.includes(CANARY_DB_PASS), `Canary DB password leaked in ${fname}!`);
        assert.ok(!content.includes(CANARY_WG_PRIV), `Canary WireGuard private key leaked in ${fname}!`);
      }

      // Format filtering ('terraform' vs 'compose') & pure helper exports check
      const tfOnly = exporter.exportEstate({ format: 'terraform', snapshot });
      assert.ok(tfOnly.files['main.tf'] && !tfOnly.files['docker-compose.yml']);
      const composeOnly = exporter.exportEstate({ format: 'compose', snapshot });
      assert.ok(composeOnly.files['docker-compose.yml'] && !composeOnly.files['main.tf']);
      assert.strictEqual(typeof renderTerraformMain, 'function');
      assert.strictEqual(typeof renderTerraformVariables, 'function');
      assert.strictEqual(typeof renderTerraformOutputs, 'function');
      assert.strictEqual(typeof renderPortableCompose, 'function');
      assert.strictEqual(typeof renderEnvExample, 'function');
    });

    console.log(`\n✅ Drift Detector, PgBouncer Preset & IaC Exporter Suite: ${passed}/4 tests PASSED!`);
  } finally {
    try {
      if (typeof pm.flushToDisk === 'function') await pm.flushToDisk();
      if (pm.flushChain) await pm.flushChain;
    } catch (e) {}
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ Drift & IaC test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
