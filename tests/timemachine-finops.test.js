const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { TimeMachineService, computeStackDiff } = require('../server/services/timeMachineService');
const { FinOpsOptimizer, CLOUD_PRICING_PROFILES, VPS_CATALOG } = require('../server/services/finopsOptimizer');
const coolifyMigrator = require('../server/services/coolifyMigrator');
const { ProjectManager } = require('../server/services/projectManager');
const DomainManagerMod = require('../server/services/domainManager');
const { CronManager } = require('../server/services/cronManager');

/**
 * Suite Cycle #6: Whole-Stack Time-Machine Checkpoints/Diff/Atomic Restore,
 * FinOps Right-Sizing & Cloud-vs-Self-Hosted Optimizer, and Coolify v4
 * 3-Tier Shared-Env Precedence + Multi-Server Fleet Mapping.
 *
 * Runs 100% isolated inside `os.tmpdir()` — ZERO mutations to live `data/`.
 */
async function runTests() {
  console.log('--- Iniciando Tests de Time-Machine, FinOps Optimizer y Coolify 3-Tier/Multi-Server ---');

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-tm-finops-'));
  const dataDir = path.join(tmpRoot, 'data');
  fs.mkdirSync(dataDir, { recursive: true });

  const DomainManagerClass = DomainManagerMod.DomainManager || DomainManagerMod.constructor;
  const pm = new ProjectManager({ dataPath: path.join(dataDir, 'projects.json'), seedDefaults: false });
  const dm = new DomainManagerClass({ dataDir, seedDefaults: false });
  const cm = new CronManager(path.join(dataDir, 'crons.json'));
  const tm = new TimeMachineService({
    dataDir,
    projectManager: pm,
    domainManager: dm,
    cronManager: cm
  });
  const finops = new FinOpsOptimizer();

  let passed = 0;
  const runCase = async (name, fn) => {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  };

  try {
    // =========================================================================
    // 1. TIME-MACHINE: CREATE CHECKPOINT → MUTATE → DIFF → DRY-RUN → ATOMIC RESTORE
    // =========================================================================
    await runCase('1. Time-Machine captures whole-stack checkpoint with SHA-256 & 0 plaintext secrets on disk', async () => {
      const proj = pm.create({
        id: 'proj_tm_saas',
        name: 'Acme SaaS',
        description: 'v1 production',
        gitRepo: 'https://github.com/acme/saas',
        gitBranch: 'main',
        containerPort: 3000,
        citadelPort: 3000,
        memoryMb: 1024,
        cpus: 2,
        lastCommit: 'culkibo/acme-saas:v1.0.0',
        linkedDatabaseIds: ['db-pg-main'],
        envVars: {
          NODE_ENV: 'production',
          STRIPE_SECRET_KEY: 'sk_live_TIMEMACHINE_NEVER_PLAINTEXT_999',
          DATABASE_URL: 'postgresql://app:ULTRA_SECRET_PG_PASS@pg:5432/acme',
          FEATURE_FLAGS: 'v1'
        }
      });

      await dm.addDomain({
        hostname: 'app.acme-tm.dev',
        projectId: proj.id,
        targetPort: 3000,
        hstsPreload: true,
        hstsMaxAge: 31536000,
        cors: { enabled: true, allowedOrigins: ['https://app.acme-tm.dev'], methods: ['GET', 'POST'] }
      });

      cm.create(proj.id, {
        name: 'Nightly Billing',
        schedule: '0 2 * * *',
        mode: 'exec',
        command: 'node scripts/billing.js',
        enabled: true
      });

      const cp1 = tm.createCheckpoint(proj.id, {
        label: 'Release v1.0.0 baseline',
        actor: 'pablo',
        snapstreamGenId: 'gen_0001_wal',
        attestationSha256: 'a'.repeat(64)
      });

      assert.ok(cp1 && cp1.id.startsWith('tm_'));
      assert.strictEqual(cp1.sha256.length, 64);
      assert.strictEqual(cp1.counts.envVars, 4);
      assert.strictEqual(cp1.counts.domains, 1);
      assert.strictEqual(cp1.counts.crons, 1);
      assert.strictEqual(cp1.counts.dbLinks, 1);
      assert.strictEqual(cp1.snapstreamGenId, 'gen_0001_wal');
      assert.strictEqual(cp1.hasSealedEnv, true);

      // Verify ZERO plaintext secrets in API response AND in timemachine.json on disk!
      const apiJson = JSON.stringify(cp1);
      const diskJson = fs.readFileSync(path.join(dataDir, 'timemachine.json'), 'utf8');
      for (const secret of ['sk_live_TIMEMACHINE_NEVER_PLAINTEXT_999', 'ULTRA_SECRET_PG_PASS']) {
        assert.ok(!apiJson.includes(secret), `Secret leaked in Time-Machine API response: ${secret}`);
        assert.ok(!diskJson.includes(secret), `Secret leaked in timemachine.json on disk: ${secret}`);
      }

      // Mutate project, env, domain edge rules, add an extra domain & extra cron
      pm.update(proj.id, {
        memoryMb: 2048,
        cpus: 4,
        lastCommit: 'culkibo/acme-saas:v2.0.0-broken',
        linkedDatabaseIds: ['db-pg-main', 'db-redis-tmp'],
        envVars: {
          NODE_ENV: 'production',
          STRIPE_SECRET_KEY: 'sk_live_TIMEMACHINE_NEVER_PLAINTEXT_999',
          DATABASE_URL: 'postgresql://app:CHANGED_PG_PASS@pg:5432/acme',
          NEW_BROKEN_FLAG: 'true'
        }
      });

      const origDom = dm.getByHostname('app.acme-tm.dev');
      await dm.updateDomain(origDom.id, { targetPort: 4000, hstsPreload: false });
      await dm.addDomain({ hostname: 'bad-canary.acme-tm.dev', projectId: proj.id, targetPort: 4000 });
      cm.create(proj.id, {
        name: 'Broken Cron',
        schedule: '*/5 * * * *',
        mode: 'exec',
        command: 'node scripts/broken.js',
        enabled: true
      });

      const cp2 = tm.createCheckpoint(proj.id, { label: 'Release v2.0.0-broken', actor: 'ci' });

      // Diff cp1 -> cp2 must capture exact structural deltas with zero secrets!
      const diff = tm.diffCheckpoints(proj.id, cp1.id, cp2.id);
      assert.strictEqual(diff.hasChanges, true);
      assert.strictEqual(diff.imageTag.changed, true);
      assert.strictEqual(diff.imageTag.from, 'culkibo/acme-saas:v1.0.0');
      assert.strictEqual(diff.imageTag.to, 'culkibo/acme-saas:v2.0.0-broken');
      assert.strictEqual(diff.resources.memoryMb.from, 1024);
      assert.strictEqual(diff.resources.memoryMb.to, 2048);
      assert.deepStrictEqual(diff.env.added, ['NEW_BROKEN_FLAG']);
      assert.deepStrictEqual(diff.env.removed, ['FEATURE_FLAGS']);
      assert.deepStrictEqual(diff.env.changed, ['DATABASE_URL']);
      assert.deepStrictEqual(diff.domains.added, ['bad-canary.acme-tm.dev']);
      assert.ok(diff.edgePoliciesChanged.includes('app.acme-tm.dev'));
      assert.deepStrictEqual(diff.crons.added, ['Broken Cron']);
      assert.ok(!JSON.stringify(diff).includes('CHANGED_PG_PASS'));

      // Pure computeStackDiff helper check
      const directDiff = computeStackDiff(cp1.state, cp1.state);
      assert.strictEqual(directDiff.hasChanges, false);
      assert.strictEqual(directDiff.changeCount, 0);

      // Dry-run restore MUST return exact preview and perform ZERO mutations!
      const dry = await tm.restoreCheckpoint(proj.id, cp1.id, { dryRun: true });
      assert.strictEqual(dry.ok, true);
      assert.strictEqual(dry.dryRun, true);
      assert.strictEqual(dry.restored, false);
      assert.strictEqual(dry.integrityVerified, true);
      assert.strictEqual(dry.willCreateSafetyCheckpoint, true);
      assert.deepStrictEqual(dry.mutations.domainsToRemove, ['bad-canary.acme-tm.dev']);
      assert.strictEqual(pm.getById(proj.id).memoryMb, 2048, 'dryRun must NOT mutate project');
      assert.ok(dm.getByHostname('bad-canary.acme-tm.dev'), 'dryRun must NOT remove domain');

      // Real atomic restore (`dryRun: false`) restores EXACT prior state + creates pre_restore safety checkpoint!
      const restored = await tm.restoreCheckpoint(proj.id, cp1.id, { dryRun: false, actor: 'pablo' });
      assert.strictEqual(restored.ok, true);
      assert.strictEqual(restored.dryRun, false);
      assert.strictEqual(restored.restored, true);
      assert.ok(restored.safetyCheckpointId && restored.safetyCheckpointId.startsWith('tm_'));
      assert.strictEqual(restored.applied.domainsRemoved, 1);
      assert.strictEqual(restored.applied.domainsUpdated, 1);
      assert.strictEqual(restored.applied.cronsRemoved, 2);
      assert.strictEqual(restored.applied.cronsAdded, 1);
      assert.strictEqual(restored.applied.envKeysRestored, 4);

      // Verify live stores match cp1 exactly
      const liveProj = pm.getById(proj.id);
      assert.strictEqual(liveProj.memoryMb, 1024);
      assert.strictEqual(liveProj.cpus, 2);
      assert.strictEqual(liveProj.lastCommit, 'culkibo/acme-saas:v1.0.0');
      assert.deepStrictEqual(liveProj.linkedDatabaseIds, ['db-pg-main']);
      assert.strictEqual(liveProj.envVars.FEATURE_FLAGS, 'v1');
      assert.strictEqual(liveProj.envVars.DATABASE_URL, 'postgresql://app:ULTRA_SECRET_PG_PASS@pg:5432/acme');
      assert.strictEqual(liveProj.envVars.NEW_BROKEN_FLAG, undefined);
      assert.strictEqual(dm.getByHostname('bad-canary.acme-tm.dev'), null);
      assert.strictEqual(dm.getByHostname('app.acme-tm.dev').targetPort, 3000);
      assert.strictEqual(dm.getByHostname('app.acme-tm.dev').hstsPreload, true);
      const restoredCrons = cm.list(proj.id);
      assert.strictEqual(restoredCrons.length, 1);
      assert.strictEqual(restoredCrons[0].name, 'Nightly Billing');

      // Safety checkpoint exists in listCheckpoints()
      const allCps = tm.listCheckpoints(proj.id);
      assert.strictEqual(allCps.length, 3);
      assert.strictEqual(allCps[0].kind, 'pre_restore');
      assert.strictEqual(allCps[0].id, restored.safetyCheckpointId);
    });

    // =========================================================================
    // 2. TIME-MACHINE TAMPER PROTECTION (SHA-256 INTEGRITY GUARD)
    // =========================================================================
    await runCase('2. Time-Machine rejects tampered checkpoint SHA-256 before restoring', async () => {
      const storePath = path.join(dataDir, 'timemachine.json');
      const raw = JSON.parse(fs.readFileSync(storePath, 'utf8'));
      const firstId = raw.projects.proj_tm_saas[0].id;
      raw.projects.proj_tm_saas[0].state.imageTag = 'evil/tampered:latest';
      fs.writeFileSync(storePath, JSON.stringify(raw, null, 2), 'utf8');

      const tmReloaded = new TimeMachineService({ dataDir, projectManager: pm, domainManager: dm, cronManager: cm });
      const fetched = tmReloaded.getCheckpoint('proj_tm_saas', firstId);
      assert.strictEqual(fetched.integrityValid, false);

      await assert.rejects(
        () => tmReloaded.restoreCheckpoint('proj_tm_saas', firstId, { dryRun: true }),
        (err) => err && err.code === 'CHECKPOINT_INTEGRITY_ERROR' && err.status === 409
      );
    });

    // =========================================================================
    // 3. FINOPS OPTIMIZER: RIGHT-SIZING & HONEST CLOUD-VS-SELF-HOSTED CALCULATOR
    // =========================================================================
    await runCase('3. FinOpsOptimizer computes accurate right-sizing & non-negative Cloud-vs-VPS savings', async () => {
      assert.ok(CLOUD_PRICING_PROFILES.vercelPro.seatMonthlyUsd === 20);
      assert.ok(VPS_CATALOG.length >= 10);

      // 3a. Pure Cloud Cost Calculator (typical indie/startup stack: 5 apps, 2 DBs, 512 MB avg)
      const calc = finops.compareCloudCosts({ apps: 5, databases: 2, avgRamMbPerApp: 512, monthlyBandwidthGb: 400 });
      assert.ok(calc.monthlyCloudUsd > calc.monthlySelfHostedUsd, 'Cloud SaaS must cost more than Hetzner VPS for 5 apps + 2 DBs');
      assert.ok(calc.annualSavingsUsd > 0);
      assert.strictEqual(calc.annualSavingsUsd, Math.round(calc.monthlySavingsUsd * 12 * 100) / 100);
      assert.ok(calc.savingsPct > 50 && calc.savingsPct < 100);
      assert.strictEqual(calc.recommendedVps.provider, 'Hetzner');
      assert.strictEqual(calc.vpsAlternatives.length, 4);
      assert.ok(calc.pricingFootnotes.length >= 4);

      // Zero-workload non-negative invariant
      const zeroCalc = finops.compareCloudCosts({ apps: 0, databases: 0, monthlyBandwidthGb: 0 });
      assert.strictEqual(zeroCalc.monthlyCloudUsd, 0);
      assert.strictEqual(zeroCalc.monthlySelfHostedUsd, 0);
      assert.strictEqual(zeroCalc.annualSavingsUsd, 0);
      assert.strictEqual(zeroCalc.savingsPct, 0);

      // 3b. Fleet & Project Right-Sizing Analysis (over-provisioned + OOM risk + idle auto-sleep)
      const report = finops.analyzeFleetAndProjects({
        projects: [
          { id: 'p-over', name: 'Overprovisioned API', memoryMb: 2048, cpus: 2 },
          { id: 'p-oom', name: 'Heavy Worker', memoryMb: 512, cpus: 1 },
          { id: 'p-idle', name: 'Staging Portal', memoryMb: 256, cpus: 1, idleMinutes: 120 }
        ],
        databases: [
          { id: 'db-1', name: 'Main PG', engine: 'postgres' },
          { id: 'db-2', name: 'Cache Valkey', engine: 'valkey' }
        ],
        metricsHistory: [
          { projectId: 'p-over', memoryMb: 180, cpuPct: 4 },
          { projectId: 'p-over', memoryMb: 220, cpuPct: 6 },
          { projectId: 'p-oom', memoryMb: 470, cpuPct: 78 },
          { projectId: 'p-idle', memoryMb: 90, cpuPct: 0.2 }
        ],
        sleepCandidates: ['p-idle']
      });

      assert.strictEqual(report.ok, true);
      assert.strictEqual(report.fleetSummary.totalApps, 3);
      assert.strictEqual(report.fleetSummary.totalDatabases, 2);
      assert.strictEqual(report.fleetSummary.overProvisionedCount, 1);
      assert.strictEqual(report.fleetSummary.oomRiskCount, 1);
      assert.strictEqual(report.fleetSummary.sleepCandidateCount, 1);
      assert.ok(report.fleetSummary.totalReclaimableRamMb >= 1536);

      const overRec = report.recommendations.find((r) => r.projectId === 'p-over' && r.type === 'right_size_ram');
      assert.ok(overRec && overRec.recommendedMemoryMb < 2048 && overRec.reclaimableRamMb > 0);
      const oomRec = report.recommendations.find((r) => r.projectId === 'p-oom' && r.type === 'oom_risk');
      assert.ok(oomRec && oomRec.severity === 'high' && oomRec.recommendedMemoryMb > 512);
      const sleepRec = report.recommendations.find((r) => r.projectId === 'p-idle' && r.type === 'enable_auto_sleep');
      assert.ok(sleepRec && sleepRec.reclaimableRamMb > 0);
      assert.ok(report.annualSavingsUsd > 0);
    });

    // =========================================================================
    // 4. COOLIFY v4 3-TIER SHARED-ENV PRECEDENCE & MULTI-SERVER FLEET MAPPING
    // =========================================================================
    await runCase('4. Coolify v4 resolves 3-tier env precedence (team < project < resource) & multi-server mapping', async () => {
      // Direct translateMagicVariables 3-tier precedence test
      const directMagic = coolifyMigrator.translateMagicVariables(
        { APP_MODE: 'resource-wins', SECRET_TOKEN: '${SERVICE_PASSWORD_64_APP}' },
        {
          resourceName: 'Billing',
          fqdn: 'https://billing.acme.dev',
          teamSharedEnvs: { TZ: 'UTC', LOG_LEVEL: 'warn', APP_MODE: 'team-default' },
          projectSharedEnvs: { LOG_LEVEL: 'info', APP_MODE: 'project-override', PROJECT_REGION: 'eu-central' }
        }
      );
      assert.strictEqual(directMagic.translatedEnv.TZ, 'UTC');
      assert.strictEqual(directMagic.translatedEnv.LOG_LEVEL, 'info');
      assert.strictEqual(directMagic.translatedEnv.APP_MODE, 'resource-wins');
      assert.strictEqual(directMagic.translatedEnv.PROJECT_REGION, 'eu-central');
      assert.strictEqual(directMagic.translatedEnv.SECRET_TOKEN, '${vault.SERVICE_PASSWORD_64_APP}');
      assert.strictEqual(directMagic.envPrecedence.keySourceTier.TZ, 'team_shared');
      assert.strictEqual(directMagic.envPrecedence.keySourceTier.LOG_LEVEL, 'project_shared');
      assert.strictEqual(directMagic.envPrecedence.keySourceTier.APP_MODE, 'resource_env');
      assert.ok(directMagic.envPrecedence.overrides.some((o) => o.key === 'APP_MODE' && o.winnerTier === 'resource_env'));

      // Full multi-server snapshot with 3-tier shared envs
      const multiServerSnapshot = {
        servers: [
          { uuid: 'srv-eu-1', name: 'EU Primary', ip: '198.51.100.10', is_localhost: true },
          { uuid: 'srv-us-2', name: 'US Edge Worker', ip: '203.0.113.20', is_localhost: false }
        ],
        projects: [
          {
            uuid: 'proj-alpha',
            name: 'Alpha Stack',
            shared_environment_variables: [
              { key: 'SHARED_TIER', value: 'from-project' },
              { key: 'PROJECT_ONLY', value: 'alpha-1' }
            ]
          },
          {
            uuid: 'proj-beta',
            name: 'Beta Stack',
            shared_environment_variables: [
              { key: 'SHARED_TIER', value: 'from-beta' }
            ]
          }
        ],
        teamSharedEnvs: [
          { key: 'TEAM_ORG', value: 'acme-corp' },
          { key: 'SHARED_TIER', value: 'from-team' },
          { key: 'OVERRIDE_ME', value: 'from-team' }
        ],
        apps: [
          {
            uuid: 'app-eu',
            name: 'Alpha Web EU',
            fqdn: 'https://eu.acme.dev',
            project_id: 'proj-alpha',
            destination: { server: { uuid: 'srv-eu-1', name: 'EU Primary', ip: '198.51.100.10', is_localhost: true } },
            environment_variables: [
              { key: 'OVERRIDE_ME', value: 'from-resource', is_preview: false }
            ]
          },
          {
            uuid: 'app-us',
            name: 'Beta Worker US',
            fqdn: 'https://us.acme.dev',
            project_id: 'proj-beta',
            server_uuid: 'srv-us-2',
            environment_variables: []
          }
        ],
        databases: [
          {
            uuid: 'db-us',
            name: 'Beta PG',
            database_type: 'standalone-postgresql',
            project_id: 'proj-beta',
            server_uuid: 'srv-us-2'
          }
        ],
        services: []
      };

      const plan = coolifyMigrator.buildMigrationPlan(multiServerSnapshot, {
        serverMap: { 'srv-us-2': 'node_us_east_1' }
      });

      assert.strictEqual(plan.multiServerDetected, true);
      assert.strictEqual(plan.serverMappings.length, 2);
      const euMap = plan.serverMappings.find((s) => s.coolifyServerUuid === 'srv-eu-1');
      const usMap = plan.serverMappings.find((s) => s.coolifyServerUuid === 'srv-us-2');
      assert.ok(euMap && euMap.culkiboFleetTarget === 'local' && euMap.resourceCount === 1);
      assert.ok(usMap && usMap.culkiboFleetTarget === 'node_us_east_1' && usMap.resourceCount === 2);

      // Verify migrated projects receive exact 3-tier env precedence & fleetTargetHint!
      const createdProjects = [];
      const res = await coolifyMigrator.migrateFromSnapshot(multiServerSnapshot, {
        serverMap: { 'srv-us-2': 'node_us_east_1' },
        projectManager: {
          create: (p) => { createdProjects.push(p); return { ...p }; },
          flushToDisk: async () => {}
        },
        domainManager: { addDomain: async () => {} },
        cronManager: { create: () => {} }
      });

      assert.strictEqual(res.importedApps, 2);
      assert.strictEqual(res.serverMappings.length, 2);
      const alphaProj = createdProjects.find((p) => p.id === 'proj-alpha');
      const betaProj = createdProjects.find((p) => p.id === 'proj-beta');
      assert.strictEqual(alphaProj.envVars.TEAM_ORG, 'acme-corp');
      assert.strictEqual(alphaProj.envVars.SHARED_TIER, 'from-project');
      assert.strictEqual(alphaProj.envVars.PROJECT_ONLY, 'alpha-1');
      assert.strictEqual(alphaProj.envVars.OVERRIDE_ME, 'from-resource');
      assert.strictEqual(alphaProj.fleetTargetHint, 'local');
      assert.strictEqual(betaProj.envVars.SHARED_TIER, 'from-beta');
      assert.strictEqual(betaProj.envVars.PROJECT_ONLY, undefined);
      assert.strictEqual(betaProj.fleetTargetHint, 'node_us_east_1');
    });

    console.log(`\n✅ Time-Machine, FinOps & Coolify 3-Tier Suite: ${passed}/4 tests PASSED!`);
  } finally {
    try { cm.stopScheduler(); } catch (e) {}
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runTests().catch((err) => {
    console.error('❌ Time-Machine & FinOps test failed:', err);
    process.exit(1);
  });
}

module.exports = runTests;
