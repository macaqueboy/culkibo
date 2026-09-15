const testCloudflare = require('./cloudflare.test');
const testSsl = require('./ssl.test');
const testDomain = require('./domain.test');
const testOrchestrator = require('./orchestrator.test');
const testMcp = require('./mcp.test');
const testBackup = require('./backup.test');
const testGithub = require('./github.test');
const testCoolifyMigrator = require('./coolifyMigrator.test');
const testLocalRunner = require('./localRunner.test');
const testStopLifecycle = require('./stop-lifecycle.test');

const { ensureDaemon } = require('./helpers/daemon');

async function runAll() {
  console.log('\n======================================================');
  console.log('🧪 RUNNING CULKIBO v1.0.0 FULL VERIFICATION SUITE');
  console.log('======================================================\n');

  let stopDaemon = null;
  try {
    stopDaemon = await ensureDaemon();
  } catch (err) {
    console.error('❌ No se pudo preparar el daemon para las pruebas:', err.message);
    process.exit(1);
  }

  const start = Date.now();
  let passed = 0;
  let failed = 0;

  const suites = [
    { name: 'Cloudflare Integration', fn: testCloudflare },
    { name: 'SSL Wildcard & On-Demand TLS', fn: testSsl },
    { name: 'Domain Manager & Routing', fn: testDomain },
    { name: 'Pod Orchestrator (<35ms Forge & Citadel)', fn: testOrchestrator },
    { name: 'Model Context Protocol (MCP) Server', fn: testMcp },
    { name: 'Database & Project Backup / Restore', fn: testBackup },
    { name: 'GitHub Integration & Auto-Deploy Webhooks', fn: testGithub },
    { name: 'Coolify Deep Migrator & Resources', fn: testCoolifyMigrator },
    { name: 'Local Execution Runner & Dev Server', fn: testLocalRunner },
    { name: 'Project Stop & Hibernate Lifecycle', fn: testStopLifecycle }
  ];

  for (const suite of suites) {
    try {
      await suite.fn();
      passed++;
    } catch (err) {
      console.error(`❌ Suite Failed: ${suite.name}`);
      console.error(err);
      failed++;
    }
  }

  const elapsed = ((Date.now() - start) / 1000).toFixed(2);
  console.log('======================================================');
  console.log(`🏁 TEST SUMMARY: ${passed} passed, ${failed} failed in ${elapsed}s`);
  console.log('======================================================\n');

  if (stopDaemon) await stopDaemon();

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runAll();
