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
const testCaddy = require('./caddy.test');
const testDatabases = require('./database.test');
const testDeploy = require('./deploy.test');
const testShellSafety = require('./shell-safety.test');
const testCatalog = require('./catalog.test');
const testLiveSync = require('./live-sync.test');
const testCompetitorBenchmarks = require('./competitor-benchmarks.test');
const testSecurityHardening = require('./security-hardening.test');
const testImporters = require('./importers.test');
const testMetricsAndBugs = require('./metrics-and-bugs.test');
const testScaleAndWildcard = require('./scale-and-wildcard.test');
const testResilienceAndFeatures = require('./resilience-and-features.test');
const testCompetitorPrs = require('./competitor-prs.test');
const testTelemetry = require('./telemetry.test');
const testFleet = require('./fleet.test');
const testRbac = require('./rbac.test');
const { testEnvironmentsGitops } = require('./environments-gitops.test');
const testUptimeSleep = require('./uptime-sleep.test');
const { testCoreBoost } = require('./core-boost.test');
const testAdversarialFuzz = require('./adversarial-fuzz.test');
const testCliDx = require('./cli-dx.test');
const testObservabilityAlerts = require('./observability-alerts.test');
const testEditionAndBola = require('./edition-and-bola.test');
const testSmartPackDirectPush = require('./smartpack-directpush.test');
const testEdgeTunnelSnapStream = require('./edgetunnel-snapstream.test');
const testCoolifyE2EReplay = require('./coolify-e2e-replay.test');
const testReleaseAndMcpE2E = require('./release-and-mcp-e2e.test');
const testOtlpAndSlsa = require('./otlp-and-slsa.test');
const testMigrationsAndWasm = require('./migrations-and-wasm.test');
const testShadowReplay = require('./shadow-replay.test');
const testTimeMachineFinOps = require('./timemachine-finops.test');
const testTerminalAndShield = require('./terminal-and-shield.test');
const testMeshAndHealer = require('./mesh-and-healer.test');
const testCronHeartbeat = require('./cron-heartbeat.test');
const testPasskeyLeaseCve = require('./passkey-lease-cve.test');
const testDriftAndIac = require('./drift-and-iac.test');
const testUptimeMaintenanceCaa = require('./uptime-maintenance-caa.test');
const testWebhooksAndS3 = require('./webhooks-and-s3.test');
const testDbStudioAndQuotas = require('./dbstudio-and-quotas.test');
const testBrandTheme = require('./brand-theme.test');

const { ensureDaemon } = require('./helpers/daemon');

async function runAll() {
  console.log('\n======================================================');
  console.log('🧪 RUNNING CULKIBO v1.2.0 FULL VERIFICATION SUITE');
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
    // Va la primera: es una propiedad estática del código, no depende del
    // daemon, y si falla el README ha dejado de ser cierto.
    { name: 'Shell-Safety (sin construcción de comandos de shell)', fn: testShellSafety },
    { name: 'Cloudflare Integration', fn: testCloudflare },
    { name: 'SSL Wildcard & On-Demand TLS', fn: testSsl },
    { name: 'Domain Manager & Routing', fn: testDomain },
    { name: 'Pod Orchestrator (Forge & Citadel)', fn: testOrchestrator },
    { name: 'Model Context Protocol (MCP) Server', fn: testMcp },
    { name: 'Database & Project Backup / Restore', fn: testBackup },
    { name: 'GitHub Integration & Auto-Deploy Webhooks', fn: testGithub },
    { name: 'Coolify Deep Migrator & Resources', fn: testCoolifyMigrator },
    { name: 'Local Execution Runner & Dev Server', fn: testLocalRunner },
    { name: 'Project Stop & Hibernate Lifecycle', fn: testStopLifecycle },
    { name: 'Ingress Data Plane (Caddy)', fn: testCaddy },
    { name: 'Managed Databases (Provision, Backup, S3, Retention)', fn: testDatabases },
    { name: 'Production Deploy Pipeline (build, cutover, rollback)', fn: testDeploy },
    { name: 'One-Click Service Catalog (100 templates, 12 categories, secrets, ports)', fn: testCatalog },
    { name: 'Live Sync Engine (Commit Frames, Merkle, Rollback <10ms, WS)', fn: testLiveSync },
    { name: 'Security Hardening (SSRF, Proxy Loopback, Symlinks, Redaction)', fn: testSecurityHardening },
    { name: 'WordPress Migrator & Universal Importer (Compose/Git/Platforms)', fn: testImporters },
    { name: 'Observability, Prometheus, Doctor & Bug Regressions', fn: testMetricsAndBugs },
    { name: 'Scale, Multi-Wildcard SSL, Build Semaphore & Fast-Path', fn: testScaleAndWildcard },
    { name: 'Resilience, Edge Hardening, DR Snapshots, Crons/Previews & Multi-Git', fn: testResilienceAndFeatures },
    { name: 'Competitor PR & CVE Regressions (Wave-1 + Wave-2 + Wave-3)', fn: testCompetitorPrs },
    { name: 'Anonymous Telemetry, PII Scrubbing, Circuit Breaker & E2E Collector', fn: testTelemetry },
    { name: 'Multi-Server SSH Fleet Orchestration (TOFU, Tunnels, Key Vault)', fn: testFleet },
    { name: 'Multi-User Teams, RBAC, Scoped Tokens & Triple-Layer Revocation', fn: testRbac },
    { name: 'Environments, Encrypted Vault, Promotion & GitOps culkibo.yaml', fn: testEnvironmentsGitops },
    { name: 'Synthetic Uptime Monitors, Public Status Pages & Auto-Sleep Advisor', fn: testUptimeSleep },
    { name: 'Core +70% Boost (Smoke Tests, Canary Auto-Guard, Freeze Windows, Remote Fleet)', fn: testCoreBoost },
    { name: 'Competitor Benchmarks & Parity Verification', fn: testCompetitorBenchmarks },
    { name: 'Adversarial Fuzz & Crash Recovery', fn: testAdversarialFuzz },
    { name: 'CLI DX (init, up, logs, env, exec, releases, rollback)', fn: testCliDx },
    { name: 'Observability Alerts, Metrics History & Topology', fn: testObservabilityAlerts },
    { name: 'Edition Ed25519 Verifier, CronParser Anti-DoS, Project Secrets & BOLA/IDOR Closure', fn: testEditionAndBola },
    { name: 'SmartPack Build Intelligence, DirectPush OCI v2 & Edge/FD Hardening', fn: testSmartPackDirectPush },
    { name: 'Sovereign EdgeTunnel WS, SnapStream SQLite WAL-to-S3 & Preview DB Branching', fn: testEdgeTunnelSnapStream },
    { name: 'Mock-Coolify v4 Full E2E Migration & Bundle Roundtrip Replay', fn: testCoolifyE2EReplay },
    { name: 'Release Provenance (CycloneDX 1.6 SBOM / SHA-256) & External MCP Stdio E2E', fn: testReleaseAndMcpE2E },
    { name: 'Zero-Dep OTLP/HTTP JSON Exporter & SLSA v1.1 Ed25519 DSSE Attestation', fn: testOtlpAndSlsa },
    { name: 'Atomic Single-Leader DB Migrations, Per-PR Schema Isolation & Micro-Wasm Edge Runtime', fn: testMigrationsAndWasm },
    { name: 'Shadow Traffic Replay & Automatic Cutover Regression Gate', fn: testShadowReplay },
    { name: 'Whole-Stack Time-Machine Checkpoints, Cloud-vs-Self-Hosted FinOps & Coolify v4 Parity', fn: testTimeMachineFinOps },
    { name: 'Zero-Dep Container Web Terminal (/ws/terminal) & Caddy Edge Shield PoW Gate', fn: testTerminalAndShield },
    { name: 'Zero-Config WireGuard Fleet Mesh (x25519) & 20-Pattern Build Auto-Healer', fn: testMeshAndHealer },
    { name: 'Cron 24h Visual Collision Heatmap & Dead-Man\'s-Switch Heartbeats', fn: testCronHeartbeat },
    { name: 'Zero-Dep WebAuthn Passkeys (FIDO2), Ephemeral Secret Leases & OSV.dev SBOM CVE Drift', fn: testPasskeyLeaseCve },
    { name: 'Live Container/DB Config Drift Detector, PgBouncer Smart Pool & OpenTofu/Compose IaC Exporter', fn: testDriftAndIac },
    { name: 'Maintenance Windows (#7704/#8193), Public Incident Timeline, Multi-CAA (#6519), 6-Day ACME & Geo-Failover', fn: testUptimeMaintenanceCaa },
    { name: 'Standard-Webhooks Outbound Event Bus + DLQ & Post-MinIO S3 Orchestrator / AWS SigV4 Presigner', fn: testWebhooksAndS3 },
    { name: 'Zero-Dep Read-Only Live DB Studio, Safe Redis Inspector & Agency Multi-Tenant Quotas / CSV Billing Ledger', fn: testDbStudioAndQuotas },
    { name: 'Open-Core White-Label Brand & Custom Login Theme Engine (coolify#1744 Anti-XSS)', fn: testBrandTheme },
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

  // Red de seguridad antes de cerrar.
  //
  // `server/index.js` instala manejadores globales de `uncaughtException` y
  // `unhandledRejection` para que el daemon no se caiga nunca. En las pruebas
  // eso se vuelve en contra: si el cierre se queda a medias, el proceso sigue
  // vivo reteniendo el puerto 3030. La siguiente ejecución encontraba ese
  // daemon zombi, `ensureDaemon()` lo reutilizaba en vez de arrancar uno limpio
  // y las suites fallaban contra un estado que no era el suyo. Un único fallo
  // se convertía así en una cadena de fallos sin relación con el código.
  const watchdog = setTimeout(() => {
    console.error('⚠ El cierre no terminó a tiempo; se fuerza la salida para no dejar el puerto ocupado.');
    process.exit(failed > 0 ? 1 : 0);
  }, 5000);
  if (watchdog.unref) watchdog.unref();

  if (stopDaemon) {
    try { await stopDaemon(); } catch (e) {}
  }
  clearTimeout(watchdog);

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runAll().catch((err) => {
  console.error('❌ La ejecución de la suite se interrumpió:', err);
  process.exit(1);
});
