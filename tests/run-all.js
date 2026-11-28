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
const testCanaryAndLogArchive = require('./canary-and-logarchive.test');
const testDrAiBuilder = require('./dr-ai-builder.test');
const testCycle10HttpE2E = require('./cycle10-http-e2e.test');
const testAdmissionAndExperiments = require('./admission-and-experiments.test');
const testComplianceAndVolumes = require('./compliance-and-volumes.test');
const testCycle11HttpE2E = require('./cycle11-http-e2e.test');
const testSyntheticAndAutoscaler = require('./synthetic-and-autoscaler.test');
const testSqllintLicenseSeccomp = require('./sqllint-license-seccomp.test');
const testCycle12HttpE2E = require('./cycle12-http-e2e.test');
const testCronLeaseAndOncall = require('./cron-lease-and-oncall.test');
const testImagePiiOom = require('./image-pii-oom.test');
const testCycle13HttpE2E = require('./cycle13-http-e2e.test');
const testEgressAndChaos = require('./egress-and-chaos.test');
const testReplicaSecretMultiarch = require('./replica-secret-multiarch.test');
const testCycle14HttpE2E = require('./cycle14-http-e2e.test');
const testMtlsAndRatelimit = require('./mtls-and-ratelimit.test');
const testFlagsAnomalyPromotion = require('./flags-anomaly-promotion.test');
const testCycle15HttpE2E = require('./cycle15-http-e2e.test');
const testStreamGuardAndDnsCutover = require('./stream-guard-and-dns-cutover.test');
const testContractOciOrphan = require('./contract-oci-orphan.test');
const testCycle16HttpE2E = require('./cycle16-http-e2e.test');
const testCacheAndRightsizer = require('./cache-and-rightsizer.test');
const testReproPreviewPostmortem = require('./repro-preview-postmortem.test');
const testCycle17HttpE2E = require('./cycle17-http-e2e.test');
const testPiiScrubberAndDrain = require('./pii-scrubber-and-drain.test');
const testQueryNetsegUpgrades = require('./query-netseg-upgrades.test');
const testCycle18HttpE2E = require('./cycle18-http-e2e.test');
const testWebhookFirewallAndTrafficShift = require('./webhook-firewall-and-traffic-shift.test');
const testDiskCredsQueueDlq = require('./disk-creds-queue-dlq.test');
const testCycle19HttpE2E = require('./cycle19-http-e2e.test');
const testProxyTrustAndMcpPoison = require('./proxy-trust-and-mcp-poison.test');
const testValkeyHardenerWorm = require('./valkey-hardener-worm.test');
const testCycle20HttpE2E = require('./cycle20-http-e2e.test');

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
    { name: 'SLO Error-Budget Canary Auto-Rollback (Caddy v2.11) & Compressed .ndjson.gz Log Archive', fn: testCanaryAndLogArchive },
    { name: 'DR Backup Fire-Drill Verifier, Self-Hosted AI/GPU LLM Orchestrator & Remote Build-Node Offloader', fn: testDrAiBuilder },
    { name: 'Cycle #10 Milestone Live Isolated HTTP E2E (All 5 API Families + Cross-Tenant ACL + ReDoS Guard)', fn: testCycle10HttpE2E },
    { name: 'Policy-as-Code Deployment Admission Engine (10 CIS/PSS Rules) & Edge Geo-Routing / Sticky A/B Experiments', fn: testAdmissionAndExperiments },
    { name: 'Ed25519-Signed Compliance Evidence Bundle (SOC 2/ISO/GDPR) & Zero-Shell Stateful Volume Migration Planner', fn: testComplianceAndVolumes },
    { name: 'Cycle #11 Enterprise Governance & Multi-Region Edge Live Isolated HTTP E2E (All 4 API Families + 422/403 Guards)', fn: testCycle11HttpE2E },
    { name: 'Synthetic Multi-Step API Flow Monitor, Live TLS/SNI Sentinel & KEDA Worker Autoscaler / Backpressure Breaker', fn: testSyntheticAndAutoscaler },
    { name: 'Zero-Downtime SQL DDL Linter (10 Rules), CycloneDX 1.6 SPDX License Auditor & Tailored Seccomp / runc CVE Guard', fn: testSqllintLicenseSeccomp },
    { name: 'Cycle #12 Reliability & Security Live Isolated HTTP E2E (All 5 API Families + RBAC/ACL + Seccomp/SSRF Guards)', fn: testCycle12HttpE2E },
    { name: 'Distributed Cron Fencing-Token Lease Guard & On-Call Escalation Router / Flapping Damper', fn: testCronLeaseAndOncall },
    { name: 'Container Image Bloat/Secret Auditor, Deterministic PR-Preview PII Masker & 8-Class OOM Forensics Classifier', fn: testImagePiiOom },
    { name: 'Cycle #13 150-MCP Milestone Live Isolated HTTP E2E (All 5 API Families + RBAC/ACL + Zero-PII/Dedup Guards)', fn: testCycle13HttpE2E },
    { name: 'Container Egress/nftables Drift Auditor & Chaos Fault-Injection GameDay Simulator / Resilience Scorecard', fn: testEgressAndChaos },
    { name: 'Blue/Green DB Read-Replica Fencing, Pre-Deploy Shannon-Entropy Secret Gate & Multi-Arch OCI Matrix Planner', fn: testReplicaSecretMultiarch },
    { name: 'Cycle #14 Resilience, Fencing & Secret-Gate Live Isolated HTTP E2E (All 5 API Families + Prod Lock + RBAC/ACL)', fn: testCycle14HttpE2E },
    { name: 'Zero-Trust SPIFFE-Lite mTLS Identity CA & Edge API Rate-Limit / AI Wallet-Drain Shield (RPM + TPM)', fn: testMtlsAndRatelimit },
    { name: 'OpenFeature-Lite Feature Flags / Kill-Switch, Falco-Lite Runtime Anomaly Detector & Immutable Digest Promotion', fn: testFlagsAnomalyPromotion },
    { name: 'Cycle #15 160-MCP Milestone Live Isolated HTTP E2E (All 5 API Families + Zero-CA-Key + 429/Dual-Control Guards)', fn: testCycle15HttpE2E },
    { name: 'Edge WS/SSE Flood & 101 Hop-by-Hop Guard (CVE-2026-55458) & Zero-Downtime DNS Cutover / Cloudflare Proxy Verifier', fn: testStreamGuardAndDnsCutover },
    { name: 'Post-Optic API Contract Gate, Pure-Node OCI/SLSA Rekor Verifier (CVE-2026-22703) & Orphan PR-Preview Auto-Reaper', fn: testContractOciOrphan },
    { name: 'Cycle #16 165-MCP Milestone Live Isolated HTTP E2E (All 5 API Families + Rekor/101/Proxy/Reaper Guards + RBAC)', fn: testCycle16HttpE2E },
    { name: 'Surrogate-Key Edge Cache & Stampede Coalescer (souin#884/#850) & VPA-Lite Container Rightsizer (dokploy#4050/#903)', fn: testCacheAndRightsizer },
    { name: 'Reproducible Build / Cache Verifier (CVE-2026-93318), Preview Smoke-Gate & Blameless Postmortem Correlator', fn: testReproPreviewPostmortem },
    { name: 'Cycle #17 170-MCP Milestone Live Isolated HTTP E2E (All 5 API Families + Fork/OOM/Cache/Postmortem Guards + RBAC)', fn: testCycle17HttpE2E },
    { name: 'Streaming Log PII Scrubber (otel-contrib#49858/#50770) & 4-Phase Graceful Shutdown / Zero-Drop Drain (coolify#8627)', fn: testPiiScrubberAndDrain },
    { name: 'DB Query-Plan/Pool Guard (PgBouncer/Prisma), Network Micro-Seg (dokploy#2798) & CVE Fast-Track Upgrade Planner', fn: testQueryNetsegUpgrades },
    { name: 'Cycle #18 175-MCP Milestone Live Isolated HTTP E2E (All 5 API Families + Pool/NetSeg/CVE/PII/Drain Guards + RBAC)', fn: testCycle18HttpE2E },
    { name: 'Inbound Webhook HMAC/Replay Firewall (CVE-2026-41351) & Multi-Region Health-Gated Blue/Green Traffic Shift (Caddy#7544)', fn: testWebhookFirewallAndTrafficShift },
    { name: 'Dual Block+Inode Disk/pg_wal Guard (Dokploy#4651), Credential Expiry Watchdog (Coolify#4702) & Queue Schema/DLQ Gate', fn: testDiskCredsQueueDlq },
    { name: 'Cycle #19 180-MCP & 80-Suites Milestone Live Isolated HTTP E2E (All 5 API Families + Replay/Inode/Shift/Watchdog/DLQ + RBAC)', fn: testCycle19HttpE2E },
    { name: 'Reverse-Proxy Trust Boundary / Smuggling Guard (CVE-2026-30851) & MCP Rug-Pull / Tool-Poisoning Guard (CVE-2025-54136)', fn: testProxyTrustAndMcpPoison },
    { name: 'Valkey/Redis Kernel & Eviction Guard, EOL Base-Image / Copa Distroless Hardener & WORM Backup AES-256-GCM KEK Rotation', fn: testValkeyHardenerWorm },
    { name: 'Cycle #20 185-MCP & 83-Suites Milestone Live Isolated HTTP E2E (All 5 API Families + Trust/Valkey/Copa/WORM/MCPoison + RBAC)', fn: testCycle20HttpE2E },
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
