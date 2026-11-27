# Culkibo Cycle-13 Competitor Forensics & Cycle-14 Pioneer Blueprint

> **Date:** 2026-11-27 · **Baseline:** Cycle #12 (`8c4f385`, `99.61%`, `54 MB` RSS, `83 µs` Wasm, `59→62` suites, `145→150` MCP tools, `ROOT_DEPS=6`) · **Scope:** Fresh 2025–2026 PRs, issues & OSS standards (zero overlap with Cycles #1, #3, #6–#12) + 5 zero-dep Cycle-14 blueprints.

---

## 1. Fresh 2025–2026 Competitor Forensics (Egress/nftables, Split-Brain, Secret Gate, Multi-Arch & Chaos)

| Domain | Real 2025–2026 Citations | Root Cause & Operational Blast Radius | Culkibo Guardrail & Win |
|---|---|---|---|
| **Docker `nftables` / `DOCKER-USER` & Egress Drift** | Docker 29 `--firewall-backend=nftables` `DOCKER-USER` regressions; [`coolify#12336`](https://github.com/coollabsio/coolify/discussions/12336) (firewall UI demand) & `firewalld` `br-*` egress breaks; [`dokploy#2486`](https://github.com/Dokploy/dokploy/issues/2486) | Custom bridge interfaces (`br-*`) bypass host `docker0` rules, `nftables` migrations corrupt `DOCKER-USER` chains, and compromised containers exfiltrate data freely with zero outbound allowlisting. | Native **Container Egress & Firewall Drift Auditor** verifying `DOCKER-USER`/`nftables` rules, flagging metadata/rogue egress, and preserving anti-lockout SSH/HTTP/HTTPS ports. |
| **DB Read-Replica Split-Brain & Lagging Promotion** | [`cloudnative-pg#8701`](https://github.com/cloudnative-pg/cloudnative-pg/issues/8701) (lagging standby promotion + `pg_rewind` data loss), [`#7407`](https://github.com/cloudnative-pg/cloudnative-pg/issues/7407)/[`#7462`](https://github.com/cloudnative-pg/cloudnative-pg/issues/7462) (partition split-brain); [`patroni#3474`](https://github.com/zalando/patroni/issues/3474); [`dokploy#1633`](https://github.com/Dokploy/dokploy/issues/1633)/[`#1640`](https://github.com/Dokploy/dokploy/pull/1640) & [`#429`](https://github.com/Dokploy/dokploy/issues/429) | Promoting a lagging standby discards committed WAL via `pg_rewind` breaking remote timelines (`#8701`); unfenced partitioned primaries accept dual-writes (`#7407`); Dokploy reload dropped replicas to 1 (`#1633`). | **Blue/Green Read-Replica Failover & Fencing Orchestrator** blocking promotion on lag excess or unfenced old primary, with lag-aware read routing & drain plan. |
| **Pre-Deploy Secret Leaks in Git Diffs & `.env`** | [`gitleaks/gitleaks`](https://github.com/gitleaks/gitleaks) & [`trufflesecurity/trufflehog`](https://github.com/trufflesecurity/trufflehog) Shannon-entropy shift-left gates; Coolify/Dokploy plaintext env & git-source advisories | PaaS deploy pipelines blindly clone & bake newly committed API keys, PEM blocks, or high-entropy secrets straight into container layers and preview logs. | Sub-ms zero-dep **Pre-Deploy Shannon-Entropy & Pattern Secret Gate** scanning diffs/`.env`/Compose before build with redacted SHA-256 fingerprints. |
| **Multi-Arch (`amd64`/`arm64`) `exec format error`** | Apple Silicon (`arm64`) → x86 VPS & Ampere `arm64` host crashes; BuildKit OCI Image Index attestation strict-registry `blob unknown` errors | Single-arch images built on Mac/CI crash on mismatched VPS CPUs (`exec format error`); blind QEMU emulation crawls; strict OCI registries reject uncoordinated attestation manifests. | **Multi-Arch OCI Manifest & Matrix Planner** catching `EXEC_FORMAT_MISMATCH` pre-deploy and routing `amd64`/`arm64` to native fleet builders ahead of QEMU. |
| **Unverified Resilience & Missing Chaos GameDays** | [`Shopify/toxiproxy`](https://github.com/Shopify/toxiproxy) (latency/jitter/drop toxics); [`chaos-mesh/chaos-mesh`](https://github.com/chaos-mesh/chaos-mesh) (`NetworkChaos` GameDays & steady-state scoring) | Teams only discover missing client timeouts, thread-pool exhaustion, and broken fallbacks during live outages — zero self-hosted PaaSes offer blast-radius-guarded chaos drills. | Zero-dep **Chaos GameDay Simulator & Resilience Scorecard** with deterministic latency/jitter/5xx faults, prod safety lock & auto-abort guardrails. |

---

## 2. Top 5 Zero-Dep (`ROOT_DEPS=6`) Cycle-14 Blueprints & Exact API Contracts

All 5 keep **`ROOT_DEPS=6`**, `shell: false`, lazy-require, `0o600` atomic storage, and idle RSS `<= 60 MB`:

### 1. Container Egress & Firewall Drift Auditor (`server/services/egressFirewallService.js`)
- **Contract:** Store `CULKIBO_DATA_DIR/data/egress-policies.json`. Exports `saveEgressPolicy(projectId, policy)`, `getEgressPolicy(projectId)`, `auditFirewallAndEgress({ projectId, observedSockets = [], firewallRules = [], backend = 'nftables' })` → `{ ok: true, compliant, riskScore, violations[], missingChains[], antiLockoutSafe, suggestedRules[] }`.
- **Guards (`coolify#12336`, `dokploy#2486`, Docker 29 `nftables`):** Blocks/flags cloud metadata (`169.254.169.254`, `fd00:ec2::254`), unauthorized private-LAN or non-allowlisted outbound sockets, missing `DOCKER-USER` / `nftables` forward-drop chain, and guarantees generated rules always keep ports `22`, `80`, `443` reachable (anti-lockout!).
- **Routes & MCP:** `GET/PUT /api/projects/:id/egress-policy`, `POST /api/projects/:id/egress-audit` (project ACL) · MCP `culkibo_egress_firewall`.

### 2. Blue/Green DB Read-Replica Promotion & Split-Brain Fencing (`server/services/replicaFailoverService.js`)
- **Contract:** Store `CULKIBO_DATA_DIR/data/replica-topologies.json`. Exports `saveTopology(dbId, { primary, replicas[] })`, `getTopology(dbId)`, `evaluateReadWriteSplit(dbId, { maxReadLagMs = 500 })` → `{ writeTarget, readTargets[], excludedLagging[], fallbackToPrimary }`, `planReplicaPromotion(dbId, { targetReplicaId, maxAcceptableLagBytes = 1048576, requireOldPrimaryFenced = true, dryRun = true })` → `{ allowed, blockers[], steps[], promotedNode, timelineNext, dryRun }`.
- **Guards (`cloudnative-pg#8701`/`#7407`, `patroni#3474`):** Refuses promotion when `replica.lagBytes > maxAcceptableLagBytes` (`REPLICA_LAG_TOO_HIGH`) or when `requireOldPrimaryFenced && !primary.fenced` (`OLD_PRIMARY_NOT_FENCED`), preventing timeline divergence & dual-write split-brain; emits ordered drain → fence → promote → re-route steps!
- **Routes & MCP:** `GET/PUT /api/databases/:id/replicas`, `POST /api/databases/:id/replicas/promote` (`dryRun: true` default) · MCP `culkibo_replica_failover`.

### 3. Pre-Deploy Shannon-Entropy & Pattern Secret Gate (`server/services/preDeploySecretGate.js`)
- **Contract:** Exports `computeShannonEntropy(str)`, `SECRET_RULES` (12 rules: PEM private keys, JWTs, cloud access keys, Git/payment/webhook tokens, generic high-entropy assignments `entropy >= 4.2` & `len >= 20`, filtering benign UUIDs/SHA-256 hex commits & `# culkibo:allow-secret` pragmas), `scanPreDeployPayload({ files = [], diffText = '', envMap = {}, mode = 'enforce', allowlistFingerprints = [] })` → `{ ok: true, allowed, mode, scannedItems, blockedCount, findings: [{ location, line, ruleId, severity, entropy, redactedPreview, fingerprintSha256 }] }`.
- **Guarantee:** NEVER echoes or persists matched secret values (only first-4/last-2 masked preview + SHA-256 fingerprint).
- **Routes & MCP:** `POST /api/security/predeploy-secret-scan` (`developer`+) · MCP `culkibo_secret_gate`.

### 4. Multi-Arch (`amd64`/`arm64`) OCI Manifest & Matrix Planner (`server/services/multiArchPlannerService.js`)
- **Contract:** Exports `SUPPORTED_PLATFORMS` (`['linux/amd64', 'linux/arm64']`), `verifyManifestCompatibility({ imageArch, imageOs = 'linux', manifestPlatforms = [], hostArch, strictOciRegistry = false, includeAttestations = true })` → `{ compatible, code, warnings[], remediation }`, `planBuildMatrix({ targetPlatforms = ['linux/amd64', 'linux/arm64'], builders = [], preferNativeOverQemu = true, imageTag })` → `{ assignments[], usesQemu, qemuWarning, buildxArgv[], manifestCreateArgv[] }`.
- **Guards:** Flags `EXEC_FORMAT_MISMATCH` whenever host arch (`amd64`/`arm64`) is absent from image/manifest platforms, warns on strict OCI registry attestation subject rules, and routes each arch to matching native fleet builders before QEMU fallback (zero-shell argv arrays!).
- **Routes & MCP:** `POST /api/build/multiarch/verify`, `POST /api/build/multiarch/plan` (`developer`+) · MCP `culkibo_multiarch_planner`.

### 5. Chaos Fault-Injection GameDay Simulator & Resilience Scorecard (`server/services/chaosGameDayService.js`)
- **Contract:** Store `CULKIBO_DATA_DIR/data/chaos-gamedays.json`. Exports `FAULT_TYPES` (`['latency_jitter', 'http_5xx', 'timeout_drop', 'dns_failure', 'bandwidth_cap']`), `evaluateResilienceScore({ errorRatePct, allowedErrorRatePct = 1.0, p95LatencyMs, sloP95Ms = 400, recoverySec, targetRecoverySec = 30 })` → `{ resilienceScore, grade, breakdown: { errorScore, latencyScore, recoveryScore } }`, `runGameDaySimulation({ projectId, environment = 'staging', explicitProdConfirm = false, faultType = 'latency_jitter', latencyMs = 250, jitterMs = 50, faultRatePct = 10, maxErrorAbortPct = 15, requestSamples = [], dryRun = true })`, `listGameDays(projectId?)`.
- **Safety Guardrails (Toxiproxy/Chaos Mesh DNA):** Hard-blocks `environment === 'production'` unless `explicitProdConfirm === true` (`PROD_CHAOS_CONFIRM_REQUIRED`), triggers instant `status: 'AUTO_ABORTED'` whenever observed error rate breaches `maxErrorAbortPct`, and persists auditable scorecards!
- **Routes & MCP:** `GET /api/projects/:id/chaos/gamedays`, `POST /api/projects/:id/chaos/simulate` (project ACL, `dryRun: true` default) · MCP `culkibo_chaos_gameday`.

---

## 3. Exact Cycle-14 Regression Tests (`tests/competitor-prs.test.js` Section 16 `16a–16e`)

1. **`16a` (`coolify#12336` / `dokploy#2486` / Docker 29 `nftables`):** `egressFirewallService` flags metadata `169.254.169.254` & unauthorized outbound sockets, detects missing `DOCKER-USER` drop chain, and guarantees `antiLockoutSafe: true` preserving SSH/HTTP/HTTPS.
2. **`16b` (`cloudnative-pg#8701`/`#7407` & `patroni#3474`):** `replicaFailoverService` blocks lagging standby (`REPLICA_LAG_TOO_HIGH`) and unfenced primary (`OLD_PRIMARY_NOT_FENCED`), excludes lagging replicas from read pool, and allows promotion once synced + fenced.
3. **`16c` (Gitleaks/TruffleHog Shift-Left):** `preDeploySecretGate` flags dynamically constructed high-entropy secret & PEM fixtures in `enforce` mode with 0 raw secret echoed, while allowing benign UUIDs, SHA-256 hashes, and `# culkibo:allow-secret`.
4. **`16d` (`arm64`/`amd64` `exec format error` & OCI Index):** `multiArchPlannerService` rejects `arm64`-only image on `amd64` host (`EXEC_FORMAT_MISMATCH`), passes multi-arch manifests, and routes builds to native fleet builders ahead of QEMU.
5. **`16e` (Toxiproxy/Chaos Mesh GameDay):** `chaosGameDayService` blocks `environment: 'production'` without `explicitProdConfirm`, auto-aborts when error rate exceeds `maxErrorAbortPct` (`AUTO_ABORTED`), and scores healthy recovery `>= 85`.
