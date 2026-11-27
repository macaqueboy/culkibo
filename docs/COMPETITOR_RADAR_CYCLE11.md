# Culkibo Cycle-11 Competitor Forensics & Cycle-12 Pioneer Blueprint

> **Date:** 2026-11-27 · **Baseline:** Cycle #10 (`99.6%+`, `49 MB` RSS, `116.6 ms` boot, `10,679 req/s` auth, `44 µs` Micro-Wasm, `53` suites, `135` MCP tools, `ROOT_DEPS=6`) · **Scope:** Fresh 2025–2026 CVEs, PRs & issues (zero overlap with Cycles #1, #3, #6–#10) + 5 zero-dep Cycle-12 breakthroughs.

---

## 1. Fresh 2025–2026 Competitor Forensics (Synthetic/TLS, DDL Locks, Autoscaling & `runc`/Licenses)

| Domain | Real 2025–2026 Citations | Root Cause & Production Blast Radius | Culkibo Guardrail & Win |
|---|---|---|---|
| **Multi-Step Synthetic & TLS/SNI Drift Gaps** | [`uptime-kuma#5772`](https://github.com/louislam/uptime-kuma/issues/5772) (multi-step HTTP), [`#7500`](https://github.com/louislam/uptime-kuma/issues/7500) (cert expiry w/ SNI+IP), [`#7682`](https://github.com/louislam/uptime-kuma/issues/7682); [`gatus#856`](https://github.com/TwiN/gatus/issues/856), [`#1940`](https://github.com/TwiN/gatus/issues/1940); Traefik ACME stop-retry & `.traefik.me` expiry | Single-GET ping checks miss broken login/checkout flows (`#5772`); cached TLS probes hide SAN/issuer drift (`gatus#856`); Traefik halts ACME retries permanently after transient DNS lag until manual proxy restart. | Native **Multi-Step API Flow Monitor** (chained token extract + JSON/latency assertions, zero secret retention) + uncached live **`tls.connect` SAN/Issuer/Expiry Sentinel**. |
| **Lock-Heavy SQL DDL Outages During Deploys** | [`sbdchd/squawk`](https://github.com/sbdchd/squawk) (`require-concurrent-index-creation`, `adding-field-with-default`), [`ankane/strong_migrations`](https://github.com/ankane/strong_migrations) (`lock_timeout`, `NOT VALID`) | `CREATE INDEX` (non-concurrent), `ADD CONSTRAINT` (without `NOT VALID`), `ALTER COLUMN TYPE`, and missing `lock_timeout` grab `ACCESS EXCLUSIVE` locks queuing every web connection into instant outage; `DROP COLUMN` crashes live old pods mid-cutover. | Pre-deploy **Zero-Downtime SQL Migration Linter** enforcing 10 Expand-Contract & lock-safety rules before `migrationRunner.js` touches prod DBs. |
| **Autoscaling Flapping & Swarm Replica Thrash** | [`dokploy#6105`](https://github.com/Dokploy/dokploy/issues/6105) (replica scaling/HPA), [`coolify#3862`](https://github.com/coollabsio/coolify/discussions/3862) (`deploy.replicas` naming), [`caprover#2164`](https://github.com/caprover/caprover/discussions/2164) (1 failed replica cycling all); [`kedacore/keda`](https://github.com/kedacore/keda) `cooldownPeriod` | Self-hosted PaaSes either lack queue-driven scaling (`dokploy#6105`, `coolify#3862`) or thrash/OOM small VPSes without cooldown hysteresis & memory ceilings; Swarm restarts cascade across healthy replicas (`caprover#2164`). | **Queue/Worker Autoscaler + Backpressure Breaker** with hysteresis deadbands, cooldown windows, hard VPS RAM ceiling (`maxSafeReplicas`), and `503 Retry-After` load shedding. |
| **`runc` Mount-Race Escapes, `io_uring` & SSPL Traps** | **`runc CVE-2025-31133`**, **`CVE-2025-52565`**, **`CVE-2025-52881`** (`<=1.2.7` / `1.3.2` `/dev/null` & `/dev/console` escapes); `io_uring` seccomp bypasses; **CycloneDX 1.6 (ECMA-424)** AGPL/SSPL custom `LicenseRef-*` | Malicious mounts exploited `runc` races to overwrite host `/proc/sys/kernel/core_pattern`; teams drop to `seccomp=unconfined` dangerously; non-OSI **SSPL** dependencies slip past naive SPDX checks as custom strings. | **Runtime-Tailored Seccomp Generator** (`node`/`python`/`go`/`rust` blocking `io_uring_*`/`mount`/`ptrace`/`bpf`) + `runc` version doctor check + **CycloneDX 1.6 License Auditor**. |

---

## 2. Top 5 Zero-Dep (`ROOT_DEPS=6`) Cycle-12 Pioneering Breakthroughs

All 5 preserve **`ROOT_DEPS=6` (0 new runtime npm deps)**, `shell: false`, and `<= 60 MB` idle RSS:

### 1. Synthetic Multi-Step API Flow Monitor & TLS/CT Sentinel (`server/services/syntheticSentinelService.js`)
- **Chained API Flows (`uptime-kuma#5772`):** Executes ordered HTTP steps (`[{ name, method, url, headers, body, extract: { token: 'json.access_token' }, assert: { status: 200, maxLatencyMs: 500, jsonPathEquals: ... } }]`) with SSRF validation on every step (`ssrfGuard.js`), ephemeral per-run variable interpolation (`{{token}}`), and strict **zero-secret persistence** (extracted tokens/headers redacted before saving run history in `CULKIBO_DATA_DIR/data/synthetic-flows.json`).
- **Live TLS/SNI/SAN Expiry & Drift Sentinel (`uptime-kuma#7500`, `gatus#856`):** Opens uncached Node `tls.connect({ host: targetIp || hostname, port, servername: sni || hostname })` to capture live `daysRemaining` (`<=14d` warn / `<=3d` critical), SAN DNS list match, SHA-256 leaf fingerprint & issuer drift vs baseline, and TLS protocol version (`TLSv1.3`).

### 2. Zero-Downtime SQL Migration Linter (`server/services/sqlMigrationLinter.js`)
- **Squawk / Strong Migrations Engine (0 Deps):** Statically tokenizes SQL DDL (stripping `--`/`/* */` comments and string literals) across 10 production safety rules: `CREATE_INDEX_NOT_CONCURRENT`, `DROP_INDEX_NOT_CONCURRENT`, `MISSING_LOCK_TIMEOUT`, `MISSING_STATEMENT_TIMEOUT`, `UNSAFE_ADD_CONSTRAINT` (missing `NOT VALID`), `DESTRUCTIVE_DROP_COLUMN_OR_TABLE` (expand-contract violation), `ALTER_COLUMN_TYPE_REWRITE`, `SET_NOT_NULL_WITHOUT_CHECK`, `VOLATILE_ADD_COLUMN_DEFAULT`, and `UNSAFE_RENAME_OBJECT`.
- Returns `{ safe, score, blockers[], warnings[], rewriteHints[], analyzedStatements }` — callable directly before `migrationRunner.js` and via MCP `culkibo_lint_sql_migration`!

### 3. Queue / Worker Autoscaler & Backpressure Circuit Breaker (`server/services/workerAutoscalerService.js`)
- **KEDA Hysteresis + Hard VPS Memory Ceiling (`dokploy#6105`, `coolify#3862`, `caprover#2164`):** Evaluates `{ queueDepth, httpSaturationPct, currentReplicas, hostFreeRamMb, perReplicaRamMb, lastScaleAtMs }` against persisted policy (`minReplicas`, `maxReplicas`, `scaleUpQueueDepth`, `scaleDownQueueDepth`, `scaleUpCooldownSec`, `scaleDownCooldownSec`, `reserveHostRamMb`):
  - Computes `maxSafeReplicas = Math.max(minReplicas, Math.floor((hostFreeRamMb - reserveHostRamMb) / perReplicaRamMb))` so scaling **never OOM-kills** the VPS.
  - Enforces hysteresis deadband & cooldown suppression (`reason: 'COOLDOWN_ACTIVE' | 'MEMORY_CEILING_CAPPED' | 'HYSTERESIS_HOLD'`).
  - Trips **Backpressure Circuit Breaker** (`OPEN`, returning `retryAfterSec`) when queue depth exceeds `breakerQueueThreshold` or free RAM drops below `reserveHostRamMb`.

### 4. SBOM SPDX License Compliance & Dependency Risk Auditor (`server/services/licenseAuditorService.js`)
- **CycloneDX 1.6 (ECMA-424) Policy Gate:** Parses CycloneDX 1.6 JSON SBOMs (or lockfiles via `scripts/release-provenance.js`), splitting compound SPDX expressions (`MIT OR Apache-2.0`, `MIT AND GPL-3.0-only`) and categorizing every component into `permissive`, `weak_copyleft`, `strong_copyleft` (`AGPL-*`, `GPL-*`), `source_available` (`SSPL-*`, `BSL-*`, `Elastic-2.0`, `LicenseRef-*`), or `unknown`.
- Ships `saas-strict` (blocks `AGPL`, `SSPL`, `GPL`, `unknown`), `oss-permissive`, and `audit-only` presets, returning `{ compliant, score, countsByCategory, violations[], warnings[] }` + MCP `culkibo_audit_licenses`.

### 5. Runtime-Tailored Seccomp Profile Generator & `runc` CVE Guard (`server/services/seccompProfileService.js`)
- **Tailored Least-Privilege OCI `seccomp.json`:** Generates minimal allowlist profiles (`defaultAction: "SCMP_ACT_ERRNO"`) per stack (`node`, `python`, `go`, `rust`, `static-caddy`), strictly **omitting/blocking** `io_uring_setup`/`io_uring_enter`/`io_uring_register`, `ptrace`, `mount`, `umount2`, `pivot_root`, `unshare`, `setns`, `keyctl`, `bpf`, `kexec_load`, `init_module`, and `reboot`, while refusing `seccomp=unconfined`.
- **`runc` CVE-2025-31133 / CVE-2025-52565 / CVE-2025-52881 Audit:** `auditRuncVersion(versionStr)` semver-checks host `runc` output (`<=1.2.7`, `1.3.0..1.3.2`, `1.4.0-rc.1..2` → `CRITICAL` escape alert; `>=1.2.8` / `>=1.3.3` → `PASS`), wired cleanly into `systemDoctor.js`!

---

## 3. Exact Cycle-12 Regression Tests (`tests/competitor-prs.test.js`)

1. **Uptime Kuma `#5772`/`#7500` & Gatus `#856`:** Assert `syntheticSentinelService` runs a live 2-step loopback login→token→assert flow (redacting extracted token + blocking `169.254.169.254` SSRF) and evaluates TLS cert expiry/SAN/issuer drift accurately.
2. **Squawk / Strong Migrations DDL Locks:** Assert `sqlMigrationLinter` blocks `CREATE INDEX` without `CONCURRENTLY`, `FOREIGN KEY` without `NOT VALID`, `DROP COLUMN`, `ALTER COLUMN TYPE`, and missing `lock_timeout`, while passing safe `SET lock_timeout='5s'; CREATE INDEX CONCURRENTLY ...`.
3. **Dokploy `#6105` / CapRover `#2164` / KEDA Autoscaler:** Assert `workerAutoscalerService` enforces cooldown anti-flapping, caps scale-up strictly at VPS RAM budget (0 OOM), and trips backpressure circuit breaker (`503 Retry-After`) under overload.
4. **CycloneDX 1.6 AGPL / SSPL / `LicenseRef-*`:** Assert `licenseAuditorService` catches `AGPL-3.0-only`, `SSPL-1.0`, `LicenseRef-proprietary`, and missing licenses under `saas-strict` while passing `MIT`/`Apache-2.0`/`ISC` trees.
5. **`runc CVE-2025-31133`/`CVE-2025-52565` & `io_uring` Seccomp:** Assert `seccompProfileService` emits valid `SCMP_ACT_ERRNO` JSON per stack with `io_uring_*`/`mount`/`ptrace`/`bpf` denied, rejects `unconfined`, and flags `runc 1.2.7` & `1.3.2` while passing `1.2.8` & `1.3.3`.
