<div align="center">

<img src="web/public/favicon.svg" alt="Culkibo Twin Planes K logo" width="84" height="84" />

# Culkibo

**The `49–54 MB`, `10,679 req/s`, Zero-Shell, AI-Native Self-Hosted PaaS (Open-Source Coolify & Dokploy Alternative)**
Deploy **140+ 1-Click Apps**, **12 Managed Databases**, **PR-Preview DB PII Masker (Post-Snaplet/Neosync)**, **Image Bloat & Secret Auditor**, **8-Class OOM Forensics**, **Cron Fencing-Token Leases**, **On-Call Escalation & Flapping Damper**, **Zero-Downtime SQL Linter**, **OOM-Safe KEDA Autoscaler**, **Synthetic TLS Sentinel**, **SPDX & Seccomp/`runc` Guards**, **Policy Admission**, **Signed SOC 2**, **Ollama/vLLM GPU**, **SRE Canaries**, **Sub-8ms Live Sync 2.0**, **Record `44 µs` Micro-Wasm**, and a **Milestone 150 MCP Tools (`-88.7%` core) + Async Tasks + 3 Inline MCP Apps** for **Claude Code, Antigravity, Cursor, Windsurf & Codex** — on a single **`49–54 MB`** Node.js control plane (`116.6 ms` boot, `10,679 req/s`) with **6 runtime dependencies**, **62 test suites**, and **Caddy v2.11** atomic routing.

[![Release: v1.2.0](https://img.shields.io/badge/Release-v1.2.0-F59E0B.svg)](.github/workflows/release.yml)
[![Interactive Sandbox: Zero Install](https://img.shields.io/badge/Live%20Sandbox-Try%20in%2010s%20(%3Fdemo%3D1)-10B981.svg)](.github/workflows/demo-pages.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-2563EB.svg)](LICENSE)
[![CI: 4 Jobs | 62 Suites | Node 20/22/24 + Caddy + Playwright](https://img.shields.io/badge/CI-62%20Suites%20%7C%20Node%2020%2F22%2F24%20%7C%20Caddy%20%7C%20Playwright-16A34A.svg)](.github/workflows/ci.yml)
[![Idle RAM: 49–54 MB RSS | 10,679 req/s](https://img.shields.io/badge/Idle%20RAM-49--54%20MB%20RSS%20%7C%2010.7k%20req%2Fs-10B981.svg)](#benchmarks-and-reproducible-results)
[![Runtime Deps: 6 | SLSA v1.1 + CycloneDX 1.6](https://img.shields.io/badge/Runtime%20Deps-6%20%7C%20SLSA%20%2B%20SBOM-0F172A.svg)](scripts/release-provenance.js)
[![Zero Shell: Verified](https://img.shields.io/badge/Shell%20Construction-0%20(CI%20Verified)-0F172A.svg)](tests/shell-safety.test.js)
[![MCP 2026-07-28: 150 Tools + Tasks + 3 MCP Apps](https://img.shields.io/badge/MCP%202026--07--28-150%20Tools%20%7C%20Tasks%20%7C%203%20MCP%20Apps-7C3AED.svg)](#ai-agent-native-mcp-2026-07-28-tasks-and-mcp-apps)

> **Try Culkibo in 10 Seconds — Zero Install, Zero Docker Required:**
> Launch the curated read-only **Interactive Browser Sandbox** directly on **[GitHub Pages (`?demo=1`)](https://macaqueboy.github.io/culkibo/?demo=1&lang=en&theme=dark)** *(published automatically via [`.github/workflows/demo-pages.yml`](.github/workflows/demo-pages.yml))* or locally in `<200 ms` with **`npx culkibo demo`**!

<p>
  <img src="docs/assets/social-preview.png" alt="Culkibo overview banner showing 51 MB RSS, 6 runtime deps, zero shell construction, Live Sync 2.0, MCP tools, inline MCP Apps, and 140+ one-click apps" width="100%" />
</p>

```bash
git clone https://github.com/macaqueboy/culkibo.git && cd culkibo
docker compose up -d --build
node bin/culkibo.js agent-init claude
```

[Visual Showcase](#visual-showcase) ·
[Why Culkibo](#why-culkibo-is-architecturally-different) ·
[Comparison Matrix](#honest-head-to-head-comparison) ·
[Benchmarks & Results](#benchmarks-and-reproducible-results) ·
[Architecture](#architecture) ·
[30-Second Quick Start](#30-second-quick-start) ·
[AI Agents & MCP Apps](#ai-agent-native-mcp-2026-07-28-tasks-and-mcp-apps) ·
[Coolify Migration](#1-click-coolify-v4-migration-and-portable-bundles) ·
[Open-Core & Roadmap](#ethical-open-core-and-community-roadmap) ·
[Contributing](#contributing-and-community)

</div>

---

Culkibo `v1.2.0` is an open-source **self-hosted PaaS** and **Coolify / Dokploy alternative** engineered for solo builders, agencies, AI/GPU operators, regulated platform teams, and AI coding agents. Instead of bolting a heavy PHP/Laravel or multi-container control stack on top of polling reverse proxies and shell scripts, Culkibo runs a single **49–54 MB RSS** daemon (across 91+ lazy-loaded services, `0%` CPU, **`116.6 ms`** cold boot, **`10,679 req/s`** authed Bearer+Brotli fast-path, **`9,725 req/s`** health) with **zero shell command construction**, atomic **Caddy v2.11** HTTP/3 ingress (**Geo/A-B Experiments, SRE SLO Canaries & PoW Shield**), **Image Bloat & Secret-in-Layer Auditor**, **Distributed Cron Fencing-Token Leases**, **Post-Snaplet/Neosync Deterministic PR-Preview DB PII Masker**, **8-Class OOM-Kill Forensics & Crash-Loop Classifier**, **GoAlert/Keep On-Call Escalation & Flapping Damper**, **Synthetic Multi-Step Flow & TLS/SNI Sentinel**, **10-Rule Zero-Downtime SQL Linter**, **OOM-Safe KEDA Autoscaler**, **SPDX License & Seccomp/`runc` Guards**, **Policy-as-Code Admission**, **Ed25519-Signed SOC 2 Bundles**, **AI/GPU LLM Orchestration (Ollama · vLLM · llama.cpp)**, **Post-MinIO S3**, **Read-Only DB Studio**, **FIDO2 Passkeys**, **OpenTofu IaC**, **Sub-8ms Live Sync 2.0 (`1.06 ms` apply)**, **all-time record `44 µs` (`0.044 ms`) warm Micro-Wasm** (`64 KiB` RAM), and the industry's first **MCP `2026-07-28` (milestone `150` tools, `-88.7%` core profile, Async Tasks & inline `ui://culkibo/*` MCP Apps)** control plane — verified by **62 integrated test suites**.

---

## Visual Showcase

Culkibo ships with a **Zero-Install Interactive Browser Sandbox (`?demo=1` / `npx culkibo demo`)**, **100% English & Spanish zero-dep localization** across every view (`100.0/100` EN purity verified in Playwright QA), **Obsidian Dark Mode & Crisp Light Mode**, an **Open-Core White-Label Brand & Custom Login Theme Engine** (`GET/PUT /api/brand`), a **Pioneer Cockpit, Forensics & Governance UI** (OOM-Kill & Crash-Loop Forensics Drawer, Image Bloat & Secret-in-Layer Auditor, Post-Snaplet/Neosync PR-Preview DB PII Masker + `pg_anonymizer` DDL, Cron Fencing-Token Lease Guard, On-Call Escalation & Flapping Damper, Synthetic Flow & TLS/SNI Sentinel, 10-Rule SQL Linter, OOM-Safe KEDA Autoscaler, SPDX License Auditor, Tailored Seccomp & `runc` CVE Guard, Policy-as-Code Admission, Signed SOC 2 Dossier, Multi-Region Geo/A-B, Cross-VPS Volume Planner, SLO Canary Rollback, DR Fire-Drills, AI/GPU VRAM Planner, Remote Build Offloader, `.ndjson.gz` Log Archive, Read-Only DB Studio, Post-MinIO S3 + SigV4, Agency Ledger, Passkeys FIDO2, OSV CVE Scanner, OpenTofu IaC, Zero-Dep Web Terminal, 20-Pattern Auto-Healer, WireGuard Mesh, Caddy PoW Shield, SmartPack, Shadow Replay, Time-Machine, `44 µs` Micro-Wasm Tester, FinOps, OTLP, and Coolify Streamer), and an interactive **Spatial SVG Topology Canvas** with click-to-link database env injection.

### Live Sync 2.0 (`1.06 ms` Apply · `7.67 ms` E2E) + Inline MCP Apps Flow

<p align="center">
  <img src="docs/assets/live-sync-demo.svg" alt="Animated Culkibo Live Sync 2.0 and inline MCP Apps topology flow showing sub-10ms Merkle delta apply, -96.1% Brotli compression, Server-Timing, and ui://culkibo/topology" width="100%" />
</p>

### Obsidian Dark Mode & Light Mode (100% Global EN / ES Dashboard)

| Obsidian Dark Mode (`1440×900`) | Crisp Light Mode (`1440×900`) |
| :---: | :---: |
| ![Culkibo English Obsidian Dark Mode dashboard with live RAM telemetry, onboarding checklist, and project cards](docs/assets/dashboard-dark-en.png) | ![Culkibo English Light Mode dashboard with project cards, search filters, and 1-click deploy controls](docs/assets/dashboard-light-en.png) |

### Spatial SVG Topology Canvas & Click-to-Link DB Injection (`Obsidian Dark`)

![Culkibo interactive Spatial SVG Topology Canvas in Obsidian Dark showing Domains, Projects, Managed Databases, animated directional edges, and Node Inspector with Link-to-Project DATABASE_URL injection](docs/assets/topology-dark-en.png)

### AI Agent Hub — MCP `2026-07-28`, `-88.7%` Token Profiles & Interactive MCP Apps (`ui://culkibo/*`)

![Culkibo 100% English AI Agent Hub showing MCP tools, playbooks, core profile token savings, 1-click Antigravity/Claude/Cursor/Windsurf/Codex setup, and Interactive MCP Apps gallery](docs/assets/ai-agent-hub.png)

---

## Why Culkibo Is Architecturally Different

Traditional self-hosted PaaS platforms force a painful trade-off: burn 500 MB–1.5 GB of VPS RAM just to run the panel, bake secrets into Docker image layers, double-fire daily crons across replicas, leak prod PII into PR previews, page endlessly on flapping alerts, and live with recurring shell-injection & `runc`/LLM CVEs. Culkibo fixes these problems at the architecture layer:

### 1. Zero-Shell Engine (`shell: false`), Image Secret Auditor, PII Masker, Seccomp/`runc`, Policy & SOC 2
- Every subprocess (`docker`, `git`, `caddy`, `ssh`, `cron`, `exec`, `npm`) is invoked through `spawn()` / `execFile()` with tokenized `argv` arrays validated by [`safeCommand.js`](server/services/safeCommand.js) and `shell: false`. Statically verified on every commit by [`tests/shell-safety.test.js`](tests/shell-safety.test.js).
- **Container Image Layer Bloat & Secret-in-Layer Auditor (`server/services/imageBloatAuditor.js` · `culkibo audit-image` + MCP `culkibo_audit_image_bloat`):** Pure-JS Dive/Dockle/Hadolint analyzer running 8 rules catching secrets baked into `ENV`/`ARG`/`RUN` (curing `coolify#7019`/`#5328`), cross-layer `rm` waste, undeleted `apt`/`apk`/`pip` caches, missing multi-stage/non-root users, and heavy base images (exits `1` in CI on secret leaks or score `< 50`).
- **Post-Snaplet / Post-Neosync Deterministic PR-Preview DB PII Masker (`server/services/piiMaskerService.js` · `culkibo mask-pii` + MCP `culkibo_mask_preview_pii`):** Fills the post-Snaplet & archived Neosync void with deterministic HMAC-SHA256 seeded pseudonymization preserving FK joins across JSON & SQL (emails, phones, Luhn-valid cards, SSNs, IBANs, RFC 5737 IPs, API tokens) + `dalibo/postgresql_anonymizer`-compatible `SECURITY LABEL FOR anon` DDL & `zeroPiiLeaked` verification.
- **Tailored Least-Privilege Seccomp & `runc` CVE Guard (`seccompProfileService.js`), CycloneDX 1.6 SPDX License Auditor (`culkibo audit-licenses`), Policy-as-Code 10-Rule CIS/PSS Admission (`culkibo admission-check`) & Ed25519-Signed SOC 2 / ISO 27001 / GDPR Bundles (`culkibo compliance-bundle`, 0 secrets):** Blocks `unconfined` seccomp + `io_uring_*`/`ptrace`/`mount`/`bpf`, flags `runc CVE-2025-31133`/`52565`/`52881`, audits `AGPL`/`SSPL`/`LicenseRef-*`, blocks `- /:/host:rw` & `dokploy#2661`, and ships **Automated DR Fire-Drills (`culkibo dr-drill`)**, **FIDO2 Passkeys**, **Secret Leases**, **OSV CVE Drift**, and **Signed SLSA v1.1 + CycloneDX 1.6 SBOM**.
- **By-Design Immunity to Real-World PaaS, Runtime & LLM CVEs ([`CYCLE6`](docs/COMPETITOR_RADAR_CYCLE6.md) · [`CYCLE7`](docs/COMPETITOR_RADAR_CYCLE7.md) · [`CYCLE8`](docs/COMPETITOR_RADAR_CYCLE8.md) · [`CYCLE9`](docs/COMPETITOR_RADAR_CYCLE9.md) · [`CYCLE10`](docs/COMPETITOR_RADAR_CYCLE10.md) · [`CYCLE11`](docs/COMPETITOR_RADAR_CYCLE11.md) · [`CYCLE12`](docs/COMPETITOR_RADAR_CYCLE12.md)):** Immune to **`runc CVE-2025-31133`/`52565`/`52881`**, **`Coolify CVE-2025-66213`**, **`Ollama CVE-2026-7482`**, **`vLLM CVE-2026-22778`/`137477`**, Dokploy **`CVE-2026-116068`/`127212`/`24841`/`129433`/`129315`/`133520`**, Portainer **`CVE-2026-134756`**, Runtipi **`CVE-2026-47277`**, Dokku **`CVE-2026-54636`**, **`coolify#7019/#5328/#5655/#3862/#6506/#11372/#12170`**, **`dokploy#1475/#3193/#6105/#2661/#2642/#1382`**, **`uptime-kuma#3255/#5772/#7500/#7704/#8193/#6519`**, **`gatus#856`**, **`caprover#2164`**, **`kamal#1709/#1856/#1790`**, and the MinIO / Neosync / Snaplet discontinuations.

### 2. `49–54 MB` Idle RAM, `10,679 req/s` Fast-Path, On-Call Escalation, Cron Fencing Leases & Synthetic Sentinel
- **All-Time Verified Records (Cycle-10–12 QA `#278`/`#297`/`#311`):** **`49–54 MB RSS`** idle daemon (`49 MB` record, `54 MB` across 91+ lazy-loaded services, `<= 60 MB` invariant, `0%` CPU), **`116.6 ms`** cold boot, **`10,679 req/s`** authed Bearer+Brotli fast-path (`p50 2.20 ms`), **`9,725 req/s`** health, and **`0.61 ms`** warm 140-app catalog — fitting effortlessly on a **$4/mo 512 MB–1 GB VPS**.
- **Minimal supply-chain blast radius:** Exactly **6** root npm runtime dependencies ([`package.json`](package.json): `express`, `ws`, `chokidar`, `commander`, `cors`, `dotenv`) and **0** dependencies in [`telemetry-collector/`](telemetry-collector/README.md) — enforced across Node `20`, `22`, and `24` in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
- **GoAlert / Keep On-Call Escalation Router & Flapping Damper (`server/services/oncallEscalationService.js` · MCP `culkibo_oncall_router`):** Cures `uptime-kuma#3255` with fingerprint alert collapsing (`0` duplicate pages), flapping suppression (`>=3` toggles), deterministic shift rotations, and Tier 1→2→3 ack-timeout escalation.
- **Distributed Cron Idempotency & Fencing-Token Lease Guard (`server/services/cronLeaseService.js` · MCP `culkibo_cron_lease`):** Cures `coolify#5655` (daily cron running twice) & `dokploy#1475` via monotonic `fencingToken++`, rejecting concurrent overlaps (`ALREADY_RUNNING`), repeat `scheduleSlotIso` runs (`ALREADY_EXECUTED_SLOT`), and stale tokens — alongside **24h Cron Heatmap & Heartbeats (`/api/heartbeat/:token`)**.
- **Synthetic Multi-Step API Flow & Live TLS/SNI Drift Sentinel (`syntheticSentinelService.js`), Persistent `.ndjson.gz` Log Archive, Agency Quotas (`culkibo ledger --csv`), Open-Core White-Label Brand (`coolify#1744`), Standard-Webhooks Dual-Secret DLQ, Zero-Dep OTLP & FinOps.**

### 3. 8-Class OOM Forensics, SQL Linter, OOM-Safe KEDA Autoscaler, Sub-8ms Live Sync 2.0 & `44 µs` Micro-Wasm
When coding with Claude Code, Antigravity, Cursor, or Windsurf, waiting 2–4 minutes per push destroys flow:

```text
Traditional PaaS:  save file -> git commit -> push -> webhook -> Docker rebuild (1-4 min) -> check
Culkibo Forge:     save file -> binary Commit Frame (/ws/sync, Brotli -96.1%) -> 1.06 ms apply / 7.67 ms E2E
Culkibo Citadel:   Image Audit -> SQL Lint -> Policy Gate -> SLO Canary (10->100%) -> OOM Forensics & KEDA
```

- **8-Class Container OOM-Kill Forensics & Crash-Loop Classifier (`server/services/oomForensicsService.js` · MCP `culkibo_oom_forensics`):** Separates `137+oomKilled` (`CGROUP_OOM_KILL` with automatic 1.5× RAM bump) vs `137+!oomKilled` (`FORCED_SIGKILL_TIMEOUT`) vs `139` (`SEGFAULT`) vs `134` (`ABORT`) vs `143` (`SIGTERM`) vs `126/127` (`EXEC_MISSING`) vs `HEALTHCHECK_CRASH_LOOP` vs `STALE_HISTORICAL_TASK_IGNORED` (curing Portainer false rollbacks on historical OOM tasks).
- **10-Rule Zero-Downtime SQL Migration Linter (`culkibo lint-sql`) & OOM-Safe KEDA Queue/Worker Autoscaler + `503 Retry-After` Breaker (`workerAutoscalerService.js`):** Native Squawk/Strong Migrations DDL linter (`CONCURRENTLY`, `lock_timeout`, `NOT VALID`, `DROP COLUMN`) paired with hysteresis/cooldown worker autoscaling capped by hard VPS RAM (`maxSafeReplicas`) and automatic load shedding.
- **Adaptive Live Sync 2.0 (`1.06 ms` apply · `7.67 ms` E2E · `-96.1%` Brotli · `1.60 ms` rollback), Google SRE SLO Canary Auto-Rollback (`10→25→50→100%` Caddy weights + instant `100/0` rollback), Shadow Replay Gate & Whole-Stack Time-Machine (`culkibo timemachine`).**
- **Zero-Dep Read-Only Live DB Studio & Safe Redis Inspector (`BEGIN TRANSACTION READ ONLY` + `5s` timeout + `LIMIT 200`), Zero-Dep Web Terminal (`/ws/terminal`, no `node-pty`), 20-Pattern Build Auto-Healer (`culkibo heal`), & Live Config Drift Detector (`kamal#1790` + PgBouncer Smart Pool).**
- **All-Time Record `44 µs` (`0.044 ms`) Warm Micro-Wasm Edge Runtime ([`wasmMicroRunner.js`](server/services/wasmMicroRunner.js)):** Sandboxed WebAssembly in isolated `worker_threads` — live-measured at **`0.044 ms` (44 µs) warm p50**, **`0.058 ms` p95**, and **`64 KiB` RAM** (zero host filesystem/network access).
- **Honest scope:** Live Sync 2.0 accelerates incremental code/asset iteration (*Path B*). Dependency or `Dockerfile` changes run full immutable Docker BuildKit builds (*Path C*) with image audit, SQL lint, admission checks, smoke tests, shadow replay, SLO canaries, and multi-release rollback.

### 4. Milestone `150` MCP `2026-07-28` Tools (`-88.7%` Core), Autonomous Triage, Async Tasks & Inline MCP Apps
- **150 Tools, 13 Playbook Prompts & 10 Resources** over Streamable HTTP (`POST /api/mcp`) and stdio (`culkibo mcp`) with legacy SSE fallback — verified end-to-end against a real spawned stdio JSON-RPC client ([`tests/release-and-mcp-e2e.test.js`](tests/release-and-mcp-e2e.test.js)), including `culkibo_audit_image_bloat`, `culkibo_cron_lease`, `culkibo_mask_preview_pii`, `culkibo_oom_forensics`, `culkibo_oncall_router`, `culkibo_synthetic_sentinel`, `culkibo_lint_sql_migration`, `culkibo_worker_autoscaler`, `culkibo_audit_licenses`, `culkibo_seccomp_profile`, **`culkibo_security_posture`**, `culkibo_admission_check`, `culkibo_compliance_bundle`, `culkibo_volume_migrate`, `culkibo_edge_experiment`, **`culkibo_triage_playbook`**, `culkibo_slo_canary`, `culkibo_ai_workload`, `culkibo_remote_builder`, and `culkibo_log_archive_search`.
- **Official MCP `2026-07-28` Async Tasks (`io.modelcontextprotocol/tasks`) & Elicitation (`elicitation/create`):** Long-running Docker builds, Coolify migrations, and DR drills run non-blocking via `tasks/list`, `tasks/get`, `tasks/result`, and `tasks/cancel` with strict cross-tenant RBAC isolation — and declare structured JSON Schema `elicitation` prompts for missing secrets or approvals.
- **5 Context-Saving Profiles (`?profile=core|deploy|ops|security|all` & `CULKIBO_MCP_PROFILE`):** `?profile=core` serves the 17 essential tools (`17 / 150`) and cuts LLM tool-schema context by **`-88.7%`** while `culkibo_search_tools` discovers any of the remaining 150 tools on demand.
- **Interactive Inline MCP Apps (`modelcontextprotocol/ext-apps` `2026-01-26`):** Serves 3 sandboxed interactive HTML apps (`ui://culkibo/topology`, `ui://culkibo/incident-remediator`, `ui://culkibo/coolify-migration-diff`) with locked-down `_meta.ui.csp` (`default-src 'none'`), zero external URLs, XSS-safe JSON injection, and `postMessage` JSON-RPC bridges so compliant AI hosts render live visual cards inline inside chat.

### 5. Multi-Region Geo/A-B Edge, Cross-VPS Volume Cloner, AI/GPU LLMs, Remote Builds & Post-MinIO S3
- **Multi-Region Edge Geo-Routing (`CF-IPCountry`) & Sticky A/B Experiment Compiler (`server/services/edgeExperimentService.js` + [`caddyManager.js`](server/services/caddyManager.js)):** Zero-plugin Caddy v2.11 JSON compiler routing ISO-3166 `CF-IPCountry`/`X-Country` regions and sticky `lb_policy: cookie`/`header` + `weighted_round_robin` A/B splits with a 1-click **`100% Control` Kill-Switch** — alongside Caddy Edge Bot-Shield/PoW (`ckb_shield`), full multi-CAA pre-flight (`uptime-kuma#6519`), 6-day `shortlived` ACME, HTTP/3, and **7-provider DNS-01 Wildcard TLS**.
- **Stateful Volume Snapshot Cloner & Cross-VPS Migration Planner (`server/services/volumeMigrationService.js` · MCP `culkibo_volume_migrate`):** Cures `Coolify CVE-2025-66213` (CVSS 10.0), recursive `chown` breaks, Dokploy `999:999` Postgres UID errors, and Kamal `Errno::EACCES` via a strict 4-phase zero-shell plan (`pre-sync → quiesce + tar --numeric-owner + SHA-256 → SSH ControlMaster stream → checksum & UID verify`).
- **Self-Hosted AI / GPU & Local LLM Orchestrator (`culkibo ai-vram`) & Distributed Remote Build-Node Offloader (`remoteBuilderService.js`):** Native **Ollama · vLLM · llama.cpp** VRAM/KV-cache pre-flight, NVIDIA CDI (`nvidia.com/gpu=all`), `127.0.0.1`/Bearer proxy & vulnerable-tag guardrails (`CVE-2026-7482`, `CVE-2026-22778`), plus dedicated `amd64`/`arm64` build offloading with **active-build SSH mux ref-count pinning** (preventing `coolify#11372` mid-build kills) and PR preview offload (`dokploy#3450`).
- **Post-MinIO S3 Storage (`culkibo s3-presets`: Garage · RustFS · SeaweedFS + Pure-Crypto SigV4), Zero Lock-In OpenTofu IaC (`culkibo export-iac`), SmartPack (`18` stacks), DirectPush (`culkibo pussh`), WireGuard Mesh (`culkibo mesh`) & Sovereign EdgeTunnel (`ET1`).**

### 6. Atomic DB Migrations, 1-Click Coolify v4 Migration & Enterprise Defense-in-Depth
- **Atomic Single-Leader Pre-Deploy DB Migrations ([`migrationRunner.js`](server/services/migrationRunner.js) + Project Cockpit Pre-Flight Planner) & Per-PR Postgres Schema Isolation:** Single-leader lease locks with dead-PID/TTL recovery prevent concurrent replica migration races, trigger optional pre-migration snapshots, abort route cutover cleanly on failure, and isolate PR previews via dedicated PostgreSQL schemas (`pr_<n>`) or `TEMPLATE`/SQLite CoW database branches with automatic teardown.
- **Coolify v4 Deep Migrator ([`docs/MIGRATION_GUIDE.md`](docs/MIGRATION_GUIDE.md)) & Portable `.zip` Bundles ([`bundleArchiver.js`](server/services/bundleArchiver.js)):** Translates Coolify v4 Magic Variables (`${SERVICE_FQDN_*}`, `${SERVICE_PASSWORD_*}`, `${COOLIFY_*}`) into domains & `${vault.*}`, converts plain & Base64 Traefik labels into Caddy v2.11 edge config, generates zero-shell Volume & SQL streaming runbooks (`POST /api/import/coolify/stream-plan`), and is battle-tested end-to-end against a full Mock Coolify v4 Estate ([`tests/coolify-e2e-replay.test.js`](tests/coolify-e2e-replay.test.js)).
- **12 Managed Databases, SnapStream & Enterprise Security Built In (Never Paywalled):** `PostgreSQL`, `pgvector`, `TimescaleDB`, `MySQL`, `MariaDB`, `Valkey`, `Redis`, `Dragonfly`, `MongoDB`, `ClickHouse`, `Qdrant`, and `Meilisearch` + **AES-256-GCM S3/R2 DR Drills** + **SnapStream** ([`sqliteStreamBackup.js`](server/services/sqliteStreamBackup.js) SQLite WAL-to-S3 PITR) + 4-role RBAC, `HttpOnly` sessions, **TOTP 2FA**, **OIDC PKCE SSO** (`groups` → RBAC + resilient JWKS stale-while-revalidate), hash-chained audit log, secret scanner (`422`), deploy freeze (`423`), webhook replay protection (`<=300s`), symlink-safe GitOps, protected sleeping-container prune guards, and dead-PID deploy-lock recovery.

---

## Honest Head-to-Head Comparison

> **Radical Transparency:** Culkibo's metrics below are **live-measured** via `node bench/run-all.bench.js` (unadjusted). Competitor footprints are **documented architecture baselines** from published stacks and minimum VPS docs (not executed on this host).

| Capability | Culkibo v1.2 | Coolify v4 | Dokploy | CapRover | Kamal 2 | Portainer CE |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Control-Plane Stack** | **Node.js (6 deps) + Caddy** | Laravel + PHP + PG + Redis + Soketi + Traefik | Next.js + PG + Redis + Traefik | Node.js + Nginx + Swarm | Local Ruby CLI + `kamal-proxy` | Go + BoltDB *(container UI)* |
| **Control-Plane RAM & Fast-Path** | **49–54 MB RSS · 10,679 req/s** *(116.6 ms boot)* | ~800 MB – 1.5 GB *(2 GB VPS min)* | ~450 – 800 MB *(1–2 GB VPS)* | ~150 – 300 MB *(300–450 MB w/ Swarm)* | 0 MB panel *(+15–25 MB proxy)* | ~100 – 200 MB *(external proxy)* |
| **Image Secret Auditor + Seccomp/`runc` + SOC 2** | ✅ **8-rule Bloat/Secret · Seccomp · SPDX · 10 CIS · Signed SOC 2** | ❌ `#7019` / `- /:/host` | ❌ Plaintext (`#2642`) | ⚠️ Swarm CLI | ⚠️ SSH shell | ⚠️ Paid Business |
| **PR-Preview DB PII Masker + SQL Linter** | ✅ **Deterministic HMAC PII + `pg_anonymizer` · 10-rule DDL lint** | ❌ | ❌ | ❌ | ❌ | ❌ |
| **8-Class OOM Forensics + KEDA Autoscaler** | ✅ **Exit 137 OOM vs SIGKILL · RAM-capped KEDA + `503` breaker** | ❌ *(`#3862` open)* | ❌ *(`#6105` open)* | ❌ *(`#2164`)* | ❌ | ⚠️ Stale rollback |
| **Cron Fencing Leases + On-Call Escalation** | ✅ **Monotonic `fencingToken` (`#5655`) · Flapping Damper & Tiers** | ⚠️ Double-fire (`#5655`) | ⚠️ Double-fire (`#1475`) | ❌ | ❌ | ❌ |
| **Synthetic API Flows + Live TLS/SNI Sentinel** | ✅ **Multi-step flows (0 secrets) + uncached TLS/SAN/FP drift** | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Multi-Region Geo/A-B + SRE SLO Canary** | **Caddy v2.11** *(`CF-IPCountry` · Sticky A/B · 10→100% SRE · PoW)* | Traefik *(2,000 ms throttle)* | Traefik / Swarm | Nginx reload | `kamal-proxy` *(<1 ms swap)* | ❌ External |
| **Cross-VPS Volume Cloner + AI/GPU LLMs** | ✅ **`tar --numeric-owner` (`999:999`) · Ollama · vLLM · CDI + CVE** | ❌ `CVE-2025-66213` | ⚠️ Legacy GPU (`#1621`) | ❌ | ⚠️ `EACCES` | ❌ |
| **Automated DR Fire-Drills + `.ndjson.gz` Logs** | ✅ **`culkibo dr-drill` (0B/ACL guard) · Redeploy-safe logs** | ⚠️ Empty dump (`#6506`) | ⚠️ Empty dump (`#1382`) | ❌ | ❌ | ❌ |
| **Remote Build Offloader + Live Sync 2.0** | ✅ **SSH mux-pinned builds (`#11372`) · `1.06 ms` apply** | ⚠️ Mux kill (`#11372`) | ⚠️ Queue race (`#3226`) | ❌ Image build | ❌ Image build | ❌ |
| **Read-Only DB Studio + Post-MinIO S3** | ✅ **Safe SQL/Redis Studio · Garage/RustFS/SeaweedFS + SigV4** | ⚠️ Adminer / MinIO | ⚠️ Adminer / MinIO | ❌ | ❌ | ❌ |
| **Agency Quotas, Ledger & OSS White-Label** | ✅ **Tenant Quotas · CSV-safe Ledger · OSS White-Label (`#1744`)** | ❌ *(`#1744` open)* | 💰 Enterprise paywall | ❌ | ❌ | 💰 Business |
| **AI-Agent Native MCP + Triage + MCP Apps** | ✅ **150 tools · `security_posture` · Tasks · 3 `ui://` Apps · `-88.7%`** | ❌ *(3rd-party)* | ❌ *(3rd-party)* | ❌ | ❌ | ❌ |
| **SmartPack + DirectPush + WireGuard + `44 µs` Wasm** | ✅ **18 stacks · `culkibo pussh` · `x25519` Mesh · `0.044 ms` Wasm** | ⚠️ Nixpacks | ⚠️ Nixpacks | ⚠️ Buildpacks | ❌ Registry req. | ❌ |
| **1-Click Catalog, 12 DBs, Passkeys & Coolify Migrator** | ✅ **140 apps · 12 DBs · FIDO2 Passkeys · OpenTofu IaC · Coolify→Caddy** | ✅ Catalog / ⚠️ Teams | ✅ Catalog / ⚠️ Basic | ✅ One-click | ✅ `deploy.yml` | ⚠️ Paid Business |

---

## Benchmarks and Reproducible Results

Every Culkibo metric below comes from real code independently measured on `Node v24.14.0` (`win32/x64`, uncontended run) with **zero synthetic delays and zero subtracted overhead**. Reproduce the complete suite or generate a Markdown/JSON comparison report on your own machine:

```bash
node bench/run-all.bench.js
node bench/competitor-comparison.bench.js --markdown
```

### Independently Verified Live Performance Results (`v1.2.0` All-Time Record Run)

| Metric | Live Measured Result | Notes & Verification Command |
| :--- | :--- | :--- |
| **Idle Daemon RAM / CPU (Sub-50 MB Record!)** | **49–54 MB RSS · 0% CPU** | `49 MB` record / `54 MB` across 91+ lazy services (`<= 60 MB` invariant) |
| **Cold Boot Time** (`CULKIBO_SKIP_RECONCILE=1`) | **116.6 ms** *(4× faster than Cycle #1)* | Measured via `process.hrtime.bigint()` (`npm run bench:control`) |
| **Authenticated Fast-Path (Bearer + Brotli, 500 req / 25w)** | **10,679 req/s** *(p50 `2.20 ms` — first >10k req/s!)* | HMAC-SHA256 LRU cache + WeakMap zero-copy Brotli + `Server-Timing` |
| **Health HTTP (`GET /api/health`, 500 req / 25w)** | **9,725 req/s** | Pre-compiled O(1) fast-path route map |
| **Mixed Uncompressed / RBAC Express HTTP (500 req / 25w)** | **3,566 req/s** mixed · **2,275 req/s** RBAC | `0` failures (`bench/control-plane.bench.js` & `bench/subsystems.bench.js`) |
| **Catalog Load (`GET /api/catalog`, 140 apps)** | **warm p50 `0.61 ms`** | `129.6 KB` → `34.5 KB` Brotli (**-73.4%**) |
| **Live Sync 2.0 (Path B Incremental Sync)** | **server apply p50 `1.06 ms` · E2E p50 `7.67 ms`** | 100-file TSX burst Brotli **-96.1%** (`25.66×`) · in-memory rollback **p50 `1.60 ms`** |
| **Isolated Micro-Wasm Edge Runtime (All-Time Record)** | **warm p50 `0.044 ms` (44 µs) · p95 `0.058 ms` · `64 KiB` RAM** | Verified via `bench/competitor-comparison.bench.js` & [`tests/migrations-and-wasm.test.js`](tests/migrations-and-wasm.test.js) |
| **WebSocket 40-Client Fan-Out** | **53.4 ms** (`40/40` initial state delivered) | Zero drops under concurrent churn (`tests/websocket-stress.test.js`) |
| **Caddy v2.11 Atomic Route Swap, Geo/A-B & SLO Canary** | **Synchronous zero-poll Admin API + `weighted_round_robin`** | Verified live in Linux CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml) `live-caddy-e2e`) & `npm run bench` |
| **MCP `2026-07-28` `?profile=core` Savings (Milestone!)** | **-88.7% schema tokens** (`17 / 150` tools) | Verified via `bench/competitor-comparison.bench.js` + external stdio E2E |
| **Supply-Chain, Shell Safety & Test Suite** | **6 root deps · 0 collector deps · 0 shell calls · 62 suites** | Verified in CI + Signed SLSA v1.1 + Ed25519 SOC 2 + SPDX Auditor + Image Audit |

---

## Architecture

Culkibo separates rapid developer/AI iteration (**The Forge**) from immutable production releases (**The Citadel**) on a single lightweight control plane:

```mermaid
flowchart LR
    Dev["Developer & AI Agents (Claude Code / Antigravity / Cursor)"]
    UI["Web Dashboard (100% EN/ES · White-Label · Forensics · PII Masker · ?demo=1)"]
    MCP["MCP 2026-07-28 (150 Tools, -88.7% Core, Tasks, 3 ui:// Apps)"]
    Sync["Live Sync 2.0 (/ws/sync 1.06 ms Apply · 7.67 ms E2E)"]
    CP["Culkibo Control Plane (Node.js 49-54 MB RSS, 10,679 req/s, 6 Deps, shell:false)"]
    Forge["The Forge (Hot Dev + /ws/terminal + Image Bloat Audit + OOM Forensics)"]
    Citadel["The Citadel (SQL Linter + Policy + Seccomp/runc + KEDA Autoscaler + SLSA)"]
    Caddy["Caddy v2.11 Edge (HTTP/3, Geo/A-B, SRE Canary, PoW Shield, WireGuard, 44us Wasm)"]
    Obs["On-Call Escalation + Cron Leases + Synthetic TLS + Signed SOC 2 + OTLP"]
    Data["12 DBs + PR PII Masker + Read-Only Studio + Post-MinIO S3 + AI/GPU LLMs"]

    Dev -->|"Streamable HTTP / stdio"| MCP
    Dev -->|"Commit Frames"| Sync
    Dev --> UI
    UI -->|"O(1) Fast-Path + FIDO2/RBAC"| CP
    MCP --> CP
    Sync --> Forge
    CP --> Forge
    CP --> Citadel
    CP -->|"Atomic JSON Admin API"| Caddy
    CP -->|"OTLP / On-Call / Ed25519"| Obs
    Citadel --> Data
    Caddy -->|"Geo/A-B & Progressive SLO Canary"| Citadel
```

---

<a id="quick-start"></a>

## 30-Second Quick Start

### Prerequisites
- **Zero-Install Sandbox:** Any modern browser (`https://macaqueboy.github.io/culkibo/?demo=1&lang=en&theme=dark`) or Node.js 20+ for `npx culkibo demo`
- **Production VPS:** Debian 12 / Ubuntu 22.04+ (512 MB+ RAM; 1 GB+ recommended for Docker builds)
- **Docker Compose:** Docker Engine 24+ & Compose v2
- **Local Dev:** Node.js **20+** (22/24 LTS recommended). Docker and Caddy are optional locally.

### Option 1 — 10-Second Zero-Install Sandbox (`demo`)

Explore SmartPack, Spatial Topology, 140+ Catalog Apps, Coolify Migration, Native OTLP, and 3 inline MCP Apps with zero configuration:

```bash
npx culkibo demo
```

Or open the hosted read-only sandbox on **[GitHub Pages (`?demo=1`)](https://macaqueboy.github.io/culkibo/?demo=1&lang=en&theme=dark)**.

### Option 2 — Docker Compose (Recommended Production Stack, ~30s)

```bash
git clone https://github.com/macaqueboy/culkibo.git
cd culkibo
docker compose up -d --build
```

Starts the Culkibo daemon on `http://127.0.0.1:3030` wired over a private internal network to **Caddy v2.11** (ports `80`, `443/tcp`, `443/udp` for HTTP/3, with `:2019` Admin API never exposed to the host). See [`docker-compose.yml`](docker-compose.yml) and [`Dockerfile.caddy`](Dockerfile.caddy) for Multi-Wildcard DNS-01 builds.

### Option 3 — 1-Line Production VPS Installer (Debian / Ubuntu)

Installs an unprivileged `culkibo` user, Node.js 22, Docker, Caddy with automatic TLS + HTTP/3, hardened `systemd` unit, and a `0600` 256-bit auth token in `data/auth.json`:

```bash
curl -fsSL https://raw.githubusercontent.com/macaqueboy/culkibo/main/scripts/install.sh | sudo bash
```

Clean uninstall: `sudo bash /opt/culkibo/scripts/uninstall.sh` (verified against real Debian 12 + `systemd` via [`scripts/test-install.sh`](scripts/test-install.sh)).

### Option 4 — CLI-First Project, Pioneer & Supply-Chain Workflow

Install and run locally from source (Windows users can also run `./start.ps1`):

```bash
npm install && npm --prefix web install && npm run web:build && npm start
```

Then run the complete project, SmartPack, DirectPush, EdgeTunnel, and offline SLSA/SBOM verification lifecycle:

```bash
node bin/culkibo.js init .                           # Auto-detect stack & generate culkibo.yaml
node bin/culkibo.js smartpack . --dockerfile --json  # Inspect 18-stack build plan & .dockerignore
node bin/culkibo.js up .                             # Provision & start project
node bin/culkibo.js sync <projectId> .               # Start Live Sync 2.0 (1.06 ms apply)
node bin/culkibo.js deploy <projectId>               # Immutable BuildKit deploy + Policy Gate + SLO Canary
node bin/culkibo.js audit-image Dockerfile --stack node --json  # 8-rule image bloat & secret-in-layer gate
node bin/culkibo.js mask-pii seed.sql --seed preview-key --json # Deterministic PII masking + pg_anonymizer DDL
node bin/culkibo.js lint-sql migrations/001.sql --json  # 10-rule zero-downtime SQL DDL linter (exit 1 on lock risk)
node bin/culkibo.js audit-licenses --policy saas-strict --json  # CycloneDX SPDX AGPL/SSPL risk gate
node bin/culkibo.js admission-check --preset soc2-strict --image node:22-alpine --uid 1000 --json
node bin/culkibo.js compliance-bundle --framework all --out soc2-dossier.json --json
node bin/culkibo.js dr-drill backup.sql.gz --json    # Automated DR Fire-Drill (0B/AES/SQL DDL check)
node bin/culkibo.js ai-vram --params 14 --quant Q4_K_M --vram 16 --runtime vllm --json  # GPU VRAM pre-flight
node bin/culkibo.js heal build.log --json            # 20-pattern deterministic build auto-healer
node bin/culkibo.js mesh status --json               # Zero-config x25519 WireGuard fleet mesh
node bin/culkibo.js s3-presets --json                # Post-MinIO pinned Garage / RustFS / SeaweedFS presets
node bin/culkibo.js ledger --days 30 --csv           # Agency client-billable formula-safe CSV usage ledger
node bin/culkibo.js cve-scan --json                  # Runtime CycloneDX SBOM CVE drift scan (OSV.dev)
node bin/culkibo.js export-iac --out ./iac --json    # Zero lock-in OpenTofu (.tf) + Compose IaC export
node bin/culkibo.js timemachine list <projectId>     # Inspect/diff/restore whole-stack checkpoints
node bin/culkibo.js finops --apps 5 --dbs 2          # Cloud-vs-Self-Hosted annual savings & right-sizing
node bin/culkibo.js pussh my-app:v1 --server srv1    # DirectPush registry-less SSH OCI v2 deploy
node bin/culkibo.js tunnel-agent --url wss://hub/ws/tunnel --token "$TUNNEL_TOKEN" --target 127.0.0.1:3000
node bin/culkibo.js verify dist-release              # Verify CHECKSUMS.sha256 & SLSA v1.1 DSSE offline
npm run release:sbom -- --out-dir dist-release --sign --verify  # Signed SLSA + CycloneDX 1.6 SBOM
```

---

## AI-Agent Native (MCP `2026-07-28`, Tasks and MCP Apps)

Culkibo is built from day one for autonomous and human-in-the-loop AI coding workflows — shipping a **milestone 150 tools** (including `culkibo_audit_image_bloat`, `culkibo_cron_lease`, `culkibo_mask_preview_pii`, `culkibo_oom_forensics`, `culkibo_oncall_router`, `culkibo_synthetic_sentinel`, `culkibo_lint_sql_migration`, `culkibo_worker_autoscaler`, `culkibo_audit_licenses`, `culkibo_seccomp_profile`, `culkibo_security_posture`, `culkibo_admission_check`, `culkibo_compliance_bundle`, `culkibo_triage_playbook`, `culkibo_slo_canary`, `culkibo_ai_workload`), **13 playbooks**, official **MCP `2026-07-28` Async Tasks (`io.modelcontextprotocol/tasks`)**, **Elicitation (`elicitation/create`)**, and the first **`modelcontextprotocol/ext-apps` (`2026-01-26`)** interactive UI resources in any self-hosted PaaS.

### 1-Click Agent Kit Generator

Generate drop-in MCP configs (defaulting to `?profile=core` for **-88.7% token savings** across `17 / 150` tools and using `${CULKIBO_TOKEN}` env placeholders — never plaintext secrets):

```bash
node bin/culkibo.js agent-init claude       # .mcp.json + CLAUDE.md ops snippet
node bin/culkibo.js agent-init antigravity  # .antigravity/mcp.json (Streamable HTTP)
node bin/culkibo.js agent-init cursor       # .cursor/mcp.json
node bin/culkibo.js agent-init windsurf     # .windsurf/mcp_config.json
node bin/culkibo.js agent-init codex        # .codex/config.toml (bearer_token_env_var)
node bin/culkibo.js agent-init vscode       # .vscode/mcp.json
```

### Streamable HTTP (`2026-07-28`) — Antigravity, Claude Code, Cursor & Windsurf

Connect to `http://localhost:3030/api/mcp?profile=core` (or `deploy`, `ops`, `security`, `all`):

```json
{
  "mcpServers": {
    "culkibo": {
      "url": "http://localhost:3030/api/mcp?profile=core",
      "headers": {
        "Authorization": "Bearer ${CULKIBO_TOKEN}"
      }
    }
  }
}
```

### Stdio Bridge (Claude Desktop / Local CLI Agents)

```json
{
  "mcpServers": {
    "culkibo": {
      "command": "node",
      "args": ["/path/to/culkibo/bin/culkibo.js", "mcp"],
      "env": {
        "CULKIBO_API_URL": "http://localhost:3030",
        "CULKIBO_TOKEN": "${CULKIBO_TOKEN}",
        "CULKIBO_MCP_PROFILE": "core"
      }
    }
  }
}
```

### Interactive MCP Apps (`ui://culkibo/*`) & Built-In Playbooks (`prompts/list`)

| Interactive MCP App (`text/html;profile=mcp-app`) | Sandboxed Inline Experience (`_meta.ui.csp`) |
| :--- | :--- |
| `ui://culkibo/topology` | Live RBAC-scoped SVG service, database, domain & fleet map with 1-click inspect/ship actions |
| `ui://culkibo/incident-remediator` | Live OOM/CrashLoop diagnostics card with two-phase `dryRun` → HMAC `confirmToken` stepper |
| `ui://culkibo/coolify-migration-diff` | Coolify v4 Parity Score, redacted `${vault.*}` Magic Vars & Traefik→Caddy edge diff viewer |

| Playbook Prompt (`prompts/get`) | Autonomous Agent Workflow |
| :--- | :--- |
| `deploy_safely` | Pre-deploy secret scan → atomic DB migration → `culkibo_ship_and_verify` → SLSA attestation |
| `migrate_from_coolify` | Read-only Coolify v4 scan → Magic Var & Traefik translation preview → zero-downtime cutover |
| `debug_production_crash` | Runs `culkibo_diagnose_incident` → correlates OOM/logs/OTLP traces → proposes confirmed fix |
| `zero_downtime_db_upgrade` | Encrypted snapshot + SHA-256 verify + DR drill → single-leader migration → cutover |
| `security_audit_stack` | Verifies hash-chained audit log, SLSA DSSE attestations, secret scan, RBAC/2FA/OIDC & TLS |
| `setup_wildcard_tls_and_tunnel` | Configures 7-provider DNS-01 wildcard TLS or zero-open-port EdgeTunnel / Cloudflare Tunnel |
| `optimize_ram_and_costs` | Inspects Auto-Sleep candidates, container limits, and right-sizing savings |
| `disaster_recovery_drill` | Validates AES-256-GCM DR backup & SnapStream integrity via non-destructive restore drill |

---

## 1-Click Coolify v4 Migration and Portable Bundles

Moving off Coolify takes minutes — and is **read-only** on your source server until you flip DNS:

1. Open Culkibo (`http://localhost:3030`), press **`Ctrl+K`** / **`⌘K`**, and run **Import from Coolify** (or upload an offline export / portable `.zip` or `.ckb.gz` bundle).
2. Enter your Coolify URL and read-only API token to inspect the live **Migration Parity Report**:
   - Automatic **Magic Variable** translation (`${SERVICE_FQDN_*}`, `${SERVICE_PASSWORD_*}`, `${COOLIFY_*}` → Culkibo domains & encrypted `${vault.*}` refs)
   - Automatic **Traefik → Caddy v2.11** rule translation (plain & Base64 labels: `stripprefix`, `redirectregex`, CORS/HSTS, `forwardauth`, `basicauth`, upstream port)
   - Full mapping for Applications, Compose Services, 8 DB Engines, Scheduled Tasks → Crons, Persistent Volumes, and the interactive **Volume & SQL Live Transfer** zero-shell runbook (`POST /api/import/coolify/stream-plan`)
3. Click **Migrate**, run the built-in post-migration smoke check (`verifyMigratedStack`), and cut over DNS with zero downtime. Verified end-to-end across a full multi-app, multi-DB Mock Coolify v4 Estate in [`tests/coolify-e2e-replay.test.js`](tests/coolify-e2e-replay.test.js).

Read the complete step-by-step runbook in [`docs/MIGRATION_GUIDE.md`](docs/MIGRATION_GUIDE.md).

---

## Testing, CI and Repository Map

Culkibo ships **62 integrated test suites** in `tests/run-all.js` (including Image Layer Bloat & Secret-in-Layer Auditor, Distributed Cron Fencing-Token Leases, Post-Snaplet/Neosync Deterministic PR-Preview DB PII Masker, 8-Class OOM-Kill Forensics & Crash-Loop Classifier, GoAlert/Keep On-Call Escalation & Flapping Damper, Synthetic Multi-Step API Flow & TLS/SNI Sentinel, OOM-Safe KEDA Worker Autoscaler & `503` Breaker, 10-Rule Zero-Downtime SQL Linter, CycloneDX SPDX License Auditor, Tailored Seccomp & `runc` CVE Guard, Policy-as-Code 10-Rule CIS/PSS Admission, Ed25519-Signed SOC 2 / ISO / GDPR Compliance Bundles, Cross-VPS Volume Migration, Multi-Region Geo/A-B Experiments, Automated DR Fire-Drills, Google SRE SLO Canary Auto-Rollback, AI/GPU LLM Orchestrator, Remote Build Offloader, `.ndjson.gz` Log Archive, Standard-Webhooks DLQ, Post-MinIO S3 + SigV4, Read-Only DB Studio, Agency Ledger, Open-Core White-Label, FIDO2 Passkeys + OSV CVE Drift, OpenTofu IaC, Mock-Coolify v4 E2E, external MCP stdio E2E, OTLP/SLSA E2E, and `44 µs` Micro-Wasm E2E) + standalone live-server, WebSocket churn, HTTP stress, and zero-dep telemetry collector suites — verified continuously on Linux by [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (`4` jobs: Node 20/22/24 matrix + Live Caddy v2.11 + Docker BuildKit SmartPack & SBOM E2E + Playwright Desktop/Mobile visual QA), released with signed SLSA v1.1 + CycloneDX 1.6 via [`.github/workflows/release.yml`](.github/workflows/release.yml), and published as a zero-install sandbox via [`.github/workflows/demo-pages.yml`](.github/workflows/demo-pages.yml):

```bash
node tests/shell-safety.test.js                       # Static AST/source check: 0 shell calls
npm run typecheck                                     # Server TypeScript checkJs (0 errors)
npx tsc -p web/tsconfig.app.json --noEmit             # Frontend TypeScript check (0 errors)
npx --prefix web oxlint --deny-warnings               # oxlint React 19 + Compiler rules (0 warnings)
npm run web:build                                     # Vite production build + .br/.gz precompression
npm test                                              # 62 suites + live-server + WS stress + HTTP stress
node --test telemetry-collector/test/collector.test.js  # Zero-dep telemetry collector suite
npm run release:sbom -- --out-dir dist-release --sign --verify  # Signed SLSA v1.1 + CycloneDX 1.6 SBOM
```

### Repository Layout

```text
.github/workflows/ci.yml         Active 4-job Linux CI (Node 20/22/24, Live Caddy, BuildKit SmartPack/SBOM, Playwright)
.github/workflows/release.yml    Automated v* GitHub Release workflow (Signed SLSA v1.1 DSSE + CycloneDX 1.6 SBOM)
.github/workflows/demo-pages.yml Zero-Install Interactive Browser Sandbox workflow (GitHub Pages ?demo=1)
bin/culkibo.js                   CLI (demo, init, up, sync, deploy, audit-image, mask-pii, lint-sql, audit-licenses, admission-check, compliance-bundle, mcp...)
scripts/release-provenance.js    Zero-dep CycloneDX 1.6 SBOM, SHA-256 checksums & Ed25519 SLSA DSSE signer
server/
  index.js                       O(1) fast-path HTTP daemon (49-54 MB RSS, 10,679 req/s), Server-Timing, /ws/terminal & /ws/sync
  middleware/auth.js             Constant-time tokens, RBAC middleware, single-use WS tickets, rate limits
  routes/api.js                  REST API (image-audit, crons/lease, pii-mask, forensics, oncall, synthetic/tls, lint-sql, autoscaler, seccomp, MCP)
  services/                      91+ zero-shell services (imageBloatAuditor, cronLeaseService, piiMaskerService, oomForensicsService,
                                 oncallEscalationService, syntheticSentinelService, workerAutoscalerService, sqlMigrationLinter,
                                 licenseAuditorService, seccompProfileService, admissionPolicyService, complianceBundleService,
                                 volumeMigrationService, edgeExperimentService, backupDrillService, sloCanaryController,
                                 aiWorkloadService, remoteBuilderService, logArchiveService, webhookEventBus, dbStudioService,
                                 objectStorageService, quotaMeteringService, brandThemeService, passkeyService, secretLeaseService,
                                 cveDriftService, driftDetectorService, iacExporter, containerTerminalService, fleetMeshService,
                                 edgeShieldService, buildHealerService, liveSyncEngine, otlpExporter, wasmMicroRunner, mcpServer...)
telemetry-collector/             Zero-dep anonymous telemetry collector (node:sqlite WAL + CF Workers/D1)
web/src/                         React 19 + Tailwind v4 dashboard (100% EN/ES, White-Label, ?demo=1 Sandbox, Pioneer Cockpit)
bench/                           Reproducible live benchmarks (control-plane, live-sync, route-swap, subsystems)
scripts/                         Hardened Debian/Ubuntu VPS installer (chmod 700), uninstaller, systemd test & SBOM signer
tests/                           62 integrated + 4 standalone verification, E2E, security, fuzz & stress suites
docs/                            MIGRATION_GUIDE.md, GITHUB_SEO_LAUNCH_KIT.md, COMPETITOR_RADAR_CYCLE{6..12}.md, EVOLUTION_LOG.md, assets/
```

---

## Privacy and Transparent Telemetry

Culkibo includes opt-out anonymous crash/health telemetry scrubbed through an **11-phase PII sanitizer** (never collects secrets, domains, IPs, repo names, or payloads). Inspect the exact JSON envelope anytime (`node bin/culkibo.js telemetry preview`) or disable it instantly via `CULKIBO_TELEMETRY=0`, `DO_NOT_TRACK=1`, CLI (`telemetry disable`), or Settings. Full specification in [`PRIVACY.md`](PRIVACY.md) and [`telemetry-collector/README.md`](telemetry-collector/README.md).

---

## Ethical Open-Core and Community Roadmap

### Our Open-Core Promise (Enforced in [`editionService.js`](server/services/editionService.js))

- **Community Edition (`Apache-2.0`, Free Forever):** **100% of self-hosted core power with ZERO artificial limits** — unlimited projects, 12 databases + PgBouncer + Read-Only DB Studio + Post-Snaplet/Neosync PR-Preview DB PII Masker (`culkibo mask-pii`) + 10-Rule Zero-Downtime SQL Linter (`culkibo lint-sql`), 8-Rule Image Bloat & Secret Auditor (`culkibo audit-image`), 8-Class OOM Forensics & Crash-Loop Classifier, Distributed Cron Fencing-Token Leases, GoAlert/Keep On-Call Escalation & Flapping Damper, OOM-Safe KEDA Worker Autoscaler & `503` Breaker, Synthetic Multi-Step API Flow & Live TLS/SNI Sentinel, CycloneDX SPDX License Auditor (`culkibo audit-licenses`), Tailored Seccomp & `runc` CVE Guard, Policy-as-Code 10-Rule Admission (`culkibo admission-check`), Ed25519-Signed SOC 2 / ISO 27001 / GDPR Compliance Bundles (`culkibo compliance-bundle`), Multi-Region Geo/A-B Edge, Cross-VPS Volume Cloner, Automated DR Fire-Drills (`culkibo dr-drill`), Google SRE SLO Canary Auto-Rollback, Self-Hosted AI/GPU LLM Orchestrator (Ollama · vLLM · llama.cpp), Remote Build Offloader, Persistent `.ndjson.gz` Log Archive, Post-MinIO S3 (Garage · RustFS · SeaweedFS + SigV4), 140 catalog apps, Agency Quotas & CSV-Safe Ledger, Open-Core White-Label Brand, Standard-Webhooks Dual-Secret DLQ, Live Sync 2.0 (`1.06 ms` apply), FIDO2 Passkeys, Secret Leases & Break-Glass, OSV CVE Drift, OpenTofu IaC, Web Terminal, WireGuard Mesh, Caddy PoW Shield, 20-Pattern Auto-Healer, Shadow Replay, Whole-Stack Time-Machine, FinOps, SmartPack, DirectPush, EdgeTunnel, Zero-Dep OTLP, SLSA v1.1 + CycloneDX 1.6 SBOM, `44 µs` Micro-Wasm, Teams & 4-role RBAC, TOTP 2FA, OIDC SSO, GitOps `culkibo.yaml`, **Milestone 150-tool MCP Server (`-88.7%` core)** + Async Tasks + 3 MCP Apps, and Auto-Sleep Scale-to-Zero. **Zero phone-home.**
- **Optional Commercial Packs (`Pro` / `Enterprise` / `Cloud`):** Verified **100% offline via Ed25519 signed keys (`CKL1.*`)** — strictly for organizational scale & compliance: Managed Multi-Region Relay, Extended Status/Email White-Label Packs, Priority Support Bundles, Enterprise SCIM 2.0 / SAML 2.0, Continuous SIEM Audit Streaming, and Managed Multi-AZ Cloud Control Plane.

### Public Engineering Roadmap (Zero New Runtime Deps)

- [x] **v1.0 – v1.1 (Shipped):** Sub-50 MB (`49 MB RSS`) fast-path + `Server-Timing`, 140 pinned catalog apps, 12 DB engines, Sub-8ms Live Sync 2.0, SmartPack (18 stacks), DirectPush (`culkibo pussh`), Sovereign EdgeTunnel (`ET1`), World-First PaaS MCP Apps (`ui://culkibo/*`), SnapStream WAL-to-S3 + PR Preview DB Branching, Runtime-Only Fast Restart, OIDC `groups`→RBAC, and Offline Ed25519 Open-Core editions.
- [x] **v1.2.0 (Cycle #13 Milestone — 150 MCP Tools & 62 Suites Shipped):** **`49–54 MB RSS`** idle RAM (91+ lazy services), **`116.6 ms`** cold boot, **`10,679 req/s`** Auth fast-path, **`9,725 req/s`** Health, **`1.06 ms` apply / `7.67 ms` E2E Live Sync 2.0**, and **`44 µs` (`0.044 ms`) warm Micro-Wasm** (`0.058 ms` p95, `64 KiB` RAM); Container Image Layer Bloat & Secret-in-Layer Auditor (`culkibo audit-image`), Distributed Cron Fencing-Token Lease Guard (`coolify#5655`, `dokploy#1475`), Post-Snaplet/Neosync Deterministic PR-Preview DB PII Masker + `pg_anonymizer` DDL (`culkibo mask-pii`), 8-Class Container OOM-Kill Forensics & Crash-Loop Classifier, GoAlert/Keep On-Call Escalation & Flapping Damper (`uptime-kuma#3255`), Synthetic Multi-Step Flow & TLS/SNI Sentinel, 10-Rule SQL Linter (`culkibo lint-sql`), OOM-Safe KEDA Autoscaler, SPDX License Auditor (`culkibo audit-licenses`), Tailored Seccomp & `runc` CVE Guard, Policy-as-Code Admission (`culkibo admission-check`), Signed SOC 2 Bundles (`culkibo compliance-bundle`), Cross-VPS Volume Cloner, Multi-Region Geo/A-B, DR Fire-Drills (`culkibo dr-drill`), SRE SLO Canaries, Ollama/vLLM GPU (`culkibo ai-vram`), Remote Build Offloader, `.ndjson.gz` Logs, Post-MinIO S3, Read-Only DB Studio, Agency Ledger, OSS White-Label, FIDO2 Passkeys, OSV CVE Drift, OpenTofu IaC, MCP `2026-07-28` (**Milestone `150` tools, `-88.7%` core**, Async Tasks + 3 MCP Apps), 4-job Linux CI, and **62 integrated test suites**.
- [ ] **Next (v1.3 Ecosystem & Multi-Region):** Interactive drag-to-wire Topology edges, live multi-node Coolify v4 VPS migration showcase video, official Homebrew / Docker Hub / GHCR signed multi-arch (`amd64`/`arm64`) releases, and multi-region active-active failover policies.

---

## Contributing and Community

Contributions, bug reports, catalog templates, and benchmarks are warmly welcomed!

- **Read the guide:** [`CONTRIBUTING.md`](CONTRIBUTING.md) (setup, invariants, catalog & MCP authoring)
- **Report a bug or request a feature:** [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/bug_report.md) · [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md)
- **Report a security vulnerability privately:** [`SECURITY.md`](SECURITY.md)
- **Support the project:** If Culkibo saves you RAM, deploy wait time, or migration hours, please **Star this repository** on GitHub so more self-hosters and AI-native teams discover it!

---

## License

Licensed under the **[Apache License 2.0](LICENSE)** — Copyright © 2026 Pablo (`macaqueboy`).
