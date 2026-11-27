<div align="center">

<img src="web/public/favicon.svg" alt="Culkibo Twin Planes K logo" width="84" height="84" />

# Culkibo

**The `51 MB`, `10,679 req/s`, Zero-Shell, AI-Native Self-Hosted PaaS (Open-Source Coolify & Dokploy Alternative)**
Deploy **140+ 1-Click Apps**, **12 Managed Databases**, **Blue/Green DB Read-Replica Split-Brain Fencing**, **Chaos Fault-Injection GameDays**, **Pre-Deploy Shannon-Entropy Secret Gate**, **Container Egress & `nftables` Drift Auditor**, **Multi-Arch (`amd64`/`arm64`) OCI Matrix Planner**, **PR-Preview DB PII Masker**, **Image Secret Auditor**, **8-Class OOM Forensics**, **Cron Fencing Leases**, **On-Call Escalation**, **Zero-Downtime SQL Linter**, **OOM-Safe KEDA Autoscaler**, **Ollama/vLLM GPU**, **Sub-10ms Live Sync 2.0**, **`44–62 µs` Micro-Wasm**, and **155 MCP Tools (`-89.3%` core) + Async Tasks + 3 Inline MCP Apps** for **Claude Code, Antigravity, Cursor, Windsurf & Codex** — on a single **`51 MB`** Node.js control plane (`142.2 ms` boot, `7,660–10,679 req/s`) with **6 runtime dependencies**, **65 test suites**, and **Caddy v2.11** atomic routing.

[![Release: v1.2.0](https://img.shields.io/badge/Release-v1.2.0-F59E0B.svg)](.github/workflows/release.yml)
[![Interactive Sandbox: Zero Install](https://img.shields.io/badge/Live%20Sandbox-Try%20in%2010s%20(%3Fdemo%3D1)-10B981.svg)](.github/workflows/demo-pages.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-2563EB.svg)](LICENSE)
[![CI: 4 Jobs | 65 Suites | Node 20/22/24 + Caddy + Playwright](https://img.shields.io/badge/CI-65%20Suites%20%7C%20Node%2020%2F22%2F24%20%7C%20Caddy%20%7C%20Playwright-16A34A.svg)](.github/workflows/ci.yml)
[![Idle RAM: 51 MB RSS | 10.7k req/s](https://img.shields.io/badge/Idle%20RAM-51%20MB%20RSS%20%7C%2010.7k%20req%2Fs-10B981.svg)](#benchmarks-and-reproducible-results)
[![Runtime Deps: 6 | SLSA v1.1 + CycloneDX 1.6](https://img.shields.io/badge/Runtime%20Deps-6%20%7C%20SLSA%20%2B%20SBOM-0F172A.svg)](scripts/release-provenance.js)
[![Zero Shell: Verified](https://img.shields.io/badge/Shell%20Construction-0%20(CI%20Verified)-0F172A.svg)](tests/shell-safety.test.js)
[![MCP 2026-07-28: 155 Tools + Tasks + 3 MCP Apps](https://img.shields.io/badge/MCP%202026--07--28-155%20Tools%20%7C%20Tasks%20%7C%203%20MCP%20Apps-7C3AED.svg)](#ai-agent-native-mcp-2026-07-28-tasks-and-mcp-apps)

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

Culkibo `v1.2.0` is an open-source **self-hosted PaaS** and **Coolify / Dokploy alternative** engineered for solo builders, agencies, AI/GPU operators, regulated platform teams, and AI coding agents. Instead of bolting a heavy PHP/Laravel or multi-container control stack on top of polling reverse proxies and shell scripts, Culkibo runs a single **51 MB RSS** daemon (across 96+ lazy-loaded services, `0%` CPU, **`142.2 ms`** boot / `116.6 ms` peak, **`7,660–10,679 req/s`** authed fast-path) with **zero shell command construction**, atomic **Caddy v2.11** HTTP/3 ingress (**Geo/A-B Experiments, SRE SLO Canaries & PoW Shield**), **Container Egress & `DOCKER-USER`/`nftables` Drift Auditor**, **Blue/Green DB Read-Replica Split-Brain Fencing**, **Pre-Deploy Shannon-Entropy Secret Gate**, **Multi-Arch (`amd64`/`arm64`) OCI Manifest & Native Builder Planner**, **Toxiproxy/Chaos Mesh GameDay Simulator**, **PR-Preview DB PII Masker**, **Image Secret Auditor**, **8-Class OOM Forensics**, **Cron Fencing Leases**, **On-Call Escalation**, **Synthetic TLS Sentinel**, **10-Rule SQL Linter**, **OOM-Safe KEDA Autoscaler**, **SPDX & Seccomp/`runc` Guards**, **Policy-as-Code Admission**, **Signed SOC 2 Bundles**, **Ollama/vLLM GPU**, **Post-MinIO S3**, **Read-Only DB Studio**, **FIDO2 Passkeys**, **OpenTofu IaC**, **Sub-10ms Live Sync 2.0 (`1.06–1.40 ms` apply / `7.67–9.94 ms` E2E)**, **`44–62 µs` Micro-Wasm** (`64 KiB` RAM), and the industry's first **MCP `2026-07-28` (`155` tools, `-89.3%` core profile, Async Tasks & inline `ui://culkibo/*` MCP Apps)** control plane — verified by **65 integrated test suites**.

---

## Visual Showcase

Culkibo ships with a **Zero-Install Interactive Browser Sandbox (`?demo=1` / `npx culkibo demo`)**, **100% English & Spanish zero-dep localization** across every view (`100.0/100` EN purity + dark-mode contrast verified in Playwright QA), **Obsidian Dark Mode & Crisp Light Mode**, an **Open-Core White-Label Brand & Custom Login Theme Engine** (`GET/PUT /api/brand`), a **Pioneer Cockpit, Resilience & Governance UI** (Pre-Deploy Shannon-Entropy Secret Gate, Blue/Green DB Read-Replica Failover & Split-Brain Fencing, 5-Tab Forensics Drawer — OOM Forensics · Image Bloat · Egress `nftables` Firewall · Multi-Arch `amd64`/`arm64` · Chaos GameDay Simulator, PR-Preview DB PII Masker + `pg_anonymizer` DDL, Cron Fencing Leases, On-Call Escalation & Flapping Damper, Synthetic Flow & TLS/SNI Sentinel, 10-Rule SQL Linter, OOM-Safe KEDA Autoscaler, SPDX License Auditor, Tailored Seccomp & `runc` Guard, Policy-as-Code Admission, Signed SOC 2 Dossier, Multi-Region Geo/A-B, Cross-VPS Volume Planner, SLO Canary Rollback, DR Fire-Drills, AI/GPU VRAM Planner, Remote Build Offloader, `.ndjson.gz` Log Archive, Read-Only DB Studio, Post-MinIO S3 + SigV4, Agency Ledger, Passkeys FIDO2, OSV CVE Scanner, OpenTofu IaC, Zero-Dep Web Terminal, 20-Pattern Auto-Healer, WireGuard Mesh, Caddy PoW Shield, SmartPack, Shadow Replay, Time-Machine, `44–62 µs` Micro-Wasm Tester, FinOps, OTLP, and Coolify Streamer), and an interactive **Spatial SVG Topology Canvas** with click-to-link database env injection.

### Live Sync 2.0 (`1.06–1.40 ms` Apply · `7.67–9.94 ms` E2E) + Inline MCP Apps Flow

<p align="center">
  <img src="docs/assets/live-sync-demo.svg" alt="Animated Culkibo Live Sync 2.0 and inline MCP Apps topology flow showing sub-10ms Merkle delta apply, -96.1% Brotli compression, Server-Timing, and ui://culkibo/topology" width="100%" />
</p>

### Obsidian Dark Mode & Light Mode (100% Global EN / ES Dashboard)

| Obsidian Dark Mode (`1440×900`) | Crisp Light Mode (`1440×900`) |
| :---: | :---: |
| ![Culkibo English Obsidian Dark Mode dashboard with live RAM telemetry, onboarding checklist, and project cards](docs/assets/dashboard-dark-en.png) | ![Culkibo English Light Mode dashboard with project cards, search filters, and 1-click deploy controls](docs/assets/dashboard-light-en.png) |

### Spatial SVG Topology Canvas & Click-to-Link DB Injection (`Obsidian Dark`)

![Culkibo interactive Spatial SVG Topology Canvas in Obsidian Dark showing Domains, Projects, Managed Databases, animated directional edges, and Node Inspector with Link-to-Project DATABASE_URL injection](docs/assets/topology-dark-en.png)

### AI Agent Hub — MCP `2026-07-28`, `-89.3%` Token Profiles & Interactive MCP Apps (`ui://culkibo/*`)

![Culkibo 100% English AI Agent Hub showing MCP tools, playbooks, core profile token savings, 1-click Antigravity/Claude/Cursor/Windsurf/Codex setup, and Interactive MCP Apps gallery](docs/assets/ai-agent-hub.png)

---

## Why Culkibo Is Architecturally Different

Traditional self-hosted PaaS platforms force a painful trade-off: burn 500 MB–1.5 GB of VPS RAM just to run the panel, leak cloud metadata through drifting Docker 29 `nftables` rules, promote lagging DB replicas into split-brain, deploy `arm64` images onto `amd64` servers (`EXEC_FORMAT_MISMATCH`), commit secrets into diffs/layers, and live with recurring shell-injection & `runc`/LLM CVEs. Culkibo fixes these problems at the architecture layer:

### 1. Zero-Shell Engine (`shell: false`), Shannon Secret Gate, Egress `nftables` Audit, Seccomp/`runc` & SOC 2
- Every subprocess (`docker`, `git`, `caddy`, `ssh`, `cron`, `exec`, `npm`) is invoked through `spawn()` / `execFile()` with tokenized `argv` arrays validated by [`safeCommand.js`](server/services/safeCommand.js) and `shell: false`. Statically verified on every commit by [`tests/shell-safety.test.js`](tests/shell-safety.test.js).
- **Pre-Deploy Shannon-Entropy & Pattern Secret Gate (`server/services/preDeploySecretGate.js` · `culkibo secret-scan` + MCP `culkibo_secret_gate`):** Gitleaks/TruffleHog shift-left sub-ms scanner (`computeShannonEntropy`, 12 secret rules + benign UUID/SHA-256 filters + `# culkibo:allow-secret`) scanning diffs, `.env`, and Compose pre-build with redacted SHA-256 fingerprints and **0 raw secret echoes** (exits `1` in CI when blocked).
- **Container Egress & Firewall (`DOCKER-USER`/`nftables`) Drift Auditor (`server/services/egressFirewallService.js` · MCP `culkibo_egress_firewall`):** Cures `coolify#12336`, `dokploy#2486` & Docker 29 `--firewall-backend=nftables` drift by flagging cloud metadata (`169.254.169.254`, `fd00:ec2::254`) & unauthorized private-LAN/outbound sockets, detecting missing drop chains, and generating anti-lockout rules that always preserve SSH (`22`), HTTP (`80`), and HTTPS (`443`).
- **Image Secret Auditor (`culkibo audit-image`), PR-Preview DB PII Masker (`culkibo mask-pii` + `pg_anonymizer` DDL), Tailored Seccomp & `runc` CVE Guard, SPDX License Auditor (`culkibo audit-licenses`), Policy-as-Code 10-Rule CIS/PSS Admission (`culkibo admission-check`) & Ed25519-Signed SOC 2 / ISO / GDPR Bundles (`culkibo compliance-bundle`, 0 secrets):** Plus Automated DR Fire-Drills (`culkibo dr-drill`), FIDO2 Passkeys, Secret Leases, OSV CVE Drift, and Signed SLSA v1.1 + CycloneDX 1.6 SBOM.
- **By-Design Immunity to Real-World PaaS, DB & Runtime CVEs ([`CYCLE6`](docs/COMPETITOR_RADAR_CYCLE6.md) · [`CYCLE7`](docs/COMPETITOR_RADAR_CYCLE7.md) · [`CYCLE8`](docs/COMPETITOR_RADAR_CYCLE8.md) · [`CYCLE9`](docs/COMPETITOR_RADAR_CYCLE9.md) · [`CYCLE10`](docs/COMPETITOR_RADAR_CYCLE10.md) · [`CYCLE11`](docs/COMPETITOR_RADAR_CYCLE11.md) · [`CYCLE12`](docs/COMPETITOR_RADAR_CYCLE12.md) · [`CYCLE13`](docs/COMPETITOR_RADAR_CYCLE13.md)):** Immune to **`coolify#12336/#7019/#5328/#5655/#3862/#6506/#11372/#12170`**, **`dokploy#2486/#429/#1633/#1475/#3193/#6105/#2661/#2642/#1382`**, **`cloudnative-pg#8701/#7407`**, **`patroni#3474`**, **`runc CVE-2025-31133`/`52565`/`52881`**, **`Coolify CVE-2025-66213`**, **`Ollama CVE-2026-7482`**, **`vLLM CVE-2026-22778`/`137477`**, Dokploy **`CVE-2026-116068`/`127212`/`24841`/`129433`/`129315`/`133520`**, Portainer **`CVE-2026-134756`**, Runtipi **`CVE-2026-47277`**, Dokku **`CVE-2026-54636`**, **`uptime-kuma#3255/#5772/#7500/#7704/#8193/#6519`**, **`gatus#856`**, **`kamal#1709/#1856/#1790`**, and the MinIO / Neosync / Snaplet discontinuations.

### 2. `51 MB` Idle RAM, `7,660–10,679 req/s`, Chaos GameDays, On-Call Escalation & Cron Fencing Leases
- **Independently Verified Performance (Cycle #10–#13 QA `#278`/`#324`):** **`51 MB RSS`** idle daemon (`49 MB` record; `51 MB` across 96+ lazy-loaded services, `<= 60 MB` invariant, `0%` CPU), **`142.2 ms`** boot (`116.6 ms` peak), **`7,660–10,679 req/s`** authed Bearer+Brotli fast-path, **`6,859–9,725 req/s`** health, and **`0.61–0.63 ms`** warm 140-app catalog — fitting effortlessly on a **$4/mo 512 MB–1 GB VPS**.
- **Minimal supply-chain blast radius:** Exactly **6** root npm runtime dependencies ([`package.json`](package.json): `express`, `ws`, `chokidar`, `commander`, `cors`, `dotenv`) and **0** dependencies in [`telemetry-collector/`](telemetry-collector/README.md) — enforced across Node `20`, `22`, and `24` in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
- **Chaos Fault-Injection GameDay Simulator & Resilience Scorecard (`server/services/chaosGameDayService.js` · MCP `culkibo_chaos_gameday`):** Toxiproxy / Chaos Mesh fault drills (`latency_jitter`, `http_5xx`, `timeout_drop`, `dns_failure`, `bandwidth_cap`) with a hard production safety lock (`PROD_CHAOS_CONFIRM_REQUIRED`), automatic error-rate abort (`AUTO_ABORTED`), and `0..100` Resilience Scorecards (`A`–`F` grade).
- **GoAlert/Keep On-Call Escalation & Flapping Damper (`oncallEscalationService.js`, `uptime-kuma#3255`), Distributed Cron Fencing-Token Leases (`cronLeaseService.js`, `coolify#5655`), Synthetic Multi-Step Flow & Live TLS/SNI Sentinel, Persistent `.ndjson.gz` Log Archive, Agency Quotas (`culkibo ledger --csv`), Open-Core White-Label Brand (`coolify#1744`), Standard-Webhooks Dual-Secret DLQ, Zero-Dep OTLP & FinOps.**

### 3. Blue/Green DB Replica Fencing, Multi-Arch OCI Planner, OOM Forensics, Sub-10ms Live Sync & `44–62 µs` Wasm
When coding with Claude Code, Antigravity, Cursor, or Windsurf, waiting 2–4 minutes per push destroys flow:

```text
Traditional PaaS:  save file -> git commit -> push -> webhook -> Docker rebuild (1-4 min) -> check
Culkibo Forge:     save file -> binary Commit Frame (/ws/sync, Brotli -96.1%) -> 1.06-1.40 ms apply / 7.67-9.94 ms E2E
Culkibo Citadel:   Secret Gate -> Multi-Arch Verify -> SQL Lint -> Policy Gate -> SLO Canary -> Chaos GameDay
```

- **Blue/Green DB Read-Replica Promotion & Split-Brain Fencing (`server/services/replicaFailoverService.js` · MCP `culkibo_replica_failover`):** Cures `cloudnative-pg#8701`/`#7407`, `patroni#3474` & `dokploy#429`/`#1633` by hard-blocking promotion on lag excess (`REPLICA_LAG_TOO_HIGH`) or unfenced primary (`OLD_PRIMARY_NOT_FENCED`), lag-filtering read pools, and emitting ordered `drain → fence → promote → re-route` steps (`dryRun: true` default).
- **Multi-Arch (`amd64`/`arm64`) OCI Manifest & Native Builder Matrix Planner (`server/services/multiArchPlannerService.js` · `culkibo multiarch-check` + MCP `culkibo_multiarch_planner`):** Catches Apple Silicon→x86 / Ampere `EXEC_FORMAT_MISMATCH` pre-deploy (exits `1` in CI), validates strict-registry OCI attestation index rules, and routes builds to native fleet builders ahead of QEMU with zero-shell `buildx` argv.
- **8-Class Container OOM Forensics (`137+oomKilled` vs `SIGKILL` vs `STALE_HISTORICAL_TASK_IGNORED`), 10-Rule Zero-Downtime SQL Linter (`culkibo lint-sql`), OOM-Safe KEDA Queue/Worker Autoscaler + `503 Retry-After` Breaker, Read-Only Live DB Studio & Safe Redis Inspector, Zero-Dep Web Terminal (`/ws/terminal`), and 20-Pattern Build Auto-Healer (`culkibo heal`).**
- **Adaptive Live Sync 2.0 (`1.06–1.40 ms` apply · `7.67–9.94 ms` E2E · `-96.1%` Brotli), Google SRE SLO Canary Auto-Rollback (`10→25→50→100%` Caddy weights + instant `100/0` rollback), Shadow Replay Gate & Whole-Stack Time-Machine (`culkibo timemachine`).**
- **Record `44–62 µs` (`0.044–0.062 ms`) Warm Micro-Wasm Edge Runtime ([`wasmMicroRunner.js`](server/services/wasmMicroRunner.js)):** Sandboxed WebAssembly in isolated `worker_threads` — live-measured at **`44 µs` peak / `62 µs` Cycle-13 warm p50** and **`64 KiB` RAM** (zero host filesystem/network access).
- **Honest scope:** Live Sync 2.0 accelerates incremental code/asset iteration (*Path B*). Dependency or `Dockerfile` changes run full immutable Docker BuildKit builds (*Path C*) with secret gate, multi-arch verify, SQL lint, admission checks, smoke tests, SLO canaries, and multi-release rollback.

### 4. `155` MCP `2026-07-28` Tools (`-89.3%` Core), Autonomous Triage, Async Tasks & Inline MCP Apps
- **155 Tools, 13 Playbook Prompts & 10 Resources** over Streamable HTTP (`POST /api/mcp`) and stdio (`culkibo mcp`) with legacy SSE fallback — verified end-to-end against a real spawned stdio JSON-RPC client ([`tests/release-and-mcp-e2e.test.js`](tests/release-and-mcp-e2e.test.js)), including `culkibo_egress_firewall`, `culkibo_replica_failover`, `culkibo_secret_gate`, `culkibo_multiarch_planner`, `culkibo_chaos_gameday`, `culkibo_audit_image_bloat`, `culkibo_cron_lease`, `culkibo_mask_preview_pii`, `culkibo_oom_forensics`, `culkibo_oncall_router`, `culkibo_synthetic_sentinel`, `culkibo_lint_sql_migration`, `culkibo_worker_autoscaler`, `culkibo_audit_licenses`, `culkibo_seccomp_profile`, **`culkibo_security_posture`**, `culkibo_admission_check`, `culkibo_compliance_bundle`, **`culkibo_triage_playbook`**, `culkibo_slo_canary`, and `culkibo_ai_workload`.
- **Official MCP `2026-07-28` Async Tasks (`io.modelcontextprotocol/tasks`) & Elicitation (`elicitation/create`):** Long-running Docker builds, Coolify migrations, and DR drills run non-blocking via `tasks/list`, `tasks/get`, `tasks/result`, and `tasks/cancel` with strict cross-tenant RBAC isolation — and declare structured JSON Schema `elicitation` prompts for missing secrets or approvals.
- **5 Context-Saving Profiles (`?profile=core|deploy|ops|security|all` & `CULKIBO_MCP_PROFILE`):** `?profile=core` serves the 17 essential tools (`17 / 155`) and cuts LLM tool-schema context by **`-89.3%`** while `culkibo_search_tools` discovers any of the remaining 155 tools on demand.
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
| **Control-Plane RAM & Fast-Path** | **51 MB RSS · 7,660–10,679 req/s** *(142 ms boot)* | ~800 MB – 1.5 GB *(2 GB VPS min)* | ~450 – 800 MB *(1–2 GB VPS)* | ~150 – 300 MB *(300–450 MB w/ Swarm)* | 0 MB panel *(+15–25 MB proxy)* | ~100 – 200 MB *(external proxy)* |
| **Shannon Secret Gate + Egress `nftables` + SOC 2** | ✅ **12-rule Entropy · `DOCKER-USER`/`nftables` · Seccomp · SOC 2** | ❌ `#12336` / `- /:/host` | ❌ `#2486` / `#2642` | ⚠️ Swarm CLI | ⚠️ SSH shell | ⚠️ Paid Business |
| **DB Read-Replica Fencing + PR PII Masker + SQL Lint** | ✅ **Split-brain fence (`#8701`) · HMAC PII · 10-rule DDL lint** | ❌ | ❌ *(`#429`/`#1633`)* | ❌ | ❌ | ❌ |
| **Multi-Arch Matrix + Chaos GameDays + OOM Forensics** | ✅ **`amd64`/`arm64` native · Prod-locked Chaos · 8-class OOM** | ❌ | ❌ | ❌ | ❌ | ⚠️ Stale rollback |
| **Cron Fencing Leases + On-Call + KEDA Autoscaler** | ✅ **Monotonic `fencingToken` · Flapping Damper · RAM-capped KEDA** | ⚠️ `#5655` / `#3862` | ⚠️ `#1475` / `#6105` | ❌ *(`#2164`)* | ❌ | ❌ |
| **Synthetic API Flows + Live TLS/SNI Sentinel** | ✅ **Multi-step flows (0 secrets) + uncached TLS/SAN/FP drift** | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Multi-Region Geo/A-B + SRE SLO Canary** | **Caddy v2.11** *(`CF-IPCountry` · Sticky A/B · 10→100% SRE · PoW)* | Traefik *(2,000 ms throttle)* | Traefik / Swarm | Nginx reload | `kamal-proxy` *(<1 ms swap)* | ❌ External |
| **Cross-VPS Volume Cloner + AI/GPU LLMs** | ✅ **`tar --numeric-owner` (`999:999`) · Ollama · vLLM · CDI + CVE** | ❌ `CVE-2025-66213` | ⚠️ Legacy GPU (`#1621`) | ❌ | ⚠️ `EACCES` | ❌ |
| **Automated DR Fire-Drills + `.ndjson.gz` Logs** | ✅ **`culkibo dr-drill` (0B/ACL guard) · Redeploy-safe logs** | ⚠️ Empty dump (`#6506`) | ⚠️ Empty dump (`#1382`) | ❌ | ❌ | ❌ |
| **Remote Build Offloader + Live Sync 2.0** | ✅ **SSH mux-pinned builds (`#11372`) · `1.06–1.40 ms` apply** | ⚠️ Mux kill (`#11372`) | ⚠️ Queue race (`#3226`) | ❌ Image build | ❌ Image build | ❌ |
| **Read-Only DB Studio + Post-MinIO S3** | ✅ **Safe SQL/Redis Studio · Garage/RustFS/SeaweedFS + SigV4** | ⚠️ Adminer / MinIO | ⚠️ Adminer / MinIO | ❌ | ❌ | ❌ |
| **Agency Quotas, Ledger & OSS White-Label** | ✅ **Tenant Quotas · CSV-safe Ledger · OSS White-Label (`#1744`)** | ❌ *(`#1744` open)* | 💰 Enterprise paywall | ❌ | ❌ | 💰 Business |
| **AI-Agent Native MCP + Triage + MCP Apps** | ✅ **155 tools · `security_posture` · Tasks · 3 `ui://` Apps · `-89.3%`** | ❌ *(3rd-party)* | ❌ *(3rd-party)* | ❌ | ❌ | ❌ |
| **SmartPack + DirectPush + WireGuard + `44–62 µs` Wasm** | ✅ **18 stacks · `culkibo pussh` · `x25519` Mesh · Micro-Wasm** | ⚠️ Nixpacks | ⚠️ Nixpacks | ⚠️ Buildpacks | ❌ Registry req. | ❌ |
| **1-Click Catalog, 12 DBs, Passkeys & Coolify Migrator** | ✅ **140 apps · 12 DBs · FIDO2 Passkeys · OpenTofu IaC · Coolify→Caddy** | ✅ Catalog / ⚠️ Teams | ✅ Catalog / ⚠️ Basic | ✅ One-click | ✅ `deploy.yml` | ⚠️ Paid Business |

---

## Benchmarks and Reproducible Results

Every Culkibo metric below comes from real code independently measured on `Node v24.14.0` (`win32/x64`, uncontended run) with **zero synthetic delays and zero subtracted overhead**. Reproduce the complete suite or generate a Markdown/JSON comparison report on your own machine:

```bash
node bench/run-all.bench.js
node bench/competitor-comparison.bench.js --markdown
```

### Independently Verified Live Performance Results (`v1.2.0` Clean Uncontended Runs)

| Metric | Live Measured Result | Notes & Verification Command |
| :--- | :--- | :--- |
| **Idle Daemon RAM / CPU** | **51 MB RSS · 0% CPU** *(49 MB all-time record)* | Verified across 96+ lazy-loaded services (`<= 60 MB` invariant) |
| **Cold Boot Time** (`CULKIBO_SKIP_RECONCILE=1`) | **142.2 ms** *(116.6 ms peak record)* | Measured via `process.hrtime.bigint()` (`npm run bench:control`) |
| **Authenticated Fast-Path (Bearer + Brotli, 500 req / 25w)** | **7,660 – 10,679 req/s** *(p50 `2.20–3.04 ms`)* | HMAC-SHA256 LRU cache + WeakMap zero-copy Brotli + `Server-Timing: cp;dur=0.02` |
| **Health HTTP (`GET /api/health`, 500 req / 25w)** | **6,859 – 9,725 req/s** | Pre-compiled O(1) fast-path route map |
| **Mixed Uncompressed / RBAC Express HTTP (500 req / 25w)** | **3,050 – 3,566 req/s** mixed · **2,330 req/s** RBAC | `0` failures · RBAC check `96,308 ops/s` (`bench/subsystems.bench.js`) |
| **Catalog Load (`GET /api/catalog`, 140 apps)** | **warm p50 `0.61 – 0.63 ms`** | `129.6 KB` → `34.5 KB` Brotli (**-73.4%**) |
| **Live Sync 2.0 (Path B Incremental Sync)** | **server apply `1.06–1.40 ms` · E2E `7.67–9.94 ms`** | Sub-10ms E2E · 100-file TSX Brotli **-96.1%** (`25.66×`) · rollback **p50 `1.60–2.13 ms`** |
| **Isolated Micro-Wasm Edge Runtime** | **warm p50 `44 – 62 µs` (`0.044–0.062 ms`) · `64 KiB` RAM** | Verified via `bench/competitor-comparison.bench.js` & [`tests/migrations-and-wasm.test.js`](tests/migrations-and-wasm.test.js) |
| **WebSocket 40-Client Fan-Out** | **53.4 – 68.4 ms** (`40/40` initial state delivered) | Zero drops under concurrent churn (`tests/websocket-stress.test.js`) |
| **Caddy v2.11 Atomic Route Swap, Geo/A-B & SLO Canary** | **Synchronous zero-poll Admin API + `weighted_round_robin`** | Verified live in Linux CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml) `live-caddy-e2e`) & `npm run bench` |
| **MCP `2026-07-28` `?profile=core` Savings** | **-89.3% schema tokens** (`17 / 155` tools) | Verified via `bench/competitor-comparison.bench.js` + external stdio E2E |
| **Supply-Chain, Shell Safety & Test Suite** | **6 root deps · 0 collector deps · 0 shell calls · 65 suites** | Verified in CI + Signed SLSA v1.1 + Ed25519 SOC 2 + Shannon Secret Gate + SPDX |

---

## Architecture

Culkibo separates rapid developer/AI iteration (**The Forge**) from immutable production releases (**The Citadel**) on a single lightweight control plane:

```mermaid
flowchart LR
    Dev["Developer & AI Agents (Claude Code / Antigravity / Cursor)"]
    UI["Web Dashboard (100% EN/ES · White-Label · 5-Tab Forensics · Replica Fence · ?demo=1)"]
    MCP["MCP 2026-07-28 (155 Tools, -89.3% Core, Tasks, 3 ui:// Apps)"]
    Sync["Live Sync 2.0 (/ws/sync 1.06-1.40 ms Apply · 7.67-9.94 ms E2E)"]
    CP["Culkibo Control Plane (Node.js 51 MB RSS, 7.6k-10.7k req/s, 6 Deps, shell:false)"]
    Forge["The Forge (Hot Dev + /ws/terminal + Shannon Secret Gate + Multi-Arch Matrix)"]
    Citadel["The Citadel (SQL Linter + Policy + Egress nftables + Chaos GameDays + SLSA)"]
    Caddy["Caddy v2.11 Edge (HTTP/3, Geo/A-B, SRE Canary, PoW Shield, WireGuard, 44-62us Wasm)"]
    Obs["On-Call Escalation + Cron Leases + Synthetic TLS + Signed SOC 2 + OTLP"]
    Data["12 DBs + Replica Fencing + PR PII Masker + Post-MinIO S3 + AI/GPU LLMs"]

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
node bin/culkibo.js sync <projectId> .               # Start Live Sync 2.0 (1.06-1.40 ms apply)
node bin/culkibo.js deploy <projectId>               # Immutable BuildKit deploy + Policy Gate + SLO Canary
node bin/culkibo.js secret-scan .env --mode enforce --json  # 12-rule Shannon-entropy secret gate (exit 1 on leak)
node bin/culkibo.js multiarch-check --image-arch arm64 --host-arch amd64 --json  # Catch EXEC_FORMAT_MISMATCH
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

Culkibo is built from day one for autonomous and human-in-the-loop AI coding workflows — shipping **155 tools** (including `culkibo_egress_firewall`, `culkibo_replica_failover`, `culkibo_secret_gate`, `culkibo_multiarch_planner`, `culkibo_chaos_gameday`, `culkibo_audit_image_bloat`, `culkibo_cron_lease`, `culkibo_mask_preview_pii`, `culkibo_oom_forensics`, `culkibo_oncall_router`, `culkibo_synthetic_sentinel`, `culkibo_lint_sql_migration`, `culkibo_worker_autoscaler`, `culkibo_audit_licenses`, `culkibo_seccomp_profile`, `culkibo_security_posture`, `culkibo_triage_playbook`), **13 playbooks**, official **MCP `2026-07-28` Async Tasks (`io.modelcontextprotocol/tasks`)**, **Elicitation (`elicitation/create`)**, and the first **`modelcontextprotocol/ext-apps` (`2026-01-26`)** interactive UI resources in any self-hosted PaaS.

### 1-Click Agent Kit Generator

Generate drop-in MCP configs (defaulting to `?profile=core` for **-89.3% token savings** across `17 / 155` tools and using `${CULKIBO_TOKEN}` env placeholders — never plaintext secrets):

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

Culkibo ships **65 integrated test suites** in `tests/run-all.js` (including Container Egress & `DOCKER-USER`/`nftables` Drift Auditor, Blue/Green DB Read-Replica Split-Brain Fencing, Pre-Deploy Shannon-Entropy Secret Gate, Multi-Arch `amd64`/`arm64` OCI Matrix Planner, Chaos Fault-Injection GameDay Simulator, Image Bloat & Secret Auditor, Distributed Cron Fencing Leases, Deterministic PR-Preview DB PII Masker, 8-Class OOM Forensics, On-Call Escalation & Flapping Damper, Synthetic Flow & TLS/SNI Sentinel, OOM-Safe KEDA Autoscaler, 10-Rule SQL Linter, SPDX License Auditor, Tailored Seccomp & `runc` Guard, Policy-as-Code Admission, Signed SOC 2 Bundles, Cross-VPS Volume Migration, Multi-Region Geo/A-B, Automated DR Fire-Drills, SRE SLO Canaries, Ollama/vLLM GPU, Remote Build Offloader, `.ndjson.gz` Log Archive, Standard-Webhooks DLQ, Post-MinIO S3, Read-Only DB Studio, Agency Ledger, White-Label, FIDO2 Passkeys, OpenTofu IaC, Mock-Coolify v4 E2E, external MCP stdio E2E, OTLP/SLSA E2E, and `44–62 µs` Micro-Wasm E2E) + standalone live-server, WebSocket churn, HTTP stress, and zero-dep telemetry collector suites — verified continuously on Linux by [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (`4` jobs: Node 20/22/24 matrix + Live Caddy v2.11 + Docker BuildKit SmartPack & SBOM E2E + Playwright Desktop/Mobile visual QA), released with signed SLSA v1.1 + CycloneDX 1.6 via [`.github/workflows/release.yml`](.github/workflows/release.yml), and published as a zero-install sandbox via [`.github/workflows/demo-pages.yml`](.github/workflows/demo-pages.yml):

```bash
node tests/shell-safety.test.js                       # Static AST/source check: 0 shell calls
npm run typecheck                                     # Server TypeScript checkJs (0 errors)
npx tsc -p web/tsconfig.app.json --noEmit             # Frontend TypeScript check (0 errors)
npx --prefix web oxlint --deny-warnings               # oxlint React 19 + Compiler rules (0 warnings)
npm run web:build                                     # Vite production build + .br/.gz precompression
npm test                                              # 65 suites + live-server + WS stress + HTTP stress
node --test telemetry-collector/test/collector.test.js  # Zero-dep telemetry collector suite
npm run release:sbom -- --out-dir dist-release --sign --verify  # Signed SLSA v1.1 + CycloneDX 1.6 SBOM
```

### Repository Layout

```text
.github/workflows/ci.yml         Active 4-job Linux CI (Node 20/22/24, Live Caddy, BuildKit SmartPack/SBOM, Playwright)
.github/workflows/release.yml    Automated v* GitHub Release workflow (Signed SLSA v1.1 DSSE + CycloneDX 1.6 SBOM)
.github/workflows/demo-pages.yml Zero-Install Interactive Browser Sandbox workflow (GitHub Pages ?demo=1)
bin/culkibo.js                   CLI (demo, init, up, sync, deploy, secret-scan, multiarch-check, audit-image, mask-pii, lint-sql, mcp...)
scripts/release-provenance.js    Zero-dep CycloneDX 1.6 SBOM, SHA-256 checksums & Ed25519 SLSA DSSE signer
server/
  index.js                       O(1) fast-path HTTP daemon (51 MB RSS, 7.6k-10.7k req/s), Server-Timing, /ws/terminal & /ws/sync
  middleware/auth.js             Constant-time tokens, RBAC middleware, single-use WS tickets, rate limits
  routes/api.js                  REST API (egress, replicas, predeploy-secret-scan, multiarch, chaos, forensics, oncall, synthetic, MCP)
  services/                      96+ zero-shell services (egressFirewallService, replicaFailoverService, preDeploySecretGate,
                                 multiArchPlannerService, chaosGameDayService, imageBloatAuditor, cronLeaseService,
                                 piiMaskerService, oomForensicsService, oncallEscalationService, syntheticSentinelService,
                                 workerAutoscalerService, sqlMigrationLinter, licenseAuditorService, seccompProfileService,
                                 admissionPolicyService, complianceBundleService, volumeMigrationService, edgeExperimentService,
                                 backupDrillService, sloCanaryController, aiWorkloadService, remoteBuilderService,
                                 logArchiveService, webhookEventBus, dbStudioService, objectStorageService, quotaMeteringService,
                                 brandThemeService, passkeyService, secretLeaseService, cveDriftService, driftDetectorService,
                                 iacExporter, containerTerminalService, fleetMeshService, edgeShieldService, mcpServer...)
telemetry-collector/             Zero-dep anonymous telemetry collector (node:sqlite WAL + CF Workers/D1)
web/src/                         React 19 + Tailwind v4 dashboard (100% EN/ES, White-Label, ?demo=1 Sandbox, Pioneer Cockpit)
bench/                           Reproducible live benchmarks (control-plane, live-sync, route-swap, subsystems)
scripts/                         Hardened Debian/Ubuntu VPS installer (chmod 700), uninstaller, systemd test & SBOM signer
tests/                           65 integrated + 4 standalone verification, E2E, security, fuzz & stress suites
docs/                            MIGRATION_GUIDE.md, GITHUB_SEO_LAUNCH_KIT.md, COMPETITOR_RADAR_CYCLE{6..13}.md, EVOLUTION_LOG.md, assets/
```

---

## Privacy and Transparent Telemetry

Culkibo includes opt-out anonymous crash/health telemetry scrubbed through an **11-phase PII sanitizer** (never collects secrets, domains, IPs, repo names, or payloads). Inspect the exact JSON envelope anytime (`node bin/culkibo.js telemetry preview`) or disable it instantly via `CULKIBO_TELEMETRY=0`, `DO_NOT_TRACK=1`, CLI (`telemetry disable`), or Settings. Full specification in [`PRIVACY.md`](PRIVACY.md) and [`telemetry-collector/README.md`](telemetry-collector/README.md).

---

## Ethical Open-Core and Community Roadmap

### Our Open-Core Promise (Enforced in [`editionService.js`](server/services/editionService.js))

- **Community Edition (`Apache-2.0`, Free Forever):** **100% of self-hosted core power with ZERO artificial limits** — unlimited projects, 12 databases + Blue/Green DB Read-Replica Split-Brain Fencing + PgBouncer + Read-Only DB Studio + PR-Preview DB PII Masker (`culkibo mask-pii`) + 10-Rule SQL Linter (`culkibo lint-sql`), Pre-Deploy Shannon-Entropy Secret Gate (`culkibo secret-scan`), Container Egress & `DOCKER-USER`/`nftables` Drift Auditor, Multi-Arch (`amd64`/`arm64`) OCI Matrix Planner (`culkibo multiarch-check`), Toxiproxy/Chaos Mesh GameDay Simulator, 8-Rule Image Bloat & Secret Auditor (`culkibo audit-image`), 8-Class OOM Forensics, Distributed Cron Fencing Leases, GoAlert/Keep On-Call Escalation & Flapping Damper, OOM-Safe KEDA Autoscaler & `503` Breaker, Synthetic Multi-Step Flow & TLS/SNI Sentinel, CycloneDX SPDX License Auditor (`culkibo audit-licenses`), Tailored Seccomp & `runc` CVE Guard, Policy-as-Code Admission (`culkibo admission-check`), Ed25519-Signed SOC 2 / ISO 27001 / GDPR Compliance Bundles (`culkibo compliance-bundle`), Multi-Region Geo/A-B Edge, Cross-VPS Volume Cloner, Automated DR Fire-Drills (`culkibo dr-drill`), Google SRE SLO Canary Auto-Rollback, Self-Hosted Ollama/vLLM GPU Orchestrator, Remote Build Offloader, `.ndjson.gz` Log Archive, Post-MinIO S3 (Garage · RustFS · SeaweedFS + SigV4), 140 catalog apps, Agency Quotas & CSV-Safe Ledger, Open-Core White-Label Brand, Standard-Webhooks DLQ, Live Sync 2.0, FIDO2 Passkeys, Secret Leases, OSV CVE Drift, OpenTofu IaC, Web Terminal, WireGuard Mesh, Caddy PoW Shield, 20-Pattern Auto-Healer, Shadow Replay, Time-Machine, FinOps, OTLP, SLSA v1.1 + CycloneDX 1.6 SBOM, `44–62 µs` Micro-Wasm, Teams & 4-role RBAC, TOTP 2FA, OIDC SSO, GitOps `culkibo.yaml`, **155-tool MCP Server (`-89.3%` core)** + Async Tasks + 3 MCP Apps, and Auto-Sleep Scale-to-Zero. **Zero phone-home.**
- **Optional Commercial Packs (`Pro` / `Enterprise` / `Cloud`):** Verified **100% offline via Ed25519 signed keys (`CKL1.*`)** — strictly for organizational scale & compliance: Managed Multi-Region Relay, Extended Status/Email White-Label Packs, Priority Support Bundles, Enterprise SCIM 2.0 / SAML 2.0, Continuous SIEM Audit Streaming, and Managed Multi-AZ Cloud Control Plane.

### Public Engineering Roadmap (Zero New Runtime Deps)

- [x] **v1.0 – v1.1 (Shipped):** Sub-50 MB (`49 MB` record) fast-path + `Server-Timing`, 140 pinned catalog apps, 12 DB engines, Sub-10ms Live Sync 2.0, SmartPack (18 stacks), DirectPush (`culkibo pussh`), Sovereign EdgeTunnel (`ET1`), World-First PaaS MCP Apps (`ui://culkibo/*`), SnapStream WAL-to-S3 + PR Preview DB Branching, Runtime-Only Fast Restart, OIDC `groups`→RBAC, and Offline Ed25519 Open-Core editions.
- [x] **v1.2.0 (Cycle #14 Shipped — 65 Suites & 155 MCP Tools):** **`51 MB RSS`** idle RAM (96+ lazy services, `49 MB` record), **`142.2 ms`** boot (`116.6 ms` peak), **`7,660–10,679 req/s`** fast-path, **`7.67–9.94 ms`** E2E Live Sync 2.0, and **`44–62 µs`** warm Micro-Wasm (`64 KiB` RAM); Container Egress & `DOCKER-USER`/`nftables` Drift Auditor (`coolify#12336`, `dokploy#2486`), Blue/Green DB Read-Replica Split-Brain Fencing (`cloudnative-pg#8701`/`#7407`, `patroni#3474`), Pre-Deploy Shannon-Entropy Secret Gate (`culkibo secret-scan`), Multi-Arch (`amd64`/`arm64`) OCI Manifest & Native Builder Planner (`culkibo multiarch-check`), Toxiproxy/Chaos Mesh GameDay Simulator, Image Bloat & Secret Auditor (`culkibo audit-image`), Distributed Cron Fencing Leases (`coolify#5655`), PR-Preview DB PII Masker (`culkibo mask-pii`), 8-Class OOM Forensics, On-Call Escalation & Flapping Damper (`uptime-kuma#3255`), Synthetic Flow & TLS/SNI Sentinel, 10-Rule SQL Linter (`culkibo lint-sql`), OOM-Safe KEDA Autoscaler, SPDX License Auditor, Tailored Seccomp/`runc` Guard, Policy-as-Code Admission, Signed SOC 2 Bundles, Cross-VPS Volume Cloner, Multi-Region Geo/A-B, DR Fire-Drills, SRE SLO Canaries, Ollama/vLLM GPU, Remote Build Offloader, `.ndjson.gz` Logs, Post-MinIO S3, Read-Only DB Studio, Agency Ledger, OSS White-Label, FIDO2 Passkeys, OSV CVE Drift, OpenTofu IaC, MCP `2026-07-28` (**`155` tools, `-89.3%` core**, Async Tasks + 3 MCP Apps), 4-job Linux CI, and **65 integrated test suites**.
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
