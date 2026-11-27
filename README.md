<div align="center">

<img src="web/public/favicon.svg" alt="Culkibo Twin Planes K logo" width="84" height="84" />

# Culkibo

**The `51–55 MB`, Zero-Shell, AI-Native Self-Hosted PaaS (Open-Source Coolify & Dokploy Alternative)**
Deploy **140+ 1-Click Apps**, **12 Managed Databases**, **Sub-8ms Live Sync 2.0** (`1.32 ms` apply · `7.85 ms` E2E · `-96.1%` Brotli), **Post-MinIO S3 (Garage · RustFS · SeaweedFS + SigV4)**, **Zero-Dep Read-Only DB Studio**, **Agency Quotas & Billing Ledger**, **Open-Core White-Label Branding**, **Standard-Webhooks Bus + DLQ**, **Passkeys (FIDO2)**, **OSV CVE Scan**, **OpenTofu IaC**, **Web Terminal**, **WireGuard Mesh**, **Caddy PoW Shield**, **`0.115 ms` Micro-Wasm**, and **130 MCP Tools + Async Tasks + 3 Inline MCP Apps** for **Claude Code, Antigravity, Cursor, Windsurf & Codex** — on a single `51–55 MB` Node.js control plane with **6 runtime dependencies**, **50 test suites**, and **Caddy v2.11** atomic routing.

[![Release: v1.2.0](https://img.shields.io/badge/Release-v1.2.0-F59E0B.svg)](.github/workflows/release.yml)
[![Interactive Sandbox: Zero Install](https://img.shields.io/badge/Live%20Sandbox-Try%20in%2010s%20(%3Fdemo%3D1)-10B981.svg)](.github/workflows/demo-pages.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-2563EB.svg)](LICENSE)
[![CI: 4 Jobs | 50 Suites | Node 20/22/24 + Caddy + Playwright](https://img.shields.io/badge/CI-50%20Suites%20%7C%20Node%2020%2F22%2F24%20%7C%20Caddy%20%7C%20Playwright-16A34A.svg)](.github/workflows/ci.yml)
[![Idle RAM: 51–55 MB RSS](https://img.shields.io/badge/Idle%20RAM-51--55%20MB%20RSS-10B981.svg)](#benchmarks-and-reproducible-results)
[![Runtime Deps: 6 | SLSA v1.1 + CycloneDX 1.6](https://img.shields.io/badge/Runtime%20Deps-6%20%7C%20SLSA%20%2B%20SBOM-0F172A.svg)](scripts/release-provenance.js)
[![Zero Shell: Verified](https://img.shields.io/badge/Shell%20Construction-0%20(CI%20Verified)-0F172A.svg)](tests/shell-safety.test.js)
[![MCP 2026-07-28: 130 Tools + Tasks + 3 MCP Apps](https://img.shields.io/badge/MCP%202026--07--28-130%20Tools%20%7C%20Tasks%20%7C%203%20MCP%20Apps-7C3AED.svg)](#ai-agent-native-mcp-2026-07-28-tasks-and-mcp-apps)

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

Culkibo `v1.2.0` is an open-source **self-hosted PaaS** and **Coolify / Dokploy alternative** engineered for solo builders, agencies, platform teams, and AI coding agents. Instead of bolting a heavy PHP/Laravel or multi-container control stack on top of polling reverse proxies and shell scripts, Culkibo runs a single **51–55 MB RSS** daemon (`132.4 ms` cold boot, `9,693 req/s` authed Bearer+Brotli fast-path, `7,951 req/s` health) with **zero shell command construction**, atomic **Caddy v2.11** HTTP/3 ingress with **Native Edge Bot-Shield & Hashcash PoW**, **Post-MinIO S3 Storage Orchestrator (Garage · RustFS · SeaweedFS + Pure-Crypto SigV4)**, **Zero-Dep Read-Only Live DB Studio & Safe Redis Inspector**, **Agency Multi-Tenant Quotas & CSV-Formula-Safe Billing Ledger**, **Open-Core White-Label Brand & Custom Login Theme**, **Standard-Webhooks Outbound Bus + Dual-Secret Rotation + Anti-SSRF DLQ Replay**, **Zero-Dep WebAuthn Passkeys (FIDO2) & Ephemeral Secret Leases**, **OSV.dev SBOM CVE Drift Scanner**, **Live Config Drift Detector & PgBouncer Pool**, **Zero Lock-In OpenTofu/Compose IaC Exporter**, **Sub-8ms Live Sync 2.0**, **Zero-Dep Web Terminal**, **WireGuard Fleet Mesh**, **20-Pattern Auto-Healer**, **Shadow Replay**, **Time-Machine**, **Zero-Dep OTLP**, **Signed SLSA v1.1 + CycloneDX 1.6 SBOM**, **`0.115 ms` record warm Micro-Wasm** (`64 KiB` RAM), and the industry's first **MCP `2026-07-28` (`130` tools, `-85%+` core profile, Autonomous Triage, Async Tasks, Elicitation & inline `ui://culkibo/*` MCP Apps)** control plane — verified by a **milestone 50 integrated test suites**.

---

## Visual Showcase

Culkibo ships with a **Zero-Install Interactive Browser Sandbox (`?demo=1` / `npx culkibo demo`)**, **100% English & Spanish zero-dep localization** across every view (auto-detecting browser locale, defaulting to English globally), **Obsidian Dark Mode & Crisp Light Mode**, an **Open-Core White-Label Brand & Custom Login Theme Engine** (`GET/PUT /api/brand`), a **Pioneer Cockpit & Enterprise Security UI** (Read-Only Live DB Studio & Safe Redis Inspector, Post-MinIO Garage/RustFS/SeaweedFS S3 Presets + SigV4 Presigner, Agency Multi-Tenant Quotas & CSV-Safe Billing Ledger, Standard-Webhooks Dual-Secret & DLQ Replay, WebAuthn Passkeys FIDO2, Ephemeral Secret Leases & 15m Break-Glass, OSV.dev SBOM CVE Scanner, OpenTofu/Compose IaC Exporter, Live Config Drift Detector, Maintenance Windows & Public Incident Timeline + Geo-Failover, Zero-Dep Web Terminal, 20-Pattern Build Auto-Healer, WireGuard Fleet Mesh, Caddy PoW Shield, 24h Cron Heatmap & Heartbeats, SmartPack, Shadow Replay, Time-Machine, SLSA Ed25519 Verifier, `<1 ms` Micro-Wasm Tester, FinOps, DirectPush, EdgeTunnel, OTLP Drawer, and Coolify Streamer), and an interactive **Spatial SVG Topology Canvas** with click-to-link database env injection.

### Live Sync 2.0 (`1.32 ms` Apply · `7.85 ms` E2E) + Inline MCP Apps Flow

<p align="center">
  <img src="docs/assets/live-sync-demo.svg" alt="Animated Culkibo Live Sync 2.0 and inline MCP Apps topology flow showing sub-10ms Merkle delta apply, -96.1% Brotli compression, Server-Timing, and ui://culkibo/topology" width="100%" />
</p>

### Obsidian Dark Mode & Light Mode (100% Global EN / ES Dashboard)

| Obsidian Dark Mode (`1440×900`) | Crisp Light Mode (`1440×900`) |
| :---: | :---: |
| ![Culkibo English Obsidian Dark Mode dashboard with live RAM telemetry, onboarding checklist, and project cards](docs/assets/dashboard-dark-en.png) | ![Culkibo English Light Mode dashboard with project cards, search filters, and 1-click deploy controls](docs/assets/dashboard-light-en.png) |

### Spatial SVG Topology Canvas & Click-to-Link DB Injection (`Obsidian Dark`)

![Culkibo interactive Spatial SVG Topology Canvas in Obsidian Dark showing Domains, Projects, Managed Databases, animated directional edges, and Node Inspector with Link-to-Project DATABASE_URL injection](docs/assets/topology-dark-en.png)

### AI Agent Hub — MCP `2026-07-28`, `-85%+` Token Profiles & Interactive MCP Apps (`ui://culkibo/*`)

![Culkibo 100% English AI Agent Hub showing MCP tools, playbooks, core profile token savings, 1-click Antigravity/Claude/Cursor/Windsurf/Codex setup, and Interactive MCP Apps gallery](docs/assets/ai-agent-hub.png)

---

## Why Culkibo Is Architecturally Different

Traditional self-hosted PaaS platforms force a painful trade-off: burn 500 MB–1.5 GB of VPS RAM just to run the panel, wait 1–4 minutes per Docker rebuild while iterating with AI coding agents, paywall basic white-label & tenant features, and live with recurring shell-injection & IDOR CVEs. Culkibo fixes these problems at the architecture layer:

### 1. Zero-Shell Engine (`shell: false`), FIDO2 Passkeys, OSV CVE Drift, SLSA v1.1 & Full CVE Immunity
- Every subprocess (`docker`, `git`, `caddy`, `ssh`, `cron`, `exec`, `npm`) is invoked through `spawn()` / `execFile()` with tokenized `argv` arrays validated by [`safeCommand.js`](server/services/safeCommand.js) and `shell: false`. Secrets travel exclusively via ephemeral `0600` `--env-file` descriptors or `GIT_ASKPASS` — statically verified on every commit by [`tests/shell-safety.test.js`](tests/shell-safety.test.js).
- **Zero-Dep WebAuthn Passkeys (FIDO2) & Ephemeral Secret Leases (`server/services/passkeyService.js`, `server/services/secretLeaseService.js`):** Pure-JS RFC 8949 CBOR/COSE decoder + native `node:crypto` ES256 (`alg:-7`) & Ed25519 (`alg:-8`) Passkey authentication with `rpIdHash`, origin & monotonic `signCount` checks — paired with Vault-class time-bounded secret leases, 90-day rotation alerts, audited 15-minute Break-Glass tokens, and TOTP brute-force lockout (`<= 5` failures → 15m lockout).
- **Runtime SBOM CVE Drift Scanner (`server/services/cveDriftService.js` · `culkibo cve-scan` + MCP `culkibo_cve_scan`):** Batches Culkibo's CycloneDX 1.6 PURLs against the live **OSV.dev Batch API** (`api.osv.dev/v1/querybatch`) with 24h local caching and deterministic offline fallback to surface newly disclosed CVEs on already-deployed releases.
- **By-Design Immunity to Real-World PaaS CVEs & Shifts ([`docs/COMPETITOR_RADAR_CYCLE6.md`](docs/COMPETITOR_RADAR_CYCLE6.md) · [`docs/COMPETITOR_RADAR_CYCLE7.md`](docs/COMPETITOR_RADAR_CYCLE7.md) · [`docs/COMPETITOR_RADAR_CYCLE8.md`](docs/COMPETITOR_RADAR_CYCLE8.md)):** Immune to Dokploy **`CVE-2026-116068` / `CVE-2026-127212`** (cross-tenant IDORs blocked by strict project/tenant ACL isolation), **`CVE-2026-24841`** (unsafe DB studio blocked by lexical read-only gate), **`CVE-2026-129433`** (DB/backup shell injection), **`CVE-2026-129315`** (`chmod 700` data dirs), **`CVE-2026-133520`** & Runtipi **`CVE-2026-47277`** (`fs.realpathSync` traversal guard), Portainer **`CVE-2026-134756`** (per-attempt DNS-resolved outbound webhook SSRF guard), Dokku **`CVE-2026-54636`**, **`kamal#1709/#1856/#1790`**, **`uptime-kuma#7704/#8193/#6519`**, and the **2025–2026 MinIO community archiving** via built-in Garage / RustFS / SeaweedFS S3 presets.
- **Zero-Dep SLSA Provenance v1.1 Ed25519 DSSE ([`supplyChainAttestor.js`](server/services/supplyChainAttestor.js) · `culkibo verify`) & CycloneDX 1.6 SBOM ([`release-provenance.js`](scripts/release-provenance.js)):** Signs every Citadel & GitHub Release as an in-toto `Statement/v1` DSSE envelope alongside `GET /api/system/sbom`, `CHECKSUMS.sha256`, `release.slsa.dsse.json`, and `attestation-public-key.pem` via [`.github/workflows/release.yml`](.github/workflows/release.yml).

### 2. `51–55 MB` Idle RAM, `9,693 req/s` Fast-Path, Agency Quotas, White-Label & Standard-Webhooks Bus
- **Measured live (independent QA):** **51–55 MB RSS** idle daemon (`<= 60 MB` invariant across 67+ services), **0% idle CPU**, **132.4 ms** cold boot, **9,693 req/s** authenticated Bearer+Brotli fast-path (`p50 2.31 ms`, `p99 3.91 ms`, `Server-Timing: cp;dur=0.02`), and **7,951 req/s** health (`p50 2.68 ms`) — fitting comfortably on a **$4/mo 512 MB–1 GB VPS**.
- **Minimal supply-chain blast radius:** Exactly **6** root npm runtime dependencies ([`package.json`](package.json): `express`, `ws`, `chokidar`, `commander`, `cors`, `dotenv`) and **0** dependencies in [`telemetry-collector/`](telemetry-collector/README.md) — enforced across Node `20`, `22`, and `24` in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
- **Agency Multi-Tenant Quotas & CSV-Formula-Safe Billing Usage Ledger (`server/services/quotaMeteringService.js` · `culkibo ledger --csv`):** Enforces per-project CPU, RAM, storage & bandwidth caps and exports client-billable JSON & formula-safe CSV (`=+-@` escaped) usage ledgers with strict tenant ACL isolation (`Dokploy CVE-2026-116068`/`127212` immune).
- **Open-Core White-Label Brand & Custom Login Theme (`server/services/brandThemeService.js` · `GET/PUT /api/brand`):** Answers `coolify#1744` and Dokploy's Enterprise branding paywall directly in Apache-2.0 Community Edition — customize workspace name, tagline, accent hex, and XSS-sanitized logo (`javascript:`/`<script>`/`on*=` stripped).
- **Standard-Webhooks Outbound Event Bus + Dual-Secret Rotation + Anti-SSRF DLQ Replay (`server/services/webhookEventBus.js`):** Full `standard-webhooks` (`webhook-id`/`webhook-timestamp`/`webhook-signature` `v1,<b64>`, base64 `whsec_`) with zero-downtime dual-secret rotation, jittered backoff, persisted 500-item DLQ with deterministic replay, and per-attempt DNS-resolved SSRF checks (`Portainer CVE-2026-134756` immune).
- **Zero-Dep OTLP/HTTP JSON ([`otlpExporter.js`](server/services/otlpExporter.js)), FinOps (`finopsOptimizer.js`), Cron Heatmap & Maintenance Windows ([`cronManager.js`](server/services/cronManager.js), [`uptimeMonitor.js`](server/services/uptimeMonitor.js)):** Native gzip OTLP traces/metrics to Grafana Tempo/SigNoz/Honeycomb, cloud savings calculator, 24h cron collision heatmap + Healthchecks.io-style `/api/heartbeat/:token`, live-evaluated Maintenance Windows, public Incident Timelines, and Active-Passive Cloudflare DNS Geo-Failover plans.

### 3. Sub-8ms Live Sync 2.0, Read-Only DB Studio, Web Terminal, Auto-Healer & `0.115 ms` Micro-Wasm
When coding with Claude Code, Antigravity, Cursor, or Windsurf, waiting 2–4 minutes per push destroys flow:

```text
Traditional PaaS:  save file -> git commit -> push -> webhook -> Docker rebuild (1-4 min) -> check
Culkibo Forge:     save file -> binary Commit Frame (/ws/sync, Brotli -96.1%) -> 1.32 ms apply / 7.85 ms E2E
Culkibo Citadel:   env edit  -> Fast Restart (~1.5 s) OR BuildKit -> Auto-Healer / Shadow Replay -> Caddy cutover
```

- **Adaptive binary framing (`0x02` Brotli / `0x03` Gzip):** `-96.1%` wire reduction on 100-file TSX bursts, SHA-256 LRU deduplication, chunked transfers (`<=100 MB` with SHA-256 check), **Merkle Tree** verification, and **in-memory time-travel patch rollback (`1.91 ms p50`)**.
- **Zero-Dep Read-Only Live DB Studio & Safe Redis/Valkey Inspector (`server/services/dbStudioService.js` · MCP `culkibo_db_studio`):** Zero-sidecar SQL/Redis studio replacing bloated Adminer containers — strips `--`/`/* */` comments before keyword scanning, blocks stacked `;`, DDL/DML, `COPY` & `psql \!`, wraps every query in `BEGIN TRANSACTION READ ONLY` + `5s` timeout + `LIMIT 200`, diagnoses Postgres table bloat & `EXPLAIN (FORMAT JSON)`, and runs safe Redis `SCAN`/`TYPE`/`TTL`/`INFO` (blocking `KEYS *`/`FLUSHALL`/`EVAL`/`CONFIG`).
- **Zero-Dep Interactive Container Web Terminal (`server/services/containerTerminalService.js`):** Direct Docker Engine Unix/TCP hijack over `/ws/terminal` with RBAC `runtime:exec`, single-use ticket, and 15-minute idle cap — **zero `node-pty` native addons**, plus an interactive simulated shell inside the `?demo=1` Sandbox.
- **20-Pattern Deterministic Build Auto-Healer (`culkibo heal`) & Live Config Drift Detector (`kamal#1790` + PgBouncer Pool):** Diagnoses 20 failure classes (Node OOM, `127.0.0.1` binds, lockfile drift, `kamal#1709`, Postgres `pg_wal` bloat) with dry-run patches, diffs live `docker inspect` vs declared state, and ships a managed **PgBouncer Smart Pool preset** (`max_prepared_statements=200`).
- **Shadow Traffic Replay Gate, Whole-Stack Time-Machine (`culkibo timemachine`) & Runtime-Only Fast Restart (`~1.5 s`):** Automatic **`PROMOTE`** / **`BLOCK_CUTOVER`** cutover verdicts, SHA-256 whole-stack snapshots (`diff`, `dryRun`, atomic rollback), and zero-rebuild env updates.
- **`0.115 ms` Record Warm Micro-Wasm Edge Runtime ([`wasmMicroRunner.js`](server/services/wasmMicroRunner.js)):** Sandboxed WebAssembly in isolated `worker_threads` — live-measured at **`0.115 ms` warm p50**, **`0.162 ms` p95**, **`0.499 ms` cold**, and **`64 KiB` RAM** (zero host filesystem/network access).
- **Honest scope:** Live Sync 2.0 accelerates incremental code/asset iteration (*Path B*). Dependency or `Dockerfile` changes run full immutable Docker BuildKit builds (*Path C*) with smoke tests, shadow replay gates, and multi-release rollback.

### 4. World-First PaaS MCP Apps (`ui://culkibo/*`), Autonomous Triage, Async Tasks & Elicitation (`MCP 2026-07-28`)
- **130 Tools, 13 Playbook Prompts & 10 Resources** over Streamable HTTP (`POST /api/mcp`) and stdio (`culkibo mcp`) with legacy SSE fallback — verified end-to-end against a real spawned stdio JSON-RPC client ([`tests/release-and-mcp-e2e.test.js`](tests/release-and-mcp-e2e.test.js)), including **`culkibo_triage_playbook`** (1-call autonomous triage), `culkibo_db_studio`, `culkibo_s3_storage`, `culkibo_agency_ledger`, `culkibo_brand_theme`, `culkibo_cve_scan`, `culkibo_drift_check`, `culkibo_export_iac`, `culkibo_secret_lease`, `culkibo_heal_build_failure`, `culkibo_fleet_mesh`, `culkibo_cron_timeline`, `culkibo_edge_shield`, `culkibo_shadow_replay`, `culkibo_time_machine`, and `culkibo_finops_report`.
- **Official MCP `2026-07-28` Async Tasks (`io.modelcontextprotocol/tasks`) & Elicitation (`elicitation/create`):** Long-running Docker builds, Coolify migrations, and DR drills run non-blocking via `tasks/list`, `tasks/get`, `tasks/result`, and `tasks/cancel` with strict cross-tenant RBAC isolation — and declare structured JSON Schema `elicitation` prompts for missing secrets or deployment approvals.
- **5 Context-Saving Profiles (`?profile=core|deploy|ops|security|all` & `CULKIBO_MCP_PROFILE`):** `?profile=core` serves the 17 essential tools (`17 / 130`) and cuts LLM tool-schema context by **`-85%+`** while `culkibo_search_tools` discovers any of the remaining 130 tools on demand.
- **Interactive Inline MCP Apps (`modelcontextprotocol/ext-apps` `2026-01-26`):** Serves 3 sandboxed interactive HTML apps (`ui://culkibo/topology`, `ui://culkibo/incident-remediator`, `ui://culkibo/coolify-migration-diff`) with locked-down `_meta.ui.csp` (`default-src 'none'`), zero external URLs, XSS-safe JSON injection, and `postMessage` JSON-RPC bridges so compliant AI hosts render live visual cards inline inside chat.

### 5. Post-MinIO S3 Storage, Zero Lock-In OpenTofu IaC, WireGuard Mesh, DirectPush & Caddy PoW Shield
- **Post-MinIO S3 Storage Orchestrator & Pure-Crypto AWS SigV4 Presigner (`server/services/objectStorageService.js` · `culkibo s3-presets` + MCP `culkibo_s3_storage`):** Built for the post-MinIO era (following MinIO's 2025–2026 console removal & community archiving) — 1-click pinned **Garage (`dxflrs/garage`)**, **RustFS (`rustfs/rustfs`)**, and **SeaweedFS** S3 presets, pure `node:crypto` AWS SigV4 query-string presigned URLs (`UNSIGNED-PAYLOAD`, `60..604800s`), and declarative S3 Bucket CORS & Lifecycle XML builders.
- **Zero Lock-In OpenTofu/Terraform HCL + Portable Compose IaC Exporter (`server/services/iacExporter.js` · `culkibo export-iac`):** Export your entire Culkibo estate anytime as clean `main.tf`, `variables.tf`, `docker-compose.yml`, and `.env.example` using `${var.*}` placeholders (**0 plaintext secrets**).
- **Culkibo SmartPack ([`smartPackBuilder.js`](server/services/smartPackBuilder.js) · `culkibo smartpack`) & DirectPush ([`directPushRegistry.js`](server/services/directPushRegistry.js) · `culkibo pussh`):** Detects **18 stacks** with BuildKit 1.7 cache mounts + host-aware cgroup caps (`zstd:chunked`), and pushes missing SHA-256 OCI v2 layers directly over Culkibo's zero-shell SSH tunnels with **zero Docker Hub / GHCR required**.
- **Zero-Config WireGuard Fleet Mesh (`culkibo mesh`) & Sovereign EdgeTunnel ([`edgeTunnelService.js`](server/services/edgeTunnelService.js) · `culkibo tunnel-agent`):** Native Node `x25519` AES-256-GCM encrypted `10.88.0.0/24` L3 overlay + `kamal#1856` UFW DB-bypass audits, paired with zero-dep `ET1` CGNAT outbound tunnels AND 1-click Cloudflare Tunnels.
- **Caddy Native Edge Bot-Shield, Hashcash PoW Gate & 6-Day `shortlived` ACME (`server/services/edgeShieldService.js`, [`ingressManager.js`](server/services/ingressManager.js), [`caddyManager.js`](server/services/caddyManager.js)):** Zero-plugin Caddy v2.11 scanner/AI-scraper matchers + Anubis-inspired SHA-256 PoW cookie gate (`ckb_shield`), full multi-CAA pre-flight (`uptime-kuma#6519`), Let's Encrypt GA **6-day `shortlived` ACME** profile + ECH QUIC probe, per-domain TLS fault isolation, HTTP/3, RFC 8297 `103 Early Hints`, and **7-provider DNS-01 Wildcard TLS**.

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
| **Control-Plane RAM Footprint** | **51–55 MB RSS** *(~70 MB w/ Caddy, measured)* | ~800 MB – 1.5 GB *(2 GB VPS min)* | ~450 – 800 MB *(1–2 GB VPS)* | ~150 – 300 MB *(300–450 MB w/ Swarm)* | 0 MB panel *(+15–25 MB proxy)* | ~100 – 200 MB *(external proxy)* |
| **Zero-Shell, OSV CVE Drift & SLSA v1.1** | ✅ **`0` shell · OSV SBOM Scan · SLSA v1.1 DSSE** | ❌ PHP shell | ❌ Child shell | ⚠️ Swarm CLI | ⚠️ SSH shell | ✅ Docker API |
| **Reverse Proxy, PoW Shield & 6d ACME** | **Caddy v2.11** *(HTTP/3, PoW Shield, Multi-CAA, 6d ACME)* | Traefik *(2,000 ms throttle)* | Traefik / Swarm | Nginx reload | `kamal-proxy` *(<1 ms swap)* | ❌ External |
| **Live Sync 2.0 + Fast Env Restart** | ✅ **`1.32 ms` apply · `7.85 ms` E2E · zero-rebuild env** | ❌ Full rebuild | ❌ Full rebuild | ❌ Image build | ❌ Image build | ❌ |
| **Read-Only DB Studio + Post-MinIO S3** | ✅ **Safe SQL/Redis Studio · Garage/RustFS/SeaweedFS + SigV4** | ⚠️ Adminer / MinIO | ⚠️ Adminer / MinIO | ❌ | ❌ | ❌ |
| **Web Terminal + Auto-Healer + Config Drift** | ✅ **Docker hijack `/ws/terminal` · `culkibo heal` · Drift + PgBouncer** | ⚠️ PTY dep | ⚠️ PTY dep | ❌ | ❌ | ✅ Exec UI |
| **Agency Quotas, Ledger & White-Label** | ✅ **Tenant Quotas · CSV-safe Ledger · OSS White-Label (`#1744`)** | ❌ *(`#1744` open)* | 💰 Enterprise paywall | ❌ | ❌ | 💰 Business |
| **Standard-Webhooks Bus + OpenTofu IaC** | ✅ **Dual-secret `whsec_` + Anti-SSRF DLQ · `.tf`/Compose export** | ❌ | ❌ | ❌ | ❌ | ❌ |
| **AI-Agent Native MCP + Triage + MCP Apps** | ✅ **130 tools · `triage_playbook` · Tasks · 3 `ui://` Apps · `-85%+`** | ❌ *(3rd-party)* | ❌ *(3rd-party)* | ❌ | ❌ | ❌ |
| **SmartPack + DirectPush + WireGuard Mesh** | ✅ **18 stacks · `culkibo pussh` · Native `x25519` Mesh · `ET1`** | ⚠️ Nixpacks | ⚠️ Nixpacks | ⚠️ Buildpacks | ❌ Registry req. | ❌ |
| **Shadow Replay, Time-Machine & `0.115 ms` Wasm** | ✅ **Auto `PROMOTE`/`BLOCK` · SHA-256 restore · Micro-Wasm** | ❌ | ❌ | ❌ | ❌ | ❌ |
| **OTLP + FinOps + Status Maintenance & Heartbeats** | ✅ **Zero-dep OTLP · FinOps · Heartbeats · Maintenance · Geo-Failover** | ❌ External | ❌ External | ❌ | ⚠️ Manual hook | ❌ |
| **1-Click App Catalog & Managed DBs** | ✅ **140 pinned apps · 12 DBs · PgBouncer · SnapStream · PR DBs** | ✅ Extensive | ✅ Extensive | ✅ One-click | ❌ Manual | ⚠️ Templates |
| **FIDO2 Passkeys + Secret Leases + Teams RBAC** | ✅ **Zero-dep Passkeys · Leases/Break-Glass · 4-role RBAC · 2FA · OIDC** | ⚠️ Coarse teams | ⚠️ Basic | ❌ | ❌ | ⚠️ Paid Business |
| **1-Click Coolify v4 Migration + GitOps** | ✅ **Magic Vars + Traefik→Caddy + `culkibo.yaml` + Auto-Sleep** | — | ❌ | ❌ | ✅ `deploy.yml` | ⚠️ Git stacks |

---

## Benchmarks and Reproducible Results

Every Culkibo metric below comes from real code independently measured on `Node v24.14.0` (`win32/x64`, uncontended run) with **zero synthetic delays and zero subtracted overhead**. Reproduce the complete suite or generate a Markdown/JSON comparison report on your own machine:

```bash
node bench/run-all.bench.js
node bench/competitor-comparison.bench.js --markdown
```

### Independently Verified Live Performance Results (`v1.2.0` Record Run)

| Metric | Live Measured Result | Notes & Verification Command |
| :--- | :--- | :--- |
| **Idle Daemon RAM / CPU** | **51–55 MB RSS · 0% CPU** | Measured across 67+ lazy-loaded services (`<= 60 MB` invariant) |
| **Cold Boot Time** (`CULKIBO_SKIP_RECONCILE=1`) | **132.4 ms** | Measured via `process.hrtime.bigint()` (`npm run bench:control`) |
| **Authenticated Fast-Path (Bearer + Brotli, 500 req / 25w)** | **9,693 req/s** *(p50 `2.31 ms` · p99 `3.91 ms`)* | HMAC-SHA256 LRU cache + WeakMap zero-copy Brotli + `Server-Timing: cp;dur=0.02` |
| **Health HTTP (`GET /api/health`, 500 req / 25w)** | **7,951 req/s** *(p50 `2.68 ms`)* | Pre-compiled O(1) fast-path route map |
| **Mixed Uncompressed / RBAC Express HTTP (500 req / 25w)** | **3,566 req/s** mixed · **2,275 req/s** RBAC | `0` failures (`bench/control-plane.bench.js` & `bench/subsystems.bench.js`) |
| **Catalog Load (`GET /api/catalog`, 140 apps)** | **warm p50 `0.68 ms`** | `129.6 KB` → `34.5 KB` Brotli (**-73.4%**) |
| **Live Sync 2.0 (Path B Incremental Sync)** | **server apply p50 `1.32 ms` · E2E p50 `7.85 ms` (sub-8ms!)** | 100-file TSX burst Brotli **-96.1%** (`25.66×`) · in-memory rollback **p50 `1.91 ms`** |
| **Isolated Micro-Wasm Edge Runtime (Record)** | **warm p50 `0.115 ms` · p95 `0.162 ms` · `64 KiB` RAM** | Cold `0.499 ms` · verified via `bench/competitor-comparison.bench.js` & [`tests/migrations-and-wasm.test.js`](tests/migrations-and-wasm.test.js) |
| **WebSocket 40-Client Fan-Out** | **51.9 ms** (`40/40` initial state delivered) | Zero drops under concurrent churn (`tests/websocket-stress.test.js`) |
| **Caddy v2.11 Atomic Route Swap** | **Synchronous zero-poll Admin API** | Verified live in Linux CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml) `live-caddy-e2e`) & `npm run bench` |
| **MCP `2026-07-28` `?profile=core` Savings** | **-85%+ schema tokens** (`17 / 130` tools) | Verified via `bench/competitor-comparison.bench.js` + external stdio E2E |
| **Supply-Chain, Shell Safety & Milestone Suite** | **6 root deps · 0 collector deps · 0 shell calls · 50 suites** | Verified in CI + Signed `release.slsa.dsse.json` + OSV.dev CycloneDX 1.6 SBOM |

---

## Architecture

Culkibo separates rapid developer/AI iteration (**The Forge**) from immutable production releases (**The Citadel**) on a single lightweight control plane:

```mermaid
flowchart LR
    Dev["Developer & AI Agents (Claude Code / Antigravity / Cursor)"]
    UI["Web Dashboard (EN/ES · White-Label · Passkeys · DB Studio · ?demo=1)"]
    MCP["MCP 2026-07-28 (130 Tools, Triage Playbook, Tasks, 3 ui:// Apps)"]
    Sync["Live Sync 2.0 (/ws/sync 1.32 ms Apply · 7.85 ms E2E)"]
    CP["Culkibo Control Plane (Node.js 51-55 MB RSS, 6 Deps, shell:false)"]
    Forge["The Forge (Hot Dev + /ws/terminal + Auto-Healer + Drift Check)"]
    Citadel["The Citadel (SmartPack + Shadow Replay + Time-Machine + OpenTofu IaC + SLSA)"]
    Caddy["Caddy v2.11 Edge (HTTP/3, PoW Shield, 6d ACME, WireGuard Mesh, 0.115 ms Wasm)"]
    Obs["Zero-Dep OTLP + OSV CVE + Standard-Webhooks DLQ + Agency Ledger & FinOps"]
    Data["12 DBs + Read-Only DB Studio + Post-MinIO S3 (Garage/RustFS) + Secret Leases"]

    Dev -->|"Streamable HTTP / stdio"| MCP
    Dev -->|"Commit Frames"| Sync
    Dev --> UI
    UI -->|"O(1) Fast-Path + FIDO2/RBAC"| CP
    MCP --> CP
    Sync --> Forge
    CP --> Forge
    CP --> Citadel
    CP -->|"Atomic JSON Admin API"| Caddy
    CP -->|"gzip OTLP / Standard-Webhooks"| Obs
    Citadel --> Data
    Caddy -->|"Zero-Downtime Route Swap"| Citadel
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
node bin/culkibo.js sync <projectId> .               # Start Live Sync 2.0 (1.32 ms apply)
node bin/culkibo.js deploy <projectId>               # Immutable BuildKit deploy + Shadow Replay + SLSA
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

Culkibo is built from day one for autonomous and human-in-the-loop AI coding workflows — shipping **130 tools** (including 1-call `culkibo_triage_playbook`, `culkibo_db_studio`, `culkibo_s3_storage`, `culkibo_agency_ledger`, `culkibo_brand_theme`), **13 playbooks**, official **MCP `2026-07-28` Async Tasks (`io.modelcontextprotocol/tasks`)**, **Elicitation (`elicitation/create`)**, and the first **`modelcontextprotocol/ext-apps` (`2026-01-26`)** interactive UI resources in any self-hosted PaaS.

### 1-Click Agent Kit Generator

Generate drop-in MCP configs (defaulting to `?profile=core` for **-85%+ token savings** across `17 / 130` tools and using `${CULKIBO_TOKEN}` env placeholders — never plaintext secrets):

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

Culkibo ships a **milestone 50 integrated test suites** in `tests/run-all.js` (including Standard-Webhooks Dual-Secret + Anti-SSRF DLQ Replay, Post-MinIO Garage/RustFS/SeaweedFS S3 + Pure-Crypto SigV4, Zero-Dep Read-Only Live DB Studio + Safe Redis Inspector, Agency Multi-Tenant Quotas + CSV-Safe Ledger, Open-Core White-Label Brand Engine, WebAuthn Passkeys FIDO2 + Secret Leases + OSV.dev CVE Drift, Live Config Drift + PgBouncer + OpenTofu IaC Export, Maintenance Windows + Multi-CAA + 6-Day ACME + Geo-Failover, Mock-Coolify v4 E2E Estate Replay, real external MCP stdio protocol E2E, OTLP/SLSA attestation E2E, Atomic DB Migrations + `0.115 ms` Micro-Wasm E2E, Shadow Replay Gate, Whole-Stack Time-Machine + Cloud FinOps, Zero-Dep Web Terminal, WireGuard Fleet Mesh, Caddy PoW Bot-Shield, 20-Pattern Auto-Healer, and 24h Cron Heatmap & Heartbeats) + standalone live-server, WebSocket churn, HTTP stress, and zero-dep telemetry collector suites — verified continuously on Linux by [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (`4` jobs: Node 20/22/24 matrix + Live Caddy v2.11 + Docker BuildKit SmartPack & SBOM E2E + Playwright Desktop/Mobile visual QA), released with signed SLSA v1.1 + CycloneDX 1.6 via [`.github/workflows/release.yml`](.github/workflows/release.yml), and published as a zero-install sandbox via [`.github/workflows/demo-pages.yml`](.github/workflows/demo-pages.yml):

```bash
node tests/shell-safety.test.js                       # Static AST/source check: 0 shell calls
npm run typecheck                                     # Server TypeScript checkJs (0 errors)
npx tsc -p web/tsconfig.app.json --noEmit             # Frontend TypeScript check (0 errors)
npx --prefix web oxlint --deny-warnings               # oxlint React 19 + Compiler rules (0 warnings)
npm run web:build                                     # Vite production build + .br/.gz precompression
npm test                                              # 50 suites + live-server + WS stress + HTTP stress
node --test telemetry-collector/test/collector.test.js  # Zero-dep telemetry collector suite
npm run release:sbom -- --out-dir dist-release --sign --verify  # Signed SLSA v1.1 + CycloneDX 1.6 SBOM
```

### Repository Layout

```text
.github/workflows/ci.yml         Active 4-job Linux CI (Node 20/22/24, Live Caddy, BuildKit SmartPack/SBOM, Playwright)
.github/workflows/release.yml    Automated v* GitHub Release workflow (Signed SLSA v1.1 DSSE + CycloneDX 1.6 SBOM)
.github/workflows/demo-pages.yml Zero-Install Interactive Browser Sandbox workflow (GitHub Pages ?demo=1)
bin/culkibo.js                   CLI (demo, init, up, sync, deploy, heal, mesh, s3-presets, ledger, cve-scan, export-iac, mcp...)
scripts/release-provenance.js    Zero-dep CycloneDX 1.6 SBOM, SHA-256 checksums & Ed25519 SLSA DSSE signer
server/
  index.js                       O(1) fast-path HTTP daemon, Server-Timing, Brotli cache, /ws/terminal & /ws/sync
  middleware/auth.js             Constant-time tokens, RBAC middleware, single-use WS tickets, rate limits
  routes/api.js                  REST API (brand, webhooks/dlq, db-studio, storage, billing, passkeys, cve-scan, iac, MCP)
  services/                      67+ zero-shell services (webhookEventBus, dbStudioService, objectStorageService,
                                 quotaMeteringService, brandThemeService, passkeyService, secretLeaseService,
                                 cveDriftService, driftDetectorService, iacExporter, containerTerminalService,
                                 fleetMeshService, edgeShieldService, buildHealerService, liveSyncEngine, cronManager,
                                 uptimeMonitor, shadowReplayService, timeMachineService, finopsOptimizer,
                                 smartPackBuilder, directPushRegistry, edgeTunnelService, sqliteStreamBackup,
                                 otlpExporter, supplyChainAttestor, migrationRunner, wasmMicroRunner, mcpAppsRenderer,
                                 mcpServer, caddyManager, ingressManager, coolifyMigrator, bundleArchiver,
                                 serverFleetManager, teamManager, editionService, databaseManager, catalog [140 apps]...)
telemetry-collector/             Zero-dep anonymous telemetry collector (node:sqlite WAL + CF Workers/D1)
web/src/                         React 19 + Tailwind v4 dashboard (100% EN/ES, White-Label, ?demo=1 Sandbox, Pioneer Cockpit)
bench/                           Reproducible live benchmarks (control-plane, live-sync, route-swap, subsystems)
scripts/                         Hardened Debian/Ubuntu VPS installer (chmod 700), uninstaller, systemd test & SBOM signer
tests/                           50 integrated + 4 standalone verification, E2E, security, fuzz & stress suites
docs/                            MIGRATION_GUIDE.md, GITHUB_SEO_LAUNCH_KIT.md, COMPETITOR_RADAR_CYCLE{6,7,8}.md, EVOLUTION_LOG.md, assets/
```

---

## Privacy and Transparent Telemetry

Culkibo includes opt-out anonymous crash/health telemetry scrubbed through an **11-phase PII sanitizer** (never collects secrets, domains, IPs, repo names, or payloads). Inspect the exact JSON envelope anytime (`node bin/culkibo.js telemetry preview`) or disable it instantly via `CULKIBO_TELEMETRY=0`, `DO_NOT_TRACK=1`, CLI (`telemetry disable`), or Settings. Full specification in [`PRIVACY.md`](PRIVACY.md) and [`telemetry-collector/README.md`](telemetry-collector/README.md).

---

## Ethical Open-Core and Community Roadmap

### Our Open-Core Promise (Enforced in [`editionService.js`](server/services/editionService.js))

- **Community Edition (`Apache-2.0`, Free Forever):** **100% of self-hosted core power with ZERO artificial limits** — unlimited projects, 12 databases + PgBouncer pool + Read-Only Live DB Studio & Safe Redis Inspector, Post-MinIO S3 Storage (Garage · RustFS · SeaweedFS + Pure-Crypto SigV4), 140 catalog apps, Agency Multi-Tenant Quotas & CSV-Formula-Safe Billing Ledger, Open-Core White-Label Brand & Custom Login Theme (`GET/PUT /api/brand`), Standard-Webhooks Outbound Event Bus + Dual-Secret Rotation + Anti-SSRF DLQ Replay, Live Sync 2.0, Zero-Dep WebAuthn Passkeys (FIDO2), Ephemeral Secret Leases & 15m Break-Glass, OSV.dev Runtime SBOM CVE Drift Scanner, Live Config Drift Detector, Zero Lock-In OpenTofu/Compose IaC Exporter, Public Maintenance Windows + Incident Timeline + Geo-Failover + 6-Day `shortlived` ACME, Zero-Dep Container Web Terminal, Zero-Config WireGuard Fleet Mesh, 24h Cron Heatmap & Heartbeats, Caddy Edge Bot-Shield & PoW Gate, 20-Pattern Build Auto-Healer, Shadow Replay Gate, Whole-Stack Time-Machine, Cloud FinOps Optimizer, SmartPack, DirectPush, Sovereign EdgeTunnel, Zero-Dep OTLP, SLSA v1.1 Attestations, CycloneDX 1.6 SBOM, Atomic DB Migrations, `0.115 ms` Micro-Wasm, SnapStream, PR DB/Schema Isolation, Multi-Server SSH Fleet, Teams & 4-role RBAC, TOTP 2FA (rate-limited), OIDC SSO (`groups` + JWKS SWR), GitOps `culkibo.yaml`, 130-tool MCP Server + Autonomous Triage + Async Tasks + 3 MCP Apps, AES-256-GCM S3 DR Backups, and Auto-Sleep Scale-to-Zero. **Zero phone-home.**
- **Optional Commercial Packs (`Pro` / `Enterprise` / `Cloud`):** Verified **100% offline via Ed25519 signed keys (`CKL1.*`)** — strictly for organizational scale & compliance: Managed Multi-Region Relay, Extended Status/Email White-Label Packs, Priority Support Bundles, Enterprise SCIM 2.0 / SAML 2.0, SOC2/ISO-27001 Signed Compliance Exports, and Managed Multi-AZ Cloud Control Plane.

### Public Engineering Roadmap (Zero New Runtime Deps)

- [x] **v1.0 – v1.1 (Shipped):** `51–55 MB RSS` fast-path + `Server-Timing`, 140 pinned catalog apps, 12 DB engines, Sub-8ms Live Sync 2.0, SmartPack (18 stacks), DirectPush (`culkibo pussh`), Sovereign EdgeTunnel (`ET1`), World-First PaaS MCP Apps (`ui://culkibo/*`), SnapStream WAL-to-S3 + PR Preview DB Branching, Runtime-Only Fast Restart, OIDC `groups`→RBAC, and Offline Ed25519 Open-Core editions.
- [x] **v1.2.0 (Shipped):** Zero-Install Browser Sandbox (`?demo=1` GitHub Pages + `npx culkibo demo`), 100% EN/ES Global UI + Open-Core White-Label Brand & Custom Login Theme, Post-MinIO S3 Storage Orchestrator (Garage · RustFS · SeaweedFS + Pure-Crypto SigV4), Zero-Dep Read-Only Live DB Studio & Safe Redis Inspector, Agency Multi-Tenant Quotas & CSV-Formula-Safe Billing Ledger, Standard-Webhooks Outbound Event Bus + Dual-Secret Rotation + Anti-SSRF DLQ Replay, Zero-Dep WebAuthn Passkeys FIDO2, Ephemeral Secret Leases & 15m Break-Glass, OSV.dev SBOM CVE Drift Scanner, Live Config Drift Detector + PgBouncer Smart Pool, Public Maintenance Windows + Incident Timeline + Multi-CAA + 6-Day `shortlived` ACME & DNS Geo-Failover, Zero Lock-In OpenTofu/Compose IaC Exporter, Zero-Dep Web Terminal, 20-Pattern Build Auto-Healer, WireGuard Fleet Mesh, Caddy Edge Bot-Shield & PoW Gate, 24h Cron Heatmap & Heartbeats, Shadow Replay, Whole-Stack Time-Machine, Cloud FinOps, OTLP, Signed SLSA v1.1 + CycloneDX 1.6 SBOM, MCP `2026-07-28` (**`130` tools, `-85%+` core**, Autonomous Triage, Async Tasks + `elicitation/create`), record **`0.115 ms` warm Micro-Wasm** (`64 KiB` RAM), full Cycle 6–9 CVE immunity (`CVE-2026-116068`/`127212`/`24841`/`134756`/`129433`/`129315`/`133520`/`47277`/`54636`), 4-job Linux CI, and **milestone 50 integrated test suites**.
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
