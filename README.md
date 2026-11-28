<div align="center">

<img src="web/public/favicon.svg" alt="Culkibo Twin Planes K logo" width="84" height="84" />

# Culkibo

**The `50 MB`, `11,382 req/s`, Zero-Shell, AI-Native Self-Hosted PaaS (Open-Source Coolify & Dokploy Alternative)**
Deploy **140+ 1-Click Apps**, **12 Managed Databases**, **React2Shell SSR & CSRF/PKCE Guards**, **Docker Hub `429` Registry Mirror**, **SQLite WAL/NFS & `/run/secrets/` Guards**, **JWT/OIDC & Zip-Slip Firewalls**, **Sub-ms Live Sync 2.0 (`0.99 ms`)**, **`33–36 µs` Micro-Wasm**, and **200 MCP Tools (`-93.5%` / `~94%` core) + Async Tasks + 3 Inline MCP Apps** for **Claude Code, Antigravity, Cursor, Windsurf & Codex** — on a single **`50 MB`** Node.js control plane (`126.2 ms` boot, `11,382 req/s`, `14,772 writes/s` JSON, `1.52 GB/s` SHA-256, `~370 kB` lazy prod bundle) with **6 runtime dependencies**, **92 test suites**, and **Caddy v2.11** atomic routing.

[![Release: v1.2.0](https://img.shields.io/badge/Release-v1.2.0-F59E0B.svg)](.github/workflows/release.yml)
[![Interactive Sandbox: Zero Install](https://img.shields.io/badge/Live%20Sandbox-Try%20in%2010s%20(%3Fdemo%3D1)-10B981.svg)](.github/workflows/demo-pages.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-2563EB.svg)](LICENSE)
[![CI: 4 Jobs | 92 Suites | Node 20/22/24 + Caddy + Playwright](https://img.shields.io/badge/CI-92%20Suites%20%7C%20Node%2020%2F22%2F24%20%7C%20Caddy%20%7C%20Playwright-16A34A.svg)](.github/workflows/ci.yml)
[![Idle RAM: 50 MB RSS | 11.4k req/s | 0.99ms Sync](https://img.shields.io/badge/Idle%20RAM-50%20MB%20RSS%20%7C%2011.4k%20req%2Fs%20%7C%200.99ms%20Sync-10B981.svg)](#benchmarks-and-reproducible-results)
[![Runtime Deps: 6 | SLSA v1.1 + CycloneDX 1.6](https://img.shields.io/badge/Runtime%20Deps-6%20%7C%20SLSA%20%2B%20SBOM-0F172A.svg)](scripts/release-provenance.js)
[![Zero Shell: Verified](https://img.shields.io/badge/Shell%20Construction-0%20(CI%20Verified)-0F172A.svg)](tests/shell-safety.test.js)
[![MCP 2026-07-28: 200 Tools (-93.5% Core) + Tasks + 3 MCP Apps](https://img.shields.io/badge/MCP%202026--07--28-200%20Tools%20(-93.5%25)%20%7C%20Tasks%20%7C%203%20MCP%20Apps-7C3AED.svg)](#ai-agent-native-mcp-2026-07-28-tasks-and-mcp-apps)

> **Try Culkibo in 10 Seconds — Zero Install, Zero Docker Required:**
> Launch the curated read-only **Interactive Browser Sandbox** directly on **[GitHub Pages (`?demo=1`)](https://macaqueboy.github.io/culkibo/?demo=1&lang=en&theme=dark)** *(published automatically via [`.github/workflows/demo-pages.yml`](.github/workflows/demo-pages.yml))* or locally in `<200 ms` with **`npx culkibo demo`**!

<p>
  <img src="docs/assets/social-preview.png" alt="Culkibo overview banner showing sub-60 MB RSS, 6 runtime deps, zero shell construction, Live Sync 2.0, MCP tools, inline MCP Apps, and 140+ one-click apps" width="100%" />
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

Culkibo `v1.2.0` is an open-source **self-hosted PaaS** and **Coolify / Dokploy alternative** engineered for solo builders, agencies, AI/GPU operators, regulated platform teams, and AI coding agents. Instead of bolting a heavy PHP/Laravel or multi-container control stack on top of polling reverse proxies and shell scripts, Culkibo runs a single **50 MB RSS** daemon (across **141+ lazy-loaded services**, `49 MB` record, `0%` CPU, **`126.2 ms`** cold boot record / `116.6 ms` peak, **`11,382 req/s`** authed fast-path & **`10,824 req/s`** health, **`4,109 req/s`** mixed & **`3,222 req/s`** Express RBAC, **NEW RECORD `14,772 writes/s`** atomic JSON, **NEW RECORD `0.143 ms`** YAML anti-DoS, **`1.52 GB/s`** SHA-256 & **`1.46 GB/s`** AES-256-GCM native crypto, **`3,334 ev/s`** SQLite WAL, **`0.53 ms`** warm catalog, and a **`~370 kB` lazy prod UI bundle** with `0` Vite warnings) with **zero shell command construction**, atomic **Caddy v2.11** HTTP/3 ingress (**Next.js / React2Shell `CVE-2025-55182` SSR Firewall**, **Go 1.25 `Sec-Fetch-Site` CSRF & OAuth 2.1 PKCE `S256` Guard**, **Container Registry Pull-Limit `429` & `registry:3` Mirror Guard**, **SQLite WAL Checkpoint & NFS Corruption Guard**, **Build-`ARG`/`ENV` Secret Surface & `/run/secrets/` Migrator**, **JWT/OIDC & Zip-Slip Firewalls**, **GraphQL DoS Shield**, **ACME RFC 9773 ARI**, **Heap/`EMFILE` Leak Guard**, **CORS/CSP & PG XID Guards**), **Sub-Millisecond Live Sync 2.0 (`0.99 ms` apply / `7.21 ms` E2E p50 / `1.29 ms` rollback)**, **`33–36 µs` Micro-Wasm** (`64 KiB` RAM), and the industry's first **Historic `200`-Tool MCP `2026-07-28` (`-93.5%` / `~94%` core profile, Async Tasks & inline `ui://culkibo/*` MCP Apps)** control plane — verified by **92 integrated test suites**.

---

## Visual Showcase

Culkibo ships with a **Zero-Install Interactive Browser Sandbox (`?demo=1` / `npx culkibo demo`, lazily code-split to keep production `index-*.js` at `~370 kB` with `0` Vite warnings & `0 B` of demo code sent to real VPS users)**, **100% English & Spanish zero-dep localization** across every view (`100.0/100` EN purity + dark-mode contrast verified in Playwright QA), **Obsidian Dark Mode & Crisp Light Mode**, an **Open-Core White-Label Brand & Custom Login Theme Engine** (`GET/PUT /api/brand`), a **Pioneer Cockpit, Zero-Trust & Resilience UI** (Session Cookie, Go 1.25 `Sec-Fetch-Site` CSRF & OAuth 2.1 PKCE Guard + Build-`ARG`/`ENV` Secret Surface & `/run/secrets/` Migrator + JWT Algorithm-Confusion & OIDC Firewall + Archive Zip-Slip, Symlink & Zip-Bomb Firewall + CORS/CSP/SRI Firewall + Shai-Hulud/CHAINDROP Guard + Proxy Trust & MCPoison Guard + Webhook Replay Firewall + Credential Watchdog + NetSeg + OCI/SLSA Rekor + SPIFFE-Lite mTLS CA in Security Settings, SQLite WAL Checkpoint Starvation & NFS Corruption Guard + PostgreSQL 32-Bit XID Wraparound Guard + Valkey/Redis Fork CoW Guard + S3 WORM `0 B` KEK Rotation + Queue DLQ Gate + DB Query/Pool Guard + Read-Replica Fencing in Databases, Container Registry Pull-Limit `429` & `registry:3` Mirror Guard + Container Heap-Slope/`EMFILE`/Event-Loop Lag Guard + ACME RFC 9773 ARI & TLS Cipher Guard + Transactional Email Auth `SPF`/`DKIM`/`DMARC`/`MTA-STS` + Dual Block+Inode & `pg_wal` Disk Guard + Streaming Log PII Scrubber + VPA-Lite Rightsizer + FinOps & Agency Ledger in Observability, Blameless Incident Postmortem Correlator in Uptime/Status, Surrogate-Key Edge Cache + WS/SSE Flood Guard + Zero-Downtime DNS Cutover + Edge AI RPM+TPM Shield in Domains, Unified 2-Row-Header Project `Forensics` Drawer — OOM Forensics · Image Bloat · Egress `nftables` · Multi-Arch · Chaos GameDay · Feature Flags · Falco-Lite Anomaly · Immutable `@sha256:` Promotion · API Contract Gate · Build Repro · Preview Gate · Graceful Drain · Region Shift · Base Hardener · Monorepo DAG · GraphQL Shield · **SSR Edge**, Read-Only DB Studio, Post-MinIO S3, Passkeys FIDO2, OpenTofu IaC, Web Terminal, WireGuard Mesh, Caddy PoW Shield, SmartPack, Shadow Replay, Time-Machine, `33–36 µs` Micro-Wasm Tester, OTLP, and Coolify Streamer), and an interactive **Spatial SVG Topology Canvas** with click-to-link database env injection.

### Live Sync 2.0 (`0.99 ms` Sub-ms Apply · `7.21 ms` E2E · `1.29 ms` Rollback) + Inline MCP Apps Flow

<p align="center">
  <img src="docs/assets/live-sync-demo.svg" alt="Animated Culkibo Live Sync 2.0 and inline MCP Apps topology flow showing sub-10ms Merkle delta apply, -96.1% Brotli compression, Server-Timing, and ui://culkibo/topology" width="100%" />
</p>

### Obsidian Dark Mode & Light Mode (100% Global EN / ES Dashboard)

| Obsidian Dark Mode (`1440×900`) | Crisp Light Mode (`1440×900`) |
| :---: | :---: |
| ![Culkibo English Obsidian Dark Mode dashboard with live RAM telemetry, onboarding checklist, and project cards](docs/assets/dashboard-dark-en.png) | ![Culkibo English Light Mode dashboard with project cards, search filters, and 1-click deploy controls](docs/assets/dashboard-light-en.png) |

### Spatial SVG Topology Canvas & Click-to-Link DB Injection (`Obsidian Dark`)

![Culkibo interactive Spatial SVG Topology Canvas in Obsidian Dark showing Domains, Projects, Managed Databases, animated directional edges, and Node Inspector with Link-to-Project DATABASE_URL injection](docs/assets/topology-dark-en.png)

### AI Agent Hub — MCP `2026-07-28`, `200` Tools (`-93.5%` / `~94%` Core) & Interactive MCP Apps (`ui://culkibo/*`)

![Culkibo 100% English AI Agent Hub showing MCP tools, playbooks, core profile token savings, 1-click Antigravity/Claude/Cursor/Windsurf/Codex setup, and Interactive MCP Apps gallery](docs/assets/ai-agent-hub.png)

---

## Why Culkibo Is Architecturally Different

Traditional self-hosted PaaS platforms force a painful trade-off: burn 500 MB–1.5 GB of VPS RAM just to run the panel, expose CVSS 10.0 React2Shell RSC RCE (`CVE-2025-55182`) & Next.js `x-middleware-subrequest` auth bypass (`CVE-2025-29927`), hit Docker Hub anonymous `429 TOOMANYREQUESTS` pull limits, leak secrets in Dockerfile `ARG`/`ENV` (`Dokploy#3347`/`Coolify#10822`), corrupt SQLite `-wal` databases on NFS/EFS or starve checkpoints, and lack zero-token `Sec-Fetch-Site` CSRF & OAuth 2.1 PKCE `S256` (`CVE-2026-26247`). Culkibo fixes these problems at the architecture layer:

### 1. Zero-Shell Engine (`shell: false`), React2Shell SSR, Go 1.25 CSRF/PKCE & `/run/secrets/` Migrator
- Every subprocess (`docker`, `git`, `caddy`, `ssh`, `cron`, `exec`, `npm`) is invoked through `spawn()` / `execFile()` with tokenized `argv` arrays validated by [`safeCommand.js`](server/services/safeCommand.js) and `shell: false`. Statically verified on every commit by [`tests/shell-safety.test.js`](tests/shell-safety.test.js).
- **Next.js / RSC Middleware & SSR Cache-Poisoning Firewall (`server/services/ssrEdgeGuardService.js` · `culkibo ssr-guard` + MCP `culkibo_ssr_edge_guard`):** Cures **`CVE-2025-29927`** (Next.js CVSS 9.1 `x-middleware-subrequest` auth bypass), **`CVE-2025-55182`** ("React2Shell" CVSS 10.0 React 19 RSC RCE), & **`CVE-2025-49005`** (omitted `Vary: RSC` cache poisoning) + emits hardened Caddy header-strip & `Vary` blocks.
- **Session Cookie, Go 1.25 `Sec-Fetch-Site` CSRF & OAuth 2.1 PKCE Guard (`server/services/sessionCsrfGuardService.js` · MCP `culkibo_session_csrf_guard`):** Implements Go 1.25 `CrossOriginProtection` zero-token CSRF (`Sec-Fetch-Site` + `Origin` fallback), OAuth 2.1 mandatory `PKCE S256` curing **`CVE-2026-26247`** (Gitea), and `__Host-`/`HttpOnly`/`Secure` cookie hygiene (`0` raw cookies/verifiers persisted).
- **Build-`ARG` / `ENV` Secret Surface & `/run/secrets/` Migrator (`server/services/envSecretSurfaceService.js` · `culkibo env-surface` + MCP `culkibo_env_secret_surface`):** Cures **`Dokploy#3347`** (`SecretsUsedInArgOrEnv`) & **`Coolify#10822`** (build+runtime secret scoping) by auditing key names ONLY (`0` raw secrets stored/echoed) and emitting `RUN --mount=type=secret` + Compose `secrets:` (`0400`) migrations.
- **JWT/OIDC Algorithm-Confusion Firewall (`culkibo jwt-audit`, `CVE-2026-29000`/`33322`), Archive Zip-Slip & Zip-Bomb Firewall (`culkibo archive-guard`, `CVE-2026-23745`/`23950`), CORS/CSP/SRI Firewall (`CVE-2025-34291`), Shai-Hulud/CHAINDROP `pkg-guard`, Proxy Smuggling & MCPoison Pinning (`CVE-2025-54136`), S3 WORM `0 B` KEK Rotation, Webhook Replay Firewall, NetSeg Compiler, Ordered OTLP PII Scrubber, OCI/SLSA Rekor Verifier & Signed SOC 2 Bundles.**
- **By-Design Immunity to Real-World PaaS, Proxy & Runtime CVEs ([`CYCLE6`](docs/COMPETITOR_RADAR_CYCLE6.md) · [`CYCLE7`](docs/COMPETITOR_RADAR_CYCLE7.md) · [`CYCLE8`](docs/COMPETITOR_RADAR_CYCLE8.md) · [`CYCLE9`](docs/COMPETITOR_RADAR_CYCLE9.md) · [`CYCLE10`](docs/COMPETITOR_RADAR_CYCLE10.md) · [`CYCLE11`](docs/COMPETITOR_RADAR_CYCLE11.md) · [`CYCLE12`](docs/COMPETITOR_RADAR_CYCLE12.md) · [`CYCLE13`](docs/COMPETITOR_RADAR_CYCLE13.md) · [`CYCLE14`](docs/COMPETITOR_RADAR_CYCLE14.md) · [`CYCLE15`](docs/COMPETITOR_RADAR_CYCLE15.md) · [`CYCLE16`](docs/COMPETITOR_RADAR_CYCLE16.md) · [`CYCLE17`](docs/COMPETITOR_RADAR_CYCLE17.md) · [`CYCLE18`](docs/COMPETITOR_RADAR_CYCLE18.md) · [`CYCLE19`](docs/COMPETITOR_RADAR_CYCLE19.md) · [`CYCLE20`](docs/COMPETITOR_RADAR_CYCLE20.md) · [`CYCLE21`](docs/COMPETITOR_RADAR_CYCLE21.md) · [`CYCLE22`](docs/COMPETITOR_RADAR_CYCLE22.md)):** Immune to **`CVE-2025-55182`/`29927`/`49005`**, **`CVE-2026-26247`**, **`dokploy#3347`/`#2238`/`#5547`/`#4651`/`#2798`**, **`coolify#10822`/`#6800`/`#4311`/`#12211`/`#4702`/`#8627`**, **`CVE-2026-29000`/`33322`/`22817`**, **`CVE-2026-47707`/`35441`**, **`CVE-2026-23745`/`23950`**, **`CVE-2025-34291`/`63388`**, **`Shai-Hulud`/`CHAINDROP`**, **`CVE-2026-30851`/`54764`/`88008`**, **`CVE-2025-54136`**, **`caddy#6783`/`#7544`/`#6393`**, **`restic#5411`**, **`CVE-2026-41351`**, **`otel-contrib#49858`**, **`CVE-2026-93318`/`22703`/`55458`**, **`runc CVE-2025-31133`/`52565`/`52881`**, **`Coolify CVE-2025-66213`**, **`Ollama CVE-2026-7482`**, and **`vLLM CVE-2026-22778`/`137477`**.

### 2. `50 MB` Idle RAM, `126.2 ms` Boot, `14,772 writes/s` JSON, SQLite WAL Guard & Registry Mirror Guard
- **Independently Verified All-Time Speed Records (Cycle-21 `#421` & Cycle-22 `#432` QA):** **`50 MB RSS`** idle daemon (`49 MB` record; `<= 60 MB` invariant across **141+ lazy-loaded services**, `0%` CPU), **`126.2 ms`** cold boot (`116.6 ms` peak), **`11,382 req/s`** authed fast-path & **`10,824 req/s`** health (`p99 4.73 ms`), **`4,109 req/s`** mixed HTTP & **`3,222 req/s`** Express RBAC (`109k–151k ops/s` route RBAC), **NEW RECORD `14,772 writes/s`** atomic JSON, **NEW RECORD `0.143 ms`** YAML anti-DoS, **`1.52 GB/s` (`1,523 MB/s`) SHA-256 & `1.46 GB/s` (`1,462.8 MB/s`) AES-256-GCM**, **`3,334 ev/s`** SQLite WAL, **`0.53 ms`** warm 140-app catalog, **`~370 kB`** lazy prod UI bundle (`0` Vite warnings), and **`49.7 ms`** 40-client WS fan-out — fitting effortlessly on a **$4/mo 512 MB–1 GB VPS**.
- **Minimal supply-chain blast radius:** Exactly **6** root npm runtime dependencies ([`package.json`](package.json): `express`, `ws`, `chokidar`, `commander`, `cors`, `dotenv`) and **0** dependencies in [`telemetry-collector/`](telemetry-collector/README.md) — enforced across Node `20`, `22`, and `24` in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
- **SQLite WAL Checkpoint Starvation & Network-FS Corruption Guard (`server/services/sqliteWalGuardService.js` · MCP `culkibo_sqlite_wal_guard`):** Protects Rails 8 Solid Queue/Cache, PocketBase, Uptime Kuma & Litestream deployments from NFS/EFS POSIX locking corruption (`SQLITE_NETWORK_FS_CORRUPTION`), `-wal` checkpoint starvation, and missing `PRAGMA busy_timeout` / `journal_size_limit`.
- **Container Registry Pull-Limit (`429`) & Pull-Through Mirror (`registry:3`) Guard (`server/services/registryMirrorGuardService.js` · MCP `culkibo_registry_mirror_guard`):** Prevents Docker Hub anonymous IPv4 `429 TOOMANYREQUESTS` & shared-NAT pull exhaustion across VPS fleets, emitting hardened `/etc/docker/daemon.json` `registry-mirrors` (`registry:3`) failover configs.
- **Container Heap-Slope/`EMFILE`/Event-Loop Lag Guard, ACME RFC 9773 ARI & TLS Cipher Guard (`Coolify#6800`/`Dokploy#2238`), PostgreSQL 32-Bit XID Wraparound Guard (`VACUUM VERBOSE`), Transactional Email Auth (`culkibo email-audit`), Valkey Fork CoW Guard, Dual Block+Inode & `pg_wal` Disk Guard, Sticky Region Shift, 4-Phase Zero-Drop Drain, VPA-Lite Rightsizer, Blameless Postmortems, OTLP & FinOps.**

### 3. GraphQL DoS Shield, Monorepo DAG, Sub-ms Live Sync 2.0 (`0.99 ms`) & `33–36 µs` Wasm
When coding with Claude Code, Antigravity, Cursor, or Windsurf, waiting 2–4 minutes per push destroys flow:

```text
Traditional PaaS:  save file -> git commit -> push -> webhook -> Docker Hub 429 / rebuild ALL monorepo apps (2-8 min)
Culkibo Forge:     save file -> binary Commit Frame (/ws/sync, Brotli -96.1%) -> 0.99 ms apply / 7.21 ms E2E (1.29 ms rollback)
Culkibo Citadel:   Registry Mirror -> /run/secrets -> Monorepo DAG -> React2Shell SSR -> CSRF/PKCE -> SQLite/PG Guard -> SLO Canary
```

- **GraphQL Depth, Fragment-Spread Alias & Introspection Shield (`CVE-2026-47707`/`35441`/`CVE-2025-32031`), Monorepo Affected-Graph Selective Builder (`Dokploy#5547`), EOL Base-Image & CNCF `copa` Distroless Advisor (`culkibo base-harden`), Queue Schema & Poison-Pill DLQ Gate (`KIP-1034`), DB Query-Plan & Pool Guard (`culkibo pool-audit`), Preview Smoke-Gate, Post-Optic API Contract Gate, Immutable `@sha256:` GitOps Promotion, Blue/Green DB Read-Replica Split-Brain Fencing & Multi-Arch (`amd64`/`arm64`) Matrix Planner.**
- **8-Class Container OOM Forensics, 10-Rule Zero-Downtime SQL Linter (`culkibo lint-sql`), OOM-Safe KEDA Autoscaler + `503` Breaker, Read-Only DB Studio, Zero-Dep Web Terminal (`/ws/terminal`), and 20-Pattern Build Auto-Healer (`culkibo heal`).**
- **Sub-Millisecond Live Sync 2.0 (`0.99 ms` apply · `7.21 ms` E2E p50 · `p99 9.80 ms` · 100-file burst `87.94 ms` / `1,137 files/s` · rollback `1.29 ms` · `-96.1%` Brotli), Google SRE SLO Canary Auto-Rollback, Shadow Replay Gate & Whole-Stack Time-Machine (`culkibo timemachine`).**
- **ALL-TIME RECORD `33–36 µs` Warm Micro-Wasm Edge Runtime ([`wasmMicroRunner.js`](server/services/wasmMicroRunner.js)):** Sandboxed WebAssembly in isolated `worker_threads` — live-measured at **`33–36 µs` warm p50** (`64 KiB` RAM, zero host filesystem/network access).
- **Honest scope:** Live Sync 2.0 accelerates incremental code/asset iteration (*Path B*). Dependency or `Dockerfile` changes run full immutable Docker BuildKit builds (*Path C*) with `registry:3` mirror failover, `/run/secrets/` secret-mount migration, Monorepo selective DAG waves, `archive-guard`, `pkg-guard`, EOL/Distroless `copa` hardening, SSR/GraphQL/queue/DB/contract/repro/preview gates, OCI Rekor verification, sticky region shifts, zero-drop drain, SLO canaries, and multi-release rollback.

### 4. Historic `200` MCP `2026-07-28` Tools (`-93.5%` / `~94%` Core), Async Tasks & MCP Apps
- **200 Tools, 13 Playbook Prompts & 10 Resources** over Streamable HTTP (`POST /api/mcp`) and stdio (`culkibo mcp`) with legacy SSE fallback — verified end-to-end against a real spawned stdio JSON-RPC client ([`tests/release-and-mcp-e2e.test.js`](tests/release-and-mcp-e2e.test.js)), including `culkibo_ssr_edge_guard`, `culkibo_registry_mirror_guard`, `culkibo_session_csrf_guard`, `culkibo_sqlite_wal_guard`, `culkibo_env_secret_surface`, `culkibo_jwt_oidc_firewall`, `culkibo_runtime_leak_guard`, `culkibo_graphql_dos_shield`, `culkibo_acme_tls_budget`, `culkibo_archive_slip_guard`, `culkibo_cors_csp_guard`, `culkibo_pg_vacuum_guard`, `culkibo_monorepo_graph`, `culkibo_email_auth_guard`, `culkibo_pkg_confusion_guard`, `culkibo_proxy_trust_guard`, `culkibo_valkey_guard`, `culkibo_base_image_hardener`, `culkibo_worm_backup_crypto`, `culkibo_mcp_poison_guard`, **`culkibo_security_posture`**, `culkibo_compliance_bundle`, **`culkibo_triage_playbook`**, `culkibo_slo_canary`, and `culkibo_ai_workload`.
- **Official MCP `2026-07-28` Async Tasks (`io.modelcontextprotocol/tasks`) & Elicitation (`elicitation/create`):** Long-running Docker builds, Coolify migrations, and DR drills run non-blocking via `tasks/list`, `tasks/get`, `tasks/result`, and `tasks/cancel` with strict cross-tenant RBAC isolation — and declare structured JSON Schema `elicitation` prompts for missing secrets or approvals.
- **5 Context-Saving Profiles (`?profile=core|deploy|ops|security|all` & `CULKIBO_MCP_PROFILE`):** `?profile=core` serves the 17 essential tools (`17 / 200`) and cuts LLM tool-schema context by **NEW RECORD `-93.5%` (`~94%`)** while `culkibo_search_tools` discovers any of the remaining 200 tools on demand.
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
| **Control-Plane RAM & Fast-Path** | **50 MB RSS · 11,382 req/s** *(~370 kB UI)* | ~800 MB – 1.5 GB *(2 GB VPS min)* | ~450 – 800 MB *(1–2 GB VPS)* | ~150 – 300 MB *(300–450 MB w/ Swarm)* | 0 MB panel *(+15–25 MB proxy)* | ~100 – 200 MB *(external proxy)* |
| **React2Shell SSR + Go 1.25 CSRF/PKCE + `/run/secrets/`** | ✅ **`CVE-2025-55182`/`29927` · `CVE-2026-26247` · `Dokploy#3347`** | ❌ `#10822` | ❌ `#3347` | ❌ | ❌ | ❌ |
| **Registry `429` Mirror (`registry:3`) + SQLite WAL/NFS Guard** | ✅ **`daemon.json` mirrors · NFS lock & checkpoint guard** | ❌ *(Hub 429)* | ❌ *(Hub 429)* | ❌ | ❌ *(Hub 429)* | ❌ |
| **JWT/OIDC Firewall + Archive Zip-Slip & Zip-Bomb Guard** | ✅ **`CVE-2026-29000`/`33322` · `CVE-2026-23745`/`23950` · `0` tokens stored** | ❌ | ❌ | ❌ | ❌ | ❌ |
| **GraphQL DoS Shield + Heap/EMFILE Leak + ACME ARI Budget** | ✅ **`CVE-2026-47707`/`35441` · `hoursToOom` · RFC 9773 ARI (`#6800`)** | ❌ `#6800` | ❌ `#2238` | ❌ | ❌ | ❌ |
| **CORS/CSP/SRI Firewall + Shai-Hulud/CHAINDROP `pkg-guard`** | ✅ **`CVE-2025-34291`/`63388` · Caddy headers · Worm IoCs & Typosquat** | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Postgres 32-Bit XID Wraparound + Monorepo Selective DAG** | ✅ **`VACUUM VERBOSE` (no `FULL`) · Kahn `deployWaves[]` (`#5547`)** | ❌ *(unordered)* | ❌ `#5547` | ❌ | ❌ | ❌ |
| **Transactional Email Auth (`SPF`/`DKIM`/`DMARC`/`MTA-STS`)** | ✅ **10-lookup SPF · 2048b DKIM · Port `465`/`587` (`#4311`)** | ❌ `#4311` | ❌ | ❌ | ❌ | ❌ |
| **Proxy Smuggling Guard + Zero-Trust MCPoison Pinning** | ✅ **`CVE-2026-30851`/`54764` · `CVE-2025-54136` SHA-256 + Unicode scan** | ❌ | ❌ *(Traefik `h2c`)* | ❌ | ❌ | ❌ |
| **Valkey Fork CoW Guard + Distroless/`copa` + S3 WORM KEK** | ✅ **`BGSAVE` OOM · BullMQ safe · CNCF `copa` · `0 B` AES-GCM KEK rotate** | ❌ `#12211` / `#4774` | ❌ | ❌ | ❌ | ❌ |
| **Webhook Replay Firewall + Cred Watchdog + Queue DLQ** | ✅ **`CVE-2026-41351` · 0-secret expiry (`#4702`) · `KIP-1034` DLQ breaker** | ❌ `#4702` (JWT skew) | ❌ `#2913` / `#5618` | ❌ | ❌ | ❌ |
| **Dual Block+Inode Disk Guard + Sticky Region Shift** | ✅ **`df -ih` + `pg_wal` (`#4651`) · Caddy `lb_policy cookie` (`#7544`/`#6393`)** | ❌ | ❌ `#4651` / `#2702` | ❌ | ❌ | ❌ |
| **DB Query/Pool Guard + NetSeg Compiler + Zero-Drop Drain** | ✅ **`EXPLAIN` + Pool · `internal: true` (`#2798`) · 4-Phase Drain (`#8627`)** | ❌ `#8627` (502/503) | ❌ `#2798` / `#2987` | ❌ | ⚠️ `SIGKILL` race | ❌ |
| **CVE Cooldown Planner + Ordered OTLP PII Scrubber** | ✅ **`pnpm`/Renovate Fast-Track · Luhn PCI + `span.events[]` (`#49858`)** | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Build Repro + Cache Poisoning + Preview Smoke-Gate** | ✅ **`CVE-2026-93318`/`33747` · SHA-bound fork + Signed Commit Status** | ❌ `#1671` / `#7155` | ❌ `#5856` / `#6010` | ❌ | ❌ | ❌ |
| **Surrogate Edge Cache + VPA Rightsizer + Blameless SRE** | ✅ **`souin#884`/`#850` · OOM +50% VPA (`#4050`) · CloudEvents Postmortem** | ❌ | ⚠️ `#4050` / `#903` | ❌ | ❌ | ❌ |
| **API Contract Gate + Pure-Node OCI/SLSA Rekor Verify** | ✅ **OpenAPI/GraphQL `MISSING-VERSION-BUMP` · `CVE-2026-22703` Rekor v2** | ❌ | ❌ | ❌ | ❌ | ❌ |
| **WS/SSE Flood + `101` Scrub + Zero-Downtime DNS Cutover** | ✅ **`CVE-2026-55458` · `dokploy#3033` · CF Proxy ACME (`#6271`) · 5-Phase TTL** | ❌ `#6271` / `#11831` | ⚠️ `#3033` / `#4202` | ❌ | ⚠️ `kamal-proxy#26` | ❌ |
| **Orphan PR-Preview Reaper (Docker-29-Immune)** | ✅ **JSON label-graph (`#12148`) · `-pr-*` vol GC · Sidecar-safe (`#3973`)** | ⚠️ `#11441` / `#12148` | ⚠️ `#4203` / `#3973` | ❌ | ❌ | ❌ |
| **SPIFFE mTLS CA + Falco-Lite Anomaly + Egress `nftables`** | ✅ **Ed25519 mTLS (`#8524`) · Cryptominer 10-rule (`#5156`) · `nftables`** | ❌ `#8524` / `#12336` | ❌ `#2605` / `#5156` / `#2486` | ⚠️ Swarm CLI | ⚠️ SSH shell | ⚠️ Paid Business |
| **Edge AI RPM+TPM Shield + Geo/A-B + SRE SLO Canary** | **Caddy v2.11** *(IETF `429` RPM+TPM · `CF-IPCountry` · 10→100% SRE · PoW)* | Traefik *(2,000 ms throttle)* | Traefik / Swarm | Nginx reload | `kamal-proxy` *(<1 ms swap)* | ❌ External |
| **DB Read-Replica Fencing + PR PII Masker + SQL Lint** | ✅ **Split-brain fence (`#8701`) · HMAC PII · 10-rule DDL lint** | ❌ | ❌ *(`#429`/`#1633`)* | ❌ | ❌ | ❌ |
| **Cross-VPS Volume Cloner + AI/GPU LLMs + DR Fire-Drills** | ✅ **`tar --numeric-owner` · Ollama · vLLM · `culkibo dr-drill` · `.ndjson.gz`** | ❌ `CVE-2025-66213` | ⚠️ `#1621` / `#1382` | ❌ | ⚠️ `EACCES` | ❌ |
| **AI-Agent Native MCP + MCPoison Guard + MCP Apps** | ✅ **200 tools · `mcp_poison_guard` · Tasks · 3 `ui://` Apps · `-93.5%`** | ❌ *(3rd-party)* | ❌ *(3rd-party)* | ❌ | ❌ | ❌ |
| **SmartPack + DirectPush + WireGuard + `33–36 µs` Wasm** | ✅ **18 stacks · `culkibo pussh` · `x25519` Mesh · Micro-Wasm** | ⚠️ Nixpacks | ⚠️ Nixpacks | ⚠️ Buildpacks | ❌ Registry req. | ❌ |
| **1-Click Catalog, 12 DBs, Passkeys & Coolify Migrator** | ✅ **140 apps · 12 DBs · FIDO2 Passkeys · OpenTofu IaC · Coolify→Caddy** | ✅ Catalog / ⚠️ Teams | ✅ Catalog / ⚠️ Basic | ✅ One-click | ✅ `deploy.yml` | ⚠️ Paid Business |

---

## Benchmarks and Reproducible Results

Every Culkibo metric below comes from real code independently measured on `Node v24.14.0` (`win32/x64`, uncontended run) with **zero synthetic delays and zero subtracted overhead**. Reproduce the complete suite or generate a Markdown/JSON comparison report on your own machine:

```bash
node bench/run-all.bench.js
node bench/competitor-comparison.bench.js --markdown
```

### Independently Verified Live Performance Results (`v1.2.0` — Cycle-21 & Cycle-22 All-Time Speed Records!)

| Metric | Live Measured Result | Notes & Verification Command |
| :--- | :--- | :--- |
| **Idle Daemon RAM / CPU** | **50 MB RSS · 0% CPU** *(49 MB all-time record)* | Verified across **141+ lazy-loaded services** (`<= 60 MB` invariant) |
| **Production Frontend Bundle (Lazy `?demo=1` Split)** | **`~370 kB` (`~101 kB` gzip) · `0` Vite warnings** | Lazy `demoMode.js` split; `0 B` of sandbox mocks sent to real VPS users |
| **Cold Boot Time** (`CULKIBO_SKIP_RECONCILE=1`) | **126.2 ms `comp` / `128–130 ms` `run-all` (RECORD)** *(116.6 ms peak)* | Measured via `process.hrtime.bigint()` (`npm run bench:control`) |
| **Authenticated Fast-Path (Bearer + Brotli, 500 req / 25w)** | **11,382 req/s (RECORD)** *(C21 `10,589 req/s`, p99 `3.51 ms`)* | HMAC-SHA256 LRU cache + WeakMap zero-copy Brotli + `Server-Timing: cp;dur=0.02` |
| **Health HTTP (`GET /api/health`, 500 req / 25w)** | **10,824 req/s (RECORD)** *(p99 `4.73 ms`)* | Pre-compiled O(1) fast-path route map |
| **Atomic JSON, YAML & Native Crypto (`SHA-256` / `AES-256-GCM`)** | **14,772 writes/s · `0.143 ms` YAML (NEW C22 RECORDS) · `1.52 GB/s` SHA-256** | `1,523 MB/s` SHA-256 · `1.46 GB/s` (`1,462.8 MB/s`) AES-GCM · **`3,334 ev/s`** WAL |
| **Mixed Uncompressed / RBAC Express HTTP (500 req / 25w)** | **4,109 req/s mixed · `3,222 req/s` Express RBAC (RECORD)** | `0` failures · route RBAC **`109k–151k ops/s`** (`bench/subsystems.bench.js`) |
| **Catalog Load (`GET /api/catalog`, 140 apps)** | **warm p50 `0.53 ms` (RECORD)** | `129.6 KB` → `34.5 KB` Brotli (**-73.4%**) |
| **Sub-Millisecond Live Sync 2.0 (Path B Incremental Sync)** | **apply `0.99 ms` · E2E `7.21 ms` p50 · rollback `1.29 ms` (RECORD)** | 100-file burst **`87.94 ms` (`1,137 files/s`)** · Brotli **-96.1%** · `p99 9.80 ms` |
| **Isolated Micro-Wasm Edge Runtime** | **warm p50 `33–36 µs` (RECORD) · `64 KiB` RAM** | `33 µs` all-time / `36 µs` C22 (`bench/run-all.bench.js` & [`tests/migrations-and-wasm.test.js`](tests/migrations-and-wasm.test.js)) |
| **WebSocket 40-Client Fan-Out** | **49.7 ms (SUB-50ms RECORD)** (`40/40` initial state delivered) | Zero drops under concurrent churn (`tests/websocket-stress.test.js`) |
| **Caddy v2.11 Atomic Swap, React2Shell SSR, ARI & mTLS** | **Synchronous Admin API + SSR header-strip/`Vary` + `tls`/ARI + `trusted_proxies`** | Verified live in Linux CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml) `live-caddy-e2e`) & `npm run bench` |
| **MCP `2026-07-28` `?profile=core` Savings** | **-93.5% (`~94%`) schema tokens (NEW RECORD)** (`17 / 200` tools) | Verified via `bench/competitor-comparison.bench.js` + external stdio E2E |
| **Supply-Chain, Shell Safety & Test Suite** | **6 root deps · 0 collector deps · 0 shell calls · 92 suites** | Verified in CI + React2Shell SSR + CSRF/PKCE + Registry Mirror + SQLite WAL + `/run/secrets/` |

---

## Architecture

Culkibo separates rapid developer/AI iteration (**The Forge**) from immutable production releases (**The Citadel**) on a single lightweight control plane:

```mermaid
flowchart LR
    Dev["Developer & AI Agents (Claude Code / Antigravity / Cursor)"]
    UI["Web Dashboard (100% EN/ES · ~370 kB Lazy Bundle · SSR Edge · CSRF/PKCE · Registry Mirror · SQLite WAL)"]
    MCP["MCP 2026-07-28 (200 Tools, -93.5% Core, MCPoison Pin, Tasks, 3 ui:// Apps)"]
    Sync["Live Sync 2.0 (/ws/sync 0.99 ms Sub-ms Apply · 7.21 ms E2E · 1.29 ms Rollback)"]
    CP["Culkibo Control Plane (Node.js 50 MB RSS, 126.2 ms Boot, 11,382 req/s, 14,772 writes/s JSON, shell:false)"]
    Forge["The Forge (Hot Dev + Registry Mirror + /run/secrets Migrator + Monorepo DAG + Archive/pkg-guard)"]
    Citadel["The Citadel (React2Shell SSR + Go 1.25 CSRF/PKCE + JWT/OIDC + GraphQL Shield + CORS/CSP + Drain)"]
    Caddy["Caddy v2.11 Edge (HTTP/3, SSR Vary/Strip, RFC 9773 ARI TLS, CORS/CSP, trusted_proxies, 33-36us Wasm)"]
    Obs["Registry 429 Budget + Heap/EMFILE Leak Guard + ACME ARI + Email Auth + Disk Guard + Scrubbed OTLP"]
    Data["12 DBs + SQLite WAL/NFS Guard + PG 32-Bit XID Guard + Valkey CoW + S3 WORM KEK + AI/GPU LLMs"]

    Dev -->|"Streamable HTTP / stdio"| MCP
    Dev -->|"Commit Frames"| Sync
    Dev --> UI
    UI -->|"O(1) Fast-Path + FIDO2/RBAC"| CP
    MCP --> CP
    Sync --> Forge
    CP --> Forge
    CP --> Citadel
    CP -->|"Atomic JSON Admin API"| Caddy
    CP -->|"Disk Guard / Scrubbed OTLP / VPA"| Obs
    Citadel --> Data
    Caddy -->|"Proxy Trust, Sticky Region Shift & SLO Canary"| Citadel
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
node bin/culkibo.js sync <projectId> .               # Start Live Sync 2.0 (0.99 ms apply / 7.21 ms E2E)
node bin/culkibo.js deploy <projectId>               # Immutable BuildKit deploy + Policy Gate + SLO Canary
node bin/culkibo.js ssr-guard next-edge.json --json  # CVE-2025-55182 React2Shell, CVE-2025-29927 & RSC Vary firewall
node bin/culkibo.js env-surface Dockerfile --json    # Dokploy#3347/Coolify#10822 Build-ARG/ENV -> /run/secrets/ migrator (key names only)
node bin/culkibo.js jwt-audit oidc-claims.json --json  # CVE-2026-29000/33322 JWT alg-confusion & OIDC firewall (0 raw tokens)
node bin/culkibo.js archive-guard bundle.json --json # CVE-2026-23745/23950 Zip-Slip, symlink & Zip-Bomb guard
node bin/culkibo.js email-audit email-auth.json --json  # 2025-2026 SPF/DKIM/DMARC/MTA-STS & Coolify#4311 SMTP parity
node bin/culkibo.js pkg-guard package.json --json    # Shai-Hulud/CHAINDROP worm IoCs, typosquats & ignore-scripts=true
node bin/culkibo.js base-harden Dockerfile --json    # EOL base, USER root, Distroless & CNCF copa thin-patch advisor
node bin/culkibo.js mcp-poison-check manifest.json --json  # CVE-2025-54136 MCPoison rug-pull & Unicode tag guard
node bin/culkibo.js disk-guard --block-pct 45 --inode-pct 92 --pg-wal-gb 14 --json  # Catch inode ENOSPC & pg_wal runaway
node bin/culkibo.js cred-watchdog --skew-sec 45 --ssh-mode 0644 --json              # Metadata-only expiry & SSH/JWT hygiene
node bin/culkibo.js pool-audit --max-conn 100 --replicas 8 --pool-size 20 --idle-timeout 30 --json  # Catch PgBouncer/Prisma overcommit
node bin/culkibo.js scrub-pii --text "Contact jane@example.com about order #1234567890123456" --json  # Deterministic OTLP/log PII scrubber
node bin/culkibo.js repro-audit Dockerfile --lockfile package-lock.json --epoch 1700000000 --json  # Build reproducibility & cache-poisoning gate
node bin/culkibo.js rightsize-check --memory 2048 --cpu 2 --samples 220,240,260,255,250,245,235,230,265,270 --json  # VPA-lite rightsizing
node bin/culkibo.js contract-diff base.json rev.json --format openapi --json  # Post-Optic API breaking-change gate
node bin/culkibo.js dns-cutover app.example.com --target-ip 203.0.113.10 --acme dns-01 --json  # 5-phase TTL & CF proxy plan
node bin/culkibo.js anomaly-scan --cmd "xmrig -o stratum+tcp://pool:3333" --json  # Falco-Lite runtime anomaly guard
node bin/culkibo.js verify-digest ghcr.io/org/app@sha256:... --json               # Reject :latest mutable tags
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

Culkibo is built from day one for autonomous and human-in-the-loop AI coding workflows — shipping a historic **200 tools** (including `culkibo_ssr_edge_guard`, `culkibo_registry_mirror_guard`, `culkibo_session_csrf_guard`, `culkibo_sqlite_wal_guard`, `culkibo_env_secret_surface`, `culkibo_jwt_oidc_firewall`, `culkibo_runtime_leak_guard`, `culkibo_graphql_dos_shield`, `culkibo_acme_tls_budget`, `culkibo_archive_slip_guard`, `culkibo_cors_csp_guard`, `culkibo_pg_vacuum_guard`, `culkibo_monorepo_graph`, `culkibo_email_auth_guard`, `culkibo_pkg_confusion_guard`, `culkibo_proxy_trust_guard`, `culkibo_valkey_guard`, `culkibo_base_image_hardener`, `culkibo_worm_backup_crypto`, `culkibo_mcp_poison_guard`, `culkibo_webhook_firewall`, `culkibo_disk_pressure_guard`, `culkibo_region_traffic_shift`, `culkibo_credential_watchdog`, `culkibo_security_posture`, `culkibo_triage_playbook`), **13 playbooks**, official **MCP `2026-07-28` Async Tasks (`io.modelcontextprotocol/tasks`)**, **Elicitation (`elicitation/create`)**, and the first **`modelcontextprotocol/ext-apps` (`2026-01-26`)** interactive UI resources in any self-hosted PaaS.

### 1-Click Agent Kit Generator

Generate drop-in MCP configs (defaulting to `?profile=core` for **-93.5% / ~94% token savings** across `17 / 200` tools and using `${CULKIBO_TOKEN}` env placeholders — never plaintext secrets):

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

Culkibo ships **92 integrated test suites** in `tests/run-all.js` (including Next.js / React2Shell `CVE-2025-55182`/`29927`/`49005` SSR Edge Firewall, Container Registry Pull-Limit `429` & `registry:3` Mirror Guard, Session Cookie, Go 1.25 `Sec-Fetch-Site` CSRF & OAuth 2.1 PKCE `S256` Guard `CVE-2026-26247`, SQLite WAL Checkpoint Starvation & NFS Corruption Guard, Build-`ARG`/`ENV` Secret Surface & `/run/secrets/` Migrator `Dokploy#3347`/`Coolify#10822`, JWT Algorithm-Confusion & OIDC Firewall `CVE-2026-29000`/`33322`/`22817`, Container Heap-Slope, `EMFILE` FD-Leak & Event-Loop Lag Guard, GraphQL Depth/Fragment-Spread Alias & Introspection Shield `CVE-2026-47707`/`35441`, ACME Rate-Limit Budget, RFC 9773 ARI & TLS Cipher Guard `Coolify#6800`/`Dokploy#2238`, Archive Zip-Slip, Symlink & Zip-Bomb Firewall `CVE-2026-23745`/`23950`, CORS/CSP/SRI Firewall `CVE-2025-34291`/`63388`, PostgreSQL 32-Bit XID Wraparound Guard, Monorepo Affected-Graph Selective Builder `Dokploy#5547`, Transactional Email Auth `Coolify#4311`, Shai-Hulud/CHAINDROP Guard, Reverse-Proxy Trust & Smuggling Guard `CVE-2026-30851`/`54764`, Zero-Trust MCPoison Rug-Pull Guard `CVE-2025-54136`, Valkey Fork CoW Guard, EOL Base-Image & CNCF `copa` Advisor, S3 WORM `0 B` AES-256-GCM KEK Rotation, Webhook Replay Firewall, Disk/Inode Guard, Sticky Region Shift, Credential Watchdog, Queue DLQ Gate, DB Query/Pool Guard, NetSeg Compiler, CVE Cooldown Planner, Ordered OTLP PII Scrubber, 4-Phase Zero-Drop Drain, Reproducible Build Verifier, Preview Smoke-Gate, Surrogate Edge Cache, VPA-Lite Rightsizer, Blameless Postmortems, API Contract Gate, OCI/SLSA Rekor Verifier, WS/SSE Flood Guard, DNS Cutover, PR Orphan Reaper, SPIFFE-Lite mTLS CA, Feature Flags, AI RPM+TPM Shield, Falco-Lite Anomaly Guard, `@sha256:` GitOps, Container Egress `nftables`, DB Replica Fencing, Shannon Secret Gate, Multi-Arch Matrix, Chaos GameDays, PR PII Masker, 8-Class OOM Forensics, 10-Rule SQL Linter, Signed SOC 2 Bundles, Ollama/vLLM GPU, Post-MinIO S3, Read-Only DB Studio, FIDO2 Passkeys, OpenTofu IaC, Mock-Coolify v4 E2E, external MCP stdio E2E, OTLP/SLSA E2E, and `33–36 µs` Micro-Wasm E2E) + standalone live-server, WebSocket churn, HTTP stress, and zero-dep telemetry collector suites — verified continuously on Linux by [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (`4` jobs: Node 20/22/24 matrix + Live Caddy v2.11 + Docker BuildKit SmartPack & SBOM E2E + Playwright Desktop/Mobile visual QA), released with signed SLSA v1.1 + CycloneDX 1.6 via [`.github/workflows/release.yml`](.github/workflows/release.yml), and published as a zero-install sandbox via [`.github/workflows/demo-pages.yml`](.github/workflows/demo-pages.yml):

```bash
node tests/shell-safety.test.js                       # Static AST/source check: 0 shell calls
npm run typecheck                                     # Server TypeScript checkJs (0 errors)
npx tsc -p web/tsconfig.app.json --noEmit             # Frontend TypeScript check (0 errors)
npx --prefix web oxlint --deny-warnings               # oxlint React 19 + Compiler rules (0 warnings)
npm run web:build                                     # Vite production build (~370 kB / ~101 kB gzip, 0 warnings)
npm test                                              # 92 suites + live-server + WS stress + HTTP stress
node --test telemetry-collector/test/collector.test.js  # Zero-dep telemetry collector suite
npm run release:sbom -- --out-dir dist-release --sign --verify  # Signed SLSA v1.1 + CycloneDX 1.6 SBOM
```

### Repository Layout

```text
.github/workflows/ci.yml         Active 4-job Linux CI (Node 20/22/24, Live Caddy, BuildKit SmartPack/SBOM, Playwright)
.github/workflows/release.yml    Automated v* GitHub Release workflow (Signed SLSA v1.1 DSSE + CycloneDX 1.6 SBOM)
.github/workflows/demo-pages.yml Zero-Install Interactive Browser Sandbox workflow (GitHub Pages ?demo=1)
bin/culkibo.js                   CLI (demo, init, up, sync, deploy, ssr-guard, env-surface, jwt-audit, archive-guard, mcp...)
scripts/release-provenance.js    Zero-dep CycloneDX 1.6 SBOM, SHA-256 checksums & Ed25519 SLSA DSSE signer
server/
  index.js                       O(1) fast-path HTTP daemon (50 MB RSS, 126.2 ms boot, 11,382 req/s, 14,772 writes/s JSON), /ws/sync
  middleware/auth.js             Constant-time tokens, RBAC middleware (3,222 req/s / 109k-151k ops/s), single-use WS tickets
  routes/api.js                  REST API (edge/ssr-guard, builds/registry-mirror, security/session-csrf, db/sqlite-wal, security/env-surface)
  services/                      141+ zero-shell services (ssrEdgeGuardService, registryMirrorGuardService, sessionCsrfGuardService,
                                 sqliteWalGuardService, envSecretSurfaceService, jwtOidcFirewallService, runtimeLeakGuardService,
                                 graphqlDosShieldService, acmeTlsBudgetService, archiveSlipGuardService, edgeCorsCspService,
                                 pgVacuumGuardService, monorepoGraphService, emailAuthGuardService, pkgConfusionGuardService,
                                 proxyTrustGuardService, valkeyGuardService, baseImageHardenerService, wormBackupCryptoService,
                                 mcpPoisonGuardService, webhookFirewallService, diskPressureGuardService, regionTrafficShiftService,
                                 credentialExpiryWatchdogService, queueSchemaDlqService, queryPlanGuardService, netSegCompilerService,
                                 depUpgradePlannerService, logPiiScrubberService, gracefulDrainService, reproducibleBuildService,
                                 previewGateService, edgeCacheService, resourceRightsizerService, postmortemCorrelatorService,
                                 apiContractGateService, ociSignatureVerifier, streamFloodGuardService, dnsCutoverService,
                                 orphanReaperService, mtlsMeshService, featureFlagService, apiRateLimitService, runtimeAnomalyService,
                                 digestPromotionService, egressFirewallService, replicaFailoverService, preDeploySecretGate,
                                 multiArchPlannerService, chaosGameDayService, imageBloatAuditor, cronLeaseService, piiMaskerService,
                                 oomForensicsService, oncallEscalationService, syntheticSentinelService, workerAutoscalerService,
                                 sqlMigrationLinter, licenseAuditorService, seccompProfileService, admissionPolicyService,
                                 complianceBundleService, volumeMigrationService, edgeExperimentService, backupDrillService,
                                 sloCanaryController, aiWorkloadService, mcpServer...)
telemetry-collector/             Zero-dep anonymous telemetry collector (node:sqlite WAL + CF Workers/D1)
web/src/                         React 19 + Tailwind v4 dashboard (100% EN/ES, ~370 kB Lazy Bundle, White-Label, Pioneer Cockpit)
bench/                           Reproducible live benchmarks (control-plane, live-sync, route-swap, subsystems)
scripts/                         Hardened Debian/Ubuntu VPS installer (chmod 700), uninstaller, systemd test & SBOM signer
tests/                           92 integrated + 4 standalone verification, E2E, security, fuzz & stress suites
docs/                            MIGRATION_GUIDE.md, GITHUB_SEO_LAUNCH_KIT.md, COMPETITOR_RADAR_CYCLE{6..22}.md, EVOLUTION_LOG.md, assets/
```

---

## Privacy and Transparent Telemetry

Culkibo includes opt-out anonymous crash/health telemetry scrubbed through an **11-phase PII sanitizer** (never collects secrets, domains, IPs, repo names, or payloads). Inspect the exact JSON envelope anytime (`node bin/culkibo.js telemetry preview`) or disable it instantly via `CULKIBO_TELEMETRY=0`, `DO_NOT_TRACK=1`, CLI (`telemetry disable`), or Settings. Full specification in [`PRIVACY.md`](PRIVACY.md) and [`telemetry-collector/README.md`](telemetry-collector/README.md).

---

## Ethical Open-Core and Community Roadmap

### Our Open-Core Promise (Enforced in [`editionService.js`](server/services/editionService.js))

- **Community Edition (`Apache-2.0`, Free Forever):** **100% of self-hosted core power with ZERO artificial limits** — unlimited projects, 12 databases + SQLite WAL Checkpoint Starvation & NFS Corruption Guard + PostgreSQL Autovacuum & 32-Bit XID Wraparound Guard + Valkey/Redis Fork CoW & Eviction Guard + DB Query-Plan & Pool Exhaustion Guard (`culkibo pool-audit`) + Blue/Green Read-Replica Split-Brain Fencing + PgBouncer + Read-Only DB Studio + PR-Preview DB PII Masker (`culkibo mask-pii`) + 10-Rule SQL Linter (`culkibo lint-sql`), Next.js / React2Shell (`CVE-2025-55182`/`29927`) SSR Edge Firewall (`culkibo ssr-guard`), Container Registry Pull-Limit (`429`) & `registry:3` Mirror Guard, Session Cookie, Go 1.25 `Sec-Fetch-Site` CSRF & OAuth 2.1 PKCE `S256` Guard (`CVE-2026-26247`), Build-`ARG`/`ENV` Secret Surface & `/run/secrets/` Migrator (`culkibo env-surface`, `Dokploy#3347`/`Coolify#10822`), JWT Algorithm-Confusion & OIDC Claim Firewall (`culkibo jwt-audit`, `CVE-2026-29000`/`33322`), Container Heap-Slope, `EMFILE` FD-Leak & Event-Loop Lag Guard, GraphQL Depth/Fragment-Spread Alias & Introspection Shield (`CVE-2026-47707`/`35441`), ACME Rate-Limit Budget, RFC 9773 ARI & TLS Cipher Guard (`Coolify#6800`/`Dokploy#2238`), Archive Zip-Slip, Symlink & Zip-Bomb Firewall (`culkibo archive-guard`, `CVE-2026-23745`/`23950`), Browser Security Headers, Strict CSP/SRI & CORS Firewall (`CVE-2025-34291`/`63388`), Supply-Chain Worm (`Shai-Hulud`/`CHAINDROP`) & Typosquat Guard (`culkibo pkg-guard`), Monorepo Affected-Graph Selective Builder (`Dokploy#5547`), Transactional Email Auth (`SPF`/`DKIM`/`DMARC`/`MTA-STS`, `culkibo email-audit`, `Coolify#4311`), Reverse-Proxy Trust & `forward_auth`/`h2c` Smuggling Guard (`CVE-2026-30851`), Zero-Trust MCPoison Rug-Pull Manifest Guard (`culkibo mcp-poison-check`, `CVE-2025-54136`), EOL Base-Image, CNCF `copa` & Distroless Advisor (`culkibo base-harden`), S3 WORM Object-Lock & AES-256-GCM Envelope KEK Rotation (`0 B` re-upload), Inbound Webhook HMAC & Replay Firewall (`CVE-2026-41351`), Dual Block+Inode & `pg_wal` Disk-Pressure Guard (`culkibo disk-guard`), Multi-Region Health-Gated Sticky Blue/Green Shift (`caddy#7544`/`#6393`), Metadata-Only Credential Expiry & SSH/JWT Watchdog (`culkibo cred-watchdog`), Queue Schema Evolution & Poison-Pill DLQ Gate (`KIP-1034`), Container Network Micro-Segmentation Compiler (`dokploy#2798`), CVE Fast-Track & Cooldown Dependency Upgrade Planner (`pnpm`/Renovate), Ordered Streaming Log PII Scrubber (`culkibo scrub-pii`, `otel-contrib#49858`), 4-Phase Graceful Shutdown & Zero-Drop Webhook Drain (`coolify#8627`), Reproducible Build & Cache-Poisoning Verifier (`culkibo repro-audit`), Preview Synthetic Smoke-Gate & Signed Commit Status, Surrogate-Key Edge Cache & Stampede Coalescer, Goldilocks/VPA-Lite Container Resource Rightsizer (`culkibo rightsize-check`), Blameless Incident Postmortem & Timeline Correlator, Post-Optic API Contract & Schema Drift Gate (`culkibo contract-diff`), Pure-Node OCI Artifact Signature & SLSA Rekor Verifier (`CVE-2026-22703`), Edge WS/SSE Connection-Flood & `101` Hop-by-Hop Guard (`CVE-2026-55458`), Zero-Downtime DNS Cutover & Cloudflare Proxy Verifier (`culkibo dns-cutover`), Docker-29-Immune Orphan PR-Preview Auto-Reaper, Zero-Trust SPIFFE-Lite mTLS Identity CA, OpenFeature-Lite Declarative Feature Flags & Instant Kill-Switch, Edge API Rate-Limit & AI RPM+TPM Wallet-Drain Shield, Falco-Lite Container Runtime Anomaly Detector (`culkibo anomaly-scan`), Immutable `@sha256:` GitOps Promotion Pipeline (`culkibo verify-digest`), Pre-Deploy Shannon-Entropy Secret Gate (`culkibo secret-scan`), Container Egress & `DOCKER-USER`/`nftables` Drift Auditor, Multi-Arch (`amd64`/`arm64`) OCI Matrix Planner (`culkibo multiarch-check`), Toxiproxy/Chaos Mesh GameDay Simulator, 8-Class OOM Forensics, Cron Fencing Leases, On-Call Escalation, Synthetic TLS Sentinel, SPDX & Seccomp/`runc` Guards, Policy Admission, Ed25519-Signed SOC 2 Bundles, Ollama/vLLM GPU, Post-MinIO S3, 140 catalog apps, Agency Ledger, OSS White-Label, Sub-ms Live Sync 2.0, FIDO2 Passkeys, OpenTofu IaC, Web Terminal, WireGuard Mesh, Caddy PoW Shield, 20-Pattern Auto-Healer, Shadow Replay, Time-Machine, FinOps, OTLP, SLSA v1.1 + CycloneDX 1.6 SBOM, `33–36 µs` Micro-Wasm, Teams & 4-role RBAC, TOTP 2FA, OIDC SSO, GitOps `culkibo.yaml`, **Historic 200-tool MCP Server (`-93.5%` / `~94%` core)** + Async Tasks + 3 MCP Apps, and Auto-Sleep Scale-to-Zero. **Zero phone-home.**
- **Optional Commercial Packs (`Pro` / `Enterprise` / `Cloud`):** Verified **100% offline via Ed25519 signed keys (`CKL1.*`)** — strictly for organizational scale & compliance: Managed Multi-Region Relay, Extended Status/Email White-Label Packs, Priority Support Bundles, Enterprise SCIM 2.0 / SAML 2.0, Continuous SIEM Audit Streaming, and Managed Multi-AZ Cloud Control Plane.

### Public Engineering Roadmap (Zero New Runtime Deps)

- [x] **v1.0 – v1.1 (Shipped):** Sub-50 MB (`49 MB` record) fast-path + `Server-Timing`, 140 pinned catalog apps, 12 DB engines, Sub-10ms Live Sync 2.0, SmartPack (18 stacks), DirectPush (`culkibo pussh`), Sovereign EdgeTunnel (`ET1`), World-First PaaS MCP Apps (`ui://culkibo/*`), SnapStream WAL-to-S3 + PR Preview DB Branching, Runtime-Only Fast Restart, OIDC `groups`→RBAC, and Offline Ed25519 Open-Core editions.
- [x] **v1.2.0 (Historic Cycle #23 Milestone Shipped — 92 Suites, 200 MCP Tools `-93.5%` / `~94%` Core & All-Time Speed Records):** **`50 MB RSS`** idle RAM (**141+ lazy services**, `49 MB` record), **`~370 kB`** lazy prod bundle (`0` Vite warnings), **`126.2 ms`** cold boot, **`11,382 req/s`** authed fast-path & **`10,824 req/s`** health, **`4,109 req/s`** mixed & **`3,222 req/s`** Express RBAC, **NEW RECORD `14,772 writes/s`** atomic JSON, **NEW RECORD `0.143 ms`** YAML anti-DoS, **`1.52 GB/s` SHA-256 & `1.46 GB/s` AES-256-GCM**, **`3,334 ev/s`** SQLite WAL, **`0.53 ms`** warm catalog, **Sub-ms Live Sync `0.99 ms` apply / `7.21 ms` E2E / `1.29 ms` rollback**, **Sub-50ms `49.7 ms`** 40-WS fan-out, and **`33–36 µs`** warm Micro-Wasm (`64 KiB` RAM); Next.js / React2Shell (`CVE-2025-55182`/`29927`/`49005`) SSR Firewall (`culkibo ssr-guard`), Container Registry Pull-Limit (`429`) & `registry:3` Mirror Guard, Session Cookie, Go 1.25 `Sec-Fetch-Site` CSRF & OAuth 2.1 PKCE `S256` Guard (`CVE-2026-26247`), SQLite WAL Checkpoint Starvation & NFS Corruption Guard, Build-`ARG`/`ENV` Secret Surface & `/run/secrets/` Migrator (`culkibo env-surface`, `Dokploy#3347`/`Coolify#10822`), JWT/OIDC Firewall (`culkibo jwt-audit`), Container Heap/`EMFILE` Leak Guard, GraphQL DoS Shield, ACME RFC 9773 ARI Budget, Archive Zip-Slip Firewall (`culkibo archive-guard`), CORS/CSP/SRI Firewall, PostgreSQL 32-Bit XID Wraparound Guard, Monorepo DAG (`Dokploy#5547`), Email Auth (`culkibo email-audit`), Shai-Hulud `pkg-guard`, Proxy Smuggling & MCPoison Guards, Valkey Fork CoW Guard, Distroless/`copa` Hardener, S3 WORM `0 B` KEK Rotation, Webhook Replay Firewall, Disk/Inode Guard, Sticky Region Shift, Credential Watchdog, Queue DLQ Gate, DB Query/Pool Guard, NetSeg Compiler, Ordered OTLP PII Scrubber, 4-Phase Zero-Drop Drain, VPA-Lite Rightsizer, Blameless Postmortems, OCI/SLSA Rekor Verifier, WS/SSE Flood Guard, DNS Cutover, PR Orphan Reaper, SPIFFE-Lite mTLS CA, Ollama/vLLM GPU, Post-MinIO S3, Read-Only DB Studio, FIDO2 Passkeys, OpenTofu IaC, MCP `2026-07-28` (**`200` tools, `-93.5%` / `~94%` core**, Async Tasks + 3 MCP Apps), 4-job Linux CI, and **92 integrated test suites**.
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
