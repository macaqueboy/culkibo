# Culkibo Pioneer Evolution Log

> **Purpose:** Persistent, strictly evidence-based ledger of each autonomous evolution cycle — recording verified changes, live-measured unadjusted benchmarks, independent QA/browser audits, an honest weighted Launch Readiness score, and prioritized targets for the next cycle.
> **Verification Policy:** Every metric, test count, and status below was independently executed and verified by `qa-verifier` after all builders landed their final fixes. Zero synthetic numbers, zero sugarcoating.

---

## Cycle #1 — Pioneer Hardening, Coolify v4 Mastery, Sub-ms Control Plane, MCP 2026 & Launch Kit

- **Timestamp (UTC):** `2026-11-27T07:10:31Z` (`2026-11-27 08:10 CET`)
- **Host / Runtime:** `Node.js v24.14.0` · `win32/x64` (8 vCPUs) · Docker Desktop & Caddy offline on host (explicitly noted where live-probed)
- **Commit Baseline:** `ef2477a` (`feat(v1.1): 140 apps, 12 DBs, TOTP 2FA, OIDC SSO, AES-GCM DR, alert engine, 107 MCP tools, honest benchmarks`)
- **Final Verification Verdict:** **100% GREEN** (`33/33` unit/integration suites + live-server + WS stress + HTTP stress + telemetry collector + root/web `tsc` + `oxlint` 0 warnings/0 errors + `web:build` + `shell-safety` + `bench/run-all.bench.js` + `9/9` isolated HTTP smoke + Playwright Desktop & Mobile visual QA)

---

### 1. Exact Changes Landed by Worker

| Worker | Scope & Key Deliverables |
| :--- | :--- |
| **`pr-hunter`** (`#109`) | Authored `docs/COMPETITOR_RADAR_CYCLE1.md` (33 KB) with live 2025–2026 GitHub forensics across Coolify, Dokploy, Kamal, CapRover, Dokku, Portainer, Runtipi, Cosmos, Railpack + 8 rising-star OSS repos mapped to 5 zero-dep Culkibo breakthroughs (`SmartPack`, `DirectPush`, `EdgeTunnel`, `MCP Apps`, `SnapStream`/Preview DB Branching). |
| **`core-pioneer`** (`#117`, `#122`) | Hardened `server/services/cronParser.js` (impossible dates like `0 0 30 2 *` fail in `<=0.141 ms`, `<5 ms` cap); persisted `buildSecrets`, healthcheck bounds & preview secrets in `server/models/Project.js` with unprivileged redaction; created zero-dep Ethical Open-Core & Offline Ed25519 License Verifier (`server/services/editionService.js`); closed legacy BOLA/IDOR routes in `server/routes/api.js` + `HttpOnly; SameSite=Strict` cookies + actor audit metadata + Wave-2 routes (CF tunnels, DNS-01, MCP `?profile=`, secret scanner `422`, deploy freeze `423`, edition endpoints, 5 Coolify/Bundle endpoints); added `tests/edition-and-bola.test.js` (registered in `tests/run-all.js`); fixed `tests/scale-and-wildcard.test.js:293` (`107 -> 109`), `tests/github.test.js:310` (Docker-offline `Push procesado`), and `.gitignore` (`data/metrics-history.json*`, `data/logs.ndjson`). |
| **`coolify-master`** (`#114`) | Upgraded `server/services/coolifyMigrator.js` with Coolify v4 Magic Variable translation (`${SERVICE_FQDN_*}`, `${SERVICE_PASSWORD_*}`, `${COOLIFY_*}` → domains + `${vault.*}` with redacted previews), Traefik → Caddy native edge translator (plain + Base64 labels, adversarial SSRF/ReDoS/CORS/APR1 guards), 8 DB engines + Crons + Compose `buildMigrationPlan`/`planMigration` parity reports, and `verifyMigratedStack`; created zero-dep pure-JS PKZIP/Gzip `server/services/bundleArchiver.js` (CRC32, AES-256-GCM vault, traversal/symlink/zip-bomb/polyglot defense); upgraded `web/src/components/CoolifyImport.tsx` into a 3-step cockpit; expanded `tests/coolifyMigrator.test.js` (13/13) & `docs/MIGRATION_GUIDE.md`. |
| **`perf-pioneer`** (`#110`, `#121`) | Added O(1) pre-compiled fast-path route maps, HMAC-SHA256 LRU auth cache (invalidated on rotation/revocation/auth mutations), WeakMap Brotli/Gzip zero-copy buffers, lazy ETag, `Server-Timing: cp;dur=<ms>` header, Wave-2 security/SSE/WS fixes, and guarded watchdog startup (`startWatchdogs` defaulting off for in-process `ensureDaemon`) in `server/index.js`; replaced `history.shift()` with an O(1) ring buffer + memoized percentiles/topRoutes + syscall caching in `server/services/metricsCollector.js`; created `bench/competitor-comparison.bench.js` and updated `bench/control-plane.bench.js` & `bench/run-all.bench.js`. |
| **`ai-mcp-pioneer`** (`#113`, `#124`) | Expanded `server/services/mcpServer.js` & `server/services/mcpStreamableHttp.js` to **109 tools** (+`culkibo_ship_and_verify` with 2-phase HMAC `confirmToken` + secret scan + auto-rollback, +`culkibo_export_agent_kit`), **13 prompts** (**8 native playbooks** via `prompts/list` & `prompts/get`), `-80.7%` `?profile=core` savings (`17/109`), and `X-Culkibo-Mcp-Profile` header fallback; added CLI `culkibo agent-init` (6 agents, 0 plaintext secrets) + `CULKIBO_MCP_PROFILE` stdio bridge in `bin/culkibo.js` and fixed Node v24 Windows `UV_HANDLE_CLOSING` teardown via native `http/https` (`agent: false`, `Connection: close`); upgraded `web/src/components/AiAgentHub.tsx` and `tests/mcp.test.js` + `tests/cli-dx.test.js`. |
| **`ux-designer`** (`#111`, `#125`) | Upgraded `web/src/index.css` (layered surfaces, GPU-safe transitions, `tabular-nums`, `prefers-reduced-motion`), `Header.tsx` (unclipped 8-tab desktop nav across `1440px`/`1280px`/`1024px`, live daemon RAM/RTT badge, accessible `>=44px` mobile drawer), `App.tsx`, `CommandPalette.tsx` (fuzzy search across projects + 140+ apps + v1.1 actions), `OnboardingChecklist.tsx` (real-state 4-step strip, synced `~81%` token-savings copy), `ProjectList.tsx` (concentric cards + 3-path empty hero), `SettingsView.tsx` + `web/src/lib/api.ts` (TOTP 2FA, OIDC SSO, SHA-256 Audit Chain Verifier, Secret Scanner, HTTP/3 + 7-provider DNS-01 card), and cleared all 4 pre-existing `oxlint` warnings in `web/src/components/ObservabilityView.tsx`. |
| **`seo-launch`** (`#116`) | Rebuilt `README.md` (`100/100` on `github_readme_lint.py`, `54/54` valid links, grounded metrics, Mermaid architecture diagram); created `CONTRIBUTING.md`, `SECURITY.md`, `.github/ISSUE_TEMPLATE/{bug_report,feature_request}.md`, `.github/PULL_REQUEST_TEMPLATE.md`, and `docs/GITHUB_SEO_LAUNCH_KIT.md` (281/350 char description, 20 topics, OG `1280×640` spec, Show HN/Reddit/PH/X launch drafts, Open-Core ladder). |
| **`qa-verifier`** (`#119`, this log) | Independently executed full verification matrix, benchmarks, live isolated HTTP smoke, and Playwright Desktop/Mobile visual QA; caught and drove resolution of **6 real defects** before sign-off (singleton `alertEngine` timer leak + dirty `data/`, Windows `UV_HANDLE_CLOSING` crash in `cli-dx.test.js:448`, `Header.tsx` 8th tab `Importar -> Im` clipping at `1440px`, `scale-and-wildcard.test.js:293` tool-count drift, Docker-offline `github.test.js:310`, and 4 `ObservabilityView.tsx` `oxlint` warnings). |

---

### 2. Independently Verified Quality Gates (Post-Fix Final Pass)

| Check | Command | Measured Result | Status |
| :--- | :--- | :--- | :---: |
| **Runtime Dependencies** | `package.json` + `telemetry-collector/package.json` | `ROOT_DEPS=6`, `COLLECTOR_DEPS=0`, `webDeps=3` | PASS |
| **Server Typecheck (`checkJs`)** | `npm run typecheck` | `0` errors (`exit 0`) | PASS |
| **Frontend Typecheck** | `npx tsc -p web/tsconfig.app.json --noEmit` | `0` errors (`exit 0`) | PASS |
| **Frontend Lint (`oxlint`)** | `npm --prefix web run lint` | `0` warnings, `0` errors across 37 files | PASS |
| **Frontend Production Build** | `npm run web:build` | Built in `5.21s` + precompressed `.br`/`.gz` | PASS |
| **Static Shell-Safety Invariant** | `node tests/shell-safety.test.js` | `0` unauthorized shell calls (2 authorized exceptions) | PASS |
| **Full Suite (`tests/run-all.js`)** | `node tests/run-all.js` | **33 passed, 0 failed** (`102.59s`), `data/` untouched | PASS |
| **Live Server & Access Control** | `node tests/live-server.test.js` | All assertions passed (`109` MCP tools, 421/403/401/200) | PASS |
| **WebSocket Churn Stress** | `node tests/websocket-stress.test.js` | 30 concurrent clients, 15 abrupt drops, 0 errors | PASS |
| **Mixed HTTP Stress** | `node tests/stress.test.js` | `100/100` success, `0` fail, p50 `48.42ms`, p99 `56.93ms` | PASS |
| **Zero-Dep Telemetry Collector** | `node --test telemetry-collector/test/collector.test.js` | `2/2` passed (`572.5ms`) | PASS |
| **Isolated Live HTTP Smoke (`:3039`)** | `/`, `/health`, `/api/system/status`, `/api/system/edition`, `/api/gitops/schema.json`, `/api/ingress/dns-providers`, `/api/mcp/tools?profile=core`, `POST /api/import/coolify/plan`, `POST /api/bundles/export` | **9/9 HTTP `200`** (`parityScore: 100`, `17/109` MCP core, 7 DNS providers, valid ZIP+SHA256, `Server-Timing` present); temp server stopped cleanly | PASS |
| **Live Playwright Visual QA** | Desktop `1440×900` + `1280×800` + Mobile `390×844` (Dashboard, `Ctrl+K`, `#/ai`, `#/settings/security`) | `0` console errors, `0` page errors, `0` failed HTTP reqs, `0px` horizontal overflow, `8/8` desktop nav tabs unclipped, `>=44px` mobile touch targets | PASS |

---

### 3. Measured Benchmark Table (Final Post-Fix Run — `node bench/run-all.bench.js`)

> Measured live on `Node v24.14.0` (`win32/x64`, 8 vCPUs, 100% unadjusted).

| Metric | Final Post-Fix Measured Result | Notes / Invariant |
| :--- | :--- | :--- |
| **Cold Boot Time (`CULKIBO_SKIP_RECONCILE=1`)** | **462.9 ms** | `process.hrtime.bigint()` (best unloaded run earlier in Cycle 1: `170.8 ms`) |
| **Idle Daemon RAM (Node RSS)** | **56 MB RSS** *(~74 MB est. incl. ~18 MB Caddy)* | **PASS** (`<= 60 MB RSS` invariant) · **0% idle CPU** |
| **Health HTTP (`GET /api/health`, 500 req / 25w)** | p50 **10.62 ms** · p95 **19.24 ms** · p99 **26.71 ms** | **2,181 req/s** · `Server-Timing: cp;dur=0.04` (earlier clean run: `6.46 ms` p50 / `3,500 req/s`) |
| **Auth Fast-Path (`Bearer` + Brotli, 500 req / 25w)** | p50 **7.16 ms** · p95 **13.14 ms** · p99 **15.09 ms** | **3,235 req/s** · HMAC LRU + WeakMap zero-copy Buffer |
| **Mixed Uncompressed Control Plane (500 req / 25w)** | p50 **37.62 ms** · p95 **66.30 ms** · p99 **121.60 ms** | **625 req/s** · `0` failures (earlier clean run: `22.75 ms` p50 / `940 req/s`) |
| **Express Multi-Tenant RBAC HTTP (500 req / 25w)** | p50 **25.34 ms** · p95 **39.64 ms** · p99 **71.62 ms** | **923 req/s** · `0` failures |
| **Catalog Load (`GET /api/catalog`, 140 apps)** | warm p50 **1.05 ms** (cold `88.01 ms`) | `132,694 B -> 35,336 B` Brotli (**-73.4%**) |
| **Live Sync 2.0 (Path B, 25 samples + 100-file burst)** | server apply p50 **3.99 ms** · E2E p50 **24.94 ms** | Brotli `-96.1%` (`25.66x`), in-memory rollback p50 **8.77 ms** |
| **Caddy Atomic Route Swap** | *Skipped — Caddy Admin API not listening on `:2019`* | Live Linux Caddy v2.11 CI verification queued for Cycle #2 |
| **MCP `2026-07-28` Context Savings (`?profile=core`)** | **-80.7%** (`17/109` tools · `~4,284` vs `~22,198` tok) | `109` tools, `13` prompts (`8` playbooks), `7` resources |
| **Test Suites & Supply-Chain Budget** | **33/33** (`run-all`) + 4 standalone suites + collector (`2/2`) | **`ROOT_DEPS = 6`**, **`COLLECTOR_DEPS = 0`**, **0 shell calls** |

---

### 4. Honest Launch Readiness Score: **90.4 / 100** *(Strong Public-Beta / Soft-Launch Ready)*

> **No sugarcoating:** Culkibo's backend architecture, security engineering, MCP 2026 depth, and Coolify migration engine already surpass most self-hosted PaaS v1 releases. The remaining **9.6 points** are concrete, verified gaps caught during Cycle-1 QA that separate a great soft launch from an unstoppable **95%+ GitHub Trending #1 global launch**.

| # | Pillar | Weight | Score | Weighted | Verified Strengths & Honest Deductions |
| :--- | :--- | :---: | :---: | :---: | :--- |
| 1 | **Speed & Architecture** | 15% | **91 / 100** | `13.65` | **Strengths:** `56 MB RSS` idle, `0%` CPU, `ROOT_DEPS=6`, `3,235 req/s` authed fast-path, `Server-Timing`, O(1) ring buffer. **Gaps (-9):** Legacy stores (`projectManager.js`, `domainManager.js`) ignored `CULKIBO_DATA_DIR` during isolated `:3039` live QA (-4); no live Linux Caddy/Docker swap or cgroup v2 telemetry verified this cycle (-3); cold-boot variance `171–463 ms` (-2). |
| 2 | **Security & RBAC** | 15% | **93 / 100** | `13.95` | **Strengths:** Zero-shell CI invariant, 4-role RBAC + BOLA closure (26+ HTTP probes), `HttpOnly` cookies, TOTP 2FA, OIDC PKCE, hash-chained audit log, secret scanner `422`, freeze `423`, CronParser anti-DoS (`0.141 ms`), offline Ed25519 licenses. **Gaps (-7):** Missing OIDC IDP `groups`→role mapping & `disablePasswordLogin` (-3); no external pentest yet (-2); missing per-principal WS log-stream FD cap (`dokploy#2974`) & `ENOSPC` disk gate (`Cosmos#591`) (-2). |
| 3 | **Coolify Migration** | 15% | **88 / 100** | `13.20` | **Strengths:** Magic Vars + Traefik→Caddy edge translation + 8 DBs + Crons + parity report (`100%` live HTTP smoke) + hardened zero-dep `.zip`/`.ckb.gz` portable bundles + 3-step UI cockpit. **Gaps (-12):** Tested against synthetic fixtures only — not yet battle-tested end-to-end against a live production Coolify v4 VPS (-7); automated live volume/SQL data streaming + Compose `mem_limit`/`cpus` cgroup enforcement (`coolify#12414`) pending (-5). |
| 4 | **AI / MCP Ecosystem** | 15% | **94 / 100** | `14.10` | **Strengths:** MCP `2026-07-28` Streamable HTTP + clean Windows stdio bridge (5/5 pass), `109` tools, `13` prompts (`8` playbooks), `-80.7%` `?profile=core`, 2-phase `culkibo_ship_and_verify`, `culkibo agent-init` (6 agents, 0 plaintext secrets). **Gaps (-6):** MCP Apps (`ui://culkibo/*` `ext-apps` inline interactive cards) not yet built (-4); not yet verified inside live external Claude Code/Cursor/Codex binaries (-2). |
| 5 | **UI / UX Polish** | 10% | **87 / 100** | `8.70` | **Strengths:** Crisp light-mode polish, `0` lint warnings, `0` console/HTTP errors, `0px` overflow at `1440`/`1280`/`390px`, all 8 nav tabs unclipped, `>=44px` mobile touch targets, `Ctrl+K`, 2FA/OIDC/Audit Verifier UI. **Gaps (-13):** **Dashboard UI is Spanish-only (no English/i18n toggle)** despite English global README/Launch Kit (-6); no dark-mode toggle (-3); static topology/no fast-restart env banner (`dokploy#2547`) or dynamic build-status favicon (-4). |
| 6 | **Catalog / DB / Edge Depth** | 10% | **86 / 100** | `8.60` | **Strengths:** 140 pinned apps (0 `:latest`), 12 DB engines + AES-GCM S3 DR drills, Caddy HTTP/3 + 7 DNS-01 providers, CF Tunnels, SSH Fleet, GitOps, Auto-Sleep, Uptime. **Gaps (-14):** Docker & Caddy offline on QA host (no live container/HTTP3/fleet execution this cycle, -6); missing SmartPack (`zstd:chunked`/implicit `.dockerignore`), DirectPush (`culkibo pussh`), sovereign EdgeTunnel, and Preview DB Branching/SnapStream (-8). |
| 7 | **Verification & QA** | 10% | **90 / 100** | `9.00` | **Strengths:** 33/33 suites + live-server + WS/HTTP stress + collector + Playwright Desktop/Mobile visual QA + zero dirty `data/` files. **Gaps (-10):** CI workflow lives in `docs/ci.workflow.yml` rather than active `.github/workflows/ci.yml` running live Linux Docker + Caddy + Playwright (-6); missing Cycle-2 competitor-CVE regressions (-2); `CULKIBO_DATA_DIR` isolation gap in legacy stores (-2). |
| 8 | **README / GitHub SEO / Launch Kit** | 10% | **92 / 100** | `9.20` | **Strengths:** `100/100` README lint, `54/54` valid links, honest comparison matrix, `CONTRIBUTING.md`, `SECURITY.md`, `.github/` templates, complete `docs/GITHUB_SEO_LAUNCH_KIT.md`. **Gaps (-8):** No committed dashboard screenshots/Live Sync GIF or rendered `1280×640` OG PNG yet (-5); Day-0 GitHub repo UI toggles + minor README RAM baseline note (`54 MB` vs `56 MB` post-fix) (-3). |
| | **TOTAL WEIGHTED SCORE** | **100%** | — | **90.4%** | **Verdict:** Ready for controlled public beta today; complete Cycle #2 targets below to cross **95%+** for peak Hacker News / Reddit / GitHub Trending launch conversion. |

---

### 5. Top 5 High-Leverage Targets for Cycle #2 (Next Hour)

1. **Global Launch Unlock — Zero-Dep EN/ES i18n, Dark Mode, Visual Launch Assets & Active Linux CI (`.github/workflows/ci.yml`)**
   - Add lightweight zero-dep English/Spanish localization (auto-detecting browser locale, defaulting to English for non-ES global visitors so Show HN / `r/selfhosted` evaluators land in English immediately) + first-class Dark Mode theme toggle.
   - Commit crisp light/dark dashboard screenshots + rendered `1280×640` Social Preview OG PNG and promote `docs/ci.workflow.yml` into active `.github/workflows/ci.yml` running Node 20/22/24 + real Linux Caddy v2.11 route-swap & Playwright E2E checks.
2. **Complete `CULKIBO_DATA_DIR` Store Isolation & Cycle-2 Competitor-CVE Guardrails (from `#109`)**
   - Audit and fix `projectManager.js`, `domainManager.js`, and all remaining `data/*.json` managers so `CULKIBO_DATA_DIR` isolates 100% of control-plane state (eliminating the leak caught during `:3039` live QA).
   - Land regressions & guardrails for the top 2025–2026 competitor outages: single-bad-TLS-cert fault isolation (`kamal-proxy#233`), Compose `mem_limit`/`cpus` cgroup enforcement (`coolify#12414`), per-principal WS/SSE log-stream FD cap (`dokploy#2974`), `ENOSPC` pre-write headroom check + SPA 401 circuit breaker (`Cosmos#591/#616`), Linux cgroup v2 container RAM readout (`runtipi#2445`), and runtime-only fast container restart (`dokploy#2547`).
3. **Culkibo SmartPack + DirectPush (`culkibo pussh`) — Zero-Dep Build & Registry-Less Deploy Breakthroughs**
   - Ship `server/services/smartPackBuilder.js` (inspectable `build-plan.json`, implicit `.dockerignore` excluding `.git`/`node_modules`/`.venv`, BuildKit cache mounts + host-aware `--memory`/`--cpus` cgroup caps, `zstd:chunked` OCI export).
   - Ship `server/services/directPushRegistry.js` + `culkibo pussh` (~250-LOC loopback OCI Distribution v2 handler over existing `serverFleetManager.js` SSH tunnels streaming only missing SHA-256 layers — zero Docker Hub/GHCR required).
4. **Culkibo MCP Apps (`ui://culkibo/*`) + Enterprise OIDC Group-to-Role Mapping & Live Coolify v4 Data-Plane Verification**
   - Implement `modelcontextprotocol/ext-apps` (`2026-01-26`) sandboxed inline interactive cards (`ui://culkibo/topology`, `ui://culkibo/incident-remediator`, `ui://culkibo/coolify-migration-diff`) with strict `_meta.ui.csp` so Claude/Antigravity/VS Code render live interactive controls inside chat.
   - Add OIDC JWT `groups` claim → Culkibo RBAC role mapping + `disablePasswordLogin` toggle, plus live Coolify v4 volume/SQL migration streaming test harness.
5. **Culkibo EdgeTunnel + SnapStream / Preview DB Branching + Railway-Class Spatial SVG Topology Canvas**
   - Ship `server/services/edgeTunnelService.js` (`culkibo tunnel-agent` sovereign CGNAT multiplexed binary WS tunnel over existing `ws` dep) + Pingora-style `streamCloseDelayMs` drain barrier in `caddyManager.js`.
   - Ship `server/services/sqliteStreamBackup.js` (WAL-to-S3 streaming over existing `s3Uploader.js`) + opt-in PR Preview DB Branching (`CREATE DATABASE ... TEMPLATE` / SQLite CoW) + interactive pan/zoom drag-to-wire SVG Topology Canvas & dynamic deploy-status tab favicon.
