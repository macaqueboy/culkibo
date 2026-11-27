# Culkibo — GitHub SEO & Launch-Tomorrow Go-To-Market Kit

> **Target Repository:** `macaqueboy/culkibo` · **Release Baseline:** `v1.2.0` (Cycle 3 Ready) · **License:** `Apache-2.0`
> **Evidence Policy:** Every benchmark metric, tool count, MCP App URI, SBOM count, and competitive citation in this launch kit is grounded in live-measured output (`node bench/run-all.bench.js`), verified source files, [`docs/EVOLUTION_LOG.md`](EVOLUTION_LOG.md), and [`docs/COMPETITOR_RADAR_CYCLE1.md`](COMPETITOR_RADAR_CYCLE1.md) / [`docs/COMPETITOR_RADAR_CYCLE3.md`](COMPETITOR_RADAR_CYCLE3.md). Zero invented numbers.

---

## 1. Exact GitHub Repository Metadata (Copy-Paste Ready)

### Repository Description (307 / 350 chars — High-Intent Keyword Optimized)

```text
The 54 MB, zero-shell, AI-native self-hosted PaaS. Deploy 140+ apps, 12 DBs, Live Sync 2.0 (1.75 ms), SmartPack, DirectPush (SSH OCI), EdgeTunnel, Caddy HTTP/3, CycloneDX SBOM, 1-click Coolify v4 migration & 111 MCP tools + inline MCP Apps for Claude Code, Cursor & Antigravity. Coolify/Dokploy alternative.
```

> **SEO rationale:** Front-loads the strongest architectural hooks (`54 MB`, `zero-shell`, `AI-native`, `self-hosted PaaS`), anchors competitor-switching queries (`Coolify`, `Dokploy alternative`), and captures the 2026 AI-agent, supply-chain & registry-less deploy wave (`MCP`, `MCP Apps`, `Claude Code`, `Cursor`, `Antigravity`, `SmartPack`, `DirectPush`, `EdgeTunnel`, `CycloneDX SBOM`) within GitHub's 350-character cap.

### Website / Homepage URL

- Set GitHub `Website` field to your live docs/landing page (e.g. `https://culkibo.dev` once live, or `https://github.com/macaqueboy/culkibo#30-second-quick-start` on Day 0 so the header link never sits empty).

### Exact 20 GitHub Topics (Max Allowed = 20, High-Intent Search Mix)

Paste these exact 20 lowercase hyphenated tags in GitHub **Settings → About → Topics**:

```text
self-hosted
paas
coolify-alternative
dokploy-alternative
mcp-server
model-context-protocol
claude-code
cursor
docker
caddy
devops
deployment
gitops
zero-downtime
live-sync
cloudflare-tunnel
rbac
homelab
nodejs
open-source
```

| Cluster | Topics | Search Intent Captured |
| :--- | :--- | :--- |
| **Core Category (4)** | `self-hosted`, `paas`, `devops`, `deployment` | Broad discovery & GitHub Trending topic feeds |
| **Competitor Switching (2)** | `coolify-alternative`, `dokploy-alternative` | High-conversion developers actively looking to migrate |
| **2026 AI-Agent Wave (4)** | `mcp-server`, `model-context-protocol`, `claude-code`, `cursor` | Fastest-growing developer search cluster on GitHub in 2026 |
| **Infrastructure & Edge (5)** | `docker`, `caddy`, `gitops`, `zero-downtime`, `cloudflare-tunnel` | Technical evaluators comparing proxy, TLS & IaC architecture |
| **Differentiators & Stack (5)** | `live-sync`, `rbac`, `homelab`, `nodejs`, `open-source` | Long-tail high-intent self-hosters & enterprise security evaluators |

---

## 2. Committed Visual Launch Assets (100% English, Privacy-Scrubbed & Ready!)

All publication-grade launch assets are already rendered, privacy-scrubbed (zero real host IPs, zero console errors, `0px` horizontal overflow), visually inspected, and committed in [`docs/assets/`](assets/social-preview.png):

| Asset Path | Dimensions & Format | Usage |
| :--- | :--- | :--- |
| [`docs/assets/social-preview.png`](assets/social-preview.png) | `1280 × 640 px` PNG (`218 KB`) | **GitHub Settings → Social Preview** upload + X/Twitter, Reddit, LinkedIn & Product Hunt hero card |
| [`docs/assets/social-preview.svg`](assets/social-preview.svg) | `1280 × 640` vector SVG | Editable master source for future version bumps |
| [`docs/assets/live-sync-demo.svg`](assets/live-sync-demo.svg) | `880 × 360` animated SVG (`12.8 KB`) | README hero flow showing `1.75 ms` Merkle delta, `-96.1%` Brotli & inline `ui://culkibo/topology` MCP App (zero scripts/deps) |
| [`docs/assets/dashboard-dark-en.png`](assets/dashboard-dark-en.png) | `1440 × 900 px` PNG (`103 KB`) | README Obsidian Dark Mode showcase + Product Hunt slide #2 + X Thread Post #2 |
| [`docs/assets/dashboard-light-en.png`](assets/dashboard-light-en.png) | `1440 × 900 px` PNG (`101 KB`) | README Crisp Light Mode side-by-side + Product Hunt slide #3 |
| [`docs/assets/topology-dark-en.png`](assets/topology-dark-en.png) | `1440 × 900 px` PNG (`101 KB`) | README Spatial SVG Topology Canvas & Click-to-Link DB Injection showcase + Product Hunt slide #4 |
| [`docs/assets/ai-agent-hub.png`](assets/ai-agent-hub.png) | `1440 × 1080 px` PNG (`152 KB`) | README 100%-English AI Agent Hub (111 MCP tools, `-81.2%` profile, 1-click Agent Cards & Interactive `ui://culkibo/*` MCP Apps) |

---

## 3. Ready-to-Publish Launch Drafts

> **Launch Timing Playbook:**
> - **Tuesday–Thursday, 13:30–15:00 UTC** (9:30–11:00 AM US Eastern / 14:30–16:00 CET) maximizes overlap between European engineers and US morning traffic on HN, Reddit, and X.
> - Stagger channels across 48 hours: **Day 1 AM:** Show HN + X Thread → **Day 1 PM:** `r/selfhosted` + `r/docker` → **Day 2:** Product Hunt + Dev.to / Hashnode deep-dive technical post.

---

### Draft A — Show HN (`news.ycombinator.com/submit`)

**Title (79 chars — HN sweet spot, factual, zero hype):**
```text
Show HN: Culkibo – A 54 MB, zero-shell, AI-native self-hosted PaaS (Apache-2.0)
```

**First Comment (Author Technical Context — post immediately after submitting):**
```text
Hi HN! I built Culkibo v1.2 (Apache-2.0) because I kept running into three frustrations while self-hosting apps and iterating with AI coding agents (Claude Code, Cursor, Antigravity):

1. Control-plane bloat: Most modern self-hosted PaaS dashboards need 500 MB–1.5 GB of RAM just for the panel (Laravel + Horizon + Postgres + Redis + Soketi, or Next.js + Postgres + Redis + Traefik), which breaks on small 512 MB–1 GB VPS nodes.
2. Shell-injection attack surface & fragile proxies: Too many PaaS tools interpolate user/repo/domain fields into shell strings, silently ignore Compose resource limits, or drop routes on proxy/TLS hiccups.
3. The AI-agent iteration tax: Waiting 1–4 minutes for a full Docker rebuild on every edit breaks flow, and dumping 100+ raw MCP tool schemas into an LLM destroys context windows.

How Culkibo approaches this differently:

- 54 MB idle RSS, 6 runtime npm dependencies, CycloneDX 1.6 SBOM: Single Node.js control plane (express, ws, chokidar, commander, cors, dotenv — 0 deps in the optional telemetry collector) paired with Caddy v2.11's JSON Admin API for synchronous, zero-poll route swaps, native HTTP/3, per-domain TLS fault isolation, Pingora-style drain barriers, and 103 Early Hints. Authenticated Bearer+Brotli fast-path hits 3,606 req/s (`Server-Timing: cp;dur=0.04`). Every `v*` release automatically publishes a CycloneDX 1.6 SBOM (`GET /api/system/sbom` / `npm run release:sbom`) and `CHECKSUMS.sha256`.
- Zero shell construction (`shell: false`): Every subprocess (`docker`, `git`, `caddy`, `ssh`, `cron`) goes through tokenized `argv` arrays (`server/services/safeCommand.js`), secrets travel via ephemeral `0600` `--env-file` or `GIT_ASKPASS`, and `node tests/shell-safety.test.js` statically verifies 0 unauthorized shell calls on every commit.
- Live Sync 2.0 + Fast Env Restart ("The Forge" & "The Citadel"): Incremental binary WebSocket sync (`/ws/sync`) with Brotli framing (-96.1% wire savings on a 100-file TSX burst), Merkle tree verification, and in-memory rollback (1.75 ms server apply p50, 11.55 ms E2E, 2.94 ms rollback). Runtime-only env var edits trigger a zero-rebuild Fast Restart (~1.5 s) instead of rebuilding the image.
- Zero-dep Pioneer Stack (all wired in CLI & UI):
  - SmartPack (`culkibo smartpack`): 18-stack deterministic build plans, implicit `.dockerignore`, BuildKit 1.7 cache mounts, host-aware cgroup build caps, and `zstd:chunked` OCI export.
  - DirectPush (`culkibo pussh`): loopback-only OCI Distribution v2 registry over existing SSH tunnels — streams only missing SHA-256 layers with zero Docker Hub or GHCR required.
  - Sovereign EdgeTunnel (`culkibo tunnel-agent`): multiplexed binary WebSocket CGNAT tunnel (`ET1`) with no Cloudflare lock-in (plus 1-click Cloudflare Tunnels if you want them).
  - SnapStream + PR Preview DB Branching: incremental encrypted SQLite WAL-to-S3 streaming (PITR) + PostgreSQL `TEMPLATE` / SQLite CoW PR preview database clones with automatic teardown.
- Native MCP 2026-07-28 + World-First PaaS MCP Apps (`ui://culkibo/*`): 111 tools, 13 playbooks (`prompts/list`), and 3 sandboxed `ext-apps` interactive HTML cards (`topology`, `incident-remediator`, `coolify-migration-diff`, locked-down `default-src 'none'` CSP), verified end-to-end against a spawned stdio JSON-RPC client. Passing `?profile=core` drops schema context size by 81.2% (~4,315 vs ~22,972 tokens).
- Batteries included without paywalling security: 100% EN/ES Obsidian Dark & Light UI, Spatial SVG Topology Canvas with click-to-link DB injection, 140 pinned catalog apps (0 `:latest`, 0 `docker.sock`), 12 managed DB engines, AES-256-GCM S3/R2 DR drills, 4-role RBAC + TOTP 2FA + OIDC PKCE (`groups` → RBAC mapping), hash-chained audit log, multi-server SSH fleet, declarative `culkibo.yaml` GitOps, auto-sleep scale-to-zero, 7-provider DNS-01 wildcard TLS, and a 1-click Coolify v4 migrator (translates Magic Vars + Traefik labels to Caddy + zero-shell Volume/SQL streaming + `.zip` portable bundles, verified via full Mock Coolify v4 E2E replay).

Honest caveats:
- Benchmarks in the README were measured on Node v24.14.0 (win32/x64); competitor RAM figures are explicitly labeled as documented architecture baselines, not locally executed benchmarks. Reproduce every Culkibo metric with `node bench/run-all.bench.js`, and check `.github/workflows/ci.yml` for our 4-job Linux CI (Node 20/22/24 + Live Caddy v2.11 + Docker BuildKit SmartPack/SBOM + Playwright QA).
- Telemetry is opt-out anonymous crash/health reporting with an 11-phase PII scrubber and `telemetry preview` inspection (`CULKIBO_TELEMETRY=0` or `DO_NOT_TRACK=1` disables it immediately).

Repo: https://github.com/macaqueboy/culkibo

Happy to answer any questions about the Caddy Admin API design, zero-shell static checker, DirectPush SSH OCI v2 shim, EdgeTunnel binary framing, CycloneDX 1.6 provenance, or MCP Apps sandbox!
```

---

### Draft B — Reddit `r/selfhosted` (and cross-post to `r/docker`)

**Title:**
```text
I built Culkibo v1.2 (Apache-2.0): a 54 MB RAM, zero-shell self-hosted PaaS with Caddy HTTP/3, 140 pinned apps, 12 DBs, DirectPush (no Docker Hub), Sovereign EdgeTunnel, 1-click Coolify v4 migration & 111 MCP tools
```

**Body:**
```markdown
Hey r/selfhosted!

I wanted a self-hosted PaaS that could actually live comfortably on a cheap **512 MB – 1 GB VPS** without giving up multi-server fleets, RBAC/2FA/OIDC, encrypted S3 backups, or Railway/Linear-grade dark-mode UX — and without needing Docker Hub/GHCR or Cloudflare lock-in.

So I built **Culkibo v1.2** (100% Apache-2.0 open source, zero paywalled self-hosted features, 100% English & Spanish UI with Obsidian Dark/Light mode):
https://github.com/macaqueboy/culkibo

### What makes it genuinely different
- **54 MB idle RSS daemon** (~72 MB total with Caddy, 0% idle CPU, **6 runtime npm deps**, **CycloneDX 1.6 SBOM**). Reproducible via `node bench/run-all.bench.js`.
- **Zero shell construction (`shell: false`)**: Every `docker`, `git`, `caddy`, and `ssh` call uses strict `argv` arrays, CI-verified by `tests/shell-safety.test.js`. No shell-injection RCE class.
- **Zero external registry or tunnel lock-in (all built into CLI & UI)**:
  - **DirectPush (`culkibo pussh`)**: loopback OCI v2 layer-delta push directly over your SSH fleet tunnel — no Docker Hub or GHCR needed.
  - **Sovereign EdgeTunnel (`culkibo tunnel-agent`)**: self-hosted multiplexed WebSocket tunnel behind CGNAT/homelab NAT (plus 1-click Cloudflare Tunnels if you prefer CF).
  - **SmartPack (`culkibo smartpack`)**: 18-stack deterministic build plans with automatic `.dockerignore`, BuildKit 1.7 cache mounts, and cgroup RAM/CPU caps so builds never OOM your VPS.
- **Caddy v2.11 atomic ingress**: Native HTTP/3 (QUIC), **7-provider DNS-01 wildcard TLS** (Cloudflare, Hetzner, DigitalOcean, Route 53, Porkbun, Bunny, DuckDNS), `103 Early Hints`, Basic Auth, IP Allowlists, and ForwardAuth.
- **140 pinned 1-click catalog apps** (zero `:latest` tags, zero `docker.sock` mounts) + **12 managed database engines** with **AES-256-GCM S3/R2 DR drills**, **SnapStream** (incremental encrypted SQLite WAL-to-S3 streaming), and **PR Preview DB Branching**.
- **Built-in features people keep requesting in Coolify/Dokploy**:
  - Native **Auto-Sleep Scale-to-Zero** (no Sablier hacks)
  - **Runtime-Only Fast Restart** (edit env vars without triggering a 3-minute rebuild!)
  - **Spatial SVG Topology Canvas** with click-to-link `DATABASE_URL` injection
  - Declarative **`culkibo.yaml` GitOps** + portable `.zip` stack bundles
  - **Multi-Server SSH Fleet** (TOFU + ControlMaster + AES-256-GCM key vault)
  - **Teams + 4-role RBAC + TOTP 2FA + OIDC SSO (`groups` → role mapping) + hash-chained tamper-evident audit log**
- **1-Click Coolify v4 Migrator (read-only on source, E2E replay tested)**: Translates Coolify Magic Variables (`SERVICE_FQDN_*`, `SERVICE_PASSWORD_*`) into domains & `${vault.*}`, converts Traefik labels into Caddy routes, and generates zero-shell Volume & SQL transfer commands before you switch DNS.
- **Live Sync 2.0 + Native MCP (`2026-07-28`) + Inline MCP Apps**: Binary hot-sync (`1.75 ms` apply, `-96.1%` Brotli) + **111 MCP tools**, **13 playbooks**, **3 sandboxed `ui://culkibo/*` MCP Apps**, and `?profile=core` (**-81.2% token savings**) for Claude Code, Cursor, Windsurf, Codex & Antigravity.

### Quick try (Docker Compose)
```bash
git clone https://github.com/macaqueboy/culkibo.git && cd culkibo
docker compose up -d --build
```

### Radical honesty on privacy & licensing
- **License:** Apache-2.0. Every single feature above is 100% free in Community Edition with zero artificial caps. Optional commercial packs (offline Ed25519 keys) are strictly for Enterprise SCIM/SAML, white-label, and compliance exports.
- **Telemetry:** Opt-out anonymous crash/health stats (11-phase PII scrubber, preview exact payload via `culkibo telemetry preview`, disable instantly via `CULKIBO_TELEMETRY=0` or `DO_NOT_TRACK=1`).

Would love honest feedback from people running Coolify, Dokploy, CapRover, or Kamal — especially if you try the Coolify migration parity preview or run `node bench/run-all.bench.js` on your own VPS!
```

---

### Draft C — Product Hunt Listing

- **Name:** `Culkibo`
- **Tagline (59 / 60 chars):** `54 MB, zero-shell, AI-native self-hosted PaaS with MCP Apps`
- **Short Description (256 / 260 chars):**
  `Deploy 140+ pinned apps, 12 DBs, Caddy HTTP/3, SmartPack, registry-less DirectPush, Sovereign EdgeTunnel & Live Sync 2.0 (1.75 ms) on a 54 MB open-source control plane. Built for Claude Code, Cursor & Antigravity with 111 MCP tools, 3 MCP Apps & Coolify import.`
- **Topics:** `Developer Tools`, `Open Source`, `DevOps`, `Artificial Intelligence`, `Cloud Infrastructure`
- **Gallery Order (5 slides — ALL committed in `docs/assets/`!):**
  1. [`docs/assets/social-preview.png`](assets/social-preview.png) — Hero Architecture & Verified Benchmarks card (`1280×640`)
  2. [`docs/assets/dashboard-dark-en.png`](assets/dashboard-dark-en.png) — Obsidian Dark Mode Dashboard + Live RAM Pill + Onboarding (`1440×900`)
  3. [`docs/assets/topology-dark-en.png`](assets/topology-dark-en.png) — Interactive Spatial SVG Topology Canvas & Click-to-Link DB Injection (`1440×900`)
  4. [`docs/assets/ai-agent-hub.png`](assets/ai-agent-hub.png) — 100%-English AI Agent Hub (111 MCP Tools, `-81.2%` Core Profile, 1-Click Agent Cards & Interactive `ui://culkibo/*` MCP Apps)
  5. [`docs/assets/dashboard-light-en.png`](assets/dashboard-light-en.png) — Crisp Light Mode Dashboard (`1440×900`)

---

### Draft D — X / Twitter Launch Thread (6 Posts)

**Post 1 (Hook + attach `docs/assets/social-preview.png`):**
> I built an open-source, self-hosted PaaS that idles at **54 MB RAM**, uses **6 runtime deps**, has **0 shell calls** (CI-verified + CycloneDX 1.6 SBOM), and ships **111 MCP tools + inline MCP Apps** for Claude Code, Cursor & Antigravity.
>
> Meet **Culkibo v1.2** (Apache-2.0) — the lightweight, AI-native alternative to Coolify & Dokploy.
>
> Thread 🧵👇

**Post 2 (Performance, Zero-Shell & Dark/Light Topology UI + attach `docs/assets/topology-dark-en.png`):**
> Most self-hosted PaaS dashboards burn 500 MB–1.5 GB RAM just sitting idle, reload Traefik with polling delays, and keep getting hit by shell-injection CVEs.
>
> Culkibo runs on:
> • 54 MB idle RSS · 6 npm deps · 3,606 req/s auth fast-path
> • `shell: false` everywhere (statically verified in CI + CycloneDX 1.6 SBOM)
> • Caddy v2.11 atomic API + HTTP/3 + `103 Early Hints` + `Server-Timing: cp;dur=0.04`
> • 100% EN/ES UI, Obsidian Dark/Light mode & Interactive Spatial SVG Topology with click-to-link DB injection

**Post 3 (SmartPack + DirectPush + Sovereign EdgeTunnel + Live Sync 2.0):**
> Zero Docker Hub lock-in. Zero Cloudflare lock-in. Zero rebuild tax on env edits.
>
> Built natively into the 54 MB daemon (0 new npm deps):
> • **Live Sync 2.0**: `1.75 ms` apply, `-96.1%` Brotli, `2.94 ms` rollback
> • **SmartPack**: 18-stack build plans, auto-`.dockerignore`, BuildKit 1.7 cache & cgroup RAM caps
> • **DirectPush (`culkibo pussh`)**: SSH OCI v2 layer-delta push directly to your VPS
> • **EdgeTunnel**: sovereign CGNAT WebSocket tunnel (`ET1`)
> • **Fast Restart**: runtime env updates in ~1.5s without rebuilding

**Post 4 (AI-Agent Native MCP 2026 + World-First PaaS MCP Apps + attach `docs/assets/ai-agent-hub.png`):**
> Dumping 100+ raw MCP tools into an LLM kills context windows.
>
> Culkibo solves it with `?profile=core` (**-81.2% tokens**, 17 essential tools + on-demand discovery across 111 tools), 13 playbooks, two-phase `confirmToken` remediation, AND **3 sandboxed inline MCP Apps (`ui://culkibo/*`)**.
>
> Connect in 1 command:
> `culkibo agent-init claude` (or `antigravity`, `cursor`, `windsurf`, `codex`, `vscode`)

**Post 5 (1-Click Coolify v4 Migration + SnapStream + Full Self-Hosted Power):**
> Already on Coolify? Migrate in 3 steps without touching your live server until DNS cutover:
> • Auto-translates Coolify Magic Vars (`SERVICE_FQDN_*`, `SERVICE_PASSWORD_*`) → native domains & `${vault.*}`
> • Auto-converts plain & Base64 Traefik labels → Caddy v2.11 routes
> • Generates zero-shell Volume & SQL streaming runbooks + `.zip` stack bundles
>
> Plus: 140 pinned apps (0 `:latest`), 12 DB engines, AES-256-GCM S3 DR drills, SnapStream SQLite WAL-to-S3, PR Preview DB Branching, Multi-Server SSH Fleet, 4-role RBAC, 2FA, OIDC `groups` mapping & Auto-Sleep Scale-to-Zero.

**Post 6 (Ethical Open-Core + CTA):**
> Zero "enterprise-paywalling basic security" games:
>
> 2FA, OIDC SSO, RBAC, Multi-Server Fleets, Encrypted DR, DirectPush, EdgeTunnel, CycloneDX SBOM, GitOps, Scale-to-Zero, and all 111 MCP tools + 3 MCP Apps are **100% free forever under Apache-2.0**.
>
> Verify every benchmark yourself (`node bench/run-all.bench.js`) and drop a ⭐ if this belongs on your VPS:
> https://github.com/macaqueboy/culkibo

---

## 4. Ethical Open-Core Monetization Ladder (Aligned with [`editionService.js`](../server/services/editionService.js))

Culkibo's monetization model is engineered to **build extreme trust with the open-source community** (never locking 2FA, SSO, RBAC, multi-server, or backups behind a paywall) while creating clear, high-margin revenue from companies that need managed relays, compliance evidence, SCIM/SAML, and SLA support.

| Tier | Pricing Target | License Verification | What Is Included |
| :--- | :--- | :--- | :--- |
| **Community (OSS)** | **$0 Forever** (`Apache-2.0`) | None required (zero phone-home) | **100% of self-hosted core power with zero artificial limits:** Unlimited projects, 12 DB engines, 140 catalog apps, Live Sync 2.0, SmartPack, DirectPush, Sovereign EdgeTunnel, SnapStream, PR Preview DB Branching, Multi-Server SSH Fleet, Teams + 4-role RBAC + ACL, TOTP 2FA, OIDC PKCE SSO (`groups` mapping), GitOps `culkibo.yaml`, 111 MCP tools + 13 playbooks + 3 MCP Apps, CycloneDX 1.6 SBOM, AES-256-GCM S3 DR Backups + Drills, Synthetic Uptime + Public Status Pages, Auto-Sleep Scale-to-Zero, 7-provider Wildcard DNS-01, Cloudflare Tunnels, Coolify v4 Migrator. |
| **Pro** | **$19–$29 / mo** *(or $190 / yr per org)* | **100% Offline Ed25519 Key (`CKL1.*`)** | Everything in Community + **Managed Multi-Region Relay** (`managed_multi_region_relay`), **Custom White-Label Branding** (`custom_branding` on dashboard, status pages & wake screens), and **Priority Diagnostics & Support Bundle** (`priority_support_bundle`). |
| **Enterprise** | **$149–$299 / mo** *(custom annual SLA)* | **100% Offline Ed25519 Key (`CKL1.*`, air-gap ready)** | Everything in Pro + **Enterprise SCIM 2.0 & SAML 2.0 Pack** (`enterprise_scim_saml` for Okta/Entra ID group sync), **SLA & Signed Compliance Exports** (`sla_support_export` for SOC2/ISO-27001), **Continuous SIEM / Audit Attestation Export** (`compliance_audit_export`), and **Dedicated Architecture & Migration SLA** (`dedicated_onboarding`). |
| **Culkibo Cloud** | **Usage / Seat Managed** *(starts ~$15 / mo)* | Hosted HA Control Plane (`managed_control_plane`) | Everything in Enterprise + **Zero-maintenance Multi-AZ Managed Control Plane** connecting directly to your own Hetzner/DO/AWS/bare-metal VPS fleet via Culkibo's zero-shell SSH tunnels. |

---

## 5. Backlink, Community & Traffic Archival Playbook

### High-Signal Distribution Channels (Weeks 1–4)

1. **Awesome Lists (PRs with clean factual 1-line descriptions):**
   - `awesome-selfhosted/awesome-selfhosted` (Platform-as-a-Service category)
   - `punkpeye/awesome-mcp-servers` & `modelcontextprotocol/servers` (DevOps / Cloud Orchestration MCP + MCP Apps category)
   - `veggiemonk/awesome-docker` (Docker PaaS / Management)
2. **Comparison & Migration Guides (SEO Long-Tail Technical Posts on Dev.to / Hashnode / Medium / `culkibo.dev/blog`):**
   - *"How We Cut Self-Hosted PaaS Idle RAM to 54 MB with Zero Shell Calls, 6 Dependencies & a CycloneDX 1.6 SBOM"*
   - *"Migrating from Coolify v4 to Culkibo Without Downtime: Translating Magic Variables, Traefik Labels & Live SQL Streams"*
   - *"Cutting MCP Context Bloat by 81% & Shipping the First Inline MCP Apps (`ui://`) for DevOps"*
   - *"Registry-Less Deploys in 250 Lines of Node: Building DirectPush (`culkibo pussh`) Over SSH"*
3. **GitHub Traffic Archival Rule (Critical — 14-Day Retention Limit):**
   - GitHub only retains `views`, `clones`, `referrers`, and `popular/paths` traffic metrics for **14 days**.
   - Starting on Launch Day, archive weekly traffic snapshots (`gh api repos/macaqueboy/culkibo/traffic/views`, `/clones`, `/popular/referrers`, `/popular/paths`) into a private metrics repo or scheduled workflow so launch spike attribution is never lost.
4. **Pre-Publish Checklist (Day 0):**
   - [x] Active 4-job Linux CI committed at [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) (Node 20/22/24 + Live Caddy v2.11 + Docker BuildKit SmartPack/SBOM + Playwright Visual QA)
   - [x] Automated tag release workflow committed at [`.github/workflows/release.yml`](../.github/workflows/release.yml) (CycloneDX 1.6 SBOM + `CHECKSUMS.sha256` + `provenance.json`)
   - [x] `1280×640` Social Preview OG PNG + animated Live Sync SVG + 100%-English Dark/Light/Topology/AI Hub screenshots committed in [`docs/assets/`](assets/social-preview.png)
   - [ ] Paste exact GitHub Description (Section 1) and all 20 Topics in GitHub Settings → About
   - [ ] Upload [`docs/assets/social-preview.png`](assets/social-preview.png) in GitHub Settings → Social preview
   - [ ] Enable **GitHub Discussions** (`Announcements`, `Q&A`, `Show and Tell`, `Catalog App Requests`) & **Private Vulnerability Reporting**
   - [ ] Push tag `git tag v1.2.0 && git push origin v1.2.0` to trigger automated GitHub Release with attached SBOM & SHA-256 checksums
