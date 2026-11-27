# Culkibo — GitHub SEO & Launch-Tomorrow Go-To-Market Kit

> **Target Repository:** `macaqueboy/culkibo` · **Release Baseline:** `v1.1.0` · **License:** `Apache-2.0`
> **Evidence Policy:** Every benchmark metric, tool count, and competitive citation in this launch kit is grounded in live-measured Cycle-1 output (`node bench/run-all.bench.js`), verified source files, and [`docs/COMPETITOR_RADAR_CYCLE1.md`](COMPETITOR_RADAR_CYCLE1.md). Zero invented numbers.

---

## 1. Exact GitHub Repository Metadata (Copy-Paste Ready)

### Repository Description (281 / 350 chars — High-Intent Keyword Optimized)

```text
The <60 MB, zero-shell, AI-native self-hosted PaaS. Deploy 140+ apps, 12 databases, Live Sync 2.0 (2 ms apply), Caddy v2.11 HTTP/3, Multi-Server SSH fleets, 1-click Coolify v4 migration & 109 MCP tools for Claude Code, Cursor & Antigravity. Open-source Coolify/Dokploy alternative.
```

> **SEO rationale:** Front-loads the 4 strongest differentiating hooks (`<60 MB`, `zero-shell`, `AI-native`, `self-hosted PaaS`), anchors the exact comparison queries (`Coolify`, `Dokploy alternative`), and targets the 2026 AI coding wave (`MCP`, `Claude Code`, `Cursor`, `Antigravity`) within GitHub's 350-character cap.

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

## 2. Social Preview (Open Graph Image) Design Spec

Upload in GitHub **Settings → Social preview** at exact **`1280 × 640 px`** PNG (safe margin `80 px` on all sides so X/Twitter, Discord, Slack, LinkedIn, and Hacker News cards never clip text).

### Visual Layout Spec

- **Canvas:** Deep Obsidian `#0B0B0E` with subtle radial Forge Amber glow (`rgba(245, 158, 11, 0.14)`) behind the top-right metric card and crisp `1 px` hairlines (`rgba(255, 255, 255, 0.08)`). No generic purple/blue AI gradients.
- **Left Column (60% width):**
  - Top: **Twin Planes K** emblem ([`web/public/favicon.svg`](../web/public/favicon.svg), `72 × 72 px`) + wordmark **`Culkibo`** (`Inter / Geist Bold`, `#FFFFFF`, `56 px`) + pill badge `Apache-2.0 · v1.1`.
  - Headline (`40 px`, crisp high-contrast `#F4F4F5`):
    **`The <60 MB, Zero-Shell, AI-Native Self-Hosted PaaS`**
  - Sub-line (`22 px`, `#A1A1AA`):
    `140+ Apps · 12 Databases · Live Sync 2.0 · 109 MCP Tools · 1-Click Coolify Migration`
  - Bottom command pill (`JetBrains Mono`, `#F59E0B` prompt):
    `$ docker compose up -d --build`
- **Right Column (36% width — Proof Card):**
  - Dark frosted terminal card (`#141418`, border `rgba(255,255,255,0.12)`, `tabular-nums`):
    - `Idle RAM` → **`54 MB RSS`** *(vs 500 MB–1.5 GB)*
    - `Runtime Deps` → **`6`** *(0 shell calls)*
    - `Live Sync Apply` → **`2.03 ms p50`** *(-96.1% Brotli)*
    - `MCP Context` → **`109 Tools`** *(-80.7% `core` profile)*
    - `Proxy Cutover` → **`Caddy v2.11`** *(HTTP/3 · Atomic)*

---

## 3. Ready-to-Publish Launch Drafts

> **Launch Timing Playbook:**
> - **Tuesday–Thursday, 13:30–15:00 UTC** (9:30–11:00 AM US Eastern / 14:30–16:00 CET) maximizes overlap between European engineers and US morning traffic on HN, Reddit, and X.
> - Stagger channels across 48 hours: **Day 1 AM:** Show HN + X Thread → **Day 1 PM:** `r/selfhosted` + `r/docker` → **Day 2:** Product Hunt + Dev.to / Hashnode deep-dive technical post.

---

### Draft A — Show HN (`news.ycombinator.com/submit`)

**Title (78 chars — HN sweet spot, factual, zero hype):**
```text
Show HN: Culkibo – A 54 MB, zero-shell, AI-native self-hosted PaaS (Apache-2.0)
```

**First Comment (Author Technical Context — post immediately after submitting):**
```text
Hi HN! I built Culkibo (Apache-2.0) because I kept running into three frustrations while self-hosting apps and iterating with AI coding agents (Claude Code, Cursor, Antigravity):

1. Control-plane bloat: Most modern self-hosted PaaS dashboards need 500 MB–1.5 GB of RAM just for the panel (Laravel + Horizon + Postgres + Redis + Soketi, or Next.js + Postgres + Redis + Traefik), which breaks on small 512 MB–1 GB VPS nodes.
2. Shell-injection attack surface: Too many PaaS tools interpolate user/repo/domain fields into shell strings.
3. The AI-agent iteration tax: Waiting 1–4 minutes for a full Docker rebuild on every agent edit breaks the loop, and dumping 100+ raw MCP tool schemas into an LLM destroys context windows.

How Culkibo approaches this differently:

- 54 MB idle RSS, 6 runtime npm dependencies: Single Node.js control plane (express, ws, chokidar, commander, cors, dotenv — 0 deps in the optional telemetry collector) paired with Caddy v2.11's JSON Admin API for synchronous, zero-poll route swaps and native HTTP/3. Cold boot measures 170.8 ms (`CULKIBO_SKIP_RECONCILE=1`); authenticated Bearer+Brotli fast-path hits 3,294 req/s (p50 6.88 ms, `Server-Timing: cp;dur=0.04`).
- Zero shell construction (`shell: false`): Every subprocess (`docker`, `git`, `caddy`, `ssh`, `cron`) goes through tokenized `argv` arrays (`server/services/safeCommand.js`), secrets travel via ephemeral `0600` `--env-file` or `GIT_ASKPASS`, and `node tests/shell-safety.test.js` statically verifies 0 unauthorized shell calls on every commit.
- Live Sync 2.0 ("The Forge"): Incremental binary WebSocket sync (`/ws/sync`) with Brotli framing (-96.1% wire savings on a 100-file TSX burst), Merkle tree reconciliation, chunked transfers, and in-memory patch rollback (3.35 ms p50; server apply 2.03 ms p50, loopback E2E 15.33 ms on Win x64). Production changes to deps/Dockerfiles still go through full immutable Docker BuildKit builds ("The Citadel") with smoke checks and multi-release rollback.
- Native MCP 2026-07-28: 109 tools, 13 interactive playbooks (`prompts/list`), and 7 resources over Streamable HTTP or stdio. Passing `?profile=core` (or `CULKIBO_MCP_PROFILE=core`) drops schema context size by 80.7% while keeping on-demand tool discovery, RBAC, secret redaction, and two-phase HMAC `confirmToken` remediation.
- Batteries included without paywalling core features: 140 pinned 1-click catalog apps (0 `:latest`, 0 `docker.sock`), 12 managed DB engines, AES-256-GCM S3/R2 DR backups with non-destructive restore drills, 4-role RBAC + TOTP 2FA + OIDC PKCE SSO, hash-chained audit log, multi-server SSH fleet (TOFU + ControlMaster), declarative `culkibo.yaml` GitOps, auto-sleep scale-to-zero, 7-provider DNS-01 wildcard TLS, Cloudflare Tunnels, and a 1-click Coolify v4 migrator (translates Coolify Magic Variables and Traefik labels to Caddy).

Honest caveats:
- Benchmarks in the README were measured on Node v24.14.0 (win32/x64); competitor RAM figures are explicitly labeled as documented architecture baselines, not locally executed benchmarks. You can reproduce every Culkibo metric with `node bench/run-all.bench.js`.
- Telemetry is opt-out anonymous crash/health reporting with an 11-phase PII scrubber and `telemetry preview` inspection (`CULKIBO_TELEMETRY=0` or `DO_NOT_TRACK=1` disables it immediately).

Repo: https://github.com/macaqueboy/culkibo

Happy to answer any questions about the Caddy Admin API design, the zero-shell static checker, the Live Sync binary protocol, or the Coolify v4 Traefik->Caddy translator!
```

---

### Draft B — Reddit `r/selfhosted` (and cross-post to `r/docker`)

**Title:**
```text
I built Culkibo (Apache-2.0): a 54 MB RAM, zero-shell self-hosted PaaS with Caddy HTTP/3, 140 pinned apps, 12 DBs, 1-click Coolify v4 migration, and native MCP for AI agents
```

**Body:**
```markdown
Hey r/selfhosted!

I wanted a self-hosted PaaS that could actually live comfortably on a cheap **512 MB – 1 GB VPS** without giving up multi-server fleets, RBAC/2FA/OIDC, encrypted S3 backups, or modern DX — and without needing to babysit Traefik reload quirks or wait 3 minutes on every code tweak.

So I built **Culkibo** (100% Apache-2.0 open source, zero paywalled self-hosted features):
https://github.com/macaqueboy/culkibo

### What makes it genuinely different
- **54 MB idle RSS daemon** (~72 MB total with Caddy, 0% idle CPU, **6 runtime npm deps**). Reproducible via `node bench/run-all.bench.js`.
- **Zero shell construction (`shell: false`)**: Every `docker`, `git`, `caddy`, and `ssh` call uses strict `argv` arrays, CI-verified by `tests/shell-safety.test.js`. No shell-injection RCE class.
- **Caddy v2.11 atomic ingress**: Native HTTP/3 (QUIC), **7-provider DNS-01 wildcard TLS** (Cloudflare, Hetzner, DigitalOcean, Route 53, Porkbun, Bunny, DuckDNS), guided **Cloudflare CGNAT Tunnels** (zero open ports), Basic Auth, IP Allowlists, and ForwardAuth.
- **140 pinned 1-click catalog apps** (zero `:latest` tags, zero `docker.sock` mounts) + **12 managed database engines** (PostgreSQL, pgvector, TimescaleDB, MySQL, MariaDB, Valkey, Redis, Dragonfly, MongoDB, ClickHouse, Qdrant, Meilisearch) with **AES-256-GCM S3/R2 DR backups & restore drills**.
- **Built-in features people keep requesting in Coolify/Dokploy**:
  - Native **Auto-Sleep Scale-to-Zero** (no Sablier hacks)
  - Declarative **`culkibo.yaml` GitOps** (`export` / `plan` / `apply` / `drift`) + portable `.zip` stack bundles
  - **Multi-Server SSH Fleet** (TOFU + ControlMaster tunnels + AES-256-GCM key vault)
  - **Teams + 4-role RBAC + TOTP 2FA + OIDC SSO + hash-chained tamper-evident audit log**
  - **Synthetic Uptime Monitors + Public `/status/:slug` pages**
- **1-Click Coolify v4 Migrator (read-only on source)**: Automatically translates Coolify Magic Variables (`SERVICE_FQDN_*`, `SERVICE_PASSWORD_*`, etc.) into Culkibo domains/`${vault.*}` and converts Traefik labels into Caddy routes, with a pre-flight Parity Report before you switch DNS.
- **Live Sync 2.0 + Native MCP (`2026-07-28`)**: Incremental binary hot-sync (`2.03 ms` server apply, `-96.1%` Brotli) + **109 MCP tools** & **13 engineering playbooks** with `?profile=core` (`-80.7%` token savings) for Claude Code, Cursor, Windsurf, and Antigravity.

### Quick try (Docker Compose)
```bash
git clone https://github.com/macaqueboy/culkibo.git && cd culkibo
docker compose up -d --build
```

### Radical honesty on privacy & licensing
- **License:** Apache-2.0. Every single feature listed above is 100% free in Community Edition with zero artificial caps. Optional commercial packs (offline Ed25519 keys) are strictly for Enterprise SCIM/SAML, white-label, and compliance exports.
- **Telemetry:** Opt-out anonymous crash/health stats (11-phase PII scrubber, preview exact payload via `culkibo telemetry preview`, disable instantly via `CULKIBO_TELEMETRY=0` or `DO_NOT_TRACK=1`).

Would love honest feedback from people running Coolify, Dokploy, CapRover, or Kamal — especially if you try the Coolify migration parity preview or run `node bench/run-all.bench.js` on your own VPS!
```

---

### Draft C — Product Hunt Listing

- **Name:** `Culkibo`
- **Tagline (59 / 60 chars):** `54 MB, zero-shell, AI-native self-hosted PaaS with 109 MCPs`
- **Short Description (246 / 260 chars):**
  `Deploy 140+ pinned apps, 12 databases, Caddy HTTP/3, multi-server SSH fleets, and Live Sync 2.0 (2 ms apply) on a 54 MB RAM open-source control plane. Built for Claude Code, Cursor & Antigravity with 109 MCP tools and 1-click Coolify v4 migration.`
- **Topics:** `Developer Tools`, `Open Source`, `DevOps`, `Artificial Intelligence`, `Cloud Infrastructure`
- **Maker First Comment:**
  Highlight the 3-minute story: why self-hosted PaaS shouldn't eat 1 GB of idle RAM, why zero-shell static verification matters for production VPS security, how Live Sync 2.0 + `?profile=core` (`-80.7%` MCP tokens) transforms AI-assisted shipping, and our Ethical Open-Core guarantee (100% free Apache-2.0 self-hosted core, offline Ed25519 keys only for optional Enterprise/Cloud packs).
- **Gallery Order (5 slides):**
  1. Hero Social Preview card (`1280×640`)
  2. Live Dashboard + `Cmd+K` Fuzzy Command Palette + Live RAM/Latency Pill
  3. 3-Step Coolify v4 Migration Cockpit (Magic Vars + Traefik→Caddy Parity Report)
  4. AI Agent Hub (1-Click Connect Claude Code / Antigravity / Cursor + `-80.7%` Profile Meter + 13 Playbooks)
  5. Security & Benchmarks (`54 MB RSS`, `Server-Timing: cp;dur=0.04`, TOTP 2FA, Hash-Chained Audit Verifier)

---

### Draft D — X / Twitter Launch Thread (6 Posts)

**Post 1 (Hook + Social Preview Image):**
> I built an open-source, self-hosted PaaS that idles at **54 MB RAM**, uses **6 runtime deps**, has **0 shell calls** (CI-verified), and ships **109 MCP tools** for Claude Code, Cursor & Antigravity.
>
> Meet **Culkibo** (Apache-2.0) — the lightweight, AI-native alternative to Coolify & Dokploy.
>
> Thread 🧵👇

**Post 2 (The Performance & Zero-Shell Bet):**
> Why build another PaaS in 2026?
>
> Most self-hosted dashboards need 500 MB–1.5 GB RAM just to sit idle, reload Traefik with polling delays, and keep getting hit by shell-injection CVEs.
>
> Culkibo runs on:
> • 54 MB idle RSS · 170.8 ms cold boot
> • 6 npm deps (`0` in telemetry collector)
> • `shell: false` everywhere (statically verified on every commit)
> • Caddy v2.11 atomic API + native HTTP/3 + `Server-Timing: cp;dur=0.04`

**Post 3 (Live Sync 2.0 — The Forge):**
> Iterating with AI coding agents shouldn't mean waiting 3 minutes per Docker rebuild.
>
> Culkibo splits dev & prod into Twin Planes:
> • **The Forge (Live Sync 2.0):** binary Brotli frames (`-96.1%` wire size), Merkle sync, `2.03 ms` server apply, `3.35 ms` in-memory patch rollback
> • **The Citadel:** immutable BuildKit builds, smoke tests, canary auto-guard, atomic Caddy cutover

**Post 4 (AI-Agent Native MCP 2026-07-28):**
> Dumping 100+ raw MCP tools into an LLM destroys context windows.
>
> Culkibo's MCP `2026-07-28` server solves this with profiles (`?profile=core` = **-80.7% tokens**, 17 essential tools + on-demand discovery), 13 engineering playbooks (`prompts/list`), RBAC, secret redaction, and two-phase `confirmToken` remediation.
>
> Connect in 1 command:
> `culkibo agent-init claude` (or `antigravity`, `cursor`, `windsurf`, `codex`)

**Post 5 (1-Click Coolify v4 Migration + Full Self-Hosted Power):**
> Already on Coolify? Migrate in 3 steps without touching your live server until DNS cutover:
> • Auto-translates Coolify Magic Vars (`SERVICE_FQDN_*`, `SERVICE_PASSWORD_*`) → native domains & `${vault.*}`
> • Auto-converts Traefik labels → Caddy v2.11 routes
> • Exports self-contained `.zip` stack bundles
>
> Plus: 140 pinned apps (0 `:latest`), 12 DB engines, AES-256-GCM S3 DR drills, Multi-Server SSH Fleet, 4-role RBAC, TOTP 2FA, OIDC SSO, `culkibo.yaml` GitOps, and native Scale-to-Zero.

**Post 6 (Ethical Open-Core + CTA):**
> Zero "enterprise-paywalling basic security" games:
>
> 2FA, OIDC SSO, RBAC, Multi-Server Fleets, Encrypted DR, GitOps, Scale-to-Zero, and all 109 MCP tools are **100% free forever under Apache-2.0**.
>
> Verify every single benchmark yourself (`node bench/run-all.bench.js`) and drop a ⭐ if this belongs on your VPS:
> https://github.com/macaqueboy/culkibo

---

## 4. Ethical Open-Core Monetization Ladder (Aligned with [`editionService.js`](../server/services/editionService.js))

Culkibo's monetization model is engineered to **build extreme trust with the open-source community** (never locking 2FA, SSO, RBAC, multi-server, or backups behind a paywall — the exact dark pattern users despise in enterprise tools) while creating clear, high-margin revenue from companies that need managed relays, compliance evidence, SCIM/SAML, and SLA support.

| Tier | Pricing Target | License Verification | What Is Included |
| :--- | :--- | :--- | :--- |
| **Community (OSS)** | **$0 Forever** (`Apache-2.0`) | None required (zero phone-home) | **100% of self-hosted core power with zero artificial limits:** Unlimited projects, 12 DB engines, 140 catalog apps, Live Sync 2.0, Multi-Server SSH Fleet, Teams + 4-role RBAC + ACL, TOTP 2FA, OIDC PKCE SSO, GitOps `culkibo.yaml`, 109 MCP tools + 13 playbooks, AES-256-GCM S3 DR Backups + Drills, Synthetic Uptime + Public Status Pages, Auto-Sleep Scale-to-Zero, 7-provider Wildcard DNS-01, Cloudflare Tunnels, Coolify v4 Migrator. |
| **Pro** | **$19–$29 / mo** *(or $190 / yr per org)* | **100% Offline Ed25519 Key (`CKL1.*`)** | Everything in Community + **Managed Multi-Region Relay** (`managed_multi_region_relay`), **Custom White-Label Branding** (`custom_branding` on dashboard, status pages & wake screens), and **Priority Diagnostics & Support Bundle** (`priority_support_bundle`). |
| **Enterprise** | **$149–$299 / mo** *(custom annual SLA)* | **100% Offline Ed25519 Key (`CKL1.*`, air-gap ready)** | Everything in Pro + **Enterprise SCIM 2.0 & SAML 2.0 Pack** (`enterprise_scim_saml` for Okta/Entra ID group sync), **SLA & Signed Compliance Exports** (`sla_support_export` for SOC2/ISO-27001), **Continuous SIEM / Audit Attestation Export** (`compliance_audit_export`), and **Dedicated Architecture & Migration SLA** (`dedicated_onboarding`). |
| **Culkibo Cloud** | **Usage / Seat Managed** *(starts ~$15 / mo)* | Hosted HA Control Plane (`managed_control_plane`) | Everything in Enterprise + **Zero-maintenance Multi-AZ Managed Control Plane** connecting directly to your own Hetzner/DO/AWS/bare-metal VPS fleet via Culkibo's zero-shell SSH tunnels. |

---

## 5. Backlink, Community & Traffic Archival Playbook

### High-Signal Distribution Channels (Weeks 1–4)

1. **Awesome Lists (PRs with clean factual 1-line descriptions):**
   - `awesome-selfhosted/awesome-selfhosted` (Platform-as-a-Service category)
   - `punkpeye/awesome-mcp-servers` & `modelcontextprotocol/servers` (DevOps / Cloud Orchestration MCP category)
   - `veggiemonk/awesome-docker` (Docker PaaS / Management)
2. **Comparison & Migration Guides (SEO Long-Tail Blog Posts on Dev.to / Hashnode / Medium / `culkibo.dev/blog`):**
   - *"How We Cut Self-Hosted PaaS Idle RAM to 54 MB with Zero Shell Calls and 6 Dependencies"*
   - *"Migrating from Coolify v4 to Culkibo Without Downtime: Translating Magic Variables and Traefik Labels to Caddy"*
   - *"Cutting MCP Context Bloat by 80%: Tool Profiles and Playbooks for Claude Code & Cursor"*
3. **GitHub Traffic Archival Rule (Critical — 14-Day Retention Limit):**
   - GitHub only retains `views`, `clones`, `referrers`, and `popular/paths` traffic metrics for **14 days**.
   - Starting on Launch Day, archive weekly traffic snapshots (`gh api repos/macaqueboy/culkibo/traffic/views`, `/clones`, `/popular/referrers`, `/popular/paths`) into a private metrics repo or automated scheduled workflow so launch spike attribution is never lost.
4. **Pre-Publish Checklist (Day 0):**
   - [ ] Set exact GitHub Description (Section 1) and all 20 Topics
   - [ ] Upload `1280×640` Social Preview PNG (Section 2)
   - [ ] Enable **GitHub Discussions** (Categories: `Announcements`, `Q&A`, `Show and Tell`, `Catalog App Requests`)
   - [ ] Enable **Private Vulnerability Reporting** in GitHub Security settings (matches `SECURITY.md`)
   - [ ] Tag and publish GitHub Release **`v1.1.0`** with live benchmark table and 1-line install snippet
   - [ ] Verify CI workflow (`.github/workflows/ci.yml` from `docs/ci.workflow.yml`) is green on `main`
