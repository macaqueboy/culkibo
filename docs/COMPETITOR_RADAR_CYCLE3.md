# Culkibo Cycle-3 Competitor Forensics & Cycle-4 Pioneer Blueprint

> **Date:** 2026-11-27 · **Baseline:** `a154cd2` (`95.4%`, `ROOT_DEPS=6`, 54 MB RSS) · **Scope:** Fresh 2026 GitHub PR/issue forensics (zero overlap with Cycle #1) + 2026 OSS standards (`OTLP/HTTP JSON`, `SLSA v1.1 / CycloneDX 1.6`, `MCP 2026-07-28 Tasks & Elicitation`, `WASI 0.2/0.3`, 10k-star README patterns).

---

## 1. Fresh 2026 Competitor Forensics (6 Blind Spots)

| Domain | Real 2025–2026 Citations | Failure Mode | Culkibo Guardrail |
|---|---|---|---|
| **Build Cache Bloat, Cleanup & Queue Deadlocks** | [`coolify#12542`](https://github.com/coollabsio/coolify/issues/12542), [`#6656`](https://github.com/coollabsio/coolify/issues/6656), [`#10996`](https://github.com/coollabsio/coolify/issues/10996); [`kamal#1655`](https://github.com/basecamp/kamal/issues/1655); Dokploy BullMQ OOM lock | Uncapped Railpack BuildKit caches grew 20+ GB (`#12542`); cached Next.js rebuilds spiked 3.6+ GB RAM (`#6656`); Docker prunes wiped sleeping Sablier containers (`#10996`); `kamal redeploy` skipped pruning filling disk (`#1655`); OOM-killed Dokploy workers locked `bull:deployments:active` until manual `redis-cli` + SQL rescue. | Cap BuildKit `--keep-storage`, label sleeping containers `culkibo.protected=1` (excluded from auto-prune), and auto-recover stale deploy locks via PID/heartbeat check on boot (`deployManager.js`). |
| **Zero-Downtime DB Migrations & Failover** | [`kamal#1513`](https://github.com/basecamp/kamal/issues/1513); [`dokploy#4154`](https://github.com/Dokploy/dokploy/issues/4154), [`#2462`](https://github.com/Dokploy/dokploy/issues/2462), [`#3689`](https://github.com/Dokploy/dokploy/issues/3689); [`coolify#11253`](https://github.com/coollabsio/coolify/issues/11253), [`#12087`](https://github.com/coollabsio/coolify/issues/12087) | Multi-host deploys race migrations or hit Unix sockets instead of `DATABASE_URL` (`kamal#1513`); PR previews collide on one Postgres schema (`dokploy#2462`); VM/region transfers lack 2-phase pre-flight (`dokploy#3689`, `coolify#11253`). | Single-leader ephemeral migration container + pre-migration snapshot + lease lock before Caddy swap; per-PR Postgres schema / SQLite clone; reuse `bundleArchiver.js` for 2-phase fleet failover. |
| **Container Drift & Git Symlink Leaks** | [`portainer#13298`](https://github.com/portainer/portainer/issues/13298) + Git-symlink host file read; [`arcane#4825`](https://github.com/getarcaneapp/arcane/issues/4825), [`#5003`](https://github.com/getarcaneapp/arcane/issues/5003), [`#4983`](https://github.com/getarcaneapp/arcane/issues/4983) | Manual redeploy left Portainer GitOps permanently `'unknown'`, halting drift auto-updates (`#13298`); symlinked `docker-compose.yml` read host files during sync; Arcane webhooks silently skipped auto-redeploy (`#4825`, `#5003`). | Recompute SHA on every `gitopsManager.js` reconcile (immune to manual redeploys), reject escaping symlinks via `fs.realpathSync` (`ssrfGuard.js`), and log deterministic webhook outcomes. |
| **Webhook False-204, Token Redaction & Replay** | [`portainer#13139`](https://github.com/portainer/portainer/issues/13139); [`dokploy#4898`](https://github.com/Dokploy/dokploy/issues/4898) (from `#4859`); [`coolify#11262`](https://github.com/coollabsio/coolify/issues/11262) | Webhook returned HTTP `204` even when registry auth/deploy failed (`portainer#13139`); Dokploy redaction patch `#4859` stripped tokens from preview lookups (`#4898`); signed webhooks lacked replay timestamp windows. | Return `202` + status URL (or `?wait=true` real error), isolate internal secret lookups from redacted DTOs, and enforce `<= 300 s` timestamp skew + persisted delivery-ID LRU (`webhookService.js`). |
| **OIDC / SAML Edge Failures & Role Loops** | [`arcane#3855`](https://github.com/getarcaneapp/arcane/issues/3855), [`#1485`](https://github.com/getarcaneapp/arcane/issues/1485), [`#3620`](https://github.com/getarcaneapp/arcane/issues/3620), [`#527`](https://github.com/getarcaneapp/arcane/issues/527); [`Cosmos#625`](https://github.com/azukaar/Cosmos-Server/issues/625) | Authentik JWKS fetch hit 30s timeout blocking SSO (`#3855`); `OIDC_MERGE_ACCOUNTS` downgraded admins/looped (`#1485`); unmapped roles blank-screened (`#3620`); Cosmos advertised `email_verified` without emitting it (`#625`). | Cache JWKS with stale-while-revalidate + 5s connect timeout (`oidcService.js`), support custom IdP CA bundle, default unmapped groups safely to `viewer`, and assert discovery-vs-token parity. |
| **Control-Plane RCE Regressions** | Coolify v4 PHP/key advisories; Dokploy template-literal git param injection patches | Shell interpolation + bloated PHP/Next.js stacks keep shipping critical CVEs. | Preserve `0` shell construction (`shell-safety.test.js`) + `ROOT_DEPS=6` as our core security moat. |

---

## 2. Top 5 Zero-Dep (`ROOT_DEPS=6`) Cycle-4 Pioneering Features

All 5 keep **0 new runtime npm deps**, 0 shell construction, and Idle RAM `<= 60 MB`:

### 1. Native OTLP/HTTP JSON Exporter (`server/services/otlpExporter.js`)
- **2026 Spec Catch (`opentelemetry.io/docs/specs/otlp`):** OTLP/HTTP JSON deviates from proto3 — `traceId` (32 chars) and `spanId` (16 chars) MUST be **hex strings (NOT base64)**; `*TimeUnixNano` are stringified uint64 nanoseconds.
- **Design:** Pure Node `fetch` + `zlib.gzip` exporter to `/v1/traces` and `/v1/metrics` (SSRF-guarded via `ssrfGuard.js`). Emits deploy pipeline spans (`git.fetch → smartpack.build → db.migrate → healthcheck → caddy.swap`) + `metricsCollector.js` batches from a 256-span bounded ring (5s flush, circuit breaker on 429/5xx, W3C `traceparent` propagation). Native Grafana Tempo / SigNoz / Honeycomb / Jaeger compatibility with 0 `@opentelemetry/*` packages.

### 2. SLSA v1.1 + CycloneDX 1.6 Supply-Chain Attestation (`server/services/supplyChainAttestor.js`)
- **2026 Standard:** OWASP **CycloneDX 1.6** SBOM + **SLSA Provenance v1.1** (`in-toto` v1 statement) in a **DSSE** envelope (Sigstore-compatible).
- **Design:** On every Citadel deploy & `.zip` bundle (`bundleArchiver.js`), parse lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `go.sum`, `Cargo.lock`, `requirements.txt`) to generate deterministic `sbom.cdx.json` + `provenance.slsa.json` (commit SHA, SmartPack plan hash, image digest), signed with Node's native `crypto` **Ed25519** key (`0600`). Expose `GET /api/projects/:id/releases/:rev/attestation` + `culkibo verify <release>`.

### 3. MCP `2026-07-28` Async Tasks + Elicitation (`server/services/mcpServer.js`)
- **Critical 2026 Spec Catch (`modelcontextprotocol.io`):** MCP `2026-07-28` **deprecated Sampling (SEP-2577)** — do NOT build Sampling! Instead, **Tasks** moved to official extension **`io.modelcontextprotocol/tasks`** (`working` | `input_required` | `completed` | `failed`) and **Elicitation** (`elicitation/create` JSON Schema forms) is the human-in-the-loop standard.
- **Design:** Add `tasks/get`, `tasks/result`, `tasks/cancel`, `tasks/list` (bounded 128-entry TTL store, RBAC-scoped) for long-running tools (`culkibo_deploy_project`, `culkibo_coolify_migrate`, `culkibo_db_restore`) so AI clients never time out during 90s builds. Emit `elicitation/create` when `clientCapabilities.elicitation` is present for missing secrets/approvals, degrading cleanly to existing `dryRun` + `ckr_` `confirmToken`.

### 4. WASI 0.2/0.3 (`wasi:http`) Micro-Handler Runtime (`server/services/wasmMicroRunner.js`)
- **2026 Breakthrough (`fermyon/spin`, `WasmEdge`, `wasi.dev`):** `wasi:http/incoming-handler` achieves `< 2 ms` cold starts, KB–MB RAM, and per-request scale-to-zero without container OS layers.
- **Design:** Add `runtime: 'wasm'` in `smartPackBuilder.js` + `deployManager.js`: auto-detect `spin.toml` / `*.wasm` to run `wasmtime serve`/`spin up`/`wasmedge` via `safeCommand.js`, **plus** a zero-binary built-in **Micro-Wasm Sandbox** (`WebAssembly.instantiate` inside `worker_threads` with wall-clock timeout + memory cap) for sub-ms webhook/edge micro-handlers routed behind Caddy v2.11.

### 5. Atomic Pre-Deploy DB Migration Runner + Preview Schema Isolation (`server/services/migrationRunner.js`)
- **Design:** Solves `kamal#1513` & `dokploy#4154/#2462`: run optional `preDeployMigrateCmd` in a **single-leader ephemeral container** from the *new* image with injected `DATABASE_URL` + lease lock (`data/locks/`) **after** an automatic pre-migration snapshot (`databaseManager.js`) and **before** Caddy swaps traffic; non-zero exit aborts with 0 downtime. Add opt-in `isolatedSchema: true` in `previewManager.js` (`CREATE SCHEMA "pr_<n>"` + `search_path`, auto-dropped on PR close).

---

## 3. Exact Cycle-4 Regression Tests (`tests/competitor-prs.test.js` & New Suites)

1. **Sleeping-Container Prune Immunity (`coolify#10996`/`#12542`):** Auto-prune skips `culkibo.protected=1` sleeping containers while honoring BuildKit storage cap.
2. **Stale Deploy-Lock Auto-Recovery (Dokploy BullMQ deadlock):** Dead-PID / expired deploy lock clears automatically on next deploy without manual DB intervention.
3. **GitOps Symlink Escape & Manual-Redeploy Drift (`portainer#13298`):** Symlinked `docker-compose.yml` escaping workspace is rejected; manual redeploy preserves drift SHA (never `'unknown'`).
4. **Webhook Replay Window & Sync Failure (`portainer#13139`, `dokploy#4898`):** Rejects signed webhooks `> 300 s` old or duplicate delivery IDs; failed sync deploy never returns `204`; redacted DTOs preserve internal preview git credentials.
5. **OIDC JWKS Stale Fallback & Safe Role Mapping (`arcane#3855/#1485/#3620`, `Cosmos#625`):** JWKS fetch timeout falls back to cached keys; unmapped groups map to `viewer`; discovery claims match emitted tokens.
6. **OTLP Hex `traceId` + SLSA Ed25519 + MCP Tasks:** `otlpExporter.js` emits 32-char lowercase hex `traceId` (never base64); `supplyChainAttestor.js` verifies & catches 1-byte tamper; `mcpServer.js` enforces RBAC across task lifecycle.

---

## 4. Viral 10k-Star GitHub README & Interactive Demo Playbook (`@seo-launch` / Cycle 4)

Breakout 2025–2026 self-hosted repos (`coolify` ~62k★, `pocketbase` ~61k★, `Dokploy` ~38k★, `beszel`, `pangolin`) win with 3 patterns:
1. **Zero-Install 10-Second Interactive Demo Above the Fold:** Ship a static read-only **Browser Sandbox (`CULKIBO_DEMO=1` / GitHub Pages mock-API build of `web/`)** linked on line 5 of `README.md` (`Try Live Interactive Demo — no Docker needed`) + 1-line `npx culkibo demo` booting in `< 200 ms`.
2. **3-Scroll Proof Hook (Zero Hype):** 1-sentence positioning (*"54 MB self-hosted PaaS for the AI-agent era — atomic Caddy deploys, 1.75 ms Live Sync, 111 MCP tools, 6 deps"*), a 15s WebM/GIF (**Live Sync + Spatial Topology + MCP App inline rollback**), and the reproducible `npm run bench:all` table right under the fold.
3. **HN & `r/selfhosted` Credibility:** Lead with radical honesty (single-VPS vs SSH-fleet scope, exact `ROOT_DEPS=6` & `0` shell calls, Apache-2.0, transparent AI-assisted build disclosure, and a non-destructive 1-click Coolify v4 `.zip` migration dry-run).
