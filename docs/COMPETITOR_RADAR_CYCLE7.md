# Culkibo Cycle-7 Competitor Forensics & Cycle-8 Pioneer Blueprint

> **Date:** 2026-11-27 · **Baseline:** Cycle #6 (`v1.2.0`, `99.3%` Launch Readiness, `ROOT_DEPS=6`, `51 MB` RSS) · **Scope:** Fresh 2025–2026 CVEs, GHSAs & PRs (zero overlap with Cycles #1, #3, #6) + 5 zero-dep Cycle-8 breakthroughs.

---

## 1. Fresh 2025–2026 Competitor Forensics (CVEs, GHSAs & High-Impact Bugs)

| Domain | Real 2025–2026 Citations | Root Cause & Blast Radius | Culkibo Guardrail |
|---|---|---|---|
| **World-Writable Install & Cross-Tenant Traversal** | **Dokploy `CVE-2026-129315`** (`<=0.31.0`), **`CVE-2026-133520` / [`GHSA-q7cq-vxv7-449c`](https://github.com/advisories/GHSA-q7cq-vxv7-449c)** (`<0.31.1`) | `install.sh` left `/etc/dokploy` world-writable (`0777`, CWE-732 local root priv-esc); `patch.readRepoDirectories` passed unconfined `repoPath` to `git ls-tree`, exposing other tenants' source trees. | Enforce `0700`/`0600` on all install/data dirs (`scripts/install.sh` + `ssrfGuard.js`); strictly scope repo/file paths to caller's project root with `path.resolve` + `realpathSync`. |
| **Symlink File Read, TOTP Brute-Force & Cron Escape** | **Runtipi `CVE-2026-47277` / [`GHSA-qrqj-p7hm-4m66`](https://github.com/advisories/GHSA-qrqj-p7hm-4m66)** (`4.9.1–4.9.3`), TOTP throttle gap; **Dokku `CVE-2026-54636`** (`<0.38.7`) | Unauthenticated app-store logo endpoint checked paths lexically without resolving symlinks (arbitrary host file read); `/api/auth/verify-totp` lacked rate limiting; Dokku `app.json` cron metacharacters (`>`, `;`) escaped containers to host. | Always verify `fs.realpathSync` containment on repo/catalog assets, enforce strict per-IP/user brute-force throttle on TOTP verification (`auth.js`), and keep `safeCommand.js` (`shell:false`) on all cron specs. |
| **PHP2Shell RCE & Secret Rotation Demand** | **PHP `CVE-2026-109618` / `CVE-2026-109619`** (Oct 2026, hit Coolify v4 PHP runtime); [`coolify#7956`](https://github.com/coollabsio/coolify/discussions/7956) (Infisical) | Unauthenticated PHP OOM `longjmp()` memory corruption RCE forced emergency Coolify patches; self-hosters increasingly demand Infisical/Vault-class short-lived secret leases & rotation instead of static `.env` files. | Lean 6-dep Node.js daemon avoids the entire PHP/Laravel RCE class; add native zero-dep **Ephemeral Secret Leases & Break-Glass** tokens + rotation-age alerts (`secretLeaseService.js`). |
| **DB Pooling Timeouts & Silent Accessory Drift** | **Dokploy `v0.28.6–0.29.0`** Drizzle/PG pool `CONNECT_TIMEOUT`; [`kamal#1790`](https://github.com/basecamp/kamal/issues/1790); PgBouncer `pool_mode=transaction` errors | `kamal deploy` ignores modified accessories, causing silent **config drift** (`#1790`); PgBouncer transaction pooling breaks Prisma/Drizzle/Node drivers (`prepared statement already exists`) unless protocol-level `max_prepared_statements` is tuned. | Ship live **Container/DB Config Drift Detector** comparing `docker inspect` vs declared state; auto-tune `max_prepared_statements=200` + ORM URL hints on Postgres pool presets. |
| **Status Maintenance Bugs, Multi-CAA & 6-Day ACME** | [`uptime-kuma#7704`](https://github.com/louislam/uptime-kuma/issues/7704), [`#8193`](https://github.com/louislam/uptime-kuma/issues/8193), [`#6519`](https://github.com/louislam/uptime-kuma/issues/6519); [`gatus#1804`](https://github.com/TwiN/gatus/pull/1804); [`caddy#7670`](https://github.com/caddyserver/caddy/pull/7670) + Let's Encrypt `shortlived` (6-day) | Uptime Kuma skipped same-day recurring maintenance (`#7704`), froze intervals `>=2d` (`#8193`), and checked only CAA record `[0]` (`#6519`); Let's Encrypt GA **6-day (`160h`) `shortlived` ACME profile** makes automated renewal & full CAA pre-flight critical. | Evaluate live `Date.now()` in maintenance windows (same-day aware), inspect **all** `dns.promises.resolveCaa()` records pre-TLS, and expose Caddy `profile: "shortlived"` + ECH QUIC check. |

---

## 2. Top 5 Zero-Dep (`ROOT_DEPS=6`) Cycle-8 Pioneering Breakthroughs

All 5 preserve **`ROOT_DEPS=6` (0 new runtime npm deps)**, `shell: false`, and `<= 60 MB` idle RSS:

### 1. Zero-Dep WebAuthn Passkeys (FIDO2) + Ephemeral Secret Leases (`passkeyService.js`, `secretLeaseService.js`)
- **Passkeys without `@simplewebauthn`:** ~180-LOC minimal RFC 8949 CBOR decoder (`attestationObject` + COSE key map) paired with Node's native `crypto.verify(null, Buffer.concat([authData, sha256(clientDataJSON)]), pubKeyObj, sig)` supporting **ES256 (`alg:-7`, P-256 JWK)** and **Ed25519 (`alg:-8`, SPKI DER)**. Strictly checks `origin`, `rpIdHash`, `UP`/`UV` flags, single-use 120s challenge LRU, and monotonic `signCount` anti-cloning.
- **Infisical/Vault-Class Secret Leases & Break-Glass:** Time-bounded scoped secret leases (`ttlSec`, auto-expiry sweep, renewal audit) + rotation-age alerts (`>90d`) in `alertEngine.js`, plus an audited **Break-Glass Emergency Access** token (mandatory reason, max 15-min TTL, instant webhook alert to owners).

### 2. Runtime SBOM CVE Drift Scanner via OSV.dev Batch API (`server/services/cveDriftService.js`)
- **Zero-Dep Design:** Reads Culkibo's existing **CycloneDX 1.6 SBOM** (`scripts/release-provenance.js` / `supplyChainAttestor.js` `components[].purl`) and queries `POST https://api.osv.dev/v1/querybatch` in 500-item chunks using native Node `fetch` (strictly allowlisted to `api.osv.dev`, 24h local cache in `CULKIBO_DATA_DIR/data/cve-cache.json`, clean offline fallback). Detects newly disclosed CVEs on *already-running* releases, ranks by severity/fix availability, triggers `alertEngine.js`, and exposes MCP tool `culkibo_cve_scan`.

### 3. Live Container & DB Drift Detector + PgBouncer Smart Pool Preset (`server/services/driftDetectorService.js`)
- **Cures `kamal#1790`:** Compares live container metadata (`Image`/`RepoDigests` SHA-256, `HostConfig.Memory`/`NanoCpus`, port bindings, env *key-set* hash — never plaintext values!) against Culkibo's declared project/DB/`culkibo.yaml` state. Outputs structured `{ drifted, severity, diffs: [{ field, declared, actual }], reconcilePlan }` with 1-click drift repair.
- **PgBouncer Pooler Safety:** Adds opt-in managed PgBouncer preset with `pool_mode=transaction`, `max_prepared_statements=200`, and automatic client connection-string hint (`?pgbouncer=true`) preventing Prisma/Drizzle prepared-statement crashes.

### 4. Status Page Incident Timeline + Maintenance Windows + Multi-CAA / 6-Day ACME & Geo-Failover (`uptimeMonitor.js`, `ingressManager.js`)
- **Maintenance & Public Incidents (BetterStack/Uptime Kuma-class, minus `#7704/#8193` bugs):** Persisted recurring/one-shot maintenance windows (same-day start aware, dynamic `Date.now()` gate — never frozen) that suppress alert storms while displaying public banners + structured incident timelines (`investigating → identified → monitoring → resolved`) on `/status/:slug`.
- **Multi-CAA + 6-Day Short-Lived ACME + DNS Geo-Failover:** Check **every** `dns.promises.resolveCaa()` record before Caddy TLS issuance (`uptime-kuma#6519`), add opt-in Caddy `acmeProfile: 'shortlived'` (Let's Encrypt 6-day certs) + ECH QUIC probe (`caddy#7670`), and expose an Active-Passive **Geo-Failover Plan** coordinating `uptimeMonitor` checks with `cloudflareService.js` DNS `A`/`AAAA` cutover.

### 5. OpenTofu/Terraform HCL & Compose IaC Exporter + Autonomous MCP Triage (`iacExporter.js`, `mcpServer.js`)
- **Zero Lock-In IaC Export (massive HN/`r/selfhosted` trust multiplier):** Deterministically compiles any Culkibo estate (`culkibo.yaml` + projects + DBs + domains + crons + WireGuard mesh) into clean **OpenTofu/Terraform `.tf`** (`docker` + `cloudflare` providers) AND portable `docker-compose.yml` using `${var.*}` secret placeholders (zero plaintext secrets ever emitted!).
- **MCP `2026` Multi-Step Autonomous Triage (`culkibo_triage_playbook`):** Single read-only orchestrator tool chaining `diagnose_incident` → `buildHealerService` → `driftDetector` → `cveDriftService` into a unified root-cause dossier with ranked `dryRun` remediation plans!

---

## 3. Exact Cycle-8 Regression Tests (`tests/competitor-prs.test.js`)

1. **Dokploy `CVE-2026-129315` & `CVE-2026-133520` (`GHSA-q7cq-vxv7-449c`):** Static check that `scripts/install.sh` never assigns `0777` to config/data paths (`0600`/`0700` enforced); verify repo/directory API rejects `../` and cross-tenant `repoPath` traversal.
2. **Runtipi `CVE-2026-47277` (`GHSA-qrqj-p7hm-4m66`) & TOTP Throttle:** Verify asset/catalog file readers call `fs.realpathSync` and block escaping symlinks; verify TOTP verification locks out after `<=5` failed 6-digit attempts.
3. **Dokku `CVE-2026-54636` & Kamal `#1790` Drift:** Reject `;`, `>`, `$()` in imported `app.json`/cron tasks via `safeCommand.js`; assert `driftDetectorService` catches image digest, memory limit, and `0.0.0.0` port drift vs declared config.
4. **Uptime Kuma `#7704`, `#8193`, `#6519`:** Assert same-day recurring maintenance window fires on day 0, multi-day interval (`>=2d`) advances dynamically across simulated timestamps, and CAA pre-flight validates **all** returned CAA records (not only `[0]`).
5. **WebAuthn COSE/ES256+Ed25519 + OSV Batch + Lease Expiry:** Assert `passkeyService` verifies live Node-signed P-256 & Ed25519 assertions while rejecting bad `origin`/`rpIdHash`/replayed challenge/regressed `signCount`; assert expired secret lease fails closed and `cveDriftService` batches CycloneDX `purl`s cleanly with offline fallback.
