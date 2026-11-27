# Culkibo Cycle-8 Competitor Forensics & Cycle-9 Pioneer Blueprint

> **Date:** 2026-11-27 · **Baseline:** Cycle #7 (`5b101ee`, `99.4%` Launch Readiness, `ROOT_DEPS=6`, `51 MB` RSS, `120→125` MCP tools) · **Scope:** Fresh 2025–2026 CVEs, ecosystem shifts & PRs (zero overlap with Cycles #1, #3, #6, #7) + 5 zero-dep Cycle-9 breakthroughs.

---

## 1. Fresh 2025–2026 Competitor Forensics & Market Shifts

| Domain | Real 2025–2026 Citations | Root Cause & Ecosystem Impact | Culkibo Guardrail & Win |
|---|---|---|---|
| **MinIO Community Archiving & S3 Exodus** | [`minio/minio`](https://github.com/minio/minio) (May 2025 console gutting → archived read-only); [`deuxfleurs/garage`](https://git.deuxfleurs.fr/Deuxfleurs/garage), [`rustfs/rustfs`](https://github.com/rustfs/rustfs), [`seaweedfs/seaweedfs`](https://github.com/seaweedfs/seaweedfs) | MinIO removed bucket/policy UI from AGPL CE (paywalled under AIStor), halted Docker builds, and archived its community repo — stranding thousands of Coolify/Dokploy MinIO templates without a modern S3 console or presigned-URL UI. | Ship 1-click **Garage / RustFS / SeaweedFS** S3 presets + native zero-dep **AWS SigV4 Presigned URL & Bucket CORS/Lifecycle Manager** (`objectStorageService.js`). |
| **Multi-Tenant Authz & Metering IDORs** | **Dokploy `CVE-2026-116068`** (`<=0.30.10`), **`CVE-2026-127212`** (`<0.31.1`); [`coolify#1744`](https://github.com/coollabsio/coolify/discussions/1744) (White-label) | `CVE-2026-116068` let org admins control foreign tenants' apps via `applicationId`; `CVE-2026-127212` leaked other orgs' metrics via `readAppMonitoring(appName)`; Coolify omitted white-labeling (`#1744`) while Dokploy paywalled it under Enterprise. | Enforce strict tenant/project ACL checks on ALL quota/metering/monitoring routes, escape CSV formula injection (`=+-@`), and ship native white-label branding + agency usage ledger. |
| **Outbound URL SSRF & WS Terminal RCE** | **Portainer `CVE-2026-134756`** (`2.39.0–2.45.1`), **`CVE-2026-134804`**; **Dokploy `CVE-2026-24841`** (`<0.26.6`, CVSS 9.9) | Portainer validated outbound URLs syntactically (`validate.IsURL`) without DNS-resolved IP checks, enabling SSRF to loopback/cloud metadata; Dokploy interpolated `containerId`/`activeWay` into shell on `/docker-container-terminal`. | Resolve & validate destination IPs via `ssrfGuard.js` on **every** outbound webhook delivery/retry (anti-DNS-rebinding); keep `containerTerminalService.js` 0-shell + strict regex/RBAC. |
| **Unreliable Webhooks (No DLQ / No Dual-Secret Rotation)** | [`standard-webhooks`](https://github.com/standard-webhooks/standard-webhooks) / `svix-webhooks`; Coolify stale-URL & stuck `in_progress` hooks; Dokploy query-token hooks | Coolify/Dokploy send fire-and-forget webhooks or bare query tokens with no Dead-Letter Queue, no replay UI, and no zero-downtime HMAC secret rotation — dropping critical deploy/alert events during rolling restarts. | Ship **Standard-Webhooks Event Bus + DLQ** (`webhook-id`, `webhook-timestamp`, `webhook-signature` `v1,<b64>`, dual-secret rotation, jitter backoff, deterministic replay). |
| **DB Studio Friction & Control-Plane DB Crashes** | [`coolify#9401`](https://github.com/coollabsio/coolify/issues/9401) (Redis recreate constraint), `SQLSTATE[42703]`; [`dokploy#3296`](https://github.com/Dokploy/dokploy/issues/3296); Portainer `BoltDB` schema mismatch; Drizzle Gateway v1.3–1.8 | Devs must deploy extra Adminer/Drizzle containers just to inspect rows/bloat or Redis keys safely, while heavy control-plane DBs (Postgres/BoltDB) suffer schema-upgrade lockouts. | Keep Culkibo's zero-DB atomic JSON control plane AND add a zero-sidecar **Read-Only Live DB Studio & Redis Inspector** with hard SQL write-blocking, `EXPLAIN`, and bloat diagnostics. |

---

## 2. Top 5 Zero-Dep (`ROOT_DEPS=6`) Cycle-9 Pioneering Breakthroughs

All 5 preserve **`ROOT_DEPS=6` (0 new runtime npm deps)**, `shell: false`, and `<= 60 MB` idle RSS:

### 1. Standard-Webhooks Outbound Event Bus + DLQ & Replay (`server/services/webhookEventBus.js`)
- **Spec-Compliant Cryptography:** Full [`standard-webhooks`](https://github.com/standard-webhooks/standard-webhooks) envelope (`webhook-id: msg_<id>`, `webhook-timestamp`, `webhook-signature: v1,<b64>` using base64-decoded `whsec_` key over `${id}.${ts}.${body}`). Supports **dual-secret rotation** (signs with both primary + grace-window secondary secret for zero-downtime cutovers!).
- **DLQ & Anti-SSRF Delivery:** Re-validates resolved DNS IPs via `ssrfGuard.js` on *every* delivery & retry (`Portainer CVE-2026-134756`), applies 10s response timeout + exponential jitter (`1s → 4s → 16s → 64s`), persists exhausted deliveries atomically (`0o600`, max 500 entries) in `CULKIBO_DATA_DIR/data/webhook-dlq.json`, and exposes `replayDlqEntry(id)` + `replayAllFailed()` + `verifyStandardWebhookSignature(...)`.

### 2. Zero-Dep Read-Only Live DB Studio & Safe Redis Inspector (`server/services/dbStudioService.js`)
- **Strict Read-Only SQL Gate:** Strips `--`/`/* */` comments, rejects multi-statement `;` and all mutating/DDL/shell tokens (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `TRUNCATE`, `CREATE`, `GRANT`, `REVOKE`, `COPY`, `CALL`, `DO`, `SET`, `VACUUM`, `ATTACH`, `PRAGMA` write, `psql` `\!`/`\copy`). Wraps approved `SELECT`/`EXPLAIN`/`SHOW`/`WITH` queries in `BEGIN TRANSACTION READ ONLY` + `SET LOCAL statement_timeout = '5000ms'` + `LIMIT 200` cap!
- **Bloat & Redis Safety:** Built-in PostgreSQL table/index bloat inspector (`pg_stat_user_tables` dead tuples + unused index ratio) + `EXPLAIN (FORMAT JSON)` plan summary; safe Redis/Valkey inspector allowing ONLY read-only `SCAN` (cursor-capped `<=100`), `TYPE`, `TTL`, `DBSIZE`, `INFO memory` while strictly denying `KEYS *`, `FLUSHALL`, `CONFIG`, `EVAL`, `DEBUG`, `SHUTDOWN`.

### 3. Post-MinIO S3 Storage Orchestrator + Zero-Dep SigV4 Presigned URLs (`server/services/objectStorageService.js`)
- **2026 MinIO Successor Presets:** Pinned, private-bridge-default presets for **Garage** (`dxflrs/garage`, CRDT Rust S3), **RustFS** (`rustfs/rustfs`, Apache-2.0 MinIO drop-in w/ ILM & Object Lock), and **SeaweedFS** (`seaweedfs/seaweedfs`) — zero manual boilerplate.
- **Zero-Dep SigV4 Presigner & Bucket Policy Builder:** Pure `node:crypto` AWS SigV4 query-string presigned URL generator (`X-Amz-Algorithm=AWS4-HMAC-SHA256`, alphabetically sorted canonical query, `UNSIGNED-PAYLOAD`, clamped `60..604800s`, strict bucket/key traversal rejection) + declarative S3 XML builders for **Bucket CORS** (`PutBucketCors`, rejecting wildcard `*` + credentials) and **Lifecycle Rules** (`Expiration` + `AbortIncompleteMultipartUpload`, compatible with Garage & RustFS).

### 4. Agency Multi-Tenant Quota Engine & Billing Usage Ledger (`server/services/quotaMeteringService.js`)
- **Fail-Closed Quotas & Tenant Isolation (`Dokploy CVE-2026-116068`/`CVE-2026-127212`):** Per-project/tenant caps (`maxContainers`, `maxMemoryMb`, `maxCpuCores`, `maxStorageGb`, `maxBandwidthGbMo`) enforced before deploy/scale; every query strictly filters by caller tenant/project ACL!
- **Client Billing Ledger:** Aggregates CPU-hours, RAM GB-hours, storage GB, and bandwidth GB into JSON and **CSV-formula-injection-safe** CSV (`=`, `+`, `-`, `@`, `\t`, `\r` neutralized with leading `'`) so agencies invoice clients transparently without external billing bloat.

### 5. Open-Core White-Label Brand & Custom Login Theme Engine (`server/services/brandThemeService.js`)
- **Answers `coolify#1744` & Dokploy Enterprise paywall:** Atomic (`0o600`) persisted white-label profile (`CULKIBO_DATA_DIR/data/brand-theme.json`) supporting custom `brandName`, `tagline`, `accentHex` (strict `/^#[0-9a-fA-F]{6}$/`), `logoUrl` (HTTPS-only or strict sanitized non-script inline SVG — rejects `javascript:`, `<script>`, `on*=` event handlers!), `supportUrl`, and `hidePoweredBy`. Served via public read-only `GET /api/brand` (owner-only `PUT /api/brand` with audit logging).

---

## 3. Exact Cycle-9 Regression Tests (`tests/competitor-prs.test.js`)

1. **Dokploy `CVE-2026-116068` & `CVE-2026-127212` Tenant Isolation:** Assert non-owner tenant requesting another org's `projectId`/`appName` on quota, usage ledger, DB studio, or monitoring endpoints receives HTTP `403` (0 cross-tenant leak); verify CSV export neutralizes `=CMD|...` formula payloads.
2. **Portainer `CVE-2026-134756` Webhook Event Bus SSRF:** Assert `webhookEventBus` blocks `http://127.0.0.1`, `http://169.254.169.254`, and DNS-rebound private IPs on both initial send AND DLQ replay; verify dual-secret `whsec_` signature validation accepts both current & rotating key and rejects tampered timestamps `>300s`.
3. **Dokploy `CVE-2026-24841` Terminal & SQL/Redis Write-Guard:** Verify `dbStudioService` blocks stacked `; DROP TABLE`, `COPY ... TO PROGRAM`, `psql` `\!`, and Redis `FLUSHALL`/`EVAL`/`KEYS *` while allowing parameterized read-only `SELECT`/`EXPLAIN`/`SCAN`.
4. **SigV4 Presigned URL & Bucket CORS Hardening:** Verify `objectStorageService` generates RFC-compliant `X-Amz-Signature` URLs (deterministic golden test vector), rejects `../` object keys & `expiresIn > 604800`, and rejects invalid CORS (`*` + credentials).
5. **White-Label XSS/Injection Guard (`coolify#1744`):** Verify `brandThemeService` rejects `javascript:` URLs, `<script>`/`onerror=` SVG payloads, and invalid CSS hex colors while persisting clean brand configs atomically.
