# Culkibo Cycle-14 Competitor Forensics & Cycle-15 Pioneer Blueprint

> **Date:** 2026-11-27 · **Baseline:** Cycle #13 (`1ed952b`, `99.61%`, `51 MB` RSS, `142.2 ms` boot, `7,660 req/s`, `62 µs` Wasm, `62→65` suites, `150→155` MCP tools, `ROOT_DEPS=6`) · **Scope:** Fresh 2025–2026 PRs, issues & standards (zero overlap with Cycles #1, #3, #6–#13) + 5 zero-dep Cycle-15 blueprints.

---

## 1. Fresh 2025–2026 Competitor Forensics (mTLS, Flags, AI Rate-Limits, Cryptominers & Freight)

| Domain | Real 2025–2026 Citations | Root Cause & Operational Blast Radius | Culkibo Guardrail & Win |
|---|---|---|---|
| **Zero-Trust mTLS & Private Network CA Gap** | [`coolify#8524`](https://github.com/coollabsio/coolify/discussions/8524) (UI mTLS client certs), [`dokploy#2605`](https://github.com/Dokploy/dokploy/issues/2605) (private-network certs); Portainer BE-only mTLS; [`spiffe/spire`](https://github.com/spiffe/spire) & Caddy `client_authentication` | Self-hosters lack automated short-lived client certs and internal service-to-service mTLS without deploying heavy Envoy/SPIRE clusters or paying Portainer BE licenses. | Pure `node:crypto` **SPIFFE-Lite mTLS Identity CA** issuing short-lived Ed25519 certs + CRL revocation + Caddy `require_and_verify` JSON compiler. |
| **No Native Feature Flags or Instant Kill-Switch** | CNCF [`open-feature`](https://github.com/open-feature), [`Unleash/unleash`](https://github.com/Unleash/unleash), [`Flagsmith/flagsmith`](https://github.com/Flagsmith/flagsmith) deterministic bucketing | Coolify/Dokploy/Kamal force full container rebuilds or rollbacks to disable broken features or gate beta tenants instead of flipping a deterministic flag in `< 1 ms`. | Native **OpenFeature-Lite Feature Flag Engine** with deterministic SHA-256 bucketing, tenant targeting & 1-click instant kill-switch (zero redeploys). |
| **AI "Denial-of-Wallet" & Missing IETF Rate-Limits** | IETF `draft-ietf-httpapi-ratelimit-headers` (`RateLimit`, `RateLimit-Policy`); OpenAI RPM/TPM limits; Coolify/Dokploy API 429 opacity | Runaway AI agents or DoW loops drain LLM API budgets in minutes; PaaS proxies lack dual-dimension (RPM + TPM) plan-tier token buckets & standardized `429 Retry-After` headers. | Native **Edge API Rate-Limit & AI Wallet-Drain Shield** with RPM+TPM buckets, IETF `RateLimit` headers, burst simulator & Caddy edge compiler. |
| **Automated Cryptominer Bots & Runtime Blindness** | [`dokploy#5156`](https://github.com/Dokploy/dokploy/issues/5156) (*"Crypto miner bot scanning new Dokploy instances & compromising them immediately"*); [`falcosecurity/falco`](https://github.com/falcosecurity/falco) & [`falcosecurity/rules`](https://github.com/falcosecurity/rules) | Newly exposed or popped containers get hit instantly by XMRig/Stratum miners, `/dev/tcp/` reverse shells, `curl\|sh` droppers, and `/etc/shadow` reads with zero runtime alerting. | Zero-dep **Falco-Lite Runtime Anomaly Rules Engine** (10 real-time process/file/socket detectors catching miners, reverse shells & `/tmp` execs). |
| **Mutable-Tag Drift Across `dev → staging → prod`** | [`dokploy#2097`](https://github.com/Dokploy/dokploy/issues/2097) (multi-env per project), [`argo-cd#5290`](https://github.com/argoproj/argo-cd/discussions/5290)/[`#5667`](https://github.com/argoproj/argo-cd/discussions/5667), [`akuity/kargo`](https://github.com/akuity/kargo) immutable Freight | Rebuilding separately per branch breaks artifact parity; mutable `:latest` tags drift silently between staging QA and prod without approval or env-key checks. | **Immutable `sha256:` Digest Promotion Pipeline** (`dev → staging → prod`) with dual-control approvals, env-key parity diff & rollback manifest. |

---

## 2. Top 5 Zero-Dep (`ROOT_DEPS=6`) Cycle-15 Blueprints & Exact API Contracts

All 5 keep **`ROOT_DEPS=6`**, `shell: false`, lazy-require, `0o600` atomic storage, and idle RSS `<= 60 MB`:

### 1. Zero-Trust SPIFFE-Lite mTLS Identity & Cert Lifecycle (`server/services/mtlsMeshService.js`)
- **Contract:** Atomic `0o600` store `CULKIBO_DATA_DIR/data/mtls-mesh.json` + CA private key (`0o600`, NEVER exposed via API!). Exports `initTrustDomain(domain?)`, `issueWorkloadCert({ serviceName, namespace = 'prod', ttlHours = 24, nowMs })`, `verifyWorkloadCert({ cert, signatureB64, nowMs })`, `revokeWorkloadCert(serial, { reason, actor })`, `listWorkloadCerts({ includeRevoked? })`, `compileCaddyMtlsPolicy({ allowedSpiffeIds = [], mode = 'require_and_verify' })`.
- **Guards (`coolify#8524`, `dokploy#2605`, SPIFFE):** Pure `node:crypto` Ed25519 trust-domain CA signing `spiffe://<domain>/ns/<ns>/sa/<service>` descriptors (`ttlHours` clamped `1..168`), instant CRL revocation (`CERT_REVOKED` / `CERT_EXPIRED`), and native Caddy v2.11 `client_authentication` JSON compilation!
- **Routes & MCP:** `GET /api/security/mtls/certs`, `POST /api/security/mtls/issue`, `POST /api/security/mtls/verify`, `POST /api/security/mtls/revoke/:serial` (`admin` on issue/revoke) · MCP `culkibo_mtls_mesh`.

### 2. Native Declarative Feature Flags & Instant Kill-Switch (`server/services/featureFlagService.js`)
- **Contract:** Store `CULKIBO_DATA_DIR/data/feature-flags.json`. Exports `computeDeterministicBucket(flagKey, subjectId, salt?)` (`0.00..99.99` via SHA-256 `readUInt32BE(0) % 10000 / 100`), `saveFlag({ key, description?, enabled = true, rolloutPct = 0, environment = 'prod', allowTenants = [], denyTenants = [], payload = {}, salt? })`, `listFlags()`, `evaluateFlag({ key, subjectId, tenantId?, environment = 'prod' })` → `{ key, enabled, reason, bucket, variant, payload }`, `killFlag(key, { reason, actor })`, `deleteFlag(key)`.
- **Guards (OpenFeature/Unleash/Flagsmith DNA):** Denylist overrides allowlist; `killFlag` sets `killed: true, enabled: false` atomically so emergency shutoffs take effect immediately without redeploys!
- **Routes & MCP:** `GET/POST /api/flags`, `POST /api/flags/:key/evaluate`, `POST /api/flags/:key/kill`, `DELETE /api/flags/:key` · MCP `culkibo_feature_flags`.

### 3. Edge API Rate-Limit & AI Wallet-Drain Shield (`server/services/apiRateLimitService.js`)
- **Contract:** Store `CULKIBO_DATA_DIR/data/ratelimit-policies.json`. Exports `PLAN_PRESETS` (`free`, `pro`, `enterprise`), `saveRateLimitPolicy({ id?, projectId?, name, planTier = 'pro', rpmLimit = 120, tpmLimit = 60000, burstMultiplier = 1.5, windowSec = 60 })`, `listRateLimitPolicies()`, `consumeTokenBucket({ policyId, clientKey, tokens = 0, nowMs })` → `{ allowed, httpStatus, headers: { 'RateLimit', 'RateLimit-Policy', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'Retry-After'? }, remainingRpm, remainingTpm }`, `simulateBurst({ policyId, requestsCount, tokensPerRequest, intervalMs = 50 })`, `compileCaddyRateLimitConfig(policy)`.
- **Guards (IETF `RateLimit` draft & AI DoW):** Enforces dual RPM + TPM buckets simultaneously, returning `429` + `Retry-After` + IETF structured headers whenever either dimension saturates!
- **Routes & MCP:** `GET/POST /api/edge/ratelimits`, `POST /api/edge/ratelimits/simulate` · MCP `culkibo_api_ratelimit`.

### 4. Falco-Lite Container Runtime Anomaly Detector (`server/services/runtimeAnomalyService.js`)
- **Contract:** Store `CULKIBO_DATA_DIR/data/runtime-anomalies.json` (last 200 alerts). Exports `ANOMALY_RULES` (10 rules: `CRYPTOMINER_STRATUM_TRAFFIC` `xmrig`/`stratum+tcp`/ports `3333|4444|14444`, `REVERSE_SHELL_SPAWN` `/dev/tcp/`/`nc -e`/`bash -i`/`socat`, `SENSITIVE_FILE_ACCESS` `/etc/shadow`/`/etc/passwd` write/`core_pattern`, `REMOTE_SCRIPT_PIPE_EXEC` `curl|sh`/`wget|bash`, `UNEXPECTED_PRIVILEGED_EXEC`, `BINARY_DRIFT_IN_TMP` `/tmp/` or `/dev/shm/` exec, `DOCKER_SOCK_PROBE`, `PACKAGE_MANAGER_AT_RUNTIME`, `ENV_CREDENTIAL_SCRAPE`, `ANOMALOUS_OUTBOUND_C2_PORT`), `inspectRuntimeEvents({ projectId, containerName, events = [], persist = true })` → `{ ok: true, clean, riskScore, criticalCount, highCount, alerts[], recommendedAction }`, `listAnomalies(projectId?)`.
- **Guards (`dokploy#5156` & Falco):** Flags compromised miner/shell events deterministically with zero kernel-module deps while passing clean runtime telemetry (`clean: true, riskScore: 0`).
- **Routes & MCP:** `GET /api/projects/:id/anomalies`, `POST /api/projects/:id/anomalies/inspect` (project ACL) · MCP `culkibo_runtime_anomaly`.

### 5. Immutable Digest Multi-Env GitOps Promotion Pipeline (`server/services/digestPromotionService.js`)
- **Contract:** Store `CULKIBO_DATA_DIR/data/digest-promotions.json`. Exports `validateImmutableDigest(imageRef)` (requires `@sha256:<64hex>`, rejects `:latest` / mutable tags with `MUTABLE_TAG_FORBIDDEN`), `createPromotion({ projectId, imageRef, fromEnv = 'staging', toEnv = 'prod', sourceEnvKeys = [], targetEnvKeys = [], requester, requireDualControl = true, previousDigest? })` → checks missing required target env keys (`MISSING_TARGET_ENV_KEYS` — keys ONLY, zero secret values!), `approvePromotion(promoId, { approver, comment })` (rejects `approver === requester` when `requireDualControl: true` with `DUAL_CONTROL_VIOLATION`!), `executePromotion(promoId, { dryRun = true })` (requires `status === 'approved'` for `prod`), `rollbackPromotion(promoId, { actor, dryRun = true })`, `listPromotions(projectId?)`.
- **Routes & MCP:** `GET/POST /api/projects/:id/promotions`, `POST /api/projects/:id/promotions/:promoId/{approve,execute,rollback}` (project ACL) · MCP `culkibo_digest_promotion`.

---

## 3. Exact Cycle-15 Regression Tests (`tests/competitor-prs.test.js` Section 17 `17a–17e`)

1. **`17a` (`coolify#8524` / `dokploy#2605` / SPIFFE mTLS):** `mtlsMeshService` issues Ed25519 workload cert, verifies valid signature, rejects revoked (`CERT_REVOKED`) & expired (`CERT_EXPIRED`) certs, leaks 0 CA private key, and compiles Caddy `require_and_verify` JSON.
2. **`17b` (OpenFeature / Unleash / Flagsmith):** `featureFlagService` computes deterministic buckets, honors tenant deny/allow overrides, and flips immediately to `enabled: false` via `killFlag` with zero redeploy.
3. **`17c` (IETF `RateLimit` / AI Denial-of-Wallet):** `apiRateLimitService` enforces both RPM & TPM buckets, emits `429` + `Retry-After` + `RateLimit`/`RateLimit-Policy` headers on AI token burst overflow.
4. **`17d` (`dokploy#5156` Cryptominer & Falco Rules):** `runtimeAnomalyService` flags `xmrig`/`stratum+tcp:3333`, `/dev/tcp/` reverse shell, `curl|sh`, `/etc/shadow`, and `/tmp/` exec while passing clean app events (`clean: true`).
5. **`17e` (`dokploy#2097` / Kargo Freight):** `digestPromotionService` blocks `:latest` (`MUTABLE_TAG_FORBIDDEN`), blocks missing target env keys (`MISSING_TARGET_ENV_KEYS`), blocks self-approval (`DUAL_CONTROL_VIOLATION`), executes approved `sha256:` promotion, and rolls back to `previousDigest`.
