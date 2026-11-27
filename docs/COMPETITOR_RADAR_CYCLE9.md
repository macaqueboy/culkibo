# Culkibo Cycle-9 Competitor Forensics & Cycle-10 Milestone Blueprint

> **Date:** 2026-11-27 · **Baseline:** Cycle #8 (`99.5%` Launch Readiness, `ROOT_DEPS=6`, `55 MB` RSS, `47→50` suites, `125→130` MCP tools) · **Scope:** Fresh 2025–2026 CVEs, PRs & issues (zero overlap with Cycles #1, #3, #6, #7, #8) + 5 zero-dep Cycle-10 milestone breakthroughs.

---

## 1. Fresh 2025–2026 Competitor Forensics (Backup Chaos, Remote Builders, AI/GPU & Logs)

| Domain | Real 2025–2026 Citations | Root Cause & Production Blast Radius | Culkibo Guardrail & Win |
|---|---|---|---|
| **Silent Empty Backups, Stripped Grants & Restore Locks** | [`dokploy#1382`](https://github.com/Dokploy/dokploy/issues/1382), [`#6035`](https://github.com/Dokploy/dokploy/issues/6035); [`coolify#6506`](https://github.com/coollabsio/coolify/issues/6506), [`#12244`](https://github.com/coollabsio/coolify/issues/12244); [`portainer#12686`](https://github.com/portainer/portainer/issues/12686) | Scheduled S3 Postgres backups silently uploaded empty `0 B`/`20 B` `.sql.gz` files (`dokploy#1382`, `coolify#6506`); `pg_dump --no-acl --no-owner` wiped Supabase grants crashing `GoTrue` on restore (`coolify#12244`); Dokploy v0.31.1 rejected authorized prod→dev restores (`#6035`). | Automated **DR Fire-Drill Verifier** rejecting `<=64 B`/empty gzip dumps, validating SQL structure & SHA-256, preserving ACLs when needed, and permitting audited same-org cross-target restores. |
| **Remote Builder SSH Kills, Queue Bottlenecks & Preview OOM** | [`coolify#11372`](https://github.com/coollabsio/coolify/issues/11372), [`#10853`](https://github.com/coollabsio/coolify/issues/10853); [`dokploy#3226`](https://github.com/Dokploy/dokploy/issues/3226), [`#3450`](https://github.com/Dokploy/dokploy/issues/3450); [`kamal#1886`](https://github.com/basecamp/kamal/issues/1886) | Coolify's age-based SSH mux cleanup ran `ssh -O exit` mid-build killing deploys with exit `255` (`#11372`); Dokploy serialized multiple build servers onto 1 queue (`#3226`) and built PR previews locally on prod hosts (`#3450`); remote builder disks filled silently. | Ref-count pin SSH ControlMasters during active builds (never recycle while active), assign per-builder queues, offload **both** prod & PR previews, ship layers via `directPushRegistry.js`, and prune remote caches. |
| **Self-Hosted AI/GPU Traps & Ollama/vLLM CVEs** | [`dokploy#1621`](https://github.com/Dokploy/dokploy/issues/1621) (`gpu=1`); **Ollama `CVE-2025-63389`, `CVE-2026-7482`, `CVE-2026-7020`**; **Open WebUI `CVE-2026-54021`**; **vLLM `CVE-2026-22778` (CVSS 9.8), `CVE-2026-137477`, `CVE-2026-137476`** | Unauthenticated `-p 11434:11434` exposed GPUs publicly (`CVE-2025-63389`); vLLM async pipeline parallelism leaked cross-user KV-cache tokens (`CVE-2026-137477`) & suffered multimodal RCE (`CVE-2026-22778`); CDI (`nvidia.com/gpu=all`) gaps caused silent CPU fallback. | Native **AI/GPU Workload Orchestrator**: VRAM + KV-cache pre-flight, CDI + NVIDIA toolkit detection, mandatory private/auth-proxy binding, vulnerable image-tag warnings, and Caddy OpenAI token/rate guardrails. |
| **Ephemeral Logs Wiped on Deploy & Missing SLO Canaries** | [`coolify#12170`](https://github.com/coollabsio/coolify/discussions/12170), [`#12176`](https://github.com/coollabsio/coolify/issues/12176); [`dokploy#2748`](https://github.com/Dokploy/dokploy/issues/2748), [`#6112`](https://github.com/Dokploy/dokploy/issues/6112); Argo Rollouts / Flagger + Caddy `weighted_round_robin` | Container logs vanish on every redeploy unless users run heavy Loki/FluentBit stacks (`coolify#12170`); no self-hosted PaaS ships Google SRE burn-rate progressive canary rollback natively over Caddy v2.11 weights. | Native **`.ndjson.gz` Compressed Log Archive & Search** surviving redeploys + **SLO Error-Budget Canary Auto-Rollback** (`10%→25%→50%→100%`) directly via Caddy Admin API. |

---

## 2. Top 5 Zero-Dep (`ROOT_DEPS=6`) Cycle-10 Milestone Breakthroughs

All 5 preserve **`ROOT_DEPS=6` (0 new runtime npm deps)**, `shell: false`, and `<= 60 MB` idle RSS:

### 1. Automated DR Backup Restore Fire-Drill Engine (`server/services/backupDrillService.js`)
- **Zero-Dep Chaos Verification:** Validates local/S3 backup artifacts without corrupting live DBs: (a) rejects `0 B` / `<= 64 B` / empty 20-byte gzip payloads (`dokploy#1382`, `coolify#6506`); (b) verifies SHA-256 checksum + AES-256-GCM decrypt + `zlib.gunzipSync` stream integrity; (c) parses SQL dump headers/DDL markers (detecting stripped ACL/owner flags for Supabase/role-heavy DBs, `coolify#12244`, and checking engine major-version compatibility); (d) supports authorized same-org cross-service restore plans (`dokploy#6035`). Persists signed DR Drill Scorecards (`CULKIBO_DATA_DIR/data/dr-drills.json`: `rtoMs`, `rpoSec`, `bytesVerified`, `verdict: 'PASS'|'FAIL'`) and triggers `alertEngine` on failure.

### 2. SLO Error-Budget Canary Auto-Rollback Controller (`server/services/sloCanaryController.js`)
- **Argo Rollouts / Flagger DNA over Native Caddy v2.11:** Orchestrates stepped traffic splits (`steps: [10, 25, 50, 100]`) using Caddy `reverse_proxy` `lb_policy: weighted_round_robin` (`stableWeight` / `canaryWeight`). Evaluates **Google SRE error-budget burn rate** (`burnRate = canary5xxRate / (1 - sloTarget)`, default SLO `99.9%` → abort if `burnRate > 14.4` OR `canaryP95Ms > baselineP95Ms * maxLatencyRatio`) at every step. On breach, immediately flips Caddy weights to `100 / 0`, marks rollout `ROLLED_BACK`, logs audit event + alert, and exposes MCP `culkibo_slo_canary` (`start`/`evaluate`/`advance`/`abort`).

### 3. Self-Hosted AI / GPU & Local LLM Workload Orchestrator (`server/services/aiWorkloadService.js`)
- **Zero-Dep GPU Pre-Flight & Guardrails:** Supports **Ollama**, **vLLM**, and **llama.cpp** presets:
  - **VRAM & Quantization Calculator:** Estimates `weightsGb + kvCacheGb` from parameter count (`7B`/`14B`/`32B`/`70B`), quantization (`Q4_K_M`/`Q8_0`/`FP16`), and context length (`ctxLen`), comparing against detected/declared GPU VRAM (supporting both NVIDIA CDI `nvidia.com/gpu=all` and legacy toolkit, curing `dokploy#1621`) to fail closed before CUDA OOM.
  - **CVE & Exposure Shield:** Enforces loopback/private-bridge binding (never unauthenticated `0.0.0.0:11434`, curing `CVE-2025-63389`), checks pinned tags against known vulnerable ranges (`Ollama < 0.17.1` `CVE-2026-7482`, `vLLM < 0.21.1` `CVE-2026-137477` / `CVE-2026-22778`), mounts persistent model-weight cache volumes, and compiles Caddy Bearer-token + body-cap OpenAI-compatible proxy routes.

### 4. Distributed Build-Node Offloader (`server/services/remoteBuilderService.js`)
- **Cures `coolify#11372` & `dokploy#3226/#3450`:** Manages dedicated fleet build nodes (`role: 'builder'`) with **per-node concurrency semaphores** (no single global bottleneck), **active-build SSH mux ref-count pinning** (forbids `ssh -O exit` while `activeBuilds > 0`), explicit **prod + PR preview offload** routing, `linux/amd64` + `linux/arm64` target matching, direct layer push via `directPushRegistry.js` (no external registry required), and post-build remote BuildKit cache pruning (`--keep-storage`).

### 5. Compressed Log Archive & Streaming Search (`server/services/logArchiveService.js`)
- **Cures `coolify#12170` with 0 external stacks:** Archives structured NDJSON container & deploy logs into rotated `CULKIBO_DATA_DIR/data/log-archives/<projectId>/<YYYY-MM-DD>.ndjson.gz` using built-in `zlib.gzip`, enforcing configurable `retentionDays` & `maxArchiveMb` pruning (`dokploy#2270/#6112`). Exposes `searchArchives({ projectId, since, until, level, releaseId, query, regex, limit })` with ReDoS-safe pattern checks and strict project ACL filtering so logs survive every redeploy.

---

## 3. Exact Cycle-10 Regression Tests (`tests/competitor-prs.test.js`)

1. **Empty/Corrupt Backup & Stripped-ACL Drill (`dokploy#1382`, `coolify#6506`/`#12244`, `dokploy#6035`):** Assert `backupDrillService` rejects `0 B` and empty 20-byte `.sql.gz` dumps, verifies `preserveAcl: true` keeps grants, and permits authorized same-org cross-target restore plans.
2. **In-Flight SSH Mux Pin & Preview Builder Offload (`coolify#11372`, `dokploy#3226`/`#3450`):** Assert `remoteBuilderService` blocks mux teardown while `activeBuilds > 0`, isolates per-builder queues, and routes PR previews to designated remote builders.
3. **AI/GPU Security & VRAM Guard (`dokploy#1621`, `CVE-2025-63389`, `CVE-2026-137477`, `CVE-2026-22778`):** Assert `aiWorkloadService` blocks unauthenticated `0.0.0.0:11434` bind, detects VRAM overflow before launch, supports CDI `nvidia.com/gpu=all`, and flags vulnerable Ollama/vLLM image versions.
4. **SLO Burn-Rate Canary Auto-Rollback:** Assert `sloCanaryController` steps `10→25→50→100` on healthy SLO telemetry and immediately rolls back Caddy weights to `100/0` when `burnRate > 14.4×` or p95 breaches ratio.
5. **Compressed Log Archive Survival & ReDoS Guard (`coolify#12170`):** Assert `logArchiveService` writes/reads `.ndjson.gz` across simulated redeploys, prunes oldest files above `maxArchiveMb`, enforces project ACL, and rejects ReDoS regexes.
