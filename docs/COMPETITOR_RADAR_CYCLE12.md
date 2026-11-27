# Culkibo Cycle-12 Competitor Forensics & Cycle-13 Pioneer Blueprint

> **Date:** 2026-11-27 · **Baseline:** Cycle #11 (`a2e0ef4`, `99.61%`, `49 MB` RSS, `66 µs` Micro-Wasm, `56→59` suites, `140→145` MCP tools, `ROOT_DEPS=6`) · **Scope:** Fresh 2025–2026 PRs, issues & ecosystem shifts (zero overlap with Cycles #1, #3, #6–#11) + 5 zero-dep Cycle-13 blueprints.

---

## 1. Fresh 2025–2026 Competitor Forensics (Layer Bloat, Double Crons, PII Void, OOM & On-Call)

| Domain | Real 2025–2026 Citations | Root Cause & Operational Blast Radius | Culkibo Guardrail & Win |
|---|---|---|---|
| **Image Layer Bloat & Secrets Baked in Layers** | [`coolify#7019`](https://github.com/coollabsio/coolify/issues/7019) (PR `#7849`, log secret leaks), [`#5328`](https://github.com/coollabsio/coolify/issues/5328) (BuildKit `.npmrc` layer leaks); [`dokploy#3193`](https://github.com/Dokploy/dokploy/issues/3193), [`#2150`](https://github.com/Dokploy/dokploy/issues/2150); [`wagoodman/dive`](https://github.com/wagoodman/dive), [`goodwithtech/dockle`](https://github.com/goodwithtech/dockle), [`hadolint/hadolint`](https://github.com/hadolint/hadolint) | Secrets passed via `ENV`/`ARG` or uncleaned `.npmrc` persist forever in OCI history (`coolify#5328`); deleting files in a subsequent `RUN` layer hides gigabytes of wasted space (Dive trap); worker nodes fill disks (`dokploy#3193`). | Native zero-dep **Image Layer Bloat & Secret-in-Layer Auditor** scanning both `Dockerfile` & `docker history` JSON with multi-stage slimming plans. |
| **Duplicate Cron Fires & Multi-Replica Races** | [`coolify#5655`](https://github.com/coollabsio/coolify/issues/5655) (daily cron running twice at 00:00 & 03:00 UTC); [`dokploy#1475`](https://github.com/Dokploy/dokploy/issues/1475) (multi-org duplicate triggers firing 2–3×) | Scaled replicas, overlapping slow jobs, or TZ/queue worker offsets fire identical cron tasks twice — causing double billing, duplicate emails, and corrupted batch writes. | Atomic **Distributed Cron Lease & Fencing-Token Guard** deduplicating both concurrent runs AND already-completed schedule slots. |
| **PR-Preview DB PII Leak Void (2025 Archivals)** | `snaplet` shut down (Aug 2024); [`nucleuscloud/neosync`](https://github.com/nucleuscloud/neosync) **archived offline (Aug/Sep 2025)**; [`dalibo/postgresql_anonymizer`](https://gitlab.com/dalibo/postgresql_anonymizer) (`anon` v3.2/3.3, PG-only) | With Snaplet & Neosync gone, teams seeding PR-preview DBs from prod backups risk GDPR/SOC 2 PII leaks (real customer emails, phones, cards, API tokens) across staging environments. | Built-in zero-dep **Deterministic PR-Preview PII Masker** (HMAC-SHA256 seeded pseudonymization preserving FK join integrity across SQL & JSON!). |
| **OOM-Kill / Exit-Code Forensics & False Rollbacks** | Portainer Swarm false rollback on historical `exit 137`; Dokploy healthcheck-induced restart loops; Coolify silent restart loops & `137`/`139` ambiguity | Operators confuse kernel OOM (`137` + `oomKilled`) with forced `SIGKILL` stop (`137` + `!oomKilled`) or CPU arch `SIGSEGV` (`139`); stale historical OOM tasks trigger bogus rollbacks. | Real-time **OOM & Crash-Loop Forensic Classifier** distinguishing `137`/`139`/`134`/`143`/`126`/`127`, ignoring historical tasks, and recommending exact RAM bumps. |
| **Alert Fatigue, Flapping & Missing Escalation** | [`uptime-kuma#3255`](https://github.com/louislam/uptime-kuma/issues/3255) (double notifications on flapping/webhooks) + host-down storms; [`target/goalert`](https://github.com/target/goalert), [`keephq/keep`](https://github.com/keephq/keep), [`grafana/oncall`](https://github.com/grafana/oncall) | Flapping probes spam Slack/Telegram; unacknowledged critical alerts stall with no Tier-1 → Tier-2 escalation or on-call shift rotation. | Native **Incident Dedup, Flapping Damper & On-Call Escalation Router** with fingerprint collapsing, flapping suppression, and ack-timeout escalation tiers. |

---

## 2. Top 5 Zero-Dep (`ROOT_DEPS=6`) Cycle-13 Blueprints & Exact API Contracts

All 5 keep **`ROOT_DEPS=6` (0 new runtime npm deps)**, `shell: false`, lazy-require, and idle RSS `<= 60 MB`:

### 1. Container Image Layer Bloat & Secret-in-Layer Auditor (`server/services/imageBloatAuditor.js`)
- **Contract:** Exports `RULES` (8 rules) & `auditDockerfileAndLayers({ dockerfile?, historyLayers?, stack? })` → `{ efficiencyScore, estimatedSavingsMb, wastedBytes, secretLeaks[], findings[], slimmingRecommendations[], multiStageTemplate }`.
- **8 Checks:** `SECRET_IN_ENV_OR_ARG` (regex for `PASSWORD`/`SECRET`/`TOKEN`/`KEY`/`sk_live_`/`ghp_`/`.npmrc` in `ENV`/`ARG`/`RUN` — `coolify#7019`/`#5328`), `CROSS_LAYER_DELETE_WASTE` (detects `rm` in later layer than create), `UNDELETED_PACKAGE_CACHE` (`apt-get`/`apk`/`pip` cache retained), `MISSING_MULTI_STAGE` (heavy SDK base as final stage), `COPY_ALL_BEFORE_LOCKFILE` (cache bust), `ADD_INSTEAD_OF_COPY`, `HEAVY_BASE_IMAGE` (`node:22` vs `-slim`/`alpine`/`distroless`), `MISSING_NON_ROOT_USER`.
- **HTTP & MCP:** `POST /api/build/image-audit` (`developer`+) · MCP `culkibo_audit_image_bloat`.

### 2. Distributed Cron Idempotency & Fencing-Token Lease Guard (`server/services/cronLeaseService.js`)
- **Contract:** Atomic `0o600` store `CULKIBO_DATA_DIR/data/cron-leases.json`. Exports `acquireCronLease({ jobId, scheduleSlotIso, holderId, ttlSec = 300, nowMs })`, `renewCronLease(leaseId, { holderId, extendSec, nowMs })`, `completeCronLease(leaseId, { holderId, fencingToken, status = 'succeeded', nowMs })`, `listCronLeases(jobId?)`.
- **Guarantees (`coolify#5655`, `dokploy#1475`):** Monotonic `fencingToken++` per job; rejects overlapping active lease (`ALREADY_RUNNING`), rejects duplicate run of an already-completed `scheduleSlotIso` (`ALREADY_EXECUTED_SLOT`), auto-reclaims expired TTL leases, and rejects stale fencing tokens on `completeCronLease` (`STALE_FENCING_TOKEN`).
- **HTTP & MCP:** `GET /api/crons/:id/leases`, `POST /api/crons/:id/lease/acquire`, `POST /api/crons/:id/lease/complete` · MCP `culkibo_cron_lease`.

### 3. PR-Preview DB PII Masking & Anonymization Engine (`server/services/piiMaskerService.js`)
- **Contract:** Zero-dep deterministic HMAC-SHA256 seeded pseudonymizer (preserves FK join consistency across tables without storing raw PII!). Exports `PII_PATTERNS`, `maskValue(val, { type, seed })`, `maskDataset({ rows?, sqlDump?, seed, rules?, autoDetect = true })` → `{ maskedRows?, maskedSql?, maskedCount, fieldsMasked[], zeroPiiLeaked, pgAnonDdl }`.
- **Auto-Detects & Masks:** Emails (`u_<h8>@masked.invalid`), phones (`+1-555-<4d>`), SSNs, credit cards (Luhn-safe fake `4000-0000-0000-<4d>`), IBANs, IPv4/IPv6 (RFC 5737 `192.0.2.x`), JWT/API tokens (`[MASKED_SECRET]`), plus explicit column rules (`hash_email`, `fake_name`, `redact`, `nullify`, `preserve`) and `dalibo/postgresql_anonymizer`-compatible `SECURITY LABEL FOR anon` DDL output!
- **HTTP & MCP:** `POST /api/databases/pii-mask` (`developer`+) · MCP `culkibo_mask_preview_pii`.

### 4. Container OOM-Kill Forensics & Crash-Loop Classifier (`server/services/oomForensicsService.js`)
- **Contract:** Exports `FAILURE_CLASSES`, `computeBackoffSec(restartCount)`, `classifyContainerFailure({ containerName?, exitCode, oomKilled = false, restartCount = 0, memoryLimitMb = 0, memoryPeakMb = 0, cgroupOomKills = 0, recentLogs = '', healthStatus = '', uptimeSec = 0, historicalOnly = false })` → `{ classification, severity, confidence, rootCause, ignoreForRollback, recommendedMemoryMb, backoffSec, remediationActions[] }`.
- **8 Classes:** `CGROUP_OOM_KILL` (`137` + `oomKilled`/`cgroupOomKills>0`, recommends `Math.ceil(Math.max(memoryLimitMb, memoryPeakMb) * 1.5)`), `FORCED_SIGKILL_TIMEOUT` (`137` + `!oomKilled`), `SEGFAULT_ARCH_OR_NATIVE` (`139`), `ABORT_HEAP_OR_ASSERT` (`134`), `GRACEFUL_SIGTERM_EXITED` (`143`), `EXEC_OR_ENTRYPOINT_MISSING` (`126`/`127`), `HEALTHCHECK_CRASH_LOOP` (app listening in logs while probe fails), and `STALE_HISTORICAL_TASK_IGNORED` (`historicalOnly: true` → `ignoreForRollback: true`, curing Portainer false rollbacks!).
- **HTTP & MCP:** `POST /api/projects/:id/forensics/classify` (project ACL) · MCP `culkibo_oom_forensics`.

### 5. Incident Deduplication, Flapping Suppression & On-Call Escalation Router (`server/services/oncallEscalationService.js`)
- **Contract:** Atomic `0o600` store `CULKIBO_DATA_DIR/data/oncall-policies.json`. Exports `savePolicy(input)`, `listPolicies()`, `resolveCurrentOnCall(policyId, nowMs)`, `ingestAlert({ policyId, fingerprint, projectId?, severity, title, state = 'firing', nowMs })`, `acknowledgeIncident(incidentId, { actor, nowMs })`, `evaluateEscalations(nowMs)`, `listIncidents({ activeOnly? })`.
- **GoAlert / Keep DNA (`uptime-kuma#3255`):** Collapses matching open fingerprints (`occurrences++`, `suppressed: true`, 0 duplicate pages), detects flapping (`>=3` `firing↔resolved` transitions inside `flappingWindowSec` → `FLAPPING_SUPPRESSED`), rotates primary responders deterministically by schedule period, escalates unacked incidents Tier 1 → Tier 2 → Tier 3 on `ackTimeoutSec`, and halts escalation immediately upon `acknowledgeIncident`.
- **HTTP & MCP:** `GET/POST /api/oncall/policies`, `GET /api/oncall/incidents`, `POST /api/oncall/ingest`, `POST /api/oncall/incidents/:id/ack`, `POST /api/oncall/evaluate` · MCP `culkibo_oncall_router`.

---

## 3. Exact Cycle-13 Regression Tests (`tests/competitor-prs.test.js` Section 15 `15a–15e`)

1. **`15a` (`coolify#7019`/`#5328` + Dive/Dockle):** `imageBloatAuditor` flags plaintext `ENV API_KEY=sk_live_...`, cross-layer `rm`, and missing multi-stage build while scoring a slim distroless multi-stage Dockerfile `>=90`.
2. **`15b` (`coolify#5655` + `dokploy#1475`):** `cronLeaseService` blocks concurrent double-execution (`ALREADY_RUNNING`), blocks repeat run of a completed `scheduleSlotIso` (`ALREADY_EXECUTED_SLOT`), and rejects stale `fencingToken`.
3. **`15c` (Post-Snaplet/Neosync PII Guard):** `piiMaskerService` deterministically masks emails, phones, cards, IBANs & API keys across JSON/SQL with 0 original PII substrings remaining and identical seed→join determinism.
4. **`15d` (Portainer/Dokploy/Coolify OOM & Crash-Loop):** `oomForensicsService` separates `137+oomKilled` (`CGROUP_OOM_KILL`) vs `137+!oomKilled` (`FORCED_SIGKILL_TIMEOUT`) vs `139` (`SEGFAULT`) and sets `ignoreForRollback: true` on `historicalOnly: true`.
5. **`15e` (`uptime-kuma#3255` + GoAlert/Keep):** `oncallEscalationService` collapses 3 duplicate alerts into 1 incident (`occurrences: 3`), suppresses flapping (`>=3` toggles), escalates unacked Tier 1 → Tier 2 after timeout, and freezes escalation on `ack`.
