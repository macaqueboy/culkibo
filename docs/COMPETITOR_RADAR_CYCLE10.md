# Culkibo Cycle-10 Competitor Forensics & Cycle-11 Pioneer Blueprint

> **Date:** 2026-11-27 · **Baseline:** Cycle #9 (`99.55%` Launch Readiness, `ROOT_DEPS=6`, `54 MB` RSS, `50→53` suites, `130→135` MCP tools, `89 µs` Micro-Wasm) · **Scope:** Fresh 2025–2026 CVEs, PRs & issues (zero overlap with Cycles #1, #3, #6, #7, #8, #9) + 5 zero-dep Cycle-11 breakthroughs.

---

## 1. Fresh 2025–2026 Competitor Forensics (Admission, Compliance, Volumes & Edge A/B)

| Domain | Real 2025–2026 Citations | Root Cause & Production Blast Radius | Culkibo Guardrail & Win |
|---|---|---|---|
| **Compose Root Mounts, `docker.sock` & Storage RCE** | **Coolify `CVE-2025-66213`** (CVSS 10.0, `<beta.451`), `<=beta.420.6` Compose `- /:/host:rw`, [`coolify#8847`](https://github.com/coollabsio/coolify/issues/8847); [`dokploy#2661`](https://github.com/Dokploy/dokploy/issues/2661) (`0.0.0.0:3000`) | Low-priv members injected `- /:/host:rw` mounts or shell metacharacters in `LocalPersistentVolume.name` (`CVE-2025-66213`) for root host escape; `coolify-sentinel` mounted RW `docker.sock` as root (`#8847`); Dokploy bound `:3000` to `0.0.0.0` (`#2661`). | Zero-dep **Policy-as-Code Admission Gate** (Kyverno/OPA-lite) blocking `privileged:true`, `docker.sock`, host-root mounts, `SYS_ADMIN`, `:latest`, `UID 0`, and `0.0.0.0` panel/DB binds before `docker run`. |
| **Enterprise SOC 2 / ISO 27001 / GDPR & Plaintext DBs** | [`dokploy#2642`](https://github.com/Dokploy/dokploy/issues/2642) (HIPAA/SOC 2), [`#4360`](https://github.com/Dokploy/dokploy/issues/4360) (plaintext Postgres secrets); [`coolify#3138`](https://github.com/coollabsio/coolify/issues/3138); Portainer BE-only Activity Log | Dokploy stores env vars & DB credentials in plaintext inside Postgres (`#4360`) and lacks automated SOC 2/ISO 27001 evidence packs (`#2642`); agencies waste days manually stitching screenshots for auditors. | 1-click Ed25519-signed **Compliance Evidence Bundle** aggregating Culkibo's existing AES-256-GCM vault, RBAC, 2FA/Passkeys, hash-chained audit logs, SLSA v1.1, OSV CVE scans & DR Fire-Drill scorecards. |
| **Stateful Volume Migrations & UID Permission Lockouts** | Coolify non-root SSH recursive `chown` mount breaks; Dokploy Postgres `999:999` UID errors; Kamal `Errno::EACCES` (`root:root` vs `1000:1000`); Portainer NFS `portainer.db.bak` permission failure | Moving persistent Docker volumes across VPSes breaks apps via numeric UID:GID shifts (`999:999` Postgres, `1000:1000` Rails), torn writes on unpaused DB volumes, or `CVE-2025-66213` unsanitized volume names. | Coordinated 4-phase **Stateful Volume Migration Planner**: validates names strictly, captures `UID:GID`, runs live pre-sync + brief-pause `tar --numeric-owner` SHA-256 delta over SSH ControlMaster. |
| **Edge Geo-Routing & Sticky A/B Splits** | [Caddy `lb_policy`](https://caddyserver.com/docs/json/apps/http/servers/routes/handle/reverse_proxy/selection_policies/) (`cookie`, `header` + `fallback`); `CF-IPCountry` multi-region edge demand | Coolify/Dokploy expose flat single-upstream routes — zero native Geo-IP country routing (`EU`/`US` regional VPSes) or sticky cookie/header A/B experiments without external CDNs or custom Traefik plugins. | Native **Caddy v2.11 Geo-Routing & Sticky A/B Compiler** (0 plugins): ISO country header matchers + `lb_policy: cookie` / `header` with weighted fallback and 1-click experiment kill-switch. |

---

## 2. Top 5 Zero-Dep (`ROOT_DEPS=6`) Cycle-11 Pioneering Breakthroughs

All 5 preserve **`ROOT_DEPS=6` (0 new runtime npm deps)**, `shell: false`, and `<= 60 MB` idle RSS:

### 1. Declarative Policy-as-Code Deployment Admission Engine (`server/services/admissionPolicyService.js`)
- **Kyverno / OPA-Lite In-Process Guardrails:** Evaluates 10 deterministic CIS / Pod Security Standards rules on every deploy/compose spec before container creation: `no_privileged`, `no_docker_sock_mount`, `no_host_root_mount` (blocks `/`, `/etc`, `/proc`, `/sys`, `/var/run/docker.sock` — curing Coolify `<=beta.420.6`), `no_dangerous_caps` (`SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN`), `no_latest_tag`, `require_non_root_uid`, `require_resource_limits`, `require_healthcheck`, `require_signed_attestation`, and `no_public_db_or_panel_bind` (`dokploy#2661`).
- **Modes & Persistence:** Supports per-rule `enforce` (blocks deploy with HTTP `422 ADMISSION_DENIED`) vs `audit` (warns + audit-logs), persisted atomically (`0o600`) in `CULKIBO_DATA_DIR/data/admission-policies.json`, plus built-in presets (`baseline`, `restricted`, `soc2-strict`) and MCP tool `culkibo_admission_check`.

### 2. Signed SOC 2 / ISO 27001 / GDPR Compliance Evidence Bundle (`server/services/complianceBundleService.js`)
- **Answers `dokploy#2642` & `#4360`:** Aggregates live control checks across Culkibo's existing services into a single auditor-ready **JSON + Markdown Evidence Dossier** mapped to **SOC 2 CC6/CC7/CC8/A1**, **ISO 27001 A.5/A.8**, and **GDPR Art. 25/32**:
  - RBAC role distribution & MFA/Passkey adoption % (`teamManager` + `passkeyService`),
  - Append-only hash-chain audit integrity check (`auditLogger`),
  - At-rest AES-256-GCM encryption & `0600` file-mode posture (explicit contrast vs Dokploy `#4360` plaintext Postgres!),
  - Latest SLSA v1.1 attestations, OSV CVE drift summary, secret rotation-age audit (`>90d`), DR Fire-Drill pass rate, and Admission Policy posture.
- **Cryptographic Non-Repudiation:** Signs the canonical JSON payload with Node's native `crypto` **Ed25519** key (same zero-dep DSSE/signature pattern as `supplyChainAttestor.js`) with `verifyComplianceBundle(bundle)` tamper check and strict 0-plaintext-secret guarantee.

### 3. Stateful Volume Snapshot Cloner & Cross-VPS Migration Planner (`server/services/volumeMigrationService.js`)
- **Zero-Shell 4-Phase Volume Transfer:** Cures Coolify `CVE-2025-66213`, recursive `chown` breaks, Dokploy `999:999` UID errors, and Kamal `root:root` `Errno::EACCES`:
  1. Validates volume names (`/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/`) and rejects `..`/host-root mount paths.
  2. Records container runtime `uid:gid` (e.g. `999:999` Postgres, `1000:1000` app) & estimated size.
  3. Emits deterministic 4-phase argv plan (zero shell interpolation!): **Pre-Sync** → **Quiesce/Pause + `tar --numeric-owner -cf` + SHA-256 manifest** → **SSH ControlMaster stream to target fleet node** → **Target SHA-256 verify + numeric UID verification + rollback retain**. Persists migration plans/receipts in `CULKIBO_DATA_DIR/data/volume-migrations.json`.

### 4. Multi-Region Edge Geo-Routing & A/B Experiment Compiler (`server/services/edgeExperimentService.js` + `caddyManager.js`)
- **Native Caddy v2.11 JSON (0 Extra Plugins):**
  - **Geo-IP Country Routing:** Validates ISO-3166-1 alpha-2 country codes (`DE`, `FR`, `US`, `ES`, …) and compiles Caddy `match: [{ header: { "CF-IPCountry": [...] } }]` (configurable header `CF-IPCountry`/`X-Country`) routing traffic to nearest fleet region upstream with deterministic default fallback.
  - **Sticky A/B Experiment Splits:** Compiles Caddy `reverse_proxy` `load_balancing.selection_policy` using `policy: "cookie"` (`name: "ckb_ab_<id>"`) or `policy: "header"` (`field: "X-AB-Group"`, `fallback: { policy: "weighted_round_robin", weights }`), validates integer weights sum to `100`, persists experiments in `CULKIBO_DATA_DIR/data/edge-experiments.json`, and provides 1-click **Kill-Switch** reverting 100% to control variant!

### 5. Exact Cycle-11 Regression Tests (`tests/competitor-prs.test.js`)
1. **Coolify `CVE-2025-66213` & `<=beta.420.6` Host-Root Escape:** Assert `admissionPolicyService` blocks `- /:/host:rw`, `/var/run/docker.sock`, `privileged: true`, and `cap_add: ['SYS_ADMIN']`; assert `volumeMigrationService` rejects shell metacharacters (`;`, `$()`, `` ` ``) in volume names.
2. **Dokploy `#2661` Public Bind & `:latest` / Root UID Admission:** Assert `restricted` / `soc2-strict` policy blocks `0.0.0.0:3000` or `0.0.0.0:5432`, `:latest` image tags, `UID 0`, and missing memory caps while passing hardened specs.
3. **Dokploy `#2642` / `#4360` Signed Compliance Bundle:** Assert `complianceBundleService` produces valid Ed25519-signed SOC 2 / ISO 27001 / GDPR JSON + Markdown dossier, detects 1-byte tampering on verify, and leaks 0 canary secrets.
4. **Kamal / Dokploy UID-Preserving Volume Migration Plan:** Assert `volumeMigrationService` preserves `--numeric-owner` (`999:999` / `1000:1000`), rejects `../` traversal paths, enforces SHA-256 verification phase, and blocks cross-tenant transfers (`403`).
5. **Caddy v2.11 Geo-Routing & Sticky A/B Compilation:** Assert `edgeExperimentService` rejects invalid country codes and weight sums `!= 100`, compiles valid Caddy `lb_policy: cookie` / `header` + `fallback` JSON, and reverts cleanly on kill-switch.
