# Security Policy

Security is a first-class architectural invariant of **Culkibo**, not a bolt-on feature. We take every vulnerability report seriously and appreciate responsible disclosure from the security community.

---

## Supported Versions

| Version | Supported | Notes |
| --- | :---: | --- |
| `1.1.x` | ✅ | Active security fixes and hardening |
| `1.0.x` | ⚠️ | Critical security patches only; upgrade to `1.1.x` recommended |
| `< 1.0.0` | ❌ | Unsupported pre-release builds |

---

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues, pull requests, or discussions.**

Instead, report vulnerabilities privately through **GitHub Private Vulnerability Reporting**:

1. Open a private security advisory at:
   **`https://github.com/macaqueboy/culkibo/security/advisories/new`**
2. Include as much detail as possible so we can reproduce and patch quickly:
   - Affected component (e.g., REST API, MCP server, Live Sync WebSocket, Caddy ingress, SSH fleet, Coolify migrator, Bundle archiver, Telemetry collector)
   - Culkibo version, Node.js version, OS, and deployment mode (VPS / Docker / local)
   - Minimal reproduction steps or proof-of-concept payload
   - Impact assessment (e.g., auth bypass, cross-project IDOR/BOLA, SSRF, secret disclosure, DoS)
   - Any suggested remediation (optional)

### Disclosure Timeline & SLA

- **Acknowledgement:** within **48 hours**
- **Triage & severity assessment:** within **5 business days**
- **Patch & coordinated disclosure:** targeting **7–14 days** for High/Critical issues, with credit in the release advisory unless you prefer anonymity

---

## Security-by-Construction Architecture

Culkibo is engineered to eliminate entire classes of vulnerabilities that have historically impacted self-hosted PaaS platforms:

### 1. Zero Shell Command Construction (`shell: false`)
- Every subprocess invocation (`git`, `docker`, `caddy`, `ssh`, `cron`, `exec`, `npm`) uses `spawn()` / `execFile()` with tokenized `argv` arrays validated by [`server/services/safeCommand.js`](server/services/safeCommand.js) and `shell: false`.
- Secrets are never placed in CLI arguments or `.git/config`; they are passed via ephemeral `0600` `--env-file` descriptors or `GIT_ASKPASS`.
- Enforced continuously in CI by the static AST/source scanner in [`tests/shell-safety.test.js`](tests/shell-safety.test.js).

### 2. Authentication, RBAC & Session Hardening
- **Constant-Time Master & Scoped Tokens:** 256-bit tokens verified with `crypto.timingSafeEqual`.
- **Multi-User Teams & 4-Role RBAC:** `owner`, `admin`, `developer`, and `viewer` roles with per-project ACL overrides (including explicit `none` denial and role-downgrade enforcement) and triple-layer revocation.
- **TOTP 2FA & OIDC PKCE SSO:** Built-in RFC 6238 TOTP two-factor authentication and OpenID Connect PKCE single sign-on.
- **Single-Use WebSocket Tickets:** `/api/auth/ws-ticket` issues ephemeral, IP-bound, one-time tickets so master tokens are never transmitted via WebSocket query strings or subprotocols.
- **Strict Origin & Rate Limiting:** Origin enforcement, trusted-proxy CIDR validation (blocking spoofed `X-Forwarded-For` / `Forwarded` headers), and shared LRU brute-force rate limiting ([`server/services/rateLimiter.js`](server/services/rateLimiter.js)).

### 3. Cryptography, Secrets & Tamper-Evident Auditing
- **AES-256-GCM + scrypt at Rest (`0600`):** Encrypts database credentials, environment vaults, catalog secrets, SSH fleet keys, S3/R2 credentials, and full-instance Disaster Recovery (DR) snapshots.
- **Pre-Restore Integrity Verification:** SHA-256 checksums are verified before restoring project, database, volume, or DR backups.
- **OpenBSD Bcrypt Edge Auth:** Pure-JS `$2a$`/`$2b$` hashing ([`server/services/bcryptHash.js`](server/services/bcryptHash.js)) for Caddy HTTP Basic Auth.
- **Hash-Chained Audit Log:** Append-only `data/audit.jsonl` (`0600`, auto-rotated) with cryptographic hash chaining and recursive secret redaction ([`server/services/auditLogger.js`](server/services/auditLogger.js)).
- **Pre-Deploy Secret Scanner:** Built-in detection of leaked credentials before deployments go live ([`server/services/secretScanner.js`](server/services/secretScanner.js)).

### 4. Network, SSRF & Container Isolation
- **SSRF Guard (IPv4/IPv6 + DNS Rebinding):** Blocks cloud metadata (`169.254.169.254`), RFC 1918 private ranges, IPv6-mapped hex addresses (`::ffff:`), and symlink escapes across webhooks, S3 endpoints, and importers ([`server/services/ssrfGuard.js`](server/services/ssrfGuard.js)).
- **Private Bridge Networks per Service/DB:** Managed databases and catalog services run on isolated Docker bridge networks with no ports exposed on `0.0.0.0` by default.
- **MCP Safety Boundaries:** Every MCP tool enforces RBAC policies, project scoping, secret redaction, `readOnlyHint`/`destructiveHint` annotations, and `dryRun` / HMAC-signed `confirmToken` two-phase confirmation for remediation actions.
- **Archive & Path-Traversal Defense:** Live Sync, importers, and portable stack bundles enforce strict path containment, symlink rejection, CRC32/SHA-256 checks, and decompression size bounds (zip-bomb protection).

---

## Verifying Security Controls Locally

You can audit and verify Culkibo's security test suites at any time:

```bash
node tests/shell-safety.test.js        # Static zero-shell verification across server/, bin/, scripts/, bench/
node tests/security-hardening.test.js  # SSRF, proxy spoofing, symlinks, PAT scoping, MCP redaction
node tests/rbac.test.js                # 4-role RBAC, per-project ACLs, scoped tokens, triple-layer revocation
node tests/competitor-prs.test.js      # Regression tests for real PaaS CVEs & competitor security advisories
node tests/adversarial-fuzz.test.js    # Fuzzing, malformed frames, and crash recovery
```

---

## Out of Scope

- Vulnerabilities in third-party upstream container images selected by the user outside Culkibo's official catalog templates.
- Attacks requiring physical host root access or pre-existing Docker daemon root compromise.
- Self-XSS or social engineering attacks.
- Issues against unsupported `< 1.0.0` snapshots or modified forks.
