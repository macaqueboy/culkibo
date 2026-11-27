# Contributing to Culkibo

Thank you for your interest in contributing to **Culkibo** — the `<60 MB`, zero-shell, AI-native self-hosted PaaS. Whether you are fixing a bug, adding a 1-click catalog app, expanding MCP tooling, or improving documentation, this guide helps you ship clean, verifiable changes.

---

## Core Engineering Invariants

Every pull request **must** preserve Culkibo's architectural guarantees. These are not guidelines — they are CI-enforced invariants:

1. **Zero Shell Construction (`shell: false`)**
   - Never construct shell strings or invoke `exec()`, `execSync()`, `sh -c`, or `spawn(..., { shell: true })`.
   - Always invoke subprocesses via `spawn()` / `execFile()` with validated `argv` arrays (see [`server/services/safeCommand.js`](server/services/safeCommand.js)).
   - Never pass secrets in process `argv` or `.git/config`; use ephemeral `0600` `--env-file` files or `GIT_ASKPASS`.
   - Verified statically by `node tests/shell-safety.test.js`.
2. **Minimal Runtime Dependency Budget (`ROOT_DEPS = 6`)**
   - Root runtime dependencies in [`package.json`](package.json) are capped at **6** (`express`, `ws`, `chokidar`, `commander`, `cors`, `dotenv`).
   - [`telemetry-collector/package.json`](telemetry-collector/package.json) maintains **0** external runtime dependencies.
   - Prefer Node.js built-ins (`node:crypto`, `node:zlib`, `node:http`, `node:fs`, `node:net`, `node:sqlite`) over third-party packages. Any new dependency requires maintainer discussion in an issue first.
3. **Sub-60 MB Idle RAM Footprint**
   - Keep heavy or optional subsystems lazy-loaded (`lazySvc`) so idle memory stays lean enough to run on a 512 MB VPS.
4. **Isolated, Non-Destructive Tests**
   - Never read or mutate live `data/*.json` files in tests. Always isolate test state inside `os.tmpdir()` and clean up handles, timers, and child processes on exit.
5. **Security & Redaction by Default**
   - Enforce RBAC/project-access checks on every mutating route and MCP tool.
   - Redact secrets in API responses, audit logs, error outputs, and MCP results.
   - Use pinned image tags (no `:latest`) and read-only mounts wherever possible in catalog templates.

---

## Local Development Setup

### Prerequisites

- **Node.js 20+** (Node 22 or 24 LTS recommended)
- **Git**
- **Docker** and **Caddy v2.11+** *(optional for local development — Culkibo degrades gracefully when Docker or Caddy are absent)*

### 1. Clone and Install

```bash
git clone https://github.com/macaqueboy/culkibo.git
cd culkibo
npm install
npm --prefix web install
```

### 2. Build and Run

```bash
# Build the React 19 + Vite dashboard (with precompressed .br / .gz assets)
npm run web:build

# Start the Culkibo daemon on http://localhost:3030
npm start
```

For hot-reloading UI development, run the daemon in one terminal (`npm start`) and the Vite dev server in another (`npm run web:dev`).

On Windows PowerShell, you can also start the stack with `./start.ps1`.

---

## Verification Checklist (Run Before Every PR)

Run the full verification suite locally before opening a pull request:

```bash
# 1. Static zero-shell invariant check
node tests/shell-safety.test.js

# 2. Server TypeScript (checkJs) verification — must report 0 errors
npm run typecheck

# 3. Frontend TypeScript & oxlint (React 19 + Compiler rules) — must report 0 errors/warnings
npx tsc -p web/tsconfig.app.json --noEmit
npm --prefix web run lint
npm run web:build

# 4. Full test suite (unit, security, live-server, WebSocket stress, mixed HTTP stress)
npm test

# 5. Telemetry collector tests (0-dep runner)
node --test telemetry-collector/test/collector.test.js

# 6. Optional: reproducible performance & idle-RAM benchmark suite
node bench/run-all.bench.js
```

> **Windows PowerShell tip:** chain commands with `;` (or check `$LASTEXITCODE`) instead of `&&` on older PowerShell versions.

---

## Common Contribution Paths

### Adding a 1-Click App to the Service Catalog

Catalog definitions live in [`server/services/catalog/templates.js`](server/services/catalog/templates.js):

1. Pin every container image to an explicit version tag (e.g., `postgres:17.2-alpine`, never `:latest`).
2. Never mount `/var/run/docker.sock`.
3. Use Culkibo template placeholders (`{{host}}`, `{{wsProtocol}}`, `{{tz}}`, generated secrets) instead of hardcoded hostnames or timezones.
4. Declare sidecar startup order (`dependsOn`, `startAfterApp`, `coupledWithApp`) and readiness probes (`tcp` / `http`) where applicable.
5. Verify with `node tests/catalog.test.js` and `node tests/shell-safety.test.js`.

### Adding or Updating an MCP Tool, Resource, or Prompt

MCP capabilities live in [`server/services/mcpServer.js`](server/services/mcpServer.js) and [`server/services/mcpStreamableHttp.js`](server/services/mcpStreamableHttp.js):

1. Annotate every tool accurately (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`).
2. Register RBAC permissions in `TOOL_POLICIES` and assign the tool to the appropriate profile(s) in `TOOL_PROFILES` (`core`, `deploy`, `ops`, `security`, `all`).
3. For destructive or production-mutating operations, support `dryRun` or two-phase `confirmToken` safety.
4. Redact secrets in tool outputs and audit records.
5. Add regression coverage in [`tests/mcp.test.js`](tests/mcp.test.js).

### Improving Coolify / Platform Importers

Importers live in [`server/services/coolifyMigrator.js`](server/services/coolifyMigrator.js), [`server/services/universalImporter.js`](server/services/universalImporter.js), and [`server/services/wordpressMigrator.js`](server/services/wordpressMigrator.js):

- Always include fixture-based tests covering adversarial edge cases (magic variables, Traefik labels, malformed inputs, path traversal, zip bombs).
- Verify with `node tests/coolifyMigrator.test.js` and `node tests/importers.test.js`.

---

## Commit & Pull Request Guidelines

- **Branch naming:** `feat/<short-topic>`, `fix/<short-topic>`, `perf/<short-topic>`, or `docs/<short-topic>`.
- **Commit messages:** Follow [Conventional Commits](https://www.conventionalcommits.org/):
  - `feat(mcp): add playbook prompt for DR restore drill`
  - `fix(ingress): reject malformed wildcard host labels`
  - `perf(sync): reduce buffer allocation in Merkle delta frames`
  - `docs(readme): update reproducible benchmark metrics`
- **Pull requests:**
  - Keep PRs focused on a single concern.
  - Complete the checklist in [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md).
  - Include exact test output and, for performance changes, before/after output from `node bench/run-all.bench.js`.
  - For UI changes, attach desktop and mobile screenshots.

---

## Reporting Bugs & Security Issues

- **Bugs & feature requests:** Use the [GitHub Issue Templates](.github/ISSUE_TEMPLATE/).
- **Security vulnerabilities:** **Do not** open a public GitHub issue. Follow the private disclosure process in [SECURITY.md](SECURITY.md).

---

## Community Conduct & Licensing

- Be constructive, direct, and respectful in issues, reviews, and discussions. Focus critique on code, architecture, and measurable evidence.
- All contributions to Culkibo are licensed under the [Apache License 2.0](LICENSE).
