## Summary

<!-- Briefly explain what this PR changes and why. -->

Fixes #

## Type of Change

- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding capability)
- [ ] Performance improvement (include before/after benchmark output below)
- [ ] Security hardening
- [ ] Catalog template / MCP tool / Importer addition
- [ ] Documentation / DX / Tests

## Culkibo Engineering Invariants Checklist

- [ ] **Zero shell construction:** No `exec()`, `execSync()`, `sh -c`, or `shell: true` added (`node tests/shell-safety.test.js` passes).
- [ ] **Dependency budget respected:** `ROOT_DEPS` remains `6` and `telemetry-collector` remains `0` runtime deps (or new dependency was explicitly pre-approved).
- [ ] **Security & RBAC:** New/modified mutating routes and MCP tools enforce project access/RBAC and redact secrets in responses and audit logs.
- [ ] **Isolated tests:** All new/updated tests use `os.tmpdir()` and never mutate live `data/*.json`.
- [ ] **Pinned images (if touching catalog/Docker):** Zero `:latest` tags and zero `/var/run/docker.sock` mounts in catalog templates.

## Verification Run

Paste exact results for the checks you ran:

- [ ] `node tests/shell-safety.test.js`
- [ ] `npm run typecheck`
- [ ] `npx tsc -p web/tsconfig.app.json --noEmit`
- [ ] `npm --prefix web run lint`
- [ ] `npm run web:build`
- [ ] `npm test`
- [ ] `node --test telemetry-collector/test/collector.test.js`
- [ ] `node bench/run-all.bench.js` *(required for performance or startup/RAM changes)*

```text
# Paste concise verification output here
```

## Screenshots / Benchmarks (If Applicable)

<!-- For UI changes, attach desktop (1440px) and mobile (390px) screenshots. For perf changes, include before/after metrics. -->
