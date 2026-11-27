---
name: Bug Report
about: Report a reproducible defect or regression in Culkibo
title: "[Bug]: "
labels: ["bug", "triage"]
assignees: ""
---

## Summary

A clear and concise description of what is broken and why it matters.

## Affected Area

- [ ] Control Plane / REST API (`server/`)
- [ ] Live Sync 2.0 (`culkibo sync` / `/ws/sync`)
- [ ] Production Deploys / Rollback / Crons / Previews
- [ ] Caddy Ingress / TLS / Wildcard DNS-01 / Cloudflare Tunnels
- [ ] Coolify v4 Migrator / Universal Importer / Portable Bundle
- [ ] Managed Databases / Backups / S3 DR
- [ ] 1-Click Service Catalog
- [ ] AI Agent Hub / MCP Server (`2026-07-28`)
- [ ] Multi-Server SSH Fleet / RBAC / 2FA / OIDC
- [ ] CLI (`culkibo`)
- [ ] Web Dashboard (`web/`)
- [ ] VPS Installer / Docker Compose

## Steps to Reproduce

1. Run `...`
2. Configure `...`
3. Observe `...`

## Expected Behavior

What you expected to happen.

## Actual Behavior

What actually happened (include exact HTTP status codes, error messages, or screenshots).

## Environment

- **Culkibo Version:** (e.g. `1.1.0` or commit SHA)
- **Node.js Version:** (output of `node -v`)
- **OS & Architecture:** (e.g. Ubuntu 24.04 x64, Debian 12 arm64, Windows 11 x64, macOS arm64)
- **Install Method:** (VPS `install.sh` / Docker Compose / Local `npm start`)
- **Docker Version:** (output of `docker --version`, or `N/A`)
- **Caddy Version:** (output of `caddy version`, or `N/A`)

## Diagnostics (`culkibo doctor` / Redacted Logs)

> **Security reminder:** Never paste real API tokens, passwords, `.env` secrets, or private keys.

```text
# Paste output of `node bin/culkibo.js doctor` or relevant redacted server/browser logs here
```

## Additional Context

Any workarounds discovered, related issues, or whether you are willing to submit a PR to fix this.
