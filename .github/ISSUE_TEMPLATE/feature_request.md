---
name: Feature Request
about: Propose a new capability, integration, catalog app, or UX improvement
title: "[Feature]: "
labels: ["enhancement"]
assignees: ""
---

## Problem Statement

What workflow is slow, painful, or impossible today? Who is affected?

## Proposed Solution

Describe the ideal UX, CLI command, API endpoint, MCP tool, or catalog template you envision.

## Category

- [ ] Live Sync 2.0 / Developer Experience
- [ ] Production Deploys / Caddy Edge / TLS / Tunnels
- [ ] Coolify / Dokploy / Platform Migration
- [ ] AI Agents & MCP (`tools` / `prompts` / `resources`)
- [ ] 1-Click Service Catalog App Request
- [ ] Managed Databases / Backups / DR
- [ ] Multi-Server Fleet / Teams / RBAC / Security
- [ ] Web Dashboard UX / CLI
- [ ] Benchmarks / Observability / Docs

## Architectural Fit

Culkibo prioritizes **zero shell construction (`shell: false`)**, **<= 6 root runtime npm dependencies**, and **< 60 MB idle RAM**. If your idea has trade-offs with those invariants (or can be solved cleanly using Node.js built-ins), note them here:

-

## Alternatives Considered

Other approaches or tools you considered (e.g., Coolify, Dokploy, Kamal, CapRover, Railpack) and why this native solution is better.

## Contribution Interest

- [ ] I would like to implement this feature in a PR
- [ ] I can help test and validate this feature once built
- [ ] Suggestion only
