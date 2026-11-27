/**
 * Culkibo Zero-Install Interactive Browser Sandbox (`?demo=1` or `VITE_DEMO_MODE=true`).
 *
 * Intercepts `/api/*` requests inside `apiFetch()` in-memory so visitors on
 * GitHub Pages or `culkibo demo` can explore SmartPack, Spatial Topology,
 * Click-to-Link DB Injection, DirectPush SSH, Sovereign EdgeTunnel, OTLP Export,
 * Coolify v4 100%-Parity Migration, and 3 Sandboxed MCP Apps in 10 seconds with
 * zero backend, zero auth prompts, and zero network errors.
 */

const DEMO_STORAGE_KEY = 'culkibo_demo_mode';

let _cachedDemo: boolean | null = null;

export function isDemoMode(): boolean {
  if (_cachedDemo !== null) return _cachedDemo;
  if (import.meta.env.VITE_DEMO_MODE === 'true') {
    _cachedDemo = true;
    return true;
  }
  if (typeof window === 'undefined') return false;
  try {
    const params = new URLSearchParams(window.location.search);
    const q = params.get('demo')?.toLowerCase();
    if (q === '0' || q === 'false') {
      window.sessionStorage.removeItem(DEMO_STORAGE_KEY);
      _cachedDemo = false;
      return false;
    }
    if (q === '1' || q === 'true') {
      window.sessionStorage.setItem(DEMO_STORAGE_KEY, '1');
      _cachedDemo = true;
      return true;
    }
    if (window.sessionStorage.getItem(DEMO_STORAGE_KEY) === '1') {
      _cachedDemo = true;
      return true;
    }
  } catch {
    // ignore storage/URL restrictions
  }
  _cachedDemo = false;
  return false;
}

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

function nowIso(offsetMs = 0): string {
  return new Date(Date.now() + offsetMs).toISOString();
}

// ============================================================================
// Curated In-Memory Sandbox State (interactive across navigations!)
// ============================================================================

interface DemoState {
  projects: any[];
  databases: any[];
  domains: any[];
  tunnels: any[];
  otlp: {
    enabled: boolean;
    endpoint: string;
    serviceName: string;
    protocol: string;
    bufferedSpans: number;
    maxBufferSize: number;
    totalExported: number;
    totalFailed: number;
    circuitOpen: boolean;
    circuitState: string;
    lastFlushAt: string | null;
    lastError: string | null;
    hasAuthHeader: boolean;
  };
  alertRules: any[];
  monitors: any[];
  statusPages: any[];
  servers: any[];
  sshKeys: any[];
  installations: any[];
  checkpoints: Record<string, any[]>;
  heartbeats: any[];
  meshPeers: any[];
  passkeys: any[];
  secretLeases: any[];
  maintenanceWindows: any[];
  incidents: any[];
}

function createInitialDemoState(): DemoState {
  const t1 = nowIso(-1000 * 60 * 14);
  const t2 = nowIso(-1000 * 60 * 48);
  const t3 = nowIso(-1000 * 60 * 190);
  const exp84 = nowIso(1000 * 60 * 60 * 24 * 84);

  return {
    projects: [
      {
        id: 'proj_acme_web',
        name: 'acme-saas-web',
        description: 'Next.js 15 storefront + dashboard with <10ms Live Sync and automatic HTTP/3.',
        status: 'active',
        runtime: 'nextjs',
        localPath: '/srv/apps/acme-saas-web',
        gitRepo: 'https://github.com/acme-labs/acme-saas-web',
        gitBranch: 'main',
        containerPort: 3000,
        localPort: 3000,
        localRunning: false,
        maintenanceMode: false,
        domains: ['app.acme-demo.dev', 'acme-demo.dev'],
        linkedDatabaseIds: ['db_pg_main', 'db_valkey_cache'],
        envVars: {
          NODE_ENV: 'production',
          PORT: '3000',
          NEXT_PUBLIC_API_URL: 'https://api.acme-demo.dev',
          DATABASE_URL: 'postgresql://acme:••••••••@db-pg-main:5432/acme_prod',
          REDIS_URL: 'redis://:••••••••@db-valkey-cache:6379',
        },
        lastDeployedAt: t1,
        createdAt: t3,
        updatedAt: t1,
        resources: [
          { id: 'res_web_1', name: 'acme-saas-web', type: 'app', image: 'culkibo/acme-saas-web:sha-8c4f1a', status: 'running', port: 3000, ports: ['3000'] },
        ],
      },
      {
        id: 'proj_edge_rust',
        name: 'edge-api-rust',
        description: 'Zero-allocation Rust Axum HTTP/3 API serving tenant billing & webhooks.',
        status: 'active',
        runtime: 'rust',
        localPath: '/srv/apps/edge-api-rust',
        gitRepo: 'https://github.com/acme-labs/edge-api-rust',
        gitBranch: 'main',
        containerPort: 8080,
        localPort: 8080,
        localRunning: false,
        maintenanceMode: false,
        domains: ['api.acme-demo.dev'],
        linkedDatabaseIds: ['db_pg_main'],
        envVars: {
          RUST_LOG: 'info',
          PORT: '8080',
          DATABASE_URL: 'postgresql://acme:••••••••@db-pg-main:5432/acme_prod',
        },
        lastDeployedAt: t2,
        createdAt: t3,
        updatedAt: t2,
        resources: [
          { id: 'res_rust_1', name: 'edge-api-rust', type: 'app', image: 'culkibo/edge-api-rust:sha-3e91b2', status: 'running', port: 8080, ports: ['8080'] },
        ],
      },
      {
        id: 'proj_ai_worker',
        name: 'ai-worker-py',
        description: 'Python uv FastAPI background worker & embedding pipeline (Scale-to-Zero ready).',
        status: 'active',
        runtime: 'python-uv',
        localPath: '/srv/apps/ai-worker-py',
        gitRepo: 'https://github.com/acme-labs/ai-worker-py',
        gitBranch: 'main',
        containerPort: 8000,
        localPort: 8000,
        localRunning: false,
        maintenanceMode: false,
        domains: ['ai.acme-demo.dev'],
        linkedDatabaseIds: ['db_valkey_cache'],
        envVars: {
          PYTHONUNBUFFERED: '1',
          PORT: '8000',
          REDIS_URL: 'redis://:••••••••@db-valkey-cache:6379',
        },
        lastDeployedAt: t3,
        createdAt: t3,
        updatedAt: t3,
        resources: [
          { id: 'res_py_1', name: 'ai-worker-py', type: 'app', image: 'culkibo/ai-worker-py:sha-71d2c0', status: 'running', port: 8000, ports: ['8000'] },
        ],
      },
    ],
    databases: [
      {
        id: 'db_pg_main',
        name: 'acme-postgres-16',
        engine: 'postgresql',
        version: '16-alpine',
        image: 'postgres:16-alpine',
        status: 'running',
        host: '127.0.0.1',
        port: 5432,
        internalHost: 'culkibo-db-pg-main',
        internalPort: 5432,
        databaseName: 'acme_prod',
        username: 'acme',
        memoryLimitMb: 512,
        cpuLimit: 1,
        publicExposure: false,
        createdAt: t3,
      },
      {
        id: 'db_valkey_cache',
        name: 'acme-valkey-8',
        engine: 'valkey',
        version: '8-alpine',
        image: 'valkey/valkey:8-alpine',
        status: 'running',
        host: '127.0.0.1',
        port: 6379,
        internalHost: 'culkibo-db-valkey',
        internalPort: 6379,
        databaseName: '0',
        username: 'default',
        memoryLimitMb: 256,
        cpuLimit: 0.5,
        publicExposure: false,
        createdAt: t3,
      },
    ],
    domains: [
      {
        id: 'dom_app',
        hostname: 'app.acme-demo.dev',
        projectId: 'proj_acme_web',
        targetPod: 'citadel',
        targetPort: 3000,
        isWildcard: false,
        cloudflareProxied: false,
        canonicalRedirect: 'none',
        sslStatus: 'active',
        createdAt: t3,
        tls: { reachable: true, trusted: true, expired: false, issuer: "Let's Encrypt E6", notAfter: exp84, daysRemaining: 84 },
      },
      {
        id: 'dom_apex',
        hostname: 'acme-demo.dev',
        projectId: 'proj_acme_web',
        targetPod: 'citadel',
        targetPort: 3000,
        isWildcard: false,
        cloudflareProxied: true,
        canonicalRedirect: 'www_to_apex',
        sslStatus: 'active',
        createdAt: t3,
        tls: { reachable: true, trusted: true, expired: false, issuer: "Let's Encrypt E6", notAfter: exp84, daysRemaining: 84 },
      },
      {
        id: 'dom_api',
        hostname: 'api.acme-demo.dev',
        projectId: 'proj_edge_rust',
        targetPod: 'citadel',
        targetPort: 8080,
        isWildcard: false,
        cloudflareProxied: false,
        canonicalRedirect: 'none',
        sslStatus: 'active',
        createdAt: t3,
        tls: { reachable: true, trusted: true, expired: false, issuer: "Let's Encrypt E6", notAfter: exp84, daysRemaining: 84 },
      },
      {
        id: 'dom_ai',
        hostname: 'ai.acme-demo.dev',
        projectId: 'proj_ai_worker',
        targetPod: 'citadel',
        targetPort: 8000,
        isWildcard: false,
        cloudflareProxied: false,
        canonicalRedirect: 'none',
        sslStatus: 'active',
        createdAt: t3,
        tls: { reachable: true, trusted: true, expired: false, issuer: "Let's Encrypt E6", notAfter: exp84, daysRemaining: 84 },
      },
    ],
    tunnels: [
      {
        id: 'tun_demo_homelab',
        name: 'homelab-cgnat-edge',
        hostname: 'edge.acme-demo.dev',
        targetHost: '127.0.0.1',
        targetPort: 4000,
        tokenPreview: 'cket_9xQ2…m7Pa',
        revoked: false,
        status: 'connected',
        connected: true,
        activeStreams: 3,
        connectedAt: t2,
        lastHeartbeatAt: nowIso(-8000),
        createdAt: t3,
        updatedAt: t2,
      },
    ],
    otlp: {
      enabled: true,
      endpoint: 'https://tempo.acme-demo.dev:4318',
      serviceName: 'culkibo-control-plane',
      protocol: 'otlp/http-json',
      bufferedSpans: 12,
      maxBufferSize: 256,
      totalExported: 482,
      totalFailed: 0,
      circuitOpen: false,
      circuitState: 'closed',
      lastFlushAt: nowIso(-15000),
      lastError: null,
      hasAuthHeader: true,
    },
    alertRules: [
      {
        id: 'rule_host_ram',
        name: 'High Host RAM > 88%',
        metric: 'host_ram_pct',
        operator: '>',
        threshold: 88,
        severity: 'warning',
        consecutiveRequired: 2,
        cooldownMs: 1800000,
        enabled: true,
        builtin: true,
        description: 'Triggers when Linux MemAvailable drops below 12%',
      },
      {
        id: 'rule_5xx',
        name: 'HTTP 5xx Surge > 2%',
        metric: 'http_5xx_pct',
        operator: '>',
        threshold: 2,
        severity: 'critical',
        consecutiveRequired: 2,
        cooldownMs: 900000,
        enabled: true,
        builtin: true,
        description: 'Detects upstream failures across published Caddy routes',
      },
      {
        id: 'rule_disk',
        name: 'Server Disk > 85%',
        metric: 'disk_used_pct',
        operator: '>',
        threshold: 85,
        severity: 'warning',
        consecutiveRequired: 1,
        cooldownMs: 3600000,
        enabled: true,
        builtin: true,
        description: 'Suggests automated BuildKit cache prune before disk fills',
      },
    ],
    monitors: [
      {
        id: 'mon_app',
        name: 'acme-saas-web HTTPS',
        type: 'http',
        url: 'https://app.acme-demo.dev/health',
        status: 'up',
        intervalSec: 60,
        uptime24h: 100,
        uptime7d: 99.98,
        uptime30d: 99.97,
        p50LatencyMs: 18,
        p95LatencyMs: 31,
        history30: Array.from({ length: 30 }, () => ({ status: 'up', uptimePct: 100 })),
      },
      {
        id: 'mon_api',
        name: 'edge-api-rust HTTP/3',
        type: 'http',
        url: 'https://api.acme-demo.dev/v1/health',
        status: 'up',
        intervalSec: 30,
        uptime24h: 100,
        uptime7d: 100,
        uptime30d: 99.99,
        p50LatencyMs: 6,
        p95LatencyMs: 12,
        history30: Array.from({ length: 30 }, () => ({ status: 'up', uptimePct: 100 })),
      },
      {
        id: 'mon_pg',
        name: 'acme-postgres-16 TCP',
        type: 'tcp',
        host: '127.0.0.1',
        port: 5432,
        status: 'up',
        intervalSec: 60,
        uptime24h: 100,
        uptime7d: 100,
        uptime30d: 100,
        p50LatencyMs: 2,
        p95LatencyMs: 4,
        history30: Array.from({ length: 30 }, () => ({ status: 'up', uptimePct: 100 })),
      },
    ],
    statusPages: [
      {
        slug: 'acme',
        title: 'Acme Platform Status',
        description: 'Live availability across storefront, Rust edge API, and managed PostgreSQL.',
        accentColor: '#10b981',
        monitorIds: ['mon_app', 'mon_api', 'mon_pg'],
        incidents: [],
      },
    ],
    servers: [
      {
        id: 'local',
        name: 'Local Server (Primary)',
        host: '127.0.0.1',
        port: 22,
        user: 'culkibo',
        isLocal: true,
        region: 'eu-central-1',
        status: 'online',
        tags: ['control-plane', 'caddy-h3'],
        projectsCount: 3,
        probe: {
          cpus: 4,
          load1m: 0.42,
          memoryTotalMb: 8192,
          memoryAvailableMb: 5340,
          diskTotalGb: 160,
          diskAvailableGb: 121.6,
          dockerReady: true,
          dockerVersion: '27.5.1',
          caddyAvailable: true,
          latencyMs: 1,
          os: 'Ubuntu 24.04 LTS',
        },
      },
      {
        id: 'srv_eu_edge_01',
        name: 'eu-central-hetzner-01',
        host: '198.51.100.42',
        port: 22,
        user: 'deploy',
        isLocal: false,
        region: 'fsn1',
        status: 'online',
        hostKeyPolicy: 'tofu',
        hostKeyFingerprint: 'SHA256:k8vQ2pL9xN4mR7tY1wZ3bC5dF6gH8jK0aS2uE4iO6pQ',
        tags: ['edge', 'directpush'],
        projectsCount: 1,
        probe: {
          cpus: 8,
          load1m: 0.68,
          memoryTotalMb: 16384,
          memoryAvailableMb: 11820,
          diskTotalGb: 240,
          diskAvailableGb: 194.2,
          dockerReady: true,
          dockerVersion: '27.5.1',
          caddyAvailable: true,
          latencyMs: 14,
          os: 'Debian 12',
        },
      },
    ],
    sshKeys: [
      {
        id: 'key_ed25519_fleet',
        name: 'fleet-ed25519-prod',
        algorithm: 'ed25519',
        fingerprint: 'SHA256:9fA4cB2dE8gH1jK5mN7pQ3rS6tU0vW2xY4zA8bC1dE3',
        publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockDemoSandboxKeyOnlyForPreviewCulkibo culkibo-fleet',
        createdAt: t3,
      },
    ],
    installations: [
      {
        id: 'inst_n8n_demo',
        templateId: 'n8n',
        name: 'n8n-workflows',
        status: 'running',
        image: 'n8nio/n8n:1.88.0',
        hostPort: 5678,
        domain: 'flows.acme-demo.dev',
        createdAt: t3,
      },
    ],
    checkpoints: {
      proj_acme_web: [
        {
          id: 'cp_demo_8c4f1a',
          projectId: 'proj_acme_web',
          label: 'Pre-v1.2.0 SmartPack cutover',
          actor: 'claude-code',
          sha256: '8c4f1a9e2b7d03f561a4c9e8d20f7b1a5c3e9d01f2a4b6c8d0e1f2a3b4c5d6e7',
          imageTag: 'culkibo/acme-saas-web:sha-8c4f1a',
          envCount: 5,
          domainsCount: 2,
          cronsCount: 1,
          dbLinksCount: 2,
          createdAt: t1,
        },
        {
          id: 'cp_demo_5b12d0',
          projectId: 'proj_acme_web',
          label: 'Initial production release',
          actor: 'pablo',
          sha256: '5b12d04a7e9f12c384b6d0e1f3a5c7e90123456789abcdef0123456789abcdef',
          imageTag: 'culkibo/acme-saas-web:sha-5b12d0',
          envCount: 4,
          domainsCount: 1,
          cronsCount: 1,
          dbLinksCount: 1,
          createdAt: t3,
        },
      ],
    },
    heartbeats: [
      {
        id: 'hb_pg_nightly',
        name: 'Nightly Postgres WAL Backup',
        projectId: 'proj_acme_web',
        token: 'ckb_hb_9e4f1a2b8c3d7e6f0a1b2c3d',
        pingUrl: '/api/heartbeat/ckb_hb_9e4f1a2b8c3d7e6f0a1b2c3d',
        periodSec: 86400,
        graceSec: 600,
        status: 'up',
        lastPingAt: t2,
        lastDurationMs: 4210,
      },
      {
        id: 'hb_billing_sync',
        name: 'Stripe Invoice Rollup Cron',
        projectId: 'proj_edge_rust',
        token: 'ckb_hb_4d8a7c1e9f0b2a5c6e7d8f9a',
        pingUrl: '/api/heartbeat/ckb_hb_4d8a7c1e9f0b2a5c6e7d8f9a',
        periodSec: 3600,
        graceSec: 300,
        status: 'up',
        lastPingAt: t1,
        lastDurationMs: 840,
      },
    ],
    meshPeers: [
      {
        nodeId: 'local',
        name: 'eu-central-control (Local)',
        meshIp: '10.88.0.1',
        publicKey: 'K7x9mQ2vR4pL8nW1cF6tY0bH3jD5zA8eN2sU4wP9qVk=',
        endpoint: '127.0.0.1:51820',
        listenPort: 51820,
        role: 'control-plane',
        keyVersion: 1,
        keyRotatedAt: t3,
        privateKeyEncrypted: true,
        status: 'connected',
      },
      {
        nodeId: 'srv_hetzner_eu',
        name: 'hetzner-cpx31-fsn1',
        meshIp: '10.88.0.2',
        publicKey: 'M3vP8rT1xN6kJ2wB9hQ4zL7cD0fG5yA1eS8uV2nK4Xo=',
        endpoint: '91.107.194.22:51820',
        listenPort: 51820,
        role: 'worker',
        keyVersion: 1,
        keyRotatedAt: t3,
        privateKeyEncrypted: true,
        status: 'connected',
      },
    ],
    passkeys: [
      {
        id: 'pk_demo_macbook_es256',
        userId: 'usr_owner',
        label: 'MacBook Pro Touch ID (ES256)',
        alg: -7,
        signCount: 14,
        createdAt: t3,
        lastUsedAt: t1,
      },
    ],
    secretLeases: [
      {
        id: 'lease_demo_ci_1',
        projectId: 'proj_acme_web',
        secretKey: 'DATABASE_URL',
        scope: 'read',
        kind: 'lease',
        issuedBy: 'owner@acme-demo.dev',
        reason: 'CI smoke verification read-only lease',
        ttlSec: 3600,
        expiresAt: nowIso(1000 * 60 * 48),
        revoked: false,
        createdAt: t1,
      },
    ],
    maintenanceWindows: [
      {
        id: 'mw_demo_pg_sunday',
        title: 'Weekly Postgres Vacuum & Index Maintenance',
        targetIds: ['*'],
        kind: 'recurring',
        startAt: nowIso(1000 * 60 * 60 * 6),
        durationMin: 30,
        intervalDays: 7,
        active: false,
      },
    ],
    incidents: [
      {
        id: 'inc_demo_cdn',
        title: 'Elevated Edge TLS Handshake Latency (EU-West)',
        severity: 'minor',
        status: 'monitoring',
        affectedIds: ['mon_app'],
        message: 'Switched ACME OCSP cache to memory fast-path; p95 latency back to 18 ms.',
        createdAt: t2,
        updatedAt: t1,
      },
    ],
  };
}

let _state: DemoState | null = null;
function state(): DemoState {
  if (!_state) _state = createInitialDemoState();
  return _state;
}

const DEMO_CATALOG_TEMPLATES = [
  { id: 'n8n', name: 'n8n', categoryId: 'automation', categoryLabel: 'Automation', summary: 'Workflow automation with 400+ integrations, native AI nodes, and SQLite/Postgres persistence.', image: 'n8nio/n8n:1.88.0', totalMemoryMb: 512, cpus: 1, licence: 'Fair-Code', sidecars: [], installedCount: 1 },
  { id: 'langfuse', name: 'Langfuse', categoryId: 'ai', categoryLabel: 'AI & LLM Ops', summary: 'Open-source LLM observability, prompt versioning, evals, and trace analytics.', image: 'langfuse/langfuse:3.45.0', totalMemoryMb: 1024, cpus: 1, licence: 'MIT', sidecars: [{ name: 'clickhouse' }], database: { engine: 'PostgreSQL 16' }, installedCount: 0 },
  { id: 'dify', name: 'Dify', categoryId: 'ai', categoryLabel: 'AI & LLM Ops', summary: 'Visual LLM agent workflow builder, RAG pipelines, and model router.', image: 'langgenius/dify-api:1.2.0', totalMemoryMb: 1536, cpus: 2, licence: 'Apache-2.0', sidecars: [{ name: 'worker' }, { name: 'redis' }], database: { engine: 'PostgreSQL 16' }, installedCount: 0 },
  { id: 'open-webui', name: 'Open WebUI', categoryId: 'ai', categoryLabel: 'AI & LLM Ops', summary: 'Self-hosted ChatGPT-class UI for Ollama, Anthropic, Gemini, and OpenAI endpoints.', image: 'ghcr.io/open-webui/open-webui:v0.6.5', totalMemoryMb: 512, cpus: 1, licence: 'MIT', sidecars: [], installedCount: 0 },
  { id: 'wordpress', name: 'WordPress', categoryId: 'cms', categoryLabel: 'CMS & Publishing', summary: 'Production WordPress with hardened MariaDB, Redis object cache, and auto-HTTPS.', image: 'wordpress:6.7.2-php8.3-apache', totalMemoryMb: 512, cpus: 1, licence: 'GPL-2.0', sidecars: [], database: { engine: 'MariaDB 11' }, installedCount: 0 },
  { id: 'ghost', name: 'Ghost', categoryId: 'cms', categoryLabel: 'CMS & Publishing', summary: 'Modern headless publishing platform, memberships, and newsletters.', image: 'ghost:5.115-alpine', totalMemoryMb: 512, cpus: 1, licence: 'MIT', sidecars: [], database: { engine: 'MySQL 8' }, installedCount: 0 },
  { id: 'authentik', name: 'Authentik', categoryId: 'security', categoryLabel: 'Identity & Security', summary: 'Enterprise OIDC / SAML / LDAP identity provider with MFA and RBAC.', image: 'ghcr.io/goauthentik/server:2025.2', totalMemoryMb: 768, cpus: 1, licence: 'MIT', sidecars: [{ name: 'worker' }], database: { engine: 'PostgreSQL 16' }, installedCount: 0 },
  { id: 'umami', name: 'Umami Analytics', categoryId: 'analytics', categoryLabel: 'Analytics', summary: 'Privacy-first, cookie-free web analytics in <128 MB RAM.', image: 'ghcr.io/umami-software/umami:postgresql-v2.17.0', totalMemoryMb: 256, cpus: 0.5, licence: 'MIT', sidecars: [], database: { engine: 'PostgreSQL 16' }, installedCount: 0 },
  { id: 'plausible', name: 'Plausible CE', categoryId: 'analytics', categoryLabel: 'Analytics', summary: 'Lightweight GDPR-compliant web analytics with ClickHouse backend.', image: 'ghcr.io/plausible/community-edition:v2.1.4', totalMemoryMb: 512, cpus: 1, licence: 'AGPL-3.0', sidecars: [{ name: 'clickhouse' }], database: { engine: 'PostgreSQL 16' }, installedCount: 0 },
  { id: 'pocketbase', name: 'PocketBase', categoryId: 'baas', categoryLabel: 'Backend & Data', summary: 'Single-binary Go backend with embedded SQLite, realtime subscriptions, and auth.', image: 'ghcr.io/muchobien/pocketbase:0.26.6', totalMemoryMb: 128, cpus: 0.5, licence: 'MIT', sidecars: [], installedCount: 0 },
  { id: 'minio', name: 'MinIO S3', categoryId: 'storage', categoryLabel: 'Storage', summary: 'S3-compatible high-performance object storage for backups and media.', image: 'minio/minio:RELEASE.2025-03-12T18-04-18Z', totalMemoryMb: 384, cpus: 0.5, licence: 'AGPL-3.0', sidecars: [], installedCount: 0 },
  { id: 'grafana', name: 'Grafana', categoryId: 'monitoring', categoryLabel: 'Monitoring', summary: 'Dashboards for Culkibo Prometheus /metrics and native OTLP traces.', image: 'grafana/grafana-oss:11.6.0', totalMemoryMb: 384, cpus: 0.5, licence: 'AGPL-3.0', sidecars: [], installedCount: 0 },
  { id: 'meilisearch', name: 'Meilisearch', categoryId: 'baas', categoryLabel: 'Backend & Data', summary: 'Sub-50ms typo-tolerant full-text & vector search engine.', image: 'getmeili/meilisearch:v1.13.3', totalMemoryMb: 384, cpus: 1, licence: 'MIT', sidecars: [], installedCount: 0 },
  { id: 'nocodb', name: 'NocoDB', categoryId: 'productivity', categoryLabel: 'Productivity', summary: 'Open-source Airtable alternative turning any Postgres DB into a smart spreadsheet.', image: 'nocodb/nocodb:0.262.5', totalMemoryMb: 384, cpus: 0.5, licence: 'AGPL-3.0', sidecars: [], installedCount: 0 },
  { id: 'directus', name: 'Directus', categoryId: 'cms', categoryLabel: 'CMS & Publishing', summary: 'Instant REST + GraphQL headless CMS over any SQL database.', image: 'directus/directus:11.5.1', totalMemoryMb: 512, cpus: 1, licence: 'BSL-1.1', sidecars: [], database: { engine: 'PostgreSQL 16' }, installedCount: 0 },
  { id: 'gitea', name: 'Gitea', categoryId: 'devtools', categoryLabel: 'DevTools', summary: 'Ultra-lightweight self-hosted Git forge with CI/CD Actions and webhooks.', image: 'gitea/gitea:1.23.6-rootless', totalMemoryMb: 256, cpus: 0.5, licence: 'MIT', sidecars: [], installedCount: 0 },
  { id: 'uptime-kuma', name: 'Uptime Kuma', categoryId: 'monitoring', categoryLabel: 'Monitoring', summary: 'Classic self-hosted status monitor (or use Culkibo built-in Uptime with 0 MB extra).', image: 'louislam/uptime-kuma:1.23.16', totalMemoryMb: 256, cpus: 0.5, licence: 'MIT', sidecars: [], installedCount: 0 },
  { id: 'metabase', name: 'Metabase', categoryId: 'analytics', categoryLabel: 'Analytics', summary: 'Self-service BI dashboards and SQL explorer for product teams.', image: 'metabase/metabase:v0.53.9', totalMemoryMb: 1024, cpus: 1, licence: 'AGPL-3.0', sidecars: [], database: { engine: 'PostgreSQL 16' }, installedCount: 0 },
];

const DEMO_MCP_APPS_HTML: Record<string, string> = {
  'ui://culkibo/topology': `<!doctype html><html><body style="margin:0;padding:16px;font-family:system-ui,-apple-system,sans-serif;background:#0b0b0f;color:#f4f4f5">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <strong style="font-size:13px">Culkibo Live Topology (MCP App · Sandbox)</strong>
      <span style="font-size:11px;padding:2px 8px;border-radius:999px;background:#052e16;color:#4ade80;border:1px solid #166534">7 nodes · 6 edges · Healthy</span>
    </div>
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;font-size:11px">
      <div style="padding:10px;border-radius:10px;background:#14141a;border:1px solid #27272a"><div style="color:#34d399;font-weight:600">Edge (Caddy HTTP/3)</div><div style="color:#a1a1aa;margin-top:4px;font-family:monospace">app.acme-demo.dev<br/>api.acme-demo.dev<br/>edge.acme-demo.dev</div></div>
      <div style="padding:10px;border-radius:10px;background:#14141a;border:1px solid #27272a"><div style="color:#fbbf24;font-weight:600">Projects (3 Active)</div><div style="color:#a1a1aa;margin-top:4px;font-family:monospace">acme-saas-web :3000<br/>edge-api-rust :8080<br/>ai-worker-py :8000</div></div>
      <div style="padding:10px;border-radius:10px;background:#14141a;border:1px solid #27272a"><div style="color:#818cf8;font-weight:600">Data & Fleet</div><div style="color:#a1a1aa;margin-top:4px;font-family:monospace">acme-postgres-16<br/>acme-valkey-8<br/>eu-central-hetzner-01</div></div>
    </div>
  </body></html>`,
  'ui://culkibo/incident-remediator': `<!doctype html><html><body style="margin:0;padding:16px;font-family:system-ui,-apple-system,sans-serif;background:#0b0b0f;color:#f4f4f5">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <strong style="font-size:13px">Incident Remediator · 2-Phase Safe Action</strong>
      <span style="font-size:11px;padding:2px 8px;border-radius:999px;background:#052e16;color:#4ade80;border:1px solid #166534">0 Active Incidents</span>
    </div>
    <p style="font-size:12px;color:#a1a1aa;margin:0;line-height:1.5">All 3 projects and 2 managed databases passed healthchecks (p95 2.40 ms, 51 MB daemon RSS). When an OOM or CrashLoop occurs, agents run <code>dryRun: true</code> → HMAC <code>confirmToken</code> → atomic rollback.</p>
  </body></html>`,
  'ui://culkibo/coolify-migration-diff': `<!doctype html><html><body style="margin:0;padding:16px;font-family:system-ui,-apple-system,sans-serif;background:#0b0b0f;color:#f4f4f5">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <strong style="font-size:13px">Coolify v4 → Culkibo Edge Diff</strong>
      <span style="font-size:11px;padding:2px 8px;border-radius:999px;background:#052e16;color:#4ade80;border:1px solid #166534">Parity Score 100%</span>
    </div>
    <div style="font-family:monospace;font-size:11px;background:#14141a;border:1px solid #27272a;border-radius:8px;padding:10px;color:#d4d4d8">
      - traefik.http.routers.web.rule=Host(\`app.acme.io\`)<br/>
      + caddy.route: app.acme.io → 127.0.0.1:3000 (HTTP/3 + Auto-TLS)<br/>
      + SERVICE_PASSWORD_POSTGRES → \${vault.postgres_pw} (AES-256-GCM)
    </div>
  </body></html>`,
};

function buildDemoTopology() {
  const s = state();
  const nodes: any[] = [
    { id: 'dom:app', kind: 'domain', entityId: 'dom_app', label: 'app.acme-demo.dev', sublabel: 'Caddy HTTP/3 · TLS 84d', status: 'active', health: 'healthy' },
    { id: 'dom:api', kind: 'domain', entityId: 'dom_api', label: 'api.acme-demo.dev', sublabel: 'Caddy HTTP/3 · TLS 84d', status: 'active', health: 'healthy' },
    ...s.projects.map((p) => ({
      id: `project:${p.id}`,
      kind: 'project',
      entityId: p.id,
      label: p.name,
      sublabel: `${p.runtime || 'node'} · :${p.containerPort || 3000}`,
      status: p.status || 'active',
      health: 'healthy',
    })),
    ...s.databases.map((db) => ({
      id: `database:${db.id}`,
      kind: db.engine === 'valkey' || db.engine === 'redis' ? 'cache' : 'database',
      entityId: db.id,
      label: db.name,
      sublabel: `${db.image} · :${db.port}`,
      status: db.status || 'running',
      health: 'healthy',
    })),
    { id: 'server:local', kind: 'server', entityId: 'local', label: 'Local Server (Primary)', sublabel: '4 vCPU · 51 MB RSS', status: 'online', health: 'healthy' },
  ];

  const edges: any[] = [
    { id: 'e_dom_web', from: 'dom:app', to: 'project:proj_acme_web', kind: 'routes_to', label: 'HTTP/3', status: 'healthy' },
    { id: 'e_dom_api', from: 'dom:api', to: 'project:proj_edge_rust', kind: 'routes_to', label: 'HTTP/3', status: 'healthy' },
  ];

  for (const p of s.projects) {
    for (const dbId of p.linkedDatabaseIds || []) {
      edges.push({
        id: `e_${p.id}_${dbId}`,
        from: `project:${p.id}`,
        to: `database:${dbId}`,
        kind: 'linked_db',
        label: dbId.includes('valkey') ? 'REDIS_URL' : 'DATABASE_URL',
        status: 'healthy',
      });
    }
    edges.push({
      id: `e_srv_${p.id}`,
      from: `project:${p.id}`,
      to: 'server:local',
      kind: 'deploys_on',
      label: 'Citadel',
      status: 'healthy',
    });
  }

  return {
    generatedAt: nowIso(),
    nodes,
    edges,
    summary: {
      totalNodes: nodes.length,
      totalEdges: edges.length,
      servers: 1,
      projects: s.projects.length,
      databases: s.databases.length,
      catalogServices: s.installations.length,
      domains: 2,
      monitors: s.monitors.length,
      unhealthyNodes: 0,
    },
  };
}

function buildDemoSmartPackPlan(projectId?: string) {
  const isRust = projectId === 'proj_edge_rust';
  const isPy = projectId === 'proj_ai_worker';
  if (isRust) {
    return {
      schemaVersion: 'culkibo.smartpack/v1',
      stack: 'rust',
      label: 'Rust (Release Multi-Stage)',
      runtime: 'rust',
      runtimeVersion: '1.85',
      packageManager: 'cargo',
      containerPort: 8080,
      baseImage: 'rust:1.85-slim-bookworm',
      runtimeImage: 'debian:bookworm-slim',
      buildCommand: 'cargo build --release && cp /src/target/release/edge-api /out/server',
      startCommand: ['/app/server'],
      layers: [
        { index: 0, name: 'builder', from: 'rust:1.85-slim-bookworm', stepCount: 3, cached: true },
        { index: 1, name: 'runtime', from: 'debian:bookworm-slim', stepCount: 1, cached: false },
      ],
      ociExport: { zstdChunked: true, compression: 'zstd', flags: ['--output', 'type=image,compression=zstd,compression-level=3,force-compression=true,oci-mediatypes=true'] },
      resourceLimits: { hostMemoryMb: 8192, hostCpus: 4, buildMemoryMb: 4096, buildCpus: 3, memory: '4096m', cpus: 3, maxParallelStages: 2, reservedHeadroomMb: 4096, zstdChunked: true },
      dockerignore: { implicit: true, mergedWithExisting: false, excludedCount: 14, patterns: ['.git', '.env', '.env.*', 'target', '*.log'], content: '# Culkibo SmartPack implicit .dockerignore\n.git\n.env\n.env.*\n!.env.example\ntarget\n*.log\n' },
      deterministicHash: '9e2c7a41d8f03b5a6c11e9d8420fa1229f4c8d1e70b2f3a8c5d9e0142a6b7c8d',
      dockerfile: '# syntax=docker/dockerfile:1.7\nFROM rust:1.85-slim-bookworm AS builder\nWORKDIR /src\nCOPY . .\nRUN --mount=type=cache,id=culkibo-cargo-reg,target=/usr/local/cargo/registry cargo build --release\n\nFROM debian:bookworm-slim AS runtime\nWORKDIR /app\nCOPY --from=builder /src/target/release/edge-api /app/server\nEXPOSE 8080\nCMD ["/app/server"]\n',
    };
  }
  if (isPy) {
    return {
      schemaVersion: 'culkibo.smartpack/v1',
      stack: 'python-uv',
      label: 'Python 3.12 (uv Fast Sync)',
      runtime: 'python',
      runtimeVersion: '3.12',
      packageManager: 'uv',
      containerPort: 8000,
      baseImage: 'ghcr.io/astral-sh/uv:python3.12-bookworm-slim',
      runtimeImage: 'ghcr.io/astral-sh/uv:python3.12-bookworm-slim',
      buildCommand: 'uv sync --frozen --no-dev',
      startCommand: ['uv', 'run', 'uvicorn', 'app.main:app', '--host', '0.0.0.0', '--port', '8000'],
      layers: [{ index: 0, name: 'runtime', from: 'ghcr.io/astral-sh/uv:python3.12-bookworm-slim', stepCount: 4, cached: true }],
      ociExport: { zstdChunked: true, compression: 'zstd', flags: ['--output', 'type=image,compression=zstd,compression-level=3,force-compression=true,oci-mediatypes=true'] },
      resourceLimits: { hostMemoryMb: 8192, hostCpus: 4, buildMemoryMb: 4096, buildCpus: 3, memory: '4096m', cpus: 3, maxParallelStages: 2, reservedHeadroomMb: 4096, zstdChunked: true },
      dockerignore: { implicit: true, mergedWithExisting: false, excludedCount: 16, patterns: ['.git', '.venv', '__pycache__', '.env*'], content: '# Culkibo SmartPack implicit .dockerignore\n.git\n.venv\n__pycache__\n.env\n.env.*\n!.env.example\n' },
      deterministicHash: '4b7f210ea9d345c8a1f6209e3bc7a1045de219f8a4b0c312e76d8910ab3c4d5e',
      dockerfile: '# syntax=docker/dockerfile:1.7\nFROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS runtime\nWORKDIR /app\nCOPY pyproject.toml uv.lock ./\nRUN --mount=type=cache,id=culkibo-uv-cache,target=/root/.cache/uv uv sync --frozen --no-dev\nCOPY . .\nEXPOSE 8000\nCMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]\n',
    };
  }
  return {
    schemaVersion: 'culkibo.smartpack/v1',
    stack: 'nextjs',
    label: 'Next.js 15 (Standalone Multi-Stage)',
    runtime: 'node',
    runtimeVersion: '22',
    packageManager: 'pnpm',
    containerPort: 3000,
    baseImage: 'node:22-alpine',
    runtimeImage: 'node:22-alpine',
    buildCommand: 'pnpm run build',
    startCommand: ['node', 'server.js'],
    layers: [
      { index: 0, name: 'deps', from: 'node:22-alpine', stepCount: 3, cached: true },
      { index: 1, name: 'builder', from: 'node:22-alpine', stepCount: 3, cached: true },
      { index: 2, name: 'runtime', from: 'node:22-alpine', stepCount: 2, cached: false },
    ],
    ociExport: { zstdChunked: true, compression: 'zstd', flags: ['--output', 'type=image,compression=zstd,compression-level=3,force-compression=true,oci-mediatypes=true'] },
    resourceLimits: { hostMemoryMb: 8192, hostCpus: 4, buildMemoryMb: 4096, buildCpus: 3, memory: '4096m', cpus: 3, maxParallelStages: 2, reservedHeadroomMb: 4096, zstdChunked: true },
    dockerignore: { implicit: true, mergedWithExisting: false, excludedCount: 24, patterns: ['.git', 'node_modules', '.next', '.env', '.env.*'], content: '# Culkibo SmartPack implicit .dockerignore\n.git\nnode_modules\n.next\n.env\n.env.*\n!.env.example\n*.log\n' },
    deterministicHash: '7a91e4c2b5d830f1a6e29c4b07d812fe5c3a90b1d4e6f7a8b9c0d1e2f3a4b5c6',
    dockerfile: '# syntax=docker/dockerfile:1.7\nFROM node:22-alpine AS builder\nWORKDIR /app\nRUN corepack enable\nCOPY package.json pnpm-lock.yaml ./\nRUN --mount=type=cache,id=culkibo-pnpm-store,target=/root/.local/share/pnpm/store pnpm install --frozen-lockfile\nCOPY . .\nRUN pnpm run build\n\nFROM node:22-alpine AS runtime\nWORKDIR /app\nENV NODE_ENV=production PORT=3000\nCOPY --from=builder /app/.next/standalone ./\nCOPY --from=builder /app/.next/static ./.next/static\nEXPOSE 3000\nCMD ["node", "server.js"]\n',
  };
}

function buildDemoCoolifyPlan() {
  return {
    parityScore: 100,
    readinessLevel: 'ready',
    summary: {
      totalResources: 5,
      apps: 2,
      databases: 3,
      domains: 3,
      magicVarsTranslated: 4,
      traefikRulesTranslated: 6,
      cronJobs: 2,
      volumes: 4,
    },
    magicVars: [
      { resourceName: 'acme-saas-web', envKey: 'DATABASE_URL', original: 'postgresql://acme:${SERVICE_PASSWORD_POSTGRES}@db:5432/acme', variable: 'SERVICE_PASSWORD_POSTGRES', kind: 'magic_secret', translated: 'postgresql://acme:${vault.service_password_postgres}@db:5432/acme', vaultKey: 'service_password_postgres', resolvedPreview: 'postgresql://acme:••••••••@db:5432/acme' },
      { resourceName: 'acme-saas-web', envKey: 'APP_URL', original: '${SERVICE_FQDN_WEB}', variable: 'SERVICE_FQDN_WEB', kind: 'magic_domain', translated: 'https://app.acme-demo.dev', vaultKey: null, resolvedPreview: 'https://app.acme-demo.dev' },
    ],
    traefikTranslations: [
      { resourceId: 'cool_app_1', resourceName: 'acme-saas-web', hosts: ['app.acme-demo.dev'], labelCount: 4, translatedRules: [{ source: 'traefik.http.routers.web.rule', target: 'caddy.route', summary: 'HTTPS + HTTP/3 route to :3000' }, { source: 'traefik.http.middlewares.compress', target: 'caddy.encode', summary: 'Native zstd + brotli + gzip' }], unsupportedLabels: [], warnings: [] },
    ],
    databases: [
      { id: 'cool_db_pg', name: 'acme-postgres-16', originalType: 'standalone-postgresql', culkiboEngine: 'postgresql', label: 'PostgreSQL 16', image: 'postgres:16-alpine', port: 5432, isPublicInCoolify: false, volumesCount: 1 },
      { id: 'cool_db_redis', name: 'acme-valkey-8', originalType: 'standalone-redis', culkiboEngine: 'valkey', label: 'Valkey 8', image: 'valkey/valkey:8-alpine', port: 6379, isPublicInCoolify: false, volumesCount: 1 },
    ],
    crons: [
      { name: 'Nightly DB Vacuum', schedule: '0 3 * * *', command: 'psql -c "VACUUM ANALYZE"', enabled: true, valid: true, warning: null, sourceResource: 'acme-saas-web' },
    ],
    cutoverChecklist: [
      { step: 1, id: 'provision', title: 'Provision Culkibo Projects & Managed Databases', detail: 'Zero-downtime parallel staging in isolated Docker network', required: true },
      { step: 2, id: 'stream', title: 'Stream PostgreSQL & Named Volumes over SSH', detail: 'Zero-shell pg_dump/tar pipeline with SHA-256 verification', required: true },
      { step: 3, id: 'dns', title: 'Cutover DNS / Caddy HTTP/3', detail: 'Automatic TLS issuance with 0-second downtime', required: true },
    ],
  };
}

function parseJsonBody(init?: RequestInit): Record<string, any> {
  if (!init?.body || typeof init.body !== 'string') return {};
  try {
    return JSON.parse(init.body);
  } catch {
    return {};
  }
}

export async function handleDemoFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const rawUrl = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
  const parsed = new URL(rawUrl, typeof window !== 'undefined' ? window.location.origin : 'http://localhost');
  const pathname = parsed.pathname.replace(/\/+$/, '') || '/';
  const method = (init.method || 'GET').toUpperCase();
  const body = parseJsonBody(init);
  const s = state();

  // --- Auth & Session ---
  if (pathname === '/api/auth/session') {
    return jsonResponse({ authenticated: true, method: 'demo', requireTokenAlways: false, tokenConfigured: false, tokenSource: 'interactive-sandbox' });
  }
  if (pathname === '/api/auth/me') {
    return jsonResponse({ authenticated: true, role: 'superadmin', email: 'explorer@culkibo.dev', teamId: 'team_default', scopes: ['*'] });
  }
  if (pathname === '/api/auth/ws-ticket') {
    return jsonResponse({ ticket: 'demo_ws_ticket' });
  }

  // --- System, Edition, Remote Access ---
  if (pathname === '/api/system/status') {
    return jsonResponse({
      status: 'online',
      version: '1.2.0',
      nodeVersion: 'v22.14.0',
      memoryUsageMb: 51,
      uptimeSeconds: 184200,
      dockerAvailable: true,
      caddyAvailable: true,
      publicIp: '198.51.100.10',
      demoMode: true,
    });
  }
  if (pathname === '/api/system/edition') {
    return jsonResponse({ edition: 'oss', licensed: false, features: { smartpack: true, directpush: true, edgetunnel: true, otlp: true, slsa: true, mcp2026: true } });
  }
  if (pathname === '/api/system/remote-access') {
    return jsonResponse({ publicIp: '198.51.100.10', panelDomain: 'panel.acme-demo.dev', recommendedUrl: 'https://panel.acme-demo.dev', port: 3030 });
  }
  if (pathname === '/api/sync/summary') {
    return jsonResponse({ totalConnectedClients: 1, sessions: [{ projectId: 'proj_acme_web', connectedClients: 1 }] });
  }

  // --- Projects ---
  if (pathname === '/api/projects' && method === 'GET') {
    return jsonResponse(s.projects);
  }
  const projectMatch = pathname.match(/^\/api\/projects\/([^/]+)$/);
  if (projectMatch && method === 'GET') {
    const proj = s.projects.find((p) => p.id === decodeURIComponent(projectMatch[1])) || s.projects[0];
    return jsonResponse(proj);
  }
  const fastRestartMatch = pathname.match(/^\/api\/projects\/([^/]+)\/fast-restart$/);
  if (fastRestartMatch && method === 'POST') {
    return jsonResponse({ restarted: true, rebuilt: false, durationMs: 1180, containerName: `culkibo-${fastRestartMatch[1]}`, message: 'Sandbox container fast-restarted (no rebuild)' });
  }
  const linkDbMatch = pathname.match(/^\/api\/projects\/([^/]+)\/databases\/([^/]+)\/link$/);
  if (linkDbMatch && method === 'POST') {
    const pid = decodeURIComponent(linkDbMatch[1]);
    const dbId = decodeURIComponent(linkDbMatch[2]);
    const proj = s.projects.find((p) => p.id === pid);
    if (proj) {
      proj.linkedDatabaseIds = Array.from(new Set([...(proj.linkedDatabaseIds || []), dbId]));
      const envKey = dbId.includes('valkey') ? 'REDIS_URL' : 'DATABASE_URL';
      proj.envVars = { ...(proj.envVars || {}), [envKey]: dbId.includes('valkey') ? 'redis://:••••••••@db-valkey-cache:6379' : 'postgresql://acme:••••••••@db-pg-main:5432/acme_prod' };
    }
    return jsonResponse({ success: true, project: proj, note: 'Linked in interactive sandbox' });
  }
  if (pathname.match(/^\/api\/projects\/[^/]+\/env$/) && (method === 'PUT' || method === 'POST')) {
    const pid = decodeURIComponent(pathname.split('/')[3] || '');
    const proj = s.projects.find((p) => p.id === pid);
    if (proj && body.envVars && typeof body.envVars === 'object') {
      proj.envVars = { ...body.envVars };
    }
    return jsonResponse({ success: true, project: proj });
  }
  if (pathname.match(/^\/api\/projects\/[^/]+\/deployments$/)) {
    return jsonResponse({
      deployments: [
        { id: 'dep_demo_1', status: 'activo', commitSha: '8c4f1a9', branch: 'main', durationMs: 14200, createdAt: nowIso(-1000 * 60 * 14), strategy: 'smartpack-zstd' },
        { id: 'dep_demo_0', status: 'reemplazado', commitSha: '5b12d04', branch: 'main', durationMs: 18900, createdAt: nowIso(-1000 * 60 * 180), strategy: 'smartpack-zstd' },
      ],
    });
  }
  const attestMatch = pathname.match(/^\/api\/projects\/([^/]+)\/releases\/([^/]+)\/attest$/);
  if (attestMatch && method === 'POST') {
    const pid = decodeURIComponent(attestMatch[1]);
    const rev = decodeURIComponent(attestMatch[2]);
    const sha = '7a91e4c2b5d830f1a6e29c4b07d812fe5c3a90b1d4e6f7a8b9c0d1e2f3a4b5c6';
    const statement = {
      _type: 'https://in-toto.io/Statement/v1',
      predicateType: 'https://slsa.dev/provenance/v1',
      subject: [{ name: `${pid}@${rev}`, digest: { sha256: sha } }],
      predicate: { buildDefinition: { buildType: 'https://culkibo.dev/smartpack/v1' } },
    };
    const envelope = {
      payloadType: 'application/vnd.in-toto+json',
      payload: btoa(JSON.stringify(statement)),
      signatures: [{ keyid: 'ed25519-demo-key-01', sig: 'ZGVtb19lZDI1NTE5X2Rzc2Vfc2lnbmF0dXJl' }],
    };
    return jsonResponse({ projectId: pid, revision: rev, keyId: 'ed25519-demo-key-01', predicateType: 'https://slsa.dev/provenance/v1', subjectDigest: sha, statement, envelope, createdAt: nowIso() }, 201);
  }
  if (pathname === '/api/security/attestation/verify' && method === 'POST') {
    return jsonResponse({
      valid: true,
      keyId: 'ed25519-demo-key-01',
      predicateType: 'https://slsa.dev/provenance/v1',
      subjectDigest: '7a91e4c2b5d830f1a6e29c4b07d812fe5c3a90b1d4e6f7a8b9c0d1e2f3a4b5c6',
      reason: null,
    });
  }
  const migPlanMatch = pathname.match(/^\/api\/projects\/([^/]+)\/migrations\/plan$/);
  if (migPlanMatch && method === 'POST') {
    const pid = decodeURIComponent(migPlanMatch[1]);
    const cmd = String(body.command || 'npx prisma migrate deploy').trim();
    const argv = cmd.split(/\s+/).filter(Boolean);
    return jsonResponse({
      command: cmd,
      argv,
      snapshotRequired: true,
      lockKey: `migration-lease:${pid}`,
      timeoutMs: 120000,
      abortCutoverOnFailure: true,
      shell: false,
      dockerArgs: ['run', '--rm', '--label', 'culkibo.migration=1', `culkibo/${pid}:latest`, ...argv],
    });
  }
  const wasmInvokeMatch = pathname.match(/^\/api\/projects\/([^/]+)\/wasm\/invoke$/);
  if (wasmInvokeMatch && method === 'POST') {
    const argVal = Number.isFinite(Number(body.arg)) ? Number(body.arg) : 200;
    return jsonResponse({
      ok: true,
      status: 200,
      headers: { 'x-culkibo-runtime': 'micro-wasm-worker', 'content-type': 'application/json' },
      result: argVal * 2 + 1,
      body: JSON.stringify({ ok: true, input: argVal, output: argVal * 2 + 1, sandbox: 'worker_threads' }),
      execMs: 0.56,
      memoryBytes: 65536,
      engine: 'node-webassembly-isolated',
    });
  }

  // --- Cycle-6 Whole-Stack Time-Machine, Shadow Replay Gate & FinOps ---
  const tmListMatch = pathname.match(/^\/api\/projects\/([^/]+)\/timemachine$/);
  if (tmListMatch) {
    const pid = decodeURIComponent(tmListMatch[1]);
    const list = s.checkpoints[pid] || s.checkpoints.proj_acme_web || [];
    if (method === 'POST') {
      const proj = s.projects.find((p) => p.id === pid) || s.projects[0];
      const envCount = Object.keys(proj?.envVars || {}).length;
      const domainsCount = (proj?.domains || []).length;
      const dbLinksCount = (proj?.linkedDatabaseIds || []).length;
      const cp = {
        id: `cp_${Date.now().toString(36)}`,
        projectId: pid,
        label: String(body.label || 'Manual whole-stack checkpoint'),
        actor: String(body.actor || 'sandbox-user'),
        sha256: `${Math.random().toString(16).slice(2, 18)}${'a4f9c2e1b8d0'.repeat(4)}`.slice(0, 64),
        imageTag: proj?.resources?.[0]?.image || `culkibo/${pid}:latest`,
        envCount,
        domainsCount,
        cronsCount: 1,
        dbLinksCount,
        counts: { envVars: envCount, domains: domainsCount, crons: 1, dbLinks: dbLinksCount },
        createdAt: nowIso(),
      };
      s.checkpoints[pid] = [cp, ...list];
      return jsonResponse({ checkpoint: cp, ...cp }, 201);
    }
    return jsonResponse({ checkpoints: list });
  }
  const tmRestoreMatch = pathname.match(/^\/api\/projects\/([^/]+)\/timemachine\/([^/]+)\/restore$/);
  if (tmRestoreMatch && method === 'POST') {
    const cpId = decodeURIComponent(tmRestoreMatch[2]);
    return jsonResponse({
      dryRun: body.dryRun !== false,
      restored: body.dryRun === false,
      checkpointId: cpId,
      safetyCheckpointId: body.dryRun === false ? `cp_safety_${Date.now().toString(36)}` : null,
      diff: { changed: true, imageChanged: true, envKeysAdded: [], envKeysRemoved: [], envKeysChanged: ['NEXT_PUBLIC_API_URL'], domainsChanged: false, cronsChanged: false },
      mutations: ['Restore container image digest to checkpoint revision', 'Reconcile HMAC env fingerprint & Caddy HTTPS routes (0-downtime)'],
    });
  }
  const srMatch = pathname.match(/^\/api\/projects\/([^/]+)\/shadow-replay$/);
  if (srMatch && method === 'POST') {
    return jsonResponse({
      id: `sr_${Date.now().toString(36)}`,
      pass: true,
      verdict: 'PROMOTE',
      blockers: [],
      summary: {
        totalRequests: 24,
        baselineP95Ms: 14.2,
        candidateP95Ms: 15.1,
        baselineLatencyMs: { p50: 8.4, p95: 14.2, p99: 19.6, avg: 9.2 },
        candidateLatencyMs: { p50: 8.8, p95: 15.1, p99: 20.4, avg: 9.7 },
        latencyRatio: 1.06,
        latencyRatioP95: 1.06,
        delta5xx: 0,
        statusMismatchPct: 0,
        schemaDriftCount: 0,
        breakingSchemaDriftCount: 0,
      },
      createdAt: nowIso(),
    });
  }
  if (pathname === '/api/finops/report' || pathname === '/api/finops/compare') {
    const apps = Number(body.apps) || s.projects.length;
    const dbs = Number(body.databases) || s.databases.length;
    const monthlyCloudUsd = Math.round(apps * 48 + dbs * 32 + 20);
    const monthlySelfHostedUsd = apps + dbs <= 6 ? 8.29 : 17.99;
    const monthlySavingsUsd = Math.round(Math.max(0, monthlyCloudUsd - monthlySelfHostedUsd) * 100) / 100;
    const annualSavingsUsd = Math.round(monthlySavingsUsd * 12);
    const savingsPct = monthlyCloudUsd > 0 ? Math.round((monthlySavingsUsd / monthlyCloudUsd) * 1000) / 10 : 0;
    const footnote = 'Published standard cloud tiers (Vercel Pro, Railway, Render, Managed Postgres) vs Hetzner Cloud CX32.';
    const comparison = {
      monthlyCloudUsd,
      monthlySelfHostedUsd,
      monthlySavingsUsd,
      annualSavingsUsd,
      savingsPct,
      recommendedVps: {
        provider: 'Hetzner',
        name: apps + dbs <= 6 ? 'CX32' : 'CX42',
        plan: apps + dbs <= 6 ? 'CX32 (4 vCPU · 8 GB RAM)' : 'CX42 (8 vCPU · 16 GB RAM)',
        vcpus: apps + dbs <= 6 ? 4 : 8,
        ramGb: apps + dbs <= 6 ? 8 : 16,
        monthlyUsd: monthlySelfHostedUsd,
        totalMonthlyUsd: monthlySelfHostedUsd,
      },
      cloudBreakdown: [
        { provider: 'Vercel Pro + Compute', monthlyUsd: Math.round(apps * 28 + 20) },
        { provider: 'Railway / Render Workers', monthlyUsd: Math.round(apps * 20) },
        { provider: 'Managed Postgres + Valkey', monthlyUsd: Math.round(dbs * 32) },
      ],
      footnote,
      pricingFootnotes: [footnote],
    };
    return jsonResponse({
      ...comparison,
      costComparison: comparison,
      comparison,
      recommendations: [
        {
          id: 'fin_1',
          projectId: 'proj_ai_worker',
          projectName: 'ai-worker-py',
          type: 'right_size_ram',
          title: 'Right-size ai-worker-py memory cap (512 MB → 256 MB) + Scale-to-Zero',
          message: 'Peak p95 RSS over 7d was 118 MB; enabling auto-sleep reclaims 256 MB RAM.',
          detail: 'Peak p95 RSS over 7d was 118 MB; enabling auto-sleep reclaims 256 MB RAM.',
          reclaimableRamMb: 256,
          estimatedMonthlySavingsUsd: 18,
        },
      ],
    });
  }

  // --- Cycle-7 Pioneer APIs (Web Terminal, Build Auto-Healer, WireGuard Mesh, Edge Shield, Cron Heatmap & Heartbeats) ---
  const termTicketMatch = pathname.match(/^\/api\/projects\/([^/]+)\/terminal\/ticket$/);
  if (termTicketMatch && method === 'POST') {
    const pid = decodeURIComponent(termTicketMatch[1]);
    const shell = typeof body.shell === 'string' && ['/bin/sh', '/bin/bash', '/bin/ash'].includes(body.shell) ? body.shell : '/bin/sh';
    const ticket = `ckb_term_${Math.random().toString(36).slice(2, 12)}`;
    return jsonResponse({
      ticket,
      expiresAt: nowIso(60_000),
      wsPath: `/ws/terminal?ticket=${ticket}`,
      containerName: `culkibo-${pid}`,
      shell,
    });
  }
  if (pathname === '/api/terminal/sessions') {
    return jsonResponse({ sessions: [] });
  }

  const healDiagMatch = pathname.match(/^\/api\/projects\/([^/]+)\/build-healer\/diagnose$/);
  if (healDiagMatch && method === 'POST') {
    const logs = String(body.logs || '');
    const matches: any[] = [];
    if (/heap limit|out of memory|FATAL ERROR/i.test(logs)) {
      matches.push({
        code: 'NODE_HEAP_OOM',
        title: 'Node.js V8 Heap Exhausted During Build',
        severity: 'high',
        rootCause: 'Next.js / Webpack exceeded default V8 heap cap inside constrained BuildKit container.',
        confidence: 97,
        matchedLine: 'FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory',
        patchPreview: '+ NODE_OPTIONS=--max-old-space-size=1536\n+ memoryLimitMb: 2048',
        autoFixAction: 'Set NODE_OPTIONS=--max-old-space-size=1536 and bump container memory cap',
      });
    }
    if (/127\.0\.0\.1|localhost:\d+|listening on localhost/i.test(logs)) {
      matches.push({
        code: 'CONTAINER_BIND_LOCALHOST',
        title: 'App Bound to Loopback (127.0.0.1) Inside Container',
        severity: 'high',
        rootCause: 'Server listens on 127.0.0.1 instead of 0.0.0.0, preventing Caddy reverse proxy reachability.',
        confidence: 94,
        matchedLine: 'Server listening on http://127.0.0.1:3000',
        patchPreview: '+ HOST=0.0.0.0\n+ HOSTNAME=0.0.0.0',
        autoFixAction: 'Inject HOST=0.0.0.0 and HOSTNAME=0.0.0.0 runtime env vars',
      });
    }
    if (/unknown log opt.*max-size|journald|syslog/i.test(logs)) {
      matches.push({
        code: 'DOCKER_LOG_OPT_DRIVER_MISMATCH',
        title: 'Docker Log Driver Option Mismatch (kamal#1709)',
        severity: 'high',
        rootCause: 'Host uses syslog/journald driver which rejects json-file max-size log-opt.',
        confidence: 96,
        matchedLine: "unknown log opt 'max-size' for journald log driver",
        patchPreview: '- --log-opt max-size=10m\n+ logDriver: json-file (or omit size opts for journald)',
        autoFixAction: 'Auto-guard --log-opt max-size to json-file/local drivers only',
      });
    }
    if (matches.length === 0 && logs.trim().length > 0) {
      matches.push({
        code: 'NPM_CI_LOCKFILE_DRIFT',
        title: 'Lockfile Out of Sync with package.json',
        severity: 'medium',
        rootCause: 'Build command ran strict npm ci against a drifted package-lock.json.',
        confidence: 88,
        matchedLine: logs.split(/\r?\n/)[0]?.slice(0, 120) || 'Build exited with non-zero status',
        patchPreview: '- npm ci\n+ npm install --no-audit --no-fund',
        autoFixAction: 'Switch SmartPack install step to safe lockfile reconcile',
      });
    }
    return jsonResponse({
      matched: matches.length > 0,
      totalMatches: matches.length,
      primary: matches[0] || null,
      matches,
      analyzedLines: logs.split(/\r?\n/).length,
      analyzedMs: 0.42,
    });
  }

  const healApplyMatch = pathname.match(/^\/api\/projects\/([^/]+)\/build-healer\/apply$/);
  if (healApplyMatch && method === 'POST') {
    const code = String(body.code || 'NODE_HEAP_OOM');
    return jsonResponse({
      ok: true,
      dryRun: body.dryRun !== false,
      applied: body.dryRun === false,
      code,
      title: code === 'CONTAINER_BIND_LOCALHOST' ? 'Bind container listener to 0.0.0.0' : 'Raise V8 heap & container memory cap',
      patchPlan: {
        envAdditions: { NODE_OPTIONS: '--max-old-space-size=1536', HOST: '0.0.0.0' },
        memoryLimitMb: 2048,
        logDriver: 'json-file',
      },
      changes: [
        'Add env NODE_OPTIONS=--max-old-space-size=1536',
        'Add env HOST=0.0.0.0 (ensures Caddy proxy reachability)',
        'Set memoryLimitMb=2048 & bounded json-file log rotation',
      ],
    });
  }

  if (pathname === '/api/fleet/mesh' && method === 'GET') {
    return jsonResponse({
      cidr: '10.88.0.0/24',
      interfaceName: 'wg0',
      peerCount: s.meshPeers.length,
      peers: s.meshPeers,
      firewallGuard: {
        blocksPublicDbPorts: true,
        ufwBypassWarning: '0 public 0.0.0.0 DB ports exposed — all fleet DB traffic routed via 10.88.0.0/24 (kamal#1856 protected).',
      },
    });
  }
  if (pathname === '/api/fleet/mesh/plan' && method === 'POST') {
    return jsonResponse({
      cidr: '10.88.0.0/24',
      interfaceName: 'wg0',
      dryRun: true,
      configs: s.meshPeers.map((peer) => ({
        nodeId: peer.nodeId,
        name: peer.name,
        meshIp: peer.meshIp,
        wgConfig: [
          '[Interface]',
          `Address = ${peer.meshIp}/24`,
          `ListenPort = ${peer.listenPort || 51820}`,
          'PrivateKey = [REDACT_ON_API — decrypted atomically on node from AES-256-GCM vault]',
          '',
          ...s.meshPeers
            .filter((o) => o.nodeId !== peer.nodeId)
            .map((o) => `[Peer] # ${o.name}\nPublicKey = ${o.publicKey}\nAllowedIPs = ${o.meshIp}/32\nEndpoint = ${o.endpoint}\nPersistentKeepalive = 25`),
        ].join('\n'),
      })),
      firewallRules: [
        'ufw allow 51820/udp comment "Culkibo WireGuard Mesh"',
        'ufw allow in on wg0 from 10.88.0.0/24 to any port 5432,6379,3306 proto tcp',
        'iptables -I DOCKER-USER -i eth0 -p tcp -m multiport --dports 5432,6379,3306 -j DROP',
      ],
      diff: { added: [], updated: [], removed: [] },
    });
  }
  if (pathname === '/api/fleet/mesh/rotate' && method === 'POST') {
    const target = s.meshPeers.find((p) => p.nodeId === body.nodeId) || s.meshPeers[0];
    const nextPub = 'X9qR4vT2mN8bK1wF6hP3zL5cD7jG0yA4eS2uV9nM8Wk=';
    return jsonResponse({
      dryRun: body.dryRun !== false,
      rotated: body.dryRun === false,
      nodeId: target?.nodeId || 'local',
      keyVersion: (target?.keyVersion || 1) + 1,
      oldPublicKey: target?.publicKey || '',
      newPublicKey: nextPub,
      rolloutPlan: [
        `Generate fresh native Node x25519 keypair for ${target?.name || 'local'}`,
        'Encrypt private key with AES-256-GCM (AAD wg:<nodeId>) in .fleet-mesh.key (0o600)',
        'Atomically push updated peer publicKey to all mesh neighbors via SSH tunnel (0 downtime)',
      ],
    });
  }

  if (pathname === '/api/edge-shield/status') {
    return jsonResponse({
      enabledCount: 2,
      powEnabledCount: 1,
      blockedPathRules: 18,
      blockedUaPatterns: 14,
      activeChallenges: 3,
      defaultDifficulty: 4,
    });
  }
  if (pathname === '/api/edge-shield/challenge') {
    const dom = parsed.searchParams.get('domain') || s.domains[0]?.hostname || 'app.acme-demo.dev';
    return jsonResponse({
      challengeId: `sh_${Date.now().toString(36)}`,
      salt: `${Math.random().toString(16).slice(2, 18)}9f4a2c1e`,
      difficulty: 4,
      expiresAt: nowIso(300_000),
      algorithm: 'sha256',
      domain: dom,
    });
  }

  if (pathname === '/api/crons/timeline') {
    const counts = [1, 0, 1, 3, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1];
    const slots = counts.map((c, h) => ({
      hour: h,
      label: `${String(h).padStart(2, '0')}:00`,
      count: c,
      hasCollision: c >= 2,
      collisions: c >= 2 ? 1 : 0,
      runs: c === 3
        ? [
            { name: 'pg-nightly-backup', projectId: 'proj_acme_web' },
            { name: 's3-snapshot-sync', projectId: 'proj_acme_web' },
            { name: 'stripe-invoice-rollup', projectId: 'proj_edge_rust' },
          ]
        : c === 1
          ? [{ name: 'health-digest-cron', projectId: 'proj_acme_web' }]
          : [],
    }));
    return jsonResponse({
      hours: 24,
      totalRuns: counts.reduce((a, b) => a + b, 0),
      slots,
      collisionWarnings: [
        {
          hour: 3,
          count: 3,
          jobs: ['pg-nightly-backup', 's3-snapshot-sync', 'stripe-invoice-rollup'],
          message: '03:00 UTC: 3 heavy-IO jobs overlap within 5m — stagger backup & rollup by +15m to avoid disk contention.',
        },
      ],
    });
  }

  if (pathname === '/api/heartbeats') {
    if (method === 'POST') {
      const token = `ckb_hb_${Math.random().toString(16).slice(2, 18)}`;
      const hb = {
        id: `hb_${Date.now().toString(36)}`,
        name: String(body.name || 'Custom Heartbeat'),
        projectId: body.projectId || null,
        token,
        pingUrl: `/api/heartbeat/${token}`,
        periodSec: Math.max(60, Number(body.periodSec) || 3600),
        graceSec: Math.max(30, Number(body.graceSec) || 300),
        status: 'new',
        lastPingAt: null,
        lastDurationMs: null,
      };
      s.heartbeats = [hb, ...s.heartbeats];
      return jsonResponse({ heartbeat: hb, ...hb }, 201);
    }
    return jsonResponse({ heartbeats: s.heartbeats });
  }
  const hbDelMatch = pathname.match(/^\/api\/heartbeats\/([^/]+)$/);
  if (hbDelMatch && method === 'DELETE') {
    const id = decodeURIComponent(hbDelMatch[1]);
    s.heartbeats = s.heartbeats.filter((h) => h.id !== id);
    return jsonResponse({ ok: true, deleted: true });
  }
  const hbPingMatch = pathname.match(/^\/api\/heartbeat\/([^/]+)(?:\/(start|fail))?$/);
  if (hbPingMatch) {
    const tok = decodeURIComponent(hbPingMatch[1]);
    const st = hbPingMatch[2];
    const hb = s.heartbeats.find((h) => h.token === tok);
    if (hb) {
      hb.status = st === 'fail' ? 'down' : 'up';
      hb.lastPingAt = nowIso();
      hb.lastDurationMs = st === 'start' ? null : 142;
    }
    return jsonResponse({ ok: true, heartbeat: hb || null, status: hb?.status || 'up', lastPingAt: nowIso() });
  }

  // --- Cycle-8 Enterprise Sovereignty APIs (Passkeys FIDO2, Secret Leases, OSV CVE, OpenTofu IaC, Drift Check, Maintenance & Incidents) ---
  if (pathname === '/api/auth/passkeys' && method === 'GET') {
    return jsonResponse({ passkeys: s.passkeys });
  }
  if (pathname === '/api/auth/passkeys/register/begin' && method === 'POST') {
    const label = String(body.label || 'YubiKey 5C NFC (Ed25519)').trim();
    const created = {
      id: `pk_${Date.now().toString(36)}`,
      userId: 'usr_owner',
      label,
      alg: -8,
      signCount: 1,
      createdAt: nowIso(),
      lastUsedAt: nowIso(),
    };
    s.passkeys = [created, ...s.passkeys];
    return jsonResponse({
      challengeId: `chg_${Date.now().toString(36)}`,
      challenge: 'Q3Vsa2lib1dlYkF1dGhuRklETzJDaGFsbGVuZ2VEZW1v',
      rpId: typeof window !== 'undefined' ? window.location.hostname : 'localhost',
      publicKey: { rp: { name: 'Culkibo' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }] },
      demoRegistered: created,
    }, 201);
  }
  const pkDelMatch = pathname.match(/^\/api\/auth\/passkeys\/([^/]+)$/);
  if (pkDelMatch && method === 'DELETE') {
    const id = decodeURIComponent(pkDelMatch[1]);
    s.passkeys = s.passkeys.filter((p) => p.id !== id);
    return jsonResponse({ ok: true, revoked: true });
  }

  if (pathname === '/api/security/leases') {
    if (method === 'POST') {
      const ttlSec = Math.max(60, Math.min(86400, Number(body.ttlSec) || 3600));
      const lease = {
        id: `lease_${Date.now().toString(36)}`,
        projectId: body.projectId || 'proj_acme_web',
        secretKey: String(body.secretKey || 'DATABASE_URL'),
        scope: String(body.scope || 'read'),
        kind: 'lease',
        issuedBy: 'owner@acme-demo.dev',
        reason: String(body.reason || 'Short-lived operator access'),
        ttlSec,
        expiresAt: nowIso(ttlSec * 1000),
        revoked: false,
        createdAt: nowIso(),
      };
      s.secretLeases = [lease, ...s.secretLeases];
      return jsonResponse({ lease, token: `ckl_demo_${Math.random().toString(36).slice(2, 16)}` }, 201);
    }
    return jsonResponse({ leases: s.secretLeases.filter((l) => !l.revoked) });
  }
  const leaseDelMatch = pathname.match(/^\/api\/security\/leases\/([^/]+)$/);
  if (leaseDelMatch && method === 'DELETE') {
    const id = decodeURIComponent(leaseDelMatch[1]);
    s.secretLeases = s.secretLeases.map((l) => (l.id === id ? { ...l, revoked: true } : l));
    return jsonResponse({ ok: true, revoked: true });
  }
  if (pathname === '/api/security/break-glass' && method === 'POST') {
    const reason = String(body.reason || '').trim();
    if (reason.length < 10) {
      return jsonResponse({ error: 'Break-Glass requires an audit reason of at least 10 characters.' }, 400);
    }
    const ttlSec = Math.min(900, Math.max(60, Number(body.ttlSec) || 900));
    const lease = {
      id: `bg_${Date.now().toString(36)}`,
      projectId: '*',
      secretKey: 'BREAK_GLASS_EMERGENCY',
      scope: 'admin:emergency',
      kind: 'break_glass',
      issuedBy: 'owner@acme-demo.dev',
      reason,
      ttlSec,
      expiresAt: nowIso(ttlSec * 1000),
      revoked: false,
      createdAt: nowIso(),
    };
    s.secretLeases = [lease, ...s.secretLeases];
    return jsonResponse({ lease, token: `ckl_bg_${Math.random().toString(36).slice(2, 16)}` }, 201);
  }
  if (pathname === '/api/security/rotation-audit') {
    return jsonResponse({
      totalKeys: 11,
      staleCount: 1,
      maxAgeDays: 90,
      staleKeys: [
        { projectId: 'proj_edge_rust', projectName: 'edge-api-rust', key: 'STRIPE_WEBHOOK_SECRET', ageDays: 112 },
      ],
    });
  }

  if (pathname === '/api/security/cve-scan' || pathname === '/api/security/cve-scan/latest') {
    return jsonResponse({
      scannedPackages: 6,
      vulnerablePackages: 0,
      totalVulnerabilities: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      offline: true,
      cached: true,
      scannedAt: nowIso(),
      findings: [],
    });
  }

  if (pathname === '/api/iac/export' && method === 'POST') {
    return jsonResponse({
      ok: true,
      format: String(body.format || 'all'),
      generatedAt: nowIso(),
      secretsRedactedCount: 11,
      stats: { projects: s.projects.length, databases: s.databases.length, domains: s.domains.length, crons: 3, meshPeers: s.meshPeers.length },
      files: {
        'main.tf': [
          'terraform {',
          '  required_version = ">= 1.6.0"',
          '  required_providers {',
          '    docker = { source = "kreuzwerker/docker", version = "~> 3.0" }',
          '  }',
          '}',
          '',
          'resource "docker_network" "culkibo_acme_saas_web" {',
          '  name = "culkibo-net-proj-acme-web"',
          '}',
          '',
          'resource "docker_container" "acme_saas_web" {',
          '  name         = "culkibo-acme-saas-web"',
          '  image        = "culkibo/acme-saas-web:sha-8c4f1a"',
          '  stop_timeout = 30',
          '  log_driver   = "json-file"',
          '  log_opts     = { "max-size" = "10m", "max-file" = "3" }',
          '  env = [',
          '    "NODE_ENV=production",',
          '    "DATABASE_URL=${var.acme_saas_web_database_url}",',
          '  ]',
          '}',
        ].join('\n'),
        'variables.tf': [
          'variable "acme_saas_web_database_url" {',
          '  type        = string',
          '  sensitive   = true',
          '  description = "Inject via TF_VAR_acme_saas_web_database_url (0 plaintext secrets exported)"',
          '}',
        ].join('\n'),
        'docker-compose.yml': [
          'services:',
          '  acme-saas-web:',
          '    image: culkibo/acme-saas-web:sha-8c4f1a',
          '    stop_grace_period: 30s',
          '    logging:',
          '      driver: json-file',
          '      options:',
          '        max-size: "10m"',
          '        max-file: "3"',
          '    environment:',
          '      DATABASE_URL: ${ACME_SAAS_WEB_DATABASE_URL}',
          '    networks:',
          '      - culkibo-net-proj-acme-web',
          'networks:',
          '  culkibo-net-proj-acme-web:',
          '    driver: bridge',
        ].join('\n'),
        '.env.example': [
          '# Culkibo Zero-Lock-In Export (0 plaintext secrets)',
          'ACME_SAAS_WEB_DATABASE_URL=',
          'ACME_SAAS_WEB_REDIS_URL=',
          'EDGE_API_RUST_DATABASE_URL=',
        ].join('\n'),
      },
    });
  }

  const driftMatch = pathname.match(/^\/api\/projects\/([^/]+)\/drift\/check$/);
  if (driftMatch && method === 'POST') {
    const pid = decodeURIComponent(driftMatch[1]);
    const isDrifted = pid === 'proj_ai_worker';
    return jsonResponse({
      ok: true,
      drifted: isDrifted,
      runtimeOffline: false,
      severity: isDrifted ? 'high' : 'none',
      checkedAt: nowIso(),
      declaredEnvKeyHash: 'sha256:9c41f8e2b7a0d3c6',
      actualEnvKeyHash: isDrifted ? 'sha256:1b77d2a9e4f1c082' : 'sha256:9c41f8e2b7a0d3c6',
      diffs: isDrifted
        ? [
            { field: 'memoryLimitMb', severity: 'high', declared: 512, actual: 1024, message: 'Live container memory cap (1024 MB) drifted from declared 512 MB.' },
          ]
        : [],
      reconcilePlan: {
        dryRunDefault: true,
        actionCount: isDrifted ? 1 : 0,
        actions: isDrifted ? ['Reconcile container memoryLimitMb 1024 MB -> 512 MB via zero-downtime fast restart'] : [],
      },
    });
  }

  if (pathname === '/api/uptime/maintenance') {
    if (method === 'POST') {
      const win = {
        id: `mw_${Date.now().toString(36)}`,
        title: String(body.title || 'Scheduled Maintenance Window'),
        targetIds: Array.isArray(body.targetIds) && body.targetIds.length > 0 ? body.targetIds : ['*'],
        kind: body.kind === 'once' ? 'once' : 'recurring',
        startAt: String(body.startAt || nowIso(1000 * 60 * 30)),
        durationMin: Math.max(5, Number(body.durationMin) || 60),
        intervalDays: Math.max(1, Number(body.intervalDays) || 7),
        active: false,
      };
      s.maintenanceWindows = [win, ...s.maintenanceWindows];
      return jsonResponse({ window: win, ...win }, 201);
    }
    return jsonResponse({ windows: s.maintenanceWindows, maintenanceWindows: s.maintenanceWindows });
  }
  const mwDelMatch = pathname.match(/^\/api\/uptime\/maintenance\/([^/]+)$/);
  if (mwDelMatch && method === 'DELETE') {
    const id = decodeURIComponent(mwDelMatch[1]);
    s.maintenanceWindows = s.maintenanceWindows.filter((w) => w.id !== id);
    return jsonResponse({ ok: true, deleted: true });
  }

  if (pathname === '/api/uptime/incidents') {
    if (method === 'POST') {
      const inc = {
        id: `inc_${Date.now().toString(36)}`,
        title: String(body.title || 'Service Degradation'),
        severity: String(body.severity || 'minor'),
        status: String(body.status || 'investigating'),
        affectedIds: Array.isArray(body.affectedIds) ? body.affectedIds : [],
        message: String(body.message || 'Investigating elevated latency on upstream edge.'),
        createdAt: nowIso(),
        updatedAt: nowIso(),
      };
      s.incidents = [inc, ...s.incidents];
      return jsonResponse({ incident: inc, ...inc }, 201);
    }
    return jsonResponse({ incidents: s.incidents });
  }
  const incPatchMatch = pathname.match(/^\/api\/uptime\/incidents\/([^/]+)$/);
  if (incPatchMatch && method === 'PATCH') {
    const id = decodeURIComponent(incPatchMatch[1]);
    const inc = s.incidents.find((i) => i.id === id);
    if (inc) {
      if (body.status) inc.status = String(body.status);
      if (body.message) inc.message = String(body.message);
      inc.updatedAt = nowIso();
    }
    return jsonResponse({ incident: inc || null });
  }

  if (pathname === '/api/uptime/geo-failover/plan' && method === 'POST') {
    const dom = String(body.domain || 'app.acme-demo.dev');
    const primaryIp = String(body.primaryIp || '91.107.194.22');
    const secondaryIp = String(body.secondaryIp || '157.90.18.44');
    return jsonResponse({
      domain: dom,
      primaryIp,
      secondaryIp,
      consecutiveFailures: Number(body.consecutiveFailures) || 3,
      ttlSec: Number(body.ttlSec) || 60,
      strategy: 'active-passive-cloudflare-dns',
      summary: `Fail over ${dom} from ${primaryIp} → ${secondaryIp} after ${Number(body.consecutiveFailures) || 3} failed health probes (TTL ${Number(body.ttlSec) || 60}s).`,
      steps: [
        `1. Verify secondary origin ${secondaryIp} passes HTTPS /health probe with <300 ms latency`,
        `2. PATCH Cloudflare DNS A record for ${dom} -> ${secondaryIp} (TTL ${Number(body.ttlSec) || 60}s, proxied)`,
        `3. Emit audit-chained failover event & open public status timeline note`,
      ],
    });
  }
  if (pathname.match(/^\/api\/projects\/[^/]+\/sync\/status$/)) {
    return jsonResponse({
      projectId: pathname.split('/')[3],
      targetDir: '/srv/apps/acme-saas-web',
      connectedClients: 1,
      lastSeq: 42,
      framesApplied: 42,
      filesWritten: 58,
      filesDeleted: 3,
      dedupSkipped: 19,
      bytesSynced: 284120,
      rollbacksCount: 0,
      driftDetected: false,
      lastPath: 'src/app/page.tsx',
      lastReason: 'merkle_delta',
      lastAppliedAt: nowIso(-12000),
      lastApplyMs: 1.41,
      historyDepth: 42,
      wireStats: { rawBytes: 284120, wireBytes: 11080, savedPct: 96.1, codec: 'br' },
      latencyMs: { samples: 42, p50: 1.41, p95: 2.85, p99: 4.12 },
    });
  }

  // --- SmartPack & DirectPush ---
  if (pathname === '/api/build/smartpack/plan' && method === 'POST') {
    return jsonResponse(buildDemoSmartPackPlan(body.projectId));
  }
  if (pathname === '/api/deploy/direct-push/plan' && method === 'POST') {
    const img = String(body.image || 'my-app:latest');
    const serverId = String(body.serverId || 'srv_eu_edge_01');
    const sshHost = String(body.sshHost || '198.51.100.42');
    const sshUser = String(body.sshUser || 'deploy');
    const sshPort = Number(body.sshPort || 22);
    const localPort = Number(body.localPort || 5055);
    const cleanRepo = img.split(':')[0].toLowerCase().replace(/[^a-z0-9._/-]/g, '-') || 'app';
    const tag = img.includes(':') ? img.split(':').pop() || 'latest' : 'latest';
    const targetRef = `127.0.0.1:${localPort}/${cleanRepo}:${tag}`;
    return jsonResponse({
      schemaVersion: 'culkibo.directpush/v1',
      protocol: 'oci-distribution-v2',
      zeroRegistryRequired: true,
      deltaTransfer: true,
      shell: false,
      direction: 'push',
      serverId,
      sourceImage: img,
      repository: cleanRepo,
      tag,
      targetImageRef: targetRef,
      tunnel: { sshHost, sshUser, sshPort, localPort, remotePort: localPort, loopbackOnly: true, forwardFlag: '-L' },
      steps: [
        { step: 1, id: 'open_ssh_tunnel', description: `Forward local 127.0.0.1:${localPort} -> remote ${sshHost} 127.0.0.1:${localPort} over SSH`, bin: 'ssh', argv: ['-N', '-T', '-p', String(sshPort), '-o', 'BatchMode=yes', '-L', `127.0.0.1:${localPort}:127.0.0.1:${localPort}`, `${sshUser}@${sshHost}`], shell: false, skippedForLocal: serverId === 'local' },
        { step: 2, id: 'tag_loopback_ref', description: `Tag ${img} as ${targetRef} for loopback OCI v2 transfer`, bin: 'docker', argv: ['tag', img, targetRef], shell: false },
        { step: 3, id: 'oci_delta_push', description: `Push ONLY missing SHA-256 layers to ${targetRef} (existing layers skipped via HEAD /v2/.../blobs/:digest)`, bin: 'docker', argv: ['push', targetRef], shell: false },
      ],
    });
  }

  // --- Domains, Ingress, EdgeTunnel, DNS-01, HTTP/3 ---
  if (pathname === '/api/domains' && method === 'GET') {
    return jsonResponse({ domains: s.domains });
  }
  if (pathname === '/api/certificates' && method === 'GET') {
    return jsonResponse({ certificates: [] });
  }
  if (pathname === '/api/ingress/status') {
    const tlsList = s.domains.map((d) => ({ hostname: d.hostname, ...d.tls }));
    return jsonResponse({
      available: true,
      inSync: true,
      version: 'v2.11.1',
      adminUrl: '127.0.0.1:2019',
      message: 'Caddy HTTP/3 (QUIC) reverse proxy synchronized with 4 published HTTPS routes.',
      routesManaged: s.domains.length,
      drift: { missing: [], unexpected: [], modified: [] },
      routes: s.domains.map((d) => ({ host: d.hostname, hosts: [d.hostname], upstreams: [`127.0.0.1:${d.targetPort}`] })),
      skipped: [],
      tls: tlsList,
      tlsProbes: tlsList,
    });
  }
  if (pathname === '/api/ingress/capabilities') {
    return jsonResponse({ hasCloudflareDnsPlugin: true, acmeEmail: 'ops@acme-demo.dev', wildcardPolicies: [{ rootDomain: 'acme-demo.dev', includeApex: true }] });
  }
  if (pathname === '/api/ingress/http3') {
    return jsonResponse({ supported: true, configured: true, protocols: ['h1', 'h2', 'h3'], automaticHttpsDisabled: false, udp443Published: true, listen: [':443'], reason: null });
  }
  if (pathname === '/api/ingress/dns-providers') {
    return jsonResponse({
      providers: [
        { id: 'cloudflare', label: 'Cloudflare', caddyModule: 'dns.providers.cloudflare', xcaddyModule: 'github.com/caddy-dns/cloudflare', fields: [] },
        { id: 'route53', label: 'AWS Route53', caddyModule: 'dns.providers.route53', xcaddyModule: 'github.com/caddy-dns/route53', fields: [] },
        { id: 'digitalocean', label: 'DigitalOcean', caddyModule: 'dns.providers.digitalocean', xcaddyModule: 'github.com/caddy-dns/digitalocean', fields: [] },
        { id: 'hetzner', label: 'Hetzner DNS', caddyModule: 'dns.providers.hetzner', xcaddyModule: 'github.com/caddy-dns/hetzner', fields: [] },
        { id: 'porkbun', label: 'Porkbun', caddyModule: 'dns.providers.porkbun', xcaddyModule: 'github.com/caddy-dns/porkbun', fields: [] },
        { id: 'duckdns', label: 'DuckDNS', caddyModule: 'dns.providers.duckdns', xcaddyModule: 'github.com/caddy-dns/duckdns', fields: [] },
        { id: 'desec', label: 'deSEC', caddyModule: 'dns.providers.desec', xcaddyModule: 'github.com/caddy-dns/desec', fields: [] },
      ],
    });
  }
  if (pathname === '/api/edge-tunnel/status' && method === 'GET') {
    const active = s.tunnels.filter((t) => !t.revoked);
    return jsonResponse({
      enabled: true,
      protocol: 'culkibo-edgetunnel/v1',
      totalTunnels: s.tunnels.length,
      activeTunnels: active.length,
      connectedTunnels: active.filter((t) => t.connected).length,
      activeStreams: 3,
      totalRequestsForwarded: 1842,
      tunnels: s.tunnels,
    });
  }
  if (pathname === '/api/edge-tunnel/tunnels' && method === 'POST') {
    const id = `tun_demo_${Math.random().toString(36).slice(2, 8)}`;
    const token = `cket_demo_${Math.random().toString(36).slice(2, 18)}`;
    const rec = {
      id,
      name: String(body.name || `tunnel-${body.targetPort || 3000}`),
      targetHost: String(body.targetHost || '127.0.0.1'),
      targetPort: Number(body.targetPort || 3000),
      hostname: body.hostname || null,
      tokenPreview: `${token.slice(0, 9)}…${token.slice(-4)}`,
      revoked: false,
      status: 'offline',
      connected: false,
      activeStreams: 0,
      createdAt: nowIso(),
      updatedAt: nowIso(),
    };
    s.tunnels = [rec, ...s.tunnels];
    return jsonResponse({ ...rec, token }, 201);
  }
  const revokeTunMatch = pathname.match(/^\/api\/edge-tunnel\/tunnels\/([^/]+)$/);
  if (revokeTunMatch && method === 'DELETE') {
    const id = decodeURIComponent(revokeTunMatch[1]);
    s.tunnels = s.tunnels.map((t) => (t.id === id ? { ...t, revoked: true, connected: false, status: 'revoked' } : t));
    return jsonResponse({ revoked: true, id });
  }

  // --- Databases ---
  if (pathname === '/api/databases' && method === 'GET') {
    return jsonResponse({ databases: s.databases });
  }
  if (pathname === '/api/databases/docker-status') {
    return jsonResponse({ available: true, version: '27.5.1', running: true });
  }
  if (pathname === '/api/databases/storage') {
    return jsonResponse({ configured: false });
  }

  // --- Catalog ---
  if (pathname === '/api/services/catalog' || pathname === '/api/catalog') {
    const catMap = new Map<string, { id: string; label: string; count: number }>();
    for (const tpl of DEMO_CATALOG_TEMPLATES) {
      const existing = catMap.get(tpl.categoryId);
      if (existing) existing.count += 1;
      else catMap.set(tpl.categoryId, { id: tpl.categoryId, label: tpl.categoryLabel, count: 1 });
    }
    return jsonResponse({
      templates: DEMO_CATALOG_TEMPLATES,
      categories: Array.from(catMap.values()),
      dockerAvailable: true,
    });
  }
  if (pathname === '/api/services/installed' || pathname === '/api/services/installations') {
    return jsonResponse({ installations: s.installations });
  }

  // --- Fleet & SSH Keys ---
  if (pathname === '/api/servers' && method === 'GET') {
    return jsonResponse({ servers: s.servers });
  }
  if (pathname === '/api/fleet/keys' && method === 'GET') {
    return jsonResponse({ keys: s.sshKeys });
  }
  if (pathname.match(/^\/api\/servers\/[^/]+\/probe$/)) {
    const sid = decodeURIComponent(pathname.split('/')[3] || '');
    const srv = s.servers.find((x) => x.id === sid) || s.servers[0];
    return jsonResponse({ server: srv, probe: srv.probe, status: 'online' });
  }

  // --- Observability, Metrics, Doctor, Alerts, Topology, OTLP ---
  if (pathname === '/api/observability/snapshot' || pathname === '/api/observability') {
    const now = Date.now();
    const pts = Array.from({ length: 24 }, (_, idx) => ({
      ts: now - (23 - idx) * 15000,
      hostCpuPct: Number((3.8 + Math.sin(idx * 0.5) * 1.4).toFixed(1)),
      hostRamPct: Number((37.4 + Math.cos(idx * 0.3) * 0.8).toFixed(1)),
      diskUsedPct: 24,
      errorRatePct: 0,
      p95Ms: Number((2.2 + Math.sin(idx * 0.4) * 0.4).toFixed(2)),
      rps: Number((138 + Math.sin(idx * 0.6) * 16).toFixed(1)),
      rssMb: 51,
      elLagMs: Number((0.4 + Math.abs(Math.sin(idx)) * 0.3).toFixed(2)),
    }));
    return jsonResponse({
      bootMs: 146,
      uptimeSeconds: 184200,
      process: {
        cpuPercent: 0.4,
        hostCpuPercent: 4.2,
        hostCpus: 4,
        loadAvg: [0.42, 0.38, 0.31],
        memoryMb: 51,
        heapUsedMb: 24,
        hostMemoryTotalMb: 8192,
        hostMemoryUsedMb: 3112,
        hostMemoryAvailableMb: 5080,
        hostMemoryUsedPct: 38,
        hostMemorySource: 'proc_meminfo',
        diskUsedPct: 24,
        diskFreeGb: 121.6,
        diskTotalGb: 160,
        nodeVersion: 'v22.14.0',
        uptimeSeconds: 184200,
      },
      http: {
        requestsTotal: 482910,
        inFlight: 2,
        errorRatePct: 0,
        error5xxRatePct: 0,
        status: { '2xx': 482890, '4xx': 20, '5xx': 0 },
        latencyMs: { p50: 1.4, p95: 2.4, p99: 4.8 },
        rps: { rps1s: 148.2, rps10s: 142.8, rps60s: 136.4 },
        topRoutes: [
          { route: 'GET /api/projects', count: 12840, avgMs: 1.2, errors: 0 },
          { route: 'GET /api/observability/topology', count: 6420, avgMs: 1.8, errors: 0 },
          { route: 'POST /api/mcp', count: 4910, avgMs: 2.1, errors: 0 },
        ],
      },
      eventLoop: { p95Ms: 0.5, utilizationRatio: 0.018 },
      websocket: { telemetryClients: 1, syncClients: 1 },
      liveSync: { framesApplied: 42, bytesSynced: 284120, applyLatencyMs: { p50: 1.41, p95: 2.85 } },
      caddy: { managedRoutes: s.domains.length, swapsTotal: 19, swapLatencyMs: { p50: 3.1 } },
      history: pts,
    });
  }
  if (pathname === '/api/observability/history' || pathname === '/api/observability/metrics/history') {
    const now = Date.now();
    const points = Array.from({ length: 30 }, (_, idx) => ({
      ts: now - (29 - idx) * 60000 * 10,
      hostCpuPct: Number((4.0 + Math.sin(idx * 0.4) * 1.8).toFixed(1)),
      hostRamPct: Number((37.5 + Math.cos(idx * 0.25) * 1.1).toFixed(1)),
      diskUsedPct: 24,
      errorRatePct: 0,
      p95Ms: Number((2.3 + Math.sin(idx * 0.5) * 0.5).toFixed(2)),
      rps: Number((140 + Math.sin(idx * 0.35) * 20).toFixed(1)),
      rssMb: 51,
      elLagMs: 0.5,
    }));
    return jsonResponse({
      points,
      series: [{ metric: 'host_cpu_pct', points: points.map((p) => ({ ts: p.ts, value: p.hostCpuPct })) }],
      markers: [{ ts: now - 1000 * 60 * 14, projectId: 'proj_acme_web', projectName: 'acme-saas-web', status: 'activo', label: 'v1.2.0' }],
    });
  }
  if (pathname === '/api/topology' || pathname === '/api/observability/topology') {
    return jsonResponse(buildDemoTopology());
  }
  if (pathname === '/api/observability/otlp') {
    if (method === 'PUT' || method === 'POST') {
      if (typeof body.enabled === 'boolean') s.otlp.enabled = body.enabled;
      if (typeof body.endpoint === 'string') s.otlp.endpoint = body.endpoint.trim();
      if (typeof body.serviceName === 'string' && body.serviceName.trim()) s.otlp.serviceName = body.serviceName.trim();
      if (body.headers && typeof body.headers === 'object' && Object.keys(body.headers).length > 0) {
        s.otlp.hasAuthHeader = true;
      }
      return jsonResponse(s.otlp);
    }
    return jsonResponse(s.otlp);
  }
  if (pathname === '/api/observability/otlp/flush' && method === 'POST') {
    const flushed = s.otlp.bufferedSpans;
    s.otlp.totalExported += flushed;
    s.otlp.bufferedSpans = 0;
    s.otlp.lastFlushAt = nowIso();
    return jsonResponse({ ok: true, flushed, status: s.otlp });
  }
  if (pathname === '/api/system/doctor' || pathname === '/api/observability/doctor') {
    return jsonResponse({
      overall: 'ok',
      durationMs: 18,
      summary: { ok: 8, warn: 0, fail: 0 },
      checks: [
        { id: 'node', title: 'Node.js Runtime', status: 'ok', detail: 'v22.14.0 LTS · 51 MB RSS' },
        { id: 'docker', title: 'Docker & BuildKit', status: 'ok', detail: 'Docker 27.5.1 · zstd:chunked ready' },
        { id: 'caddy', title: 'Caddy HTTP/3 Edge', status: 'ok', detail: 'v2.11.1 · 4 HTTPS routes synced' },
        { id: 'memory', title: 'Host MemAvailable', status: 'ok', detail: '5,080 MB available (62% free)' },
        { id: 'disk', title: 'Storage Headroom', status: 'ok', detail: '121.6 GB free (24% used)' },
        { id: 'security', title: 'Zero-Shell & SSRF Guard', status: 'ok', detail: '0 shell calls · Hash-chained audit valid' },
        { id: 'otlp', title: 'Native OTLP Exporter', status: 'ok', detail: 'Zero-dep gzip JSON · lowercase hex IDs' },
        { id: 'sbom', title: 'CycloneDX 1.6 & SLSA v1.1', status: 'ok', detail: 'Ed25519 DSSE signing ready' },
      ],
    });
  }
  if (pathname === '/api/alerts/rules' || pathname === '/api/observability/alerts/rules') {
    return jsonResponse({ rules: s.alertRules });
  }
  if (pathname === '/api/alerts/active' || pathname === '/api/observability/alerts/active') {
    return jsonResponse({ alerts: [] });
  }
  if (pathname === '/api/alerts/history' || pathname === '/api/observability/alerts/history') {
    return jsonResponse({ history: [], alerts: [] });
  }

  // --- Uptime, Status Pages & Cost Advisor ---
  if (pathname === '/api/uptime/monitors' && method === 'GET') {
    return jsonResponse({ monitors: s.monitors });
  }
  if (pathname === '/api/uptime/status-pages' && method === 'GET') {
    return jsonResponse({ pages: s.statusPages });
  }
  if (pathname === '/api/advisor/resources' || pathname === '/api/uptime/advisor') {
    return jsonResponse({
      vpsMonthlyEur: 12,
      costLedger: { monthlySavingsEur: 164, annualSavingsEur: 1968, saasAverageMonthlyEur: 176, vpsMonthlyEur: 12 },
      host: { freeMemMb: 5080, totalMemMb: 8192, freeMemPct: 62 },
      summary: { reclaimableRamMb: 384 },
      recommendations: [
        { id: 'rec_1', severity: 'info', title: 'Enable Scale-to-Zero on ai-worker-py during off-peak hours', detail: 'Reclaims ~384 MB RAM automatically with <800ms cold wake.', estimatedMonthlySavingsEur: 18, projectId: 'proj_ai_worker' },
      ],
    });
  }
  if (pathname === '/api/sleep/policies') {
    return jsonResponse({ policies: {} });
  }

  // --- MCP 2026-07-28 (125 tools + 13 prompts + 3 sandboxed MCP Apps) ---
  if (pathname === '/api/mcp/tools') {
    const coreTools = [
      { name: 'culkibo_ship_and_verify', description: 'Atomic ship with secret scan, SmartPack build, smoke check, and auto-rollback', readOnly: false, profile: 'core' },
      { name: 'culkibo_search_tools', description: 'Discover any of the 125 MCP tools on demand without bloating context (-84%)', readOnly: true, profile: 'core' },
      { name: 'culkibo_list_projects', description: 'List projects, live status, domains, and linked databases', readOnly: true, profile: 'core' },
      { name: 'culkibo_smartpack_plan', description: 'Generate deterministic SmartPack build plan across 18 stacks', readOnly: true, profile: 'core' },
      { name: 'culkibo_diagnose_incident', description: 'Correlate OOMKilled, CrashLoop, logs, and uptime telemetry', readOnly: true, profile: 'core' },
      { name: 'culkibo_auto_remediate', description: '2-phase safe remediation (dryRun -> HMAC confirmToken)', readOnly: false, profile: 'core' },
      { name: 'culkibo_migrate_coolify', description: 'Zero-downtime Coolify v4 migration with 100% parity diff', readOnly: false, profile: 'core' },
      { name: 'culkibo_triage_playbook', description: 'Autonomous multi-signal triage chaining incidents, Build Healer, Drift Check & SBOM CVE scan', readOnly: true, profile: 'ops' },
      { name: 'culkibo_cve_scan', description: 'Scan CycloneDX 1.6 SBOM against OSV.dev batch API with 24h cache & offline fallback', readOnly: true, profile: 'security' },
      { name: 'culkibo_drift_check', description: 'Detect live container/DB config drift vs declared state & generate PgBouncer smart pool presets', readOnly: true, profile: 'ops' },
      { name: 'culkibo_export_iac', description: 'Export zero lock-in OpenTofu/Terraform HCL + portable Compose with 0 plaintext secrets', readOnly: true, profile: 'deploy' },
      { name: 'culkibo_secret_lease', description: 'Manage ephemeral secret leases, 90d rotation audits & audited 15m Break-Glass escalation', readOnly: false, profile: 'security' },
      { name: 'culkibo_heal_build_failure', description: 'Deterministic 20-pattern build/runtime root-cause classifier & safe dry-run auto-healer', readOnly: false, profile: 'deploy' },
      { name: 'culkibo_fleet_mesh', description: 'Zero-config WireGuard x25519 fleet mesh status, wg0.conf plan, and key rotation', readOnly: false, profile: 'ops' },
      { name: 'culkibo_cron_timeline', description: '24h cron collision heatmap and Dead-Man’s-Switch heartbeats status', readOnly: true, profile: 'ops' },
      { name: 'culkibo_edge_shield', description: 'Caddy native Edge Bot-Shield & SHA-256 Hashcash PoW gate controls', readOnly: false, profile: 'security' },
      { name: 'culkibo_verify_attestation', description: 'Verify SLSA v1.1 Ed25519 DSSE release attestation', readOnly: true, profile: 'security' },
    ];
    const generated = Array.from({ length: 125 - coreTools.length }, (_, i) => ({
      name: `culkibo_ops_tool_${i + coreTools.length + 1}`,
      description: `Managed PaaS control-plane operation #${i + coreTools.length + 1} (RBAC + audit-chained)`,
      readOnly: i % 2 === 0,
      profile: i % 3 === 0 ? 'deploy' : i % 3 === 1 ? 'ops' : 'security',
    }));
    return jsonResponse({ tools: [...coreTools, ...generated], total: 125, coreCount: 17 });
  }
  if (pathname === '/api/mcp/audit') {
    return jsonResponse({
      auditLog: [
        { id: 'aud_1', toolName: 'culkibo_triage_playbook', status: 'ok', durationMs: 4, timestamp: nowIso(-60000), client: 'claude-code' },
        { id: 'aud_2', toolName: 'culkibo_export_iac', status: 'ok', durationMs: 2, timestamp: nowIso(-180000), client: 'antigravity' },
      ],
    });
  }
  if (pathname === '/api/mcp/config') {
    return jsonResponse({
      protocol: { version: '2026-07-28', transport: 'streamable-http', endpoint: `${parsed.origin}/api/mcp` },
      totalTools: 125,
      profiles: { core: { count: 17, savedPct: 84 } },
    });
  }
  if (pathname === '/api/mcp' && method === 'POST') {
    const rpcMethod = String(body.method || '');
    if (rpcMethod === 'resources/list') {
      return jsonResponse({
        jsonrpc: '2.0',
        id: body.id || 1,
        result: {
          resources: [
            { uri: 'ui://culkibo/topology', name: 'Culkibo Live Topology App', title: 'Interactive Service, DB, Domain & Fleet Topology', description: 'Live interactive map of domains, projects, databases, and SSH fleet.', mimeType: 'text/html;profile=mcp-app' },
            { uri: 'ui://culkibo/incident-remediator', name: 'Culkibo Incident Remediator App', title: 'Live OOM/Crash Diagnostics & 2-Phase Safe Remediator', description: 'Correlates OOMKilled, CrashLoop, logs, and uptime with 2-phase remediation.', mimeType: 'text/html;profile=mcp-app' },
            { uri: 'ui://culkibo/coolify-migration-diff', name: 'Culkibo Coolify v4 Migration Diff App', title: 'Coolify v4 Parity Score & Traefik → Caddy Edge Diff', description: 'Visualizes Coolify v4 Parity Score, redacted Magic Vars, and Traefik → Caddy edge diff.', mimeType: 'text/html;profile=mcp-app' },
          ],
        },
      });
    }
    if (rpcMethod === 'resources/read') {
      const uri = String(body.params?.uri || 'ui://culkibo/topology');
      return jsonResponse({
        jsonrpc: '2.0',
        id: body.id || 1,
        result: {
          contents: [{ uri, mimeType: 'text/html;profile=mcp-app', text: DEMO_MCP_APPS_HTML[uri] || DEMO_MCP_APPS_HTML['ui://culkibo/topology'] }],
        },
      });
    }
    if (rpcMethod === 'prompts/list') {
      return jsonResponse({
        jsonrpc: '2.0',
        id: body.id || 1,
        result: {
          prompts: [
            { name: 'ship_safely', title: 'Ship & Verify Release', description: 'Run SmartPack plan, secret scan, zero-downtime deploy, and smoke verification.' },
            { name: 'migrate_coolify_v4', title: 'Migrate Coolify v4 Estate', description: 'Compute 100% parity plan, translate Traefik labels to Caddy, and stream DBs safely.' },
            { name: 'triage_production_incident', title: 'Triage Production Incident', description: 'Correlate metrics, OTLP traces, and container logs with 2-phase remediation.' },
          ],
        },
      });
    }
    return jsonResponse({
      jsonrpc: '2.0',
      id: body.id || 1,
      result: {
        ok: true,
        sandbox: true,
        tool: body.params?.name || rpcMethod,
        content: [{ type: 'text', text: JSON.stringify({ status: 'ok', sandbox: true, message: 'Executed safely in Culkibo Interactive Sandbox' }, null, 2) }],
      },
    });
  }

  // --- Coolify v4 Importer ---
  if (pathname === '/api/import/coolify/plan' || pathname === '/api/import/coolify/test' || pathname === '/api/import/coolify/fetch') {
    return jsonResponse({ ok: true, connected: true, plan: buildDemoCoolifyPlan(), ...buildDemoCoolifyPlan() });
  }
  if (pathname === '/api/import/coolify/stream-plan') {
    return jsonResponse({
      ok: true,
      zeroShell: true,
      schemaVersion: 'culkibo.coolify-stream/v1',
      totalStreams: 2,
      databases: [
        { name: 'acme-postgres-16', engine: 'postgresql', command: 'ssh -o BatchMode=yes root@source-vps docker exec acme-postgres-16 pg_dump -Fc -U acme acme_prod | docker exec -i culkibo-pg pg_restore -d acme_prod', sha256Verify: true },
      ],
      volumes: [
        { name: 'acme_uploads', command: 'ssh -o BatchMode=yes root@source-vps docker run --rm -v acme_uploads:/src alpine tar -czf - -C /src . | docker run --rm -i -v acme_uploads:/dst alpine tar -xzf - -C /dst', sha256Verify: true },
      ],
      warnings: [],
    });
  }

  // --- Security v1.1, Remote Access, Team, GitOps, Backups, Notifications & Settings ---
  if (pathname === '/api/system/remote-access') {
    return jsonResponse({
      panelDomain: 'panel.acme-demo.dev',
      currentOrigin: parsed.origin,
      recommendedUrl: 'https://panel.acme-demo.dev',
      serverIp: '91.107.194.22',
      auth: {
        authenticated: true,
        method: 'sandbox',
        requireTokenAlways: true,
        tokenConfigured: true,
        tokenSource: 'data/auth.json',
        allowedOrigins: [parsed.origin, 'https://panel.acme-demo.dev'],
      },
      caddy: { available: true, adminUrl: '127.0.0.1:2019', version: 'v2.11.1', reason: null },
      cloudflare: { isConfigured: false, hasApiToken: false, accountId: null, tokenMasked: null, useMock: false },
      tunnels: [],
      tunnelsMock: false,
      clientConfigs: {},
      cliUpdateCommand: 'culkibo config set apiUrl https://panel.acme-demo.dev',
    });
  }
  if (pathname === '/api/auth/me') {
    return jsonResponse({
      isSuperAdmin: true,
      kind: 'session',
      userId: 'usr_owner',
      email: 'owner@acme-demo.dev',
      name: 'Acme Platform Owner',
      role: 'owner',
      teamId: 'team_default',
      scopes: ['*'],
      projectIds: null,
      multiUserEnabled: true,
      usersCount: 2,
      teamsCount: 1,
    });
  }
  if (pathname === '/api/teams') {
    return jsonResponse({ teams: [{ id: 'team_default', name: 'Acme Platform', slug: 'acme-platform', role: 'owner', membersCount: 2 }] });
  }
  if (pathname.match(/^\/api\/teams\/[^/]+\/members$/)) {
    return jsonResponse({
      members: [
        { id: 'usr_owner', userId: 'usr_owner', email: 'owner@acme-demo.dev', name: 'Acme Owner', role: 'owner', createdAt: nowIso(-1000 * 60 * 60 * 240) },
        { id: 'usr_dev', userId: 'usr_dev', email: 'dev@acme-demo.dev', name: 'Lead Engineer', role: 'developer', createdAt: nowIso(-1000 * 60 * 60 * 120) },
      ],
      invites: [],
    });
  }
  if (pathname.match(/^\/api\/teams\/[^/]+\/invites$/)) {
    return jsonResponse({ invites: [] });
  }
  if (pathname === '/api/auth/tokens') {
    return jsonResponse({ tokens: [] });
  }
  if (pathname === '/api/vault') {
    return jsonResponse({
      secrets: [
        { key: 'STRIPE_SECRET_KEY', scope: 'runtime', description: 'Production Stripe billing secret', updatedAt: nowIso(-1000 * 60 * 60 * 48) },
      ],
    });
  }
  if (pathname === '/api/gitops/drift') {
    return jsonResponse({ inSync: true, drifted: false, hasDrift: false, drifts: [], summary: { create: 0, update: 0, delete: 0 } });
  }
  if (pathname === '/api/gitops/export' && method === 'POST') {
    return jsonResponse({ yaml: 'version: 1\nprojects:\n  - name: acme-saas-web\n    branch: main\n', manifestHash: 'sha256:demo1234' });
  }
  if (pathname.match(/^\/api\/projects\/[^/]+\/environments$/)) {
    return jsonResponse({ environments: [{ name: 'production', branch: 'main', varsCount: 5 }, { name: 'staging', branch: 'staging', varsCount: 4 }] });
  }
  if (pathname === '/api/backup/list') {
    return jsonResponse({ backups: [] });
  }
  if (pathname === '/api/databases/storage') {
    return jsonResponse({ configured: false });
  }
  if (pathname === '/api/databases/storage/objects') {
    return jsonResponse({ objects: [] });
  }
  if (pathname === '/api/security/secrets/scan' && method === 'POST') {
    const txt = String(body.text || '');
    const findings: any[] = [];
    if (/AKIA[0-9A-Z]{16}|sk_live_|ghp_/i.test(txt)) {
      findings.push({ ruleId: 'secret-token', severity: 'critical', title: 'High-confidence API credential detected', line: 1, source: 'input', preview: '••••••', remediation: 'Move credential into Culkibo AES-256-GCM Vault (${vault.KEY}).' });
    }
    return jsonResponse({ clean: findings.length === 0, summary: { total: findings.length, critical: findings.length, high: 0, medium: 0, low: 0 }, findings });
  }
  if (pathname === '/api/security/audit-log/verify') {
    return jsonResponse({ valid: true, checkedCount: 48, filesChecked: ['audit-2026-11.jsonl'], anchored: true, firstSeq: 1, lastSeq: 48, headHash: 'sha256:9f84b2c1e0d3a7f6543210fedcba9876', brokenAtSeq: null, brokenAtLine: null, brokenFile: null, reason: null });
  }
  if (pathname === '/api/security/audit-log' || pathname === '/api/system/audit' || pathname === '/api/audit') {
    const list = [
      { id: 'ev_1', seq: 48, source: 'deploy', action: 'deploy.promoted', target: 'acme-saas-web', entryHash: '9f84b2c1e0d3a7f6', timestamp: nowIso(-1000 * 60 * 14) },
      { id: 'ev_2', seq: 47, source: 'ingress', action: 'tls.verified', target: 'app.acme-demo.dev', entryHash: '7a3c19e4b2d80f12', timestamp: nowIso(-1000 * 60 * 35) },
    ];
    return jsonResponse({ entries: list, events: list });
  }
  if (pathname === '/api/auth/oidc/providers') {
    return jsonResponse({ providers: [{ id: 'oidc_demo', type: 'oidc', protocol: 'OIDC PKCE S256', name: 'Authentik / Okta SSO', enabled: true, issuerUrl: 'https://sso.acme-demo.dev', defaultRole: 'developer' }] });
  }
  if (pathname === '/api/notifications/config') {
    return jsonResponse({
      enabled: true,
      events: { deploy_failed: true, deploy_succeeded: true, service_down: true, ssl_issued: true, tls_expiring: true, project_stopped: false },
      channels: {
        telegram: { enabled: false, botToken: '', chatId: '', configured: false },
        discord: { enabled: false, webhookUrl: '', configured: false },
        slack: { enabled: false, webhookUrl: '', configured: false },
        webhook: { enabled: false, url: '', configured: false },
      },
    });
  }
  if (pathname === '/api/notifications/history') {
    return jsonResponse({ notifications: [] });
  }
  if (pathname === '/api/telemetry/status') {
    return jsonResponse({ enabled: false, persistedEnabled: false, lockedByEnv: false, instanceId: 'sandbox-ephemeral-0000' });
  }
  if (pathname === '/api/github/status') {
    return jsonResponse({ connected: true, username: 'acme-labs', scopes: ['repo', 'admin:repo_hook'] });
  }
  if (pathname === '/api/cloudflare/config') {
    return jsonResponse({ isConfigured: false });
  }

  // Safe default for any other sandbox route
  return jsonResponse({ ok: true, demo: true });
}
