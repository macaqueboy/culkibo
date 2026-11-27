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
  brand: {
    brandName: string;
    tagline: string;
    accentHex: string;
    logoUrl: string;
    supportUrl: string;
    hidePoweredBy: boolean;
    updatedAt: string | null;
  };
  webhookSubscriptions: any[];
  webhookDlq: any[];
  quotas: Record<string, { projectId: string; containers: number; memoryMb: number; cpuCores: number; storageGb: number; bandwidthGbMo: number }>;
  drDrills: any[];
  sloCanaries: Record<string, any[]>;
  remoteBuilders: any[];
  admissionPolicy: {
    preset: string;
    rules: Record<string, string>;
    updatedAt: string;
  };
  latestComplianceBundle: any;
  edgeExperiments: any[];
  volumeMigrations: any[];
  syntheticFlows: any[];
  autoscalerPolicies: Record<string, any>;
  cronLeases: Record<string, any[]>;
  oncallPolicies: any[];
  oncallIncidents: any[];
  replicaTopologies: Record<string, any>;
  chaosGameDays: Record<string, any[]>;
  mtlsCerts: any[];
  rateLimitPolicies: any[];
  featureFlags: any[];
  runtimeAnomalies: Record<string, any[]>;
  digestPromotions: Record<string, any[]>;
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
        engineLabel: 'PostgreSQL 16',
        version: '16-alpine',
        image: 'postgres:16-alpine',
        status: 'running',
        health: 'healthy',
        containerName: 'culkibo-db-pg-main',
        networkName: 'culkibo-net-proj-acme-web',
        connectionTemplate: 'postgresql://acme:••••••••@culkibo-db-pg-main:5432/acme_prod',
        host: '127.0.0.1',
        port: 5432,
        internalHost: 'culkibo-db-pg-main',
        internalPort: 5432,
        databaseName: 'acme_prod',
        username: 'acme',
        memoryMb: 512,
        memoryLimitMb: 512,
        cpus: 1,
        cpuLimit: 1,
        publicExposure: false,
        exposure: { enabled: false, bindAddress: '127.0.0.1', hostPort: null },
        schedule: { enabled: true, cron: '0 3 * * *', nextRunAt: nowIso(1000 * 60 * 60 * 8), lastRunAt: t3, lastStatus: 'ok' },
        retention: { hourly: 6, daily: 7, weekly: 4 },
        backupsCount: 2,
        createdAt: t3,
      },
      {
        id: 'db_valkey_cache',
        name: 'acme-valkey-8',
        engine: 'valkey',
        engineLabel: 'Valkey 8 (Redis)',
        version: '8-alpine',
        image: 'valkey/valkey:8-alpine',
        status: 'running',
        health: 'healthy',
        containerName: 'culkibo-db-valkey',
        networkName: 'culkibo-net-proj-acme-web',
        connectionTemplate: 'redis://:••••••••@culkibo-db-valkey:6379/0',
        host: '127.0.0.1',
        port: 6379,
        internalHost: 'culkibo-db-valkey',
        internalPort: 6379,
        databaseName: '0',
        username: 'default',
        memoryMb: 256,
        memoryLimitMb: 256,
        cpus: 0.5,
        cpuLimit: 0.5,
        publicExposure: false,
        exposure: { enabled: false, bindAddress: '127.0.0.1', hostPort: null },
        schedule: { enabled: false, cron: '0 4 * * 0', nextRunAt: null, lastRunAt: null, lastStatus: null },
        retention: { hourly: 0, daily: 7, weekly: 4 },
        backupsCount: 1,
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
    brand: {
      brandName: 'Culkibo',
      tagline: 'Ultra-lightweight self-hosted PaaS',
      accentHex: '#6366f1',
      logoUrl: '',
      supportUrl: 'https://status.acme-demo.dev',
      hidePoweredBy: false,
      updatedAt: t2,
    },
    webhookSubscriptions: [
      {
        id: 'whsub_deploy_prod',
        url: 'https://hooks.acme-demo.dev/culkibo/events',
        events: ['deploy.succeeded', 'deploy.failed', 'backup.verified', 'cve.detected'],
        description: 'Production Release & Security Event Bus',
        enabled: true,
        secretPreview: 'whsec_9kF2••••••••8mQ1',
        hasSecondarySecret: false,
        secondaryExpiresAt: null,
        createdAt: t3,
        updatedAt: t1,
      },
      {
        id: 'whsub_billing_erp',
        url: 'https://billing.acme-demo.dev/webhooks/usage',
        events: ['quota.threshold', 'billing.snapshot'],
        description: 'Agency Client ERP Metering Sink',
        enabled: true,
        secretPreview: 'whsec_4xP7••••••••2nR9',
        hasSecondarySecret: true,
        secondaryExpiresAt: nowIso(1000 * 60 * 60 * 18),
        createdAt: t3,
        updatedAt: t2,
      },
    ],
    webhookDlq: [
      {
        id: 'dlq_demo_001',
        subscriptionId: 'whsub_deploy_prod',
        url: 'https://hooks.acme-demo.dev/culkibo/events',
        eventType: 'deploy.succeeded',
        status: 'failed',
        attempts: 2,
        httpStatus: 503,
        lastStatusCode: 503,
        lastError: 'Upstream returned HTTP 503 Service Unavailable (retry window exhausted)',
        createdAt: t1,
        replayedAt: null,
      },
    ],
    quotas: {
      proj_acme_web: { projectId: 'proj_acme_web', containers: 4, memoryMb: 1024, cpuCores: 2, storageGb: 25, bandwidthGbMo: 250 },
      proj_edge_rust: { projectId: 'proj_edge_rust', containers: 2, memoryMb: 512, cpuCores: 1, storageGb: 10, bandwidthGbMo: 200 },
      proj_ai_worker: { projectId: 'proj_ai_worker', containers: 2, memoryMb: 1024, cpuCores: 2, storageGb: 20, bandwidthGbMo: 100 },
    },
    drDrills: [
      {
        id: 'drill_demo_pg_01',
        databaseId: 'db_pg_main',
        projectId: 'proj_acme_web',
        engine: 'postgres',
        verdict: 'PASS',
        rtoMs: 312,
        rpoSec: 1800,
        bytesVerified: 18420112,
        uncompressedBytes: 74910208,
        sha256: '4e9a2c71f8b03d5e6a1c9f0b2d4e8a7c1f3b5d9e0a2c4f6a8b1d3e5f7a9c0b1d',
        aclPreserved: true,
        checks: [
          { name: 'min_bytes', passed: true, detail: '18.4 MB compressed (> 64 B threshold)' },
          { name: 'sha256_integrity', passed: true, detail: 'SHA-256 digest verified' },
          { name: 'gunzip_stream', passed: true, detail: 'Valid gzip stream decompressed (74.9 MB)' },
          { name: 'sql_ddl_and_acl', passed: true, detail: 'PostgreSQL dump + GRANT ACLs preserved' },
        ],
        warnings: [],
        errors: [],
        createdAt: t2,
      },
    ],
    sloCanaries: {},
    remoteBuilders: [
      {
        id: 'bld_hetzner_amd64',
        name: 'hetzner-cpx41-builder-eu',
        host: '91.107.194.44',
        arch: 'linux/amd64',
        maxConcurrency: 4,
        activeBuilds: 1,
        allowPreviews: true,
        keepStorageGb: 40,
        sshMuxPinned: true,
        status: 'ready',
      },
      {
        id: 'bld_hetzner_arm64',
        name: 'hetzner-cax21-arm64-eu',
        host: '91.107.194.88',
        arch: 'linux/arm64',
        maxConcurrency: 2,
        activeBuilds: 0,
        allowPreviews: true,
        keepStorageGb: 25,
        sshMuxPinned: false,
        status: 'ready',
      },
    ],
    admissionPolicy: {
      preset: 'restricted',
      rules: {
        no_privileged: 'enforce',
        no_docker_sock_mount: 'enforce',
        no_host_root_mount: 'enforce',
        no_dangerous_caps: 'enforce',
        no_latest_tag: 'enforce',
        require_non_root_uid: 'enforce',
        require_resource_limits: 'enforce',
        require_healthcheck: 'enforce',
        require_signed_attestation: 'audit',
        no_public_db_or_panel_bind: 'enforce',
      },
      updatedAt: t1,
    },
    latestComplianceBundle: {
      ok: true,
      algorithm: 'Ed25519',
      bundleId: 'cmp_demo_soc2_01',
      framework: 'all',
      generatedAt: t1,
      overallScore: 96,
      payloadSha256: 'c4f92e1a8b7d30654a2c9e8d10f7b1a5c3e9d01f2a4b6c8d0e1f2a3b4c5d6e7f',
      signatureB64: 'mN7pQ3rS6tU0vW2xY4zA8bC1dE3fG5hI9jK2lM4nO6pQ8rS0tU2vW4xY6zA8bC1dE3fG5hI9jK2lM4nO6pQ==',
      publicKeyPem: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEADEMOCulkiboComplianceEd25519PubKeyOnlyForSandbox==\n-----END PUBLIC KEY-----',
      payload: {
        schemaVersion: '1.0.0',
        bundleId: 'cmp_demo_soc2_01',
        framework: 'all',
        overallScore: 96,
        zeroPlaintextSecrets: true,
        generatedAt: t1,
        controls: [
          { domain: 'Access Control & Strong Authentication', controlIds: ['SOC2-CC6.1', 'ISO27001-A.5.15', 'GDPR-Art32'], status: 'pass', score: 100, summary: 'RBAC=ON, TOTP 2FA + FIDO2 Passkeys active (100% adoption).' },
          { domain: 'Encryption at Rest & Secret Isolation', controlIds: ['SOC2-CC6.7', 'ISO27001-A.8.24', 'GDPR-Art32'], status: 'pass', score: 100, summary: 'AES-256-GCM encrypted Vault with 0600 file modes (0 plaintext Postgres env storage).' },
          { domain: 'Tamper-Evident Audit Trail', controlIds: ['SOC2-CC7.2', 'ISO27001-A.8.15'], status: 'pass', score: 100, summary: 'SHA-256 hash-chained append-only audit log integrity VERIFIED.' },
          { domain: 'Supply-Chain & Vulnerability Management', controlIds: ['SOC2-CC7.1', 'ISO27001-A.8.8'], status: 'pass', score: 95, summary: 'CycloneDX 1.6 SBOM + SLSA v1.1 Ed25519 provenance; 0 critical CVEs.' },
          { domain: 'Change & Admission Governance', controlIds: ['SOC2-CC8.1', 'ISO27001-A.8.9'], status: 'pass', score: 100, summary: 'Policy-as-Code Admission preset="restricted", shell:false zero-shell enforced.' },
          { domain: 'Availability & Disaster Recovery Drills', controlIds: ['SOC2-A1.2', 'ISO27001-A.8.14', 'GDPR-Art32'], status: 'pass', score: 100, summary: 'DR Fire-Drills: 100% pass rate, latest RTO=312 ms, RPO=30m.' },
        ],
      },
      markdownReport: [
        '# Culkibo Cryptographic Compliance Evidence Dossier',
        '',
        '- **Bundle ID:** `cmp_demo_soc2_01`',
        '- **Frameworks:** SOC 2 · ISO 27001 · GDPR',
        '- **Overall Score:** **96 / 100**',
        '- **Signature:** Ed25519 Verified · `0` plaintext secrets',
        '- **Payload SHA-256:** `c4f92e1a8b7d30654a2c9e8d10f7b1a5c3e9d01f2a4b6c8d0e1f2a3b4c5d6e7f`',
        '',
        '| Domain | Controls | Status | Score |',
        '|---|---|---|---|',
        '| Access Control & Strong Auth | SOC2-CC6.1, ISO27001-A.5.15, GDPR-Art32 | PASS | 100 |',
        '| Encryption at Rest (AES-256-GCM) | SOC2-CC6.7, ISO27001-A.8.24, GDPR-Art32 | PASS | 100 |',
        '| Tamper-Evident Audit Trail | SOC2-CC7.2, ISO27001-A.8.15 | PASS | 100 |',
        '| Supply-Chain & SBOM/SLSA | SOC2-CC7.1, ISO27001-A.8.8 | PASS | 95 |',
        '| Admission & Zero-Shell Governance | SOC2-CC8.1, ISO27001-A.8.9 | PASS | 100 |',
        '| Disaster Recovery Fire-Drills | SOC2-A1.2, ISO27001-A.8.14, GDPR-Art32 | PASS | 100 |',
      ].join('\n'),
    },
    edgeExperiments: [
      {
        id: 'exp_geo_eu_us',
        projectId: 'proj_acme_web',
        name: 'Global Geo-IP Edge Router',
        kind: 'geo',
        hostname: 'app.acme-demo.dev',
        headerName: 'CF-IPCountry',
        regions: [
          { countries: ['DE', 'FR', 'ES', 'NL'], upstream: '10.88.0.2:3000', label: 'eu-central' },
          { countries: ['US', 'CA'], upstream: '10.88.0.3:3000', label: 'us-east' },
        ],
        defaultUpstream: '127.0.0.1:3000',
        killed: false,
        compiledCaddy: {
          subroutes: [
            { match: [{ header: { 'CF-IPCountry': ['DE', 'FR', 'ES', 'NL'] } }], handle: [{ handler: 'reverse_proxy', upstreams: [{ dial: '10.88.0.2:3000' }] }], terminal: true },
            { match: [{ header: { 'CF-IPCountry': ['US', 'CA'] } }], handle: [{ handler: 'reverse_proxy', upstreams: [{ dial: '10.88.0.3:3000' }] }], terminal: true },
            { handle: [{ handler: 'reverse_proxy', upstreams: [{ dial: '127.0.0.1:3000' }] }] },
          ],
        },
        updatedAt: t1,
      },
      {
        id: 'exp_ab_checkout_v2',
        projectId: 'proj_acme_web',
        name: 'Sticky Checkout v2 A/B Split',
        kind: 'ab',
        hostname: 'app.acme-demo.dev',
        stickyMode: 'cookie',
        cookieName: 'ckb_ab_checkout',
        variants: [
          { name: 'control', upstream: '127.0.0.1:3000', weight: 50 },
          { name: 'variant-b', upstream: '127.0.0.1:3001', weight: 50 },
        ],
        killed: false,
        compiledCaddy: {
          route: {
            match: [{ host: ['app.acme-demo.dev'] }],
            handle: [{
              handler: 'reverse_proxy',
              upstreams: [{ dial: '127.0.0.1:3000' }, { dial: '127.0.0.1:3001' }],
              load_balancing: {
                selection_policy: {
                  policy: 'cookie',
                  name: 'ckb_ab_checkout',
                  fallback: { policy: 'weighted_round_robin', weights: [50, 50] },
                },
              },
            }],
            terminal: true,
          },
        },
        updatedAt: t1,
      },
    ],
    volumeMigrations: [
      {
        id: 'volmig_demo_pg_01',
        projectId: 'proj_acme_web',
        volumeName: 'acme_postgres_data',
        mountPath: '/var/lib/postgresql/data',
        sourceHost: 'local',
        targetHost: '198.51.100.42',
        uid: 999,
        gid: 999,
        containerName: 'culkibo-db-pg-main',
        estimatedMb: 420,
        status: 'planned',
        numericOwnerPreserved: true,
        zeroShell: true,
        plan: {
          zeroShell: true,
          numericOwnerPreserved: true,
          uidGid: '999:999',
          retainSourceVolume: true,
          requiredFreeSpaceMb: 924,
          phases: [
            { phase: 1, id: 'pre_sync', title: 'Warm pre-sync & disk headroom check', commands: [{ program: 'docker', args: ['volume', 'inspect', 'acme_postgres_data'] }, { program: 'ssh', args: ['-o', 'BatchMode=yes', 'root@198.51.100.42', 'docker', 'volume', 'create', 'acme_postgres_data'] }] },
            { phase: 2, id: 'quiesce_snapshot', title: 'Quiesce + tar --numeric-owner (999:999) + SHA-256', commands: [{ program: 'docker', args: ['pause', 'culkibo-db-pg-main'] }, { program: 'docker', args: ['run', '--rm', '--mount', 'type=volume,source=acme_postgres_data,target=/source,readonly', 'alpine:3.20', 'tar', '--numeric-owner', '-czf', '/backup/acme_postgres_data.tar.gz', '-C', '/source', '.'] }, { program: 'docker', args: ['unpause', 'culkibo-db-pg-main'] }] },
            { phase: 3, id: 'ssh_stream_transfer', title: 'SSH ControlMaster zero-shell transfer to 198.51.100.42', commands: [{ program: 'scp', args: ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '/var/tmp/culkibo-volmig/acme_postgres_data/acme_postgres_data.tar.gz', 'root@198.51.100.42:/var/tmp/culkibo-volmig/acme_postgres_data/'] }] },
            { phase: 4, id: 'verify_and_cutover', title: 'Target SHA-256 verify + tar --numeric-owner extract + stat 999:999', commands: [{ program: 'ssh', args: ['-o', 'BatchMode=yes', 'root@198.51.100.42', 'sha256sum', '-c', '/var/tmp/culkibo-volmig/acme_postgres_data/acme_postgres_data.sha256'] }, { program: 'ssh', args: ['-o', 'BatchMode=yes', 'root@198.51.100.42', 'docker', 'run', '--rm', '--mount', 'type=volume,source=acme_postgres_data,target=/target', 'alpine:3.20', 'tar', '--numeric-owner', '-xzf', '/backup/acme_postgres_data.tar.gz', '-C', '/target'] }] },
          ],
        },
        createdAt: t2,
      },
    ],
    syntheticFlows: [
      {
        id: 'flow_demo_auth_checkout',
        name: 'Auth Login → JWT Session → Orders API',
        steps: [
          { name: 'POST /api/auth/token', method: 'POST', url: 'https://api.acme-demo.dev/v1/auth/token', headers: { Authorization: '[REDACTED]' }, extract: { token: 'json.access_token' }, assert: { status: 200, maxLatencyMs: 400 } },
          { name: 'GET /v1/orders/health', method: 'GET', url: 'https://api.acme-demo.dev/v1/orders/health', headers: { Authorization: '[REDACTED]' }, assert: { status: 200, maxLatencyMs: 300 } },
        ],
        lastRunAt: t1,
        lastOk: true,
        lastLatencyMs: 64,
        createdAt: t3,
      },
    ],
    autoscalerPolicies: {
      proj_acme_web: {
        projectId: 'proj_acme_web',
        minReplicas: 1,
        maxReplicas: 6,
        scaleUpQueueThreshold: 40,
        scaleDownQueueThreshold: 8,
        scaleUpCooldownSec: 60,
        scaleDownCooldownSec: 180,
        perReplicaRamMb: 384,
        reserveHostRamMb: 512,
        breakerQueueThreshold: 250,
        breakerRetryAfterSec: 15,
      },
    },
    cronLeases: {
      cron_billing_rollup: [
        {
          id: 'lease_demo_42',
          jobId: 'cron_billing_rollup',
          scheduleSlotIso: '2026-11-27T20:00:00.000Z',
          holderId: 'worker-replica-a',
          fencingToken: 42,
          status: 'succeeded',
          acquiredAtMs: Date.now() - 1800000,
          expiresAtMs: Date.now() - 1500000,
          completedAtMs: Date.now() - 1794000,
        },
      ],
    },
    oncallPolicies: [
      {
        id: 'pol_prod_primary',
        name: 'Primary Production SRE Escalation',
        shiftDurationHours: 24,
        rotationStartMs: Date.now() - 1000 * 60 * 60 * 3,
        ackTimeoutSec: 300,
        flappingWindowSec: 600,
        flappingThreshold: 3,
        currentResponder: 'alice',
        tiers: [
          { tier: 1, responders: ['alice', 'bob'] },
          { tier: 2, responders: ['charlie'] },
          { tier: 3, responders: ['vp-eng'] },
        ],
      },
    ],
    oncallIncidents: [
      {
        id: 'ocinc_demo_1',
        policyId: 'pol_prod_primary',
        fingerprint: 'fp_pg_replica_lag',
        projectId: 'proj_acme_web',
        severity: 'high',
        title: 'PostgreSQL Connection Pool Saturation (>82%)',
        status: 'firing',
        currentTier: 1,
        assignedResponder: 'alice',
        occurrences: 2,
        flapping: false,
        acknowledgedBy: null,
        acknowledgedAtMs: null,
        createdAtMs: Date.now() - 120000,
        updatedAtMs: Date.now() - 30000,
      },
    ],
    replicaTopologies: {
      db_pg_main: {
        dbId: 'db_pg_main',
        primary: { id: 'pg-primary-fsn1', host: '10.88.0.10', port: 5432, region: 'eu-central', healthy: true, fenced: false, role: 'primary' },
        replicas: [
          { id: 'rep-eu-west', host: '10.88.0.11', port: 5432, region: 'eu-west', lagMs: 18, lagBytes: 65536, healthy: true, role: 'replica' },
          { id: 'rep-us-east', host: '10.88.0.12', port: 5432, region: 'us-east', lagMs: 1850, lagBytes: 6710886, healthy: true, role: 'replica' },
        ],
      },
    },
    chaosGameDays: {},
    mtlsCerts: [
      {
        serial: 'CKB-8F4A-1001',
        spiffeId: 'spiffe://culkibo.internal/ns/prod/sa/edge-api-rust',
        serviceName: 'edge-api-rust',
        namespace: 'prod',
        issuedAt: t1,
        expiresAt: nowIso(1000 * 60 * 60 * 24),
        ttlHours: 24,
        revoked: false,
        signatureB64: 'ed25519_demo_sig_9e8d7c6b5a4f3e2d1c0b',
      },
    ],
    rateLimitPolicies: [
      { id: 'rl_free', name: 'Free Tier AI Shield', planTier: 'free', rpmLimit: 30, tpmLimit: 15000, burstMultiplier: 1.2, windowSec: 60 },
      { id: 'rl_pro', name: 'Pro Tier AI Shield', planTier: 'pro', rpmLimit: 120, tpmLimit: 60000, burstMultiplier: 1.5, windowSec: 60 },
      { id: 'rl_enterprise', name: 'Enterprise AI Shield', planTier: 'enterprise', rpmLimit: 600, tpmLimit: 300000, burstMultiplier: 2.0, windowSec: 60 },
    ],
    featureFlags: [
      { key: 'ai_streaming_v2', description: 'Zero-buffering SSE token streaming across edge nodes', enabled: true, killed: false, rolloutPct: 35, environment: 'prod', allowTenants: ['acme-pro'], denyTenants: [] },
      { key: 'instant_checkout_h3', description: 'HTTP/3 0-RTT optimistic cart checkout pipeline', enabled: true, killed: false, rolloutPct: 50, environment: 'prod', allowTenants: [], denyTenants: [] },
    ],
    runtimeAnomalies: {},
    digestPromotions: {},
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

  // --- Databases & Cycle-9 Read-Only DB Studio + Post-MinIO S3 Storage ---
  if (pathname === '/api/databases' && method === 'GET') {
    return jsonResponse({ databases: s.databases });
  }
  if (pathname === '/api/databases/engines' && method === 'GET') {
    return jsonResponse({
      engines: [
        { engine: 'postgresql', label: 'PostgreSQL 16', image: 'postgres:16-alpine', licence: 'PostgreSQL License' },
        { engine: 'valkey', label: 'Valkey 8 (Redis)', image: 'valkey/valkey:8-alpine', licence: 'BSD-3-Clause' },
        { engine: 'mysql', label: 'MySQL 8.4 LTS', image: 'mysql:8.4', licence: 'GPL-2.0' },
        { engine: 'mariadb', label: 'MariaDB 11', image: 'mariadb:11.4', licence: 'GPL-2.0' },
        { engine: 'mongodb', label: 'MongoDB 7', image: 'mongo:7.0', licence: 'SSPL' },
      ],
    });
  }
  if (pathname === '/api/databases/docker-status') {
    return jsonResponse({ available: true, version: '27.5.1', running: true });
  }
  if (pathname === '/api/databases/storage') {
    return jsonResponse({ configured: false });
  }
  if (pathname.match(/^\/api\/databases\/[^/]+\/backups$/) && method === 'GET') {
    return jsonResponse({
      backups: [
        { id: 'bk_demo_1', createdAt: nowIso(-1000 * 60 * 60 * 6), sizeBytes: 18_420_112, trigger: 'scheduled', localAvailable: true, remoteAvailable: false },
      ],
    });
  }
  const dbStudioSqlMatch = pathname.match(/^\/api\/databases\/([^/]+)\/studio\/sql$/);
  if (dbStudioSqlMatch && method === 'POST') {
    const rawQuery = String(body.query || '').trim();
    if (!rawQuery) {
      return jsonResponse({ error: 'SQL query is required.' }, 400);
    }
    const stripped = rawQuery
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/--[^\n]*/g, ' ')
      .trim();
    const withoutTrailingSemi = stripped.replace(/;+$/, '');
    if (/^\\[a-z!?]/i.test(rawQuery) || withoutTrailingSemi.includes(';')) {
      return jsonResponse({ error: 'Blocked by Read-Only SQL Gate: stacked statements and psql metacommands are forbidden.' }, 400);
    }
    const forbiddenRe = /\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|GRANT|REVOKE|COPY|CALL|DO|SET|RESET|VACUUM|ANALYZE|CLUSTER|REINDEX|ATTACH|DETACH|PRAGMA|MERGE|REPLACE|EXEC|EXECUTE|LOAD|LOCK|LISTEN|NOTIFY|PREPARE|DEALLOCATE|PG_TERMINATE_BACKEND|PG_READ_FILE|PG_LS_DIR|LO_IMPORT|LO_EXPORT)\b/i;
    const hit = withoutTrailingSemi.match(forbiddenRe);
    if (hit) {
      return jsonResponse({ error: `Blocked by Read-Only SQL Gate: destructive/mutating keyword "${hit[1].toUpperCase()}" is forbidden.` }, 400);
    }
    if (!/^(SELECT|EXPLAIN|SHOW|WITH)\b/i.test(withoutTrailingSemi)) {
      return jsonResponse({ error: 'Blocked by Read-Only SQL Gate: only SELECT, EXPLAIN, SHOW, or read-only WITH queries are allowed.' }, 400);
    }
    const hasLimit = /\bLIMIT\s+\d+/i.test(withoutTrailingSemi);
    const cappedQuery = /^(SELECT|WITH)\b/i.test(withoutTrailingSemi) && !hasLimit
      ? `${withoutTrailingSemi} LIMIT 200`
      : withoutTrailingSemi;
    return jsonResponse({
      ok: true,
      dryRunPreview: true,
      readOnlyEnforced: true,
      engine: String(body.engine || 'postgres'),
      sanitizedQuery: cappedQuery,
      wrappedSql: `BEGIN TRANSACTION READ ONLY; SET LOCAL statement_timeout = '5000ms'; ${cappedQuery}; ROLLBACK;`,
      statementTimeoutMs: 5000,
      rowCap: 200,
      durationMs: 1.8,
      columns: ['id', 'project', 'status', 'duration_ms', 'created_at'],
      rowCount: 3,
      rows: [
        { id: 'dep_8c4f1a', project: 'acme-saas-web', status: 'active', duration_ms: 14200, created_at: nowIso(-1000 * 60 * 14) },
        { id: 'dep_3e91b2', project: 'edge-api-rust', status: 'active', duration_ms: 11850, created_at: nowIso(-1000 * 60 * 48) },
        { id: 'dep_71d2c0', project: 'ai-worker-py', status: 'active', duration_ms: 9410, created_at: nowIso(-1000 * 60 * 190) },
      ],
    });
  }
  const dbStudioRedisMatch = pathname.match(/^\/api\/databases\/([^/]+)\/studio\/redis$/);
  if (dbStudioRedisMatch && method === 'POST') {
    const tokens = Array.isArray(body.argv)
      ? body.argv.map((x: unknown) => String(x)).filter(Boolean)
      : String(body.argv || '').trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) {
      return jsonResponse({ error: 'Redis command is required.' }, 400);
    }
    const cmd = tokens[0].toUpperCase();
    const allowed = new Set(['SCAN', 'TYPE', 'TTL', 'PTTL', 'DBSIZE', 'INFO', 'STRLEN', 'LLEN', 'HLEN', 'SCARD', 'ZCARD', 'GET']);
    if (!allowed.has(cmd)) {
      return jsonResponse({ error: `Blocked by Safe Redis Gate: command "${cmd}" is disallowed (read-only allowlist only).` }, 400);
    }
    const normalized = [cmd, ...tokens.slice(1)];
    let clampedCount: number | null = null;
    if (cmd === 'SCAN') {
      if (normalized.length === 1) normalized.push('0');
      const countIdx = normalized.findIndex((t) => t.toUpperCase() === 'COUNT');
      if (countIdx !== -1 && normalized[countIdx + 1]) {
        const parsedCount = Math.max(1, Math.min(100, parseInt(normalized[countIdx + 1], 10) || 50));
        normalized[countIdx + 1] = String(parsedCount);
        clampedCount = parsedCount;
      } else {
        normalized.push('COUNT', '50');
        clampedCount = 50;
      }
    }
    const output = cmd === 'INFO'
      ? '# Memory\nused_memory_human:18.42M\nused_memory_peak_human:24.10M\nmaxmemory_human:256.00M\nmem_fragmentation_ratio:1.08'
      : cmd === 'DBSIZE'
        ? '(integer) 1428'
        : 'cursor: "0"\nkeys: ["session:usr_owner", "cache:catalog:v2", "ratelimit:edge:91.107.194.22", "queue:webhooks:pending"]';
    return jsonResponse({
      ok: true,
      dryRunPreview: true,
      readOnlyEnforced: true,
      command: cmd,
      normalizedArgv: normalized,
      clampedCount,
      output,
    });
  }
  const dbStudioBloatMatch = pathname.match(/^\/api\/databases\/([^/]+)\/studio\/bloat$/);
  if (dbStudioBloatMatch && method === 'POST') {
    return jsonResponse({
      ok: true,
      checkedTables: 14,
      bloatedTables: [
        { tableName: 'webhook_deliveries', liveTuples: 48200, deadTuples: 16400, deadTupleRatio: 0.254, sizeBytes: 42_991_616, recommendation: 'Run VACUUM (ANALYZE) webhook_deliveries' },
      ],
      unusedIndexes: [
        { indexName: 'idx_events_legacy_payload', tableName: 'audit_events', sizeBytes: 12_582_912, idxScan: 0 },
      ],
      recommendations: [
        'Table "webhook_deliveries" has 25.4% dead tuples (16,400 dead) — schedule VACUUM (ANALYZE) during off-peak window.',
        'Unused index "idx_events_legacy_payload" (12.0 MB, 0 scans) — safe candidate for DROP INDEX CONCURRENTLY.',
      ],
    });
  }

  if (pathname === '/api/storage/presets' && method === 'GET') {
    return jsonResponse({
      presets: [
        {
          id: 'garage',
          name: 'Garage',
          label: 'Garage S3 (Rust CRDT)',
          image: 'dxflrs/garage:v1.0.1',
          licence: 'AGPL-3.0',
          bindAddress: '127.0.0.1',
          defaultPort: 3900,
          memoryMb: 40,
          region: 'garage',
          summary: 'Ultra-lightweight (~40 MB RAM) Rust geo-distributed S3 compatible with WireGuard mesh.',
        },
        {
          id: 'rustfs',
          name: 'RustFS',
          label: 'RustFS (Apache-2.0 MinIO Drop-In)',
          image: 'rustfs/rustfs:1.0.0-alpha.45',
          licence: 'Apache-2.0',
          bindAddress: '127.0.0.1',
          defaultPort: 9000,
          memoryMb: 96,
          region: 'us-east-1',
          summary: 'High-throughput Apache-2.0 drop-in MinIO replacement with ILM & Object Lock.',
        },
        {
          id: 'seaweedfs',
          name: 'SeaweedFS',
          label: 'SeaweedFS Filer + S3',
          image: 'chrislusf/seaweedfs:3.85',
          licence: 'Apache-2.0',
          bindAddress: '127.0.0.1',
          defaultPort: 8333,
          memoryMb: 128,
          region: 'us-east-1',
          summary: 'Distributed Filer + S3 gateway built for billions of blobs and fast tiering.',
        },
      ],
    });
  }
  if (pathname === '/api/storage/presign' && method === 'POST') {
    const bucket = String(body.bucket || '').trim();
    const key = String(body.key || '').trim();
    const expiresIn = Number(body.expiresIn ?? 900);
    const httpMethod = String(body.method || 'GET').toUpperCase();
    const endpoint = String(body.endpoint || 'http://127.0.0.1:3900').replace(/\/+$/, '');
    const region = String(body.region || 'us-east-1').trim() || 'us-east-1';
    const accessKeyId = String(body.accessKeyId || 'GK_demo_access_key').trim();
    if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucket)) {
      return jsonResponse({ error: 'Invalid S3 bucket name (3-63 lowercase alphanumeric, dots, or hyphens).' }, 400);
    }
    if (!key || key.startsWith('/') || key.includes('..') || Array.from(key).some((ch) => ch.charCodeAt(0) < 32)) {
      return jsonResponse({ error: 'Invalid object key: path traversal (".."), leading slash, and control chars are blocked.' }, 400);
    }
    if (!Number.isFinite(expiresIn) || expiresIn < 60 || expiresIn > 604800) {
      return jsonResponse({ error: 'expiresIn must be between 60s and 604800s (7 days).' }, 400);
    }
    const dateStamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const amzDate = `${dateStamp}T120000Z`;
    const fakeSig = '9a7c4e2b8f01d356a4c9e8d20f7b1a5c3e9d01f2a4b6c8d0e1f2a3b4c5d6e7f8';
    const cred = encodeURIComponent(`${accessKeyId}/${dateStamp}/${region}/s3/aws4_request`);
    const url = `${endpoint}/${bucket}/${key.split('/').map(encodeURIComponent).join('/')}?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=${cred}&X-Amz-Date=${amzDate}&X-Amz-Expires=${expiresIn}&X-Amz-SignedHeaders=host&X-Amz-Signature=${fakeSig}`;
    return jsonResponse({
      ok: true,
      url,
      method: httpMethod,
      bucket,
      key,
      expiresIn,
      expiresAt: nowIso(expiresIn * 1000),
      algorithm: 'AWS4-HMAC-SHA256',
      signature: fakeSig,
    });
  }

  // --- Cycle-9 White-Label Brand Engine, Standard-Webhooks DLQ & Agency Billing Ledger ---
  if (pathname === '/api/brand') {
    if (method === 'PUT' || method === 'POST') {
      const nextName = body.brandName != null ? String(body.brandName).trim() : s.brand.brandName;
      const nextTagline = body.tagline != null ? String(body.tagline).trim() : s.brand.tagline;
      const nextAccent = body.accentHex != null ? String(body.accentHex).trim() : s.brand.accentHex;
      const nextLogo = body.logoUrl != null ? String(body.logoUrl).trim() : s.brand.logoUrl;
      const nextSupport = body.supportUrl != null ? String(body.supportUrl).trim() : s.brand.supportUrl;
      if (!nextName || nextName.length > 60 || /[<>'"]/.test(nextName)) {
        return jsonResponse({ error: 'Invalid brandName (1-60 chars, HTML/quote chars forbidden).' }, 400);
      }
      if (nextTagline.length > 140 || /[<>]/.test(nextTagline)) {
        return jsonResponse({ error: 'Invalid tagline (max 140 chars, < and > forbidden).' }, 400);
      }
      if (!/^#[0-9a-fA-F]{6}$/.test(nextAccent)) {
        return jsonResponse({ error: 'Invalid accentHex: strict #RRGGBB format required (CSS injection blocked).' }, 400);
      }
      if (nextSupport && !/^https:\/\//i.test(nextSupport)) {
        return jsonResponse({ error: 'Invalid supportUrl: must start with https://' }, 400);
      }
      if (nextLogo && (!/^https:\/\//i.test(nextLogo) && !/^data:image\/svg\+xml/i.test(nextLogo) || /<script|on[a-z]+\s*=|foreignObject|javascript:|<iframe/i.test(nextLogo))) {
        return jsonResponse({ error: 'Invalid logoUrl: unsafe URI or SVG payload rejected.' }, 400);
      }
      s.brand = {
        brandName: nextName,
        tagline: nextTagline,
        accentHex: nextAccent,
        logoUrl: nextLogo,
        supportUrl: nextSupport,
        hidePoweredBy: typeof body.hidePoweredBy === 'boolean' ? body.hidePoweredBy : s.brand.hidePoweredBy,
        updatedAt: nowIso(),
      };
      return jsonResponse({ brand: s.brand, ...s.brand });
    }
    return jsonResponse({ brand: s.brand, ...s.brand });
  }
  if (pathname === '/api/brand/reset' && method === 'POST') {
    s.brand = {
      brandName: 'Culkibo',
      tagline: 'Ultra-lightweight self-hosted PaaS',
      accentHex: '#6366f1',
      logoUrl: '',
      supportUrl: '',
      hidePoweredBy: false,
      updatedAt: null,
    };
    return jsonResponse({ brand: s.brand, ...s.brand });
  }

  if (pathname === '/api/webhooks/outbound') {
    if (method === 'POST') {
      const urlStr = String(body.url || '').trim();
      if (!/^https?:\/\//i.test(urlStr) || /127\.0\.0\.1|localhost|169\.254\.169\.254/i.test(urlStr)) {
        return jsonResponse({ error: 'Webhook URL blocked by anti-SSRF guard (must be public HTTPS endpoint).' }, 400);
      }
      const rawSec = `whsec_${Math.random().toString(36).slice(2, 10)}${Math.random().toString(36).slice(2, 14)}`;
      const sub = {
        id: `whsub_${Date.now().toString(36)}`,
        url: urlStr,
        events: Array.isArray(body.events) && body.events.length > 0 ? body.events : ['*'],
        description: String(body.description || 'Custom Standard-Webhook'),
        enabled: body.enabled !== false,
        secretPreview: `${rawSec.slice(0, 10)}••••••••${rawSec.slice(-4)}`,
        hasSecondarySecret: false,
        secondaryExpiresAt: null,
        createdAt: nowIso(),
        updatedAt: nowIso(),
      };
      s.webhookSubscriptions = [sub, ...s.webhookSubscriptions];
      return jsonResponse({ subscription: sub, secret: rawSec, secretPreview: sub.secretPreview }, 201);
    }
    return jsonResponse({ subscriptions: s.webhookSubscriptions });
  }
  const whRotateMatch = pathname.match(/^\/api\/webhooks\/outbound\/([^/]+)\/rotate-secret$/);
  if (whRotateMatch && method === 'POST') {
    const id = decodeURIComponent(whRotateMatch[1]);
    const graceSec = Number(body.graceSec) || 86400;
    const rawSec = `whsec_${Math.random().toString(36).slice(2, 10)}${Math.random().toString(36).slice(2, 14)}`;
    const preview = `${rawSec.slice(0, 10)}••••••••${rawSec.slice(-4)}`;
    const exp = nowIso(graceSec * 1000);
    s.webhookSubscriptions = s.webhookSubscriptions.map((sub) =>
      sub.id === id ? { ...sub, secretPreview: preview, hasSecondarySecret: true, secondaryExpiresAt: exp, updatedAt: nowIso() } : sub
    );
    const updated = s.webhookSubscriptions.find((sub) => sub.id === id);
    return jsonResponse({ ok: true, subscription: updated, secret: rawSec, secretPreview: preview, graceSec, secondaryExpiresAt: exp });
  }
  if (pathname === '/api/webhooks/dlq' && method === 'GET') {
    return jsonResponse({ entries: s.webhookDlq });
  }
  const whReplayMatch = pathname.match(/^\/api\/webhooks\/dlq\/([^/]+)\/replay$/);
  if (whReplayMatch && method === 'POST') {
    const id = decodeURIComponent(whReplayMatch[1]);
    s.webhookDlq = s.webhookDlq.map((e) =>
      e.id === id ? { ...e, status: 'replayed', httpStatus: 200, attempts: (e.attempts || 1) + 1, replayedAt: nowIso(), lastError: null } : e
    );
    const entry = s.webhookDlq.find((e) => e.id === id);
    return jsonResponse({ ok: true, replayed: true, delivered: true, entry });
  }

  if (pathname === '/api/quotas' && method === 'GET') {
    return jsonResponse({ quotas: s.quotas, items: Object.values(s.quotas) });
  }
  if (pathname === '/api/billing/ledger' && method === 'GET') {
    const periodDays = Math.max(1, Math.min(365, Number(parsed.searchParams.get('periodDays')) || 30));
    const scale = periodDays / 30;
    const rows = [
      {
        projectId: 'proj_acme_web',
        projectName: 'acme-saas-web',
        cpuHours: Number((540 * scale).toFixed(1)),
        ramGbHours: Number((360 * scale).toFixed(1)),
        storageGb: 14.2,
        bandwidthGb: Number((92.4 * scale).toFixed(1)),
        estimatedCostUsd: Number((18.42 * scale).toFixed(2)),
        containersCount: 2,
        memoryMb: 512,
        quota: s.quotas.proj_acme_web,
        quotaUtilizationPct: 57,
      },
      {
        projectId: 'proj_edge_rust',
        projectName: 'edge-api-rust',
        cpuHours: Number((288 * scale).toFixed(1)),
        ramGbHours: Number((180 * scale).toFixed(1)),
        storageGb: 4.8,
        bandwidthGb: Number((64.1 * scale).toFixed(1)),
        estimatedCostUsd: Number((9.85 * scale).toFixed(2)),
        containersCount: 1,
        memoryMb: 256,
        quota: s.quotas.proj_edge_rust,
        quotaUtilizationPct: 50,
      },
      {
        projectId: 'proj_ai_worker',
        projectName: 'ai-worker-py',
        cpuHours: Number((412 * scale).toFixed(1)),
        ramGbHours: Number((384 * scale).toFixed(1)),
        storageGb: 16.5,
        bandwidthGb: Number((28.0 * scale).toFixed(1)),
        estimatedCostUsd: Number((14.60 * scale).toFixed(2)),
        containersCount: 1,
        memoryMb: 512,
        quota: s.quotas.proj_ai_worker,
        quotaUtilizationPct: 83,
      },
    ];
    const totals = {
      cpuHours: Number(rows.reduce((a, r) => a + r.cpuHours, 0).toFixed(1)),
      ramGbHours: Number(rows.reduce((a, r) => a + r.ramGbHours, 0).toFixed(1)),
      storageGb: Number(rows.reduce((a, r) => a + r.storageGb, 0).toFixed(1)),
      bandwidthGb: Number(rows.reduce((a, r) => a + r.bandwidthGb, 0).toFixed(1)),
      estimatedCostUsd: Number(rows.reduce((a, r) => a + r.estimatedCostUsd, 0).toFixed(2)),
    };
    if (parsed.searchParams.get('format') === 'csv') {
      const csvLines = [
        'project_id,project_name,cpu_hours,ram_gb_hours,storage_gb,bandwidth_gb,estimated_cost_usd',
        ...rows.map((r) => `${r.projectId},${r.projectName},${r.cpuHours},${r.ramGbHours},${r.storageGb},${r.bandwidthGb},${r.estimatedCostUsd.toFixed(2)}`),
        `TOTAL,ALL_PROJECTS,${totals.cpuHours},${totals.ramGbHours},${totals.storageGb},${totals.bandwidthGb},${totals.estimatedCostUsd.toFixed(2)}`,
      ].join('\n');
      return new Response(csvLines, {
        status: 200,
        headers: { 'Content-Type': 'text/csv; charset=utf-8' },
      });
    }
    return jsonResponse({ ok: true, periodDays, currency: 'USD', generatedAt: nowIso(), entries: rows, projects: rows, totals });
  }

  // --- Cycle-10 Milestone APIs (DR Fire-Drills, SLO Canary, Compressed Log Archive, Remote Builders, Self-Hosted AI/GPU Planner) ---
  if (pathname === '/api/dr/drills' && method === 'GET') {
    const dbFilter = parsed.searchParams.get('databaseId');
    const drills = dbFilter ? s.drDrills.filter((d) => d.databaseId === dbFilter) : s.drDrills;
    return jsonResponse({ ok: true, drills });
  }
  const drDrillMatch = pathname.match(/^\/api\/databases\/([^/]+)\/dr-drill$/);
  if (drDrillMatch && method === 'POST') {
    const dbId = decodeURIComponent(drDrillMatch[1]);
    const sample = String(body.sqlSample || '');
    const b64 = String(body.artifactBase64 || '');
    const decodedLen = b64 ? Math.floor((b64.length * 3) / 4) : sample.length;
    const isCorrupt = (b64 && decodedLen <= 64) || (!b64 && sample.length > 0 && sample.length <= 64);
    if (isCorrupt) {
      const failDrill = {
        id: `drill_fail_${Date.now().toString(36)}`,
        databaseId: dbId,
        projectId: body.projectId || 'proj_acme_web',
        engine: String(body.engine || 'postgres'),
        verdict: 'FAIL',
        rtoMs: 4,
        rpoSec: 0,
        bytesVerified: decodedLen || 20,
        uncompressedBytes: 0,
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        aclPreserved: false,
        checks: [
          { name: 'min_bytes', passed: false, detail: `EMPTY_OR_TRUNCATED_DUMP: ${decodedLen || 20} B <= 64 B minimum (silent empty S3 dump caught!)` },
        ],
        warnings: [],
        errors: ['EMPTY_OR_TRUNCATED_DUMP: Backup artifact is 20 B empty gzip — restore aborted and DR alert fired (dokploy#1382 / coolify#6506).'],
        createdAt: nowIso(),
      };
      s.drDrills = [failDrill, ...s.drDrills].slice(0, 20);
      return jsonResponse({ ok: false, drill: failDrill, ...failDrill });
    }
    const passDrill = {
      id: `drill_pass_${Date.now().toString(36)}`,
      databaseId: dbId,
      projectId: body.projectId || 'proj_acme_web',
      engine: String(body.engine || 'postgres'),
      verdict: 'PASS',
      rtoMs: 284,
      rpoSec: 120,
      bytesVerified: 18420112,
      uncompressedBytes: 74910208,
      sha256: '9c7e4b2a1d8f3056a4c9e8d20f7b1a5c3e9d01f2a4b6c8d0e1f2a3b4c5d6e7f8',
      aclPreserved: body.preserveAcl !== false,
      checks: [
        { name: 'min_bytes', passed: true, detail: '18.4 MB compressed (> 64 B threshold)' },
        { name: 'sha256_integrity', passed: true, detail: 'SHA-256 digest matched' },
        { name: 'gunzip_stream', passed: true, detail: 'Clean gzip decompression verified' },
        { name: 'sql_ddl_and_acl', passed: true, detail: 'CREATE TABLE + GRANT ACL statements intact' },
      ],
      warnings: [],
      errors: [],
      createdAt: nowIso(),
    };
    s.drDrills = [passDrill, ...s.drDrills].slice(0, 20);
    return jsonResponse({ ok: true, drill: passDrill, ...passDrill });
  }

  const canaryListMatch = pathname.match(/^\/api\/projects\/([^/]+)\/slo-canary$/);
  if (canaryListMatch && method === 'GET') {
    const pid = decodeURIComponent(canaryListMatch[1]);
    return jsonResponse({ ok: true, rollouts: s.sloCanaries[pid] || [] });
  }
  const canaryStartMatch = pathname.match(/^\/api\/projects\/([^/]+)\/slo-canary\/start$/);
  if (canaryStartMatch && method === 'POST') {
    const pid = decodeURIComponent(canaryStartMatch[1]);
    const steps = Array.isArray(body.steps) && body.steps.length > 0 ? body.steps.map(Number) : [10, 25, 50, 100];
    const w = steps[0] || 10;
    const rollout = {
      id: `can_${Date.now().toString(36)}`,
      projectId: pid,
      hostname: String(body.hostname || 'app.acme-demo.dev'),
      stableUpstream: String(body.stableUpstream || '127.0.0.1:3000'),
      canaryUpstream: String(body.canaryUpstream || '127.0.0.1:3001'),
      steps,
      stepIndex: 0,
      canaryWeight: w,
      stableWeight: 100 - w,
      status: 'IN_PROGRESS',
      sloTarget: Number(body.sloTarget) || 0.999,
      maxBurnRate: Number(body.maxBurnRate) || 14.4,
      lastBurnRate: 0.4,
      lastLatencyRatio: 1.03,
      breachReasons: [],
      caddyRoute: {
        match: [{ host: [String(body.hostname || 'app.acme-demo.dev')] }],
        handle: [{ handler: 'reverse_proxy', load_balancing: { selection_policy: { policy: 'weighted_round_robin', weights: [100 - w, w] } } }],
      },
      startedAt: nowIso(),
      updatedAt: nowIso(),
    };
    s.sloCanaries[pid] = [rollout, ...(s.sloCanaries[pid] || [])].slice(0, 10);
    return jsonResponse({ ok: true, rollout, ...rollout }, 201);
  }
  const canaryEvalMatch = pathname.match(/^\/api\/projects\/([^/]+)\/slo-canary\/([^/]+)\/evaluate$/);
  if (canaryEvalMatch && method === 'POST') {
    const pid = decodeURIComponent(canaryEvalMatch[1]);
    const rid = decodeURIComponent(canaryEvalMatch[2]);
    const list = s.sloCanaries[pid] || [];
    const r = list.find((x) => x.id === rid) || list[0];
    if (!r) return jsonResponse({ error: 'Canary rollout not found' }, 404);
    const total = Math.max(1, Number(body.totalRequests) || 1000);
    const errs = Math.max(0, Number(body.error5xxCount) || 0);
    const baseP95 = Math.max(1, Number(body.baselineP95Ms) || 18);
    const candP95 = Math.max(1, Number(body.canaryP95Ms) || 19);
    const slo = r.sloTarget || 0.999;
    const burnRate = Number(((errs / total) / Math.max(0.0001, 1 - slo)).toFixed(2));
    const latRatio = Number((candP95 / baseP95).toFixed(2));
    const breachReasons: string[] = [];
    if (burnRate > (r.maxBurnRate || 14.4)) {
      breachReasons.push(`SRE error-budget burn rate ${burnRate}x exceeded ${r.maxBurnRate || 14.4}x threshold (${errs}/${total} HTTP 5xx)`);
    }
    if (latRatio > 2.0 && candP95 - baseP95 >= 25) {
      breachReasons.push(`Canary p95 latency regression ${candP95}ms vs ${baseP95}ms baseline (${latRatio}x)`);
    }
    r.lastBurnRate = burnRate;
    r.lastLatencyRatio = latRatio;
    r.updatedAt = nowIso();
    if (breachReasons.length > 0) {
      r.status = 'ROLLED_BACK';
      r.canaryWeight = 0;
      r.stableWeight = 100;
      r.breachReasons = breachReasons;
      r.caddyRoute = {
        match: [{ host: [r.hostname] }],
        handle: [{ handler: 'reverse_proxy', load_balancing: { selection_policy: { policy: 'weighted_round_robin', weights: [100, 0] } } }],
      };
    } else {
      const steps = Array.isArray(r.steps) ? r.steps : [10, 25, 50, 100];
      const nextIdx = Math.min(steps.length - 1, (r.stepIndex || 0) + 1);
      r.stepIndex = nextIdx;
      r.canaryWeight = steps[nextIdx];
      r.stableWeight = 100 - r.canaryWeight;
      r.status = r.canaryWeight >= 100 ? 'PROMOTED' : 'IN_PROGRESS';
      r.breachReasons = [];
      r.caddyRoute = {
        match: [{ host: [r.hostname] }],
        handle: [{ handler: 'reverse_proxy', load_balancing: { selection_policy: { policy: 'weighted_round_robin', weights: [100 - r.canaryWeight, r.canaryWeight] } } }],
      };
    }
    return jsonResponse({ ok: true, rollout: r, burnRate, breached: breachReasons.length > 0, breachReasons, status: r.status, canaryWeight: r.canaryWeight, caddyRoute: r.caddyRoute });
  }
  const canaryAbortMatch = pathname.match(/^\/api\/projects\/([^/]+)\/slo-canary\/([^/]+)\/abort$/);
  if (canaryAbortMatch && method === 'POST') {
    const pid = decodeURIComponent(canaryAbortMatch[1]);
    const rid = decodeURIComponent(canaryAbortMatch[2]);
    const list = s.sloCanaries[pid] || [];
    const r = list.find((x) => x.id === rid) || list[0];
    if (r) {
      r.status = 'ROLLED_BACK';
      r.canaryWeight = 0;
      r.stableWeight = 100;
      r.breachReasons = [String(body.reason || 'manual_abort')];
      r.updatedAt = nowIso();
    }
    return jsonResponse({ ok: true, rollout: r });
  }

  if (pathname === '/api/logs' && method === 'GET') {
    return jsonResponse({
      logs: [
        { id: 'log_1', projectId: 'proj_acme_web', pod: 'citadel', level: 'INFO', message: 'Caddy HTTP/3 route synced for app.acme-demo.dev -> 127.0.0.1:3000 (3.1ms)', timestamp: nowIso(-12000) },
        { id: 'log_2', projectId: 'proj_acme_web', pod: 'forge', level: 'HOT_SYNC', message: 'Merkle delta applied src/app/page.tsx (1.41ms, -96.1% brotli)', timestamp: nowIso(-45000) },
        { id: 'log_3', projectId: 'proj_edge_rust', pod: 'citadel', level: 'SUCCESS', message: 'Health probe /health 200 OK (p95 1.8ms, 48 MB RSS)', timestamp: nowIso(-90000) },
      ],
    });
  }
  const logStatsMatch = pathname.match(/^\/api\/projects\/([^/]+)\/logs\/archive\/stats$/);
  if (logStatsMatch && method === 'GET') {
    const pid = decodeURIComponent(logStatsMatch[1]);
    const today = new Date().toISOString().slice(0, 10);
    return jsonResponse({
      ok: true,
      projectId: pid,
      filesCount: 4,
      totalFiles: 4,
      totalBytes: 148_240,
      totalEntries: 3842,
      retentionDays: 30,
      maxArchiveMb: 50,
      files: [
        { name: `${today}.ndjson.gz`, sizeBytes: 42_180, date: today },
        { name: '2026-11-26.ndjson.gz', sizeBytes: 38_920, date: '2026-11-26' },
      ],
    });
  }
  const logSearchMatch = pathname.match(/^\/api\/projects\/([^/]+)\/logs\/archive\/search$/);
  if (logSearchMatch && method === 'POST') {
    const pid = decodeURIComponent(logSearchMatch[1]);
    const regexStr = String(body.regex || '').trim();
    if (regexStr && (regexStr.length > 120 || /\([^)]*[+*?][^)]*\)[+*?]/.test(regexStr) || /\\[1-9]/.test(regexStr))) {
      return jsonResponse({ error: 'UNSAFE_REGEX: Nested quantifiers or backreferences rejected by ReDoS guard.' }, 400);
    }
    const q = String(body.query || '').trim().toLowerCase();
    const lvl = String(body.level || '').trim().toUpperCase();
    const archiveEntries = [
      { ts: nowIso(-1000 * 60 * 180), level: 'INFO', releaseId: 'rel_8c4f1a', stream: 'stdout', message: 'SmartPack zstd:chunked release rel_8c4f1a promoted with 0ms dropped connections' },
      { ts: nowIso(-1000 * 60 * 420), level: 'WARN', releaseId: 'rel_5b12d0', stream: 'stderr', message: 'Upstream pool wait 42ms on acme-postgres-16 (survived redeploy #41)' },
      { ts: nowIso(-1000 * 60 * 960), level: 'ERROR', releaseId: 'rel_5b12d0', stream: 'stderr', message: 'Webhook receiver returned HTTP 503 — persisted to Standard-Webhooks DLQ' },
      { ts: nowIso(-1000 * 60 * 1440), level: 'INFO', releaseId: 'rel_4a09e1', stream: 'stdout', message: 'DR backup fire-drill PASS (18.4 MB gzipped SQL verified, RTO 312ms)' },
    ].filter((e) => {
      if (lvl && lvl !== 'ALL' && e.level !== lvl) return false;
      if (q && !e.message.toLowerCase().includes(q) && !String(e.releaseId || '').toLowerCase().includes(q)) return false;
      if (regexStr) {
        try {
          if (!new RegExp(regexStr, 'i').test(e.message)) return false;
        } catch {
          return false;
        }
      }
      return true;
    });
    return jsonResponse({
      ok: true,
      projectId: pid,
      filesScanned: 4,
      totalMatches: archiveEntries.length,
      truncated: false,
      entries: archiveEntries,
    });
  }

  if (pathname === '/api/fleet/builders' && method === 'GET') {
    return jsonResponse({ ok: true, builders: s.remoteBuilders });
  }
  if (pathname === '/api/fleet/builders' && method === 'POST') {
    const rec = {
      id: `bld_${Date.now().toString(36)}`,
      name: String(body.name || 'remote-builder'),
      host: String(body.host || '10.88.0.10'),
      arch: String(body.arch || 'linux/amd64'),
      maxConcurrency: Number(body.maxConcurrency) || 4,
      activeBuilds: 0,
      allowPreviews: body.allowPreviews !== false,
      keepStorageGb: Number(body.keepStorageGb) || 20,
      sshMuxPinned: false,
      status: 'ready',
    };
    s.remoteBuilders = [rec, ...s.remoteBuilders];
    return jsonResponse({ ok: true, builder: rec }, 201);
  }
  if (pathname === '/api/fleet/builders/schedule' && method === 'POST') {
    const isPreview = Boolean(body.isPreview);
    const arch = String(body.arch || 'linux/amd64');
    const chosen = s.remoteBuilders.find((b) => (!isPreview || b.allowPreviews) && b.arch === arch && b.activeBuilds < b.maxConcurrency)
      || s.remoteBuilders[0];
    if (chosen) {
      chosen.activeBuilds = Math.min(chosen.maxConcurrency, (chosen.activeBuilds || 0) + 1);
      chosen.sshMuxPinned = true;
    }
    return jsonResponse({
      ok: true,
      leased: true,
      queued: false,
      leaseId: `lease_bld_${Date.now().toString(36)}`,
      builderId: chosen?.id || 'bld_hetzner_amd64',
      builderName: chosen?.name || 'hetzner-cpx41-builder-eu',
      arch: chosen?.arch || arch,
      isPreview,
      activeBuilds: chosen?.activeBuilds || 1,
      maxConcurrency: chosen?.maxConcurrency || 4,
      sshMuxPinned: true,
      directPushTarget: `127.0.0.1:5055/${String(body.projectId || 'pr-preview')}:latest`,
      canRecycleMux: { allowed: false, reason: 'ACTIVE_BUILDS_IN_FLIGHT', activeBuilds: chosen?.activeBuilds || 1 },
    });
  }

  if (pathname === '/api/ai/presets' && method === 'GET') {
    return jsonResponse({
      ok: true,
      presets: [
        { id: 'ollama', name: 'Ollama', label: 'Ollama 0.17.4 (Pinned CVE-Safe)', image: 'ollama/ollama:0.17.4', bindAddress: '127.0.0.1', port: 11434, cacheMount: '/root/.ollama', description: 'Zero-config local LLM runner with GGUF quantization and private Bearer proxy.' },
        { id: 'vllm', name: 'vLLM', label: 'vLLM v0.21.2 (OpenAI API)', image: 'vllm/vllm-openai:v0.21.2', bindAddress: '127.0.0.1', port: 8000, cacheMount: '/root/.cache/huggingface', description: 'High-throughput PagedAttention server (patches CVE-2026-22778 & CVE-2026-137477).' },
        { id: 'llamacpp', name: 'llama.cpp', label: 'llama.cpp CUDA Server', image: 'ghcr.io/ggml-org/llama.cpp:server-cuda-b5120', bindAddress: '127.0.0.1', port: 8080, cacheMount: '/models', description: 'Ultra-lean C++ GGUF inference server for small 8–24 GB VRAM GPUs.' },
      ],
    });
  }
  const calcDemoVram = (p: Record<string, any>) => {
    const paramsB = Math.max(0.5, Number(p.paramsB) || 8);
    const quant = String(p.quantization || 'Q4_K_M').toUpperCase();
    const ctx = Math.max(512, Number(p.contextLen) || 8192);
    const bytesPerParam = quant === 'FP16' ? 2.0 : quant === 'Q8_0' ? 1.08 : 0.62;
    const weightsGb = Number((paramsB * bytesPerParam).toFixed(2));
    const kvCacheGb = Number((((ctx / 8192) * (paramsB / 8)) * 0.95).toFixed(2));
    const overheadGb = Number((0.8 + weightsGb * 0.08).toFixed(2));
    const totalRequiredGb = Number((weightsGb + kvCacheGb + overheadGb).toFixed(2));
    const availableVramGb = p.availableVramGb != null ? Number(p.availableVramGb) : 16;
    return { ok: true, paramsB, quantization: quant, contextLen: ctx, weightsGb, kvCacheGb, overheadGb, totalRequiredGb, availableVramGb, fits: totalRequiredGb <= availableVramGb };
  };
  if (pathname === '/api/ai/vram-estimate' && method === 'POST') {
    return jsonResponse(calcDemoVram(body));
  }
  if (pathname === '/api/ai/plan' && method === 'POST') {
    const vram = calcDemoVram(body);
    const runtime = String(body.runtime || 'ollama').toLowerCase();
    const bindAddress = String(body.bindAddress || '127.0.0.1');
    const authProxyEnabled = body.authProxyEnabled !== false;
    if (bindAddress === '0.0.0.0' && !authProxyEnabled) {
      return jsonResponse({ error: 'PUBLIC_AI_ENDPOINT_BLOCKED: Binding AI runtime to 0.0.0.0 without Bearer auth proxy is forbidden (CVE-2025-63389).' }, 400);
    }
    if (!vram.fits) {
      return jsonResponse({ error: `VRAM_INSUFFICIENT: Required ${vram.totalRequiredGb} GB (${vram.weightsGb} GB weights + ${vram.kvCacheGb} GB KV-cache) exceeds ${vram.availableVramGb} GB GPU VRAM.` }, 400);
    }
    const imageMap: Record<string, string> = {
      ollama: 'ollama/ollama:0.17.4',
      vllm: 'vllm/vllm-openai:v0.21.2',
      llamacpp: 'ghcr.io/ggml-org/llama.cpp:server-cuda-b5120',
    };
    const gpuMode = String(body.gpuMode || 'cdi');
    const gpuArgs = gpuMode === 'legacy' ? ['--gpus', 'all'] : gpuMode === 'cpu' ? [] : ['--device', 'nvidia.com/gpu=all'];
    const port = runtime === 'vllm' ? 8000 : runtime === 'llamacpp' ? 8080 : 11434;
    const cachePath = runtime === 'vllm' ? '/root/.cache/huggingface' : runtime === 'llamacpp' ? '/models' : '/root/.ollama';
    return jsonResponse({
      ok: true,
      runtime,
      model: String(body.model || `${runtime}-${vram.paramsB}b-${vram.quantization.toLowerCase()}`),
      image: imageMap[runtime] || imageMap.ollama,
      gpuMode,
      bindAddress,
      authProxyEnabled,
      vram,
      security: { safe: true, blockers: [], warnings: [], cves: [] },
      dockerArgs: ['run', '-d', '--restart=unless-stopped', ...gpuArgs, '-p', `${bindAddress}:${port}:${port}`, '-v', `culkibo_ai_${runtime}_cache:${cachePath}`, imageMap[runtime] || imageMap.ollama],
      volumeMount: `culkibo_ai_${runtime}_cache:${cachePath}`,
      caddyProxyGuard: `Caddy Bearer Auth Proxy -> ${bindAddress}:${port} (blocks unauthenticated CVE-2025-63389 access)`,
    });
  }

  // --- Cycle-11 Enterprise Governance & Multi-Region Edge APIs ---
  if (pathname === '/api/security/admission-policy' && method === 'GET') {
    return jsonResponse({ ok: true, ...s.admissionPolicy });
  }
  if (pathname === '/api/security/admission-policy' && method === 'PUT') {
    const presetMap: Record<string, Record<string, string>> = {
      baseline: {
        no_privileged: 'enforce',
        no_docker_sock_mount: 'enforce',
        no_host_root_mount: 'enforce',
        no_dangerous_caps: 'enforce',
        no_latest_tag: 'audit',
        require_non_root_uid: 'audit',
        require_resource_limits: 'audit',
        require_healthcheck: 'audit',
        require_signed_attestation: 'audit',
        no_public_db_or_panel_bind: 'enforce',
      },
      restricted: {
        no_privileged: 'enforce',
        no_docker_sock_mount: 'enforce',
        no_host_root_mount: 'enforce',
        no_dangerous_caps: 'enforce',
        no_latest_tag: 'enforce',
        require_non_root_uid: 'enforce',
        require_resource_limits: 'enforce',
        require_healthcheck: 'enforce',
        require_signed_attestation: 'audit',
        no_public_db_or_panel_bind: 'enforce',
      },
      'soc2-strict': {
        no_privileged: 'enforce',
        no_docker_sock_mount: 'enforce',
        no_host_root_mount: 'enforce',
        no_dangerous_caps: 'enforce',
        no_latest_tag: 'enforce',
        require_non_root_uid: 'enforce',
        require_resource_limits: 'enforce',
        require_healthcheck: 'enforce',
        require_signed_attestation: 'enforce',
        no_public_db_or_panel_bind: 'enforce',
      },
    };
    const nextPreset = String(body.preset || s.admissionPolicy.preset);
    const baseRules = presetMap[nextPreset] || s.admissionPolicy.rules;
    s.admissionPolicy = {
      preset: nextPreset,
      rules: { ...baseRules, ...(body.rules && typeof body.rules === 'object' ? body.rules : {}) },
      updatedAt: nowIso(),
    };
    return jsonResponse({ ok: true, ...s.admissionPolicy });
  }
  if (pathname === '/api/security/admission-policy/evaluate' && method === 'POST') {
    const spec = (body.spec && typeof body.spec === 'object' ? body.spec : body) as Record<string, any>;
    const rules = s.admissionPolicy.rules;
    const mounts = [...(Array.isArray(spec.mounts) ? spec.mounts : []), ...(Array.isArray(spec.volumes) ? spec.volumes : [])].map(String);
    const ports = Array.isArray(spec.ports) ? spec.ports.map(String) : [];
    const caps = Array.isArray(spec.capAdd) ? spec.capAdd.map((c: unknown) => String(c).toUpperCase()) : [];
    const img = String(spec.image || '');
    const checks: Array<{ id: string; passed: boolean; message: string; severity: string }> = [
      { id: 'no_privileged', passed: !spec.privileged, severity: 'critical', message: spec.privileged ? 'Container requests privileged: true (full host root escape)' : 'Not privileged' },
      { id: 'no_docker_sock_mount', passed: !mounts.some((m) => m.includes('docker.sock') || m.includes('containerd.sock')), severity: 'critical', message: mounts.some((m) => m.includes('docker.sock')) ? 'Blocked docker.sock bind mount' : 'No socket mount' },
      { id: 'no_host_root_mount', passed: !mounts.some((m) => /^(- )?\/(:|$)|\/etc(:|\/|$)|\/proc|\/sys|\/root/.test(m.trim())), severity: 'critical', message: mounts.some((m) => /^(- )?\/(:|$)/.test(m.trim())) ? 'Blocked host root mount (- /:/host:rw — Coolify <=beta.420.6 vector)' : 'No sensitive host mount' },
      { id: 'no_dangerous_caps', passed: !caps.some((c: string) => ['SYS_ADMIN', 'SYS_PTRACE', 'NET_ADMIN', 'ALL'].includes(c)), severity: 'high', message: 'Linux capabilities restricted' },
      { id: 'no_latest_tag', passed: Boolean(img && !img.endsWith(':latest') && (img.includes(':') || img.includes('@sha256:'))), severity: 'medium', message: img.endsWith(':latest') || !img.includes(':') ? `Mutable :latest or untagged image "${img || 'none'}"` : 'Immutable image tag pinned' },
      { id: 'require_non_root_uid', passed: spec.uid != null ? Number(spec.uid) > 0 : (spec.user != null && String(spec.user) !== '0' && String(spec.user) !== 'root'), severity: 'high', message: 'Non-root numeric UID verified' },
      { id: 'require_resource_limits', passed: Number(spec.memoryLimitMb) > 0 && Number(spec.cpuLimit) > 0, severity: 'medium', message: 'Memory and CPU limits declared' },
      { id: 'require_healthcheck', passed: Boolean(spec.healthcheck || spec.healthcheckPath), severity: 'medium', message: 'Healthcheck probe declared' },
      { id: 'require_signed_attestation', passed: Boolean(spec.attestationVerified), severity: 'medium', message: spec.attestationVerified ? 'SLSA v1.1 Ed25519 attestation verified' : 'SLSA attestation not yet attached' },
      { id: 'no_public_db_or_panel_bind', passed: !ports.some((p) => /^(0\.0\.0\.0|::):(3000|5432|3306|6379|27017|11434)/.test(p)), severity: 'critical', message: ports.some((p) => /^(0\.0\.0\.0|::):(3000|5432|3306|6379|27017|11434)/.test(p)) ? 'Blocked public 0.0.0.0 bind on sensitive DB/panel port (dokploy#2661)' : 'No public DB/panel port binds' },
    ];
    const enforcedViolations: any[] = [];
    const auditWarnings: any[] = [];
    const passedRules: any[] = [];
    for (const c of checks) {
      const mode = rules[c.id] || 'audit';
      if (mode === 'off' || c.passed) passedRules.push({ ...c, mode });
      else if (mode === 'enforce') enforcedViolations.push({ ...c, mode });
      else auditWarnings.push({ ...c, mode });
    }
    const allowed = enforcedViolations.length === 0;
    const decision = !allowed ? 'DENY' : (auditWarnings.length > 0 ? 'AUDIT_WARN' : 'ALLOW');
    const score = Math.round((passedRules.length / checks.length) * 100);
    const out = { ok: true, allowed, decision, preset: s.admissionPolicy.preset, score, totalRules: checks.length, enforcedViolations, auditWarnings, passedRules };
    if (body.enforceStatus === true && !allowed) {
      return jsonResponse({ ...out, code: 'ADMISSION_DENIED' }, 422);
    }
    return jsonResponse(out);
  }

  if (pathname === '/api/compliance/bundle/latest' && method === 'GET') {
    return jsonResponse(s.latestComplianceBundle);
  }
  if (pathname === '/api/compliance/bundle' && method === 'POST') {
    const fw = String(body.framework || 'all').toLowerCase();
    const allControls = s.latestComplianceBundle.payload.controls;
    const filtered = fw === 'all'
      ? allControls
      : allControls.filter((c: any) => Array.isArray(c.controlIds) && c.controlIds.some((id: string) => id.toLowerCase().startsWith(fw === 'iso27001' ? 'iso' : fw)));
    const nextBundle = {
      ...s.latestComplianceBundle,
      bundleId: `cmp_${Date.now().toString(36)}`,
      framework: fw,
      generatedAt: nowIso(),
      payload: {
        ...s.latestComplianceBundle.payload,
        bundleId: `cmp_${Date.now().toString(36)}`,
        framework: fw,
        generatedAt: nowIso(),
        controls: filtered.length > 0 ? filtered : allControls,
      },
    };
    s.latestComplianceBundle = nextBundle;
    return jsonResponse(nextBundle, 201);
  }
  if (pathname === '/api/compliance/bundle/verify' && method === 'POST') {
    const b = body.bundle || body;
    const valid = Boolean(b && b.payloadSha256 && b.signatureB64 && b.payloadSha256 === s.latestComplianceBundle.payloadSha256);
    return jsonResponse({
      ok: true,
      valid,
      reason: valid ? null : 'PAYLOAD_SHA256_MISMATCH',
      payloadSha256: b?.payloadSha256 || s.latestComplianceBundle.payloadSha256,
    });
  }

  if (pathname === '/api/edge/experiments' && method === 'GET') {
    return jsonResponse({ ok: true, experiments: s.edgeExperiments });
  }
  if (pathname === '/api/edge/experiments' && method === 'POST') {
    const isGeo = Array.isArray(body.regions) && body.regions.length > 0;
    const id = String(body.id || `exp_${Date.now().toString(36)}`);
    const hostname = String(body.hostname || 'app.acme-demo.dev');
    const variants = Array.isArray(body.variants) && body.variants.length > 0
      ? body.variants
      : [
          { name: 'control', upstream: '127.0.0.1:3000', weight: 50 },
          { name: 'variant-b', upstream: '127.0.0.1:3001', weight: 50 },
        ];
    const rec = isGeo
      ? {
          id,
          projectId: body.projectId || 'proj_acme_web',
          name: String(body.name || 'Regional Geo-IP Route'),
          kind: 'geo',
          hostname,
          headerName: String(body.headerName || 'CF-IPCountry'),
          regions: body.regions,
          defaultUpstream: String(body.defaultUpstream || '127.0.0.1:3000'),
          killed: false,
          compiledCaddy: {
            subroutes: [
              ...body.regions.map((r: any) => ({
                match: [{ header: { [String(body.headerName || 'CF-IPCountry')]: r.countries } }],
                handle: [{ handler: 'reverse_proxy', upstreams: [{ dial: r.upstream }] }],
                terminal: true,
              })),
              { handle: [{ handler: 'reverse_proxy', upstreams: [{ dial: String(body.defaultUpstream || '127.0.0.1:3000') }] }] },
            ],
          },
          updatedAt: nowIso(),
        }
      : {
          id,
          projectId: body.projectId || 'proj_acme_web',
          name: String(body.name || 'Sticky Cookie A/B Split'),
          kind: 'ab',
          hostname,
          stickyMode: String(body.stickyMode || 'cookie'),
          cookieName: String(body.cookieName || `ckb_ab_${id.slice(-6)}`),
          variants,
          killed: false,
          compiledCaddy: {
            route: {
              match: [{ host: [hostname] }],
              handle: [{
                handler: 'reverse_proxy',
                upstreams: variants.map((v: any) => ({ dial: v.upstream })),
                load_balancing: {
                  selection_policy: {
                    policy: String(body.stickyMode || 'cookie'),
                    name: String(body.cookieName || `ckb_ab_${id.slice(-6)}`),
                    fallback: { policy: 'weighted_round_robin', weights: variants.map((v: any) => Number(v.weight) || 50) },
                  },
                },
              }],
              terminal: true,
            },
          },
          updatedAt: nowIso(),
        };
    s.edgeExperiments = [rec, ...s.edgeExperiments.filter((e) => e.id !== id)];
    return jsonResponse({ ok: true, experiment: rec }, 201);
  }
  const killExpMatch = pathname.match(/^\/api\/edge\/experiments\/([^/]+)\/kill-switch$/);
  if (killExpMatch && method === 'POST') {
    const eid = decodeURIComponent(killExpMatch[1]);
    const target = s.edgeExperiments.find((e) => e.id === eid);
    if (!target) return jsonResponse({ error: 'Experiment not found' }, 404);
    target.killed = true;
    target.killReason = String(body.reason || 'operator_kill_switch');
    target.updatedAt = nowIso();
    const ctrlUpstream = target.variants?.[0]?.upstream || target.defaultUpstream || '127.0.0.1:3000';
    target.compiledCaddy = {
      route: {
        match: [{ host: [target.hostname] }],
        handle: [{ handler: 'reverse_proxy', upstreams: [{ dial: ctrlUpstream }] }],
        terminal: true,
      },
    };
    return jsonResponse({ ok: true, killed: true, id: target.id, controlUpstream: ctrlUpstream, experiment: target });
  }

  if (pathname === '/api/volumes/migrations' && method === 'GET') {
    return jsonResponse({ ok: true, migrations: s.volumeMigrations });
  }
  if (pathname === '/api/volumes/migrations/plan' && method === 'POST') {
    const volName = String(body.volumeName || '').trim();
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(volName)) {
      return jsonResponse({ error: `UNSAFE_VOLUME_NAME: Rejected shell metacharacters or unsafe volume name "${volName}" (CVE-2025-66213 guard).` }, 400);
    }
    const mountPath = String(body.mountPath || '/var/lib/postgresql/data').trim();
    if (mountPath.includes('..') || mountPath === '/' || /^\/(etc|proc|sys|var\/run)/.test(mountPath)) {
      return jsonResponse({ error: `UNSAFE_MOUNT_PATH: Rejected traversal or sensitive host mount "${mountPath}".` }, 400);
    }
    const uid = Number.isInteger(Number(body.uid)) ? Number(body.uid) : 999;
    const gid = Number.isInteger(Number(body.gid)) ? Number(body.gid) : 999;
    const targetHost = String(body.targetHost || '198.51.100.42').trim();
    const mig = {
      id: `volmig_${Date.now().toString(36)}`,
      projectId: body.projectId || 'proj_acme_web',
      volumeName: volName,
      mountPath,
      sourceHost: String(body.sourceHost || 'local'),
      targetHost,
      uid,
      gid,
      containerName: String(body.containerName || 'culkibo-db-pg-main'),
      estimatedMb: Number(body.estimatedMb) || 256,
      status: 'planned',
      numericOwnerPreserved: true,
      zeroShell: true,
      plan: {
        zeroShell: true,
        numericOwnerPreserved: true,
        uidGid: `${uid}:${gid}`,
        retainSourceVolume: true,
        requiredFreeSpaceMb: Math.ceil((Number(body.estimatedMb) || 256) * 2.2),
        phases: [
          { phase: 1, id: 'pre_sync', title: 'Warm pre-sync & disk headroom check', commands: [{ program: 'docker', args: ['volume', 'inspect', volName] }, { program: 'ssh', args: ['-o', 'BatchMode=yes', `root@${targetHost}`, 'docker', 'volume', 'create', volName] }] },
          { phase: 2, id: 'quiesce_snapshot', title: `Quiesce + tar --numeric-owner (${uid}:${gid}) + SHA-256`, commands: [{ program: 'docker', args: ['run', '--rm', '--mount', `type=volume,source=${volName},target=/source,readonly`, 'alpine:3.20', 'tar', '--numeric-owner', '-czf', `/backup/${volName}.tar.gz`, '-C', '/source', '.'] }, { program: 'sha256sum', args: [`/var/tmp/culkibo-volmig/${volName}/${volName}.tar.gz`] }] },
          { phase: 3, id: 'ssh_stream_transfer', title: `SSH ControlMaster zero-shell transfer to ${targetHost}`, commands: [{ program: 'scp', args: ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', `/var/tmp/culkibo-volmig/${volName}/${volName}.tar.gz`, `root@${targetHost}:/var/tmp/culkibo-volmig/${volName}/`] }] },
          { phase: 4, id: 'verify_and_cutover', title: `Target SHA-256 verify + tar --numeric-owner extract + stat ${uid}:${gid}`, commands: [{ program: 'ssh', args: ['-o', 'BatchMode=yes', `root@${targetHost}`, 'sha256sum', '-c', `/var/tmp/culkibo-volmig/${volName}/${volName}.sha256`] }, { program: 'ssh', args: ['-o', 'BatchMode=yes', `root@${targetHost}`, 'docker', 'run', '--rm', '--mount', `type=volume,source=${volName},target=/target`, 'alpine:3.20', 'tar', '--numeric-owner', '-xzf', `/backup/${volName}.tar.gz`, '-C', '/target'] }] },
        ],
      },
      createdAt: nowIso(),
    };
    s.volumeMigrations = [mig, ...s.volumeMigrations].slice(0, 20);
    return jsonResponse({ ok: true, migration: mig }, 201);
  }

  // --- Cycle-12 Reliability & Security APIs (Synthetic/TLS Sentinel, SQL Linter, Worker Autoscaler, SPDX Auditor, Seccomp/runc) ---
  if (pathname === '/api/uptime/synthetic/flows' && method === 'GET') {
    return jsonResponse({ ok: true, flows: s.syntheticFlows });
  }
  if (pathname === '/api/uptime/synthetic/flows' && method === 'POST') {
    const id = String(body.id || `flow_${Date.now().toString(36)}`);
    const saved = { id, name: String(body.name || 'Synthetic API Flow'), steps: Array.isArray(body.steps) ? body.steps : [], lastRunAt: null, lastOk: null, createdAt: nowIso() };
    s.syntheticFlows = [saved, ...s.syntheticFlows.filter((f) => f.id !== id)];
    return jsonResponse({ ok: true, flow: saved }, 201);
  }
  if (pathname === '/api/uptime/synthetic/run' && method === 'POST') {
    const flow = s.syntheticFlows.find((f) => f.id === body.flowId) || s.syntheticFlows[0];
    if (flow) {
      flow.lastRunAt = nowIso();
      flow.lastOk = true;
      flow.lastLatencyMs = 58;
    }
    return jsonResponse({
      ok: true,
      flowId: flow?.id || 'flow_demo_auth_checkout',
      flowName: flow?.name || 'Auth Login → JWT Session → Orders API',
      totalLatencyMs: 58,
      failedStep: null,
      steps: [
        { name: 'POST /api/auth/token', method: 'POST', url: 'https://api.acme-demo.dev/v1/auth/token', status: 200, latencyMs: 31, ok: true, errors: [], extractedKeys: ['token ([REDACTED])'] },
        { name: 'GET /v1/orders/health', method: 'GET', url: 'https://api.acme-demo.dev/v1/orders/health', status: 200, latencyMs: 27, ok: true, errors: [], extractedKeys: [] },
      ],
      checkedAt: nowIso(),
    });
  }
  if (pathname === '/api/uptime/tls-sentinel' && method === 'POST') {
    const host = String(body.host || 'app.acme-demo.dev').trim();
    return jsonResponse({
      host,
      port: Number(body.port) || 443,
      daysRemaining: 84,
      validFrom: nowIso(-1000 * 60 * 60 * 24 * 6),
      validTo: nowIso(1000 * 60 * 60 * 24 * 84),
      subject: `CN=${host}`,
      issuer: "Let's Encrypt E6",
      fingerprintSha256: 'A4:7F:19:0C:E2:44:8B:91:3D:66:20:5E:1F:8A:90:C3:41:2B:7E:05:89:D1:3A:4C:6F:11:9E:22:7C:8D:04:B2',
      protocol: 'TLSv1.3',
      sanList: [host, `*.${host.replace(/^[^.]+\./, '')}`],
      sanMatched: true,
      fingerprintDrifted: false,
      issuerDrifted: false,
      status: 'OK',
      alerts: [],
    });
  }
  if (pathname === '/api/databases/lint-sql' && method === 'POST') {
    const rawSql = String(body.sql || '');
    const stripped = rawSql
      .replace(/--[^\n]*/g, ' ')
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/'(?:''|[^'])*'/g, "''");
    const stmts = stripped.split(';').map((x) => x.trim()).filter(Boolean);
    const hasLockTimeout = /\bSET\s+(?:LOCAL\s+)?lock_timeout\b/i.test(stripped);
    const hasStmtTimeout = /\bSET\s+(?:LOCAL\s+)?statement_timeout\b/i.test(stripped);
    const blockers: any[] = [];
    const warnings: any[] = [];
    const rewriteHints: string[] = [];
    const hasDdl = /\b(CREATE|ALTER|DROP)\b/i.test(stripped);
    if (/\bCREATE\s+(?:UNIQUE\s+)?INDEX\b(?![\s\S]{0,40}\bCONCURRENTLY\b)/i.test(stripped)) {
      blockers.push({ rule: 'CREATE_INDEX_NOT_CONCURRENT', severity: 'critical', message: 'CREATE INDEX without CONCURRENTLY acquires SHARE lock and blocks writes.' });
      rewriteHints.push('Use CREATE INDEX CONCURRENTLY idx_name ON table(col);');
    }
    if (/\bDROP\s+INDEX\b(?![\s\S]{0,30}\bCONCURRENTLY\b)/i.test(stripped)) {
      blockers.push({ rule: 'DROP_INDEX_NOT_CONCURRENT', severity: 'high', message: 'DROP INDEX without CONCURRENTLY acquires ACCESS EXCLUSIVE lock.' });
      rewriteHints.push('Use DROP INDEX CONCURRENTLY IF EXISTS idx_name;');
    }
    if (/\bDROP\s+(?:TABLE|COLUMN)\b/i.test(stripped)) {
      blockers.push({ rule: 'DESTRUCTIVE_DROP_COLUMN_OR_TABLE', severity: 'critical', message: 'Destructive DROP COLUMN / DROP TABLE breaks rolling zero-downtime replicas.' });
      rewriteHints.push('Follow expand-and-contract: stop reading column in app code first, drop in a follow-up release.');
    }
    if (/\bALTER\s+TABLE\b[\s\S]*\bADD\s+(?:CONSTRAINT\s+\S+\s+)?(?:FOREIGN\s+KEY|CHECK)\b(?![\s\S]*\bNOT\s+VALID\b)/i.test(stripped)) {
      blockers.push({ rule: 'UNSAFE_ADD_CONSTRAINT', severity: 'high', message: 'ADD CONSTRAINT (FOREIGN KEY / CHECK) without NOT VALID scans full table under lock.' });
      rewriteHints.push('Add with NOT VALID, then run ALTER TABLE ... VALIDATE CONSTRAINT in a separate transaction.');
    }
    if (/\bALTER\s+TABLE\b[\s\S]*\bALTER\s+COLUMN\b[\s\S]*\bTYPE\b/i.test(stripped)) {
      blockers.push({ rule: 'ALTER_COLUMN_TYPE_REWRITE', severity: 'critical', message: 'ALTER COLUMN TYPE triggers full table rewrite under ACCESS EXCLUSIVE lock.' });
      rewriteHints.push('Add a new typed column, backfill in batches, swap in app, then retire old column.');
    }
    if (/\bADD\s+COLUMN\b[\s\S]*\bDEFAULT\b[\s\S]*\b(now|random|gen_random_uuid|uuid_generate_v4|clock_timestamp|current_timestamp)\b/i.test(stripped)) {
      blockers.push({ rule: 'VOLATILE_ADD_COLUMN_DEFAULT', severity: 'high', message: 'Volatile ADD COLUMN DEFAULT forces full table rewrite.' });
      rewriteHints.push('Add nullable column first, set DEFAULT for new rows, then backfill existing rows in chunks.');
    }
    if (hasDdl && !hasLockTimeout) {
      blockers.push({ rule: 'MISSING_LOCK_TIMEOUT', severity: 'high', message: 'DDL migration lacks SET lock_timeout — blocked lock queue will stall all app queries.' });
      rewriteHints.push("Prepend SET lock_timeout = '5s'; at top of migration.");
    }
    if (hasDdl && !hasStmtTimeout) {
      warnings.push({ rule: 'MISSING_STATEMENT_TIMEOUT', severity: 'low', message: "Consider adding SET statement_timeout = '30s'; to bound long DDL runs." });
    }
    const safe = blockers.length === 0;
    const score = Math.max(0, 100 - blockers.length * 22 - warnings.length * 4);
    return jsonResponse({ safe, score, blockers, warnings, rewriteHints, analyzedStatements: stmts.length, hasLockTimeout, hasStatementTimeout: hasStmtTimeout });
  }
  const autoMatch = pathname.match(/^\/api\/projects\/([^/]+)\/autoscaler$/);
  if (autoMatch) {
    const pid = decodeURIComponent(autoMatch[1]);
    const fallback = { projectId: pid, minReplicas: 1, maxReplicas: 6, scaleUpQueueThreshold: 40, scaleDownQueueThreshold: 8, scaleUpCooldownSec: 60, scaleDownCooldownSec: 180, perReplicaRamMb: 384, reserveHostRamMb: 512, breakerQueueThreshold: 250, breakerRetryAfterSec: 15 };
    if (method === 'PUT') {
      s.autoscalerPolicies[pid] = { ...(s.autoscalerPolicies[pid] || fallback), ...body, projectId: pid };
      return jsonResponse({ ok: true, policy: s.autoscalerPolicies[pid] });
    }
    return jsonResponse({ ok: true, policy: s.autoscalerPolicies[pid] || fallback });
  }
  const autoEvalMatch = pathname.match(/^\/api\/projects\/([^/]+)\/autoscaler\/evaluate$/);
  if (autoEvalMatch && method === 'POST') {
    const pid = decodeURIComponent(autoEvalMatch[1]);
    const pol = s.autoscalerPolicies[pid] || { projectId: pid, minReplicas: 1, maxReplicas: 6, scaleUpQueueThreshold: 40, scaleDownQueueThreshold: 8, scaleUpCooldownSec: 60, scaleDownCooldownSec: 180, perReplicaRamMb: 384, reserveHostRamMb: 512, breakerQueueThreshold: 250, breakerRetryAfterSec: 15 };
    const queueDepth = Math.max(0, Number(body.queueDepth) || 0);
    const currentReplicas = Math.max(1, Number(body.currentReplicas) || 1);
    const hostFreeRamMb = Math.max(0, Number(body.hostFreeRamMb ?? 2048));
    const perReplicaRamMb = Math.max(64, Number(body.perReplicaRamMb || pol.perReplicaRamMb || 384));
    const maxSafeReplicas = Math.max(pol.minReplicas, Math.floor(Math.max(0, hostFreeRamMb - pol.reserveHostRamMb) / perReplicaRamMb));
    const breakerTripped = queueDepth >= pol.breakerQueueThreshold || hostFreeRamMb < pol.reserveHostRamMb;
    let desiredReplicas = currentReplicas;
    let action = 'HOLD';
    let reason = 'HYSTERESIS_HOLD';
    if (queueDepth >= pol.scaleUpQueueThreshold) {
      desiredReplicas = Math.min(pol.maxReplicas, currentReplicas + Math.max(1, Math.ceil((queueDepth - pol.scaleUpQueueThreshold) / 30)));
      action = 'SCALE_UP';
      reason = 'SCALE_UP';
    } else if (queueDepth <= pol.scaleDownQueueThreshold && currentReplicas > pol.minReplicas) {
      desiredReplicas = Math.max(pol.minReplicas, currentReplicas - 1);
      action = 'SCALE_DOWN';
      reason = 'SCALE_DOWN';
    }
    let targetReplicas = Math.min(desiredReplicas, maxSafeReplicas);
    if (targetReplicas < desiredReplicas) reason = 'MEMORY_CEILING_CAPPED';
    if (breakerTripped) {
      action = targetReplicas > currentReplicas ? 'SCALE_UP' : 'HOLD';
      reason = 'BREAKER_OPEN';
    }
    return jsonResponse({
      projectId: pid,
      action,
      reason,
      currentReplicas,
      desiredReplicas,
      targetReplicas,
      maxSafeReplicas,
      memoryHeadroomMb: Math.max(0, hostFreeRamMb - pol.reserveHostRamMb),
      cooldownRemainingSec: 0,
      circuitBreaker: breakerTripped
        ? { state: 'OPEN', httpStatus: 503, retryAfterSec: pol.breakerRetryAfterSec, headers: { 'Retry-After': String(pol.breakerRetryAfterSec) } }
        : { state: 'CLOSED', httpStatus: null, retryAfterSec: null, headers: {} },
      policy: pol,
      evaluatedAt: nowIso(),
    });
  }
  if (pathname === '/api/security/license-audit' && method === 'POST') {
    const policy = String(body.policy || 'saas-strict');
    const isStrict = policy === 'saas-strict';
    const isAuditOnly = policy === 'audit-only';
    const countsByCategory = { permissive: 11, weak_copyleft: 1, strong_copyleft: 0, source_available: 0, unknown: 0 };
    return jsonResponse({
      compliant: true,
      policy,
      score: isStrict ? 98 : isAuditOnly ? 100 : 100,
      totalComponents: 12,
      countsByCategory,
      violations: [],
      warnings: isStrict ? [{ component: 'culkibo-collector-optional', license: 'MPL-2.0', category: 'weak_copyleft', message: 'Weak copyleft file-level disclosure (permitted under saas-strict).' }] : [],
      auditedAt: nowIso(),
    });
  }
  if (pathname === '/api/security/seccomp/profile' && method === 'POST') {
    const stack = String(body.stack || 'node').toLowerCase();
    if (stack === 'unconfined' || String(body.mode || '').toLowerCase() === 'unconfined') {
      return jsonResponse({ error: 'SECCOMP_UNCONFINED_FORBIDDEN: seccomp=unconfined is strictly prohibited.', code: 'SECCOMP_UNCONFINED_FORBIDDEN' }, 400);
    }
    const blockedSyscalls = ['io_uring_setup', 'io_uring_enter', 'io_uring_register', 'ptrace', 'mount', 'umount2', 'pivot_root', 'unshare', 'setns', 'keyctl', 'bpf', 'kexec_load', 'init_module', 'reboot'];
    const baseAllow = ['read', 'write', 'close', 'fstat', 'mmap', 'mprotect', 'munmap', 'brk', 'rt_sigaction', 'rt_sigprocmask', 'epoll_wait', 'epoll_ctl', 'socket', 'connect', 'accept4', 'sendto', 'recvfrom', 'futex', 'clock_gettime', 'exit_group'];
    const profile = {
      defaultAction: 'SCMP_ACT_ERRNO',
      architectures: ['SCMP_ARCH_X86_64', 'SCMP_ARCH_AARCH64'],
      syscalls: [
        { names: baseAllow, action: 'SCMP_ACT_ALLOW' },
        { names: blockedSyscalls, action: 'SCMP_ACT_ERRNO', errnoRet: 1 },
      ],
    };
    return jsonResponse({
      stack,
      profile,
      allowedCount: stack === 'static-caddy' ? 42 : stack === 'rust' ? 54 : stack === 'go' ? 68 : stack === 'python' ? 84 : 76,
      blockedSyscalls,
      dockerSecurityOpt: [
        '--security-opt', 'no-new-privileges:true',
        '--security-opt', `seccomp=/etc/culkibo/seccomp-${stack}.json`,
      ],
      sha256: '7e4c9a12b8d0f3e6a1c5b9d2e4f8a0c3d5e7f9a1b3c5d7e9f1a3b5c7d9e1f3a5',
    });
  }
  if (pathname === '/api/security/runc-audit' && method === 'POST') {
    const raw = String(body.version || '1.3.3').trim();
    const m = raw.match(/(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?/i);
    if (!m) return jsonResponse({ version: raw, parsedVersion: null, status: 'UNKNOWN', vulnerable: false, cves: [], fixedIn: '1.2.8 / 1.3.3 / 1.4.0-rc.3' });
    const maj = Number(m[1]);
    const min = Number(m[2]);
    const pat = Number(m[3]);
    const rc = m[4] != null ? Number(m[4]) : null;
    const vuln = (maj === 1 && min < 2) || (maj === 1 && min === 2 && pat <= 7) || (maj === 1 && min === 3 && pat <= 2) || (maj === 1 && min === 4 && pat === 0 && rc != null && rc <= 2);
    return jsonResponse({
      version: raw,
      parsedVersion: `${maj}.${min}.${pat}${rc != null ? `-rc.${rc}` : ''}`,
      status: vuln ? 'CRITICAL' : 'PASS',
      vulnerable: vuln,
      cves: vuln ? ['CVE-2025-31133', 'CVE-2025-52565', 'CVE-2025-52881'] : [],
      fixedIn: '1.2.8 / 1.3.3 / 1.4.0-rc.3',
    });
  }

  // --- Cycle-13: Image Bloat Auditor, Cron Fencing Leases, PII Masker, OOM Forensics, On-Call Escalation ---
  if (pathname === '/api/build/image-audit' && method === 'POST') {
    const df = String(body.dockerfile || '');
    const secretLeaks: Array<{ rule: string; line: number; message: string; redactedSnippet: string }> = [];
    const findings: Array<{ rule: string; severity: string; message: string }> = [];
    const slimmingRecommendations: string[] = [];
    const lines = df.split(/\r?\n/);
    const secretPrefixRe = new RegExp(`${['sk', 'live', ''].join('_')}|${['ghp', ''].join('_')}|AKIA[0-9A-Z]{8}`, 'i');
    lines.forEach((ln, idx) => {
      if (/\b(?:ENV|ARG)\b.*(?:SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)/i.test(ln) || secretPrefixRe.test(ln)) {
        secretLeaks.push({
          rule: 'SECRET_IN_ENV_OR_ARG',
          line: idx + 1,
          message: `Hardcoded secret detected in ENV/ARG at line ${idx + 1} (value redacted; use BuildKit --mount=type=secret).`,
          redactedSnippet: ln.replace(/=.+$/, '=[REDACTED]'),
        });
      }
    });
    if (/apt-get\s+install/i.test(df) && !/rm\s+-rf\s+\/var\/lib\/apt\/lists/i.test(df)) {
      findings.push({ rule: 'UNDELETED_PACKAGE_CACHE', severity: 'medium', message: 'apt-get install leaves /var/lib/apt/lists cache in image layer.' });
      slimmingRecommendations.push('Chain && rm -rf /var/lib/apt/lists/* inside the same RUN instruction (~45 MB saved).');
    }
    if (/^FROM\s+(?:node:22|python:3\.12|golang:1\.23|ubuntu)\s*$/im.test(df)) {
      findings.push({ rule: 'HEAVY_BASE_IMAGE', severity: 'high', message: 'Full SDK base image used as final runtime stage.' });
      slimmingRecommendations.push('Switch final stage to node:22-alpine or distroless (~280 MB saved).');
    }
    if (!/\bUSER\s+(?!root\b)\S+/i.test(df)) {
      findings.push({ rule: 'MISSING_NON_ROOT_USER', severity: 'medium', message: 'Container runs as root; add USER node or USER 10001.' });
      slimmingRecommendations.push('Add non-root USER directive before CMD/ENTRYPOINT.');
    }
    if (/\bRUN\s+rm\s+-rf\b/i.test(df)) {
      findings.push({ rule: 'CROSS_LAYER_DELETE_WASTE', severity: 'medium', message: 'rm -rf in a separate RUN layer does not shrink prior image layers.' });
      slimmingRecommendations.push('Remove temporary files in the same RUN layer or isolate them in a multi-stage builder.');
    }
    const penalty = secretLeaks.length * 30 + findings.length * 14;
    const score = Math.max(8, Math.min(100, 100 - penalty));
    const savingsMb = findings.length * 85 + secretLeaks.length * 12;
    return jsonResponse({
      ok: true,
      efficiencyScore: score,
      estimatedSavingsMb: savingsMb,
      wastedBytes: savingsMb * 1024 * 1024,
      secretLeaks,
      findings,
      slimmingRecommendations: slimmingRecommendations.length > 0 ? slimmingRecommendations : ['Multi-stage alpine/non-root Dockerfile already optimal (96/100).'],
    });
  }

  const cronLeaseMatch = pathname.match(/^\/api\/crons\/([^/]+)\/(leases|lease\/acquire|lease\/complete)$/);
  if (cronLeaseMatch) {
    const jobId = decodeURIComponent(cronLeaseMatch[1]);
    const action = cronLeaseMatch[2];
    const list = s.cronLeases[jobId] || (s.cronLeases[jobId] = []);
    if (action === 'leases' && method === 'GET') {
      return jsonResponse({ ok: true, leases: list });
    }
    if (action === 'lease/acquire' && method === 'POST') {
      const slot = String(body.scheduleSlotIso || new Date().toISOString());
      const holderId = String(body.holderId || 'worker-1');
      const doneSlot = list.find((l) => l.scheduleSlotIso === slot && l.status === 'succeeded');
      if (doneSlot) {
        return jsonResponse({ ok: true, acquired: false, reason: 'ALREADY_EXECUTED_SLOT', completedLease: doneSlot });
      }
      const running = list.find((l) => l.status === 'active' && (l.expiresAtMs || 0) > Date.now());
      if (running) {
        return jsonResponse({ ok: true, acquired: false, reason: 'ALREADY_RUNNING', activeLease: running });
      }
      const maxTok = list.reduce((m, l) => Math.max(m, Number(l.fencingToken || 0)), 42);
      const created = {
        id: `lease_demo_${maxTok + 1}`,
        jobId,
        scheduleSlotIso: slot,
        holderId,
        fencingToken: maxTok + 1,
        status: 'active',
        acquiredAtMs: Date.now(),
        expiresAtMs: Date.now() + Number(body.ttlSec || 300) * 1000,
      };
      list.unshift(created);
      return jsonResponse({ ok: true, acquired: true, lease: created });
    }
    if (action === 'lease/complete' && method === 'POST') {
      const target = list.find((l) => l.id === body.leaseId);
      if (!target) return jsonResponse({ ok: false, reason: 'LEASE_NOT_FOUND' });
      if (Number(body.fencingToken) !== Number(target.fencingToken)) {
        return jsonResponse({ ok: false, reason: 'STALE_FENCING_TOKEN' });
      }
      target.status = body.status || 'succeeded';
      target.completedAtMs = Date.now();
      return jsonResponse({ ok: true, lease: target });
    }
  }

  if (pathname === '/api/databases/pii-mask' && method === 'POST') {
    const seed = String(body.seed || 'culkibo-preview-seed');
    const hash8 = (val: string) => {
      let h = 2166136261;
      const str = `${seed}:${val}`;
      for (let i = 0; i < str.length; i++) {
        h ^= str.charCodeAt(i);
        h = Math.imul(h, 16777619);
      }
      return (h >>> 0).toString(16).padStart(8, '0');
    };
    const fieldsSet = new Set<string>();
    let maskedCount = 0;
    const maskStr = (key: string, raw: string) => {
      if (/@/.test(raw)) {
        fieldsSet.add(key);
        maskedCount += 1;
        return `u_${hash8(raw)}@masked.invalid`;
      }
      if (/^\d{3}-\d{2}-\d{4}$/.test(raw)) {
        fieldsSet.add(key);
        maskedCount += 1;
        return `000-00-${String(parseInt(hash8(raw).slice(0, 4), 16) % 9000 + 1000)}`;
      }
      if (/^\+?\d[\d\s-]{8,}$/.test(raw)) {
        fieldsSet.add(key);
        maskedCount += 1;
        return `+1-555-${String(parseInt(hash8(raw).slice(0, 4), 16) % 9000 + 1000)}`;
      }
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(raw)) {
        fieldsSet.add(key);
        maskedCount += 1;
        return `192.0.2.${(parseInt(hash8(raw).slice(0, 2), 16) % 250) + 1}`;
      }
      if (/name/i.test(key)) {
        fieldsSet.add(key);
        maskedCount += 1;
        return `User_${hash8(raw).slice(0, 6)}`;
      }
      return raw;
    };
    if (Array.isArray(body.rows)) {
      const maskedRows = body.rows.map((row: Record<string, unknown>) => {
        const out: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(row || {})) {
          out[k] = typeof v === 'string' ? maskStr(k, v) : v;
        }
        return out;
      });
      const fieldsMasked = Array.from(fieldsSet);
      const pgAnonDdl = [
        'CREATE EXTENSION IF NOT EXISTS anon CASCADE;',
        ...fieldsMasked.map((col) =>
          `SECURITY LABEL FOR anon ON COLUMN public.users.${col} IS 'MASKED WITH FUNCTION anon.pseudo_email(${col})';`
        ),
      ].join('\n');
      return jsonResponse({ ok: true, maskedRows, maskedCount, fieldsMasked, zeroPiiLeaked: true, pgAnonDdl });
    }
    const sqlDump = String(body.sqlDump || '');
    const maskedSql = sqlDump
      .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, (m) => {
        maskedCount += 1;
        fieldsSet.add('email');
        return `u_${hash8(m)}@masked.invalid`;
      })
      .replace(/\b\d{3}-\d{2}-\d{4}\b/g, (m) => {
        maskedCount += 1;
        fieldsSet.add('ssn');
        return `000-00-${String(parseInt(hash8(m).slice(0, 4), 16) % 9000 + 1000)}`;
      });
    return jsonResponse({
      ok: true,
      maskedSql,
      maskedCount,
      fieldsMasked: Array.from(fieldsSet),
      zeroPiiLeaked: true,
      pgAnonDdl: "CREATE EXTENSION IF NOT EXISTS anon CASCADE;\nSECURITY LABEL FOR anon ON COLUMN public.users.email IS 'MASKED WITH FUNCTION anon.pseudo_email(email)';",
    });
  }

  const forensicsMatch = pathname.match(/^\/api\/projects\/([^/]+)\/forensics\/classify$/);
  if (forensicsMatch && method === 'POST') {
    const exitCode = Number(body.exitCode ?? 137);
    const oomKilled = Boolean(body.oomKilled);
    const cgroupOomKills = Number(body.cgroupOomKills ?? 0);
    const restartCount = Number(body.restartCount ?? 0);
    const memLim = Number(body.memoryLimitMb ?? 512) || 512;
    const memPeak = Number(body.memoryPeakMb ?? memLim) || memLim;
    const historicalOnly = Boolean(body.historicalOnly);
    const backoffSec = Math.min(300, Math.pow(2, Math.min(8, restartCount)) * 5);

    if (historicalOnly) {
      return jsonResponse({
        ok: true,
        classification: 'STALE_HISTORICAL_TASK_IGNORED',
        severity: 'info',
        confidence: 0.99,
        rootCause: 'Exit 137 originated from a historical stopped container task — active deployment replica is healthy.',
        ignoreForRollback: true,
        recommendedMemoryMb: null,
        backoffSec: 0,
        remediationActions: ['No rollback triggered (Portainer stale-task guard active).', 'Archive historical container metadata after retention window.'],
      });
    }
    if (exitCode === 137 && (oomKilled || cgroupOomKills > 0)) {
      const recMb = Math.ceil(Math.max(memLim, memPeak) * 1.5);
      return jsonResponse({
        ok: true,
        classification: 'CGROUP_OOM_KILL',
        severity: 'critical',
        confidence: 0.98,
        rootCause: `Linux cgroup OOM killer terminated process (exit 137, oomKilled=true, peak=${memPeak} MB / limit=${memLim} MB).`,
        ignoreForRollback: false,
        recommendedMemoryMb: recMb,
        backoffSec,
        remediationActions: [
          `Raise container memory limit from ${memLim} MB to ${recMb} MB.`,
          'Set NODE_OPTIONS=--max-old-space-size to 75% of cgroup limit to prevent native RSS spikes.',
        ],
      });
    }
    if (exitCode === 137) {
      return jsonResponse({
        ok: true,
        classification: 'FORCED_SIGKILL_TIMEOUT',
        severity: 'high',
        confidence: 0.94,
        rootCause: 'Exit 137 with oomKilled=false and 0 cgroup OOM kills — container ignored SIGTERM and was SIGKILLed after stop grace timeout.',
        ignoreForRollback: false,
        recommendedMemoryMb: null,
        backoffSec,
        remediationActions: [
          'Attach a SIGTERM handler to close HTTP keep-alive & DB pools cleanly within stop_grace_period.',
          'Use exec-form CMD ["node", "server.js"] instead of shell form so PID 1 receives SIGTERM.',
        ],
      });
    }
    return jsonResponse({
      ok: true,
      classification: exitCode === 139 ? 'SEGFAULT_ARCH_OR_NATIVE' : exitCode === 143 ? 'GRACEFUL_SIGTERM_EXITED' : 'HEALTHCHECK_CRASH_LOOP',
      severity: exitCode === 143 ? 'info' : 'high',
      confidence: 0.9,
      rootCause: `Container exited with code ${exitCode}.`,
      ignoreForRollback: exitCode === 143,
      recommendedMemoryMb: null,
      backoffSec,
      remediationActions: ['Inspect structured container logs and verify healthcheck timeout/interval.'],
    });
  }

  if (pathname === '/api/oncall/policies' && method === 'GET') {
    return jsonResponse({ ok: true, policies: s.oncallPolicies });
  }
  if (pathname === '/api/oncall/policies' && method === 'POST') {
    const pol = {
      id: body.id || `pol_${Date.now()}`,
      name: String(body.name || 'SRE Escalation Policy'),
      shiftDurationHours: Number(body.shiftDurationHours || 24),
      rotationStartMs: Date.now(),
      ackTimeoutSec: Number(body.ackTimeoutSec || 300),
      flappingWindowSec: Number(body.flappingWindowSec || 600),
      flappingThreshold: Number(body.flappingThreshold || 3),
      currentResponder: body.tiers?.[0]?.responders?.[0] || 'alice',
      tiers: Array.isArray(body.tiers) ? body.tiers : [{ tier: 1, responders: ['alice', 'bob'] }],
    };
    s.oncallPolicies = [pol, ...s.oncallPolicies.filter((p) => p.id !== pol.id)];
    return jsonResponse({ ok: true, policy: pol });
  }
  if (pathname === '/api/oncall/incidents' && method === 'GET') {
    return jsonResponse({ ok: true, incidents: s.oncallIncidents });
  }
  if (pathname === '/api/oncall/ingest' && method === 'POST') {
    const fp = String(body.fingerprint || 'fp_default');
    const existing = s.oncallIncidents.find((i) => i.fingerprint === fp && i.status !== 'resolved');
    if (existing) {
      existing.occurrences = Number(existing.occurrences || 1) + 1;
      existing.updatedAtMs = Date.now();
      return jsonResponse({ ok: true, incident: existing, deduplicated: true, suppressed: true, flapping: false });
    }
    const created = {
      id: `ocinc_${Date.now()}`,
      policyId: String(body.policyId || 'pol_prod_primary'),
      fingerprint: fp,
      projectId: body.projectId || 'proj_edge_rust',
      severity: String(body.severity || 'critical'),
      title: String(body.title || 'Production Service Alert'),
      status: 'firing',
      currentTier: 1,
      assignedResponder: 'alice',
      occurrences: 1,
      flapping: false,
      acknowledgedBy: null,
      acknowledgedAtMs: null,
      createdAtMs: Date.now(),
      updatedAtMs: Date.now(),
    };
    s.oncallIncidents.unshift(created);
    return jsonResponse({ ok: true, incident: created, deduplicated: false, suppressed: false, flapping: false });
  }
  const ackMatch = pathname.match(/^\/api\/oncall\/incidents\/([^/]+)\/ack$/);
  if (ackMatch && method === 'POST') {
    const incId = decodeURIComponent(ackMatch[1]);
    const target = s.oncallIncidents.find((i) => i.id === incId);
    if (target) {
      target.status = 'acknowledged';
      target.acknowledgedBy = String(body.actor || 'owner@acme-demo.dev');
      target.acknowledgedAtMs = Date.now();
      target.updatedAtMs = Date.now();
      return jsonResponse({ ok: true, incident: target });
    }
    return jsonResponse({ ok: true, incident: { id: incId, status: 'acknowledged', occurrences: 1, title: 'Incident', fingerprint: 'fp', policyId: 'pol_prod_primary', severity: 'high' } });
  }
  if (pathname === '/api/oncall/evaluate' && method === 'POST') {
    return jsonResponse({ ok: true, escalated: [], incidents: s.oncallIncidents });
  }

  // --- Cycle-14: Pre-Deploy Secret Gate, DB Replica Failover, Egress Firewall, Multi-Arch Planner, Chaos GameDay ---
  if (pathname === '/api/security/predeploy-secret-scan' && method === 'POST') {
    const mode = String(body.mode || 'enforce');
    const diffText = String(body.diffText || '');
    const lines = diffText.split(/\r?\n/);
    const payPrefix = ['sk', 'live', ''].join('_');
    const ghPrefix = ['ghp', ''].join('_');
    const findings: Array<{ location: string; line: number; ruleId: string; severity: string; entropy: number; redactedPreview: string; fingerprintSha256: string }> = [];
    const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const shaRe = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/i;
    const shannon = (str: string) => {
      const freq: Record<string, number> = {};
      for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
      let ent = 0;
      for (const c of Object.values(freq)) {
        const p = c / str.length;
        ent -= p * Math.log2(p);
      }
      return Number(ent.toFixed(2));
    };
    lines.forEach((rawLine, idx) => {
      if (/culkibo:allow-secret/i.test(rawLine)) return;
      const clean = rawLine.replace(/^[+-]/, '').trim();
      if (!clean) return;
      const eq = clean.indexOf('=');
      const val = eq >= 0 ? clean.slice(eq + 1).trim().replace(/^["']|["']$/g, '') : clean;
      if (!val || uuidRe.test(val) || shaRe.test(val) || /^(?:changeme|example|your_api_key|https?:\/\/)/i.test(val)) return;
      const mkFp = (seedStr: string) => {
        let h = 2166136261;
        for (let i = 0; i < seedStr.length; i++) {
          h ^= seedStr.charCodeAt(i);
          h = Math.imul(h, 16777619);
        }
        return (h >>> 0).toString(16).padStart(8, '0') + 'e4a1b9c2d3f05678';
      };
      if (val.includes(payPrefix)) {
        findings.push({ location: 'diffText', line: idx + 1, ruleId: 'STRIPE_PAYMENT_KEY', severity: 'critical', entropy: shannon(val), redactedPreview: `${clean.slice(0, eq + 1)}[REDACTED_PAYMENT_KEY]`, fingerprintSha256: mkFp(val) });
      } else if (val.includes(ghPrefix)) {
        findings.push({ location: 'diffText', line: idx + 1, ruleId: 'GITHUB_PAT_TOKEN', severity: 'critical', entropy: shannon(val), redactedPreview: `${clean.slice(0, eq + 1)}[REDACTED_GITHUB_TOKEN]`, fingerprintSha256: mkFp(val) });
      } else if (/^postgres(?:ql)?:\/\/[^:]+:[^@]+@/i.test(val)) {
        findings.push({ location: 'diffText', line: idx + 1, ruleId: 'DB_URI_PASSWORD', severity: 'critical', entropy: shannon(val), redactedPreview: `${clean.slice(0, eq + 1)}postgresql://admin:[REDACTED]@db.internal:5432/prod`, fingerprintSha256: mkFp(val) });
      } else if (val.length >= 20 && shannon(val) >= 4.2) {
        findings.push({ location: 'diffText', line: idx + 1, ruleId: 'HIGH_ENTROPY_SECRET', severity: 'high', entropy: shannon(val), redactedPreview: `${clean.slice(0, eq + 1)}[REDACTED_HIGH_ENTROPY]`, fingerprintSha256: mkFp(val) });
      }
    });
    return jsonResponse({
      ok: true,
      allowed: mode === 'warn' ? true : findings.length === 0,
      mode,
      scannedItems: lines.filter(Boolean).length,
      blockedCount: findings.length,
      findings,
    });
  }

  const repTopoMatch = pathname.match(/^\/api\/databases\/([^/]+)\/replicas$/);
  if (repTopoMatch) {
    const dbId = decodeURIComponent(repTopoMatch[1]);
    const topo = s.replicaTopologies[dbId] || s.replicaTopologies.db_pg_main;
    if (method === 'GET') {
      const readTargets = (topo.replicas || []).filter((r: any) => r.healthy !== false && (r.lagMs ?? 0) <= 500);
      const excludedLagging = (topo.replicas || []).filter((r: any) => r.healthy === false || (r.lagMs ?? 0) > 500);
      return jsonResponse({
        ok: true,
        dbId,
        primary: topo.primary,
        replicas: topo.replicas,
        topology: topo,
        readWriteSplit: {
          writeTarget: topo.primary,
          readTargets,
          excludedLagging,
          fallbackToPrimary: readTargets.length === 0,
        },
      });
    }
    if (method === 'PUT') {
      s.replicaTopologies[dbId] = { dbId, primary: body.primary || topo.primary, replicas: Array.isArray(body.replicas) ? body.replicas : topo.replicas };
      return jsonResponse({ ok: true, dbId, ...s.replicaTopologies[dbId] });
    }
  }

  const repPromoteMatch = pathname.match(/^\/api\/databases\/([^/]+)\/replicas\/promote$/);
  if (repPromoteMatch && method === 'POST') {
    const dbId = decodeURIComponent(repPromoteMatch[1]);
    const topo = s.replicaTopologies[dbId] || s.replicaTopologies.db_pg_main;
    const targetId = String(body.targetReplicaId || topo.replicas[0]?.id || 'rep-eu-west');
    const maxLag = Number(body.maxAcceptableLagBytes ?? 1048576);
    const requireFenced = body.requireOldPrimaryFenced !== false;
    const target = (topo.replicas || []).find((r: any) => r.id === targetId) || topo.replicas[0];
    const blockers: Array<{ code: string; message: string }> = [];
    if (requireFenced && !topo.primary?.fenced) {
      blockers.push({ code: 'OLD_PRIMARY_NOT_FENCED', message: `Old primary ${topo.primary?.id} is not fenced — split-brain risk blocked.` });
    }
    if (target && Number(target.lagBytes || 0) > maxLag) {
      blockers.push({ code: 'REPLICA_LAG_TOO_HIGH', message: `Replica ${target.id} lag (${Math.round(target.lagBytes / 1024)} KB) exceeds ${Math.round(maxLag / 1024)} KB ceiling.` });
    }
    const allowed = blockers.length === 0;
    return jsonResponse({
      ok: true,
      dbId,
      allowed,
      blockers,
      promotedNode: allowed ? target : null,
      timelineNext: 3,
      dryRun: body.dryRun !== false,
      steps: allowed
        ? [
            { step: 1, phase: 'drain', title: `Drain active PgBouncer write connections on ${topo.primary?.id}` },
            { step: 2, phase: 'fence', title: `Fence old primary ${topo.primary?.id} (read-only + network STONITH)` },
            { step: 3, phase: 'promote', title: `Promote ${target?.id} to primary (WAL timeline #3)` },
            { step: 4, phase: 're-route', title: `Atomic Caddy/PgBouncer pool switch to ${target?.host}:5432` },
          ]
        : [],
    });
  }

  const egressAuditMatch = pathname.match(/^\/api\/projects\/([^/]+)\/egress-(policy|audit)$/);
  if (egressAuditMatch) {
    const pid = decodeURIComponent(egressAuditMatch[1]);
    const kind = egressAuditMatch[2];
    if (kind === 'policy') {
      return jsonResponse({
        ok: true,
        projectId: pid,
        mode: 'allowlist',
        allowedCidrs: [],
        allowedDomains: ['api.stripe.com'],
        blockMetadata: true,
        blockPrivateLan: true,
        preserveAdminPorts: [22, 80, 443],
      });
    }
    const sockets = Array.isArray(body.observedSockets) ? body.observedSockets : [];
    const violations: Array<{ code: string; severity: string; target: string; message: string }> = [];
    for (const sock of sockets) {
      const target = String(sock?.ip || sock?.host || '');
      if (target === '169.254.169.254' || target.includes('metadata')) {
        violations.push({ code: 'CLOUD_METADATA_EGRESS', severity: 'critical', target, message: 'Container attempted outbound access to cloud IMDS metadata endpoint (169.254.169.254).' });
      } else if (/^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)/.test(target)) {
        violations.push({ code: 'PRIVATE_LAN_EGRESS', severity: 'high', target, message: `Unauthorized private RFC1918 LAN socket to ${target}:${sock?.port || 0}.` });
      }
    }
    const missingChains = Array.isArray(body.firewallRules) && body.firewallRules.length > 0 ? [] : ['DOCKER-USER', 'inet culkibo_egress forward'];
    const riskScore = Math.min(100, violations.length * 32 + missingChains.length * 14);
    return jsonResponse({
      ok: true,
      projectId: pid,
      backend: body.backend || 'nftables',
      compliant: violations.length === 0 && missingChains.length === 0,
      riskScore,
      violations,
      missingChains,
      antiLockoutSafe: true,
      suggestedRules: [
        'table inet culkibo_egress {',
        '  chain forward {',
        '    type filter hook forward priority -10; policy accept;',
        '    tcp dport { 22, 80, 443 } accept # anti-lockout admin/ingress preserve',
        '    ip daddr 169.254.169.254 drop # block cloud IMDS metadata',
        '    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } drop # block lateral LAN',
        '  }',
        '}',
      ],
      auditedAt: new Date().toISOString(),
    });
  }

  if (pathname === '/api/build/multiarch/verify' && method === 'POST') {
    const norm = (a: string) => (a === 'x86_64' ? 'amd64' : a === 'aarch64' ? 'arm64' : a.replace(/^linux\//, '').toLowerCase());
    const hostArch = norm(String(body.hostArch || 'amd64'));
    const platforms = Array.isArray(body.manifestPlatforms) && body.manifestPlatforms.length > 0
      ? body.manifestPlatforms.map((p: string) => norm(String(p)))
      : [norm(String(body.imageArch || 'amd64'))];
    const compatible = platforms.includes(hostArch);
    const warnings: string[] = [];
    if (body.strictOciRegistry && body.includeAttestations) {
      warnings.push('Strict OCI registry detected: set --provenance=false or enable OCI image index v1.1 to avoid attestation reject.');
    }
    return jsonResponse({
      ok: true,
      compatible,
      code: compatible ? 'ARCH_COMPATIBLE' : 'EXEC_FORMAT_MISMATCH',
      warnings,
      remediation: compatible
        ? 'Manifest covers target host architecture.'
        : `Rebuild with multi-arch manifest covering linux/${hostArch} (or route to a native ${platforms[0]} fleet builder).`,
    });
  }

  if (pathname === '/api/build/multiarch/plan' && method === 'POST') {
    const targetPlatforms = Array.isArray(body.targetPlatforms) ? body.targetPlatforms : ['linux/amd64', 'linux/arm64'];
    const builders = Array.isArray(body.builders) ? body.builders : [];
    const imageTag = String(body.imageTag || 'app:latest');
    const assignments = targetPlatforms.map((plat: string) => {
      const arch = plat.replace(/^linux\//, '');
      const nativeBuilder = builders.find((b: any) => String(b.arch || '').toLowerCase() === arch);
      return {
        platform: plat,
        builder: nativeBuilder ? (nativeBuilder.name || nativeBuilder.id) : 'local-qemu',
        native: Boolean(nativeBuilder),
        mode: nativeBuilder ? 'native' : 'qemu',
      };
    });
    const usesQemu = assignments.some((a: any) => !a.native);
    return jsonResponse({
      ok: true,
      imageTag,
      assignments,
      usesQemu,
      qemuWarning: usesQemu ? 'Missing native fleet node for one or more architectures; falling back to QEMU.' : null,
      buildxArgv: ['docker', 'buildx', 'build', '--platform', targetPlatforms.join(','), '-t', imageTag, '--push', '.'],
      manifestCreateArgv: ['docker', 'buildx', 'imagetools', 'create', '-t', imageTag, ...targetPlatforms.map((p: string) => `${imageTag}-${p.replace('linux/', '')}`)],
    });
  }

  const chaosMatch = pathname.match(/^\/api\/projects\/([^/]+)\/chaos\/(gamedays|simulate)$/);
  if (chaosMatch) {
    const pid = decodeURIComponent(chaosMatch[1]);
    const action = chaosMatch[2];
    const list = s.chaosGameDays[pid] || (s.chaosGameDays[pid] = []);
    if (action === 'gamedays' && method === 'GET') {
      return jsonResponse({ ok: true, gamedays: list });
    }
    if (action === 'simulate' && method === 'POST') {
      const env = String(body.environment || 'staging').toLowerCase();
      if (env === 'production' && body.explicitProdConfirm !== true) {
        return jsonResponse({
          ok: false,
          blocked: true,
          code: 'PROD_CHAOS_CONFIRM_REQUIRED',
          environment: 'production',
          faultType: body.faultType || 'latency_jitter',
          message: 'Production chaos drill hard-blocked: pass explicitProdConfirm: true after change-window signoff.',
        });
      }
      const errRate = Number(body.faultRatePct ?? 1);
      const maxAbort = Number(body.maxErrorAbortPct ?? 15);
      const recSec = Number(body.recoverySec ?? 10);
      const aborted = errRate > maxAbort;
      const score = aborted ? 42 : Math.max(85, Math.min(100, Math.round(100 - errRate * 2 - Math.max(0, recSec - 5) * 0.5)));
      const record = {
        ok: true,
        id: `gd_${Date.now()}`,
        projectId: pid,
        environment: env,
        faultType: body.faultType || 'latency_jitter',
        blocked: false,
        aborted,
        status: aborted ? 'AUTO_ABORTED' : 'COMPLETED',
        resilienceScore: score,
        grade: score >= 90 ? 'A' : score >= 80 ? 'B' : 'D',
        breakdown: {
          errorScore: aborted ? 20 : 98,
          latencyScore: aborted ? 55 : 94,
          recoveryScore: aborted ? 50 : 96,
        },
        observedErrorRatePct: errRate,
        p95LatencyMs: Number(body.latencyMs ?? 180) + Number(body.jitterMs ?? 25),
        recoverySec: recSec,
        dryRun: body.dryRun !== false,
        message: aborted
          ? `Observed error rate (${errRate}%) breached maxErrorAbortPct (${maxAbort}%) — fault injector aborted automatically.`
          : `Service absorbed ${body.faultType || 'latency_jitter'} within SLO and recovered in ${recSec}s.`,
      };
      list.unshift(record);
      return jsonResponse(record);
    }
  }

  // --- Cycle-15: SPIFFE mTLS CA, Edge AI Rate-Limit (RPM+TPM), Feature Flags, Runtime Anomaly & Digest Promotion ---
  if (pathname === '/api/security/mtls/certs' && method === 'GET') {
    return jsonResponse({
      ok: true,
      trustDomain: 'culkibo.internal',
      certs: s.mtlsCerts,
      caddyClientAuth: {
        mode: 'require_and_verify',
        trusted_leaf_spiffe_ids: s.mtlsCerts.filter((c) => !c.revoked).map((c) => c.spiffeId),
      },
    });
  }
  if (pathname === '/api/security/mtls/issue' && method === 'POST') {
    const svc = String(body.serviceName || 'edge-api-rust').trim() || 'edge-api-rust';
    const ns = String(body.namespace || 'prod').trim() || 'prod';
    const ttl = Math.max(1, Math.min(168, Number(body.ttlHours || 24)));
    const serial = `CKB-${Math.random().toString(16).slice(2, 6).toUpperCase()}-${Date.now().toString().slice(-4)}`;
    const sig = `ed25519_sig_${serial.toLowerCase().replace(/-/g, '')}_verified`;
    const cert = {
      serial,
      spiffeId: `spiffe://culkibo.internal/ns/${ns}/sa/${svc}`,
      serviceName: svc,
      namespace: ns,
      issuedAt: new Date().toISOString(),
      expiresAt: nowIso(ttl * 3600000),
      ttlHours: ttl,
      revoked: false,
      signatureB64: sig,
    };
    s.mtlsCerts.unshift(cert);
    return jsonResponse({
      ok: true,
      cert,
      signatureB64: sig,
      caddyClientAuth: {
        mode: 'require_and_verify',
        trust_domain: 'culkibo.internal',
        allowed_spiffe_ids: [cert.spiffeId],
        ca_private_key_exposed: false,
      },
    });
  }
  if (pathname === '/api/security/mtls/verify' && method === 'POST') {
    const cert = body.cert || {};
    const found = s.mtlsCerts.find((c) => c.serial === cert.serial);
    if (found?.revoked) {
      return jsonResponse({ ok: true, valid: false, code: 'CERT_REVOKED', spiffeId: found.spiffeId, serial: found.serial, remainingMs: 0 });
    }
    return jsonResponse({
      ok: true,
      valid: true,
      code: 'CERT_VALID',
      spiffeId: cert.spiffeId || 'spiffe://culkibo.internal/ns/prod/sa/edge-api-rust',
      serial: cert.serial || 'CKB-8F4A-1001',
      remainingMs: 86395000,
    });
  }
  const mtlsRevokeMatch = pathname.match(/^\/api\/security\/mtls\/revoke\/([^/]+)$/);
  if (mtlsRevokeMatch && method === 'POST') {
    const serial = decodeURIComponent(mtlsRevokeMatch[1]);
    const found = s.mtlsCerts.find((c) => c.serial === serial);
    if (found) {
      found.revoked = true;
      found.revokedReason = String(body.reason || 'manual_revoke');
    }
    return jsonResponse({ ok: true, revoked: true, serial, cert: found || null });
  }

  if (pathname === '/api/edge/ratelimits' && method === 'GET') {
    return jsonResponse({ ok: true, policies: s.rateLimitPolicies });
  }
  if (pathname === '/api/edge/ratelimits' && method === 'POST') {
    const pol = {
      id: body.id || `rl_${Date.now()}`,
      name: String(body.name || 'Custom AI Shield'),
      planTier: String(body.planTier || 'pro'),
      rpmLimit: Number(body.rpmLimit || 120),
      tpmLimit: Number(body.tpmLimit || 60000),
      burstMultiplier: Number(body.burstMultiplier || 1.5),
      windowSec: Number(body.windowSec || 60),
    };
    s.rateLimitPolicies = [pol, ...s.rateLimitPolicies.filter((p) => p.id !== pol.id)];
    return jsonResponse({ ok: true, policy: pol });
  }
  if (pathname === '/api/edge/ratelimits/simulate' && method === 'POST') {
    const pol = s.rateLimitPolicies.find((p) => p.id === body.policyId) || s.rateLimitPolicies[1] || s.rateLimitPolicies[0];
    const reqs = Math.max(1, Number(body.requestsCount || 20));
    const tokPerReq = Math.max(100, Number(body.tokensPerRequest || 5000));
    const cap = Math.floor((pol.tpmLimit * (pol.burstMultiplier || 1.5)) / tokPerReq);
    const allowedCount = Math.min(reqs, Math.max(1, cap));
    const throttledCount = Math.max(0, reqs - allowedCount);
    const savedUsd = Number(((throttledCount * tokPerReq * 0.000015)).toFixed(2));
    return jsonResponse({
      ok: true,
      policyId: pol.id,
      totalRequests: reqs,
      allowedCount,
      throttledCount,
      first429AtIndex: throttledCount > 0 ? allowedCount : null,
      throttleReason: throttledCount > 0 ? 'TPM_WALLET_BUDGET_EXCEEDED' : null,
      estimatedWalletSavedUsd: savedUsd > 0 ? savedUsd : 1.85,
      sample429Headers: {
        'Retry-After': '60',
        RateLimit: `"${pol.planTier}";r=0;t=60`,
        'RateLimit-Policy': `"${pol.planTier}";q=${pol.tpmLimit};w=${pol.windowSec || 60}`,
        'X-RateLimit-Limit': String(pol.tpmLimit),
        'X-RateLimit-Remaining': '0',
      },
      caddyConfig: {
        handler: 'rate_limit',
        zone: `culkibo_${pol.planTier}_ai`,
        rpm_limit: pol.rpmLimit,
        tpm_limit: pol.tpmLimit,
        status_code: 429,
        retry_after_sec: 60,
      },
    });
  }

  if (pathname === '/api/flags' && method === 'GET') {
    return jsonResponse({ ok: true, flags: s.featureFlags });
  }
  if (pathname === '/api/flags' && method === 'POST') {
    const fl = {
      key: String(body.key || 'new_flag'),
      description: String(body.description || ''),
      enabled: body.enabled !== false,
      killed: false,
      rolloutPct: Number(body.rolloutPct ?? 50),
      environment: String(body.environment || 'prod'),
      allowTenants: Array.isArray(body.allowTenants) ? body.allowTenants : [],
      denyTenants: Array.isArray(body.denyTenants) ? body.denyTenants : [],
    };
    s.featureFlags = [fl, ...s.featureFlags.filter((f) => f.key !== fl.key)];
    return jsonResponse({ ok: true, flag: fl });
  }
  const flagActionMatch = pathname.match(/^\/api\/flags\/([^/]+)\/(evaluate|kill)$/);
  if (flagActionMatch && method === 'POST') {
    const key = decodeURIComponent(flagActionMatch[1]);
    const act = flagActionMatch[2];
    const fl = s.featureFlags.find((f) => f.key === key);
    if (act === 'kill') {
      if (fl) {
        fl.killed = true;
        fl.enabled = false;
      }
      return jsonResponse({ ok: true, killed: true, flag: fl || { key, killed: true, enabled: false, rolloutPct: 0 } });
    }
    if (!fl) return jsonResponse({ ok: true, key, enabled: false, reason: 'FLAG_NOT_FOUND', bucket: 0 });
    if (fl.killed) return jsonResponse({ ok: true, key, enabled: false, reason: 'KILL_SWITCH_ACTIVE', bucket: 0 });
    const bucket = 21.45;
    const enabled = fl.enabled && (bucket < fl.rolloutPct || (fl.allowTenants || []).includes(body.tenantId));
    return jsonResponse({
      ok: true,
      key,
      enabled,
      reason: enabled ? ((fl.allowTenants || []).includes(body.tenantId) ? 'TENANT_ALLOWED' : 'ROLLOUT_MATCH') : 'ROLLOUT_EXCLUDED',
      bucket,
      variant: enabled ? 'on' : 'off',
    });
  }

  const anomalyMatch = pathname.match(/^\/api\/projects\/([^/]+)\/anomalies(\/inspect)?$/);
  if (anomalyMatch) {
    const pid = decodeURIComponent(anomalyMatch[1]);
    const list = s.runtimeAnomalies[pid] || (s.runtimeAnomalies[pid] = []);
    if (!anomalyMatch[2] && method === 'GET') {
      return jsonResponse({ ok: true, alerts: list });
    }
    if (anomalyMatch[2] === '/inspect' && method === 'POST') {
      const events = Array.isArray(body.events) ? body.events : [];
      const alerts: Array<{ ruleId: string; severity: string; message: string }> = [];
      for (const ev of events) {
        const cmd = String(ev?.cmd || '');
        if (/xmrig|stratum\+tcp|:3333|:4444/i.test(cmd)) {
          alerts.push({ ruleId: 'CRYPTOMINER_STRATUM_TRAFFIC', severity: 'critical', message: 'Cryptominer binary / stratum+tcp pool traffic detected (dokploy#5156 signature).' });
        }
        if (/\/dev\/tcp\/|bash\s+-i|nc\s+-e/i.test(cmd)) {
          alerts.push({ ruleId: 'REVERSE_SHELL_SPAWN', severity: 'critical', message: 'Interactive reverse shell /dev/tcp egress spawn detected inside container.' });
        }
      }
      const riskScore = Math.min(100, alerts.length * 48);
      return jsonResponse({
        ok: true,
        projectId: pid,
        containerName: String(body.containerName || 'app'),
        clean: alerts.length === 0,
        riskScore,
        criticalCount: alerts.length,
        highCount: 0,
        alerts,
        recommendedAction: alerts.length > 0 ? 'ISOLATE_AND_ROTATE_SECRETS' : 'NONE',
      });
    }
  }

  const promoBaseMatch = pathname.match(/^\/api\/projects\/([^/]+)\/promotions$/);
  if (promoBaseMatch) {
    const pid = decodeURIComponent(promoBaseMatch[1]);
    const list = s.digestPromotions[pid] || (s.digestPromotions[pid] = []);
    if (method === 'GET') return jsonResponse({ ok: true, promotions: list });
    if (method === 'POST') {
      const imageRef = String(body.imageRef || '');
      if (!/@sha256:[a-f0-9]{64}$/i.test(imageRef)) {
        return jsonResponse({
          ok: false,
          blocked: true,
          code: 'MUTABLE_TAG_FORBIDDEN',
          message: `Mutable tag "${imageRef}" rejected — production promotions require immutable @sha256:<64hex> digest.`,
        });
      }
      const promo = {
        id: `promo_${Date.now()}`,
        projectId: pid,
        imageRef,
        fromEnv: String(body.fromEnv || 'staging'),
        toEnv: String(body.toEnv || 'prod'),
        requester: String(body.requester || 'alice@acme.dev'),
        approver: null,
        status: 'pending_approval',
        previousDigest: body.previousDigest || null,
      };
      list.unshift(promo);
      return jsonResponse({ ok: true, promotion: promo });
    }
  }
  const promoActMatch = pathname.match(/^\/api\/projects\/([^/]+)\/promotions\/([^/]+)\/(approve|execute|rollback)$/);
  if (promoActMatch && method === 'POST') {
    const pid = decodeURIComponent(promoActMatch[1]);
    const promoId = decodeURIComponent(promoActMatch[2]);
    const act = promoActMatch[3];
    const list = s.digestPromotions[pid] || [];
    const promo = list.find((p) => p.id === promoId) || {
      id: promoId,
      projectId: pid,
      imageRef: 'ghcr.io/acme/app@sha256:a3f5c8e1b9d20476a3f5c8e1b9d20476a3f5c8e1b9d20476a3f5c8e1b9d20476',
      fromEnv: 'staging',
      toEnv: 'prod',
      requester: 'alice@acme.dev',
      approver: null,
      status: 'pending_approval',
      previousDigest: 'ghcr.io/acme/app@sha256:91b0d4c2e8a7531091b0d4c2e8a7531091b0d4c2e8a7531091b0d4c2e8a75310',
    };
    if (act === 'approve') {
      if (String(body.approver || '') === promo.requester) {
        return jsonResponse({
          ok: false,
          blocked: true,
          code: 'DUAL_CONTROL_VIOLATION',
          message: `Self-approval blocked: requester "${promo.requester}" cannot approve their own production promotion.`,
        });
      }
      promo.approver = String(body.approver || 'bob@acme.dev');
      promo.status = 'approved';
      return jsonResponse({ ok: true, promotion: promo });
    }
    if (act === 'execute') {
      promo.status = body.dryRun === false ? 'promoted' : 'dry_run_verified';
      return jsonResponse({
        ok: true,
        dryRun: body.dryRun !== false,
        promotion: promo,
        rollbackManifest: {
          projectId: pid,
          revertToDigest: promo.previousDigest,
          targetEnv: promo.toEnv,
          verifiedBy: promo.approver || 'bob@acme.dev',
          zeroDowntimeCaddySwitch: true,
        },
      });
    }
    return jsonResponse({ ok: true, dryRun: body.dryRun !== false, promotion: { ...promo, status: 'rolled_back' } });
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

  // --- MCP 2026-07-28 (160 tools + 13 prompts + 3 sandboxed MCP Apps) ---
  if (pathname === '/api/mcp/tools') {
    const coreTools = [
      { name: 'culkibo_ship_and_verify', description: 'Atomic ship with secret scan, SmartPack build, smoke check, and auto-rollback', readOnly: false, profile: 'core' },
      { name: 'culkibo_search_tools', description: 'Discover any of the 160 MCP tools on demand without bloating context (-90%)', readOnly: true, profile: 'core' },
      { name: 'culkibo_list_projects', description: 'List projects, live status, domains, and linked databases', readOnly: true, profile: 'core' },
      { name: 'culkibo_smartpack_plan', description: 'Generate deterministic SmartPack build plan across 18 stacks', readOnly: true, profile: 'core' },
      { name: 'culkibo_diagnose_incident', description: 'Correlate OOMKilled, CrashLoop, logs, and uptime telemetry', readOnly: true, profile: 'core' },
      { name: 'culkibo_auto_remediate', description: '2-phase safe remediation (dryRun -> HMAC confirmToken)', readOnly: false, profile: 'core' },
      { name: 'culkibo_migrate_coolify', description: 'Zero-downtime Coolify v4 migration with 100% parity diff', readOnly: false, profile: 'core' },
      { name: 'culkibo_mtls_mesh', description: 'Zero-Trust SPIFFE-Lite Ed25519 mTLS workload CA with CRL revocation & Caddy require_and_verify JSON', readOnly: false, profile: 'security' },
      { name: 'culkibo_feature_flags', description: 'OpenFeature-Lite deterministic SHA-256 feature flags with tenant overrides & zero-redeploy kill-switch', readOnly: false, profile: 'deploy' },
      { name: 'culkibo_api_ratelimit', description: 'Edge dual RPM+TPM AI wallet-drain shield emitting IETF RateLimit + 429 Retry-After headers', readOnly: false, profile: 'ops' },
      { name: 'culkibo_runtime_anomaly', description: '10-rule Falco-Lite runtime detector blocking cryptominer stratum pools & reverse shells (dokploy#5156)', readOnly: true, profile: 'security' },
      { name: 'culkibo_digest_promotion', description: 'Kargo-style immutable @sha256: GitOps promotion pipeline with dual-control approval & rollback manifest', readOnly: false, profile: 'deploy' },
      { name: 'culkibo_egress_firewall', description: 'Container egress & DOCKER-USER/nftables drift auditor blocking IMDS metadata with anti-lockout SSH/80/443 rules', readOnly: false, profile: 'security' },
      { name: 'culkibo_replica_failover', description: 'Blue/Green DB read-replica promotion & split-brain fencing blocking lagging/unfenced promotions', readOnly: false, profile: 'ops' },
      { name: 'culkibo_secret_gate', description: 'Pre-deploy 12-rule Shannon-entropy & pattern secret gate with zero raw echoes and UUID/SHA benign filters', readOnly: true, profile: 'security' },
      { name: 'culkibo_multiarch_planner', description: 'Multi-arch amd64/arm64 OCI manifest verifier (EXEC_FORMAT_MISMATCH) & native fleet builder matrix planner', readOnly: true, profile: 'deploy' },
      { name: 'culkibo_chaos_gameday', description: 'Toxiproxy/Chaos Mesh GameDay fault-injection simulator with prod safety lock & auto-abort scorecards', readOnly: false, profile: 'ops' },
      { name: 'culkibo_audit_image_bloat', description: '8-rule Dockerfile layer bloat & secret-in-layer auditor with efficiencyScore & multi-stage slimming tips', readOnly: true, profile: 'deploy' },
      { name: 'culkibo_cron_lease', description: 'Distributed cron fencing-token lease guard blocking duplicate scheduled fires & concurrent overlaps', readOnly: false, profile: 'ops' },
      { name: 'culkibo_mask_preview_pii', description: 'Deterministic HMAC-SHA256 PR-Preview PII masker (FK-safe) + dalibo pg_anonymizer SECURITY LABEL DDL', readOnly: true, profile: 'security' },
      { name: 'culkibo_oom_forensics', description: '8-class container exit-code & OOM-kill forensics classifier (137 OOM vs SIGKILL vs stale historical tasks)', readOnly: true, profile: 'ops' },
      { name: 'culkibo_oncall_router', description: 'Tier 1->2->3 on-call escalation rotation with fingerprint dedup, flapping damper & instant ack', readOnly: false, profile: 'ops' },
      { name: 'culkibo_synthetic_sentinel', description: 'Synthetic multi-step API flow monitor (SSRF-guarded, zero-secret) & live uncached TLS/SNI drift sentinel', readOnly: false, profile: 'ops' },
      { name: 'culkibo_lint_sql_migration', description: '10-rule pure-JS zero-downtime SQL DDL linter catching lock/rewrite footguns before prod', readOnly: true, profile: 'deploy' },
      { name: 'culkibo_worker_autoscaler', description: 'OOM-safe KEDA queue/worker autoscaler with hysteresis, RAM ceiling & 503 Retry-After circuit breaker', readOnly: false, profile: 'ops' },
      { name: 'culkibo_audit_licenses', description: 'CycloneDX 1.6 SPDX compound license risk auditor flagging AGPL/SSPL/GPL/LicenseRef violations', readOnly: true, profile: 'security' },
      { name: 'culkibo_seccomp_profile', description: 'Runtime-tailored least-privilege SCMP_ACT_ERRNO seccomp generator & runc CVE-2025-31133/52565/52881 guard', readOnly: true, profile: 'security' },
      { name: 'culkibo_admission_check', description: 'Declarative Policy-as-Code pre-deploy CIS/PSS admission gate (10 rules, baseline/restricted/soc2-strict)', readOnly: false, profile: 'security' },
      { name: 'culkibo_compliance_bundle', description: 'Generate & verify Ed25519-signed SOC 2 / ISO 27001 / GDPR compliance evidence bundles (0 plaintext secrets)', readOnly: true, profile: 'security' },
      { name: 'culkibo_volume_migrate', description: 'Zero-shell 4-phase stateful volume migration planner preserving tar --numeric-owner UID:GID & SHA-256', readOnly: false, profile: 'deploy' },
      { name: 'culkibo_edge_experiment', description: 'Native Caddy v2.11 Geo-Routing (CF-IPCountry) & sticky cookie/header A/B experiment compiler with 1-click Kill-Switch', readOnly: false, profile: 'deploy' },
      { name: 'culkibo_security_posture', description: 'Unified executive governance scorecard combining admission preset, compliance score, CVE drift, secret rotation & DR drills', readOnly: true, profile: 'security' },
      { name: 'culkibo_dr_drill', description: 'Automated DR backup restore fire-drill verifier catching 0 B / 20 B corrupt dumps & ACL strips', readOnly: false, profile: 'ops' },
      { name: 'culkibo_slo_canary', description: 'Google SRE error-budget SLO canary controller (10->25->50->100%) with instant 100/0 auto-rollback', readOnly: false, profile: 'deploy' },
      { name: 'culkibo_ai_workload', description: 'Self-hosted AI/GPU LLM planner (Ollama/vLLM/llama.cpp) with VRAM pre-flight, CDI & CVE guards', readOnly: true, profile: 'ops' },
      { name: 'culkibo_remote_builder', description: 'Distributed remote build-node offloader with independent queues & SSH mux ref-count pinning', readOnly: false, profile: 'deploy' },
      { name: 'culkibo_log_archive_search', description: 'Compressed .ndjson.gz persistent log archive search surviving redeploys (ReDoS-safe)', readOnly: true, profile: 'ops' },
      { name: 'culkibo_webhook_dlq', description: 'Manage Standard-Webhooks whsec_ subscriptions, dual-secret rotation & anti-SSRF DLQ replay', readOnly: false, profile: 'ops' },
      { name: 'culkibo_db_studio', description: 'Read-only SQL (BEGIN TRANSACTION READ ONLY) & safe Redis/Valkey inspector + Postgres bloat diagnostics', readOnly: true, profile: 'ops' },
      { name: 'culkibo_s3_storage', description: 'Post-MinIO Garage/RustFS/SeaweedFS presets, pure-crypto AWS SigV4 presigned URLs & CORS/Lifecycle XML', readOnly: false, profile: 'deploy' },
      { name: 'culkibo_agency_ledger', description: 'Multi-tenant Agency Quotas & CSV-formula-safe billing usage ledger with strict project ACL', readOnly: true, profile: 'ops' },
      { name: 'culkibo_brand_theme', description: 'Open-Core White-Label brand & custom login theme engine with XSS/CSS-injection guard', readOnly: false, profile: 'ops' },
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
    const generated = Array.from({ length: 160 - coreTools.length }, (_, i) => ({
      name: `culkibo_ops_tool_${i + coreTools.length + 1}`,
      description: `Managed PaaS control-plane operation #${i + coreTools.length + 1} (RBAC + audit-chained)`,
      readOnly: i % 2 === 0,
      profile: i % 3 === 0 ? 'deploy' : i % 3 === 1 ? 'ops' : 'security',
    }));
    return jsonResponse({ tools: [...coreTools, ...generated], total: 160, coreCount: 17 });
  }
  if (pathname === '/api/mcp/audit') {
    return jsonResponse({
      auditLog: [
        { id: 'aud_1', toolName: 'culkibo_mtls_mesh', status: 'ok', durationMs: 1, timestamp: nowIso(-30000), client: 'claude-code' },
        { id: 'aud_2', toolName: 'culkibo_runtime_anomaly', status: 'ok', durationMs: 2, timestamp: nowIso(-120000), client: 'antigravity' },
      ],
    });
  }
  if (pathname === '/api/mcp/config') {
    return jsonResponse({
      protocol: { version: '2026-07-28', transport: 'streamable-http', endpoint: `${parsed.origin}/api/mcp` },
      totalTools: 160,
      profiles: { core: { count: 17, savedPct: 90 } },
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
