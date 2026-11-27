const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const {
  generateBuildPlan,
  generateImplicitDockerignore,
  computeBuildKitResourceLimits,
  renderDockerfileFromPlan,
  SUPPORTED_STACKS
} = require('../server/services/smartPackBuilder');
const {
  DirectPushRegistry,
  createDirectPushRegistry,
  planDirectPush,
  sha256Digest
} = require('../server/services/directPushRegistry');
const caddyManager = require('../server/services/caddyManager');
const { CaddyManager, formatEarlyHintsLinks } = caddyManager;

/** Helper HTTP request with full status, headers, and Buffer body. */
function httpCall(urlStr, { method = 'GET', headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const payload = body == null ? null : (Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8'));
    const reqHeaders = {
      ...(payload ? { 'Content-Length': String(payload.length) } : {}),
      ...headers
    };
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: `${u.pathname}${u.search}`,
        method,
        headers: reqHeaders,
        agent: false
      },
      (res) => {
        /** @type {Buffer[]} */
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          let json = null;
          try { json = JSON.parse(buf.toString('utf8')); } catch (e) {}
          resolve({ status: res.statusCode || 0, headers: res.headers, body: buf, text: buf.toString('utf8'), json });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

/** Lightweight mock Caddy Admin API for kamal-proxy#233 TLS isolation tests. */
function createTlsIsolationMockCaddy({ missingDnsModules = ['hetzner'] } = {}) {
  /** @type {any} */
  let config = {
    apps: {
      http: { servers: { culkibo: { listen: [':80', ':443'], routes: [] } } },
      tls: { automation: { policies: [] } }
    }
  };
  let etag = 1;
  const server = http.createServer((req, res) => {
    const method = req.method || 'GET';
    const urlPath = (req.url || '/').split('?')[0];
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const body = raw ? JSON.parse(raw) : null;

      if (method === 'GET' && urlPath === '/reverse_proxy/upstreams') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end('[]');
      }
      if (urlPath === '/config/apps/tls') {
        if (method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json', ETag: `"e${etag}"` });
          return res.end(JSON.stringify(config.apps.tls));
        }
        if (method === 'PATCH' || method === 'PUT') {
          const serialized = JSON.stringify(body || {});
          for (const missing of missingDnsModules) {
            if (serialized.includes(`"name":"${missing}"`)) {
              res.writeHead(400, { 'Content-Type': 'text/plain' });
              return res.end(`loading tls app: module not registered: dns.providers.${missing}`);
            }
          }
          config.apps.tls = body;
          etag++;
          res.writeHead(200, { ETag: `"e${etag}"` });
          return res.end();
        }
      }
      if (urlPath === '/config/apps/http/servers/culkibo/routes') {
        if (method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json', ETag: `"e${etag}"` });
          return res.end(JSON.stringify(config.apps.http.servers.culkibo.routes));
        }
        if (method === 'PATCH' || method === 'PUT') {
          config.apps.http.servers.culkibo.routes = body;
          etag++;
          res.writeHead(200, { ETag: `"e${etag}"` });
          return res.end();
        }
      }
      res.writeHead(404);
      res.end('not found');
    });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = /** @type {import('net').AddressInfo} */ (server.address());
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        getConfig: () => config,
        close: () => new Promise((r) => server.close(r))
      });
    });
  });
}

async function testSmartPackDirectPush() {
  console.log('\n🚀 Testing SmartPack, DirectPush OCI v2, kamal-proxy#233 TLS Isolation & dokploy#2974 Stream Caps...\n');

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-sp-dp-'));

  try {
    // =========================================================================
    // 1. SmartPack: 8+ Stacks, Deterministic Build Plan, Implicit .dockerignore & Cgroup Caps
    // =========================================================================
    assert.ok(SUPPORTED_STACKS.length >= 14, `Expected >=14 supported stacks, got ${SUPPORTED_STACKS.length}`);

    const fixtures = [
      {
        name: 'next-standalone',
        expectedStack: 'nextjs',
        files: {
          'package.json': JSON.stringify({ name: 'web', dependencies: { next: '15.2.0', react: '19.0.0' }, scripts: { build: 'next build', start: 'next start' } }),
          'pnpm-lock.yaml': 'lockfileVersion: 9.0\n',
          'next.config.mjs': 'export default { output: "standalone" };\n'
        },
        expectCacheMount: '/root/.local/share/pnpm/store',
        expectStartIncludes: 'server.js'
      },
      {
        name: 'vite-spa',
        expectedStack: 'vite',
        files: {
          'package.json': JSON.stringify({ name: 'spa', devDependencies: { vite: '6.0.0' }, scripts: { build: 'vite build' } }),
          'package-lock.json': '{}'
        },
        expectCacheMount: '/root/.npm',
        expectStartIncludes: 'caddy'
      },
      {
        name: 'bun-api',
        expectedStack: 'bun',
        files: {
          'package.json': JSON.stringify({ name: 'bun-api', scripts: { start: 'bun run src/index.ts' } }),
          'bun.lock': ''
        },
        expectCacheMount: '/root/.bun/install/cache',
        expectStartIncludes: 'bun'
      },
      {
        name: 'deno-edge',
        expectedStack: 'deno',
        files: {
          'deno.json': JSON.stringify({ tasks: { start: 'deno run main.ts' } }),
          'main.ts': 'Deno.serve(() => new Response("ok"));'
        },
        expectCacheMount: '/deno-dir',
        expectStartIncludes: 'deno'
      },
      {
        name: 'python-uv',
        expectedStack: 'python-uv',
        files: {
          'pyproject.toml': '[project]\nname="api"\ndependencies=["fastapi","uvicorn"]\n[tool.uv]\ndev-dependencies=[]\n',
          'uv.lock': 'version = 1\n',
          'main.py': 'from fastapi import FastAPI\napp = FastAPI()\n'
        },
        expectCacheMount: '/root/.cache/uv',
        expectStartIncludes: 'uvicorn'
      },
      {
        name: 'go-service',
        expectedStack: 'go',
        files: {
          'go.mod': 'module example.com/svc\n\ngo 1.24\n',
          'main.go': 'package main\nfunc main() {}\n'
        },
        expectCacheMount: '/go/pkg/mod',
        expectStartIncludes: '/app/server'
      },
      {
        name: 'rust-crate',
        expectedStack: 'rust',
        files: {
          'Cargo.toml': '[package]\nname = "hyper-api"\nversion = "0.1.0"\n'
        },
        expectCacheMount: '/usr/local/cargo/registry',
        expectStartIncludes: '/app/server'
      },
      {
        name: 'php-frankenphp',
        expectedStack: 'php-frankenphp',
        files: {
          'composer.json': JSON.stringify({ require: { 'laravel/framework': '^11.0' } }),
          'artisan': '#!/usr/bin/env php\n',
          'public/index.php': '<?php echo "ok";'
        },
        expectCacheMount: '/root/.composer/cache',
        expectStartIncludes: 'frankenphp'
      },
      {
        name: 'elixir-phx',
        expectedStack: 'elixir',
        files: {
          'mix.exs': 'defmodule MyApp.MixProject do end\n'
        },
        expectCacheMount: '/root/.hex',
        expectStartIncludes: '/app/bin/server'
      },
      {
        name: 'java-maven',
        expectedStack: 'java',
        files: {
          'pom.xml': '<project><modelVersion>4.0.0</modelVersion></project>\n'
        },
        expectCacheMount: '/root/.m2',
        expectStartIncludes: 'java'
      }
    ];

    for (const fx of fixtures) {
      const dir = path.join(tmpRoot, fx.name);
      fs.mkdirSync(dir, { recursive: true });
      for (const [rel, content] of Object.entries(fx.files)) {
        const abs = path.join(dir, rel);
        fs.mkdirSync(path.dirname(abs), { recursive: true });
        fs.writeFileSync(abs, content, 'utf8');
      }

      const planA = generateBuildPlan(dir, { hostMemoryMb: 2048, hostCpus: 2, zstdChunked: true });
      const planB = generateBuildPlan(dir, { hostMemoryMb: 2048, hostCpus: 2, zstdChunked: true });

      assert.strictEqual(planA.stack, fx.expectedStack, `${fx.name}: expected stack ${fx.expectedStack}, got ${planA.stack}`);
      assert.strictEqual(planA.deterministicHash, planB.deterministicHash, `${fx.name}: build-plan hash must be deterministic`);
      assert.strictEqual(planA.dockerfile, planB.dockerfile, `${fx.name}: rendered Dockerfile must be byte-identical`);
      assert.ok(planA.dockerfile.includes('# syntax=docker/dockerfile:1.7'), `${fx.name}: must enable BuildKit 1.7 syntax`);
      assert.ok(!/^\s*ARG\s+/m.test(planA.dockerfile), `${fx.name}: must NOT inject volatile ARGs`);
      assert.ok(
        planA.dockerfile.includes(`target=${fx.expectCacheMount}`),
        `${fx.name}: expected BuildKit cache mount ${fx.expectCacheMount} in Dockerfile`
      );
      assert.ok(
        Array.isArray(planA.startCommand) && planA.startCommand.join(' ').includes(fx.expectStartIncludes),
        `${fx.name}: expected startCommand containing "${fx.expectStartIncludes}", got ${JSON.stringify(planA.startCommand)}`
      );
      assert.strictEqual(planA.ociExport.zstdChunked, true);
      assert.ok(planA.ociExport.flags.join(' ').includes('compression=zstd'));
      assert.strictEqual(renderDockerfileFromPlan(planA), planA.dockerfile);
    }

    // Implicit .dockerignore verification
    const ign = generateImplicitDockerignore('rust');
    for (const required of ['.git', 'node_modules', '.venv', 'target', '.env*', '*.log']) {
      const checkPattern = required === '.env*' ? '.env.*' : required;
      assert.ok(ign.patterns.includes(checkPattern), `Implicit .dockerignore missing ${checkPattern}`);
    }

    // Host-aware BuildKit cgroup limits across 1 GB, 4 GB, and 16 GB VPS sizes
    const lim1g = computeBuildKitResourceLimits({ hostMemoryMb: 1024, hostCpus: 1 });
    const lim4g = computeBuildKitResourceLimits({ hostMemoryMb: 4096, hostCpus: 4 });
    const lim16g = computeBuildKitResourceLimits({ hostMemoryMb: 16384, hostCpus: 8 });
    assert.ok(lim1g.buildMemoryMb <= 600 && lim1g.reservedHeadroomMb >= 400, `1GB VPS must leave headroom: ${JSON.stringify(lim1g)}`);
    assert.strictEqual(lim1g.maxParallelStages, 1);
    assert.ok(lim4g.buildMemoryMb <= 3000 && lim4g.buildCpus <= 3);
    assert.ok(lim16g.buildMemoryMb <= 8192 && lim16g.buildCpus === 7);
    assert.ok(lim4g.dockerBuildFlags.includes('--memory') && lim4g.dockerBuildFlags.includes('--cpus'));

    console.log(`  ✓ 1. SmartPack verified across ${fixtures.length} real stacks, deterministic hashes, implicit .dockerignore & host-aware cgroup caps`);

    // =========================================================================
    // 2. DirectPush OCI v2 Loopback Registry: Delta Skip + SHA-256 Tamper Reject + SSH Plan
    // =========================================================================
    const regDir = path.join(tmpRoot, 'directpush-store');
    const registry = createDirectPushRegistry({ storageDir: regDir });
    const started = await registry.start({ port: 0, host: '127.0.0.1' });
    assert.strictEqual(started.running, true);
    assert.strictEqual(started.host, '127.0.0.1');
    assert.ok(started.port > 0);

    try {
      // Base /v2/ probe
      const v2 = await httpCall(`${started.url}/v2/`);
      assert.strictEqual(v2.status, 200);
      assert.strictEqual(v2.headers['docker-distribution-api-version'], 'registry/2.0');

      // Refuse non-loopback bind
      const remoteReg = new DirectPushRegistry();
      await assert.rejects(() => remoteReg.start({ host: '0.0.0.0', port: 0 }), /loopback/i);

      // Chunked upload of Layer A (POST -> PATCH x2 -> PUT ?digest=)
      const layerAChunk1 = Buffer.from('culkibo-layer-a-chunk-1-'.repeat(64), 'utf8');
      const layerAChunk2 = Buffer.from('culkibo-layer-a-chunk-2-'.repeat(64), 'utf8');
      const layerAFull = Buffer.concat([layerAChunk1, layerAChunk2]);
      const digestA = sha256Digest(layerAFull);

      // Before upload, HEAD must return 404 BLOB_UNKNOWN
      const headMissing = await httpCall(`${started.url}/v2/acme/web/blobs/${digestA}`, { method: 'HEAD' });
      assert.strictEqual(headMissing.status, 404);

      const initUp = await httpCall(`${started.url}/v2/acme/web/blobs/uploads/`, { method: 'POST' });
      assert.strictEqual(initUp.status, 202);
      const locA = String(initUp.headers.location || '');
      assert.ok(locA.startsWith('/v2/acme/web/blobs/uploads/'));

      const patch1 = await httpCall(`${started.url}${locA}`, { method: 'PATCH', body: layerAChunk1 });
      assert.strictEqual(patch1.status, 202);
      const patch2 = await httpCall(`${started.url}${locA}`, { method: 'PATCH', body: layerAChunk2 });
      assert.strictEqual(patch2.status, 202);

      const commitA = await httpCall(`${started.url}${locA}?digest=${encodeURIComponent(digestA)}`, { method: 'PUT' });
      assert.strictEqual(commitA.status, 201);
      assert.strictEqual(commitA.headers['docker-content-digest'], digestA);

      // DELTA SKIP: Second deploy probes HEAD on Layer A -> 200 OK, skipped without re-uploading!
      const headExisting = await httpCall(`${started.url}/v2/acme/web/blobs/${digestA}`, { method: 'HEAD' });
      assert.strictEqual(headExisting.status, 200);
      assert.strictEqual(headExisting.headers['docker-content-digest'], digestA);

      // Upload only new Layer B (monolithic POST ?digest=)
      const layerB = Buffer.from('culkibo-delta-layer-b-payload', 'utf8');
      const digestB = sha256Digest(layerB);
      const uploadB = await httpCall(
        `${started.url}/v2/acme/web/blobs/uploads/?digest=${encodeURIComponent(digestB)}`,
        { method: 'POST', body: layerB }
      );
      assert.strictEqual(uploadB.status, 201);

      // STRICT SHA-256 TAMPER REJECTION -> HTTP 400 DIGEST_INVALID
      const tamperedBytes = Buffer.from('evil-corrupted-layer-bytes', 'utf8');
      const fakeClaimedDigest = `sha256:${'f'.repeat(64)}`;
      const badInit = await httpCall(`${started.url}/v2/acme/web/blobs/uploads/`, { method: 'POST' });
      assert.strictEqual(badInit.status, 202);
      const badCommit = await httpCall(
        `${started.url}${badInit.headers.location}?digest=${encodeURIComponent(fakeClaimedDigest)}`,
        { method: 'PUT', body: tamperedBytes }
      );
      assert.strictEqual(badCommit.status, 400, `Tampered blob must return HTTP 400, got ${badCommit.status}`);
      assert.strictEqual(badCommit.json?.errors?.[0]?.code, 'DIGEST_INVALID');
      assert.strictEqual(registry.hasBlob(fakeClaimedDigest), false, 'Tampered blob must never be committed');

      // Push & fetch OCI manifest referencing Layer A + Layer B
      const manifestPayload = JSON.stringify({
        schemaVersion: 2,
        mediaType: 'application/vnd.oci.image.manifest.v1+json',
        layers: [
          { mediaType: 'application/vnd.oci.image.layer.v1.tar+zstd', digest: digestA, size: layerAFull.length },
          { mediaType: 'application/vnd.oci.image.layer.v1.tar+zstd', digest: digestB, size: layerB.length }
        ]
      });
      const putMan = await httpCall(`${started.url}/v2/acme/web/manifests/v1.0`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/vnd.oci.image.manifest.v1+json' },
        body: manifestPayload
      });
      assert.strictEqual(putMan.status, 201);
      const getMan = await httpCall(`${started.url}/v2/acme/web/manifests/v1.0`);
      assert.strictEqual(getMan.status, 200);
      assert.strictEqual(getMan.text, manifestPayload);

      // Stats accounting: 1 skipped layer, bytesSaved === layerAFull.length, 1 digestRejection
      const stats = registry.getStats();
      assert.strictEqual(stats.blobsStored, 2);
      assert.strictEqual(stats.blobsSkipped, 1);
      assert.strictEqual(stats.bytesSaved, layerAFull.length);
      assert.strictEqual(stats.digestRejections, 1);
      assert.strictEqual(stats.manifestsPushed, 1);
      assert.strictEqual(stats.activeUploads, 0);

      // SSH tunnel DirectPush plan (0 shell strings, strict argv, rejects injection)
      const pushPlan = planDirectPush({ image: 'acme/web:v1.0', serverId: 'srv_eu_1', localPort: 5055, sshHost: '203.0.113.10' });
      assert.strictEqual(pushPlan.shell, false);
      assert.strictEqual(pushPlan.zeroRegistryRequired, true);
      assert.strictEqual(pushPlan.targetImageRef, '127.0.0.1:5055/acme/web:v1.0');
      assert.strictEqual(pushPlan.steps.length, 3);
      assert.ok(pushPlan.steps.every((s) => s.shell === false && Array.isArray(s.argv)));
      assert.throws(() => planDirectPush({ image: 'bad;rm -rf /', serverId: 'srv_eu_1' }), /Invalid Docker image/i);
    } finally {
      await registry.stop();
    }
    console.log('  ✓ 2. DirectPush OCI v2 loopback registry: chunked/monolithic upload, delta skip, SHA-256 tamper 400 DIGEST_INVALID & SSH plan verified');

    // =========================================================================
    // 3. kamal-proxy#233 Per-Domain TLS Isolation + Drain Barrier + 103 Early Hints
    // =========================================================================
    const tlsMock = await createTlsIsolationMockCaddy({ missingDnsModules: ['hetzner'] });
    try {
      const cm = new CaddyManager();
      cm.adminUrl = tlsMock.url;

      // 1 healthy Cloudflare policy + 1 missing Hetzner module + 1 malformed invalid domain/provider policy
      const recTls = await cm.reconcileTls({
        askEndpoint: 'http://127.0.0.1:3030/api/ingress/ask',
        wildcardPolicies: [
          { rootDomain: 'healthy.example.test', provider: 'cloudflare', includeApex: true },
          { rootDomain: 'missing-mod.example.test', provider: 'hetzner', includeApex: true },
          { rootDomain: 'bad..domain', provider: 'unknown_provider' }
        ]
      });

      assert.strictEqual(recTls.applied, true, 'Healthy Cloudflare wildcard must still be applied when sibling domain fails');
      assert.strictEqual(recTls.partial, true);
      assert.strictEqual(recTls.wildcardCount, 1);
      assert.ok(Array.isArray(recTls.isolatedPolicies) && recTls.isolatedPolicies.length >= 2);
      const livePolicies = tlsMock.getConfig().apps.tls.automation.policies;
      assert.ok(
        livePolicies.some((p) => Array.isArray(p.subjects) && p.subjects.includes('*.healthy.example.test')),
        'Healthy domain wildcard policy must remain active in Caddy TLS config'
      );
      assert.ok(
        livePolicies.some((p) => p.on_demand === true),
        'on_demand fallback TLS policy must remain active'
      );

      // Route reconcile isolation: 1 broken route spec must not wipe healthy routes
      const recRoutes = await cm.reconcile([
        { projectId: 'healthy_a', hostnames: ['a.example.test'], upstreams: ['127.0.0.1:4100'] },
        { projectId: 'broken_ssrf', hostnames: ['bad.example.test'], upstreams: ['127.0.0.1:4101'], forwardAuth: { enabled: true, upstream: '169.254.169.254:80' } },
        { projectId: 'healthy_b', hostnames: ['b.example.test'], upstreams: ['127.0.0.1:4102'] }
      ]);
      assert.strictEqual(recRoutes.applied.length, 2);
      assert.strictEqual(recRoutes.skippedInvalid.length, 1);
      assert.strictEqual(recRoutes.skippedInvalid[0].projectId, 'broken_ssrf');

      // Pingora-style drain barrier + 103 Early Hints RFC 8297 Link headers
      const baseCfg = cm.buildBaseConfig({
        askEndpoint: 'http://127.0.0.1:3030/api/ingress/ask',
        gracePeriodMs: 12000,
        shutdownDelayMs: 3000
      });
      assert.strictEqual(baseCfg.apps.http.grace_period, 12000 * 1e6);
      assert.strictEqual(baseCfg.apps.http.shutdown_delay, 3000 * 1e6);

      const hintRoute = cm.buildRoute({
        projectId: 'hints_app',
        hostnames: ['fast.example.test'],
        upstreams: ['127.0.0.1:3000'],
        streamCloseDelayMs: 8000,
        earlyHints: {
          enabled: true,
          links: [
            { href: '/assets/app.css', rel: 'preload', as: 'style' },
            { href: 'https://fonts.gstatic.com', rel: 'preconnect', crossorigin: true }
          ]
        }
      });
      const rp = cm.extractProxyHandler(hintRoute);
      assert.strictEqual(rp.stream_close_delay, 8000 * 1e6);
      assert.deepStrictEqual(rp.headers.response.add.Link, [
        '</assets/app.css>; rel=preload; as=style',
        '<https://fonts.gstatic.com>; rel=preconnect; crossorigin'
      ]);
      assert.throws(() => formatEarlyHintsLinks([{ href: 'javascript:alert(1)', rel: 'preload' }]), /inválido|bloqueado/i);
    } finally {
      await tlsMock.close();
    }
    console.log('  ✓ 3. kamal-proxy#233 TLS/route isolation, Pingora drain barrier & 103 Early Hints verified');

    // =========================================================================
    // 4. dokploy#2974 Per-Principal SSE/WS Stream Cap (10/principal, 50 global) & Guaranteed FD Cleanup
    // =========================================================================
    const serverMod = require('../server/index');
    const {
      server,
      logStreamTracker,
      createLogStreamTracker,
      MAX_LOG_STREAMS_PER_PRINCIPAL,
      MAX_LOG_STREAMS_GLOBAL,
      getRuntimeMeta
    } = serverMod;

    assert.strictEqual(MAX_LOG_STREAMS_PER_PRINCIPAL, 10);
    assert.strictEqual(MAX_LOG_STREAMS_GLOBAL, 50);

    // 4a. Unit verification of global 50 cap across 6 principals + idempotent cleanup
    const unitTracker = createLogStreamTracker({ maxPerPrincipal: 10, maxGlobal: 50 });
    /** @type {Array<() => void>} */
    const releases = [];
    for (let p = 0; p < 5; p++) {
      for (let i = 0; i < 10; i++) {
        const res = unitTracker.acquire(`user:u${p}`, { p, i });
        assert.strictEqual(res.ok, true);
        releases.push(/** @type {() => void} */ (res.release));
      }
      // 11th on same principal -> 429 MAX_PRINCIPAL_STREAMS
      const overPrincipal = unitTracker.acquire(`user:u${p}`, { overflow: true });
      assert.strictEqual(overPrincipal.ok, false);
      assert.strictEqual(overPrincipal.status, p < 4 ? 429 : 503);
    }
    // 51st global from fresh 6th principal -> 503 MAX_GLOBAL_STREAMS
    const overGlobal = unitTracker.acquire('user:u5', { globalOverflow: true });
    assert.strictEqual(overGlobal.ok, false);
    assert.strictEqual(overGlobal.status, 503);
    assert.strictEqual(overGlobal.code, 'MAX_GLOBAL_STREAMS');
    assert.strictEqual(unitTracker.getStats().activeGlobal, 50);

    // Double-calling release() must be strictly idempotent and return counts to 0
    for (const rel of releases) { rel(); rel(); }
    assert.strictEqual(unitTracker.getStats().activeGlobal, 0);
    assert.strictEqual(unitTracker.getStats().activePrincipals, 0);

    // 4b. Live HTTP SSE stream cap + abrupt disconnect FD cleanup on server/index.js
    const ownListen = !server.listening;
    if (ownListen) {
      await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    }
    const addr = /** @type {import('net').AddressInfo} */ (server.address());
    const port = addr.port;

    /** @type {Array<{ req: http.ClientRequest, res: http.IncomingMessage }>} */
    const openedSse = [];
    const openSse = () => new Promise((resolve, reject) => {
      const req = http.request(
        { hostname: '127.0.0.1', port, path: '/api/mcp/sse', method: 'GET', agent: false },
        (res) => resolve({ req, res, status: res.statusCode || 0 })
      );
      req.on('error', reject);
      req.end();
    });

    try {
      for (let i = 0; i < 10; i++) {
        const conn = await openSse();
        assert.strictEqual(conn.status, 200, `SSE stream #${i + 1} should succeed (got ${conn.status})`);
        openedSse.push(conn);
      }
      assert.strictEqual(getRuntimeMeta().activeSseClients, 10);

      // 11th concurrent SSE stream from same principal MUST be rejected with HTTP 429
      const eleventh = await httpCall(`http://127.0.0.1:${port}/api/mcp/sse`);
      assert.strictEqual(eleventh.status, 429, `11th SSE stream must return HTTP 429, got ${eleventh.status}`);
      assert.strictEqual(eleventh.json?.code, 'MAX_PRINCIPAL_STREAMS');

      // Abruptly destroy all 10 SSE sockets -> guaranteed cleanup back to 0 active streams
      for (const c of openedSse) {
        c.res.destroy();
        c.req.destroy();
      }
      openedSse.length = 0;

      const deadline = Date.now() + 3000;
      while (Date.now() < deadline && (getRuntimeMeta().activeSseClients > 0 || logStreamTracker.getStats().activeGlobal > 0)) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.strictEqual(getRuntimeMeta().activeSseClients, 0, 'All destroyed SSE sockets must release activeSseClients to 0');
      assert.strictEqual(logStreamTracker.getStats().activeGlobal, 0, 'logStreamTracker must release all slots to 0 (no FD leak)');

      // Fresh stream succeeds immediately after cleanup
      const afterCleanup = await openSse();
      assert.strictEqual(afterCleanup.status, 200);
      afterCleanup.res.destroy();
      afterCleanup.req.destroy();
      const deadline2 = Date.now() + 2000;
      while (Date.now() < deadline2 && getRuntimeMeta().activeSseClients > 0) {
        await new Promise((r) => setTimeout(r, 20));
      }
      assert.strictEqual(getRuntimeMeta().activeSseClients, 0);
    } finally {
      for (const c of openedSse) {
        try { c.res.destroy(); c.req.destroy(); } catch (e) {}
      }
      if (ownListen) {
        await new Promise((resolve) => server.close(resolve));
      }
    }
    console.log('  ✓ 4. dokploy#2974 per-principal (10) & global (50) SSE/WS stream caps + guaranteed socket cleanup verified');

    console.log('\n✅ All SmartPack, DirectPush OCI v2, TLS Isolation & Stream-Cap tests PASSED!\n');
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

module.exports = testSmartPackDirectPush;

if (require.main === module) {
  testSmartPackDirectPush()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('❌ smartpack-directpush.test.js failed:', err);
      process.exit(1);
    });
}
