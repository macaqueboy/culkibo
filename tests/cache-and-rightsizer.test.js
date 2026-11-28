'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const edgeCacheService = require('../server/services/edgeCacheService');
const resourceRightsizerService = require('../server/services/resourceRightsizerService');

const {
  EdgeCacheService,
  parseSurrogateKeys,
  registerCachedEntry,
  purgeBySurrogateKey,
  evaluateCoalescing,
  renderCacheControlPolicy,
  listEdgeCacheTags
} = edgeCacheService;

const {
  ResourceRightsizerService,
  computePercentile,
  validateDockerLimits,
  recommendContainerResources,
  buildComposeResourcePatch,
  listRecommendations
} = resourceRightsizerService;

/**
 * Verifies souin#884 empty-safe surrogate keys, souin#850 private bypass & bounded singleflight,
 * dry-run vs live tag eviction, multi-edge provider plans, and Cache-Control rendering.
 * @param {string} tmpRoot
 */
function testEdgeCacheService(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'cache-data');
  const svc = new EdgeCacheService({ dataDir });

  // 1. souin#884 empty-safe parsing: NEVER [""] or global SURROGATE_
  assert.deepStrictEqual(svc.parseSurrogateKeys(''), []);
  assert.deepStrictEqual(svc.parseSurrogateKeys('   \t\n '), []);
  assert.deepStrictEqual(svc.parseSurrogateKeys(null), []);
  assert.deepStrictEqual(svc.parseSurrogateKeys(undefined), []);
  assert.deepStrictEqual(svc.parseSurrogateKeys('SURROGATE_'), []);
  assert.deepStrictEqual(
    svc.parseSurrogateKeys('product-42 catalog, product-42 hero'),
    ['product-42', 'catalog', 'hero']
  );

  // Max 64 tags cap
  const manyTags = Array.from({ length: 80 }, (_, i) => `tag-${i}`).join(' ');
  assert.strictEqual(svc.parseSurrogateKeys(manyTags).length, 64);

  // 2. Register entries (including untagged entry that must NOT attach to SURROGATE_)
  const untagged = svc.registerCachedEntry({ cacheKey: '/health', surrogateKeys: '' });
  assert.deepStrictEqual(untagged.entry.surrogateKeys, []);
  assert.strictEqual(untagged.globalSurrogateBucketUsed, false);

  svc.registerCachedEntry({ cacheKey: '/products/42', surrogateKeys: ['product-42', 'catalog'] });
  svc.registerCachedEntry({ cacheKey: '/products/42/reviews', surrogateKeys: 'product-42 reviews' });
  svc.registerCachedEntry({ cacheKey: '/about', surrogateKeys: ['static'] });
  assert.ok(fs.existsSync(path.join(dataDir, 'edge-cache-keys.json')));

  const tagsBefore = svc.listEdgeCacheTags();
  assert.ok(!tagsBefore.some((t) => t.tag === '' || t.tag === 'SURROGATE_'));
  assert.strictEqual(tagsBefore.find((t) => t.tag === 'product-42')?.entryCount, 2);

  // 3. Dry-run purge reports invalidatedCount === 2 WITHOUT evicting from disk
  const dryPurge = svc.purgeBySurrogateKey({
    tags: ['product-42'],
    providers: ['caddy', 'cloudflare', 'fastly'],
    dryRun: true
  });
  assert.strictEqual(dryPurge.ok, true);
  assert.strictEqual(dryPurge.dryRun, true);
  assert.strictEqual(dryPurge.invalidatedCount, 2);
  assert.strictEqual(dryPurge.providerPlans.length, 3);
  assert.strictEqual(svc.listEdgeCacheTags().find((t) => t.tag === 'product-42')?.entryCount, 2);

  // 4. Live purge (`dryRun: false`) evicts both product-42 entries while keeping /about
  const livePurge = svc.purgeBySurrogateKey({
    tags: ['product-42'],
    providers: ['caddy', 'cloudflare'],
    dryRun: false
  });
  assert.strictEqual(livePurge.dryRun, false);
  assert.strictEqual(livePurge.invalidatedCount, 2);
  assert.strictEqual(svc.listEdgeCacheTags().find((t) => t.tag === 'product-42'), undefined);
  assert.strictEqual(svc.listEdgeCacheTags().find((t) => t.tag === 'static')?.entryCount, 1);

  // 5. souin#850 coalescing: private & no-store MUST bypass; public coalesces bounded by backendTimeoutMs
  const privCoalesce = svc.evaluateCoalescing({
    cacheKey: '/api/me',
    inFlightCount: 25,
    backendTimeoutMs: 3000,
    cacheControl: 'private, max-age=30'
  });
  assert.strictEqual(privCoalesce.coalesced, false);
  assert.strictEqual(privCoalesce.reason, 'PRIVATE_OR_NO_STORE_BYPASS');
  assert.strictEqual(privCoalesce.safeForSharedCache, false);

  const noStoreCoalesce = svc.evaluateCoalescing({
    cacheKey: '/api/checkout',
    inFlightCount: 10,
    cacheControl: 'no-store'
  });
  assert.strictEqual(noStoreCoalesce.coalesced, false);
  assert.strictEqual(noStoreCoalesce.reason, 'PRIVATE_OR_NO_STORE_BYPASS');

  const pubCoalesce = svc.evaluateCoalescing({
    cacheKey: '/catalog',
    inFlightCount: 40,
    backendTimeoutMs: 4000,
    cacheControl: 'public, max-age=60, stale-while-revalidate=120'
  });
  assert.strictEqual(pubCoalesce.coalesced, true);
  assert.strictEqual(pubCoalesce.collapsedFollowers, 39);
  assert.ok(pubCoalesce.maxWaitMs <= 4000);
  assert.strictEqual(pubCoalesce.swrFallback, true);

  // 6. Cache-Control policy renderer
  const rendered = svc.renderCacheControlPolicy({
    visibility: 'public',
    maxAgeSec: 60,
    sMaxAgeSec: 300,
    staleWhileRevalidateSec: 120,
    surrogateKeys: ['catalog', 'home']
  });
  assert.ok(rendered.cacheControl.includes('s-maxage=300'));
  assert.strictEqual(rendered.surrogateKeyHeader, 'catalog home');
}

/**
 * Verifies VPA-lite P50/P95/P99 rightsizing, >= 10 sample guard, OOM +50% safety upscale,
 * Docker floor validation (<4 MiB RAM, <0.001 CPU), and uniform database Compose patches.
 * @param {string} tmpRoot
 */
function testResourceRightsizerService(tmpRoot) {
  const dataDir = path.join(tmpRoot, 'rightsize-data');
  const svc = new ResourceRightsizerService({ dataDir });

  // 1. Percentile accuracy
  assert.strictEqual(svc.computePercentile([100, 200, 300, 400, 500], 50), 300);
  assert.strictEqual(svc.computePercentile([100, 200, 300, 400, 500], 95), 500);

  // 2. Docker floor validation (Dokploy#903 / #927)
  const lowMem = svc.validateDockerLimits({ memoryMb: 2, cpuCores: 0.5 });
  assert.strictEqual(lowMem.valid, false);
  assert.strictEqual(lowMem.code, 'BELOW_DOCKER_MEMORY_FLOOR');

  const lowCpu = svc.validateDockerLimits({ memoryMb: 128, cpuCores: 0.0005 });
  assert.strictEqual(lowCpu.valid, false);
  assert.strictEqual(lowCpu.code, 'BELOW_DOCKER_CPU_FLOOR');

  const validLimits = svc.validateDockerLimits({ memoryMb: 256, cpuCores: 0.1254 });
  assert.strictEqual(validLimits.valid, true);
  assert.strictEqual(validLimits.normalized?.cpuCores, 0.125);

  // 3. < 10 samples guard -> INSUFFICIENT_SAMPLES
  const tooFew = svc.recommendContainerResources({
    projectId: 'proj_web',
    currentMemoryMb: 1024,
    currentCpuCores: 1,
    samples: [{ memoryMb: 200, cpuCores: 0.2 }, { memoryMb: 220, cpuCores: 0.2 }]
  });
  assert.strictEqual(tooFew.ok, false);
  assert.strictEqual(tooFew.code, 'INSUFFICIENT_SAMPLES');

  // 4. Overprovisioned 2048 MB app at P95 256 MB -> SHRINK with reclaimableMb > 1400!
  const idleSamples = Array.from({ length: 20 }, (_, i) => ({
    memoryMb: i < 18 ? 220 : 256,
    cpuCores: i < 18 ? 0.15 : 0.2
  }));
  const shrink = svc.recommendContainerResources({
    projectId: 'proj_web',
    serviceName: 'web-api',
    serviceType: 'app',
    currentMemoryMb: 2048,
    currentCpuCores: 2,
    samples: idleSamples,
    oomCount: 0
  });
  assert.strictEqual(shrink.ok, true);
  assert.strictEqual(shrink.action, 'SHRINK');
  assert.strictEqual(shrink.recommendedMemoryMb, 320); // ceil(256 * 1.25)
  assert.ok(shrink.reclaimableMb > 1400, `Expected reclaimableMb > 1400, got ${shrink.reclaimableMb}`);
  assert.ok(shrink.wastePct > 80);

  // 5. OOMing service (`oomCount: 2`) MUST upscale +50% and NEVER shrink!
  const oomUpscale = svc.recommendContainerResources({
    projectId: 'proj_worker',
    serviceName: 'pdf-worker',
    serviceType: 'app',
    currentMemoryMb: 512,
    currentCpuCores: 0.5,
    samples: idleSamples,
    oomCount: 2
  });
  assert.strictEqual(oomUpscale.ok, true);
  assert.strictEqual(oomUpscale.action, 'UPSCALE_OOM');
  assert.strictEqual(oomUpscale.recommendedMemoryMb, 768); // 512 * 1.5
  assert.strictEqual(oomUpscale.reclaimableMb, 0);

  // 6. Database rightsizing (+35% default headroom + uniform Compose deploy.resources patch — Dokploy#4050)
  const dbSamples = Array.from({ length: 12 }, () => ({ memoryMb: 500, cpuCores: 0.4 }));
  const dbRec = svc.recommendContainerResources({
    projectId: 'proj_db',
    serviceName: 'primary-pg',
    serviceType: 'database',
    currentMemoryMb: 2048,
    currentCpuCores: 2,
    samples: dbSamples,
    oomCount: 0
  });
  assert.strictEqual(dbRec.ok, true);
  assert.strictEqual(dbRec.headroomPct, 35);
  assert.strictEqual(dbRec.recommendedMemoryMb, 675); // ceil(500 * 1.35)
  const dbPatch = svc.buildComposeResourcePatch(dbRec);
  assert.strictEqual(dbPatch.ok, true);
  assert.strictEqual(dbPatch.patch.services['primary-pg'].deploy.resources.limits.memory, '675M');
  assert.ok(dbPatch.yaml.includes('deploy:') && dbPatch.yaml.includes('reservations:'));

  assert.ok(fs.existsSync(path.join(dataDir, 'resource-rightsizing.json')));
  assert.strictEqual(svc.listRecommendations().length, 3);
}

/**
 * Verifies BOTH singleton (`svc.fn`) AND destructured (`fn`) exports with dynamic `CULKIBO_DATA_DIR`.
 * @param {string} tmpRoot
 */
function testSingletonAndDestructuredExports(tmpRoot) {
  const prevDataDir = process.env.CULKIBO_DATA_DIR;
  process.env.CULKIBO_DATA_DIR = path.join(tmpRoot, 'singleton-env');

  try {
    // EdgeCacheService singleton + destructured
    assert.deepStrictEqual(parseSurrogateKeys(''), []);
    edgeCacheService.registerCachedEntry({ cacheKey: '/s/1', surrogateKeys: 'k1 k2' });
    assert.strictEqual(registerCachedEntry({ cacheKey: '/s/2', surrogateKeys: ['k1'] }).ok, true);
    assert.strictEqual(listEdgeCacheTags().find((t) => t.tag === 'k1')?.entryCount, 2);
    assert.strictEqual(purgeBySurrogateKey({ tags: ['k1'], dryRun: false }).invalidatedCount, 2);
    assert.strictEqual(evaluateCoalescing({ cacheKey: '/x', cacheControl: 'private' }).reason, 'PRIVATE_OR_NO_STORE_BYPASS');
    assert.ok(renderCacheControlPolicy({ maxAgeSec: 120 }).cacheControl.includes('max-age=120'));

    // ResourceRightsizerService singleton + destructured
    assert.strictEqual(computePercentile([10, 20, 30], 50), 20);
    assert.strictEqual(validateDockerLimits({ memoryMb: 3, cpuCores: 0.5 }).code, 'BELOW_DOCKER_MEMORY_FLOOR');
    const rec = recommendContainerResources({
      projectId: 'singleton-p',
      currentMemoryMb: 1024,
      currentCpuCores: 1,
      samples: [100, 120, 140, 150, 160, 170, 180, 190, 200, 200]
    });
    assert.strictEqual(rec.ok, true);
    assert.strictEqual(buildComposeResourcePatch(rec).ok, true);
    assert.strictEqual(listRecommendations('singleton-p').length, 1);
    assert.strictEqual(resourceRightsizerService.listRecommendations('singleton-p').length, 1);
  } finally {
    if (prevDataDir === undefined) {
      delete process.env.CULKIBO_DATA_DIR;
    } else {
      process.env.CULKIBO_DATA_DIR = prevDataDir;
    }
  }
}

async function runAllTests() {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-c17-cache-rightsize-'));
  try {
    testEdgeCacheService(tmpRoot);
    testResourceRightsizerService(tmpRoot);
    testSingletonAndDestructuredExports(tmpRoot);
    console.log('✅ cache-and-rightsizer.test.js PASSED (souin#884/#850 surrogate cache, VPA-lite P95/OOM+50%, Docker floors, Compose DB patch, singleton+destructured)');
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }
}

if (require.main === module) {
  runAllTests().catch((err) => {
    console.error('❌ cache-and-rightsizer.test.js FAILED:', err);
    process.exit(1);
  });
}

module.exports = runAllTests;
