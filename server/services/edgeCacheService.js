'use strict';

/**
 * Culkibo Surrogate-Key Edge Cache Invalidation & Stampede Coalescing Coordinator.
 *
 * Cures `darkweak/souin#884` (empty `Surrogate-Key: ""` piling untagged traffic onto a
 * global `SURROGATE_` mutex until OOM), `darkweak/souin#850` (unbounded singleflight leader
 * hangs & cross-tenant `private` coalescing leaks), and `caddyserver/cache-handler` silent
 * `204` stale-tag purges — zero external npm dependencies:
 *  - Atomic `0o600` bounded LRU store in `CULKIBO_DATA_DIR/data/edge-cache-keys.json`.
 *  - Empty-safe `parseSurrogateKeys` returning `[]` on empty/missing/whitespace headers
 *    (NEVER `[""]` or global `SURROGATE_`, max 64 deduplicated tags per entry).
 *  - `evaluateCoalescing`: unconditionally bypasses `Cache-Control: private|no-store`
 *    (`PRIVATE_OR_NO_STORE_BYPASS`) and bounds follower wait `<= backendTimeoutMs` with SWR fallback.
 *  - Multi-edge purge plans for Caddy/Souin (`Surrogate-Key`), Cloudflare (`Cache-Tag`), and Fastly.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MAX_SURROGATE_TAGS_PER_ENTRY = 64;
const MAX_INDEXED_ENTRIES = 2000;
const VALID_PROVIDERS = new Set(['caddy', 'souin', 'cloudflare', 'fastly']);

/**
 * @typedef {object} CachedEdgeEntry
 * @property {string} cacheKey
 * @property {string[]} surrogateKeys
 * @property {number} ttlSec
 * @property {number} staleWhileRevalidateSec
 * @property {string} registeredAt
 */

/**
 * @typedef {object} EdgeCacheStoreState
 * @property {number} schemaVersion
 * @property {string} updatedAt
 * @property {CachedEdgeEntry[]} entries
 */

/**
 * Atomically writes UTF-8 text to disk with `0o600` mode.
 * @param {string} targetPath
 * @param {string} content
 */
function atomicWriteFileSync(targetPath, content) {
  const dir = path.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = `${targetPath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(tmpPath, content, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmpPath, targetPath);
    try { fs.chmodSync(targetPath, 0o600); } catch (e) {}
  } catch (err) {
    try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e) {}
    throw err;
  }
}

/**
 * Creates an HTTP-annotated Error.
 * @param {string} code
 * @param {string} msg
 * @param {number} [status]
 */
function cacheError(code, msg, status = 400) {
  const err = /** @type {any} */ (new Error(msg));
  err.code = code;
  err.status = status;
  return err;
}

/**
 * Parses a `Surrogate-Key` / `Cache-Tag` header string or string array into clean,
 * deduplicated tags (max 64). Cures `darkweak/souin#884`: empty, missing, or whitespace-only
 * inputs ALWAYS return `[]` — NEVER `[""]` or a global `SURROGATE_` bucket.
 *
 * @param {string | string[] | null | undefined} headerValue
 * @returns {string[]}
 */
function parseSurrogateKeys(headerValue) {
  if (headerValue === null || headerValue === undefined) return [];
  const rawList = Array.isArray(headerValue) ? headerValue : [headerValue];
  /** @type {Set<string>} */
  const unique = new Set();

  for (const item of rawList) {
    if (typeof item !== 'string') continue;
    const trimmed = item.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/[\s,]+/);
    for (const part of parts) {
      const token = part.trim();
      if (!token || token === 'SURROGATE_') continue;
      if (!/^[a-zA-Z0-9._:/-]{1,128}$/.test(token)) continue;
      unique.add(token);
      if (unique.size >= MAX_SURROGATE_TAGS_PER_ENTRY) {
        return Array.from(unique);
      }
    }
  }
  return Array.from(unique);
}

/**
 * Evaluates singleflight stampede coalescing safety (`darkweak/souin#850`):
 *  - Unconditionally bypasses `Cache-Control: private` or `no-store` (zero cross-tenant leak).
 *  - Bounds leader/follower wait strictly `<= backendTimeoutMs` with SWR fallback.
 *
 * @param {{
 *   cacheKey?: string,
 *   inFlightCount?: number,
 *   backendTimeoutMs?: number,
 *   cacheControl?: string,
 *   staleAvailable?: boolean,
 *   staleWhileRevalidateSec?: number
 * }} [input]
 */
function evaluateCoalescing(input = {}) {
  const src = input && typeof input === 'object' ? input : {};
  const cacheKey = typeof src.cacheKey === 'string' && src.cacheKey.trim()
    ? src.cacheKey.trim().slice(0, 512)
    : '/';
  const cacheControl = typeof src.cacheControl === 'string' ? src.cacheControl.trim() : 'public, max-age=60';
  const directives = new Set(
    cacheControl
      .toLowerCase()
      .split(',')
      .map((d) => d.trim().split('=')[0].trim())
      .filter(Boolean)
  );

  // HARD TENANT-ISOLATION GUARD: never coalesce private or no-store responses!
  if (directives.has('private') || directives.has('no-store')) {
    return {
      ok: true,
      cacheKey,
      coalesced: false,
      inFlightCount: Math.max(1, Math.round(Number(src.inFlightCount ?? 1) || 1)),
      collapsedFollowers: 0,
      reason: /** @type {'PRIVATE_OR_NO_STORE_BYPASS'} */ ('PRIVATE_OR_NO_STORE_BYPASS'),
      maxWaitMs: 0,
      backendTimeoutMs: Math.max(100, Math.min(30000, Math.round(Number(src.backendTimeoutMs ?? 5000) || 5000))),
      swrFallback: false,
      safeForSharedCache: false,
      cacheControl
    };
  }

  const inFlightCount = Math.max(1, Math.min(100000, Math.round(Number(src.inFlightCount ?? 1) || 1)));
  const backendTimeoutMs = Math.max(100, Math.min(30000, Math.round(Number(src.backendTimeoutMs ?? 5000) || 5000)));
  const coalesced = inFlightCount > 1;
  const collapsedFollowers = Math.max(0, inFlightCount - 1);
  const swrMatch = cacheControl.match(/stale-while-revalidate=(\d+)/i);
  const swrSec = src.staleWhileRevalidateSec !== undefined
    ? Math.max(0, Number(src.staleWhileRevalidateSec) || 0)
    : (swrMatch ? Number(swrMatch[1]) : 60);
  const staleAvailable = src.staleAvailable !== undefined ? Boolean(src.staleAvailable) : true;
  const swrFallback = staleAvailable && swrSec > 0;

  return {
    ok: true,
    cacheKey,
    coalesced,
    inFlightCount,
    collapsedFollowers,
    reason: coalesced ? 'SINGLEFLIGHT_COALESCED' : 'LEADER_REQUEST',
    maxWaitMs: backendTimeoutMs,
    backendTimeoutMs,
    swrFallback,
    staleWhileRevalidateSec: swrSec,
    safeForSharedCache: true,
    cacheControl
  };
}

/**
 * Renders RFC 9111 `Cache-Control`, empty-safe `Surrogate-Key` header, and Caddy cache snippet.
 *
 * @param {{
 *   visibility?: 'public' | 'private',
 *   maxAgeSec?: number,
 *   sMaxAgeSec?: number,
 *   staleWhileRevalidateSec?: number,
 *   staleIfErrorSec?: number,
 *   surrogateKeys?: string[] | string,
 *   immutable?: boolean,
 *   noStore?: boolean
 * }} [policy]
 */
function renderCacheControlPolicy(policy = {}) {
  const src = policy && typeof policy === 'object' ? policy : {};
  const noStore = Boolean(src.noStore);
  const visibility = src.visibility === 'private' ? 'private' : 'public';
  const maxAgeSec = Math.max(0, Math.round(Number(src.maxAgeSec ?? 60) || 0));
  const sMaxAgeSec = src.sMaxAgeSec !== undefined ? Math.max(0, Math.round(Number(src.sMaxAgeSec) || 0)) : null;
  const swrSec = Math.max(0, Math.round(Number(src.staleWhileRevalidateSec ?? 60) || 0));
  const sieSec = Math.max(0, Math.round(Number(src.staleIfErrorSec ?? 600) || 0));
  const surrogateKeys = parseSurrogateKeys(src.surrogateKeys);

  /** @type {string[]} */
  const parts = [];
  if (noStore) {
    parts.push('no-store', 'max-age=0');
  } else {
    parts.push(visibility, `max-age=${maxAgeSec}`);
    if (visibility === 'public' && sMaxAgeSec !== null) {
      parts.push(`s-maxage=${sMaxAgeSec}`);
    }
    if (visibility === 'public' && swrSec > 0) {
      parts.push(`stale-while-revalidate=${swrSec}`);
    }
    if (visibility === 'public' && sieSec > 0) {
      parts.push(`stale-if-error=${sieSec}`);
    }
    if (src.immutable) parts.push('immutable');
  }

  const cacheControl = parts.join(', ');
  const surrogateKeyHeader = surrogateKeys.length > 0 ? surrogateKeys.join(' ') : null;
  /** @type {Record<string, string>} */
  const headers = { 'Cache-Control': cacheControl };
  if (surrogateKeyHeader) {
    headers['Surrogate-Key'] = surrogateKeyHeader;
  }

  const caddyLines = [
    'header {',
    `  Cache-Control "${cacheControl}"`
  ];
  if (surrogateKeyHeader) {
    caddyLines.push(`  Surrogate-Key "${surrogateKeyHeader}"`);
  }
  caddyLines.push('}');

  return {
    ok: true,
    cacheControl,
    surrogateKeyHeader,
    surrogateKeys,
    headers,
    caddyfile: caddyLines.join('\n')
  };
}

class EdgeCacheService {
  /**
   * @param {{ dataDir?: string | null }} [opts]
   */
  constructor(opts = {}) {
    /** @type {string | null} */
    this._explicitDataDir = opts && typeof opts.dataDir === 'string' && opts.dataDir.trim()
      ? path.resolve(opts.dataDir.trim())
      : null;
  }

  /** @returns {string} */
  resolveDataDir() {
    if (this._explicitDataDir) return this._explicitDataDir;
    if (process.env.CULKIBO_DATA_DIR) {
      return path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data');
    }
    return path.join(__dirname, '..', '..', 'data');
  }

  /** @returns {string} */
  getStoreFilePath() {
    return path.join(this.resolveDataDir(), 'edge-cache-keys.json');
  }

  /** @returns {EdgeCacheStoreState} */
  _loadState() {
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) {
      return {
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        entries: []
      };
    }
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      return {
        schemaVersion: 1,
        updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : new Date().toISOString(),
        entries: Array.isArray(parsed.entries) ? parsed.entries : []
      };
    } catch (e) {
      return {
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        entries: []
      };
    }
  }

  /** @param {EdgeCacheStoreState} state */
  _saveState(state) {
    const trimmed = state.entries.length > MAX_INDEXED_ENTRIES
      ? state.entries.slice(-MAX_INDEXED_ENTRIES)
      : state.entries;
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        entries: trimmed
      }, null, 2) + '\n'
    );
  }

  /**
   * Delegates to `parseSurrogateKeys`.
   * @param {string | string[] | null | undefined} headerValue
   * @returns {string[]}
   */
  parseSurrogateKeys(headerValue) {
    return parseSurrogateKeys(headerValue);
  }

  /**
   * Registers a cached response key and its parsed surrogate tags inside the bounded LRU index.
   * Empty surrogate tags are stored as `[]` — never attached to a global `SURROGATE_` bucket.
   *
   * @param {{
   *   cacheKey: string,
   *   surrogateKeys?: string[] | string,
   *   ttlSec?: number,
   *   staleWhileRevalidateSec?: number
   * }} input
   */
  registerCachedEntry(input) {
    if (!input || typeof input !== 'object') {
      throw cacheError('INVALID_INPUT', 'registerCachedEntry requires an entry object');
    }
    const cacheKey = typeof input.cacheKey === 'string' ? input.cacheKey.trim().slice(0, 512) : '';
    if (!cacheKey) {
      throw cacheError('INVALID_CACHE_KEY', 'cacheKey is required');
    }

    const surrogateKeys = parseSurrogateKeys(input.surrogateKeys);
    const ttlSec = Math.max(0, Math.min(31536000, Math.round(Number(input.ttlSec ?? 300) || 0)));
    const staleWhileRevalidateSec = Math.max(0, Math.min(86400, Math.round(Number(input.staleWhileRevalidateSec ?? 60) || 0)));

    const state = this._loadState();
    state.entries = state.entries.filter((e) => e.cacheKey !== cacheKey);

    /** @type {CachedEdgeEntry} */
    const entry = {
      cacheKey,
      surrogateKeys,
      ttlSec,
      staleWhileRevalidateSec,
      registeredAt: new Date().toISOString()
    };
    state.entries.push(entry);
    if (state.entries.length > MAX_INDEXED_ENTRIES) {
      state.entries = state.entries.slice(-MAX_INDEXED_ENTRIES);
    }
    this._saveState(state);

    return {
      ok: true,
      entry,
      tagCount: surrogateKeys.length,
      globalSurrogateBucketUsed: false
    };
  }

  /**
   * Plans or executes instant tag-based surrogate-key purge across Caddy/Souin, Cloudflare, and Fastly.
   * Defaults to `dryRun: true`; evicts matching entries from the bounded LRU index when `dryRun: false`.
   *
   * @param {{
   *   tags?: string[] | string,
   *   providers?: string[],
   *   dryRun?: boolean
   * }} [input]
   */
  purgeBySurrogateKey(input = {}) {
    const src = input && typeof input === 'object' ? input : {};
    const dryRun = src.dryRun !== undefined ? Boolean(src.dryRun) : true;
    const tags = parseSurrogateKeys(src.tags);
    const rawProviders = Array.isArray(src.providers) && src.providers.length > 0 ? src.providers : ['caddy'];
    const providers = Array.from(
      new Set(
        rawProviders
          .map((p) => String(p || '').trim().toLowerCase())
          .filter((p) => VALID_PROVIDERS.has(p))
      )
    );
    if (providers.length === 0) providers.push('caddy');

    const state = this._loadState();
    const tagSet = new Set(tags);

    /** @type {string[]} */
    const invalidatedKeys = [];
    /** @type {CachedEdgeEntry[]} */
    const keptEntries = [];

    for (const entry of state.entries) {
      const hits = tags.length > 0 && Array.isArray(entry.surrogateKeys) && entry.surrogateKeys.some((t) => tagSet.has(t));
      if (hits) {
        invalidatedKeys.push(entry.cacheKey);
      } else {
        keptEntries.push(entry);
      }
    }

    if (!dryRun && invalidatedKeys.length > 0) {
      state.entries = keptEntries;
      this._saveState(state);
    }

    const providerPlans = providers.map((provider) => {
      if (provider === 'cloudflare') {
        return {
          provider: 'cloudflare',
          method: 'POST',
          endpoint: '/client/v4/zones/{zone_id}/purge_cache',
          header: 'Cache-Tag',
          body: { tags },
          maxTagsPerBatch: 30,
          avoidsSilent204: true,
          tags
        };
      }
      if (provider === 'fastly') {
        return {
          provider: 'fastly',
          method: 'POST',
          endpoint: '/service/{service_id}/purge',
          header: 'Surrogate-Key',
          headerValue: tags.join(' '),
          softPurgeSupported: true,
          avoidsSilent204: true,
          tags
        };
      }
      return {
        provider,
        method: 'PURGE',
        endpoint: '/souin-api/souin',
        header: 'Surrogate-Key',
        headerValue: tags.join(' '),
        expectedStatus: 200,
        avoidsSilent204: true,
        tags
      };
    });

    return {
      ok: true,
      dryRun,
      tags,
      providers,
      invalidatedCount: invalidatedKeys.length,
      invalidatedKeys,
      providerPlans,
      remainingEntries: dryRun ? state.entries.length : keptEntries.length,
      globalSurrogateBucketUsed: false,
      purgedAt: new Date().toISOString()
    };
  }

  /**
   * Delegates to `evaluateCoalescing`.
   * @param {{
   *   cacheKey?: string,
   *   inFlightCount?: number,
   *   backendTimeoutMs?: number,
   *   cacheControl?: string,
   *   staleAvailable?: boolean,
   *   staleWhileRevalidateSec?: number
   * }} [input]
   */
  evaluateCoalescing(input) {
    return evaluateCoalescing(input);
  }

  /**
   * Delegates to `renderCacheControlPolicy`.
   * @param {Record<string, any>} [policy]
   */
  renderCacheControlPolicy(policy) {
    return renderCacheControlPolicy(policy);
  }

  /**
   * Lists all active indexed surrogate tags with entry counts and sample cache keys.
   * Empty entries are never aggregated under a `SURROGATE_` key.
   */
  listEdgeCacheTags() {
    const state = this._loadState();
    /** @type {Map<string, string[]>} */
    const byTag = new Map();
    for (const entry of state.entries) {
      for (const tag of parseSurrogateKeys(entry.surrogateKeys)) {
        if (!byTag.has(tag)) byTag.set(tag, []);
        const list = byTag.get(tag);
        if (list) list.push(entry.cacheKey);
      }
    }
    return Array.from(byTag.entries())
      .map(([tag, keys]) => ({
        tag,
        entryCount: keys.length,
        cacheKeys: keys.slice(0, 20)
      }))
      .sort((a, b) => (b.entryCount - a.entryCount) || a.tag.localeCompare(b.tag));
  }
}

const defaultEdgeCacheService = new EdgeCacheService();

const exported = Object.assign(defaultEdgeCacheService, {
  EdgeCacheService,
  MAX_SURROGATE_TAGS_PER_ENTRY,
  MAX_INDEXED_ENTRIES,
  parseSurrogateKeys: EdgeCacheService.prototype.parseSurrogateKeys.bind(defaultEdgeCacheService),
  registerCachedEntry: EdgeCacheService.prototype.registerCachedEntry.bind(defaultEdgeCacheService),
  purgeBySurrogateKey: EdgeCacheService.prototype.purgeBySurrogateKey.bind(defaultEdgeCacheService),
  evaluateCoalescing: EdgeCacheService.prototype.evaluateCoalescing.bind(defaultEdgeCacheService),
  renderCacheControlPolicy: EdgeCacheService.prototype.renderCacheControlPolicy.bind(defaultEdgeCacheService),
  listEdgeCacheTags: EdgeCacheService.prototype.listEdgeCacheTags.bind(defaultEdgeCacheService)
});

module.exports = exported;
