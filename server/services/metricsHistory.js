const fs = require('fs');
const os = require('os');
const path = require('path');
const { EventEmitter } = require('events');
const { atomicWriteJsonSync, loadJsonWithBackupSync } = require('./ssrfGuard');

/**
 * Lightweight 2-tier persisted time-series ring buffer (zero npm deps, <300 KB RAM).
 *
 * - Tier 1 (1-minute resolution): up to 1,440 samples (24 hours).
 * - Tier 2 (15-minute rollups):   up to 672 samples (7 days).
 * - Deploy markers ring:          up to 200 markers (7 days) for chart overlays.
 * - Lazy sampler: 0 timers on require(); `start()` creates a single `.unref()` timer.
 * - Uses Linux `/proc/meminfo` `MemAvailable` (avoiding page-cache false alarms)
 *   and `os.cpus()` tick deltas for real cross-platform host CPU%.
 */

const TIER_1M_CAP = 1440; // 24h @ 1m
const TIER_15M_CAP = 672; // 7d @ 15m
const MARKERS_CAP = 200;
const FIFTEEN_MIN_MS = 15 * 60 * 1000;
const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
const DEFAULT_SAMPLE_INTERVAL_MS = 60 * 1000;
const DEFAULT_FLUSH_EVERY_SAMPLES = 5;

function resolveDataDir() {
  return process.env.CULKIBO_DATA_DIR
    ? path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data')
    : path.resolve(__dirname, '..', '..', 'data');
}

/**
 * Reads host memory stats accurately. On Linux parses `/proc/meminfo` `MemAvailable`
 * so reclaimable page cache never triggers false OOM/RAM pressure alerts.
 * @param {(() => string | null) | null} [readProcMeminfo]
 */
function readHostMemoryStats(readProcMeminfo = null) {
  const totalBytes = os.totalmem();
  let totalMb = Math.round(totalBytes / (1024 * 1024));
  let availableMb = Math.round(os.freemem() / (1024 * 1024));
  let swapTotalMb = 0;
  let swapUsedMb = 0;
  let swapUsedPct = 0;
  let source = 'os_freemem';

  if (typeof readProcMeminfo === 'function' || process.platform === 'linux') {
    try {
      const raw = typeof readProcMeminfo === 'function'
        ? readProcMeminfo()
        : fs.readFileSync('/proc/meminfo', 'utf8');
      if (typeof raw === 'string' && raw.length > 0) {
        /** @type {Record<string, number>} */
        const map = {};
        for (const line of raw.split(/\r?\n/)) {
          const m = line.match(/^([A-Za-z0-9_()]+):\s+(\d+)\s+kB/);
          if (m) map[m[1]] = Math.round(Number(m[2]) / 1024);
        }
        if (map.MemTotal > 0) {
          totalMb = map.MemTotal;
          availableMb = map.MemAvailable !== undefined
            ? map.MemAvailable
            : (map.MemFree || 0) + (map.Buffers || 0) + (map.Cached || 0);
          swapTotalMb = map.SwapTotal || 0;
          const swapFreeMb = map.SwapFree || 0;
          swapUsedMb = Math.max(0, swapTotalMb - swapFreeMb);
          swapUsedPct = swapTotalMb > 0 ? Math.round((swapUsedMb / swapTotalMb) * 100) : 0;
          source = 'proc_meminfo';
        }
      }
    } catch (e) {}
  }

  availableMb = Math.max(0, Math.min(totalMb, availableMb));
  const usedMb = Math.max(0, totalMb - availableMb);
  const usedPct = totalMb > 0 ? Number(((usedMb / totalMb) * 100).toFixed(1)) : 0;
  const availablePct = totalMb > 0 ? Number(((availableMb / totalMb) * 100).toFixed(1)) : 100;

  return {
    totalMb,
    usedMb,
    availableMb,
    usedPct,
    availablePct,
    swapTotalMb,
    swapUsedMb,
    swapUsedPct,
    source
  };
}

/**
 * Reads disk usage stats for a target directory using Node's native `fs.statfsSync`.
 * @param {string} [targetDir]
 */
function readDiskStats(targetDir) {
  const dir = targetDir || resolveDataDir();
  try {
    if (typeof fs.statfsSync === 'function') {
      const probeDir = fs.existsSync(dir) ? dir : path.dirname(dir);
      const st = fs.statfsSync(probeDir);
      const totalBytes = Number(st.blocks) * Number(st.bsize);
      const freeBytes = Number(st.bavail) * Number(st.bsize);
      if (Number.isFinite(totalBytes) && totalBytes > 0) {
        const totalGb = Number((totalBytes / (1024 ** 3)).toFixed(1));
        const freeGb = Number((Math.max(0, freeBytes) / (1024 ** 3)).toFixed(1));
        const usedPct = Number((((totalBytes - Math.max(0, freeBytes)) / totalBytes) * 100).toFixed(1));
        return { available: true, totalGb, freeGb, usedPct };
      }
    }
  } catch (e) {}
  return { available: false, totalGb: null, freeGb: null, usedPct: null };
}

/** Captures aggregate CPU tick totals across all cores via `os.cpus()`. */
function readHostCpuTotals() {
  const cpus = os.cpus();
  let idle = 0;
  let total = 0;
  for (let i = 0; i < cpus.length; i++) {
    const t = cpus[i].times;
    const sum = (t.user || 0) + (t.nice || 0) + (t.sys || 0) + (t.idle || 0) + (t.irq || 0);
    idle += t.idle || 0;
    total += sum;
  }
  return { idle, total, cores: cpus.length || 1 };
}

/**
 * Computes host CPU usage percent from two `readHostCpuTotals()` readings.
 * @param {{ idle: number, total: number } | null} prev
 * @param {{ idle: number, total: number }} curr
 * @returns {number | null}
 */
function computeHostCpuDelta(prev, curr) {
  if (!prev || !curr) return null;
  const totalDiff = curr.total - prev.total;
  const idleDiff = curr.idle - prev.idle;
  if (totalDiff <= 0) return 0;
  const busy = Math.max(0, totalDiff - Math.max(0, idleDiff));
  return Number(Math.min(100, Math.max(0, (busy / totalDiff) * 100)).toFixed(1));
}

/**
 * Normalizes a persisted or incoming point into compact bounded shape.
 * @param {any} p
 */
function normalizePoint(p) {
  if (!p || typeof p !== 'object' || !Number.isFinite(Number(p.ts))) return null;
  const num = (v, def = 0) => (typeof v === 'number' && Number.isFinite(v) ? Number(v.toFixed(2)) : def);
  const optNum = (v) => (typeof v === 'number' && Number.isFinite(v) ? Number(v.toFixed(2)) : null);
  return {
    ts: Math.round(Number(p.ts)),
    hostCpuPct: num(p.hostCpuPct, 0),
    hostRamPct: num(p.hostRamPct, 0),
    hostRamUsedMb: Math.round(Number(p.hostRamUsedMb) || 0),
    hostRamTotalMb: Math.round(Number(p.hostRamTotalMb) || 0),
    diskUsedPct: optNum(p.diskUsedPct),
    diskFreeGb: optNum(p.diskFreeGb),
    rssMb: Math.round(Number(p.rssMb) || 0),
    heapMb: Math.round(Number(p.heapMb) || 0),
    elLagMs: num(p.elLagMs, 0),
    rps: num(p.rps, 0),
    p50Ms: num(p.p50Ms, 0),
    p95Ms: num(p.p95Ms, 0),
    errorRatePct: num(p.errorRatePct, 0),
    err5xxRatePct: num(p.err5xxRatePct, 0),
    reqDelta: Math.max(0, Math.round(Number(p.reqDelta) || 0))
  };
}

class MetricsHistory extends EventEmitter {
  /**
   * @param {{
   *   storeFile?: string | null,
   *   metricsCollector?: any,
   *   readProcMeminfo?: (() => string | null) | null,
   *   readDiskStatsFn?: (() => { available: boolean, totalGb: number | null, freeGb: number | null, usedPct: number | null }) | null,
   *   flushEverySamples?: number,
   *   sampleIntervalMs?: number
   * }} [options]
   */
  constructor(options = {}) {
    super();
    this._customStoreFile = options.storeFile || null;
    this._metricsCollector = options.metricsCollector || null;
    this._readProcMeminfo = options.readProcMeminfo || null;
    this._readDiskStatsFn = options.readDiskStatsFn || null;
    this._flushEverySamples = Math.max(1, Number(options.flushEverySamples) || DEFAULT_FLUSH_EVERY_SAMPLES);
    this._sampleIntervalMs = Math.max(1000, Number(options.sampleIntervalMs) || DEFAULT_SAMPLE_INTERVAL_MS);

    /** @type {Array<ReturnType<typeof normalizePoint> & {}>} */
    this.tier1m = [];
    /** @type {Array<any>} */
    this.tier15m = [];
    /** @type {Array<{ ts: number, projectId: string | null, projectName: string, status: string, label: string }>} */
    this.deployMarkers = [];

    this._loaded = false;
    this._dirty = false;
    this._samplesSinceFlush = 0;
    /** @type {ReturnType<typeof setInterval> | null} */
    this._timer = null;

    // Deltas for interval-accurate CPU and HTTP error-rate
    this._prevCpu = readHostCpuTotals();
    this._prevHttp = { requests: 0, err4xx: 0, err5xx: 0, ts: 0 };
  }

  getStoreFile() {
    if (this._customStoreFile) return this._customStoreFile;
    return path.join(resolveDataDir(), 'metrics-history.json');
  }

  _getMetricsCollector() {
    if (this._metricsCollector) return this._metricsCollector;
    try {
      this._metricsCollector = require('./metricsCollector');
    } catch (e) {
      this._metricsCollector = null;
    }
    return this._metricsCollector;
  }

  _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;
    const file = this.getStoreFile();
    const res = loadJsonWithBackupSync(file, {
      validate: (parsed) => Boolean(parsed && typeof parsed === 'object' && Array.isArray(parsed.tier1m))
    });
    if (res.ok && res.data) {
      const now = Date.now();
      const cutoff7d = now - SEVEN_DAYS_MS;
      const cutoff24h = now - 24 * 60 * 60 * 1000;

      const loaded1m = [];
      for (const raw of res.data.tier1m || []) {
        const pt = normalizePoint(raw);
        if (pt && pt.ts >= cutoff24h) loaded1m.push(pt);
      }
      this.tier1m = loaded1m.slice(-TIER_1M_CAP);

      const loaded15m = [];
      for (const raw of res.data.tier15m || []) {
        const pt = normalizePoint(raw);
        if (pt && pt.ts >= cutoff7d) {
          loaded15m.push({
            ...pt,
            samples: Math.max(1, Math.round(Number(raw.samples) || 1)),
            maxHostCpuPct: typeof raw.maxHostCpuPct === 'number' ? raw.maxHostCpuPct : pt.hostCpuPct,
            maxHostRamPct: typeof raw.maxHostRamPct === 'number' ? raw.maxHostRamPct : pt.hostRamPct,
            maxP95Ms: typeof raw.maxP95Ms === 'number' ? raw.maxP95Ms : pt.p95Ms
          });
        }
      }
      this.tier15m = loaded15m.slice(-TIER_15M_CAP);

      if (Array.isArray(res.data.deployMarkers)) {
        this.deployMarkers = res.data.deployMarkers
          .filter((m) => m && Number.isFinite(Number(m.ts)) && Number(m.ts) >= cutoff7d)
          .slice(-MARKERS_CAP);
      }
    }
  }

  /**
   * Flushes persisted rings atomically to disk.
   * @returns {{ flushed: boolean, file: string, tier1mCount: number, tier15mCount: number, bytes: number }}
   */
  flush() {
    this._ensureLoaded();
    const file = this.getStoreFile();
    const payload = {
      version: 1,
      updatedAt: new Date().toISOString(),
      tier1m: this.tier1m.slice(-TIER_1M_CAP),
      tier15m: this.tier15m.slice(-TIER_15M_CAP),
      deployMarkers: this.deployMarkers.slice(-MARKERS_CAP)
    };
    const serialized = JSON.stringify(payload);
    atomicWriteJsonSync(file, payload, { mode: 0o600, backup: true });
    this._dirty = false;
    this._samplesSinceFlush = 0;
    return {
      flushed: true,
      file,
      tier1mCount: payload.tier1m.length,
      tier15mCount: payload.tier15m.length,
      bytes: Buffer.byteLength(serialized, 'utf8')
    };
  }

  /**
   * Updates the 15-minute rollup bucket with a new 1-minute sample.
   * @param {NonNullable<ReturnType<typeof normalizePoint>>} pt
   */
  _ingestInto15mRollup(pt) {
    const bucketTs = Math.floor(pt.ts / FIFTEEN_MIN_MS) * FIFTEEN_MIN_MS;
    const last = this.tier15m.length > 0 ? this.tier15m[this.tier15m.length - 1] : null;

    if (last && last.ts === bucketTs) {
      const n = (last.samples || 1) + 1;
      const blend = (prev, cur) => Number((((prev * (n - 1)) + cur) / n).toFixed(2));
      last.hostCpuPct = blend(last.hostCpuPct, pt.hostCpuPct);
      last.hostRamPct = blend(last.hostRamPct, pt.hostRamPct);
      last.hostRamUsedMb = Math.round(((last.hostRamUsedMb * (n - 1)) + pt.hostRamUsedMb) / n);
      last.hostRamTotalMb = pt.hostRamTotalMb || last.hostRamTotalMb;
      if (pt.diskUsedPct !== null) {
        last.diskUsedPct = last.diskUsedPct === null ? pt.diskUsedPct : blend(last.diskUsedPct, pt.diskUsedPct);
      }
      if (pt.diskFreeGb !== null) last.diskFreeGb = pt.diskFreeGb;
      last.rssMb = Math.round(((last.rssMb * (n - 1)) + pt.rssMb) / n);
      last.heapMb = Math.round(((last.heapMb * (n - 1)) + pt.heapMb) / n);
      last.elLagMs = blend(last.elLagMs, pt.elLagMs);
      last.rps = blend(last.rps, pt.rps);
      last.p50Ms = blend(last.p50Ms, pt.p50Ms);
      last.p95Ms = blend(last.p95Ms, pt.p95Ms);
      last.errorRatePct = blend(last.errorRatePct, pt.errorRatePct);
      last.err5xxRatePct = blend(last.err5xxRatePct, pt.err5xxRatePct);
      last.reqDelta = (last.reqDelta || 0) + (pt.reqDelta || 0);
      last.maxHostCpuPct = Math.max(last.maxHostCpuPct ?? last.hostCpuPct, pt.hostCpuPct);
      last.maxHostRamPct = Math.max(last.maxHostRamPct ?? last.hostRamPct, pt.hostRamPct);
      last.maxP95Ms = Math.max(last.maxP95Ms ?? last.p95Ms, pt.p95Ms);
      last.samples = n;
      return;
    }

    this.tier15m.push({
      ...pt,
      ts: bucketTs,
      samples: 1,
      maxHostCpuPct: pt.hostCpuPct,
      maxHostRamPct: pt.hostRamPct,
      maxP95Ms: pt.p95Ms
    });
    if (this.tier15m.length > TIER_15M_CAP) {
      this.tier15m.splice(0, this.tier15m.length - TIER_15M_CAP);
    }
  }

  /**
   * Collects one real sample (or ingests an explicit override in tests), appends
   * to the 24h & 7d rings, emits `'sample'`, and flushes periodically to disk.
   * @param {Partial<NonNullable<ReturnType<typeof normalizePoint>>> | null} [override]
   */
  sampleNow(override = null) {
    this._ensureLoaded();
    const now = override && Number.isFinite(Number(override.ts)) ? Math.round(Number(override.ts)) : Date.now();

    let pt;
    if (override && typeof override === 'object' && Object.keys(override).length > 1) {
      pt = normalizePoint({ ts: now, ...override });
    } else {
      const cpuNow = readHostCpuTotals();
      const hostCpuPct = computeHostCpuDelta(this._prevCpu, cpuNow) ?? 0;
      this._prevCpu = cpuNow;

      const mem = readHostMemoryStats(this._readProcMeminfo);
      const disk = this._readDiskStatsFn ? this._readDiskStatsFn() : readDiskStats();
      const procMem = process.memoryUsage();
      const rssMb = Math.round(procMem.rss / (1024 * 1024));
      const heapMb = Math.round(procMem.heapUsed / (1024 * 1024));

      const mc = this._getMetricsCollector();
      let rps = 0;
      let p50Ms = 0;
      let p95Ms = 0;
      let elLagMs = 0;
      let reqDelta = 0;
      let errorRatePct = 0;
      let err5xxRatePct = 0;

      if (mc && typeof mc.getSnapshot === 'function') {
        const snap = mc.getSnapshot(false);
        rps = Number(snap?.http?.rps?.rps60s ?? snap?.http?.rps?.rps10s ?? 0) || 0;
        p50Ms = Number(snap?.http?.latencyMs?.p50 ?? 0) || 0;
        p95Ms = Number(snap?.http?.latencyMs?.p95 ?? 0) || 0;
        elLagMs = Number(snap?.eventLoop?.p95Ms ?? 0) || 0;

        const totalReq = Number(snap?.http?.requestsTotal || 0);
        const err4xx = Number(snap?.http?.status?.['4xx'] || 0);
        const err5xx = Number(snap?.http?.status?.['5xx'] || 0);

        if (this._prevHttp.ts > 0 && totalReq >= this._prevHttp.requests) {
          reqDelta = totalReq - this._prevHttp.requests;
          const d4 = Math.max(0, err4xx - this._prevHttp.err4xx);
          const d5 = Math.max(0, err5xx - this._prevHttp.err5xx);
          if (reqDelta > 0) {
            errorRatePct = Number((((d4 + d5) / reqDelta) * 100).toFixed(2));
            err5xxRatePct = Number(((d5 / reqDelta) * 100).toFixed(2));
          }
        } else if (totalReq > 0) {
          reqDelta = totalReq;
          errorRatePct = Number((((err4xx + err5xx) / totalReq) * 100).toFixed(2));
          err5xxRatePct = Number(((err5xx / totalReq) * 100).toFixed(2));
        }
        this._prevHttp = { requests: totalReq, err4xx, err5xx, ts: now };
      }

      pt = normalizePoint({
        ts: now,
        hostCpuPct,
        hostRamPct: mem.usedPct,
        hostRamUsedMb: mem.usedMb,
        hostRamTotalMb: mem.totalMb,
        diskUsedPct: disk.usedPct,
        diskFreeGb: disk.freeGb,
        rssMb,
        heapMb,
        elLagMs,
        rps,
        p50Ms,
        p95Ms,
        errorRatePct,
        err5xxRatePct,
        reqDelta
      });
    }

    if (!pt) return null;

    this.tier1m.push(pt);
    if (this.tier1m.length > TIER_1M_CAP) {
      this.tier1m.splice(0, this.tier1m.length - TIER_1M_CAP);
    }
    this._ingestInto15mRollup(pt);

    this._dirty = true;
    this._samplesSinceFlush++;
    if (this._samplesSinceFlush >= this._flushEverySamples) {
      try { this.flush(); } catch (e) {}
    }

    this.emit('sample', pt);
    return pt;
  }

  /**
   * Records a deployment or rollback marker for time-series chart overlays.
   * @param {{ projectId?: string | null, projectName?: string, status?: string, label?: string, ts?: number }} marker
   */
  recordDeployMarker(marker = {}) {
    this._ensureLoaded();
    const ts = Number.isFinite(Number(marker.ts)) ? Math.round(Number(marker.ts)) : Date.now();
    const entry = {
      ts,
      projectId: marker.projectId ? String(marker.projectId).slice(0, 80) : null,
      projectName: String(marker.projectName || marker.projectId || 'proyecto').slice(0, 80),
      status: String(marker.status || 'deployed').slice(0, 32),
      label: String(marker.label || `Deploy ${marker.projectName || marker.projectId || ''}`).trim().slice(0, 120)
    };
    this.deployMarkers.push(entry);
    if (this.deployMarkers.length > MARKERS_CAP) {
      this.deployMarkers.splice(0, this.deployMarkers.length - MARKERS_CAP);
    }
    this._dirty = true;
    return entry;
  }

  /**
   * Queries persisted time-series points for a window (`15m`, `1h`, `6h`, `24h`, `7d`).
   * @param {{ range?: string, includeMarkers?: boolean, now?: number }} [opts]
   */
  query(opts = {}) {
    this._ensureLoaded();
    const now = Number.isFinite(Number(opts.now)) ? Number(opts.now) : Date.now();
    const rawRange = String(opts.range || '24h').trim().toLowerCase();
    /** @type {Record<string, { ms: number, tier: '1m' | '15m', resolutionSec: number }>} */
    const rangeMap = {
      '15m': { ms: 15 * 60 * 1000, tier: '1m', resolutionSec: 60 },
      '1h': { ms: 60 * 60 * 1000, tier: '1m', resolutionSec: 60 },
      '6h': { ms: 6 * 60 * 60 * 1000, tier: '1m', resolutionSec: 60 },
      '24h': { ms: 24 * 60 * 60 * 1000, tier: '1m', resolutionSec: 60 },
      '7d': { ms: SEVEN_DAYS_MS, tier: '15m', resolutionSec: 900 }
    };
    const cfg = rangeMap[rawRange] || rangeMap['24h'];
    const normalizedRange = rangeMap[rawRange] ? rawRange : '24h';
    const cutoff = now - cfg.ms;

    const source = cfg.tier === '15m' ? this.tier15m : this.tier1m;
    const points = source.filter((p) => p && p.ts >= cutoff);
    const markers = opts.includeMarkers === false
      ? []
      : this.deployMarkers.filter((m) => m && m.ts >= cutoff);

    let sumCpu = 0;
    let maxCpu = 0;
    let sumRam = 0;
    let maxRam = 0;
    let maxRss = 0;
    let sumP95 = 0;
    let maxP95 = 0;
    let sumErr = 0;
    for (const p of points) {
      sumCpu += p.hostCpuPct;
      if (p.hostCpuPct > maxCpu) maxCpu = p.hostCpuPct;
      sumRam += p.hostRamPct;
      if (p.hostRamPct > maxRam) maxRam = p.hostRamPct;
      if (p.rssMb > maxRss) maxRss = p.rssMb;
      sumP95 += p.p95Ms;
      if (p.p95Ms > maxP95) maxP95 = p.p95Ms;
      sumErr += p.errorRatePct;
    }
    const count = points.length;

    return {
      range: normalizedRange,
      tier: cfg.tier,
      resolutionSec: cfg.resolutionSec,
      from: new Date(cutoff).toISOString(),
      to: new Date(now).toISOString(),
      points,
      markers,
      summary: {
        sampleCount: count,
        avgHostCpuPct: count > 0 ? Number((sumCpu / count).toFixed(1)) : null,
        maxHostCpuPct: count > 0 ? Number(maxCpu.toFixed(1)) : null,
        avgHostRamPct: count > 0 ? Number((sumRam / count).toFixed(1)) : null,
        maxHostRamPct: count > 0 ? Number(maxRam.toFixed(1)) : null,
        maxRssMb: count > 0 ? maxRss : null,
        avgP95Ms: count > 0 ? Number((sumP95 / count).toFixed(2)) : null,
        maxP95Ms: count > 0 ? Number(maxP95.toFixed(2)) : null,
        avgErrorRatePct: count > 0 ? Number((sumErr / count).toFixed(2)) : null
      }
    };
  }

  /** Returns latest captured sample (or null if empty). */
  getLatest() {
    this._ensureLoaded();
    return this.tier1m.length > 0 ? this.tier1m[this.tier1m.length - 1] : null;
  }

  /** Estimates current serialized byte footprint of the in-memory rings. */
  estimateMemoryBytes() {
    this._ensureLoaded();
    return Buffer.byteLength(
      JSON.stringify({ tier1m: this.tier1m, tier15m: this.tier15m, deployMarkers: this.deployMarkers }),
      'utf8'
    );
  }

  /**
   * Starts the lazy background sampler (`.unref()` so it never blocks exit).
   * @param {{ intervalMs?: number, sampleImmediately?: boolean }} [opts]
   */
  start(opts = {}) {
    this._ensureLoaded();
    const intervalMs = Math.max(1000, Number(opts.intervalMs) || this._sampleIntervalMs);
    if (opts.sampleImmediately !== false && this.tier1m.length === 0) {
      try { this.sampleNow(); } catch (e) {}
    }
    if (this._timer) return { running: true, intervalMs };
    this._timer = setInterval(() => {
      try { this.sampleNow(); } catch (e) {}
    }, intervalMs);
    if (this._timer.unref) this._timer.unref();
    return { running: true, intervalMs };
  }

  /** Stops the background timer and flushes unsaved points cleanly. */
  stop() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
    if (this._dirty) {
      try { this.flush(); } catch (e) {}
    }
  }

  shutdown() {
    this.stop();
  }
}

const metricsHistoryInstance = Object.assign(new MetricsHistory(), {
  MetricsHistory,
  readHostMemoryStats,
  readDiskStats,
  readHostCpuTotals,
  computeHostCpuDelta,
  TIER_1M_CAP,
  TIER_15M_CAP
});

module.exports = metricsHistoryInstance;
