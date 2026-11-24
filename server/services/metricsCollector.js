const { monitorEventLoopDelay, performance } = require('perf_hooks');
const os = require('os');

/**
 * Recolector de telemetría real en tiempo de ejecución (cero dependencias externas).
 *
 * - Anillo de latencia HTTP pre-alojado (`Float64Array(1024)`) sin asignaciones en el camino caliente.
 * - Histograma acumulativo estándar Prometheus (`Uint32Array(13)`).
 * - Ventana deslizante de RPS a 1s / 10s / 60s (`Uint32Array(60)` sin temporizadores extra).
 * - Event-loop lag real vía `perf_hooks.monitorEventLoopDelay` (con corrección de resolución).
 * - Historial de 60 puntos (~5 min) para gráficas reales en el panel de observabilidad.
 */

const RING_SIZE = 1024;
const RING_MASK = RING_SIZE - 1;
const ELD_RESOLUTION_MS = 20;
const PROM_BUCKETS_SEC = [0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5];
const MAX_ROUTES = 32;
const HISTORY_CAP = 60;
const HOST_CPUS = typeof os.availableParallelism === 'function' ? os.availableParallelism() : os.cpus().length;
const HOST_TOTAL_MEM_MB = Math.round(os.totalmem() / 1024 / 1024);

/** Normaliza rutas dinámicas para evitar explosión de cardinalidad. */
function canonicalizeRoute(rawPath) {
  if (!rawPath || typeof rawPath !== 'string') return '/';
  const qIdx = rawPath.indexOf('?');
  const p = qIdx === -1 ? rawPath : rawPath.slice(0, qIdx);
  if (
    p === '/health' || p === '/api/health' || p === '/metrics' || p === '/api/metrics' ||
    p === '/api/pods' || p === '/api/projects' || p === '/api/catalog' || p === '/api/domains' ||
    p === '/api/system/status' || p === '/api/system/doctor' || p === '/api/observability/snapshot' ||
    p === '/api/ingress/ask' || p === '/api/ingress/status' || p === '/api/sync/summary' ||
    p === '/api/mcp'
  ) {
    return p;
  }
  if (!p.startsWith('/api/')) return '/static';
  const parts = p.split('/');
  // /api/<resource>/<id>/<sub...> -> /api/<resource>/:id/<sub...>
  if (
    parts.length >= 4 &&
    parts[3] &&
    parts[3] !== 'status' &&
    parts[3] !== 'summary' &&
    parts[3] !== 'config' &&
    parts[3] !== 'doctor' &&
    parts[3] !== 'installations' &&
    parts[3] !== 'session' &&
    parts[3] !== 'verify' &&
    parts[3] !== 'rotate' &&
    parts[3] !== 'ws-ticket' &&
    parts[3] !== 'audit' &&
    parts[3] !== 'health-summary'
  ) {
    parts[3] = ':id';
  }
  if (parts.length >= 6 && parts[5]) {
    parts[5] = ':subId';
  }
  return parts.slice(0, 6).join('/');
}

class MetricsCollector {
  constructor() {
    this.startedAt = Date.now();
    /** @type {number | null} */
    this.bootMs = null;

    // HTTP latency ring buffer (ms) — 0 allocations on hot path
    this.latRing = new Float64Array(RING_SIZE);
    this.latScratch = new Float64Array(RING_SIZE);
    this.latCursor = 0;
    this.latCount = 0;

    // Prometheus histogram buckets (seconds): 12 finite + 1 +Inf
    this.histBuckets = new Uint32Array(PROM_BUCKETS_SEC.length + 1);
    this.durationSumSec = 0;

    // Counters
    this.requestsTotal = 0;
    this.inFlight = 0;
    this.status2xx = 0;
    this.status3xx = 0;
    this.status4xx = 0;
    this.status5xx = 0;
    this.methods = { GET: 0, POST: 0, PUT: 0, PATCH: 0, DELETE: 0, OTHER: 0 };

    // Security telemetry counters (zero-dep, exposed in JSON + Prometheus)
    this.security = {
      authFailures: 0,
      authBlocked429: 0,
      originRejected403: 0,
      rateLimited429: 0,
      wsAuthRejected: 0
    };

    // 60-second rolling RPS ring
    this.rpsCounts = new Uint32Array(60);
    this.rpsEpochSec = new Uint32Array(60);

    // Bounded per-route breakdown
    /** @type {Map<string, { count: number, errors: number, totalMs: number, maxMs: number }>} */
    this.routes = new Map();

    // Event loop delay & utilization
    this.eld = monitorEventLoopDelay({ resolution: ELD_RESOLUTION_MS });
    this.eld.enable();
    this.eldLastResetAt = Date.now();
    this.prevElu = typeof performance.eventLoopUtilization === 'function'
      ? performance.eventLoopUtilization()
      : null;
    this.lastEluRatio = 0;

    // Process CPU/mem cache (250 ms)
    this.lastCpuSample = null;
    /** @type {{ at: number, data: any } | null} */
    this._procCache = null;

    // Snapshot / Prometheus serialization caches (250 ms)
    /** @type {{ at: number, data: any } | null} */
    this._snapshotCache = null;
    /** @type {{ at: number, buf: Buffer } | null} */
    this._snapshotBufCache = null;
    /** @type {{ at: number, buf: Buffer } | null} */
    this._promBufCache = null;

    // History ring (max 60 samples, 1 per 5s)
    /** @type {Array<{ ts: number, rps: number, p50Ms: number, p95Ms: number, rssMb: number, heapMb: number, elLagMs: number, cpuPercent: number }>} */
    this.history = [];
    this._lastHistoryAt = 0;

    // External lazy getters (injected by server/index.js — never force require)
    this._wsGetter = () => ({ telemetryClients: 0, syncClients: 0, sseClients: 0, connectionsTotal: 0, broadcastsTotal: 0 });
    this._liveSyncGetter = () => null;
    this._caddyGetter = () => null;

    // Caddy swap ring (populated by caddyManager without extra I/O)
    this.caddySwapRing = new Float64Array(64);
    this.caddySwapScratch = new Float64Array(64);
    this.caddySwapCursor = 0;
    this.caddySwapCount = 0;
    this.caddySwapsTotal = 0;
    this.caddyNoopSkips = 0;
  }

  /** @param {() => any} fn */
  setWsStatsGetter(fn) {
    if (typeof fn === 'function') this._wsGetter = fn;
  }

  /** @param {() => any} fn */
  setLiveSyncGetter(fn) {
    if (typeof fn === 'function') this._liveSyncGetter = fn;
  }

  /** @param {() => any} fn */
  setCaddyGetter(fn) {
    if (typeof fn === 'function') this._caddyGetter = fn;
  }

  /** @param {number} ms */
  setBootMs(ms) {
    if (Number.isFinite(ms) && ms >= 0) this.bootMs = Math.round(ms);
  }

  /** Registra una conmutación real de ruta en Caddy sin overhead. */
  recordCaddySwap(durationMs, noop = false) {
    if (noop) {
      this.caddyNoopSkips++;
      return;
    }
    this.caddySwapsTotal++;
    this.caddySwapRing[this.caddySwapCursor & 63] = durationMs;
    this.caddySwapCursor++;
    if (this.caddySwapCount < 64) this.caddySwapCount++;
  }

  onRequestStart() {
    this.inFlight++;
  }

  /** @param {string} method @param {string} route @param {number} statusCode @param {number} durationMs */
  _recordCore(method, route, statusCode, durationMs) {
    this.requestsTotal++;

    if (statusCode >= 500) this.status5xx++;
    else if (statusCode >= 400) this.status4xx++;
    else if (statusCode >= 300) this.status3xx++;
    else this.status2xx++;

    if (method === 'GET') this.methods.GET++;
    else if (method === 'POST') this.methods.POST++;
    else if (method === 'PUT') this.methods.PUT++;
    else if (method === 'PATCH') this.methods.PATCH++;
    else if (method === 'DELETE') this.methods.DELETE++;
    else this.methods.OTHER++;

    const safeMs = durationMs >= 0 && Number.isFinite(durationMs) ? durationMs : 0;
    this.latRing[this.latCursor & RING_MASK] = safeMs;
    this.latCursor++;
    if (this.latCount < RING_SIZE) this.latCount++;

    const sec = safeMs / 1000;
    this.durationSumSec += sec;
    let placed = false;
    for (let i = 0; i < PROM_BUCKETS_SEC.length; i++) {
      if (sec <= PROM_BUCKETS_SEC[i]) {
        this.histBuckets[i]++;
        placed = true;
        break;
      }
    }
    if (!placed) this.histBuckets[PROM_BUCKETS_SEC.length]++;

    const nowSec = Math.floor(Date.now() / 1000);
    const slot = nowSec % 60;
    if (this.rpsEpochSec[slot] !== nowSec) {
      this.rpsEpochSec[slot] = nowSec;
      this.rpsCounts[slot] = 1;
    } else {
      this.rpsCounts[slot]++;
    }

    let entry = this.routes.get(route);
    if (!entry) {
      const key = this.routes.size < MAX_ROUTES ? route : '/api/other';
      entry = this.routes.get(key);
      if (!entry) {
        entry = { count: 0, errors: 0, totalMs: 0, maxMs: 0 };
        this.routes.set(key, entry);
      }
    }
    entry.count++;
    if (statusCode >= 400) entry.errors++;
    entry.totalMs += safeMs;
    if (safeMs > entry.maxMs) entry.maxMs = safeMs;
  }

  /** Camino ultra-rápido sin listeners (invocado tras enviar respuesta síncrona). */
  recordFastPath(method, canonicalRoute, statusCode, durationMs) {
    this._recordCore(method || 'GET', canonicalRoute, statusCode || 200, durationMs);
  }

  /** Cierre de petición Express (con `onRequestStart()` previo). */
  onRequestEnd(method, rawPath, statusCode, durationMs) {
    if (this.inFlight > 0) this.inFlight--;
    this._recordCore(method || 'GET', canonicalizeRoute(rawPath), statusCode || 200, durationMs);
  }

  _computePercentiles(ring, count, scratch) {
    if (count === 0) {
      return { samples: 0, min: null, mean: null, p50: null, p95: null, p99: null, max: null };
    }
    let sum = 0;
    for (let i = 0; i < count; i++) {
      const v = ring[i];
      scratch[i] = v;
      sum += v;
    }
    const view = scratch.subarray(0, count);
    view.sort();
    const pick = (p) => Number(view[Math.min(count - 1, Math.max(0, Math.ceil((p / 100) * count) - 1))].toFixed(2));
    return {
      samples: count,
      min: Number(view[0].toFixed(2)),
      mean: Number((sum / count).toFixed(2)),
      p50: pick(50),
      p95: pick(95),
      p99: pick(99),
      max: Number(view[count - 1].toFixed(2))
    };
  }

  _computeRps() {
    const nowSec = Math.floor(Date.now() / 1000);
    let c1 = 0;
    let c10 = 0;
    let c60 = 0;
    for (let i = 0; i < 60; i++) {
      const age = nowSec - this.rpsEpochSec[i];
      if (age >= 0 && age < 60) {
        const v = this.rpsCounts[i];
        c60 += v;
        if (age < 10) c10 += v;
        if (age <= 1) c1 += v;
      }
    }
    return {
      rps1s: Number((c1 / 2).toFixed(1)),
      rps10s: Number((c10 / 10).toFixed(1)),
      rps60s: Number((c60 / 60).toFixed(2))
    };
  }

  sampleProcess(force = false) {
    const now = Date.now();
    if (!force && this._procCache && (now - this._procCache.at) < 250) {
      return this._procCache.data;
    }
    const cpu = process.cpuUsage();
    const mem = process.memoryUsage();
    /** @type {number | null} */
    let cpuPercent = null;
    if (this.lastCpuSample) {
      const elapsedMs = now - this.lastCpuSample.at;
      const usedMicros = (cpu.user - this.lastCpuSample.user) + (cpu.system - this.lastCpuSample.system);
      if (elapsedMs > 0) {
        cpuPercent = Number(((usedMicros / 1000 / elapsedMs) * 100).toFixed(1));
      }
    }
    this.lastCpuSample = { at: now, user: cpu.user, system: cpu.system };

    if (this.prevElu && typeof performance.eventLoopUtilization === 'function') {
      const cur = performance.eventLoopUtilization();
      const delta = performance.eventLoopUtilization(cur, this.prevElu);
      this.prevElu = cur;
      this.lastEluRatio = Number((delta.utilization || 0).toFixed(4));
    }

    const totalMemMb = HOST_TOTAL_MEM_MB;
    const freeMemMb = Math.round(os.freemem() / 1024 / 1024);

    const data = {
      pid: process.pid,
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      uptimeSeconds: Math.round(process.uptime()),
      cpuPercent,
      cpuUserSec: Number((cpu.user / 1e6).toFixed(3)),
      cpuSystemSec: Number((cpu.system / 1e6).toFixed(3)),
      rssBytes: mem.rss,
      heapUsedBytes: mem.heapUsed,
      heapTotalBytes: mem.heapTotal,
      externalBytes: mem.external,
      arrayBuffersBytes: mem.arrayBuffers || 0,
      memoryMb: Math.round(mem.rss / 1024 / 1024),
      heapUsedMb: Math.round(mem.heapUsed / 1024 / 1024),
      heapTotalMb: Math.round(mem.heapTotal / 1024 / 1024),
      hostMemoryTotalMb: totalMemMb,
      hostMemoryUsedMb: totalMemMb - freeMemMb,
      hostMemoryFreeMb: freeMemMb,
      hostCpus: HOST_CPUS,
      loadAvg: os.loadavg().map((n) => Number(n.toFixed(2))),
      measured: true
    };
    this._procCache = { at: now, data };
    return data;
  }

  sampleEventLoop() {
    const now = Date.now();
    const hasSamples = this.eld.count > 0;
    const adjust = (ns) => Number(Math.max(0, ns / 1e6 - ELD_RESOLUTION_MS).toFixed(2));
    const snap = {
      resolutionMs: ELD_RESOLUTION_MS,
      samples: this.eld.count,
      p50Ms: hasSamples ? adjust(this.eld.percentile(50)) : null,
      p95Ms: hasSamples ? adjust(this.eld.percentile(95)) : null,
      p99Ms: hasSamples ? adjust(this.eld.percentile(99)) : null,
      maxMs: hasSamples ? adjust(this.eld.max) : null,
      utilizationRatio: this.lastEluRatio
    };
    // Rotar histograma cada 60s para que p99/max reflejen salud viva y no el pico de arranque
    if (now - this.eldLastResetAt >= 60000) {
      this.eld.reset();
      this.eldLastResetAt = now;
    }
    return snap;
  }

  getSnapshot(fresh = false) {
    const now = Date.now();
    if (!fresh && this._snapshotCache && (now - this._snapshotCache.at) < 250) {
      return this._snapshotCache.data;
    }

    const proc = this.sampleProcess(fresh);
    const el = this.sampleEventLoop();
    const lat = this._computePercentiles(this.latRing, this.latCount, this.latScratch);
    const rps = this._computeRps();
    const ws = this._wsGetter();
    const liveSync = this._liveSyncGetter() || {
      loaded: false,
      activeSessions: 0,
      connectedClients: 0,
      framesApplied: 0,
      filesWritten: 0,
      dedupSkipped: 0,
      bytesSynced: 0,
      rollbacksCount: 0,
      applyLatencyMs: { samples: 0, p50: null, p95: null, p99: null }
    };

    const caddyBase = this._caddyGetter() || { available: null, version: null, managedRoutes: null };
    const caddyLatency = this._computePercentiles(this.caddySwapRing, this.caddySwapCount, this.caddySwapScratch);

    const topRoutes = Array.from(this.routes.entries())
      .map(([route, s]) => ({
        route,
        count: s.count,
        errors: s.errors,
        avgMs: s.count > 0 ? Number((s.totalMs / s.count).toFixed(2)) : 0,
        maxMs: Number(s.maxMs.toFixed(2))
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 12);

    // Muestreo histórico (máx 1 punto cada 5 s)
    if (now - this._lastHistoryAt >= 5000 || this.history.length === 0) {
      this._lastHistoryAt = now;
      this.history.push({
        ts: now,
        rps: rps.rps10s,
        p50Ms: lat.p50 ?? 0,
        p95Ms: lat.p95 ?? 0,
        rssMb: proc.memoryMb,
        heapMb: proc.heapUsedMb,
        elLagMs: el.p95Ms ?? 0,
        cpuPercent: proc.cpuPercent ?? 0
      });
      if (this.history.length > HISTORY_CAP) {
        this.history.shift();
      }
    }

    const snapshot = {
      timestamp: new Date(now).toISOString(),
      uptimeSeconds: proc.uptimeSeconds,
      bootMs: this.bootMs,
      http: {
        requestsTotal: this.requestsTotal,
        inFlight: this.inFlight,
        rps,
        status: {
          '2xx': this.status2xx,
          '3xx': this.status3xx,
          '4xx': this.status4xx,
          '5xx': this.status5xx
        },
        methods: { ...this.methods },
        latencyMs: lat,
        topRoutes
      },
      eventLoop: el,
      process: proc,
      websocket: ws,
      liveSync,
      caddy: {
        ...caddyBase,
        swapsTotal: this.caddySwapsTotal,
        noopSkips: this.caddyNoopSkips,
        swapLatencyMs: caddyLatency
      },
      security: { ...this.security },
      history: this.history
    };

    this._snapshotCache = { at: now, data: snapshot };
    return snapshot;
  }

  getSnapshotBuffer(fresh = false) {
    const now = Date.now();
    if (!fresh && this._snapshotBufCache && (now - this._snapshotBufCache.at) < 250) {
      return this._snapshotBufCache.buf;
    }
    const buf = Buffer.from(JSON.stringify(this.getSnapshot(fresh)), 'utf8');
    this._snapshotBufCache = { at: now, buf };
    return buf;
  }

  getPrometheusText(fresh = false) {
    const snap = this.getSnapshot(fresh);
    const lines = [
      '# HELP culkibo_uptime_seconds Control-plane daemon uptime in seconds.',
      '# TYPE culkibo_uptime_seconds gauge',
      `culkibo_uptime_seconds ${snap.uptimeSeconds}`,
      '',
      '# HELP culkibo_http_requests_total Total HTTP requests served by status class.',
      '# TYPE culkibo_http_requests_total counter',
      `culkibo_http_requests_total{status_class="2xx"} ${snap.http.status['2xx']}`,
      `culkibo_http_requests_total{status_class="3xx"} ${snap.http.status['3xx']}`,
      `culkibo_http_requests_total{status_class="4xx"} ${snap.http.status['4xx']}`,
      `culkibo_http_requests_total{status_class="5xx"} ${snap.http.status['5xx']}`,
      '',
      '# HELP culkibo_http_requests_in_flight Currently active in-flight HTTP requests.',
      '# TYPE culkibo_http_requests_in_flight gauge',
      `culkibo_http_requests_in_flight ${snap.http.inFlight}`,
      '',
      '# HELP culkibo_http_request_duration_seconds HTTP request latency distribution in seconds.',
      '# TYPE culkibo_http_request_duration_seconds histogram'
    ];

    let cumulative = 0;
    for (let i = 0; i < PROM_BUCKETS_SEC.length; i++) {
      cumulative += this.histBuckets[i];
      lines.push(`culkibo_http_request_duration_seconds_bucket{le="${PROM_BUCKETS_SEC[i]}"} ${cumulative}`);
    }
    cumulative += this.histBuckets[PROM_BUCKETS_SEC.length];
    lines.push(`culkibo_http_request_duration_seconds_bucket{le="+Inf"} ${cumulative}`);
    lines.push(`culkibo_http_request_duration_seconds_sum ${this.durationSumSec.toFixed(6)}`);
    lines.push(`culkibo_http_request_duration_seconds_count ${this.requestsTotal}`);
    lines.push('');

    lines.push('# HELP culkibo_eventloop_lag_seconds Node.js event loop delay quantiles in seconds.');
    lines.push('# TYPE culkibo_eventloop_lag_seconds gauge');
    lines.push(`culkibo_eventloop_lag_seconds{quantile="0.5"} ${((snap.eventLoop.p50Ms ?? 0) / 1000).toFixed(6)}`);
    lines.push(`culkibo_eventloop_lag_seconds{quantile="0.95"} ${((snap.eventLoop.p95Ms ?? 0) / 1000).toFixed(6)}`);
    lines.push(`culkibo_eventloop_lag_seconds{quantile="0.99"} ${((snap.eventLoop.p99Ms ?? 0) / 1000).toFixed(6)}`);
    lines.push('# HELP culkibo_eventloop_utilization_ratio Node.js event loop utilization (0..1).');
    lines.push('# TYPE culkibo_eventloop_utilization_ratio gauge');
    lines.push(`culkibo_eventloop_utilization_ratio ${snap.eventLoop.utilizationRatio}`);
    lines.push('');

    lines.push('# HELP process_resident_memory_bytes Resident memory size in bytes.');
    lines.push('# TYPE process_resident_memory_bytes gauge');
    lines.push(`process_resident_memory_bytes ${snap.process.rssBytes}`);
    lines.push('# HELP nodejs_heap_size_used_bytes V8 heap used in bytes.');
    lines.push('# TYPE nodejs_heap_size_used_bytes gauge');
    lines.push(`nodejs_heap_size_used_bytes ${snap.process.heapUsedBytes}`);
    lines.push('# HELP nodejs_heap_size_total_bytes V8 heap total in bytes.');
    lines.push('# TYPE nodejs_heap_size_total_bytes gauge');
    lines.push(`nodejs_heap_size_total_bytes ${snap.process.heapTotalBytes}`);
    lines.push('# HELP nodejs_external_memory_bytes V8 external memory in bytes.');
    lines.push('# TYPE nodejs_external_memory_bytes gauge');
    lines.push(`nodejs_external_memory_bytes ${snap.process.externalBytes}`);
    lines.push('');

    lines.push('# HELP culkibo_ws_connections Active WebSocket and SSE connections by channel.');
    lines.push('# TYPE culkibo_ws_connections gauge');
    lines.push(`culkibo_ws_connections{channel="telemetry"} ${snap.websocket.telemetryClients || 0}`);
    lines.push(`culkibo_ws_connections{channel="sync"} ${snap.websocket.syncClients || 0}`);
    lines.push(`culkibo_ws_connections{channel="sse"} ${snap.websocket.sseClients || 0}`);
    lines.push('');

    lines.push('# HELP culkibo_livesync_frames_total Total Live Sync atomic Commit Frames applied.');
    lines.push('# TYPE culkibo_livesync_frames_total counter');
    lines.push(`culkibo_livesync_frames_total ${snap.liveSync.framesApplied || 0}`);
    lines.push('# HELP culkibo_livesync_apply_duration_ms Live Sync server apply latency in milliseconds.');
    lines.push('# TYPE culkibo_livesync_apply_duration_ms gauge');
    lines.push(`culkibo_livesync_apply_duration_ms{quantile="0.5"} ${snap.liveSync.applyLatencyMs?.p50 ?? 0}`);
    lines.push(`culkibo_livesync_apply_duration_ms{quantile="0.95"} ${snap.liveSync.applyLatencyMs?.p95 ?? 0}`);
    lines.push('');

    const caddyUp = snap.caddy.available === true ? 1 : 0;
    lines.push('# HELP culkibo_caddy_up Whether Caddy Admin API was reachable on last check (1=up, 0=down).');
    lines.push('# TYPE culkibo_caddy_up gauge');
    lines.push(`culkibo_caddy_up ${caddyUp}`);
    lines.push('# HELP culkibo_caddy_managed_routes Number of routes managed by Culkibo in Caddy.');
    lines.push('# TYPE culkibo_caddy_managed_routes gauge');
    lines.push(`culkibo_caddy_managed_routes ${snap.caddy.managedRoutes ?? 0}`);
    lines.push('# HELP culkibo_caddy_route_swaps_total Total live route updates sent to Caddy.');
    lines.push('# TYPE culkibo_caddy_route_swaps_total counter');
    lines.push(`culkibo_caddy_route_swaps_total ${snap.caddy.swapsTotal || 0}`);
    lines.push('');

    lines.push('# HELP culkibo_security_events_total Security & abuse control events by category.');
    lines.push('# TYPE culkibo_security_events_total counter');
    lines.push(`culkibo_security_events_total{kind="auth_failures"} ${snap.security?.authFailures || 0}`);
    lines.push(`culkibo_security_events_total{kind="auth_blocked_429"} ${snap.security?.authBlocked429 || 0}`);
    lines.push(`culkibo_security_events_total{kind="origin_rejected_403"} ${snap.security?.originRejected403 || 0}`);
    lines.push(`culkibo_security_events_total{kind="rate_limited_429"} ${snap.security?.rateLimited429 || 0}`);
    lines.push(`culkibo_security_events_total{kind="ws_auth_rejected"} ${snap.security?.wsAuthRejected || 0}`);
    lines.push('');

    return lines.join('\n');
  }

  /** @param {'authFailures'|'authBlocked429'|'originRejected403'|'rateLimited429'|'wsAuthRejected'} kind */
  recordSecurityEvent(kind) {
    if (Object.prototype.hasOwnProperty.call(this.security, kind)) {
      this.security[kind]++;
    }
  }

  getPrometheusBuffer(fresh = false) {
    const now = Date.now();
    if (!fresh && this._promBufCache && (now - this._promBufCache.at) < 250) {
      return this._promBufCache.buf;
    }
    const buf = Buffer.from(this.getPrometheusText(fresh), 'utf8');
    this._promBufCache = { at: now, buf };
    return buf;
  }

  stop() {
    try { this.eld.disable(); } catch (e) {}
  }
}

module.exports = new MetricsCollector();
