'use strict';

/**
 * Culkibo Multi-Region Health-Gated Blue/Green Traffic Shift & Sticky-Session Drain Controller.
 *
 * Cures `caddyserver/caddy#7544`/`#7524` (separate `health_port` causing false `503` all-down
 * due to missing Host header / 3xx redirects) and `#6393`/`#8415` (`lb_policy cookie` lacking
 * bounded `Max-Age` & active health checks hammering draining nodes) — zero external deps:
 *  - Atomic `0o600` shift history in `CULKIBO_DATA_DIR/data/region-traffic-shifts.json`.
 *  - Blocks traffic shifts to regions with `healthyEndpoints === 0`, error-rate breaches,
 *    or failing/redirecting `health_port` probes (`UNHEALTHY_TARGET_REGION`).
 *  - Plans progressive blue -> green weight steps preserving active sticky sessions via
 *    bounded `Max-Age` + `SameSite=Lax` + `HttpOnly` drain window (`dryRun: true` default).
 *  - Compiles ready-to-apply Caddy v2.11 `lb_policy cookie` + `health_uri` + `health_status 200`
 *    + `lb_try_duration 5s` + `fail_duration 30s` config blocks.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MAX_STORED_SHIFTS = 500;
const DEFAULT_MAX_ERROR_RATE_PCT = 2.0;

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
 * Emits a Caddy v2.11 `reverse_proxy` sticky-cookie failover block curing
 * `caddy#7544`/`#7524` (explicit `health_headers Host` + `health_status 200`) and
 * `caddy#6393`/`#8415` (bounded cookie `Max-Age` + active health probes + `lb_try_duration`).
 *
 * @param {{
 *   cookieName?: string,
 *   stickyMaxAgeSec?: number,
 *   sameSite?: string,
 *   httpOnly?: boolean,
 *   healthUri?: string,
 *   healthPort?: number | null,
 *   healthHostHeader?: string,
 *   lbTryDurationSec?: number,
 *   failDurationSec?: number,
 *   upstreams?: string[]
 * }} [config]
 */
function renderCaddyStickyFailoverBlock(config = {}) {
  const src = config && typeof config === 'object' ? config : {};
  const cookieName = typeof src.cookieName === 'string' && /^[a-zA-Z0-9_-]{2,64}$/.test(src.cookieName.trim())
    ? src.cookieName.trim()
    : 'culkibo_affinity';
  const stickyMaxAgeSec = Math.max(60, Math.min(86400, Math.round(Number(src.stickyMaxAgeSec ?? 900) || 900)));
  const sameSite = src.sameSite === 'Strict' ? 'Strict' : 'Lax';
  const httpOnly = src.httpOnly !== false;
  const healthUri = typeof src.healthUri === 'string' && src.healthUri.trim().startsWith('/')
    ? src.healthUri.trim().slice(0, 128)
    : '/healthz';
  const healthPort = src.healthPort !== undefined && src.healthPort !== null && Number.isInteger(Number(src.healthPort))
    ? Math.max(1, Math.min(65535, Number(src.healthPort)))
    : null;
  const healthHostHeader = typeof src.healthHostHeader === 'string' && src.healthHostHeader.trim()
    ? src.healthHostHeader.trim().slice(0, 128)
    : 'internal.culkibo.local';
  const lbTryDurationSec = Math.max(1, Math.min(60, Math.round(Number(src.lbTryDurationSec ?? 5) || 5)));
  const failDurationSec = Math.max(5, Math.min(300, Math.round(Number(src.failDurationSec ?? 30) || 30)));
  const upstreams = Array.isArray(src.upstreams) && src.upstreams.length > 0
    ? src.upstreams.map((u) => String(u || '').trim()).filter(Boolean)
    : ['blue-eu:8080', 'green-us:8080'];

  const lines = [
    `reverse_proxy ${upstreams.join(' ')} {`,
    `  lb_policy cookie ${cookieName}`,
    `  lb_try_duration ${lbTryDurationSec}s`,
    `  fail_duration ${failDurationSec}s`,
    `  health_uri ${healthUri}`,
    '  health_status 200',
    '  health_interval 5s',
    '  health_timeout 2s'
  ];
  if (healthPort !== null) {
    lines.push(`  health_port ${healthPort}`);
  }
  lines.push('  health_headers {');
  lines.push(`    Host ${healthHostHeader}`);
  lines.push('  }');
  lines.push(
    `  header_down Set-Cookie "${cookieName}={http.request.cookie.${cookieName}}; Max-Age=${stickyMaxAgeSec}; Path=/; SameSite=${sameSite}${httpOnly ? '; HttpOnly' : ''}; Secure"`
  );
  lines.push('}');

  const caddyfile = lines.join('\n');
  const caddyJson = {
    handler: 'reverse_proxy',
    upstreams: upstreams.map((dial) => ({ dial })),
    load_balancing: {
      selection_policy: {
        policy: 'cookie',
        name: cookieName,
        fallback: { policy: 'least_conn' }
      },
      try_duration: `${lbTryDurationSec}s`
    },
    health_checks: {
      active: {
        uri: healthUri,
        ...(healthPort !== null ? { port: healthPort } : {}),
        expect_status: 200,
        interval: '5s',
        timeout: '2s',
        headers: { Host: [healthHostHeader] }
      },
      passive: {
        fail_duration: `${failDurationSec}s`,
        max_fails: 2
      }
    },
    sticky_cookie_policy: {
      name: cookieName,
      maxAgeSec: stickyMaxAgeSec,
      sameSite,
      httpOnly,
      secure: true
    }
  };

  return {
    ok: true,
    cookieName,
    stickyMaxAgeSec,
    sameSite,
    httpOnly,
    healthUri,
    healthPort,
    healthHostHeader,
    lbTryDurationSec,
    failDurationSec,
    upstreams,
    caddyfile,
    caddyJson
  };
}

/**
 * Evaluates whether shifting green traffic weight across multi-region upstreams is safe,
 * validating active endpoints, error-rate SLO, `health_port` Host/200 probes, and sticky cookie bounds.
 *
 * @param {{
 *   projectId?: string,
 *   regions?: any[],
 *   targetGreenWeightPct?: number,
 *   maxErrorRatePct?: number,
 *   stickyCookiePolicy?: Record<string, any>,
 *   healthProbes?: any[]
 * }} [input]
 */
function evaluateTrafficShift(input = {}) {
  const src = input && typeof input === 'object' ? input : {};
  const projectId = String(src.projectId || 'default').trim().slice(0, 128) || 'default';
  const targetGreenWeightPct = Math.max(0, Math.min(100, Math.round(Number(src.targetGreenWeightPct ?? 50))));
  const targetBlueWeightPct = Math.max(0, 100 - targetGreenWeightPct);
  const maxErrorRatePct = Math.max(0.1, Number(src.maxErrorRatePct ?? DEFAULT_MAX_ERROR_RATE_PCT) || DEFAULT_MAX_ERROR_RATE_PCT);

  const regions = Array.isArray(src.regions) ? src.regions : [];
  const healthProbes = Array.isArray(src.healthProbes) ? src.healthProbes : [];
  const sticky = src.stickyCookiePolicy && typeof src.stickyCookiePolicy === 'object'
    ? src.stickyCookiePolicy
    : { name: 'culkibo_affinity', maxAgeSec: 900, sameSite: 'Lax', httpOnly: true };

  /** @type {Array<{ code: string, subCode?: string, region: string, severity: 'critical' | 'high', message: string }>} */
  const blockers = [];
  /** @type {string[]} */
  const warnings = [];

  const regionHealthSummary = regions.map((r) => {
    const regionId = String((r && (r.id || r.region || r.name)) || 'unknown');
    const role = String((r && r.role) || 'green').toLowerCase();
    const healthyEndpoints = Math.max(0, Math.round(Number(r && r.healthyEndpoints) || 0));
    const totalEndpoints = Math.max(healthyEndpoints, Math.round(Number(r && r.totalEndpoints) || healthyEndpoints));
    const errorRatePct = Math.max(0, Number(r && r.errorRatePct) || 0);
    const probeStatus = r && r.probeStatus !== undefined ? Number(r.probeStatus) : 200;
    const probeHostHeader = r && r.probeHostHeader !== undefined ? r.probeHostHeader : true;
    const hasHealthPort = Boolean(r && r.healthPort);

    const receivesTraffic = (role === 'green' && targetGreenWeightPct > 0) || (role === 'blue' && targetBlueWeightPct > 0);
    let healthy = true;

    if (receivesTraffic && healthyEndpoints === 0) {
      healthy = false;
      blockers.push({
        code: 'UNHEALTHY_TARGET_REGION',
        subCode: 'ZERO_HEALTHY_ENDPOINTS',
        region: regionId,
        severity: 'critical',
        message: `Target region "${regionId}" (${role}) has 0 healthy endpoints; refusing traffic shift to prevent 503 outage.`
      });
    }

    if (receivesTraffic && errorRatePct > maxErrorRatePct) {
      healthy = false;
      blockers.push({
        code: 'UNHEALTHY_TARGET_REGION',
        subCode: 'ERROR_RATE_EXCEEDED',
        region: regionId,
        severity: 'critical',
        message: `Target region "${regionId}" error rate (${errorRatePct}%) exceeds threshold (${maxErrorRatePct}%).`
      });
    }

    // Caddy #7544 / #7524 guard: health_port redirecting (3xx) or missing Host header causes false 503 all-down
    if (receivesTraffic && (probeStatus !== 200 || (hasHealthPort && !probeHostHeader))) {
      healthy = false;
      blockers.push({
        code: 'UNHEALTHY_TARGET_REGION',
        subCode: 'HEALTH_PORT_PROBE_FAILURE',
        region: regionId,
        severity: 'critical',
        message: `Region "${regionId}" health probe failed (status=${probeStatus}, hostHeader=${Boolean(probeHostHeader)}); non-200/3xx health_port responses trigger Caddy #7544 false 503.`
      });
    }

    return {
      region: regionId,
      role,
      healthy,
      healthyEndpoints,
      totalEndpoints,
      errorRatePct,
      probeStatus
    };
  });

  // Also check explicit standalone `healthProbes[]` array if provided
  for (const probe of healthProbes) {
    if (!probe || typeof probe !== 'object') continue;
    const regionId = String(probe.region || probe.id || 'unknown');
    const status = Number(probe.status ?? 200);
    const hasHealthPort = Boolean(probe.healthPort);
    const hostOk = probe.hostHeader !== false && probe.hostHeader !== '';
    if (status !== 200 || (hasHealthPort && !hostOk)) {
      blockers.push({
        code: 'UNHEALTHY_TARGET_REGION',
        subCode: 'HEALTH_PORT_PROBE_FAILURE',
        region: regionId,
        severity: 'critical',
        message: `Health probe for "${regionId}" returned HTTP ${status} (healthPort=${probe.healthPort || 'default'}, hostHeader=${hostOk}) — blocked to prevent Caddy #7544 false 503.`
      });
    }
  }

  // Sticky cookie drain hygiene check (caddy#6393 / #8415)
  const maxAgeSec = Number(sticky.maxAgeSec ?? 900);
  let stickyCookieSafe = true;
  if (!Number.isFinite(maxAgeSec) || maxAgeSec <= 0 || maxAgeSec > 86400) {
    stickyCookieSafe = false;
    warnings.push('Sticky session cookie lacks a bounded Max-Age (60..86400s); draining blue nodes may retain pinned users indefinitely.');
  }
  if (sticky.httpOnly === false) {
    stickyCookieSafe = false;
    warnings.push('Sticky session cookie should set HttpOnly and SameSite=Lax.');
  }

  const allowed = blockers.length === 0;
  return {
    ok: true,
    projectId,
    allowed,
    blocked: !allowed,
    code: allowed ? 'SHIFT_ALLOWED' : blockers[0].code,
    targetBlueWeightPct,
    targetGreenWeightPct,
    blockers,
    warnings,
    stickyCookieSafe,
    regionHealthSummary,
    evaluatedAt: new Date().toISOString()
  };
}

class RegionTrafficShiftService {
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
    return path.join(this.resolveDataDir(), 'region-traffic-shifts.json');
  }

  /** @returns {any[]} */
  _loadHistory() {
    const filePath = this.getStoreFilePath();
    if (!fs.existsSync(filePath)) return [];
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      return parsed && Array.isArray(parsed.shifts) ? parsed.shifts : [];
    } catch (e) {
      return [];
    }
  }

  /** @param {any[]} shifts */
  _saveHistory(shifts) {
    const trimmed = shifts.slice(-MAX_STORED_SHIFTS);
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({ schemaVersion: 1, updatedAt: new Date().toISOString(), shifts: trimmed }, null, 2) + '\n'
    );
  }

  /**
   * Delegates to `evaluateTrafficShift`.
   * @param {Record<string, any>} [input]
   */
  evaluateTrafficShift(input) {
    return evaluateTrafficShift(input);
  }

  /**
   * Delegates to `renderCaddyStickyFailoverBlock`.
   * @param {Record<string, any>} [config]
   */
  renderCaddyStickyFailoverBlock(config) {
    return renderCaddyStickyFailoverBlock(config);
  }

  /**
   * Generates a progressive blue -> green multi-region traffic shift plan with bounded
   * sticky-cookie session draining (`Max-Age` + `SameSite=Lax` + `HttpOnly`) and Caddy config.
   * Defaults to `dryRun: true`.
   *
   * @param {{
   *   projectId?: string,
   *   currentBlueWeightPct?: number,
   *   stepPct?: number,
   *   stickyMaxAgeSec?: number,
   *   failDurationSec?: number,
   *   lbTryDurationSec?: number,
   *   cookieName?: string,
   *   healthUri?: string,
   *   upstreams?: string[],
   *   regions?: any[],
   *   healthProbes?: any[],
   *   dryRun?: boolean
   * }} [input]
   */
  planBlueGreenShift(input = {}) {
    const src = input && typeof input === 'object' ? input : {};
    const projectId = String(src.projectId || 'default').trim().slice(0, 128) || 'default';
    const currentBlueWeightPct = Math.max(0, Math.min(100, Math.round(Number(src.currentBlueWeightPct ?? 100))));
    const stepPct = Math.max(5, Math.min(100, Math.round(Number(src.stepPct ?? 25) || 25)));
    const stickyMaxAgeSec = Math.max(60, Math.min(86400, Math.round(Number(src.stickyMaxAgeSec ?? 900) || 900)));
    const failDurationSec = Math.max(5, Math.min(300, Math.round(Number(src.failDurationSec ?? 30) || 30)));
    const lbTryDurationSec = Math.max(1, Math.min(60, Math.round(Number(src.lbTryDurationSec ?? 5) || 5)));
    const dryRun = src.dryRun !== undefined ? Boolean(src.dryRun) : true;

    const healthCheck = (Array.isArray(src.regions) && src.regions.length > 0) || (Array.isArray(src.healthProbes) && src.healthProbes.length > 0)
      ? evaluateTrafficShift({
          projectId,
          regions: src.regions || [],
          healthProbes: src.healthProbes || [],
          targetGreenWeightPct: Math.min(100, (100 - currentBlueWeightPct) + stepPct),
          stickyCookiePolicy: { maxAgeSec: stickyMaxAgeSec, sameSite: 'Lax', httpOnly: true }
        })
      : { allowed: true, blocked: false, code: 'SHIFT_ALLOWED', blockers: [] };

    /** @type {Array<{ step: number, blueWeightPct: number, greenWeightPct: number, action: string, soakSec: number }>} */
    const steps = [];
    let blue = currentBlueWeightPct;
    let stepNum = 1;
    while (blue > 0) {
      blue = Math.max(0, blue - stepPct);
      const green = 100 - blue;
      steps.push({
        step: stepNum,
        blueWeightPct: blue,
        greenWeightPct: green,
        action: blue === 0 ? 'COMPLETE_GREEN_CUTOVER_AND_DRAIN_STICKY' : `SHIFT_GREEN_${green}_PCT`,
        soakSec: blue === 0 ? stickyMaxAgeSec : Math.max(60, failDurationSec * 2)
      });
      stepNum += 1;
    }
    if (steps.length === 0) {
      steps.push({
        step: 1,
        blueWeightPct: 0,
        greenWeightPct: 100,
        action: 'VERIFY_GREEN_STEADY_STATE',
        soakSec: stickyMaxAgeSec
      });
    }

    const stickyCookiePolicy = {
      name: typeof src.cookieName === 'string' && src.cookieName.trim() ? src.cookieName.trim() : 'culkibo_affinity',
      maxAgeSec: stickyMaxAgeSec,
      sameSite: 'Lax',
      httpOnly: true,
      secure: true
    };

    const caddyBlock = renderCaddyStickyFailoverBlock({
      cookieName: stickyCookiePolicy.name,
      stickyMaxAgeSec,
      failDurationSec,
      lbTryDurationSec,
      healthUri: src.healthUri || '/healthz',
      upstreams: src.upstreams
    });

    const record = {
      ok: true,
      id: `shift_${crypto.randomBytes(6).toString('hex')}`,
      projectId,
      dryRun,
      allowed: healthCheck.allowed,
      blocked: !healthCheck.allowed,
      code: healthCheck.allowed ? 'PLAN_READY' : healthCheck.code,
      blockers: healthCheck.blockers || [],
      currentBlueWeightPct,
      stepPct,
      stickyCookiePolicy,
      failDurationSec,
      lbTryDurationSec,
      steps,
      caddyBlock,
      createdAt: new Date().toISOString()
    };

    if (!dryRun && healthCheck.allowed) {
      const history = this._loadHistory();
      history.push(record);
      this._saveHistory(history);
    }

    return record;
  }

  /**
   * Lists persisted traffic shift plans (optionally filtered by `projectId`), newest first.
   * @param {string | null} [projectId]
   */
  listTrafficShifts(projectId) {
    const filterId = typeof projectId === 'string' && projectId.trim() ? projectId.trim() : null;
    return this._loadHistory()
      .filter((s) => (!filterId || s.projectId === filterId))
      .slice()
      .reverse();
  }
}

const defaultRegionTrafficShiftService = new RegionTrafficShiftService();

const exported = Object.assign(defaultRegionTrafficShiftService, {
  RegionTrafficShiftService,
  evaluateTrafficShift: RegionTrafficShiftService.prototype.evaluateTrafficShift.bind(defaultRegionTrafficShiftService),
  planBlueGreenShift: RegionTrafficShiftService.prototype.planBlueGreenShift.bind(defaultRegionTrafficShiftService),
  renderCaddyStickyFailoverBlock: RegionTrafficShiftService.prototype.renderCaddyStickyFailoverBlock.bind(defaultRegionTrafficShiftService),
  listTrafficShifts: RegionTrafficShiftService.prototype.listTrafficShifts.bind(defaultRegionTrafficShiftService)
});

module.exports = exported;
