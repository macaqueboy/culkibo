'use strict';

/**
 * Culkibo Zero-Dep Multi-Region Caddy v2.11 Edge Geo-Routing & Sticky A/B Experiment Compiler.
 *
 * Compiles strictly validated Geo-IP regional routing and sticky cookie/header A/B experiments
 * directly into native Caddy v2.11 JSON (ZERO extra Caddy plugins):
 *  - Comprehensive ISO-3166-1 alpha-2 country code allowlist (`ISO_COUNTRY_CODES`).
 *  - Strict Geo header allowlist (`CF-IPCountry` | `X-Country`).
 *  - Exact 100% weight-sum validation across A/B variants (`variants[].weight`).
 *  - Sticky `cookie` (`ckb_ab_<slug>`), `header` (`X-AB-Group`), or `weighted` selection policies
 *    with `weighted_round_robin` fallback.
 *  - 1-click instant kill-switch (`triggerKillSwitch`) reverting 100% of traffic cleanly to control (`variants[0]`).
 *  - Atomic `0o600` persistence in isolated `CULKIBO_DATA_DIR/data/edge-experiments.json`.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ALLOWED_GEO_HEADERS = Object.freeze(['CF-IPCountry', 'X-Country']);
const ALLOWED_STICKY_MODES = Object.freeze(['cookie', 'header', 'weighted']);
const HOSTNAME_RE = /^(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;
const UPSTREAM_DIAL_RE = /^(?:\[[0-9a-fA-F:]+\]|[a-zA-Z0-9._-]+):(\d{1,5})$/;
const COOKIE_NAME_RE = /^[a-zA-Z0-9_-]{2,64}$/;
const HEADER_NAME_RE = /^[A-Za-z0-9-]{2,64}$/;
const SLUG_RE = /^[a-zA-Z0-9_-]{1,64}$/;

// Official ISO-3166-1 alpha-2 country codes (249 assigned codes)
const ISO_COUNTRY_CODES = new Set([
  'AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AO', 'AQ', 'AR', 'AS', 'AT', 'AU', 'AW', 'AX', 'AZ',
  'BA', 'BB', 'BD', 'BE', 'BF', 'BG', 'BH', 'BI', 'BJ', 'BL', 'BM', 'BN', 'BO', 'BQ', 'BR', 'BS',
  'BT', 'BV', 'BW', 'BY', 'BZ', 'CA', 'CC', 'CD', 'CF', 'CG', 'CH', 'CI', 'CK', 'CL', 'CM', 'CN',
  'CO', 'CR', 'CU', 'CV', 'CW', 'CX', 'CY', 'CZ', 'DE', 'DJ', 'DK', 'DM', 'DO', 'DZ', 'EC', 'EE',
  'EG', 'EH', 'ER', 'ES', 'ET', 'FI', 'FJ', 'FK', 'FM', 'FO', 'FR', 'GA', 'GB', 'GD', 'GE', 'GF',
  'GG', 'GH', 'GI', 'GL', 'GM', 'GN', 'GP', 'GQ', 'GR', 'GS', 'GT', 'GU', 'GW', 'GY', 'HK', 'HM',
  'HN', 'HR', 'HT', 'HU', 'ID', 'IE', 'IL', 'IM', 'IN', 'IO', 'IQ', 'IR', 'IS', 'IT', 'JE', 'JM',
  'JO', 'JP', 'KE', 'KG', 'KH', 'KI', 'KM', 'KN', 'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB', 'LC',
  'LI', 'LK', 'LR', 'LS', 'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'ME', 'MF', 'MG', 'MH', 'MK',
  'ML', 'MM', 'MN', 'MO', 'MP', 'MQ', 'MR', 'MS', 'MT', 'MU', 'MV', 'MW', 'MX', 'MY', 'MZ', 'NA',
  'NC', 'NE', 'NF', 'NG', 'NI', 'NL', 'NO', 'NP', 'NR', 'NU', 'NZ', 'OM', 'PA', 'PE', 'PF', 'PG',
  'PH', 'PK', 'PL', 'PM', 'PN', 'PR', 'PS', 'PT', 'PW', 'PY', 'QA', 'RE', 'RO', 'RS', 'RU', 'RW',
  'SA', 'SB', 'SC', 'SD', 'SE', 'SG', 'SH', 'SI', 'SJ', 'SK', 'SL', 'SM', 'SN', 'SO', 'SR', 'SS',
  'ST', 'SV', 'SX', 'SY', 'SZ', 'TC', 'TD', 'TF', 'TG', 'TH', 'TJ', 'TK', 'TL', 'TM', 'TN', 'TO',
  'TR', 'TT', 'TV', 'TW', 'TZ', 'UA', 'UG', 'UM', 'US', 'UY', 'UZ', 'VA', 'VC', 'VE', 'VG', 'VI',
  'VN', 'VU', 'WF', 'WS', 'YE', 'YT', 'ZA', 'ZM', 'ZW'
]);

/**
 * Atomically writes UTF-8 text to disk with `0o600` permissions.
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
 * @param {string} code
 * @param {string} msg
 */
function badRequest(code, msg) {
  const err = /** @type {any} */ (new Error(msg));
  err.code = code;
  err.status = 400;
  return err;
}

/**
 * Validates an upstream `host:port` dial string cleanly.
 * @param {string} raw
 * @param {string} label
 * @returns {string}
 */
function validateUpstream(raw, label) {
  const clean = String(raw || '').trim();
  const m = UPSTREAM_DIAL_RE.exec(clean);
  if (!m || /[\s\r\n\0]/.test(clean)) {
    throw badRequest('INVALID_UPSTREAM', `Invalid ${label} upstream dial: "${clean.slice(0, 64)}"`);
  }
  const port = Number(m[1]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw badRequest('INVALID_UPSTREAM', `Invalid port in ${label}: ${port}`);
  }
  return clean;
}

/**
 * Validates a Geo-Routing or A/B Experiment configuration strictly before Caddy compilation.
 *
 * @param {Record<string, any>} cfg
 */
function validateExperimentConfig(cfg) {
  if (!cfg || typeof cfg !== 'object') {
    throw badRequest('INVALID_CONFIG', 'Experiment config must be an object');
  }

  let hostname = '';
  if (cfg.hostname !== undefined && cfg.hostname !== null && String(cfg.hostname).trim() !== '') {
    hostname = String(cfg.hostname).trim().toLowerCase();
    if (hostname.length > 253 || !HOSTNAME_RE.test(hostname)) {
      throw badRequest('INVALID_HOSTNAME', `Invalid hostname: "${hostname.slice(0, 64)}"`);
    }
  }

  const kind = cfg.regions ? 'geo' : 'ab';

  if (kind === 'geo') {
    const headerName = String(cfg.headerName || 'CF-IPCountry').trim();
    if (!ALLOWED_GEO_HEADERS.includes(/** @type {any} */ (headerName))) {
      throw badRequest('INVALID_GEO_HEADER', `Unsupported geo header "${headerName}". Allowed: ${ALLOWED_GEO_HEADERS.join(', ')}`);
    }
    const defaultUpstream = validateUpstream(cfg.defaultUpstream, 'defaultUpstream');
    if (!Array.isArray(cfg.regions) || cfg.regions.length === 0) {
      throw badRequest('INVALID_REGIONS', 'Geo-routing requires at least one region entry');
    }
    /** @type {Array<{ countries: string[], upstream: string }>} */
    const normalizedRegions = [];
    for (let i = 0; i < Math.min(cfg.regions.length, 32); i++) {
      const reg = cfg.regions[i];
      if (!reg || !Array.isArray(reg.countries) || reg.countries.length === 0) {
        throw badRequest('INVALID_REGIONS', `Region #${i} requires a non-empty countries[] array`);
      }
      const countries = [];
      for (const rawCode of reg.countries) {
        const code = String(rawCode || '').trim().toUpperCase();
        if (!ISO_COUNTRY_CODES.has(code)) {
          throw badRequest('INVALID_COUNTRY_CODE', `Invalid ISO-3166-1 alpha-2 country code: "${String(rawCode || '').slice(0, 24)}"`);
        }
        if (!countries.includes(code)) countries.push(code);
      }
      const upstream = validateUpstream(reg.upstream, `regions[${i}].upstream`);
      normalizedRegions.push({ countries, upstream });
    }

    return {
      kind: /** @type {'geo'} */ ('geo'),
      hostname,
      headerName,
      regions: normalizedRegions,
      defaultUpstream
    };
  }

  // A/B Experiment validation
  const stickyMode = String(cfg.stickyMode || 'cookie').trim().toLowerCase();
  if (!ALLOWED_STICKY_MODES.includes(/** @type {any} */ (stickyMode))) {
    throw badRequest('INVALID_STICKY_MODE', `Unsupported stickyMode "${stickyMode}". Allowed: ${ALLOWED_STICKY_MODES.join(', ')}`);
  }

  const rawId = String(cfg.id || cfg.slug || 'exp').trim().replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 48) || 'exp';
  const cookieName = String(cfg.cookieName || `ckb_ab_${rawId}`).trim();
  if (stickyMode === 'cookie' && !COOKIE_NAME_RE.test(cookieName)) {
    throw badRequest('INVALID_COOKIE_NAME', `Invalid sticky cookieName: "${cookieName.slice(0, 64)}"`);
  }

  const headerField = String(cfg.headerField || 'X-AB-Group').trim();
  if (stickyMode === 'header' && !HEADER_NAME_RE.test(headerField)) {
    throw badRequest('INVALID_HEADER_FIELD', `Invalid sticky headerField: "${headerField.slice(0, 64)}"`);
  }

  if (!Array.isArray(cfg.variants) || cfg.variants.length < 2) {
    throw badRequest('INVALID_VARIANTS', 'A/B experiment requires at least 2 variants (control + treatment)');
  }

  /** @type {Array<{ name: string, upstream: string, weight: number }>} */
  const variants = [];
  let weightSum = 0;
  const seenNames = new Set();

  for (let i = 0; i < Math.min(cfg.variants.length, 10); i++) {
    const v = cfg.variants[i];
    if (!v || typeof v !== 'object') {
      throw badRequest('INVALID_VARIANTS', `Invalid variant at index ${i}`);
    }
    const name = String(v.name || `variant_${i}`).trim();
    if (!SLUG_RE.test(name) || seenNames.has(name)) {
      throw badRequest('INVALID_VARIANT_NAME', `Invalid or duplicate variant name: "${name.slice(0, 40)}"`);
    }
    seenNames.add(name);
    const upstream = validateUpstream(v.upstream, `variants[${i}].upstream`);
    const weight = Number(v.weight);
    if (!Number.isInteger(weight) || weight < 1 || weight > 100) {
      throw badRequest('INVALID_WEIGHT', `Variant "${name}" weight must be an integer 1..100 (got ${v.weight})`);
    }
    weightSum += weight;
    variants.push({ name, upstream, weight });
  }

  if (weightSum !== 100) {
    throw badRequest('INVALID_WEIGHT_SUM', `A/B variant weights must sum strictly to 100 (got ${weightSum})`);
  }

  return {
    kind: /** @type {'ab'} */ ('ab'),
    id: rawId,
    hostname,
    stickyMode: /** @type {'cookie' | 'header' | 'weighted'} */ (stickyMode),
    cookieName,
    headerField,
    variants,
    killed: Boolean(cfg.killed)
  };
}

/**
 * Compiles native Caddy v2.11 JSON subroutes for multi-region Geo-IP routing (0 Caddy plugins!).
 *
 * @param {{
 *   hostname?: string,
 *   headerName?: string,
 *   regions: Array<{ countries: string[], upstream: string }>,
 *   defaultUpstream: string
 * }} cfg
 */
function compileGeoRoutes(cfg) {
  const validated = validateExperimentConfig({ ...cfg, regions: cfg.regions, defaultUpstream: cfg.defaultUpstream });
  if (validated.kind !== 'geo') {
    throw badRequest('INVALID_CONFIG', 'compileGeoRoutes requires regions[] and defaultUpstream');
  }

  /** @type {Array<any>} */
  const subroutes = [];
  for (const reg of validated.regions) {
    subroutes.push({
      match: [
        {
          header: {
            [validated.headerName]: reg.countries
          }
        }
      ],
      handle: [
        {
          handler: 'reverse_proxy',
          upstreams: [{ dial: reg.upstream }]
        }
      ],
      terminal: true
    });
  }

  // Fallback route for non-matching countries
  subroutes.push({
    handle: [
      {
        handler: 'reverse_proxy',
        upstreams: [{ dial: validated.defaultUpstream }]
      }
    ]
  });

  return subroutes;
}

/**
 * Compiles a native Caddy v2.11 JSON route for a sticky Cookie/Header/Weighted A/B experiment.
 * When `killed === true`, emits 100% control (`variants[0]`) with zero traffic split!
 *
 * @param {{
 *   id?: string,
 *   hostname?: string,
 *   stickyMode?: 'cookie' | 'header' | 'weighted',
 *   cookieName?: string,
 *   headerField?: string,
 *   variants: Array<{ name: string, upstream: string, weight: number }>,
 *   killed?: boolean
 * }} cfg
 */
function compileAbExperimentRoute(cfg) {
  const validated = validateExperimentConfig({ ...cfg, regions: undefined });
  if (validated.kind !== 'ab') {
    throw badRequest('INVALID_CONFIG', 'compileAbExperimentRoute requires variants[]');
  }

  /** @type {any} */
  let proxyHandler;
  if (validated.killed) {
    // Instant Kill-Switch: 100% control upstream, zero experiment split!
    proxyHandler = {
      handler: 'reverse_proxy',
      upstreams: [{ dial: validated.variants[0].upstream }]
    };
  } else {
    const weights = validated.variants.map((v) => v.weight);
    /** @type {any} */
    let selectionPolicy;
    if (validated.stickyMode === 'cookie') {
      selectionPolicy = {
        policy: 'cookie',
        name: validated.cookieName,
        fallback: {
          policy: 'weighted_round_robin',
          weights
        }
      };
    } else if (validated.stickyMode === 'header') {
      selectionPolicy = {
        policy: 'header',
        field: validated.headerField,
        fallback: {
          policy: 'weighted_round_robin',
          weights
        }
      };
    } else {
      selectionPolicy = {
        policy: 'weighted_round_robin',
        weights
      };
    }

    proxyHandler = {
      handler: 'reverse_proxy',
      upstreams: validated.variants.map((v) => ({ dial: v.upstream })),
      load_balancing: {
        selection_policy: selectionPolicy
      }
    };
  }

  return {
    ...(validated.hostname ? { match: [{ host: [validated.hostname] }] } : {}),
    handle: [proxyHandler],
    terminal: true
  };
}

class EdgeExperimentService {
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
    return path.join(this.resolveDataDir(), 'edge-experiments.json');
  }

  /** @returns {Array<any>} */
  _loadExperiments() {
    const p = this.getStoreFilePath();
    if (!fs.existsSync(p)) return [];
    try {
      const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
      return parsed && Array.isArray(parsed.experiments) ? parsed.experiments : [];
    } catch (e) {
      return [];
    }
  }

  /** @param {Array<any>} experiments */
  _saveExperiments(experiments) {
    atomicWriteFileSync(
      this.getStoreFilePath(),
      JSON.stringify({ schemaVersion: 1, updatedAt: new Date().toISOString(), experiments: experiments.slice(0, 100) }, null, 2) + '\n'
    );
  }

  /**
   * Lists persisted Edge Geo-Routing & A/B experiments (optionally filtered by `projectId`).
   * @param {string | null | undefined} [projectId]
   */
  listExperiments(projectId) {
    const all = this._loadExperiments();
    if (!projectId) return all;
    const target = String(projectId).trim();
    return all.filter((e) => e && e.projectId === target);
  }

  /**
   * Fetches one experiment by ID.
   * @param {string} id
   */
  getExperiment(id) {
    const clean = String(id || '').trim();
    if (!clean) return null;
    return this._loadExperiments().find((e) => e && e.id === clean) || null;
  }

  /**
   * Validates, compiles native Caddy v2.11 JSON, and atomically persists an experiment.
   * @param {Record<string, any>} cfg
   */
  upsertExperiment(cfg) {
    const validated = validateExperimentConfig(cfg);
    const projectId = String(cfg.projectId || 'default').trim().slice(0, 128) || 'default';
    const id = cfg.id
      ? String(cfg.id).trim().slice(0, 64)
      : `exp_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const name = String(cfg.name || id).trim().slice(0, 120);
    const nowIso = new Date().toISOString();

    const compiledCaddy = validated.kind === 'geo'
      ? { subroutes: compileGeoRoutes(validated) }
      : { route: compileAbExperimentRoute({ ...validated, id }) };

    const all = this._loadExperiments();
    const idx = all.findIndex((e) => e && e.id === id);

    const record = {
      id,
      projectId,
      name,
      enabled: cfg.enabled !== false,
      ...validated,
      ...(validated.kind === 'ab' ? { killed: Boolean(validated.killed), killedAt: null, killReason: null } : {}),
      compiledCaddy,
      createdAt: idx !== -1 ? all[idx].createdAt : nowIso,
      updatedAt: nowIso
    };

    if (idx !== -1) all[idx] = record;
    else all.unshift(record);
    this._saveExperiments(all);

    return {
      ok: true,
      created: idx === -1,
      experiment: record
    };
  }

  /**
   * 1-click kill-switch: immediately reverts an A/B experiment to 100% control (`variants[0]`).
   * @param {string} id
   * @param {{ reason?: string }} [opts]
   */
  triggerKillSwitch(id, opts = {}) {
    const all = this._loadExperiments();
    const idx = all.findIndex((e) => e && e.id === String(id || '').trim());
    if (idx === -1) {
      const err = /** @type {any} */ (new Error(`Edge experiment not found: ${id}`));
      err.code = 'NOT_FOUND';
      err.status = 404;
      throw err;
    }

    const exp = all[idx];
    const nowIso = new Date().toISOString();
    const reason = String(opts.reason || 'manual_kill_switch').trim().slice(0, 200);

    exp.killed = true;
    exp.killedAt = nowIso;
    exp.killReason = reason;
    exp.updatedAt = nowIso;

    if (exp.kind === 'ab' && Array.isArray(exp.variants) && exp.variants.length > 0) {
      exp.compiledCaddy = {
        route: compileAbExperimentRoute({
          id: exp.id,
          hostname: exp.hostname,
          stickyMode: exp.stickyMode,
          cookieName: exp.cookieName,
          headerField: exp.headerField,
          variants: exp.variants,
          killed: true
        })
      };
    }

    all[idx] = exp;
    this._saveExperiments(all);

    return {
      ok: true,
      killed: true,
      id: exp.id,
      controlUpstream: exp.kind === 'ab' && exp.variants?.[0]?.upstream ? exp.variants[0].upstream : exp.defaultUpstream || null,
      reason,
      experiment: exp
    };
  }
}

const defaultEdgeExperimentService = new EdgeExperimentService();

const exported = Object.assign(defaultEdgeExperimentService, {
  EdgeExperimentService,
  ISO_COUNTRY_CODES,
  ALLOWED_GEO_HEADERS,
  ALLOWED_STICKY_MODES,
  compileGeoRoutes,
  compileAbExperimentRoute,
  validateExperimentConfig
});

module.exports = exported;
