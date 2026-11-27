const crypto = require('crypto');

const PROJECT_ID_RE = /^[a-zA-Z0-9_-]{1,80}$/;
const SERVER_ID_RE = /^[a-z0-9_-]{1,64}$/;
const TEAM_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const FORBIDDEN_MAP_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const SMOKE_HEADER_BLOCKLIST = /^(host|connection|content-length|transfer-encoding|keep-alive|te|trailer|upgrade)$/i;
const DAY_NAME_TO_INDEX = { sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6 };

/**
 * Normaliza un mapa clave-valor de variables de entorno o secretos de build
 * descartando claves peligrosas (prototype pollution o nombres no-POSIX).
 * @param {any} raw
 * @param {number} [maxEntries]
 * @param {number} [maxValueLen]
 * @returns {Record<string, string>}
 */
function normalizeKeyValueMap(raw, maxEntries = 100, maxValueLen = 16384) {
  /** @type {Record<string, string>} */
  const out = {};
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return out;
  let count = 0;
  for (const [rawKey, rawVal] of Object.entries(raw)) {
    if (count >= maxEntries) break;
    const key = String(rawKey || '').trim();
    if (!key || FORBIDDEN_MAP_KEYS.has(key) || !ENV_KEY_RE.test(key)) continue;
    if (rawVal === undefined || rawVal === null) continue;
    if (typeof rawVal === 'string') {
      out[key] = rawVal.slice(0, maxValueLen);
      count++;
    } else if (typeof rawVal === 'number' || typeof rawVal === 'boolean') {
      out[key] = String(rawVal);
      count++;
    }
  }
  return out;
}

/**
 * Normaliza un entero acotado opcional; devuelve `fallback` si está ausente.
 * @param {any} raw
 * @param {number} min
 * @param {number} max
 * @param {number | null} [fallback]
 * @returns {number | null}
 */
function normalizeBoundedInt(raw, min, max, fallback = null) {
  if (raw === undefined || raw === null || raw === '') return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  const rounded = Math.round(n);
  if (rounded < min) return min;
  if (rounded > max) return max;
  return rounded;
}

/**
 * Sustituye todos los valores de un objeto de secretos por `'[REDACTED]'` sin mutarlo.
 * @param {Record<string, any> | null | undefined} map
 * @returns {Record<string, string>}
 */
function maskSecretMap(map) {
  /** @type {Record<string, string>} */
  const masked = {};
  if (!map || typeof map !== 'object' || Array.isArray(map)) return masked;
  for (const key of Object.keys(map)) {
    if (FORBIDDEN_MAP_KEYS.has(key)) continue;
    masked[key] = '[REDACTED]';
  }
  return masked;
}

/**
 * Normaliza una entrada individual de smoke test post-despliegue.
 * @param {any} raw
 */
function normalizeSmokeCheck(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const rawPath = String(raw.path || '').trim();
  if (!rawPath || !rawPath.startsWith('/') || rawPath.startsWith('//') || rawPath.length > 512) return null;
  if (rawPath.includes('..') || /[\s\r\n\0]/.test(rawPath)) return null;

  const rawMethod = String(raw.method || 'GET').toUpperCase();
  const method = (rawMethod === 'HEAD' || rawMethod === 'POST') ? rawMethod : 'GET';

  const expectStatusRaw = raw.expectStatus !== undefined ? raw.expectStatus : raw.expectedStatus;
  let expectStatus = /** @type {number | number[] | string} */ (200);
  if (typeof expectStatusRaw === 'number' && Number.isInteger(expectStatusRaw) && expectStatusRaw >= 100 && expectStatusRaw <= 599) {
    expectStatus = expectStatusRaw;
  } else if (typeof expectStatusRaw === 'string' && /^[1-5]xx$/i.test(expectStatusRaw.trim())) {
    expectStatus = expectStatusRaw.trim().toLowerCase();
  } else if (Array.isArray(expectStatusRaw)) {
    const valid = expectStatusRaw
      .map((n) => Number(n))
      .filter((n) => Number.isInteger(n) && n >= 100 && n <= 599)
      .slice(0, 10);
    if (valid.length > 0) expectStatus = valid;
  } else if (expectStatusRaw === undefined || expectStatusRaw === null) {
    expectStatus = '2xx';
  }

  const containsRaw = raw.expectBodyContains !== undefined ? raw.expectBodyContains : raw.bodyContains;
  const expectBodyContains = typeof containsRaw === 'string' && containsRaw.length > 0
    ? containsRaw.replace(/\0/g, '').slice(0, 256)
    : null;
  const bodyNotContains = typeof raw.bodyNotContains === 'string' && raw.bodyNotContains.length > 0
    ? raw.bodyNotContains.replace(/\0/g, '').slice(0, 256)
    : null;

  const maxLat = raw.maxLatencyMs !== undefined && raw.maxLatencyMs !== null && raw.maxLatencyMs !== ''
    ? Number(raw.maxLatencyMs)
    : null;
  const maxLatencyMs = maxLat !== null && Number.isFinite(maxLat) && maxLat >= 1 && maxLat <= 60000
    ? Math.round(maxLat)
    : null;

  const timeoutRaw = raw.timeoutMs !== undefined && raw.timeoutMs !== null ? Number(raw.timeoutMs) : null;
  const timeoutMs = timeoutRaw !== null && Number.isFinite(timeoutRaw) && timeoutRaw >= 50 && timeoutRaw <= 30000
    ? Math.round(timeoutRaw)
    : undefined;

  const retriesRaw = raw.retries !== undefined && raw.retries !== null ? parseInt(String(raw.retries), 10) : 0;
  const retries = Number.isInteger(retriesRaw) && retriesRaw >= 0 && retriesRaw <= 3 ? retriesRaw : 0;

  /** @type {Record<string, string> | undefined} */
  let headers;
  if (raw.headers && typeof raw.headers === 'object' && !Array.isArray(raw.headers)) {
    /** @type {Record<string, string>} */
    const cleanHeaders = {};
    let count = 0;
    for (const [k, v] of Object.entries(raw.headers)) {
      if (count >= 10) break;
      if (/^[A-Za-z0-9-]+$/.test(k) && !SMOKE_HEADER_BLOCKLIST.test(k) && typeof v === 'string') {
        cleanHeaders[k] = v.replace(/[\r\n\0]/g, '').slice(0, 512);
        count++;
      }
    }
    if (count > 0) headers = cleanHeaders;
  }

  /** @type {any} */
  const normalized = {
    ...(raw.name ? { name: String(raw.name).replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 80) } : {}),
    method,
    path: rawPath,
    expectStatus,
    ...(expectBodyContains !== null ? { expectBodyContains } : {}),
    ...(bodyNotContains !== null ? { bodyNotContains } : {}),
    ...(maxLatencyMs !== null ? { maxLatencyMs } : {}),
    ...(timeoutMs !== undefined ? { timeoutMs } : {}),
    ...(retries > 0 ? { retries } : {}),
    ...(headers ? { headers } : {}),
    ...(method === 'POST' && typeof raw.body === 'string' ? { body: raw.body.slice(0, 16384) } : {})
  };

  if (raw.jsonPathEquals && typeof raw.jsonPathEquals === 'object' && !Array.isArray(raw.jsonPathEquals)) {
    const jp = String(raw.jsonPathEquals.path || '').trim();
    const parts = jp.split('.').filter(Boolean);
    const forbidden = new Set(['__proto__', 'constructor', 'prototype']);
    if (parts.length >= 1 && parts.length <= 5 && parts.every((seg) => /^[A-Za-z0-9_-]{1,64}$/.test(seg) && !forbidden.has(seg))) {
      normalized.jsonPathEquals = { path: parts.join('.'), value: raw.jsonPathEquals.value };
    }
  }

  return normalized;
}

/**
 * Soporta tanto el formato compacto de array `[{ path, expectStatus, expectBodyContains, maxLatencyMs }]`
 * como el formato extendido `{ enabled, failPolicy, checks }`.
 * @param {any} raw
 */
function normalizeSmokeTests(raw) {
  if (Array.isArray(raw)) {
    return raw.map(normalizeSmokeCheck).filter(Boolean).slice(0, 10);
  }
  if (raw && typeof raw === 'object' && Array.isArray(raw.checks)) {
    const failPolicy = raw.failPolicy === 'rollback' || raw.failPolicy === 'warn' ? raw.failPolicy : 'abort';
    return {
      enabled: Boolean(raw.enabled),
      failPolicy,
      checks: raw.checks.map(normalizeSmokeCheck).filter(Boolean).slice(0, 10)
    };
  }
  return [];
}

/**
 * Normaliza la configuración de Canary Auto-Guard.
 * @param {any} raw
 */
function normalizeCanary(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return {
      enabled: false,
      weightPercent: 10,
      observeSeconds: 30,
      maxErrorRate: 0.05,
      autoRollback: true
    };
  }
  const wpRaw = Number(raw.weightPercent);
  const weightPercent = Number.isFinite(wpRaw) && wpRaw >= 1 && wpRaw <= 99 ? Math.round(wpRaw) : 10;
  const obsRaw = Number(raw.observeSeconds);
  const observeSeconds = Number.isFinite(obsRaw) && obsRaw > 0 && obsRaw <= 3600 ? obsRaw : 30;
  const errRaw = raw.maxErrorRate !== undefined && raw.maxErrorRate !== null ? Number(raw.maxErrorRate) : 0.05;
  const maxErrorRate = Number.isFinite(errRaw) && errRaw >= 0 && errRaw <= 1 ? errRaw : 0.05;

  /** @type {any} */
  const out = {
    enabled: Boolean(raw.enabled),
    weightPercent,
    observeSeconds,
    maxErrorRate,
    autoRollback: raw.autoRollback !== undefined ? Boolean(raw.autoRollback) : true
  };
  if (Array.isArray(raw.steps) && raw.steps.length > 0) {
    const cleanSteps = raw.steps
      .map((s) => Math.round(Number(s)))
      .filter((n) => Number.isInteger(n) && n >= 1 && n <= 100)
      .slice(0, 5);
    if (cleanSteps.length > 0) out.steps = cleanSteps;
  }
  if (raw.stepDurationMs !== undefined && raw.stepDurationMs !== null) {
    const sd = Number(raw.stepDurationMs);
    if (Number.isFinite(sd) && sd >= 10 && sd <= 300000) out.stepDurationMs = Math.round(sd);
  }
  if (raw.checksPerStep !== undefined && raw.checksPerStep !== null) {
    const cps = parseInt(String(raw.checksPerStep), 10);
    if (Number.isInteger(cps) && cps >= 1 && cps <= 10) out.checksPerStep = cps;
  }
  if (raw.maxLatencyMs !== undefined && raw.maxLatencyMs !== null) {
    const ml = Number(raw.maxLatencyMs);
    if (Number.isFinite(ml) && ml >= 1 && ml <= 60000) out.maxLatencyMs = Math.round(ml);
  }
  if (raw.requireManualPromote !== undefined) {
    out.requireManualPromote = Boolean(raw.requireManualPromote);
  }
  return out;
}

/**
 * Normaliza los días de semana a enteros 0..6 (0=domingo .. 6=sábado).
 * @param {any} rawDays
 * @returns {number[] | null}
 */
function normalizeDaysArray(rawDays) {
  if (!Array.isArray(rawDays)) return null;
  /** @type {number[]} */
  const out = [];
  for (const d of rawDays) {
    if (typeof d === 'number' && Number.isInteger(d) && d >= 0 && d <= 6) {
      out.push(d);
    } else if (typeof d === 'string') {
      const k = d.trim().toLowerCase().slice(0, 3);
      if (Object.prototype.hasOwnProperty.call(DAY_NAME_TO_INDEX, k)) {
        out.push(DAY_NAME_TO_INDEX[/** @type {keyof typeof DAY_NAME_TO_INDEX} */ (k)]);
      } else {
        const parsed = parseInt(d.trim(), 10);
        if (Number.isInteger(parsed) && parsed >= 0 && parsed <= 6) out.push(parsed);
      }
    }
  }
  return Array.from(new Set(out)).sort((a, b) => a - b);
}

/**
 * Normaliza ventanas de congelación de despliegues (soporta `{ days, startHour, endHour, tz, reason }`
 * y `{ daysOfWeek, startTime, endTime, timezone, kind, startAt, endAt, reason }`).
 * @param {any} raw
 */
function normalizeFreezeWindows(raw) {
  if (!Array.isArray(raw)) return [];
  /** @type {any[]} */
  const out = [];
  for (const w of raw.slice(0, 16)) {
    if (!w || typeof w !== 'object' || Array.isArray(w)) continue;
    const tzRaw = String(w.tz || w.timezone || 'UTC').trim() || 'UTC';
    let tz = 'UTC';
    try {
      new Intl.DateTimeFormat('en-US', { timeZone: tzRaw });
      tz = tzRaw;
    } catch (e) {
      continue;
    }
    const reason = String(w.reason || '').replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 200);
    const enabled = w.enabled !== undefined ? Boolean(w.enabled) : true;
    const base = {
      ...(w.id ? { id: String(w.id).replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 48) } : {}),
      ...(w.name ? { name: String(w.name).replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 80) } : {}),
      enabled,
      tz,
      reason
    };

    if (w.kind === 'once' && w.startAt && w.endAt) {
      const s = Date.parse(String(w.startAt));
      const e = Date.parse(String(w.endAt));
      if (Number.isFinite(s) && Number.isFinite(e) && e > s) {
        out.push({ ...base, kind: 'once', startAt: new Date(s).toISOString(), endAt: new Date(e).toISOString() });
      }
      continue;
    }

    const days = normalizeDaysArray(w.days !== undefined ? w.days : w.daysOfWeek) || [0, 1, 2, 3, 4, 5, 6];
    const hasHours = w.startHour !== undefined && w.endHour !== undefined;
    const hasTimes = typeof w.startTime === 'string' && typeof w.endTime === 'string';
    if (hasHours) {
      const sh = Number(w.startHour);
      const eh = Number(w.endHour);
      if (Number.isInteger(sh) && sh >= 0 && sh <= 23 && Number.isInteger(eh) && eh >= 0 && eh <= 24) {
        out.push({
          ...base,
          days,
          startHour: sh,
          endHour: eh,
          ...(Array.isArray(w.blockTriggers) ? { blockTriggers: w.blockTriggers.map(String).slice(0, 8) } : {})
        });
      }
    } else if (hasTimes) {
      const st = w.startTime.trim();
      const et = w.endTime.trim();
      if (/^([01]\d|2[0-3]):[0-5]\d$/.test(st) && /^(([01]\d|2[0-3]):[0-5]\d|24:00)$/.test(et)) {
        out.push({
          ...base,
          kind: 'recurring',
          days,
          startTime: st,
          endTime: et,
          ...(Array.isArray(w.blockTriggers) ? { blockTriggers: w.blockTriggers.map(String).slice(0, 8) } : {})
        });
      }
    }
  }
  return out;
}

class Project {
  constructor(data) {
    // `proj_${Date.now()}` collides when several projects are created inside the
    // same millisecond (bulk Coolify import), silently overwriting each other in
    // the Map. Suffix with entropy while keeping the id filesystem/URL safe.
    if (data.id !== undefined && data.id !== null && data.id !== '') {
      const rawId = String(data.id);
      if (!PROJECT_ID_RE.test(rawId)) {
        throw new Error(`Invalid project ID: ${rawId.slice(0, 40)}`);
      }
      this.id = rawId;
    } else {
      this.id = `proj_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    }
    this.name = data.name || 'Nuevo Proyecto';
    this.description = data.description || '';
    this.icon = data.icon || '🚀';
    this.status = data.status || 'active'; // active | hibernated | stopped
    this.forgePort = data.forgePort || 3001;
    this.citadelPort = data.citadelPort || 8080;
    this.trafficSplit = data.trafficSplit || { forge: 0, citadel: 100 };
    this.domains = data.domains || [];
    this.envVars = data.envVars || {};
    this.gitRepo = data.gitRepo || '';
    this.createdAt = data.createdAt || new Date().toISOString();
    this.updatedAt = data.updatedAt || new Date().toISOString();
    this.source = data.source || 'manual'; // manual | coolify-import | github
    this.resources = data.resources || [];
    this.gitBranch = data.gitBranch || 'main';
    this.buildCommand = data.buildCommand || '';
    this.startCommand = data.startCommand || '';
    this.baseDirectory = data.baseDirectory || '/';
    this.watchPaths = data.watchPaths || [];
    this.volumes = data.volumes || [];
    this.fileMounts = data.fileMounts || [];
    this.webhookSecret = data.webhookSecret || crypto.randomBytes(16).toString('hex');
    this.deployHookToken = data.deployHookToken || crypto.randomBytes(24).toString('hex');
    this.autoDeploy = data.autoDeploy !== undefined ? data.autoDeploy : true;
    this.lastDeployedAt = data.lastDeployedAt || null;
    this.lastCommit = data.lastCommit || null;
    this.githubOwner = data.githubOwner || '';
    this.githubRepo = data.githubRepo || '';
    this.localPath = data.localPath ? String(data.localPath).trim() : '';
    this.localRunning = data.localRunning !== undefined ? data.localRunning : false;
    this.localPort = data.localPort || null;
    // Ajustes del despliegue a producción (deployManager). Sin estos campos en
    // el modelo, cualquier valor que el usuario configurase se perdía en el
    // siguiente `update()`, porque el constructor reconstruye el objeto entero.
    // Todos se vuelven a validar en deployManager antes de tocar un argv.
    this.containerPort = data.containerPort || null;
    this.healthPath = data.healthPath || '/';
    this.healthStartPeriodSec = normalizeBoundedInt(data.healthStartPeriodSec, 0, 300, null);
    this.healthRetries = normalizeBoundedInt(data.healthRetries, 1, 10, null);
    this.healthyThreshold = normalizeBoundedInt(data.healthyThreshold, 1, 5, null);
    this.memoryMb = data.memoryMb || null;
    this.cpus = data.cpus || null;
    this.buildArgs = data.buildArgs || {};
    this.buildSecrets = normalizeKeyValueMap(data.buildSecrets);
    // Hooks pre/post despliegue ejecutados sin shell (argv puro dentro del contenedor).
    this.preDeployCommand = data.preDeployCommand || '';
    this.postDeployCommand = data.postDeployCommand || '';
    this.hookTimeoutMs = Math.min(600000, Math.max(5000, Number(data.hookTimeoutMs) || 120000));
    this.postDeployFailPolicy = data.postDeployFailPolicy === 'rollback' ? 'rollback' : 'warn';
    // Enlaces declarativos a bases de datos gestionadas (solo IDs; los secretos
    // nunca se persisten en texto plano en projects.json) y dependencias internas.
    this.linkedDatabaseIds = Array.isArray(data.linkedDatabaseIds)
      ? Array.from(new Set(data.linkedDatabaseIds.filter((x) => typeof x === 'string' && x.trim())))
      : [];
    this.dependencies = Array.isArray(data.dependencies) ? data.dependencies : [];
    // Modo mantenimiento atómico (<10 ms en Caddy), auto-rollback ante crash-loop/OOM
    // y vistas previas HTTPS automáticas por Pull Request / rama.
    this.maintenanceMode = Boolean(data.maintenanceMode);
    this.autoRollback = data.autoRollback !== undefined ? Boolean(data.autoRollback) : true;
    this.previewDeployments = data.previewDeployments && typeof data.previewDeployments === 'object' && !Array.isArray(data.previewDeployments)
      ? {
          enabled: Boolean(data.previewDeployments.enabled),
          baseDomain: String(data.previewDeployments.baseDomain || '').trim().toLowerCase(),
          maxPreviews: Math.min(20, Math.max(1, Number(data.previewDeployments.maxPreviews) || 5)),
          allowForks: Boolean(data.previewDeployments.allowForks),
          ttlHours: Math.min(720, Math.max(1, Number(data.previewDeployments.ttlHours) || 168)),
          memoryMb: Math.min(4096, Math.max(64, Number(data.previewDeployments.memoryMb) || 512)),
          envVars: normalizeKeyValueMap(data.previewDeployments.envVars),
          buildSecrets: normalizeKeyValueMap(data.previewDeployments.buildSecrets),
          healthTimeoutMs: normalizeBoundedInt(data.previewDeployments.healthTimeoutMs, 5000, 300000, null)
        }
      : {
          enabled: false,
          baseDomain: '',
          maxPreviews: 5,
          allowForks: false,
          ttlHours: 168,
          memoryMb: 512,
          envVars: {},
          buildSecrets: {},
          healthTimeoutMs: null
        };
    // Enrutamiento multi-servidor (Fleet SSH), aislamiento multi-equipo (RBAC)
    // y guardias de despliegue (Smoke Tests, Canary Auto-Guard, Freeze Windows).
    const rawServerId = data.serverId !== undefined && data.serverId !== null ? String(data.serverId).trim() : '';
    this.serverId = rawServerId && SERVER_ID_RE.test(rawServerId) ? rawServerId : 'local';
    const rawTeamId = data.teamId !== undefined && data.teamId !== null ? String(data.teamId).trim() : '';
    this.teamId = rawTeamId && TEAM_ID_RE.test(rawTeamId) ? rawTeamId : 'team_default';
    this.smokeTests = normalizeSmokeTests(data.smokeTests);
    this.canary = normalizeCanary(data.canary);
    this.freezeWindows = normalizeFreezeWindows(data.freezeWindows);
  }

  /**
   * Devuelve una copia segura del proyecto para serialización sin privilegios (`viewer` o sin `secrets:read`).
   * Jamás muta la instancia original en memoria ni expone `buildSecrets` ni `previewDeployments.buildSecrets`.
   * @param {{ includeSecrets?: boolean, maskBuildSecrets?: boolean }} [opts]
   */
  toSafeJSON(opts = {}) {
    return Project.redactForUnprivileged(this, opts);
  }

  /**
   * Clona y redacta secretos de un objeto `Project` (incluidos `buildSecrets` y
   * `previewDeployments.{buildSecrets,envVars}`) para respuestas sin privilegios.
   * @param {any} proj
   * @param {{ includeSecrets?: boolean, maskBuildSecrets?: boolean }} [opts]
   */
  static redactForUnprivileged(proj, opts = {}) {
    if (!proj || typeof proj !== 'object') return proj;
    const includeSecrets = opts.includeSecrets === true;
    const maskBuildOnly = opts.maskBuildSecrets === true;
    const copy = { ...proj };

    if (!includeSecrets || maskBuildOnly) {
      if (copy.buildSecrets && typeof copy.buildSecrets === 'object' && !Array.isArray(copy.buildSecrets)) {
        copy.buildSecrets = maskSecretMap(copy.buildSecrets);
      }
      if (copy.previewDeployments && typeof copy.previewDeployments === 'object' && !Array.isArray(copy.previewDeployments)) {
        const pd = { ...copy.previewDeployments };
        if (pd.buildSecrets && typeof pd.buildSecrets === 'object' && !Array.isArray(pd.buildSecrets)) {
          pd.buildSecrets = maskSecretMap(pd.buildSecrets);
        }
        if (!includeSecrets && pd.envVars && typeof pd.envVars === 'object' && !Array.isArray(pd.envVars)) {
          pd.envVars = maskSecretMap(pd.envVars);
        }
        copy.previewDeployments = pd;
      }
    }

    if (!includeSecrets) {
      if (copy.envVars && typeof copy.envVars === 'object' && !Array.isArray(copy.envVars)) {
        copy.envVars = maskSecretMap(copy.envVars);
      }
      if (copy.buildArgs && typeof copy.buildArgs === 'object' && !Array.isArray(copy.buildArgs)) {
        copy.buildArgs = maskSecretMap(copy.buildArgs);
      }
      if (copy.webhookSecret) copy.webhookSecret = '[REDACTED]';
      if (copy.deployHookToken) copy.deployHookToken = '[REDACTED]';
      if (copy.secrets && typeof copy.secrets === 'object' && !Array.isArray(copy.secrets)) {
        copy.secrets = maskSecretMap(copy.secrets);
      }
      copy._secretsRedacted = true;
    }

    return copy;
  }
}

Project.maskSecretMap = maskSecretMap;
Project.normalizeKeyValueMap = normalizeKeyValueMap;

module.exports = Project;
