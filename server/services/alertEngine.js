const crypto = require('crypto');
const path = require('path');
const { EventEmitter } = require('events');
const { atomicWriteJsonSync, loadJsonWithBackupSync } = require('./ssrfGuard');
const { readHostMemoryStats, readDiskStats } = require('./metricsHistory');

/**
 * Proactive Alert Rules Engine (zero npm deps, zero shell, lazy scheduler).
 *
 * Solves the #1 complaint in Komodo/Coolify/Dokploy: either no proactive host/container
 * threshold alerts, or raw spike spam with no damping/cooldown/recovery.
 *
 * Features:
 *  - Configurable persisted rules (`data/alerts.json`, mode 0600, `.bak` recovery):
 *    Host RAM > 90%, Disk > 85%, CPU > 85%, Container OOMKill, Container Restart Loop (>=3),
 *    TLS Cert expiry < 14d, Uptime Down, HTTP 5xx error rate.
 *  - Consecutive-sample damping (`consecutiveRequired`) to suppress brief spikes.
 *  - Per-(rule, target) cooldown & deduplication routed cleanly to `notificationService`.
 *  - Auto-resolve with recovery notifications (`alert_resolved`) & duration tracking.
 *  - Rule silencing (`silenceRule(id, minutes)`) & alert acknowledgement.
 */

const MAX_RULES = 100;
const MAX_HISTORY = 200;
const DEFAULT_EVAL_INTERVAL_MS = 60 * 1000;

const VALID_METRICS = new Set([
  'host_ram_pct',
  'host_disk_pct',
  'host_cpu_pct',
  'container_oom',
  'container_restart_count',
  'tls_days_remaining',
  'uptime_down_count',
  'http_5xx_rate_pct',
  'event_loop_lag_ms'
]);

const VALID_OPERATORS = new Set(['>', '>=', '<', '<=', '==']);
const VALID_SEVERITIES = new Set(['info', 'warning', 'critical']);

const METRIC_EVENT_MAP = {
  host_ram_pct: 'host_ram_high',
  host_disk_pct: 'host_disk_high',
  host_cpu_pct: 'host_cpu_high',
  container_oom: 'container_oom',
  container_restart_count: 'container_restart_loop',
  tls_days_remaining: 'tls_expiring',
  uptime_down_count: 'uptime_down',
  http_5xx_rate_pct: 'alert_fired',
  event_loop_lag_ms: 'alert_fired'
};

/** @type {Array<{ id: string, name: string, metric: string, operator: string, threshold: number, severity: 'info'|'warning'|'critical', consecutiveRequired: number, cooldownMs: number, enabled: boolean, builtin: boolean, description: string }>} */
const DEFAULT_RULES = [
  {
    id: 'rule_host_ram',
    name: 'Host RAM alta (> 90%)',
    metric: 'host_ram_pct',
    operator: '>',
    threshold: 90,
    severity: 'critical',
    consecutiveRequired: 2,
    cooldownMs: 30 * 60 * 1000,
    enabled: true,
    builtin: true,
    description: 'Alerta cuando la memoria usada real del host (Linux MemAvailable) supera el 90%.'
  },
  {
    id: 'rule_host_disk',
    name: 'Disco del servidor lleno (> 85%)',
    metric: 'host_disk_pct',
    operator: '>',
    threshold: 85,
    severity: 'warning',
    consecutiveRequired: 1,
    cooldownMs: 6 * 3600 * 1000,
    enabled: true,
    builtin: true,
    description: 'Alerta cuando el volumen de datos supera el 85% de uso.'
  },
  {
    id: 'rule_host_cpu',
    name: 'CPU del host sostenida (> 85%)',
    metric: 'host_cpu_pct',
    operator: '>',
    threshold: 85,
    severity: 'warning',
    consecutiveRequired: 3,
    cooldownMs: 30 * 60 * 1000,
    enabled: true,
    builtin: true,
    description: 'Requiere 3 muestras consecutivas > 85% para evitar falsas alarmas por picos breves.'
  },
  {
    id: 'rule_container_oom',
    name: 'Contenedor OOMKilled',
    metric: 'container_oom',
    operator: '>=',
    threshold: 1,
    severity: 'critical',
    consecutiveRequired: 1,
    cooldownMs: 15 * 60 * 1000,
    enabled: true,
    builtin: true,
    description: 'Alerta inmediata cuando Docker marca un contenedor como terminado por falta de memoria (OOMKilled).'
  },
  {
    id: 'rule_container_restart_loop',
    name: 'Bucle de reinicios de contenedor (>= 3)',
    metric: 'container_restart_count',
    operator: '>=',
    threshold: 3,
    severity: 'critical',
    consecutiveRequired: 1,
    cooldownMs: 15 * 60 * 1000,
    enabled: true,
    builtin: true,
    description: 'Detecta contenedores atrapados en crash-loop con 3 o más reinicios.'
  },
  {
    id: 'rule_tls_expiry',
    name: 'Certificado TLS caduca en < 14 días',
    metric: 'tls_days_remaining',
    operator: '<',
    threshold: 14,
    severity: 'warning',
    consecutiveRequired: 1,
    cooldownMs: 12 * 3600 * 1000,
    enabled: true,
    builtin: true,
    description: 'Alerta preventiva antes de que caduque un certificado TLS en disco o en vivo.'
  },
  {
    id: 'rule_uptime_down',
    name: 'Monitor de disponibilidad caído',
    metric: 'uptime_down_count',
    operator: '>=',
    threshold: 1,
    severity: 'critical',
    consecutiveRequired: 1,
    cooldownMs: 15 * 60 * 1000,
    enabled: true,
    builtin: true,
    description: 'Alerta cuando uno o más monitores sintéticos están caídos.'
  },
  {
    id: 'rule_http_5xx',
    name: 'Tasa elevada de errores HTTP 5xx (> 5%)',
    metric: 'http_5xx_rate_pct',
    operator: '>',
    threshold: 5,
    severity: 'warning',
    consecutiveRequired: 2,
    cooldownMs: 15 * 60 * 1000,
    enabled: false,
    builtin: true,
    description: 'Alerta opcional cuando más del 5% de las respuestas del plano de control son 5xx.'
  }
];

function resolveDataDir() {
  return process.env.CULKIBO_DATA_DIR
    ? path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data')
    : path.resolve(__dirname, '..', '..', 'data');
}

/**
 * Evaluates a numeric threshold comparison safely.
 * @param {number} value
 * @param {string} op
 * @param {number} threshold
 */
function compareMetric(value, op, threshold) {
  if (!Number.isFinite(value) || !Number.isFinite(threshold)) return false;
  switch (op) {
    case '>': return value > threshold;
    case '>=': return value >= threshold;
    case '<': return value < threshold;
    case '<=': return value <= threshold;
    case '==': return value === threshold;
    default: return false;
  }
}

/**
 * Maps alert severity to notificationService level.
 * @param {string} severity
 */
function severityToNotifyLevel(severity) {
  if (severity === 'critical') return 'error';
  if (severity === 'warning') return 'warning';
  return 'info';
}

class AlertEngine extends EventEmitter {
  /**
   * @param {{
   *   storeFile?: string | null,
   *   notifier?: { notify: (payload: any) => Promise<any> } | null,
   *   deps?: {
   *     metricsHistory?: any,
   *     metricsCollector?: any,
   *     sslManager?: any,
   *     ingressManager?: any,
   *     uptimeMonitor?: any,
   *     deployManager?: any
   *   }
   * }} [options]
   */
  constructor(options = {}) {
    super();
    this._customStoreFile = options.storeFile || null;
    this._notifier = options.notifier || null;
    this._deps = options.deps || {};

    /** @type {Map<string, any>} */
    this.rules = new Map();
    /** @type {Map<string, { streak: number, firing: boolean, activeAlertId: string | null, lastFiredAt: number, lastValue: number | null }>} */
    this._stateByKey = new Map();
    /** @type {Map<string, any>} */
    this.activeAlerts = new Map();
    /** @type {Array<any>} */
    this.history = [];

    this._loaded = false;
    /** @type {ReturnType<typeof setInterval> | null} */
    this._timer = null;
  }

  getStoreFile() {
    if (this._customStoreFile) return this._customStoreFile;
    return path.join(resolveDataDir(), 'alerts.json');
  }

  _getNotifier() {
    if (this._notifier) return this._notifier;
    try {
      this._notifier = require('./notificationService');
    } catch (e) {
      this._notifier = null;
    }
    return this._notifier;
  }

  _getDep(name) {
    if (Object.prototype.hasOwnProperty.call(this._deps, name)) {
      return this._deps[name];
    }
    try {
      return require(`./${name}`);
    } catch (e) {
      return null;
    }
  }

  _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;

    // Seed defaults first
    for (const r of DEFAULT_RULES) {
      this.rules.set(r.id, {
        ...r,
        silencedUntil: null,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      });
    }

    const res = loadJsonWithBackupSync(this.getStoreFile(), {
      validate: (p) => Boolean(p && typeof p === 'object' && Array.isArray(p.rules))
    });
    if (res.ok && res.data) {
      for (const r of res.data.rules || []) {
        if (r && typeof r.id === 'string' && VALID_METRICS.has(r.metric)) {
          this.rules.set(r.id, {
            id: r.id,
            name: String(r.name || r.id).slice(0, 100),
            metric: r.metric,
            operator: VALID_OPERATORS.has(r.operator) ? r.operator : '>',
            threshold: Number(r.threshold),
            severity: VALID_SEVERITIES.has(r.severity) ? r.severity : 'warning',
            consecutiveRequired: Math.max(1, Math.min(10, Math.round(Number(r.consecutiveRequired) || 1))),
            cooldownMs: Math.max(0, Math.min(7 * 86400000, Math.round(Number(r.cooldownMs) || 900000))),
            enabled: Boolean(r.enabled),
            builtin: Boolean(r.builtin),
            description: String(r.description || '').slice(0, 240),
            silencedUntil: r.silencedUntil || null,
            createdAt: r.createdAt || new Date().toISOString(),
            updatedAt: r.updatedAt || new Date().toISOString()
          });
        }
      }
      if (Array.isArray(res.data.activeAlerts)) {
        for (const a of res.data.activeAlerts) {
          if (a && typeof a.id === 'string' && a.status === 'firing') {
            this.activeAlerts.set(a.id, a);
            if (a.stateKey) {
              this._stateByKey.set(a.stateKey, {
                streak: Math.max(1, Number(a.breachCount) || 1),
                firing: true,
                activeAlertId: a.id,
                lastFiredAt: a.lastNotifiedAt ? Date.parse(a.lastNotifiedAt) || 0 : Date.parse(a.firedAt) || 0,
                lastValue: typeof a.value === 'number' ? a.value : null
              });
            }
          }
        }
      }
      if (Array.isArray(res.data.history)) {
        this.history = res.data.history.slice(0, MAX_HISTORY);
      }
    }
  }

  _save() {
    this._ensureLoaded();
    const payload = {
      version: 1,
      updatedAt: new Date().toISOString(),
      rules: Array.from(this.rules.values()),
      activeAlerts: Array.from(this.activeAlerts.values()),
      history: this.history.slice(0, MAX_HISTORY)
    };
    atomicWriteJsonSync(this.getStoreFile(), payload, { mode: 0o600, backup: true });
  }

  // -------------------------------------------------------------------------
  // Rule CRUD
  // -------------------------------------------------------------------------

  listRules() {
    this._ensureLoaded();
    return Array.from(this.rules.values()).map((r) => ({ ...r }));
  }

  /** @param {string} id */
  getRule(id) {
    this._ensureLoaded();
    const r = this.rules.get(id);
    return r ? { ...r } : null;
  }

  /** @param {any} input @param {any} [existing] */
  _validateRuleInput(input, existing = null) {
    const name = input.name !== undefined
      ? String(input.name || '').trim().slice(0, 100)
      : (existing ? existing.name : '');
    if (!name) throw new Error('El nombre de la regla de alerta es obligatorio');

    const metric = input.metric !== undefined
      ? String(input.metric).trim()
      : (existing ? existing.metric : '');
    if (!VALID_METRICS.has(metric)) {
      throw new Error(`Métrica de alerta no soportada: ${metric}`);
    }

    const operator = input.operator !== undefined
      ? String(input.operator).trim()
      : (existing ? existing.operator : '>');
    if (!VALID_OPERATORS.has(operator)) {
      throw new Error(`Operador inválido: ${operator}`);
    }

    const threshold = input.threshold !== undefined
      ? Number(input.threshold)
      : (existing ? existing.threshold : NaN);
    if (!Number.isFinite(threshold) || threshold < 0 || threshold > 1_000_000) {
      throw new Error('threshold debe ser un número válido >= 0');
    }

    const severity = input.severity !== undefined
      ? String(input.severity).trim().toLowerCase()
      : (existing ? existing.severity : 'warning');
    if (!VALID_SEVERITIES.has(severity)) {
      throw new Error('severity debe ser info, warning o critical');
    }

    const consecutiveRequired = input.consecutiveRequired !== undefined
      ? Math.round(Number(input.consecutiveRequired))
      : (existing ? existing.consecutiveRequired : 1);
    if (!Number.isInteger(consecutiveRequired) || consecutiveRequired < 1 || consecutiveRequired > 10) {
      throw new Error('consecutiveRequired debe ser un entero entre 1 y 10');
    }

    const cooldownMs = input.cooldownMs !== undefined
      ? Math.round(Number(input.cooldownMs))
      : (existing ? existing.cooldownMs : 15 * 60 * 1000);
    if (!Number.isFinite(cooldownMs) || cooldownMs < 0 || cooldownMs > 7 * 86400000) {
      throw new Error('cooldownMs debe estar entre 0 y 7 días');
    }

    const enabled = input.enabled !== undefined ? Boolean(input.enabled) : (existing ? existing.enabled : true);
    const description = input.description !== undefined
      ? String(input.description || '').trim().slice(0, 240)
      : (existing ? existing.description : '');

    return {
      name,
      metric,
      operator,
      threshold,
      severity,
      consecutiveRequired,
      cooldownMs,
      enabled,
      description
    };
  }

  /** @param {any} data */
  createRule(data = {}) {
    this._ensureLoaded();
    if (this.rules.size >= MAX_RULES) {
      throw new Error(`Límite máximo de ${MAX_RULES} reglas de alerta alcanzado`);
    }
    const cfg = this._validateRuleInput(data);
    const nowIso = new Date().toISOString();
    const rule = {
      id: `rule_${crypto.randomBytes(6).toString('hex')}`,
      ...cfg,
      builtin: false,
      silencedUntil: null,
      createdAt: nowIso,
      updatedAt: nowIso
    };
    this.rules.set(rule.id, rule);
    this._save();
    return { ...rule };
  }

  /** @param {string} id @param {any} patch */
  updateRule(id, patch = {}) {
    this._ensureLoaded();
    const existing = this.rules.get(id);
    if (!existing) {
      const err = new Error(`Regla de alerta no encontrada: ${id}`);
      /** @type {any} */ (err).status = 404;
      throw err;
    }
    const cfg = this._validateRuleInput(patch, existing);
    const updated = {
      ...existing,
      ...cfg,
      silencedUntil: patch.silencedUntil !== undefined ? patch.silencedUntil : existing.silencedUntil,
      updatedAt: new Date().toISOString()
    };
    this.rules.set(id, updated);
    this._save();
    return { ...updated };
  }

  /** @param {string} id */
  deleteRule(id) {
    this._ensureLoaded();
    const existing = this.rules.get(id);
    if (!existing) {
      const err = new Error(`Regla de alerta no encontrada: ${id}`);
      /** @type {any} */ (err).status = 404;
      throw err;
    }
    if (existing.builtin) {
      const err = new Error('Las reglas integradas no se eliminan; desactívalas con enabled: false');
      /** @type {any} */ (err).status = 400;
      throw err;
    }
    this.rules.delete(id);
    for (const [aid, alert] of this.activeAlerts.entries()) {
      if (alert.ruleId === id) this.activeAlerts.delete(aid);
    }
    this._save();
    return { deleted: true, id };
  }

  /**
   * Silences a rule for `durationMinutes` (0 clears silence).
   * @param {string} id
   * @param {number} durationMinutes
   */
  silenceRule(id, durationMinutes = 60) {
    this._ensureLoaded();
    const existing = this.rules.get(id);
    if (!existing) {
      const err = new Error(`Regla de alerta no encontrada: ${id}`);
      /** @type {any} */ (err).status = 404;
      throw err;
    }
    const mins = Number(durationMinutes);
    if (!Number.isFinite(mins) || mins < 0 || mins > 7 * 24 * 60) {
      throw new Error('durationMinutes debe estar entre 0 y 10080');
    }
    existing.silencedUntil = mins === 0 ? null : new Date(Date.now() + mins * 60 * 1000).toISOString();
    existing.updatedAt = new Date().toISOString();
    this._save();
    return { ...existing };
  }

  /** @param {string} alertId */
  acknowledgeAlert(alertId) {
    this._ensureLoaded();
    const alert = this.activeAlerts.get(alertId);
    if (!alert) {
      const err = new Error(`Alerta activa no encontrada: ${alertId}`);
      /** @type {any} */ (err).status = 404;
      throw err;
    }
    alert.acknowledged = true;
    alert.acknowledgedAt = new Date().toISOString();
    this._save();
    return { ...alert };
  }

  /**
   * @param {{ projectIds?: string[] | null }} [opts]
   */
  getActiveAlerts(opts = {}) {
    this._ensureLoaded();
    const allowed = Array.isArray(opts.projectIds) ? new Set(opts.projectIds) : null;
    const list = Array.from(this.activeAlerts.values()).filter((a) => {
      if (!allowed) return true;
      return a.projectId ? allowed.has(a.projectId) : false;
    });
    return list.map((a) => ({ ...a }));
  }

  /**
   * @param {{ limit?: number, ruleId?: string | null, status?: string | null, projectIds?: string[] | null }} [opts]
   */
  getHistory(opts = {}) {
    this._ensureLoaded();
    const allowed = Array.isArray(opts.projectIds) ? new Set(opts.projectIds) : null;
    let list = this.history;
    if (allowed) {
      list = list.filter((a) => a.projectId && allowed.has(a.projectId));
    }
    if (opts.ruleId) list = list.filter((a) => a.ruleId === opts.ruleId);
    if (opts.status) list = list.filter((a) => a.status === opts.status);
    const limit = Math.max(1, Math.min(MAX_HISTORY, Number(opts.limit) || 50));
    return list.slice(0, limit).map((a) => ({ ...a }));
  }

  /** @param {{ projectIds?: string[] | null }} [opts] */
  getSummary(opts = {}) {
    this._ensureLoaded();
    const active = this.getActiveAlerts(opts);
    return {
      rulesTotal: this.rules.size,
      rulesEnabled: Array.from(this.rules.values()).filter((r) => r.enabled).length,
      firingCount: active.length,
      criticalFiringCount: active.filter((a) => a.severity === 'critical').length,
      warningFiringCount: active.filter((a) => a.severity === 'warning').length,
      activeAlerts: active
    };
  }

  // -------------------------------------------------------------------------
  // Evaluation Engine (Damping + Cooldown + Dedup + Auto-Resolve)
  // -------------------------------------------------------------------------

  /** @param {any} payload */
  async _sendNotification(payload) {
    const svc = this._getNotifier();
    if (!svc || typeof svc.notify !== 'function') return { sent: false, reason: 'no_notifier' };
    try {
      return await svc.notify(payload);
    } catch (e) {
      return { sent: false, reason: 'error' };
    }
  }

  /**
   * Evaluates a single `(rule, target)` observation with damping, cooldown and auto-resolve.
   * @param {any} rule
   * @param {{ target: string, value: number, projectId?: string | null, projectName?: string | null, detail?: string }} obs
   * @param {number} now
   */
  async _evaluateObservation(rule, obs, now) {
    const stateKey = `${rule.id}:${obs.target}`;
    let st = this._stateByKey.get(stateKey);
    if (!st) {
      st = { streak: 0, firing: false, activeAlertId: null, lastFiredAt: 0, lastValue: null };
      this._stateByKey.set(stateKey, st);
    }
    st.lastValue = obs.value;

    const breached = compareMetric(obs.value, rule.operator, rule.threshold);
    const isSilenced = Boolean(rule.silencedUntil && Date.parse(rule.silencedUntil) > now);

    if (breached) {
      st.streak += 1;
      if (st.streak < rule.consecutiveRequired) {
        return { transition: 'pending_damping', ruleId: rule.id, target: obs.target, streak: st.streak, required: rule.consecutiveRequired };
      }

      if (isSilenced) {
        return { transition: 'silenced', ruleId: rule.id, target: obs.target };
      }

      const withinCooldown = st.lastFiredAt > 0 && rule.cooldownMs > 0 && (now - st.lastFiredAt) < rule.cooldownMs;

      if (!st.firing) {
        const nowIso = new Date(now).toISOString();
        const alert = {
          id: `alt_${crypto.randomBytes(6).toString('hex')}`,
          stateKey,
          ruleId: rule.id,
          ruleName: rule.name,
          metric: rule.metric,
          operator: rule.operator,
          threshold: rule.threshold,
          severity: rule.severity,
          target: obs.target,
          projectId: obs.projectId || null,
          projectName: obs.projectName || null,
          value: obs.value,
          detail: obs.detail || `${rule.name}: valor actual ${obs.value} (umbral ${rule.operator} ${rule.threshold})`,
          status: /** @type {'firing' | 'resolved'} */ ('firing'),
          acknowledged: false,
          acknowledgedAt: /** @type {string | null} */ (null),
          breachCount: st.streak,
          firedAt: nowIso,
          lastNotifiedAt: /** @type {string | null} */ (null),
          resolvedAt: /** @type {string | null} */ (null),
          durationMs: /** @type {number | null} */ (null)
        };
        st.firing = true;
        st.activeAlertId = alert.id;
        this.activeAlerts.set(alert.id, alert);

        let notifyRes = null;
        if (!withinCooldown) {
          st.lastFiredAt = now;
          alert.lastNotifiedAt = nowIso;
          notifyRes = await this._sendNotification({
            event: METRIC_EVENT_MAP[rule.metric] || 'alert_fired',
            level: severityToNotifyLevel(rule.severity),
            title: `[Alerta ${rule.severity.toUpperCase()}] ${rule.name}`,
            message: alert.detail,
            projectId: alert.projectId,
            projectName: alert.projectName || (obs.target !== 'host' ? obs.target : null),
            cooldownMs: rule.cooldownMs
          });
        }

        this.history.unshift({ ...alert });
        if (this.history.length > MAX_HISTORY) this.history = this.history.slice(0, MAX_HISTORY);
        this.emit('alert_fired', alert);
        return { transition: 'fired', alert, notified: !withinCooldown, notifyRes };
      }

      // Already firing: update live value and re-notify only if cooldown has elapsed
      const existing = st.activeAlertId ? this.activeAlerts.get(st.activeAlertId) : null;
      if (existing) {
        existing.value = obs.value;
        existing.breachCount = st.streak;
        if (obs.detail) existing.detail = obs.detail;
        if (!withinCooldown && !existing.acknowledged) {
          st.lastFiredAt = now;
          existing.lastNotifiedAt = new Date(now).toISOString();
          await this._sendNotification({
            event: METRIC_EVENT_MAP[rule.metric] || 'alert_fired',
            level: severityToNotifyLevel(rule.severity),
            title: `[Recordatorio ${rule.severity.toUpperCase()}] ${rule.name}`,
            message: existing.detail,
            projectId: existing.projectId,
            projectName: existing.projectName || (obs.target !== 'host' ? obs.target : null),
            cooldownMs: rule.cooldownMs
          });
          return { transition: 'renotified', alert: existing };
        }
      }
      return { transition: 'deduplicated', ruleId: rule.id, target: obs.target };
    }

    // Healthy observation: reset streak and auto-resolve if previously firing
    st.streak = 0;
    if (st.firing) {
      const nowIso = new Date(now).toISOString();
      const active = st.activeAlertId ? this.activeAlerts.get(st.activeAlertId) : null;
      st.firing = false;
      st.activeAlertId = null;

      if (active) {
        this.activeAlerts.delete(active.id);
        active.status = 'resolved';
        active.resolvedAt = nowIso;
        active.resolvedValue = obs.value;
        active.durationMs = Math.max(0, now - (Date.parse(active.firedAt) || now));

        const histEntry = this.history.find((h) => h.id === active.id);
        if (histEntry) {
          Object.assign(histEntry, {
            status: 'resolved',
            resolvedAt: nowIso,
            resolvedValue: obs.value,
            durationMs: active.durationMs
          });
        } else {
          this.history.unshift({ ...active });
          if (this.history.length > MAX_HISTORY) this.history = this.history.slice(0, MAX_HISTORY);
        }

        const notifyRes = await this._sendNotification({
          event: 'alert_resolved',
          level: 'success',
          title: `[Recuperado] ${rule.name}`,
          message: `${obs.target} volvió a estado normal (valor actual: ${obs.value}, duración: ${Math.round(active.durationMs / 1000)}s).`,
          projectId: active.projectId,
          projectName: active.projectName || (obs.target !== 'host' ? obs.target : null),
          cooldownMs: 0
        });
        this.emit('alert_resolved', active);
        return { transition: 'resolved', alert: active, notifyRes };
      }
    }

    return { transition: 'ok', ruleId: rule.id, target: obs.target };
  }

  /**
   * Evaluates all enabled rules against an explicit telemetry snapshot.
   * @param {{
   *   now?: number,
   *   hostRamPct?: number | null,
   *   hostDiskPct?: number | null,
   *   hostCpuPct?: number | null,
   *   http5xxRatePct?: number | null,
   *   eventLoopLagMs?: number | null,
   *   containers?: Array<{ name: string, projectId?: string | null, projectName?: string | null, oomKilled?: boolean, restartCount?: number }>,
   *   certs?: Array<{ domain: string, daysRemaining: number }>,
   *   uptimeMonitors?: Array<{ id: string, name: string, projectId?: string | null, status: string }>
   * }} snapshot
   */
  async evaluateSnapshot(snapshot = {}) {
    this._ensureLoaded();
    const now = Number.isFinite(Number(snapshot.now)) ? Number(snapshot.now) : Date.now();
    /** @type {Array<any>} */
    const results = [];
    let mutated = false;

    for (const rule of this.rules.values()) {
      if (!rule.enabled) continue;

      /** @type {Array<{ target: string, value: number, projectId?: string | null, projectName?: string | null, detail?: string }>} */
      const observations = [];

      if (rule.metric === 'host_ram_pct' && typeof snapshot.hostRamPct === 'number') {
        observations.push({
          target: 'host',
          value: snapshot.hostRamPct,
          detail: `RAM usada del servidor al ${snapshot.hostRamPct}% (umbral ${rule.operator} ${rule.threshold}%).`
        });
      } else if (rule.metric === 'host_disk_pct' && typeof snapshot.hostDiskPct === 'number') {
        observations.push({
          target: 'host',
          value: snapshot.hostDiskPct,
          detail: `Disco del servidor al ${snapshot.hostDiskPct}% (umbral ${rule.operator} ${rule.threshold}%).`
        });
      } else if (rule.metric === 'host_cpu_pct' && typeof snapshot.hostCpuPct === 'number') {
        observations.push({
          target: 'host',
          value: snapshot.hostCpuPct,
          detail: `CPU del host al ${snapshot.hostCpuPct}% durante ${rule.consecutiveRequired} muestras (umbral ${rule.operator} ${rule.threshold}%).`
        });
      } else if (rule.metric === 'http_5xx_rate_pct' && typeof snapshot.http5xxRatePct === 'number') {
        observations.push({
          target: 'control-plane',
          value: snapshot.http5xxRatePct,
          detail: `Tasa de errores HTTP 5xx al ${snapshot.http5xxRatePct}% (umbral ${rule.operator} ${rule.threshold}%).`
        });
      } else if (rule.metric === 'event_loop_lag_ms' && typeof snapshot.eventLoopLagMs === 'number') {
        observations.push({
          target: 'control-plane',
          value: snapshot.eventLoopLagMs,
          detail: `Event loop lag p95 en ${snapshot.eventLoopLagMs} ms (umbral ${rule.operator} ${rule.threshold} ms).`
        });
      } else if (rule.metric === 'container_oom' && Array.isArray(snapshot.containers)) {
        for (const c of snapshot.containers) {
          if (!c || !c.name) continue;
          const val = c.oomKilled ? 1 : 0;
          observations.push({
            target: c.name,
            value: val,
            projectId: c.projectId || null,
            projectName: c.projectName || c.name,
            detail: `Contenedor "${c.name}" sufrió OOMKilled por superar su límite de RAM.`
          });
        }
      } else if (rule.metric === 'container_restart_count' && Array.isArray(snapshot.containers)) {
        for (const c of snapshot.containers) {
          if (!c || !c.name) continue;
          const restarts = Number(c.restartCount || 0);
          observations.push({
            target: c.name,
            value: restarts,
            projectId: c.projectId || null,
            projectName: c.projectName || c.name,
            detail: `Contenedor "${c.name}" en crash-loop con ${restarts} reinicios (umbral ${rule.operator} ${rule.threshold}).`
          });
        }
      } else if (rule.metric === 'tls_days_remaining' && Array.isArray(snapshot.certs)) {
        for (const cert of snapshot.certs) {
          if (!cert || !cert.domain || typeof cert.daysRemaining !== 'number') continue;
          observations.push({
            target: cert.domain,
            value: cert.daysRemaining,
            detail: `Certificado TLS para "${cert.domain}" caduca en ${cert.daysRemaining} días (umbral < ${rule.threshold} días).`
          });
        }
      } else if (rule.metric === 'uptime_down_count' && Array.isArray(snapshot.uptimeMonitors)) {
        for (const mon of snapshot.uptimeMonitors) {
          if (!mon || !mon.id) continue;
          const isDown = mon.status === 'down' ? 1 : 0;
          observations.push({
            target: mon.name || mon.id,
            value: isDown,
            projectId: mon.projectId || null,
            projectName: mon.name || mon.id,
            detail: `Monitor sintético "${mon.name || mon.id}" se encuentra CAÍDO.`
          });
        }
      }

      for (const obs of observations) {
        const res = await this._evaluateObservation(rule, obs, now);
        results.push(res);
        if (res.transition === 'fired' || res.transition === 'resolved' || res.transition === 'renotified') {
          mutated = true;
        }
      }
    }

    if (mutated) {
      try { this._save(); } catch (e) {}
    }

    return {
      evaluatedAt: new Date(now).toISOString(),
      results,
      firingCount: this.activeAlerts.size
    };
  }

  /**
   * Collects live metrics lazily from Culkibo's in-process services (0 shell exec)
   * and runs `evaluateSnapshot()`.
   */
  async evaluateLive() {
    this._ensureLoaded();
    const mh = this._getDep('metricsHistory');
    const latest = mh && typeof mh.getLatest === 'function' ? mh.getLatest() : null;

    const mem = readHostMemoryStats();
    const disk = readDiskStats();

    const hostRamPct = latest ? latest.hostRamPct : mem.usedPct;
    const hostDiskPct = latest && latest.diskUsedPct !== null ? latest.diskUsedPct : disk.usedPct;
    const hostCpuPct = latest ? latest.hostCpuPct : null;
    const http5xxRatePct = latest ? latest.err5xxRatePct : null;
    const eventLoopLagMs = latest ? latest.elLagMs : null;

    /** @type {Array<{ name: string, projectId?: string | null, projectName?: string | null, oomKilled?: boolean, restartCount?: number }>} */
    const containers = [];
    const dm = this._getDep('deployManager');
    if (dm && dm.store && typeof dm.store === 'object') {
      for (const [projectId, entry] of Object.entries(dm.store)) {
        const cur = entry && entry.current;
        if (!cur || !cur.containerName) continue;
        containers.push({
          name: cur.containerName,
          projectId,
          projectName: cur.projectName || projectId,
          oomKilled: Boolean(cur.oomKilled),
          restartCount: Number(cur.restartCount || 0)
        });
      }
    }

    /** @type {Array<{ domain: string, daysRemaining: number }>} */
    const certs = [];
    const seenCertDomains = new Set();
    const ssl = this._getDep('sslManager');
    if (ssl && typeof ssl.listCertificates === 'function') {
      try {
        for (const c of ssl.listCertificates()) {
          if (c && c.domain && typeof c.daysRemaining === 'number') {
            seenCertDomains.add(c.domain);
            certs.push({ domain: c.domain, daysRemaining: c.daysRemaining });
          }
        }
      } catch (e) {}
    }
    const ing = this._getDep('ingressManager');
    const lastAudit = ing && ing.lastTlsAudit;
    if (lastAudit) {
      for (const list of [lastAudit.expiring, lastAudit.expired]) {
        if (!Array.isArray(list)) continue;
        for (const c of list) {
          const dom = c && (c.hostname || c.domain);
          if (dom && !seenCertDomains.has(dom) && typeof c.daysRemaining === 'number') {
            seenCertDomains.add(dom);
            certs.push({ domain: dom, daysRemaining: c.daysRemaining });
          }
        }
      }
    }

    /** @type {Array<{ id: string, name: string, projectId?: string | null, status: string }>} */
    const uptimeMonitors = [];
    const um = this._getDep('uptimeMonitor');
    if (um && typeof um.listMonitors === 'function') {
      try {
        for (const m of um.listMonitors()) {
          if (m && m.enabled) {
            uptimeMonitors.push({
              id: m.id,
              name: m.name,
              projectId: m.projectId || null,
              status: m.status || 'unknown'
            });
          }
        }
      } catch (e) {}
    }

    return this.evaluateSnapshot({
      hostRamPct,
      hostDiskPct,
      hostCpuPct,
      http5xxRatePct,
      eventLoopLagMs,
      containers,
      certs,
      uptimeMonitors
    });
  }

  /**
   * Starts lazy background evaluation (never called on require()).
   * @param {{ intervalMs?: number }} [opts]
   */
  start(opts = {}) {
    this._ensureLoaded();
    const intervalMs = Math.max(5000, Number(opts.intervalMs) || DEFAULT_EVAL_INTERVAL_MS);
    if (this._timer) return { running: true, intervalMs };
    this._timer = setInterval(() => {
      this.evaluateLive().catch(() => {});
    }, intervalMs);
    if (this._timer.unref) this._timer.unref();
    return { running: true, intervalMs };
  }

  stop() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
  }

  shutdown() {
    this.stop();
  }
}

const alertEngineInstance = Object.assign(new AlertEngine(), {
  AlertEngine,
  DEFAULT_RULES,
  VALID_METRICS,
  VALID_OPERATORS,
  compareMetric
});

module.exports = alertEngineInstance;
