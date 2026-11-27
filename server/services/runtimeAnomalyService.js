const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Falco-Lite Container Runtime Anomaly Detector (100% Zero-Dep Pure JS).
 *
 * Contramedida directa ante `dokploy#5156` (bots automatizados de criptominería
 * escaneando y comprometiendo instancias PaaS) y patrones de detección de Falco:
 *  - 10 reglas deterministas sobre telemetría de procesos, archivos y sockets.
 *  - Cero dependencias de kernel/eBPF, 0 invocaciones de shell.
 *  - Persistencia atómica `0o600` acotada a las últimas 200 alertas en
 *    `CULKIBO_DATA_DIR/data/runtime-anomalies.json`.
 */

const MAX_PERSISTED_ALERTS = 200;

const MINER_PORTS = new Set([3333, 4444, 5555, 7777, 14433, 14444, 45700]);
const C2_PORTS = new Set([1337, 4445, 6667, 6697, 9001, 9050, 9999, 12345, 31337]);

const ANOMALY_RULES = Object.freeze([
  Object.freeze({
    id: 'CRYPTOMINER_STRATUM_TRAFFIC',
    severity: 'critical',
    title: 'Cryptominer binary or Stratum mining pool traffic detected (dokploy#5156)'
  }),
  Object.freeze({
    id: 'REVERSE_SHELL_SPAWN',
    severity: 'critical',
    title: 'Interactive reverse shell spawn attempt detected'
  }),
  Object.freeze({
    id: 'SENSITIVE_FILE_ACCESS',
    severity: 'critical',
    title: 'Sensitive credential/host file read or tampering detected (/etc/shadow, /etc/passwd, core_pattern)'
  }),
  Object.freeze({
    id: 'REMOTE_SCRIPT_PIPE_EXEC',
    severity: 'high',
    title: 'Remote script piped directly into shell (curl|sh or wget|bash)'
  }),
  Object.freeze({
    id: 'UNEXPECTED_PRIVILEGED_EXEC',
    severity: 'high',
    title: 'Unexpected privileged or namespace-escape execution inside container'
  }),
  Object.freeze({
    id: 'BINARY_DRIFT_IN_TMP',
    severity: 'high',
    title: 'Execution of dropped binary from writable /tmp or /dev/shm directory'
  }),
  Object.freeze({
    id: 'DOCKER_SOCK_PROBE',
    severity: 'critical',
    title: 'Container probed Docker or containerd host control socket'
  }),
  Object.freeze({
    id: 'PACKAGE_MANAGER_AT_RUNTIME',
    severity: 'medium',
    title: 'OS package manager invoked inside a running production container'
  }),
  Object.freeze({
    id: 'ENV_CREDENTIAL_SCRAPE',
    severity: 'high',
    title: 'Runtime credential scrape (/proc/*/environ, IMDS metadata, or k8s serviceaccount token)'
  }),
  Object.freeze({
    id: 'ANOMALOUS_OUTBOUND_C2_PORT',
    severity: 'high',
    title: 'Outbound connection to anomalous C2/IRC/Tor port or darknet domain'
  })
]);

const RULE_BY_ID = Object.freeze(
  Object.fromEntries(ANOMALY_RULES.map((r) => [r.id, r]))
);

/**
 * Resuelve dinámicamente la ruta a `runtime-anomalies.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'runtime-anomalies.json')
    : path.join(base, 'data', 'runtime-anomalies.json');
}

/**
 * Escritura atómica con permisos `0o600`.
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
 * @typedef {object} RuntimeAnomalyAlert
 * @property {string} id
 * @property {string} projectId
 * @property {string} containerName
 * @property {string} ruleId
 * @property {string} severity
 * @property {string} title
 * @property {string} evidence
 * @property {number} eventIndex
 * @property {string} detectedAt
 */

/**
 * Carga alertas almacenadas (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, alerts: RuntimeAnomalyAlert[] }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), alerts: [] };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && Array.isArray(parsed.alerts)) {
      return parsed;
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), alerts: [] };
}

/**
 * Normaliza un evento de telemetría (objeto o string) a campos inspeccionables.
 * @param {any} rawEvent
 */
function normalizeEvent(rawEvent) {
  if (typeof rawEvent === 'string') {
    return {
      type: 'process',
      cmd: rawEvent,
      file: '',
      action: '',
      host: '',
      port: 0,
      privileged: false,
      capabilities: /** @type {string[]} */ ([])
    };
  }
  const ev = (rawEvent && typeof rawEvent === 'object') ? rawEvent : {};
  const parts = [
    ev.process,
    ev.command,
    ev.cmd,
    ev.cmdline,
    Array.isArray(ev.args) ? ev.args.join(' ') : ev.args
  ].filter(Boolean).map(String);

  return {
    type: String(ev.type || 'process').toLowerCase(),
    cmd: parts.join(' ').trim(),
    file: String(ev.file || ev.path || ev.targetPath || '').trim(),
    action: String(ev.action || ev.op || '').toLowerCase(),
    host: String(ev.destHost || ev.destIp || ev.host || ev.remoteHost || '').trim(),
    port: Number(ev.destPort ?? ev.port ?? ev.remotePort ?? 0) || 0,
    privileged: Boolean(ev.privileged),
    capabilities: Array.isArray(ev.capabilities) ? ev.capabilities.map(String) : []
  };
}

/**
 * Evalúa un evento normalizado contra las 10 reglas Falco-lite y devuelve los IDs disparados.
 * @param {ReturnType<typeof normalizeEvent>} ev
 * @returns {Array<{ ruleId: string, evidence: string }>}
 */
function matchEventRules(ev) {
  /** @type {Array<{ ruleId: string, evidence: string }>} */
  const hits = [];
  const combined = `${ev.cmd} ${ev.file} ${ev.host}`.trim();

  // 1. CRYPTOMINER_STRATUM_TRAFFIC
  if (
    /\b(?:xmrig|minerd|cpuminer|ethminer|t-rex|lolminer|nbminer|kdevtmpfsi|kinsing)\b/i.test(combined)
    || /stratum\+(?:tcp|ssl):\/\//i.test(combined)
    || /(?:minexmr|supportxmr|hashvault|nanopool|moneroocean|c3pool)/i.test(combined)
    || MINER_PORTS.has(ev.port)
  ) {
    hits.push({
      ruleId: 'CRYPTOMINER_STRATUM_TRAFFIC',
      evidence: ev.port && MINER_PORTS.has(ev.port)
        ? `Outbound mining/Stratum port ${ev.port}${ev.host ? ` (${ev.host})` : ''}`
        : combined.slice(0, 140)
    });
  }

  // 2. REVERSE_SHELL_SPAWN
  if (
    /\/dev\/(?:tcp|udp)\//i.test(ev.cmd)
    || /\b(?:nc|ncat|netcat)\b[^\n]*(?:\s-e\s|\s-c\s|--sh-exec)/i.test(ev.cmd)
    || /\b(?:bash|sh|zsh)\s+-i\b/i.test(ev.cmd)
    || /\bsocat\b[^\n]*\b(?:exec:|system:)/i.test(ev.cmd)
    || /\b(?:python3?|perl|ruby|php)\s+-[cr]\b[^\n]*(?:socket|fsockopen|pty\.spawn)/i.test(ev.cmd)
    || /\bmkfifo\s+\/tmp\//i.test(ev.cmd)
  ) {
    hits.push({
      ruleId: 'REVERSE_SHELL_SPAWN',
      evidence: ev.cmd.slice(0, 140)
    });
  }

  // 3. SENSITIVE_FILE_ACCESS
  const touchesShadowOrCore = /(?:\/etc\/g?shadow\b|\/proc\/sys\/kernel\/core_pattern\b|\/etc\/sudoers\b|\/root\/\.ssh\/authorized_keys\b)/i.test(combined);
  const writesPasswd = /\/etc\/passwd\b/i.test(combined) && (
    ev.action === 'write'
    || ev.action === 'modify'
    || ev.action === 'append'
    || /(?:>>?|tee\s|sed\s+-i|echo\s+.*\/etc\/passwd|usermod|useradd)/i.test(ev.cmd)
  );
  if (touchesShadowOrCore || writesPasswd) {
    hits.push({
      ruleId: 'SENSITIVE_FILE_ACCESS',
      evidence: (ev.file || ev.cmd).slice(0, 140)
    });
  }

  // 4. REMOTE_SCRIPT_PIPE_EXEC
  if (/\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:\/bin\/|\/usr\/bin\/)?(?:sh|bash|zsh|dash|python3?)\b/i.test(ev.cmd)) {
    hits.push({
      ruleId: 'REMOTE_SCRIPT_PIPE_EXEC',
      evidence: ev.cmd.slice(0, 140)
    });
  }

  // 5. UNEXPECTED_PRIVILEGED_EXEC
  const dangerousCap = ev.capabilities.some((c) => /SYS_ADMIN|SYS_PTRACE|SYS_MODULE|NET_ADMIN/i.test(c));
  if (
    ev.privileged
    || dangerousCap
    || /\b(?:nsenter|chroot|capsh|setcap|insmod|modprobe|iptables|nft\s+add)\b/i.test(ev.cmd)
    || /\bmount\s+-o\b/i.test(ev.cmd)
  ) {
    hits.push({
      ruleId: 'UNEXPECTED_PRIVILEGED_EXEC',
      evidence: (ev.cmd || `privileged=${ev.privileged} caps=${ev.capabilities.join(',')}`).slice(0, 140)
    });
  }

  // 6. BINARY_DRIFT_IN_TMP
  if (
    /(?:^|\s|&&|\|\||;)(?:\/tmp\/|\/var\/tmp\/|\/dev\/shm\/)[^\s;&|]+/i.test(ev.cmd)
    && !/^\s*(?:rm|ls|cat|mkdir|touch)\s/i.test(ev.cmd)
  ) {
    hits.push({
      ruleId: 'BINARY_DRIFT_IN_TMP',
      evidence: ev.cmd.slice(0, 140)
    });
  } else if (ev.type === 'exec' && /^(?:\/tmp\/|\/var\/tmp\/|\/dev\/shm\/)/i.test(ev.file)) {
    hits.push({
      ruleId: 'BINARY_DRIFT_IN_TMP',
      evidence: `Exec from writable temp path: ${ev.file}`
    });
  }

  // 7. DOCKER_SOCK_PROBE
  if (/(?:\/var\/run\/docker\.sock|\/run\/containerd\/containerd\.sock|docker\.sock)/i.test(combined)) {
    hits.push({
      ruleId: 'DOCKER_SOCK_PROBE',
      evidence: (ev.file || ev.cmd).slice(0, 140)
    });
  }

  // 8. PACKAGE_MANAGER_AT_RUNTIME
  if (/\b(?:apt-get\s+install|apt\s+install|apk\s+add|yum\s+install|dnf\s+install|pacman\s+-S|pip3?\s+install)\b/i.test(ev.cmd)) {
    hits.push({
      ruleId: 'PACKAGE_MANAGER_AT_RUNTIME',
      evidence: ev.cmd.slice(0, 140)
    });
  }

  // 9. ENV_CREDENTIAL_SCRAPE
  if (
    /\/proc\/(?:\d+|self|1)\/environ\b/i.test(combined)
    || /169\.254\.169\.254|fd00:ec2::254|metadata\.google\.internal/i.test(combined)
    || /\/var\/run\/secrets\/kubernetes\.io/i.test(combined)
    || /\b(?:env|printenv)\b[^\n|]*\|\s*(?:curl|wget|nc|base64)\b/i.test(ev.cmd)
  ) {
    hits.push({
      ruleId: 'ENV_CREDENTIAL_SCRAPE',
      evidence: (ev.file || ev.cmd || ev.host).slice(0, 140)
    });
  }

  // 10. ANOMALOUS_OUTBOUND_C2_PORT
  if (C2_PORTS.has(ev.port) || /\.onion\b/i.test(ev.host)) {
    hits.push({
      ruleId: 'ANOMALOUS_OUTBOUND_C2_PORT',
      evidence: `Suspicious outbound endpoint ${ev.host || 'unknown'}:${ev.port || 'n/a'}`
    });
  }

  return hits;
}

/**
 * Inspecciona un lote de eventos de telemetría runtime contra las 10 reglas Falco-lite.
 *
 * @param {{
 *   projectId?: string,
 *   containerName?: string,
 *   events?: any[],
 *   persist?: boolean
 * }} [input]
 */
function inspectRuntimeEvents(input = {}) {
  const opts = input || {};
  const projectId = String(opts.projectId || 'default').trim() || 'default';
  const containerName = String(opts.containerName || 'app').trim() || 'app';
  const events = Array.isArray(opts.events) ? opts.events : [];
  const persist = opts.persist !== undefined ? Boolean(opts.persist) : true;
  const inspectedAt = new Date().toISOString();

  /** @type {RuntimeAnomalyAlert[]} */
  const alerts = [];

  for (let i = 0; i < events.length; i++) {
    const norm = normalizeEvent(events[i]);
    const matches = matchEventRules(norm);
    for (const m of matches) {
      const rule = RULE_BY_ID[m.ruleId];
      if (!rule) continue;
      alerts.push({
        id: `anom_${crypto.randomBytes(6).toString('hex')}`,
        projectId,
        containerName,
        ruleId: rule.id,
        severity: rule.severity,
        title: rule.title,
        evidence: m.evidence,
        eventIndex: i,
        detectedAt: inspectedAt
      });
    }
  }

  const criticalCount = alerts.filter((a) => a.severity === 'critical').length;
  const highCount = alerts.filter((a) => a.severity === 'high').length;
  const mediumCount = alerts.filter((a) => a.severity === 'medium').length;
  const riskScore = Math.min(100, (criticalCount * 35) + (highCount * 20) + (mediumCount * 10));
  const clean = alerts.length === 0;

  let recommendedAction = 'NONE';
  if (criticalCount > 0) recommendedAction = 'KILL_AND_QUARANTINE_IMMEDIATELY';
  else if (highCount > 0) recommendedAction = 'ISOLATE_CONTAINER';
  else if (mediumCount > 0) recommendedAction = 'MONITOR_AND_AUDIT';

  if (persist && alerts.length > 0) {
    const store = loadStore();
    store.alerts.push(...alerts);
    if (store.alerts.length > MAX_PERSISTED_ALERTS) {
      store.alerts = store.alerts.slice(-MAX_PERSISTED_ALERTS);
    }
    store.updatedAt = inspectedAt;
    atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
  }

  return {
    ok: true,
    projectId,
    containerName,
    clean,
    riskScore,
    criticalCount,
    highCount,
    alerts,
    recommendedAction,
    inspectedAt
  };
}

/**
 * Lista las alertas runtime almacenadas (opcionalmente filtradas por `projectId`, más recientes primero).
 * @param {string} [projectId]
 * @returns {RuntimeAnomalyAlert[]}
 */
function listAnomalies(projectId) {
  const store = loadStore();
  const cleanId = projectId ? String(projectId).trim() : '';
  const list = cleanId
    ? store.alerts.filter((a) => a.projectId === cleanId)
    : store.alerts;
  return [...list].reverse();
}

module.exports = {
  ANOMALY_RULES,
  inspectRuntimeEvents,
  listAnomalies
};
