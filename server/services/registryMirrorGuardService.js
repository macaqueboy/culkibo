const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Container Registry Pull-Limit & Pull-Through Mirror Guard (100% Zero-Dep).
 *
 * Previene bloqueos `429 TOOMANYREQUESTS` de Docker Hub (10 pulls/h anónimos por IPv4,
 * 100+/6h autenticados) y amplificación por despliegues multi-arquitectura en VPS
 * Coolify/Dokploy/Kamal o NAT compartido:
 *  - Calcula tasa efectiva (`effectivePullsPerHour = pullsPerHour * archCount`).
 *  - Detecta `ANONYMOUS_HUB_RATE_LIMIT_RISK`, `SHARED_NAT_QUOTA_EXHAUSTION`,
 *    `MISSING_REGISTRY_MIRROR` y `PLAINTEXT_DOCKER_CONFIG_AUTH`.
 *  - Emite `/etc/docker/daemon.json` endurecido con `registry-mirrors` (`registry:3` /
 *    Culkibo DirectPush) y planificación jittered de pulls (`dryRun: true` por defecto).
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/registry-mirror-guard.json`.
 */

const MAX_AUDITS = 200;
const DOCKER_HUB_HOSTS = new Set([
  'docker.io',
  'index.docker.io',
  'registry-1.docker.io',
  'hub.docker.com',
  'dockerhub'
]);
const DEFAULT_MIRROR_URLS = ['http://127.0.0.1:5000', 'https://mirror.gcr.io'];

/**
 * Resuelve dinámicamente la ruta a `registry-mirror-guard.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'registry-mirror-guard.json')
    : path.join(base, 'data', 'registry-mirror-guard.json');
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
 * Carga auditorías almacenadas desde disco (sin mutar si no existe).
 * @returns {{ schemaVersion: number, updatedAt: string, audits: any[] }}
 */
function loadStore() {
  const p = resolveStorePath();
  if (!fs.existsSync(p)) {
    return { schemaVersion: 1, updatedAt: new Date().toISOString(), audits: [] };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (parsed && Array.isArray(parsed.audits)) {
      return parsed;
    }
  } catch (e) {}
  return { schemaVersion: 1, updatedAt: new Date().toISOString(), audits: [] };
}

/**
 * Guarda auditorías de forma atómica (`0o600`).
 * @param {{ schemaVersion: number, updatedAt: string, audits: any[] }} store
 */
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  if (store.audits.length > MAX_AUDITS) {
    store.audits = store.audits.slice(-MAX_AUDITS);
  }
  atomicWriteFileSync(resolveStorePath(), JSON.stringify(store, null, 2));
}

/**
 * Normaliza y valida URLs de mirrors HTTP/HTTPS.
 * @param {unknown} list
 * @returns {string[]}
 */
function sanitizeMirrorUrls(list) {
  if (!Array.isArray(list)) return [];
  /** @type {string[]} */
  const out = [];
  const seen = new Set();
  for (const item of list) {
    const raw = String(item || '').trim();
    if (!raw) continue;
    try {
      const parsed = new URL(raw);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') continue;
      // Strip embedded userinfo if accidentally passed
      parsed.username = '';
      parsed.password = '';
      const clean = parsed.toString().replace(/\/$/, '');
      if (!seen.has(clean)) {
        seen.add(clean);
        out.push(clean);
      }
    } catch (e) {}
  }
  return out;
}

/**
 * Genera configuración endurecida de `/etc/docker/daemon.json` con `registry-mirrors`
 * (`registry:3` / Culkibo DirectPush) y ventana jittered para escalonar pulls.
 * `dryRun: true` por defecto.
 *
 * @param {{
 *   mirrorUrls?: string[],
 *   mirrors?: string[],
 *   maxConcurrentDownloads?: number,
 *   maxConcurrentUploads?: number,
 *   nodeId?: string,
 *   dryRun?: boolean
 * }} [input]
 */
function renderDaemonMirrorConfig(input = {}) {
  const opts = input || {};
  const dryRun = opts.dryRun !== undefined ? Boolean(opts.dryRun) : true;
  const rawList = Array.isArray(opts.mirrorUrls) && opts.mirrorUrls.length > 0
    ? opts.mirrorUrls
    : (Array.isArray(opts.mirrors) ? opts.mirrors : []);
  const sanitized = sanitizeMirrorUrls(rawList);
  const mirrorUrls = sanitized.length > 0 ? sanitized : [...DEFAULT_MIRROR_URLS];
  const maxConcurrentDownloads = Math.max(1, Math.min(10, Math.floor(Number(opts.maxConcurrentDownloads ?? 3) || 3)));
  const maxConcurrentUploads = Math.max(1, Math.min(10, Math.floor(Number(opts.maxConcurrentUploads ?? 3) || 3)));
  const nodeId = opts.nodeId ? String(opts.nodeId).trim() : 'node-default';

  // Deterministic deploy jitter (15..90s) derived from nodeId + mirror set
  const hashVal = crypto
    .createHash('sha256')
    .update(`${nodeId}:${mirrorUrls.join(',')}`, 'utf8')
    .digest()
    .readUInt32BE(0);
  const pullScheduleJitterSec = 15 + (hashVal % 76);

  const daemonConfig = {
    'registry-mirrors': mirrorUrls,
    'max-concurrent-downloads': maxConcurrentDownloads,
    'max-concurrent-uploads': maxConcurrentUploads,
    features: {
      buildkit: true
    }
  };
  const daemonJsonText = JSON.stringify(daemonConfig, null, 2);

  return {
    ok: true,
    dryRun,
    targetPath: '/etc/docker/daemon.json',
    nodeId,
    mirrorUrls,
    maxConcurrentDownloads,
    maxConcurrentUploads,
    pullScheduleJitterSec,
    daemonConfig,
    daemonJsonText,
    renderedAt: new Date().toISOString()
  };
}

/**
 * Audita el presupuesto de pulls de registros OCI/Docker Hub en un nodo VPS y detecta
 * riesgos de `429 TOOMANYREQUESTS`, NAT compartido, ausencia de mirror y auth en texto plano.
 *
 * @param {{
 *   nodeId?: string,
 *   registry?: string,
 *   authenticated?: boolean,
 *   pullsPerHour?: number,
 *   archCount?: number,
 *   sharedNatIp?: boolean,
 *   mirrors?: string[],
 *   plaintextConfigAuth?: boolean,
 *   maxConcurrentDownloads?: number,
 *   persist?: boolean
 * }} [input]
 */
function auditRegistryPullBudget(input = {}) {
  const opts = input || {};
  const nodeId = opts.nodeId ? String(opts.nodeId).trim() : null;
  const registry = String(opts.registry || 'docker.io').trim().toLowerCase() || 'docker.io';
  const isDockerHub = DOCKER_HUB_HOSTS.has(registry);
  const authenticated = Boolean(opts.authenticated);
  const pullsPerHour = Math.max(0, Number(opts.pullsPerHour) || 0);
  const archCount = Math.max(1, Math.floor(Number(opts.archCount ?? 1) || 1));
  const effectivePullsPerHour = Math.round(pullsPerHour * archCount * 100) / 100;
  const sharedNatIp = Boolean(opts.sharedNatIp);
  const mirrors = sanitizeMirrorUrls(opts.mirrors);
  const plaintextConfigAuth = Boolean(opts.plaintextConfigAuth);

  // Docker Hub limits: 10 pulls/hr anonymous per IPv4, ~100+/6h (~17/hr sustained) authenticated free, higher for GHCR
  const hourlyQuotaLimit = isDockerHub ? (authenticated ? 100 : 10) : (authenticated ? 500 : 60);
  const utilizationPct = hourlyQuotaLimit > 0
    ? Math.round((effectivePullsPerHour / hourlyQuotaLimit) * 1000) / 10
    : 0;

  /** @type {Array<{ code: string, severity: 'critical' | 'high' | 'medium', message: string, fix: string }>} */
  const findings = [];

  // 1. Anonymous Docker Hub rate-limit exhaustion (10/hr IPv4 cap)
  if (isDockerHub && !authenticated && (effectivePullsPerHour >= 8 || opts.pullsPerHour === undefined)) {
    findings.push({
      code: 'ANONYMOUS_HUB_RATE_LIMIT_RISK',
      severity: 'critical',
      message: `Unauthenticated "${registry}" pulls (${effectivePullsPerHour}/hr across ${archCount} arch(es)) risk hitting Docker Hub 10/hr anonymous 429 TOOMANYREQUESTS limit.`,
      fix: 'Authenticate Docker daemon with a scoped registry token (via credsStore) and route pulls through a local registry:3 pull-through mirror.'
    });
  }

  // 2. Shared NAT / egress IP pool exhaustion
  if (sharedNatIp && (!authenticated || mirrors.length === 0 || effectivePullsPerHour >= hourlyQuotaLimit * 0.5)) {
    findings.push({
      code: 'SHARED_NAT_QUOTA_EXHAUSTION',
      severity: 'critical',
      message: `Node shares an egress NAT IP with other tenants while pulling from "${registry}" (${effectivePullsPerHour}/hr) — neighbor traffic can instantaneously exhaust IP-keyed 429 quotas.`,
      fix: 'Configure authenticated pulls and deploy a local pull-through cache (registry:3) or Culkibo DirectPush mirror.'
    });
  }

  // 3. Missing pull-through registry mirror
  if (mirrors.length === 0) {
    findings.push({
      code: 'MISSING_REGISTRY_MIRROR',
      severity: 'high',
      message: `No pull-through registry mirrors configured in /etc/docker/daemon.json for "${registry}" — every container recreate hits upstream rate limits.`,
      fix: 'Add local registry:3 / mirror.gcr.io entries under `registry-mirrors` in /etc/docker/daemon.json.'
    });
  }

  // 4. Plaintext base64 auth in ~/.docker/config.json
  if (plaintextConfigAuth) {
    findings.push({
      code: 'PLAINTEXT_DOCKER_CONFIG_AUTH',
      severity: 'critical',
      message: 'Docker registry credentials are stored as unencrypted base64 in ~/.docker/config.json instead of an OS credential helper (`credsStore`).',
      fix: 'Configure `credsStore` (pass/secretservice/osxkeychain) or short-lived scoped tokens and purge plaintext `auth` fields from config.json.'
    });
  }

  const rendered = renderDaemonMirrorConfig({
    mirrorUrls: mirrors.length > 0 ? mirrors : DEFAULT_MIRROR_URLS,
    maxConcurrentDownloads: opts.maxConcurrentDownloads,
    nodeId: nodeId || 'node-default',
    dryRun: true
  });

  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const safe = findings.length === 0;
  const blocked = criticalCount > 0 || findings.some((f) => f.severity === 'high');
  const status = criticalCount > 0 ? 'CRITICAL' : (findings.length > 0 ? 'WARNING' : 'HEALTHY');
  const auditedAt = new Date().toISOString();

  const result = {
    ok: true,
    id: `reg_${crypto.randomBytes(5).toString('hex')}`,
    nodeId,
    registry,
    authenticated,
    pullsPerHour,
    archCount,
    effectivePullsPerHour,
    hourlyQuotaLimit,
    utilizationPct,
    sharedNatIp,
    mirrors,
    plaintextConfigAuth,
    safe,
    blocked,
    status,
    findings,
    findingCodes: findings.map((f) => f.code),
    daemonConfig: rendered.daemonConfig,
    daemonJsonText: rendered.daemonJsonText,
    pullScheduleJitterSec: rendered.pullScheduleJitterSec,
    auditedAt
  };

  if (opts.persist !== false) {
    const store = loadStore();
    store.audits.push({
      id: result.id,
      nodeId,
      registry,
      authenticated,
      effectivePullsPerHour,
      safe,
      status,
      findingCodes: result.findingCodes,
      auditedAt
    });
    saveStore(store);
  }

  return result;
}

/**
 * Lista auditorías de cuotas/mirrors de registro (más recientes primero).
 * @param {string} [nodeId]
 */
function listRegistryMirrorAudits(nodeId) {
  const store = loadStore();
  const cleanId = nodeId ? String(nodeId).trim() : '';
  const items = cleanId
    ? store.audits.filter((a) => a.nodeId === cleanId)
    : store.audits;
  return [...items].reverse();
}

module.exports = {
  auditRegistryPullBudget,
  renderDaemonMirrorConfig,
  listRegistryMirrorAudits
};
