const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Valkey / Redis Persistence, Eviction & Hot-Key Telemetry Guard (100% Zero-Dep).
 *
 * Previene caídas clásicas de Valkey 8/9 y Redis en VPS de producción:
 *  - `BGSAVE_FORK_OOM_RISK`: `vm.overcommit_memory !== 1` bloquea `fork()` y detiene escrituras.
 *  - `THP_COW_AMPLIFICATION`: Transparent Huge Pages (`always`/`madvise`) multiplica picos CoW.
 *  - `INSUFFICIENT_FORK_HEADROOM`: `maxmemoryMb > hostRamMb * 0.75` sin margen >=25% para CoW.
 *  - `QUEUE_SILENT_JOB_EVICTION`: `workload === 'queue'` con política distinta de `noeviction`
 *    desaloja silenciosamente trabajos BullMQ/Sidekiq.
 *  - `CACHE_OOM_OUTAGE`: `workload === 'cache'` con `noeviction` tumba escrituras con OOM.
 *  - `NO_TTL_KEY_BLOAT` (`noTtlPct > 40%`) y `HOT_KEY_SKEW` (`topKeyTrafficPct > 20%`).
 *
 * Persistencia atómica `0o600` en `CULKIBO_DATA_DIR/data/valkey-guard.json`.
 */

const MAX_AUDITS = 200;

/**
 * Resuelve dinámicamente la ruta a `valkey-guard.json`.
 */
function resolveStorePath() {
  const base = process.env.CULKIBO_DATA_DIR
    ? path.resolve(process.env.CULKIBO_DATA_DIR)
    : path.resolve(__dirname, '..', '..');
  return path.basename(base).toLowerCase() === 'data'
    ? path.join(base, 'valkey-guard.json')
    : path.join(base, 'data', 'valkey-guard.json');
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
 * Carga auditorías desde disco (sin mutar si no existe).
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
 * Genera bloques `valkey.conf` y `sysctl` endurecidos para el perfil de carga indicado (`dryRun: true` por defecto).
 *
 * @param {{
 *   workload?: 'queue' | 'cache' | 'session' | string,
 *   hostRamMb?: number,
 *   appendonly?: boolean,
 *   dryRun?: boolean
 * }} [options]
 */
function renderHardenedValkeyConfig(options = {}) {
  const opts = options || {};
  const workload = String(opts.workload || 'cache').trim().toLowerCase();
  const hostRamMb = Math.max(64, Math.floor(Number(opts.hostRamMb) || 1024));
  const recommendedMaxmemoryMb = Math.max(32, Math.floor(hostRamMb * 0.7));
  const recommendedEvictionPolicy = workload === 'queue' ? 'noeviction' : 'allkeys-lfu';
  const appendonly = opts.appendonly !== undefined ? Boolean(opts.appendonly) : (workload === 'queue');
  const dryRun = opts.dryRun !== undefined ? Boolean(opts.dryRun) : true;

  const valkeyConf = [
    `# Culkibo Hardened Valkey 8/9 Configuration (workload: ${workload})`,
    `maxmemory ${recommendedMaxmemoryMb}mb`,
    `maxmemory-policy ${recommendedEvictionPolicy}`,
    `appendonly ${appendonly ? 'yes' : 'no'}`,
    appendonly ? 'appendfsync everysec' : 'save 300 100',
    'aof-use-rdb-preamble yes',
    'stop-writes-on-bgsave-error yes',
    'lazyfree-lazy-eviction yes',
    'lazyfree-lazy-expire yes',
    'activedefrag yes'
  ].join('\n');

  const sysctlSnippet = [
    '# /etc/sysctl.d/99-culkibo-valkey.conf',
    'vm.overcommit_memory = 1',
    'net.core.somaxconn = 1024',
    '# Disable Transparent Huge Pages (THP) to prevent BGSAVE CoW RAM doubling:',
    '# echo never > /sys/kernel/mm/transparent_hugepage/enabled'
  ].join('\n');

  return {
    ok: true,
    dryRun,
    workload,
    hostRamMb,
    recommendedMaxmemoryMb,
    recommendedEvictionPolicy,
    appendonly,
    valkeyConf,
    sysctlSnippet
  };
}

/**
 * Audita configuración Valkey/Redis, parámetros de kernel y telemetría de claves calientes/TTL.
 *
 * @param {{
 *   projectId?: string,
 *   workload?: 'queue' | 'cache' | 'session' | string,
 *   hostRamMb?: number,
 *   maxmemoryMb?: number,
 *   evictionPolicy?: string,
 *   overcommitMemory?: number,
 *   thpEnabled?: string,
 *   appendonly?: boolean,
 *   noTtlPct?: number,
 *   topKeyTrafficPct?: number,
 *   persist?: boolean
 * }} [input]
 */
function auditValkeyConfig(input = {}) {
  const opts = input || {};
  const projectId = opts.projectId ? String(opts.projectId).trim() : null;
  const workload = String(opts.workload || 'cache').trim().toLowerCase();
  const hostRamMb = Math.max(64, Number(opts.hostRamMb) || 1024);
  const maxmemoryMb = Math.max(0, Number(opts.maxmemoryMb ?? Math.floor(hostRamMb * 0.7)));
  const evictionPolicy = String(opts.evictionPolicy || (workload === 'queue' ? 'noeviction' : 'allkeys-lfu')).trim().toLowerCase();
  const overcommitMemory = opts.overcommitMemory !== undefined ? Number(opts.overcommitMemory) : 1;
  const thpEnabled = String(opts.thpEnabled || 'never').trim().toLowerCase();
  const appendonly = opts.appendonly !== undefined ? Boolean(opts.appendonly) : (workload === 'queue');
  const noTtlPct = Math.max(0, Math.min(100, Number(opts.noTtlPct) || 0));
  const topKeyTrafficPct = Math.max(0, Math.min(100, Number(opts.topKeyTrafficPct) || 0));

  /** @type {Array<{ code: string, severity: 'critical' | 'high' | 'medium', message: string, fix: string }>} */
  const findings = [];

  // 1. vm.overcommit_memory=0 -> BGSAVE fork OOM halt
  if (overcommitMemory !== 1) {
    findings.push({
      code: 'BGSAVE_FORK_OOM_RISK',
      severity: 'critical',
      message: `Kernel vm.overcommit_memory=${overcommitMemory} (must be 1) — BGSAVE/AOF fork() can fail under low free RAM and halt all Valkey writes.`,
      fix: 'Set vm.overcommit_memory = 1 in /etc/sysctl.d/99-culkibo-valkey.conf and apply sysctl --system.'
    });
  }

  // 2. Transparent Huge Pages CoW amplification
  if (thpEnabled !== 'never') {
    findings.push({
      code: 'THP_COW_AMPLIFICATION',
      severity: 'high',
      message: `Transparent Huge Pages is "${thpEnabled}" (must be "never") — 2 MiB THP pages amplify BGSAVE copy-on-write memory spikes up to 2x.`,
      fix: 'Disable THP at boot: echo never > /sys/kernel/mm/transparent_hugepage/enabled.'
    });
  }

  // 3. Fork CoW RAM headroom (<25% reserve)
  const maxSafeMb = Math.floor(hostRamMb * 0.75);
  if (maxmemoryMb > maxSafeMb) {
    findings.push({
      code: 'INSUFFICIENT_FORK_HEADROOM',
      severity: 'critical',
      message: `maxmemory (${maxmemoryMb} MB) exceeds 75% of host RAM (${maxSafeMb} MB / ${hostRamMb} MB) leaving insufficient CoW headroom during BGSAVE.`,
      fix: `Lower maxmemory to <= ${Math.floor(hostRamMb * 0.7)} MB or upgrade host RAM.`
    });
  }

  // 4. Queue vs Cache eviction mismatch
  if (workload === 'queue' && evictionPolicy !== 'noeviction') {
    findings.push({
      code: 'QUEUE_SILENT_JOB_EVICTION',
      severity: 'critical',
      message: `Queue workload uses evictionPolicy="${evictionPolicy}" — Valkey will silently evict queued BullMQ/Sidekiq jobs under memory pressure!`,
      fix: 'Switch queue instances to maxmemory-policy noeviction with appendonly yes and isolate caches onto a separate Valkey instance.'
    });
  } else if (workload === 'cache' && evictionPolicy === 'noeviction') {
    findings.push({
      code: 'CACHE_OOM_OUTAGE',
      severity: 'high',
      message: 'Cache workload uses evictionPolicy="noeviction" — filling maxmemory will reject all SET writes with OOM errors.',
      fix: 'Set maxmemory-policy allkeys-lfu (or volatile-lru) on cache instances.'
    });
  }

  // 5. Missing TTL bloat
  if (workload !== 'queue' && noTtlPct > 40) {
    findings.push({
      code: 'NO_TTL_KEY_BLOAT',
      severity: 'medium',
      message: `${noTtlPct}% of cache keys have no TTL (> 40% threshold), causing unbounded memory bloat.`,
      fix: 'Set explicit EX/PX TTLs on cache writes and audit unbounded session/token prefixes.'
    });
  }

  // 6. Hot-key traffic skew
  if (topKeyTrafficPct > 20) {
    findings.push({
      code: 'HOT_KEY_SKEW',
      severity: 'medium',
      message: `Single hot key accounts for ${topKeyTrafficPct}% of total Valkey traffic (> 20%), risking single-thread latency spikes.`,
      fix: 'Add short-lived in-process L1 caching or shard the hot key across N buckets.'
    });
  }

  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const safe = findings.length === 0;
  const blocked = !safe;
  const status = criticalCount > 0 ? 'CRITICAL' : (findings.length > 0 ? 'WARNING' : 'HEALTHY');
  const rendered = renderHardenedValkeyConfig({ workload, hostRamMb, appendonly, dryRun: true });
  const auditedAt = new Date().toISOString();

  const result = {
    ok: true,
    id: `vk_${crypto.randomBytes(5).toString('hex')}`,
    projectId,
    workload,
    safe,
    blocked,
    status,
    findings,
    findingCodes: findings.map((f) => f.code),
    recommendedMaxmemoryMb: rendered.recommendedMaxmemoryMb,
    recommendedEvictionPolicy: rendered.recommendedEvictionPolicy,
    valkeyConf: rendered.valkeyConf,
    sysctlSnippet: rendered.sysctlSnippet,
    auditedAt
  };

  if (opts.persist !== false && projectId) {
    const store = loadStore();
    store.audits.push({
      id: result.id,
      projectId,
      workload,
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
 * Lista auditorías Valkey/Redis almacenadas (más recientes primero).
 * @param {string} [projectId]
 */
function listValkeyAudits(projectId) {
  const store = loadStore();
  const cleanId = projectId ? String(projectId).trim() : '';
  const items = cleanId
    ? store.audits.filter((a) => a.projectId === cleanId)
    : store.audits;
  return [...items].reverse();
}

module.exports = {
  auditValkeyConfig,
  renderHardenedValkeyConfig,
  listValkeyAudits
};
