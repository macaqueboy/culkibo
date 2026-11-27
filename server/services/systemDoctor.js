const fs = require('fs');
const os = require('os');
const path = require('path');

const metricsCollector = require('./metricsCollector');
const { readHostMemoryStats } = require('./metricsHistory');

/**
 * Diagnóstico real en 1 clic del estado del sistema (`systemDoctor`).
 * Sin números inventados ni dependencias externas: ejecuta comprobaciones
 * verificables sobre Node, Docker, Caddy, disco, memoria, seguridad, TLS,
 * contenedores huérfanos, bases de datos y archivos temporales.
 */

const ROOT_BASE_DIR = process.env.CULKIBO_DATA_DIR
  ? path.resolve(process.env.CULKIBO_DATA_DIR)
  : path.resolve(__dirname, '..', '..');
const DATA_DIR = path.join(ROOT_BASE_DIR, 'data');
const TMP_DIR = path.join(DATA_DIR, '.tmp');
const LEGACY_TMP_DIR = path.join(DATA_DIR, 'tmp');
const SAFE_TMP_AGE_MS = 3600 * 1000;

function checkDiskSpace() {
  try {
    if (typeof fs.statfsSync === 'function') {
      const st = fs.statfsSync(DATA_DIR);
      const totalGb = Number(((st.blocks * st.bsize) / (1024 ** 3)).toFixed(1));
      const freeGb = Number(((st.bavail * st.bsize) / (1024 ** 3)).toFixed(1));
      const usedPct = totalGb > 0 ? Math.round(((totalGb - freeGb) / totalGb) * 100) : 0;
      /** @type {'ok' | 'warn' | 'fail'} */
      const status = (freeGb < 2 || usedPct >= 92) ? 'fail' : (freeGb < 5 || usedPct >= 82) ? 'warn' : 'ok';
      return {
        id: 'disk_memory',
        name: 'Espacio en disco',
        status,
        summary: `Disco libre: ${freeGb} GB de ${totalGb} GB (${usedPct}% usado)`,
        detail: status === 'ok'
          ? 'Margen suficiente para imágenes Docker, copias de seguridad y cachés de BuildKit.'
          : 'Poco espacio libre en disco. Puedes limpiar cachés de BuildKit y archivos temporales con un clic.',
        fixAction: status !== 'ok' ? 'prune_buildkit' : null,
        fixLabel: status !== 'ok' ? 'Limpiar caché BuildKit' : null,
        metrics: { freeGb, totalGb, usedPct }
      };
    }
  } catch (e) {}

  return {
    id: 'disk_memory',
    name: 'Espacio en disco',
    status: /** @type {'ok'} */ ('ok'),
    summary: 'Estadística de disco no disponible en este runtime',
    detail: 'Comprueba el espacio libre con df -h en tu servidor.',
    fixAction: null,
    fixLabel: null
  };
}

function checkHostMemory(snap, readProcMeminfo = null) {
  const mem = readHostMemoryStats(readProcMeminfo);
  const totalMb = mem.totalMb;
  const freeMb = mem.availableMb;
  const freePct = Math.round(mem.availablePct);
  const usedPct = Math.round(mem.usedPct);
  /** @type {'ok' | 'warn' | 'fail'} */
  const status = (freeMb < 128 || freePct < 6 || (mem.swapTotalMb > 0 && mem.swapUsedPct >= 85))
    ? 'fail'
    : (freeMb < 384 || freePct < 12 || (mem.swapTotalMb > 0 && mem.swapUsedPct >= 50))
      ? 'warn'
      : 'ok';
  const swapSuffix = mem.swapTotalMb > 0 ? ` · Swap ${mem.swapUsedPct}%` : '';
  return {
    id: 'host_memory',
    name: 'Memoria RAM del servidor',
    status,
    summary: `RAM disponible: ${freeMb} MB de ${totalMb} MB (${freePct}% libre${swapSuffix}) · Daemon ${snap.process.memoryMb} MB RSS`,
    detail: status === 'ok'
      ? 'Memoria disponible real suficiente (MemAvailable en Linux, excluye caché recuperable) para contenedores y builds.'
      : 'Memoria RAM ajustada. Limita despliegues simultáneos con CULKIBO_MAX_CONCURRENT_BUILDS=1, activa Auto-Sleep o añade swap.',
    fixAction: null,
    fixLabel: null,
    metrics: {
      freeMb,
      availableMb: mem.availableMb,
      usedMb: mem.usedMb,
      totalMb,
      freePct,
      usedPct,
      swapTotalMb: mem.swapTotalMb,
      swapUsedPct: mem.swapUsedPct,
      source: mem.source,
      rssMb: snap.process.memoryMb
    }
  };
}

/**
 * Auditoría anti-bypass UFW de Docker (`kamal#1856`):
 * Docker inyecta reglas `iptables` DNAT antes de `INPUT`, saltándose UFW cuando una BD se enlaza a `0.0.0.0`.
 * Marca cualquier base de datos gestionada expuesta en `0.0.0.0` / `publicExpose: true` con severidad `high`
 * y código `UFW_DOCKER_BYPASS_RISK`, recomendando WireGuard Fleet Mesh (`10.88.0.0/24`) o `127.0.0.1`.
 *
 * @param {Array<any>} databases
 */
function auditExposedDatabases(databases = []) {
  const list = Array.isArray(databases) ? databases : [];
  /** @type {Array<{ databaseId: string, name: string, engine: string, bindAddress: string, hostPort: number | null, severity: 'high', code: 'UFW_DOCKER_BYPASS_RISK', recommendation: string }>} */
  const findings = [];
  for (const db of list) {
    if (!db || typeof db !== 'object') continue;
    const exp = db.exposure && typeof db.exposure === 'object' ? db.exposure : null;
    const bindRaw = String((exp && exp.bindAddress) || db.bindAddress || '127.0.0.1').trim();
    const isWildcardBind = bindRaw === '0.0.0.0' || bindRaw === '::' || bindRaw === '*';
    const isExternalExposure = Boolean(
      db.publicExpose === true ||
      isWildcardBind ||
      (exp && exp.enabled && bindRaw !== '127.0.0.1' && bindRaw !== '::1' && bindRaw !== 'localhost')
    );
    if (!isExternalExposure) continue;
    findings.push({
      databaseId: String(db.id || db.name || 'unknown'),
      name: String(db.name || db.id || 'database'),
      engine: String(db.engine || 'unknown'),
      bindAddress: isWildcardBind ? bindRaw : (db.publicExpose ? '0.0.0.0' : bindRaw),
      hostPort: exp && exp.hostPort != null ? Number(exp.hostPort) : (db.hostPort != null ? Number(db.hostPort) : null),
      severity: 'high',
      code: 'UFW_DOCKER_BYPASS_RISK',
      recommendation: 'Bind managed databases to 127.0.0.1 or route cross-node DB traffic through Culkibo WireGuard Fleet Mesh (10.88.0.0/24) instead of 0.0.0.0 (Docker iptables bypasses UFW).'
    });
  }
  return {
    safe: findings.length === 0,
    exposedCount: findings.length,
    findings
  };
}

function checkKeyFilePermissions() {
  if (process.platform === 'win32') return { ok: true, issues: [] };
  /** @type {string[]} */
  const issues = [];
  const sensitiveFiles = [
    'auth.json',
    '.databases.key',
    '.services.key',
    '.fleet.key',
    'fleet-keys.json',
    '.vault.key',
    '.rbac.key',
    '.teams.key',
    'teams.json',
    'advisor.json',
    'deploy-freeze.json'
  ];
  for (const name of sensitiveFiles) {
    const filePath = path.join(DATA_DIR, name);
    try {
      if (!fs.existsSync(filePath)) continue;
      const st = fs.statSync(filePath);
      if ((st.mode & 0o077) !== 0) {
        issues.push(`${name} (${(st.mode & 0o777).toString(8)})`);
      }
    } catch (e) {}
  }
  return { ok: issues.length === 0, issues };
}

/**
 * Estima el tramo VPS europeo de referencia según RAM total del host (sin dependencias).
 * @param {number} totalMb
 */
function estimateVpsTierEur(totalMb) {
  const tiers = [
    { ramGb: 2, eur: 3.79 },
    { ramGb: 4, eur: 4.59 },
    { ramGb: 8, eur: 7.59 },
    { ramGb: 16, eur: 13.99 },
    { ramGb: 32, eur: 26.99 }
  ];
  const gb = totalMb / 1024;
  return tiers.find((t) => gb <= t.ramGb + 0.5) || tiers[tiers.length - 1];
}

/** Lee `/proc/meminfo` en Linux (degrada limpiamente en Windows/macOS). */
function readLinuxMemInfo() {
  if (process.platform !== 'linux') return null;
  try {
    const raw = fs.readFileSync('/proc/meminfo', 'utf8');
    /** @type {Record<string, number>} */
    const map = {};
    for (const line of raw.split(/\r?\n/)) {
      const m = line.match(/^([A-Za-z0-9_()]+):\s+(\d+)\s+kB/);
      if (m) map[m[1]] = Math.round(Number(m[2]) / 1024);
    }
    if (!map.MemTotal) return null;
    const swapTotalMb = map.SwapTotal || 0;
    const swapFreeMb = map.SwapFree || 0;
    const swapUsedMb = Math.max(0, swapTotalMb - swapFreeMb);
    const swapUsedPct = swapTotalMb > 0 ? Math.round((swapUsedMb / swapTotalMb) * 100) : 0;
    return {
      memTotalMb: map.MemTotal,
      memAvailableMb: map.MemAvailable ?? map.MemFree ?? 0,
      swapTotalMb,
      swapUsedMb,
      swapUsedPct
    };
  } catch (e) {
    return null;
  }
}

/**
 * Comprobación #10: Asesor de costes/RAM del VPS + salud de nodos de flota SSH.
 * Carga de forma perezosa `sleepAdvisor` y `serverFleetManager` con degradación
 * limpia si aún no están disponibles o configurados.
 *
 * @param {{
 *   snap?: any,
 *   sleepAdvisorMod?: any,
 *   fleetManagerMod?: any
 * }} [opts]
 */
async function checkCostAndFleet({ snap = null, sleepAdvisorMod = undefined, fleetManagerMod = undefined } = {}) {
  let advisorMod = sleepAdvisorMod;
  if (advisorMod === undefined) {
    try { advisorMod = require('./sleepAdvisor'); } catch (e) { advisorMod = null; }
  }
  let fleetMod = fleetManagerMod;
  if (fleetMod === undefined) {
    try { fleetMod = require('./serverFleetManager'); } catch (e) { fleetMod = null; }
  }

  /** @type {'ok' | 'warn' | 'fail'} */
  let status = 'ok';
  const summaryParts = [];
  const detailParts = [];
  /** @type {Record<string, any>} */
  const metrics = {};

  // 1. Asesor de costes y RAM del VPS
  let advisorHandled = false;
  /** @type {string | null} */
  let advisorFixAction = null;
  /** @type {string | null} */
  let advisorFixLabel = null;
  if (advisorMod && typeof advisorMod === 'object') {
    try {
      /** @type {any} */
      let adv = null;
      if (typeof advisorMod.getDoctorSummary === 'function') {
        adv = await Promise.resolve(advisorMod.getDoctorSummary());
      } else if (typeof advisorMod.analyzeResources === 'function') {
        adv = await Promise.resolve(advisorMod.analyzeResources());
      }
      if (adv && typeof adv === 'object') {
        advisorHandled = true;
        const advStatus = adv.status === 'fail' ? 'fail' : (adv.status === 'warn' ? 'warn' : 'ok');
        if (advStatus === 'fail') status = 'fail';
        else if (advStatus === 'warn' && status === 'ok') status = 'warn';
        if (typeof adv.fixAction === 'string' && adv.fixAction.trim()) {
          advisorFixAction = adv.fixAction.trim();
          advisorFixLabel = typeof adv.fixLabel === 'string' && adv.fixLabel.trim()
            ? adv.fixLabel.trim()
            : 'Revisar Auto-Sleep';
        }

        const advMetrics = (adv.metrics && typeof adv.metrics === 'object') ? adv.metrics : {};
        const reclaimableMb = Number(advMetrics.reclaimableRamMb ?? adv.reclaimableMb ?? adv.savings?.reclaimableRamMb ?? 0) || 0;
        const savingsEur = Number(advMetrics.monthlySavingsEur ?? adv.estimatedSavingsEurMonth ?? adv.savings?.estimatedMonthlyEur ?? 0) || 0;
        const idleCount = Number(advMetrics.idleCandidatesCount ?? adv.idleCount ?? adv.idleCandidates?.length ?? 0) || 0;
        const oomRiskCount = Number(advMetrics.oomRiskCount ?? adv.oomRiskCount ?? adv.oomRisks?.length ?? 0) || 0;

        metrics.advisor = {
          source: 'sleepAdvisor',
          reclaimableMb,
          estimatedSavingsEurMonth: Number(savingsEur.toFixed(2)),
          idleCount,
          oomRiskCount
        };

        if (typeof adv.summary === 'string' && adv.summary.trim()) {
          summaryParts.push(adv.summary.trim());
        } else if (oomRiskCount > 0) {
          summaryParts.push(`${oomRiskCount} servicio(s) en riesgo de OOM`);
        } else if (reclaimableMb > 0 || savingsEur > 0) {
          summaryParts.push(`~${reclaimableMb} MB recuperables (~€${savingsEur.toFixed(2)}/mes)`);
        } else {
          summaryParts.push('Uso de RAM/costes optimizado');
        }

        if (typeof adv.detail === 'string' && adv.detail.trim()) {
          detailParts.push(adv.detail.trim());
        } else if (idleCount > 0) {
          detailParts.push(`${idleCount} servicio(s) inactivos candidatos a Auto-Sleep (Scale-to-Zero).`);
        } else {
          detailParts.push('Sin contenedores inactivos ni sobrecapacidad crítica detectada.');
        }
      }
    } catch (e) {
      advisorHandled = false;
    }
  }

  if (!advisorHandled) {
    const totalMb = Math.round(os.totalmem() / 1024 / 1024);
    const freeMb = Math.round(os.freemem() / 1024 / 1024);
    const linuxMem = readLinuxMemInfo();
    const availMb = linuxMem ? linuxMem.memAvailableMb : freeMb;
    const availPct = totalMb > 0 ? Math.round((availMb / totalMb) * 100) : 100;
    const tier = estimateVpsTierEur(totalMb);
    const rssMb = snap && snap.process && Number.isFinite(snap.process.memoryMb) ? snap.process.memoryMb : Math.round(process.memoryUsage().rss / 1024 / 1024);

    metrics.advisor = {
      source: 'builtin_fallback',
      hostTotalMb: totalMb,
      hostAvailableMb: availMb,
      hostAvailablePct: availPct,
      daemonRssMb: rssMb,
      estimatedTierEurMonth: tier.eur,
      swapSupported: Boolean(linuxMem && linuxMem.swapTotalMb > 0),
      swapUsedPct: linuxMem ? linuxMem.swapUsedPct : null
    };

    if (linuxMem && linuxMem.swapTotalMb > 0 && linuxMem.swapUsedPct >= 85) {
      status = 'fail';
      summaryParts.push(`Presión crítica de swap (${linuxMem.swapUsedPct}%) · VPS ~€${tier.eur.toFixed(2)}/mes`);
      detailParts.push('El host está usando más del 85% del swap. Reduce límites de memoria o activa Auto-Sleep en servicios secundarios.');
    } else if ((linuxMem && linuxMem.swapTotalMb > 0 && linuxMem.swapUsedPct >= 50) || availPct < 15) {
      if (status === 'ok') status = 'warn';
      summaryParts.push(`RAM disponible ajustada (${availPct}%) · VPS ~€${tier.eur.toFixed(2)}/mes`);
      detailParts.push('Considera habilitar Auto-Sleep o ajustar los topes de RAM de los contenedores.');
    } else {
      summaryParts.push(`VPS ~${Math.max(1, Math.round(totalMb / 1024))} GB (~€${tier.eur.toFixed(2)}/mes) · ${availPct}% RAM libre`);
      detailParts.push(`Plano de control en ${rssMb} MB RSS con margen saludable de memoria.`);
    }
  }

  // 2. Salud de nodos de flota SSH (`serverFleetManager`)
  if (fleetMod && typeof fleetMod.listServers === 'function') {
    try {
      const allServers = fleetMod.listServers();
      const remotes = Array.isArray(allServers) ? allServers.filter((s) => s && s.id && s.id !== 'local') : [];
      if (remotes.length > 0) {
        let online = 0;
        let degraded = 0;
        let offline = 0;
        let hostKeyMismatch = 0;
        const problemNames = [];
        for (const s of remotes) {
          const st = String(s.status || 'unknown').toLowerCase();
          if (st === 'online') online++;
          else if (st === 'host_key_mismatch') {
            hostKeyMismatch++;
            problemNames.push(`${s.name || s.id} (host_key_mismatch)`);
          } else if (st === 'degraded') {
            degraded++;
            problemNames.push(`${s.name || s.id} (degraded)`);
          } else {
            offline++;
            problemNames.push(`${s.name || s.id} (${st})`);
          }
        }
        metrics.fleet = { totalRemote: remotes.length, online, degraded, offline, hostKeyMismatch };

        if (hostKeyMismatch > 0) {
          status = 'fail';
          summaryParts.push(`Flota: ${hostKeyMismatch} nodo(s) bloqueados por host_key_mismatch`);
          detailParts.push(`Alerta SSH TOFU en: ${problemNames.slice(0, 4).join(', ')}. Verifica la huella y usa repin manual.`);
        } else if (offline > 0 || degraded > 0) {
          if (status === 'ok') status = 'warn';
          summaryParts.push(`Flota: ${online}/${remotes.length} nodos remotos online`);
          detailParts.push(`Nodos con incidencias: ${problemNames.slice(0, 4).join(', ')}.`);
        } else {
          summaryParts.push(`Flota: ${online}/${remotes.length} nodos remotos online`);
          detailParts.push('Todos los nodos remotos SSH responden con Docker operativo.');
        }
      } else {
        metrics.fleet = { totalRemote: 0, online: 0, degraded: 0, offline: 0, hostKeyMismatch: 0 };
        summaryParts.push('Flota: nodo local');
      }
    } catch (e) {
      metrics.fleet = { available: false, error: String(e.message || 'error').slice(0, 120) };
    }
  } else {
    metrics.fleet = { totalRemote: 0, mode: 'local_only' };
  }

  return {
    id: 'cost_ram_advisor',
    name: 'Asesor de costes/RAM y flota VPS',
    status,
    summary: summaryParts.join(' · '),
    detail: detailParts.join(' '),
    fixAction: advisorFixAction,
    fixLabel: advisorFixLabel,
    metrics
  };
}

/**
 * @param {string} dirPath
 * @param {number} cutoffMs
 * @param {string | null} [prefix]
 */
function countStaleFilesInDir(dirPath, cutoffMs, prefix = null) {
  let count = 0;
  try {
    if (!fs.existsSync(dirPath)) return 0;
    for (const f of fs.readdirSync(dirPath)) {
      if (prefix && !f.startsWith(prefix)) continue;
      try {
        const st = fs.statSync(path.join(dirPath, f));
        if (st.mtimeMs < cutoffMs) count++;
      } catch (e) {}
    }
  } catch (e) {}
  return count;
}

/**
 * @param {string} dirPath
 * @param {number} cutoffMs
 * @param {string | null} [prefix]
 */
function removeStaleFilesInDir(dirPath, cutoffMs, prefix = null) {
  let removed = 0;
  try {
    if (!fs.existsSync(dirPath)) return 0;
    for (const f of fs.readdirSync(dirPath)) {
      if (prefix && !f.startsWith(prefix)) continue;
      try {
        const full = path.join(dirPath, f);
        const st = fs.statSync(full);
        if (st.mtimeMs < cutoffMs) {
          fs.rmSync(full, { recursive: true, force: true });
          removed++;
        }
      } catch (e) {}
    }
  } catch (e) {}
  return removed;
}

/** Detecta contenedores `culkibo.managed=true` detenidos que ya no están referenciados por ningún servicio. */
async function listOrphanedManagedContainers() {
  try {
    const deployManager = require('./deployManager');
    const databaseManager = require('./databaseManager');
    const catalogManager = /** @type {any} */ (require('./catalogManager'));
    /** @type {any} */
    let previewManager = null;
    try { previewManager = require('./previewManager'); } catch (e) {}

    const res = await deployManager.runDocker(
      ['ps', '-a', '--filter', 'label=culkibo.managed=true', '--filter', 'status=exited', '--format', '{{.Names}}'],
      { timeoutMs: 8000 }
    );
    if (res.code !== 0) return [];

    /** @type {Set<string>} */
    const known = new Set(['culkibo-caddy', 'culkibo-cloudflared']);
    for (const st of Object.values(deployManager.store || {})) {
      if (st?.current?.containerName) known.add(st.current.containerName);
      if (st?.previous?.containerName) known.add(st.previous.containerName);
    }
    if (deployManager.inFlightContainers) {
      for (const n of deployManager.inFlightContainers) known.add(n);
    }
    if (databaseManager && typeof databaseManager.list === 'function') {
      for (const db of databaseManager.list()) {
        if (db.containerName) known.add(db.containerName);
      }
    }
    const installs = typeof catalogManager.list === 'function'
      ? catalogManager.list()
      : (typeof catalogManager.listInstallations === 'function' ? catalogManager.listInstallations() : []);
    for (const inst of installs) {
      if (inst.containerName) known.add(inst.containerName);
      if (inst.appContainer) known.add(inst.appContainer);
      if (inst.dbContainer) known.add(inst.dbContainer);
      if (Array.isArray(inst.sidecars)) {
        for (const s of inst.sidecars) {
          if (s && s.containerName) known.add(s.containerName);
        }
      }
      if (Array.isArray(inst.containers)) {
        for (const c of inst.containers) {
          if (typeof c === 'string') known.add(c);
          else if (c && (c.containerName || c.name)) known.add(c.containerName || c.name);
        }
      }
    }
    if (previewManager && typeof previewManager.list === 'function') {
      for (const prev of previewManager.list()) {
        if (prev.containerName) known.add(prev.containerName);
      }
    }

    return (res.stdout || '')
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((name) => name && !known.has(name));
  } catch (e) {
    return [];
  }
}

async function runDoctor() {
  const started = Date.now();
  const snap = metricsCollector.getSnapshot(true);

  const dockerManager = require('./dockerManager');
  const caddyManager = require('./caddyManager');
  const ingressManager = require('./ingressManager');
  const domainManager = require('./domainManager');
  const databaseManager = require('./databaseManager');
  const sslManager = require('./sslManager');
  const { authStatus } = require('../middleware/auth');

  /** @type {Array<{ id: string, name: string, status: 'ok' | 'warn' | 'fail', summary: string, detail: string, fixAction: string | null, fixLabel: string | null, metrics?: any }>} */
  const checks = [];

  // 1. Runtime & Event Loop
  const lagP95 = snap.eventLoop.p95Ms ?? 0;
  checks.push({
    id: 'runtime',
    name: 'Motor Node.js y bucle de eventos',
    status: lagP95 > 100 ? 'warn' : 'ok',
    summary: `Node ${process.version} · RAM ${snap.process.memoryMb} MB RSS · Lag p95 ${lagP95} ms`,
    detail: lagP95 > 100
      ? 'El bucle de eventos presenta latencia elevada. Revisa procesos locales intensivos o despliegues simultáneos.'
      : 'Latencia del plano de control y huella de memoria dentro de los márgenes óptimos.',
    fixAction: null,
    fixLabel: null
  });

  // 2. Docker Engine
  let dockerAvail = false;
  let dockerDetail = 'Docker no detectado en el sistema.';
  try {
    const ds = await dockerManager.checkDockerStatus(true);
    dockerAvail = Boolean(ds && ds.available);
    const ver = ds ? (ds.serverVersion || ds.clientVersion || ds.version || '') : '';
    dockerDetail = dockerAvail
      ? `Docker ${ver} activo con soporte de contenedores y BuildKit.`.replace(/\s+/g, ' ')
      : 'Docker no está en marcha. Puedes seguir usando proyectos locales y sincronización en vivo, pero despliegues a producción y catálogo requieren Docker.';
  } catch (e) {
    dockerDetail = e.message || dockerDetail;
  }
  checks.push({
    id: 'docker',
    name: 'Motor de contenedores Docker',
    status: dockerAvail ? 'ok' : 'warn',
    summary: dockerAvail ? 'Docker operativo' : 'Docker no disponible (modo ligero)',
    detail: dockerDetail,
    fixAction: null,
    fixLabel: null
  });

  // 3. Caddy Data Plane & Route Sync
  /** @type {'ok' | 'warn' | 'fail'} */
  let caddyStatus = 'warn';
  let caddySummary = 'Caddy no detectado en :2019';
  let caddyDetail = 'Sin Caddy activo no se sirven dominios públicos ni HTTPS automático. Arranca el plano de datos con un clic o desde Dominios.';
  /** @type {string | null} */
  let caddyFix = dockerAvail ? 'start_caddy' : null;
  /** @type {string | null} */
  let caddyFixLabel = dockerAvail ? 'Arrancar Caddy con Docker' : null;
  try {
    const det = await caddyManager.detect({ force: true });
    if (det && det.available) {
      const ing = await ingressManager.status();
      const driftCount = (ing?.drift?.missing?.length || 0)
        + (ing?.drift?.unexpected?.length || 0)
        + (ing?.drift?.modified?.length || 0);
      if (ing && ing.inSync === false) {
        caddyStatus = 'warn';
        caddySummary = `Caddy activo con deriva de rutas (${driftCount} ${driftCount === 1 ? 'diferencia' : 'diferencias'})`;
        caddyDetail = 'Las rutas publicadas en Caddy difieren del estado esperado en Culkibo.';
        caddyFix = 'reconcile_caddy';
        caddyFixLabel = 'Reconciliar rutas en Caddy';
      } else {
        caddyStatus = 'ok';
        const count = Array.isArray(ing?.routes) ? ing.routes.length : 0;
        caddySummary = `Caddy activo · ${count} ${count === 1 ? 'ruta sincronizada' : 'rutas sincronizadas'}`;
        caddyDetail = 'Plano de datos sincronizado y listo para conmutaciones atómicas y TLS automático.';
        caddyFix = null;
        caddyFixLabel = null;
      }
    }
  } catch (e) {
    caddyDetail = e.message || caddyDetail;
  }
  checks.push({
    id: 'caddy',
    name: 'Proxy inverso Caddy y TLS',
    status: caddyStatus,
    summary: caddySummary,
    detail: caddyDetail,
    fixAction: caddyFix,
    fixLabel: caddyFixLabel
  });

  // 4. Disco y Memoria del host (separados para no ocultar problemas de RAM)
  checks.push(checkDiskSpace());
  checks.push(checkHostMemory(snap));

  // 5. Postura de Seguridad
  const auth = authStatus();
  const bindHost = process.env.CULKIBO_BIND || process.env.HOST || process.env.CULKIBO_HOST || '127.0.0.1';
  const exposedWithoutToken = bindHost === '0.0.0.0' && !auth.requireTokenAlways;
  const allManagedDbs = databaseManager.list ? databaseManager.list() : [];
  const dbExposureAudit = auditExposedDatabases(allManagedDbs);
  const exposedDbs = dbExposureAudit.findings;
  const permCheck = checkKeyFilePermissions();
  /** @type {'ok' | 'warn' | 'fail'} */
  let secStatus = 'ok';
  let secSummary = `Token configurado (${auth.tokenSource}) · Escucha en ${bindHost}`;
  let secDetail = 'Autenticación activa, cabeceras de seguridad HTTP habilitadas y bases de datos aisladas en red privada.';
  if (exposedWithoutToken) {
    secStatus = 'warn';
    secSummary = 'Escuchando en 0.0.0.0 sin CULKIBO_REQUIRE_TOKEN=1';
    secDetail = 'En servidores expuestos a internet, define CULKIBO_REQUIRE_TOKEN=1 o escucha solo en 127.0.0.1 detrás de Caddy.';
  } else if (!permCheck.ok) {
    secStatus = 'warn';
    secSummary = `Permisos demasiado abiertos en ${permCheck.issues.join(', ')}`;
    secDetail = 'Los ficheros de claves deben tener modo 0600 (solo lectura/escritura para el propietario).';
  } else if (exposedDbs.length > 0) {
    secStatus = 'warn';
    secSummary = `${exposedDbs.length} ${exposedDbs.length === 1 ? 'base de datos expuesta' : 'bases de datos expuestas'} fuera de loopback (UFW_DOCKER_BYPASS_RISK)`;
    secDetail = 'Docker iptables omite UFW cuando un puerto escucha en 0.0.0.0. Usa 127.0.0.1 o la malla privada WireGuard Fleet Mesh (10.88.0.0/24).';
  }
  checks.push({
    id: 'security',
    name: 'Postura de seguridad',
    status: secStatus,
    summary: secSummary,
    detail: secDetail,
    fixAction: null,
    fixLabel: null,
    metrics: {
      ufwBypassCount: dbExposureAudit.exposedCount,
      ufwBypassFindings: dbExposureAudit.findings
    }
  });

  // 6. Dominios y caducidad TLS real
  const domains = domainManager.listDomains();
  const wildcardCount = domains.filter((d) => d.isWildcard).length;
  const certs = sslManager && typeof sslManager.listCertificates === 'function' ? sslManager.listCertificates() : [];
  const expiredCerts = certs.filter((c) => c.isExpired);
  const expiringCerts = certs.filter((c) => !c.isExpired && c.isExpiringSoon);
  const lastTlsAudit = /** @type {any} */ (ingressManager)?.lastTlsAudit || null;
  const liveExpiring = (lastTlsAudit && Array.isArray(lastTlsAudit.expiring)) ? lastTlsAudit.expiring : [];
  const liveExpired = (lastTlsAudit && Array.isArray(lastTlsAudit.expired)) ? lastTlsAudit.expired : [];
  /** @type {'ok' | 'warn' | 'fail'} */
  let domStatus = 'ok';
  let domSummary = `${domains.length} ${domains.length === 1 ? 'dominio' : 'dominios'} (${wildcardCount} ${wildcardCount === 1 ? 'comodín' : 'comodines'})`;
  let domDetail = domains.length > 0
    ? 'Usa el diagnóstico de 4 capas en Dominios para auditar DNS, rutas Caddy, comodines y TLS en directo.'
    : 'Añade tu primer dominio o genera un dominio gratuito sslip.io en el asistente de Dominios.';
  if (expiredCerts.length > 0 || liveExpired.length > 0) {
    domStatus = 'fail';
    const names = [...expiredCerts.map((c) => c.domain), ...liveExpired.map((c) => c.hostname)];
    domSummary = `${names.length} certificado(s) TLS caducado(s): ${names.slice(0, 3).join(', ')}`;
    domDetail = 'Renueva o sube un nuevo certificado PEM desde la pestaña Dominios para evitar avisos HTTPS en el navegador.';
  } else if (expiringCerts.length > 0 || liveExpiring.length > 0) {
    domStatus = 'warn';
    const names = [...expiringCerts.map((c) => c.domain), ...liveExpiring.map((c) => c.hostname)];
    domSummary = `${names.length} certificado(s) caducan en < 14 días: ${names.slice(0, 3).join(', ')}`;
    domDetail = 'Revisa la renovación automática de Caddy o reemplaza los certificados PEM personalizados antes de su vencimiento.';
  }
  checks.push({
    id: 'domains',
    name: 'Dominios y caducidad TLS',
    status: domStatus,
    summary: domSummary,
    detail: domDetail,
    fixAction: null,
    fixLabel: null
  });

  // 7. Bases de datos y copias de seguridad
  const dbs = databaseManager.list ? databaseManager.list() : [];
  const withSchedule = dbs.filter((d) => d.schedule && d.schedule.enabled).length;
  const failedBackups = dbs.filter((d) => d.schedule && d.schedule.lastStatus === 'error');
  const dbStatus = failedBackups.length > 0 ? 'fail' : (dbs.length > 0 && withSchedule === 0) ? 'warn' : 'ok';
  checks.push({
    id: 'databases',
    name: 'Bases de datos y copias',
    status: dbStatus,
    summary: dbs.length === 0
      ? 'Sin bases de datos gestionadas'
      : failedBackups.length > 0
        ? `${failedBackups.length} base(s) de datos con fallo en última copia`
        : `${dbs.length} ${dbs.length === 1 ? 'base de datos' : 'bases de datos'} · ${withSchedule} con copia automática`,
    detail: failedBackups.length > 0
      ? `Revisa el historial de copias y destino S3/disco para: ${failedBackups.map((d) => d.name).join(', ')}.`
      : dbStatus === 'warn'
        ? 'Tienes bases de datos activas sin copias programadas. Activa un horario cron desde el panel del proyecto.'
        : 'Estado de almacenamiento y copias verificado.',
    fixAction: null,
    fixLabel: null
  });

  // 8. Contenedores huérfanos (solo si Docker está disponible)
  if (dockerAvail) {
    const orphans = await listOrphanedManagedContainers();
    checks.push({
      id: 'orphaned_containers',
      name: 'Contenedores huérfanos',
      status: orphans.length > 0 ? 'warn' : 'ok',
      summary: orphans.length > 0
        ? `${orphans.length} contenedor(es) detenidos sin referencia activa`
        : 'Sin contenedores huérfanos',
      detail: orphans.length > 0
        ? `Contenedores residuales detectados: ${orphans.slice(0, 4).join(', ')}${orphans.length > 4 ? '...' : ''}.`
        : 'Todos los contenedores gestionados por Culkibo corresponden a servicios, despliegues o bases activas.',
      fixAction: orphans.length > 0 ? 'clean_orphans' : null,
      fixLabel: orphans.length > 0 ? 'Eliminar contenedores huérfanos' : null
    });
  }

  // 9. Archivos temporales antiguos (> 1 hora)
  const cutoff = Date.now() - SAFE_TMP_AGE_MS;
  const staleTmp = countStaleFilesInDir(TMP_DIR, cutoff)
    + countStaleFilesInDir(LEGACY_TMP_DIR, cutoff)
    + countStaleFilesInDir(os.tmpdir(), cutoff, 'culkibo-git-');
  checks.push({
    id: 'tmp_hygiene',
    name: 'Higiene de archivos temporales',
    status: staleTmp > 0 ? 'warn' : 'ok',
    summary: staleTmp > 0 ? `${staleTmp} archivos temporales antiguos (>1 h)` : 'Directorio temporal limpio',
    detail: staleTmp > 0
      ? 'Archivos residuales de despliegues o clones interrumpidos (>1 hora) que pueden eliminarse de forma segura.'
      : 'Sin residuos temporales antiguos de despliegues anteriores.',
    fixAction: staleTmp > 0 ? 'clean_tmp' : null,
    fixLabel: staleTmp > 0 ? 'Limpiar archivos temporales' : null
  });

  // 10. Asesor de costes/RAM del VPS y salud de nodos de flota SSH (perezoso, degradación limpia)
  checks.push(await checkCostAndFleet({ snap }));

  // 11. Motor de reglas de alertas proactivas
  try {
    const alertEngine = require('./alertEngine');
    const alertSum = alertEngine.getSummary();
    /** @type {'ok' | 'warn' | 'fail'} */
    const alertStatus = alertSum.criticalFiringCount > 0 ? 'fail' : (alertSum.firingCount > 0 ? 'warn' : 'ok');
    checks.push({
      id: 'alert_rules',
      name: 'Motor de alertas proactivas',
      status: alertStatus,
      summary: alertSum.firingCount > 0
        ? `${alertSum.firingCount} alerta(s) activa(s) (${alertSum.criticalFiringCount} críticas)`
        : `${alertSum.rulesEnabled}/${alertSum.rulesTotal} reglas activas · sin alertas disparadas`,
      detail: alertSum.firingCount > 0
        ? alertSum.activeAlerts.slice(0, 3).map((a) => `${a.ruleName} (${a.target})`).join(' · ')
        : 'Reglas de RAM, disco, CPU, OOM, TLS y Uptime configuradas con amortiguación y enfriamiento.',
      fixAction: null,
      fixLabel: null,
      metrics: {
        rulesTotal: alertSum.rulesTotal,
        rulesEnabled: alertSum.rulesEnabled,
        firingCount: alertSum.firingCount,
        criticalFiringCount: alertSum.criticalFiringCount
      }
    });
  } catch (e) {}

  // 12. Auditoría del runtime OCI `runc` (CVE-2025-31133 / CVE-2025-52565 / CVE-2025-52881)
  checks.push(checkRuncRuntime());

  const summary = {
    ok: checks.filter((c) => c.status === 'ok').length,
    warn: checks.filter((c) => c.status === 'warn').length,
    fail: checks.filter((c) => c.status === 'fail').length
  };
  const overall = summary.fail > 0 ? 'fail' : summary.warn > 0 ? 'warn' : 'ok';

  return {
    overall,
    durationMs: Date.now() - started,
    timestamp: new Date().toISOString(),
    summary,
    checks
  };
}

/**
 * Ejecuta una remediación segura en 1 clic.
 * @param {string} action
 */
async function applyFix(action) {
  if (action === 'reconcile_caddy') {
    const ing1 = require('./ingressManager');
    // ingressManager.reconcile() ya incorpora deployments.json preservando mantenimiento, cabeceras y Basic Auth
    const ingRes = await ing1.reconcile();
    return {
      ok: true,
      action,
      message: 'Rutas de Caddy reconciliadas correctamente.',
      detail: { ingress: ingRes }
    };
  }

  if (action === 'start_caddy') {
    const cm = require('./caddyManager');
    const ing2 = require('./ingressManager');
    const started = await cm.startWithDocker();
    const ingRes = await ing2.reconcile().catch(() => null);
    return {
      ok: Boolean(started && started.started !== false),
      action,
      message: 'Caddy arrancado y rutas reconciliadas.',
      detail: { caddy: started, ingress: ingRes }
    };
  }

  if (action === 'clean_tmp') {
    // Jamás borra archivos <1h para no destruir env-files ni volcados de despliegues/restauraciones en curso
    const cutoff = Date.now() - SAFE_TMP_AGE_MS;
    const removed = removeStaleFilesInDir(TMP_DIR, cutoff)
      + removeStaleFilesInDir(LEGACY_TMP_DIR, cutoff)
      + removeStaleFilesInDir(os.tmpdir(), cutoff, 'culkibo-git-');
    return {
      ok: true,
      action,
      message: removed > 0
        ? `Eliminados ${removed} archivos temporales antiguos (>1 h).`
        : 'No había archivos temporales antiguos por limpiar (los archivos recientes en curso se protegen automáticamente).',
      removed
    };
  }

  if (action === 'clean_orphans') {
    const dm1 = require('./deployManager');
    const orphans = await listOrphanedManagedContainers();
    let removed = 0;
    for (const name of orphans) {
      const r = await dm1.runDocker(['rm', '-f', name], { timeoutMs: 15000 }).catch(() => ({ code: 1 }));
      if (r.code === 0) removed++;
    }
    return {
      ok: true,
      action,
      message: removed > 0
        ? `Eliminados ${removed} contenedor(es) huérfanos detenidos.`
        : 'No había contenedores huérfanos por eliminar.',
      removed
    };
  }

  if (action === 'prune_buildkit') {
    const dm2 = require('./deployManager');
    const res = await dm2.pruneBuildCache({ keepStorageGb: 2 });
    return {
      ok: true,
      action,
      message: 'Caché de BuildKit purgada conservando las capas recientes (2 GB).',
      detail: res
    };
  }

  if (action === 'review_sleep_candidates') {
    const sa = require('./sleepAdvisor');
    const candidates = typeof sa.getSleepCandidates === 'function' ? sa.getSleepCandidates() : [];
    const totalMb = candidates.reduce((sum, c) => sum + (Number(c.reclaimableRamMb) || 0), 0);
    return {
      ok: true,
      action,
      message: candidates.length > 0
        ? `${candidates.length} candidato(s) a Auto-Sleep detectados (~${totalMb} MB recuperables). Actívalos desde Uptime → Ahorro y Reposo.`
        : 'No hay proyectos inactivos pendientes de Auto-Sleep en este momento.',
      candidates,
      reclaimableRamMb: totalMb
    };
  }

  const err = new Error(`Acción de remediación no soportada: ${action}`);
  /** @type {any} */ (err).status = 400;
  throw err;
}

/**
 * Comprobación #12: Auditoría del runtime OCI `runc` (CVE-2025-31133 / CVE-2025-52565 / CVE-2025-52881).
 * Carga de forma perezosa `seccompProfileService.auditRuncVersion` y sondea `runc --version`
 * sin shell (`shell: false`), degradando limpiamente en Windows o hosts sin `runc`.
 *
 * @param {{ versionOutput?: string | null, seccompMod?: any, platform?: string }} [opts]
 */
function checkRuncRuntime({ versionOutput = undefined, seccompMod = undefined, platform = process.platform } = {}) {
  let mod = seccompMod;
  if (mod === undefined) {
    try { mod = require('./seccompProfileService'); } catch (e) { mod = null; }
  }

  /** @type {string | null} */
  let rawOutput = versionOutput !== undefined ? versionOutput : null;
  if (versionOutput === undefined) {
    if (platform === 'win32') {
      return {
        id: 'runc_runtime',
        name: 'Runtime OCI runc (CVE-2025-31133/52565/52881)',
        status: /** @type {'ok'} */ ('ok'),
        summary: 'Comprobación de runc omitida en Windows (aplica a hosts Linux Docker)',
        detail: 'En servidores Linux de producción, Culkibo audita automáticamente runc frente a escapes de montaje CVE-2025-31133, CVE-2025-52565 y CVE-2025-52881.',
        fixAction: null,
        fixLabel: null,
        metrics: { available: false, platform, status: 'SKIPPED', vulnerable: false, cves: [] }
      };
    }
    try {
      const { execFileSync } = require('child_process');
      rawOutput = String(execFileSync('runc', ['--version'], {
        encoding: 'utf8',
        shell: false,
        timeout: 2000,
        stdio: ['ignore', 'pipe', 'pipe']
      }) || '').trim();
    } catch (e) {
      return {
        id: 'runc_runtime',
        name: 'Runtime OCI runc (CVE-2025-31133/52565/52881)',
        status: /** @type {'ok'} */ ('ok'),
        summary: 'Binario runc no detectado en el PATH del host',
        detail: 'No se encontró `runc` localmente (modo ligero o contenedor remoto). Verifica `runc --version` (>= 1.2.8 / >= 1.3.3) en tus nodos Docker Linux.',
        fixAction: null,
        fixLabel: null,
        metrics: { available: false, platform, status: 'UNAVAILABLE', vulnerable: false, cves: [] }
      };
    }
  }

  if (!mod || typeof mod.auditRuncVersion !== 'function') {
    return {
      id: 'runc_runtime',
      name: 'Runtime OCI runc (CVE-2025-31133/52565/52881)',
      status: /** @type {'ok'} */ ('ok'),
      summary: 'Módulo seccompProfileService no disponible',
      detail: 'No se pudo cargar la auditoría semver de runc.',
      fixAction: null,
      fixLabel: null,
      metrics: { available: false, status: 'UNKNOWN', vulnerable: false, cves: [] }
    };
  }

  const audit = mod.auditRuncVersion(rawOutput || '');
  const isCritical = Boolean(audit && (audit.vulnerable === true || audit.status === 'CRITICAL'));
  const verLabel = (audit && (audit.version || audit.parsedVersion)) ? String(audit.version || audit.parsedVersion) : 'desconocida';
  const cves = Array.isArray(audit && audit.cves) ? audit.cves : [];

  if (isCritical) {
    return {
      id: 'runc_runtime',
      name: 'Runtime OCI runc (CVE-2025-31133/52565/52881)',
      status: /** @type {'fail'} */ ('fail'),
      summary: `CRITICAL: runc ${verLabel} vulnerable a escapes de contenedor (${cves.join(', ')})`,
      detail: `Actualiza runc/containerd inmediatamente (${audit.fixedIn || '>= 1.2.8 / >= 1.3.3'}) y aplica perfiles seccomp restringidos sin io_uring/mount.`,
      fixAction: null,
      fixLabel: null,
      metrics: { available: true, ...audit }
    };
  }

  return {
    id: 'runc_runtime',
    name: 'Runtime OCI runc (CVE-2025-31133/52565/52881)',
    status: /** @type {'ok'} */ ('ok'),
    summary: audit && audit.status === 'PASS'
      ? `runc ${verLabel} parcheado (sin CVE-2025-31133/52565/52881)`
      : `runc detectado (${verLabel}) · versión sin coincidencia vulnerable`,
    detail: 'Runtime OCI verificado frente a los escapes críticos de montaje de runc 2025.',
    fixAction: null,
    fixLabel: null,
    metrics: { available: true, ...audit }
  };
}

module.exports = { runDoctor, applyFix, checkDiskSpace, checkHostMemory, checkKeyFilePermissions, listOrphanedManagedContainers, checkCostAndFleet, auditExposedDatabases, checkRuncRuntime };
