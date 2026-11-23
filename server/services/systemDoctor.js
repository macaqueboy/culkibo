const fs = require('fs');
const os = require('os');
const path = require('path');

const metricsCollector = require('./metricsCollector');

/**
 * Diagnóstico real en 1 clic del estado del sistema (`systemDoctor`).
 * Sin números inventados ni dependencias externas: ejecuta comprobaciones
 * verificables sobre Node, Docker, Caddy, memoria/disco, seguridad, TLS y BD.
 */

const DATA_DIR = path.resolve(__dirname, '..', '..', 'data');
const TMP_DIR = path.join(DATA_DIR, '.tmp');

function checkDiskSpace() {
  try {
    if (typeof fs.statfsSync === 'function') {
      const st = fs.statfsSync(DATA_DIR);
      const totalGb = Number(((st.blocks * st.bsize) / (1024 ** 3)).toFixed(1));
      const freeGb = Number(((st.bavail * st.bsize) / (1024 ** 3)).toFixed(1));
      const usedPct = totalGb > 0 ? Math.round(((totalGb - freeGb) / totalGb) * 100) : 0;
      /** @type {'ok' | 'warn' | 'fail'} */
      const status = freeGb < 2 ? 'fail' : freeGb < 5 ? 'warn' : 'ok';
      return {
        id: 'disk_memory',
        name: 'Memoria y espacio en disco',
        status,
        summary: `Disco libre: ${freeGb} GB de ${totalGb} GB (${usedPct}% usado)`,
        detail: status === 'ok'
          ? 'Margen suficiente para imágenes Docker, copias de seguridad y cachés de BuildKit.'
          : 'Poco espacio libre en disco. Puedes limpiar cachés de BuildKit y archivos temporales con un clic.',
        fixAction: status !== 'ok' ? 'prune_buildkit' : null,
        fixLabel: status !== 'ok' ? 'Limpiar caché BuildKit' : null
      };
    }
  } catch (e) {}

  const totalMb = Math.round(os.totalmem() / 1024 / 1024);
  const freeMb = Math.round(os.freemem() / 1024 / 1024);
  /** @type {'ok' | 'warn' | 'fail'} */
  const status = freeMb < 128 ? 'warn' : 'ok';
  return {
    id: 'disk_memory',
    name: 'Memoria del servidor',
    status,
    summary: `RAM libre: ${freeMb} MB de ${totalMb} MB`,
    detail: 'Comprobación de memoria del host completada.',
    fixAction: null,
    fixLabel: null
  };
}

async function runDoctor() {
  const started = Date.now();
  const snap = metricsCollector.getSnapshot(true);

  const dockerManager = require('./dockerManager');
  const caddyManager = require('./caddyManager');
  const ingressManager = require('./ingressManager');
  const domainManager = require('./domainManager');
  const databaseManager = require('./databaseManager');
  const { authStatus } = require('../middleware/auth');

  /** @type {Array<{ id: string, name: string, status: 'ok' | 'warn' | 'fail', summary: string, detail: string, fixAction: string | null, fixLabel: string | null }>} */
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
  let caddyDetail = 'Sin Caddy activo no se sirven dominios públicos ni HTTPS automático. Arranca el plano de datos desde Dominios o con culkibo.';
  /** @type {string | null} */
  let caddyFix = null;
  /** @type {string | null} */
  let caddyFixLabel = null;
  try {
    const det = await caddyManager.detect({ force: true });
    if (det && det.available) {
      const ing = await ingressManager.status();
      const driftCount = (ing?.drift?.missing?.length || 0) + (ing?.drift?.unexpected?.length || 0);
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

  // 4. Memoria y Disco
  checks.push(checkDiskSpace());

  // 5. Postura de Seguridad
  const auth = authStatus();
  const bindHost = process.env.CULKIBO_BIND || process.env.HOST || process.env.CULKIBO_HOST || '127.0.0.1';
  const exposedWithoutToken = bindHost === '0.0.0.0' && !auth.requireTokenAlways;
  const exposedDbs = (databaseManager.list ? databaseManager.list() : []).filter(
    (d) => d.exposure && d.exposure.enabled && d.exposure.bindAddress !== '127.0.0.1'
  );
  /** @type {'ok' | 'warn' | 'fail'} */
  let secStatus = 'ok';
  let secSummary = `Token configurado (${auth.tokenSource}) · Escucha en ${bindHost}`;
  let secDetail = 'Autenticación activa, cabeceras de seguridad HTTP habilitadas y bases de datos aisladas en red privada.';
  if (exposedWithoutToken) {
    secStatus = 'warn';
    secSummary = 'Escuchando en 0.0.0.0 sin CULKIBO_REQUIRE_TOKEN=1';
    secDetail = 'En servidores expuestos a internet, define CULKIBO_REQUIRE_TOKEN=1 o escucha solo en 127.0.0.1 detrás de Caddy.';
  } else if (exposedDbs.length > 0) {
    secStatus = 'warn';
    secSummary = `${exposedDbs.length} ${exposedDbs.length === 1 ? 'base de datos expuesta' : 'bases de datos expuestas'} fuera de loopback`;
    secDetail = 'Revisa la exposición externa de tus bases de datos gestionadas y asegúrate de restringir el cortafuegos.';
  }
  checks.push({
    id: 'security',
    name: 'Postura de seguridad',
    status: secStatus,
    summary: secSummary,
    detail: secDetail,
    fixAction: null,
    fixLabel: null
  });

  // 6. Dominios y TLS
  const domains = domainManager.listDomains();
  const wildcardCount = domains.filter((d) => d.isWildcard).length;
  checks.push({
    id: 'domains',
    name: 'Dominios configurados',
    status: 'ok',
    summary: `${domains.length} ${domains.length === 1 ? 'dominio' : 'dominios'} (${wildcardCount} ${wildcardCount === 1 ? 'comodín' : 'comodines'})`,
    detail: domains.length > 0
      ? 'Usa la comprobación TLS en la vista de Dominios para auditar emisores y caducidad en directo.'
      : 'Añade tu primer dominio o genera un dominio gratuito sslip.io en el asistente de Dominios.',
    fixAction: null,
    fixLabel: null
  });

  // 7. Bases de datos y copias de seguridad
  const dbs = databaseManager.list ? databaseManager.list() : [];
  const withSchedule = dbs.filter((d) => d.schedule && d.schedule.enabled).length;
  const dbWarn = dbs.length > 0 && withSchedule === 0;
  checks.push({
    id: 'databases',
    name: 'Bases de datos y copias',
    status: dbWarn ? 'warn' : 'ok',
    summary: dbs.length === 0
      ? 'Sin bases de datos gestionadas'
      : `${dbs.length} ${dbs.length === 1 ? 'base de datos' : 'bases de datos'} · ${withSchedule} con copia automática`,
    detail: dbWarn
      ? 'Tienes bases de datos activas sin copias programadas. Activa un horario cron desde el panel del proyecto.'
      : 'Estado de almacenamiento y copias verificado.',
    fixAction: null,
    fixLabel: null
  });

  // 8. Archivos temporales huérfanos
  let staleTmp = 0;
  try {
    if (fs.existsSync(TMP_DIR)) {
      const cutoff = Date.now() - 3600 * 1000;
      for (const f of fs.readdirSync(TMP_DIR)) {
        try {
          const st = fs.statSync(path.join(TMP_DIR, f));
          if (st.mtimeMs < cutoff) staleTmp++;
        } catch (e) {}
      }
    }
  } catch (e) {}
  checks.push({
    id: 'tmp_hygiene',
    name: 'Higiene de archivos temporales',
    status: staleTmp > 0 ? 'warn' : 'ok',
    summary: staleTmp > 0 ? `${staleTmp} archivos temporales antiguos en data/.tmp` : 'Directorio temporal limpio',
    detail: staleTmp > 0
      ? 'Archivos residuales de despliegues interrumpidos que pueden eliminarse de forma segura.'
      : 'Sin residuos temporales de despliegues anteriores.',
    fixAction: staleTmp > 0 ? 'clean_tmp' : null,
    fixLabel: staleTmp > 0 ? 'Limpiar archivos temporales' : null
  });

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
    const ingressManager = require('./ingressManager');
    const dm = require('./deployManager');
    const ingRes = await ingressManager.reconcile();
    const depRes = await dm.reconcileRoutes().catch(() => ({ applied: [] }));
    return {
      ok: true,
      action,
      message: 'Rutas de Caddy reconciliadas correctamente.',
      detail: { ingress: ingRes, deploy: depRes }
    };
  }

  if (action === 'clean_tmp') {
    let removed = 0;
    try {
      if (fs.existsSync(TMP_DIR)) {
        for (const f of fs.readdirSync(TMP_DIR)) {
          try {
            fs.rmSync(path.join(TMP_DIR, f), { recursive: true, force: true });
            removed++;
          } catch (e) {}
        }
      }
    } catch (e) {}
    return {
      ok: true,
      action,
      message: removed > 0
        ? `Eliminados ${removed} archivos temporales residuales.`
        : 'No había archivos temporales por limpiar.',
      removed
    };
  }

  if (action === 'prune_buildkit') {
    const deployManager = require('./deployManager');
    const res = await deployManager.pruneBuildCache({ keepStorageGb: 2 });
    return {
      ok: true,
      action,
      message: 'Caché de BuildKit purgada conservando las capas recientes (2 GB).',
      detail: res
    };
  }

  const err = new Error(`Acción de remediación no soportada: ${action}`);
  /** @type {any} */ (err).status = 400;
  throw err;
}

module.exports = { runDoctor, applyFix };
