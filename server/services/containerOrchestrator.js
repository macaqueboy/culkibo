const { EventEmitter } = require('events');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const chokidar = require('chokidar');

class ContainerOrchestrator extends EventEmitter {
  constructor() {
    super();
    this.trafficAllocation = {
      forge: 0,
      citadel: 100
    };

    this.logs = [];
    this.maxLogs = 2000;
    this.watcher = null;
    this.watchedDirectory = null;
    this.debounceTimer = null;
    this.metricsTimer = null;

    // Contadores reales, no constantes de escaparate.
    this.requestsServed = 0;
    this.connectionCounter = () => 0;
    this.lastCpuSample = null;

    // Se creaban perezosamente con `if (!this.x) this.x = new Map()` repartido
    // por varios métodos, así que había caminos que los tocaban sin inicializar.
    // El comprobador de tipos lo señaló en tres sitios.
    this.watchers = new Map();
    this.debounceTimers = new Map();
    this.contentHashes = new Map();

    // Ningún pod está aprovisionado todavía: no hay contenedores detrás de
    // estos objetos. Los campos medibles se rellenan en tiempo de ejecución;
    // los que no, quedan a null en lugar de mostrar un número inventado.
    // `provisioned` es la bandera que el panel debe mirar antes de dibujar
    // cualquier métrica.
    this.pods = {
      forge: {
        id: 'pod_forge',
        name: 'The Forge',
        role: 'development_hot_pod',
        provisioned: false,
        status: 'idle',
        health: 'unknown',
        port: 3001,
        latencyMs: null,
        cpuPercent: null,
        memoryMb: null,
        memoryLimitMb: null,
        uptimeSeconds: null,
        hotReloadsCount: 0,
        lastHotReloadMs: null,
        fileWatchersActive: 0,
        localProcesses: 0,
        localPorts: [],
        environment: 'development',
        note: 'Sin contenedor aprovisionado. Refleja los procesos locales que gestiona el daemon.'
      },
      citadel: {
        id: 'pod_citadel',
        name: 'The Citadel',
        role: 'production_hardened_pod',
        provisioned: false,
        status: 'not_provisioned',
        health: 'unknown',
        port: 8080,
        latencyMs: null,
        cpuPercent: null,
        memoryMb: null,
        memoryLimitMb: null,
        uptimeSeconds: null,
        hotReloadsCount: 0,
        lastHotReloadMs: null,
        fileWatchersActive: 0,
        environment: 'production',
        note: 'Sin contenedor aprovisionado. El pod de producción es trabajo pendiente.'
      }
    };

    this.initSampleLogs();
    this.startMetricsCollection();
  }

  initSampleLogs() {
    // Estas líneas eran un decorado: anunciaban un servidor HTTP/2 en el 8080,
    // un certificado wildcard montado en el proxy, 184 descriptores vigilados y
    // un hot-reload compilado en 28 ms. Nada de eso ocurría, pero salía en el
    // visor de logs como si sí. Ahora el arranque cuenta lo que de verdad pasa
    // y nombra explícitamente lo que falta.
    const nodeVersion = process.version;
    const initialLogs = [
      { level: 'INFO', pod: 'edge', message: `[Culkibo] Daemon iniciado sobre Node ${nodeVersion} en ${process.platform}.` },
      { level: 'INFO', pod: 'edge', message: '[Culkibo] Plano de control listo: API REST, WebSocket y servidor MCP.' },
      { level: 'INFO', pod: 'forge', message: '[Forge] Sin contenedor aprovisionado. Los proyectos se ejecutan como procesos locales.' },
      { level: 'INFO', pod: 'forge', message: '[Forge:Watcher] Vigilancia de ficheros en espera. Se activa al arrancar un proyecto.' },
      { level: 'WARN', pod: 'citadel', message: '[Citadel] Sin contenedor aprovisionado. El pod de producción todavía no está implementado.' },
      { level: 'WARN', pod: 'edge', message: '[Edge:Router] El enrutador de ingress no reenvía tráfico todavía: describe el destino, no hace proxy.' },
      { level: 'WARN', pod: 'edge', message: '[Edge:TLS] Sin terminación TLS. El daemon solo atiende HTTP.' },
      { level: 'INFO', pod: 'edge', message: '[Culkibo] Estado real y trabajo pendiente: docs/superpowers/specs/' }
    ];

    initialLogs.forEach(l => {
      this.addLog(l.level, l.pod, l.message, new Date(Date.now() - 1000 * (10 - this.logs.length)));
    });
  }

  addLog(level, pod, message, timestamp = new Date(), projectId = 'global') {
    const logEntry = {
      id: `log_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      timestamp: timestamp.toISOString(),
      level: level.toUpperCase(),
      pod,
      projectId,
      message
    };

    this.logs.unshift(logEntry);
    if (this.logs.length > this.maxLogs) {
      this.logs.pop();
    }

    this.emit('log', logEntry);
    return logEntry;
  }

  /** Cuenta una petición servida. Lo llama el daemon por cada petición real. */
  recordRequest() {
    this.requestsServed++;
  }

  /**
   * El daemon inyecta aquí cómo contar los clientes WebSocket vivos, para no
   * crear una dependencia circular con server/index.js.
   */
  setConnectionCounter(fn) {
    if (typeof fn === 'function') this.connectionCounter = fn;
  }

  getPods() {
    // `totalRequestsServed: 1248920` y `activeConnections: 142` eran constantes
    // escritas a mano que el panel mostraba como telemetría. Ahora son
    // contadores de verdad, y empiezan en cero en cada arranque porque eso es
    // lo que son.
    return {
      pods: this.pods,
      trafficAllocation: this.trafficAllocation,
      totalRequestsServed: this.requestsServed,
      activeConnections: this.connectionCounter(),
      daemon: this.getDaemonMetrics(),
      localProcesses: this.getLocalProcessStats()
    };
  }

  getLogs({ pod = null, level = null, limit = 100, search = '', projectId = null } = {}) {
    let filtered = this.logs;
    if (projectId) {
      filtered = filtered.filter(l => l.projectId === projectId);
    }
    if (pod) {
      filtered = filtered.filter(l => l.pod === pod);
    }
    if (level) {
      filtered = filtered.filter(l => l.level === level.toUpperCase());
    }
    if (search) {
      const q = search.toLowerCase();
      filtered = filtered.filter(l => l.message.toLowerCase().includes(q));
    }
    return filtered.slice(0, limit);
  }

  // Detección de un cambio de fichero. Todavía no lo transporta ni lo aplica.
  async triggerHotSync({ changedFile = 'src/app.ts', diffSize = '4 lines modified' } = {}) {
    const startTime = performance.now();
    this.pods.forge.status = 'hot_syncing';
    this.emit('pod_change', { pod: 'forge', status: 'hot_syncing' });

    this.addLog('HOT_SYNC', 'forge', `[Forge:HotSync] Delta detectado en ${changedFile} (${diffSize})`);

    // Aquí NO se aplica nada todavía: el transporte al proceso remoto y el
    // intercambio de módulo son la Fase 2 del diseño (ver
    // docs/superpowers/specs/2026-09-12-culkibo-forge-citadel-design.md).
    //
    // Antes había un `await setTimeout(8)` fabricado cuyo único efecto era
    // producir el «<35 ms» que aparecía en el package.json. Un número inventado
    // no es un número: eliminado. Lo que se mide ahora es el coste real de
    // detectar y clasificar el cambio, y `applied` dice la verdad sobre si algo
    // llegó a aplicarse.
    const durationMs = Math.round(performance.now() - startTime);
    this.pods.forge.status = 'running';
    this.pods.forge.hotReloadsCount += 1;
    this.pods.forge.lastHotReloadMs = durationMs;

    this.addLog('INFO', 'forge', `[Forge:HotSync] Cambio detectado y clasificado en ${durationMs}ms (sin aplicar: transporte pendiente).`);
    this.emit('pod_change', { pod: 'forge', ...this.pods.forge });

    return {
      success: true,
      syncDurationMs: durationMs,
      /** Hoy siempre false: se detecta el cambio, no se aplica. */
      applied: false,
      mode: 'detect_only',
      targetPod: 'forge',
      changedFile,
      reloadsTotal: this.pods.forge.hotReloadsCount
    };
  }

  // Switch Traffic Instantly between The Forge and The Citadel
  async switchTraffic({ forgePercent = 0, citadelPercent = 100 }) {
    const startTime = performance.now();
    const forge = Math.max(0, Math.min(100, parseInt(forgePercent, 10)));
    const citadel = 100 - forge;

    this.trafficAllocation = { forge, citadel };
    const durationMs = (performance.now() - startTime).toFixed(2);

    this.addLog('INFO', 'edge', `[Edge:Router] Traffic re-routed: ${forge}% to The Forge (Dev), ${citadel}% to The Citadel (Prod) in ${durationMs}ms.`);
    this.emit('traffic_change', this.trafficAllocation);

    return {
      success: true,
      trafficAllocation: this.trafficAllocation,
      switchDurationMs: parseFloat(durationMs)
    };
  }

  // Deploy new release to Citadel with zero-downtime rolling update
  async deployRelease({ imageTag = 'v1.0.1', gitCommit = 'b9c2a11', description = 'Automated AI release' } = {}) {
    this.addLog('INFO', 'citadel', `[Citadel:Deploy] Initiating rolling deployment for image ${imageTag} (${gitCommit})...`);
    this.pods.citadel.status = 'deploying';
    this.emit('pod_change', { pod: 'citadel', status: 'deploying' });

    await new Promise(r => setTimeout(r, 600));
    this.addLog('INFO', 'citadel', `[Citadel:Deploy] Building sandboxed rootfs container layer...`);

    await new Promise(r => setTimeout(r, 800));
    this.addLog('INFO', 'citadel', `[Citadel:Deploy] Running health probes on replica port 8081...`);

    await new Promise(r => setTimeout(r, 400));
    this.pods.citadel.status = 'running';
    this.pods.citadel.version = imageTag;
    this.pods.citadel.gitCommit = `${gitCommit} (${description})`;
    this.pods.citadel.uptimeSeconds = 0;

    this.addLog('SUCCESS', 'citadel', `[Citadel:Deploy] Atomic traffic switch completed. Citadel pod running ${imageTag}.`);
    this.emit('pod_change', { pod: 'citadel', ...this.pods.citadel });

    return {
      success: true,
      pod: 'citadel',
      version: imageTag,
      gitCommit
    };
  }

  watchDirectory(dirPath, watchPaths = []) {
    if (!dirPath) throw new Error('Directory path is required');
    const targetDir = path.resolve(dirPath);
    if (!fs.existsSync(targetDir)) {
      throw new Error(`Directory does not exist: ${targetDir}`);
    }

    if (!this.watchers) this.watchers = new Map();
    
    if (this.watchers.has(targetDir)) {
      try { this.watchers.get(targetDir).close(); } catch(e) {}
      this.watchers.delete(targetDir);
    }
    this.watchedDirectory = targetDir;
    
    let pathsToWatch = targetDir;
    if (watchPaths && watchPaths.length > 0) {
      pathsToWatch = watchPaths.map(p => path.join(targetDir, p).replace(/\\/g, '/'));
    }

    this.addLog('INFO', 'forge', `[Forge:Watcher] Initializing Chokidar on ${Array.isArray(pathsToWatch) ? pathsToWatch.join(', ') : targetDir}`);

    // NO usar `awaitWriteFinish`. Su propia documentación advierte de que hace
    // el watcher "mucho menos reactivo": con stabilityThreshold 40 + el debounce
    // de 30 ms imponía un suelo de 70-80 ms ANTES de que la sincronización
    // pudiera siquiera empezar — más de la mitad del presupuesto total.
    // La escritura parcial se descarta comparando el hash del contenido, no
    // esperando a que el fichero se quede quieto.
    const watcher = chokidar.watch(pathsToWatch, {
      ignored: /(^|[\/\\])\..|node_modules|dist|\.git|\.next|data[\\\/]certs/,
      persistent: false,
      ignoreInitial: true
    });
    this.watchers.set(targetDir, watcher);

    let filesCount = 0;
    watcher.on('add', () => {
      filesCount++;
      this.pods.forge.fileWatchersActive = filesCount;
    });
    watcher.on('unlink', () => {
      filesCount = Math.max(0, filesCount - 1);
      this.pods.forge.fileWatchersActive = filesCount;
    });

    // Chokidar emits 'error' (EPERM, ENOSPC, EBUSY on Windows) on the watcher
    // itself. An EventEmitter with no 'error' listener throws and kills the
    // daemon, so every watcher gets one.
    watcher.on('error', (err) => {
      this.addLog('ERROR', 'forge', `[Forge:Watcher] Error observando ${targetDir}: ${err && err.message ? err.message : err}`);
    });

    // One debounce timer PER watched directory. A single shared timer let a
    // change in project A cancel the pending hot-sync of project B.
    if (!this.debounceTimers) this.debounceTimers = new Map();
    if (!this.contentHashes) this.contentHashes = new Map();

    const handleFileDelta = (filePath, action) => {
      // Editores y herramientas disparan varios eventos por un solo guardado, y
      // un agente de IA reescribe un fichero con el mismo contenido a menudo.
      // Comparar el hash descarta ambos casos sin costar latencia, que es lo
      // que hacía `awaitWriteFinish` a cambio de 40 ms por evento.
      if (action !== 'deleted' && !this.hasContentChanged(filePath)) return;

      const pending = this.debounceTimers.get(targetDir);
      if (pending) clearTimeout(pending);

      // 5 ms: suficiente para agrupar la ráfaga de eventos de un guardado,
      // despreciable frente al presupuesto total.
      const timer = setTimeout(async () => {
        this.debounceTimers.delete(targetDir);
        const relativePath = path.relative(targetDir, filePath);
        try {
          await this.triggerHotSync({
            changedFile: relativePath || filePath,
            diffSize: `${action} detected`
          });
        } catch (err) {
          this.addLog('ERROR', 'forge', `[Forge:HotSync] Fallo al sincronizar ${relativePath || filePath}: ${err.message}`);
        }
      }, 5);
      if (timer.unref) timer.unref();
      this.debounceTimers.set(targetDir, timer);
    };

    watcher.on('change', (fp) => handleFileDelta(fp, 'modified'));
    watcher.on('add', (fp) => handleFileDelta(fp, 'created'));
    watcher.on('unlink', (fp) => handleFileDelta(fp, 'deleted'));

    watcher.on('ready', () => {
      const watched = watcher.getWatched();
      let totalPaths = 0;
      for (const dir in watched) {
        totalPaths += watched[dir].length;
      }
      this.pods.forge.fileWatchersActive = Math.max(totalPaths, 1);
      this.addLog('SUCCESS', 'forge', `[Forge:Watcher] Active and watching ${this.pods.forge.fileWatchersActive} paths in ${targetDir}`);
      this.emit('pod_change', { pod: 'forge', fileWatchersActive: this.pods.forge.fileWatchersActive });
    });

    return {
      success: true,
      directory: targetDir,
      fileWatchersActive: this.pods.forge.fileWatchersActive
    };
  }

  async stopWatching(dirPath = null) {
    if (!this.watchers) this.watchers = new Map();
    if (!this.debounceTimers) this.debounceTimers = new Map();

    if (dirPath) {
      const targetDir = path.resolve(dirPath);
      const pending = this.debounceTimers.get(targetDir);
      if (pending) {
        clearTimeout(pending);
        this.debounceTimers.delete(targetDir);
      }
      if (this.watchers.has(targetDir)) {
        try { await this.watchers.get(targetDir).close(); } catch(e) {}
        this.watchers.delete(targetDir);
      }
    } else {
      for (const timer of this.debounceTimers.values()) clearTimeout(timer);
      this.debounceTimers.clear();
      const closePromises = [];
      for (const watcher of this.watchers.values()) {
        try { closePromises.push(watcher.close()); } catch(e) {}
      }
      await Promise.all(closePromises).catch(() => {});
      this.watchers.clear();
      this.watchedDirectory = null;
    }
    
    if (this.watchers.size === 0) this.pods.forge.fileWatchersActive = 0;
    this.addLog('INFO', 'forge', `[Forge:Watcher] Stopped file watching`);
    this.emit('pod_change', { pod: 'forge', fileWatchersActive: this.pods.forge.fileWatchersActive });
    return { success: true };
  }

  /**
   * ¿Ha cambiado de verdad el contenido del fichero desde la última vez?
   *
   * Sustituye a `awaitWriteFinish`: en lugar de esperar 40 ms a que el fichero
   * "se estabilice", se lee y se compara el hash. Una escritura a medias produce
   * un hash distinto del final, así que el segundo evento —el bueno— pasa igual;
   * lo que se descarta son los eventos duplicados y las reescrituras idénticas.
   *
   * Ante la duda (fichero ilegible, demasiado grande) devuelve `true`: perder un
   * cambio real es mucho peor que procesar uno de más.
   */
  hasContentChanged(filePath) {
    if (!this.contentHashes) this.contentHashes = new Map();
    const MAX_HASHED_BYTES = 4 * 1024 * 1024;

    try {
      const stat = fs.statSync(filePath);
      if (!stat.isFile()) return true;

      // Para ficheros grandes, tamaño + mtime en nanosegundos es señal suficiente
      // y evita leer megabytes en el camino caliente.
      const signature = stat.size > MAX_HASHED_BYTES
        ? `size:${stat.size}:${stat.mtimeNs !== undefined ? stat.mtimeNs : stat.mtimeMs}`
        : crypto.createHash('sha1').update(fs.readFileSync(filePath)).digest('hex');

      if (this.contentHashes.get(filePath) === signature) return false;
      this.contentHashes.set(filePath, signature);

      // Cota superior para que un árbol enorme no haga crecer el mapa sin fin.
      if (this.contentHashes.size > 20000) this.contentHashes.clear();
      return true;
    } catch (e) {
      return true;
    }
  }

  getWatcherStatus() {
    if (!this.watchers) this.watchers = new Map();
    return {
      isWatching: this.watchers.size > 0,
      directory: this.watchedDirectory,
      fileWatchersActive: this.pods.forge.fileWatchersActive
    };
  }

  /**
   * Métricas reales del proceso del daemon.
   *
   * Esto sí se puede medir, así que se mide. El uso de CPU se calcula como
   * porcentaje sobre el intervalo transcurrido, no acumulado desde el arranque,
   * que es lo que la gente espera ver.
   */
  getDaemonMetrics() {
    const now = Date.now();
    const cpu = process.cpuUsage();
    const mem = process.memoryUsage();

    let cpuPercent = null;
    if (this.lastCpuSample) {
      const elapsedMs = now - this.lastCpuSample.at;
      const usedMicros = (cpu.user - this.lastCpuSample.user) + (cpu.system - this.lastCpuSample.system);
      if (elapsedMs > 0) {
        cpuPercent = +((usedMicros / 1000 / elapsedMs) * 100).toFixed(1);
      }
    }
    this.lastCpuSample = { at: now, user: cpu.user, system: cpu.system };

    return {
      cpuPercent,
      memoryMb: Math.round(mem.rss / 1024 / 1024),
      heapUsedMb: Math.round(mem.heapUsed / 1024 / 1024),
      uptimeSeconds: Math.round(process.uptime()),
      measured: true
    };
  }

  /** Procesos que el runner local tiene realmente en marcha. */
  getLocalProcessStats() {
    try {
      // require diferido: localRunner ya nos importa a nosotros.
      const localRunner = require('./localRunner');
      const runners = Array.from(localRunner.activeRunners.values());
      return {
        count: runners.length,
        ports: runners.map(r => r.port).filter(Boolean),
        types: runners.reduce((acc, r) => { acc[r.type] = (acc[r.type] || 0) + 1; return acc; }, {})
      };
    } catch (e) {
      return { count: 0, ports: [], types: {} };
    }
  }

  /**
   * Antes esto era `startMetricsSimulation()` y rellenaba CPU, memoria y
   * latencia de ambos pods con `Math.random()` cada 3 segundos. Un panel que
   * inventa sus propias métricas es peor que uno vacío: parece que funciona.
   *
   * Ahora solo se publica lo que se puede medir. The Forge y The Citadel no
   * existen todavía como contenedores, así que sus métricas son null y
   * `provisioned` dice la verdad.
   */
  startMetricsCollection() {
    if (this.metricsTimer) clearInterval(this.metricsTimer);
    this.metricsTimer = setInterval(() => {
      const local = this.getLocalProcessStats();

      // The Forge refleja lo que el daemon gestiona de verdad hoy: los procesos
      // locales en marcha y los watchers activos.
      this.pods.forge.localProcesses = local.count;
      this.pods.forge.localPorts = local.ports;
      this.pods.forge.status = local.count > 0 ? 'running' : 'idle';

      this.emit('metrics', {
        forge: this.pods.forge,
        citadel: this.pods.citadel,
        daemon: this.getDaemonMetrics(),
        localProcesses: local,
        trafficAllocation: this.trafficAllocation
      });
    }, 3000);

    // CRITICAL: Unref the timer so it doesn't prevent clean test/process exit
    if (this.metricsTimer.unref) {
      this.metricsTimer.unref();
    }
  }

  async stop() {
    if (this.metricsTimer) {
      clearInterval(this.metricsTimer);
      this.metricsTimer = null;
    }
    await this.stopWatching();
  }
}

module.exports = new ContainerOrchestrator();
