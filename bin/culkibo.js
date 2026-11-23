#!/usr/bin/env node

const { Command } = require('commander');
const readline = require('readline');
const fs = require('fs');
const path = require('path');
const net = require('net');
const { spawn } = require('child_process');

// Carga perezosa de servicios: comandos ligeros (`--version`, `status`, `update`)
// arrancan al instante sin levantar timers ni leer JSONs innecesarios.
const svc = {
  get containerOrchestrator() { return require('../server/services/containerOrchestrator'); },
  get domainManager() { return require('../server/services/domainManager'); },
  get sslManager() { return require('../server/services/sslManager'); },
  get cloudflareService() { return require('../server/services/cloudflareService'); },
  get mcpServer() { return require('../server/services/mcpServer'); },
  get dockerManager() { return require('../server/services/dockerManager'); },
  get dbBackupManager() { return require('../server/services/dbBackupManager'); },
  get projectManager() { return require('../server/services/projectManager'); },
  get caddyManager() { return require('../server/services/caddyManager'); },
  get deployManager() { return require('../server/services/deployManager'); },
  get catalogManager() { return require('../server/services/catalogManager'); },
  get LiveSyncClient() { return require('../server/services/liveSyncClient').LiveSyncClient; }
};

function runSpawnStep(bin, args, cwd) {
  return new Promise((/** @type {(v?: void) => void} */ resolve, reject) => {
    const isWin = process.platform === 'win32';
    const cmd = isWin && bin === 'npm' ? 'cmd.exe' : bin;
    const argv = isWin && bin === 'npm' ? ['/c', 'npm', ...args] : args;
    const child = spawn(cmd, argv, { cwd, stdio: 'inherit', shell: false });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${bin} ${args.join(' ')} terminó con código ${code}`));
    });
  });
}

const program = new Command();

program
  .name('culkibo')
  .description('Culkibo — Orquestador cloud autohospedado para desarrollar con agentes de IA')
  .version('1.0.0');

// Comando start
program
  .command('start')
  .description('Inicia el demonio de Culkibo Orchestrator y el panel de control web')
  .option('-p, --port <port>', 'Puerto del servidor', '3030')
  .option('-w, --watch [dir]', 'Activar la vigilancia de ficheros para el entorno de Desarrollo')
  .action(async (options) => {
    process.env.PORT = options.port;
    if (options.watch) {
      process.env.CULKIBO_WATCH_DIR = options.watch === true ? process.cwd() : options.watch;
    }
    const { startServer, shutdown } = require('../server/index');
    const bindHost = process.env.CULKIBO_BIND || process.env.HOST || process.env.CULKIBO_HOST || '127.0.0.1';
    try {
      await startServer(parseInt(options.port, 10) || 3030, bindHost);
      for (const sig of ['SIGINT', 'SIGTERM']) {
        process.once(sig, () => {
          shutdown(sig).finally(() => process.exit(0));
        });
      }
    } catch (err) {
      console.error(`\x1b[31m❌ No se pudo iniciar el demonio de Culkibo:\x1b[0m`, err.message);
      process.exit(1);
    }
  });

// Comando status
program
  .command('status')
  .description('Muestra el estado operativo del demonio de Culkibo')
  .action(async () => {
    try {
      const res = await fetch('http://localhost:3030/api/health');
      if (res.ok) {
        console.log('\x1b[32m✅ Culkibo está en ejecución y saludable (Código HTTP 200).\x1b[0m');
      } else {
        console.log('\x1b[33m⚠️ Culkibo responde pero reporta anomalías.\x1b[0m');
      }
    } catch (err) {
      console.log('\x1b[31m❌ Culkibo está detenido o inalcanzable en el puerto 3030.\x1b[0m');
    }
  });

// Comando stop
program
  .command('stop')
  .description('Instrucciones para detener el demonio de Culkibo')
  .action(() => {
    console.log('\x1b[33m🛑 Para detener el servidor, presione Ctrl+C en la terminal activa o termine el proceso de Node con Stop-Process / kill.\x1b[0m');
  });

// Comando doctor (diagnóstico integral del sistema)
program
  .command('doctor')
  .description('Ejecuta un chequeo de diagnóstico integral del entorno y dependencias')
  .action(async () => {
    console.log('\n\x1b[36m🩺 DIAGNÓSTICO INTEGRAL DE CULKIBO\x1b[0m');
    console.log('==================================================');

    // 1. Node.js version
    const nodeMajor = parseInt(process.versions.node.split('.')[0], 10);
    if (nodeMajor >= 18) {
      console.log(`\x1b[32m  ✓ Node.js:\x1b[0m ${process.version} (Cumple requisito mínimo >= v18)`);
    } else {
      console.log(`\x1b[31m  ✗ Node.js:\x1b[0m ${process.version} (Se recomienda actualizar a >= v20)`);
    }

    // 2. Docker Daemon
    const dockerStatus = await svc.dockerManager.checkDockerStatus(true);
    if (dockerStatus.available) {
      console.log(`\x1b[32m  ✓ Motor Docker:\x1b[0m Activo (${dockerStatus.serverVersion}) — Modo Nativo`);
    } else {
      console.log(`\x1b[33m  ⚠️ Motor Docker:\x1b[0m Inactivo o no detectado. Modo Sandbox de Procesos activado`);
    }

    // 2b. Caddy (Plano de datos)
    const caddyStatus = await svc.caddyManager.detect({ force: true });
    if (caddyStatus.available) {
      console.log(`\x1b[32m  ✓ Plano de datos Caddy:\x1b[0m Activo en ${caddyStatus.adminUrl}`);
    } else {
      console.log(`\x1b[33m  ⚠️ Plano de datos Caddy:\x1b[0m No detectado (${caddyStatus.reason}). El panel sigue operativo sin ingress real.`);
    }

    // 3. Permisos de disco
    const dirsToCheck = ['./data', './projects', './data/backups'];
    dirsToCheck.forEach(d => {
      try {
        if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
        const testFile = path.join(d, '.write_test');
        fs.writeFileSync(testFile, 'ok');
        fs.unlinkSync(testFile);
        console.log(`\x1b[32m  ✓ Directorio ${d}:\x1b[0m Permisos de lectura/escritura correctos`);
      } catch (e) {
        console.log(`\x1b[31m  ✗ Directorio ${d}:\x1b[0m Error de permisos: ${e.message}`);
      }
    });

    // 4. Cloudflare
    const cfConfig = svc.cloudflareService.config;
    if (cfConfig.apiToken) {
      console.log(`\x1b[32m  ✓ Cloudflare API:\x1b[0m Token configurado correctamente`);
    } else {
      console.log(`\x1b[33m  ⚠️ Cloudflare API:\x1b[0m Token no configurado (usando emulador local de zonas)`);
    }

    // 5. Verificación de puertos
    const checkPort = (port) => new Promise(resolve => {
      const tester = net.createServer()
        .once('error', (/** @type {any} */ err) => resolve({ port, free: false, error: err.code }))
        .once('listening', () => tester.once('close', () => resolve({ port, free: true })).close())
        .listen(port, '0.0.0.0');
    });

    const port3030 = await checkPort(3030);
    console.log(`  • Puerto 3030 (Panel/API): ${port3030.free ? '\x1b[32mDisponible\x1b[0m' : '\x1b[36mEn uso (demonio activo)\x1b[0m'}`);

    console.log('==================================================');
    console.log('\x1b[32m✨ Diagnóstico finalizado con éxito.\x1b[0m\n');
  });

// Comando watch
program
  .command('watch [directorio]')
  .description('Vigila un directorio y notifica los cambios al entorno de Desarrollo')
  .action((directorio = process.cwd()) => {
    try {
      const containerOrchestrator = svc.containerOrchestrator;
      const res = containerOrchestrator.watchDirectory(directorio);
      console.log(`\n⚡ [Desarrollo] Monitoreando ${res.directory} (${res.fileWatchersActive} rutas vigiladas)`);
      console.log(`   Vigilancia activa. Los cambios se detectan y registran; para sincronizar con un daemon usa "culkibo sync <projectId>".\n`);

      containerOrchestrator.on('pod_change', (pod) => {
        if (pod.lastHotReloadMs) {
          console.log(`✨ Delta sincronizado en ${pod.lastHotReloadMs}ms | Recargas totales: ${pod.hotReloadsCount}`);
        }
      });
      containerOrchestrator.on('log', (log) => {
        if (log.level === 'HOT_SYNC' || log.level === 'SUCCESS') {
          console.log(`  [${log.level}] ${log.message}`);
        }
      });
    } catch (err) {
      console.error(`❌ Error en el observador: ${err.message}`);
      process.exit(1);
    }
  });

// Grupo de comandos para Pods / Entornos
const podCmd = program.command('pod').description('Gestión de entornos de Desarrollo y Producción');

podCmd
  .command('list')
  .description('Muestra el estado y métricas en tiempo real de los entornos')
  .action(() => {
    const data = svc.containerOrchestrator.getPods();
    console.log('\n--- Estado de Entornos Culkibo ---');
    console.table([
      {
        Entorno: 'Desarrollo (:3001)',
        Estado: data.pods.forge.status === 'running' ? 'Activo' : data.pods.forge.status,
        Latencia: `${data.pods.forge.latencyMs}ms`,
        CPU: `${data.pods.forge.cpuPercent}%`,
        Memoria: `${data.pods.forge.memoryMb}MB`,
        Puerto: data.pods.forge.port,
        Tráfico: `${data.trafficAllocation.forge}%`
      },
      {
        Entorno: 'Producción (:8080)',
        Estado: data.pods.citadel.status === 'running' ? 'Activo' : data.pods.citadel.status,
        Latencia: `${data.pods.citadel.latencyMs}ms`,
        CPU: `${data.pods.citadel.cpuPercent}%`,
        Memoria: `${data.pods.citadel.memoryMb}MB`,
        Puerto: data.pods.citadel.port,
        Tráfico: `${data.trafficAllocation.citadel}%`
      }
    ]);
  });

podCmd
  .command('sync')
  .description('Dispara manualmente la detección de un cambio')
  .option('-f, --file <file>', 'Archivo modificado', 'src/app.ts')
  .action(async (options) => {
    console.log(`[Culkibo CLI] Disparando sincronización en caliente para ${options.file}...`);
    const res = await svc.containerOrchestrator.triggerHotSync({ changedFile: options.file });
    console.log(`✨ Sincronizado en ${res.syncDurationMs}ms. Recargas totales: ${res.reloadsTotal}`);
  });

podCmd
  .command('switch <objetivo>')
  .description('Conmuta el tráfico: "desarrollo", "produccion", o reparto e.g. "50/50"')
  .action(async (objetivo) => {
    let forge = 0;
    let citadel = 100;
    const lower = objetivo.toLowerCase();
    if (lower === 'desarrollo' || lower === 'forge') {
      forge = 100;
      citadel = 0;
    } else if (lower === 'produccion' || lower === 'citadel') {
      forge = 0;
      citadel = 100;
    } else if (objetivo.includes('/')) {
      const parts = objetivo.split('/');
      forge = parseInt(parts[0], 10) || 0;
      citadel = parseInt(parts[1], 10) || (100 - forge);
    }
    const res = await svc.containerOrchestrator.switchTraffic({ forgePercent: forge, citadelPercent: citadel });
    console.log(`Tráfico enrutado: ${res.trafficAllocation.citadel}% Producción / ${res.trafficAllocation.forge}% Desarrollo (en ${res.switchDurationMs}ms)`);
  });

// Grupo de comandos para Dominios y SSL
const domainCmd = program.command('domain').description('Gestión de dominios, Cloudflare y certificados SSL');

domainCmd
  .command('list')
  .description('Lista los dominios configurados y el estado de sus certificados')
  .action(() => {
    const domains = svc.domainManager.listDomains();
    console.log('\n--- Dominios Configurados en Culkibo ---');
    console.table(domains.map(d => ({
      Dominio: d.hostname,
      Entorno: d.targetPod === 'forge' ? 'Desarrollo' : 'Producción',
      Puerto: d.targetPort,
      Cloudflare: d.cloudflareProxied ? 'Proxy Activo (Nube Naranja ☁️)' : 'Solo DNS',
      SSL: d.sslStatus === 'active' ? 'Activo' : d.sslStatus,
      Validez: d.certClaim && d.certClaim.daysRemaining != null ? `${d.certClaim.daysRemaining} días` : 'N/D'
    })));
  });

domainCmd
  .command('add <hostname>')
  .description('Añade un nuevo dominio o subdominio comodín (*.dominio.com)')
  .option('--pod <pod>', 'Entorno destino (forge o citadel)', 'citadel')
  .option('--port <port>', 'Puerto destino', '8080')
  .option('--no-proxy', 'Desactivar proxy de Cloudflare')
  .action(async (hostname, options) => {
    try {
      const res = await svc.domainManager.addDomain({
        hostname,
        targetPod: options.pod,
        targetPort: options.port,
        cloudflareProxied: options.proxy
      });
      console.log(`✨ Dominio ${res.hostname} añadido con éxito.`);
    } catch (err) {
      console.error(`❌ Error al añadir dominio: ${err.message}`);
      process.exitCode = 1;
    }
  });

domainCmd
  .command('issue-wildcard <dominio>')
  .description('(No implementado) Emisión de comodín por ACME DNS-01')
  .action(async (dominio) => {
    const res = await svc.sslManager.issueWildcardCertificate({ domain: dominio });
    console.error(`❌ ${res.error}`);
    console.error('\n   Alternativa: configura Wildcard DNS-01 en Caddy con POST /api/ingress/wildcard-dns01 o desde el panel Dominios.');
    process.exitCode = 1;
  });

domainCmd
  .command('toggle-proxy <idODominio>')
  .description('Alterna el proxy de Cloudflare (Nube Naranja vs Solo DNS)')
  .action(async (idODominio) => {
    try {
      const domains = svc.domainManager.listDomains();
      const match = domains.find(d => d.id === idODominio || d.hostname === idODominio);
      if (!match) {
        console.error(`❌ Dominio "${idODominio}" no encontrado.`);
        process.exit(1);
      }
      const updated = await svc.domainManager.toggleProxy(match.id);
      console.log(`✨ Dominio ${updated.hostname}: ${updated.cloudflareProxied ? 'Proxy Cloudflare Activado (Nube Naranja ☁️)' : 'Solo DNS (Nube Gris ☁️)'}`);
    } catch (err) {
      console.error(`❌ Error al alternar proxy: ${err.message}`);
      process.exitCode = 1;
    }
  });

domainCmd
  .command('delete <idODominio>')
  .description('Elimina un dominio configurado')
  .action(async (idODominio) => {
    try {
      const domains = svc.domainManager.listDomains();
      const match = domains.find(d => d.id === idODominio || d.hostname === idODominio);
      if (!match) {
        console.error(`❌ Dominio "${idODominio}" no encontrado.`);
        process.exit(1);
      }
      await svc.domainManager.deleteDomain(match.id);
      console.log(`✨ Dominio ${match.hostname} eliminado con éxito.`);
    } catch (err) {
      console.error(`❌ Error al eliminar dominio: ${err.message}`);
      process.exitCode = 1;
    }
  });

// Comandos de Backup y Restauración
program
  .command('backup <projectId>')
  .description('Genera un paquete de respaldo exportable de un proyecto')
  .action(async (projectId) => {
    try {
      console.log(`[Culkibo Backup] Exportando proyecto ${projectId}...`);
      const res = await svc.dbBackupManager.exportProject(projectId);
      console.log(`\x1b[32m✅ Respaldo generado con éxito:\x1b[0m ${res.fullPath}`);
      console.log(`   Recursos: ${res.resourcesCount} | Dominios: ${res.domainsCount}`);
    } catch (err) {
      console.error(`❌ Error al exportar respaldo:`, err.message);
      process.exitCode = 1;
    }
  });

program
  .command('restore <archivoBackup>')
  .description('Restaura un proyecto a partir de un archivo de respaldo JSON')
  .action(async (archivoBackup) => {
    try {
      console.log(`[Culkibo Restore] Restaurando desde ${archivoBackup}...`);
      const res = await svc.dbBackupManager.restoreProject(archivoBackup, { allowExternalPath: true });
      console.log(`\x1b[32m✅ Proyecto restaurado con éxito:\x1b[0m ${res.restoredName} (ID: ${res.restoredProjectId})`);
    } catch (err) {
      console.error(`❌ Error al restaurar proyecto:`, err.message);
      process.exitCode = 1;
    }
  });

// Grupo Docker
const dockerCmd = program.command('docker').description('Comandos de inspección del motor Docker');

dockerCmd
  .command('status')
  .description('Comprueba la conexión con el daemon de Docker')
  .action(async () => {
    const status = await svc.dockerManager.checkDockerStatus(true);
    console.log('\n--- Estado del Motor Docker ---');
    console.log(`Modo:         ${status.mode === 'docker_native' ? '\x1b[32mNativo (Docker Daemon)\x1b[0m' : '\x1b[33mSandbox de Procesos Ultrarrápido\x1b[0m'}`);
    console.log(`Versión:      ${status.clientVersion || 'N/D'}`);
    console.log(`Contenedores: ${status.containersRunning || 0} activos`);
    console.log(`Mensaje:      ${status.message}\n`);
  });

dockerCmd
  .command('list')
  .description('Lista contenedores en ejecución')
  .action(async () => {
    const list = await svc.dockerManager.listContainers({ all: false });
    console.log('\n--- Contenedores Activos ---');
    console.table(list.map(c => ({
      ID: c.id?.substring(0, 12) || 'N/D',
      Imagen: c.image || 'N/D',
      Estado: c.status || c.state || 'Up',
      Puertos: c.ports || 'N/D',
      Modo: c.mode || 'N/D'
    })));
  });

// Ingress resolution inspector
program
  .command('ingress <hostname>')
  .description('Inspecciona el enrutamiento y SSL para una cabecera Host entrante')
  .action((hostname) => {
    const route = svc.domainManager.resolveRoute(hostname);
    if (!route) {
      console.log(`\n❌ No hay ruta asignada para "${hostname}".`);
      return;
    }
    const cert = svc.sslManager.getCertificateByDomain(hostname);
    const traffic = svc.containerOrchestrator.trafficAllocation;
    console.log(`\n--- Inspector de Enrutamiento Ingress: ${hostname} ---`);
    console.table([
      {
        HostEntrada: hostname,
        Regla: route.hostname,
        Tipo: route.isWildcard ? 'Comodín (*)' : 'Exacto',
        Entorno: route.targetPod === 'forge' ? 'Desarrollo (:3001)' : 'Producción (:8080)',
        Cloudflare: route.cloudflareProxied ? 'Proxy (Nube Naranja ☁️)' : 'Solo DNS',
        TLS: cert
          ? (cert.managedBy ? 'Delegado en Caddy (bajo demanda)' : `En disco (${cert.issuer || 'emisor desconocido'})`)
          : 'Sin anotación en el registro',
        RepartoTráfico: `${traffic.citadel}% Prod / ${traffic.forge}% Dev`
      }
    ]);
  });

// Live Sync (The Forge): sincronización local -> daemon en milisegundos
program
  .command('sync <projectId> [directorio]')
  .description('Sincroniza un directorio local en tiempo real vía Commit Frames + Merkle hacia el daemon')
  .option('-u, --url <wsUrl>', 'URL del WebSocket del daemon', process.env.CULKIBO_SYNC_URL || 'ws://127.0.0.1:3030/ws/sync')
  .option('-t, --token <token>', 'Token de autenticación (CULKIBO_TOKEN)', process.env.CULKIBO_TOKEN || '')
  .option('-q, --quiescence <ms>', 'Ventana de agrupación de ráfagas en ms', '12')
  .option('--no-reconcile', 'Omitir la reconciliación Merkle inicial al conectar')
  .action(async (projectId, directorio = process.cwd(), options) => {
    const client = new svc.LiveSyncClient({
      projectId,
      sourceDir: directorio,
      wsUrl: options.url,
      token: options.token || null,
      quiescenceMs: parseInt(options.quiescence, 10) || 12
    });

    client.on('frame_ack', (ack) => {
      console.log(`⚡ [Forge] Frame #${ack.seq} · ${ack.written} escritos, ${ack.deleted} borrados, ${ack.dedupSkipped} sin cambios · ${ack.applyMs} ms [${ack.mode}]`);
    });
    client.on('sync_error', (err) => {
      console.error(`❌ [Forge] ${err.message}`);
    });
    client.on('error', (err) => {
      console.error(`❌ [Forge:Watcher] ${err.message}`);
    });

    const stopSync = async () => {
      await client.stop();
      process.exit(0);
    };

    try {
      await client.start();
      console.log(`\n⚡ Culkibo Live Sync activo`);
      console.log(`   Proyecto:   ${projectId}`);
      console.log(`   Directorio: ${path.resolve(directorio)}`);
      console.log(`   Destino:    ${options.url}`);
      if (options.reconcile) {
        const rec = await client.reconcileFull();
        console.log(`   Merkle:     ${rec.rootDigest.slice(0, 12)} (${rec.changed} ficheros sincronizados)\n`);
      }
      process.once('SIGINT', stopSync);
      process.once('SIGTERM', stopSync);
    } catch (err) {
      console.error(`❌ No se pudo iniciar Live Sync: ${err.message}`);
      process.exit(1);
    }
  });

// Despliegue a producción y rollback instantáneo
program
  .command('deploy <projectId>')
  .description('Despliega un proyecto a producción (Docker BuildKit + healthcheck + swap Caddy)')
  .option('--no-git-sync', 'Desplegar el árbol local tal cual (promoción desde Forge)')
  .action(async (projectId, options) => {
    try {
      const project = svc.projectManager.getById(projectId);
      if (!project) {
        console.error(`❌ Proyecto "${projectId}" no encontrado.`);
        process.exit(1);
      }
      const result = await svc.deployManager.deploy(project, { gitSync: options.gitSync, trigger: 'cli' });
      if (result.status === 'activo') {
        console.log(`\x1b[32m✅ Despliegue ${result.id} activo en ${result.durationMs} ms (${result.upstream || 'sin ruta'})\x1b[0m`);
        // Esperar al drenaje para no dejar el contenedor anterior vivo al terminar el proceso CLI
        await svc.deployManager.awaitDrain(project.id);
      } else {
        console.error(`❌ Despliegue fallido: ${result.error}`);
        process.exit(1);
      }
    } catch (err) {
      console.error(`❌ Error al desplegar: ${err.message}`);
      process.exit(1);
    }
  });

program
  .command('rollback <projectId>')
  .description('Revierte un proyecto a la versión de producción anterior por conmutación de ruta')
  .action(async (projectId) => {
    const project = svc.projectManager.getById(projectId);
    if (!project) {
      console.error(`❌ Proyecto "${projectId}" no encontrado.`);
      process.exit(1);
    }
    try {
      const result = await svc.deployManager.rollback(project.id);
      console.log(`\x1b[32m✅ Rollback completado (${result.id})\x1b[0m`);
      await svc.deployManager.awaitDrain(project.id);
    } catch (err) {
      console.error(`❌ Error en rollback: ${err.message}`);
      process.exit(1);
    }
  });

// Catálogo de servicios
const catalogCmd = program.command('catalog').description('Catálogo de servicios autohospedados de un clic');
catalogCmd
  .command('list')
  .description('Lista las plantillas disponibles en el catálogo')
  .action(() => {
    const templates = svc.catalogManager.listTemplates();
    console.table(templates.map(t => ({
      ID: t.id,
      Nombre: t.name,
      Categoría: t.categoryLabel,
      Imagen: t.image,
      RAM_Total: `${t.totalMemoryMb} MB`,
      BD: t.database ? t.database.engine : '—'
    })));
  });

// Auto-actualización limpia sin shell
program
  .command('update')
  .description('Actualiza Culkibo desde GitHub (git pull --ff-only + dependencias + panel web)')
  .action(async () => {
    const rootDir = path.resolve(__dirname, '..');
    console.log('\n🔄 Actualizando Culkibo desde origin/main...');
    try {
      await runSpawnStep('git', ['pull', '--ff-only'], rootDir);
      await runSpawnStep('npm', ['install', '--no-audit', '--no-fund'], rootDir);
      await runSpawnStep('npm', ['--prefix', 'web', 'ci', '--no-audit', '--no-fund'], rootDir);
      await runSpawnStep('npm', ['run', 'web:build'], rootDir);
      console.log('\x1b[32m✅ Culkibo actualizado. Reinicia el servicio (p. ej. systemctl restart culkibo) para aplicar cambios.\x1b[0m\n');
    } catch (err) {
      console.error(`\x1b[31m❌ Error al actualizar Culkibo:\x1b[0m ${err.message}`);
      process.exit(1);
    }
  });

// Transporte stdio MCP
program
  .command('mcp')
  .description('Ejecuta el servidor MCP sobre entrada/salida estándar (stdio)')
  .action(() => {
    // En transporte MCP stdio, stdout está reservado 100% a tramas JSON-RPC: redirigir logs de servicios a stderr.
    const toStderr = (...args) => {
      try { process.stderr.write(args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ') + '\n'); } catch (e) {}
    };
    console.log = toStderr;
    console.info = toStderr;
    console.warn = toStderr;

    const mcpServer = svc.mcpServer;
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: false
    });

    rl.on('line', async (line) => {
      try {
        if (!line.trim()) return;
        const request = JSON.parse(line);
        // Las notificaciones JSON-RPC (sin `id`) no llevan respuesta según especificación.
        if (!('id' in request) || request.id === undefined) return;
        const response = await mcpServer.handleJsonRpc(request);
        process.stdout.write(JSON.stringify(response) + '\n');
      } catch (err) {
        process.stdout.write(JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: `Error de parseo: ${err.message}` }
        }) + '\n');
      }
    });

    // P0-6: garantizar escritura atómica en disco al cerrar stdin del transporte MCP stdio
    rl.on('close', () => {
      Promise.resolve(svc.projectManager.flushToDisk()).catch(() => {}).finally(() => {
        process.exit(0);
      });
    });
  });

program.parse(process.argv);
