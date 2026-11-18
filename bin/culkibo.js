#!/usr/bin/env node

const { Command } = require('commander');
const readline = require('readline');
const fs = require('fs');
const path = require('path');
const net = require('net');

const containerOrchestrator = require('../server/services/containerOrchestrator');
const domainManager = require('../server/services/domainManager');
const sslManager = require('../server/services/sslManager');
const cloudflareService = require('../server/services/cloudflareService');
const mcpServer = require('../server/services/mcpServer');
const dockerManager = require('../server/services/dockerManager');
const dbBackupManager = require('../server/services/dbBackupManager');
const projectManager = require('../server/services/projectManager');

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
    const { startServer } = require('../server/index');
    try {
      await startServer(parseInt(options.port, 10) || 3030, '0.0.0.0');
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
    const dockerStatus = await dockerManager.checkDockerStatus(true);
    if (dockerStatus.available) {
      console.log(`\x1b[32m  ✓ Motor Docker:\x1b[0m Activo (${dockerStatus.serverVersion}) — Modo Nativo`);
    } else {
      console.log(`\x1b[33m  ⚠️ Motor Docker:\x1b[0m Inactivo o no detectado. Modo Sandbox de Procesos activado`);
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
    const cfConfig = cloudflareService.config;
    if (cfConfig.apiToken) {
      console.log(`\x1b[32m  ✓ Cloudflare API:\x1b[0m Token configurado correctamente`);
    } else {
      console.log(`\x1b[33m  ⚠️ Cloudflare API:\x1b[0m Token no configurado (usando emulador local de zonas)`);
    }

    // 5. Verificación de puertos
    const checkPort = (port) => new Promise(resolve => {
      const tester = net.createServer()
        .once('error', err => resolve({ port, free: false, error: err.code }))
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
      const res = containerOrchestrator.watchDirectory(directorio);
      console.log(`\n⚡ [Desarrollo] Monitoreando ${res.directory} (${res.fileWatchersActive} rutas vigiladas)`);
      console.log(`   Vigilancia activa. Los cambios se detectan y registran; el transporte al pod remoto aún no está implementado.\n`);

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
    const data = containerOrchestrator.getPods();
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
    const res = await containerOrchestrator.triggerHotSync({ changedFile: options.file });
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
    const res = await containerOrchestrator.switchTraffic({ forgePercent: forge, citadelPercent: citadel });
    console.log(`Tráfico enrutado: ${res.trafficAllocation.citadel}% Producción / ${res.trafficAllocation.forge}% Desarrollo (en ${res.switchDurationMs}ms)`);
  });

// Grupo de comandos para Dominios y SSL
const domainCmd = program.command('domain').description('Gestión de dominios, Cloudflare y certificados SSL');

domainCmd
  .command('list')
  .description('Lista los dominios configurados y el estado de sus certificados')
  .action(() => {
    const domains = domainManager.listDomains();
    console.log('\n--- Dominios Configurados en Culkibo ---');
    console.table(domains.map(d => ({
      Dominio: d.hostname,
      Entorno: d.targetPod === 'forge' ? 'Desarrollo' : 'Producción',
      Puerto: d.targetPort,
      Cloudflare: d.cloudflareProxied ? 'Proxy Activo (Nube Naranja ☁️)' : 'Solo DNS',
      SSL: d.sslStatus === 'active' ? 'Activo' : d.sslStatus,
      Validez: d.certInfo ? `${d.certInfo.daysRemaining} días` : 'N/D'
    })));
  });

domainCmd
  .command('add <hostname>')
  .description('Añade un nuevo dominio o subdominio comodín (*.dominio.com)')
  .option('--pod <pod>', 'Entorno destino (forge o citadel)', 'citadel')
  .option('--port <port>', 'Puerto destino', 8080)
  .option('--no-proxy', 'Desactivar proxy de Cloudflare')
  .action(async (hostname, options) => {
    try {
      const res = await domainManager.addDomain({
        hostname,
        targetPod: options.pod,
        targetPort: options.port,
        cloudflareProxied: options.proxy
      });
      console.log(`✨ Dominio ${res.hostname} añadido con éxito.`);
    } catch (err) {
      console.error(`❌ Error al añadir dominio: ${err.message}`);
    }
  });

domainCmd
  .command('issue-wildcard <dominio>')
  .description('(No implementado) Emisión de comodín por ACME DNS-01')
  .action(async (dominio) => {
    const res = await sslManager.issueWildcardCertificate({ domain: dominio });
    // Nunca devuelve success. Se mantiene el comando —y sale con código 1— para
    // que quien lo tuviera en un script se entere en vez de creer que funcionó.
    console.error(`❌ ${res.error}`);
    console.error('\n   Alternativa: registra el dominio con `culkibo domain add` y deja que');
    console.error('   Caddy emita el certificado en la primera conexión HTTPS.');
    console.error('   Comprueba el resultado real con `culkibo ingress <hostname>`.');
    process.exitCode = 1;
  });

domainCmd
  .command('toggle-proxy <idODominio>')
  .description('Alterna el proxy de Cloudflare (Nube Naranja vs Solo DNS)')
  .action(async (idODominio) => {
    try {
      const domains = domainManager.listDomains();
      const match = domains.find(d => d.id === idODominio || d.hostname === idODominio);
      if (!match) {
        console.error(`❌ Dominio "${idODominio}" no encontrado.`);
        process.exit(1);
      }
      const updated = await domainManager.toggleProxy(match.id);
      console.log(`✨ Dominio ${updated.hostname}: ${updated.cloudflareProxied ? 'Proxy Cloudflare Activado (Nube Naranja ☁️)' : 'Solo DNS (Nube Gris ☁️)'}`);
    } catch (err) {
      console.error(`❌ Error al alternar proxy: ${err.message}`);
    }
  });

domainCmd
  .command('delete <idODominio>')
  .description('Elimina un dominio configurado')
  .action(async (idODominio) => {
    try {
      const domains = domainManager.listDomains();
      const match = domains.find(d => d.id === idODominio || d.hostname === idODominio);
      if (!match) {
        console.error(`❌ Dominio "${idODominio}" no encontrado.`);
        process.exit(1);
      }
      await domainManager.deleteDomain(match.id);
      console.log(`✨ Dominio ${match.hostname} eliminado con éxito.`);
    } catch (err) {
      console.error(`❌ Error al eliminar dominio: ${err.message}`);
    }
  });

// Comandos de Backup y Restauración
program
  .command('backup <projectId>')
  .description('Genera un paquete de respaldo exportable de un proyecto')
  .action(async (projectId) => {
    try {
      console.log(`[Culkibo Backup] Exportando proyecto ${projectId}...`);
      const res = await dbBackupManager.exportProject(projectId);
      console.log(`\x1b[32m✅ Respaldo generado con éxito:\x1b[0m ${res.fullPath}`);
      console.log(`   Recursos: ${res.resourcesCount} | Dominios: ${res.domainsCount}`);
    } catch (err) {
      console.error(`❌ Error al exportar respaldo:`, err.message);
    }
  });

program
  .command('restore <archivoBackup>')
  .description('Restaura un proyecto a partir de un archivo de respaldo JSON')
  .action(async (archivoBackup) => {
    try {
      console.log(`[Culkibo Restore] Restaurando desde ${archivoBackup}...`);
      const res = await dbBackupManager.restoreProject(archivoBackup);
      console.log(`\x1b[32m✅ Proyecto restaurado con éxito:\x1b[0m ${res.restoredName} (ID: ${res.restoredProjectId})`);
    } catch (err) {
      console.error(`❌ Error al restaurar proyecto:`, err.message);
    }
  });

// Grupo Docker
const dockerCmd = program.command('docker').description('Comandos de inspección del motor Docker');

dockerCmd
  .command('status')
  .description('Comprueba la conexión con el daemon de Docker')
  .action(async () => {
    const status = await dockerManager.checkDockerStatus(true);
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
    const list = await dockerManager.listContainers({ all: false });
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
    const route = domainManager.resolveRoute(hostname);
    if (!route) {
      console.log(`\n❌ No hay ruta asignada para "${hostname}".`);
      return;
    }
    const cert = sslManager.getCertificateByDomain(hostname);
    const traffic = containerOrchestrator.trafficAllocation;
    console.log(`\n--- Inspector de Enrutamiento Ingress: ${hostname} ---`);
    console.table([
      {
        HostEntrada: hostname,
        Regla: route.hostname,
        Tipo: route.isWildcard ? 'Comodín (*)' : 'Exacto',
        Entorno: route.targetPod === 'forge' ? 'Desarrollo (:3001)' : 'Producción (:8080)',
        Cloudflare: route.cloudflareProxied ? 'Proxy (Nube Naranja ☁️)' : 'Solo DNS',
        // «Según el registro», no «Activo»: esto es una anotación propia, no un
        // handshake. Un certificado delegado a Caddy no tiene emisor conocido.
        TLS: cert
          ? (cert.managedBy ? 'Delegado en Caddy (bajo demanda)' : `En disco (${cert.issuer || 'emisor desconocido'})`)
          : 'Sin anotación en el registro',
        RepartoTráfico: `${traffic.citadel}% Prod / ${traffic.forge}% Dev`
      }
    ]);
  });

// Transporte stdio MCP
program
  .command('mcp')
  .description('Ejecuta el servidor MCP sobre entrada/salida estándar (stdio)')
  .action(() => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: false
    });

    rl.on('line', async (line) => {
      try {
        if (!line.trim()) return;
        const request = JSON.parse(line);
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
  });

program.parse(process.argv);
