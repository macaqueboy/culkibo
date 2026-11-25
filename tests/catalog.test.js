const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');

const catalogManager = require('../server/services/catalogManager');
const {
  CatalogManager,
  resolvePlaceholders,
  resolveEnv,
  generateSecret,
  orderSidecars,
  parseImageRef,
  resolveCoupledSidecarImage,
  BACKUP_IMAGE,
  STEPS,
  PORT_RANGE
} = require('../server/services/catalogManager');
const {
  TEMPLATES,
  CATEGORIES,
  validateTemplate,
  validateCatalog,
  IMAGE_RE,
  FLOATING_TAG_RE
} = require('../server/services/catalog/templates');

/**
 * Pruebas exhaustivas del catálogo de servicios de un clic.
 *
 * No requieren un demonio Docker vivo: validan estáticamente las 140+ plantillas
 * y prueban el ciclo de vida completo de `CatalogManager` (orden topológico,
 * sondas TCP/exec, fail-fast, rollback de imagen + sidecars acoplados, detección
 * de drift, contratos getEnv/getStats, registro de extraPorts, copias de
 * volúmenes con verificación SHA-256 y redacción de secretos) contra instancias
 * aisladas en `os.tmpdir()` sin tocar `data/*.json`.
 */
async function testCatalog() {
  console.log('🧪 Probando el catálogo de servicios de un clic...');

  // -------------------------------------------------------------------------
  // 1. El catálogo entero pasa su propia validación y supera 140 plantillas
  // -------------------------------------------------------------------------
  const problems = validateCatalog();
  assert.deepStrictEqual(problems, [], `El catálogo tiene problemas de formato:\n${problems.join('\n')}`);
  assert.ok(TEMPLATES.length >= 140, `El catálogo debe traer al menos 140 plantillas (actual: ${TEMPLATES.length})`);
  const requiredIds = [
    'wordpress', 'n8n', 'plausible', 'glitchtip', 'hoppscotch', 'immich',
    'langfuse', 'dify', 'librechat', 'lobechat', 'langflow', 'perplexica', 'milvus',
    'authelia', 'zitadel', 'logto', 'twofauth', 'headscale', 'guacamole', 'adguard-home',
    'outline', 'affine', 'calcom', 'docuseal', 'actual-budget', 'firefly-iii',
    'karakeep', 'linkwarden', 'linkding', 'grist',
    'it-tools', 'excalidraw', 'glance', 'rabbitmq', 'nats', 'garage', 'backrest', 'adminer',
    'syncthing', 'kavita', 'komga', 'calibre-web', 'owncast',
    'openobserve', 'alertmanager', 'miniflux'
  ];
  for (const id of requiredIds) {
    assert.ok(TEMPLATES.some((t) => t.id === id), `Falta la plantilla requerida «${id}»`);
  }
  console.log(`  ✓ ${TEMPLATES.length} plantillas válidas en ${CATEGORIES.length} categorías (incluye las 40 nuevas top 2025–2026)`);

  // -------------------------------------------------------------------------
  // 2. Ninguna imagen usa etiqueta móvil (FLOATING_TAG_RE completo) ni docker.sock
  // -------------------------------------------------------------------------
  assert.ok(IMAGE_RE.test(BACKUP_IMAGE) && !FLOATING_TAG_RE.test(BACKUP_IMAGE), `BACKUP_IMAGE debe estar fijada: ${BACKUP_IMAGE}`);
  for (const tpl of TEMPLATES) {
    const images = [tpl.app.image, ...(tpl.sidecars || []).map((c) => c.image)];
    if (tpl.database && tpl.database.image) images.push(tpl.database.image);
    for (const image of images) {
      assert.ok(IMAGE_RE.test(image), `${tpl.id}: imagen inválida ${image}`);
      assert.ok(!FLOATING_TAG_RE.test(image), `${tpl.id}: ${image} usa etiqueta móvil`);
    }
    const runtimeSpec = JSON.stringify({ app: tpl.app, sidecars: tpl.sidecars || [], database: tpl.database });
    assert.ok(!runtimeSpec.includes('docker.sock'), `${tpl.id}: referencia prohibida a docker.sock`);
    assert.ok(!runtimeSpec.includes('Europe/Madrid'), `${tpl.id}: zona horaria hardcodeada (usa {{tz}})`);

    // Comprobar que ningún comando sin shell intenta expandir `$VAR` literalmente
    const cmds = [{ role: 'app', cmd: tpl.app.command }, ...(tpl.sidecars || []).map((s) => ({ role: s.name, cmd: s.command }))];
    for (const { role, cmd } of cmds) {
      if (!cmd) continue;
      if (cmd[0] !== 'sh' && cmd[0] !== '/bin/sh' && cmd[0] !== 'bash') {
        assert.ok(!JSON.stringify(cmd).includes('$'), `${tpl.id}/${role}: comando sin shell contiene $VAR sin expandir`);
      }
    }
  }
  console.log('  ✓ 100% imágenes fijadas (0 :latest/móviles), 0 docker.sock y 0 TZ hardcodeada');

  // -------------------------------------------------------------------------
  // 3. Límites, volúmenes, sondas y grafo topológico en todas
  // -------------------------------------------------------------------------
  for (const tpl of TEMPLATES) {
    assert.ok(tpl.app.memoryMb >= 128, `${tpl.id}: sin límite de memoria`);
    assert.ok(tpl.app.cpus > 0, `${tpl.id}: sin límite de CPU`);
    assert.ok(tpl.app.readiness && tpl.app.readiness.path.startsWith('/'), `${tpl.id}: sonda inválida`);
    assert.ok(tpl.app.readiness.expect.length > 0, `${tpl.id}: la sonda no declara códigos esperados`);
    const persists = Boolean(tpl.database) || (tpl.app.volumes || []).length > 0;
    assert.ok(persists, `${tpl.id}: no persiste nada`);
    assert.doesNotThrow(() => orderSidecars(tpl.sidecars || []), `${tpl.id}: dependsOn inválido`);
  }
  console.log('  ✓ Todas declaran límites de recursos, persistencia, sonda y grafo acíclico');

  // -------------------------------------------------------------------------
  // 4. Resolución completa con dominio HTTPS y en modo local (`domain: null`)
  // -------------------------------------------------------------------------
  for (const tpl of TEMPLATES) {
    const secrets = {};
    for (const [key, spec] of Object.entries(tpl.secrets || {})) secrets[key] = generateSecret(spec);

    const modes = [
      { label: 'https', domain: 'servicio.ejemplo.com', hostPort: 42000, url: 'https://servicio.ejemplo.com', tz: 'UTC' },
      { label: 'local', domain: null, hostPort: 42000, url: 'http://127.0.0.1:42000', tz: 'UTC' }
    ];

    for (const mode of modes) {
      const context = {
        installId: 'svc_prueba_00000000',
        ...mode,
        secrets,
        db: tpl.database
          ? { host: tpl.database.engine, port: 5432, user: 'u', password: 'p', name: 'd', url: 'postgresql://u:p@h/d' }
          : null,
        sidecarHosts: Object.fromEntries((tpl.sidecars || []).map((c) => [c.name, `culkibo_svc_x_${c.name}`]))
      };

      const resolvedApp = resolveEnv(tpl.app.env, context);
      const allValues = [...Object.values(resolvedApp)];
      for (const [key, value] of Object.entries(resolvedApp)) {
        assert.ok(!value.includes('{{'), `${tpl.id} (${mode.label}): ${key} deja marcador sin resolver: ${value}`);
        if (mode.label === 'local') {
          assert.ok(!value.includes('@127.0.0.1:'), `${tpl.id}: correo roto en modo local (${key}=${value})`);
          assert.ok(!value.startsWith('wss://127.0.0.1:'), `${tpl.id}: wss:// sobre HTTP local (${key}=${value})`);
        }
      }
      for (const car of tpl.sidecars || []) {
        const resolvedCar = resolveEnv(car.env, context);
        allValues.push(...Object.values(resolvedCar));
        for (const [key, value] of Object.entries(resolvedCar)) {
          assert.ok(!value.includes('{{'), `${tpl.id}/${car.name} (${mode.label}): ${key} deja marcador sin resolver`);
          if (mode.label === 'local') {
            assert.ok(!value.includes('@127.0.0.1:'), `${tpl.id}/${car.name}: correo roto en modo local (${key}=${value})`);
          }
        }
      }

      for (const [key, value] of Object.entries(secrets)) {
        assert.ok(allValues.some((v) => v.includes(value)), `${tpl.id}: el secreto ${key} se genera pero no llega a ninguna variable`);
      }
    }
  }
  console.log(`  ✓ Las ${TEMPLATES.length} plantillas resuelven limpio tanto en HTTPS como en modo local (domain: null)`);

  // -------------------------------------------------------------------------
  // 5. Nuevos marcadores ({{host}}, {{wsProtocol}}, {{tz}}) y rechazo de desconocidos
  // -------------------------------------------------------------------------
  const ctxHttps = { installId: 'svc_x_0', domain: 'app.ejemplo.com', hostPort: 42010, url: 'https://app.ejemplo.com', tz: 'America/New_York', secrets: { A: '1' }, db: null, sidecarHosts: {} };
  const ctxLocal = { installId: 'svc_x_0', domain: null, hostPort: 42010, url: 'http://127.0.0.1:42010', tz: 'UTC', secrets: { A: '1' }, db: null, sidecarHosts: {} };
  assert.strictEqual(resolvePlaceholders('{{secret.A}}', ctxHttps), '1');
  assert.strictEqual(resolvePlaceholders('pre-{{domain}}-post', ctxHttps), 'pre-app.ejemplo.com-post');
  assert.strictEqual(resolvePlaceholders('noreply@{{host}}|{{wsProtocol}}|{{tz}}', ctxHttps), 'noreply@app.ejemplo.com|wss|America/New_York');
  assert.strictEqual(resolvePlaceholders('noreply@{{host}}|{{wsProtocol}}|{{tz}}', ctxLocal), 'noreply@127.0.0.1|ws|UTC');
  assert.throws(() => resolvePlaceholders('{{secret.NOEXISTE}}', ctxHttps), /Marcador desconocido/);
  assert.throws(() => resolvePlaceholders('{{inventado}}', ctxHttps), /Marcador desconocido/);
  assert.throws(() => resolvePlaceholders('{{db.url}}', ctxHttps), /requiere una base de datos/);
  assert.throws(() => resolvePlaceholders('{{sidecar.fantasma.host}}', ctxHttps), /Marcador desconocido/);
  console.log('  ✓ Marcadores {{host}}/{{wsProtocol}}/{{tz}} verificados y marcadores desconocidos rechazados');

  // -------------------------------------------------------------------------
  // 6. Secretos: entropía y alfabeto
  // -------------------------------------------------------------------------
  const hex = generateSecret({ bytes: 32, encoding: 'hex' });
  assert.strictEqual(hex.length, 64);
  assert.ok(/^[0-9a-f]+$/.test(hex), 'hex debe ser hexadecimal');
  const urlSafe = generateSecret({ bytes: 24, encoding: 'base64url' });
  assert.ok(/^[A-Za-z0-9_-]+$/.test(urlSafe), 'base64url no puede traer +, / ni =');
  const b64 = generateSecret({ bytes: 64, encoding: 'base64' });
  assert.strictEqual(Buffer.from(b64, 'base64').length, 64, 'base64 debe decodificar a los bytes pedidos');
  assert.notStrictEqual(generateSecret({ bytes: 32, encoding: 'hex' }), hex);
  assert.ok(Buffer.from(generateSecret({ bytes: 4, encoding: 'hex' }), 'hex').length >= 16);
  console.log('  ✓ Secretos con alfabeto correcto y suelo de entropía de 16 bytes');

  // -------------------------------------------------------------------------
  // 7. La validación rechaza todas las formas de plantilla rota (18 casos)
  // -------------------------------------------------------------------------
  const base = {
    id: 'prueba', name: 'Prueba', category: 'datos', summary: 's', description: 'd',
    licence: 'MIT', website: 'https://x', secrets: {},
    app: {
      image: 'ejemplo/imagen:1.0', port: 80, memoryMb: 256, cpus: 1,
      env: {}, volumes: [{ name: 'data', path: '/data' }],
      readiness: { path: '/', expect: [200] }
    }
  };
  assert.deepStrictEqual(validateTemplate(base), [], 'La plantilla de referencia debe ser válida');

  const cases = [
    [{ ...base, app: { ...base.app, image: 'ejemplo/imagen:latest' } }, /latest/],
    [{ ...base, app: { ...base.app, image: 'ejemplo/imagen:canary' } }, /canary/],
    [{ ...base, app: { ...base.app, memoryMb: 0 } }, /límite de memoria/],
    [{ ...base, app: { ...base.app, readiness: null } }, /sonda de disponibilidad/],
    [{ ...base, app: { ...base.app, volumes: [] } }, /no sobrevivirían/],
    [{ ...base, category: 'inventada' }, /categoría desconocida/],
    [{ ...base, id: 'MAYUSCULAS' }, /id inválido/],
    [{ ...base, app: { ...base.app, env: { X: '{{secret.SIN_DECLARAR}}' } } }, /sin declararlo/],
    [{ ...base, secrets: { HUERFANO: { bytes: 32, encoding: 'hex' } } }, /no lo usa/],
    [{ ...base, app: { ...base.app, env: { X: '{{db.url}}' } } }, /no declara ninguna base de datos/],
    [{ ...base, secrets: { DEBIL: { bytes: 4, encoding: 'hex' } }, app: { ...base.app, env: { X: '{{secret.DEBIL}}' } } }, /menos de 16 bytes/],
    [{ ...base, app: { ...base.app, volumes: [{ name: 'sock', path: '/var/run/docker.sock' }] } }, /docker\.sock/],
    [{ ...base, app: { ...base.app, files: [{ name: 'a.conf', path: '/etc/a.conf', content: 'k={{secret.X}}' }] } }, /texto plano/],
    [{ ...base, app: { ...base.app, shmSize: '1gb' } }, /shmSize inválido/],
    [{ ...base, app: { ...base.app, extraPorts: [{ containerPort: 80, label: 'dup' }] } }, /colisiona con app\.port/],
    [{ ...base, app: { ...base.app, env: { X: '{{desconocido}}' } } }, /marcador desconocido/i],
    [{
      ...base,
      sidecars: [
        { name: 'a', image: 'img/a:1.0', memoryMb: 128, cpus: 0.5, dependsOn: ['fantasma'] }
      ]
    }, /depende de «fantasma»/],
    [{
      ...base,
      sidecars: [
        { name: 'a', image: 'img/a:1.0', memoryMb: 128, cpus: 0.5, dependsOn: ['b'] },
        { name: 'b', image: 'img/b:1.0', memoryMb: 128, cpus: 0.5, dependsOn: ['a'] }
      ]
    }, /dependencia circular/i]
  ];
  for (const [bad, pattern] of cases) {
    const found = validateTemplate(bad);
    assert.ok(found.length > 0, `Debería rechazarse: ${pattern}`);
    assert.ok(found.some((p) => pattern.test(p)), `Se esperaba ${pattern}, se obtuvo: ${found.join(' | ')}`);
  }
  console.log(`  ✓ La validación rechaza las ${cases.length} formas de plantilla rota (incl. docker.sock y ciclos)`);

  // -------------------------------------------------------------------------
  // 8. Nombres seguros, reserva de puerto SIN fugas y rechazo de entradas malas
  // -------------------------------------------------------------------------
  const id = 'svc_uptime-kuma_deadbeef';
  assert.ok(/^[a-z0-9_-]+$/.test(catalogManager.containerName(id, 'app')));
  assert.ok(/^[a-z0-9_-]+$/.test(catalogManager.volumeName(id, 'data')));
  assert.ok(/^[a-z0-9_-]+$/.test(catalogManager.networkName(id)));
  assert.throws(() => catalogManager.mustGet('no-es-un-id'), /inválido/);
  assert.throws(() => catalogManager.mustGet('svc_x_$(whoami)'), /inválido/);

  const testOwner = 'test_catalog_port_check';
  const port = await catalogManager.allocatePort(testOwner);
  try {
    assert.ok(port >= PORT_RANGE.start && port <= PORT_RANGE.end, `Puerto fuera del rango: ${port}`);
    assert.ok(await catalogManager.portIsFree(port), 'El puerto reservado debe estar realmente libre');
  } finally {
    catalogManager.releasePort(port, testOwner);
    assert.ok(!catalogManager.pendingPorts.has(port), 'releasePort debe limpiar pendingPorts');
  }

  await assert.rejects(() => catalogManager.install({ templateId: 'no-existe' }), /no existe en el catálogo/);
  await assert.rejects(
    () => catalogManager.install({ templateId: 'uptime-kuma', domain: 'esto no es un dominio' }),
    /Dominio inválido|Docker no está disponible/
  );
  await assert.rejects(
    () => catalogManager.install({ templateId: 'uptime-kuma', env: { 'BAD-KEY': '1' } }),
    /Nombre de variable inválido/
  );
  await assert.rejects(
    () => catalogManager.install({ templateId: 'uptime-kuma', env: { GOOD_KEY: 'line1\nline2' } }),
    /saltos de línea/
  );
  await assert.rejects(
    () => catalogManager.install({ templateId: 'uptime-kuma', tz: 'UTC; rm -rf /' }),
    /Zona horaria inválida/
  );
  console.log('  ✓ Nombres seguros, reserva/liberación de puertos sin fugas y validaciones pre-vuelo OK');

  // -------------------------------------------------------------------------
  // 9. La proyección pública nunca filtra secretos y expone drift/extraPorts
  // -------------------------------------------------------------------------
  const fake = {
    id: 'svc_prueba_12345678', templateId: 'uptime-kuma', templateName: 'Uptime Kuma',
    name: 'X', category: 'monitorizacion', image: 'louislam/uptime-kuma:1.0.0', domain: null, url: 'http://127.0.0.1:42000',
    hostPort: 42000, appPort: 3001, extraPorts: { '4317': 42001 }, containerName: 'c', networkName: 'n', sidecars: [],
    volumes: {}, databaseId: null, memoryMb: 512, cpus: 1, status: 'running', health: 'healthy',
    progress: null, createdAt: 'a', updatedAt: 'b',
    secretsEnc: { UN_SECRETO: 'v1:aaa:bbb:ccc' }
  };
  const pub = catalogManager.toPublic(fake);
  const proyectado = JSON.stringify(pub);
  assert.ok(proyectado.includes('UN_SECRETO'), 'El nombre del secreto sí se publica');
  assert.ok(!proyectado.includes('v1:aaa'), 'El valor cifrado NO puede salir en la proyección pública');
  assert.ok(!proyectado.includes('secretsEnc'), 'La proyección pública no expone el almacén de secretos');
  assert.strictEqual(pub.updateAvailable, true, 'Debe detectar actualización disponible frente al catálogo');
  assert.deepStrictEqual(pub.extraPorts, { '4317': 42001 });
  console.log('  ✓ Proyección pública segura (0 fugas) con detección de drift y extraPorts');

  // -------------------------------------------------------------------------
  // 10. Orden topológico, parseImageRef y acoplamiento de imágenes
  // -------------------------------------------------------------------------
  const difyTpl = catalogManager.getTemplate('dify');
  const difyOrder = orderSidecars(difyTpl.sidecars);
  assert.deepStrictEqual(difyOrder.preApp.map((s) => s.name), ['valkey', 'api']);
  assert.deepStrictEqual(difyOrder.postApp.map((s) => s.name), ['worker']);
  assert.deepStrictEqual(parseImageRef('localhost:5000/org/app:1.2.3'), { repo: 'localhost:5000/org/app', tag: '1.2.3' });
  assert.strictEqual(
    resolveCoupledSidecarImage({ image: 'ghcr.io/immich-app/immich-machine-learning:v1.125.0', coupledTagOnly: true }, 'x', 'ghcr.io/immich-app/immich-server:v1.130.0'),
    'ghcr.io/immich-app/immich-machine-learning:v1.130.0'
  );
  console.log('  ✓ Orden topológico (preApp/postApp) y resolución de imágenes acopladas verificados');

  // -------------------------------------------------------------------------
  // 11. Pruebas de ciclo de vida aislado en `os.tmpdir()` con Docker simulado
  // -------------------------------------------------------------------------
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-catalog-test-'));
  let tcpSrv = null;
  try {
    const cm = new CatalogManager({ dataDir: tmpDir, registerPorts: false });

    // --- 11a. Sonda TCP real contra un socket loopback vivo + fail-fast en puerto cerrado
    tcpSrv = net.createServer((sock) => sock.end());
    await new Promise((resolve) => tcpSrv.listen(0, '127.0.0.1', resolve));
    const livePort = /** @type {net.AddressInfo} */ (tcpSrv.address()).port;
    const closedSrv = net.createServer();
    await new Promise((resolve) => closedSrv.listen(0, '127.0.0.1', resolve));
    const deadPort = /** @type {net.AddressInfo} */ (closedSrv.address()).port;
    await new Promise((resolve) => closedSrv.close(resolve));

    cm.docker = async (args) => {
      if (args[0] === 'inspect' && String(args[2]).includes('IPAddress')) {
        return { stdout: 'true|false|127.0.0.1 \n', stderr: '' };
      }
      if (args[0] === 'inspect') return { stdout: 'true\n', stderr: '' };
      if (args[0] === 'exec') throw new Error('exec exit 1');
      return { stdout: '', stderr: '' };
    };

    const tcpOk = await cm.waitSidecarReady('test_tcp_ok', { type: 'tcp', port: livePort, timeoutMs: 2500 }, { hostOverride: '127.0.0.1' });
    assert.strictEqual(tcpOk.ok, true);
    assert.strictEqual(tcpOk.mode, 'tcp');

    await assert.rejects(
      () => cm.waitSidecarReady('test_tcp_fail', { type: 'tcp', port: deadPort, timeoutMs: 600 }, { hostOverride: '127.0.0.1' }),
      /no escuchó en TCP/
    );
    await assert.rejects(
      () => cm.waitSidecarReady('test_exec_fail', { type: 'exec', cmd: ['valkey-cli', 'ping'], timeoutMs: 600 }),
      /no superó su sonda exec/
    );
    console.log('  ✓ Sonda TCP real (pasa en socket vivo, falla en puerto cerrado) y exec fail-fast OK');

    // --- 11b. `--mount` seguro en materialiseFiles + guardia cgroupv2 `--memory-swap`
    const calls = [];
    cm._swapLimitSupported = null;
    cm.docker = async (args) => {
      calls.push([...args]);
      if (args[0] === 'info') return { stdout: 'false\n', stderr: '' };
      return { stdout: 'cid_1234567890abcdef\n', stderr: '' };
    };
    const mounts = cm.materialiseFiles('svc_glance_00000001', 'app', [
      { name: 'glance.yml', path: '/app/config/glance.yml', content: 'pages: []\n' }
    ]);
    assert.strictEqual(mounts.length, 1);
    assert.ok(mounts[0].hostPath.includes('glance.yml') && !mounts[0].hostPath.includes('\\'));
    await cm.runContainer({
      containerName: 'culkibo_svc_glance_00000001_app',
      image: 'glanceapp/glance:v0.8.4',
      networkName: 'culkibo_net_svc_glance_00000001',
      networkAlias: 'app',
      env: { TZ: 'UTC' },
      volumes: ['culkibo_svcdata_test_assets:/app/assets'],
      files: mounts,
      memoryMb: 128,
      cpus: 0.25,
      publish: ['127.0.0.1:42099:8080'],
      labels: { 'culkibo.service': 'svc_glance_00000001', 'culkibo.role': 'app' }
    });
    const runArgv = calls.find((c) => c[0] === 'run');
    assert.ok(runArgv, 'Debe invocarse docker run');
    assert.ok(!runArgv.includes('--memory-swap'), 'Sin soporte de swap en kernel debe omitirse --memory-swap');
    const mountIdx = runArgv.indexOf('--mount');
    assert.ok(mountIdx > 0 && runArgv[mountIdx + 1].includes('type=bind,source=') && runArgv[mountIdx + 1].endsWith(',readonly'));
    assert.ok(runArgv.includes('--security-opt') && runArgv.includes('no-new-privileges'));
    assert.throws(() => cm.materialiseFiles('svc_glance_00000001', 'app', [{ name: '../escape', path: '/etc/x', content: '' }]), /inválido/);
    await assert.rejects(() => cm.runContainer({
      containerName: 'c', image: 'a:1', networkName: 'n', networkAlias: 'a', env: {},
      volumes: ['/var/run/docker.sock:/var/run/docker.sock'], files: [], memoryMb: 128, cpus: 1,
      labels: { 'culkibo.service': 'svc_x_00000000' }
    }), /docker\.sock prohibido/);
    console.log('  ✓ Montaje --mount (Windows/Linux), guardia --memory-swap y bloqueo docker.sock OK');

    // --- 11c. Ciclo completo: extraPorts, getEnv/updateEnv, updateImage acoplado + rollback, drift, logs, stats, backup/restore SHA-256
    const dockerTimeline = [];
    cm._swapLimitSupported = true;
    cm.isDockerAvailable = async () => true;
    let probeShouldPass = true;
    cm.waitUntilReady = async () => ({
      healthy: probeShouldPass,
      status: probeShouldPass ? 200 : 503,
      detail: probeShouldPass ? 'HTTP 200' : 'HTTP 503',
      attempts: 1,
      checkedAt: new Date().toISOString()
    });
    cm.waitSidecarReady = async (name) => {
      dockerTimeline.push(`wait:${name}`);
      return { ok: true, mode: 'mock' };
    };
    cm.docker = async (args) => {
      dockerTimeline.push(args.join(' '));
      if (args[0] === 'run' && args.includes(BACKUP_IMAGE)) {
        // Simular creación del tar.gz en la carpeta --mount
        const mArg = args[args.indexOf('--mount') + 1] || '';
        const srcMatch = mArg.match(/source=([^,]+)/);
        const tarIdx = args.indexOf('-czf');
        if (srcMatch && tarIdx !== -1) {
          const archiveName = path.basename(args[tarIdx + 1]);
          fs.writeFileSync(path.join(srcMatch[1], archiveName), Buffer.from('mock-tar-gz-payload-culkibo'));
        }
        return { stdout: '', stderr: '' };
      }
      if (args[0] === 'stats') {
        const cname = args[args.length - 1];
        return { stdout: `${cname}|1.50%|42MiB / 512MiB|8.20%|1kB / 2kB|12\n`, stderr: '' };
      }
      if (args[0] === 'logs') {
        return { stdout: 'boot ok token=SUPER_SECRET_CUSTOM_VAL_9999\n', stderr: '' };
      }
      return { stdout: 'cid_mock_001\n', stderr: '' };
    };

    // Inyectar registro multi-contenedor tipo Immich (app + valkey + ml coupledTagOnly) con extraPorts y volúmenes
    const immichTpl = cm.getTemplate('immich');
    const recId = 'svc_immich_aabbccdd';
    const origBuildCtx = cm.buildRuntimeContext.bind(cm);
    cm.buildRuntimeContext = (r, t) => {
      const ctx = origBuildCtx(r, t);
      if (t.database && !ctx.db) {
        ctx.db = { host: t.database.engine, port: 5432, user: 'immich', password: 'mock_db_password_12345', name: 'immich', url: 'postgresql://immich:mock_db_password_12345@postgres:5432/immich' };
      }
      return ctx;
    };
    const rec = {
      id: recId,
      templateId: 'immich',
      name: 'Immich Fotos',
      templateName: immichTpl.name,
      category: immichTpl.category,
      image: immichTpl.app.image,
      domain: null,
      url: 'http://127.0.0.1:42555',
      tz: 'UTC',
      domainId: null,
      hostPort: 42555,
      appPort: immichTpl.app.port,
      extraPorts: { '4317': 42556 },
      containerName: cm.containerName(recId, 'app'),
      networkName: cm.networkName(recId),
      volumes: { uploads: cm.volumeName(recId, 'uploads') },
      sidecars: [
        { name: 'valkey', image: 'valkey/valkey:8.1-alpine', containerName: cm.containerName(recId, 'valkey'), startAfterApp: false, coupledWithApp: false, coupledTagOnly: false, volumes: { data: cm.volumeName(recId, 'valkey_data') } },
        { name: 'ml', image: 'ghcr.io/immich-app/immich-machine-learning:v1.125.0', containerName: cm.containerName(recId, 'ml'), startAfterApp: false, coupledWithApp: true, coupledTagOnly: true, volumes: { cache: cm.volumeName(recId, 'ml_cache') } }
      ],
      databaseId: null,
      secretsEnc: {},
      customEnvEnc: {},
      memoryMb: 2048,
      cpus: 2,
      status: 'running',
      health: 'healthy',
      lastError: null,
      progress: null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    cm.state.installations.push(rec);
    cm.save();

    // También inyectar registro tipo GlitchTip con worker `startAfterApp: true` para probar orden pre/post-app en start/stop
    const gtTpl = cm.getTemplate('glitchtip');
    const gtId = 'svc_glitchtip_11223344';
    const gtRec = {
      id: gtId,
      templateId: 'glitchtip',
      name: 'GlitchTip',
      templateName: gtTpl.name,
      category: gtTpl.category,
      image: gtTpl.app.image,
      domain: null,
      url: 'http://127.0.0.1:42557',
      tz: 'UTC',
      domainId: null,
      hostPort: 42557,
      appPort: gtTpl.app.port,
      extraPorts: {},
      containerName: cm.containerName(gtId, 'app'),
      networkName: cm.networkName(gtId),
      volumes: { uploads: cm.volumeName(gtId, 'uploads') },
      sidecars: [
        { name: 'valkey', image: 'valkey/valkey:8.1-alpine', containerName: cm.containerName(gtId, 'valkey'), startAfterApp: false, coupledWithApp: false, coupledTagOnly: false, volumes: { data: cm.volumeName(gtId, 'valkey_data') } },
        { name: 'worker', image: gtTpl.app.image, containerName: cm.containerName(gtId, 'worker'), startAfterApp: true, coupledWithApp: true, coupledTagOnly: false, volumes: {} }
      ],
      databaseId: null,
      secretsEnc: {},
      customEnvEnc: {},
      memoryMb: 1024,
      cpus: 1,
      status: 'stopped',
      health: 'unknown',
      lastError: null,
      progress: null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    cm.state.installations.push(gtRec);
    cm.save();

    // Verificar orden start/stop escalonado con worker post-app (`valkey` -> `wait:valkey` -> `app` -> `worker`)
    dockerTimeline.length = 0;
    await cm.start(gtId);
    const gtStartValkey = dockerTimeline.findIndex((l) => l === `start ${cm.containerName(gtId, 'valkey')}`);
    const gtWaitValkey = dockerTimeline.findIndex((l) => l === `wait:${cm.containerName(gtId, 'valkey')}`);
    const gtStartApp = dockerTimeline.findIndex((l) => l === `start ${gtRec.containerName}`);
    const gtStartWorker = dockerTimeline.findIndex((l) => l === `start ${cm.containerName(gtId, 'worker')}`);
    assert.ok(
      gtStartValkey >= 0 && gtWaitValkey > gtStartValkey && gtStartApp > gtWaitValkey && gtStartWorker > gtStartApp,
      `Orden start() incorrecto en glitchtip: ${JSON.stringify(dockerTimeline)}`
    );

    dockerTimeline.length = 0;
    await cm.stop(gtId);
    const gtStopWorker = dockerTimeline.findIndex((l) => l === `stop ${cm.containerName(gtId, 'worker')}`);
    const gtStopApp = dockerTimeline.findIndex((l) => l === `stop ${gtRec.containerName}`);
    const gtStopValkey = dockerTimeline.findIndex((l) => l === `stop ${cm.containerName(gtId, 'valkey')}`);
    assert.ok(
      gtStopWorker >= 0 && gtStopApp > gtStopWorker && gtStopValkey > gtStopApp,
      `Orden inverso stop() incorrecto en glitchtip: ${JSON.stringify(dockerTimeline)}`
    );
    await cm.remove(gtId, { deleteVolumes: false });

    // Verificar extraPorts en allAllocatedPorts y reservedPorts
    assert.ok(cm.reservedPorts().has(42555) && cm.reservedPorts().has(42556), 'reservedPorts debe cubrir hostPort y extraPorts');

    // Verificar getEnv/updateEnv y propagación a auxiliar acoplado `ml` + redacción en logs
    await cm.updateEnv(recId, { CUSTOM_TOKEN: 'SUPER_SECRET_CUSTOM_VAL_9999' });
    const envRes = cm.getEnv(recId);
    assert.strictEqual(envRes.overrides.CUSTOM_TOKEN, 'SUPER_SECRET_CUSTOM_VAL_9999');
    assert.strictEqual(envRes.customEnv.CUSTOM_TOKEN, 'SUPER_SECRET_CUSTOM_VAL_9999');
    assert.ok(dockerTimeline.some((l) => l.includes(`--name ${cm.containerName(recId, 'ml')}`)), 'updateEnv debe recrear auxiliar acoplado');

    const logRes = await cm.logs(recId);
    assert.ok(!logRes.output.includes('SUPER_SECRET_CUSTOM_VAL_9999'), 'logs() debe redactar customEnv');
    assert.ok(logRes.output.includes('«oculto»'));

    const statsRes = await cm.getStats(recId);
    assert.strictEqual(statsRes.available, true);
    assert.ok(statsRes.containers.length > 0 && statsRes.containers[0].containerName === statsRes.containers[0].name);

    // Verificar updateImage: rechaza :latest y repositorio distinto; actualiza app + ml juntos
    await assert.rejects(() => cm.updateImage(recId, 'ghcr.io/immich-app/immich-server:latest'), /versión fija/);
    await assert.rejects(() => cm.updateImage(recId, 'otro/repo:1.0.0'), /otro repositorio/);

    const upd = await cm.updateImage(recId, 'ghcr.io/immich-app/immich-server:v1.130.0');
    assert.strictEqual(upd.success, true);
    assert.strictEqual(rec.image, 'ghcr.io/immich-app/immich-server:v1.130.0');
    assert.strictEqual(rec.sidecars.find((s) => s.name === 'ml').image, 'ghcr.io/immich-app/immich-machine-learning:v1.130.0');
    assert.strictEqual(upd.updatedSidecars.length, 1);

    // Verificar checkImageDrift detecta desfase respecto al catálogo
    const drift = cm.checkImageDrift(recId);
    assert.strictEqual(drift.hasUpdate, true);
    assert.strictEqual(drift.totalDrifts, 2); // app + ml

    // Verificar rollback automático completo (app + ml) cuando falla la sonda
    probeShouldPass = false;
    await assert.rejects(() => cm.updateImage(recId, 'ghcr.io/immich-app/immich-server:v1.999.0'), /Actualización revertida/);
    assert.strictEqual(rec.image, 'ghcr.io/immich-app/immich-server:v1.130.0');
    assert.strictEqual(rec.sidecars.find((s) => s.name === 'ml').image, 'ghcr.io/immich-app/immich-machine-learning:v1.130.0');
    assert.strictEqual(rec.health, 'healthy');
    probeShouldPass = true;

    // Verificar backupVolumes + listVolumeBackups + restoreVolume + detección de corrupción SHA-256
    const bkp = await cm.backupVolumes(recId, { label: 'pre-upgrade' });
    assert.strictEqual(bkp.success, true);
    assert.strictEqual(bkp.volumes.length, 3); // uploads + valkey_data + ml_cache
    assert.strictEqual(cm.listVolumeBackups(recId).length, 1);

    const rest = await cm.restoreVolume(recId, bkp.backupId);
    assert.strictEqual(rest.success, true);
    assert.strictEqual(rest.restoredVolumes.length, 3);

    // Corromper un archivo del backup y comprobar fail-fast SHA-256
    const corruptedPath = path.join(cm.backupsRoot, recId, bkp.backupId, bkp.volumes[0].archiveName);
    fs.appendFileSync(corruptedPath, 'TAMPERED');
    await assert.rejects(() => cm.restoreVolume(recId, bkp.backupId), /Integridad SHA-256 fallida/);

    // Verificar orden inverso en stop() y orden escalonado en start()
    dockerTimeline.length = 0;
    await cm.stop(recId);
    assert.strictEqual(rec.status, 'stopped');
    const stopAppIdx = dockerTimeline.findIndex((l) => l === `stop ${rec.containerName}`);
    const stopValkeyIdx = dockerTimeline.findIndex((l) => l === `stop ${cm.containerName(recId, 'valkey')}`);
    assert.ok(stopAppIdx >= 0 && stopValkeyIdx > stopAppIdx, 'stop() debe parar app antes que los auxiliares previos');

    dockerTimeline.length = 0;
    await cm.start(recId);
    const startValkeyIdx = dockerTimeline.findIndex((l) => l === `start ${cm.containerName(recId, 'valkey')}`);
    const waitValkeyIdx = dockerTimeline.findIndex((l) => l === `wait:${cm.containerName(recId, 'valkey')}`);
    const startAppIdx = dockerTimeline.findIndex((l) => l === `start ${rec.containerName}`);
    assert.ok(startValkeyIdx >= 0 && waitValkeyIdx > startValkeyIdx && startAppIdx > waitValkeyIdx, 'start() debe esperar salud de auxiliares antes de arrancar app');

    // Verificar remove() limpia ficheros de configuración incluso con deleteVolumes: false
    cm.materialiseFiles(recId, 'app', [{ name: 'test.ini', path: '/etc/test.ini', content: 'a=1\n' }]);
    assert.ok(fs.existsSync(path.join(cm.filesRoot, recId)));
    await cm.remove(recId, { deleteVolumes: false });
    assert.ok(!fs.existsSync(path.join(cm.filesRoot, recId)), 'remove() debe limpiar ficheros de configuración generados');
    assert.strictEqual(cm.list().length, 0);

    console.log('  ✓ Ciclo de vida completo: extraPorts, env/stats, update acoplado + rollback, drift, backup/restore SHA-256 y arranque por fases OK');
  } finally {
    if (tcpSrv) await new Promise((resolve) => tcpSrv.close(resolve));
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) {}
  }

  // -------------------------------------------------------------------------
  // 12. Los pasos de progreso están completos y ordenados
  // -------------------------------------------------------------------------
  assert.ok(STEPS.length >= 5, 'Debe haber pasos de progreso suficientes para una barra honesta');
  assert.strictEqual(STEPS[0].key, 'validar');
  assert.strictEqual(STEPS[STEPS.length - 1].key, 'listo');
  for (const s of STEPS) assert.ok(s.label && s.label.length > 3, `El paso ${s.key} no tiene etiqueta legible`);
  console.log(`  ✓ ${STEPS.length} pasos de progreso, todos con etiqueta en español`);

  console.log('✅ Catálogo de servicios verificado\n');
}

module.exports = testCatalog;

if (require.main === module) {
  testCatalog().catch((err) => {
    console.error('❌ Fallo en las pruebas del catálogo:', err);
    process.exit(1);
  });
}
